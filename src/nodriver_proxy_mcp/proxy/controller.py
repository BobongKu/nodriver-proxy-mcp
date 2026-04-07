"""Proxy lifecycle manager — starts/stops mitmdump as a subprocess.

The mitmdump process runs with a custom addon script that records
all traffic into the SQLite TrafficDB and applies interception rules.
"""

import os
import signal
import subprocess
import sys
import time
import threading
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Path to the addon script that mitmdump loads
ADDON_SCRIPT = Path(__file__).parent / "_mitm_addon.py"


class ProxyManager:
    """Manages mitmdump/mitmweb subprocess lifecycle."""

    def __init__(self):
        self._proc: subprocess.Popen | None = None
        self._port: int = 0
        self._watchdog: threading.Thread | None = None
        self._stderr_lines: list[str] = []  # Last N lines of stderr for diagnostics

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def port(self) -> int:
        return self._port

    def start(self, port: int = 8082, ui: bool = False, upstream: str = "") -> dict:
        if self.running:
            return {
                "status": "already_running",
                "port": self._port,
                "pid": self._proc.pid,
            }

        # Step 0: Ensure the port is clean before starting
        self._kill_process_on_port(port)

        # Find mitmdump or mitmweb binary based on ui parameter
        mitmdump_name = "mitmweb.exe" if ui and os.name == "nt" else "mitmweb" if ui else "mitmdump.exe" if os.name == "nt" else "mitmdump"
        venv_bin = Path(sys.executable).parent
        mitmdump = venv_bin / mitmdump_name
        if not mitmdump.exists():
            mitmdump_str = mitmdump_name  # Fall back to PATH
        else:
            mitmdump_str = str(mitmdump)

        cmd = [
            mitmdump_str,
            "--listen-port", str(port),
            "--set", "flow_detail=0",
            "--ssl-insecure",
            "-s", str(ADDON_SCRIPT),
        ]

        if upstream:
            upstream_arg = f"upstream:{upstream}" if upstream.startswith("http") else f"upstream:http://{upstream}"
            cmd.extend(["--mode", upstream_arg])

        if ui:
            cmd.insert(3, "--web-port")
            cmd.insert(4, "8081")

        logger.info(f"Starting {mitmdump_name}: {' '.join(cmd)}")

        # Platform-specific subprocess flags
        # stdout → DEVNULL to prevent pipe buffer filling up and blocking mitmdump.
        # stderr → PIPE, drained by a background thread (keeps last 50 lines for diagnostics).
        popen_kwargs = dict(
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["close_fds"] = True
            popen_kwargs["start_new_session"] = True

        self._proc = subprocess.Popen(cmd, **popen_kwargs)
        self._port = port

        # Drain stderr in background to prevent pipe buffer from filling up
        self._stderr_lines = []
        stderr_drain = threading.Thread(
            target=self._drain_stderr,
            args=(self._proc,),
            daemon=True,
        )
        stderr_drain.start()

        # Start watchdog thread to kill mitmdump if parent dies
        parent_pid = os.getpid()
        self._watchdog = threading.Thread(
            target=self._parent_watchdog,
            args=(self._proc, parent_pid),
            daemon=True,
        )
        self._watchdog.start()

        # Poll for port readiness instead of blind sleep
        if not self._wait_for_port(port, timeout=5.0):
            if self._proc.poll() is not None:
                time.sleep(0.5)  # Let drain thread collect stderr
                stderr = "\n".join(self._stderr_lines[-10:])
                self._proc = None
                return {"status": "error", "message": f"{mitmdump_name} exited: {stderr[:500]}"}
            else:
                # Process alive but port not ready — might be slow start
                logger.warning(f"Port {port} not responsive after 5s, but process is alive")

        result = {
            "status": "started",
            "port": port,
            "pid": self._proc.pid,
        }

        if ui:
            result["web_ui"] = "http://127.0.0.1:8081"

        return result

    def _drain_stderr(self, proc: subprocess.Popen):
        """Background thread: continuously read stderr to prevent pipe buffer from blocking."""
        try:
            for line in proc.stderr:
                text = line.decode(errors="replace").rstrip()
                self._stderr_lines.append(text)
                # Keep only last 50 lines
                if len(self._stderr_lines) > 50:
                    self._stderr_lines = self._stderr_lines[-50:]
        except (ValueError, OSError):
            pass  # Pipe closed

    @staticmethod
    def _parent_watchdog(proc: subprocess.Popen, parent_pid: int):
        """Background thread: kill mitmdump if our parent process dies."""
        while proc.poll() is None:
            if not _is_process_alive(parent_pid):
                logger.warning(f"Parent process {parent_pid} died. Killing mitmdump {proc.pid}")
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
                return
            time.sleep(2)

    @staticmethod
    def _wait_for_port(port: int, timeout: float = 5.0) -> bool:
        """Poll until a TCP port is accepting connections."""
        import socket
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.2)
        return False

    @staticmethod
    def _kill_process_on_port(port: int):
        """Find and kill any process listening on the given port (cross-platform)."""
        if sys.platform == "win32":
            try:
                output = subprocess.check_output(
                    f"netstat -ano | findstr :{port}", shell=True
                ).decode()
                pids = set()
                for line in output.strip().split("\n"):
                    if "LISTENING" in line:
                        parts = line.split()
                        if len(parts) >= 5:
                            pids.add(parts[-1])
                for pid in pids:
                    if pid == "0":
                        continue
                    logger.warning(f"Killing orphan process {pid} on port {port}")
                    subprocess.run(f"taskkill /F /PID {pid}", shell=True, capture_output=True)
            except subprocess.CalledProcessError:
                pass
            except Exception as e:
                logger.error(f"Error cleaning up port {port}: {e}")
        else:
            # Linux/macOS: use lsof to find process on port
            try:
                output = subprocess.check_output(
                    ["lsof", "-ti", f":{port}"], stderr=subprocess.DEVNULL
                ).decode().strip()
                for pid_str in output.split("\n"):
                    pid_str = pid_str.strip()
                    if pid_str and pid_str.isdigit():
                        pid = int(pid_str)
                        logger.warning(f"Killing orphan process {pid} on port {port}")
                        try:
                            os.kill(pid, signal.SIGTERM)
                            time.sleep(0.5)
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
            except (subprocess.CalledProcessError, FileNotFoundError):
                # lsof not found or no process on port — try fuser as fallback
                try:
                    output = subprocess.check_output(
                        ["fuser", f"{port}/tcp"], stderr=subprocess.DEVNULL
                    ).decode().strip()
                    for pid_str in output.split():
                        pid_str = pid_str.strip()
                        if pid_str.isdigit():
                            pid = int(pid_str)
                            logger.warning(f"Killing orphan process {pid} on port {port}")
                            try:
                                os.kill(pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
            except Exception as e:
                logger.error(f"Error cleaning up port {port}: {e}")

    def stop(self) -> dict:
        if not self.running:
            return {"status": "not_running"}

        pid = self._proc.pid
        try:
            self._proc.terminate()
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()
            self._proc.wait(timeout=3)

        self._proc = None
        self._port = 0
        return {"status": "stopped", "pid": pid}


def _is_process_alive(pid: int) -> bool:
    """Check if a process is still running (cross-platform)."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            SYNCHRONIZE = 0x00100000
            handle = kernel32.OpenProcess(SYNCHRONIZE, False, pid)
            if handle:
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True
        except OSError:
            return False


# Global instance
proxy_manager = ProxyManager()
