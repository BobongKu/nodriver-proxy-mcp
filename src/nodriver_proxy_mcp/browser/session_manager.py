"""Browser session manager — manages multiple BrowserDaemon processes.

Each session is a separate Chrome instance with its own IPC connection.
Session info is persisted to ~/.nodriver-proxy-mcp/sessions.json for
cross-process access.
"""

import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)

DAEMON_MODULE = "nodriver_proxy_mcp.browser.daemon"
SESSIONS_FILE = Path.home() / ".nodriver-proxy-mcp" / "sessions.json"


def _find_free_port() -> int:
    """Find a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _save_sessions_file(sessions: dict[str, dict]):
    """Write active session info to disk for cross-process access."""
    SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        SESSIONS_FILE.write_text(json.dumps(sessions, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to write sessions file: {e}")


def load_sessions_file() -> dict[str, dict]:
    """Read session info from disk."""
    try:
        if SESSIONS_FILE.exists():
            return json.loads(SESSIONS_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


class BrowserSession:
    """A single browser session backed by a BrowserDaemon subprocess."""

    def __init__(self, name: str, proc: subprocess.Popen, ipc_port: int, cdp_port: int):
        self.name = name
        self.proc = proc
        self.ipc_port = ipc_port
        self.cdp_port = cdp_port
        self.created_at = time.time()

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    async def send(self, method: str, params: dict = None, timeout: float = 120) -> dict:
        """Send an IPC request and wait for response."""
        if not self.alive:
            return {"error": "Browser session is dead"}

        request = json.dumps({
            "method": method,
            "params": params or {},
            "id": int(time.time() * 1000),
        }) + "\n"

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self.ipc_port),
                timeout=5,
            )
            writer.write(request.encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.readline(), timeout=timeout)
            writer.close()
            await writer.wait_closed()

            if data:
                response = json.loads(data.decode())
                if "error" in response:
                    return {"error": response["error"]}
                return response.get("result", {})
            return {"error": "Empty response from daemon"}

        except asyncio.TimeoutError:
            return {"error": f"Timeout after {timeout}s"}
        except ConnectionRefusedError:
            return {"error": "Cannot connect to browser daemon"}
        except Exception as e:
            return {"error": f"IPC error: {str(e)}"}

    def close(self):
        """Gracefully close the daemon: send IPC close command (which stops Chrome),
        then terminate the process if it doesn't exit cleanly."""
        if not self.alive:
            return

        # Step 1: Try graceful IPC close (daemon will call browser.stop())
        try:
            import socket
            with socket.create_connection(("127.0.0.1", self.ipc_port), timeout=2) as s:
                s.sendall(b'{"method":"close","params":{},"id":0}\n')
                s.settimeout(3)
                try:
                    s.recv(1024)
                except socket.timeout:
                    pass
        except (ConnectionRefusedError, OSError):
            pass

        # Step 2: Wait briefly for graceful exit
        try:
            self.proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass

        # Step 3: Force terminate
        try:
            self.proc.terminate()
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=3)


class SessionManager:
    """Manages multiple browser sessions."""

    def __init__(self):
        self._sessions: dict[str, BrowserSession] = {}

    def _sync_sessions_file(self):
        """Persist current session state to disk."""
        data = {}
        for name, session in self._sessions.items():
            if session.alive:
                data[name] = {
                    "ipc_port": session.ipc_port,
                    "cdp_port": session.cdp_port,
                    "pid": session.proc.pid,
                    "created_at": session.created_at,
                }
        _save_sessions_file(data)

    def open(
        self,
        session_name: str = "default",
        proxy_port: int | None = None,
        headless: bool = True,
    ) -> dict:
        """Start a new browser session."""
        if session_name in self._sessions and self._sessions[session_name].alive:
            return {
                "status": "already_open",
                "session": session_name,
                "ipc_port": self._sessions[session_name].ipc_port,
                "cdp_port": self._sessions[session_name].cdp_port,
            }

        ipc_port = _find_free_port()
        cdp_port = _find_free_port()

        browser_args = [
            # ── Suppress background noise traffic ──
            "--disable-background-networking",
            "--disable-background-timer-throttling",
            "--disable-backgrounding-occluded-windows",
            "--disable-breakpad",
            "--disable-client-side-phishing-detection",
            "--disable-component-update",
            "--disable-default-apps",
            "--disable-domain-reliability",
            "--disable-extensions",
            "--disable-hang-monitor",
            "--disable-ipc-flooding-protection",
            "--disable-notifications",
            "--disable-offer-store-unmasked-wallet-cards",
            "--disable-popup-blocking",
            "--disable-print-preview",
            "--disable-prompt-on-repost",
            "--disable-renderer-backgrounding",
            "--disable-speech-api",
            "--disable-sync",
            "--hide-scrollbars",
            "--metrics-recording-only",
            "--mute-audio",
            "--no-default-browser-check",
            "--no-first-run",
            "--no-pings",
            "--password-store=basic",
            "--use-mock-keychain",
            # ── Kill Google background services (c2dm, GCM, Safe Browsing, etc.) ──
            "--disable-features="
            "AutofillServerCommunication,OptimizationHints,DialMediaRouteProvider,"
            "MediaRouter,Translate,GCMConnectionStatusLogging,"
            "SafeBrowsingEnhancedProtection,InterestFeedContentSuggestions,"
            "BackgroundSync,BackgroundFetch,SpellCheckServiceIntegration",
            "--disable-component-extensions-with-background-pages",
            "--disable-field-trial-config",
            "--no-service-autorun",
            "--safebrowsing-disable-auto-update",
            "--safebrowsing-disable-download-protection",
        ]

        if proxy_port:
            browser_args.extend([
                f"--proxy-server=127.0.0.1:{proxy_port}",
                "--ignore-certificate-errors",
            ])
        else:
            browser_args.append("--no-proxy-server")

        cmd = [
            sys.executable, "-m", DAEMON_MODULE,
            "--ipc-port", str(ipc_port),
            "--cdp-port", str(cdp_port),
            "--headless", str(headless).lower(),
            "--browser-args", json.dumps(browser_args),
            "--parent-pid", str(os.getpid()),
        ]

        logger.info(f"Starting browser session '{session_name}': {' '.join(cmd)}")

        popen_kwargs = dict(
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        proc = subprocess.Popen(cmd, **popen_kwargs)

        if not self._wait_for_ipc(ipc_port, timeout=10.0):
            if proc.poll() is not None:
                stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
                return {"status": "error", "message": f"Daemon exited: {stderr[:500]}"}
            else:
                logger.warning(f"IPC port {ipc_port} not ready after 10s, but daemon process is alive")

        session = BrowserSession(session_name, proc, ipc_port, cdp_port)
        self._sessions[session_name] = session
        self._sync_sessions_file()

        result = {
            "status": "ready",
            "session": session_name,
            "ipc_port": ipc_port,
            "cdp_port": cdp_port,
            "pid": proc.pid,
        }
        if proxy_port:
            result["proxy"] = f"127.0.0.1:{proxy_port}"
        return result

    @staticmethod
    def _wait_for_ipc(port: int, timeout: float = 10.0) -> bool:
        """Poll until the IPC port is accepting connections."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                    return True
            except (ConnectionRefusedError, OSError):
                time.sleep(0.3)
        return False

    async def send(self, session_name: str, method: str, params: dict = None) -> dict:
        """Send command to a session."""
        session = self._sessions.get(session_name)
        if not session:
            return {"error": f"Session '{session_name}' not found. Use browser_open first."}
        if not session.alive:
            del self._sessions[session_name]
            self._sync_sessions_file()
            return {"error": f"Session '{session_name}' has died. Please browser_open again."}
        return await session.send(method, params)

    def close(self, session_name: str = None) -> dict:
        """Close a session or all sessions."""
        if session_name:
            session = self._sessions.pop(session_name, None)
            if session:
                session.close()
                self._sync_sessions_file()
                return {"status": "closed", "session": session_name}
            return {"status": "not_found", "session": session_name}
        else:
            closed = []
            for name, session in self._sessions.items():
                session.close()
                closed.append(name)
            self._sessions.clear()
            self._sync_sessions_file()
            return {"status": "closed_all", "sessions": closed}

    def list_sessions(self) -> list[dict]:
        """List all active sessions."""
        result = []
        dead = []
        for name, session in self._sessions.items():
            if session.alive:
                result.append({
                    "name": name,
                    "ipc_port": session.ipc_port,
                    "cdp_port": session.cdp_port,
                    "pid": session.proc.pid,
                    "status": "active",
                    "uptime_s": int(time.time() - session.created_at),
                })
            else:
                dead.append(name)
        for name in dead:
            del self._sessions[name]
        if dead:
            self._sync_sessions_file()
        return result


# Global instance
session_manager = SessionManager()
