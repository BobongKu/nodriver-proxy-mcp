"""Code-Mode Sandbox — executes Python scripts locally in a subprocess."""

import json
import logging
import asyncio
import os as os_lib
import subprocess
import sys
from pathlib import Path

from nodriver_proxy_mcp.browser.session_manager import session_manager

logger = logging.getLogger(__name__)

MAX_OUTPUT = 32768  # 32KB — recon scripts can produce substantial output


def _create_windows_job_object(memory_limit_mb: int = 256):
    """Create a Windows Job Object with memory limits.
    Returns (job_handle, None) on success, (None, error_msg) on failure."""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32

        # CreateJobObjectW
        job = kernel32.CreateJobObjectW(None, None)
        if not job:
            return None, "Failed to create Job Object"

        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_uint64),
                ("WriteOperationCount", ctypes.c_uint64),
                ("OtherOperationCount", ctypes.c_uint64),
                ("ReadTransferCount", ctypes.c_uint64),
                ("WriteTransferCount", ctypes.c_uint64),
                ("OtherTransferCount", ctypes.c_uint64),
            ]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.POINTER(ctypes.c_ulong)),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        # JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        info.ProcessMemoryLimit = memory_limit_mb * 1024 * 1024

        # SetInformationJobObject (class 9 = JobObjectExtendedLimitInformation)
        success = kernel32.SetInformationJobObject(
            job, 9, ctypes.byref(info), ctypes.sizeof(info)
        )
        if not success:
            kernel32.CloseHandle(job)
            return None, "Failed to set Job Object limits"

        return job, None
    except Exception as e:
        return None, str(e)


def _assign_process_to_job(job_handle, pid: int):
    """Assign a process to a Windows Job Object."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_ALL_ACCESS = 0x1F0FFF
        proc_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if proc_handle:
            kernel32.AssignProcessToJobObject(job_handle, proc_handle)
            kernel32.CloseHandle(proc_handle)
    except Exception:
        pass


def _kill_process_tree(proc: asyncio.subprocess.Process):
    """Kill a process and all its children (cross-platform)."""
    pid = proc.pid
    if pid is None:
        return

    if sys.platform == "win32":
        # taskkill /T kills the process tree
        try:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True, timeout=5,
            )
        except Exception:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
    else:
        # Kill the entire process group (since we used start_new_session)
        import signal
        try:
            os_lib.killpg(os_lib.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass


async def run_in_codemode(script_content: str, timeout: int = 300, bypass_proxy: bool = False, dependencies: list = None) -> str:
    """Core codemode subprocess engine. HITL gate (approved=True) is the security boundary."""
    env_vars = {}

    # SDK 사용을 위해 src 디렉토리를 PYTHONPATH에 자동 추가
    current_src = str(Path(__file__).parent.parent.parent.resolve())
    env_vars["PYTHONPATH"] = current_src

    # Dynamically resolve proxy port from running proxy
    from nodriver_proxy_mcp.proxy.controller import proxy_manager

    # Try to use current running port, fallback to default 8082 if we want to force it
    current_port = proxy_manager.port if proxy_manager.running else 8082

    if not bypass_proxy:
        proxy_url = f"http://127.0.0.1:{current_port}"
        env_vars.update({
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NO_PROXY": "localhost,127.0.0.1",
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "no_proxy": "localhost,127.0.0.1",
            "PYTHONHTTPSVERIFY": "0",  # Disable global SSL verification for sandbox
            "REQUESTS_CA_BUNDLE": "",  # Force requests to ignore bundled CA and trust env
        })
    else:  # Ensure any existing proxy envs are stripped
        env_vars.update({
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
        })

    # 기본 세션 CDP 포트 (nodriver 직접 연결용)
    session = session_manager._sessions.get("default")
    if session and session.alive:
        env_vars["CDP_PORT"] = str(session.cdp_port)
        env_vars["IPC_PORT"] = str(session.ipc_port)

    # 모든 활성 세션 정보를 JSON으로 전달 (SDK의 browser_* 도구 사용을 위해)
    all_sessions = {}
    for _name, _s in session_manager._sessions.items():
        if _s.alive:
            all_sessions[_name] = {"ipc_port": _s.ipc_port, "cdp_port": _s.cdp_port}
    if all_sessions:
        env_vars["MCP_BROWSER_SESSIONS"] = json.dumps(all_sessions)

    import tempfile

    # Store script out of command line arguments to avoid length limit and escaping issues
    fd, path = tempfile.mkstemp(suffix=".py", prefix="mcp_sandbox_")
    with os_lib.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(script_content)

    job_handle = None
    try:
        merged_env = os_lib.environ.copy()
        # 우리가 방금 추가한 PYTHONPATH는 유지해야 함
        ext_python_path = merged_env.get("PYTHONPATH", "")
        if ext_python_path:
            merged_env["PYTHONPATH"] = f"{env_vars['PYTHONPATH']}{os_lib.pathsep}{ext_python_path}"
        else:
            merged_env["PYTHONPATH"] = env_vars["PYTHONPATH"]

        merged_env.update(env_vars)

        # Platform-specific subprocess creation
        kwargs = dict(
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            stdin=asyncio.subprocess.DEVNULL,
            env=merged_env,
        )
        if sys.platform == "win32":
            # CREATE_NEW_PROCESS_GROUP for clean termination on Windows
            # CREATE_SUSPENDED is NOT used — Job Object is assigned after creation
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["start_new_session"] = True
            # Apply resource limits on Unix via preexec_fn
            def _set_limits():
                try:
                    import resource
                    # 60s CPU time limit (Apply to all Unix)
                    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))

                    # 256MB memory limit (Skip RLIMIT_AS on macOS due to lack of support/stability)
                    if sys.platform != "darwin":
                        try:
                            resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
                        except (ValueError, OSError):
                            pass
                except Exception:
                    pass
            kwargs["preexec_fn"] = _set_limits

        import shutil
        python_exe = sys.executable
        if os_lib.path.basename(python_exe).lower() not in ("python.exe", "python", "python3", "python3.exe"):
            python_exe = shutil.which("python") or python_exe

        if dependencies:
            uv_path = shutil.which("uv")
            if uv_path:
                install_cmd = [uv_path, "pip", "install"] + dependencies
            else:
                install_cmd = [python_exe, "-m", "pip", "install"] + dependencies

            install_proc = await asyncio.create_subprocess_exec(
                *install_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=merged_env,
            )
            stdout_data, _ = await install_proc.communicate()
            if install_proc.returncode != 0:
                return f"Error: Failed to install dependencies {dependencies}\n{stdout_data.decode(errors='replace')}"

        # Execute the script
        result = await asyncio.create_subprocess_exec(
            python_exe, path,
            **kwargs,
        )

        # Windows: assign to Job Object for memory limits + auto-kill on close
        if sys.platform == "win32" and result.pid:
            job_handle, err = _create_windows_job_object(memory_limit_mb=256)
            if job_handle:
                _assign_process_to_job(job_handle, result.pid)
            elif err:
                logger.warning(f"Could not create Job Object: {err}")

        # Read output dynamically to avoid deadlocks on large stdout
        stdout_chunks = []
        try:
            async with asyncio.timeout(timeout):
                while True:
                    line = await result.stdout.readline()
                    if not line:
                        break
                    stdout_chunks.append(line.decode(errors="replace"))
                    if len("".join(stdout_chunks)) > MAX_OUTPUT:
                        stdout_chunks.append(f"\n\n[Output truncated to {MAX_OUTPUT} bytes]")
                        _kill_process_tree(result)
                        break
            await result.wait()
        except asyncio.TimeoutError:
            stdout_chunks.append(f"\nError: Script execution timed out after {timeout}s")
            _kill_process_tree(result)

        final_out = "".join(stdout_chunks)
        return final_out if final_out else "Script execution completed with no output."
    except Exception as e:
        if 'result' in locals():
            _kill_process_tree(result)
        return f"Error: {str(e)}"
    finally:
        # Cleanup temp file
        try:
            os_lib.remove(path)
        except OSError:
            pass
        # Close Job Object handle (kills all assigned processes via KILL_ON_JOB_CLOSE)
        if job_handle and sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.CloseHandle(job_handle)
            except Exception:
                pass


def register_codemode_tools(mcp):
    """Register codemode tool."""

    @mcp.tool()
    async def execute_security_code(script_content: str, dependencies: list[str] = None, timeout: int = 300, approved: bool = False, bypass_proxy: bool = False) -> str:
        """Execute a Python script in an isolated sandbox with full access to all other tools via NdpSDK.

        REQUIRES: approved=true (human must approve arbitrary code execution).

        WHEN TO USE THIS (instead of individual tools):
        - Race conditions / TOCTOU attacks (need precise timing)
        - Blind SQL injection (needs hundreds of sequential requests with conditional logic)
        - Multi-step exploit chains (login → extract token → IDOR scan → report)
        - Heavy loops (brute force, enumeration)
        - Complex encoding/decoding chains (double URL encoding, JWT manipulation)
        - Custom PoC/exploit generation

        HOW TO USE NdpSDK:
        ```python
        from nodriver_proxy_mcp.sdk import NdpSDK
        import asyncio

        async def main():
            sdk = NdpSDK()  # auto-connects to running proxy and browser sessions

            # All 38 other tools are available as async methods:
            await sdk.manage_proxy("start")
            await sdk.browser_open()
            await sdk.browser_go("https://target.com")
            flows = await sdk.get_traffic_summary()
            result = await sdk.replay_flow(flow_id, replacements=[...])

        asyncio.run(main())
        ```

        RESOURCE LIMITS: 256MB memory, 60s CPU time, 32KB output cap.
        External packages can be auto-installed via the dependencies parameter.

        Args:
            script_content: Python code to execute. Use NdpSDK to access all proxy/browser tools programmatically.
            dependencies: Pip packages to install before execution (e.g. ["pyjwt", "pycryptodome", "beautifulsoup4"]).
            timeout: Maximum wall-clock execution time in seconds (default: 300 = 5 minutes).
            approved: MUST be true. Set this ONLY after the human user has explicitly approved code execution.
            bypass_proxy: If true, HTTP requests from the script skip the proxy (for raw speed or avoiding interception loops).
        """
        if not approved:
            return json.dumps({"error": "HITL Gateway: Execution of arbitrary code requires explicit approval. Please call again with approved=true after obtaining user consent."})

        if not script_content.strip():
            return "Error: script_content is empty"

        return await run_in_codemode(script_content, timeout=timeout, bypass_proxy=bypass_proxy, dependencies=dependencies)
