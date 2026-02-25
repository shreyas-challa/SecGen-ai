"""
tools/shell_tool.py — Execute shell commands and manage background processes.

Actions:
  run             — Execute a command synchronously, return stdout/stderr/returncode
  run_background  — Start a process in the background, return its PID
  check_background — Read current output from a background process by PID
  stop_background — Terminate a background process by PID
"""
from __future__ import annotations

import atexit
import json
import os
import re
import subprocess
import sys
import tempfile
import threading
from typing import Any, Dict, Optional

from scope import ScopeEnforcer

# Maximum bytes of stdout/stderr returned to avoid context window pollution
_MAX_OUTPUT_BYTES = 10 * 1024  # 10 KB

# Module-level registry of background processes: {pid: (Popen, stdout_path, stderr_path)}
_background_processes: Dict[int, Dict[str, Any]] = {}
_bg_lock = threading.Lock()

# SSH credential store: {host: {"username": str, "password": str}}
_ssh_credentials: Dict[str, Dict[str, str]] = {}
_ssh_lock = threading.Lock()


def _cleanup_background_processes() -> None:
    """Kill all background processes on interpreter exit."""
    with _bg_lock:
        for pid, info in list(_background_processes.items()):
            proc = info["process"]
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass


atexit.register(_cleanup_background_processes)


def _extract_ips_from_command(command: str) -> list[str]:
    """Best-effort extraction of IP addresses from a command string."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", command)


def _check_scope(command: str, scope: ScopeEnforcer) -> None:
    """Validate any IPs found in the command against the scope enforcer."""
    ips = _extract_ips_from_command(command)
    for ip in ips:
        scope.validate(ip)


def _cap_output(text: str) -> str:
    """Truncate output to _MAX_OUTPUT_BYTES with a notice."""
    if len(text.encode("utf-8", errors="replace")) <= _MAX_OUTPUT_BYTES:
        return text
    truncated = text.encode("utf-8", errors="replace")[:_MAX_OUTPUT_BYTES].decode(
        "utf-8", errors="replace"
    )
    return truncated + "\n\n[... output truncated at 10KB ...]"


def _get_workdir(working_dir: Optional[str]) -> str:
    """Return the working directory, creating it if needed."""
    if working_dir:
        os.makedirs(working_dir, exist_ok=True)
        return working_dir
    default = os.path.join("output", "workdir")
    os.makedirs(default, exist_ok=True)
    return default


def run_shell_command(
    action: str,
    command: Optional[str] = None,
    pid: Optional[int] = None,
    timeout_seconds: int = 120,
    working_dir: Optional[str] = None,
    scope: Optional[ScopeEnforcer] = None,
    dry_run: bool = False,
    input_data: Optional[str] = None,
    host: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
) -> str:
    """
    Execute shell commands or manage background processes.

    Returns a JSON string with the result.
    """
    if action == "run":
        return _action_run(command, timeout_seconds, working_dir, scope, dry_run, input_data)
    elif action == "run_background":
        return _action_run_background(command, working_dir, scope, dry_run)
    elif action == "check_background":
        return _action_check_background(pid)
    elif action == "stop_background":
        return _action_stop_background(pid)
    elif action == "store_credentials":
        return _action_store_credentials(host, username, password)
    elif action == "run_ssh":
        return _action_run_ssh(host, command, timeout_seconds, dry_run)
    else:
        return json.dumps({"error": "INVALID_ACTION", "message": f"Unknown action: {action!r}. Use: run, run_background, run_ssh, check_background, stop_background, store_credentials"})


# ------------------------------------------------------------------ #
# Action handlers                                                      #
# ------------------------------------------------------------------ #

def _action_store_credentials(
    host: Optional[str],
    username: Optional[str],
    password: Optional[str],
) -> str:
    """Store SSH/service credentials for a target host for automatic reuse."""
    if not host or not username or not password:
        return json.dumps({
            "error": "MISSING_PARAM",
            "message": "host, username, and password are all required for action=store_credentials",
        })
    with _ssh_lock:
        _ssh_credentials[host] = {"username": username, "password": password}
    import platform
    on_windows = platform.system() == "Windows"
    ssh_hint = (
        f"Use action='run_ssh' with host='{host}' and command='...' to run commands on the target. "
        "This uses Paramiko directly and works on all platforms without sshpass."
        if on_windows else
        f"SSH commands targeting this host will now be auto-wrapped with sshpass. "
        f"You can also use action='run_ssh' with host='{host}' for a cleaner Paramiko-based connection."
    )
    return json.dumps({
        "status": "stored",
        "host": host,
        "username": username,
        "message": f"Credentials stored for {username}@{host}. {ssh_hint}",
    })


def _auto_wrap_ssh(command: str) -> str:
    """
    On Linux/Mac: wrap SSH commands targeting a host with stored credentials
    with sshpass and -o StrictHostKeyChecking=no.
    On Windows: sshpass is not available — return the command unchanged.
    The run_ssh action should be used instead for password-based SSH on Windows.
    """
    import platform
    if platform.system() == "Windows":
        return command  # sshpass unavailable; use action='run_ssh' instead

    if "sshpass" in command:
        return command  # Already wrapped

    # Match: ssh [options] user@host ...
    ssh_match = re.match(
        r'^(ssh\s+(?:-\S+\s+)*)(\S+)@(\S+)(.*)', command
    )
    if not ssh_match:
        return command

    _prefix, user, host, rest = ssh_match.groups()
    host_clean = host.split(":")[0].strip()

    with _ssh_lock:
        creds = _ssh_credentials.get(host_clean)

    if not creds:
        return command  # No stored creds for this host

    passwd = creds["password"]
    strict_flag = "-o StrictHostKeyChecking=no"
    if strict_flag not in command:
        return f"sshpass -p '{passwd}' ssh {strict_flag} {user}@{host}{rest}"
    else:
        return f"sshpass -p '{passwd}' {command}"


def _action_run(
    command: Optional[str],
    timeout_seconds: int,
    working_dir: Optional[str],
    scope: Optional[ScopeEnforcer],
    dry_run: bool,
    input_data: Optional[str] = None,
) -> str:
    if not command:
        return json.dumps({"error": "MISSING_PARAM", "message": "command is required for action=run"})

    # Auto-wrap SSH commands with stored credentials
    command = _auto_wrap_ssh(command)

    if scope:
        _check_scope(command, scope)

    if dry_run:
        return json.dumps({
            "status": "dry_run",
            "command": command,
            "stdout": "[DRY RUN] Command not executed.",
            "stderr": "",
            "returncode": 0,
        })

    cwd = _get_workdir(working_dir)

    try:
        # PYTHONUNBUFFERED=1 prevents Python subprocesses from fully buffering
        # stdout when piped — without this, print() output is silently lost.
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"

        run_kwargs: Dict[str, Any] = dict(
            shell=True,
            text=True,
            timeout=timeout_seconds,
            cwd=cwd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        if input_data is not None:
            run_kwargs["input"] = input_data
        else:
            run_kwargs["stdin"] = subprocess.DEVNULL

        result = subprocess.run(command, **run_kwargs)
        return json.dumps({
            "status": "success",
            "command": command,
            "stdout": _cap_output(result.stdout),
            "stderr": _cap_output(result.stderr),
            "returncode": result.returncode,
        })
    except subprocess.TimeoutExpired:
        return json.dumps({
            "status": "timeout",
            "command": command,
            "message": f"Command timed out after {timeout_seconds}s",
        })
    except Exception as exc:
        return json.dumps({
            "status": "error",
            "command": command,
            "message": str(exc),
        })


def _action_run_ssh(
    host: Optional[str],
    command: Optional[str],
    timeout_seconds: int,
    dry_run: bool,
) -> str:
    """
    Run a single command on a remote host over SSH using Paramiko.

    Uses credentials stored via action='store_credentials'.
    Works on Windows, Linux, and Mac — no sshpass required.
    """
    if not host:
        return json.dumps({"error": "MISSING_PARAM", "message": "host is required for action=run_ssh"})
    if not command:
        return json.dumps({"error": "MISSING_PARAM", "message": "command is required for action=run_ssh"})

    with _ssh_lock:
        creds = _ssh_credentials.get(host)

    if not creds:
        return json.dumps({
            "error": "NO_CREDENTIALS",
            "message": (
                f"No credentials stored for {host}. "
                "Call action='store_credentials' with host, username, and password first."
            ),
        })

    if dry_run:
        return json.dumps({
            "status": "dry_run",
            "host": host,
            "user": creds["username"],
            "command": command,
            "stdout": "[DRY RUN] SSH command not executed.",
            "stderr": "",
            "returncode": 0,
        })

    try:
        import paramiko
    except ImportError:
        return json.dumps({
            "error": "MISSING_DEPENDENCY",
            "message": "paramiko is not installed. Run: pip install paramiko",
        })

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            username=creds["username"],
            password=creds["password"],
            timeout=30,
            allow_agent=False,
            look_for_keys=False,
        )
        _stdin, stdout, stderr = client.exec_command(command, timeout=timeout_seconds)
        stdout_str = stdout.read().decode("utf-8", errors="replace")
        stderr_str = stderr.read().decode("utf-8", errors="replace")
        returncode = stdout.channel.recv_exit_status()
        client.close()

        return json.dumps({
            "status": "success",
            "host": host,
            "user": creds["username"],
            "command": command,
            "stdout": _cap_output(stdout_str),
            "stderr": _cap_output(stderr_str),
            "returncode": returncode,
        })
    except Exception as exc:
        return json.dumps({
            "status": "error",
            "host": host,
            "command": command,
            "message": str(exc),
        })


def _action_run_background(
    command: Optional[str],
    working_dir: Optional[str],
    scope: Optional[ScopeEnforcer],
    dry_run: bool,
) -> str:
    if not command:
        return json.dumps({"error": "MISSING_PARAM", "message": "command is required for action=run_background"})

    if scope:
        _check_scope(command, scope)

    if dry_run:
        return json.dumps({
            "status": "dry_run",
            "command": command,
            "pid": -1,
            "message": "[DRY RUN] Background process not started.",
        })

    cwd = _get_workdir(working_dir)

    try:
        # Create temp files for stdout/stderr capture
        stdout_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_stdout.txt", dir=cwd, delete=False
        )
        stderr_file = tempfile.NamedTemporaryFile(
            mode="w", suffix="_stderr.txt", dir=cwd, delete=False
        )

        proc = subprocess.Popen(
            command,
            shell=True,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
        )

        with _bg_lock:
            _background_processes[proc.pid] = {
                "process": proc,
                "stdout_path": stdout_file.name,
                "stderr_path": stderr_file.name,
                "command": command,
            }

        return json.dumps({
            "status": "started",
            "command": command,
            "pid": proc.pid,
            "message": f"Background process started with PID {proc.pid}",
        })
    except Exception as exc:
        return json.dumps({
            "status": "error",
            "command": command,
            "message": str(exc),
        })


def _action_check_background(pid: Optional[int]) -> str:
    if pid is None:
        return json.dumps({"error": "MISSING_PARAM", "message": "pid is required for action=check_background"})

    with _bg_lock:
        info = _background_processes.get(pid)

    if not info:
        return json.dumps({
            "error": "NOT_FOUND",
            "message": f"No background process found with PID {pid}",
            "active_pids": list(_background_processes.keys()),
        })

    proc = info["process"]
    running = proc.poll() is None

    stdout_content = ""
    stderr_content = ""
    try:
        with open(info["stdout_path"], "r", encoding="utf-8", errors="replace") as f:
            stdout_content = _cap_output(f.read())
    except Exception:
        pass
    try:
        with open(info["stderr_path"], "r", encoding="utf-8", errors="replace") as f:
            stderr_content = _cap_output(f.read())
    except Exception:
        pass

    return json.dumps({
        "status": "running" if running else "exited",
        "pid": pid,
        "command": info["command"],
        "returncode": proc.returncode,
        "stdout": stdout_content,
        "stderr": stderr_content,
    })


def _action_stop_background(pid: Optional[int]) -> str:
    if pid is None:
        return json.dumps({"error": "MISSING_PARAM", "message": "pid is required for action=stop_background"})

    with _bg_lock:
        info = _background_processes.get(pid)

    if not info:
        return json.dumps({
            "error": "NOT_FOUND",
            "message": f"No background process found with PID {pid}",
            "active_pids": list(_background_processes.keys()),
        })

    proc = info["process"]
    try:
        proc.terminate()
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)

    # Read final output
    stdout_content = ""
    stderr_content = ""
    try:
        with open(info["stdout_path"], "r", encoding="utf-8", errors="replace") as f:
            stdout_content = _cap_output(f.read())
    except Exception:
        pass
    try:
        with open(info["stderr_path"], "r", encoding="utf-8", errors="replace") as f:
            stderr_content = _cap_output(f.read())
    except Exception:
        pass

    # Clean up temp files
    for path_key in ("stdout_path", "stderr_path"):
        try:
            os.unlink(info[path_key])
        except Exception:
            pass

    with _bg_lock:
        _background_processes.pop(pid, None)

    return json.dumps({
        "status": "stopped",
        "pid": pid,
        "command": info["command"],
        "returncode": proc.returncode,
        "stdout": stdout_content,
        "stderr": stderr_content,
    })


def get_active_background_pids() -> list[int]:
    """Return list of active background process PIDs."""
    with _bg_lock:
        return [
            pid for pid, info in _background_processes.items()
            if info["process"].poll() is None
        ]
