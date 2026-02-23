"""
tools/metasploit_tool.py — Metasploit RPC wrapper via pymetasploit3.

Prerequisites:
    msfrpcd -P <password> -S -a 127.0.0.1

The client connection is a lazy singleton — it is created on first use
and reused for subsequent calls within the same agent session.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from scope import ScopeEnforcer


# Lazy singleton
_msf_client: Optional[Any] = None


def _get_client(host: str, port: int, user: str, password: str, ssl: bool) -> Any:
    """Return a cached MsfRpcClient, creating it if necessary."""
    global _msf_client
    if _msf_client is not None:
        return _msf_client

    try:
        from pymetasploit3.msfrpc import MsfRpcClient  # type: ignore
    except ImportError:
        raise RuntimeError(
            "pymetasploit3 is not installed. Run: pip install pymetasploit3"
        )

    _msf_client = MsfRpcClient(
        password,
        server=host,
        port=port,
        username=user,
        ssl=ssl,
    )
    return _msf_client


def run_metasploit(
    module_path: str,
    options: Optional[Dict[str, str]],
    check_only: bool,
    timeout_seconds: int,
    msf_host: str,
    msf_port: int,
    msf_user: str,
    msf_password: str,
    msf_ssl: bool,
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Execute a Metasploit module and return structured JSON."""
    # Scope-check the RHOSTS option if present
    opts = options or {}
    rhosts = opts.get("RHOSTS") or opts.get("rhosts")
    if rhosts:
        scope.validate(rhosts)

    if dry_run:
        return json.dumps({
            "dry_run": True,
            "tool": "metasploit",
            "module_path": module_path,
            "check_only": check_only,
        })

    try:
        client = _get_client(msf_host, msf_port, msf_user, msf_password, msf_ssl)
    except Exception as exc:
        return json.dumps({"error": f"MSF connection failed: {exc}"})

    # Snapshot sessions before the module runs
    try:
        sessions_before: set = set(client.sessions.list.keys())
    except Exception:
        sessions_before = set()

    # Create a new console for this interaction
    try:
        console = client.consoles.console()
        console_id = console.cid
    except Exception as exc:
        return json.dumps({"error": f"Failed to create MSF console: {exc}"})

    output_lines: List[str] = []

    def _send(cmd: str) -> None:
        console.write(cmd)
        # Give Metasploit a moment to process
        time.sleep(0.5)

    try:
        _send(f"use {module_path}")
        for key, value in opts.items():
            _send(f"set {key} {value}")

        if check_only:
            _send("check")
        else:
            _send("run -j")

        # Poll until console is no longer busy or timeout
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            data = console.read()
            if data and data.get("data"):
                output_lines.append(data["data"])
            if not data.get("busy", True):
                break
            time.sleep(1)

        # Flush any remaining output
        final = console.read()
        if final and final.get("data"):
            output_lines.append(final["data"])

    except Exception as exc:
        return json.dumps({
            "error": f"Console execution error: {exc}",
            "module_path": module_path,
        })
    finally:
        try:
            client.consoles.destroy(console_id)
        except Exception:
            pass

    full_output = "\n".join(output_lines)

    # Detect newly opened sessions
    new_sessions: List[str] = []
    try:
        sessions_after: set = set(client.sessions.list.keys())
        new_sessions = list(sessions_after - sessions_before)
    except Exception:
        pass

    return json.dumps({
        "module_path": module_path,
        "options": opts,
        "check_only": check_only,
        "output": full_output[:5000],
        "sessions_opened": new_sessions,
        "success": len(new_sessions) > 0 or "check" in full_output.lower(),
    })
