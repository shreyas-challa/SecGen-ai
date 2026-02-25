"""
tools/dispatcher.py — Routes Claude tool_use blocks to the correct handler.

All exceptions (including ScopeViolation) are caught here and returned
as error JSON so the agent loop NEVER crashes on a tool failure.
"""
# ruff: noqa: E402
from __future__ import annotations

import json
import traceback
from typing import Any, Dict

from config import Config
from scope import ScopeEnforcer, ScopeViolation
from session_log import SessionLogger

from tools.nmap_tool import run_nmap
from tools.nuclei_tool import run_nuclei
from tools.ffuf_tool import run_ffuf
from tools.sqlmap_tool import run_sqlmap
from tools.metasploit_tool import run_metasploit
from tools.http_tool import run_http_request
from tools.report_tool import generate_report
from tools.shell_tool import run_shell_command


class ToolDispatcher:
    """Routes tool calls from the agent to the correct handler function."""

    def __init__(
        self,
        config: Config,
        scope: ScopeEnforcer,
        session_logger: SessionLogger,
    ) -> None:
        self.config = config
        self.scope = scope
        self.logger = session_logger

    def dispatch(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        """
        Dispatch *tool_name* with *tool_input* to the correct handler.

        Returns a JSON string. Never raises — all exceptions become error JSON.
        """
        try:
            return self._route(tool_name, tool_input)
        except ScopeViolation as exc:
            return json.dumps({
                "error": "SCOPE_VIOLATION",
                "message": str(exc),
                "tool": tool_name,
            })
        except Exception as exc:
            tb = traceback.format_exc()
            self.logger.log_error(
                error=str(exc),
                context={"tool": tool_name, "traceback": tb[:2000]},
            )
            return json.dumps({
                "error": "TOOL_ERROR",
                "message": str(exc),
                "tool": tool_name,
            })

    # ------------------------------------------------------------------ #
    # Routing                                                              #
    # ------------------------------------------------------------------ #

    def _route(self, tool_name: str, inp: Dict[str, Any]) -> str:
        cfg = self.config

        if tool_name == "nmap_scan":
            scan_type_val = inp.get("scan_type", "version")
            # If scan_type looks like raw nmap flags (e.g. "-sC -sV -T4 -p-"),
            # treat it as extra_flags so the model doesn't lose its intended options.
            _VALID_SCAN_TYPES = {"stealth", "connect", "udp", "vuln", "version"}
            if scan_type_val and scan_type_val not in _VALID_SCAN_TYPES:
                raw_flags = scan_type_val
                scan_type_val = "version"
            else:
                raw_flags = None
            # Merge all flag-like parameters: extra_flags, flags, options, timing,
            # and any raw flags recovered from an invalid scan_type value.
            # "timing" is a common extra param the model passes (e.g. "-T4") that
            # isn't in the schema but should be forwarded as a flag.
            flag_parts = [
                f for f in [
                    inp.get("extra_flags"),
                    inp.get("flags"),
                    inp.get("options"),
                    inp.get("timing"),
                    raw_flags,
                ] if f
            ]
            extra_flags = " ".join(flag_parts) if flag_parts else None
            # Coerce ports to string — the model sometimes passes an integer (e.g. ports=21)
            # which causes a TypeError in subprocess.
            ports_val = inp.get("ports")
            if ports_val is not None:
                ports_val = str(ports_val)
            return run_nmap(
                target=inp["target"],
                scan_type=scan_type_val,
                ports=ports_val,
                extra_flags=extra_flags,
                timeout_seconds=int(inp.get("timeout_seconds", 300)),
                nmap_path=cfg.nmap_path,
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "nuclei_scan":
            return run_nuclei(
                target=inp["target"],
                templates=inp.get("templates"),
                severity=inp.get("severity"),
                extra_flags=inp.get("extra_flags"),
                timeout_seconds=int(inp.get("timeout_seconds", 300)),
                nuclei_path=cfg.nuclei_path,
                nuclei_templates_path=cfg.nuclei_templates_path or None,
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "ffuf_scan":
            # Accept "url" as alias for "target" — the model sometimes uses this
            ffuf_target = inp.get("target") or inp.get("url")
            if not ffuf_target:
                return json.dumps({
                    "error": "MISSING_PARAM",
                    "message": "ffuf_scan requires 'target' (base URL or domain).",
                    "tool": tool_name,
                })
            return run_ffuf(
                target=ffuf_target,
                scan_mode=inp.get("scan_mode", "directory"),
                wordlist=inp.get("wordlist"),
                extensions=inp.get("extensions"),
                filter_status=inp.get("filter_status", "404"),
                threads=int(inp.get("threads", 40)),
                timeout_seconds=int(inp.get("timeout_seconds", 120)),
                ffuf_path=cfg.ffuf_path,
                default_wordlist=cfg.default_wordlist,
                subdomains_wordlist=cfg.subdomains_wordlist,
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "sqlmap_scan":
            return run_sqlmap(
                url=inp["url"],
                parameter=inp.get("parameter"),
                level=int(inp.get("level", 1)),
                risk=int(inp.get("risk", 1)),
                dump_tables=bool(inp.get("dump_tables", False)),
                extra_flags=inp.get("extra_flags"),
                timeout_seconds=int(inp.get("timeout_seconds", 180)),
                sqlmap_path=cfg.sqlmap_path,
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "metasploit_run":
            return run_metasploit(
                module_path=inp["module_path"],
                options=inp.get("options"),
                check_only=bool(inp.get("check_only", True)),
                timeout_seconds=int(inp.get("timeout_seconds", 120)),
                msf_host=cfg.msf_host,
                msf_port=cfg.msf_port,
                msf_user=cfg.msf_user,
                msf_password=cfg.msf_password,
                msf_ssl=cfg.msf_ssl,
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "http_request":
            return run_http_request(
                url=inp["url"],
                method=inp.get("method", "GET"),
                headers=inp.get("headers"),
                body=inp.get("body"),
                follow_redirects=bool(inp.get("follow_redirects", True)),
                timeout_seconds=int(inp.get("timeout_seconds", 30)),
                scope=self.scope,
                dry_run=cfg.dry_run,
            )

        elif tool_name == "shell_command":
            return run_shell_command(
                action=inp.get("action", "run"),  # default to "run" when omitted
                command=inp.get("command"),
                pid=inp.get("pid"),
                timeout_seconds=int(inp.get("timeout_seconds", cfg.shell_timeout)),
                working_dir=inp.get("working_dir"),
                scope=self.scope,
                dry_run=cfg.dry_run,
                input_data=inp.get("input_data") or inp.get("stdin"),
                host=inp.get("host"),
                username=inp.get("username"),
                password=inp.get("password"),
            )

        elif tool_name == "generate_report":
            # Accept common parameter name variants the model may use
            target = (inp.get("target") or inp.get("title") or inp.get("host") or "unknown")
            executive_summary = (
                inp.get("executive_summary")
                or inp.get("summary")
                or inp.get("description")
                or "See findings below."
            )
            return generate_report(
                target=target,
                executive_summary=executive_summary,
                findings=inp.get("findings", []),
                methodology_notes=inp.get("methodology_notes") or inp.get("recommendations"),
                output_dir=cfg.output_dir,
                flags_captured=inp.get("flags_captured"),
                attack_chain=inp.get("attack_chain"),
                shell_proof=inp.get("shell_proof"),
                privilege_escalation=inp.get("privilege_escalation"),
                shell_access=inp.get("shell_access"),
            )

        else:
            return json.dumps({
                "error": "UNKNOWN_TOOL",
                "message": f"No handler registered for tool: {tool_name!r}",
                "tool": tool_name,
            })
