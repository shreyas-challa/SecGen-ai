"""
graph_updater.py — Parses tool results and mutates GraphState.

Called by agent.py after every tool dispatch. Each tool has its own
parsing logic that extracts hosts, services, vulnerabilities,
credentials, and access levels from the result string.
"""
from __future__ import annotations

import json
import re
from typing import Optional
from urllib.parse import urlparse

from graph_state import GraphState


class GraphUpdater:
    """Parses tool results and updates the attack surface graph."""

    def __init__(self, graph_state: GraphState) -> None:
        self.gs = graph_state

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def process_tool_result(
        self,
        tool_name: str,
        tool_input: dict,
        result_str: str,
        iteration: int,
    ) -> None:
        """Dispatch to per-tool handler."""
        try:
            handler = self._handlers.get(tool_name)
            if handler:
                handler(self, tool_input, result_str, iteration)
        except Exception:
            pass  # never crash the agent over graph updates

    # ------------------------------------------------------------------ #
    # Per-tool handlers                                                    #
    # ------------------------------------------------------------------ #

    def _handle_nmap(self, tool_input: dict, result_str: str, iteration: int) -> None:
        target = tool_input.get("target", "")
        host = self._extract_host(target)
        if not host:
            return

        host_id = f"host:{host}"
        self.gs.add_node(host_id, "host", host, {"ip": host, "iteration": iteration})

        # Parse open ports from nmap output
        # Match lines like: 80/tcp   open  http
        port_pattern = re.compile(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?", re.IGNORECASE
        )
        for match in port_pattern.finditer(result_str):
            port = match.group(1)
            proto = match.group(2)
            service_name = match.group(3)
            version_info = (match.group(4) or "").strip()

            service_id = f"service:{port}/{proto}:{host}"
            label = f"{service_name.upper()}:{port}"
            data = {
                "port": port,
                "protocol": proto,
                "service": service_name,
                "version": version_info,
                "host": host,
                "iteration": iteration,
            }
            self.gs.add_node(service_id, "service", label, data)
            self.gs.add_edge(host_id, service_id, "has_service", f"port {port}/{proto}")

    def _handle_nuclei(self, tool_input: dict, result_str: str, iteration: int) -> None:
        target = tool_input.get("target", "")

        # Try to parse JSON lines output from nuclei
        for line in result_str.splitlines():
            line = line.strip()
            if not line:
                continue

            # Try JSON format first
            finding = None
            try:
                finding = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                pass

            if finding and isinstance(finding, dict):
                self._process_nuclei_finding(finding, iteration)
            else:
                # Fallback: parse text output like "[severity] [template-id] url"
                self._parse_nuclei_text_line(line, target, iteration)

    def _process_nuclei_finding(self, finding: dict, iteration: int) -> None:
        template_id = finding.get("template-id", finding.get("templateID", "unknown"))
        severity = finding.get("info", {}).get("severity", "info").lower()
        name = finding.get("info", {}).get("name", template_id)
        matched_at = finding.get("matched-at", finding.get("matched_at", ""))
        host = self._extract_host(matched_at) or self._extract_host(
            finding.get("host", "")
        )
        port = self._extract_port(matched_at)

        if not host:
            return

        vuln_id = f"vuln:{template_id}:{host}"
        label = f"{severity.upper()}: {name}"
        data = {
            "severity": severity,
            "template": template_id,
            "matched_at": matched_at,
            "host": host,
            "iteration": iteration,
        }
        self.gs.add_node(vuln_id, "vulnerability", label, data)

        # Link to service if we can find it
        service_id = self._find_service_for_host_port(host, port)
        if service_id:
            self.gs.add_edge(service_id, vuln_id, "exposes_vuln", severity)
        else:
            host_id = f"host:{host}"
            if self.gs.has_node(host_id):
                self.gs.add_edge(host_id, vuln_id, "exposes_vuln", severity)

    def _parse_nuclei_text_line(self, line: str, target: str, iteration: int) -> None:
        # Match: [severity] [template-id] [protocol] url
        match = re.search(
            r"\[(\w+)\]\s+\[([^\]]+)\].*?(https?://\S+|[\d.]+(?::\d+)?)", line, re.IGNORECASE
        )
        if not match:
            return
        severity = match.group(1).lower()
        template_id = match.group(2)
        url_or_host = match.group(3)
        host = self._extract_host(url_or_host)
        port = self._extract_port(url_or_host)

        if not host:
            host = self._extract_host(target)
        if not host:
            return

        vuln_id = f"vuln:{template_id}:{host}"
        label = f"{severity.upper()}: {template_id}"
        data = {"severity": severity, "template": template_id, "host": host, "iteration": iteration}
        self.gs.add_node(vuln_id, "vulnerability", label, data)

        service_id = self._find_service_for_host_port(host, port)
        if service_id:
            self.gs.add_edge(service_id, vuln_id, "exposes_vuln", severity)
        else:
            host_id = f"host:{host}"
            if self.gs.has_node(host_id):
                self.gs.add_edge(host_id, vuln_id, "exposes_vuln", severity)

    def _handle_ffuf(self, tool_input: dict, result_str: str, iteration: int) -> None:
        target = tool_input.get("target", tool_input.get("url", ""))
        host = self._extract_host(target)
        port = self._extract_port(target)
        if not host:
            return

        # Collect discovered paths
        paths = []
        path_pattern = re.compile(r"(Status:\s*\d+.*?(?:\/\S+))", re.IGNORECASE)
        # Also try to extract paths from lines like: GET /path [status=200]
        for line in result_str.splitlines():
            # Common ffuf output: "/path  [Status: 200, Size: ...]"
            m = re.search(r"(/[^\s\[]*)", line)
            if m:
                path = m.group(1)
                if path and path not in paths:
                    paths.append(path)

        if paths:
            service_id = self._find_service_for_host_port(host, port)
            if service_id:
                node = self.gs.get_node(service_id)
                if node:
                    existing_paths = node.data.get("paths", [])
                    merged = list(set(existing_paths + paths[:50]))  # cap at 50
                    self.gs.add_node(
                        service_id, node.type, node.label,
                        {"paths": merged, "ffuf_iteration": iteration}
                    )

    def _handle_sqlmap(self, tool_input: dict, result_str: str, iteration: int) -> None:
        target = tool_input.get("target", tool_input.get("url", ""))
        host = self._extract_host(target)
        port = self._extract_port(target)
        if not host:
            return

        # Check if sqlmap found a vulnerability
        vulnerable = (
            "is vulnerable" in result_str.lower()
            or "sql injection" in result_str.lower()
            or "parameter" in result_str.lower() and "injectable" in result_str.lower()
        )
        if not vulnerable:
            return

        vuln_id = f"vuln:sqli:{host}"
        label = "HIGH: SQL Injection"
        data = {"severity": "high", "template": "sql-injection", "host": host, "iteration": iteration}
        self.gs.add_node(vuln_id, "vulnerability", label, data)

        service_id = self._find_service_for_host_port(host, port)
        if service_id:
            self.gs.add_edge(service_id, vuln_id, "exposes_vuln", "high")
        else:
            host_id = f"host:{host}"
            if self.gs.has_node(host_id):
                self.gs.add_edge(host_id, vuln_id, "exposes_vuln", "high")

    def _handle_shell_command(self, tool_input: dict, result_str: str, iteration: int) -> None:
        action = tool_input.get("action", "")

        if action == "store_credentials":
            self._handle_store_creds(tool_input, result_str, iteration)
        elif action == "run":
            self._handle_shell_run(tool_input, result_str, iteration)

    def _handle_store_creds(self, tool_input: dict, result_str: str, iteration: int) -> None:
        username = tool_input.get("username", "")
        password = tool_input.get("password", "")
        host = tool_input.get("host", "")

        if not username or not host:
            return

        cred_id = f"cred:{username}@{host}"
        label = f"{username}@{host}"
        data = {
            "username": username,
            "host": host,
            "has_password": bool(password),
            "iteration": iteration,
        }
        self.gs.add_node(cred_id, "credential", label, data)

        # Link credential to a service on the same host (prefer SSH port 22)
        service_id = self._find_service_for_host_port(host, "22") or self._find_any_service_for_host(host)
        if service_id:
            self.gs.add_edge(service_id, cred_id, "yields_cred", f"{username}@{host}")

        # Lateral movement detection: if same cred exists on another host
        self._detect_lateral_movement(cred_id, host, username)

    def _detect_lateral_movement(self, new_cred_id: str, host: str, username: str) -> None:
        """If the same username appears on multiple hosts, add lateral_movement edges."""
        # Look for existing credential nodes with same username but different host
        snapshot = self.gs.to_cytoscape_dict()
        for node_data in snapshot["nodes"]:
            if (
                node_data.get("type") == "credential"
                and node_data.get("username") == username
                and node_data.get("host") != host
                and node_data["id"] != new_cred_id
            ):
                other_host = node_data.get("host", "")
                # Add lateral movement between the two host services
                src_svc = self._find_any_service_for_host(other_host)
                tgt_svc = self._find_any_service_for_host(host)
                if src_svc and tgt_svc:
                    self.gs.add_edge(src_svc, tgt_svc, "lateral_movement", f"via {username}")

    def _handle_shell_run(self, tool_input: dict, result_str: str, iteration: int) -> None:
        command = tool_input.get("command", "")

        # Check for root access
        root_match = re.search(r"uid=0\(root\)", result_str)
        if root_match:
            host = self._guess_current_host(tool_input, result_str)
            access_id = f"access:root:{host}"
            label = f"root@{host}"
            data = {"access_level": "root", "host": host, "iteration": iteration}
            self.gs.add_node(access_id, "access", label, data)

            cred_id = self._find_cred_for_host(host)
            if cred_id:
                self.gs.add_edge(cred_id, access_id, "grants_access", "root")
            return

        # Check for user access
        user_match = re.search(r"uid=\d+\((\w+)\)", result_str)
        if user_match:
            username = user_match.group(1)
            if username == "root":
                return  # handled above
            host = self._guess_current_host(tool_input, result_str)
            access_id = f"access:user:{username}:{host}"
            label = f"{username}@{host}"
            data = {"access_level": "user", "username": username, "host": host, "iteration": iteration}
            self.gs.add_node(access_id, "access", label, data)

            cred_id = self._find_cred_for_host(host)
            if cred_id:
                self.gs.add_edge(cred_id, access_id, "grants_access", "user")

    def _handle_generate_report(self, tool_input: dict, result_str: str, iteration: int) -> None:
        """Enrich graph from report fields."""
        try:
            report = json.loads(result_str)
        except (json.JSONDecodeError, ValueError):
            return

        target = tool_input.get("target", "")
        host = self._extract_host(target)

        # Process findings
        findings = report.get("findings", [])
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            title = finding.get("title", "Unknown")
            service_info = finding.get("service", "")
            port = None
            if ":" in service_info:
                parts = service_info.split(":")
                port = parts[-1] if parts[-1].isdigit() else None

            if host:
                vuln_id = f"vuln:report:{title.lower().replace(' ', '-')}:{host}"
                if not self.gs.has_node(vuln_id):
                    label = f"{severity.upper()}: {title}"
                    data = {"severity": severity, "host": host, "from_report": True, "iteration": iteration}
                    self.gs.add_node(vuln_id, "vulnerability", label, data)

                    service_id = self._find_service_for_host_port(host, port)
                    if service_id:
                        self.gs.add_edge(service_id, vuln_id, "exposes_vuln", severity)

        # Process attack chain
        attack_chain = report.get("attack_chain", [])
        prev_node_id = None
        for step in attack_chain:
            step_type = step.get("type", "")
            step_id = step.get("id", "")
            if step_id and prev_node_id and step_type:
                if not self.gs.has_node(step_id):
                    label = step.get("label", step_id)
                    self.gs.add_node(step_id, step_type, label, step)
                self.gs.add_edge(prev_node_id, step_id, "grants_access", "chain")
            if step_id:
                prev_node_id = step_id

    # ------------------------------------------------------------------ #
    # Helper methods                                                       #
    # ------------------------------------------------------------------ #

    def _extract_host(self, url_or_ip: str) -> str:
        """Extract hostname/IP from a URL, IP, or IP:port string."""
        if not url_or_ip:
            return ""
        url_or_ip = url_or_ip.strip()
        # If it looks like a URL, parse it
        if "://" in url_or_ip:
            try:
                parsed = urlparse(url_or_ip)
                return parsed.hostname or ""
            except Exception:
                return ""
        # Strip port if present
        if ":" in url_or_ip and not url_or_ip.startswith("["):
            return url_or_ip.split(":")[0]
        return url_or_ip

    def _extract_port(self, url: str) -> Optional[str]:
        """Extract port from URL or host:port string."""
        if not url:
            return None
        if "://" in url:
            try:
                parsed = urlparse(url)
                if parsed.port:
                    return str(parsed.port)
                # Infer from scheme
                scheme_ports = {"http": "80", "https": "443", "ftp": "21", "ssh": "22"}
                return scheme_ports.get(parsed.scheme)
            except Exception:
                return None
        if ":" in url:
            parts = url.split(":")
            port_str = parts[-1]
            if port_str.isdigit():
                return port_str
        return None

    def _find_service_for_host_port(self, host: str, port: Optional[str]) -> Optional[str]:
        """Find service node id for a given host and port."""
        if not host or not port:
            return None
        snapshot = self.gs.to_cytoscape_dict()
        # Try exact match with tcp first
        for proto in ("tcp", "udp"):
            candidate = f"service:{port}/{proto}:{host}"
            for node in snapshot["nodes"]:
                if node["id"] == candidate:
                    return candidate
        # Fallback: scan for any service on that host matching that port
        for node in snapshot["nodes"]:
            if node.get("type") == "service" and node.get("host") == host:
                if node.get("port") == port:
                    return node["id"]
        return None

    def _find_any_service_for_host(self, host: str) -> Optional[str]:
        """Return the first service node id for a host, preferring SSH."""
        if not host:
            return None
        snapshot = self.gs.to_cytoscape_dict()
        ssh_id = None
        first_id = None
        for node in snapshot["nodes"]:
            if node.get("type") == "service" and node.get("host") == host:
                if first_id is None:
                    first_id = node["id"]
                if node.get("port") == "22":
                    ssh_id = node["id"]
        return ssh_id or first_id

    def _find_cred_for_host(self, host: str) -> Optional[str]:
        """Return credential node id for a given host."""
        if not host:
            return None
        snapshot = self.gs.to_cytoscape_dict()
        for node in snapshot["nodes"]:
            if node.get("type") == "credential" and node.get("host") == host:
                return node["id"]
        return None

    def _guess_current_host(self, tool_input: dict, result_str: str) -> str:
        """Try to determine the current host from tool input or result."""
        # Check common input keys
        for key in ("host", "target", "ip"):
            val = tool_input.get(key, "")
            if val:
                return self._extract_host(val)
        # Try to find an IP in the result string
        ip_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", result_str)
        if ip_match:
            return ip_match.group(1)
        # Fall back to first host in graph
        snapshot = self.gs.to_cytoscape_dict()
        for node in snapshot["nodes"]:
            if node.get("type") == "host":
                return node.get("ip", node["id"].replace("host:", ""))
        return "unknown"

    # Map tool names to handlers
    _handlers = {
        "nmap_scan": _handle_nmap,
        "nuclei_scan": _handle_nuclei,
        "ffuf_scan": _handle_ffuf,
        "sqlmap_scan": _handle_sqlmap,
        "shell_command": _handle_shell_command,
        "generate_report": _handle_generate_report,
    }
