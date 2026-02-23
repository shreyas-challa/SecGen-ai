"""
tools/nmap_tool.py — nmap subprocess wrapper with XML → JSON parsing.

Scope is checked at the top of run_nmap() before any network activity.
"""
from __future__ import annotations

import json
import subprocess
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from scope import ScopeEnforcer


# Map friendly scan_type names to nmap flag lists
_SCAN_TYPE_FLAGS: Dict[str, List[str]] = {
    "stealth":  ["-sS", "-T4"],
    "connect":  ["-sT", "-T4"],
    "udp":      ["-sU", "-T4"],
    "vuln":     ["-sV", "-sC", "--script=vuln", "-T4"],
    "version":  ["-sV", "-sC", "-T4"],
}


def run_nmap(
    target: str,
    scan_type: str,
    ports: Optional[str],
    extra_flags: Optional[str],
    timeout_seconds: int,
    nmap_path: str,
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Execute nmap and return a JSON string with structured results."""
    scope.validate(target)

    if dry_run:
        return json.dumps({"dry_run": True, "tool": "nmap", "target": target})

    flags = _SCAN_TYPE_FLAGS.get(scan_type, ["-sV", "-T4"])
    cmd: List[str] = [nmap_path] + flags + ["-oX", "-"]

    if ports:
        cmd += ["-p", ports]

    if extra_flags:
        cmd += extra_flags.split()

    cmd.append(target)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nmap timed out", "command": " ".join(cmd)})
    except FileNotFoundError:
        return json.dumps({"error": f"nmap binary not found at: {nmap_path}"})

    if proc.returncode not in (0, 1):
        return json.dumps({
            "error": "nmap exited with non-zero status",
            "returncode": proc.returncode,
            "stderr": proc.stderr[:2000],
            "command": " ".join(cmd),
        })

    return json.dumps(_parse_nmap_xml(proc.stdout, " ".join(cmd)))


def _parse_nmap_xml(xml_output: str, command: str) -> Dict[str, Any]:
    """Parse nmap XML output into a Python dict."""
    result: Dict[str, Any] = {"command": command, "hosts": []}

    if not xml_output.strip():
        result["error"] = "nmap produced no output"
        return result

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        result["error"] = f"XML parse error: {exc}"
        result["raw_output_head"] = xml_output[:1000]
        return result

    for host_el in root.findall("host"):
        host: Dict[str, Any] = {
            "ip": "",
            "hostname": "",
            "state": "",
            "ports": [],
        }

        # State
        state_el = host_el.find("status")
        if state_el is not None:
            host["state"] = state_el.get("state", "")

        # Addresses
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") in ("ipv4", "ipv6"):
                host["ip"] = addr_el.get("addr", "")

        # Hostnames
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                host["hostname"] = hn.get("name", "")

        # Ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                port_info: Dict[str, Any] = {
                    "port": port_el.get("portid", ""),
                    "protocol": port_el.get("protocol", ""),
                    "state": "",
                    "service": "",
                    "version": "",
                    "scripts": {},
                }

                state_el = port_el.find("state")
                if state_el is not None:
                    port_info["state"] = state_el.get("state", "")

                service_el = port_el.find("service")
                if service_el is not None:
                    port_info["service"] = service_el.get("name", "")
                    parts = [
                        service_el.get("product", ""),
                        service_el.get("version", ""),
                        service_el.get("extrainfo", ""),
                    ]
                    port_info["version"] = " ".join(p for p in parts if p).strip()

                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    script_out = script_el.get("output", "")
                    port_info["scripts"][script_id] = script_out

                host["ports"].append(port_info)

        result["hosts"].append(host)

    return result
