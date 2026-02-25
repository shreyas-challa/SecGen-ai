"""
tools/nmap_tool.py — nmap subprocess wrapper with XML → JSON parsing.

Scope is checked at the top of run_nmap() before any network activity.

Windows compatibility:
  - nmap on Windows often crashes (ACCESS_VIOLATION / 0xC0000005) when
    using ``-oX -`` (XML output to stdout). If XML mode fails on Windows,
    we automatically retry with normal text output and parse that instead.
  - ``--unprivileged`` is added on Windows to avoid raw-socket issues
    when not running as Administrator.
"""
from __future__ import annotations

import json
import os
import platform
import re
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional

from scope import ScopeEnforcer

_IS_WINDOWS = platform.system() == "Windows"

# Map friendly scan_type names to nmap flag lists
_SCAN_TYPE_FLAGS: Dict[str, List[str]] = {
    "stealth":  ["-sS", "-T4"],
    "connect":  ["-sT", "-T4"],
    "udp":      ["-sU", "-T4"],
    "vuln":     ["-sV", "-sC", "--script=vuln", "-T4"],
    "version":  ["-sV", "-sC", "-T4"],
}

# On Windows, stealth/SYN scan requires raw sockets (admin).
# Automatically fall back to connect scan.
if _IS_WINDOWS:
    _SCAN_TYPE_FLAGS["stealth"] = ["-sT", "-T4"]


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

    # If the caller passed raw flags covering scan options, skip the scan_type defaults
    # to avoid duplicating flags like -sV or -T4.
    if extra_flags and any(f in extra_flags for f in ("-sS", "-sT", "-sU", "-sV", "-sC")):
        base_flags: List[str] = []
    else:
        base_flags = list(_SCAN_TYPE_FLAGS.get(scan_type, ["-sV", "-T4"]))

    # On Windows: replace -sS with -sT if present (requires admin for raw sockets)
    if _IS_WINDOWS:
        base_flags = ["-sT" if f == "-sS" else f for f in base_flags]
        if extra_flags:
            extra_flags = extra_flags.replace("-sS", "-sT")

    # Build extra flags list
    extra_list: List[str] = extra_flags.split() if extra_flags else []

    # On Windows: strip flags that always require root/admin and cause nmap to abort
    # immediately before any scanning.  Return an informative error instead of letting
    # nmap quit with "requires root privileges" after wasting a full iteration.
    if _IS_WINDOWS:
        privileged_flags = {"-O", "--osscan-guess", "--osscan-limit"}
        stripped = [f for f in extra_list if f not in privileged_flags]
        if len(stripped) < len(extra_list):
            removed = set(extra_list) - set(stripped)
            # Return early with a clear message so Claude doesn't retry the same call
            return json.dumps({
                "error": "WINDOWS_PRIVILEGE_REQUIRED",
                "message": (
                    f"Flags {sorted(removed)} require Administrator/root on Windows and were not run. "
                    "Re-run without those flags. "
                    "Use 'udp' scan_type or skip OS detection — use banner-grabbing instead."
                ),
                "stripped_flags": sorted(removed),
                "hint": "Retry the scan without -O. Service versions (-sV) give sufficient info.",
            })
        # Also handle -sU in extra_list (UDP requires raw sockets on Windows)
        if "-sU" in extra_list:
            return json.dumps({
                "error": "WINDOWS_PRIVILEGE_REQUIRED",
                "message": (
                    "-sU (UDP scan) requires Administrator/root on Windows. "
                    "Skip UDP enumeration or run nmap as Administrator."
                ),
                "hint": "Use scan_type='connect' or 'version' for TCP enumeration instead.",
            })
        extra_list = stripped

    # On Windows: add --unprivileged if not running as admin, to avoid crashes
    if _IS_WINDOWS and "--unprivileged" not in extra_list and "--privileged" not in extra_list:
        extra_list.append("--unprivileged")

    # Strategy 1: Try XML output to a temp file (avoids -oX - stdout crash on Windows)
    # Strategy 2: If XML fails, fall back to normal text output
    result_str = _try_nmap_xml_file(
        nmap_path, base_flags, ports, extra_list, target, timeout_seconds
    )
    if result_str is not None:
        return result_str

    # Strategy 2: Fall back to text output parsing
    return _try_nmap_text(
        nmap_path, base_flags, ports, extra_list, target, timeout_seconds
    )


def _try_nmap_xml_file(
    nmap_path: str,
    base_flags: List[str],
    ports: Optional[str],
    extra_list: List[str],
    target: str,
    timeout_seconds: int,
) -> Optional[str]:
    """
    Run nmap with XML output to a temp file instead of stdout.
    Returns JSON string on success, None if nmap crashes.
    """
    # Create a temp file for XML output
    try:
        tmp = tempfile.NamedTemporaryFile(
            suffix=".xml", prefix="nmap_", delete=False
        )
        xml_path = tmp.name
        tmp.close()
    except Exception:
        return None

    try:
        cmd: List[str] = [nmap_path] + base_flags + ["-oX", xml_path]

        # If extra_list already contain a -p specification, don't add ports separately
        if ports and not any(f.startswith("-p") for f in extra_list):
            cmd += ["-p", ports]

        cmd += extra_list
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

        # Check for crash (ACCESS_VIOLATION on Windows = 0xC0000005 = 3221225477 unsigned)
        if proc.returncode not in (0, 1):
            # nmap crashed — return None so caller tries text fallback
            return None

        # Read the XML file
        try:
            with open(xml_path, "r", encoding="utf-8", errors="replace") as f:
                xml_output = f.read()
        except Exception:
            xml_output = ""

        if not xml_output.strip():
            # XML file empty — try text fallback
            return None

        return json.dumps(_parse_nmap_xml(xml_output, " ".join(cmd)))

    finally:
        # Clean up temp file
        try:
            os.unlink(xml_path)
        except Exception:
            pass


def _try_nmap_text(
    nmap_path: str,
    base_flags: List[str],
    ports: Optional[str],
    extra_list: List[str],
    target: str,
    timeout_seconds: int,
) -> str:
    """
    Fallback: run nmap with normal text output (no -oX) and parse the text.
    This is used when XML output crashes nmap on Windows.
    """
    # Remove any -oX flags from extra_list
    clean_extra = [f for f in extra_list if f != "-oX" and not f.endswith(".xml")]

    # Also try removing -sC which can cause crashes on some Windows nmap builds
    # Keep -sV for version detection
    safe_base = [f for f in base_flags if f != "-sC"]

    cmd: List[str] = [nmap_path] + safe_base

    if ports and not any(f.startswith("-p") for f in clean_extra):
        cmd += ["-p", ports]

    cmd += clean_extra
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
        # Even text mode crashed — return error with details
        return json.dumps({
            "error": "nmap crashed (text fallback also failed)",
            "returncode": proc.returncode,
            "stderr": proc.stderr[:2000],
            "command": " ".join(cmd),
            "hint": (
                "nmap is crashing on this system. Try: "
                "(1) Update nmap to latest version, "
                "(2) Run as Administrator, "
                "(3) Use shell_command with a simpler nmap invocation."
            ),
        })

    output = proc.stdout
    if not output.strip():
        output = proc.stderr  # Some nmap versions write to stderr

    return json.dumps(_parse_nmap_text(output, " ".join(cmd)))


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


def _parse_nmap_text(text_output: str, command: str) -> Dict[str, Any]:
    """
    Parse nmap normal text output into a structured dict.
    This is the fallback when XML output is unavailable (Windows crash workaround).
    """
    result: Dict[str, Any] = {"command": command, "hosts": [], "parse_mode": "text_fallback"}

    if not text_output.strip():
        result["error"] = "nmap produced no output"
        return result

    host: Dict[str, Any] = {
        "ip": "",
        "hostname": "",
        "state": "",
        "ports": [],
    }

    # Extract target IP from "Nmap scan report for <ip>" line
    report_match = re.search(r"Nmap scan report for (\S+)", text_output)
    if report_match:
        target_str = report_match.group(1)
        # Could be "hostname (ip)" or just "ip"
        ip_in_parens = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", text_output)
        if ip_in_parens:
            host["ip"] = ip_in_parens.group(1)
            host["hostname"] = target_str
        else:
            host["ip"] = target_str

    # Check host state
    if "Host is up" in text_output:
        host["state"] = "up"

    # Parse PORT lines: "21/tcp   open  ftp     vsftpd 3.0.3"
    # Pattern: port/proto  state  service  [version info]
    port_pattern = re.compile(
        r"^(\d+)/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)\s*(.*)",
        re.MULTILINE,
    )
    for match in port_pattern.finditer(text_output):
        port_num, proto, state, service, version_str = match.groups()
        host["ports"].append({
            "port": port_num,
            "protocol": proto,
            "state": state,
            "service": service,
            "version": version_str.strip(),
            "scripts": {},
        })

    result["hosts"].append(host)

    # Also include raw output head for context the agent can use
    result["raw_output_head"] = text_output[:3000]

    return result
