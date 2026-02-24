"""
tools/report_tool.py — Generates the final penetration test report in Markdown.

Findings are sorted by severity: Critical -> High -> Medium -> Low -> Info.
Supports HTB-specific sections: attack chain, flags, shell proof, privesc.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


_SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Info": 4,
}


def generate_report(
    target: str,
    executive_summary: str,
    findings: List[Dict[str, Any]],
    methodology_notes: Optional[str],
    output_dir: str,
    flags_captured: Optional[Dict[str, str]] = None,
    attack_chain: Optional[List[Dict[str, Any]]] = None,
    shell_proof: Optional[str] = None,
    privilege_escalation: Optional[Dict[str, str]] = None,
    shell_access: Optional[Dict[str, str]] = None,
) -> str:
    """Write the markdown report to disk and return a JSON status string."""
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w\-.]", "_", target)[:64]
    filename = f"report_{safe_target}_{timestamp}.md"
    report_path = os.path.join(output_dir, filename)

    # Sort findings by severity
    sorted_findings = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "Info"), 99),
    )

    md = _render_report(
        target,
        executive_summary,
        sorted_findings,
        methodology_notes,
        timestamp,
        flags_captured=flags_captured,
        attack_chain=attack_chain,
        shell_proof=shell_proof,
        privilege_escalation=privilege_escalation,
        shell_access=shell_access,
    )

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    return json.dumps({
        "status": "success",
        "report_path": report_path,
        "finding_count": len(findings),
        "severities": _severity_summary(sorted_findings),
        "flags_captured": bool(flags_captured),
        "has_shell_access": bool(shell_access),
    })


# ------------------------------------------------------------------ #
# Rendering helpers                                                    #
# ------------------------------------------------------------------ #

def _severity_badge(severity: str) -> str:
    badges = {
        "Critical": "🔴 Critical",
        "High":     "🟠 High",
        "Medium":   "🟡 Medium",
        "Low":      "🔵 Low",
        "Info":     "⚪ Info",
    }
    return badges.get(severity, severity)


def _severity_summary(findings: List[Dict]) -> Dict[str, int]:
    summary: Dict[str, int] = {
        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0
    }
    for f in findings:
        sev = f.get("severity", "Info")
        if sev in summary:
            summary[sev] += 1
    return summary


def _render_report(
    target: str,
    executive_summary: str,
    findings: List[Dict],
    methodology_notes: Optional[str],
    timestamp: str,
    flags_captured: Optional[Dict[str, str]] = None,
    attack_chain: Optional[List[Dict[str, Any]]] = None,
    shell_proof: Optional[str] = None,
    privilege_escalation: Optional[Dict[str, str]] = None,
    shell_access: Optional[Dict[str, str]] = None,
) -> str:
    summary = _severity_summary(findings)
    date_str = datetime.now().strftime("%B %d, %Y %H:%M UTC")

    lines: List[str] = [
        f"# Penetration Test Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{target}` |",
        f"| **Date** | {date_str} |",
        f"| **Classification** | Confidential — Authorized Testing Only |",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        executive_summary,
        f"",
        f"---",
        f"",
    ]

    # ---- Attack Chain ------------------------------------------------ #
    if attack_chain:
        lines += [
            f"## Attack Chain",
            f"",
            f"| Step | Phase | Action | Result |",
            f"|------|-------|--------|--------|",
        ]
        for step in attack_chain:
            step_num = step.get("step", "?")
            phase = step.get("phase", "")
            action = step.get("action", "")
            result = step.get("result", "")
            lines.append(f"| {step_num} | {phase} | {action} | {result} |")
        lines += ["", "---", ""]

    # ---- Findings Overview ------------------------------------------- #
    lines += [
        f"## Findings Overview",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = summary.get(sev, 0)
        lines.append(f"| {_severity_badge(sev)} | {count} |")

    lines += [
        f"",
        f"### Findings Table",
        f"",
        f"| # | Title | Severity |",
        f"|---|-------|----------|",
    ]

    for i, f in enumerate(findings, 1):
        title = f.get("title", "Untitled")
        sev = f.get("severity", "Info")
        lines.append(f"| {i} | {title} | {_severity_badge(sev)} |")

    lines += ["", "---", "", "## Detailed Findings", ""]

    for i, f in enumerate(findings, 1):
        title = f.get("title", "Untitled")
        sev = f.get("severity", "Info")
        description = f.get("description", "")
        evidence = f.get("evidence", "")
        poc = f.get("poc", "")
        remediation = f.get("remediation", "")

        lines += [
            f"### {i}. {title}",
            f"",
            f"**Severity:** {_severity_badge(sev)}",
            f"",
            f"#### Description",
            f"",
            description,
            f"",
        ]

        if evidence:
            lines += [
                f"#### Evidence",
                f"",
                f"```",
                evidence,
                f"```",
                f"",
            ]

        if poc:
            lines += [
                f"#### Proof of Concept",
                f"",
                poc,
                f"",
            ]

        if remediation:
            lines += [
                f"#### Remediation",
                f"",
                remediation,
                f"",
            ]

        lines += ["---", ""]

    # ---- Privilege Escalation ---------------------------------------- #
    if privilege_escalation:
        vector = privilege_escalation.get("vector", "Unknown")
        desc = privilege_escalation.get("description", "")
        evidence = privilege_escalation.get("evidence", "")
        lines += [
            f"## Privilege Escalation",
            f"",
            f"**Vector:** {vector}",
            f"",
            desc,
            f"",
        ]
        if evidence:
            lines += [
                f"```",
                evidence,
                f"```",
                f"",
            ]
        lines += ["---", ""]

    # ---- Flags Captured ---------------------------------------------- #
    if flags_captured:
        user_flag = flags_captured.get("user_flag", "—")
        root_flag = flags_captured.get("root_flag", "—")
        lines += [
            f"## Flags Captured",
            f"",
            f"| Flag | Value |",
            f"|------|-------|",
            f"| **user.txt** | `{user_flag}` |",
            f"| **root.txt** | `{root_flag}` |",
            f"",
            f"---",
            f"",
        ]

    # ---- Shell Proof ------------------------------------------------- #
    if shell_proof:
        lines += [
            f"## Shell Proof",
            f"",
            f"```",
            shell_proof,
            f"```",
            f"",
            f"---",
            f"",
        ]

    # ---- Shell Access ------------------------------------------------ #
    if shell_access:
        method = shell_access.get("method", "Unknown")
        conn_info = shell_access.get("connection_info", "")
        lines += [
            f"## Shell Access",
            f"",
            f"**Method:** {method}",
            f"",
            f"```",
            conn_info,
            f"```",
            f"",
            f"---",
            f"",
        ]

    # ---- Methodology Notes ------------------------------------------- #
    if methodology_notes:
        lines += [
            f"## Methodology Notes",
            f"",
            methodology_notes,
            f"",
            f"---",
            f"",
        ]

    lines += [
        f"## Disclaimer",
        f"",
        f"This report was generated by an AI-assisted penetration testing agent "
        f"for authorized security assessment purposes only. All testing was "
        f"conducted within the defined scope. Unauthorized use of this information "
        f"is prohibited.",
        f"",
        f"*Generated by SecurityAgent powered by Claude*",
    ]

    return "\n".join(lines)
