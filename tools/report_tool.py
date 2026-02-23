"""
tools/report_tool.py — Generates the final penetration test report in Markdown.

Findings are sorted by severity: Critical → High → Medium → Low → Info.
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

    md = _render_report(target, executive_summary, sorted_findings, methodology_notes, timestamp)

    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(md)

    return json.dumps({
        "status": "success",
        "report_path": report_path,
        "finding_count": len(findings),
        "severities": _severity_summary(sorted_findings),
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
