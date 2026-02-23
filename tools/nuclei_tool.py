"""
tools/nuclei_tool.py — Nuclei subprocess wrapper with JSONL output parser.

Scope is validated before any network call.
"""
from __future__ import annotations

import json
import subprocess
from typing import Any, Dict, List, Optional

from scope import ScopeEnforcer


def run_nuclei(
    target: str,
    templates: Optional[List[str]],
    severity: Optional[List[str]],
    extra_flags: Optional[str],
    timeout_seconds: int,
    nuclei_path: str,
    nuclei_templates_path: Optional[str],
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Run nuclei against *target* and return structured JSON."""
    scope.validate(target)

    if dry_run:
        return json.dumps({"dry_run": True, "tool": "nuclei", "target": target})

    cmd: List[str] = [nuclei_path, "-target", target, "-json", "-silent"]

    if templates:
        for tmpl in templates:
            if nuclei_templates_path and not tmpl.startswith("/"):
                import os
                tmpl = os.path.join(nuclei_templates_path, tmpl)
            cmd += ["-t", tmpl]

    if severity:
        cmd += ["-severity", ",".join(severity)]

    if extra_flags:
        cmd += extra_flags.split()

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nuclei timed out", "command": " ".join(cmd)})
    except FileNotFoundError:
        return json.dumps({"error": f"nuclei binary not found at: {nuclei_path}"})

    findings: List[Dict[str, Any]] = []
    parse_errors: List[str] = []

    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            parse_errors.append(line[:200])

    result: Dict[str, Any] = {
        "command": " ".join(cmd),
        "findings": findings,
        "finding_count": len(findings),
    }
    if parse_errors:
        result["parse_errors"] = parse_errors
    if proc.returncode not in (0, 1) and proc.stderr:
        result["stderr"] = proc.stderr[:2000]

    return json.dumps(result)
