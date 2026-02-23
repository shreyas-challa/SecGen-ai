"""
tools/sqlmap_tool.py — sqlmap subprocess wrapper.

Runs non-interactively (--batch). Scope is validated on the URL before execution.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scope import ScopeEnforcer


def run_sqlmap(
    url: str,
    parameter: Optional[str],
    level: int,
    risk: int,
    dump_tables: bool,
    extra_flags: Optional[str],
    timeout_seconds: int,
    sqlmap_path: str,
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Run sqlmap against *url* and return structured JSON."""
    scope.validate(url)

    if dry_run:
        return json.dumps({"dry_run": True, "tool": "sqlmap", "url": url})

    output_dir = tempfile.mkdtemp(prefix="sqlmap_output_")

    cmd: List[str] = [
        sqlmap_path,
        "-u", url,
        "--batch",
        "--level", str(max(1, min(5, level))),
        "--risk", str(max(1, min(3, risk))),
        "--output-dir", output_dir,
    ]

    if parameter:
        cmd += ["-p", parameter]

    if dump_tables:
        cmd += ["--dump"]

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
        return json.dumps({"error": "sqlmap timed out", "command": " ".join(cmd)})
    except FileNotFoundError:
        return json.dumps({"error": f"sqlmap binary not found at: {sqlmap_path}"})

    stdout = proc.stdout or ""
    result: Dict[str, Any] = {
        "command": " ".join(cmd),
        "vulnerable": False,
        "injections": [],
        "raw_output": stdout[:5000],
    }

    # Parse vulnerability indicators from stdout
    result["vulnerable"] = _is_vulnerable(stdout)
    result["injections"] = _extract_injections(stdout)

    return json.dumps(result)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

_VULN_PATTERNS = [
    r"is vulnerable",
    r"parameter .+ is (injectable|vulnerable)",
    r"sql injection",
    r"\[CRITICAL\]",
]

def _is_vulnerable(stdout: str) -> bool:
    lower = stdout.lower()
    return any(re.search(p, lower) for p in _VULN_PATTERNS)


def _extract_injections(stdout: str) -> List[Dict[str, str]]:
    """Extract injection point summaries from sqlmap output."""
    injections: List[Dict[str, str]] = []
    # Pattern: "Parameter: X (GET)" or "Parameter: X (POST)"
    param_re = re.compile(
        r"Parameter:\s+(.+?)\s+\((\w+)\)\n"
        r"\s+Type:\s+(.+?)\n"
        r"\s+Title:\s+(.+?)\n",
        re.DOTALL,
    )
    for m in param_re.finditer(stdout):
        injections.append({
            "parameter": m.group(1).strip(),
            "method": m.group(2).strip(),
            "type": m.group(3).strip(),
            "title": m.group(4).strip(),
        })
    return injections
