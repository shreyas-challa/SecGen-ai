"""
tools/ffuf_tool.py — ffuf subprocess wrapper with structured JSON output.

Scope is validated before execution.
Temp output file is always cleaned up.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from scope import ScopeEnforcer


def run_ffuf(
    target: str,
    scan_mode: str,
    wordlist: Optional[str],
    extensions: Optional[str],
    filter_status: str,
    threads: int,
    timeout_seconds: int,
    ffuf_path: str,
    default_wordlist: str,
    subdomains_wordlist: str,
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Run ffuf in directory or subdomain mode and return structured JSON."""
    scope.validate(target)

    if dry_run:
        return json.dumps({"dry_run": True, "tool": "ffuf", "target": target, "mode": scan_mode})

    wl = wordlist or (subdomains_wordlist if scan_mode == "subdomain" else default_wordlist)

    # Build the URL with FUZZ placeholder
    if scan_mode == "directory":
        base_url = target.rstrip("/")
        if not base_url.startswith("http"):
            base_url = "http://" + base_url
        fuzz_url = base_url + "/FUZZ"
    else:
        # Subdomain mode: FUZZ.target or Host header fuzzing
        domain = target.lstrip("http://").lstrip("https://").split("/")[0]
        fuzz_url = f"http://FUZZ.{domain}"

    output_fd, output_path = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
    os.close(output_fd)

    cmd: List[str] = [
        ffuf_path,
        "-u", fuzz_url,
        "-w", wl,
        "-of", "json",
        "-o", output_path,
        "-t", str(threads),
        "-fc", filter_status or "404",
        "-s",  # silent — suppress banner
    ]

    if scan_mode == "directory" and extensions:
        cmd += ["-e", extensions]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        _cleanup(output_path)
        return json.dumps({"error": "ffuf timed out", "command": " ".join(cmd)})
    except FileNotFoundError:
        _cleanup(output_path)
        return json.dumps({"error": f"ffuf binary not found at: {ffuf_path}"})

    result: Dict[str, Any] = {"command": " ".join(cmd), "results": []}

    try:
        with open(output_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        raw_results = data.get("results", [])
        for r in raw_results:
            result["results"].append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
            })
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        result["error"] = "Failed to parse ffuf output"
        if proc.stderr:
            result["stderr"] = proc.stderr[:1000]

    _cleanup(output_path)
    return json.dumps(result)


def _cleanup(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass
