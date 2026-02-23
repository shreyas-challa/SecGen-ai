"""
tools/http_tool.py — Raw HTTP request tool via the requests library.

SSL verification is disabled (pentest context — target may have self-signed certs).
Response body is capped at 50 KB.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import urllib3
import requests
from requests.exceptions import RequestException

from scope import ScopeEnforcer

# Suppress the InsecureRequestWarning that fires when verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BODY_CAP = 50 * 1024  # 50 KB
_ALLOWED_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def run_http_request(
    url: str,
    method: str,
    headers: Optional[Dict[str, str]],
    body: Optional[str],
    follow_redirects: bool,
    timeout_seconds: int,
    scope: ScopeEnforcer,
    dry_run: bool = False,
) -> str:
    """Send an HTTP request and return a JSON string with the response details."""
    scope.validate(url)

    if dry_run:
        return json.dumps({"dry_run": True, "tool": "http_request", "url": url})

    method = (method or "GET").upper()
    if method not in _ALLOWED_METHODS:
        return json.dumps({"error": f"Unsupported HTTP method: {method}"})

    req_headers = headers or {}
    # Set a descriptive User-Agent if none provided
    req_headers.setdefault(
        "User-Agent",
        "SecurityAgent/1.0 (Authorized Penetration Test)",
    )

    start = time.monotonic()
    redirect_history: list = []

    try:
        response = requests.request(
            method=method,
            url=url,
            headers=req_headers,
            data=body.encode() if body else None,
            allow_redirects=follow_redirects,
            verify=False,
            timeout=timeout_seconds,
            stream=True,
        )
    except requests.exceptions.ConnectionError as exc:
        return json.dumps({"error": f"Connection error: {exc}", "url": url})
    except requests.exceptions.Timeout:
        return json.dumps({"error": "Request timed out", "url": url})
    except RequestException as exc:
        return json.dumps({"error": str(exc), "url": url})

    elapsed_ms = int((time.monotonic() - start) * 1000)

    # Build redirect history
    for r in response.history:
        redirect_history.append({
            "url": r.url,
            "status_code": r.status_code,
        })

    # Read body with cap
    try:
        raw_body = response.raw.read(_BODY_CAP + 1, decode_content=True)
        truncated = len(raw_body) > _BODY_CAP
        body_bytes = raw_body[:_BODY_CAP]
        body_text = body_bytes.decode("utf-8", errors="replace")
    except Exception:
        body_text = ""
        truncated = False

    result: Dict[str, Any] = {
        "url": response.url,
        "method": method,
        "status_code": response.status_code,
        "response_headers": dict(response.headers),
        "body": body_text,
        "body_length": len(body_bytes) if 'body_bytes' in dir() else 0,
        "body_truncated": truncated,
        "elapsed_ms": elapsed_ms,
        "redirect_history": redirect_history,
    }

    return json.dumps(result)
