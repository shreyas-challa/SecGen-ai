"""
tools/http_tool.py — Raw HTTP request tool via the requests library.

SSL verification is disabled (pentest context — target may have self-signed certs).
Response body is capped at 50 KB for text responses.

Binary responses (pcap, images, executables, etc.) are automatically detected
via Content-Type and saved to disk. The JSON result includes the file path
instead of garbled binary data, plus a hex dump of the first 512 bytes and
any printable strings found in the content.
"""
from __future__ import annotations

import base64
import json
import os
import re
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

# Content-Types that indicate binary data
_BINARY_CONTENT_TYPES = {
    "application/octet-stream",
    "application/vnd.tcpdump.pcap",
    "application/x-pcap",
    "application/cap",
    "application/pcap",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-tar",
    "application/x-gzip",
    "application/x-bzip2",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
    "application/x-executable",
    "application/x-mach-binary",
    "application/x-elf",
    "application/x-dosexec",
    "audio/mpeg",
    "video/mp4",
}

# File extensions to force binary treatment
_BINARY_EXTENSIONS = {
    ".pcap", ".pcapng", ".cap", ".png", ".jpg", ".jpeg", ".gif",
    ".pdf", ".zip", ".gz", ".tar", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".bin", ".img", ".iso",
    ".mp3", ".mp4", ".avi", ".mkv", ".wav",
}

# Save directory for downloaded binary files
_DOWNLOAD_DIR = os.path.join("output", "downloads")


def _is_binary_response(content_type: str, url: str, body_bytes: bytes) -> bool:
    """Detect whether a response is binary based on Content-Type, URL, and content."""
    ct_lower = content_type.lower().split(";")[0].strip()

    # Check Content-Type
    if ct_lower in _BINARY_CONTENT_TYPES:
        return True

    # Check URL extension
    url_path = url.split("?")[0].split("#")[0]
    for ext in _BINARY_EXTENSIONS:
        if url_path.lower().endswith(ext):
            return True

    # Check for binary content: if >30% of bytes are non-text, it's binary
    if len(body_bytes) > 32:
        non_text = sum(
            1 for b in body_bytes[:1024]
            if b < 0x09 or (0x0E <= b <= 0x1F) or b == 0x7F
        )
        if non_text / min(len(body_bytes), 1024) > 0.30:
            return True

    return False


def _extract_strings(data: bytes, min_length: int = 4) -> list:
    """Extract printable ASCII strings from binary data (like the `strings` command)."""
    strings = []
    current = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:  # printable ASCII
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        strings.append("".join(current))
    return strings


def _save_binary_file(body_bytes: bytes, url: str, content_type: str) -> str:
    """Save binary response body to disk and return the file path."""
    os.makedirs(_DOWNLOAD_DIR, exist_ok=True)

    # Derive filename from URL
    url_path = url.split("?")[0].split("#")[0]
    basename = url_path.rstrip("/").split("/")[-1] or "download"

    # Add extension based on content type if missing
    if "." not in basename:
        ct_lower = content_type.lower().split(";")[0].strip()
        ext_map = {
            "application/vnd.tcpdump.pcap": ".pcap",
            "application/x-pcap": ".pcap",
            "application/octet-stream": ".bin",
            "application/pcap": ".pcap",
            "application/cap": ".pcap",
            "image/png": ".png",
            "image/jpeg": ".jpg",
            "application/pdf": ".pdf",
            "application/zip": ".zip",
        }
        ext = ext_map.get(ct_lower, ".bin")
        basename += ext

    # Avoid overwriting: append counter if file exists
    filepath = os.path.join(_DOWNLOAD_DIR, basename)
    counter = 1
    while os.path.exists(filepath):
        name, ext = os.path.splitext(basename)
        filepath = os.path.join(_DOWNLOAD_DIR, f"{name}_{counter}{ext}")
        counter += 1

    with open(filepath, "wb") as f:
        f.write(body_bytes)

    return filepath


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
    body_bytes = b""
    body_text = ""
    truncated = False
    try:
        raw_body = response.raw.read(_BODY_CAP + 1, decode_content=True)
        truncated = len(raw_body) > _BODY_CAP
        body_bytes = raw_body[:_BODY_CAP]
    except Exception:
        body_bytes = b""

    content_type = response.headers.get("Content-Type", "")

    # Check if this is a binary response
    if body_bytes and _is_binary_response(content_type, url, body_bytes):
        # Save binary file to disk
        filepath = _save_binary_file(body_bytes, url, content_type)

        # Extract printable strings for analysis (like the `strings` command)
        extracted_strings = _extract_strings(body_bytes, min_length=4)
        # Limit to most useful strings
        useful_strings = extracted_strings[:100]

        # Look specifically for credential-like patterns in strings
        credential_hints = []
        for s in extracted_strings:
            s_lower = s.lower()
            if any(kw in s_lower for kw in ("user", "pass", "login", "ftp", "ssh", "admin", "root", "secret", "token", "key")):
                credential_hints.append(s)

        result: Dict[str, Any] = {
            "url": response.url,
            "method": method,
            "status_code": response.status_code,
            "response_headers": dict(response.headers),
            "binary_response": True,
            "content_type": content_type,
            "saved_to": filepath,
            "file_size_bytes": len(body_bytes),
            "body_truncated": truncated,
            "elapsed_ms": elapsed_ms,
            "redirect_history": redirect_history,
            "extracted_strings": useful_strings,
            "credential_hints": credential_hints[:20],
            "hex_dump_head": body_bytes[:256].hex(" "),
            "analysis_hint": (
                f"Binary file saved to {filepath}. "
                "To analyze a pcap file, use shell_command with: "
                f"python -c \"from scapy.all import *; pkts=rdpcap('{filepath}'); "
                "for p in pkts: print(p.summary())\" "
                "or: tshark -r " + filepath + " -Y 'ftp || http || tcp.stream' "
                "or check the extracted_strings and credential_hints fields above."
            ),
        }
    else:
        # Text response — decode normally
        body_text = body_bytes.decode("utf-8", errors="replace")
        result = {
            "url": response.url,
            "method": method,
            "status_code": response.status_code,
            "response_headers": dict(response.headers),
            "body": body_text,
            "body_length": len(body_bytes),
            "body_truncated": truncated,
            "elapsed_ms": elapsed_ms,
            "redirect_history": redirect_history,
        }

    return json.dumps(result)
