"""
session_log.py — JSONL audit logger for every tool call, result, and Claude message.

Each session produces a file:
    <output_dir>/session_<sanitized_target>_<timestamp>.jsonl

Every line is a self-contained JSON object, making the log easy to parse,
grep, or stream into a SIEM.
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize(target: str) -> str:
    """Make a target string safe for use in a filename."""
    return re.sub(r"[^\w\-.]", "_", target)[:64]


class SessionLogger:
    """Thread-safe JSONL logger for a single agent session."""

    def __init__(self, output_dir: str, target: str) -> None:
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"session_{_sanitize(target)}_{timestamp}.jsonl"
        self.log_path = os.path.join(output_dir, filename)
        self._lock = threading.Lock()
        self._write({"event": "session_start", "target": target, "timestamp": _now_iso()})

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def log_claude_message(
        self,
        role: str,
        content: Any,
        iteration: Optional[int] = None,
        stop_reason: Optional[str] = None,
        usage: Optional[Dict] = None,
    ) -> None:
        self._write(
            {
                "event": "claude_message",
                "role": role,
                "content": content,
                "iteration": iteration,
                "stop_reason": stop_reason,
                "usage": usage,
                "timestamp": _now_iso(),
            }
        )

    def log_tool_call(
        self,
        tool_use_id: str,
        tool_name: str,
        tool_input: Dict,
        iteration: Optional[int] = None,
    ) -> None:
        self._write(
            {
                "event": "tool_call",
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "tool_input": tool_input,
                "iteration": iteration,
                "timestamp": _now_iso(),
            }
        )

    def log_tool_result(
        self,
        tool_use_id: str,
        tool_name: str,
        result: str,
        iteration: Optional[int] = None,
    ) -> None:
        self._write(
            {
                "event": "tool_result",
                "tool_use_id": tool_use_id,
                "tool_name": tool_name,
                "result_preview": result[:2000] if len(result) > 2000 else result,
                "result_length": len(result),
                "iteration": iteration,
                "timestamp": _now_iso(),
            }
        )

    def log_iteration(self, iteration: int, extra: Optional[Dict] = None) -> None:
        payload: Dict = {
            "event": "iteration",
            "iteration": iteration,
            "timestamp": _now_iso(),
        }
        if extra:
            payload.update(extra)
        self._write(payload)

    def log_error(
        self,
        error: str,
        context: Optional[Dict] = None,
        iteration: Optional[int] = None,
    ) -> None:
        self._write(
            {
                "event": "error",
                "error": error,
                "context": context or {},
                "iteration": iteration,
                "timestamp": _now_iso(),
            }
        )

    def log_session_end(
        self,
        reason: str,
        iterations_used: int,
        report_path: Optional[str] = None,
    ) -> None:
        self._write(
            {
                "event": "session_end",
                "reason": reason,
                "iterations_used": iterations_used,
                "report_path": report_path,
                "timestamp": _now_iso(),
            }
        )

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write(self, obj: Dict) -> None:
        line = json.dumps(obj, default=str) + "\n"
        with self._lock:
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
