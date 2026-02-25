"""
agent.py — Core Claude tool-use agent loop for the security research agent.

The agent drives through the full pentest lifecycle by:
  1. Sending the current message history to the LLM (Anthropic or OpenRouter)
  2. Logging Claude's reasoning
  3. Dispatching any tool_use blocks to the ToolDispatcher
  4. Appending ALL tool results as a single user message (API requirement)
  5. Repeating until: end_turn with no tool calls, generate_report called,
     or max_iterations reached
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from config import Config
from llm_client import create_llm_client
from scope import ScopeEnforcer
from session_log import SessionLogger
from system_prompt import build_system_prompt
from tools.definitions import TOOL_DEFINITIONS
from tools.dispatcher import ToolDispatcher
from tools.shell_tool import get_active_background_pids


class SecurityAgent:
    """Orchestrates the Claude-powered penetration test."""

    def __init__(
        self,
        config: Config,
        scope: ScopeEnforcer,
        target: str,
        session_logger: SessionLogger,
    ) -> None:
        self.config = config
        self.scope = scope
        self.target = target
        self.logger = session_logger
        self.dispatcher = ToolDispatcher(config, scope, session_logger)

        # Create the LLM client based on provider config
        api_key = (
            config.openrouter_api_key
            if config.provider == "openrouter"
            else config.anthropic_api_key
        )
        self.llm = create_llm_client(config.provider, api_key)
        self.messages: List[Dict[str, Any]] = []
        self.report_path: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def run(self) -> Optional[str]:
        """
        Execute the agent loop.

        Returns the path to the generated report (if any), or None.
        """
        scope_description = self._build_scope_description()
        system_prompt = build_system_prompt(
            target=self.target,
            scope_description=scope_description,
            mode=self.config.agent_mode,
            lhost=self.config.lhost,
            lport=self.config.lport,
        )

        # Determine iteration limit based on mode
        max_iter = self.config.max_iterations
        if self.config.agent_mode == "htb" and max_iter <= 30:
            max_iter = 50

        # HTB mode uses larger max_tokens for complex exploit reasoning
        max_tokens = 16384 if self.config.agent_mode == "htb" else 8192

        # Seed the conversation
        if self.config.agent_mode == "htb":
            initial_message = (
                f"Begin a full penetration test against HackTheBox target: {self.target}. "
                f"Goal: root access, capture user.txt and root.txt flags. "
                f"Start with Phase 1 enumeration."
            )
        else:
            initial_message = (
                f"Begin a comprehensive penetration test against: {self.target}. "
                f"Start with Phase 1 reconnaissance."
            )
        self.messages.append({"role": "user", "content": initial_message})

        generate_report_called = False
        stop_reason = "INIT"

        for iteration in range(1, max_iter + 1):
            self.logger.log_iteration(iteration)
            print(f"\n[*] Iteration {iteration}/{max_iter}", flush=True)

            # ---- Call LLM (with retry on rate limits) ---------------- #
            try:
                response = self.llm.call(
                    model=self.config.claude_model,
                    max_tokens=max_tokens,
                    system=system_prompt,
                    tools=TOOL_DEFINITIONS,
                    messages=self.messages,
                )
            except Exception as exc:
                self.logger.log_error(str(exc), context={"iteration": iteration})
                print(f"[!] API error: {exc}", flush=True)
                break

            stop_reason = response.stop_reason
            usage = {
                "input_tokens": response.usage.input_tokens,
                "output_tokens": response.usage.output_tokens,
            }
            # Include cache metrics when available (Anthropic provider only)
            if response.usage.cache_creation_input_tokens:
                usage["cache_creation_input_tokens"] = response.usage.cache_creation_input_tokens
            if response.usage.cache_read_input_tokens:
                usage["cache_read_input_tokens"] = response.usage.cache_read_input_tokens

            # Serialize content for logging / message history
            content_blocks = _serialize_content(response.content)
            self.messages.append({"role": "assistant", "content": response.content})

            self.logger.log_claude_message(
                role="assistant",
                content=content_blocks,
                iteration=iteration,
                stop_reason=stop_reason,
                usage=usage,
            )

            # Build usage display string
            usage_str = f"in={usage['input_tokens']} out={usage['output_tokens']}"
            if usage.get("cache_read_input_tokens"):
                usage_str += f" cache_read={usage['cache_read_input_tokens']}"
            if usage.get("cache_creation_input_tokens"):
                usage_str += f" cache_create={usage['cache_creation_input_tokens']}"

            print(
                f"    stop_reason={stop_reason}  {usage_str}",
                flush=True,
            )

            # ---- Extract tool_use blocks ----------------------------- #
            tool_use_blocks = [b for b in response.content if b.type == "tool_use"]

            # Print any text reasoning from Claude
            for block in response.content:
                if block.type == "text" and block.text.strip():
                    print(f"\n[Claude] {block.text[:500]}", flush=True)

            # ---- Check for natural stop ----------------------------- #
            if stop_reason == "end_turn" and not tool_use_blocks:
                print("[*] Claude finished without tool calls — stopping.", flush=True)
                break

            if not tool_use_blocks:
                # stop_reason == "max_tokens" or other — no tools to process
                break

            # ---- Dispatch all tool calls ----------------------------- #
            tool_results: List[Dict[str, Any]] = []
            report_called_this_turn = False

            for block in tool_use_blocks:
                tool_name = block.name
                tool_input = block.input
                tool_use_id = block.id

                self.logger.log_tool_call(
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    tool_input=tool_input,
                    iteration=iteration,
                )
                print(f"    -> Calling: {tool_name}({_summarize_input(tool_input)})", flush=True)

                result_str = self.dispatcher.dispatch(tool_name, tool_input)

                self.logger.log_tool_result(
                    tool_use_id=tool_use_id,
                    tool_name=tool_name,
                    result=result_str,
                    iteration=iteration,
                )

                # Capture report path if generate_report was called
                if tool_name == "generate_report":
                    report_called_this_turn = True
                    generate_report_called = True
                    try:
                        parsed = json.loads(result_str)
                        self.report_path = parsed.get("report_path")
                        print(f"    [+] Report written: {self.report_path}", flush=True)
                    except (json.JSONDecodeError, KeyError):
                        pass

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_use_id,
                    "content": result_str,
                })

            # ---- Append ALL tool results as ONE user message --------- #
            self.messages.append({"role": "user", "content": tool_results})

            # ---- Stop after report is confirmed --------------------- #
            if report_called_this_turn:
                print("[*] generate_report called — allowing one final Claude turn.", flush=True)
                try:
                    final_response = self.llm.call(
                        model=self.config.claude_model,
                        max_tokens=2048,
                        system=system_prompt,
                        tools=TOOL_DEFINITIONS,
                        messages=self.messages,
                    )
                    self.messages.append({"role": "assistant", "content": final_response.content})
                    for block in final_response.content:
                        if block.type == "text" and block.text.strip():
                            print(f"\n[Claude] {block.text[:1000]}", flush=True)
                    self.logger.log_claude_message(
                        role="assistant",
                        content=_serialize_content(final_response.content),
                        iteration=iteration + 1,
                        stop_reason=final_response.stop_reason,
                    )
                except Exception:
                    pass
                break

        # ---- Session end -------------------------------------------- #
        reason = "max_iterations" if iteration >= max_iter else stop_reason
        self.logger.log_session_end(
            reason=reason,
            iterations_used=iteration,
            report_path=self.report_path,
        )

        if self.report_path:
            print(f"\n[+] Penetration test complete. Report: {self.report_path}", flush=True)
        else:
            print("\n[!] Agent stopped without generating a report.", flush=True)

        return self.report_path

    def get_active_shells(self) -> List[int]:
        """Return list of active background process PIDs (e.g. listeners, shells)."""
        return get_active_background_pids()

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    def _build_scope_description(self) -> str:
        parts: List[str] = []
        if self.config.allowed_scope:
            parts.append("Allowed targets: " + ", ".join(self.config.allowed_scope))
        else:
            parts.append(f"Single target: {self.target}")
        return "; ".join(parts)


# ------------------------------------------------------------------ #
# Module-level helpers                                                #
# ------------------------------------------------------------------ #

def _serialize_content(content: Any) -> Any:
    """Convert Anthropic content objects to plain dicts for JSON serialization."""
    if isinstance(content, list):
        return [_serialize_content(b) for b in content]
    if hasattr(content, "__dict__"):
        return {k: _serialize_content(v) for k, v in vars(content).items()}
    return content


def _summarize_input(tool_input: Dict) -> str:
    """Produce a short one-line summary of tool input for console output."""
    parts = []
    for key, value in tool_input.items():
        if isinstance(value, str) and len(value) < 60:
            parts.append(f"{key}={value!r}")
        elif isinstance(value, (int, bool, float)):
            parts.append(f"{key}={value}")
        else:
            parts.append(f"{key}=...")
    return ", ".join(parts[:4])
