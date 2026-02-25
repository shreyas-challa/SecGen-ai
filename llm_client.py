"""
llm_client.py — Unified LLM client abstraction for Anthropic and OpenRouter.

Provides a single interface so agent.py doesn't care which provider is used.
OpenRouter uses the OpenAI-compatible API but hosts Claude models with
much higher rate limits.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ------------------------------------------------------------------ #
# Normalized response types                                            #
# ------------------------------------------------------------------ #

@dataclass
class Usage:
    input_tokens: int = 0
    output_tokens: int = 0
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0


@dataclass
class TextBlock:
    type: str = "text"
    text: str = ""


@dataclass
class ToolUseBlock:
    type: str = "tool_use"
    id: str = ""
    name: str = ""
    input: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    content: List[Any] = field(default_factory=list)  # List of TextBlock | ToolUseBlock
    stop_reason: str = "end_turn"
    usage: Usage = field(default_factory=Usage)


# ------------------------------------------------------------------ #
# Tool definition converters                                           #
# ------------------------------------------------------------------ #

def _anthropic_tools_to_openai(tools: List[Dict], add_cache_control: bool = False) -> List[Dict]:
    """Convert Anthropic tool schemas to OpenAI function-calling format."""
    openai_tools = []
    for tool in tools:
        openai_tools.append({
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "parameters": tool.get("input_schema", {}),
            },
        })
    # Mark last tool for caching — everything up to and including it will be cached
    if add_cache_control and openai_tools:
        openai_tools[-1] = {**openai_tools[-1], "cache_control": {"type": "ephemeral"}}
    return openai_tools


def _anthropic_messages_to_openai(
    messages: List[Dict], system: str, use_cache: bool = False
) -> List[Dict]:
    """
    Convert Anthropic message format to OpenAI format.

    Key differences:
    - System prompt becomes a system message
    - Tool results go from user message with tool_result blocks
      to separate tool-role messages
    - Assistant tool_use blocks become tool_calls
    """
    openai_msgs: List[Dict] = []

    if system:
        if use_cache:
            # Array form required for cache_control to be forwarded to Anthropic
            openai_msgs.append({
                "role": "system",
                "content": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            })
        else:
            openai_msgs.append({"role": "system", "content": system})

    for msg in messages:
        role = msg["role"]
        content = msg["content"]

        if role == "user":
            if isinstance(content, str):
                openai_msgs.append({"role": "user", "content": content})
            elif isinstance(content, list):
                # Check if these are tool_result blocks
                tool_results = [
                    b for b in content
                    if isinstance(b, dict) and b.get("type") == "tool_result"
                ]
                if tool_results:
                    for tr in tool_results:
                        openai_msgs.append({
                            "role": "tool",
                            "tool_call_id": tr["tool_use_id"],
                            "content": tr.get("content", ""),
                        })
                else:
                    # Regular content blocks
                    text_parts = []
                    for b in content:
                        if isinstance(b, dict) and b.get("type") == "text":
                            text_parts.append(b.get("text", ""))
                        elif isinstance(b, str):
                            text_parts.append(b)
                    openai_msgs.append({"role": "user", "content": "\n".join(text_parts)})

        elif role == "assistant":
            # Convert Anthropic content blocks to OpenAI format
            text_content = ""
            tool_calls = []

            if isinstance(content, list):
                for block in content:
                    # Handle both dict and object forms
                    if hasattr(block, "type"):
                        block_type = block.type
                    elif isinstance(block, dict):
                        block_type = block.get("type", "")
                    else:
                        continue

                    if block_type == "text":
                        t = block.text if hasattr(block, "text") else block.get("text", "")
                        text_content += t
                    elif block_type == "tool_use":
                        name = block.name if hasattr(block, "name") else block.get("name", "")
                        bid = block.id if hasattr(block, "id") else block.get("id", "")
                        inp = block.input if hasattr(block, "input") else block.get("input", {})
                        tool_calls.append({
                            "id": bid,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(inp),
                            },
                        })
            elif isinstance(content, str):
                text_content = content

            msg_dict: Dict[str, Any] = {"role": "assistant"}
            msg_dict["content"] = text_content or None
            if tool_calls:
                msg_dict["tool_calls"] = tool_calls
            openai_msgs.append(msg_dict)

    return openai_msgs


# ------------------------------------------------------------------ #
# Provider implementations                                             #
# ------------------------------------------------------------------ #

class AnthropicProvider:
    """Direct Anthropic API client with prompt caching."""

    def __init__(self, api_key: str) -> None:
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
        self._anthropic = anthropic

    def _with_cache_control(self, system: str, tools: List[Dict]) -> tuple:
        """
        Add cache_control breakpoints to system prompt and the last tool definition.

        Anthropic caches all content up to and including each cache_control marker.
        By marking the system prompt and the last tool, we cache ~5K tokens that
        are identical across every iteration of the agent loop.
        """
        cached_system = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]

        # Deep-copy the last tool and add cache_control to it
        cached_tools = list(tools)
        if cached_tools:
            cached_tools[-1] = {**cached_tools[-1], "cache_control": {"type": "ephemeral"}}

        return cached_system, cached_tools

    def call(
        self,
        model: str,
        max_tokens: int,
        system: str,
        tools: List[Dict],
        messages: List[Dict],
        max_retries: int = 5,
    ) -> LLMResponse:
        cached_system, cached_tools = self._with_cache_control(system, tools)

        for attempt in range(max_retries + 1):
            try:
                response = self.client.messages.create(
                    model=model,
                    max_tokens=max_tokens,
                    system=cached_system,
                    tools=cached_tools,
                    messages=messages,
                )

                # Extract cache metrics if available
                usage_kwargs = {
                    "input_tokens": response.usage.input_tokens,
                    "output_tokens": response.usage.output_tokens,
                }
                cache_creation = getattr(response.usage, "cache_creation_input_tokens", 0) or 0
                cache_read = getattr(response.usage, "cache_read_input_tokens", 0) or 0
                if cache_creation or cache_read:
                    usage_kwargs["cache_creation_input_tokens"] = cache_creation
                    usage_kwargs["cache_read_input_tokens"] = cache_read

                return LLMResponse(
                    content=response.content,
                    stop_reason=response.stop_reason,
                    usage=Usage(**usage_kwargs),
                )
            except self._anthropic.RateLimitError:
                if attempt == max_retries:
                    raise
                wait_time = 65 * (attempt + 1)
                print(
                    f"    [!] Rate limited (attempt {attempt + 1}/{max_retries}). "
                    f"Waiting {wait_time}s...",
                    flush=True,
                )
                time.sleep(wait_time)
            except self._anthropic.APIError:
                raise


class OpenRouterProvider:
    """OpenAI-compatible provider client (OpenRouter, Dedalus Labs, etc.)."""

    _ANTHROPIC_BETA = ["prompt-caching-2024-07-31"]

    def __init__(self, api_key: str, base_url: str = "https://openrouter.ai/api/v1") -> None:
        from openai import OpenAI
        self.client = OpenAI(
            base_url=base_url,
            api_key=api_key,
        )
        self._openai = __import__("openai")

    @staticmethod
    def _is_claude(model: str) -> bool:
        return "anthropic" in model.lower() or "claude" in model.lower()

    def call(
        self,
        model: str,
        max_tokens: int,
        system: str,
        tools: List[Dict],
        messages: List[Dict],
        max_retries: int = 3,
    ) -> LLMResponse:
        use_cache = self._is_claude(model)
        openai_messages = _anthropic_messages_to_openai(messages, system, use_cache=use_cache)
        openai_tools = _anthropic_tools_to_openai(tools, add_cache_control=use_cache)

        extra_body: Dict[str, Any] = {}
        if use_cache:
            extra_body["anthropic_beta"] = self._ANTHROPIC_BETA

        for attempt in range(max_retries + 1):
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    max_tokens=max_tokens,
                    messages=openai_messages,
                    tools=openai_tools,
                    **({"extra_body": extra_body} if extra_body else {}),
                )
                return self._normalize_response(response)
            except self._openai.RateLimitError:
                if attempt == max_retries:
                    raise
                wait_time = 30 * (attempt + 1)
                print(
                    f"    [!] Rate limited (attempt {attempt + 1}/{max_retries}). "
                    f"Waiting {wait_time}s...",
                    flush=True,
                )
                time.sleep(wait_time)
            except self._openai.APIError:
                raise

    def _normalize_response(self, response) -> LLMResponse:
        """Convert OpenAI response to our normalized format."""
        choice = response.choices[0]
        message = choice.message

        content: List[Any] = []

        if message.content:
            content.append(TextBlock(text=message.content))

        if message.tool_calls:
            for tc in message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except (json.JSONDecodeError, TypeError):
                    args = {}
                content.append(ToolUseBlock(
                    id=tc.id,
                    name=tc.function.name,
                    input=args,
                ))

        stop_reason_map = {
            "stop": "end_turn",
            "tool_calls": "tool_use",
            "length": "max_tokens",
        }
        stop_reason = stop_reason_map.get(choice.finish_reason, choice.finish_reason or "end_turn")

        usage = Usage()
        if response.usage:
            usage.input_tokens = response.usage.prompt_tokens or 0
            usage.output_tokens = response.usage.completion_tokens or 0
            # OpenRouter returns cache metrics for Anthropic models in prompt_tokens_details
            details = getattr(response.usage, "prompt_tokens_details", None)
            if details:
                cached = getattr(details, "cached_tokens", 0) or 0
                if cached:
                    usage.cache_read_input_tokens = cached
                    usage.input_tokens = max(0, usage.input_tokens - cached)

        return LLMResponse(
            content=content,
            stop_reason=stop_reason,
            usage=usage,
        )


# ------------------------------------------------------------------ #
# Factory                                                              #
# ------------------------------------------------------------------ #

def create_llm_client(provider: str, api_key: str) -> Any:
    """
    Create an LLM client for the given provider.

    provider: "anthropic", "openrouter", or "dedalus"
    api_key: the API key for that provider
    """
    if provider == "openrouter":
        return OpenRouterProvider(api_key, base_url="https://openrouter.ai/api/v1")
    elif provider == "dedalus":
        return OpenRouterProvider(api_key, base_url="https://api.dedaluslabs.ai/v1")
    else:
        return AnthropicProvider(api_key)
