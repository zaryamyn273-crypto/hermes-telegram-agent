"""
Hermes Agent Core Engine:
Handles session-based conversational context, dynamic tool execution,
and live streaming response generation.
"""

import re
import time
import json
import logging
import asyncio
import httpx
from typing import Dict, Any, List, Optional, Tuple, AsyncIterator, Callable

from config import settings, get_candidate_endpoints, get_effective_router_url, get_effective_api_key, get_effective_model
from tools.registry import get_smart_tools, execute_tool
from utils.formatter import strip_thinking

logger = logging.getLogger("HermesAgentEngine")

# Session Conversation History: chat_id -> List of message dicts
_SESSIONS: Dict[int, List[Dict[str, Any]]] = {}

# Prometheus Agent System Instruction
PROMETHEUS_SYSTEM_PROMPT = """You are Prometheus (پرومته), an autonomous Persian AI assistant operating inside Telegram.

Operating Directives:
1. Strict Identity:
- Your name is Prometheus (پرومته).
- You were engineered and designed exclusively as Prometheus (پرومته).
- You must NEVER refer to yourself as Hermes, Nous Research, ChatGPT, Claude, or any other agent or backend project.
- If asked who you are, who created you, or what model you use, state clearly and proudly in Persian that you are Prometheus (پرومته), an autonomous AI assistant built to help users with real-time analysis, tools, and queries.

2. Language & Tone:
- Always respond naturally, natively, and fluently in Persian (فارسی) unless the user explicitly prompts in English or another language.
- Provide direct, concise, high-value, and technically sharp answers.
- Never use conversational filler ("Hello, I am Prometheus", "As an AI model"). Deliver the fact, figure, code, or answer immediately.

3. Live Tool Integration:
- You have access to real-time tools for cryptocurrency rates, currency/gold, weather, web search, webpage scraping, math calculations, and official Tehran time.
- When tool results are provided in the conversation, ALWAYS use that exact data to formulate your answer. NEVER state you lack real-time access or internet connectivity when tool data is present.

4. Formatting:
- Use clean Markdown: bold important numbers/names, bullet points for lists, and code blocks for code or structured data.
"""


def sanitize_identity(text: str) -> str:
    """
    Ensures bot output NEVER leaks Hermes or Nous Research identity,
    preserving Prometheus branding throughout all responses.
    """
    if not text:
        return ""

    replacements = [
        (r"\bhermes[-_\s]*agent\b", "پرومته"),
        (r"\bhermes\b", "پرومته"),
        (r"\bHermes\b", "پرومته"),
        (r"\bHERMES\b", "پرومته"),
        (r"هرمس ایجنت", "پرومته"),
        (r"هرمس", "پرومته"),
        (r"نوس\s*ریسرچ", "توسعه‌دهندگان پرومته"),
        (r"nous\s*research", "Prometheus Core"),
        (r"NousResearch", "Prometheus"),
    ]
    for pat, rep in replacements:
        text = re.sub(pat, rep, text, flags=re.IGNORECASE)
    return text



class StreamingTokenBuffer:
    """
    Buffers streaming tokens to respect Telegram's rate-limits (~1 edit/sec)
    while providing responsive, instant Time-To-First-Token (TTFT) visual feedback.
    """
    def __init__(self, min_interval: float = 0.85, min_chars: int = 25):
        self.min_interval = min_interval
        self.min_chars = min_chars
        self.last_flush_time = 0.0
        self.last_flushed_len = 0
        self.buffer: List[str] = []
        self.total_len = 0

    def feed(self, chunk: str) -> Optional[str]:
        if not chunk:
            return None
        self.buffer.append(chunk)
        self.total_len += len(chunk)
        now = time.monotonic()
        elapsed = now - self.last_flush_time
        new_chars = self.total_len - self.last_flushed_len

        # Fast initial flush for early user feedback
        if self.last_flushed_len == 0 and new_chars >= 15 and elapsed >= 0.4:
            self.last_flush_time = now
            self.last_flushed_len = self.total_len
            full_text = "".join(self.buffer)
            self.buffer = [full_text]
            return full_text

        # Standard batch interval flush
        if elapsed >= self.min_interval and new_chars >= self.min_chars:
            self.last_flush_time = now
            self.last_flushed_len = self.total_len
            full_text = "".join(self.buffer)
            self.buffer = [full_text]
            return full_text

        return None

    def flush(self) -> str:
        if not self.buffer:
            return ""
        full_text = "".join(self.buffer)
        self.buffer = [full_text]
        self.last_flushed_len = len(full_text)
        self.last_flush_time = time.monotonic()
        return full_text


def get_session_history(chat_id: int) -> List[Dict[str, Any]]:
    """Retrieves or creates the conversation history for a given chat_id."""
    if chat_id not in _SESSIONS:
        _SESSIONS[chat_id] = []
    return _SESSIONS[chat_id]


def append_to_session(chat_id: int, role: str, content: Any, tool_calls: Optional[List[Dict[str, Any]]] = None, tool_call_id: Optional[str] = None):
    """Appends a message to the session history, respecting MAX_SESSION_HISTORY."""
    history = get_session_history(chat_id)
    msg: Dict[str, Any] = {"role": role}
    if content is not None:
        msg["content"] = content
    if tool_calls:
        msg["tool_calls"] = tool_calls
    if tool_call_id:
        msg["tool_call_id"] = tool_call_id

    history.append(msg)
    # Trim history to keep within sliding window
    max_len = settings.MAX_SESSION_HISTORY * 2
    if len(history) > max_len:
        _SESSIONS[chat_id] = history[-max_len:]


def clear_session(chat_id: int):
    """Clears the session memory for a chat."""
    _SESSIONS.pop(chat_id, None)


async def execute_hermes_agent(
    chat_id: int,
    user_prompt: str,
    on_stream_delta: Optional[Callable[[str], Any]] = None,
    max_loops: int = 4
) -> str:
    """
    Main Autonomous Agent execution loop:
    1. Attaches session context and smart tools.
    2. Multi-endpoint failover for lightning-fast responses without timeouts.
    3. Handles multi-step parallel tool execution automatically.
    4. Strictly sanitizes output to enforce Prometheus identity.
    """
    append_to_session(chat_id, "user", user_prompt)
    history = get_session_history(chat_id)

    candidate_endpoints = get_candidate_endpoints()
    if not candidate_endpoints:
        candidate_endpoints = [(
            get_effective_router_url(),
            get_effective_api_key(),
            get_effective_model()
        )]

    active_tools = get_smart_tools(user_prompt)

    messages = [
        {"role": "system", "content": PROMETHEUS_SYSTEM_PROMPT}
    ] + history

    token_buffer = StreamingTokenBuffer(min_interval=settings.STREAM_EDIT_INTERVAL)

    for loop_idx in range(max_loops):
        content_chunks: List[str] = []
        tool_calls_map: Dict[int, Dict[str, Any]] = {}
        stream_success = False

        for api_url, api_key, model in candidate_endpoints:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}"
            }
            payload: Dict[str, Any] = {
                "model": model,
                "messages": messages,
                "stream": True,
                "temperature": 0.3,
                "max_tokens": 1500
            }
            if active_tools:
                payload["tools"] = active_tools
                payload["tool_choice"] = "auto"

            content_chunks.clear()
            tool_calls_map.clear()

            try:
                async with httpx.AsyncClient(timeout=httpx.Timeout(connect=3.5, read=25.0, write=5.0, pool=5.0)) as client:
                    async with client.stream("POST", f"{api_url}/chat/completions", headers=headers, json=payload) as response:
                        if response.status_code != 200:
                            err_body = await response.aread()
                            logger.warning(f"Endpoint {api_url} returned {response.status_code}: {err_body.decode('utf-8', errors='ignore')}")
                            continue

                        async for line in response.aiter_lines():
                            if not line or not line.startswith("data:"):
                                continue
                            data_str = line[5:].strip()
                            if data_str == "[DONE]":
                                break

                            try:
                                chunk = json.loads(data_str)
                                choices = chunk.get("choices") or []
                                if not choices:
                                    continue
                                delta = choices[0].get("delta") or {}

                                # 1. Text delta
                                text_delta = delta.get("content") or ""
                                if text_delta:
                                    content_chunks.append(text_delta)
                                    if on_stream_delta and not tool_calls_map:
                                        flushed = token_buffer.feed(text_delta)
                                        if flushed:
                                            cleaned_stream = strip_thinking(flushed)
                                            if cleaned_stream:
                                                try:
                                                    res = on_stream_delta(cleaned_stream)
                                                    if asyncio.iscoroutine(res):
                                                        await res
                                                except Exception:
                                                    pass

                                # 2. Tool calls delta
                                raw_tool_calls = delta.get("tool_calls")
                                if raw_tool_calls:
                                    for tc in raw_tool_calls:
                                        idx = tc.get("index", 0)
                                        fn = tc.get("function") or {}
                                        name = fn.get("name") or ""
                                        args = fn.get("arguments") or ""
                                        call_id = tc.get("id")

                                        if idx not in tool_calls_map:
                                            tool_calls_map[idx] = {
                                                "id": call_id or f"call_{idx}",
                                                "type": "function",
                                                "function": {
                                                    "name": name,
                                                    "arguments": args
                                                }
                                            }
                                        else:
                                            if name:
                                                tool_calls_map[idx]["function"]["name"] += name
                                            if args:
                                                tool_calls_map[idx]["function"]["arguments"] += args
                                            if call_id:
                                                tool_calls_map[idx]["id"] = call_id

                            except json.JSONDecodeError:
                                continue

                        stream_success = True
                        break  # Break candidate_endpoints loop on success!

            except Exception as e:
                logger.warning(f"Endpoint {api_url} failed with: {e}. Trying next candidate...")
                continue

        if not stream_success and not content_chunks and not tool_calls_map:
            return "⚠️ متأسفانه ارتباط با سرویس‌های هوش مصنوعی برقرار نشد. لطفاً چند لحظه دیگر مجدداً تلاش نمایید."

        full_content = "".join(content_chunks).strip()

        # If no tool calls, this is the final answer!
        if not tool_calls_map:
            final_answer = sanitize_identity(strip_thinking(full_content))
            if not final_answer:
                final_answer = "درود بر شما! در پردازش این پرسش خروجی متنی دریافت نشد. لطفاً مجدداً سوال خود را بپرسید."
            append_to_session(chat_id, "assistant", final_answer)
            return final_answer

        # Process Tool Calls
        tool_calls_list = [tool_calls_map[k] for k in sorted(tool_calls_map.keys())]
        append_to_session(chat_id, "assistant", full_content or None, tool_calls=tool_calls_list)
        messages.append({
            "role": "assistant",
            "content": full_content or None,
            "tool_calls": tool_calls_list
        })

        # Execute Tools in Parallel
        async def _run_tool(tc: Dict[str, Any]):
            fn_info = tc.get("function", {})
            f_name = fn_info.get("name", "")
            f_args_raw = fn_info.get("arguments", "{}")
            c_id = tc.get("id", "call_default")

            try:
                f_args = json.loads(f_args_raw) if isinstance(f_args_raw, str) else (f_args_raw or {})
            except Exception:
                f_args = {}

            out = await execute_tool(f_name, f_args)
            return c_id, out

        tool_tasks = [_run_tool(tc) for tc in tool_calls_list]
        tool_results = await asyncio.gather(*tool_tasks, return_exceptions=True)

        for res in tool_results:
            if isinstance(res, Exception):
                c_id, out_str = "call_err", f"خطا در اجرای ابزار: {str(res)}"
            else:
                c_id, out_str = res

            append_to_session(chat_id, "tool", out_str, tool_call_id=c_id)
            messages.append({
                "role": "tool",
                "tool_call_id": c_id,
                "content": str(out_str)
            })

        # Disable tools on final synthesis to avoid loops
        active_tools = []

    # If loop limit reached
    final_res = sanitize_identity(strip_thinking(full_content))
    return final_res or "عملیات با موفقیت توسط پرومته انجام شد."
