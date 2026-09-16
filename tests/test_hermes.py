"""
Test suite for Hermes Telegram Agent.
Verifies trigger logic, tools, formatter, and registry.
"""

import pytest
import asyncio
from tools.registry import get_smart_tools, execute_tool
from tools.system import calculate_math, get_current_time
from utils.formatter import markdown_to_telegram_html, strip_thinking, split_message


def test_strip_thinking():
    raw = "<thought>Let me think about this.</thought>This is the real answer."
    assert strip_thinking(raw) == "This is the real answer."

    raw2 = "<think>Internal deliberation</think>Done."
    assert strip_thinking(raw2) == "Done."


def test_markdown_formatter():
    md = "**Hello** *world* `code` [link](https://example.com)"
    html_out = markdown_to_telegram_html(md)
    assert "<b>Hello</b>" in html_out
    assert "<code>code</code>" in html_out
    assert '<a href="https://example.com">link</a>' in html_out


def test_split_message():
    long_txt = "A" * 5000
    chunks = split_message(long_txt, max_len=3000)
    assert len(chunks) == 2
    assert len(chunks[0]) <= 3000
    assert len(chunks[1]) <= 3000


def test_math_tool():
    res = calculate_math("25 * 4 + 10")
    assert "110" in res

    res_sqrt = calculate_math("sqrt(144)")
    assert "12" in res_sqrt


def test_time_tool():
    res = get_current_time()
    assert "ساعت" in res
    assert "تاریخ" in res


def test_smart_tool_filtering():
    # Casual chatter -> 0 tools
    tools_chat = get_smart_tools("سلام خوبی؟ مرسی")
    assert len(tools_chat) == 0

    # Weather intent -> weather tool
    tools_weather = get_smart_tools("هوای شیراز چطوره؟")
    assert any(t["function"]["name"] == "get_weather" for t in tools_weather)

    # Crypto intent -> crypto tool
    tools_crypto = get_smart_tools("قیمت اتریوم به دلار چنده؟")
    assert any(t["function"]["name"] == "get_crypto_price" for t in tools_crypto)

    # Search intent -> web search
    tools_search = get_smart_tools("جدیدترین اخبار هوش مصنوعی")
    assert any(t["function"]["name"] == "web_search" for t in tools_search)


@pytest.mark.asyncio
async def test_execute_tool():
    res = await execute_tool("calculate_math", {"expression": "50 / 2"})
    assert "25" in res

    res_time = await execute_tool("get_current_time", {})
    assert "ساعت" in res_time


def test_sanitize_identity():
    from agent_engine import sanitize_identity
    raw = "من مدل Hermes Agent ساخته شده توسط Nous Research هستم و نام من هرمس است."
    sanitized = sanitize_identity(raw)
    assert "Hermes" not in sanitized
    assert "هرمس" not in sanitized
    assert "پرومته" in sanitized


def test_candidate_endpoints():
    from config import get_candidate_endpoints
    candidates = get_candidate_endpoints()
    assert len(candidates) >= 1
    # Check that model is fast model
    for url, key, model in candidates:
        assert model in ["ag/gemini-3.8-flash-low", "Hermes-3-Llama-3.1-8B"] or "flash" in model

