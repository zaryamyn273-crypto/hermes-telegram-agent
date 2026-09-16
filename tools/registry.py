"""
Hermes Agent Tool Registry & Smart Schema Filter.
Filters and formats tools cleanly for the LLM without payload bloat.
"""

import json
from typing import Dict, Any, List, Optional
from .financial import get_crypto_price, get_fiat_and_gold_rates
from .weather import get_weather
from .search import web_search, fetch_webpage
from .system import get_current_time, calculate_math


# Hermes-compliant tool definitions
ALL_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_crypto_price",
            "description": "استعلام قیمت لحظه‌ای ارز دیجیتال و رمزارزها (مانند بیتکوین BTC، اتریوم ETH، تتر، سولانا، تون و غیره)",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "نماد رمزارز (مثال: BTC, ETH, SOL, TON, DOGE)"
                    }
                },
                "required": ["symbol"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_fiat_and_gold_rates",
            "description": "استعلام نرخ لحظه‌ای دلار، یورو، درهم امارات و بازار طلا و ارز",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "استعلام وضعیت آب و هوا، دما، رطوبت و وزش باد برای یک شهر مشخص در ایران یا جهان",
            "parameters": {
                "type": "object",
                "properties": {
                    "city": {
                        "type": "string",
                        "description": "نام شهر مورد نظر (مثال: تهران، اصفهان، مشهد، شیراز، تبریز، London)"
                    }
                },
                "required": ["city"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "جستجوی زنده در اینترنت برای اخبار جدید، مقالات، رویدادها و اطلاعات به‌روز",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "عبارت یا کلمات کلیدی برای جستجو در وب"
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_webpage",
            "description": "خواندن و استخراج متن کامل یک صفحه یا لینک وب (URL) ارسالی توسط کاربر",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "آدرس کامل صفحه وب (با https://)"
                    }
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_current_time",
            "description": "دریافت ساعت دقیق و رسمی تهران به همراه تاریخ شمسی و میلادی تقویم",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_math",
            "description": "انجام محاسبات ریاضی، علمی، آماری و توابع جبری و مهندسی",
            "parameters": {
                "type": "object",
                "properties": {
                    "expression": {
                        "type": "string",
                        "description": "عبارت ریاضی برای محاسبه (مثال: sqrt(144) + 25 * 4)"
                    }
                },
                "required": ["expression"]
            }
        }
    }
]


def get_smart_tools(prompt: str) -> List[Dict[str, Any]]:
    """
    Intelligently selects 2-5 relevant tools for the prompt,
    preventing context bloat and keeping TTFT minimal.
    """
    p_low = (prompt or "").lower()

    # Fast check: Pure casual conversation -> NO tools overhead
    casual_words = ["سلام", "درود", "خوبی", "چطوری", "چه خبر", "مرسی", "ممنون", "تشکر", "دمت گرم", "hi", "hello", "hey"]
    cleaned = p_low
    for w in casual_words:
        cleaned = cleaned.replace(w, "")
    if len(cleaned.strip()) <= 3:
        return []

    selected = []
    selected_names = set()

    def add_tool(name: str):
        if name not in selected_names:
            for t in ALL_TOOLS:
                if t["function"]["name"] == name:
                    selected.append(t)
                    selected_names.add(name)
                    break

    # 1. Financial
    if any(k in p_low for k in ["قیمت", "نرخ", "چنده", "ارز", "دلار", "یورو", "طلا", "سکه", "تتر", "درهم", "price", "rate", "dollar"]):
        add_tool("get_fiat_and_gold_rates")
    if any(k in p_low for k in ["بیتکوین", "بیت کوین", "اتریوم", "کریپتو", "رمزارز", "btc", "eth", "sol", "ton", "doge", "crypto"]):
        add_tool("get_crypto_price")

    # 2. Weather
    if any(k in p_low for k in ["هوا", "بارون", "باران", "دما", "سرد", "گرم", "weather"]):
        add_tool("get_weather")

    # 3. URL / Webpage
    if "http://" in p_low or "https://" in p_low or "www." in p_low:
        add_tool("fetch_webpage")

    # 4. Search / News
    if any(k in p_low for k in ["سرچ", "جستجو", "اخبار", "جدیدترین", "آخرین", "search", "news", "کیست", "چیست", "تعریف"]):
        add_tool("web_search")

    # 5. Math / Calculation
    if any(k in p_low for k in ["حساب کن", "محاسبه", "جمع", "ضرب", "تقسیم", "جذر", "calc", "+", "-", "*", "/", "^"]):
        add_tool("calculate_math")

    # 6. Time / Calendar
    if any(k in p_low for k in ["ساعت", "تاریخ", "امروز", "تقویم", "چندمه", "time", "date"]):
        add_tool("get_current_time")

    # Baseline: If no specific trigger matched but not casual, provide search & time
    if not selected:
        add_tool("web_search")
        add_tool("get_current_time")

    return selected


async def execute_tool(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Executes a registered tool asynchronously and returns string output."""
    try:
        if tool_name == "get_crypto_price":
            symbol = arguments.get("symbol", "BTC")
            return await get_crypto_price(symbol=symbol)
        elif tool_name == "get_fiat_and_gold_rates":
            return await get_fiat_and_gold_rates()
        elif tool_name == "get_weather":
            city = arguments.get("city", "تهران")
            return await get_weather(city=city)
        elif tool_name == "web_search":
            query = arguments.get("query", "")
            return await web_search(query=query)
        elif tool_name == "fetch_webpage":
            url = arguments.get("url", "")
            return await fetch_webpage(url=url)
        elif tool_name == "get_current_time":
            return get_current_time()
        elif tool_name == "calculate_math":
            expr = arguments.get("expression", "")
            return calculate_math(expression=expr)
        else:
            return f"ابزار ناشناخته: {tool_name}"
    except Exception as e:
        return f"خطا در اجرای ابزار {tool_name}: {str(e)}"
