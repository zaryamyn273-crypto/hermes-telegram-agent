"""
System tools: Time, Calendar, Calculator, QR Code, and Diagnostics.
"""

import io
import time
import math
import datetime
import pytz
import jdatetime
import qrcode
from typing import Tuple, Dict, Any, Optional


def get_current_time() -> str:
    """Returns official Iran/Tehran time and Persian (Jalali) / Gregorian calendar date."""
    try:
        tz = pytz.timezone("Asia/Tehran")
        now = datetime.datetime.now(tz)
        j_now = jdatetime.datetime.fromgregorian(datetime=now)

        weekdays_fa = ["دوشنبه", "سه‌شنبه", "چهارشنبه", "پنج‌شنبه", "جمعه", "شنبه", "یکشنبه"]
        months_fa = ["فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور", "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"]

        day_name = weekdays_fa[now.weekday()]
        month_name = months_fa[j_now.month - 1]

        return (
            f"🕒 *زمان و تقویم رسمی (تهران):*\n"
            f"• **ساعت:** `{now.strftime('%H:%M:%S')}`\n"
            f"• **تاریخ شمسی:** `{day_name} {j_now.day} {month_name} {j_now.year}`\n"
            f"• **تاریخ میلادی:** `{now.strftime('%Y-%m-%d')}`"
        )
    except Exception as e:
        return f"ساعت جاری: {time.strftime('%H:%M:%S')}"


def calculate_math(expression: str) -> str:
    """Safely evaluates mathematical and scientific expressions."""
    clean_expr = expression.strip()
    # Allow numbers, basic operators, brackets, decimals, and math functions
    safe_dict = {
        "abs": abs, "round": round, "min": min, "max": max,
        "sqrt": math.sqrt, "sin": math.sin, "cos": math.cos, "tan": math.tan,
        "log": math.log, "log10": math.log10, "exp": math.exp,
        "pi": math.pi, "e": math.e, "pow": pow
    }

    sanitized = clean_expr.replace("^", "**").replace("×", "*").replace("÷", "/")
    # Security check: ensure no forbidden words or builtins
    if any(k in sanitized for k in ["import", "eval", "exec", "open", "os", "sys", "__", "lambda"]):
        return "❌ عبارت ریاضی نامعتبر یا غیرمجاز است."

    try:
        result = eval(sanitized, {"__builtins__": {}}, safe_dict)
        return f"🧮 **محاسبه ریاضی:**\n`{clean_expr}` = **`{result}`**"
    except Exception as e:
        return f"خطا در محاسبه عبارت ریاضی: {str(e)}"


def generate_qr_code(data: str) -> bytes:
    """Generates a PNG QR Code for any text or link."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=3,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
