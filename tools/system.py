"""
System, Time, Calendar, and Math Tools for Prometheus:
Provides accurate Tehran Time (Asia/Tehran), Solar Jalali Calendar,
day of the week, and safe mathematical evaluation.
"""

import ast
import math
import logging
from datetime import datetime

logger = logging.getLogger("SystemTool")

try:
    import pytz
    import jdatetime
    _HAS_JALALI = True
except ImportError:
    _HAS_JALALI = False

# Persian Weekdays and Months
_WEEKDAYS = {
    0: "شنبه",
    1: "یکشنبه",
    2: "دوشنبه",
    3: "سه‌شنبه",
    4: "چهارشنبه",
    5: "پنجشنبه",
    6: "جمعه",
}

_JALALI_MONTHS = [
    "", "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
    "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند"
]


def get_current_time() -> str:
    """
    Returns official Tehran time, Solar Jalali date, day of week, and Gregorian date.
    """
    if _HAS_JALALI:
        tehran_tz = pytz.timezone("Asia/Tehran")
        now_tehran = datetime.now(tehran_tz)
        j_now = jdatetime.datetime.fromgregorian(datetime=now_tehran)

        weekday_name = _WEEKDAYS.get(j_now.weekday(), "")
        month_name = _JALALI_MONTHS[j_now.month] if 1 <= j_now.month <= 12 else ""

        time_str = j_now.strftime("%H:%M:%S")
        date_shamsi = f"{j_now.year}/{j_now.month:02d}/{j_now.day:02d}"
        date_verbose = f"{weekday_name}، {j_now.day} {month_name} {j_now.year}"
        date_gregorian = now_tehran.strftime("%Y-%m-%d")

        return (
            "🕒 **ساعت رسمی و تقویم تهران:**\n\n"
            f"⏱ **زمان:** `{time_str}` (به وقت رسمی ایران)\n"
            f"📅 **تاریخ شمسی:** `{date_verbose}` (`{date_shamsi}`)\n"
            f"🌍 **تاریخ میلادی:** `{date_gregorian}`\n\n"
            "⚡ *محاسبه دقیق توسط پرومته*"
        )
    else:
        now = datetime.now()
        return f"🕒 زمان سرور: `{now.strftime('%Y-%m-%d %H:%M:%S')}`"


# Safe Math AST Evaluator
_SAFE_MATH_NAMES = {
    "abs": abs,
    "round": round,
    "min": min,
    "max": max,
    "pow": pow,
    "sqrt": math.sqrt,
    "sin": math.sin,
    "cos": math.cos,
    "tan": math.tan,
    "log": math.log,
    "log10": math.log10,
    "exp": math.exp,
    "pi": math.pi,
    "e": math.e,
}


def calculate_math(expression: str) -> str:
    """
    Safely evaluates basic and scientific math expressions using AST parsing.
    """
    try:
        expr = expression.strip().replace("^", "**").replace("×", "*").replace("÷", "/")
        node = ast.parse(expr, mode='eval')

        for subnode in ast.walk(node):
            if isinstance(subnode, (ast.Call, ast.Name)):
                name = getattr(subnode, 'id', None) or getattr(getattr(subnode, 'func', None), 'id', None)
                if name and name not in _SAFE_MATH_NAMES:
                    return f"❌ تابع یا شناسه نامجاز در عبارت ریاضی: `{name}`"
            elif isinstance(subnode, (ast.Import, ast.ImportFrom, ast.Attribute, ast.Lambda)):
                return "❌ دستورات یا عبارات نامجاز شناسایی شد."

        code_obj = compile(node, "<math>", "eval")
        result = eval(code_obj, {"__builtins__": {}}, _SAFE_MATH_NAMES)

        if isinstance(result, float) and result.is_integer():
            result = int(result)

        return f"🧮 **نتیجه محاسبه:**\n\n`{expression}` = **{result}**"
    except Exception as e:
        return f"❌ خطا در محاسبه عبارت ریاضی: {str(e)}"
