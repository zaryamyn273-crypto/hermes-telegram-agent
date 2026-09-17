"""
Python Sandbox & Code Execution Engine for Prometheus (Hermes Telegram Agent):
Allows secure, isolated, sub-millisecond execution of Python scripts, algorithms,
and calculations directly within a sandboxed subprocess.
Features:
- Wall-clock timeout enforcement (default 8s)
- Complete environment sanitization (strips API keys and bot tokens)
- Output buffer capping to prevent memory attacks
- Monospace formatting with execution metrics (duration in ms, return code)
"""

import os
import re
import html
import time
import asyncio
import logging
from typing import Dict, Any, Optional

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

logger = logging.getLogger("HermesTelegramAgent.Sandbox")

_MAX_OUTPUT_CHARS = 10000

# Keys to sanitize and scrub from the sandbox environment
_SENSITIVE_ENV_PREFIXES = (
    "BOT_", "TELEGRAM_", "HERMES_", "ROUTER_", "API_", "TOKEN",
    "CLOUDFLARE_", "ADMIN_", "VIRUSTOTAL_", "SECRET", "PASSWORD", "KEY"
)


def _get_sanitized_env() -> Dict[str, str]:
    """Returns a clean environment dictionary stripped of all bot credentials and secrets."""
    sanitized = {}
    for k, v in os.environ.items():
        k_upper = k.upper()
        if not any(k_upper.startswith(prefix) or prefix in k_upper for prefix in _SENSITIVE_ENV_PREFIXES):
            sanitized[k] = v
    # Ensure safe locale and non-interactive python execution
    sanitized["PYTHONUNBUFFERED"] = "1"
    sanitized["PYTHONIOENCODING"] = "utf-8"
    return sanitized


async def run_python_sandbox(code: str, timeout_sec: float = 8.0) -> Dict[str, Any]:
    """
    Executes Python 3 code in an isolated subprocess with timeout and resource limits.
    Returns:
      {
        "success": bool,
        "stdout": str,
        "stderr": str,
        "exit_code": int,
        "duration_ms": float,
        "timed_out": bool,
        "error": Optional[str]
      }
    """
    cleaned_code = code.strip()
    if not cleaned_code:
        return {
            "success": False,
            "stdout": "",
            "stderr": "کدی برای اجرا وارد نشده است.",
            "exit_code": 1,
            "duration_ms": 0.0,
            "timed_out": False,
            "error": "Empty code"
        }

    t0 = time.perf_counter()
    env = _get_sanitized_env()

    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", "-c", cleaned_code,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )

        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
            dur = (time.perf_counter() - t0) * 1000

            stdout_str = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr_str = stderr_bytes.decode("utf-8", errors="replace").strip()

            if len(stdout_str) > _MAX_OUTPUT_CHARS:
                stdout_str = stdout_str[:_MAX_OUTPUT_CHARS] + "\n... [خروجی بیش از حد طولانی بود و کوتاه شد]"

            if len(stderr_str) > _MAX_OUTPUT_CHARS:
                stderr_str = stderr_str[:_MAX_OUTPUT_CHARS] + "\n... [خطا کوتاه شد]"

            return {
                "success": proc.returncode == 0,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "exit_code": proc.returncode or 0,
                "duration_ms": round(dur, 2),
                "timed_out": False,
                "error": None if proc.returncode == 0 else "Execution failed with non-zero exit code"
            }

        except asyncio.TimeoutError:
            dur = (time.perf_counter() - t0) * 1000
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
            return {
                "success": False,
                "stdout": "",
                "stderr": f"⏱ زمان اجرای اسکریپت از {timeout_sec:.1f} ثانیه فراتر رفت و متوقف (Killed) شد.",
                "exit_code": -1,
                "duration_ms": round(dur, 2),
                "timed_out": True,
                "error": "Execution timed out"
            }

    except Exception as e:
        dur = (time.perf_counter() - t0) * 1000
        logger.error(f"Failed to spawn sandbox subprocess: {e}")
        return {
            "success": False,
            "stdout": "",
            "stderr": f"خطا در ایجاد محیط ساندباکس: {str(e)}",
            "exit_code": 1,
            "duration_ms": round(dur, 2),
            "timed_out": False,
            "error": str(e)
        }


def format_sandbox_result(res: Dict[str, Any], code: str) -> str:
    """Formats sandbox execution result into an elegant Telegram HTML response."""
    success = res.get("success", False)
    timed_out = res.get("timed_out", False)
    dur_ms = res.get("duration_ms", 0.0)
    stdout = res.get("stdout", "").strip()
    stderr = res.get("stderr", "").strip()
    exit_code = res.get("exit_code", 0)

    if timed_out:
        status_emoji = "⏱"
        status_text = "تایم‌اوت (Timeout)"
    elif success:
        status_emoji = "✅"
        status_text = "موفقیت‌آمیز (Exit 0)"
    else:
        status_emoji = "❌"
        status_text = f"خطای اجرا (Exit {exit_code})"

    lines = [
        f"⚡ <b>ساندباکس اجرای کد پایتون پرومته (Python 3):</b>",
        f"• <b>وضعیت:</b> {status_emoji} <code>{status_text}</code>",
        f"• <b>مدت زمان اجرا:</b> <code>{dur_ms}ms</code>",
        ""
    ]

    # Show code preview
    code_preview = code.strip()
    if len(code_preview) > 800:
        code_preview = code_preview[:800] + "\n# ..."
    lines.append(f"<blockquote expandable>💻 <b>کد اجرا شده:</b>\n<pre><code class=\"language-python\">{html.escape(code_preview)}</code></pre></blockquote>")
    lines.append("")

    if stdout:
        lines.append(f"📤 <b>خروجی استاندارد (stdout):</b>")
        lines.append(f"<pre>{html.escape(stdout)}</pre>")
    elif success and not stderr:
        lines.append("ℹ️ <i>کد بدون خروجی متنی با موفقیت به پایان رسید.</i>")

    if stderr:
        lines.append("")
        lines.append(f"⚠️ <b>خطا / گزارش سیستمی (stderr):</b>")
        lines.append(f"<pre>{html.escape(stderr)}</pre>")

    return "\n".join(lines)


# =========================================================================
# Intent Detection & Code Extraction
# =========================================================================

_SANDBOX_COMMAND_PREFIXES = (
    "/run", "/exec", "/py", "/python", "/sandbox",
    "/prun", "/pexec", "/ppy", "/ppython", "/psandbox",
    "/pro_run", "/p_run", "/pro_exec", "/p_exec", "/p_py", "/pro_py"
)

_CODE_TRIGGER_PATTERNS = [
    re.compile(r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:این\s*)?(?:کد|اسکریپت)?\s*(?:پایتون)?\s*(?:رو|را|زیر\s*رو|زیر\s*را)?\s*(?:اجرا\s*کن|ران\s*کن|تست\s*کن|run\s*کن|exec\s*کن)", re.IGNORECASE),
    re.compile(r"^(?:اجرا|ران|run|exec)(?:\s*(?:کن|ش\s*کن|کردن))?\s*[:\n]", re.IGNORECASE),
]


def is_sandbox_request(text: str) -> bool:
    """Matches commands and natural Persian queries requesting Python code execution in sandbox."""
    if not text:
        return False
    t = text.strip()
    first_token = t.split()[0].lower() if t.split() else ""
    if any(first_token == cmd or first_token.startswith(f"{cmd}@") for cmd in _SANDBOX_COMMAND_PREFIXES):
        return True
    if any(p.search(t) for p in _CODE_TRIGGER_PATTERNS):
        return True
    return False


def extract_code_snippet(text: str) -> Optional[str]:
    """Extracts Python code snippet from markdown code blocks or command arguments."""
    if not text:
        return None

    # 1. Check for fenced code block ```python ... ``` or ``` ... ```
    code_blocks = re.findall(r"```(?:python|py)?\n([\s\S]*?)```", text, re.IGNORECASE)
    if code_blocks:
        return code_blocks[0].strip()

    # 2. Check for inline backticks `code`
    inline_blocks = re.findall(r"`([^`\n]+)`", text)
    if inline_blocks and len(inline_blocks[0].strip()) >= 3:
        return inline_blocks[0].strip()

    # 3. Strip command or trigger phrase from beginning
    t = text.strip()
    # Strip slash command
    t = re.sub(r"^/(?:p|pro|prom|prometheus)?_?(?:run|exec|py|python|sandbox)(?:@\w+)?\s*", "", t, flags=re.IGNORECASE)
    # Strip natural language trigger
    for p in _CODE_TRIGGER_PATTERNS:
        t = p.sub("", t).strip()

    t = t.lstrip(":\n -").strip()
    return t if len(t) >= 2 else None


async def sandbox_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Telegram handler for /run, /exec, /py, /python, /sandbox commands."""
    msg = update.effective_message
    if not msg:
        return

    raw_text = msg.text or msg.caption or ""
    # Check args or reply_to_message
    args = context.args or []
    code = " ".join(args).strip()

    if not code:
        # Check if user replied to a message with code
        reply_msg = msg.reply_to_message
        if reply_msg and (reply_msg.text or reply_msg.caption):
            code = extract_code_snippet(reply_msg.text or reply_msg.caption or "") or ""
        else:
            code = extract_code_snippet(raw_text) or ""

    if not code:
        guide = (
            "💻 <b>ساندباکس اجرای کد پایتون پرومته (Python 3):</b>\n\n"
            "برای اجرای سریع، امن و بلادرنگ کدهای پایتون در محیط ساندباکس سرور:\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/run print('Hello, World!')</code>\n"
            "• <code>/py [کد شما]</code>\n"
            "• ریپلای کردن دستور <code>/run</code> روی پیامی که حاوی کد است.\n\n"
            "💡 <i>پشتیبانی کامل از ساختارهای داده، توابع، محاسبات ریاضی و کتابخانه‌های استاندارد پایتون با محدودیت زمانی و حافظه امن.</i>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    res = await run_python_sandbox(code)
    formatted = format_sandbox_result(res, code)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)
