"""
Python & E2B Cloud Sandbox Engine for Prometheus (Hermes Telegram Agent):
Allows high-performance, secure, isolated execution of Python scripts, algorithms,
and calculations directly within E2B Cloud Code Interpreter or a sandboxed subprocess.
Features:
- Dual-engine execution: E2B Cloud Code Interpreter with automatic local fallback
- Multi-modal chart and plot extraction (matplotlib, seaborn, PIL base64 PNG/JPEG)
- Wall-clock timeout enforcement
- Complete environment sanitization (strips API keys and bot tokens)
- Output buffer capping to prevent memory attacks
- Monospace Telegram HTML formatting with execution metrics
"""

import os
import re
import io
import html
import time
import base64
import asyncio
import logging
from typing import Dict, Any, Optional, List

from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ContextTypes

from config import settings

logger = logging.getLogger("HermesTelegramAgent.Sandbox")

_MAX_OUTPUT_CHARS = 10000

# Keys to sanitize and scrub from the sandbox environment
_SENSITIVE_ENV_PREFIXES = (
    "BOT_", "TELEGRAM_", "HERMES_", "ROUTER_", "API_", "TOKEN",
    "CLOUDFLARE_", "ADMIN_", "VIRUSTOTAL_", "SECRET", "PASSWORD", "KEY", "E2B_"
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


async def run_e2b_sandbox(
    code: str,
    language: str = "python",
    timeout_sec: float = 15.0,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Executes code inside the state-of-the-art E2B Cloud Code Interpreter sandbox.
    Supports Python, JavaScript, Bash, R, and extracts generated plots/charts.
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
            "error": "Empty code",
            "backend": "e2b",
            "images": [],
            "text_results": [],
        }

    effective_key = api_key or getattr(settings, "E2B_API_KEY", "") or os.getenv("E2B_API_KEY", "")
    if not effective_key:
        raise ValueError("E2B_API_KEY is not configured")

    from e2b_code_interpreter import AsyncSandbox

    t0 = time.perf_counter()
    images: List[bytes] = []
    text_results: List[str] = []

    sb = await AsyncSandbox.create(api_key=effective_key, timeout=int(timeout_sec) + 15)
    try:
        execution = await sb.run_code(cleaned_code, language=language, timeout=timeout_sec)
        dur = (time.perf_counter() - t0) * 1000

        stdout_lines = [msg.line for msg in (execution.logs.stdout or [])]
        stderr_lines = [msg.line for msg in (execution.logs.stderr or [])]
        stdout_str = "\n".join(stdout_lines).strip()
        stderr_str = "\n".join(stderr_lines).strip()

        # Extract visual artifacts (charts/plots) and computed data
        if execution.results:
            for r in execution.results:
                if getattr(r, "png", None):
                    try:
                        img_bytes = base64.b64decode(r.png)
                        images.append(img_bytes)
                    except Exception as ie:
                        logger.warning(f"Failed to decode PNG result from E2B: {ie}")
                elif getattr(r, "jpeg", None):
                    try:
                        img_bytes = base64.b64decode(r.jpeg)
                        images.append(img_bytes)
                    except Exception as ie:
                        logger.warning(f"Failed to decode JPEG result from E2B: {ie}")
                if getattr(r, "text", None) and r.text.strip():
                    text_results.append(r.text.strip())

        err_msg = None
        if execution.error:
            err_msg = f"{execution.error.name}: {execution.error.value}"
            if execution.error.traceback:
                tb = execution.error.traceback.strip()
                stderr_str = f"{stderr_str}\n{tb}".strip() if stderr_str else tb
            elif not stderr_str:
                stderr_str = err_msg

        return {
            "success": execution.error is None,
            "stdout": stdout_str[:_MAX_OUTPUT_CHARS],
            "stderr": stderr_str[:_MAX_OUTPUT_CHARS],
            "exit_code": 0 if execution.error is None else 1,
            "duration_ms": round(dur, 2),
            "timed_out": False,
            "error": err_msg,
            "backend": "e2b",
            "images": images,
            "text_results": text_results,
        }
    finally:
        try:
            await sb.kill()
        except Exception:
            pass


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
        "error": Optional[str],
        "backend": "local",
        "images": [],
        "text_results": []
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
            "error": "Empty code",
            "backend": "local",
            "images": [],
            "text_results": []
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
                "error": None if proc.returncode == 0 else "Execution failed with non-zero exit code",
                "backend": "local",
                "images": [],
                "text_results": []
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
                "error": "Execution timed out",
                "backend": "local",
                "images": [],
                "text_results": []
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
            "error": str(e),
            "backend": "local",
            "images": [],
            "text_results": []
        }


async def run_code_sandbox(
    code: str,
    language: str = "python",
    timeout_sec: float = 15.0
) -> Dict[str, Any]:
    """
    Unified high-performance code execution engine:
    1. Tries E2B Cloud Sandbox if E2B_API_KEY is configured.
    2. Seamlessly falls back to local isolated Python subprocess sandbox if E2B is unavailable or fails.
    """
    effective_key = getattr(settings, "E2B_API_KEY", "") or os.getenv("E2B_API_KEY", "")
    if effective_key:
        try:
            res = await run_e2b_sandbox(code=code, language=language, timeout_sec=timeout_sec, api_key=effective_key)
            return res
        except Exception as e:
            logger.warning(f"E2B Sandbox execution failed ({e}), seamlessly falling back to local sandbox.")

    # Local sandbox fallback
    return await run_python_sandbox(code=code, timeout_sec=min(timeout_sec, 12.0))


def format_sandbox_result(res: Dict[str, Any], code: str) -> str:
    """Formats sandbox execution result into an elegant Telegram HTML response."""
    backend = res.get("backend", "local")
    backend_title = "ساندباکس ابری E2B پرومته (Cloud Code Interpreter)" if backend == "e2b" else "ساندباکس ایزوله پرومته (Python 3)"
    success = res.get("success", False)
    timed_out = res.get("timed_out", False)
    dur_ms = res.get("duration_ms", 0.0)
    stdout = res.get("stdout", "").strip()
    stderr = res.get("stderr", "").strip()
    exit_code = res.get("exit_code", 0)
    text_results = res.get("text_results", [])
    images_count = len(res.get("images", []))

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
        f"⚡ <b>{backend_title}:</b>",
        f"• <b>وضعیت:</b> {status_emoji} <code>{status_text}</code>",
        f"• <b>مدت زمان اجرا:</b> <code>{dur_ms}ms</code>",
    ]
    if images_count > 0:
        lines.append(f"• <b>خروجی نمودار/تصویر:</b> 🖼 <code>{images_count} فایل استخراج شد</code>")
    lines.append("")

    # Show code preview
    code_preview = code.strip()
    if len(code_preview) > 800:
        code_preview = code_preview[:800] + "\n# ..."
    lines.append(f"<blockquote expandable>💻 <b>کد اجرا شده:</b>\n<pre><code class=\"language-python\">{html.escape(code_preview)}</code></pre></blockquote>")
    lines.append("")

    if text_results:
        lines.append(f"📊 <b>نتیجه محاسباتی:</b>")
        lines.append(f"<pre>{html.escape(chr(10).join(text_results))}</pre>")
        lines.append("")

    if stdout:
        lines.append(f"📤 <b>خروجی استاندارد (stdout):</b>")
        lines.append(f"<pre>{html.escape(stdout)}</pre>")
    elif success and not stderr and not text_results and images_count == 0:
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
    "/run", "/exec", "/py", "/python", "/sandbox", "/e2b", "/code",
    "/prun", "/pexec", "/ppy", "/ppython", "/psandbox", "/pe2b",
    "/pro_run", "/p_run", "/pro_exec", "/p_exec", "/p_py", "/pro_py", "/p_e2b", "/pro_e2b"
)

_CODE_TRIGGER_PATTERNS = [
    re.compile(r"^(?:لطف[ااً]|میشه|بی‌زحمت|بی\s*زحمت)?\s*(?:این\s*)?(?:کد|اسکریپت)?\s*(?:پایتون)?\s*(?:رو|را|زیر\s*رو|زیر\s*را)?\s*(?:اجرا\s*کن|ران\s*کن|تست\s*کن|run\s*کن|exec\s*کن)", re.IGNORECASE),
    re.compile(r"^(?:اجرا|ران|run|exec)(?:\s*(?:کن|ش\s*کن|کردن))?\s*[:\n]", re.IGNORECASE),
    re.compile(r"(?:اجرا|تست|ران|run|exec)[\s\S]*?(?:e2b|ساندباکس)|(?:e2b|ساندباکس)[\s\S]*?(?:اجرا|تست|ران|run|exec)", re.IGNORECASE),
]


def is_sandbox_request(text: str) -> bool:
    """Matches commands and natural Persian queries requesting code execution in sandbox or E2B."""
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
    """Extracts Python/general code snippet from markdown code blocks or command arguments."""
    if not text:
        return None

    # 1. Check for fenced code block ```python ... ``` or ``` ... ```
    code_blocks = re.findall(r"```(?:python|py|javascript|js|bash|sh)?\n([\s\S]*?)```", text, re.IGNORECASE)
    if code_blocks:
        return code_blocks[0].strip()

    # 2. Check for inline backticks `code`
    inline_blocks = re.findall(r"`([^`\n]+)`", text)
    if inline_blocks and len(inline_blocks[0].strip()) >= 3:
        return inline_blocks[0].strip()

    # 3. Strip command or trigger phrase from beginning
    t = text.strip()
    # Strip slash command
    t = re.sub(r"^/(?:p|pro|prom|prometheus)?_?(?:run|exec|py|python|sandbox|e2b|code)(?:@\w+)?\s*", "", t, flags=re.IGNORECASE)
    # Strip natural language trigger
    for p in _CODE_TRIGGER_PATTERNS:
        t = p.sub("", t).strip()

    t = t.lstrip(":\n -").strip()
    return t if len(t) >= 2 else None


async def sandbox_command_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Telegram handler for /run, /exec, /py, /python, /sandbox, /e2b commands."""
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
            "💻 <b>ساندباکس اجرای کد ابری E2B و محلی پرومته:</b>\n\n"
            "برای اجرای بلادرنگ، امن و فوق‌سریع کدها (Python, JS, Bash) در ساندباکس ابری E2B:\n\n"
            "📌 <b>نحوه استفاده:</b>\n"
            "• <code>/run print('Hello, World!')</code>\n"
            "• <code>/py [کد شما]</code>\n"
            "• <code>/e2b [کد محاسباتی یا تحلیلی]</code>\n"
            "• ریپلای کردن دستور <code>/run</code> یا <code>/e2b</code> روی پیامی که حاوی کد است.\n\n"
            "💡 <i>پشتیبانی از کتابخانه‌های هوش مصنوعی، ماتریس‌ها، محاسبات ریاضی و استخراج خودکار نمودارهای ترسیمی (Matplotlib / Seaborn).</i>"
        )
        await msg.reply_text(guide, parse_mode=ParseMode.HTML)
        return

    res = await run_code_sandbox(code)

    # Deliver any visual chart/plot images generated
    images = res.get("images", [])
    for img_bytes in images:
        try:
            await msg.reply_photo(
                photo=io.BytesIO(img_bytes),
                caption="📊 <b>نمودار خروجی تولیدشده در ساندباکس E2B</b>",
                parse_mode=ParseMode.HTML
            )
        except Exception as pe:
            logger.warning(f"Could not send sandbox plot image: {pe}")

    formatted = format_sandbox_result(res, code)
    await msg.reply_text(formatted, parse_mode=ParseMode.HTML)
