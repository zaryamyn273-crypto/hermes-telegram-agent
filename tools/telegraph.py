"""
Specialized Telegraph (Telegra.ph) Publishing Tool for Prometheus:
Creates beautiful, rich articles with Instant View support in Telegram.
Features:
- Markdown/Text to Telegraph DOM node converter (headings, bold, italic, code, quotes, lists, links)
- Resilient token caching in Cloudflare KV & L1 RAM with auto-recovery on token revocation
- Automatic title & content extraction
- Clean, user-friendly Persian responses
"""

import re
import json
import logging
import httpx
from typing import Dict, Any, List, Optional, Tuple

import database

logger = logging.getLogger("TelegraphTool")

KV_KEY_TELEGRAPH_TOKEN = "PROMETHEUS_TELEGRAPH_TOKEN"
_MEM_TELEGRAPH_TOKEN: Optional[str] = None
_TELEGRAPH_API_BASE = "https://api.telegra.ph"


def _parse_inline_elements(text: str) -> List[Any]:
    """Parses inline Markdown formatting (links, bold, italic, code) into Telegraph DOM children."""
    if not text:
        return []

    tokens: List[Any] = []
    # Pattern to match links [text](url), bold **text**, italic *text*, inline `code`
    pattern = re.compile(r"(\[[^\]]+\]\([^\)]+\)|\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)")
    last_idx = 0

    for match in pattern.finditer(text):
        start, end = match.span()
        if start > last_idx:
            tokens.append(text[last_idx:start])

        m_str = match.group(0)
        if m_str.startswith("[") and "](" in m_str:
            parts = m_str[1:-1].split("](", 1)
            link_text = parts[0]
            link_url = parts[1]
            tokens.append({"tag": "a", "attrs": {"href": link_url}, "children": [link_text]})
        elif m_str.startswith("**") and m_str.endswith("**"):
            inner = m_str[2:-2].strip()
            if inner:
                tokens.append({"tag": "b", "children": [inner]})
        elif m_str.startswith("*") and m_str.endswith("*"):
            inner = m_str[1:-1].strip()
            if inner:
                tokens.append({"tag": "i", "children": [inner]})
        elif m_str.startswith("`") and m_str.endswith("`"):
            inner = m_str[1:-1].strip()
            if inner:
                tokens.append({"tag": "code", "children": [inner]})
        else:
            tokens.append(m_str)

        last_idx = end

    if last_idx < len(text):
        tokens.append(text[last_idx:])

    return tokens if tokens else [text]


def markdown_to_telegraph_nodes(content: str) -> List[Dict[str, Any]]:
    """Converts structured Markdown or multi-line text into Telegraph DOM node objects."""
    nodes: List[Dict[str, Any]] = []
    lines = content.strip().split("\n")
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # 1. Code Blocks
        if stripped.startswith("```"):
            code_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("```"):
                code_lines.append(lines[i])
                i += 1
            i += 1  # Skip closing ```
            nodes.append({"tag": "pre", "children": ["\n".join(code_lines)]})
            continue

        # 2. Headings
        if stripped.startswith("### "):
            nodes.append({"tag": "h4", "children": _parse_inline_elements(stripped[4:])})
        elif stripped.startswith("## "):
            nodes.append({"tag": "h3", "children": _parse_inline_elements(stripped[3:])})
        elif stripped.startswith("# "):
            nodes.append({"tag": "h3", "children": _parse_inline_elements(stripped[2:])})

        # 3. Blockquotes
        elif stripped.startswith("> "):
            nodes.append({"tag": "blockquote", "children": _parse_inline_elements(stripped[2:])})

        # 4. Bullet lists
        elif stripped.startswith(("- ", "* ", "• ")):
            bullet_text = stripped[2:].strip()
            nodes.append({"tag": "p", "children": ["• "] + _parse_inline_elements(bullet_text)})

        # 5. Numbered lists
        elif re.match(r"^\d+[\.\)]\s+", stripped):
            num_match = re.match(r"^(\d+[\.\)]\s+)(.*)", stripped)
            if num_match:
                prefix = num_match.group(1)
                rest = num_match.group(2)
                nodes.append({"tag": "p", "children": [prefix] + _parse_inline_elements(rest)})
            else:
                nodes.append({"tag": "p", "children": _parse_inline_elements(stripped)})

        # 6. Standard paragraph
        else:
            nodes.append({"tag": "p", "children": _parse_inline_elements(stripped)})

        i += 1

    if not nodes:
        nodes.append({"tag": "p", "children": ["مستند پرومته"]})

    return nodes


async def get_or_create_telegraph_token(force_new: bool = False) -> str:
    """Retrieves Telegraph access token from RAM/KV, creating a new account if missing or revoked."""
    global _MEM_TELEGRAPH_TOKEN

    if not force_new:
        if _MEM_TELEGRAPH_TOKEN:
            return _MEM_TELEGRAPH_TOKEN
        kv_token = await database.kv_get(KV_KEY_TELEGRAPH_TOKEN)
        if kv_token:
            _MEM_TELEGRAPH_TOKEN = kv_token
            return kv_token

    # Create a fresh account
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.post(
                f"{_TELEGRAPH_API_BASE}/createAccount",
                data={
                    "short_name": "Prometheus",
                    "author_name": "Prometheus Super Agent",
                    "author_url": "https://t.me",
                }
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("ok"):
                    new_token = data.get("result", {}).get("access_token", "")
                    if new_token:
                        _MEM_TELEGRAPH_TOKEN = new_token
                        await database.kv_set(KV_KEY_TELEGRAPH_TOKEN, new_token, ttl_sec=86400 * 60)
                        logger.info("Successfully generated new Telegraph access token.")
                        return new_token
    except Exception as e:
        logger.error(f"Failed to create Telegraph account: {e}")

    return _MEM_TELEGRAPH_TOKEN or ""


async def publish_to_telegraph(
    title: str,
    content: str,
    author_name: str = "پرومته",
    author_url: str = "",
) -> Dict[str, Any]:
    """
    Publishes article content directly to Telegra.ph.
    Automatically handles token creation, DOM node serialization, and error recovery.
    """
    clean_title = (title or "مستند پرومته").strip()[:64]
    if not content or not content.strip():
        return {"ok": False, "error": "متن مقاله خالی است."}

    nodes = markdown_to_telegraph_nodes(content)
    token = await get_or_create_telegraph_token()

    for attempt in range(2):
        if not token:
            token = await get_or_create_telegraph_token(force_new=True)
            if not token:
                return {"ok": False, "error": "عدم دسترسی به توکن ایجاد حساب تلگراف."}

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    f"{_TELEGRAPH_API_BASE}/createPage",
                    data={
                        "access_token": token,
                        "title": clean_title,
                        "author_name": author_name or "پرومته",
                        "author_url": author_url or "https://t.me",
                        "content": json.dumps(nodes, ensure_ascii=False),
                        "return_content": "false",
                    }
                )

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("ok"):
                        result = data.get("result", {})
                        return {
                            "ok": True,
                            "url": result.get("url", ""),
                            "path": result.get("path", ""),
                            "title": result.get("title", clean_title),
                            "author_name": author_name,
                        }
                    else:
                        err_msg = data.get("error", "UNKNOWN_ERROR")
                        logger.warning(f"Telegraph createPage error (attempt {attempt + 1}): {err_msg}")
                        # If token was invalid, clear and force new token
                        if "ACCESS_TOKEN_INVALID" in err_msg or "SHORT_NAME_REQUIRED" in err_msg:
                            token = await get_or_create_telegraph_token(force_new=True)
                            continue
                        return {"ok": False, "error": err_msg}

        except Exception as e:
            logger.error(f"Exception calling Telegraph createPage (attempt {attempt + 1}): {e}")
            if attempt == 0:
                continue
            return {"ok": False, "error": str(e)}

    return {"ok": False, "error": "خطا در برقراری ارتباط با سرورهای تلگراف."}


async def create_telegraph_article(
    title: str,
    content: str,
    author_name: str = "پرومته",
) -> str:
    """
    High-level user-facing function to create a Telegraph page and format a clean Persian response.
    """
    res = await publish_to_telegraph(title=title, content=content, author_name=author_name)
    if res.get("ok"):
        page_url = res.get("url", "")
        page_title = res.get("title", title)
        return (
            "📝 **صفحه تلگراف با موفقیت منتشر شد:**\n\n"
            f"• **عنوان:** **{page_title}**\n"
            f"• **نویسنده:** {author_name}\n"
            f"• **پیوند مطالعه و نمایش فوری (Instant View):**\n"
            f"🔗 {page_url}"
        )
    else:
        err = res.get("error", "خطای نامشخص")
        return f"❌ خطا در ایجاد صفحه تلگراف: `{err}`\nلطفاً کمی بعد دوباره تلاش نمایید."


def extract_telegraph_args(text: str) -> Tuple[str, str]:
    """
    Extracts title and content from user command arguments.
    Supports:
    - title | content
    - title : content
    - title on first line, content on next lines
    """
    t = text.strip()
    if "|" in t:
        parts = t.split("|", 1)
        return parts[0].strip(), parts[1].strip()

    lines = [line for line in t.split("\n") if line.strip()]
    if len(lines) >= 2:
        title = lines[0].strip().replace("#", "").strip()
        body = "\n".join(lines[1:]).strip()
        return title[:60], body

    if ":" in t:
        parts = t.split(":", 1)
        if len(parts[0].strip()) <= 40:
            return parts[0].strip(), parts[1].strip()

    # Fallback: title from first 35 chars
    title = t[:35].strip()
    return title, t
