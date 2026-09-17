"""
Specialized Telegraph (Telegra.ph) Publishing & Professional Article Tool for Prometheus:
Creates beautiful, rich articles with native Instant View support in Telegram.

Features:
- Markdown/Text to Telegraph DOM node converter:
  * Headers (h3, h4)
  * Code blocks (pre)
  * Horizontal dividers (hr)
  * Images & captions (figure, img, figcaption)
  * Callouts & asides (aside)
  * Blockquotes (blockquote)
  * Native unordered lists (ul, li)
  * Native ordered lists (ol, li)
  * Inline formatting (bold, italic, strikethrough, underline, inline code, links)
- Resilient token caching in Cloudflare KV & L1 RAM with auto-recovery on token revocation
- Automatic title & content extraction with title de-duplication
- Estimated reading time computation
- Clean, user-friendly Persian responses optimized for Instant View
"""

import re
import json
import logging
import html
import httpx
from typing import Dict, Any, List, Optional, Tuple

import database

logger = logging.getLogger("TelegraphTool")

KV_KEY_TELEGRAPH_TOKEN = "PROMETHEUS_TELEGRAPH_TOKEN"
_MEM_TELEGRAPH_TOKEN: Optional[str] = None
_TELEGRAPH_API_BASE = "https://api.telegra.ph"


def estimate_reading_time(text: str) -> int:
    """Estimates reading time in minutes based on ~180-220 words per minute."""
    if not text:
        return 1
    words = len(text.split())
    minutes = max(1, round(words / 200))
    return minutes


def _parse_inline_elements(text: str) -> List[Any]:
    """Parses inline Markdown formatting (links, bold, italic, strike, underline, code) into Telegraph DOM children."""
    if not text:
        return []

    tokens: List[Any] = []
    # Pattern to match links [text](url), bold **text**, strike ~~text~~, underline __text__, italic *text* or _text_, inline `code`
    pattern = re.compile(
        r"(\[[^\]]+\]\([^\)]+\)|"
        r"\*\*[^*]+\*\*|"
        r"~~[^~]+~~|"
        r"__(?:(?!__).)+__|"
        r"\*[^*]+\*|"
        r"`[^`]+`)"
    )
    last_idx = 0

    for match in pattern.finditer(text):
        start, end = match.span()
        if start > last_idx:
            tokens.append(text[last_idx:start])

        m_str = match.group(0)
        if m_str.startswith("[") and "](" in m_str:
            parts = m_str[1:-1].split("](", 1)
            link_text = parts[0].strip() or "پیوند"
            link_url = parts[1].strip()
            tokens.append({"tag": "a", "attrs": {"href": link_url}, "children": [link_text]})
        elif m_str.startswith("**") and m_str.endswith("**"):
            inner = m_str[2:-2].strip()
            if inner:
                tokens.append({"tag": "b", "children": _parse_inline_elements(inner)})
        elif m_str.startswith("~~") and m_str.endswith("~~"):
            inner = m_str[2:-2].strip()
            if inner:
                tokens.append({"tag": "s", "children": [inner]})
        elif m_str.startswith("__") and m_str.endswith("__"):
            inner = m_str[2:-2].strip()
            if inner:
                tokens.append({"tag": "u", "children": [inner]})
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
    """
    Converts structured Markdown or multi-line text into a complete,
    rich Telegraph DOM node structure conforming to Telegraph API specifications.
    """
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

        # 2. Horizontal Rules (---, ***, ___)
        if stripped in ("---", "***", "___", "- - -", "* * *") or (len(stripped) >= 3 and set(stripped) <= {"-", "*", "_"}):
            nodes.append({"tag": "hr"})
            i += 1
            continue

        # 3. Images: ![alt](url)
        img_match = re.match(r"^!\[([^\]]*)\]\(([^\)]+)\)$", stripped)
        if img_match:
            alt_text = img_match.group(1).strip()
            img_url = img_match.group(2).strip()
            fig_children: List[Any] = [{"tag": "img", "attrs": {"src": img_url}}]
            if alt_text:
                fig_children.append({"tag": "figcaption", "children": [alt_text]})
            nodes.append({"tag": "figure", "children": fig_children})
            i += 1
            continue

        # 4. Headings
        if stripped.startswith("### ") or stripped.startswith("#### "):
            h_text = stripped.lstrip("#").strip()
            nodes.append({"tag": "h4", "children": _parse_inline_elements(h_text)})
            i += 1
            continue
        elif stripped.startswith("## ") or stripped.startswith("# "):
            h_text = stripped.lstrip("#").strip()
            nodes.append({"tag": "h3", "children": _parse_inline_elements(h_text)})
            i += 1
            continue

        # 5. Callouts / Asides (> [!NOTE], > 💡, > 📌, >>)
        if (
            stripped.startswith("> [!")
            or stripped.startswith("> 💡")
            or stripped.startswith("> 📌")
            or stripped.startswith("> ⚠️")
            or stripped.startswith(">> ")
        ):
            aside_lines = []
            while i < len(lines) and lines[i].strip().startswith(">"):
                raw_aside = lines[i].strip().lstrip(">").strip()
                # Clean GitHub alert syntax like [!NOTE], [!TIP]
                clean_aside = re.sub(r"^\[!(?:NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*", "", raw_aside, flags=re.IGNORECASE)
                if clean_aside:
                    aside_lines.append(clean_aside)
                i += 1
            full_aside = " ".join(aside_lines)
            nodes.append({"tag": "aside", "children": _parse_inline_elements(full_aside)})
            continue

        # 6. Standard Blockquotes (> text)
        elif stripped.startswith("> "):
            quote_lines = []
            while i < len(lines) and lines[i].strip().startswith("> "):
                quote_lines.append(lines[i].strip()[2:].strip())
                i += 1
            nodes.append({"tag": "blockquote", "children": _parse_inline_elements(" ".join(quote_lines))})
            continue

        # 7. Unordered Lists (- , * , • )
        elif stripped.startswith(("- ", "* ", "• ")):
            li_items: List[Dict[str, Any]] = []
            while i < len(lines) and lines[i].strip().startswith(("- ", "* ", "• ")):
                item_text = lines[i].strip()[2:].strip()
                li_items.append({"tag": "li", "children": _parse_inline_elements(item_text)})
                i += 1
            nodes.append({"tag": "ul", "children": li_items})
            continue

        # 8. Ordered Lists (1. , 2. )
        elif re.match(r"^\d+[\.\)]\s+", stripped):
            li_items_num: List[Dict[str, Any]] = []
            while i < len(lines) and re.match(r"^\d+[\.\)]\s+", lines[i].strip()):
                num_match = re.match(r"^\d+[\.\)]\s+(.*)", lines[i].strip())
                item_text = num_match.group(1).strip() if num_match else lines[i].strip()
                li_items_num.append({"tag": "li", "children": _parse_inline_elements(item_text)})
                i += 1
            nodes.append({"tag": "ol", "children": li_items_num})
            continue

        # 9. Markdown Tables (| a | b | or a | b \n ---|---)
        elif "|" in stripped and i + 1 < len(lines) and re.match(r"^[ \t]*\|?(?:[ \t]*:?-+:?[ \t]*\|)+[ \t]*:?-+:?[ \t]*\|?[ \t]*$", lines[i + 1].strip()):
            from utils.formatter import format_table_as_box, _split_table_row, _detect_alignments
            table_lines = [stripped]
            sep_line = lines[i + 1].strip()
            i += 2
            while i < len(lines):
                r_str = lines[i].strip()
                if not r_str or "|" not in r_str:
                    break
                if re.match(r"^[ \t]*\|?(?:[ \t]*:?-+:?[ \t]*\|)+[ \t]*:?-+:?[ \t]*\|?[ \t]*$", r_str):
                    break
                table_lines.append(r_str)
                i += 1

            header_cells = _split_table_row(table_lines[0])
            alignments = _detect_alignments(sep_line, len(header_cells))
            rows = [header_cells]
            for tl in table_lines[1:]:
                rows.append(_split_table_row(tl))

            box_table = format_table_as_box(rows, alignments)
            if box_table:
                nodes.append({"tag": "pre", "children": [box_table]})
            continue

        # 10. Standard Paragraph
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


def clean_article_title_and_body(title: str, content: str) -> Tuple[str, str]:
    """
    Extracts high-quality title from content if needed and cleans any leading duplicate title line.
    """
    lines = [l for l in content.split("\n") if l.strip()]
    extracted_title = (title or "").strip()

    # If title is missing or generic, extract from first Markdown header
    if not extracted_title or extracted_title in ("مستند تلگراف پرومته", "مقاله پرومته", "مستند پرومته"):
        for l in lines[:3]:
            st = l.strip()
            if st.startswith("#") or st.startswith("**"):
                clean = re.sub(r"^[#*\s]+|[#*\s]+$", "", st).strip()
                if clean and len(clean) >= 3:
                    extracted_title = clean[:64]
                    break

    if not extracted_title and lines:
        extracted_title = lines[0].strip()[:60]

    final_title = extracted_title or "مقاله تخصصی پرومته"

    # Remove duplicate title header from top of body so Telegraph won't render it twice
    body_lines = list(lines)
    if body_lines:
        first_line_clean = re.sub(r"^[#*\s]+|[#*\s]+$", "", body_lines[0].strip())
        if first_line_clean.lower() == final_title.lower() or final_title.lower() in first_line_clean.lower():
            body_lines.pop(0)

    clean_content = "\n".join(body_lines) if body_lines else content
    return final_title[:64], clean_content


async def publish_to_telegraph(
    title: str,
    content: str,
    author_name: str = "پرومته",
    author_url: str = "",
) -> Dict[str, Any]:
    """
    Publishes article content directly to Telegra.ph.
    Handles DOM node conversion, title de-duplication, token resilience, and retry.
    """
    final_title, clean_content = clean_article_title_and_body(title, content)
    if not clean_content or not clean_content.strip():
        return {"ok": False, "error": "متن مقاله خالی است."}

    nodes = markdown_to_telegraph_nodes(clean_content)
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
                        "title": final_title,
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
                            "title": result.get("title", final_title),
                            "author_name": author_name,
                            "reading_time": estimate_reading_time(clean_content),
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
    High-level user-facing function to create a Telegraph page and format an exquisite Persian response.
    """
    res = await publish_to_telegraph(title=title, content=content, author_name=author_name)
    if res.get("ok"):
        page_url = res.get("url", "")
        page_title = res.get("title", title)
        reading_time = res.get("reading_time", estimate_reading_time(content))

        return (
            "📰 **مقاله با موفقیت در تلگراف منتشر شد:**\n\n"
            f"🏷 **عنوان:** **{page_title}**\n"
            f"👤 **نویسنده:** {author_name}\n"
            f"⏱ **زمان تقریبی مطالعه:** {reading_time} دقیقه\n"
            f"⚡️ **قابلیت نمایش فوری (Instant View):** فعال\n\n"
            f"🔗 **پیوند مطالعه مقاله کامل در تلگراف:**\n"
            f"{page_url}"
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
