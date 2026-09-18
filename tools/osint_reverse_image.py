"""
Prometheus OSINT Suite - Reverse Image Search & Visual Entity Reconnaissance Engine.
Generates direct multi-engine reverse lookup targets (Google Lens, Yandex, Bing, TinEye, Baidu),
computes perceptual dHash/aHash fingerprints, and synthesizes AI visual identification.
"""

import io
import re
import html
import hashlib
import urllib.parse
import logging
import asyncio
from typing import Dict, Any, List, Optional
import httpx
from PIL import Image

# Decompression bomb guard
Image.MAX_IMAGE_PIXELS = 100_000_000

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_ReverseImage")

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"


def is_reverse_image_query(text: Optional[str]) -> bool:
    """Detects if the user query/caption requests a reverse image search."""
    if not text:
        return False
    t = text.lower()
    patterns = [
        r"جستجو(?:ی)?\s+معکوس",
        r"سرچ\s+معکوس",
        r"گوگل\s*لنز",
        r"google\s*lens",
        r"reverse\s*(?:image)?",
        r"این\s+(?:عکس|تصویر)\s+(?:کیه|مال\s+کیه|چیه|کجاست|از\s+کجا\s+اومده)",
        r"(?:منبع|سورس|اصل)\s+(?:این\s+)?(?:عکس|تصویر)",
        r"tineye",
        r"yandex\s*images",
    ]
    return any(re.search(p, t) for p in patterns)


def compute_image_fingerprints(image_bytes: bytes) -> Dict[str, Any]:
    """
    Computes cryptographic hashes, perceptual difference hash (dHash),
    average hash (aHash), and structural dimensions of an image.
    """
    sha256 = hashlib.sha256(image_bytes).hexdigest()
    md5 = hashlib.md5(image_bytes).hexdigest()

    width, height = 0, 0
    img_format = "JPEG"
    aspect_ratio = "1:1"
    dhash_hex = "0000000000000000"
    ahash_hex = "0000000000000000"

    try:
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        img_format = img.format or "JPEG"
        if height > 0:
            aspect_ratio = f"{round(width / height, 2)}:1"

        # 1. Compute dHash (8x8 difference)
        img_gray = img.convert("L").resize((9, 8), Image.Resampling.LANCZOS)
        pixels = list(img_gray.tobytes())
        diff = []
        for row in range(8):
            for col in range(8):
                diff.append(pixels[row * 9 + col] > pixels[row * 9 + col + 1])
        dhash_hex = hex(int("".join(["1" if v else "0" for v in diff]), 2))[2:].zfill(16)

        # 2. Compute aHash (8x8 average)
        img_avg = img.convert("L").resize((8, 8), Image.Resampling.LANCZOS)
        avg_pixels = list(img_avg.tobytes())
        avg_val = sum(avg_pixels) / len(avg_pixels) if avg_pixels else 0
        ahash_bits = [p >= avg_val for p in avg_pixels]
        ahash_hex = hex(int("".join(["1" if v else "0" for v in ahash_bits]), 2))[2:].zfill(16)

    except Exception as e:
        logger.warning(f"Error computing perceptual hash: {e}")

    return {
        "sha256": sha256,
        "md5": md5,
        "dhash": dhash_hex,
        "ahash": ahash_hex,
        "width": width,
        "height": height,
        "format": img_format,
        "aspect_ratio": aspect_ratio,
        "file_size_bytes": len(image_bytes),
        "file_size_kb": round(len(image_bytes) / 1024, 1),
    }


async def upload_image_for_recon(image_bytes: bytes, filename: str = "image.jpg") -> Optional[str]:
    """
    Uploads an image to a temporary public host (Litterbox/Catbox or tmpfiles)
    so reverse image search engines can fetch and index it.
    """
    # 1. Try Litterbox (1 hour temporary retention, fast & anonymous)
    try:
        headers = {"User-Agent": _USER_AGENT}
        files = {"fileToUpload": (filename, image_bytes, "image/jpeg")}
        data = {"reqtype": "fileupload", "time": "1h"}
        async with httpx.AsyncClient(headers=headers, timeout=10.0) as client:
            resp = await client.post("https://litterbox.catbox.moe/resources/internals/api.php", files=files, data=data)
            if resp.status_code == 200 and resp.text.startswith("http"):
                url = resp.text.strip()
                logger.info(f"Uploaded image to Litterbox: {url}")
                return url
    except Exception as e:
        logger.debug(f"Litterbox upload failed: {e}")

    # 2. Fallback to tmpfiles.org
    try:
        files = {"file": (filename, image_bytes, "image/jpeg")}
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post("https://tmpfiles.org/api/v1/upload", files=files)
            if resp.status_code == 200:
                d = resp.json()
                raw_url = d.get("data", {}).get("url", "")
                if raw_url:
                    # Convert tmpfiles URL to direct link (insert /dl/)
                    direct_url = raw_url.replace("tmpfiles.org/", "tmpfiles.org/dl/")
                    logger.info(f"Uploaded image to tmpfiles: {direct_url}")
                    return direct_url
    except Exception as e:
        logger.debug(f"Tmpfiles upload failed: {e}")

    return None


def generate_reverse_search_urls(public_image_url: str) -> Dict[str, str]:
    """
    Generates direct reverse image lookup URLs for the world's leading visual search engines.
    """
    encoded_url = urllib.parse.quote(public_image_url, safe="")
    return {
        "google_lens": f"https://lens.google.com/uploadbyurl?url={encoded_url}",
        "yandex": f"https://yandex.com/images/search?rpt=imageview&url={encoded_url}",
        "bing": f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{encoded_url}",
        "tineye": f"https://tineye.com/search?url={encoded_url}",
        "baidu": f"https://graph.baidu.com/details?isurf=1&url={encoded_url}",
        "saucenao": f"https://saucenao.com/search.php?url={encoded_url}",
    }


async def perform_reverse_image_recon(
    image_bytes: bytes,
    filename: str = "target_image.jpg",
    perform_ai_id: bool = True,
    chat_id: int = 0,
) -> Dict[str, Any]:
    """
    Unified reverse image search & visual OSINT reconnaissance:
    - Calculates perceptual hashes (dHash, aHash, SHA256)
    - Uploads image for visual search engine querying
    - Generates direct Google Lens, Yandex, Bing, and TinEye query links
    - Executes multimodal AI visual identification and background intel search
    """
    if len(image_bytes) > 25 * 1024 * 1024:
        return {
            "success": False,
            "error": "حجم تصویر ارسالی بیش از سقف مجاز ۲۵ مگابایت است.",
            "fingerprints": {},
            "public_url": "",
            "search_urls": {},
            "ai_summary": "",
            "entity_search_data": None,
        }

    # Run fingerprinting and upload concurrently
    fp_task = asyncio.to_thread(compute_image_fingerprints, image_bytes)
    up_task = upload_image_for_recon(image_bytes, filename=filename)

    fingerprints, public_url = await asyncio.gather(fp_task, up_task)

    search_urls = generate_reverse_search_urls(public_url) if public_url else {}

    # AI Visual Identification
    ai_summary = ""
    entity_search_data = None
    if perform_ai_id:
        try:
            from tools.vision import analyze_image_with_vision
            v_prompt = (
                "این تصویر را برای اهداف شناسایی و اوسینت (OSINT) به دقت بررسی کن. "
                "سوژه‌های اصلی، اشخاص احتمالی، مکان/بناهای تاریخی، برندها، مدل خودرو یا تجهیزات و متون موجود در آن را "
                "در ۱ یا ۲ بند خلاصه و دقیق به زبان فارسی مشخص کن."
            )
            ai_summary = await analyze_image_with_vision(
                images=[image_bytes],
                prompt=v_prompt,
                chat_id=chat_id,
            )

            # Extract search keyword and query Tavily if meaningful
            if ai_summary and len(ai_summary) > 25 and "متأسفانه" not in ai_summary:
                try:
                    from tools.osint_search import search_web_osint
                    # Use first line or key sentence as query
                    first_line = ai_summary.split("\n")[0][:100]
                    clean_query = urllib.parse.unquote(first_line).strip()
                    if clean_query:
                        s_res = await search_web_osint(clean_query, max_results=2)
                        if s_res.get("success") and s_res.get("results"):
                            entity_search_data = s_res.get("results")[:2]
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Failed to perform AI visual identification: {e}")

    return {
        "success": True,
        "filename": filename,
        "public_url": public_url,
        "fingerprints": fingerprints,
        "search_urls": search_urls,
        "ai_visual_identification": ai_summary,
        "related_web_intel": entity_search_data,
    }


def format_reverse_image_report(data: Dict[str, Any]) -> str:
    """Formats reverse image reconnaissance findings into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🔍 <b>خطا در جستجوی معکوس تصویر:</b> {html.escape(data.get('error', 'ناشناخته'))}"

    fname = html.escape(data.get("filename", "تصویر"))
    fp = data.get("fingerprints", {})
    w = fp.get("width", 0)
    h = fp.get("height", 0)
    fmt = fp.get("format", "JPEG")
    dhash = fp.get("dhash", "")
    sha = fp.get("sha256", "")[:16]
    sz_kb = fp.get("file_size_kb", 0)
    p_url = data.get("public_url")
    urls = data.get("search_urls", {})

    lines = [
        f"🔍 <b>کالبدشکافی و جستجوی معکوس تصویر (Reverse Image Search OSINT):</b>\n<code>{fname}</code>\n",
        f"• <b>ابعاد تصویر:</b> <code>{w}x{h}</code> پیکسل ({sz_kb} KB | <code>{fmt}</code>)",
        f"• <b>ردپای ادراکی (dHash):</b> <code>{dhash}</code>",
        f"• <b>چکیده هش (SHA-256):</b> <code>{sha}...</code>\n",
    ]

    if p_url and urls:
        search_links = [
            f"• 🌐 <a href=\"{urls.get('google_lens', '')}\"><b>Google Lens (گوگل لنز)</b></a> - تطبیق بصری، کالاها و مکان‌ها",
            f"• 🇷🇺 <a href=\"{urls.get('yandex', '')}\"><b>Yandex Images (یاندکس)</b></a> - شماره ۱ تشخیص چهره و سوژه‌ها",
            f"• 🔍 <a href=\"{urls.get('bing', '')}\"><b>Bing Visual Search (بینگ)</b></a> - هوش بینایی مایکروسافت",
            f"• 🕰 <a href=\"{urls.get('tineye', '')}\"><b>TinEye (تین‌آی)</b></a> - کشف اولین تاریخ انتشار و نسخه اصلی",
            f"• 🎨 <a href=\"{urls.get('saucenao', '')}\"><b>SauceNAO</b></a> - شناسایی آثار دیجیتال و آواتارها",
            f"• 🇨🇳 <a href=\"{urls.get('baidu', '')}\"><b>Baidu Visual (بایدو)</b></a> - موتور بصری شرق آسیا",
        ]
        lines.append("🚀 <b>موتورهای جستجوی معکوس فعال (یک کلیک جهت جستجو):</b>\n" + "\n".join(search_links) + "\n")
    else:
        lines.append("⚠️ <i>به دلیل محدودیت اتصال آپلود موقت، لینک‌های موتورهای بصری در دسترس نیست.</i>\n")

    # AI Visual Identification Block
    ai_id = data.get("ai_visual_identification", "")
    if ai_id:
        lines.append(f"🧠 <b>تحلیل هوشمند و شناسایی بصری پرومته:</b>\n{wrap_in_expandable_blockquote(ai_id)}\n")

    # Related web intel snippets if found
    web_hits = data.get("related_web_intel")
    if web_hits:
        hit_lines = []
        for hit in web_hits:
            t = html.escape(hit.get("title", ""))
            u = html.escape(hit.get("url", ""))
            s = html.escape(hit.get("snippet", ""))[:140]
            hit_lines.append(f"• <a href=\"{u}\"><b>{t}</b></a>:\n  <i>{s}</i>")
        lines.append("🌐 <b>منابع و نتایج مرتبط وب (OSINT Hits):</b>\n" + "\n".join(hit_lines) + "\n")

    lines.append("⚡️ <i>جستجوی بصری چندموتوره و استخراج الگوهای ادراکی بر پایه استانداردهای هوش منبع باز (OSINT)</i>")
    return "\n".join(lines)
