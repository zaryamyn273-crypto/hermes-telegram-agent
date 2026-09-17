"""
Specialized Music Search, Download & Telegram Audio Uploader for Prometheus:
Finds, extracts, streams, and uploads high-fidelity studio MP3 tracks (320kbps & 128kbps)
directly to Telegram chats with cover art, metadata, and sub-second file_id caching.
Uses parallel racing crawler across top Iranian and global portals with early-exit optimization.
"""

import re
import io
import time
import html
import logging
import asyncio
import urllib.parse
import httpx
from bs4 import BeautifulSoup
from typing import Dict, Any, List, Optional, Tuple

from telegram import Update
from telegram.constants import ChatAction, ParseMode
from telegram.ext import ContextTypes

import database

logger = logging.getLogger("MusicTool")

_MAX_AUDIO_BYTES = 45 * 1024 * 1024  # Telegram bot limit (up to 45-50 MB for bots)

_MUSIC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
}

_MUSIC_CLIENT: Optional[httpx.AsyncClient] = None


def get_music_client() -> httpx.AsyncClient:
    """Returns shared AsyncClient with keepalive connection pooling and relaxed SSL for CDNs."""
    global _MUSIC_CLIENT
    if _MUSIC_CLIENT is None or _MUSIC_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=30, max_connections=60, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)
        _MUSIC_CLIENT = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            headers=_MUSIC_HEADERS,
            verify=False,
            follow_redirects=True
        )
    return _MUSIC_CLIENT


def clean_url(url: str) -> str:
    """Safely decodes and re-quotes URLs ensuring spaces and unicode chars are valid without double-encoding."""
    if not url or not url.startswith("http"):
        return url
    try:
        p = urllib.parse.urlsplit(url)
        path = urllib.parse.quote(urllib.parse.unquote(p.path), safe="/:@!$&'()*+,;=-_.~")
        query = urllib.parse.quote(urllib.parse.unquote(p.query), safe="=&?+~/:@!$&'()*+,;=-_.")
        return urllib.parse.urlunsplit((p.scheme, p.netloc, path, query, p.fragment))
    except Exception:
        return url


def clean_music_query(q: str) -> str:
    """Strips conversational noise, filler words, and punctuation from music queries."""
    cleaned = (q or "").strip()
    cleaned = re.sub(r"^/(?:p|pro|prom|prometheus)?_?(?:music|song|play|ahang)\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"[\\/:\*\?\"<>\|!.,،؛]", " ", cleaned)

    noise_phrases = [
        "فایل صوتی آهنگ", "فایل صوتی موزیک", "فایل صوتی", "فایل آهنگ", "فایل موزیک", "فایل mp3",
        "دانلود آهنگ", "دانلود اهنگ", "دانلود ترانه", "دانلود موزیک",
        "رو برام دانلود کن", "رو برام بفرست", "رو برام بفرستید", "برام دانلود کن", "برام بفرست",
        "توی تلگرام بفرست", "در تلگرام بفرست", "توی چت بفرست", "توی تلگرام", "در تلگرام",
        "توی پیوی", "در پیوی", "توی چت", "داخل چت",
        "رو دانلود کن", "رو آپلود کن", "رو اپلود کن", "رو بفرست", "رو بفرستید", "رو بفرستین",
        "دانلودش کن", "آپلودش کن", "اپلودش کن", "بفرستش",
        "آپلود کن", "اپلود کن", "دانلود کن", "پخش کن", "پلی کن", "ارسال کن", "پیدا کن",
        "آپلود کنی", "اپلود کنی", "دانلود کنی", "پخش کنی", "پلی کنی", "ارسال کنی", "بفرستی",
        "آپلود کنید", "اپلود کنید", "دانلود کنید", "پخش کنید", "پلی کنید", "ارسال کنید", "بفرستید",
        "آپلود کنین", "اپلود کنین", "دانلود کنین", "بفرستین", "ارسال کنین",
        "میشه لطفاً", "میشه لطفا", "لطفاً", "لطفا", "بی‌زحمت", "بی زحمت", "میشه", "میتونی", "می‌تونی",
        "آهنگ جدید", "اهنگ جدید", "موزیک جدید", "ترانه جدید",
        "آهنگ کامل", "اهنگ کامل", "موزیک کامل", "ترانه کامل",
        "اهنگ", "آهنگ", "موزیک", "ترانه", "دانلود", "آپلود", "اپلود", "upload", "download",
        "remix", "ریمیکس", "320", "128", "full", "mp3", "new", "جدید", "کامل", "کیفیت",
        "اصلی", "original", "بفرست", "پخش", "پلی", "play", "رو بده", "رو بده برام",
        "بذار", "بزار", "بگذار", "بخوان", "بخون", "میخوام", "می‌خوام",
        "برام", "برامون", "واسم", "واسه من", "به من", "یه", "یک", "رو", "را", "کن", "کنی", "کنید", "کنین", "فایل", "صوتی", "تلگرام"
    ]
    for n in noise_phrases:
        cleaned = re.sub(rf"(?<!\w){re.escape(n)}(?!\w)", " ", cleaned, flags=re.IGNORECASE)

    res = " ".join(cleaned.split()).strip()
    # Strip leading 'از ' if present (e.g. 'یک آهنگ از هایده' -> 'هایده')
    res = re.sub(r"^از\s+", "", res).strip()
    return res


_MUSIC_COMMANDS = (
    "/music", "/song", "/play", "/ahang",
    "/pmusic", "/psong", "/pahang",
    "/p_music", "/p_song", "/p_ahang"
)

_MUSIC_EXPLICIT_PHRASES = (
    "دانلود آهنگ", "دانلود اهنگ", "دانلود موزیک", "دانلود ترانه",
    "آهنگ جدید", "اهنگ جدید", "موزیک جدید", "ترانه جدید",
    "آهنگ رو بفرست", "اهنگ رو بفرست", "موزیک رو بفرست",
    "آهنگ برام بفرست", "اهنگ برام بفرست", "موزیک برام بفرست",
    "آهنگ رو دانلود کن", "اهنگ رو دانلود کن", "موزیک رو دانلود کن",
    "آهنگ رو آپلود کن", "اهنگ رو آپلود کن", "موزیک رو آپلود کن",
    "آهنگ بده", "اهنگ بده", "موزیک بده",
    "آهنگ میخوام", "اهنگ میخوام", "موزیک میخوام", "آهنگ می‌خوام", "اهنگ می‌خوام", "موزیک می‌خوام",
    "آهنگ بزار", "اهنگ بزار", "موزیک بزار", "آهنگ بذار", "اهنگ بذار", "موزیک بذار"
)

_MUSIC_EXCLUSIONS = (
    "کیه", "کیست", "چرا", "چطور", "چگونه", "بیوگرافی", "اطلاعات", "آموزش",
    "نت آهنگ", "آکورد", "ساز", "تئوری", "تاریخچه", "کنسرت"
)

_MUSIC_INTENTS = ("آهنگ", "اهنگ", "موزیک", "ترانه", "music", "song", "mp3")
_MUSIC_ACTIONS = (
    "دانلود", "دانلودش", "دانلود کن", "دانلودش کن", "دانلود کنی", "دانلود کنید", "دانلود کنین", "دانلود نمیکنی",
    "آپلود", "اپلود", "آپلودش", "اپلودش", "آپلود کن", "اپلود کن", "آپلودش کن", "اپلودش کن", "آپلود کنی", "اپلود کنی", "آپلود کنید", "اپلود کنید", "آپلود کنین", "اپلود کنین", "آپلود نمیکنی",
    "بفرست", "بفرستش", "بفرستی", "بفرستین", "بفرستید", "میفرستی", "می‌فرستی", "میفرستین", "می‌فرستین", "بفرست برام",
    "ارسال", "ارسالش", "ارسال کن", "ارسالش کن", "ارسال کنی", "ارسال کنید", "ارسال کنین",
    "پخش", "پخشش", "پخش کن", "پخشش کن", "پخش کنی", "پخش کنید", "پخش کنین",
    "پلی", "پلیش", "پلی کن", "پلیش کن", "پلی کنی", "پلی کنید",
    "بذار", "بذارش", "بذاری", "بذارین", "بزار", "بزارش", "بزاری", "بزارین", "بگذار",
    "پیدا کن", "پیداش کن", "پیدا کنی",
    "بده", "بدین", "بده برام", "میخوام", "می‌خوام", "گوش بدیم", "گوش کنم", "گوش کنیم"
)


def is_music_request(text: str) -> bool:
    """Matches natural Persian queries explicitly requesting a song or music track."""
    t = text.lower().strip()
    if any(t.startswith(cmd) for cmd in _MUSIC_COMMANDS):
        return True
    if any(ex in t for ex in _MUSIC_EXCLUSIONS):
        return False
    if any(sp in t for sp in _MUSIC_EXPLICIT_PHRASES):
        return True
    if any(t.startswith(f"{m} ") for m in _MUSIC_INTENTS):
        return True
    has_m = any(re.search(rf"(?<!\w){re.escape(k)}(?!\w)", t) for k in _MUSIC_INTENTS)
    has_a = any(re.search(rf"(?<!\w){re.escape(a)}(?!\w)", t) for a in _MUSIC_ACTIONS)
    return has_m and has_a


def extract_music_query(text: str) -> Optional[str]:
    """Extracts the song title and artist from the query."""
    if not is_music_request(text):
        return None
    cleaned = clean_music_query(text)
    return cleaned if len(cleaned) >= 2 else None


async def _crawl_portal_fast(
    client: httpx.AsyncClient,
    url_pattern: str,
    regex_pattern: str,
    clean_q: str,
) -> Optional[Dict[str, Any]]:
    """Crawls a single portal with early exit on first valid MP3."""
    enc = urllib.parse.quote(clean_q)
    try:
        r = await client.get(url_pattern.format(q=enc), timeout=4.0)
        if r.status_code == 200:
            matches = re.findall(regex_pattern, r.text, re.DOTALL | re.IGNORECASE)
            q_words = [w.lower() for w in clean_q.split() if len(w) > 1]
            for m in matches[:3]:
                href = m[0] if isinstance(m, tuple) and m[0].startswith("http") else (m[1] if isinstance(m, tuple) and len(m) > 1 and m[1].startswith("http") else "")
                raw_t = m[1] if isinstance(m, tuple) and href == m[0] else (m[0] if isinstance(m, tuple) else "")

                if not href:
                    continue

                clean_title = BeautifulSoup(raw_t, "html.parser").get_text().strip()
                clean_title = re.sub(r"دانلود آهنگ|دانلود اهنگ|ریمیکس|موزیک|mp3", "", clean_title, flags=re.I).strip(" -—")

                # Verify relevance with query words if query has specific keywords
                if q_words and not any(w in clean_title.lower() or w in href.lower() for w in q_words):
                    continue

                # Track page fetch
                p_res = await client.get(href, timeout=4.0)
                if p_res.status_code == 200:
                    mp3s = re.findall(r"""href=["\x27](https?://[^\s"\x27]+\.mp3)""", p_res.text, re.IGNORECASE)
                    valid_mp3s = [
                        u for u in mp3s
                        if not any(b in u.lower() for b in ["voice", "advert", "ads", "intro", "teaser", "demo", "sample", "64.mp3"])
                    ]
                    if valid_mp3s:
                        mp3_320 = [u for u in valid_mp3s if "320" in u]
                        chosen = mp3_320[0] if mp3_320 else valid_mp3s[0]

                        # Extract performer
                        performer = ""
                        if "–" in clean_title or "-" in clean_title:
                            performer = re.split(r"[–-]", clean_title)[0].strip()[:50]
                        else:
                            performer = clean_q.split()[0] if clean_q else "هنرمند"

                        return {
                            "title": clean_title or clean_q.title(),
                            "performer": performer or "هنرمند",
                            "url": chosen,
                            "quality": "320kbps Original" if ("320" in chosen) else "128kbps HQ",
                        }
    except Exception as e:
        logger.debug(f"Portal crawl error ({url_pattern}): {e}")

    return None


async def _search_deezer_fast(client: httpx.AsyncClient, clean_q: str) -> Optional[Dict[str, Any]]:
    """Searches Deezer for tracks."""
    try:
        enc = urllib.parse.quote(clean_q)
        resp = await client.get(f"https://api.deezer.com/search?q={enc}&limit=3", timeout=3.0)
        if resp.status_code == 200:
            tracks = resp.json().get("data") or []
            if tracks:
                t = tracks[0]
                preview = t.get("preview")
                if preview:
                    return {
                        "title": t.get("title", clean_q.title()),
                        "performer": t.get("artist", {}).get("name", "هنرمند"),
                        "url": preview,
                        "quality": "Preview Track",
                    }
    except Exception as e:
        logger.debug(f"Deezer search error: {e}")
    return None


async def _extract_mp3_from_page(client: httpx.AsyncClient, page_url: str, page_title: str) -> Optional[Dict[str, Any]]:
    """Fetches a candidate song webpage and extracts clean MP3 direct links."""
    try:
        r = await client.get(page_url, timeout=4.0)
        if r.status_code == 200:
            mp3s = re.findall(r"""href=["\x27](https?://[^\s"\x27]+\.mp3)""", r.text, re.I)
            valid = [
                m for m in mp3s
                if not any(x in m.lower() for x in ['ads', 'advert', 'teaser', 'demo', '64.mp3', 'voice'])
            ]
            if valid:
                mp3_320 = [m for m in valid if '320' in m]
                chosen = mp3_320[0] if mp3_320 else valid[0]
                clean_title = re.sub(r'دانلود آهنگ|دانلود اهنگ|دانلود|mp3|320|128|-.*|\|.*|•.*', '', page_title, flags=re.I).strip()
                return {
                    'title': clean_title or page_title,
                    'performer': clean_title.split()[0] if clean_title else "هنرمند",
                    'url': chosen,
                    'quality': '320kbps Original' if '320' in chosen else '128kbps HQ'
                }
    except Exception:
        pass
    return None


async def download_mp3_stream(url: str, max_bytes: int = _MAX_AUDIO_BYTES, timeout_sec: float = 12.0) -> Optional[bytes]:
    """Streams MP3 file into memory buffer with absolute wall-clock timeout and URL quoting."""
    if not url or not url.startswith("http"):
        return None
    safe_url = clean_url(url)
    client = get_music_client()

    async def _stream():
        buf = io.BytesIO()
        async with client.stream("GET", safe_url, timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0)) as resp:
            if resp.status_code == 200:
                async for chunk in resp.aiter_bytes(chunk_size=131072):
                    buf.write(chunk)
                    if len(buf.getvalue()) > max_bytes:
                        logger.warning(f"MP3 stream exceeded limit: {len(buf.getvalue())} bytes")
                        return None
                raw = buf.getvalue()
                if len(raw) >= 100_000:
                    return raw
        return None

    try:
        return await asyncio.wait_for(_stream(), timeout=timeout_sec)
    except Exception as e:
        logger.warning(f"Error streaming MP3 from {safe_url}: {e}")
        return None


async def search_and_stream_music(clean_q: str) -> Optional[Tuple[Dict[str, Any], bytes]]:
    """
    Finds candidates via DuckDuckGo and portals, then downloads the first working MP3 stream directly.
    Guarantees that a returned track actually has complete downloadable audio bytes in memory.
    """
    client = get_music_client()
    candidates: List[Dict[str, Any]] = []

    # 1. Search DuckDuckGo for candidate pages
    search_terms = [f'دانلود آهنگ {clean_q} 320 mp3', f'دانلود آهنگ {clean_q}']
    pages: List[Tuple[str, str]] = []
    for st in search_terms:
        try:
            r = await client.post('https://html.duckduckgo.com/html/', data={'q': st}, timeout=5.0)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, 'html.parser')
                for a in soup.find_all('a', class_='result__a'):
                    h = a.get('href', '')
                    t = a.get_text().strip()
                    if 'uddg=' in h:
                        h = urllib.parse.unquote(re.search(r'uddg=([^&]+)', h).group(1))
                    if h.startswith('http') and not any(x in h for x in ['youtube.com', 'aparat.com', 'spotify.com', 'instagram.com', 'tarafdari.com']):
                        if not any(c[0] == h for c in pages):
                            pages.append((h, t))
            if len(pages) >= 6:
                break
        except Exception as e:
            logger.debug(f"DDG search error: {e}")

    # 2. Concurrently fetch candidate pages
    async def _fetch_cand(page_url: str, page_title: str) -> Optional[Dict[str, Any]]:
        return await _extract_mp3_from_page(client, page_url, page_title)

    if pages:
        tasks = [_fetch_cand(h, t) for h, t in pages[:6]]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r.get('url'):
                candidates.append(r)

    # 3. If no DDG candidates found, try direct portals
    if not candidates:
        portal_tasks = [
            _crawl_portal_fast(client, "https://musics-fa.com/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>', clean_q),
            _crawl_portal_fast(client, "https://golsarmusic.ir/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>', clean_q),
        ]
        portal_res = await asyncio.gather(*portal_tasks, return_exceptions=True)
        for pr in portal_res:
            if isinstance(pr, dict) and pr.get('url'):
                candidates.append(pr)

    # 4. Sort candidates: prioritize 320kbps
    candidates.sort(key=lambda c: 0 if "320" in c.get("quality", "") else 1)

    # 5. Try downloading candidate audio streams with early exit upon first success
    for cand in candidates[:4]:
        url = cand["url"]
        logger.info(f"Attempting MP3 download for '{clean_q}' from: {url}")
        raw = await download_mp3_stream(url, timeout_sec=12.0)
        if raw and len(raw) >= 100_000:
            logger.info(f"Successfully streamed {len(raw)} bytes for '{clean_q}'")
            return cand, raw

    # 6. Fallback to Deezer if available
    deezer_cand = await _search_deezer_fast(client, clean_q)
    if deezer_cand and deezer_cand.get("url"):
        raw = await download_mp3_stream(deezer_cand["url"], timeout_sec=8.0)
        if raw:
            return deezer_cand, raw

    return None


async def search_music_track(clean_q: str) -> Optional[Dict[str, Any]]:
    """Legacy helper: searches for track metadata and verifies existence."""
    res = await search_and_stream_music(clean_q)
    if res:
        cand, _ = res
        return cand
    return None


async def handle_music_request(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    query: str
):
    """
    Core music handler: searches, downloads, and directly uploads MP3 audio to Telegram chat.
    Uses continuous upload action indicator and caches file_id for sub-second redelivery.
    """
    message = update.effective_message
    chat = update.effective_chat
    if not message or not chat:
        return

    clean_q = clean_music_query(query)
    if not clean_q or len(clean_q) < 2:
        await message.reply_text(
            "🎵 **راهنمای دانلود موزیک پرومته:**\n\n"
            "لطفاً نام آهنگ یا خواننده مورد نظر را وارد نمایید.\n"
            "مثال: `/music هایده سوغاتی` یا `آهنگ مرغ سحر شجریان رو بفرست`",
            parse_mode=ParseMode.MARKDOWN
        )
        return

    # 1. Background Uploading Chat Action Loop
    is_active = True

    async def _action_loop():
        while is_active:
            try:
                await context.bot.send_chat_action(chat_id=chat.id, action=ChatAction.UPLOAD_VOICE)
            except Exception:
                pass
            await asyncio.sleep(3.5)

    action_task = asyncio.create_task(_action_loop())

    try:
        cache_key = f"MUSIC_FID_{clean_q.replace(' ', '_')}"

        # 2. Check KV Cache for Instant file_id Redelivery
        cached_file_id = await database.kv_get(cache_key)
        if cached_file_id:
            try:
                await message.reply_audio(
                    audio=cached_file_id,
                    caption=(
                        f"🎵 <b>{html.escape(clean_q.title())}</b>\n"
                        f"⚡ <i>تحویل فوری از کش ابری پرومته</i>"
                    ),
                    parse_mode=ParseMode.HTML
                )
                logger.info(f"Delivered music via cached file_id for '{clean_q}'")
                return
            except Exception as e_cid:
                logger.debug(f"Cached file_id invalid: {e_cid}")

        # 3. Search and stream MP3 bytes directly
        res = await search_and_stream_music(clean_q)
        if not res:
            await message.reply_text(
                f"❌ متأسفانه قطعه صوتی برای «<b>{html.escape(clean_q)}</b>» یافت نشد یا سرورهای دانلود پاسخگو نبودند.\n"
                f"لطفاً نام دقیق‌تر ترانه یا خواننده را امتحان نمایید.",
                parse_mode=ParseMode.HTML
            )
            return

        track, raw_bytes = res
        title = track.get("title") or clean_q.title()
        performer = track.get("performer") or "هنرمند"
        quality = track.get("quality") or "320kbps Original"

        caption = (
            f"🎵 <b>{html.escape(title)}</b>\n"
            f"🎤 <b>خواننده:</b> {html.escape(performer)}\n"
            f"• <b>کیفیت:</b> <code>{quality}</code>\n"
            f"⚡ <i>دانلود و ارسال اختصاصی توسط پرومته</i>"
        )

        audio_io = io.BytesIO(raw_bytes)
        safe_fname = re.sub(r'[\\/*?:"<>|]', "", title).strip() or "track"
        audio_io.name = f"{safe_fname}.mp3"

        sent_msg = await message.reply_audio(
            audio=audio_io,
            title=title,
            performer=performer,
            caption=caption,
            parse_mode=ParseMode.HTML,
            write_timeout=120.0,
            read_timeout=60.0,
        )
        logger.info(f"Delivered music via streamed bytes for '{clean_q}' ({len(raw_bytes)} bytes)")

        # 4. Cache file_id in Cloudflare KV for sub-second redelivery
        if sent_msg and sent_msg.audio and sent_msg.audio.file_id:
            await database.kv_set(cache_key, sent_msg.audio.file_id, ttl_sec=86400 * 30)

    except Exception as err:
        logger.error(f"Error handling music request: {err}", exc_info=True)
        await message.reply_text(f"❌ خطا در پردازش و ارسال موزیک: {str(err)}")
    finally:
        is_active = False
        action_task.cancel()
        try:
            await action_task
        except asyncio.CancelledError:
            pass
