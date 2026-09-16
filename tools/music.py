"""
Specialized Music Search, Download & Telegram Audio Uploader for Prometheus:
Finds, extracts, streams, and uploads high-fidelity studio MP3 tracks (320kbps & 128kbps)
directly to Telegram chats with cover art, metadata, and sub-second file_id caching.
Uses parallel racing crawler across top Iranian and global portals with early-exit optimization.
"""

import re
import io
import time
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
from utils.formatter import strip_thinking

logger = logging.getLogger("MusicTool")

_MAX_AUDIO_BYTES = 25 * 1024 * 1024  # Telegram bot limit (25 MB)

_MUSIC_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

MUSIC_PORTALS = [
    ("https://upmusics.com/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>'),
    ("https://behmelody.in/?s={q}", r'<a\s+title=[\"\']([^\"\']+)[\"\']\s+href=[\"\'](https?://behmelody\.in/[^\"\']+)[\"\']'),
    ("https://tabamusic.com/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>'),
    ("https://golsarmusic.ir/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>'),
    ("https://muzicir.com/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>'),
    ("https://music-fa.com/?s={q}", r'<h2[^>]*>.*?<a\s+href=[\"\']([^\"\']+)[\"\'][^>]*>(.*?)</a>.*?</h2>'),
]

_MUSIC_CLIENT: Optional[httpx.AsyncClient] = None


def get_music_client() -> httpx.AsyncClient:
    """Returns shared AsyncClient with keepalive connection pooling."""
    global _MUSIC_CLIENT
    if _MUSIC_CLIENT is None or _MUSIC_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=30, max_connections=60, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=2.5, read=4.5, write=3.0, pool=3.0)
        _MUSIC_CLIENT = httpx.AsyncClient(limits=limits, timeout=timeout, headers=_MUSIC_HEADERS, follow_redirects=True)
    return _MUSIC_CLIENT


def clean_music_query(q: str) -> str:
    """Strips conversational noise, filler words, and punctuation from music queries."""
    cleaned = re.sub(r'[\\/:\*\?\"<>\|]', ' ', q or '')
    noise = [
        "دانلود آهنگ", "دانلود اهنگ", "اهنگ", "آهنگ", "موزیک", "ترانه", "دانلود",
        "remix", "ریمیکس", "320", "128", "full", "mp3", "new", "جدید", "کامل",
        "اصلی", "original", "بفرست", "پخش کن", "پلی کن", "رو بده", "رو بفرست",
        "بذار", "بزار", "بخوان", "بخون", "پیدا کن", "میخوام", "می‌خوام",
        "لطفا", "لطفاً", "برام", "برامون", "یه", "یک", "رو", "را",
    ]
    for n in noise:
        cleaned = re.sub(rf"\b{n}\b", " ", cleaned, flags=re.IGNORECASE)
    return " ".join(cleaned.split()).strip()


_MUSIC_COMMANDS = ("/music", "/song", "/play", "/ahang")

_MUSIC_EXPLICIT_PHRASES = (
    "دانلود آهنگ", "دانلود اهنگ", "دانلود موزیک", "دانلود ترانه",
    "آهنگ رو بفرست", "اهنگ رو بفرست", "موزیک رو بفرست",
    "آهنگ برام بفرست", "اهنگ برام بفرست", "موزیک برام بفرست",
    "آهنگ جدید", "اهنگ جدید", "موزیک جدید",
    "آهنگ رو دانلود کن", "اهنگ رو دانلود کن", "موزیک رو دانلود کن"
)

_MUSIC_EXCLUSIONS = (
    "کیه", "کیست", "چرا", "چطور", "چگونه", "بیوگرافی", "اطلاعات", "آموزش",
    "نت آهنگ", "آکورد", "ساز", "تئوری", "تاریخچه", "کنسرت"
)

_MUSIC_INTENTS = ("آهنگ", "اهنگ", "موزیک", "ترانه", "music", "song", "mp3")
_MUSIC_ACTIONS = ("دانلود", "بفرست", "پخش", "پلی", "پخش کن", "پلی کن", "ارسال کن", "دانلود کن", "بذار", "بزار", "بگذار")


def is_music_request(text: str) -> bool:
    """Matches natural Persian queries explicitly requesting a song or music track."""
    t = text.lower().strip()
    if any(t.startswith(cmd) for cmd in _MUSIC_COMMANDS):
        return True
    if any(ex in t for ex in _MUSIC_EXCLUSIONS):
        return False
    if any(sp in t for sp in _MUSIC_EXPLICIT_PHRASES):
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
        r = await client.get(url_pattern.format(q=enc), timeout=3.5)
        if r.status_code == 200:
            matches = re.findall(regex_pattern, r.text, re.DOTALL | re.IGNORECASE)
            for m in matches[:2]:
                href = m[0] if isinstance(m, tuple) and m[0].startswith("http") else (m[1] if isinstance(m, tuple) and len(m) > 1 and m[1].startswith("http") else "")
                raw_t = m[1] if isinstance(m, tuple) and href == m[0] else (m[0] if isinstance(m, tuple) else "")

                if not href:
                    continue

                clean_title = BeautifulSoup(raw_t, "html.parser").get_text().strip()
                clean_title = re.sub(r"دانلود آهنگ|دانلود اهنگ|ریمیکس|موزیک|mp3", "", clean_title, flags=re.I).strip(" -—")

                # Track page fetch
                p_res = await client.get(href, timeout=3.5)
                if p_res.status_code == 200:
                    mp3s = re.findall(r'href=[\"\'](https?://[^\"\']+\.mp3)[\"\']', p_res.text, re.IGNORECASE)
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


async def search_music_track(clean_q: str) -> Optional[Dict[str, Any]]:
    """
    Races multiple music portals concurrently.
    Returns the first matching candidate with early exit for sub-second performance.
    """
    client = get_music_client()
    tasks = [
        asyncio.create_task(_crawl_portal_fast(client, pat, reg, clean_q))
        for pat, reg in MUSIC_PORTALS
    ]
    tasks.append(asyncio.create_task(_search_deezer_fast(client, clean_q)))

    best_candidate: Optional[Dict[str, Any]] = None

    for fut in asyncio.as_completed(tasks):
        try:
            res = await fut
            if res and res.get("url"):
                # If we find a 320kbps full track, return immediately!
                if "320" in res.get("quality", ""):
                    for t in tasks:
                        t.cancel()
                    return res
                if not best_candidate:
                    best_candidate = res
        except Exception:
            pass

    return best_candidate


async def download_mp3_stream(url: str, max_bytes: int = _MAX_AUDIO_BYTES) -> Optional[bytes]:
    """Streams MP3 file into memory buffer with size and timeout guards."""
    if not url or not url.startswith("http"):
        return None
    try:
        client = get_music_client()
        buf = io.BytesIO()
        async with client.stream("GET", url, timeout=20.0) as resp:
            if resp.status_code == 200:
                total = 0
                async for chunk in resp.aiter_bytes(chunk_size=131072):
                    total += len(chunk)
                    if total > max_bytes:
                        logger.warning(f"MP3 stream exceeded limit: {total} bytes")
                        return None
                    buf.write(chunk)
                raw = buf.getvalue()
                if len(raw) >= 200_000:
                    return raw
    except Exception as e:
        logger.warning(f"Error streaming MP3 from {url}: {e}")
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
    if not clean_q:
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
                        f"🎵 <b>{clean_q.title()}</b>\n"
                        f"⚡ <i>تحویل فوری از کش ابری پرومته</i>"
                    ),
                    parse_mode=ParseMode.HTML
                )
                logger.info(f"Delivered music via cached file_id for '{clean_q}'")
                return
            except Exception as e_cid:
                logger.debug(f"Cached file_id invalid: {e_cid}")

        # 3. Search Portals
        track = await search_music_track(clean_q)
        if not track:
            await message.reply_text(
                f"❌ متأسفانه قطعه صوتی برای «<b>{clean_q}</b>» یافت نشد.\n"
                f"لطفاً نام خواننده یا بخش دیگری از متن ترانه را امتحان نمایید.",
                parse_mode=ParseMode.HTML
            )
            return

        title = track.get("title") or clean_q.title()
        performer = track.get("performer") or "هنرمند"
        quality = track.get("quality") or "320kbps Original"
        audio_url = track["url"]

        caption = (
            f"🎵 <b>{title}</b>\n"
            f"🎤 <b>خواننده:</b> {performer}\n"
            f"• <b>کیفیت:</b> <code>{quality}</code>\n"
            f"⚡ <i>دانلود و ارسال اختصاصی توسط پرومته</i>"
        )

        # 4. Attempt Direct Telegram URL Delivery
        sent_msg = None
        try:
            sent_msg = await message.reply_audio(
                audio=audio_url,
                title=title,
                performer=performer,
                caption=caption,
                parse_mode=ParseMode.HTML,
                write_timeout=60.0,
                read_timeout=60.0,
            )
            logger.info(f"Delivered music via direct URL for '{clean_q}'")
        except Exception as e_url:
            logger.debug(f"Direct URL send failed ({e_url}), streaming bytes into buffer...")

            # 5. Fallback: Stream bytes directly and upload
            raw_bytes = await download_mp3_stream(audio_url)
            if raw_bytes:
                audio_io = io.BytesIO(raw_bytes)
                audio_io.name = f"{title}.mp3"
                sent_msg = await message.reply_audio(
                    audio=audio_io,
                    title=title,
                    performer=performer,
                    caption=caption,
                    parse_mode=ParseMode.HTML,
                    write_timeout=90.0,
                    read_timeout=60.0,
                )
                logger.info(f"Delivered music via streamed bytes for '{clean_q}'")
            else:
                await message.reply_text(
                    f"⚠️ لینک قطعه صوتی «{title}» استخراج شد اما بارگیری آن مقدور نبود:\n🔗 {audio_url}"
                )
                return

        # 6. Cache file_id for sub-second redelivery
        if sent_msg and sent_msg.audio and sent_msg.audio.file_id:
            await database.kv_set(cache_key, sent_msg.audio.file_id, ttl_sec=86400 * 14)

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
