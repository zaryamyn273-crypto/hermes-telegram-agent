"""
Telegram Media Group (Album) Cache & Multimodal Coordinator for Prometheus.
Tracks, groups, and persists all photos belonging to Telegram albums (media_group_id)
so that replying to any single photo in an album or sending a direct multi-photo album
allows the vision engine to see and analyze all photos in that album simultaneously.
"""

import time
import json
import logging
import asyncio
from collections import OrderedDict
from typing import List, Dict, Any, Optional, Tuple, Callable

import database

logger = logging.getLogger("MediaGroupManager")

# In-memory LRU caches for high-speed sub-millisecond retrieval
# 1. Key: f"{chat_id}:{media_group_id}" -> list of {message_id, file_id, timestamp, caption}
_RAM_MEDIA_GROUPS: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
# 2. Key: f"{chat_id}:{message_id}" -> media_group_id
_RAM_MSG_TO_MG: "OrderedDict[str, str]" = OrderedDict()
# 3. Key: file_id -> (chat_id, media_group_id)
_RAM_FID_TO_MG: "OrderedDict[str, Tuple[int, str]]" = OrderedDict()

_RAM_LOCK = asyncio.Lock()
_MAX_RAM_ALBUMS = 2000
_MAX_RAM_MAPPINGS = 10000

# Debounce tasks for incoming albums: f"{chat_id}:{media_group_id}" -> asyncio.Task
_ALBUM_TIMERS: Dict[str, asyncio.Task] = {}
_ALBUM_ACCUMULATORS: Dict[str, Dict[str, Any]] = {}


async def record_media_group_photo(
    chat_id: int,
    media_group_id: str,
    message_id: int,
    file_id: str,
    caption: Optional[str] = None
) -> None:
    """
    Records a photo belonging to a media group (album).
    Saves to RAM triple-index and persists to Cloudflare KV.
    """
    if not media_group_id or not file_id:
        return

    mg_id_str = str(media_group_id).strip()
    mg_key = f"{chat_id}:{mg_id_str}"
    msg_key = f"{chat_id}:{message_id}"
    now = time.time()

    async with _RAM_LOCK:
        # 1. Update Media Group List
        if mg_key not in _RAM_MEDIA_GROUPS:
            if len(_RAM_MEDIA_GROUPS) >= _MAX_RAM_ALBUMS:
                _RAM_MEDIA_GROUPS.popitem(last=False)
            _RAM_MEDIA_GROUPS[mg_key] = []

        entries = _RAM_MEDIA_GROUPS[mg_key]
        if not any(e.get("message_id") == message_id or e.get("file_id") == file_id for e in entries):
            entries.append({
                "message_id": message_id,
                "file_id": file_id,
                "timestamp": now,
                "caption": caption
            })
            _RAM_MEDIA_GROUPS.move_to_end(mg_key)

        # 2. Update message_id -> media_group_id mapping
        if len(_RAM_MSG_TO_MG) >= _MAX_RAM_MAPPINGS:
            _RAM_MSG_TO_MG.popitem(last=False)
        _RAM_MSG_TO_MG[msg_key] = mg_id_str
        _RAM_MSG_TO_MG.move_to_end(msg_key)

        # 3. Update file_id -> media_group_id mapping
        if len(_RAM_FID_TO_MG) >= _MAX_RAM_MAPPINGS:
            _RAM_FID_TO_MG.popitem(last=False)
        _RAM_FID_TO_MG[file_id] = (chat_id, mg_id_str)
        _RAM_FID_TO_MG.move_to_end(file_id)

        file_ids_snapshot = [e["file_id"] for e in entries]

    # Asynchronously persist to Cloudflare KV (7 days TTL)
    asyncio.create_task(
        database.kv_set(
            key=f"MG_{chat_id}_{mg_id_str}",
            value=json.dumps(file_ids_snapshot),
            ttl_sec=86400 * 7
        )
    )
    asyncio.create_task(
        database.kv_set(
            key=f"MID_{chat_id}_{message_id}",
            value=mg_id_str,
            ttl_sec=86400 * 7
        )
    )


async def resolve_media_group_id(
    chat_id: int,
    media_group_id: Optional[str] = None,
    message_id: Optional[int] = None,
    file_id: Optional[str] = None
) -> Optional[str]:
    """
    Robustly resolves the media_group_id for a message or photo.
    Handles cases where Telegram strips media_group_id on replies.
    """
    if media_group_id:
        return str(media_group_id).strip()

    async with _RAM_LOCK:
        # 1. Direct message_id lookup in RAM
        if message_id:
            msg_key = f"{chat_id}:{message_id}"
            if msg_key in _RAM_MSG_TO_MG:
                return _RAM_MSG_TO_MG[msg_key]

            # Check adjacent message IDs (album photos have consecutive message IDs)
            for delta in [-1, 1, -2, 2, -3, 3]:
                adj_key = f"{chat_id}:{message_id + delta}"
                if adj_key in _RAM_MSG_TO_MG:
                    return _RAM_MSG_TO_MG[adj_key]

        # 2. file_id lookup in RAM
        if file_id and file_id in _RAM_FID_TO_MG:
            return _RAM_FID_TO_MG[file_id][1]

    # 3. Fallback to Cloudflare KV for message_id
    if message_id:
        try:
            val = await database.kv_get(f"MID_{chat_id}_{message_id}")
            if val:
                return str(val).strip()
            # Check adjacent in KV
            for delta in [-1, 1, -2, 2]:
                adj_val = await database.kv_get(f"MID_{chat_id}_{message_id + delta}")
                if adj_val:
                    return str(adj_val).strip()
        except Exception as e:
            logger.debug(f"KV error resolving MID for {message_id}: {e}")

    return None


async def get_media_group_photos(
    chat_id: int,
    media_group_id: str,
    wait_for_incoming: bool = False
) -> List[str]:
    """
    Retrieves all photo file_ids belonging to a media group.
    Checks RAM first, then Cloudflare KV.
    If wait_for_incoming is True, waits up to 1.2s for all album photos to arrive.
    """
    if not media_group_id:
        return []

    mg_id_str = str(media_group_id).strip()
    mg_key = f"{chat_id}:{mg_id_str}"

    if wait_for_incoming:
        # Poll up to 1.2s until album size stabilizes
        prev_count = 0
        for _ in range(8):
            await asyncio.sleep(0.15)
            async with _RAM_LOCK:
                curr_count = len(_RAM_MEDIA_GROUPS.get(mg_key, []))
            if curr_count > 0 and curr_count == prev_count:
                break
            prev_count = curr_count

    async with _RAM_LOCK:
        if mg_key in _RAM_MEDIA_GROUPS:
            entries = _RAM_MEDIA_GROUPS[mg_key]
            if entries:
                _RAM_MEDIA_GROUPS.move_to_end(mg_key)
                return [e["file_id"] for e in entries]

    # Fallback to Cloudflare KV
    kv_key = f"MG_{chat_id}_{mg_id_str}"
    try:
        cached_json = await database.kv_get(kv_key)
        if cached_json:
            parsed = json.loads(cached_json)
            if isinstance(parsed, list) and parsed:
                async with _RAM_LOCK:
                    _RAM_MEDIA_GROUPS[mg_key] = [
                        {"message_id": 0, "file_id": fid, "timestamp": time.time(), "caption": None}
                        for fid in parsed
                    ]
                return parsed
    except Exception as e:
        logger.debug(f"KV media group lookup error for {kv_key}: {e}")

    return []


async def debounce_incoming_album(
    chat_id: int,
    media_group_id: str,
    message_id: int,
    file_id: str,
    caption: Optional[str],
    on_ready_callback: Callable,
    delay: float = 1.0
) -> None:
    """
    Debounces incoming album messages: collects all photos across arriving updates
    and fires exactly ONE vision processing task once all album photos are collected.
    """
    mg_id_str = str(media_group_id).strip()
    mg_key = f"{chat_id}:{mg_id_str}"

    # Record photo first
    await record_media_group_photo(
        chat_id=chat_id,
        media_group_id=mg_id_str,
        message_id=message_id,
        file_id=file_id,
        caption=caption
    )

    if mg_key not in _ALBUM_ACCUMULATORS:
        _ALBUM_ACCUMULATORS[mg_key] = {
            "caption": caption or "",
            "latest_msg_id": message_id
        }
    else:
        if caption and not _ALBUM_ACCUMULATORS[mg_key]["caption"]:
            _ALBUM_ACCUMULATORS[mg_key]["caption"] = caption
        _ALBUM_ACCUMULATORS[mg_key]["latest_msg_id"] = max(
            _ALBUM_ACCUMULATORS[mg_key]["latest_msg_id"], message_id
        )

    # Cancel previous timer if still waiting for more photos
    if mg_key in _ALBUM_TIMERS:
        _ALBUM_TIMERS[mg_key].cancel()

    async def _debounced_worker():
        try:
            await asyncio.sleep(delay)
            meta = _ALBUM_ACCUMULATORS.pop(mg_key, {})
            _ALBUM_TIMERS.pop(mg_key, None)
            all_fids = await get_media_group_photos(chat_id, mg_id_str)
            if all_fids:
                await on_ready_callback(mg_id_str, all_fids, meta.get("caption", ""))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error in album debounced worker for {mg_key}: {e}")

    _ALBUM_TIMERS[mg_key] = asyncio.create_task(_debounced_worker())
