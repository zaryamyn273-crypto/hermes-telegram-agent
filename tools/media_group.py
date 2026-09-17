"""
Telegram Media Group (Album) Cache & Multimodal Coordinator for Prometheus.
Tracks, groups, and persists all photos belonging to Telegram albums (media_group_id)
so that replying to any single photo in an album allows the vision engine
to see and analyze all photos in that album simultaneously.
"""

import time
import json
import logging
import asyncio
from collections import OrderedDict
from typing import List, Dict, Any, Optional, Tuple

import database

logger = logging.getLogger("MediaGroupManager")

# In-memory LRU cache for high-speed sub-millisecond retrieval
# Key: f"{chat_id}:{media_group_id}" -> list of (message_id, file_id, timestamp)
_RAM_MEDIA_GROUPS: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
_RAM_LOCK = asyncio.Lock()
_MAX_RAM_ALBUMS = 1500
_TTL_RAM_SECONDS = 7200  # 2 hours in RAM


async def record_media_group_photo(
    chat_id: int,
    media_group_id: str,
    message_id: int,
    file_id: str
) -> None:
    """
    Records a photo belonging to a media group (album).
    Saves to RAM LRU cache and persists to Cloudflare KV.
    """
    if not media_group_id or not file_id:
        return

    mg_key = f"{chat_id}:{media_group_id}"
    now = time.time()

    async with _RAM_LOCK:
        if mg_key not in _RAM_MEDIA_GROUPS:
            if len(_RAM_MEDIA_GROUPS) >= _MAX_RAM_ALBUMS:
                _RAM_MEDIA_GROUPS.popitem(last=False)
            _RAM_MEDIA_GROUPS[mg_key] = []

        entries = _RAM_MEDIA_GROUPS[mg_key]
        # Avoid duplicate message_id or file_id
        if not any(e.get("message_id") == message_id or e.get("file_id") == file_id for e in entries):
            entries.append({
                "message_id": message_id,
                "file_id": file_id,
                "timestamp": now
            })
            _RAM_MEDIA_GROUPS.move_to_end(mg_key)

        file_ids_snapshot = [e["file_id"] for e in entries]

    # Asynchronously persist to Cloudflare KV for durability across bot redeployments (7 days TTL)
    kv_key = f"MG_{chat_id}_{media_group_id}"
    asyncio.create_task(
        database.kv_set(
            key=kv_key,
            value=json.dumps(file_ids_snapshot),
            ttl_sec=86400 * 7
        )
    )


async def get_media_group_photos(
    chat_id: int,
    media_group_id: str,
    wait_for_incoming: bool = False
) -> List[str]:
    """
    Retrieves all photo file_ids belonging to a media group.
    Checks RAM first, then Cloudflare KV.
    If wait_for_incoming is True, waits up to 0.5s for trailing album photos to arrive.
    """
    if not media_group_id:
        return []

    mg_key = f"{chat_id}:{media_group_id}"

    if wait_for_incoming:
        # Give Telegram a few hundred ms to deliver other photos of the same album
        await asyncio.sleep(0.5)

    async with _RAM_LOCK:
        if mg_key in _RAM_MEDIA_GROUPS:
            entries = _RAM_MEDIA_GROUPS[mg_key]
            if entries:
                _RAM_MEDIA_GROUPS.move_to_end(mg_key)
                return [e["file_id"] for e in entries]

    # Fallback to Cloudflare KV
    kv_key = f"MG_{chat_id}_{media_group_id}"
    try:
        cached_json = await database.kv_get(kv_key)
        if cached_json:
            parsed = json.loads(cached_json)
            if isinstance(parsed, list) and parsed:
                # Populate back to RAM cache
                async with _RAM_LOCK:
                    _RAM_MEDIA_GROUPS[mg_key] = [
                        {"message_id": 0, "file_id": fid, "timestamp": time.time()}
                        for fid in parsed
                    ]
                return parsed
    except Exception as e:
        logger.debug(f"KV media group lookup error for {kv_key}: {e}")

    return []
