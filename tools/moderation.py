"""
Comprehensive High-Performance Moderation & Governance Engine for Prometheus:
- Multi-tier User & Group Ban/Unban Management with Persistent Cloudflare D1 Storage
- Timed User Muting with Auto-Expiry and Group Bot Muting
- Group Authorization & Admin Approval Workflow (Default-Inactive for Unknown Groups)
- Persistent Audit Logging for All Admin Commands and Actions
- Sub-millisecond In-Memory RAM Caches for Instant Non-Blocking Filtering
"""

import os
import re
import json
import time
import logging
import asyncio
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set, Union

from config import settings, is_admin
import database

logger = logging.getLogger("PrometheusModeration")

# =========================================================================
# In-Memory RAM Caches (Tier 1 Sub-Millisecond Filtering)
# =========================================================================

_MOD_LOCK = threading.Lock()

# user_id -> dict
_BANNED_USERS: Dict[int, Dict[str, Any]] = {}
# username.lower() -> dict
_BANNED_USERNAMES: Dict[str, Dict[str, Any]] = {}

# user_id -> dict (includes until_ts)
_MUTED_USERS: Dict[int, Dict[str, Any]] = {}
# username.lower() -> dict (includes until_ts)
_MUTED_USERNAMES: Dict[str, Dict[str, Any]] = {}

# chat_id -> dict
_BANNED_GROUPS: Dict[int, Dict[str, Any]] = {}

# chat_id -> dict (includes until_ts; 0 = indefinite)
_MUTED_GROUPS: Dict[int, Dict[str, Any]] = {}

# chat_id -> dict (status: 'active' | 'approved' | 'pending' | 'rejected' | 'left')
_TRACKED_GROUPS: Dict[int, Dict[str, Any]] = {}

# Track pending notification sent to admins so we don't spam them on every message
_PENDING_NOTIFIED_CHATS: Set[int] = set()

# In-memory fast cache for custom settings & directives (key_name -> dict)
_ADMIN_SETTINGS: Dict[str, Dict[str, Any]] = {}

# In-memory circular buffer for recent admin commands
_ADMIN_COMMANDS_CACHE: deque = deque(maxlen=100)

_ENGINE_INITIALIZED: bool = False


# =========================================================================
# Database Initialization & Hydration
# =========================================================================

async def init_moderation_engine():
    """
    Initializes database tables and hydrates fast L1 in-memory caches from Cloudflare D1.
    """
    global _ENGINE_INITIALIZED
    logger.info("Initializing Prometheus Moderation Engine...")

    # Ensure required tables exist in Cloudflare D1
    schema_stmts = [
        """CREATE TABLE IF NOT EXISTS banned_users (
            user_id INTEGER PRIMARY KEY,
            name TEXT DEFAULT '',
            username TEXT DEFAULT '',
            reason TEXT,
            banned_by INTEGER,
            banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            first_name TEXT DEFAULT '',
            source_chat_id INTEGER DEFAULT 0,
            source_chat_title TEXT DEFAULT ''
        );""",
        """CREATE TABLE IF NOT EXISTS muted_users (
            user_id INTEGER PRIMARY KEY,
            username TEXT,
            first_name TEXT DEFAULT '',
            reason TEXT,
            muted_by INTEGER DEFAULT 0,
            source_chat_id INTEGER DEFAULT 0,
            source_chat_title TEXT DEFAULT '',
            until_ts REAL DEFAULT 0,
            muted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        """CREATE TABLE IF NOT EXISTS banned_groups (
            chat_id INTEGER PRIMARY KEY,
            title TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            banned_by INTEGER DEFAULT 0,
            banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        """CREATE TABLE IF NOT EXISTS muted_groups (
            chat_id INTEGER PRIMARY KEY,
            title TEXT DEFAULT '',
            until_ts REAL DEFAULT 0,
            muted_by INTEGER DEFAULT 0,
            muted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        """CREATE TABLE IF NOT EXISTS tracked_groups (
            chat_id INTEGER PRIMARY KEY,
            title TEXT,
            chat_type TEXT,
            member_count INTEGER DEFAULT 0,
            added_by INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            username TEXT DEFAULT '',
            invite_link TEXT DEFAULT '',
            status TEXT DEFAULT 'active'
        );""",
        """CREATE TABLE IF NOT EXISTS admin_commands_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER,
            command TEXT,
            args TEXT,
            target_id INTEGER DEFAULT 0,
            target_username TEXT DEFAULT '',
            details TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        """CREATE TABLE IF NOT EXISTS unbanned_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entity_type TEXT,
            entity_id INTEGER,
            username TEXT DEFAULT '',
            title TEXT DEFAULT '',
            unbanned_by INTEGER,
            reason TEXT DEFAULT '',
            unbanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );""",
        """CREATE TABLE IF NOT EXISTS custom_data_store (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT UNIQUE NOT NULL,
            data_value TEXT NOT NULL,
            category TEXT DEFAULT 'general',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );"""
    ]

    for stmt in schema_stmts:
        try:
            await database.execute_d1_query(stmt)
        except Exception as e:
            logger.warning(f"Error executing schema statement: {e}")

    # Hydrate Caches from Cloudflare D1
    await refresh_moderation_caches()
    _ENGINE_INITIALIZED = True
    logger.info("Prometheus Moderation Engine successfully initialized.")


async def refresh_moderation_caches():
    """Fetches all moderation states from D1 into RAM."""
    now = time.time()

    # 1. Banned Users
    res_banned = await database.execute_d1_query("SELECT * FROM banned_users")
    if res_banned.get("success"):
        with _MOD_LOCK:
            _BANNED_USERS.clear()
            _BANNED_USERNAMES.clear()
            for r in res_banned.get("results", []):
                uid = r.get("user_id")
                uname = (r.get("username") or "").lower().lstrip("@")
                if uid:
                    _BANNED_USERS[int(uid)] = r
                if uname:
                    _BANNED_USERNAMES[uname] = r

    # 2. Muted Users (filter out already expired)
    res_muted = await database.execute_d1_query("SELECT * FROM muted_users")
    if res_muted.get("success"):
        with _MOD_LOCK:
            _MUTED_USERS.clear()
            _MUTED_USERNAMES.clear()
            for r in res_muted.get("results", []):
                uid = r.get("user_id")
                uname = (r.get("username") or "").lower().lstrip("@")
                until_ts = float(r.get("until_ts") or 0)
                if until_ts > 0 and until_ts <= now:
                    # Expired, queue delete from D1
                    asyncio.create_task(database.execute_d1_query("DELETE FROM muted_users WHERE user_id = ?", [uid]))
                    continue
                if uid:
                    _MUTED_USERS[int(uid)] = r
                if uname:
                    _MUTED_USERNAMES[uname] = r

    # 3. Banned Groups
    res_bgroups = await database.execute_d1_query("SELECT * FROM banned_groups")
    if res_bgroups.get("success"):
        with _MOD_LOCK:
            _BANNED_GROUPS.clear()
            for r in res_bgroups.get("results", []):
                cid = r.get("chat_id")
                if cid:
                    _BANNED_GROUPS[int(cid)] = r

    # 4. Muted Groups
    res_mgroups = await database.execute_d1_query("SELECT * FROM muted_groups")
    if res_mgroups.get("success"):
        with _MOD_LOCK:
            _MUTED_GROUPS.clear()
            for r in res_mgroups.get("results", []):
                cid = r.get("chat_id")
                until_ts = float(r.get("until_ts") or 0)
                if until_ts > 0 and until_ts <= now:
                    asyncio.create_task(database.execute_d1_query("DELETE FROM muted_groups WHERE chat_id = ?", [cid]))
                    continue
                if cid:
                    _MUTED_GROUPS[int(cid)] = r

    # 5. Tracked Groups & Approvals
    res_tgroups = await database.execute_d1_query("SELECT * FROM tracked_groups")
    if res_tgroups.get("success"):
        with _MOD_LOCK:
            _TRACKED_GROUPS.clear()
            for r in res_tgroups.get("results", []):
                cid = r.get("chat_id")
                if cid:
                    int_cid = int(cid)
                    _TRACKED_GROUPS[int_cid] = r
                    if r.get("status") == "pending":
                        _PENDING_NOTIFIED_CHATS.add(int_cid)

    # 6. Admin Custom Settings & Directives
    res_settings = await database.execute_d1_query("SELECT key_name, data_value, category, updated_at FROM custom_data_store")
    if res_settings.get("success"):
        with _MOD_LOCK:
            _ADMIN_SETTINGS.clear()
            for r in res_settings.get("results", []):
                k = r.get("key_name")
                if k:
                    _ADMIN_SETTINGS[k] = r

    # 7. Recent Admin Commands Log
    res_logs = await database.execute_d1_query("SELECT * FROM admin_commands_log ORDER BY id DESC LIMIT 50")
    if res_logs.get("success"):
        with _MOD_LOCK:
            _ADMIN_COMMANDS_CACHE.clear()
            for r in reversed(res_logs.get("results", [])):
                _ADMIN_COMMANDS_CACHE.appendleft(r)


# =========================================================================
# Real-Time Fast Lookups (< 0.001ms)
# =========================================================================

def is_user_banned(user_id: Optional[int], username: Optional[str] = None) -> bool:
    """Returns True if the user is currently banned from using the bot."""
    if not user_id and not username:
        return False
    with _MOD_LOCK:
        if user_id and int(user_id) in _BANNED_USERS:
            return True
        if username:
            clean_name = username.lower().lstrip("@").strip()
            if clean_name and clean_name in _BANNED_USERNAMES:
                return True
    return False


def is_user_muted(user_id: Optional[int], username: Optional[str] = None) -> Tuple[bool, float]:
    """
    Returns (True, remaining_seconds) if the user is currently muted.
    If the mute period has expired, automatically cleans up and returns (False, 0.0).
    """
    if not user_id and not username:
        return False, 0.0

    now = time.time()
    expired_uid = None

    with _MOD_LOCK:
        record = None
        if user_id and int(user_id) in _MUTED_USERS:
            record = _MUTED_USERS[int(user_id)]
        elif username:
            clean_name = username.lower().lstrip("@").strip()
            if clean_name and clean_name in _MUTED_USERNAMES:
                record = _MUTED_USERNAMES[clean_name]

        if not record:
            return False, 0.0

        until_ts = float(record.get("until_ts") or 0)
        if until_ts == 0 or until_ts > now:
            remaining = max(1.0, until_ts - now) if until_ts > 0 else 999999.0
            return True, remaining
        else:
            # Expired! Remove from memory cache
            expired_uid = record.get("user_id")
            if expired_uid:
                _MUTED_USERS.pop(int(expired_uid), None)
            uname = (record.get("username") or "").lower().lstrip("@")
            if uname:
                _MUTED_USERNAMES.pop(uname, None)

    # Clean expired from D1 asynchronously
    if expired_uid:
        asyncio.create_task(database.execute_d1_query("DELETE FROM muted_users WHERE user_id = ?", [expired_uid]))

    return False, 0.0


def is_group_banned(chat_id: int) -> bool:
    """Returns True if the group is banned."""
    if not chat_id:
        return False
    with _MOD_LOCK:
        return int(chat_id) in _BANNED_GROUPS


def is_group_muted(chat_id: int) -> Tuple[bool, float]:
    """
    Returns (True, remaining_seconds) if the bot is currently muted in this group.
    until_ts = 0 denotes indefinite mute until manually unmuted.
    """
    if not chat_id:
        return False, 0.0

    now = time.time()
    with _MOD_LOCK:
        record = _MUTED_GROUPS.get(int(chat_id))
        if not record:
            return False, 0.0

        until_ts = float(record.get("until_ts") or 0)
        if until_ts == 0:
            return True, 0.0  # Indefinite
        if until_ts > now:
            return True, until_ts - now

        # Expired
        _MUTED_GROUPS.pop(int(chat_id), None)

    asyncio.create_task(database.execute_d1_query("DELETE FROM muted_groups WHERE chat_id = ?", [chat_id]))
    return False, 0.0


def is_group_approved(chat_id: int) -> bool:
    """
    Returns True if the group is verified/approved to use the bot.
    New groups added by non-admins require bot admin approval first.
    """
    if not chat_id:
        return False
    with _MOD_LOCK:
        rec = _TRACKED_GROUPS.get(int(chat_id))
        if not rec:
            return False
        return rec.get("status") in ("active", "approved")


def get_group_status(chat_id: int) -> str:
    """Returns group status: 'approved', 'pending', 'rejected', or 'unknown'."""
    with _MOD_LOCK:
        rec = _TRACKED_GROUPS.get(int(chat_id))
        if not rec:
            return "unknown"
        st = rec.get("status", "pending")
        if st in ("active", "approved"):
            return "approved"
        return st


# =========================================================================
# Moderation Actions & Persistence
# =========================================================================

async def ban_user(
    user_id: int,
    username: str = "",
    name: str = "",
    reason: str = "",
    banned_by: int = 0,
    chat_id: int = 0,
    chat_title: str = ""
) -> bool:
    """Permanently bans a user from using the bot, updating RAM cache & D1."""
    clean_username = (username or "").lstrip("@").strip()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    item = {
        "user_id": int(user_id),
        "name": name or "",
        "first_name": name or "",
        "username": clean_username,
        "reason": reason or "توسط ادمین مسدود شد",
        "banned_by": banned_by,
        "banned_at": now_str,
        "source_chat_id": chat_id,
        "source_chat_title": chat_title
    }

    with _MOD_LOCK:
        _BANNED_USERS[int(user_id)] = item
        if clean_username:
            _BANNED_USERNAMES[clean_username.lower()] = item
        # If user was also muted, remove from mute cache
        _MUTED_USERS.pop(int(user_id), None)
        if clean_username:
            _MUTED_USERNAMES.pop(clean_username.lower(), None)

    # Persist in D1
    sql = """
    INSERT OR REPLACE INTO banned_users
    (user_id, name, username, reason, banned_by, banned_at, first_name, source_chat_id, source_chat_title)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    await database.execute_d1_query(sql, [
        user_id, name, clean_username, item["reason"], banned_by, now_str, name, chat_id, chat_title
    ])

    # Log admin command
    await log_admin_command(
        admin_id=banned_by,
        command="ban_user",
        args=reason,
        target_id=user_id,
        target_username=clean_username,
        details=f"Name: {name}, Chat: {chat_title} ({chat_id})"
    )

    return True


async def unban_user(user_id: int, unbanned_by: int = 0, reason: str = "") -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Unbans a user, logs to unbanned_log, and removes from banned_users."""
    with _MOD_LOCK:
        item = _BANNED_USERS.pop(int(user_id), None)
        uname = (item.get("username") or "") if item else ""
        if uname:
            _BANNED_USERNAMES.pop(uname.lower(), None)

    # Also query D1 if not in memory to capture metadata
    if not item:
        res = await database.execute_d1_query("SELECT * FROM banned_users WHERE user_id = ?", [user_id])
        if res.get("success") and res.get("results"):
            item = res["results"][0]
            uname = item.get("username") or ""

    # Delete from D1
    await database.execute_d1_query("DELETE FROM banned_users WHERE user_id = ?", [user_id])

    # Record in unbanned_log for permanent auditing
    u_name = uname or (item.get("username") if item else "") or ""
    t_name = (item.get("name") or item.get("first_name")) if item else ""
    sql_log = """
    INSERT INTO unbanned_log (entity_type, entity_id, username, title, unbanned_by, reason, unbanned_at)
    VALUES ('user', ?, ?, ?, ?, ?, datetime('now'))
    """
    await database.execute_d1_query(sql_log, [user_id, u_name, t_name, unbanned_by, reason or "رفع مسدودیت توسط ادمین"])

    await log_admin_command(
        admin_id=unbanned_by,
        command="unban_user",
        args=reason,
        target_id=user_id,
        target_username=u_name,
        details=f"Unbanned: {t_name}"
    )

    return True, item


async def mute_user(
    user_id: int,
    duration_sec: float,
    username: str = "",
    first_name: str = "",
    reason: str = "",
    muted_by: int = 0,
    chat_id: int = 0,
    chat_title: str = ""
) -> Tuple[bool, float]:
    """
    Mutes a user for duration_sec.
    The bot will completely ignore this user until until_ts expires.
    """
    now = time.time()
    until_ts = now + max(1.0, duration_sec)
    clean_username = (username or "").lstrip("@").strip()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    item = {
        "user_id": int(user_id),
        "username": clean_username,
        "first_name": first_name or "",
        "reason": reason or f"سکوت موقت ({int(duration_sec // 60)} دقیقه)",
        "muted_by": muted_by,
        "source_chat_id": chat_id,
        "source_chat_title": chat_title,
        "until_ts": until_ts,
        "muted_at": now_str
    }

    with _MOD_LOCK:
        _MUTED_USERS[int(user_id)] = item
        if clean_username:
            _MUTED_USERNAMES[clean_username.lower()] = item

    # Persist in D1
    sql = """
    INSERT OR REPLACE INTO muted_users
    (user_id, username, first_name, reason, muted_by, source_chat_id, source_chat_title, until_ts, muted_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    await database.execute_d1_query(sql, [
        user_id, clean_username, first_name, item["reason"], muted_by, chat_id, chat_title, until_ts, now_str
    ])

    await log_admin_command(
        admin_id=muted_by,
        command="mute_user",
        args=f"duration: {int(duration_sec)}s, reason: {reason}",
        target_id=user_id,
        target_username=clean_username,
        details=f"Until: {until_ts}"
    )

    return True, until_ts


async def unmute_user(user_id: int, unmuted_by: int = 0) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Unmutes a user immediately."""
    with _MOD_LOCK:
        item = _MUTED_USERS.pop(int(user_id), None)
        uname = (item.get("username") or "") if item else ""
        if uname:
            _MUTED_USERNAMES.pop(uname.lower(), None)

    await database.execute_d1_query("DELETE FROM muted_users WHERE user_id = ?", [user_id])

    await log_admin_command(
        admin_id=unmuted_by,
        command="unmute_user",
        target_id=user_id,
        target_username=uname,
        details="Manual unmute"
    )

    return True, item


async def ban_group(
    chat_id: int,
    title: str = "",
    reason: str = "",
    banned_by: int = 0
) -> bool:
    """Permanently bans a group."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    item = {
        "chat_id": int(chat_id),
        "title": title or "",
        "reason": reason or "مسدودسازی گروه توسط ادمین",
        "banned_by": banned_by,
        "banned_at": now_str
    }

    with _MOD_LOCK:
        _BANNED_GROUPS[int(chat_id)] = item
        if int(chat_id) in _TRACKED_GROUPS:
            _TRACKED_GROUPS[int(chat_id)]["status"] = "banned"

    sql = """
    INSERT OR REPLACE INTO banned_groups (chat_id, title, reason, banned_by, banned_at)
    VALUES (?, ?, ?, ?, ?)
    """
    await database.execute_d1_query(sql, [chat_id, title, item["reason"], banned_by, now_str])
    await database.execute_d1_query("UPDATE tracked_groups SET status = 'banned' WHERE chat_id = ?", [chat_id])

    await log_admin_command(
        admin_id=banned_by,
        command="ban_group",
        args=reason,
        target_id=chat_id,
        details=f"Title: {title}"
    )

    return True


async def unban_group(chat_id: int, unbanned_by: int = 0, reason: str = "") -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Unbans a group, logging to unbanned_log."""
    with _MOD_LOCK:
        item = _BANNED_GROUPS.pop(int(chat_id), None)
        if int(chat_id) in _TRACKED_GROUPS:
            _TRACKED_GROUPS[int(chat_id)]["status"] = "active"

    if not item:
        res = await database.execute_d1_query("SELECT * FROM banned_groups WHERE chat_id = ?", [chat_id])
        if res.get("success") and res.get("results"):
            item = res["results"][0]

    await database.execute_d1_query("DELETE FROM banned_groups WHERE chat_id = ?", [chat_id])
    await database.execute_d1_query("UPDATE tracked_groups SET status = 'active' WHERE chat_id = ?", [chat_id])

    title = (item.get("title") if item else "") or ""
    sql_log = """
    INSERT INTO unbanned_log (entity_type, entity_id, username, title, unbanned_by, reason, unbanned_at)
    VALUES ('group', ?, '', ?, ?, ?, datetime('now'))
    """
    await database.execute_d1_query(sql_log, [chat_id, title, unbanned_by, reason or "رفع مسدودیت گروه توسط ادمین"])

    await log_admin_command(
        admin_id=unbanned_by,
        command="unban_group",
        args=reason,
        target_id=chat_id,
        details=f"Title: {title}"
    )

    return True, item


async def mute_group(
    chat_id: int,
    duration_sec: float = 0.0,
    title: str = "",
    muted_by: int = 0
) -> Tuple[bool, float]:
    """
    Mutes the bot in a specific group.
    duration_sec = 0 means indefinite until unmuted.
    """
    now = time.time()
    until_ts = (now + duration_sec) if duration_sec > 0 else 0.0
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    item = {
        "chat_id": int(chat_id),
        "title": title or "",
        "until_ts": until_ts,
        "muted_by": muted_by,
        "muted_at": now_str
    }

    with _MOD_LOCK:
        _MUTED_GROUPS[int(chat_id)] = item

    sql = """
    INSERT OR REPLACE INTO muted_groups (chat_id, title, until_ts, muted_by, muted_at)
    VALUES (?, ?, ?, ?, ?)
    """
    await database.execute_d1_query(sql, [chat_id, title, until_ts, muted_by, now_str])

    await log_admin_command(
        admin_id=muted_by,
        command="mute_group",
        args=f"duration: {int(duration_sec)}s",
        target_id=chat_id,
        details=f"Title: {title}, until: {until_ts}"
    )

    return True, until_ts


async def unmute_group(chat_id: int, unmuted_by: int = 0) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """Unmutes the bot in a group."""
    with _MOD_LOCK:
        item = _MUTED_GROUPS.pop(int(chat_id), None)

    await database.execute_d1_query("DELETE FROM muted_groups WHERE chat_id = ?", [chat_id])

    await log_admin_command(
        admin_id=unmuted_by,
        command="unmute_group",
        target_id=chat_id,
        details="Manual unmute group"
    )

    return True, item


# =========================================================================
# Group Onboarding & Authorization Workflow
# =========================================================================

async def register_group_event(
    chat_id: int,
    title: str,
    chat_type: str,
    added_by_id: int,
    username: str = "",
    member_count: int = 0
) -> Tuple[str, bool]:
    """
    Registers or updates group status.
    Returns:
        (status, is_new_pending)
        where status is 'approved', 'pending', 'rejected', or 'banned'.
        is_new_pending is True if this is a newly pending group needing admin notification.
    """
    cid = int(chat_id)
    clean_username = (username or "").lstrip("@").strip()

    with _MOD_LOCK:
        existing = _TRACKED_GROUPS.get(cid)
        if existing:
            if title and title != "گروه":
                existing["title"] = title
            if clean_username:
                existing["username"] = clean_username
            if member_count > 0:
                existing["member_count"] = member_count
            if is_admin(added_by_id):
                existing["status"] = "approved"
                asyncio.create_task(database.execute_d1_query(
                    "UPDATE tracked_groups SET status = 'approved', added_by = ?, title = CASE WHEN ? != '' THEN ? ELSE title END WHERE chat_id = ?",
                    [added_by_id, title or "", title or "", cid]
                ))
                return "approved", False
            current_status = existing.get("status", "pending")
            # If already active/approved, keep approved
            if current_status in ("active", "approved"):
                return "approved", False
            if current_status == "banned":
                return "banned", False
            if current_status == "rejected":
                return "rejected", False
            is_new = (cid not in _PENDING_NOTIFIED_CHATS)
            if is_new:
                _PENDING_NOTIFIED_CHATS.add(cid)
            return "pending", is_new

    # Not existing yet: evaluate who added the bot
    if is_admin(added_by_id):
        new_status = "approved"
        is_new_pending = False
    else:
        new_status = "pending"
        is_new_pending = True

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    item = {
        "chat_id": cid,
        "title": title or "",
        "chat_type": chat_type or "supergroup",
        "member_count": member_count,
        "added_by": added_by_id,
        "added_at": now_str,
        "username": clean_username,
        "invite_link": "",
        "status": new_status
    }

    with _MOD_LOCK:
        _TRACKED_GROUPS[cid] = item
        if is_new_pending:
            _PENDING_NOTIFIED_CHATS.add(cid)

    sql = """
    INSERT OR REPLACE INTO tracked_groups
    (chat_id, title, chat_type, member_count, added_by, added_at, username, invite_link, status)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    await database.execute_d1_query(sql, [
        cid, title, chat_type, member_count, added_by_id, now_str, clean_username, "", new_status
    ])

    return new_status, is_new_pending


async def approve_group(chat_id: int, reviewed_by: int = 0, title: str = "") -> bool:
    """Approves a group for bot operation, persisting to RAM and D1."""
    cid = int(chat_id)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _MOD_LOCK:
        if cid in _TRACKED_GROUPS:
            _TRACKED_GROUPS[cid]["status"] = "approved"
            if title and (not _TRACKED_GROUPS[cid].get("title") or _TRACKED_GROUPS[cid].get("title") == "گروه"):
                _TRACKED_GROUPS[cid]["title"] = title
        else:
            _TRACKED_GROUPS[cid] = {"chat_id": cid, "title": title or "گروه", "status": "approved", "added_at": now_str}
        _PENDING_NOTIFIED_CHATS.discard(cid)

    sql = """
    INSERT INTO tracked_groups (chat_id, title, status, added_at)
    VALUES (?, ?, 'approved', ?)
    ON CONFLICT(chat_id) DO UPDATE SET status = 'approved', title = CASE WHEN ? != '' THEN ? ELSE tracked_groups.title END
    """
    await database.execute_d1_query(sql, [cid, title or "گروه", now_str, title or "", title or ""])

    await log_admin_command(
        admin_id=reviewed_by,
        command="approve_group",
        target_id=cid,
        details=f"Approved group activation: {title}" if title else "Approved group activation"
    )

    return True


async def reject_group(chat_id: int, reviewed_by: int = 0) -> bool:
    """Rejects a group and marks as rejected."""
    cid = int(chat_id)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    with _MOD_LOCK:
        if cid in _TRACKED_GROUPS:
            _TRACKED_GROUPS[cid]["status"] = "rejected"
        else:
            _TRACKED_GROUPS[cid] = {"chat_id": cid, "status": "rejected", "added_at": now_str}
        _PENDING_NOTIFIED_CHATS.discard(cid)

    sql = """
    INSERT INTO tracked_groups (chat_id, status, added_at)
    VALUES (?, 'rejected', ?)
    ON CONFLICT(chat_id) DO UPDATE SET status = 'rejected'
    """
    await database.execute_d1_query(sql, [cid, now_str])

    await log_admin_command(
        admin_id=reviewed_by,
        command="reject_group",
        target_id=cid,
        details="Rejected group activation"
    )

    return True


# =========================================================================
# Querying Lists & Persistent Audit Data
# =========================================================================

async def get_banned_users_list() -> List[Dict[str, Any]]:
    """Returns all currently banned users with numeric ID and username."""
    res = await database.execute_d1_query("SELECT * FROM banned_users ORDER BY banned_at DESC")
    if res.get("success"):
        return res.get("results", [])
    with _MOD_LOCK:
        return list(_BANNED_USERS.values())


async def get_muted_users_list() -> List[Dict[str, Any]]:
    """Returns all currently active muted users with remaining duration."""
    now = time.time()
    res = await database.execute_d1_query("SELECT * FROM muted_users WHERE until_ts > ? ORDER BY until_ts ASC", [now])
    if res.get("success"):
        results = res.get("results", [])
        for r in results:
            r["remaining_seconds"] = max(0.0, float(r.get("until_ts") or 0) - now)
        return results

    with _MOD_LOCK:
        active = []
        for r in _MUTED_USERS.values():
            until_ts = float(r.get("until_ts") or 0)
            if until_ts == 0 or until_ts > now:
                r_copy = dict(r)
                r_copy["remaining_seconds"] = max(0.0, until_ts - now) if until_ts > 0 else 999999.0
                active.append(r_copy)
        return active


async def get_banned_groups_list() -> List[Dict[str, Any]]:
    """Returns all banned groups."""
    res = await database.execute_d1_query("SELECT * FROM banned_groups ORDER BY banned_at DESC")
    if res.get("success"):
        return res.get("results", [])
    with _MOD_LOCK:
        return list(_BANNED_GROUPS.values())


async def get_muted_groups_list() -> List[Dict[str, Any]]:
    """Returns all currently muted groups."""
    now = time.time()
    res = await database.execute_d1_query("SELECT * FROM muted_groups WHERE until_ts = 0 OR until_ts > ?", [now])
    if res.get("success"):
        results = res.get("results", [])
        for r in results:
            uts = float(r.get("until_ts") or 0)
            r["remaining_seconds"] = max(0.0, uts - now) if uts > 0 else 0.0
        return results
    with _MOD_LOCK:
        return list(_MUTED_GROUPS.values())


async def get_pending_groups_list() -> List[Dict[str, Any]]:
    """Returns all groups awaiting admin approval."""
    res = await database.execute_d1_query(
        "SELECT * FROM tracked_groups WHERE status = 'pending' ORDER BY added_at DESC"
    )
    if res.get("success"):
        return res.get("results", [])
    with _MOD_LOCK:
        return [g for g in _TRACKED_GROUPS.values() if g.get("status") == "pending"]


async def get_all_tracked_groups(status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Returns all tracked groups from Cloudflare D1 merged with in-memory cache.
    Optionally filters by status ('approved', 'active', 'pending', 'banned', 'rejected', etc.).
    """
    db_groups: Dict[int, Dict[str, Any]] = {}
    if status_filter:
        sql = "SELECT * FROM tracked_groups WHERE status = ? ORDER BY added_at DESC"
        params = [status_filter]
    else:
        sql = "SELECT * FROM tracked_groups ORDER BY added_at DESC"
        params = []

    res = await database.execute_d1_query(sql, params)
    if res.get("success"):
        for r in res.get("results", []):
            cid = r.get("chat_id")
            if cid:
                db_groups[int(cid)] = r

    with _MOD_LOCK:
        merged = dict(_TRACKED_GROUPS)
        # Merge D1 data into cached data
        merged.update(db_groups)
        groups = list(merged.values())

    if status_filter:
        groups = [g for g in groups if g.get("status") == status_filter]

    groups.sort(key=lambda x: str(x.get("added_at", "")), reverse=True)
    return groups


def update_group_live_metadata(chat_id: int, title: str = "", username: str = ""):
    """Updates group title and username in memory and async updates DB if changed."""
    cid = int(chat_id)
    with _MOD_LOCK:
        entry = _TRACKED_GROUPS.get(cid)
        if entry:
            changed = False
            if title and entry.get("title") != title:
                entry["title"] = title
                changed = True
            clean_u = (username or "").lstrip("@").strip()
            if clean_u and entry.get("username") != clean_u:
                entry["username"] = clean_u
                changed = True
            if changed:
                asyncio.create_task(database.execute_d1_query(
                    "UPDATE tracked_groups SET title = ?, username = ? WHERE chat_id = ?",
                    [entry.get("title", ""), entry.get("username", ""), cid]
                ))


async def get_live_telegram_groups(bot, include_left: bool = False) -> List[Dict[str, Any]]:
    """
    Performs real-time live verification of all candidate groups directly against Telegram Bot API:
    - Collects candidate group IDs from tracked_groups, messages, and in-memory caches.
    - Concurrently verifies if the bot is currently an active member or administrator in each group.
    - Fetches live title, username, member count, and bot permissions directly from Telegram.
    - Permanently purges non-existent/deleted groups (e.g. dummy test chats) from the database.
    - Marks groups where the bot was kicked or left as 'left'.
    - Returns strictly verified, live active groups.
    """
    candidate_cids: Set[int] = set()

    # 1. From in-memory caches
    with _MOD_LOCK:
        candidate_cids.update(_TRACKED_GROUPS.keys())
        candidate_cids.update(_BANNED_GROUPS.keys())
        candidate_cids.update(_MUTED_GROUPS.keys())

    # 2. From database tracked_groups
    try:
        res_t = await database.execute_d1_query("SELECT chat_id FROM tracked_groups")
        if res_t.get("success"):
            for r in res_t.get("results", []):
                if r.get("chat_id"):
                    candidate_cids.add(int(r["chat_id"]))
    except Exception as e:
        logger.debug(f"Candidate groups DB fetch: {e}")

    # 3. From messages table (any group chat where messages were exchanged)
    try:
        res_m = await database.execute_d1_query("SELECT DISTINCT chat_id FROM messages WHERE chat_id < 0")
        if res_m.get("success"):
            for r in res_m.get("results", []):
                if r.get("chat_id"):
                    candidate_cids.add(int(r["chat_id"]))
    except Exception as e:
        logger.debug(f"Candidate messages DB fetch: {e}")

    # 4. From local SQLite fallback
    try:
        r_sq = database._execute_sqlite("SELECT DISTINCT chat_id FROM messages WHERE chat_id < 0")
        for r in r_sq.get("results", []):
            if r.get("chat_id"):
                candidate_cids.add(int(r["chat_id"]))
        r_sq2 = database._execute_sqlite("SELECT chat_id FROM tracked_groups")
        for r in r_sq2.get("results", []):
            if r.get("chat_id"):
                candidate_cids.add(int(r["chat_id"]))
    except Exception:
        pass

    group_cids = [cid for cid in candidate_cids if cid < 0]
    if not group_cids:
        return []

    sem = asyncio.Semaphore(15)
    live_groups: List[Dict[str, Any]] = []

    # Get current bot user ID
    try:
        bot_id = bot.id if hasattr(bot, "id") and bot.id else (await bot.get_me()).id
    except Exception:
        bot_id = 0

    async def verify_chat(cid: int):
        async with sem:
            try:
                tg_chat = await bot.get_chat(cid)
                member = await bot.get_chat_member(cid, bot_id)

                status_str = getattr(member, "status", "")
                is_active = status_str in ("member", "administrator", "creator")

                if is_active:
                    is_admin = status_str in ("administrator", "creator")
                    try:
                        m_count = await bot.get_chat_member_count(cid)
                    except Exception:
                        m_count = getattr(tg_chat, "member_count", 0) or 0

                    title = tg_chat.title or "گروه بدون عنوان"
                    username = (tg_chat.username or "").lstrip("@")
                    chat_type = str(getattr(tg_chat, "type", "supergroup"))

                    existing_st = get_group_status(cid)
                    if existing_st in ("unknown", "left"):
                        existing_st = "approved"

                    item = {
                        "chat_id": cid,
                        "title": title,
                        "username": username,
                        "chat_type": chat_type,
                        "member_count": m_count,
                        "status": existing_st,
                        "is_admin": is_admin,
                        "is_live": True,
                    }

                    with _MOD_LOCK:
                        _TRACKED_GROUPS[cid] = item

                    asyncio.create_task(database.execute_d1_query(
                        """INSERT INTO tracked_groups (chat_id, title, username, chat_type, member_count, status)
                           VALUES (?, ?, ?, ?, ?, ?)
                           ON CONFLICT(chat_id) DO UPDATE SET
                           title=excluded.title, username=excluded.username, member_count=excluded.member_count,
                           status=CASE WHEN tracked_groups.status = 'banned' THEN 'banned' ELSE excluded.status END""",
                        [cid, title, username, chat_type, m_count, existing_st]
                    ))

                    live_groups.append(item)
                else:
                    with _MOD_LOCK:
                        if cid in _TRACKED_GROUPS:
                            _TRACKED_GROUPS[cid]["status"] = "left"
                    asyncio.create_task(database.execute_d1_query(
                        "UPDATE tracked_groups SET status = 'left' WHERE chat_id = ?", [cid]
                    ))
            except Exception as e:
                err = str(e).lower()
                if "chat not found" in err:
                    with _MOD_LOCK:
                        _TRACKED_GROUPS.pop(cid, None)
                    asyncio.create_task(database.execute_d1_query(
                        "DELETE FROM tracked_groups WHERE chat_id = ?", [cid]
                    ))
                    asyncio.create_task(asyncio.to_thread(
                        database._execute_sqlite, "DELETE FROM tracked_groups WHERE chat_id = ?", [cid]
                    ))
                elif "kicked" in err or "forbidden" in err or "blocked" in err:
                    with _MOD_LOCK:
                        if cid in _TRACKED_GROUPS:
                            _TRACKED_GROUPS[cid]["status"] = "left"
                    asyncio.create_task(database.execute_d1_query(
                        "UPDATE tracked_groups SET status = 'left' WHERE chat_id = ?", [cid]
                    ))
                else:
                    logger.debug(f"Live group verification notice for {cid}: {e}")

    await asyncio.gather(*(verify_chat(cid) for cid in group_cids), return_exceptions=True)
    live_groups.sort(key=lambda g: (g.get("is_admin", False), g.get("member_count", 0)), reverse=True)
    return live_groups


async def get_unbanned_history(limit: int = 25) -> List[Dict[str, Any]]:
    """Returns unban audit logs."""
    res = await database.execute_d1_query(
        "SELECT * FROM unbanned_log ORDER BY id DESC LIMIT ?", [limit]
    )
    return res.get("results", []) if res.get("success") else []


async def log_admin_command(
    admin_id: int,
    command: str,
    args: str = "",
    target_id: int = 0,
    target_username: str = "",
    details: str = ""
) -> bool:
    """Logs an admin command into admin_commands_log permanently (D1 and RAM buffer)."""
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "admin_id": admin_id,
        "command": command,
        "args": args,
        "target_id": target_id,
        "target_username": target_username,
        "details": details,
        "created_at": now_str,
    }
    with _MOD_LOCK:
        _ADMIN_COMMANDS_CACHE.appendleft(entry)

    sql = """
    INSERT INTO admin_commands_log
    (admin_id, command, args, target_id, target_username, details, created_at)
    VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
    """
    await database.execute_d1_query(sql, [
        admin_id, command, args, target_id, target_username, details
    ])
    return True


async def get_admin_commands_log(limit: int = 25) -> List[Dict[str, Any]]:
    """Retrieves recent admin commands log with instant cache fallback."""
    res = await database.execute_d1_query(
        "SELECT * FROM admin_commands_log ORDER BY id DESC LIMIT ?", [limit]
    )
    if res.get("success") and res.get("results"):
        return res["results"]
    with _MOD_LOCK:
        return list(_ADMIN_COMMANDS_CACHE)[:limit]


# =========================================================================
# Persistent Admin Settings & Directives
# =========================================================================

async def set_admin_setting(key_name: str, data_value: str, category: str = "settings", admin_id: int = 0) -> bool:
    """Persists a configuration key-value pair in custom_data_store, L1 RAM cache, and Cloudflare KV."""
    clean_key = key_name.strip()
    clean_val = str(data_value).strip()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "key_name": clean_key,
        "data_value": clean_val,
        "category": category,
        "updated_at": now_str,
    }
    with _MOD_LOCK:
        _ADMIN_SETTINGS[clean_key] = entry

    sql = """
    INSERT INTO custom_data_store (key_name, data_value, category, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key_name) DO UPDATE SET
        data_value = excluded.data_value,
        category = excluded.category,
        updated_at = datetime('now')
    """
    res = await database.execute_d1_query(sql, [clean_key, clean_val, category])
    try:
        await database.kv_set(f"ADMIN_SETTING_{clean_key}", json.dumps(entry))
    except Exception:
        pass

    await log_admin_command(
        admin_id=admin_id,
        command="set_setting",
        args=f"{clean_key} = {clean_val}",
        details=f"Category: {category}"
    )
    return res.get("success", True)


async def delete_admin_setting(key_name: str, admin_id: int = 0) -> bool:
    """Deletes an admin setting or directive from RAM cache, Cloudflare D1, and KV."""
    clean_key = key_name.strip()
    with _MOD_LOCK:
        existed = _ADMIN_SETTINGS.pop(clean_key, None)

    sql = "DELETE FROM custom_data_store WHERE key_name = ?"
    await database.execute_d1_query(sql, [clean_key])
    try:
        await database.kv_delete(f"ADMIN_SETTING_{clean_key}")
    except Exception:
        pass

    await log_admin_command(
        admin_id=admin_id,
        command="delete_setting",
        args=clean_key,
        details=f"Admin deleted custom setting/directive (existed={bool(existed)})"
    )
    return True


async def get_admin_setting(key_name: str, default: Optional[str] = None) -> Optional[str]:
    """Retrieves a configuration value from L1 RAM cache or custom_data_store."""
    clean_key = key_name.strip()
    with _MOD_LOCK:
        if clean_key in _ADMIN_SETTINGS:
            return _ADMIN_SETTINGS[clean_key].get("data_value", default)

    sql = "SELECT data_value, category, updated_at FROM custom_data_store WHERE key_name = ? LIMIT 1"
    res = await database.execute_d1_query(sql, [clean_key])
    if res.get("success") and res.get("results"):
        row = res["results"][0]
        val = row.get("data_value", default)
        with _MOD_LOCK:
            _ADMIN_SETTINGS[clean_key] = {
                "key_name": clean_key,
                "data_value": val,
                "category": row.get("category", "general"),
                "updated_at": row.get("updated_at", "")
            }
        return val
    return default


async def get_all_admin_settings() -> List[Dict[str, Any]]:
    """Returns all settings stored in custom_data_store and L1 RAM."""
    sql = "SELECT key_name, data_value, category, updated_at FROM custom_data_store ORDER BY category, key_name"
    res = await database.execute_d1_query(sql)
    if res.get("success") and res.get("results"):
        with _MOD_LOCK:
            for r in res.get("results", []):
                k = r.get("key_name")
                if k:
                    _ADMIN_SETTINGS[k] = r
        return res.get("results", [])
    with _MOD_LOCK:
        return list(_ADMIN_SETTINGS.values())


def get_cached_admin_directives() -> List[Dict[str, Any]]:
    """Returns all active admin directives/instructions currently cached in memory (<0.001ms)."""
    with _MOD_LOCK:
        return [
            dict(v) for v in _ADMIN_SETTINGS.values()
            if v.get("category") in ("directive", "rule", "instruction", "system")
        ]


# =========================================================================
# Helper Utilities (Target Extraction & Duration Parsing)
# =========================================================================

def parse_duration_string(text: str) -> Optional[float]:
    """
    Parses human duration string into seconds.
    Supports English & Persian:
    - 10m, 30m, 1h, 24h, 2d, 7d, 60s
    - ۱۰ دقیقه, ۲ ساعت, ۱ روز, ۱ هفته
    - 30 (default assumes minutes)
    """
    if not text:
        return None

    raw = text.strip().lower()

    # Persian digits conversion
    fa_digits = "۰۱۲۳۴۵۶۷۸۹"
    en_digits = "0123456789"
    trans = str.maketrans(fa_digits, en_digits)
    raw = raw.translate(trans)

    # Patterns
    patterns = [
        (r"^(\d+)\s*(?:s|sec|second|seconds|ثانیه)$", 1),
        (r"^(\d+)\s*(?:m|min|minute|minutes|دقیقه|دقایق)$", 60),
        (r"^(\d+)\s*(?:h|hr|hour|hours|ساعت|ساعته)$", 3600),
        (r"^(\d+)\s*(?:d|day|days|روز|روزه)$", 86400),
        (r"^(\d+)\s*(?:w|week|weeks|هفته)$", 604800),
        (r"^(\d+)\s*(?:mo|month|months|ماه)$", 2592000),
    ]

    for pat, mult in patterns:
        m = re.match(pat, raw)
        if m:
            return float(m.group(1)) * mult

    # Plain integer: default to minutes
    if raw.isdigit():
        return float(raw) * 60.0

    return None


def format_duration_persian(seconds: float) -> str:
    """Formats seconds into friendly Persian text."""
    sec = int(seconds)
    if sec <= 0:
        return "منقضی شده"
    if sec < 60:
        return f"{sec} ثانیه"
    minutes = sec // 60
    if minutes < 60:
        return f"{minutes} دقیقه"
    hours = minutes // 60
    rem_min = minutes % 60
    if hours < 24:
        return f"{hours} ساعت و {rem_min} دقیقه" if rem_min else f"{hours} ساعت"
    days = hours // 24
    rem_hours = hours % 24
    return f"{days} روز و {rem_hours} ساعت" if rem_hours else f"{days} روز"
