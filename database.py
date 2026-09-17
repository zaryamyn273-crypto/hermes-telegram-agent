"""
High-Performance Multi-Tier Storage Engine for Prometheus (Hermes Telegram Agent):
- Tier 1: Sub-millisecond In-Memory LRU L1 Fast Buffer (Hot RAM)
- Tier 2: Cloudflare Workers KV Global Distributed Key-Value Store
- Tier 3: Cloudflare D1 Serverless SQL Database with Async Persistence
"""

import os
import time
import json
import logging
import asyncio
import threading
from typing import Dict, Any, List, Optional, Tuple, Union
from collections import OrderedDict

import httpx
from config import settings

logger = logging.getLogger("PrometheusStorage")

# =========================================================================
# Tier 1: Sub-Millisecond In-Memory LRU L1 Fast Buffer
# =========================================================================

_L1_CACHE: OrderedDict[str, Dict[str, Any]] = OrderedDict()
_L1_LOCK = threading.Lock()
_L1_MAX_SIZE = 1000
_L1_LOW_WATER = 800

def l1_get(key: str) -> Optional[str]:
    """Retrieves value from L1 RAM cache in < 0.001ms."""
    now = time.monotonic()
    with _L1_LOCK:
        item = _L1_CACHE.get(key)
        if item is None:
            return None
        if now > item["expires_at"]:
            _L1_CACHE.pop(key, None)
            return None
        # Move to end (LRU)
        _L1_CACHE.move_to_end(key)
        return item["value"]

def l1_set(key: str, value: str, ttl_sec: int = 300):
    """Sets value in L1 RAM cache."""
    now = time.monotonic()
    ttl = max(10, int(ttl_sec))
    clean_val = str(value) if value is not None else ""
    with _L1_LOCK:
        if len(_L1_CACHE) >= _L1_MAX_SIZE:
            while len(_L1_CACHE) >= _L1_LOW_WATER:
                try:
                    _L1_CACHE.popitem(last=False)
                except KeyError:
                    break
        _L1_CACHE[key] = {
            "value": clean_val,
            "expires_at": now + ttl,
        }
        _L1_CACHE.move_to_end(key)

def l1_delete(key: str):
    """Deletes key from L1 RAM cache."""
    with _L1_LOCK:
        _L1_CACHE.pop(key, None)


# =========================================================================
# Cloudflare API Clients & Headers
# =========================================================================

_http_limits = httpx.Limits(max_keepalive_connections=100, max_connections=200, keepalive_expiry=300.0)
_cf_client: Optional[httpx.AsyncClient] = None
_CF_CLIENT_LOCK = threading.Lock()

def get_cf_client() -> httpx.AsyncClient:
    """Returns persistent AsyncClient for Cloudflare API."""
    global _cf_client
    if _cf_client is None or _cf_client.is_closed:
        with _CF_CLIENT_LOCK:
            if _cf_client is None or _cf_client.is_closed:
                _cf_client = httpx.AsyncClient(
                    limits=_http_limits,
                    timeout=httpx.Timeout(connect=3.0, read=6.0, write=4.0, pool=4.0),
                    headers={"Content-Type": "application/json"}
                )
    return _cf_client

def _cf_headers() -> Dict[str, str]:
    token = settings.CLOUDFLARE_API_TOKEN or os.getenv("CLOUDFLARE_API_TOKEN", "")
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }


# =========================================================================
# Tier 2: Cloudflare Workers KV Operations
# =========================================================================

_KV_CIRCUIT_OPEN_UNTIL: float = 0.0
_KV_LAST_CLOUD_WRITE: Dict[str, float] = {}

def _kv_circuit_open() -> bool:
    return time.monotonic() < _KV_CIRCUIT_OPEN_UNTIL

async def kv_get(key: str) -> Optional[str]:
    """
    Reads from L1 RAM first. On miss, reads from Cloudflare KV.
    """
    # 1. Check L1 RAM
    val = l1_get(key)
    if val is not None:
        return val

    if _kv_circuit_open():
        return None

    account_id = settings.CLOUDFLARE_ACCOUNT_ID or os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    kv_id = settings.CLOUDFLARE_KV_ID or os.getenv("CLOUDFLARE_KV_ID", "")
    if not account_id or not kv_id:
        return None

    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{kv_id}/values/{key}"
    try:
        client = get_cf_client()
        resp = await client.get(url, headers=_cf_headers())
        if resp.status_code == 200:
            result_str = resp.text
            l1_set(key, result_str, ttl_sec=120)
            return result_str
        elif resp.status_code == 429:
            global _KV_CIRCUIT_OPEN_UNTIL
            _KV_CIRCUIT_OPEN_UNTIL = time.monotonic() + 60.0
            logger.warning("Cloudflare KV rate limited (429); pausing cloud KV for 60s.")
    except Exception as e:
        logger.debug(f"KV get exception for '{key}': {e}")
    return None

async def kv_set(key: str, value: str, ttl_sec: int = 300) -> bool:
    """
    Writes to L1 RAM immediately, then persists to Cloudflare KV.
    """
    val_str = str(value) if value is not None else ""
    l1_set(key, val_str, ttl_sec=ttl_sec)

    if _kv_circuit_open():
        return True

    account_id = settings.CLOUDFLARE_ACCOUNT_ID or os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    kv_id = settings.CLOUDFLARE_KV_ID or os.getenv("CLOUDFLARE_KV_ID", "")
    if not account_id or not kv_id:
        return True

    now = time.monotonic()
    # Rate limit KV writes on identical keys
    if now - _KV_LAST_CLOUD_WRITE.get(key, 0.0) < 15.0:
        return True

    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{kv_id}/values/{key}"
    params = {"expiration_ttl": max(60, int(ttl_sec))}
    try:
        client = get_cf_client()
        _KV_LAST_CLOUD_WRITE[key] = now
        resp = await client.put(url, headers=_cf_headers(), params=params, content=val_str.encode("utf-8"))
        if resp.status_code == 429:
            global _KV_CIRCUIT_OPEN_UNTIL
            _KV_CIRCUIT_OPEN_UNTIL = time.monotonic() + 60.0
        return resp.status_code in (200, 201)
    except Exception as e:
        logger.debug(f"KV put exception for '{key}': {e}")
        return False

async def kv_delete(key: str):
    """Deletes from L1 RAM and Cloudflare KV."""
    l1_delete(key)
    account_id = settings.CLOUDFLARE_ACCOUNT_ID or os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    kv_id = settings.CLOUDFLARE_KV_ID or os.getenv("CLOUDFLARE_KV_ID", "")
    if not account_id or not kv_id:
        return
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/storage/kv/namespaces/{kv_id}/values/{key}"
    try:
        client = get_cf_client()
        await client.delete(url, headers=_cf_headers())
    except Exception:
        pass


# =========================================================================
# Tier 3: Cloudflare D1 Serverless SQL Database Operations
# =========================================================================

import sqlite3

_SQLITE_CONN = None
_SQLITE_LOCK = threading.RLock()

def _get_sqlite_conn():
    global _SQLITE_CONN
    if _SQLITE_CONN is None:
        with _SQLITE_LOCK:
            if _SQLITE_CONN is None:
                db_path = os.getenv("SQLITE_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "bot.db"))
                os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
                _SQLITE_CONN = sqlite3.connect(db_path, check_same_thread=False)
                _SQLITE_CONN.row_factory = sqlite3.Row
    return _SQLITE_CONN

def _execute_sqlite(sql: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
    with _SQLITE_LOCK:
        try:
            conn = _get_sqlite_conn()
            cur = conn.cursor()
            cur.execute(sql, params or [])
            if sql.strip().upper().startswith("SELECT") or "RETURNING" in sql.upper():
                rows = [dict(r) for r in cur.fetchall()]
                return {"success": True, "results": rows}
            conn.commit()
            return {"success": True, "results": []}
        except Exception as e:
            logger.debug(f"SQLite fallback error: {e}")
            return {"success": False, "results": []}

async def execute_d1_query(sql: str, params: Optional[List[Any]] = None) -> Dict[str, Any]:
    """
    Executes a parameterized SQL query on Cloudflare D1.
    If Cloudflare D1 credentials are not configured, seamlessly falls back to local SQLite.
    """
    account_id = settings.CLOUDFLARE_ACCOUNT_ID or os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    d1_id = settings.CLOUDFLARE_D1_ID or os.getenv("CLOUDFLARE_D1_ID", "")
    if not account_id or not d1_id:
        return _execute_sqlite(sql, params)

    clean_params = [
        p if isinstance(p, (int, float, str, bool)) or p is None else str(p)
        for p in (params or [])
    ]

    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/{d1_id}/query"
    body = {"sql": sql, "params": clean_params}

    try:
        client = get_cf_client()
        resp = await client.post(url, headers=_cf_headers(), json=body, timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("success") and data.get("result"):
                return {"success": True, "results": data["result"][0].get("results", [])}
        else:
            logger.debug(f"D1 HTTP {resp.status_code}: {resp.text[:150]}")
    except Exception as e:
        logger.debug(f"D1 query exception: {e}")

    # Fallback to local SQLite if cloud D1 temporarily fails
    return _execute_sqlite(sql, clean_params)


# =========================================================================
# Persistent Session & Message History in D1
# =========================================================================

async def persist_message_to_d1(chat_id: int, user_id: int, role: str, content: str, username: str = ""):
    """Asynchronously persists a message to Cloudflare D1."""
    sql = """
    INSERT INTO messages (chat_id, user_id, username, role, content, created_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    """
    await execute_d1_query(sql, [chat_id, user_id, username, role, content])

async def load_session_history_from_d1(chat_id: int, limit: int = 15) -> List[Dict[str, Any]]:
    """Loads recent messages from Cloudflare D1 for session restoration."""
    sql = """
    SELECT role, content FROM messages
    WHERE chat_id = ?
    ORDER BY id DESC LIMIT ?
    """
    res = await execute_d1_query(sql, [chat_id, limit])
    if res.get("success"):
        rows = res.get("results", [])
        rows.reverse()
        return [{"role": r["role"], "content": r["content"]} for r in rows if r.get("content")]
    return []

async def clear_session_in_d1(chat_id: int):
    """Deletes all messages for chat_id in Cloudflare D1."""
    sql = "DELETE FROM messages WHERE chat_id = ?"
    await execute_d1_query(sql, [chat_id])
