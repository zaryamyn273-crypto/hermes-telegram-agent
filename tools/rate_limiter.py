"""
User-based Dynamic Rate Limiter for Prometheus:
Provides multi-tier request throttling based on Telegram user_id:
1. Micro-burst limiter (cooldown between rapid messages)
2. Rolling window per-minute throttle (prevents API spam)
3. Daily quota tracking with Cloudflare L1/KV synchronization
Exempts administrators unconditionally.
"""

import time
import logging
from collections import deque
from typing import Tuple, Optional, Dict
from datetime import datetime

from config import settings, is_admin
import database

logger = logging.getLogger("RateLimiter")

# In-memory sliding windows: user_id -> deque of timestamps
_USER_MINUTE_WINDOWS: Dict[int, deque] = {}
_USER_LAST_REQ: Dict[int, float] = {}

# Constants
MIN_COOLDOWN_SEC = 0.9          # Minimum seconds between consecutive requests
BURST_WINDOW_SEC = 10.0         # Seconds for burst tracking
MAX_BURST_REQUESTS = 6          # Max requests allowed in 10-second window
MINUTE_WINDOW_SEC = 60.0        # Rolling minute window
MAX_MINUTE_REQUESTS = 25        # Max requests allowed per minute


def check_user_rate_limit(user_id: int) -> Tuple[bool, Optional[str]]:
    """
    Evaluates rate limits for a specific user_id.
    Returns:
        (True, None) if allowed.
        (False, warning_message) if throttled or quota exceeded.
    """
    if not user_id:
        return True, None

    # 1. Admin exemption
    if is_admin(user_id):
        return True, None

    now = time.monotonic()
    t_epoch = time.time()

    # 2. Tier 1: Minimum cooldown between requests
    last_req = _USER_LAST_REQ.get(user_id, 0.0)
    elapsed = now - last_req
    if elapsed < MIN_COOLDOWN_SEC:
        wait = round(MIN_COOLDOWN_SEC - elapsed, 1)
        return False, f"⚠️ لطفاً کمی شکیبا باشید ({wait} ثانیه دیگر مجدداً ارسال فرمایید)."

    # 3. Tier 2: Rolling 60-second window
    if user_id not in _USER_MINUTE_WINDOWS:
        _USER_MINUTE_WINDOWS[user_id] = deque()

    dq = _USER_MINUTE_WINDOWS[user_id]

    # Purge timestamps older than 60 seconds
    while dq and (now - dq[0]) > MINUTE_WINDOW_SEC:
        dq.popleft()

    # Check burst in last 10 seconds
    recent_burst = sum(1 for ts in dq if (now - ts) <= BURST_WINDOW_SEC)
    if recent_burst >= MAX_BURST_REQUESTS:
        return False, "⚠️ سرعت ارسال پیام‌های شما بیش از حد مجاز است. لطفاً چند ثانیه شکیبا باشید."

    # Check per-minute limit
    if len(dq) >= MAX_MINUTE_REQUESTS:
        earliest = dq[0]
        wait_min = int(MINUTE_WINDOW_SEC - (now - earliest)) + 1
        return False, f"⚠️ شما به سقف مجاز {MAX_MINUTE_REQUESTS} پیام در دقیقه رسیدید. لطفاً {wait_min} ثانیه دیگر پیام بفرستید."

    # 4. Tier 3: Daily Quota Check (Cloudflare L1 RAM + KV)
    daily_limit = getattr(settings, "DAILY_USER_LIMIT", 50)
    try:
        daily_limit = int(daily_limit)
    except (ValueError, TypeError):
        daily_limit = 50

    if daily_limit > 0:
        today_str = datetime.now().strftime("%Y%m%d")
        daily_key = f"USER_DAILY_REQ_{user_id}_{today_str}"
        current_daily = database.l1_get(daily_key)
        daily_count = int(current_daily) if current_daily and str(current_daily).isdigit() else 0

        if daily_count >= daily_limit:
            return False, f"⚠️ شما به سقف مجاز استفاده روزانه ({daily_limit} درخواست) رسیده‌اید. سهمیه شما بامداد فردا بازنشانی خواهد شد."

        # Increment daily counter
        database.l1_set(daily_key, str(daily_count + 1), ttl_sec=86400)

    # Record successful request timestamp
    _USER_LAST_REQ[user_id] = now
    dq.append(now)

    return True, None


def get_user_quota_info(user_id: int) -> dict:
    """Returns user's current daily usage stats."""
    daily_limit = getattr(settings, "DAILY_USER_LIMIT", 50)
    try:
        daily_limit = int(daily_limit)
    except Exception:
        daily_limit = 50

    today_str = datetime.now().strftime("%Y%m%d")
    daily_key = f"USER_DAILY_REQ_{user_id}_{today_str}"
    current_daily = database.l1_get(daily_key)
    count = int(current_daily) if current_daily and str(current_daily).isdigit() else 0

    return {
        "used": count,
        "limit": daily_limit,
        "remaining": max(0, daily_limit - count),
        "is_admin": is_admin(user_id),
    }
