"""
Specialized Tools Package for Prometheus Telegram Agent.
"""

from .financial import get_fiat_and_gold_rates, get_crypto_price
from .system import (
    get_current_time,
    calculate_math,
    record_chat_latency,
    format_last_latency_response,
    run_live_speed_test,
)
from .weather import get_weather
from .ecommerce import search_digikala
from .web_reader import fetch_webpage_text
from .telegraph import create_telegraph_article, publish_to_telegraph, extract_telegraph_args
from .music import (
    clean_music_query,
    search_music_track,
    search_and_stream_music,
    is_music_request,
    extract_music_query,
    handle_music_request,
)

__all__ = [
    "get_fiat_and_gold_rates",
    "get_crypto_price",
    "get_current_time",
    "calculate_math",
    "record_chat_latency",
    "format_last_latency_response",
    "run_live_speed_test",
    "get_weather",
    "search_digikala",
    "fetch_webpage_text",
    "create_telegraph_article",
    "publish_to_telegraph",
    "extract_telegraph_args",
    "clean_music_query",
    "search_music_track",
    "search_and_stream_music",
    "is_music_request",
    "extract_music_query",
    "handle_music_request",
]
