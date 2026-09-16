"""
Specialized Tools Package for Prometheus Telegram Agent.
"""

from .financial import get_fiat_and_gold_rates, get_crypto_price
from .system import get_current_time, calculate_math
from .weather import get_weather

__all__ = [
    "get_fiat_and_gold_rates",
    "get_crypto_price",
    "get_current_time",
    "calculate_math",
    "get_weather",
]
