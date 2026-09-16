"""
Live Weather Tool for Prometheus:
Provides real-time weather forecasts, temperatures, humidity, wind,
and conditions for Iranian and international cities via Open-Meteo and wttr.in fallback.
Uses persistent keepalive connection pooling, pre-indexed coordinates, and multi-tier L1 RAM & Cloudflare KV caching.
"""

import logging
import asyncio
import httpx
from typing import Dict, Any, Optional, Tuple

import database

logger = logging.getLogger("WeatherTool")

_WEATHER_CLIENT: Optional[httpx.AsyncClient] = None


def get_weather_client() -> httpx.AsyncClient:
    """Returns persistent AsyncClient with keepalive connection pooling."""
    global _WEATHER_CLIENT
    if _WEATHER_CLIENT is None or _WEATHER_CLIENT.is_closed:
        limits = httpx.Limits(max_keepalive_connections=30, max_connections=60, keepalive_expiry=60.0)
        timeout = httpx.Timeout(connect=2.0, read=4.0, write=2.0, pool=2.0)
        _WEATHER_CLIENT = httpx.AsyncClient(limits=limits, timeout=timeout)
    return _WEATHER_CLIENT


# Comprehensive Pre-Mapped Geographic Coordinates (Iran + Top Global Destinations)
_CITY_COORDINATES: Dict[str, Tuple[float, float]] = {
    # Iran Provincial Capitals & Major Cities
    "تهران": (35.6892, 51.3890),
    "مشهد": (36.2972, 59.6067),
    "اصفهان": (32.6546, 51.6680),
    "شیراز": (29.5918, 52.5837),
    "تبریز": (38.0800, 46.2919),
    "کرج": (35.8327, 50.9915),
    "قم": (34.6401, 50.8764),
    "اهواز": (31.3183, 48.6706),
    "کرمانشاه": (34.3142, 47.0650),
    "ارومیه": (37.5527, 45.0761),
    "رشت": (37.2808, 49.5832),
    "کرمان": (30.2839, 57.0788),
    "زاهدان": (29.4963, 60.8629),
    "همدان": (34.7982, 48.5146),
    "یزد": (31.8974, 54.3569),
    "اراک": (34.0954, 49.7013),
    "اردبیل": (38.2498, 48.2933),
    "بندرعباس": (27.1832, 56.2666),
    "قزوین": (36.2688, 50.0041),
    "زنجان": (36.6736, 48.4787),
    "سنندج": (35.3219, 46.9862),
    "گرگان": (36.8427, 54.4439),
    "ساری": (36.5659, 53.0586),
    "بوشهر": (28.9220, 50.8331),
    "خرم‌آباد": (33.4878, 48.3558),
    "ایلام": (33.6374, 46.4227),
    "سمنان": (35.5769, 53.3971),
    "شهرکرد": (32.3256, 50.8644),
    "یاسوج": (30.6684, 51.5876),
    "بیرجند": (32.8663, 59.2211),
    "بجنورد": (37.4761, 57.3237),
    "کیش": (26.5578, 53.9793),
    "قشم": (26.9585, 56.2718),
    "چابهار": (25.2919, 60.6430),
    "کاشان": (33.9850, 51.4100),
    "نیشابور": (36.2133, 58.7958),
    "دزفول": (32.3811, 48.4058),
    "آبادان": (30.3392, 48.3043),
    "بابل": (36.5513, 52.6789),
    "آمل": (36.4676, 52.3507),
    "لاهیجان": (37.2070, 50.0031),
    "بندرانزلی": (37.4681, 49.4622),
    "ساوه": (35.0213, 50.3566),
    "مراغه": (37.3919, 46.2392),
    "مهاباد": (36.7631, 45.7222),

    # Top International Destinations
    "دبی": (25.2048, 55.2708),
    "استانبول": (41.0082, 28.9784),
    "آنکارا": (39.9334, 32.8597),
    "لندن": (51.5074, -0.1278),
    "تورنتو": (43.6532, -79.3832),
    "ونکوور": (49.2827, -123.1207),
    "پاریس": (48.8566, 2.3522),
    "برلین": (52.5200, 13.4050),
    "فرانکفورت": (50.1109, 8.6821),
    "نیویورک": (40.7128, -74.0060),
    "لس آنجلس": (34.0522, -118.2437),
    "واشنگتن": (38.9072, -77.0369),
    "مسکو": (55.7558, 37.6173),
    "بغداد": (33.3152, 44.3661),
    "نجف": (32.0256, 44.3463),
    "کربلا": (32.6160, 44.0249),
    "اربیل": (36.1911, 44.0091),
    "ایروان": (40.1792, 44.4991),
    "تفلیس": (41.7151, 44.8271),
    "باکو": (40.4093, 49.8671),
    "دوحه": (25.2854, 51.5310),
    "ریاض": (24.7136, 46.6753),
    "مکه": (21.4225, 39.8262),
    "مدینه": (24.5247, 39.5692),
    "آمستردام": (52.3676, 4.9041),
    "توکیو": (35.6762, 139.6503),
    "سیدنی": (33.8688, 151.2093),
}

_WEATHER_CODE_MAP = {
    0: ("آسمان کاملاً صاف و آفتابی", "☀️"),
    1: ("عمدتاً صاف و آفتابی", "🌤"),
    2: ("نیمه‌ابری", "⛅"),
    3: ("ابری و گرفته", "☁️"),
    45: ("مه‌آلود", "🌫"),
    48: ("مه همراه با یخ‌زدگی", "🌫"),
    51: ("باران نم‌نم ملایم", "🌦"),
    53: ("باران نم‌نم متوسط", "🌦"),
    55: ("باران نم‌نم شدید", "🌧"),
    61: ("بارش ملایم باران", "🌧"),
    63: ("بارش متوسط باران", "🌧"),
    65: ("بارش شدید باران", "⛈"),
    71: ("بارش ملایم برف", "🌨"),
    73: ("بارش متوسط برف", "🌨"),
    75: ("بارش شدید برف", "❄️"),
    80: ("رگبار پراکنده باران", "🌦"),
    81: ("رگبار متوسط", "🌧"),
    82: ("رگبار شدید و تندبار", "⛈"),
    95: ("رعد و برق", "🌩"),
    96: ("رعد و برق همراه با تگرگ", "⛈"),
}


async def _geocode_city(city_clean: str) -> Tuple[Optional[float], Optional[float]]:
    """Geocodes city name via Open-Meteo Geocoding API."""
    client = get_weather_client()
    try:
        geo_resp = await client.get(
            "https://geocoding-api.open-meteo.com/v1/search",
            params={"name": city_clean, "count": 1, "language": "fa", "format": "json"}
        )
        if geo_resp.status_code == 200:
            results = geo_resp.json().get("results") or []
            if results:
                return results[0].get("latitude"), results[0].get("longitude")
    except Exception as e:
        logger.debug(f"Geocoding error for {city_clean}: {e}")
    return None, None


async def get_weather(city_name: str = "تهران") -> str:
    """
    Fetches real-time weather information with pre-indexed coordinate lookup and fast API delivery.
    """
    city_clean = city_name.strip()
    cache_key = f"PROMETHEUS_WEATHER_{city_clean.lower()}"

    cached = await database.kv_get(cache_key)
    if cached:
        return cached

    coords = _CITY_COORDINATES.get(city_clean)
    lat, lon = None, None

    if coords:
        lat, lon = coords
    else:
        lat, lon = await _geocode_city(city_clean)

    if lat is None or lon is None:
        return f"⚠️ اطلاعات جغرافیایی شهر «{city_name}» یافت نشد. لطفاً نام شهر را مجدداً بررسی نمایید."

    client = get_weather_client()
    try:
        resp = await client.get(
            "https://api.open-meteo.com/v1/forecast",
            params={
                "latitude": lat,
                "longitude": lon,
                "current": "temperature_2m,relative_humidity_2m,apparent_temperature,precipitation,weather_code,wind_speed_10m",
                "daily": "temperature_2m_max,temperature_2m_min",
                "timezone": "auto"
            }
        )
        if resp.status_code == 200:
            data = resp.json()
            curr = data.get("current", {})
            daily = data.get("daily", {})

            temp = curr.get("temperature_2m", 0)
            feels_like = curr.get("apparent_temperature", temp)
            humidity = curr.get("relative_humidity_2m", 0)
            wind = curr.get("wind_speed_10m", 0)
            code = curr.get("weather_code", 0)

            desc, emoji = _WEATHER_CODE_MAP.get(code, ("وضعیت متغیر", "⛅"))

            max_temp = daily.get("temperature_2m_max", [temp])[0]
            min_temp = daily.get("temperature_2m_min", [temp])[0]

            text = (
                f"🌦 **وضعیت آب و هوای {city_clean}:**\n\n"
                f"{emoji} **وضعیت جوی:** `{desc}`\n"
                f"🌡 **دمای کنونی:** `{temp}°C` (دمای حسی: `{feels_like}°C`)\n"
                f"🔺 **حداکثر دما:** `{max_temp}°C` | 🔻 **حداقل دما:** `{min_temp}°C`\n"
                f"💧 **رطوبت هوا:** `{humidity}%`\n"
                f"💨 **سرعت وزش باد:** `{wind} km/h`\n\n"
                "⚡ *استعلام زنده توسط پرومته*"
            )

            await database.kv_set(cache_key, text, ttl_sec=600)
            return text

    except Exception as e:
        logger.warning(f"Open-Meteo failed for {city_clean}: {e}")

    # Fallback to wttr.in
    try:
        wttr_resp = await client.get(f"https://wttr.in/{city_clean}?format=j1")
        if wttr_resp.status_code == 200:
            wd = wttr_resp.json()
            cur = wd.get("current_condition", [{}])[0]
            temp = cur.get("temp_C", "0")
            feels = cur.get("FeelsLikeC", temp)
            hum = cur.get("humidity", "0")
            desc = cur.get("lang_fa", [{}])[0].get("value") or cur.get("weatherDesc", [{}])[0].get("value", "صاف")

            text = (
                f"🌦 **وضعیت آب و هوای {city_clean}:**\n\n"
                f"⛅ **وضعیت جوی:** `{desc}`\n"
                f"🌡 **دمای کنونی:** `{temp}°C` (دمای حسی: `{feels}°C`)\n"
                f"💧 **رطوبت هوا:** `{hum}%`\n\n"
                "⚡ *استعلام زنده توسط پرومته (منبع پشتیبان)*"
            )
            await database.kv_set(cache_key, text, ttl_sec=600)
            return text
    except Exception as e2:
        logger.error(f"Weather fallback error for {city_clean}: {e2}")

    return f"⚠️ خطایی در استعلام وضعیت آب و هوای «{city_clean}» رخ داد."
