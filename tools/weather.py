"""
Live Weather Tool for Prometheus:
Provides real-time weather forecasts, temperatures, humidity, wind,
and conditions for Iranian and international cities via Open-Meteo.
Uses Cloudflare KV and L1 RAM caching.
"""

import httpx
import logging
import database

logger = logging.getLogger("WeatherTool")

_CITY_COORDINATES = {
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
    "کیش": (26.5578, 53.9793),
}

_WEATHER_CODE_MAP = {
    0: ("آسمان کاملاً صاف و آفتابی", "☀️"),
    1: ("عمدتاً صاف", "🌤"),
    2: ("نیمه‌ابری", "⛅"),
    3: ("ابری", "☁️"),
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


async def get_weather(city_name: str = "تهران") -> str:
    """
    Fetches real-time weather information for a specified city.
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
        # Geocode city name via Open-Meteo Geocoding API
        try:
            async with httpx.AsyncClient(timeout=3.5) as client:
                geo_resp = await client.get(
                    "https://geocoding-api.open-meteo.com/v1/search",
                    params={"name": city_clean, "count": 1, "language": "fa", "format": "json"}
                )
                if geo_resp.status_code == 200:
                    results = geo_resp.json().get("results") or []
                    if results:
                        lat = results[0].get("latitude")
                        lon = results[0].get("longitude")
        except Exception:
            pass

    if lat is None or lon is None:
        return f"⚠️ اطلاعات جغرافیایی شهر «{city_name}» یافت نشد. لطفاً نام شهر را مجدداً بررسی نمایید."

    try:
        async with httpx.AsyncClient(timeout=4.0) as client:
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
            if resp.status_code != 200:
                return f"⚠️ دریافت داده‌های آب و هوا برای شهر «{city_clean}» با خطا مواجه شد."

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
        logger.error(f"Weather query error for {city_clean}: {e}")
        return f"⚠️ خطایی در استعلام وضعیت آب و هوای «{city_clean}» رخ داد: {str(e)}"
