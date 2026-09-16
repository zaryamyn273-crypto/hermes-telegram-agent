"""
Instant Real-Time Weather Forecast using Open-Meteo.
Zero API Key required, sub-200ms response time.
"""

import httpx
from typing import Optional


# Pre-mapped coordinates for major Iranian and global cities for instant 0-latency hits
_KNOWN_CITIES = {
    "تهران": (35.6892, 51.3890),
    "tehran": (35.6892, 51.3890),
    "مشهد": (36.2972, 59.6067),
    "mashhad": (36.2972, 59.6067),
    "اصفهان": (32.6546, 51.6680),
    "isfahan": (32.6546, 51.6680),
    "شیراز": (29.5918, 52.5837),
    "shiraz": (29.5918, 52.5837),
    "تبریز": (38.0800, 46.2919),
    "tabriz": (38.0800, 46.2919),
    "کرج": (35.8327, 50.9915),
    "اهواز": (31.3183, 48.6706),
    "قم": (34.6401, 50.8764),
    "رشت": (37.2808, 49.5832),
    "کرمانشاه": (34.3142, 47.0650),
    "یزد": (31.8974, 54.3569),
    "دبی": (25.2048, 55.2708),
    "dubai": (25.2048, 55.2708),
    "استانبول": (41.0082, 28.9784),
    "istanbul": (41.0082, 28.9784),
    "لندن": (51.5074, -0.1278),
    "london": (51.5074, -0.1278),
}


_WEATHER_CODES = {
    0: ("آسمان کاملاً صاف و آفتابی ☀️", "Clear"),
    1: ("عمدتاً صاف 🌤", "Mainly clear"),
    2: ("نیمه ابری ⛅", "Partly cloudy"),
    3: ("تمام ابری ☁️", "Overcast"),
    45: ("مه‌آلود 🌫", "Fog"),
    48: ("مه همراه با یخ‌زدگی 🌫", "Depositing rime fog"),
    51: ("نم‌نم باران خفیف 🌦", "Light drizzle"),
    53: ("باران نم‌نم متوسط 🌦", "Moderate drizzle"),
    55: ("نم‌نم باران شدید 🌧", "Dense drizzle"),
    61: ("بارش ملایم باران 🌧", "Slight rain"),
    63: ("باران متوسط 🌧", "Moderate rain"),
    65: ("بارش شدید باران 🌧", "Heavy rain"),
    71: ("بارش خفیف برف 🌨", "Slight snow"),
    73: ("بارش برف متوسط 🌨", "Moderate snow"),
    75: ("بارش شدید برف ❄️", "Heavy snow"),
    80: ("رگبار خفیف باران 🌦", "Slight rain showers"),
    81: ("رگبار باران متوسط 🌧", "Moderate rain showers"),
    82: ("رگبار سیل‌آسا و شدید ⛈", "Violent rain showers"),
    95: ("رعد و برق و طوفان ⛈", "Thunderstorm"),
}


async def get_weather(city: str = "تهران") -> str:
    """Gets instant live weather and temperature for a given city."""
    clean_city = city.strip().lower()
    lat, lon = _KNOWN_CITIES.get(clean_city, (None, None))

    async with httpx.AsyncClient(timeout=4.0) as client:
        # Geocode if city is not in pre-mapped table
        if lat is None or lon is None:
            try:
                geo_url = f"https://geocoding-api.open-meteo.com/v1/search?name={city}&count=1&language=en&format=json"
                geo_resp = await client.get(geo_url)
                if geo_resp.status_code == 200:
                    results = geo_resp.json().get("results", [])
                    if results:
                        lat = results[0]["latitude"]
                        lon = results[0]["longitude"]
            except Exception:
                pass

        if lat is None or lon is None:
            return f"❌ مختصات جغرافیایی شهر '{city}' پیدا نشد. لطفاً نام شهر را دقیق‌تر وارد نمایید."

        try:
            weather_url = (
                f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}"
                f"&current=temperature_2m,relative_humidity_2m,apparent_temperature,is_day,precipitation,weather_code,wind_speed_10m"
                f"&timezone=auto"
            )
            w_resp = await client.get(weather_url)
            if w_resp.status_code != 200:
                return "⚠️ خطا در دریافت اطلاعات هواشناسی از سرور جهانی."

            current = w_resp.json().get("current", {})
            temp = current.get("temperature_2m", "--")
            app_temp = current.get("apparent_temperature", "--")
            humidity = current.get("relative_humidity_2m", "--")
            wind = current.get("wind_speed_10m", "--")
            code = current.get("weather_code", 0)
            desc_fa, desc_en = _WEATHER_CODES.get(code, ("وضعیت متغیر 🌤", "Variable"))

            lines = [
                f"🌦 *وضعیت آب و هوای {city}:*",
                f"• **شرایط:** {desc_fa}",
                f"• **دما:** `{temp}°C` (دمای حسی: `{app_temp}°C`)",
                f"• **رطوبت هوا:** `{humidity}%`",
                f"• **سرعت وزش باد:** `{wind} km/h`"
            ]
            return "\n".join(lines)
        except Exception as e:
            return f"خطا در ارتباط با سرور هواشناسی: {e}"
