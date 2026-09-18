"""
Prometheus OSINT Suite - Image & Forensic EXIF / Geolocation Metadata Extractor.
Extracts camera hardware, capture timestamps, software alterations,
and exact GPS coordinates with direct Google Maps and OpenStreetMap links.
"""

import io
import html
import logging
from typing import Dict, Any, Optional, Tuple
import httpx
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS, IFD

from utils.formatter import wrap_in_expandable_blockquote

logger = logging.getLogger("OSINT_Exif")


def _convert_dms_to_decimal(dms: Any, ref: str) -> Optional[float]:
    """Converts Degrees, Minutes, Seconds tuple/list to signed decimal degrees."""
    try:
        if isinstance(dms, (list, tuple)) and len(dms) == 3:
            deg = float(dms[0])
            minute = float(dms[1])
            sec = float(dms[2])
            decimal = deg + (minute / 60.0) + (sec / 3600.0)
            if ref.upper() in ["S", "W"]:
                decimal = -decimal
            return round(decimal, 6)
    except Exception as e:
        logger.debug(f"Failed to convert DMS to decimal: {e}")
    return None


def extract_exif_metadata(image_bytes: bytes, filename: str = "image.jpg") -> Dict[str, Any]:
    """
    Parses EXIF and GPS IFD metadata from raw image bytes.
    """
    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception as e:
        return {
            "success": False,
            "filename": filename,
            "error": f"فایل ارسالی یک تصویر معتبر یا قابل خواندن نیست: {e}",
        }

    width, height = image.size
    img_format = image.format or "نامشخص"
    mode = image.mode

    # Extract standard EXIF tags
    exif_data = image.getexif()
    parsed_tags: Dict[str, Any] = {}
    gps_info: Dict[str, Any] = {}

    if exif_data:
        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, str(tag_id))
            # Format bytes value into readable string
            if isinstance(value, bytes):
                try:
                    value = value.decode("utf-8", errors="replace").strip("\x00")
                except Exception:
                    value = f"<Binary Data {len(value)} bytes>"
            parsed_tags[tag_name] = value

        # Try extracting GPS IFD
        try:
            gps_ifd = exif_data.get_ifd(IFD.GPSInfo)
            if gps_ifd:
                for k, v in gps_ifd.items():
                    sub_name = GPSTAGS.get(k, str(k))
                    gps_info[sub_name] = v
        except Exception:
            pass

    # Fallback to _getexif() if available
    if not parsed_tags and hasattr(image, "_getexif"):
        try:
            raw_exif = image._getexif()
            if raw_exif:
                for k, v in raw_exif.items():
                    tag_name = TAGS.get(k, str(k))
                    if tag_name == "GPSInfo":
                        for gk, gv in v.items():
                            gps_info[GPSTAGS.get(gk, str(gk))] = gv
                    else:
                        parsed_tags[tag_name] = v
        except Exception:
            pass

    # Extract Camera Hardware & Settings
    camera_make = parsed_tags.get("Make", "نامشخص")
    camera_model = parsed_tags.get("Model", "نامشخص")
    software = parsed_tags.get("Software", "نامشخص")
    datetime_original = parsed_tags.get("DateTimeOriginal") or parsed_tags.get("DateTime", "نامشخص")
    lens_model = parsed_tags.get("LensModel", "")
    f_number = parsed_tags.get("FNumber", "")
    iso = parsed_tags.get("ISOSpeedRatings", "")
    focal_length = parsed_tags.get("FocalLength", "")

    # Calculate Coordinates
    has_gps = False
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude: Optional[float] = None
    google_maps_url = ""
    osm_url = ""

    if gps_info:
        lat_dms = gps_info.get("GPSLatitude")
        lat_ref = gps_info.get("GPSLatitudeRef", "N")
        lon_dms = gps_info.get("GPSLongitude")
        lon_ref = gps_info.get("GPSLongitudeRef", "E")

        if lat_dms and lon_dms:
            latitude = _convert_dms_to_decimal(lat_dms, lat_ref)
            longitude = _convert_dms_to_decimal(lon_dms, lon_ref)

            if latitude is not None and longitude is not None:
                has_gps = True
                google_maps_url = f"https://www.google.com/maps?q={latitude},{longitude}"
                osm_url = f"https://www.openstreetmap.org/?mlat={latitude}&mlon={longitude}#map=16/{latitude}/{longitude}"

        alt_val = gps_info.get("GPSAltitude")
        if alt_val:
            try:
                altitude = round(float(alt_val), 1)
            except Exception:
                pass

    has_exif = bool(parsed_tags or gps_info)

    return {
        "success": True,
        "filename": filename,
        "format": img_format,
        "width": width,
        "height": height,
        "mode": mode,
        "has_exif": has_exif,
        "camera_make": str(camera_make).strip(),
        "camera_model": str(camera_model).strip(),
        "software": str(software).strip(),
        "datetime_original": str(datetime_original).strip(),
        "lens_model": str(lens_model).strip() if lens_model else "",
        "f_number": str(f_number) if f_number else "",
        "iso": str(iso) if iso else "",
        "focal_length": str(focal_length) if focal_length else "",
        "has_gps": has_gps,
        "latitude": latitude,
        "longitude": longitude,
        "altitude_meters": altitude,
        "google_maps_url": google_maps_url,
        "openstreetmap_url": osm_url,
        "raw_tags_count": len(parsed_tags),
    }


async def extract_exif_from_url(image_url: str) -> Dict[str, Any]:
    """Downloads an image from a URL and extracts forensic EXIF data."""
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Prometheus OSINT Forensic Engine)"}
        async with httpx.AsyncClient(headers=headers, timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(image_url)
            if resp.status_code == 200 and resp.content:
                filename = image_url.split("?")[0].split("/")[-1] or "image.jpg"
                return extract_exif_metadata(resp.content, filename=filename)
            return {
                "success": False,
                "url": image_url,
                "error": f"خطا در دریافت تصویر از سرور (کد خطا: {resp.status_code})",
            }
    except Exception as e:
        return {
            "success": False,
            "url": image_url,
            "error": f"عدم برقراری ارتباط با لینک تصویر: {e}",
        }


def format_exif_report(data: Dict[str, Any]) -> str:
    """Formats EXIF and geolocation forensic analysis into Persian Telegram HTML."""
    if not data.get("success"):
        return f"🖼 <b>خطا در استخراج متاداده تصویر (EXIF):</b> {html.escape(data.get('error', 'ناشناخته'))}"

    fname = html.escape(data.get("filename", "تصویر"))
    fmt = html.escape(data.get("format", ""))
    w = data.get("width", 0)
    h = data.get("height", 0)
    has_ex = data.get("has_exif", False)
    make = html.escape(data.get("camera_make", "نامشخص"))
    model = html.escape(data.get("camera_model", "نامشخص"))
    sw = html.escape(data.get("software", "نامشخص"))
    dt = html.escape(data.get("datetime_original", "نامشخص"))
    has_gps = data.get("has_gps", False)

    lines = [
        f"🖼 <b>کالبدشکافی فارنزیک و متاداده تصویر (EXIF & Geolocation Intel):</b>\n<code>{fname}</code>\n",
        f"• <b>ابعاد و فرمت:</b> <code>{w}x{h}</code> پیکسل (فرمت: <code>{fmt}</code>)",
        f"• <b>وجود متاداده EXIF:</b> {'✅ شناسایی شد' if has_ex else '⚠️ متاداده یافت نشد (یا توسط پلتفرم پاکسازی شده)'}",
    ]

    if has_ex:
        lines.extend([
            f"• <b>شرکت سازنده:</b> <code>{make}</code>",
            f"• <b>مدل دوربین/گوشی:</b> <b>{model}</b>",
            f"• <b>نرم‌افزار/سیستم‌عامل ویرایش:</b> <code>{sw}</code>",
            f"• <b>زمان ثبت عکس:</b> <code>{dt}</code>",
        ])
        if data.get("lens_model"):
            lines.append(f"• <b>مدل لنز:</b> <code>{html.escape(data['lens_model'])}</code>")
        if data.get("iso"):
            lines.append(f"• <b>تنظیمات شات:</b> ISO: <code>{html.escape(data['iso'])}</code> | دیافراگم: <code>f/{html.escape(data.get('f_number', ''))}</code>")

    # Geolocation / GPS section
    if has_gps:
        lat = data.get("latitude")
        lon = data.get("longitude")
        gmaps = data.get("google_maps_url")
        osm = data.get("openstreetmap_url")
        alt = data.get("altitude_meters")
        alt_str = f" (ارتفاع: <code>{alt} متر</code>)" if alt else ""

        gps_block = (
            f"📍 <b>مختصات جغرافیایی دقیق:</b>\n"
            f"• عرض جغرافیایی (Lat): <code>{lat}</code>\n"
            f"• طول جغرافیایی (Lon): <code>{lon}</code>{alt_str}\n\n"
            f"🗺 <b>مشاهده مستقیم روی نقشه:</b>\n"
            f"• <a href=\"{gmaps}\">مسیریابی در Google Maps</a>\n"
            f"• <a href=\"{osm}\">مشاهده در OpenStreetMap</a>"
        )
        lines.append(f"\n🌐 <b>موقعیت مکانی ثبت عکس (GPS Coordinates):</b>\n{wrap_in_expandable_blockquote(gps_block)}")
    else:
        lines.append("\n📍 <b>مختصات GPS:</b> برچسب موقعیت مکانی در فایل موجود نیست.")

    lines.append("\n⚡️ <i>استخراج متاداده‌های هویتی، تجهیزات تصویربرداری و موقعیت‌یابی ماهواره‌ای</i>")
    return "\n".join(lines)
