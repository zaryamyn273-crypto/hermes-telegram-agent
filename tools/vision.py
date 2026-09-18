"""
Prometheus Supercharged Vision & Multimodal Forensic Intelligence Engine.
Provides high-speed visual scene decomposition, precision multilingual OCR,
visual cyber threat / phishing detection, geographic reconnaissance (Geo-Guessing),
and master-level AI image prompt reverse-engineering (Midjourney / Flux / SD).
"""

import re
import base64
import random
import hashlib
import logging
import urllib.parse
from typing import Optional, Tuple, List, Union, Dict, Any

from config import (
    get_candidate_endpoints,
    get_effective_router_url,
    get_effective_api_key,
    get_effective_model,
)
from agent_engine import get_http_client, clean_agent_output, is_provider_error
from utils.cache import vision_cache

logger = logging.getLogger("PrometheusVision")


# =========================================================================
# Specialized Multimodal System Prompts
# =========================================================================

PROMETHEUS_VISION_BASE_SYSTEM = """You are Prometheus Supercharged Vision Engine (موتور بینایی و هوش دیداری فوق‌پیشرفته پرومته).
Your purpose is to deeply analyze images provided by Telegram users with exceptional accuracy, factual rigor, and native Persian (فارسی).

Core Operating Principles:
1. Deliver direct, professional analysis without conversational filler ("In this picture I see").
2. Use clean Markdown formatting with bold keywords and structured bullet points.
3. Zero Hallucination: Never invent or assume details that are not visibly present in the image.
"""

MODE_SYSTEM_PROMPTS = {
    "general": PROMETHEUS_VISION_BASE_SYSTEM + """
Mode: Deep Visual & Forensic Scene Decomposition (تحلیل جامع دیداری و کالبدشکافی صحنه)
Guidelines:
- Object & Subject Breakdown: Identify key subjects, individuals, facial features, apparel, actions, or focal items.
- Environment & Context: Describe setting (interior/exterior), lighting, atmosphere, time of day, and color palette.
- Detectable Details: Mention any visible logos, brands, vehicle models, or unique patterns.
- OCR Highlights: Point out and transcribe any noticeable text or labels.
""",

    "ocr": PROMETHEUS_VISION_BASE_SYSTEM + """
Mode: High-Precision Multilingual Document & OCR Text Extraction (استخراج دقیق متون و اسناد)
Guidelines:
- Extract and transcribe ALL visible text verbatim in Persian, Arabic, English, or any other language.
- Maintain original structure: Use Markdown code blocks, lists, and tables for tables, receipts, or forms.
- Transcribe numbers, license plates, serial numbers, phone numbers, and dates with 100% precision.
- If text is partially obscured or low-resolution, state: [نامشخص/مخدوش] without guessing.
""",

    "threat": PROMETHEUS_VISION_BASE_SYSTEM + """
Mode: Visual Threat, Fraud & Phishing Forensic Inspection (بازرسی امنیتی فیشینگ و اسکرین‌شات‌های مشکوک)
Guidelines:
- Carefully scrutinize the screenshot or document for malicious indicators:
  * Phishing login pages (fake Telegram web login, fake banking portal, fake Metamask popup).
  * Forged transaction receipts (رسیدهای جعلی فیش‌زنی / انتقال شبا).
  * Fake SMS / social media verification codes and impersonation.
  * Suspicious or mismatched URLs displayed in browser address bars.
- Provide a clear Security Verdict (🟢 امن / 🟡 مشکوک / 🔴 جعلی یا فیشینگ) followed by specific red flags observed.
""",

    "geoguess": PROMETHEUS_VISION_BASE_SYSTEM + """
Mode: OSINT Geographic & Environmental Reconnaissance (شناسایی موقعیت مکانی و سرنخ‌های جغرافیایی)
Guidelines:
- Identify every visual clue that reveals the location or country:
  * Architectural styles, roofing, and building materials.
  * Road signage, traffic signs, lane markings, and driving side (left vs right).
  * Utility poles, power lines, transformer designs, and streetlights.
  * Vehicle license plate shapes and colors.
  * Flora, tree species, soil type, sun angle, and climate cues.
  * Languages or scripts on billboards and storefronts.
- Conclude with Most Probable Countries/Cities and the specific clues that support your hypothesis.
""",

    "reconstruct": PROMETHEUS_VISION_BASE_SYSTEM + """
Mode: Master-Level Prompt Reverse-Engineering (مهندسی معکوس پرامپت جهت بازسازی مجدد تصویر)
Guidelines:
1. Provide a thorough Persian breakdown of the visual style, subject, composition, and lighting.
2. In a separate code block, provide an exhaustive, master-tier English Prompt for Midjourney v6 / Flux.1 / Stable Diffusion:
   - Include subject description, camera lens (e.g. 35mm f/1.4), lighting style (e.g. volumetric, rim lighting, golden hour), medium/render style (e.g. photorealistic 8k octane render), and parameters (e.g. --ar 16:9 --v 6.0).
"""
}


def detect_vision_mode(prompt: Optional[str]) -> str:
    """
    Intelligently determines the optimal vision processing mode based on user prompt keywords.
    """
    if not prompt:
        return "general"

    t = prompt.lower().strip()

    # OCR / Text extraction
    ocr_keywords = [
        "متن", "ocr", "بخوان", "بخون", "نوشته", "کلمات", "رونویسی", "فاکتور",
        "رسید", "شماره", "پلاک", "جدول", "ترجمه متن", "extract text", "read"
    ]
    if any(k in t for k in ocr_keywords) and not any(k in t for k in ["جعلی", "فیشینگ"]):
        return "ocr"

    # Threat / Phishing / Fraud
    threat_keywords = [
        "فیشینگ", "کلاهبرداری", "جعلی", "اسکم", "رسید فیک", "فیش زنی", "فیشزنی",
        "رسید جعلی", "هک", "امنیتی", "مشکوک", "phish", "scam", "fake", "threat"
    ]
    if any(k in t for k in threat_keywords):
        return "threat"

    # Geoguess / Location
    geo_keywords = [
        "کجاست", "مکان", "لوکیشن", "موقعیت", "کدوم کشور", "کدام کشور", "شهر",
        "منطقه", "جغرافیا", "geoguess", "location", "where is"
    ]
    if any(k in t for k in geo_keywords):
        return "geoguess"

    # Prompt reconstruction
    if is_reconstruction_query(t):
        return "reconstruct"

    return "general"


def is_reconstruction_query(text: str) -> bool:
    """Detects if the user specifically requested image reconstruction or generation."""
    t = (text or "").lower().strip()
    keywords = [
        "بازسازی", "ساخت مجدد", "مجدد بساز", "دوباره بساز", "شبیه‌سازی تصویر",
        "شبیه سازی تصویر", "پرامپت برای ساخت", "عکس رو بساز", "تصویر رو بساز",
        "پرامپت", "پرامپتشو", "پرامپت بساز", "reconstruct", "recreate", "remake"
    ]
    if any(k in t for k in keywords):
        return True
    if "مجدد" in t and ("بساز" in t or "تولید" in t or "ایجاد" in t):
        return True
    if "دوباره" in t and ("بساز" in t or "تولید" in t or "ایجاد" in t):
        return True
    return False


def build_reconstruction_image_url(english_prompt: str) -> str:
    """Generates an instant visual preview URL from English prompt via Pollinations.ai."""
    clean_p = re.sub(r"[^\w\s,\-]", "", english_prompt).strip()[:250]
    encoded = urllib.parse.quote(clean_p)
    seed = random.randint(1000, 999999)
    return f"https://image.pollinations.ai/prompt/{encoded}?width=1024&height=1024&seed={seed}&nologo=true"


async def analyze_image_with_vision(
    image_bytes: Optional[Union[bytes, List[bytes]]] = None,
    prompt: Optional[str] = None,
    mime_type: str = "image/jpeg",
    chat_id: int = 0,
    images: Optional[List[bytes]] = None,
    force_mode: Optional[str] = None,
) -> str:
    """
    Sends one or multiple images to the multimodal neural vision engine
    with specialized task modes (OCR, Cyber Threat, Geo-Guessing, Reconstruct, General).
    """
    # Normalize images
    img_list: List[bytes] = []
    if images:
        img_list.extend([img for img in images if img])
    elif image_bytes:
        if isinstance(image_bytes, list):
            img_list.extend([img for img in image_bytes if img])
        elif isinstance(image_bytes, (bytes, bytearray)):
            img_list.append(bytes(image_bytes))

    if not img_list:
        return "⚠️ هیچ تصویری برای تحلیل دریافت نشد."

    user_query = (prompt or "").strip()
    is_album = len(img_list) > 1

    # Detect specialized mode
    mode = force_mode if force_mode in MODE_SYSTEM_PROMPTS else detect_vision_mode(user_query)
    system_prompt = MODE_SYSTEM_PROMPTS.get(mode, MODE_SYSTEM_PROMPTS["general"])

    # Check cache for single image requests
    cache_key = ""
    if not is_album:
        h = hashlib.sha256(img_list[0]).hexdigest()[:16]
        cache_key = f"vis_{h}_{mode}_{user_query[:50]}"
        cached_res = await vision_cache.get(cache_key)
        if cached_res:
            logger.debug(f"Vision cache hit for {cache_key}")
            return cached_res

    # Default prompts per mode
    if is_album:
        if not user_query:
            user_query = (
                f"این مجموعه شامل {len(img_list)} تصویر از یک آلبوم تلگرام است. "
                "لطفاً همه تصاویر را با دقت بررسی، مقایسه و تک‌تک آن‌ها را با ذکر شماره (تصویر ۱، تصویر ۲ و...) "
                "به زبان فارسی توضیح داده و نکات مشترک یا تفاوت‌های آن‌ها را بیان کن."
            )
        else:
            user_query = (
                f"این مجموعه شامل {len(img_list)} تصویر از یک آلبوم تلگرام است. "
                f"با در نظر گرفتن همه تصاویر، به پرسش یا دستور زیر پاسخ بده:\n{user_query}"
            )
    elif not user_query:
        if mode == "ocr":
            user_query = "تمام متون، اعداد، ارقام و اطلاعات موجود در این تصویر را به طور کامل، دقیق و بدون تغییر رونویسی کن."
        elif mode == "threat":
            user_query = "این اسکرین‌شات یا تصویر را از نظر اصالت، جعل، فیشینگ یا تهدیدات سایبری ارزیابی کن."
        elif mode == "geoguess":
            user_query = "تمام سرنخ‌های محیطی، معماری و مکانی این عکس را بررسی کن و محتمل‌ترین کشور یا شهر را مشخص کن."
        elif mode == "reconstruct":
            user_query = "این تصویر را تحلیل کن و یک پرامپت حرفه‌ای انگلیسی برای بازسازی آن در Midjourney ارائه بده."
        else:
            user_query = "این تصویر را به دقت بررسی کن و تمام جزئیات، اشیاء، اشخاص، متون احتمالی و مفهوم آن را به زبان فارسی توضیح بده."

    # Build multimodal content payload
    content_payload: List[Dict[str, Any]] = [
        {"type": "text", "text": user_query}
    ]

    for idx, img_b in enumerate(img_list, start=1):
        b64 = base64.b64encode(img_b).decode("utf-8")
        content_payload.append({
            "type": "image_url",
            "image_url": {"url": f"data:{mime_type};base64,{b64}"}
        })

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": content_payload}
    ]

    # Temperature tuning: lower for factual OCR/Threat, higher for creative
    temp = 0.1 if mode in ["ocr", "threat"] else (0.4 if mode == "reconstruct" else 0.2)

    candidate_endpoints = get_candidate_endpoints(force_fast=True)
    if not candidate_endpoints:
        candidate_endpoints = [(
            get_effective_router_url(),
            get_effective_api_key(),
            get_effective_model()
        )]

    client = get_http_client()
    for api_url, api_key, model in candidate_endpoints:
        v_model = model
        if "low" in model:
            v_model = "ag/gemini-3.8-flash-low"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "X-Hermes-Session-Id": f"vision_chat_{chat_id}",
        }
        payload = {
            "model": v_model,
            "messages": messages,
            "stream": False,
            "temperature": temp,
            "max_tokens": 2048,
        }

        try:
            total_bytes = sum(len(b) for b in img_list)
            logger.info(f"Dispatching Vision request to {api_url} (mode={mode}, model={v_model}, images={len(img_list)}, bytes={total_bytes})")
            resp = await client.post(
                f"{api_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=25.0
            )
            if resp.status_code != 200:
                logger.warning(f"Vision endpoint {api_url} returned HTTP {resp.status_code}: {resp.text[:200]}")
                continue

            data = resp.json()
            choices = data.get("choices") or []
            if not choices:
                continue

            content = choices[0].get("message", {}).get("content") or ""
            if is_provider_error(content):
                continue

            cleaned = clean_agent_output(content)
            if cleaned:
                logger.info(f"Successfully received vision analysis ({len(cleaned)} chars, mode={mode})")
                if cache_key:
                    await vision_cache.set(cache_key, cleaned, ttl=600.0)
                return cleaned

        except Exception as e:
            logger.warning(f"Vision request failed on {api_url}: {e}")
            continue

    return "⚠️ متأسفانه امکان پردازش و بینایی این تصویر در حال حاضر میسر نشد. لطفاً مجدداً امتحان نمایید."
