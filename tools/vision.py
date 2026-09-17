"""
Prometheus Vision & Multimodal Image Understanding Engine:
Provides high-speed image analysis, visual Q&A, OCR text extraction,
and visual reconstruction (reverse-engineering prompts & generating previews)
using Gemini multimodal models via 9router private network.
"""

import re
import base64
import random
import logging
import urllib.parse
from typing import Optional, Tuple

from config import (
    get_candidate_endpoints,
    get_effective_router_url,
    get_effective_api_key,
    get_effective_model,
)
from agent_engine import get_http_client, clean_agent_output, is_provider_error

logger = logging.getLogger("PrometheusVision")

PROMETHEUS_VISION_SYSTEM_PROMPT = """You are Prometheus Vision Engine (موتور بینایی هوشمند پرومته).
Your purpose is to deeply analyze images provided by Telegram users with exceptional clarity, accuracy, and fluency in native Persian (فارسی).

Operating Guidelines:
1. Thorough Visual Breakdown:
   - Identify every key object, subject, person, expression, or action.
   - Accurately read and transcribe any text, sign, numbers, or logo visible (OCR).
   - Describe lighting, color palette, background, atmosphere, and artistic style.
2. Direct, Engaging Tone:
   - Deliver clear, well-structured answers using clean Markdown (bold keywords, bullet points).
   - Do NOT use filler phrases ("In this picture I see"). Deliver the facts directly.
3. Prompt Engineering & Image Reconstruction:
   - When asked to reconstruct, recreate, or make a prompt for an image ("بازسازی", "ساخت مجدد", "پرامپت بساز"):
     Provide both:
     a) A comprehensive Persian visual breakdown.
     b) A master-level, highly descriptive English Prompt for Midjourney / Flux / Stable Diffusion enclosed in a code block.
"""


from typing import Optional, Tuple, List, Union, Dict, Any

async def analyze_image_with_vision(
    image_bytes: Optional[Union[bytes, List[bytes]]] = None,
    prompt: Optional[str] = None,
    mime_type: str = "image/jpeg",
    chat_id: int = 0,
    images: Optional[List[bytes]] = None,
) -> str:
    """
    Sends one or multiple images (such as a Telegram album) to the multimodal neural vision engine
    and returns detailed Persian analysis.
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
        user_query = "این تصویر را به دقت بررسی کن و تمام جزئیات، اشیاء، متون احتمالی و مفهوم آن را به زبان فارسی توضیح بده."

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
        {"role": "system", "content": PROMETHEUS_VISION_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": content_payload
        }
    ]

    candidate_endpoints = get_candidate_endpoints(force_fast=True)
    if not candidate_endpoints:
        candidate_endpoints = [(
            get_effective_router_url(),
            get_effective_api_key(),
            get_effective_model()
        )]

    client = get_http_client()
    for api_url, api_key, model in candidate_endpoints:
        # Multimodal requests default to vision model
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
            "temperature": 0.2,
            "max_tokens": 2048,
        }

        try:
            total_bytes = sum(len(b) for b in img_list)
            logger.info(f"Dispatching Vision request to {api_url} (model={v_model}, images={len(img_list)}, total_bytes={total_bytes})")
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
                logger.info(f"Successfully received vision analysis ({len(cleaned)} chars)")
                return cleaned

        except Exception as e:
            logger.warning(f"Vision request failed on {api_url}: {e}")
            continue

    return "⚠️ متأسفانه امکان پردازش و بینایی این تصویر در حال حاضر میسر نشد. لطفاً مجدداً امتحان نمایید."


def is_reconstruction_query(text: str) -> bool:
    """Detects if the user specifically requested image reconstruction or generation."""
    t = (text or "").lower().strip()
    keywords = [
        "بازسازی", "ساخت مجدد", "مجدد بساز", "دوباره بساز", "شبیه‌سازی تصویر",
        "شبیه سازی تصویر", "پرامپت برای ساخت", "عکس رو بساز", "تصویر رو بساز",
        "reconstruct", "recreate", "remake"
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
