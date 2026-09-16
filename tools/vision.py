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


async def analyze_image_with_vision(
    image_bytes: bytes,
    prompt: Optional[str] = None,
    mime_type: str = "image/jpeg",
    chat_id: int = 0,
) -> str:
    """
    Sends the user's image to the multimodal neural vision engine and returns detailed Persian analysis.
    """
    if not image_bytes:
        return "⚠️ هیچ تصویری برای تحلیل دریافت نشد."

    # Base64 encode image
    b64 = base64.b64encode(image_bytes).decode("utf-8")
    data_url = f"data:{mime_type};base64,{b64}"

    user_query = (prompt or "").strip()
    if not user_query:
        user_query = "این تصویر را به دقت بررسی کن و تمام جزئیات، اشیاء، متون احتمالی و مفهوم آن را به زبان فارسی توضیح بده."

    # Format multimodal user message
    messages = [
        {"role": "system", "content": PROMETHEUS_VISION_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {"type": "text", "text": user_query},
                {"type": "image_url", "image_url": {"url": data_url}}
            ]
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
            logger.info(f"Dispatching Vision request to {api_url} (model={v_model}, bytes={len(image_bytes)})")
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
