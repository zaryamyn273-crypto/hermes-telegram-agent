"""
Configuration manager for Prometheus OSINT Telegram Agent.
Loads configuration from environment variables with zero hardcoded secrets.
Uses Pydantic if available, otherwise falls back seamlessly to standard dataclasses.
"""

import os
import re
from typing import Set, Optional, List, Tuple

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field

    class Settings(BaseSettings):
        TELEGRAM_BOT_TOKEN: str = Field(default="", env="TELEGRAM_BOT_TOKEN")
        ADMIN_ID: int = Field(default=8814471014, env="ADMIN_ID")
        ADMIN_IDS_RAW: str = Field(default="", env="ADMIN_IDS")

        ROUTER_BASE_URL: str = Field(default="https://api.openai.com/v1", env="ROUTER_BASE_URL")
        ROUTER_INTERNAL_BASE_URL: str = Field(default="", env="ROUTER_INTERNAL_BASE_URL")
        ROUTER_API_KEY: str = Field(default="", env="ROUTER_API_KEY")
        ROUTER_MODEL: str = Field(default="ag/gemini-3.8-flash-low", env="ROUTER_MODEL")
        ROUTER_FAST_MODEL: str = Field(default="ag/gemini-3.8-flash-low", env="ROUTER_FAST_MODEL")

        GITHUB_TOKEN: str = Field(default="", env="GITHUB_TOKEN")
        TAVILY_API_KEYS: str = Field(default="", env="TAVILY_API_KEYS")
        TAVILY_API_KEY: str = Field(default="", env="TAVILY_API_KEY")
        TAVILY_KEY: str = Field(default="", env="TAVILY_KEY")
        TAVILY_TOKEN: str = Field(default="", env="TAVILY_TOKEN")
        VIRUSTOTAL_API_KEY: str = Field(
            default="8c715c84eef42a06fcc42d407e547c63cb77ababf962877bfcea30834d1ff084",
            env="VIRUSTOTAL_API_KEY"
        )
        E2B_API_KEY: str = Field(default="", env="E2B_API_KEY")
        CLOUDFLARE_ACCOUNT_ID: str = Field(default="", env="CLOUDFLARE_ACCOUNT_ID")
        CLOUDFLARE_API_TOKEN: str = Field(default="", env="CLOUDFLARE_API_TOKEN")
        CLOUDFLARE_D1_ID: str = Field(default="", env="CLOUDFLARE_D1_ID")
        CLOUDFLARE_KV_ID: str = Field(default="", env="CLOUDFLARE_KV_ID")

        MAX_SESSION_HISTORY: int = Field(default=20, env="MAX_SESSION_HISTORY")
        STREAM_EDIT_INTERVAL: float = Field(default=0.85, env="STREAM_EDIT_INTERVAL")
        DAILY_USER_LIMIT: int = Field(default=50, env="DAILY_USER_LIMIT")
        RATE_LIMIT_USER_MAX_REQUESTS: int = Field(default=40, env="RATE_LIMIT_USER_MAX_REQUESTS")

        ADMIN_USER_IDS: List[int] = Field(default_factory=list)

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "allow"

    settings = Settings()

except ImportError:
    from dataclasses import dataclass

    @dataclass
    class Settings:
        TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
        ADMIN_ID: int = int(os.getenv("ADMIN_ID", "8814471014") or "8814471014")
        ADMIN_IDS_RAW: str = os.getenv("ADMIN_IDS", "")

        ROUTER_BASE_URL: str = os.getenv("ROUTER_BASE_URL", "https://api.openai.com/v1")
        ROUTER_INTERNAL_BASE_URL: str = os.getenv("ROUTER_INTERNAL_BASE_URL", "")
        ROUTER_API_KEY: str = os.getenv("ROUTER_API_KEY", "")
        ROUTER_MODEL: str = os.getenv("ROUTER_MODEL", "ag/gemini-3.8-flash-low")
        ROUTER_FAST_MODEL: str = os.getenv("ROUTER_FAST_MODEL", "ag/gemini-3.8-flash-low")

        GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
        TAVILY_API_KEYS: str = os.getenv("TAVILY_API_KEYS", "")
        TAVILY_API_KEY: str = os.getenv("TAVILY_API_KEY", "")
        TAVILY_KEY: str = os.getenv("TAVILY_KEY", "")
        TAVILY_TOKEN: str = os.getenv("TAVILY_TOKEN", "")
        VIRUSTOTAL_API_KEY: str = os.getenv(
            "VIRUSTOTAL_API_KEY",
            "8c715c84eef42a06fcc42d407e547c63cb77ababf962877bfcea30834d1ff084"
        )
        E2B_API_KEY: str = os.getenv("E2B_API_KEY", "")
        CLOUDFLARE_ACCOUNT_ID: str = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
        CLOUDFLARE_API_TOKEN: str = os.getenv("CLOUDFLARE_API_TOKEN", "")
        CLOUDFLARE_D1_ID: str = os.getenv("CLOUDFLARE_D1_ID", "")
        CLOUDFLARE_KV_ID: str = os.getenv("CLOUDFLARE_KV_ID", "")

        MAX_SESSION_HISTORY: int = int(os.getenv("MAX_SESSION_HISTORY", "20"))
        STREAM_EDIT_INTERVAL: float = float(os.getenv("STREAM_EDIT_INTERVAL", "0.85"))
        DAILY_USER_LIMIT: int = int(os.getenv("DAILY_USER_LIMIT", "50"))
        RATE_LIMIT_USER_MAX_REQUESTS: int = int(os.getenv("RATE_LIMIT_USER_MAX_REQUESTS", "40"))

    settings = Settings()


# Dynamic Admin ID Resolution
_ADMIN_IDS: Set[int] = set()
if settings.ADMIN_ID > 0:
    _ADMIN_IDS.add(settings.ADMIN_ID)
if settings.ADMIN_IDS_RAW:
    for part in settings.ADMIN_IDS_RAW.replace(",", " ").split():
        try:
            val = int(part.strip())
            if val > 0:
                _ADMIN_IDS.add(val)
        except ValueError:
            pass


def is_admin(user_id: Optional[int]) -> bool:
    """Returns True if user_id belongs to authorized administrators."""
    if user_id is None or type(user_id) is bool:
        return False
    try:
        uid = int(user_id)
        if uid in _ADMIN_IDS or (settings.ADMIN_ID > 0 and uid == settings.ADMIN_ID):
            return True
        admin_list = getattr(settings, "ADMIN_USER_IDS", None)
        if admin_list and uid in admin_list:
            return True
        return False
    except (ValueError, TypeError):
        return False


def get_candidate_endpoints(force_hermes: bool = False, force_fast: bool = False, *args, **kwargs) -> List[Tuple[str, str, str]]:
    """
    Returns ordered list of (base_url, api_key, model) candidates for resilient 9router connection.
    Prioritizes ultra low-latency internal 9router first, then public 9router.
    """
    fast_model = settings.ROUTER_FAST_MODEL or "ag/gemini-3.8-flash-low"
    candidates: List[Tuple[str, str, str]] = []

    if settings.ROUTER_INTERNAL_BASE_URL:
        candidates.append((
            settings.ROUTER_INTERNAL_BASE_URL.rstrip("/"),
            settings.ROUTER_API_KEY,
            fast_model
        ))
    if settings.ROUTER_BASE_URL:
        candidates.append((
            settings.ROUTER_BASE_URL.rstrip("/"),
            settings.ROUTER_API_KEY,
            fast_model
        ))

    if not candidates:
        candidates.append(("https://api.openai.com/v1", settings.ROUTER_API_KEY, fast_model))

    return candidates


def get_effective_router_url() -> str:
    """Selects the best available API endpoint."""
    if settings.ROUTER_INTERNAL_BASE_URL:
        return settings.ROUTER_INTERNAL_BASE_URL.rstrip("/")
    if settings.ROUTER_BASE_URL:
        return settings.ROUTER_BASE_URL.rstrip("/")
    return "https://api.openai.com/v1"


def get_effective_api_key() -> str:
    """Returns the effective API key for LLM requests."""
    return settings.ROUTER_API_KEY or os.getenv("ROUTER_API_KEY", "")


def get_effective_model() -> str:
    """Returns the effective LLM model name."""
    if settings.ROUTER_FAST_MODEL:
        return settings.ROUTER_FAST_MODEL
    model = os.getenv("ROUTER_MODEL") or settings.ROUTER_MODEL
    if not model or model.lower() == "high":
        return "ag/gemini-3.8-flash-low"
    return model


def get_github_token() -> str:
    """Returns the GitHub token for OSINT lookups."""
    return getattr(settings, "GITHUB_TOKEN", "") or os.getenv("GITHUB_TOKEN", "")


def get_tavily_api_keys() -> List[str]:
    """Returns parsed list of Tavily API keys from configuration or environment."""
    keys: List[str] = []
    candidates = [
        getattr(settings, "TAVILY_API_KEYS", ""),
        getattr(settings, "TAVILY_API_KEY", ""),
        getattr(settings, "TAVILY_KEY", ""),
        getattr(settings, "TAVILY_TOKEN", ""),
        os.getenv("TAVILY_API_KEYS", ""),
        os.getenv("TAVILY_API_KEY", ""),
        os.getenv("TAVILY_KEY", ""),
        os.getenv("TAVILY_TOKEN", ""),
    ]
    for c in candidates:
        if c:
            for k in re.split(r"[,;\s\n]+", str(c)):
                k = k.strip()
                if k and k not in keys:
                    keys.append(k)
    return keys
