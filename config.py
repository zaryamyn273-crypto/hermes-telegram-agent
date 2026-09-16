"""
Configuration manager for Hermes Telegram Agent.
Loads configuration from environment variables with zero hardcoded secrets.
Uses Pydantic if available, otherwise falls back seamlessly to standard dataclasses.
"""

import os
from typing import Set, Optional, List

try:
    from pydantic_settings import BaseSettings
    from pydantic import Field

    class Settings(BaseSettings):
        TELEGRAM_BOT_TOKEN: str = Field(default="", env="TELEGRAM_BOT_TOKEN")
        ADMIN_ID: int = Field(default=0, env="ADMIN_ID")
        ADMIN_IDS_RAW: str = Field(default="", env="ADMIN_IDS")

        ROUTER_BASE_URL: str = Field(default="https://api.openai.com/v1", env="ROUTER_BASE_URL")
        ROUTER_INTERNAL_BASE_URL: str = Field(default="", env="ROUTER_INTERNAL_BASE_URL")
        ROUTER_API_KEY: str = Field(default="", env="ROUTER_API_KEY")
        ROUTER_MODEL: str = Field(default="Hermes-3-Llama-3.1-8B", env="ROUTER_MODEL")
        ROUTER_FAST_MODEL: str = Field(default="Hermes-3-Llama-3.1-8B", env="ROUTER_FAST_MODEL")

        HERMES_ENDPOINT: str = Field(default="", env="HERMES_ENDPOINT")
        HERMES_API_KEY: str = Field(default="", env="HERMES_API_KEY")

        TAVILY_API_KEYS: str = Field(default="", env="TAVILY_API_KEYS")
        CLOUDFLARE_ACCOUNT_ID: str = Field(default="", env="CLOUDFLARE_ACCOUNT_ID")
        CLOUDFLARE_API_TOKEN: str = Field(default="", env="CLOUDFLARE_API_TOKEN")
        CLOUDFLARE_D1_ID: str = Field(default="", env="CLOUDFLARE_D1_ID")
        CLOUDFLARE_KV_ID: str = Field(default="", env="CLOUDFLARE_KV_ID")

        MAX_SESSION_HISTORY: int = Field(default=20, env="MAX_SESSION_HISTORY")
        STREAM_EDIT_INTERVAL: float = Field(default=0.85, env="STREAM_EDIT_INTERVAL")
        DAILY_USER_LIMIT: int = Field(default=50, env="DAILY_USER_LIMIT")
        RATE_LIMIT_USER_MAX_REQUESTS: int = Field(default=40, env="RATE_LIMIT_USER_MAX_REQUESTS")

        class Config:
            env_file = ".env"
            env_file_encoding = "utf-8"
            extra = "ignore"

    settings = Settings()

except ImportError:
    from dataclasses import dataclass

    @dataclass
    class Settings:
        TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")
        ADMIN_ID: int = int(os.getenv("ADMIN_ID", "0") or "0")
        ADMIN_IDS_RAW: str = os.getenv("ADMIN_IDS", "")

        ROUTER_BASE_URL: str = os.getenv("ROUTER_BASE_URL", "https://api.openai.com/v1")
        ROUTER_INTERNAL_BASE_URL: str = os.getenv("ROUTER_INTERNAL_BASE_URL", "")
        ROUTER_API_KEY: str = os.getenv("ROUTER_API_KEY", "")
        ROUTER_MODEL: str = os.getenv("ROUTER_MODEL", "Hermes-3-Llama-3.1-8B")
        ROUTER_FAST_MODEL: str = os.getenv("ROUTER_FAST_MODEL", "Hermes-3-Llama-3.1-8B")

        HERMES_ENDPOINT: str = os.getenv("HERMES_ENDPOINT", "")
        HERMES_API_KEY: str = os.getenv("HERMES_API_KEY", "")

        TAVILY_API_KEYS: str = os.getenv("TAVILY_API_KEYS", "")
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
        return uid in _ADMIN_IDS or (settings.ADMIN_ID > 0 and uid == settings.ADMIN_ID)
    except (ValueError, TypeError):
        return False


def get_effective_router_url() -> str:
    """Selects the best available API endpoint."""
    if settings.HERMES_ENDPOINT:
        return settings.HERMES_ENDPOINT.rstrip("/")
    if settings.ROUTER_INTERNAL_BASE_URL:
        return settings.ROUTER_INTERNAL_BASE_URL.rstrip("/")
    return settings.ROUTER_BASE_URL.rstrip("/")


def get_effective_api_key() -> str:
    """Returns the effective API key for LLM requests."""
    return settings.HERMES_API_KEY or settings.ROUTER_API_KEY or os.getenv("ROUTER_API_KEY", "")


def get_effective_model() -> str:
    """Returns the effective LLM model name."""
    return os.getenv("ROUTER_MODEL") or settings.ROUTER_MODEL or "Hermes-3-Llama-3.1-8B"
