"""Configuration settings for the AutoHeal FastAPI control plane."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class ApiSettings(BaseSettings):
    """Validated settings for the FastAPI control plane."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    api_port: int = Field(default=8000)
    autoheal_db_path: str = Field(default="/data/autoheal.db")
    monitor_target_service: str = Field(default="web")
    monitor_target_url: str = Field(default="http://web/health")
    monitor_enabled: bool = Field(default=True)
    log_level: str = Field(default="INFO")

    @field_validator("api_port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        if not (1 <= value <= 65535):
            raise ValueError("API_PORT must be between 1 and 65535")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        if normalized not in VALID_LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}")
        return normalized


@lru_cache
def get_settings() -> ApiSettings:
    """Return cached API settings."""
    return ApiSettings()


def clear_settings_cache() -> None:
    """Reset cached API settings for tests."""
    get_settings.cache_clear()

