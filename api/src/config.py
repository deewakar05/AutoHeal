"""Configuration settings for the AutoHeal FastAPI control plane."""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from remediation.src.config import RemediationSettings
from remediation.src.nagios_models import parse_nagios_service_map

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
logger = logging.getLogger("control-plane-api")


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
    autoheal_nagios_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("AUTOHEAL_NAGIOS_ENABLED", "NAGIOS_ENABLED"),
    )
    autoheal_nagios_webhook_secret: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("AUTOHEAL_NAGIOS_WEBHOOK_SECRET", "NAGIOS_WEBHOOK_SECRET"),
    )
    autoheal_nagios_service_map: str = Field(
        default="",
        validation_alias=AliasChoices("AUTOHEAL_NAGIOS_SERVICE_MAP", "NAGIOS_SERVICE_MAP"),
    )

    @field_validator("autoheal_nagios_webhook_secret", mode="before")
    @classmethod
    def clean_nagios_secret(cls, value: object) -> str | None:
        if value is None:
            return None
        cleaned = str(value).strip()
        return cleaned or None

    @field_validator("autoheal_nagios_service_map")
    @classmethod
    def validate_nagios_service_map(cls, value: str) -> str:
        parse_nagios_service_map(value)
        return value.strip()

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


def load_remediation_settings_safe(db_path: str) -> RemediationSettings:
    """Load RemediationSettings, falling back safely to disabled dry-run defaults on error."""
    try:
        return RemediationSettings(autoheal_db_path=db_path)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Invalid remediation settings detected; falling back to disabled dry-run defaults",
            extra={"event": "remediation_settings_fallback", "error": str(exc)},
        )
        try:
            return RemediationSettings(_env_file=None, autoheal_db_path=db_path)
        except Exception:  # noqa: BLE001
            defaults = {
                name: field.default
                for name, field in RemediationSettings.model_fields.items()
                if field.default is not None
            }
            defaults["autoheal_db_path"] = db_path
            defaults["autoheal_remediation_enabled"] = False
            defaults["autoheal_remediation_dry_run"] = True
            return RemediationSettings.model_construct(**defaults)
