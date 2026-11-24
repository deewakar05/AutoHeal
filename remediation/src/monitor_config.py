"""Configuration management and validation for the AutoHeal monitoring engine."""

from __future__ import annotations

import math
from functools import lru_cache
from urllib.parse import urlparse

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

VALID_LOG_LEVELS = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}


class MonitorSettings(BaseSettings):
    """Validated settings for the asynchronous monitoring service."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    monitor_enabled: bool = Field(default=True)
    monitor_target_url: str = Field(default="http://web/health")
    monitor_target_service: str = Field(default="web")
    monitor_interval: float = Field(
        default=5.0,
        validation_alias=AliasChoices("MONITOR_INTERVAL", "MONITOR_INTERVAL_SECONDS"),
    )
    monitor_timeout: float = Field(
        default=3.0,
        validation_alias=AliasChoices("MONITOR_TIMEOUT", "MONITOR_TIMEOUT_SECONDS"),
    )
    monitor_failure_threshold: int = Field(default=3)
    monitor_recovery_threshold: int = Field(default=2)
    autoheal_db_path: str = Field(default="/data/autoheal.db")
    heartbeat_path: str = Field(default="/tmp/monitor.heartbeat")
    log_level: str = Field(default="INFO")
    nagios_monitor_enabled: bool = Field(
        default=False,
        validation_alias=AliasChoices("NAGIOS_MONITOR_ENABLED", "AUTOHEAL_NAGIOS_MONITOR_ENABLED"),
    )
    nagios_status_url: str = Field(
        default="http://nagios:8081/nagios4/cgi-bin/statusjson.cgi?query=programstatus",
        validation_alias=AliasChoices("NAGIOS_STATUS_URL", "AUTOHEAL_NAGIOS_STATUS_URL"),
    )
    nagios_admin_user: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("NAGIOS_ADMIN_USER"),
    )
    nagios_admin_password: str | None = Field(
        default=None,
        repr=False,
        validation_alias=AliasChoices("NAGIOS_ADMIN_PASSWORD"),
    )
    nagios_probe_timeout: float = Field(
        default=3.0,
        validation_alias=AliasChoices("NAGIOS_PROBE_TIMEOUT"),
    )

    @field_validator("nagios_status_url")
    @classmethod
    def validate_nagios_status_url(cls, value: str) -> str:
        """Ensure optional Nagios status CGI URL is valid http/https."""
        cleaned = value.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("NAGIOS_STATUS_URL must be a valid http or https URL")
        return cleaned

    @field_validator("nagios_probe_timeout", mode="before")
    @classmethod
    def reject_boolean_nagios_timeout(cls, value: object) -> object:
        if isinstance(value, bool):
            raise ValueError("NAGIOS_PROBE_TIMEOUT must be a numeric value, not a boolean")
        return value

    @field_validator("nagios_probe_timeout")
    @classmethod
    def validate_nagios_timeout(cls, value: float) -> float:
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0:
            raise ValueError("NAGIOS_PROBE_TIMEOUT must be finite and greater than 0")
        return numeric

    @field_validator("monitor_target_url")
    @classmethod
    def validate_target_url(cls, value: str) -> str:
        """Ensure the target URL uses http/https and includes a network location."""
        cleaned = value.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("MONITOR_TARGET_URL must be a valid http or https URL")
        return cleaned

    @field_validator("monitor_target_service")
    @classmethod
    def validate_service_name(cls, value: str) -> str:
        """Ensure the monitored service name is non-empty."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("MONITOR_TARGET_SERVICE must not be empty")
        return cleaned

    @field_validator(
        "monitor_interval",
        "monitor_timeout",
        "monitor_failure_threshold",
        "monitor_recovery_threshold",
        mode="before",
    )
    @classmethod
    def reject_booleans_in_numeric_fields(cls, value: object, info) -> object:
        """Prevent booleans from silently coercing to integer or float limits."""
        if isinstance(value, bool):
            raise ValueError(f"{info.field_name.upper()} must be a numeric value, not a boolean")
        return value

    @field_validator("monitor_interval", "monitor_timeout")
    @classmethod
    def validate_positive_float(cls, value: float) -> float:
        """Ensure interval and timeout durations are finite and strictly positive."""
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0:
            raise ValueError("Duration settings must be finite and greater than 0")
        return numeric

    @field_validator("monitor_failure_threshold", "monitor_recovery_threshold")
    @classmethod
    def validate_positive_threshold(cls, value: int) -> int:
        """Ensure failure and recovery thresholds are at least 1."""
        if value < 1:
            raise ValueError("Threshold settings must be at least 1")
        return value

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Ensure log level is a standard Python logging level."""
        normalized = value.strip().upper()
        if normalized not in VALID_LOG_LEVELS:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(VALID_LOG_LEVELS)}")
        return normalized


@lru_cache
def get_settings() -> MonitorSettings:
    """Return cached monitor settings loaded from environment variables."""
    return MonitorSettings()

