"""Configuration validation and safe defaults for the remediation policy engine."""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import lru_cache
from typing import Annotated

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .models import RemediationAction

SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
FORBIDDEN_SERVICE_TOKENS = frozenset({"all", "any", "none"})
ALLOWED_ACTION_NAMES = frozenset(action.value for action in RemediationAction)


def _reject_boolean(value: object, field_name: str) -> None:
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be a numeric value, not a boolean")


def _parse_allowlist(raw: object, *, field_name: str) -> list[str]:
    """Normalize a comma-separated string or sequence into ordered unique lowercase tokens."""
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            raise ValueError(f"{field_name} must not be empty")
        tokens = [part.strip().lower() for part in stripped.split(",")]
    elif isinstance(raw, Iterable) and not isinstance(raw, (bytes, bytearray, dict)):
        tokens = []
        for item in raw:
            if not isinstance(item, str):
                raise ValueError(f"{field_name} entries must be strings")
            tokens.append(item.strip().lower())
        if not tokens:
            raise ValueError(f"{field_name} must not be empty")
    else:
        raise ValueError(f"{field_name} must be a comma-separated string or sequence")

    if any(not token for token in tokens):
        raise ValueError(f"{field_name} must not contain empty entries")

    # Preserve configured order while removing exact duplicates.
    return list(dict.fromkeys(tokens))


class RemediationSettings(BaseSettings):
    """Validated settings for automated remediation policies with safe defaults."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    autoheal_remediation_enabled: bool = Field(default=False)
    autoheal_remediation_dry_run: bool = Field(default=True)
    autoheal_remediation_cooldown_seconds: int = Field(default=300)
    autoheal_remediation_max_attempts: int = Field(default=3)
    autoheal_remediation_timeout_seconds: float = Field(default=120.0)
    autoheal_allowed_services: Annotated[tuple[str, ...], NoDecode] = Field(default=("web",))
    autoheal_allowed_actions: Annotated[tuple[str, ...], NoDecode] = Field(default=("restart",))
    autoheal_remediation_verify_interval: float = Field(default=5.0)
    autoheal_remediation_verify_attempts: int = Field(default=6)

    @field_validator(
        "autoheal_remediation_cooldown_seconds",
        "autoheal_remediation_max_attempts",
        "autoheal_remediation_timeout_seconds",
        "autoheal_remediation_verify_interval",
        "autoheal_remediation_verify_attempts",
        mode="before",
    )
    @classmethod
    def reject_booleans_in_numeric_fields(cls, value: object, info) -> object:
        """Prevent accidental boolean coercion into integer/float limits."""
        _reject_boolean(value, info.field_name)
        return value

    @field_validator("autoheal_remediation_cooldown_seconds")
    @classmethod
    def validate_cooldown(cls, value: int) -> int:
        """Ensure cooldown duration is non-negative."""
        if value < 0:
            raise ValueError("AUTOHEAL_REMEDIATION_COOLDOWN_SECONDS must be >= 0")
        return value

    @field_validator("autoheal_remediation_max_attempts", "autoheal_remediation_verify_attempts")
    @classmethod
    def validate_positive_count(cls, value: int, info) -> int:
        """Ensure attempt counters are at least 1."""
        if value < 1:
            raise ValueError(f"{info.field_name.upper()} must be >= 1")
        return value

    @field_validator("autoheal_remediation_timeout_seconds", "autoheal_remediation_verify_interval")
    @classmethod
    def validate_positive_duration(cls, value: float, info) -> float:
        """Ensure timeout and verification interval durations are strictly greater than 0."""
        if value <= 0:
            raise ValueError(f"{info.field_name.upper()} must be greater than 0")
        return float(value)

    @field_validator("autoheal_allowed_services", mode="before")
    @classmethod
    def validate_allowed_services(cls, value: object) -> tuple[str, ...]:
        """Parse and strictly validate service names against safe identifier rules."""
        tokens = _parse_allowlist(value, field_name="AUTOHEAL_ALLOWED_SERVICES")
        for service in tokens:
            if service in FORBIDDEN_SERVICE_TOKENS or not SAFE_IDENTIFIER_RE.fullmatch(service):
                raise ValueError(
                    f"Unsafe or invalid service name in AUTOHEAL_ALLOWED_SERVICES: {service!r}"
                )
        return tuple(tokens)

    @field_validator("autoheal_allowed_actions", mode="before")
    @classmethod
    def validate_allowed_actions(cls, value: object) -> tuple[str, ...]:
        """Parse and restrict allowed actions to finite approved remediation actions."""
        tokens = _parse_allowlist(value, field_name="AUTOHEAL_ALLOWED_ACTIONS")
        for action in tokens:
            if action not in ALLOWED_ACTION_NAMES:
                raise ValueError(
                    f"Unsupported or unsafe action in AUTOHEAL_ALLOWED_ACTIONS: {action!r} "
                    f"(allowed: {sorted(ALLOWED_ACTION_NAMES)})"
                )
        return tuple(tokens)


@lru_cache
def get_settings() -> RemediationSettings:
    """Return cached remediation settings loaded from environment variables."""
    return RemediationSettings()


def clear_settings_cache() -> None:
    """Reset cached remediation settings (useful in automated tests)."""
    get_settings.cache_clear()

