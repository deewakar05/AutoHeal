"""Configuration validation and safe defaults for the remediation policy engine."""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .models import RemediationAction

SAFE_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
SAFE_REL_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_./-]{0,200}$")
FORBIDDEN_SERVICE_TOKENS = frozenset({"all", "any", "none"})
ALLOWED_ACTION_NAMES = frozenset(action.value for action in RemediationAction)
APPROVED_ANSIBLE_EXECUTABLES = frozenset(
    {"ansible-playbook", "/usr/local/bin/ansible-playbook", "/usr/bin/ansible-playbook"}
)
APPROVED_INVENTORY_PATHS = frozenset({"ansible/inventory.ini"})
APPROVED_CONFIG_PATHS = frozenset({"ansible/ansible.cfg"})
VALID_DISPATCH_MODES = frozenset({"in_process", "queue", "disabled"})
DEFAULT_WORKSPACE_ROOT = str(Path(__file__).resolve().parents[2])


def _validate_safe_relative_path(raw: str, *, field_name: str) -> str:
    """Validate a workspace-relative file path without traversal or shell characters."""
    cleaned = raw.strip().replace("\\", "/")
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty")
    if cleaned.startswith("/") or ".." in Path(cleaned).parts:
        raise ValueError(f"{field_name} must be a relative path without '..' traversal: {raw!r}")
    if not SAFE_REL_PATH_RE.fullmatch(cleaned):
        raise ValueError(f"{field_name} contains disallowed characters: {raw!r}")
    return cleaned


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
    autoheal_remediation_verify_required_successes: int = Field(default=2)
    autoheal_remediation_verify_target_url: str = Field(default="http://web/health")
    autoheal_db_path: str = Field(default="/data/autoheal.db")
    autoheal_remediation_max_concurrency: int = Field(default=1)
    autoheal_remediation_stale_timeout_seconds: float = Field(default=180.0)
    autoheal_remediation_workspace_root: str = Field(default=DEFAULT_WORKSPACE_ROOT)
    autoheal_remediation_approved_playbooks: Annotated[tuple[str, ...], NoDecode] = Field(
        default=("remediation/recover.yml",)
    )
    autoheal_ansible_playbook_path: str = Field(default="remediation/recover.yml")
    autoheal_ansible_inventory_path: str = Field(default="ansible/inventory.ini")
    autoheal_ansible_config_path: str = Field(default="ansible/ansible.cfg")
    autoheal_ansible_executable: str = Field(default="ansible-playbook")
    autoheal_remediation_executor_poll_interval: float = Field(default=1.0)
    autoheal_remediation_executor_heartbeat_path: str = Field(default="/tmp/executor.heartbeat")
    autoheal_remediation_require_isolation: bool = Field(default=True)
    autoheal_remediation_allowed_proxy_host: str = Field(default="docker-socket-proxy")
    autoheal_remediation_allowed_proxy_port: int = Field(default=2375)
    autoheal_remediation_dispatch_mode: str = Field(default="in_process")

    @field_validator("autoheal_db_path", "autoheal_remediation_workspace_root", "autoheal_remediation_executor_heartbeat_path")
    @classmethod
    def validate_non_empty_path(cls, value: str, info) -> str:
        """Ensure configured filesystem paths are non-empty."""
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{info.field_name.upper()} must not be empty")
        return cleaned

    @field_validator("autoheal_remediation_verify_target_url")
    @classmethod
    def validate_verify_target_url(cls, value: str) -> str:
        """Ensure recovery verification target URL is valid HTTP/HTTPS."""
        cleaned = value.strip()
        parsed = urlparse(cleaned)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("AUTOHEAL_REMEDIATION_VERIFY_TARGET_URL must be a valid http or https URL")
        return cleaned

    @field_validator(
        "autoheal_remediation_cooldown_seconds",
        "autoheal_remediation_max_attempts",
        "autoheal_remediation_timeout_seconds",
        "autoheal_remediation_verify_interval",
        "autoheal_remediation_verify_attempts",
        "autoheal_remediation_verify_required_successes",
        "autoheal_remediation_max_concurrency",
        "autoheal_remediation_stale_timeout_seconds",
        "autoheal_remediation_executor_poll_interval",
        "autoheal_remediation_allowed_proxy_port",
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

    @field_validator(
        "autoheal_remediation_max_attempts",
        "autoheal_remediation_verify_attempts",
        "autoheal_remediation_verify_required_successes",
        "autoheal_remediation_max_concurrency",
    )
    @classmethod
    def validate_positive_count(cls, value: int, info) -> int:
        """Ensure positive integer counters are at least 1."""
        if value < 1:
            raise ValueError(f"{info.field_name.upper()} must be >= 1")
        return value

    @field_validator(
        "autoheal_remediation_timeout_seconds",
        "autoheal_remediation_verify_interval",
        "autoheal_remediation_stale_timeout_seconds",
        "autoheal_remediation_executor_poll_interval",
    )
    @classmethod
    def validate_positive_duration(cls, value: float, info) -> float:
        """Ensure duration limits are finite and strictly greater than 0."""
        numeric = float(value)
        if not math.isfinite(numeric) or numeric <= 0:
            raise ValueError(f"{info.field_name.upper()} must be a finite number greater than 0")
        return numeric

    @field_validator("autoheal_remediation_allowed_proxy_host")
    @classmethod
    def validate_allowed_proxy_host(cls, value: str) -> str:
        """Ensure allowed Docker socket proxy hostname is valid and non-empty."""
        cleaned = value.strip().lower()
        if not SAFE_HOSTNAME_RE.fullmatch(cleaned):
            raise ValueError(
                f"AUTOHEAL_REMEDIATION_ALLOWED_PROXY_HOST contains invalid hostname: {value!r}"
            )
        return cleaned

    @field_validator("autoheal_remediation_allowed_proxy_port")
    @classmethod
    def validate_allowed_proxy_port(cls, value: int) -> int:
        """Ensure allowed Docker socket proxy TCP port is in valid TCP range."""
        if not 1 <= value <= 65535:
            raise ValueError("AUTOHEAL_REMEDIATION_ALLOWED_PROXY_PORT must be between 1 and 65535")
        return value

    @field_validator("autoheal_remediation_approved_playbooks", mode="before")
    @classmethod
    def validate_approved_playbooks(cls, value: object) -> tuple[str, ...]:
        """Parse and validate relative allowlisted Ansible playbook paths."""
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("AUTOHEAL_REMEDIATION_APPROVED_PLAYBOOKS must not be empty")
            raw_tokens = [part.strip() for part in stripped.split(",")]
        elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray, dict)):
            raw_tokens = [str(item).strip() for item in value]
            if not raw_tokens:
                raise ValueError("AUTOHEAL_REMEDIATION_APPROVED_PLAYBOOKS must not be empty")
        else:
            raise ValueError("AUTOHEAL_REMEDIATION_APPROVED_PLAYBOOKS must be a list or CSV string")

        normalized: list[str] = []
        for token in raw_tokens:
            safe = _validate_safe_relative_path(
                token, field_name="AUTOHEAL_REMEDIATION_APPROVED_PLAYBOOKS"
            )
            if not safe.endswith((".yml", ".yaml")):
                raise ValueError(f"Playbook path must end with .yml or .yaml: {safe!r}")
            normalized.append(safe)
        return tuple(dict.fromkeys(normalized))

    @field_validator("autoheal_ansible_playbook_path")
    @classmethod
    def validate_ansible_playbook_rel_path(cls, value: str) -> str:
        """Ensure Ansible playbook path stays relative without traversal."""
        return _validate_safe_relative_path(value, field_name="AUTOHEAL_ANSIBLE_PLAYBOOK_PATH")

    @field_validator("autoheal_ansible_inventory_path")
    @classmethod
    def validate_ansible_inventory_path(cls, value: str) -> str:
        """Restrict Ansible inventory strictly to the fixed approved inventory path."""
        cleaned = _validate_safe_relative_path(value, field_name="AUTOHEAL_ANSIBLE_INVENTORY_PATH")
        if cleaned not in APPROVED_INVENTORY_PATHS:
            raise ValueError(
                f"AUTOHEAL_ANSIBLE_INVENTORY_PATH must be one of {sorted(APPROVED_INVENTORY_PATHS)}"
            )
        return cleaned

    @field_validator("autoheal_ansible_config_path")
    @classmethod
    def validate_ansible_config_path(cls, value: str) -> str:
        """Restrict Ansible config strictly to the fixed approved configuration path."""
        cleaned = _validate_safe_relative_path(value, field_name="AUTOHEAL_ANSIBLE_CONFIG_PATH")
        if cleaned not in APPROVED_CONFIG_PATHS:
            raise ValueError(
                f"AUTOHEAL_ANSIBLE_CONFIG_PATH must be one of {sorted(APPROVED_CONFIG_PATHS)}"
            )
        return cleaned

    @field_validator("autoheal_ansible_executable")
    @classmethod
    def validate_ansible_executable(cls, value: str) -> str:
        """Restrict executable strictly to known ansible-playbook binaries."""
        cleaned = value.strip()
        if cleaned not in APPROVED_ANSIBLE_EXECUTABLES:
            raise ValueError(
                "AUTOHEAL_ANSIBLE_EXECUTABLE must be one of "
                f"{sorted(APPROVED_ANSIBLE_EXECUTABLES)}"
            )
        return cleaned

    @field_validator("autoheal_remediation_dispatch_mode")
    @classmethod
    def validate_dispatch_mode(cls, value: str) -> str:
        """Validate remediation dispatch strategy."""
        normalized = value.strip().lower()
        if normalized not in VALID_DISPATCH_MODES:
            raise ValueError(
                f"AUTOHEAL_REMEDIATION_DISPATCH_MODE must be one of {sorted(VALID_DISPATCH_MODES)}"
            )
        return normalized

    @model_validator(mode="after")
    def validate_playbook_in_allowlist(self) -> RemediationSettings:
        """Ensure the active remediation playbook is listed in the approved allowlist."""
        if self.autoheal_ansible_playbook_path not in self.autoheal_remediation_approved_playbooks:
            raise ValueError(
                f"Playbook {self.autoheal_ansible_playbook_path!r} is not in "
                f"AUTOHEAL_REMEDIATION_APPROVED_PLAYBOOKS={list(self.autoheal_remediation_approved_playbooks)!r}"
            )
        return self

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
