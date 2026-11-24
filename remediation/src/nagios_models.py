"""Typed Pydantic and domain models for Nagios Core alert ingestion and status."""

from __future__ import annotations

import hashlib
import math
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from .config import SAFE_IDENTIFIER_RE
from .database import ensure_utc, format_utc
from .repository import sanitize_execution_text

NAGIOS_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
NAGIOS_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,128}$")
NAGIOS_NUM_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

VALID_HOST_STATES = frozenset({"UP", "DOWN", "UNREACHABLE"})
VALID_SERVICE_STATES = frozenset({"OK", "WARNING", "CRITICAL", "UNKNOWN"})
CRITICAL_STATES = frozenset({"CRITICAL", "DOWN", "UNREACHABLE"})
RECOVERY_STATES = frozenset({"OK", "UP"})
VALID_STATE_TYPES = frozenset({"HARD", "SOFT"})
VALID_NOTIFICATION_TYPES = frozenset(
    {
        "PROBLEM",
        "RECOVERY",
        "FLAPPINGSTART",
        "FLAPPINGSTOP",
        "FLAPPINGDISABLED",
        "DOWNTIMESTART",
        "DOWNTIMEEND",
        "DOWNTIMECANCELLED",
        "ACKNOWLEDGEMENT",
        "CUSTOM",
    }
)


class NagiosProcessingOutcome(str, Enum):
    """Bounded outcome labels persisted for Nagios event auditing and Prometheus."""

    REMEDIATION_QUEUED = "remediation_queued"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_RESOLVED = "incident_resolved"
    DEFERRED_ACTIVE_REMEDIATION = "deferred_active_remediation"
    FLAPPING_MARKED = "flapping_marked"
    FLAPPING_CLEARED = "flapping_cleared"
    IGNORED_SOFT_STATE = "ignored_soft_state"
    IGNORED_NON_CRITICAL = "ignored_non_critical"
    IGNORED_NO_OPEN_INCIDENT = "ignored_no_open_incident"
    IGNORED_STALE_RECOVERY = "ignored_stale_recovery"
    DUPLICATE = "duplicate"


DEFAULT_NAGIOS_SERVICE_MAP: dict[str, str] = {
    "autoheal-web:*": "web",
    "web:*": "web",
    "autoheal-api:*": "api",
    "api:*": "api",
    "autoheal-prometheus:*": "prometheus",
    "prometheus:*": "prometheus",
    "autoheal-alertmanager:*": "alertmanager",
    "alertmanager:*": "alertmanager",
    "autoheal-grafana:*": "grafana",
    "grafana:*": "grafana",
    "autoheal-nagios:*": "nagios",
    "nagios:*": "nagios",
    "autoheal-nrpe-agent:*": "nrpe-agent",
    "nrpe-agent:*": "nrpe-agent",
}


def parse_nagios_service_map(raw: str | dict[str, str] | None) -> dict[str, str]:
    """Parse server-side Nagios host/service mapping overrides cleanly and fail closed."""
    merged = dict(DEFAULT_NAGIOS_SERVICE_MAP)
    if raw is None:
        return merged

    if isinstance(raw, dict):
        items = list(raw.items())
    elif isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            return merged
        items = []
        for entry in cleaned.split(","):
            part = entry.strip()
            if not part:
                continue
            if "=" not in part:
                raise ValueError(f"Invalid Nagios service map entry {part!r}; expected key=service")
            key, target = part.split("=", 1)
            items.append((key, target))
    else:
        raise ValueError("AUTOHEAL_NAGIOS_SERVICE_MAP must be a mapping or comma-separated string")

    for raw_key, raw_target in items:
        key = str(raw_key).strip().lower()
        target = str(raw_target).strip().lower()
        if not key or not SAFE_IDENTIFIER_RE.fullmatch(target):
            raise ValueError(
                f"Invalid Nagios service map entry {raw_key!r}={raw_target!r}"
            )
        merged[key] = target
    return merged


def _strip_control_chars(value: str) -> str:
    """Strip unsafe ASCII control characters while keeping tabs and newlines."""
    return "".join(
        ch for ch in value if ch in {"\n", "\t"} or (ord(ch) >= 32 and ord(ch) != 127)
    )


class NagiosAlertEvent(BaseModel):
    """Validated inbound Nagios host or service notification payload."""

    notification_kind: Literal["host", "service"] | None = Field(default=None)
    notification_type: str = Field(..., min_length=1, max_length=32)
    host_name: str = Field(..., min_length=1, max_length=128)
    service_name: str | None = Field(default=None, max_length=128)
    target_service: str | None = Field(default=None, max_length=64)
    state: str = Field(..., min_length=1, max_length=32)
    state_type: str = Field(default="HARD", min_length=1, max_length=16)
    attempt: int = Field(default=1, ge=1, le=1000)
    max_attempts: int = Field(default=3, ge=1, le=1000)
    output: str = Field(default="", max_length=4000)
    event_timestamp: datetime
    event_id: str | None = Field(default=None, max_length=128)
    nagios_problem_id: str | None = Field(default=None, max_length=64)
    nagios_notification_id: str | None = Field(default=None, max_length=64)
    flapping: bool = Field(default=False)

    @field_validator("notification_kind", mode="before")
    @classmethod
    def normalize_kind(cls, value: object) -> str | None:
        """Normalize optional notification kind casing."""
        if value is None:
            return None
        cleaned = str(value).strip().lower()
        if not cleaned:
            return None
        return cleaned

    @field_validator("notification_type", mode="before")
    @classmethod
    def validate_notification_type(cls, value: object) -> str:
        """Validate against Nagios notification types."""
        cleaned = str(value).strip().upper()
        if cleaned not in VALID_NOTIFICATION_TYPES:
            raise ValueError(
                f"Unsupported Nagios notification_type {value!r}; expected one of "
                f"{sorted(VALID_NOTIFICATION_TYPES)}"
            )
        return cleaned

    @field_validator("host_name")
    @classmethod
    def validate_host_name(cls, value: str) -> str:
        """Normalize and constrain host names to safe identifier characters."""
        cleaned = value.strip().lower()
        if not NAGIOS_HOST_RE.fullmatch(cleaned):
            raise ValueError(f"Invalid Nagios host_name: {value!r}")
        return cleaned

    @field_validator("service_name", mode="before")
    @classmethod
    def sanitize_service_name(cls, value: object) -> str | None:
        """Clean optional Nagios service description."""
        if value is None:
            return None
        cleaned = _strip_control_chars(str(value).replace("\x00", "")).strip()
        if not cleaned:
            return None
        if len(cleaned) > 128:
            cleaned = cleaned[:128]
        return cleaned

    @field_validator("target_service", mode="before")
    @classmethod
    def validate_target_service(cls, value: object) -> str | None:
        """Validate optional target service hint against safe identifier syntax."""
        if value is None:
            return None
        cleaned = str(value).strip().lower()
        if not cleaned:
            return None
        if not SAFE_IDENTIFIER_RE.fullmatch(cleaned):
            raise ValueError(f"Invalid target_service: {value!r}")
        return cleaned

    @field_validator("state", mode="before")
    @classmethod
    def normalize_state(cls, value: object) -> str:
        """Normalize Nagios host/service state token."""
        cleaned = str(value).strip().upper()
        if cleaned not in (VALID_HOST_STATES | VALID_SERVICE_STATES):
            raise ValueError(f"Unsupported Nagios state: {value!r}")
        return cleaned

    @field_validator("state_type", mode="before")
    @classmethod
    def validate_state_type(cls, value: object) -> str:
        """Ensure Nagios state_type is HARD or SOFT."""
        cleaned = str(value).strip().upper()
        if cleaned not in VALID_STATE_TYPES:
            raise ValueError(f"Invalid state_type {value!r}; must be HARD or SOFT")
        return cleaned

    @field_validator("output", mode="before")
    @classmethod
    def sanitize_output(cls, value: object) -> str:
        """Mask embedded secrets, strip control chars, and cap output length."""
        if value is None:
            return ""
        cleaned = _strip_control_chars(str(value).replace("\x00", ""))
        sanitized = sanitize_execution_text(cleaned, max_length=2000)
        return sanitized or ""

    @field_validator("event_timestamp", mode="before")
    @classmethod
    def parse_event_timestamp(cls, value: object) -> datetime:
        """Accept Nagios Unix epoch seconds or ISO-8601 datetime strings."""
        if isinstance(value, bool) or value is None:
            raise ValueError("event_timestamp must be an ISO-8601 string or Unix epoch seconds")
        if isinstance(value, (int, float)):
            num = float(value)
            if not math.isfinite(num) or num <= 0:
                raise ValueError("Unix epoch event_timestamp must be finite and > 0")
            return datetime.fromtimestamp(num, tz=timezone.utc)
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                raise ValueError("event_timestamp must not be empty")
            if stripped.isdigit():
                num = float(int(stripped))
                if num <= 0:
                    raise ValueError("Unix epoch event_timestamp must be > 0")
                return datetime.fromtimestamp(num, tz=timezone.utc)
            try:
                parsed = datetime.fromisoformat(stripped.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"Invalid event_timestamp format: {value!r}") from exc
            return ensure_utc(parsed)
        if isinstance(value, datetime):
            return ensure_utc(value)
        raise ValueError(f"Unsupported event_timestamp type: {type(value).__name__}")

    @field_validator("event_id", mode="before")
    @classmethod
    def validate_event_id(cls, value: object) -> str | None:
        """Validate optional idempotency event_id."""
        if value is None:
            return None
        cleaned = str(value).strip()
        if not cleaned:
            return None
        if not NAGIOS_EVENT_ID_RE.fullmatch(cleaned):
            raise ValueError(f"Invalid event_id: {value!r}")
        return cleaned

    @field_validator("nagios_problem_id", "nagios_notification_id", mode="before")
    @classmethod
    def validate_nagios_id(cls, value: object) -> str | None:
        """Normalize Nagios numeric/string IDs while treating '0' as unset."""
        if value is None:
            return None
        cleaned = str(value).strip()
        if not cleaned or cleaned == "0":
            return None
        if not NAGIOS_NUM_ID_RE.fullmatch(cleaned):
            raise ValueError(f"Invalid Nagios identifier: {value!r}")
        return cleaned

    @model_validator(mode="after")
    def validate_kind_and_state_consistency(self) -> NagiosAlertEvent:
        """Infer notification_kind when omitted and verify state matches kind."""
        if self.notification_kind is None:
            self.notification_kind = "service" if self.service_name else "host"

        if self.notification_kind == "service":
            if not self.service_name:
                raise ValueError("service_name is required when notification_kind='service'")
            if self.state not in VALID_SERVICE_STATES:
                raise ValueError(
                    f"Service notification state {self.state!r} must be one of "
                    f"{sorted(VALID_SERVICE_STATES)}"
                )
        else:
            if self.state not in VALID_HOST_STATES:
                raise ValueError(
                    f"Host notification state {self.state!r} must be one of "
                    f"{sorted(VALID_HOST_STATES)}"
                )
        return self

    def compute_dedup_key(self) -> str:
        """Compute deterministic SHA-256 deduplication key for Nagios retry idempotency."""
        svc_part = (self.service_name or "").lower()
        kind = self.notification_kind or "host"
        if self.event_id:
            raw = f"event_id|{kind}|{self.host_name}|{svc_part}|{self.event_id}"
        elif self.nagios_notification_id:
            raw = (
                f"notif|{kind}|{self.notification_type}|{self.host_name}|{svc_part}|"
                f"{self.state}|{self.state_type}|{self.nagios_notification_id}|"
                f"{self.nagios_problem_id or ''}|{int(self.event_timestamp.timestamp())}"
            )
        else:
            raw = (
                f"payload|{kind}|{self.notification_type}|{self.host_name}|{svc_part}|"
                f"{self.state}|{self.state_type}|{self.attempt}|"
                f"{self.nagios_problem_id or ''}|{format_utc(self.event_timestamp)}"
            )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def resolve_mapped_service(
    event: NagiosAlertEvent,
    service_map: dict[str, str],
) -> str:
    """Resolve Nagios host/service pair deterministically to an AutoHeal service identifier."""
    host_lower = event.host_name.lower()
    svc_lower = (event.service_name or "").lower()

    if svc_lower:
        exact_key = f"{host_lower}:{svc_lower}"
        if exact_key in service_map:
            return service_map[exact_key]
    else:
        host_key = f"{host_lower}:host"
        if host_key in service_map:
            return service_map[host_key]

    wildcard_key = f"{host_lower}:*"
    if wildcard_key in service_map:
        return service_map[wildcard_key]

    if event.target_service:
        return event.target_service

    candidate = host_lower.removeprefix("autoheal-")
    if SAFE_IDENTIFIER_RE.fullmatch(candidate):
        return candidate
    if SAFE_IDENTIFIER_RE.fullmatch(host_lower):
        return host_lower
    raise ValueError(f"Could not map Nagios host {event.host_name!r} to a safe service identifier")


class NagiosAlertOutcome(BaseModel):
    """Structured result returned after atomic Nagios alert processing."""

    accepted: bool = True
    duplicate: bool = False
    outcome: NagiosProcessingOutcome
    dedup_key: str
    mapped_service: str
    incident_id: int | None = None
    incident_created: bool = False
    incident_resolved: bool = False
    remediation_queued: bool = False
    execution_id: int | None = None
    dry_run: bool | None = None
    policy_reason: str | None = None
    details: str = ""
