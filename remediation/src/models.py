"""Typed domain models, enums, and protocols for the AutoHeal remediation policy engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable


class RemediationAction(str, Enum):
    """Finite set of safe container remediation actions recognized by AutoHeal."""

    RESTART = "restart"
    START = "start"


class PolicyReason(str, Enum):
    """Structured reason codes returned by policy evaluation."""

    REMEDIATION_DISABLED = "REMEDIATION_DISABLED"
    INCIDENT_NOT_FOUND = "INCIDENT_NOT_FOUND"
    INCIDENT_ALREADY_RESOLVED = "INCIDENT_ALREADY_RESOLVED"
    SERVICE_NOT_ALLOWED = "SERVICE_NOT_ALLOWED"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    MAX_ATTEMPTS_REACHED = "MAX_ATTEMPTS_REACHED"
    COOLDOWN_ACTIVE = "COOLDOWN_ACTIVE"
    REMEDIATION_ALREADY_RUNNING = "REMEDIATION_ALREADY_RUNNING"
    POLICY_APPROVED = "POLICY_APPROVED"


@runtime_checkable
class IncidentView(Protocol):
    """Structural interface satisfied by Monitoring `IncidentRecord` and snapshots."""

    @property
    def id(self) -> int: ...

    @property
    def service_name(self) -> str: ...

    @property
    def status(self) -> str: ...


@dataclass(frozen=True)
class IncidentSnapshot:
    """Lightweight immutable incident representation for policy evaluation and testing."""

    id: int
    service_name: str
    status: str
    failure_reason: str | None = None
    failure_count: int = 1
    resolved_at: datetime | None = None


@dataclass(frozen=True)
class RemediationState:
    """Current remediation attempt history and execution lock state for policy checks."""

    attempts: int = 0
    last_attempt_at: datetime | None = None
    is_running: bool = False

    def __post_init__(self) -> None:
        if self.attempts < 0:
            raise ValueError("attempts must be >= 0")


@dataclass(frozen=True)
class RemediationRequest:
    """Proposed remediation action to evaluate against policy gates."""

    incident_id: int
    service_name: str
    action: str | RemediationAction


@dataclass(frozen=True)
class RemediationDecision:
    """Structured outcome produced by `RemediationPolicy.evaluate`."""

    allowed: bool
    reason: PolicyReason
    dry_run: bool
    service_name: str
    action: str
    incident_id: int
    details: str = ""
    cooldown_remaining_seconds: float = 0.0

