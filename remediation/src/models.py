"""Typed domain models, enums, and protocols for the AutoHeal remediation policy engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol, runtime_checkable


class IncidentStatus(str, Enum):
    """Lifecycle status values for recorded infrastructure incidents."""

    OPEN = "open"
    RESOLVED = "resolved"


class ServiceState(str, Enum):
    """High-level operational health states for monitored services."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class CheckOutcome(str, Enum):
    """Categorized results from an individual health check probe."""

    SUCCESS = "success"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"
    UNHEALTHY_PAYLOAD = "unhealthy_payload"


@dataclass
class HealthCheckResult:
    """Detailed result payload produced by a health checker probe."""

    service_name: str
    target_url: str
    healthy: bool
    outcome: CheckOutcome
    status_code: int | None
    response_time_ms: float
    checked_at: datetime
    error: str | None = None


@dataclass
class IncidentRecord:
    """Full database representation of an incident record."""

    id: int
    service_name: str
    status: IncidentStatus | str
    failure_reason: str
    started_at: datetime
    last_seen_at: datetime
    resolved_at: datetime | None = None
    failure_count: int = 1
    source: str = "nagios"
    host_name: str | None = None
    nagios_service_name: str | None = None
    nagios_state: str | None = None
    last_problem_at: str | None = None
    nagios_alert_count: int = 0
    flapping: bool = False


@dataclass(frozen=True)
class ServiceStatusRecord:
    """Persisted status snapshot of a monitored service."""

    service_name: str
    target_url: str
    status: ServiceState
    consecutive_failures: int
    consecutive_successes: int
    last_checked_at: datetime | None = None
    last_status_change_at: datetime | None = None
    last_http_status: int | None = None
    last_response_time_ms: float | None = None
    last_error: str | None = None
    active_incident_id: int | None = None


@dataclass
class StateEvaluation:
    """Result of evaluating service health against threshold rules."""

    previous_state: ServiceState
    current_state: ServiceState
    state_changed: bool
    incident_created: IncidentRecord | None = None
    incident_resolved: IncidentRecord | None = None
    active_incident: IncidentRecord | None = None
    status_record: ServiceStatusRecord | None = None
    consecutive_failures: int = 0
    consecutive_successes: int = 0


class RemediationStatus(str, Enum):
    """Lifecycle status values persisted for remediation execution records."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    DRY_RUN = "dry_run"


ACTIVE_REMEDIATION_STATUSES = frozenset({RemediationStatus.PENDING, RemediationStatus.RUNNING})
TERMINAL_REMEDIATION_STATUSES = frozenset(
    {
        RemediationStatus.SUCCEEDED,
        RemediationStatus.FAILED,
        RemediationStatus.TIMED_OUT,
        RemediationStatus.DRY_RUN,
    }
)


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
class RemediationExecution:
    """Persisted remediation execution audit and state record."""

    id: int
    incident_id: int
    service_name: str
    action: str
    status: RemediationStatus
    attempt_number: int
    started_at: datetime | None
    completed_at: datetime | None
    duration_seconds: float | None
    ansible_exit_code: int | None
    execution_output: str | None
    failure_reason: str | None
    dry_run: bool
    created_at: datetime


@dataclass(frozen=True)
class RemediationState:
    """Current remediation attempt history and execution lock state for policy checks."""

    attempts: int = 0
    last_attempt_at: datetime | None = None
    is_running: bool = False
    current_execution: RemediationExecution | None = None
    latest_execution: RemediationExecution | None = None
    stale_execution: RemediationExecution | None = None

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


@dataclass(frozen=True)
class ReservationResult:
    """Outcome of an atomic SQLite remediation execution reservation attempt."""

    reserved: bool
    decision: RemediationDecision
    execution: RemediationExecution | None = None
