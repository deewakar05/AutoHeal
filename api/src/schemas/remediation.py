"""Pydantic response schemas for read-only FastAPI remediation visibility endpoints."""

from __future__ import annotations

from pydantic import BaseModel


class RemediationExecutionResponse(BaseModel):
    """Safe, sanitized view of a persisted remediation execution record."""

    id: int
    incident_id: int
    service_name: str
    action: str
    status: str
    attempt_number: int
    started_at: str | None = None
    completed_at: str | None = None
    duration_seconds: float | None = None
    ansible_exit_code: int | None = None
    execution_output: str | None = None
    failure_reason: str | None = None
    dry_run: bool
    created_at: str


class RemediationListResponse(BaseModel):
    """Paginated and filtered remediation execution history response."""

    total: int
    limit: int
    offset: int
    items: list[RemediationExecutionResponse]


class RemediationStatusResponse(BaseModel):
    """Operational summary of remediation state, active jobs, and attempt totals."""

    remediation_enabled: bool
    dry_run: bool
    dispatch_mode: str
    active_executions: int
    pending_executions: int
    running_executions: int
    total_attempts: int
    successful_attempts: int
    failed_attempts: int
    timed_out_attempts: int
    dry_run_attempts: int
    exhausted_incidents: int
    currently_allowed_services: list[str]
    currently_allowed_actions: list[str]


class RemediationPolicyResponse(BaseModel):
    """Non-secret policy constraints governing automated remediation eligibility."""

    remediation_enabled: bool
    dry_run: bool
    cooldown_seconds: int
    max_attempts: int
    timeout_seconds: float
    stale_timeout_seconds: float
    verify_interval_seconds: float
    verify_attempts: int
    verify_required_successes: int
    allowed_services: list[str]
    allowed_actions: list[str]
    approved_playbooks: list[str]
    manual_execution_endpoint_enabled: bool = False
    manual_execution_policy_note: str
