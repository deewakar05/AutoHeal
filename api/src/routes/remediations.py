"""Read-only remediation visibility, history, status, and policy routes.

Note on manual remediation execution:
This control plane API does not expose a manual `POST` remediation trigger endpoint
because the existing FastAPI service has no authentication or authorization layer.
Exposing an unauthenticated infrastructure-mutating endpoint would violate least-privilege
security controls.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Path, Query

from remediation.src.config import RemediationSettings
from remediation.src.database import format_utc
from remediation.src.models import RemediationExecution, RemediationStatus
from remediation.src.repository import RemediationRepository, sanitize_execution_text

from ..config import get_settings, load_remediation_settings_safe
from ..database import ensure_database
from ..schemas.remediation import (
    RemediationExecutionResponse,
    RemediationListResponse,
    RemediationPolicyResponse,
    RemediationStatusResponse,
)

router = APIRouter(prefix="/api/v1/remediations", tags=["remediations"])


def _load_remediation_settings() -> tuple[str, RemediationSettings]:
    db_path = get_settings().autoheal_db_path
    return db_path, load_remediation_settings_safe(db_path)


def _to_response(item: RemediationExecution) -> RemediationExecutionResponse:
    return RemediationExecutionResponse(
        id=item.id,
        incident_id=item.incident_id,
        service_name=item.service_name,
        action=item.action,
        status=item.status.value,
        attempt_number=item.attempt_number,
        started_at=format_utc(item.started_at) if item.started_at is not None else None,
        completed_at=format_utc(item.completed_at) if item.completed_at is not None else None,
        duration_seconds=item.duration_seconds,
        ansible_exit_code=item.ansible_exit_code,
        execution_output=sanitize_execution_text(item.execution_output),
        failure_reason=sanitize_execution_text(item.failure_reason, max_length=1000),
        dry_run=item.dry_run,
        created_at=format_utc(item.created_at),
    )


@router.get("/status", response_model=RemediationStatusResponse)
def get_remediation_status() -> RemediationStatusResponse:
    """Return aggregate remediation activity counts and enabled state."""
    db_path, rem_settings = _load_remediation_settings()
    ensure_database(db_path)
    repo = RemediationRepository(db_path)
    summary = repo.get_status_summary(max_attempts=rem_settings.autoheal_remediation_max_attempts)
    return RemediationStatusResponse(
        remediation_enabled=rem_settings.autoheal_remediation_enabled,
        dry_run=rem_settings.autoheal_remediation_dry_run,
        dispatch_mode=rem_settings.autoheal_remediation_dispatch_mode,
        active_executions=summary["active_executions"],
        pending_executions=summary["pending_executions"],
        running_executions=summary["running_executions"],
        total_attempts=summary["total_attempts"],
        successful_attempts=summary["successful_attempts"],
        failed_attempts=summary["failed_attempts"],
        timed_out_attempts=summary["timed_out_attempts"],
        dry_run_attempts=summary["dry_run_attempts"],
        exhausted_incidents=summary["exhausted_incidents"],
        currently_allowed_services=list(rem_settings.autoheal_allowed_services),
        currently_allowed_actions=list(rem_settings.autoheal_allowed_actions),
    )


@router.get("/policies", response_model=RemediationPolicyResponse)
def get_remediation_policies() -> RemediationPolicyResponse:
    """Return safe, non-secret remediation policy rules and thresholds."""
    _db_path, rem_settings = _load_remediation_settings()
    return RemediationPolicyResponse(
        remediation_enabled=rem_settings.autoheal_remediation_enabled,
        dry_run=rem_settings.autoheal_remediation_dry_run,
        cooldown_seconds=rem_settings.autoheal_remediation_cooldown_seconds,
        max_attempts=rem_settings.autoheal_remediation_max_attempts,
        timeout_seconds=rem_settings.autoheal_remediation_timeout_seconds,
        stale_timeout_seconds=rem_settings.autoheal_remediation_stale_timeout_seconds,
        verify_interval_seconds=rem_settings.autoheal_remediation_verify_interval,
        verify_attempts=rem_settings.autoheal_remediation_verify_attempts,
        verify_required_successes=rem_settings.autoheal_remediation_verify_required_successes,
        allowed_services=list(rem_settings.autoheal_allowed_services),
        allowed_actions=list(rem_settings.autoheal_allowed_actions),
        approved_playbooks=list(rem_settings.autoheal_remediation_approved_playbooks),
        manual_execution_endpoint_enabled=False,
        manual_execution_policy_note=(
            "Manual remediation trigger endpoint is intentionally omitted because no "
            "authentication/authorization middleware is configured on this API."
        ),
    )


@router.get("", response_model=RemediationListResponse)
def list_remediations(
    incident_id: int | None = Query(default=None, ge=1, description="Filter by incident ID"),
    service_name: str | None = Query(default=None, description="Filter by service name"),
    status: RemediationStatus | None = Query(
        default=None, description="Filter by remediation execution status"
    ),
    dry_run: bool | None = Query(default=None, description="Filter by dry-run flag"),
    started_after: datetime | None = Query(
        default=None, description="ISO-8601 lower bound on execution timestamp"
    ),
    started_before: datetime | None = Query(
        default=None, description="ISO-8601 upper bound on execution timestamp"
    ),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum items to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset"),
) -> RemediationListResponse:
    """List paginated remediation execution history ordered newest first."""
    if started_after is not None and started_before is not None and started_after > started_before:
        raise HTTPException(
            status_code=422,
            detail="started_after must be less than or equal to started_before",
        )

    db_path, _rem_settings = _load_remediation_settings()
    ensure_database(db_path)
    repo = RemediationRepository(db_path)

    total = repo.count_executions(
        incident_id=incident_id,
        service_name=service_name,
        status=status,
        dry_run=dry_run,
        started_after=started_after,
        started_before=started_before,
    )
    items = repo.list_executions(
        incident_id=incident_id,
        service_name=service_name,
        status=status,
        dry_run=dry_run,
        started_after=started_after,
        started_before=started_before,
        limit=limit,
        offset=offset,
    )
    return RemediationListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=[_to_response(item) for item in items],
    )


@router.get("/{execution_id}", response_model=RemediationExecutionResponse)
def get_remediation(
    execution_id: int = Path(..., ge=1, description="Remediation execution ID"),
) -> RemediationExecutionResponse:
    """Return full sanitized details of a single remediation execution."""
    db_path, _rem_settings = _load_remediation_settings()
    ensure_database(db_path)
    repo = RemediationRepository(db_path)
    execution = repo.get_execution(execution_id)
    if execution is None:
        raise HTTPException(
            status_code=404,
            detail=f"Remediation execution {execution_id} not found",
        )
    return _to_response(execution)
