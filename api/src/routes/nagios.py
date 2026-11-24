"""Authenticated Nagios Core webhook ingestion and read-only status routes."""

from __future__ import annotations

import hashlib
import hmac
import logging

from fastapi import APIRouter, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from remediation.src.nagios_models import NagiosAlertEvent
from remediation.src.nagios_service import NagiosAlertService, record_nagios_http_rejection

from ..config import ApiSettings, get_settings, load_remediation_settings_safe
from ..database import ensure_database
from ..schemas.nagios import (
    NagiosAlertResponse,
    NagiosEventItem,
    NagiosEventListResponse,
    NagiosMonitorProbeStatus,
    NagiosStatusResponse,
)

logger = logging.getLogger("control-plane-api")

router = APIRouter(prefix="/api/v1/monitoring/nagios", tags=["nagios"])


def _extract_supplied_token(request: Request) -> str | None:
    for header_name in ("X-Nagios-Token", "X-AutoHeal-Signature", "X-Autoheal-Signature"):
        header_token = request.headers.get(header_name)
        if header_token is not None:
            cleaned = header_token.strip()
            if cleaned:
                return cleaned

    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.strip().split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            cleaned = parts[1].strip()
            if cleaned:
                return cleaned
    return None


def _safe_record_rejection(db_path: str, *, outcome: str) -> None:
    try:
        record_nagios_http_rejection(db_path, outcome=outcome)
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Unable to persist Nagios HTTP rejection metric",
            extra={"event": "nagios_metric_write_error", "error": str(exc)},
        )


def _authorize_nagios_request(
    request: Request,
    settings: ApiSettings,
    *,
    raw_body: bytes | None = None,
) -> None:
    if not settings.autoheal_nagios_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nagios integration is currently disabled.",
        )

    configured_secret = settings.autoheal_nagios_webhook_secret
    if not configured_secret:
        _safe_record_rejection(settings.autoheal_db_path, outcome="auth_unconfigured")
        logger.error(
            "Nagios alert rejected because webhook secret is not configured",
            extra={"event": "nagios_auth_unconfigured"},
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nagios webhook authentication is not configured (fail-closed).",
        )

    supplied = _extract_supplied_token(request)
    if not supplied:
        _safe_record_rejection(settings.autoheal_db_path, outcome="auth_failed")
        logger.warning(
            "Unauthorized Nagios webhook request rejected: missing token/signature",
            extra={"event": "nagios_auth_failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Nagios authentication token.",
        )

    # Constant-time comparison: accept either raw shared secret or HMAC-SHA256 hex digest
    token_valid = hmac.compare_digest(
        supplied.encode("utf-8"),
        configured_secret.encode("utf-8"),
    )
    if not token_valid and raw_body is not None:
        computed_hex = hmac.new(
            configured_secret.encode("utf-8"),
            raw_body,
            hashlib.sha256,
        ).hexdigest()
        cleaned_supplied = (
            supplied[7:] if supplied.lower().startswith("sha256=") else supplied
        )
        token_valid = hmac.compare_digest(
            cleaned_supplied.encode("utf-8"),
            computed_hex.encode("utf-8"),
        )

    if not token_valid:
        _safe_record_rejection(settings.autoheal_db_path, outcome="auth_failed")
        logger.warning(
            "Unauthorized Nagios webhook request rejected: invalid token/signature",
            extra={"event": "nagios_auth_failed"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing Nagios authentication token.",
        )


@router.post(
    "/alerts",
    response_model=NagiosAlertResponse,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": NagiosAlertEvent.model_json_schema(),
                }
            },
        }
    },
)
@router.post(
    "/alert",
    response_model=NagiosAlertResponse,
    include_in_schema=False,
)
async def ingest_nagios_alert(request: Request) -> NagiosAlertResponse:
    """Authenticate, validate, deduplicate, and ingest a Nagios notification event."""
    settings = get_settings()
    raw_body = await request.body()
    _authorize_nagios_request(request, settings, raw_body=raw_body)

    try:
        raw_payload = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid JSON request body.",
        ) from exc

    try:
        payload = NagiosAlertEvent.model_validate(raw_payload)
    except ValidationError as exc:
        raise RequestValidationError(exc.errors()) from exc

    def _process() -> NagiosAlertResponse:
        ensure_database(settings.autoheal_db_path)
        remediation_settings = load_remediation_settings_safe(settings.autoheal_db_path)
        service = NagiosAlertService(
            remediation_settings=remediation_settings,
            service_map=settings.autoheal_nagios_service_map,
        )
        outcome = service.process_alert(payload)
        return NagiosAlertResponse(**outcome.model_dump())

    try:
        return await run_in_threadpool(_process)
    except ValueError as exc:
        _safe_record_rejection(settings.autoheal_db_path, outcome="ingestion_error")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        _safe_record_rejection(settings.autoheal_db_path, outcome="ingestion_error")
        logger.exception(
            "Unexpected error while processing Nagios alert",
            extra={"event": "nagios_ingestion_error", "error": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process Nagios alert.",
        ) from exc


@router.get("/events", response_model=NagiosEventListResponse)
def list_nagios_events(
    limit: int = Query(default=50, ge=1, le=200),
    service: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
) -> NagiosEventListResponse:
    """Return recent persisted Nagios notification events for operational inspection."""
    settings = get_settings()
    ensure_database(settings.autoheal_db_path)
    remediation_settings = load_remediation_settings_safe(settings.autoheal_db_path)
    svc = NagiosAlertService(
        remediation_settings=remediation_settings,
        service_map=settings.autoheal_nagios_service_map,
    )
    rows = svc.list_events(limit=limit, service_name=service, outcome=outcome)
    return NagiosEventListResponse(
        total=len(rows),
        events=[NagiosEventItem(**row) for row in rows],
    )


@router.get("/status", response_model=NagiosStatusResponse)
def get_nagios_status() -> NagiosStatusResponse:
    """Return Nagios integration health, probe status, and event outcome counters."""
    settings = get_settings()
    ensure_database(settings.autoheal_db_path)
    remediation_settings = load_remediation_settings_safe(settings.autoheal_db_path)
    svc = NagiosAlertService(
        remediation_settings=remediation_settings,
        service_map=settings.autoheal_nagios_service_map,
    )
    summary = svc.get_status_summary()
    raw_monitor = summary["monitor_status"]
    monitor_status = (
        NagiosMonitorProbeStatus(
            target_name=str(raw_monitor["target_name"]),
            target_url=str(raw_monitor["target_url"]),
            up=bool(raw_monitor["up"]),
            http_status=raw_monitor["http_status"],
            response_time_ms=raw_monitor["response_time_ms"],
            program_running=bool(raw_monitor["program_running"]),
            last_checked_at=raw_monitor["last_checked_at"],
            last_error=raw_monitor["last_error"],
            updated_at=str(raw_monitor["updated_at"]),
        )
        if raw_monitor is not None
        else None
    )
    return NagiosStatusResponse(
        nagios_enabled=settings.autoheal_nagios_enabled,
        webhook_auth_configured=bool(settings.autoheal_nagios_webhook_secret),
        monitor_status=monitor_status,
        total_events=int(summary["total_events"]),
        events_by_outcome=dict(summary["events_by_outcome"]),
        open_incidents_by_source=dict(summary["open_incidents_by_source"]),
    )
