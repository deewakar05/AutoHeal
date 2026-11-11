"""Incident history routes."""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from ..config import get_settings
from ..database import ensure_database, get_connection
from ..schemas.incident import IncidentListResponse, IncidentResponse

router = APIRouter(prefix="/api/v1", tags=["incidents"])


def _row_to_response(row) -> IncidentResponse:
    return IncidentResponse(
        id=int(row["id"]),
        service_name=row["service_name"],
        status=row["status"],
        failure_reason=row["failure_reason"],
        started_at=row["started_at"],
        resolved_at=row["resolved_at"],
        last_seen_at=row["last_seen_at"],
        failure_count=int(row["failure_count"]),
    )


@router.get("/incidents", response_model=IncidentListResponse)
def list_incidents(
    status: Literal["open", "resolved"] | None = Query(
        default=None, description="Optional incident status filter"
    ),
    service: str | None = Query(default=None, description="Optional service name filter"),
    limit: int = Query(default=50, ge=1, le=500, description="Maximum incidents to return"),
) -> IncidentListResponse:
    """List recorded incidents ordered newest first."""
    settings = get_settings()
    ensure_database(settings.autoheal_db_path)

    clauses: list[str] = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if service is not None:
        clauses.append("service_name = ?")
        params.append(service.strip())

    where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    conn = get_connection(settings.autoheal_db_path)
    try:
        rows = conn.execute(
            f"SELECT * FROM incidents {where_sql} ORDER BY id DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
        total_row = conn.execute(
            f"SELECT COUNT(*) AS cnt FROM incidents {where_sql}",
            params,
        ).fetchone()
        open_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM incidents WHERE status = 'open'"
        ).fetchone()
    finally:
        conn.close()

    return IncidentListResponse(
        total=int(total_row["cnt"]) if total_row else 0,
        open_count=int(open_row["cnt"]) if open_row else 0,
        incidents=[_row_to_response(row) for row in rows],
    )


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: int) -> IncidentResponse:
    """Fetch a single incident by ID."""
    settings = get_settings()
    ensure_database(settings.autoheal_db_path)

    conn = get_connection(settings.autoheal_db_path)
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    return _row_to_response(row)

