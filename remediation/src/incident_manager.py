"""Persistent SQLite-backed state machine and incident lifecycle manager."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .database import (
    CORE_MONITORING_SCHEMA_SQL,
    ensure_autoheal_database,
    ensure_incident_columns,
    format_utc,
    get_connection,
    parse_optional_dt,
)
from .models import (
    HealthCheckResult,
    IncidentRecord,
    IncidentStatus,
    ServiceState,
    StateEvaluation,
)

SCHEMA_SQL = CORE_MONITORING_SCHEMA_SQL


class IncidentManager:
    """Evaluates health check outcomes and manages incidents in SQLite."""

    def __init__(
        self,
        db_path: str,
        failure_threshold: int = 3,
        recovery_threshold: int = 2,
    ) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be >= 1")
        if recovery_threshold < 1:
            raise ValueError("recovery_threshold must be >= 1")

        self.db_path = db_path
        self.failure_threshold = failure_threshold
        self.recovery_threshold = recovery_threshold
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self, *, manual_transactions: bool = False) -> sqlite3.Connection:
        return get_connection(self.db_path, manual_transactions=manual_transactions)

    def _init_db(self) -> None:
        ensure_autoheal_database(self.db_path)

    def ensure_service_initialized(self, service_name: str, target_url: str) -> None:
        """Create an initial UNKNOWN status row if one does not yet exist."""
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self._connect(manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT OR IGNORE INTO service_status (
                    service_name, target_url, status, consecutive_failures,
                    consecutive_successes, updated_at
                ) VALUES (?, ?, ?, 0, 0, ?)
                """,
                (service_name, target_url, ServiceState.UNKNOWN.value, now_iso),
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def process_check(self, result: HealthCheckResult) -> StateEvaluation:
        """Persist check result, update state, and create/update/resolve incidents."""
        checked_iso = result.checked_at.isoformat()
        conn = self._connect(manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing_row = conn.execute(
                "SELECT * FROM service_status WHERE service_name = ?",
                (result.service_name,),
            ).fetchone()

            if existing_row is None:
                prev_state = ServiceState.UNKNOWN
                consecutive_failures = 0
                consecutive_successes = 0
                last_change_dt: datetime | None = None
            else:
                prev_state = ServiceState(existing_row["status"])
                consecutive_failures = int(existing_row["consecutive_failures"])
                consecutive_successes = int(existing_row["consecutive_successes"])
                last_change_dt = parse_optional_dt(existing_row["last_status_change_at"])

            open_incident = self._fetch_open_incident(conn, result.service_name)
            incident_created: IncidentRecord | None = None
            incident_resolved: IncidentRecord | None = None
            active_incident: IncidentRecord | None = open_incident
            new_state = prev_state

            if result.healthy:
                consecutive_failures = 0
                consecutive_successes += 1

                if prev_state == ServiceState.UNKNOWN:
                    new_state = ServiceState.HEALTHY
                elif (
                    prev_state == ServiceState.UNHEALTHY
                    and consecutive_successes >= self.recovery_threshold
                ):
                    new_state = ServiceState.HEALTHY
                    if open_incident is not None:
                        incident_resolved = self._resolve_incident(
                            conn, open_incident.id, checked_iso
                        )
                        active_incident = None
            else:
                consecutive_successes = 0
                consecutive_failures += 1
                reason = result.error or f"Health check failed ({result.outcome.value})"

                if (
                    prev_state != ServiceState.UNHEALTHY
                    and consecutive_failures >= self.failure_threshold
                ):
                    new_state = ServiceState.UNHEALTHY
                    if open_incident is None:
                        incident_created = self._create_incident(
                            conn,
                            service_name=result.service_name,
                            reason=reason,
                            started_at=checked_iso,
                            failure_count=consecutive_failures,
                        )
                        active_incident = incident_created
                    else:
                        active_incident = self._update_incident(
                            conn, open_incident.id, checked_iso, reason
                        )
                elif open_incident is not None:
                    active_incident = self._update_incident(
                        conn, open_incident.id, checked_iso, reason
                    )

            state_changed = new_state != prev_state
            status_change_at = (
                checked_iso
                if state_changed
                else (last_change_dt.isoformat() if last_change_dt else None)
            )

            conn.execute(
                """
                INSERT INTO service_status (
                    service_name, target_url, status, consecutive_failures,
                    consecutive_successes, last_checked_at, last_status_change_at,
                    last_http_status, last_response_time_ms, last_error,
                    active_incident_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(service_name) DO UPDATE SET
                    target_url = excluded.target_url,
                    status = excluded.status,
                    consecutive_failures = excluded.consecutive_failures,
                    consecutive_successes = excluded.consecutive_successes,
                    last_checked_at = excluded.last_checked_at,
                    last_status_change_at = excluded.last_status_change_at,
                    last_http_status = excluded.last_http_status,
                    last_response_time_ms = excluded.last_response_time_ms,
                    last_error = excluded.last_error,
                    active_incident_id = excluded.active_incident_id,
                    updated_at = excluded.updated_at
                """,
                (
                    result.service_name,
                    result.target_url,
                    new_state.value,
                    consecutive_failures,
                    consecutive_successes,
                    checked_iso,
                    status_change_at,
                    result.status_code,
                    result.response_time_ms,
                    result.error,
                    active_incident.id if active_incident else None,
                    checked_iso,
                ),
            )
            conn.execute("COMMIT")

            return StateEvaluation(
                previous_state=prev_state,
                current_state=new_state,
                state_changed=state_changed,
                incident_created=incident_created,
                incident_resolved=incident_resolved,
                active_incident=active_incident,
                consecutive_failures=consecutive_failures,
                consecutive_successes=consecutive_successes,
            )
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def resolve_open_incident(
        self,
        incident_id: int,
        resolved_at: datetime | None = None,
        *,
        response_time_ms: float | None = None,
        http_status: int | None = 200,
    ) -> IncidentRecord | None:
        """Mark an incident RESOLVED and transition service status to HEALTHY."""
        now_dt = resolved_at or datetime.now(timezone.utc)
        conn = self._connect(manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            incident, _ = self.resolve_open_incident_in_tx(
                conn,
                incident_id,
                now_dt,
                response_time_ms=response_time_ms,
                http_status=http_status,
            )
            conn.execute("COMMIT")
            return incident
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def resolve_open_incident_in_tx(
        self,
        conn: sqlite3.Connection,
        incident_id: int,
        resolved_at: datetime,
        *,
        response_time_ms: float | None = None,
        http_status: int | None = 200,
    ) -> tuple[IncidentRecord | None, bool]:
        """Resolve an open incident inside a caller-managed SQLite transaction."""
        if incident_id <= 0:
            return None, False

        resolved_dt = (
            resolved_at.replace(tzinfo=timezone.utc)
            if resolved_at.tzinfo is None
            else resolved_at.astimezone(timezone.utc)
        )
        resolved_iso = resolved_dt.isoformat()

        existing_row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        if existing_row is None:
            return None, False
        if existing_row["status"] != IncidentStatus.OPEN.value:
            return self._row_to_incident(existing_row), False

        cursor = conn.execute(
            """
            UPDATE incidents
            SET status = ?, resolved_at = ?, last_seen_at = ?, flapping = 0
            WHERE id = ? AND status = ?
            """,
            (
                IncidentStatus.RESOLVED.value,
                resolved_iso,
                resolved_iso,
                incident_id,
                IncidentStatus.OPEN.value,
            ),
        )
        if cursor.rowcount != 1:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return (self._row_to_incident(row) if row is not None else None), False

        service_name = str(existing_row["service_name"])
        conn.execute(
            """
            UPDATE service_status
            SET status = ?,
                consecutive_failures = 0,
                consecutive_successes = ?,
                last_checked_at = ?,
                last_status_change_at = ?,
                last_http_status = ?,
                last_response_time_ms = COALESCE(?, last_response_time_ms),
                last_error = NULL,
                active_incident_id = NULL,
                updated_at = ?
            WHERE service_name = ?
            """,
            (
                ServiceState.HEALTHY.value,
                self.recovery_threshold,
                resolved_iso,
                resolved_iso,
                http_status,
                response_time_ms,
                resolved_iso,
                service_name,
            ),
        )

        updated_row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return (self._row_to_incident(updated_row) if updated_row is not None else None), True

    def _fetch_open_incident(
        self, conn: sqlite3.Connection, service_name: str
    ) -> IncidentRecord | None:
        row = conn.execute(
            """
            SELECT * FROM incidents
            WHERE service_name = ? AND status = ?
            ORDER BY id DESC LIMIT 1
            """,
            (service_name, IncidentStatus.OPEN.value),
        ).fetchone()
        return self._row_to_incident(row) if row else None

    def _create_incident(
        self,
        conn: sqlite3.Connection,
        service_name: str,
        reason: str,
        started_at: str,
        failure_count: int,
    ) -> IncidentRecord:
        cursor = conn.execute(
            """
            INSERT INTO incidents (
                service_name, status, failure_reason, started_at, resolved_at,
                last_seen_at, failure_count, source, last_problem_at
            ) VALUES (?, ?, ?, ?, NULL, ?, ?, 'internal_monitor', ?)
            """,
            (
                service_name,
                IncidentStatus.OPEN.value,
                reason,
                started_at,
                started_at,
                failure_count,
                started_at,
            ),
        )
        incident_id = cursor.lastrowid
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row)

    def _update_incident(
        self,
        conn: sqlite3.Connection,
        incident_id: int,
        seen_at: str,
        reason: str,
    ) -> IncidentRecord:
        existing_row = conn.execute(
            "SELECT last_problem_at FROM incidents WHERE id = ?",
            (incident_id,),
        ).fetchone()
        existing_problem_dt = (
            parse_optional_dt(existing_row["last_problem_at"])
            if existing_row is not None
            else None
        )
        current_dt = parse_optional_dt(seen_at)
        if existing_problem_dt is not None and current_dt is not None:
            next_problem_iso = format_utc(max(existing_problem_dt, current_dt))
        else:
            next_problem_iso = seen_at

        conn.execute(
            """
            UPDATE incidents
            SET failure_reason = ?,
                last_seen_at = ?,
                last_problem_at = ?,
                failure_count = failure_count + 1,
                source = CASE
                    WHEN source = 'nagios' THEN 'internal_monitor+nagios'
                    ELSE source
                END
            WHERE id = ?
            """,
            (reason, seen_at, next_problem_iso, incident_id),
        )
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row)

    def _resolve_incident(
        self, conn: sqlite3.Connection, incident_id: int, resolved_at: str
    ) -> IncidentRecord:
        conn.execute(
            """
            UPDATE incidents
            SET status = ?, resolved_at = ?, last_seen_at = ?, flapping = 0
            WHERE id = ?
            """,
            (IncidentStatus.RESOLVED.value, resolved_at, resolved_at, incident_id),
        )
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (incident_id,)
        ).fetchone()
        return self._row_to_incident(row)

    def list_incidents(
        self,
        service_name: str | None = None,
        status: IncidentStatus | str | None = None,
        limit: int = 100,
    ) -> list[IncidentRecord]:
        """Fetch recorded incidents, optionally filtered by service_name or status."""
        if service_name in ("open", "resolved") and status is None:
            status = service_name
            service_name = None

        clauses: list[str] = []
        params: list[object] = []
        if service_name is not None:
            clauses.append("service_name = ?")
            params.append(service_name)
        if status is not None:
            val = status.value if isinstance(status, IncidentStatus) else str(status)
            clauses.append("status = ?")
            params.append(val)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        conn = self._connect()
        try:
            rows = conn.execute(
                f"SELECT * FROM incidents {where_sql} ORDER BY id DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
            return [self._row_to_incident(r) for r in rows]
        finally:
            conn.close()

    def get_incident(self, incident_id: int) -> IncidentRecord | None:
        """Fetch a single incident by ID."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM incidents WHERE id = ?", (incident_id,)
            ).fetchone()
            return self._row_to_incident(row) if row else None
        finally:
            conn.close()

    def _row_to_incident(self, row: sqlite3.Row) -> IncidentRecord:
        keys = set(row.keys())
        return IncidentRecord(
            id=int(row["id"]),
            service_name=row["service_name"],
            status=IncidentStatus(row["status"]) if row["status"] in ("open", "resolved") else row["status"],
            failure_reason=row["failure_reason"],
            started_at=datetime.fromisoformat(row["started_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            resolved_at=parse_optional_dt(row["resolved_at"]),
            failure_count=int(row["failure_count"]),
            source=str(row["source"]) if "source" in keys and row["source"] else "nagios",
            host_name=row["host_name"] if "host_name" in keys else None,
            nagios_service_name=row["nagios_service_name"] if "nagios_service_name" in keys else None,
            nagios_state=row["nagios_state"] if "nagios_state" in keys else None,
            last_problem_at=row["last_problem_at"] if "last_problem_at" in keys else None,
            nagios_alert_count=(
                int(row["nagios_alert_count"])
                if "nagios_alert_count" in keys and row["nagios_alert_count"] is not None
                else 0
            ),
            flapping=bool(row["flapping"]) if "flapping" in keys and row["flapping"] is not None else False,
        )
