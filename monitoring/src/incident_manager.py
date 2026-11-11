"""Persistent SQLite-backed state machine and incident lifecycle manager."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .models import (
    HealthCheckResult,
    IncidentRecord,
    IncidentStatus,
    ServiceState,
    ServiceStatusRecord,
    StateEvaluation,
)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS service_status (
    service_name TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    status TEXT NOT NULL,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    consecutive_successes INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    last_status_change_at TEXT,
    last_http_status INTEGER,
    last_response_time_ms REAL,
    last_error TEXT,
    active_incident_id INTEGER,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    status TEXT NOT NULL,
    failure_reason TEXT NOT NULL,
    started_at TEXT NOT NULL,
    resolved_at TEXT,
    last_seen_at TEXT NOT NULL,
    failure_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_incidents_service_status
    ON incidents (service_name, status);

CREATE TABLE IF NOT EXISTS monitoring_counters (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    value REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json)
);

CREATE TABLE IF NOT EXISTS monitoring_histogram_buckets (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    le TEXT NOT NULL,
    bucket_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json, le)
);

CREATE TABLE IF NOT EXISTS monitoring_histogram_totals (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    total_sum REAL NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json)
);
"""


def _parse_dt(value: str | None) -> datetime | None:
    if value is None:
        return None
    return datetime.fromisoformat(value)


class IncidentManager:
    """Evaluates health check outcomes and manages incidents in SQLite.

    State transitions:
    - UNKNOWN -> HEALTHY on the first healthy check.
    - HEALTHY / UNKNOWN -> UNHEALTHY when consecutive failures reach `failure_threshold`,
      opening one incident (and updating it on subsequent failures without duplicates).
    - UNHEALTHY -> HEALTHY when consecutive successes reach `recovery_threshold`,
      resolving the active open incident.
    """

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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def ensure_service_initialized(self, service_name: str, target_url: str) -> None:
        """Create an initial UNKNOWN status row if one does not yet exist."""
        now_iso = datetime.now(timezone.utc).isoformat()
        conn = self._connect()
        try:
            with conn:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO service_status (
                        service_name, target_url, status, consecutive_failures,
                        consecutive_successes, updated_at
                    ) VALUES (?, ?, ?, 0, 0, ?)
                    """,
                    (service_name, target_url, ServiceState.UNKNOWN.value, now_iso),
                )
        finally:
            conn.close()

    def process_check(self, result: HealthCheckResult) -> StateEvaluation:
        """Persist check result, update state, and create/update/resolve incidents."""
        checked_iso = result.checked_at.isoformat()
        conn = self._connect()
        try:
            with conn:
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
                    last_change_dt = _parse_dt(existing_row["last_status_change_at"])

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

                    if consecutive_failures >= self.failure_threshold:
                        new_state = ServiceState.UNHEALTHY
                    if open_incident is not None:
                        active_incident = self._update_open_incident(
                            conn,
                            incident_id=open_incident.id,
                            failure_reason=reason,
                            timestamp_iso=checked_iso,
                        )
                    elif consecutive_failures >= self.failure_threshold:
                        incident_created = self._create_incident(
                            conn,
                            service_name=result.service_name,
                            failure_reason=reason,
                            timestamp_iso=checked_iso,
                            initial_failures=consecutive_failures,
                        )
                        active_incident = incident_created

                state_changed = new_state != prev_state
                if state_changed or last_change_dt is None:
                    last_change_iso = checked_iso
                else:
                    last_change_iso = last_change_dt.isoformat()

                active_incident_id = active_incident.id if active_incident is not None else None
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
                        last_change_iso,
                        result.status_code,
                        result.response_time_ms,
                        result.error,
                        active_incident_id,
                        checked_iso,
                    ),
                )

                status_record = ServiceStatusRecord(
                    service_name=result.service_name,
                    target_url=result.target_url,
                    status=new_state,
                    consecutive_failures=consecutive_failures,
                    consecutive_successes=consecutive_successes,
                    last_checked_at=result.checked_at,
                    last_status_change_at=_parse_dt(last_change_iso),
                    last_http_status=result.status_code,
                    last_response_time_ms=result.response_time_ms,
                    last_error=result.error,
                    active_incident_id=active_incident_id,
                )

                return StateEvaluation(
                    previous_state=prev_state,
                    current_state=new_state,
                    state_changed=state_changed,
                    incident_created=incident_created,
                    incident_resolved=incident_resolved,
                    active_incident=active_incident,
                    status_record=status_record,
                )
        finally:
            conn.close()

    def list_incidents(self, service_name: str | None = None) -> list[IncidentRecord]:
        """List incidents ordered newest first."""
        conn = self._connect()
        try:
            if service_name is None:
                rows = conn.execute("SELECT * FROM incidents ORDER BY id DESC").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE service_name = ? ORDER BY id DESC",
                    (service_name,),
                ).fetchall()
            return [self._row_to_incident(row) for row in rows]
        finally:
            conn.close()

    @staticmethod
    def _row_to_incident(row: sqlite3.Row) -> IncidentRecord:
        return IncidentRecord(
            id=int(row["id"]),
            service_name=row["service_name"],
            status=IncidentStatus(row["status"]),
            failure_reason=row["failure_reason"],
            started_at=datetime.fromisoformat(row["started_at"]),
            resolved_at=_parse_dt(row["resolved_at"]),
            last_seen_at=datetime.fromisoformat(row["last_seen_at"]),
            failure_count=int(row["failure_count"]),
        )

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
        return self._row_to_incident(row) if row is not None else None

    def _create_incident(
        self,
        conn: sqlite3.Connection,
        service_name: str,
        failure_reason: str,
        timestamp_iso: str,
        initial_failures: int,
    ) -> IncidentRecord:
        cursor = conn.execute(
            """
            INSERT INTO incidents (
                service_name, status, failure_reason, started_at, resolved_at,
                last_seen_at, failure_count
            ) VALUES (?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                service_name,
                IncidentStatus.OPEN.value,
                failure_reason,
                timestamp_iso,
                timestamp_iso,
                initial_failures,
            ),
        )
        row = conn.execute(
            "SELECT * FROM incidents WHERE id = ?", (cursor.lastrowid,)
        ).fetchone()
        return self._row_to_incident(row)

    def _update_open_incident(
        self,
        conn: sqlite3.Connection,
        incident_id: int,
        failure_reason: str,
        timestamp_iso: str,
    ) -> IncidentRecord:
        conn.execute(
            """
            UPDATE incidents
            SET failure_reason = ?, last_seen_at = ?, failure_count = failure_count + 1
            WHERE id = ?
            """,
            (failure_reason, timestamp_iso, incident_id),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._row_to_incident(row)

    def _resolve_incident(
        self,
        conn: sqlite3.Connection,
        incident_id: int,
        timestamp_iso: str,
    ) -> IncidentRecord:
        conn.execute(
            """
            UPDATE incidents
            SET status = ?, resolved_at = ?, last_seen_at = ?
            WHERE id = ?
            """,
            (IncidentStatus.RESOLVED.value, timestamp_iso, timestamp_iso, incident_id),
        )
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        return self._row_to_incident(row)

