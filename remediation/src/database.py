"""SQLite connection, query helpers, and idempotent remediation schema initialization."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .models import (
    ACTIVE_REMEDIATION_STATUSES,
    IncidentSnapshot,
    RemediationExecution,
    RemediationState,
    RemediationStatus,
)

REMEDIATION_SCHEMA_VERSION = 3

CORE_MONITORING_SCHEMA_SQL = """
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

_COUNTER_TABLES = frozenset({
    "monitoring_counters",
    "remediation_counters",
    "nagios_counters",
})

REMEDIATION_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS remediation_schema_meta (
    schema_name TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediation_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE RESTRICT,
    service_name TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'running', 'succeeded', 'failed', 'timed_out', 'dry_run')
    ),
    attempt_number INTEGER NOT NULL CHECK (attempt_number >= 1),
    started_at TEXT,
    completed_at TEXT,
    duration_seconds REAL,
    ansible_exit_code INTEGER,
    execution_output TEXT,
    failure_reason TEXT,
    dry_run INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_remediation_incident_attempt
    ON remediation_executions (incident_id, attempt_number);

CREATE UNIQUE INDEX IF NOT EXISTS uq_remediation_active_incident
    ON remediation_executions (incident_id)
    WHERE status IN ('pending', 'running');

CREATE INDEX IF NOT EXISTS idx_remediation_incident_status
    ON remediation_executions (incident_id, status);

CREATE INDEX IF NOT EXISTS idx_remediation_service_created
    ON remediation_executions (service_name, created_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_remediation_status_started
    ON remediation_executions (status, started_at, created_at);

CREATE TABLE IF NOT EXISTS remediation_counters (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    value REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json)
);

CREATE TABLE IF NOT EXISTS remediation_histogram_buckets (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    le TEXT NOT NULL,
    bucket_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json, le)
);

CREATE TABLE IF NOT EXISTS remediation_histogram_totals (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    total_sum REAL NOT NULL DEFAULT 0,
    total_count INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json)
);

CREATE TABLE IF NOT EXISTS remediation_metric_events (
    execution_id INTEGER NOT NULL REFERENCES remediation_executions(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    PRIMARY KEY (execution_id, event_type)
);

CREATE TABLE IF NOT EXISTS remediation_exhausted_incidents (
    incident_id INTEGER PRIMARY KEY REFERENCES incidents(id) ON DELETE RESTRICT,
    service_name TEXT NOT NULL,
    action TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nagios_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dedup_key TEXT NOT NULL UNIQUE,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE SET NULL,
    notification_kind TEXT NOT NULL,
    notification_type TEXT NOT NULL,
    host_name TEXT NOT NULL,
    nagios_service_name TEXT,
    mapped_service TEXT NOT NULL,
    state TEXT NOT NULL,
    state_type TEXT NOT NULL,
    attempt INTEGER NOT NULL DEFAULT 1,
    output TEXT,
    nagios_problem_id TEXT,
    nagios_notification_id TEXT,
    event_timestamp TEXT NOT NULL,
    received_at TEXT NOT NULL,
    processing_status TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_nagios_events_service_received
    ON nagios_events (mapped_service, received_at DESC, id DESC);

CREATE INDEX IF NOT EXISTS idx_nagios_events_incident
    ON nagios_events (incident_id, id DESC);

CREATE TABLE IF NOT EXISTS nagios_counters (
    metric_name TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    value REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (metric_name, labels_json)
);

CREATE TABLE IF NOT EXISTS nagios_monitor_status (
    target_name TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    up INTEGER NOT NULL DEFAULT 0,
    http_status INTEGER,
    response_time_ms REAL,
    program_running INTEGER NOT NULL DEFAULT 0,
    last_checked_at TEXT,
    last_error TEXT,
    updated_at TEXT NOT NULL
);
"""

_INCIDENT_EXTENSION_COLUMNS: tuple[tuple[str, str], ...] = (
    ("source", "TEXT NOT NULL DEFAULT 'internal_monitor'"),
    ("host_name", "TEXT"),
    ("nagios_service_name", "TEXT"),
    ("nagios_state", "TEXT"),
    ("last_problem_at", "TEXT"),
    ("nagios_alert_count", "INTEGER NOT NULL DEFAULT 0"),
    ("flapping", "INTEGER NOT NULL DEFAULT 0"),
)


def ensure_incident_columns(conn: sqlite3.Connection) -> None:
    """Safely migrate `incidents` table with multi-source and Nagios metadata columns."""
    table_row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='incidents'"
    ).fetchone()
    if table_row is None:
        return

    existing_cols = {
        str(row["name"])
        for row in conn.execute("PRAGMA table_info(incidents)").fetchall()
    }
    for col_name, col_def in _INCIDENT_EXTENSION_COLUMNS:
        if col_name not in existing_cols:
            conn.execute(f"ALTER TABLE incidents ADD COLUMN {col_name} {col_def}")

    dup_row = conn.execute(
        """
        SELECT 1 FROM incidents
        WHERE status = 'open'
        GROUP BY service_name
        HAVING COUNT(*) > 1
        LIMIT 1
        """
    ).fetchone()
    if dup_row is None:
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS uq_incidents_open_service
                ON incidents (service_name)
                WHERE status = 'open'
            """
        )


def ensure_utc(value: datetime) -> datetime:
    """Normalize a datetime instance to timezone-aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    """Format a datetime consistently as a UTC ISO 8601 string."""
    return ensure_utc(value).isoformat()


def parse_optional_dt(value: str | None) -> datetime | None:
    """Parse an optional ISO 8601 timestamp string into timezone-aware UTC."""
    if value is None:
        return None
    return ensure_utc(datetime.fromisoformat(value))


def get_connection(
    db_path: str,
    *,
    read_only: bool = False,
    manual_transactions: bool = False,
) -> sqlite3.Connection:
    """Open a SQLite connection configured for safe concurrency on shared DB storage."""
    if read_only:
        resolved = Path(db_path).resolve()
        conn = sqlite3.connect(f"file:{resolved}?mode=ro", uri=True, timeout=5.0)
    else:
        isolation_level = None if manual_transactions else ""
        conn = sqlite3.connect(db_path, timeout=5.0, isolation_level=isolation_level)

    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    if not read_only:
        conn.execute("PRAGMA foreign_keys=ON")
    return conn


def ensure_remediation_database(db_path: str) -> None:
    """Idempotently initialize remediation tables and indexes on the shared database."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(db_path, manual_transactions=True)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(REMEDIATION_SCHEMA_SQL)
        conn.execute("BEGIN IMMEDIATE")
        ensure_incident_columns(conn)
        conn.execute(
            """
            INSERT INTO remediation_schema_meta (schema_name, version, applied_at)
            VALUES ('remediation', ?, ?)
            ON CONFLICT(schema_name) DO UPDATE SET
                version = CASE WHEN excluded.version > version THEN excluded.version ELSE version END,
                applied_at = CASE WHEN excluded.version > version THEN excluded.applied_at ELSE applied_at END
            """,
            (REMEDIATION_SCHEMA_VERSION, format_utc(utc_now())),
        )
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def ensure_autoheal_database(db_path: str) -> None:
    """Idempotently initialize core monitoring, Nagios, and remediation tables on one DB."""
    if db_path != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(db_path)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(CORE_MONITORING_SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()
    ensure_remediation_database(db_path)


def increment_sql_counter(
    conn: sqlite3.Connection,
    table_name: str,
    metric_name: str,
    labels_json: str,
    *,
    increment: float = 1.0,
) -> None:
    """Atomically increment a persisted SQLite Prometheus counter row in an allowlisted table."""
    if table_name not in _COUNTER_TABLES:
        raise ValueError(f"Unsupported counter table: {table_name!r}")
    conn.execute(
        f"""
        INSERT INTO {table_name} (metric_name, labels_json, value)
        VALUES (?, ?, ?)
        ON CONFLICT(metric_name, labels_json)
        DO UPDATE SET value = value + excluded.value
        """,
        (metric_name, labels_json, float(increment)),
    )


def record_incident_event_in_tx(
    conn: sqlite3.Connection,
    service: str,
    event: str,
) -> None:
    """Persist an incident lifecycle counter increment inside an existing transaction."""
    labels_json = json.dumps({"event": event, "service": service}, sort_keys=True)
    increment_sql_counter(
        conn,
        "monitoring_counters",
        "autoheal_incidents_total",
        labels_json,
    )


def row_to_incident_snapshot(row: sqlite3.Row) -> IncidentSnapshot:
    """Map an existing `incidents` table row to `IncidentSnapshot`."""
    return IncidentSnapshot(
        id=int(row["id"]),
        service_name=str(row["service_name"]),
        status=str(row["status"]),
        failure_reason=row["failure_reason"],
        failure_count=int(row["failure_count"]),
        resolved_at=parse_optional_dt(row["resolved_at"]),
    )


def row_to_execution(row: sqlite3.Row) -> RemediationExecution:
    """Map a `remediation_executions` row to `RemediationExecution`."""
    return RemediationExecution(
        id=int(row["id"]),
        incident_id=int(row["incident_id"]),
        service_name=str(row["service_name"]),
        action=str(row["action"]),
        status=RemediationStatus(str(row["status"])),
        attempt_number=int(row["attempt_number"]),
        started_at=parse_optional_dt(row["started_at"]),
        completed_at=parse_optional_dt(row["completed_at"]),
        duration_seconds=(
            float(row["duration_seconds"]) if row["duration_seconds"] is not None else None
        ),
        ansible_exit_code=(
            int(row["ansible_exit_code"]) if row["ansible_exit_code"] is not None else None
        ),
        execution_output=row["execution_output"],
        failure_reason=row["failure_reason"],
        dry_run=bool(row["dry_run"]),
        created_at=ensure_utc(datetime.fromisoformat(str(row["created_at"]))),
    )


def query_incident_snapshot(conn: sqlite3.Connection, incident_id: int) -> IncidentSnapshot | None:
    """Look up an incident from the existing `incidents` table."""
    if incident_id <= 0:
        return None
    try:
        row = conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return None
        raise
    return row_to_incident_snapshot(row) if row is not None else None


def query_remediation_summary(
    conn: sqlite3.Connection,
    incident_id: int,
) -> tuple[int, RemediationExecution | None, RemediationExecution | None]:
    """Fetch total attempts, any active execution, and the latest execution for an incident."""
    if incident_id <= 0:
        return (0, None, None)

    try:
        count_row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM remediation_executions WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        active_row = conn.execute(
            """
            SELECT * FROM remediation_executions
            WHERE incident_id = ? AND status IN ('pending', 'running')
            ORDER BY id DESC LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
        latest_row = conn.execute(
            """
            SELECT * FROM remediation_executions
            WHERE incident_id = ?
            ORDER BY attempt_number DESC, id DESC LIMIT 1
            """,
            (incident_id,),
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return (0, None, None)
        raise

    attempts = int(count_row["cnt"]) if count_row is not None else 0
    active_execution = row_to_execution(active_row) if active_row is not None else None
    latest_execution = row_to_execution(latest_row) if latest_row is not None else None
    return (attempts, active_execution, latest_execution)


def is_execution_stale(
    execution: RemediationExecution,
    *,
    stale_after_seconds: float | None,
    current_time: datetime,
) -> bool:
    """Determine whether an active pending/running execution has exceeded its stale threshold."""
    if stale_after_seconds is None or stale_after_seconds <= 0:
        return False
    if execution.status not in ACTIVE_REMEDIATION_STATUSES:
        return False
    reference_ts = execution.started_at or execution.created_at
    cutoff = ensure_utc(current_time) - timedelta(seconds=stale_after_seconds)
    return ensure_utc(reference_ts) <= cutoff


def build_state_from_summary(
    attempts: int,
    active_execution: RemediationExecution | None,
    latest_execution: RemediationExecution | None,
    *,
    current_time: datetime,
    stale_after_seconds: float | None,
) -> RemediationState:
    """Build `RemediationState` from DB summary rows without mutating DB state."""
    last_attempt_at = (
        (latest_execution.started_at or latest_execution.created_at)
        if latest_execution is not None
        else None
    )

    if active_execution is None:
        return RemediationState(
            attempts=attempts,
            last_attempt_at=last_attempt_at,
            is_running=False,
            current_execution=None,
            latest_execution=latest_execution,
            stale_execution=None,
        )

    if is_execution_stale(
        active_execution,
        stale_after_seconds=stale_after_seconds,
        current_time=current_time,
    ):
        return RemediationState(
            attempts=attempts,
            last_attempt_at=last_attempt_at,
            is_running=False,
            current_execution=None,
            latest_execution=latest_execution,
            stale_execution=active_execution,
        )

    return RemediationState(
        attempts=attempts,
        last_attempt_at=last_attempt_at,
        is_running=True,
        current_execution=active_execution,
        latest_execution=latest_execution,
        stale_execution=None,
    )
