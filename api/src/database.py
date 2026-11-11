"""SQLite read and schema-initialization helpers for the FastAPI control plane."""

from __future__ import annotations

import sqlite3
from pathlib import Path

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


def ensure_database(db_path: str) -> None:
    """Create the SQLite database file and schema if missing."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def get_connection(db_path: str) -> sqlite3.Connection:
    """Open a SQLite connection configured with row factory and busy timeout."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def check_database_health(db_path: str) -> bool:
    """Verify SQLite connectivity."""
    conn = get_connection(db_path)
    try:
        conn.execute("SELECT 1").fetchone()
        return True
    finally:
        conn.close()

