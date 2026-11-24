"""SQLite read and schema-initialization helpers for the FastAPI control plane."""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

from remediation.src.database import (
    CORE_MONITORING_SCHEMA_SQL,
    ensure_autoheal_database,
)

_INIT_LOCK = threading.Lock()
_INITIALIZED_DBS: set[tuple[str, int, int]] = set()

SCHEMA_SQL = CORE_MONITORING_SCHEMA_SQL


def ensure_database(db_path: str) -> None:
    """Create the SQLite database file and schema if missing or uninitialized."""
    resolved = Path(db_path).resolve() if db_path != ":memory:" else None
    if resolved is not None and resolved.is_file():
        stat = os.stat(resolved)
        key = (str(resolved), stat.st_dev, stat.st_ino)
        with _INIT_LOCK:
            if key in _INITIALIZED_DBS:
                return

    ensure_autoheal_database(db_path)

    if resolved is not None and resolved.is_file():
        stat = os.stat(resolved)
        key = (str(resolved), stat.st_dev, stat.st_ino)
        with _INIT_LOCK:
            _INITIALIZED_DBS.add(key)


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
