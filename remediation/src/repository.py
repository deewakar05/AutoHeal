"""SQLite repository for persistent remediation history, locks, and atomic reservations."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterable
from datetime import datetime, timedelta
from enum import Enum

from .config import RemediationSettings, SAFE_IDENTIFIER_RE
from .database import (
    build_state_from_summary,
    ensure_remediation_database,
    ensure_utc,
    format_utc,
    get_connection,
    query_incident_snapshot,
    query_remediation_summary,
    row_to_execution,
    utc_now,
)
from .models import (
    ACTIVE_REMEDIATION_STATUSES,
    TERMINAL_REMEDIATION_STATUSES,
    RemediationAction,
    RemediationExecution,
    RemediationRequest,
    RemediationStatus,
    ReservationResult,
)
from .policy import evaluate_policy_gates

_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|secret|token|api_key|apikey|authorization)\b(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9\-._~+/]+=*)")
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)


def sanitize_execution_text(value: str | None, *, max_length: int = 4000) -> str | None:
    """Remove control bytes, mask sensitive credentials/keys, and bound stored length."""
    if value is None:
        return None
    cleaned = value.replace("\x00", "").strip()
    cleaned = _PEM_BLOCK_RE.sub("[REDACTED_PRIVATE_KEY]", cleaned)
    cleaned = _BEARER_RE.sub(r"\1***", cleaned)
    cleaned = _SECRET_KV_RE.sub(r"\1\2***", cleaned)
    if len(cleaned) > max_length:
        return cleaned[: max_length - 15] + "...[truncated]"
    return cleaned


def _coerce_status(value: RemediationStatus | str) -> RemediationStatus:
    raw = value.value if isinstance(value, Enum) else str(value).strip().lower()
    return RemediationStatus(raw)


def _coerce_action(value: RemediationAction | str) -> str:
    raw = value.value if isinstance(value, Enum) else str(value).strip().lower()
    return RemediationAction(raw).value


def _validate_service_name(service_name: str) -> str:
    cleaned = service_name.strip().lower()
    if not cleaned or not SAFE_IDENTIFIER_RE.fullmatch(cleaned):
        raise ValueError(f"Invalid service_name: {service_name!r}")
    return cleaned


class RemediationRepository:
    """SQLite persistence repository for remediation executions and atomic reservations."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        ensure_remediation_database(db_path)

    def create_execution(
        self,
        *,
        incident_id: int,
        service_name: str,
        action: str | RemediationAction,
        status: RemediationStatus | str = RemediationStatus.PENDING,
        attempt_number: int | None = None,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float | None = None,
        ansible_exit_code: int | None = None,
        execution_output: str | None = None,
        failure_reason: str | None = None,
        dry_run: bool = True,
        created_at: datetime | None = None,
    ) -> RemediationExecution:
        """Create and persist a remediation execution record atomically."""
        if incident_id <= 0:
            raise ValueError("incident_id must be >= 1")
        normalized_service = _validate_service_name(service_name)
        normalized_action = _coerce_action(action)
        normalized_status = _coerce_status(status)

        if attempt_number is not None and attempt_number < 1:
            raise ValueError("attempt_number must be >= 1")
        if duration_seconds is not None and duration_seconds < 0:
            raise ValueError("duration_seconds must be >= 0")

        effective_created_at = ensure_utc(created_at or utc_now())
        effective_started_at = ensure_utc(started_at) if started_at is not None else None
        if normalized_status == RemediationStatus.RUNNING and effective_started_at is None:
            effective_started_at = effective_created_at

        effective_completed_at = ensure_utc(completed_at) if completed_at is not None else None
        if (
            normalized_status in TERMINAL_REMEDIATION_STATUSES
            and effective_completed_at is None
        ):
            effective_completed_at = effective_created_at

        effective_duration = duration_seconds
        if (
            effective_duration is None
            and effective_started_at is not None
            and effective_completed_at is not None
        ):
            effective_duration = max(
                (effective_completed_at - effective_started_at).total_seconds(),
                0.0,
            )

        sanitized_output = sanitize_execution_text(execution_output)
        sanitized_reason = sanitize_execution_text(failure_reason, max_length=1000)

        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if attempt_number is None:
                row = conn.execute(
                    "SELECT COALESCE(MAX(attempt_number), 0) AS max_attempt FROM remediation_executions WHERE incident_id = ?",
                    (incident_id,),
                ).fetchone()
                resolved_attempt = (int(row["max_attempt"]) if row is not None else 0) + 1
            else:
                resolved_attempt = attempt_number

            cursor = conn.execute(
                """
                INSERT INTO remediation_executions (
                    incident_id, service_name, action, status, attempt_number,
                    started_at, completed_at, duration_seconds, ansible_exit_code,
                    execution_output, failure_reason, dry_run, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    normalized_service,
                    normalized_action,
                    normalized_status.value,
                    resolved_attempt,
                    format_utc(effective_started_at) if effective_started_at else None,
                    format_utc(effective_completed_at) if effective_completed_at else None,
                    effective_duration,
                    ansible_exit_code,
                    sanitized_output,
                    sanitized_reason,
                    1 if dry_run else 0,
                    format_utc(effective_created_at),
                ),
            )
            created_row = conn.execute(
                "SELECT * FROM remediation_executions WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            conn.execute("COMMIT")
            assert created_row is not None
            return row_to_execution(created_row)
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_execution(self, execution_id: int) -> RemediationExecution | None:
        """Retrieve a single remediation execution by ID."""
        if execution_id <= 0:
            return None
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT * FROM remediation_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            return row_to_execution(row) if row is not None else None
        finally:
            conn.close()

    @staticmethod
    def _build_list_filters(
        *,
        incident_id: int | None = None,
        service_name: str | None = None,
        status: RemediationStatus | str | None = None,
        dry_run: bool | None = None,
        started_after: datetime | None = None,
        started_before: datetime | None = None,
    ) -> tuple[str, list[object]]:
        clauses: list[str] = []
        params: list[object] = []
        if incident_id is not None:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        if service_name is not None:
            clauses.append("service_name = ?")
            params.append(service_name.strip().lower())
        if status is not None:
            clauses.append("status = ?")
            params.append(_coerce_status(status).value)
        if dry_run is not None:
            clauses.append("dry_run = ?")
            params.append(1 if dry_run else 0)
        if started_after is not None:
            clauses.append("COALESCE(started_at, created_at) >= ?")
            params.append(format_utc(started_after))
        if started_before is not None:
            clauses.append("COALESCE(started_at, created_at) <= ?")
            params.append(format_utc(started_before))
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        return where_sql, params

    def list_executions(
        self,
        *,
        incident_id: int | None = None,
        service_name: str | None = None,
        status: RemediationStatus | str | None = None,
        dry_run: bool | None = None,
        started_after: datetime | None = None,
        started_before: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[RemediationExecution]:
        """List remediation execution records filtered cleanly with pagination."""
        if not (1 <= limit <= 500):
            raise ValueError("limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("offset must be >= 0")

        where_sql, params = self._build_list_filters(
            incident_id=incident_id,
            service_name=service_name,
            status=status,
            dry_run=dry_run,
            started_after=started_after,
            started_before=started_before,
        )
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                f"SELECT * FROM remediation_executions {where_sql} ORDER BY id DESC LIMIT ? OFFSET ?",
                [*params, limit, offset],
            ).fetchall()
            return [row_to_execution(row) for row in rows]
        finally:
            conn.close()

    def count_executions(
        self,
        *,
        incident_id: int | None = None,
        service_name: str | None = None,
        status: RemediationStatus | str | None = None,
        dry_run: bool | None = None,
        started_after: datetime | None = None,
        started_before: datetime | None = None,
    ) -> int:
        """Return total count matching execution filters."""
        where_sql, params = self._build_list_filters(
            incident_id=incident_id,
            service_name=service_name,
            status=status,
            dry_run=dry_run,
            started_after=started_after,
            started_before=started_before,
        )
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM remediation_executions {where_sql}",
                params,
            ).fetchone()
            return int(row["cnt"]) if row is not None else 0
        finally:
            conn.close()

    def list_pending_executions(self, *, limit: int = 10) -> list[RemediationExecution]:
        """List queued pending remediation executions oldest-first for isolated worker pickup."""
        if not (1 <= limit <= 100):
            raise ValueError("limit must be between 1 and 100")
        conn = get_connection(self.db_path)
        try:
            rows = conn.execute(
                """
                SELECT * FROM remediation_executions
                WHERE status = 'pending'
                ORDER BY id ASC LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [row_to_execution(row) for row in rows]
        finally:
            conn.close()

    def claim_pending_execution(
        self,
        execution_id: int,
        *,
        now: datetime | None = None,
    ) -> RemediationExecution | None:
        """Atomically transition a `pending` execution to `running`, or return None if claimed."""
        if execution_id <= 0:
            raise ValueError("execution_id must be >= 1")
        started_iso = format_utc(now or utc_now())
        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            cursor = conn.execute(
                """
                UPDATE remediation_executions
                SET status = ?, started_at = COALESCE(started_at, ?)
                WHERE id = ? AND status = ?
                """,
                (
                    RemediationStatus.RUNNING.value,
                    started_iso,
                    execution_id,
                    RemediationStatus.PENDING.value,
                ),
            )
            if cursor.rowcount != 1:
                conn.execute("ROLLBACK")
                return None
            row = conn.execute(
                "SELECT * FROM remediation_executions WHERE id = ?",
                (execution_id,),
            ).fetchone()
            conn.execute("COMMIT")
            return row_to_execution(row) if row is not None else None
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def get_status_summary(self, *, max_attempts: int) -> dict[str, int]:
        """Compute aggregate remediation counts safely from persistent history."""
        if max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        conn = get_connection(self.db_path)
        try:
            counts_row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_attempts,
                    SUM(CASE WHEN status IN ('pending', 'running') THEN 1 ELSE 0 END) AS active_executions,
                    SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending_executions,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running_executions,
                    SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) AS successful_attempts,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed_attempts,
                    SUM(CASE WHEN status = 'timed_out' THEN 1 ELSE 0 END) AS timed_out_attempts,
                    SUM(CASE WHEN status = 'dry_run' THEN 1 ELSE 0 END) AS dry_run_attempts
                FROM remediation_executions
                """
            ).fetchone()
            exhausted_row = conn.execute(
                """
                SELECT COUNT(*) AS cnt FROM (
                    SELECT incident_id
                    FROM remediation_executions
                    GROUP BY incident_id
                    HAVING COUNT(*) >= ?
                       AND SUM(CASE WHEN status = 'succeeded' THEN 1 ELSE 0 END) = 0
                )
                """,
                (max_attempts,),
            ).fetchone()
        finally:
            conn.close()

        def _num(key: str) -> int:
            if counts_row is None or counts_row[key] is None:
                return 0
            return int(counts_row[key])

        return {
            "total_attempts": _num("total_attempts"),
            "active_executions": _num("active_executions"),
            "pending_executions": _num("pending_executions"),
            "running_executions": _num("running_executions"),
            "successful_attempts": _num("successful_attempts"),
            "failed_attempts": _num("failed_attempts"),
            "timed_out_attempts": _num("timed_out_attempts"),
            "dry_run_attempts": _num("dry_run_attempts"),
            "exhausted_incidents": int(exhausted_row["cnt"]) if exhausted_row else 0,
        }

    def count_attempts(self, incident_id: int) -> int:
        """Return total recorded remediation attempts for an incident."""
        if incident_id <= 0:
            return 0
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM remediation_executions WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            return int(row["cnt"]) if row is not None else 0
        finally:
            conn.close()

    def get_latest_execution(self, incident_id: int) -> RemediationExecution | None:
        """Return the most recent remediation execution for an incident."""
        if incident_id <= 0:
            return None
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                """
                SELECT * FROM remediation_executions
                WHERE incident_id = ?
                ORDER BY attempt_number DESC, id DESC LIMIT 1
                """,
                (incident_id,),
            ).fetchone()
            return row_to_execution(row) if row is not None else None
        finally:
            conn.close()

    def get_latest_attempt_at(self, incident_id: int) -> datetime | None:
        """Return the UTC timestamp of the latest remediation attempt for an incident."""
        latest = self.get_latest_execution(incident_id)
        if latest is None:
            return None
        return latest.started_at or latest.created_at

    def get_active_execution(self, incident_id: int) -> RemediationExecution | None:
        """Return any active pending/running execution for an incident."""
        if incident_id <= 0:
            return None
        conn = get_connection(self.db_path)
        try:
            row = conn.execute(
                """
                SELECT * FROM remediation_executions
                WHERE incident_id = ? AND status IN ('pending', 'running')
                ORDER BY id DESC LIMIT 1
                """,
                (incident_id,),
            ).fetchone()
            return row_to_execution(row) if row is not None else None
        finally:
            conn.close()

    def update_status_in_tx(
        self,
        conn: sqlite3.Connection,
        execution_id: int,
        status: RemediationStatus | str,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float | None = None,
        ansible_exit_code: int | None = None,
        execution_output: str | None = None,
        failure_reason: str | None = None,
        now: datetime | None = None,
    ) -> RemediationExecution:
        """Transition a remediation record inside a caller-managed SQLite transaction."""
        if execution_id <= 0:
            raise ValueError("execution_id must be >= 1")
        if duration_seconds is not None and duration_seconds < 0:
            raise ValueError("duration_seconds must be >= 0")

        new_status = _coerce_status(status)
        effective_now = ensure_utc(now or utc_now())

        existing_row = conn.execute(
            "SELECT * FROM remediation_executions WHERE id = ?",
            (execution_id,),
        ).fetchone()
        if existing_row is None:
            raise LookupError(f"Remediation execution {execution_id} not found")

        existing = row_to_execution(existing_row)
        if existing.status in TERMINAL_REMEDIATION_STATUSES:
            raise ValueError(
                f"Cannot transition execution {execution_id} from terminal status "
                f"{existing.status.value!r} to {new_status.value!r}"
            )

        effective_started_at = (
            ensure_utc(started_at) if started_at is not None else existing.started_at
        )
        if new_status == RemediationStatus.RUNNING and effective_started_at is None:
            effective_started_at = effective_now

        effective_completed_at = existing.completed_at
        if completed_at is not None:
            effective_completed_at = ensure_utc(completed_at)
        elif new_status in TERMINAL_REMEDIATION_STATUSES:
            effective_completed_at = effective_now

        effective_duration = existing.duration_seconds
        if duration_seconds is not None:
            effective_duration = duration_seconds
        elif (
            new_status in TERMINAL_REMEDIATION_STATUSES
            and effective_completed_at is not None
            and effective_started_at is not None
        ):
            effective_duration = max(
                (effective_completed_at - effective_started_at).total_seconds(),
                0.0,
            )

        effective_exit_code = (
            ansible_exit_code if ansible_exit_code is not None else existing.ansible_exit_code
        )
        effective_output = (
            sanitize_execution_text(execution_output)
            if execution_output is not None
            else existing.execution_output
        )
        effective_reason = (
            sanitize_execution_text(failure_reason, max_length=1000)
            if failure_reason is not None
            else existing.failure_reason
        )

        conn.execute(
            """
            UPDATE remediation_executions
            SET status = ?,
                started_at = ?,
                completed_at = ?,
                duration_seconds = ?,
                ansible_exit_code = ?,
                execution_output = ?,
                failure_reason = ?
            WHERE id = ?
            """,
            (
                new_status.value,
                format_utc(effective_started_at) if effective_started_at else None,
                format_utc(effective_completed_at) if effective_completed_at else None,
                effective_duration,
                effective_exit_code,
                effective_output,
                effective_reason,
                execution_id,
            ),
        )
        updated_row = conn.execute(
            "SELECT * FROM remediation_executions WHERE id = ?",
            (execution_id,),
        ).fetchone()
        assert updated_row is not None
        return row_to_execution(updated_row)

    def update_status(
        self,
        execution_id: int,
        status: RemediationStatus | str,
        *,
        started_at: datetime | None = None,
        completed_at: datetime | None = None,
        duration_seconds: float | None = None,
        ansible_exit_code: int | None = None,
        execution_output: str | None = None,
        failure_reason: str | None = None,
        now: datetime | None = None,
    ) -> RemediationExecution:
        """Transition an existing remediation record's status and persist outcome metadata."""
        if execution_id <= 0:
            raise ValueError("execution_id must be >= 1")
        if duration_seconds is not None and duration_seconds < 0:
            raise ValueError("duration_seconds must be >= 0")

        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            updated = self.update_status_in_tx(
                conn,
                execution_id,
                status,
                started_at=started_at,
                completed_at=completed_at,
                duration_seconds=duration_seconds,
                ansible_exit_code=ansible_exit_code,
                execution_output=execution_output,
                failure_reason=failure_reason,
                now=now,
            )
            conn.execute("COMMIT")
            return updated
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def recover_stale_executions(
        self,
        stale_after_seconds: float,
        *,
        incident_id: int | None = None,
        exclude_execution_ids: Iterable[int] | None = None,
        now: datetime | None = None,
    ) -> list[RemediationExecution]:
        """Mark stale `pending`/`running` records as `timed_out` without assuming success."""
        if stale_after_seconds <= 0:
            raise ValueError("stale_after_seconds must be greater than 0")

        current_time = ensure_utc(now or utc_now())
        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            recovered = self._recover_stale_in_tx(
                conn,
                stale_after_seconds=stale_after_seconds,
                incident_id=incident_id,
                exclude_execution_ids=exclude_execution_ids,
                current_time=current_time,
            )
            conn.execute("COMMIT")
            return recovered
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def reserve_execution(
        self,
        request: RemediationRequest,
        settings: RemediationSettings,
        *,
        initial_status: RemediationStatus = RemediationStatus.RUNNING,
        stale_after_seconds: float | None = None,
        now: datetime | None = None,
    ) -> ReservationResult:
        """Atomically evaluate policy gates and reserve an execution slot."""
        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            result = self.reserve_execution_in_tx(
                conn,
                request,
                settings,
                initial_status=initial_status,
                stale_after_seconds=stale_after_seconds,
                now=now,
            )
            conn.execute("COMMIT")
            return result
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def reserve_execution_in_tx(
        self,
        conn: sqlite3.Connection,
        request: RemediationRequest,
        settings: RemediationSettings,
        *,
        initial_status: RemediationStatus = RemediationStatus.RUNNING,
        stale_after_seconds: float | None = None,
        now: datetime | None = None,
    ) -> ReservationResult:
        """Evaluate policy and reserve using a caller-owned transaction.

        The caller must hold a write transaction (BEGIN IMMEDIATE). This allows
        an incoming event, its incident, its remediation reservation, and its
        final processing status to commit or roll back as one unit.
        """
        if initial_status not in ACTIVE_REMEDIATION_STATUSES:
            raise ValueError(
                f"initial_status must be one of {[s.value for s in ACTIVE_REMEDIATION_STATUSES]}"
            )
        if not conn.in_transaction:
            raise RuntimeError("reserve_execution_in_tx requires an active caller-owned transaction")

        current_time = ensure_utc(now or utc_now())
        effective_stale_seconds = (
            settings.autoheal_remediation_stale_timeout_seconds
            if stale_after_seconds is None
            else stale_after_seconds
        )
        # Validate before creating the savepoint so invalid input cannot leave
        # a savepoint open in a caller-owned transaction.
        if effective_stale_seconds <= 0:
            raise ValueError("stale_after_seconds must be greater than 0")

        # Isolate reservation-specific writes. A policy denial or an exception
        # must not leave stale-row recovery changes in the caller's transaction.
        savepoint_name = "autoheal_reservation"
        conn.execute(f"SAVEPOINT {savepoint_name}")
        try:
            if request.incident_id > 0:
                self._recover_stale_in_tx(
                    conn,
                    stale_after_seconds=effective_stale_seconds,
                    incident_id=request.incident_id,
                    current_time=current_time,
                )

            incident = query_incident_snapshot(conn, request.incident_id)
            attempts, active_execution, latest_execution = query_remediation_summary(
                conn, request.incident_id
            )
            state = build_state_from_summary(
                attempts,
                active_execution,
                latest_execution,
                current_time=current_time,
                stale_after_seconds=effective_stale_seconds,
            )

            decision = evaluate_policy_gates(
                request=request,
                settings=settings,
                incident=incident,
                state=state,
                current_time=current_time,
            )
            if not decision.allowed:
                conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
                conn.execute(f"RELEASE SAVEPOINT {savepoint_name}")
                return ReservationResult(
                    reserved=False,
                    decision=decision,
                    execution=None,
                )

            max_row = conn.execute(
                "SELECT COALESCE(MAX(attempt_number), 0) AS max_attempt "
                "FROM remediation_executions WHERE incident_id = ?",
                (decision.incident_id,),
            ).fetchone()
            next_attempt = (
                int(max_row["max_attempt"]) if max_row is not None else 0
            ) + 1
            now_iso = format_utc(current_time)
            started_iso = now_iso if initial_status == RemediationStatus.RUNNING else None

            cursor = conn.execute(
                """
                INSERT INTO remediation_executions (
                    incident_id, service_name, action, status, attempt_number,
                    started_at, completed_at, duration_seconds, ansible_exit_code,
                    execution_output, failure_reason, dry_run, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?)
                """,
                (
                    decision.incident_id,
                    decision.service_name,
                    decision.action,
                    initial_status.value,
                    next_attempt,
                    started_iso,
                    1 if decision.dry_run else 0,
                    now_iso,
                ),
            )
            created_row = conn.execute(
                "SELECT * FROM remediation_executions WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
            if created_row is None:
                raise RuntimeError("Reserved remediation execution could not be read back")

            # Construct the return value before releasing the savepoint. If
            # conversion fails, the reservation insert is still rolled back.
            result = ReservationResult(
                reserved=True,
                decision=decision,
                execution=row_to_execution(created_row),
            )
            conn.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            return result
        except BaseException:
            # Preserve the original exception if SQLite cleanup itself fails.
            try:
                conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint_name}")
            except sqlite3.Error:
                pass
            try:
                conn.execute(f"RELEASE SAVEPOINT {savepoint_name}")
            except sqlite3.Error:
                pass
            raise

    @staticmethod
    def _recover_stale_in_tx(
        conn: sqlite3.Connection,
        *,
        stale_after_seconds: float,
        incident_id: int | None,
        exclude_execution_ids: Iterable[int] | None = None,
        current_time: datetime,
    ) -> list[RemediationExecution]:
        excluded = {int(eid) for eid in (exclude_execution_ids or ())}
        cutoff = current_time - timedelta(seconds=stale_after_seconds)
        if incident_id is not None:
            rows = conn.execute(
                """
                SELECT * FROM remediation_executions
                WHERE incident_id = ? AND status IN ('pending', 'running')
                ORDER BY id ASC
                """,
                (incident_id,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM remediation_executions
                WHERE status IN ('pending', 'running')
                ORDER BY id ASC
                """
            ).fetchall()

        recovered: list[RemediationExecution] = []
        now_iso = format_utc(current_time)
        reason = (
            f"Marked timed_out after exceeding stale running threshold "
            f"({stale_after_seconds}s); worker interrupted or orphaned."
        )

        for row in rows:
            candidate = row_to_execution(row)
            if candidate.id in excluded:
                continue
            reference_ts = candidate.started_at or candidate.created_at
            if reference_ts > cutoff:
                continue

            duration = max((current_time - reference_ts).total_seconds(), 0.0)
            conn.execute(
                """
                UPDATE remediation_executions
                SET status = ?, completed_at = ?, duration_seconds = ?, failure_reason = ?
                WHERE id = ?
                """,
                (
                    RemediationStatus.TIMED_OUT.value,
                    now_iso,
                    duration,
                    reason,
                    candidate.id,
                ),
            )
            updated_row = conn.execute(
                "SELECT * FROM remediation_executions WHERE id = ?",
                (candidate.id,),
            ).fetchone()
            if updated_row is not None:
                recovered.append(row_to_execution(updated_row))

        return recovered
