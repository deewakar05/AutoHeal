"""SQLite-backed Prometheus remediation metrics persistence preventing double counting."""

from __future__ import annotations

import json
import math
import sqlite3

from .database import ensure_remediation_database, format_utc, get_connection, utc_now
from .models import TERMINAL_REMEDIATION_STATUSES, RemediationExecution, RemediationStatus

REMEDIATION_DURATION_BUCKETS: tuple[float, ...] = (
    0.1,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    20.0,
    30.0,
    60.0,
    120.0,
    180.0,
)


class RemediationMetricsRecorder:
    """Atomically persists cumulative remediation metrics into shared SQLite tables."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        ensure_remediation_database(db_path)

    def record_attempt(self, execution: RemediationExecution) -> bool:
        """Increment `autoheal_remediation_attempts_total` once per execution ID."""
        service_action_labels = json.dumps(
            {"action": execution.action, "service": execution.service_name},
            sort_keys=True,
        )
        now_iso = format_utc(utc_now())
        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            if not self._claim_metric_event(conn, execution.id, "attempt", now_iso):
                conn.execute("ROLLBACK")
                return False
            self._increment_counter(
                conn,
                metric_name="autoheal_remediation_attempts_total",
                labels_json=service_action_labels,
            )
            conn.execute("COMMIT")
            return True
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record_terminal_in_tx(
        self,
        conn: sqlite3.Connection,
        execution: RemediationExecution,
        *,
        max_attempts: int | None = None,
        failure_outcome: str | None = None,
        record_failure_metric: bool = True,
    ) -> bool:
        """Persist terminal outcome counters and duration inside a caller-managed transaction."""
        if execution.status not in TERMINAL_REMEDIATION_STATUSES:
            return False

        service_action_labels = json.dumps(
            {"action": execution.action, "service": execution.service_name},
            sort_keys=True,
        )
        now_iso = format_utc(utc_now())

        # Ensure attempt is always counted at least once even if crashed before explicit attempt call.
        if self._claim_metric_event(conn, execution.id, "attempt", now_iso):
            self._increment_counter(
                conn,
                metric_name="autoheal_remediation_attempts_total",
                labels_json=service_action_labels,
            )

        if not self._claim_metric_event(conn, execution.id, "terminal", now_iso):
            return False

        if (
            execution.duration_seconds is not None
            and math.isfinite(float(execution.duration_seconds))
            and execution.duration_seconds >= 0
        ):
            self._observe_histogram(
                conn,
                metric_name="autoheal_remediation_duration_seconds",
                labels_json=service_action_labels,
                value=float(execution.duration_seconds),
            )

        if execution.status == RemediationStatus.SUCCEEDED:
            self._increment_counter(
                conn,
                metric_name="autoheal_remediation_success_total",
                labels_json=service_action_labels,
            )
        elif execution.status == RemediationStatus.TIMED_OUT:
            self._increment_counter(
                conn,
                metric_name="autoheal_remediation_timeouts_total",
                labels_json=service_action_labels,
            )
            fail_labels = json.dumps(
                {
                    "action": execution.action,
                    "outcome": failure_outcome or "timed_out",
                    "service": execution.service_name,
                },
                sort_keys=True,
            )
            self._increment_counter(
                conn,
                metric_name="autoheal_remediation_failures_total",
                labels_json=fail_labels,
            )
        elif execution.status == RemediationStatus.FAILED:
            if record_failure_metric:
                fail_labels = json.dumps(
                    {
                        "action": execution.action,
                        "outcome": failure_outcome or "failed",
                        "service": execution.service_name,
                    },
                    sort_keys=True,
                )
                self._increment_counter(
                    conn,
                    metric_name="autoheal_remediation_failures_total",
                    labels_json=fail_labels,
                )

        # Only non-dry-run failures/timeouts trigger attempts-exhausted alert metric.
        if (
            max_attempts is not None
            and not execution.dry_run
            and (execution.status == RemediationStatus.TIMED_OUT or (execution.status == RemediationStatus.FAILED and record_failure_metric))
            and execution.attempt_number >= max_attempts
        ):
            ex_cursor = conn.execute(
                """
                INSERT OR IGNORE INTO remediation_exhausted_incidents (
                    incident_id, service_name, action, recorded_at
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    execution.incident_id,
                    execution.service_name,
                    execution.action,
                    now_iso,
                ),
            )
            if ex_cursor.rowcount == 1:
                self._increment_counter(
                    conn,
                    metric_name="autoheal_remediation_attempts_exhausted_total",
                    labels_json=service_action_labels,
                )

        return True

    def record_terminal(
        self,
        execution: RemediationExecution,
        *,
        max_attempts: int | None = None,
        failure_outcome: str | None = None,
        record_failure_metric: bool = True,
    ) -> bool:
        """Record terminal outcome counters and duration once per execution ID."""
        if execution.status not in TERMINAL_REMEDIATION_STATUSES:
            return False

        conn = get_connection(self.db_path, manual_transactions=True)
        try:
            conn.execute("BEGIN IMMEDIATE")
            recorded = self.record_terminal_in_tx(
                conn,
                execution,
                max_attempts=max_attempts,
                failure_outcome=failure_outcome,
                record_failure_metric=record_failure_metric,
            )
            conn.execute("COMMIT")
            return recorded
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @staticmethod
    def _claim_metric_event(
        conn: sqlite3.Connection,
        execution_id: int,
        event_type: str,
        recorded_at: str,
    ) -> bool:
        cursor = conn.execute(
            """
            INSERT OR IGNORE INTO remediation_metric_events (execution_id, event_type, recorded_at)
            VALUES (?, ?, ?)
            """,
            (execution_id, event_type, recorded_at),
        )
        return cursor.rowcount == 1

    @staticmethod
    def _increment_counter(conn: sqlite3.Connection, metric_name: str, labels_json: str) -> None:
        conn.execute(
            """
            INSERT INTO remediation_counters (metric_name, labels_json, value)
            VALUES (?, ?, 1)
            ON CONFLICT(metric_name, labels_json)
            DO UPDATE SET value = value + 1
            """,
            (metric_name, labels_json),
        )

    @staticmethod
    def _observe_histogram(
        conn: sqlite3.Connection,
        metric_name: str,
        labels_json: str,
        value: float,
    ) -> None:
        conn.execute(
            """
            INSERT INTO remediation_histogram_totals (metric_name, labels_json, total_sum, total_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(metric_name, labels_json)
            DO UPDATE SET
                total_sum = total_sum + excluded.total_sum,
                total_count = total_count + 1
            """,
            (metric_name, labels_json, value),
        )
        for bucket in REMEDIATION_DURATION_BUCKETS:
            inc = 1 if value <= bucket else 0
            conn.execute(
                """
                INSERT INTO remediation_histogram_buckets (metric_name, labels_json, le, bucket_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(metric_name, labels_json, le)
                DO UPDATE SET bucket_count = bucket_count + excluded.bucket_count
                """,
                (metric_name, labels_json, str(bucket), inc),
            )
        conn.execute(
            """
            INSERT INTO remediation_histogram_buckets (metric_name, labels_json, le, bucket_count)
            VALUES (?, ?, '+Inf', 1)
            ON CONFLICT(metric_name, labels_json, le)
            DO UPDATE SET bucket_count = bucket_count + 1
            """,
            (metric_name, labels_json),
        )
