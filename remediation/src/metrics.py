"""Metrics helpers with optional SQLite persistence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from .database import increment_sql_counter, record_incident_event_in_tx

DURATION_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class MonitorMetrics:
    """Maintains in-process metrics and optionally persists cumulative values to SQLite."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.registry = CollectorRegistry()

        self.checks_total = Counter(
            "autoheal_health_checks_total",
            "Total number of health check probes executed",
            labelnames=("service", "outcome"),
            registry=self.registry,
        )
        self.check_duration_seconds = Histogram(
            "autoheal_health_check_duration_seconds",
            "Duration of health check HTTP requests in seconds",
            labelnames=("service",),
            buckets=DURATION_BUCKETS,
            registry=self.registry,
        )
        self.service_up = Gauge(
            "autoheal_service_up",
            "Whether the monitored service is healthy (1) or unhealthy/unknown (0)",
            labelnames=("service",),
            registry=self.registry,
        )
        self.consecutive_failures = Gauge(
            "autoheal_consecutive_failures",
            "Current consecutive health check failure count",
            labelnames=("service",),
            registry=self.registry,
        )
        self.consecutive_successes = Gauge(
            "autoheal_consecutive_successes",
            "Current consecutive health check success count",
            labelnames=("service",),
            registry=self.registry,
        )
        self.incidents_total = Counter(
            "autoheal_incidents_total",
            "Total number of incident lifecycle events",
            labelnames=("service", "event"),
            registry=self.registry,
        )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0, isolation_level=None)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def record_incident_resolved_in_tx(conn: sqlite3.Connection, service: str) -> None:
        """Persist a resolved-incident counter increment inside an existing transaction."""
        record_incident_event_in_tx(conn, service, "resolved")

    def record_incident_resolved(self, service: str) -> None:
        """Persist a single resolved-incident counter increment to SQLite."""
        self.incidents_total.labels(service=service, event="resolved").inc()
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self.record_incident_resolved_in_tx(conn, service)
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    def record(self, result, evaluation) -> None:
        """Record check outcome and evaluation gauges."""
        outcome_label = result.outcome.value if hasattr(result.outcome, "value") else str(result.outcome)
        self.checks_total.labels(service=result.service_name, outcome=outcome_label).inc()
        self.service_up.labels(service=result.service_name).set(1.0 if result.healthy else 0.0)
        self.consecutive_failures.labels(service=result.service_name).set(evaluation.consecutive_failures)
        self.consecutive_successes.labels(service=result.service_name).set(evaluation.consecutive_successes)

        incident_events: list[str] = []
        if evaluation.incident_created is not None:
            self.incidents_total.labels(service=result.service_name, event="created").inc()
            incident_events.append("created")
        if evaluation.incident_resolved is not None:
            self.incidents_total.labels(service=result.service_name, event="resolved").inc()
            incident_events.append("resolved")

        duration_seconds = max((result.response_time_ms or 0.0) / 1000.0, 0.0)
        self.check_duration_seconds.labels(service=result.service_name).observe(duration_seconds)
        self._persist_to_sqlite(
            service=result.service_name,
            outcome=outcome_label,
            duration_seconds=duration_seconds,
            incident_events=incident_events,
        )

    def render_prometheus(self) -> str:
        """Render in-process Prometheus exposition text."""
        return generate_latest(self.registry).decode("utf-8")

    def _persist_to_sqlite(
        self,
        service: str,
        outcome: str,
        duration_seconds: float,
        incident_events: list[str],
    ) -> None:
        check_labels = json.dumps({"outcome": outcome, "service": service}, sort_keys=True)
        service_labels = json.dumps({"service": service}, sort_keys=True)

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            increment_sql_counter(
                conn,
                "monitoring_counters",
                "autoheal_health_checks_total",
                check_labels,
            )
            for event in incident_events:
                event_labels = json.dumps({"event": event, "service": service}, sort_keys=True)
                increment_sql_counter(
                    conn,
                    "monitoring_counters",
                    "autoheal_incidents_total",
                    event_labels,
                )
            conn.execute(
                """
                INSERT INTO monitoring_histogram_totals (metric_name, labels_json, total_sum, total_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(metric_name, labels_json)
                DO UPDATE SET
                    total_sum = total_sum + excluded.total_sum,
                    total_count = total_count + 1
                """,
                ("autoheal_health_check_duration_seconds", service_labels, duration_seconds),
            )
            for bucket in DURATION_BUCKETS:
                inc = 1 if duration_seconds <= bucket else 0
                conn.execute(
                    """
                    INSERT INTO monitoring_histogram_buckets (metric_name, labels_json, le, bucket_count)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(metric_name, labels_json, le)
                    DO UPDATE SET bucket_count = bucket_count + excluded.bucket_count
                    """,
                    ("autoheal_health_check_duration_seconds", service_labels, str(bucket), inc),
                )
            conn.execute(
                """
                INSERT INTO monitoring_histogram_buckets (metric_name, labels_json, le, bucket_count)
                VALUES (?, ?, '+Inf', 1)
                ON CONFLICT(metric_name, labels_json, le)
                DO UPDATE SET bucket_count = bucket_count + 1
                """,
                ("autoheal_health_check_duration_seconds", service_labels),
            )
            conn.execute("COMMIT")
        except Exception:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()
