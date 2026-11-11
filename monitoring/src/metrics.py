"""Prometheus-compatible metrics with SQLite persistence for cross-container sharing."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from .models import CheckOutcome, HealthCheckResult, ServiceState, StateEvaluation

DURATION_BUCKETS: tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)


class MonitorMetrics:
    """Maintains in-process Prometheus metrics and persists cumulative values to SQLite."""

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
        self.open_incidents = Gauge(
            "autoheal_open_incidents",
            "Current count of open incidents for the service",
            labelnames=("service",),
            registry=self.registry,
        )

    def record(self, result: HealthCheckResult, evaluation: StateEvaluation) -> None:
        """Record check metrics, state gauges, and incident events."""
        duration_seconds = max(result.response_time_ms / 1000.0, 0.0)
        outcome_label = result.outcome.value
        service = result.service_name

        self.checks_total.labels(service=service, outcome=outcome_label).inc()
        self.check_duration_seconds.labels(service=service).observe(duration_seconds)

        is_up = 1.0 if evaluation.current_state == ServiceState.HEALTHY else 0.0
        self.service_up.labels(service=service).set(is_up)
        self.consecutive_failures.labels(service=service).set(
            float(evaluation.status_record.consecutive_failures)
        )
        self.consecutive_successes.labels(service=service).set(
            float(evaluation.status_record.consecutive_successes)
        )
        self.open_incidents.labels(service=service).set(
            1.0 if evaluation.active_incident is not None else 0.0
        )

        incident_events: list[str] = []
        if evaluation.incident_created is not None:
            self.incidents_total.labels(service=service, event="created").inc()
            incident_events.append("created")
        if evaluation.incident_resolved is not None:
            self.incidents_total.labels(service=service, event="resolved").inc()
            incident_events.append("resolved")

        self._persist_to_sqlite(
            service=service,
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

        conn = sqlite3.connect(self.db_path, timeout=5.0)
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            with conn:
                self._increment_counter(
                    conn,
                    metric_name="autoheal_health_checks_total",
                    labels_json=check_labels,
                )
                for event in incident_events:
                    event_labels = json.dumps({"event": event, "service": service}, sort_keys=True)
                    self._increment_counter(
                        conn,
                        metric_name="autoheal_incidents_total",
                        labels_json=event_labels,
                    )
                self._observe_histogram(
                    conn,
                    metric_name="autoheal_health_check_duration_seconds",
                    labels_json=service_labels,
                    value=duration_seconds,
                )
        finally:
            conn.close()

    @staticmethod
    def _increment_counter(conn: sqlite3.Connection, metric_name: str, labels_json: str) -> None:
        conn.execute(
            """
            INSERT INTO monitoring_counters (metric_name, labels_json, value)
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
            INSERT INTO monitoring_histogram_totals (metric_name, labels_json, total_sum, total_count)
            VALUES (?, ?, ?, 1)
            ON CONFLICT(metric_name, labels_json)
            DO UPDATE SET
                total_sum = total_sum + excluded.total_sum,
                total_count = total_count + 1
            """,
            (metric_name, labels_json, value),
        )
        for bucket in DURATION_BUCKETS:
            inc = 1 if value <= bucket else 0
            conn.execute(
                """
                INSERT INTO monitoring_histogram_buckets (metric_name, labels_json, le, bucket_count)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(metric_name, labels_json, le)
                DO UPDATE SET bucket_count = bucket_count + excluded.bucket_count
                """,
                (metric_name, labels_json, str(bucket), inc),
            )
        conn.execute(
            """
            INSERT INTO monitoring_histogram_buckets (metric_name, labels_json, le, bucket_count)
            VALUES (?, ?, '+Inf', 1)
            ON CONFLICT(metric_name, labels_json, le)
            DO UPDATE SET bucket_count = bucket_count + 1
            """,
            (metric_name, labels_json),
        )


def all_known_outcomes() -> tuple[str, ...]:
    """Return all health check outcome label strings."""
    return tuple(item.value for item in CheckOutcome)

