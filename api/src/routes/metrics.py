"""Prometheus-compatible metrics route reading persisted monitoring telemetry."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Counter, generate_latest
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, HistogramMetricFamily
from prometheus_client.registry import Collector

from ..config import get_settings
from ..database import ensure_database, get_connection

router = APIRouter(prefix="/api/v1", tags=["metrics"])


class AutoHealDbCollector(Collector):
    """Collects monitoring counters, histograms, and service gauges from SQLite."""

    def __init__(self, db_path_provider: Callable[[], str]) -> None:
        self._db_path_provider = db_path_provider

    def collect(self) -> Iterator[CounterMetricFamily | GaugeMetricFamily | HistogramMetricFamily]:
        db_path = self._db_path_provider()
        ensure_database(db_path)

        checks_family = CounterMetricFamily(
            "autoheal_health_checks_total",
            "Total number of health check probes executed",
            labels=["service", "outcome"],
        )
        incidents_family = CounterMetricFamily(
            "autoheal_incidents_total",
            "Total number of incident lifecycle events",
            labels=["service", "event"],
        )
        duration_family = HistogramMetricFamily(
            "autoheal_health_check_duration_seconds",
            "Duration of health check HTTP requests in seconds",
            labels=["service"],
        )
        service_up_family = GaugeMetricFamily(
            "autoheal_service_up",
            "Whether the monitored service is healthy (1) or unhealthy/unknown (0)",
            labels=["service"],
        )
        failures_family = GaugeMetricFamily(
            "autoheal_consecutive_failures",
            "Current consecutive health check failure count",
            labels=["service"],
        )
        successes_family = GaugeMetricFamily(
            "autoheal_consecutive_successes",
            "Current consecutive health check success count",
            labels=["service"],
        )
        open_incidents_family = GaugeMetricFamily(
            "autoheal_open_incidents",
            "Current count of open incidents for the service",
            labels=["service"],
        )

        conn = get_connection(db_path)
        try:
            counter_rows = conn.execute(
                "SELECT metric_name, labels_json, value FROM monitoring_counters"
            ).fetchall()
            for row in counter_rows:
                labels = json.loads(row["labels_json"])
                if row["metric_name"] == "autoheal_health_checks_total":
                    checks_family.add_metric(
                        [labels.get("service", "web"), labels.get("outcome", "unknown")],
                        float(row["value"]),
                    )
                elif row["metric_name"] == "autoheal_incidents_total":
                    incidents_family.add_metric(
                        [labels.get("service", "web"), labels.get("event", "unknown")],
                        float(row["value"]),
                    )

            total_rows = conn.execute(
                """
                SELECT labels_json, total_sum, total_count
                FROM monitoring_histogram_totals
                WHERE metric_name = 'autoheal_health_check_duration_seconds'
                """
            ).fetchall()
            for total_row in total_rows:
                labels_json = total_row["labels_json"]
                labels = json.loads(labels_json)
                bucket_rows = conn.execute(
                    """
                    SELECT le, bucket_count
                    FROM monitoring_histogram_buckets
                    WHERE metric_name = 'autoheal_health_check_duration_seconds'
                      AND labels_json = ?
                    """,
                    (labels_json,),
                ).fetchall()
                sorted_buckets = sorted(
                    [(row["le"], int(row["bucket_count"])) for row in bucket_rows],
                    key=lambda item: float("inf") if item[0] == "+Inf" else float(item[0]),
                )
                duration_family.add_metric(
                    [labels.get("service", "web")],
                    buckets=sorted_buckets,
                    sum_value=float(total_row["total_sum"]),
                )

            open_counts: dict[str, int] = {}
            open_rows = conn.execute(
                """
                SELECT service_name, COUNT(*) AS cnt
                FROM incidents
                WHERE status = 'open'
                GROUP BY service_name
                """
            ).fetchall()
            for row in open_rows:
                open_counts[row["service_name"]] = int(row["cnt"])

            status_rows = conn.execute("SELECT * FROM service_status").fetchall()
            for row in status_rows:
                svc = row["service_name"]
                service_up_family.add_metric([svc], 1.0 if row["status"] == "healthy" else 0.0)
                failures_family.add_metric([svc], float(row["consecutive_failures"]))
                successes_family.add_metric([svc], float(row["consecutive_successes"]))
                open_incidents_family.add_metric([svc], float(open_counts.get(svc, 0)))
        finally:
            conn.close()

        yield checks_family
        yield duration_family
        yield service_up_family
        yield failures_family
        yield successes_family
        yield incidents_family
        yield open_incidents_family


METRICS_REGISTRY = CollectorRegistry()
API_REQUESTS_TOTAL = Counter(
    "autoheal_api_requests_total",
    "Total HTTP requests served by the AutoHeal control plane API",
    labelnames=("method", "path", "status_code"),
    registry=METRICS_REGISTRY,
)
METRICS_REGISTRY.register(AutoHealDbCollector(lambda: get_settings().autoheal_db_path))


@router.get("/metrics", response_class=PlainTextResponse)
def get_prometheus_metrics() -> PlainTextResponse:
    """Expose Prometheus-compatible monitoring and API metrics."""
    payload = generate_latest(METRICS_REGISTRY).decode("utf-8")
    return PlainTextResponse(
        content=payload,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )

