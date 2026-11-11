"""Configuration validation tests for Phase 3 observability artifacts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_yaml(rel_path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / rel_path).read_text(encoding="utf-8"))


def test_prometheus_scrape_configuration() -> None:
    cfg = _load_yaml("observability/prometheus/prometheus.yml")

    assert cfg["global"]["scrape_interval"] == "5s"
    assert cfg["global"]["evaluation_interval"] == "5s"
    assert "/etc/prometheus/rules/*.yml" in cfg["rule_files"]

    am_targets = cfg["alerting"]["alertmanagers"][0]["static_configs"][0]["targets"]
    assert "alertmanager:9093" in am_targets

    jobs = {job["job_name"]: job for job in cfg["scrape_configs"]}
    assert "autoheal-api" in jobs
    api_job = jobs["autoheal-api"]
    assert api_job["metrics_path"] == "/api/v1/metrics"
    assert "api:8000" in api_job["static_configs"][0]["targets"]
    # Avoid shadowing metric-level `service="web"` label into `exported_service`.
    assert "service" not in api_job["static_configs"][0].get("labels", {})


def test_prometheus_alert_rules_cover_required_scenarios() -> None:
    rules_doc = _load_yaml("observability/prometheus/rules/autoheal_alerts.yml")
    groups = rules_doc["groups"]
    assert len(groups) >= 1

    rules = {rule["alert"]: rule for group in groups for rule in group["rules"]}
    expected_alerts = {
        "AutoHealServiceDown",
        "AutoHealConsecutiveCheckFailures",
        "AutoHealMonitoringProbeFailures",
        "AutoHealMonitoringEngineStalled",
        "AutoHealApiDown",
        "AutoHealApiServerErrors",
        "AutoHealUnresolvedIncident",
    }
    assert expected_alerts.issubset(rules.keys())

    for name, rule in rules.items():
        assert rule.get("expr"), f"{name} missing expr"
        assert rule.get("for"), f"{name} missing for duration"
        assert rule.get("labels", {}).get("severity") in {"critical", "warning"}
        assert rule.get("annotations", {}).get("summary")
        assert rule.get("annotations", {}).get("description")


def test_alertmanager_grouping_deduplication_and_receivers() -> None:
    am = _load_yaml("observability/alertmanager/alertmanager.yml")

    route = am["route"]
    assert {"alertname", "service", "severity"}.issubset(set(route["group_by"]))
    assert route["group_wait"]
    assert route["group_interval"]
    assert route["repeat_interval"]

    receivers = {item["name"] for item in am["receivers"]}
    assert route["receiver"] in receivers
    for subroute in route.get("routes", []):
        assert subroute["receiver"] in receivers

    assert len(am.get("inhibit_rules", [])) >= 2


def test_grafana_provisioning_and_dashboard() -> None:
    ds_doc = _load_yaml("observability/grafana/provisioning/datasources/prometheus.yml")
    ds = ds_doc["datasources"][0]
    assert ds["type"] == "prometheus"
    assert ds["uid"] == "autoheal-prometheus"
    assert ds["url"] == "http://prometheus:9090"
    assert ds["isDefault"] is True

    provider_doc = _load_yaml("observability/grafana/provisioning/dashboards/dashboards.yml")
    provider = provider_doc["providers"][0]
    assert provider["options"]["path"] == "/etc/grafana/provisioning/dashboards"

    dashboard = json.loads(
        (REPO_ROOT / "observability/grafana/provisioning/dashboards/autoheal_overview.json").read_text(
            encoding="utf-8"
        )
    )
    assert dashboard["uid"] == "autoheal-overview"
    assert len(dashboard["panels"]) >= 8

    all_exprs = []
    for panel in dashboard["panels"]:
        assert panel["datasource"]["uid"] == "autoheal-prometheus"
        for target in panel["targets"]:
            all_exprs.append(target["expr"])

    joined = "\n".join(all_exprs)
    for expected_metric in (
        "autoheal_service_up",
        "autoheal_open_incidents",
        "autoheal_consecutive_failures",
        "autoheal_health_checks_total",
        "autoheal_health_check_duration_seconds_bucket",
        "autoheal_api_requests_total",
        "autoheal_incidents_total",
        "up{job=",
    ):
        assert expected_metric in joined


def test_compose_preserves_phase2_and_hardens_phase3() -> None:
    compose = _load_yaml("compose.yaml")
    services = compose["services"]

    assert {"web", "monitor", "api", "prometheus", "alertmanager", "grafana"}.issubset(
        services.keys()
    )
    assert {"prometheus-data", "alertmanager-data", "grafana-data"}.issubset(
        compose["volumes"].keys()
    )
    assert compose["networks"]["autoheal-network"]["name"] == "autoheal-network"

    for svc_name in ("monitor", "api", "prometheus", "alertmanager", "grafana"):
        svc = services[svc_name]
        assert svc["read_only"] is True
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]
        for vol in svc.get("volumes", []):
            assert "/var/run/docker.sock" not in str(vol)

    for svc_name in ("web", "prometheus", "alertmanager", "grafana"):
        assert "healthcheck" in services[svc_name]
