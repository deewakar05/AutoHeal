# AutoHeal — Testing & Validation Report (Phase 3)

All tests and live verification checks were executed on macOS Apple Silicon M1 (`arm64` / `aarch64`) with Docker `29.1.3`, Docker Compose `v2.40.3-desktop.1`, and Python `3.14.7`.

## 1. Automated Test Suite (`pytest`)

```bash
.venv/bin/python -m pytest -v tests/
```

- **Result:** `30 passed in 0.56s` (Phase 2 unit/API tests + 5 new Phase 3 observability validation tests in `tests/test_observability_config.py`).

## 2. Official Tool Config Validation (`promtool` & `amtool`)

```bash
docker exec autoheal-prometheus promtool check config /etc/prometheus/prometheus.yml
docker exec autoheal-alertmanager amtool check-config /etc/alertmanager/alertmanager.yml
```

- `promtool`: `SUCCESS: 1 rule files found`, `SUCCESS: /etc/prometheus/prometheus.yml is valid prometheus config file syntax`, `SUCCESS: 7 rules found`.
- `amtool`: `SUCCESS`, `2 inhibit rules`, `3 receivers`.

## 3. Live Metric Collection & Grafana Dashboard Verification

- **Prometheus Targets (`/api/v1/targets`):** `[('autoheal-api', 'up', 'http://api:8000/api/v1/metrics'), ('prometheus', 'up', 'http://localhost:9090/metrics')]`.
- **Grafana Datasource & Dashboard:** Provisioned `Prometheus` (`uid: autoheal-prometheus`, default) and `AutoHeal Infrastructure Overview` (`uid: autoheal-overview`, 10 panels).
- **Live Grafana Proxy Query (`/api/ds/query`):**
  - `autoheal_service_up{service="web"}` returned `1` (with `service="web"` label preserved intact).
  - `sum by (outcome) (rate(autoheal_health_checks_total{service="web"}[1m])) * 60` returned live check rate (`outcome="success"` and `outcome="connection_error"`).

## 4. Alert Firing, Alertmanager Grouping/Inhibition & Resolution

1. **Outage Injection (`docker compose stop web` + 42s wait):**
   - **Prometheus `/api/v1/alerts`:** 4 alerts entered `firing`: `AutoHealServiceDown` (`critical`), `AutoHealConsecutiveCheckFailures` (`warning`), `AutoHealMonitoringProbeFailures` (`warning`), `AutoHealUnresolvedIncident` (`critical`).
   - **Alertmanager `/api/v2/alerts`:**
     - `AutoHealServiceDown` (`critical`) -> `active`, receiver `autoheal-critical`.
     - `AutoHealUnresolvedIncident` (`critical`) -> `active`, receiver `autoheal-critical`.
     - `AutoHealConsecutiveCheckFailures` (`warning`) -> `suppressed` (`inhibitedBy: ['b14784e598f877a5']`), receiver `autoheal-warning`.
     - `AutoHealMonitoringProbeFailures` (`warning`) -> `suppressed` (`inhibitedBy: ['b14784e598f877a5']`), receiver `autoheal-warning`.
   - **Grafana Query:** `autoheal_service_up{service="web"}` = `0`, `count(ALERTS{alertstate="firing"})` = `4`.
2. **Recovery (`docker compose start web` + 65s wait):**
   - **Prometheus `/api/v1/alerts`:** `[]`
   - **Alertmanager `/api/v2/alerts`:** `[]`
   - **Grafana Query:** `autoheal_service_up{service="web"}` = `1`, `count(ALERTS{alertstate="firing"})` = `0`.
   - **FastAPI `/api/v1/incidents`:** `total: 2, open_count: 0`, incident `2` marked `resolved` (`failure_count: 12`).

## 5. Observability Restart Persistence (`docker compose restart prometheus alertmanager grafana`)

- Named volumes verified: `autoheal_alertmanager-data`, `autoheal_grafana-data`, `autoheal_prometheus-data`.
- After restart, all 6 containers returned to `(healthy)` (`arm64/linux`).
- Pre-restart TSDB history survived in Prometheus: `min_over_time(autoheal_service_up{service="web"}[10m])` returned `0` across `39` samples (`samples_over_10m: 39`).
- Alertmanager reported `AM version: 0.28.1 cluster: ready`; Grafana reported `database: ok` (`11.6.0`) with `autoheal-overview` dashboard available.

## 6. Verified Live vs. Statically Validated Rules

- **Verified Live (Fired, Routed/Inhibited, and Resolved):** `AutoHealServiceDown`, `AutoHealConsecutiveCheckFailures`, `AutoHealMonitoringProbeFailures`, `AutoHealUnresolvedIncident`.
- **Statically Validated & Loaded (`promtool`, `amtool`, `pytest`, `/api/v1/rules`), Not Fault-Injected Live:** `AutoHealMonitoringEngineStalled`, `AutoHealApiDown`, `AutoHealApiServerErrors`, and external webhook/Slack/SMTP delivery via `ALERTMANAGER_CONFIG_FILE`.
