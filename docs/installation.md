# AutoHeal — Installation Guide (Phase 3)

## Prerequisites

- **Docker Desktop** (verified on macOS Apple Silicon M1 `arm64`, Docker `29.1.3`, Compose `v2.40.3-desktop.1`)
- **Git** and **curl**
- **Python 3.10+** (for running the `pytest` validation suite locally)

## 1. Environment Configuration

Copy the template if you do not yet have a local `.env`:

```bash
cp .env.example .env
```

Phase 3 environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PROMETHEUS_PORT` | `9090` | Host port for Prometheus UI & API |
| `ALERTMANAGER_PORT` | `9093` | Host port for Alertmanager UI & API |
| `ALERTMANAGER_CONFIG_FILE` | `./observability/alertmanager/alertmanager.yml` | Path to Alertmanager config (override with `*.local.yml` for private webhook/Slack secrets) |
| `GRAFANA_PORT` | `3000` | Host port for Grafana UI |
| `GRAFANA_ADMIN_USER` | `admin` | Grafana admin username |
| `GRAFANA_ADMIN_PASSWORD` | `admin` | Grafana admin password (change in `.env` for non-local use) |

## 2. Start the Full Phase 3 Stack

```bash
docker compose config
docker compose up --build -d
docker compose ps
```

Startup dependency order:
1. `autoheal-web` -> `healthy`
2. `autoheal-monitor` -> `healthy`
3. `autoheal-api` & `autoheal-alertmanager` -> `healthy`
4. `autoheal-prometheus` -> `healthy`
5. `autoheal-grafana` -> `healthy`

## 3. Access Endpoints & Dashboards

- **Web App:** `http://localhost:8080/` (`http://localhost:8080/health`)
- **FastAPI Control Plane:** `http://localhost:8000/api/v1/status`, `/api/v1/incidents`, `/api/v1/metrics`
- **Prometheus:** `http://localhost:9090/` (`/targets`, `/alerts`, `/rules`)
- **Alertmanager:** `http://localhost:9093/` (`/#/alerts`)
- **Grafana:** `http://localhost:3000/` (Dashboard: **AutoHeal → AutoHeal Infrastructure Overview**)

## 4. Validate Configurations & Automated Tests

```bash
docker exec autoheal-prometheus promtool check config /etc/prometheus/prometheus.yml
docker exec autoheal-alertmanager amtool check-config /etc/alertmanager/alertmanager.yml
.venv/bin/python -m pytest -v tests/
```

## 5. Stop & Persistence Notes

- `docker compose down` stops containers while preserving `./data/autoheal.db` and the Docker volumes `autoheal_prometheus-data`, `autoheal_alertmanager-data`, and `autoheal_grafana-data`.
- Only `docker compose down -v` removes named observability volumes.
