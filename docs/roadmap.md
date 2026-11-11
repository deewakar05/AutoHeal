# AutoHeal — Development Roadmap

## Phase 1 — Infrastructure Foundation (Completed)

- [x] Docker Compose setup with `nginx:alpine`, `autoheal-network`, `:ro` mounts, and health checks
- [x] Responsive landing page (`/`) and JSON `/health` endpoint
- [x] `.env.example` template, `.gitignore`, and Apple Silicon `arm64` validation

## Phase 2 — Python Monitoring Engine & FastAPI Control Plane (Completed)

- [x] Asynchronous Python monitoring engine (`httpx`) probing `http://web/health`
- [x] Threshold state machine (`MONITOR_FAILURE_THRESHOLD`, `MONITOR_RECOVERY_THRESHOLD`)
- [x] Persistent SQLite incident manager (creation, deduplication, resolution, restart persistence)
- [x] FastAPI control plane (`/health`, `/api/v1/status`, `/api/v1/incidents`, `/api/v1/metrics`)
- [x] Automated unit & API test suite (`pytest`)

## Phase 3 — Observability & Alerting Stack (Completed)

- [x] Prometheus scraping `api:8000/api/v1/metrics` every `5s` with 15-day TSDB volume persistence
- [x] Prometheus alert rules for service, monitoring, API, and unresolved incident states
- [x] Alertmanager grouping, deduplication, severity routing, inhibition rules, and configurable receivers
- [x] Grafana provisioned Prometheus datasource (`autoheal-prometheus`) and **AutoHeal Infrastructure Overview** dashboard (`autoheal-overview`)
- [x] Hardened Compose integration (`read_only: true`, `cap_drop: ALL`, `no-new-privileges:true`)
- [x] Automated configuration validation (`pytest`, `promtool`, `amtool`) and live failure/recovery/restart verification

## Phase 4 — Automated Ansible Remediation Engine (Planned)

- [ ] Trigger Ansible recovery workflows (`ansible/`, `remediation/recover.yml`) from confirmed alerts
- [ ] Add cooldown windows, retry caps, and escalation safeguards
- [ ] Mediate container lifecycle actions via a least-privilege Docker Socket Proxy

## Phase 5 — Cloud Deployment & CI/CD (Planned)

- [ ] Terraform modules for AWS infrastructure provisioning
- [ ] GitHub Actions pipelines for automated linting, `pytest`, Docker builds, and security scanning
