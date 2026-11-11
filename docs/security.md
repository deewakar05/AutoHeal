# AutoHeal — Security Guide (Phase 3)

## Phase 3 Security Baseline

Adding Prometheus, Alertmanager, and Grafana preserves all Phase 1 and Phase 2 security controls while applying identical container hardening to the observability stack.

### 1. Container Hardening Summary

| Container | User | Read-Only Rootfs | Cap Drop | `no-new-privileges` | Docker Socket |
|---|---|---|---|---|---|
| `autoheal-web` | `nginx` workers | Read-only `:ro` mounts | `ALL` (+ minimal nginx caps) | Enabled | None |
| `autoheal-monitor` | `autoheal` (10001) | `true` (`tmpfs /tmp`) | `ALL` | Enabled | None |
| `autoheal-api` | `autoheal` (10001) | `true` (`tmpfs /tmp`) | `ALL` | Enabled | None |
| `autoheal-prometheus` | `nobody` (65534) | `true` | `ALL` | Enabled | None |
| `autoheal-alertmanager` | `nobody` (65534) | `true` | `ALL` | Enabled | None |
| `autoheal-grafana` | `grafana` (472) | `true` (`tmpfs /tmp`, `/var/log/grafana`) | `ALL` | Enabled | None |

### 2. Read-Only Configuration & Secrets Protection
- Prometheus (`prometheus.yml`, `rules/`), Alertmanager (`alertmanager.yml`), and Grafana (`provisioning/`) configurations are all bind-mounted `:ro`.
- `.env` and `observability/alertmanager/*.local.yml` are gitignored so Grafana credentials and webhook/Slack/SMTP receiver tokens never enter Git.
- Grafana disables user self-registration (`GF_USERS_ALLOW_SIGN_UP=false`) and telemetry (`GF_ANALYTICS_REPORTING_ENABLED=false`).
- Note: `.env.example` provides local-only default `GRAFANA_ADMIN_PASSWORD=admin` for zero-friction local evaluation; replace this in `.env` for any shared environment.

### 3. Network Isolation
- All six services communicate internally over the dedicated bridge network `autoheal-network`.
- Only required UI/API ports (`8080`, `8000`, `9090`, `9093`, `3000`) are published to the host; `autoheal-monitor` exposes no host ports.
