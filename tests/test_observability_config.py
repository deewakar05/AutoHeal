"""Configuration validation tests for AutoHeal Nagios monitoring, compose security, and docs hygiene."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_yaml(rel_path: str) -> dict:
    return yaml.safe_load((REPO_ROOT / rel_path).read_text(encoding="utf-8"))


def test_nagios_core_object_configuration() -> None:
    """Validate Nagios Core object definitions for monitored infrastructure."""
    hosts_cfg = (REPO_ROOT / "nagios/etc/objects/hosts.cfg").read_text(encoding="utf-8")
    assert "host_name   autoheal-web" in hosts_cfg
    assert "host_name   autoheal-api" in hosts_cfg
    assert "host_name   autoheal-nagios" in hosts_cfg
    assert "check_tcp_port!80" in hosts_cfg
    assert "check_tcp_port!8000" in hosts_cfg

    services_cfg = (REPO_ROOT / "nagios/etc/objects/services.cfg").read_text(encoding="utf-8")
    assert "service_description Web HTTP Health" in services_cfg
    assert "service_description API Health" in services_cfg
    assert "service_description Nagios Web UI Auth" in services_cfg
    assert "check_http_endpoint!80!/health" in services_cfg
    assert "check_http_endpoint!8000!/health" in services_cfg


def test_nagios_notification_commands_structure() -> None:
    """Validate Nagios event handler notification commands and contacts."""
    commands_cfg = (REPO_ROOT / "nagios/etc/objects/commands.cfg").read_text(encoding="utf-8")
    assert "command_name    notify-service-autoheal" in commands_cfg
    assert "command_name    notify-host-autoheal" in commands_cfg
    assert "nagios_notify.py" in commands_cfg
    assert "--kind service" in commands_cfg
    assert "--kind host" in commands_cfg

    contacts_cfg = (REPO_ROOT / "nagios/etc/objects/contacts.cfg").read_text(encoding="utf-8")
    assert "contact_name                    autoheal-webhook" in contacts_cfg
    assert "notify-service-autoheal" in contacts_cfg
    assert "notify-host-autoheal" in contacts_cfg

    templates_cfg = (REPO_ROOT / "nagios/etc/objects/templates.cfg").read_text(encoding="utf-8")
    assert "name                            autoheal-host" in templates_cfg
    assert "name                            autoheal-service" in templates_cfg


def test_compose_and_proxy_hardening_baseline() -> None:
    """Verify production security baseline for the 5-container architecture."""
    compose = _load_yaml("compose.yaml")
    services = compose["services"]

    expected_services = {
        "web",
        "api",
        "docker-socket-proxy",
        "remediation-executor",
        "nagios",
    }
    assert set(services.keys()) == expected_services
    assert "nagios-data" in compose["volumes"]
    assert compose["networks"]["autoheal-network"]["name"] == "autoheal-network"
    assert compose["networks"]["autoheal-control-network"]["internal"] is True

    for svc_name in expected_services:
        svc = services[svc_name]
        assert svc["read_only"] is True
        assert svc["cap_drop"] == ["ALL"]
        assert "no-new-privileges:true" in svc["security_opt"]
        assert "mem_limit" in svc
        assert "cpus" in svc
        if svc_name != "docker-socket-proxy":
            for vol in svc.get("volumes", []):
                assert "/var/run/docker.sock" not in str(vol)

    proxy = services["docker-socket-proxy"]
    assert not proxy.get("ports")
    assert proxy["networks"] == ["autoheal-control-network"]

    executor = services["remediation-executor"]
    assert not executor.get("ports")
    assert executor["environment"]["DOCKER_HOST"] == "tcp://docker-socket-proxy:2375"

    for svc_name in ("web", "api", "docker-socket-proxy", "remediation-executor", "nagios"):
        assert "healthcheck" in services[svc_name]

    assert services["nagios"].get("init") is True
    assert services["nagios"]["networks"] == ["autoheal-network"]
    assert services["api"]["networks"] == ["autoheal-network"]
    assert not services["api"].get("ports") or "autoheal-control-network" not in services["api"]["networks"]
    assert "nagios4 -v" in (REPO_ROOT / "docker/nagios/entrypoint.sh").read_text(encoding="utf-8")

    assert (REPO_ROOT / ".dockerignore").is_file()
    proxy_conf = (REPO_ROOT / "docker/socket-proxy/nginx.conf").read_text(encoding="utf-8")
    assert "merge_slashes off;" in proxy_conf
    assert "server_tokens off;" in proxy_conf
    assert r"(\.\.|//|%|\\|;|\?)" in proxy_conf
    assert "^(/v[1-9][0-9]*\\.[0-9]+)?" in proxy_conf


def test_documentation_and_templates_exclude_phase_references() -> None:
    """Ensure student documentation avoids internal dev phase terminology."""
    pattern = re.compile(r"\bphase\b", re.IGNORECASE)
    for rel_path in ("README.md", ".env.example", "app/html/index.html"):
        file_path = REPO_ROOT / rel_path
        if file_path.is_file():
            content = file_path.read_text(encoding="utf-8")
            assert not pattern.search(content), f"Found unexpected phase mention in {rel_path}"
