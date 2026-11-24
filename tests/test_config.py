"""Automated tests for configuration validation in monitoring and API services."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.src.config import ApiSettings
from remediation.src.monitor_config import MonitorSettings


def test_monitor_settings_defaults() -> None:
    settings = MonitorSettings(_env_file=None)
    assert settings.monitor_enabled is True
    assert settings.monitor_target_url == "http://web/health"
    assert settings.monitor_target_service == "web"
    assert settings.monitor_interval == 5.0
    assert settings.monitor_timeout == 3.0
    assert settings.monitor_failure_threshold == 3
    assert settings.monitor_recovery_threshold == 2
    assert settings.log_level == "INFO"


def test_monitor_settings_legacy_interval_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MONITOR_INTERVAL", raising=False)
    monkeypatch.delenv("MONITOR_TIMEOUT", raising=False)
    monkeypatch.setenv("MONITOR_INTERVAL_SECONDS", "12")
    monkeypatch.setenv("MONITOR_TIMEOUT_SECONDS", "4")

    settings = MonitorSettings(_env_file=None)
    assert settings.monitor_interval == 12.0
    assert settings.monitor_timeout == 4.0


@pytest.mark.parametrize(
    "overrides",
    [
        {"monitor_target_url": "ftp://web/health"},
        {"monitor_target_url": "not-a-url"},
        {"monitor_target_service": "   "},
        {"monitor_interval": 0},
        {"monitor_interval": -2},
        {"monitor_interval": float("nan")},
        {"monitor_interval": float("inf")},
        {"monitor_interval": True},
        {"monitor_timeout": 0},
        {"monitor_timeout": float("nan")},
        {"monitor_timeout": float("inf")},
        {"monitor_failure_threshold": 0},
        {"monitor_failure_threshold": True},
        {"monitor_recovery_threshold": 0},
        {"log_level": "TRACE"},
    ],
)
def test_monitor_settings_rejects_invalid_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        MonitorSettings(_env_file=None, **overrides)


@pytest.mark.parametrize("bad_port", [0, -1, 70000])
def test_api_settings_rejects_invalid_port(bad_port: int) -> None:
    with pytest.raises(ValidationError):
        ApiSettings(_env_file=None, api_port=bad_port)


def test_nagios_settings_validation_and_secret_redaction() -> None:
    mon = MonitorSettings(
        _env_file=None,
        nagios_monitor_enabled=True,
        nagios_status_url="http://nagios:8081/nagios4/cgi-bin/statusjson.cgi?query=programstatus",
        nagios_admin_user="nagiosadmin",
        nagios_admin_password="secret-password",
    )
    assert "secret-password" not in repr(mon)

    with pytest.raises(ValidationError):
        MonitorSettings(_env_file=None, nagios_status_url="ftp://nagios/bad")
    with pytest.raises(ValidationError):
        MonitorSettings(_env_file=None, nagios_probe_timeout=0)
    with pytest.raises(ValidationError):
        MonitorSettings(_env_file=None, nagios_probe_timeout=True)

    api_cfg = ApiSettings(
        _env_file=None,
        autoheal_nagios_webhook_secret="webhook-secret-xyz",
        autoheal_nagios_service_map="edge-web:*=web",
    )
    assert "webhook-secret-xyz" not in repr(api_cfg)
    with pytest.raises(ValidationError):
        ApiSettings(_env_file=None, autoheal_nagios_service_map="invalid-entry-without-equals")
