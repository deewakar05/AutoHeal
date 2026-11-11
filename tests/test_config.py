"""Automated tests for configuration validation in monitoring and API services."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from api.src.config import ApiSettings
from monitoring.src.config import MonitorSettings


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
        {"monitor_timeout": 0},
        {"monitor_failure_threshold": 0},
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

