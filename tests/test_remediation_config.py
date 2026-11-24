"""Automated unit tests for remediation configuration validation and safety defaults."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from remediation.src.config import RemediationSettings, clear_settings_cache, get_settings


def test_remediation_settings_safe_defaults() -> None:
    settings = RemediationSettings(_env_file=None)

    assert settings.autoheal_remediation_enabled is False
    assert settings.autoheal_remediation_dry_run is True
    assert settings.autoheal_remediation_cooldown_seconds == 300
    assert settings.autoheal_remediation_max_attempts == 3
    assert settings.autoheal_remediation_timeout_seconds == 120.0
    assert settings.autoheal_allowed_services == ("web",)
    assert settings.autoheal_allowed_actions == ("restart",)
    assert settings.autoheal_remediation_verify_interval == 5.0
    assert settings.autoheal_remediation_verify_attempts == 6
    assert settings.autoheal_db_path == "/data/autoheal.db"


def test_remediation_never_enabled_implicitly_when_other_vars_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("AUTOHEAL_REMEDIATION_ENABLED", raising=False)
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_DRY_RUN", "false")
    monkeypatch.setenv("AUTOHEAL_ALLOWED_SERVICES", "web,api")
    monkeypatch.setenv("AUTOHEAL_ALLOWED_ACTIONS", "restart,start")
    clear_settings_cache()

    settings = RemediationSettings(_env_file=None)
    try:
        assert settings.autoheal_remediation_enabled is False
        assert settings.autoheal_allowed_services == ("web", "api")
        assert settings.autoheal_allowed_actions == ("restart", "start")
    finally:
        clear_settings_cache()


def test_allowlist_normalization_and_deduplication(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTOHEAL_ALLOWED_SERVICES", " WEB , api-gateway , web ")
    monkeypatch.setenv("AUTOHEAL_ALLOWED_ACTIONS", " RESTART , start , restart ")
    clear_settings_cache()

    try:
        settings = get_settings()
        assert settings.autoheal_allowed_services == ("web", "api-gateway")
        assert settings.autoheal_allowed_actions == ("restart", "start")
    finally:
        clear_settings_cache()


@pytest.mark.parametrize(
    "overrides",
    [
        {"autoheal_remediation_cooldown_seconds": -1},
        {"autoheal_remediation_max_attempts": 0},
        {"autoheal_remediation_max_attempts": -2},
        {"autoheal_remediation_timeout_seconds": 0},
        {"autoheal_remediation_timeout_seconds": -10},
        {"autoheal_remediation_verify_interval": 0},
        {"autoheal_remediation_verify_interval": -1.5},
        {"autoheal_remediation_verify_attempts": 0},
        {"autoheal_remediation_verify_attempts": -3},
        {"autoheal_remediation_max_attempts": True},
        {"autoheal_remediation_cooldown_seconds": False},
        {"autoheal_allowed_services": ""},
        {"autoheal_allowed_services": "   "},
        {"autoheal_allowed_services": "web,"},
        {"autoheal_allowed_services": "*"},
        {"autoheal_allowed_services": "all"},
        {"autoheal_allowed_services": "any"},
        {"autoheal_allowed_services": "web; rm -rf /"},
        {"autoheal_allowed_services": "../web"},
        {"autoheal_allowed_actions": ""},
        {"autoheal_allowed_actions": "*"},
        {"autoheal_allowed_actions": "exec"},
        {"autoheal_allowed_actions": "shell"},
        {"autoheal_allowed_actions": "restart, /bin/sh"},
        {"autoheal_db_path": ""},
        {"autoheal_db_path": "   "},
    ],
)
def test_remediation_settings_rejects_invalid_and_unsafe_config(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RemediationSettings(_env_file=None, **overrides)


def test_remediation_settings_rejects_invalid_env_strings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOHEAL_REMEDIATION_MAX_ATTEMPTS", "not-a-number")
    with pytest.raises(ValidationError):
        RemediationSettings(_env_file=None)


def test_remediation_settings_allows_custom_db_path_env_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOHEAL_DB_PATH", " /tmp/custom-autoheal.db ")
    clear_settings_cache()

    try:
        settings = get_settings()
        assert settings.autoheal_db_path == "/tmp/custom-autoheal.db"
    finally:
        clear_settings_cache()


@pytest.mark.parametrize(
    "overrides",
    [
        {"autoheal_remediation_verify_required_successes": 0},
        {"autoheal_remediation_max_concurrency": 0},
        {"autoheal_remediation_timeout_seconds": float("nan")},
        {"autoheal_remediation_timeout_seconds": float("inf")},
        {"autoheal_remediation_stale_timeout_seconds": 0},
        {"autoheal_remediation_stale_timeout_seconds": float("nan")},
        {"autoheal_remediation_executor_poll_interval": -1},
        {"autoheal_remediation_verify_interval": float("inf")},
        {"autoheal_remediation_allowed_proxy_host": ""},
        {"autoheal_remediation_allowed_proxy_host": "bad host!"},
        {"autoheal_remediation_allowed_proxy_port": 0},
        {"autoheal_remediation_allowed_proxy_port": 70000},
        {"autoheal_remediation_allowed_proxy_port": True},
        {"autoheal_remediation_verify_target_url": "ftp://web/health"},
        {"autoheal_remediation_dispatch_mode": "invalid_mode"},
        {"autoheal_remediation_approved_playbooks": "../outside.yml"},
        {"autoheal_ansible_playbook_path": "remediation/unapproved.yml"},
        {"autoheal_ansible_inventory_path": "/etc/hosts"},
        {"autoheal_ansible_config_path": "../ansible.cfg"},
        {"autoheal_ansible_executable": "/bin/sh"},
    ],
)
def test_remediation_settings_rejects_unsafe_execution_fields(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RemediationSettings(_env_file=None, **overrides)
