"""Strict, allowlisted Ansible subprocess runner for isolated AutoHeal remediation."""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

from .config import (
    APPROVED_ANSIBLE_EXECUTABLES,
    APPROVED_CONFIG_PATHS,
    APPROVED_INVENTORY_PATHS,
    SAFE_IDENTIFIER_RE,
    SAFE_REL_PATH_RE,
    RemediationSettings,
)
from .execution_models import AnsibleRunResult
from .models import RemediationAction
from .repository import sanitize_execution_text

_APPROVED_EXTRA_VAR_KEYS = frozenset({"autoheal_target_service", "autoheal_action"})
_DISALLOWED_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f;|&$`><]")
_MAX_CAPTURED_STREAM_CHARS = 16384


def _terminate_process_group(proc: subprocess.Popen[str], *, grace_seconds: float = 1.5) -> None:
    """Terminate a child subprocess and every descendant in its process group."""
    try:
        pgid = os.getpgid(proc.pid)
    except OSError:
        pgid = None

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return
        except OSError:
            proc.terminate()
    else:
        proc.terminate()

    try:
        proc.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        pass

    if pgid is not None:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except OSError:
            if proc.poll() is None:
                proc.kill()
    elif proc.poll() is None:
        proc.kill()

    try:
        proc.wait(timeout=2.0)
    except subprocess.TimeoutExpired:
        pass


def _read_stream_bounded(stream, sink: list[str], max_chars: int = _MAX_CAPTURED_STREAM_CHARS) -> None:
    """Drain text stream chunks into `sink` without exceeding memory bounds."""
    captured = 0
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            if captured < max_chars:
                remaining = max_chars - captured
                sink.append(chunk[:remaining])
                captured += min(len(chunk), remaining)
    except Exception:  # noqa: BLE001
        pass


def sanitize_ansible_output(value: str | None, *, max_length: int = 4000) -> str:
    """Scrub private keys, tokens, credentials, and control bytes from Ansible output."""
    if not value:
        return ""
    return sanitize_execution_text(value, max_length=max_length) or ""


def resolve_approved_workspace_file(
    workspace_root: Path,
    rel_path: str,
    *,
    allowlist: frozenset[str] | set[str] | tuple[str, ...],
    label: str,
) -> Path:
    """Resolve an allowlisted relative file strictly inside `workspace_root` without traversal."""
    normalized = rel_path.strip().replace("\\", "/")
    if not normalized:
        raise ValueError(f"{label} must not be empty")
    if normalized.startswith("/") or ".." in Path(normalized).parts:
        raise ValueError(f"{label} traversal or absolute paths are forbidden: {rel_path!r}")
    if _DISALLOWED_CONTROL_CHARS_RE.search(normalized) or not SAFE_REL_PATH_RE.fullmatch(normalized):
        raise ValueError(f"{label} contains unsafe characters: {rel_path!r}")
    if normalized not in allowlist:
        raise ValueError(f"{label} {normalized!r} is not in allowlist {sorted(allowlist)}")

    root_resolved = workspace_root.resolve()
    candidate = (root_resolved / normalized).resolve()
    if not candidate.is_relative_to(root_resolved):
        raise ValueError(f"{label} escapes workspace root: {rel_path!r}")
    if not candidate.is_file():
        raise FileNotFoundError(f"{label} file not found at {candidate}")
    return candidate


def check_execution_isolation(
    *,
    docker_host: str | None = None,
    docker_sock_path: Path = Path("/var/run/docker.sock"),
    allowed_proxy_host: str = "docker-socket-proxy",
    allowed_proxy_port: int = 2375,
) -> tuple[bool, str]:
    """Fail closed unless running without direct docker.sock via the approved socket proxy."""
    if docker_sock_path.exists():
        return (
            False,
            "Fail-closed isolation check rejected execution: direct /var/run/docker.sock "
            "detected in executor environment.",
        )

    effective_host = (docker_host if docker_host is not None else os.getenv("DOCKER_HOST", "")).strip()
    if not effective_host:
        return (
            False,
            "Fail-closed isolation check rejected execution: DOCKER_HOST proxy endpoint "
            "is not configured.",
        )
    if effective_host.startswith("unix://"):
        return (
            False,
            "Fail-closed isolation check rejected execution: unix:// Docker socket URIs "
            "are forbidden; use restricted tcp:// socket proxy.",
        )
    if not effective_host.startswith("tcp://"):
        return (
            False,
            f"Fail-closed isolation check rejected execution: invalid DOCKER_HOST scheme "
            f"({effective_host!r}).",
        )

    parsed = urlparse(effective_host)
    if (
        parsed.scheme != "tcp"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        return (
            False,
            "Fail-closed isolation check rejected execution: DOCKER_HOST must be an exact "
            f"tcp://<host>:<port> proxy endpoint without credentials or path ({effective_host!r}).",
        )

    try:
        parsed_port = parsed.port
    except ValueError:
        parsed_port = None

    expected_host = allowed_proxy_host.strip().lower()
    actual_host = (parsed.hostname or "").strip().lower()
    if actual_host != expected_host or parsed_port != allowed_proxy_port:
        return (
            False,
            "Fail-closed isolation check rejected execution: unapproved DOCKER_HOST proxy "
            f"target {effective_host!r}; expected 'tcp://{expected_host}:{allowed_proxy_port}'.",
        )

    return (True, f"Isolated socket proxy verified ({effective_host}).")


class AnsibleRunner:
    """Executes only allowlisted Ansible recovery playbooks with shell=False and timeouts."""

    def __init__(
        self,
        settings: RemediationSettings,
        *,
        subprocess_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        isolation_checker: Callable[[], tuple[bool, str]] | None = None,
    ) -> None:
        self._settings = settings
        self._subprocess_runner = subprocess_runner
        self._isolation_checker = isolation_checker or (
            lambda: check_execution_isolation(
                allowed_proxy_host=settings.autoheal_remediation_allowed_proxy_host,
                allowed_proxy_port=settings.autoheal_remediation_allowed_proxy_port,
            )
        )

    def validate_and_build_command(
        self,
        *,
        service_name: str,
        action: str | RemediationAction,
        playbook: str | None = None,
        executable: str | None = None,
        extra_vars: dict[str, object] | None = None,
        check_mode: bool = False,
    ) -> tuple[list[str], dict[str, str], Path, str]:
        """Validate every Ansible input against strict allowlists and construct fixed argv."""
        normalized_service = service_name.strip().lower()
        if (
            not normalized_service
            or _DISALLOWED_CONTROL_CHARS_RE.search(normalized_service)
            or not SAFE_IDENTIFIER_RE.fullmatch(normalized_service)
            or normalized_service not in self._settings.autoheal_allowed_services
        ):
            raise ValueError(f"Service {service_name!r} is invalid or not allowlisted")

        raw_action = action.value if isinstance(action, RemediationAction) else str(action).strip().lower()
        try:
            validated_action = RemediationAction(raw_action).value
        except ValueError as exc:
            raise ValueError(f"Action {action!r} is not a recognized remediation action") from exc
        if validated_action not in self._settings.autoheal_allowed_actions:
            raise ValueError(f"Action {validated_action!r} is not allowlisted")

        if extra_vars:
            unknown_keys = set(extra_vars.keys()) - _APPROVED_EXTRA_VAR_KEYS
            if unknown_keys:
                raise ValueError(
                    f"Arbitrary Ansible extra variables are forbidden: {sorted(unknown_keys)}"
                )

        chosen_executable = (executable or self._settings.autoheal_ansible_executable).strip()
        if chosen_executable not in APPROVED_ANSIBLE_EXECUTABLES:
            raise ValueError(f"Unapproved Ansible executable rejected: {chosen_executable!r}")

        workspace_root = Path(self._settings.autoheal_remediation_workspace_root)
        chosen_playbook = playbook or self._settings.autoheal_ansible_playbook_path
        playbook_file = resolve_approved_workspace_file(
            workspace_root,
            chosen_playbook,
            allowlist=self._settings.autoheal_remediation_approved_playbooks,
            label="Playbook",
        )
        inventory_file = resolve_approved_workspace_file(
            workspace_root,
            self._settings.autoheal_ansible_inventory_path,
            allowlist=APPROVED_INVENTORY_PATHS,
            label="Inventory",
        )
        config_file = resolve_approved_workspace_file(
            workspace_root,
            self._settings.autoheal_ansible_config_path,
            allowlist=APPROVED_CONFIG_PATHS,
            label="Ansible config",
        )

        # Fail closed if someone injects disallowed control characters into fixed payload values.
        payload_vars = json.dumps(
            {
                "autoheal_target_service": normalized_service,
                "autoheal_action": validated_action,
            },
            separators=(",", ":"),
        )

        # Minimal curated subprocess environment (never inherit parent secrets/tokens).
        child_env = {
            "PATH": os.getenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
            "HOME": "/tmp",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "ANSIBLE_CONFIG": str(config_file),
            "ANSIBLE_HOME": "/tmp/.ansible",
            "ANSIBLE_LOCAL_TEMP": "/tmp/.ansible/tmp",
            "ANSIBLE_REMOTE_TEMP": "/tmp/.ansible/tmp",
            "ANSIBLE_HOST_KEY_CHECKING": "False",
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_NOCOLOR": "1",
        }
        docker_host = os.getenv("DOCKER_HOST", "").strip()
        if docker_host:
            if _DISALLOWED_CONTROL_CHARS_RE.search(docker_host):
                raise ValueError("DOCKER_HOST contains disallowed control characters")
            child_env["DOCKER_HOST"] = docker_host

        # Resolve executable to verified absolute path.
        resolved_executable = chosen_executable
        if not Path(chosen_executable).is_file():
            found = shutil.which(Path(chosen_executable).name, path=child_env["PATH"])
            if found:
                resolved_executable = str(Path(found).resolve())
        else:
            resolved_executable = str(Path(chosen_executable).resolve())

        argv = [
            resolved_executable,
            "-i",
            str(inventory_file),
            str(playbook_file),
            "-e",
            payload_vars,
        ]
        if check_mode:
            argv.append("--check")

        return argv, child_env, workspace_root.resolve(), chosen_playbook

    def _run_with_popen(
        self,
        argv: list[str],
        *,
        cwd_path: Path,
        child_env: dict[str, str],
        timeout_seconds: float,
        validated_playbook: str,
        started: float,
        cancel_event: threading.Event | None = None,
    ) -> AnsibleRunResult:
        """Execute subprocess in its own process group with bounded output capture and teardown."""
        proc = subprocess.Popen(
            argv,
            shell=False,
            cwd=str(cwd_path),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
        out_chunks: list[str] = []
        err_chunks: list[str] = []
        out_thread = threading.Thread(
            target=_read_stream_bounded,
            args=(proc.stdout, out_chunks),
            daemon=True,
        )
        err_thread = threading.Thread(
            target=_read_stream_bounded,
            args=(proc.stderr, err_chunks),
            daemon=True,
        )
        out_thread.start()
        err_thread.start()

        timed_out = False
        cancelled = False
        deadline = time.monotonic() + timeout_seconds
        try:
            while proc.poll() is None:
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    proc.wait(timeout=min(0.05, remaining))
                    break
                except subprocess.TimeoutExpired:
                    continue

            if timed_out or cancelled:
                _terminate_process_group(proc, grace_seconds=1.5)
        finally:
            out_thread.join(timeout=1.0)
            err_thread.join(timeout=1.0)
            if proc.stdout is not None:
                try:
                    proc.stdout.close()
                except OSError:
                    pass
            if proc.stderr is not None:
                try:
                    proc.stderr.close()
                except OSError:
                    pass

        elapsed = max(round(time.monotonic() - started, 3), 0.0)
        raw_out = "".join(out_chunks)
        raw_err = "".join(err_chunks)
        if timed_out:
            clean_stdout = sanitize_ansible_output(raw_out, max_length=2000)
            clean_stderr = sanitize_ansible_output(raw_err, max_length=1500)
            reason = f"Ansible execution timed out after {timeout_seconds}s"
            combined = sanitize_ansible_output(
                "\n".join(part for part in (reason, clean_stdout, clean_stderr) if part),
                max_length=4000,
            )
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=True,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout=clean_stdout,
                stderr=clean_stderr,
                combined_output=combined,
                error=reason,
            )

        if cancelled:
            clean_stdout = sanitize_ansible_output(raw_out, max_length=2000)
            clean_stderr = sanitize_ansible_output(raw_err, max_length=1500)
            reason = "Ansible execution cancelled"
            combined = sanitize_ansible_output(
                "\n".join(part for part in (reason, clean_stdout, clean_stderr) if part),
                max_length=4000,
            )
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=False,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout=clean_stdout,
                stderr=clean_stderr,
                combined_output=combined,
                error=reason,
            )

        clean_stdout = sanitize_ansible_output(raw_out, max_length=2500)
        clean_stderr = sanitize_ansible_output(raw_err, max_length=1500)
        combined = sanitize_ansible_output(
            "\n".join(part for part in (clean_stdout, clean_stderr) if part),
            max_length=4000,
        )
        rc = int(proc.returncode or 0)
        succeeded = rc == 0
        error_msg = (
            None
            if succeeded
            else sanitize_ansible_output(
                f"Ansible exited with code {rc}: {clean_stderr or clean_stdout}",
                max_length=1000,
            )
        )
        return AnsibleRunResult(
            succeeded=succeeded,
            exit_code=rc,
            timed_out=False,
            duration_seconds=elapsed,
            playbook=validated_playbook,
            stdout=clean_stdout,
            stderr=clean_stderr,
            combined_output=combined,
            error=error_msg,
        )

    def run(
        self,
        *,
        service_name: str,
        action: str | RemediationAction,
        playbook: str | None = None,
        executable: str | None = None,
        extra_vars: dict[str, object] | None = None,
        timeout_seconds: float | None = None,
        check_mode: bool = False,
        cancel_event: threading.Event | None = None,
    ) -> AnsibleRunResult:
        """Execute an approved Ansible playbook inside isolation and timeout constraints."""
        effective_timeout = (
            self._settings.autoheal_remediation_timeout_seconds
            if timeout_seconds is None
            else float(timeout_seconds)
        )
        if not math.isfinite(effective_timeout) or effective_timeout <= 0:
            raise ValueError("timeout_seconds must be a finite number greater than 0")

        started = time.monotonic()
        playbook_label = playbook or self._settings.autoheal_ansible_playbook_path

        if self._settings.autoheal_remediation_require_isolation:
            isolated, iso_reason = self._isolation_checker()
            if not isolated:
                elapsed = max(round(time.monotonic() - started, 3), 0.0)
                return AnsibleRunResult(
                    succeeded=False,
                    exit_code=None,
                    timed_out=False,
                    duration_seconds=elapsed,
                    playbook=playbook_label,
                    stdout="",
                    stderr="",
                    combined_output=sanitize_ansible_output(iso_reason),
                    error=iso_reason,
                )

        try:
            argv, child_env, cwd_path, validated_playbook = self.validate_and_build_command(
                service_name=service_name,
                action=action,
                playbook=playbook,
                executable=executable,
                extra_vars=extra_vars,
                check_mode=check_mode,
            )
            playbook_label = validated_playbook
        except (ValueError, FileNotFoundError) as exc:
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            msg = sanitize_ansible_output(str(exc), max_length=1000)
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=False,
                duration_seconds=elapsed,
                playbook=playbook_label,
                stdout="",
                stderr="",
                combined_output=msg,
                error=msg,
            )

        try:
            if self._subprocess_runner is subprocess.run:
                return self._run_with_popen(
                    argv,
                    cwd_path=cwd_path,
                    child_env=child_env,
                    timeout_seconds=effective_timeout,
                    validated_playbook=validated_playbook,
                    started=started,
                    cancel_event=cancel_event,
                )

            if cancel_event is not None and cancel_event.is_set():
                elapsed = max(round(time.monotonic() - started, 3), 0.0)
                return AnsibleRunResult(
                    succeeded=False,
                    exit_code=None,
                    timed_out=False,
                    duration_seconds=elapsed,
                    playbook=validated_playbook,
                    stdout="",
                    stderr="",
                    combined_output="Ansible execution cancelled",
                    error="Ansible execution cancelled",
                )

            completed = self._subprocess_runner(
                argv,
                shell=False,
                cwd=str(cwd_path),
                env=child_env,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            clean_stdout = sanitize_ansible_output(completed.stdout, max_length=2500)
            clean_stderr = sanitize_ansible_output(completed.stderr, max_length=1500)
            combined = sanitize_ansible_output(
                "\n".join(part for part in (clean_stdout, clean_stderr) if part),
                max_length=4000,
            )
            succeeded = completed.returncode == 0
            error_msg = (
                None
                if succeeded
                else sanitize_ansible_output(
                    f"Ansible exited with code {completed.returncode}: {clean_stderr or clean_stdout}",
                    max_length=1000,
                )
            )
            return AnsibleRunResult(
                succeeded=succeeded,
                exit_code=int(completed.returncode),
                timed_out=False,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout=clean_stdout,
                stderr=clean_stderr,
                combined_output=combined,
                error=error_msg,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            raw_out = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            raw_err = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            clean_stdout = sanitize_ansible_output(raw_out, max_length=2000)
            clean_stderr = sanitize_ansible_output(raw_err, max_length=1500)
            reason = f"Ansible execution timed out after {effective_timeout}s"
            combined = sanitize_ansible_output(
                "\n".join(part for part in (reason, clean_stdout, clean_stderr) if part),
                max_length=4000,
            )
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=True,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout=clean_stdout,
                stderr=clean_stderr,
                combined_output=combined,
                error=reason,
            )
        except FileNotFoundError:
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            reason = f"Ansible executable {argv[0]!r} was not found in executor environment."
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=False,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout="",
                stderr="",
                combined_output=reason,
                error=reason,
            )
        except OSError as exc:
            elapsed = max(round(time.monotonic() - started, 3), 0.0)
            reason = sanitize_ansible_output(f"Ansible process invocation failed: {exc}", max_length=1000)
            return AnsibleRunResult(
                succeeded=False,
                exit_code=None,
                timed_out=False,
                duration_seconds=elapsed,
                playbook=validated_playbook,
                stdout="",
                stderr="",
                combined_output=reason,
                error=reason,
            )
