"""Typed execution, Ansible runner, and recovery verification models for AutoHeal."""

from __future__ import annotations

from dataclasses import dataclass

from .models import RemediationDecision, RemediationExecution


@dataclass(frozen=True)
class AnsibleRunResult:
    """Structured outcome returned by `AnsibleRunner` after running an allowlisted playbook."""

    succeeded: bool
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    playbook: str
    stdout: str
    stderr: str
    combined_output: str
    error: str | None = None


@dataclass(frozen=True)
class VerificationResult:
    """Outcome produced by `RecoveryVerifier` after independent service health probing."""

    verified: bool
    attempts_made: int
    consecutive_successes: int
    duration_seconds: float
    last_outcome: str | None
    details: str


@dataclass(frozen=True)
class ExecutionOutcome:
    """End-to-end result of evaluating, reserving, executing, and verifying remediation."""

    executed: bool
    verified: bool
    dry_run: bool
    decision: RemediationDecision
    execution: RemediationExecution | None = None
    ansible_result: AnsibleRunResult | None = None
    verification: VerificationResult | None = None
    incident_resolved: bool = False
    error: str | None = None
