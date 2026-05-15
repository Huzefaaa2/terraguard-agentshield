from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from terraguard_agentshield.audit import SessionAudit


@dataclass(frozen=True)
class EvidenceValidationResult:
    valid: bool
    session_id: str | None
    failures: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "session_id": self.session_id,
            "failures": self.failures,
            "summary": self.summary,
        }


def latest_audit_file(audit_dir: Path) -> Path | None:
    files = sorted(audit_dir.glob("session-*.json"), key=lambda path: path.stat().st_mtime)
    return files[-1] if files else None


def load_audit_for_validation(audit_dir: Path, session_id: str | None = None) -> SessionAudit:
    if session_id:
        audit_path = audit_dir / f"session-{session_id}.json"
    else:
        audit_path = latest_audit_file(audit_dir) or Path()

    if not audit_path.exists():
        raise FileNotFoundError(f"No AgentShield audit file found in {audit_dir}")
    return SessionAudit.read(audit_path)


def validate_attestation(
    audit: SessionAudit,
    fail_on: set[str] | None = None,
    require_policy_pack: str | None = None,
    require_tool: str | None = None,
    min_actions: int = 1,
) -> EvidenceValidationResult:
    fail_decisions = fail_on or {"block", "require_approval"}
    failures: list[str] = []
    decisions = _decision_counts(audit)

    if len(audit.actions) < min_actions:
        failures.append(
            f"Audit contains {len(audit.actions)} action(s); expected at least {min_actions}."
        )

    if require_policy_pack and audit.policy_pack != require_policy_pack:
        failures.append(
            f"Policy pack mismatch: expected {require_policy_pack}, found {audit.policy_pack}."
        )

    if require_tool and audit.tool != require_tool:
        failures.append(f"Tool mismatch: expected {require_tool}, found {audit.tool}.")

    for decision in sorted(fail_decisions):
        count = decisions.get(decision, 0)
        if count:
            failures.append(f"Audit contains {count} {decision} action(s).")

    summary = {
        "tool": audit.tool,
        "repo": str(audit.repo),
        "policy_pack": audit.policy_pack,
        "action_count": len(audit.actions),
        "decisions": decisions,
    }
    return EvidenceValidationResult(
        valid=not failures,
        session_id=audit.session_id,
        failures=failures,
        summary=summary,
    )


def write_validation_result(result: EvidenceValidationResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")


def _decision_counts(audit: SessionAudit) -> dict[str, int]:
    counts: dict[str, int] = {}
    for action in audit.actions:
        counts[action.decision] = counts.get(action.decision, 0) + 1
    return counts
