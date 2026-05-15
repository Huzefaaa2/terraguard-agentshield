from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class AuditAction:
    type: str
    target: str
    decision: str
    reason: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "target": self.target,
            "decision": self.decision,
            "reason": self.reason,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "AuditAction":
        return cls(
            type=str(payload["type"]),
            target=str(payload["target"]),
            decision=str(payload["decision"]),
            reason=payload.get("reason"),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass
class SessionAudit:
    session_id: str
    tool: str
    repo: Path
    policy_pack: str = "ai-agent-baseline"
    developer: str | None = None
    environment: str | None = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    actions: list[AuditAction] = field(default_factory=list)

    def add_action(self, action: AuditAction) -> None:
        self.actions.append(action)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "tool": self.tool,
            "repo": str(self.repo),
            "policy_pack": self.policy_pack,
            "developer": self.developer,
            "environment": self.environment,
            "started_at": self.started_at.isoformat() + "Z",
            "actions": [action.to_dict() for action in self.actions],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SessionAudit":
        started_at = payload.get("started_at")
        parsed_started_at = datetime.utcnow()
        if isinstance(started_at, str):
            parsed_started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            parsed_started_at = parsed_started_at.replace(tzinfo=None)

        actions = [
            AuditAction.from_dict(action)
            for action in payload.get("actions", [])
            if isinstance(action, dict)
        ]

        return cls(
            session_id=str(payload["session_id"]),
            tool=str(payload["tool"]),
            repo=Path(str(payload["repo"])),
            policy_pack=str(payload.get("policy_pack") or "ai-agent-baseline"),
            developer=payload.get("developer"),
            environment=payload.get("environment"),
            started_at=parsed_started_at,
            actions=actions,
        )

    def write(self, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        audit_path = destination / f"session-{self.session_id}.json"
        audit_path.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return audit_path

    @classmethod
    def read(cls, audit_path: Path) -> "SessionAudit":
        return cls.from_dict(json.loads(audit_path.read_text(encoding="utf-8")))


def create_attestation_markdown(audit: SessionAudit) -> str:
    allowed = [action for action in audit.actions if action.decision == "allow"]
    blocked = [action for action in audit.actions if action.decision == "block"]
    required = [action for action in audit.actions if action.decision == "require_approval"]

    lines = [
        "## TerraGuard AgentShield Governance Report",
        "",
        f"Agent: {audit.tool}",
        f"Session: {audit.session_id}",
        f"Repository: {audit.repo}",
        f"Policy Pack: {audit.policy_pack}",
        "",
        "### Decisions",
        f"- Allowed actions: {len(allowed)}",
        f"- Blocked actions: {len(blocked)}",
        f"- Approval-required actions: {len(required)}",
        "",
    ]

    if blocked:
        lines.append("### Blocked Actions")
        for action in blocked:
            lines.append(f"- `{action.target}` - {action.reason or 'blocked by policy'}")
        lines.append("")

    if required:
        lines.append("### Human Approval Required")
        for action in required:
            lines.append(f"- `{action.target}` - {action.reason or 'requires approval'}")
        lines.append("")

    return "\n".join(lines)
