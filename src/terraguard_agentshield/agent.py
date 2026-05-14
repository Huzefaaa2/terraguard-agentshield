from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.runtime import RuntimeGuard


@dataclass
class AgentSession:
    session_id: str
    tool: str
    repo: Path
    policy_pack: str | None
    audit: SessionAudit
    audit_path: Path


class AgentSessionManager:
    def __init__(
        self,
        repo: Path,
        tool: str,
        policy_pack: str | None = None,
        output_dir: Path = Path(".terraguard"),
    ) -> None:
        self.repo = repo.resolve()
        self.tool = tool
        self.policy_pack = policy_pack or "ai-agent-baseline"
        self.output_dir = output_dir
        self.guard = RuntimeGuard(policy_pack=self.policy_pack)

    def start_session(self) -> AgentSession:
        session_id = uuid.uuid4().hex[:12]
        audit = SessionAudit(
            session_id=session_id,
            tool=self.tool,
            repo=self.repo,
            policy_pack=self.policy_pack,
        )
        audit.add_action(
            AuditAction(
                type="session_start",
                target=str(self.repo),
                decision="allow",
                reason=f"Agent session started with policy pack {self.policy_pack}.",
            )
        )

        audit_path = audit.write(self.output_dir)
        return AgentSession(
            session_id=session_id,
            tool=self.tool,
            repo=self.repo,
            policy_pack=self.policy_pack,
            audit=audit,
            audit_path=audit_path,
        )
