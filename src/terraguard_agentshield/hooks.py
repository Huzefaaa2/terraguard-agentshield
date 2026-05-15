from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.runtime import ActionDecision, RuntimeGuard


CLAUDE_TOOL_FILE_READ = {"Read"}
CLAUDE_TOOL_FILE_WRITE = {"Edit", "MultiEdit", "Write", "NotebookEdit"}


@dataclass(frozen=True)
class HookDecision:
    decision: str
    reason: str
    output: dict[str, Any]


class ClaudeHookProcessor:
    """Process Claude Code hook events into AgentShield policy decisions."""

    def __init__(
        self,
        policy_pack: str = "ai-agent-baseline",
        repo: Path = Path("."),
        audit_dir: Path = Path(".terraguard/audit"),
        tool: str = "claude-code",
    ) -> None:
        self.policy_pack = policy_pack
        self.repo = repo.resolve()
        self.audit_dir = audit_dir
        self.tool = tool
        self.guard = RuntimeGuard(policy_pack=policy_pack)

    def process(self, payload: dict[str, Any]) -> HookDecision:
        event_name = str(payload.get("hook_event_name") or payload.get("event") or "")
        tool_name = str(payload.get("tool_name") or "")
        tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}

        decision, action_type, target = self._evaluate_tool(tool_name, tool_input)
        reason = decision.reason or f"{decision.decision} by AgentShield policy"

        audit = self._load_or_create_audit(payload)
        audit.add_action(
            AuditAction(
                type=action_type,
                target=target,
                decision=decision.decision,
                reason=reason,
                metadata={
                    "hook_event": event_name,
                    "tool_name": tool_name,
                    "policy_pack": self.policy_pack,
                    "tool_input_keys": sorted(str(key) for key in tool_input.keys()),
                },
            )
        )
        audit.write(self.audit_dir)

        return HookDecision(
            decision=decision.decision,
            reason=reason,
            output=self._claude_output(event_name, decision.decision, reason),
        )

    def _evaluate_tool(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> tuple[ActionDecision, str, str]:
        if tool_name == "Bash":
            command = str(tool_input.get("command") or "")
            return self.guard.evaluate_command(command), "execute_command", command

        if tool_name in CLAUDE_TOOL_FILE_READ:
            file_path = self._file_target(tool_input)
            return self.guard.evaluate_file_access(Path(file_path), "read"), "read_file", file_path

        if tool_name in CLAUDE_TOOL_FILE_WRITE:
            file_path = self._file_target(tool_input)
            return self.guard.evaluate_file_access(Path(file_path), "write"), "write_file", file_path

        if tool_name.startswith("mcp__"):
            server_id, capability = self._mcp_target(tool_name)
            return (
                self.guard.evaluate_mcp_server(server_id, capability=capability),
                "mcp_connect",
                server_id,
            )

        return ActionDecision("allow", f"No AgentShield policy mapped for tool: {tool_name}"), "tool_use", tool_name

    def _load_or_create_audit(self, payload: dict[str, Any]) -> SessionAudit:
        session_id = str(payload.get("session_id") or uuid.uuid4().hex[:12])
        audit_path = self.audit_dir / f"session-{session_id}.json"
        if audit_path.exists():
            return SessionAudit.read(audit_path)

        return SessionAudit(
            session_id=session_id,
            tool=self.tool,
            repo=Path(str(payload.get("cwd") or self.repo)),
            policy_pack=self.policy_pack,
            environment=payload.get("environment"),
        )

    @staticmethod
    def _file_target(tool_input: dict[str, Any]) -> str:
        for key in ("file_path", "path", "notebook_path"):
            value = tool_input.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _mcp_target(tool_name: str) -> tuple[str, str | None]:
        parts = tool_name.split("__")
        if len(parts) >= 3:
            return parts[1], parts[2]
        if len(parts) == 2:
            return parts[1], None
        return tool_name, None

    @staticmethod
    def _claude_output(event_name: str, decision: str, reason: str) -> dict[str, Any]:
        if event_name != "PreToolUse":
            return {}

        permission_decision = {
            "allow": "allow",
            "block": "deny",
            "require_approval": "ask",
        }.get(decision, "ask")

        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": permission_decision,
                "permissionDecisionReason": reason,
            }
        }
