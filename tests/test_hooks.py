import json
from pathlib import Path

from terraguard_agentshield.audit import SessionAudit
from terraguard_agentshield.hooks import ClaudeHookProcessor


def test_claude_hook_blocks_terraform_apply(tmp_path: Path) -> None:
    processor = ClaudeHookProcessor(
        policy_pack="terraform-ai-guardrails",
        repo=tmp_path,
        audit_dir=tmp_path / "audit",
    )

    decision = processor.process(
        {
            "session_id": "sess-001",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "terraform apply -auto-approve"},
        }
    )

    assert decision.decision == "block"
    assert decision.output["hookSpecificOutput"]["permissionDecision"] == "deny"

    audit = SessionAudit.read(tmp_path / "audit" / "session-sess-001.json")
    assert audit.actions[0].decision == "block"
    assert audit.actions[0].type == "execute_command"


def test_claude_hook_blocks_sensitive_read(tmp_path: Path) -> None:
    processor = ClaudeHookProcessor(
        policy_pack="ai-agent-baseline",
        repo=tmp_path,
        audit_dir=tmp_path / "audit",
    )

    decision = processor.process(
        {
            "session_id": "sess-002",
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_input": {"file_path": str(tmp_path / ".env")},
        }
    )

    assert decision.decision == "block"
    assert decision.output["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_claude_hook_appends_to_existing_session(tmp_path: Path) -> None:
    processor = ClaudeHookProcessor(
        policy_pack="ai-agent-baseline",
        repo=tmp_path,
        audit_dir=tmp_path / "audit",
    )
    payload = {
        "session_id": "sess-003",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "terraform plan"},
    }

    processor.process(payload)
    processor.process(payload)

    audit = SessionAudit.read(tmp_path / "audit" / "session-sess-003.json")
    assert len(audit.actions) == 2
    assert all(action.decision == "allow" for action in audit.actions)


def test_claude_hook_mcp_capability_block(tmp_path: Path) -> None:
    processor = ClaudeHookProcessor(
        policy_pack="mcp-server-governance",
        repo=tmp_path,
        audit_dir=tmp_path / "audit",
    )

    decision = processor.process(
        {
            "session_id": "sess-004",
            "hook_event_name": "PreToolUse",
            "tool_name": "mcp__github-enterprise__delete_repo",
            "tool_input": {},
        }
    )

    assert decision.decision == "block"
    assert json.dumps(decision.output)
