import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.agent_detector import detect_ai_agent_change
from terraguard_agentshield.audit import SessionAudit
from terraguard_agentshield.cli import app


runner = CliRunner()


def test_copilot_branch_detects_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, branch="copilot/fix-policy")

    assert result.detected
    assert result.agent_type == "github-copilot"


def test_codex_branch_detects_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, branch="codex/add-tests")

    assert result.detected
    assert result.agent_type == "openai-codex"


def test_claude_commit_message_detects_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(
        repo=tmp_path,
        commit_messages=["Generated with Claude Code"],
    )

    assert result.detected
    assert result.agent_type == "claude-code"


def test_cursor_signal_detects_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, pr_body="Implemented with Cursor")

    assert result.detected
    assert result.agent_type == "cursor"


def test_generic_bot_without_ai_signal_is_not_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, authors=["build-bot"])

    assert not result.detected
    assert result.confidence == "none"


def test_dependabot_alone_is_automation_not_ai_agent(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, authors=["dependabot[bot]"])

    assert not result.detected
    assert result.agent_type == "automation-bot"
    assert result.confidence == "low"


def test_multiple_signals_increase_confidence(tmp_path: Path) -> None:
    result = detect_ai_agent_change(
        repo=tmp_path,
        branch="copilot/fix-policy",
        commit_messages=["Co-authored-by: GitHub Copilot"],
    )

    assert result.detected
    assert result.confidence == "high"
    assert result.score >= 80


def test_empty_input_returns_not_detected(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path)

    assert not result.detected
    assert result.confidence == "none"
    assert result.score == 0


def test_audit_metadata_detects_tool(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    SessionAudit(session_id="detect-1", tool="claude-code", repo=tmp_path).write(audit_dir)

    result = detect_ai_agent_change(repo=tmp_path, audit_dir=audit_dir)

    assert result.detected
    assert result.agent_type == "claude-code"


def test_json_serialization_and_cli_output(tmp_path: Path) -> None:
    result = detect_ai_agent_change(repo=tmp_path, branch="copilot/demo")
    payload = json.loads(result.to_json())

    assert payload["detected"] is True
    assert payload["signals"][0]["source"] == "branch"

    output = tmp_path / "detect.json"
    cli_result = runner.invoke(
        app,
        [
            "agent",
            "detect",
            "--repo",
            str(tmp_path),
            "--branch",
            "copilot/demo",
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    assert cli_result.exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8"))["detected"] is True
