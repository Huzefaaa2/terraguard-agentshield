from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import _github_event_pr_number, app
from terraguard_agentshield.evidence import (
    latest_audit_file,
    load_audit_for_validation,
    validate_attestation,
)


runner = CliRunner()


def test_latest_audit_file_and_load(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="sess-001", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="terraform plan", decision="allow"))
    audit.write(tmp_path)

    latest = latest_audit_file(tmp_path)
    loaded = load_audit_for_validation(tmp_path)

    assert latest is not None
    assert latest.name == "session-sess-001.json"
    assert loaded.session_id == "sess-001"


def test_validate_attestation_blocks_failed_decisions(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="sess-002", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="terraform apply", decision="block"))

    result = validate_attestation(audit)

    assert not result.valid
    assert result.failures == ["Audit contains 1 block action(s)."]


def test_validate_attestation_cli_success(tmp_path: Path) -> None:
    audit = SessionAudit(
        session_id="sess-003",
        tool="claude-code",
        repo=tmp_path,
        policy_pack="banking-regulated-ai",
    )
    audit.add_action(AuditAction(type="execute_command", target="terraform plan", decision="allow"))
    audit.write(tmp_path)

    result = runner.invoke(
        app,
        [
            "evidence",
            "validate",
            "--session-id",
            "sess-003",
            "--audit-dir",
            str(tmp_path),
            "--require-policy-pack",
            "banking-regulated-ai",
            "--output",
            str(tmp_path / "validation.json"),
        ],
    )

    assert result.exit_code == 0
    assert (tmp_path / "validation.json").exists()


def test_validate_attestation_cli_fails_on_block(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="sess-004", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="terraform apply", decision="block"))
    audit.write(tmp_path)

    result = runner.invoke(
        app,
        ["evidence", "validate", "--session-id", "sess-004", "--audit-dir", str(tmp_path)],
    )

    assert result.exit_code == 1
    assert "Audit contains 1 block action" in result.output


def test_github_event_pr_number(monkeypatch, tmp_path: Path) -> None:
    event_path = tmp_path / "event.json"
    event_path.write_text('{"pull_request":{"number":42}}', encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event_path))

    assert _github_event_pr_number() == 42
