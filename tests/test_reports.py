import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import app
from terraguard_agentshield.reports import (
    create_governance_report,
    render_markdown_report,
)


runner = CliRunner()


def test_create_governance_report_combines_sections(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="report-001", tool="codex", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change", "risk": "critical"},
        )
    )
    audit.write(audit_dir)
    validation = {"valid": False, "session_id": "report-001", "failures": ["blocked"]}

    report = create_governance_report(
        audit_dir=audit_dir,
        bundle_dir=tmp_path / "missing",
        validation=validation,
        metadata={"change": "CHG123"},
    ).to_dict()

    assert report["status"] == "failed"
    assert report["validation"]["failures"] == ["blocked"]
    assert report["decision_summary"]["decisions"]["block"] == 1
    assert report["approval_routes"]["routes"][0]["approver_group"] == "platform-security"
    assert "infrastructure-change" in report["compliance"]["active_mappings"]
    assert report["metadata"]["change"] == "CHG123"


def test_render_markdown_report(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="report-md", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="read_file", target=".env", decision="block"))
    audit.write(audit_dir)
    report = create_governance_report(audit_dir=audit_dir, bundle_dir=tmp_path / "missing")

    markdown = render_markdown_report(report)

    assert "TerraGuard AgentShield Check Summary" in markdown
    assert "### Decisions" in markdown
    assert "### Approval Routes" in markdown
    assert "### Compliance Mapping" in markdown


def test_report_generate_cli_writes_markdown(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="report-cli", tool="codex", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))
    audit.write(audit_dir)
    validation = tmp_path / "validation.json"
    validation.write_text(
        json.dumps({"valid": True, "session_id": "report-cli", "failures": []}),
        encoding="utf-8",
    )
    output = tmp_path / "report.md"

    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--audit-dir",
            str(audit_dir),
            "--bundle-dir",
            str(tmp_path / "missing"),
            "--validation",
            str(validation),
            "--output",
            str(output),
            "--metadata",
            "change=CHG123",
        ],
    )

    assert result.exit_code == 0
    text = output.read_text(encoding="utf-8")
    assert "Status: **passed**" in text
    assert "Validation" in text


def test_report_generate_cli_outputs_json(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="report-json", tool="cursor", repo=tmp_path)
    audit.add_action(AuditAction(type="mcp_connect", target="github-enterprise", decision="allow"))
    audit.write(audit_dir)
    output = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "--audit-dir",
            str(audit_dir),
            "--bundle-dir",
            str(tmp_path / "missing"),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert payload["decision_summary"]["action_count"] == 1
    assert payload["status"] == "passed"
