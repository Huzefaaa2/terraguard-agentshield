import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import app
from terraguard_agentshield.compliance import (
    list_compliance_mappings,
    map_summary_to_compliance,
    render_text_mappings,
)
from terraguard_agentshield.summary import summarize_audits


runner = CliRunner()


def test_list_compliance_mappings_contains_frameworks() -> None:
    result = list_compliance_mappings().to_dict()

    assert result["framework_count"] == 5
    assert "data-protection" in result["mappings"]
    assert "iso27001" in result["mappings"]["data-protection"]
    assert "nist_ssdf" in result["mappings"]["data-protection"]


def test_map_summary_to_compliance_includes_active_families(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="compliance-001", tool="codex", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change"},
        )
    )
    summary = summarize_audits([audit])

    result = map_summary_to_compliance(summary).to_dict()

    active = result["active_mappings"]["infrastructure-change"]
    assert active["activity"]["actions"] == 1
    assert "pci_dss" in active["frameworks"]
    assert "nist_ssdf" in active["frameworks"]


def test_compliance_cli_outputs_json(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="compliance-cli", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="read_file", target=".env", decision="block"))
    audit.write(audit_dir)
    output = tmp_path / "compliance.json"

    result = runner.invoke(
        app,
        [
            "compliance",
            "map",
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
    assert "data-protection" in payload["active_mappings"]


def test_render_text_mappings() -> None:
    text = render_text_mappings(list_compliance_mappings())

    assert "TerraGuard AgentShield Compliance Mapping" in text
    assert "data-protection" in text
    assert "Mappings are implementation guidance" in text
