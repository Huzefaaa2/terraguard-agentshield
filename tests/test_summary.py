import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import app
from terraguard_agentshield.evidence import create_evidence_bundle
from terraguard_agentshield.policy_signing import generate_ed25519_key_pair
from terraguard_agentshield.summary import (
    render_text_summary,
    summarize_audits,
    summarize_bundle_dir,
    summarize_evidence,
)


runner = CliRunner()


def test_summarize_audits_counts_decisions_and_control_families(tmp_path: Path) -> None:
    audit = SessionAudit(
        session_id="summary-001",
        tool="claude-code",
        repo=tmp_path,
        policy_pack="banking-regulated-ai",
        environment="regulated",
    )
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change", "risk": "critical"},
        )
    )
    audit.add_action(
        AuditAction(type="read_file", target=".env", decision="block")
    )

    summary = summarize_audits([audit]).to_dict()

    assert summary["session_count"] == 1
    assert summary["action_count"] == 2
    assert summary["decisions"]["block"] == 2
    assert summary["risks"]["critical"] == 1
    assert summary["control_families"]["infrastructure-change"]["actions"] == 1
    assert summary["control_families"]["data-protection"]["actions"] == 1
    assert summary["top_blocked_targets"]["terraform apply"] == 1


def test_summarize_bundle_dir_counts_risk_findings(tmp_path: Path) -> None:
    bundle_dir = tmp_path / "evidence"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    audit = SessionAudit(session_id="summary-002", tool="codex", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))
    bundle = create_evidence_bundle(
        audit,
        private_key.read_bytes(),
        signer="security",
        risk={
            "decision": "block",
            "max_risk": "critical",
            "findings": [
                {
                    "risk": "critical",
                    "category": "public-exposure",
                    "control_family": "network-security",
                },
                {
                    "risk": "high",
                    "category": "encryption",
                    "control_family": "data-protection",
                },
            ],
        },
    )
    bundle.write(bundle_dir / "bundle.json")

    summary = summarize_bundle_dir(bundle_dir).to_dict()

    assert summary["bundle_count"] == 1
    assert summary["session_count"] == 1
    assert summary["finding_count"] == 2
    assert summary["risks"] == {"critical": 1, "high": 1}
    assert summary["control_families"]["network-security"]["findings"] == 1
    assert summary["control_families"]["data-protection"]["findings"] == 1


def test_summary_cli_outputs_json(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="summary-cli", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="mcp_connect", target="personal-drive", decision="block"))
    audit.write(audit_dir)
    output = tmp_path / "summary.json"

    result = runner.invoke(
        app,
        [
            "evidence",
            "summary",
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
    assert payload["decisions"]["block"] == 1
    assert payload["control_families"]["tool-governance"]["actions"] == 1


def test_render_text_summary(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="summary-text", tool="cursor", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))

    text = render_text_summary(summarize_audits([audit]))

    assert "TerraGuard AgentShield Decision Summary" in text
    assert "Sessions: 1" in text
    assert "- allow: 1" in text


def test_summarize_evidence_combines_audits_and_bundles(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="summary-audit", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="read_file", target=".env", decision="block"))
    audit.write(audit_dir)

    bundle_dir = tmp_path / "evidence"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    bundle_audit = SessionAudit(session_id="summary-bundle", tool="codex", repo=tmp_path)
    bundle_audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))
    create_evidence_bundle(
        bundle_audit,
        private_key.read_bytes(),
        signer="security",
    ).write(bundle_dir / "bundle.json")

    summary = summarize_evidence(audit_dir=audit_dir, bundle_dir=bundle_dir).to_dict()

    assert summary["session_count"] == 2
    assert summary["bundle_count"] == 1
    assert summary["decisions"]["block"] == 1
    assert summary["decisions"]["allow"] == 1
