from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import _github_event_pr_number, app
from terraguard_agentshield.evidence import (
    create_evidence_bundle,
    latest_audit_file,
    load_audit_for_validation,
    read_evidence_bundle,
    validate_attestation,
    verify_evidence_bundle,
)
from terraguard_agentshield.policy_signing import generate_ed25519_key_pair


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


def test_evidence_bundle_round_trip(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    audit = SessionAudit(session_id="sess-bundle", tool="codex", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))

    bundle = create_evidence_bundle(
        audit,
        private_key.read_bytes(),
        signer="platform-security",
        risk={"decision": "warn", "max_risk": "medium"},
        metadata={"change": "CHG001"},
    )
    output = tmp_path / "bundle.json"
    bundle.write(output)

    loaded = read_evidence_bundle(output)
    result = verify_evidence_bundle(loaded, public_key.read_bytes())

    assert result.valid
    assert result.bundle_id == "bundle-sess-bundle"
    assert result.summary["session_id"] == "sess-bundle"
    assert loaded.metadata["change"] == "CHG001"


def test_evidence_bundle_detects_tampering(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    audit = SessionAudit(session_id="sess-tamper", tool="codex", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))
    bundle = create_evidence_bundle(audit, private_key.read_bytes(), signer="security")
    payload = bundle.to_dict()
    payload["audit"]["tool"] = "tampered"

    tampered = read_evidence_bundle(_write_json(tmp_path / "tampered.json", payload))
    result = verify_evidence_bundle(tampered, public_key.read_bytes())

    assert not result.valid
    assert "digest" in result.failures[0]


def test_evidence_bundle_cli_create_and_verify(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    audit = SessionAudit(session_id="sess-cli-bundle", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="execute_command", target="terraform plan", decision="allow"))
    audit.write(tmp_path)
    risk_path = _write_json(tmp_path / "risk.json", {"decision": "pass", "max_risk": "low"})
    output = tmp_path / "evidence.json"

    bundle_result = runner.invoke(
        app,
        [
            "evidence",
            "bundle",
            "--session-id",
            "sess-cli-bundle",
            "--audit-dir",
            str(tmp_path),
            "--private-key",
            str(private_key),
            "--risk",
            str(risk_path),
            "--metadata",
            "change=CHG123",
            "--output",
            str(output),
        ],
    )
    verify_result = runner.invoke(
        app,
        [
            "evidence",
            "verify-bundle",
            str(output),
            "--public-key",
            str(public_key),
        ],
    )

    assert bundle_result.exit_code == 0
    assert verify_result.exit_code == 0
    assert output.exists()


def _write_json(path: Path, payload: dict[str, object]) -> Path:
    import json

    path.write_text(json.dumps(payload), encoding="utf-8")
    return path
