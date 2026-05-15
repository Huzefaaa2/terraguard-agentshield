from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.integrations import (
    CommandInterceptor,
    GitHubPRAttestationExporter,
    WebhookExporter,
)
from terraguard_agentshield.runtime import RuntimeGuard


def test_command_interceptor_blocks_terraform_apply() -> None:
    guard = RuntimeGuard(policy_pack="ai-agent-baseline")

    session = SessionAudit(session_id="test-001", tool="claude-code", repo=Path("."))
    interceptor = CommandInterceptor(guard, session)

    result = interceptor.execute("terraform apply -auto-approve")
    assert not result.success
    assert "blocked" in result.error.lower()
    assert len(session.actions) == 1
    assert session.actions[0].decision == "block"


def test_github_attestation_export() -> None:
    session = SessionAudit(session_id="test-001", tool="claude-code", repo=Path("."))
    session.add_action(
        AuditAction(type="execute_command", target="terraform apply", decision="block")
    )
    session.add_action(
        AuditAction(type="read_file", target=".env", decision="block")
    )

    markdown = GitHubPRAttestationExporter.export_comment(session)
    assert "TerraGuard AgentShield Governance Report" in markdown
    assert "Blocked Actions" in markdown
    assert "terraform apply" in markdown
    assert ".env" in markdown


def test_attestation_artifact_export(tmp_path: Path) -> None:
    session = SessionAudit(session_id="test-002", tool="claude-code", repo=Path("."))
    session.add_action(
        AuditAction(type="execute_command", target="terraform plan", decision="allow")
    )

    artifact_path = GitHubPRAttestationExporter.save_artifact(session, tmp_path)
    assert artifact_path.exists()
    assert artifact_path.name.startswith("agentshield-attestation-")

    import json

    content = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert content["session_id"] == "test-002"
    assert len(content["actions"]) == 1


def test_session_audit_round_trip_from_json_payload() -> None:
    session = SessionAudit(
        session_id="test-003",
        tool="codex",
        repo=Path("/repo"),
        policy_pack="banking-regulated-ai",
    )
    session.add_action(
        AuditAction(
            type="mcp_connect",
            target="github-enterprise",
            decision="allow",
            metadata={"capability": "read_repo"},
        )
    )

    parsed = SessionAudit.from_dict(session.to_dict())
    assert parsed.session_id == "test-003"
    assert parsed.repo == Path("/repo")
    assert parsed.policy_pack == "banking-regulated-ai"
    assert parsed.actions[0].metadata["capability"] == "read_repo"


def test_webhook_exporter_sends_signed_payload(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class Response:
        status = 202

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args) -> None:
            return None

    def fake_urlopen(request: Request, timeout: int) -> Response:
        captured["request"] = request
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    audit = SessionAudit(session_id="test-004", tool="claude-code", repo=Path("."))

    ok = WebhookExporter(
        "https://example.com/events", hmac_secret="secret", timeout=3
    ).export(audit)

    request = captured["request"]
    assert ok
    assert captured["timeout"] == 3
    assert isinstance(request, Request)
    assert request.headers["X-agentshield-signature"].startswith("sha256=")


def test_webhook_exporter_returns_false_on_delivery_error(monkeypatch) -> None:
    def fake_urlopen(request: Request, timeout: int) -> None:
        raise URLError("down")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    audit = SessionAudit(session_id="test-005", tool="claude-code", repo=Path("."))

    assert not WebhookExporter("https://example.com/events").export(audit)
