from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.integrations import (
    CommandInterceptor,
    GitHubPRCommentPublisher,
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


def test_webhook_exporter_retries_transient_failure(monkeypatch) -> None:
    calls = 0

    class Response:
        status = 202

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args) -> None:
            return None

    def fake_urlopen(request: Request, timeout: int) -> Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise URLError("temporary")
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("time.sleep", lambda seconds: None)
    audit = SessionAudit(session_id="test-retry", tool="claude-code", repo=Path("."))

    result = WebhookExporter(
        "https://example.com/events", retries=2, backoff_seconds=0
    ).deliver(audit)

    assert result.success
    assert result.attempts == 2
    assert calls == 2


def test_webhook_exporter_returns_false_on_delivery_error(monkeypatch) -> None:
    def fake_urlopen(request: Request, timeout: int) -> None:
        raise URLError("down")

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    audit = SessionAudit(session_id="test-005", tool="claude-code", repo=Path("."))

    assert not WebhookExporter("https://example.com/events", retries=0).export(audit)


def test_github_pr_comment_publisher_creates_comment(monkeypatch) -> None:
    requests: list[Request] = []

    class Response:
        def __init__(self, payload: object) -> None:
            self.payload = payload

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args) -> None:
            return None

        def read(self) -> bytes:
            import json

            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request: Request, timeout: int) -> Response:
        requests.append(request)
        if request.get_method() == "GET":
            return Response([])
        return Response({"html_url": "https://github.example/comment/1"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = GitHubPRCommentPublisher("token", api_url="https://api.github.test").publish(
        "owner/repo", 12, "body"
    )

    assert result.success
    assert result.action == "created"
    assert [request.get_method() for request in requests] == ["GET", "POST"]


def test_github_pr_comment_publisher_updates_existing_comment(monkeypatch) -> None:
    requests: list[Request] = []

    class Response:
        def __init__(self, payload: object) -> None:
            self.payload = payload

        def __enter__(self) -> "Response":
            return self

        def __exit__(self, *args) -> None:
            return None

        def read(self) -> bytes:
            import json

            return json.dumps(self.payload).encode("utf-8")

    def fake_urlopen(request: Request, timeout: int) -> Response:
        requests.append(request)
        if request.get_method() == "GET":
            return Response(
                [{"id": 99, "body": "<!-- terraguard-agentshield-attestation -->\nold"}]
            )
        return Response({"html_url": "https://github.example/comment/99"})

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = GitHubPRCommentPublisher("token", api_url="https://api.github.test").publish(
        "owner/repo", 12, "body"
    )

    assert result.success
    assert result.action == "updated"
    assert [request.get_method() for request in requests] == ["GET", "PATCH"]
