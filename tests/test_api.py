import yaml
from fastapi.testclient import TestClient

from terraguard_agentshield.api import create_app
from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.evidence import create_evidence_bundle
from terraguard_agentshield.policy_signing import generate_ed25519_key_pair


def test_api_health() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "terraguard-agentshield",
    }


def test_api_lists_and_reads_policy_packs() -> None:
    client = TestClient(create_app())

    list_response = client.get("/policies")
    detail_response = client.get("/policies/ai-agent-baseline")

    assert list_response.status_code == 200
    assert any(
        policy["id"] == "ai-agent-baseline"
        for policy in list_response.json()["policies"]
    )
    assert detail_response.status_code == 200
    assert detail_response.json()["id"] == "ai-agent-baseline"


def test_api_resolves_layered_policy(tmp_path) -> None:
    _write_policy(
        tmp_path,
        "enterprise",
        {
            "metadata": {"id": "enterprise"},
            "commands": {"block": ["terraform apply*"]},
            "filesystem": {"block_read": [".env"]},
        },
    )
    _write_policy(
        tmp_path,
        "repo",
        {
            "metadata": {"id": "repo"},
            "commands": {"allow": ["pytest*"]},
            "filesystem": {"require_approval_write": ["src/auth/**"]},
        },
    )
    client = TestClient(create_app(policy_root=tmp_path))

    response = client.post(
        "/policies/resolve",
        json={"enterprise": "enterprise", "repository": "repo"},
    )

    assert response.status_code == 200
    policy = response.json()["policy"]
    assert policy["metadata"]["resolved_layers"] == ["enterprise", "repo"]
    assert policy["commands"]["block"] == ["terraform apply*"]
    assert policy["commands"]["allow"] == ["pytest*"]
    assert policy["filesystem"]["block_read"] == [".env"]


def test_api_lists_and_reads_evidence_bundles(tmp_path) -> None:
    data_dir = tmp_path / "data"
    bundle_dir = data_dir / "evidence"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    audit = SessionAudit(
        session_id="api-session",
        tool="codex",
        repo=tmp_path,
        policy_pack="banking-regulated-ai",
    )
    audit.add_action(AuditAction(type="execute_command", target="pytest", decision="allow"))
    bundle = create_evidence_bundle(
        audit,
        private_key.read_bytes(),
        signer="platform-security",
        risk={"decision": "warn", "max_risk": "medium"},
    )
    bundle.write(bundle_dir / "api-bundle.json")
    client = TestClient(create_app(data_dir=data_dir))

    list_response = client.get("/evidence/bundles")
    detail_response = client.get(f"/evidence/bundles/{bundle.bundle_id}")

    assert list_response.status_code == 200
    bundles = list_response.json()["bundles"]
    assert len(bundles) == 1
    assert bundles[0]["bundle_id"] == "bundle-api-session"
    assert bundles[0]["risk_max"] == "medium"
    assert detail_response.status_code == 200
    assert detail_response.json()["audit"]["session_id"] == "api-session"


def test_api_summarizes_evidence(tmp_path) -> None:
    data_dir = tmp_path / "data"
    audit_dir = data_dir / "audit"
    audit = SessionAudit(session_id="api-summary", tool="claude-code", repo=tmp_path)
    audit.add_action(AuditAction(type="read_file", target=".env", decision="block"))
    audit.write(audit_dir)
    client = TestClient(create_app(data_dir=data_dir))

    response = client.get("/evidence/summary")

    assert response.status_code == 200
    payload = response.json()
    assert payload["session_count"] == 1
    assert payload["decisions"]["block"] == 1
    assert payload["control_families"]["data-protection"]["actions"] == 1


def test_api_routes_approvals(tmp_path) -> None:
    data_dir = tmp_path / "data"
    audit_dir = data_dir / "audit"
    audit = SessionAudit(session_id="api-approval", tool="codex", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change", "risk": "critical"},
        )
    )
    audit.write(audit_dir)
    client = TestClient(create_app(data_dir=data_dir))

    response = client.get("/approval/routes")

    assert response.status_code == 200
    payload = response.json()
    assert payload["route_count"] == 1
    assert payload["routes"][0]["approver_group"] == "platform-security"
    assert payload["routes"][0]["priority"] == "critical"


def test_api_lists_compliance_mappings() -> None:
    client = TestClient(create_app())

    response = client.get("/compliance/mappings")

    assert response.status_code == 200
    payload = response.json()
    assert "data-protection" in payload["mappings"]
    assert "soc2" in payload["mappings"]["data-protection"]


def test_api_maps_compliance_summary(tmp_path) -> None:
    data_dir = tmp_path / "data"
    audit_dir = data_dir / "audit"
    audit = SessionAudit(session_id="api-compliance", tool="codex", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change"},
        )
    )
    audit.write(audit_dir)
    client = TestClient(create_app(data_dir=data_dir))

    response = client.get("/compliance/summary")

    assert response.status_code == 200
    payload = response.json()
    assert "infrastructure-change" in payload["active_mappings"]
    assert "pci_dss" in payload["active_mappings"]["infrastructure-change"]["frameworks"]


def test_api_classifies_diff_risk() -> None:
    client = TestClient(create_app())
    diff = """diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -0,0 +1 @@
+cidr_blocks = ["0.0.0.0/0"]
"""

    response = client.post("/risk/diff", json={"diff": diff, "fail_on": "high"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"] == "block"
    assert payload["max_risk"] == "critical"
    assert payload["failed_threshold"] is True


def _write_policy(root, pack_id: str, content: dict) -> None:
    pack_dir = root / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "policy.yaml").write_text(yaml.safe_dump(content), encoding="utf-8")
