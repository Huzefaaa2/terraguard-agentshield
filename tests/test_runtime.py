from pathlib import Path

from terraguard_agentshield.policy_registry import PolicyRegistry
from terraguard_agentshield.runtime import RuntimeGuard


def test_runtime_guard_blocks_sensitive_read() -> None:
    guard = RuntimeGuard(policy_pack="ai-agent-baseline")
    decision = guard.evaluate_file_access(Path(".env"), "read")
    assert decision.decision == "block"


def test_runtime_guard_blocks_sensitive_absolute_read() -> None:
    guard = RuntimeGuard(policy_pack="ai-agent-baseline")
    decision = guard.evaluate_file_access(Path("/repo/app/.env"), "read")
    assert decision.decision == "block"


def test_runtime_guard_requires_approval_for_sensitive_write() -> None:
    guard = RuntimeGuard(policy_pack="banking-regulated-ai")
    decision = guard.evaluate_file_access(Path("platform/iam/role.tf"), "write")
    assert decision.decision == "require_approval"


def test_runtime_guard_blocks_terraform_apply() -> None:
    guard = RuntimeGuard(policy_pack="ai-agent-baseline")
    decision = guard.evaluate_command("terraform apply -auto-approve")
    assert decision.decision == "block"


def test_runtime_guard_requires_approval_for_policy_command() -> None:
    guard = RuntimeGuard(policy_pack="banking-regulated-ai")
    decision = guard.evaluate_command("aws s3 ls")
    assert decision.decision == "require_approval"


def test_runtime_guard_requires_approval_for_unknown_command() -> None:
    guard = RuntimeGuard(policy_pack="ai-agent-baseline")
    decision = guard.evaluate_command("python scripts/custom_release.py")
    assert decision.decision == "require_approval"


def test_runtime_guard_blocks_mcp_unknown_server() -> None:
    guard = RuntimeGuard(policy_pack="mcp-server-governance")
    decision = guard.evaluate_mcp_server("personal-drive-mcp")
    assert decision.decision == "block"


def test_runtime_guard_allows_mcp_approved_server() -> None:
    guard = RuntimeGuard(policy_pack="mcp-server-governance")
    decision = guard.evaluate_mcp_server("github-enterprise", capability="read_repo")
    assert decision.decision == "allow"


def test_runtime_guard_blocks_mcp_dangerous_capability() -> None:
    guard = RuntimeGuard(policy_pack="mcp-server-governance")
    decision = guard.evaluate_mcp_server("github-enterprise", capability="delete_repo")
    assert decision.decision == "block"


def test_runtime_guard_uses_inherited_policy_layers(monkeypatch) -> None:
    def fake_resolve_policy(self, **kwargs):
        assert kwargs["enterprise"] == "enterprise"
        assert kwargs["repository"] == "repo"
        return {
            "metadata": {"id": "resolved", "resolved_layers": ["enterprise", "repo"]},
            "filesystem": {"block_read": [".env"]},
            "commands": {"block": ["terraform apply*"], "allow": ["pytest*"]},
        }

    monkeypatch.setattr(PolicyRegistry, "resolve_policy", fake_resolve_policy)

    guard = RuntimeGuard(
        enterprise_policy="enterprise",
        repository_policy="repo",
        policy_pack=None,
    )

    assert guard.evaluate_file_access(Path(".env"), "read").decision == "block"
    assert guard.evaluate_command("terraform apply").decision == "block"
    assert guard.evaluate_command("pytest").decision == "allow"
