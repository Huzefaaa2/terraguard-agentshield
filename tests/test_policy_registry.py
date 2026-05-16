from pathlib import Path

import yaml
from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.policy_registry import PolicyRegistry, merge_policy


runner = CliRunner()


def test_list_policy_packs() -> None:
    root = Path(__file__).resolve().parents[1] / "policies"
    registry = PolicyRegistry(root=root)
    packs = registry.list_policy_packs()
    assert any(pack["id"] == "ai-agent-baseline" for pack in packs)
    assert any(pack["id"] == "banking-regulated-ai" for pack in packs)


def test_get_policy_pack() -> None:
    root = Path(__file__).resolve().parents[1] / "policies"
    registry = PolicyRegistry(root=root)
    pack = registry.get_policy_pack("ai-agent-baseline")
    assert pack["title"] == "AI Agent Baseline Governance"
    assert "policy" in pack and "filesystem" in pack["policy"]


def test_merge_policy_adds_lists_and_overrides_scalars() -> None:
    base = {
        "metadata": {"id": "enterprise", "version": "1.0"},
        "commands": {"block": ["terraform apply*"], "allow": ["pytest*"]},
        "git": {"block_direct_push_to_protected_branch": True},
    }
    overlay = {
        "metadata": {"id": "repo"},
        "commands": {"block": ["kubectl delete*", "terraform apply*"]},
        "git": {"protected_branches": ["main"]},
    }

    merged = merge_policy(base, overlay)

    assert merged["metadata"]["id"] == "repo"
    assert merged["commands"]["block"] == ["terraform apply*", "kubectl delete*"]
    assert merged["commands"]["allow"] == ["pytest*"]
    assert merged["git"]["block_direct_push_to_protected_branch"] is True
    assert merged["git"]["protected_branches"] == ["main"]


def test_resolve_policy_layers(tmp_path: Path) -> None:
    _write_policy(
        tmp_path,
        "enterprise",
        {
            "metadata": {"id": "enterprise"},
            "filesystem": {"block_read": [".env"]},
            "commands": {"block": ["terraform apply*"], "allow": ["pytest*"]},
        },
    )
    _write_policy(
        tmp_path,
        "business-unit",
        {
            "metadata": {"id": "business-unit"},
            "commands": {"require_approval": ["aws *"]},
        },
    )
    _write_policy(
        tmp_path,
        "repository",
        {
            "metadata": {"id": "repository"},
            "filesystem": {"require_approval_write": ["src/auth/**"]},
            "commands": {"allow": ["ruff*"]},
        },
    )

    policy = PolicyRegistry(root=tmp_path).resolve_policy(
        enterprise="enterprise",
        business_unit="business-unit",
        repository="repository",
    )

    assert policy["filesystem"]["block_read"] == [".env"]
    assert policy["filesystem"]["require_approval_write"] == ["src/auth/**"]
    assert policy["commands"]["block"] == ["terraform apply*"]
    assert policy["commands"]["require_approval"] == ["aws *"]
    assert policy["commands"]["allow"] == ["pytest*", "ruff*"]
    assert policy["metadata"]["resolved_layers"] == [
        "enterprise",
        "business-unit",
        "repository",
    ]


def test_policy_resolve_cli_writes_output(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "policies"
    _write_policy(root, "enterprise", {"metadata": {"id": "enterprise"}})
    _write_policy(root, "repo", {"metadata": {"id": "repo"}, "commands": {"block": ["rm -rf *"]}})
    output = tmp_path / "resolved.json"
    monkeypatch.setattr("terraguard_agentshield.policy_registry.POLICY_DIR", root)

    result = runner.invoke(
        app,
        [
            "policy",
            "resolve",
            "--enterprise",
            "enterprise",
            "--repository",
            "repo",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert output.exists()
    assert "rm -rf *" in output.read_text(encoding="utf-8")


def _write_policy(root: Path, pack_id: str, content: dict) -> None:
    pack_dir = root / pack_id
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "policy.yaml").write_text(yaml.safe_dump(content), encoding="utf-8")
