from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pr_guardian_workflows_exist() -> None:
    assert (ROOT / ".github/workflows/agentshield-pr-guardian.yml").exists()
    assert (ROOT / "examples/github-actions/agentshield-pr-guardian.yml").exists()


def test_pr_guardian_workflow_contains_required_shape() -> None:
    workflow = (ROOT / ".github/workflows/agentshield-pr-guardian.yml").read_text(
        encoding="utf-8"
    )
    example = (ROOT / "examples/github-actions/agentshield-pr-guardian.yml").read_text(
        encoding="utf-8"
    )

    for text in (workflow, example):
        assert "pull_request:" in text
        assert "contents: read" in text
        assert "pull-requests: write" in text
        assert "terraguard-agentshield pr guard" in text
        assert "actions/upload-artifact" in text
        assert "secrets.GITHUB_TOKEN" in text
        assert "PRIVATE_KEY" not in text
        assert "PASSWORD" not in text
