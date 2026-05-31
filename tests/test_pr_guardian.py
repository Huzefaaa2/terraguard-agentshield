import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.pr_guardian import PRGuardianConfig, run_pr_guardian


runner = CliRunner()


HIGH_RISK_DIFF = """diff --git a/main.tf b/main.tf
--- a/main.tf
+++ b/main.tf
@@ -0,0 +1,3 @@
+resource "aws_security_group_rule" "ssh" {
+  cidr_blocks = ["0.0.0.0/0"]
+}
"""

LOW_RISK_DIFF = """diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 # Demo
+Documentation only.
"""


def test_pr_guardian_reads_diff_and_produces_risk_summary(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(HIGH_RISK_DIFF, encoding="utf-8")

    result = run_pr_guardian(
        PRGuardianConfig(
            diff_path=diff,
            output_dir=tmp_path / "out",
            branch="copilot/demo",
            dry_run=True,
        )
    )

    assert result.max_risk == "critical"
    assert result.risk_summary["finding_count"] >= 1
    assert result.ai_agent_detected is True
    assert result.explanation["items"]


def test_pr_guardian_writes_json_and_markdown_outputs(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    output_dir = tmp_path / "guardian"
    diff.write_text(HIGH_RISK_DIFF, encoding="utf-8")

    result = run_pr_guardian(
        PRGuardianConfig(diff_path=diff, output_dir=output_dir, dry_run=True)
    )

    assert Path(result.json_report_path or "").exists()
    assert Path(result.markdown_report_path or "").exists()
    assert (output_dir / "agentshield-policy-explanation.md").exists()
    assert "TerraGuard AgentShield PR Guardian" in result.markdown_report
    assert json.loads((output_dir / "agentshield-pr-guardian.json").read_text())[
        "max_risk"
    ] == "critical"


def test_pr_guardian_sets_should_fail_for_high_threshold(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(HIGH_RISK_DIFF, encoding="utf-8")

    result = run_pr_guardian(
        PRGuardianConfig(diff_path=diff, output_dir=tmp_path / "out", fail_on="high")
    )

    assert result.should_fail is True


def test_pr_guardian_sets_should_fail_false_for_low_risk(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(LOW_RISK_DIFF, encoding="utf-8")

    result = run_pr_guardian(
        PRGuardianConfig(diff_path=diff, output_dir=tmp_path / "out", fail_on="high")
    )

    assert result.should_fail is False
    assert result.decision == "pass"


def test_pr_guardian_empty_findings_do_not_fail_low_threshold(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(LOW_RISK_DIFF, encoding="utf-8")

    result = run_pr_guardian(
        PRGuardianConfig(diff_path=diff, output_dir=tmp_path / "out", fail_on="low")
    )

    assert result.should_fail is False


def test_pr_guardian_dry_run_does_not_call_github(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(HIGH_RISK_DIFF, encoding="utf-8")

    def fail_publisher(*args: object, **kwargs: object) -> object:
        raise AssertionError("publisher should not be constructed")

    monkeypatch.setattr("terraguard_agentshield.pr_guardian.GitHubPRCommentPublisher", fail_publisher)

    result = run_pr_guardian(
        PRGuardianConfig(
            diff_path=diff,
            output_dir=tmp_path / "out",
            publish_comment=True,
            dry_run=True,
        )
    )

    assert result.pr_comment_url is None


def test_pr_guardian_publish_is_mocked(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    diff = tmp_path / "change.diff"
    diff.write_text(LOW_RISK_DIFF, encoding="utf-8")

    class FakePublisher:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def publish(self, repo: str, pr_number: int, body: str) -> object:
            assert repo == "owner/repo"
            assert pr_number == 123
            assert "PR Guardian" in body

            class Result:
                success = True
                comment_url = "https://github.example/comment"
                error = None

            return Result()

    monkeypatch.setattr("terraguard_agentshield.pr_guardian.GitHubPRCommentPublisher", FakePublisher)

    result = run_pr_guardian(
        PRGuardianConfig(
            diff_path=diff,
            repo="owner/repo",
            pr_number=123,
            github_token="token",
            publish_comment=True,
            output_dir=tmp_path / "out",
        )
    )

    assert result.pr_comment_url == "https://github.example/comment"


def test_pr_guardian_missing_diff_has_clear_error(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Diff file not found"):
        run_pr_guardian(PRGuardianConfig(diff_path=tmp_path / "missing.diff"))


def test_pr_guardian_cli_writes_reports_before_failing(tmp_path: Path) -> None:
    diff = tmp_path / "change.diff"
    output_dir = tmp_path / "out"
    diff.write_text(HIGH_RISK_DIFF, encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "pr",
            "guard",
            "--diff",
            str(diff),
            "--fail-on",
            "high",
            "--dry-run",
            "--output-dir",
            str(output_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 1
    assert (output_dir / "agentshield-pr-guardian.json").exists()
    assert (output_dir / "agentshield-pr-guardian.md").exists()


def test_new_cli_help_commands_exist() -> None:
    assert runner.invoke(app, ["pr", "guard", "--help"]).exit_code == 0
    assert runner.invoke(app, ["agent", "detect", "--help"]).exit_code == 0
    assert runner.invoke(app, ["policy", "explain", "--help"]).exit_code == 0
