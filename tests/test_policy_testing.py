import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.policy_testing import (
    load_policy_test_suite,
    render_text_result,
    run_policy_test_file,
    run_policy_test_suite,
)


runner = CliRunner()


def test_policy_test_suite_passes_for_builtin_baseline() -> None:
    suite_path = (
        Path(__file__).resolve().parents[1]
        / "examples/policy-tests/ai-agent-baseline.yaml"
    )

    result = run_policy_test_file(suite_path)

    assert result.passed
    assert result.case_count == 6
    assert result.failed_count == 0


def test_policy_test_suite_reports_failures(tmp_path: Path) -> None:
    suite_path = tmp_path / "suite.yaml"
    suite_path.write_text(
        yaml.safe_dump(
            {
                "name": "Expected failure",
                "policy_pack": "ai-agent-baseline",
                "cases": [
                    {
                        "name": "Wrong expectation",
                        "action": "command",
                        "command": "terraform apply",
                        "expect": "allow",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    result = run_policy_test_file(suite_path)

    assert not result.passed
    assert result.failed_count == 1
    assert result.results[0].actual == "block"


def test_policy_test_cli_outputs_json(tmp_path: Path) -> None:
    suite_path = (
        Path(__file__).resolve().parents[1]
        / "examples/policy-tests/mcp-server-governance.yaml"
    )
    output = tmp_path / "policy-test.json"

    result = runner.invoke(
        app,
        [
            "policy",
            "test",
            str(suite_path),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert payload["passed"] is True
    assert payload["case_count"] == 3


def test_policy_test_suite_uses_custom_policy_root(tmp_path: Path) -> None:
    policy_root = tmp_path / "policies"
    pack_dir = policy_root / "custom"
    pack_dir.mkdir(parents=True)
    (pack_dir / "policy.yaml").write_text(
        yaml.safe_dump(
            {
                "metadata": {"id": "custom", "title": "Custom"},
                "commands": {"block": ["danger *"], "allow": ["safe *"]},
            }
        ),
        encoding="utf-8",
    )
    suite = load_policy_test_suite(
        _write_suite(
            tmp_path / "suite.yaml",
            {
                "name": "Custom suite",
                "policy_pack": "custom",
                "cases": [
                    {
                        "name": "Block danger",
                        "action": "command",
                        "command": "danger now",
                        "expect": "block",
                    }
                ],
            },
        )
    )

    result = run_policy_test_suite(suite, policy_root=policy_root)

    assert result.passed
    assert "PASS Block danger" in render_text_result(result)


def _write_suite(path: Path, payload: dict) -> Path:
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path
