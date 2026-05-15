from pathlib import Path

import yaml
from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.policy_signing import (
    read_signature,
    sign_policy,
    verify_policy_signature,
)


runner = CliRunner()


def test_policy_signature_round_trip() -> None:
    policy = {
        "metadata": {"id": "test-policy", "version": "1.0.0"},
        "commands": {"block": ["terraform apply*"]},
    }

    signature = sign_policy(policy, "secret", signer="unit-test")
    valid, reason = verify_policy_signature(policy, signature, "secret")

    assert valid
    assert reason == "Policy signature verified."
    assert signature.policy_id == "test-policy"


def test_policy_signature_detects_tampering() -> None:
    policy = {
        "metadata": {"id": "test-policy", "version": "1.0.0"},
        "commands": {"block": ["terraform apply*"]},
    }
    tampered = {
        "metadata": {"id": "test-policy", "version": "1.0.0"},
        "commands": {"allow": ["terraform apply*"]},
    }

    signature = sign_policy(policy, "secret")
    valid, reason = verify_policy_signature(tampered, signature, "secret")

    assert not valid
    assert "digest" in reason


def test_policy_sign_and_verify_cli(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TERRAGUARD_AGENTSHIELD_POLICY_SECRET", "secret")
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "metadata": {"id": "cli-policy", "version": "1.0.0"},
                "commands": {"block": ["terraform apply*"]},
            }
        ),
        encoding="utf-8",
    )

    sign_result = runner.invoke(app, ["policy", "sign", str(policy_path)])
    verify_result = runner.invoke(app, ["policy", "verify", str(policy_path)])

    assert sign_result.exit_code == 0
    assert verify_result.exit_code == 0
    assert read_signature(policy_path.with_suffix(".yaml.sig")).policy_id == "cli-policy"
