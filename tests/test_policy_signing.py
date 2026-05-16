from pathlib import Path

import yaml
from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.policy_signing import (
    ED25519_SIGNATURE_ALGORITHM,
    generate_ed25519_key_pair,
    read_signature,
    sign_policy,
    sign_policy_asymmetric,
    verify_policy_signature,
    verify_policy_signature_asymmetric,
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


def test_asymmetric_policy_signature_round_trip(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    key_id = generate_ed25519_key_pair(private_key, public_key)
    policy = {
        "metadata": {"id": "asymmetric-policy", "version": "1.0.0"},
        "commands": {"block": ["terraform apply*"]},
    }

    signature = sign_policy_asymmetric(
        policy, private_key.read_bytes(), signer="platform-security"
    )
    valid, reason = verify_policy_signature_asymmetric(
        policy, signature, public_key.read_bytes()
    )

    assert valid
    assert reason == "Policy signature verified."
    assert signature.algorithm == ED25519_SIGNATURE_ALGORITHM
    assert signature.key_id == key_id
    assert oct(private_key.stat().st_mode & 0o777) == "0o600"


def test_asymmetric_policy_signature_detects_tampering(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    generate_ed25519_key_pair(private_key, public_key)
    policy = {
        "metadata": {"id": "asymmetric-policy", "version": "1.0.0"},
        "commands": {"block": ["terraform apply*"]},
    }
    tampered = {
        "metadata": {"id": "asymmetric-policy", "version": "1.0.0"},
        "commands": {"allow": ["terraform apply*"]},
    }

    signature = sign_policy_asymmetric(policy, private_key.read_bytes())
    valid, reason = verify_policy_signature_asymmetric(
        tampered, signature, public_key.read_bytes()
    )

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


def test_policy_keygen_sign_and_verify_cli(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "metadata": {"id": "cli-asymmetric-policy", "version": "1.0.0"},
                "commands": {"block": ["terraform apply*"]},
            }
        ),
        encoding="utf-8",
    )

    keygen_result = runner.invoke(
        app,
        [
            "policy",
            "keygen",
            "--private-key",
            str(private_key),
            "--public-key",
            str(public_key),
        ],
    )
    sign_result = runner.invoke(
        app,
        ["policy", "sign", str(policy_path), "--private-key", str(private_key)],
    )
    verify_result = runner.invoke(
        app,
        ["policy", "verify", str(policy_path), "--public-key", str(public_key)],
    )

    signature = read_signature(policy_path.with_suffix(".yaml.sig"))
    assert keygen_result.exit_code == 0
    assert sign_result.exit_code == 0
    assert verify_result.exit_code == 0
    assert signature.policy_id == "cli-asymmetric-policy"
    assert signature.algorithm == ED25519_SIGNATURE_ALGORITHM
    assert signature.key_id
