from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml


SIGNATURE_ALGORITHM = "HMAC-SHA256"
SIGNATURE_SCHEMA = "terraguard-agentshield.policy-signature.v1"


@dataclass(frozen=True)
class PolicySignature:
    schema: str
    algorithm: str
    policy_id: str
    policy_version: str | None
    digest: str
    signature: str
    signer: str
    signed_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "algorithm": self.algorithm,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "digest": self.digest,
            "signature": self.signature,
            "signer": self.signer,
            "signed_at": self.signed_at,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicySignature":
        return cls(
            schema=str(payload["schema"]),
            algorithm=str(payload["algorithm"]),
            policy_id=str(payload["policy_id"]),
            policy_version=payload.get("policy_version"),
            digest=str(payload["digest"]),
            signature=str(payload["signature"]),
            signer=str(payload["signer"]),
            signed_at=str(payload["signed_at"]),
        )


def load_policy_file(policy_path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Policy file is not a YAML mapping: {policy_path}")
    return payload


def canonical_policy_bytes(policy: dict[str, Any]) -> bytes:
    return json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")


def policy_digest(policy: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_policy_bytes(policy)).hexdigest()


def sign_policy(
    policy: dict[str, Any],
    secret: str,
    signer: str = "terraguard-agentshield",
) -> PolicySignature:
    metadata = policy.get("metadata", {})
    digest = policy_digest(policy)
    signature = hmac.new(secret.encode("utf-8"), digest.encode("utf-8"), hashlib.sha256)
    return PolicySignature(
        schema=SIGNATURE_SCHEMA,
        algorithm=SIGNATURE_ALGORITHM,
        policy_id=str(metadata.get("id") or "unknown"),
        policy_version=metadata.get("version"),
        digest=digest,
        signature=signature.hexdigest(),
        signer=signer,
        signed_at=datetime.utcnow().isoformat() + "Z",
    )


def verify_policy_signature(
    policy: dict[str, Any],
    signature: PolicySignature,
    secret: str,
) -> tuple[bool, str]:
    if signature.schema != SIGNATURE_SCHEMA:
        return False, f"Unsupported signature schema: {signature.schema}"
    if signature.algorithm != SIGNATURE_ALGORITHM:
        return False, f"Unsupported signature algorithm: {signature.algorithm}"

    expected_digest = policy_digest(policy)
    if not hmac.compare_digest(expected_digest, signature.digest):
        return False, "Policy digest does not match signature payload."

    expected_signature = hmac.new(
        secret.encode("utf-8"), expected_digest.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature.signature):
        return False, "Policy signature verification failed."

    return True, "Policy signature verified."


def write_signature(signature: PolicySignature, signature_path: Path) -> None:
    signature_path.parent.mkdir(parents=True, exist_ok=True)
    signature_path.write_text(
        json.dumps(signature.to_dict(), indent=2) + "\n", encoding="utf-8"
    )


def read_signature(signature_path: Path) -> PolicySignature:
    payload = json.loads(signature_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Signature file is not a JSON object: {signature_path}")
    return PolicySignature.from_dict(payload)
