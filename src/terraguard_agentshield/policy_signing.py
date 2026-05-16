from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


HMAC_SIGNATURE_ALGORITHM = "HMAC-SHA256"
ED25519_SIGNATURE_ALGORITHM = "ED25519"
SIGNATURE_ALGORITHM = HMAC_SIGNATURE_ALGORITHM
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
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "schema": self.schema,
            "algorithm": self.algorithm,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "digest": self.digest,
            "signature": self.signature,
            "signer": self.signer,
            "signed_at": self.signed_at,
        }
        if self.key_id:
            payload["key_id"] = self.key_id
        return payload

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
            key_id=payload.get("key_id"),
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
        algorithm=HMAC_SIGNATURE_ALGORITHM,
        policy_id=str(metadata.get("id") or "unknown"),
        policy_version=metadata.get("version"),
        digest=digest,
        signature=signature.hexdigest(),
        signer=signer,
        signed_at=datetime.utcnow().isoformat() + "Z",
    )


def sign_policy_asymmetric(
    policy: dict[str, Any],
    private_key_pem: str | bytes,
    signer: str = "terraguard-agentshield",
    key_id: str | None = None,
) -> PolicySignature:
    metadata = policy.get("metadata", {})
    digest = policy_digest(policy)
    private_key = load_ed25519_private_key(private_key_pem)
    signature = private_key.sign(canonical_policy_bytes(policy))
    public_key = private_key.public_key()
    return PolicySignature(
        schema=SIGNATURE_SCHEMA,
        algorithm=ED25519_SIGNATURE_ALGORITHM,
        policy_id=str(metadata.get("id") or "unknown"),
        policy_version=metadata.get("version"),
        digest=digest,
        signature=base64.b64encode(signature).decode("ascii"),
        signer=signer,
        signed_at=datetime.utcnow().isoformat() + "Z",
        key_id=key_id or ed25519_public_key_id(public_key),
    )


def verify_policy_signature(
    policy: dict[str, Any],
    signature: PolicySignature,
    secret: str,
) -> tuple[bool, str]:
    if signature.schema != SIGNATURE_SCHEMA:
        return False, f"Unsupported signature schema: {signature.schema}"
    if signature.algorithm != HMAC_SIGNATURE_ALGORITHM:
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


def verify_policy_signature_asymmetric(
    policy: dict[str, Any],
    signature: PolicySignature,
    public_key_pem: str | bytes,
) -> tuple[bool, str]:
    if signature.schema != SIGNATURE_SCHEMA:
        return False, f"Unsupported signature schema: {signature.schema}"
    if signature.algorithm != ED25519_SIGNATURE_ALGORITHM:
        return False, f"Unsupported signature algorithm: {signature.algorithm}"

    expected_digest = policy_digest(policy)
    if not hmac.compare_digest(expected_digest, signature.digest):
        return False, "Policy digest does not match signature payload."

    public_key = load_ed25519_public_key(public_key_pem)
    expected_key_id = ed25519_public_key_id(public_key)
    if signature.key_id and signature.key_id != expected_key_id:
        return False, "Policy signature key id does not match public key."

    try:
        public_key.verify(
            base64.b64decode(signature.signature.encode("ascii")),
            canonical_policy_bytes(policy),
        )
    except (InvalidSignature, ValueError):
        return False, "Policy signature verification failed."

    return True, "Policy signature verified."


def generate_ed25519_key_pair(
    private_key_path: Path,
    public_key_path: Path,
) -> str:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_key_path.chmod(0o600)
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_key_path.chmod(0o644)
    return ed25519_public_key_id(public_key)


def load_ed25519_private_key(private_key_pem: str | bytes) -> Ed25519PrivateKey:
    payload = _pem_bytes(private_key_pem)
    private_key = serialization.load_pem_private_key(payload, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("Private key is not an Ed25519 key.")
    return private_key


def load_ed25519_public_key(public_key_pem: str | bytes) -> Ed25519PublicKey:
    payload = _pem_bytes(public_key_pem)
    public_key = serialization.load_pem_public_key(payload)
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError("Public key is not an Ed25519 key.")
    return public_key


def ed25519_public_key_id(public_key: Ed25519PublicKey) -> str:
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(public_der).hexdigest()[:16]


def _pem_bytes(payload: str | bytes) -> bytes:
    if isinstance(payload, bytes):
        return payload
    return payload.encode("utf-8")


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
