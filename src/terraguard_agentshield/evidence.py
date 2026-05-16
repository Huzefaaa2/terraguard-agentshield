from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from terraguard_agentshield.audit import SessionAudit
from terraguard_agentshield.policy_signing import (
    ED25519_SIGNATURE_ALGORITHM,
    ed25519_public_key_id,
    load_ed25519_private_key,
    load_ed25519_public_key,
)


EVIDENCE_BUNDLE_SCHEMA = "terraguard-agentshield.evidence-bundle.v1"


@dataclass(frozen=True)
class EvidenceValidationResult:
    valid: bool
    session_id: str | None
    failures: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "session_id": self.session_id,
            "failures": self.failures,
            "summary": self.summary,
        }


def latest_audit_file(audit_dir: Path) -> Path | None:
    files = sorted(audit_dir.glob("session-*.json"), key=lambda path: path.stat().st_mtime)
    return files[-1] if files else None


def load_audit_for_validation(audit_dir: Path, session_id: str | None = None) -> SessionAudit:
    if session_id:
        audit_path = audit_dir / f"session-{session_id}.json"
    else:
        audit_path = latest_audit_file(audit_dir) or Path()

    if not audit_path.exists():
        raise FileNotFoundError(f"No AgentShield audit file found in {audit_dir}")
    return SessionAudit.read(audit_path)


def validate_attestation(
    audit: SessionAudit,
    fail_on: set[str] | None = None,
    require_policy_pack: str | None = None,
    require_tool: str | None = None,
    min_actions: int = 1,
) -> EvidenceValidationResult:
    fail_decisions = fail_on or {"block", "require_approval"}
    failures: list[str] = []
    decisions = _decision_counts(audit)

    if len(audit.actions) < min_actions:
        failures.append(
            f"Audit contains {len(audit.actions)} action(s); expected at least {min_actions}."
        )

    if require_policy_pack and audit.policy_pack != require_policy_pack:
        failures.append(
            f"Policy pack mismatch: expected {require_policy_pack}, found {audit.policy_pack}."
        )

    if require_tool and audit.tool != require_tool:
        failures.append(f"Tool mismatch: expected {require_tool}, found {audit.tool}.")

    for decision in sorted(fail_decisions):
        count = decisions.get(decision, 0)
        if count:
            failures.append(f"Audit contains {count} {decision} action(s).")

    summary = {
        "tool": audit.tool,
        "repo": str(audit.repo),
        "policy_pack": audit.policy_pack,
        "action_count": len(audit.actions),
        "decisions": decisions,
    }
    return EvidenceValidationResult(
        valid=not failures,
        session_id=audit.session_id,
        failures=failures,
        summary=summary,
    )


def write_validation_result(result: EvidenceValidationResult, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class EvidenceBundleSignature:
    algorithm: str
    digest: str
    signature: str
    signer: str
    signed_at: str
    key_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "digest": self.digest,
            "signature": self.signature,
            "signer": self.signer,
            "signed_at": self.signed_at,
            "key_id": self.key_id,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceBundleSignature":
        return cls(
            algorithm=str(payload["algorithm"]),
            digest=str(payload["digest"]),
            signature=str(payload["signature"]),
            signer=str(payload["signer"]),
            signed_at=str(payload["signed_at"]),
            key_id=str(payload["key_id"]),
        )


@dataclass(frozen=True)
class EvidenceBundle:
    schema: str
    bundle_id: str
    created_at: str
    audit: dict[str, Any]
    risk: dict[str, Any] | None = None
    policy_signature: dict[str, Any] | None = None
    validation: dict[str, Any] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    signature: EvidenceBundleSignature | None = None

    def payload_to_sign(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "bundle_id": self.bundle_id,
            "created_at": self.created_at,
            "audit": self.audit,
            "risk": self.risk,
            "policy_signature": self.policy_signature,
            "validation": self.validation,
            "metadata": self.metadata,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload_to_sign()
        payload["signature"] = self.signature.to_dict() if self.signature else None
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EvidenceBundle":
        signature_payload = payload.get("signature")
        signature = (
            EvidenceBundleSignature.from_dict(signature_payload)
            if isinstance(signature_payload, dict)
            else None
        )
        return cls(
            schema=str(payload["schema"]),
            bundle_id=str(payload["bundle_id"]),
            created_at=str(payload["created_at"]),
            audit=dict(payload["audit"]),
            risk=dict(payload["risk"]) if isinstance(payload.get("risk"), dict) else None,
            policy_signature=dict(payload["policy_signature"])
            if isinstance(payload.get("policy_signature"), dict)
            else None,
            validation=dict(payload["validation"])
            if isinstance(payload.get("validation"), dict)
            else None,
            metadata=dict(payload.get("metadata") or {}),
            signature=signature,
        )

    def write(self, output: Path) -> None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class EvidenceBundleVerificationResult:
    valid: bool
    bundle_id: str | None
    failures: list[str] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "bundle_id": self.bundle_id,
            "failures": self.failures,
            "summary": self.summary,
        }


def create_evidence_bundle(
    audit: SessionAudit,
    private_key_pem: str | bytes,
    signer: str,
    risk: dict[str, Any] | None = None,
    policy_signature: dict[str, Any] | None = None,
    validation: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> EvidenceBundle:
    created_at = datetime.utcnow().isoformat() + "Z"
    bundle_id = f"bundle-{audit.session_id}"
    bundle = EvidenceBundle(
        schema=EVIDENCE_BUNDLE_SCHEMA,
        bundle_id=bundle_id,
        created_at=created_at,
        audit=audit.to_dict(),
        risk=risk,
        policy_signature=policy_signature,
        validation=validation,
        metadata=metadata or {},
    )
    signature = sign_evidence_bundle(bundle, private_key_pem, signer)
    return EvidenceBundle(
        schema=bundle.schema,
        bundle_id=bundle.bundle_id,
        created_at=bundle.created_at,
        audit=bundle.audit,
        risk=bundle.risk,
        policy_signature=bundle.policy_signature,
        validation=bundle.validation,
        metadata=bundle.metadata,
        signature=signature,
    )


def sign_evidence_bundle(
    bundle: EvidenceBundle,
    private_key_pem: str | bytes,
    signer: str,
) -> EvidenceBundleSignature:
    private_key = load_ed25519_private_key(private_key_pem)
    payload = canonical_bundle_bytes(bundle)
    signature = private_key.sign(payload)
    return EvidenceBundleSignature(
        algorithm=ED25519_SIGNATURE_ALGORITHM,
        digest=hashlib.sha256(payload).hexdigest(),
        signature=base64.b64encode(signature).decode("ascii"),
        signer=signer,
        signed_at=datetime.utcnow().isoformat() + "Z",
        key_id=ed25519_public_key_id(private_key.public_key()),
    )


def verify_evidence_bundle(
    bundle: EvidenceBundle,
    public_key_pem: str | bytes,
) -> EvidenceBundleVerificationResult:
    failures: list[str] = []
    if bundle.schema != EVIDENCE_BUNDLE_SCHEMA:
        failures.append(f"Unsupported evidence bundle schema: {bundle.schema}")

    if not bundle.signature:
        failures.append("Evidence bundle signature is missing.")
        return EvidenceBundleVerificationResult(False, bundle.bundle_id, failures)

    if bundle.signature.algorithm != ED25519_SIGNATURE_ALGORITHM:
        failures.append(
            f"Unsupported evidence bundle signature algorithm: {bundle.signature.algorithm}"
        )

    payload = canonical_bundle_bytes(bundle)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != bundle.signature.digest:
        failures.append("Evidence bundle digest does not match signature payload.")

    public_key = load_ed25519_public_key(public_key_pem)
    key_id = ed25519_public_key_id(public_key)
    if bundle.signature.key_id != key_id:
        failures.append("Evidence bundle key id does not match public key.")

    if not failures:
        from cryptography.exceptions import InvalidSignature

        try:
            public_key.verify(
                base64.b64decode(bundle.signature.signature.encode("ascii")),
                payload,
            )
        except (InvalidSignature, ValueError):
            failures.append("Evidence bundle signature verification failed.")

    return EvidenceBundleVerificationResult(
        valid=not failures,
        bundle_id=bundle.bundle_id,
        failures=failures,
        summary={
            "schema": bundle.schema,
            "session_id": bundle.audit.get("session_id"),
            "tool": bundle.audit.get("tool"),
            "policy_pack": bundle.audit.get("policy_pack"),
            "risk_decision": (bundle.risk or {}).get("decision"),
            "risk_max": (bundle.risk or {}).get("max_risk"),
            "signer": bundle.signature.signer if bundle.signature else None,
            "key_id": bundle.signature.key_id if bundle.signature else None,
        },
    )


def read_evidence_bundle(path: Path) -> EvidenceBundle:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Evidence bundle is not a JSON object: {path}")
    return EvidenceBundle.from_dict(payload)


def canonical_bundle_bytes(bundle: EvidenceBundle) -> bytes:
    return json.dumps(
        bundle.payload_to_sign(), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _decision_counts(audit: SessionAudit) -> dict[str, int]:
    counts: dict[str, int] = {}
    for action in audit.actions:
        counts[action.decision] = counts.get(action.decision, 0) + 1
    return counts
