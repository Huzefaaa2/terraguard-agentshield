from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from terraguard_agentshield.evidence import read_evidence_bundle
from terraguard_agentshield.policy_registry import PolicyRegistry, PolicyRegistryError
from terraguard_agentshield.risk import SemanticRiskClassifier, should_fail_for_risk
from terraguard_agentshield.summary import summarize_evidence


DEFAULT_DATA_DIR = Path(".terraguard/agentshield")
DATA_DIR_ENV = "TERRAGUARD_AGENTSHIELD_DATA_DIR"


class ResolvePolicyRequest(BaseModel):
    enterprise: str | None = Field(
        default=None, description="Enterprise-level policy pack ID."
    )
    business_unit: str | None = Field(
        default=None, description="Business unit policy pack ID."
    )
    repository: str | None = Field(default=None, description="Repository policy pack ID.")
    policy_pack: str | None = Field(default=None, description="Final/default policy pack ID.")


class RiskDiffRequest(BaseModel):
    diff: str = Field(description="Unified diff text to classify.")
    fail_on: str | None = Field(
        default=None, description="Optional fail threshold: low, medium, high, critical."
    )


def create_app(
    policy_root: Path | None = None,
    data_dir: Path | None = None,
) -> FastAPI:
    """Create the AgentShield enterprise integration API."""
    app = FastAPI(
        title="TerraGuard AgentShield API",
        version="0.1.0",
        description="Enterprise policy, evidence, and risk inspection API.",
    )
    registry = PolicyRegistry(root=policy_root)
    base_data_dir = _data_dir(data_dir)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "terraguard-agentshield"}

    @app.get("/policies")
    def list_policies() -> dict[str, Any]:
        return {"policies": registry.list_policy_packs()}

    @app.get("/policies/{pack_id}")
    def get_policy(pack_id: str) -> dict[str, Any]:
        try:
            return registry.get_policy_pack(pack_id)
        except PolicyRegistryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/policies/resolve")
    def resolve_policy(request: ResolvePolicyRequest) -> dict[str, Any]:
        try:
            policy = registry.resolve_policy(
                enterprise=request.enterprise,
                business_unit=request.business_unit,
                repository=request.repository,
                policy_pack=request.policy_pack,
            )
        except PolicyRegistryError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        return {"policy": policy}

    @app.get("/evidence/bundles")
    def list_evidence_bundles() -> dict[str, Any]:
        bundle_dir = _bundle_dir(base_data_dir)
        bundles = [_bundle_summary(path) for path in sorted(bundle_dir.glob("*.json"))]
        return {
            "data_dir": str(base_data_dir),
            "bundle_dir": str(bundle_dir),
            "bundles": [bundle for bundle in bundles if bundle is not None],
        }

    @app.get("/evidence/bundles/{bundle_id}")
    def get_evidence_bundle(bundle_id: str) -> dict[str, Any]:
        bundle_dir = _bundle_dir(base_data_dir)
        bundle_path = _find_bundle(bundle_dir, bundle_id)
        if bundle_path is None:
            raise HTTPException(
                status_code=404, detail=f"Evidence bundle '{bundle_id}' not found."
            )
        return read_evidence_bundle(bundle_path).to_dict()

    @app.get("/evidence/summary")
    def summarize_evidence_decisions() -> dict[str, Any]:
        return summarize_evidence(
            audit_dir=base_data_dir / "audit",
            bundle_dir=_bundle_dir(base_data_dir),
        ).to_dict()

    @app.post("/risk/diff")
    def classify_diff(request: RiskDiffRequest) -> dict[str, Any]:
        summary = SemanticRiskClassifier().classify_diff(request.diff)
        payload = summary.to_dict()
        if request.fail_on:
            try:
                payload["failed_threshold"] = should_fail_for_risk(
                    summary, request.fail_on
                )
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        return payload

    return app


def _data_dir(data_dir: Path | None) -> Path:
    if data_dir is not None:
        return data_dir
    return Path(os.environ.get(DATA_DIR_ENV, DEFAULT_DATA_DIR))


def _bundle_dir(data_dir: Path) -> Path:
    return data_dir / "evidence"


def _bundle_summary(path: Path) -> dict[str, Any] | None:
    try:
        bundle = read_evidence_bundle(path)
    except (OSError, ValueError, KeyError, TypeError):
        return None

    signature = bundle.signature.to_dict() if bundle.signature else {}
    return {
        "bundle_id": bundle.bundle_id,
        "created_at": bundle.created_at,
        "path": str(path),
        "session_id": bundle.audit.get("session_id"),
        "tool": bundle.audit.get("tool"),
        "repo": bundle.audit.get("repo"),
        "policy_pack": bundle.audit.get("policy_pack"),
        "risk_decision": (bundle.risk or {}).get("decision"),
        "risk_max": (bundle.risk or {}).get("max_risk"),
        "signer": signature.get("signer"),
        "key_id": signature.get("key_id"),
    }


def _find_bundle(bundle_dir: Path, bundle_id: str) -> Path | None:
    candidates = [
        bundle_dir / f"{bundle_id}.json",
        bundle_dir / f"evidence-{bundle_id}.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate

    for path in sorted(bundle_dir.glob("*.json")):
        try:
            if read_evidence_bundle(path).bundle_id == bundle_id:
                return path
        except (OSError, ValueError, KeyError, TypeError):
            continue
    return None


app = create_app()
