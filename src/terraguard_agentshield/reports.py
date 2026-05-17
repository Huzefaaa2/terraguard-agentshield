from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from terraguard_agentshield.approval import ApprovalRoutingResult, route_approvals
from terraguard_agentshield.compliance import (
    ComplianceMappingResult,
    map_summary_to_compliance,
)
from terraguard_agentshield.summary import DecisionSummary, summarize_evidence


@dataclass(frozen=True)
class GovernanceReport:
    generated_at: str
    validation: dict[str, Any] | None
    decision_summary: dict[str, Any]
    approval_routes: dict[str, Any]
    compliance: dict[str, Any]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> str:
        if self.validation and self.validation.get("valid") is False:
            return "failed"
        if self.approval_routes.get("required_route_count", 0):
            return "requires_approval"
        if self.decision_summary.get("decisions", {}).get("block", 0):
            return "requires_attention"
        return "passed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "status": self.status,
            "validation": self.validation,
            "decision_summary": self.decision_summary,
            "approval_routes": self.approval_routes,
            "compliance": self.compliance,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def create_governance_report(
    audit_dir: Path | None = None,
    bundle_dir: Path | None = None,
    validation: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> GovernanceReport:
    summary = summarize_evidence(audit_dir=audit_dir, bundle_dir=bundle_dir)
    routes = route_approvals(summary)
    compliance = map_summary_to_compliance(summary)
    return _create_report(summary, routes, compliance, validation, metadata or {})


def create_governance_report_from_summary(
    summary: DecisionSummary,
    validation: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> GovernanceReport:
    routes = route_approvals(summary)
    compliance = map_summary_to_compliance(summary)
    return _create_report(summary, routes, compliance, validation, metadata or {})


def render_markdown_report(report: GovernanceReport) -> str:
    payload = report.to_dict()
    summary = payload["decision_summary"]
    routes = payload["approval_routes"]
    compliance = payload["compliance"]
    validation = payload.get("validation")

    lines = [
        "## TerraGuard AgentShield Check Summary",
        "",
        f"Status: **{payload['status']}**",
        f"Generated: `{payload['generated_at']}`",
        "",
        "### Validation",
    ]
    if validation:
        valid = "pass" if validation.get("valid") else "fail"
        lines.append(f"- Result: **{valid}**")
        if validation.get("session_id"):
            lines.append(f"- Session: `{validation['session_id']}`")
        failures = validation.get("failures") or []
        if failures:
            lines.append("- Failures:")
            for failure in failures:
                lines.append(f"  - {failure}")
    else:
        lines.append("- Result: not supplied")

    lines.extend(
        [
            "",
            "### Decisions",
            f"- Sessions: {summary.get('session_count', 0)}",
            f"- Evidence bundles: {summary.get('bundle_count', 0)}",
            f"- Actions: {summary.get('action_count', 0)}",
            f"- Risk findings: {summary.get('finding_count', 0)}",
        ]
    )
    for decision, count in (summary.get("decisions") or {}).items():
        lines.append(f"- {decision}: {count}")

    lines.extend(["", "### Approval Routes"])
    route_items = routes.get("routes") or []
    if route_items:
        for route in route_items:
            marker = "required" if route.get("approval_required") else "advisory"
            lines.append(
                f"- `{route['control_family']}` -> **{route['approver_group']}** "
                f"({route['priority']}, {marker})"
            )
    else:
        lines.append("- No approval routes required")

    lines.extend(["", "### Compliance Mapping"])
    active_mappings = compliance.get("active_mappings") or {}
    if active_mappings:
        for family, values in active_mappings.items():
            frameworks = values.get("frameworks", {})
            framework_names = ", ".join(sorted(frameworks)) if frameworks else "none"
            lines.append(f"- `{family}`: {framework_names}")
    else:
        lines.append("- No active control families found")

    lines.extend(
        [
            "",
            "> Compliance mappings are evidence-preparation guidance and require formal control-owner review.",
        ]
    )
    return "\n".join(lines)


def read_optional_json(path: Path | None) -> dict[str, Any] | None:
    if path is None:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON file is not an object: {path}")
    return payload


def _create_report(
    summary: DecisionSummary,
    routes: ApprovalRoutingResult,
    compliance: ComplianceMappingResult,
    validation: dict[str, Any] | None,
    metadata: dict[str, Any],
) -> GovernanceReport:
    return GovernanceReport(
        generated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        validation=validation,
        decision_summary=summary.to_dict(),
        approval_routes=routes.to_dict(),
        compliance=compliance.to_dict(),
        metadata=metadata,
    )
