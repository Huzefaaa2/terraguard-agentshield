from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from terraguard_agentshield.summary import DecisionSummary


COMPLIANCE_MAPPINGS: dict[str, dict[str, list[str]]] = {
    "application-security": {
        "soc2": ["Security", "Confidentiality"],
        "iso27001": ["A.8.25", "A.8.28", "A.8.29"],
        "pci_dss": ["6.2", "6.3", "6.4"],
        "nist_ssdf": ["PW.4", "PW.5", "RV.1"],
        "internal_ai_governance": ["AI-SDLC-01", "AI-REVIEW-01"],
    },
    "audit-monitoring": {
        "soc2": ["Security"],
        "iso27001": ["A.8.15", "A.8.16"],
        "pci_dss": ["10.2", "10.4", "10.7"],
        "nist_ssdf": ["PO.3", "RV.1"],
        "internal_ai_governance": ["AI-AUDIT-01", "AI-EVIDENCE-01"],
    },
    "change-management": {
        "soc2": ["Security", "Availability"],
        "iso27001": ["A.8.32"],
        "pci_dss": ["6.5", "6.5.1"],
        "nist_ssdf": ["PO.1", "PO.3", "PS.3"],
        "internal_ai_governance": ["AI-CHANGE-01", "AI-APPROVAL-01"],
    },
    "data-protection": {
        "soc2": ["Security", "Confidentiality", "Privacy"],
        "iso27001": ["A.5.12", "A.5.15", "A.8.11", "A.8.24"],
        "pci_dss": ["3.3", "3.4", "4.2"],
        "nist_ssdf": ["PO.5", "PS.3"],
        "internal_ai_governance": ["AI-DATA-01", "AI-SECRETS-01"],
    },
    "identity-access": {
        "soc2": ["Security"],
        "iso27001": ["A.5.15", "A.5.16", "A.5.18", "A.8.2", "A.8.3"],
        "pci_dss": ["7.2", "7.3", "8.2", "8.6"],
        "nist_ssdf": ["PO.1", "PS.3"],
        "internal_ai_governance": ["AI-IAM-01", "AI-PRIV-01"],
    },
    "infrastructure-change": {
        "soc2": ["Security", "Availability"],
        "iso27001": ["A.8.9", "A.8.32"],
        "pci_dss": ["1.2", "2.2", "6.5"],
        "nist_ssdf": ["PO.3", "PS.3", "PW.9"],
        "internal_ai_governance": ["AI-IAC-01", "AI-RUNTIME-01"],
    },
    "network-security": {
        "soc2": ["Security", "Availability"],
        "iso27001": ["A.8.20", "A.8.21", "A.8.22"],
        "pci_dss": ["1.2", "1.3", "11.4"],
        "nist_ssdf": ["PO.5", "PW.8"],
        "internal_ai_governance": ["AI-NETWORK-01"],
    },
    "runtime-governance": {
        "soc2": ["Security"],
        "iso27001": ["A.5.1", "A.5.36", "A.8.1"],
        "pci_dss": ["12.1", "12.3"],
        "nist_ssdf": ["PO.1", "PO.3"],
        "internal_ai_governance": ["AI-RUNTIME-01", "AI-POLICY-01"],
    },
    "source-control": {
        "soc2": ["Security"],
        "iso27001": ["A.8.4", "A.8.25", "A.8.32"],
        "pci_dss": ["6.3", "6.5", "7.2"],
        "nist_ssdf": ["PS.1", "PS.3", "PW.4"],
        "internal_ai_governance": ["AI-SOURCE-01", "AI-REVIEW-01"],
    },
    "tool-governance": {
        "soc2": ["Security", "Confidentiality"],
        "iso27001": ["A.5.10", "A.5.23", "A.8.1"],
        "pci_dss": ["12.2", "12.3", "12.8"],
        "nist_ssdf": ["PO.1", "PO.3", "PS.2"],
        "internal_ai_governance": ["AI-TOOLS-01", "AI-MCP-01"],
    },
    "unmapped": {
        "soc2": ["Security"],
        "iso27001": ["A.5.36"],
        "pci_dss": ["12.1"],
        "nist_ssdf": ["PO.1"],
        "internal_ai_governance": ["AI-GOV-01"],
    },
}


@dataclass(frozen=True)
class ComplianceMappingResult:
    generated_at: str
    framework_count: int
    control_family_count: int
    mappings: dict[str, dict[str, list[str]]]
    active_mappings: dict[str, dict[str, Any]] = field(default_factory=dict)
    disclaimer: str = (
        "Mappings are implementation guidance for audit evidence preparation and "
        "must be reviewed against your formal control scope by qualified assessors."
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "framework_count": self.framework_count,
            "control_family_count": self.control_family_count,
            "mappings": self.mappings,
            "active_mappings": self.active_mappings,
            "disclaimer": self.disclaimer,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def list_compliance_mappings() -> ComplianceMappingResult:
    return ComplianceMappingResult(
        generated_at=datetime.utcnow().isoformat() + "Z",
        framework_count=len(_frameworks(COMPLIANCE_MAPPINGS)),
        control_family_count=len(COMPLIANCE_MAPPINGS),
        mappings=COMPLIANCE_MAPPINGS,
    )


def map_summary_to_compliance(
    summary: DecisionSummary | dict[str, Any],
) -> ComplianceMappingResult:
    payload = summary.to_dict() if isinstance(summary, DecisionSummary) else summary
    families = payload.get("control_families", {})
    active: dict[str, dict[str, Any]] = {}
    if isinstance(families, dict):
        for family, values in families.items():
            family_key = str(family)
            if family_key not in COMPLIANCE_MAPPINGS:
                family_key = "unmapped"
            active[str(family)] = {
                "activity": values,
                "frameworks": COMPLIANCE_MAPPINGS[family_key],
            }

    return ComplianceMappingResult(
        generated_at=datetime.utcnow().isoformat() + "Z",
        framework_count=len(_frameworks(COMPLIANCE_MAPPINGS)),
        control_family_count=len(active),
        mappings=COMPLIANCE_MAPPINGS,
        active_mappings=active,
    )


def render_text_mappings(result: ComplianceMappingResult) -> str:
    payload = result.to_dict()
    lines = [
        "TerraGuard AgentShield Compliance Mapping",
        "",
        f"Frameworks: {payload['framework_count']}",
        f"Control families: {payload['control_family_count']}",
        "",
    ]
    active = payload["active_mappings"] or {
        family: {"frameworks": frameworks}
        for family, frameworks in payload["mappings"].items()
    }
    for family, values in active.items():
        lines.append(f"- {family}")
        for framework, controls in values["frameworks"].items():
            lines.append(f"  {framework}: {', '.join(controls)}")
    lines.append("")
    lines.append(payload["disclaimer"])
    return "\n".join(lines)


def _frameworks(mappings: dict[str, dict[str, list[str]]]) -> set[str]:
    frameworks: set[str] = set()
    for values in mappings.values():
        frameworks.update(values)
    return frameworks
