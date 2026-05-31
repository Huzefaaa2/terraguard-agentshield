from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from terraguard_agentshield.risk import RISK_ORDER, RiskFinding, RiskSummary


CATEGORY_GUIDANCE: dict[str, dict[str, str]] = {
    "secrets": {
        "why": "Credential material may enter source control or AI-agent context.",
        "recommendation": "Move the secret to an approved secret manager and remove it from the diff and history.",
    },
    "public-exposure": {
        "why": "Internet-exposed ingress can expose systems or data to untrusted networks.",
        "recommendation": "Restrict CIDR ranges, require security approval, and document the business need.",
    },
    "privilege-expansion": {
        "why": "Wildcard or administrative permissions violate least-privilege controls.",
        "recommendation": "Replace wildcard or admin actions with exact actions and resource scope.",
    },
    "encryption": {
        "why": "Data protection controls are weakened or removed.",
        "recommendation": "Keep encryption enabled and use approved KMS or platform-managed keys.",
    },
    "logging": {
        "why": "Auditability and incident response visibility may be reduced.",
        "recommendation": "Keep audit logging enabled or document approved compensating controls.",
    },
    "tls": {
        "why": "Disabling certificate verification enables man-in-the-middle risk.",
        "recommendation": "Keep verification enabled and use trusted certificates.",
    },
    "crypto": {
        "why": "Weak cryptographic primitives can break confidentiality or integrity.",
        "recommendation": "Use approved modern algorithms.",
    },
    "sensitive-code": {
        "why": "Authentication, payment, identity, token, or security code needs independent review.",
        "recommendation": "Require a reviewer familiar with that control area.",
    },
}

REVIEWER_HINTS = {
    "identity-access": "Security/IAM approver",
    "network-security": "Network/security approver",
    "data-protection": "Security/data protection approver",
    "audit-monitoring": "SRE/security monitoring approver",
    "application-security": "AppSec approver",
}


@dataclass(frozen=True)
class PolicyExplanationItem:
    risk: str
    category: str
    title: str
    why_it_matters: str
    evidence: str | None
    file: str | None
    line: int | None
    recommendation: str
    control_family: str | None
    reviewer_hint: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "category": self.category,
            "title": self.title,
            "why_it_matters": self.why_it_matters,
            "evidence": self.evidence,
            "file": self.file,
            "line": self.line,
            "recommendation": self.recommendation,
            "control_family": self.control_family,
            "reviewer_hint": self.reviewer_hint,
        }


@dataclass(frozen=True)
class PolicyExplanation:
    decision: str
    max_risk: str
    policy_pack: str | None
    summary: str
    items: list[PolicyExplanationItem] = field(default_factory=list)
    fail_on: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "max_risk": self.max_risk,
            "policy_pack": self.policy_pack,
            "fail_on": self.fail_on,
            "summary": self.summary,
            "items": [item.to_dict() for item in self.items],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def explain_risk_summary(
    risk_summary: RiskSummary | dict[str, Any],
    policy_pack: str | None = None,
    fail_on: str = "high",
) -> PolicyExplanation:
    summary = _coerce_summary(risk_summary)
    decision = _explain_decision(summary, fail_on)
    items = [_explain_finding(finding) for finding in summary.findings]
    return PolicyExplanation(
        decision=decision,
        max_risk=summary.max_risk,
        policy_pack=policy_pack,
        summary=_summary_text(summary, decision, fail_on),
        items=items,
        fail_on=fail_on,
    )


def explain_from_file(
    path: Path, policy_pack: str | None = None, fail_on: str = "high"
) -> PolicyExplanation:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Risk summary JSON is not an object: {path}")
    return explain_risk_summary(payload, policy_pack=policy_pack, fail_on=fail_on)


def render_explanation_text(explanation: PolicyExplanation) -> str:
    lines = [
        f"Decision: {explanation.decision}",
        f"Max risk: {explanation.max_risk}",
        f"Policy pack: {explanation.policy_pack or 'not supplied'}",
        f"Failure threshold: {explanation.fail_on}",
        "",
        explanation.summary,
    ]
    for index, item in enumerate(explanation.items, start=1):
        location = _location(item.file, item.line)
        lines.extend(
            [
                "",
                f"Finding {index}: {item.title}",
                f"Risk: {item.risk}",
                f"Category: {item.category}",
                f"Control family: {item.control_family or 'unknown'}",
                f"Reviewer hint: {item.reviewer_hint or 'Platform/security reviewer'}",
                f"Location: {location}",
                f"Why: {item.why_it_matters}",
                f"Recommendation: {item.recommendation}",
            ]
        )
        if item.evidence:
            lines.append(f"Evidence: {item.evidence}")
    return "\n".join(lines)


def render_explanation_markdown(explanation: PolicyExplanation) -> str:
    lines = [
        "# AgentShield Policy Explanation",
        "",
        f"**Decision:** {_display_decision(explanation.decision)}  ",
        f"**Max risk:** {explanation.max_risk.title()}  ",
        f"**Policy pack:** {explanation.policy_pack or 'not supplied'}  ",
        f"**Failure threshold:** {explanation.fail_on}",
        "",
        explanation.summary,
    ]
    for index, item in enumerate(explanation.items, start=1):
        lines.extend(
            [
                "",
                f"## Finding {index}: {item.title}",
                "",
                f"**Risk:** {item.risk.title()}  ",
                f"**Category:** {item.category}  ",
                f"**Control family:** {item.control_family or 'unknown'}  ",
                f"**Reviewer hint:** {item.reviewer_hint or 'Platform/security reviewer'}  ",
                f"**Location:** {_location(item.file, item.line)}",
                "",
                "### Why this matters",
                "",
                item.why_it_matters,
            ]
        )
        if item.evidence:
            lines.extend(["", "### Evidence", "", "```text", item.evidence, "```"])
        lines.extend(["", "### Recommended fix", "", item.recommendation])
    if not explanation.items:
        lines.extend(["", "No AgentShield risk findings were present in the supplied summary."])
    return "\n".join(lines)


def _coerce_summary(risk_summary: RiskSummary | dict[str, Any]) -> RiskSummary:
    if isinstance(risk_summary, RiskSummary):
        return risk_summary
    findings: list[RiskFinding] = []
    for payload in risk_summary.get("findings", []):
        if not isinstance(payload, dict):
            continue
        findings.append(
            RiskFinding(
                risk=str(payload.get("risk") or "low"),
                category=str(payload.get("category") or "unknown"),
                title=str(payload.get("title") or "Risk finding"),
                description=str(payload.get("description") or ""),
                file=str(payload.get("file") or "unknown"),
                line=payload.get("line") if isinstance(payload.get("line"), int) else None,
                evidence=payload.get("evidence"),
                recommendation=payload.get("recommendation"),
                control_family=payload.get("control_family"),
            )
        )
    return RiskSummary(findings=findings)


def _explain_finding(finding: RiskFinding) -> PolicyExplanationItem:
    guidance = CATEGORY_GUIDANCE.get(
        finding.category,
        {
            "why": "The change touches a control area that needs security review.",
            "recommendation": "Request platform or security review and document the intended behavior.",
        },
    )
    control_family = finding.control_family
    return PolicyExplanationItem(
        risk=finding.risk,
        category=finding.category,
        title=finding.title,
        why_it_matters=guidance["why"],
        evidence=finding.evidence,
        file=finding.file,
        line=finding.line,
        recommendation=finding.recommendation or guidance["recommendation"],
        control_family=control_family,
        reviewer_hint=REVIEWER_HINTS.get(control_family or "", "Platform/security reviewer"),
    )


def _explain_decision(summary: RiskSummary, fail_on: str) -> str:
    if not summary.findings:
        return "pass"
    threshold = RISK_ORDER.get(fail_on.lower())
    if threshold is None:
        raise ValueError(f"Unknown risk threshold: {fail_on}")
    if summary.decision == "block":
        return "block"
    if RISK_ORDER[summary.max_risk] >= threshold:
        return "require_approval"
    return summary.decision


def _summary_text(summary: RiskSummary, decision: str, fail_on: str) -> str:
    if not summary.findings:
        return "AgentShield did not find policy-relevant risk in the supplied summary."
    if decision == "block":
        return (
            "AgentShield blocks this change because it introduces critical-risk "
            "security-sensitive behavior."
        )
    if decision == "require_approval":
        return (
            "AgentShield requires approval because this change introduces "
            f"{summary.max_risk}-risk behavior at or above the `{fail_on}` threshold."
        )
    if decision == "warn":
        return (
            "AgentShield warns because this change affects security-relevant controls "
            "but is below the configured failure threshold."
        )
    return "AgentShield findings are below the configured failure threshold."


def _location(file: str | None, line: int | None) -> str:
    if not file:
        return "unknown"
    return f"{file}:{line}" if line is not None else file


def _display_decision(decision: str) -> str:
    return decision.replace("_", " ").title()
