"""
Policy Explain Mode — Deterministic explanations of AgentShield risk findings.

Explains why AgentShield blocked, warned, or required approval for a change,
mapping risk categories to business context, evidence, recommendations, and
reviewer hints. No external services, no LLM calls.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyExplanationItem:
    """Explanation for a single risk finding."""

    risk: str
    """Risk level: 'critical', 'high', 'medium', 'low'."""
    category: str
    """Risk category: 'secrets', 'privilege-expansion', 'public-exposure', etc."""
    title: str
    """Human-readable title of the finding."""
    why_it_matters: str
    """Business/security context explaining why this risk matters."""
    evidence: str | None
    """Extracted evidence from the diff (code snippet, pattern match, etc.)."""
    file: str | None
    """File path where finding was detected."""
    line: int | None
    """Line number in file."""
    recommendation: str
    """Actionable remediation steps."""
    control_family: str | None
    """Control family: 'identity-access', 'network-security', 'data-protection', etc."""
    reviewer_hint: str | None
    """Reviewer group or expertise needed."""


@dataclass(frozen=True)
class PolicyExplanation:
    """Overall policy explanation for a PR or risk summary."""

    decision: str
    """Decision: 'pass', 'warn', 'require_approval', 'block'."""
    max_risk: str
    """Maximum risk level found."""
    policy_pack: str | None
    """Policy pack ID used for evaluation."""
    summary: str
    """Concise human-readable explanation."""
    items: list[PolicyExplanationItem] = field(default_factory=list)
    """Per-finding explanations."""

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "decision": self.decision,
            "max_risk": self.max_risk,
            "policy_pack": self.policy_pack,
            "summary": self.summary,
            "items": [
                {
                    "risk": item.risk,
                    "category": item.category,
                    "title": item.title,
                    "why_it_matters": item.why_it_matters,
                    "evidence": item.evidence,
                    "file": item.file,
                    "line": item.line,
                    "recommendation": item.recommendation,
                    "control_family": item.control_family,
                    "reviewer_hint": item.reviewer_hint,
                }
                for item in self.items
            ],
        }


# Category-to-explanation mappings
_CATEGORY_EXPLANATIONS = {
    "secrets": {
        "why": "Credential material (API keys, tokens, passwords) may enter source control or AI context.",
        "recommendation": "Move secret to approved secret manager and remove from diff/history.",
        "control_family": "data-protection",
        "reviewer_hint": "Security/data protection approver",
    },
    "public-exposure": {
        "why": "Internet-exposed ingress (0.0.0.0/0, ::/0) can expose systems or data to unauthorized access.",
        "recommendation": "Restrict CIDR ranges to specific IPs, document business need, and request security approval.",
        "control_family": "network-security",
        "reviewer_hint": "Network/security approver",
    },
    "privilege-expansion": {
        "why": "Wildcard or admin permissions violate least-privilege controls and expand attack surface.",
        "recommendation": "Replace wildcard/admin actions with exact least-privilege permissions and scoped resources.",
        "control_family": "identity-access",
        "reviewer_hint": "Security/IAM approver",
    },
    "encryption": {
        "why": "Disabling or weakening data protection controls reduces confidentiality and integrity.",
        "recommendation": "Keep encryption enabled, use approved KMS/platform keys, and document any exceptions.",
        "control_family": "data-protection",
        "reviewer_hint": "Security/data protection approver",
    },
    "logging": {
        "why": "Disabling audit logging reduces visibility for incident response and compliance audits.",
        "recommendation": "Keep audit logging enabled or document compensating controls for monitoring.",
        "control_family": "audit-monitoring",
        "reviewer_hint": "SRE/security monitoring approver",
    },
    "tls": {
        "why": "Disabling certificate verification enables MITM attacks and credential theft.",
        "recommendation": "Keep verification enabled and use trusted, approved certificates.",
        "control_family": "network-security",
        "reviewer_hint": "Network/security approver",
    },
    "crypto": {
        "why": "Weak cryptographic primitives (MD5, DES, RC4) can break confidentiality and integrity.",
        "recommendation": "Use modern, NIST-approved cryptographic algorithms (SHA-256, AES-256, etc.).",
        "control_family": "data-protection",
        "reviewer_hint": "Security/data protection approver",
    },
    "sensitive-code": {
        "why": "Authentication, payment, identity, token, or security-related code needs independent review.",
        "recommendation": "Require reviewer familiar with that control area; document security rationale.",
        "control_family": "application-security",
        "reviewer_hint": "AppSec or subject-matter expert approver",
    },
}


def explain_risk_summary(
    risk_summary: dict[str, Any],
    policy_pack: str | None = None,
    fail_on: str = "high",
) -> PolicyExplanation:
    """
    Explain a risk summary into business-ready guidance.

    Args:
        risk_summary: Risk summary dict from SemanticRiskClassifier (typically from JSON).
        policy_pack: Policy pack ID for context.
        fail_on: Failure threshold: 'low', 'medium', 'high', 'critical'.

    Returns:
        PolicyExplanation with decision, max_risk, summary, and per-finding explanations.
    """
    if not isinstance(risk_summary, dict):
        risk_summary = {}

    findings = risk_summary.get("findings", [])
    max_risk = risk_summary.get("max_risk", "none")

    # Determine decision
    risk_hierarchy = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    fail_on_level = risk_hierarchy.get(fail_on, 3)
    max_risk_level = risk_hierarchy.get(max_risk, 0)

    if max_risk_level >= fail_on_level:
        decision = "require_approval"
    elif max_risk == "medium":
        decision = "warn"
    elif max_risk == "low":
        decision = "warn"
    else:
        decision = "pass"

    # Generate per-finding explanations
    items: list[PolicyExplanationItem] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        category = finding.get("category", "unknown")
        risk_level = finding.get("risk", "medium")
        evidence_line = finding.get("evidence", "")
        file_name = finding.get("file")
        line_num = finding.get("line")

        # Get explanation template for category
        template = _CATEGORY_EXPLANATIONS.get(category, {})
        why = template.get("why", "Security risk detected in code.")
        rec = template.get("recommendation", "Review and remediate this finding.")
        family = template.get("control_family", "application-security")
        reviewer = template.get("reviewer_hint", "Platform/security reviewer")

        # Build title
        title = f"{category.replace('-', ' ').title()}"

        item = PolicyExplanationItem(
            risk=risk_level,
            category=category,
            title=title,
            why_it_matters=why,
            evidence=evidence_line if evidence_line else None,
            file=file_name,
            line=line_num,
            recommendation=rec,
            control_family=family,
            reviewer_hint=reviewer,
        )
        items.append(item)

    # Generate summary
    num_findings = len(items)
    if num_findings == 0:
        summary_text = "No high-risk AgentShield findings were detected in this pull request."
    elif decision == "require_approval":
        summary_text = (
            f"AgentShield requires approval because this change introduces "
            f"{num_findings} finding(s) with {max_risk}-risk security implications."
        )
    elif decision == "warn":
        summary_text = (
            f"AgentShield detected {num_findings} finding(s) with {max_risk}-risk implications. "
            "Please review before merge."
        )
    else:
        summary_text = "AgentShield risk assessment: pass."

    return PolicyExplanation(
        decision=decision,
        max_risk=max_risk,
        policy_pack=policy_pack,
        summary=summary_text,
        items=items,
    )


def explain_from_file(
    path: Path, policy_pack: str | None = None, fail_on: str = "high"
) -> PolicyExplanation:
    """
    Load a risk summary JSON file and produce an explanation.

    Args:
        path: Path to risk JSON file (from risk diff command).
        policy_pack: Policy pack ID for context.
        fail_on: Failure threshold.

    Returns:
        PolicyExplanation.
    """
    risk_data = json.loads(path.read_text(encoding="utf-8"))
    return explain_risk_summary(risk_data, policy_pack=policy_pack, fail_on=fail_on)
