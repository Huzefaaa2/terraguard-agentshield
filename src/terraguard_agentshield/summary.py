from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.evidence import EvidenceBundle, read_evidence_bundle


@dataclass
class DecisionSummary:
    session_count: int = 0
    bundle_count: int = 0
    action_count: int = 0
    finding_count: int = 0
    decisions: Counter[str] = field(default_factory=Counter)
    action_types: Counter[str] = field(default_factory=Counter)
    tools: Counter[str] = field(default_factory=Counter)
    policy_packs: Counter[str] = field(default_factory=Counter)
    environments: Counter[str] = field(default_factory=Counter)
    risks: Counter[str] = field(default_factory=Counter)
    control_families: dict[str, dict[str, Any]] = field(default_factory=dict)
    sessions: list[dict[str, Any]] = field(default_factory=list)
    top_blocked_targets: Counter[str] = field(default_factory=Counter)

    def add_audit(self, audit: SessionAudit, bundle_id: str | None = None) -> None:
        self.session_count += 1
        self.tools[audit.tool] += 1
        self.policy_packs[audit.policy_pack] += 1
        if audit.environment:
            self.environments[audit.environment] += 1

        session_decisions: Counter[str] = Counter()
        for action in audit.actions:
            self.add_action(action)
            session_decisions[action.decision] += 1

        self.sessions.append(
            {
                "session_id": audit.session_id,
                "bundle_id": bundle_id,
                "tool": audit.tool,
                "repo": str(audit.repo),
                "policy_pack": audit.policy_pack,
                "environment": audit.environment,
                "action_count": len(audit.actions),
                "decisions": _ordered_counter(session_decisions),
            }
        )

    def add_action(self, action: AuditAction) -> None:
        self.action_count += 1
        self.decisions[action.decision] += 1
        self.action_types[action.type] += 1

        control_family = _action_control_family(action)
        family = self._family(control_family)
        family["actions"] += 1
        family["decisions"][action.decision] += 1

        risk = action.metadata.get("risk")
        if risk:
            risk_value = str(risk)
            self.risks[risk_value] += 1
            family["risks"][risk_value] += 1

        if action.decision == "block":
            self.top_blocked_targets[action.target] += 1

    def add_bundle(self, bundle: EvidenceBundle) -> None:
        self.bundle_count += 1
        audit = SessionAudit.from_dict(bundle.audit)
        self.add_audit(audit, bundle_id=bundle.bundle_id)
        self.add_risk_payload(bundle.risk)

    def add_risk_payload(self, risk: dict[str, Any] | None) -> None:
        if not isinstance(risk, dict):
            return

        findings = risk.get("findings", [])
        if not findings:
            risk_counts = risk.get("risk_counts")
            if isinstance(risk_counts, dict):
                for risk_name, count in risk_counts.items():
                    self.risks[str(risk_name)] += int(count)
            return

        if not isinstance(findings, list):
            return

        for finding in findings:
            if not isinstance(finding, dict):
                continue
            self.finding_count += 1
            risk_value = str(finding.get("risk") or "unknown")
            control_family = str(finding.get("control_family") or "unmapped")
            self.risks[risk_value] += 1
            family = self._family(control_family)
            family["findings"] += 1
            family["risks"][risk_value] += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "session_count": self.session_count,
            "bundle_count": self.bundle_count,
            "action_count": self.action_count,
            "finding_count": self.finding_count,
            "decisions": _ordered_counter(self.decisions),
            "action_types": _ordered_counter(self.action_types),
            "tools": _ordered_counter(self.tools),
            "policy_packs": _ordered_counter(self.policy_packs),
            "environments": _ordered_counter(self.environments),
            "risks": _ordered_counter(self.risks),
            "control_families": {
                family: {
                    "actions": values["actions"],
                    "findings": values["findings"],
                    "decisions": _ordered_counter(values["decisions"]),
                    "risks": _ordered_counter(values["risks"]),
                }
                for family, values in sorted(self.control_families.items())
            },
            "top_blocked_targets": _ordered_counter(self.top_blocked_targets),
            "sessions": sorted(
                self.sessions,
                key=lambda item: str(item.get("session_id") or ""),
            ),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def _family(self, control_family: str) -> dict[str, Any]:
        if control_family not in self.control_families:
            self.control_families[control_family] = {
                "actions": 0,
                "findings": 0,
                "decisions": Counter(),
                "risks": Counter(),
            }
        return self.control_families[control_family]


def summarize_audits(audits: list[SessionAudit]) -> DecisionSummary:
    summary = DecisionSummary()
    for audit in audits:
        summary.add_audit(audit)
    return summary


def summarize_audit_dir(audit_dir: Path) -> DecisionSummary:
    audits: list[SessionAudit] = []
    for path in sorted(audit_dir.glob("session-*.json")):
        try:
            audits.append(SessionAudit.read(path))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
    return summarize_audits(audits)


def summarize_bundles(bundles: list[EvidenceBundle]) -> DecisionSummary:
    summary = DecisionSummary()
    for bundle in bundles:
        summary.add_bundle(bundle)
    return summary


def summarize_bundle_dir(bundle_dir: Path) -> DecisionSummary:
    bundles: list[EvidenceBundle] = []
    for path in sorted(bundle_dir.glob("*.json")):
        try:
            bundles.append(read_evidence_bundle(path))
        except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
    return summarize_bundles(bundles)


def summarize_evidence(
    audit_dir: Path | None = None,
    bundle_dir: Path | None = None,
) -> DecisionSummary:
    summary = DecisionSummary()
    if audit_dir is not None:
        for path in sorted(audit_dir.glob("session-*.json")):
            try:
                summary.add_audit(SessionAudit.read(path))
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    if bundle_dir is not None:
        for path in sorted(bundle_dir.glob("*.json")):
            try:
                summary.add_bundle(read_evidence_bundle(path))
            except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
                continue
    return summary


def render_text_summary(summary: DecisionSummary) -> str:
    payload = summary.to_dict()
    lines = [
        "TerraGuard AgentShield Decision Summary",
        "",
        f"Sessions: {payload['session_count']}",
        f"Evidence bundles: {payload['bundle_count']}",
        f"Actions: {payload['action_count']}",
        f"Risk findings: {payload['finding_count']}",
        "",
        "Decisions:",
    ]
    lines.extend(_render_mapping(payload["decisions"]))
    lines.append("")
    lines.append("Risks:")
    lines.extend(_render_mapping(payload["risks"]))
    lines.append("")
    lines.append("Control families:")
    for family, values in payload["control_families"].items():
        lines.append(
            f"- {family}: {values['actions']} action(s), {values['findings']} finding(s)"
        )
    return "\n".join(lines)


def _action_control_family(action: AuditAction) -> str:
    metadata_family = action.metadata.get("control_family")
    if metadata_family:
        return str(metadata_family)

    action_type = action.type.lower()
    target = action.target.lower()
    reason = (action.reason or "").lower()
    combined = f"{action_type} {target} {reason}"

    if "mcp" in combined:
        return "tool-governance"
    if "git" in combined or "push" in combined or "branch" in combined:
        return "change-management"
    if "terraform" in combined or "tofu" in combined or "kubectl" in combined:
        return "infrastructure-change"
    if any(token in combined for token in (".env", ".pem", "secret", "tfstate", "tfvars")):
        return "data-protection"
    if "iam" in combined or "role" in combined or "policy" in combined:
        return "identity-access"
    if "file" in action_type:
        return "source-control"
    return "runtime-governance"


def _ordered_counter(counter: Counter[str]) -> dict[str, int]:
    return {
        key: counter[key]
        for key in sorted(counter, key=lambda item: (-counter[item], item))
    }


def _render_mapping(mapping: dict[str, int]) -> list[str]:
    if not mapping:
        return ["- none"]
    return [f"- {key}: {value}" for key, value in mapping.items()]
