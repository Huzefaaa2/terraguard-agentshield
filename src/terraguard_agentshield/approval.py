from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from terraguard_agentshield.summary import DecisionSummary


DEFAULT_APPROVER_GROUPS = {
    "application-security": "appsec-reviewers",
    "audit-monitoring": "security-operations",
    "change-management": "change-advisory-board",
    "data-protection": "data-protection-office",
    "identity-access": "iam-security",
    "infrastructure-change": "platform-security",
    "network-security": "cloud-security",
    "runtime-governance": "platform-security",
    "source-control": "engineering-reviewers",
    "tool-governance": "ai-governance",
    "unmapped": "platform-security",
}

RISK_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
PRIORITY_LABELS = {4: "critical", 3: "high", 2: "medium", 1: "low"}


@dataclass(frozen=True)
class ApprovalRoutingConfig:
    approver_groups: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_APPROVER_GROUPS))
    default_group: str = "platform-security"
    require_approval_for_risks: set[str] = field(
        default_factory=lambda: {"critical", "high"}
    )
    require_approval_for_decisions: set[str] = field(
        default_factory=lambda: {"block", "require_approval"}
    )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ApprovalRoutingConfig":
        approver_groups = dict(DEFAULT_APPROVER_GROUPS)
        configured_groups = payload.get("approver_groups", {})
        if isinstance(configured_groups, Mapping):
            approver_groups.update(
                {str(key): str(value) for key, value in configured_groups.items()}
            )

        risk_items = payload.get("require_approval_for_risks")
        decision_items = payload.get("require_approval_for_decisions")
        return cls(
            approver_groups=approver_groups,
            default_group=str(payload.get("default_group") or "platform-security"),
            require_approval_for_risks=_string_set(
                risk_items, default={"critical", "high"}
            ),
            require_approval_for_decisions=_string_set(
                decision_items, default={"block", "require_approval"}
            ),
        )

    @classmethod
    def from_file(cls, path: Path) -> "ApprovalRoutingConfig":
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(payload, Mapping):
            raise ValueError(f"Approval routing config is not a mapping: {path}")
        return cls.from_dict(payload)

    def group_for_family(self, control_family: str) -> str:
        return self.approver_groups.get(control_family, self.default_group)


@dataclass(frozen=True)
class ApprovalRoute:
    route_id: str
    control_family: str
    approver_group: str
    priority: str
    approval_required: bool
    reason: str
    action_count: int = 0
    finding_count: int = 0
    decisions: dict[str, int] = field(default_factory=dict)
    risks: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "control_family": self.control_family,
            "approver_group": self.approver_group,
            "priority": self.priority,
            "approval_required": self.approval_required,
            "reason": self.reason,
            "action_count": self.action_count,
            "finding_count": self.finding_count,
            "decisions": self.decisions,
            "risks": self.risks,
        }


@dataclass(frozen=True)
class ApprovalRoutingResult:
    generated_at: str
    routes: list[ApprovalRoute] = field(default_factory=list)

    @property
    def required_route_count(self) -> int:
        return len([route for route in self.routes if route.approval_required])

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "route_count": len(self.routes),
            "required_route_count": self.required_route_count,
            "routes": [route.to_dict() for route in self.routes],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def route_approvals(
    summary: DecisionSummary | Mapping[str, Any],
    config: ApprovalRoutingConfig | None = None,
) -> ApprovalRoutingResult:
    payload = summary.to_dict() if isinstance(summary, DecisionSummary) else dict(summary)
    routing_config = config or ApprovalRoutingConfig()
    routes: list[ApprovalRoute] = []

    families = payload.get("control_families", {})
    if isinstance(families, Mapping):
        for family, values in families.items():
            if not isinstance(values, Mapping):
                continue
            route = _route_family(str(family), values, routing_config)
            if route is not None:
                routes.append(route)

    routes = sorted(
        routes,
        key=lambda item: (
            -RISK_PRIORITY.get(item.priority, 0),
            not item.approval_required,
            item.control_family,
        ),
    )
    return ApprovalRoutingResult(
        generated_at=datetime.utcnow().isoformat() + "Z",
        routes=routes,
    )


def render_text_routes(result: ApprovalRoutingResult) -> str:
    payload = result.to_dict()
    lines = [
        "TerraGuard AgentShield Approval Routes",
        "",
        f"Routes: {payload['route_count']}",
        f"Approval required: {payload['required_route_count']}",
        "",
    ]
    if not result.routes:
        lines.append("No approval routes required.")
        return "\n".join(lines)

    for route in result.routes:
        marker = "required" if route.approval_required else "advisory"
        lines.append(
            f"- {route.control_family} -> {route.approver_group} "
            f"({route.priority}, {marker})"
        )
        lines.append(f"  {route.reason}")
    return "\n".join(lines)


def _route_family(
    control_family: str,
    values: Mapping[str, Any],
    config: ApprovalRoutingConfig,
) -> ApprovalRoute | None:
    decisions = _int_mapping(values.get("decisions", {}))
    risks = _int_mapping(values.get("risks", {}))
    action_count = int(values.get("actions") or 0)
    finding_count = int(values.get("findings") or 0)

    approval_decisions = {
        decision: count
        for decision, count in decisions.items()
        if decision in config.require_approval_for_decisions and count > 0
    }
    approval_risks = {
        risk: count
        for risk, count in risks.items()
        if risk in config.require_approval_for_risks and count > 0
    }

    if not approval_decisions and not approval_risks and finding_count == 0:
        return None

    priority = _priority(decisions, risks, finding_count)
    approval_required = bool(approval_decisions or approval_risks)
    return ApprovalRoute(
        route_id=f"route-{control_family}",
        control_family=control_family,
        approver_group=config.group_for_family(control_family),
        priority=priority,
        approval_required=approval_required,
        reason=_reason(control_family, decisions, risks, action_count, finding_count),
        action_count=action_count,
        finding_count=finding_count,
        decisions=decisions,
        risks=risks,
    )


def _priority(
    decisions: dict[str, int],
    risks: dict[str, int],
    finding_count: int,
) -> str:
    max_priority = 1
    for risk, count in risks.items():
        if count:
            max_priority = max(max_priority, RISK_PRIORITY.get(risk, 1))
    if decisions.get("block", 0):
        max_priority = max(max_priority, 3)
    if decisions.get("require_approval", 0):
        max_priority = max(max_priority, 3)
    if finding_count:
        max_priority = max(max_priority, 2)
    return PRIORITY_LABELS[max_priority]


def _reason(
    control_family: str,
    decisions: dict[str, int],
    risks: dict[str, int],
    action_count: int,
    finding_count: int,
) -> str:
    parts = [f"{control_family} has {action_count} governed action(s)"]
    if finding_count:
        parts.append(f"{finding_count} semantic risk finding(s)")
    if decisions:
        parts.append(
            "decisions: "
            + ", ".join(f"{decision}={count}" for decision, count in decisions.items())
        )
    if risks:
        parts.append(
            "risks: " + ", ".join(f"{risk}={count}" for risk, count in risks.items())
        )
    return "; ".join(parts) + "."


def _int_mapping(payload: Any) -> dict[str, int]:
    if not isinstance(payload, Mapping):
        return {}
    parsed: dict[str, int] = {}
    for key, value in payload.items():
        try:
            parsed[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return parsed


def _string_set(items: Any, default: set[str]) -> set[str]:
    if items is None:
        return set(default)
    if not isinstance(items, list):
        return set(default)
    return {str(item) for item in items}
