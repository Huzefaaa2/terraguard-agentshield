from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from terraguard_agentshield.agent_detector import (
    detect_ai_agent_change,
    render_detection_markdown,
)
from terraguard_agentshield.explain import (
    PolicyExplanation,
    explain_risk_summary,
    render_explanation_markdown,
)
from terraguard_agentshield.integrations import GitHubPRCommentPublisher
from terraguard_agentshield.risk import (
    RiskSummary,
    SemanticRiskClassifier,
    should_fail_for_risk,
)


REPORT_JSON = "agentshield-pr-guardian.json"
REPORT_MARKDOWN = "agentshield-pr-guardian.md"
EXPLANATION_MARKDOWN = "agentshield-policy-explanation.md"
PR_GUARDIAN_MARKER = "<!-- terraguard-agentshield-pr-guardian -->"


@dataclass(frozen=True)
class PRGuardianConfig:
    diff_path: Path
    repo: str | None = None
    pr_number: int | None = None
    policy_pack: str | None = None
    fail_on: str = "high"
    audit_dir: Path = Path(".terraguard/audit")
    bundle_dir: Path = Path(".terraguard/agentshield/evidence")
    output_dir: Path = Path(".terraguard/agentshield/pr-guardian")
    publish_comment: bool = False
    github_token: str | None = None
    github_api_url: str = "https://api.github.com"
    dry_run: bool = False
    event_path: Path | None = None
    branch: str | None = None
    pr_title: str | None = None
    pr_body: str | None = None


@dataclass(frozen=True)
class PRGuardianResult:
    decision: str
    max_risk: str
    should_fail: bool
    ai_agent_detected: bool
    ai_agent_confidence: str
    ai_agent_type: str | None
    risk_summary: dict[str, Any]
    agent_detection: dict[str, Any]
    explanation: dict[str, Any]
    markdown_report: str
    json_report_path: str | None = None
    markdown_report_path: str | None = None
    pr_comment_url: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision,
            "max_risk": self.max_risk,
            "should_fail": self.should_fail,
            "ai_agent_detected": self.ai_agent_detected,
            "ai_agent_confidence": self.ai_agent_confidence,
            "ai_agent_type": self.ai_agent_type,
            "risk_summary": self.risk_summary,
            "agent_detection": self.agent_detection,
            "explanation": self.explanation,
            "markdown_report": self.markdown_report,
            "json_report_path": self.json_report_path,
            "markdown_report_path": self.markdown_report_path,
            "pr_comment_url": self.pr_comment_url,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def run_pr_guardian(config: PRGuardianConfig) -> PRGuardianResult:
    if not config.diff_path.exists():
        raise FileNotFoundError(f"Diff file not found: {config.diff_path}")

    diff_text = config.diff_path.read_text(encoding="utf-8")
    risk_summary = SemanticRiskClassifier().classify_diff(diff_text)
    should_fail = bool(risk_summary.findings) and should_fail_for_risk(
        risk_summary, config.fail_on
    )
    detection = detect_ai_agent_change(
        repo=Path("."),
        branch=config.branch,
        pr_title=config.pr_title,
        pr_body=config.pr_body,
        event_path=config.event_path,
        audit_dir=config.audit_dir,
    )
    explanation = explain_risk_summary(
        risk_summary,
        policy_pack=config.policy_pack,
        fail_on=config.fail_on,
    )
    markdown_report = render_pr_guardian_markdown(
        risk_summary=risk_summary,
        explanation=explanation,
        agent_detection_markdown=render_detection_markdown(detection),
        policy_pack=config.policy_pack,
        fail_on=config.fail_on,
    )

    config.output_dir.mkdir(parents=True, exist_ok=True)
    markdown_path = config.output_dir / REPORT_MARKDOWN
    explanation_path = config.output_dir / EXPLANATION_MARKDOWN
    json_path = config.output_dir / REPORT_JSON
    markdown_path.write_text(markdown_report + "\n", encoding="utf-8")
    explanation_path.write_text(
        render_explanation_markdown(explanation) + "\n", encoding="utf-8"
    )

    pr_comment_url = None
    if config.publish_comment and not config.dry_run:
        if not config.repo:
            raise ValueError("GitHub repository missing. Set --repo or GITHUB_REPOSITORY.")
        if config.pr_number is None:
            raise ValueError("Pull request number missing. Set --pr-number or GITHUB_EVENT_PATH.")
        if not config.github_token:
            raise ValueError("GitHub token missing. Set GITHUB_TOKEN or --github-token-env.")
        publisher = GitHubPRCommentPublisher(
            config.github_token,
            api_url=config.github_api_url,
            marker=PR_GUARDIAN_MARKER,
        )
        publish_result = publisher.publish(config.repo, config.pr_number, markdown_report)
        if not publish_result.success:
            raise RuntimeError(f"GitHub PR comment publish failed: {publish_result.error}")
        pr_comment_url = publish_result.comment_url

    result = PRGuardianResult(
        decision=explanation.decision,
        max_risk=risk_summary.max_risk,
        should_fail=should_fail,
        ai_agent_detected=detection.detected,
        ai_agent_confidence=detection.confidence,
        ai_agent_type=detection.agent_type,
        risk_summary=risk_summary.to_dict(),
        agent_detection=detection.to_dict(),
        explanation=explanation.to_dict(),
        markdown_report=markdown_report,
        json_report_path=str(json_path),
        markdown_report_path=str(markdown_path),
        pr_comment_url=pr_comment_url,
    )
    json_path.write_text(result.to_json() + "\n", encoding="utf-8")
    return result


def render_pr_guardian_markdown(
    risk_summary: RiskSummary,
    explanation: PolicyExplanation,
    agent_detection_markdown: str,
    policy_pack: str | None = None,
    fail_on: str = "high",
) -> str:
    if not risk_summary.findings:
        return "\n".join(
            [
                PR_GUARDIAN_MARKER,
                "",
                "# TerraGuard AgentShield PR Guardian",
                "",
                "**Decision:** Pass  ",
                f"**Max risk:** {risk_summary.max_risk.title()}  ",
                f"**Failure threshold:** {fail_on}  ",
                f"**Policy pack:** {policy_pack or 'not supplied'}",
                "",
                "No high-risk AgentShield findings were detected in this pull request.",
                "",
                agent_detection_markdown,
            ]
        )

    lines = [
        PR_GUARDIAN_MARKER,
        "",
        "# TerraGuard AgentShield PR Guardian",
        "",
        f"**Decision:** {_display_decision(explanation.decision)}  ",
        f"**Max risk:** {risk_summary.max_risk.title()}  ",
        f"**Failure threshold:** {fail_on}  ",
        f"**Policy pack:** {policy_pack or 'not supplied'}",
        "",
        agent_detection_markdown,
        "",
        "## Risk Summary",
        "",
        "| Risk | Count |",
        "| --- | ---: |",
    ]
    counts = risk_summary.to_dict().get("risk_counts", {})
    for risk in ("critical", "high", "medium", "low"):
        lines.append(f"| {risk.title()} | {counts.get(risk, 0)} |")

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Risk | Category | File | Line | Why it matters |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for item in explanation.items:
        lines.append(
            f"| {item.risk.title()} | {item.category} | `{item.file or 'unknown'}` | "
            f"{item.line if item.line is not None else ''} | {item.why_it_matters} |"
        )

    reviewer_groups = _unique(
        item.reviewer_hint or "Platform/security reviewer" for item in explanation.items
    )
    recommendations = _unique(item.recommendation for item in explanation.items)
    lines.extend(
        [
            "",
            "## Policy Explanation",
            "",
            explanation.summary,
            "",
            "### Required reviewer groups",
            "",
        ]
    )
    lines.extend(f"- {reviewer}" for reviewer in reviewer_groups)
    lines.extend(["", "## Recommended remediation", ""])
    lines.extend(f"{index}. {text}" for index, text in enumerate(recommendations, start=1))
    lines.extend(
        [
            "",
            "## Evidence artifacts",
            "",
            f"- `{REPORT_JSON}`",
            f"- `{REPORT_MARKDOWN}`",
            f"- `{EXPLANATION_MARKDOWN}`",
        ]
    )
    return "\n".join(lines)


def _unique(values: Any) -> list[str]:
    seen: set[str] = set()
    unique_values: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            unique_values.append(value)
    return unique_values


def _display_decision(decision: str) -> str:
    return decision.replace("_", " ").title()
