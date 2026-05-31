"""
PR Guardian — GitHub pull request governance orchestration.

Combines AI Agent Detection, Semantic Risk Classification, and Policy Explanation
into a single reviewer-ready governance report. Optionally publishes to GitHub PR.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from terraguard_agentshield.agent_detector import detect_ai_agent_change
from terraguard_agentshield.explain import explain_risk_summary
from terraguard_agentshield.risk import SemanticRiskClassifier, should_fail_for_risk


@dataclass(frozen=True)
class PRGuardianConfig:
    """Configuration for PR Guardian execution."""

    diff_path: Path
    """Path to unified diff file."""
    repo: str | None = None
    """GitHub repository as owner/name."""
    pr_number: int | None = None
    """Pull request number."""
    policy_pack: str | None = None
    """Policy pack ID for risk and policy evaluation."""
    fail_on: str = "high"
    """Failure threshold: 'low', 'medium', 'high', 'critical'."""
    audit_dir: Path = Path(".terraguard/audit")
    """Audit directory for agent detection signals."""
    bundle_dir: Path = Path(".terraguard/agentshield/evidence")
    """Evidence bundle directory."""
    output_dir: Path = Path(".terraguard/agentshield/pr-guardian")
    """Output directory for reports."""
    publish_comment: bool = False
    """Publish result to GitHub PR comment."""
    github_token: str | None = None
    """GitHub API token."""
    github_api_url: str = "https://api.github.com"
    """GitHub API base URL."""
    dry_run: bool = False
    """Print output without publishing or failing."""


@dataclass(frozen=True)
class PRGuardianResult:
    """Result of PR Guardian analysis."""

    decision: str
    """Decision: 'pass', 'warn', 'require_approval', 'block'."""
    max_risk: str
    """Maximum risk level: 'critical', 'high', 'medium', 'low', 'none'."""
    should_fail: bool
    """Whether to exit with failure code."""
    ai_agent_detected: bool
    """Whether AI agent is likely involved."""
    ai_agent_confidence: str
    """AI agent confidence: 'high', 'medium', 'low', 'none'."""
    ai_agent_type: str | None
    """Inferred AI agent type."""
    risk_summary: dict[str, Any]
    """Risk classification summary."""
    agent_detection: dict[str, Any]
    """Agent detection result."""
    explanation: dict[str, Any]
    """Policy explanation."""
    markdown_report: str
    """Markdown-formatted governance report."""
    json_report_path: str | None = None
    """Path to JSON report if written."""
    markdown_report_path: str | None = None
    """Path to Markdown report if written."""
    pr_comment_url: str | None = None
    """GitHub PR comment URL if published."""


def run_pr_guardian(config: PRGuardianConfig) -> PRGuardianResult:
    """
    Execute PR Guardian: AI detection + risk classification + policy explanation.

    Args:
        config: PRGuardianConfig with all settings.

    Returns:
        PRGuardianResult with decision, risks, agent detection, and reports.
    """
    # 1. Read diff
    if not config.diff_path.exists():
        raise FileNotFoundError(f"Diff file not found: {config.diff_path}")

    diff_text = config.diff_path.read_text(encoding="utf-8")

    # 2. Run semantic risk classifier
    risk_classifier = SemanticRiskClassifier()
    risk_summary = risk_classifier.classify_diff(diff_text)
    risk_dict = risk_summary.to_dict()

    # 3. Run AI agent detector
    agent_result = detect_ai_agent_change(
        repo=Path("."),
        audit_dir=config.audit_dir if config.audit_dir.exists() else None,
    )
    agent_dict = agent_result.to_dict()

    # 4. Run policy explain
    explanation_result = explain_risk_summary(
        risk_dict, policy_pack=config.policy_pack, fail_on=config.fail_on
    )
    explanation_dict = explanation_result.to_dict()

    # 5. Determine decision and should_fail
    max_risk = risk_summary.max_risk
    try:
        should_fail = should_fail_for_risk(risk_summary, config.fail_on)
    except ValueError:
        should_fail = False

    decision = explanation_result.decision

    # 6. Generate markdown report
    markdown_report = _render_pr_guardian_markdown(
        decision=decision,
        max_risk=max_risk,
        fail_on=config.fail_on,
        policy_pack=config.policy_pack,
        agent_result=agent_result,
        risk_summary=risk_dict,
        explanation=explanation_result,
    )

    # 7. Write JSON and Markdown artifacts if output_dir provided
    json_report_path = None
    markdown_report_path = None

    if config.output_dir:
        config.output_dir.mkdir(parents=True, exist_ok=True)

        # Write JSON report
        json_report_path_obj = config.output_dir / "agentshield-pr-guardian.json"
        json_payload = {
            "timestamp": datetime.utcnow().isoformat(),
            "decision": decision,
            "max_risk": max_risk,
            "fail_on": config.fail_on,
            "policy_pack": config.policy_pack,
            "repository": config.repo,
            "pr_number": config.pr_number,
            "ai_agent_detected": agent_result.detected,
            "ai_agent_confidence": agent_result.confidence,
            "ai_agent_type": agent_result.agent_type,
            "risk_summary": risk_dict,
            "agent_detection": agent_dict,
            "explanation": explanation_dict,
        }
        json_report_path_obj.write_text(json.dumps(json_payload, indent=2) + "\n")
        json_report_path = str(json_report_path_obj)

        # Write Markdown report
        markdown_report_path_obj = config.output_dir / "agentshield-pr-guardian.md"
        markdown_report_path_obj.write_text(markdown_report + "\n")
        markdown_report_path = str(markdown_report_path_obj)

    # 8. Publish GitHub comment if requested (and not dry-run)
    pr_comment_url = None
    if config.publish_comment and not config.dry_run:
        from terraguard_agentshield.integrations import GitHubPRCommentPublisher

        if not config.repo or config.pr_number is None or not config.github_token:
            raise ValueError(
                "GitHub publish requires --repo, --pr-number, and GitHub token"
            )

        publisher = GitHubPRCommentPublisher(
            config.github_token,
            api_url=config.github_api_url,
            marker="<!-- terraguard-agentshield-pr-guardian -->",
        )
        result = publisher.publish(config.repo, config.pr_number, markdown_report)
        if result.success:
            pr_comment_url = result.comment_url
        else:
            raise RuntimeError(
                f"Failed to publish GitHub PR comment: {result.error}"
            )

    return PRGuardianResult(
        decision=decision,
        max_risk=max_risk,
        should_fail=should_fail,
        ai_agent_detected=agent_result.detected,
        ai_agent_confidence=agent_result.confidence,
        ai_agent_type=agent_result.agent_type,
        risk_summary=risk_dict,
        agent_detection=agent_dict,
        explanation=explanation_dict,
        markdown_report=markdown_report,
        json_report_path=json_report_path,
        markdown_report_path=markdown_report_path,
        pr_comment_url=pr_comment_url,
    )


def _render_pr_guardian_markdown(
    decision: str,
    max_risk: str,
    fail_on: str,
    policy_pack: str | None,
    agent_result: Any,
    risk_summary: dict[str, Any],
    explanation: Any,
) -> str:
    """
    Render PR Guardian result as a GitHub-ready Markdown report.

    Args:
        decision: Overall decision.
        max_risk: Maximum risk level.
        fail_on: Failure threshold.
        policy_pack: Policy pack ID.
        agent_result: Agent detection result object.
        risk_summary: Risk summary dict.
        explanation: PolicyExplanation object.

    Returns:
        Markdown-formatted report string.
    """
    lines = [
        "<!-- terraguard-agentshield-pr-guardian -->",
        "",
        "# TerraGuard AgentShield PR Guardian",
        "",
        f"**Decision:** {decision.replace('_', ' ').title()}",
        f"**Max risk:** {max_risk}",
        f"**Failure threshold:** {fail_on}",
    ]

    if policy_pack:
        lines.append(f"**Policy pack:** {policy_pack}")

    lines.append("")

    # AI Agent Detection section
    lines.append("## AI Agent Detection")
    lines.append("")
    lines.append(
        f"**AI agent detected:** {'Yes' if agent_result.detected else 'No'}"
    )
    lines.append(f"**Confidence:** {agent_result.confidence.title()}")
    if agent_result.agent_type:
        lines.append(f"**Likely agent:** {agent_result.agent_type.replace('-', ' ').title()}")
    lines.append("")

    # Risk Summary section
    findings = risk_summary.get("findings", [])
    risk_counts = {}
    for finding in findings:
        risk_level = finding.get("risk", "medium")
        risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1

    lines.append("## Risk Summary")
    lines.append("")
    lines.append("| Risk | Count |")
    lines.append("| --- | ---: |")
    for level in ["critical", "high", "medium", "low"]:
        count = risk_counts.get(level, 0)
        lines.append(f"| {level.title()} | {count} |")
    lines.append("")

    # Findings table
    if findings:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Risk | Category | File | Line | Why it matters |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for finding in findings:
            risk = finding.get("risk", "medium").title()
            category = finding.get("category", "unknown").replace("-", " ").title()
            file_name = finding.get("file", "—")
            line_num = finding.get("line", "—")
            evidence = finding.get("evidence", "")[:50] + "..." if len(finding.get("evidence", "")) > 50 else finding.get("evidence", "")
            lines.append(
                f"| {risk} | {category} | {file_name} | {line_num} | {evidence or '—'} |"
            )
        lines.append("")

    # Policy Explanation section
    lines.append("## Policy Explanation")
    lines.append("")
    lines.append(explanation.summary)
    lines.append("")

    # Required reviewers
    reviewer_hints = set()
    for item in explanation.items:
        if item.reviewer_hint:
            reviewer_hints.add(item.reviewer_hint)

    if reviewer_hints:
        lines.append("### Required reviewer groups")
        lines.append("")
        for hint in sorted(reviewer_hints):
            lines.append(f"- {hint}")
        lines.append("")

    # Remediation
    if findings:
        lines.append("## Recommended remediation")
        lines.append("")
        lines.append("1. Review each finding above.")
        lines.append("2. Apply recommended fixes.")
        lines.append("3. Re-run AgentShield PR Guardian after remediation.")
        lines.append("")

    # Evidence artifacts
    lines.append("## Evidence artifacts")
    lines.append("")
    lines.append("- `agentshield-pr-guardian.json`")
    lines.append("- `agentshield-pr-guardian.md`")
    lines.append("")

    return "\n".join(lines)
