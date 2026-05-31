from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


KNOWN_AGENT_MARKERS = {
    "github-copilot": (
        "github copilot",
        "copilot",
        "created by copilot",
        "co-authored-by: github copilot",
    ),
    "openai-codex": (
        "openai codex",
        "codex cli",
        "codex",
        "created by codex",
    ),
    "claude-code": (
        "generated with claude code",
        "claude code",
        "claude",
    ),
    "cursor": ("cursor",),
}

AUTOMATION_BOT_MARKERS = ("dependabot", "renovate")


@dataclass(frozen=True)
class AgentSignal:
    source: str
    value: str
    weight: int
    agent_type: str | None = None
    description: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "value": self.value,
            "weight": self.weight,
            "agent_type": self.agent_type,
            "description": self.description,
        }


@dataclass(frozen=True)
class AgentDetectionResult:
    detected: bool
    confidence: str
    score: int
    agent_type: str | None
    signals: list[AgentSignal] = field(default_factory=list)
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detected": self.detected,
            "confidence": self.confidence,
            "score": self.score,
            "agent_type": self.agent_type,
            "signals": [signal.to_dict() for signal in self.signals],
            "recommendation": self.recommendation,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def detect_ai_agent_change(
    repo: Path = Path("."),
    branch: str | None = None,
    pr_title: str | None = None,
    pr_body: str | None = None,
    event_path: Path | None = None,
    commit_messages: list[str] | None = None,
    authors: list[str] | None = None,
    audit_dir: Path | None = None,
) -> AgentDetectionResult:
    """Detect likely AI-agent involvement using deterministic weighted signals."""
    event_data = _read_event(event_path)
    branch = branch or _event_branch(event_data) or _current_branch(repo)
    pr_title = pr_title or _event_pr_text(event_data, "title")
    pr_body = pr_body or _event_pr_text(event_data, "body")
    commit_messages = commit_messages if commit_messages is not None else []
    authors = authors if authors is not None else []
    authors.extend(_event_authors(event_data))

    signals: list[AgentSignal] = []
    signals.extend(_branch_signals(branch))
    signals.extend(_text_signals("pr_title", pr_title, weight_high=40, weight_medium=25))
    signals.extend(_text_signals("pr_body", pr_body, weight_high=50, weight_medium=30))
    for message in commit_messages:
        signals.extend(
            _text_signals("commit_message", message, weight_high=50, weight_medium=30)
        )
    for author in authors:
        signals.extend(_author_signals(author))
    signals.extend(_event_sender_signals(event_data, branch, pr_title, pr_body))
    signals.extend(_audit_signals(audit_dir or repo / ".terraguard" / "audit"))
    signals.extend(_repo_context_signals(repo))

    return _result_from_signals(signals)


def render_detection_text(result: AgentDetectionResult) -> str:
    lines = [
        f"Detected: {'yes' if result.detected else 'no'}",
        f"Confidence: {result.confidence}",
        f"Score: {result.score}",
        f"Likely agent: {result.agent_type or 'none'}",
    ]
    if result.signals:
        lines.append("")
        lines.append("Signals:")
        for signal in result.signals:
            lines.append(
                f"- {signal.source}: {signal.value} "
                f"({signal.weight}, {signal.agent_type or 'unknown'})"
            )
    if result.recommendation:
        lines.append("")
        lines.append(f"Recommendation: {result.recommendation}")
    return "\n".join(lines)


def render_detection_markdown(result: AgentDetectionResult) -> str:
    lines = [
        "## AI Agent Detection",
        "",
        f"**Detected:** {'Yes' if result.detected else 'No'}  ",
        f"**Confidence:** {result.confidence.title()}  ",
        f"**Likely agent:** {_display_agent(result.agent_type)}  ",
        f"**Score:** {result.score}",
        "",
    ]
    if result.signals:
        lines.extend(
            [
                "### Signals",
                "",
                "| Source | Signal | Weight | Meaning |",
                "| --- | --- | ---: | --- |",
            ]
        )
        for signal in result.signals:
            lines.append(
                f"| {signal.source} | `{_escape_table(signal.value)}` | "
                f"{signal.weight} | {signal.description or ''} |"
            )
    else:
        lines.append("No AI-agent signals were detected.")
    if result.recommendation:
        lines.extend(["", f"**Recommendation:** {result.recommendation}"])
    return "\n".join(lines)


def _branch_signals(branch: str | None) -> list[AgentSignal]:
    if not branch:
        return []
    lowered = branch.lower()
    patterns = (
        (r"^copilot/", "github-copilot", 45, "Branch name matches known Copilot pattern."),
        (r"^codex/", "openai-codex", 45, "Branch name matches known Codex pattern."),
        (r"^claude/", "claude-code", 45, "Branch name matches known Claude pattern."),
        (r"^cursor/", "cursor", 45, "Branch name matches known Cursor pattern."),
        (r"^ai-agent/", "generic-ai-agent", 40, "Branch name matches AI-agent pattern."),
        (r"^agents/", "generic-ai-agent", 35, "Branch name matches agent pattern."),
    )
    for pattern, agent_type, weight, description in patterns:
        if re.search(pattern, lowered):
            return [AgentSignal("branch", branch, weight, agent_type, description)]
    if re.search(r"(^|[-_/])(ai|assistant|bot)([-_/]|$)", lowered):
        return [
            AgentSignal(
                "branch",
                branch,
                20,
                "generic-ai-agent",
                "Branch contains a generic AI, assistant, or bot marker.",
            )
        ]
    return []


def _text_signals(
    source: str, text: str | None, weight_high: int, weight_medium: int
) -> list[AgentSignal]:
    if not text:
        return []
    lowered = text.lower()
    signals: list[AgentSignal] = []
    for agent_type, markers in KNOWN_AGENT_MARKERS.items():
        for marker in markers:
            if marker in lowered:
                signals.append(
                    AgentSignal(
                        source,
                        _matching_fragment(text, marker),
                        weight_high,
                        agent_type,
                        f"{source.replace('_', ' ').title()} indicates {_display_agent(agent_type)} participation.",
                    )
                )
                return signals
    medium_markers = (
        "ai assisted",
        "ai-assisted",
        "ai-generated",
        "agent",
        "copilot suggested",
        "codex generated",
        "generated by an ai agent",
        "created by an ai agent",
    )
    for marker in medium_markers:
        if marker in lowered:
            return [
                AgentSignal(
                    source,
                    _matching_fragment(text, marker),
                    weight_medium,
                    "generic-ai-agent",
                    f"{source.replace('_', ' ').title()} contains an AI-agent marker.",
                )
            ]
    return []


def _author_signals(author: str) -> list[AgentSignal]:
    lowered = author.lower()
    for marker in AUTOMATION_BOT_MARKERS:
        if marker in lowered:
            return [
                AgentSignal(
                    "author",
                    author,
                    15,
                    "automation-bot",
                    f"{marker.title()} is automation, not an AI coding agent by itself.",
                )
            ]
    for agent_type, markers in KNOWN_AGENT_MARKERS.items():
        if any(marker in lowered for marker in markers):
            return [
                AgentSignal(
                    "author",
                    author,
                    45,
                    agent_type,
                    f"Author identity matches {_display_agent(agent_type)} marker.",
                )
            ]
    if "bot" in lowered and any(
        marker in lowered for markers in KNOWN_AGENT_MARKERS.values() for marker in markers
    ):
        return [
            AgentSignal(
                "author",
                author,
                35,
                "generic-ai-agent",
                "Bot author also contains an AI-agent marker.",
            )
        ]
    return []


def _event_sender_signals(
    event_data: dict[str, Any],
    branch: str | None,
    pr_title: str | None,
    pr_body: str | None,
) -> list[AgentSignal]:
    sender = event_data.get("sender")
    if not isinstance(sender, dict):
        return []
    sender_type = str(sender.get("type") or "").lower()
    login = str(sender.get("login") or "")
    if sender_type != "bot":
        return []
    bot_signals = _author_signals(login)
    if any(signal.agent_type != "automation-bot" for signal in bot_signals):
        return bot_signals
    has_ai_context = bool(_branch_signals(branch) or _text_signals("pr_title", pr_title, 40, 25) or _text_signals("pr_body", pr_body, 50, 30))
    if has_ai_context:
        return [
            AgentSignal(
                "event_sender",
                login or "Bot",
                20,
                "generic-ai-agent",
                "GitHub event sender is a bot and PR metadata has AI-agent context.",
            )
        ]
    return bot_signals


def _audit_signals(audit_dir: Path | None) -> list[AgentSignal]:
    if not audit_dir or not audit_dir.exists():
        return []
    signals: list[AgentSignal] = []
    for path in sorted(audit_dir.glob("session-*.json"))[:20]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        values = [
            payload.get("tool"),
            payload.get("agent"),
            payload.get("tool_name"),
        ]
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            values.extend([metadata.get("tool"), metadata.get("agent")])
        for value in values:
            agent_type = _agent_type_from_text(str(value or ""))
            if agent_type:
                signals.append(
                    AgentSignal(
                        "audit_metadata",
                        str(value),
                        55,
                        agent_type,
                        "AgentShield audit metadata identifies the AI coding tool.",
                    )
                )
                return signals
    return signals


def _repo_context_signals(repo: Path) -> list[AgentSignal]:
    copilot_instructions = repo / ".github" / "copilot-instructions.md"
    if copilot_instructions.exists():
        return [
            AgentSignal(
                "repo_context",
                ".github/copilot-instructions.md",
                10,
                "github-copilot",
                "Repository contains Copilot instructions; this is a low-confidence context signal.",
            )
        ]
    return []


def _result_from_signals(signals: list[AgentSignal]) -> AgentDetectionResult:
    score = min(100, sum(signal.weight for signal in signals))
    ai_signals = [signal for signal in signals if signal.agent_type != "automation-bot"]
    automation_only = bool(signals) and not ai_signals
    detected = bool(ai_signals) and score >= 25
    if automation_only:
        confidence = "low"
        agent_type = "automation-bot"
    elif score >= 80:
        confidence = "high"
        agent_type = _strongest_agent(ai_signals)
    elif score >= 50:
        confidence = "medium"
        agent_type = _strongest_agent(ai_signals)
    elif score >= 25:
        confidence = "low"
        agent_type = _strongest_agent(ai_signals)
    else:
        confidence = "none"
        agent_type = None
    recommendation = (
        "Review this PR with AI-agent governance controls enabled."
        if detected
        else "No AI-agent-specific review path is required from detector signals alone."
    )
    if automation_only:
        recommendation = (
            "Automation bot detected, but no AI coding-agent signal was found."
        )
    return AgentDetectionResult(
        detected=detected,
        confidence=confidence,
        score=score,
        agent_type=agent_type,
        signals=signals,
        recommendation=recommendation,
    )


def _strongest_agent(signals: list[AgentSignal]) -> str | None:
    if not signals:
        return None
    strongest = max(signals, key=lambda signal: signal.weight)
    return strongest.agent_type or "unknown"


def _read_event(event_path: Path | None) -> dict[str, Any]:
    if not event_path or not event_path.exists():
        return {}
    try:
        payload = json.loads(event_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _event_branch(event_data: dict[str, Any]) -> str | None:
    pr = event_data.get("pull_request")
    if isinstance(pr, dict):
        head = pr.get("head")
        if isinstance(head, dict) and head.get("ref"):
            return str(head["ref"])
    return None


def _event_pr_text(event_data: dict[str, Any], key: str) -> str | None:
    pr = event_data.get("pull_request")
    if isinstance(pr, dict) and pr.get(key):
        return str(pr[key])
    return None


def _event_authors(event_data: dict[str, Any]) -> list[str]:
    authors: list[str] = []
    sender = event_data.get("sender")
    if isinstance(sender, dict) and sender.get("login"):
        authors.append(str(sender["login"]))
    pr = event_data.get("pull_request")
    if isinstance(pr, dict):
        user = pr.get("user")
        if isinstance(user, dict) and user.get("login"):
            authors.append(str(user["login"]))
    return authors


def _current_branch(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return None
    branch = result.stdout.strip()
    return branch or None


def _agent_type_from_text(text: str) -> str | None:
    lowered = text.lower()
    for agent_type, markers in KNOWN_AGENT_MARKERS.items():
        if any(marker in lowered for marker in markers):
            return agent_type
    if any(marker in lowered for marker in ("ai-agent", "ai agent", "assistant")):
        return "generic-ai-agent"
    return None


def _matching_fragment(text: str, marker: str) -> str:
    lowered = text.lower()
    index = lowered.find(marker)
    if index == -1:
        return marker
    return text[index : index + len(marker)]


def _display_agent(agent_type: str | None) -> str:
    labels = {
        "github-copilot": "GitHub Copilot",
        "openai-codex": "OpenAI Codex",
        "claude-code": "Claude Code",
        "cursor": "Cursor",
        "generic-ai-agent": "Generic AI Agent",
        "automation-bot": "Automation Bot",
        "unknown": "Unknown",
    }
    return labels.get(agent_type or "", agent_type or "None")


def _escape_table(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
