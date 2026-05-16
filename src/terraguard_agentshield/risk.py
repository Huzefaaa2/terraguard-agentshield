from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


RISK_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class RiskFinding:
    risk: str
    category: str
    title: str
    description: str
    file: str
    line: int | None = None
    evidence: str | None = None
    recommendation: str | None = None
    control_family: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk": self.risk,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "control_family": self.control_family,
        }


@dataclass(frozen=True)
class RiskSummary:
    findings: list[RiskFinding] = field(default_factory=list)

    @property
    def max_risk(self) -> str:
        if not self.findings:
            return "low"
        return max(self.findings, key=lambda item: RISK_ORDER[item.risk]).risk

    @property
    def decision(self) -> str:
        if any(finding.risk == "critical" for finding in self.findings):
            return "block"
        if any(finding.risk == "high" for finding in self.findings):
            return "require_approval"
        if any(finding.risk == "medium" for finding in self.findings):
            return "warn"
        return "pass"

    def to_dict(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.risk] = counts.get(finding.risk, 0) + 1
        return {
            "decision": self.decision,
            "max_risk": self.max_risk,
            "finding_count": len(self.findings),
            "risk_counts": counts,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


@dataclass(frozen=True)
class DiffLine:
    file: str
    line: int | None
    marker: str
    content: str


class SemanticRiskClassifier:
    def classify_diff(self, diff_text: str) -> RiskSummary:
        findings: list[RiskFinding] = []
        seen: set[tuple[str, str, int | None, str]] = set()
        for diff_line in _parse_unified_diff(diff_text):
            for finding in self._classify_line(diff_line):
                key = (
                    finding.file,
                    finding.category,
                    finding.line,
                    finding.evidence or "",
                )
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
        return RiskSummary(findings=findings)

    def _classify_line(self, diff_line: DiffLine) -> list[RiskFinding]:
        content = diff_line.content.strip()
        lowered = content.lower()
        file_path = diff_line.file.lower()
        findings: list[RiskFinding] = []

        if not content or diff_line.marker not in {"+", "-"}:
            return findings

        if diff_line.marker == "+":
            findings.extend(self._classify_added_line(diff_line, lowered, file_path))
        else:
            findings.extend(self._classify_removed_line(diff_line, lowered, file_path))

        if _is_sensitive_source_path(file_path) and diff_line.marker == "+":
            findings.extend(self._classify_sensitive_source_line(diff_line, lowered))

        return findings

    def _classify_added_line(
        self, diff_line: DiffLine, lowered: str, file_path: str
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        if _looks_like_secret_assignment(lowered) or _is_secret_file(file_path):
            findings.append(
                _finding(
                    "high",
                    "secrets",
                    "Potential secret introduced",
                    "The diff appears to add a credential, token, key, or secret-bearing file.",
                    diff_line,
                    "Move secrets to an approved secret manager and keep them out of agent context.",
                    "data-protection",
                )
            )

        if _contains_public_network_exposure(lowered):
            findings.append(
                _finding(
                    "critical",
                    "public-exposure",
                    "Public network exposure",
                    "The diff appears to allow inbound access from the public internet.",
                    diff_line,
                    "Restrict source ranges to approved private CIDRs or require explicit security approval.",
                    "network-security",
                )
            )

        if _contains_privilege_expansion(lowered):
            findings.append(
                _finding(
                    "critical",
                    "privilege-expansion",
                    "Broad IAM or admin privilege introduced",
                    "The diff appears to grant wildcard or administrative permissions.",
                    diff_line,
                    "Replace wildcard/admin access with least-privilege permissions and independent review.",
                    "identity-access",
                )
            )

        if _weakens_encryption(lowered):
            findings.append(
                _finding(
                    "high",
                    "encryption",
                    "Encryption control weakened",
                    "The diff appears to disable or weaken encryption.",
                    diff_line,
                    "Keep encryption enabled and use approved KMS or platform-managed keys.",
                    "data-protection",
                )
            )

        if _weakens_logging(lowered):
            findings.append(
                _finding(
                    "medium",
                    "logging",
                    "Logging or audit control weakened",
                    "The diff appears to disable logging, audit, or monitoring.",
                    diff_line,
                    "Keep audit logging enabled or document compensating controls.",
                    "audit-monitoring",
                )
            )

        return findings

    def _classify_removed_line(
        self, diff_line: DiffLine, lowered: str, file_path: str
    ) -> list[RiskFinding]:
        del file_path
        findings: list[RiskFinding] = []

        if _removes_encryption_control(lowered):
            findings.append(
                _finding(
                    "high",
                    "encryption",
                    "Encryption configuration removed",
                    "The diff appears to remove an encryption or KMS control.",
                    diff_line,
                    "Confirm encryption remains enforced by another approved control.",
                    "data-protection",
                )
            )

        if _removes_logging_control(lowered):
            findings.append(
                _finding(
                    "medium",
                    "logging",
                    "Logging or audit configuration removed",
                    "The diff appears to remove logging, audit, or monitoring configuration.",
                    diff_line,
                    "Confirm audit coverage remains intact before approval.",
                    "audit-monitoring",
                )
            )

        return findings

    def _classify_sensitive_source_line(
        self, diff_line: DiffLine, lowered: str
    ) -> list[RiskFinding]:
        findings: list[RiskFinding] = []

        if any(token in lowered for token in ("verify=false", "verify = false")):
            findings.append(
                _finding(
                    "high",
                    "tls",
                    "TLS verification disabled",
                    "The diff appears to disable certificate verification.",
                    diff_line,
                    "Keep TLS verification enabled and use trusted certificates.",
                    "application-security",
                )
            )

        if re.search(r"\b(md5|sha1)\s*\(", lowered):
            findings.append(
                _finding(
                    "high",
                    "crypto",
                    "Weak hash algorithm introduced",
                    "The diff appears to introduce MD5 or SHA1 in sensitive code.",
                    diff_line,
                    "Use approved modern cryptographic primitives.",
                    "application-security",
                )
            )

        if any(token in lowered for token in ("auth", "jwt", "oauth", "payment")):
            findings.append(
                _finding(
                    "medium",
                    "sensitive-code",
                    "Sensitive application area changed",
                    "The diff modifies authentication, identity, token, or payment-related code.",
                    diff_line,
                    "Require an independent reviewer familiar with this control area.",
                    "application-security",
                )
            )

        return findings


def should_fail_for_risk(summary: RiskSummary, fail_on: str) -> bool:
    threshold = RISK_ORDER.get(fail_on.lower())
    if threshold is None:
        raise ValueError(f"Unknown risk threshold: {fail_on}")
    return RISK_ORDER[summary.max_risk] >= threshold


def render_text_summary(summary: RiskSummary) -> str:
    lines = [
        f"Decision: {summary.decision}",
        f"Max risk: {summary.max_risk}",
        f"Findings: {len(summary.findings)}",
    ]
    for finding in summary.findings:
        location = finding.file
        if finding.line is not None:
            location = f"{location}:{finding.line}"
        lines.append("")
        lines.append(f"- [{finding.risk}] {finding.title} ({location})")
        lines.append(f"  Category: {finding.category}")
        lines.append(f"  Detail: {finding.description}")
        if finding.recommendation:
            lines.append(f"  Recommendation: {finding.recommendation}")
        if finding.evidence:
            lines.append(f"  Evidence: {finding.evidence}")
    return "\n".join(lines)


def _parse_unified_diff(diff_text: str) -> list[DiffLine]:
    lines: list[DiffLine] = []
    current_file = "unknown"
    new_line: int | None = None
    old_line: int | None = None

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("+++ "):
            current_file = raw_line[4:].strip()
            if current_file.startswith("b/"):
                current_file = current_file[2:]
            continue
        if raw_line.startswith("@@"):
            old_line, new_line = _parse_hunk_header(raw_line)
            continue
        if not raw_line:
            continue

        marker = raw_line[0]
        if marker not in {" ", "+", "-"}:
            continue
        if raw_line.startswith("+++") or raw_line.startswith("---"):
            continue

        if marker == "+":
            lines.append(DiffLine(current_file, new_line, marker, raw_line[1:]))
            new_line = new_line + 1 if new_line is not None else None
        elif marker == "-":
            lines.append(DiffLine(current_file, old_line, marker, raw_line[1:]))
            old_line = old_line + 1 if old_line is not None else None
        else:
            new_line = new_line + 1 if new_line is not None else None
            old_line = old_line + 1 if old_line is not None else None

    return lines


def _parse_hunk_header(header: str) -> tuple[int | None, int | None]:
    match = re.search(r"@@ -(?P<old>\d+)(?:,\d+)? \+(?P<new>\d+)(?:,\d+)? @@", header)
    if not match:
        return None, None
    return int(match.group("old")), int(match.group("new"))


def _finding(
    risk: str,
    category: str,
    title: str,
    description: str,
    diff_line: DiffLine,
    recommendation: str,
    control_family: str,
) -> RiskFinding:
    return RiskFinding(
        risk=risk,
        category=category,
        title=title,
        description=description,
        file=diff_line.file,
        line=diff_line.line,
        evidence=diff_line.content.strip(),
        recommendation=recommendation,
        control_family=control_family,
    )


def _looks_like_secret_assignment(lowered: str) -> bool:
    return bool(
        re.search(
            r"(password|passwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|token)\s*[:=]",
            lowered,
        )
    )


def _is_secret_file(file_path: str) -> bool:
    return any(
        pattern in file_path
        for pattern in (".env", ".tfvars", "terraform.tfstate", ".pem", ".pfx", "id_rsa")
    )


def _contains_public_network_exposure(lowered: str) -> bool:
    public_sources = (
        "0.0.0.0/0",
        "::/0",
        'source_address_prefix = "*"',
        'source_ranges = ["0.0.0.0/0"]',
    )
    exposure_terms = (
        "cidr_blocks",
        "ipv6_cidr_blocks",
        "source_ranges",
        "source_address_prefix",
        "ingress",
        "from_port",
        "to_port",
    )
    return any(source in lowered for source in public_sources) and any(
        term in lowered for term in exposure_terms
    )


def _contains_privilege_expansion(lowered: str) -> bool:
    patterns = (
        r'"action"\s*:\s*"\*"',
        r"action\s*=\s*\"\*\"",
        r"actions\s*=\s*\[\"\\*\"\]",
        r"iam:\*",
        r"administratoraccess",
        r"owner\"",
        r"role_definition_name\s*=\s*\"owner\"",
    )
    return any(re.search(pattern, lowered) for pattern in patterns)


def _weakens_encryption(lowered: str) -> bool:
    return any(
        token in lowered
        for token in (
            "encrypt = false",
            "encryption_enabled = false",
            "enable_encryption = false",
            "server_side_encryption = false",
            "disable_encryption = true",
        )
    )


def _weakens_logging(lowered: str) -> bool:
    return any(
        token in lowered
        for token in (
            "logging = false",
            "logging_enabled = false",
            "audit_enabled = false",
            "enable_logging = false",
            "disable_logging = true",
        )
    )


def _removes_encryption_control(lowered: str) -> bool:
    return any(
        token in lowered
        for token in (
            "kms_key_id",
            "server_side_encryption",
            "customer_managed_key",
            "encryption_key",
            "encrypt = true",
        )
    )


def _removes_logging_control(lowered: str) -> bool:
    return any(
        token in lowered
        for token in (
            "cloudtrail",
            "diagnostic_setting",
            "audit_log",
            "logging_enabled = true",
            "enable_logging = true",
        )
    )


def _is_sensitive_source_path(file_path: str) -> bool:
    return any(
        segment in file_path
        for segment in (
            "auth",
            "oauth",
            "jwt",
            "crypto",
            "encrypt",
            "payment",
            "identity",
            "security",
        )
    )
