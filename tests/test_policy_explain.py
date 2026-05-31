import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.cli import app
from terraguard_agentshield.explain import (
    explain_risk_summary,
    render_explanation_markdown,
)
from terraguard_agentshield.risk import RiskFinding, RiskSummary


runner = CliRunner()


def _summary(category: str, risk: str = "high") -> RiskSummary:
    return RiskSummary(
        findings=[
            RiskFinding(
                risk=risk,
                category=category,
                title=f"{category} finding",
                description="demo",
                file="main.tf",
                line=22,
                evidence='value = "demo"',
                control_family={
                    "secrets": "data-protection",
                    "public-exposure": "network-security",
                    "privilege-expansion": "identity-access",
                    "encryption": "data-protection",
                    "logging": "audit-monitoring",
                }.get(category, "application-security"),
            )
        ]
    )


def test_secrets_explanation() -> None:
    explanation = explain_risk_summary(_summary("secrets"))

    assert "Credential material" in explanation.items[0].why_it_matters
    assert explanation.items[0].reviewer_hint == "Security/data protection approver"


def test_public_exposure_explanation() -> None:
    explanation = explain_risk_summary(_summary("public-exposure", risk="critical"))

    assert explanation.decision == "block"
    assert "Internet-exposed" in explanation.items[0].why_it_matters


def test_privilege_expansion_explanation() -> None:
    explanation = explain_risk_summary(_summary("privilege-expansion", risk="critical"))

    assert "least-privilege" in explanation.items[0].why_it_matters
    assert explanation.items[0].reviewer_hint == "Security/IAM approver"


def test_encryption_explanation() -> None:
    explanation = explain_risk_summary(_summary("encryption"))

    assert "Data protection" in explanation.items[0].why_it_matters


def test_logging_explanation() -> None:
    explanation = explain_risk_summary(_summary("logging", risk="medium"))

    assert "Auditability" in explanation.items[0].why_it_matters
    assert explanation.decision == "warn"


def test_unknown_category_fallback() -> None:
    explanation = explain_risk_summary(_summary("custom-risk", risk="medium"))

    assert "security review" in explanation.items[0].why_it_matters
    assert explanation.items[0].reviewer_hint == "AppSec approver"


def test_markdown_rendering_includes_key_fields() -> None:
    explanation = explain_risk_summary(
        _summary("privilege-expansion", risk="critical"),
        policy_pack="banking-regulated-ai",
    )
    markdown = render_explanation_markdown(explanation)

    assert "AgentShield Policy Explanation" in markdown
    assert "Critical" in markdown
    assert 'value = "demo"' in markdown
    assert "Recommended fix" in markdown


def test_json_output_has_stable_keys() -> None:
    payload = explain_risk_summary(_summary("tls")).to_dict()

    assert set(payload) == {
        "decision",
        "max_risk",
        "policy_pack",
        "fail_on",
        "summary",
        "items",
    }


def test_fail_threshold_affects_decision() -> None:
    explanation = explain_risk_summary(_summary("logging", risk="medium"), fail_on="medium")

    assert explanation.decision == "require_approval"


def test_policy_explain_cli_writes_markdown(tmp_path: Path) -> None:
    risk_file = tmp_path / "risk.json"
    output = tmp_path / "explain.md"
    risk_file.write_text(json.dumps(_summary("secrets").to_dict()), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "policy",
            "explain",
            "--risk",
            str(risk_file),
            "--policy-pack",
            "banking-regulated-ai",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0
    assert "AgentShield Policy Explanation" in output.read_text(encoding="utf-8")
