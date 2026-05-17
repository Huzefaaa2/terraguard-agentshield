import json
from pathlib import Path

from typer.testing import CliRunner

from terraguard_agentshield.approval import (
    ApprovalRoutingConfig,
    render_text_routes,
    route_approvals,
)
from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.cli import app
from terraguard_agentshield.summary import summarize_audits


runner = CliRunner()


def test_routes_blocked_infrastructure_to_platform_security(tmp_path: Path) -> None:
    audit = SessionAudit(session_id="approval-001", tool="claude-code", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="execute_command",
            target="terraform apply",
            decision="block",
            metadata={"control_family": "infrastructure-change", "risk": "critical"},
        )
    )
    summary = summarize_audits([audit])

    result = route_approvals(summary).to_dict()

    assert result["route_count"] == 1
    route = result["routes"][0]
    assert route["control_family"] == "infrastructure-change"
    assert route["approver_group"] == "platform-security"
    assert route["priority"] == "critical"
    assert route["approval_required"] is True


def test_routes_risk_findings_to_mapped_approver() -> None:
    summary = {
        "control_families": {
            "network-security": {
                "actions": 0,
                "findings": 1,
                "decisions": {},
                "risks": {"critical": 1},
            }
        }
    }

    result = route_approvals(summary).to_dict()

    assert result["required_route_count"] == 1
    assert result["routes"][0]["approver_group"] == "cloud-security"


def test_routing_config_overrides_approver_group(tmp_path: Path) -> None:
    config_path = tmp_path / "approval-routing.yaml"
    config_path.write_text(
        """
default_group: central-security
approver_groups:
  data-protection: privacy-office
require_approval_for_risks:
  - critical
require_approval_for_decisions:
  - block
""",
        encoding="utf-8",
    )
    config = ApprovalRoutingConfig.from_file(config_path)
    summary = {
        "control_families": {
            "data-protection": {
                "actions": 1,
                "findings": 1,
                "decisions": {"require_approval": 1},
                "risks": {"high": 1},
            }
        }
    }

    result = route_approvals(summary, config=config).to_dict()

    assert result["routes"][0]["approver_group"] == "privacy-office"
    assert result["routes"][0]["approval_required"] is False


def test_approval_route_cli_outputs_json(tmp_path: Path) -> None:
    audit_dir = tmp_path / "audit"
    audit = SessionAudit(session_id="approval-cli", tool="codex", repo=tmp_path)
    audit.add_action(
        AuditAction(
            type="read_file",
            target=".env",
            decision="block",
            metadata={"control_family": "data-protection", "risk": "high"},
        )
    )
    audit.write(audit_dir)
    output = tmp_path / "routes.json"

    result = runner.invoke(
        app,
        [
            "approval",
            "route",
            "--audit-dir",
            str(audit_dir),
            "--bundle-dir",
            str(tmp_path / "missing"),
            "--format",
            "json",
            "--output",
            str(output),
        ],
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result.exit_code == 0
    assert payload["route_count"] == 1
    assert payload["routes"][0]["approver_group"] == "data-protection-office"


def test_render_text_routes() -> None:
    result = route_approvals(
        {
            "control_families": {
                "identity-access": {
                    "actions": 1,
                    "findings": 0,
                    "decisions": {"require_approval": 1},
                    "risks": {},
                }
            }
        }
    )

    text = render_text_routes(result)

    assert "TerraGuard AgentShield Approval Routes" in text
    assert "identity-access -> iam-security" in text
