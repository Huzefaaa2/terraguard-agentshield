from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from terraguard_agentshield.audit import SessionAudit, create_attestation_markdown
from terraguard_agentshield.runtime import RuntimeGuard


@dataclass
class ExecutionResult:
    success: bool
    output: str
    error: str | None = None


class CommandInterceptor:
    def __init__(self, guard: RuntimeGuard, audit: SessionAudit) -> None:
        self.guard = guard
        self.audit = audit

    def execute(self, command: str) -> ExecutionResult:
        decision = self.guard.evaluate_command(command)
        from terraguard_agentshield.audit import AuditAction

        self.audit.add_action(
            AuditAction(
                type="execute_command",
                target=command,
                decision=decision.decision,
                reason=decision.reason,
            )
        )

        if decision.decision == "block":
            return ExecutionResult(
                success=False, output="", error=f"Command blocked: {decision.reason}"
            )

        if decision.decision == "require_approval":
            return ExecutionResult(
                success=False,
                output="",
                error=f"Command requires approval: {decision.reason}",
            )

        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, check=False
            )
            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout,
                error=result.stderr if result.returncode != 0 else None,
            )
        except Exception as exc:
            return ExecutionResult(success=False, output="", error=str(exc))


class GitHubPRAttestationExporter:
    @staticmethod
    def export_comment(audit: SessionAudit) -> str:
        markdown = create_attestation_markdown(audit)
        return markdown

    @staticmethod
    def export_json(audit: SessionAudit) -> str:
        return json.dumps(audit.to_dict(), indent=2)

    @staticmethod
    def save_artifact(audit: SessionAudit, destination: Path) -> Path:
        destination.mkdir(parents=True, exist_ok=True)
        artifact_path = destination / f"agentshield-attestation-{audit.session_id}.json"
        artifact_path.write_text(
            GitHubPRAttestationExporter.export_json(audit), encoding="utf-8"
        )
        return artifact_path


class WebhookExporter:
    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    def export(self, audit: SessionAudit) -> bool:
        try:
            import requests

            response = requests.post(
                self.webhook_url,
                json=audit.to_dict(),
                timeout=10,
            )
            return response.status_code in (200, 201, 204)
        except Exception:
            return False
