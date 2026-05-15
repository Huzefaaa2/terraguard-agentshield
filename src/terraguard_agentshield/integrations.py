from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.request
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
    def __init__(
        self,
        webhook_url: str,
        hmac_secret: str | None = None,
        timeout: int = 10,
    ) -> None:
        self.webhook_url = webhook_url
        self.hmac_secret = hmac_secret
        self.timeout = timeout

    def export(self, audit: SessionAudit) -> bool:
        try:
            payload = json.dumps(audit.to_dict()).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "terraguard-agentshield",
            }
            if self.hmac_secret:
                signature = hmac.new(
                    self.hmac_secret.encode("utf-8"), payload, hashlib.sha256
                ).hexdigest()
                headers["X-AgentShield-Signature"] = f"sha256={signature}"

            request = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status in (200, 201, 202, 204)
        except (urllib.error.URLError, TimeoutError, OSError):
            return False
