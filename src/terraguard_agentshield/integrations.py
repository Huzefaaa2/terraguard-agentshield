from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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


@dataclass(frozen=True)
class GitHubCommentResult:
    success: bool
    action: str
    comment_url: str | None = None
    error: str | None = None


class GitHubPRCommentPublisher:
    def __init__(
        self,
        token: str,
        api_url: str = "https://api.github.com",
        marker: str = "<!-- terraguard-agentshield-attestation -->",
    ) -> None:
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.marker = marker

    def publish(self, repo: str, pr_number: int, body: str) -> GitHubCommentResult:
        comment_body = f"{self.marker}\n\n{body}"
        try:
            existing = self._find_existing_comment(repo, pr_number)
            if existing:
                comment_id = existing["id"]
                payload = self._request(
                    "PATCH",
                    f"/repos/{repo}/issues/comments/{comment_id}",
                    {"body": comment_body},
                )
                return GitHubCommentResult(
                    success=True,
                    action="updated",
                    comment_url=payload.get("html_url"),
                )

            payload = self._request(
                "POST",
                f"/repos/{repo}/issues/{pr_number}/comments",
                {"body": comment_body},
            )
            return GitHubCommentResult(
                success=True,
                action="created",
                comment_url=payload.get("html_url"),
            )
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            return GitHubCommentResult(success=False, action="failed", error=str(exc))

    def _find_existing_comment(self, repo: str, pr_number: int) -> dict[str, Any] | None:
        comments = self._request(
            "GET",
            f"/repos/{repo}/issues/{pr_number}/comments?per_page=100",
            None,
        )
        if not isinstance(comments, list):
            return None
        for comment in comments:
            if isinstance(comment, dict) and self.marker in str(comment.get("body", "")):
                return comment
        return None

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
    ) -> Any:
        data = None
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json",
                "User-Agent": "terraguard-agentshield",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response_data = response.read().decode("utf-8")
            if not response_data:
                return {}
            return json.loads(response_data)
