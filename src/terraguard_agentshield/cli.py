from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.json import JSON

from terraguard_agentshield.agent import AgentSessionManager
from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.evidence import (
    load_audit_for_validation,
    validate_attestation,
    write_validation_result,
)
from terraguard_agentshield.hooks import ClaudeHookProcessor
from terraguard_agentshield.integrations import (
    CommandInterceptor,
    GitHubPRCommentPublisher,
    GitHubPRAttestationExporter,
    WebhookExporter,
)
from terraguard_agentshield.policy_signing import (
    load_policy_file,
    read_signature,
    sign_policy,
    verify_policy_signature,
    write_signature,
)
from terraguard_agentshield.policy_registry import PolicyRegistry
from terraguard_agentshield.runtime import RuntimeGuard

console = Console()
app = typer.Typer(add_completion=False)
agent_app = typer.Typer(help="AI agent runtime commands.")
evidence_app = typer.Typer(help="Evidence export commands.")
hooks_app = typer.Typer(help="AI agent hook adapters.")
policy_app = typer.Typer(help="Policy registry commands.")
app.add_typer(agent_app, name="agent")
app.add_typer(evidence_app, name="evidence")
app.add_typer(hooks_app, name="hooks")
app.add_typer(policy_app, name="policy")


@app.command()
def version() -> None:
    typer.echo("terraguard-agentshield 0.1.0")


@agent_app.command("start")
def start_agent(
    tool: Annotated[str, typer.Option(help="AI tool identifier, e.g. claude-code.")],
    repo: Annotated[Path, typer.Option(help="Path to the repository/workspace.")] = Path("."),
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID to use.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Start an AI agent governance session."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()
    console.print(f"[green]OK[/green] Started session: {session.session_id}")
    console.print(f"[dim]Audit saved at: {session.audit_path}[/dim]")
    console.print(f"[dim]Policy pack: {session.policy_pack or 'ai-agent-baseline'}[/dim]")


@agent_app.command("exec")
def exec_command(
    command: Annotated[str, typer.Argument(help="Command to execute.")],
    tool: Annotated[str, typer.Option(help="AI tool identifier.")] = "claude-code",
    repo: Annotated[Path, typer.Option(help="Repository path.")] = Path("."),
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Execute a command under governance policy."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()

    guard = RuntimeGuard(policy_pack=session.policy_pack or "ai-agent-baseline")
    interceptor = CommandInterceptor(guard, session.audit)
    result = interceptor.execute(command)

    if result.success:
        console.print("[green]OK[/green] Command executed successfully")
        if result.output:
            console.print(result.output)
    else:
        console.print(f"[red]ERROR[/red] {result.error}")
        raise typer.Exit(code=1)

    session.audit.write(output)


@agent_app.command("check-file")
def check_file(
    path: Annotated[Path, typer.Argument(help="File path the AI agent wants to access.")],
    mode: Annotated[str, typer.Option(help="Access mode: read or write.")] = "read",
    tool: Annotated[str, typer.Option(help="AI tool identifier.")] = "claude-code",
    repo: Annotated[Path, typer.Option(help="Repository path.")] = Path("."),
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Evaluate and audit an AI agent file access request."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()
    guard = RuntimeGuard(policy_pack=session.policy_pack)
    decision = guard.evaluate_file_access(path, mode)
    session.audit.add_action(
        AuditAction(
            type=f"{mode.lower()}_file",
            target=str(path),
            decision=decision.decision,
            reason=decision.reason,
        )
    )
    session.audit.write(output)

    console.print(f"[bold]{decision.decision}[/bold]: {decision.reason or 'policy matched'}")
    console.print(f"[dim]Audit saved at: {session.audit_path}[/dim]")
    if decision.decision == "block":
        raise typer.Exit(code=1)
    if decision.decision == "require_approval":
        raise typer.Exit(code=2)


@agent_app.command("check-mcp")
def check_mcp(
    server_id: Annotated[str, typer.Argument(help="MCP server identifier.")],
    capability: Annotated[str | None, typer.Option(help="Requested MCP capability.")] = None,
    tool: Annotated[str, typer.Option(help="AI tool identifier.")] = "claude-code",
    repo: Annotated[Path, typer.Option(help="Repository path.")] = Path("."),
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID.")] = "mcp-server-governance",
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Evaluate and audit an MCP server connection request."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()
    guard = RuntimeGuard(policy_pack=session.policy_pack)
    decision = guard.evaluate_mcp_server(server_id, capability=capability)
    session.audit.add_action(
        AuditAction(
            type="mcp_connect",
            target=server_id,
            decision=decision.decision,
            reason=decision.reason,
            metadata={"capability": capability},
        )
    )
    session.audit.write(output)

    console.print(f"[bold]{decision.decision}[/bold]: {decision.reason or 'policy matched'}")
    console.print(f"[dim]Audit saved at: {session.audit_path}[/dim]")
    if decision.decision == "block":
        raise typer.Exit(code=1)
    if decision.decision == "require_approval":
        raise typer.Exit(code=2)


@agent_app.command("attest")
def generate_attestation(
    session_id: Annotated[str, typer.Argument(help="Session ID.")],
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard"),
    format: Annotated[str, typer.Option(help="Output format: markdown, json, artifact")] = "markdown",
) -> None:
    """Generate PR attestation from audit session."""
    audit_path = audit_dir / f"session-{session_id}.json"
    if not audit_path.exists():
        console.print(f"[red]ERROR[/red] Audit file not found: {audit_path}")
        raise typer.Exit(code=1)

    audit_data = json.loads(audit_path.read_text(encoding="utf-8"))

    if format == "markdown":
        audit = SessionAudit.from_dict(audit_data)
        output = GitHubPRAttestationExporter.export_comment(audit)
        console.print(output)
    elif format == "json":
        console.print(json.dumps(audit_data, indent=2))
    elif format == "artifact":
        audit = SessionAudit.from_dict(audit_data)
        path = GitHubPRAttestationExporter.save_artifact(audit, audit_dir)
        console.print(f"[green]OK[/green] Artifact saved: {path}")
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)


@hooks_app.command("claude")
def claude_hook(
    policy_pack: Annotated[str, typer.Option(help="Policy pack ID.")] = "ai-agent-baseline",
    repo: Annotated[Path, typer.Option(help="Repository path.")] = Path("."),
    audit_dir: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard/audit"),
    tool: Annotated[str, typer.Option(help="Agent tool label for audit evidence.")] = "claude-code",
) -> None:
    """Process a Claude Code hook JSON event from stdin."""
    try:
        payload = json.loads(sys.stdin.read() or "{}")
    except json.JSONDecodeError as exc:
        typer.echo(json.dumps({"error": f"Invalid hook JSON: {exc}"}))
        raise typer.Exit(code=1) from exc

    processor = ClaudeHookProcessor(
        policy_pack=policy_pack,
        repo=repo,
        audit_dir=audit_dir,
        tool=tool,
    )
    decision = processor.process(payload)
    typer.echo(json.dumps(decision.output))


@evidence_app.command("send-webhook")
def send_webhook(
    session_id: Annotated[str, typer.Argument(help="Session ID.")],
    url: Annotated[str, typer.Option(help="Webhook endpoint URL.")],
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    hmac_secret: Annotated[str | None, typer.Option(help="Optional HMAC signing secret.")] = None,
    dry_run: Annotated[bool, typer.Option(help="Print payload without sending.")] = False,
) -> None:
    """Send session evidence to an enterprise webhook/SIEM endpoint."""
    audit_path = audit_dir / f"session-{session_id}.json"
    if not audit_path.exists():
        console.print(f"[red]ERROR[/red] Audit file not found: {audit_path}")
        raise typer.Exit(code=1)

    audit = SessionAudit.read(audit_path)
    if dry_run:
        console.print(json.dumps(audit.to_dict(), indent=2))
        return

    secret = hmac_secret or os.environ.get("TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET")
    exporter = WebhookExporter(url, hmac_secret=secret)
    if exporter.export(audit):
        console.print("[green]OK[/green] Evidence delivered")
        return

    console.print("[red]ERROR[/red] Evidence delivery failed")
    raise typer.Exit(code=1)


@evidence_app.command("validate")
def validate_evidence(
    session_id: Annotated[str | None, typer.Option(help="Session ID. Defaults to latest audit.")] = None,
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    fail_on: Annotated[str, typer.Option(help="Comma-separated decisions that fail validation.")] = "block,require_approval",
    require_policy_pack: Annotated[str | None, typer.Option(help="Required policy pack ID.")] = None,
    require_tool: Annotated[str | None, typer.Option(help="Required AI tool identifier.")] = None,
    min_actions: Annotated[int, typer.Option(help="Minimum expected audited actions.")] = 1,
    output: Annotated[Path | None, typer.Option(help="Optional JSON validation report path.")] = None,
) -> None:
    """Validate AgentShield audit evidence for protected branch checks."""
    try:
        audit = load_audit_for_validation(audit_dir, session_id=session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    result = validate_attestation(
        audit,
        fail_on={item.strip() for item in fail_on.split(",") if item.strip()},
        require_policy_pack=require_policy_pack,
        require_tool=require_tool,
        min_actions=min_actions,
    )

    if output:
        write_validation_result(result, output)

    console.print(json.dumps(result.to_dict(), indent=2))
    if not result.valid:
        raise typer.Exit(code=1)


@evidence_app.command("publish-github-comment")
def publish_github_comment(
    session_id: Annotated[str | None, typer.Option(help="Session ID. Defaults to latest audit.")] = None,
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    repo: Annotated[str | None, typer.Option(help="GitHub repository as owner/name.")] = None,
    pr_number: Annotated[int | None, typer.Option(help="Pull request number.")] = None,
    token: Annotated[str | None, typer.Option(help="GitHub token. Prefer env var in CI.")] = None,
    token_env: Annotated[str, typer.Option(help="Environment variable containing GitHub token.")] = "GITHUB_TOKEN",
    api_url: Annotated[str, typer.Option(help="GitHub API URL.")] = "https://api.github.com",
) -> None:
    """Create or update a GitHub PR comment with AgentShield attestation."""
    try:
        audit = load_audit_for_validation(audit_dir, session_id=session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    github_repo = repo or os.environ.get("GITHUB_REPOSITORY")
    if not github_repo:
        console.print("[red]ERROR[/red] GitHub repository missing. Set --repo or GITHUB_REPOSITORY.")
        raise typer.Exit(code=1)

    github_pr_number = pr_number or _github_event_pr_number()
    if github_pr_number is None:
        console.print("[red]ERROR[/red] Pull request number missing. Set --pr-number or GITHUB_EVENT_PATH.")
        raise typer.Exit(code=1)

    github_token = token or os.environ.get(token_env)
    if not github_token:
        console.print(f"[red]ERROR[/red] GitHub token missing. Set {token_env}.")
        raise typer.Exit(code=1)

    body = GitHubPRAttestationExporter.export_comment(audit)
    publisher = GitHubPRCommentPublisher(github_token, api_url=api_url)
    result = publisher.publish(github_repo, github_pr_number, body)
    if result.success:
        console.print(f"[green]OK[/green] GitHub PR comment {result.action}")
        if result.comment_url:
            console.print(result.comment_url)
        return

    console.print(f"[red]ERROR[/red] GitHub PR comment failed: {result.error}")
    raise typer.Exit(code=1)


@policy_app.command("list")
def list_policies() -> None:
    """List available policy packs."""
    registry = PolicyRegistry()
    packs = registry.list_policy_packs()
    console.print("Available policy packs:")
    for pack in packs:
        console.print(f"  [blue]{pack['id']}[/blue]: {pack['title']}")


@policy_app.command("describe")
def describe_policy(
    pack_id: Annotated[str, typer.Argument(help="Policy pack ID.")]
) -> None:
    """Describe a policy pack."""
    registry = PolicyRegistry()
    pack = registry.get_policy_pack(pack_id)
    console.print(f"[bold]{pack['title']}[/bold]")
    console.print(f"[dim]Version: {pack.get('version', 'N/A')}[/dim]")
    console.print(f"{pack['description']}")
    console.print("")
    if pack.get("policy"):
        console.print("[yellow]Policy rules:[/yellow]")
        console.print(JSON(json.dumps(pack["policy"], indent=2)))


@policy_app.command("sign")
def sign_policy_pack(
    policy_path: Annotated[Path, typer.Argument(help="Path to policy.yaml.")],
    output: Annotated[Path | None, typer.Option(help="Signature output path.")] = None,
    signer: Annotated[str, typer.Option(help="Signer identity for audit metadata.")] = "terraguard-agentshield",
    secret: Annotated[str | None, typer.Option(help="Signing secret. Prefer env var in CI.")] = None,
    secret_env: Annotated[str, typer.Option(help="Environment variable containing signing secret.")] = "TERRAGUARD_AGENTSHIELD_POLICY_SECRET",
) -> None:
    """Create a detached signature for a policy bundle."""
    signing_secret = secret or os.environ.get(secret_env)
    if not signing_secret:
        console.print(f"[red]ERROR[/red] Signing secret missing. Set {secret_env}.")
        raise typer.Exit(code=1)

    policy = load_policy_file(policy_path)
    signature = sign_policy(policy, signing_secret, signer=signer)
    signature_path = output or policy_path.with_suffix(policy_path.suffix + ".sig")
    write_signature(signature, signature_path)
    console.print(f"[green]OK[/green] Policy signature written: {signature_path}")


@policy_app.command("verify")
def verify_policy_pack(
    policy_path: Annotated[Path, typer.Argument(help="Path to policy.yaml.")],
    signature: Annotated[Path | None, typer.Option(help="Signature JSON path.")] = None,
    secret: Annotated[str | None, typer.Option(help="Verification secret. Prefer env var in CI.")] = None,
    secret_env: Annotated[str, typer.Option(help="Environment variable containing verification secret.")] = "TERRAGUARD_AGENTSHIELD_POLICY_SECRET",
) -> None:
    """Verify a detached policy bundle signature."""
    verification_secret = secret or os.environ.get(secret_env)
    if not verification_secret:
        console.print(f"[red]ERROR[/red] Verification secret missing. Set {secret_env}.")
        raise typer.Exit(code=1)

    policy = load_policy_file(policy_path)
    signature_path = signature or policy_path.with_suffix(policy_path.suffix + ".sig")
    policy_signature = read_signature(signature_path)
    valid, reason = verify_policy_signature(policy, policy_signature, verification_secret)
    if valid:
        console.print(f"[green]OK[/green] {reason}")
        return

    console.print(f"[red]ERROR[/red] {reason}")
    raise typer.Exit(code=1)


def main() -> None:
    app()


def _github_event_pr_number() -> int | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    path = Path(event_path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if isinstance(payload.get("pull_request"), dict):
        number = payload["pull_request"].get("number")
        return int(number) if number is not None else None
    number = payload.get("number")
    return int(number) if number is not None else None
