from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.json import JSON

from terraguard_agentshield.approval import (
    ApprovalRoutingConfig,
    render_text_routes,
    route_approvals,
)
from terraguard_agentshield.agent import AgentSessionManager
from terraguard_agentshield.agent_detector import (
    detect_ai_agent_change,
    render_detection_markdown,
    render_detection_text,
)
from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.compliance import (
    list_compliance_mappings,
    map_summary_to_compliance,
    render_text_mappings,
)
from terraguard_agentshield.evidence import (
    create_evidence_bundle,
    load_audit_for_validation,
    read_evidence_bundle,
    validate_attestation,
    verify_evidence_bundle,
    write_validation_result,
)
from terraguard_agentshield.hooks import ClaudeHookProcessor
from terraguard_agentshield.integrations import (
    CommandInterceptor,
    GitHubPRCommentPublisher,
    GitHubPRAttestationExporter,
    JiraEvidencePublisher,
    ServiceNowEvidencePublisher,
    WebhookExporter,
)
from terraguard_agentshield.policy_signing import (
    ED25519_SIGNATURE_ALGORITHM,
    HMAC_SIGNATURE_ALGORITHM,
    generate_ed25519_key_pair,
    load_policy_file,
    read_signature,
    sign_policy,
    sign_policy_asymmetric,
    verify_policy_signature,
    verify_policy_signature_asymmetric,
    write_signature,
)
from terraguard_agentshield.policy_testing import (
    render_text_result as render_policy_test_result,
    run_policy_test_file,
)
from terraguard_agentshield.policy_registry import PolicyRegistry
from terraguard_agentshield.risk import (
    SemanticRiskClassifier,
    render_text_summary,
    should_fail_for_risk,
)
from terraguard_agentshield.explain import (
    explain_from_file,
    render_explanation_markdown,
    render_explanation_text,
)
from terraguard_agentshield.pr_guardian import PRGuardianConfig, run_pr_guardian
from terraguard_agentshield.reports import (
    create_governance_report,
    read_optional_json as read_optional_report_json,
    render_markdown_report,
)
from terraguard_agentshield.runtime import RuntimeGuard
from terraguard_agentshield.summary import (
    render_text_summary as render_decision_summary,
)
from terraguard_agentshield.summary import summarize_evidence

console = Console()
app = typer.Typer(add_completion=False)
agent_app = typer.Typer(help="AI agent runtime commands.")
api_app = typer.Typer(help="Enterprise HTTP API commands.")
approval_app = typer.Typer(help="Approval routing commands.")
compliance_app = typer.Typer(help="Compliance mapping commands.")
evidence_app = typer.Typer(help="Evidence export commands.")
hooks_app = typer.Typer(help="AI agent hook adapters.")
policy_app = typer.Typer(help="Policy registry commands.")
pr_app = typer.Typer(help="Pull request governance commands.")
report_app = typer.Typer(help="Generated report commands.")
risk_app = typer.Typer(help="Semantic risk classification commands.")
app.add_typer(agent_app, name="agent")
app.add_typer(api_app, name="api")
app.add_typer(approval_app, name="approval")
app.add_typer(compliance_app, name="compliance")
app.add_typer(evidence_app, name="evidence")
app.add_typer(hooks_app, name="hooks")
app.add_typer(policy_app, name="policy")
app.add_typer(pr_app, name="pr")
app.add_typer(report_app, name="report")
app.add_typer(risk_app, name="risk")


@app.command()
def version() -> None:
    typer.echo("terraguard-agentshield 0.1.0")


@api_app.command("serve")
def serve_api(
    host: Annotated[str, typer.Option(help="API host/interface.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="API port.")] = 8000,
    data_dir: Annotated[
        Path,
        typer.Option(help="AgentShield data directory for evidence inspection."),
    ] = Path(".terraguard/agentshield"),
    reload: Annotated[bool, typer.Option(help="Enable uvicorn reload for development.")] = False,
) -> None:
    """Run the enterprise policy, evidence, and risk inspection API."""
    os.environ["TERRAGUARD_AGENTSHIELD_DATA_DIR"] = str(data_dir)
    import uvicorn

    uvicorn.run(
        "terraguard_agentshield.api:app",
        host=host,
        port=port,
        reload=reload,
    )


@approval_app.command("route")
def route_approval(
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="Audit directory containing session-*.json files."),
    ] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path | None,
        typer.Option(help="Evidence bundle directory containing *.json files."),
    ] = Path(".terraguard/agentshield/evidence"),
    routing_config: Annotated[
        Path | None,
        typer.Option(help="Optional YAML file overriding approver groups."),
    ] = None,
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """Route summarized AgentShield evidence to the right approver groups."""
    config = (
        ApprovalRoutingConfig.from_file(routing_config)
        if routing_config
        else ApprovalRoutingConfig()
    )
    summary = summarize_evidence(audit_dir=audit_dir, bundle_dir=bundle_dir)
    result = route_approvals(summary, config=config)
    payload = result.to_json()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    if format == "json":
        console.print(payload)
    elif format == "text":
        console.print(render_text_routes(result))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)


@compliance_app.command("list")
def list_compliance(
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """List AgentShield control-family compliance mappings."""
    result = list_compliance_mappings()
    payload = result.to_json()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    if format == "json":
        console.print(payload)
    elif format == "text":
        console.print(render_text_mappings(result))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)


@compliance_app.command("map")
def map_compliance(
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="Audit directory containing session-*.json files."),
    ] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path | None,
        typer.Option(help="Evidence bundle directory containing *.json files."),
    ] = Path(".terraguard/agentshield/evidence"),
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """Map AgentShield evidence summary to compliance framework references."""
    summary = summarize_evidence(audit_dir=audit_dir, bundle_dir=bundle_dir)
    result = map_summary_to_compliance(summary)
    payload = result.to_json()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    if format == "json":
        console.print(payload)
    elif format == "text":
        console.print(render_text_mappings(result))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)


@report_app.command("generate")
def generate_report(
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="Audit directory containing session-*.json files."),
    ] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path | None,
        typer.Option(help="Evidence bundle directory containing *.json files."),
    ] = Path(".terraguard/agentshield/evidence"),
    validation: Annotated[
        Path | None,
        typer.Option(help="Optional validation JSON from evidence validate."),
    ] = None,
    format: Annotated[str, typer.Option(help="Output format: markdown or json.")] = "markdown",
    output: Annotated[Path | None, typer.Option(help="Optional report output path.")] = None,
    metadata: Annotated[
        list[str] | None,
        typer.Option(help="Additional report metadata as key=value."),
    ] = None,
) -> None:
    """Generate one reviewer-friendly AgentShield governance report."""
    try:
        report = create_governance_report(
            audit_dir=audit_dir,
            bundle_dir=bundle_dir,
            validation=read_optional_report_json(validation),
            metadata=_parse_metadata(metadata or []),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if format == "json":
        content = report.to_json()
    elif format == "markdown":
        content = render_markdown_report(report)
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
    console.print(content)


@report_app.command("publish-github-comment")
def publish_github_report(
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="Audit directory containing session-*.json files."),
    ] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path | None,
        typer.Option(help="Evidence bundle directory containing *.json files."),
    ] = Path(".terraguard/agentshield/evidence"),
    validation: Annotated[
        Path | None,
        typer.Option(help="Optional validation JSON from evidence validate."),
    ] = None,
    repo: Annotated[str | None, typer.Option(help="GitHub repository as owner/name.")] = None,
    pr_number: Annotated[int | None, typer.Option(help="Pull request number.")] = None,
    token: Annotated[str | None, typer.Option(help="GitHub token. Prefer env var in CI.")] = None,
    token_env: Annotated[str, typer.Option(help="Environment variable containing GitHub token.")] = "GITHUB_TOKEN",
    api_url: Annotated[str, typer.Option(help="GitHub API URL.")] = "https://api.github.com",
) -> None:
    """Publish the generated AgentShield governance report to a GitHub PR."""
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

    try:
        report = create_governance_report(
            audit_dir=audit_dir,
            bundle_dir=bundle_dir,
            validation=read_optional_report_json(validation),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    body = render_markdown_report(report)
    publisher = GitHubPRCommentPublisher(
        github_token,
        api_url=api_url,
        marker="<!-- terraguard-agentshield-governance-report -->",
    )
    result = publisher.publish(github_repo, github_pr_number, body)
    if result.success:
        console.print(f"[green]OK[/green] GitHub PR governance report {result.action}")
        if result.comment_url:
            console.print(result.comment_url)
        return

    console.print(f"[red]ERROR[/red] GitHub PR report failed: {result.error}")
    raise typer.Exit(code=1)


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
    enterprise_policy: Annotated[str | None, typer.Option(help="Enterprise policy layer.")] = None,
    business_unit_policy: Annotated[str | None, typer.Option(help="Business unit policy layer.")] = None,
    repository_policy: Annotated[str | None, typer.Option(help="Repository policy layer.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Execute a command under governance policy."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()

    guard = RuntimeGuard(
        policy_pack=policy_pack,
        enterprise_policy=enterprise_policy,
        business_unit_policy=business_unit_policy,
        repository_policy=repository_policy,
    )
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
    enterprise_policy: Annotated[str | None, typer.Option(help="Enterprise policy layer.")] = None,
    business_unit_policy: Annotated[str | None, typer.Option(help="Business unit policy layer.")] = None,
    repository_policy: Annotated[str | None, typer.Option(help="Repository policy layer.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Evaluate and audit an AI agent file access request."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()
    guard = RuntimeGuard(
        policy_pack=policy_pack,
        enterprise_policy=enterprise_policy,
        business_unit_policy=business_unit_policy,
        repository_policy=repository_policy,
    )
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
    enterprise_policy: Annotated[str | None, typer.Option(help="Enterprise policy layer.")] = None,
    business_unit_policy: Annotated[str | None, typer.Option(help="Business unit policy layer.")] = None,
    repository_policy: Annotated[str | None, typer.Option(help="Repository policy layer.")] = None,
    output: Annotated[Path, typer.Option(help="Audit output directory.")] = Path(".terraguard"),
) -> None:
    """Evaluate and audit an MCP server connection request."""
    manager = AgentSessionManager(
        repo=repo, tool=tool, policy_pack=policy_pack, output_dir=output
    )
    session = manager.start_session()
    guard = RuntimeGuard(
        policy_pack=policy_pack,
        enterprise_policy=enterprise_policy,
        business_unit_policy=business_unit_policy,
        repository_policy=repository_policy,
    )
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


@agent_app.command("detect")
def detect_agent(
    repo: Annotated[Path, typer.Option(help="Repository path.")] = Path("."),
    branch: Annotated[str | None, typer.Option(help="Pull request branch name.")] = None,
    pr_title: Annotated[str | None, typer.Option(help="Pull request title.")] = None,
    pr_body_file: Annotated[
        Path | None,
        typer.Option(help="Optional file containing pull request body text."),
    ] = None,
    event_path: Annotated[
        Path | None,
        typer.Option(help="GitHub event JSON path. Defaults to GITHUB_EVENT_PATH."),
    ] = None,
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="AgentShield audit directory to scan for tool metadata."),
    ] = None,
    format: Annotated[str, typer.Option(help="Output format: text, json, or markdown.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional output path.")] = None,
) -> None:
    """Detect likely AI coding-agent involvement from PR and audit signals."""
    try:
        pr_body = pr_body_file.read_text(encoding="utf-8") if pr_body_file else None
        result = detect_ai_agent_change(
            repo=repo,
            branch=branch,
            pr_title=pr_title,
            pr_body=pr_body,
            event_path=event_path or _github_event_path(),
            audit_dir=audit_dir,
        )
    except OSError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if format == "json":
        content = result.to_json()
    elif format == "markdown":
        content = render_detection_markdown(result)
    elif format == "text":
        content = render_detection_text(result)
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
    console.print(content)


@hooks_app.command("claude")
def claude_hook(
    policy_pack: Annotated[str, typer.Option(help="Policy pack ID.")] = "ai-agent-baseline",
    enterprise_policy: Annotated[str | None, typer.Option(help="Enterprise policy layer.")] = None,
    business_unit_policy: Annotated[str | None, typer.Option(help="Business unit policy layer.")] = None,
    repository_policy: Annotated[str | None, typer.Option(help="Repository policy layer.")] = None,
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
        enterprise_policy=enterprise_policy,
        business_unit_policy=business_unit_policy,
        repository_policy=repository_policy,
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
    timeout: Annotated[int, typer.Option(help="HTTP timeout in seconds.")] = 10,
    retries: Annotated[int, typer.Option(help="Retry count after the first attempt.")] = 2,
    backoff_seconds: Annotated[float, typer.Option(help="Linear backoff seconds between retries.")] = 1.0,
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
    exporter = WebhookExporter(
        url,
        hmac_secret=secret,
        timeout=timeout,
        retries=retries,
        backoff_seconds=backoff_seconds,
    )
    result = exporter.deliver(audit)
    if result.success:
        console.print(f"[green]OK[/green] Evidence delivered in {result.attempts} attempt(s)")
        return

    console.print(
        f"[red]ERROR[/red] Evidence delivery failed after {result.attempts} attempt(s): {result.error}"
    )
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


@evidence_app.command("bundle")
def create_bundle(
    session_id: Annotated[str | None, typer.Option(help="Session ID. Defaults to latest audit.")] = None,
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    private_key: Annotated[Path, typer.Option(help="Ed25519 private key PEM for bundle signing.")] = Path("agentshield-evidence-private.pem"),
    output: Annotated[Path | None, typer.Option(help="Evidence bundle JSON output path.")] = None,
    signer: Annotated[str, typer.Option(help="Signer identity for evidence metadata.")] = "terraguard-agentshield",
    risk: Annotated[Path | None, typer.Option(help="Optional risk JSON file from risk diff.")] = None,
    policy_signature: Annotated[Path | None, typer.Option(help="Optional policy signature JSON file.")] = None,
    validation: Annotated[Path | None, typer.Option(help="Optional attestation validation JSON file.")] = None,
    metadata: Annotated[list[str] | None, typer.Option(help="Additional metadata as key=value.")] = None,
) -> None:
    """Create and sign an immutable-style AgentShield evidence bundle."""
    try:
        audit = load_audit_for_validation(audit_dir, session_id=session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    bundle = create_evidence_bundle(
        audit,
        private_key.read_bytes(),
        signer=signer,
        risk=_read_optional_json(risk),
        policy_signature=_read_optional_json(policy_signature),
        validation=_read_optional_json(validation),
        metadata=_parse_metadata(metadata or []),
    )
    bundle_path = output or audit_dir / f"evidence-{bundle.bundle_id}.json"
    bundle.write(bundle_path)
    console.print(f"[green]OK[/green] Evidence bundle written: {bundle_path}")


@evidence_app.command("verify-bundle")
def verify_bundle(
    bundle_path: Annotated[Path, typer.Argument(help="Evidence bundle JSON path.")],
    public_key: Annotated[Path, typer.Option(help="Ed25519 public key PEM for verification.")],
    output: Annotated[Path | None, typer.Option(help="Optional verification JSON output path.")] = None,
) -> None:
    """Verify a signed AgentShield evidence bundle."""
    bundle = read_evidence_bundle(bundle_path)
    result = verify_evidence_bundle(bundle, public_key.read_bytes())
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")

    console.print(json.dumps(result.to_dict(), indent=2))
    if not result.valid:
        raise typer.Exit(code=1)


@evidence_app.command("summary")
def summarize_decisions(
    audit_dir: Annotated[
        Path | None,
        typer.Option(help="Audit directory containing session-*.json files."),
    ] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path | None,
        typer.Option(help="Evidence bundle directory containing *.json files."),
    ] = Path(".terraguard/agentshield/evidence"),
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """Summarize decisions, risks, and control families from audits and bundles."""
    summary = summarize_evidence(audit_dir=audit_dir, bundle_dir=bundle_dir)
    payload = summary.to_json()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    if format == "json":
        console.print(payload)
    elif format == "text":
        console.print(render_decision_summary(summary))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
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


@evidence_app.command("publish-jira")
def publish_jira(
    issue_key: Annotated[str, typer.Argument(help="Jira issue key, e.g. SEC-123.")],
    session_id: Annotated[str | None, typer.Option(help="Session ID. Defaults to latest audit.")] = None,
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    base_url: Annotated[str | None, typer.Option(help="Jira base URL, e.g. https://org.atlassian.net.")] = None,
    email: Annotated[str | None, typer.Option(help="Jira account email for API token auth.")] = None,
    api_token: Annotated[str | None, typer.Option(help="Jira API token. Prefer env var in CI.")] = None,
    bearer_token: Annotated[str | None, typer.Option(help="Optional Jira bearer token.")] = None,
    timeout: Annotated[int, typer.Option(help="HTTP timeout in seconds.")] = 10,
) -> None:
    """Publish AgentShield evidence as a Jira issue comment."""
    try:
        audit = load_audit_for_validation(audit_dir, session_id=session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    jira_base_url = base_url or os.environ.get("JIRA_BASE_URL")
    if not jira_base_url:
        console.print("[red]ERROR[/red] Jira base URL missing. Set --base-url or JIRA_BASE_URL.")
        raise typer.Exit(code=1)

    publisher = JiraEvidencePublisher(
        jira_base_url,
        email=email or os.environ.get("JIRA_EMAIL"),
        api_token=api_token or os.environ.get("JIRA_API_TOKEN"),
        bearer_token=bearer_token or os.environ.get("JIRA_BEARER_TOKEN"),
        timeout=timeout,
    )
    result = publisher.publish_comment(issue_key, audit)
    if result.success:
        console.print(f"[green]OK[/green] Jira evidence published to {result.target}")
        if result.url:
            console.print(result.url)
        return

    console.print(f"[red]ERROR[/red] Jira evidence publish failed: {result.error}")
    raise typer.Exit(code=1)


@evidence_app.command("publish-servicenow")
def publish_servicenow(
    sys_id: Annotated[str, typer.Argument(help="ServiceNow record sys_id.")],
    session_id: Annotated[str | None, typer.Option(help="Session ID. Defaults to latest audit.")] = None,
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    instance_url: Annotated[str | None, typer.Option(help="ServiceNow instance URL.")] = None,
    table: Annotated[str, typer.Option(help="ServiceNow table name.")] = "change_request",
    field: Annotated[str, typer.Option(help="Field to update with evidence.")] = "work_notes",
    username: Annotated[str | None, typer.Option(help="ServiceNow username for basic auth.")] = None,
    password: Annotated[str | None, typer.Option(help="ServiceNow password. Prefer env var in CI.")] = None,
    bearer_token: Annotated[str | None, typer.Option(help="Optional ServiceNow bearer token.")] = None,
    timeout: Annotated[int, typer.Option(help="HTTP timeout in seconds.")] = 10,
) -> None:
    """Publish AgentShield evidence to a ServiceNow record work note."""
    try:
        audit = load_audit_for_validation(audit_dir, session_id=session_id)
    except FileNotFoundError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    snow_instance_url = instance_url or os.environ.get("SERVICENOW_INSTANCE_URL")
    if not snow_instance_url:
        console.print(
            "[red]ERROR[/red] ServiceNow instance URL missing. "
            "Set --instance-url or SERVICENOW_INSTANCE_URL."
        )
        raise typer.Exit(code=1)

    publisher = ServiceNowEvidencePublisher(
        snow_instance_url,
        username=username or os.environ.get("SERVICENOW_USERNAME"),
        password=password or os.environ.get("SERVICENOW_PASSWORD"),
        bearer_token=bearer_token or os.environ.get("SERVICENOW_BEARER_TOKEN"),
        timeout=timeout,
    )
    result = publisher.publish_work_note(table, sys_id, audit, field=field)
    if result.success:
        console.print(
            f"[green]OK[/green] ServiceNow evidence published to {result.target}"
        )
        if result.url:
            console.print(result.url)
        return

    console.print(f"[red]ERROR[/red] ServiceNow evidence publish failed: {result.error}")
    raise typer.Exit(code=1)


@risk_app.command("diff")
def classify_diff(
    diff_path: Annotated[
        Path | None,
        typer.Argument(help="Unified diff file. Reads stdin when omitted."),
    ] = None,
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Fail when max risk is at or above: low, medium, high, critical."),
    ] = None,
) -> None:
    """Classify semantic risk in a source or IaC unified diff."""
    if diff_path:
        diff_text = diff_path.read_text(encoding="utf-8")
    else:
        diff_text = sys.stdin.read()

    summary = SemanticRiskClassifier().classify_diff(diff_text)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(summary.to_json() + "\n", encoding="utf-8")

    if format == "json":
        console.print(summary.to_json())
    elif format == "text":
        console.print(render_text_summary(summary))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)

    if fail_on:
        try:
            should_fail = should_fail_for_risk(summary, fail_on)
        except ValueError as exc:
            console.print(f"[red]ERROR[/red] {exc}")
            raise typer.Exit(code=1) from exc
        if should_fail:
            raise typer.Exit(code=1)


@pr_app.command("guard")
def guard_pr(
    diff: Annotated[Path, typer.Option("--diff", help="Unified pull request diff path.")],
    repo: Annotated[
        str | None,
        typer.Option(help="GitHub repository as owner/name. Defaults to GITHUB_REPOSITORY."),
    ] = None,
    pr_number: Annotated[
        int | None,
        typer.Option(help="Pull request number. Defaults from GITHUB_EVENT_PATH."),
    ] = None,
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID.")] = None,
    fail_on: Annotated[
        str,
        typer.Option(help="Fail when max risk is at or above: low, medium, high, critical."),
    ] = "high",
    audit_dir: Annotated[Path, typer.Option(help="Audit directory.")] = Path(".terraguard/audit"),
    bundle_dir: Annotated[
        Path,
        typer.Option(help="Evidence bundle directory."),
    ] = Path(".terraguard/agentshield/evidence"),
    output_dir: Annotated[
        Path,
        typer.Option(help="PR Guardian output artifact directory."),
    ] = Path(".terraguard/agentshield/pr-guardian"),
    publish_comment: Annotated[
        bool,
        typer.Option("--publish-comment/--no-publish-comment", help="Publish GitHub PR comment."),
    ] = False,
    github_token_env: Annotated[
        str,
        typer.Option(help="Environment variable containing GitHub token."),
    ] = "GITHUB_TOKEN",
    github_api_url: Annotated[str, typer.Option(help="GitHub API URL.")] = "https://api.github.com",
    dry_run: Annotated[bool, typer.Option(help="Render artifacts without calling GitHub.")] = False,
    format: Annotated[str, typer.Option(help="Output format: text, json, or markdown.")] = "markdown",
) -> None:
    """Run AgentShield PR Guardian against a pull request diff."""
    try:
        result = run_pr_guardian(
            PRGuardianConfig(
                diff_path=diff,
                repo=repo or os.environ.get("GITHUB_REPOSITORY"),
                pr_number=pr_number or _github_event_pr_number(),
                policy_pack=policy_pack,
                fail_on=fail_on,
                audit_dir=audit_dir,
                bundle_dir=bundle_dir,
                output_dir=output_dir,
                publish_comment=publish_comment,
                github_token=os.environ.get(github_token_env),
                github_api_url=github_api_url,
                dry_run=dry_run,
                event_path=_github_event_path(),
            )
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2) from exc
    except RuntimeError as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if format == "json":
        console.print(result.to_json())
    elif format == "markdown":
        console.print(result.markdown_report)
    elif format == "text":
        console.print(
            "\n".join(
                [
                    f"Decision: {result.decision}",
                    f"Max risk: {result.max_risk}",
                    f"Should fail: {result.should_fail}",
                    f"AI agent detected: {result.ai_agent_detected}",
                    f"Artifacts: {result.markdown_report_path}",
                ]
            )
        )
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=2)

    if result.should_fail:
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


@policy_app.command("resolve")
def resolve_policy(
    enterprise: Annotated[str | None, typer.Option(help="Enterprise policy pack ID.")] = None,
    business_unit: Annotated[str | None, typer.Option(help="Business unit policy pack ID.")] = None,
    repository: Annotated[str | None, typer.Option(help="Repository policy pack ID.")] = None,
    policy_pack: Annotated[str | None, typer.Option(help="Final/default policy pack ID.")] = None,
    output: Annotated[Path | None, typer.Option(help="Optional resolved policy JSON output path.")] = None,
) -> None:
    """Resolve inherited policy layers into one effective policy."""
    registry = PolicyRegistry()
    policy = registry.resolve_policy(
        enterprise=enterprise,
        business_unit=business_unit,
        repository=repository,
        policy_pack=policy_pack,
    )
    payload = json.dumps(policy, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    console.print(JSON(payload))


@policy_app.command("test")
def test_policy(
    suite: Annotated[Path, typer.Argument(help="Policy test suite YAML path.")],
    policy_root: Annotated[
        Path | None,
        typer.Option(help="Optional policy root containing policy pack directories."),
    ] = None,
    format: Annotated[str, typer.Option(help="Output format: text or json.")] = "text",
    output: Annotated[Path | None, typer.Option(help="Optional JSON output path.")] = None,
) -> None:
    """Run policy behavior tests against a policy pack."""
    try:
        result = run_policy_test_file(suite, policy_root=policy_root)
    except (OSError, ValueError, KeyError) as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=1) from exc

    payload = result.to_json()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")

    if format == "json":
        console.print(payload)
    elif format == "text":
        console.print(render_policy_test_result(result))
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=1)

    if not result.passed:
        raise typer.Exit(code=1)


@policy_app.command("explain")
def explain_policy(
    risk: Annotated[Path, typer.Option(help="Risk summary JSON from risk diff.")],
    policy_pack: Annotated[str | None, typer.Option(help="Policy pack ID.")] = None,
    fail_on: Annotated[
        str,
        typer.Option(help="Failure threshold: low, medium, high, or critical."),
    ] = "high",
    format: Annotated[str, typer.Option(help="Output format: text, json, or markdown.")] = "markdown",
    output: Annotated[Path | None, typer.Option(help="Optional output path.")] = None,
) -> None:
    """Explain why AgentShield blocked, warned, or required approval."""
    try:
        explanation = explain_from_file(risk, policy_pack=policy_pack, fail_on=fail_on)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        console.print(f"[red]ERROR[/red] {exc}")
        raise typer.Exit(code=2) from exc

    if format == "json":
        content = explanation.to_json()
    elif format == "markdown":
        content = render_explanation_markdown(explanation)
    elif format == "text":
        content = render_explanation_text(explanation)
    else:
        console.print(f"[red]ERROR[/red] Unknown format: {format}")
        raise typer.Exit(code=2)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content + "\n", encoding="utf-8")
    console.print(content)


@policy_app.command("sign")
def sign_policy_pack(
    policy_path: Annotated[Path, typer.Argument(help="Path to policy.yaml.")],
    output: Annotated[Path | None, typer.Option(help="Signature output path.")] = None,
    signer: Annotated[str, typer.Option(help="Signer identity for audit metadata.")] = "terraguard-agentshield",
    secret: Annotated[str | None, typer.Option(help="Signing secret. Prefer env var in CI.")] = None,
    secret_env: Annotated[str, typer.Option(help="Environment variable containing signing secret.")] = "TERRAGUARD_AGENTSHIELD_POLICY_SECRET",
    private_key: Annotated[Path | None, typer.Option(help="Ed25519 private key PEM for asymmetric signing.")] = None,
    key_id: Annotated[str | None, typer.Option(help="Optional key identifier to embed in the signature.")] = None,
) -> None:
    """Create a detached signature for a policy bundle."""
    policy = load_policy_file(policy_path)
    if private_key:
        signature = sign_policy_asymmetric(
            policy,
            private_key.read_bytes(),
            signer=signer,
            key_id=key_id,
        )
    else:
        signing_secret = secret or os.environ.get(secret_env)
        if not signing_secret:
            console.print(f"[red]ERROR[/red] Signing secret missing. Set {secret_env}.")
            raise typer.Exit(code=1)
        signature = sign_policy(policy, signing_secret, signer=signer)

    signature_path = output or policy_path.with_suffix(policy_path.suffix + ".sig")
    write_signature(signature, signature_path)
    console.print(
        f"[green]OK[/green] {signature.algorithm} policy signature written: {signature_path}"
    )


@policy_app.command("verify")
def verify_policy_pack(
    policy_path: Annotated[Path, typer.Argument(help="Path to policy.yaml.")],
    signature: Annotated[Path | None, typer.Option(help="Signature JSON path.")] = None,
    secret: Annotated[str | None, typer.Option(help="Verification secret. Prefer env var in CI.")] = None,
    secret_env: Annotated[str, typer.Option(help="Environment variable containing verification secret.")] = "TERRAGUARD_AGENTSHIELD_POLICY_SECRET",
    public_key: Annotated[Path | None, typer.Option(help="Ed25519 public key PEM for asymmetric verification.")] = None,
) -> None:
    """Verify a detached policy bundle signature."""
    policy = load_policy_file(policy_path)
    signature_path = signature or policy_path.with_suffix(policy_path.suffix + ".sig")
    policy_signature = read_signature(signature_path)
    if policy_signature.algorithm == ED25519_SIGNATURE_ALGORITHM:
        if not public_key:
            console.print("[red]ERROR[/red] Public key missing. Set --public-key.")
            raise typer.Exit(code=1)
        valid, reason = verify_policy_signature_asymmetric(
            policy, policy_signature, public_key.read_bytes()
        )
    elif policy_signature.algorithm == HMAC_SIGNATURE_ALGORITHM:
        verification_secret = secret or os.environ.get(secret_env)
        if not verification_secret:
            console.print(f"[red]ERROR[/red] Verification secret missing. Set {secret_env}.")
            raise typer.Exit(code=1)
        valid, reason = verify_policy_signature(
            policy, policy_signature, verification_secret
        )
    else:
        valid, reason = False, f"Unsupported signature algorithm: {policy_signature.algorithm}"

    if valid:
        console.print(f"[green]OK[/green] {reason}")
        return

    console.print(f"[red]ERROR[/red] {reason}")
    raise typer.Exit(code=1)


@policy_app.command("keygen")
def generate_policy_key_pair(
    private_key: Annotated[Path, typer.Option(help="Private key output path.")] = Path("agentshield-policy-private.pem"),
    public_key: Annotated[Path, typer.Option(help="Public key output path.")] = Path("agentshield-policy-public.pem"),
) -> None:
    """Generate an Ed25519 policy signing key pair."""
    key_id = generate_ed25519_key_pair(private_key, public_key)
    console.print(f"[green]OK[/green] Policy signing key pair generated. key_id={key_id}")
    console.print(f"[dim]Private key: {private_key}[/dim]")
    console.print(f"[dim]Public key: {public_key}[/dim]")


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


def _github_event_path() -> Path | None:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    path = Path(event_path)
    return path if path.exists() else None


def _read_optional_json(path: Path | None) -> dict[str, object] | None:
    if not path:
        return None
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise typer.BadParameter(f"JSON file is not an object: {path}")
    return payload


def _parse_metadata(items: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise typer.BadParameter(f"Metadata must be key=value: {item}")
        key, value = item.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed
