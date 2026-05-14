from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.json import JSON

from terraguard_agentshield.agent import AgentSessionManager
from terraguard_agentshield.audit import AuditAction, SessionAudit
from terraguard_agentshield.integrations import CommandInterceptor, GitHubPRAttestationExporter
from terraguard_agentshield.policy_registry import PolicyRegistry
from terraguard_agentshield.runtime import RuntimeGuard

console = Console()
app = typer.Typer(add_completion=False)
agent_app = typer.Typer(help="AI agent runtime commands.")
policy_app = typer.Typer(help="Policy registry commands.")
app.add_typer(agent_app, name="agent")
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


def main() -> None:
    app()
