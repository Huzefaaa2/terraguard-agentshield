# C4 Model

This page documents TerraGuard AgentShield using the C4 model: system context, container, component, and deployment views.

![C4 container view](assets/agentshield-c4-container.svg)

## Level 1: System Context

```mermaid
C4Context
    title TerraGuard AgentShield - System Context
    Person(developer, "Developer", "Uses AI coding agents to work in repositories")
    Person(reviewer, "Independent Reviewer", "Reviews PRs and governance evidence")
    System(agent, "AI Coding Agent", "Claude Code, Codex, Copilot, Cursor, Duo")
    System(agentshield, "TerraGuard AgentShield", "Runtime governance for AI-agent actions")
    System_Ext(repo, "Git Repository", "Source code, IaC, branches, pull requests")
    System_Ext(siem, "SIEM / GRC", "Audit evidence and compliance archive")
    System_Ext(mcp, "MCP Servers", "External tools and context providers")
    System_Ext(portal, "Enterprise Portal", "Internal platform, GRC, or security workflow")

    Rel(developer, agent, "Delegates engineering task")
    Rel(agent, agentshield, "Requests governed action")
    Rel(agentshield, repo, "Allows, blocks, or attests changes")
    Rel(agentshield, mcp, "Allows or blocks tool access")
    Rel(agentshield, siem, "Exports evidence")
    Rel(portal, agentshield, "Inspects policies, evidence, and risk through API")
    Rel(reviewer, repo, "Approves PR after reviewing attestation")
```

## Level 2: Container View

```mermaid
C4Container
    title TerraGuard AgentShield - Containers
    Person(developer, "Developer")
    System_Boundary(agentshield, "TerraGuard AgentShield") {
        Container(cli, "CLI / Hook Adapter", "Python Typer", "Normalizes AI-agent actions into policy checks")
        Container(api, "Enterprise API", "FastAPI", "Exposes policy, evidence, and risk inspection")
        Container(runtime, "RuntimeGuard", "Python", "Evaluates file, command, Git, and MCP decisions")
        Container(registry, "Policy Registry", "YAML", "Loads built-in and custom policy packs")
        Container(audit, "Audit Recorder", "JSON/Markdown", "Writes session evidence and PR attestation")
    }
    System_Ext(agent, "AI Coding Agent")
    System_Ext(repo, "Git Repository")
    System_Ext(mcp, "MCP Servers")

    Rel(developer, agent, "Uses")
    Rel(agent, cli, "Action request")
    Rel(developer, api, "Inspect effective policy and evidence")
    Rel(cli, runtime, "Evaluate")
    Rel(api, registry, "List and resolve policies")
    Rel(api, audit, "Read signed evidence bundles")
    Rel(runtime, registry, "Load policy")
    Rel(runtime, audit, "Record decision")
    Rel(cli, repo, "Execute allowed repo/shell/git action")
    Rel(cli, mcp, "Connect if allowed")
```

## Level 3: Component View

```mermaid
flowchart TB
    CLI[Typer CLI Commands] --> Session[AgentSessionManager]
    API[FastAPI Enterprise API] --> Registry
    API --> Evidence[Evidence Bundle Reader]
    API --> Risk[SemanticRiskClassifier]
    CLI --> Interceptor[CommandInterceptor]
    CLI --> Guard[RuntimeGuard]
    Session --> Audit[SessionAudit]
    Interceptor --> Guard
    Interceptor --> Audit
    Guard --> File[File Policy Evaluator]
    Guard --> Command[Command Policy Evaluator]
    Guard --> Git[Git Policy Evaluator]
    Guard --> MCP[MCP Policy Evaluator]
    Guard --> Registry[PolicyRegistry]
    Registry --> Packs[YAML Policy Packs]
    Audit --> JSON[Session JSON]
    Audit --> Markdown[PR Markdown Attestation]
    Evidence --> Bundle[Signed Evidence Bundle]
```

## Level 4: Deployment View

```mermaid
flowchart LR
    subgraph Workstation[Developer Workstation]
        Agent[AI Coding Agent]
        CLI[AgentShield CLI]
        Audit[.terraguard/audit/*.json]
    end

    subgraph Repo[Git Provider]
        PR[Pull Request]
        Checks[CI Checks]
    end

    subgraph Enterprise[Enterprise Security Systems]
        SIEM[SIEM]
        GRC[GRC Evidence Store]
        Change[Change Management]
    end

    Agent --> CLI
    CLI --> Audit
    Audit --> PR
    PR --> Checks
    Checks --> SIEM
    Checks --> GRC
    Checks --> Change
```

## Current C4 Status

| Area | Status |
| --- | --- |
| Local CLI adapter | Implemented |
| Runtime policy decision engine | Implemented |
| Packaged policy packs | Implemented |
| JSON audit and markdown attestation | Implemented |
| Claude Code hook adapter | Implemented |
| Policy signing | Implemented |
| Attestation validation | Implemented |
| GitHub PR comment publishing | Implemented |
| GitHub Action attestation validation | Example provided |
| SIEM/GRC/change evidence exporters | Implemented foundation |
| Enterprise API | Implemented foundation |
| Hardened deployment examples | Implemented foundation |
| Decision summary | Implemented foundation |
