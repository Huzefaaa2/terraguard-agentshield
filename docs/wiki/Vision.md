# Vision

TerraGuard AgentShield secures AI coding agents in regulated engineering environments by evaluating what agents can read, change, execute, connect to, and attest.

## Product Statement

AgentShield enforces policy on AI-agent behavior across Claude Code, Codex-style agents, GitHub Copilot, Cursor, Duo, and MCP-enabled tools.

## Core Principle

AI can assist engineering, but it must not bypass engineering controls.

## The Control Gap

Traditional controls evaluate output after the agent has acted:

```text
AI writes code -> commit -> CI scan -> reviewer decision
```

AgentShield shifts control earlier:

```text
AI requests action -> policy decision -> allow / block / approval -> audit
```

## Governance Layers

1. Configuration governance: approved tools, approved MCP servers, policy packs, repo scope.
2. Behavioral governance: instructions and standards converted into enforceable rules where possible.
3. Runtime enforcement: file, shell, Git, MCP, and evidence decisions during agent work.
