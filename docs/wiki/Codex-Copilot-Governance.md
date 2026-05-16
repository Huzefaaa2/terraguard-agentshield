# Codex and Copilot Governance

AgentShield supports governance patterns for Codex and GitHub Copilot coding agent.

## Codex

Use `examples/codex/AGENTS.md` to tell Codex how to work in an AgentShield-governed repository.

Recommended commands:

```bash
terraguard-agentshield agent start --tool codex --policy-pack banking-regulated-ai
terraguard-agentshield evidence validate --audit-dir .terraguard/audit
```

## GitHub Copilot

Use `examples/copilot/copilot-instructions.md` as `.github/copilot-instructions.md`.

Recommended GitHub Actions:

```text
examples/github-actions/agentshield-required-check.yml
```

## Publish PR Comment

```bash
terraguard-agentshield evidence publish-github-comment \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

In GitHub Actions, repository, PR number, and token can be detected from the standard GitHub environment.
