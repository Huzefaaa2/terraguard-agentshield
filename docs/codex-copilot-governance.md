# Codex and Copilot Governance

AgentShield is designed to govern multiple AI coding-agent workflows, not only Claude Code hooks.

## Codex

OpenAI Codex CLI runs locally and can read, edit, and run code with approval modes. AgentShield complements Codex by producing policy-controlled evidence that CI can validate before merge.

Use:

- `examples/codex/AGENTS.md`
- `terraguard-agentshield agent start --tool codex`
- `terraguard-agentshield evidence validate`

Recommended regulated workflow:

1. Add `AGENTS.md` to the repository.
2. Start AgentShield audit sessions for AI-assisted work.
3. Validate AgentShield evidence before pull request merge.
4. Require independent human review.

## GitHub Copilot Coding Agent

GitHub Copilot coding agent operates through GitHub pull requests. AgentShield fits this workflow by publishing PR attestation comments and providing a required check.

Use:

- `examples/copilot/copilot-instructions.md`
- `examples/github-actions/agentshield-required-check.yml`
- `terraguard-agentshield evidence publish-github-comment`

Recommended regulated workflow:

1. Add `.github/copilot-instructions.md`.
2. Sign approved policy packs.
3. Add the AgentShield required workflow.
4. Require the workflow in branch protection.
5. Require independent human review.

## PR Comment Publishing

Publish or update a pull request comment:

```bash
terraguard-agentshield evidence publish-github-comment \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --repo owner/repo \
  --pr-number 123
```

In GitHub Actions, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, and `GITHUB_TOKEN` are detected automatically.

AgentShield uses a stable hidden marker so repeated workflow runs update the same comment instead of posting duplicates.
