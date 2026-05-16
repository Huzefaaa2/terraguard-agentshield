# Codex Governance Example

OpenAI Codex CLI is a local coding agent that can read, edit, and run code with configurable approval modes. AgentShield complements Codex by producing enforceable audit evidence that CI can validate before merge.

Use `AGENTS.md` as the durable instruction surface for Codex. Copy this example into a repository and adapt the policy pack to your environment.

## Recommended Flow

1. Add `AGENTS.md` to the repo root.
2. Run Codex in a conservative approval mode for regulated repositories.
3. Use AgentShield commands before high-risk actions.
4. Generate or validate `.terraguard/audit/session-*.json`.
5. Require `AgentShield Required Check` in branch protection.

## Manual Evidence

```bash
terraguard-agentshield agent start \
  --tool codex \
  --repo . \
  --policy-pack banking-regulated-ai \
  --output .terraguard/audit
```

Validate before merge:

```bash
terraguard-agentshield evidence validate \
  --audit-dir .terraguard/audit \
  --fail-on block,require_approval
```
