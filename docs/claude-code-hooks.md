# Claude Code Hooks Integration

TerraGuard AgentShield includes a Claude Code hook adapter for `PreToolUse` events. This is the first real runtime-enforcement integration beyond manual CLI checks.

Official Claude Code hooks documentation describes hooks as deterministic commands that run on lifecycle events such as `PreToolUse` and can return structured JSON decisions. AgentShield uses that model to evaluate agent actions before they run.

Reference: https://docs.claude.com/en/docs/claude-code/hooks

## What Is Governed

| Claude tool | AgentShield check |
| --- | --- |
| `Bash` | `commands.block`, `commands.require_approval`, `commands.allow` |
| `Read` | `filesystem.block_read` |
| `Edit`, `Write`, `MultiEdit`, `NotebookEdit` | `filesystem.block_write`, `filesystem.require_approval_write` |
| `mcp__server__tool` | MCP server and capability policy |

## Configure Claude Code

Example settings:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|MultiEdit|NotebookEdit|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "terraguard-agentshield hooks claude --policy-pack banking-regulated-ai --repo . --audit-dir .terraguard/audit"
          }
        ]
      }
    ]
  }
}
```

The same example is available at `examples/claude-code/settings.json`.

## Manual Test

```bash
printf '%s' '{
  "session_id": "demo",
  "hook_event_name": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": {
    "command": "terraform apply -auto-approve"
  }
}' | terraguard-agentshield hooks claude \
  --policy-pack terraform-ai-guardrails \
  --repo . \
  --audit-dir .terraguard/audit
```

Expected response:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Matched blocked command policy: terraform apply*"
  }
}
```

## Evidence

Hook decisions are appended to:

```text
.terraguard/audit/session-<session-id>.json
```

Generate pull request attestation:

```bash
terraguard-agentshield agent attest demo \
  --audit-dir .terraguard/audit \
  --format markdown
```

## Enterprise Rollout

1. Start with `ai-agent-baseline` in one pilot repository.
2. Move regulated repos to `banking-regulated-ai`.
3. Use `terraform-ai-guardrails` for infrastructure repositories.
4. Require PR attestation for protected branches.
5. Export evidence to SIEM or GRC with `evidence send-webhook`.
