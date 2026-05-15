# Claude Code Hooks

AgentShield includes a Claude Code `PreToolUse` hook adapter.

## Configure

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

## Governed Actions

| Claude tool | AgentShield policy |
| --- | --- |
| `Bash` | command block, approval, allow |
| `Read` | sensitive file read block |
| `Edit`, `Write`, `MultiEdit`, `NotebookEdit` | protected write or approval |
| `mcp__server__tool` | MCP server and capability rules |

## Test

```bash
printf '%s' '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve"}}' \
  | terraguard-agentshield hooks claude --policy-pack terraform-ai-guardrails
```

Expected outcome: Claude receives a deny decision and AgentShield writes audit evidence.
