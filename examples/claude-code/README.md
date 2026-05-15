# Claude Code Hook Example

This example shows how to connect Claude Code `PreToolUse` events to TerraGuard AgentShield.

Copy `settings.json` into the appropriate Claude Code settings location for a pilot repository, then run normal Claude Code workflows. AgentShield will evaluate:

- `Bash` command execution
- `Read` file access
- `Edit`, `Write`, `MultiEdit`, and `NotebookEdit` file writes
- MCP tool names matching `mcp__server__tool`

Audit evidence is written to:

```text
.terraguard/audit/session-<claude-session-id>.json
```

Generate attestation:

```bash
terraguard-agentshield agent attest <session-id> \
  --audit-dir .terraguard/audit \
  --format markdown
```
