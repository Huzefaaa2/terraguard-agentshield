# Release Notes

## v0.1.0 - May 14, 2026

### Agent Firewall Foundation

TerraGuard AgentShield v0.1.0 establishes the foundation for runtime governance of AI coding agents in regulated engineering environments.

### Implemented

Core governance:

- Policy-as-code with YAML definitions
- File access decisions for block, allow, and approval-required writes
- Command decisions for block, allow, and approval-required execution
- Git protected branch decision model
- MCP server allowlist, blocklist, risk, and capability decisions
- Claude Code `PreToolUse` hook adapter
- Session-based JSON audit trail
- PR-ready markdown attestation
- Webhook evidence sender with optional HMAC signing
- Detached policy signing and verification
- Attestation validation for protected branch checks
- Packaged built-in policy packs for installed usage

Policy packs:

- `ai-agent-baseline`
- `banking-regulated-ai`
- `terraform-ai-guardrails`
- `mcp-server-governance`

CLI:

- `terraguard-agentshield agent start`
- `terraguard-agentshield agent exec`
- `terraguard-agentshield agent check-file`
- `terraguard-agentshield agent check-mcp`
- `terraguard-agentshield agent attest`
- `terraguard-agentshield hooks claude`
- `terraguard-agentshield evidence send-webhook`
- `terraguard-agentshield evidence validate`
- `terraguard-agentshield policy sign`
- `terraguard-agentshield policy verify`
- `terraguard-agentshield policy list`
- `terraguard-agentshield policy describe`

Documentation:

- README
- Architecture
- C4 model
- Threat model
- Implementation guide
- Policy authoring
- Enterprise adoption guide
- Case studies
- Roadmap
- Wiki source pages under `docs/wiki/`

### Known Limitations

- Codex and Copilot workflow adapters are not implemented yet.
- Jira and ServiceNow integrations are roadmap items.
- Policy inheritance is a roadmap item.
- Semantic risk analysis is roadmap work.

### Recommended Next Release

v0.2 should focus on broader agent integrations and enterprise controls:

- Codex/Copilot PR evidence examples
- Retryable webhook delivery and SIEM receiver examples
- Asymmetric policy-signing option

### Verification

Current local verification:

```text
ruff check . -> pass
pytest -q -> 28 passed
```

### Links

- Repository: https://github.com/Huzefaaa2/terraguard-agentshield
- Documentation: see `README.md` and `docs/`
- Wiki source: `docs/wiki/`

### License

BUSL-1.1
