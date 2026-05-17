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
- Detached Ed25519 and HMAC policy signing and verification
- Attestation validation for protected branch checks
- GitHub PR comment publishing
- Codex and Copilot governance examples
- Retryable webhook delivery plus Splunk/Sentinel receiver examples
- Jira and ServiceNow evidence routing
- Semantic risk classification for source and IaC diffs
- Signed evidence bundle format
- Policy inheritance across enterprise, business unit, and repository layers
- Enterprise API for policy, evidence, and risk inspection
- Hardened Docker, Compose, Nginx, and Kubernetes deployment examples
- Decision summaries by outcome, risk, and control family
- Dynamic approval routing from risk findings and control families
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
- `terraguard-agentshield evidence publish-github-comment`
- `terraguard-agentshield evidence publish-jira`
- `terraguard-agentshield evidence publish-servicenow`
- `terraguard-agentshield evidence bundle`
- `terraguard-agentshield evidence verify-bundle`
- `terraguard-agentshield evidence summary`
- `terraguard-agentshield approval route`
- `terraguard-agentshield api serve`
- `terraguard-agentshield policy keygen`
- `terraguard-agentshield policy sign`
- `terraguard-agentshield policy verify`
- `terraguard-agentshield policy list`
- `terraguard-agentshield policy describe`
- `terraguard-agentshield policy resolve`
- `terraguard-agentshield risk diff`

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

- Advanced semantic risk routing is roadmap work.
- The current API is inspect-focused; write-side policy administration is roadmap work.

### Recommended Next Release

v0.2 should focus on broader agent integrations and enterprise controls:

- Policy test harness and compliance mappings
- Write-side policy management and approval workflow API

### Verification

Current local verification:

```text
ruff check . -> pass
pytest -q -> 71 passed
```

### Links

- Repository: https://github.com/Huzefaaa2/terraguard-agentshield
- Documentation: see `README.md` and `docs/`
- Wiki source: `docs/wiki/`

### License

BUSL-1.1
