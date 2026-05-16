# TerraGuard AgentShield Implementation Summary

## Current State

TerraGuard AgentShield now has a working v0.1 agent-firewall foundation for AI coding-agent governance.

Implemented:

- Runtime policy engine
- Built-in YAML policy packs
- File read/write decisions
- Command allow/block/approval decisions
- MCP allowlist/blocklist/capability decisions
- Claude Code `PreToolUse` hook adapter
- Protected branch Git decision model
- Session audit JSON
- PR-ready markdown attestation
- Webhook evidence sender with optional HMAC signing
- Detached Ed25519 and HMAC policy signing and verification
- Attestation validation for protected branch checks
- GitHub PR comment publishing
- Codex and Copilot governance examples
- Retryable webhook delivery plus Splunk/Sentinel receiver examples
- Jira and ServiceNow evidence routing
- Asymmetric policy bundle signing for CI verification
- Semantic risk classification for source and IaC diffs
- Signed evidence bundle format
- Policy inheritance across enterprise, business unit, and repository layers
- Packaged policy data for PyPI-style installs
- CLI commands for start, exec, file checks, MCP checks, and attestation
- Tests and lint coverage for current behavior
- README, architecture, C4, roadmap, threat model, implementation, enterprise adoption, case-study, and wiki-source documentation

Not yet implemented:

- Advanced semantic risk routing
- Web UI

## Repository Structure

```text
terraguard-agentshield/
+-- src/terraguard_agentshield/
|   +-- agent.py
|   +-- audit.py
|   +-- cli.py
|   +-- integrations.py
|   +-- policy_registry.py
|   +-- runtime.py
|   +-- policies/
+-- policies/
+-- docs/
|   +-- assets/
|   +-- wiki/
|   +-- architecture.md
|   +-- c4-model.md
|   +-- case-studies.md
|   +-- enterprise-adoption.md
|   +-- implementation-guide.md
|   +-- policy-authoring.md
|   +-- roadmap.md
|   +-- threat-model.md
|   +-- webhook-integration.md
+-- tests/
+-- .github/workflows/
+-- README.md
+-- pyproject.toml
```

## CLI Surface

```bash
terraguard-agentshield policy list
terraguard-agentshield policy describe ai-agent-baseline
terraguard-agentshield policy resolve --enterprise banking-regulated-ai --repository terraform-ai-guardrails

terraguard-agentshield agent start --tool claude-code --repo .
terraguard-agentshield agent exec "terraform plan"
terraguard-agentshield agent check-file .env --mode read
terraguard-agentshield agent check-mcp github-enterprise --capability read_repo
terraguard-agentshield hooks claude --policy-pack banking-regulated-ai
terraguard-agentshield agent attest <session-id> --format markdown
terraguard-agentshield evidence send-webhook <session-id> --url https://security.example.com/events
terraguard-agentshield policy keygen --private-key private.pem --public-key public.pem
terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml
terraguard-agentshield evidence validate --audit-dir .terraguard/audit
terraguard-agentshield evidence publish-github-comment --audit-dir .terraguard/audit
terraguard-agentshield evidence publish-jira SEC-123 --audit-dir .terraguard/audit
terraguard-agentshield evidence publish-servicenow <sys-id> --audit-dir .terraguard/audit
terraguard-agentshield risk diff change.diff --fail-on high
terraguard-agentshield evidence bundle --audit-dir .terraguard/audit --private-key private.pem
terraguard-agentshield evidence verify-bundle agentshield-evidence-bundle.json --public-key public.pem
```

## Policy Packs

| Pack | Purpose |
| --- | --- |
| `ai-agent-baseline` | General AI-agent sensitive file and command controls |
| `banking-regulated-ai` | Stronger controls for regulated financial engineering |
| `terraform-ai-guardrails` | Terraform/OpenTofu runtime safety controls |
| `mcp-server-governance` | MCP server and capability governance |

## Verification

Current local verification:

```text
ruff check . -> pass
pytest -q -> 50 passed
```

## Recommended Next Implementation

The next recommended development step is **v0.3 Evidence Hardening**:

1. Add a lightweight enterprise policy management API.
2. Add deployment hardening examples for containerized receivers.
3. Add dynamic approval routing from risk findings.
4. Add policy decision summary by risk and control family.
5. Add policy test harness and compliance mappings.
