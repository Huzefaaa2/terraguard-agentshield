# Roadmap

TerraGuard AgentShield is the AI-agent runtime governance product line in the TerraGuard ecosystem. Terraform Guardrail remains focused on IaC governance. AgentShield focuses on agent behavior before code reaches Git.

## Product Thesis

The next generation of DevSecOps controls will not only scan code. They will govern autonomous engineering behavior.

AI coding agents can now read files, write code, execute commands, call tools, and create pull requests. Regulated enterprises need proportionate controls that preserve productivity while preventing agents from bypassing security, privacy, compliance, and change-management processes.

## v0.1: Agent Firewall Foundation

Status: **Implemented in this repo**

- Policy registry and built-in YAML policy packs
- File read/write decisions
- Command block, allow, and approval decisions
- MCP allowlist/blocklist/capability decisions
- Claude Code `PreToolUse` hook adapter
- Protected branch git decision model
- Session audit JSON
- PR markdown attestation
- Webhook evidence sender with optional HMAC signing
- Detached policy signatures with Ed25519 and HMAC-SHA256
- Attestation validation for protected branch checks
- GitHub PR comment publishing
- Codex and Copilot governance examples
- Retryable webhook delivery and SIEM receiver examples
- Jira and ServiceNow evidence routing
- Asymmetric policy bundle signing
- Semantic risk classification for source and IaC diffs
- CLI commands:
  - `agent start`
  - `agent exec`
  - `agent check-file`
  - `agent check-mcp`
  - `agent attest`
- Test coverage for runtime and evidence behavior

## v0.2: Real Agent Integrations

Recommended next implementation phase.

- Hardened Claude Code hook packaging and cross-platform examples
- Hardened Codex/Codex CLI workflow examples
- Hardened GitHub Copilot cloud-agent PR attestation workflow
- GitHub Actions examples for required AgentShield checks
- Documentation for safe pilot rollout in regulated repos

## v0.3: Enterprise Evidence and Approval

- Policy decision summary by risk and control family
- Signed evidence bundle format
- Deployment hardening examples for containerized receivers

## v0.4: Policy Governance

- Organization policy pack templates
- Policy inheritance: enterprise -> business unit -> repo
- Policy test harness
- Policy bundle version pinning
- Control mappings for SOC 2, ISO 27001, PCI DSS, NIST SSDF, and banking technology risk controls

## v0.5: Advanced Semantic Risk Engine

- Policy-pack-specific risk tuning
- Multi-file context and ownership-aware risk scoring
- Dynamic approval routing based on action, repo, environment, and policy
- Remediation suggestions with explainable policy reasoning

## v1.0: Enterprise Release

Release criteria:

- Stable CLI and documented policy schema
- Claude Code hook integration
- GitHub PR attestation workflow
- Packaged policies available from PyPI install
- Enterprise pilot guide
- Threat model and C4 diagrams complete
- Test suite and lint passing in CI
- Clear support matrix for AI coding agents and enforcement maturity

## Long-Term Direction

AgentShield should become the runtime control plane for AI-assisted engineering:

- Agent identity registry
- MCP registry governance
- Cost and session limits
- SIEM/GRC exports
- PAM-aware controls
- Enterprise approval workflows
- Policy recommendations
- Multi-agent session governance

## Adoption Sequence

1. Start with audit-only sessions for pilot teams.
2. Block secret reads and destructive infrastructure commands.
3. Require approval for IAM, security, and production workflow changes.
4. Add PR attestation to protected branches.
5. Expand to MCP governance and SIEM evidence export.
6. Move from pattern-based controls to semantic risk analysis.
