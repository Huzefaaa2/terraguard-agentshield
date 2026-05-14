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
- Protected branch git decision model
- Session audit JSON
- PR markdown attestation
- CLI commands:
  - `agent start`
  - `agent exec`
  - `agent check-file`
  - `agent check-mcp`
  - `agent attest`
- Test coverage for runtime and evidence behavior

## v0.2: Real Agent Integrations

Recommended next implementation phase.

- Claude Code `PreToolUse` hook adapter for Bash, Read, Edit, Write, and MCP tools
- Example `.claude/settings.json` hook configuration
- Codex/Codex CLI wrapper examples using `AGENTS.md`
- GitHub Copilot cloud-agent PR attestation workflow
- GitHub Actions check that validates a required AgentShield audit artifact
- Documentation for safe pilot rollout in regulated repos

## v0.3: Enterprise Evidence and Approval

- Webhook exporter CLI for SIEM ingestion
- Splunk and Microsoft Sentinel examples
- GitHub PR comment publishing workflow
- Jira and ServiceNow evidence mapping examples
- Policy decision summary by risk and control family
- Signed evidence bundle format

## v0.4: Policy Governance

- Policy signing and verification
- Organization policy pack templates
- Policy inheritance: enterprise -> business unit -> repo
- Policy test harness
- Policy bundle version pinning
- Control mappings for SOC 2, ISO 27001, PCI DSS, NIST SSDF, and banking technology risk controls

## v0.5: Semantic Risk Engine

- Diff-aware risk classification
- IaC intent detection for public exposure, IAM privilege escalation, encryption weakening, and logging removal
- Source-code sensitive area classification for auth, crypto, payment, identity, and data export paths
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
