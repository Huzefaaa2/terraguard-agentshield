# TerraGuard AgentShield Wiki

**TerraGuard AgentShield is the agent firewall for regulated engineering.**

AI coding agents can read files, write code, execute commands, connect to tools, and open pull requests. AgentShield helps enterprises govern those actions before they become Git changes, cloud changes, or audit findings.

![TerraGuard AgentShield overview](https://raw.githubusercontent.com/Huzefaaa2/terraguard-agentshield/main/docs/assets/agentshield-agent-firewall.svg)

## Latest Release

Current foundation: **v0.1 Agent Firewall Foundation**

Implemented:

- Runtime policy decisions for file access
- Command allow/block/approval decisions
- MCP server allowlist and capability decisions
- Detached policy signing and verification
- Attestation validation for protected branch checks
- Protected branch Git decision model
- Built-in policy packs
- Session audit JSON
- Pull-request-ready markdown attestation
- CLI commands for sessions, execution checks, file checks, MCP checks, and attestation

## Roadmap Snapshot

| Phase | Focus |
| --- | --- |
| v0.1 | Agent firewall foundation |
| v0.2 | Claude Code hooks, Codex/Copilot workflows, PR attestation checks |
| v0.3 | SIEM/GRC evidence export and approval workflow examples |
| v0.4 | Policy signing, inheritance, and compliance mappings |
| v0.5 | Semantic diff and risk engine |
| v1.0 | Enterprise release |

## Start Here

- [Vision](Vision)
- [Architecture](Architecture)
- [C4 Model](C4-Model)
- [Implementation Guide](Implementation-Guide)
- [Claude Code Hooks](Claude-Code-Hooks)
- [Policy Signing](Policy-Signing)
- [Attestation Validation](Attestation-Validation)
- [Policy Authoring](Policy-Authoring)
- [Threat Model](Threat-Model)
- [Enterprise Adoption](Enterprise-Adoption)
- [Case Studies](Case-Studies)
- [Roadmap](Roadmap)

## Related Product

Terraform Guardrail governs Infrastructure-as-Code output. AgentShield governs AI-agent runtime behavior. They share a policy-as-code and audit-evidence philosophy, but remain separate products to keep the architecture and user story clear.
