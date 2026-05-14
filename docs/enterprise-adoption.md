# Enterprise Adoption Guide

AgentShield is designed for regulated enterprises that want to adopt AI coding agents without weakening engineering controls.

## Industry Challenges

| Challenge | Why it matters | AgentShield response |
| --- | --- | --- |
| Agents act through developer identity | Audit trails show the human account, not always the agent behavior | Session metadata and AI governance attestation |
| Local context is hard to control | Agents may read `.env`, tfstate, certificates, or sensitive configs | File access policy and sensitive-read blocks |
| Shell access expands blast radius | Agents can run cloud CLIs, Terraform, Kubernetes, Git, and network commands | Command guard with block/approval/allow decisions |
| MCP expands tool access | Agent capabilities grow as new tools are connected | MCP allowlist, blocklist, capability restrictions, risk scoring |
| Guidance is not enforcement | `CLAUDE.md`, `AGENTS.md`, and custom instructions can guide but cannot fully govern | Convert key standards into executable policy packs |
| CI is late | CI catches code after the agent has already acted | Runtime decisioning before execution or commit |
| Review evidence is inconsistent | Reviewers cannot easily see what the agent touched or was blocked from doing | PR attestation and JSON evidence |

## Recommended Governance Layers

### Layer 1: Configuration Governance

Use enterprise-approved AI coding agents only. Enforce identity, network, repository, and tool allowlists through platform controls where available.

AgentShield role:

- Identify the declared agent tool in each session.
- Pin sessions to a policy pack.
- Record repo and policy metadata in audit output.

### Layer 2: Behavioral Governance

Keep guidance files such as `CLAUDE.md`, `AGENTS.md`, and Copilot custom instructions. Treat them as standards and context, not enforcement.

AgentShield role:

- Turn sensitive file, command, Git, and MCP expectations into executable policy.
- Generate evidence that reviewers can inspect.

### Layer 3: Runtime Enforcement

Intercept or check agent actions before they execute.

AgentShield role:

- Block sensitive reads.
- Block destructive commands.
- Require approval for IAM, security, workflow, and production-impacting changes.
- Record decisions for PRs, SIEM, and audit.

## Pilot Pattern

1. Select one regulated but non-production repository.
2. Install AgentShield and start with `ai-agent-baseline`.
3. Run audit-only checks for normal AI-assisted work.
4. Move `.env`, tfstate, certificates, and keys to block mode.
5. Move Terraform apply, Kubernetes delete, cloud IAM creation, and direct protected-branch push to block mode.
6. Require approval for IAM/security/workflow writes.
7. Attach attestation to PRs.
8. Review false positives weekly and tune policy packs.

## Enterprise Control Mapping

| Control family | AgentShield evidence |
| --- | --- |
| Secure SDLC | AI session audit, command decisions, PR attestation |
| Change management | Approval-required actions, protected branch decisions |
| Access control | MCP allowlist, sensitive path blocks, policy pack |
| Data protection | Secret-read blocking and evidence |
| Infrastructure governance | Terraform/Kubernetes/cloud command blocks |
| Audit and compliance | JSON evidence bundle and reviewer-facing markdown |

## Adoption Anti-Patterns

- Blocking all AI coding agents without a path to governed adoption.
- Allowing agents full local shell and filesystem access with only post-commit review.
- Treating AI review as independent human approval.
- Letting personal MCP servers or browser tools access enterprise repositories.
- Relying only on natural-language instruction files for security-critical controls.

## Recommended First Enterprise Policy

Start with:

- `block_read`: `.env`, `**/*.pem`, `**/*.pfx`, `**/terraform.tfstate`, `**/terraform.tfvars`, `**/kubeconfig`
- `block`: `terraform apply*`, `tofu apply*`, `kubectl delete*`, cloud IAM key/role commands, direct push to protected branches
- `require_approval_write`: `**/iam/**`, `**/security/**`, `.github/workflows/**`, `**/policies/**`
- `mcp.allowed_servers`: enterprise GitHub, Jira, Confluence, internal docs
- `mcp.blocked_servers`: personal drive, public browser, unknown filesystem, unknown remote tools
