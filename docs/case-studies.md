# Case Studies

These fictionalized case studies show how enterprises can use TerraGuard AgentShield to adopt AI coding agents responsibly.

## 1. Banking Platform Team: Terraform Apply Must Not Run Locally

The platform engineering team wants Claude Code and Codex to help with Terraform modules. The risk is that an agent might run `terraform apply` from a developer workstation using privileged credentials.

AgentShield approach:

1. Install AgentShield in the repo.
2. Use `terraform-ai-guardrails`.
3. Block `terraform apply*`, `tofu apply*`, `terraform destroy*`, and `tofu destroy*`.
4. Allow `terraform fmt*`, `terraform validate*`, and `terraform plan*`.
5. Require PR attestation for protected branches.

Example:

```bash
terraguard-agentshield agent exec "terraform apply -auto-approve" \
  --policy-pack terraform-ai-guardrails
```

Outcome: the agent can help create plans and tests, but cannot perform infrastructure changes without the organization's established release process.

## 2. Payments Team: Secrets Must Not Enter AI Context

A payments team uses AI coding agents to improve test coverage. The repo contains local `.env` files, certificates, and encrypted configuration examples.

AgentShield approach:

1. Use `ai-agent-baseline`.
2. Block reads of `.env`, `**/*.pem`, `**/*.pfx`, `**/terraform.tfstate`, and `**/terraform.tfvars`.
3. Run file checks from a hook adapter or manually during pilot.

Example:

```bash
terraguard-agentshield agent check-file .env --mode read
```

Outcome: AI agents can inspect source files and tests, but sensitive local data is kept out of model context.

## 3. Retail Enterprise: MCP Tool Sprawl

Developers start connecting AI tools to GitHub, Jira, personal drives, browser automation, and filesystem MCP servers. Security cannot tell which tools are safe.

AgentShield approach:

1. Use `mcp-server-governance`.
2. Allow `github-enterprise`, `jira-enterprise`, `confluence-readonly`, and `internal-docs-readonly`.
3. Block personal drive and public browser MCP servers.
4. Block dangerous capabilities such as `delete_repo` and `force_push`.

Example:

```bash
terraguard-agentshield agent check-mcp github-enterprise --capability delete_repo \
  --policy-pack mcp-server-governance
```

Outcome: teams keep the productivity of MCP tools while limiting unapproved capability expansion.

## 4. Healthcare SaaS: Sensitive Code Areas Need Human Approval

An AI agent is asked to refactor authentication and encryption code. The change may be valid, but it must not bypass security review.

AgentShield approach:

1. Create an organization policy pack.
2. Add `require_approval_write` for `auth/**`, `crypto/**`, `security/**`, and `.github/workflows/**`.
3. Generate PR attestation for reviewers.

Outcome: the agent can prepare the change, but human reviewers see exactly which sensitive areas were touched and which controls applied.

## 5. Public Sector: Audit Evidence for AI-Assisted Engineering

A public sector technology group needs to show auditors how AI-assisted code changes were governed.

AgentShield approach:

1. Require every AI-assisted session to generate `.terraguard/audit/session-*.json`.
2. Store the attestation artifact with the pull request.
3. Map blocked and approval-required actions to internal control IDs.

Outcome: audit evidence is produced as a normal engineering artifact, not reconstructed after the fact.

## 6. Global Bank: Proportionate AI Adoption

The CISO office does not want to ban AI coding agents, but also cannot accept unrestricted local shell, repo, and tool access.

AgentShield approach:

1. Start with audit-only pilot.
2. Move secrets and destructive commands to block.
3. Move IAM/security/workflow files to approval-required.
4. Add MCP allowlisting.
5. Use PR attestation for independent reviewer context.

Outcome: productivity gains are preserved while governance becomes visible, measurable, and enforceable.

## 7. Unique Proposition: AI-Agent Change Intelligence

Most enterprises will ask, "Did the AI write insecure code?" A better question is, "What did the AI try to do while working?"

AgentShield makes this visible:

- Which tool acted
- Which repo it acted in
- Which policy version applied
- Which files it tried to read or write
- Which commands were blocked
- Which MCP tools were allowed or denied
- Which actions need human approval

This creates a new operating model: AI agents become governed engineering participants, not invisible assistants behind a developer identity.
