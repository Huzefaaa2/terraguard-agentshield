# Case Studies

## 1. Banking Terraform Safety

Challenge: an AI agent helps with Terraform modules but might run `terraform apply` locally.

Solution: use `terraform-ai-guardrails` to allow `plan`, `fmt`, and `validate`, while blocking `apply` and `destroy`.

## 2. Payments Secret Protection

Challenge: agents might read `.env`, certificates, tfstate, or tfvars.

Solution: use `filesystem.block_read` and audit every blocked access.

## 3. MCP Tool Sprawl

Challenge: developers connect agents to unknown MCP servers.

Solution: allow enterprise GitHub/Jira/docs MCP servers and block personal drive, browser, or unknown filesystem servers.

## 4. Healthcare Sensitive Code Review

Challenge: agents modify authentication, encryption, or workflow files.

Solution: use `require_approval_write` for sensitive paths and include attestation in PR review.

## 5. Public Sector Audit Evidence

Challenge: auditors need proof of how AI-assisted work was governed.

Solution: archive AgentShield session JSON and PR attestation with each change.

## 6. Global Bank Proportionate Adoption

Challenge: the business wants productivity, the CISO wants runtime control.

Solution: start audit-only, then block secrets/destructive commands, then require approval for high-risk writes.

## 7. Unique Proposition

AgentShield answers a question most enterprises are not yet asking clearly: not only "what code did AI write?", but "what did the AI try to do while working?"
