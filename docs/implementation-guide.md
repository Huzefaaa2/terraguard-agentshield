# Implementation Guide

This guide shows how to pilot TerraGuard AgentShield in a regulated engineering environment.

## 1. Install Locally

```bash
git clone https://github.com/Huzefaaa2/terraguard-agentshield.git
cd terraguard-agentshield
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Verify:

```bash
terraguard-agentshield version
terraguard-agentshield policy list
```

## 2. Start an AI Governance Session

```bash
terraguard-agentshield agent start \
  --tool claude-code \
  --repo . \
  --policy-pack banking-regulated-ai \
  --output .terraguard/audit
```

This creates a session file:

```text
.terraguard/audit/session-<session-id>.json
```

## 3. Check Commands Before Execution

Allowed example:

```bash
terraguard-agentshield agent exec "terraform plan" \
  --policy-pack terraform-ai-guardrails \
  --output .terraguard/audit
```

Blocked example:

```bash
terraguard-agentshield agent exec "terraform apply -auto-approve" \
  --policy-pack terraform-ai-guardrails \
  --output .terraguard/audit
```

Approval-required example:

```bash
terraguard-agentshield agent exec "aws s3 ls" \
  --policy-pack banking-regulated-ai \
  --output .terraguard/audit
```

## 4. Check File Access

Block secret reads:

```bash
terraguard-agentshield agent check-file .env --mode read \
  --policy-pack ai-agent-baseline \
  --output .terraguard/audit
```

Require approval for sensitive writes:

```bash
terraguard-agentshield agent check-file platform/iam/role.tf --mode write \
  --policy-pack banking-regulated-ai \
  --output .terraguard/audit
```

## 5. Check MCP Tool Access

Allow an approved enterprise MCP server:

```bash
terraguard-agentshield agent check-mcp github-enterprise \
  --capability read_repo \
  --policy-pack mcp-server-governance \
  --output .terraguard/audit
```

Block a risky MCP server:

```bash
terraguard-agentshield agent check-mcp personal-drive-mcp \
  --policy-pack mcp-server-governance \
  --output .terraguard/audit
```

Block a risky capability:

```bash
terraguard-agentshield agent check-mcp github-enterprise \
  --capability delete_repo \
  --policy-pack mcp-server-governance \
  --output .terraguard/audit
```

## 6. Connect Claude Code Hooks

Use the sample settings at `examples/claude-code/settings.json` to connect Claude Code `PreToolUse` events to AgentShield.

Manual test:

```bash
printf '%s' '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve"}}' \
  | terraguard-agentshield hooks claude \
      --policy-pack terraform-ai-guardrails \
      --repo . \
      --audit-dir .terraguard/audit
```

Expected outcome: a deny decision is returned and evidence is written to `.terraguard/audit/session-demo.json`.

## 7. Generate PR Attestation

```bash
terraguard-agentshield agent attest <session-id> \
  --audit-dir .terraguard/audit \
  --format markdown
```

This produces a markdown report that can be pasted into a pull request or published by CI.

## 8. Send Evidence to a Webhook

Dry run:

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://security.example.com/events \
  --dry-run
```

Send with HMAC signing:

```bash
export TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET="replace-me"
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://security.example.com/events
```

## 9. GitHub Actions Example

Create `.github/workflows/agentshield-attestation.yml`:

```yaml
name: AgentShield Attestation

on:
  pull_request:

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install AgentShield
        run: pip install terraguard-agentshield
      - name: Generate attestation when audit exists
        run: |
          if ls .terraguard/audit/session-*.json >/dev/null 2>&1; then
            SESSION_ID=$(ls -t .terraguard/audit/session-*.json | head -1 | sed 's/.*session-//;s/\.json//')
            terraguard-agentshield agent attest "$SESSION_ID" \
              --audit-dir .terraguard/audit \
              --format markdown > agentshield-attestation.md
          else
            echo "No AgentShield audit found" > agentshield-attestation.md
          fi
      - uses: actions/upload-artifact@v4
        with:
          name: agentshield-attestation
          path: agentshield-attestation.md
```

## 10. Pilot Rollout Model

| Stage | Policy mode | Objective |
| --- | --- | --- |
| Week 1 | Audit only | Understand agent behavior and common commands |
| Week 2 | Block secrets | Prevent `.env`, tfstate, certificates, and keys from entering AI context |
| Week 3 | Block destructive commands | Prevent `terraform apply`, `kubectl delete`, cloud IAM creation |
| Week 4 | Require approval | Gate IAM, security, workflow, and production-impacting changes |
| Week 5+ | PR attestation | Make AgentShield evidence part of protected branch review |

## 11. Enterprise Operating Model

Recommended controls:

- Use enterprise-approved AI coding agents only.
- Keep production credentials and sensitive data unavailable to agentic sessions.
- Add AgentShield policies to each regulated repo.
- Require independent human review for protected branches.
- Store AgentShield audit evidence with PRs and compliance records.
- Track unknown commands and refine policy packs every sprint during pilot.
