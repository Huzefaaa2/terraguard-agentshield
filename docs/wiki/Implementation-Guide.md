# Implementation Guide

## Install

```bash
git clone https://github.com/Huzefaaa2/terraguard-agentshield.git
cd terraguard-agentshield
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Start a Session

```bash
terraguard-agentshield agent start \
  --tool claude-code \
  --repo . \
  --policy-pack banking-regulated-ai \
  --output .terraguard/audit
```

## Check a Command

```bash
terraguard-agentshield agent exec "terraform apply -auto-approve" \
  --policy-pack terraform-ai-guardrails
```

## Check File Access

```bash
terraguard-agentshield agent check-file .env --mode read
terraguard-agentshield agent check-file platform/iam/role.tf --mode write \
  --policy-pack banking-regulated-ai
```

## Check MCP Access

```bash
terraguard-agentshield agent check-mcp github-enterprise \
  --capability read_repo \
  --policy-pack mcp-server-governance
```

## Connect Claude Code Hooks

```bash
printf '%s' '{"session_id":"demo","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"terraform apply -auto-approve"}}' \
  | terraguard-agentshield hooks claude --policy-pack terraform-ai-guardrails
```

## Generate Attestation

```bash
terraguard-agentshield agent attest <session-id> \
  --audit-dir .terraguard/audit \
  --format markdown
```

## Send Evidence

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://security.example.com/events
```
