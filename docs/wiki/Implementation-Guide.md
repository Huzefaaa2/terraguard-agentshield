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

## Resolve Layered Policy

```bash
terraguard-agentshield policy resolve \
  --enterprise banking-regulated-ai \
  --repository terraform-ai-guardrails \
  --output resolved-policy.json
```

## Run the Enterprise API

```bash
terraguard-agentshield api serve \
  --host 127.0.0.1 \
  --port 8000 \
  --data-dir .terraguard/agentshield
```

Inspect effective policy:

```bash
curl -s http://127.0.0.1:8000/policies/resolve \
  -H 'content-type: application/json' \
  -d '{"enterprise":"banking-regulated-ai","repository":"terraform-ai-guardrails"}' \
  | jq .
```

Classify diff risk:

```bash
jq -Rs '{diff: ., fail_on: "high"}' change.diff \
  | curl -s http://127.0.0.1:8000/risk/diff \
      -H 'content-type: application/json' \
      -d @- \
  | jq .
```

## Run the Hardened Deployment Examples

Docker Compose:

```bash
cd examples/deployment
docker compose up --build
curl http://127.0.0.1:8080/health
```

Kubernetes:

```bash
kubectl apply -f examples/deployment/kubernetes/agentshield-api.yaml
kubectl -n agentshield rollout status deployment/agentshield-api
```

## Summarize Decisions

```bash
terraguard-agentshield evidence summary \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-decision-summary.json
```

## Route Approvals

```bash
terraguard-agentshield approval route \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-approval-routes.json
```

## Test Policy Packs

```bash
terraguard-agentshield policy test examples/policy-tests/ai-agent-baseline.yaml
```

## Map Compliance Evidence

```bash
terraguard-agentshield compliance map \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-compliance-map.json
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
  --url https://security.example.com/events \
  --retries 3 \
  --backoff-seconds 2
```

## Sign Policy

```bash
terraguard-agentshield policy keygen \
  --private-key .terraguard/keys/policy-private.pem \
  --public-key .terraguard/keys/policy-public.pem

terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml \
  --private-key .terraguard/keys/policy-private.pem

terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml \
  --public-key .terraguard/keys/policy-public.pem
```

## Validate Evidence

```bash
terraguard-agentshield evidence validate \
  --audit-dir .terraguard/audit \
  --fail-on block,require_approval
```

## Classify Diff Risk

```bash
git diff main...HEAD > change.diff

terraguard-agentshield risk diff change.diff \
  --format json \
  --output agentshield-risk.json \
  --fail-on high
```

## Create Evidence Bundle

```bash
terraguard-agentshield evidence bundle \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --risk agentshield-risk.json \
  --validation agentshield-validation.json \
  --private-key .terraguard/keys/evidence-private.pem \
  --output agentshield-evidence-bundle.json
```

## Publish PR Comment

```bash
terraguard-agentshield evidence publish-github-comment \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

## Publish to Jira and ServiceNow

```bash
terraguard-agentshield evidence publish-jira SEC-123 \
  --session-id <session-id> \
  --audit-dir .terraguard/audit

terraguard-agentshield evidence publish-servicenow <record-sys-id> \
  --table change_request \
  --field work_notes \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```
