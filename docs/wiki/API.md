# Enterprise API

AgentShield provides a lightweight HTTP API for enterprise systems that need policy, evidence, and risk inspection.

## Start the API

```bash
terraguard-agentshield api serve \
  --host 127.0.0.1 \
  --port 8000 \
  --data-dir .terraguard/agentshield
```

Evidence bundles are read from:

```text
.terraguard/agentshield/evidence/*.json
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness check |
| `GET` | `/policies` | List policy packs |
| `GET` | `/policies/{pack_id}` | Inspect one policy pack |
| `POST` | `/policies/resolve` | Resolve inherited policy layers |
| `GET` | `/evidence/bundles` | List signed evidence bundles |
| `GET` | `/evidence/bundles/{bundle_id}` | Read one evidence bundle |
| `GET` | `/evidence/summary` | Summarize decisions by outcome, risk, and control family |
| `POST` | `/risk/diff` | Classify semantic risk in a unified diff |

## Resolve Effective Policy

```bash
curl -s http://127.0.0.1:8000/policies/resolve \
  -H 'content-type: application/json' \
  -d '{
    "enterprise": "banking-regulated-ai",
    "business_unit": "mcp-server-governance",
    "repository": "terraform-ai-guardrails"
  }' | jq .
```

The response includes `metadata.resolved_layers`, so teams can see exactly which layers produced the effective policy.

## Inspect Evidence

```bash
curl -s http://127.0.0.1:8000/evidence/bundles | jq .
curl -s http://127.0.0.1:8000/evidence/bundles/bundle-<session-id> | jq .
```

## Summarize Decisions

```bash
curl -s http://127.0.0.1:8000/evidence/summary | jq .
```

## Classify Risk

```bash
jq -Rs '{diff: ., fail_on: "high"}' change.diff \
  | curl -s http://127.0.0.1:8000/risk/diff \
      -H 'content-type: application/json' \
      -d @- \
  | jq .
```

## Enterprise Notes

- Put the API behind SSO, reverse proxy authentication, or private network access.
- Use signed evidence bundles for branch protection, GRC, and change-management workflows.
- Keep local developer data directories private.
