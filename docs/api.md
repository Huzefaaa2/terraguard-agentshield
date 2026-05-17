# Enterprise API

TerraGuard AgentShield includes a lightweight FastAPI interface for enterprise integrations that need to inspect policy packs, resolved policy layers, signed evidence bundles, and semantic risk summaries.

The API is intentionally read/inspect focused in this slice. Policy authoring, approval workflow storage, and organization administration remain CLI and policy-as-code workflows until the management API is expanded.

## Run Locally

```bash
terraguard-agentshield api serve \
  --host 127.0.0.1 \
  --port 8000 \
  --data-dir .terraguard/agentshield
```

The same data directory can be configured for embedded deployments with:

```bash
export TERRAGUARD_AGENTSHIELD_DATA_DIR=.terraguard/agentshield
```

Signed evidence bundles are read from:

```text
.terraguard/agentshield/evidence/*.json
```

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness check |
| `GET` | `/policies` | List available policy packs |
| `GET` | `/policies/{pack_id}` | Inspect one policy pack |
| `POST` | `/policies/resolve` | Resolve enterprise, business unit, repository, and pack layers |
| `GET` | `/evidence/bundles` | List signed evidence bundles |
| `GET` | `/evidence/bundles/{bundle_id}` | Read one evidence bundle |
| `GET` | `/evidence/summary` | Summarize audit and bundle decisions by outcome, risk, and control family |
| `GET` | `/approval/routes` | Route evidence to enterprise approver groups |
| `GET` | `/compliance/mappings` | List control-family framework mappings |
| `GET` | `/compliance/summary` | Map active AgentShield evidence to compliance frameworks |
| `GET` | `/reports/governance` | Generate a combined validation, summary, approval, and compliance report |
| `GET` | `/reports/governance/markdown` | Generate the same governance report as markdown |
| `POST` | `/risk/diff` | Classify semantic risk in a unified diff |

## Resolve Policy Example

```bash
curl -s http://127.0.0.1:8000/policies/resolve \
  -H 'content-type: application/json' \
  -d '{
    "enterprise": "banking-regulated-ai",
    "business_unit": "mcp-server-governance",
    "repository": "terraform-ai-guardrails"
  }' | jq .
```

The response includes a single effective policy and `metadata.resolved_layers`, which records the inheritance path used for the decision context.

## Evidence Bundle Example

Create a bundle:

```bash
terraguard-agentshield evidence bundle \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --private-key .terraguard/keys/evidence-private.pem \
  --output .terraguard/agentshield/evidence/evidence-<session-id>.json
```

List bundles:

```bash
curl -s http://127.0.0.1:8000/evidence/bundles | jq .
```

Read a bundle:

```bash
curl -s http://127.0.0.1:8000/evidence/bundles/bundle-<session-id> | jq .
```

## Decision Summary Example

```bash
curl -s http://127.0.0.1:8000/evidence/summary | jq .
```

The API summarizes `audit/session-*.json` and `evidence/*.json` under the configured AgentShield data directory.

## Approval Routes Example

```bash
curl -s http://127.0.0.1:8000/approval/routes | jq .
```

The response maps control families and risk signals to approver groups such as platform security, cloud security, IAM security, data protection, change management, and AI governance.

## Compliance Mapping Example

```bash
curl -s http://127.0.0.1:8000/compliance/mappings | jq .
curl -s http://127.0.0.1:8000/compliance/summary | jq .
```

## Governance Report Example

```bash
curl -s http://127.0.0.1:8000/reports/governance | jq .
curl -s http://127.0.0.1:8000/reports/governance/markdown | jq -r .markdown
```

The report combines the active validation result, decision summary, approval routes, and compliance mapping into one payload for internal portals or pull-request checks.

## Risk Diff Example

```bash
jq -Rs '{diff: ., fail_on: "high"}' change.diff \
  | curl -s http://127.0.0.1:8000/risk/diff \
      -H 'content-type: application/json' \
      -d @- \
  | jq .
```

The response includes `decision`, `max_risk`, `risk_counts`, `findings`, and `failed_threshold` when `fail_on` is supplied.

## Enterprise Usage

Recommended early integrations:

- expose `/policies/resolve` to platform portals so teams can inspect their effective policy;
- expose `/evidence/bundles` to GRC tooling so signed audit records can be indexed;
- expose `/reports/governance` to PR portals so reviewers get one combined governance view;
- expose `/risk/diff` to internal developer portals and change workflows;
- run the API inside a private network boundary and put enterprise authentication in front of it.

## Security Notes

- Treat evidence bundles as audit records and store them in controlled storage.
- Put the API behind SSO, reverse proxy authentication, or private network controls before enterprise rollout.
- Do not expose local developer data directories publicly.
- Use signed evidence bundles when evidence is used for protected branch, GRC, or change-management decisions.
