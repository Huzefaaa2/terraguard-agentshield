# Decision Summary

AgentShield can aggregate audit sessions and signed evidence bundles into a decision summary for enterprise dashboards, GRC reporting, and approval-routing workflows.

## CLI

```bash
terraguard-agentshield evidence summary \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-decision-summary.json
```

## API

```bash
curl -s http://127.0.0.1:8000/evidence/summary | jq .
```

## Summary Contents

The summary includes:

- session count;
- evidence bundle count;
- action count;
- risk finding count;
- allow/block/approval decision counts;
- action type counts;
- AI tool counts;
- policy pack counts;
- risk counts;
- control family breakdown;
- top blocked targets.

## Control Family Mapping

AgentShield uses explicit action metadata when available. When metadata is absent, it infers a practical family from action type, target, and policy reason.

| Signal | Default family |
| --- | --- |
| MCP/tool activity | `tool-governance` |
| Git push/branch activity | `change-management` |
| Terraform/OpenTofu/Kubernetes commands | `infrastructure-change` |
| Secrets, `.env`, tfstate, tfvars, certificates | `data-protection` |
| IAM, roles, policy files | `identity-access` |
| File reads/writes without stronger signal | `source-control` |
| Other runtime actions | `runtime-governance` |

## Enterprise Usage

- Publish summary JSON as a CI artifact.
- Display allow/block/approval trends in an internal portal.
- Feed control-family and risk counts into GRC evidence records.
- Use repeated high-risk families as input for approval routing.

See [Approval Routing](Approval-Routing) for reviewer group mapping.
