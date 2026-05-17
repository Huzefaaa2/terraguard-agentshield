# Decision Summary

AgentShield can aggregate audit sessions and signed evidence bundles into a decision summary for enterprise dashboards, GRC reporting, and approval-routing workflows.

The summary answers:

- how many actions were allowed, blocked, or required approval;
- which tools and policy packs were used;
- which action types generated the most friction;
- which control families were involved;
- which risk levels appeared in signed evidence bundles;
- which blocked targets appeared most often.

## CLI

```bash
terraguard-agentshield evidence summary \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-decision-summary.json
```

Text output:

```bash
terraguard-agentshield evidence summary \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence
```

## API

```bash
curl -s http://127.0.0.1:8000/evidence/summary | jq .
```

The API reads from:

```text
.terraguard/agentshield/audit/session-*.json
.terraguard/agentshield/evidence/*.json
```

or from the directory configured by `TERRAGUARD_AGENTSHIELD_DATA_DIR`.

## Output Shape

```json
{
  "session_count": 2,
  "bundle_count": 1,
  "action_count": 4,
  "finding_count": 2,
  "decisions": {
    "block": 2,
    "allow": 1,
    "require_approval": 1
  },
  "risks": {
    "critical": 1,
    "high": 1
  },
  "control_families": {
    "data-protection": {
      "actions": 1,
      "findings": 1,
      "decisions": {
        "block": 1
      },
      "risks": {
        "high": 1
      }
    }
  }
}
```

## Control Family Mapping

AgentShield uses explicit action metadata when available:

```json
{
  "metadata": {
    "control_family": "identity-access",
    "risk": "critical"
  }
}
```

When metadata is absent, it infers a practical family from action type, target, and policy reason:

| Signal | Default family |
| --- | --- |
| MCP/tool activity | `tool-governance` |
| Git push/branch activity | `change-management` |
| Terraform/OpenTofu/Kubernetes commands | `infrastructure-change` |
| Secrets, `.env`, tfstate, tfvars, certificates | `data-protection` |
| IAM, roles, policy files | `identity-access` |
| File reads/writes without stronger signal | `source-control` |
| Other runtime actions | `runtime-governance` |

Risk findings from `risk diff` use their native `control_family` values.

## Enterprise Usage

Recommended uses:

- publish summary JSON as a CI artifact;
- display allow/block/approval trends in an internal developer portal;
- feed `control_families` and `risks` into GRC evidence records;
- route repeated high-risk families to the right approver group in later workflow automation;
- track policy tuning during audit-only pilots.
