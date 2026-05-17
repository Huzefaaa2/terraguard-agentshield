# Approval Routing

AgentShield can route governed actions and semantic risk findings to the right enterprise approver groups.

This is not a ticketing workflow engine yet. It produces deterministic routing recommendations that Jira, ServiceNow, PR checks, internal portals, or future workflow automation can consume.

## CLI

```bash
terraguard-agentshield approval route \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-approval-routes.json
```

Text output:

```bash
terraguard-agentshield approval route \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence
```

## API

```bash
curl -s http://127.0.0.1:8000/approval/routes | jq .
```

The API routes evidence from the configured AgentShield data directory:

```text
.terraguard/agentshield/audit/session-*.json
.terraguard/agentshield/evidence/*.json
```

## Default Routing

| Control family | Approver group |
| --- | --- |
| `application-security` | `appsec-reviewers` |
| `audit-monitoring` | `security-operations` |
| `change-management` | `change-advisory-board` |
| `data-protection` | `data-protection-office` |
| `identity-access` | `iam-security` |
| `infrastructure-change` | `platform-security` |
| `network-security` | `cloud-security` |
| `runtime-governance` | `platform-security` |
| `source-control` | `engineering-reviewers` |
| `tool-governance` | `ai-governance` |
| `unmapped` | `platform-security` |

## Routing Logic

AgentShield creates a route when a control family has:

- blocked actions;
- approval-required actions;
- high or critical risk;
- semantic risk findings.

Priorities are assigned from the strongest signal:

| Signal | Priority |
| --- | --- |
| Critical risk | `critical` |
| High risk, blocked action, approval-required action | `high` |
| Medium risk or semantic finding without high/critical risk | `medium` |
| Low risk | `low` |

Routes are marked `approval_required` when the family has a blocked/approval-required decision or a configured approval-required risk.

## Custom Routing Config

Create `approval-routing.yaml`:

```yaml
default_group: central-platform-security

approver_groups:
  data-protection: privacy-office
  identity-access: iam-governance
  network-security: cloud-security-review
  tool-governance: ai-governance-board

require_approval_for_risks:
  - critical
  - high

require_approval_for_decisions:
  - block
  - require_approval
```

Run with overrides:

```bash
terraguard-agentshield approval route \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --routing-config approval-routing.yaml \
  --format json
```

## Example Output

```json
{
  "route_count": 2,
  "required_route_count": 2,
  "routes": [
    {
      "route_id": "route-infrastructure-change",
      "control_family": "infrastructure-change",
      "approver_group": "platform-security",
      "priority": "critical",
      "approval_required": true,
      "action_count": 1,
      "finding_count": 0,
      "decisions": {
        "block": 1
      },
      "risks": {
        "critical": 1
      }
    }
  ]
}
```

## Enterprise Usage

Recommended integrations:

- add the JSON as a CI artifact;
- publish route summaries into pull request comments;
- attach routes to Jira or ServiceNow change records;
- use `approver_group` to select required reviewers in protected-branch workflows;
- tune `approval-routing.yaml` during pilots as ownership becomes clearer.
