# Approval Routing

AgentShield can route governed actions and semantic risk findings to the right enterprise approver groups.

## CLI

```bash
terraguard-agentshield approval route \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-approval-routes.json
```

## API

```bash
curl -s http://127.0.0.1:8000/approval/routes | jq .
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

## Routing Logic

AgentShield creates a route when a control family has blocked actions, approval-required actions, high/critical risk, or semantic risk findings.

Priorities are assigned from the strongest signal:

| Signal | Priority |
| --- | --- |
| Critical risk | `critical` |
| High risk, blocked action, approval-required action | `high` |
| Medium risk or semantic finding | `medium` |
| Low risk | `low` |

## Custom Routing Config

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

## Enterprise Usage

- Publish route JSON as a CI artifact.
- Attach routes to pull requests, Jira issues, or ServiceNow changes.
- Use `approver_group` to select required reviewer groups.
- Tune routing during pilots as ownership becomes clearer.
