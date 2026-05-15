# Webhook and SIEM Integration

Webhook delivery is implemented through the `evidence send-webhook` command. Native SIEM-specific exporters remain roadmap work, but enterprises can already send signed JSON evidence to a webhook receiver, SIEM collector, GRC archive, or change-management bridge.

## Current Evidence Outputs

Generate JSON evidence:

```bash
terraguard-agentshield agent attest <session-id> \
  --audit-dir .terraguard/audit \
  --format json
```

Generate markdown attestation:

```bash
terraguard-agentshield agent attest <session-id> \
  --audit-dir .terraguard/audit \
  --format markdown
```

## Send Evidence

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://your-webhook-endpoint/events
```

Dry run:

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://your-webhook-endpoint/events \
  --dry-run
```

HMAC signing:

```bash
export TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET="replace-me"
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://your-webhook-endpoint/events
```

AgentShield sends `X-AgentShield-Signature: sha256=<digest>` when a signing secret is configured.

## Event Payload

```json
{
  "session_id": "abc123def456",
  "tool": "claude-code",
  "repo": "/path/to/repo",
  "policy_pack": "banking-regulated-ai",
  "started_at": "2026-05-14T10:30:00Z",
  "actions": [
    {
      "type": "execute_command",
      "target": "terraform apply",
      "decision": "block",
      "reason": "Matched blocked command policy: terraform apply*",
      "metadata": {}
    }
  ]
}
```

## Receiver Requirements

Webhook receivers should:

- Accept JSON POST requests.
- Return HTTP 200, 201, or 204 on success.
- Handle duplicate evidence idempotently.
- Store the raw payload for audit traceability.
- Map decisions to internal control IDs where possible.

## Example Splunk Mapping

| AgentShield field | Splunk field |
| --- | --- |
| `session_id` | `session_id` |
| `tool` | `ai_agent` |
| `policy_pack` | `policy_pack` |
| `actions[].decision` | `decision` |
| `actions[].target` | `target` |

## Roadmap

- Retry and timeout controls
- Splunk HEC example
- Microsoft Sentinel example
- ServiceNow/Jira change evidence mapping
