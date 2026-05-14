# Webhook and SIEM Integration

Webhook and native SIEM exports are part of the enterprise evidence roadmap. The current MVP writes local JSON session evidence and PR-ready markdown attestation. This page defines the planned integration contract so enterprise pilots can design receivers without overloading the current CLI.

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

## Planned CLI

Planned command:

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://your-webhook-endpoint/events
```

## Planned Event Payload

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

- Webhook sender CLI
- Retry and timeout controls
- HMAC request signing
- Splunk HEC example
- Microsoft Sentinel example
- ServiceNow/Jira change evidence mapping
