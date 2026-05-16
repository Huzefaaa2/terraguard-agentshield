# SIEM Integration

AgentShield can send signed JSON evidence to webhook receivers. The repository includes examples for Splunk HEC and Microsoft Sentinel.

## Splunk

Receiver:

```text
examples/siem/splunk/receiver.py
```

Run:

```bash
export SPLUNK_HEC_URL="https://splunk.example.com:8088"
export SPLUNK_HEC_TOKEN="replace-me"
export AGENTSHIELD_WEBHOOK_SECRET="replace-me"
python examples/siem/splunk/receiver.py
```

Send evidence:

```bash
export TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET="replace-me"
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url http://localhost:8080 \
  --retries 3 \
  --backoff-seconds 2
```

## Microsoft Sentinel

Receiver:

```text
examples/siem/sentinel/receiver.py
```

Run:

```bash
export SENTINEL_WORKSPACE_ID="workspace-id"
export SENTINEL_SHARED_KEY="base64-shared-key"
export SENTINEL_LOG_TYPE="AgentShieldAudit"
export AGENTSHIELD_WEBHOOK_SECRET="replace-me"
python examples/siem/sentinel/receiver.py
```

Query:

```kusto
AgentShieldAudit_CL
| summarize count() by tool_s, policy_pack_s
| order by count_ desc
```

## Production Guidance

- Terminate TLS at the receiver or an enterprise gateway.
- Require HMAC signatures for inbound AgentShield evidence.
- Store raw JSON for audit traceability.
- Map `session_id`, `tool`, `policy_pack`, and decisions to SIEM fields.
- Set alerts for blocked secret reads, blocked cloud mutations, and approval-required production changes.
