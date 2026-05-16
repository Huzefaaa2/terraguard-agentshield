# Splunk HEC Receiver Example

This example receives AgentShield webhook evidence and forwards it to Splunk HTTP Event Collector.

## Environment

```bash
export SPLUNK_HEC_URL="https://splunk.example.com:8088"
export SPLUNK_HEC_TOKEN="replace-me"
export AGENTSHIELD_WEBHOOK_SECRET="replace-me"
export PORT=8080
python receiver.py
```

## Send Evidence

```bash
export TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET="replace-me"
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url http://localhost:8080 \
  --retries 3 \
  --backoff-seconds 2
```

## Splunk Fields

| Field | Source |
| --- | --- |
| `session_id` | AgentShield audit |
| `tool` | Agent identity |
| `policy_pack` | Policy pack |
| `actions[].decision` | Governance result |
