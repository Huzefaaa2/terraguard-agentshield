# Microsoft Sentinel Receiver Example

This example receives AgentShield webhook evidence and forwards it to Azure Monitor Logs / Microsoft Sentinel through the HTTP Data Collector API.

## Environment

```bash
export SENTINEL_WORKSPACE_ID="workspace-id"
export SENTINEL_SHARED_KEY="base64-shared-key"
export SENTINEL_LOG_TYPE="AgentShieldAudit"
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

## Query Example

```kusto
AgentShieldAudit_CL
| summarize count() by tool_s, policy_pack_s
| order by count_ desc
```
