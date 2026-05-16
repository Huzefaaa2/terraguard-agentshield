# SIEM Integration

AgentShield supports retryable webhook delivery and includes receiver examples for Splunk and Microsoft Sentinel.

## Send Evidence

```bash
terraguard-agentshield evidence send-webhook <session-id> \
  --audit-dir .terraguard/audit \
  --url https://security.example.com/events \
  --retries 3 \
  --backoff-seconds 2
```

## Examples

```text
examples/siem/splunk/receiver.py
examples/siem/sentinel/receiver.py
```

Use `TERRAGUARD_AGENTSHIELD_WEBHOOK_SECRET` to sign outbound evidence and `AGENTSHIELD_WEBHOOK_SECRET` in receivers to verify it.
