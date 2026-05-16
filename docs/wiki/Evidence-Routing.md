# Evidence Routing

AgentShield can publish AI-agent governance evidence to Jira and ServiceNow.

## Jira

```bash
export JIRA_BASE_URL="https://your-org.atlassian.net"
export JIRA_EMAIL="security@example.com"
export JIRA_API_TOKEN="replace-me"

terraguard-agentshield evidence publish-jira SEC-123 \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

## ServiceNow

```bash
export SERVICENOW_INSTANCE_URL="https://your-instance.service-now.com"
export SERVICENOW_USERNAME="agentshield.integration"
export SERVICENOW_PASSWORD="replace-me"

terraguard-agentshield evidence publish-servicenow <record-sys-id> \
  --table change_request \
  --field work_notes \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

## Recommended Flow

1. Generate AgentShield session evidence.
2. Validate the evidence in CI.
3. Publish the report to the pull request.
4. Route the same evidence to the Jira issue or ServiceNow change record.
5. Archive JSON evidence in SIEM.
