# Jira and ServiceNow Evidence Routing

AgentShield can publish AI-agent governance evidence directly into enterprise change and work-management systems.

Use this when a regulated workflow needs AgentShield evidence attached to a Jira issue, ServiceNow change request, incident, or approval record.

## Jira Issue Comments

AgentShield publishes the PR-ready governance report as a Jira Cloud comment.

```bash
export JIRA_BASE_URL="https://your-org.atlassian.net"
export JIRA_EMAIL="security@example.com"
export JIRA_API_TOKEN="replace-me"

terraguard-agentshield evidence publish-jira SEC-123 \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

Bearer-token mode is also supported:

```bash
export JIRA_BASE_URL="https://your-org.atlassian.net"
export JIRA_BEARER_TOKEN="replace-me"

terraguard-agentshield evidence publish-jira SEC-123 \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

## ServiceNow Work Notes

AgentShield updates a ServiceNow Table API record with the governance report.

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

Bearer-token mode is also supported:

```bash
export SERVICENOW_INSTANCE_URL="https://your-instance.service-now.com"
export SERVICENOW_BEARER_TOKEN="replace-me"

terraguard-agentshield evidence publish-servicenow <record-sys-id> \
  --table incident \
  --field work_notes \
  --session-id <session-id> \
  --audit-dir .terraguard/audit
```

## Recommended Enterprise Pattern

1. Start or capture an AgentShield session during AI-assisted engineering work.
2. Validate evidence in CI before merge.
3. Publish the same evidence to the pull request, Jira issue, and ServiceNow change record.
4. Require human approval for blocked or approval-required decisions.
5. Archive the JSON audit in SIEM or evidence storage.

## Environment Variables

| Variable | Purpose |
| --- | --- |
| `JIRA_BASE_URL` | Jira site URL |
| `JIRA_EMAIL` | Jira account email for API-token authentication |
| `JIRA_API_TOKEN` | Jira API token |
| `JIRA_BEARER_TOKEN` | Optional Jira bearer token |
| `SERVICENOW_INSTANCE_URL` | ServiceNow instance URL |
| `SERVICENOW_USERNAME` | ServiceNow username for basic auth |
| `SERVICENOW_PASSWORD` | ServiceNow password |
| `SERVICENOW_BEARER_TOKEN` | Optional ServiceNow bearer token |

## API References

- Jira Cloud comment endpoint: `POST /rest/api/3/issue/{issueIdOrKey}/comment`
- ServiceNow Table API update endpoint: `PATCH /api/now/table/{tableName}/{sys_id}`
- Jira reference: https://developer.atlassian.com/cloud/jira/platform/rest/v3/api-group-issue-comments/
- ServiceNow reference: https://www.servicenow.com/docs/r/api-reference/rest-apis/c_TableAPI.html
