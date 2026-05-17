# Generated PR and Check Reports

AgentShield can generate one reviewer-friendly report that combines:

- evidence validation;
- decision summary;
- approval routing;
- compliance mapping.

Use this report as a CI artifact, pull request comment, or internal portal payload.

## Generate Markdown

```bash
terraguard-agentshield report generate \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --validation agentshield-validation.json \
  --output agentshield-governance-report.md
```

## Generate JSON

```bash
terraguard-agentshield report generate \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --validation agentshield-validation.json \
  --format json \
  --output agentshield-governance-report.json
```

## Publish to GitHub PR

```bash
terraguard-agentshield report publish-github-comment \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --validation agentshield-validation.json \
  --repo owner/repo \
  --pr-number 123
```

In GitHub Actions, `GITHUB_REPOSITORY`, `GITHUB_EVENT_PATH`, and `GITHUB_TOKEN` are used automatically.

## API

```bash
curl -s http://127.0.0.1:8000/reports/governance | jq .
curl -s http://127.0.0.1:8000/reports/governance/markdown | jq -r .markdown
```

## Report Status

| Status | Meaning |
| --- | --- |
| `failed` | Validation explicitly failed |
| `requires_approval` | Approval routes are required |
| `requires_attention` | Blocked decisions exist without validation failure |
| `passed` | No validation failure, no required approval routes, no blocked decisions |

## CI Example

```yaml
- name: Generate AgentShield governance report
  run: |
    SESSION_ID=$(ls -t .terraguard/audit/session-*.json | head -1 | sed 's/.*session-//;s/\.json//')
    terraguard-agentshield evidence validate \
      --session-id "$SESSION_ID" \
      --audit-dir .terraguard/audit \
      --fail-on block,require_approval \
      --output agentshield-validation.json
    terraguard-agentshield report generate \
      --audit-dir .terraguard/audit \
      --bundle-dir .terraguard/agentshield/evidence \
      --validation agentshield-validation.json \
      --output agentshield-governance-report.md
```

The GitHub Actions examples in `examples/github-actions/` include report generation and PR comment publishing.
