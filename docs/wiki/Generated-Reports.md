# Generated PR and Check Reports

AgentShield can generate one reviewer-friendly report that combines evidence validation, decision summary, approval routing, and compliance mapping.

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
  --validation agentshield-validation.json
```

## API

```bash
curl -s http://127.0.0.1:8000/reports/governance | jq .
curl -s http://127.0.0.1:8000/reports/governance/markdown | jq -r .markdown
```

## Status Values

| Status | Meaning |
| --- | --- |
| `failed` | Validation explicitly failed |
| `requires_approval` | Approval routes are required |
| `requires_attention` | Blocked decisions exist without validation failure |
| `passed` | No validation failure, no required approval route, and no blocked decision |
