# Attestation Validation

AgentShield can validate audit evidence in CI so protected branches can require proof that AI-agent activity was governed.

## Validate Latest Audit

```bash
terraguard-agentshield evidence validate \
  --audit-dir .terraguard/audit \
  --fail-on block,require_approval
```

## Validate a Specific Session

```bash
terraguard-agentshield evidence validate \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --require-policy-pack banking-regulated-ai \
  --fail-on block,require_approval \
  --output agentshield-validation.json
```

## Validation Rules

| Option | Purpose |
| --- | --- |
| `--fail-on` | Comma-separated decisions that fail the check |
| `--require-policy-pack` | Require a specific policy pack |
| `--require-tool` | Require a specific AI tool identifier |
| `--min-actions` | Require at least this many audited actions |
| `--output` | Write JSON validation output |

Default failure decisions:

```text
block,require_approval
```

This means protected branch checks fail if the AI session had blocked actions or unresolved approval-required actions.

## GitHub Actions Required Check

Use `examples/github-actions/agentshield-required-check.yml` as a starting point.

Recommended branch protection:

1. Require pull request before merge.
2. Require `AgentShield Required Check`.
3. Require independent human review.
4. Require signed policy verification.
5. Require AgentShield validation artifact upload.

## Example Output

```json
{
  "valid": false,
  "session_id": "sess-001",
  "failures": [
    "Audit contains 1 block action(s)."
  ],
  "summary": {
    "tool": "claude-code",
    "repo": "/repo",
    "policy_pack": "banking-regulated-ai",
    "action_count": 3,
    "decisions": {
      "allow": 2,
      "block": 1
    }
  }
}
```
