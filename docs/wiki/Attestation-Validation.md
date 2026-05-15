# Attestation Validation

AgentShield can validate audit evidence in CI so protected branches can require governed AI-agent activity.

## Validate

```bash
terraguard-agentshield evidence validate \
  --audit-dir .terraguard/audit \
  --fail-on block,require_approval
```

## Required Check

Use `examples/github-actions/agentshield-required-check.yml`.

Recommended branch protection:

1. Require `AgentShield Required Check`.
2. Require independent human review.
3. Require signed policy verification.
4. Require AgentShield validation output.
