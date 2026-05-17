# Evidence Bundles

AgentShield signed evidence bundles combine audit, risk, validation, policy signature, and metadata into one tamper-evident JSON artifact.

## Create

```bash
terraguard-agentshield evidence bundle \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --risk agentshield-risk.json \
  --validation agentshield-validation.json \
  --metadata change=CHG123 \
  --private-key .terraguard/keys/evidence-private.pem \
  --output agentshield-evidence-bundle.json
```

## Verify

```bash
terraguard-agentshield evidence verify-bundle agentshield-evidence-bundle.json \
  --public-key .terraguard/keys/evidence-public.pem
```

## Summarize

```bash
terraguard-agentshield evidence summary \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-decision-summary.json
```
