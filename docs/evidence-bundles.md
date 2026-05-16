# Signed Evidence Bundles

AgentShield can package session audit evidence, semantic risk output, policy signature metadata, validation results, and change metadata into one signed JSON artifact.

Use signed bundles when CI, SIEM, Jira, ServiceNow, and audit archives need the same tamper-evident evidence object.

## Create a Bundle

```bash
terraguard-agentshield evidence bundle \
  --session-id <session-id> \
  --audit-dir .terraguard/audit \
  --risk agentshield-risk.json \
  --policy-signature policies/banking-regulated-ai/policy.yaml.sig \
  --validation agentshield-validation.json \
  --metadata change=CHG123 \
  --metadata repo=payments-iac \
  --private-key .terraguard/keys/evidence-private.pem \
  --output agentshield-evidence-bundle.json
```

## Verify a Bundle

```bash
terraguard-agentshield evidence verify-bundle agentshield-evidence-bundle.json \
  --public-key .terraguard/keys/evidence-public.pem \
  --output agentshield-evidence-verification.json
```

## Bundle Contents

| Field | Purpose |
| --- | --- |
| `audit` | AgentShield session audit JSON |
| `risk` | Optional output from `risk diff` |
| `policy_signature` | Optional policy bundle signature metadata |
| `validation` | Optional evidence validation result |
| `metadata` | Caller-supplied change, repo, environment, or control metadata |
| `signature` | Ed25519 signature over the canonical bundle payload |

## Recommended CI Flow

1. Run AgentShield session checks and capture audit evidence.
2. Run `risk diff` and write `agentshield-risk.json`.
3. Verify signed policy packs.
4. Run `evidence validate`.
5. Create a signed evidence bundle.
6. Upload the bundle as a CI artifact and route it to SIEM, Jira, or ServiceNow.
