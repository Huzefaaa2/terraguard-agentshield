# Policy Signing

AgentShield supports detached signatures for YAML policy packs. This lets enterprises require verified policy bundles in CI before a protected branch can merge.

The current implementation uses HMAC-SHA256 with a shared secret. This keeps the release dependency-light and easy to run in GitHub Actions. Enterprises can store the secret in GitHub repository or organization secrets. Asymmetric signing can be layered later without changing the policy schema.

## Sign a Policy Pack

```bash
export TERRAGUARD_AGENTSHIELD_POLICY_SECRET="replace-me"
terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml \
  --signer platform-security
```

This writes:

```text
policies/banking-regulated-ai/policy.yaml.sig
```

Signature payload:

```json
{
  "schema": "terraguard-agentshield.policy-signature.v1",
  "algorithm": "HMAC-SHA256",
  "policy_id": "banking-regulated-ai",
  "policy_version": "0.1.0",
  "digest": "...",
  "signature": "...",
  "signer": "platform-security",
  "signed_at": "2026-05-15T00:00:00Z"
}
```

## Verify a Policy Pack

```bash
export TERRAGUARD_AGENTSHIELD_POLICY_SECRET="replace-me"
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml
```

Explicit signature path:

```bash
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml \
  --signature policies/banking-regulated-ai/policy.yaml.sig
```

## GitHub Actions

```yaml
- name: Verify signed policy pack
  env:
    TERRAGUARD_AGENTSHIELD_POLICY_SECRET: ${{ secrets.AGENTSHIELD_POLICY_SECRET }}
  run: |
    terraguard-agentshield policy verify \
      policies/banking-regulated-ai/policy.yaml \
      --signature policies/banking-regulated-ai/policy.yaml.sig
```

## Operational Guidance

- Keep signing secrets in organization-level secret stores.
- Rotate signing secrets on a regular schedule.
- Re-sign policy packs after every approved policy change.
- Require policy verification in protected branch checks.
- Review signature files like code, since they define which policy content was approved.
