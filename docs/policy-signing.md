# Policy Signing

AgentShield supports detached signatures for YAML policy packs. This lets enterprises require verified policy bundles in CI before a protected branch can merge.

Two signing modes are supported:

| Mode | Use case |
| --- | --- |
| `ED25519` | Recommended for enterprise CI because verification uses only a public key |
| `HMAC-SHA256` | Simple shared-secret signing for small teams and local pilots |

## Generate an Ed25519 Key Pair

```bash
terraguard-agentshield policy keygen \
  --private-key .terraguard/keys/policy-private.pem \
  --public-key .terraguard/keys/policy-public.pem
```

Store the private key in a secure signing environment. Put the public key in CI or a repository-controlled trusted-key location.

## Sign a Policy Pack

Recommended asymmetric signing:

```bash
terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml \
  --private-key .terraguard/keys/policy-private.pem \
  --signer platform-security
```

Shared-secret signing:

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
  "algorithm": "ED25519",
  "policy_id": "banking-regulated-ai",
  "policy_version": "0.1.0",
  "digest": "...",
  "signature": "...",
  "key_id": "...",
  "signer": "platform-security",
  "signed_at": "2026-05-15T00:00:00Z"
}
```

## Verify a Policy Pack

Recommended asymmetric verification:

```bash
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml \
  --public-key .terraguard/keys/policy-public.pem
```

Shared-secret verification:

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
  run: |
    terraguard-agentshield policy verify \
      policies/banking-regulated-ai/policy.yaml \
      --signature policies/banking-regulated-ai/policy.yaml.sig \
      --public-key .github/agentshield/policy-public.pem
```

## Operational Guidance

- Prefer Ed25519 signatures for protected branch checks.
- Keep private signing keys in organization-level secret stores.
- Rotate signing keys on a regular schedule.
- Re-sign policy packs after every approved policy change.
- Require policy verification in protected branch checks.
- Review signature files like code, since they define which policy content was approved.
