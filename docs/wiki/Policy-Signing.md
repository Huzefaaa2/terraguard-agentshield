# Policy Signing

AgentShield supports detached signatures for YAML policy packs.

Use `ED25519` for enterprise CI so protected branches can verify policy bundles with a public key. `HMAC-SHA256` remains available for shared-secret pilots.

## Generate Keys

```bash
terraguard-agentshield policy keygen \
  --private-key .terraguard/keys/policy-private.pem \
  --public-key .terraguard/keys/policy-public.pem
```

## Sign

Asymmetric signing:

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

## Verify

```bash
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml \
  --signature policies/banking-regulated-ai/policy.yaml.sig \
  --public-key .terraguard/keys/policy-public.pem
```

## CI Use

Store only the public key in CI. Keep the private key in a controlled signing environment and require verification before merge.
