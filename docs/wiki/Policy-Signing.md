# Policy Signing

AgentShield supports detached HMAC-SHA256 signatures for YAML policy packs.

## Sign

```bash
export TERRAGUARD_AGENTSHIELD_POLICY_SECRET="replace-me"
terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml \
  --signer platform-security
```

## Verify

```bash
terraguard-agentshield policy verify policies/banking-regulated-ai/policy.yaml \
  --signature policies/banking-regulated-ai/policy.yaml.sig
```

## CI Use

Store the signing secret in `AGENTSHIELD_POLICY_SECRET` and require verification before merge.
