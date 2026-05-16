# Policy Inheritance

AgentShield resolves layered policy packs into one effective policy.

Merge order:

```text
enterprise -> business unit -> repository -> policy pack
```

## Resolve a Policy

```bash
terraguard-agentshield policy resolve \
  --enterprise banking-regulated-ai \
  --business-unit mcp-server-governance \
  --repository terraform-ai-guardrails \
  --output resolved-policy.json
```

## Runtime Checks with Layers

```bash
terraguard-agentshield agent exec "terraform apply -auto-approve" \
  --enterprise-policy banking-regulated-ai \
  --repository-policy terraform-ai-guardrails
```

```bash
terraguard-agentshield hooks claude \
  --enterprise-policy banking-regulated-ai \
  --business-unit-policy mcp-server-governance \
  --repository-policy terraform-ai-guardrails
```

## Merge Semantics

| Data type | Behavior |
| --- | --- |
| Lists | Additive, de-duplicated in first-seen order |
| Dictionaries | Recursive merge |
| Scalars | Narrower layer overrides broader layer |

Resolved policies include `metadata.resolved_layers` for audit and troubleshooting.
