# Policy Inheritance

AgentShield resolves policy layers in this order:

```text
enterprise -> business unit -> repository -> policy pack
```

## Resolve

```bash
terraguard-agentshield policy resolve \
  --enterprise banking-regulated-ai \
  --business-unit mcp-server-governance \
  --repository terraform-ai-guardrails \
  --output resolved-policy.json
```

## Use at Runtime

```bash
terraguard-agentshield agent exec "terraform apply -auto-approve" \
  --enterprise-policy banking-regulated-ai \
  --repository-policy terraform-ai-guardrails
```

Lists are additive, dictionaries merge recursively, and scalar values from narrower layers override broader layers.
