# Compliance Mapping Examples

AgentShield maps control families to common enterprise frameworks for evidence preparation.

List all mappings:

```bash
terraguard-agentshield compliance list
```

Map actual audit evidence:

```bash
terraguard-agentshield compliance map \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-compliance-map.json
```

The mapping is guidance for audit evidence preparation. Formal control applicability should be confirmed with your assessor and internal control owners.
