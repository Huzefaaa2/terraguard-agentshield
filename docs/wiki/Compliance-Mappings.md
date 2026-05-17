# Compliance Mappings

AgentShield maps control families to common enterprise frameworks for audit, GRC, and security evidence preparation.

These mappings are guidance and must be reviewed against your formal control scope by qualified assessors and internal control owners.

## CLI

```bash
terraguard-agentshield compliance list

terraguard-agentshield compliance map \
  --audit-dir .terraguard/audit \
  --bundle-dir .terraguard/agentshield/evidence \
  --format json \
  --output agentshield-compliance-map.json
```

## API

```bash
curl -s http://127.0.0.1:8000/compliance/mappings | jq .
curl -s http://127.0.0.1:8000/compliance/summary | jq .
```

## Frameworks

- SOC 2 Trust Services
- ISO/IEC 27001:2022
- PCI DSS v4.0.1
- NIST SSDF SP 800-218
- Internal AI governance controls

## Control Families

| AgentShield family | Example use |
| --- | --- |
| `data-protection` | Secrets, sensitive files, tfstate, tfvars, keys |
| `identity-access` | IAM, roles, access rights, privilege expansion |
| `infrastructure-change` | Terraform, Kubernetes, cloud runtime changes |
| `network-security` | Public exposure and network control changes |
| `tool-governance` | MCP/tool allowlisting and third-party tool access |

## References

- NIST SP 800-218 SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- PCI DSS overview and document library: https://www.pcisecuritystandards.org/standards/pci-dss/
- AICPA SOC 2 and Trust Services Criteria resources: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
