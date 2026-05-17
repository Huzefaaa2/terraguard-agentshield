# Compliance Mappings

AgentShield maps its control families to common enterprise control frameworks so audit, GRC, and security teams can connect runtime AI-agent governance evidence to existing compliance programs.

The mappings are guidance for evidence preparation. They are not a compliance certification and should be reviewed against your formal scope by qualified assessors and internal control owners.

## CLI

List all mappings:

```bash
terraguard-agentshield compliance list
```

Map actual AgentShield evidence:

```bash
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

AgentShield currently includes mappings for:

| Framework | Mapping style |
| --- | --- |
| SOC 2 Trust Services | Trust Services categories and security themes |
| ISO/IEC 27001:2022 | Annex A-style control references |
| PCI DSS v4.0.1 | Requirement-area references |
| NIST SSDF SP 800-218 | SSDF practice references |
| Internal AI governance | AgentShield-specific governance IDs |

## Control Families

| AgentShield family | Example use |
| --- | --- |
| `application-security` | AI-generated app code and secure development evidence |
| `audit-monitoring` | Logs, evidence, monitoring, and traceability |
| `change-management` | PR flow, protected branches, and human approval |
| `data-protection` | Secrets, sensitive files, tfstate, tfvars, keys |
| `identity-access` | IAM, roles, access rights, privilege expansion |
| `infrastructure-change` | Terraform, OpenTofu, Kubernetes, cloud runtime changes |
| `network-security` | Public exposure and network control changes |
| `runtime-governance` | Agent execution policy and runtime control |
| `source-control` | Repository and file-change governance |
| `tool-governance` | MCP/tool allowlisting and third-party tool access |

## Example Output

```json
{
  "active_mappings": {
    "data-protection": {
      "activity": {
        "actions": 1,
        "findings": 1
      },
      "frameworks": {
        "soc2": ["Security", "Confidentiality", "Privacy"],
        "iso27001": ["A.5.12", "A.5.15", "A.8.11", "A.8.24"],
        "pci_dss": ["3.3", "3.4", "4.2"],
        "nist_ssdf": ["PO.5", "PS.3"],
        "internal_ai_governance": ["AI-DATA-01", "AI-SECRETS-01"]
      }
    }
  }
}
```

## References

- NIST SP 800-218 SSDF: https://csrc.nist.gov/pubs/sp/800/218/final
- PCI DSS overview and document library: https://www.pcisecuritystandards.org/standards/pci-dss/
- AICPA SOC 2 and Trust Services Criteria resources: https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2
