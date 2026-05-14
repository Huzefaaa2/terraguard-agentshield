# Policy Authoring

AgentShield policies are YAML files. Each policy pack lives in `policies/<pack-id>/policy.yaml`.

## Example

```yaml
metadata:
  id: banking-regulated-ai
  title: Banking Regulated AI Governance
  version: 0.1.0

filesystem:
  block_read:
    - ".env"
    - "**/*.pem"
    - "**/terraform.tfstate"
  require_approval_write:
    - "**/iam/**"
    - "**/security/**"

commands:
  block:
    - "terraform apply*"
    - "kubectl delete*"
  require_approval:
    - "aws *"
    - "curl *"
  allow:
    - "terraform plan*"
    - "pytest*"

mcp:
  allowlist_enabled: true
  block_unknown_servers: true
  allowed_servers:
    - github-enterprise
    - jira-enterprise
```

Decision precedence:

1. Block
2. Require approval
3. Allow
4. Unknown command defaults to approval required
