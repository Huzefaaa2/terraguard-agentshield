# Policy Authoring Guide

TerraGuard AgentShield policies are YAML-based rule sets that govern AI agent behavior at runtime. This guide explains how to author, test, and deploy custom policies.

## Policy structure

Every policy pack is a YAML file with metadata and rule sections:

```yaml
metadata:
  id: my-policy
  title: My Custom Policy
  description: Description of what this policy controls
  version: 1.0.0

filesystem:
  block_read: []    # Paths that agents cannot read
  block_write: []   # Paths that agents cannot write
  require_approval_write: []  # Paths that require human approval

commands:
  block: []         # Commands that are forbidden
  allow: []         # Commands that are explicitly permitted
  require_approval: []  # Commands that need approval

git:
  require_pull_request: true
  block_direct_push_to_protected_branch: true
  require_human_reviewer: true
  require_ai_attestation: true

mcp:
  allowlist_enabled: true
  allowed_servers: []
  blocked_servers: []
```

## Writing patterns

### Filesystem rules

Use glob patterns for flexible path matching:

```yaml
filesystem:
  block_read:
    - ".env"           # Exact match
    - "**/*.pem"       # Wildcard match
    - "**/secrets/**"  # Directory pattern
    - "*.tfvars"       # File pattern
```

### Command rules

Commands are matched against the full command string:

```yaml
commands:
  block:
    - "terraform apply*"   # Block terraform apply and variants
    - "kubectl delete*"    # Block kubectl delete
  allow:
    - "terraform fmt*"     # Allow formatting
    - "git*"               # Allow git operations
```

### Policy pack inheritance

Policy pack inheritance is planned for a future release. In the current MVP, create one composed policy pack per environment or team.

Recommended structure:

```text
policies/
  platform-banking-ai/
    policy.yaml
  payments-ai/
    policy.yaml
  developer-sandbox-ai/
    policy.yaml
```

Within a policy pack, decision precedence is block, then require approval, then allow.

## Best practices

1. **Start permissive, tighten over time**
   - Begin with `ai-agent-baseline`
   - Add stricter rules incrementally
   - Monitor blocked actions and iterate

2. **Use semantic rule names**
   - `block_dangerous_commands`
   - `protect_secrets`
   - `enforce_infrastructure_safety`

3. **Document every rule**
   ```yaml
   metadata:
    rules:
      - name: "Prevent secret exposure"
        description: "Block access to .env files and secret stores"
        target: "filesystem:block_read"
        compliance: "PCI DSS 3.5.1"
  ```

4. **Test policies locally**
   ```bash
   # Test that a command is blocked
   terraguard-agentshield agent exec "terraform apply" \
     --policy-pack my-custom-policy
   ```

5. **Version your policies**
   - Update version in metadata when rules change
   - Keep a changelog
   - Reference policy versions in audit trails

## Common patterns

### Banking and regulated workloads

```yaml
filesystem:
  block_read:
    - ".env"
    - "**/*.tfvars"
    - "**/terraform.tfstate"

commands:
  block:
    - "terraform apply*"
    - "kubectl apply*"
    - "aws iam*"
```

### Terraform-specific

```yaml
filesystem:
  block_write:
    - "**/modules/**"
    - "**/.terraform/**"
  require_approval_write:
    - "**/main.tf"

commands:
  allow:
    - "terraform fmt*"
    - "terraform plan*"
    - "terraform validate*"
  block:
    - "terraform apply*"
    - "terraform destroy*"
```

### Development vs production

Create separate packs:

```yaml
# dev.yaml
commands:
  allow:
    - "terraform plan*"
    - "pytest*"
    - "npm test*"

# prod.yaml
commands:
  block:
    - "terraform apply*"
    - "kubectl patch*"
  require_approval:
    - "aws*"
```

## Validation

Validate your policy YAML:

```bash
# Parse and list rules
terraguard-agentshield policy describe my-custom-policy

# Test against a command
terraguard-agentshield agent exec "my-test-command" --policy-pack my-custom-policy

# Test file access
terraguard-agentshield agent check-file .env --mode read --policy-pack my-custom-policy

# Test MCP access
terraguard-agentshield agent check-mcp github-enterprise --capability read_repo
```
