# Policy Test Harness

AgentShield includes a policy test harness so teams can validate custom policy packs before rollout.

## Run Examples

```bash
terraguard-agentshield policy test examples/policy-tests/ai-agent-baseline.yaml

terraguard-agentshield policy test examples/policy-tests/mcp-server-governance.yaml \
  --format json \
  --output agentshield-policy-test.json
```

The command exits non-zero when any test case fails.

## Suite Format

```yaml
name: AI Agent Baseline Policy Tests
policy_pack: ai-agent-baseline
cases:
  - name: Block Terraform apply
    action: command
    command: terraform apply -auto-approve
    expect: block

  - name: Block .env reads
    action: file
    path: .env
    mode: read
    expect: block
```

Supported actions:

| Action | Required fields |
| --- | --- |
| `command` | `command`, `expect` |
| `file` | `path`, `expect` |
| `git` | `git_action`, `expect` |
| `mcp` | `server_id`, `expect` |

Expected decisions: `allow`, `block`, `require_approval`.

## Custom Policy Root

```bash
terraguard-agentshield policy test custom-suite.yaml \
  --policy-root ./policies \
  --format json
```
