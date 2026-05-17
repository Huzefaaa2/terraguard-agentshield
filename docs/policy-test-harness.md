# Policy Test Harness

AgentShield includes a policy test harness so teams can validate custom policy packs before using them in developer workstations, hooks, CI, or protected branch checks.

## Run Built-In Examples

```bash
terraguard-agentshield policy test examples/policy-tests/ai-agent-baseline.yaml

terraguard-agentshield policy test examples/policy-tests/mcp-server-governance.yaml \
  --format json \
  --output agentshield-policy-test.json
```

The command exits non-zero when any test case fails, so it can be used directly in CI.

## Test Suite Format

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

  - name: Block direct push to main
    action: git
    git_action: push
    target: refs/heads/main
    expect: block

  - name: Allow approved GitHub MCP read
    action: mcp
    server_id: github-enterprise
    capability: read_repo
    expect: allow
```

## Supported Actions

| Action | Required fields | Optional fields |
| --- | --- | --- |
| `command` | `command`, `expect` | none |
| `file` | `path`, `expect` | `mode` |
| `git` | `git_action`, `expect` | `target` |
| `mcp` | `server_id`, `expect` | `capability` |

Expected decisions:

- `allow`
- `block`
- `require_approval`

## Custom Policy Root

```bash
terraguard-agentshield policy test custom-suite.yaml \
  --policy-root ./policies \
  --format json
```

The policy root should contain policy pack directories:

```text
policies/
  custom-banking-policy/
    policy.yaml
```

## CI Pattern

```yaml
- name: Test AgentShield policy pack
  run: |
    terraguard-agentshield policy test examples/policy-tests/ai-agent-baseline.yaml
```

Use this before signing policy bundles or promoting policy changes into regulated repositories.
