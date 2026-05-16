# Risk Classification

AgentShield can classify semantic risk in source-code and IaC diffs.

```bash
git diff main...HEAD > change.diff

terraguard-agentshield risk diff change.diff \
  --format json \
  --output agentshield-risk.json \
  --fail-on high
```

## Current Signals

| Category | Severity |
| --- | --- |
| Public internet exposure | Critical |
| Broad IAM/admin privilege | Critical |
| Added secrets or secret-bearing files | High |
| Encryption weakened or removed | High |
| TLS verification disabled or weak hashes | High |
| Logging/audit weakened or removed | Medium |
| Auth/JWT/OAuth/crypto/payment paths changed | Medium |

## Decisions

| Max risk | Decision |
| --- | --- |
| Critical | `block` |
| High | `require_approval` |
| Medium | `warn` |
| Low/no findings | `pass` |
