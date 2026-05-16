# Semantic Risk Classification

AgentShield can classify semantic risk in source-code and Infrastructure-as-Code diffs before a pull request is approved.

This is intentionally deterministic in the current foundation. It looks for high-signal changes that regulated engineering teams usually want reviewed before merge.

## Classify a Diff

```bash
git diff main...HEAD > change.diff

terraguard-agentshield risk diff change.diff
```

JSON output:

```bash
terraguard-agentshield risk diff change.diff \
  --format json \
  --output agentshield-risk.json
```

Fail CI on high or critical risk:

```bash
terraguard-agentshield risk diff change.diff \
  --format json \
  --output agentshield-risk.json \
  --fail-on high
```

## Current Risk Signals

| Category | Examples | Default severity |
| --- | --- | --- |
| Public exposure | `0.0.0.0/0`, `::/0`, public source ranges | Critical |
| Privilege expansion | `Action: *`, `iam:*`, `AdministratorAccess`, owner roles | Critical |
| Secrets | Added tokens, passwords, API keys, `.env`, tfvars, private keys | High |
| Encryption weakening | Disabled encryption or removed KMS/encryption config | High |
| Logging weakening | Disabled or removed logging/audit settings | Medium |
| TLS/crypto weakness | `verify=False`, MD5/SHA1 in sensitive code | High |
| Sensitive source areas | Auth, JWT, OAuth, crypto, identity, payment paths | Medium |

## Output Model

```json
{
  "decision": "require_approval",
  "max_risk": "high",
  "finding_count": 1,
  "risk_counts": {
    "high": 1
  },
  "findings": [
    {
      "risk": "high",
      "category": "secrets",
      "title": "Potential secret introduced",
      "file": ".env",
      "line": 1,
      "evidence": "API_TOKEN=secret"
    }
  ]
}
```

## Decision Mapping

| Max risk | Decision |
| --- | --- |
| Critical | `block` |
| High | `require_approval` |
| Medium | `warn` |
| Low/no findings | `pass` |

## Recommended PR Workflow

1. Generate a diff in CI.
2. Run `terraguard-agentshield risk diff`.
3. Upload `agentshield-risk.json` as an artifact.
4. Fail the required check on high or critical risk.
5. Route high-risk findings to an independent human reviewer.

## Current Scope

The classifier is a deterministic foundation. Future work will add deeper semantic diff context, policy-pack-specific risk tuning, approval routing, and remediation suggestions.
