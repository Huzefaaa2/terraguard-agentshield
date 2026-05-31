# AgentShield PR Guardian

PR Guardian is a GitHub-native pull-request firewall for AI-assisted engineering. It reads a PR diff, detects AI-agent signals, classifies semantic risk, explains policy decisions, writes evidence artifacts, and can publish one reviewer-ready PR comment.

## Local Use

```bash
git diff origin/main...HEAD > change.diff

terraguard-agentshield pr guard \
  --diff change.diff \
  --policy-pack banking-regulated-ai \
  --fail-on high \
  --output-dir .terraguard/agentshield/pr-guardian
```

## GitHub Actions

Copy `examples/github-actions/agentshield-pr-guardian.yml` into `.github/workflows/`.

Artifacts:

- `agentshield-pr-guardian.json`
- `agentshield-pr-guardian.md`
- `agentshield-policy-explanation.md`

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Risk is below threshold |
| `1` | Risk meets or exceeds threshold, or publishing failed |
| `2` | Configuration or input error |

```mermaid
sequenceDiagram
    participant Agent as AI Coding Agent
    participant PR as GitHub Pull Request
    participant Actions as GitHub Actions
    participant Shield as AgentShield PR Guardian
    participant Reviewer as Reviewer

    Agent->>PR: Opens or updates PR
    PR->>Actions: Triggers pull_request workflow
    Actions->>Shield: Provides diff and event metadata
    Shield->>Shield: Detects AI-agent signals
    Shield->>Shield: Classifies semantic risk
    Shield->>Shield: Explains policy decision
    Shield->>PR: Publishes governance comment
    Shield->>Actions: Returns pass/fail status
    Reviewer->>PR: Reviews risk, explanation, and evidence
```
