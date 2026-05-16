# GitHub Copilot Governance Example

GitHub Copilot coding agent works through GitHub pull requests. AgentShield fits this model by publishing a PR attestation and providing a required check that validates AI-agent evidence before merge.

Use this example when enabling Copilot coding agent in regulated repositories.

## Setup

1. Copy `copilot-instructions.md` to `.github/copilot-instructions.md`.
2. Add `examples/github-actions/agentshield-required-check.yml` to `.github/workflows/`.
3. Add repository or organization secret `AGENTSHIELD_POLICY_SECRET`.
4. Sign the approved policy pack:

```bash
export TERRAGUARD_AGENTSHIELD_POLICY_SECRET="replace-me"
terraguard-agentshield policy sign policies/banking-regulated-ai/policy.yaml \
  --signer platform-security
```

5. Configure branch protection to require `AgentShield Required Check`.

## Review Model

Copilot may create or update a pull request, but AgentShield makes the governance evidence visible to reviewers. Human review remains required for protected branches.
