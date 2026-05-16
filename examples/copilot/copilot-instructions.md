# AgentShield Governance Instructions for GitHub Copilot

This repository uses TerraGuard AgentShield to validate AI-assisted pull requests.

When working on this repository:

- Do not modify protected branch workflows unless explicitly requested.
- Do not introduce direct cloud or infrastructure apply steps.
- Do not read or expose secret-bearing files such as `.env`, certificates, tfstate, tfvars, kubeconfigs, or private keys.
- Prefer changes that can be validated through tests, plans, and pull request review.
- Keep AI-generated changes reviewable and explainable.

Pull requests must pass:

- AgentShield signed policy verification
- AgentShield evidence validation
- Independent human review

If you make infrastructure changes, expect the reviewer to require AgentShield attestation and Terraform plan evidence.
