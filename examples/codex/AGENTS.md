# AgentShield Governance Instructions for Codex

This repository uses TerraGuard AgentShield for AI-agent runtime governance evidence.

Before proposing a pull request or asking for merge:

1. Do not read `.env`, private keys, certificates, `terraform.tfstate`, `terraform.tfvars`, kubeconfig files, or other secret-bearing files.
2. Do not run `terraform apply`, `tofu apply`, `terraform destroy`, `kubectl delete`, or cloud IAM mutation commands.
3. Use AgentShield checks before high-risk actions:

```bash
terraguard-agentshield agent check-file .env --mode read
terraguard-agentshield agent exec "terraform plan" --policy-pack terraform-ai-guardrails
terraguard-agentshield evidence validate --audit-dir .terraguard/audit
```

4. If working on infrastructure code, use `terraform-ai-guardrails`.
5. If working in regulated application code, use `banking-regulated-ai`.
6. Include the AgentShield attestation in the pull request.

Protected branches require:

- signed policy verification
- AgentShield evidence validation
- independent human review
