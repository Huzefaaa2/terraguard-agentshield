# AgentShield Risky PR Demo

This directory is a non-deploying demo fixture. It intentionally contains risky Terraform-like snippets so AgentShield PR Guardian can demonstrate policy explanation, AI-agent detection, and reviewer evidence.

Run:

```bash
terraguard-agentshield pr guard \
  --diff examples/demo-risky-pr/change.diff \
  --policy-pack banking-regulated-ai \
  --fail-on high \
  --dry-run
```

Expected result: PR Guardian writes JSON and Markdown reports under `.terraguard/agentshield/pr-guardian` and exits non-zero because the diff contains critical and high-risk findings.
