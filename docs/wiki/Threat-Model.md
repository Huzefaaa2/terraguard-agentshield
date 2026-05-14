# Threat Model

AgentShield addresses these AI-agent risks:

| Threat | Example | Control |
| --- | --- | --- |
| Secret exposure | Agent reads `.env`, tfstate, private keys | `filesystem.block_read` |
| Unsafe infrastructure change | Agent runs `terraform apply` | `commands.block` |
| Privilege escalation | Agent creates IAM keys or role assignments | command block and approval rules |
| Direct branch bypass | Agent pushes to `main` | protected branch Git decision |
| MCP tool sprawl | Agent connects to unknown tools | MCP allowlist/blocklist |
| Audit gap | No evidence of agent actions | JSON session audit and PR attestation |

Defense-in-depth:

1. Configuration governance
2. Runtime policy decisions
3. Audit evidence
4. Independent human review
5. SIEM/GRC export roadmap
