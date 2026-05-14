# Enterprise Adoption

## Pilot Sequence

1. Select one regulated non-production repository.
2. Start with `ai-agent-baseline`.
3. Audit common AI-agent actions.
4. Block secret reads.
5. Block destructive infrastructure and cloud commands.
6. Require approval for IAM, security, workflow, and production-impacting writes.
7. Attach AgentShield attestation to pull requests.
8. Tune policies weekly during pilot.

## Enterprise Control Mapping

| Control family | AgentShield evidence |
| --- | --- |
| Secure SDLC | Command and file decisions |
| Change management | Approval-required actions |
| Access control | MCP allowlist and sensitive path blocking |
| Data protection | Secret-read blocks |
| Audit | Session JSON and PR markdown |

## What to Avoid

- Treating AI review as independent human approval.
- Allowing personal MCP servers in regulated repos.
- Relying only on instruction files for security-critical controls.
- Waiting until CI to understand what the agent did.
