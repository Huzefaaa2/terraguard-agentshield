from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from terraguard_agentshield.policy_registry import PolicyRegistry


@dataclass(frozen=True)
class ActionDecision:
    decision: str
    reason: str | None = None


class RuntimeGuard:
    def __init__(self, policy_pack: str | None = None) -> None:
        self.registry = PolicyRegistry()
        self.policy = self.registry.load_policy(policy_pack or "ai-agent-baseline")
        self.sensitive_read = self._patterns("filesystem", "block_read")
        self.sensitive_write = self._patterns("filesystem", "block_write")
        self.approval_write = self._patterns("filesystem", "require_approval_write")
        self.command_block = self._patterns("commands", "block")
        self.command_approval = self._patterns("commands", "require_approval")
        self.command_allow = self._patterns("commands", "allow")

    def _patterns(self, section: str, key: str) -> list[str]:
        items = self.policy.get(section, {}).get(key, [])
        if not isinstance(items, list):
            return []
        return [str(item) for item in items if item is not None]

    def evaluate_file_access(self, path: Path, mode: str) -> ActionDecision:
        target = self._normalise_path(path)
        normalised_mode = mode.lower()

        if normalised_mode == "read":
            for pattern in self.sensitive_read:
                if self._match_pattern(target, pattern):
                    return ActionDecision("block", f"Matched sensitive path policy: {pattern}")
            return ActionDecision("allow")

        if normalised_mode != "write":
            return ActionDecision("require_approval", f"Unknown file access mode: {mode}")

        for pattern in self.sensitive_write:
            if self._match_pattern(target, pattern):
                return ActionDecision("block", f"Matched protected write policy: {pattern}")

        for pattern in self.approval_write:
            if self._match_pattern(target, pattern):
                return ActionDecision("require_approval", f"Matched approval-required write policy: {pattern}")

        return ActionDecision("allow")

    def evaluate_command(self, command: str) -> ActionDecision:
        cleaned = command.strip()
        for pattern in self.command_block:
            if self._match_pattern(cleaned, pattern):
                return ActionDecision("block", f"Matched blocked command policy: {pattern}")
        for pattern in self.command_approval:
            if self._match_pattern(cleaned, pattern):
                return ActionDecision("require_approval", f"Matched approval-required command policy: {pattern}")
        for pattern in self.command_allow:
            if self._match_pattern(cleaned, pattern):
                return ActionDecision("allow")
        return ActionDecision("require_approval", "No allow rule matched; review required.")

    def evaluate_git_action(self, action: str, target: str | None = None) -> ActionDecision:
        git_policy = self.policy.get("git", {})
        protected = git_policy.get("protected_branches", ["main", "master"])
        block_direct_push = git_policy.get("block_direct_push_to_protected_branch", True)

        if action == "push" and target and block_direct_push:
            if any(target.endswith(str(branch)) for branch in protected):
                return ActionDecision("block", "Direct push to protected branch is blocked.")
        return ActionDecision("allow")

    def evaluate_mcp_server(self, server_id: str, capability: str | None = None) -> ActionDecision:
        mcp_policy = self.policy.get("mcp", {})
        if not isinstance(mcp_policy, dict):
            return ActionDecision("allow")

        blocked_servers = {str(server) for server in mcp_policy.get("blocked_servers", [])}
        allowed_servers = {str(server) for server in mcp_policy.get("allowed_servers", [])}
        allowlist_enabled = bool(mcp_policy.get("allowlist_enabled", False))
        block_unknown = bool(mcp_policy.get("block_unknown_servers", False))

        if server_id in blocked_servers:
            return ActionDecision("block", f"MCP server is explicitly blocked: {server_id}")

        if allowlist_enabled and server_id not in allowed_servers:
            decision = "block" if block_unknown else "require_approval"
            return ActionDecision(decision, f"MCP server is not in the allowlist: {server_id}")

        capability_rules = mcp_policy.get("capabilities", {})
        if capability and isinstance(capability_rules, dict):
            blocked_capabilities = capability_rules.get(server_id, {}).get("block", [])
            for blocked in blocked_capabilities:
                if self._match_pattern(capability, str(blocked)):
                    return ActionDecision("block", f"MCP capability is blocked for {server_id}: {blocked}")

        risk_scoring = mcp_policy.get("risk_scoring", {})
        risk = risk_scoring.get(server_id) if isinstance(risk_scoring, dict) else None
        if risk == "high":
            return ActionDecision("require_approval", f"MCP server is high risk: {server_id}")

        return ActionDecision("allow", f"MCP server allowed: {server_id}")

    @staticmethod
    def _normalise_path(path: Path) -> str:
        return str(path).replace("\\", "/")

    @staticmethod
    def _match_pattern(value: str, pattern: str) -> bool:
        candidates = [value, value.lstrip("./")]

        try:
            path_name = Path(value).name
            if path_name:
                candidates.append(path_name)
        except ValueError:
            pass

        normalised_pattern = pattern.replace("\\", "/")
        pattern_candidates = [normalised_pattern]
        if "/" not in normalised_pattern:
            pattern_candidates.append(f"**/{normalised_pattern}")

        return any(
            fnmatch.fnmatchcase(candidate, candidate_pattern)
            for candidate in candidates
            for candidate_pattern in pattern_candidates
        )
