from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from terraguard_agentshield.runtime import RuntimeGuard


@dataclass(frozen=True)
class PolicyTestCase:
    name: str
    action: str
    expect: str
    command: str | None = None
    path: str | None = None
    mode: str | None = None
    git_action: str | None = None
    target: str | None = None
    server_id: str | None = None
    capability: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicyTestCase":
        return cls(
            name=str(payload["name"]),
            action=str(payload["action"]),
            expect=str(payload["expect"]),
            command=_optional_str(payload.get("command")),
            path=_optional_str(payload.get("path")),
            mode=_optional_str(payload.get("mode")),
            git_action=_optional_str(payload.get("git_action")),
            target=_optional_str(payload.get("target")),
            server_id=_optional_str(payload.get("server_id")),
            capability=_optional_str(payload.get("capability")),
        )


@dataclass(frozen=True)
class PolicyTestSuite:
    name: str
    policy_pack: str | None = None
    enterprise_policy: str | None = None
    business_unit_policy: str | None = None
    repository_policy: str | None = None
    cases: list[PolicyTestCase] = field(default_factory=list)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicyTestSuite":
        cases = [
            PolicyTestCase.from_dict(item)
            for item in payload.get("cases", [])
            if isinstance(item, dict)
        ]
        return cls(
            name=str(payload.get("name") or "AgentShield policy test suite"),
            policy_pack=_optional_str(payload.get("policy_pack")),
            enterprise_policy=_optional_str(payload.get("enterprise_policy")),
            business_unit_policy=_optional_str(payload.get("business_unit_policy")),
            repository_policy=_optional_str(payload.get("repository_policy")),
            cases=cases,
        )


@dataclass(frozen=True)
class PolicyTestCaseResult:
    name: str
    action: str
    expected: str
    actual: str
    passed: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "action": self.action,
            "expected": self.expected,
            "actual": self.actual,
            "passed": self.passed,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class PolicyTestRunResult:
    suite: str
    policy_pack: str | None
    passed: bool
    case_count: int
    passed_count: int
    failed_count: int
    results: list[PolicyTestCaseResult]

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "policy_pack": self.policy_pack,
            "passed": self.passed,
            "case_count": self.case_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "results": [result.to_dict() for result in self.results],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


def load_policy_test_suite(path: Path) -> PolicyTestSuite:
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(payload, dict):
        raise ValueError(f"Policy test suite is not a mapping: {path}")
    return PolicyTestSuite.from_dict(payload)


def run_policy_test_suite(
    suite: PolicyTestSuite,
    policy_root: Path | None = None,
) -> PolicyTestRunResult:
    guard = RuntimeGuard(
        policy_pack=suite.policy_pack,
        enterprise_policy=suite.enterprise_policy,
        business_unit_policy=suite.business_unit_policy,
        repository_policy=suite.repository_policy,
        policy_root=policy_root,
    )
    results = [_run_case(guard, case) for case in suite.cases]
    passed_count = len([result for result in results if result.passed])
    failed_count = len(results) - passed_count
    return PolicyTestRunResult(
        suite=suite.name,
        policy_pack=suite.policy_pack,
        passed=failed_count == 0,
        case_count=len(results),
        passed_count=passed_count,
        failed_count=failed_count,
        results=results,
    )


def run_policy_test_file(
    path: Path,
    policy_root: Path | None = None,
) -> PolicyTestRunResult:
    return run_policy_test_suite(load_policy_test_suite(path), policy_root=policy_root)


def render_text_result(result: PolicyTestRunResult) -> str:
    lines = [
        "TerraGuard AgentShield Policy Test Result",
        "",
        f"Suite: {result.suite}",
        f"Policy pack: {result.policy_pack or 'resolved default'}",
        f"Passed: {result.passed_count}/{result.case_count}",
        "",
    ]
    for case in result.results:
        status = "PASS" if case.passed else "FAIL"
        lines.append(
            f"- {status} {case.name}: expected {case.expected}, got {case.actual}"
        )
        if case.reason:
            lines.append(f"  {case.reason}")
    return "\n".join(lines)


def _run_case(guard: RuntimeGuard, case: PolicyTestCase) -> PolicyTestCaseResult:
    decision = _evaluate_case(guard, case)
    return PolicyTestCaseResult(
        name=case.name,
        action=case.action,
        expected=case.expect,
        actual=decision.decision,
        passed=decision.decision == case.expect,
        reason=decision.reason,
    )


def _evaluate_case(guard: RuntimeGuard, case: PolicyTestCase):
    if case.action == "command":
        if not case.command:
            raise ValueError(f"Policy test case '{case.name}' is missing command.")
        return guard.evaluate_command(case.command)
    if case.action == "file":
        if not case.path:
            raise ValueError(f"Policy test case '{case.name}' is missing path.")
        return guard.evaluate_file_access(Path(case.path), case.mode or "read")
    if case.action == "git":
        if not case.git_action:
            raise ValueError(f"Policy test case '{case.name}' is missing git_action.")
        return guard.evaluate_git_action(case.git_action, target=case.target)
    if case.action == "mcp":
        if not case.server_id:
            raise ValueError(f"Policy test case '{case.name}' is missing server_id.")
        return guard.evaluate_mcp_server(case.server_id, capability=case.capability)
    raise ValueError(f"Unsupported policy test action: {case.action}")


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)
