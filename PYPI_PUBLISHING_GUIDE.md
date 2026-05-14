# PyPI Publishing Guide

This guide describes how to publish TerraGuard AgentShield to PyPI and create a GitHub release.

## Prerequisites

1. GitHub repository access.
2. PyPI account.
3. PyPI API token.
4. Local Python 3.10+ environment.

## 1. Build Locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pip install build twine
```

Run verification:

```bash
ruff check .
pytest -q
```

Build:

```bash
rm -rf dist build *.egg-info
python -m build
twine check dist/*
```

Expected artifacts:

- `dist/terraguard_agentshield-<version>-py3-none-any.whl`
- `dist/terraguard_agentshield-<version>.tar.gz`

## 2. Test the Built Wheel

```bash
python -m venv /tmp/agentshield-wheel-test
source /tmp/agentshield-wheel-test/bin/activate
pip install dist/terraguard_agentshield-*.whl
terraguard-agentshield version
terraguard-agentshield policy list
```

The package should include built-in policy packs. Verify `policy list` shows:

- `ai-agent-baseline`
- `banking-regulated-ai`
- `terraform-ai-guardrails`
- `mcp-server-governance`

## 3. Upload to TestPyPI

```bash
twine upload --repository testpypi dist/*
```

Use:

- Username: `__token__`
- Password: your TestPyPI API token

Install from TestPyPI in a clean environment:

```bash
python -m venv /tmp/agentshield-testpypi
source /tmp/agentshield-testpypi/bin/activate
pip install --index-url https://test.pypi.org/simple/ terraguard-agentshield
terraguard-agentshield version
terraguard-agentshield policy list
```

## 4. Publish to PyPI

```bash
twine upload dist/*
```

Use:

- Username: `__token__`
- Password: your PyPI API token

Verify:

```bash
python -m venv /tmp/agentshield-pypi
source /tmp/agentshield-pypi/bin/activate
pip install terraguard-agentshield
terraguard-agentshield version
terraguard-agentshield policy list
```

## 5. Create GitHub Release

Create and push a tag:

```bash
git tag -a v0.1.0 -m "Release TerraGuard AgentShield v0.1.0"
git push origin v0.1.0
```

Release title:

```text
TerraGuard AgentShield v0.1.0 - Agent Firewall Foundation
```

Release summary:

TerraGuard AgentShield v0.1.0 introduces the agent-firewall foundation for runtime governance of AI coding agents in regulated engineering environments.

Implemented:

- YAML policy packs
- File access decisions
- Command allow/block/approval decisions
- MCP server and capability decisions
- Protected branch Git decision model
- JSON session audit
- PR-ready markdown attestation
- CLI workflows
- README, architecture, C4, threat model, roadmap, and wiki source docs

Install:

```bash
pip install terraguard-agentshield
```

Verify:

```bash
terraguard-agentshield version
terraguard-agentshield policy list
```

## 6. GitHub Repository Settings

Recommended branch protection for `main`:

- Require pull request before merging.
- Require one independent reviewer.
- Require status checks.
- Require branches to be up to date.
- Restrict direct pushes.

Required repository secrets:

- `PYPI_API_TOKEN`

## 7. Troubleshooting

### 401 Unauthorized

Verify the PyPI token and ensure it belongs to the target project or account.

### File Already Exists

PyPI does not allow replacing published files. Increment the version and rebuild.

### Policies Missing After Install

Check:

```bash
python -m build
twine check dist/*
terraguard-agentshield policy list
```

The `pyproject.toml` package-data entry and `MANIFEST.in` should include `src/terraguard_agentshield/policies/*/policy.yaml`.

## 8. Future Release Checklist

1. Update `pyproject.toml` and `setup.py` version.
2. Update `RELEASE_NOTES.md`.
3. Run `ruff check .`.
4. Run `pytest -q`.
5. Build with `python -m build`.
6. Run `twine check dist/*`.
7. Publish to TestPyPI.
8. Publish to PyPI.
9. Create GitHub tag and release.
10. Monitor GitHub Actions and PyPI installation.
