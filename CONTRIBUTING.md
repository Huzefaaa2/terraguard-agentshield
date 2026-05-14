# Contributing to TerraGuard AgentShield

Thank you for your interest in contributing! This document provides guidelines for contributing to the TerraGuard AgentShield project.

## Code of Conduct

Be respectful, inclusive, and professional. We follow the Contributor Covenant.

## Getting started

1. Fork the repository
2. Clone your fork
3. Create a virtual environment: `python3 -m venv .venv && source .venv/bin/activate`
4. Install in development mode: `pip install -e ".[dev]"`
5. Run tests: `pytest tests -v`

## Contribution process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Add tests for new functionality
4. Run tests and linting:
   ```bash
   ruff check src/ tests/
   pytest tests -v
   ```
5. Commit with clear messages: `git commit -m "Add description of change"`
6. Push and open a pull request

## Code style

- Use Python 3.10+ type hints
- Follow PEP 8
- Format with `black` (enforced by ruff)
- Max line length: 100 characters

## Testing

- Add unit tests for all new features
- Add integration tests for workflows
- Aim for >80% code coverage
- Use `pytest` fixtures for test data

## Documentation

- Update README.md for user-facing changes
- Update docs/ for architectural changes
- Add docstrings to new functions/classes
- Include examples in policy authoring guides

## Policy packs

- Add new policy packs to `policies/`
- Include metadata (id, title, description, version)
- Test policies with `terraguard-agentshield agent exec`
- Document use cases and threat coverage

## Reporting issues

- Use GitHub Issues
- Include steps to reproduce
- Provide audit logs if applicable
- Suggest a fix if you have one

## Questions?

Open an issue or reach out on LinkedIn: https://www.linkedin.com/in/huzefaaa
