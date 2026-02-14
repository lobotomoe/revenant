# Contributing to Revenant

Thank you for your interest in contributing to Revenant.

## Getting Started

### Prerequisites

- Python 3.10 or later
- Git

### Development Setup

```bash
git clone https://github.com/lobotomoe/revenant.git
cd revenant/python
pip install -e ".[dev]"
```

### Running Checks

```bash
# Lint and format
ruff check src/ tests/ scripts/
ruff format --check src/ tests/ scripts/

# Type check (strict mode, 0 errors expected)
pyright src/

# Tests (expects 96%+ coverage)
pytest

# Security audit
pip install pip-audit
pip-audit --skip-editable --ignore-vuln CVE-2024-23342
```

All four checks must pass before submitting a pull request. CI runs them automatically.

## How to Contribute

### Reporting Bugs

Open an [issue](https://github.com/lobotomoe/revenant/issues) with:
- Steps to reproduce
- Expected vs actual behavior
- Python version and OS

### Security Issues

**Do not open a public issue.** See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

### Pull Requests

1. Fork the repository and create a branch from `main`
2. Make your changes
3. Ensure all checks pass (lint, typecheck, tests, audit)
4. Submit a pull request against `main`

Keep PRs focused on a single change. If you're fixing a bug and want to refactor nearby code, split them into separate PRs.

## Code Style

- **Language:** All code, comments, and commit messages in English
- **Formatting:** ruff (no configuration needed, uses `pyproject.toml`)
- **Type hints:** Required on all function signatures, pyright strict mode
- **Docstrings:** Module-level required, Google style for public functions
- **Imports:** isort order (stdlib, third-party, first-party), relative within package

## Commit Messages

```
type(scope): brief description

feat(sign): add batch signing support
fix(soap): handle empty response body
refactor(pdf): simplify ByteRange parsing
```

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
