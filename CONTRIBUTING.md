# Contributing to Revenant

Thank you for your interest in contributing to Revenant.

## Getting Started

### Prerequisites

**Python client:**
- Python 3.10+
- [ruff](https://docs.astral.sh/ruff/) (linting/formatting)
- [pyright](https://github.com/microsoft/pyright) (type checking)

**TypeScript client:**
- Node.js 18+
- [pnpm](https://pnpm.io/)

### Development Setup

```bash
# Python
cd python
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# TypeScript
cd typescript
pnpm install
```

### Running Checks

```bash
# Python
cd python
ruff check src/ tests/          # lint
ruff format --check src/ tests/ # format check
pyright src/                    # type check (strict, 0 errors expected)
pytest                          # tests (96%+ coverage)

# TypeScript
cd typescript
pnpm lint                       # lint (Biome)
pnpm typecheck                  # type check (tsc --noEmit)
pnpm test                       # tests (Vitest, 96%+ coverage)
pnpm build                      # build
```

Or use the root Makefile:

```bash
make check    # lint + typecheck + test (both languages)
make lint     # lint both
make test     # test both
```

All checks must pass before submitting a pull request. CI runs them automatically.

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
3. Ensure all checks pass (lint, typecheck, tests)
4. Fill out the PR template
5. Submit a pull request against `main`

Keep PRs focused on a single change. If you're fixing a bug and want to refactor nearby code, split them into separate PRs.

### PR Checklist

- [ ] Linter passes with zero warnings
- [ ] Type checker passes with zero errors
- [ ] Tests pass on all supported versions
- [ ] Coverage thresholds met (90%+ Python, 96%+ TypeScript)
- [ ] No unused code, imports, or files

## Code Standards

### Both Languages

- **Language:** All code, comments, and commit messages in English
- **No magic numbers or strings** -- use named constants
- **Explicit error handling** -- no silent catches, no swallowed errors
- **Files under 400 lines** -- split by responsibility when they grow

### Python

- **Formatting:** ruff (config in `pyproject.toml`)
- **Type hints:** Required on all function signatures, pyright strict mode
- **Docstrings:** Module-level required, Google style for public functions
- **Imports:** isort order (stdlib, third-party, first-party), relative within package

### TypeScript

- **`as` type assertions are banned** -- use runtime checks or Zod validation (`as const` is allowed)
- **Formatting:** Biome (config in `biome.json`)
- **Zod validation** for all external data (API responses, file contents, env vars)
- **No `any` types** -- the codebase is strict TypeScript

## Commit Messages

```
type(scope): brief description

feat(sign): add batch signing support
fix(soap): handle empty response body
refactor(pdf): simplify ByteRange parsing
```

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
