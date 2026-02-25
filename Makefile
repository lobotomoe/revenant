# Revenant -- unified development commands
# Run `make help` to see available targets.

.DEFAULT_GOAL := help
SHELL := /bin/bash

# -- Python -------------------------------------------------------------------

.PHONY: py-lint py-format py-typecheck py-test py-build

py-lint: ## Lint Python (ruff)
	cd python && ruff check src/ tests/

py-format: ## Check Python formatting (ruff)
	cd python && ruff format --check src/ tests/

py-typecheck: ## Type-check Python (pyright)
	cd python && pyright src/

py-test: ## Run Python tests (pytest)
	cd python && pytest -v

py-build: ## Build Python package (sdist + wheel)
	python -m build python/

# -- TypeScript ---------------------------------------------------------------

.PHONY: ts-lint ts-typecheck ts-test ts-build

ts-lint: ## Lint TypeScript (Biome)
	cd typescript && pnpm lint

ts-typecheck: ## Type-check TypeScript (tsc)
	cd typescript && pnpm typecheck

ts-test: ## Run TypeScript tests (Vitest)
	cd typescript && pnpm test

ts-build: ## Build TypeScript package (tsup)
	cd typescript && pnpm build

# -- Combined ----------------------------------------------------------------

.PHONY: lint typecheck test build check clean

lint: py-lint py-format ts-lint ## Lint both Python and TypeScript

typecheck: py-typecheck ts-typecheck ## Type-check both

test: py-test ts-test ## Test both

build: py-build ts-build ## Build both

check: lint typecheck test ## Run all checks (lint + typecheck + test)

clean: ## Remove build artifacts
	rm -rf python/dist python/build python/*.egg-info
	cd typescript && pnpm clean

# -- Help ---------------------------------------------------------------------

.PHONY: help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
