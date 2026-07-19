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

# -- Rust ---------------------------------------------------------------------

.PHONY: rs-lint rs-format rs-typecheck rs-test rs-build

rs-lint: ## Lint Rust (clippy, warnings as errors)
	cd rust && cargo clippy --workspace --all-targets -- -D warnings

rs-format: ## Check Rust formatting (rustfmt)
	cd rust && cargo fmt --all --check

rs-typecheck: ## Type-check Rust (cargo check)
	cd rust && cargo check --workspace --all-targets

rs-test: ## Run Rust tests (cargo test)
	cd rust && cargo test --workspace

rs-build: ## Build Rust workspace (release)
	cd rust && cargo build --workspace --release

# -- Rust desktop packaging (see rust/packaging/) -----------------------------
# Per-platform bundling is hand-rolled over the store-approved manifests. Only
# the macOS targets run on this host; Windows MSIX / Linux AppImage / Snap /
# Flatpak build in CI (their tools are OS-specific). See rust/packaging/*.

.PHONY: rs-bundle-macos rs-icns

rs-bundle-macos: rs-build ## Assemble Revenant.app from the release binary (macOS)
	cd rust && packaging/macos/bundle-app.sh target/release/revenant-gui dist

rs-icns: ## Regenerate the macOS app icon (.icns) from the SVG master (macOS)
	cd rust && packaging/icons/make-icns.sh

# -- Combined ----------------------------------------------------------------

.PHONY: lint typecheck test build check clean

lint: py-lint py-format ts-lint rs-lint rs-format ## Lint Python, TypeScript, and Rust

typecheck: py-typecheck ts-typecheck rs-typecheck ## Type-check all

test: py-test ts-test rs-test ## Test all

build: py-build ts-build rs-build ## Build all

check: lint typecheck test ## Run all checks (lint + typecheck + test)

clean: ## Remove build artifacts
	rm -rf python/dist python/build python/*.egg-info
	cd typescript && pnpm clean
	cd rust && cargo clean

# -- Help ---------------------------------------------------------------------

.PHONY: help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
