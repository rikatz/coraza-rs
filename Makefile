# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

V ?=

ifneq ($(V),)
  _NOCAPTURE := -- --nocapture
endif

.PHONY: all build check clean test lint fmt doc setup-hooks help

all: build fmt lint test

# -------------------------------------------------------------------
# Build
# -------------------------------------------------------------------

build:
	cargo build --workspace

check:
	cargo check --workspace

clean:
	cargo clean

# -------------------------------------------------------------------
# Test
# -------------------------------------------------------------------

test:
	cargo test --workspace $(_NOCAPTURE)

# -------------------------------------------------------------------
# Quality
# -------------------------------------------------------------------

lint:
	cargo clippy --workspace --all-targets -- -D warnings
	cargo fmt --all -- --check
	cargo xtask lint-license

fmt:
	cargo fmt --all

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items

# -------------------------------------------------------------------
# Dev Setup
# -------------------------------------------------------------------

setup-hooks:
	ln -sf ../../.hooks/pre-commit .git/hooks/pre-commit
	@echo "Git hooks installed."

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------

help:
	@echo "Variables:"
	@echo "  V=1        show test output (--nocapture)"
	@echo ""
	@echo "Top-level:"
	@echo "  all        build + fmt + lint + test"
	@echo ""
	@echo "Build:"
	@echo "  build      cargo build --workspace"
	@echo "  check      cargo check --workspace"
	@echo "  clean      cargo clean"
	@echo ""
	@echo "Test:"
	@echo "  test       run all tests"
	@echo ""
	@echo "Quality:"
	@echo "  lint       clippy + rustfmt check + license header check"
	@echo "  fmt        format with rustfmt"
	@echo "  doc        build docs with warnings denied"
	@echo ""
	@echo "Dev Setup:"
	@echo "  setup-hooks  install git pre-commit hook (commit signing + lint)"
