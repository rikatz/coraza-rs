# Rust Static Analysis & Linting Guide (2025–2026)

A practical setup guide for the **coraza-rs + libinjection-rs workspace**.

---

## Current State: coraza-rs

**CI:** `coraza-rs/.github/workflows/rust.yml`

| Tool | Status |
|------|--------|
| `cargo build` | ✅ Runs |
| `cargo test` | ⚠️ `continue-on-error: true` (does not block PRs) |
| `cargo fmt --check` | ⚠️ `continue-on-error: true` |
| `cargo clippy --all-features --all-targets -- -D warnings` | ✅ Only hard gate |
| `rustfmt.toml` / `clippy.toml` | ❌ None |
| Workspace root `Cargo.toml` | ❌ None (sibling crates) |
| `cargo-deny` / `cargo-audit` | ❌ None |
| Miri | ❌ None (`coraza-rs` has `unsafe` in ~6 files) |
| typos / taplo | ❌ None |

Both crates use `edition = "2024"`. `coraza-rs` depends on published `libinjectionrs = "0.1.1"`; local `libinjection-rs/` is the new from-scratch port.

---

## 1. Recommended Tool Stack

### Must-have

| Tool | Purpose |
|------|---------|
| **rustfmt** | Consistent formatting; edition 2024 needs explicit `style_edition` |
| **clippy** (`-D warnings`) | Idiomatic Rust, perf, suspicious patterns for WAF code |
| **cargo-deny** | Licenses, advisories, bans, duplicate deps |
| **GitHub Actions CI** | Enforce all of the above (remove `continue-on-error`) |

### Strongly recommended

| Tool | Purpose |
|------|---------|
| **cargo-audit** | Fast RustSec advisory scan; complements cargo-deny |
| **taplo** | TOML formatting/lint for `Cargo.toml`, `deny.toml` |
| **typos** | Spell-check source/docs |

### Nice-to-have (tier 2+)

| Tool | When |
|------|------|
| **Miri** | Once `libinjection-rs` has unsafe + tests |
| **cargo-hack** | Feature-matrix check when features grow |
| **cargo-machete** | Unused dependency detection (weekly) |
| **cargo-semver-checks** | Before publishing to crates.io |
| **cargo-llvm-cov** | Coverage reporting |
| **pre-commit** | Local gate after CI is stable |

> **Note:** There is no widely-used tool named `cargo-vulnerabilities`. Use **`cargo-audit`** (RustSec) and/or **`cargo deny check advisories`**.

---

## 2. Workspace Layout

```
coraza-rs/                          # repo root
├── Cargo.toml                      # [workspace]
├── rustfmt.toml
├── clippy.toml
├── deny.toml
├── _typos.toml
├── taplo.toml
├── .cargo/config.toml
├── .github/workflows/ci.yml
├── coraza-rs/Cargo.toml
└── libinjection-rs/Cargo.toml
```

---

## 3. Example Configuration Files

### Root `Cargo.toml`

```toml
[workspace]
members = ["coraza-rs", "libinjection-rs"]
resolver = "2"

[workspace.package]
edition = "2024"
rust-version = "1.85"
license = "Apache-2.0"

[workspace.lints.rust]
unsafe_code = "warn"
missing_docs = "warn"
rust_2018_idioms = "warn"

[workspace.lints.clippy]
all = { level = "warn", priority = -1 }
pedantic = { level = "warn", priority = -1 }
cargo = { level = "warn", priority = -1 }
nursery = { level = "warn", priority = -1 }

# Cherry-picked restriction lints (never enable restriction as a group)
unwrap_used = "deny"
expect_used = "deny"
todo = "warn"
dbg_macro = "deny"
print_stdout = "deny"
indexing_slicing = "warn"

module_name_repetitions = "allow"
missing_errors_doc = "allow"
doc_markdown = "allow"
```

Per-crate: `[lints] workspace = true`

### `rustfmt.toml`

```toml
edition = "2024"
style_edition = "2024"
max_width = 100
use_small_heuristics = "Max"
newline_style = "Unix"
reorder_imports = true
imports_granularity = "Module"
group_imports = "StdExternalCrate"
```

### `clippy.toml` (thresholds only)

```toml
msrv = "1.85.0"
too-many-arguments-threshold = 8
too-many-lines-threshold = 120
type-complexity-threshold = 300
allow-unwrap-in-tests = true
allow-expect-in-tests = true
allow-indexing-slicing-in-tests = true
doc-valid-idents = ["WAF", "CRS", "SecLang", "..", "libinjection"]
```

### `deny.toml`

```toml
[graph]
all-features = true

[advisories]
version = 2
yanked = "deny"
unmaintained = "warn"

[licenses]
version = 2
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0", "Zlib"]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

### Minimal CI (`.github/workflows/ci.yml`)

```yaml
name: CI
on: [push, pull_request]
env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: -Dwarnings

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --all -- --check
      - run: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
      - run: cargo test --workspace --all-features --locked
```

### Miri workflow (nightly, separate)

```yaml
- uses: dtolnay/rust-toolchain@nightly
  with:
    components: miri
- run: cargo miri setup
- run: cargo miri test -p libinjection-rs
  env:
    MIRIFLAGS: "-Zmiri-tree-borrows"
```

---

## 4. Rationale by Tool

### rustfmt
Zero debate on formatting. **Edition 2024 projects must set `style_edition = "2024"`** or editor and CI disagree.

### clippy
- Default groups promoted to errors via `-D warnings`
- **`pedantic`**: High signal for libraries; allow noisy lints individually
- **`nursery`**: Experimental; enable as warn with explicit allows
- **`restriction`**: Never as a group; cherry-pick `unwrap_used`, `expect_used`, `indexing_slicing`
- Lint levels in `[workspace.lints]`; **`clippy.toml` is thresholds only**

### cargo-deny
License allow-list, duplicate version bans, unknown registry blocking. Overlaps with cargo-audit on advisories - pick one as primary for advisories.

### cargo-audit
Official RustSec scanner; fast per-PR feedback.

### Miri
Essential for parser/unsafe code. 10–100× slower - run targeted crates, not full FTW suite.

### typos / taplo
Cheap hygiene for docs and TOML config files.

---

## 5. Setup Tiers

### Tier 0 - Current coraza-rs
`build`, `test` (non-blocking), `fmt` (non-blocking), `clippy -D warnings`

### Tier 1 - Minimal (recommended start)
- Root workspace + `[workspace.lints]`
- `rustfmt.toml` with `style_edition = "2024"`
- CI: fmt + clippy + test all **blocking**
- Path dep: `libinjection-rs = { path = "../libinjection-rs" }`

### Tier 2 - Standard library workspace
Tier 1 + `clippy.toml`, `deny.toml`, `cargo audit`, `taplo`, `typos`

### Tier 3 - Security-critical
Tier 2 + Miri, `cargo hack`, pre-commit, `unsafe_code = "forbid"` except explicit modules

---

## 6. libinjection-rs–Specific Recommendations

1. **Crate type:** `[lib]` only; move `main.rs` to `examples/`
2. **Stricter lints:** `indexing_slicing = "deny"`, `unwrap_used = "deny"` in parser modules
3. **Miri:** First-class for parser port
4. **Fuzz:** `cargo-fuzz` on tokenize + fold
5. **Public API:** `missing_docs = "warn"` before crates.io publish

---

## 7. Key Clippy Lint Names

### Restriction (cherry-pick)
`unwrap_used`, `expect_used`, `dbg_macro`, `todo`, `print_stdout`, `indexing_slicing`, `panic`

### Pedantic (group + allows)
Enable group; allow `module_name_repetitions`, `missing_errors_doc`, `doc_markdown`

### Nursery (group + allows)
Allow `option_if_let_else`, `redundant_pub_crate`

---

## 8. Migration Checklist

1. Create root workspace `Cargo.toml` with both members
2. Add `rustfmt.toml`, `clippy.toml`, `deny.toml`, `_typos.toml`
3. Add `[lints] workspace = true` to each crate
4. Switch to path dependency during local development
5. Fix CI: remove all `continue-on-error: true`
6. Add Miri once parser has tests

---

## Local Developer Workflow

```bash
cargo fmt --all -- --check
taplo fmt --check
typos
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo audit
cargo deny check
cargo miri test -p libinjection-rs   # during unsafe work
```

Install once:

```bash
rustup component add rustfmt clippy
cargo install cargo-deny cargo-audit --locked
cargo install typos-cli taplo-cli --locked
rustup +nightly component add miri
```

*Document version: 2026-07-08*
