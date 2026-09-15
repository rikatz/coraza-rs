# libinjection-rs migration PRD

**Status:** Accepted  
**Last updated:** 2026-09-15  
**Decision:** [ADR 0001](adr/0001-libinjection-rust-migration.md)

## Outcome

`coraza-rs` uses the in-workspace `libinjection` crate for `@detectSQLi` and `@detectXSS`, replacing `libinjectionrs = "0.1.1"`, without regressing the Go/C-derived compatibility required by CRS. The library returns analysis; Coraza applies WAF policy and captures the legacy SQL fingerprint in audit field 0 when a compatibility match is present.

## Current baseline

The in-workspace crate already provides the bounded stage-1 API:

- `analyze_sqli` / `analyze_xss` and option-taking variants return `AnalysisSnapshot` with construct flags, evidence, context, status, and an optional legacy fingerprint.
- `detect_sqli` / `detect_xss` provide the compatibility predicate. The default `legacy` feature contains the SQL fingerprint path; `std` is optional and `memchr` is the only runtime dependency.
- The default scan budget is 8 KiB, clamped to 64 KiB. Normalization, token, and evidence storage are fixed-size; input truncation fails closed unless `AnalyzeOptions::allow_truncation()` is explicitly selected.
- Coraza still imports `libinjectionrs`; the local crate is not wired into `coraza-rs/src/operators/detection.rs` yet.
- On 2026-09-15, the focused baseline passed: 53 default-feature unit tests, 49 `--no-default-features` unit tests, the `no_alloc` gate, and the `wasm32-wasip1 --no-default-features` compile check. The vendored corpus and its harness are absent, so full legacy parity is unproven.

## Goals

1. Preserve Go/C-derived SQLi and XSS behavior needed by Coraza, including SQL fingerprint capture for `@detectSQLi`.
2. Preserve the hot-path contract: byte input, no panics on untrusted data, no default-path allocation, fixed working storage, and linear work over a bounded scan.
3. Replace Coraza's dependency only when corpus parity and CRS 941/942 operator validation pass.
4. Establish construct-based analysis as the future extension point without embedding rule packs or security actions in the library.

## Non-goals

- A full SQL AST/parser, semantic second stage, regex-based detector, or embedded CRS policy.
- A proxy-WASM plugin, `cdylib`, deployment configuration, or a new runtime dependency for the detector.
- Benchmark, fuzzing, Miri, or new detection semantics as part of the dependency replacement. They are modernization work, not migration gates, unless a specific change requires them.

## Terms and authority

| Term | Meaning |
| --- | --- |
| **Modern analysis** | The bounded construct classifier that produces `AnalysisSnapshot`. |
| **Legacy compatibility** | The Go-derived SQL fingerprint path under `legacy`; the baseline XSS tokenizer also retains five Go/C-derived entry contexts. |
| **Migration** | The completed replacement of Coraza's dependency after all release gates pass. |
| **Modernization** | Post-migration, separately reviewed detection and quality improvements. |

Code and executable tests define the current behavior. The ADR defines accepted architectural decisions. This PRD defines delivery requirements. The [C](LIBINJECTION_C_ANALYSIS.md) and [Go](LIBINJECTION_GO_ANALYSIS.md) analyses are evidence and behavioral references, not active plans.

## Delivery plan

### 1. Restore the compatibility characterization gate

Vendor the libinjection-go v0.3.2 fixtures and a test-only harness for raw tokens, folding, SQLi fingerprints, HTML5 tokens, and XSS decisions. The documented inventory is **496** fixtures: 249 tokens, 118 folding, 54 SQLi, 68 HTML5, and 7 XSS. The harness must assert the count as part of import so a future upstream update is deliberate, not silent.

**Exit gate:** `cargo test -p libinjection --features legacy --test corpus_parse` exists and reports zero failures for the pinned fixture inventory.

### 2. Establish legacy compatibility

Use the corpus to close gaps in tokenizer dispatch, folding, fingerprints, false-positive suppression, SQL quote/dialect passes, and five-context HTML tokenization. Preserve raw byte semantics and original-input offsets. Focused tests remain alongside each correction; the corpus is the compatibility gate, not a substitute for readable regressions.

**Exit gate:** all 496 fixtures pass, including exact SQL fingerprints and token/folding output where supplied.

### 3. Migrate Coraza

Change Coraza to its local `libinjection` path dependency with `legacy` and `std` enabled. Update the detection operators to use `DetectionVerdict`, capture `snapshot.legacy_fingerprint` in field 0 on a SQLi hit, and retain the existing no-argument operator contract. Configure scan budgets only at WAF initialization, never from request metadata.

**Exit gates:** Coraza operator tests pass; CRS 941xxx and 942xxx validation passes; corpus parity from step 2 remains green. Only then is the dependency replacement complete.

### 4. Modernize after migration

Work in small, independently approved slices: differential tests between modern and legacy paths; Go/C-backed bypass and benign vectors; fuller construct evidence; fuzzing; Miri; and measured performance gates. Every detection change needs its expected construct flag, a benign boundary case, original-input evidence where relevant, and an explicit false-positive policy.

The accepted hardening deviations are: malformed numeric exponents stay visible as barewords, and numeric HTML entities outside `u8` are rejected rather than truncated. Keep both covered by focused tests and differential coverage when the corpus gate is restored.

## Required quality gates

| Gate | Required for |
| --- | --- |
| `cargo test -p libinjection` | Every library change |
| `cargo test -p libinjection --no-default-features` | Core/no_std-compatible change |
| `cargo test -p libinjection --test no_alloc` | Hot-path change |
| `cargo check -p libinjection --target wasm32-wasip1 --no-default-features` | Core dependency or portability change |
| `cargo test -p libinjection --features legacy --test corpus_parse` | Legacy compatibility and Coraza replacement |
| Coraza operator tests and CRS 941/942 validation | Coraza replacement |

## Completion definition

The migration is complete when the local crate replaces `libinjectionrs` in Coraza, all required library gates and the 496-fixture corpus pass, Coraza's `@detectSQLi` capture behavior is preserved, and CRS 941/942 validation is green. Modernization remains an ongoing, separately scoped program after that point.
