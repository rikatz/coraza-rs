# libinjection-rs - Context & Research

Pre-implementation research and build plan for a **WAF-first** Rust port of [libinjection](https://github.com/client9/libinjection), targeting [coraza-rs](https://github.com/alexsnaps/coraza-rs) operators `@detectSQLi` and `@detectXSS`.

**Last updated:** 2026-07-09

---

## Start here

| Document | Description |
|----------|-------------|
| **[`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md)** | **Build plan** - phases 0–6, checklist, success criteria |
| **[`MODERNIZATION_PLAN.md`](./MODERNIZATION_PLAN.md)** | **WAF-first architecture** - `AnalysisSnapshot`, hot-path contract, Coraza boundary |
| [`WASM_PORTABILITY.md`](./WASM_PORTABILITY.md) | Library constraints for future WASM embedders |

---

## Research & guidelines

| Document | Description |
|----------|-------------|
| [`RUST_BEST_PRACTICES.md`](./RUST_BEST_PRACTICES.md) | Zero-copy, stack-only, `&[u8]`, memchr, no_std |
| [`RUST_LINTING_SETUP.md`](./RUST_LINTING_SETUP.md) | rustfmt, clippy, cargo-deny, Miri, CI tiers |
| [`LIBINJECTION_C_ANALYSIS.md`](./LIBINJECTION_C_ANALYSIS.md) | Original C library - algorithm authority |
| [`LIBINJECTION_GO_ANALYSIS.md`](./LIBINJECTION_GO_ANALYSIS.md) | Go port v0.3.2 - legacy engine reference |

---

## Executive Summary

### What we're building

A pure-Rust **analysis library** on the WAF hot path - called **per field/value** during request processing. It normalizes input (bounded), tokenizes, classifies SQL/XSS **constructs**, and returns a fixed-size **`AnalysisSnapshot`**. It does **not** decide block vs allow; **Coraza owns policy** via SecRules and CRS.

### Architectural split

| Layer | Responsibility |
|-------|----------------|
| **libinjection-rs** | normalize → tokenize → construct flags + evidence spans (+ optional legacy fingerprint) |
| **Coraza** | when to scan, `@detectSQLi` / `@detectXSS`, block/log/audit, CRS 941/942 rules |

Rules and policy **do not** ship as embedded YAML in this crate. Coraza precompiles rule conditions against `ConstructFlags` at WAF init (off hot path).

### Hard constraints

- **Zero heap allocation** on `detect_sqli` / `detect_xss` / `analyze_*` default path
- Stack-only, bounded buffers, **`no_std` core**, WASM-safe
- Never panic on untrusted input
- **O(n)** scan with early exit; **p99 ≤ libinjection-go**
- **`legacy` feature** - fingerprint engine for 499-test corpus + audit compat
- **Modern default** - construct classification, not fingerprint-blacklist-as-primary

### Target API

```rust
// Primary - zero alloc, fixed-size output
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot;
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot;

// Convenience - built-in minimal policy for @detectSQLi / @detectXSS backward compat
pub fn detect_sqli(input: &[u8]) -> DetectionVerdict;
pub fn detect_xss(input: &[u8]) -> DetectionVerdict;
```

Coraza captures legacy SQLi fingerprint in audit field 0 via [`operators/detection.rs`](../../coraza-rs/src/operators/detection.rs) when `legacy` feature provides it.

### Modern hot path

```
Input &[u8]
  → prefilter → normalize (512B stack) → tokenize [TokenMeta; 8]
  → construct classify → ConstructFlags
  → AnalysisSnapshot (evidence spans, optional LegacyFingerprint)
```

No sqlparser / full AST on default path. Optional `deep` feature for native offline analysis only.

### Legacy parity (`legacy` feature)

499 libinjection-go test files must pass 100%:

```
tokenize → fold → fingerprint → blacklist → whitelist → multi-pass
```

### Dependencies

| Tier | Item |
|------|------|
| Core runtime | `memchr` only |
| Optional | `std` (native SIMD) |
| Feature-gated | `legacy` (build.rs tables), `deep`/`alloc` (not hot path) |
| Never | embedded rules, proxy-wasm, regex, sqlparser |

### Phases (summary)

| Phase | Focus |
|-------|-------|
| 0–1 | Scaffold + corpus harness |
| 2a | Legacy parity (`legacy`, 499 tests) |
| 2b | `AnalysisSnapshot` + construct detectors |
| 3 | Coraza integration (`detection.rs`) |
| 4 | Rule-matching interface + CRS 941/942 validation |
| 5 | Construct hardening (no heap) |
| 6 | Benchmarks, fuzz, bypass corpus |

### Success criteria

- Zero heap on hot path (Miri + no-alloc test)
- `wasm32-wasip1 --no-default-features` clean
- Legacy corpus 100% with `legacy`
- p99 ≤ libinjection-go @ 256 B and 1 KiB
- coraza-rs + CRS 941/942 green

### Explicit non-goals

- Embedded policy rule packs in crate
- ML, full SQL semantic analysis
- proxy-wasm / cdylib
- Heap on `detect_*` default path

### Next steps

Follow [`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md) from Phase 0.

---

## Agent Research Notes

Four parallel research agents (2026-07-08):

1. **Rust performance best practices** → `RUST_BEST_PRACTICES.md`
2. **Rust linting setup** → `RUST_LINTING_SETUP.md`
3. **libinjection-go analysis** → `LIBINJECTION_GO_ANALYSIS.md`
4. **libinjection C analysis** → `LIBINJECTION_C_ANALYSIS.md`

Copy of Go analysis at repo root: `../LIBINJECTION_GO_ANALYSIS.md`
