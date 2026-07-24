# libinjection-rs

Pure-Rust **WAF hot-path analysis library** for SQL injection and XSS construct detection.

**Status:** Planning complete (WAF-first modern rewrite) — implementation not started.

## Documentation

All planning and research lives in [`docs/`](docs/):

- **[Implementation plan](docs/IMPLEMENTATION_PLAN.md)** — phases 0–6, checklist, success criteria
- **[Modernization plan](docs/MODERNIZATION_PLAN.md)** — `AnalysisSnapshot` API, hot-path contract, Coraza boundary
- [WASM portability](docs/WASM_PORTABILITY.md) — embedder constraints (not a filter guide)
- [Research index](docs/README.md) — Go/C analyses, Rust best practices

## Goal

Replace `libinjectionrs = "0.1.1"` in [coraza-rs](../coraza-rs/) for `@detectSQLi` and `@detectXSS`.

**Library role:** emit fixed-size `AnalysisSnapshot` (construct flags, evidence spans) — **zero heap** on the default path.

**Coraza role:** SecRules/CRS policy, block/log/audit, rule reload at init. Rules are **not** embedded in this crate.

## Constraints

- **Hot path:** stack-only, `no_std` core, never panic on untrusted input, O(n) + early exit
- **Runtime deps:** `memchr` only (core); `legacy` feature for fingerprint corpus parity
- **WASM-safe** by design — no Envoy filter in this repo
- **p99 latency** ≤ libinjection-go at 256 B and 1 KiB inputs
