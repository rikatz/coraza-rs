# Migrate Coraza to the in-workspace Rust libinjection implementation

**Status:** Accepted — 2026-09-15

`coraza-rs` will replace its `libinjectionrs` dependency with the in-workspace `libinjection-rs` crate only after legacy corpus parity and CRS operator compatibility are demonstrated. The crate is a byte-oriented, bounded analysis library; Coraza retains responsibility for SecRules/CRS policy, actions, audit integration, and the choice of what to scan.

## Goals

- Replace the current Rust dependency for `@detectSQLi` and `@detectXSS` without reducing established protection or audit compatibility.
- Keep the hot path `no_std`-capable, panic-free for untrusted bytes, allocation-free, bounded, and suitable for future WASM embedders.
- Make construct-level analysis (`AnalysisSnapshot`) the durable API while retaining legacy SQL fingerprints for compatibility and audit capture.
- Modernize detection only through separately reviewed, test-backed work after the migration gate.

## Non-goals

- Embed CRS/SecRule policy, block/allow actions, an Envoy/proxy-WASM filter, ML, or a full SQL parser in `libinjection-rs`.
- Treat the current focused test suite as evidence of complete Go/C parity.
- Couple broader detection changes to the dependency replacement.

## Decision record

| ID | Decision | Status | Revisit when |
| --- | --- | --- | --- |
| D1 | `libinjection-rs` accepts `&[u8]` and returns fixed-size analysis data; `AnalysisSnapshot` is the primary long-term model. | Accepted | A consumer needs an incompatible public API. |
| D2 | Coraza owns scan placement, SecRules/CRS matching, block/log actions, and audit formatting. `detect_*` remains a compatibility predicate, not an embedded rule engine. | Accepted | Coraza gains a construct-aware operator interface. |
| D3 | The `legacy` feature preserves Go-compatible SQL fingerprint behavior and supplies the fingerprint captured by `@detectSQLi`. It is compatibility support, not the future policy model. | Accepted | CRS no longer requires fingerprint-compatible behavior. |
| D4 | The default path is bounded, stack-only, allocation-free, and fail-closed on truncation unless the caller explicitly allows an inconclusive result. | Accepted | A measured deployment requirement changes the safety/performance trade-off. |
| D5 | Full corpus parity and CRS 941/942 validation are release gates for replacing `libinjectionrs` in Coraza. Work may integrate earlier, but the replacement is not complete before both gates pass. | Accepted | The authoritative upstream fixture set or CRS contract changes. |
| D6 | Rust intentionally retains malformed numeric exponents as barewords and rejects numeric HTML entities that do not fit in `u8`; both require focused regression and differential coverage. | Accepted | Compatibility testing shows either change alters the required Coraza contract. |

## Consequences

The migration is a compatibility-first sequence: characterize and restore the corpus gate, prove parity, wire Coraza, then validate CRS. The current focused tests prove only the implemented baseline. In particular, the legacy fingerprint is produced by the legacy SQL path; it is not derived from the modern tokenizer.

The C and Go analyses remain reference material. This ADR and the [migration PRD](../MIGRATION_PRD.md) replace the former competing implementation plans, PR notes, and port blueprint.
