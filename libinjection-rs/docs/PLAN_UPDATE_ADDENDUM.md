## Addendum - incorporate into existing plan update

### Scan budget (2026-07-17)
- Stage-1 input scan cap is **caller policy**: `DEFAULT_MAX_INPUT_LEN` (8192) + `AnalyzeOptions::max_input_len`, clamped by `ABSOLUTE_MAX_INPUT_LEN` (65536)
- Stack buffers (`NORM_BUF_LEN`, token/evidence slots) and zero-heap remain **hard requirements** - raising scan budget does not enlarge them
- Configure from WAF init / SecLang - never from untrusted request metadata
- API: `analyze_*_with` / `detect_*_with`; bare `analyze_*` uses defaults
- Document caller caveats (CPU cost, TRUNCATED still possible, parse fields > raise whole-body cap)

### WAF hot-path (override embedded rule packs)
- Default detect_* path: zero heap, stack-only, early exit, p99 ≤ legacy libinjection
- Library emits fixed-size AnalysisSnapshot (ConstructFlags, evidence spans, verdict hint) - no Vec/String/Box
- Rules/policy live in Coraza, not in this crate; document library vs Coraza boundary

### Legacy compat
- Parity engine behind `legacy` feature (499 corpus, fingerprint for CRS audit field 0)
- `legacy_fingerprint` derived from snapshot; not the primary internal model

### Optional `deep` feature (OFF by default)

```toml
deep = ["dep:sqlparser", "alloc"]
```

- Second-stage only; never on default hot path or default @detectSQLi integration
- Coraza decides when: operator arg or inconclusive escalation (<1% of scans)
- Guardrails: 2KB cap, single dialect, bounded nodes, bail on budget
- wasm32 core build: deep disabled
- Separate fast vs deep benchmarks; CI fails on fast-path regression

### Revise phases to include
2a legacy parity | 2b AnalysisSnapshot + constructs | 3 Coraza integration | 4 Coraza rule interface | 5 construct hardening | 6 deep (sqlparser) | 7 bypass/differential/fuzz/alloc-guard tests

### Success criteria add
- Zero-alloc hot path test
- Modern ≥ legacy on bypass corpus; no FP regression
- Deep not in default Coraza wiring
