# libinjection-rs Modernization Plan

**WAF-first rewrite** - library on the hot path, Coraza owns policy.

**Last updated:** 2026-07-17 (scan budget as caller policy; AnalyzeOptions)

---

## Changelog

| Date | Change |
|------|--------|
| 2026-07-17 | **Scan budget as caller policy:** `DEFAULT_MAX_INPUT_LEN` + `AnalyzeOptions` override, clamped by `ABSOLUTE_MAX_INPUT_LEN`; stack buffers remain hard requirements |
| 2026-07-09 | **Hot-path addendum:** `VerdictHint` on snapshot; deep guardrails (2 KiB, single dialect, bounded nodes); phases 6–7; separate fast/deep benches; deep not in default Coraza wiring |
| 2026-07-09 | **`deep` addendum:** optional second-stage analyzer with `sqlparser` behind `deep` feature; Coraza decides when it runs - never automatic on every field scan |
| 2026-07-09 | **WAF-first pivot:** construct classification + `AnalysisSnapshot` as default; legacy fingerprint engine behind `legacy` feature; rules/policy explicitly Coraza-side |
| 2026-07-08 | Initial plan: fingerprint-blacklist port mirroring libinjection-go |

---

## Design thesis

Legacy libinjection answers one question: *"Does this input match a known bad fingerprint?"*

A WAF on the hot path needs a different contract: *"What SQL/XSS constructs are present in this field, so Coraza can apply SecRules/CRS policy?"*

```
┌─────────────────────────────────────────────────────────────────┐
│ CORAZA (consumer) - policy, NOT in libinjection-rs              │
│  • SecRules / CRS: when to scan, what to block, audit, log       │
│  • Rule reload at WAF init → read-only matchers (off hot path)  │
│  • @detectSQLi / @detectXSS: call library once, apply policy   │
└────────────────────────────┬────────────────────────────────────┘
                             │ analyze_*(&[u8]) → AnalysisSnapshot
┌────────────────────────────▼────────────────────────────────────┐
│ libinjection-rs (library) - analysis ONLY                         │
│  • normalize (bounded stack)                                      │
│  • tokenize / lightweight construct detection                   │
│  • emit fixed-size AnalysisSnapshot                             │
│  • NO block/log, NO SecRule actions, NO embedded rule packs     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Hot-path contract

These guarantees apply to **`analyze_sqli` / `analyze_xss`** and the thin **`detect_*`** wrappers built on top (default features, no `deep`/`alloc`).

| Guarantee | Specification |
|-----------|---------------|
| **Zero heap allocation** | No `Vec`, `String`, `Box`, `HashMap`, or implicit alloc in `detect_sqli` / `detect_xss` / `analyze_*` default path. Verified by custom no-alloc test + Miri. |
| **Stack budget** | Parser + snapshot ≤ **4 KiB** stack per call (target ~1–2 KiB; hard cap documented in `limits.rs`). |
| **Max input length (default)** | **8192 bytes** (`DEFAULT_MAX_INPUT_LEN`) per call when using `analyze_*` without options. |
| **Max input length (absolute)** | **65536 bytes** (`ABSOLUTE_MAX_INPUT_LEN`) - hard clamp; library never scans unbounded input. |
| **Scan budget override** | Coraza may pass `AnalyzeOptions { max_input_len }` (WAF init / operator config). Effective scan = `min(input.len(), opts.max_input_len, ABSOLUTE_MAX_INPUT_LEN)`. Longer → prefix + `TRUNCATED`. |
| **Normalization buffer** | Stack buffer **512 bytes** (`NORM_BUF_LEN`); overflow → `TRUNCATED`, no heap spill. **Not** caller-overridable (hard layout). |
| **Token buffer** | Fixed **`[TokenMeta; 8]`** - offsets into input, no token value copies. **Hard**. |
| **Evidence spans** | Fixed **`[EvidenceSpan; 4]`** - `(offset, len)` only. **Hard**. |
| **Time complexity** | **O(n)** single pass over **scanned** bytes; **early exit** when decisive constructs found or hard limits hit. |
| **Latency** | **p99 ≤ libinjection-go** at 256 B and 1 KiB inputs on the **default** scan profile (fast-path benchmark gate in Phase 7). |
| **Output shape** | Fixed-size `AnalysisSnapshot` only - no `Vec` / `String` / `Box` on hot path |
| **Panic safety** | Never panic on untrusted input; return empty/benign snapshot or `Err(AnalysisError::*)`. |
| **`no_std`** | Core builds with `--no-default-features`; WASM-safe (`wasm32-wasip1` CI). |

### Early-exit semantics

1. Empty input → immediate benign snapshot (no work).
2. Input longer than **effective** scan budget → normalize/scan prefix only, set `TRUNCATED`.
3. After normalization, if no SQL/XSS-relevant bytes (fast prefilter) → benign snapshot.
4. Construct detectors run in **cheap → expensive** order; stop when `ConstructFlags` satisfy internal "decisive" threshold **or** token budget exhausted.
5. **`detect_sqli` / `detect_xss`** apply Coraza's **built-in minimal policy** (see below) on the snapshot - still zero alloc.

### Scan budget (caller policy)

**Thesis:** How many bytes to scan is **Coraza policy**. Stack buffer sizes and zero-heap are **library requirements**.

| Limit | Kind | Notes |
|-------|------|-------|
| `DEFAULT_MAX_INPUT_LEN` (8192) | Soft default | Used by `analyze_*` / `detect_*` without options |
| `AnalyzeOptions::max_input_len` | Soft override | Set at WAF init / SecLang config - **never** from untrusted request metadata |
| `ABSOLUTE_MAX_INPUT_LEN` (65536) | Hard clamp | Misconfig cannot request unbounded scans |
| `NORM_BUF_LEN`, token/evidence slots | Hard | Raising scan budget does **not** enlarge these |
| `DEEP_MAX_INPUT_LEN` (2048) | Separate deep default + its own absolute (Phase 6) | Deep stays stricter than stage 1 |

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalyzeOptions {
    /// Requested scan budget; clamped to ABSOLUTE_MAX_INPUT_LEN inside analyze_*.
    pub max_input_len: usize,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self { max_input_len: DEFAULT_MAX_INPUT_LEN }
    }
}

pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot {
    analyze_sqli_with(input, AnalyzeOptions::default())
}
```

**Caller caveats (document in crate docs + Coraza):**

1. Larger `max_input_len` ⇒ linear CPU cost per field × rule frequency.
2. Does **not** enlarge norm/token/evidence stacks - `TRUNCATED` / `TOKEN_LIMIT` can still fire.
3. Does **not** change deep caps; deep is a separate opt-in path.
4. Completeness still depends on **which slices** Coraza passes (parsed ARGS vs whole body). Raising the cap on a mega-blob is a weak substitute for body parsers.
5. Prefer WAF-init configuration; never let request content choose the budget.
6. Fast-path CI SLO is measured on the **default** profile; raised-cap profiles are optional separate benches.

---

## AnalysisSnapshot API spec

Fixed-size, `Copy`/`Clone` friendly, no heap fields.

```rust
/// Result of one analysis pass over a single field value.
/// All spans are indices into the original input slice passed to analyze_*.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisSnapshot {
    /// SQLi and/or XSS construct classification.
    pub constructs: ConstructFlags,
    /// Parse/normalize status (truncation, legacy compat, etc.).
    pub flags: AnalysisFlags,
    /// Stage-1 classification hint for Coraza / optional deep escalation.
    pub verdict_hint: VerdictHint,
    /// Parsing context used (quote mode, HTML entry context, dialect hint).
    pub context: AnalysisContext,
    /// Up to 4 evidence regions in the original input.
    pub evidence: EvidenceSet,
    /// Optional legacy type-byte fingerprint (derived compat view).
    pub legacy_fingerprint: LegacyFingerprint,
}

/// Hint for Coraza policy - not a block/allow decision.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum VerdictHint {
    #[default]
    Benign = 0,           // prefilter miss or no constructs
    Suspicious = 1,       // constructs present but below built-in policy threshold
    Decisive = 2,         // constructs match built-in policy (detect_* would return true)
    Inconclusive = 3,     // ambiguous: TRUNCATED + partial constructs - Coraza *may* escalate to deep (<1% target)
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct ConstructFlags(u32);

impl ConstructFlags {
    // ── SQLi constructs (bits 0–15) ──
    pub const SQL_UNION: u32              = 1 << 0;
    pub const SQL_TAUTOLOGY: u32            = 1 << 1;  // e.g. OR 1=1, AND 'a'='a'
    pub const SQL_STRING_BREAK: u32         = 1 << 2;  // quote/comment string escape
    pub const SQL_STACKED_QUERY: u32        = 1 << 3;  // semicolon-chained statements
    pub const SQL_COMMENT_INJECTION: u32    = 1 << 4;  // --, #, /* */
    pub const SQL_FUNCTION_CALL: u32        = 1 << 5;  // LOAD_FILE, SLEEP, etc.
    pub const SQL_BOOLEAN_BLIND: u32        = 1 << 6;  // AND/OR with comparators
    pub const SQL_NUMERIC_INJECTION: u32    = 1 << 7;  // arithmetic/logical on numbers
    pub const SQL_DIALECT_MYSQL: u32        = 1 << 8;  // backtick, #, /*! */
    pub const SQL_DIALECT_MSSQL: u32        = 1 << 9;  // bracket id, EXEC
    pub const SQL_DIALECT_ORACLE: u32         = 1 << 10; // q-quote, dual
    pub const SQL_KEYWORD_CHAIN: u32        = 1 << 11; // SELECT…FROM, UNION ALL, etc.

    // ── XSS constructs (bits 16–27) ──
    pub const XSS_TAG_SCRIPT: u32           = 1 << 16;
    pub const XSS_TAG_IFRAME: u32           = 1 << 17;
    pub const XSS_TAG_OBJECT: u32           = 1 << 18;
    pub const XSS_TAG_SVG: u32              = 1 << 19;
    pub const XSS_EVENT_HANDLER: u32        = 1 << 20; // on* attributes
    pub const XSS_URL_JAVASCRIPT: u32       = 1 << 21;
    pub const XSS_URL_DATA: u32             = 1 << 22;
    pub const XSS_STYLE_EXPRESSION: u32     = 1 << 23;
    pub const XSS_COMMENT_BYPASS: u32       = 1 << 24; // IE conditional, backtick
    pub const XSS_DOCTYPE: u32              = 1 << 25;

    pub fn any_sqli(self) -> bool { (self.0 & 0x0000_FFFF) != 0 }
    pub fn any_xss(self) -> bool { (self.0 & 0x0FFF_0000) != 0 }
    pub fn intersects(self, mask: ConstructFlags) -> bool { (self.0 & mask.0) != 0 }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AnalysisFlags(u16);

impl AnalysisFlags {
    pub const TRUNCATED: u16          = 1 << 0;  // input or norm buf exceeded cap
    pub const LEGACY_FP_AVAILABLE: u16  = 1 << 1;  // legacy_fingerprint valid (legacy feature)
    pub const MULTI_CONTEXT: u16        = 1 << 2;  // multiple quote/HTML contexts tried
    pub const PREFILTER_MISS: u16       = 1 << 3;  // fast reject path (benign)
    pub const TOKEN_LIMIT: u16          = 1 << 4;  // token buffer full
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct AnalysisContext {
    pub sqli_quote_mode: SqliQuoteMode,   // None | Single | Double | Backtick
    pub xss_html_context: XssHtmlContext, // Data | AttrUnquoted | AttrSingle | ...
    pub dialect: SqlDialect,              // Ansi | Mysql | Mssql (hint from constructs)
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvidenceSpan {
    pub offset: u16,
    pub len: u16,
}

pub const MAX_EVIDENCE: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct EvidenceSet {
    pub spans: [EvidenceSpan; MAX_EVIDENCE],
    pub count: u8,
}

/// Legacy libinjection type-byte fingerprint (e.g. b"s&1UE").
/// Populated only when `legacy` feature enabled; derived from token fold, not primary signal.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct LegacyFingerprint {
    pub bytes: [u8; 8],
    pub len: u8,
}
```

### Public entry points

```rust
/// Primary hot-path API - returns snapshot, never allocates.
/// Uses AnalyzeOptions::default() (DEFAULT_MAX_INPUT_LEN).
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot;
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot;

pub fn analyze_sqli_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot;
pub fn analyze_xss_with(input: &[u8], opts: AnalyzeOptions) -> AnalysisSnapshot;

/// Convenience wrappers - apply built-in minimal policy (backward compat with @detectSQLi/@detectXSS).
pub fn detect_sqli(input: &[u8]) -> DetectionVerdict;
pub fn detect_xss(input: &[u8]) -> DetectionVerdict;
pub fn detect_sqli_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict;
pub fn detect_xss_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DetectionVerdict {
    pub detected: bool,
    pub snapshot: AnalysisSnapshot,
}
```

### `legacy_fingerprint` (feature-gated) - derived compat, not primary model

| Aspect | Detail |
|--------|--------|
| Feature | `legacy` - enables fingerprint fold + static blacklist tables in `build.rs` |
| Purpose | CRS audit logs, `@detectSQLi` capture field 0, 499-test corpus parity |
| **Primary internal model** | **`ConstructFlags`** + `VerdictHint` - fingerprint is **not** the core representation |
| Derivation | **Derived view** from shared tokenize/fold after construct classification - same pipeline, compat output |
| Hot path | No separate legacy-only engine on stage-1 default path when modern + legacy both enabled |
| Without `legacy` | `legacy_fingerprint.len == 0`, `AnalysisFlags::LEGACY_FP_AVAILABLE` unset; constructs still populated |
| Coraza default build | `features = ["legacy", "std"]` - **not** `deep` |

---

## Library vs Coraza boundary

| Concern | libinjection-rs | Coraza (coraza-rs) |
|---------|-----------------|-------------------|
| **When to scan a field** | - | SecRules: target variable, phase, chain |
| **How many bytes to scan** | Default + absolute clamp; applies `AnalyzeOptions` | Sets scan budget at WAF init / operator config (policy) |
| **Block / deny / drop** | - | `deny`, `block`, `redirect` actions |
| **Audit / log content** | Provides snapshot + spans | Formats audit log, `capture_field` |
| **CRS rule packs** | - | Loaded from `@owasp_crs`, `@demo-conf`, etc. |
| **Rule reload** | - | WAF init; compile rules to matchers (off hot path) |
| **Normalization** | Bounded stack normalize | May pre-transform variables (t: operators) before calling library |
| **Tokenization** | Lightweight, fixed buffer | - |
| **Construct detection** | Sets `ConstructFlags` | - |
| **Legacy fingerprint** | Derives `[u8; 8]` if `legacy` feature | Captures in field 0 for audit |
| **Built-in @detectSQLi policy** | Exposes `detect_sqli()` helper | Operator calls it; maps to rule match |
| **Construct-specific CRS rules** | Exposes `analyze_*` + flags | Future: rules match `ConstructFlags` without fingerprint |
| **FP tuning per deployment** | - | SecRule exclusions, CRS tuning |
| **Performance SLO** | Guarantees O(n), zero alloc | Operator invoked per variable per rule |
| **When to run `deep` analysis** | Provides `analyze_sqli_deep` (feature `deep`) | Operator arg or `VerdictHint::Inconclusive` escalation (**<1%** scans) - **never** default `@detectSQLi` |
| **Embedded rule packs** | - | SecRules / CRS only - **never** in libinjection-rs |

### How `@detectSQLi` maps today

Current [`detection.rs`](../../coraza-rs/src/operators/detection.rs):

```rust
let result = libinjection::detect_sqli(input.as_bytes());
if result.is_injection() {
    tx.capture_field(0, fingerprint_as_str);  // legacy fingerprint string
    return true;
}
```

**After modernization (Phase 3):**

```rust
let verdict = libinjection::detect_sqli(input.as_bytes());
if verdict.detected {
    // Audit: legacy fingerprint when available (feature legacy)
    if let Some(fp) = verdict.snapshot.legacy_fingerprint.as_str() {
        tx.capture_field(0, fp);
    }
    return true;
}
```

`detect_sqli()` built-in policy (library-side, minimal, for backward compat):

```rust
// Pseudocode - fixed const mask, zero alloc
const BUILTIN_SQLI_POLICY: ConstructFlags = ConstructFlags(
    SQL_UNION | SQL_TAUTOLOGY | SQL_STRING_BREAK | SQL_STACKED_QUERY
    | SQL_COMMENT_INJECTION | SQL_FUNCTION_CALL | SQL_BOOLEAN_BLIND | SQL_KEYWORD_CHAIN
);
// OR legacy fingerprint blacklist hit when `legacy` feature on
fn detect_sqli(input: &[u8]) -> DetectionVerdict {
    let snap = analyze_sqli(input);
    let detected = snap.constructs.intersects(BUILTIN_SQLI_POLICY)
        || (cfg!(feature = "legacy") && legacy_blacklist_hit(&snap.legacy_fingerprint));
    DetectionVerdict { detected, snapshot: snap }
}
```

### Future: construct-aware operator

Coraza could add `@detectSQLiConstructs` (or rule metadata) that exposes `AnalysisSnapshot` to SecLang - e.g. match `SQL_UNION | SQL_STACKED_QUERY` without depending on legacy fingerprint strings. **Rule definitions stay in CRS files**, not in this crate.

---

## Modern engine design (WAF-optimized)

### Default path (no `legacy`, no `deep`)

```
input &[u8]
  → prefilter (memchr for ', ", <, --, union, etc.) → early benign exit
  → normalize (stack buf 512B, cap) → AnalysisFlags
  → tokenize → [TokenMeta; 8] (offset, len, kind - no copies)
  → construct classify → ConstructFlags (bit OR per detector)
  → set VerdictHint (Benign | Suspicious | Decisive | Inconclusive)
  → optional: derive legacy_fingerprint into snapshot (if legacy feature)
  → AnalysisSnapshot
```

**No** full SQL AST. **No** sqlparser. **No** fingerprint-blacklist-as-primary on default path.

### Legacy engine (`legacy` feature)

- Static fingerprint tables from Go `sqli_data.go` / C `sqlparse_data.json` (build.rs codegen)
- Full fold + blacklist + `notWhitelist()` for **499-test corpus parity**
- Used to populate `LegacyFingerprint` and to satisfy `detect_sqli()` when construct engine is conservative
- **Not linked** in minimal/WASM builds if Coraza disables feature

### Deep analysis (`deep` feature - off by default)

Optional **second-stage analyzer** for cases where stage-1 construct detection is inconclusive or when the consumer explicitly requests deeper inspection. **`sqlparser` is allowed only here** - never on the default hot path.

#### Two-stage model

| Stage | Feature | When | Alloc | API |
|-------|---------|------|-------|-----|
| **1 (default)** | core (+ optional `legacy`) | Every field scan | **Zero heap** | `analyze_sqli` / `analyze_xss` → `AnalysisSnapshot` |
| **2 (optional)** | `deep` | Consumer-triggered only | May use `alloc` + `sqlparser` | `analyze_sqli_deep` (see below) |

Stage 1 always runs first and remains the only path for `@detectSQLi` / `@detectXSS` unless Coraza opts in to stage 2.

#### When Coraza runs `deep` (consumer policy - not library policy)

The library **does not** auto-escalate to `deep`. Coraza decides **when** stage 2 runs:

| Trigger | Example | Expected volume |
|---------|---------|-----------------|
| **Operator argument** | `@detectSQLi:deep` or future SecLang modifier | Explicit rules only |
| **Inconclusive escalation** | Stage-1 `VerdictHint::Inconclusive` (e.g. `TRUNCATED` + partial constructs) | **Target <1%** of field scans |

**Not in default wiring:** standard CRS 941/942 `@detectSQLi` uses stage 1 only. Coraza `Cargo.toml` must **not** enable `deep` by default.

#### Deep guardrails (mandatory)

| Guardrail | Limit |
|-----------|-------|
| **Input cap** | **2048 bytes** (`DEEP_MAX_INPUT_LEN`) - stricter than stage-1 8192 B |
| **Dialect** | **One dialect** per call - taken from stage-1 `AnalysisContext.dialect` |
| **AST budget** | **Bounded node count** (e.g. 256 nodes); exceed → bail, return partial upgraded snapshot |
| **Time** | Bail on budget; never unbounded parse |
| **WASM** | `wasm32-wasip1 --no-default-features` build excludes `deep` / `sqlparser` entirely |
| **Benchmarks** | Separate **fast-path** vs **deep-path** Criterion suites; **CI fails on fast-path regression only** |

#### Stage-2 API (feature-gated)

```rust
/// Requires `deep` feature. Never called from detect_* / analyze_* default path.
#[cfg(feature = "deep")]
pub fn analyze_sqli_deep(
    input: &[u8],
    prior: &AnalysisSnapshot,  // stage-1 result; avoids re-tokenizing when possible
) -> DeepAnalysisResult;

#[cfg(feature = "deep")]
pub struct DeepAnalysisResult {
    pub snapshot: AnalysisSnapshot,       // merged/upgraded construct flags
    pub sqlparser_ok: bool,                 // parse succeeded (not necessarily benign)
    pub dialect: SqlDialect,
    // optional diagnostic fields for audit/debug - may allocate
}
```

Stage 2 uses **`sqlparser`** for semantic confirmation (e.g. stacked statements, dialect-specific syntax) and merges findings back into `ConstructFlags`. XSS deep path (if added later) stays hand-written or HTML subset - **no heavy HTML crate on hot path**.

#### Constraints

- **`deep` is OFF by default** - not in Coraza default `Cargo.toml`; not in default `@detectSQLi` integration
- **Never** invoked from `detect_sqli` / `detect_xss` / `analyze_*` internally
- Guardrails enforced inside `analyze_sqli_deep` - 2 KiB cap, single dialect, bounded nodes, bail on budget
- For offline tuning and bypass review when explicitly enabled - not production default path

### Token model

```rust
#[repr(C)]
pub struct TokenMeta {
    pub offset: u16,
    pub len: u16,
    pub kind: TokenKind,   // u8 discriminant
}
```

Token text is always `input[offset..offset+len]` - zero copy.

### Normalization

- Decode common evasions (URL encoding layer, null-byte strip, case fold ASCII keywords) in **stack buffer**
- On overflow: partial normalize + `AnalysisFlags::TRUNCATED`
- Normalization is **not** full input transformation - bounded best-effort for detection only

---

## Rule model (Coraza-side)

**Rules are NOT shipped in libinjection-rs.**

### WAF init (off hot path)

1. Coraza loads SecRules / CRS from filesystem or embed (consumer concern).
2. At init, rules referencing `@detectSQLi`, `@detectXSS`, or future construct operators compile to read-only matchers:
   - `ConstructMask` - which bits trigger match
   - Optional legacy fingerprint patterns (transitional)
3. Hot path per request: operator calls `analyze_*` once per variable evaluation, compares snapshot to precompiled matcher.

### Policy evolution without library releases

| Change | Where |
|--------|-------|
| New CRS 942xxx rule using `@detectSQLi` | CRS tarball + Coraza reload |
| Tighter construct mask for UNION-only | Coraza operator config / new SecLang |
| Disable legacy fingerprint in audit | Coraza audit config |
| Add bypass exclusion for path `/api/v2` | Coraza SecRule |

---

## Dependency policy (revised)

| Tier | Crate / feature | Hot path? |
|------|-----------------|-----------|
| **Core runtime** | `memchr` (`default-features = false`) | Yes - every field scan |
| **`std` feature** | Enables `memchr/std` (runtime SIMD on native) | Yes (native Coraza) |
| **`legacy` feature** | Static fingerprint tables via build.rs | Yes (derived fingerprint only) |
| **`deep` feature** | `sqlparser` + `alloc` - second stage only | **No** - opt-in per Coraza policy |
| **`alloc` feature** | Explicit opt-in heap (required by `deep`) | **No** |
| **build.rs** | `phf_codegen` / table codegen | Only when `legacy` enabled |
| **Avoid (hot path)** | `regex`, `serde`, `proxy-wasm`, `bitflags` crate | - |
| **`sqlparser`** | Allowed **only** with `deep` feature | **Never** on stage-1 / default path |

```toml
[features]
default = ["legacy"]   # Coraza compat until CRS construct migration complete
std = ["memchr/std"]
legacy = []            # build.rs generates fingerprint tables
deep = ["dep:sqlparser", "alloc"]   # OFF by default - second-stage only
alloc = []             # explicit; pulled in by deep

[dependencies]
memchr = { version = "2", default-features = false }
sqlparser = { version = "0.54", optional = true, default-features = false, features = ["std"] }
```

**Default path:** stack-only `AnalysisSnapshot` + construct flags - zero heap, every field scan.

**`deep` path:** second-stage only; Coraza decides when; not automatic on every request.

---

## Success criteria

| Criterion | Verification |
|-----------|--------------|
| **Zero-alloc hot path** | `tests/no_alloc.rs` + Miri on stage-1 parsers - CI gate |
| **Fast-path latency** | Criterion p99 ≤ libinjection-go @ 256 B / 1 KiB - **CI fails on regression** |
| **Legacy corpus** | 100% pass with `--features legacy` (499 files) |
| **Bypass corpus** | Modern stage-1 **≥ legacy TP**; **no FP regression** |
| **WASM core** | `wasm32-wasip1 --no-default-features` clean |
| **Deep isolation** | `deep` not in default Coraza dependency features; `@detectSQLi` uses stage 1 only |
| **Policy location** | No embedded rule packs in crate |

---

## Implementation phases (reference)

| Phase | Deliverable |
|-------|-------------|
| **0–1** | Scaffold + corpus harness |
| **2a** | Legacy parity (`legacy`, 499 tests) |
| **2b** | `AnalysisSnapshot` + construct detectors (stack-only) |
| **3** | Coraza integration - `detection.rs`, no `deep` in default wiring |
| **4** | Coraza rule-matching interface + CRS 941/942 validation |
| **5** | Construct hardening (no heap) |
| **6** | `deep` feature - `sqlparser` second stage with guardrails |
| **7** | Bypass / differential / fuzz / alloc-guard + fast-path bench CI |

Details: [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).

---

## Explicit non-goals

- Embedded policy / YAML rule packs in this crate
- ML or statistical classifiers
- **`sqlparser` or any heavy parser on stage-1 / default hot path** (allowed only behind `deep`, consumer-triggered)
- Automatic escalation to `deep` on every field scan or inside `detect_*` / `analyze_*`
- **`deep` in default Coraza `Cargo.toml`** or standard `@detectSQLi` operator path
- proxy-wasm / cdylib / Envoy filter code
- Heap allocation in `detect_*` / `analyze_*` default path
- Deciding block vs allow (always Coraza)

---

## Related documents

- [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) - phased delivery
- [WASM_PORTABILITY.md](./WASM_PORTABILITY.md) - embedder constraints
- [LIBINJECTION_GO_ANALYSIS.md](./LIBINJECTION_GO_ANALYSIS.md) - legacy engine reference
