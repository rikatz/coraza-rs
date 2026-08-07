# Rust Best Practices for High-Performance Security Libraries

**Target:** libinjection-rs - SQL/XSS injection detection from byte strings  
**Context:** WAF hot path (Coraza `detectSQLi` / `detectXSS` operators), per-request/per-field evaluation  
**Audience:** Engineers porting or hardening the libinjection C reference implementation in Rust

---

## 1. Executive Summary

A libinjection port is a **byte-oriented, allocation-sensitive, stack-friendly parser** - not a typical application-layer Rust library. The C reference keeps nearly all working state on the stack: a fixed `tokenvec[5]`, an 8-byte fingerprint buffer, pointers into the input (`s`, `slen`), and a static keyword lookup tree compiled into the binary. Detection runs in microseconds on short strings and may execute **thousands of times per HTTP request** inside a WAF.

The Rust port should preserve these invariants:

| Invariant | Why it matters |
|-----------|----------------|
| **`&[u8]` as the primary input type** | Attacker-controlled WAF input is not valid UTF-8. Avoiding `&str` skips UTF-8 validation and matches libinjection semantics. |
| **Zero-copy tokenization** | Tokens are `(type, start, len)` slices into the input, not owned `String`s. |
| **Bounded stack storage** | C uses `LIBINJECTION_SQLI_MAX_TOKENS = 5` and `fingerprint[8]`. Mirror with `[Token; 8]` / `SmallVec<[Token; 8]>` and `[u8; 8]`. |
| **No per-detection heap allocation on the happy path** | Keyword/fingerprint tables are `static`; parser state is reused via `SqliState::reset()`. |
| **Errors, not panics** | libinjection v4 replaced `abort()` with `LIBINJECTION_RESULT_ERROR`. WAF code must never crash the process on malformed input. |
| **Deterministic, branch-predictable inner loops** | Hot functions (`parse_*`, `memchr2`, char-class tests) benefit from `#[inline]`, lookup tables, and SIMD-backed search (`memchr` crate). |

The existing `libinjectionrs` crate (used by Coraza today) already follows several of these patterns (`detect_sqli(&[u8])`, `SmallVec<[Token; 8]>`, `fingerprint: [u8; 8]`). A from-scratch port in `libinjection-rs/` should treat that crate as a reference implementation while tightening correctness against the C test vectors and reducing avoidable allocations (e.g. `fingerprint_string() -> String` on the hot path).

**Bottom line:** Write Rust that looks like idiomatic systems Rust - explicit lifetimes on parser state, `const` classification tables, owned-vs-borrowed API tiers - not like a direct line-by-line `#![allow(...)]` C transliteration with `String` everywhere.

---

## 2. Key Principles

### 2.1 Ownership, Borrowing, and Lifetimes

#### Parser state owns nothing from the input

The C `libinjection_sqli_state` holds `const char *s` and `size_t slen`. In Rust, encode this as a lifetime parameter:

```rust
pub struct SqliState<'a> {
    input: &'a [u8],
    pos: usize,
    flags: SqliFlags,
    tokens: [Token<'a>; 8],   // or SmallVec<[Token<'a>; 8]>
    token_count: usize,
    fingerprint: [u8; 8],
}

pub struct Token<'a> {
    pub ty: TokenType,
    pub span: &'a [u8],       // zero-copy view into input
    pub open: u8,            // quote char, if any
    pub close: u8,
}
```

The lifetime `'a` ties token spans to the input buffer. Callers cannot use tokens after the input is dropped - the borrow checker enforces what C enforced by convention.

#### Separate "init" from "detect" for reuse

WAF operators may scan the same normalized field multiple times (different flags/contexts). Expose:

```rust
impl<'a> SqliState<'a> {
    pub fn new(input: &'a [u8], flags: SqliFlags) -> Self { /* ... */ }

    /// Reset in-place; no allocation. Equivalent to C `libinjection_sqli_reset`.
    pub fn reset(&mut self, flags: SqliFlags) {
        self.pos = 0;
        self.token_count = 0;
        self.flags = flags;
        self.fingerprint = [0; 8];
        // do NOT zero input - it stays borrowed
    }

    pub fn detect(&mut self) -> Result<DetectionVerdict, ParseError> { /* ... */ }
}
```

#### Freeze input while parsing

Rust's borrow rules mirror the C invalidation bug (push to `Vec` while holding `&data[0]`). During tokenization, hold `&[u8]` immutably; never mutate a backing buffer. If normalization is required (URL decode, lowercase), either:

1. Normalize into a separate buffer **before** calling the detector, or
2. Use `Cow<'a, [u8]>` at the API boundary (see §2.2).

#### `'static` only for compile-time data

Keyword lists, fingerprint blacklists, and char-class tables belong in `static`/`const` data:

```rust
static KEYWORDS: &[(&[u8], TokenType)] = &[
    (b"select", TokenType::Keyword),
    (b"union",  TokenType::Union),
    // sorted for binary search
];

#[inline]
fn lookup_keyword(word: &[u8]) -> Option<TokenType> {
    KEYWORDS.binary_search_by_key(&word, |(k, _)| *k)
        .ok()
        .map(|i| KEYWORDS[i].1)
}
```

Do **not** build keyword maps at runtime with `HashMap::new()` unless you have measured proof that startup cost is acceptable and lookup is faster (unlikely for ~few-hundred static entries).

---

### 2.2 Avoiding Unnecessary Copies

#### Prefer `&[u8]` over `&str` on the public API

Coraza currently does `input.as_bytes()` before calling libinjection - correct, because WAF variables may contain invalid UTF-8 after transformations. The library API should accept `&[u8]` directly:

```rust
// Good - primary entry point
pub fn detect_sqli(input: &[u8]) -> DetectionResult { /* ... */ }

// Convenience wrapper; documents UTF-8 precondition
pub fn detect_sqli_str(input: &str) -> DetectionResult {
    detect_sqli(input.as_bytes())
}
```

**Do not** require `&str` and force callers to use `from_utf8_lossy` (allocates) or `str::from_utf8` (fails on binary data).

#### `Cow` at normalization boundaries

When optional preprocessing is needed (e.g. SQL Server `0x` hex literals, comment stripping for diagnostics):

```rust
pub fn detect_sqli_cow(input: Cow<'_, [u8]>) -> DetectionResult {
    match input {
        Cow::Borrowed(bytes) => detect_sqli(bytes),
        Cow::Owned(bytes) => detect_sqli(&bytes),
    }
}
```

Use `Cow::Borrowed` on the fast path. Only allocate when transformation actually changes bytes.

#### Move semantics for owned results

Return small, `Copy` verdict types; defer allocation to logging/audit paths:

```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DetectionVerdict {
    Clean,
    Sqli { fingerprint: [u8; 8] },  // fixed-size, no heap
    Error(ParseError),
}

impl DetectionVerdict {
    /// Audit/logging only - allocates
    pub fn fingerprint_str(&self) -> Option<String> {
        match self {
            Self::Sqli { fingerprint } => {
                let len = fingerprint.iter().position(|&b| b == 0).unwrap_or(8);
                Some(String::from_utf8_lossy(&fingerprint[..len]).into_owned())
            }
            _ => None,
        }
    }
}
```

Coraza's `capture_field(0, fingerprint.as_str())` needs a `&str` only at the audit boundary - not inside the tokenizer.

#### Slices, not subslices via `to_vec()`

Token values in C live in `stoken_t.val` (fixed buffer) because folding **merges** tokens. In Rust, prefer:

- **Non-merge path:** `&'a [u8]` slice into input (zero-copy).
- **Merge path:** fixed-size stack buffer `[u8; 32]` inside `Token`, with `len: u8`. Only spill to heap for pathological cases (should match C's bounded behavior).

```rust
// Anti-pattern
let word = String::from_utf8_lossy(&input[start..end]).into_owned();

// Idiomatic
let word = &input[start..end];
```

Case-insensitive compare without allocation:

```rust
#[inline]
fn eq_ascii_ci(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| x.eq_ignore_ascii_case(y))
}
```

#### `Arc` vs `Rc` - rarely needed inside the detector

| Type | Use in libinjection port |
|------|--------------------------|
| **`Arc<T>`** | Share immutable fingerprint/blacklist tables across threads if you lazy-load them (usually unnecessary - use `static`). Coraza shares `RuleGroup` via `Arc`; the detector itself stays stack-local. |
| **`Rc<T>`** | Avoid - WAF is multi-threaded. |
| **Neither** | Per-request `SqliState` on the stack. No shared mutable parser state. |

Thread-local reuse is an option for high-throughput servers:

```rust
thread_local! {
    static SQLI_STATE: RefCell<SqliState<'static>> = /* placeholder */;
}
// Prefer: pass &mut SqliState from caller (Coraza Transaction) for explicit lifetimes
```

Explicit `SqliState` reuse from the caller is clearer and avoids `'static` hacks.

#### Stack vs heap sizing guide

| Data | C size | Rust recommendation |
|------|--------|---------------------|
| Token vector | 5 active, 8 buffer | `[Token; 8]` on stack |
| Fingerprint | `char[8]` | `[u8; 8]` |
| Token value | `LIBINJECTION_SQLI_TOKEN_SIZE` | `[u8; 32]` or match C exactly |
| Keyword lookup | Static tree in `.rodata` | `static` sorted table or `phf` crate |
| Input | Caller-owned | `&[u8]` borrow |

Heap (`Vec`, `Box`, `String`) is for test harnesses, fingerprint pretty-printing, and error messages - not per-token storage.

---

### 2.3 Performance-Focused Patterns

#### Zero-copy scanning

The C code implements `memchr2` for delimiter pairs (`--`, `/*`, `*/`). Use the `memchr` crate:

```rust
use memchr::{memchr, memchr2, memchr3};

fn parse_line_comment(input: &[u8], mut pos: usize) -> usize {
    if let Some(p) = memchr2(b'-', b'-', &input[pos..]) {
        pos + p + 2
    } else {
        input.len()
    }
}
```

`memchr` uses SIMD on x86_64/aarch64 when available - a direct upgrade over C's scalar loop without `unsafe` in your code.

#### `#[inline]` and `#[inline(always)]` - surgically

Apply to:

- Char-class predicates (`is_sql_whitespace`, `is_operator_char`)
- Single-byte advance functions
- `TokenType` conversions

```rust
#[inline]
const fn is_digit(b: u8) -> bool {
    b.is_ascii_digit()
}

#[inline]
const fn char_class(b: u8) -> CharClass {
    CHAR_TABLE[b as usize]
}

const CHAR_TABLE: [CharClass; 256] = build_char_table();
```

Do **not** blanket `inline(always)` on large functions (`fold`, `blacklist_check`) - icache pressure hurts.

#### `const` / `const fn` for compile-time tables

Build classification and fold-rule tables at compile time:

```rust
const fn build_char_table() -> [CharClass; 256] {
    let mut t = [CharClass::Other; 256];
    // populate...
    t
}
```

This moves work from runtime to compile time and keeps `.rodata` hot paths clean.

#### SIMD - when to use it

| Scenario | Recommendation |
|----------|----------------|
| Find `'`, `"`, `\`, `/`, `-`, `<`, `>` in input | `memchr` / `memchr2` / `memchr3` |
| Case-folding ASCII keywords | SIMD less helpful; branchless `to_ascii_lowercase` on stack buffer only when folding merges |
| Fingerprint compare | 8 bytes - plain `u64` compare (`u64::from_ne_bytes(fingerprint[..8])`) |
| Custom wide scanning | `std::arch` only after benchmarking; prefer maintained crates |

Rule: **reach for `memchr` before writing `unsafe` SIMD**.

#### Allocation strategies

1. **Default:** stack-only, zero alloc per `detect()` call.
2. **`SmallVec<[T; N]`:** when token count has a soft bound but rare overflow is possible. C hard-limits at 5 - `SmallVec<[Token; 8]>` with capacity 8 never heap-allocates in correct operation.
3. **Bump allocator (`bumpalo`):** consider only if batch-processing many fields in one pass (e.g. scanning all args in a query string) where amortizing a single arena beats repeated stack setup. Not the first optimization.
4. **`String` pooling:** unnecessary - fingerprints fit in 8 bytes.

#### Benchmark-driven thresholds

Use `criterion` with inputs from libinjection's test corpus:

- Median payload size in WAF: ~50–500 bytes
- Tail: multi-KiB POST bodies (still scan only the matched variable, not whole body)

Track: allocations/call (via `dhat` or `stats_alloc`), ns/call, branch misses ( `perf` ).

---

### 2.4 Idiomatic Library / API Design

#### Tiered API surface

Follow the pattern established by `libinjectionrs` and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/):

```rust
// Tier 1 - 95% of callers (Coraza, modsecurity-style operators)
pub fn detect_sqli(input: &[u8]) -> DetectionResult;
pub fn detect_xss(input: &[u8]) -> DetectionResult;

// Tier 2 - flag/context control
pub fn detect_sqli_with_flags(input: &[u8], flags: SqliFlags) -> DetectionResult;

// Tier 3 - state reuse / debugging / parity testing
pub struct SqliState<'a> { /* ... */ }
impl SqliState<'_> {
    pub fn tokenize(&mut self) -> Result<(), ParseError>;
    pub fn fold(&mut self) -> Result<usize, ParseError>;
    pub fn fingerprint(&mut self) -> &[u8; 8];
}
```

#### Type design

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectionType {
    None,
    SqlInjection,
    Xss,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliFlags(u32);  // bitflags crate

impl SqliFlags {
    pub const QUOTE_SINGLE: Self = Self(1 << 0);
    pub const QUOTE_DOUBLE: Self = Self(1 << 1);
    // mirror C FLAG_* values exactly for test parity
}
```

Use `#[non_exhaustive]` on public enums to allow future token/flag extensions without semver breaks.

#### Error handling - never panic on untrusted input

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Unparsable,       // C: TYPE_EVIL
    TokenOverflow,    // exceeded LIBINJECTION_SQLI_MAX_TOKENS
    InvalidState,
}

pub type Result<T> = core::result::Result<T, ParseError>;
```

Map C `LIBINJECTION_RESULT_ERROR` to `Err(ParseError::*)`, not `panic!()`. Coraza should treat errors as non-match or log at debug level - configurable policy.

#### `no_std` considerations

libinjection is a pure parser + static tables - **`no_std` + `alloc` is feasible**:

```toml
[features]
default = ["std"]
std = []
alloc = []  # SmallVec, Vec for test-only paths
```

| Component | `no_std` approach |
|-----------|-------------------|
| Parser | `core` only |
| `SmallVec` | `feature = "alloc"` |
| `memchr` | Works without `std` (disable default features if needed) |
| Keyword tables | `'static` slices in `.rodata` |
| Tests | `std` behind `dev-dependencies` |

Full `no_std` (no `alloc`) is possible if you replace `SmallVec` with fixed arrays - recommended for embedded/WAF WASM targets.

#### Crate layout

```
libinjection-rs/
├── src/
│   lib.rs           # re-exports, detect_* functions
│   sqli/
│   │   mod.rs
│   │   token.rs     # Token, TokenType
│   │   parse.rs     # parse_* functions
│   │   fold.rs      # fold logic (port of libinjection_sqli_fold)
│   │   fingerprint.rs
│   │   lookup.rs    # keyword/fingerprint tables
│   │   state.rs     # SqliState
│   xss/
│   │   mod.rs
│   error.rs
│   flags.rs
├── data/            # generated from fingerprints.txt (build.rs)
└── tests/
    └── c_corpus.rs  # libinjection C test vectors
```

Use `build.rs` + `include_bytes!` / `phf` to compile `fingerprints.txt` into perfect-hash lookup - no runtime file I/O.

#### Rust API Guidelines checklist (high-signal items)

- **C-GETTER:** `fingerprint()` returns `&[u8]`, not hidden state mutation without documentation.
- **C-COMMON-TRAITS:** Derive `Copy`/`Clone`/`Debug`/`PartialEq` on flags and small types.
- **C-STRUCTURAL:** Use `#[non_exhaustive]` on extensible enums.
- **C-INTERMEDIATE:** Provide `detect_sqli_with_flags` between one-liner and full `SqliState`.
- **C-ERROR-CONTEXT:** `ParseError` is `Copy` + `Display`; no `anyhow` in library core.
- **C-NO-STD:** Document `no_std` support in crate README if implemented.

---

### 2.5 Common Anti-Patterns to Avoid

#### Parsing / detection anti-patterns

| Anti-pattern | Why it's wrong | Do instead |
|--------------|----------------|------------|
| `Regex` for tokenization | Slow compile, allocation, backtracking on attacker input | Hand-written byte scanner (like C) |
| `input.to_string()` at API entry | Allocates every call | `&[u8]` |
| `str::from_utf8` in hot path | Fails or branches on binary data | Stay on bytes |
| `String` per token | N allocations per payload | `&[u8]` spans or stack buffer |
| `HashMap<String, _>` for keywords | Heap + hashing on every lookup | Static sorted table / PHF |
| `Box<dyn Parser>` | Indirect call, allocation | Monomorphized `SqliState` |
| `unwrap()` / `expect()` on parse | DoS via panic (WAF must stay up) | `Result` + error mapping |
| `abort()` / `process::exit` on evil input | C pre-v4 behavior; unacceptable in WAF | Return `ParseError::Unparsable` |
| Cloning full input for each context try | libinjection tries multiple flag contexts | Reset `SqliState` in place |
| `Rc<RefCell<SqliState>>` | Single-threaded pattern in async WAF | Stack state or `&mut` param |

#### Rust-specific transliteration traps

| C idiom | Bad Rust port | Good Rust port |
|---------|---------------|----------------|
| `char*` + `strlen` | `&str` everywhere | `&[u8]` + explicit `len` |
| `memset(state, 0, ...)` | `SqliState::default()` that re-allocates inner `Vec` | `reset()` clearing fixed arrays |
| `goto`-like loops | Deeply nested `loop` + `break 'outer` without structure | Labeled blocks or state machine enum |
| Function pointers for lookup | `Box<dyn Fn(...)>` | Generic `fn` parameter or module-level static fn |
| `assert()` in production | `debug_assert!()` only | Release builds skip checks; errors returned |

#### WAF integration anti-patterns (Coraza-specific)

Current Coraza code (`coraza-rs/src/operators/detection.rs`):

```rust
let result = libinjectionrs::detect_sqli(input.as_bytes());
if result.is_injection() {
    if let Some(fingerprint) = &result.fingerprint {
        tx.capture_field(0, fingerprint.as_str());  // allocates if fingerprint is String
    }
}
```

Improvements for a hardened port:

1. Accept `&[u8]` from transaction variables directly (skip UTF-8 round-trip if variable storage is bytes).
2. Return `[u8; 8]` fingerprint; convert to `str` only in `capture_field`.
3. Allow reusing `SqliState` stored on `Transaction` to avoid re-parsing when multiple SQLi rules target the same variable.

#### Over-abstraction (from Coraza porting guidelines)

Do not introduce traits unless there are **multiple implementations**. libinjection has one parser - concrete types are fine:

```rust
// Unnecessary
trait InjectionDetector { fn detect(&self, input: &[u8]) -> bool; }

// Sufficient
pub fn detect_sqli(input: &[u8]) -> DetectionResult;
```

---

## 3. Recommendations for a libinjection Parsing/Detection Library

### 3.1 Architecture map (C → Rust)

```
Input &[u8]
    │
    ▼
SqliState::new(input, flags)
    │
    ├─► tokenize() ──► parse_* handlers (zero-copy spans)
    │                      │
    │                      └─► lookup_word() ──► static KEYWORDS / fingerprints
    │
    ├─► fold() ──► merge rules (1/2/3-token patterns from C)
    │
    ├─► fingerprint[0..5] = token types as ASCII bytes ('s', 'k', '1', ...)
    │
    └─► check_fingerprint()
            ├─► blacklist (static set / bloom / sorted array)
            └─► not_whitelist (contextual false-positive filters)
```

Port **tests first**: libinjection ships hundreds of test cases in `tests/test-sqli-*.txt` and fingerprint lists. Wire these as `#[test]` + `rstest` parameterized cases before refactoring for elegance.

### 3.2 Token representation

Mirror C token types exactly (ASCII discriminant chars):

```rust
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenType {
    None = 0,
    Keyword = b'k',
    Union = b'U',
    Bareword = b'n',
    Number = b'1',
    String = b's',
    Operator = b'o',
    LogicOperator = b'&',
    Comment = b'c',
    LeftParens = b'(',
    Evil = b'X',  // unparsable
    // ... full set from sqli_token_types enum in libinjection_sqli.c
}
```

Fingerprint generation (from C):

```rust
fn build_fingerprint(tokens: &[Token], out: &mut [u8; 8]) {
    for (i, tok) in tokens.iter().enumerate().take(5) {
        out[i] = tok.ty as u8;
    }
    out[tokens.len().min(5)] = 0; // NUL terminate
}
```

### 3.3 Flag/context iteration

C tries multiple parsing contexts (quote flags, SQL dialect hints). Structure as:

```rust
const CONTEXTS: &[SqliFlags] = &[
    SqliFlags::NONE,
    SqliFlags::QUOTE_SINGLE,
    SqliFlags::QUOTE_DOUBLE,
    // ...
];

pub fn detect_sqli(input: &[u8]) -> DetectionResult {
    for &flags in CONTEXTS {
        let mut st = SqliState::new(input, flags);
        match st.detect() {
            Ok(DetectionVerdict::Sqli { fingerprint }) => {
                return DetectionResult::sqli(fingerprint);
            }
            Ok(DetectionVerdict::Clean) => continue,
            Err(_) => continue, // try next context; or short-circuit on Evil
        }
    }
    DetectionResult::clean()
}
```

Reuse one `SqliState` with `reset(flags)` instead of reallocating.

### 3.4 XSS module differences

XSS detection is HTML/tag oriented - still byte-based, but state includes context (attribute, data, comment). Same rules apply:

- `&[u8]` input
- Stack state machine (no `Regex`)
- Static tag/attribute lists in `static` data
- Separate `XssState<'a>` from `SqliState<'a>` - do not unify into one mega-trait

### 3.5 Security-specific correctness

1. **Constant-time comparisons** are *not* required for fingerprint matching (fingerprints are not secrets) - favor speed.
2. **Do require** bounded work: cap token count, cap fold iterations, cap input length at API boundary (`input.len().min(MAX_SCAN)`).
3. **No `unsafe` string** creation from bytes except in documented audit helpers (Coraza's `wrap_unsafe` pattern).
4. **Fuzz** with `cargo fuzz` - libinjection is a binary parser; fuzz tokenize + fold + xss decode.

### 3.6 Integration contract for Coraza

```rust
// Recommended operator integration
impl Operator for DetectSQLi {
    fn evaluate<TX: TransactionState>(&self, tx: Option<&mut TX>, input: &str) -> bool {
        self.evaluate_bytes(tx, input.as_bytes())
    }
}

impl DetectSQLi {
    pub fn evaluate_bytes<TX: TransactionState>(
        &self,
        tx: Option<&mut TX>,
        input: &[u8],
    ) -> bool {
        if input.is_empty() {
            return false;
        }
        let result = libinjection::detect_sqli(input);
        if let (Some(tx), DetectionResult { fingerprint: Some(fp), .. }) =
            (tx, result) && result.is_injection()
        {
            tx.capture_field(0, fp.as_ascii_str()); // stack-only conversion
        }
        result.is_injection()
    }
}
```

Add `evaluate_bytes` so binary-safe variable paths skip UTF-8 entirely.

### 3.7 Testing and parity checklist

- [ ] Port all `test-sqli-*.txt` vectors (expected detect / no-detect)
- [ ] Fingerprint string parity (`s&1UE`, etc.) against C 4.0.0
- [ ] Error cases return `Err`, never panic (C v4 behavior)
- [ ] `cargo miri test` on parser (validate no undefined behavior if any `unsafe`)
- [ ] `criterion` benchmarks vs C baseline and vs `libinjectionrs` 0.1.1
- [ ] `#![deny(clippy::pedantic)]` selectively - not at expense of readable ports

### 3.8 Suggested dependency policy

| Crate | Role | Notes |
|-------|------|-------|
| `memchr` | Delimiter scanning | Default features OK for WAF |
| `smallvec` | Token buffer | `SmallVec<[Token; 8]>` |
| `bitflags` | `SqliFlags` | Matches C `#define FLAG_*` |
| `phf` / `phf_codegen` | Perfect hash for fingerprints | Build-time only |
| `criterion` | Benchmarks | Dev dependency |
| Avoid `regex`, `nom` (initially) | - | Hand parser matches C; add only if proven equivalent |

Keep default dependency count minimal - security libraries have long audit tails.

---

## 4. References

### Official Rust documentation

| Resource | URL | Relevance |
|----------|-----|-----------|
| The Rust Book - Ownership | https://doc.rust-lang.org/book/ch04-00-understanding-ownership.html | Ownership/borrow basics |
| Rust by Example - Lifetimes | https://doc.rust-lang.org/rust-by-example/scope/lifetime.html | Parser `'a` patterns |
| The Rustonomicon - Ownership | https://doc.rust-lang.org/nomicon/ownership.html | Advanced lifetime/validity |
| Rust Reference - Inline attributes | https://doc.rust-lang.org/reference/attributes/codegen.html#the-inline-attribute | `#[inline]` usage |
| `const` evaluation | https://doc.rust-lang.org/reference/const_eval.html | Compile-time tables |
| `no_std` | https://doc.rust-lang.org/nomicon/embedding.html | Embedded/WASM WAF targets |

### Rust API design

| Resource | URL |
|----------|-----|
| Rust API Guidelines (full) | https://rust-lang.github.io/api-guidelines/ |
| API Guidelines Checklist | https://rust-lang.github.io/api-guidelines/checklist.html |
| Naming (`C-CASE`) | https://rust-lang.github.io/api-guidelines/naming.html |
| Future proofing (`C-ENUM-RESERVED`) | https://rust-lang.github.io/api-guidelines/future-proofing.html |
| `rust-lang/api-guidelines` repo | https://github.com/rust-lang/api-guidelines |

### Performance and low-allocation Rust

| Resource | URL | Relevance |
|----------|-----|-----------|
| `memchr` crate docs | https://docs.rs/memchr | SIMD byte search |
| `memchr` README (SIMD rationale) | https://github.com/BurntSushi/memchr | Why not `str::find` |
| `smallvec` docs | https://docs.rs/smallvec | Stack-first vectors |
| `bumpalo` docs | https://docs.rs/bumpalo | Arena allocation (optional) |
| `phf` docs | https://docs.rs/phf | Compile-time perfect hashing |
| Criterion.rs | https://bheisler.github.io/criterion.rs/book/ | Benchmarking |
| `dhat` - heap profiling | https://docs.rs/dhat | Allocations per detect |

### libinjection reference implementation

| Resource | URL |
|----------|-----|
| libinjection repository | https://github.com/libinjection/libinjection |
| SQLi parser (`libinjection_sqli.c`) | https://github.com/libinjection/libinjection/blob/main/src/libinjection_sqli.c |
| SQLi header / state struct | https://github.com/libinjection/libinjection/blob/main/src/libinjection_sqli.h |
| Fingerprint list | https://github.com/libinjection/libinjection/blob/main/src/fingerprints.txt |
| v4.0 error handling (no `abort`) | https://github.com/libinjection/libinjection (see `injection_result_t`) |

### Existing Rust ecosystem

| Resource | URL | Notes |
|----------|-----|-------|
| `libinjectionrs` (pure Rust port) | https://docs.rs/libinjectionrs | Reference API; Coraza dependency today |
| `libinjection` (FFI bindings) | https://docs.rs/libinjection | C wrapper; compare perf/correctness |
| Coraza detection operators | `coraza-rs/src/operators/detection.rs` | Integration pattern |

### Security / robust parsing

| Resource | URL |
|----------|-----|
| `cargo-fuzz` book | https://rust-fuzz.github.io/book/ |
| OWASP ModSecurity libinjection operator docs | https://github.com/SpiderLabs/ModSecurity/wiki |

---

## Appendix: Quick Decision Matrix

| Question | Answer for libinjection-rs |
|----------|----------------------------|
| Primary input type? | `&[u8]` |
| Primary output type? | `DetectionResult` (verdict + optional `[u8; 8]`) |
| Heap alloc per detect? | Target: **0** |
| Panic on bad input? | **Never** |
| `no_std`? | Yes, with `alloc` feature recommended |
| `Arc`/`Rc` in parser? | **No** |
| `Regex`? | **No** |
| `Cow`? | At normalization boundary only |
| `SmallVec`? | Yes, `[Token; 8]` inline capacity |
| SIMD? | Via `memchr`, not hand-rolled initially |
| Traits for parser? | No - concrete `SqliState` |
| Test source of truth? | libinjection C test corpus + fingerprints.txt |

---

*Document version: 2026-07-08 - for libinjection-rs development in the Coraza WAF workspace.*
