# libinjection-go Technical Analysis

> **Purpose:** Primary reference for a pure-Rust libinjection port used by [coraza-rs](https://github.com/corazawaf/coraza-rs) WAF operators `@detectSQLi` and `@detectXSS`.
>
> **Source:** [corazawaf/libinjection-go](https://github.com/corazawaf/libinjection-go) (main branch, analyzed 2026-07-08; Coraza pins **v0.3.2**).
>
> **Upstream lineage:** Go port of Nick Sullivan's [C libinjection](https://github.com/client9/libinjection) (client9/libinjection), maintained by the Coraza project.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Repository Structure](#repository-structure)
3. [Public API Surface](#public-api-surface)
4. [SQL Injection Detection](#sql-injection-detection)
5. [XSS Detection](#xss-detection)
6. [Fingerprinting and Tokenization](#fingerprinting-and-tokenization)
7. [Important Constants, Lookup Tables, and Fingerprints](#important-constants-lookup-tables-and-fingerprints)
8. [File-by-File Breakdown](#file-by-file-breakdown)
9. [Test Coverage Approach](#test-coverage-approach)
10. [Performance Characteristics](#performance-characteristics)
11. [Differences from Original C libinjection](#differences-from-original-c-libinjection)
12. [Dependencies and Coraza Integration](#dependencies-and-coraza-integration)
13. [Behavioral Parity Requirements for Rust Port](#behavioral-parity-requirements-for-rust-port)
14. [Known Limitations and TODOs](#known-limitations-and-todos)

---

## Architecture Overview

libinjection-go is a **single-package, zero-dependency** Go library (`module github.com/corazawaf/libinjection-go`) that implements two independent detection pipelines:

```
┌─────────────────────────────────────────────────────────────────┐
│                     Public API (thread-safe)                    │
│   IsSQLi(input) → (bool, fingerprint)    IsXSS(input) → bool  │
└───────────────┬─────────────────────────────┬───────────────────┘
                │                             │
    ┌───────────▼──────────┐      ┌───────────▼──────────┐
    │   SQLi Pipeline      │      │   XSS Pipeline       │
    │                      │      │                      │
    │ 1. Tokenize (byte    │      │ 1. HTML5 tokenizer   │
    │    dispatch table)   │      │    (5 entry contexts)│
    │ 2. Fold to ≤5 tokens │      │ 2. Per-token policy  │
    │ 3. Build fingerprint │      │    checks            │
    │ 4. Blacklist lookup  │      │    (tags/attrs/URLs) │
    │ 5. Whitelist filter  │      │                      │
    │ 6. Multi-pass reparse│      │                      │
    │    (ANSI/MySQL/quotes│      │                      │
    └──────────────────────┘      └──────────────────────┘
```

**Design philosophy (inherited from C libinjection):**

- **Fingerprint-based SQLi detection:** Normalize attacker input into a short sequence of token *type* characters (e.g. `s&1`), then match against a large blacklist of known SQLi patterns. This avoids full SQL parsing while catching structural attack shapes.
- **HTML5-context XSS detection:** Tokenize input as HTML in multiple plausible contexts (raw data, unquoted/single/double/back-quoted attribute values), then apply blacklist rules to tags, event handlers, URL schemes, and IE-specific comment syntax.
- **Stateful parsing, stateless API:** All state lives in stack-allocated `sqliState` / `h5State` structs created per call. No globals are mutated during detection → **thread-safe** without locks.

**Total source size:** ~14,000 lines of Go across 18 source files; ~9,500 lines are the embedded `sqlKeywords` map in `sqli_data.go`.

---

## Repository Structure

```
libinjection-go/
├── sqli.go              # SQLi state machine, fold(), check(), IsSQLi()
├── sqli_const.go        # Token type bytes, flags, lookup constants
├── sqli_token.go        # sqliToken struct, string parsing, unary op helpers
├── sqli_parse.go        # Per-byte token parsers (parseWord, parseNumber, …)
├── sqli_helpers.go      # Escaping, whitespace, keyword search helpers
├── sqli_data.go         # byteParsers[256], sqlKeywords map (~9.5K entries)
├── xss.go               # isXSS(), IsXSS() - multi-context orchestration
├── xss_helpers.go       # isBlackTag/Attr/URL, htmlEncodeStartsWith
├── xss_decls.go         # blackTags, blackEvents, blacks, gsHexDecodeMap
├── html5.go             # HTML5 tokenizer state machine
├── html5_decls.go       # h5State struct, token type constants
├── *_test.go            # Unit tests + file-based test drivers
└── tests/               # ~500 C-compatible test corpus files
    ├── test-sqli-*.txt       (54 files)  - end-to-end SQLi fingerprints
    ├── test-folding-*.txt    (118 files) - token folding output
    ├── test-tokens-*.txt     (249 files) - raw tokenization output
    ├── test-html5-*.txt      (68 files)  - HTML5 tokenizer output
    └── test-xss-*.txt        (7 files)   - XSS boolean detection
```

**CI / quality tooling:** CodeQL, codecov, pre-commit hooks. **License:** BSD-3-Clause (same as C libinjection).

---

## Public API Surface

The package exports exactly **two public functions**. All other types and functions are unexported (lowercase).

### `IsSQLi(input string) (bool, string)`

```go
func IsSQLi(input string) (bool, string) {
    state := new(sqliState)
    sqliInit(state, input, 0)
    result := state.check()
    if result {
        return result, state.fingerprint
    }
    return result, ""
}
```

| Aspect | Behavior |
|--------|----------|
| **Input** | Raw string (typically a single HTTP parameter value) |
| **Output** | `(true, fingerprint)` on detection; `(false, "")` otherwise |
| **Fingerprint** | 1–5 byte string of token type characters (see [Token Types](#sqli-token-type-bytes)); returned **without** the internal `0` prefix used for blacklist lookup |
| **Empty input** | `(false, "")` |

### `IsXSS(input string) bool`

```go
func IsXSS(input string) bool {
    return isXSS(input, html5FlagsDataState) ||
        isXSS(input, html5FlagsValueNoQuote) ||
        isXSS(input, html5FlagsValueSingleQuote) ||
        isXSS(input, html5FlagsValueDoubleQuote) ||
        isXSS(input, html5FlagsValueBackQuote)
}
```

| Aspect | Behavior |
|--------|----------|
| **Input** | Raw string |
| **Output** | `true` if XSS detected in **any** of 5 HTML parsing contexts |
| **No fingerprint** | Unlike SQLi, XSS returns only a boolean |

### Internal Key Types (unexported, must be replicated in Rust)

| Type | File | Role |
|------|------|------|
| `sqliState` | `sqli.go` | SQLi parser/folder state |
| `sqliToken` | `sqli_token.go` | Single SQL token |
| `h5State` | `html5_decls.go` | HTML5 tokenizer state |
| `fnH5State` | `html5_decls.go` | State function pointer (`func() bool`) |

---

## SQL Injection Detection

### High-Level Flow

```
IsSQLi(input)
  └─ check()
       ├─ Pass 1: sqliFingerprint(QuoteNone | SQLAnsi) → lookup
       ├─ Pass 2: if MySQL comments seen → sqliFingerprint(QuoteNone | SQLMysql) → lookup
       ├─ Pass 3: if input contains ' → sqliFingerprint(QuoteSingle | SQLAnsi) → lookup
       ├─ Pass 4: if MySQL comments + ' → sqliFingerprint(QuoteSingle | SQLMysql) → lookup
       ├─ Pass 5: if input contains " → sqliFingerprint(QuoteDouble | SQLMysql) → lookup
       └─ return false
```

Each `lookup` calls `lookupWord(sqliLookupFingerprint, fingerprint)` which runs `checkFingerprint()` = `blacklist() && notWhitelist()`.

### Step-by-Step: Tokenization

**Entry:** `tokenize()` in `sqli.go`

1. **Empty input** → return `false` (no more tokens).
2. **Simulated quote context:** If `pos == 0` and flags include `sqliFlagQuoteSingle` or `sqliFlagQuoteDouble`, parse as if input started inside a string (used for reparse passes).
3. **Byte dispatch loop:** For each byte at `s.pos`:
   - Call `parseByteFunctions(s, ch)` → `byteParsers[ch](s)` (256-entry dispatch table built in `sqli_data.go`).
   - Parser either assigns `s.current` (a `sqliToken`) and advances `s.pos`, or advances `s.pos` without emitting (whitespace).
   - Return `true` when a token is emitted; continue loop on whitespace/no-token.
4. **End of input** → return `false`.

**Parser highlights** (`sqli_parse.go`):

| Parser | Trigger | Notes |
|--------|---------|-------|
| `parseWhite` | ASCII ≤32, 127, 160 | Skip, no token |
| `parseString` | `'` or `"` | Escaped strings, doubled-quote escape |
| `parseDash` | `-` | `--` comment vs unary minus (ANSI vs MySQL diverge) |
| `parseHash` | `#` | MySQL EOL comment or operator (mode-dependent) |
| `parseSlash` | `/` | `/* */` comment; nested `/*` or `/*!` → `X` (evil) |
| `parseNumber` | digits, `.` | hex/binary/scientific/float suffixes; **`1.e` without exponent is ignored** (WAF bypass fix) |
| `parseWord` | alpha/unicode | Keyword lookup; splits on embedded `.` or `` ` `` |
| `parseVar` | `@` | `@@`, backtick/quoted vars |
| `parseTick` | `` ` `` | MySQL identifier |
| `parseMoney` | `$` | PostgreSQL `$tag$`, `$$`, or bare `$` |
| `parseQString` | `Q'` / `q'` | Oracle q-quote strings |
| `parseBWord` | `[` | T-SQL bracket identifiers |
| `parseBackSlash` | `\` | MySQL `\N` null literal |

### Step-by-Step: Folding

**Entry:** `fold()` in `sqli.go` - reduces token stream to **at most 5** fingerprint tokens.

1. **Skip leading noise:** Tokenize until first token that is NOT comment, `(`, SQL type, or unary operator. If input is only noise → return 0.
2. **Main fold loop:** Maintain `pos` (write cursor) and `left` (fold frontier):
   - Read 2 tokens at a time.
   - Apply **2-token fold rules** (string merge, semicolon collapse, unary op removal, keyword merge, IN/LIKE disambiguation, T-SQL IF, function/column name disambiguation, backslash folding, brace handling, etc.).
   - If no 2-token rule matches, read a 3rd token and apply **3-token fold rules** (arithmetic collapse, `bareword . bareword` → drop `.bareword`, comma lists, etc.).
   - If no rule matches, advance `left++` (commit leftmost token).
3. **Max-token overflow handling:** Special cases when `pos >= 5` for patterns like `1,(1)`, `n,(n)`, etc.
4. **Trailing comment reattachment:** If ≤4 tokens and a dangling comment was seen, append it.
5. **Cap at 5:** `if left > maxTokens { left = maxTokens }`.

### Step-by-Step: Fingerprint Generation

**Entry:** `sqliFingerprint(flags)` in `sqli.go`

1. `reset(flags)` - reinitialize state with same input but new flags.
2. `fold()` → `length` token count.
3. **PHP backtick edge case:** Unclosed empty backtick bareword → reclassify as comment.
4. Build fingerprint: concatenate each token's `category` byte.
5. If any token is `X` (evil/unparseable) → fingerprint = `"X"`, early return.

**Example:** Input `1' OR 1=1` → tokens after fold → fingerprint `"1&1"` or similar (depends on folding).

### Step-by-Step: Blacklist Lookup

**Entry:** `blacklist()` in `sqli.go`

1. Uppercase fingerprint bytes.
2. Prepend `'0'` → key like `"01&1"`.
3. Lookup in `sqlKeywords` map.
4. Match iff value == `'F'` (`sqliTokenTypeFingerprint`).

The map contains **8367 fingerprint entries** (keys starting with `0`) plus **~985 keyword/operator/phrase entries**.

### Step-by-Step: Whitelist (False-Positive Reduction)

**Entry:** `notWhitelist()` in `sqli.go` - runs **after** blacklist match; returns `true` to **confirm** SQLi.

Key rules:

| Condition | Effect |
|-----------|--------|
| Fingerprint ends in `c` (comment) + input contains `sp_password` | Force SQLi (MSSQL audit evasion) |
| 2-token fingerprint ending in `U` (UNION) with only 2 stats tokens | **Not** SQLi (reduce FP on "1 union") |
| 2-token `nc` with `#` comment | Not SQLi |
| 2-token `nc` with bareword + non-`/*` comment | Not SQLi |
| 2-token `1c` with block comment `/*` | SQLi |
| 2-token `1c` without proper `--`/`/*` separator after number | Not SQLi (base64-like strings) |
| 2-token ending in `--` comment with content after `--` | Not SQLi |
| 3-token `sos`/`s&s` string concatenation without open/close quotes | SQLi |
| 3-token `s&n`, `n&1`, etc. with exactly 3 stats tokens | Not SQLi ("sexy and 17") |
| 3-token with keyword not `INTO` | Not SQLi |

### MySQL Reparse Trigger

**Entry:** `reparseAsMySQL()` - returns true if `statsCommentDDX > 0` or `statsCommentHash > 0`.

This handles the ANSI vs MySQL `--` comment divergence: `--foo` is a comment in ANSI but two unary minus operators in MySQL.

---

## XSS Detection

### High-Level Flow

```
IsXSS(input)
  for each context in [DataState, ValueNoQuote, ValueSingleQuote,
                       ValueDoubleQuote, ValueBackQuote]:
    isXSS(input, context)
      h5.init(input, context)
      for h5.next():
        switch token type → apply blacklist rules
      return false
```

**Early exit:** Any rule match → immediately return `true`.

### HTML5 Tokenizer Contexts

| Flag | Initial State | Simulates |
|------|---------------|-----------|
| `html5FlagsDataState` | `stateData` | Normal HTML document |
| `html5FlagsValueNoQuote` | `stateBeforeAttributeName` | Unquoted attribute value context |
| `html5FlagsValueSingleQuote` | `stateAttributeValueSingleQuote` | Inside `'...'` attribute |
| `html5FlagsValueDoubleQuote` | `stateAttributeValueDoubleQuote` | Inside `"..."` attribute |
| `html5FlagsValueBackQuote` | `stateAttributeValueBackQuote` | Inside `` `...` `` attribute (IE) |

The tokenizer implements a **subset** of the HTML5 spec (sections referenced in comments, e.g. 12.2.4.x) plus IE/Opera legacy extensions (`%>` comments, backtick quotes, null bytes in tag names).

### Step-by-Step: Token Processing in `isXSS()`

For each token emitted by `h5.next()`:

| Token Type | Check |
|------------|-------|
| `html5TypeDocType` | **Always XSS** (`<!DOCTYPE ...>`) |
| `html5TypeTagNameOpen` | `isBlackTag(name)` - exact match against 17 tags + SVG*/XSL* prefix |
| `html5TypeAttrName` | `isBlackAttr(name)` → stores attribute type for value check |
| `html5TypeAttrValue` | Depends on attribute type from preceding name (see below) |
| `html5TypeTagComment` | Backtick in comment; `[IF` IE conditional; `XML` prefix; `IMPORT`/`ENTITY` after null-stripped uppercase |

**Attribute value handling:**

| Attribute Type | Value Check |
|----------------|-------------|
| `attributeTypeNone` | Skip |
| `attributeTypeBlack` | **XSS** (e.g. `onclick`, `dataformatas`) |
| `attributeTypeAttrURL` | `isBlackURL(value)` - scheme starts with DATA/JAVA/VBSCRIPT/VIEW-SOURCE |
| `attributeTypeStyle` | **Always XSS** (includes `style=` and `filter=`) |
| `attributeTypeAttrIndirect` | Re-check value as attribute name (`attributename=`) |

### Step-by-Step: Blacklist Helpers

**`isBlackTag(s)`** (`xss_helpers.go`):
1. Normalize: uppercase ASCII, strip null bytes (max 64 chars).
2. Exact match against `blackTags` (17 entries: SCRIPT, IFRAME, SVG-not-prefix, etc.).
3. Prefix match: `SVG*` or `XSL*` (first 3 chars).

**`isBlackAttr(s)`** (`xss_helpers.go`):
1. Normalize (same as above).
2. Check `XMLNS`, `XLINK` → black.
3. Check `ON*` against `blackEvents` (~430 event handler names from WebKit/Chromium/Firefox sources).
4. Check against `blacks` (18 named attributes with type classification).

**`isBlackURL(s)`** (`xss_helpers.go`):
1. Trim leading whitespace/control/high-bit chars.
2. HTML-decode and case-fold prefix match against `DATA`, `VIEW-SOURCE`, `VBSCRIPT`, `JAVA`.

**`htmlEncodeStartsWith(a, b)`** - Decodes `&#...;` / `&#x...;` entities in `b` while comparing prefix `a`. Uses `HasPrefix` semantics (fixed in v0.3.1 to avoid substring false positives).

---

## Fingerprinting and Tokenization

### SQLi Token Type Bytes

Each token contributes one character to the fingerprint:

| Byte | Constant | Meaning |
|------|----------|---------|
| `k` | `sqliTokenTypeKeyword` | SQL keyword (generic) |
| `U` | `sqliTokenTypeUnion` | UNION / UNION ALL |
| `B` | `sqliTokenTypeGroup` | GROUP BY |
| `E` | `sqliTokenTypeExpression` | SELECT, CASE, WHEN, … |
| `t` | `sqliTokenTypeSQLType` | CAST, CHAR, … |
| `f` | `sqliTokenTypeFunction` | SQL function call |
| `n` | `sqliTokenTypeBareWord` | Unrecognized identifier |
| `1` | `sqliTokenTypeNumber` | Numeric literal |
| `v` | `sqliTokenTypeVariable` | `@var`, `@@var` |
| `s` | `sqliTokenTypeString` | Quoted string |
| `o` | `sqliTokenTypeOperator` | `=`, `||`, `>=`, … |
| `&` | `sqliTokenTypeLogicOperator` | AND, OR, XOR, … |
| `c` | `sqliTokenTypeComment` | `--`, `#`, `/* */` |
| `A` | `sqliTokenTypeCollate` | COLLATE |
| `(` `)` | Left/Right paren | |
| `{` `}` | Left/Right brace | ODBC/MySQL extension |
| `.` | Dot | Member access |
| `,` | Comma | |
| `:` | Colon | |
| `;` | SemiColon | |
| `T` | `sqliTokenTypeTSQL` | T-SQL control flow (IF after `;`) |
| `?` | `sqliTokenTypeUnknown` | Unrecognized byte |
| `X` | `sqliTokenTypeEvil` | Unparseable (nested comments, `{ ```) |
| `F` | `sqliTokenTypeFingerprint` | Map value only (not in output) |
| `\` | `sqliTokenTypeBackslash` | T-SQL backslash (transient) |

### Token Merge (Compound Phrases)

`merge(tokenA, tokenB)` concatenates with space, looks up in `sqlKeywords`. Examples from the map:

- `"UNION ALL"` → type `U`
- `"NOT IN"` → type `k` (may later become operator `o`)
- `"SELECT"` → type `E`
- `"AND"`, `"OR"` → type `&`

### SQLi Flags

```go
sqliFlagQuoteNone   = 1   // Parse as-is
sqliFlagQuoteSingle = 2   // Pretend input starts in '...'
sqliFlagQuoteDouble = 4   // Pretend input starts in "..."
sqliFlagSQLAnsi     = 8   // ANSI comment rules
sqliFlagSQLMysql    = 16  // MySQL comment rules (#, --nonwhite)
```

Default: `sqliFlagQuoteNone | sqliFlagSQLAnsi`.

### HTML5 Token Types

| Value | Name | Emitted When |
|-------|------|--------------|
| 0 | `html5TypeDataText` | Text between tags |
| 1 | `html5TypeTagNameOpen` | Opening tag name |
| 2 | `html5TypeTagNameClose` | Closing `>` of opening tag |
| 3 | `html5TypeTagNameSelfClose` | `/>` self-close |
| 4 | `html5TypeTagData` | (unused in current code paths) |
| 5 | `html5TypeTagClose` | Closing tag `</...>` |
| 6 | `html5TypeAttrName` | Attribute name |
| 7 | `html5TypeAttrValue` | Attribute value |
| 8 | `html5TypeTagComment` | Comment content |
| 9 | `html5TypeDocType` | DOCTYPE declaration |

---

## Important Constants, Lookup Tables, and Fingerprints

### `sqlKeywords` Map (`sqli_data.go`)

| Category | Count | Key Pattern | Value |
|----------|-------|-------------|-------|
| Fingerprints | 8,367 | `"0" + FINGERPRINT` e.g. `"0s&1"`, `"01UEk"` | `'F'` |
| Operators | ~30 | `"="`, `"<>"`, `"::"`, … | `'o'` or specific type |
| Keywords | ~200+ | `"SELECT"`, `"UNION"`, `"FROM"`, … | `'E'`, `'U'`, `'k'`, … |
| Functions | ~100+ | `"LOAD_FILE"`, `"SLEEP"`, … | `'f'` |
| Phrases | ~50+ | `"UNION ALL"`, `"ORDER BY"`, … | various |

**Fingerprint examples** (from test corpus):

| Input | Expected Fingerprint | Detected |
|-------|---------------------|----------|
| `1' or 1.e(1)` | `s&(1)` | Yes |
| `-1' and 1=1 union/* foo */select load_file(...)` | (varies) | Yes |
| `foo 'bar' "zap"` | (empty) | No |
| `1# blah blah` | (empty) | No (FP reduction) |

### `byteParsers[256]` (`sqli_data.go`)

Built by `buildByteParsers()`: maps each byte 0–255 to a parser function. High bytes (128–255, except 160) → `parseWord`. This table must be **bit-identical** in a Rust port.

### XSS Blacklists (`xss_decls.go`)

| Table | Size | Purpose |
|-------|------|---------|
| `blackTags` | 17 strings | Dangerous HTML tags |
| `blackEvents` | ~430 strings | `on*` event handler suffixes |
| `blacks` | 18 entries | Named attributes with type classification |
| `gsHexDecodeMap` | 256 ints | HTML hex entity decoding (256 = invalid) |

### Limits

| Constant | Value | Location |
|----------|-------|----------|
| `maxTokens` | 5 | `sqli_token.go` |
| `tokenSize` | 32 | Max token value length |
| `maxNormalizedTokenLen` | 64 | XSS tag/attr normalization buffer |

---

## File-by-File Breakdown

| File | Lines | Description |
|------|-------|-------------|
| **`sqli.go`** | 910 | Core SQLi logic: `sqliState`, `fold()`, `sqliFingerprint()`, `blacklist()`, `notWhitelist()`, `check()`, `IsSQLi()`. Contains extensive fold rule switch statements. |
| **`sqli_const.go`** | 55 | All SQLi constants: flags, lookup types, token type byte values. |
| **`sqli_token.go`** | 108 | `sqliToken` struct, `parseStringCore()`, `assign()`, `isUnaryOp()`, `isArithmeticOp()`. |
| **`sqli_parse.go`** | 506 | All byte-level parsers. Comment handling, number parsing (including scientific notation fix), string variants, accept tables. |
| **`sqli_helpers.go`** | 134 | `flag2Delimiter`, escape detection, whitespace, `strLenSpn`/`strLenCSpn`, `toUpperCmp`, `searchKeyword`. |
| **`sqli_data.go`** | 9,548 | `parseQStringCore`, `byteParsers[256]` builder, entire `sqlKeywords` map. **Generated-equivalent data file - port verbatim.** |
| **`xss.go`** | 100 | `isXSS()` token dispatch, `IsXSS()` multi-context wrapper. |
| **`xss_helpers.go`** | 274 | Normalization, blacklist checks, HTML entity decoding, URL scheme detection. |
| **`xss_decls.go`** | 528 | All XSS blacklist data: events, tags, attributes, hex decode map. |
| **`html5.go`** | 624 | Full HTML5 tokenizer: ~15 state functions, IE extensions, DOCTYPE/CDATA/comment handling. |
| **`html5_decls.go`** | 48 | `h5State` struct, byte constants, token type enum, context flags. |
| **`sqli_test.go`** | 398 | File-based SQLi test driver, benchmarks, edge-case unit tests. |
| **`xss_test.go`** | 266 | XSS unit tests (PortSwigger examples), file-based XSS/HTML5 driver, benchmarks. |
| **`html5_test.go`** | 249 | HTML5 state machine edge-case tests. |
| **`xss_helpers_test.go`** | 190 | Blacklist helper unit tests. |
| **`xss_stack_overflow_test.go`** | 16 | 10MB `/` input stack safety test. |

---

## Test Coverage Approach

### File-Based Test Corpus (C libinjection heritage)

Tests use a **sectioned text format** compatible with the original C testdriver:

```
--TEST--
description
--INPUT--
<input string>
--EXPECTED--
<expected output>
```

**Test drivers:**

| Pattern | Count | Mode | Validates |
|---------|-------|------|-----------|
| `test-sqli-*.txt` | 54 | `IsSQLi()` → fingerprint string | End-to-end SQLi detection |
| `test-folding-*.txt` | 118 | `fold()` → printed tokens | Token folding rules |
| `test-tokens-*.txt` | 249 | `tokenize()` loop | Raw tokenization (ANSI) |
| `test-tokens_mysql-*.txt` | (subset) | `tokenize()` with MySQL flag | MySQL-specific tokenization |
| `test-html5-*.txt` | 68 | HTML5 tokenizer | Token type, length, content |
| `test-xss-*.txt` | 7 | `IsXSS()` → `"1"` or `"0"` | XSS boolean detection |

**Current status:** All **499** tests pass (`go test` on main branch).

### Supplementary Unit Tests

- **PortSwigger XSS cheat sheet** examples (~40 cases) in `TestIsXSS`
- **Scientific notation** bypass tests (`test-sqli-1e-*.txt`)
- **False positive regression** tests (issue #46 URL paths, `#46` `htmlEncodeStartsWith`)
- **Edge-case** tests for `notWhitelist`, Q-string delimiters, B-string early returns
- **Stack overflow** safety: 10MB input for XSS

### Codecov

README badge indicates codecov integration; coverage targets the Go port specifically.

### Recommended Rust Port Test Strategy

1. **Import the entire `tests/` directory** verbatim from libinjection-go.
2. Implement identical test file parsers (section order, right-trim only).
3. Run fingerprint, folding, token, html5, and xss drivers against Rust implementation.
4. Add Rust unit tests mirroring Go's supplementary tests.
5. **Do not skip** MySQL reparse or multi-quote passes - many SQLi tests depend on them.

---

## Performance Characteristics

### Documented Optimizations (v0.3.2, Feb 2026)

CHANGELOG entries:
- **SQLi:** "optimize sqli detection with safe, zero-alloc patterns" ([#97](https://github.com/corazawaf/libinjection-go/issues/97))
- **XSS:** "optimize xss detection with zero-alloc patterns" ([#98](https://github.com/corazawaf/libinjection-go/issues/98))

Techniques observed in code:
- Stack-allocated `[maxTokens]byte` buffers for fingerprint building
- `upperRemoveNulls` writes into fixed `[64]byte` buffer (no heap)
- `asciiEqualFold` for tag comparison without allocation
- `byteParsers[256]` direct indexing vs switch

### Benchmark Results (local, AMD Ryzen 7 PRO 7840HS, `-benchtime=1x` full corpus)

| Benchmark | Time/op | Allocs/op | Bytes/op |
|-----------|---------|-----------|----------|
| `BenchmarkSQLiDriver/sqli` (54 tests) | ~62 µs | 266 | 53 KB |
| `BenchmarkSQLiDriver/folding` (118 tests) | ~299 µs | 1,734 | 71 KB |
| `BenchmarkSQLiDriver/tokens` (249 tests) | ~242 µs | 3,671 | 150 KB |

**Remaining allocation hot spot:** `blacklist()` converts fingerprint lookup key to `string` for map access (`sqlKeywords` is `map[string]byte`). Comment in code notes this is "currently unavoidable" without changing key type.

### Operational Profile for WAF Use

- **Per-request cost:** One `IsSQLi` + one `IsXSS` call per targeted rule variable (typically ARGS, REQUEST_BODY, QUERY_STRING).
- **Input size:** No explicit length limit; XSS stack test validates 10MB input safety.
- **Concurrency:** Embarrassingly parallel - no shared mutable state.

---

## Differences from Original C libinjection

Documented in README, CHANGELOG, and code comments:

| Area | C libinjection | libinjection-go |
|------|----------------|-----------------|
| **Thread safety** | C API uses caller-provided `libinjection_sqli_state` (not inherently thread-safe) | Go API creates fresh state per call; **explicitly thread-safe** |
| **Memory** | Stack/static allocation in C | Go heap (GC); v0.3.2 reduced allocations |
| **String handling** | `char*` + lengths | Go `string` (immutable, UTF-8 bytes treated as raw) |
| **Scientific notation** | Original bypass (`1.e`) | Fixed in v0.2.4 - `haveE && !haveExp` → no token assigned |
| **XSS SVG detection** | (typo in tag check) | Fixed v0.3.1 - prefix matching for SVG/XSL |
| **`htmlEncodeStartsWith`** | C substring semantics | v0.3.1 - `HasPrefix` to fix false positives on URLs containing `data` |
| **XML comment XSS** | Off-by-one | v0.3.1 - requires `tokenLen > 3` for XML detection |
| **Test driver** | C testdriver | v0.3.1 - aligned parser with C (right-trim, section order) |
| **XSS event list** | Smaller set | Expanded ~430 events from WebKit/Chromium/Firefox sources |
| **Performance** | C is faster baseline | v0.3.2 Go-specific zero-alloc optimizations |

**Not documented but observable:** Go uses a `map[string]byte` for keywords vs C's static array/binary search. Behavior must match, implementation may differ.

---

## Dependencies and Coraza Integration

### Go Module Dependency

```go
// coraza/go.mod
github.com/corazawaf/libinjection-go v0.3.2
```

Zero transitive dependencies. Built with Go 1.24.6.

### Coraza Operator Wiring

**`@detectSQLi`** (`coraza/internal/operators/detect_sqli.go`):

```go
res, fingerprint := libinjection.IsSQLi(value)
if res {
    tx.CaptureField(0, fingerprint)  // fingerprint → capture field 0
    return true
}
```

**`@detectXSS`** (`coraza/internal/operators/detect_xss.go`):

```go
return libinjection.IsXSS(value)
```

Both operators:
- Take **no arguments** (operate on rule target variable)
- Can be disabled at compile time via `coraza.disabled_operators.detectSQLi` / `detectXSS` build tags
- Are used heavily by OWASP CRS rules **942xxx** (SQLi) and **941xxx** (XSS)

### coraza-rs Integration (current)

```toml
# coraza-rs/Cargo.toml
libinjectionrs = "0.1.1"
```

```rust
// coraza-rs/src/operators/detection.rs
libinjectionrs::detect_sqli(input.as_bytes())  // → is_injection() + fingerprint
libinjectionrs::detect_xss(input.as_bytes())   // → is_injection() only
```

The Rust crate API mirrors the Go API: SQLi returns a fingerprint for capture field 0; XSS returns boolean only.

### CRS Impact

From coraza-rs `CRS_TEST_COVERAGE.md`:
- **942xxx (SQLi):** ~80% of rules require `@detectSQLi`
- **941xxx (XSS):** ~80% of rules require `@detectXSS`

Behavioral parity with libinjection-go is **required** for CRS compliance, not optional.

---

## Behavioral Parity Requirements for Rust Port

### Must Preserve Exactly

1. **Public API semantics:**
   - `detect_sqli(&[u8]) → { is_injection: bool, fingerprint: Option<String> }`
   - `detect_xss(&[u8]) → { is_injection: bool }`
   - Empty input → not detected
   - SQLi fingerprint is the **lowercase type-byte string** (1–5 chars), empty when not detected

2. **`sqlKeywords` map:** All 9,352 entries with identical keys (uppercase) and values (type bytes). Especially all 8,367 `"0..."` fingerprint entries.

3. **`byteParsers[256]` dispatch table:** Identical parser selection per byte value.

4. **All fold rules** in `fold()`: Order of rule evaluation matters. The 2-token and 3-token switches are security-critical.

5. **Multi-pass `check()` logic:** Exact flag combinations and reparse conditions (ANSI → MySQL fallback, single-quote pass, double-quote pass).

6. **`notWhitelist()` FP reduction:** Every branch - CRS tuning depends on these thresholds.

7. **Token type assignment:** Including edge cases (scientific notation, `\N`, `$tag$`, q-quotes, T-SQL brackets, evil `X` tokens).

8. **HTML5 state machine:** All states in `html5.go`, including IE extensions (`%>` comments, backtick attributes, null in tag names).

9. **XSS blacklists:** All entries in `blackTags`, `blackEvents`, `blacks` with identical attribute type mappings.

10. **XSS multi-context scanning:** All 5 entry contexts must be tried; first match wins.

11. **Normalization functions:** `upperRemoveNulls`, `htmlEncodeStartsWith`, `htmlDecodeByteAt` - byte-level behavior including `cb & 0xFF` truncation.

12. **Test corpus:** 100% pass rate on all `tests/test-*.txt` files.

### Acceptable Implementation Differences

- Internal data structures (map vs perfect hash vs trie)
- Allocation patterns (Rust can do zero-copy with `&str` / `&[u8]`)
- Error handling (Go panics in test driver; production code doesn't panic)
- Parallelism

### Suggested Rust Crate Structure

```
libinjection-rs/
├── src/
│   ├── lib.rs           # pub fn is_sqli, is_xss
│   ├── sqli/
│   │   ├── mod.rs       # check(), fold(), fingerprint
│   │   ├── token.rs
│   │   ├── parse.rs
│   │   ├── fold.rs
│   │   └── data.rs      # include! or build-script generated keywords
│   └── xss/
│       ├── mod.rs
│       ├── html5.rs
│       ├── blacklist.rs
│       └── data.rs
└── tests/
    └── corpus/          # symlink or include libinjection-go/tests/
```

Consider a **build script** to convert `sqli_data.go`'s `sqlKeywords` map into a Rust static map/phf map to avoid manual drift.

---

## Known Limitations and TODOs

### In-Code TODOs

| Location | Issue |
|----------|-------|
| `sqli.go:422` | `select \`\`.id` marked invalid but comment says "todo: this is valid" |
| `sqli.go:433` | MySQL `{ \`\` . \`\`.id }` blacklist "Highly likely this will need revisiting!" |
| `xss.go:33-34` | Attribute value `<` check "probably need adjusting to handle escaped characters" |

### Behavioral Limitations

| Limitation | Impact |
|------------|--------|
| **5-token fingerprint cap** | Attacks requiring 6+ structural tokens may evade detection |
| **`X` (evil) token** | Nested `/* */` comments abort fingerprinting - rare FN |
| **Plain-text `javascript:`** | Not detected outside HTML attribute context (by design) |
| **`style=` always XSS** | `<div style="color:red">` triggers - intentional but FP-prone |
| **`<!DOCTYPE>` always XSS** | Any DOCTYPE declaration detected |
| **`#` comment FP reduction** | `1# foo` intentionally not flagged |
| **Fingerprint lookup allocates in Go** | Performance overhead; Rust can improve |
| **UTF-8** | Bytes processed as raw; no Unicode normalization |
| **No HTML entity decoding in tag names** | Except via `htmlEncodeStartsWith` for URL checks |
| **Truncation at 64 bytes** | XSS normalization silently drops bytes beyond 64 (safe for current blacklists) |

### False Positive Cases (Documented in Tests)

- URLs containing `data` in path: `https://github.com/Simbiat/database` → not XSS (issue #46)
- Base64-like strings ending in `--`: `1234-ABCDEFEhfhihwuefi--`
- Normal text with "union": `1 UNION` (without further SQL structure)
- Comparison expressions: `a < b && c > d` → not XSS

### False Negative Cases (Documented in Tests)

- `<!--xml-->` (tokenLen=3) → not XSS (needs `tokenLen > 3`)
- `<!--?xml -->` → not XSS (xml not at token start)
- `href=&#` incomplete entity → not XSS

---

## Appendix: Quick Reference for Coraza Rule Authors

When `@detectSQLi` fires, audit logs contain:

```
detected SQLi using libinjection with fingerprint 's&1'
```

The fingerprint string is the **folded token type sequence** - useful for tuning CRS exclusions or understanding attack structure.

When `@detectXSS` fires, no fingerprint is captured - only the boolean match.

---

## References

- [libinjection-go repository](https://github.com/corazawaf/libinjection-go)
- [Original C libinjection](https://github.com/client9/libinjection)
- [Coraza detectSQLi operator](https://github.com/corazawaf/coraza/blob/main/internal/operators/detect_sqli.go)
- [Coraza detectXSS operator](https://github.com/corazawaf/coraza/blob/main/internal/operators/detect_xss.go)
- [GoSecure scientific notation bypass analysis](https://gosecure.ai/blog/2021/10/19/a-scientific-notation-bug-in-mysql-left-aws-waf-clients-vulnerable-to-sql-injection/)
- [HTML5 Security Cheat Sheet (html5sec.org)](https://html5sec.org/)
