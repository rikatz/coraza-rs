# SQLi Legacy Port Blueprint

> **Source of truth:** [corazawaf/libinjection-go](https://github.com/corazawaf/libinjection-go) tag **v0.3.2** (cloned to `/tmp/libinjection-go-v0.3.2` for this analysis).
>
> **Target:** `libinjection-rs/src/sqli/legacy/` behind the `legacy` feature, matching Go corpus behavior.
>
> **Corpus (vendored):** `libinjection-rs/tests/corpus/` — 249 tokens + 118 folding + 54 sqli fixtures (421 SQLi-related; HTML5/XSS already pass).

---

## 1. Executive summary

Port the Go SQLi pipeline in **three implementation layers**, tested incrementally:

| Order | Layer | Go entry points | Corpus driver | Pass target |
|-------|-------|-----------------|---------------|-------------|
| **0** | Static data (`sqlKeywords`, `byteParsers`) | `sqli_data.go` | — | compiles |
| **1** | Tokenizer | `tokenize()`, `sqli_parse.go`, `sqli_token.go` | `test-tokens-*.txt` (249) | 249/249 |
| **2** | Folding | `fold()`, `merge()` | `test-folding-*.txt` (118) | 118/118 |
| **3** | Detection | `sqliFingerprint()`, `blacklist()`, `notWhitelist()`, `check()`, `IsSQLi()` | `test-sqli-*.txt` (54) | 54/54 |
| **4** | Integration | `detect_sqli`, `drivers.rs` | all three + `failed == 0` baselines | 421/421 |

**Agent split (recommended):**

- **Agent 1 (tokenizer):** Milestones 0–1 — `data` codegen, `const`, `token`, `parse`, `helpers`, `state::tokenize`, corpus `actual_tokens_output`.
- **Agent 2 (folding + detection):** Milestones 2–4 — `fold`, `merge`, `sqli_fingerprint`, `blacklist`, `not_whitelist`, `check`, `detect`, wire `lib.rs` + baseline asserts.

Follow the **XSS legacy pattern** (`src/xss/legacy/`): `no_std` in library code, heap/`String` only in integration-test drivers. Input is raw bytes (`&[u8]`); UTF-8 is not normalized.

---

## 2. Go file → Rust module map

Proposed layout under `src/sqli/legacy/`:

| Go file | Lines (approx) | Rust module | Responsibility |
|---------|----------------|-------------|----------------|
| `sqli_const.go` | 55 | `const.rs` | Flags, lookup kinds, token type byte constants |
| `sqli_token.go` | 108 | `token.rs` | `SqliToken`, `assign`, `parse_string_core`, `is_unary_op`, `is_arithmetic_op`; `MAX_TOKENS=5`, `TOKEN_SIZE=32` |
| `sqli_helpers.go` | 134 | `helpers.rs` | `flag2_delimiter`, `is_backslash_escaped`, `is_double_delimiter_escaped`, `is_byte_white`, `str_len_spn`, `str_len_cspn`, `to_upper_cmp`, `search_keyword` |
| `sqli_parse.go` | 506 | `parse.rs` | All `parse*` functions, `word_accept_table`, `var_accept_table`, `build_accept_table` |
| `sqli_data.go` | 9,548 | `data.rs` (generated) | `parse_qstring_core`, `byte_parsers[256]`, `sql_keywords` lookup |
| `sqli.go` | 910 | `mod.rs` + `state.rs` + `fold.rs` + `detect.rs` | `SqliState`, `tokenize`, `fold`, `merge`, `sqli_fingerprint`, `blacklist`, `not_whitelist`, `check`, `is_sqli` |

Suggested file split (keeps `mod.rs` thin, mirrors XSS):

```
src/sqli/legacy/
├── mod.rs          # pub(crate) detect(), re-exports for tests if needed
├── const.rs        # from sqli_const.go
├── token.rs        # from sqli_token.go
├── helpers.rs      # from sqli_helpers.go
├── parse.rs        # from sqli_parse.go
├── state.rs        # sqliState struct, sqli_init, reset, tokenize
├── fold.rs         # fold(), merge()
├── detect.rs       # sqli_fingerprint, blacklist, not_whitelist, check, is_sqli
└── data.rs         # include!(OUT_DIR/...) or generated inline
```

`src/sqli/mod.rs` already gates `legacy` behind `#[cfg(feature = "legacy")]`.

---

## 3. Core types

### 3.1 `sqliState` → `SqliState` (`state.rs`)

Go (`sqli.go:7-63`):

```go
type sqliState struct {
    input       string
    length      int
    flags       int
    pos         int
    tokenVec    [8]sqliToken   // 5 folded + lookahead buffer
    current     *sqliToken
    fingerprint string
    statsCommentDDX  int
    statsCommentHash int
    statsFolds       int
    statsTokens      int
}
```

Rust (`no_std`):

```rust
pub(crate) struct SqliState<'a> {
    input: &'a [u8],
    flags: SqliFlags,           // bitflags, see below
    pos: usize,
    token_vec: [SqliToken<'a>; 8],
    current: usize,             // index into token_vec (avoid raw pointers)
    fingerprint: [u8; 5],
    fingerprint_len: u8,
    stats_comment_ddx: u16,
    stats_comment_hash: u16,
    stats_folds: u16,
    stats_tokens: u16,
}
```

- `sqliInit` / `reset` (`sqli.go:65-75`, `841-846`): zero state; default flags `QuoteNone | SQLAnsi` when `flags == 0`.
- `input` is **never mutated**; all token values are subslices of `input` (max `TOKEN_SIZE - 1` = 31 bytes copied or referenced).

### 3.2 `sqliToken` → `SqliToken` (`token.rs`)

Go (`sqli_token.go:5-17`):

```go
type sqliToken struct {
    pos, len, count int
    category        byte
    strOpen, strClose byte
    val             string
}
```

Rust:

```rust
pub(crate) struct SqliToken<'a> {
    pub pos: usize,
    pub len: usize,          // significant val length (≤ 31)
    pub count: u8,           // '@' count for type 'v'
    pub category: u8,
    pub str_open: u8,        // 0 = byteNull
    pub str_close: u8,
    pub val: &'a [u8],       // slice into input, len ≤ token_size-1
}
```

`assign` (`sqli_token.go:74-86`): sets category, pos, truncates value to `token_size - 1`.

### 3.3 Flags (`const.rs` / reuse `crate::flags::SqliFlags`)

Go (`sqli_const.go:3-10`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `sqliFlagQuoteNone` | 1 | Parse input as-is |
| `sqliFlagQuoteSingle` | 2 | At pos 0, pretend inside `'...'` |
| `sqliFlagQuoteDouble` | 4 | At pos 0, pretend inside `"..."` |
| `sqliFlagSQLAnsi` | 8 | ANSI `--[not-white]` is comment; `#` is operator |
| `sqliFlagSQLMysql` | 16 | MySQL `#` EOL comment; `--foo` is two unary `-` |

Default: `QuoteNone | SQLAnsi` (`sqli.go:66-68`).

Lookup kinds (`sqli_const.go:12-17`): `sqliLookupWord=1`, `sqliLookupOperator=3`, `sqliLookupFingerprint=4`.

### 3.4 Token type bytes (`sqli_const.go:26-55`)

| Byte | Go constant | Role in fingerprint |
|------|-------------|---------------------|
| `k` | `sqliTokenTypeKeyword` | Generic keyword |
| `U` | `sqliTokenTypeUnion` | UNION / UNION ALL |
| `B` | `sqliTokenTypeGroup` | GROUP BY |
| `E` | `sqliTokenTypeExpression` | SELECT, CASE, … |
| `t` | `sqliTokenTypeSQLType` | CAST, CHAR, collation types |
| `f` | `sqliTokenTypeFunction` | Function call |
| `n` | `sqliTokenTypeBareWord` | Unrecognized identifier |
| `1` | `sqliTokenTypeNumber` | Numeric literal |
| `v` | `sqliTokenTypeVariable` | `@var`, `@@var` |
| `s` | `sqliTokenTypeString` | Quoted string |
| `o` | `sqliTokenTypeOperator` | `=`, `||`, … |
| `&` | `sqliTokenTypeLogicOperator` | AND, OR, XOR |
| `c` | `sqliTokenTypeComment` | `--`, `#`, `/* */` |
| `A` | `sqliTokenTypeCollate` | COLLATE |
| `(`, `)`, `{`, `}`, `.`, `,`, `:`, `;` | punctuation | literal in fingerprint |
| `T` | `sqliTokenTypeTSQL` | T-SQL IF after `;` |
| `?` | `sqliTokenTypeUnknown` | Unrecognized byte |
| `X` | `sqliTokenTypeEvil` | Unparseable (nested `/*`, `{ ``) |
| `F` | `sqliTokenTypeFingerprint` | Map value only (blacklist hit marker) |
| `\` | `sqliTokenTypeBackslash` | T-SQL backslash (transient, folded away) |

Delimiter bytes (`sqli_const.go:19-24`): `byteNull=0`, `byteSingle='\'`, `byteDouble='"'`, `byteTick='`'`.

---

## 4. Tokenizer

### 4.1 `byteParsers[256]` (`sqli_data.go:58-195`)

Built by `buildByteParsers()`: each byte 0–255 maps to exactly one parser function.

| Byte range / chars | Parser |
|--------------------|--------|
| 0–32, 127 | `parseWhite` |
| 33, 38, 42, 58, 60–62, 124 | `parseOperator2` |
| 34, 39 | `parseString` |
| 35 | `parseHash` |
| 36 | `parseMoney` |
| 37, 43, 94, 126 | `parseOperator1` |
| 40–41, 44, 59, 123, 125 | `parseByte` (category = byte itself) |
| 45 | `parseDash` |
| 46, 48–57 | `parseNumber` |
| 47 | `parseSlash` |
| 63, 93 | `parseOther` |
| 64 | `parseVar` |
| 65, 67–68, 70–77, 79–80, 82–84, 86–87, 89–90, 95, 97, 99–100, 102–109, 111–112, 114–116, 118–119, 121–122 | `parseWord` |
| 66, 98 | `parseBString` |
| 69, 101 | `parseEString` |
| 78, 110 | `parseNqString` |
| 81, 113 | `parseQString` |
| 85, 117 | `parseUString` |
| 88, 120 | `parseXString` |
| 91 | `parseBWord` |
| 92 | `parseBackSlash` |
| 96 | `parseTick` |
| 128–159 (except 160) | `parseWord` |
| 160 | `parseWhite` |
| 161–255 | `parseWord` |

**Rust:** encode as `const BYTE_PARSERS: [ParserFn; 256]` or a `match` on `u8` generated from the same table. Must be **bit-identical** to Go.

Dispatch (`sqli_data.go:54-56`, `sqli.go:647-657`):

```go
s.pos = parseByteFunctions(s, ch)  // parser returns new pos
if s.current.category != byteNull { return true }  // token emitted
// else continue loop (whitespace)
```

### 4.2 Parse functions (`sqli_parse.go`, `sqli_data.go`)

| Function | File | Trigger / notes |
|----------|------|-----------------|
| `parseWhite` | `sqli_parse.go:88-90` | Advance pos; no token (`category` stays 0) |
| `parseOperator1` | `sqli_parse.go:92-95` | Single-char operator |
| `parseOperator2` | `sqli_parse.go:181-206` | 2-char ops via `lookupWord(Operator)`; `<=>` 3-char; lone `:` → type `:` not operator |
| `parseByte` | `sqli_parse.go:97-100` | Punctuation: category = byte value |
| `parseHash` | `sqli_parse.go:104-112` | MySQL: EOL comment + `statsCommentHash++`; ANSI: operator `#` |
| `parseDash` | `sqli_parse.go:114-134` | See §10 gotchas; increments `statsCommentDDX` on ANSI `--[not-white]` |
| `parseSlash` | `sqli_parse.go:136-169` | `/* */`; nested `/*` or `/*!` → evil `X` |
| `parseBackSlash` | `sqli_parse.go:172-179` | `\N` → number; else backslash token |
| `parseString` | `sqli_parse.go:208-211` | `'` / `"` via `parseStringCore` |
| `parseWord` | `sqli_parse.go:213-242` | Alpha/unicode; split on embedded `.` or `` ` ``; keyword lookup |
| `parseVar` | `sqli_parse.go:244-281` | `@`, `@@`, backtick/quoted vars |
| `parseNumber` | `sqli_parse.go:283-380` | Hex/binary/float/scientific; **`haveE && !haveExp` → no token** (WAF bypass fix) |
| `parseTick` | `sqli_parse.go:383-403` | MySQL backtick identifier |
| `parseMoney` | `sqli_parse.go:22-81` | `$`, `$$`, `$tag$` strings |
| `parseQString` / `parseNqString` | `sqli_parse.go:420-431` | Oracle q-quote / `n'...'` |
| `parseQStringCore` | `sqli_data.go:7-48` | Delimiter pairing for q-quotes |
| `parseXString` / `parseBString` | `sqli_parse.go:437-470` | `X'hex'`, `B'01'` |
| `parseEString` | `sqli_parse.go:476-482` | `E'...'` / `e'...'` escaped strings |
| `parseUString` | `sqli_parse.go:405-418` | `u&'...'` |
| `parseBWord` | `sqli_parse.go:486-494` | T-SQL `[identifier]` |
| `parseEolComment` | `sqli_parse.go:11-20` | To newline or EOF |
| `parseOther` | `sqli_parse.go:83-86` | Unknown `?` |

Accept tables (`sqli_parse.go:8-9`, `496-506`):

- `wordAcceptTable`: `" []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r\"\240\000"`
- `varAcceptTable`: same but includes `` ` `` and excludes `[` `]`

### 4.3 `tokenize()` loop (`sqli.go:633-661`)

1. Empty input → `false`.
2. Clear `*current` token.
3. **Simulated quote** at `pos == 0` if `QuoteSingle` or `QuoteDouble` flag: call `parseStringCore` with `offset=0`, `delimiter=flag2Delimiter(flags)`; return `true`.
4. While `pos < length`:
   - `ch = input[pos]`
   - `pos = byteParsers[ch](state)` — parser mutates `current` and returns new pos
   - If `current.category != 0`: `statsTokens++`, return `true`
5. End → `false`.

### 4.4 Corpus output format — tokens driver

**Go driver:** `sqli_test.go` — `runSQLiTest(..., flag="tokens", sqliFlag)`.

**Flags for vendored corpus:** All `test-tokens-*.txt` files match `-tokens-` and run with **`sqliFlagQuoteNone | sqliFlagSQLAnsi`** (`sqli_test.go:175-178`).

> **Note:** Go also has a branch for `-tokens_mysql-` (`sqli_test.go:171-174`), but **no fixture in v0.3.2 uses that substring**. Files named `test-tokens-comments-mysql-*.txt` still run under **ANSI** flags. MySQL-specific tokenizer behavior is exercised indirectly via `IsSQLi` reparse passes, not the tokens driver.

**Algorithm:**

```go
for state.tokenize() {
    actual += printToken(state.current) + "\n"
}
actual = strings.TrimSpace(actual)
```

**`printToken` / `printTokenString`** (`sqli_test.go:31-62`):

| Token category | Line format |
|----------------|-------------|
| Default (`E`, `n`, `1`, `o`, `c`, `X`, punctuation, …) | `{category} {val}` — e.g. `E SELECT`, `1 1`, `c --` |
| `s` (string) | `{category} {strOpen}{val}{strClose}` — e.g. `s 'FOO'`, `s q{content}q` |
| `v` (variable) | `{category} {@ or @@}{strOpen?}{val}{strClose?}` — e.g. `v @`, `v @@version` |

- `val` is at most 31 bytes (`token_size - 1`).
- Each line: `strings.TrimRight(line, "\n\r")` only (no left-trim).
- Join lines with `\n`; final `strings.TrimSpace` on whole output (strips leading/trailing whitespace including newlines).

**Examples from corpus:**

```
--INPUT--
SELECT 'FOO';
--EXPECTED--
E SELECT
s 'FOO'
; ;
```

```
--INPUT--
SELECT @;
--EXPECTED--
E SELECT
v @
; ;
```

```
--INPUT--
SELECT 1 /*!
--EXPECTED--
E SELECT
1 1
X /*!
```

**Rust driver:** implement `format_token_line(&SqliToken) -> String` mirroring `printToken`, then `format_tokens_expected` (already in `tests/common/drivers.rs:59-62`).

**Test command (M1 gate):**

```bash
cd libinjection-rs
cargo test -p libinjection --features legacy tokens_corpus_baseline -- --nocapture
# Expect: failed == 0, passed == 249
```

---

## 5. Folding

### 5.1 `fold()` algorithm (`sqli.go:177-631`)

**Purpose:** Reduce token stream to **≤ 5** tokens for fingerprinting.

**State variables:**

- `pos` — next write index in `tokenVec`
- `left` — fold frontier (committed tokens)
- `more` — more input to tokenize
- `lastComment` — dangling comment for reattachment

**Phases:**

1. **Skip leading noise** (`sqli.go:186-201`): Tokenize until first token that is NOT `comment`, `(`, SQL type (`t`), or unary op. If only noise → return `0`. Else `pos = 1`.

2. **Main loop** while `more && left < maxTokens`:
   - **5-token overflow** special cases (`sqli.go:207-237`): patterns like `1,(1)`, `n,(n)`, `1),(1`, `n),(n` — collapse buffer.
   - **Read 2 tokens** (`sqli.go:244-256`): comments update `lastComment` but don't increment `pos`.
   - **2-token rules** (`sqli.go:267-449`): see §5.2.
   - If no match, **read 3rd token** (`sqli.go:453-464`).
   - **3-token rules** (`sqli.go:473-609`): see §5.3.
   - If still no match: `left++` (commit leftmost token).

3. **Trailing comment reattach** (`sqli.go:617-622`): If `left < 5` and `lastComment` is set, append it.

4. **Cap** (`sqli.go:624-628`): `if left > maxTokens { left = maxTokens }`.

Returns `left` (token count).

### 5.2 Two-token fold rules (`sqli.go:267-449`)

| Rule | Pattern | Action |
|------|---------|--------|
| String merge | `ss` | Drop second string (`pos--`) |
| Semicolon collapse | `;;` | Drop second `;` |
| Unary removal | `(operator\|&)(unary\|t)` | Drop second; `left=0` |
| Paren + unary | `( + unary` | Drop unary; maybe `left--` |
| Keyword merge | `merge(a,b)` | Concat with space, `lookupWord`; reassign type |
| T-SQL IF | `;` + `IF` function | Reclassify IF as `T` (TSQL) |
| Function disambiguation | `(n\|v)(` + known names | USER_ID, DATABASE, CURRENT_USER, … → `f` |
| IN / NOT IN | `k` + `(` | `IN`/`NOT IN` + `(` → operator `o`; else bareword `n` |
| LIKE / NOT LIKE | `o` + `(` | `LIKE`/`NOT LIKE` + `(` → function `f` |
| SQL type swallow | `t` + (n\|1\|t\|(\|f\|v\|s) | Replace `t` with second token |
| COLLATE | `A` + `n` with `_` in name | Second → `t` |
| Backslash | `\` + arith | `\` → `1` or absorb second |
| Paren/brace collapse | `((`, `))` | Drop duplicate |
| MySQL brace evil | `{` + empty bareword | Second → `X`; early return |
| ODBC brace strip | `{` + bareword | `pos -= 2`, `left = 0` |
| Right brace | `?}` | Drop `}` token |

### 5.3 Three-token fold rules (`sqli.go:473-609`)

| Rule | Pattern | Action |
|------|---------|--------|
| Arithmetic fold | `1 o 1`, `o ? o`, `& ? &` | Collapse three → zero (`pos -= 2`, `left = 0`) |
| Variable expr | `v o (v\|1\|n)` | Collapse |
| Bareword/number expr | `(n\|1) o (1\|n)` | Collapse |
| PG cast | `? :: t` | Collapse |
| Comma lists | `? , ?` (same type family) | Collapse |
| Unary before paren | `(E\|B\|,) + unary + (` | Drop unary |
| Unary before value | `(k\|E\|B) + unary + value` | Drop unary |
| Comma unary | `, unary value` | Special: `pos -= 3` or drop unary before function |
| Qualified name | `n . n` | Drop `.n` |
| SELECT `.foo` | `E . n` | Replace `.n` with `n` |
| USER() disambiguation | `f ( ?` not `)` | USER → bareword |

### 5.4 `merge()` (`sqli.go:137-175`)

Concatenate `tokenA.val + " " + tokenB.val` (max `token_size`); `lookupWord(sqliLookupWord, tmp)`; on hit, reassign `tokenA` with merged type/value.

### 5.5 Corpus output format — folding driver

**Go driver:** `runSQLiTest(..., flag="folding", sqliFlagQuoteNone|sqliFlagSQLAnsi)` (`sqli_test.go:167-170`).

```go
numTokens := state.fold()
for i := 0; i < numTokens; i++ {
    actual += printToken(getToken(state, i)) + "\n"
}
actual = strings.TrimSpace(actual)
```

Same per-line encoding as tokens driver (§4.4). Only **first `numTokens` entries** of `tokenVec` are printed (after fold).

**Example** (`test-folding-001.txt`):

```
--INPUT--
SELECT "first" "second";
--EXPECTED--
E SELECT
s "first"
; ;
```

(String folding merges `"first" "second"` → keep first string only.)

**Test command (M2 gate):**

```bash
cargo test -p libinjection --features legacy folding_corpus_baseline -- --nocapture
# Expect: failed == 0, passed == 118
```

---

## 6. SQLi detection

### 6.1 `sqliFingerprint(flags)` (`sqli.go:86-128`)

1. `reset(flags)` — re-init with same input, new flags.
2. `length = fold()`.
3. **PHP backtick edge case** (`sqli.go:97-103`): last token bareword, backtick-open, empty, unclosed → reclassify as comment `c`.
4. Build fingerprint: concatenate each token's `category` byte.
5. If any token is `X` → fingerprint = `"X"`, early return.

Fingerprint is **1–5 type bytes** (lowercase in output; uppercase only for blacklist key).

### 6.2 `blacklist()` (`sqli.go:666-692`)

1. `length = len(fingerprint)`; if 0 → false.
2. Build key: `'0'` + uppercase fingerprint bytes → e.g. `"01&1"`.
3. Lookup in `sqlKeywords`; hit iff value == `'F'` (`sqliTokenTypeFingerprint`).

### 6.3 `notWhitelist()` (`sqli.go:698-825`)

Runs **after** blacklist match; returns `true` to **confirm** SQLi (i.e. not a false positive).

| Condition | Returns |
|-----------|---------|
| Fingerprint ends in `c` + input contains `sp_password` | `true` (force SQLi) |
| **2-token** `?U` (ends in UNION) + `statsTokens == 2` | `false` ("1 union" FP) |
| **2-token** + token[1] starts with `#` | `false` |
| **2-token** `nc` + comment not starting with `/` | `false` |
| **2-token** `1c` + comment not starting with `/` | `true` |
| **2-token** `1c` + base64-like (see below) | nuanced |
| **2-token** `--` comment with content after `--` (len > 2) | `false` |
| **3-token** `sos` / `s&s` string concat without open/close quotes | `true` |
| **3-token** `s&n`, `n&1`, `1&1`, `1&v`, `1&s` + `statsTokens == 3` | `false` |
| **3-token** keyword not `INTO` (len < 5 or not INTO) | `false` |
| Default | `true` |

**`1c` base64 check** (`sqli.go:759-782`): uses **original input** at `input[tokenVec[0].len]` — must be whitespace, `/*`, or `--` to confirm SQLi; else false if only 2 stats tokens.

### 6.4 `check()` multi-pass (`sqli.go:853-895`)

```
Pass 1: fingerprint(QuoteNone | SQLAnsi)     → lookup
Pass 2: if reparseAsMySQL() → fingerprint(QuoteNone | SQLMysql) → lookup
Pass 3: if input contains ' → fingerprint(QuoteSingle | SQLAnsi) → lookup
Pass 4: if reparseAsMySQL() → fingerprint(QuoteSingle | SQLMysql) → lookup
Pass 5: if input contains " → fingerprint(QuoteDouble | SQLMysql) → lookup
```

`reparseAsMySQL()` (`sqli.go:849-851`): `statsCommentDDX > 0 || statsCommentHash > 0` from **first pass** (preserved across `reset`? **No** — `reset` calls `sqliInit` which zeros stats. **Gotcha:** `reparseAsMySQL` is evaluated on state **after** first `sqliFingerprint` call; `sqliFingerprint` → `reset` → zeros stats. 

**Critical:** Read `check()` flow again:

```go
s.sqliFingerprint(sqliFlagQuoteNone | sqliFlagSQLAnsi)  // this resets and folds
if s.lookupWord(...) { return true }
else if s.reparseAsMySQL() {  // uses stats from INSIDE sqliFingerprint's fold/tokenize
```

Wait - `sqliFingerprint` calls `reset` first which zeros everything, then `fold` which repopulates `statsCommentDDX` and `statsCommentHash`. So after `sqliFingerprint` returns, stats reflect that pass. Good.

`lookupWord(sqliLookupFingerprint, ...)` (`sqli.go:831-839`) calls `checkFingerprint()` = `blacklist() && notWhitelist()`.

### 6.5 `IsSQLi()` (`sqli.go:897-907`)

```go
sqliInit(state, input, 0)
result := state.check()
if result { return true, state.fingerprint }
return false, ""
```

Empty input → `(false, "")`.

### 6.6 `sqlKeywords` map (`sqli_data.go:197-9548`)

**Total entries:** 9,352 (`grep -c '":' sqli_data.go`)

| Category | Count | Key pattern | Value |
|----------|-------|-------------|-------|
| Fingerprints | 8,367 | `"0" + FINGERPRINT` e.g. `"0s&1"`, `"01UEk"` | `'F'` |
| Operators | ~30 | `"="`, `"<>"`, `"::"`, … | `'o'` or specific |
| Keywords | ~200+ | `"SELECT"`, `"UNION"`, … | `'E'`, `'U'`, `'k'`, … |
| Functions | ~100+ | `"SLEEP"`, `"LOAD_FILE"`, … | `'f'` |
| Phrases | ~50+ | `"UNION ALL"`, `"NOT IN"`, … | various |

Keys are **uppercase** for word lookups (`searchKeyword` uppercases). Fingerprint keys are already uppercase type bytes with `0` prefix.

`searchKeyword` (`sqli_helpers.go:126-134`): uppercase key, map lookup, else `byteNull`.

### 6.7 Corpus output format — sqli driver

**Go driver:** `runSQLiTest(..., flag="fingerprints", sqliFlag=0)` → calls `IsSQLi(input)` (`sqli_test.go:127-131`).

| Result | Expected string |
|--------|-----------------|
| SQLi detected | Fingerprint (1–5 chars, e.g. `s&1`, `1U`, `X`) |
| Not detected | Empty string |

**Examples:**

| Fixture | Input (abridged) | Expected |
|---------|------------------|----------|
| `test-sqli-001` | `foo 'bar' "zap"` | `` (empty) |
| `test-sqli-1e-001` | `1' or 1.e(1)` | `s&(1)` |
| `test-sqli-007` | `1 /* /* */ */ 2` | `X` |
| `test-sqli-012` | `foo/* yes this is sqli */` | `nc` |
| `test-sqli-045` | `1 /* junk */ UNION` | `1U` |

**Rust:** `format_sqli_expected(Option<&str>)` already in `drivers.rs:46-48`. `actual_sqli_output` should call `legacy::detect` and return fingerprint or `""`.

**Test command (M3 gate):**

```bash
cargo test -p libinjection --features legacy sqli_corpus_baseline -- --nocapture
# Expect: failed == 0, passed == 54
```

---

## 7. `build.rs` strategy

### 7.1 What to generate

From `/tmp/libinjection-go-v0.3.2/sqli_data.go`:

1. **`SQL_KEYWORDS`** — all 9,352 `(key, type_byte)` pairs.
2. Optionally **`BYTE_PARSER_TABLE`** — 256-entry dispatch (can remain `match` in Rust source).

### 7.2 Recommendation: **PHF for fingerprints + static tables for words**

| Approach | Pros | Cons |
|----------|------|------|
| **`phf` / `phf_codegen`** (recommended) | O(1) lookup, no runtime alloc, ~200KB `.rodata`, matches `WASM_PORTABILITY.md` | Build-time dep; regenerate on Go data changes |
| **Single giant `match` / static array** | No deps | 9K+ arms → slow compile, huge binary |
| **Sorted static array + binary search** | Simple, no phf dep | O(log n); still need alloc or stack buffer for uppercase fingerprint key unless compare in-place |
| **Two-tier: PHF for `0*` keys (8367) + small static for words (~985)** | Optimal hot path for `blacklist()` | Slightly more build complexity |

**Rationale:** `blacklist()` runs on every `check()` pass (up to 5× per input). Go allocates a `string` per lookup (`sqli.go:683-688`). Rust PHF on `&[u8; N]` keys eliminates that allocation and fits the `no_std` hot path.

**Build script sketch:**

```rust
// build.rs (feature = legacy)
// 1. Parse sqli_data.go map entries (regex or line parser)
// 2. Emit OUT_DIR/sqli_keywords.rs via phf_codegen::Map::new()
// 3. Split fingerprint keys (starts with b"0") into PHF_BLACKLIST
// 4. Word/operator keys into PHF_WORDS or const sorted table
```

Gate codegen on `feature = "legacy"` (see `Cargo.toml` `[build-dependencies]` comment).

**Validation:** Assert generated entry count == 9352; fingerprint count == 8367; spot-check `"0s&(1)" => 'F'`, `"SELECT" => 'E'`, `"UNION ALL" => 'U'`.

### 7.3 Alternative acceptable for Agent 2

A single PHF map for all 9,352 entries is simpler to implement first; optimize split later if compile time matters.

---

## 8. Integration

### 8.1 Wire `detect_sqli` (`src/lib.rs`)

Mirror `detect_xss` pattern (`lib.rs:99-110`):

```rust
#[cfg(feature = "legacy")]
let (detected, fp) = sqli::legacy::detect(input);
#[cfg(not(feature = "legacy"))]
let (detected, fp) = (false, None);

DetectionVerdict {
    detected,
    snapshot: {
        let mut snap = analyze_sqli_with(input, opts);
        if let Some(f) = fp {
            snap.legacy_fingerprint = f; // LegacyFingerprint from bytes
        }
        snap
    },
}
```

`legacy::detect(&[u8]) -> (bool, Option<LegacyFingerprint>)` wraps `is_sqli` logic.

### 8.2 `drivers.rs` functions

| Function | Current | Target |
|----------|---------|--------|
| `actual_tokens_output` | stub `""` | `SqliState::new(input, ANSI).tokenize loop` + `format_token_line` |
| `actual_folding_output` | stub `""` | `state.fold()` + print `token_vec[0..n]` |
| `actual_sqli_output` | stub `""` | `legacy::detect` → `format_sqli_expected` |

**Flags for drivers** (match Go `sqli_test.go`):

| Driver | Flags |
|--------|-------|
| Tokens | `SqliFlags::QUOTE_NONE \| SqliFlags::SQL_ANSI` |
| Folding | same |
| SQLi | full `IsSQLi` (all passes internal) |

### 8.3 Baseline tests (`tests/corpus_parse.rs`)

Update stubs to assert **`failed == 0`** (like `html5_corpus_baseline` / `xss_corpus_baseline`):

```rust
#[test]
fn tokens_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Tokens, actual_tokens_output);
    assert_eq!(failed, 0);
}

#[test]
fn folding_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Folding, actual_folding_output);
    assert_eq!(failed, 0);
}

#[test]
fn sqli_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Sqli, actual_sqli_output);
    assert_eq!(failed, 0);
}
```

### 8.4 `LegacyFingerprint` (`src/snapshot.rs:276-294`)

Populate `bytes[0..len]` with fingerprint type bytes; `len` = 1–5 (or 1 for `"X"`). `as_str()` returns `None` when `len == 0`.

### 8.5 Optional test-only API

For drivers (integration tests only), expose behind `#[cfg(test)]` or `feature = "legacy"`:

```rust
pub(crate) fn tokenize_all(input: &[u8], flags: SqliFlags) -> Vec<...>  // tests only
pub(crate) fn fold_tokens(input: &[u8], flags: SqliFlags) -> ...
```

Keep these in `legacy/mod.rs` to avoid public API surface creep.

---

## 9. Milestones & test commands

| Milestone | Deliverable | Corpus pass | Command |
|-----------|-------------|-------------|---------|
| **M0** | `build.rs` generates `sql_keywords`; `byte_parsers` dispatch; compiles | — | `cargo build -p libinjection --features legacy` |
| **M1** | Tokenizer complete | **249/249** tokens | `cargo test -p libinjection --features legacy tokens_driver_stub_on_words_002 tokens_corpus_baseline` |
| **M2** | `fold()` + `merge()` | **118/118** folding | `cargo test -p libinjection --features legacy folding_corpus_baseline` |
| **M3** | `check()` / `IsSQLi` | **54/54** sqli | `cargo test -p libinjection --features legacy sqli_corpus_baseline` |
| **M4** | `detect_sqli` wired; all baselines `failed == 0` | **421/421** | `cargo test -p libinjection --features legacy --test corpus_parse` |

**Full regression (SQLi + existing HTML5/XSS):**

```bash
cd libinjection-rs
cargo test -p libinjection --features legacy --test corpus_parse -- --nocapture
# HTML5: 68/68, XSS: 7/7, Tokens: 249/249, Folding: 118/118, SQLi: 54/54
```

**Incremental dev loop:**

```bash
# Single fixture
cargo test -p libinjection --features legacy parse_real_folding_001 -- --nocapture

# Go parity spot-check (optional, requires Go)
cd /tmp/libinjection-go-v0.3.2 && go test -run TestSQLiDriver/test-tokens-words-002 -v
```

---

## 10. Top parity gotchas

| # | Issue | Go reference | Impact |
|---|-------|--------------|--------|
| 1 | **Scientific notation `1.e`** — `haveE && !haveExp` assigns **no token**; input advances but `category` stays 0 | `parseNumber` `sqli_parse.go:364-377` | `test-sqli-1e-*`, `test-folding-100` |
| 2 | **ANSI vs MySQL `--`** — `--foo` is comment (ANSI) vs two unary `-` (MySQL); sets `statsCommentDDX` | `parseDash` `sqli_parse.go:114-134` | `IsSQLi` reparse pass 2/4 |
| 3 | **`#` comment** — MySQL EOL comment vs ANSI operator | `parseHash` `sqli_parse.go:104-112` | `statsCommentHash` triggers MySQL reparse; tokens corpus uses ANSI (`o #`) |
| 4 | **Nested `/*` or `/*!` in block comment** → evil `X` | `parseSlash` `sqli_parse.go:160-165`, `isMysqlComment` `sqli_helpers.go:96-108` | `test-sqli-007`, `test-tokens-comments-mysql-*` |
| 5 | **Fingerprint `X` short-circuits** — any evil token → entire fingerprint `"X"` | `sqliFingerprint` `sqli.go:116-121` | Nested comment SQLi |
| 6 | **`notWhitelist` uses original input offsets** for `1c` check, not folded tokens | `notWhitelist` `sqli.go:755-782` | Base64-like `1234-ABCD--` FP reduction |
| 7 | **`statsTokens` for FP rules** — e.g. `1U` only SQLi if `statsTokens != 2` | `notWhitelist` `sqli.go:718-726` | "1 union" not flagged |
| 8 | **Simulated quote at pos 0** for `'` / `"` reparses | `tokenize` `sqli.go:639-645` | `test-sqli-017` (double-quote unclosed → not detected) |
| 9 | **Double-quote pass uses MySQL only** (no ANSI double-quote pass) | `check` `sqli.go:886-891` | Inputs with `"` only |
| 10 | **Token value truncation** at 31 bytes | `assign` `sqli_token.go:74-86` | Long identifiers |
| 11 | **String escaping** — odd backslashes escape; doubled delimiter escapes | `parseStringCore` `sqli_token.go:30-72` | `test-tokens-string-*` |
| 12 | **Variable `@` rendering** — `count` 1 → `@`, 2 → `@@` in corpus output | `printToken` `sqli_test.go:50-57` | `test-tokens-variables-*` |
| 13 | **Fold `{ `` empty`** → evil `X`, early return from `fold` | `fold` `sqli.go:413-436` | MySQL ODBC brace edge case |
| 14 | **PHP backtick empty unclosed** → comment after fold | `sqliFingerprint` `sqli.go:97-103` | Rare hosting payloads |
| 15 | **Go `-tokens_mysql-` driver branch is dead** — no fixtures; all `test-tokens-*` use ANSI | `sqli_test.go:171-178` | Rust tokens driver: use ANSI only |
| 16 | **Corpus trim** — right-trim sections only; `TrimSpace` on driver output | `readTestData` `sqli_test.go:109-112`, `runSQLiTest` `sqli_test.go:145` | Parser already matches in `corpus.rs` |
| 17 | **`lookupWord` for fingerprint** runs full `blacklist && notWhitelist`, returns `'X'` on hit | `lookupWord` `sqli.go:831-839` | Internal only; `IsSQLi` uses returned `state.fingerprint` string |
| 18 | **Keyword split on `.` and `` ` ``** inside `parseWord` | `parseWord` `sqli_parse.go:219-231` | `SELECT.1`, `` SELECT `col` `` |
| 19 | **Merge requires space** between tokens for phrase lookup | `merge` `sqli.go:168` | `UNION` + `ALL` → `UNION ALL` |
| 20 | **5-token buffer uses 8 slots** — fold may read 6th token for disambiguation | `tokenVec [8]` `sqli.go:20`, `fold` `sqli.go:228-229` | Overflow patterns |

---

## Appendix A: Function index (Go → Rust)

| Go | File | Rust target |
|----|------|-------------|
| `sqliInit` | `sqli.go:65` | `SqliState::init` |
| `tokenize` | `sqli.go:633` | `SqliState::tokenize` |
| `fold` | `sqli.go:177` | `fold::fold` |
| `merge` | `sqli.go:137` | `fold::merge` |
| `sqliFingerprint` | `sqli.go:86` | `detect::fingerprint` |
| `blacklist` | `sqli.go:666` | `detect::blacklist` |
| `notWhitelist` | `sqli.go:698` | `detect::not_whitelist` |
| `checkFingerprint` | `sqli.go:827` | `detect::check_fingerprint` |
| `check` | `sqli.go:853` | `detect::check` |
| `IsSQLi` | `sqli.go:897` | `detect::is_sqli` / `legacy::detect` |
| `reparseAsMySQL` | `sqli.go:849` | `detect::reparse_as_mysql` |
| `lookupWord` | `sqli.go:831` | `data::lookup_word` |
| `searchKeyword` | `sqli_helpers.go:126` | `data::search_keyword` |
| `parseByteFunctions` | `sqli_data.go:54` | `parse::dispatch` |
| `buildByteParsers` | `sqli_data.go:58` | `parse::build_byte_parsers` or `const BYTE_PARSERS` |
| `printToken` | `sqli_test.go:43` | `tests/common/drivers.rs::format_token_line` (test only) |

---

## Appendix B: Corpus inventory

| Pattern | Count | Driver | Go flags |
|---------|-------|--------|----------|
| `test-tokens-*.txt` | 249 | `tokenize()` loop | `QuoteNone \| SQLAnsi` |
| `test-folding-*.txt` | 118 | `fold()` | `QuoteNone \| SQLAnsi` |
| `test-sqli-*.txt` | 54 | `IsSQLi()` | (internal multi-pass) |
| `test-html5-*.txt` | 68 | (done) | — |
| `test-xss-*.txt` | 7 | (done) | — |

**SQLi detection split:** 33 fixtures expect fingerprint (detected), 21 expect empty (benign / FP-reduced).

---

## References

- Go source: `/tmp/libinjection-go-v0.3.2/sqli*.go`
- Existing analysis: `libinjection-rs/docs/LIBINJECTION_GO_ANALYSIS.md`
- XSS port pattern: `libinjection-rs/src/xss/legacy/`
- Test drivers: `libinjection-rs/tests/common/drivers.rs`, `corpus_parse.rs`
- Go test driver: `/tmp/libinjection-go-v0.3.2/sqli_test.go`
