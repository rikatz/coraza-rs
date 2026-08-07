# libinjection C Library - Technical Analysis

**Source:** [client9/libinjection](https://github.com/client9/libinjection) (version **3.9.2** in `libinjection_sqli.c`)  
**Purpose:** Authoritative behavioral reference for Rust (`libinjection-rs`) and Go ports used by OWASP Coraza WAF.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Repository Structure](#2-repository-structure)
3. [Public C API](#3-public-c-api)
4. [SQL Injection Detection](#4-sql-injection-detection)
5. [XSS Detection](#5-xss-detection)
6. [Key Data Structures](#6-key-data-structures)
7. [Lookup Tables and Generated Data](#7-lookup-tables-and-generated-data)
8. [Memory Model](#8-memory-model)
9. [Performance Design Choices](#9-performance-design-choices)
10. [Test Suite Structure](#10-test-suite-structure)
11. [Go Port and Ecosystem Relationship](#11-go-port-and-ecosystem-relationship)
12. [File-by-File Breakdown](#12-file-by-file-breakdown)
13. [Critical Invariants for a Rust Port](#13-critical-invariants-for-a-rust-port)
14. [Security-Relevant Edge Cases](#14-security-relevant-edge-cases)

---

## 1. Architecture Overview

libinjection is a **signature-free, fingerprint-based** attack detector. It does not parse full SQL or HTML grammars. Instead it:

1. **Tokenizes** input with a lightweight lexer tuned for SQL/HTML attack fragments.
2. **Folds** (normalizes) token sequences to collapse benign syntactic sugar.
3. **Fingerprints** the resulting ≤5 token type sequence (e.g. `s&1UE`).
4. **Matches** fingerprints against a large sorted keyword table (~9,352 entries).
5. **Whitelists** known false-positive patterns via hand-tuned heuristics.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Input bytes + length                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         │         SQLi path (libinjection_sqli)    │
         │  ┌─────────────────────────────────┐   │
         │  │ Multi-context scan (up to 5):   │   │
         │  │  • no-quote + ANSI              │   │
         │  │  • no-quote + MySQL (reparse)   │   │
         │  │  • single-quote context         │   │
         │  │  • double-quote context         │   │
         │  └──────────────┬──────────────────┘   │
         │                 ▼                       │
         │  char_parse_map[byte] → parse_*()       │
         │                 ▼                       │
         │  libinjection_sqli_tokenize()           │
         │                 ▼                       │
         │  libinjection_sqli_fold()  (≤5 tokens) │
         │                 ▼                       │
         │  fingerprint = token types as string    │
         │                 ▼                       │
         │  blacklist (table lookup)               │
         │                 ▼                       │
         │  not_whitelist (heuristics)             │
         └───────────────────┬───────────────────┘
                             │
         ┌───────────────────┴───────────────────┐
         │         XSS path (libinjection_xss)      │
         │  ┌─────────────────────────────────┐   │
         │  │ HTML5 tokenizer (5 contexts)    │   │
         │  │  • DATA_STATE                   │   │
         │  │  • VALUE_NO/SINGLE/DOUBLE/BACK  │   │
         │  └──────────────┬──────────────────┘   │
         │                 ▼                       │
         │  Black-tag / black-attr / black-url     │
         │  checks on each token                   │
         └─────────────────────────────────────────┘
```

**Design philosophy:** optimize for WAF embedding - **zero heap allocation**, bounded stack buffers, O(log n) binary search on static tables, and deterministic behavior on arbitrary binary input (including embedded NUL bytes).

---

## 2. Repository Structure

```
libinjection/
├── src/                          # Core C implementation (embeddable)
│   ├── libinjection.h            # Minimal public API (2 functions)
│   ├── libinjection_sqli.c/.h    # SQLi engine
│   ├── libinjection_sqli_data.h  # Generated: char map, keywords, fingerprints
│   ├── libinjection_html5.c/.h   # HTML5 subset tokenizer (for XSS)
│   ├── libinjection_xss.c/.h     # XSS detector
│   ├── fingerprints.txt          # ~8,367 fingerprint patterns (source data)
│   ├── sqlparse_map.py           # Generates keyword/fingerprint JSON
│   ├── sqlparse2c.py             # Generates libinjection_sqli_data.h
│   ├── make_parens.py            # Expands parenthesis variants in fingerprints
│   ├── testdriver.c              # Unit test runner
│   ├── reader.c                  # Corpus/bulk sample runner
│   └── Makefile
├── tests/                        # 480 structured unit tests
│   ├── test-tokens-*   (249)     # Raw tokenization
│   ├── test-folding-*  (118)     # Tokenize + fold
│   ├── test-sqli-*     (50)      # End-to-end SQLi detection
│   └── test-html5-*    (63)      # HTML5 tokenizer output
├── data/                         # Real-world URL-encoded corpora
│   ├── sqli-*.txt                # Positive SQLi samples
│   ├── xss*                      # Positive XSS samples
│   └── false_positives.txt       # Known benign inputs
├── go/                           # CGO demo only (not a pure Go port)
├── python/, php/, lua/           # Language bindings
└── misc/                         # Benchmarks, presentations
```

**Minimal embed set** (per README): `libinjection.h`, `libinjection_sqli.c`, `libinjection_sqli_data.h`, `COPYING`.

---

## 3. Public C API

### 3.1 Simple API (`libinjection.h`)

```c
const char* libinjection_version(void);

/* Returns 1 if SQLi, 0 if benign. fingerprint set on match. */
int libinjection_sqli(const char* s, size_t slen, char fingerprint[]);

/* Returns 1 if XSS, 0 if benign. */
int libinjection_xss(const char* s, size_t slen);
```

**Contract notes:**
- Input **may contain embedded NUL bytes**; `slen` is authoritative (not `strlen`).
- Input is **never modified** (read-only scan).
- `fingerprint` buffer must be ≥8 bytes (includes NUL terminator; max 5 type chars + NUL).
- On benign input, `fingerprint[0] = '\0'`.

### 3.2 Advanced SQLi API (`libinjection_sqli.h`)

| Function | Purpose |
|----------|---------|
| `libinjection_sqli_init()` | Initialize state with input, flags, default lookup |
| `libinjection_sqli_reset()` | Reset parser; preserve input and callback |
| `libinjection_sqli_callback()` | Override word/fingerprint lookup (testing/hooks) |
| `libinjection_sqli_tokenize()` | Stream one token at a time |
| `libinjection_sqli_fold()` | Tokenize + fold; returns token count |
| `libinjection_sqli_fingerprint()` | Full pipeline for one quote/SQL dialect context |
| `libinjection_sqli_check_fingerprint()` | Blacklist ∧ ¬whitelist |
| `libinjection_sqli_blacklist()` | Fingerprint table match |
| `libinjection_sqli_not_whitelist()` | False-positive suppression |
| `libinjection_is_sqli()` | Multi-context orchestrator (main detection) |
| `libinjection_sqli_lookup_word()` | Default binary-search keyword lookup |
| `libinjection_sqli_get_token()` | Access folded token vector by index |

### 3.3 XSS Internal API (`libinjection_xss.h`)

```c
int libinjection_is_xss(const char* s, size_t len, int flags);
```

`libinjection_xss()` calls `libinjection_is_xss()` in five HTML5 parse contexts (see §5).

### 3.4 Flags

```c
enum sqli_flags {
    FLAG_NONE         = 0,
    FLAG_QUOTE_NONE   = 1,   /* Process input as-is */
    FLAG_QUOTE_SINGLE = 2,   /* Pretend input starts inside '...' */
    FLAG_QUOTE_DOUBLE = 4,   /* Pretend input starts inside "..." */
    FLAG_SQL_ANSI     = 8,   /* ANSI comment/operator semantics */
    FLAG_SQL_MYSQL    = 16,  /* MySQL-specific comment semantics */
};

enum html5_flags {
    DATA_STATE, VALUE_NO_QUOTE, VALUE_SINGLE_QUOTE,
    VALUE_DOUBLE_QUOTE, VALUE_BACK_QUOTE
};
```

---

## 4. SQL Injection Detection

### 4.1 Detection Pipeline

`libinjection_is_sqli()` runs up to **5 parse passes**:

| Pass | Flags | Trigger |
|------|-------|---------|
| 1 | `FLAG_QUOTE_NONE \| FLAG_SQL_ANSI` | Always |
| 2 | `FLAG_QUOTE_NONE \| FLAG_SQL_MYSQL` | If MySQL-specific comments detected in pass 1 |
| 3 | `FLAG_QUOTE_SINGLE \| FLAG_SQL_ANSI` | If `'` found in input |
| 4 | `FLAG_QUOTE_SINGLE \| FLAG_SQL_MYSQL` | MySQL reparse after pass 3 |
| 5 | `FLAG_QUOTE_DOUBLE \| FLAG_SQL_MYSQL` | If `"` found in input |

**MySQL reparse trigger** (`reparse_as_mysql`):
```c
return sql_state->stats_comment_ddx || sql_state->stats_comment_hash;
```

### 4.2 Token Types

Internal enum maps to single-character fingerprint symbols:

| Char | Constant | Meaning |
|------|----------|---------|
| `k` | TYPE_KEYWORD | SQL keyword (SELECT, FROM, …) |
| `U` | TYPE_UNION | UNION keyword (special-cased) |
| `B` | TYPE_GROUP | GROUP BY phrase |
| `E` | TYPE_EXPRESSION | SELECT-like expression starter |
| `t` | TYPE_SQLTYPE | Type/collation (_UTF8, binary, …) |
| `f` | TYPE_FUNCTION | Function call |
| `n` | TYPE_BAREWORD | Unquoted identifier |
| `1` | TYPE_NUMBER | Numeric literal |
| `v` | TYPE_VARIABLE | `@var`, `@@var` |
| `s` | TYPE_STRING | Quoted string |
| `o` | TYPE_OPERATOR | `=`, `*`, `::`, etc. |
| `&` | TYPE_LOGIC_OPERATOR | AND, OR, XOR, `\|\|` |
| `c` | TYPE_COMMENT | `--`, `#`, `/* */` |
| `A` | TYPE_COLLATE | COLLATE |
| `(` `)` | TYPE_LEFTPARENS / RIGHTPARENS | Parentheses |
| `{` `}` | TYPE_LEFTBRACE / RIGHTBRACE | MySQL `{identifier}` |
| `.` `,` `:` `;` | TYPE_DOT, COMMA, COLON, SEMICOLON | Punctuation |
| `T` | TYPE_TSQL | T-SQL control flow (IF after `;`) |
| `?` | TYPE_UNKNOWN | Unclassified single char |
| `X` | TYPE_EVIL | Unparseable / banned (auto-detect) |
| `F` | TYPE_FINGERPRINT | Table entry type (not a runtime token) |
| `\` | TYPE_BACKSLASH | MySQL escape/backslash semantics |

### 4.3 Tokenizer: Character Dispatch Table

The lexer uses a **256-entry function pointer table** (`char_parse_map[]`) indexed by `(unsigned char) input[pos]`:

| Byte range / char | Parser |
|-------------------|--------|
| 0–32 | `parse_white` (skip; no token emitted) |
| `'`, `"` | `parse_string` |
| `#` | `parse_hash` |
| `$` | `parse_money` (PostgreSQL `$$`, `$tag$`) |
| `-` | `parse_dash` |
| `/` | `parse_slash` |
| `\` | `parse_backslash` |
| `` ` `` | `parse_tick` (MySQL backtick) |
| `0`–`9` | `parse_number` |
| `@` | `parse_var` |
| `a`–`z`, `A`–`Z`, `_`, high bytes | `parse_word` |
| Multi-char operators | `parse_operator2` (`!=`, `&&`, `<=>`, …) |

**Quote-context bootstrap:** when `FLAG_QUOTE_SINGLE|DOUBLE` and `pos==0`, tokenizer calls `parse_string_core()` directly - simulating input already inside a string literal.

### 4.4 Notable Parser Behaviors

**Comments (`parse_dash`, `parse_hash`, `parse_slash`):**
- `--[whitespace]` or `--` at EOF → always comment (all DBs).
- `--[not-whitespace]` → comment in ANSI mode; **two unary `-` operators** in MySQL mode (`stats_comment_ddx++`).
- `#` → EOL comment in MySQL mode; `#` as operator in ANSI mode.
- `/* */` → comment; nested `/*` inside comment → `TYPE_EVIL`.
- `/*! ... */` MySQL versioned comment → `TYPE_EVIL` (auto-ban).

**Strings (`parse_string_core`):**
- Handles backslash escaping (odd count of `\` before quote = escaped).
- Handles doubled-quote escape (`''`, `""`).
- Tracks `str_open`, `str_close` on token for whitelist heuristics.

**Words (`parse_word`):**
- Scans until delimiter set: ` []{}<>:\\?=@!#~+-*/&|^%(),';\t\n\v\f\r"\240\000`
- Splits on embedded `.` or `` ` `` if prefix is a keyword.
- Binary-searches `sql_keywords[]` for classification.

**Numbers (`parse_number`):**
- Decimal, hex (`0x`), binary (`0b`), scientific notation.
- Oracle suffixes `d`/`f` with special "1fUNION" split logic.
- Incomplete exponent (`1.2e`) → bareword, not number.

### 4.5 Folding Algorithm

`libinjection_sqli_fold()` maintains a sliding window of up to **8 tokens** in `tokenvec[8]` but emits at most **5** fingerprint tokens (`LIBINJECTION_SQLI_MAX_TOKENS`).

**Phase 1 - Skip prefix noise:** comments, `(`, unary ops, SQL types.

**Phase 2 - Two-token folds** (representative rules):
- `"ss"` → keep first string (adjacent string literals).
- `;;` → collapse duplicate semicolons.
- `UNION` + `ALL` → merge via `syntax_merge_words()` + keyword lookup.
- `;` + `IF` → retype `IF` from function to TSQL (`T`).
- `bareword` + `(` → promote to function for known names (USER, DATABASE, …).
- `IN`/`NOT IN` + `(` → operator; without `(` → bareword.
- `LIKE`/`NOT LIKE` + `(` → function.
- `sqltype` + value → drop type token.
- `{` + bareword → strip ODBC/MySQL `{foo ...}` wrapper.
- `..`, `((`, `))` → collapse.

**Phase 3 - Three-token folds** (representative):
- `number op number` → fold away (arithmetic noise).
- `op op op` → fold (except `( op (` pattern).
- `bareword . bareword` → drop qualifier (database.table → table).
- `expr . bareword` → keep bareword.
- `value , value` → fold list elements.

**Phase 4 - Five-token special cases:** preserve patterns like `1,(1)` that would over-fold.

**Comment reattachment:** if ≤4 tokens remain and trailing comment was buffered, reattach comment as final token.

### 4.6 Fingerprint Format

After folding, fingerprint is built by concatenating **token type characters**:

```
Input:  -1' and 1=1 union/* foo */select load_file('/etc/passwd')--
Tokens: s  &  1  U  E   (after fold)
Fingerprint: "s&1UE"
```

**Blacklist lookup** prepends `'0'` and uppercases for v1 table format:
```c
fp2[0] = '0';
for (i = 0; i < len; ++i)
    fp2[i+1] = toupper(fingerprint[i]);
// e.g. "s&1UE" → "0S&1UE" searched in sql_keywords[]
```

Match when `is_keyword(fp2, len+1) == TYPE_FINGERPRINT ('F')`.

**~8,367 unique fingerprint patterns** in `fingerprints.txt`, expanded with parenthesis variants via `make_parens.py`.

### 4.7 Whitelist Heuristics (`libinjection_sqli_not_whitelist`)

Applied **after** blacklist match to reduce false positives:

| Fingerprint length | Rule |
|--------------------|------|
| 2 | `1U` benign if only 2 tokens total |
| 2 | `#` comments ignored |
| 2 | `nc` benign unless comment starts with `/` (C-style) |
| 2 | `1c` requires original-string validation (not base64-like `--`) |
| 2 | `--` comment must end input (not `1-- foo`) |
| 2 | `sp_password` in input → always SQLi |
| 3 | `sos`, `s&s` string-concat only if unquoted open/close pattern |
| 3 | `s&n`, `n&1`, `1&1`, etc. benign if exactly 3 tokens |
| 3 | keyword in position 2 must be `INTO` (OUTFILE/DUMPFILE) |

The `reason` field stores `__LINE__` of the rejecting/accepting branch (debug only).

---

## 5. XSS Detection

### 5.1 Architecture

XSS detection is **rule-based over an HTML5 subset tokenizer**. It does not build a DOM. The header explicitly marks it **"ALPHA / NOT DONE"**.

```
libinjection_xss()
  ├── libinjection_is_xss(s, len, DATA_STATE)
  ├── libinjection_is_xss(s, len, VALUE_NO_QUOTE)
  ├── libinjection_is_xss(s, len, VALUE_SINGLE_QUOTE)
  ├── libinjection_is_xss(s, len, VALUE_DOUBLE_QUOTE)
  └── libinjection_is_xss(s, len, VALUE_BACK_QUOTE)
```

Any context returning 1 → XSS detected.

### 5.2 HTML5 Tokenizer (`libinjection_html5.c`)

Implements a **partial HTML5 state machine** (~850 LOC) with function-pointer states:

| State function | Purpose |
|----------------|---------|
| `h5_state_data` | Scan text until `<` |
| `h5_state_tag_open` | Handle `<`, `<!`, `</`, `<?`, `<%` |
| `h5_state_tag_name` | Tag name token |
| `h5_state_attribute_name` | Attribute name |
| `h5_state_attribute_value_*` | Quoted/unquoted/backtick values |
| `h5_state_comment` | `<!-- ... -->` |
| `h5_state_bogus_comment` | `<?...>`, `%...>` (IE legacy) |
| `h5_state_doctype` | `<!DOCTYPE` → immediate XSS flag |

**Token types emitted:** `DATA_TEXT`, `TAG_NAME_OPEN/CLOSE`, `ATTR_NAME`, `ATTR_VALUE`, `TAG_COMMENT`, `DOCTYPE`.

**Context entry points:**
- `DATA_STATE` - full HTML document fragment scan.
- `VALUE_*` - start parsing as if inside an attribute value (simulates injection into HTML attribute context).

### 5.3 XSS Decision Logic

For each HTML5 token:

| Token | Check |
|-------|-------|
| `DOCTYPE` | Always XSS (1) |
| `TAG_NAME_OPEN` | `is_black_tag()` |
| `ATTR_NAME` | `is_black_attr()` → stores attr class for next value |
| `ATTR_VALUE` | Apply stored attr class |
| `TAG_COMMENT` | Backtick, `[if`, `xml`, `IMPORT`, `ENTITY` patterns |

**Black tags** (`BLACKTAG[]`): APPLET, BASE, COMMENT, EMBED, FRAME, IFRAME, SCRIPT, STYLE, SVG*, XSL*, etc.

**Black attributes** (`BLACKATTR[]`):
- `on*` event handlers → `TYPE_BLACK`
- `XMLNS`, `XLINK` → `TYPE_BLACK`
- URL attrs (href, src, action, …) → `TYPE_ATTR_URL`
- `style`, `filter` → `TYPE_STYLE` (always XSS in value)
- `ATTRIBUTENAME` → `TYPE_ATTR_INDIRECT` (SVG)

**Black URLs** (`is_black_url`): case-insensitive, HTML-entity-aware prefix match for:
- `DATA:`
- `VIEW-SOURCE:`
- `JAVA` (covers JAVASCRIPT:, JAVA:)
- `VBSCRIPT:`

**HTML entity decoding** (`html_decode_char_at`): handles `&#...;` and `&#x...;` for URL scheme evasion (`j&#97;vascript:`).

### 5.4 Known XSS Limitations

- Plain-text `javascript:` URLs **not detected** outside attribute context (confirmed in coraza-rs tests).
- Attribute values containing `<` tags not re-parsed (commented-out check).
- No CSS expression / `-moz-binding` deep analysis.
- `DATA_TEXT` tokens are never inspected (text-only payloads may evade).

---

## 6. Key Data Structures

### 6.1 `stoken_t` (SQL token)

```c
typedef struct libinjection_sqli_token {
    size_t pos;       /* byte offset in original input */
    size_t len;       /* byte length in original input */
    int count;        /* @ count for TYPE_VARIABLE */
    char type;        /* fingerprint character */
    char str_open;    /* opening quote char (or '\0') */
    char str_close;   /* closing quote char (or '\0') */
    char val[32];     /* token text (truncated to 31 + NUL) */
} stoken_t;
```

### 6.2 `libinjection_sqli_state` (SQL filter)

```c
typedef struct libinjection_sqli_state {
    const char *s;              /* input pointer (not owned) */
    size_t slen;
    ptr_lookup_fn lookup;       /* keyword/fingerprint lookup callback */
    void *userdata;
    int flags;
    size_t pos;                 /* current parse position */
    stoken_t tokenvec[8];       /* 5 folded + 3 lookahead */
    stoken_t *current;
    char fingerprint[8];          /* 5 types + NUL + stack-protector pad */
    int reason;                 /* debug: __LINE__ of decision */
    int stats_comment_ddw;      /* '-- ' style comments */
    int stats_comment_ddx;      /* '--foo' non-MySQL style */
    int stats_comment_c;        /* C-style comments */
    int stats_comment_hash;     /* # comments */
    int stats_folds;
    int stats_tokens;
} sfilter;
```

### 6.3 `h5_state_t` (HTML5 tokenizer)

```c
typedef struct h5_state {
    const char* s;
    size_t len;
    size_t pos;
    int is_close;
    ptr_html5_state state;      /* current state function */
    const char* token_start;
    size_t token_len;
    enum html5_type token_type;
} h5_state_t;
```

---

## 7. Lookup Tables and Generated Data

All tables live in **`libinjection_sqli_data.h`** (~207 KB, generated).

### 7.1 Generation Pipeline

```
fingerprints.txt
    → make_parens.py (expand parenthesis variants)
    → sqlparse_map.py (merge keywords, operators, phrases, fingerprints)
    → sqlparse_data.json
    → sqlparse2c.py
    → libinjection_sqli_data.h
```

### 7.2 `char_parse_map[256]`

Maps each byte value to a `parse_*` function. This is the primary lexer dispatch mechanism - **must be reproduced exactly** in ports.

### 7.3 `sql_keywords[]`

Sorted array of `{word, type}` pairs (~9,352 entries). Used for:

| Lookup type | Purpose |
|-------------|---------|
| `LOOKUP_WORD` | Classify barewords, merged phrases |
| `LOOKUP_OPERATOR` | Two-char operators |
| `LOOKUP_TYPE` | (reserved) |
| `LOOKUP_FINGERPRINT` | Indirect via `check_fingerprint()` |

Search uses **custom `cstrcasecmp()`** - ASCII uppercase comparison without locale dependency.

**Entry types in table:**
- `'k'` keywords (SELECT, FROM, …)
- `'f'` functions
- `'o'` operators
- `'&'` logic operators
- `'F'` **fingerprint patterns** (with leading `0` prefix)
- `'t'` SQL types/collations

### 7.4 Fingerprint Semantics (from `fingerprints2sqli.py`)

| Char | Attack fragment |
|------|-----------------|
| `1` | number |
| `s` | string `"1"` |
| `&` | AND |
| `U` | UNION |
| `E` | SELECT |
| `f` | function |
| `c` | comment |
| `(` `)` | parentheses |
| `X` | nested comment (unparseable) |

---

## 8. Memory Model

### 8.1 Stack-Only, Zero Heap

The production detection path (`libinjection_sqli`, `libinjection_xss`, `libinjection_is_sqli`) performs **no malloc/free**:

| Allocation | Location | Size |
|------------|----------|------|
| SQL state | caller stack or local in `libinjection_sqli()` | `sizeof(sfilter)` ≈ few hundred bytes |
| HTML5 state | stack in `libinjection_is_xss()` | `sizeof(h5_state_t)` |
| Token values | embedded in `stoken_t.val[32]` | 32 bytes each |
| Fingerprint | `state.fingerprint[8]` | 8 bytes |
| Fold temporaries | `tmp[32]` in `syntax_merge_words()` | stack |

### 8.2 Heap Usage (Non-Production Only)

- `testdriver.c` - `malloc` for input copy and HTML5 token printing.
- `reader.c` - line buffer on stack; URL decode to stack buffer.

### 8.3 Buffer Bounds

- Token text truncated at **31 bytes** (`LIBINJECTION_SQLI_TOKEN_SIZE - 1`).
- Fingerprint max **5 characters** + NUL.
- `tokenvec[8]` holds 5 output + up to 3 lookahead tokens during fold.
- Input length **unbounded** - parsing is O(n) single-pass with no backtracking buffer.

### 8.4 String Safety

- All string ops use explicit `slen` - **embedded NULs are handled correctly**.
- `memchr`, `memchr2`, `my_memmem` replace libc string functions.
- No `%s` on untrusted input in library code.

---

## 9. Performance Design Choices

| Technique | Rationale |
|-----------|-----------|
| `char_parse_map[256]` | O(1) lexer dispatch per byte |
| Binary search on sorted keywords | O(log n) lookup; no hash table allocation |
| Custom `cstrcasecmp` | Avoid locale; faster than `strcasecmp` |
| `ISDIGIT` macro | Branch-friendly digit test |
| `-O3 -fPIC` default | Production WAF throughput |
| Fold to ≤5 tokens | Bounded work regardless of input length |
| Early exit in `libinjection_is_sqli` | Stop on first matching context |
| `memchr` for `<` in HTML5 | Skip text runs quickly |
| Static blacklists for XSS | No runtime compilation |

**Benchmark tooling:** `test_speed_sqli.c`, `test_speed_xss.c` (optional CI targets).

**Typical cost:** single SQLi check ≈ 1–5 µs on modern hardware (varies by input length and context count).

---

## 10. Test Suite Structure

### 10.1 Unit Tests (`tests/`, 480 files)

Format (parsed by `testdriver.c`):

```
--TEST--
description
--INPUT--
payload here
--EXPECTED--
expected output
```

| Pattern | testtype | Validates |
|---------|----------|-----------|
| `test-tokens-*` | 0 | Raw tokenization |
| `test-folding-*` | 1 | Tokenize + fold |
| `test-sqli-*` | 2 | `libinjection_sqli()` → fingerprint or empty |
| `test-html5-*` | 3 | HTML5 token stream |
| `test-xss-*` | 4 | `libinjection_xss()` → `"0"` or `"1"` |

Run via: `make check` → `test-driver.sh test-unit.sh`

### 10.2 Corpus Tests (`data/`)

`reader.c` bulk runner:
- **SQLi positive:** `./reader -i -m 18 ../data/sqli-*.txt`
- **XSS positive:** `./reader -t -x -m 18 ../data/xss*`
- **False positives:** `false_positives.txt` (must NOT match)

Lines are URL-decoded before testing (simulates query-string input).

### 10.3 CI Quality Gates

- GCC + Clang builds
- Clang static analyzer
- cppcheck
- Valgrind (via `test-driver.sh`)
- gcov coverage scripts

---

## 11. Go Port and Ecosystem Relationship

### 11.1 Official `go/` Directory

The upstream `go/main.go` is a **CGO wrapper demo only** - it calls C `libinjection_sqli()` via `#cgo` directives. It is **not** a native Go reimplementation.

### 11.2 Coraza Ecosystem Ports

| Project | Type | Notes |
|---------|------|-------|
| [corazawaf/libinjection-go](https://github.com/corazawaf/libinjection-go) | **Pure Go port** | Line-by-line port of C logic; `IsSQLi()`, `IsXSS()` API |
| [wasilibs/go-libinjection](https://github.com/wasilibs/go-libinjection) | **WASM/CGO wrapper** | Drop-in replacement for libinjection-go; wraps C via wazero or cgo |
| [saarw/libinjectionrs](https://github.com/saarw/libinjectionrs) | **Rust port** | Used by coraza-rs via `libinjectionrs` crate v0.1.1 |
| coraza-rs `libinjection-rs/` | **Placeholder** | Empty stub; production uses crates.io `libinjectionrs` |

### 11.3 Behavioral Parity Chain

```
client9/libinjection (C, authoritative)
    ↓ port
corazawaf/libinjection-go (pure Go, primary behavioral reference for Go)
    ↓ wrap OR re-port
wasilibs/go-libinjection (WASM/C for performance)
libinjectionrs (Rust, for coraza-rs)
```

**Coraza-rs integration** (`coraza-rs/src/operators/detection.rs`):
```rust
let result = libinjectionrs::detect_sqli(input.as_bytes());
// Captures fingerprint in transaction field 0 on match
```

### 11.4 Key Go Port Mapping

The Go port mirrors C structures directly:

| C | Go (`libinjection-go`) |
|---|------------------------|
| `stoken_t` | `sqliToken` |
| `libinjection_sqli_state` | `sqliState` |
| `libinjection_sqli_fold()` | `(s *sqliState) fold()` |
| `libinjection_is_sqli()` | `(s *sqliState) check()` |
| `libinjection_sqli_not_whitelist()` | `(s *sqliState) notWhitelist()` |
| `sql_keywords[]` | embedded Go slice `sqlKeywords` |
| `char_parse_map[]` | Go array of parse functions |

---

## 12. File-by-File Breakdown

| File | LOC | Role |
|------|-----|------|
| `libinjection.h` | 65 | Public 2-function API |
| `libinjection_sqli.h` | 214 | Extended SQLi API, types, flags |
| `libinjection_sqli.c` | 2325 | Tokenizer, folder, fingerprint, detection |
| `libinjection_sqli_data.h` | 9652 | Generated tables (keywords, char map) |
| `libinjection_html5.h` | 54 | HTML5 tokenizer types |
| `libinjection_html5.c` | 850 | HTML5 state machine |
| `libinjection_xss.h` | 12 | XSS function declaration |
| `libinjection_xss.c` | 532 | Blacklists + XSS orchestration |
| `fingerprints.txt` | 8367 lines | Fingerprint source data |
| `sqlparse_map.py` | ~1200 | Keyword/fingerprint generator |
| `sqlparse2c.py` | ~100 | JSON → C header |
| `make_parens.py` | ~300 | Parenthesis expansion |
| `testdriver.c` | 280 | Unit test harness |
| `reader.c` | 280 | Corpus test harness |
| `fptool.c` | 70 | Fingerprint debugging CLI |
| `sqli_cli.c` | 130 | Interactive SQLi CLI |

---

## 13. Critical Invariants for a Rust Port

### 13.1 Must Match Exactly

1. **Token type characters** - fingerprint alphabet is part of the detection contract; CRS rules log fingerprints.
2. **`char_parse_map` dispatch** - byte-to-parser mapping must be identical.
3. **`sql_keywords` table** - same words, same order, same types (binary search depends on sort order).
4. **Fold rules** - all 2-token and 3-token fold cases; order of evaluation matters.
5. **Multi-context scan order** in `libinjection_is_sqli()` - ANSI before MySQL reparse; single-quote before double-quote.
6. **MySQL reparse trigger** - `stats_comment_ddx || stats_comment_hash`.
7. **Fingerprint v1 encoding** - prepend `'0'`, uppercase before table lookup.
8. **Whitelist heuristics** - every branch in `not_whitelist()`; these are security tuning.
9. **`TYPE_EVIL` handling** - nested comments, MySQL versioned comments.
10. **XSS five-context scan** - DATA, NO_QUOTE, SINGLE, DOUBLE, BACK_QUOTE.
11. **HTML5 tokenizer states** - attribute context simulation affects detection.
12. **Token `val` truncation at 31 bytes** - affects keyword merge and edge cases.

### 13.2 Semantic Preservation

- Input is `&[u8]` not `&str` - **UTF-8 validity irrelevant**; bytes processed as-is.
- `pos`/`len` on tokens refer to **original input offsets**, not folded buffer.
- `stats_tokens` counts tokenizer emissions including folded-away tokens.
- Quote simulation: `FLAG_QUOTE_SINGLE` at pos 0 skips opening quote parsing.
- Comment statistics accumulate across entire parse even when comments are folded away.

### 13.3 Acceptable Differences

- Memory allocation strategy (Rust `Vec` internally OK if behavior identical).
- Error handling (C undefined behavior zones → Rust safe equivalents).
- `reason` field (__LINE__ numbers won't match; debug only).

### 13.4 Verification Strategy

1. Run all 480 `tests/test-*.txt` fixtures.
2. Run `data/sqli-*.txt` and `data/xss*` corpora via reader equivalent.
3. Run `data/false_positives.txt` - must stay benign.
4. Compare fingerprints byte-for-byte against C for corpus inputs.
5. Fuzz with C/Rust differential testing (libinjectionrs includes `comparison-bin/`).

---

## 14. Security-Relevant Edge Cases

### 14.1 SQLi Evasion Surfaces

| Technique | C behavior |
|-----------|------------|
| `1*1--` | Folding may merge to `1`; whitelist checks **original string** at `s[tokenvec[0].len]` |
| `1234-ABCD--` | Base64-like suffix → `1c` fingerprint but **whitelisted** (no WS after number) |
| `1-- foo` | `--` comment with trailing text → **not SQLi** (len > 2 check) |
| `1/*!50000UNION*/` | MySQL versioned comment → `TYPE_EVIL` → detect |
| PostgreSQL nested `/* /* */ */` | Inner `/*` → `TYPE_EVIL` |
| `--foo` (no space) | ANSI: comment + `stats_comment_ddx`; triggers MySQL reparse |
| `# comment` | MySQL mode only; `#` alone is operator in ANSI |
| `$tag$...$tag$` | PostgreSQL dollar-quoting → TYPE_STRING |
| `{ `` . `` .id }` | Empty bareword in braces → `TYPE_EVIL` |
| `sp_password` | Always flagged even with comment fingerprint |
| String concat `'a'+'b'` | Folds to single string; `sos`/`s&s` whitelist applies |
| `UNION` alone | `1U` with 2 tokens → whitelisted |

### 14.2 SQLi False Positive Surfaces

| Input pattern | Why benign |
|---------------|------------|
| `"sexy and 17"` | `s&n` with exactly 3 tokens |
| `"foo" OR "BAR"` | Quoted OR without injection structure |
| `#hashtag` in ANSI mode | `#` parsed as operator, not comment |
| `1234--` in base64 strings | Original-char whitelist |

### 14.3 XSS Evasion Surfaces

| Technique | Detected? |
|-----------|-----------|
| `<script>alert(1)</script>` | Yes (SCRIPT tag) |
| `<img src=x onerror=alert(1)>` | Yes (`on*` attr) |
| `<a href="javascript:...">` | Yes (in attribute value context) |
| `javascript:alert(1)` plain text | **No** (no HTML context) |
| `&#106;&#97;vascript:` | Yes (entity decoding in URL check) |
| `<svg/onload=...>` | Yes (SVG tag prefix) |
| `<!DOCTYPE ...>` | Yes (immediate flag) |
| `<!--[if IE]>` | Yes (IE conditional comment) |
| `%>` (IE ASP comment) | Parsed as bogus comment; inner IMPORT/ENTITY checked |

### 14.4 Implementation Hazards for Ports

1. **Locale-dependent case folding** - must use ASCII-only uppercase (`a-z` → subtract 0x20).
2. **Signed char pitfalls** - XSS URL skip treats `*s >= 127` as whitespace (high bytes skipped).
3. **Off-by-one in `--` detection** - five distinct cases in `parse_dash()`.
4. **Oracle null in whitespace** - `\000` treated as whitespace in SQL tokenizer.
5. **Windows-1252 nbsp** - `\240` in SQL whitespace set.
6. **Token truncation** - keywords >31 chars silently truncated before lookup.
7. **Double-quote context uses MySQL only** - `FLAG_QUOTE_DOUBLE | FLAG_SQL_MYSQL` (no ANSI variant).

---

## Appendix A: Example Detection Trace

**Input:** `-1' and 1=1 union/* foo */select load_file('/etc/passwd')--`

**Pass 1** (no quote, ANSI):
1. Tokenize: `-`, `1`, `'`, `and`, `1`, `=`, `1`, `union`, `/* foo */`, `select`, …
2. Fold: skip unary `-`; merge `and`; fold arithmetic; merge `UNION ALL`-like patterns
3. Fingerprint: `s&1UE`
4. Blacklist: `0S&1UE` → match (`F`)
5. Whitelist: passes (length > 2)
6. **Result: SQLi detected**

---

## Appendix B: Versioning Policy

From README:
- **Major** - API or fingerprint format changes (requires recompile/rule updates).
- **Minor** - C logic changes (detection/suppression/optimization).
- **Point** - data-only changes (safe to apply).

Current embedded version: **3.9.2** (`LIBINJECTION_VERSION` in `libinjection_sqli.c`).

---

## References

- Upstream: https://github.com/client9/libinjection
- Documentation: https://libinjection.client9.com/
- Go port: https://github.com/corazawaf/libinjection-go
- Rust port: https://github.com/saarw/libinjectionrs
- Coraza WASM wrapper: https://github.com/wasilibs/go-libinjection
