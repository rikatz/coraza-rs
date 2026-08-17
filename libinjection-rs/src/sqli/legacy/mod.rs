/*
Copyright Coraza Kubernetes Operator contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! Legacy `SQLi` path: tokenize, fold, fingerprint, blacklist, whitelist.
//!
//! Enabled only with the `legacy` feature. Used for corpus parity and
//! audit field 0 (`LegacyFingerprint`), not as the primary internal model.

/// Safe accessor helpers for `SqliState` (bounds-checked token/fingerprint/input access).
mod access;
/// Constants (flags, token types, limits).
pub(crate) mod consts;
/// Generated keyword / fingerprint table (`build.rs` + `include!`).
pub(crate) mod data;
/// SQLi detection: fingerprint, blacklist, whitelist, multi-pass check.
mod detect;
/// Folding engine: reduce token stream to ≤5 tokens for fingerprinting.
mod fold;
/// Byte-level helpers (escaping, whitespace, accept tables).
pub(crate) mod helpers;
/// Per-byte token parsers and dispatch table.
pub(crate) mod parse;
/// `SqliState` struct and `tokenize()`.
pub(crate) mod state;
/// `SqliToken` and token-level helpers.
pub(crate) mod token;

pub(crate) use state::SqliState;

/// One emitted SQL token visible to integration-test drivers.
///
/// Carries only the data needed for `printToken`-style formatting.
pub struct SqliTokenInfo {
    /// Token type byte (`b'E'`, `b's'`, `b'v'`, ...).
    pub category: u8,
    /// Significant value length (≤ 31).
    pub len: usize,
    /// `@` count for variables (1 or 2).
    pub count: u8,
    /// Opening string delimiter (0 = none).
    pub str_open: u8,
    /// Closing string delimiter (0 = none/unclosed).
    pub str_close: u8,
    /// Value bytes (≤ 31 bytes).
    pub val: [u8; 31],
}

/// Tokenize `input` with `flags` and call `visit` for each emitted token.
///
/// This is the zero-alloc public API for test drivers (mirrors `html5_visit`).
pub fn sqli_tokenize_visit(input: &[u8], flags: u32, mut visit: impl FnMut(SqliTokenInfo)) {
    let mut state = SqliState::new(input, flags);
    while state.tokenize() {
        let tok = state.current();
        let mut val = [0_u8; 31];
        let copy_len = tok.len.min(31);
        if let Some(dst) = val.get_mut(..copy_len) {
            dst.copy_from_slice(tok.val_slice().get(..copy_len).unwrap_or(&[]));
        }
        visit(SqliTokenInfo {
            category: tok.category,
            len: tok.len,
            count: tok.count,
            str_open: tok.str_open,
            str_close: tok.str_close,
            val,
        });
    }
}

/// Fold `input` with `flags` and call `visit` for each folded token.
///
/// Used by the folding corpus driver.
pub fn sqli_fold_visit(input: &[u8], flags: u32, mut visit: impl FnMut(SqliTokenInfo)) {
    let mut state = SqliState::new(input, flags);
    let num_tokens = state.fold();
    for tok in state.token_vec.iter().take(num_tokens) {
        let mut val = [0_u8; 31];
        let copy_len = tok.len.min(31);
        if let Some(dst) = val.get_mut(..copy_len) {
            dst.copy_from_slice(tok.val_slice().get(..copy_len).unwrap_or(&[]));
        }
        visit(SqliTokenInfo {
            category: tok.category,
            len: tok.len,
            count: tok.count,
            str_open: tok.str_open,
            str_close: tok.str_close,
            val,
        });
    }
}

/// Top-level legacy `SQLi` detection returning fingerprint bytes.
///
/// Returns `(detected, fingerprint_bytes, fingerprint_len)`.
pub(crate) fn detect_with_fingerprint(input: &[u8]) -> (bool, [u8; 5], u8) {
    detect::is_sqli(input)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::sqli::legacy::consts::{FLAG_QUOTE_NONE, FLAG_SQL_ANSI};
    use std::string::String;

    const FLAGS_ANSI: u32 = FLAG_QUOTE_NONE | FLAG_SQL_ANSI;

    /// Format one token line per Go `printToken` (matches corpus drivers).
    fn format_token_line(tok: &SqliTokenInfo) -> String {
        let cat = tok.category as char;
        let val = core::str::from_utf8(tok.val.get(..tok.len).unwrap_or(&tok.val)).unwrap_or("");

        let mut out = String::new();
        out.push(cat);
        out.push(' ');
        match tok.category {
            b's' => {
                if tok.str_open != 0 {
                    out.push(tok.str_open as char);
                }
                out.push_str(val);
                if tok.str_close != 0 {
                    out.push(tok.str_close as char);
                }
            },
            b'v' => {
                if tok.count == 1 {
                    out.push('@');
                } else if tok.count == 2 {
                    out.push('@');
                    out.push('@');
                }
                if tok.str_open != 0 {
                    out.push(tok.str_open as char);
                }
                out.push_str(val);
                if tok.str_close != 0 {
                    out.push(tok.str_close as char);
                }
            },
            _ => {
                out.push_str(val);
            },
        }
        out
    }

    fn token_lines<const N: usize>(input: &[u8], flags: u32) -> ([String; N], usize) {
        let mut lines = [const { String::new() }; N];
        let mut count = 0_usize;
        sqli_tokenize_visit(input, flags, |tok| {
            if count < N {
                if let Some(slot) = lines.get_mut(count) {
                    *slot = format_token_line(&tok);
                }
                count += 1;
            }
        });
        (lines, count)
    }

    fn fold_lines<const N: usize>(input: &[u8], flags: u32) -> ([String; N], usize) {
        let mut lines = [const { String::new() }; N];
        let mut count = 0_usize;
        sqli_fold_visit(input, flags, |tok| {
            if count < N {
                if let Some(slot) = lines.get_mut(count) {
                    *slot = format_token_line(&tok);
                }
                count += 1;
            }
        });
        (lines, count)
    }

    fn assert_token_lines<const N: usize>(input: &[u8], flags: u32, expected: &[&str]) {
        let (lines, count) = token_lines::<N>(input, flags);
        assert_eq!(count, expected.len(), "token count mismatch for input={input:?}");
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(
                lines.get(i).map(String::as_str),
                Some(*exp),
                "token {i} input={input:?}"
            );
        }
    }

    fn assert_fold_lines<const N: usize>(input: &[u8], flags: u32, expected: &[&str]) {
        let (lines, count) = fold_lines::<N>(input, flags);
        assert_eq!(count, expected.len(), "fold count mismatch for input={input:?}");
        for (i, exp) in expected.iter().enumerate() {
            assert_eq!(lines.get(i).map(String::as_str), Some(*exp), "fold {i} input={input:?}");
        }
    }

    fn assert_fingerprint(input: &[u8], expected: &[u8]) {
        let (detected, fp, len) = detect_with_fingerprint(input);
        assert!(detected, "expected SQLi for input={input:?}");
        let end = usize::from(len);
        assert_eq!(fp.get(..end), Some(expected), "input={input:?}");
    }

    #[test]
    fn tokenize_keyword_smoke() {
        assert_token_lines::<4>(b"SELECT Z;", FLAGS_ANSI, &["E SELECT", "n Z", "; ;"]);
    }

    #[test]
    fn tokenize_single_quoted_string() {
        assert_token_lines::<4>(b"SELECT 'FOO';", FLAGS_ANSI, &["E SELECT", "s 'FOO'", "; ;"]);
    }

    #[test]
    fn tokenize_ddash_comment() {
        assert_token_lines::<4>(b"SELECT 1 --", FLAGS_ANSI, &["E SELECT", "1 1", "c --"]);
    }

    #[test]
    fn tokenize_backtick_function() {
        assert_token_lines::<8>(
            b"SELECT `version`();",
            FLAGS_ANSI,
            &["E SELECT", "f version", "( (", ") )", "; ;"],
        );
    }

    struct TokenizeCase {
        input: &'static [u8],
        expect: &'static [&'static str],
    }

    const TOKENIZE_CASES: &[TokenizeCase] = &[
        TokenizeCase {
            input: b"SELECT 1",
            expect: &["E SELECT", "1 1"],
        },
        TokenizeCase {
            input: b"foo--bar",
            expect: &["n foo", "c --bar"],
        },
    ];

    #[test]
    fn tokenize_table_cases() {
        for case in TOKENIZE_CASES {
            assert_token_lines::<8>(case.input, FLAGS_ANSI, case.expect);
        }
    }

    #[test]
    fn fold_merges_adjacent_strings() {
        assert_fold_lines::<4>(
            b"SELECT \"first\" \"second\";",
            FLAGS_ANSI,
            &["E SELECT", "s \"first\"", "; ;"],
        );
    }

    #[test]
    fn fold_strips_leading_unary_minus() {
        assert_fold_lines::<4>(b"- SELECT 1;", FLAGS_ANSI, &["E SELECT", "1 1", "; ;"]);
    }

    struct FoldCase {
        input: &'static [u8],
        expect: &'static [&'static str],
    }

    const FOLD_CASES: &[FoldCase] = &[FoldCase {
        input: b"123 /* junk */;",
        expect: &["1 123", "; ;"],
    }];

    #[test]
    fn fold_table_cases() {
        for case in FOLD_CASES {
            assert_fold_lines::<8>(case.input, FLAGS_ANSI, case.expect);
        }
    }

    #[test]
    fn is_sqli_benign_inputs() {
        let (detected, _, len) = detect_with_fingerprint(b"");
        assert!(!detected);
        assert_eq!(len, 0);

        for input in [b"hello".as_slice(), b"foo 'bar'", b"foo 'bar' \"zap\""] {
            let (detected, _, len) = detect_with_fingerprint(input);
            assert!(!detected, "benign input should not detect: {input:?}");
            assert_eq!(len, 0);
        }
    }

    #[test]
    fn is_sqli_detects_classic_patterns() {
        assert_fingerprint(b"1 = 1 OR 1", b"1&1");
        assert_fingerprint(b"1\" UNION ALL SELECT * FROM FOO", b"sUEok");
        assert_fingerprint(b"1' or 1.e(1)", b"s&(1)");
        assert_fingerprint(b"1' OR '1'='1", b"s&sos");
    }

    #[test]
    fn detect_union_select_fingerprint() {
        assert_fingerprint(b"1 UNION SELECT 1", b"1UE1");
    }

    #[test]
    fn tokenize_quoted_or_absorbed_in_string() {
        assert_token_lines::<8>(b"1' OR '1'='1", FLAGS_ANSI, &["1 1", "s ' OR '", "1 1", "s '='", "1 1"]);
    }
}
