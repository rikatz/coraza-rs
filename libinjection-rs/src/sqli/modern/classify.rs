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

//! Stage-1 SQL construct classifiers (stack-only heuristics).

#![allow(clippy::missing_docs_in_private_items, reason = "internal detector helpers")]

use crate::engine::ascii::{
    find_ignore_ascii_case, for_each_ignore_ascii_case, word_boundary_after, word_boundary_before,
};
use crate::engine::normalize::NormView;
use crate::engine::token::{TokenBuf, TokenKind};
use crate::limits::MAX_EVIDENCE;
use crate::snapshot::{ConstructFlags, EvidenceSet, EvidenceSpan, SqlDialect, SqliQuoteMode};

/// Classification output for one `SQLi` pass.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SqliClassifyResult {
    /// Matched construct bits.
    pub constructs: ConstructFlags,
    /// Evidence spans (offsets into original input).
    pub evidence: EvidenceSet,
    /// Best-effort quote mode.
    pub quote_mode: SqliQuoteMode,
    /// Best-effort dialect hint.
    pub dialect: SqlDialect,
}

/// Run all `SQLi` construct detectors.
#[must_use]
pub(crate) fn classify(norm: NormView<'_>, tokens: &TokenBuf) -> SqliClassifyResult {
    let mut out = SqliClassifyResult::default();
    let hay_orig = norm.original;
    let hay_norm = norm.bytes;

    detect_union(hay_orig, hay_norm, &mut out);
    detect_tautology(hay_orig, hay_norm, &mut out);
    detect_string_break(hay_orig, &mut out);
    detect_stacked(hay_orig, hay_norm, tokens, &mut out);
    detect_comments(hay_orig, &mut out);
    detect_functions(hay_orig, hay_norm, &mut out);
    detect_boolean_blind(hay_orig, hay_norm, &mut out);
    detect_keyword_chain(hay_orig, hay_norm, &mut out);
    detect_dialect(hay_orig, &mut out);
    out.quote_mode = infer_quote_mode(hay_orig);
    out
}

fn detect_union(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b"union", |pos| {
            if word_boundary_before(hay, pos) && word_boundary_after(hay, pos, 5) {
                out.constructs.0 |= ConstructFlags::SQL_UNION;
                push_evidence(&mut out.evidence, hay, pos, 5);
            }
        });
        if out.constructs.0 & ConstructFlags::SQL_UNION != 0 {
            return;
        }
    }
}

fn detect_tautology(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    const PATTERNS: &[&[u8]] = &[
        b"or 1=1",
        b"or '1'='1",
        b"or \"1\"=\"1",
        b"and 1=1",
        b"or true",
        b"and true",
        b"'='",
        b"\"=\"",
    ];
    for hay in [orig, norm] {
        for pat in PATTERNS {
            if let Some(pos) = find_ignore_ascii_case(hay, pat) {
                out.constructs.0 |= ConstructFlags::SQL_TAUTOLOGY;
                push_evidence(&mut out.evidence, hay, pos, pat.len());
                return;
            }
        }
    }
}

fn detect_string_break(orig: &[u8], out: &mut SqliClassifyResult) {
    const PATTERNS: &[&[u8]] = &[b"' or", b"\" or", b"';", b"\";--", b"'--", b"\"--"];
    for pat in PATTERNS {
        if let Some(pos) = find_ignore_ascii_case(orig, pat) {
            out.constructs.0 |= ConstructFlags::SQL_STRING_BREAK;
            push_evidence(&mut out.evidence, orig, pos, pat.len());
            return;
        }
    }
}

fn detect_stacked(orig: &[u8], norm: &[u8], tokens: &TokenBuf, out: &mut SqliClassifyResult) {
    const VERBS: &[&[u8]] = &[
        b"select", b"insert", b"update", b"delete", b"drop", b"create", b"alter", b"exec",
    ];
    let semicolon = tokens
        .slots
        .iter()
        .take(usize::from(tokens.count))
        .any(|t| t.kind == TokenKind::Semicolon)
        || orig.contains(&b';');
    if !semicolon {
        return;
    }
    for hay in [orig, norm] {
        for verb in VERBS {
            if let Some(pos) = find_ignore_ascii_case(hay, verb)
                && word_boundary_before(hay, pos)
                && word_boundary_after(hay, pos, verb.len())
            {
                out.constructs.0 |= ConstructFlags::SQL_STACKED_QUERY;
                push_evidence(&mut out.evidence, hay, pos, verb.len());
                return;
            }
        }
    }
}

fn detect_comments(orig: &[u8], out: &mut SqliClassifyResult) {
    if find_ignore_ascii_case(orig, b"--").is_some()
        || orig.contains(&b'#')
        || find_ignore_ascii_case(orig, b"/*").is_some()
    {
        out.constructs.0 |= ConstructFlags::SQL_COMMENT_INJECTION;
        if let Some(pos) = find_ignore_ascii_case(orig, b"--") {
            push_evidence(&mut out.evidence, orig, pos, 2);
        } else if let Some(pos) = orig.iter().position(|&b| b == b'#') {
            push_evidence(&mut out.evidence, orig, pos, 1);
        }
    }
}

fn detect_functions(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    const FUNCS: &[&[u8]] = &[
        b"sleep(",
        b"benchmark(",
        b"load_file(",
        b"xp_cmdshell",
        b"waitfor delay",
        b"extractvalue(",
        b"updatexml(",
        b"pg_sleep(",
    ];
    for hay in [orig, norm] {
        for func in FUNCS {
            if let Some(pos) = find_ignore_ascii_case(hay, func) {
                out.constructs.0 |= ConstructFlags::SQL_FUNCTION_CALL;
                push_evidence(&mut out.evidence, hay, pos, func.len());
                return;
            }
        }
    }
}

fn detect_boolean_blind(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b" and ", |pos| {
            if has_comparison_near(hay, pos + 5) {
                out.constructs.0 |= ConstructFlags::SQL_BOOLEAN_BLIND;
                push_evidence(&mut out.evidence, hay, pos, 5);
            }
        });
        for_each_ignore_ascii_case(hay, b" or ", |pos| {
            if has_comparison_near(hay, pos + 4) {
                out.constructs.0 |= ConstructFlags::SQL_BOOLEAN_BLIND;
                push_evidence(&mut out.evidence, hay, pos, 4);
            }
        });
        if out.constructs.0 & ConstructFlags::SQL_BOOLEAN_BLIND != 0 {
            return;
        }
    }
}

fn has_comparison_near(hay: &[u8], start: usize) -> bool {
    let end = start.saturating_add(12).min(hay.len());
    let slice = hay.get(start..end).unwrap_or(&[]);
    slice.contains(&b'=') || find_ignore_ascii_case(slice, b"like").is_some()
}

fn detect_keyword_chain(orig: &[u8], norm: &[u8], out: &mut SqliClassifyResult) {
    for hay in [orig, norm] {
        if let Some(sel) = find_ignore_ascii_case(hay, b"select") {
            let after = sel.saturating_add(6);
            let tail = hay.get(after..).unwrap_or(&[]);
            if find_ignore_ascii_case(tail, b"from").is_some() {
                out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
                push_evidence(&mut out.evidence, hay, sel, 6);
                return;
            }
        }
        if find_ignore_ascii_case(hay, b"union").is_some() && find_ignore_ascii_case(hay, b"select").is_some() {
            out.constructs.0 |= ConstructFlags::SQL_KEYWORD_CHAIN;
            return;
        }
    }
}

fn detect_dialect(orig: &[u8], out: &mut SqliClassifyResult) {
    if orig.contains(&b'`') {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if orig.contains(&b'#') {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MYSQL;
        out.dialect = SqlDialect::Mysql;
    }
    if orig.contains(&b'[') && orig.contains(&b']') {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_MSSQL;
        out.dialect = SqlDialect::Mssql;
    }
    if find_ignore_ascii_case(orig, b" dual").is_some() || find_ignore_ascii_case(orig, b"q'").is_some() {
        out.constructs.0 |= ConstructFlags::SQL_DIALECT_ORACLE;
        out.dialect = SqlDialect::Oracle;
    }
}

fn infer_quote_mode(orig: &[u8]) -> SqliQuoteMode {
    if orig.contains(&b'\'') {
        SqliQuoteMode::Single
    } else if orig.contains(&b'"') {
        SqliQuoteMode::Double
    } else if orig.contains(&b'`') {
        SqliQuoteMode::Backtick
    } else {
        SqliQuoteMode::None
    }
}

fn push_evidence(evidence: &mut EvidenceSet, hay: &[u8], pos: usize, len: usize) {
    if usize::from(evidence.count) >= MAX_EVIDENCE {
        return;
    }
    let offset = u16::try_from(pos).unwrap_or(u16::MAX);
    let span_len = u16::try_from(len.min(hay.len().saturating_sub(pos))).unwrap_or(u16::MAX);
    let idx = usize::from(evidence.count);
    if let Some(slot) = evidence.spans.get_mut(idx) {
        *slot = EvidenceSpan { offset, len: span_len };
        evidence.count = evidence.count.saturating_add(1);
    }
}
