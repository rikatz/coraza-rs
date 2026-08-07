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

//! Corpus driver output formatting (Go encoding).
use libinjection::detect_xss;
use std::fs;
use std::path::Path;

use super::corpus::{DriverKind, parse_corpus_file};

/// Go `IsXSS` corpus encoding: detected -> `"1"`, else `"0"`.
#[must_use]
pub(crate) fn format_xss_expected(detected: bool) -> &'static str {
    if detected { "1" } else { "0" }
}

/// Go `SQLi` corpus encoding: fingerprint text, or empty if not `SQLi`.
#[must_use]
pub(crate) fn format_sqli_expected(fingerprint: Option<&str>) -> String {
    fingerprint.unwrap_or("").to_owned()
}

/// Go HTML5 corpus encoding: one token per line `TYPE,len,text`, joined by `\n`.
///
/// Empty token list → empty string (Go `TrimSpace` on no tokens).
#[must_use]
pub(crate) fn format_html5_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

/// Go tokens corpus encoding: one raw token per line, joined by `\n`.
#[must_use]
pub(crate) fn format_tokens_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

/// Go folding corpus encoding: one folded token per line, joined by `\n`.
#[must_use]
pub(crate) fn format_folding_expected(token_lines: &[String]) -> String {
    token_lines.join("\n")
}

pub(crate) fn actual_folding_output(_input: &str) -> String {
    format_folding_expected(&[])
}

pub(crate) fn actual_xss_output(input: &str) -> String {
    let verdict = detect_xss(input.as_bytes());
    format_xss_expected(verdict.detected).to_owned()
}

pub(crate) fn actual_sqli_output(_input: &str) -> String {
    // Stub: detect_sqli never sets a fingerprint yet.
    format_sqli_expected(None)
}

pub(crate) fn actual_html5_output(_input: &str) -> String {
    format_html5_expected(&[])
}

pub(crate) fn actual_tokens_output(_input: &str) -> String {
    // Stub: no SQL tokenizer yet.
    format_tokens_expected(&[])
}

/// Walk vendored fixtures for `kind`, compare stub/engine output to `--EXPECTED--`.
///
/// Returns `(passed, failed)`.
pub(crate) fn run_baseline(kind: DriverKind, actual: impl Fn(&str) -> String) -> (usize, usize) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut passed = 0_usize;
    let mut failed = 0_usize;

    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(filename.starts_with("test-") && filename.ends_with(".txt")) {
            continue;
        }

        let case = parse_corpus_file(&path).unwrap();
        if DriverKind::from_name(&case.name) != Some(kind) {
            continue;
        }

        if actual(&case.input) == case.expected {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    (passed, failed)
}
