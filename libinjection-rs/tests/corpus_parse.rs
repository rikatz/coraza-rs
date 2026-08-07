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

//! Smoke tests for the corpus file parser.
#![expect(clippy::tests_outside_test_module, reason = "integration test binary")]
#![expect(clippy::unwrap_used, reason = "tests")]
#![expect(clippy::panic, reason = "tests")]
#![expect(clippy::print_stderr, reason = "baseline pass/fail reporting")]

mod common;

use common::corpus::{CorpusCase, DriverKind, ParseError, parse_corpus_file, parse_corpus_str, right_trim_line};
use common::drivers::{
    actual_folding_output, actual_html5_output, actual_sqli_output, actual_tokens_output, actual_xss_output,
    run_baseline,
};
use std::{fs, path::Path};

#[test]
fn corpus_case_can_be_constructed() {
    let case = CorpusCase {
        name: "test-folding-001".into(),
        description: "strings are merged".into(),
        input: "SELECT 1".into(),
        expected: "E SELECT".into(),
    };
    assert_eq!(case.name, "test-folding-001");
    assert!(case.expected.contains("SELECT"));
}

#[test]
fn parse_error_can_be_constructed() {
    assert_eq!(ParseError::Io("boom".into()), ParseError::Io("boom".into()));
    assert_eq!(
        ParseError::MissingSection { marker: "--INPUT--" },
        ParseError::MissingSection { marker: "--INPUT--" }
    );
    assert_eq!(ParseError::Empty, ParseError::Empty);
}

#[test]
fn right_trim_keeps_leading_spaces() {
    assert_eq!(right_trim_line("  foo  "), "  foo");
}

#[test]
fn right_trim_strips_cr_and_tabs() {
    assert_eq!(right_trim_line("bar\t\r"), "bar");
}

#[test]
fn right_trim_leaves_internal_spaces() {
    assert_eq!(right_trim_line("<foo  bar  "), "<foo  bar");
}

#[test]
fn parse_minimal_fixture() {
    let contents = "\
--TEST--
desc
--INPUT--
SELECT 1
--EXPECTED--
E SELECT
";
    let case = parse_corpus_str("test-x", contents).unwrap();
    assert_eq!(case.name, "test-x");
    assert_eq!(case.description, "desc");
    assert_eq!(case.input, "SELECT 1");
    assert_eq!(case.expected, "E SELECT");
}

#[test]
fn parse_empty_expected_ok() {
    let contents = "\
--TEST--
sqli
--INPUT--
foo
--EXPECTED--
";
    let case = parse_corpus_str("test-sqli-001", contents).unwrap();
    assert_eq!(case.input, "foo");
    assert_eq!(case.expected, "");
}

#[test]
fn parse_missing_input_errors() {
    let contents = "\
--TEST--
only test
--EXPECTED--
1
";
    assert!(matches!(
        parse_corpus_str("bad", contents),
        Err(ParseError::MissingSection { .. })
    ));
}

#[test]
fn parse_real_folding_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-folding-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(case.name, "test-folding-001");
    assert!(case.input.contains("SELECT"));
    assert!(!case.expected.is_empty());
}

#[test]
fn all_corpus_files_parse() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    let mut count = 0_usize;
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(name.starts_with("test-") && name.ends_with(".txt")) {
            continue;
        }
        parse_corpus_file(&path).unwrap_or_else(|err| {
            panic!("failed to parse {}: {err:?}", path.display());
        });
        count += 1;
    }
    assert!(count >= 490, "expected ~496 fixtures, got {count}");
}

#[test]
fn driver_kind_can_be_constructed() {
    assert_eq!(DriverKind::Folding, DriverKind::Folding);
    assert_eq!(DriverKind::Html5, DriverKind::Html5);
    assert_eq!(DriverKind::Sqli, DriverKind::Sqli);
    assert_eq!(DriverKind::Tokens, DriverKind::Tokens);
    assert_eq!(DriverKind::Xss, DriverKind::Xss);
}

#[test]
fn driver_kind_from_name_examples() {
    assert_eq!(DriverKind::from_name("test-sqli-001"), Some(DriverKind::Sqli));
    assert_eq!(DriverKind::from_name("test-sqli-1e-001"), Some(DriverKind::Sqli));
    assert_eq!(DriverKind::from_name("test-folding-001"), Some(DriverKind::Folding));
    assert_eq!(DriverKind::from_name("test-tokens-words-002"), Some(DriverKind::Tokens));
    assert_eq!(DriverKind::from_name("test-html5-012"), Some(DriverKind::Html5));
    assert_eq!(DriverKind::from_name("test-xss-001"), Some(DriverKind::Xss));
    assert_eq!(DriverKind::from_name("README"), None);
}

#[test]
fn every_corpus_file_has_a_driver_kind() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus");
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let Some(filename) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !(filename.starts_with("test-") && filename.ends_with(".txt")) {
            continue;
        }
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap();
        assert!(DriverKind::from_name(stem).is_some(), "no DriverKind for {stem}");
    }
}

#[test]
fn xss_driver_detects_script_fixture() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-xss-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Xss));

    let actual = actual_xss_output(&case.input);
    assert_eq!(actual, "1");
    assert_eq!(actual, case.expected);
}

#[test]
fn sqli_driver_stub_on_sqli_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-sqli-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Sqli));
    let actual = actual_sqli_output(&case.input);
    assert_eq!(actual, "");
    assert_eq!(actual, case.expected); // this fixture is benign / empty expected
}

#[test]
fn folding_corpus_baseline_stub() {
    let (passed, failed) = run_baseline(DriverKind::Folding, actual_folding_output);
    eprintln!("folding stub baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no folding fixtures found");
}

#[test]
fn html5_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Html5, actual_html5_output);
    eprintln!("html5 baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no HTML5 fixtures found");
    // Intentionally no assert_eq!(failed, 0) yet - climb parity fixture-by-fixture.
}

#[test]
fn sqli_corpus_baseline_stub() {
    let (passed, failed) = run_baseline(DriverKind::Sqli, actual_sqli_output);
    eprintln!("sqli stub baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no SQLi fixtures found");
}

#[test]
fn xss_corpus_baseline() {
    let (passed, failed) = run_baseline(DriverKind::Xss, actual_xss_output);
    eprintln!("xss baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no XSS fixtures found");
    assert_eq!(failed, 0);
}

#[test]
fn html5_driver_on_ascii_word() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-html5-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Html5));

    let actual = actual_html5_output(&case.input);
    assert_eq!(actual, "");
    assert_eq!(case.expected, "DATA_TEXT,3,foo");
    assert_ne!(actual, case.expected);
}

#[test]
fn folding_driver_stub_on_folding_001() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-folding-001.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Folding));

    let actual = actual_folding_output(&case.input);
    assert_eq!(actual, "");
    assert!(case.expected.contains("SELECT"));
    assert_ne!(actual, case.expected);
}

#[test]
fn tokens_driver_stub_on_words_002() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/test-tokens-words-002.txt");
    let case = parse_corpus_file(&path).unwrap();
    assert_eq!(DriverKind::from_name(&case.name), Some(DriverKind::Tokens));

    let actual = actual_tokens_output(&case.input);
    assert_eq!(actual, "");
    assert!(case.expected.contains("SELECT"));
    assert_ne!(actual, case.expected);
}

#[test]
fn tokens_corpus_baseline_stub() {
    let (passed, failed) = run_baseline(DriverKind::Tokens, actual_tokens_output);
    eprintln!("tokens stub baseline: {passed} passed, {failed} failed");
    assert!(passed + failed > 0, "no tokens fixtures found");
}
