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

//! Parser for libinjection-go sectioned corpus files.

use std::fs;
use std::path::Path;

/// One corpus fixture after parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CorpusCase {
    /// Filename stem, e.g. `test-folding-001`.
    pub(crate) name: String,
    /// Text from the `--TEST--` section.
    pub(crate) description: String,
    /// Body of `--INPUT--` (after right-trim rules).
    pub(crate) input: String,
    /// Body of `--EXPECTED--` (after right-trim rules).
    pub(crate) expected: String,
}

/// Failure while reading or interpreting a corpus file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParseError {
    /// Filesystem / UTF-8 read failure (message is enough for tests).
    Io(String),
    /// A required section marker was missing or out of order.
    MissingSection {
        /// Which marker we expected, e.g. `--INPUT--`.
        marker: &'static str,
    },
    /// File content was empty or had no usable sections.
    Empty,
}

/// Which legacy corpus driver should run this fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverKind {
    /// `test-sqli-*.txt` - fingerprint / `IsSQLi`.
    Sqli,
    /// `test-folding-*.txt` - folded tokens.
    Folding,
    /// `test-tokens-*.txt` - raw ANSI tokenize (incl. `tokens_mysql` if you fold that in later).
    Tokens,
    /// `test-html5-*.txt` - HTML5 tokenizer dump.
    Html5,
    /// `test-xss-*.txt` - `IsXSS` -> `1` / `0`.
    Xss,
}

impl DriverKind {
    /// Classify a corpus stem such as `test-folding-001`.
    #[must_use]
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        match name {
            n if n.starts_with("test-sqli-") => Some(Self::Sqli),
            n if n.starts_with("test-folding-") => Some(Self::Folding),
            n if n.starts_with("test-tokens-") => Some(Self::Tokens),
            n if n.starts_with("test-html5-") => Some(Self::Html5),
            n if n.starts_with("test-xss-") => Some(Self::Xss),
            _ => None,
        }
    }
}

/// Possible Sections of a corpus test file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Test,
    Input,
    Expected,
}

/// Trim trailing ASCII whitespace from a line (` `, `\t`, `\r`).
///
/// Does **not** trim the left side. Matches libinjection-go / C testdriver.
#[must_use]
pub(crate) fn right_trim_line(line: &str) -> &str {
    // We do not use trim_end here to keep contract with the migration
    line.trim_end_matches([' ', '\t', '\r'])
}

/// Parse one corpus file's text into a [`CorpusCase`].
///
/// `name` is the filename stem (e.g. `test-folding-001`).
pub(crate) fn parse_corpus_str(name: &str, contents: &str) -> Result<CorpusCase, ParseError> {
    if contents.is_empty() {
        return Err(ParseError::Empty);
    }

    let mut current: Option<Section> = None;
    let mut seen_test = false;
    let mut seen_input = false;
    let mut seen_expected = false;

    let mut description_lines: Vec<String> = Vec::new();
    let mut input_lines: Vec<String> = Vec::new();
    let mut expected_lines: Vec<String> = Vec::new();

    for raw_line in contents.lines() {
        let line = right_trim_line(raw_line);

        match line {
            "--TEST--" => {
                if seen_test || seen_input || seen_expected {
                    return Err(ParseError::MissingSection { marker: "--TEST--" });
                }
                seen_test = true;
                current = Some(Section::Test);
            },
            "--INPUT--" => {
                if !seen_test || seen_input || seen_expected {
                    return Err(ParseError::MissingSection { marker: "--INPUT--" });
                }
                seen_input = true;
                current = Some(Section::Input);
            },
            "--EXPECTED--" => {
                if !seen_test || !seen_input || seen_expected {
                    return Err(ParseError::MissingSection { marker: "--EXPECTED--" });
                }
                seen_expected = true;
                current = Some(Section::Expected);
            },
            _ => {
                let Some(section) = current else {
                    // Text before any marker.
                    return Err(ParseError::MissingSection { marker: "--TEST--" });
                };
                match section {
                    Section::Test => description_lines.push(line.to_owned()),
                    Section::Input => input_lines.push(line.to_owned()),
                    Section::Expected => expected_lines.push(line.to_owned()),
                }
            },
        }
    }

    if !seen_test {
        return Err(ParseError::MissingSection { marker: "--TEST--" });
    }
    if !seen_input {
        return Err(ParseError::MissingSection { marker: "--INPUT--" });
    }
    if !seen_expected {
        return Err(ParseError::MissingSection { marker: "--EXPECTED--" });
    }

    Ok(CorpusCase {
        name: name.to_owned(),
        description: trim_section_trailing_ws(&join_lines(&description_lines)),
        input: trim_section_trailing_ws(&join_lines(&input_lines)),
        expected: trim_section_trailing_ws(&join_lines(&expected_lines)),
    })
}

/// Right-trim section bodies (Go `readTestData` + `modp_rtrim` on `--INPUT--` / `--EXPECTED--`).
fn trim_section_trailing_ws(s: &str) -> String {
    s.trim_end_matches([' ', '\t', '\r', '\n']).to_owned()
}

/// Read `path` and parse it as one corpus fixture.
pub(crate) fn parse_corpus_file(path: &Path) -> Result<CorpusCase, ParseError> {
    let contents = fs::read_to_string(path).map_err(|err| ParseError::Io(err.to_string()))?;

    let name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| ParseError::Io(format!("bad corpus path: {}", path.display())))?;

    parse_corpus_str(name, &contents)
}

fn join_lines(lines: &[String]) -> String {
    lines.join("\n")
}
