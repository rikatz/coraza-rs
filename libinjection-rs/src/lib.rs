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

#![cfg_attr(not(feature = "std"), no_std)]

//! SQL injection and XSS analysis for WAF hot paths (Coraza).
//!
//! Stage 1 returns a fixed-size [`AnalysisSnapshot`] (zero heap).
//! [`detect_sqli`] / [`detect_xss`] apply a built-in minimal policy for
//! Coraza operators `@detectSQLi` / `@detectXSS`. Scan budget defaults are in
//! [`limits`]; override via [`AnalyzeOptions`] (Coraza policy, not request input).

pub mod error;
pub mod flags;
pub mod limits;
pub mod options;
pub mod snapshot;

mod sqli;
mod xss;

pub use flags::SqliFlags;
pub use limits::{
    ABSOLUTE_MAX_INPUT_LEN, DEEP_MAX_INPUT_LEN, DEFAULT_MAX_INPUT_LEN, MAX_EVIDENCE, MAX_INPUT_LEN, MAX_STACK_BUDGET,
    MAX_TOKEN_SLOTS, NORM_BUF_LEN, clamp_max_input_len,
};
pub use options::AnalyzeOptions;
pub use snapshot::{
    AnalysisContext, AnalysisFlags, AnalysisSnapshot, ConstructFlags, DetectionVerdict, EvidenceSet, EvidenceSpan,
    LegacyFingerprint, SqlDialect, SqliQuoteMode, VerdictHint, XssHtmlContext,
};

/// Primary hot-path `SQLi` analysis.
///
/// Uses [`AnalyzeOptions::default`] (`DEFAULT_MAX_INPUT_LEN`).
#[must_use]
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot {
    analyze_sqli_with(input, AnalyzeOptions::default())
}

/// `SQLi` analysis with a caller scan budget (clamped in Phase 2b).
///
/// Stub: always [`AnalysisSnapshot::benign`].
#[must_use]
pub fn analyze_sqli_with(_input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    AnalysisSnapshot::benign()
}

/// Primary hot-path XSS analysis.
#[must_use]
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot {
    analyze_xss_with(input, AnalyzeOptions::default())
}

/// XSS analysis with a caller scan budget.
///
/// Stub: always [`AnalysisSnapshot::benign`].
#[must_use]
pub fn analyze_xss_with(_input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    AnalysisSnapshot::benign()
}

/// Built-in minimal policy for Coraza `@detectSQLi` (stub: never detects).
#[must_use]
pub fn detect_sqli(input: &[u8]) -> DetectionVerdict {
    detect_sqli_with(input, AnalyzeOptions::default())
}

/// Coraza `@detectSQLi` with caller scan budget (stub).
#[must_use]
pub fn detect_sqli_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict {
    DetectionVerdict {
        detected: false,
        snapshot: analyze_sqli_with(input, opts),
    }
}

/// Built-in minimal policy for Coraza `@detectXSS`
#[must_use]
pub fn detect_xss(input: &[u8]) -> DetectionVerdict {
    detect_xss_with(input, AnalyzeOptions::default())
}

/// Coraza `@detectXSS` with caller scan budget.
#[must_use]
pub fn detect_xss_with(input: &[u8], opts: AnalyzeOptions) -> DetectionVerdict {
    let _ = opts; // scan budget applied when we truncate in a later step
    #[cfg(feature = "legacy")]
    let detected = xss::legacy::detect(input);
    #[cfg(not(feature = "legacy"))]
    let detected = false;

    DetectionVerdict {
        detected,
        snapshot: analyze_xss_with(input, opts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_benign() {
        let sqli = detect_sqli(b"");
        assert!(!sqli.detected);
        assert_eq!(sqli.snapshot.verdict_hint, VerdictHint::Benign);

        let xss = detect_xss(b"");
        assert!(!xss.detected);
        assert_eq!(xss.snapshot.verdict_hint, VerdictHint::Benign);
    }

    #[test]
    fn detect_sqli_still_stub() {
        assert!(!detect_sqli(b"1' OR '1'='1").detected);
    }

    #[test]
    fn detect_xss_flags_deny_script() {
        assert!(detect_xss(b"<script>alert(1)</script>").detected);
    }

    #[test]
    fn analyze_returns_copy_snapshot() {
        let a = analyze_sqli(b"hello");
        let b = a;
        assert_eq!(a, b);
        assert!(!a.constructs.any_sqli());
    }

    #[test]
    fn analyze_options_default_matches_limit() {
        let opts = AnalyzeOptions::default();
        assert_eq!(opts.max_input_len, DEFAULT_MAX_INPUT_LEN);
        assert_eq!(opts.effective_max_input_len(), DEFAULT_MAX_INPUT_LEN);
    }

    #[test]
    fn analyze_options_clamps_to_absolute_max() {
        let opts = AnalyzeOptions::with_max_input_len(usize::MAX);
        assert_eq!(opts.effective_max_input_len(), ABSOLUTE_MAX_INPUT_LEN);
    }
}
