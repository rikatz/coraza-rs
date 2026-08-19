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

//! Stage-1 XSS analysis (construct flags, zero heap).

mod classify;

use crate::engine::normalize::normalize;
use crate::engine::prefilter::xss_may_be_interesting;
use crate::engine::verdict::verdict_hint;
use crate::limits::NORM_BUF_LEN;
use crate::options::AnalyzeOptions;
use crate::policy;
use crate::snapshot::{AnalysisContext, AnalysisFlags, AnalysisSnapshot, LegacyFingerprint, SqlDialect, SqliQuoteMode};

use classify::{classify, infer_html_context};

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !xss_may_be_interesting(input) {
        return AnalysisSnapshot {
            flags: AnalysisFlags(AnalysisFlags::PREFILTER_MISS),
            ..AnalysisSnapshot::benign()
        };
    }

    let html_context = infer_html_context(input);
    let mut norm_buf = [0_u8; NORM_BUF_LEN];
    let norm = normalize(input, &mut norm_buf);
    let classified = classify(norm, html_context);

    let mut flags = AnalysisFlags::empty();
    if norm.norm_truncated {
        flags.0 |= AnalysisFlags::TRUNCATED;
    }

    let verdict_hint = verdict_hint(classified.constructs, flags, policy::BUILTIN_XSS_DETECT);

    AnalysisSnapshot {
        constructs: classified.constructs,
        flags,
        verdict_hint,
        context: AnalysisContext {
            sqli_quote_mode: SqliQuoteMode::None,
            xss_html_context: classified.html_context,
            dialect: SqlDialect::Ansi,
        },
        evidence: classified.evidence,
        legacy_fingerprint: LegacyFingerprint::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{ConstructFlags, VerdictHint};

    #[test]
    fn script_tag_sets_construct() {
        let snap = analyze(b"<script>alert(1)</script>", AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_TAG_SCRIPT))
        );
        assert_eq!(snap.verdict_hint, VerdictHint::Decisive);
    }

    #[test]
    fn javascript_url_detected() {
        let snap = analyze(b"javascript:alert(1)", AnalyzeOptions::default());
        assert!(
            snap.constructs
                .intersects(ConstructFlags(ConstructFlags::XSS_URL_JAVASCRIPT))
        );
    }
}
