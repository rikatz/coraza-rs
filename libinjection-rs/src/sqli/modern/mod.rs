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

//! Stage-1 `SQLi` analysis (construct flags, zero heap).

mod classify;

use crate::engine::normalize::normalize;
use crate::engine::prefilter::sqli_may_be_interesting;
use crate::engine::token::tokenize;
use crate::engine::verdict::verdict_hint;
use crate::limits::NORM_BUF_LEN;
use crate::options::AnalyzeOptions;
use crate::policy;
use crate::snapshot::{AnalysisContext, AnalysisFlags, AnalysisSnapshot, LegacyFingerprint, XssHtmlContext};

use classify::classify;

/// Analyze one input slice (caller applies scan budget).
#[must_use]
pub(crate) fn analyze(input: &[u8], _opts: AnalyzeOptions) -> AnalysisSnapshot {
    if input.is_empty() {
        return AnalysisSnapshot::benign();
    }
    if !sqli_may_be_interesting(input) {
        return AnalysisSnapshot {
            flags: AnalysisFlags(AnalysisFlags::PREFILTER_MISS),
            ..AnalysisSnapshot::benign()
        };
    }

    let mut norm_buf = [0_u8; NORM_BUF_LEN];
    let norm = normalize(input, &mut norm_buf);
    let tokens = tokenize(norm.original);

    let classified = classify(norm, &tokens);

    let mut flags = AnalysisFlags::empty();
    if norm.norm_truncated {
        flags.0 |= AnalysisFlags::TRUNCATED;
    }
    if tokens.limit_hit {
        flags.0 |= AnalysisFlags::TOKEN_LIMIT;
    }

    let verdict_hint = verdict_hint(classified.constructs, flags, policy::BUILTIN_SQLI_DETECT);

    AnalysisSnapshot {
        constructs: classified.constructs,
        flags,
        verdict_hint,
        context: AnalysisContext {
            sqli_quote_mode: classified.quote_mode,
            xss_html_context: XssHtmlContext::Data,
            dialect: classified.dialect,
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
    fn prefilter_miss_is_benign() {
        let snap = analyze(b"hello", AnalyzeOptions::default());
        assert!(snap.flags.contains(AnalysisFlags::PREFILTER_MISS));
        assert_eq!(snap.verdict_hint, VerdictHint::Benign);
    }

    #[test]
    fn union_injection_sets_construct() {
        let snap = analyze(b"1' UNION SELECT null--", AnalyzeOptions::default());
        assert!(snap.constructs.intersects(ConstructFlags(ConstructFlags::SQL_UNION)));
        assert!(snap.constructs.any_sqli());
    }

    #[test]
    fn classic_tautology_detected() {
        let snap = analyze(b"1' OR '1'='1", AnalyzeOptions::default());
        assert!(snap.constructs.intersects(ConstructFlags(
            ConstructFlags::SQL_TAUTOLOGY | ConstructFlags::SQL_STRING_BREAK
        )));
    }
}
