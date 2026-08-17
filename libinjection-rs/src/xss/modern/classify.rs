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

//! Stage-1 XSS construct classifiers.

#![allow(clippy::missing_docs_in_private_items, reason = "internal detector helpers")]

use crate::engine::ascii::{find_ignore_ascii_case, for_each_ignore_ascii_case, word_boundary_before};
use crate::engine::normalize::NormView;
use crate::limits::MAX_EVIDENCE;
use crate::snapshot::{ConstructFlags, EvidenceSet, EvidenceSpan, XssHtmlContext};

/// Classification output for one XSS pass.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct XssClassifyResult {
    /// Matched construct bits.
    pub constructs: ConstructFlags,
    /// Evidence spans.
    pub evidence: EvidenceSet,
    /// HTML context hint.
    pub html_context: XssHtmlContext,
}

/// Run XSS construct detectors.
#[must_use]
pub(crate) fn classify(norm: NormView<'_>, html_context: XssHtmlContext) -> XssClassifyResult {
    let mut out = XssClassifyResult {
        html_context,
        ..XssClassifyResult::default()
    };
    let orig = norm.original;
    let norm_bytes = norm.bytes;

    detect_script(orig, norm_bytes, &mut out);
    detect_iframe(orig, norm_bytes, &mut out);
    detect_object(orig, norm_bytes, &mut out);
    detect_svg(orig, norm_bytes, &mut out);
    detect_event_handlers(orig, norm_bytes, &mut out);
    detect_javascript_url(orig, norm_bytes, &mut out);
    detect_data_url(orig, norm_bytes, &mut out);
    detect_expression(orig, norm_bytes, &mut out);
    detect_comment_bypass(orig, &mut out);
    detect_doctype(orig, norm_bytes, &mut out);
    out
}

fn detect_script(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        for_each_ignore_ascii_case(hay, b"<script", |pos| {
            out.constructs.0 |= ConstructFlags::XSS_TAG_SCRIPT;
            push_evidence(&mut out.evidence, hay, pos, 7);
        });
        if out.constructs.0 & ConstructFlags::XSS_TAG_SCRIPT != 0 {
            return;
        }
    }
}

fn detect_iframe(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if find_ignore_ascii_case(hay, b"<iframe").is_some() {
            out.constructs.0 |= ConstructFlags::XSS_TAG_IFRAME;
            return;
        }
    }
}

fn detect_object(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if find_ignore_ascii_case(hay, b"<object").is_some() {
            out.constructs.0 |= ConstructFlags::XSS_TAG_OBJECT;
            return;
        }
    }
}

fn detect_svg(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if find_ignore_ascii_case(hay, b"<svg").is_some() {
            out.constructs.0 |= ConstructFlags::XSS_TAG_SVG;
            return;
        }
    }
}

fn detect_event_handlers(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    const EVENTS: &[&[u8]] = &[
        b"onerror",
        b"onload",
        b"onclick",
        b"onmouseover",
        b"onfocus",
        b"onblur",
        b"onchange",
        b"onsubmit",
    ];
    for hay in [orig, norm] {
        for ev in EVENTS {
            for_each_ignore_ascii_case(hay, ev, |pos| {
                if word_boundary_before(hay, pos) {
                    out.constructs.0 |= ConstructFlags::XSS_EVENT_HANDLER;
                    push_evidence(&mut out.evidence, hay, pos, ev.len());
                }
            });
        }
        if out.constructs.0 & ConstructFlags::XSS_EVENT_HANDLER != 0 {
            return;
        }
    }
}

fn detect_javascript_url(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"javascript:") {
            out.constructs.0 |= ConstructFlags::XSS_URL_JAVASCRIPT;
            push_evidence(&mut out.evidence, hay, pos, 11);
            return;
        }
    }
}

fn detect_data_url(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"data:text/html") {
            out.constructs.0 |= ConstructFlags::XSS_URL_DATA;
            push_evidence(&mut out.evidence, hay, pos, 14);
            return;
        }
        if let Some(pos) = find_ignore_ascii_case(hay, b"data:")
            && word_boundary_before(hay, pos)
        {
            out.constructs.0 |= ConstructFlags::XSS_URL_DATA;
            push_evidence(&mut out.evidence, hay, pos, 5);
            return;
        }
    }
}

fn detect_expression(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if find_ignore_ascii_case(hay, b"expression(").is_some() {
            out.constructs.0 |= ConstructFlags::XSS_STYLE_EXPRESSION;
            return;
        }
    }
}

fn detect_comment_bypass(orig: &[u8], out: &mut XssClassifyResult) {
    if find_ignore_ascii_case(orig, b"<!--").is_some() || find_ignore_ascii_case(orig, b"<![cdata[").is_some() {
        out.constructs.0 |= ConstructFlags::XSS_COMMENT_BYPASS;
    }
}

fn detect_doctype(orig: &[u8], norm: &[u8], out: &mut XssClassifyResult) {
    for hay in [orig, norm] {
        if let Some(pos) = find_ignore_ascii_case(hay, b"<!doctype") {
            out.constructs.0 |= ConstructFlags::XSS_DOCTYPE;
            push_evidence(&mut out.evidence, hay, pos, 9);
            return;
        }
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

/// Infer HTML context from entry hint and input shape.
#[must_use]
pub(crate) fn infer_html_context(input: &[u8]) -> XssHtmlContext {
    if input.starts_with(b"\"") {
        XssHtmlContext::AttrDouble
    } else if input.starts_with(b"'") {
        XssHtmlContext::AttrSingle
    } else if input.starts_with(b"`") {
        XssHtmlContext::AttrBacktick
    } else if input.contains(&b'=') && !input.contains(&b'<') {
        XssHtmlContext::AttrUnquoted
    } else {
        XssHtmlContext::Data
    }
}
