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

use super::deny_list::{DENY_ATTRS, DENY_EVENTS, DENY_TAGS, DENY_URL_PREFIXES};

/// Go `attributeType*` (libinjection-go).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DenyAttrKind {
    /// Not on the deny list.
    None = 0,
    /// Go `attributeTypeBlack` - XSS on the attribute name.
    Deny = 1,
    /// Go `attributeTypeAttrURL` - check value later (`is_deny_url`).
    Url = 2,
    /// Go `attributeTypeStyle` - XSS on the name (`style` / `filter`).
    Style = 3,
    /// Go `attributeTypeAttrIndirect` - value is another attr name.
    Indirect = 4,
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_tag(name: &[u8]) -> bool {
    if DENY_TAGS.iter().any(|t| name.eq_ignore_ascii_case(t)) {
        return true;
    }
    // Go: SVG* / XSL* prefix (length >= 3)
    name.get(..3)
        .is_some_and(|p| p.eq_ignore_ascii_case(b"SVG") || p.eq_ignore_ascii_case(b"XSL"))
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_attr(name: &[u8]) -> DenyAttrKind {
    // Go: XMLNS* / XLINK* -> deny
    if name.len() >= 5
        && (name.get(..5).is_some_and(|p| p.eq_ignore_ascii_case(b"XMLNS"))
            || name.get(..5).is_some_and(|p| p.eq_ignore_ascii_case(b"XLINK")))
    {
        return DenyAttrKind::Deny;
    }

    // Go: ON* -> match suffix against deny events
    if let Some((prefix, rest)) = name.split_at_checked(2)
        && prefix.eq_ignore_ascii_case(b"ON")
        && DENY_EVENTS.iter().any(|ev| rest.eq_ignore_ascii_case(ev))
    {
        return DenyAttrKind::Deny;
    }

    DENY_ATTRS
        .iter()
        .find(|(n, _)| name.eq_ignore_ascii_case(n))
        .map_or(DenyAttrKind::None, |(_, k)| *k)
}

/// verifies if the name from a html tag is inside a deny list
pub(crate) fn is_deny_url(value: &[u8]) -> bool {
    let mut i = 0;
    // Skip leading whitespace / controls / high-bit (Go c <= 32 || c >= 127)
    while let Some(&b) = value.get(i) {
        if b > 32 && b < 127 {
            break;
        }
        i += 1;
    }
    let Some(s) = value.get(i..) else {
        return false;
    };

    DENY_URL_PREFIXES.iter().any(|p| starts_with_ignore_ascii_case(s, p))
}

/// Go XSS checks on `html5TypeTagComment` body.
pub(crate) fn is_deny_comment(body: &[u8]) -> bool {
    // 1) backtick anywhere
    if body.contains(&b'`') {
        return true;
    }

    // 2) IE conditional: len > 3 and "[IF" (ASCII case-insensitive on IF)
    if body.len() > 3 && body.first() == Some(&b'[') && body.get(1..3).is_some_and(|p| p.eq_ignore_ascii_case(b"IF")) {
        return true;
    }

    // 3) XML prefix: len > 3 (Go v0.3.1 off-by-one fix)
    if body.len() > 3 && body.get(..3).is_some_and(|p| p.eq_ignore_ascii_case(b"XML")) {
        return true;
    }

    // 4) IMPORT / ENTITY after uppercase + strip nulls (first 6 meaningful bytes in Go)
    let mut buf = [0_u8; 6];
    let mut n = 0;
    for &b in body {
        if b == 0 {
            continue;
        }
        let Some(slot) = buf.get_mut(n) else {
            break;
        };
        *slot = b.to_ascii_uppercase();
        n += 1;
    }
    let prefix = buf.get(..n).unwrap_or(&[]);
    prefix.starts_with(b"IMPORT") || prefix.starts_with(b"ENTITY")
}

/// verifies if a string starts with a prefix, ignoring the case
fn starts_with_ignore_ascii_case(hay: &[u8], prefix: &[u8]) -> bool {
    hay.get(..prefix.len()).is_some_and(|h| h.eq_ignore_ascii_case(prefix))
}
