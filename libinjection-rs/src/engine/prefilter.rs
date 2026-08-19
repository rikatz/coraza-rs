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

//! Fast prefilter: skip obviously benign inputs before normalization.

use crate::engine::ascii::find_ignore_ascii_case;
use memchr::memchr3;

/// True if the input may contain SQLi-relevant bytes.
#[must_use]
pub(crate) fn sqli_may_be_interesting(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    let mut i = 0;
    while i < input.len() {
        let rest = input.get(i..).unwrap_or(&[]);
        let Some(rel) = memchr3(b'\'', b'"', b';', rest) else {
            break;
        };
        let pos = i + rel;
        if input.get(pos).is_some() {
            return true;
        }
        i = pos + 1;
    }
    // Secondary scan for comment/keyword triggers.
    memchr::memchr2(b'-', b'#', input).is_some()
        || memchr::memchr(b'/', input).is_some()
        || memchr::memchr(b'\\', input).is_some()
        || memchr::memchr(b'(', input).is_some()
        || memchr::memchr(b')', input).is_some()
        || memchr::memchr(b'=', input).is_some()
        || find_ignore_ascii_case(input, b"union").is_some()
        || find_ignore_ascii_case(input, b"select").is_some()
        || find_ignore_ascii_case(input, b" or ").is_some()
        || find_ignore_ascii_case(input, b" and ").is_some()
}

/// True if the input may contain XSS-relevant bytes.
#[must_use]
pub(crate) fn xss_may_be_interesting(input: &[u8]) -> bool {
    if input.is_empty() {
        return false;
    }
    memchr::memchr(b'<', input).is_some()
        || memchr::memchr(b'>', input).is_some()
        || memchr::memchr(b'&', input).is_some()
        || memchr::memchr(b'\'', input).is_some()
        || memchr::memchr(b'"', input).is_some()
        || memchr::memchr(b'`', input).is_some()
        || find_ignore_ascii_case(input, b"javascript:").is_some()
        || find_ignore_ascii_case(input, b"data:").is_some()
        || find_ignore_ascii_case(input, b"<script").is_some()
        || find_ignore_ascii_case(input, b"onerror").is_some()
}
