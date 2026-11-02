// Copyright Coraza Kubernetes Operator contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Temporary Stage A lifecycle probe; observed contracts are recorded in the evidence document.

use std::cell::Cell;

use envoy_proxy_dynamic_modules_rust_sdk::{
    abi::{
        envoy_dynamic_module_type_on_http_filter_local_reply_status as LocalReplyStatus,
        envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as RequestHeadersStatus,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailersStatus,
        envoy_dynamic_module_type_on_http_filter_response_body_status as ResponseBodyStatus,
        envoy_dynamic_module_type_on_http_filter_response_headers_status as ResponseHeadersStatus,
        envoy_dynamic_module_type_on_http_filter_response_trailers_status as ResponseTrailersStatus,
    },
    CatchUnwind, EnvoyBuffer, EnvoyHttpFilter, EnvoyHttpFilterScheduler as _, EnvoyMutBuffer, HttpFilter,
    HttpFilterConfig,
};

/// Buffer bound requested by the limit-overflow probe.
const BUFFER_LIMIT: u64 = 32;
/// Scheduled event used to continue a held request.
const CONTINUE_EVENT: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Lifecycle behavior selected by the probe header.
enum ProbeMode {
    /// No special behavior.
    Pass,
    /// Hold request headers and continue from a scheduled event.
    Hold,
    /// Buffer successive request-body frames through body EOS.
    Body,
    /// Buffer request-body frames through trailer EOS.
    Trailer,
    /// Send a request-side local denial.
    Deny,
    /// Replace the upstream response on the encode path.
    Replace,
    /// Set a small host buffer limit and retain body data.
    Limit,
    /// Panic on the request path when the opt-in feature is enabled.
    PanicRequest,
    /// Panic on the response path when the opt-in feature is enabled.
    PanicResponse,
}

impl ProbeMode {
    /// Maps a request probe header to its fixed behavior.
    fn from_header(value: Option<EnvoyBuffer<'_>>) -> Self {
        if let Some(value) = value {
            let value = value.as_slice();
            if value == b"hold" {
                return Self::Hold;
            }
            if value == b"body" {
                return Self::Body;
            }
            if value == b"trailer" {
                return Self::Trailer;
            }
            if value == b"deny" {
                return Self::Deny;
            }
            if value == b"replace" {
                return Self::Replace;
            }
            if value == b"limit" {
                return Self::Limit;
            }
            if value == b"panic" {
                return Self::PanicRequest;
            }
            if value == b"panic-response" {
                return Self::PanicResponse;
            }
        }
        Self::Pass
    }
}

/// Minimal factory config for the Stage A lifecycle probe.
pub(crate) struct ProbeConfig;

impl<EHF: EnvoyHttpFilter> HttpFilterConfig<EHF> for ProbeConfig {
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(CatchUnwind::new(ProbeFilter::new()))
    }
}

/// Per-stream state; interior mutability permits SDK `&self` callback re-entry.
struct ProbeFilter {
    /// Behavior selected by request headers.
    mode: Cell<ProbeMode>,
    /// Monotonic callback index used in host logs.
    event_number: Cell<u32>,
    /// Whether the request-header hook is currently on the stack.
    in_request_headers: Cell<bool>,
    /// Whether the response-header hook is currently on the stack.
    in_response_headers: Cell<bool>,
    /// Whether a terminal local reply or replacement has been selected.
    terminal: Cell<bool>,
}

impl ProbeFilter {
    /// Creates a pass-through probe with empty stream state.
    fn new() -> Self {
        Self {
            mode: Cell::new(ProbeMode::Pass),
            event_number: Cell::new(0),
            in_request_headers: Cell::new(false),
            in_response_headers: Cell::new(false),
            terminal: Cell::new(false),
        }
    }

    /// Advances the callback index without wrapping.
    fn next_event(&self) -> u32 {
        let next = self.event_number.get().saturating_add(1);
        self.event_number.set(next);
        next
    }

    /// Captures the current and cumulative request-body views before logging.
    fn observe_body(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) {
        let event_number = self.next_event();
        let received = summarize_body(envoy.get_received_request_body());
        let buffered = summarize_body(envoy.get_buffered_request_body());
        let received_size = envoy.get_received_request_body_size();
        let buffered_size = envoy.get_buffered_request_body_size();
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
            "coraza-dynamic-probe event={event_number} callback=request_body mode={:?} eos={end_of_stream} received_size={received_size} received={received} buffered_size={buffered_size} buffered={buffered}",
            self.mode.get(),
        );
    }

    /// Captures the buffered request body at trailer EOS.
    fn observe_trailers(&self, envoy: &mut impl EnvoyHttpFilter) {
        let event_number = self.next_event();
        let buffered = summarize_body(envoy.get_buffered_request_body());
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
            "coraza-dynamic-probe event={event_number} callback=request_trailers mode={:?} buffered={buffered}",
            self.mode.get(),
        );
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for ProbeFilter {
    fn on_request_headers(&self, envoy: &mut EHF, _end_of_stream: bool) -> RequestHeadersStatus {
        let mode = ProbeMode::from_header(envoy.get_request_header_value("x-coraza-probe"));
        self.mode.set(mode);
        let event_number = self.next_event();
        self.in_request_headers.set(true);
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
            "coraza-dynamic-probe event={event_number} callback=request_headers mode={mode:?}"
        );

        #[cfg(feature = "panic-probe")]
        if mode == ProbeMode::PanicRequest {
            panic!("feature-gated request panic probe");
        }

        match mode {
            ProbeMode::Hold => {
                envoy.new_scheduler().commit(CONTINUE_EVENT);
                self.in_request_headers.set(false);
                RequestHeadersStatus::StopIteration
            },
            ProbeMode::Deny => {
                self.terminal.set(true);
                envoy.send_response(
                    403,
                    &[("content-type", b"text/plain")],
                    Some(b"probe denied"),
                    Some("coraza_dynamic_probe_deny"),
                );
                self.in_request_headers.set(false);
                RequestHeadersStatus::StopIteration
            },
            ProbeMode::Limit => {
                let previous = envoy.get_buffer_limit();
                envoy.set_buffer_limit(BUFFER_LIMIT);
                let current = envoy.get_buffer_limit();
                envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
                    "coraza-dynamic-probe buffer_limit previous={previous} requested={BUFFER_LIMIT} current={current} headers_held=true"
                );
                self.in_request_headers.set(false);
                RequestHeadersStatus::StopIteration
            },
            _ => {
                self.in_request_headers.set(false);
                RequestHeadersStatus::Continue
            },
        }
    }

    fn on_request_body(&self, envoy: &mut EHF, end_of_stream: bool) -> RequestBodyStatus {
        self.observe_body(envoy, end_of_stream);
        if self.mode.get() == ProbeMode::Limit {
            return RequestBodyStatus::StopIterationAndBuffer;
        }
        if matches!(self.mode.get(), ProbeMode::Body | ProbeMode::Trailer) {
            if end_of_stream && self.mode.get() == ProbeMode::Body {
                RequestBodyStatus::Continue
            } else {
                RequestBodyStatus::StopIterationAndBuffer
            }
        } else {
            RequestBodyStatus::Continue
        }
    }

    fn on_request_trailers(&self, envoy: &mut EHF) -> RequestTrailersStatus {
        self.observe_trailers(envoy);
        RequestTrailersStatus::Continue
    }

    fn on_response_headers(&self, envoy: &mut EHF, _end_of_stream: bool) -> ResponseHeadersStatus {
        if self.mode.get() == ProbeMode::PanicResponse {
            #[cfg(feature = "panic-probe")]
            panic!("feature-gated response panic probe");
        }
        if self.mode.get() == ProbeMode::Replace {
            self.terminal.set(true);
            self.in_response_headers.set(true);
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
                "coraza-dynamic-probe callback=response_headers action=replace"
            );
            envoy.send_response(
                200,
                &[("content-type", b"text/plain")],
                Some(b"replacement response"),
                Some("coraza_dynamic_probe_replace"),
            );
            self.in_response_headers.set(false);
            return ResponseHeadersStatus::StopIteration;
        }
        ResponseHeadersStatus::Continue
    }

    fn on_response_body(&self, _envoy: &mut EHF, _end_of_stream: bool) -> ResponseBodyStatus {
        ResponseBodyStatus::Continue
    }

    fn on_response_trailers(&self, _envoy: &mut EHF) -> ResponseTrailersStatus {
        ResponseTrailersStatus::Continue
    }

    fn on_local_reply(
        &self,
        _envoy: &mut EHF,
        response_code: u32,
        _details: EnvoyBuffer<'_>,
        _reset_imminent: bool,
    ) -> LocalReplyStatus {
        let event_number = self.next_event();
        envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
            "coraza-dynamic-probe event={event_number} callback=local_reply status={response_code} nested_request_headers={} nested_response_headers={} terminal={}",
            self.in_request_headers.get(),
            self.in_response_headers.get(),
            self.terminal.get(),
        );
        LocalReplyStatus::Continue
    }

    fn on_scheduled(&self, envoy: &mut EHF, event_id: u64) {
        if event_id == CONTINUE_EVENT && self.mode.get() == ProbeMode::Hold {
            let event_number = self.next_event();
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_info!(
                "coraza-dynamic-probe event={event_number} callback=scheduled action=continue_decoding"
            );
            envoy.continue_decoding();
        }
    }
}

/// Summarizes borrowed body fragments without retaining Envoy-owned views.
fn summarize_body(buffers: Option<Vec<EnvoyMutBuffer<'_>>>) -> String {
    match buffers {
        Some(buffers) => {
            let total = buffers
                .iter()
                .fold(0_usize, |sum, buffer| sum.saturating_add(buffer.as_slice().len()));
            if total > 128 {
                format!(
                    "fragment_lengths={:?} total_bytes={total}",
                    buffers.iter().map(|buffer| buffer.as_slice().len()).collect::<Vec<_>>()
                )
            } else {
                format!("{:?}", buffers.iter().map(EnvoyMutBuffer::as_slice).collect::<Vec<_>>())
            }
        },
        None => "unavailable".to_owned(),
    }
}

/// Accepts UTF-8 JSON objects without imposing a Stage A policy schema.
pub(crate) fn validate_config(bytes: &[u8]) -> Result<(), &'static str> {
    let config = std::str::from_utf8(bytes).map_err(|_error| "configuration is not valid UTF-8")?;
    let value: serde_json::Value = serde_json::from_str(config).map_err(|_error| "configuration is not valid JSON")?;
    if !value.is_object() {
        return Err("configuration must be a JSON object");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_config;

    #[test]
    fn accepts_json_objects_only() {
        assert!(validate_config(br#"{"probe":true}"#).is_ok());
        assert!(validate_config(b"[]").is_err());
        assert!(validate_config(b"not json").is_err());
        assert!(validate_config(&[0xFF]).is_err());
    }
}
