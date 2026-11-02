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

//! Request-side policy selection, body gating and enforcement.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "Private adapter details are documented by their callbacks and enclosing types."
)]

use std::{
    cell::{Cell, RefCell},
    net::{IpAddr, SocketAddr},
    str,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use coraza::{
    transaction::{Interruption, Transaction},
    types::RuleEngineStatus,
};
use envoy_coraza_common::{
    authority::{
        authority_host, find_header, has_unsupported_content_encoding, has_upgrade, headers_within_limits,
        normalize_authority, request_authority, MAX_HEADERS_BYTES, MAX_HEADER_COUNT, MAX_HEADER_VALUE_BYTES,
    },
    policy::{Generation, Policy},
};
use envoy_proxy_dynamic_modules_rust_sdk::{
    abi::{
        envoy_dynamic_module_type_attribute_id as AttributeId,
        envoy_dynamic_module_type_on_http_filter_local_reply_status as LocalReplyStatus,
        envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus,
        envoy_dynamic_module_type_on_http_filter_request_headers_status as RequestHeadersStatus,
        envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailersStatus,
    },
    CatchUnwind, EnvoyBuffer, EnvoyHttpFilter, HttpFilter,
};

/// Hard request body bound, independent of SecLang controls and Envoy limits.
const MAX_REQUEST_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES_U64: u64 = 16 * 1024 * 1024;
/// Aggregate retained body bytes shared by the loaded native module.
const MAX_RETAINED_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Process-wide for this loaded module, across filter configs, generations and workers.
static RETAINED_BODY_BYTES: AtomicUsize = AtomicUsize::new(0);
const EMPTY_BODY: &[u8] = b"";
const REQUEST_DENY_BODY: &[u8] = b"Request denied\n";
const REQUEST_ERROR_BODY: &[u8] = b"Request inspection unavailable\n";
const UNSUPPORTED_BODY: &[u8] = b"Request feature is not supported\n";

type OwnedHeaders = Vec<(String, Vec<u8>)>;
type EnvoyHeaders<'a> = Vec<(EnvoyBuffer<'a>, EnvoyBuffer<'a>)>;

/// One immutable generation-backed filter configuration.
pub(crate) struct FilterConfig {
    generation: Arc<Generation>,
}

impl FilterConfig {
    pub(crate) fn new(generation: Arc<Generation>) -> Self {
        Self { generation }
    }

    fn new_stream(&self) -> RequestFilter {
        RequestFilter::new(Arc::clone(&self.generation))
    }
}

impl<EHF: EnvoyHttpFilter> envoy_proxy_dynamic_modules_rust_sdk::HttpFilterConfig<EHF> for FilterConfig {
    fn new_http_filter(&self, _envoy: &mut EHF) -> Box<dyn HttpFilter<EHF>> {
        Box::new(CatchUnwind::new(self.new_stream()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    New,
    Held,
    Complete,
    Bypassed,
    Terminal,
}

struct StreamState {
    generation: Arc<Generation>,
    stage: Stage,
    transaction: Option<Box<Transaction>>,
    method: String,
    body_access: bool,
    phase2_done: bool,
    body_bytes: usize,
    reservation: BodyReservation,
}

impl StreamState {
    fn new(generation: Arc<Generation>) -> Self {
        Self {
            generation,
            stage: Stage::New,
            transaction: None,
            method: String::new(),
            body_access: false,
            phase2_done: false,
            body_bytes: 0,
            reservation: BodyReservation::default(),
        }
    }
}

/// Per-stream body admission reservation; releasing it is independent of callbacks.
#[derive(Default)]
struct BodyReservation {
    bytes: usize,
}

struct RequestMetadata {
    method: String,
    uri: Vec<u8>,
    protocol: String,
}

impl BodyReservation {
    fn resize(&mut self, target: usize) -> bool {
        if target > self.bytes {
            let additional = target.saturating_sub(self.bytes);
            if !try_reserve(&RETAINED_BODY_BYTES, additional, MAX_RETAINED_BODY_BYTES) {
                return false;
            }
        } else {
            RETAINED_BODY_BYTES.fetch_sub(self.bytes.saturating_sub(target), Ordering::AcqRel);
        }
        self.bytes = target;
        true
    }
}

impl Drop for BodyReservation {
    fn drop(&mut self) {
        RETAINED_BODY_BYTES.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Atomically reserves bytes without a load-then-add race.
fn try_reserve(counter: &AtomicUsize, additional: usize, limit: usize) -> bool {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(additional) else {
            return false;
        };
        if next > limit {
            return false;
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

enum Reply {
    Status { status: u16, body: &'static [u8] },
    Interruption(Interruption),
}

#[derive(Clone, Copy)]
enum HeadersAction {
    Continue,
    Hold,
}

enum BodyAction {
    Continue,
    Buffer,
}

/// One request stream, pinning the generation selected when Envoy creates it.
pub(crate) struct RequestFilter {
    state: RefCell<StreamState>,
    terminal: Cell<bool>,
}

impl RequestFilter {
    fn new(generation: Arc<Generation>) -> Self {
        Self {
            state: RefCell::new(StreamState::new(generation)),
            terminal: Cell::new(false),
        }
    }

    fn reject(&self, envoy: &mut impl EnvoyHttpFilter, status: u16, body: &'static [u8]) {
        self.terminal.set(true);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            state.stage = Stage::Terminal;
        }
        envoy.send_response(
            u32::from(status),
            &[
                ("content-type", b"text/plain; charset=utf-8"),
                ("cache-control", b"no-store"),
            ],
            Some(if self.is_head() { EMPTY_BODY } else { body }),
            Some("coraza_dynamic_request_error"),
        );
    }

    fn is_head(&self) -> bool {
        self.state
            .try_borrow()
            .is_ok_and(|state| state.method.eq_ignore_ascii_case("HEAD"))
    }

    fn send_interruption(&self, envoy: &mut impl EnvoyHttpFilter, interruption: &Interruption) {
        let status = valid_status(interruption.status);
        let redirect = interruption.action == "redirect";
        let no_body_status = matches!(status, 204 | 304);
        let head = self.is_head();
        let mut headers: Vec<(&str, &[u8])> = vec![
            ("content-type", b"text/plain; charset=utf-8"),
            ("cache-control", b"no-store"),
        ];
        if redirect && !interruption.data.is_empty() {
            headers.push(("location", interruption.data.as_bytes()));
        }
        self.terminal.set(true);
        if let Ok(mut state) = self.state.try_borrow_mut() {
            state.stage = Stage::Terminal;
        }
        envoy.send_response(
            u32::from(status),
            &headers,
            Some(if redirect || no_body_status || head {
                EMPTY_BODY
            } else {
                REQUEST_DENY_BODY
            }),
            Some("coraza_dynamic_request_denied"),
        );
    }

    fn fail_closed(&self, envoy: &mut impl EnvoyHttpFilter, reply: Reply) {
        match reply {
            Reply::Status { status, body } => self.reject(envoy, status, body),
            Reply::Interruption(interruption) => self.send_interruption(envoy, &interruption),
        }
    }

    fn on_headers(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) -> Result<HeadersAction, Reply> {
        let mut state = self.state.try_borrow_mut().map_err(|_error| Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        if state.stage != Stage::New {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let headers = copy_headers(envoy.get_request_headers()).map_err(|_error| Reply::Status {
            status: 431,
            body: REQUEST_ERROR_BODY,
        })?;
        if !headers_within_limits(&headers, headers.len()) {
            return Err(Reply::Status {
                status: 431,
                body: REQUEST_ERROR_BODY,
            });
        }
        let fallback_authority = attribute_bytes(envoy, AttributeId::RequestHost);
        let raw_authority = request_authority(&headers, fallback_authority.as_deref());
        let scheme = find_header(&headers, ":scheme")
            .map(<[u8]>::to_vec)
            .or_else(|| attribute_bytes(envoy, AttributeId::RequestScheme))
            .unwrap_or_default();
        let Some(authority) = normalize_authority(&raw_authority, &scheme) else {
            return Err(Reply::Status {
                status: 400,
                body: REQUEST_ERROR_BODY,
            });
        };
        let generation = Arc::clone(&state.generation);
        let Some((_name, policy)) = generation.select_named(&authority) else {
            state.stage = Stage::Bypassed;
            envoy_proxy_dynamic_modules_rust_sdk::envoy_log_warn!(
                "envoy-coraza-dynamic: no authority policy matched; request passed uninspected"
            );
            return Ok(HeadersAction::Continue);
        };
        let Some(metadata) = request_metadata(envoy, &headers, &raw_authority) else {
            return Err(Reply::Status {
                status: 400,
                body: REQUEST_ERROR_BODY,
            });
        };
        state.method.clone_from(&metadata.method);
        let (transaction, interruption) = create_transaction(envoy, policy, &authority, &headers, &metadata);
        state.body_access = transaction.request_body_access();
        state.transaction = Some(transaction);
        if let Some(interruption) = interruption {
            return Err(Reply::Interruption(interruption));
        }
        if state
            .transaction
            .as_ref()
            .is_some_and(|tx| tx.rule_engine() == RuleEngineStatus::Off)
        {
            state.stage = Stage::Bypassed;
            return Ok(HeadersAction::Continue);
        }
        if metadata.method.eq_ignore_ascii_case("CONNECT") || has_upgrade(&headers) {
            return Err(Reply::Status {
                status: 501,
                body: UNSUPPORTED_BODY,
            });
        }
        if state.body_access && has_unsupported_content_encoding(&headers) {
            return Err(Reply::Status {
                status: 415,
                body: UNSUPPORTED_BODY,
            });
        }
        if state.body_access && !end_of_stream {
            let current = envoy.get_buffer_limit();
            let limit = MAX_REQUEST_BODY_BYTES_U64;
            if current == 0 || current > limit {
                envoy.set_buffer_limit(limit);
            }
            state.stage = Stage::Held;
            return Ok(HeadersAction::Hold);
        }
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(&mut state, EMPTY_BODY);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        if !state.reservation.resize(retained) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        result.map(|()| HeadersAction::Continue)
    }

    fn on_body(&self, envoy: &mut impl EnvoyHttpFilter, end_of_stream: bool) -> Result<BodyAction, Reply> {
        let mut state = self.state.try_borrow_mut().map_err(|_error| Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        if self.terminal.get() || matches!(state.stage, Stage::Bypassed | Stage::Complete | Stage::Terminal) {
            return Ok(BodyAction::Continue);
        }
        if state.stage != Stage::Held || state.phase2_done {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let received_buffered = envoy.received_buffered_request_body();
        let received_size = envoy.get_received_request_body_size();
        let buffered_size = envoy.get_buffered_request_body_size();
        let body_size = if received_buffered {
            received_size
        } else {
            buffered_size.checked_add(received_size).ok_or(Reply::Status {
                status: 413,
                body: REQUEST_ERROR_BODY,
            })?
        };
        if body_size < state.body_bytes {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        if body_size > MAX_REQUEST_BODY_BYTES {
            return Err(Reply::Status {
                status: 413,
                body: REQUEST_ERROR_BODY,
            });
        }
        if !state.reservation.resize(body_size) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        state.body_bytes = body_size;
        if !end_of_stream {
            return Ok(BodyAction::Buffer);
        }
        let prior_engine_bytes = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let scratch_and_engine = body_size
            .checked_mul(2)
            .and_then(|size| size.checked_add(prior_engine_bytes));
        let target = scratch_and_engine.and_then(|size| body_size.checked_add(size));
        if !target.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let body = copy_terminal_body(envoy, received_buffered, body_size, false).ok_or(Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        drop(state);
        let mut state = self.state.try_borrow_mut().map_err(|_error| Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(&mut state, &body);
        drop(body);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let host_and_engine = state.body_bytes.checked_add(retained);
        if !host_and_engine.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        result.map(|()| BodyAction::Continue)
    }

    fn on_trailers(&self, envoy: &mut impl EnvoyHttpFilter) -> Result<(), Reply> {
        let mut state = self.state.try_borrow_mut().map_err(|_error| Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        if self.terminal.get() || matches!(state.stage, Stage::Bypassed | Stage::Terminal) {
            return Ok(());
        }
        let trailers = copy_headers(envoy.get_request_trailers()).map_err(|_error| Reply::Status {
            status: 431,
            body: REQUEST_ERROR_BODY,
        })?;
        if !headers_within_limits(&trailers, trailers.len()) {
            return Err(Reply::Status {
                status: 431,
                body: REQUEST_ERROR_BODY,
            });
        }
        if state.stage == Stage::Complete {
            return Ok(());
        }
        if state.stage != Stage::Held || state.phase2_done {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let body_size = envoy.get_buffered_request_body_size();
        if body_size < state.body_bytes || body_size > MAX_REQUEST_BODY_BYTES {
            return Err(Reply::Status {
                status: if body_size > MAX_REQUEST_BODY_BYTES { 413 } else { 503 },
                body: REQUEST_ERROR_BODY,
            });
        }
        if !state.reservation.resize(body_size) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let prior_engine_bytes = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let target = body_size
            .checked_mul(2)
            .and_then(|size| size.checked_add(prior_engine_bytes))
            .and_then(|size| body_size.checked_add(size));
        if !target.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        let body = copy_terminal_body(envoy, false, body_size, true).ok_or(Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        })?;
        state.phase2_done = true;
        state.stage = Stage::Complete;
        let result = phase2(&mut state, &body);
        drop(body);
        let retained = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
        let host_and_engine = state.body_bytes.max(body_size).checked_add(retained);
        if !host_and_engine.is_some_and(|target| state.reservation.resize(target)) {
            return Err(Reply::Status {
                status: 503,
                body: REQUEST_ERROR_BODY,
            });
        }
        state.body_bytes = body_size;
        result
    }
}

impl<EHF: EnvoyHttpFilter> HttpFilter<EHF> for RequestFilter {
    fn on_request_headers(&self, envoy: &mut EHF, end_of_stream: bool) -> RequestHeadersStatus {
        if self.terminal.get() {
            return RequestHeadersStatus::StopIteration;
        }
        #[cfg(feature = "panic-probe")]
        if envoy
            .get_request_header_value("x-coraza-probe")
            .is_some_and(|value| value.as_slice() == b"panic")
        {
            panic!("feature-gated request panic probe");
        }
        let result = self.on_headers(envoy, end_of_stream);
        match result {
            Ok(HeadersAction::Continue) => RequestHeadersStatus::Continue,
            Ok(HeadersAction::Hold) => RequestHeadersStatus::StopIteration,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestHeadersStatus::StopIteration
            },
        }
    }

    fn on_request_body(&self, envoy: &mut EHF, end_of_stream: bool) -> RequestBodyStatus {
        if self.terminal.get() {
            return RequestBodyStatus::StopIterationNoBuffer;
        }
        match self.on_body(envoy, end_of_stream) {
            Ok(BodyAction::Buffer) => RequestBodyStatus::StopIterationAndBuffer,
            Ok(BodyAction::Continue) => RequestBodyStatus::Continue,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestBodyStatus::StopIterationNoBuffer
            },
        }
    }

    fn on_request_trailers(&self, envoy: &mut EHF) -> RequestTrailersStatus {
        if self.terminal.get() {
            return RequestTrailersStatus::StopIteration;
        }
        match self.on_trailers(envoy) {
            Ok(()) => RequestTrailersStatus::Continue,
            Err(reply) => {
                self.fail_closed(envoy, reply);
                RequestTrailersStatus::StopIteration
            },
        }
    }

    fn on_local_reply(
        &self,
        _envoy: &mut EHF,
        _response_code: u32,
        _details: EnvoyBuffer<'_>,
        _reset_imminent: bool,
    ) -> LocalReplyStatus {
        // Request local replies are terminal and must never become Coraza input.
        LocalReplyStatus::Continue
    }

    fn on_stream_complete(&self, _envoy: &mut EHF) {
        if let Ok(mut state) = self.state.try_borrow_mut() {
            let body_bytes = state.transaction.as_ref().map_or(0, |tx| tx.body_memory_bytes());
            let _ = state.reservation.resize(body_bytes);
        }
    }
}

fn phase2(state: &mut StreamState, body: &[u8]) -> Result<(), Reply> {
    let Some(transaction) = state.transaction.as_mut() else {
        return Err(Reply::Status {
            status: 503,
            body: REQUEST_ERROR_BODY,
        });
    };
    if let Some(interruption) = transaction.process_request_body(body) {
        return Err(Reply::Interruption(interruption));
    }
    if transaction.inspection_incomplete() || transaction.arguments_limit_reached() {
        return Err(Reply::Status {
            status: 413,
            body: REQUEST_ERROR_BODY,
        });
    }
    Ok(())
}

fn create_transaction<EHF: EnvoyHttpFilter>(
    envoy: &EHF,
    policy: &Policy,
    authority: &str,
    headers: &OwnedHeaders,
    metadata: &RequestMetadata,
) -> (Box<Transaction>, Option<Interruption>) {
    let mut transaction = Box::new(policy.waf.new_transaction());
    apply_connection_metadata(envoy, &mut transaction, authority);
    transaction.process_uri(&metadata.uri, &metadata.method, &metadata.protocol);
    for (name, value) in headers {
        transaction.add_request_header(name, value);
    }
    if !headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("host")) && !authority.is_empty() {
        transaction.add_request_header("host", authority.as_bytes());
    }
    let interruption = transaction.process_request_headers();
    (transaction, interruption)
}

fn valid_status(status: u16) -> u16 {
    if (200..=599).contains(&status) {
        status
    } else {
        403
    }
}

fn copy_headers(headers: EnvoyHeaders<'_>) -> Result<OwnedHeaders, ()> {
    if headers.len() > MAX_HEADER_COUNT {
        return Err(());
    }
    let mut total = 0_usize;
    let mut copied = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        let name = str::from_utf8(name.as_slice()).map_err(|_error| ())?.to_owned();
        let value = value.as_slice();
        if value.len() > MAX_HEADER_VALUE_BYTES {
            return Err(());
        }
        total = total
            .checked_add(name.len())
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(())?;
        if total > MAX_HEADERS_BYTES {
            return Err(());
        }
        copied.push((name, value.to_vec()));
    }
    Ok(copied)
}

fn attribute_bytes<EHF: EnvoyHttpFilter>(envoy: &EHF, id: AttributeId) -> Option<Vec<u8>> {
    envoy.get_attribute_string(id).map(|value| value.as_slice().to_vec())
}

fn request_metadata<EHF: EnvoyHttpFilter>(
    envoy: &EHF,
    headers: &[(String, Vec<u8>)],
    connect_target: &[u8],
) -> Option<RequestMetadata> {
    let method = find_header(headers, ":method")
        .map(<[u8]>::to_vec)
        .or_else(|| attribute_bytes(envoy, AttributeId::RequestMethod))?;
    let method = str::from_utf8(&method).ok()?.to_owned();
    let uri = find_header(headers, ":path")
        .map(<[u8]>::to_vec)
        .or_else(|| attribute_bytes(envoy, AttributeId::RequestPath))
        .or_else(|| method.eq_ignore_ascii_case("CONNECT").then(|| connect_target.to_vec()))?;
    let protocol = attribute_bytes(envoy, AttributeId::RequestProtocol)?;
    let protocol = str::from_utf8(&protocol).ok()?.to_owned();
    if method.is_empty() || protocol.is_empty() {
        return None;
    }
    Some(RequestMetadata { method, uri, protocol })
}

fn apply_connection_metadata<EHF: EnvoyHttpFilter>(envoy: &EHF, tx: &mut Transaction, authority: &str) {
    let remote = envoy
        .get_downstream_direct_remote_address()
        .map(|value| value.as_slice().to_vec())
        .or_else(|| attribute_bytes(envoy, AttributeId::SourceAddress))
        .unwrap_or_default();
    let (remote_addr, remote_port) = endpoint(&remote);
    tx.set_remote_addr(remote_addr);
    let remote_port = match envoy
        .get_attribute_int(AttributeId::SourcePort)
        .and_then(|port| u16::try_from(port).ok())
    {
        Some(port) => port,
        None => remote_port,
    };
    tx.set_remote_port(remote_port);
    let server = attribute_bytes(envoy, AttributeId::DestinationAddress).unwrap_or_default();
    let (server_addr, server_port) = endpoint(&server);
    tx.set_server_addr(server_addr);
    let server_port = match envoy
        .get_attribute_int(AttributeId::DestinationPort)
        .and_then(|port| u16::try_from(port).ok())
    {
        Some(port) => port,
        None => server_port,
    };
    tx.set_server_port(server_port);
    tx.set_server_name(authority_host(authority).as_bytes());
}

fn endpoint(bytes: &[u8]) -> (Vec<u8>, u16) {
    let Ok(address) = str::from_utf8(bytes) else {
        return (Vec::new(), 0);
    };
    let parsed = address
        .parse::<SocketAddr>()
        .map(|socket| (socket.ip().to_string(), socket.port()))
        .or_else(|_| address.parse::<IpAddr>().map(|ip| (ip.to_string(), 0)));
    match parsed {
        Ok((ip, port)) => (ip.into_bytes(), port),
        Err(_) => (bytes.to_vec(), 0),
    }
}

fn copy_terminal_body<EHF: EnvoyHttpFilter>(
    envoy: &mut EHF,
    received_buffered: bool,
    expected: usize,
    trailers: bool,
) -> Option<Vec<u8>> {
    let mut body = Vec::with_capacity(expected);
    if trailers || !received_buffered {
        if let Some(buffered) = envoy.get_buffered_request_body() {
            for fragment in &buffered {
                body.extend_from_slice(fragment.as_slice());
            }
            drop(buffered);
        }
    }
    if !trailers {
        if let Some(received) = envoy.get_received_request_body() {
            for fragment in &received {
                body.extend_from_slice(fragment.as_slice());
            }
            drop(received);
        }
    }
    (body.len() == expected).then_some(body)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "Native stream tests use fixed valid fixtures.")]
#[expect(
    unsafe_code,
    reason = "The SDK mock body view aliases fixed test-only static storage."
)]
mod tests {
    use std::{
        rc::Rc,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
    };

    use coraza::transaction::Interruption;
    use envoy_coraza_common::{config::Config, observability::Diagnostics, policy::Generation};
    use envoy_proxy_dynamic_modules_rust_sdk::{
        abi::{
            envoy_dynamic_module_type_attribute_id as AttributeId,
            envoy_dynamic_module_type_on_http_filter_local_reply_status as LocalReplyStatus,
            envoy_dynamic_module_type_on_http_filter_request_body_status as RequestBodyStatus,
            envoy_dynamic_module_type_on_http_filter_request_headers_status as RequestHeadersStatus,
            envoy_dynamic_module_type_on_http_filter_request_trailers_status as RequestTrailersStatus,
        },
        EnvoyBuffer, EnvoyMutBuffer, HttpFilter as _, MockEnvoyHttpFilter,
    };

    use super::{try_reserve, BodyReservation, FilterConfig, Stage, RETAINED_BODY_BYTES};

    fn generation(directive: &str) -> Arc<Generation> {
        Arc::new(
            Generation::compile(
                Config::parse(
                    format!(r#"{{"directives_map":{{"p":[{directive:?}]}},"default_directives":"p"}}"#).as_bytes(),
                )
                .unwrap(),
                Arc::new(Diagnostics::default()),
                |_| {},
                |_, _| {},
            )
            .unwrap(),
        )
    }

    fn prepare_header_mock(envoy: &mut MockEnvoyHttpFilter, method: &'static [u8], uri: &'static [u8]) {
        prepare_header_mock_with_remote(envoy, method, uri, None);
    }

    fn prepare_header_mock_with_remote(
        envoy: &mut MockEnvoyHttpFilter,
        method: &'static [u8],
        uri: &'static [u8],
        remote: Option<&'static [u8]>,
    ) {
        envoy.expect_get_request_headers().returning(move || {
            let mut headers = vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(method)),
                (EnvoyBuffer::new(b":path"), EnvoyBuffer::new(uri)),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"http")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test")),
            ];
            if method == b"POST" {
                headers.push((EnvoyBuffer::new(b"content-type"), EnvoyBuffer::new(b"text/plain")));
            }
            headers
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(move || remote.map(EnvoyBuffer::new));
    }

    fn prepare_connect_mock(envoy: &mut MockEnvoyHttpFilter) {
        envoy.expect_get_request_headers().returning(|| {
            vec![
                (EnvoyBuffer::new(b":method"), EnvoyBuffer::new(b"CONNECT")),
                (EnvoyBuffer::new(b":scheme"), EnvoyBuffer::new(b"https")),
                (EnvoyBuffer::new(b":authority"), EnvoyBuffer::new(b"example.test:443")),
            ]
        });
        envoy.expect_get_attribute_string().returning(|id| match id {
            AttributeId::RequestProtocol => Some(EnvoyBuffer::new(b"HTTP/2")),
            _ => None,
        });
        envoy.expect_get_attribute_int().returning(|_| None);
        envoy
            .expect_get_downstream_direct_remote_address()
            .returning_st(|| None);
    }

    fn prepare_body_hold(envoy: &mut MockEnvoyHttpFilter) {
        envoy.expect_get_buffer_limit().return_const(16_u64 * 1024 * 1024);
    }

    fn expect_inline_reply(envoy: &mut MockEnvoyHttpFilter, filter: Rc<super::RequestFilter>, expected: u32) {
        envoy
            .expect_send_response()
            .returning_st(move |status, _headers, body, _details| {
                assert_eq!(status, expected);
                assert!(
                    filter.terminal.get(),
                    "terminal state is published before the re-entrant host call"
                );
                if expected == 409 {
                    assert_eq!(body, Some(b"Request denied\n".as_slice()));
                }
                let mut callback_envoy = MockEnvoyHttpFilter::default();
                assert_eq!(
                    filter.on_local_reply(&mut callback_envoy, status, EnvoyBuffer::new(b""), false),
                    LocalReplyStatus::Continue,
                    "the inline local reply is ignored by request inspection"
                );
            });
    }

    fn body_rule_generation() -> Arc<Generation> {
        Arc::new(Generation::compile(
            Config::parse(
                br#"{"directives_map":{"p":["SecRuleEngine On","SecRequestBodyAccess On","SecRequestBodyLimit 100","SecAction \"id:1,phase:1,ctl:requestBodyProcessor=RAW,pass\"","SecRule REQUEST_BODY \"@contains attack\" \"id:2,phase:2,deny,status:409\""]},"default_directives":"p"}"#,
            )
            .unwrap(),
            Arc::new(Diagnostics::default()),
            |_| {},
            |_, _| {},
        )
        .unwrap())
    }

    fn attack_view() -> EnvoyMutBuffer<'static> {
        static mut BODY: [u8; 6] = *b"attack";
        // SAFETY: the mock only reads the immutable static bytes during the synchronous hook.
        unsafe { EnvoyMutBuffer::new(&raw mut BODY) }
    }

    #[test]
    fn admission_reservation_is_checked_and_released_on_drop() {
        let counter = AtomicUsize::new(0);
        assert!(try_reserve(&counter, 7, 10));
        assert!(!try_reserve(&counter, 4, 10));
        assert_eq!(counter.load(Ordering::Acquire), 7);
        assert!(!try_reserve(&counter, usize::MAX, 10));

        let initial = RETAINED_BODY_BYTES.load(Ordering::Acquire);
        let mut reservation = BodyReservation::default();
        assert!(reservation.resize(17));
        assert_eq!(RETAINED_BODY_BYTES.load(Ordering::Acquire), initial + 17);
        drop(reservation);
        assert_eq!(RETAINED_BODY_BYTES.load(Ordering::Acquire), initial);
    }

    #[test]
    fn concurrent_reservations_never_cross_the_shared_limit() {
        let counter = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let counter = Arc::clone(&counter);
            workers.push(std::thread::spawn(move || {
                (0..100).filter(|_| try_reserve(&counter, 1, 10)).count()
            }));
        }
        let reserved: usize = workers.into_iter().map(|worker| worker.join().unwrap()).sum();
        assert_eq!(reserved, 10);
        assert_eq!(counter.load(Ordering::Acquire), 10);
    }

    #[test]
    fn streams_pin_the_generation_across_config_replacement() {
        let old_config = FilterConfig::new(generation("SecRuleEngine On"));
        let old_stream = old_config.new_stream();
        let old_ptr = Arc::as_ptr(&old_stream.state.borrow().generation);
        drop(old_config);

        let new_config = FilterConfig::new(generation("SecRuleEngine DetectionOnly"));
        let new_stream = new_config.new_stream();
        let new_ptr = Arc::as_ptr(&new_stream.state.borrow().generation);

        assert_ne!(old_ptr, new_ptr);
        assert_eq!(Arc::as_ptr(&old_stream.state.borrow().generation), old_ptr);
        assert_eq!(old_stream.state.borrow().stage, Stage::New);
    }

    #[test]
    fn phase_one_interruption_uses_rule_status_and_stops_before_forwarding() {
        let filter = Rc::new(
            FilterConfig::new(generation(
                r#"SecRule REQUEST_URI "@contains attack" "id:1,phase:1,deny,status:418""#,
            ))
            .new_stream(),
        );
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"GET", b"/attack");
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 418);

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration,
        );
    }

    #[test]
    fn redirect_action_keeps_an_empty_body_even_without_a_location() {
        let filter = FilterConfig::new(generation("SecRuleEngine On")).new_stream();
        let mut envoy = MockEnvoyHttpFilter::default();
        envoy
            .expect_send_response()
            .returning_st(|status, headers, body, _details| {
                assert_eq!(status, 302);
                assert_eq!(body, Some(super::EMPTY_BODY));
                assert!(!headers.iter().any(|(name, _)| *name == "location"));
            });
        let interruption = Interruption {
            rule_id: 1,
            action: "redirect".to_owned(),
            status: 302,
            data: String::new(),
        };

        filter.send_interruption(&mut envoy, &interruption);
        assert!(filter.terminal.get());
    }

    #[test]
    fn phase_one_uses_the_host_protocol_and_direct_client_address() {
        for (directive, remote, status) in [
            (
                "SecRule REQUEST_PROTOCOL \"@streq HTTP/2\" \"id:20,phase:1,deny,status:419\"",
                None,
                419,
            ),
            (
                "SecRule REMOTE_ADDR \"@streq 203.0.113.7\" \"id:21,phase:1,deny,status:420\"",
                Some(b"203.0.113.7:41234".as_slice()),
                420,
            ),
        ] {
            let filter = Rc::new(FilterConfig::new(generation(directive)).new_stream());
            let mut envoy = MockEnvoyHttpFilter::default();
            prepare_header_mock_with_remote(&mut envoy, b"GET", b"/metadata", remote);
            expect_inline_reply(&mut envoy, Rc::clone(&filter), status);

            assert_eq!(
                filter.on_request_headers(&mut envoy, true),
                RequestHeadersStatus::StopIteration,
                "the SDK supplies the actual protocol and direct client address to Coraza"
            );
        }
    }

    #[test]
    fn connect_without_a_path_fails_with_the_unsupported_status() {
        let filter = Rc::new(FilterConfig::new(generation("SecRuleEngine On")).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_connect_mock(&mut envoy);
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 501);

        assert_eq!(
            filter.on_request_headers(&mut envoy, true),
            RequestHeadersStatus::StopIteration
        );
    }

    #[test]
    fn body_phase_denial_reads_the_complete_buffer_once_and_is_terminal_before_reply() {
        let filter = Rc::new(FilterConfig::new(body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration,
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(0_usize);
        envoy.expect_get_buffered_request_body_size().return_const(6_usize);
        let attack = attack_view();
        envoy
            .expect_get_buffered_request_body()
            .returning_st(move || Some(vec![attack]));
        envoy.expect_get_received_request_body().returning_st(|| None);
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 409);

        assert_eq!(
            filter.on_request_body(&mut envoy, true),
            RequestBodyStatus::StopIterationNoBuffer,
        );
        assert_eq!(filter.state.borrow().stage, Stage::Terminal);
    }

    #[test]
    fn trailer_termination_assembles_the_buffered_prefix_and_checks_trailers() {
        let filter = Rc::new(FilterConfig::new(body_rule_generation()).new_stream());
        let mut envoy = MockEnvoyHttpFilter::default();
        prepare_header_mock(&mut envoy, b"POST", b"/upload");
        prepare_body_hold(&mut envoy);
        assert_eq!(
            filter.on_request_headers(&mut envoy, false),
            RequestHeadersStatus::StopIteration,
        );

        envoy.expect_received_buffered_request_body().return_const(false);
        envoy.expect_get_received_request_body_size().return_const(6_usize);
        envoy
            .expect_get_buffered_request_body_size()
            .return_const(0_usize)
            .times(1);
        assert_eq!(
            filter.on_request_body(&mut envoy, false),
            RequestBodyStatus::StopIterationAndBuffer,
        );

        envoy
            .expect_get_request_trailers()
            .returning(|| vec![(EnvoyBuffer::new(b"x-client-trailer"), EnvoyBuffer::new(b"preserved"))]);
        envoy
            .expect_get_buffered_request_body_size()
            .return_const(6_usize)
            .times(1);
        let attack = attack_view();
        envoy
            .expect_get_buffered_request_body()
            .returning_st(move || Some(vec![attack]));
        expect_inline_reply(&mut envoy, Rc::clone(&filter), 409);

        assert_eq!(
            filter.on_request_trailers(&mut envoy),
            RequestTrailersStatus::StopIteration,
        );
        assert!(filter.terminal.get());
    }

    #[test]
    fn detection_only_and_body_access_off_complete_phase_two_without_holding_headers() {
        for directives in [
            "SecRuleEngine DetectionOnly\nSecRule REQUEST_URI \"@contains attack\" \"id:1,phase:1,deny,status:403\"",
            "SecRuleEngine On\nSecRequestBodyAccess Off",
        ] {
            let filter = FilterConfig::new(generation(directives)).new_stream();
            let mut envoy = MockEnvoyHttpFilter::default();
            prepare_header_mock(&mut envoy, b"GET", b"/attack");
            assert_eq!(
                filter.on_request_headers(&mut envoy, false),
                RequestHeadersStatus::Continue,
            );
            assert_eq!(filter.state.borrow().stage, Stage::Complete);
            assert!(filter.state.borrow().phase2_done);
            assert!(!filter.terminal.get());
        }
    }
}
