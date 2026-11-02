# Envoy Coraza dynamic-module Stage D evidence

Stage D adds response inspection, terminal finalization, native filter state and
embedded CRS to the request-enforcing Stage C filter.

## Proven host and artifact pair

The host is the pinned Stage A pair: standalone Envoy 1.40.0, image
`envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de`
(`linux/amd64`), SDK revision
`9e5580933739775e8bce696a57a2e1bc99368f23`, ABI `v0.2.0`. The pinned binary,
glibc and build identities are recorded in
[`envoy-coraza-dynamic-stage-a.md`](envoy-coraza-dynamic-stage-a.md).

The native module's CRS feature forwards to the shared generator; the only pin
remains `envoy-coraza/crs.pin` (`v4.30.0`). `make crs-fetch` populated the
shared `envoy-coraza/crs` tree.

## Implemented

- Response header names and values are copied under the common count/value/byte
  budgets before phase 3. Eligible response headers are held only when response
  body access is enabled, the MIME type is processable, and the response has not
  ended. MIME-excluded and body-access-off responses run phase 4 with an empty
  body at headers, so phase-4 response-header rules still apply before the body
  streams.
- Response body EOS and response trailers use the SDK's received/buffered-body
  semantics to assemble one bounded inspection buffer. Response body processing
  runs once; allowed body bytes and trailers remain unchanged. The host ceiling
  is 1 MiB, independently of the compiled SecLang limit, and uses the same
  module-wide atomic admission reservation as request bodies.
- Response denials use `send_response` from the encode-header/body/trailer path
  as selected by decision 9. The filter marks the stream terminal, publishes
  enabled interruption fields, releases state borrows, and then makes the host
  call. Any body/host/admission failure uses a generic 502; engine response-body
  limit interruptions keep the engine's status. Redirect status/Location and
  empty bodies for HEAD, 204 and 304 are preserved.
- Stream request state is `None` until decode starts. Response callbacks and
  stream completion for never-decoded Envoy local replies pass through without
  creating a transaction.
- `Transaction::finish` is once-only from `on_stream_complete`; `StreamState`
  drop finalizes as a host-independent fallback when poisoned `CatchUnwind`
  skips completion. Normal completion, denial, incomplete inspection, and
  upstream failure/cancellation map to the shared `TerminalOutcome` values.
- Native filter state uses exactly `wasm.io.coraza.waf.<field>` and
  `wasm.io.coraza.waf.v1.<field>`. It publishes the Wasm field sets, respects
  `enable_filter_state_logs`, publishes interruptions before local replies, and
  publishes health after finalization and before access-log flush. Failed state
  writes mark telemetry failure but do not change enforcement.
- Error, audit and debug callbacks use shared bounds/escaping. Error output is
  capped at 4 KiB; audit at 16 KiB; debug at 4 KiB. Audit entries remain subject
  to Coraza's configured `SecAuditEngine` relevance. Debug output uses an
  Envoy-backed `DebugLogger`; `SecDebugLog` file sinks are rejected rather than
  opened on a worker.

## Real-host results

`bash examples/envoy-coraza-dynamic/test-envoy.sh` passed on the pinned host.
It exercises:

- phase-3 response-header and phase-4 response-body decisions, including the
  rule-configured 451 response denial from the response-body callback;
- zero upstream response header/body leakage on body, MIME-excluded and
  body-access-off denial paths; a trailer-terminated denial also removed the
  upstream trailer; byte-exact allowed response bodies and preserved response
  trailers;
- a phase-4 response redirect with 307 and Location, plus empty response bodies
  for HEAD/204/304 replacements;
- generic 502 at the native 1 MiB response ceiling and the engine's 500
  `SecResponseBodyLimitAction Reject` status;
- an access-log row for a response denial containing interruption fields and
  final health state, followed by an allow row with no stale denial fields;
- `enable_filter_state_logs=false` leaves health filter-state fields absent;
- rule 949110 denying CRS SQLi on `crs.local`, with benign CRS traffic allowed;
- feature-gated response-body panic/reset and a healthy follow-up stream;
- existing request enforcement, request trailers, startup-negative controls,
  two filter instances and request panic behavior.

The response denial audit marker appeared once in the Envoy log. The access-log
row contains the terminal outcome published from `on_stream_complete`, proving
the state was set before HCM access-log flush. The filter-state values are
per-stream; the following allow row had absent (`-`) legacy interruption fields.

## Unit-tested

`cargo test -p envoy-coraza-dynamic` covers response local-reply re-entry from
the encode-body callback; never-decoded response callbacks; MIME-excluded and
body-access-off phase-4 header rules; response body/header denial status; the
shared terminal outcome mapping; completion publication ordering and exactly
once behavior; admission release on normal completion/drop; Drop-based
transaction finish; telemetry failure non-disruption; and bounded debug/state
formatting. `cargo test -p envoy-coraza-dynamic --features panic-probe` also
passes.

The tests exercise the fixed SDK mock boundary. The real-host harness establishes
the corresponding response-body callback, local-reply, trailer, filter-state,
access-log and panic/reset behavior.

## Required checks

| Check | Result |
| --- | --- |
| `make lint` | Passed |
| `cargo test -p envoy-coraza-dynamic` | Passed (24 tests) |
| `make test` | Passed |
| `make build-envoy-wasm` | Passed |
| `make lint-extra` | Passed |
| `make crs-fetch` | Passed; the pinned shared tree was already current on the final run |
| `cargo test -p envoy-coraza-dynamic --features embed-crs` | Passed |
| `cargo test -p envoy-coraza --features embed-crs` | Passed |
| `bash examples/envoy-coraza-dynamic/test-envoy.sh` | Passed on pinned Envoy 1.40.0, including CRS and response-trailer denial |
| `bash examples/envoy-coraza/test-envoy.sh` | Passed; existing Wasm harness remains green |
| `bash examples/envoy-libperfusion/test-envoy.sh` | Passed (repository Envoy-adapter lint gate) |

## Compatibility ledger (decision 16)

| Behavior | Wasm artifact | Native Stage D | Evidence / disposition |
| --- | --- | --- | --- |
| Response denial mechanism | Replaces response headers/body and clears trailers in place. | Uses Envoy SDK `send_response` from encode callbacks. | Intentional, simpler/safer decision-9 divergence. Response-header and response-body callback use were proven on Envoy 1.40; upstream headers/body/trailers did not leak. |
| Blocked response status/body | Rule status/redirect is kept; generic blocked body; empty for redirect, HEAD, 204 and 304. | Same rule status/Location and blocked body; empty for redirect, HEAD, 204 and 304. | Real-host status, body and Location checks passed. The SDK local-reply API is `void`, so it cannot report a send failure for a subsequent reset; this is an SDK observability limit. The callback path was proven successful on the pinned host. |
| Replacement response headers | Wasm installs its explicit response map and content length. | Native supplies cache-control, Location when applicable, and content-type only for a body-bearing response or a redirect without Location; Envoy owns local-reply framing. | Upstream headers are absent and the native adapter avoids Wasm's content-type on HEAD/204/304/redirect-with-Location. Envoy-owned content-length/date/server framing can still differ; exact ancillary headers are not a parity guarantee. |
| Response inspection failure | Generic 502; engine body-limit interruption keeps its status. | Same: host ceiling/connector failure is 502; engine Reject remains 500. | Real-host 1 MiB 502 and engine-limit 500 checks passed without upstream leakage. |
| Filter-state key strings/field sets | Uses the two legacy Wasm property namespaces. | Writes the exact same strings through native `set_filter_state_bytes`. | Real-host response deny/allow access-log visibility and isolation passed. |
| Decode-phase request local-reply access log | Wasm and native both issue local replies from the decoder path. | The pinned HCM returned the request denial, but the file access logger did not emit a row for that early decoder local reply in the harness. | Request-denial filter state is written before `send_response`; its HCM access-log visibility is **INCOMPLETE**. Response-phase denial visibility is proven. No adapter-specific difference from Wasm was established for this HCM behavior. |
| Request denial body | Wasm uses an empty request-block body. | Stage C native path uses `Request denied\n` except HEAD/204/304/redirect. | Existing Stage C divergence, retained and explicitly tracked; response blocked-body shape is unchanged. |

## INCOMPLETE / not yet tested (decision 10)

- Decode-phase request-denial access-log row visibility is unavailable in the
  observed HCM local-reply path as described above; state publication before the
  local-reply call is implemented, but this particular formatter path could not
  be demonstrated.
- Client cancellation/upstream reset stress, admission exhaustion under
  concurrent Envoy load, and exact module-counter observation after host reset
  remain untested. Unit tests cover completion/drop release; the real response
  panic reset with a retained request body and a healthy follow-up passed.
- HTTP/2, multi-worker load/concurrency, live configuration replacement and
  multi-architecture behavior are Stage E/F work and were not tested.
- Full go-ftw CRS conformance, CRS parity against the Wasm artifact, response
  decompression and other unsupported protocol/body classes remain outside this
  Stage D acceptance run.
- The prescribed detector benchmark matrix and native-vs-Wasm performance
  comparison were not run in Stage D; record as incomplete, not passed.
