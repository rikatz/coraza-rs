# Envoy Coraza dynamic-module Stage C evidence

Stage C connects the Stage A Envoy 1.40.0 host boundary to Stage B's shared
policy compiler. It implements request phases 1 and 2 only; response inspection,
transaction finalization, and telemetry remain Stage D.

## Implemented

- The `coraza` filter factory enforces the 8 MiB configuration bound, parses
  through `envoy-coraza-common`, compiles every policy before publication, and
  returns `None` for unknown names, malformed input, and compile errors. Error,
  warning, and bounded audit callbacks use the SDK's Envoy logging macros.
- One immutable `Arc<Generation>` belongs to each accepted filter configuration;
  request streams retain the generation they started with.
- Request headers are copied as bytes within the shared count/value/aggregate
  limits. Authority normalization and policy selection use the shared helpers.
  The transaction receives the SDK's request protocol, URI and method plus the
  downstream direct peer and destination connection attributes; forwarded
  headers are not trusted as client identity. A CONNECT request without `:path`
  uses its authority-form target for phase 1 before the required 501 response.
  Coraza receives Envoy's current `:path`; normalization performed by Envoy or
  earlier filters is not reversed to recover the client wire target.
- Phase 1 runs before forwarding. Engine-off and unmatched-authority requests
  continue explicitly uninspected. CONNECT/upgrades and inspected residual
  content encodings return 501 and 415. Headers are held only when an enabled
  request-body inspection needs a later phase-2 verdict.
- The adapter buffers request data through body EOS or trailers, enforces the
  16 MiB host ceiling, checks trailers against the header budgets, and passes
  trailers through unchanged. A complete buffered body is coalesced once and
  supplied once to phase 2. Trailers are not exposed as SecLang rule variables.
- A checked atomic reservation tracks retained request-body bytes across filter
  configurations and streams for this loaded module, with a 64 MiB cap. A
  reservation is owned by its stream and released by `Drop`; exhaustion fails
  closed with 503, while the host body ceiling returns 413.
- Request interruptions use their rule-selected status and redirect location.
  HEAD, 204 and 304 replies have empty bodies. Terminal state and all borrowed
  header/body views are released before the SDK local-reply call, which Stage A
  proved can synchronously re-enter the filter.

## Real-host results

The updated `examples/envoy-coraza-dynamic/test-envoy.sh` passed against the
Stage A pinned standalone Envoy 1.40.0 image and reused backend. The executed
cases include:

- phase-1 status 451 and phase-2 body status 429, both before backend contact;
- rule-configured 307 redirect and `Location`, empty bodies for HEAD/204/304;
- rejection of unsupported request encoding with 415 and a websocket upgrade
  with 501; the harness explicitly enables that HCM upgrade so the request
  reaches the filter;
- an allowed 65,536-byte binary upload split at 16 KiB boundaries, byte-exact
  at the backend, and a trailer-terminated byte-exact upload whose trailer
  reached the backend;
- DetectionOnly, engine-off, body-access-off, unmatched authority, empty
  configuration, and two filter instances with distinct policies;
- unknown filter name, malformed JSON and invalid UTF-8 rejected at startup;
- the `panic-probe` request regression: fail-closed 500 and healthy follow-up.

These results prove the selected request-side flows on the pinned host pair;
they do not establish HTTP/2 or multi-worker load/concurrency behavior.

## Unit-tested only

SDK mock tests cover rule-configured phase-1/phase-2 denial, inline local-reply
re-entry and terminal-state ordering, body buffering and trailer EOS, protocol
and direct-client metadata propagation, body-access-off and DetectionOnly
transitions, CONNECT without a path, compare-and-reserve admission under
contention, reservation release, and stream generation pinning across two
constructed configurations.

The atomic reservation implementation is unit-tested under contention, but
real-host admission exhaustion and aggregate retained-memory accounting under
concurrent streams were not load-tested. The real-host upload was 64 KiB; the
16 MiB host ceiling's boundary/overflow behavior is not established by Stage C.

## INCOMPLETE and deferred

- **Live configuration update with old in-flight streams — INCOMPLETE.** The
  harness is static bootstrap configuration and has no LDS/ECDS update path.
  Generation pinning is unit-tested only; no live-update preservation claim is
  made (decision 10: record and continue).
- HTTP/2 framing, multiple Envoy workers, cancellation stress, and module-wide
  admission exhaustion under real load remain untested.
- Trailer values are bounded and preserved but are not Coraza rule inputs.
- Response phases, response replacement, transaction `finish`, final telemetry,
  and audit lifecycle remain Stage D, not partial Stage C support.

The native request-denial path intentionally uses Envoy's local-reply API rather
than the Wasm adapter's response-replacement path, following decision 9. No
other request outcome divergence from the decision-16 contract is intended.
