# Envoy Coraza dynamic-module Stage A evidence

Stage A was exercised against a real standalone Envoy process on 2026-11-02.
This records the observed host boundary for the Stage C/D design; it is not a
claim that native Coraza transactions or policy enforcement are implemented.

## Proven host and artifact pair

| Item | Observed value |
| --- | --- |
| Repository base | `1d0f11ac96a57670e6e4f4f30d1e2e0eb18074f8` |
| Envoy image | `envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de` (`linux/amd64`) |
| Envoy version | `9e5580933739775e8bce696a57a2e1bc99368f23/1.40.0/Clean/RELEASE/BoringSSL` |
| Envoy executable | `/usr/local/bin/envoy`, SHA-256 `8aa137a7d00994ce43f613556f5a120709229f63bedb86eedde5ccbc402c2b80` |
| Runtime OS / glibc | Ubuntu 22.04.5, glibc `2.35-0ubuntu3.15` |
| Dynamic-module ABI log | `Dynamic module ABI version v0.2.0 matched.` |
| SDK | `https://github.com/envoyproxy/envoy`, revision `9e5580933739775e8bce696a57a2e1bc99368f23` |
| Build host / target | Fedora 44 x86-64; `x86_64-unknown-linux-gnu` |
| Rust | `rustc 1.99.1 (58cf8f9c3 2026-10-13)` |
| Clang / libclang | Clang `22.1.8`; `libclang.so.22.1` available |
| Default release module SHA-256 | `501950cc2ec70dbd199ed00ddd695dab11d810c8fd74802483d64e2774c4b3df` |
| `panic-probe` release module SHA-256 | `72f8e886753889c832c3c2cb3790be3c900a0fb3c7cbecac29a481b143602188` |

The host loaded the `panic-probe` module from a local file named
`/opt/envoy/modules/libenvoy_coraza_dynamic.so`. The derived image pins the
base image above, sets `ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/opt/envoy/modules`,
and installs the library root-owned with mode `0444` in a root-owned `0555`
directory. Configuration uses `name: envoy_coraza_dynamic`,
`do_not_close: true`, `load_globally: false`, `filter_name: coraza`, and a
`google.protobuf.StringValue` JSON-object value. No remote module source is
configured.

The default artifact is `ELF64`, little-endian x86-64, `ET_DYN`. Its dynamic
dependencies are `libgcc_s.so.1`, `libc.so.6`, and `ld-linux-x86-64.so.2`; the
highest observed GLIBC symbol requirement is `GLIBC_2.34`, below the pinned
runtime's glibc 2.35. The SDK exports `envoy_dynamic_module_on_program_init`,
`envoy_dynamic_module_on_http_filter_config_new`, and the HTTP filter lifecycle
hooks, among other SDK extension hooks. Envoy callback names such as
`envoy_dynamic_module_callback_http_filter_continue_decoding`,
`envoy_dynamic_module_callback_http_send_response`,
`envoy_dynamic_module_callback_http_set_buffer_limit`, and
`envoy_dynamic_module_callback_log_v2` are undefined imports in the ELF, as
expected for the dynamic-module ABI. The successful load and exercised calls
prove resolution for this host/module pair; `ldd` alone does not.

## Observed HTTP lifecycle

The example filter is only a lifecycle probe. Its small JSON object is checked
for UTF-8 and JSON-object shape; it is not parsed as a Coraza policy. The
`coraza` path dependency is compiled into the native cdylib, but Stage A does
not create or run a Coraza transaction.

| Probe | Status/action observed | Host result |
| --- | --- | --- |
| `x-coraza-probe: hold` | `on_request_headers` returned `StopIteration`; a scheduled event later called `continue_decoding` | The subsequent request reached the backend and returned 200. Log order was request headers, then scheduled continuation. No filter state borrow or body view was held across continuation. |
| `x-coraza-probe: body` | Non-final request-body callbacks returned `StopIterationAndBuffer`; the final empty EOS callback returned `Continue` | Request body reached the echo backend byte-exactly as `frame-one-frame-two-frame-three`. |
| `x-coraza-probe: trailer` | Body callbacks returned `StopIterationAndBuffer`; request trailers returned `Continue` | Trailer-terminated request completed, the full body reached the backend once, and the backend saw `x-client-trailer: present`. |
| `x-coraza-probe: deny` | `send_response(403, ...)` from request headers; callback returned `StopIteration` | 403 body delivered, backend count unchanged. `on_local_reply(status=403)` ran inline while the request-header hook was still active. Exactly one denial callback was observed. |
| `x-coraza-probe: replace` | `send_response(200, ...)` from response headers; callback returned `StopIteration` | Response was `replacement response`; upstream secret header and body were absent. `on_local_reply(status=200)` ran inline while the response-header hook was active. |
| `x-coraza-probe: limit` | Set limit to 32 bytes, held headers with `StopIteration`, then returned `StopIterationAndBuffer` for request body | Envoy returned a 413 local reply for the 2 MiB request before backend contact. The final run callback saw `received_size=238216` and `buffered_size=0`; an earlier run saw all 2 MiB in that view. `get_buffer_limit()` read back 32. This is the observed result for this host and workload, not a general threshold guarantee. |
| `x-coraza-probe: panic` in default build | Panic branch is compiled out | Request completed normally with HTTP 200; no panic log. |
| `x-coraza-probe: panic` with `panic-probe` | Request-header hook panicked inside `CatchUnwind` | SDK wrapper returned a fail-closed 500 local reply; backend was not contacted. A following healthy request on the same Envoy returned 200. Poisoned cleanup/local-reply hooks may be skipped by the SDK. |
| `x-coraza-probe: panic-response` with `panic-probe` | Response-header hook panicked inside `CatchUnwind` | SDK wrapper reset the stream; curl observed HTTP code `000` (no response). A following healthy request on the same Envoy returned 200. |

### Body views and callback ordering

For the controlled 31-byte body `frame-one-frame-two-frame-three`, the body
callbacks were:

| Callback | EOS | `get_received_request_body` | `get_buffered_request_body` |
| --- | --- | --- | --- |
| 1 | false | one current fragment, `frame-one-` (10 bytes) | unavailable / size 0 |
| 2 | false | one current fragment, `frame-two-` (10 bytes) | prior buffered prefix `frame-one-` (10 bytes) |
| 3 | false | one current fragment, `frame-three` (11 bytes) | prior buffered prefix `frame-one-frame-two-` (20 bytes) |
| 4 | true | unavailable / size 0; this was an empty terminal body event | all 31 bytes, `frame-one-frame-two-frame-three` |

This confirms frame ownership: the received view is the current event, while
the buffered view at the next event contains earlier frames. At empty body EOS,
the buffered view contained the full body. The current frame must not be added
to the buffered view a second time. Returning `Continue` on that terminal event
forwarded the message exactly once.

For the trailer-terminated 18-byte body `trailer-terminated`, both body events
had `end_of_stream=false`; current received fragments were 8 and 10 bytes, and
the buffered view advanced from unavailable/0 to the first 8 bytes. No
body-event EOS callback occurred. At `on_request_trailers`, the buffered view
contained all 18 bytes. The probe does not call the received-body API from the
trailer hook; the pinned SDK documents that getter for `on_request_body`.
Returning `Continue` from trailers resumed the request, passed the trailer to
the backend, and completed without a stuck stream.

Small-fragment logs show byte values as decimal arrays; the values above are
their ASCII decoding. For views over 128 bytes, the probe logs fragment lengths
and total size instead of copying/logging the full contents.

### Inline re-entrancy

Both `send_response` call sites produced a nested `on_local_reply` before the
outer callback returned:

```text
request_headers mode=Deny
local_reply status=403 nested_request_headers=true terminal=true

response_headers action=replace
local_reply status=200 nested_request_headers=false nested_response_headers=true terminal=true
```

The terminal flag was set before the host call; state uses `Cell`, and no
mutable state borrow or Envoy buffer view crosses the call. The deny case did
not reach the backend; the response-replacement case did not leak the upstream
response. No hang or duplicate denial/replacement was observed.

### Buffer-limit observation

The SDK-reported initial per-stream buffer limit was `16777216`. The probe set
it to `32` in `on_request_headers`, read back `32`, and returned
`StopIteration` to keep headers held. The client wrote a 2 MiB
`Content-Length` body to its local socket. In the final run, Envoy invoked the
body hook with `end_of_stream=false`, `received_size=238216` across 15 body
fragments, and `buffered_size=0`; an earlier run delivered all 2,097,152 bytes
in one received view. In both runs, after the probe returned
`StopIterationAndBuffer`, Envoy generated `on_local_reply(status=413)` before
backend contact. The variable received-view size shows callback aggregation is
not a stable framing boundary. This proves a concrete over-limit outcome, but
not the exact boundary at which Envoy rejects under other body framing or
filter-chain layouts. Do not treat `set_buffer_limit` as a replacement for
adapter-owned body bounds.

## Rejected startup controls

The harness ran actual Envoy startup (not only `--mode validate`) for each
variant. Every process exited nonzero before serving, and a curl connection to
the listener failed afterward:

| Variant | Mutation | Observed result |
| --- | --- | --- |
| Missing library | Mounted an empty module search directory over the image's local module directory | Startup rejected; listener did not serve traffic. |
| Corrupt library | Mounted a non-ELF file at `libenvoy_coraza_dynamic.so` | Startup rejected; listener did not serve traffic. |
| Wrong architecture | Changed the ELF `e_machine` field to `EM_AARCH64` in the x86-64 module | Startup rejected; listener did not serve traffic. |
| Unknown filter | Changed `filter_name` from `coraza` to `unknown` | Factory rejection stopped startup; listener did not serve traffic. |
| Invalid JSON | Passed `not-json` in a `StringValue` | Configuration rejected; listener did not serve traffic. |
| Invalid UTF-8 | Passed byte `0xff` using a `BytesValue` | Configuration rejected; listener did not serve traffic. |

No unfiltered request was served in these cases. The harness is static bootstrap
configuration and does not use LDS/ECDS/xDS; a rejected update against an
already-running Envoy is therefore **not tested**. No live-update preservation
claim is made.

## Test-linking boundary

`cargo test -p envoy-coraza-dynamic` links a native test executable using the
SDK's `mock` feature. `CatchUnwind` references two host logging imports, so
`#[cfg(test)]` provides only `envoy_dynamic_module_callback_log_enabled` and
`envoy_dynamic_module_callback_log_v2` as inert test symbols. Production
builds contain no host-call shims. Config-gate tests cover unknown names,
non-UTF-8, invalid JSON, non-object JSON, and valid objects; another test
constructs the HTTP filter against `MockEnvoyHttpFilter`.

The dependency lock pins `prettyplease` 0.2.37. An unconstrained resolution to
0.3.0 made the pinned SDK's bindgen 0.73.2 fail to compile due to its `syn` API
version; the compatible 0.2 release builds successfully.

## Not established by Stage A

- Live rejected configuration updates; the provided harness is static.
- HTTP/2, multiple-worker isolation/concurrency, cancellation stress, response
  trailers, or other protocol/framing combinations beyond those listed above.
- Coraza rule compilation, transaction phases, policy enforcement, observability,
  or resource accounting. These are Stage C/D work.
- Production readiness, sandboxing, unload safety, or compatibility with any
  Envoy build/image other than the pinned x86-64 image.

The real-host lifecycle cases in this document passed. Broader protocol and
concurrency gates remain open for later stages; this result is a feasibility
boundary, not a release approval.
