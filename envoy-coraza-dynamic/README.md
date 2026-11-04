# Envoy Coraza native dynamic module

This crate builds an experimental native HTTP filter for standalone Envoy
1.40.0. It is a separate artifact from `envoy-coraza`'s Proxy-Wasm filter;
both use the same Coraza policy configuration, but the native module is not
sandboxed by Wasm.

## Build and test

The pinned Envoy SDK runs bindgen during compilation. Install `clang` and
`libclang-dev`, then use the workspace targets:

```sh
make build-envoy-dynamic
make build-envoy-dynamic-crs
make test-envoy-dynamic
```

The build produces `target/release/libenvoy_coraza_dynamic.so`. The CRS target
fetches the version pinned in `envoy-coraza/crs.pin` before enabling the
`embed-crs` feature. The integration harness needs Docker Compose, curl with
HTTP/2 support, Python 3, and an unused local port 9901; it runs the module only
from a local file in the pinned Envoy image, never from a remote module source.

## Deployment limits

- Tested host: digest-pinned standalone Envoy 1.40.0 on Linux/amd64 with glibc.
  This is not an Istio compatibility claim.
- Request and response retained-body ceilings are 16 MiB and 1 MiB per stream.
  A checked module-wide admission budget of 64 MiB covers Envoy's buffered body
  copy, the module's contiguous copy, and the Coraza transaction's body
  buffers, retained body variables, parser collection growth, selected rule
  values, transformation output, and matched values. Body buffers reserve their
  requested growth directly; parsed JSON rows and collection entries are
  charged before they are inserted; XML and multipart allocations are bounded
  before parsing by element/part/header counts plus copied bytes. Macro
  expansions and TX/ENV writes are charged before their strings and map copies
  grow. Body storage is charged before it grows;
  admission exhaustion fails closed with 503 for requests and 502 for responses,
  including in `DetectionOnly`. The native engine charges nothing when no budget
  is attached.
- Built-in transformation bounds cover the expanding encoders (`urlEncode`,
  `utf8ToUnicode`, `base64Encode`, `hexEncode`), hashes, length, and case
  mapping. A custom transformation has no declared bound, so a transaction with
  a budget fails closed before invoking it rather than guessing its output.
- The admission budget is not a hard process-RSS cap. It does not account for
  Envoy memory outside the body copies, allocator slack beyond the requested
  capacity, audit-log copies made at finalization, operator-internal buffers, or
  host custom operator/transformation output. A stream under pressure can be
  rejected before reaching its individual body ceiling.
- Request/response trailers are bounded and passed through when allowed, but
  trailer values are not SecLang rule variables. Residual compressed bodies,
  WebSocket/CONNECT inspection, HTTP/3, and indefinite SSE/gRPC bodies are not
  supported as fully inspected content.
- The first release intentionally writes the compatibility filter-state names
  `wasm.io.coraza.waf.*` and `wasm.io.coraza.waf.v1.*`; the `wasm.` prefix is
  retained explicitly and is not added by the native SDK.
- The native module executes in Envoy's address space. Panic containment does
  not isolate allocation aborts, memory corruption, fatal signals, or blocked
  worker threads. Load only trusted local artifacts and roll binaries by
  restarting Envoy; safe module unloading is not established.

The [integration harness guide](../examples/envoy-coraza-dynamic/README.md)
covers local execution; [CI checks](../docs/ci.md) lists the reproducible test
jobs.
