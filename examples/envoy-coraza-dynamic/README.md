# Envoy Coraza native dynamic-module harness

Run the request/response enforcement cases against the Stage A-proven,
digest-pinned standalone Envoy 1.40.0 host with:

```sh
bash examples/envoy-coraza-dynamic/test-envoy.sh
```

Docker Compose, curl with HTTP/2 support, Python 3, Rust, clang, and libclang are
required. The harness reuses `examples/envoy-coraza/backend.go`, sends controlled
HTTP/1.1 body frames and trailers, tests two Envoy workers and multiplexed HTTP/2
streams, and installs the native module as a root-owned local file. The module
is never fetched remotely.

The script covers configuration rejection, request/response denial and
replacement, byte-exact uploads, trailer pass-through, cancellation recovery,
multi-worker and HTTP/2 deny/allow isolation, real-host 64 MiB admission
exhaustion/recovery, DetectionOnly, body-access-off, unmatched authority, empty
configuration, independent filter instances, and the feature-gated panic
regression. The adapter intentionally does not inspect trailer values as
SecLang variables.
The checked-in `envoy.yaml` uses `{}` as an explicit uninspected baseline; it is
not a protective policy configuration to deploy unchanged. Filter-state output
uses the explicit legacy `wasm.io.coraza.waf.*` compatibility keys.

The bootstrap is static and does not use xDS/ECDS. A live rejected filter
configuration update with in-flight requests is therefore not tested. See
`docs/envoy-coraza-dynamic-stage-e.md` for the Stage E acceptance results and
remaining gaps, and `docs/envoy-coraza-dynamic-stage-a.md` for the proven native
host callback semantics.
