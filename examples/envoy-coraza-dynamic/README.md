# Envoy Coraza native dynamic-module harness

Run the Stage C request-enforcement cases against the Stage A-proven,
digest-pinned standalone Envoy 1.40.0 host with:

```sh
bash examples/envoy-coraza-dynamic/test-envoy.sh
```

Docker Compose, curl, Python 3, Rust, and libclang are required. The harness
reuses `examples/envoy-coraza/backend.go`, sends controlled HTTP/1.1 body frames
and trailers, and installs the native module as a root-owned local file. The
module is never fetched remotely.

The script covers configuration rejection, phase-1 and phase-2 denial before
backend contact, byte-exact fragmented uploads and trailers, DetectionOnly,
body-access-off, unmatched authority, empty configuration, independent filter
instances, and the feature-gated request panic regression. The request-side
adapter intentionally does not inspect trailer values as SecLang variables.
The checked-in `envoy.yaml` uses `{}` as an explicit uninspected baseline; it is
not a protective policy configuration to deploy unchanged.

The bootstrap is static and does not use xDS/ECDS. A live rejected filter
configuration update with in-flight requests is therefore not tested. See
`docs/envoy-coraza-dynamic-stage-c.md` for the Stage C evidence and remaining
gates, and `docs/envoy-coraza-dynamic-stage-a.md` for the proven native host
callback semantics.
