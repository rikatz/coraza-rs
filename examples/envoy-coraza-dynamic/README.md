# Envoy Coraza native dynamic-module spike

This harness builds `envoy-coraza-dynamic` and runs its feature-gated probe in
the digest-pinned standalone Envoy 1.40.0 image. It also builds the default
artifact separately, without the panic probe:

```sh
bash examples/envoy-coraza-dynamic/test-envoy.sh
```

Docker Compose, curl, Python 3, Rust, and libclang are required. The script
uses Python's standard library to send controlled HTTP/1.1 body frames and
trailers. The Envoy image contains the native module as a root-owned,
non-writable file in `/opt/envoy/modules`; the module is loaded by local name
only, never fetched remotely.

The `filter_config` JSON object is only a transport smoke-test value. Stage A
does not parse or compile SecLang policy; Stage C will add the shared policy
parser. `x-coraza-probe` selects the temporary lifecycle behavior (`hold`,
`body`, `trailer`, `deny`, `replace`, `limit`, `panic`, or `panic-response`).
The two panic probes exist only in the non-default `panic-probe` build.

The script first proves the default artifact does not panic when the panic probe
header is present, then exercises rejected initial startup with missing,
corrupt, and wrong-architecture modules, unknown filter names, invalid JSON,
and invalid UTF-8; request-header stop and scheduled continuation; current and
buffered body observations; trailer EOS; request denial before backend contact;
response replacement; buffer-limit overflow while headers are held; and
feature-gated request/response panic containment with healthy follow-up traffic.
The bootstrap is static, not xDS/ECDS-backed, so it cannot exercise a live
rejected filter configuration update.

`envoy.yaml` keeps `ENVOY_DYNAMIC_MODULES_SEARCH_PATH` local to the image and
sets `do_not_close: true`, `load_globally: false`. Use the recorded Stage A
results in `docs/envoy-coraza-dynamic-stage-a.md`; this spike is not the full
Coraza enforcement adapter.
