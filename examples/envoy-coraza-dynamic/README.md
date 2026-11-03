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

## Switch between Wasm and native

The two filters are alternatives. Replace the Wasm entry in the HTTP filter
chain with the native entry; **never configure both on one chain**. Both entries
must carry the exact same policy JSON bytes in their `google.protobuf.StringValue`
`value`. Do not translate, reformat, or otherwise change the policy during a
rollback.

The Wasm form wraps the JSON in `configuration`:

```yaml
- name: envoy.filters.http.wasm
  typed_config:
    "@type": type.googleapis.com/udpa.type.v1.TypedStruct
    type_url: type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
    value:
      config:
        name: envoy-coraza
        root_id: envoy-coraza
        failure_policy: FAIL_CLOSED
        allow_on_headers_stop_iteration: true
        vm_config:
          runtime: envoy.wasm.runtime.v8
          code:
            local:
              filename: /etc/envoy/envoy_coraza.wasm
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}
```

Replace that single list item with the native form, copying the JSON value
verbatim:

```yaml
- name: envoy.filters.http.dynamic_modules
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
    dynamic_module_config:
      name: envoy_coraza_dynamic
      do_not_close: true
      load_globally: false
    filter_name: coraza
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {"directives_map":{"default":["SecRuleEngine On"]},"default_directives":"default"}
```

The example JSON above is only a transport example; deploy the policy that has
been validated for your service, not this minimal policy.

Artifact installation differs. The Wasm filter uses the Wasm asset/WASMPlugin
or its OCI distribution. The native filter uses the matching, digest-pinned
Envoy 1.40.0 derived image (`ghcr.io/networking-incubator/coraza-rs-dynamic-envoy`
or `...-dynamic-crs-envoy`), or a locally installed `.so` at
`/opt/envoy/modules/libenvoy_coraza_dynamic.so` with
`ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/opt/envoy/modules`. Keep the module
root-owned and non-writable by Envoy's runtime UID, and roll the Envoy process
when replacing it; do not overwrite a loaded library.

Filter-state compatibility keys remain `wasm.io.coraza.waf.*` and
`wasm.io.coraza.waf.v1.*` with either adapter. Switching is not a filter-state
key migration. For rollback, switch the one filter-chain item back to the Wasm
entry and the Wasm artifact/image while keeping the policy JSON value unchanged.
Run `bash examples/envoy-coraza-dynamic/test-switch-rollback.sh` to exercise the
native entry, swap to the Wasm entry with the same policy bytes, and verify a
request denial and an allowed upload on each. The Stage F evidence records its
results.
