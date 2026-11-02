# Envoy Coraza dynamic-module Stage E evidence

Stage E adds repeatable native-module build/host checks and extends the real
Envoy harness to cover the previously unproven worker, HTTP/2, cancellation,
and retained-body admission cases. The pinned host is the Stage A pair:
standalone Envoy 1.40.0 from
`envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de`
(`linux/amd64`), with SDK revision
`9e5580933739775e8bce696a57a2e1bc99368f23` and ABI `v0.2.0`.

## Build and CI wiring

- Added `make build-envoy-dynamic`, `make build-envoy-dynamic-crs`, and
  `make test-envoy-dynamic`. The embedded build fetches the existing CRS pin in
  `envoy-coraza/crs.pin`; no second CRS pin or dependency was added. Existing
  Wasm targets are unchanged.
- Added `envoy-dynamic` and `envoy-dynamic-crs` jobs to
  `.github/workflows/tests.yaml`. Both use the pinned Envoy image through the
  harness; the CRS job additionally fetches CRS, builds with `embed-crs`, and
  runs the native CRS unit tests.
- Added opt-in `clang`/`libclang-dev` installation to the Rust setup actions and
  enabled it for workspace lint, test, feature-matrix, MSRV, and coverage jobs,
  plus both native jobs. The existing Wasm job setup remains unchanged.
- Added the native module and common crate to the root workspace map and
  documented native build prerequisites and limits in
  `envoy-coraza-dynamic/README.md`.

## Acceptance cases exercised on the real host

All four Stage E cases requested for the harness passed on this host:

| Case | Result |
| --- | --- |
| Multiple Envoy workers | Started Envoy with `--concurrency 2`; ran deny and byte-exact 64 KiB allow requests concurrently. The deny returned 451 without backend contact; the allowed upload was unchanged. |
| HTTP/2 stream multiplexing | Sent concurrent deny/allow transfers using curl prior-knowledge HTTP/2, capped to one connection. Both reported HTTP/2; trace stream IDs 1 and 3 verified multiplexing on one connection. The deny did not reach the backend and the allowed binary body was exact. |
| Client cancellation | Sent a slow 2 MiB prefix of an 8 MiB declared upload, reset the connection before EOS, verified no backend contact, and received a healthy follow-up response. |
| Admission exhaustion and recovery | Kept four incomplete 13 MiB request bodies retained, then opened a fifth below the per-stream 16 MiB ceiling. It received 503 when the module-wide 64 MiB admission budget was crossed. Reset the retained streams and verified a healthy follow-up response. No counters or metrics were added. |

The harness also retains the Stage C/D request, response, trailers, local-reply,
telemetry, CRS, panic, and startup-rejection checks. It checks that port 9901 is
free before starting its Compose stack and does not stop any unrelated process.

## Required checks

| Check | Result |
| --- | --- |
| `make lint` | Passed. |
| `make test` | Passed. |
| `make lint-extra` | Passed, including taplo, shellcheck, typos, and actionlint. |
| `make audit` | Passed. Cargo deny emitted the existing duplicate-version and unused-license-allowance warnings; no dependency was added. |
| `make build-envoy-dynamic` | Passed. |
| `make build-envoy-dynamic-crs` | Passed with the existing CRS v4.30.0 pin. |
| `make build-envoy-wasm` | Passed; the Wasm artifact remains buildable. |
| `bash examples/envoy-coraza-dynamic/test-envoy.sh` | Passed on the pinned host, including the four cases above. |
| `make test-envoy-dynamic` | Passed. |
| `bash examples/envoy-coraza/test-envoy.sh` | Passed; the existing Coraza Wasm harness remains green. |
| `bash examples/envoy-libperfusion/test-envoy.sh` | Passed, as required for Envoy adapter changes. |
| `actionlint` on `tests.yaml` and `msrv.yaml` | Passed with the repository's documented ignore for local `$/.github/...` action references. |
| Focused fuzz: `coraza_uri_parser` | Passed, 60 seconds / 827,324 executions; no crash. |
| Focused fuzz: `coraza_json_body` | Passed, 60 seconds / 490,053 executions; no crash. |
| Focused fuzz: `coraza_multipart_body` | Passed, 60 seconds / 540,087 executions; no crash. |
| `make coverage-check` | Passed both reports. Default workspace coverage was 91.70% lines / 92.23% regions; the `coraza --all-features` report also met the configured 90% / 80% floors. Native code was not added to the ignore regex. |

No new adapter fuzz target was warranted: Stage E adds no native parser or
configuration-envelope implementation, and the lifecycle transitions remain
unit-tested. The existing parser campaigns above were run as requested. Cargo
refreshed `coraza/fuzz/Cargo.lock` to include `indexmap`, already declared by
`coraza`; this changes no production dependency or package version.

## Remaining INCOMPLETE items

These are recorded rather than inferred from the successful cases, per decision
10:

- Live LDS/ECDS configuration replacement with in-flight old-generation
  streams: the checked-in harness uses static bootstrap configuration.
- Request decode-phase denial visibility in the example file access logger:
  Stage D found that this HCM path did not emit a file-logger row for the local
  reply. Filter state is still published before the reply; formatter visibility
  for that request path is not demonstrated.
- Response-side cancellation/upstream-reset stress and a measured RSS/load
  campaign: the new cancellation case is a downstream request upload; admission
  behavior is verified, but there are intentionally no module counters and no
  process-memory bound is claimed.
- Full go-ftw CRS conformance and a complete native-versus-Wasm CRS outcome
  comparison were not run in this stage.
- Response decompression, trailer variables, and indefinite/binary protocol
  classes remain outside the documented inspection contract.

Release packaging, benchmarks, and arm64 verification remain Stage F and were
not started. The native crate README was absent from this worktree despite the
Stage A path list, so Stage E created the requested README rather than editing
an existing file.
