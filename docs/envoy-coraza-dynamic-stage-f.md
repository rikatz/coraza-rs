# Envoy Coraza dynamic-module Stage F evidence

Stage F adds CRS FTW evidence, an apples-to-apples Envoy benchmark, native
release assets/images, and a tested switch/rollback path. The pinned host is
Envoy 1.40.0, image
`envoyproxy/envoy:v1.40.0@sha256:459f2a6404c340fe6afccd69d85527012d47f3c036765493e6f8f3113fa384de`.
The SDK is `9e5580933739775e8bce696a57a2e1bc99368f23`.

## 1. go-ftw CRS run and divergence ledger

`make crs-fetch` verified the pinned v4.30.0 minimal archive against
`envoy-coraza/crs.pin` (SHA-256
`3d678a41fd5aade34760127fef5dd64fd7a77848913fc0f70dde0cf467c94427`). The
matching full source checkout was the v4.30.0 tag at commit
`e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`. The 327-file test tree came from
that checkout. Its `rules/` files and `crs-setup.conf.example` compared
byte-for-byte with the `make crs-fetch` tree.

The FTW runner now supports an external request target and log file while still
starting its strict Rust engine server to validate the 669-rule inventory. It
also writes each test ID, outcome, duration and triggered rule IDs to its
manifest. The Envoy upstream gained the `/reflect` behavior used by CRS FTW.
Both adapters were tested with the same `StringValue` policy bytes; SHA-256 is
`efdece96253833e17374a3f18e1faa3e9ed44a141952448b53b5b6e8535fe6de`. The
effective request/response limits, rule bytes, phase policy and audit settings
were shared. The 13.1 MiB request in-memory limit is explicit because these
connectors prohibit rule-body spill to disk.

| Target | Inventory/run | Passed | Failed | Skipped/ignored |
| --- | ---: | ---: | ---: | ---: |
| Standalone Coraza FTW server, baseline | 327 files / 5,231 tests / 5,237 stages | 5,215 | 16 | 0 / 0 |
| Native filter in Envoy | 327 files / 5,231 tests / 5,237 stages | 5,163 | 68 | 0 / 0 |
| Native filter in Envoy, deterministic full rerun (`native-rerun-20261103T100830Z`) | 327 files / 5,231 tests / 5,237 stages | 5,164 | 67 | 0 / 0 |
| Wasm full run | Stopped at `950020-1` | — | — | — |
| Wasm focused comparison | 67 of the 68 native-failed IDs | 1 | 66 | 0 / 0 |

The standalone baseline was rerun with the same no-spill request-memory limit
used by the Envoy policy; it produced the same 5,215/16 result. Its 16 failures
are the known Apache-vs-Go expectations documented by the FTW runner. The
per-test manifests and failure lists are preserved under
[`docs/performance/envoy-coraza-dynamic-stage-f/ftw/`](performance/envoy-coraza-dynamic-stage-f/ftw/):

- `engine-standalone.json` / `engine-failed.txt`: original engine baseline.
- `engine-same-memory-policy.json` / `engine-same-memory-policy-failed.txt`:
  engine baseline with the Envoy-compatible no-spill limit.
- `native-full.json` / `native-failed.txt`: all native test outcomes.
- `native-rerun-20261103T020831Z/`: earlier completed full-suite run (5,163
  passed, 68 failed; `944110-18` passed). Its runner completed, but wrapper
  post-processing was interrupted; the manifest and compressed log are retained
  as supplementary evidence.
- `native-rerun-20261103T100830Z/`: fresh full-suite manifest, failure list,
  marker-bracketed Envoy access log (`envoy-access.log.gz`), runner log, and run
  metadata. The 54 MiB access log is gzip archived; its decompressed SHA-256 is
  recorded in `run-metadata.json`. The runner exits nonzero for the 67 remaining
  CRS expectation failures; all 5,231 tests ran and the failure set introduced
  no new IDs.
- `wasm-native-failures-except-950020-2.json` / `wasm-failed.txt`: focused
  Wasm outcomes for the native failure set excluding the timeout case.
- `policy.json`: the policy bytes used by native and Wasm.

The checked-in reproduction path is `make test-envoy-dynamic-ftw`, implemented
by `examples/envoy-coraza-dynamic/test-ftw.sh`. With no selection it runs the
full pinned 5,231-case suite and writes a new `native-rerun-*` directory here;
it preserves the historical artifacts above. It checks out CRS tests at
`e03a4f6dabc7a30ebd8c52c97d28a154f590a48f`, uses the pinned module policy and
Envoy image, collects marker-bracketed Envoy status/path lines, and spaces go-ftw
marker retries by 25 ms (at most 100 attempts). The manifest also records
per-test expected/observed statuses and triggered rules where the failed test
and access-log brackets provide them. `enrich-ftw-ledger.py` joins those fields
to engine/Wasm outcomes and leaves unresolved cases explicitly undecided.

CI runs a bounded ten-case set: five prior shared failures and five previously
passing controls. Four residual failures are allow-listed; `944110-18` must pass
under the deterministic marker wait. The job detects new failures but is not a
full-suite or native/Wasm parity claim.

### Failure attribution

The exact set arithmetic is preserved in
[`divergence-ledger.json`](performance/envoy-coraza-dynamic-stage-f/ftw/divergence-ledger.json).

- **66 cases failed in both adapters.** Twelve overlap the standalone engine's
  known failure set; the other 54 pass in the standalone engine but fail in the
  shared Envoy/FTW path. They are not native-only divergences. The raw manifests
  give the exact IDs, outcomes and triggered IDs; `911100-5` is one concrete
  example: the standalone engine expects rule 911100, while the Envoy run saw
  only the FTW markers and no 911100 match in either adapter.
- Native passed four cases that failed in the standalone baseline:
  `920100-5`, `920100-8`, `920610-2` and `920620-1`.
- **`944110-18` was a non-reproducible native full-run failure.** Its isolated
  native rerun passed and recorded rules 944110/944250/949110/980170; the
  focused Wasm run also passed it. See
  `native-focused-944110-18.json`. The complete native manifest retains the
  original failure rather than rewriting history.
- The deterministic full rerun and the CI subset both pass `944110-18` with
  triggered rules `[944110, 944250, 949110, 980170]`; the marker-bracketed
  Envoy access log records `POST /post` with status 200. The runner now spaces
  marker retries by 25 ms, bounded to 100 attempts; the historical full-run
  failure remains preserved above.
- **`950020-2` remains INCOMPLETE for Wasm attribution.** Native reported a
  failure in the full run; Wasm's full run timed out in the response-compression
  case (`ReadTimeout=30s`) and a targeted retry of `950020-2` also timed out.
  This is the known unsupported compressed-response path, not a claimed pass.
  The Wasm run did pass `944110-18` and all other selected cases completed.

The divergence ledger now records expected-status assertions (null where FTW
does not assert a status), observed status/path, triggered-rule arrays for the
native, Wasm and standalone engine, and a disposition for each of the 54 shared
failures. Eleven have status 400 with no parsed path, a candidate Envoy/harness
pre-routing rejection; the other cases have varied 200/4xx status-path pairs
but no native or Wasm expected-rule match. All 54 are classified as connector-or-harness, not
engine-wide, with exact attribution explicitly **undecided** because the
filter-visible request bytes were not retained. The ledger names the bounded
filter-input capture needed to decide those cases. A complete Native-vs-Wasm
outcome diff remains a later decision-14 follow-up.

The full native suite and the ten-case CI regression subset both ran through the
checked-in path. CI completed with four allow-listed baseline failures, no new
failures, and `944110-18` passed; the subset is not a full CRS conformance or
parity claim.

## 2. Benchmarks and deferred stress items

`benchmarks/envoy-dynamic/run.py` compares no-WAF Envoy, Wasm Coraza and the
native module with the pinned Envoy image and identical Go backend. The Wasm
and native policy hashes match per ruleset; audit output and HCM access logs are
disabled for all variants. There is no compressed traffic. Envoy uses two
workers, offered concurrency is 16, and the workload generator is CPU-affined
to one available CPU. The host exposes CPUs 0–1 for the containers. For each
ruleset, the three paired run orders were control/Wasm/native,
native/control/Wasm, then Wasm/native/control.

The workloads cover benign, phase-1 and phase-2 denials; 1 KiB and 512 KiB
JSON bodies; 64 KiB chunked uploads; deny/allow isolation with two Envoy
workers; and multiplexed HTTP/2. Startup/configure time is measured from Compose
startup until Envoy readiness. CPU is the Envoy-plus-backend cgroup CPU-time
delta; RSS is the sampled sum of their process `VmRSS` values. The 20 ms RSS
sampler and CPU counters, per-request latencies, status counts and raw inputs
are preserved in
[`benchmark-raw.json`](performance/envoy-coraza-dynamic-stage-f/benchmark-raw.json).
Per-workload medians and min/max ranges for throughput, p50/p95/p99, CPU and
peak RSS are in
[`benchmark-summary.json`](performance/envoy-coraza-dynamic-stage-f/benchmark-summary.json).

Selected medians (throughput is requests/s; latency is ms; RSS is MiB):

| Rules | Variant | Startup s | Benign p50/p95/p99 | Early deny p50/p95/p99 | Large body rps / p95 | Peak RSS, benign / large |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Minimal | No WAF | 1.059 | 4.80 / 14.49 / 17.88 | 4.00 / 7.07 / 8.78 | 385.8 [315.6–398.6] / 27.45 | 74.4 / 89.4 |
| Minimal | Wasm | 2.558 | 5.63 / 21.64 / 26.25 | 2.69 / 5.07 / 7.07 | 250.5 [236.5–256.1] / 45.37 | 212.9 / 240.2 |
| Minimal | Native | 1.123 | 6.26 / 20.39 / 23.59 | 2.68 / 4.81 / 5.42 | 279.1 [247.3–290.8] / 41.70 | 77.7 / 106.9 |
| Pinned CRS | No WAF | 1.052 | 5.12 / 16.91 / 22.21 | 3.57 / 5.97 / 6.55 | 404.2 [376.9–405.9] / 27.49 | 74.0 / 89.6 |
| Pinned CRS | Wasm | 3.296 | 18.02 / 40.12 / 44.17 | 13.04 / 30.49 / 32.66 | 5.7 [5.4–5.8] / 2,105.15 | 324.9 / 366.8 |
| Pinned CRS | Native | 1.347 | 14.07 / 35.06 / 42.80 | 11.58 / 21.72 / 25.83 | 9.9 [9.9–10.4] / 1,207.11 | 122.6 / 171.2 |

There is no asserted speedup target. On these workloads the native CRS run had
lower startup/configure time and RSS than Wasm, while both filters paid a large
CRS/large-body cost versus no WAF. The repeated ranges, not a single best run,
are authoritative; see the summary JSON for every workload.

The response-side cancellation gate ran three batches of 24 slow responses for
each Envoy variant/ruleset/repetition. The backend observed 24/24 upstream
cancellations in every batch. A successful HTTP/2/healthy follow-up workload
ran after each cancellation stress. Recovery RSS had no upward trend across the
three batches in a process; the largest first-to-third increase was under
1 MiB. The raw file keeps
each sample. This closes the Stage E response-reset and measured-load-RSS
deferrals for this bounded stress profile; it is not a hard process-memory
bound or an unbounded-load guarantee.

The detector benchmark gate is **not applicable**: `git diff
1d0f11ac96a57670e6e4f4f30d1e2e0eb18074f8 -- coraza/ libperfusion/` shows no
production `coraza` or `libperfusion` source change (the only `coraza/` path
change is the existing Stage E `coraza/fuzz/Cargo.lock`). No detector behavior
changed.

## 3. Release assets and multi-architecture verification

`.goreleaser.yaml` now stages and checksums these distinct assets:

- `coraza-rs-dynamic.so` and `coraza-rs-dynamic-crs.so` (amd64).
- `coraza-rs-dynamic-linux-arm64.so` and
  `coraza-rs-dynamic-crs-linux-arm64.so`.
- One JSON provenance manifest per library, with source revision, SDK commit,
  pinned Envoy digest, Rust/Clang versions, enabled features, target, library
  SHA-256 and arm64 verification level.

The release workflow builds `.so` files inside per-target BuildKit containers
based on the exact Envoy 1.40.0 digest; it does not cross-compile the SDK on the
host. The GoReleaser derived images are
`ghcr.io/networking-incubator/coraza-rs-dynamic-envoy` and
`ghcr.io/networking-incubator/coraza-rs-dynamic-crs-envoy`. Both use the pinned
base, install the module root-owned/non-writable at `/opt/envoy/modules`, set
`ENVOY_DYNAMIC_MODULES_SEARCH_PATH`, and use the existing nightly/manual tag
templates under separate names.

Local Buildx builds passed for amd64 and arm64. The default and CRS images for
both architectures passed `test-derived-image-smoke.sh` (arm64 under QEMU).
Each smoke loaded the module, rejected an unknown filter name at startup,
denied before backend contact, allowed the backend response unchanged, and
passed `ldd`. `readelf` verified x86-64/AArch64 ELF machines and
the exported module-init, HTTP-filter config, request-header and response-header
hooks. Both architectures depend on `libc.so.6`, `libgcc_s.so.1` and the
architecture-specific glibc loader; the observed GLIBC symbol ceiling was
`GLIBC_2.34`, below the pinned image's glibc 2.35. Provenance labels the arm64
level `qemu-load-smoke-passed`. The arm smoke read every module's undefined
`envoy_dynamic_module_callback_*` symbol and matched all 216 imported names to
the pinned arm64 Envoy executable's dynamic exports (including weak host
exports); no imports were missing.

`goreleaser check` and `goreleaser release --snapshot --clean` passed. Snapshot
created local images for both architectures and did not push them. No GitHub
release, GHCR push, or multi-arch registry manifest publication was performed;
the owner's nightly/tag action remains the publish step.

## 4. Switch and rollback proof

[`examples/envoy-coraza-dynamic/README.md`](../examples/envoy-coraza-dynamic/README.md)
documents replacing the Wasm filter-list entry with the native
`envoy.filters.http.dynamic_modules` entry, keeping the `StringValue` JSON
identical, changing the artifact/image, preserving
`wasm.io.coraza.waf.*` filter-state keys, and never stacking both filters.

`bash examples/envoy-coraza-dynamic/test-switch-rollback.sh` ran the native
harness entry first, then swapped to the Wasm entry with the exact same policy
SHA-256 `c946a9879384c9539112032015908f8006577e5095e3af0e2bbb89ceb326bd2e`.
Both returned the configured phase-1 451 and phase-2 429 without backend
contact, then passed an allowed upload byte-exactly. This is a bootstrap switch
smoke, not live xDS update testing.

## 5. Required checks

| Check | Result |
| --- | --- |
| `make lint` | Passed. |
| `make test` | Passed (workspace tests and doc tests). |
| `make lint-extra` | Passed, including typos, taplo, actionlint and shellcheck. |
| `make audit` | Passed; cargo-deny printed existing duplicate-version and unused-license-allowance warnings. |
| `make build-envoy-dynamic` | Passed. |
| `make build-envoy-dynamic-crs` | Passed with pinned CRS v4.30.0. |
| `make build-envoy-wasm` | Passed. |
| `bash examples/envoy-coraza-dynamic/test-envoy.sh` | Passed on pinned Envoy 1.40.0. |
| `bash examples/envoy-coraza/test-envoy.sh` | Passed; Wasm harness remains functional. |
| `bash examples/envoy-libperfusion/test-envoy.sh` | Passed (additional adapter gate). |
| `bash examples/envoy-coraza-dynamic/test-switch-rollback.sh` | Passed; same policy bytes, 451/429 denies and byte-exact allow on both filters. |
| amd64 default/CRS derived-image smoke | Passed; load, invalid-filter rejection, deny, allow and `ldd`. |
| arm64 default/CRS derived-image smoke | Passed under QEMU; import resolution, load, invalid-filter rejection, deny, allow and `ldd`. |
| `actionlint .github/workflows/release.yml` | Passed with the repository's `$/.github/...` ignore. |
| `goreleaser release --snapshot --clean` | Passed; local-only, no push. |

## INCOMPLETE / limits

- Full Wasm CRS FTW conformance cannot complete because `950020-1` and the
  targeted `950020-2` gzip-response case hit the runner's 30-second read
  timeout. Their Wasm attribution remains INCOMPLETE.
- The full acceptance matrix remains amd64. Arm64 received the required QEMU
  load/smoke and ELF/dependency checks, not the complete functional matrix.
- The benchmark host had only CPUs 0–1 available; the generator shared CPU 0
  with one Envoy/backend-allowed CPU. CPU percentages are aggregate Envoy plus
  backend CPU time normalized to one core and show scheduler variance on the
  short workloads.
- Live LDS/ECDS replacement and decompression remain out of scope.
