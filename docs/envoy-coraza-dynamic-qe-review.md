# Envoy Coraza dynamic-module QE review

Review of the completed lane `1d0f11a..b624e0b` (branch `envoy-coraza-dynamic`)
against plan section 8, the stage evidence documents, and owner decisions 7, 10,
13, 14, and 16. This document is review evidence only: no implementation, test,
or harness file was changed.

Baseline audited: `b624e0b` (`Complete Stage F dynamic module evidence`).
Worktree: a clean checkout of that revision.

## 0. Method and what was actually executed

Read line by line: `docs/envoy-coraza-dynamic-module-plan.md`,
`docs/envoy-coraza-dynamic-stage-{a,c,d,e,f}.md`, `envoy-coraza-dynamic/src/{stream,abi,observability}.rs`,
`envoy-coraza-common/src/{config,policy,authority,observability}.rs`,
`envoy-coraza/src/stream.rs` (Wasm reference), `examples/envoy-coraza-dynamic/*`,
`examples/envoy-coraza/test-envoy.sh` (Wasm harness, as the reuse reference),
`benchmarks/envoy-dynamic/run.py`, `ftw-runner/{main,main_test}.go`,
`.github/workflows/{tests,msrv,release}.yaml`, `Makefile`, `.goreleaser.yaml`,
`Dockerfile.goreleaser-dynamic*`, `.dockerignore`, and the committed FTW and
benchmark JSON artefacts.

Executed in this worktree:

- `cargo test -p envoy-coraza-dynamic --offline` — **24 passed**, matching the
  Stage D claim, including all 18 `stream::tests`.
- `make lint` — **passed** on the reviewed revision.
- Arithmetic re-derivation of the FTW native/engine/Wasm failure sets from the
  committed manifests (see section 3).
- Re-derivation of the benchmark cancellation counts and RSS samples from
  `docs/performance/envoy-coraza-dynamic-stage-f/benchmark-summary.json`.
- Reading of the pinned go-ftw v2.1.0 marker-retry implementation
  (`config/types.go`, `runner/run.go`, `waflog/read.go`) to test the
  "non-reproducible" explanation for `944110-18`.

Not executed (environment): the real-host harness, the benchmark runner, the
go-ftw runs, and `cargo llvm-cov`. The reviewer therefore accepted nothing that
depends on those runs without checking the code or the committed artefact that
backs it. Where an evidence claim could only be checked by re-running a
container harness, that is called out.

## 1. Verdict summary

The evidence set is broad and mostly honest: the stage documents do not claim
what they did not run, the 24 unit tests exist and pass, the check matrix in
section 8 is largely mapped, and the FTW/benchmark numbers are internally
consistent with the committed artefacts. Two things stop this from being
shippable evidence under decision 7:

1. The native real-host harness is **not** at parity with the existing Wasm
   harness on exactly the cases where the native response path is new code
   (allowed-response byte exactness, `N-1`/`N`/`N+1` body limits, empty final
   bodies). Nothing in CI would catch a regression that truncated or corrupted
   an allowed response body.
2. The decision-14 CRS evidence is a one-shot manual run with **no checked-in
   reproduction path and no CI gate**, and its single unexplained intermittent
   failure (`944110-18`) recorded no rule match under load. The committed
   artefacts cannot distinguish "the rule did not run" from "the log line was
   lost", which is the one ambiguity a WAF evidence set must not have.

Silent gaps found: **12** (section 2.12). High and Critical findings: **7**.

## 2. Acceptance-matrix coverage map (plan section 8)

Legend: **COVERED** = an executed assertion proves the case; **UNIT** = shared
or mock unit test only (no real-host assertion); **INCOMPLETE** = deferred with
a reason in a named stage document; **GAP** = neither covered nor recorded.
Citations are `file:line` plus test or case name.

### 2.1 Configuration

| Case | Evidence | Status |
| --- | --- | --- |
| Plain JSON | `test-envoy.sh:216-225` (all policies), `envoy-coraza-common/src/config.rs:1003` `parses_all_keys` | COVERED |
| Compressed JSON (`config_gzip_b64`) | `config.rs:1549` `a_compressed_document_parses_like_the_plain_document`, `:1592`, `:1677`, `:1695`, `:1702` | UNIT (shared parser, unchanged) |
| Size/structure/decompression bounds | `config.rs:1515` `the_numeric_array_amplification_is_rejected_before_parsing`, `:1576` gzip bomb, `:1608` decompressed cap; `envoy-coraza-dynamic/src/abi.rs:115` oversize config | COVERED (unit) |
| Missing rule data | `policy.rs` `a_rule_data_file_that_is_missing_fails_the_policy` | COVERED (unit) |
| Skipped directive rejection | `policy.rs` `sec_ignore_rule_compilation_errors_cannot_drop_a_rule`, `a_skipped_include_budget_diagnostic_is_rejected` | COVERED (unit) |
| Unknown filter name | `abi.rs:115` + `test-envoy.sh:617-621` | COVERED |
| Exact/default/no authority | `authority.rs:200`, `test-envoy.sh:590-597`, `:632` (`crs.local`), `:371` (`off.local`) | COVERED |
| Normalized ports/IPv6 | `authority.rs:200` `authority_normalization_covers_case_default_ports_and_ipv6` (the two tests removed from `envoy-coraza/src/stream.rs` were relocated here, not dropped) | COVERED (unit) |
| Empty/off/detect policies | `test-envoy.sh:562-603`; `stream::tests::detection_only_and_body_access_off_complete_phase_two_without_holding_headers` | COVERED |
| Independent filter instances | `test-envoy.sh:605-615` (451/452) | COVERED |

### 2.2 Update

Every case in this row is live-xDS only. `test-envoy.sh` is static bootstrap
(config mounted read-only, `compose.yaml:28`). Stage C records generation
pinning as unit-only and live update as INCOMPLETE
(`docs/envoy-coraza-dynamic-stage-c.md:76-81`); Stage E repeats it
(`stage-e.md:75-76`).

| Case | Evidence | Status |
| --- | --- | --- |
| Valid update with old streams pinned | `stream::tests::streams_pin_the_generation_across_config_replacement` (pointer identity only, no behavior) | INCOMPLETE (Stage C) |
| Invalid update keeps old serving config | none | INCOMPLETE (collapsed into the single Stage C bullet; not named) |
| Rapid successive updates | none | INCOMPLETE (collapsed; not named) |
| Old/new-generation memory admission | `stream::tests::concurrent_reservations_never_cross_the_shared_limit` (counter only) | INCOMPLETE |
| No partial policy publication | `policy.rs` `an_invalid_directive_fails_the_whole_generation` | COVERED (unit) |

### 2.3 Input preservation

| Case | Evidence | Status |
| --- | --- | --- |
| Repeated/empty headers | none | **GAP** |
| Invalid UTF-8 where transport permits | none | **GAP** (Envoy rejects most header bytes before the filter; the matrix qualification is unaddressed) |
| Encoded URI/body values | `test-envoy.sh:640-645` (`%27%20OR%201%3D1`); FTW run | COVERED |
| URLENCODED/JSON/XML/multipart through Coraza processors | native harness forces `ctl:requestBodyProcessor=RAW` (`test-envoy.sh:216`); only the manual FTW run exercises the processors | UNIT/manual only |
| File upload rejection | `policy.rs:1214` `a_upload_directory_is_rejected`, `:1313` body-spill threshold | COVERED (unit, capability) |
| Unmodified allowed trailers | `test-envoy.sh:530-558` (request, backend sees trailer), `:417-432` (response trailer) | COVERED |

### 2.4 Blocking

| Case | Evidence | Status |
| --- | --- | --- |
| Phase-1 denial never reaches backend | `test-envoy.sh:366-369`; unit `phase_one_interruption_uses_rule_status_and_stops_before_forwarding` | COVERED |
| Phase-2 denial never reaches backend | `test-envoy.sh:482-486` (`backend_count /echo`) | COVERED |
| Phase-3/4 interruption | `test-envoy.sh:337-347` (phase 4 body, 451), `:394-415` (phase 3, 204/304), `:358-364` (engine limit 500) | COVERED |
| Response header rules with MIME-excluded / body-off body | `test-envoy.sh:371-385` (452, no leak); unit `phase_four_header_rules_run_at_headers_for_mime_excluded_and_body_off_responses` | COVERED |
| Generic replacement strips upstream headers/body/trailers | `test-envoy.sh:343-346`, `:361-364`, `:374-377`, `:382-385`, `:439-442` | COVERED |
| Supported redirects | `test-envoy.sh:387-392` (response 307 + Location + empty body), `:468-473` (request 307) | COVERED |
| Empty bodies for HEAD/204/304 | `test-envoy.sh:394-415`, `:452-466`, `:475-480` | COVERED |

### 2.5 Framing

| Case | Evidence | Status |
| --- | --- | --- |
| Empty/header-only request | `test-envoy.sh:232` (`GET /telemetry-allow`) | COVERED |
| Header-only/empty **response** (`/empty`, header EOS) | none — the Wasm harness tests this at `examples/envoy-coraza/test-envoy.sh:313-316`; the native harness does not port it | **GAP** |
| Zero-length final body (`Content-Length: 0` POST) | none | **GAP** |
| One frame | `test-envoy.sh:567-570` and `:576-579` (single `body-attack` POSTs with body comparison) | COVERED |
| Many frames | `test-envoy.sh:501-528` (four HTTP chunks), `:530-558` | COVERED |
| 16 KiB boundaries | `test-envoy.sh:508` (16383/1/16384/rest) — request only; no response-frame boundary case | Request COVERED, response **GAP** |
| Delayed chunks (complete upload) | none; `:66-93` delays only to abort the stream | **GAP** |
| Trailer EOS | `test-envoy.sh:530-558`; unit `trailer_termination_assembles_the_buffered_prefix_and_checks_trailers` | COVERED |
| `Expect: 100-continue` | none; `examples/envoy-coraza-dynamic/envoy.yaml` sets `proxy_100_continue: false`, so the path is not even exercised incidentally | **GAP** |
| No dropped/duplicated/reordered bytes | request: `test-envoy.sh:254-255`, `:283-284`, `:527-528`; response: only small bodies (`:342`, `:392`, `:430`) | Request COVERED, response **GAP** |

### 2.6 Limits

| Case | Evidence | Status |
| --- | --- | --- |
| Request `N-1`/`N`/`N+1` | none. The policy sets `SecRequestBodyLimit 16777216` but no boundary body is sent | **GAP** |
| Response `N-1`/`N`/`N+1` | `test-envoy.sh:358-364` only proves `N+1` for engine Reject (limit 5, body 29 bytes); `:444-450` only proves `N+1` at the 1 MiB host ceiling | Partial **GAP** |
| Reject / ProcessPartial / DetectionOnly | Reject: response only. Request Reject (413) never asserted. ProcessPartial: never exercised in either direction. DetectionOnly: request phases 1/2 only (`:562-570`) | **GAP** |
| `ctl` cannot raise host bounds / enable spill | `policy.rs:814` `every_policy_locks_the_audit_engine_and_body_ceilings` asserts the installed caps; no directive tries `ctl:requestBodyLimit` above the cap; `policy.rs:1313` rejects a spill threshold | Partial (cap installed, escalation untested) |
| Admission exhaustion | `test-envoy.sh:293-335` (4×13 MiB retained, fifth gets 503) | COVERED |
| Header/trailer budgets | response header budget: unit `response_header_budget_failure_returns_generic_502`; request-header 431 and request/response trailer budgets: no test | Partial **GAP** |
| Host overflow while headers are held | Stage A one-off 32-byte probe (`stage-a.md:60`); Stage C says the 16 MiB ceiling boundary is not established (`stage-c.md:71-74`); not repeated in Stage E/F | INCOMPLETE (Stage C only) |

### 2.7 Failures

| Case | Evidence | Status |
| --- | --- | --- |
| Missing native library | Stage A record only (`stage-a.md:136-142`); not in the committed harness | Recorded, **not reproducible** |
| Corrupt library | Stage A record only | Recorded, **not reproducible** |
| Wrong-architecture library | Stage A record only | Recorded, **not reproducible** |
| Configuration failure | `test-envoy.sh:617-629` (unknown name, invalid JSON, invalid UTF-8) | COVERED |
| Failed response mutation | Not reachable: SDK `send_response` is `void` (ledger row, `stage-d.md:121`); Wasm has a test (`failed_response_mutations_stay_paused`) with no native equivalent | Recorded in ledger, untestable |
| Upstream reset | `benchmarks/envoy-dynamic/run.py:534-557` (24/24 backend resets, 3 batches × 3 reps); benchmark is manual, not CI | Recorded (manual) |
| Client cancellation / slow upload | `test-envoy.sh:66-93`, `:286-291` | COVERED |
| Inline local reply / completion | `stream::tests::request_interruption_state_is_published_before_local_reply_even_if_it_fails`, `response_body_rule_uses_local_reply_from_encode_body_without_upstream_leakage`; real-host re-entry recorded in Stage A | UNIT + Stage A record |
| Never-decoded response | unit `never_decoded_stream_response_callbacks_pass_without_creating_state`; no real-host case (needs an Envoy-generated local reply that bypasses decode) | UNIT |
| Injected panic + poisoned cleanup | `test-envoy.sh:650-670` (500, no backend contact, reset on response panic, healthy follow-up) | COVERED |
| Follow with healthy traffic | `test-envoy.sh:669-670` | COVERED |

### 2.8 Concurrency

| Case | Evidence | Status |
| --- | --- | --- |
| At least two Envoy workers | `test-envoy.sh:238` passes `--concurrency 2`; nothing asserts the worker count, and nothing shows the two requests ran on different workers | **Claim not proven** |
| Concurrent HTTP/2 streams on one connection | `test-envoy.sh:257-284`; trace must contain streams `[1]` and `[3]`, which implies one connection | COVERED (overlap not asserted) |
| Deny/allow isolation | `test-envoy.sh:236-255`, `:257-284` | COVERED |
| Request cancellation | `test-envoy.sh:66-93`, `:286-288` | COVERED |
| Response cancellation | `benchmarks/envoy-dynamic/run.py:248-259`, `:534-557` (manual) | Recorded (manual) |
| Atomic budget contention | `stream::tests::concurrent_reservations_never_cross_the_shared_limit` | COVERED (unit) |
| Bounded RSS / no stuck streams after stress | benchmark RSS sampler (`run.py:331-375`); manual | Recorded (manual) |

### 2.9 Audit/state

| Case | Evidence | Status |
| --- | --- | --- |
| Phase 5 and audit once | `test-envoy.sh:348-349` (exactly one `stage-d-response-audit` line); unit `stream_completion_finishes_once_releases_admission_and_publishes_health_before_host_flush` | COVERED |
| Configured parts/relevance | `SecAuditEngine RelevantOnly` + `auditlog` on rule 8; parts selection (`SecAuditLogParts`) not configured or asserted | Partial |
| Bounded/sanitized output | `envoy-coraza-common/src/observability.rs:353` sanitizing, `:368` multibyte truncation; native `observability::tests::debug_events_use_bounded_control_escaped_text` | COVERED (unit) |
| Truncation disclosure | `request_body_truncated`/`response_body_truncated` are published (`stream.rs:1162-1177`) but no test ever produces a truncated body; the request path never sets `BodyPartiallyInspected` (`stream.rs:167-187`) | **GAP** |
| Filter state visible before access logging | `test-envoy.sh:234`, `:347`, `:355-356` | COVERED |
| No secrets in default health state | allow row asserts every legacy field is `-` (`:234`, `:355`); no assertion that bodies/matched values are absent from the audit record | Partial |
| No telemetry-based enforcement bypass | `request_interruption_state_is_published_before_local_reply_even_if_it_fails` | COVERED (unit) |

### 2.10 CRS (superseded by decision 14)

| Case | Evidence | Status |
| --- | --- | --- |
| Feature off/on | default + `embed-crs` builds; `policy.rs:968` `embedded_crs_compiles_and_blocks_a_sqli_request`; `cargo test --features embed-crs` in CI (`tests.yaml:178-179`) | COVERED |
| Current pinned complete CRS | `native-full.json` (5,231 tests, 669 rules); manual | COVERED (manual) |
| Configured overrides | `test-envoy.sh:632` (custom policy with `Include` + per-authority) | COVERED |
| Expected attack IDs + benign controls | `test-envoy.sh:640-648` (949110 + benign 200); FTW triggered-rule manifests | COVERED |
| Identical policy bytes / outcome vs Wasm | Deferred by decision 14 ("follow-up item"); `divergence-ledger.json` `interpretation.full_native_vs_wasm_outcome_diff = not performed` | INCOMPLETE (recorded) |

### 2.11 Capabilities

| Case | Evidence | Status |
| --- | --- | --- |
| No disk spill / upload / audit sink / blocking operator | `policy.rs:1313` spill rejected, `:1214` upload dir rejected, `:1230` audit target rejected, `:1386` `file_debug_sink_is_rejected_instead_of_opened_on_a_worker`, `audit_engine_on_uses_the_connector_sink_without_a_native_target` | COVERED (unit) |
| Residual compression / unsupported protocol tested | `test-envoy.sh:488-499` (request 415/501); response `Content-Encoding` path (`stream.rs:772-774`) has no test; compressed response FTW case `950020-2` fails for both adapters | Partial |

### 2.12 Silent-gap ledger

Cases that are **neither** covered **nor** recorded anywhere (the highest-value
finding class):

1. Repeated and empty request/response headers.
2. Invalid UTF-8 header bytes "where transport permits".
3. Zero-length final request body (`Content-Length: 0`).
4. A complete delayed-chunk upload (the only delayed writes abort the stream).
5. `Expect: 100-continue`.
6. Request body limit `N-1`/`N`/`N+1`, including the request Reject (413) path.
7. Response body limit `N-1`/`N` (only `N+1` is sent).
8. `SecRequestBodyLimitAction ProcessPartial` and `SecResponseBodyLimitAction ProcessPartial`.
9. Request header budget (431) and request/response trailer budgets.
10. An allowed response larger than one frame (byte-exactness and header
    preservation); the Wasm harness has this at
    `examples/envoy-coraza/test-envoy.sh:348-367`.
11. Header-only/empty response (`/empty`, empty EOS at response headers).
12. Truncation disclosure (`request_body_truncated` / `response_body_truncated`
    set and published in a real stream).

### 2.13 Recorded-but-unproven items (not silent, still open)

- Missing/corrupt/wrong-architecture library rejection: Stage A narrative only;
  no checked-in script, no CI case (finding Q4).
- Live xDS update: recorded, no harness (accepted per decision 10).
- Decode-phase request-denial access-log row: recorded INCOMPLETE
  (`stage-d.md:126`, `stage-e.md:77-80`).
- Full native-vs-Wasm CRS outcome diff: recorded as a follow-up by decision 14
  (but the decision-11 follow-up ledger file does not exist; finding Q15).
- arm64 full matrix: recorded (`stage-f.md:214-215`), QEMU smoke only.
- Wasm attribution of `950020-1`/`950020-2`: recorded INCOMPLETE
  (`stage-f.md:211-213`).

## 3. Verification of the stage-document claims

Claims I could check exactly, and the result:

| Claim | Check | Result |
| --- | --- | --- |
| `cargo test -p envoy-coraza-dynamic` passes 24 tests | ran it | **Confirmed** (24 passed, 0 failed) |
| `make lint` passes | ran it | **Confirmed** |
| Wasm test suite did not lose coverage when helpers moved | diffed test names, `1d0f11a` vs `b624e0b` | **Confirmed**: only `authority_normalization_covers_case_default_ports_and_ipv6` and `malformed_and_missing_authority_paths_are_explicit` left `envoy-coraza/src/stream.rs`; both exist in `envoy-coraza-common/src/authority.rs:200,228` |
| Coverage ignores no native path | `Makefile:207,209` regex lists only `envoy-libperfusion`, `main.rs`, and `xtask` files | **Confirmed** |
| Native FTW: 5,231 run, 5,163 passed, 68 failed | parsed `native-full.json` | **Confirmed** |
| Engine baseline: 5,215/16, identical with the no-spill policy | parsed both manifests | **Confirmed** (`engine-failed.txt` == `engine-same-memory-policy-failed.txt`) |
| Native-only failures are `944110-18` and `950020-2` | set difference `native-failed.txt` − `wasm-failed.txt` | **Confirmed** (exactly those two) |
| 66 common failures, 54 outside the engine baseline | set arithmetic | **Confirmed** (66 = 68 − 2; 54 = 66 − 12) |
| 4 engine failures pass natively | set difference | **Confirmed** (`920100-5`, `920100-8`, `920610-2`, `920620-1`) |
| Wasm focused run: 67 selected, 1 passed, 66 failed | parsed manifest | **Confirmed** |
| 944110-18 passed an isolated native rerun with 944110/944250/949110/980170 | `native-focused-944110-18.json` | **Confirmed** |
| Response cancellation: 24/24 resets in every batch | all `backend_upstream_resets` entries in `benchmark-summary.json` | **Confirmed** (6 groups × 3 batches × 3 reps, every value 24) |
| RSS recovery rise < 1 MiB across batches | compared `rss_recovery_bytes` batch 1 vs 3 | **Consistent** with the claim |
| Policy bytes shared by native and Wasm FTW runs | `sha256sum policy.json` | **Confirmed** (`efdece96…` matches `stage-f.md:24`) |
| Multi-worker exercised | searched harness for a worker-count assertion | **Not confirmed** (see Q3) |
| HTTP/2 multiplexing exercised | harness asserts stream IDs 1 and 3 in one prior-knowledge connection | **Confirmed** (weakly; overlap not asserted) |
| arm64 smoke covers each image | read `test-derived-image-smoke.sh` | **Partial**: the CRS images are smoked with a non-CRS policy, so arm64 CRS content is unverified (Q12) |

## 4. Findings

Severity: Critical/High are ship blockers under decision 7.

### Q1 (Critical) — The native harness does not test the allowed response body path, response limits, or empty final bodies

**Evidence.** The only byte-exact allowed-response assertions in
`examples/envoy-coraza-dynamic/test-envoy.sh` are 16-byte bodies:
`test-envoy.sh:417-432` (`trailer response`) and the empty-body cases
`:392`, `:415`, `:477`, `:480`. The multi-frame response path
(`stream.rs:812-908`, `StopIterationAndBuffer` then `Continue`) and the
trailer path (`stream.rs:910-994`) are otherwise exercised only by *denied*
responses, where the bytes are never compared, or by the 13-byte mock body in
`response_body_rule_uses_local_reply_from_encode_body_without_upstream_leakage`.

Meanwhile the existing Wasm harness, which the plan says to reuse
(`plan:58, 539-540`), has exactly the missing cases:
`examples/envoy-coraza/test-envoy.sh:281-310` (request and response
`N-1`/`N`/`N+1` for both Reject and ProcessPartial, `31/32/33` bytes) and
`:348-367` (1 MiB + 1 MIME-excluded response byte-exact, body-access-off
response byte-exact, `X-Large-Probe` preserved). The backend fixtures for this
already exist in `examples/envoy-coraza/backend.go:72` (`/empty`), `:75`
(`/large-uninspectable`), and `:89` (`/bytes/N`), but the native harness never
requests `/large-uninspectable`, `/bytes/*`, or `/empty` (grep of
`test-envoy.sh`).

**Impact.** A regression in `copy_terminal_response_body` (`stream.rs:1390-1412`),
in the `received_buffered` accounting (`stream.rs:834-849`), or in the buffer
limit release (`stream.rs:805-809`) could truncate, reorder, or corrupt an
allowed response and every committed automated check would still pass. This is
completion criterion 3 ("allowed data remains byte-exact") for the response
direction.

**Fix.** Port the three Wasm cases into `test-envoy.sh`: (a) `31/32/33`-byte and
1 MiB `N-1`/`N`/`N+1` bodies in both directions with both limit actions,
comparing the exact bytes; (b) a 1 MiB + 1 MIME-excluded `application/octet-stream`
allow with `cmp` and a header-preservation check; (c) `GET /empty`. Add a
`SecRequestBodyLimitAction Reject` authority so the request 413 path is asserted
without a backend hit.

### Q2 (Critical) — Decision-14 CRS evidence is not reproducible, not CI-gated, and the one intermittent failure is unexplained

**Evidence.** The lane adds `--target-addr`, `--target-port`, `--include-tests`
and `--log-file` to `ftw-runner` (`ftw-runner/main.go:63-66, 90-105, 421-451`)
but there is no checked-in script, Makefile target, or workflow step that starts
Envoy with `docs/performance/envoy-coraza-dynamic-stage-f/ftw/policy.json` and
runs the runner against it. `examples/envoy-coraza-dynamic/` contains only
`test-envoy.sh`, `test-switch-rollback.sh`, and `test-derived-image-smoke.sh`;
`.github/workflows/tests.yaml:134-182` adds only the harness jobs. The exact
commands, log capture mode, Envoy concurrency, and runner flags used for the
committed manifests are not recorded anywhere, so the 5,163/68 result cannot be
re-derived.

The intermittent failure is `944110-18`: in the full native run it took
**101.8 ms** and reported `triggered_rules: [[]]` (`native-full.json`
`results.runtime_ns` / `results.triggered_rules`); the isolated rerun took
11.2 ms and reported `[944110, 944250, 949110, 980170`
(`native-focused-944110-18.json`). The engine baseline reports the same four
rules at 4.8 ms. `triggered_rules` is parsed from the WAF log between go-ftw
markers, and go-ftw's marker search is 20 retries with no explicit wait between
them (`go-ftw/v2@v2.1.0/config/types.go:24` `DefaultMaxMarkerRetries = 20`,
`runner/run.go:215-240`, `waflog/read.go:201-247`). A 20-retry loop of
keep-alive marker requests is consistent with ~100 ms, so the most likely cause
is that the transaction's audit line had not been flushed when the end marker
was read — not that rule 944110 failed to run. The committed evidence cannot prove which,
because no per-test request/response or log slice was preserved.

**Impact.** This is the security-critical conformance evidence for decision 14,
and it currently has (a) no way to be re-run or re-gated and (b) one
observable "no rule applied" outcome under load. If it is a real miss, it is a
bypass; if it is a log race, the evidence standard ("better than the Wasm
artifact's", decision 13) is not met by an un-attributed flake.

**Fix.** (1) Check in `examples/envoy-coraza-dynamic/test-ftw.sh` (or a
`make test-envoy-dynamic-ftw` target) that starts the pinned image with the
committed policy and runs `ftw-runner` with the recorded flags, and run it in a
nightly/manual job. (2) Make the marker read deterministic: wrap the Envoy log
sink in a line-buffered writer (`stdbuf -oL`) or add a bounded sleep between
marker retries in `ftw-runner`, then rerun the full native suite at least twice
and record both failure sets. (3) For any remaining failure, preserve the request,
the response, and the log slice so `triggered_rules: []` can be read as either
"no match" or "line lost".

### Q3 (High) — The multi-worker claim is not proven

**Evidence.** `test-envoy.sh:238` starts Envoy with `--concurrency 2`
(`compose.yaml:21-22`), then runs one deny request and one 64 KiB allow request
concurrently (`:239-255`). No assertion reads the actual worker count (e.g. the
`server.concurrency` gauge on the admin listener, already exposed on port 9901),
and no request is tagged to show which worker served it. With one request on a
single worker the case would still pass. `docs/ci.md:24` and
`examples/envoy-coraza-dynamic/README.md:12` both state the harness "tests two
Envoy workers", which the harness does not establish.

**Impact.** Per-worker stream isolation is a release gate (`plan:532`,
completion criterion 3). A regression where a filter instance is shared across
workers (the exact thing `CatchUnwind`/`Arc<Generation>` design is meant to
avoid) would not be detected by this case.

**Fix.** After `wait_ready`, assert
`curl -s http://127.0.0.1:9901/stats | grep -E '^server.concurrency: 2$'` (or
`server.live`/`workers_started`), and make the two concurrent requests long
enough and repeated enough (e.g. 20 each) that a single worker cannot serve
them all, or record the worker id per request via a filter-state field.

### Q4 (High) — Missing/corrupt/wrong-architecture library rejection exists only as Stage A prose

**Evidence.** `expect_startup_rejection` (`test-envoy.sh:202-214`) is used for
exactly three mutations: `unknown-filter-name`, `malformed-json`, and
`malformed-utf8` (`:617-629`). Stage A's table
(`docs/envoy-coraza-dynamic-stage-a.md:136-142`) records six variants, including
the missing library, a non-ELF file, and a wrong `e_machine`. The Stage A probe
and its mutation commands are not in the tree, so the three unfiltered-traffic
negative controls cannot be re-run by anyone.

**Impact.** The plan's pinned proto warns that a failed dynamic-module load can
leave traffic unfiltered (`plan:103-106`; completion criterion 1). This is the
one failure where detection loss is a full bypass. A future image or config
change that turns a startup failure into a warning would ship with no failing
test. Stage C (`stage-c.md:56`) also narrowed its own claim to the three cases
that remain, without recording the other three as deferred.

**Fix.** Add three cases to `expect_startup_rejection`: mount an empty
`/opt/envoy/modules` (or a non-ELF file, or an ELF with `e_machine` patched to
`EM_AARCH64`) exactly as Stage A did, assert nonzero exit, and assert the
listener never serves (`curl --max-time 1` fails). Record them in
`stage-e.md`/`stage-f.md` as the current gate, or list them INCOMPLETE with the
missing fixture.

### Q5 (High) — No CI or harness coverage for the request/response body limits, ProcessPartial, or header/trailer budgets

**Evidence.** The native harness sets `SecRequestBodyLimit 16777216`
(`test-envoy.sh:216`) and never sends a near-limit body. Request Reject (413)
is unreachable in the harness because no authority uses
`SecRequestBodyLimitAction Reject` and no request exceeds a limit. ProcessPartial
is never configured. The unit tests do not cover `phase2`'s 413
(`stream.rs:1214-1231`), the request 431 paths (`stream.rs:456-465`, `:648-657`),
or the trailer budgets. The Wasm harness covers all of these
(`examples/envoy-coraza/test-envoy.sh:281-310`).

**Impact.** `plan:530` lists these as required, and `plan:328-331` requires the
engine boundary (`>=`) and `Reject`/`ProcessPartial` semantics to be preserved.
A change in the adapter's `body_size > MAX_REQUEST_BODY_BYTES` check
(`stream.rs:580-585`) or in the engine-limit mapping would ship silently. The
request 413 path is the documented fail-closed outcome for oversized bodies
(`stage-c.md:34`).

**Fix.** Same as Q1: add one "reject" and one "partial" authority with small
limits and send `N-1`/`N`/`N+1` bodies in both directions. Add unit tests for
`on_body`/`on_trailers` returning 413 and 431, and for a `ctl:requestBodyLimit`
above the configured cap remaining ineffective.

### Q6 (High) — Admission reservation release is never observed directly; panic and cancellation release are unverified for anything but gross leaks

**Evidence.** `BodyReservation::drop` and `StreamState::drop` release the
counter (`stream.rs:190-194`, `:223-227`), and both are unit-tested
(`admission_reservation_is_checked_and_released_on_drop`,
`drop_finalizes_transaction_when_completion_callback_is_missing`). But the
drop test uses a 17-byte reservation on a standalone `BodyReservation`, not a
`StreamState` that has retained bytes, and the `drop_finalizes…` test drops a
state whose reservation is zero (`stream.rs:2115-2151`). In the real host, every
"healthy follow-up" after cancellation (`test-envoy.sh:289-291`), admission
exhaustion (`:333-335`), and the response panic (`:662-670`) is a bodyless
`GET`, which reserves nothing. The only proxy for release is the unrelated
64 KiB upload much later at `:501-528`, which would only notice a leak larger
than ~63 MiB.

**Impact.** `plan:479` and Stage D's exit gate require "reservations released on
completion/reset/panic/drop". A leak of, say, one request body per reset would
accumulate across a process lifetime and eventually cause a 503 outage; nothing
here would catch it.

**Fix.** Expose the admission counter for tests (test-only filter state or an
admin `/stats` gauge), assert it returns to its pre-request value after
(a) a normal large upload, (b) the cancelled 2 MiB upload, and (c) the panic
reset with a retained body. If a counter cannot be exposed, make each follow-up
after a stress case a body large enough that a leak of the preceding stream's
reservation would fail closed.

### Q7 (High) — Fifty-four FTW failures that pass standalone are ledgered but not attributed, and the ledger cannot distinguish a connector defect from a harness difference

**Evidence.** `divergence-ledger.json` records
`failure_sets.common_not_in_engine_baseline` (54 IDs) and
`interpretation.shared_failures_not_native_specific: true`, with the prose
"not attributed more finely than common connector or FTW/Envoy harness
behavior" (`stage-f.md:74-78`). The manifests only contain pass/fail IDs,
`runtime_ns` and `triggered_rules`; `results.failures` is `["1 test(s) failed"]`
(`native-full.json`) with no expected vs actual status, stage, or body. Two
families in the shared-failure set are protocol enforcement (`920100-*`,
`932161-*`) and RCE (`932*`), which is exactly where a connector bug that
drops a header, body, or method would appear.

**Impact.** Decision 14 requires divergence-ledgering against the engine; the
ledger exists but its central claim ("shared, not native-specific") is inferred
from Wasm also failing, and a *shared* adapter-path defect is still a real
defect in the shipped artifact. The current artefacts cannot tell the reviewer
whether, for example, `911100-5` failed because a method or header never reached
the engine.

**Fix.** Capture, at minimum for a sample of the 54, the FTW stage
(expected/actual status, headers, body, and the log slice between markers) in
the run manifest, and add that to `divergence-ledger.json`. State an explicit
disposition per family (harness difference vs accepted connector difference) or
record it as a follow-up with the owner.

### Q8 (Medium) — The `received_buffered_*` branches are never exercised by any test, and the request/response handling is asymmetric

**Evidence.** Every test sets `received_buffered_request_body()` or
`received_buffered_response_body()` to `false`
(`stream.rs:1800`, `:1831`, `:1931`); no test uses `true`. The SDK documents the
`true` case as "a previous filter in the chain stopped and buffered the body,
then resumed" (`envoy sdk http.rs:1684-1690`). The request path then uses
`received_size` as the total (`stream.rs:563-573`) while the response path uses
`buffered_size` (`stream.rs:834-849`). One of those is likely misreading the
view; the response branch falls back to failing closed in some framings but
could pass through as an empty inspected body in others.

**Impact.** The native adapter is advertised for use in an Envoy filter chain
(`envoy.yaml:75-85`); this is the one documented inter-filter interaction, and
it is untested in both directions.

**Fix.** Add one unit test per direction with `received_buffered = true` and
buffered/received sizes set to the Stage A-observed shapes, asserting the
assembled inspection body. If the host cannot produce the shape, record it
INCOMPLETE with that reason instead of leaving the branch untested.

### Q9 (Medium) — Framing cases recorded nowhere: `Expect: 100-continue`, zero-length EOS, delayed chunks

**Evidence.** No test in the repository sends `Expect: 100-continue`; the native
bootstrap disables proxying it (`envoy.yaml` `proxy_100_continue: false`). No
test sends `Content-Length: 0` through the body hooks. No test sends a chunked
upload with a delay between chunks and then completes it (the delayed writer at
`test-envoy.sh:66-93` aborts instead). None of these is listed in any
INCOMPLETE section.

**Impact.** `plan:529` names all three explicitly. The `100-continue` case is
the one where a held-headers filter and Envoy's continue handling interact; a
regression there can hang or prematurely forward.

**Fix.** Add three Python-driven cases to `test-envoy.sh`: an `Expect:
100-continue` POST (with `proxy_100_continue` both false and true), a
`Content-Length: 0` POST, and a chunked upload with ~100 ms between chunks that
completes and is compared byte-for-byte.

### Q10 (Medium) — Truncation disclosure is unobservable in the evidence

**Evidence.** `request_body_truncated` is only ever set from
`transaction.request_body_stats().truncated` at finish (`stream.rs:176-179`),
never from the request path, and the request path never sets
`BodyPartiallyInspected` (contrast the response path, `stream.rs:796-802`). No
test produces a truncated body; the access-log format exposes
`request_truncated`/`response_truncated` (`envoy.yaml`), but no assertion reads
them with a non-`-` value.

**Impact.** `plan:533` requires "truncation disclosure". An operator relying on
`inspection_complete` could see `true` on a partially inspected request if this
wiring ever regressed.

**Fix.** Add a harness case with `SecRequestBodyLimitAction ProcessPartial` and a
body over the engine limit; assert `request_truncated=true`,
`inspection_complete=false` in the access-log row. Add the matching response
case.

### Q11 (Medium) — Response cancellation "closure" rests on a manual benchmark whose assertion is a timing proxy

**Evidence.** `cancel_response` opens `/slow-response` with a 0.1 s socket
timeout (`run.py:248-256`); for the WAF variants the expected status is `0`
(`run.py:538`), i.e. the test asserts the WAF withheld response headers for more
than 100 ms. The backend counter assertion (24/24) is good and the committed
data confirms it for all 54 batches, but (a) the run is manual,
(b) it proves the *client* aborted and the *backend* saw cancellation, not that
the filter released its reservation or finished the transaction, and (c) the
RSS evidence is a 20 ms `VmRSS` sampler with no module counter
(`run.py:363-374`). The following HTTP/2 workload is the only "not stuck" check.

**Impact.** Stage F claims this "closes the Stage E response-reset … deferrals"
(`stage-f.md:119-127`). It closes the observed-reset part, but the release and
exactly-once-finish parts are still inference.

**Fix.** Before calling this closed, add the admission-counter observation from
Q6 to the benchmark, or record explicitly in the stage doc that filter-side
release after response cancellation is inferred and not measured.

### Q12 (Medium) — arm64 artefact verification gaps and a mislabelled provenance field

**Evidence.** `test-derived-image-smoke.sh:93-101` configures the CRS images
with a plain `SecRuleEngine On` policy and never includes `crs/`. The release
step runs the same script for the `embed-crs` images (`release.yml:152-160`),
so "the CRS image loads and enforces" is proven but "the CRS image contains the
CRS" is not. Separately, `release.yml:188-200` passes
`verification=qemu-load-smoke-passed` to all four provenance manifests,
including the amd64 ones, so `arm64_verification` on an amd64 artefact claims a
QEMU smoke that did not happen.

**Impact.** A CRS build that silently failed to embed the rule set (e.g. a
build-arg or feature-name drift) would publish an image that passes its smoke
tests and denies nothing from CRS. Provenance readers are misled about which
architecture got which verification.

**Fix.** Have the smoke use a policy with `Include crs/rules/*.conf` and assert a
CRS denial for the CRS images (the module is already built with `embed-crs` in
that step). Emit `arm64_verification` only for the arm64 manifests or rename the
field to `verification_level`.

### Q13 (Medium) — `.dockerignore` re-includes the whole `target/` directory

**Evidence.** `.dockerignore` starts with `**` and then adds `!target/`
(`.dockerignore:12-13`), plus a now-unreferenced
`!target/envoy-coraza-dynamic-probe.so`. That makes the entire Cargo target
directory part of the build context for `examples/envoy-coraza-dynamic/Dockerfile`
(`compose.yaml`, `ENVOY_CORAZA_DYNAMIC_MODULE`), which the harness builds three
times per run.

**Impact.** In CI this uploads a multi-gigabyte context to the Docker daemon for
a one-file `COPY`, risking disk/time limits in the new 45-minute jobs; locally
it can leak unrelated build artifacts into the daemon context.

**Fix.** Ignore `target/*`, then re-include only the module files the Dockerfile
copies (e.g. `!target/*.so`), or copy the `.so` into a dedicated `dist/`
staging directory before `docker compose build`.

### Q14 (Medium) — Benchmark correctness checks are status and length only; the benchmark's HTTP/2 multiplex check is weaker than the harness's

**Evidence.** `run.py:198-208` returns `(status, latency, len(body))` and
`check_status` (`run.py:429-433`) compares status only; `check_status_counts`
compares status counts. No digest is computed, so a payload corrupted in place
(same length) passes every benchmark workload, including the 512 KiB and 64 KiB
body workloads. `run.py:307` counts all `OPENED stream` lines and requires at
least two, without asserting they belong to one connection (the harness does
this correctly at `test-envoy.sh:278-281`).

**Fix.** Return a SHA-256 of the response body for `/reflect` and assert it
equals the digest of the request payload; assert the trace's stream IDs are
`1` and `3` (one connection) as the harness does.

### Q15 (Medium) — Decision-10/11 ledger discipline gaps

**Evidence.** (a) `docs/envoy-coraza-dynamic-followups.md` (decision 11) does not
exist, although decision 14 explicitly names a follow-up (native-vs-Wasm CRS
outcome diff) and this review raises Medium/Low items that belong there.
(b) The Update row's four sub-cases are collapsed into one Stage C bullet that
names only "live configuration update with old in-flight streams"
(`stage-c.md:78-81`); "invalid update keeps old serving config" and "rapid
successive updates" are not named. (c) The Stage A missing/corrupt/wrong-arch
controls are not carried into any later stage's INCOMPLETE/covered list.
(d) Fuzz results (executions, seeds) are prose only; no log or corpus artefact
is committed, unlike the FTW and benchmark evidence.

**Fix.** Create the follow-up ledger with the decision-14 item and this review's
Medium/Low findings; expand the Update and startup-control bullets so each
matrix case has an explicit disposition.

### Q16 (Low) — Unit-test names overstate their assertions

**Evidence.** `body_phase_denial_reads_the_complete_buffer_once_and_is_terminal_before_reply`
(`stream.rs:1790-1818`) says "once" but sets no `.times(1)` on
`expect_get_buffered_request_body`, so a second read would still pass.
`streams_pin_the_generation_across_config_replacement` (`stream.rs:1654-1667`)
asserts only `Arc` pointer identity, not that the old stream still enforces the
old policy. `trailer_termination_assembles_the_buffered_prefix_and_checks_trailers`
counts the size getter once but not the body getter.

**Fix.** Add `.times(1)` on the load-bearing getters and add one old-generation
behavioral assertion (a request on the old stream still hits the old rule).

### Q17 (Low) — Harness/reporting cosmetics that can confuse triage

**Evidence.** `require_access_log` polls for up to 10 s (`test-envoy.sh:105-119`);
that is correct for an access logger but means a state-publication ordering
regression that still eventually writes the fields would pass. The 502
assertion at `:447-450` checks only the absence of the letter `z`, not the
generic body. `test-derived-image-smoke.sh:19` defaults `ENVOY_PLATFORM` to
`linux/arm64` and every message says "arm64" even when it runs amd64.

**Fix.** Assert the exact generic body strings and pass the platform explicitly;
consider asserting ordering by reading the log position of the access-log line
rather than merely its presence.

## 5. Assertion-quality assessment of the load-bearing guarantees

| Guarantee | Strongest assertion today | Would it catch a regression? |
| --- | --- | --- |
| Byte-exact request forwarding | `cmp` of multi-worker, HTTP/2, and 16 KiB-boundary uploads (`test-envoy.sh:254,283,527`) | Yes |
| Byte-exact response forwarding | 16-byte body only (`:430`); no large allowed response (`/large-uninspectable` unused) | **No** (Q1) |
| Deny never reaches backend | per-path `backend_count` before/after (`:240/253`, `:366/369`, `:482/486`) | Yes |
| Exactly-once finish/audit | one request, `grep -c` == 1 (`:348`) + unit `stream_completion…` | Mostly (single request, single stream) |
| Per-stream isolation | two filter instances (`:609-612`), deny/allow pair (`:251-253`) | Yes for policy isolation; not for worker isolation (Q3) |
| Reservation release | indirect: later 64 KiB upload; `BodyReservation` unit test | Only for leaks > ~63 MiB (Q6) |
| Panic fail-closed + healthy follow-up | `:658-670` | Yes for lifecycle, not for resource release |
| Response denial zero-leak | header/body/trailer greps (`:343-346`, `:361-364`, `:439-442`) | Yes |
| Filter state before access log | access-log row contains fields (`:347`) | Yes |
| CRS conformance | manual FTW (`native-full.json`) | Not gated (Q2) |

## 6. CI job correctness

**Verified correct.**

- `envoy-dynamic` (`tests.yaml:134-154`) and `envoy-dynamic-crs` (`:156-182`)
  run on `pull_request`/`push` to `main` with no `paths`/`if` filter, 45-minute
  timeouts, `permissions: contents: read`, and pinned `actions/checkout`. They
  are real gates.
- `libclang` is threaded through both composite setup actions
  (`setup-rust/action.yaml`, `setup-rust-lint/action.yaml`) and enabled for
  lint (`tests.yaml:40`), test (`:79`), feature-matrix (`:238`), MSRV
  (`msrv.yaml:33`), coverage (`coverage-check/action.yaml`), and both native
  jobs — every job that compiles the SDK. The Wasm jobs
  (`tests.yaml:86-132`) are untouched and do not install clang.
- `Makefile:52-60`: `build-envoy-dynamic` is
  `cargo build --locked --release -p envoy-coraza-dynamic`;
  `build-envoy-dynamic-crs` depends on `crs-fetch` and forwards
  `envoy-coraza-dynamic/embed-crs`; `test-envoy-dynamic` runs the harness. The
  names match what they do. The harness itself rebuilds default/CRS/panic
  modules, so the jobs' separate build steps are redundant but not wrong.
- `release.yml` adds QEMU + Buildx, builds
  `--platform linux/amd64,linux/arm64` inside per-arch containers (no host
  cross-compile), runs `readelf`/`ldd`/import-resolution checks, and runs the
  four image smokes. `goreleaser check` and snapshot evidence are recorded.
- `deny.toml` allow-lists only the Envoy git source (`deny.toml:36-40`);
  `.goreleaser.yaml` uses distinct asset names and separate image names with
  the pinned Envoy digest.

**Gaps.**

- No job runs the FTW conformance or the benchmark (Q2, Q11). The only
  security-conformance evidence for decision 14 is outside CI.
- No job exercises the missing/corrupt/wrong-architecture cases (Q4).
- The native jobs build the module three times (job step + harness default +
  harness CRS + harness panic, each in its own target directory:
  `test-envoy.sh:25-26, 220, 634, 650`). On a 4-core runner this is the main
  reason for the 45-minute timeout; a timeout here would look like a test
  failure, not a capacity problem. Consider a single pre-built default module
  and one CRS build, or a larger timeout.
- `envoy-dynamic-crs` runs `make test-envoy-dynamic`, which internally runs
  `make crs-fetch` again and rebuilds the default module; the CRS module the
  job pre-built is not the one the harness uses for the default portion. This
  costs time but does not weaken the gate.

## 7. Coverage and fuzz assessment

**Coverage.** `Makefile:206-209` runs `cargo llvm-cov nextest --workspace`
with a regex that excludes only `envoy-libperfusion/src/lib.rs`, `src/main.rs`,
and four `xtask` files; no native path is excluded, and
`cargo test --workspace` includes `envoy-coraza-dynamic` (verified: the 24 unit
tests run). The claimed 91.70% lines / 92.23% regions is therefore
*workspace-wide* and is not evidence of native-path depth. The native crate ships 24
unit tests, 18 of which cover a 1,414-line production module (2,152 lines with
its test module), and the untested branches above (Q8, Q9, Q10, Q5) are exactly
the ones the percentage would not reveal. Recommendation: add a
`-p envoy-coraza-dynamic` summary line
to `make coverage-check` so native-path depth is visible and tracked, without
lowering the workspace floor.

**Fuzz.** The three campaigns run (`coraza_uri_parser`, `coraza_json_body`,
`coraza_multipart_body`; `stage-e.md:59-61`) exist in
`coraza/fuzz/fuzz_targets/` and are the repository's standard parser targets.
Stage E's rationale ("no new native parser") is correct: `stream.rs` validates
lengths and copies bytes, and configuration parsing is the moved, unchanged
shared code. Under `plan:558` ("add a narrow adapter target only for new logic
that existing targets do not reach") no adapter target is required. Two caveats:
the configuration envelope (including the gzip member) has no fuzz target at
all, and it is now reachable from a second ABI, so a
`envoy_coraza_common_config` target would be cheap and worthwhile (Low); and the
campaign results are prose only — no seed, log, or corpus is committed
(Q15d).

## 8. Flakiness inventory

| Item | Dependency | Risk | Determinism fix |
| --- | --- | --- | --- |
| Port occupancy (`test-envoy.sh:56-58`, `test-switch-rollback.sh:36-41`, `test-derived-image-smoke.sh:34-39`) | host port 9901/10001/3000 | Fails fast and clearly | Already deterministic; consider ephemeral ports |
| `require_access_log` (`:105-119`) | access-log write latency, 10 s poll | Low; can mask ordering | Assert sequence position, not only presence |
| Admission exhaustion (`:295-332`) | four 13 MiB senders must be retained before the fifth reserves | Medium: a slow sender or Envoy flow control could delay a reservation and let the fifth succeed | Sample/await the module counter, or repeat until the 5th is denied and assert the first four were held |
| Client cancellation (`:66-93`) | 0.5 s `select` and RST | Medium | Assert the backend count after a bounded wait for connection teardown |
| Response cancellation (`run.py:248-256`) | 100 ms client timeout vs 320 ms backend stream | Low but timing-based; asserts a proxy behaviour, not a mechanism | Keep, but add the filter-side release observation (Q6) |
| `944110-18` (`native-full.json`) | go-ftw 20 no-wait marker retries vs Envoy log flush | High: already produced one unexplained failure | Line-buffer the log sink; add sleep between marker retries; rerun and record |
| `benchmark` startup/readiness (`run.py:184-196`) | Compose startup, 90 s | Low | Already bounded |
| arm64 QEMU smoke | QEMU availability and speed | Low (release-time only) | Already isolated in the release workflow |

## 9. Consolidation of decision-10 deferrals

| Deferred item | Recorded where | Adequate? |
| --- | --- | --- |
| Live LDS/ECDS update, old in-flight streams | `stage-c.md:76-81`, `stage-e.md:75-76`, `examples/.../README.md:27-29` | Yes, but sub-cases not named (Q15b) |
| Decode-phase request-denial access-log row | `stage-d.md:126`, `stage-e.md:77-80` | Yes |
| Response-side cancellation / measured RSS | `stage-d.md:135-138`, `stage-e.md:81-84`, closed in `stage-f.md:119-127` | Closed only for observed resets; release inference remains (Q11) |
| arm64 full matrix | `stage-f.md:214-215` | Yes |
| `950020` Wasm attribution | `stage-f.md:68-72, 211-213`; `divergence-ledger.json` `outcomes.wasm_full.status = INCOMPLETE` | Yes |
| Full native-vs-Wasm CRS diff | `divergence-ledger.json` `interpretation`, `stage-f.md:76-78` | Recorded, but no follow-up ledger file (Q15a) |
| Wasm full-run coverage after `950020-1` | Not quantified anywhere | **Implicit**: the number of unexecuted tests after the timeout is unknown |
| Detector benchmark gate | `stage-f.md:129-133` (not applicable; no `coraza`/`libperfusion` source change) | Yes, and the `git diff` claim checks out (only `coraza/fuzz/Cargo.lock`) |
| Config Struct transport (`plan:242-243`) | Not addressed in any stage document; `README.md` shows `StringValue` only; `test-switch-rollback.sh:77` uses `TypedStruct` for the Wasm side | **Implicit deferral** (Low) |

## 10. Required closure before ship (decision 7)

Must close (Critical/High): Q1, Q2, Q3, Q4, Q5, Q6, Q7. Recommended sequence:
port the Wasm limit/framing/byte-exactness cases (Q1, Q5), add the three startup
controls (Q4), assert worker count (Q3), check in and gate the FTW runner (Q2),
expose/observe the admission counter (Q6), and add per-test FTW detail plus a
family disposition for the 54 shared failures (Q7).

Goes to the decision-11 follow-up ledger: Q8-Q17, plus the implicit deferrals in
section 9 (post-timeout Wasm coverage count, `Struct` transport).

The performance gate in `AGENTS.md` is correctly recorded as not applicable for
the detector benchmarks (`stage-f.md:129-133`); the native-vs-Wasm Envoy
comparison follows the three-paired-repetition protocol in
`benchmarks/envoy-dynamic/run.py` and its metadata records the run order,
policy hashes, and runner digest. I did not re-run any benchmark, so I can
confirm the protocol and the internal consistency of the committed data, not the
numbers themselves.
