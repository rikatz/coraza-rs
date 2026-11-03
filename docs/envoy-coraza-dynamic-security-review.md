# Security review: native Envoy Coraza dynamic module

Reviewer role: adversarial security review, separate from the implementation lane
(owner decision 8). This review reports only; it changes no code.

| Item | Value |
| --- | --- |
| Reviewed revision | `b624e0b` (branch `envoy-coraza-dynamic`) |
| Diff range | `1d0f11a..b624e0b` |
| Contract | [envoy-coraza-dynamic-module-plan.md](envoy-coraza-dynamic-module-plan.md), sections 2, 3, 5, 6, 11 |
| Threat model | WAF enforcement filter executing unsandboxed inside Envoy; every request and response byte is hostile |
| Severities | Owner decision 7: Critical/High block the ship; Medium/Low go to the follow-up ledger |

## Summary

| ID | Severity | Title | Location |
| --- | --- | --- | --- |
| H-1 | **High** | Macro-expanded redirect target is emitted as a `Location` header without CR/LF validation (response splitting) | `envoy-coraza-dynamic/src/stream.rs:316`, `:401`-`:403` |
| M-1 | Medium | EOS admission charges 3x the body; three concurrent 16 MiB uploads starve all body inspection, and the acceptance case only exercises the 1x incomplete-body path | `envoy-coraza-dynamic/src/stream.rs:596`-`:606`, `:680`-`:690`, `:1017`-`:1030` |
| M-2 | Medium | Filter-state publication failures are counted and never reported, so denial telemetry can be lost silently | `envoy-coraza-dynamic/src/stream.rs:420`, `:1040`, `:1185`; `envoy-coraza-common/src/observability.rs:38`-`:48` |
| M-3 | Medium | CRS FTW evidence cannot distinguish harness artifacts from detection gaps for 54 shared Envoy-path failures; a cluster of RCE/XSS/SSRF tests triggers no rule at all | `docs/performance/envoy-coraza-dynamic-stage-f/ftw/*` |
| L-1 | Low | Audit sanitizer preserves `\n`, allowing log-line injection from attacker-influenced audit content | `envoy-coraza-common/src/observability.rs:225`-`:227` |
| L-2 | Low | Shared policy layer now rejects `SecDebugLog`, silently changing the accepted configuration set of the already-shipped Wasm filter | `envoy-coraza-common/src/policy.rs:681`-`:683` |
| L-3 | Low | Release provenance omits required fields and records the arm64 verification label on amd64 manifests; checksum coverage of staged assets is unproven | `.github/workflows/release.yml:162`-`:201`, `.goreleaser.yaml:41`-`:43` |
| L-4 | Low | Effective request-body ceiling is `min(16 MiB, host per-stream buffer limit)`; the README states 16 MiB unconditionally | `envoy-coraza-dynamic/src/stream.rs:524`-`:532`; `envoy-coraza-dynamic/README.md:29` |
| L-5 | Low | Published `telemetry_publish_failed` is captured before the health writes, so it reports `false` when publication itself fails | `envoy-coraza-dynamic/src/observability.rs:99`-`:118` |
| L-6 | Low | Void `send_response` cannot report a failed local reply; currently unreachable, but the invariant that makes it safe is undocumented | `envoy-coraza-dynamic/src/stream.rs:1032`-`:1061` |

No Critical finding was identified. One High finding (H-1) must be fixed before
ship under decision 7; it is a small, local change.

## Findings

### H-1: Redirect target reaches the downstream `Location` header unvalidated (High)

**Location:** `envoy-coraza-dynamic/src/stream.rs:316` (response path) and
`envoy-coraza-dynamic/src/stream.rs:401`-`:403` (request path).

```rust
// response path, stream.rs:316
location: (redirect && !interruption.data.is_empty()).then(|| interruption.data.as_bytes().to_vec()),
// request path, stream.rs:401
if redirect && !interruption.data.is_empty() {
    headers.push(("location", interruption.data.as_bytes()));
}
```

**Description.** `Interruption::data` is the redirect target supplied by the
rule. The engine expands SecLang macros inside that target before storing it:

```rust
// coraza/src/actions/mod.rs:212-213
"redirect" => {
    let data = Macro::new(&self.argument).map_or_else(|_| self.argument.clone(), |value| value.expand(tx));
```

`Macro::expand` copies the variable value verbatim
(`coraza/src/operators/macros.rs:98`-`:110`) and performs no character
filtering. The adapter then hands those bytes to `send_response`, which the host
turns into a header value with no validation:

```cpp
// source/extensions/filters/http/dynamic_modules/abi_impl.cc:1033-1040 (pinned SDK revision)
modify_headers = [headers_vector, headers_vector_size](ResponseHeaderMap& headers) {
  for (size_t i = 0; i < headers_vector_size; i++) {
    ...
    headers.addCopy(Http::LowerCaseString(key), value);
  }
};
```

Envoy's header-map API does not sanitize values: the checks reachable from
`addCopy` are debug-only `ASSERT`s (`source/common/http/header_map_impl.cc:38`-`:47`)
and the pinned Envoy image is `Clean/RELEASE`, so they are compiled out. The
HTTP/1 response encoder then writes the value verbatim with no character check
(`source/common/http/http1/codec_impl.cc:116`-`:123`); only the *request*
encoder calls `HeaderUtility::checkValidRequestHeaders`. Nothing between the
rule and the socket removes `CR`, `LF`, `NUL` or other control bytes.

**Attack scenario.** A policy that templates a request-derived variable into a
redirect target, for example:

```text
SecRule REQUEST_BODY "@rx ^evil" "id:100,phase:2,redirect:https://example.test/blocked?m=%{MATCHED_VAR}"
```

An attacker sends a body whose matched value contains `x`, then a literal
carriage return and line feed, then `Set-Cookie: session=attacker`. The adapter
builds `location: https://example.test/blocked?m=x` followed by a real CRLF and
the forged header, and Envoy writes both lines. The client receives a second,
attacker-chosen header on the WAF's own denial response: session fixation on the
protected site, a forged `Location`, or a truncated header block that starts an
injected body. Request bodies, decoded values of variables that carry raw
request bytes, and `TX` values set from them are all attacker-controlled and may
contain `CR`/`LF`.

The same code shape exists in the Wasm adapter
(`envoy-coraza/src/stream.rs`, `reject_interruption`), so the root cause is
shared; the native adapter is nevertheless a trust boundary that must not emit
unvalidated rule data as a protocol header.

**Fix.** When building the `location` value (both `send_response_reply` and
`send_interruption`), reject or strip bytes outside a safe set: drop the
redirect (or fall back to a body-only denial) if `interruption.data` contains
any byte `< 0x20`, `0x7f`, or `> 0x7e`. Add one regression test per path
asserting that a control byte in `Interruption::data` never reaches
`send_response`. Fixing it in the adapter requires no engine change; fixing it
once in `coraza/src/actions/mod.rs` would cover both adapters and should be
considered as well.

### M-1: EOS admission charges 3x the body and can starve body inspection (Medium)

**Location:** `envoy-coraza-dynamic/src/stream.rs:596`-`:606` (request body
EOS), `:680`-`:690` (request trailers), `:1017`-`:1030` (response).

```rust
// stream.rs:596-606
let scratch_and_engine = body_size.checked_mul(2).and_then(|size| size.checked_add(prior_engine_bytes));
let target = scratch_and_engine.and_then(|size| body_size.checked_add(size));
// target = 3 * body_size + prior_engine_bytes
```

**Description.** While a body is still incomplete the stream reserves `1x` its
cumulative size (`stream.rs:586`, `:674`). At EOS or trailers it must also hold
the coalescing copy and the engine's retained body, so it reserves `3x` plus the
engine's pre-phase-2 retention. With `MAX_REQUEST_BODY_BYTES` at 16 MiB
(`stream.rs:59`) and `MAX_RETAINED_BODY_BYTES` at 64 MiB (`stream.rs:63`), the
arithmetic is:

- one 16 MiB EOS body reserves 48 MiB before phase 2 and can reach 64 MiB with
  engine retention, i.e. **one** request can consume the entire module-wide
  budget;
- two concurrent 16 MiB uploads fit at EOS (32 MiB held, 32 MiB more needed,
  64 MiB exactly); with **three** in flight (48 MiB held) no stream can complete
  inspection, because each completing stream needs 32 MiB more and is refused
  with 503 while the others are still uploading;
- with only three or four connections sending 16 MiB each, an attacker can hold
  the 64 MiB budget for the whole loaded module and force 503 on every *new*
  request that has a body, and on the completing uploads themselves, for as long
  as the uploads trickle (the example HCM uses a 30 s `stream_idle_timeout`,
  which a slowly progressing upload never reaches).

Request-body bytes are never forwarded uninspected, so this is not a bypass:
the outcome is a fail-closed 503, which the approved resource policy explicitly
allows. What is missing is the evidence and the operational statement.
`examples/envoy-coraza-dynamic/test-envoy.sh:293`-`:335` only exercises the
`1x` path with four 13 MiB *incomplete* bodies and then a fifth 503; it never
completes an upload while the budget is contended, so the 3x amplification and
the resulting `503` on *legitimate* concurrent uploads are unmeasured and
undocumented. The README states the ceilings without mentioning that only two
full-size inspected bodies fit, and only when they complete one after the other.

**Fix.** The 3x peak is real: the host bytes, the coalescing copy and the
engine's retained body all coexist inside `process_request_body`, so
under-accounting would be wrong. Two honest options:

- (a) Size the budget for the stated per-stream ceiling: ask the owner to raise
  `MAX_RETAINED_BODY_BYTES` (for example 256 MiB covers four concurrent 16 MiB
  inspections plus headroom) and record the RSS consequence, or lower
  `MAX_REQUEST_BODY_BYTES` so that 3x it fits the approved 64 MiB several times.
- (b) Keep both constants, document the practical concurrency
  (`64 MiB / (3 x 16 MiB)`), and add an acceptance case that completes two
  concurrent 16 MiB uploads while a third is in flight and asserts the
  documented outcomes.

Either way the number belongs in the module README and the compatibility
ledger, not only in the code.

### M-2: Telemetry publication failures are silently swallowed (Medium)

**Location:** `envoy-coraza-dynamic/src/stream.rs:420`, `:1040`, `:1185`;
`envoy-coraza-common/src/observability.rs:38`-`:48`.

**Description.** All three sites handle a failed `set_filter_state_bytes` by
calling `state.generation.diagnostics().record_failure()`, which increments an
`AtomicU64`. In the native adapter that counter is never read: the only
`failure_count()` callers are the Wasm adapter
(`envoy-coraza/src/stream.rs:303`, `:310`) and unit tests. So when filter-state
writes fail, the denial is still enforced but the access-log row loses
`event`, `rule_id`, `phase`, `action` and `status`, and nothing is logged,
counted or warned about. Plan section 6 requires the opposite: "Telemetry
failures must be observable but must not turn a denial into an allow."

**Failure scenario.** An operator's formatter or the host rejects the write (for
example a filter-state key or value limit, or a changed host). The access-log
row then loses its rule attribution (those fields render as `-`), and nothing
is logged, counted or warned about, so the failure itself leaves no trace.
Incident response cannot tell "the WAF denied and logged it" from "the WAF
denied but telemetry broke".

**Fix.** Mirror the Wasm adapter's bounded diagnostic: log at failure counts 1,
2, 4, 8 and so on through `envoy_log_error!`, including the failing field name.
`publish_interruption` and `publish_health` already return enough information to
name it, or can return the first failing field. One small test can assert the
first failure logs once and the second does not.

### M-3: FTW failures are unattributed; possible shared detection gap (Medium)

**Location:** `docs/performance/envoy-coraza-dynamic-stage-f/ftw/native-full.json`,
`.../wasm-native-failures-except-950020-2.json`, `.../divergence-ledger.json`;
`docs/envoy-coraza-dynamic-stage-f.md` section 1.

**Description.** Native failed 68 of 5,231 CRS FTW cases; 66 of those also fail
on the Wasm artifact. The stage document attributes the 54 cases that pass on
the standalone engine but fail through Envoy to "common connector or FTW/Envoy
harness behavior" and stops there. The checked-in manifests record only pass or
fail plus triggered rule IDs: no expected status, no observed status, and no
captured request, so the claim cannot be verified from the evidence. For
example, `941120-49` (XSS) records `triggered_rules: [[]]`, meaning no rule
fired at all. The same is true across a cluster of attack classes that only make
sense as body-borne detections: `932161-*`, `932200-13`, `932207-*`,
`932237-*`, `932239-*`, `932300-10`, `932390-9`, `933120-2`, `934120-*`,
`941101-1`, `941110-4`, `941120-49`, `941120-50`, `941210-6`, `942280-3`,
`949110-4`.

Two explanations are possible, and the evidence does not distinguish them:
the FTW harness sends something Envoy rewrites or answers before the filter can
decide (a harness artifact), or phase-2 body inspection does not see these
payloads through either adapter (a real detection gap that both adapters
share). The native module's own tests only prove phase 2 for a RAW processor and
for one CRS SQLi case on `REQUEST_URI`, so they do not settle it either.
Decision 13 requires CRS evidence better than the Wasm artifact's standard, and
decision 14 requires a divergence ledger; an unattributed 54-case set where
known attack tests trigger zero rules does not meet that bar for an enforcement
artifact.

**Fix.** For a representative subset (at least `932161-7`, `934120-23`,
`941120-49`, `949110-4`), record the expected status/rule, the observed status,
and what the filter actually received (a bounded debug-log line or access-log
row per test). Then either fix the harness, fix the adapter, or land each
remaining case in the divergence ledger with a one-line cause. This is evidence
work, not necessarily a code defect.

### L-1: Audit sanitizer keeps `\n`, permitting log-line injection (Low)

**Location:** `envoy-coraza-common/src/observability.rs:225`-`:227`.

`sanitize_audit` escapes every control character except `\n`, which it copies.
The audit record is emitted as one `envoy_log_critical!` message
(`envoy-coraza-dynamic/src/observability.rs:127`-`:133`) and can contain
attacker-influenced values in the native audit format. A `\n` in a header or
body value can therefore start a forged log line next to the real one. The
behavior is pre-existing and shared with the Wasm adapter, and the test name
shows it is deliberate, so this is a ledger item rather than a lane regression.
Fix: escape `\n` as well whenever the record is destined for a single log line,
or document why multi-line output is required and what consumes it.

### L-2: `SecDebugLog` is now rejected for the Wasm adapter too (Low)

**Location:** `envoy-coraza-common/src/policy.rs:681`-`:683`.

Extracting the shared policy layer added a `debug_log.is_empty()` check to what
is now `check_host_safety`. The rejection matches plan section 6 ("Route debug
output through an Envoy-backed `DebugLogger` or reject a requested file debug
sink") and fails closed, but it changes the accepted configuration set of the
already-published Wasm artifact: a policy carrying `SecDebugLog` now makes the
whole filter configuration invalid, and Envoy refuses to start that listener.
Plan slice B promised "no behavior changes" for the Wasm artifact. Fix: add a
line to the Wasm adapter's release notes and to the compatibility ledger so the
change is not discovered during an upgrade.

### L-3: Release provenance and checksum completeness (Low)

**Location:** `.github/workflows/release.yml:162`-`:201`, `.goreleaser.yaml:41`-`:43`.

The provenance manifests record repository revision, SDK commit, Envoy image
reference, architecture, target triple, Rust/Clang versions, enabled features
and the library SHA-256. Plan section 4 also requires the actual Envoy
version/build SHA, the CRS identity and native dependencies/licenses; none are
present (`release.yml:171`-`:184`). All four manifests write
`"arm64_verification": "qemu-load-smoke-passed"` (`release.yml:183`, `:188`),
including the amd64 ones, which makes the field useless for the audience it was
added for; decision 17 wants the arm64 level labeled. Separately, the four `.so`
assets are staged through `release.extra_files` while `checksum` is a GoReleaser
artifact pipe and `builds:` is a single skipped entry, so `checksums.txt` may
list nothing; the provenance SHA-256 is the only guaranteed integrity data.
Fix: add the missing provenance fields, use a per-architecture verification
value (for example `full-acceptance-amd64`), and either verify that
`checksums.txt` covers the staged assets or publish an explicit checksum file
next to them.

### L-4: Effective request-body ceiling depends on the host buffer limit (Low)

**Location:** `envoy-coraza-dynamic/src/stream.rs:524`-`:532`;
`envoy-coraza-dynamic/README.md:29`.

The module only ever *lowers* the per-stream buffer limit:

```rust
let current = envoy.get_buffer_limit();
let limit = MAX_REQUEST_BODY_BYTES_U64;
if current == 0 || current > limit { envoy.set_buffer_limit(limit); }
```

With the Envoy default listener (`per_connection_buffer_limit_bytes` unset, 1
MiB), a request larger than 1 MiB is rejected by Envoy's own 413
(`ActiveStreamDecoderFilter::requestDataTooLarge`) before the module can reach
its 16 MiB ceiling. That is fail-closed and therefore not a vulnerability, but
the README states the 16 MiB ceiling unconditionally. Fix: say the effective
ceiling is `min(16 MiB, host per-stream buffer limit)` and that operators must
raise the listener limit to use the native ceiling.

### L-5: Published `telemetry_publish_failed` cannot report its own failure (Low)

**Location:** `envoy-coraza-dynamic/src/observability.rs:99`-`:118`.

`HealthState::telemetry_publish_failed` is captured before the seven
`set_filter_state_bytes` calls, so the value written for that field is always
the pre-publication value. When the publication fails, the consumer sees
`telemetry_publish_failed=false` plus (for the current host) a missing or stale
set of fields. Fix: publish that field first with the pre-existing value, then
write the rest, or emit a dedicated failure counter that is written last and
tolerate its loss. Low impact, listed for the ledger because it is the field
that is supposed to detect this class of problem.

### L-6: A failed local reply is undetectable; the invariant is undocumented (Low)

**Location:** `envoy-coraza-dynamic/src/stream.rs:1032`-`:1061`.

The SDK's `send_response` returns `()` (plan section 5 and the Stage D ledger
already record this). If the host turns the call into a stream reset instead of
a reply, the adapter cannot tell. Assessment: **not exploitable in this
design.** Every path that inspects a response body holds the response headers
(`ResponseHeadersStatus::StopIteration` at `stream.rs:809`), so when a response
denial is issued, `non_100_response_headers_encoded_` is still false and Envoy
takes the `sendDirectLocalReply` branch
(`source/common/http/filter_manager.cc:1118`-`:1128`). The one path that would
fail silently, a local reply after the headers were already sent, cannot be
reached because no callback inspects a body whose headers were released. Fix:
record that invariant in a comment next to `send_response_reply` and in the
Ledger so a future change towards streaming responses cannot quietly break it;
any such change must also add a real-host assertion that a late denial resets
rather than replies.

## Verified sound

Priority order from the review brief. Each item was checked against the code and,
where noted, against the pinned host source or the real-host harness.

**1. FFI, re-entrancy and memory safety**

- `CatchUnwind` wraps the stream filter (`stream.rs:93`), so a panic in any hook
  is contained and the request path fails closed with 500 while the response
  path resets.
- No `RefCell` borrow is held across `send_response`. All three sites close the
  borrow first: `reject` (`stream.rs:346`-`:367`) and `send_interruption`
  (`:404`-`:434`) end the `try_borrow_mut` block before the call, and
  `send_response_reply` (`:1032`-`:1061`) publishes filter state and drops the
  borrow before `send_response`. `is_head()` uses a short shared borrow.
- The terminal flag is set before every host call that can re-enter
  (`:347`, `:404`, `:1033`), and the unit tests assert the ordering
  (`expect_inline_reply`, `request_interruption_state_is_published_before_local_reply_even_if_it_fails`).
- No Envoy buffer view crosses a host call: `copy_headers` copies into owned
  buffers (`:1271`-`:1293`), `copy_terminal_body` and
  `copy_terminal_response_body` copy fragments and `drop` the views before
  returning (`:1364`-`:1412`), `attribute_bytes` copies (`:1295`).
- The module's own local reply cannot be re-inspected: the host sets
  `sent_local_reply_` and short-circuits its encode hooks
  (`filter.cc:166`-`:200`), and `on_local_reply` returns `Continue`
  (`stream.rs:1107`-`:1116`).
- A poisoned wrapper that skips `on_stream_complete` cannot leak a reservation:
  `Drop for BodyReservation` subtracts its own bytes (`stream.rs:223`-`:227`),
  and `Drop for StreamState` finalizes once (`:167`-`:194`). Finalization is
  once-only through the `finalized` flag, so a normal completion followed by
  `Drop` cannot double-finish.
- No raw pointers, no handwritten `unsafe` in adapter logic; the only `unsafe`
  in the crate is a test-only body view and the test-only log stubs
  (`stream.rs:1414`-`:1419`, `:1605`-`:1615`, `test_hostcalls.rs`), all inside
  `#[cfg(test)]` modules.
- `Generation`/`Policy`/`Waf` carry a compile-time `Send + Sync` assertion
  (`envoy-coraza-common/src/policy.rs:232`-`:237`); no unsafe trait impl exists.

**2. Admission budget**

- `try_reserve` is a compare-and-swap loop with `checked_add` before the
  exchange (`stream.rs:230`-`:244`), so there is no load-then-add race and no
  TOCTOU between the size check and the reservation; reservation happens
  *before* the copy at every EOS site (`:601`, `:685`, `:1029`).
- Every exit releases exactly once: success, error reply, admission refusal
  (unchanged `self.bytes`), panic, reset and drop. `resize` never releases more
  than it holds, so the shared counter cannot wrap; `MAX_RETAINED_BODY_BYTES`
  is a single static shared by every stream, configuration and generation of
  the loaded module (the module is loaded once per configured name, and
  `do_not_close` keeps it resident).
- Concurrent CAS behaviour is unit-tested under contention
  (`concurrent_reservations_never_cross_the_shared_limit`); the real-host
  harness proves exhaustion returns 503 and that a follow-up request succeeds
  after the reservations are released (`test-envoy.sh:293`-`:335`).

**3. Fail-open paths**

- Configuration rejection is complete for the native factory: unknown filter
  name, oversize input, parse error and compile error all return `None`, which
  the host turns into a startup/config rejection
  (`abi.rs:59`-`:104`; real-host negative controls for unknown name, malformed
  JSON, invalid UTF-8 and oversized input).
- Every adapter-side error returns an explicit status: 400 for a bad authority,
  413 for size, 415 for residual encoding, 431 for header budgets, 501 for
  CONNECT/upgrade, 502/503 for host and lifecycle failures. No branch converts
  an error into `Continue`. `Continue` is only returned for the four documented
  uninspected outcomes (no matching authority, engine off, empty configuration,
  and explicitly excluded bodies).
- Host or engine body limits fail closed: `SecRequestBodyLimit` and
  `SecResponseBodyLimit` ceilings are enforced at compile time
  (`MAX_REQUEST_BODY_LIMIT`/`MAX_RESPONSE_BODY_LIMIT`), and `ctl` cannot raise
  them because the limits are set on the parser config after directive parsing
  with `audit_engine_locked`.
- The void-`send_response` limitation is assessed in L-6 and is not currently
  reachable.

**4. Content leakage on denial**

- Response headers are released only when the body is not inspected
  (`stream.rs:776`-`:809`): a body-inspecting response holds the headers, so
  every body or trailer denial is issued while the downstream has received
  nothing. Confirmed on the real host for header, body, trailer, MIME-excluded
  and body-access-off denials, including `HEAD`, 204 and 304, with the upstream
  `x-upstream-secret` and trailer markers absent (`test-envoy.sh:337`-`:450`).
- No path inspects a body after releasing its headers, so no late denial can
  arrive after upstream bytes were flushed.
- The denied-content body is a fixed static string
  (`stream.rs:67`-`:71`); `ResponseReply::body()` empties it for `HEAD`,
  204 and 304 (`:321`-`:327`); redirects send an empty body (`:312`). The
  replacement headers are fixed to `content-type`, `cache-control` and
  `location`, so no upstream header is ever re-emitted.
- A response large enough to exceed the 1 MiB ceiling reaches the module's own
  502 check before Envoy's buffer watermark can fire, because the size check
  runs on `buffered + received` before the callback returns
  `StopIterationAndBuffer`; the real-host 502 case confirms it.

**5. Hostile input handling**

- Header and trailer budgets are enforced before retention and before any
  engine call: count, per-value size and aggregate size
  (`authority.rs:45`-`:58`, used at `stream.rs:460`, `:652`, `:734`, `:934`).
- All body arithmetic is checked (`checked_add`, `checked_mul`,
  `saturating_sub`), the workspace builds with `overflow-checks = true` in
  release (`Cargo.toml:247`-`:248`), and no wrapping arithmetic exists on the
  body path.
- Size regressions (a callback reporting less than a previous one) are rejected
  with 503/502 rather than silently resuming (`stream.rs:574`, `:668`, `:844`,
  `:938`).
- Authority normalization rejects invalid UTF-8, malformed host syntax, bad
  ports and ambiguous colon forms, and strips only the scheme's default port
  (`authority.rs:64`-`:179`). An empty authority selects the default policy
  rather than bypassing.
- Residual `Content-Encoding` is rejected for inspected request and response
  bodies (`authority.rs:98`-`:105`; `stream.rs:518`, `:772`); CONNECT and
  upgrades are rejected with 501 (`:512`-`:517`).
- UTF-8 is enforced for header names, method and protocol; header *values* stay
  byte-preserving.
- Trailer values are intentionally not SecLang inputs and are passed through
  only after the budget check; this is documented in the module README and the
  plan, and is an accepted coverage choice, not a defect.
- Every `try_borrow`/`try_borrow_mut` failure path fails closed with 503 instead
  of interpreting an unavailable borrow as a clean verdict.

**6. Information disclosure**

- Filter-state writes use a closed set of field names and bounded values:
  `event`, `rule_id`, `phase`, `action`, `status`, `severity`, `category`,
  `client_ip` (`envoy-coraza-dynamic/src/observability.rs:52`-`:86`) and seven
  boolean/closed-outcome health fields (`:99`-`:118`). No request or response
  body and no matched value is ever published.
- `category` is a validated 1-63 byte slug
  (`envoy-coraza-common/src/observability.rs:282`-`:299`); `client_ip` comes
  from the direct peer address attribute, not from a forwarded header.
- Default health state contains no payload data; `enable_filter_state_logs`
  gates both field sets, and the real host shows absent fields when disabled.
- Audit and error output are bounded (16 KiB / 4 KiB) and control-escaped
  except for the `\n` noted in L-1. Debug events are level-gated by the engine
  before the host logger is consulted (`coraza/src/transaction.rs:666`), so a
  logger whose `enabled()` returns `true` cannot flood the log at the default
  level. A configured `SecDebugLog` file sink is rejected (L-2).
- `envoy-coraza-dynamic` enables no `coraza` host operator: no workspace member
  requests `inspect-file`, `rbl`, `https-audit` or `validate-schema`, so the
  shipped feature graph has no filesystem or network sink, and
  `check_host_safety` rejects upload-file storage, native audit sinks and
  disk-spill audit types (`policy.rs:667`-`:715`).

**7. Supply chain, packaging and the panic probe**

- The SDK is a git dependency pinned by revision in both `Cargo.toml` and
  `Cargo.lock`; `deny.toml` allowlists only `envoyproxy/envoy` besides the
  existing Wasm SDK, so a new git source stays denied by default.
- `panic-probe` is not a default feature, is not enabled by the release
  Dockerfile, `.goreleaser.yaml` (`CARGO_FEATURES` is empty or `embed-crs`) or
  the release workflow, and the real-host harness asserts that the default
  artifact ignores `x-coraza-probe: panic` and logs no caught panic
  (`test-envoy.sh:226`-`:230`). The probe is therefore unreachable in the
  shipped artifacts.
- The derived image installs the module at `/opt/envoy/modules`, root-owned,
  mode `0444` inside a `0555` directory (`Dockerfile.goreleaser-dynamic:29`-`:32`),
  and sets `ENVOY_DYNAMIC_MODULES_SEARCH_PATH`; the runtime stage is the same
  pinned digest as the build stage, so the observed `GLIBC_2.34` ceiling is
  consistent with the runtime and the library cannot be replaced by a
  non-root process.
- The derived-image smoke test verifies ELF imports resolve against the real
  Envoy binary, rejects an unknown filter name at startup, proves
  deny-before-backend and a byte-exact allow, and checks `ldd`
  (`test-derived-image-smoke.sh:73`-`:203`).
- The switch/rollback harness runs the identical policy bytes through the
  native filter and then the Wasm filter and asserts the same 451/429 denials
  and a byte-exact allowed upload (`test-switch-rollback.sh:114`-`:156`).

## Intended divergences (not reported as defects)

- Request denials use Envoy's local-reply API instead of response replacement,
  and the denial body differs from the Wasm connector (decision 9 and 16,
  recorded in the Stage D ledger).
- Response inspection failures map to 502, and the request path uses
  `Request denied` except for HEAD/204/304/redirect (recorded in the Stage D
  ledger).
- An unmatched authority, `SecRuleEngine Off`, and an empty configuration pass
  traffic uninspected with a warning (plan section 4). Note for operators, not a
  defect: a deployment that configures only `per_authority_directives` and no
  `default_directives` can be bypassed by changing the `Host` header; this
  matches the documented configuration contract and the Wasm behavior.
- Trailer values are not SecLang rule variables; compressed, upgraded and
  indefinite streams are documented as outside full-body coverage.
- HTTP/2, multi-worker and live configuration replacement have real-host
  evidence, while arm64 has load-and-smoke only (decision 17).

## Evidence claims checked against the code

| Stage claim | Verdict |
| --- | --- |
| "Terminal state and all borrowed header/body views are released before the SDK local-reply call" | Confirmed for all three `send_response` sites |
| "Reservation is owned by its stream and released by `Drop`" | Confirmed, including the poisoned-wrapper path |
| "Response denials leave zero upstream header/body/trailer bytes" | Confirmed structurally (headers held) and by the real-host harness |
| "Requests are never inspected twice / phase 2 runs once" | Confirmed: stage and `phase2_done` are set before the engine call and the re-entrant `doData` callback short-circuits |
| "Filter-state writes happen before the local reply and before access-log flush" | Confirmed for interruption fields and for health fields |
| "The panic probe is unreachable in the default build" | Confirmed by features, release wiring and a real-host assertion |
| "Admission exhaustion is covered by the harness" | Partly: only the 1x incomplete-body path is exercised (M-1) |
| "Telemetry failures are observable" | Not met in the native adapter (M-2) |
| "54 shared FTW failures are harness/connector behavior" | Unproven from the checked-in evidence (M-3) |
| "Aggregate admission is module-wide across workers" | Consistent with the host loading one module copy; the harness test at two workers covers isolation, not contention |

## Required checks run

- `cargo test -p envoy-coraza-dynamic` in this worktree: 24 tests passed.
- `make lint` in this worktree: passed (clippy, rustfmt, license headers).
- Not run here (not applicable to a review-only change): `make test`,
  `make test-envoy-dynamic`, `make build-envoy-dynamic-crs`, the FTW run and
  the benchmark protocol. The stage evidence covers them on the pinned host;
  M-3 lists where that evidence is insufficient.

## Verdict

One High finding (H-1) must be fixed, with a focused regression test, and
re-reviewed once before this lane can ship under owner decision 7. No Critical
finding was found: FFI re-entrancy, admission accounting, fail-closed behaviour,
response-side leakage and hostile-input handling are internally consistent and
match the real-host evidence, with M-1 through M-3 as the remaining assurance
gaps. M-1, M-2, M-3 and the Low items belong in
`docs/envoy-coraza-dynamic-followups.md` per decision 11.
