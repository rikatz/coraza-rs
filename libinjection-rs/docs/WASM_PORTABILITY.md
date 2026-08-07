# WASM Portability Guidelines

**Audience:** Engineers implementing or embedding `libinjection-rs`  
**Scope:** Library design constraints only - **not** a guide to building Envoy WASM filters

---

## Purpose

`libinjection-rs` is built for **native coraza-rs today**, but must remain safe to link into future WASM environments (Envoy `envoy.filters.http.wasm`, Istio, ngx_wasm_module, etc.) without architectural changes.

We researched [proxy-wasm](https://github.com/proxy-wasm/spec) and Rust Envoy filter patterns to understand **what constraints WASM VMs impose on embedded libraries**. Filter-level concerns (`proxy_wasm::main!`, `cdylib`, Envoy YAML) belong in a **separate future project** - not this crate.

---

## What this crate is NOT

| Not in this repo | Why |
|------------------|-----|
| `proxy-wasm` dependency | Host/filter SDK - embedder's responsibility |
| `crate-type = ["cdylib"]` | Produces a plugin binary; we ship an `rlib` library |
| Envoy config YAML | Deployment concern |
| `RootContext` / `HttpContext` | Filter lifecycle - not detection logic |

---

## WASM runtime constraints → library rules

| WASM constraint | libinjection-rs rule |
|-----------------|---------------------|
| Single-threaded VM | Stack-local `SqliState`; no `Arc`/`Mutex`/`Rc<RefCell>` in parser |
| Bounded linear memory | Zero heap on detection hot path; ~200-byte stack state (match C) |
| `panic = abort` in filters | Never panic on untrusted input; return `Result` or benign `false` |
| Binary size pressure | Static `.rodata` tables OK; no runtime proc-macros; avoid extra deps |
| No filesystem in VM | All keyword data via `build.rs` + `include!`; no runtime file I/O |
| Non-UTF-8 request data | Public API uses `&[u8]`, not `&str` |
| Capability restrictions | No dependency on threads, sockets, env, or WASI beyond what embedder provides |

---

## Crate configuration

```toml
[lib]
crate-type = ["rlib"]   # NOT cdylib

[features]
default = []
std = ["memchr/std"]    # optional: native SIMD CPU detection only

[dependencies]
memchr = { version = "2", default-features = false }
```

Core crate attribute:

```rust
#![cfg_attr(not(feature = "std"), no_std)]
```

---

## API contract for embedders

See [MODERNIZATION_PLAN.md § Hot-path contract](./MODERNIZATION_PLAN.md#hot-path-contract) for full limits.

### Input

- **`&[u8]`** - headers, query params, and body chunks may contain invalid UTF-8
- Default scan cap **8192 bytes**; longer input sets `AnalysisFlags::TRUNCATED` (prefix scanned)

### Output

Primary API returns a fixed-size **`AnalysisSnapshot`** - no `Vec`, `String`, or `Box`:

```rust
pub fn analyze_sqli(input: &[u8]) -> AnalysisSnapshot;
pub fn analyze_xss(input: &[u8]) -> AnalysisSnapshot;
```

`AnalysisSnapshot` contains `ConstructFlags`, evidence spans `(offset, len)`, and optional `LegacyFingerprint` (when `legacy` feature enabled). Convenience wrappers:

```rust
pub fn detect_sqli(input: &[u8]) -> DetectionVerdict;  // { detected, snapshot }
```

- No heap on `analyze_*` / `detect_*` default path
- Policy (block/allow) is **embedder responsibility** - Coraza applies SecRules; library only classifies constructs
- Convert legacy fingerprint to `str` only at audit/logging boundaries

### State

- `SqliState<'a>` / `XssState<'a>` borrow input; no global mutable state
- `reset()` for in-place reuse across flag contexts (multi-pass SQLi check)
- Thread-safe by design: fresh state per call, or caller-owned reusable state

---

## Memory budget

Per-call stack (modern + legacy shared path):

| Field | Size |
|-------|------|
| Normalization buffer | 512 B stack |
| `TokenMeta` buffer | 8 × ~6 B (offsets, no token copies) |
| `EvidenceSpan` buffer | 4 × 4 B |
| `AnalysisSnapshot` | Fixed `Copy` struct |
| Parser state | Target ~1–2 KiB; hard cap 4 KiB |

Static `.rodata` ( **`legacy` feature only** ):

| Field | Size |
|-------|------|
| Keyword/fingerprint tables | ~200 KB (from build.rs) |

Minimal WASM builds use `--no-default-features` (no legacy tables). Detection of a single field value must not allocate on the heap.

---

## Dependencies and WASM

### Allowed: `memchr`

- Supports `no_std` with `default-features = false`
- Has **wasm32 vector-accelerated** implementations ([memchr docs](https://docs.rs/memchr/latest/memchr/))
- Acceptable single runtime dependency per project policy

### Avoid in library crate

- `smallvec`, `bitflags`, `regex`, `serde`, `hashbrown` - use fixed arrays, const flags, static tables
- `phf` - **build-dependencies only**; generated code lands in `.rodata`

---

## Verification (library only)

Add to CI - proves the **library** compiles for WASM, does **not** build a filter:

```bash
rustup target add wasm32-wasip1
cargo check -p libinjection --target wasm32-wasip1 --no-default-features
```

Optional (when unit tests are `no_std`-compatible):

```bash
cargo test -p libinjection --target wasm32-wasip1 --no-default-features
```

This is a compile gate, not filter validation. A future filter project would:

1. Depend on `libinjection` as a normal Rust dependency
2. Add `proxy-wasm` + `cdylib` in **that** crate
3. Build with `cargo build --target wasm32-wasip1 --release`
4. Deploy via Envoy `envoy.filters.http.wasm`

None of that is in scope for `libinjection-rs`.

---

## Coraza ecosystem context

| Project | Uses libinjection how | Relation to this crate |
|---------|----------------------|------------------------|
| **coraza-rs** (native) | `libinjectionrs` today → `libinjection-rs` | **Primary consumer** |
| [coraza-proxy-wasm](https://github.com/corazawaf/coraza-proxy-wasm) | Go `libinjection-go` inside TinyGo WASM | Unchanged; separate codebase |
| [coraza-wasilibs](https://github.com/corazawaf/coraza-wasilibs) | C libinjection as WASM module via wazero | Future: could wrap `libinjection-rs` - not our task |

---

## References

- [MODERNIZATION_PLAN.md](./MODERNIZATION_PLAN.md) - AnalysisSnapshot spec, hot-path contract
- [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) - full build plan
- [RUST_BEST_PRACTICES.md](./RUST_BEST_PRACTICES.md) - performance and memory patterns
- [proxy-wasm spec](https://github.com/proxy-wasm/spec) - ABI background (filter authors)
- [Envoy WASM overview](https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/wasm) - host runtime background
- [memchr crate](https://docs.rs/memchr) - planned runtime dependency
