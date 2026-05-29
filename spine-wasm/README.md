# spine-wasm

WebAssembly façade over [`spine-core`](../spine-core). Exposes the strict
demo verifier (and, for debug, the lenient one) to JavaScript through
[`wasm-bindgen`](https://rustwasm.github.io/wasm-bindgen/).

## What it ships

A wasm bundle plus generated JS glue (produced by `wasm-pack`) with two
exported functions:

```ts
// Primary: the only function the playground UI is allowed to call.
function verify_demo_wal_json(
    wal_bytes: Uint8Array,
    expected_pubkey_hex: string,    // 64 lowercase hex chars (32 raw bytes)
    expected_root_hex: string,      // 64 lowercase hex chars (32 raw bytes)
    manifest_version: number,       // currently must be 1
): string;                          // JSON envelope (see below)

// Secondary: lenient verifier for debug/auditor use only. DO NOT call
// from the public playground.
function verify_wal_bytes_json(
    wal_bytes: Uint8Array,
    expected_root_hex: string | null,
): string;                          // JSON envelope (see below)
```

Both return a JSON string. Once the wasm crate has parsed its inputs the
envelope is always:

```jsonc
{ "ok": true, "report": { /* DemoReport or VerificationResult */ } }
```

`ok` is `false` only when serializing the report itself fails; this is
an internal `spine-core` bug, effectively unreachable:

```jsonc
{ "ok": false, "error": { "kind": "ReportSerializationFailed", "message": "..." } }
```

`ReportSerializationFailed` is currently the only `ok:false` kind. There
is **no** envelope-level error for bad input (empty WAL, malformed
pubkey, …): those surface inside the report, not as `ok:false`.

When `ok: true`, the verdict lives inside the report:

- Strict (`verify_demo_wal_json`) → `report.status`: `"valid"`,
  `"invalid"`, or `"error"`. `"invalid"` covers tampering, chain-root
  mismatch, and an empty WAL that cannot match the pinned root.
  `"error"` is a caller-side configuration problem caught before chain
  replay (malformed `expected_pubkey` or `expected_root`), with the
  detail in `report.error`.
- Lenient (`verify_wal_bytes_json`) → `report.valid` (boolean), with
  failures listed in `report.errors`.

A "valid envelope, failed report" outcome means the verifier ran
end-to-end but the WAL did not pass. That is the common failure shape
the playground UI should render.

## Building the bundle

```sh
# One-time
cargo install wasm-pack

# Build
cd spine-wasm
wasm-pack build --target nodejs --release        # for Node integration tests
wasm-pack build --target web --release           # for the browser playground
```

`wasm-pack` writes the artifacts to `pkg/`. The browser-ready output
(`--target web`) includes `spine_wasm.js`, `spine_wasm_bg.wasm`, and
`package.json`, all of which can be consumed by Vite as a local
`pkg = "../path/to/spine-wasm/pkg"` import.

## Cross-target gate

`tests/integration.mjs` runs the bundle in Node 20+ against the
fixture produced by `demo-seeder --deterministic-seed=42`. The fixture
is byte-reproducible across runs of the same seed, so this test is
suitable for CI.

```sh
# 1. Generate the deterministic fixture (one-shot):
(cd demo-seeder && \
    cargo run --release -- --deterministic-seed 42 --non-interactive --output-dir out-test)

# 2. Build the wasm bundle for Node:
(cd spine-wasm && wasm-pack build --target nodejs --release)

# 3. Run the integration test:
node spine-wasm/tests/integration.mjs
```

The script asserts:

- Strict verifier on the fixture: `status=valid`, `events_verified=20`,
  `chain_root` matches the pinned `expected_root`.
- Strict verifier on a tampered fixture (the demo flow: the amount in
  record 11 is edited): `status=invalid`, and the failing record carries
  `reason.kind=payload_hash_mismatch`.
- Strict verifier with a wrong pinned pubkey: `status=invalid`, failing
  record `outcome=rejected`, `reason.kind=pubkey_mismatch` (never a
  signature-verification failure).
- Strict verifier on an empty input: `ok=true`, `status=invalid`,
  `events_verified=0`, and `report.error` contains "chain_root mismatch"
  (the accumulator over zero records cannot match the pinned root).
- Lenient verifier on the same fixture: `chain_root` byte-for-byte equal
  to the strict one. This is the cross-API parity guarantee surfaced
  through the wasm boundary. (The lenient verifier fails signature
  verification on a strict-signed WAL by design; only the `chain_root`
  is compared here.)
- Determinism: two runs on the same input produce byte-identical JSON.

If any check fails, **the bundle is not cleared for playground
integration**.

## Bundle size and determinism

Raw release `.wasm` (pre-`wasm-pack`, post-`cargo build` only): around
**410 KB** at the time of writing. `wasm-pack` is configured with
`wasm-opt = false` in `Cargo.toml` (its bundled binaryen is too old for
recent rustc/wasm-bindgen output), so the bundle it emits is
unoptimised. Running a fresh `wasm-opt -Oz` separately (which
`build-playground-assets.sh` does when `wasm-opt` is on PATH) brings it
to **150-200 KB**, and around **80-110 KB** gzipped on the wire.

The strict verifier deliberately depends on `unicode-normalization`
(NFC tables ~100 KB), `subtle`, `blake3`, `ed25519-dalek`, and
`serde_json`. These are essential. None can be dropped without losing
either the strict-profile guarantees or the cross-language parity.

For manifest pinning the wasm bundle is meant to be
byte-reproducible across rebuilds of the same source. After
`wasm-pack build --target nodejs --release`, hash the artifact:

```sh
sha256sum pkg/spine_wasm_bg.wasm
cargo clean -p spine-wasm
wasm-pack build --target nodejs --release
sha256sum pkg/spine_wasm_bg.wasm        # must match
```

If the two digests differ, something non-deterministic is leaking into
the build (debuginfo paths, timestamps, …) and the manifest pinning
becomes meaningless. Investigate before relying on manifest pinning. `--remap-path-prefix`
and `RUSTFLAGS="-C strip=symbols"` are the usual fixes.

## Why not load `spine-core` directly via `cargo build --target wasm32`?

Because `spine-core` exports plain Rust functions with `Result<T, E>`
return types and types like `&[u8]` arguments. JavaScript cannot call
into those without an FFI shim, and the shim is exactly what
`wasm-bindgen` generates. This crate is that shim, and only that shim:
no business logic, no policy, no crypto. If a strict-profile
requirement looks like it belongs here, it belongs in `spine-core`
instead.
