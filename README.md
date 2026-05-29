# Spine

Cryptographically verifiable audit evidence: independent verification tools.

This repository contains the Apache-2.0 licensed components of
[Spine](https://eulbite.com): the core verification library, the
standalone CLI for offline auditors, and the WebAssembly build that
powers an in-browser verification playground.

The Spine production server (event ingestion, batch sealing,
retention, dashboard) is not part of this repository. The components
here are designed so that the same verification logic that backs the
production system also runs, byte-for-byte, in your browser and in
the standalone CLI. Anyone can audit the verifier source and run it
offline against a WAL file without trusting any Spine infrastructure.

## Status

Pre-release. The verifier crates and the wasm bundle are stable and
covered by regression vectors. The browser playground
is wired up via [`playground-spec/`](playground-spec/) and pending
deployment.

## Layout

```
spine-core/        Pure verification library: hash chain, signature verify,
                   canonical JSON. No filesystem, no network, no signing,
                   just pure logic suitable for native and wasm targets alike.
spine-cli/         Standalone CLI for offline WAL verification.
spine-wasm/        wasm-bindgen façade over spine-core for browser use.
test-vectors/      Language-independent reference vectors pinning canonical
                   JSON, hashing, and the signature contracts. The Rust crates
                   are checked against them; any implementation must match.
playground-spec/   Integration contract for any host site that wants to
                   embed the in-browser playground.
demo-seeder/       Operational tool: generates a signed demo WAL on an
                   airgapped machine. Excluded from the verifier crates'
                   dependency graph so its `rand` deps cannot reach the
                   wasm bundle.
```

## What this verifies, and what it does not

This codebase verifies that a given Spine WAL file is internally consistent and matches a pinned
public key, expected chain root, and manifest. It does **not** verify the operational integrity of
the Spine server, key management practices, or the broader compliance posture of any deployment
that uses Spine. Those concerns belong in audit and operational reviews, not in cryptographic code.

## License

Apache License 2.0. See [LICENSE](LICENSE).
