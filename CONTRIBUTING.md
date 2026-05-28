# Contributing to Spine

Thanks for your interest. Spine is small, the surface is
deliberately narrow, and the bar for changes is "does the
verifier still say the right thing on every test vector?". A
contribution that improves clarity, hardens a check, fixes a real
bug, or extends documentation is welcome; a contribution that adds
machinery without a concrete failing case is usually better as an
issue first.

## Project shape (so you know where to land)

```
spine-core/        Pure verification library: the source of truth.
                   No filesystem, no network, no signing. Compiles for
                   native and wasm32 targets alike. This is where
                   substantive crypto changes go.
spine-cli/         Standalone offline auditor binary. Filesystem +
                   presentation glue over spine-core. Add CLI surface
                   here, not in spine-core.
spine-wasm/        wasm-bindgen façade over spine-core. Exposes
                   verify_demo_wal_json + verify_wal_bytes_json as
                   JSON-string-returning functions. No business logic
                   lives here; it is purely the FFI shim.
test-vectors/      Cross-language fixtures. Authoritative for canonical
                   JSON, entry hashing, and Ed25519 signature parity.
playground-spec/   Integration contract for any host page that mounts
                   the playground. React skeleton + flow diagram +
                   manifest example + build pipeline.
demo-seeder/       Operational tool for generating the signed demo WAL
                   on an airgapped machine. Excluded from the workspace
                   so its `rand` deps cannot reach the verifier crates'
                   wasm32 dependency graph.
```

Cross-cutting rules:

- Anything signature-, hash-, or canonical-JSON-related belongs in
  `spine-core`. The wasm and CLI sides are deliberately thin.
- New invariants the strict verifier should check land in
  `spine-core/src/verify_demo.rs`, with a corresponding test and
  (ideally) a cross-language vector.
- The cross-language test vectors in `test-vectors/vectors.json`
  are authoritative. Changing them is a coordinated change across
  the Rust, Node, and Python implementations.

## Building and testing

Prerequisites:

- Rust toolchain: `rustc 1.75` or newer (the workspace pins this
  via `rust-version` in `spine-cli/Cargo.toml`).
- The `wasm32-unknown-unknown` target: `rustup target add
  wasm32-unknown-unknown`. Required for the non-regression check
  on `spine-core`'s wasm build.
- For the cross-target gate (`spine-wasm/tests/integration.mjs`)
  also: `wasm-pack` (`cargo install wasm-pack --locked`) and
  Node 20+.

The minimum gate every change must pass before merge:

```sh
cargo test --workspace                    # 114/114 pass
cargo clippy --workspace --all-targets    # zero warnings
cargo build --target wasm32-unknown-unknown -p spine-core --release
                                          # clean wasm32 build
```

If your change touches `spine-core`, `spine-wasm`, or
`test-vectors/`, also run the cross-target gate:

```sh
# Generate the deterministic fixture
(cd demo-seeder && cargo run --release -- \
    --deterministic-seed 42 --non-interactive --output-dir out-test)

# Build the bundle
(cd spine-wasm && wasm-pack build --target nodejs --release)

# Run the gate
node spine-wasm/tests/integration.mjs
```

If your change touches anything that affects the wasm bundle's
bytes, also re-confirm bundle determinism:

```sh
sha256sum spine-wasm/pkg/spine_wasm_bg.wasm
cargo clean -p spine-wasm
(cd spine-wasm && wasm-pack build --target nodejs --release)
sha256sum spine-wasm/pkg/spine_wasm_bg.wasm   # must match
```

## Code style

- `cargo fmt --all` before committing.
- `cargo clippy --workspace --all-targets` must be clean. Allow
  attributes are fine when they are documented inline (one-line
  comment explaining *why* the lint does not apply); silent
  `#[allow]` is not.
- `spine-core` is `#![deny(clippy::unwrap_used)]` and
  `#![deny(clippy::expect_used)]`. Use typed errors, `?`, or
  explicit fallbacks. The wasm crate is the same. The CLI shell
  uses `#![warn(...)]` (not deny) because user-input panics can
  be acceptable on a CLI but every `unwrap` site should be
  intentional.
- Comments should explain *why*, not *what*. The function name
  and the code already say what; a comment earns its place by
  surfacing a non-obvious constraint, a subtle invariant, or a
  decision rationale that would not be visible to a future
  reader.
- Don't add module-level "module overview" comments unless the
  module's purpose is non-obvious. The structure is documented
  in the README; per-module commentary should focus
  on contracts and invariants the rest of the crate depends on.

## Commit conventions

- One concern per commit. A bugfix and a refactor in the same
  commit are two commits.
- Imperative mood in the title ("Fix payload-hash recompute on
  empty payload", not "Fixed …" or "Fixes …").
- Title under ~70 chars. Body wrapped at ~72.
- Body explains the *why*. The diff already shows the *what*.
- For changes that touch crypto contracts, signature schemes, or
  the canonical-JSON subset, include a one-line verification
  block in the body listing the test commands you ran and their
  results (`114/114 pass`, `wasm32 build clean`, etc.).
- Update `CHANGELOG.md` under the `[Unreleased]` heading for any
  notable or user-facing change. The format follows
  [Keep a Changelog](https://keepachangelog.com).

## Pull requests

- Open against `main`. We do not maintain long-running release
  branches at this point.
- The PR description should answer: *what* changed, *why* it
  changed, and *what could break*. The "what could break" line
  is required for any change that touches `spine-core` or
  `test-vectors/`.
- The CI gate (when wired up) is the same as the local gate
  documented above. PRs that fail the gate are not merged.
- Squash vs. merge: we prefer linear history. Multi-commit PRs
  are fine if each commit is independently meaningful; otherwise
  the maintainer may squash on merge.

## Cross-language vectors are sacred

`test-vectors/vectors.json` is regenerated independently by the
Rust, Node, and Python implementations and asserted byte-equal in
each. Do not change a vector unless you have:

1. Identified what the vector currently asserts and *why*: read
   the existing case's `description` and the surrounding context.
2. Updated all three implementations to produce the new value, or
   confirmed by running them that the new value is correct on each.
3. Bumped the relevant `_version` field in `vectors.json` and
   noted the change in the PR description.

A "fix" that updates only the Rust side and then changes the
expected value to match is a regression in disguise.

## Licensing of contributions

By contributing you agree that your contribution is licensed
under the [Apache License 2.0](LICENSE), the same license the
rest of this repository ships under. We use the Developer
Certificate of Origin (DCO): sign commits with `git commit -s`.
A `Signed-off-by:` line attests that you have the right to
contribute the code under the project's licence.

## Reporting security issues

Security issues go through a separate process. See
[SECURITY.md](SECURITY.md). Please do not open a public issue or
PR for a vulnerability until it has been disclosed and patched.

## Asking questions

For usage questions or design discussion, open a GitHub issue
with the `question` or `discussion` label. For substantive design
proposals (new verifier invariants, schema bumps, contract
changes), open an issue first and link to the PR. Code-only PRs
that change a contract without prior discussion will be closed
with a request to open the design issue first.
