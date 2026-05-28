# Demo WAL Offline Seeding

This document is the operational runbook for generating the signed demo
WAL that backs the public playground. It is meant to be followed by a
human, not by an automation, because the security of the entire demo
hinges on the private key never leaving an airgapped boundary.

The Rust binary `demo-seeder` is the only tool involved. Its source lives
next to this file; everything it does is documented in `src/main.rs` and
`src/scenario.rs`.

> **One-liner**: Compile on a connected machine, copy the binary onto
> a USB stick, run it on a freshly-wiped airgapped machine, write the
> private key onto paper, transfer the four output files back via a
> separate clean USB stick, destroy the airgapped machine's terminal.

## What the binary produces

Four files in `--output-dir` (default: current directory):

- `demo.jsonl`: the signed WAL (one JSONL record per line, 20 records).
- `demo.pubkey`: 64-char lowercase hex of the Ed25519 verifying key.
- `demo.expected_root`: 64-char lowercase hex of the BLAKE3 chain root.
- `demo-manifest.json`: playground manifest skeleton with the pinned
  crypto values filled in. `wal_sha256` / `wasm_sha256` / `wasm_url` are
  left as `TODO_FILLED_BY_BUILD` placeholders for the build pipeline
  to fill in once the wasm bundle and WAL hash are known.

The **private key** is printed once on stdout, in red, between two
`[Enter]` prompts, and never written to disk. Capture it manually onto
paper or a hardware vault. If you lose it, the demo WAL becomes immutable:
you can verify it forever, but you can never re-sign or extend it.

## Pre-flight checklist (connected machine)

Run these on the regular development machine, **before** going airgapped:

1. Build a release binary and a fresh test fixture:

   ```sh
   cd demo-seeder
   cargo build --release
   ./target/release/demo-seeder --deterministic-seed 42 --non-interactive --output-dir out-test
   ```

   The run ends with `Generated 20 records (test fixture, seed exposed
   in source).`, the four output paths, and `Chain root:
   c36bd135f17fbd48…`. That `chain_root` is reproducible across runs of
   the same seed; if it ever drifts, something in `spine-core` changed
   and the cross-language parity needs re-validating.

2. Cross-check the test fixture with `spine-cli verify`:

   ```sh
   cd ../
   cargo build --release -p spine-cli
   ./target/release/spine-cli --format json verify --wal demo-seeder/out-test/ \
     | grep -E 'chain_root|events_verified|valid'
   ```

   Expected output: `valid: false`, `events_verified: 20`,
   `chain_root: c36bd135…`. The `valid: false` is **correct**: the
   lenient verifier (used by `spine-cli`) and the strict verifier
   (used by the playground) sign over different messages by design.
   See the cross-API doc-comments in `verify.rs` and
   `verify_demo.rs`. The matching `chain_root` is the parity
   guarantee that this fixture and a live playground run see the
   same chain.

3. Wipe the test fixture so it does not contaminate the airgapped run:

   ```sh
   rm -rf demo-seeder/out-test
   ```

4. Copy the airgapped binary onto a fresh USB stick:

   ```sh
   cp demo-seeder/target/release/demo-seeder /path/to/usb-binary/
   ```

5. Verify the USB stick is otherwise empty (no other files, no
   leftover history). Eject.

## Airgapped run

Use a freshly-wiped laptop or a known-clean USB live OS. Confirm Wi-Fi,
Ethernet, and Bluetooth are all physically disabled before plugging
anything in.

1. Plug the binary USB stick. Mount it.
2. Run the seeder:

   ```sh
   /path/to/usb-binary/demo-seeder --records 20 --output-dir ./out
   ```

   No `--deterministic-seed` flag: the production run uses `OsRng`. The
   seeder first prints the scenario, output directory, and pubkey, then
   waits on `Press Enter to continue, Ctrl-C to abort.`. Review the
   summary and press `[Enter]`.

3. It generates and self-verifies the WAL, writes the four files
   (`Generated 20 records.` followed by the WAL / Pubkey / Root /
   Manifest paths), then prints the private key inside a red banner:

   ```
   ================================================================
     PRIVATE KEY HEX (this is shown ONCE, copy to offline vault)
   ================================================================

     <64 lowercase hex chars>

   ================================================================
   ```
4. Write the 64-character hex key onto paper, or burn it into a hardware
   vault (Yubikey, Trezor, paper wallet). Double-check the hex by reading
   it back to a colleague or to a recorder. **This is the only time the
   key will exist outside the running process.**
5. Press `[Enter]` once the key is captured. The in-memory copies are
   zeroised and the binary exits. (Best-effort only: scrollback buffers
   on some terminals may still retain the line, so treat the terminal as
   disposable after this run.)
6. Eject the binary USB stick. Plug a separate, freshly-wiped
   transfer USB stick.
7. Copy the four output files to the transfer stick:

   ```sh
   cp ./out/demo.jsonl ./out/demo.pubkey ./out/demo.expected_root \
      ./out/demo-manifest.json /path/to/usb-transfer/
   ```

8. Eject the transfer USB stick. Shut down the airgapped machine
   (full power-off, not sleep).

## Post-airgap (back on connected machine)

1. Mount the transfer USB stick.
2. Sanity-check the WAL with `spine-cli`:

   ```sh
   spine-cli --format json verify --wal /path/to/usb-transfer/ \
     | grep -E 'chain_root|events_verified'
   ```

   Confirm `events_verified: 20` and that the `chain_root` matches
   the contents of `demo.expected_root`.

3. Move the four files into the input directory the build
   pipeline expects (default: `demo-seeder/out/` at the repository
   root, picked up by `playground-spec/build-playground-assets.sh`):

   ```sh
   mkdir -p demo-seeder/out/
   mv /path/to/usb-transfer/demo.* demo-seeder/out/
   mv /path/to/usb-transfer/demo-manifest.json demo-seeder/out/
   ```

   The hosting build is responsible for hashing `demo.jsonl` into
   `wal_sha256` and the wasm bundle into `wasm_sha256`, replacing the
   `TODO_FILLED_BY_BUILD` placeholders in `demo-manifest.json`, and
   pinning the manifest in 3+ independent locations.

4. Wipe the transfer USB stick (full overwrite, not just delete).

## What can go wrong

- **Self-verify fails inside the seeder.** The binary aborts before
  writing anything. Re-run; if it persists, there is a bug in
  `spine-core` or in `demo-seeder`. Do not ship corrupt output.

- **You skipped capturing the private key.** The four output files are
  still cryptographically valid and the playground will work. You just
  cannot extend the WAL or re-sign anything. Generate a new keypair
  (= new airgapped run) and pin a new manifest.

- **The terminal scrollback retained the key line.** Treat the machine
  as compromised: do not reuse it for sensitive work, and rotate the
  manifest pubkey at the next opportunity.

- **You are tempted to commit `demo.jsonl` to the public repo.** It is
  ignored by `.gitignore` for this reason. The manifest pinning happens
  in the build pipeline with a deliberate path; do not pre-commit fixtures.

## What this binary does NOT do

- Generate or rotate the wasm bundle.
- Compute SHA256 over `demo.jsonl` and the wasm bundle.
- Pin the manifest in 3+ independent locations.
- Talk to any network (`getrandom` is the only entropy source, reading
  from `/dev/urandom` on Linux, BCryptGenRandom on Windows).

## Determinism flag (testing only)

`--deterministic-seed <u64>` replaces `OsRng` with a ChaCha20-seeded
RNG. Output is byte-for-byte reproducible across runs of the same seed.
Useful for CI and regression tests; **fatal in production**, because the
private key has zero entropy. The flag is hidden from `--help`. Anyone
reaching for it should already know what they are doing.
