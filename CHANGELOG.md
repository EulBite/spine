# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `spine-cli` integration tests covering argument parsing, exit codes, and
  JSONL/CSV/text output.

### Changed

- `spine-core`: parse fixed-width hex strings with `try_into`.
- Resolved `clippy` pedantic and nursery lints across `spine-cli` and
  `spine-wasm`.
- Rendered the playground initialisation and integrity-check flow as a Mermaid
  sequence diagram.
- Aligned the demo seeder's private-key disclosure output with its operational
  runbook.
- General documentation wording and formatting polish.

### Fixed

- `spine-core`: canonical JSON now rejects integer-valued floats outside `i64`
  range instead of saturating the cast, tightening payload encoding so distinct payloads always serialise to distinct canonical bytes.
- `spine-cli`: write the export sidecar manifest before publishing the data
  file, so a failed manifest write can no longer leave a named export without a
  manifest.
- Corrected the documented test count and the demo chain-root value so the
  runbook matches the current output.

## [0.1.0] - 2026-05-27

### Added

- `spine-core`: WAL verification library with BLAKE3 hash-chain replay, Ed25519
  signature verification, an RFC 8785 (JCS) canonical-JSON subset, and both
  lenient and strict verifier profiles.
- `spine-cli`: standalone offline auditor with `verify`, `export`
  (JSONL/CSV/syslog), and `inspect` subcommands.
- `spine-wasm`: WebAssembly facade exposing the strict and lenient verifiers to
  JavaScript.
- `test-vectors`: language-independent vectors pinning canonical JSON, entry
  hashing, and Ed25519 signatures.
- `playground-spec`: integration contract for embedding the in-browser
  verification playground.

[Unreleased]: https://github.com/EulBite/spine/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/EulBite/spine/releases/tag/v0.1.0
