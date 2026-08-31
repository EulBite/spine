# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-31

### Added

- `spine-core`: pure verification for `spine-checkpoint-receipt-v2`, chained
  checkpoint histories, independently pinned witness observations and
  cross-signed operator-key rotation.
- `spine-core`: tenant-scoped `spine-audit-pack-v1` verification, including
  tenant identity, versioned payload hashes, event ordering, signed interval
  commitments and the embedded checkpoint proof.
- `spine-cli verify-checkpoint` and `verify-audit-pack`, witness-required by
  default with an explicit `--allow-unwitnessed` downgrade.
- WASM entry points for individual checkpoints, checkpoint histories and audit
  packs, with bounded JSON inputs and structured valid/invalid reports.
- Server-generated interoperability fixtures covering rotation, witness and a
  complete tenant audit pack.
- `spine-core`: exact, no-network verification of
  `spine-public-checkpoint-v1` envelopes emitted by the private server. The
  verifier pins the Ed25519 key from outside the envelope, covers every signed
  field, and can reject stale or future checkpoints.
- `spine-cli verify`: `--checkpoint`, `--checkpoint-pubkey`, and
  `--checkpoint-max-age-secs` authenticate a server checkpoint and use its
  `chain_root` as the WAL anchor. A conflicting explicit `--expected-root` is a
  usage error.
- Public documentation for current event-ingest, checkpoint, tenant isolation,
  WebSocket, and production-versus-playground compatibility contracts.

### Security

- External pins are compared in constant time; embedded signed fields require
  canonical lowercase hex. Witness observations cannot predate their
  checkpoint, move backwards in a history or claim a future observation under
  a caller-supplied clock.
- Updated the transitive `anyhow` test-tool dependency to 1.0.103, resolving
  the `Error::downcast_mut` unsoundness tracked as RUSTSEC-2026-0190.

### Changed

- `WAL_FORMAT_VERSION` is now 3. New producer records hash payloads with the
  same NFC-normalized canonical JSON used by the public verifier. Versions 1
  and 2 retain their historical payload encoding and remain verifiable.

## [0.2.0] - 2026-07-05

### Added

- WAL format version 2 for the entry hash. Optional fields are now
  length-prefixed (`0x01 || u64_LE(len) || value`) so a value can no longer
  imitate the boundary of the next field, and `severity`, `key_id`, `event_id`,
  and `stream_id` join the hashed preimage. Verifiers keep accepting version-1
  records and hash them with the original framing, so existing WAL files and the
  published demo continue to verify unchanged.
- Rejection of ASCII control characters in the free-text record fields
  (`event_type`, `source`, `severity`, and the SDK metadata identifiers). These
  fields are short identifiers where control characters carry no meaning, and
  refusing them also closes the version-1 collision (see Fixed) for records
  still read under the old framing.
- Cross-language vectors for version 2, including injectivity witnesses and
  cases for the newly bound severity and metadata fields, so a re-implementation
  proves it frames every hashed field the same way.
- `spine-cli verify --strict`: verify a WAL under the strict profile (the same
  contract the browser playground runs). Pins the signing key from
  `--trusted-pubkey`, requires `--expected-root`, and recomputes each
  `payload_hash` from the canonical JSON of the inline payload. This is the
  profile the published demo WAL is signed under, so it now verifies on the CLI
  as well as in the playground.
- `spine-cli verify`: when every record fails signature verification under the
  default lenient profile, the report now hints that the WAL may be
  strict-profile and points at `--strict`, rather than leaving a bare wall of
  identical signature errors.
- `spine-cli` integration tests covering argument parsing, exit codes, and
  JSONL/CSV/text output, plus the strict profile and the profile hint.

### Changed

- `WAL_FORMAT_VERSION` is now 2. New producers emit version 2; the verifier
  reads each record's declared version and hashes it with the framing of that
  version, so a single build verifies both v1 and v2 WAL files.
- The strict verifier accepts any supported format version rather than only the
  latest, which is what lets an already-published version-1 demo keep verifying
  after the bump.
- `spine-core`: parse fixed-width hex strings with `try_into`.
- Resolved `clippy` pedantic and nursery lints across `spine-cli` and
  `spine-wasm`.
- Rendered the playground initialisation and integrity-check flow as a Mermaid
  sequence diagram.
- Aligned the demo seeder's private-key disclosure output with its operational
  runbook.
- General documentation wording and formatting polish.

### Fixed

- The WAL entry hash was not injective. A `U+0001` byte inside `event_type` or
  `source` could imitate the presence marker of the following field, so two
  semantically different records hashed to the same digest. It was reachable
  from arbitrary ingest text, which weakened the chain against a forger. The
  version-2 length prefix removes the ambiguity.
- The strict verifier committed to only part of each record it accepted:
  `key_id`, `event_id`, and `stream_id` were on the allowlist but outside the
  hash, so all three could be altered on an otherwise-valid record and it still
  verified. Version 2 binds them, so a field the verifier accepts can no longer
  ride along unauthenticated.
- The strict verifier now rejects a record that carries a receipt it cannot
  verify instead of accepting it unchecked. Receipts remain verifiable under the
  lenient profile when a keystore is supplied.
- `spine-core`: canonical JSON now rejects integer-valued floats outside `i64`
  range instead of saturating the cast, tightening payload encoding so distinct
  payloads always serialise to distinct canonical bytes.
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

[Unreleased]: https://github.com/EulBite/spine/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/EulBite/spine/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/EulBite/spine/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/EulBite/spine/releases/tag/v0.1.0
