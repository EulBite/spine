# spine-cli

Standalone offline auditor for [Spine](https://eulbite.com) WAL files.

This binary verifies the cryptographic integrity of a WAL directory without
trusting any Spine server. The verification logic itself lives in
[`spine-core`](../spine-core); this crate is the filesystem and presentation
shell. The same `spine-core` library also backs the in-browser WebAssembly
playground, so a WAL that verifies here verifies there byte-for-byte.

## Subcommands

- `verify`: run BLAKE3 hash-chain and Ed25519 signature verification over a
  WAL directory. Exit code is `0` on `valid:true`, `1` on `valid:false`, `2`
  on I/O or input errors.
- `export`: emit the audit trail as JSON-Lines, CSV, or RFC 5424 syslog.
  JSONL exports written to file are accompanied by a `.manifest.json` that
  pins the chain root (cross-verifiable with `verify`).
- `inspect`: human-readable view of stats, last-N events, and lookup by sequence.

## Quick example

```bash
# Verify a directory of .wal / .jsonl segments
spine-cli verify --wal /path/to/wal

# Same, but emit a JSON report to stdout
spine-cli --format json verify --wal /path/to/wal

# Show 20 most recent events as a table
spine-cli inspect --wal /path/to/wal -n 20

# Export as CSV for spreadsheet analysis
spine-cli export --wal /path/to/wal --export-format csv > audit.csv
```

## Scope

This binary verifies that a WAL is internally consistent: hash chain links,
sequence continuity, timestamp monotonicity, signature validity (when both
the signature and public key are present in the record), and optional
agreement with a caller-supplied `--expected-root` anchor.

It does **not** verify operational integrity of any Spine deployment, key
management practices, or compliance posture. Those concerns belong in audit
and operational reviews, not in cryptographic code.

## License

Apache-2.0. See [LICENSE](../LICENSE).
