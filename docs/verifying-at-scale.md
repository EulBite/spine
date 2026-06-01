# Verifying large WALs

An auditor may receive months of a bank's write-ahead log on a disk:
billions of records, terabytes of JSONL. This note describes how the
open-source verifier handles that, what it guarantees, and where the
honest limits are. It separates three things:

1. What ships in this repository today (the verifier).
2. A verifier-side optimization that is designed but not built here.
3. Server-side work that is out of scope for this repository (it
   belongs to the production server, which is not open source).

The numbers below are measured, not modelled, unless a row is labelled a
projection. The benchmark is a 1,000,000-record lenient-signed WAL
(709.5 MB on disk, ~740 bytes/record, 10 segments) verified by the
release CLI on a single core.

## 1. What ships today

### Streaming verification (constant memory)

`spine-cli verify` streams the WAL one line at a time. Peak memory is
flat regardless of total size: the verifier holds one line buffer plus
the running chain state (a few hashes and counters), never the WAL
itself.

| Run on the 709.5 MB / 1M-record WAL | Wall time | Peak RAM | Throughput |
|-------------------------------------|-----------|----------|------------|
| `verify` (full, every signature)    | 35.4 s    | 4.4 MB   | 28,254 ev/s  |
| `verify --chain-only`               |  4.0 s    | 4.4 MB   | 249,875 ev/s |
| `verify --sample-signatures 1000`   |  4.1 s    | 4.5 MB   | 246,609 ev/s |

The headline is the 4.4 MB column: it does not grow with the WAL. A
buffer-the-whole-file verifier would peak above the WAL size (roughly
1.2 GB on this input); streaming removes that ceiling entirely, so the
disk a bank ships is never bounded by the auditor's RAM.

The same state machine drives the buffered byte API used by the browser
playground and the cross-language vectors, so the streaming and buffered
paths cannot diverge.

### Signature policy

Verifying one Ed25519 signature per record dominates the cost: on the
benchmark it is about 93% of full-verify time. Walking the chain and
parsing JSON is roughly an order of magnitude cheaper. Three policies
let an auditor choose coverage:

- **Full (default).** Every signed record's signature is verified. The
  only policy that defends against a targeted forger. O(n) in the number
  of records.
- **`--chain-only`.** Verifies chain linkage, sequence, timestamps,
  hash formats and the chain root; skips per-record signatures. About
  9x faster here. It retains tamper-evidence only when paired with an
  authenticated `--expected-root` (an external anchor the auditor trusts
  out of band); without one it proves internal self-consistency only.
  Incompatible with `--trusted-pubkey` and `--keystore`.
- **`--sample-signatures N`.** Verifies one record in every N (those
  whose `sequence` is a multiple of N). A routine spot-check for
  accidental corruption or a wrong-key rollout. It is NOT a defense
  against a targeted forger, who can simply avoid the sampled positions;
  a record left unchecked is reported in `signatures_skipped` and the
  result carries a warning. A sampled signature that fails still fails
  the whole run.

Reducing signature coverage never weakens the chain's own
tamper-evidence: chain, sequence, timestamp, hash-format and root checks
always run in full. A broken hash-chain link fails even under
`--chain-only`.

### What this means for an auditor's scenarios

Single core, constant ~5 MB RAM in every row. The first data row is
measured; the rest are projections that scale the measured throughput
linearly (each record is independent work, so this holds until disk I/O
becomes the floor).

| Records (approx size)     | Full verify | `--chain-only` | Peak RAM |
|---------------------------|-------------|----------------|----------|
| 1M (0.7 GB, measured)     | 35 s        | 4 s            | 4.4 MB   |
| 180M (~130 GB)            | ~1.8 h      | ~12 min        | ~5 MB    |
| 1.8B (~1.3 TB)            | ~17.7 h     | ~2.0 h         | ~5 MB    |
| 18B (~13 TB)              | ~7.4 days   | ~20 h          | ~5 MB    |

At 13 TB the `--chain-only` compute time (~20 h) and the time to read
13 TB from disk are the same order of magnitude, so that row is
I/O-bound: wall clock is about a day either way, but still at a few MB
of RAM, on a laptop.

The takeaway: streaming removes the memory wall outright, and
`--chain-only` / `--sample-signatures` make the small and mid scenarios
a matter of minutes to a couple of hours. The largest scenario is the
one that wants a different verification model, described in section 3.

### Honest limits

- Full verification is O(n): there is no way to check every one of N
  signatures in less than N signature verifications on one core.
- `--sample-signatures` trades completeness for speed and is not
  adversarial: document the sample rate in the audit record.
- `--chain-only` is only as strong as the `--expected-root` you pin. An
  unauthenticated root proves the log is self-consistent, not that it is
  the log the bank committed to.

## 2. Designed, not built here: parallel signature verification

Signature verification of one record is independent of every other
record, so the full-verify path parallelizes across cores for a roughly
linear speed-up (for example ~8x on 8 cores), at bounded memory, by
verifying signatures for a window of records in parallel while the chain
walk stays sequential.

This is a verifier-side change and could live in this repository. It is
deliberately not in this release:

- The headline wins (the memory wall, and the order-of-magnitude speed-up
  for routine runs) come from streaming and the signature policy, which
  are simpler and provably correct.
- Doing it without forking the canonical lenient state machine means
  adding threads to `spine-core`, whose value rests on being
  single-source-of-truth, no-panic, and clean to compile to wasm (which
  has no threads by default). That is a larger change than fits beside
  the above.
- Parallelism speeds up the O(n) regime by a constant factor; it does
  not change the asymptotics. For the largest scenario the right answer
  is the sub-linear, proof-based model in section 3, not a faster brute
  force.

Design sketch for when it is built: read records into a bounded window
(for example 8,192 at a time); verify that window's signatures on a
thread pool calling the existing per-record signature primitive in
`spine-core`; keep the chain link, sequence, timestamp and root checks
sequential; merge signature failures back by sequence so output stays
deterministic. Memory stays O(window). No change to the verdict, only to
how fast signatures are checked.

## 3. Out of scope here: sub-linear verification via proofs

The production server (ingestion, batch sealing, retention) is not in
this repository and is not open source. The verification model that
actually removes the "process every record" cost requires the server to
emit additional structure. This section records the design so the
auditor-facing proof-checking can be specified against it; none of it is
implemented in this repository.

### Tier 2: signed checkpoints

The server periodically signs a checkpoint over `(chain_root, length,
timestamp)`: a Signed Tree Head. An auditor verifies a chain of
checkpoints and their consistency instead of every event. The receipts
already carry a `batch_id`, and the README mentions batch sealing, so
the batch structure likely exists server-side already; what is missing
is exposing it to the auditor.

### Tier 3: Merkle transparency log

This is the model that scales to the largest scenario. It is the design
used by Certificate Transparency (RFC 6962) and Trillian to verify
billions of certificates.

The server maintains an append-only Merkle tree over the events and
publishes a signed tree head. With it, an auditor can verify:

- **Inclusion.** That specific events (the ones in the audit scope) are
  in the committed log, each via an inclusion proof of about log2(N)
  hashes. For 18 billion events that is about 35 hashes per event, not
  18 billion.
- **Consistency.** That the current tree is an append-only extension of
  an earlier tree head the auditor already trusts, via a consistency
  proof, so nothing was edited or removed behind the scenes.

The auditor downloads the signed tree head, the events in scope, and
their proofs, and verifies in seconds at constant memory on a laptop,
without reading the bulk of the log at all. That is what turns the
largest scenario from days into seconds.

A future open-source addition to this repository would be the
auditor-side proof checker: given a signed tree head, a set of leaves,
and their inclusion and consistency proofs, verify them. That checker is
pure logic with no server dependency and would fit the same no-panic,
cross-language-vectored contract as the rest of `spine-core`. The
proof-emitting side stays in the production server.

## Recommended workflow

- Routine / periodic re-check of a large WAL: `--chain-only` with an
  authenticated `--expected-root`, or `--sample-signatures N` to spot a
  wrong-key rollout cheaply.
- One-time forensic audit where every signature must be checked: full
  `verify` (streaming keeps it to a few MB of RAM); accept the O(n)
  time, or parallelize once section 2 is built.
- Targeting specific events out of a very large log: the proof-based
  model in section 3, once the server emits proofs.
