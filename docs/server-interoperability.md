# Private server interoperability

This document describes the public compatibility surface exposed by a private
Spine server. The server itself is not part of this Apache-2.0 repository; the
types and verification logic needed by an independent auditor are.

## Authenticate and ingest

Health endpoints are public. Other API routes use the deployment key in the
`x-api-key` header.

```bash
curl -fsS https://spine.example/health/ready

curl -fsS https://spine.example/api/v1/events \
  -H "x-api-key: $SPINE_API_KEY" \
  -H "content-type: application/json" \
  --data '{
    "event_type": "access.reviewed",
    "source": "iam",
    "severity": "info",
    "payload": {"subject":"user-42","decision":"approved"}
  }'
```

Only `payload` is required. The response contains the assigned `sequence`,
`timestamp_ns`, `payload_hash`, and `prev_hash`. `POST /events` remains a
compatibility alias; new integrations should use `/api/v1/events`.

The server replaces any client-supplied authentication metadata with the
authenticated tenant and key identity before hashing and persistence. Managed
tenants can read only their own records through
`GET /api/v1/events/{sequence}`. Older records may not contain a recoverable
inline payload.

## Fetch and verify an authenticated root

The server publishes a signed snapshot of its current linear chain root:

```bash
curl -fsS https://spine.example/api/v1/checkpoint/public \
  -H "x-api-key: $SPINE_API_KEY" \
  -o checkpoint.json
```

The response is a `spine-public-checkpoint-v1` envelope containing
`chain_root`, coverage counters, a nanosecond timestamp, an Ed25519 signature,
and the signing key. The embedded key is descriptive metadata, **not a trust
anchor**. Obtain the deployment's checkpoint public key through an
authenticated out-of-band channel, then pin it explicitly:

```bash
spine-cli verify \
  --wal /path/to/exported-wal \
  --checkpoint checkpoint.json \
  --checkpoint-pubkey "$SPINE_CHECKPOINT_PUBKEY" \
  --checkpoint-max-age-secs 300 \
  --chain-only
```

This first verifies the entire signed checkpoint envelope against the pinned
key, then uses its `chain_root` as the expected root while replaying the WAL.
Supplying both `--checkpoint` and `--expected-root` is allowed only when the
two roots agree. `--checkpoint-max-age-secs` also rejects a checkpoint dated in
the future.

Drop `--chain-only` to verify the record signatures that are present. Use
`--trusted-pubkey` separately when every production record is expected to be
signed by one pinned record key; that key and the checkpoint key serve
different purposes.

## Production and playground profiles

The private server hashes the exact serialized, post-PII-processing payload
bytes it persists. Its WAL should therefore be checked with the default
lenient profile or `--chain-only`, anchored by a verified checkpoint.

The public playground's `--strict` profile instead recomputes every
`payload_hash` from canonical JSON and requires a domain-separated signature
on every record. It is the published demo contract, not a drop-in replacement
for production-server WAL verification.

WAL formats v1 and v2 retain their historical payload representation. New
production records use WAL format v3: their `payload_hash` is computed from the
same NFC-normalized, UTF-16-key-ordered canonical JSON used by `spine-core` and
the browser verifier. Format v3 keeps the injective v2 entry framing. The public
verifier retains v1/v2 support, so existing evidence is never reinterpreted.

## Witnessed checkpoint history and tenant audit packs

The evidence API exposes the independently verifiable proof surface:

- `GET /api/v2/checkpoints/latest`: latest persisted checkpoint receipt;
- `GET /api/v2/checkpoints/history`: paginated receipt history;
- `POST /api/v2/audit-packs`: tenant-scoped evidence bundle.

A v2 checkpoint commits to the global chain root and to each tenant's events in
the newly covered interval. Receipts link by `previous_checkpoint_id`.
Operator-key changes are accepted only through a transition signed by both the
previous and new key. A witness separately signs the checkpoint id and its own
`observed_at_ns`.

For offline verification, save the complete history as JSONL and pin the
genesis operator key and witness key through an independent channel:

```bash
spine-cli verify-checkpoint \
  --input checkpoint-history-v2.jsonl --history \
  --operator-public-key "$SPINE_GENESIS_OPERATOR_PUBKEY" \
  --witness-id "$SPINE_WITNESS_ID" \
  --witness-public-key "$SPINE_WITNESS_PUBKEY" \
  --expected-chain-id primary-eu \
  --max-age-secs 300
```

Audit packs require the expected tenant id as independent input; the verifier
hashes it locally rather than trusting the embedded `tenant_ref`:

```bash
spine-cli verify-audit-pack \
  --input tenant-audit-pack.json \
  --tenant-id tenant-a \
  --operator-public-key "$SPINE_GENESIS_OPERATOR_PUBKEY" \
  --witness-id "$SPINE_WITNESS_ID" \
  --witness-public-key "$SPINE_WITNESS_PUBKEY"
```

When a witness is pinned, freshness uses the witness-signed observation time.
Operator time is used only under the explicit `--allow-unwitnessed` downgrade.

## Live updates

Dashboard-compatible live updates use `GET /ws/live` with WebSocket
subprotocol `spine.dashboard.v1`. A managed tenant receives its own events and
sanitized shared-chain state. The server does not send other tenants' events or
global tenant aggregates on that connection.

The checkpoint JSON schema, signed-message byte layout, and WAL field framing
are pinned by tests in `spine-core`. Any incompatible server change requires a
new public schema/version rather than a silent reinterpretation.
