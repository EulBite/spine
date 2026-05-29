# Security policy

Spine ships cryptographic verification code that runs in browsers,
on the command line, and inside production WAL-pipeline servers. We
take security reports seriously and welcome scrutiny. Finding a
real flaw here is high-value work, and a verifier that lies is
worse than no verifier at all.

## Reporting a vulnerability

Email: **security@eulbite.com**

Please **do not** open a public GitHub issue for security reports.
The standard channel is email; if you cannot use email, request a
private discussion thread by opening a non-descriptive issue
("requesting private security disclosure channel") and we will
respond there with a way to share details privately.

We aim to:

- **Acknowledge** the report within 3 business days.
- **Assess** severity and reproducibility within 10 business days.
- **Patch** within 90 days for confirmed high/critical findings,
  faster for active exploitation. We coordinate timing with the
  reporter; early publication is fine when the issue is mitigated
  or low risk.

If you do not hear back within the acknowledgement window, please
follow up, as your report may have been caught by a spam filter.

## What is in scope

The following components, when used as documented:

- **`spine-core`**: the verification library.
  - Soundness of `verify_demo_wal` (strict) and `verify_wal_bytes`
    (lenient): chain replay, signature verification, payload-hash
    recomputation, canonical-JSON serialisation.
  - Memory safety / panic paths reachable from public APIs. The
    crate is `#![deny(clippy::unwrap_used)]` by policy; any
    documented public input that produces a panic is in scope.
  - Test-vector conformance (`test-vectors/vectors.json`): a case
    where the verifier does not reproduce a pinned canonical-JSON,
    entry-hash, or signature value. The vectors are the wire
    contract; a divergence is a correctness bug.
- **`spine-wasm`**: the WebAssembly façade.
  - The JS-callable surface (`verify_demo_wal_json`,
    `verify_wal_bytes_json`) and its JSON envelope.
  - Bundle-integrity issues that survive the documented bootstrap
    (manifest-pinned hashes, Blob-URL dynamic import).
- **`spine-cli`**: the offline auditor binary.
  - Verification correctness; export integrity (the manifest
    that accompanies a JSONL export must commit to a digest of the
    full source WAL, distinct from the filtered subset).
- **`playground-spec/`**: the integration contract.
  - Documented bootstrap order and integrity-check flow.
  - The reference React component's integrity logic (manifest +
    SHA-256 + Blob-URL dynamic import). Cosmetic React issues are
    not security; bypasses of the integrity flow are.
- **`demo-seeder`**: the offline seeding tool.
  - Key-handling hygiene (no key bytes on disk, zeroize-on-drop,
    interactive prompts before display).
  - Self-verify guard: the binary refuses to write outputs that
    fail `verify_demo_wal` against its own freshly-computed
    pubkey/root.

## What is out of scope

These are **not** security issues against this repository:

- Operational integrity of any specific Spine deployment.
  Misconfiguration of a host site's CSP, SRI, cache, or asset
  pipeline is the deploying site's responsibility. See
  `playground-spec/INTEGRATION.md` § 7 for the documented
  requirements.
- Key-management, HSM integration, key rotation, or multi-signer
  flows. None of that lives here.
- Compliance certifications.
- Misuse of the lenient `verify_wal_bytes` in a context that
  required pinning. The default lenient entry point is policy-free
  (an opt-in `trusted_pubkey` pin and `expected_root` anchor exist
  but are off by default); using the unpinned path where strict
  pinning is needed is a usage error, not a vulnerability.
- DoS reports against the lenient CLI auditor on adversarial
  inputs. The strict path has documented hard limits
  (`MAX_RECORDS_DEMO`, `MAX_PAYLOAD_BYTES`); the lenient path does
  not, by design, because it processes large production WALs.
- Issues that require the attacker to already have the demo
  signing private key, or to control the deploy host's filesystem.
  Those threat models are documented as outside the verifier's
  scope.

## Disclosure and credit

After a reported issue is patched and the fix is published, we
publish a brief advisory in the repository's GitHub Security
Advisories. Reporters are credited by name (or pseudonym) with
their consent; if you prefer to remain anonymous, say so in your
report and we will respect that.

We do not currently run a paid bug bounty programme. We do
acknowledge significant contributions in release notes and on the
project's launch page.

## What constitutes a "verifier lie"

The most consequential class of report against this codebase is a
verifier that returns `valid:true` on a WAL that should be
detected as tampered, or a verifier that fails to detect a
specific class of tampering. Examples that would qualify:

- A WAL whose canonical-JSON serialisation does not match the
  pinned test vectors, so a payload-hash check passes when it
  should fail (or fails when it should pass).
- A signature scheme mismatch where bytes signed by the strict
  contract verify under the lenient one (or vice versa). The two
  contracts are namespaced by domain separator precisely to make
  this impossible; a counterexample would be a serious finding.
- A chain-root computation that ignores ordering, allowing record
  re-arrangement to produce the same digest.
- A timing side channel in pubkey or chain-root comparison that
  leaks the pinned value.

If you find anything in the neighbourhood of those, please report
even if you are not 100% sure. False positives cost us an hour;
false negatives cost us the project.
