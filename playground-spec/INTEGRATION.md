# Spine Playground Integration Spec

This directory is the **interface contract** between the public verifier
stack (this repository) and any host page that wants to embed the
playground. The host page lives outside this repository. It can be
the launch site, a fork, or any third-party deployment that wants to
verify Spine WAL files in a browser.

This spec exists so that wiring up the integration does not require
deciphering the strict-verifier contract from scratch. It is
deliberately framework-light and host-agnostic; nothing here assumes
a specific React app, build tool, or deploy target.

## What "the playground" is

A page that loads the wasm verifier in the visitor's browser, fetches a
pre-signed demo banking WAL, and lets the visitor edit the amount field
of one specific record. On every "Verify" click, the wasm verifier runs
end-to-end (including BLAKE3 chain replay, payload-hash recomputation
from canonical JSON, and Ed25519 signature verification with domain
separation) and surfaces the result.

Editing the amount makes verification fail at the modified sequence
with a `PayloadHashMismatch` outcome. That failure is the demo's
cryptographic claim: "you cannot forge a signed entry without the
private key."

## The five files in this directory

| File | Purpose |
|---|---|
| [INTEGRATION.md](INTEGRATION.md) | This file: index + integration overview. |
| [DemoSection.example.jsx](DemoSection.example.jsx) | Reference React 18 component, drop-in template for the host page. |
| [manifest.example.json](manifest.example.json) | Shape of `playground/manifest.json` after the build pipeline fills in the SHA256s. |
| [flow-diagram.md](flow-diagram.md) | Sequence diagram of the async init + integrity-check flow. |
| [build-playground-assets.sh](build-playground-assets.sh) | Orchestrates `wasm-pack` + `demo-seeder` + manifest hash injection into a staged asset directory ready for copy into the host site's static-asset directory. |

## The integration contract

### 1. Async init pattern (one-shot before any verify call)

```js
// DO NOT statically import the JS glue:
//   import init from '/playground/assets/spine_wasm.js';   <- UNSAFE
// A static import executes the glue BEFORE any integrity check runs.
// A compromised CDN that swaps spine_wasm.js for a malicious build
// would win immediately. The wasm bytes verification that comes after
// is irrelevant once attacker JS is already executing.
//
// Instead, fetch the glue, hash-check it against `manifest.js_sha256`,
// and dynamic-import the verified bytes through a Blob URL:

const jsBytes = new Uint8Array(await (await fetch(manifest.js_url)).arrayBuffer());
if (await sha256Hex(jsBytes.buffer) !== manifest.js_sha256) {
    throw new Error('JS glue hash mismatch: refusing to verify');
}
const blobUrl = URL.createObjectURL(
    new Blob([jsBytes], { type: 'application/javascript' }),
);
let mod;
try { mod = await import(blobUrl); }
finally { URL.revokeObjectURL(blobUrl); }

const { default: init, verify_demo_wal_json } = mod;

// init() accepts a BufferSource. Pass the wasm bytes you have ALREADY
// fetched and verified. This avoids a second network round trip and
// closes a TOCTOU window between fetch+hash and import+execute.
await init(verifiedWasmBytes);

// Now safe to call verify_demo_wal_json(...) any number of times.
```

In React: gate every verify call behind a `wasmReady` boolean state;
flip it true inside the `useEffect` that finished `init()`. See
`DemoSection.example.jsx`.

### 2. Integrity-check sequence (strict order, fail-loud)

```
 1. Fetch /playground/manifest.json
 2. assert manifest.schema_version === 1
 3. Fetch /playground/assets/<wal_url> -> ArrayBuffer
 4. Compute SHA-256 via crypto.subtle.digest("SHA-256", walBytes)
 5. assert hex(walHash) === manifest.wal_sha256   else ABORT
 6. Fetch /playground/assets/<js_url> -> ArrayBuffer (the wasm-bindgen glue)
 7. Compute SHA-256 via crypto.subtle.digest("SHA-256", jsBytes)
 8. assert hex(jsHash) === manifest.js_sha256     else ABORT
 9. Dynamic-import the JS glue via a Blob URL constructed from jsBytes
    so the bytes that hashed are the bytes that execute
10. Fetch /playground/assets/<wasm_url> -> ArrayBuffer
11. Compute SHA-256 via crypto.subtle.digest("SHA-256", wasmBytes)
12. assert hex(wasmHash) === manifest.wasm_sha256 else ABORT
13. await init(wasmBytes)   <- uses the already-verified buffer
14. UI ready
```

`ABORT` means: render a red banner ("manifest verification failed,
refusing to verify") and **do not import the glue or call `init()`**.
Loading a wasm bundle (or JS glue) whose SHA-256 disagrees with the
manifest is worse than not running the demo at all. It's a lying
verifier.

Step 8 is the critical one. A naïve implementation would import the JS
glue statically (`import init from '...'`) and hash the wasm only,
which is wrong, because the JS glue runs unconditionally on import. A
compromised CDN that swaps the glue would win before any wasm hash
check ran. Always fetch+hash+blob-import the glue too.

The browser-side hash is **in addition to**, not a replacement for,
the SRI attribute on the `<script>` tag (see §7 below).

### 3. Editing: string replacement, never JSON round-trip

The canonical JSON form is byte-sensitive. `JSON.parse(line)` followed
by `JSON.stringify(...)` can change key order, escape forms, whitespace,
or numeric formatting, producing a different byte sequence than the one
the producer signed. That would corrupt the demo's whole point.

```js
const lines = walText.split('\n');
const targetIdx = manifest.edit_target_sequence - 1;  // sequence is 1-indexed
const original = lines[targetIdx];

// Surgical replace inside the JSON value of "amount". Safe here because
// the producer (demo-seeder) controls the field shape exactly:
//   "amount":"100.00 EUR"
const tampered = original.replace(
    /("amount":")[^"]*(")/,
    `$1${newAmount}$2`
);

lines[targetIdx] = tampered;
const tamperedBytes = new TextEncoder().encode(lines.join('\n'));

// Verify. Pass `manifest_version` (the verifier's pinned axis), NOT
// `schema_version` (the manifest envelope's own axis). The two evolve
// independently.
const envelope = JSON.parse(verify_demo_wal_json(
    tamperedBytes,
    manifest.expected_public_key,
    manifest.expected_chain_root,
    manifest.manifest_version,
));
```

Document this verbatim in the React component:

> We deliberately avoid `JSON.parse` + `JSON.stringify` round-trip
> because the demo's cryptographic guarantee depends on canonical-JSON
> byte equality. Even an apparently-equivalent reserialisation would
> break that guarantee.

### 4. UX: minimal on VALID, maximal on INVALID

The valid path is uneventful: calm green checkmark, "20 records
verified", chain root, done. The visitor's takeaway is "it just
worked."

The invalid path is where the cryptographic claim becomes visible.
Render a side-by-side diff:

```
✗ TAMPERING DETECTED at sequence 11

Field: payload.amount
  Original (signed):    "100.00 EUR"
  Modified (your edit): "10000.00 EUR"

Computed payload_hash: a3f2b1c4...
Declared payload_hash: 9c2b0d18...
                        ↑ MISMATCH

This is mathematically detectable. The attacker has full disk access,
but cannot forge a signed entry without the private key, which never
touches any server.
```

The strict verifier surfaces a record with
`outcome: "invalid"` and
`reason: { kind: "payload_hash_mismatch", declared, computed }` for the
case above. The React component reads `report.records[i].reason` and
renders this panel directly.

### 5. Honest scope disclaimer (collapsed accordion)

Below the verifier output, a closed-by-default accordion titled
"What this demo does and does not verify":

- ✓ The cryptographic integrity of a signed WAL: hash chain replay,
  payload-hash recomputation, Ed25519 signature with domain separation.
- ✗ Operational integrity of any Spine deployment, key-management
  practices, compliance posture of any specific customer.
- Link to the public verifier source (`github.com/EulBite/spine`,
  once the repo is made public).

Honesty up front pre-empts the first competent critic.

### 6. Manifest pinning (build pipeline)

Run [`build-playground-assets.sh`](build-playground-assets.sh) on the
build host. It:

1. Builds the wasm bundle: `wasm-pack build --target web --release`
2. SHA-256s `demo-seeder/out/demo.jsonl`, `pkg/spine_wasm_bg.wasm`,
   and the wasm-bindgen glue `pkg/spine_wasm.js`
3. Injects those digests into the manifest skeleton, replacing the
   `REPLACE_WITH_SHA256` placeholders left by `demo-seeder`
4. Stages the four files (`spine_wasm.js`, `spine_wasm_bg.wasm`,
   `demo.jsonl`, `manifest.json`) in `playground-spec/dist/`
5. Prints the next step: copy `dist/*` into the host site's
   static-asset directory (e.g. `public/playground/`).

The same `manifest.json` is also published in **two more independent
locations**:

- This repository, under `playground/manifest.json`.
- A versioned launch blog post pinned to the manifest digest.

Three publication points means a CDN compromise is detectable by
anyone who cross-checks.

### 7. CSP, SRI, immutable cache (host page concerns)

The page that mounts the playground needs:

- **CSP**: a strict policy that whitelists the playground asset origin
  for `script-src` and `connect-src`, **plus the `blob:` scheme in
  `script-src`** because the integrity-check flow in §1 dynamic-imports
  the verified glue from a `Blob` URL. Minimum viable directive:

  ```
  Content-Security-Policy:
      default-src 'self';
      script-src 'self' blob:;
      connect-src 'self';
      style-src 'self' 'unsafe-inline';
      img-src 'self' data:;
      object-src 'none';
      base-uri 'none';
      form-action 'none';
      frame-ancestors 'none';
  ```

  Notes on the choices:
  - `script-src 'self' blob:`: required for `import(blobUrl)` after
    the SHA-256 check. **Adding `blob:` is NOT a substitute for
    verification**: the bytes inside the Blob are the bytes the
    browser already hashed against `manifest.js_sha256`. Without
    `blob:` the bootstrap fails at the dynamic import step with a CSP
    violation, and the playground never reaches the verifier.
  - `'unsafe-eval'` is **NOT** required. `import(blobUrl)` is the
    module-loader path, distinct from `eval()`. Do not add it.
  - `'unsafe-inline'` on `script-src` is **NOT** required and must
    not be added, as there are no inline scripts on the page.
  - The page does no XHR/fetch outside its own origin, so
    `connect-src 'self'` is sufficient.

  An alternative architecture would skip the Blob URL by static-importing
  the wasm-bindgen glue and verifying only the wasm bytes, but that
  reopens the original "JS glue executes before any check" hole. The
  Blob-URL approach trades one extra CSP scheme for closing that hole;
  verified bytes are what executes.

- **SRI**: in the integration described above, `spine_wasm.js` is **not**
  loaded by a `<script src="…">` tag in the host HTML. It is fetched
  and dynamic-imported from a Blob URL after the manifest hash check
  (§1, §2). SRI on a `<script>` tag therefore does not apply to the
  glue. The manifest's `js_sha256` is the integrity guarantee for the
  glue, and `manifest.json` itself is published in three independent
  locations (§6) so a CDN compromise of the manifest is detectable by
  cross-checking.

  The host page's own bundle (the site's main JS, not part of this
  contract) can carry its own SRI digest at the deploy host's
  discretion.
- **Immutable cache** on hash-named assets: `Cache-Control:
  public, max-age=31536000, immutable`. The wasm bundle's filename
  contains its content hash (e.g. `spine-verifier-9c2b0d18.wasm`),
  so cache poisoning is harmless: a different version has a
  different URL.
- **No tracking on `/playground`**: the page loads no analytics, no
  social pixels, no third-party fonts. The pitch is "you don't have
  to trust us", and the page itself must demonstrate that posture.

## Asset URL convention

The build pipeline sets the canonical paths. Until then the example manifest uses
placeholder URLs (`/playground/assets/demo-banking-TODO.jsonl`). After
the build pipeline runs, the URL contains the hash so each version is
addressable independently:

```
/playground/manifest.json
/playground/assets/spine_wasm.js
/playground/assets/spine-verifier-<wasm_sha256[:8]>.wasm
/playground/assets/demo-banking-<wal_sha256[:8]>.jsonl
```

`spine_wasm.js` does not need a hash in the filename because it is
fetched and hash-checked against `manifest.js_sha256` at runtime (§1,
§2), not loaded via a static `<script src>` tag.

## Out of scope for this spec

- The actual visual design, animations, and copy. The component's
  job is to faithfully render the verifier's output; the page's job
  is to frame it. Both belong to whatever site mounts the playground.
- Internationalisation. The verifier output is structured JSON; any
  localisation happens at the React layer.
- Telemetry / analytics. There is none. See §7.
