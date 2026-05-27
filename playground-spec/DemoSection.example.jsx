// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite
//
// Reference React 18 component for the Spine playground. Drop this
// into the host site's section or page directory and adapt to local
// styling conventions. See ../INTEGRATION.md for the contract this
// component implements.
//
// This file is intentionally framework-light: no Redux, no React
// Query, no animation library. The cryptographic story is the focus,
// not the visual choreography. The host site is free to wrap this
// in any animation or layout library AFTER the integration contract
// is stable.

import { useEffect, useRef, useState } from 'react';

// IMPORTANT: do NOT do `import init from '/playground/assets/spine_wasm.js'`
// at module top-level. A static import executes the JS glue BEFORE the
// integrity-check sequence runs, defeating the whole "verified before
// run" posture. The bootstrap function below fetches the glue, hashes it
// against `manifest.js_sha256`, and only then dynamic-imports it through
// a Blob URL so that the verified bytes are the bytes that execute.

const MANIFEST_URL = '/playground/manifest.json';

// Module-scoped handles populated by bootstrap() once the glue is
// verified and the wasm module is initialised.
let initWasm = null;          // default export from spine_wasm.js
let verifyDemoWalJson = null; // named export

// ----- Crypto helpers (browser-side hash for manifest pinning) ----------

async function sha256Hex(arrayBuffer) {
    const digest = await crypto.subtle.digest('SHA-256', arrayBuffer);
    return Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
}

// ----- Manifest + asset bootstrap -----------------------------------------

async function bootstrap() {
    // 1. Manifest
    const manifestResp = await fetch(MANIFEST_URL, { cache: 'no-cache' });
    if (!manifestResp.ok) {
        throw new BootstrapError('manifest_fetch_failed',
            `Could not fetch manifest (HTTP ${manifestResp.status}).`);
    }
    const manifest = await manifestResp.json();

    if (manifest.schema_version !== 1) {
        throw new BootstrapError('schema_version_mismatch',
            `Manifest schema version ${manifest.schema_version} not supported by this build.`);
    }

    // 2. WAL bytes + hash check
    const walResp = await fetch(manifest.wal_url, { cache: 'force-cache' });
    if (!walResp.ok) {
        throw new BootstrapError('wal_fetch_failed',
            `Could not fetch WAL (HTTP ${walResp.status}).`);
    }
    const walBytes = new Uint8Array(await walResp.arrayBuffer());
    const walHash = await sha256Hex(walBytes.buffer);
    if (walHash !== manifest.wal_sha256) {
        throw new BootstrapError('wal_hash_mismatch',
            `Manifest pinned ${manifest.wal_sha256.slice(0, 16)}…, ` +
            `served bytes hash to ${walHash.slice(0, 16)}…. ` +
            `Refusing to verify.`);
    }

    // 3. JS glue bytes + hash check (BEFORE any code from the glue runs).
    //    A compromised CDN that swaps spine_wasm.js for a malicious build
    //    would otherwise win — the glue runs unconditionally on import.
    //    We verify the hash, then dynamic-import the verified bytes via a
    //    Blob URL so the bytes that hashed are the bytes that execute.
    const jsResp = await fetch(manifest.js_url, { cache: 'force-cache' });
    if (!jsResp.ok) {
        throw new BootstrapError('js_fetch_failed',
            `Could not fetch JS glue (HTTP ${jsResp.status}).`);
    }
    const jsBytes = new Uint8Array(await jsResp.arrayBuffer());
    const jsHash = await sha256Hex(jsBytes.buffer);
    if (jsHash !== manifest.js_sha256) {
        throw new BootstrapError('js_hash_mismatch',
            `Manifest pinned ${manifest.js_sha256.slice(0, 16)}…, ` +
            `served JS glue hash to ${jsHash.slice(0, 16)}…. ` +
            `Refusing to verify.`);
    }

    // Dynamic-import the verified glue. The Blob URL is revoked
    // immediately so it cannot be re-imported under a different
    // identity later.
    const blob = new Blob([jsBytes], { type: 'application/javascript' });
    const blobUrl = URL.createObjectURL(blob);
    let mod;
    try {
        mod = await import(/* @vite-ignore */ blobUrl);
    } finally {
        URL.revokeObjectURL(blobUrl);
    }
    initWasm = mod.default;
    verifyDemoWalJson = mod.verify_demo_wal_json;
    if (typeof initWasm !== 'function' || typeof verifyDemoWalJson !== 'function') {
        throw new BootstrapError('js_glue_shape_unexpected',
            'Verified JS glue does not export init / verify_demo_wal_json.');
    }

    // 4. WASM bytes + hash check.
    const wasmResp = await fetch(manifest.wasm_url, { cache: 'force-cache' });
    if (!wasmResp.ok) {
        throw new BootstrapError('wasm_fetch_failed',
            `Could not fetch wasm bundle (HTTP ${wasmResp.status}).`);
    }
    const wasmBytes = new Uint8Array(await wasmResp.arrayBuffer());
    const wasmHash = await sha256Hex(wasmBytes.buffer);
    if (wasmHash !== manifest.wasm_sha256) {
        throw new BootstrapError('wasm_hash_mismatch',
            `Manifest pinned ${manifest.wasm_sha256.slice(0, 16)}…, ` +
            `served bytes hash to ${wasmHash.slice(0, 16)}…. ` +
            `Refusing to verify.`);
    }

    // 5. Initialise the wasm module from the ALREADY-VERIFIED bytes.
    //    Passing wasmBytes (BufferSource) bypasses init's URL-resolution
    //    path, so the bytes that hashed are the bytes that execute. No
    //    second fetch, no TOCTOU window.
    await initWasm(wasmBytes);

    return { manifest, walBytes };
}

class BootstrapError extends Error {
    constructor(kind, message) {
        super(message);
        this.kind = kind;
    }
}

// ----- Surgical edit of the target record -------------------------------
//
// IMPORTANT: we deliberately avoid JSON.parse + JSON.stringify on the
// target line because the canonical JSON form is byte-sensitive. Any
// reserialisation could change key order, escape forms, or whitespace
// and produce bytes the producer never signed. The demo's whole pitch
// rests on byte-exact canonical equality.

function rewriteAmount(walBytes, editTargetSequence, newAmount) {
    const text = new TextDecoder().decode(walBytes);
    const lines = text.split('\n');
    const idx = editTargetSequence - 1; // sequence is 1-indexed
    const original = lines[idx];

    if (typeof original !== 'string' || original.length === 0) {
        throw new Error(`edit target sequence ${editTargetSequence} not found in WAL`);
    }

    // Replace the JSON value of "amount" using a precise regex. Safe
    // because demo-seeder controls the field shape exactly:
    //   "amount":"100.00 EUR"
    const AMOUNT_RE = /("amount":")[^"]*(")/;
    if (!AMOUNT_RE.test(original)) {
        throw new Error(
            `edit target sequence ${editTargetSequence} does not contain an "amount" ` +
            `field — refusing to silently no-op. The WAL scenario may have changed; ` +
            `update edit_target_sequence in the manifest or fix this regex.`
        );
    }

    const tampered = original.replace(
        AMOUNT_RE,
        (_, open, close) => `${open}${newAmount}${close}`,
    );

    // Defence in depth: assert the bytes actually changed when the user
    // entered a different value. Without this, typing the original
    // amount back in (or hitting an edge-case in the regex) would
    // silently produce an unchanged WAL and the verifier would say
    // "valid", surprising the visitor.
    if (tampered === original && newAmount !== extractAmount(original)) {
        throw new Error(
            `regex matched but produced no change at sequence ${editTargetSequence}. ` +
            `This is a bug in the rewrite logic — investigate.`
        );
    }

    lines[idx] = tampered;
    return new TextEncoder().encode(lines.join('\n'));
}

function extractAmount(line) {
    const m = line.match(/"amount":"([^"]*)"/);
    return m ? m[1] : null;
}

// ----- Component ----------------------------------------------------------

export default function DemoSection() {
    const [bootstrapState, setBootstrapState] = useState({ kind: 'loading' });
    const [walText, setWalText] = useState('');
    const [editValue, setEditValue] = useState('100.00 EUR');
    const [report, setReport] = useState(null);

    // Hold the verified WAL bytes outside React state so we don't
    // serialise a Uint8Array through every render.
    const walBytesRef = useRef(null);

    useEffect(() => {
        let cancelled = false;
        bootstrap()
            .then(({ manifest, walBytes }) => {
                if (cancelled) return;
                walBytesRef.current = walBytes;
                setWalText(new TextDecoder().decode(walBytes));
                setBootstrapState({ kind: 'ready', manifest });
            })
            .catch((err) => {
                if (cancelled) return;
                setBootstrapState({
                    kind: 'aborted',
                    errorKind: err.kind ?? 'unknown',
                    message: err.message,
                });
            });
        return () => { cancelled = true; };
    }, []);

    function handleVerify() {
        if (bootstrapState.kind !== 'ready') return;
        if (typeof verifyDemoWalJson !== 'function') {
            // Belt-and-braces: bootstrap completed without populating
            // the verifier handle. Should be unreachable.
            setReport({
                ok: false,
                error: { kind: 'verifier_unavailable',
                         message: 'Verifier handle not populated.' },
            });
            return;
        }
        const { manifest } = bootstrapState;

        let tampered;
        try {
            tampered = rewriteAmount(
                walBytesRef.current,
                manifest.edit_target_sequence,
                editValue,
            );
        } catch (e) {
            setReport({
                ok: false,
                error: { kind: 'edit_rewrite_failed', message: e.message },
            });
            return;
        }

        // Pass manifest_version (the strict verifier's
        // `manifest_version_used` echo) — NOT schema_version. The two
        // are namespaced separately so the manifest envelope can
        // evolve without forcing the verifier's pinned version axis to
        // move in lockstep.
        const json = verifyDemoWalJson(
            tampered,
            manifest.expected_public_key,
            manifest.expected_chain_root,
            manifest.manifest_version,
        );
        const envelope = JSON.parse(json);
        setReport(envelope);
    }

    function handleReset() {
        if (bootstrapState.kind !== 'ready') return;
        setEditValue('100.00 EUR');
        setReport(null);
    }

    return (
        <section className="playground">
            <h2>Verify the demo audit trail in your browser</h2>

            {bootstrapState.kind === 'loading' && (
                <div className="status status--loading">
                    Loading verifier…
                </div>
            )}

            {bootstrapState.kind === 'aborted' && (
                <div className="status status--aborted" role="alert">
                    <strong>Manifest verification failed.</strong>
                    <div className="status__detail">
                        ({bootstrapState.errorKind}) {bootstrapState.message}
                    </div>
                    <p>
                        Refusing to run the verifier. The page must serve bytes
                        that match the manifest pin; if they do not, this
                        playground would be lying to you. Please report at{' '}
                        <a href="/security">/security</a>.
                    </p>
                </div>
            )}

            {bootstrapState.kind === 'ready' && (
                <Ready
                    manifest={bootstrapState.manifest}
                    walText={walText}
                    editValue={editValue}
                    setEditValue={setEditValue}
                    onVerify={handleVerify}
                    onReset={handleReset}
                    report={report}
                />
            )}

            <ScopeAccordion />
        </section>
    );
}

// ----- "Ready" state — editor + verifier output --------------------------

function Ready({
    manifest, walText, editValue, setEditValue,
    onVerify, onReset, report,
}) {
    const lines = walText.split('\n').filter((l) => l.length > 0);
    const targetIdx = manifest.edit_target_sequence - 1;

    return (
        <div className="ready">
            <div className="meta">
                <div>Verifier: {manifest.verifier_version}</div>
                <div>Scenario: {manifest.scenario}</div>
                <div>Records: {manifest.records_count}</div>
                <div>
                    Pinned root: <code>{manifest.expected_chain_root.slice(0, 16)}…</code>
                </div>
                <div>
                    Pinned key:{' '}
                    <code>{manifest.expected_public_key.slice(0, 16)}…</code>
                </div>
            </div>

            <div className="wal-view">
                {lines.map((line, i) => (
                    <div
                        key={i}
                        className={`wal-line ${i === targetIdx ? 'wal-line--editable' : ''}`}
                    >
                        <span className="wal-line__seq">{i + 1}</span>
                        <code className="wal-line__body">{line}</code>
                    </div>
                ))}
            </div>

            <div className="editor">
                <label htmlFor="amount-input">
                    Edit the wire transfer amount at sequence{' '}
                    {manifest.edit_target_sequence}:
                </label>
                <input
                    id="amount-input"
                    type="text"
                    value={editValue}
                    onChange={(e) => setEditValue(e.target.value)}
                    spellCheck={false}
                />
                <button type="button" onClick={onVerify}>Verify</button>
                <button type="button" onClick={onReset}>Reset</button>
            </div>

            {report && <Report manifest={manifest} envelope={report} />}
        </div>
    );
}

// ----- Verifier output rendering -----------------------------------------

function Report({ manifest, envelope }) {
    if (!envelope.ok) {
        return (
            <div className="report report--structural-error" role="alert">
                <strong>Structural error:</strong> {envelope.error.kind}
                <p>{envelope.error.message}</p>
            </div>
        );
    }

    const r = envelope.report;
    if (r.status === 'valid') {
        return (
            <div className="report report--valid">
                <strong>✓ VALID</strong> — {r.events_verified} records verified.
                <div>Chain root: <code>{r.chain_root.slice(0, 16)}…</code></div>
                <div>Pinned key fingerprint: <code>{r.expected_pubkey_fp}</code></div>
            </div>
        );
    }

    // status === 'invalid' — find the first non-Valid record outcome
    // and surface it as the side-by-side diff panel that is the demo's
    // pitch. The strict verifier is fail-fast, so the failing record
    // is always the last one in the array.
    const failingRecord = r.records.find((rec) => rec.outcome !== 'valid');

    return (
        <div className="report report--invalid" role="alert">
            <strong>✗ TAMPERING DETECTED</strong>
            {failingRecord && <FailingRecord record={failingRecord} />}
            {!failingRecord && r.error && (
                <div className="failing-record">
                    Error: <code>{r.error}</code>
                </div>
            )}
            <p className="pitch">
                This is mathematically detectable. The attacker has full disk
                access, but cannot forge a signed entry without the private
                key, which never touches any server.
            </p>
            <details>
                <summary>Full report (JSON)</summary>
                <pre>{JSON.stringify(envelope, null, 2)}</pre>
            </details>
        </div>
    );
}

function FailingRecord({ record }) {
    // DemoRecordEntry flattens the outcome discriminator into the
    // record body: { sequence, outcome: "valid"|"invalid"|"rejected",
    // reason?: { kind, ... } }. The strict verifier guarantees `reason`
    // is present whenever `outcome` is not "valid".
    const { sequence, outcome, reason } = record;
    if (outcome === 'invalid' && reason?.kind === 'payload_hash_mismatch') {
        return (
            <div className="failing-record">
                <div>Field: <code>payload.amount</code></div>
                <div>Sequence: {sequence}</div>
                <div className="diff">
                    <div>
                        Computed payload_hash:{' '}
                        <code>{reason.computed.slice(0, 16)}…</code>
                    </div>
                    <div>
                        Declared payload_hash:{' '}
                        <code>{reason.declared.slice(0, 16)}…</code>
                    </div>
                    <div className="diff__arrow">↑ MISMATCH</div>
                </div>
            </div>
        );
    }
    return (
        <div className="failing-record">
            Sequence: {sequence}. Outcome: <code>{outcome}</code>
            {reason?.kind && (
                <>
                    {' '}Reason: <code>{reason.kind}</code>
                </>
            )}
        </div>
    );
}

// ----- Scope disclaimer ---------------------------------------------------

function ScopeAccordion() {
    return (
        <details className="scope">
            <summary>About this demo: what it verifies and what it does not</summary>
            <ul>
                <li>
                    <strong>Does verify:</strong> the cryptographic integrity of
                    a signed WAL — hash chain replay, payload-hash recomputation
                    from canonical JSON, Ed25519 signature verification with
                    domain separation. The same code that runs in your browser
                    runs in our standalone CLI auditor.
                </li>
                <li>
                    <strong>Does not verify:</strong> the operational integrity
                    of any specific Spine deployment, key-management practices,
                    or the broader compliance posture of any customer using
                    Spine. Those concerns belong in audit and operational
                    reviews, not in cryptographic code.
                </li>
                <li>
                    Read the verifier source:{' '}
                    <a href="https://github.com/EulBite/spine">
                        github.com/EulBite/spine
                    </a>
                    {' '}, in particular <code>spine-core/src/verify_demo.rs</code>
                    {' '}and the cross-language test vectors in <code>test-vectors/</code>.
                </li>
                <li>
                    Threat model and design choices: the design notes
                    published alongside the launch announcement.
                </li>
            </ul>
        </details>
    );
}
