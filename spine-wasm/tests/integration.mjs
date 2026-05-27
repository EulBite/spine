// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite

// Cross-target integration test for the wasm verifier.
//
// Loads the pkg artifact produced by `wasm-pack build --target nodejs`
// and the deterministic fixture produced by
// `demo-seeder --deterministic-seed 42 --non-interactive
//      --output-dir out-test`.
//
// Asserts:
//   - strict verifier returns status=valid on the unmodified fixture
//   - strict verifier returns status=invalid when a payload byte
//     flips (the "edit the amount" demo flow)
//   - strict verifier rejects when the pinned pubkey differs from
//     the signing key (no false "valid signature" surfacing)
//   - empty input produces status=invalid with the expected
//     chain_root-mismatch error
//   - the chain_root computed by strict equals the one computed by
//     the lenient verifier on the same bytes (cross-API parity)
//
// Run with:
//   node spine-wasm/tests/integration.mjs
//
// from the repository root, after a fresh demo-seeder and wasm-pack
// build.

import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '..', '..');
const PKG = pathToFileURL(resolve(__dirname, '..', 'pkg', 'spine_wasm.js')).href;
const FIXTURE_DIR = resolve(REPO_ROOT, 'demo-seeder', 'out-test');

const MANIFEST_VERSION = 1;

function readText(p) {
    return readFileSync(p, 'utf-8').trim();
}

function readBytes(p) {
    return readFileSync(p);
}

function bail(msg) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
}

function assertEq(actual, expected, label) {
    if (actual !== expected) {
        bail(`${label}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
    }
}

function assertTrue(cond, label) {
    if (!cond) bail(label);
}

async function main() {
    const mod = await import(PKG);
    const { verify_demo_wal_json, verify_wal_bytes_json } = mod;

    const walBytes = readBytes(resolve(FIXTURE_DIR, 'demo.jsonl'));
    const pubkey = readText(resolve(FIXTURE_DIR, 'demo.pubkey'));
    const expectedRoot = readText(resolve(FIXTURE_DIR, 'demo.expected_root'));

    console.log(`Fixture loaded. pubkey=${pubkey.slice(0, 16)}... root=${expectedRoot.slice(0, 16)}...`);

    // 1. Happy path.
    {
        const env = JSON.parse(
            verify_demo_wal_json(walBytes, pubkey, expectedRoot, MANIFEST_VERSION)
        );
        assertTrue(env.ok === true, 'envelope.ok must be true on happy path');
        assertEq(env.report.status, 'valid', 'happy path status');
        assertTrue(env.report.events_verified > 0, 'happy path events_verified');
        assertEq(
            env.report.chain_root,
            expectedRoot,
            'happy path chain_root matches expected_root'
        );
        console.log(`PASS happy_path (${env.report.events_verified} records)`);
    }

    // 2. Tamper: flip a byte inside a payload. Pick something inside
    // the JSON body of record 11 (the edit target) so we exercise
    // the realistic playground flow.
    {
        const text = walBytes.toString('utf-8');
        const needle = '100.00 EUR';
        const idx = text.indexOf(needle);
        assertTrue(idx > 0, 'fixture must contain the "100.00 EUR" edit target');
        const tampered = Buffer.from(
            text.slice(0, idx) + '900.00 EUR' + text.slice(idx + needle.length),
            'utf-8'
        );
        const env = JSON.parse(
            verify_demo_wal_json(tampered, pubkey, expectedRoot, MANIFEST_VERSION)
        );
        assertEq(env.report.status, 'invalid', 'tamper status');
        const last = env.report.records[env.report.records.length - 1];
        assertEq(last.outcome, 'invalid', 'last record outcome on tamper');
        assertEq(
            last.reason.kind,
            'payload_hash_mismatch',
            'tamper reason must be payload_hash_mismatch'
        );
        console.log(`PASS tamper_payload_byte (caught at seq ${last.sequence})`);
    }

    // 3. Wrong pubkey: pin to a different key. Must surface as
    // Rejected/pubkey_mismatch, never as SignatureVerificationFailed.
    {
        const wrongPubkey =
            'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc';
        const env = JSON.parse(
            verify_demo_wal_json(walBytes, wrongPubkey, expectedRoot, MANIFEST_VERSION)
        );
        assertEq(env.report.status, 'invalid', 'wrong pubkey status');
        const last = env.report.records[env.report.records.length - 1];
        assertEq(last.outcome, 'rejected', 'wrong pubkey outcome');
        assertEq(
            last.reason.kind,
            'pubkey_mismatch',
            'wrong pubkey reason must be pubkey_mismatch'
        );
        console.log('PASS wrong_pubkey_rejected_not_called_signature_failure');
    }

    // 4. Empty input: the accumulator over zero records cannot match
    // an attacker-chosen expected_root. Strict must catch this.
    {
        const env = JSON.parse(
            verify_demo_wal_json(Buffer.alloc(0), pubkey, expectedRoot, MANIFEST_VERSION)
        );
        assertEq(env.report.status, 'invalid', 'empty wal status');
        assertEq(env.report.events_verified, 0, 'empty wal events_verified');
        assertTrue(env.report.error.includes('chain_root mismatch'), 'empty wal error msg');
        console.log('PASS empty_wal_invalid');
    }

    // 5. Cross-API parity: lenient and strict must agree on
    // chain_root for the same bytes. This is the regression net
    // under compute_entry_hash; if they ever diverge, the whole
    // "same verifier in browser and CLI" pitch falls apart.
    {
        const strict = JSON.parse(
            verify_demo_wal_json(walBytes, pubkey, expectedRoot, MANIFEST_VERSION)
        );
        const lenient = JSON.parse(verify_wal_bytes_json(walBytes, expectedRoot));
        assertEq(
            strict.report.chain_root,
            lenient.report.chain_root,
            'strict and lenient chain_root must match'
        );
        console.log('PASS cross_api_chain_root_parity');
    }

    // 6. Determinism: same input must produce the same JSON byte for
    // byte. Deterministic reports let a host page hash the result as
    // a "verification receipt" and cache by it.
    {
        const s1 = verify_demo_wal_json(walBytes, pubkey, expectedRoot, MANIFEST_VERSION);
        const s2 = verify_demo_wal_json(walBytes, pubkey, expectedRoot, MANIFEST_VERSION);
        assertEq(s1, s2, 'strict envelope must be byte-deterministic');
        console.log('PASS determinism_byte_for_byte');
    }

    console.log('\nAll wasm integration checks passed.');
}

main().catch((e) => {
    console.error('Integration runner crashed:', e);
    process.exit(2);
});
