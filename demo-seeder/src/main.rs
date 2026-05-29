// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Eul Bite
//
// Operational seeder. NOT distributed. Runs on an airgapped machine
// to seed the playground demo. See OPERATIONAL.md for
// the exact procedure.

mod scenario;

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use blake3::Hasher;
use clap::Parser;
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, RngCore, SeedableRng};
use serde_json::json;
use spine_core::{
    compute_entry_hash, compute_entry_hash_for_signing, verify_demo_wal, DemoStatus, WalEntry,
    GENESIS_PREV_HASH, STRICT_DOMAIN_SEP, VERIFIER_VERSION, WAL_FORMAT_VERSION,
};
use zeroize::{Zeroize, Zeroizing};

use crate::scenario::{build_scenario, EDIT_TARGET_SEQUENCE};

const BASE_TIMESTAMP_NS: i64 = 1_716_800_000_000_000_000;
const SECOND_NS: i64 = 1_000_000_000;
const MANIFEST_VERSION: u32 = 1;
const SCENARIO_TAG: &str = "banking-wire-transfer-v1";

#[derive(Parser)]
#[command(
    name = "demo-seeder",
    about = "Generate the signed demo banking WAL on an airgapped machine. Not part of the distributed product."
)]
struct Args {
    /// Output directory. Created if missing.
    #[arg(long, default_value = "out")]
    output_dir: PathBuf,

    /// Skip interactive prompts. Required for CI/test runs. Refused
    /// unless --deterministic-seed is also provided, so an operator
    /// cannot accidentally dump a real signing key without intent.
    #[arg(long)]
    non_interactive: bool,

    /// Seed the signing-key generator deterministically. The u64 is
    /// expanded with ChaCha20Rng::seed_from_u64. Use a fresh value for
    /// every release; reuse for tests only.
    #[arg(long)]
    deterministic_seed: Option<u64>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Guard: --non-interactive without a seed would derive the demo
    // key from OS entropy and write it to disk without operator
    // confirmation. That is fine for a real release, but only after
    // an explicit interactive go-ahead. Block the combination.
    if args.non_interactive && args.deterministic_seed.is_none() {
        bail!(
            "--non-interactive requires --deterministic-seed. \
             Refusing to run: a non-interactive run with OS-random entropy \
             would write a freshly-generated signing key to disk with no \
             operator confirmation. If you want a real release key, drop \
             --non-interactive and confirm at the prompt."
        );
    }

    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!(
            "create output directory {}",
            args.output_dir.display()
        )
    })?;

    let signing_key = build_signing_key(args.deterministic_seed);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex::encode(verifying_key.to_bytes());

    if !args.non_interactive {
        eprintln!("=== Spine demo seeder ===");
        eprintln!("Scenario: {SCENARIO_TAG}");
        eprintln!(
            "Output:   {}",
            args.output_dir.canonicalize().unwrap_or_else(|_| args.output_dir.clone()).display()
        );
        eprintln!("Pubkey:   {pubkey_hex}");
        eprintln!();
        eprintln!("Press Enter to continue, Ctrl-C to abort.");
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("read operator confirmation")?;
    }

    let (entries, jsonl_bytes, expected_root) = seal_chain(&signing_key)?;

    // Self-verify before persisting. If the strict verifier refuses
    // our own output the operator must abort and investigate; never
    // ship a WAL that cannot self-verify.
    let report = verify_demo_wal(&jsonl_bytes, &pubkey_hex, &expected_root, MANIFEST_VERSION);
    if report.status != DemoStatus::Valid {
        return Err(anyhow!(
            "self-verification failed: {:?} (events {} signatures {})",
            report.status,
            report.events_verified,
            report.signatures_verified
        ));
    }

    let wal_path = args.output_dir.join("demo.jsonl");
    let pubkey_path = args.output_dir.join("demo.pubkey");
    let root_path = args.output_dir.join("demo.expected_root");
    let manifest_path = args.output_dir.join("demo-manifest.json");

    fs::write(&wal_path, &jsonl_bytes).with_context(|| format!("write {}", wal_path.display()))?;
    fs::write(&pubkey_path, format!("{pubkey_hex}\n"))
        .with_context(|| format!("write {}", pubkey_path.display()))?;
    fs::write(&root_path, format!("{expected_root}\n"))
        .with_context(|| format!("write {}", root_path.display()))?;

    let manifest = manifest_skeleton(&pubkey_hex, &expected_root);
    fs::write(&manifest_path, format!("{manifest}\n"))
        .with_context(|| format!("write {}", manifest_path.display()))?;

    // Private key handling: print to stderr ONCE, between two [Enter]
    // prompts (stderr so a piped stdout capture never receives the
    // secret), so the operator copies it onto paper or a hardware
    // vault. NEVER written to disk: a hex file in the output dir is
    // a foot-gun (gets copied with the other artefacts, ends up in
    // backups, screen-recordings, version control). Wrapped in
    // Zeroizing so the heap allocation is overwritten when the
    // binding goes out of scope. ed25519-dalek already zeroises the
    // SigningKey's internal scalar on Drop via its `zeroize`
    // feature; this guards the secondary copy we just printed.
    let private_hex: Zeroizing<String> = Zeroizing::new(hex::encode(signing_key.to_bytes()));
    if args.non_interactive {
        // --non-interactive paths are reserved for `--deterministic-seed`
        // (test fixtures). The key is derivable from the seed in the
        // source, so disclosure is not a fresh leak. Still NOT
        // written to disk; tests that need it re-derive it
        // themselves from the seed.
        if args.deterministic_seed.is_none() {
            // Defence in depth: the argument-parsing guard at the top
            // of main() should have caught this already.
            bail!("--non-interactive requires --deterministic-seed.");
        }
        eprintln!();
        eprintln!("Generated {} records (test fixture, seed exposed in source).", entries.len());
        eprintln!("  WAL:      {}", wal_path.display());
        eprintln!("  Pubkey:   {}", pubkey_path.display());
        eprintln!("  Root:     {}", root_path.display());
        eprintln!("  Manifest: {}", manifest_path.display());
        eprintln!("Chain root: {expected_root}");
        // For test fixtures we deliberately do NOT print the private
        // key. Anyone running the same seed gets the same key; no
        // value in surfacing it to test logs.
    } else {
        // PRODUCTION PATH: stderr disclosure between two [Enter]
        // prompts. Operator must capture the hex onto paper or a
        // hardware vault before pressing Enter the second time;
        // after that, the SigningKey's memory copy is dropped and
        // the heap string is zeroised.
        eprintln!();
        eprintln!("Generated {} records.", entries.len());
        eprintln!("  WAL:      {}", wal_path.display());
        eprintln!("  Pubkey:   {}", pubkey_path.display());
        eprintln!("  Root:     {}", root_path.display());
        eprintln!("  Manifest: {}", manifest_path.display());
        eprintln!();
        eprintln!("Edit target sequence: {EDIT_TARGET_SEQUENCE}");
        eprintln!("Chain root: {expected_root}");
        eprintln!();
        eprintln!("\x1b[1;31m================================================================\x1b[0m");
        eprintln!("\x1b[1;31m  PRIVATE KEY HEX (this is shown ONCE, copy to offline vault)\x1b[0m");
        eprintln!("\x1b[1;31m================================================================\x1b[0m");
        eprintln!();
        eprintln!("  {}", private_hex.as_str());
        eprintln!();
        eprintln!("\x1b[1;31m================================================================\x1b[0m");
        eprintln!();
        eprintln!("Press Enter once you have captured the private key.");
        eprintln!("After Enter, the in-memory copies are zeroised and the binary exits.");
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("read operator confirmation after key capture")?;
    }

    // private_hex (Zeroizing<String>) drops here, wiping the heap
    // allocation. signing_key drops on function return, zeroising
    // the scalar via ed25519-dalek's `zeroize` feature.
    Ok(())
}

fn build_signing_key(seed: Option<u64>) -> SigningKey {
    let mut bytes = [0u8; 32];
    match seed {
        Some(n) => {
            // ChaCha20 from a u64 seed expands a small operator
            // input into a full 32-byte signing seed. This is the
            // deterministic path used in tests; never reuse a value
            // for a release.
            let mut rng = ChaCha20Rng::seed_from_u64(n);
            rng.fill_bytes(&mut bytes);
        }
        None => {
            OsRng.fill_bytes(&mut bytes);
        }
    }
    let key = SigningKey::from_bytes(&bytes);
    // Wipe the local seed buffer the moment the SigningKey owns its
    // internal copy. Two copies of the secret on the heap was the
    // round-1 finding.
    bytes.zeroize();
    key
}

fn seal_chain(signing_key: &SigningKey) -> Result<(Vec<WalEntry>, Vec<u8>, String)> {
    let scenario = build_scenario();
    let pubkey_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut entries: Vec<WalEntry> = Vec::with_capacity(scenario.len());
    let mut prev = GENESIS_PREV_HASH.to_string();
    let mut accum = Hasher::new();

    for (idx, rec) in scenario.iter().enumerate() {
        let seq = idx as u64 + 1;
        let timestamp_ns = BASE_TIMESTAMP_NS + (seq as i64 - 1) * SECOND_NS;

        let canonical = spine_core::canonical_json(&rec.payload)
            .map_err(|e| anyhow!("canonical_json failed at sequence {seq}: {e}"))?;
        let payload_hash = hex::encode(blake3::hash(&canonical).as_bytes());

        let mut entry = WalEntry {
            format_version: WAL_FORMAT_VERSION,
            sequence: seq,
            timestamp_ns,
            prev_hash: prev.clone(),
            payload_hash,
            event_type: Some(rec.event_type.to_string()),
            source: Some(rec.source.to_string()),
            signature: None,
            public_key: None,
            key_id: None,
            event_id: None,
            stream_id: None,
            hash_alg: Some("blake3".to_string()),
            payload: Some(rec.payload.clone()),
            receipt: None,
        };

        // Sign with the strict contract: domain prefix + UTF-8 hex of
        // sign hash. Must match `STRICT_DOMAIN_SEP || compute_entry_hash_for_signing(e).as_bytes()`
        // in `spine_core::verify_demo_wal`.
        let sign_hash_hex = compute_entry_hash_for_signing(&entry);
        let mut msg = Vec::with_capacity(STRICT_DOMAIN_SEP.len() + sign_hash_hex.len());
        msg.extend_from_slice(STRICT_DOMAIN_SEP);
        msg.extend_from_slice(sign_hash_hex.as_bytes());
        let sig = signing_key.sign(&msg);

        entry.signature = Some(hex::encode(sig.to_bytes()));
        entry.public_key = Some(pubkey_hex.clone());

        let chain_h = compute_entry_hash(&entry);
        accum.update(chain_h.as_bytes());
        prev = chain_h;
        entries.push(entry);
    }

    let expected_root = hex::encode(accum.finalize().as_bytes());

    let mut bytes = Vec::new();
    for e in &entries {
        let line = serde_json::to_string(e).map_err(|err| anyhow!("serialize WAL entry: {err}"))?;
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
    }

    Ok((entries, bytes, expected_root))
}

fn manifest_skeleton(pubkey_hex: &str, expected_root: &str) -> String {
    let value = json!({
        "schema_version": 1,
        "manifest_version": MANIFEST_VERSION,
        "verifier_version": VERIFIER_VERSION,
        "scenario": SCENARIO_TAG,
        "records_count": scenario::build_scenario().len() as u64,
        "edit_target_sequence": EDIT_TARGET_SEQUENCE,
        "expected_public_key": pubkey_hex,
        "expected_chain_root": expected_root,
        "wal_url": "/playground/assets/demo-banking-REPLACE_WITH_SHA256.jsonl",
        "wal_sha256": "REPLACE_WITH_SHA256",
        "wasm_url": "/playground/assets/spine-verifier-REPLACE_WITH_SHA256.wasm",
        "wasm_sha256": "REPLACE_WITH_SHA256",
        "js_url": "/playground/assets/spine_wasm.js",
        "js_sha256": "REPLACE_WITH_SHA256"
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}
