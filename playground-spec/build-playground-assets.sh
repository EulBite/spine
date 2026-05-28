#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Eul Bite
#
# Build pipeline: produces a directory of static assets ready
# to be deployed under /playground/ on whatever site mounts the
# playground.
#
# Inputs:
#   - demo-seeder/out/{demo.jsonl, demo.pubkey, demo.expected_root,
#                      demo-manifest.json}
#     Produced by the airgapped seeding run, transferred onto this
#     machine via clean USB. Must have schema_version=1 and the
#     placeholder strings TODO_FILLED_BY_BUILD for wal_sha256 /
#     wasm_sha256 / wasm_url.
#
#   - spine-wasm/ source tree.
#
# Outputs (in playground-spec/dist/):
#   manifest.json                 <-finalised, hashes filled in
#   assets/spine_wasm.js          <-wasm-bindgen JS glue
#   assets/spine-verifier-<sha8>.wasm
#   assets/demo-banking-<sha8>.jsonl
#
# After this script succeeds, copy dist/* into the host site's
# static-asset directory (typically `public/playground/`).
# spine_wasm.js is fetched + hashed at runtime against
# manifest.js_sha256 (see playground-spec/INTEGRATION.md §1, §2).
# There is intentionally no SRI digest emitted here, because the
# glue is NOT loaded via a static <script src="…"> tag.
#
# Requirements:
#   - wasm-pack (cargo install wasm-pack --locked)
#   - jq        (apt install jq / brew install jq / choco install jq)
#   - sha256sum
#   - A binaryen wasm-opt on PATH IF you want size optimisation; absent
#     binaryen, the script ships the unoptimised bundle.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEED_OUT="${REPO_ROOT}/demo-seeder/out"
WASM_DIR="${REPO_ROOT}/spine-wasm"
DIST="${REPO_ROOT}/playground-spec/dist"
ASSETS="${DIST}/assets"

# ---- Pre-flight --------------------------------------------------------

if [[ ! -d "${SEED_OUT}" ]]; then
    echo "ERROR: ${SEED_OUT} does not exist." >&2
    echo "Run the airgapped seeder first; see demo-seeder/OPERATIONAL.md." >&2
    exit 1
fi

for required in demo.jsonl demo.pubkey demo.expected_root demo-manifest.json; do
    if [[ ! -f "${SEED_OUT}/${required}" ]]; then
        echo "ERROR: ${SEED_OUT}/${required} missing." >&2
        exit 1
    fi
done

for tool in wasm-pack jq sha256sum; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not on PATH: $tool" >&2
        exit 1
    fi
done

# ---- 1. Build wasm bundle ----------------------------------------------

echo "[1/5] Building wasm bundle (wasm-pack --target web --release)…"
(cd "${WASM_DIR}" && wasm-pack build --target web --release)

if [[ ! -f "${WASM_DIR}/pkg/spine_wasm_bg.wasm" ]]; then
    echo "ERROR: wasm-pack did not produce pkg/spine_wasm_bg.wasm" >&2
    exit 1
fi

# Optional binaryen pass, skipped if wasm-opt is missing or refuses the
# input. The unoptimised bundle is acceptable for testing.
if command -v wasm-opt >/dev/null 2>&1; then
    echo "  Running wasm-opt -Oz (optional)…"
    if wasm-opt -Oz \
        "${WASM_DIR}/pkg/spine_wasm_bg.wasm" \
        -o "${WASM_DIR}/pkg/spine_wasm_bg.wasm" 2>/dev/null; then
        echo "  ✓ wasm-opt applied"
    else
        echo "  ⚠ wasm-opt failed (likely binaryen too old for rustc output);"
        echo "    shipping the unoptimised bundle."
    fi
else
    echo "  (wasm-opt not on PATH, shipping unoptimised bundle)"
fi

# ---- 2. Compute hashes --------------------------------------------------

echo "[2/5] Computing SHA-256 of WAL, wasm bundle, and JS glue…"
WAL_SHA=$(sha256sum "${SEED_OUT}/demo.jsonl" | cut -d' ' -f1)
WASM_SHA=$(sha256sum "${WASM_DIR}/pkg/spine_wasm_bg.wasm" | cut -d' ' -f1)
JS_SHA=$(sha256sum "${WASM_DIR}/pkg/spine_wasm.js" | cut -d' ' -f1)

WAL_SHA_SHORT="${WAL_SHA:0:8}"
WASM_SHA_SHORT="${WASM_SHA:0:8}"

echo "  wal_sha256:  ${WAL_SHA}"
echo "  wasm_sha256: ${WASM_SHA}"
echo "  js_sha256:   ${JS_SHA}"

# ---- 3. Stage assets with content-hashed filenames ---------------------

echo "[3/5] Staging assets in ${DIST}…"
rm -rf "${DIST}"
mkdir -p "${ASSETS}"

WAL_FILENAME="demo-banking-${WAL_SHA_SHORT}.jsonl"
WASM_FILENAME="spine-verifier-${WASM_SHA_SHORT}.wasm"

cp "${SEED_OUT}/demo.jsonl"                       "${ASSETS}/${WAL_FILENAME}"
cp "${WASM_DIR}/pkg/spine_wasm_bg.wasm"           "${ASSETS}/${WASM_FILENAME}"
cp "${WASM_DIR}/pkg/spine_wasm.js"                "${ASSETS}/spine_wasm.js"

# ---- 4. Inject hashes into manifest ------------------------------------

echo "[4/5] Finalising manifest…"
jq \
    --arg wal_sha "${WAL_SHA}" \
    --arg wasm_sha "${WASM_SHA}" \
    --arg js_sha "${JS_SHA}" \
    --arg wal_url "/playground/assets/${WAL_FILENAME}" \
    --arg wasm_url "/playground/assets/${WASM_FILENAME}" \
    --arg js_url "/playground/assets/spine_wasm.js" \
    '.wal_sha256 = $wal_sha
     | .wasm_sha256 = $wasm_sha
     | .js_sha256 = $js_sha
     | .wal_url = $wal_url
     | .wasm_url = $wasm_url
     | .js_url = $js_url' \
    "${SEED_OUT}/demo-manifest.json" \
    > "${DIST}/manifest.json"

echo "  ✓ ${DIST}/manifest.json"

echo ""
echo "Done. Assets staged in ${DIST}/."
echo ""
echo "Next steps:"
echo "  1. Review ${DIST}/manifest.json: verify wal_sha256, wasm_sha256,"
echo "     and js_sha256 match what was generated."
echo "  2. Copy ${DIST}/* into the host site's static-asset"
echo "     directory (typically public/playground/) on the deploy host."
echo "  3. Configure the host's CSP: script-src 'self' blob: (the"
echo "     blob: scheme is required for the dynamic-import flow that"
echo "     loads the verified glue; see playground-spec/INTEGRATION.md"
echo "     §7)."
echo "  4. Republish ${DIST}/manifest.json to two more independent"
echo "     locations (this repo + a versioned launch blog post)."
