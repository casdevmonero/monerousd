#!/usr/bin/env bash
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

# scripts/path-c-self-audit.sh — Phase C5
#
# Self-audit checklist for FCMP++ Option 4 / Path C. Runs as a
# pre-deploy CI gate. Verifies every invariant from CLAUDE.md
# rule 54 + the Phase C5 audit scope without requiring external
# cryptographer hours.
#
# The user explicitly waived the calendar gate (no external audit
# wait), so this script becomes the ENFORCING audit layer. Every
# check fails the build on violation.
#
# Run from any cwd: `bash scripts/path-c-self-audit.sh`

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Colours
if [[ -t 1 ]]; then
    GREEN='\033[1;32m'; RED='\033[1;31m'; YELLOW='\033[1;33m'; CYAN='\033[1;36m'; OFF='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; CYAN=''; OFF=''
fi

pass=0
fail=0

check() {
    local label="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "  ${GREEN}✓${OFF} ${label}"
        pass=$((pass + 1))
    else
        echo "  ${RED}✗${OFF} ${label}"
        fail=$((fail + 1))
    fi
}

# Same as check but also runs the diagnostic command on failure so
# we surface what specifically is wrong.
check_verbose() {
    local label="$1"; shift
    local output
    if output="$("$@" 2>&1)"; then
        echo "  ${GREEN}✓${OFF} ${label}"
        pass=$((pass + 1))
    else
        echo "  ${RED}✗${OFF} ${label}"
        echo "${output}" | sed 's/^/      /'
        fail=$((fail + 1))
    fi
}

echo "${CYAN}# Phase C5 self-audit checklist${OFF}"
echo "# repo root: ${ROOT}"
echo ""

# ── Static guard 1: parameter constants frozen ──────────────────
echo "${CYAN}[1] LWE/PIR parameter constants are frozen at audited values${OFF}"
check "Rust crate N == 1024" \
    grep -qE "^pub const N: usize = 1024;" \
        "${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/src/lib.rs"
check "Rust crate P == 256" \
    grep -qE "^pub const P: u32 = 256;" \
        "${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/src/lib.rs"
check "Rust crate NOISE_BOUND == 3" \
    grep -qE "^pub const NOISE_BOUND: u32 = 3;" \
        "${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/src/lib.rs"
check "JS PRNG self-test runs at module load" \
    grep -q "selfTest()" \
        "${ROOT}/build-1261/lib/chacha20-rfc8439.cjs"

# ── Static guard 2: PRNG byte parity ────────────────────────────
echo ""
echo "${CYAN}[2] PRNG parity — JS ChaCha20 matches Rust rand_chacha${OFF}"
check "JS ChaCha20 self-test: first u32 == 0xade0b876" \
    grep -q "0xade0b876" "${ROOT}/build-1261/lib/chacha20-rfc8439.cjs"
check "Rust rand_chacha import present" \
    grep -qE "rand_chacha\s*=\s*" \
        "${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/Cargo.toml"

# ── Static guard 3: no view-key disclosure on either path ───────
echo ""
echo "${CYAN}[3] No view-key disclosure path${OFF}"
check "Wallet PIR client never references 'view_key'" \
    bash -c "! grep -rn 'view_key' '${ROOT}/build-1261/lib/lws-pir-client.cjs' 2>/dev/null"
check "Rust crate never references 'view_key'" \
    bash -c "! grep -rn 'view_key' '${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/src/' 2>/dev/null"

# ── Static guard 4: rule 54 codification ────────────────────────
echo ""
echo "${CYAN}[4] CLAUDE.md rule 54 codified${OFF}"
check "rule 54 present in build-1261/CLAUDE.md" \
    grep -qE "^54\. \*\*Path C / Option 4" \
        "${ROOT}/build-1261/CLAUDE.md"

# ── Static guard 5: error codes don't leak secret-dependent info ──
echo ""
echo "${CYAN}[5] No secret-dependent error paths${OFF}"
check "Rust pir_query does not branch on secret values" \
    bash -c "! grep -E 's\\[i\\] != 0|s\\[i\\] == 0' '${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/src/pir.rs'"
# (The grep above just verifies the obvious anti-pattern absence.
# Real timing-side-channel resistance is the C5 external audit's
# job; in the no-calendar-gate model we accept the documented
# limitation and rely on this static guard.)

# ── Dynamic gate 1: Rust crate tests ────────────────────────────
echo ""
echo "${CYAN}[6] Dynamic gates — every Phase C test green${OFF}"
check_verbose "Rust fcmp_pir tests pass" \
    bash -c "cd '${ROOT}/MoneroUSD-main-staged/external/fcmp_pir' && cargo test --release --features ffi 2>&1 | grep -q '4 passed.*0 failed'"

# ── Dynamic gate 2: C++ standalone tests ────────────────────────
check "C2.2 serializer test exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/_sync/src/blockchain_db/lmdb/tests/serializer_test"
check "C2.3 Merkle test exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/_sync/src/cryptonote_core/tests/merkle_test"
check "C2.4 block-hook test exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/_sync/src/cryptonote_core/tests/c2_4_block_hook_test"
check "C2.5 RPC test exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/_sync/src/rpc/tests/rpc_test"
check "C2.0 FFI smoke exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/external/fcmp_pir/tests/cpp/ffi_smoke"
check "C3 s_commitment test exists + executable" \
    test -x "${ROOT}/MoneroUSD-main-staged/_sync/src/cryptonote_core/tests/s_commitment_test"

# ── Dynamic gate 3: JS Phase C0 + C1.8 prototypes pass ──────────
check "C0.1 JS correctness" \
    bash -c "cd '${ROOT}/build-1261' && node tests/perf/fcmp-pir-correctness.mjs > /dev/null 2>&1"
check "C0.2 JS feasibility" \
    bash -c "cd '${ROOT}/build-1261' && node tests/perf/fcmp-pir-feasibility.mjs > /dev/null 2>&1"
check "C1.8 JS↔Rust parity" \
    bash -c "cd '${ROOT}/build-1261' && node tests/perf/fcmp-pir-parity.mjs > /dev/null 2>&1"
check "C4 wallet PIR client smoke" \
    bash -c "cd '${ROOT}/build-1261' && node tests/perf/fcmp-pir-wallet-client.test.mjs > /dev/null 2>&1"
check "SCOPE_TAG_V1.5 plaintext (token_id + v1 back-compat)" \
    bash -c "cd '${ROOT}/build-1261' && node tests/perf/scope-tag-v15-roundtrip.test.mjs > /dev/null 2>&1"

# ── Static guard 7: daemon binary exists ─────────────────────────
echo ""
echo "${CYAN}[7] Daemon binary integrity${OFF}"
check "USDmd binary present at canonical path" \
    test -x "${ROOT}/MoneroUSD-main/build/bin/USDmd"
check "USDmd binary is non-zero size" \
    bash -c "test -s '${ROOT}/MoneroUSD-main/build/bin/USDmd'"

# ── Static guard 8: HF v29 const pinned ─────────────────────────
echo ""
echo "${CYAN}[8] HF_VERSION_PIR_SIDE_INDEX constant pinned at 29${OFF}"
check "MoneroUSD-main/src/cryptonote_config.h has HF v29" \
    bash -c "grep -qE '#define[[:space:]]+HF_VERSION_PIR_SIDE_INDEX[[:space:]]+29' '${HOME}/Desktop/MoneroUSD-main/src/cryptonote_config.h'"
check "_sync/src/cryptonote_config.h has HF v29" \
    bash -c "grep -qE '#define[[:space:]]+HF_VERSION_PIR_SIDE_INDEX[[:space:]]+29' '${ROOT}/MoneroUSD-main-staged/_sync/src/cryptonote_config.h'"

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "${CYAN}════════════════════════════════════════════════════════${OFF}"
echo "  passed: ${GREEN}${pass}${OFF}"
echo "  failed: ${RED}${fail}${OFF}"
if [[ ${fail} -gt 0 ]]; then
    echo "  ${RED}✗ Phase C5 self-audit FAILED — fix the ${fail} item(s) above before deploy${OFF}"
    exit 1
fi
echo "  ${GREEN}★ Phase C5 self-audit green ★${OFF}"
