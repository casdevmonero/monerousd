# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
# circuit.rs: e2e selftest
cf = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool/src/circuit.rs"
s = open(cf).read()
if "reserve_yield_spend_e2e_selftest" in s:
    print("circuit.rs already has e2e; skip")
else:
    E2E = r'''/// CRY-6f: end-to-end double-spend + fake-note gate (pure-Rust simulation of the daemon's three
/// acceptance checks against a wallet-built bundle). (1) a wallet spend of a REAL coinbase note is
/// accepted: it verifies, its anchor is in the daemon's cmt-root set, and ns_root_old == the current
/// ns_root -> advance. (2) a REPLAY of the same bundle is rejected (stale ns_root_old; state unchanged).
/// (3) a FAKE-NOTE spend (membership proven against a 1-note tree the daemon never built) verifies
/// internally yet its anchor is NOT in the cmt-root set -> rejected. This is the soundness core of
/// CRY-6: miner liquidity that cannot be double-spent (hidden-nf IMT) and cannot mint a fake note.
pub fn reserve_yield_spend_e2e_selftest() -> bool {
    let mkb = |x: u64| -> Vec<u8> { let mut v = vec![0u8; DIGEST * 4]; v[0..8].copy_from_slice(&x.to_le_bytes()); v };
    let (cmt_depth, imt_depth) = (4usize, 4usize);
    let note_cm_of = |skv: u64, rhov: u64, rcmv: u64, value: u64| -> [F; DIGEST] {
        let sk = ry_bytes_to_digest(&mkb(skv)); let rho = ry_bytes_to_digest(&mkb(rhov)); let rcm = ry_bytes_to_digest(&mkb(rcmv));
        let pk_d = own_null_run(sk, rho).pk_d;
        run_sponge(&note_commit_preimage(value, 0, &pk_d, &rho, &rcm)).digest
    };
    // daemon state: cmt-tree from the one real v45 coinbase note; ns_root starts at the genesis empty root
    let real_cm = note_cm_of(0xC0FFEE, 0x1234, 0x5678, 12345);
    let cmt_notes = publics_to_bytes(&real_cm);
    let cmt_root = match ry_note_tree_root_bytes(&cmt_notes, cmt_depth) { Some(r) => r, None => return false };
    let empty = match imt_empty_root_bytes(imt_depth) { Some(r) => r, None => return false };
    let cmt_roots = vec![cmt_root];
    // daemon-side acceptance, mirroring blockchain.cpp: verify + cmt-anchor (anti-fake-note) + ns-root thread (anti-replay)
    let daemon_accept = |bundle: &ReserveYieldSpendBundle, cur: &mut Vec<u8>| -> bool {
        if !verify_reserve_yield_spend_bundle(bundle) { return false; }
        let anchor = publics_to_bytes(&bundle.batch_pvs[0..DIGEST]);
        if !cmt_roots.iter().any(|r| *r == anchor) { return false; }
        let old = publics_to_bytes(&bundle.imt_pvs[0..DIGEST]);
        let new = publics_to_bytes(&bundle.imt_pvs[DIGEST..2 * DIGEST]);
        if old != *cur { return false; }
        *cur = new; true
    };
    let mut current_ns = empty.clone();
    // (1) honest spend of the real coinbase note -> accepted, ns advances
    let bundle = match prove_reserve_yield_coinbase_spend_bundle(&mkb(0xC0FFEE), &mkb(0x1234), &mkb(0x5678), 12345, 0, &cmt_notes, 0, cmt_depth, &mkb(0xBEEF), 2345, 7, imt_depth) { Some(b) => b, None => return false };
    if !daemon_accept(&bundle, &mut current_ns) { return false; }
    let advanced = current_ns.clone();
    if advanced == empty { return false; } // ns_root genuinely moved
    // (2) REPLAY the same bundle -> rejected (stale ns_root_old); state unchanged
    if daemon_accept(&bundle, &mut current_ns) { return false; }
    if current_ns != advanced { return false; }
    // (3) FAKE-NOTE: a note the daemon never minted, proven against the attacker's own 1-note tree
    let fake_cm = note_cm_of(0xBADBEEF, 0xAAAA, 0xBBBB, 99999);
    let fake_notes = publics_to_bytes(&fake_cm);
    let fake_bundle = match prove_reserve_yield_coinbase_spend_bundle(&mkb(0xBADBEEF), &mkb(0xAAAA), &mkb(0xBBBB), 99999, 0, &fake_notes, 0, cmt_depth, &mkb(0xBEEF), 2345, 7, imt_depth) { Some(b) => b, None => return false };
    if !verify_reserve_yield_spend_bundle(&fake_bundle) { return false; } // internally valid proof...
    let mut cur2 = advanced.clone();
    if daemon_accept(&fake_bundle, &mut cur2) { return false; }           // ...but anchor not in cmt-roots -> rejected
    if cur2 != advanced { return false; }
    true
}

'''
    anchor = "/// CRY-6e: produce a fixed reserve-yield spend bundle's serialized bytes (for the C++ ABI smoke).\npub fn prove_test_reserve_yield_spend_bytes() -> Vec<u8> {"
    if s.count(anchor) != 1: print("FATAL circuit anchor x%d" % s.count(anchor)); sys.exit(1)
    s = s.replace(anchor, E2E + anchor, 1)
    open(cf, "w").write(s); print("circuit.rs: e2e selftest added")

# lib.rs FFI
lf = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool_ffi/src/lib.rs"
l = open(lf).read()
if "pqpool_reserve_yield_spend_e2e_selftest" in l:
    print("lib.rs already has e2e FFI; skip")
else:
    imp = "reserve_yield_coinbase_spend_selftest,"
    if l.count(imp) != 1: print("FATAL lib import anchor x%d" % l.count(imp)); sys.exit(1)
    l = l.replace(imp, "reserve_yield_coinbase_spend_selftest, reserve_yield_spend_e2e_selftest,", 1)
    anc = 'pub extern "C" fn pqpool_reserve_yield_coinbase_spend_selftest() -> i32 { if reserve_yield_coinbase_spend_selftest() { 1 } else { 0 } }'
    if l.count(anc) != 1: print("FATAL lib export anchor x%d" % l.count(anc)); sys.exit(1)
    l = l.replace(anc, anc + '''

/// CRY-6f: end-to-end double-spend + fake-note gate (honest accept, replay reject, fake-note reject).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_e2e_selftest() -> i32 { if reserve_yield_spend_e2e_selftest() { 1 } else { 0 } }''', 1)
    open(lf, "w").write(l); print("lib.rs: e2e FFI added")

# header
hf = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"
h = open(hf).read()
if "pqpool_reserve_yield_spend_e2e_selftest" not in h:
    h = h.replace("int32_t pqpool_reserve_yield_coinbase_spend_selftest(void);",
                  "int32_t pqpool_reserve_yield_coinbase_spend_selftest(void);\nint32_t pqpool_reserve_yield_spend_e2e_selftest(void);", 1)
    open(hf, "w").write(h); print("header: e2e decl added")
print("DONE")
