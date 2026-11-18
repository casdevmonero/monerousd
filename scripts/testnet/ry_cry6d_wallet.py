# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
f = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool/src/circuit.rs"
s = open(f).read()
if "prove_reserve_yield_coinbase_spend_bundle" in s:
    print("already present; skip"); sys.exit(0)

WALLET = r'''/// CRY-6d-wallet: build a reserve-yield COINBASE-NOTE spend bundle — the wallet's prove path. The spent
/// note is a real v45 coinbase note (value, asset, pk_d = own_null(sk).pk_d, rho, rcm) sitting at
/// `leaf_index` of the coinbase-note tree whose leaves are `cmt_notes` (concat of 32-byte note_cm — the
/// SAME list the daemon rebuilds deterministically from the chain). The spend's membership anchor IS that
/// tree's root, so the daemon's cmt-anchor check recognises it; ns_root_old IS the empty IMT root
/// (genesis), so the daemon's ns_root threading accepts the first spend then advances. The wallet
/// self-computes the Merkle path; nothing secret leaves this function. Returns None on inconsistent input.
#[allow(clippy::too_many_arguments)]
pub fn prove_reserve_yield_coinbase_spend_bundle(
    sk_bytes: &[u8], rho_bytes: &[u8], rcm_bytes: &[u8], value: u64, asset: u32,
    cmt_notes: &[u8], leaf_index: usize, cmt_depth: usize,
    out_pk_bytes: &[u8], fee: u64, chain_id: u64, imt_depth: usize,
) -> Option<ReserveYieldSpendBundle> {
    if sk_bytes.len() != DIGEST * 4 || rho_bytes.len() != DIGEST * 4 || rcm_bytes.len() != DIGEST * 4 || out_pk_bytes.len() != DIGEST * 4 { return None; }
    if value < fee || cmt_notes.len() % 32 != 0 || cmt_depth == 0 || cmt_depth > 16 { return None; }
    let count = cmt_notes.len() / 32;
    if count == 0 || leaf_index >= count || count > (1usize << cmt_depth) { return None; }
    let sk = ry_bytes_to_digest(sk_bytes); let rho = ry_bytes_to_digest(rho_bytes); let rcm = ry_bytes_to_digest(rcm_bytes);
    let out_pk = ry_bytes_to_digest(out_pk_bytes);
    // recompute our coinbase note's commitment; it MUST equal the on-chain leaf at leaf_index
    let pk_d = own_null_run(sk, rho).pk_d;
    let note_cm = run_sponge(&note_commit_preimage(value, asset, &pk_d, &rho, &rcm)).digest;
    if ry_bytes_to_digest(&cmt_notes[leaf_index * 32..leaf_index * 32 + 32]) != note_cm { return None; }
    // self-compute the Merkle path against the daemon's tree
    let sib_bytes = ry_note_tree_path_bytes(cmt_notes, cmt_depth, leaf_index)?;
    let siblings: Vec<[F; DIGEST]> = (0..cmt_depth).map(|k| ry_bytes_to_digest(&sib_bytes[k * 32..k * 32 + 32])).collect();
    // deterministic change-note params (testnet placeholder; production draws fresh hidden randomness)
    let dom = |tag: u64, seed: &[F; DIGEST]| -> [F; DIGEST] { let mut p = Vec::with_capacity(1 + DIGEST); p.push(F::from_u64(tag)); p.extend_from_slice(seed); run_sponge(&p).digest };
    let out_rho = dom(0x6f75745f72686f, &rho); // "out_rho"
    let out_rcm = dom(0x6f75745f72636d, &rcm); // "out_rcm"
    let sp = (value, asset, rcm, sk, rho, siblings, leaf_index, value - fee, asset, out_pk, out_rho, out_rcm, fee, chain_id, FullSpendTamper::None);
    Some(prove_reserve_yield_spend_bundle(sp, imt_depth))
}

/// CRY-6d-wallet gate: the wallet builds a REAL coinbase-note spend; assert (a) it verifies via the
/// daemon's from-bytes path, (b) its membership anchor == the daemon's cmt-tree root over the same
/// note_cm (the cmt-anchor check input), (c) its ns_root_old == the empty IMT root (the daemon's genesis
/// ns_root). Passing proves a wallet can construct a spend the daemon accepts on BOTH the anchor AND the
/// ns-root threading — i.e. the wallet builder, cmt-anchor, and ns-root all line up by construction.
pub fn reserve_yield_coinbase_spend_selftest() -> bool {
    let mkb = |x: u64| -> Vec<u8> { let mut v = vec![0u8; DIGEST * 4]; v[0..8].copy_from_slice(&x.to_le_bytes()); v };
    let (sk_b, rho_b, rcm_b, opk_b) = (mkb(0xC0FFEE), mkb(0x1234), mkb(0x5678), mkb(0xBEEF));
    let (cmt_depth, imt_depth) = (4usize, 4usize);
    // seed the cmt-tree with this note's commitment at leaf 0 (= the daemon's view after one coinbase)
    let sk = ry_bytes_to_digest(&sk_b); let rho = ry_bytes_to_digest(&rho_b); let rcm = ry_bytes_to_digest(&rcm_b);
    let pk_d = own_null_run(sk, rho).pk_d;
    let note_cm = run_sponge(&note_commit_preimage(12345, 0, &pk_d, &rho, &rcm)).digest;
    let cmt_notes = publics_to_bytes(&note_cm);
    let bundle = match prove_reserve_yield_coinbase_spend_bundle(&sk_b, &rho_b, &rcm_b, 12345, 0, &cmt_notes, 0, cmt_depth, &opk_b, 2345, 7, imt_depth) { Some(b) => b, None => return false };
    if !verify_reserve_yield_spend_bundle(&bundle) { return false; }
    // (b) anchor (batch_pvs[0..DIGEST]) == daemon cmt-tree root over the same note_cm
    let anchor = publics_to_bytes(&bundle.batch_pvs[0..DIGEST]);
    let daemon_root = match ry_note_tree_root_bytes(&cmt_notes, cmt_depth) { Some(r) => r, None => return false };
    if anchor != daemon_root { return false; }
    // (c) ns_root_old (imt_pvs[0..DIGEST]) == empty IMT root (genesis)
    let ns_old = publics_to_bytes(&bundle.imt_pvs[0..DIGEST]);
    let empty = match imt_empty_root_bytes(imt_depth) { Some(r) => r, None => return false };
    if ns_old != empty { return false; }
    // negative: a wrong leaf_index (note not at that position) must refuse to build
    if prove_reserve_yield_coinbase_spend_bundle(&sk_b, &rho_b, &rcm_b, 12345, 0, &cmt_notes, 1, cmt_depth, &opk_b, 2345, 7, imt_depth).is_some() { return false; }
    true
}

'''
anchor = "/// CRY-6e: produce a fixed reserve-yield spend bundle's serialized bytes (for the C++ ABI smoke).\npub fn prove_test_reserve_yield_spend_bytes() -> Vec<u8> {"
if s.count(anchor) != 1:
    print("FATAL wallet anchor x%d" % s.count(anchor)); sys.exit(1)
s = s.replace(anchor, WALLET + anchor, 1)

# add a #[test] mirroring the module pattern
tanchor = "    #[test]\n    fn bind_r5_gated_diffheight() {"
TEST = '''    #[test]
    fn reserve_yield_coinbase_spend() {
        // CRY-6d-wallet: wallet builds a real coinbase-note spend; anchor == daemon cmt-root,
        // ns_root_old == genesis empty IMT root, verifies from bytes, wrong leaf_index refused.
        assert!(super::reserve_yield_coinbase_spend_selftest(), "wallet coinbase-note spend must build, verify, and line up with cmt-root + genesis ns_root");
        eprintln!("[COINBASE_SPEND_OK] wallet builder anchor==cmt-root, ns_root_old==empty, verifies");
    }

'''
if s.count(tanchor) != 1:
    print("FATAL test anchor x%d" % s.count(tanchor)); sys.exit(1)
s = s.replace(tanchor, TEST + tanchor, 1)
open(f, "w").write(s)
print("circuit.rs: wallet builder + selftest + test added")
