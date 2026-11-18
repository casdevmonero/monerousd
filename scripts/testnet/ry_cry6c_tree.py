# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# 1) circuit.rs: circuit-matched reserve-yield note tree (root + path) + a tree->spend selftest.
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()
if "reserve_yield_tree_spend_selftest" not in s:
    anc = "pub fn reserve_yield_spend_selftest() -> bool {"
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6c: a fixed-depth binary Merkle tree over reserve-yield note commitments, using the EXACT
// node hash the SpendAir C2 membership constraint folds (`H(DS_MERKLE | left | right)` via run_sponge),
// so a root/path built here is accepted by the spend circuit BY CONSTRUCTION. The daemon and wallet
// both rebuild this tree deterministically from the public v45 coinbase note_cms (same block order ->
// same root), so the wallet self-computes Merkle paths and the daemon recognises valid anchor roots.
fn ry_merkle_node(left: &[F; DIGEST], right: &[F; DIGEST]) -> [F; DIGEST] {
    let mut p = Vec::with_capacity(1 + 2 * DIGEST);
    p.push(F::from_u64(DS_MERKLE));
    p.extend_from_slice(left);
    p.extend_from_slice(right);
    run_sponge(&p).digest
}

/// Build a materialised fixed-depth tree; real leaves first, the rest padded with the zero leaf.
/// Returns (root, levels) where levels[0] = leaves, levels[d] = nodes at height d. depth <= 16.
fn ry_build_tree(leaves: &[[F; DIGEST]], depth: usize) -> ([F; DIGEST], Vec<Vec<[F; DIGEST]>>) {
    let n = 1usize << depth;
    let zero = [F::ZERO; DIGEST];
    let mut cur: Vec<[F; DIGEST]> = (0..n).map(|i| if i < leaves.len() { leaves[i] } else { zero }).collect();
    let mut levels: Vec<Vec<[F; DIGEST]>> = vec![cur.clone()];
    while cur.len() > 1 {
        let next: Vec<[F; DIGEST]> = cur.chunks(2).map(|ch| ry_merkle_node(&ch[0], &ch[1])).collect();
        levels.push(next.clone());
        cur = next;
    }
    (cur[0], levels)
}

/// Bottom-up sibling list for `leaf_idx` (matches merkle_path_run's consumption order + bit convention).
fn ry_tree_path(levels: &[Vec<[F; DIGEST]>], mut idx: usize, depth: usize) -> Vec<[F; DIGEST]> {
    let mut sibs = Vec::with_capacity(depth);
    for d in 0..depth { sibs.push(levels[d][idx ^ 1]); idx >>= 1; }
    sibs
}

fn ry_bytes_to_digest(bb: &[u8]) -> [F; DIGEST] {
    let mut a = [F::ZERO; DIGEST];
    for i in 0..DIGEST { let o = i * 4; a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o+1], bb[o+2], bb[o+3]]) as u64); }
    a
}

/// FFI helper: root of the note tree built from `note_cms` (concatenated 32-byte commitments).
pub fn ry_note_tree_root_bytes(note_cms: &[u8], depth: usize) -> Option<Vec<u8>> {
    if note_cms.len() % 32 != 0 || depth == 0 || depth > 16 { return None; }
    let count = note_cms.len() / 32;
    if count > (1usize << depth) { return None; }
    let leaves: Vec<[F; DIGEST]> = (0..count).map(|i| ry_bytes_to_digest(&note_cms[i*32..i*32+32])).collect();
    let (root, _) = ry_build_tree(&leaves, depth);
    Some(publics_to_bytes(&root))
}

/// FFI helper: bottom-up Merkle path (depth * 32 bytes) for `leaf_idx` in the note tree.
pub fn ry_note_tree_path_bytes(note_cms: &[u8], depth: usize, leaf_idx: usize) -> Option<Vec<u8>> {
    if note_cms.len() % 32 != 0 || depth == 0 || depth > 16 { return None; }
    let count = note_cms.len() / 32;
    if count > (1usize << depth) || leaf_idx >= (1usize << depth) { return None; }
    let leaves: Vec<[F; DIGEST]> = (0..count).map(|i| ry_bytes_to_digest(&note_cms[i*32..i*32+32])).collect();
    let (_root, levels) = ry_build_tree(&leaves, depth);
    let sibs = ry_tree_path(&levels, leaf_idx, depth);
    let mut out = Vec::with_capacity(depth * 32);
    for s in &sibs { out.extend_from_slice(&publics_to_bytes(s)); }
    Some(out)
}

/// CRY-6c gate: build a note tree, place an owned note at a leaf, extract the path, and (a) assert the
/// path folds to the tree root, (b) prove+verify a spend whose anchor IS that root. Passing proves the
/// tree built here is circuit-compatible with SpendAir membership.
pub fn reserve_yield_tree_spend_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut a = [F::ZERO; DIGEST]; a[0] = F::from_u64(x); a };
    let sk = mk(7); let rho = mk(11); let rcm = mk(13);
    let pk_d = own_null_run(sk, rho).pk_d;
    let note_cm = run_sponge(&note_commit_preimage(12345, 0, &pk_d, &rho, &rcm)).digest;
    let depth = 4usize; let idx = 5usize;
    let mut leaves: Vec<[F; DIGEST]> = (0..(1usize << depth)).map(|i| mk(100 + i as u64)).collect();
    leaves[idx] = note_cm;
    let (root, levels) = ry_build_tree(&leaves, depth);
    let sibs = ry_tree_path(&levels, idx, depth);
    if merkle_path_run(note_cm, &sibs, idx).root != root { return false; }  // (a) tree root == circuit fold
    prove_verify_spend(12345, 0, rcm, sk, rho, sibs, idx, 11345, 0, mk(9), mk(10), mk(11), 1000, 42, FullSpendTamper::None)  // (b)
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("circuit 6c tree added")
else: print("circuit 6c present; skip")

# 2) pqpool_ffi/lib.rs: import + extern C (root, path, selftest).
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_ry_note_tree_root" not in fs:
    io = "    own_null_pkd_nf_bytes, reserve_yield_spend_selftest,"
    inew = io + "\n    ry_note_tree_root_bytes, ry_note_tree_path_bytes, reserve_yield_tree_spend_selftest,"
    if fs.count(io) != 1: print("FATAL import anchor x%d" % fs.count(io)); sys.exit(1)
    fs = fs.replace(io, inew, 1)
    anc2 = "#[no_mangle]\npub extern \"C\" fn pqpool_reserve_yield_spend_selftest() -> i32 {"
    fn2 = '''#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_tree_spend_selftest() -> i32 {
    if reserve_yield_tree_spend_selftest() { 1 } else { 0 }
}

/// CRY-6c: root of the reserve-yield note tree over `note_cms` (count*32 bytes). out_root = 32 bytes.
#[no_mangle]
pub extern "C" fn pqpool_ry_note_tree_root(
    note_cms: *const u8, note_cms_len: usize, depth: usize, out_root: *mut u8, out_root_len: usize,
) -> i32 {
    if note_cms.is_null() || out_root.is_null() { return -1; }
    if out_root_len != 32 { return -2; }
    let s = unsafe { core::slice::from_raw_parts(note_cms, note_cms_len) };
    match ry_note_tree_root_bytes(s, depth) {
        Some(r) => { if r.len() != 32 { return -3; } unsafe { core::ptr::copy_nonoverlapping(r.as_ptr(), out_root, 32); } 1 }
        None => 0,
    }
}

/// CRY-6c: bottom-up Merkle path for `leaf_idx`. out_sibs must be depth*32 bytes.
#[no_mangle]
pub extern "C" fn pqpool_ry_note_tree_path(
    note_cms: *const u8, note_cms_len: usize, depth: usize, leaf_idx: usize, out_sibs: *mut u8, out_sibs_len: usize,
) -> i32 {
    if note_cms.is_null() || out_sibs.is_null() { return -1; }
    if out_sibs_len != depth * 32 { return -2; }
    let s = unsafe { core::slice::from_raw_parts(note_cms, note_cms_len) };
    match ry_note_tree_path_bytes(s, depth, leaf_idx) {
        Some(p) => { if p.len() != depth * 32 { return -3; } unsafe { core::ptr::copy_nonoverlapping(p.as_ptr(), out_sibs, depth * 32); } 1 }
        None => 0,
    }
}

#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_selftest() -> i32 {'''
    if fs.count(anc2) != 1: print("FATAL externc anchor x%d" % fs.count(anc2)); sys.exit(1)
    fs = fs.replace(anc2, fn2, 1); open(f, "w").write(fs); print("ffi 6c tree added")
else: print("ffi 6c present; skip")

# 3) pqpool_ffi.h decls.
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_ry_note_tree_root" not in hs:
    ha = "int32_t pqpool_reserve_yield_spend_selftest(void);"
    hn = ("int32_t pqpool_reserve_yield_tree_spend_selftest(void);\n"
          "int32_t pqpool_ry_note_tree_root(const uint8_t* note_cms, size_t note_cms_len, size_t depth, uint8_t* out_root, size_t out_root_len);\n"
          "int32_t pqpool_ry_note_tree_path(const uint8_t* note_cms, size_t note_cms_len, size_t depth, size_t leaf_idx, uint8_t* out_sibs, size_t out_sibs_len);\n"
          "int32_t pqpool_reserve_yield_spend_selftest(void);")
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    open(h, "w").write(hs.replace(ha, hn, 1)); print("ffi.h 6c added")
else: print("ffi.h 6c present; skip")
print("DONE")
