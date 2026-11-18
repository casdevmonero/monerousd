# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# 1) circuit.rs: lightweight note_cm derivation (reuse note_commit_preimage + run_sponge + publics_to_bytes).
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()
if "reserve_yield_note_cm_bytes" not in s:
    anc = "/// FFI marshaling (verifier side): verify a ZK reserve-yield proof from raw bytes"
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''/// Lightweight note_cm derivation for the wallet scanner (NO proof): note_cm = H(DS_NOTE_CM | value | asset | pk_d | rho | rcm).
/// Returns the 32-byte note_cm in the SAME byte layout as the on-chain publics[64:96] (publics_to_bytes).
pub fn reserve_yield_note_cm_bytes(note_value: u64, asset: u32, pk_d_bytes: &[u8], rho_bytes: &[u8], rcm_bytes: &[u8]) -> Option<Vec<u8>> {
    if pk_d_bytes.len() != DIGEST * 4 || rho_bytes.len() != DIGEST * 4 || rcm_bytes.len() != DIGEST * 4 { return None; }
    let to_note = |bb: &[u8]| -> [F; DIGEST] {
        let mut a = [F::ZERO; DIGEST];
        for i in 0..DIGEST { let o = i * 4; a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o+1], bb[o+2], bb[o+3]]) as u64); }
        a
    };
    let preimage = note_commit_preimage(note_value, asset, &to_note(pk_d_bytes), &to_note(rho_bytes), &to_note(rcm_bytes));
    let run = run_sponge(&preimage);
    let cm: Vec<F> = run.states_out[NOTE_COMMIT_PERMS - 1][0..DIGEST].to_vec();
    Some(publics_to_bytes(&cm))
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("circuit note_cm fn added")
else: print("circuit note_cm present; skip")

# 2) pqpool_ffi/lib.rs: import + extern C.
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_reserve_yield_note_cm" not in fs:
    io = "    reserve_yield_prove_zk_raw, reserve_yield_prove_zk_raw_note, reserve_yield_verify_zk_raw, reserve_yield_zk_selftest,"
    inew = "    reserve_yield_prove_zk_raw, reserve_yield_prove_zk_raw_note, reserve_yield_note_cm_bytes, reserve_yield_verify_zk_raw, reserve_yield_zk_selftest,"
    if fs.count(io) != 1: print("FATAL import anchor x%d" % fs.count(io)); sys.exit(1)
    fs = fs.replace(io, inew, 1)
    anc2 = "#[no_mangle]\npub extern \"C\" fn pqpool_reserve_yield_prove_note("
    fn2 = '''#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_note_cm(
    note_value: u64, asset: u32,
    pk_d: *const u8, pk_d_len: usize, rho: *const u8, rho_len: usize, rcm: *const u8, rcm_len: usize,
    out_note_cm: *mut u8, out_note_cm_len: usize,
) -> i32 {
    if pk_d.is_null() || rho.is_null() || rcm.is_null() || out_note_cm.is_null() { return -1; }
    if out_note_cm_len != 32 { return -2; }
    let pk_d_s = unsafe { core::slice::from_raw_parts(pk_d, pk_d_len) };
    let rho_s = unsafe { core::slice::from_raw_parts(rho, rho_len) };
    let rcm_s = unsafe { core::slice::from_raw_parts(rcm, rcm_len) };
    match reserve_yield_note_cm_bytes(note_value, asset, pk_d_s, rho_s, rcm_s) {
        Some(cm) => { if cm.len() != 32 { return -3; } unsafe { core::ptr::copy_nonoverlapping(cm.as_ptr(), out_note_cm, 32); } 1 }
        None => 0,
    }
}

'''
    if fs.count(anc2) != 1: print("FATAL externc2 anchor x%d" % fs.count(anc2)); sys.exit(1)
    fs = fs.replace(anc2, fn2 + anc2, 1); open(f, "w").write(fs); print("ffi note_cm extern C added")
else: print("ffi note_cm present; skip")

# 3) pqpool_ffi.h decl.
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_reserve_yield_note_cm" not in hs:
    ha = "int32_t pqpool_reserve_yield_prove_note(uint32_t k, uint64_t modulus, uint64_t b, uint64_t x,"
    hn = ("int32_t pqpool_reserve_yield_note_cm(uint64_t note_value, uint32_t asset,\n"
          "    const uint8_t* pk_d, size_t pk_d_len, const uint8_t* rho, size_t rho_len, const uint8_t* rcm, size_t rcm_len,\n"
          "    uint8_t* out_note_cm, size_t out_note_cm_len);\n\n")
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    open(h, "w").write(hs.replace(ha, hn + ha, 1)); print("ffi.h note_cm decl added")
else: print("ffi.h note_cm present; skip")
print("DONE")
