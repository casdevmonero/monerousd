# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# 1) circuit.rs: own_null_pkd_nf_bytes (spend-auth derivation) + reserve_yield_spend_selftest (full round-trip).
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()
if "reserve_yield_spend_selftest" not in s:
    anc = "pub fn prove_verify_spend("
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''/// CRY-6: expose the spend-auth derivation so the coinbase producer can commit a SPENDABLE pk_d
/// and the wallet can reconstruct (sk -> pk_d, nf). pk_d = H(DS_PK | sk) (depends on sk only);
/// nf = H(DS_NF | H(DS_NK|sk) | rho). Byte layout matches the on-chain publics (publics_to_bytes).
pub fn own_null_pkd_nf_bytes(sk_bytes: &[u8], rho_bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if sk_bytes.len() != DIGEST * 4 || rho_bytes.len() != DIGEST * 4 { return None; }
    let to = |bb: &[u8]| -> [F; DIGEST] {
        let mut a = [F::ZERO; DIGEST];
        for i in 0..DIGEST { let o = i * 4; a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o+1], bb[o+2], bb[o+3]]) as u64); }
        a
    };
    let own = own_null_run(to(sk_bytes), to(rho_bytes));
    Some((publics_to_bytes(&own.pk_d), publics_to_bytes(&own.nf)))
}

/// CRY-6: end-to-end spend round-trip for a reserve-yield note through the SpendAir prove+verify
/// path: a value-12345 note owned by sk at a depth-4 Merkle leaf, spent 1-in/1-out (out 11345 +
/// fee 1000, balanced). Returns true iff the honest spend verifies. Proves a reserve-yield note is
/// spendable via the existing validated shielded-pool machinery (SpendAir membership + nullifier).
pub fn reserve_yield_spend_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut a = [F::ZERO; DIGEST]; a[0] = F::from_u64(x); a };
    let sk = mk(7); let rho = mk(11); let rcm = mk(13);
    let sibs = vec![mk(2), mk(3), mk(4), mk(5)];
    prove_verify_spend(12345, 0, rcm, sk, rho, sibs, 0b1010, 11345, 0, mk(9), mk(10), mk(11), 1000, 42, FullSpendTamper::None)
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("circuit spend FFI helpers added")
else: print("circuit spend helpers present; skip")

# 2) pqpool_ffi/lib.rs: import + extern C.
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_reserve_yield_spend_selftest" not in fs:
    io = "    reserve_yield_prove_zk_raw, reserve_yield_prove_zk_raw_note, reserve_yield_note_cm_bytes, reserve_yield_verify_zk_raw, reserve_yield_zk_selftest,"
    inew = io + "\n    own_null_pkd_nf_bytes, reserve_yield_spend_selftest,"
    if fs.count(io) != 1: print("FATAL import anchor x%d" % fs.count(io)); sys.exit(1)
    fs = fs.replace(io, inew, 1)
    anc2 = "#[no_mangle]\npub extern \"C\" fn pqpool_reserve_yield_note_cm("
    fn2 = '''#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_selftest() -> i32 {
    if reserve_yield_spend_selftest() { 1 } else { 0 }
}

/// CRY-6: derive (pk_d, nf) from (sk, rho). Each 32-byte buffer is 8 little-endian u32 limbs.
/// out_pk_d/out_nf must be 32 bytes. Returns 1 ok, 0 bad-length input, <0 null/bad-out-length.
#[no_mangle]
pub extern "C" fn pqpool_own_null_pkd_nf(
    sk: *const u8, sk_len: usize, rho: *const u8, rho_len: usize,
    out_pk_d: *mut u8, out_pk_d_len: usize, out_nf: *mut u8, out_nf_len: usize,
) -> i32 {
    if sk.is_null() || rho.is_null() || out_pk_d.is_null() || out_nf.is_null() { return -1; }
    if out_pk_d_len != 32 || out_nf_len != 32 { return -2; }
    let sk_s = unsafe { core::slice::from_raw_parts(sk, sk_len) };
    let rho_s = unsafe { core::slice::from_raw_parts(rho, rho_len) };
    match own_null_pkd_nf_bytes(sk_s, rho_s) {
        Some((pkd, nf)) => {
            if pkd.len() != 32 || nf.len() != 32 { return -3; }
            unsafe {
                core::ptr::copy_nonoverlapping(pkd.as_ptr(), out_pk_d, 32);
                core::ptr::copy_nonoverlapping(nf.as_ptr(), out_nf, 32);
            }
            1
        }
        None => 0,
    }
}

'''
    if fs.count(anc2) != 1: print("FATAL externc anchor x%d" % fs.count(anc2)); sys.exit(1)
    fs = fs.replace(anc2, fn2 + anc2, 1); open(f, "w").write(fs); print("ffi spend extern C added")
else: print("ffi spend present; skip")

# 3) pqpool_ffi.h decls.
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_reserve_yield_spend_selftest" not in hs:
    ha = "int32_t pqpool_reserve_yield_note_cm(uint64_t note_value, uint32_t asset,"
    hn = ("int32_t pqpool_reserve_yield_spend_selftest(void);\n"
          "int32_t pqpool_own_null_pkd_nf(const uint8_t* sk, size_t sk_len, const uint8_t* rho, size_t rho_len,\n"
          "    uint8_t* out_pk_d, size_t out_pk_d_len, uint8_t* out_nf, size_t out_nf_len);\n\n")
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    open(h, "w").write(hs.replace(ha, hn + ha, 1)); print("ffi.h spend decls added")
else: print("ffi.h spend present; skip")
print("DONE")
