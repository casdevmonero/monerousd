# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
P3="/root/MoneroUSD-clean/monero/external/Plonky3/"
# circuit helper
cf=P3+"pqpool/src/circuit.rs"; s=open(cf).read()
if "reserve_yield_derive_from_ss_bytes" not in s:
    anc="/// CRY-6 public-nf: extract the PUBLIC nullifier (batch_pvs[anchor+chain+commitment ..]) — the daemon's set key."
    HELP='''/// CRY-6 PQ-stealth: derive a 32-byte note secret from the ML-KEM shared secret `ss`, the output index
/// `i`, and a domain `tag`, via the Poseidon2 sponge (post-quantum; NO ECDH/keccak). Producer and wallet
/// derive identically from the same `ss`. Used for sk / rho / rcm / amount-mask (distinct tags).
pub fn reserve_yield_derive_from_ss_bytes(ss: &[u8], i: u64, tag: u64) -> Option<Vec<u8>> {
    if ss.len() != 32 { return None; }
    let mut p = Vec::with_capacity(1 + DIGEST + 1);
    p.push(F::from_u64(tag));
    for k in 0..DIGEST { p.push(F::from_u64(u32::from_le_bytes([ss[k*4], ss[k*4+1], ss[k*4+2], ss[k*4+3]]) as u64)); }
    p.push(F::from_u64(i));
    Some(publics_to_bytes(&run_sponge(&p).digest))
}

'''
    if s.count(anc)!=1: print("FATAL circuit anchor x%d"%s.count(anc)); sys.exit(1)
    s=s.replace(anc, HELP+anc, 1); open(cf,"w").write(s); print("circuit.rs: PQ derive helper added")
else: print("circuit derive present; skip")
# lib.rs FFI
lf=P3+"pqpool_ffi/src/lib.rs"; l=open(lf).read()
if "pqpool_reserve_yield_derive_secrets" not in l:
    imp="reserve_yield_spend_nullifier_bytes,"
    l=l.replace(imp, imp+" reserve_yield_derive_from_ss_bytes,", 1)
    anc='/// CRY-6 public-nf: multi-spend gate (two distinct spends accepted by the nullifier set, replay rejected).'
    NEW='''/// CRY-6 PQ-stealth: derive (sk, rho, rcm) from the ML-KEM shared secret + output index (Poseidon2 sponge).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_derive_secrets(ss: *const u8, i: u64, out_sk: *mut u8, out_rho: *mut u8, out_rcm: *mut u8) -> i32 {
    if ss.is_null() || out_sk.is_null() || out_rho.is_null() || out_rcm.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(ss, 32) };
    let sk = match reserve_yield_derive_from_ss_bytes(s, i, 0x52595f534bu64) { Some(v) => v, None => return 0 };
    let rho = match reserve_yield_derive_from_ss_bytes(s, i, 0x52595f52484fu64) { Some(v) => v, None => return 0 };
    let rcm = match reserve_yield_derive_from_ss_bytes(s, i, 0x52595f52434du64) { Some(v) => v, None => return 0 };
    unsafe { core::ptr::copy_nonoverlapping(sk.as_ptr(), out_sk, 32); core::ptr::copy_nonoverlapping(rho.as_ptr(), out_rho, 32); core::ptr::copy_nonoverlapping(rcm.as_ptr(), out_rcm, 32); }
    1
}

/// CRY-6 PQ-stealth: 8-byte amount mask from the ML-KEM shared secret (r_enc = value ^ mask).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_amount_mask(ss: *const u8, i: u64, out_mask: *mut u8) -> i32 {
    if ss.is_null() || out_mask.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(ss, 32) };
    let m = match reserve_yield_derive_from_ss_bytes(s, i, 0x52595f414d54u64) { Some(v) => v, None => return 0 };
    unsafe { core::ptr::copy_nonoverlapping(m.as_ptr(), out_mask, 8); }
    1
}

''' + anc
    l=l.replace(anc, NEW, 1); open(lf,"w").write(l); print("lib.rs: PQ derive FFI added")
else: print("lib derive present; skip")
# header
hf=P3+"pqpool_ffi/include/pqpool_ffi.h"; h=open(hf).read()
if "pqpool_reserve_yield_derive_secrets" not in h:
    h=h.replace("int32_t pqpool_reserve_yield_spend_multispend_selftest(void);",
        "int32_t pqpool_reserve_yield_spend_multispend_selftest(void);\nint32_t pqpool_reserve_yield_derive_secrets(const uint8_t *ss, uint64_t i, uint8_t *out_sk, uint8_t *out_rho, uint8_t *out_rcm);\nint32_t pqpool_reserve_yield_amount_mask(const uint8_t *ss, uint64_t i, uint8_t *out_mask);", 1)
    open(hf,"w").write(h); print("header: PQ derive decls added")
print("DONE")
