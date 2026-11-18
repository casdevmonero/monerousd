# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
p = "external/Plonky3/pqpool_ffi/src/lib.rs"
s = open(p).read()
if "pqpool_reserve_yield_prove_note" in s:
    print("present; skip"); sys.exit(0)

# import
imp_old = "    reserve_yield_prove_zk_raw, reserve_yield_verify_zk_raw, reserve_yield_zk_selftest,"
imp_new = "    reserve_yield_prove_zk_raw, reserve_yield_prove_zk_raw_note, reserve_yield_verify_zk_raw, reserve_yield_zk_selftest,"
if s.count(imp_old) != 1:
    print("FATAL import anchor x%d" % s.count(imp_old)); sys.exit(1)
s = s.replace(imp_old, imp_new, 1)

# new extern C before the existing one
anc = "#[no_mangle]\npub extern \"C\" fn pqpool_reserve_yield_prove(\n    k: u32, modulus: u64, b: u64, x: u64,"
if s.count(anc) != 1:
    print("FATAL externc anchor x%d" % s.count(anc)); sys.exit(1)
fn = '''#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_prove_note(
    k: u32, modulus: u64, b: u64, x: u64,
    rcmx: *const u8, rcmx_len: usize,
    rcmy: *const u8, rcmy_len: usize,
    rcmb: *const u8, rcmb_len: usize,
    note_value: u64,
    asset: u32,
    pk_d: *const u8, pk_d_len: usize,
    rho: *const u8, rho_len: usize,
    rcm: *const u8, rcm_len: usize,
    out_proof_ptr: *mut *mut u8, out_proof_len: *mut usize,
    out_publics: *mut u8, out_publics_len: usize,
) -> i32 {
    if rcmx.is_null() || rcmy.is_null() || rcmb.is_null() || pk_d.is_null() || rho.is_null() || rcm.is_null()
        || out_proof_ptr.is_null() || out_proof_len.is_null() || out_publics.is_null() { return -1; }
    if out_publics_len != 128 { return -2; }
    let rcmx_s = unsafe { core::slice::from_raw_parts(rcmx, rcmx_len) };
    let rcmy_s = unsafe { core::slice::from_raw_parts(rcmy, rcmy_len) };
    let rcmb_s = unsafe { core::slice::from_raw_parts(rcmb, rcmb_len) };
    let pk_d_s = unsafe { core::slice::from_raw_parts(pk_d, pk_d_len) };
    let rho_s = unsafe { core::slice::from_raw_parts(rho, rho_len) };
    let rcm_s = unsafe { core::slice::from_raw_parts(rcm, rcm_len) };
    match reserve_yield_prove_zk_raw_note(k as usize, modulus, b, x, rcmx_s, rcmy_s, rcmb_s, note_value, asset, pk_d_s, rho_s, rcm_s) {
        Some((proof, publics)) => {
            if publics.len() != 128 { return -3; }
            unsafe { core::ptr::copy_nonoverlapping(publics.as_ptr(), out_publics, 128); }
            let boxed = proof.into_boxed_slice();
            let len = boxed.len();
            let raw = Box::into_raw(boxed) as *mut u8;
            unsafe { *out_proof_ptr = raw; *out_proof_len = len; }
            1
        }
        None => 0,
    }
}

'''
s = s.replace(anc, fn + anc, 1)
open(p, "w").write(s)
print("extern C pqpool_reserve_yield_prove_note added")
