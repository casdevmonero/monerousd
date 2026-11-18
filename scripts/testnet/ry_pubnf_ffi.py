# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
P3 = "/root/MoneroUSD-clean/monero/external/Plonky3/"
lf = P3 + "pqpool_ffi/src/lib.rs"; l = open(lf).read()
if "pqpool_reserve_yield_spend_multispend_selftest" in l:
    print("v2 FFI present; skip"); sys.exit(0)
imp = "reserve_yield_spend_anchor_bytes,"
if l.count(imp) != 1: print("FATAL import x%d" % l.count(imp)); sys.exit(1)
l = l.replace(imp, imp + " prove_reserve_yield_spend_bundle_v2, verify_reserve_yield_spend_bundle_v2, reserve_yield_spend_nullifier_bytes, prove_reserve_yield_coinbase_spend_bundle_v2, reserve_yield_spend_multispend_selftest,", 1)
anc = 'pub extern "C" fn pqpool_reserve_yield_spend_anchor(bundle: *const u8, bundle_len: usize, out_anchor: *mut u8) -> i32 {'
# insert the new exports right before the anchor fn (find its doc comment start)
marker = "/// CRY-6c-2: extract the spend's membership anchor (32 bytes) from a serialized bundle."
if l.count(marker) != 1: print("FATAL marker x%d" % l.count(marker)); sys.exit(1)
NEW = '''/// CRY-6 public-nf: multi-spend gate (two distinct spends accepted by the nullifier set, replay rejected).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_multispend_selftest() -> i32 { if reserve_yield_spend_multispend_selftest() { 1 } else { 0 } }

/// CRY-6 public-nf: verify a v2 (public-nf, no-IMT) bundle.
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_verify_v2(bundle: *const u8, bundle_len: usize) -> i32 {
    if bundle.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(bundle, bundle_len) };
    match ReserveYieldSpendBundle::deserialize_bundle(s) { Ok(b) => if verify_reserve_yield_spend_bundle_v2(&b) { 1 } else { 0 }, Err(_) => 0 }
}

/// CRY-6 public-nf: extract the PUBLIC nullifier (32 bytes) from a v2 bundle (the daemon's set key).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_nullifier(bundle: *const u8, bundle_len: usize, out_nf: *mut u8) -> i32 {
    if bundle.is_null() || out_nf.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(bundle, bundle_len) };
    match reserve_yield_spend_nullifier_bytes(s) { Some(nf) => { if nf.len() != 32 { return -3; } unsafe { core::ptr::copy_nonoverlapping(nf.as_ptr(), out_nf, 32); } 1 }, None => 0 }
}

/// CRY-6 public-nf wallet builder (v2): build a public-nf coinbase-note spend bundle into `out`.
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_coinbase_spend_prove_v2(
    sk: *const u8, rho: *const u8, rcm: *const u8, value: u64, asset: u32,
    cmt_notes: *const u8, cmt_notes_len: usize, leaf_index: usize, cmt_depth: usize,
    out_pk: *const u8, fee: u64, chain_id: u64, out: *mut u8, out_cap: usize, out_len: *mut usize,
) -> i32 {
    if sk.is_null() || rho.is_null() || rcm.is_null() || cmt_notes.is_null() || out_pk.is_null() || out.is_null() || out_len.is_null() { return -1; }
    let sk_s = unsafe { core::slice::from_raw_parts(sk, 32) };
    let rho_s = unsafe { core::slice::from_raw_parts(rho, 32) };
    let rcm_s = unsafe { core::slice::from_raw_parts(rcm, 32) };
    let opk_s = unsafe { core::slice::from_raw_parts(out_pk, 32) };
    let cmt_s = unsafe { core::slice::from_raw_parts(cmt_notes, cmt_notes_len) };
    match prove_reserve_yield_coinbase_spend_bundle_v2(sk_s, rho_s, rcm_s, value, asset, cmt_s, leaf_index, cmt_depth, opk_s, fee, chain_id) {
        Some(b) => { let bytes = b.serialize_bundle(); unsafe { *out_len = bytes.len(); } if bytes.len() > out_cap { return -2; } unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()); } 1 }
        None => 0,
    }
}

''' + marker
l = l.replace(marker, NEW, 1)
open(lf, "w").write(l); print("lib.rs: v2 FFI added")

# header
hf = P3 + "pqpool_ffi/include/pqpool_ffi.h"; h = open(hf).read()
if "pqpool_reserve_yield_spend_multispend_selftest" not in h:
    h = h.replace("int32_t pqpool_reserve_yield_spend_anchor(const uint8_t *bundle, size_t bundle_len, uint8_t *out_anchor);",
        '''int32_t pqpool_reserve_yield_spend_anchor(const uint8_t *bundle, size_t bundle_len, uint8_t *out_anchor);
int32_t pqpool_reserve_yield_spend_multispend_selftest(void);
int32_t pqpool_reserve_yield_spend_verify_v2(const uint8_t *bundle, size_t bundle_len);
int32_t pqpool_reserve_yield_spend_nullifier(const uint8_t *bundle, size_t bundle_len, uint8_t *out_nf);
int32_t pqpool_reserve_yield_coinbase_spend_prove_v2(const uint8_t *sk, const uint8_t *rho, const uint8_t *rcm, uint64_t value, uint32_t asset, const uint8_t *cmt_notes, size_t cmt_notes_len, size_t leaf_index, size_t cmt_depth, const uint8_t *out_pk, uint64_t fee, uint64_t chain_id, uint8_t *out, size_t out_cap, size_t *out_len);''', 1)
    open(hf, "w").write(h); print("header: v2 decls added")
print("DONE")
