# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
# 1) lib.rs: import + FFI exports
lf = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool_ffi/src/lib.rs"
s = open(lf).read()
if "pqpool_reserve_yield_coinbase_spend_selftest" in s:
    print("lib.rs already has coinbase-spend FFI; skip")
else:
    imp = "reserve_yield_spend_roots_bytes,"
    if s.count(imp) != 1: print("FATAL import anchor x%d" % s.count(imp)); sys.exit(1)
    s = s.replace(imp, "reserve_yield_spend_roots_bytes, prove_reserve_yield_coinbase_spend_bundle, reserve_yield_coinbase_spend_selftest,", 1)
    anchor = 'pub extern "C" fn pqpool_reserve_yield_spend_compose_selftest() -> i32 { if reserve_yield_spend_compose_selftest() { 1 } else { 0 } }'
    if s.count(anchor) != 1: print("FATAL export anchor x%d" % s.count(anchor)); sys.exit(1)
    EXPORTS = anchor + '''

/// CRY-6d-wallet: validate the wallet's coinbase-note spend builder (anchor==cmt-root, ns_root_old==empty, verifies).
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_coinbase_spend_selftest() -> i32 { if reserve_yield_coinbase_spend_selftest() { 1 } else { 0 } }

/// CRY-6d-wallet: build a real coinbase-note spend bundle into `out` (serialized). Returns 1 ok / 0 inconsistent / <0 ptr|cap error; *out_len set to needed length.
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_coinbase_spend_prove(
    sk: *const u8, rho: *const u8, rcm: *const u8, value: u64, asset: u32,
    cmt_notes: *const u8, cmt_notes_len: usize, leaf_index: usize, cmt_depth: usize,
    out_pk: *const u8, fee: u64, chain_id: u64, imt_depth: usize,
    out: *mut u8, out_cap: usize, out_len: *mut usize,
) -> i32 {
    if sk.is_null() || rho.is_null() || rcm.is_null() || cmt_notes.is_null() || out_pk.is_null() || out.is_null() || out_len.is_null() { return -1; }
    let sk_s = unsafe { core::slice::from_raw_parts(sk, 32) };
    let rho_s = unsafe { core::slice::from_raw_parts(rho, 32) };
    let rcm_s = unsafe { core::slice::from_raw_parts(rcm, 32) };
    let opk_s = unsafe { core::slice::from_raw_parts(out_pk, 32) };
    let cmt_s = unsafe { core::slice::from_raw_parts(cmt_notes, cmt_notes_len) };
    match prove_reserve_yield_coinbase_spend_bundle(sk_s, rho_s, rcm_s, value, asset, cmt_s, leaf_index, cmt_depth, opk_s, fee, chain_id, imt_depth) {
        Some(b) => {
            let bytes = b.serialize_bundle();
            unsafe { *out_len = bytes.len(); }
            if bytes.len() > out_cap { return -2; }
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()); }
            1
        }
        None => 0,
    }
}'''
    s = s.replace(anchor, EXPORTS, 1)
    open(lf, "w").write(s); print("lib.rs: coinbase-spend FFI added")

# 2) header decls
hf = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"
h = open(hf).read()
if "pqpool_reserve_yield_coinbase_spend_selftest" in h:
    print("header already has decls; skip")
else:
    # anchor on an existing reserve_yield decl close paren; insert before the last #endif or extern close
    import re
    decl = '''
int32_t pqpool_reserve_yield_coinbase_spend_selftest(void);
int32_t pqpool_reserve_yield_coinbase_spend_prove(
    const uint8_t *sk, const uint8_t *rho, const uint8_t *rcm, uint64_t value, uint32_t asset,
    const uint8_t *cmt_notes, size_t cmt_notes_len, size_t leaf_index, size_t cmt_depth,
    const uint8_t *out_pk, uint64_t fee, uint64_t chain_id, size_t imt_depth,
    uint8_t *out, size_t out_cap, size_t *out_len);
'''
    anchor = None
    for cand in ["int32_t pqpool_reserve_yield_spend_roots(", "int32_t pqpool_imt_empty_root(", "int32_t pqpool_reserve_yield_spend_verify("]:
        if cand in h:
            # insert decl right before this line
            anchor = cand; break
    if anchor is None: print("FATAL no header anchor"); sys.exit(1)
    h = h.replace(anchor, decl.strip() + "\n" + anchor, 1)
    open(hf, "w").write(h); print("header: decls added (before %s)" % anchor[:40])
print("DONE")
