# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
P3 = "/root/MoneroUSD-clean/monero/external/Plonky3/"
CC = "/root/MoneroUSD-clean/monero/src/cryptonote_core/"

# 1) circuit.rs: anchor extractor helper
cf = P3 + "pqpool/src/circuit.rs"; s = open(cf).read()
if "reserve_yield_spend_anchor_bytes" not in s:
    anc = "/// CRY-6e: extract (ns_root_old, ns_root_new) from a serialized reserve-yield spend bundle (imt_pvs)."
    HELP = '''/// CRY-6c-2: extract the spend's membership ANCHOR (batch_pvs[0..DIGEST]) from a serialized bundle —
/// the daemon checks this against its set of valid coinbase-note-tree roots (anti-fake-note).
pub fn reserve_yield_spend_anchor_bytes(bundle: &[u8]) -> Option<Vec<u8>> {
    let b = ReserveYieldSpendBundle::deserialize_bundle(bundle).ok()?;
    if b.batch_pvs.len() < DIGEST { return None; }
    Some(publics_to_bytes(&b.batch_pvs[0..DIGEST]))
}

'''
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    s = s.replace(anc, HELP + anc, 1); open(cf, "w").write(s); print("circuit.rs: anchor helper added")
else: print("circuit.rs anchor helper present; skip")

# 2) lib.rs FFI export + import
lf = P3 + "pqpool_ffi/src/lib.rs"; l = open(lf).read()
if "pqpool_reserve_yield_spend_anchor" not in l:
    imp = "reserve_yield_spend_roots_bytes,"
    l = l.replace(imp, imp + " reserve_yield_spend_anchor_bytes,", 1)
    anc = 'pub extern "C" fn pqpool_reserve_yield_spend_e2e_selftest() -> i32 { if reserve_yield_spend_e2e_selftest() { 1 } else { 0 } }'
    if l.count(anc) != 1: print("FATAL lib anchor x%d" % l.count(anc)); sys.exit(1)
    l = l.replace(anc, anc + '''

/// CRY-6c-2: extract the spend's membership anchor (32 bytes) from a serialized bundle.
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_anchor(bundle: *const u8, bundle_len: usize, out_anchor: *mut u8) -> i32 {
    if bundle.is_null() || out_anchor.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(bundle, bundle_len) };
    match reserve_yield_spend_anchor_bytes(s) {
        Some(a) => { if a.len() != 32 { return -3; } unsafe { core::ptr::copy_nonoverlapping(a.as_ptr(), out_anchor, 32); } 1 }
        None => 0,
    }
}''', 1)
    open(lf, "w").write(l); print("lib.rs: anchor FFI added")
else: print("lib.rs anchor FFI present; skip")

# 3) header
hf = P3 + "pqpool_ffi/include/pqpool_ffi.h"; h = open(hf).read()
if "pqpool_reserve_yield_spend_anchor" not in h:
    h = h.replace("int32_t pqpool_reserve_yield_spend_e2e_selftest(void);",
                  "int32_t pqpool_reserve_yield_spend_e2e_selftest(void);\nint32_t pqpool_reserve_yield_spend_anchor(const uint8_t *bundle, size_t bundle_len, uint8_t *out_anchor);", 1)
    open(hf, "w").write(h); print("header: anchor decl added")
else: print("header anchor present; skip")

# 4) glue .h
gh = CC + "pqpool_transition_glue.h"; g = open(gh).read()
if "reserve_yield_spend_anchor" not in g:
    anc = "bool reserve_yield_spend_pkd(const unsigned char *sk, size_t sk_len, const unsigned char *rho, size_t rho_len, unsigned char *pk_d_out, unsigned char *nf_out);"
    if g.count(anc) != 1: print("FATAL glue.h anchor x%d" % g.count(anc)); sys.exit(1)
    g = g.replace(anc, anc + '''
// CRY-6c-2: extract a spend bundle's membership anchor; compute the coinbase-note-tree root over note_cms.
bool reserve_yield_spend_anchor(const unsigned char *bundle, size_t bundle_len, unsigned char *out_anchor);
bool reserve_yield_note_tree_root(const unsigned char *note_cms, size_t note_cms_len, size_t depth, unsigned char *out_root);''', 1)
    open(gh, "w").write(g); print("glue.h: decls added")
else: print("glue.h present; skip")

# 5) glue .cpp
gc = CC + "pqpool_transition_glue.cpp"; c = open(gc).read()
if "reserve_yield_spend_anchor" not in c:
    anc = "bool reserve_yield_note_cm(uint64_t note_value, uint32_t asset,"
    if c.count(anc) != 1: print("FATAL glue.cpp anchor x%d" % c.count(anc)); sys.exit(1)
    IMPL = '''// CRY-6c-2: spend-anchor extraction + coinbase-note-tree root (anti-fake-note plumbing).
bool reserve_yield_spend_anchor(const unsigned char *bundle, size_t bundle_len, unsigned char *out_anchor) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  return ::pqpool_reserve_yield_spend_anchor(bundle, bundle_len, out_anchor) == 1;
#else
  (void)bundle; (void)bundle_len; (void)out_anchor; return false;
#endif
}
bool reserve_yield_note_tree_root(const unsigned char *note_cms, size_t note_cms_len, size_t depth, unsigned char *out_root) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  return ::pqpool_ry_note_tree_root(note_cms, note_cms_len, depth, out_root, 32) == 1;
#else
  (void)note_cms; (void)note_cms_len; (void)depth; (void)out_root; return false;
#endif
}

'''
    c = c.replace(anc, IMPL + anc, 1); open(gc, "w").write(c); print("glue.cpp: impls added")
else: print("glue.cpp present; skip")
print("DONE")
