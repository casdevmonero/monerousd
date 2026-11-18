# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()
if "prove_test_reserve_yield_spend_bytes" not in s:
    anc = "/// CRY-6e round-trip gate: prove -> serialize"
    if s.count(anc) != 1: print("FATAL circuit anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''/// CRY-6e: produce a fixed reserve-yield spend bundle's serialized bytes (for the C++ ABI smoke).
pub fn prove_test_reserve_yield_spend_bytes() -> Vec<u8> {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sp = (1_000_000u64, 5u32, mk(6), mk(7), mk(8), vec![mk(2), mk(3), mk(4), mk(5)], 0b1010usize, 999_000u64, 5u32, mk(9), mk(10), mk(11), 1000u64, 42u64, FullSpendTamper::None);
    prove_reserve_yield_spend_bundle(sp, 4).serialize_bundle()
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("circuit prove_test added")
else: print("circuit prove_test present; skip")

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_reserve_yield_spend_prove_test" not in fs:
    fs = fs.replace("ReserveYieldSpendBundle,", "ReserveYieldSpendBundle, prove_test_reserve_yield_spend_bytes,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_reserve_yield_spend_verify('
    fn2 = '#[no_mangle]\npub extern "C" fn pqpool_reserve_yield_spend_prove_test(out: *mut u8, out_cap: usize, out_len: *mut usize) -> i32 {\n    if out.is_null() || out_len.is_null() { return -1; }\n    let bytes = prove_test_reserve_yield_spend_bytes();\n    if bytes.len() > out_cap { return -2; }\n    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()); *out_len = bytes.len(); }\n    1\n}\n\n' + anc2
    if fs.count(anc2) != 1: print("FATAL ffi anchor x%d" % fs.count(anc2)); sys.exit(1)
    fs = fs.replace(anc2, fn2, 1); open(f, "w").write(fs); print("ffi prove-test added")
else: print("ffi prove-test present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_reserve_yield_spend_prove_test" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_reserve_yield_spend_verify(const uint8_t* bundle, size_t bundle_len);",
        "int32_t pqpool_reserve_yield_spend_verify(const uint8_t* bundle, size_t bundle_len);\nint32_t pqpool_reserve_yield_spend_prove_test(uint8_t* out, size_t out_cap, size_t* out_len);", 1)); print("ffi.h prove-test added")

gc = base + "src/cryptonote_core/pqpool_transition_glue.cpp"; gs = open(gc).read()
if "reserve_yield_spend_verify" not in gs:
    ga = "bool reserve_yield_note_cm("
    fn3 = '''// CRY-6e: the daemon reserve-yield spend verify — routes the serialized spend bundle to the FFI
// verify-from-bytes. The daemon additionally checks the cmt anchor is a known coinbase-note-tree root and
// threads the IMT ns_root (blockchain.cpp, 6e-daemon).
bool reserve_yield_spend_verify(const unsigned char *bundle, size_t bundle_len) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  return ::pqpool_reserve_yield_spend_verify(bundle, bundle_len) == 1;
#else
  (void)bundle; (void)bundle_len; return false;
#endif
}

'''
    if gs.count(ga) < 1: print("FATAL glue anchor"); sys.exit(1)
    gs = gs.replace(ga, fn3 + ga, 1); open(gc, "w").write(gs); print("glue.cpp verify bridge added")
gh = base + "src/cryptonote_core/pqpool_transition_glue.h"; ghs = open(gh).read()
if "reserve_yield_spend_verify" not in ghs:
    gha = "bool reserve_yield_note_cm(uint64_t note_value"
    open(gh, "w").write(ghs.replace(gha, "// CRY-6e: verify a serialized reserve-yield spend bundle.\nbool reserve_yield_spend_verify(const unsigned char *bundle, size_t bundle_len);\n" + gha, 1)); print("glue.h decl added")
print("DONE")
