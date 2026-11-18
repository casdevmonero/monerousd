# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
p = "external/Plonky3/pqpool/src/circuit.rs"
s = open(p).read()

# A) prove_zk_bytes: take note params + un-wrap the test-note call.
a_old = ("pub fn reserve_yield_prove_zk_bytes(\n"
         "    k: usize, modulus: u64, b: u64, x: u64,\n"
         "    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],\n"
         "    note_value: u64, y_override: Option<u64>,\n"
         ") -> (Vec<u8>, Vec<F>) {\n"
         "    let (trace, source_trace, cm) =\n"
         "        { let (rya, ryp, ryh, ryc) = ry_test_note(); reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, rya, ryp, ryh, ryc) };")
a_new = ("pub fn reserve_yield_prove_zk_bytes(\n"
         "    k: usize, modulus: u64, b: u64, x: u64,\n"
         "    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],\n"
         "    note_value: u64, y_override: Option<u64>,\n"
         "    asset: u32, pk_d: [F; DIGEST], rho: [F; DIGEST], rcm: [F; DIGEST],\n"
         ") -> (Vec<u8>, Vec<F>) {\n"
         "    let (trace, source_trace, cm) =\n"
         "        reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, asset, pk_d, rho, rcm);")
if "asset: u32, pk_d: [F; DIGEST], rho: [F; DIGEST], rcm: [F; DIGEST],\n) -> (Vec<u8>, Vec<F>) {" in s:
    print("A present; skip")
elif s.count(a_old) == 1:
    s = s.replace(a_old, a_new, 1); print("A: prove_zk_bytes note-aware ok")
else:
    print("FATAL A anchor x%d" % s.count(a_old)); sys.exit(1)

# B) prove_zk_raw: its call to prove_zk_bytes now passes the test note (extern-C still works).
b_old = ("    let (proof, publics) = reserve_yield_prove_zk_bytes(\n"
         "        k, modulus, b, x, to_rcm(rcmx_bytes), to_rcm(rcmy_bytes), to_rcm(rcmb_bytes), note_value, None);")
b_new = ("    let (rya, ryp, ryh, ryc) = ry_test_note();\n"
         "    let (proof, publics) = reserve_yield_prove_zk_bytes(\n"
         "        k, modulus, b, x, to_rcm(rcmx_bytes), to_rcm(rcmy_bytes), to_rcm(rcmb_bytes), note_value, None, rya, ryp, ryh, ryc);")
if "let (rya, ryp, ryh, ryc) = ry_test_note();\n    let (proof, publics) = reserve_yield_prove_zk_bytes(" in s:
    print("B present; skip")
elif s.count(b_old) == 1:
    s = s.replace(b_old, b_new, 1); print("B: prove_zk_raw passes test note ok")
else:
    print("FATAL B anchor x%d" % s.count(b_old)); sys.exit(1)

open(p, "w").write(s)
