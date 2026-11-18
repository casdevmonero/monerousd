# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
p = "external/Plonky3/pqpool/src/circuit.rs"
s = open(p).read()
orig = s

# Edit 3 (helper) — add ry_test_note() before the trace builder.
if "fn ry_test_note()" not in s:
    anc = "fn reserve_yield_traces("
    if s.count(anc) != 1:
        print("FATAL traces-def anchor x%d" % s.count(anc)); sys.exit(1)
    helper = ("fn ry_test_note() -> (u32, [F; DIGEST], [F; DIGEST], [F; DIGEST]) {\n"
              "    let pk_d: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(101 + i as u64));\n"
              "    let rho: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(201 + i as u64));\n"
              "    let rcm: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(301 + i as u64));\n"
              "    (7u32, pk_d, rho, rcm)\n}\n\nfn reserve_yield_traces(")
    s = s.replace(anc, helper, 1)

# Edit 1 (signature) — add the miner note params.
sig_old = "    note_value: u64, y_override: Option<u64>,\n) -> (RowMajorMatrix<F>, RowMajorMatrix<F>, Vec<F>) {"
sig_new = "    note_value: u64, y_override: Option<u64>,\n    asset: u32, pk_d: [F; DIGEST], rho: [F; DIGEST], rcm: [F; DIGEST],\n) -> (RowMajorMatrix<F>, RowMajorMatrix<F>, Vec<F>) {"
if sig_new not in s:
    if s.count(sig_old) != 1:
        print("FATAL sig anchor x%d" % s.count(sig_old)); sys.exit(1)
    s = s.replace(sig_old, sig_new, 1)

# Edit 2 (body) — drop the hardcoded note fields (now params). Target the reserve_yield block ONLY,
# via the unique `preimage_b = v64_commit_preimage(b, &rcmb)` context (another circuit also has `let asset=7u32`).
body_old = ("    let preimage_b = v64_commit_preimage(b, &rcmb);\n"
            "    let asset = 7u32;\n"
            "    let pk_d: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(101 + i as u64));\n"
            "    let rho: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(201 + i as u64));\n"
            "    let rcm: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(301 + i as u64));\n"
            "    let preimage_note = note_commit_preimage(note_value, asset, &pk_d, &rho, &rcm);")
body_new = ("    let preimage_b = v64_commit_preimage(b, &rcmb);\n"
            "    let preimage_note = note_commit_preimage(note_value, asset, &pk_d, &rho, &rcm);")
if "let asset = 7u32;\n    let pk_d: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(101 + i as u64));\n    let rho: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(201 + i as u64));\n    let rcm: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(301 + i as u64));\n    let preimage_note = note_commit_preimage(note_value" in s:
    if s.count(body_old) != 1:
        print("FATAL body anchor x%d" % s.count(body_old)); sys.exit(1)
    s = s.replace(body_old, body_new, 1)

# Edit 4 (callers) — pass the test note (production producer overrides via the FFI in sub-step 1b).
call_old = "reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override)"
call_new = "{ let (rya, ryp, ryh, ryc) = ry_test_note(); reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, rya, ryp, ryh, ryc) }"
nc = s.count(call_old)
if nc:
    s = s.replace(call_old, call_new)
print("calls rewritten:", nc, "| changed:", s != orig)
open(p, "w").write(s)
