# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
p = "src/cryptonote_core/blockchain.cpp"
s = open(p).read()
if "_ry_gate" in s:
    print("present; skip"); sys.exit(0)
anc = 'MGINFO("pqpool ReserveYield confidential coinbase verifier: linked=" << cryptonote::pqpool_transition::linked() << " selftest=" << _ry_ok);'
n = s.count(anc)
if n != 1:
    print("FATAL anchor x%d" % n); sys.exit(1)
add = anc + """
    // CRY-8 adversarial gate: the wired no-inflation verifier MUST reject over-reward forgeries.
    const bool _ry_gate = cryptonote::pqpool_transition::reserve_yield_adversarial_gate(63, 0x0001000000000000ULL);
    MGINFO("pqpool ReserveYield CRY-8 adversarial gate (over-reward MUST reject): " << (_ry_gate ? "PASS" : "FAIL"));"""
s = s.replace(anc, add, 1)
open(p, "w").write(s)
print("CRY-8 gate wired into daemon selftest")
