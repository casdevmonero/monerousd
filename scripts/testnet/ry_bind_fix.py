# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys

# 1) PRODUCER: v45 coinbase Monero output commits 0 (reward is the PQ note note_cm).
TU = "src/cryptonote_core/cryptonote_tx_utils.cpp"
t = open(TU).read()
old_p = "const uint64_t miner_output_amount = block_reward;"
new_p = "const uint64_t miner_output_amount = (hard_fork_version >= HF_VERSION_RESERVE_YIELD) ? 0 : block_reward; // v45: spendable reward is the PQ note (note_cm); the Monero output commits 0"
if new_p in t:
    print("producer present; skip")
elif t.count(old_p) == 1:
    open(TU, "w").write(t.replace(old_p, new_p, 1)); print("producer: miner_output_amount=0 for v45 ok")
else:
    print("FATAL producer anchor x%d" % t.count(old_p)); sys.exit(1)

# 2) VERIFIER: replace the v45 early-return with a base_reward=0 override (cc-verify then binds vout[0]==0).
BC = "src/cryptonote_core/blockchain.cpp"
s = open(BC).read()
old_v = ("    // ── v45 Confidential Reserve-Yield coinbase (abolish-the-total emission) ──\n"
         "    // Replaces the v32 Pedersen cc-verify with the no-inflation reserve-yield proof.\n"
         "    if (version >= HF_VERSION_RESERVE_YIELD) {\n"
         "      partial_block_reward = false;\n"
         "      return validate_reserve_yield_coinbase(b, block_height, base_reward);\n"
         "    }\n")
new_v = ("    // ── v45: zero the DAG emission so the cc-verify binds the coinbase output to 0 ──\n"
         "    // Spendable reward is the reserve-yield PQ note (note_cm), validated after the cc-verify.\n"
         "    // The v32 amount-equality (expected_reward = minted(0)+fee) then enforces vout[0]==0, so\n"
         "    // an over-reward Monero output is rejected by the existing, proven equality proof.\n"
         "    if (version >= HF_VERSION_RESERVE_YIELD) base_reward = 0;\n")
if "zero the DAG emission so the cc-verify binds" in s:
    print("verifier branch present; skip")
elif s.count(old_v) == 1:
    s = s.replace(old_v, new_v, 1); print("verifier: early-return -> base_reward=0 ok")
else:
    print("FATAL verifier branch anchor x%d" % s.count(old_v)); sys.exit(1)

# 3) VERIFIER: add the RY attestation check after the cc-verify, before the else-if return true.
old_r = ("    }\n"
         "    return true;\n"
         "  }\n"
         "\n"
         "  return true;\n"
         "}\n")
new_r = ("    }\n"
         "    // ── v45: validate the reserve-yield attestation (reward note_cm = confidential draw r, cm_S chain) ──\n"
         "    if (version >= HF_VERSION_RESERVE_YIELD) {\n"
         "      partial_block_reward = false;\n"
         "      if (!validate_reserve_yield_coinbase(b, block_height, base_reward)) return false;\n"
         "    }\n"
         "    return true;\n"
         "  }\n"
         "\n"
         "  return true;\n"
         "}\n")
if "validate the reserve-yield attestation (reward note_cm" in s:
    print("RY check present; skip")
elif s.count(old_r) == 1:
    s = s.replace(old_r, new_r, 1); print("verifier: RY check after cc-verify ok")
else:
    print("FATAL RY-check anchor x%d" % s.count(old_r)); sys.exit(1)

open(BC, "w").write(s)
print("ALL DONE")
