# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
# 1) blockchain.h: declare the method after validate_miner_transaction decl.
h = "src/cryptonote_core/blockchain.h"
hs = open(h).read()
if "validate_reserve_yield_coinbase" in hs:
    print("h present; skip")
else:
    hanc = "bool validate_miner_transaction(const block& b, size_t cumulative_block_weight, uint64_t fee, uint64_t& base_reward, uint64_t already_generated_coins, bool &partial_block_reward, uint8_t version, const rct::key &block_fee_sum);"
    if hs.count(hanc) != 1:
        print("FATAL h anchor x%d" % hs.count(hanc)); sys.exit(1)
    hadd = hanc + "\n    // v45 Confidential Reserve-Yield coinbase verifier (no-inflation enforcement; abolish-the-total).\n    bool validate_reserve_yield_coinbase(const block& b, uint64_t block_height, uint64_t& base_reward);"
    hs = hs.replace(hanc, hadd, 1)
    open(h, "w").write(hs); print("h: decl added")

# 2) blockchain.cpp: insert the method def before validate_miner_transaction + the v45 branch.
p = "src/cryptonote_core/blockchain.cpp"
s = open(p).read()
method = open("/tmp/ry_validate_method.cpp").read()
if "Blockchain::validate_reserve_yield_coinbase" in s:
    print("cpp method present; skip")
else:
    manc = "// This function validates the miner transaction reward\nbool Blockchain::validate_miner_transaction("
    if s.count(manc) != 1:
        print("FATAL cpp method anchor x%d" % s.count(manc)); sys.exit(1)
    s = s.replace(manc, method + "\n" + manc, 1)
    print("cpp: method inserted")

# 3) the v45 early-branch at the top of the else-if (block_height >= HARDFORK_V30_HEIGHT) block.
if "validate_reserve_yield_coinbase(b, block_height, base_reward)" in s and "version >= HF_VERSION_RESERVE_YIELD" in s:
    print("cpp branch present; skip")
else:
    banc = "  } else if (block_height >= HARDFORK_V30_HEIGHT) {\n    // Scan b.miner_tx.extra raw bytes for TX_EXTRA_TAG_CONFIDENTIAL_COINBASE."
    if s.count(banc) != 1:
        print("FATAL cpp branch anchor x%d" % s.count(banc)); sys.exit(1)
    badd = ("  } else if (block_height >= HARDFORK_V30_HEIGHT) {\n"
            "    // ── v45 Confidential Reserve-Yield coinbase (abolish-the-total emission) ──\n"
            "    // Replaces the v32 Pedersen cc-verify with the no-inflation reserve-yield proof.\n"
            "    if (version >= HF_VERSION_RESERVE_YIELD) {\n"
            "      partial_block_reward = false;\n"
            "      return validate_reserve_yield_coinbase(b, block_height, base_reward);\n"
            "    }\n"
            "    // Scan b.miner_tx.extra raw bytes for TX_EXTRA_TAG_CONFIDENTIAL_COINBASE.")
    s = s.replace(banc, badd, 1)
    print("cpp: v45 branch inserted")

open(p, "w").write(s)
print("done")
