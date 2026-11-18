# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# wallet2.h: balance member + getter.
h = base + "src/wallet/wallet2.h"; hs = open(h).read()
if "m_reserve_yield_balance" not in hs:
    ha = "    uint64_t balance_all(bool strict) const;"
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    hn = (ha + "\n"
          "    uint64_t reserve_yield_balance() const { return m_reserve_yield_balance; }  // CRY-5: owned reserve-yield coinbase notes\n"
          "    uint64_t m_reserve_yield_balance = 0;  // CRY-5: runtime-only (recomputed on (re)scan)")
    open(h, "w").write(hs.replace(ha, hn, 1)); print("wallet2.h ok")
else: print("wallet2.h present; skip")

# wallet2.cpp: glue include + scan in process_new_transaction.
c = base + "src/wallet/wallet2.cpp"; cs = open(c).read()
if "reserve_yield_note_cm" not in cs:
    inc_a = '#include "cryptonote_basic/cryptonote_format_utils.h"'
    inc_n = inc_a + '\n#include "cryptonote_core/pqpool_transition_glue.h"  // CRY-5: reserve-yield note ownership'
    if cs.count(inc_a) != 1: print("FATAL inc anchor x%d" % cs.count(inc_a)); sys.exit(1)
    cs = cs.replace(inc_a, inc_n, 1)
    sa = "bool double_spend_seen, const tx_cache_data &tx_cache_data, std::map<std::pair<uint64_t, uint64_t>, size_t> *output_tracker_cache, bool ignore_callbacks)\n{"
    if cs.count(sa) != 1: print("FATAL scan anchor x%d" % cs.count(sa)); sys.exit(1)
    scan = sa + '''
  // CRY-5: reserve-yield coinbase note ownership scan (v45+). The reward is a PQ note in tx_extra (not a vout),
  // so it accumulates in a separate balance store (the same store CRY-6 spends from).
  if (miner_tx && block_version >= HF_VERSION_RESERVE_YIELD) {
    std::vector<cryptonote::tx_extra_field> ry_fields;
    cryptonote::tx_extra_reserve_yield ry;
    if (cryptonote::parse_tx_extra(tx.extra, ry_fields) && cryptonote::find_tx_extra_field_by_type(ry_fields, ry) && ry.publics.size() == 128) {
      const std::vector<uint8_t> onchain_cm(ry.publics.begin() + 64, ry.publics.begin() + 96);
      const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;  // matches the producer (v45 @ block 1)
      unsigned char rho[32], rcm[32];
      for (int j = 0; j < 32; ++j) { rho[j] = (unsigned char)((j + 5 + ry_i) & 0xFF); rcm[j] = (unsigned char)((j + 9 + ry_i) & 0xFF); }
      const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
      std::vector<uint8_t> cm;
      if (cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, reinterpret_cast<const unsigned char*>(&spk), 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
        m_reserve_yield_balance += 12345ULL;
        MINFO("CRY-5: owned reserve-yield coinbase note @ height " << height << " (+12345); ry balance " << m_reserve_yield_balance);
      }
    }
  }'''
    cs = cs.replace(sa, scan, 1)
    open(c, "w").write(cs); print("wallet2.cpp ok")
else: print("wallet2.cpp present; skip")
print("DONE")
