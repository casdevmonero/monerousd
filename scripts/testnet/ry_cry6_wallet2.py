# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
W = "/root/MoneroUSD-clean/monero/src/wallet/"
# wallet2.h: method decl
wh = W + "wallet2.h"; h = open(wh).read()
if "reserve_yield_build_spend_bundle" not in h:
    anc = "    uint64_t reserve_yield_balance() const { return m_reserve_yield_balance; }  // CRY-5: owned reserve-yield coinbase notes"
    if h.count(anc) != 1: print("FATAL wh anchor x%d" % h.count(anc)); sys.exit(1)
    h = h.replace(anc, anc + '''
    // CRY-6: build a spend bundle for an owned reserve-yield coinbase note (reconstructs sk/rho/rcm from
    // its block height exactly as the CRY-5 scan derived them). `cmt_notes` = concatenated v45 coinbase
    // note_cms (the daemon's cmt-tree leaves, block order); `leaf_index` = this note's position. The
    // bundle's anchor == the daemon cmt-tree root, ns_root_old == empty IMT root. Returns false on bad input.
    bool reserve_yield_build_spend_bundle(uint64_t note_height, size_t leaf_index, const std::vector<uint8_t>& cmt_notes, uint64_t fee, std::string& bundle_out) const;''', 1)
    open(wh, "w").write(h); print("wallet2.h: method decl added")
else: print("wallet2.h decl present; skip")

# wallet2.cpp: method impl + include glue if needed
wc = W + "wallet2.cpp"; c = open(wc).read()
if "wallet2::reserve_yield_build_spend_bundle" not in c:
    anc = "//----------------------------------------------------------------------------------------------------\nvoid wallet2::process_new_transaction("
    if c.count(anc) != 1: print("FATAL wc anchor x%d" % c.count(anc)); sys.exit(1)
    IMPL = '''//----------------------------------------------------------------------------------------------------
bool wallet2::reserve_yield_build_spend_bundle(uint64_t note_height, size_t leaf_index, const std::vector<uint8_t>& cmt_notes, uint64_t fee, std::string& bundle_out) const
{
  // CRY-6: reconstruct the owned coinbase note exactly as the CRY-5 scan derived it (sk = spend public
  // key, rho/rcm deterministic from height, value 12345, asset 0), then build the spend bundle via the
  // prove bridge. The membership anchor equals the daemon cmt-tree root over `cmt_notes`; ns_root_old is
  // the genesis empty IMT root. The 2.8MB bundle is delivered by self-inclusion in the miner's own block
  // (it exceeds the mempool tx_extra cap) or, in production, after recursion-compression.
  if (note_height < 1 || fee >= 12345ULL || cmt_notes.empty() || (cmt_notes.size() % 32) != 0) return false;
  if (leaf_index >= cmt_notes.size() / 32) return false;
  const uint64_t ry_i = note_height - 1;
  unsigned char rho[32], rcm[32];
  for (int j = 0; j < 32; ++j) { rho[j] = (unsigned char)((j + 5 + ry_i) & 0xFF); rcm[j] = (unsigned char)((j + 9 + ry_i) & 0xFF); }
  const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
  std::vector<uint8_t> bundle;
  if (!cryptonote::pqpool_transition::reserve_yield_coinbase_spend_prove(
        reinterpret_cast<const unsigned char*>(&spk), rho, rcm, 12345ULL, 0u,
        cmt_notes.data(), cmt_notes.size(), leaf_index, /*cmt_depth*/4,
        reinterpret_cast<const unsigned char*>(&spk), fee, /*chain_id*/7ULL, /*imt_depth*/4, bundle))
    return false;
  bundle_out.assign(reinterpret_cast<const char*>(bundle.data()), bundle.size());
  return true;
}
//----------------------------------------------------------------------------------------------------
void wallet2::process_new_transaction('''
    c = c.replace(anc, IMPL, 1); open(wc, "w").write(c); print("wallet2.cpp: method impl added")
else: print("wallet2.cpp impl present; skip")
print("DONE")
