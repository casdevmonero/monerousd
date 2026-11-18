# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
CC = "/root/MoneroUSD-clean/monero/src/cryptonote_core/"

# 1) blockchain.h: cmt-tree members (deque of roots + concatenated note_cms)
bh = CC + "blockchain.h"; h = open(bh).read()
if "m_reserve_yield_cmt_roots" not in h:
    anc = "    crypto::hash m_reserve_yield_ns_root{};  // CRY-6: IMT nullifier-set root (hidden-nf double-spend guard), threaded per block"
    if h.count(anc) != 1: print("FATAL bh anchor x%d" % h.count(anc)); sys.exit(1)
    h = h.replace(anc, anc + '''
    std::string m_reserve_yield_cmt_notes;               // CRY-6c-2: concatenated v45 coinbase note_cms (cmt-tree leaves)
    std::deque<crypto::hash> m_reserve_yield_cmt_roots;  // CRY-6c-2: recent valid coinbase-note-tree roots (anchor window, anti-fake-note)''', 1)
    open(bh, "w").write(h); print("blockchain.h: cmt members added")
    # ensure <deque> include
    if "#include <deque>" not in h:
        h2 = open(bh).read().replace("#include <unordered_map>", "#include <unordered_map>\n#include <deque>", 1)
        if "#include <deque>" in h2: open(bh, "w").write(h2); print("blockchain.h: <deque> added")
else: print("bh cmt members present; skip")

# 2) blockchain.cpp: stateful spend check (fetch loop) + coinbase note_cm append (after loop)
bc = CC + "blockchain.cpp"; s = open(bc).read()
if "reserve-yield spend ns_root_old stale" in s:
    print("bc stateful checks present; skip"); 
else:
    # (a) stateful spend check in the fetch loop, right after check_tx_inputs timing
    anc_a = "    TIME_MEASURE_FINISH(cc);\n    t_checktx += cc;\n    fee_summary += fee;"
    if s.count(anc_a) != 1: print("FATAL bc anchor_a x%d" % s.count(anc_a)); sys.exit(1)
    SPEND = '''    TIME_MEASURE_FINISH(cc);
    t_checktx += cc;

    // CRY-6c-2 + CRY-6: stateful gate for a reserve-yield SPEND tx (0x2F) at block-add. Re-verifies the
    // bundle, then enforces (a) the membership ANCHOR is a known coinbase-note-tree root (anti-fake-note:
    // a spend can only reference a note the chain actually minted) and (b) the IMT ns_root_old == the
    // current ns_root, advancing it (anti-replay / double-spend; a re-spend has a stale old root). Both
    // are the daemon translation of the CRY6_E2E_OK pure-Rust gate. Testnet depths (4); production: 32.
    if (m_hardfork && m_hardfork->get_current_version() >= HF_VERSION_RESERVE_YIELD)
    {
      std::vector<tx_extra_field> _ryf;
      tx_extra_reserve_yield_spend _rys;
      if (parse_tx_extra(tx.extra, _ryf) && find_tx_extra_field_by_type(_ryf, _rys) && !_rys.bundle.empty())
      {
        const unsigned char* _bp = reinterpret_cast<const unsigned char*>(_rys.bundle.data());
        if (m_reserve_yield_ns_root == crypto::null_hash)
          cryptonote::pqpool_transition::reserve_yield_imt_empty_root(4, reinterpret_cast<unsigned char*>(m_reserve_yield_ns_root.data));
        unsigned char _anchor[32], _ns_old[32], _ns_new[32];
        bool _ok = cryptonote::pqpool_transition::reserve_yield_spend_verify(_bp, _rys.bundle.size())
                && cryptonote::pqpool_transition::reserve_yield_spend_anchor(_bp, _rys.bundle.size(), _anchor)
                && cryptonote::pqpool_transition::reserve_yield_spend_roots(_bp, _rys.bundle.size(), _ns_old, _ns_new);
        if (!_ok)
        {
          MERROR_VER("Block " << id << " REJECTED: reserve-yield spend bundle invalid (block-add)");
          bvc.m_verifivation_failed = true; return_txs_to_pool(); return false;
        }
        crypto::hash _a; std::memcpy(_a.data, _anchor, 32);
        bool _anchor_known = false;
        for (const crypto::hash& _r : m_reserve_yield_cmt_roots) { if (_r == _a) { _anchor_known = true; break; } }
        if (!_anchor_known)
        {
          MERROR_VER("Block " << id << " REJECTED: reserve-yield spend anchor is not a known coinbase-note-tree root (fake note)");
          bvc.m_verifivation_failed = true; return_txs_to_pool(); return false;
        }
        if (std::memcmp(_ns_old, m_reserve_yield_ns_root.data, 32) != 0)
        {
          MERROR_VER("Block " << id << " REJECTED: reserve-yield spend ns_root_old stale (replay / double-spend)");
          bvc.m_verifivation_failed = true; return_txs_to_pool(); return false;
        }
        std::memcpy(m_reserve_yield_ns_root.data, _ns_new, 32);
        MINFO("CRY-6: reserve-yield spend accepted (anchor known, nf threaded) for tx " << tx_id);
      }
    }
    fee_summary += fee;'''
    s = s.replace(anc_a, SPEND, 1)

    # (b) coinbase note_cm append after the fetch loop closes
    anc_b = "    cumulative_block_weight += tx_weight;\n  }\n\n  // ── Model B (Build 1, increment 1): GHOSTDAG ledger-merge consumer"
    if s.count(anc_b) != 1: print("FATAL bc anchor_b x%d" % s.count(anc_b)); sys.exit(1)
    APPEND = '''    cumulative_block_weight += tx_weight;
  }

  // CRY-6c-2: append THIS v45 block's coinbase note_cm to the coinbase-note tree and publish the new root
  // into the valid-anchor window. Done AFTER the spend loop so a spend in block N can only reference a note
  // minted in a block < N. note_cm = coinbase reserve_yield publics[64:96] (= cm_S_new|cm_S_old|note_cm|cm_b).
  if (m_hardfork && m_hardfork->get_current_version() >= HF_VERSION_RESERVE_YIELD)
  {
    std::vector<tx_extra_field> _cf;
    tx_extra_reserve_yield _cry;
    if (parse_tx_extra(bl.miner_tx.extra, _cf) && find_tx_extra_field_by_type(_cf, _cry) && _cry.publics.size() == 128)
    {
      m_reserve_yield_cmt_notes.append(reinterpret_cast<const char*>(_cry.publics.data()) + 64, 32);
      const size_t _count = m_reserve_yield_cmt_notes.size() / 32;
      if (_count <= (size_t(1) << 4))  // testnet cmt-tree depth 4 (<=16 notes); production: 32
      {
        unsigned char _root[32];
        if (cryptonote::pqpool_transition::reserve_yield_note_tree_root(
              reinterpret_cast<const unsigned char*>(m_reserve_yield_cmt_notes.data()), m_reserve_yield_cmt_notes.size(), 4, _root))
        {
          crypto::hash _rh; std::memcpy(_rh.data, _root, 32);
          m_reserve_yield_cmt_roots.push_back(_rh);
          while (m_reserve_yield_cmt_roots.size() > 10000) m_reserve_yield_cmt_roots.pop_front();  // anchor window
          MINFO("CRY-6c-2: coinbase note appended; cmt-tree now " << _count << " note(s), root published");
        }
      }
    }
  }

  // ── Model B (Build 1, increment 1): GHOSTDAG ledger-merge consumer'''
    s = s.replace(anc_b, APPEND, 1)
    open(bc, "w").write(s); print("blockchain.cpp: stateful spend gate + coinbase append added")
print("DONE")
