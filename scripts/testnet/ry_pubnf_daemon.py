# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
CC = "/root/MoneroUSD-clean/monero/src/cryptonote_core/"

# 1) blockchain.h: nf-set member
bh = CC + "blockchain.h"; h = open(bh).read()
if "m_reserve_yield_nf_set" not in h:
    anc = "    std::deque<crypto::hash> m_reserve_yield_cmt_roots;  // CRY-6c-2: recent valid coinbase-note-tree roots (anchor window, anti-fake-note)"
    if h.count(anc) != 1: print("FATAL bh anchor x%d" % h.count(anc)); sys.exit(1)
    h = h.replace(anc, anc + "\n    std::unordered_set<std::string> m_reserve_yield_nf_set;  // CRY-6 public-nf: spent nullifiers (double-spend guard, enables multi-spend)", 1)
    if "#include <unordered_set>" not in h:
        h = h.replace("#include <deque>", "#include <deque>\n#include <unordered_set>", 1)
    open(bh, "w").write(h); print("blockchain.h: nf-set member added")
else: print("bh nf-set present; skip")

# 2) blockchain.cpp
bc = CC + "blockchain.cpp"; s = open(bc).read()
# 2a) check_tx_inputs verify -> verify_v2
v1 = "if (!cryptonote::pqpool_transition::reserve_yield_spend_verify(\n              reinterpret_cast<const unsigned char*>(rys.bundle.data()), rys.bundle.size()))"
if v1 in s:
    s = s.replace(v1, "if (!cryptonote::pqpool_transition::reserve_yield_spend_verify_v2(\n              reinterpret_cast<const unsigned char*>(rys.bundle.data()), rys.bundle.size()))", 1)
    print("check_tx_inputs: verify -> verify_v2")
else: print("WARN: check_tx_inputs verify line not found (maybe already v2)")

# 2b) block-add: replace the inner ns-root-threading block with the nf-set block
old_inner = '''        const unsigned char* _bp = reinterpret_cast<const unsigned char*>(_rys.bundle.data());
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
        MINFO("CRY-6: reserve-yield spend accepted (anchor known, nf threaded) for tx " << tx_id);'''
new_inner = '''        const unsigned char* _bp = reinterpret_cast<const unsigned char*>(_rys.bundle.data());
        unsigned char _anchor[32], _nf[32];
        bool _ok = cryptonote::pqpool_transition::reserve_yield_spend_verify_v2(_bp, _rys.bundle.size())
                && cryptonote::pqpool_transition::reserve_yield_spend_anchor(_bp, _rys.bundle.size(), _anchor)
                && cryptonote::pqpool_transition::reserve_yield_spend_nullifier(_bp, _rys.bundle.size(), _nf);
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
        // CRY-6 public-nf: the nullifier is PUBLIC; a SET of spent nullifiers prevents double-spend
        // (Zcash/Monero model) while allowing unlimited multi-spend (distinct notes -> distinct nullifiers).
        std::string _nfkey(reinterpret_cast<const char*>(_nf), 32);
        if (m_reserve_yield_nf_set.count(_nfkey))
        {
          MERROR_VER("Block " << id << " REJECTED: reserve-yield nullifier already spent (double-spend)");
          bvc.m_verifivation_failed = true; return_txs_to_pool(); return false;
        }
        m_reserve_yield_nf_set.insert(_nfkey);
        MINFO("CRY-6: reserve-yield spend accepted (anchor known, nullifier new) for tx " << tx_id);'''
if old_inner in s:
    s = s.replace(old_inner, new_inner, 1); print("block-add: ns-root threading -> public-nf set")
else: print("FATAL: block-add inner block not found"); sys.exit(1)
# update the gate comment
s = s.replace("current ns_root, advancing it (anti-replay / double-spend; a re-spend has a stale old root). Both\n    // are the daemon translation of the CRY6_E2E_OK pure-Rust gate. Testnet depths (4); production: 32.",
              "nullifier is NOT already in the spent-set (anti-replay / double-spend), inserting it. Public unlinkable\n    // nullifiers (Zcash/Monero model) -> multi-spend works. Testnet in-memory set; production: DB-backed.", 1)
open(bc, "w").write(s); print("blockchain.cpp: updated")
print("DONE")
