# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
B="/root/MoneroUSD-clean/monero/src/"
# 1) header: enc_note param
hf=B+"cryptonote_basic/cryptonote_format_utils.h"; h=open(hf).read()
old="  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof);"
if old in h and "enc_note" not in h.split("add_reserve_yield_to_tx_extra")[1][:160]:
    h=h.replace(old, "  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof, const std::string& enc_note = std::string());", 1)
    open(hf,"w").write(h); print("format_utils.h: enc_note param added")
else: print("format_utils.h enc_note present/skip")
# 2) cpp: use the param
cf=B+"cryptonote_basic/cryptonote_format_utils.cpp"; c=open(cf).read()
old2="""  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof)
  {
    tx_extra_reserve_yield rye;
    rye.publics = publics;
    rye.proof = proof;
    rye.enc_note = std::string();"""
new2="""  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof, const std::string& enc_note)
  {
    tx_extra_reserve_yield rye;
    rye.publics = publics;
    rye.proof = proof;
    rye.enc_note = enc_note;"""
if old2 in c:
    c=c.replace(old2,new2,1); open(cf,"w").write(c); print("format_utils.cpp: enc_note wired")
elif "rye.enc_note = enc_note;" in c: print("format_utils.cpp present/skip")
else: print("FATAL format_utils.cpp old block not found")
# 3) construct_miner_tx: PQ-stealth producer (env ML-KEM pubkey -> produce_v2, fallback placeholder)
tf=B+"cryptonote_core/cryptonote_tx_utils.cpp"; t=open(tf).read()
old3='''        const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;
        std::vector<uint8_t> ry_pub, ry_proof;
        CHECK_AND_ASSERT_MES(cryptonote::pqpool_transition::reserve_yield_produce(ry_i, reinterpret_cast<const unsigned char*>(&miner_address.m_spend_public_key), 32, ry_pub, ry_proof), false, "v45 coinbase: reserve_yield_produce failed");
        CHECK_AND_ASSERT_MES(add_reserve_yield_to_tx_extra(tx.extra, std::string(ry_pub.begin(), ry_pub.end()), std::string(ry_proof.begin(), ry_proof.end())), false, "v45 coinbase: add_reserve_yield_to_tx_extra failed");'''
new3='''        const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;
        std::vector<uint8_t> ry_pub, ry_proof; std::string ry_enc;
        // CRY-6 PQ-stealth (testnet=production): if the miner ML-KEM view pubkey is configured, the note's
        // spend secret derives from a REAL ML-KEM shared secret (encapsulate); the ciphertext rides in
        // enc_note so only the miner (decapsulate) recovers it. Else fall back to the placeholder producer.
        static const std::vector<uint8_t> s_mlkem_pub = [](){
          std::vector<uint8_t> v; const char* hx = std::getenv("RESERVE_YIELD_MINER_MLKEM_PUB_HEX");
          if (hx) { std::string hs(hx); if (hs.size() % 2 == 0) { auto hv=[](char ch)->int{ if(ch>='0'&&ch<='9')return ch-'0'; if(ch>='a'&&ch<='f')return ch-'a'+10; if(ch>='A'&&ch<='F')return ch-'A'+10; return -1; }; for (size_t kk=0;kk+1<hs.size();kk+=2){ int hi=hv(hs[kk]),lo=hv(hs[kk+1]); if(hi<0||lo<0){v.clear();break;} v.push_back((uint8_t)((hi<<4)|lo)); } } }
          return v;
        }();
        if (!s_mlkem_pub.empty()) {
          std::vector<uint8_t> ct;
          CHECK_AND_ASSERT_MES(cryptonote::pqpool_transition::reserve_yield_produce_v2(s_mlkem_pub.data(), s_mlkem_pub.size(), ry_i, ct, ry_pub, ry_proof), false, "v45 coinbase: reserve_yield_produce_v2 (PQ-stealth) failed");
          ry_enc.assign(ct.begin(), ct.end());
        } else {
          CHECK_AND_ASSERT_MES(cryptonote::pqpool_transition::reserve_yield_produce(ry_i, reinterpret_cast<const unsigned char*>(&miner_address.m_spend_public_key), 32, ry_pub, ry_proof), false, "v45 coinbase: reserve_yield_produce failed");
        }
        CHECK_AND_ASSERT_MES(add_reserve_yield_to_tx_extra(tx.extra, std::string(ry_pub.begin(), ry_pub.end()), std::string(ry_proof.begin(), ry_proof.end()), ry_enc), false, "v45 coinbase: add_reserve_yield_to_tx_extra failed");'''
if old3 in t:
    t=t.replace(old3,new3,1)
    if "#include <cstdlib>" not in t: t=t.replace('#include "cryptonote_tx_utils.h"', '#include <cstdlib>\n#include "cryptonote_tx_utils.h"', 1)
    open(tf,"w").write(t); print("cryptonote_tx_utils.cpp: PQ-stealth producer wired")
elif "reserve_yield_produce_v2" in t: print("tx_utils present/skip")
else: print("FATAL tx_utils old block not found")
print("DONE")
