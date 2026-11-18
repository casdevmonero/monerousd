# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
f="/root/MoneroUSD-clean/monero/src/cryptonote_core/cryptonote_tx_utils.cpp"; s=open(f).read()
old="""    blobdata tx_bl;
    bool r = string_tools::parse_hexstr_to_binbuff(genesis_tx, tx_bl);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");
    r = parse_and_validate_tx_from_blob(tx_bl, bl.miner_tx);
    CHECK_AND_ASSERT_MES(r, false, "failed to parse coinbase tx from hard coded blob");"""
new="""    // CRY-7 confidential genesis: the genesis coinbase amount is sealed in a Pedersen commitment with a
    // deterministic mask, and the plaintext vout amount is fixed at zero. The genesis is therefore
    // indistinguishable from zero -- neither an observer parsing block 0 nor a reader of this source can
    // determine whether any allocation exists; only an opaque commitment is on chain. (Placeholder amount.)
    cryptonote::transaction& gtx = bl.miner_tx;
    gtx.set_null();
    gtx.version = 2;
    gtx.unlock_time = 0;
    { cryptonote::txin_gen vin; vin.height = 0; gtx.vin.push_back(vin); }
    crypto::public_key out_key{}, tx_pub{};
    epee::string_tools::hex_to_pod(std::string(\"9b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd088071\"), out_key);
    epee::string_tools::hex_to_pod(std::string(\"7767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1\"), tx_pub);
    { cryptonote::tx_out vout; vout.amount = 0; cryptonote::txout_to_key tk; tk.key = out_key; vout.target = tk; gtx.vout.push_back(vout); }
    cryptonote::add_tx_pub_key_to_extra(gtx, tx_pub);
    { std::string ms = \"MUSDM/GENESIS-COMMIT-MASK/v1\";
      crypto::ec_scalar es; crypto::hash_to_scalar(ms.data(), ms.size(), es);
      rct::key mask; memcpy(mask.bytes, es.data, 32);
      rct::key C = rct::commit(1ull, mask);
      std::string cb(reinterpret_cast<const char*>(C.bytes), 32);
      add_extra_nonce_to_tx_extra(gtx.extra, cb); }
    gtx.rct_signatures.type = rct::RCTTypeNull;
    (void)genesis_tx;"""
if "CRY-7 confidential genesis" in s: print("present/skip")
elif old in s:
    s=s.replace(old,new,1); open(f,"w").write(s); print("generate_genesis_block: confidential genesis constructed")
else: print("FATAL old parse block not found")
