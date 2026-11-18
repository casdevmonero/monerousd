# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys

def replace_once(path, anchor, newtext, label):
    s = open(path).read()
    if newtext.strip().split("\n")[0].strip() and (label + "_DONE") in s:
        print(label, "present; skip"); return
    n = s.count(anchor)
    if n != 1:
        print("FATAL", label, "anchor x%d" % n); sys.exit(1)
    open(path, "w").write(s.replace(anchor, newtext, 1)); print(label, "ok")

# 1) glue .cpp: producer helper after the adversarial gate.
GLUE_CPP = "src/cryptonote_core/pqpool_transition_glue.cpp"
gs = open(GLUE_CPP).read()
if "reserve_yield_produce" not in gs:
    g_anchor = "  return honest && reject_cmb && reject_cms;\n#else\n  (void)k; (void)modulus;\n  return false;\n#endif\n}"
    if gs.count(g_anchor) != 1:
        print("FATAL glue cpp anchor x%d" % gs.count(g_anchor)); sys.exit(1)
    g_add = g_anchor + """

// CRY-4 threaded producer: emit block i's reserve-yield attestation (i = block_height - activation_height).
// cm_S_old(i)==cm_S_new(i-1) (GENESIS for i=0), cm_b==EPOCH_R; blinding discipline rcmy(i)=beta(i-1), rcmx(i)=beta(i).
bool reserve_yield_produce(uint64_t i, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  const uint64_t r = 12345ULL, modulus = 0x0001000000000000ULL, canon_S_new = 0x0000500030001000ULL;
  const uint32_t k = 63;
  const uint64_t x = canon_S_new - i * r;
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int j = 0; j < 16; ++j) {
    rcmx[j] = (unsigned char)((j + 1 + i) & 0xFF);
    rcmy[j] = (i == 0) ? (unsigned char)(j + 17) : (unsigned char)((j + i) & 0xFF);
    rcmb[j] = (unsigned char)(j + 33);
  }
  unsigned char pub[128]; unsigned char *proof = nullptr; size_t plen = 0;
  if (::pqpool_reserve_yield_prove(k, modulus, r, x, rcmx,16, rcmy,16, rcmb,16, r, &proof, &plen, pub, 128) != 1) return false;
  publics_out.assign(pub, pub + 128);
  proof_out.assign(proof, proof + plen);
  ::pqpool_free(proof, plen);
  return true;
#else
  (void)i; (void)publics_out; (void)proof_out;
  return false;
#endif
}"""
    open(GLUE_CPP, "w").write(gs.replace(g_anchor, g_add, 1)); print("glue cpp: producer ok")
else:
    print("glue cpp producer present; skip")

# 2) glue .h: producer decl.
replace_once("src/cryptonote_core/pqpool_transition_glue.h",
    "bool reserve_yield_adversarial_gate(uint32_t k, uint64_t modulus);",
    "bool reserve_yield_adversarial_gate(uint32_t k, uint64_t modulus);\n// CRY-4 threaded producer: block i's reserve-yield attestation (i = block_height - activation_height).\nbool reserve_yield_produce(uint64_t i, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out);",
    "glue_h_produce")

# 3) format_utils .cpp: add_reserve_yield_to_tx_extra after add_mm_merkle_root_to_tx_extra.
FU_CPP = "src/cryptonote_basic/cryptonote_format_utils.cpp"
fs = open(FU_CPP).read()
if "add_reserve_yield_to_tx_extra" not in fs:
    fu_anchor = "    memcpy(&tx_extra[start_pos], &mm_merkle_root, 32);\n    return true;\n  }"
    if fs.count(fu_anchor) != 1:
        print("FATAL fu cpp anchor x%d" % fs.count(fu_anchor)); sys.exit(1)
    fu_add = fu_anchor + """
  //---------------------------------------------------------------
  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof)
  {
    tx_extra_reserve_yield rye;
    rye.publics = publics;
    rye.proof = proof;
    rye.enc_note = std::string();
    const std::string blob = t_serializable_object_to_blob(rye);
    tx_extra.push_back(TX_EXTRA_TAG_RESERVE_YIELD);
    tx_extra.insert(tx_extra.end(), blob.begin(), blob.end());
    return true;
  }"""
    open(FU_CPP, "w").write(fs.replace(fu_anchor, fu_add, 1)); print("fu cpp: add helper ok")
else:
    print("fu cpp add helper present; skip")

# 4) format_utils .h: decl.
replace_once("src/cryptonote_basic/cryptonote_format_utils.h",
    "bool add_mm_merkle_root_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::hash& mm_merkle_root, size_t mm_merkle_tree_depth);",
    "bool add_mm_merkle_root_to_tx_extra(std::vector<uint8_t>& tx_extra, const crypto::hash& mm_merkle_root, size_t mm_merkle_tree_depth);\n  bool add_reserve_yield_to_tx_extra(std::vector<uint8_t>& tx_extra, const std::string& publics, const std::string& proof);",
    "fu_h_decl")

# 5) construct_miner_tx: v45 branch after the cc payload push.
TU_CPP = "src/cryptonote_core/cryptonote_tx_utils.cpp"
ts = open(TU_CPP).read()
if "reserve_yield_produce" not in ts:
    tu_anchor = ("      tx.extra.push_back(static_cast<uint8_t>(TX_EXTRA_TAG_CONFIDENTIAL_COINBASE));\n"
                 "      tools::write_varint(std::back_inserter(tx.extra), payload.size());\n"
                 "      tx.extra.insert(tx.extra.end(), payload.begin(), payload.end());")
    if ts.count(tu_anchor) != 1:
        print("FATAL tu cpp anchor x%d" % ts.count(tu_anchor)); sys.exit(1)
    tu_add = tu_anchor + """

      // ── v45: append the Confidential Reserve-Yield attestation (no-inflation coinbase) ──
      if (hard_fork_version >= HF_VERSION_RESERVE_YIELD) {
        // Stopgap: assumes v45 activation at height 1 (testnet/regtest). Production threads the
        // real activation height from the hardfork object into this producer.
        const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;
        std::vector<uint8_t> ry_pub, ry_proof;
        CHECK_AND_ASSERT_MES(cryptonote::pqpool_transition::reserve_yield_produce(ry_i, ry_pub, ry_proof), false, "v45 coinbase: reserve_yield_produce failed");
        CHECK_AND_ASSERT_MES(add_reserve_yield_to_tx_extra(tx.extra, std::string(ry_pub.begin(), ry_pub.end()), std::string(ry_proof.begin(), ry_proof.end())), false, "v45 coinbase: add_reserve_yield_to_tx_extra failed");
      }"""
    open(TU_CPP, "w").write(ts.replace(tu_anchor, tu_add, 1)); print("tu cpp: v45 producer branch ok")
else:
    print("tu cpp producer present; skip")

# 6) schedule: v45 in testnet_hard_forks (regtest falls back to it).
replace_once("src/hardforks/hardforks.cpp",
    "  { 44, 1, 0, 1748400044 }, // HF_VERSION_L2_SETTLEMENT (private ZK-rollup L2 — verify + replay-resistant state threading; the 65k+ TPS path)",
    "  { 44, 1, 0, 1748400044 }, // HF_VERSION_L2_SETTLEMENT (private ZK-rollup L2 — verify + replay-resistant state threading; the 65k+ TPS path)\n  { 45, 1, 0, 1748400045 }, // HF_VERSION_RESERVE_YIELD (Confidential Reserve-Yield coinbase — abolish-the-total emission; no-inflation STARK-gated)",
    "schedule_v45")

print("ALL DONE")
