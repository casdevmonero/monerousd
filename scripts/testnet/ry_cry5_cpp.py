# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# 1) glue.cpp — signature + switch to the note FFI with pk_d + deterministic rho/rcm.
g = base + "src/cryptonote_core/pqpool_transition_glue.cpp"; s = open(g).read()
sig_old = "bool reserve_yield_produce(uint64_t i, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out) {"
sig_new = "bool reserve_yield_produce(uint64_t i, const unsigned char *pk_d, size_t pk_d_len, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out) {"
call_old = ("  unsigned char pub[128]; unsigned char *proof = nullptr; size_t plen = 0;\n"
            "  if (::pqpool_reserve_yield_prove(k, modulus, r, x, rcmx,16, rcmy,16, rcmb,16, r, &proof, &plen, pub, 128) != 1) return false;")
call_new = ("  if (pk_d == nullptr || pk_d_len != 32) return false;  // pk_d = miner spend key (32B) → the note recipient\n"
            "  // CRY-5: deterministic rho/rcm from i (32B each) so the wallet recomputes note_cm WITHOUT an enc_note\n"
            "  // (testnet placeholder economics; the production hidden-draw path encrypts these to the view key).\n"
            "  unsigned char rho[32], rcm[32];\n"
            "  for (int j = 0; j < 32; ++j) { rho[j] = (unsigned char)((j + 5 + i) & 0xFF); rcm[j] = (unsigned char)((j + 9 + i) & 0xFF); }\n"
            "  const uint32_t asset = 0u;\n"
            "  unsigned char pub[128]; unsigned char *proof = nullptr; size_t plen = 0;\n"
            "  if (::pqpool_reserve_yield_prove_note(k, modulus, r, x, rcmx,16, rcmy,16, rcmb,16, r, asset, pk_d,32, rho,32, rcm,32, &proof, &plen, pub, 128) != 1) return false;")
if "pqpool_reserve_yield_prove_note" not in s:
    if s.count(sig_old) != 1 or s.count(call_old) != 1: print("FATAL glue.cpp anchors sig=%d call=%d"%(s.count(sig_old),s.count(call_old))); sys.exit(1)
    s = s.replace(sig_old, sig_new, 1).replace(call_old, call_new, 1); open(g,"w").write(s); print("glue.cpp ok")
else: print("glue.cpp present; skip")

# 2) glue.h decl.
h = base + "src/cryptonote_core/pqpool_transition_glue.h"; hs = open(h).read()
ho = "bool reserve_yield_produce(uint64_t i, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out);"
hn = "bool reserve_yield_produce(uint64_t i, const unsigned char *pk_d, size_t pk_d_len, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out);"
if hn not in hs:
    if hs.count(ho)!=1: print("FATAL glue.h anchor x%d"%hs.count(ho)); sys.exit(1)
    open(h,"w").write(hs.replace(ho,hn,1)); print("glue.h ok")
else: print("glue.h present; skip")

# 3) producer call — pass the miner spend key as pk_d.
t = base + "src/cryptonote_core/cryptonote_tx_utils.cpp"; ts = open(t).read()
to = "cryptonote::pqpool_transition::reserve_yield_produce(ry_i, ry_pub, ry_proof)"
tn = "cryptonote::pqpool_transition::reserve_yield_produce(ry_i, reinterpret_cast<const unsigned char*>(&miner_address.m_spend_public_key), 32, ry_pub, ry_proof)"
if tn not in ts:
    if ts.count(to)!=1: print("FATAL tx_utils anchor x%d"%ts.count(to)); sys.exit(1)
    open(t,"w").write(ts.replace(to,tn,1)); print("tx_utils ok")
else: print("tx_utils present; skip")

# 4) pqpool_ffi.h decl.
f = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; fs = open(f).read()
fa = "int32_t pqpool_reserve_yield_prove(uint32_t k, uint64_t modulus, uint64_t b, uint64_t x,"
fn = ("int32_t pqpool_reserve_yield_prove_note(uint32_t k, uint64_t modulus, uint64_t b, uint64_t x,\n"
      "    const uint8_t* rcmx, size_t rcmx_len, const uint8_t* rcmy, size_t rcmy_len, const uint8_t* rcmb, size_t rcmb_len,\n"
      "    uint64_t note_value, uint32_t asset,\n"
      "    const uint8_t* pk_d, size_t pk_d_len, const uint8_t* rho, size_t rho_len, const uint8_t* rcm, size_t rcm_len,\n"
      "    uint8_t** out_proof_ptr, size_t* out_proof_len, uint8_t* out_publics, size_t out_publics_len);\n\n")
if "pqpool_reserve_yield_prove_note" not in fs:
    if fs.count(fa)!=1: print("FATAL ffi.h anchor x%d"%fs.count(fa)); sys.exit(1)
    open(f,"w").write(fs.replace(fa, fn+fa, 1)); print("ffi.h ok")
else: print("ffi.h present; skip")
print("DONE")
