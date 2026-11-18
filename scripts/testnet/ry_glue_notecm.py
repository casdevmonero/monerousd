# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "src/cryptonote_core/pqpool_transition_glue.cpp"; s = open(c).read()
if "reserve_yield_note_cm" not in s:
    anc = "bool reserve_yield_coinbase_verify("
    if s.count(anc) < 1: print("FATAL cpp anchor"); sys.exit(1)
    fn = '''// CRY-5 wallet scanner bridge: recompute note_cm = H(value|asset|pk_d|rho|rcm) (no proof) so the
// miner wallet can test-own a coinbase reserve-yield note. Routes to the FFI (cryptonote_core links it).
bool reserve_yield_note_cm(uint64_t note_value, uint32_t asset,
                           const unsigned char *pk_d, size_t pk_d_len,
                           const unsigned char *rho, size_t rho_len,
                           const unsigned char *rcm, size_t rcm_len,
                           std::vector<uint8_t> &note_cm_out) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  unsigned char cm[32];
  if (::pqpool_reserve_yield_note_cm(note_value, asset, pk_d, pk_d_len, rho, rho_len, rcm, rcm_len, cm, 32) != 1) return false;
  note_cm_out.assign(cm, cm + 32);
  return true;
#else
  (void)note_value; (void)asset; (void)pk_d; (void)pk_d_len; (void)rho; (void)rho_len; (void)rcm; (void)rcm_len; (void)note_cm_out;
  return false;
#endif
}

'''
    s = s.replace(anc, fn + anc, 1); open(c, "w").write(s); print("glue.cpp note_cm wrapper ok")
else: print("glue.cpp present; skip")
h = base + "src/cryptonote_core/pqpool_transition_glue.h"; hs = open(h).read()
if "reserve_yield_note_cm" not in hs:
    ha = "bool reserve_yield_produce(uint64_t i, const unsigned char *pk_d, size_t pk_d_len, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out);"
    if hs.count(ha) != 1: print("FATAL h anchor x%d" % hs.count(ha)); sys.exit(1)
    hn = ha + "\n// CRY-5: recompute a reserve-yield note commitment (wallet scanner ownership test).\nbool reserve_yield_note_cm(uint64_t note_value, uint32_t asset, const unsigned char *pk_d, size_t pk_d_len, const unsigned char *rho, size_t rho_len, const unsigned char *rcm, size_t rcm_len, std::vector<uint8_t> &note_cm_out);"
    open(h, "w").write(hs.replace(ha, hn, 1)); print("glue.h decl ok")
else: print("glue.h present; skip")
