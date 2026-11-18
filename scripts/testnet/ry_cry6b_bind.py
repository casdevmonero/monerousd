# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"

# 1) glue.cpp: (a) producer commits spendable pk_d; (b) NEW reserve_yield_spend_pkd wrapper for the wallet.
c = base + "src/cryptonote_core/pqpool_transition_glue.cpp"; s = open(c).read()
if "spend_pk_d" not in s:
    # (a) derive spendable pk_d before the asset line
    a1 = "  const uint32_t asset = 0u;\n  unsigned char pub[128];"
    n1 = ("  // CRY-6: commit a SPENDABLE pk_d = H(DS_PK|sk) so the miner can later spend the note via SpendAir.\n"
          "  // Testnet placeholder: sk = the miner spend-key bytes (public-derivable so the wallet reconstructs sk;\n"
          "  // the production hidden-draw path encrypts sk to the miner via enc_note).\n"
          "  unsigned char spend_pk_d[32], spend_nf[32];\n"
          "  if (::pqpool_own_null_pkd_nf(pk_d, 32, rho, 32, spend_pk_d, 32, spend_nf, 32) != 1) return false;\n"
          "  const uint32_t asset = 0u;\n  unsigned char pub[128];")
    if s.count(a1) != 1: print("FATAL glue a1 x%d" % s.count(a1)); sys.exit(1)
    s = s.replace(a1, n1, 1)
    # change prove_note pk_d arg -> spend_pk_d
    a2 = "asset, pk_d,32, rho,32, rcm,32"
    if s.count(a2) != 1: print("FATAL glue a2 x%d" % s.count(a2)); sys.exit(1)
    s = s.replace(a2, "asset, spend_pk_d,32, rho,32, rcm,32", 1)
    # (b) wallet bridge wrapper, before reserve_yield_note_cm definition
    a3 = "bool reserve_yield_note_cm(uint64_t note_value, uint32_t asset,"
    n3 = ('''// CRY-6: derive (pk_d, nf) from (sk, rho) for the wallet (which routes through the glue, not the FFI).
bool reserve_yield_spend_pkd(const unsigned char *sk, size_t sk_len, const unsigned char *rho, size_t rho_len,
                             unsigned char *pk_d_out, unsigned char *nf_out) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  return ::pqpool_own_null_pkd_nf(sk, sk_len, rho, rho_len, pk_d_out, 32, nf_out, 32) == 1;
#else
  (void)sk; (void)sk_len; (void)rho; (void)rho_len; (void)pk_d_out; (void)nf_out; return false;
#endif
}

''')
    if s.count(a3) < 1: print("FATAL glue a3"); sys.exit(1)
    s = s.replace(a3, n3 + a3, 1)
    open(c, "w").write(s); print("glue.cpp 6b ok")
else: print("glue.cpp 6b present; skip")

# 2) glue.h: declare reserve_yield_spend_pkd
h = base + "src/cryptonote_core/pqpool_transition_glue.h"; hs = open(h).read()
if "reserve_yield_spend_pkd" not in hs:
    ha = "bool reserve_yield_note_cm(uint64_t note_value, uint32_t asset, const unsigned char *pk_d, size_t pk_d_len, const unsigned char *rho, size_t rho_len, const unsigned char *rcm, size_t rcm_len, std::vector<uint8_t> &note_cm_out);"
    hn = ha + "\n// CRY-6: derive (pk_d, nf) from (sk, rho) — wallet spend-auth bridge.\nbool reserve_yield_spend_pkd(const unsigned char *sk, size_t sk_len, const unsigned char *rho, size_t rho_len, unsigned char *pk_d_out, unsigned char *nf_out);"
    if hs.count(ha) != 1: print("FATAL glue.h x%d" % hs.count(ha)); sys.exit(1)
    open(h, "w").write(hs.replace(ha, hn, 1)); print("glue.h 6b ok")
else: print("glue.h 6b present; skip")

# 3) wallet2.h: owned-note heights store
wh = base + "src/wallet/wallet2.h"; ws = open(wh).read()
if "m_reserve_yield_note_heights" not in ws:
    wa = "    uint64_t m_reserve_yield_balance = 0;  // CRY-5: runtime-only (recomputed on (re)scan)"
    wn = wa + "\n    std::vector<uint64_t> m_reserve_yield_note_heights;  // CRY-6: owned spendable notes (height fully derives sk/rho/rcm/value)"
    if ws.count(wa) != 1: print("FATAL wallet2.h x%d" % ws.count(wa)); sys.exit(1)
    open(wh, "w").write(ws.replace(wa, wn, 1)); print("wallet2.h 6b ok")
else: print("wallet2.h 6b present; skip")

# 4) wallet2.cpp: match against the SPENDABLE pk_d + record owned note
wc = base + "src/wallet/wallet2.cpp"; wcs = open(wc).read()
if "reserve_yield_spend_pkd" not in wcs:
    old = '''      const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
      std::vector<uint8_t> cm;
      if (cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, reinterpret_cast<const unsigned char*>(&spk), 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
        m_reserve_yield_balance += 12345ULL;
        MINFO("CRY-5: owned reserve-yield coinbase note @ height " << height << " (+12345); ry balance " << m_reserve_yield_balance);
      }'''
    new = '''      const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
      unsigned char spend_pk_d[32], spend_nf[32];
      std::vector<uint8_t> cm;
      if (cryptonote::pqpool_transition::reserve_yield_spend_pkd(reinterpret_cast<const unsigned char*>(&spk), 32, rho, 32, spend_pk_d, spend_nf) &&
          cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, spend_pk_d, 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
        m_reserve_yield_balance += 12345ULL;
        m_reserve_yield_note_heights.push_back(height);
        MINFO("CRY-6: owned SPENDABLE reserve-yield note @ height " << height << " (+12345); ry balance " << m_reserve_yield_balance);
      }'''
    if wcs.count(old) != 1: print("FATAL wallet2.cpp x%d" % wcs.count(old)); sys.exit(1)
    open(wc, "w").write(wcs.replace(old, new, 1)); print("wallet2.cpp 6b ok")
else: print("wallet2.cpp 6b present; skip")
print("DONE")
