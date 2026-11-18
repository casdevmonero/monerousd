# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
CC="/root/MoneroUSD-clean/monero/src/cryptonote_core/"; W="/root/MoneroUSD-clean/monero/src/wallet/"
# 1) glue derive_secrets wrapper
gh=CC+"pqpool_transition_glue.h"; g=open(gh).read()
if "bool reserve_yield_derive_secrets(" not in g:
    anc="bool reserve_yield_spend_nullifier(const unsigned char *bundle, size_t bundle_len, unsigned char *out_nf);"
    g=g.replace(anc, anc+"\n// CRY-6 PQ-stealth: derive (sk,rho,rcm) from the ML-KEM shared secret + output index (Poseidon2).\nbool reserve_yield_derive_secrets(const unsigned char *ss, uint64_t i, unsigned char *sk, unsigned char *rho, unsigned char *rcm);", 1)
    open(gh,"w").write(g); print("glue.h: derive_secrets decl")
gc=CC+"pqpool_transition_glue.cpp"; c=open(gc).read()
if "bool reserve_yield_derive_secrets(" not in c:
    anc="bool reserve_yield_spend_nullifier(const unsigned char *bundle, size_t bundle_len, unsigned char *out_nf) {"
    IMPL="""bool reserve_yield_derive_secrets(const unsigned char *ss, uint64_t i, unsigned char *sk, unsigned char *rho, unsigned char *rcm) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  return ::pqpool_reserve_yield_derive_secrets(ss, i, sk, rho, rcm) == 1;
#else
  (void)ss;(void)i;(void)sk;(void)rho;(void)rcm; return false;
#endif
}
"""
    c=c.replace(anc, IMPL+anc, 1); open(gc,"w").write(c); print("glue.cpp: derive_secrets impl")
# 2) wallet2.h member
wh=W+"wallet2.h"; h=open(wh).read()
if "m_reserve_yield_note_secrets" not in h:
    anc="    std::vector<uint64_t> m_reserve_yield_note_heights;  // CRY-6: owned spendable notes (height fully derives sk/rho/rcm/value)"
    h=h.replace(anc, anc+"\n    std::vector<std::string> m_reserve_yield_note_secrets;  // CRY-6 PQ-stealth: per-note ML-KEM shared secret ss (empty=placeholder); parallel to heights", 1)
    open(wh,"w").write(h); print("wallet2.h: secrets member")
# 3) wallet2.cpp scan block (PQ + placeholder)
wc=W+"wallet2.cpp"; s=open(wc).read()
if '#include "crypto/pq/mlkem.h"' not in s:
    import re; s=re.sub(r'(#include "cryptonote_basic/cryptonote_format_utils.h"\n)', r'\1#include "crypto/pq/mlkem.h"\n', s, count=1)
    if '#include "crypto/pq/mlkem.h"' not in s:
        s=re.sub(r'(#include [^\n]+\n)', r'\1#include "crypto/pq/mlkem.h"\n', s, count=1)
old="""      const std::vector<uint8_t> onchain_cm(ry.publics.begin() + 64, ry.publics.begin() + 96);
      const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;
      unsigned char rho[32], rcm[32];
      for (int j = 0; j < 32; ++j) { rho[j] = (unsigned char)((j + 5 + ry_i) & 0xFF); rcm[j] = (unsigned char)((j + 9 + ry_i) & 0xFF); }
      const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
      unsigned char spend_pk_d[32], spend_nf[32];
      std::vector<uint8_t> cm;
      if (cryptonote::pqpool_transition::reserve_yield_spend_pkd(reinterpret_cast<const unsigned char*>(&spk), 32, rho, 32, spend_pk_d, spend_nf) &&
          cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, spend_pk_d, 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
        m_reserve_yield_balance += 12345ULL;
        m_reserve_yield_note_heights.push_back(height);
        MINFO("CRY-6: owned SPENDABLE reserve-yield note @ height " << height << " (+12345); ry balance " << m_reserve_yield_balance);
      }"""
new="""      const std::vector<uint8_t> onchain_cm(ry.publics.begin() + 64, ry.publics.begin() + 96);
      const uint64_t ry_i = (height >= 1) ? (height - 1) : 0;
      namespace kem = cryptonote::pq::kem;
      bool owned = false; std::string matched_ss;
      unsigned char sk[32], rho[32], rcm[32], pk_d[32], nf[32]; std::vector<uint8_t> cm;
      if (ry.enc_note.size() == kem::MLKEM_CIPHERTEXT_BYTES) {
        // CRY-6 PQ-stealth (production): derive the wallet ML-KEM keypair from the VIEW SECRET, decapsulate
        // the coinbase ciphertext -> shared secret -> the note's REAL spend secret + rho/rcm (PQ, no placeholder).
        const crypto::secret_key &vsk = m_account.get_keys().m_view_secret_key;
        uint8_t mk_pub[kem::MLKEM_PUBLIC_KEY_BYTES], mk_priv[kem::MLKEM_SECRET_KEY_BYTES], ss[kem::MLKEM_SHARED_SECRET_BYTES];
        kem::keypair_from_seed(reinterpret_cast<const uint8_t*>(&vsk), mk_pub, mk_priv);
        if (kem::decapsulate(mk_priv, reinterpret_cast<const uint8_t*>(ry.enc_note.data()), ss) &&
            cryptonote::pqpool_transition::reserve_yield_derive_secrets(ss, ry_i, sk, rho, rcm) &&
            cryptonote::pqpool_transition::reserve_yield_spend_pkd(sk, 32, rho, 32, pk_d, nf) &&
            cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, pk_d, 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
          owned = true; matched_ss.assign(reinterpret_cast<const char*>(ss), 32);
        }
      } else {
        // testnet placeholder (no enc_note): sk = spend pubkey, rho/rcm from height
        for (int j = 0; j < 32; ++j) { rho[j] = (unsigned char)((j + 5 + ry_i) & 0xFF); rcm[j] = (unsigned char)((j + 9 + ry_i) & 0xFF); }
        const crypto::public_key &spk = m_account.get_keys().m_account_address.m_spend_public_key;
        if (cryptonote::pqpool_transition::reserve_yield_spend_pkd(reinterpret_cast<const unsigned char*>(&spk), 32, rho, 32, pk_d, nf) &&
            cryptonote::pqpool_transition::reserve_yield_note_cm(12345ULL, 0u, pk_d, 32, rho, 32, rcm, 32, cm) && cm == onchain_cm) {
          owned = true;
        }
      }
      if (owned) {
        m_reserve_yield_balance += 12345ULL;
        m_reserve_yield_note_heights.push_back(height);
        m_reserve_yield_note_secrets.push_back(matched_ss);
        MINFO("CRY-6: owned reserve-yield note @ height " << height << (matched_ss.empty() ? " (placeholder)" : " (PQ ML-KEM decapsulated)") << "; ry balance " << m_reserve_yield_balance);
      }"""
if old in s:
    s=s.replace(old,new,1); open(wc,"w").write(s); print("wallet2.cpp: PQ scan wired")
elif "PQ ML-KEM decapsulated" in s: print("wallet2 scan present/skip")
else: print("FATAL wallet2 scan old block not found")
print("DONE")
