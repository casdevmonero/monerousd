# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
CC="/root/MoneroUSD-clean/monero/src/cryptonote_core/"
gh=CC+"pqpool_transition_glue.h"; g=open(gh).read()
if "reserve_yield_produce_v2" not in g:
    anc="bool reserve_yield_spend_verify_v2(const unsigned char *bundle, size_t bundle_len);"
    if g.count(anc)!=1: print("FATAL gh anchor x%d"%g.count(anc)); sys.exit(1)
    g=g.replace(anc, anc+'''
// CRY-6 PQ-stealth producer (testnet=production): ML-KEM encapsulate to the miner PQ view key -> shared
// secret -> derive the note's REAL spend secret + rho/rcm (Poseidon2) -> build the coinbase note. Outputs
// the ML-KEM ciphertext (-> tx_extra enc_note) so only the miner (decapsulate) recovers the secret.
bool reserve_yield_produce_v2(const unsigned char *mlkem_pub, size_t mlkem_pub_len, uint64_t i,
                              std::vector<uint8_t> &ct_out, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out);
// CRY-6 PQ-stealth roundtrip selftest (producer encapsulate+build -> wallet decapsulate+derive -> note_cm match + proof verify).
bool reserve_yield_pq_produce_scan_selftest();''', 1)
    open(gh,"w").write(g); print("glue.h: produce_v2 + selftest decls")
gc=CC+"pqpool_transition_glue.cpp"; c=open(gc).read()
if '#include "crypto/pq/mlkem.h"' not in c:
    # add include near the top (after the first #include)
    import re
    c=re.sub(r'(#include [^\n]+\n)', r'\1#include "crypto/pq/mlkem.h"\n', c, count=1)
if "reserve_yield_produce_v2" not in c:
    anc="bool reserve_yield_spend_verify_v2(const unsigned char *bundle, size_t bundle_len) {"
    if c.count(anc)!=1: print("FATAL gc anchor x%d"%c.count(anc)); sys.exit(1)
    IMPL='''bool reserve_yield_produce_v2(const unsigned char *mlkem_pub, size_t mlkem_pub_len, uint64_t i,
                              std::vector<uint8_t> &ct_out, std::vector<uint8_t> &publics_out, std::vector<uint8_t> &proof_out) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  namespace kem = cryptonote::pq::kem;
  if (mlkem_pub == nullptr || mlkem_pub_len != kem::MLKEM_PUBLIC_KEY_BYTES) return false;
  unsigned char ct[kem::MLKEM_CIPHERTEXT_BYTES], ss[kem::MLKEM_SHARED_SECRET_BYTES];
  kem::encapsulate(mlkem_pub, ct, ss);                                   // PQ KEM: ciphertext + shared secret
  unsigned char sk[32], rho[32], rcm[32];
  if (::pqpool_reserve_yield_derive_secrets(ss, i, sk, rho, rcm) != 1) return false;   // PQ sponge derivation
  unsigned char spend_pk_d[32], spend_nf[32];
  if (::pqpool_own_null_pkd_nf(sk, 32, rho, 32, spend_pk_d, 32, spend_nf, 32) != 1) return false;
  const uint64_t r = 12345ULL, modulus = 0x0001000000000000ULL, canon_S_new = 0x0000500030001000ULL;  // value/surplus hiding is CRY-7
  const uint32_t k = 63; const uint64_t x = canon_S_new - i * r;
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int j = 0; j < 16; ++j) { rcmx[j]=(unsigned char)((j+1+i)&0xFF); rcmy[j]=(i==0)?(unsigned char)(j+17):(unsigned char)((j+i)&0xFF); rcmb[j]=(unsigned char)(j+33); }
  unsigned char pub[128]; unsigned char *proof=nullptr; size_t plen=0;
  if (::pqpool_reserve_yield_prove_note(k, modulus, r, x, rcmx,16, rcmy,16, rcmb,16, r, 0u, spend_pk_d,32, rho,32, rcm,32, &proof, &plen, pub, 128) != 1) return false;
  publics_out.assign(pub, pub+128); proof_out.assign(proof, proof+plen); ct_out.assign(ct, ct+sizeof(ct));
  ::pqpool_free(proof, plen);
  return true;
#else
  (void)mlkem_pub;(void)mlkem_pub_len;(void)i;(void)ct_out;(void)publics_out;(void)proof_out; return false;
#endif
}
bool reserve_yield_pq_produce_scan_selftest() {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  namespace kem = cryptonote::pq::kem;
  unsigned char seed[kem::MLKEM_SEED_BYTES]; for (size_t j=0;j<sizeof(seed);++j) seed[j]=(unsigned char)(0x42 ^ j);
  std::vector<uint8_t> pk(kem::MLKEM_PUBLIC_KEY_BYTES), sk(kem::MLKEM_SECRET_KEY_BYTES);
  kem::keypair_from_seed(seed, pk.data(), sk.data());
  std::vector<uint8_t> ct, publics, proof;
  if (!reserve_yield_produce_v2(pk.data(), pk.size(), 0, ct, publics, proof)) return false;
  if (publics.size() != 128) return false;
  unsigned char ss[kem::MLKEM_SHARED_SECRET_BYTES];
  if (!kem::decapsulate(sk.data(), ct.data(), ss)) return false;          // wallet recovers the SAME ss
  unsigned char dsk[32], rho[32], rcm[32];
  if (::pqpool_reserve_yield_derive_secrets(ss, 0, dsk, rho, rcm) != 1) return false;
  unsigned char pk_d[32], nf[32];
  if (::pqpool_own_null_pkd_nf(dsk, 32, rho, 32, pk_d, 32, nf, 32) != 1) return false;
  std::vector<uint8_t> cm;
  if (!reserve_yield_note_cm(12345ULL, 0u, pk_d, 32, rho, 32, rcm, 32, cm)) return false;
  if (cm.size() != 32) return false;
  for (int j=0;j<32;++j) if (cm[j] != publics[64+j]) return false;        // recomputed note_cm == on-chain note_cm
  std::vector<uint8_t> exp_cm_S_old(publics.begin()+32, publics.begin()+64);
  if (!reserve_yield_coinbase_verify(proof, publics, exp_cm_S_old, 63, 0x0001000000000000ULL)) return false;  // proof verifies
  return true;
#else
  return false;
#endif
}
'''
    c=c.replace(anc, IMPL+"bool reserve_yield_spend_verify_v2(const unsigned char *bundle, size_t bundle_len) {", 1)
    open(gc,"w").write(c); print("glue.cpp: produce_v2 + selftest impls")
print("DONE")
