// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <oqs/oqs.h>
extern "C" {
#include "pqpool_ffi.h"
}
// CRY-6 producer pass E2E (real ML-KEM-768 via liboqs): producer ENCAPSULATES to the miner PQ view key
// -> shared secret -> derives the note's REAL secret + builds note_cm; wallet DECAPSULATES -> same secret
// -> recovers the identical note -> spends it (public-nf v2). Plus tamper: a wrong KEM key cannot recover.
int main(){
  OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
  if (!kem) kem = OQS_KEM_new(OQS_KEM_alg_kyber_768);
  if (!kem) { printf("OQS_KEM_new FAIL\nCRY6_PQ_PRODUCER_E2E_FAIL\n"); return 1; }
  std::vector<uint8_t> pk(kem->length_public_key), sk(kem->length_secret_key), ct(kem->length_ciphertext);
  std::vector<uint8_t> ss(kem->length_shared_secret), ss2(kem->length_shared_secret);
  OQS_KEM_keypair(kem, pk.data(), sk.data());
  OQS_KEM_encaps(kem, ct.data(), ss.data(), pk.data());          // producer
  OQS_KEM_decaps(kem, ss2.data(), ct.data(), sk.data());         // wallet
  int handshake = (ss.size()==32 && memcmp(ss.data(), ss2.data(), 32)==0);

  const uint64_t i=0, r=12345ULL;
  auto note_from = [&](const uint8_t* s, uint8_t out[32]){
    unsigned char skn[32], rho[32], rcm[32]; pqpool_reserve_yield_derive_secrets(s, i, skn, rho, rcm);
    unsigned char pkd[32], nf[32]; pqpool_own_null_pkd_nf(skn,32,rho,32,pkd,32,nf,32);
    pqpool_reserve_yield_note_cm(r,0u,pkd,32,rho,32,rcm,32,out,32);
  };
  unsigned char note_p[32], note_w[32]; note_from(ss.data(), note_p); note_from(ss2.data(), note_w);
  int wallet_recovers = (memcmp(note_p, note_w, 32)==0);

  // wallet spends via its decaps-derived secret
  unsigned char skw[32], rhow[32], rcmw[32]; pqpool_reserve_yield_derive_secrets(ss2.data(), i, skw, rhow, rcmw);
  unsigned char cmt[32]; memcpy(cmt, note_w, 32);
  unsigned char opk[32]; for(int j=0;j<32;++j) opk[j]=(unsigned char)(0x5C^(j*5+1));
  std::vector<uint8_t> bundle(4u*1024u*1024u); size_t blen=0;
  int pr = pqpool_reserve_yield_coinbase_spend_prove_v2(skw,rhow,rcmw,r,0u,cmt,32,0,4,opk,2345ULL,7ULL,bundle.data(),bundle.size(),&blen);
  int spend_ok = (pr==1) && (pqpool_reserve_yield_spend_verify_v2(bundle.data(),blen)==1);

  // tamper: a DIFFERENT KEM key decapsulates the same ct to a different (pseudorandom) secret
  std::vector<uint8_t> pkb(kem->length_public_key), skb_(kem->length_secret_key), ssb(32);
  OQS_KEM_keypair(kem, pkb.data(), skb_.data());
  OQS_KEM_decaps(kem, ssb.data(), ct.data(), skb_.data());
  unsigned char note_b[32]; note_from(ssb.data(), note_b);
  int tamper_safe = (memcmp(note_p, note_b, 32)!=0);

  printf("ML-KEM handshake=%d  wallet-recovers-note=%d  spendable=%d  tamper-safe=%d\n",
         handshake, wallet_recovers, spend_ok, tamper_safe);
  OQS_KEM_free(kem);
  int ok = handshake && wallet_recovers && spend_ok && tamper_safe;
  printf("CRY6_PQ_PRODUCER_E2E_%s\n", ok?"OK":"FAIL");
  return ok?0:1;
}
