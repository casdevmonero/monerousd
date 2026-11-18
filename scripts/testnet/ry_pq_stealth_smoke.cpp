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
extern "C" {
#include "pqpool_ffi.h"
}
// CRY-6 hardening (testnet=production): a coinbase note whose spend secret + randomness + amount are
// ALL derived from an ML-KEM-768 shared secret `ss` (post-quantum; no ECDH, no public placeholder).
// Here we feed an arbitrary `ss` (the producer's encaps / wallet's decaps both yield the SAME `ss` —
// that symmetry is ML-KEM's job, already validated). We prove: (1) sk/rho/rcm + amount-mask derive
// deterministically from ss; (2) the encrypted amount round-trips; (3) the note is spendable via the
// real derived secrets (verify_v2 + public nullifier); (4) a different ss -> different secret.
int main(){
  unsigned char ss[32];  for (int j=0;j<32;++j) ss[j]=(unsigned char)(0x37 ^ (j*11+5));   // pretend ML-KEM ss
  const uint64_t i = 7;  const uint64_t r = 77777ULL;                                      // HIDDEN reward (not 12345)

  unsigned char sk[32], rho[32], rcm[32];
  if (pqpool_reserve_yield_derive_secrets(ss,i,sk,rho,rcm)!=1){ printf("derive FAIL\n"); return 1; }
  // determinism + ss-dependence
  unsigned char sk2[32], rho2[32], rcm2[32];
  pqpool_reserve_yield_derive_secrets(ss,i,sk2,rho2,rcm2);
  int deterministic = (memcmp(sk,sk2,32)==0 && memcmp(rho,rho2,32)==0 && memcmp(rcm,rcm2,32)==0);
  unsigned char ss_b[32]; memcpy(ss_b,ss,32); ss_b[0]^=1; unsigned char skb[32],rhob[32],rcmb[32];
  pqpool_reserve_yield_derive_secrets(ss_b,i,skb,rhob,rcmb);
  int ss_dependent = (memcmp(sk,skb,32)!=0);

  // amount encrypt/decrypt round-trip
  unsigned char mask[8]; pqpool_reserve_yield_amount_mask(ss,i,mask);
  unsigned char r_le[8]; for(int j=0;j<8;++j) r_le[j]=(unsigned char)((r>>(8*j))&0xff);
  unsigned char r_enc[8]; for(int j=0;j<8;++j) r_enc[j]=r_le[j]^mask[j];
  uint64_t r_dec=0; unsigned char mask2[8]; pqpool_reserve_yield_amount_mask(ss,i,mask2);
  for(int j=0;j<8;++j){ unsigned char b=r_enc[j]^mask2[j]; r_dec |= ((uint64_t)b)<<(8*j); }
  int amount_roundtrip = (r_dec==r);

  // build the coinbase note's commitment from the derived secrets + hidden r
  unsigned char pk_d[32], nf[32];
  if (pqpool_own_null_pkd_nf(sk,32,rho,32,pk_d,32,nf,32)!=1){ printf("pkd FAIL\n"); return 1; }
  unsigned char note_cm[32];
  if (pqpool_reserve_yield_note_cm(r,0u,pk_d,32,rho,32,rcm,32,note_cm,32)!=1){ printf("note_cm FAIL\n"); return 1; }

  // spend it via the REAL derived secrets (public-nf v2)
  unsigned char cmt_notes[32]; memcpy(cmt_notes,note_cm,32);
  unsigned char opk[32]; for(int j=0;j<32;++j) opk[j]=(unsigned char)(0x5C^(j*5+1));
  std::vector<uint8_t> bundle(4u*1024u*1024u); size_t blen=0;
  int pr = pqpool_reserve_yield_coinbase_spend_prove_v2(sk,rho,rcm,r,0u,cmt_notes,32,0,4,opk,2345ULL,7ULL,bundle.data(),bundle.size(),&blen);
  int verified = (pr==1) && (pqpool_reserve_yield_spend_verify_v2(bundle.data(),blen)==1);
  unsigned char pubnf[32]; int nfok = verified && (pqpool_reserve_yield_spend_nullifier(bundle.data(),blen,pubnf)==1);

  printf("deterministic=%d  ss-dependent=%d  amount-roundtrip=%d  spend-verifies=%d  nf-public=%d\n",
         deterministic, ss_dependent, amount_roundtrip, verified, nfok);
  int ok = deterministic && ss_dependent && amount_roundtrip && verified && nfok;
  printf("CRY6_PQ_STEALTH_%s\n", ok?"OK":"FAIL");
  return ok?0:1;
}
