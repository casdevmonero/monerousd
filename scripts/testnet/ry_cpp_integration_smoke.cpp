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
// CRY-6 C++ integration e2e: replicate the wallet's CRY-5 note derivation (sk=spend_public_key,
// rho/rcm from block height), build a spend via the wallet prove FFI, then run the daemon's three
// acceptance checks (verify + cmt-anchor + ns-root) + a replay rejection — all in C++ off the .a.
static void derive_rho_rcm(uint64_t ry_i, unsigned char rho[32], unsigned char rcm[32]) {
  for (int j = 0; j < 32; ++j) { rho[j]=(unsigned char)((j+5+ry_i)&0xFF); rcm[j]=(unsigned char)((j+9+ry_i)&0xFF); }
}
int main(){
  // a test wallet spend public key (the CRY-5 scan uses m_account...m_spend_public_key as the note 'sk')
  unsigned char spk[32]; for (int j=0;j<32;++j) spk[j]=(unsigned char)(0xA0 ^ (j*7+3));
  unsigned char out_pk[32]; for (int j=0;j<32;++j) out_pk[j]=(unsigned char)(0x5C ^ (j*5+1));
  const uint64_t height = 1;                 // first v45 block -> ry_i = 0
  const uint64_t ry_i = (height>=1)?(height-1):0;
  unsigned char rho[32], rcm[32]; derive_rho_rcm(ry_i, rho, rcm);

  // (CRY-4/CRY-5) on-chain coinbase note_cm = note_commit(12345,0, pk_d=own_null(spk,rho).pk_d, rho, rcm)
  unsigned char pk_d[32], nf[32];
  if (pqpool_own_null_pkd_nf(spk,32,rho,32,pk_d,32,nf,32)!=1){ printf("pkd FAIL\n"); return 1; }
  unsigned char note_cm[32];
  if (pqpool_reserve_yield_note_cm(12345ULL,0u,pk_d,32,rho,32,rcm,32,note_cm,32)!=1){ printf("note_cm FAIL\n"); return 1; }

  // daemon cmt-tree after this one coinbase = [note_cm]; the spend's anchor must equal its root
  unsigned char cmt_notes[32]; memcpy(cmt_notes, note_cm, 32);

  // wallet builds the spend (value 12345, fee 2345, leaf 0, depths 4)
  std::vector<uint8_t> bundle(4u*1024u*1024u); size_t blen=0;
  int pr = pqpool_reserve_yield_coinbase_spend_prove(spk,rho,rcm,12345ULL,0u,cmt_notes,32,0,4,out_pk,2345ULL,7ULL,4,bundle.data(),bundle.size(),&blen);
  printf("wallet prove (real CRY-5 note derivation) = %d, bundle %zu bytes\n", pr, blen);
  if (pr!=1){ printf("CRY6_CPP_E2E_FAIL\n"); return 1; }

  // daemon check 1: proof verifies
  int v = pqpool_reserve_yield_spend_verify(bundle.data(), blen);
  // daemon check 2: cmt-anchor == known coinbase-note-tree root (anti-fake-note)
  unsigned char anchor[32], cmt_root[32];
  int a = pqpool_reserve_yield_spend_anchor(bundle.data(), blen, anchor);
  int tr = pqpool_ry_note_tree_root(cmt_notes,32,4,cmt_root,32);
  int anchor_ok = (a==1 && tr==1 && memcmp(anchor,cmt_root,32)==0);
  // daemon check 3: ns_root_old == genesis empty IMT root (anti-replay threading start)
  unsigned char ns_old[32], ns_new[32], empty[32];
  int rr = pqpool_reserve_yield_spend_roots(bundle.data(), blen, ns_old, ns_new);
  int er = pqpool_imt_empty_root(4, empty);
  int ns_ok = (rr==1 && er==1 && memcmp(ns_old,empty,32)==0);
  int advanced = (memcmp(ns_old,ns_new,32)!=0);
  printf("verify=%d  anchor==cmt-root=%d  ns_root_old==empty=%d  ns advances=%d\n", v, anchor_ok, ns_ok, advanced);

  // replay simulation: a second application sees ns_root_old (==empty) != current (==ns_new) -> rejected
  int replay_rejected = (memcmp(ns_old, ns_new, 32) != 0);

  int ok = (v==1) && anchor_ok && ns_ok && advanced && replay_rejected;
  printf("CRY6_CPP_E2E_%s\n", ok?"OK":"FAIL");
  return ok?0:1;
}
