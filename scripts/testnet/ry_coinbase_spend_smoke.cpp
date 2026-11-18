// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#include <cstdio>
#include <cstring>
#include <cstdint>
extern "C" {
#include "pqpool_ffi.h"
}
int main(){
  // (1) wallet coinbase-note spend selftest: builds a REAL coinbase-note spend, asserts it verifies
  //     from bytes, its membership anchor == the daemon's cmt-tree root over the same note_cm, and its
  //     ns_root_old == the empty IMT root (genesis); plus a negative (wrong leaf_index refused).
  int st = pqpool_reserve_yield_coinbase_spend_selftest();
  printf("wallet coinbase-note spend selftest = %d (expect 1)\n", st);

  // (2) FFI prove shim ptr-safety + consistency: an arbitrary cmt-tree leaf is NOT our note -> refused.
  uint8_t sk[32]={0}, rho[32]={0}, rcm[32]={0}, opk[32]={0};
  uint64_t skv=0xC0FFEE, rhov=0x1234, rcmv=0x5678, opkv=0xBEEF;
  memcpy(sk,&skv,8); memcpy(rho,&rhov,8); memcpy(rcm,&rcmv,8); memcpy(opk,&opkv,8);
  uint8_t cmt_notes[32]; memset(cmt_notes,7,32);
  uint8_t out[8192]; size_t out_len=0;
  int pr = pqpool_reserve_yield_coinbase_spend_prove(sk,rho,rcm,12345,0,cmt_notes,32,0,4,opk,2345,7,4,out,sizeof(out),&out_len);
  printf("prove FFI (note not at leaf) = %d (expect 0 refused)\n", pr);

  int ok = (st==1) && (pr==0);
  printf("COINBASE_SPEND_%s\n", ok?"OK":"FAIL");
  return ok?0:1;
}
