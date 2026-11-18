// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main(){
  // CRY-6 public-nf: two DISTINCT coinbase notes each spent; daemon nullifier-set accepts both
  // (multi-spend) and rejects a replay of the first. Plus distinct nullifiers + anchor==cmt-root.
  int ms = pqpool_reserve_yield_spend_multispend_selftest();
  printf("multi-spend: 2 distinct spends accepted + replay rejected = %d (expect 1)\n", ms);
  printf("CRY6_MULTISPEND_%s\n", ms==1?"OK":"FAIL");
  return ms==1?0:1;
}
