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
  int cb = pqpool_reserve_yield_coinbase_spend_selftest();
  printf("wallet coinbase-note spend builder      = %d (expect 1)\n", cb);
  int e2e = pqpool_reserve_yield_spend_e2e_selftest();
  printf("e2e: accept + REPLAY-reject + FAKE-reject = %d (expect 1)\n", e2e);
  int ok = (cb==1) && (e2e==1);
  printf("CRY6_E2E_%s\n", ok?"OK":"FAIL");
  return ok?0:1;
}
