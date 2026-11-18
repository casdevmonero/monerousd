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
int main(){ int st=pqpool_reserve_yield_spend_compose_selftest();
  printf("reserve-yield spend compose (nf bound to spent note, private, inserted) = %d\n",st);
  printf("SPENDCOMPOSE_%s\n",st==1?"OK":"FAIL"); return st==1?0:1; }
