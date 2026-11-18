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
int main(){ int a=pqpool_imt_insert_selftest(); int b=pqpool_imt_insert_private_selftest();
  printf("imt insert (public nf)=%d  (PRIVATE nf via bus)=%d\n",a,b);
  printf("NFBUS_%s\n",(a==1&&b==1)?"OK":"FAIL"); return (a==1&&b==1)?0:1; }
