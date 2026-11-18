// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6e C ABI smoke: prove a reserve-yield spend bundle, verify it from bytes, confirm tamper rejects.
#include <cstdio>
#include <vector>
extern "C" {
#include "pqpool_ffi.h"
}
int main(){
  std::vector<unsigned char> buf(8*1024*1024); size_t len=0;
  int pr=pqpool_reserve_yield_spend_prove_test(buf.data(), buf.size(), &len);
  int v1=pqpool_reserve_yield_spend_verify(buf.data(), len);          // honest -> 1
  buf[len/2]^=0xFF;
  int v2=pqpool_reserve_yield_spend_verify(buf.data(), len);          // corrupted -> 0
  printf("prove=%d len=%zu  verify(honest)=%d  verify(corrupt)=%d\n", pr, len, v1, v2);
  int ok=(pr==1 && v1==1 && v2==0);
  printf("GLUEVERIFY_%s\n", ok?"OK":"FAIL"); return ok?0:1;
}
