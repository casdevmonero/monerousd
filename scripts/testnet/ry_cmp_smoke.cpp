// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d-2a smoke: the in-circuit 256-bit comparison AIR proves a<b and rejects a>=b.
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_compare_selftest();
  printf("compare selftest = %d (a<b verifies; a==b, a>b unprovable; MSB element decides)\n", st);
  printf("CMP_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
