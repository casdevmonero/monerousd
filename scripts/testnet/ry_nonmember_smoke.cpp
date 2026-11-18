// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d-2b-ii smoke: monolithic IMT non-membership (membership + 2 comparisons, shared columns).
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_imt_nonmembership_selftest();
  printf("imt non-membership selftest = %d (in-gap nf verifies; out-of-gap / boundary rejected)\n", st);
  printf("NONMEMBER_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
