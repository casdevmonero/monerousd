// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d step 1 smoke: the IMT nullifier set has sound sorted-set + double-spend semantics.
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_imt_nullifier_selftest();
  printf("IMT nullifier selftest = %d (root advances; non-membership correct; re-spend rejected)\n", st);
  printf("IMT_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
