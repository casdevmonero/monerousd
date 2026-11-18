// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d-2b-i smoke: IMT leaf membership (sponge leaf-hash + Merkle membership) verifies; tamper rejects.
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_imt_membership_selftest();
  printf("imt membership selftest = %d (honest member verifies; tampered leaf rejected)\n", st);
  printf("MEMBER_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
