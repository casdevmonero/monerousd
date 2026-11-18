// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d-2b-iii smoke: Merkle update (dual-fold, shared path) — honest update verifies, wrong root rejects.
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_merkle_update_selftest();
  printf("merkle update selftest = %d (leaf_old->root_old + leaf_new->root_new same path; tamper rejects)\n", st);
  printf("UPDATE_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
