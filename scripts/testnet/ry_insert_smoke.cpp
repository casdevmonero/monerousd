// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6d-2b-iii smoke: full IMT insert (non-membership + L->L' update + Q append) — honest verifies, wrong root rejects.
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_imt_insert_selftest();
  printf("imt insert selftest = %d (root_old->root_new adds nf; tamper rejects)\n", st);
  printf("INSERT_%s\n", st == 1 ? "OK" : "FAIL");
  return st == 1 ? 0 : 1;
}
