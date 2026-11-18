// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-6 foundation smoke: prove a reserve-yield note is spendable through the FFI boundary
// (SpendAir prove+verify round-trip) and that the spend-auth derivation (sk -> pk_d, nf) works.
#include <cstdio>
#include <cstring>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  int st = pqpool_reserve_yield_spend_selftest();   // full 1-in/1-out SpendAir prove+verify
  printf("spend selftest = %d (1=honest spend verifies)\n", st);

  unsigned char sk[32] = {0}, rho[32] = {0}, pk_d[32], nf[32];
  sk[0] = 7; rho[0] = 11;                            // sk/rho as little-endian u32 limbs
  int dr = pqpool_own_null_pkd_nf(sk, 32, rho, 32, pk_d, 32, nf, 32);
  int pk_nz = 0, nf_nz = 0;
  for (int i = 0; i < 32; i++) { if (pk_d[i]) pk_nz = 1; if (nf[i]) nf_nz = 1; }
  printf("own_null derive=%d  pk_d=%02x%02x..  nf=%02x%02x..  pk_nz=%d nf_nz=%d\n",
         dr, pk_d[0], pk_d[1], nf[0], nf[1], pk_nz, nf_nz);

  // Determinism: same (sk,rho) -> same (pk_d,nf).
  unsigned char pk2[32], nf2[32];
  pqpool_own_null_pkd_nf(sk, 32, rho, 32, pk2, 32, nf2, 32);
  int deterministic = (memcmp(pk_d, pk2, 32) == 0) && (memcmp(nf, nf2, 32) == 0);

  int ok = (st == 1) && (dr == 1) && pk_nz && nf_nz && deterministic;
  printf("SPENDFFI_%s\n", ok ? "OK" : "FAIL");
  return ok ? 0 : 1;
}
