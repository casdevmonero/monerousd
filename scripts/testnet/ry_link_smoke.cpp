// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// Standalone FFI-link smoke: confirms the daemon's C surface can reach the
// Rust reserve-yield prover/verifier in libpqpool_ffi.a (no daemon build needed).
#include <vector>
#include <cstdint>
#include <cstdio>
extern "C" {
#include "pqpool_ffi.h"
}

int main() {
  const uint32_t k = 63;
  const uint64_t modulus = 0x0001000000000000ULL;
  const uint64_t b = 12345ULL;
  const uint64_t x = 0x0000500030001000ULL;

  int st = pqpool_reserve_yield_selftest(k, modulus, b, x);
  printf("pqpool_reserve_yield_selftest = %d\n", st);

  // Full marshaled round-trip through the C ABI: prove -> 128B publics -> verify.
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int i = 0; i < 16; ++i) { rcmx[i] = (unsigned char)(i + 1); rcmy[i] = (unsigned char)(i + 17); rcmb[i] = (unsigned char)(i + 33); }
  unsigned char publics[128];
  unsigned char *proof = nullptr; size_t proof_len = 0;
  int pr = pqpool_reserve_yield_prove(k, modulus, b, x,
                                      rcmx, 16, rcmy, 16, rcmb, 16, b,
                                      &proof, &proof_len, publics, 128);
  printf("pqpool_reserve_yield_prove = %d (proof_len=%zu)\n", pr, proof_len);
  int vr = -9;
  if (pr == 1) {
    vr = pqpool_reserve_yield_verify(proof, proof_len, publics, 128, k, modulus);
    printf("pqpool_reserve_yield_verify = %d\n", vr);
    // Dump the 128-byte publics = cm_S_new(32) | cm_S_old(32) | note_cm(32) | cm_b(32).
    const char *names[4] = {"cm_S_new", "cm_S_old(GENESIS_CM_S cand)", "note_cm", "cm_b(EPOCH_R)"};
    for (int blk = 0; blk < 4; ++blk) {
      printf("RY_PUB_%s=", names[blk]);
      for (int i = 0; i < 32; ++i) printf("%02x", publics[blk * 32 + i]);
      printf("\n");
    }
    pqpool_free(proof, proof_len);
  }
  bool ok = (st == 1) && (pr == 1) && (vr == 1);
  printf("RY_FFI_LINK_%s\n", ok ? "OK" : "FAIL");
  return ok ? 0 : 1;
}
