// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-4 threaded producer, validated standalone: produces a real multi-block reserve-yield
// chain where each block's cm_S_old == the previous block's cm_S_new (surplus conservation),
// cm_b == EPOCH_R (fixed reward), and the STARK proof verifies. This is what the daemon
// producer (construct_miner_tx) emits; height index i = block_height - activation_height.
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
extern "C" {
#include "pqpool_ffi.h"
}

static const uint32_t K = 63;
static const uint64_t MODULUS = 0x0001000000000000ULL;
static const uint64_t R = 12345ULL;                  // fixed hidden reward draw
static const uint64_t CANON_S_NEW = 0x0000500030001000ULL;

// Produce block i's reserve-yield attestation. Blinding discipline:
//   rcmx(i)=β(i) commits cm_S_new(i); rcmy(i)=β(i-1) commits cm_S_old(i) == cm_S_new(i-1).
//   β(0)=j+1 (canonical), β(i)=(j+1+i); rcmy(0)=j+17 (the canonical GENESIS opening).
//   rcmb=j+33 fixed ⇒ cm_b == EPOCH_R for every block.
bool produce(uint64_t i, unsigned char pub[128], std::vector<unsigned char>& proof_out) {
  const uint64_t x = CANON_S_NEW - i * R;            // S_new(i); S_old(i)=x+R threads to parent
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int j = 0; j < 16; ++j) {
    rcmx[j] = (unsigned char)((j + 1 + i) & 0xFF);                                  // β(i)
    rcmy[j] = (i == 0) ? (unsigned char)(j + 17) : (unsigned char)((j + i) & 0xFF); // β(i-1) / GENESIS
    rcmb[j] = (unsigned char)(j + 33);                                              // fixed → EPOCH_R
  }
  unsigned char* proof = nullptr; size_t plen = 0;
  int pr = pqpool_reserve_yield_prove(K, MODULUS, R, x, rcmx,16, rcmy,16, rcmb,16, R,
                                      &proof, &plen, pub, 128);
  if (pr != 1) return false;
  proof_out.assign(proof, proof + plen);
  pqpool_free(proof, plen);
  return true;
}

int main() {
  const int N = 5;
  unsigned char pub[N][128];
  std::vector<unsigned char> proof[N];
  for (uint64_t i = 0; i < (uint64_t)N; ++i)
    if (!produce(i, pub[i], proof[i])) { printf("produce block %llu FAILED\n", (unsigned long long)i); return 1; }

  unsigned char EPOCH_R[32], GENESIS[32];
  memcpy(EPOCH_R, pub[0] + 96, 32);   // canonical cm_b
  memcpy(GENESIS, pub[0] + 32, 32);   // canonical cm_S_old (first-block anchor)
  printf("EPOCH_R=%02x%02x..%02x  GENESIS_CM_S=%02x%02x..%02x\n",
         EPOCH_R[0],EPOCH_R[1],EPOCH_R[31], GENESIS[0],GENESIS[1],GENESIS[31]);

  bool all = true;
  for (uint64_t i = 0; i < (uint64_t)N; ++i) {
    bool cmb_ok    = memcmp(pub[i] + 96, EPOCH_R, 32) == 0;                          // cm_b == EPOCH_R
    const unsigned char* expected = (i == 0) ? GENESIS : (pub[i-1] + 0);             // parent cm_S_new
    bool cms_chain = memcmp(pub[i] + 32, expected, 32) == 0;                          // cm_S_old(i)==expected
    bool proof_ok  = pqpool_reserve_yield_verify(proof[i].data(), proof[i].size(), pub[i], 128, K, MODULUS) == 1;
    bool ok = cmb_ok && cms_chain && proof_ok;
    printf("block %llu: cm_b==EPOCH_R=%d  cm_S_old==parent_cm_S_new=%d  proof=%d -> %s\n",
           (unsigned long long)i, cmb_ok, cms_chain, proof_ok, ok ? "OK" : "FAIL");
    all = all && ok;
  }
  printf("RY_PRODUCER_CHAIN_%s\n", all ? "OK" : "FAIL");
  return all ? 0 : 1;
}
