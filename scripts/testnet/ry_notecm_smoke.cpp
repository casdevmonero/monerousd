// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// Validate the wallet-side note_cm derivation matches the producer's on-chain note_cm (publics[64:96]).
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
extern "C" {
#include "pqpool_ffi.h"
}
int main() {
  const uint32_t k = 63; const uint64_t modulus = 0x0001000000000000ULL, r = 12345ULL;
  const uint64_t i = 2;                                  // mid-chain block index
  const uint64_t x = 0x0000500030001000ULL - i * r;
  unsigned char rcmx[16], rcmy[16], rcmb[16], pk_d[32], rho[32], rcm[32];
  for (int j = 0; j < 16; ++j) { rcmx[j]=(unsigned char)((j+1+i)&0xFF); rcmy[j]=(unsigned char)((j+i)&0xFF); rcmb[j]=(unsigned char)(j+33); }
  for (int j = 0; j < 32; ++j) { pk_d[j]=(unsigned char)((j*7+3)&0xFF); rho[j]=(unsigned char)((j+5+i)&0xFF); rcm[j]=(unsigned char)((j+9+i)&0xFF); }
  const uint32_t asset = 0u;
  unsigned char pub[128]; unsigned char *proof = nullptr; size_t plen = 0;
  int pr = pqpool_reserve_yield_prove_note(k, modulus, r, x, rcmx,16, rcmy,16, rcmb,16, r, asset, pk_d,32, rho,32, rcm,32, &proof, &plen, pub, 128);
  if (pr != 1) { printf("prove fail %d\n", pr); return 1; }
  pqpool_free(proof, plen);
  unsigned char notecm[32];
  int nr = pqpool_reserve_yield_note_cm(r, asset, pk_d,32, rho,32, rcm,32, notecm, 32);
  if (nr != 1) { printf("note_cm fail %d\n", nr); return 1; }
  bool match = std::memcmp(pub + 64, notecm, 32) == 0;   // publics[64:96] == recomputed note_cm
  printf("on-chain note_cm = %02x%02x..%02x ; recomputed = %02x%02x..%02x\n", pub[64],pub[65],pub[95], notecm[0],notecm[1],notecm[31]);
  printf("NOTECM_%s\n", match ? "OK" : "FAIL");
  return match ? 0 : 1;
}
