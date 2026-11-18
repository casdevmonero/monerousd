// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// CRY-3 verify LOGIC, tested standalone (the daemon module packages this; wiring into
// validate_miner_transaction is the follow-on). Proves the consensus checks are sound + fail-closed.
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
extern "C" {
#include "pqpool_ffi.h"
}

// v45 ReserveYield consensus constants (placeholders; deterministic from the fixed test proof).
static const uint8_t RY_EPOCH_R[32] = {
  0x6f,0x77,0x19,0x19,0x95,0xb8,0xc7,0x2a,0xc2,0x13,0x45,0x39,0xfb,0x05,0xdd,0x32,
  0x30,0xd4,0xff,0x74,0xae,0xd2,0xa3,0x7b,0x8f,0x26,0x91,0x33,0x82,0x84,0x10,0x79};
static const uint32_t RY_K = 63;
static const uint64_t RY_MODULUS = 0x0001000000000000ULL;

// Fail-closed v45 confidential reserve-yield coinbase verify.
// publics(128) = cm_S_new(32) | cm_S_old(32) | note_cm(32) | cm_b(32).
// expected_cm_S_old = GENESIS_CM_S (first RY block) or the selected-parent coinbase's cm_S_new.
bool verify_ry_coinbase(const std::vector<uint8_t>& publics,
                        const std::vector<uint8_t>& proof,
                        const std::vector<uint8_t>& expected_cm_S_old) {
  if (publics.size() != 128 || proof.empty() || expected_cm_S_old.size() != 32) return false;
  if (std::memcmp(publics.data() + 96, RY_EPOCH_R, 32) != 0) return false;               // cm_b == EPOCH_R
  if (std::memcmp(publics.data() + 32, expected_cm_S_old.data(), 32) != 0) return false; // cm_S_old == expected (conservation chain)
  return pqpool_reserve_yield_verify(proof.data(), proof.size(),
                                     publics.data(), publics.size(), RY_K, RY_MODULUS) == 1; // no-inflation proof
}

int main() {
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int i = 0; i < 16; ++i) { rcmx[i] = i + 1; rcmy[i] = i + 17; rcmb[i] = i + 33; }
  unsigned char pub[128]; unsigned char* proof = nullptr; size_t plen = 0;
  int pr = pqpool_reserve_yield_prove(RY_K, RY_MODULUS, 12345, 0x0000500030001000ULL,
                                      rcmx, 16, rcmy, 16, rcmb, 16, 12345,
                                      &proof, &plen, pub, 128);
  if (pr != 1) { printf("prove failed=%d\n", pr); return 1; }
  std::vector<uint8_t> publics(pub, pub + 128), pf(proof, proof + plen);
  std::vector<uint8_t> cm_S_old(pub + 32, pub + 64);  // the proof's own cm_S_old

  bool honest      = verify_ry_coinbase(publics, pf, cm_S_old);            // want 1
  std::vector<uint8_t> badpub = publics; badpub[96] ^= 1;                  // tamper cm_b
  bool tamper_cmb  = verify_ry_coinbase(badpub, pf, cm_S_old);             // want 0 (cm_b != EPOCH_R + proof binds publics)
  std::vector<uint8_t> wrongS(32, 0xAB);
  bool wrong_cmS   = verify_ry_coinbase(publics, pf, wrongS);              // want 0 (surplus-chain break)
  pqpool_free(proof, plen);

  printf("honest=%d(1)  tamper_cmb=%d(0)  wrong_cmS=%d(0)\n", honest, tamper_cmb, wrong_cmS);
  bool pass = honest && !tamper_cmb && !wrong_cmS;
  printf("RY_VERIFY_LOGIC_%s\n", pass ? "OK" : "FAIL");
  return pass ? 0 : 1;
}
