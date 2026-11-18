// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.


// ── v45 Confidential Reserve-Yield coinbase: CONSENSUS verify ──────────────
// publics(128) = cm_S_new(32) | cm_S_old(32) | note_cm(32) | cm_b(32).
// Fail-closed no-inflation enforcement:
//   (1) cm_b == EPOCH_R   — pins the hidden reward r so it cannot be inflated;
//   (2) cm_S_old == expected — the surplus commitment threaded from the
//       selected-parent coinbase (GENESIS_CM_S for the first reserve-yield
//       block); enforces the homomorphic conservation chain S_new = S_old - r;
//   (3) the STARK proof verifies (range + conservation + fixed-draw).
static const unsigned char RY_EPOCH_R_COMMITMENT[32] = {
  0x6f,0x77,0x19,0x19,0x95,0xb8,0xc7,0x2a,0xc2,0x13,0x45,0x39,0xfb,0x05,0xdd,0x32,
  0x30,0xd4,0xff,0x74,0xae,0xd2,0xa3,0x7b,0x8f,0x26,0x91,0x33,0x82,0x84,0x10,0x79};

bool reserve_yield_coinbase_verify(const std::vector<uint8_t> &proof,
                                   const std::vector<uint8_t> &publics,
                                   const std::vector<uint8_t> &expected_cm_S_old,
                                   uint32_t k, uint64_t modulus) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  if (proof.empty() || publics.size() != 128 || expected_cm_S_old.size() != 32) return false;
  if (std::memcmp(publics.data() + 96, RY_EPOCH_R_COMMITMENT, 32) != 0) return false;   // cm_b == EPOCH_R
  if (std::memcmp(publics.data() + 32, expected_cm_S_old.data(), 32) != 0) return false; // cm_S_old == expected
  return ::pqpool_reserve_yield_verify(proof.data(), proof.size(),
                                       publics.data(), publics.size(), k, modulus) == 1;
#else
  (void)proof; (void)publics; (void)expected_cm_S_old; (void)k; (void)modulus;
  return false;
#endif
}

// ── CRY-8 adversarial gate: the wired verifier MUST REJECT over-reward ──────
// Compiled into the daemon + run at startup. Produces a canonical valid coinbase,
// asserts ACCEPT, then asserts two over-reward forgeries are REJECTED:
//   (1) tampered reward commitment cm_b (would raise the hidden draw r),
//   (2) broken surplus-conservation chain (cm_S_old != parent cm_S_new).
// Returns true iff accept && reject(cm_b) && reject(cm_S). A false here is a
// no-inflation soundness failure and MUST block reserve-yield activation.
bool reserve_yield_adversarial_gate(uint32_t k, uint64_t modulus) {
#if defined(MONEROUSD_HAVE_PQPOOL_FFI)
  unsigned char rcmx[16], rcmy[16], rcmb[16];
  for (int i = 0; i < 16; ++i) { rcmx[i]=(unsigned char)(i+1); rcmy[i]=(unsigned char)(i+17); rcmb[i]=(unsigned char)(i+33); }
  unsigned char pub[128]; unsigned char *proof = nullptr; size_t plen = 0;
  if (::pqpool_reserve_yield_prove(k, modulus, 12345ULL, 0x0000500030001000ULL,
                                   rcmx,16, rcmy,16, rcmb,16, 12345ULL,
                                   &proof, &plen, pub, 128) != 1) return false;
  std::vector<uint8_t> publics(pub, pub + 128), pf(proof, proof + plen);
  std::vector<uint8_t> cm_S_old(pub + 32, pub + 64);    // the canonical proof's own cm_S_old
  ::pqpool_free(proof, plen);
  const bool honest     = reserve_yield_coinbase_verify(pf, publics, cm_S_old, k, modulus);         // accept
  std::vector<uint8_t> tampered_cmb = publics; tampered_cmb[96] ^= 1;                                // raise r
  const bool reject_cmb = !reserve_yield_coinbase_verify(pf, tampered_cmb, cm_S_old, k, modulus);    // reject
  std::vector<uint8_t> wrong_cmS(32, 0xAB);                                                          // fake surplus
  const bool reject_cms = !reserve_yield_coinbase_verify(pf, publics, wrong_cmS, k, modulus);        // reject
  return honest && reject_cmb && reject_cms;
#else
  (void)k; (void)modulus;
  return false;
#endif
}
