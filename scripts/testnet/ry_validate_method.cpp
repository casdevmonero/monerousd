// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//------------------------------------------------------------------
// v45 Confidential Reserve-Yield coinbase verifier (no-inflation enforcement).
// Fail-closed. Extracts the block's tx_extra_reserve_yield attestation, threads the
// surplus-conservation chain (cm_S_old must equal the selected-parent coinbase's
// cm_S_new, or GENESIS_CM_S for the first reserve-yield block), and delegates to the
// glue consensus verify (cm_b==EPOCH_R + STARK proof). base_reward is forced to 0 so
// the hidden reward is never AGC-tracked (abolish-the-total).
bool Blockchain::validate_reserve_yield_coinbase(const block& b, uint64_t block_height, uint64_t& base_reward)
{
  base_reward = 0;
  std::vector<cryptonote::tx_extra_field> fields;
  cryptonote::tx_extra_reserve_yield ry;
  if (!cryptonote::parse_tx_extra(b.miner_tx.extra, fields) ||
      !cryptonote::find_tx_extra_field_by_type(fields, ry)) {
    MERROR_VER("v45 coinbase: missing tx_extra_reserve_yield (height " << block_height << ")");
    return false;
  }
  const std::vector<uint8_t> publics(ry.publics.begin(), ry.publics.end());
  const std::vector<uint8_t> proof(ry.proof.begin(), ry.proof.end());
  if (publics.size() != 128) { MERROR_VER("v45 coinbase: bad publics size " << publics.size()); return false; }

  // GENESIS_CM_S — the surplus commitment anchoring the first reserve-yield block.
  static const unsigned char GENESIS_CM_S[32] = {
    0xf0,0xab,0x40,0x14,0xba,0x4e,0x61,0x0c,0x83,0xc6,0x42,0x63,0x26,0x95,0x01,0x68,
    0xe3,0x71,0x60,0x1a,0xec,0xec,0xf1,0x05,0xf6,0x1a,0x8e,0x12,0xb6,0xaa,0xa3,0x5a};
  std::vector<uint8_t> expected_cm_S_old;
  bool first_ry = true;
  try {
    const block parent = m_db->get_block(b.prev_id);
    if (parent.major_version >= HF_VERSION_RESERVE_YIELD) {
      std::vector<cryptonote::tx_extra_field> pfields;
      cryptonote::tx_extra_reserve_yield pry;
      if (cryptonote::parse_tx_extra(parent.miner_tx.extra, pfields) &&
          cryptonote::find_tx_extra_field_by_type(pfields, pry) &&
          pry.publics.size() == 128) {
        expected_cm_S_old.assign(pry.publics.begin(), pry.publics.begin() + 32);  // parent cm_S_new
        first_ry = false;
      } else {
        MERROR_VER("v45 coinbase: v45 parent lacks a valid reserve-yield attestation (chain break)");
        return false;  // fail-closed: a v45 parent MUST carry the surplus chain
      }
    }
  } catch (const std::exception &e) {
    MERROR_VER("v45 coinbase: parent fetch failed: " << e.what());
    return false;
  }
  if (first_ry) expected_cm_S_old.assign(GENESIS_CM_S, GENESIS_CM_S + 32);

  if (!cryptonote::pqpool_transition::reserve_yield_coinbase_verify(
        proof, publics, expected_cm_S_old, 63, 0x0001000000000000ULL)) {
    MERROR_VER("v45 coinbase: reserve-yield verification FAILED (height " << block_height << ")");
    return false;
  }
  return true;
}
