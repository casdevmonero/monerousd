// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ KILL LIST §AG FAILURE CLASS 9 — A BYTE BUFFER SIZED BY A LANE COUNT. THE GATE.
//!
//! `DIGEST_LANES` moved from 4 to 8 on 2026-09-12 and every hand-rolled `for (i, slot) in
//! out.iter_mut().enumerate()` over a THIRTY-TWO byte source kept compiling. Two shapes came out of it:
//!
//!   * the PANIC — `src[i*8..i*8+8]` reads past a 32-byte buffer at lane 4, `range end index 40 out of
//!     range for slice of length 32`. MEASURED 2026-09-13 on LIVE DOORS: `/get_membership_acc`,
//!     `/membership_transition`, `/get_nf_unspent_acc`, `/membership_roots`, `/post_order`, the sovereign
//!     token-create fee gate, and `adopt_ladder_span` — a PEER-served blob that crashed the node. A
//!     `try_from(..).unwrap_or(..)` never helped: the slice index panics first.
//!   * the SILENT HALF-WIDTH — `for i in 0..4` leaves lanes 4..7 zero, or writes lanes 0..3 and drops the
//!     rest. No panic; a 124-bit value where the tree widened to 248, or a commitment that is half a
//!     commitment on the wire (the DSOL commit, the coinbase `miner_commitment`, the faucet spend key, the
//!     peg reserve/minted commitments). The `spent_leaf` defect (§AI) was the same trap: `lanes_of(&[x; 4])`
//!     and `[x; 8]` both read as "a row of x" and are DIFFERENT constants.
//!
//! A grep is not a gate. This module EXECUTES the property on every helper that maps bytes into a digest
//! or a digest into bytes, and then proves its own registry is complete against the source tree:
//!
//!   1. every bytes→digest HASHER is total over a panel of 32-byte inputs and populates EVERY lane;
//!   2. every bytes→digest DECODER is total over every length (never a panic on a short or long buffer),
//!      refuses a non-canonical encoding, and round-trips a full-width digest;
//!   3. every digest→bytes ENCODER has the declared width, BINDS every lane (a change in lane 7 changes the
//!      bytes — this is the truncation detector), and round-trips through its paired decoder;
//!   4. every fn in `src/` whose signature maps bytes↔digest is in the registry above, and every hand-rolled
//!      lane walk (`x * 8..x * 8 + 8`) over a digest outside the ONE definition fails — so the next helper
//!      cannot be added without being gated, and the next lane walk cannot be added at all (no marker excuses one).
//!
//! ⭐ CALIBRATION (refutation-before-green): the encoder and hasher checks re-run themselves against the
//! deliberately truncating four-lane shapes and assert they FIRE, so a green run means the detectors are armed.
//!
//! ROOT-LAYER: the property is executed on the helpers that PRODUCE a digest's byte form and RECOVER it
//! (`spend_frontier` / `poseidon2_compress` one-definitions, the ladder slot codec, the nullifier key), not
//! on any route that merely reads one — a route that delegates cannot go stale; a helper that walks lanes can.
//! MEASURED: 2026-09-13, before the sweep, on the unmodified test binary: `rpc_http.rs:3258` and `:3221`
//! (`/get_membership_acc`, `/membership_transition`) and `sovereign.rs:1293` panicked `range end index 40 out
//! of range for slice of length 32`; `node.rs:19447` panicked `range end index 72 out of range for slice of
//! length 64`; `node.rs:35356` failed "a SPENT nf cannot build an absence proof" because the planted tag was
//! the digest's lanes 0..3 — 7 red pins from one class. After: every registered helper is total over the panel
//! and full-width; the calibration specimens (the exact pre-fix shapes) are caught.
//! MUST-STAY-GREEN: `get_nf_unspent_acc_route_serves_the_live_a_tip`, both `/get_membership_acc` route pins,
//! `two_nodes_answer_a_membership_transition_query_identically…`, `node_maintains_o1_nf_unspent_acc…`,
//! `a_held_ladder_root_that_disagrees…`, `a_fabricated_fee_note_buys_nothing` and its honest twin, and every
//! calibration test in this module — a detector that stops firing on its specimen is a detector that is off.

#[cfg(all(test, feature = "pins-core"))]
mod gate {
    use crate::spend_frontier::{Digest4, DIGEST_LANE_BYTES, NOTE_CM_BYTES};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use usdm_decider::poseidon2_compress::{
        digest_from_bytes, digest_to_bytes, hash32_to_digest, zero_digest, DIGEST_LANES,
    };

    const KB_P: u64 = 2_130_706_433;

    /// A digest with EVERY lane non-zero, distinct, and canonical — lanes 4..7 included, which is the half
    /// a four-lane loop never touches.
    fn full_width() -> Digest4 {
        core::array::from_fn(|i| 1_000_003 * (i as u64 + 1) + 17)
    }

    /// The input panel every hasher must survive: the all-zero id, the all-ones id, an id with only bit
    /// 255 set (outside the 248-bit canonical encoding), a real blake3 output, and a canonical encoding of
    /// a full-width digest.
    fn panel() -> Vec<(&'static str, [u8; 32])> {
        let mut top = [0u8; 32];
        top[31] = 0x80;
        vec![
            ("zero", [0u8; 32]),
            ("ones", [0xFFu8; 32]),
            ("bit255", top),
            ("blake3", *blake3::hash(b"AG class 9 panel").as_bytes()),
            ("canonical", digest_to_bytes(&full_width())),
        ]
    }

    // ───────────────────────────── THE REGISTRY ─────────────────────────────
    // Every name here is checked against the source scan below; a bytes↔digest fn in `src/` that is not
    // listed fails `every_digest_helper_in_src_is_registered`.

    type Hasher = Box<dyn Fn(&[u8; 32]) -> Digest4>;
    type Decoder = Box<dyn Fn(&[u8]) -> Option<Digest4>>;
    type Encoder = Box<dyn Fn(&Digest4) -> Vec<u8>>;

    /// Maps from 32 ARBITRARY bytes into a digest — total by contract, full width by contract.
    fn hashers() -> Vec<(&'static str, Hasher)> {
        vec![
            ("hash32_to_digest", Box::new(|b| hash32_to_digest(b))),
            // DB-273's OLI filing domain digest: a one-line wrapper over `hash32_to_digest`, registered so the gate
            // EXECUTES it (every lane populated over a 32-byte input), not merely allows it.
            ("filing_d_digest", Box::new(|b| crate::oli::filing_d_digest(b))),
            ("cm_bytes_to_leaf", Box::new(|b| crate::spend_frontier::cm_bytes_to_leaf(b))),
            // §BR-14 item 4: a creation's fee-burn opening from its derived asset id — a domain-tagged hash through the
            // registered `cm_bytes_to_leaf`, executed here so every lane populates over a 32-byte id.
            ("creation_burn_opening", Box::new(|b| crate::asset_tx::creation_burn_opening(b))),
            // §BR-12 L1: a contract deploy's fee-burn opening from its cid — the same domain-tagged shape as a creation's.
            ("deploy_burn_opening", Box::new(|b| crate::dsol_deploy_tx::deploy_burn_opening(b))),
            // §BR-12 L2: a call's publisher-fee note seed from its cid and tx hash — a domain-tagged hash through the registered
            // `cm_bytes_to_leaf`, executed here over a fixed second half so every lane populates.
            ("publisher_fee_seed", Box::new(|b| crate::dsol_call_tx::publisher_fee_seed(b, &[0x7fu8; 32]))),
            // §BR-3 17.3: a delegation's burn opening from its minted note's commitment — the same shape.
            ("delegation_burn_opening", Box::new(|b| crate::sat_delegation_tx::delegation_burn_opening(b))),
            // §BR-6: an entry-mix output's burned-output opening from the output script — a domain-tagged hash through the
            // registered `cm_bytes_to_leaf`, executed here so every lane populates over a 32-byte script.
            ("output_opening", Box::new(|b| crate::entry_mix::output_opening(&crate::entry_mix::RoundTerms { round_id: [7u8; 32], denom: 100_000, fee_rate_sat_vb: 2, coordinator_pk: Vec::new() }, b))),
            // §BR-3 17.5: a theft repayment's per-leg blind from its seed — a keyed hash through the registered cm_bytes_to_leaf.
            ("theft_repay_blind", Box::new(|b| crate::peg::theft_repay_blind(b, 2))),
            // §BR-3 17.5 layer 1: a pot fill's burned-output opening from the SAT note's commitment — the delegation's shape.
            ("pot_burn_opening", Box::new(|b| crate::pot_fill_tx::pot_burn_opening(b))),
            // §BR-4 B4-3: a unit close's two burned-output openings from the ticket's commitment (and the unit's nullifier) —
            // domain-tagged hashes through the registered cm_bytes_to_leaf, executed over a 32-byte input.
            ("unit_burn_opening", Box::new(|b| crate::unit_close_tx::unit_burn_opening(&crate::debt_units::UnitTerms { k: 18, l: 2, day: 0, epoch: 0 }, b))),
            ("debt_burn_opening", Box::new(|b| crate::unit_close_tx::debt_burn_opening(&crate::debt_units::UnitTerms { k: 18, l: 2, day: 0, epoch: 0 }, b, b))),
            // §BR-5 B5-d: the escrow note's key parts and address key from the ticket key — keyed hashes into the field,
            // executed here so every lane populates over a 32-byte key.
            ("escrow_key_part", Box::new(|b| crate::cashout_ticket::escrow_key_part(b, b"ask"))),
            ("escrow_spk", Box::new(|b| crate::cashout_ticket::escrow_spk(b))),
            ("nf_to_limbs", Box::new(|b| usdm_decider::nf_sparse_air::nf_to_limbs(b))),
            ("nf_key", Box::new(|b| crate::nullifier_tree::nf_key(b))),
            ("bytes32_to_limbs", Box::new(|b| crate::whir_decider::bytes32_to_limbs(b))),
            ("blind_digest", Box::new(|b| crate::dsol::blind_digest(b))),
            ("note_seed_from_ss", Box::new(|b| crate::faucet::note_seed_from_ss(b))),
            // DB-395: the note opening `P(spk, seed(ss))` — the seed's map is the registered one above; executed here so the
            // opening populates every lane over a 32-byte secret too.
            ("note_opening", Box::new(|b| crate::faucet::note_opening(&full_width(), b))),
            // LIQUIDATION §10 v2: the per-leg blind from the liquidation seed — a one-line wrapper over `hash32_to_digest`.
            ("liquidation_blind", Box::new(|b| crate::peg::liquidation_blind(b, 3))),
            (
                "next_op_blind",
                Box::new(|b| crate::peg::PegLedger::next_op_blind(b, &full_width(), &full_width(), 7, 11)),
            ),
            ("hash_leaf", Box::new(|b| crate::nullifier_tree::hash_leaf(b, &[9u8; 32]))),
            // a lone spent leaf folded up `level` empty levels — a bit-walk over the id, never a lane walk
            // the id is a nullifier TAG; the tree walks its KEY (the DB-353 boundary converts once, here)
            ("fold_lone_leaf", Box::new(|b| crate::nf_sparse::RefSparseNf::fold_lone_leaf(&crate::nf_sparse::SparseKey::of(b), 5))),
            // §RF-3 §14: the header seed over a block's reals. Each note's first 32 bytes are absorbed as zeros (the
            // cm-free law), so the 32 panel bytes ride in a note's TAIL — a 32-byte note alone would map every input
            // to one digest.
            (
                "header_seed",
                Box::new(|b| {
                    let mut note = vec![0u8; 64];
                    note[32..].copy_from_slice(b);
                    crate::cover::header_seed(&note, &crate::cover::TEST_COVER_KEY)
                }),
            ),
        ]
    }

    /// Decoders of a produced digest's byte form: `(name, slot width, canonical, decoder, the encoder
    /// whose inverse it is)`. Total over every input length; `None` on the wrong length. `canonical`
    /// decoders also refuse a non-canonical encoding and only ever yield limbs `< p`; the RAW-LANE decoder
    /// is total over every `[u64; DIGEST_LANES]` BY CONTRACT (the membership accumulator is a wrapping
    /// sum whose limbs exceed the field), so canonicity is not part of its contract.
    fn decoders() -> Vec<(&'static str, usize, bool, Decoder, Encoder)> {
        vec![
            (
                "digest_from_bytes",
                32,
                true,
                Box::new(|b| <[u8; 32]>::try_from(b).ok().and_then(|a| digest_from_bytes(&a))),
                Box::new(|d| digest_to_bytes(d).to_vec()),
            ),
            (
                "cm_bytes_to_root",
                32,
                true,
                Box::new(|b| {
                    <[u8; 32]>::try_from(b).ok().and_then(|a| crate::spend_frontier::cm_bytes_to_root(&a))
                }),
                Box::new(|d| crate::spend_frontier::leaf_to_cm_bytes(*d).to_vec()),
            ),
            (
                "note_cm_of",
                NOTE_CM_BYTES,
                true,
                Box::new(|b| crate::spend_frontier::note_cm_of(b)),
                Box::new(|d| crate::spend_frontier::leaf_to_cm_bytes(*d).to_vec()),
            ),
            (
                "digest_from_lane_bytes",
                DIGEST_LANE_BYTES,
                false,
                Box::new(|b| crate::spend_frontier::digest_from_lane_bytes(b)),
                Box::new(|d| crate::spend_frontier::digest_to_lane_bytes(d).to_vec()),
            ),
            (
                "ladder_slot_decode",
                crate::node::Node::LADDER_SLOT_BYTES,
                true,
                Box::new(|b| crate::node::Node::ladder_slot_decode(b)),
                Box::new(|d| crate::node::Node::ladder_slot_encode(d).to_vec()),
            ),
        ]
    }

    /// Every digest→bytes encoder with its declared width. Each must BIND every lane.
    fn encoders() -> Vec<(&'static str, usize, Encoder)> {
        vec![
            ("digest_to_bytes", 32, Box::new(|d| digest_to_bytes(d).to_vec())),
            ("leaf_to_cm_bytes", 32, Box::new(|d| crate::spend_frontier::leaf_to_cm_bytes(*d).to_vec())),
            (
                "digest_to_lane_bytes",
                DIGEST_LANE_BYTES,
                Box::new(|d| crate::spend_frontier::digest_to_lane_bytes(d).to_vec()),
            ),
            (
                "ladder_slot_encode",
                crate::node::Node::LADDER_SLOT_BYTES,
                Box::new(|d| crate::node::Node::ladder_slot_encode(d).to_vec()),
            ),
            ("limbs_to_hash32", 32, Box::new(|d| crate::whir_decider::limbs_to_hash32(d).0.to_vec())),
            (
                "belimb_key",
                crate::nullifier_tree::NF_KEY_BYTES,
                // belimb_key hashes its 32-byte input first; feed it the canonical form so the digest it
                // orders is `nf_key(bytes)` — the lane-binding property is checked on THAT digest below.
                Box::new(|d| crate::nullifier_tree::belimb_key(&digest_to_bytes(d)).to_vec()),
            ),
            // Attestation messages and the sealed custodian opening carry digests as raw lanes: every lane
            // must reach the bytes, or a threshold signature / a seal binds half a commitment. The other
            // arguments are fixed; the property varies ONLY the digest under test (0 = no declared width:
            // these are messages, not slots — only the lane binding is checked).
            (
                "peg_in_confidential_msg",
                0,
                Box::new(|d| crate::peg::peg_in_confidential_msg(&[1u8; 32], d, &full_width(), &full_width(), &[2u8; 32], &[3u8; 32])),
            ),
            (
                // DB-80: the committed mint delta is attested too — every lane of it must reach the bytes.
                "peg_in_confidential_msg[delta_commit]",
                0,
                Box::new(|d| crate::peg::peg_in_confidential_msg(&[1u8; 32], &full_width(), &full_width(), d, &[2u8; 32], &[3u8; 32])),
            ),
            (
                "wrapped_mint_confidential_msg",
                0,
                Box::new(|d| crate::peg::wrapped_mint_confidential_msg(7, &[1u8; 32], &full_width(), d, &full_width(), &[2u8; 32])),
            ),
            (
                // DB-80b: the wrapped mint's committed delta is attested too — every lane must reach the bytes.
                "wrapped_mint_confidential_msg[delta_commit]",
                0,
                Box::new(|d| crate::peg::wrapped_mint_confidential_msg(7, &[1u8; 32], &full_width(), &full_width(), d, &[2u8; 32])),
            ),
            (
                "peg_out_confidential_msg",
                0,
                Box::new(|d| crate::peg::peg_out_confidential_msg(&[3u8; 32], d, &full_width(), &[9u8; 32], &[0u8; 32], &full_width(), &[0u8; 32], &[0u8; 32])),
            ),
            (
                "revalue_msg",
                0,
                Box::new(|d| {
                    let h = crate::liquidation_tx::LiquidationHeader {
                        epoch_id: 4,
                        asset_id: 2,
                        position_id: [5u8; 32],
                        retired_commit: full_width(),
                        seized_commit: full_width(),
                        new_reserve_commit: full_width(),
                        new_minted_commit: full_width(),
                        new_pool_t: full_width(),
                        new_pool_p: full_width(),
                        new_pool_s: full_width(),
                        pool_close: false,
                    };
                    let pool = crate::peg::PoolWords { t: full_width(), p: full_width(), s: full_width(), epoch: 1 };
                    crate::peg::revalue_msg(&h, d, &full_width(), &pool, 7)
                }),
            ),
            (
                "reserve_move_statement",
                0,
                Box::new(|d| crate::bond_tally::reserve_move_statement("BTC", b"dest", d, &[6u8; 32], 9)),
            ),
            (
                "seal_opening",
                0,
                Box::new(|d| crate::node::seal_opening(11, *d, 13, full_width())),
            ),
            // §BR-3 17.6: the stakers' pool paid-out opening rides the same seal codec (its first pair)
            ("seal_paid", 0, Box::new(|d| crate::node::seal_paid(11, *d))),
        ]
    }

    /// Names that appear as bytes↔digest signatures in `src/` and are deliberately NOT in the registry,
    /// each with the reason. Keep this list SHORT and every entry justified.
    const ALLOWED_UNREGISTERED: &[(&str, &str)] = &[
        ("state_root_of", "digest×bytes → digest: a domain fold of two roots, never inverted"),
        // §BR-3 17.5 layer 1: a pot fill's new-supply blind — a keyed hash over the registered liquidation seed and the request
        // digest, through the registered cm_bytes_to_leaf; never a lane conversion of its own.
        ("pot_fill_blind", "opening×digest → digest: a keyed hash through the registered cm_bytes_to_leaf, never inverted"),
        // §BR-6: the entry-mix output's commitment — asset_note_cm over the REGISTERED output_opening; and the coordinator's
        // signed record message over the registered digest_to_lane_bytes/leaf_to_cm_bytes of the root.
        ("output_cm", "terms×script → digest: asset_note_cm over the registered output_opening, never inverted"),
        // §BR-4 B4-3: a close's two leg blinds (the pot fill's shape, two domains) and the message custody signs over both legs.
        ("unit_close_blinds", "opening×digest → two digests: keyed hashes through the registered cm_bytes_to_leaf, never inverted"),
        ("unit_close_msg", "digest×four commitments → message bytes custody signs: the registered digest_to_lane_bytes inside a domain-separated message, never inverted"),
        ("pot_fill_msg", "digest×digest → message bytes custody signs: the registered digest_to_lane_bytes of two commitments inside a domain-separated message, never inverted"),
        ("record_msg", "round×root → message bytes: the registered leaf_to_cm_bytes of the root inside a signed message, never inverted"),
        // §BR-5 B5-d: the escrow note's nullifier in canonical bytes — the REGISTERED leaf_to_cm_bytes over the escrow owner's
        // nullifier of the escrow commitment; no lane arithmetic of its own.
        ("escrow_nf", "key×value×seed → nullifier bytes: registered leaf_to_cm_bytes over the owner's nullifier, never inverted"),
        // §BR-3 17.6: `solvency_commit_256` over the REGISTERED `seal_paid` opening — a commitment, never a lane conversion
        ("paid_commit_of", "seal → digest: solvency_commit_256 over the registered seal_paid opening, never inverted"),
        // §BR-14 item 4: the note commitment `asset_note_cm(price, USDm, creation_burn_opening(id))` — the opening is the
        // REGISTERED hasher above; this composes it with the decider's own commitment, never a lane conversion of its own.
        ("creation_burn_cm", "bytes×amount → digest: asset_note_cm over the registered creation_burn_opening, never inverted"),
        // §BR-12 L1: the deploy's burn commitment — the same composition over the registered deploy_burn_opening.
        ("deploy_burn_cm", "bytes×amount → digest: asset_note_cm over the registered deploy_burn_opening, never inverted"),
        // §BR-12 L2: the publisher-fee note's opening and commitment — compositions over the registered publisher_fee_seed.
        ("publisher_fee_opening", "bytes → Option<digest>: owner_opening over the registered publisher_fee_seed and a decoded spk"),
        ("publisher_fee_cm", "manifest×bytes → Option<digest>: asset_note_cm over publisher_fee_opening, never inverted"),
        // §BR-12 L1: the prover-side contract-state map's lookup — returns the leaf STORED under the key, computes nothing.
        ("get", "a map lookup (ContractStateTree::get): the leaf stored under a 32-byte key, no hash"),
        // §BR-2 (2026-10-28): the test depositor's Bitcoin key, derived from a deposit blind's canonical bytes through the
        // REGISTERED `digest_to_lane_bytes`; a keyed hash for a fixture, never a lane conversion of its own.
        ("test_depositor_secret", "test-only: blake3_derive over the registered digest_to_lane_bytes of a deposit blind → a fixture key"),
        ("test_depositor_x", "test-only: the x-only public key of test_depositor_secret; no digest arithmetic"),
        // §18/§19 (2026-10-28): fixture tag-list builders and the ledger builder — they COMPOSE registered encoders
        // (`leaf_to_cm_bytes`, `cm_bytes_to_root`) over whole tag lists and carriers; no lane arithmetic of their own.
        ("test_tag_list_registered", "test-only: a 32-tag fixture list over registered leaf_to_cm_bytes + its spend-or-decoy carrier"),
        ("test_tag_list_claiming", "test-only: the claiming send's fixture list, the same composition"),
        ("build_ledger_sets_with", "the ledger builder: tags in canonical bytes through registered cm_bytes_to_root; proves, never converts"),
        (
            "note_cm",
            "digest×bytes → cm bytes (DB-395): the USDm note commitment, a one-line composition of the REGISTERED note_opening \
             and leaf_to_cm_bytes over asset_note_cm; no lane arithmetic of its own",
        ),
        (
            "note_cm_asset",
            "digest×bytes → cm bytes (DB-395): note_cm for any asset tag — the same composition of registered helpers",
        ),
        (
            "spend_tx_from_carrier_for_test",
            "TEST-ONLY (DB-395): pools a proven spend; its digests pass straight to leaf_to_cm_bytes (registered)",
        ),
        (
            "test_spk_of_ek",
            "TEST-ONLY (DB-395): a fixture wallet's spend key from its ek — hash32_to_digest (registered) into owner_spk",
        ),
        ("test_spk_of_dk", "TEST-ONLY (DB-395): test_spk_of_ek over the ek a FIPS 203 dk embeds"),
        (
            "yc_note",
            "digest → note bytes: a TEST-ONLY rogue-role fixture over spend_frontier::leaf_to_cm_bytes (registered) that \
             zero-fills the note's tail; no lane arithmetic of its own",
        ),
        (
            "cover_filing_k",
            "digest×bytes → filing key (§RF-3 §10 C1): a blake3 derive-key PRF that absorbs EVERY lane of the seed \
             (`for v in seed`) and the cm; output is K_BYTES of XOF, never decoded back into lanes",
        ),
        (
            "cover_seed_commit_of",
            "digest → header word (§RF-3): seed_commit_native's lanes, each a canonical element as u32 LE, walked by \
             `lanes.iter()` (every lane, no fixed count); its one decoder is cover_seed_commit_lanes",
        ),
        (
            "build_ledger",
            "a ledger BLOCK BUILDER, not a codec (returns NoteTransition + its root): composes registered helpers, no lane \
             arithmetic of its own",
        ),
        ("build_ledger_with", "build_ledger with the bound flag — the same builder, the same registered helpers"),
        (
            "block_filing",
            "TEST-ONLY: the producer's filing laid by uniform_ledger_filing; seed passes through whole, no lane arithmetic",
        ),
        (
            "seq1_root_limbs",
            "bytes → digest: a TEST-ONLY one-line wrapper over spend_frontier::cm_bytes_to_root (registered), kept out of \
             the seq1 pin's body for the two-party census; no lane arithmetic of its own",
        ),
        (
            "root_in_column",
            "bytes → digest: a CELL SELECTOR over a PIR column; the decode is spend_frontier::digest_from_lane_bytes \
             (registered) on exactly ROOT_BYTES, no lane arithmetic of its own",
        ),
        (
            "outs_digest",
            "bytes×bytes → digest: a domain Poseidon2 fold of two roots, each decoded by cm_bytes_to_root (registered); \
             never inverted",
        ),
        ("nf_key_lt", "bytes×bytes → bool: an ordering, not a map into a digest"),
        ("empty_leaf", "() → digest constant"),
        ("zero_digest", "() → digest constant"),
        ("poseidon_pair", "digest×digest → digest"),
        ("letter_cm", "bytes → [u8; 32] blake3, not a digest"),
        ("fold_letter_acc", "[u8; 32] 256-bit integer accumulator, not a digest"),
        ("fold_account_acc", "Hash32 256-bit integer accumulator, not a digest"),
        ("account_write_leaf", "bytes → Hash32 blake3, not a digest"),
        ("bucket_leaf", "bytes → Hash32 blake3, not a digest"),
        ("note_kdf", "bytes → [u8; 32] blake3 KDF, not a digest"),
        (
            "fixed_levels",
            "cm → the witness's OWN captured siblings (`IncrementalWitness::captured_sibling`, already Digest4): a keyed \
             LOOKUP in the member-witness book, never a bytes→digest decode (DB-223 Q2 §12d L, lane-wallet)",
        ),
        // §AO. NOT a new bytes↔digest map: it is the DISPATCH between the two that already exist
        // (`cm_bytes_to_root` for a commitment, `cm_bytes_to_leaf` for a record leaf), both registered
        // and both executed by this gate. Registering it again would measure the same two maps twice.
        ("note_leaf_of", "digest-or-hash DISPATCH over cm_bytes_to_root / cm_bytes_to_leaf, both registered"),
        (
            "test_spend_tag_list",
            "digest → Hash32 list: a TEST fixture laying a spend's tag list (DB-329 §7f: nf, claim, pads); each digest is \
             encoded by leaf_to_cm_bytes (registered), no lane arithmetic of its own",
        ),
        (
            "test_tag_list",
            "digest×digest → Hash32 list: the TEST fixture test_spend_tag_list delegates to (a claiming send's list); each \
             digest is encoded by leaf_to_cm_bytes (registered), no lane arithmetic of its own",
        ),
        ("commit_u64", "u64×bytes → [u8; 32]: composes solvency_commit ∘ blind_digest ∘ leaf_to_cm_bytes, each gated"),
        ("note_for", "test-only note builder: `leaf_to_cm_bytes(cm)` into `note[..32]` (registered encoder)"),
        ("node_at", "sparse-tree LOOKUP by (level, id): a map read, not a map into a digest"),
        ("node_at_pub", "sparse-tree LOOKUP by (level, id): a map read, not a map into a digest"),
        ("node", "BandCursor's sparse-tree LOOKUP by (level, id) over the view plus its overlay: a map read, not a map into a digest"),
        ("base_node", "sparse-tree LOOKUP by (level, id): a map read, not a map into a digest"),
        // DB-110. bytes×digest → [u8; 32] blake3 COMMITMENT to a foreign address, the `letter_cm` class:
        // the output is never read back as lanes and has no inverse. Its only digest input is the blind,
        // which it reads through `digest_to_lane_bytes` — a registered encoder this gate already executes.
        ("redeem_commit", "bytes×digest → [u8; 32] blake3 commitment, not a digest; folds the blind via the registered digest_to_lane_bytes"),
        // DB-110. Composes blake3 ∘ `cm_bytes_to_root`, and that decoder is registered and executed here;
        // registering this too would measure the same map a second time under another name.
        ("redeem_blind_for", "composes blake3 ∘ cm_bytes_to_root (registered decoder); adds no new bytes↔digest map"),
    ];

    fn assert_canonical(name: &str, input: &str, d: &Digest4) {
        for (l, v) in d.iter().enumerate() {
            assert!(
                *v < KB_P,
                "{name}({input}): lane {l} = {v} is not a canonical limb (>= p) — a hasher must reduce into the field"
            );
        }
    }

    // ───────────────────────────── 1. HASHERS ─────────────────────────────

    #[test]
    fn every_hasher_is_total_and_populates_every_lane_over_a_32_byte_input() {
        for (name, f) in hashers() {
            let mut lane_seen_nonzero = [false; DIGEST_LANES];
            for (label, input) in panel() {
                let out = catch_unwind(AssertUnwindSafe(|| f(&input))).unwrap_or_else(|_| {
                    panic!("⛔ AG CLASS 9: `{name}` PANICKED on the {label} 32-byte input — a lane walk read past the buffer")
                });
                assert_canonical(name, label, &out);
                for (l, v) in out.iter().enumerate() {
                    lane_seen_nonzero[l] |= *v != 0;
                }
            }
            for (l, seen) in lane_seen_nonzero.iter().enumerate() {
                assert!(
                    seen,
                    "⛔ AG CLASS 9 (silent half): `{name}` left lane {l} ZERO on every panel input — a \
                     four-lane loop over an eight-lane digest"
                );
            }
        }
    }

    // ───────────────────────────── 2. DECODERS ─────────────────────────────

    #[test]
    fn every_decoder_is_total_over_every_length_refuses_non_canonical_and_round_trips() {
        let lengths = [0usize, 1, 7, 8, 16, 24, 31, 32, 33, 40, 48, 63, 64, 65, 96, 128, 1153];
        for (name, slot, canonical, dec, enc) in decoders() {
            for len in lengths {
                for fill in [0x00u8, 0x7f, 0xab, 0xff] {
                    let buf = vec![fill; len];
                    let out = catch_unwind(AssertUnwindSafe(|| dec(&buf))).unwrap_or_else(|_| {
                        panic!("⛔ AG CLASS 9: `{name}` PANICKED on a {len}-byte buffer (fill {fill:#x}) — a decoder must refuse, never crash")
                    });
                    if len < slot {
                        assert!(out.is_none(), "`{name}` accepted a {len}-byte buffer shorter than its {slot}-byte slot");
                    }
                    if let (Some(d), true) = (out, canonical) {
                        assert_canonical(name, "decoded", &d);
                    }
                }
            }
            // A non-canonical 32-byte form (bit 255 set) is refused by every canonical-form decoder.
            if canonical && slot == 32 {
                let mut top = vec![0u8; slot];
                top[31] = 0x80;
                assert!(dec(&top).is_none(), "`{name}` laundered a non-canonical encoding into a digest");
            }
            // Round trip of a FULL-WIDTH digest: every lane comes back, lanes 4..7 included.
            let d = full_width();
            let bytes = enc(&d);
            assert_eq!(bytes.len(), slot, "`{name}`'s paired encoder is not {slot} bytes wide");
            assert_eq!(
                dec(&bytes),
                Some(d),
                "⛔ `{name}` does not invert its encoder on a full-width digest — a lane was dropped or zero-filled"
            );
            // And an over-long buffer that STARTS with a valid slot: the note reader and the ladder slot
            // reader accept a longer payload (they read the FRONT); an exact-slot decoder refuses.
            let mut long = bytes.clone();
            long.extend_from_slice(&[0u8; 100]);
            let over = dec(&long);
            if name == "note_cm_of" || name == "ladder_slot_decode" {
                assert_eq!(over, Some(d), "`{name}` reads the FRONT of a longer payload");
            } else {
                assert!(over.is_none(), "`{name}` must refuse a buffer longer than its slot");
            }
        }
    }

    // ───────────────────────────── 3. ENCODERS ─────────────────────────────

    /// The property, as a function, so the calibration below can run it against a known-bad encoder.
    fn encoder_binds_every_lane(name: &str, width: usize, enc: &dyn Fn(&Digest4) -> Vec<u8>) -> Result<(), String> {
        let base = full_width();
        let bytes = enc(&base);
        if width != 0 && bytes.len() != width {
            return Err(format!("`{name}` is {} bytes wide, declared {width}", bytes.len()));
        }
        for l in 0..DIGEST_LANES {
            let mut moved = base;
            moved[l] = (moved[l] + 1) % KB_P;
            if enc(&moved) == bytes {
                return Err(format!(
                    "⛔ AG CLASS 9 (silent half): `{name}` does NOT bind lane {l} — a digest differing only in that lane encodes to the same bytes (TRUNCATION)"
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn every_encoder_has_its_declared_width_and_binds_every_lane() {
        for (name, width, enc) in encoders() {
            encoder_binds_every_lane(name, width, &*enc).unwrap_or_else(|e| panic!("{e}"));
        }
    }

    /// ⭐ CALIBRATION — the detector fires on the exact defect it exists to catch: the pre-fix
    /// `limbs_to_hash32` / `dsol::limbs_to_bytes` shape (lanes 0..3 as LE u64s into 32 bytes).
    #[test]
    fn the_lane_binding_detector_fires_on_a_four_lane_truncating_encoder() {
        let truncating = |d: &Digest4| -> Vec<u8> {
            let mut out = [0u8; 32];
            // This IS the class, reproduced on purpose as the calibration specimen (this file is skipped by the scan).
            for i in 0..4 {
                out[i * 8..i * 8 + 8].copy_from_slice(&d[i].to_le_bytes());
            }
            out.to_vec()
        };
        let verdict = encoder_binds_every_lane("four_lane_truncating", 32, &truncating);
        assert!(
            matches!(&verdict, Err(e) if e.contains("does NOT bind lane 4")),
            "the detector must name lane 4 as unbound on a four-lane encoder; got {verdict:?}"
        );
        // And the honest encoder passes the same function — the detector discriminates.
        assert!(encoder_binds_every_lane("digest_to_bytes", 32, &|d| digest_to_bytes(d).to_vec()).is_ok());
    }

    /// ⭐ CALIBRATION for the hasher check: a four-lane hasher (the pre-fix `blind4` / `note_sk_from_ss` /
    /// `bytes32_to_limbs` shape) is caught by the lane-population property, and the eight-lane walk over
    /// 32 bytes (the pre-fix `next_blind` / route shape) is caught by `catch_unwind`.
    #[test]
    fn the_lane_population_detector_fires_on_a_four_lane_hasher() {
        let four_lane = |b: &[u8; 32]| -> Digest4 {
            let mut l = zero_digest();
            // This IS the class, reproduced on purpose as the calibration specimen (this file is skipped by the scan).
            for i in 0..4 {
                let mut w = [0u8; 8];
                w.copy_from_slice(&b[i * 8..i * 8 + 8]);
                l[i] = u64::from_le_bytes(w) % KB_P;
            }
            l
        };
        let mut lane_seen = [false; DIGEST_LANES];
        for (_, input) in panel() {
            for (l, v) in four_lane(&input).iter().enumerate() {
                lane_seen[l] |= *v != 0;
            }
        }
        assert!(lane_seen[..4].iter().all(|s| *s), "a four-lane hasher populates lanes 0..3");
        assert!(lane_seen[4..].iter().all(|s| !*s), "and the detector sees lanes 4..7 silent — armed");
        let eight_lane_walk = |b: &[u8; 32]| -> Digest4 {
            let mut out = zero_digest();
            // This IS the class, reproduced on purpose as the calibration specimen (this file is skipped by the scan).
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap_or([0u8; 8]));
            }
            out
        };
        assert!(
            catch_unwind(AssertUnwindSafe(|| eight_lane_walk(&[0u8; 32]))).is_err(),
            "the eight-lane walk over 32 bytes must panic — that is the class, and `try_into().unwrap_or` never runs"
        );
    }

    // ───────────────────────────── 4. COMPLETENESS ─────────────────────────────

    /// A `#[cfg(test)]` walk of this crate's OWN SOURCE TREE (`CARGO_MANIFEST_DIR/src`) so the registry
    /// above is checked for completeness against the code. Test-time only: the node holds no state here
    /// and nothing about it is a function of chain height, blocks or notes.
    fn src_files() -> Vec<(String, String)> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut out = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(here) = stack.pop() {
            for e in std::fs::read_dir(&here).expect("src readable") {
                let p = e.expect("entry").path();
                // A folder is anything read_dir can open; everything else is a file.
                if std::fs::read_dir(&p).is_ok() {
                    stack.push(p);
                    continue;
                }
                let name = p.file_name().map(|n| n.to_string_lossy().to_string()).expect("a file has a name");
                if !name.ends_with(".rs") || name.contains(".pre") {
                    continue;
                }
                let rel = p.strip_prefix(&root).map(|r| r.to_string_lossy().to_string()).expect("under src/");
                out.push((rel, std::fs::read_to_string(&p).expect("readable")));
            }
        }
        out
    }

    fn is_digest_ty(t: &str) -> bool {
        let t = t.trim();
        t.ends_with("Digest4") || t.ends_with("poseidon2_compress::Digest") || t == "Digest"
            || t.ends_with("Option<Digest4>") || t.ends_with("Option<crate::spend_frontier::Digest4>")
    }
    fn is_bytes_ty(t: &str) -> bool {
        let t = t.trim();
        t.starts_with("&[u8") || t.starts_with("[u8") || t.contains("Hash32") || t.starts_with("&Vec<u8>") || t.starts_with("Vec<u8>")
    }
    fn is_ident_char(c: char) -> bool {
        matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
    }
    /// `name: type` → `type`, for one parameter.
    fn param_type(p: &str) -> Option<&str> {
        let k = p.chars().position(|c| c == ':')?;
        Some(&p[k + 1..])
    }

    #[test]
    fn every_digest_helper_in_src_is_registered() {
        let registered: std::collections::BTreeSet<&str> = hashers()
            .iter()
            .map(|(n, _)| *n)
            .chain(decoders().iter().map(|(n, _, _, _, _)| *n))
            .chain(encoders().iter().map(|(n, _, _)| *n))
            .collect();
        let allowed: std::collections::BTreeSet<&str> = ALLOWED_UNREGISTERED.iter().map(|(n, _)| *n).collect();
        let mut missing = Vec::new();
        for (file, text) in src_files() {
            if file.ends_with("digest_width_gate.rs") {
                continue;
            }
            for (name, params, ret) in fn_signatures(&text) {
                let param_tys: Vec<&str> = params.split(',').filter_map(param_type).collect();
                let bytes_in = param_tys.iter().any(|t| is_bytes_ty(t));
                let digest_in = param_tys.iter().any(|t| is_digest_ty(t));
                let bytes_to_digest = bytes_in && is_digest_ty(&ret) && !digest_in;
                let digest_to_bytes = digest_in && (ret.trim().starts_with("[u8") || ret.contains("Hash32") || ret.trim() == "Vec<u8>");
                if (bytes_to_digest || digest_to_bytes) && !registered.contains(name.as_str()) && !allowed.contains(name.as_str()) {
                    missing.push(format!("{file}: fn {name}({params}) -> {ret}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "⛔ AG CLASS 9 GATE: these bytes↔digest helpers are NOT registered in digest_width_gate — a \
             helper the gate does not execute is a helper that can go stale with the lane count. Register \
             each (or list it in ALLOWED_UNREGISTERED with a reason):\n  {}",
            missing.join("\n  ")
        );
    }

    /// Hand-rolled lane arithmetic — `x * 8..x * 8 + 8`, `(x + 1) * 8` — inside a function that works on a
    /// DIGEST (its body names `Digest`, `DIGEST_LANES`, `zero_digest` or `lanes_of`), outside the ONE
    /// definition (`digest_to_lane_bytes` / `digest_from_lane_bytes`) and outside the frozen persistence
    /// doors (which are `[u64; 4]` BY LAW and never read the live lane count), is the class waiting to
    /// happen again. There is NO comment that excuses a site: a walk over a digest either delegates to the
    /// one definition or is rewritten so its bound is the buffer's own length (zip/chunks), never `i * 8`.
    /// A 256-bit integer add, a base58 block, a `[u64; 3]` asset tag: no digest in the function, not the class.
    #[test]
    fn every_hand_rolled_lane_walk_over_a_digest_is_the_one_definition() {
        let walk = |line: &str| -> bool {
            let l = line.replace(' ', "");
            (l.contains("*8..") && l.contains("*8+8]")) || l.contains("+1)*8]") || (l.contains("*8..(") && l.contains("+1)*8"))
        };
        let digest_context = |body: &str| -> bool {
            body.contains("Digest") || body.contains("DIGEST_LANES") || body.contains("zero_digest") || body.contains("lanes_of")
        };
        let mut offenders = Vec::new();
        for (file, text) in src_files() {
            if file.ends_with("digest_width_gate.rs") || file.contains("persist_frozen_v") {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            // the line index where each fn starts, so a walk can be attributed to its enclosing fn body
            let fn_starts: Vec<(usize, String)> = lines
                .iter()
                .enumerate()
                .filter_map(|(i, line)| {
                    let t = line.trim_start();
                    let head = t.strip_prefix("pub(crate) fn ").or_else(|| t.strip_prefix("pub(super) fn ")).or_else(|| t.strip_prefix("pub fn ")).or_else(|| t.strip_prefix("fn "))?;
                    let end = match head.chars().position(|c| !is_ident_char(c)) {
                        Some(e) => e,
                        None => head.len(), // the whole remainder is the identifier
                    };
                    Some((i, head[..end].to_string()))
                })
                .collect();
            for (i, line) in lines.iter().enumerate() {
                if !walk(line) || line.trim_start().starts_with("//") {
                    continue;
                }
                // The INNERMOST fn whose brace-matched body contains this line — a nested `fn limbs3`
                // inside a route arm is its own function, and the arm's later code is not its body.
                let mut enclosing: Option<(usize, usize, String)> = None;
                for (s, n) in fn_starts.iter() {
                    if *s > i {
                        break;
                    }
                    let end = fn_body_end(&lines, *s);
                    if i < end {
                        enclosing = Some((*s, end, n.clone()));
                    }
                }
                let (fn_line, fn_end, fn_name) = enclosing.expect("a lane walk sits inside some fn");
                if fn_name == "digest_to_lane_bytes" || fn_name == "digest_from_lane_bytes" {
                    continue;
                }
                let body = lines[fn_line..fn_end].join("\n");
                if digest_context(&body) {
                    offenders.push(format!("{file}:{} (in `{fn_name}`): {}", i + 1, line.trim()));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "⛔ AG CLASS 9 GATE: hand-rolled lane walks over a digest outside the one definition. Delegate to \
             `digest_to_lane_bytes` / `digest_from_lane_bytes` / `leaf_to_cm_bytes` / `cm_bytes_to_root`, or \
             bound the walk by the buffer's own length (zip / chunks), never by `i * 8`:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// The line index one past the closing brace of the fn that starts at `start` — brace-matched from
    /// its first `{`, with braces inside `//` comments and string literals ignored well enough for source
    /// this crate writes. A fn with no body found runs to the end of the file.
    fn fn_body_end(lines: &[&str], start: usize) -> usize {
        let mut depth = 0i64;
        let mut opened = false;
        for (k, line) in lines.iter().enumerate().skip(start) {
            // a BYTE index (`find`), never `chars().position` — a char index slices inside a multi-byte '≥'
            let code = match line.find('/').and_then(|p| {
                let rest = &line[p..];
                if rest.starts_with("//") { Some(p) } else { None }
            }) {
                Some(p) => &line[..p],
                None => line,
            };
            let mut in_str = false;
            let mut prev = ' ';
            for c in code.chars() {
                if c == '"' && prev != '\\' {
                    in_str = !in_str;
                }
                if !in_str {
                    if c == '{' {
                        depth += 1;
                        opened = true;
                    } else if c == '}' {
                        depth -= 1;
                    }
                }
                prev = c;
            }
            if opened && depth <= 0 {
                return k + 1;
            }
        }
        lines.len()
    }

    /// A small signature extractor: `fn NAME(PARAMS) -> RET {` across line breaks. Deliberately simple —
    /// nested generics in params are tolerated because only the `name: type` pairs are inspected.
    fn fn_signatures(text: &str) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        let bytes = text.as_bytes();
        let mut i = 0usize;
        while i + 3 <= bytes.len() {
            // compare BYTES: `i` may sit inside a multi-byte char (⛔ is three bytes), where a `&str`
            // slice would panic; the match itself is ASCII so `i` is a char boundary once it matches.
            if bytes[i] != b'f' || bytes[i + 1] != b'n' || bytes[i + 2] != b' ' {
                i += 1;
                continue;
            }
            let start = i;
            i += 3;
            // must be a keyword position: preceded by whitespace or `)` (pub(crate) fn)
            if !(start == 0 || matches!(bytes[start - 1], b' ' | b'\n' | b'\t' | b')')) {
                continue;
            }
            let rest = &text[i..];
            let Some(paren) = rest.chars().position(|c| c == '(') else { break };
            let name = rest[..paren].trim();
            if name.is_empty() || !name.chars().all(is_ident_char) {
                continue;
            }
            // find the matching close paren
            let mut depth = 0usize;
            let mut close = None;
            for (j, c) in rest[paren..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            close = Some(paren + j);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(close) = close else { break };
            let params = rest[paren + 1..close].replace('\n', " ");
            let after = rest[close + 1..].trim_start();
            let ret = match after.strip_prefix("->") {
                Some(a) => match a.split(['{', ';']).next() {
                    Some(r) => r.replace('\n', " ").trim().to_string(),
                    None => String::new(), // `split` always yields one piece; kept explicit
                },
                None => String::new(),
            };
            out.push((name.to_string(), params, ret));
        }
        out
    }
}
