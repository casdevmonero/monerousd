// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE WIRE FAMILY — hostile-but-well-formed bytes, generated PER CLASS from the class table.**
//!
//! This is the fuzz family the design calls the cheapest and highest-yield in the whole harness, and the
//! reason is its shape: it is not a hand-written test per decoder, it is a family GENERATED from
//! `chain_object::Class`. The match over `Class` below is exhaustive, so a sixth class added tomorrow
//! fails to compile until it is given a canonical value — the coverage cannot silently fall behind the
//! class table, which is exactly how the fifth decoder came to be uncovered the first time.
//!
//! ## THE PROPERTY: I-12, ONE OBJECT, ONE ENCODING
//!
//! A transaction's identity is `blake3(blob)`. If two DIFFERENT byte strings decode to the SAME object,
//! then one object has two identities — the pool's by-id dedup goes blind, one object occupies unbounded
//! pool slots (I-5) and can ride a block more than once (I-1). So for every class decoder:
//!
//! ```text
//!   decode(canonical(x) ‖ junk) must be ⊥   for every non-empty junk
//! ```
//!
//! ## WHY THIS FILE IS ALSO THE LANE'S SELF-PROOF
//!
//! `postcard::from_bytes` deserialises a PREFIX and ignores the tail. Every class decoder in this tree
//! used it until 2026-09-06, when the red team measured **5 of 5 decoders RED** with 7 junk bytes
//! appended, and the fix was one shared `chain_object::decode_exact` built on `take_from_bytes` plus an
//! empty-remainder demand.
//!
//! Both decoders are run here, over the SAME generated family, with the SAME oracle:
//!
//! | door under test | what it is | expected |
//! |---|---|---|
//! | `chain_object::decode_exact` | the tree as it stands today | every padded blob REFUSED |
//! | `postcard::from_bytes` | the pre-fix decoder, called exactly as `chain_object.rs.preHoleClose-20260906` called it | every padded blob ACCEPTED — the hole |
//!
//! ⛔ WHAT THIS IS AND IS NOT. It is a decoder-level replay of a historical hole using the ACTUAL
//! pre-fix call, not a re-injection tuned until the harness notices it: the generator comes from the
//! class table, the oracle is fixed, and the same family runs against both doors. It is NOT a build of
//! the whole pre-fix tree, so it demonstrates detection power for the wire-malleability CLASS and not for
//! every hole in the calibration set. Both halves of that sentence belong in any report that cites it.

use crate::chain_object::{decode_exact, Class};

/// Every class the mempool may carry. Exhaustive by construction: `Class` has no `_` arm anywhere in this
/// file, so adding a sixth class breaks the build here until it is given a canonical value.
pub const CLASSES: [Class; 56] = [
    // ⭐ A-F114 — a payout's release, listed the day the class landed.
    Class::ReleaseConfirm,
    // ⭐ SAFE AT SCALE, stage three — part of a vault's ledgers moves to another vault, listed the day the class landed.
    Class::VaultRebalance,
    // ⭐ SAFE AT SCALE, stage three — a vault takes or retires a custody key, listed the day the class landed.
    Class::VaultKey,
    // ⭐ SAFE AT SCALE — the custody vault merge, listed the day the class landed.
    Class::VaultMerge,
    // ⭐ SAFE AT SCALE — a vault's reserve less a foreign fee, listed the day the class landed.
    Class::ReserveCost,
    Class::OrderFill,
    Class::OrderPost,
    Class::BridgeCredit,
    Class::AssetCreate,
    Class::AssetMint,
    // The ratio class joins the family the day it is added, which is what this constant's own doc demands:
    // a new class must be given a canonical value here rather than quietly skipping the tail coverage.
    Class::WrappedAssetRegister,
    Class::WrappedMint,
    // ⛔ LIQUIDATION WAS QUIETLY SKIPPED. It has had a `canonical` arm and a door arm since it landed and
    // was simply never listed here, so the tail-tolerance family never covered the one class that SEIZES
    // COLLATERAL. Exactly the silent gap this constant's doc warns about, found by adding the next class.
    Class::Liquidation,
    // ⭐ §BR-3 17.5 — the theft repayment, listed the day the class landed.
    Class::TheftRepayment,
    // ⭐ §BR-3 17.5 layer 1 — the pot fill, listed the day the class landed.
    Class::PotFill,
    // ⭐ §BR-8 — the decoy booking and return, listed the day the classes landed.
    Class::DecoyBatch,
    Class::DecoyReturn,
    // ⭐ §BR-4 B4-2 — the unit open, listed the day the class landed.
    Class::UnitOpen,
    // ⭐ §BR-4 B4-3 — the unit close, listed the day the class landed.
    Class::UnitClose,
    Class::AssetSpend,
    // ⭐ §CS — the native BTC/XMR peg-in, the route USDm is issued through. Listed the day the class
    // landed, so the tail-tolerance family covers the PRIMARY ISSUANCE object from its first hour.
    Class::PegIn,
    Class::PegOut,
    Class::YieldClaim,
    Class::MembershipBond,
    // ⛔ UNBOND AND PRICEMARK WERE QUIETLY SKIPPED (found 2026-09-26 adding Equivocation): both pool-carried, both
    // with a canonical arm and door arms, never listed — the Liquidation miss a second time. The list is now
    // pinned against the framing layer (`every_class_the_framing_layer_accepts_is_in_the_tail_family`).
    Class::Unbond,
    Class::PriceMark,
    // ⛔ DB-266 — equivocation evidence, listed the day the class landed.
    Class::Equivocation,
    // ⛔ G2 (2026-10-22) — a carried finality vote, listed the day the class landed.
    Class::FinalityVote,
    // ⭐ DB-313 §3 — the welded class's block-level aggregate, listed the day the class landed.
    Class::BondTransition,
    // ⭐ SATOSHI — the mining reward (credit-set only, never pooled), listed the day the class landed.
    Class::SatoshiReward,
    // ⭐ §BR-11 — the miner pool's per-block payout (credit-set only, never pooled), listed the day the class landed.
    Class::MinerPayout,
    // ⭐ §BR-3 17.3 — the delegated-SAT conversion, listed the day the class landed.
    Class::SatDelegation,
    // ⭐ §BR-3 17.6 — a validator's own-weight yield claim, listed the day the class landed.
    Class::BondYieldClaim,
    // ⭐ §BR-10 — the bug bounty from the surplus buffer, listed the day the class landed.
    Class::BountyPayout,
    // ⭐ §BR-13 — the canonical SAT set-aside, listed the day the class landed.
    Class::SatSetAside,
    // ⭐ §BR-10 — a validator's deployment signal, listed the day the class landed.
    Class::DeploymentSignal,
    // ⭐ §BR-10 — a builder's release attestation, listed the day the class landed.
    Class::ReleaseAttestation,
    // ⭐ §BR-9a — a custodian's epoch-key deal, listed the day the class landed.
    Class::EpochKeyDeal,
    // ⭐ §BR-9a — an epoch-key dealer's fraud proof, listed the day the class landed.
    Class::EpochKeyFraud,
    Class::SatBond,
    // ⛔ DB-274 P4b (§8.15) — reserve-theft evidence, listed the day the class landed.
    Class::ReserveTheft,
    // ⭐ LIQUIDATION §10 — the stability-pool deposit and withdrawal, each listed the day its class landed.
    Class::PoolDeposit,
    Class::PoolWithdraw,
    // ⭐ §BR-12 — the DSOL deploy, call and fee-update doors (their arms were written the day each landed; the list was not).
    Class::DsolDeploy,
    Class::DsolCall,
    Class::DsolFeeUpdate,
    // audit F15 — the paid directory entry, listed the day the class landed.
    Class::DirEntry,
    // IonSwap pools — the order and the settlement, listed the day the classes were written.
    Class::IonOrder,
    Class::IonSettle,
    // ⭐ §BR-15 — the private DeFi layer's order, settlement, expiry and claim (likewise: arms present, list caught up).
    Class::DefiOrder,
    Class::DefiSettle,
    Class::DefiExpire,
    Class::DefiClaim,
    Class::DefiHandover,
    Class::DefiSlots,
    // ⭐ Earn step 3 — the EarnEpoch (its state is the books', inside the ChainDerived `peg`)
    Class::DefiEarnEpoch,
];

/// §BR-15 §18.12 — the smallest order slot the strict decoder accepts.
fn defi_order_fixture() -> crate::defi_batch::DefiOrderTx {
    crate::defi_batch::DefiOrderTx {
        pair: 0,
        amount_commit: [1; 8],
        limit_commit: [3; 8],
        share_commits: vec![[2; 4]],
        epoch: 0,
        epoch_ct: vec![9u8; crate::epoch_key::CT_BYTES],
        sealed: vec![vec![3u8; crate::defi_batch::SEALED_BYTES]],
        share_proof: Vec::new(),
        nullifier: [4; 8],
        leaf_commit: [6; 8],
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        index: 0,
    }
}

/// §BR-15 §18.12 — the smallest claim slot the strict decoder accepts.
fn defi_claim_fixture() -> crate::defi_batch::DefiClaimTx {
    crate::defi_batch::DefiClaimTx {
        pair: 0,
        nullifier: [1; 8],
        leaf_commit: [2; 8],
        out_commit: [3; 8],
        pays_y: false,
        claim_proof: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
        mint_carrier: Vec::new(),
        note: vec![5u8; crate::cover::PQ_NOTE_BYTES],
        // a claim's clue is exactly the fixed width (`DefiClaimTx::shaped`, since ad8bef16): see `Class::DefiClaim` below
        owner_clue: vec![6u8; crate::peg_in_tx::OWNER_CLUE_MAX],
    }
}

/// A canonical, valid encoding for one class — the bytes a well-behaved publisher writes.
///
/// The VALUES are deliberately dull. The property under test is a property of the DECODER, not of the
/// object: whether a tail is tolerated does not depend on what the fields hold, so the fields hold the
/// smallest thing that round-trips. What matters is that these are the real wire types the real class
/// arms decode, produced by the real encoder.
pub fn canonical(class: Class) -> Vec<u8> {
    match class {
        // SATOSHI: the smallest reward its strict decoder accepts — key 0 at the first era's amount, a full-width note.
        Class::SatBond => {
            let (pk, _sk) = crate::pqauth::ml_dsa_keypair();
            crate::sat_bond_tx::SatBondTx {
                notes: [vec![1u8; crate::cover::PQ_NOTE_BYTES], vec![2u8; crate::cover::PQ_NOTE_BYTES]],
                nullifier: [3u8; 32],
                leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
                validity_carrier: vec![4u8; 4],
                membership_carrier: vec![5u8; 4],
                member_tuple: Vec::new(),
                named_record: 7,
                tip_prev: usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
                tip_root: usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
                tip_acc: usdm_decider::poseidon2_compress::lanes_of(&[13, 14, 15, 16]),
                weight: 11,
                vid: crate::pqauth::pubkey_id(&pk),
                pubkey: pk,
                sig: vec![6u8; 8],
                owner_clue: vec![3u8; 4],
                rebond: None,
            }
            .encode()
        }
        Class::SatoshiReward => crate::satoshi::SatoshiRewardTx {
            key: 0,
            amount: crate::satoshi::INITIAL_REWARD,
            note: vec![1u8; crate::cover::PQ_NOTE_BYTES],
            opening: [2u8; 32],
            owner_clue: vec![3u8; 4],
        }
        .encode(),
        Class::MinerPayout => crate::miner_payout_tx::MinerPayoutTx {
            key: 0,
            amount: 1,
            note: vec![1u8; crate::cover::PQ_NOTE_BYTES],
            opening: [2u8; 32],
            owner_clue: vec![3u8; 4],
        }
        .encode(),
        Class::ReleaseAttestation => crate::release_attestation_tx::ReleaseAttestationTx {
            release_hash: [0u8; 32],
            version: "0".into(),
            notes: String::new(),
            emergency: false,
            builder_pk: vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES],
            sig: vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES],
        }
        .encode(),
        Class::DeploymentSignal => crate::deployment_signal_tx::DeploymentSignalTx {
            vid: [0u8; 32],
            bits: 1,
            window: 0,
            pubkey: vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES],
            sig: vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES],
        }
        .encode(),
        Class::EpochKeyDeal => crate::epoch_deal_tx::EpochKeyDealTx {
            vid: [0u8; 32],
            epoch: 0,
            b: vec![0u8; crate::epoch_key::B_BYTES],
            shares: vec![crate::epoch_deal_tx::SealedShare {
                to: [1u8; 32],
                sealed: vec![2u8; crate::epoch_deal_tx::sealed_len()],
                commit: [3u8; 32],
            }],
            pubkey: vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES],
            sig: vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES],
        }
        .encode(),
        Class::EpochKeyFraud => crate::fixed::encode_plain(&crate::epoch_release::FraudProof {
            dealer: [0u8; 32],
            epoch: 0,
            shares: vec![([1u8; 32], vec![2u8; crate::epoch_deal_tx::SHARE_BYTES])],
        }),
        Class::SatSetAside => crate::sat_set_aside::SatSetAsideTx {
            note: vec![0u8; crate::cover::PQ_NOTE_BYTES],
            owner_clue: vec![1u8; 4],
            out1_cm: [0u8; 32],
            nullifier: [0u8; 32],
            input_opening: [0u8; 32],
            lc_blind: [0u8; 32],
            carrier: vec![2u8; 4],
        }
        .encode(),
        Class::BountyPayout => crate::bounty_payout_tx::BountyPayoutTx {
            nonce: [0u8; 32],
            amount: 1,
            note: vec![0u8; crate::cover::PQ_NOTE_BYTES],
            carrier: vec![1u8; 4],
            owner_clue: vec![2u8; 4],
            attestors: vec![(vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES], vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES])],
        }
        .encode(),
        Class::BondYieldClaim => crate::bond_yield_claim_tx::BondYieldClaimTx {
            vid: [0u8; 32],
            y_now: 1,
            amount: 1,
            note: vec![0u8; crate::cover::PQ_NOTE_BYTES],
            carrier: vec![1u8; 4],
            owner_clue: vec![2u8; 4],
            pubkey: vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES],
            sig: vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES],
        }
        .encode(),
        Class::SatDelegation => crate::sat_delegation_tx::SatDelegationTx {
            kind: crate::sat_delegation_tx::DelegationKind::Release { matures: 1 },
            amount: 1,
            nullifier: [0u8; 32],
            leaf_commit: [0u8; 32],
            burn_carrier: vec![1u8; 4],
            membership_carrier: vec![2u8; 4],
            membership_tip: vec![3u8; 4],
            change_note: vec![0u8; crate::cover::PQ_NOTE_BYTES],
            change_clue: vec![4u8; 4],
            minted_note: vec![0u8; crate::cover::PQ_NOTE_BYTES],
            mint_carrier: vec![5u8; 4],
            minted_clue: vec![6u8; 4],
            yield_note: vec![],
            yield_carrier: vec![],
            yield_clue: vec![],
            uptime: (0, 0),
        }
        .encode(),
        // LIQUIDATION §10.2: the smallest IN-BOUNDS pool withdrawal.
        Class::PoolWithdraw => {
            let lanes = usdm_decider::poseidon2_compress::lanes_of;
            let h = crate::pool_tx::PoolWithdrawHeader {
                asset_id: 0,
                epoch: 0,
                nullifier: [1u8; 32],
                leaf_commit: lanes(&[5, 0, 0, 0]),
                out_cm: lanes(&[3, 0, 0, 0]),
                dd: lanes(&[6, 0, 0, 0]),
                du: lanes(&[7, 0, 0, 0]),
                pd: lanes(&[8, 0, 0, 0]),
                sd: lanes(&[9, 0, 0, 0]),
                gain_commit: lanes(&[10, 0, 0, 0]),
                redeem_commit: [11u8; 32],
                new_t: lanes(&[12, 0, 0, 0]),
                pb: lanes(&[13, 0, 0, 0]),
                sb: lanes(&[14, 0, 0, 0]),
            };
            let mut out = crate::spend_frontier::leaf_to_cm_bytes(h.out_cm).to_vec();
            out.resize(48, 9);
            crate::pool_tx::encode_withdraw(&crate::pool_tx::PoolWithdrawDecoded {
                h,
                receipt_carrier: vec![1u8; 8],
                bridge_carrier: vec![6u8; 8],
                withdraw_carrier: vec![2u8; 8],
                transition_carrier: vec![3u8; 8],
                membership_carrier: vec![4u8; 8],
                membership_tip: vec![5u8; 8],
                out,
                owner_clues: vec![vec![0xC1u8; 16]],
                sealed: vec![([7u8; 32], vec![8u8; 16])],
                gain_sealed: vec![([7u8; 32], vec![9u8; 16])],
            })
        }
        // LIQUIDATION §10: the smallest IN-BOUNDS pool deposit — every carrier non-empty, a non-zero cross-bind, two notes
        // carrying the header's commitments, one owner clue each.
        Class::PoolDeposit => {
            let lanes = usdm_decider::poseidon2_compress::lanes_of;
            let h = crate::pool_tx::PoolDepositHeader {
                asset_id: 0,
                epoch: 0,
                nullifier: [1u8; 32],
                leaf_commit: lanes(&[5, 0, 0, 0]),
                receipt_cm: lanes(&[3, 0, 0, 0]),
                change_cm: lanes(&[4, 0, 0, 0]),
                dv: lanes(&[6, 0, 0, 0]),
                pd: lanes(&[7, 0, 0, 0]),
                sd: lanes(&[8, 0, 0, 0]),
                new_t: lanes(&[9, 0, 0, 0]),
            };
            let note_of = |cm: crate::spend_frontier::Digest4, fill: u8| {
                let mut n = crate::spend_frontier::leaf_to_cm_bytes(cm).to_vec();
                n.resize(48, fill);
                n
            };
            crate::pool_tx::encode(&crate::pool_tx::PoolDepositDecoded {
                h,
                deposit_carrier: vec![1u8; 8],
                snapshot_carrier: vec![2u8; 8],
                transition_carrier: vec![3u8; 8],
                membership_carrier: vec![4u8; 8],
                membership_tip: vec![5u8; 8],
                receipt: note_of(h.receipt_cm, 9),
                change: note_of(h.change_cm, 8),
                owner_clues: vec![vec![0xC1u8; 16], vec![0xC2u8; 16]],
                sealed: vec![([7u8; 32], vec![8u8; 16])],
            })
        }
        // ⭐ THE UNBOND'S REAL WIRE TYPE — a fixed-width header plus the three PQ blobs, produced by the
        // real encoder. Its PQ material is dull-but-well-formed: the property under test is the DECODER's
        // tail tolerance, and `decode` refuses a wrong-length encapsulation key regardless of content.
        // DB-273 §19.3 L2: the owner is a clue whose canonical digest the header names.
        Class::Unbond => crate::unbond_tx::encode(
            &crate::unbond_tx::UnbondHeader {
                owner_clue_digest: crate::oli::owner_clue_digest(&[4u8; 16]),
                bond_instance: [9u8; 32],
                nonce: [5u8; 32],
            },
            &[2u8; 8],
            &[3u8; 8],
            &[4u8; 16],
        )
        .unwrap_or_default(),
        // ⛔ DB-266 — the evidence's REAL encoder on dull-but-well-formed votes: one key, one height, two different
        // blocks. `decode` never checks the signatures (the door's verify does), so the property under test here is
        // the TAIL alone.
        Class::Equivocation => {
            let vote = |block: u8, sig: u8| crate::validator::VoteCert {
                pubkey: vec![1u8; 4],
                block: crate::hash::Hash32([block; 32]),
                height: 7,
                sig: vec![sig; 4],
            };
            crate::equivocation_tx::encode(&vote(1, 3), &vote(2, 4)).unwrap_or_default()
        }
        // G2: one vote of exact ML-DSA-65 widths (the strict decoder refuses any other width).
        Class::FinalityVote => crate::finality_vote_tx::encode(&crate::validator::VoteCert {
            pubkey: vec![1u8; crate::finality_vote_tx::ML_DSA_65_PK_LEN],
            block: crate::hash::Hash32([1u8; 32]),
            height: 7,
            sig: vec![3u8; crate::finality_vote_tx::ML_DSA_65_SIG_LEN],
        }),
        // ⛔ DB-274 P4b (§8.15) — the evidence's REAL wire type, dull-but-well-formed: ascending offenders and one
        // attestor of the exact ML-DSA-65 widths. `decode` never checks the signatures (the fold's tally does), so the
        // property under test here is the TAIL alone.
        Class::ReserveTheft => postcard::to_allocvec::<crate::theft_tx::ReserveTheftPayload>(&(
            b"stmt".to_vec(),
            vec![[1u8; 32], [2u8; 32]],
            100_000_000,
            vec![(vec![3u8; crate::theft_tx::ML_DSA_65_PK_BYTES], vec![4u8; crate::theft_tx::ML_DSA_65_SIG_BYTES])],
        ))
        .unwrap_or_default(),
        // ⭐ DB-313 §3 — the aggregate's REAL wire type through its real encoder, dull-but-well-formed: `decode` checks
        // structure only (the verify is the graft's), so the property under test is the TAIL alone.
        Class::BondTransition => {
            crate::note_transition::BondTransition { agg: vec![1u8; 4], tuples: vec![2u8; 8], shape: [3u32; 8] }
                .encode()
        }
        Class::MembershipBond => crate::membership_bond_tx::encode(
            &crate::membership_bond_tx::MembershipBondHeader {
                secp33: vec![5u8; crate::membership_bond_tx::CUSTODY_POINT_BYTES],
                ed32: [6u8; 32],
                kem_ek: vec![7u8; crate::membership_bond_tx::CUSTODY_KEM_EK_BYTES],
                nonce: [8u8; 32],
            },
            &[2u8; 8],
            &[3u8; 8],
        )
        .unwrap_or_default(),
        Class::OrderPost => {
            let v = crate::order_book::OrderWire {
                lot: 1,
                pay_b: 2,
                asset_a: [1, 0, 0],
                asset_b: [2, 0, 0],
                expires_at_height: 9,
                nullifier: usdm_decider::poseidon2_compress::lanes_of(&[3, 0, 0, 0]),
                leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[4, 0, 0, 0]),
                payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[5, 0, 0, 0]),
                maker_bytes: vec![7u8; 4],
                payout_note: vec![8u8; 4],
                membership_carrier: Vec::new(),
                membership_tip: Vec::new(),
                payout_clue: vec![9u8; 4],
            };
            postcard::to_stdvec(&v).expect("the canonical order wire encodes")
        }
        Class::WrappedMint => {
            // The smallest object that is IN BOUNDS: a non-empty carrier, one attestation, a non-zero
            // amount and a note long enough to carry a commitment — `wrapped_mint_tx::decode` refuses
            // each of those either way, and the property under test here is the TAIL, not the bounds.
            let h = crate::wrapped_mint_tx::WrappedMintHeader {
                asset_id: 5,
                deposit_id: [1u8; 32],
                recipient: [2u8; 32],
                new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]),
                new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[2, 0, 0, 0]),
                delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[7, 0, 0, 0]),
            };
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            // DB-273 §19 L1: the owner clue is the payload's last element (the TAIL the family pads after).
            crate::wrapped_mint_tx::encode(&h, &[3u8; 8], &[4u8; 8], &att, &[9u8; 40], &[], &[0xC7u8; 16])
        }
        Class::PegIn => {
            // The smallest object that is IN BOUNDS: both carriers non-empty, one attestation, a
            // non-zero amount and a note long enough to carry a commitment — `peg_in_tx::decode` refuses
            // each of those either way, and the property under test here is the TAIL, not the bounds.
            let h = crate::peg_in_tx::PegInHeader {
                deposit_id: [1u8; 32],
                recipient: [2u8; 32],
                new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]),
                new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[2, 0, 0, 0]),
                delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[7, 0, 0, 0]),
                proposal_nonce: [3u8; 32],
            };
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            // DB-273 §19 L1: the owner clue is the payload's last element (the TAIL the family pads after).
            crate::peg_in_tx::encode(&h, &[3u8; 8], &[4u8; 8], &[5u8; 8], &att, &[9u8; 48], &[], &[0xC7u8; 16])
        }
        Class::PegOut => {
            // The smallest object that is IN BOUNDS: a non-empty carrier, a redeem destination and one
            // attestation — `peg_out_tx::decode` refuses each either way; the property here is the TAIL.
            let h = crate::peg_out_tx::PegOutHeader {
                usdm_nullifier: [1u8; 32],
                new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]),
                new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[2, 0, 0, 0]),
                proposal_nonce: [6u8; 32],
                leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[3, 0, 0, 0]),
                // DB-273 §19.3 L2: the change owner the carried clue must open.
                change_owner: crate::peg_out_tx::change_owner_of(&[0xC7u8; 16]),
                // DB-365: the change note's commitment — the front of the carried note below.
                change_cm: crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::lanes_of(&[4, 0, 0, 0])),
            };
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            let mut change = h.change_cm.to_vec();
            change.resize(48, 9);
            crate::peg_out_tx::encode(&h, &[3u8; 8], &[7u8; 32], &att, &change, &[], &[0xC7u8; 16], &(vec![0u8; crate::cashout_ticket::TICKET_BYTES], vec![([1u8; 32], vec![0u8; crate::peg_attest::request_sealed_len()])], vec![2u8; crate::epoch_key::CT_BYTES]))
        }
        Class::YieldClaim => {
            // DB-237: the smallest stake object that is IN BOUNDS — both carriers and the membership cross-bind non-empty,
            // a non-zero cross-bind, two notes carrying the header's commitments, one owner clue each.
            let lanes = usdm_decider::poseidon2_compress::lanes_of;
            let h = crate::stake_tx::StakeHeader {
                nullifier: [1u8; 32],
                e_now: 7,
                rate_bps: 500,
                out0_cm: lanes(&[3, 0, 0, 0]),
                out1_cm: lanes(&[4, 0, 0, 0]),
                leaf_commit: lanes(&[5, 0, 0, 0]),
                reward_commit: lanes(&[6, 0, 0, 0]),
                new_paid_commit: lanes(&[2, 0, 0, 0]),
            };
            let note_of = |cm: crate::spend_frontier::Digest4, fill: u8| {
                let mut n = crate::spend_frontier::leaf_to_cm_bytes(cm).to_vec();
                n.resize(48, fill);
                n
            };
            crate::stake_tx::encode(&crate::stake_tx::StakeDecoded {
                h,
                stake_carrier: vec![3u8; 8],
                supply_carrier: vec![4u8; 8],
                membership_carrier: vec![5u8; 8],
                membership_tip: vec![6u8; 8],
                out0: note_of(h.out0_cm, 9),
                out1: note_of(h.out1_cm, 8),
                owner_clues: vec![vec![0xC1u8; 16], vec![0xC2u8; 16]],
                sealed: vec![([7u8; 32], vec![8u8; 16])],
            })
        }
        Class::PriceMark => {
            // The real encoder, on the smallest object that is IN BOUNDS: one quote at a non-zero price,
            // because `price_mark_tx::decode` refuses an empty list or a zero price either way and the
            // property under test is the TAIL, not the bounds.
            let h = crate::price_mark_tx::PriceMarkHeader { epoch_id: 1, asset_id: 5 };
            let q = vec![crate::price_mark_tx::PriceQuote {
                price: 15_000,
                pubkey: vec![1u8; 4],
                sig: vec![2u8; 4],
            }];
            crate::price_mark_tx::encode(&h, &q)
        }
        Class::VaultMerge => {
            // The real encoder, on the smallest object the strict decoder accepts: two distinct vaults, ONE leg (a
            // custody-funded ledger kind, its pair after and its two proofs), one attestation in each list.
            let d = crate::spend_frontier::Digest4::default();
            let header = crate::vault_merge_tx::VaultMergeHeader { from: 1, into: 0 };
            let legs = vec![crate::peg::MergeLeg { asset: crate::peg::CUSTODY_LEDGER_KINDS[0], post: (d, d), reserve_sum: vec![3u8; 4], minted_sum: vec![4u8; 4] }];
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            crate::vault_merge_tx::VaultMerge { header, legs, ride: Vec::new(), release: att.clone(), accept: att }.encode()
        }
        Class::VaultRebalance => {
            // The real encoder, on the smallest object the strict decoder accepts: a carve between two distinct vaults,
            // ONE leg (a custody-funded ledger kind, its part, its pair after and its two proofs), one attestation.
            let d = crate::spend_frontier::Digest4::default();
            let header = crate::vault_rebalance_tx::VaultRebalanceHeader::Carve { from: 1, into: 0 };
            let legs = vec![crate::peg::RebalanceLeg { asset: crate::peg::CUSTODY_LEDGER_KINDS[0], part: Some((d, d)), post: (d, d), reserve_sum: vec![3u8; 4], minted_sum: vec![4u8; 4] }];
            let sigs = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            crate::vault_rebalance_tx::VaultRebalance { header, legs, ride: Vec::new(), sigs }.encode()
        }
        Class::VaultKey => {
            // The real encoder, on the smallest object the strict decoder accepts: a take of a one-member key with no
            // Monero address, one attestation.
            crate::vault_key_tx::VaultKey {
                header: crate::vault_key_tx::VaultKeyHeader::Take { vault: 0, members: vec![[7u8; 32]], xmr_address: Vec::new() },
                attestors: vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }],
            }
            .encode()
        }
        Class::ReleaseConfirm => {
            // The real encoder, on the smallest object the strict decoder accepts: one released burn.
            crate::release_confirm_tx::ReleaseConfirmTx { ledger: crate::peg::NATIVE_PEG_ASSET_ID, txid: [5u8; 32], released: vec![[6u8; 32]], swept: Vec::new(), attestors: vec![(vec![1u8; 4], vec![2u8; 4])] }
                .encode()
        }
        Class::ReserveCost => {
            // The real encoder, on the smallest object the strict decoder accepts: a fee under the floor (no bound proof).
            crate::reserve_cost_tx::ReserveCost {
                header: crate::reserve_cost_tx::ReserveCostHeader { ledger: crate::peg::NATIVE_PEG_ASSET_ID, cost: 1, txid: [5u8; 32], post_reserve: crate::spend_frontier::Digest4::default() },
                sum: vec![3u8; 4],
                bound: Vec::new(),
                attestors: vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }],
            }
            .encode()
        }
        Class::WrappedAssetRegister => {
            // The real encoder, on the smallest object that is IN BOUNDS: one attestation, and a ratio the
            // decoder would accept (>= 10000), because `wrapped_asset_tx::decode` refuses either way and
            // the property under test is the TAIL, not the bounds.
            let h = crate::wrapped_asset_tx::WrappedAssetRegisterHeader {
                epoch_id: 1,
                asset_id: 5,
                prev_ratio_bps: 0,
                ratio_bps: 15_000,
            };
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            crate::wrapped_asset_tx::encode(&h, &att)
        }
        Class::Liquidation => {
            // The real encoder, on the smallest object that is IN BOUNDS: one attestation and five non-empty
            // legs, because `liquidation_tx::decode` refuses an empty either way and the property under
            // test is the tail, not the bounds.
            let l = usdm_decider::poseidon2_compress::lanes_of;
            let h = crate::liquidation_tx::LiquidationHeader {
                epoch_id: 1,
                asset_id: crate::peg::NATIVE_PEG_ASSET_ID,
                position_id: [1u8; 32],
                retired_commit: l(&[7, 0, 0, 0]),
                seized_commit: l(&[8, 0, 0, 0]),
                new_reserve_commit: l(&[2, 0, 0, 0]),
                new_minted_commit: l(&[3, 0, 0, 0]),
                new_pool_t: l(&[9, 0, 0, 0]),
                new_pool_p: l(&[10, 0, 0, 0]),
                new_pool_s: l(&[11, 0, 0, 0]),
                pool_close: false,
            };
            let legs = crate::liquidation_tx::LiquidationLegs {
                amount: vec![6u8; 4],
                pool_transition: vec![6u8; 4],
                pool_step: vec![6u8; 4],
                retire: vec![6u8; 4],
                seize: vec![6u8; 4],
            };
            let att = [crate::psm::MintAttestor {
                pubkey: vec![4u8; 4],
                sig: vec![5u8; 4],
            }];
            crate::liquidation_tx::encode(&h, &legs, &att)
        }
        Class::TheftRepayment => {
            let l = usdm_decider::poseidon2_compress::lanes_of;
            let h = crate::theft_repayment_tx::TheftRepaymentHeader {
                repay_id: [1u8; 32],
                loss_sats: 1,
                split: [4, 1, 1, 2],
                pool_c: 2,
                remainder: 0,
                pool_retired_commit: l(&[7, 0, 0, 0]),
                new_reserve_commit: l(&[2, 0, 0, 0]),
                mid_minted_commit: l(&[3, 0, 0, 0]),
                new_minted_commit: l(&[4, 0, 0, 0]),
                new_pool_t: l(&[9, 0, 0, 0]),
                new_pool_p: l(&[10, 0, 0, 0]),
                new_pool_s: l(&[11, 0, 0, 0]),
                pool_close: false,
            };
            let legs = crate::theft_repayment_tx::TheftRepaymentLegs { seize: vec![6u8; 4], ..Default::default() };
            let att = [crate::psm::MintAttestor { pubkey: vec![4u8; 4], sig: vec![5u8; 4] }];
            crate::theft_repayment_tx::encode(&h, &legs, &att)
        }
        Class::PotFill => crate::pot_fill_tx::PotFillTx {
            burn_usdm: 1,
            sat_out: 1,
            nullifier: [1u8; 32],
            leaf_commit: [2u8; 32],
            burn_carrier: vec![6u8; 4],
            membership_carrier: vec![6u8; 4],
            membership_tip: vec![6u8; 4],
            change_note: vec![3u8; 64],
            change_clue: vec![4u8; 8],
            sat_note: vec![5u8; 64],
            sat_mint_carrier: vec![6u8; 4],
            sat_clue: vec![7u8; 8],
            new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[3, 0, 0, 0]),
            retire_leg: vec![6u8; 4],
            attestors: vec![(vec![4u8; 4], vec![5u8; 4])],
        }
        .encode(),
        Class::DecoyBatch => crate::decoy_tx::DecoyBatchTx {
            payout_txid: [1u8; 32],
            decoys: vec![crate::decoy_tx::DecoyEntry { vid: [2u8; 32], sats: 100_000, vout: 1 }],
            fee_usdm: 3,
            attestors: vec![(vec![4u8; 4], vec![5u8; 4])],
        }
        .encode(),
        Class::DecoyReturn => crate::decoy_tx::DecoyReturnTx { txid: [1u8; 32], vout: 1, return_txid: [3u8; 32], attestors: vec![(vec![4u8; 4], vec![5u8; 4])] }.encode(),
        // §BR-4 B4-2: the smallest unit open whose inner peg-in decodes and whose deposit id binds the unit
        Class::UnitOpen => {
            let terms = crate::debt_units::UnitTerms { k: 40, l: 1, day: 0, epoch: 0 };
            let mut unit_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            unit_note[..32].copy_from_slice(&[0x31u8; 32]);
            let base = [8u8; 32];
            let dep = crate::unit_open_tx::unit_deposit_id(&base, &terms, &[0x31u8; 32]);
            let clue = vec![0xC7u8; 16];
            let h = crate::peg_in_tx::PegInHeader {
                deposit_id: dep,
                recipient: crate::peg::peg_in_recipient(&dep, &clue),
                new_reserve_commit: usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]),
                new_minted_commit: usdm_decider::poseidon2_compress::lanes_of(&[2, 0, 0, 0]),
                delta_commit: usdm_decider::poseidon2_compress::lanes_of(&[7, 0, 0, 0]),
                proposal_nonce: [3u8; 32],
            };
            let att = vec![crate::psm::MintAttestor { pubkey: vec![1u8; 4], sig: vec![2u8; 4] }];
            let peg_in = crate::peg_in_tx::encode(&h, &[3u8; 8], &[4u8; 8], &[5u8; 8], &att, &[9u8; 48], &[], &clue);
            crate::unit_open_tx::UnitOpenTx { peg_in, base_deposit_id: base, terms, unit_note, unit_clue: vec![0xC8u8; 16], unit_carrier: vec![6u8; 8] }
                .encode()
                .expect("the sample encodes")
        }
        // §BR-4 B4-3: the smallest unit close every width admits
        Class::UnitClose => {
            let mut change_note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            change_note[..32].copy_from_slice(&[0x41u8; 32]);
            let z = usdm_decider::poseidon2_compress::lanes_of(&[1, 0, 0, 0]);
            crate::unit_close_tx::UnitCloseTx {
                terms: crate::debt_units::UnitTerms { k: 40, l: 1, day: 0, epoch: 0 },
                unit_nullifier: [1u8; 32],
                unit_leaf_commit: [2u8; 32],
                unit_burn_carrier: vec![3u8; 8],
                unit_membership_carrier: vec![4u8; 8],
                unit_membership_tip: vec![5u8; 8],
                debt_atomic: 1_000,
                debt_nullifier: [6u8; 32],
                debt_leaf_commit: [7u8; 32],
                debt_burn_carrier: vec![8u8; 8],
                debt_membership_carrier: vec![9u8; 8],
                debt_membership_tip: vec![10u8; 8],
                change_note,
                change_clue: vec![0xC9u8; 16],
                ticket: crate::peg_out_tx::ticket_parts_for_test(),
                redeem_commit: [11u8; 32],
                new_minted_commit: z,
                new_reserve_commit: z,
                retire_leg: vec![12u8; 8],
                release_leg: vec![13u8; 8],
                attestors: vec![(vec![4u8; 4], vec![5u8; 4])],
            }
            .encode()
            .expect("the sample encodes")
        }
        Class::BridgeCredit => {
            let v = crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id: [1u8; 32],
                asset_tag: [2, 0, 0],
                amount: 5,
                note: vec![9u8; 4],
                owner_clue: Vec::new(),
                attestors: Vec::new(),
        };
            postcard::to_stdvec(&v).expect("the canonical bridge credit encodes")
        }
        Class::AssetCreate => {
            let v = crate::asset_tx::AssetCreateTx {
                kind: crate::asset_tx::AssetKind::Token,
                symbol: "AAA".to_string(),
                name: "Aaa".to_string(),
                logo: [3u8; 32],
                bytecode: vec![4u8; 4],
                creator: [0u8; 32],
                asset_id: [5u8; 32],
                fee: crate::asset_tx::CreationFee::default(),
                art: Vec::new(),
                supply: None,
            };
            postcard::to_stdvec(&v).expect("the canonical asset create encodes")
        }
        // §BR-12 L1: the smallest deploy its strict decoder accepts — every fixed-width field at its exact width.
        Class::DsolDeploy => {
            let v = crate::dsol_deploy_tx::DsolDeployTx {
                code: vec![4u8; 4],
                height_class: crate::dsol_deploy_tx::DSOL_HEIGHT_CLASS_MIN,
                name: String::new(),
                publisher_fee_le: [0u8; 8],
                publisher_spk: [0u8; 32],
                view_ek: vec![0u8; crate::dsol_deploy_tx::ML_KEM_768_EK_BYTES],
                kc_commit: [0u8; 32],
                deployer_pk: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES],
                sig: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES],
                state_path: crate::contract_state::PathWire::default(),
                fee: crate::asset_tx::CreationFee::default(),
            };
            postcard::to_stdvec(&v).expect("the canonical dsol deploy encodes")
        }
        // audit F15: the smallest paid directory entry's SHAPE — a @username entry with a key and signature of ML-DSA-65's
        // exact widths (the strict decoder goes on to refuse the default fee on its bounds; the raw form is what round-trips).
        Class::DirEntry => {
            let v = crate::dir_entry_tx::DirEntryTx {
                entry: crate::directory::DirEntry {
                    kind: crate::directory::KIND_NAME,
                    key: "a".to_string(),
                    address: String::new(),
                    name: String::new(),
                    topic: String::new(),
                    pubkey: vec![0u8; crate::dir_entry_tx::ML_DSA_65_PK_BYTES],
                    sig: vec![0u8; crate::dir_entry_tx::ML_DSA_65_SIG_BYTES],
                    pic: None,
                },
                fee: crate::asset_tx::CreationFee::default(),
                art: Vec::new(),
            };
            postcard::to_stdvec(&v).expect("the canonical paid directory entry encodes")
        }
        // IonSwap pools: the smallest order's SHAPE — a buy with one leg (the strict decoder goes on to refuse the default
        // leg on its bounds; the raw form is what round-trips).
        Class::IonOrder => {
            let v = crate::ion_pool_tx::IonOrderTx {
                creator: None,
                token: [1u8; 32],
                core: crate::ion_pool_tx::IonOrderCore {
                    kind: crate::ion_pool_tx::ION_BUY,
                    x: 0,
                    y: 1,
                    shares: 0,
                    min_out: 0,
                    owner_opening: [0u8; 32],
                    shell_ct: vec![0u8; crate::ion_pool_tx::ION_SHELL_CT_BYTES],
                    shell_pad: [0u8; 32],
                    shell_vt: 0,
                    locators: [[1u8; 32], [2u8; 32], [3u8; 32]],
                    hop: [0u8; 32],
                    hop_min_out: 0,
                    lock_from: 0,
                    lock_until: 0,
                },
                legs: vec![crate::asset_tx::CreationFee::default()],
            };
            postcard::to_stdvec(&v).expect("the canonical pool order encodes")
        }
        // IonSwap pools: the smallest settlement — a pool with no leaf yet, an empty path, no payout.
        Class::IonSettle => {
            let v = crate::ion_pool_tx::IonSettleTx {
                token: [1u8; 32],
                cutoff: 1,
                pre: None,
                path: crate::contract_state::PathWire::default(),
                notes: Vec::new(),
            };
            postcard::to_stdvec(&v).expect("the canonical pool settlement encodes")
        }
        // §BR-12 L2: the smallest call its decoder's SHAPE accepts (the strict decoder refuses it on bounds; the raw form is the
        // round-trip under test).
        Class::DsolCall => {
            let stmt = usdm_decider::dsol_cpu_air::DsolStatement {
                code_id: [1u8; 32],
                entry_sel: 0,
                start_pc: 0,
                argv_digest: usdm_decider::poseidon2_compress::zero_digest(),
                argv_len: 0,
                storage_pre: usdm_decider::poseidon2_compress::zero_digest(),
                storage_post: usdm_decider::poseidon2_compress::zero_digest(),
                effects_digest: usdm_decider::poseidon2_compress::zero_digest(),
                ret_digest: usdm_decider::poseidon2_compress::zero_digest(),
                height_log2: 5,
                cid: usdm_decider::poseidon2_compress::zero_digest(),
                caller: usdm_decider::poseidon2_compress::zero_digest(),
                subaddress: usdm_decider::poseidon2_compress::zero_digest(),
                tx_hash: usdm_decider::poseidon2_compress::zero_digest(),
                block_number: 0,
                state_in: usdm_decider::poseidon2_compress::zero_digest(),
                state_out: usdm_decider::poseidon2_compress::zero_digest(),
            };
            let seg = crate::dsol_call_tx::ProvenSegment { stmt, proof: usdm_decider::dsol_cpu_air::DsolCallProof { bytes: vec![1u8; 4] }, effects: Vec::new() };
            let v = crate::dsol_call_tx::DsolCallTx {
                cid: [2u8; 32],
                manifest: crate::dsol_deploy_tx::ContractManifest { code_id: [1u8; 32], publisher_fee_le: [0u8; 8], publisher_spk: [0u8; 32], deployer_id: [0u8; 32], kc_commit: [0u8; 32], height_class: 0 },
                storage_pre: [0u8; 32],
                state_path: crate::contract_state::PathWire::default(),
                pk_c: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES],
                sig: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES],
                root: seg,
                libraries: Vec::new(),
                code: vec![vec![4u8; 4]],
                fee: crate::dsol_call_tx::CallFee::default(),
                storage: crate::dsol_call_tx::StorageBlob::default(),
            };
            postcard::to_stdvec(&v).expect("the canonical dsol call encodes")
        }
        // §BR-15: the smallest order, settlement, expiry and claim each strict decoder accepts.
        Class::DefiOrder => {
            let mut change = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            change[..32].copy_from_slice(&[5u8; 32]);
            let _ = change;
            let v = defi_order_fixture();
            postcard::to_stdvec(&v).expect("the canonical order encodes")
        }
        Class::DefiSettle => {
            let part = crate::defi_batch::CustodianPart {
                published: vec![([0; 4], vec![[0; 4]; usdm_decider::br15_audit::AUDIT_REPS], vec![[0; 4]; usdm_decider::br15_audit::AUDIT_REPS]); usdm_decider::br15_audit::AUDIT_STATEMENTS],
                new_pool: [2; 4],
                new_fee: [3; 4],
                new_close: [4; 4],
                audit: Vec::new(),
            };
            let v = crate::defi_batch::DefiSettleTx { pair: 0, sells: true, j_min: 0, batch: 0, tick: 0, excluded: Vec::new(), phase1: vec![[1; 4]], first: 0, parts: vec![part], leaves: Vec::new() };
            postcard::to_stdvec(&v).expect("the canonical settlement encodes")
        }
        Class::DefiExpire => postcard::to_stdvec(&crate::defi_batch::DefiExpireTx { pair: 0, batch: 0, leaves: Vec::new() }).expect("encodes"),
        Class::DefiHandover => postcard::to_stdvec(&crate::defi_handover::DefiHandoverTx::Accept { pair: 0, batch: 0, to: 0, new_pool: [1; 4], new_fee: [2; 4], new_close: [3; 4], proof: Vec::new() }).expect("encodes"),
        Class::DefiEarnEpoch => {
            let part = crate::defi_batch::EpochPart {
                published: (0..usdm_decider::br15_audit::EPOCH_STATEMENTS)
                    .map(|_| ([0; 4], vec![[0; 4]; usdm_decider::br15_audit::AUDIT_REPS], vec![[0; 4]; usdm_decider::br15_audit::AUDIT_REPS]))
                    .collect(),
                audit: Vec::new(),
            };
            let v = crate::defi_batch::DefiEarnEpochTx { raise: 0, dg: 1, phase1: vec![[1; 4]], first: 0, parts: vec![part] };
            postcard::to_stdvec(&v).expect("the canonical EarnEpoch encodes")
        }
        Class::DefiSlots => {
            let v = crate::defi_batch::DefiSlotsTx {
                pair: 0,
                batch: 0,
                part: 0,
                orders: vec![defi_order_fixture(); crate::defi_batch::PART_SLOTS],
                claims: vec![defi_claim_fixture(); crate::defi_batch::PART_SLOTS],
            };
            postcard::to_stdvec(&v).expect("the canonical slots encode")
        }
        Class::DefiClaim => {
            let v = crate::defi_batch::DefiClaimTx {
                pair: 0,
                nullifier: [1; 8],
                leaf_commit: [2; 8],
                out_commit: [3; 8],
                pays_y: false,
                claim_proof: Vec::new(),
                member_carrier: Vec::new(),
                member_tuple: Vec::new(),
                mint_carrier: Vec::new(),
                note: vec![4u8; crate::cover::PQ_NOTE_BYTES],
                // the claim's decoder takes a clue of exactly the fixed width since ad8bef16 ("no payment its owner
                // cannot find"); the four-byte fixture here was refused at the door and stopped this family at this
                // class (MEASURED 2026-11-11 on main 258422bf plus lane vaults' commits, none of which touch this class:
                // the canonical-decodes pin was red here and never reached the classes after it)
                owner_clue: vec![5u8; crate::peg_in_tx::OWNER_CLUE_MAX],
            };
            postcard::to_stdvec(&v).expect("the canonical claim encodes")
        }
        // §BR-12 L3: the smallest fee update its strict decoder accepts.
        Class::DsolFeeUpdate => {
            let v = crate::dsol_fee_update_tx::DsolFeeUpdateTx {
                cid: [2u8; 32],
                manifest: crate::dsol_deploy_tx::ContractManifest { code_id: [1u8; 32], publisher_fee_le: 1u64.to_le_bytes(), publisher_spk: [0u8; 32], deployer_id: [0u8; 32], kc_commit: [0u8; 32], height_class: 0 },
                storage_root: [0u8; 32],
                state_path: crate::contract_state::PathWire::default(),
                new_fee_le: [0u8; 8],
                deployer_pk: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_PK_BYTES],
                sig: vec![0u8; crate::dsol_deploy_tx::ML_DSA_65_SIG_BYTES],
            };
            postcard::to_stdvec(&v).expect("the canonical dsol fee update encodes")
        }
        Class::AssetMint => {
            let v = crate::asset_tx::AssetMintTx {
                asset_id: [6u8; 32],
                kind: crate::asset_tx::AssetKind::Token,
                amount: 11,
                note: vec![1u8; 4],
                mint_carrier: vec![2u8; 4],
                owner_clue: vec![3u8; 4],
                creator_pubkey: vec![1u8; 8],
                creator_sig: vec![2u8; 8],
                symbol: String::new(),
                asset_name: String::new(),
                registry_path: Vec::new(),
                registry_dirs: Vec::new(),
                logo: [0u8; 32],
                collection: String::new(),
            };
            postcard::to_stdvec(&v).expect("the canonical asset mint encodes")
        }
        Class::AssetSpend => {
            let v = crate::asset_tx::AssetSpendTx {
                notes: [vec![1u8; 4], vec![2u8; 4]],
                nullifier: [3u8; 32],
                leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[4, 0, 0, 0]),
                validity_carrier: vec![5u8; 4],
                membership_carrier: vec![6u8; 4],
                member_tuple: Vec::new(),
                named_record: 7,
                tip_prev: usdm_decider::poseidon2_compress::zero_digest(),
                tip_root: usdm_decider::poseidon2_compress::zero_digest(),
                tip_acc: usdm_decider::poseidon2_compress::zero_digest(),
                owner_clues: vec![vec![3u8; 4], vec![4u8; 4]],
                slot_tag: None,
            };
            postcard::to_stdvec(&v).expect("the canonical asset transfer encodes")
        }
        Class::OrderFill => {
            let v = crate::order_fill_tx::OrderFillTx {
                lot: 1,
                pay_b: 2,
                asset_a: [1, 0, 0],
                asset_b: [2, 0, 0],
                expires_at_height: 9,
                maker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[3, 0, 0, 0]),
                maker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[4, 0, 0, 0]),
                maker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[5, 0, 0, 0]),
                maker_bytes: vec![7u8; 4],
                taker_nullifier: usdm_decider::poseidon2_compress::lanes_of(&[6, 0, 0, 0]),
                taker_leaf_commit: usdm_decider::poseidon2_compress::lanes_of(&[7, 0, 0, 0]),
                taker_payout_cm: usdm_decider::poseidon2_compress::lanes_of(&[8, 0, 0, 0]),
                taker_change_cm: usdm_decider::poseidon2_compress::lanes_of(&[9, 0, 0, 0]),
                taker_bytes: vec![8u8; 4],
                maker_membership_carrier: Vec::new(),
                maker_membership_tip: Vec::new(),
                taker_membership_carrier: Vec::new(),
                taker_membership_tip: Vec::new(),
                notes: [vec![1u8; 4], vec![2u8; 4], vec![3u8; 4]],
                owner_clues: [vec![4u8; 4], vec![5u8; 4], vec![6u8; 4]],
            };
            postcard::to_stdvec(&v).expect("the canonical order fill encodes")
        }
    }
}

/// Does the CURRENT tree's strict decoder accept these bytes as this class?
///
/// The `Class` match is exhaustive so the type parameter is chosen per class rather than guessed at — the
/// point of the family is that it exercises the REAL type each arm decodes.
pub fn current_door_accepts(class: Class, bytes: &[u8]) -> bool {
    match class {
        Class::PoolDeposit => crate::pool_tx::decode(bytes).is_some(),
        Class::DefiOrder => crate::defi_batch::DefiOrderTx::decode(bytes).is_some(),
        Class::DefiSettle => crate::defi_batch::DefiSettleTx::decode(bytes).is_some(),
        Class::DefiExpire => crate::defi_batch::DefiExpireTx::decode(bytes).is_some(),
        Class::DefiClaim => crate::defi_batch::DefiClaimTx::decode(bytes).is_some(),
        Class::DefiHandover => crate::defi_handover::DefiHandoverTx::decode(bytes).is_some(),
        Class::DefiSlots => crate::defi_batch::DefiSlotsTx::decode(bytes).is_some(),
        Class::DefiEarnEpoch => crate::defi_batch::DefiEarnEpochTx::decode(bytes).is_some(),
        Class::VaultMerge => crate::vault_merge_tx::decode(bytes).is_some(),
        Class::ReserveCost => crate::reserve_cost_tx::decode(bytes).is_some(),
        Class::ReleaseConfirm => crate::release_confirm_tx::ReleaseConfirmTx::decode(bytes).is_some(),
        Class::VaultKey => crate::vault_key_tx::decode(bytes).is_some(),
        Class::VaultRebalance => crate::vault_rebalance_tx::decode(bytes).is_some(),
        Class::PoolWithdraw => crate::pool_tx::decode_withdraw(bytes).is_some(),
        Class::Unbond => crate::unbond_tx::decode(bytes).is_some(),
        Class::MembershipBond => crate::membership_bond_tx::decode(bytes).is_some(),
        Class::Equivocation => crate::equivocation_tx::decode(bytes).is_some(),
        Class::FinalityVote => crate::finality_vote_tx::decode(bytes).is_some(),
        Class::ReserveTheft => crate::theft_tx::decode(bytes).is_some(),
        Class::BondTransition => crate::note_transition::BondTransition::decode(bytes).is_some(),
        Class::OrderPost => decode_exact::<crate::order_book::OrderWire>(bytes).is_some(),
        Class::BridgeCredit => decode_exact::<crate::bridge_credit_tx::BridgeCreditTx>(bytes).is_some(),
        Class::AssetCreate => decode_exact::<crate::asset_tx::AssetCreateTx>(bytes).is_some(),
        Class::DsolDeploy => decode_exact::<crate::dsol_deploy_tx::DsolDeployTx>(bytes).is_some(),
        Class::DirEntry => decode_exact::<crate::dir_entry_tx::DirEntryTx>(bytes).is_some(),
        Class::IonOrder => decode_exact::<crate::ion_pool_tx::IonOrderTx>(bytes).is_some(),
        Class::IonSettle => decode_exact::<crate::ion_pool_tx::IonSettleTx>(bytes).is_some(),
        Class::DsolCall => decode_exact::<crate::dsol_call_tx::DsolCallTx>(bytes).is_some(),
        Class::DsolFeeUpdate => decode_exact::<crate::dsol_fee_update_tx::DsolFeeUpdateTx>(bytes).is_some(),
        Class::AssetMint => decode_exact::<crate::asset_tx::AssetMintTx>(bytes).is_some(),
        Class::SatoshiReward => decode_exact::<crate::satoshi::SatoshiRewardTx>(bytes).is_some(),
        Class::MinerPayout => decode_exact::<crate::miner_payout_tx::MinerPayoutTx>(bytes).is_some(),
        Class::SatDelegation => decode_exact::<crate::sat_delegation_tx::SatDelegationTx>(bytes).is_some(),
        Class::BondYieldClaim => decode_exact::<crate::bond_yield_claim_tx::BondYieldClaimTx>(bytes).is_some(),
        Class::BountyPayout => decode_exact::<crate::bounty_payout_tx::BountyPayoutTx>(bytes).is_some(),
        Class::SatSetAside => decode_exact::<crate::sat_set_aside::SatSetAsideTx>(bytes).is_some(),
        Class::DeploymentSignal => decode_exact::<crate::deployment_signal_tx::DeploymentSignalTx>(bytes).is_some(),
        Class::ReleaseAttestation => decode_exact::<crate::release_attestation_tx::ReleaseAttestationTx>(bytes).is_some(),
        Class::EpochKeyDeal => decode_exact::<crate::epoch_deal_tx::EpochKeyDealTx>(bytes).is_some(),
        Class::EpochKeyFraud => crate::epoch_fraud_tx::decode(bytes).is_some(),
        Class::SatBond => decode_exact::<crate::sat_bond_tx::SatBondTx>(bytes).is_some(),
        Class::AssetSpend => decode_exact::<crate::asset_tx::AssetSpendTx>(bytes).is_some(),
        Class::OrderFill => decode_exact::<crate::order_fill_tx::OrderFillTx>(bytes).is_some(),
        Class::Liquidation => {
            decode_exact::<crate::liquidation_tx::LiquidationPayload>(bytes).is_some()
        }
        Class::TheftRepayment => decode_exact::<crate::theft_repayment_tx::TheftRepaymentPayload>(bytes).is_some(),
        Class::PotFill => decode_exact::<crate::pot_fill_tx::PotFillTx>(bytes).is_some(),
        Class::DecoyBatch => decode_exact::<crate::decoy_tx::DecoyBatchTx>(bytes).is_some(),
        Class::DecoyReturn => decode_exact::<crate::decoy_tx::DecoyReturnTx>(bytes).is_some(),
        Class::UnitOpen => crate::unit_open_tx::UnitOpenTx::decode(bytes).is_some(),
        Class::UnitClose => crate::unit_close_tx::UnitCloseTx::decode(bytes).is_some(),
        Class::PriceMark => {
            decode_exact::<crate::price_mark_tx::PriceMarkPayload>(bytes).is_some()
        }
        Class::WrappedAssetRegister => {
            decode_exact::<crate::wrapped_asset_tx::WrappedAssetRegisterPayload>(bytes).is_some()
        }
        Class::WrappedMint => {
            decode_exact::<crate::wrapped_mint_tx::WrappedMintPayload>(bytes).is_some()
        }
        Class::PegIn => decode_exact::<crate::peg_in_tx::PegInPayload>(bytes).is_some(),
        Class::PegOut => decode_exact::<crate::peg_out_tx::PegOutPayload>(bytes).is_some(),
        Class::YieldClaim => {
            decode_exact::<crate::stake_tx::StakePayload>(bytes).is_some() // DB-237: the stake object's payload type
        }
    }
}

/// Does the PRE-FIX decoder accept these bytes as this class?
///
/// ⛔ This is the historical call, not an approximation of it: every class arm in
/// `chain_object.rs.preHoleClose-20260906` reached `postcard::from_bytes`, whose documented behaviour is
/// to deserialise a prefix and ignore the remainder. Nothing here is tuned; it is one library call, the
/// same one the pre-fix source made.
pub fn prefix_door_accepts(class: Class, bytes: &[u8]) -> bool {
    match class {
        Class::PoolDeposit => postcard::from_bytes::<crate::pool_tx::PoolDepositPayload>(bytes).is_ok(),
        Class::DefiOrder => postcard::from_bytes::<crate::defi_batch::DefiOrderTx>(bytes).is_ok(),
        Class::DefiSettle => postcard::from_bytes::<crate::defi_batch::DefiSettleTx>(bytes).is_ok(),
        Class::DefiExpire => postcard::from_bytes::<crate::defi_batch::DefiExpireTx>(bytes).is_ok(),
        Class::DefiClaim => postcard::from_bytes::<crate::defi_batch::DefiClaimTx>(bytes).is_ok(),
        Class::DefiHandover => postcard::from_bytes::<crate::defi_handover::DefiHandoverTx>(bytes).is_ok(),
        Class::DefiSlots => postcard::from_bytes::<crate::defi_batch::DefiSlotsTx>(bytes).is_ok(),
        Class::DefiEarnEpoch => postcard::from_bytes::<crate::defi_batch::DefiEarnEpochTx>(bytes).is_ok(),
        Class::VaultMerge => postcard::from_bytes::<crate::vault_merge_tx::VaultMergePayload>(bytes).is_ok(),
        Class::ReserveCost => postcard::from_bytes::<crate::reserve_cost_tx::ReserveCostPayload>(bytes).is_ok(),
        Class::ReleaseConfirm => postcard::from_bytes::<crate::release_confirm_tx::ReleaseConfirmTx>(bytes).is_ok(),
        Class::VaultKey => postcard::from_bytes::<crate::vault_key_tx::VaultKeyPayload>(bytes).is_ok(),
        Class::VaultRebalance => postcard::from_bytes::<crate::vault_rebalance_tx::VaultRebalancePayload>(bytes).is_ok(),
        Class::PoolWithdraw => postcard::from_bytes::<crate::pool_tx::PoolWithdrawPayload>(bytes).is_ok(),
        Class::Unbond => {
            postcard::from_bytes::<crate::unbond_tx::UnbondPayload>(bytes).is_ok()
        }
        Class::MembershipBond => {
            postcard::from_bytes::<crate::membership_bond_tx::MembershipBondPayload>(bytes).is_ok()
        }
        Class::Equivocation => {
            postcard::from_bytes::<crate::equivocation_tx::EquivocationPayload>(bytes).is_ok()
        }
        Class::FinalityVote => postcard::from_bytes::<crate::validator::VoteCert>(bytes).is_ok(),
        Class::ReserveTheft => postcard::from_bytes::<crate::theft_tx::ReserveTheftPayload>(bytes).is_ok(),
        Class::BondTransition => postcard::from_bytes::<crate::note_transition::BondTransition>(bytes).is_ok(),
        Class::OrderPost => postcard::from_bytes::<crate::order_book::OrderWire>(bytes).is_ok(),
        Class::BridgeCredit => postcard::from_bytes::<crate::bridge_credit_tx::BridgeCreditTx>(bytes).is_ok(),
        Class::AssetCreate => postcard::from_bytes::<crate::asset_tx::AssetCreateTx>(bytes).is_ok(),
        Class::DsolDeploy => postcard::from_bytes::<crate::dsol_deploy_tx::DsolDeployTx>(bytes).is_ok(),
        Class::DirEntry => postcard::from_bytes::<crate::dir_entry_tx::DirEntryTx>(bytes).is_ok(),
        Class::IonOrder => postcard::from_bytes::<crate::ion_pool_tx::IonOrderTx>(bytes).is_ok(),
        Class::IonSettle => postcard::from_bytes::<crate::ion_pool_tx::IonSettleTx>(bytes).is_ok(),
        Class::DsolCall => postcard::from_bytes::<crate::dsol_call_tx::DsolCallTx>(bytes).is_ok(),
        Class::DsolFeeUpdate => postcard::from_bytes::<crate::dsol_fee_update_tx::DsolFeeUpdateTx>(bytes).is_ok(),
        Class::AssetMint => postcard::from_bytes::<crate::asset_tx::AssetMintTx>(bytes).is_ok(),
        Class::SatoshiReward => postcard::from_bytes::<crate::satoshi::SatoshiRewardTx>(bytes).is_ok(),
        Class::MinerPayout => postcard::from_bytes::<crate::miner_payout_tx::MinerPayoutTx>(bytes).is_ok(),
        Class::SatDelegation => postcard::from_bytes::<crate::sat_delegation_tx::SatDelegationTx>(bytes).is_ok(),
        Class::BondYieldClaim => postcard::from_bytes::<crate::bond_yield_claim_tx::BondYieldClaimTx>(bytes).is_ok(),
        Class::BountyPayout => postcard::from_bytes::<crate::bounty_payout_tx::BountyPayoutTx>(bytes).is_ok(),
        Class::SatSetAside => postcard::from_bytes::<crate::sat_set_aside::SatSetAsideTx>(bytes).is_ok(),
        Class::DeploymentSignal => postcard::from_bytes::<crate::deployment_signal_tx::DeploymentSignalTx>(bytes).is_ok(),
        Class::ReleaseAttestation => postcard::from_bytes::<crate::release_attestation_tx::ReleaseAttestationTx>(bytes).is_ok(),
        Class::EpochKeyDeal => postcard::from_bytes::<crate::epoch_deal_tx::EpochKeyDealTx>(bytes).is_ok(),
        Class::EpochKeyFraud => postcard::from_bytes::<crate::epoch_release::FraudProof>(bytes).is_ok(),
        Class::SatBond => postcard::from_bytes::<crate::sat_bond_tx::SatBondTx>(bytes).is_ok(),
        Class::AssetSpend => postcard::from_bytes::<crate::asset_tx::AssetSpendTx>(bytes).is_ok(),
        Class::OrderFill => postcard::from_bytes::<crate::order_fill_tx::OrderFillTx>(bytes).is_ok(),
        Class::PriceMark => {
            postcard::from_bytes::<crate::price_mark_tx::PriceMarkPayload>(bytes).is_ok()
        }
        Class::Liquidation => {
            postcard::from_bytes::<crate::liquidation_tx::LiquidationPayload>(bytes).is_ok()
        }
        Class::TheftRepayment => postcard::from_bytes::<crate::theft_repayment_tx::TheftRepaymentPayload>(bytes).is_ok(),
        Class::PotFill => postcard::from_bytes::<crate::pot_fill_tx::PotFillTx>(bytes).is_ok(),
        Class::DecoyBatch => postcard::from_bytes::<crate::decoy_tx::DecoyBatchTx>(bytes).is_ok(),
        Class::DecoyReturn => postcard::from_bytes::<crate::decoy_tx::DecoyReturnTx>(bytes).is_ok(),
        Class::UnitOpen => postcard::from_bytes::<crate::unit_open_tx::UnitOpenTx>(bytes).is_ok(),
        Class::UnitClose => postcard::from_bytes::<crate::unit_close_tx::UnitCloseTx>(bytes).is_ok(),
        Class::WrappedAssetRegister => {
            postcard::from_bytes::<crate::wrapped_asset_tx::WrappedAssetRegisterPayload>(bytes).is_ok()
        }
        Class::WrappedMint => {
            postcard::from_bytes::<crate::wrapped_mint_tx::WrappedMintPayload>(bytes).is_ok()
        }
        Class::PegIn => postcard::from_bytes::<crate::peg_in_tx::PegInPayload>(bytes).is_ok(),
        Class::PegOut => postcard::from_bytes::<crate::peg_out_tx::PegOutPayload>(bytes).is_ok(),
        Class::YieldClaim => {
            postcard::from_bytes::<crate::stake_tx::StakePayload>(bytes).is_ok() // DB-237: the stake object's payload type
        }
    }
}

/// A hostile variant of a canonical encoding, and the name of what was done to it.
///
/// cons: none — each variant is one allocation of at most `canonical.len() + 8` bytes, and the family is
/// `CLASSES.len()` × 8 = 40 blobs, fixed at compile time. No term in chain height, notes or peers.
pub fn padded(canonical_bytes: &[u8], junk_len: usize) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for b in canonical_bytes.iter() {
        out.push(*b);
    }
    let mut k = 0usize;
    while k < junk_len {
        // The junk value is deliberately varied: a decoder that stops at a zero byte and one that stops
        // at any byte are different holes, and a family that only ever appends 0x00 would see one of them.
        out.push((0xA5u8).wrapping_add(k as u8));
        k += 1;
    }
    out
}

/// The junk lengths the family tries. 1 is the minimal forgery — one byte is enough to change
/// `blake3(blob)` while leaving the decoded object identical — and 7 is the length the 2026-09-06 red
/// team measured RED at all five decoders, kept so this family covers the historical measurement exactly.
pub const JUNK_LENGTHS: [usize; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

/// The name of a class, for a report.
pub fn class_name(class: Class) -> &'static str {
    match class {
        Class::PoolDeposit => "PoolDeposit",
        Class::DefiOrder => "DefiOrder",
        Class::DefiSettle => "DefiSettle",
        Class::DefiExpire => "DefiExpire",
        Class::DefiClaim => "DefiClaim",
        Class::DefiHandover => "DefiHandover",
        Class::DefiSlots => "DefiSlots",
        Class::DefiEarnEpoch => "DefiEarnEpoch",
        Class::VaultMerge => "VaultMerge",
        Class::ReserveCost => "ReserveCost",
        Class::ReleaseConfirm => "ReleaseConfirm",
        Class::VaultKey => "VaultKey",
        Class::VaultRebalance => "VaultRebalance",
        Class::PoolWithdraw => "PoolWithdraw",
        Class::Unbond => "Unbond",
        Class::MembershipBond => "MembershipBond",
        Class::Equivocation => "Equivocation",
        Class::FinalityVote => "FinalityVote",
        Class::ReserveTheft => "ReserveTheft",
        Class::BondTransition => "BondTransition",
        Class::OrderFill => "OrderFill",
        Class::OrderPost => "OrderPost",
        Class::BridgeCredit => "BridgeCredit",
        Class::AssetCreate => "AssetCreate",
        Class::DsolDeploy => "DsolDeploy",
        Class::DirEntry => "DirEntry",
        Class::IonOrder => "IonOrder",
        Class::IonSettle => "IonSettle",
        Class::DsolCall => "DsolCall",
        Class::DsolFeeUpdate => "DsolFeeUpdate",
        Class::AssetMint => "AssetMint",
        Class::SatoshiReward => "SatoshiReward",
        Class::MinerPayout => "MinerPayout",
        Class::SatDelegation => "SatDelegation",
        Class::BondYieldClaim => "BondYieldClaim",
        Class::BountyPayout => "BountyPayout",
        Class::SatSetAside => "SatSetAside",
        Class::DeploymentSignal => "DeploymentSignal",
        Class::ReleaseAttestation => "ReleaseAttestation",
        Class::EpochKeyDeal => "EpochKeyDeal",
        Class::EpochKeyFraud => "EpochKeyFraud",
        Class::SatBond => "SatBond",
        Class::AssetSpend => "AssetSpend",
        Class::Liquidation => "Liquidation",
        Class::TheftRepayment => "TheftRepayment",
        Class::PotFill => "PotFill",
        Class::DecoyBatch => "DecoyBatch",
        Class::DecoyReturn => "DecoyReturn",
        Class::UnitOpen => "UnitOpen",
        Class::UnitClose => "UnitClose",
        Class::WrappedAssetRegister => "WrappedAssetRegister",
        Class::PriceMark => "PriceMark",
        Class::WrappedMint => "WrappedMint",
        Class::PegIn => "PegIn",
        Class::PegOut => "PegOut",
        Class::YieldClaim => "YieldClaim",
    }
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::{
        canonical, class_name, current_door_accepts, padded, prefix_door_accepts, CLASSES,
        JUNK_LENGTHS,
    };

    /// ⛔ `CLASSES` IS THE ONE HAND-KEPT LIST IN THIS FAMILY, AND IT HAD SILENTLY DROPPED TWO CLASSES. The matches
    /// are exhaustive by construction; the list was not, so Unbond and PriceMark were never tail-tested. Every
    /// class byte the framing layer accepts must be listed, and nothing else may be.
    #[test]
    fn every_class_the_framing_layer_accepts_is_in_the_tail_family() {
        let mut blob = crate::chain_object::frame(crate::chain_object::Class::OrderFill, &[0u8]);
        let at = crate::chain_object::MAGIC.len();
        let mut known = 0usize;
        for b in 0..=u8::MAX {
            blob[at] = b;
            if let Some((class, _)) = crate::chain_object::unframe(&blob) {
                known += 1;
                assert!(
                    CLASSES.contains(&class),
                    "{} is a framed class the tail-tolerance family never covers",
                    class_name(class)
                );
            }
        }
        assert_eq!(known, CLASSES.len(), "CLASSES lists a class the framing layer refuses, or one class twice");
    }

    /// MUST-STAY-GREEN: the exact wire still decodes. A strictness fix that also refuses honest traffic
    /// is not a fix, and this is the half of the property that keeps the other half honest.
    #[test]
    fn every_canonical_class_encoding_still_decodes_at_the_current_door() {
        // EVERY class is judged before the pin fails. It used to stop at its first red class, so one stale fixture hid
        // every class listed after it (MEASURED 2026-11-11: red at DefiClaim, then at DefiSlots behind it, and the two
        // classes added after them had never been judged here at all).
        let refused: Vec<&str> = CLASSES.iter().copied().filter(|class| !current_door_accepts(*class, &canonical(*class))).map(class_name).collect();
        assert!(
            refused.is_empty(),
            "{refused:?} — the canonical encoding must still decode, or the strict decoder is refusing honest traffic"
        );
    }

    /// ⭐⭐⭐ I-12 AT EVERY CLASS DECODER: one object, one encoding.
    ///
    /// Generated from the class table, not written per decoder: `CLASSES` is exhaustive over
    /// `chain_object::Class`, so a sixth class cannot be added without this family covering it.
    #[test]
    fn a_trailing_byte_forgery_is_refused_at_every_class_decoder() {
        let mut checked = 0usize;
        for class in CLASSES {
            let bytes = canonical(class);
            for junk in JUNK_LENGTHS {
                let forged = padded(&bytes, junk);
                checked += 1;
                assert!(
                    !current_door_accepts(class, &forged),
                    "{} — a {junk}-byte tail was TOLERATED: `encode(x) ‖ junk` decodes to the same \
                     object under a different content id, so one object has two identities. The pool's \
                     by-id dedup goes blind and the object can ride a block more than once.",
                    class_name(class)
                );
            }
        }
        assert_eq!(checked, CLASSES.len() * JUNK_LENGTHS.len(), "the family did not run in full");
        eprintln!("[lane-f wire] {checked} trailing-byte forgeries refused across {} classes", CLASSES.len());
    }

    /// ⭐⭐⭐ THE SELF-PROOF: THE SAME GENERATED FAMILY, AGAINST THE PRE-FIX DECODER.
    ///
    /// A harness that has never been shown to catch anything is a green light with no bulb in it. This
    /// runs the IDENTICAL family, with the IDENTICAL oracle, against the decoder the tree actually used
    /// before 2026-09-06 — `postcard::from_bytes`, called the way the pre-fix source called it — and
    /// requires the family to go RED at every class.
    ///
    /// It then SHRINKS the find the way the stateful lane shrinks a schedule: the minimal forgery is the
    /// smallest junk length that still forges, and the assertion is that it is ONE byte.
    ///
    /// ⛔ The test passes when the OLD decoder is caught. If this ever fails, the family has stopped
    /// being able to see the hole it was built for, and every green run it reports elsewhere is
    /// meaningless until that is explained.
    #[test]
    fn the_wire_family_catches_the_pre_fix_prefix_tolerant_decoder_at_every_class() {
        let mut caught: Vec<String> = Vec::new();
        let mut minimal_junk: Vec<usize> = Vec::new();

        for class in CLASSES {
            let bytes = canonical(class);

            // The pre-fix decoder must accept the canonical bytes too, or the comparison is not
            // like-for-like and the "catch" below would be an artefact.
            assert!(
                prefix_door_accepts(class, &bytes),
                "{} — the pre-fix decoder must accept the canonical encoding, or this is not a \
                 like-for-like comparison",
                class_name(class)
            );

            // SHRINK: the smallest junk length that still forges. `JUNK_LENGTHS` is ascending, so the
            // first hit is the minimal reproducer for this class.
            let mut smallest: Option<usize> = None;
            for junk in JUNK_LENGTHS {
                let forged = padded(&bytes, junk);
                if prefix_door_accepts(class, &forged) && smallest.is_none() {
                    smallest = Some(junk);
                }
            }

            match smallest {
                Some(k) => {
                    caught.push(format!("{} (minimal forgery: {k} junk byte(s))", class_name(class)));
                    minimal_junk.push(k);
                }
                None => {}
            }
        }

        assert_eq!(
            caught.len(),
            CLASSES.len(),
            "the wire family caught the pre-fix decoder at only {} of {} classes: {caught:?}. This \
             family exists because the 2026-09-06 red team measured 5 of 5 RED; a family that can no \
             longer see that hole cannot be trusted to report a clean run anywhere else.",
            caught.len(),
            CLASSES.len()
        );

        for k in minimal_junk.iter() {
            assert_eq!(
                *k, 1,
                "the minimal forgery should shrink to ONE junk byte — one byte is all it takes to change \
                 `blake3(blob)` while leaving the decoded object identical"
            );
        }

        eprintln!(
            "[lane-f wire] SELF-PROOF: the pre-fix decoder was caught at {}/{} classes, every one \
             shrinking to a 1-byte forgery; the current decoder refuses all {} of them.",
            caught.len(),
            CLASSES.len(),
            CLASSES.len() * JUNK_LENGTHS.len()
        );
        for line in caught.iter() {
            eprintln!("[lane-f wire]   caught: {line}");
        }
    }
}
