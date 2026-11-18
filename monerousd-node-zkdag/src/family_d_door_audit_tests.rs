// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ FAMILY D DOOR AUDIT (§9.6, 2026-09-07) — WANT-SLOT / SNAPSHOT / CERTIFIED-BUNDLE /
//! OVERLAY / ORACLE INGRESS.
//!
//! WHY THIS FILE EXISTS: the block-locator descent lane (2026-09-07) added a second way for a block
//! to enter the DAG, carried the merkle and parents-present checks across, and did not carry the PoW
//! check — a fabricated shell claiming work 8.5e37 took the selected tip against an honest tip of 295.
//! The charter's question 6 ("name the door this parallels, list EVERY check that door runs, and state
//! for EACH whether this path carries it") exists because of it. This file hunts the SIBLINGS of that
//! omission in the family whose doors move WHOLE STATE in one step: the #29 DSYNC certified-bundle
//! adopt, the want-slot wideners, the signed-overlay adopts, the transport's bulk lane beneath them,
//! and the two EXTERNAL oracles that gate minting.
//!
//! EVERY test here is an ADVERSARIAL PIN: it CONSTRUCTS the attack and runs it. A pin that goes RED is
//! a CONFIRMED HOLE and is LEFT RED as the fix spec — it is not to be relaxed, weakened, deleted or
//! `#[ignore]`d. Fix the door; the pin turns green on its own.
//!
//! cons: none on any growth axis — this file is `#[cfg(test)]` only, adds no store and no wire path.
//! Its costs are f(fixed constants), never f(history): 3 whole-chain proves at the pinned
//! `WHOLE_CHAIN_T = 32` shape (a fixed-height trace, identical work at any chain length), one 5,000-
//! iteration in-memory loop of ~40 B strings ≈ 200 KB released at test end, and one source-file read.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    fn attacker_nullifier_snapshot() -> NullifierSnapshot {
        NullifierSnapshot {
            letter_acc: crate::letter::letter_acc_genesis(),
            dir_acc: crate::directory::dir_acc_genesis(),
            finality_validators: Vec::new(),
            custody_seat_active_from: Vec::new(),
            finality_seat_active_from: Vec::new(),
            departed_custody_seats: Vec::new(),
            departed_finality_seats: Vec::new(),
            seat_words: Vec::new(),
            bonded_validators: Vec::new(),
            slashed_validators: Vec::new(),
            slashed_bond_burned: 0,
            validator_bond_commit: usdm_decider::poseidon2_compress::zero_digest(),
            validator_custody: Vec::new(),
            validator_kem_eks: Vec::new(),
            custody_seat_numbers: Vec::new(),
            applied_one_time_ids: Vec::new(),
            peg_reserve_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_minted_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_reserve_hwm_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_ratio_bps: 0,
            peg_redeem_floor_bps: 0,
            peg_yield_rate_bps: 0,
            peg_sat_issued: 0,
            peg_pendulum: (0, 0),
            peg_br: Default::default(),
            nf_fold_base_words: Default::default(),
            nf_fold_span: Vec::new(),
            peg_price_marks: Vec::new(),
            bond_heights: Vec::new(),
            bond_locked_notes: Vec::new(),
            unbonding: Vec::new(),
            peg_wrapped_assets: Vec::new(),
            peg_pools: Vec::new(),
            peg_retention_endowment_commit: usdm_decider::poseidon2_compress::zero_digest(),
            l2_state_root: [0u8; 32],
            root_history_peaks_hex: crate::spend_frontier::PoseidonSpendFrontier::new().peaks_hex(),
            membership_tip: (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()),
            root: *Hash32::hash(b"attacker-nf").as_bytes(),
            count: 7,
            sparse_root: [0u8; 32],
            band: Vec::new(),
            band_next_ordinal: 0,
            band_awaiting: Vec::new(),
            nf_cover_conf_acc: [0u8; 32],
            nf_unspent_acc: usdm_decider::poseidon2_compress::zero_digest(),
            dsol_registry_peaks: Vec::new(),
            dsol_registry_count: 0,
            peg_ion_pending: Vec::new(),
            peg_ion_pools: 0,
            peg_ion_usdm_held: 0,
        }
    }
    /// A block an attacker types out. NO grind, NO `pow_proof`, `work` set to whatever it likes —
    /// exactly the shell class the 2026-09-07 descent hole admitted.
    fn fabricated_block(tag: &[u8], work: u128) -> Block {
        let mut b = crate::node::tests::genesis_block();
        b.header = BlockHeader {
            level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
            note_commitments_root: crate::hash::Hash32::hash(&[]),
            nullifier_tags_root: Hash32::hash(&[]),
            output_notes_root: Hash32::hash(&[]),
            oli_tags_root: crate::block::da_sidecar_root_of(&[]),
            // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
            credit_set_root: crate::block::da_sidecar_root_of(&[]),
            transitions_root: crate::block::empty_transitions_root(),
            cover_seed_commit: crate::hash::Hash32::ZERO,
            member_ring_commit: crate::hash::Hash32::ZERO,
            account_targets_root: crate::block::da_sidecar_root_of(&[]),
            bond_set_root: crate::block::da_sidecar_root_of(&[]),
            dir_set_root: crate::block::da_sidecar_root_of(&[]),
            letter_set_root: crate::block::da_sidecar_root_of(&[]),
            tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
            version: 1,
            parents: vec![],
            timestamp: 1,
            nonce: 0,
            work,
            pow_bind: Hash32::ZERO,
            tx_merkle_root: Hash32::hash(tag),
            frontier_root: Hash32::ZERO,
            nullifier_root: Hash32::ZERO,
            sparse_root: Hash32::ZERO,
            chain_acc: [0u8; 16],
            miner_commitment: Hash32::ZERO,
            account_root: Hash32::ZERO,
        };
        b.pow_proof = Vec::new(); // NOT MINED. Nothing was ever ground for this block.
        b
    }
    use crate::block::{Block, BlockHeader};
    use crate::decider::DeciderBundle;
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::sync::{
        sync_binding, AdoptOutcome, FoldCarry, FrontierSnapshot, NullifierSnapshot, SyncBundle,
    };

    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        Node::with_params(g, p).expect("a testnet node builds")
    }

    /// Build a bundle for a chain state the attacker INVENTS, then mint the whole-chain decider proof
    /// for it with the SAME public entry every honest server calls. Nothing here is stolen or replayed:
    /// every field is chosen, and the certificate is produced locally.
    fn self_minted_bundle(
        genesis_commit: &[u8],
        tip_block: &Block,
        blue_work: u128,
        blue_score: u64,
        nullifier: NullifierSnapshot,
    ) -> Option<SyncBundle> {
        let tip = tip_block.id();
        let frontier = FrontierSnapshot {
            root: *Hash32::hash(b"attacker-frontier").as_bytes(),
            height: blue_score,
            peaks_hex: String::new(),
        };
        let carry = FoldCarry::default();
        let chain_acc = sync_binding(
            &tip,
            blue_score,
            &frontier,
            &nullifier,
            genesis_commit,
            &tip,
            blue_score,
            &carry.digest(),
            // Arity only (2026-09-07): `sync_binding` now folds the fork-choice weights and the record
            // base. The attacker mints the binding around the weights IT wants — which is the point of
            // this fixture, and is why binding them does not close D-1/D-2/D-4.
            blue_work,
            blue_work,
            0,
        );
        // THE WHOLE ATTACK IN ONE LINE: the production prover takes the accumulator as its ONLY input.
        let proof = crate::whir_decider::decider_prove_light(&chain_acc)?;
        Some(crate::sync::with_fixture_cert(SyncBundle {
            join: Default::default(),
            cert: crate::sync::unset_cert(),
            tip_cover_key: None,
            tip_wide_objects: Vec::new(),
            decider: DeciderBundle {
                tip,
                blue_score,
                chain_acc,
                proof,
            },
            frontier,
            nullifier,
            tip_block: tip_block.clone(),
            blue_work,
            genesis_commit: genesis_commit.to_vec(),
            anchor_block: tip_block.clone(),
            anchor_blue_work: blue_work,
            anchor_blue_score: blue_score,
            anchor_ordinal: 0,
            fold_carry: carry,
            tips: Vec::new(), // test fixture: no sibling tips beyond the selected one
            anchor_ring: Vec::new(),
            member_ring_commits: Vec::new(),
        }))
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // D01 — THE #29 DSYNC CERTIFIED-BUNDLE ADOPT (node.rs `instant_sync`, sync.rs `adopt_sync_bundle`,
    //       whir_decider.rs `WhirDecider`). §9.6 QUESTION 2: "is the object's own validity proof
    //       verified here, or taken on trust — name what verifies it and where."
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⭐ PIN D-1 — THE ADOPT GATE'S EVIDENCE MUST BE A STATEMENT ABOUT A CHAIN.
    ///
    /// `whir_decider::decider_prove_light` takes ONE argument: `chain_acc`. It proves the FIXED public
    /// `TallSisOpenAir` (`usdm-decider/src/whole_chain.rs`), with `chain_acc` used only to seed the
    /// Fiat-Shamir transcript — so the (prove, verify) pair attests exactly one fact, *"somebody ran the
    /// prover with THIS accumulator"*, and every party can run the prover. Every field of a #29 DSYNC
    /// bundle is bound into that accumulator by `sync_binding`, so all of them were FORGEABLE BY
    /// CONSTRUCTION.
    ///
    /// ⛔ THAT DECIDER IS STILL EXACTLY WHAT IT WAS, AND THE CALIBRATION BELOW HOLDS IT THERE. The fix
    /// was never to make a fixed public AIR say something about a chain — it cannot. The fix is a SECOND,
    /// REQUIRED piece of evidence at the door: `usdm_decider::whole_chain_cert`, a chain of
    /// `ivc_one_table` steps each recursively verifying the step below it, bottoming out at a base step
    /// anchored on the empty chain with zero work. `adopt_sync_bundle` now refuses a bundle without one,
    /// and refuses one whose certificate stands for any position other than the one the bundle declares.
    ///
    /// ⛔ WHAT THIS PIN DOES NOT CLAIM, STATED HERE SO NOBODY READS MORE INTO IT. A ONE-STEP base
    /// certificate is legitimately mintable by anyone — it says "the empty chain plus this position" —
    /// and `acc_step_air` binds the ADDITION of work but not the per-step figure, because re-executing a
    /// memory-hard PoW in-circuit is MEASURED impossible (kill list §AB). So the certificate is a gate
    /// that can only REFUSE. What stops a chainless party from serving a bundle at all is the PoUW
    /// WITNESS door (§AH), held green by `block_ingress_door_audit_tests`.
    #[test]
    fn pin_d1_a_self_minted_whole_chain_proof_must_not_verify_as_a_chain_certificate() {
        use crate::decider::ConsensusVerifier;
        // An accumulator over a chain that does not exist: an invented tip, an invented frontier, an
        // invented spent-state. No block was mined, no state was folded, nothing was replayed.
        // The tip BLOCK and the certified tip must agree, or the bundle is refused by the tip check
        // ahead of the certificate gate and this pin measures that check instead.
        let shell = fabricated_block(b"family-d-pin-d1", u128::MAX);
        let invented_tip = shell.id();
        // MEASURED 2026-11-13 (lane goods): the door answers this bundle `FrontierUnbound`, with an invented root and with the
        // empty frontier served as its own spine alike: the frontier binding refuses it before the certificate gate this pin
        // names, so the bundle is refused and the pin's red is the gate it reached, not an acceptance.
        // MEASURED 2026-11-15 (lane goodshalt, main bc4fc829): that empty-frontier attempt kept anchor_ordinal 9,999,999, and the
        // spine check (`sync::frontier_spine_binds`) also asks count == anchor_ordinal × BLOCK_FIXED_NOTE_COUNT, so it still read
        // `FrontierUnbound`. An attacker binds every field it chooses: here the EMPTY frontier, served as its own spine (its
        // real root and peaks), at record ordinal 0, so every structural check passes and the bundle meets the certificate gate.
        let empty = crate::spend_frontier::PoseidonSpendFrontier::new();
        let frontier = FrontierSnapshot {
            root: crate::spend_frontier::leaf_to_cm_bytes(empty.root()),
            height: 0,
            peaks_hex: empty.peaks_hex(),
        };
        let nullifier = attacker_nullifier_snapshot();
        let genesis = network_genesis_prefix("testnet");
        let carry = FoldCarry::default();
        let invented = sync_binding(
            &invented_tip,
            9_999_999,
            &frontier,
            &nullifier,
            &genesis,
            &invented_tip,
            9_999_999,
            &carry.digest(),
            u128::MAX,
            u128::MAX,
            0,
        );
        let proof = crate::whir_decider::decider_prove_light(&invented)
            .expect("the PUBLIC production prover mints a proof for any accumulator handed to it");
        let decider = DeciderBundle {
            tip: invented_tip,
            blue_score: 9_999_999,
            chain_acc: invented,
            proof,
        };

        // ⭐ CALIBRATION — THE HOLE IS STILL THERE IN THE OBJECT IT WAS ALWAYS IN. The production
        // decider verifier ACCEPTS a certificate minted by a party with no chain. If this ever flips,
        // the fixed AIR has been changed into something else and every claim below needs re-deriving.
        assert!(
            crate::whir_decider::WhirDecider.verify_bundle(&decider),
            "CALIBRATION FAILED: `WhirDecider` refused a self-minted proof, so this pin is no longer \
             measuring the decider it names. Re-derive before trusting the guarantee below."
        );

        let attacker = SyncBundle {
            join: Default::default(),
            cert: crate::sync::unset_cert(),
            tip_cover_key: None,
            tip_wide_objects: Vec::new(),
            decider,
            frontier,
            nullifier,
            tip_block: shell.clone(),
            blue_work: u128::MAX,
            genesis_commit: genesis.to_vec(),
            anchor_block: shell.clone(),
            anchor_blue_work: u128::MAX,
            anchor_blue_score: 9_999_999,
            anchor_ordinal: 0,
            fold_carry: carry,
            tips: Vec::new(),
            anchor_ring: Vec::new(),
            member_ring_commits: Vec::new(),
        };

        // ⭐⭐⭐ THE GUARANTEE: the DOOR refuses it, and names WHY. `accept_bundle` is no longer treated
        // as evidence of anything — the bundle carries no certificate, so no field of it is installed.
        let door = crate::sync::adopt_sync_bundle(&crate::whir_decider::WhirDecider, None, &attacker);
        assert!(
            matches!(door, crate::sync::AdoptOutcome::CertificateUnproven),
            "⛔ (the door answered {door:?}) CONFIRMED HOLE (§9.6 Q2, D01): the production adopt gate accepted a bundle whose only \
             evidence was a certificate MINTED BY THE ATTACKER for an accumulator the attacker chose. \
             Every field of the #29 DSYNC bundle is bound into that accumulator by `sync_binding` and \
             is therefore FORGEABLE BY CONSTRUCTION. `adopt_sync_bundle` must not treat `accept_bundle` \
             as evidence and no bundle field may be installed on its authority."
        );

        // And a certificate for some OTHER position does not rescue it: the adopter RECOMPUTES the
        // summary from the fields it is about to install and never reads it off the wire.
        let mut elsewhere = attacker.clone();
        let mut other = elsewhere.clone();
        other.blue_work = 1;
        elsewhere.cert = crate::sync::with_fixture_cert(other).cert;
        assert!(
            matches!(
                crate::sync::adopt_sync_bundle(&crate::whir_decider::WhirDecider, None, &elsewhere),
                crate::sync::AdoptOutcome::CertificateUnproven
            ),
            "⛔ A CERTIFICATE FOR ANOTHER POSITION WAS ACCEPTED FOR THIS ONE"
        );
    }

    /// ⛔ PIN D-2 — A SELF-MINTED BUNDLE MUST NOT BE ADOPTED BY A NODE RUNNING THE PRODUCTION
    /// VERIFIER (the end-to-end form of D-1, through the real door).
    ///
    /// §9.6 Q1 (PoW) for this door: `instant_sync` never calls the header grind check on `tip_block`,
    /// on `anchor_block`, or on any block in `fold_carry`. The reference door (`preverify_block`) runs
    /// that check on every gossiped block. The bundle door's stated substitute for it is the decider
    /// proof — which D-1 shows is not a chain statement.
    #[test]
    fn pin_d2_a_self_minted_dsync_bundle_must_not_be_adopted() {
        let genesis_commit = network_genesis_prefix("testnet");
        let mut node = testnet_node();
        node.set_decider_verifier(Box::new(crate::whir_decider::WhirDecider)); // THE PRODUCTION GATE

        // A shell that was never mined, claiming absurd accumulated work.
        let shell = fabricated_block(b"family-d-takeover", u128::MAX);
        let bundle = self_minted_bundle(
            &genesis_commit,
            &shell,
            u128::MAX, // heavier than any honest chain will ever be
            9_999_999,
            attacker_nullifier_snapshot(),
        )
        .expect("the production prover mints the certificate");

        let outcome = node.instant_sync(bundle);
        assert!(
            !matches!(outcome, AdoptOutcome::Adopted(_)),
            "⛔ CONFIRMED HOLE (§9.6 Q1+Q2, D01): a node running the PRODUCTION `WhirDecider` adopted a \
             bundle whose every field the attacker chose and whose certificate the attacker minted \
             locally. Outcome was {outcome:?}. This is whole-state substitution in ONE message: the \
             adopt installs the certified nullifier count and leaf count, the sparse root, the \
             nf-unspent acc (and indexes it as a chain-held accumulator), the unspent-note root, the \
             letter and directory accumulators and the bonded validator set VERBATIM. FIX SPEC: see \
             PIN D-1 — the adopt gate needs a proof that constrains the chain. INDEPENDENTLY of that, \
             `instant_sync` must ALSO run the reference door's OWN PoW check — \
             `crate::pow::verify_block_pow(&header, &pow_proof, hasher)`, which node.rs \
             `preverify_block` runs on every gossiped block (the carried blocks are full `Block`s, so \
             their `pow_proof` is present), falling back to the header-only \
             `pow::hash_meets_target(&hash(header.preimage()), header.work)` for a shell — on \
             `tip_block`, on `anchor_block` and on every block in `fold_carry.ancestors` / \
             `fold_carry.unfolded` before any of them reaches `Dag::add_anchor` / `add_ancestor_anchor` / \
             `add_carried_block` — none of those three verify work — so a no-proof shell can never be \
             the selected tip even if the decider gate is weakened again."
        );
    }

    /// A shell an attacker types out that SATISFIES every rule the one header door can ask without
    /// the shell's ancestry: a parent it names but the victim does not hold, `work = 1` (the value at
    /// which the grind's target is the whole digest space — and an HONEST DAA value, so no floor may
    /// refuse it), a `tx_merkle_root` that reproduces its empty tx list, every sidecar root sealing an
    /// empty sidecar, `version = 1`, a plausible timestamp. NO grind, NO `pow_proof`.
    fn well_formed_unmined_shell(tag: &[u8]) -> Block {
        let mut b = fabricated_block(tag, 1);
        b.header.parents = vec![Hash32::hash(b"a-parent-the-victim-does-not-hold")];
        b.header.tx_merkle_root = crate::miner::tx_merkle_root(&[]);
        b.header.timestamp = 1_700_000_000_000;
        b
    }

    /// ⛔ PIN D-2b (2026-09-11) — THE ARMED FORM OF D-2: A WELL-FORMED NEVER-MINED SHELL WHOSE
    /// PARENTS THE VICTIM DOES NOT HOLD, ON A SELF-MINTED CERTIFICATE, MUST NOT BE ADOPTED.
    ///
    /// D-2 / D-3 / D-4 went green on 2026-09-07 because their fixture is refused on STRUCTURE —
    /// `parents: vec![]` (`NoParents`) and a `tx_merkle_root` that does not reproduce the empty tx
    /// list — by `bundle_blocks_admitted`, the one header door. That door's own doc names what it
    /// cannot judge: "this door holds no ancestry for the carried tip and cannot" — `header_work_is_bound`
    /// returns "not judgeable" when a parent is not held, which is the HONEST jumper's shape by
    /// construction (a node jumps precisely because it lacks the tip's ancestry). So the rules that
    /// remain for a tip with unheld parents are: the grind at the header's OWN `work` (free at
    /// `work = 1`), structure, and the body commitments. All three are satisfiable by typing.
    ///
    /// What then stands between the attacker and whole-state substitution is the whole-chain
    /// certificate — and PIN D-1 shows it certifies nothing about a chain (the prover's trace is a
    /// function of `WHOLE_CHAIN_T` alone; `chain_acc` only seeds the transcript).
    ///
    /// REFUTATION-BEFORE-GREEN: this is the calibration pin that proves the ATTACK IS ARMED on the
    /// tree as it stands. It is expected RED until the adopt door's authority for a tip with unknown
    /// ancestry is something a party without the chain cannot mint — what every proven chain does:
    /// Bitcoin Core never accepts a header whose parent it does not hold (headers-first; chainwork is
    /// DERIVED from PoW-checked headers, never carried); Kaspa syncs a pruned node to a pruning point
    /// only through a PoW-VERIFIED header proof and verifies the downloaded state against the
    /// pruning-point header's own `utxo_commitment`; Mina's certificate is a recursive proof that
    /// VERIFIES the previous certificate and the transition in-circuit. None of the three admits a tip
    /// on a self-seeded fixed-AIR opening.
    #[test]
    fn pin_d2b_a_well_formed_unmined_shell_with_unheld_parents_must_not_be_adopted_on_a_self_minted_certificate() {
        let genesis_commit = network_genesis_prefix("testnet");
        let mut node = testnet_node();
        node.set_decider_verifier(Box::new(crate::whir_decider::WhirDecider)); // THE PRODUCTION GATE
        let honest_tip = node.dag().selected_tip().expect("the node starts on its own genesis");

        let shell = well_formed_unmined_shell(b"family-d-armed-takeover");
        let shell_id = shell.id();
        // The one header door, asked directly first, so the verdict below cannot be mistaken for a
        // structural refusal: this shell passes it.
        let mut nullifier = attacker_nullifier_snapshot();
        let attacker_id = [0xACu8; 32];
        nullifier.bonded_validators = vec![(attacker_id, u128::MAX / 2)];
        let bundle = self_minted_bundle(&genesis_commit, &shell, u128::MAX, 9_999_999, nullifier)
            .expect("the production prover mints the certificate");
        let door = node.bundle_blocks_refusal(&bundle).is_none();
        eprintln!("[pin-d2b] header door admits the well-formed unmined shell: {door}");

        let outcome = node.instant_sync(bundle);
        let tip_after = node.dag().selected_tip();
        let quorum = node.validators().bond_of(&attacker_id);
        eprintln!(
            "[pin-d2b] outcome={outcome:?} tip_moved={} attacker_bond={quorum}",
            tip_after == Some(shell_id)
        );
        assert!(
            !matches!(outcome, AdoptOutcome::Adopted(_)) && tip_after != Some(shell_id) && quorum == 0,
            "⛔ ARMED (D-2b): a node running the PRODUCTION `WhirDecider` adopted a bundle whose tip is \
             a WELL-FORMED, NEVER-MINED shell (work = 1, a parent this node does not hold, empty tx \
             list reproduced by its merkle root) on a certificate the attacker minted locally. Outcome \
             {outcome:?}; the header door admitted the shell: {door}; honest tip was {honest_tip:?}, \
             selected tip is now {tip_after:?}; the attacker's bond on this node is {quorum}. The one \
             header door cannot judge `work` without the parents (its own doc says so), and the \
             certificate is not a chain statement (PIN D-1) — so nothing on this door costs the \
             attacker a single hash. FIX = the proven shape, not a stricter door: a tip with unknown \
             ancestry is admitted only on evidence a party without the chain cannot mint — PoW-verified \
             ancestry (Bitcoin headers-first / Kaspa pruning-point proof, with the state verified \
             against the tip header's own commitment) or a certificate that recursively verifies the \
             chain transition (Mina)."
        );
    }

    /// ⛔ PIN D-3 — THE SELECTED TIP MUST NOT MOVE ONTO AN UNMINED SHELL.
    ///
    /// This is the 2026-09-07 takeover re-run through the certified-bundle door instead of the
    /// block-locator descent door. `Dag::add_anchor` reorgs on the CARRIED `blue_work` and inserts the
    /// block with `selected_parent: None` — it verifies no work at all, by design, because "the
    /// decider proof certifies it".
    #[test]
    fn pin_d3_a_self_minted_bundle_must_not_take_the_selected_tip_with_an_unmined_shell() {
        let genesis_commit = network_genesis_prefix("testnet");
        let mut node = testnet_node();
        node.set_decider_verifier(Box::new(crate::whir_decider::WhirDecider));
        let honest_tip = node
            .dag()
            .selected_tip()
            .expect("the node starts on its own genesis");

        let shell = fabricated_block(b"family-d-tip-takeover", u128::MAX);
        let shell_id = shell.id();
        let bundle = self_minted_bundle(
            &genesis_commit,
            &shell,
            u128::MAX,
            9_999_999,
            attacker_nullifier_snapshot(),
        )
        .expect("the production prover mints the certificate");
        let _ = node.instant_sync(bundle);

        let now = node.dag().selected_tip();
        assert_ne!(
            now,
            Some(shell_id),
            "⛔ CONFIRMED HOLE (§9.6 Q1, D01): the selected tip moved onto a block that was NEVER \
             MINED (empty `pow_proof`, `work` typed by the attacker), carried in on a locally-minted \
             certificate. The honest tip was {honest_tip:?}. Same class as the block-locator descent \
             takeover of 2026-09-07, one door over. FIX SPEC: PoW-gate every block a bundle carries at \
             `instant_sync` before `add_anchor` runs, and make `add_anchor` / `add_carried_block` / \
             `add_ancestor_anchor` refuse a header whose grind does not verify \
             (`pow::hash_meets_target` needs no witness and works on a shell) — ONE shared check at \
             the `BlockNode` construction sites, never a per-caller patch."
        );
    }

    /// ⛔ PIN D-4 — THE FINALITY QUORUM MUST NOT BE INSTALLABLE BY A SELF-MINTED BUNDLE.
    ///
    /// §9.6 Q3 (conservation) for D01: `instant_sync` installs `state.bonded_validators` verbatim.
    /// `sync_binding` folds the set into `chain_acc`, and sync.rs's own
    /// `a_forged_bonded_validator_set_breaks_the_sync_binding` proves a TAMPERED set changes the
    /// binding. That test is sound and stays green; it simply does not test the attack that matters,
    /// because an attacker does not tamper with someone else's bundle — it mints a fresh binding
    /// around the set it wants, then mints the matching certificate.
    #[test]
    fn pin_d4_a_self_minted_bundle_must_not_install_an_attacker_chosen_validator_set() {
        let genesis_commit = network_genesis_prefix("testnet");
        let mut node = testnet_node();
        node.set_decider_verifier(Box::new(crate::whir_decider::WhirDecider));

        let attacker_id = [0xABu8; 32];
        let mut nullifier = attacker_nullifier_snapshot();
        nullifier.bonded_validators = vec![(attacker_id, u128::MAX / 2)];

        let shell = fabricated_block(b"family-d-quorum-capture", 1);
        let bundle = self_minted_bundle(&genesis_commit, &shell, u128::MAX, 9_999_999, nullifier)
            .expect("the production prover mints the certificate");
        let _ = node.instant_sync(bundle);

        assert_eq!(
            node.validators().bond_of(&attacker_id),
            0u128,
            "⛔ CONFIRMED HOLE (§9.6 Q3, D01): a locally-minted bundle installed an attacker-chosen \
             bonded validator set, so the attacker alone holds the finality quorum on this node — it \
             can finalize any height it likes and the node will never see a conflicting finality vote \
             as authorized. Nothing on this path costs the attacker a bond. FIX SPEC: PIN D-1 — the \
             quorum is only as sound as the certificate that carries it."
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // D14 — THE SIGNED-OVERLAY GOSSIP ADOPTS (node_runtime.rs `WireMsg::` arms for Site / Vote /
    //       Name / Clue / NoteClue / Peer / Govern / Dir / Letter / Bond / LetterSet).
    //       §9.6 QUESTION 5 on the ONE arm that is declared UNAUTHENTICATED by design.
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⛔ PIN D-7 — THE UNAUTHENTICATED NoteClue ARM MUST NOT WRITE INTO A STORE THAT NEVER DRAINS.
    ///
    /// `Node::record_note_clue` is reached from the `WireMsg::NoteClue` gossip arm, which its own
    /// comment calls "UNAUTHENTICATED but money-safe … a forged/garbage clue can never lose money".
    /// That judgement is about the CLUE. It is not about the second store the same function writes:
    /// `self.pending_tags.insert(cm, k)`.
    ///
    /// `pending_tags` carries this declared bound in its own doc: "inserted when a tx is ACCEPTED and
    /// REMOVED when its block is recorded … drained EVERY block by `record_note_payload`, so its size
    /// is bounded by the mempool's fixed in-flight capacity". That is true of the tx-accept writer.
    /// It is FALSE of this gossip writer: the only removal is `pending_tags.remove(&cm)` in the record
    /// loop, which runs for a cm that actually appears in a recorded block. A cm an attacker invents
    /// never appears in any block, so its entry is never removed — and the same doc forbids ageing
    /// entries out ("a tag that misses its block silently hides that note from its owner forever"), so
    /// the store cannot be trimmed either. PARITY GAP (§9.6 Q6): the tx-accept writer's entries drain
    /// by construction; this writer's do not, and the field's stated bound was written for the first.
    ///
    /// ARITHMETIC of the defect being pinned: one entry is 32 B cm + `K_BYTES` key ≈ 48 B, and a
    /// gossiping attacker can name a fresh cm per message — at the beacon-era gossip rate of ~4
    /// messages/s that is 48 B × 4/s = 192 B/s = 16.6 MB/day = 6 GB/year of node RAM that nothing in
    /// the tree ever releases.
    /// cons: none for the pin itself — 5,000 × 48 B = 240 KB in-test, released with the process; no
    /// store, no wire path, no term in history.
    #[test]
    fn pin_d7_a_forged_note_clue_gossip_must_not_grow_a_store_that_never_drains() {
        let mut node = testnet_node();
        let pending_tags_len = |n: &Node| -> usize {
            n.da_entry_census_named()
                .into_iter()
                .find(|(name, _, _)| *name == "pending_tags")
                .map(|(_, len, _)| len)
                .expect("the census names pending_tags")
        };
        let before = pending_tags_len(&node);
        for i in 0..5_000u32 {
            let cm = *Hash32::hash(format!("forged-clue-cm-{i}").as_bytes()).as_bytes();
            let _ = node.record_note_clue(cm, vec![0x5Au8; 32]);
        }
        let after = pending_tags_len(&node);
        assert!(
            after.saturating_sub(before) < 5_000,
            "⛔ CONFIRMED HOLE (§9.6 Q5+Q6, D14): 5,000 forged NoteClue gossips grew `pending_tags` \
             {before} -> {after}. The store's own O1-INFINITY-REVIEWED bound says it is 'bounded by \
             the mempool's fixed in-flight capacity' because entries are removed when their block is \
             recorded — but a commitment an attacker invents is never in a block, so nothing removes \
             it, and the same doc forbids trimming it. Every node that hears the gossip pays, and the \
             `note_clues` serve cache beside it IS bounded, which is why the growth is invisible in \
             the obvious place. FIX SPEC: `record_note_clue` must stage a tag ONLY for a commitment \
             this node has evidence of — one it has already recorded (`da_seq_at_note_cm`) or one an \
             ACCEPTED tx in its own pool named. A commitment with neither may still fill the bounded \
             `note_clues` serve cache (that is what makes the hint useful, and that cache front-\
             evicts by design), but it must not reach `pending_tags`. Nothing legitimate is refused: \
             a real note's tag arrives with its own tx or rides its block's carried `oli_tags`, and \
             both of those writers already hold the evidence."
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // D15 — THE EXTERNAL ORACLES (btc_watch.rs / xmr_watch.rs): the only Family-D doors whose trust
    //       anchor is OUTSIDE the tree. §9.6 QUESTION 5: bounded work against a hostile input.
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⛔ PIN D-5 — WHAT THE DEPOSIT WATCHER SWEEPS MUST BE DECIDED BY THIS NODE, NOT BY ITS CALLER.
    ///
    /// `btc_watch::confirmed_pending_cached` does `c.want.insert(address.to_string())` on EVERY call,
    /// with no validation and no bound — its own doc says the watcher "keeps every address it has
    /// ever been asked about warm". Its caller from outside the crate is the `/btc_deposit_status` RPC
    /// route, which takes the string straight from a POST body. `start_deposit_watch` then makes ONE
    /// Tor round-trip PER ENTRY PER 8-SECOND CYCLE, forever.
    ///
    /// THE ATTACK: post N distinct strings. `want` grows with N (a direct no-growth-pillar violation),
    /// and the sweep time grows linearly with N, so the REAL reserve addresses are refreshed later and
    /// later — a deposit-confirmation liveness kill on the mint path, from a loopback route a web page
    /// can reach with a cross-origin POST.
    ///
    /// cons: none — 5,000 × ~40 B strings = ~200 KB of in-test memory, released with the process;
    /// no store, no wire path, no growth term in history.
    #[test]
    fn pin_d5_the_btc_deposit_watch_set_must_be_bounded_against_a_hostile_caller() {
        let before = crate::btc_watch::watch_set_len_for_audit();
        for i in 0..5_000u32 {
            let _ = crate::btc_watch::confirmed_pending_cached(&format!("tb1qaudit{i:032}"));
        }
        let after = crate::btc_watch::watch_set_len_for_audit();
        assert!(
            after.saturating_sub(before) < 5_000,
            "⛔ CONFIRMED HOLE (§9.6 Q5, oracle door): 5,000 strings a hostile caller typed became \
             5,000 permanent sweep entries ({before} -> {after}), each costing one Tor round-trip \
             every 8 s forever. FIX SPEC — make the swept set one this node PRODUCED, so nothing has \
             to be thrown away and no answer is ever destroyed: the set must be exactly the reserve \
             addresses this node ISSUED for open swaps (the peg-in path already mints them and learns \
             when a swap settles), and `confirmed_pending_cached` must READ that set rather than \
             extend it. A caller naming an address this node never issued gets whatever answer is \
             already held and adds no sweep work at all. The size is then f(concurrent open swaps) — \
             real pending business — never f(callers) and never f(history). Do not fix at the RPC \
             route: every other caller would keep the hole."
        );
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // D13 — THE TRANSPORT BULK LANE beneath every Family-D fetch (arti_transport.rs).
    //       §9.6 QUESTION 5: name the bound and its site. QUESTION 6: the outbound twin is the
    //       parallel door, and it runs a check this one does not.
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⛔ PIN D-6 — THE INBOUND BULK SERVE MUST BOUND WHAT ONE HOSTILE DIALER CAN MAKE IT HOLD.
    ///
    /// `serve_bulk_stream` reads a 4-byte length, admits anything up to the 16 MiB inbound frame
    /// ceiling (nine times the ≤1.8 MB transport pillar), allocates `vec![0u8; len]` up front, and
    /// then `read_exact`s the body with nothing to release the buffer if the body never comes. Its
    /// OUTBOUND twin, `bulk_exchange`, wraps BOTH of the same two reads in
    /// `tokio::time::timeout(60s)` — the check the inbound side does not carry. The accept loop
    /// `tokio::spawn`s one such task PER INBOUND STREAM with no semaphore.
    ///
    /// THE ATTACK: open N bulk streams, send the four bytes that declare 16 MiB on each, then stall.
    /// N × 16 MiB is pinned in RSS with nothing to reclaim it — the 2026-09-03 unbounded-outbound
    /// blowup shape (16+23 GB), inbound this time.
    ///
    /// A socket read-guard is not a bound on any proof's reach: no note, carrier or copath is ever
    /// judged by it, and the dialer simply reconnects and re-asks — the same guard the outbound twin
    /// already runs. What it bounds is how long an attacker's byte count holds this node's memory.
    ///
    /// This pin reads the source because the defect is an ABSENCE, and an absence has no runtime
    /// handle to grab (the same technique `store_bound_manifest_tests` uses).
    /// cons: none — one 3,800-line source read per run, f(a fixed file), never f(history).
    #[test]
    fn pin_d6_the_inbound_bulk_frame_read_must_bound_how_long_it_holds_a_hostile_buffer() {
        let src =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/arti_transport.rs"))
                .expect("the transport source is readable");
        let body = src
            .split("async fn serve_bulk_stream")
            .nth(1)
            .and_then(|s| s.split("/// One BULK fetch").next())
            .expect("serve_bulk_stream is present in the transport source");
        assert!(
            body.contains("tokio::time::"),
            "⛔ CONFIRMED HOLE (§9.6 Q5+Q6, D13): `serve_bulk_stream` allocates an attacker-declared \
             frame (up to the 16 MiB inbound frame ceiling) and then awaits the body with nothing to \
             release the buffer, while its outbound twin `bulk_exchange` wraps the identical two \
             reads in `tokio::time::timeout(60s)`. PARITY GAP: a check the sibling door runs and this \
             one does not. FIX SPEC: wrap BOTH `read_exact` calls in `serve_bulk_stream` in the same \
             60 s read-guard the outbound twin uses; bring the inbound frame ceiling down to the \
             ≤1.8 MB transport pillar the rest of the protocol is written against (a protocol-derived \
             value, not a tuned one); and gate the accept-side spawn on a bounded semaphore so \
             concurrent in-flight frame buffers are a fixed constant, never f(dialers)."
        );
    }




}
