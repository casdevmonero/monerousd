// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔ QUESTION 1 — PROVE-FALSE. Can an ACCEPTING proof be produced for a FALSE statement?
//!
//! "False" here is measured against the statement the CHAIN needs, not against the statement the AIR
//! happens to encode. That distinction is the whole lane: a gate can be perfectly satisfied and still
//! certify nothing a payment depends on.
//!
//! Every attempt below runs the PRODUCTION entry — `whir_decider::pqspend_direct_verify_carrier` and
//! `chain_object::admissible` for the send door, `whir_decider::decider_verify_light` for the adopt
//! gate (the coinbase bind was retired 2026-09-18) — never a re-implementation, so a
//! verdict here is a verdict about the node that ships.
//!
//! ⛔ THIS MODULE WEAKENS NO GATE. It calls existing verifiers and reports their verdicts; it edits no
//! consensus code, relaxes no check, and adds no code path a node can reach. Where a pin ASSERTS a
//! hole, the hole was measured, not introduced — see the module doc of [`super`] for why an
//! open-break pin is written to go RED on closure.
//!
//! COST, arithmetic written down — cons: none. Every pin is a pure function of bytes the attacker
//! controls: a FIXED 32-row × ≤3-column trace (32 × 3 × 4 B = 384 B) and one ~8.7 KB carrier per pin,
//! `#[cfg(test)]` only, so nothing here links into the node binary. 0 B persisted, 0 sockets, 0 state
//! mutated. Per-pin cost is f(fixed trace shape) — never f(chain height, note count, record count or
//! peer count) — so it is identical on block 1 and on block 10^9.

use crate::harness::circuit::{
    KOALABEAR_P, amount_as_field_element, amount_column_32, send_carrier_public_bind,
};
use crate::hash::Hash32;
use crate::mempool::PqTx;
use usdm_decider::{SpendConservationGate, SpendRow, prove_spend_carrier_bytes};

/// This chain's fee rate and mint allowance as a MAINNET node derives them: allowance 0 means no
/// mint-class object can ever be satisfied, so nothing below is smuggled in through a mint class.
/// Everything these pins admit is admitted as an ORDINARY SEND.
pub const MAINNET_FEE_BPS: u64 = 10;
pub const MAINNET_MINT_ALLOWANCE: u64 = 0;

/// Build the transaction an attacker would actually submit: an UNFRAMED blob (so the door routes it
/// to the send gate, exactly as `chain_object::admissible` documents), carrying whatever nullifiers
/// and output notes the attacker chose. The anti-spam stamp is ground honestly — an attacker grinds
/// it too, and this lane never wants a refusal it can attribute to the wrong door.
pub fn hostile_tx(blob: &[u8], nullifiers: Vec<Hash32>, output_notes: Vec<u8>) -> PqTx {
    let id = PqTx::content_id(blob);
    let mut stamp = 0u64;
    loop {
        let tx = PqTx {
            clock_ms: 0,
            id,
            blob: blob.to_vec(),
            weight: blob.len() as u32,
            nullifiers: nullifiers.clone(),
            pow_stamp: stamp,
            output_notes: output_notes.clone(),
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses: Vec::new(),
            nullifier_absence: Vec::new(),
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        if tx.stamp_work() >= 1 {
            return tx;
        }
        stamp += 1;
    }
}

/// The production SEND DOOR verdict on a blob, asked exactly the way `Node::admit_tx_shared` asks it.
pub fn send_door_admits(blob: &[u8]) -> bool {
    crate::chain_object::admissible(blob, MAINNET_FEE_BPS, MAINNET_MINT_ALLOWANCE, false)
}

#[cfg(all(test, feature = "pins-harness"))]
mod pins {
    use super::*;

    /// ⛔⛔⛔ PIN C-1 — A CARRIER THAT PROVES NO NOTE, NO KEY AND NO MEMBERSHIP IS ADMITTED.
    ///
    /// THE ATTACK, stated as an attacker would: I hold no note. I know no spend key. I have no
    /// membership witness for any leaf of any frontier. I run one PUBLIC function with three numbers
    /// I invented, and I hand the result to the node's send door.
    ///
    /// WHAT MUST HAPPEN for funds to be safe: the door refuses, because a send carrier should be
    /// unprovable without (a) a note that is in the tree, (b) the key that opens it, (c) a nullifier
    /// derived from both.
    ///
    /// ✅ CLOSED 2026-09-08, AND THE VERDICT ASSERTED IS THE **RECEIVING PEER'S**.
    ///
    /// `prove_spend_carrier_bytes` still needs none of those: its whole witness is `[in, out, fee]`
    /// and its whole public input is a CONSTANT domain tag. What changed is that this statement is no
    /// longer an ADMISSION ROUTE. `chain_object::admissible`'s unframed arm answers `false` — no
    /// blob-only rule can judge a spend, whose statement is welded to the transaction's own
    /// nullifiers, both recorded output commitments and the membership cross-bind — and the submit
    /// door's disjunction no longer carries `direct_ok`.
    ///
    /// The door measured here is the one a REMOTE VERIFIER runs on gossip it did not submit
    /// (`Node::ingest_tx` -> `chain_object::admissible`), so the assertion is about what a stranger
    /// concludes from the attacker's bytes alone — not about what the attacker's own process decides.
    ///
    /// THE PIN HOLDS THE CLOSURE FROM BOTH ENDS: the verifier REFUSES the secretless carrier, and
    /// `pqspend_direct_verify_carrier` is measured STILL ACCEPTING it. That function is sound for the
    /// one statement it makes; the defect was ever asking it. Keeping both halves means that if some
    /// future door is re-pointed at it, this pin names exactly what was re-opened.
    #[test]
    fn c1_a_spend_carrier_proving_no_note_no_key_and_no_membership_is_refused_by_a_verifier() {
        // Everything an attacker needs: three numbers that add up. No key. No note. No tree.
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 1,
            out_value: 1,
            fee: 0,
        }])
        .expect("the public prover accepts a witness of three invented numbers");

        // The statement's own verifier — unchanged, and sound for what it claims.
        let conservation_gate =
            crate::whir_decider::pqspend_direct_verify_carrier(&carrier).is_some();
        // What a RECEIVING VERIFIER concludes from these bytes on the gossip path.
        let verifier_admits = send_door_admits(&carrier);
        println!(
            "[C-1] carrier bytes={} conservation gate={conservation_gate} \
             receiving verifier admits={verifier_admits} (secrets required to build it: NONE)",
            carrier.len()
        );
        assert!(
            conservation_gate,
            "PRECONDITION: the conservation statement still verifies under its own gate — if this \
             flips, this pin is measuring a broken prover, not a closed door"
        );
        assert!(
            !verifier_admits,
            "⛔ C-1 REOPENED: a receiving verifier ADMITTED a carrier built with no note, no key and \
             no membership witness. One such proof admits every transaction, and building it needs \
             no secret at all. Find which door was re-pointed at the conservation-only gate."
        );
    }

    /// ⛔⛔⛔ PIN C-2 — ONE CARRIER IS ADMITTED FOR EVERY DISTINCT TRANSACTION.
    ///
    /// A proof is only worth anything if it is about the thing it is attached to. This asks whether
    /// the send carrier is bound to its transaction at all, by presenting the SAME carrier bytes with
    /// wildly different nullifier sets and output notes and asking BOTH doors the node runs:
    /// `chain_object::admissible` (the class rule) and `chain_object::wrapper_binds_object` (the
    /// wrapper<->object binding at the pool door AND at note assembly).
    ///
    /// ✅ CLOSED 2026-09-08. The carrier's transcript still contains no tx field and never will — that
    /// is what the statement IS. The closure is that a statement naming no transaction is no longer a
    /// route: a receiving VERIFIER refuses every one of these transactions, including the one that
    /// matters most (ZERO nullifiers, so nothing is spent, and 1,153 bytes of output note, so value
    /// appears from nowhere — the mint shape `wrapper_binds_object` waves through by design because an
    /// unframed blob is not a framed object).
    ///
    /// The pin now asserts the count from the other end: ZERO of these transactions are admitted, and
    /// it names the mint case explicitly so a partial re-opening cannot hide inside an aggregate.
    #[test]
    fn c2_one_carrier_admits_no_transaction_at_all() {
        let carrier = prove_spend_carrier_bytes(&[SpendRow {
            in_value: 7,
            out_value: 6,
            fee: 1,
        }])
        .expect("prove a single honest-shaped conservation carrier");

        // Four transactions with nothing in common but the carrier bytes. The last is the one that
        // matters: ZERO nullifiers (nothing is spent) and 1,153 bytes of output note (value appears).
        let cases: Vec<(&str, Vec<Hash32>, Vec<u8>)> = vec![
            ("honest-shaped", vec![Hash32::hash(b"nf-a")], vec![0u8; 1153]),
            (
                "someone else's nullifier",
                vec![Hash32::hash(b"nf-victim")],
                vec![9u8; 1153],
            ),
            (
                "sixteen nullifiers, four notes",
                vec![Hash32::hash(b"nf-x"); 16],
                vec![3u8; 4 * 1153],
            ),
            ("NO nullifier at all, one note", Vec::new(), vec![7u8; 1153]),
        ];

        let mut admitted: Vec<&str> = Vec::new();
        for (name, nfs, notes) in &cases {
            let tx = hostile_tx(&carrier, nfs.clone(), notes.clone());
            // The class rule a RECEIVING VERIFIER runs on gossip it did not submit.
            let class_door = send_door_admits(&tx.blob);
            let wrapper_door = crate::chain_object::wrapper_binds_object(&tx);
            println!(
                "[C-2] tx '{name}': nullifiers={} note_bytes={} class_door={class_door} \
                 wrapper_door={wrapper_door}",
                nfs.len(),
                notes.len()
            );
            if class_door && wrapper_door {
                admitted.push(name);
            }
        }
        assert!(
            admitted.is_empty(),
            "⛔ C-2 REOPENED: a verifier admitted {} of {} transactions that share one carrier's \
             bytes and agree on nothing else: {admitted:?}. A proof that admits a transaction it \
             does not name admits every transaction — and the 'NO nullifier at all, one note' case \
             is value appearing with nothing spent.",
            admitted.len(),
            cases.len()
        );
    }

    /// ✅✅✅ PIN C-3 — CLOSED 2026-09-11, NOW MUST-STAY-GREEN. A ROW THAT DOES NOT CONSERVE IN u64 IS
    /// REFUSED IN-CIRCUIT.
    ///
    /// What this pin recorded as OPEN: the no-inflation gate was ONE KoalaBear field identity,
    /// `in - out - fee == 0`, and the only integer test lived in the PROVER's own column builder —
    /// code the attacker never runs, because `prove_air_direct_light_decider_selfcontained_bytes` is
    /// public and takes the columns directly. `out = in + p` therefore proved and verified: two
    /// amounts differing by p (= 21.31 USDm) satisfied the same conservation.
    ///
    /// What closed it — BORROWED, not derived (user-locked: "no more rederiving"): the Zcash
    /// Sapling/Orchard value shape, in the exact form `confidential_solvency` already exercised at nine
    /// sites. Each amount is four 16-bit limbs; `out + fee == in` is a limb-wise carry chain with the
    /// TOP CARRY FORCED ZERO (wrap-around unrepresentable); every limb is bit-decomposed with bits
    /// constrained boolean and the reconstruction bound to the limb (the RANGE constraint, without
    /// which the other two prove nothing). Width 3 → `SC_WIDTH` (208). The prover-side `checked_add`
    /// STAYS — it binds an honest prover; the gate binds a dishonest one.
    ///
    /// Three halves asserted: the honest builder still refuses the u64-overflowing row; the OLD attack
    /// shape (a 3-column trace) can no longer even be proven against the gate; and the NEW attack
    /// shape — a hand-built full-width trace whose limb is wider than 16 bits while the linear limb
    /// equation still balances — is REFUSED by the node's own door. Mutation-checked in the decider:
    /// removing the reconstruction constraint turns the 70000-limb pin RED while the control stays
    /// green (`whir_rec_block::range_binding_acceptance`).
    #[test]
    fn c3_a_row_that_does_not_conserve_in_u64_still_proves_and_verifies() {
        use usdm_decider::{spend_carrier_cols, SC_IN, SC_OUT};
        let in_value = 5u64;
        let out_value = 5u64 + KOALABEAR_P; // 2,130,706,438 — a strictly larger integer
        assert!(out_value > in_value, "the row must be non-conserving over the integers");

        // (a) The honest builder refuses it — unchanged, and still not the load-bearing check.
        assert!(
            prove_spend_carrier_bytes(&[SpendRow { in_value, out_value, fee: 0 }]).is_none(),
            "the honest column builder's native u64 test must refuse a non-conserving row"
        );

        // (b) The OLD attack — three raw field columns with `out ≡ in (mod p)` — no longer fits the
        //     circuit at all: the range-bound gate reads 208 columns, so a 3-column trace cannot be
        //     proven against it. (The prover trips on its OWN trace; that is the attacker's process,
        //     never the verifier's, and the verifier's shape latch refuses the width regardless.)
        assert_eq!(
            amount_as_field_element(out_value),
            amount_as_field_element(in_value),
            "in-circuit the two amounts WERE the same field element — that was the whole attack"
        );
        let narrow = std::panic::catch_unwind(|| {
            usdm_decider::prove_air_direct_light_decider_selfcontained_bytes(
                vec![amount_column_32(in_value), amount_column_32(out_value), amount_column_32(0)],
                |gamma| SpendConservationGate::new(gamma),
                &send_carrier_public_bind(),
            )
        });
        let narrow_carrier_exists = matches!(narrow, Ok(Some(_)));
        assert!(
            !narrow_carrier_exists,
            "⛔ C-3 REOPENED: the 3-column `out = in + p` trace produced a carrier against the \
             range-bound gate — the gate is reading only the first three columns again"
        );

        // (c) The NEW attack: a full-width hand-built trace, honest bits, a limb shifted by 70000
        //     (> 2^16) on BOTH out and in so the linear limb equation still balances. Only the
        //     reconstruction constraint can refuse it — and the node's door must.
        let mut cols = spend_carrier_cols(&[SpendRow { in_value: 6, out_value: 5, fee: 1 }])
            .expect("the honest trace to mutate");
        let shift = 70_000u64;
        cols[SC_OUT][0] = amount_as_field_element(5 + shift);
        cols[SC_IN][0] = amount_as_field_element(6 + shift);
        assert_ne!(
            cols[SC_OUT][0],
            amount_as_field_element(5),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT"
        );
        let wide = usdm_decider::prove_air_direct_light_decider_selfcontained_bytes(
            cols,
            |gamma| SpendConservationGate::new(gamma),
            &send_carrier_public_bind(),
        );
        let node_gate = match &wide {
            Some(forged) => crate::whir_decider::pqspend_direct_verify_carrier(forged).is_some(),
            None => false,
        };
        let door = match &wide {
            Some(forged) => send_door_admits(forged),
            None => false,
        };
        println!(
            "[C-3] 3-col attack proves={narrow_carrier_exists} · 70000-limb attack: carrier={} \
             conservation gate={node_gate} verifier admits={door}",
            wide.is_some()
        );
        assert!(
            !node_gate,
            "⛔⛔ C-3 REOPENED: a limb of 70000 (> 2^16) proved and the node's conservation gate \
             ACCEPTED it. The linear equation balanced and nothing bound the limb to its bits."
        );
        assert!(
            !door,
            "⛔ THE DOOR REGRESSED: a verifier admitted a hand-built conservation-only carrier. It \
             must never be reachable by a carrier that needs nothing."
        );
    }

    /// ⛔⛔ PIN C-4 — A WHOLE-CHAIN PROOF FOR AN INVENTED ACCUMULATOR VERIFIES.
    ///
    /// This is D01, re-measured INDEPENDENTLY of the family-D lane so the finding does not rest on
    /// one lane's word. `decider_prove_light` takes the accumulator as its ONLY argument and proves a
    /// FIXED public AIR that reads nothing from any chain; the accumulator is welded into the
    /// Fiat-Shamir transcript, which SEPARATES chains but PROVES none.
    ///
    /// The attack needs no chain, no blocks, no keys and no peers: pick 16 bytes, prove, verify.
    #[test]
    fn c4_a_whole_chain_proof_for_an_invented_accumulator_verifies() {
        // An accumulator naming a chain that does not exist and never did.
        let invented = *b"NO-SUCH-CHAIN-01";
        let proof = crate::whir_decider::decider_prove_light(&invented)
            .expect("the whole-chain prover is public and takes no witness");
        let verified = crate::whir_decider::decider_verify_light(&proof, &invented);

        // …and the adopt gate itself, over a bundle whose tip was never mined.
        let bundle = crate::decider::DeciderBundle {
            tip: Hash32::hash(b"a tip no miner ever ground"),
            blue_score: 1_000_000,
            chain_acc: invented,
            proof: proof.clone(),
        };
        let adopt = crate::decider::accept_bundle(&crate::whir_decider::WhirDecider, &bundle);
        println!(
            "[C-4] invented accumulator: proof bytes={} verify={verified} adopt_gate={adopt} \
             (chain state consulted by the prover: NONE)",
            proof.len()
        );
        assert!(
            verified && adopt,
            "C-4 CLOSED: the whole-chain decider now refuses an accumulator no chain produced, so \
             the proof has become a CHAIN statement (public inputs (A_prev, A_next) with a \
             transition witness). Record the construction that closed it."
        );
    }

    // c5 (the coinbase's self-declared reward value) RETIRED 2026-09-18 with the coinbase bind itself: the
    // chain is zero-emission and the block carries no coinbase carrier any more — there is no value claim
    // to prove false. The refusal that remains (bind bytes / a non-zero bind on a block) is pinned in
    // `pow::a_block_carrying_bind_bytes_or_a_nonzero_bind_is_refused`.
}
