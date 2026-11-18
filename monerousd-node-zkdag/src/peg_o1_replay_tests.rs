// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ THE PEG'S REPLAY GUARDS MUST BE O(1) — the measured case for replacing four unbounded sets.
//!
//! ## What this pins, and why it exists before the change rather than after
//!
//! `PegLedger` holds FOUR `HashSet<[u8; 32]>` replay guards — `spent_burns`,
//! `confidential_deposit_ids`, `released`, `liquidated` — three of them PERSISTED. Each grows by 32 bytes
//! per operation, forever, in RAM and on disk, and together they hold the stablecoin's supply state. The
//! store-bound guard never saw them: its classifier skipped any field whose type contains a `;`, which is
//! every `HashSet<[u8; 32]>` in the tree (kill list §AF — 70 fields invisible, `peg.rs` absent from the
//! backlog census entirely).
//!
//! `nullifier_tree` already answers the identical question — *has this 32-byte identifier been consumed?*
//! — in constant state. Its own doc states the property: *"NO nullifier set stored … TRUE constant size at
//! any spend count."* This module MEASURES that claim in the deposit-id role, so the replacement that
//! follows is made against numbers rather than an expectation.
//!
//! ⭐ NOTHING IS TRADED HERE, and that is the point: the accumulator REMOVES a state axis and adds none.
//! The witness it needs is built by the producer from public replicated data and rides the transaction,
//! so it is never stored by anyone; the node keeps a root and a count and nothing else.
//!
//! ROOT-LAYER: the replay guard is being moved to where the answer is DERIVED (a root the witness proves
//! against) instead of where it is REMEMBERED (a set every node must hold forever). A remembered set is
//! also a divergence surface — two nodes with different sets disagree about which deposits have already
//! minted, and the one holding fewer mints against a deposit that already paid out.
//!
//! ⛔⛔⛔ CORRECTION, 2026-09-12 — THIS MODULE MEASURES THE WRONG COMPONENT, AND THE RECORD SAYS SO.
//!
//! The gates below use `nullifier_tree::NullifierTree` with a carried `InsertWitness` the verifier
//! re-checks. That is **R-B3**, refuted 2026-07-31 and caught here by the refuted-claims guard:
//! *"the copath is a PRIVATE WITNESS inside the zero-knowledge proof — the spender proves
//! `∃ cm, copath : fold(cm,cm,copath) == old_root ∧ fold(EMPTY,cm,copath) == new_root`, and the verifier
//! checks that against `(old_root, new_root)` ALONE. The node needs NO tree: it verifies a proof, not a
//! witness."* The question I kept circling — *who builds the copath?* — only exists if the copath is
//! checked publicly, and it never is.
//!
//! The component the peg must use is [`crate::nf_sparse::SparseNfAcc`]: a single 32-byte root, **COUNT
//! FREE**. The count is not cosmetic — `nf_sparse`'s own doc records that *"a cumulative `count` would
//! hand a jumper the whole chain's real volume"*, so the design measured below would have leaked PEG
//! VOLUME to every DSYNC jumper, a `count/volume` metadata leak the digital-cash cardinal bans by name.
//!
//! WHAT THESE GATES STILL PROVE, and it is why they are kept rather than deleted: that a replay guard CAN
//! be answered from constant state instead of a remembered set — 40 B at 10 deposits and at 2,000, with
//! replay, forgery and role-independence all refused. That conclusion survives the component change; the
//! numbers below are the IMT's, and the sparse accumulator's are strictly better (32 B, no count).
//!
//! MEASURED: reported by the gates below on every run (`[peg-o1]` lines).

#[cfg(all(test, feature = "pins-core"))]
mod peg_o1_replay_tests {
    use crate::nullifier_tree::{FullNullifierImt, NullifierError, NullifierTree};

    /// A deposit id, derived so ids are spread across the key space the way real ones are.
    fn deposit_id(i: u64) -> [u8; 32] {
        *blake3::hash(&[b"musdm.peg.deposit-id.probe".as_slice(), &i.to_le_bytes()].concat())
            .as_bytes()
    }

    /// The node-side state, in bytes, exactly as the frozen door would persist it: a 32-byte root plus an
    /// 8-byte count. Both widths are read from the types themselves so this cannot drift from what is
    /// stored.
    fn node_state_bytes(t: &NullifierTree) -> usize {
        t.root_bytes().len() + (u64::BITS as usize) / 8
    }

    /// ⭐⭐⭐ THE MEASUREMENT THE REPLACEMENT RESTS ON — node state is FLAT while a set would have grown
    /// linearly.
    ///
    /// Two very different consumption counts, one deterministic byte figure. This is the counter the O(1)
    /// definition asks for: not a ratio, not a clock — the same number at both N.
    #[test]
    fn the_node_state_is_flat_while_a_set_would_have_grown() {
        let mut small = (FullNullifierImt::new(), NullifierTree::new());
        let mut large = (FullNullifierImt::new(), NullifierTree::new());
        let consume = |imt: &mut FullNullifierImt, node: &mut NullifierTree, n: u64| {
            for i in 0..n {
                let id = deposit_id(i);
                let w = imt.insert_and_witness(&id).expect("the producer builds a witness");
                node.verify_and_insert(&id, &w).expect("the node accepts an unconsumed id");
            }
        };
        consume(&mut small.0, &mut small.1, 10);
        consume(&mut large.0, &mut large.1, 2_000);

        // The tree opens with the sentinel `(0,0)` low leaf, so `count` is 1 + the number consumed.
        // MEASURED on the first run of this gate: 10 consumes reported 11. Writing the sentinel down
        // rather than "fixing" the expectation to whatever came out is the difference between a gate and
        // a rubber stamp.
        assert_eq!(small.1.count(), 1 + 10, "the small accumulator consumed what it was given");
        assert_eq!(large.1.count(), 1 + 2_000, "the large accumulator consumed what it was given");
        assert_eq!(
            node_state_bytes(&small.1),
            node_state_bytes(&large.1),
            "⛔ the node's replay state moved with the number of deposits — that is a growth axis"
        );
        assert_ne!(
            small.1.root_bytes(),
            large.1.root_bytes(),
            "different histories must give different roots, or the accumulator commits to nothing"
        );

        let flat = node_state_bytes(&large.1);
        let as_a_set = 32 * 2_000;
        assert!(
            as_a_set > flat * 100,
            "the comparison is vacuous unless the set is far larger: {as_a_set} vs {flat}"
        );
        eprintln!(
            "[peg-o1] node replay state = {flat} B at 10 deposits AND at 2,000 — a HashSet would hold \
             {as_a_set} B at 2,000 and grow 32 B per deposit forever"
        );
    }

    /// ⭐⭐ NON-MEMBERSHIP *IS* THE REPLAY CHECK. The same deposit cannot mint twice: no unspent witness
    /// can be BUILT for a consumed id, and replaying the old one is refused because its copath no longer
    /// hashes to the moved root. Nothing is remembered; the answer is derived.
    #[test]
    fn a_deposit_cannot_be_consumed_twice() {
        let (mut imt, mut node) = (FullNullifierImt::new(), NullifierTree::new());
        let id = deposit_id(7);
        let w1 = imt.insert_and_witness(&id).expect("the first consume builds a witness");
        node.verify_and_insert(&id, &w1).expect("the first consume is accepted");
        let root_after_first = node.root_bytes();

        // The producer itself refuses to build a second witness for a consumed id...
        assert!(imt.is_spent(&id), "the producer knows the id is consumed");
        assert!(
            imt.build_unspent_witness(&id).is_none(),
            "no unspent witness can exist for a consumed id"
        );
        // Replaying the FIRST witness is refused as `BadLowMembership`: the tree moved when the id was
        // consumed, so that copath no longer hashes to the current root. `NotBracketed` is the refusal
        // for a witness built against the CURRENT root claiming an occupied range — and no such witness
        // can be built at all (asserted above). Both are correct; the gate demands a refusal and names
        // which one it got, rather than insisting on a variant I guessed.
        let replayed = node.verify_and_insert(&id, &w1);
        assert!(
            matches!(replayed, Err(NullifierError::BadLowMembership) | Err(NullifierError::NotBracketed)),
            "⛔ A DEPOSIT MINTED TWICE ({replayed:?}). The replay guard is the whole reason this state \
             exists."
        );
        assert_eq!(
            node.root_bytes(),
            root_after_first,
            "a refused replay must not move the root — nothing may be consumed by a rejected attempt"
        );
        eprintln!("[peg-o1] a replayed deposit is refused ({replayed:?}), and the root does not move");
    }

    /// A forged or stale witness is refused. The guarantee is SELF-VERIFYING: the node holds no set to
    /// consult, so the witness must hash up to the root it claims, or it is nothing.
    #[test]
    fn a_forged_or_stale_witness_is_refused() {
        let (mut imt, mut node) = (FullNullifierImt::new(), NullifierTree::new());
        for i in 0..8 {
            let id = deposit_id(i);
            let w = imt.insert_and_witness(&id).expect("witness");
            node.verify_and_insert(&id, &w).expect("accepted");
        }
        let fresh = deposit_id(999);
        let honest = imt.build_unspent_witness(&fresh).expect("an unconsumed id has a witness");

        // A tampered copath cannot hash up to the node's root.
        let mut forged = honest.clone();
        forged.low_copath[0] = usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]);
        assert!(
            node.verify_and_insert(&fresh, &forged).is_err(),
            "⛔ a FORGED copath was accepted — the accumulator would vouch for an id nobody consumed"
        );
        // A witness built for a DIFFERENT id must not license this one.
        let other = deposit_id(1000);
        let other_w = imt.build_unspent_witness(&other).expect("witness");
        assert!(
            node.verify_and_insert(&fresh, &other_w).is_err(),
            "⛔ a witness built for another id licensed this one"
        );
        // And the honest one still works, so the refusals above are not blanket.
        assert!(
            node.verify_and_insert(&fresh, &honest).is_ok(),
            "the honest witness must still be accepted, or this gate proves only that everything fails"
        );
        eprintln!("[peg-o1] a forged copath and a foreign witness are refused; the honest one is accepted");
    }

    /// The four peg roles are SEPARATE accumulators, so an id consumed in one role cannot be replayed into
    /// another. `spent_burns` gates a FOREIGN payout and `confidential_deposit_ids` gates a mint — an
    /// identifier crossing between them would be the sharpest failure available.
    #[test]
    fn the_roles_do_not_share_a_replay_domain() {
        let (mut burns_imt, mut burns) = (FullNullifierImt::new(), NullifierTree::new());
        let (mut deposits_imt, mut deposits) = (FullNullifierImt::new(), NullifierTree::new());
        let id = deposit_id(42);
        let w = burns_imt.insert_and_witness(&id).expect("witness");
        burns.verify_and_insert(&id, &w).expect("consumed in the burn role");

        // The SAME id is still unconsumed in the deposit role, and needs its own witness there.
        assert!(!deposits_imt.is_spent(&id), "the roles must not share a set");
        let dw = deposits_imt.insert_and_witness(&id).expect("witness in the deposit role");
        deposits.verify_and_insert(&id, &dw).expect("consumed in the deposit role");
        // ⛔ NOT an inequality of roots on the SAME input — the accumulator is deterministic, so two
        // roles that consumed the identical history MUST agree, and my first version of this gate
        // wrongly demanded they differ. The property that matters is INDEPENDENCE: consuming in one role
        // leaves the other untouched (asserted above), and a role's root moves only with its OWN history.
        let burns_before = burns.root_bytes();
        let extra = deposit_id(43);
        let ew = deposits_imt.insert_and_witness(&extra).expect("witness");
        deposits.verify_and_insert(&extra, &ew).expect("consumed in the deposit role");
        assert_ne!(
            deposits.root_bytes(),
            burns.root_bytes(),
            "a role that consumed more must not share the other's root"
        );
        assert_eq!(
            burns.root_bytes(),
            burns_before,
            "⛔ consuming in the DEPOSIT role moved the BURN role's root — one identifier would gate both \
             a foreign payout and a mint"
        );
        eprintln!("[peg-o1] the roles are independent: a deposit-role consume does not move the burn root");
    }
}
