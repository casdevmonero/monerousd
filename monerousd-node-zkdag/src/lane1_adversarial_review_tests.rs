// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ADVERSARIAL REVIEW OF LANE 1's HOLE-A3/A4 CLOSURE (2026-09-08) — the FRESH attacks, not the
//! fixer's own pins. Lane 1 states a COMPLETENESS LAW on `sync::sync_binding`: "Every field of
//! `SyncBundle` that an adopting node ACTS ON must be in this preimage", and an enumeration table
//! whose rows read `tip_block | by id` and `fold_carry | carry_digest`. These tests construct the
//! same attack the audit's own A3/A4 pins construct — a relay edits a bundle that already verifies —
//! against the fields the enumeration did NOT reach, and measure what the adopt door does.
//!
//! Nothing here is a fix and nothing here is a fixture for one: these are MEASUREMENTS of the tree as
//! it stands, written so the next round argues with a number instead of with a paragraph.
//!
//! ROOT-LAYER: each attack is aimed at the layer where the certified value is PRODUCED and CONSUMED —
//! `sync::sync_binding` (the preimage a decider proof is transcript-bound to) and `Node::instant_sync`
//! (the one door that installs a bundle). Nothing is asserted at a downstream reader, because a reader
//! cannot tell a certified byte from an invented one, which is the whole point of the holes below.
//! MEASURED before writing these: the lane's own pins re-run on this tree — family-A
//! `a_tampered_bundle_cannot_install_a_max_weight_anchor_as_the_selected_tip` GREEN
//! (`adopt=FrontierUnbound anchor_in_dag=false work_after=32 honest_work=32`), family-D D-2/D-3/D-4
//! GREEN (`[dsync] REFUSED a bundle carrying a block this node's header door does not admit`), D-1
//! still RED by design, and family-A's `a_tampered_anchor_blue_work_breaks_the_sync_binding` still RED
//! (it ends in an unconditional `panic!`, so no production change can turn it green).
//! MUST-STAY-GREEN: everything the lane listed — the #29 DSYNC adopt suite, both rolling-restart pins,
//! the dex three-party pin, the no-growth census and the canonical_record_fold jump/adopt pins. These
//! tests add no production code and change no behaviour, so they cannot move any of them.
//!
//! SCALE: every block below is built by `Node::produce`, so each carries this chain's PRODUCTION
//! constant-256 cover (`cover::BLOCK_FIXED_NOTE_COUNT`) by construction — nothing here shrinks a
//! cover, a note set or a nullifier set. `CHAIN_BLOCKS` is a CHAIN LENGTH (how many blocks the
//! serving node has mined before it serves), the one axis a #29 bundle is O(1) in; the attacks are on
//! ONE bundle and do not vary with it.
//!
//! cons: none — three in-memory nodes, one bundle apiece, one adopt call each. No store, no walk over
//! history, no retained structure, and no term in chain height, block count or note count.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::block::Block;
    use crate::decider::{ConsensusVerifier, DeciderBundle};
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::sync::AdoptOutcome;

    /// How many blocks the SERVING node mines before it builds a bundle — a chain length, not a
    /// cover count. It only has to exceed `record_fold_depth` so the bundle carries a real anchor
    /// AND a non-empty `fold_carry.unfolded`; each of these blocks holds the full production cover.
    const CHAIN_BLOCKS: u64 = 12;

    struct AcceptAll;
    impl ConsensusVerifier for AcceptAll {
        fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
            true
        }
    }

    fn testnet_node() -> Node {
        let mut p = ChainParams::default();
        p.genesis_parity_commit = network_genesis_prefix("testnet");
        p.net_prefix_len = p.genesis_parity_commit.len();
        p.record_fold_depth = 4;
        let mut g = crate::node::tests::genesis_block();
        g.header = crate::block::genesis_header_for_network(&network_genesis_prefix("testnet"));
        Node::with_params(g, p).expect("a testnet node builds")
    }

    fn genesis_ts(n: &Node) -> u64 {
        n.dag()
            .get(&n.selected_tip().expect("tip"))
            .expect("header")
            .header
            .timestamp
    }

    fn produce(n: &mut Node, ts: u64, tag: &str) -> Block {
        n.produce(ts, Hash32::hash(tag.as_bytes()), Hash32::hash(b"miner"))
            .expect("a block produces")
    }

    /// A serving node with a chain long enough to serve a bundle with a real carry.
    fn served_node(tag: &str) -> Node {
        let mut a = testnet_node();
        let t0 = genesis_ts(&a);
        for k in 0..CHAIN_BLOCKS {
            produce(&mut a, t0 + 60_000 * (k + 1), &format!("{tag}{k}"));
        }
        a
    }

    fn bundle_of(node: &mut Node) -> crate::sync::SyncBundle {
        node.build_sync_bundle(
            vec![1u8; 4096],
            crate::sync::FrontierSnapshot {
                root: *node.note_frontier_root().as_bytes(),
                height: node.note_frontier_count(),
                peaks_hex: node.spend_frontier_peaks_hex(),
            },
        )
        .expect("the node serves a bundle")
    }

    fn attacker_note(tag: &[u8]) -> Vec<u8> {
        let mut n = vec![0xa5u8; crate::cover::PQ_NOTE_BYTES];
        n[..32].copy_from_slice(Hash32::hash(tag).as_bytes());
        n
    }

    /// Does the victim's record for `rid` contain the attacker's note? `None` (no record at all) is
    /// reported as `(0, false)` by the caller's own `match` — never rescued into a default here.
    fn injected_into(victim: &Node, rid: u64, tag: &[u8]) -> (usize, bool) {
        match victim.da_record_notes(rid) {
            Some(stored) => {
                let cm = Hash32::hash(tag);
                let found = stored
                    .chunks(crate::cover::PQ_NOTE_BYTES)
                    .any(|c| c.len() >= 32 && &c[..32] == cm.as_bytes());
                (stored.len(), found)
            }
            None => (0, false),
        }
    }

    /// REVIEW ATTACK 1 — the SAME hole A3 states, one field further in: a relay edits the BODY BYTES
    /// of the certified tip block. `Block::id()` is `header.id()`, so the id the binding folds does
    /// not move; `header.output_notes_root` / `account_targets_root` exist to commit those bodies, and
    /// nothing on the #29 adopt path re-hashes the body against them (`validate_header_structural` is
    /// header + tx-ids only, by construction). `instant_sync` then applies both verbatim.
    /// ROOT-LAYER: asserted on the adopt door's own outcome and on the victim's stored record — the
    /// two things the door PRODUCES — not on a later reader of those bytes.
    /// MEASURED: see the module doc; the number this test prints is the verdict.
    /// MUST-STAY-GREEN: nothing — this test adds no production code.
    /// cons: none — one serving node, one bundle, one adopt; f(fixed constants).
    #[test]
    fn review_a3_the_certified_tip_blocks_body_bytes_are_not_bound_by_the_completeness_law() {
        let mut a = served_node("g");
        let honest = bundle_of(&mut a);
        let honest_acc = honest.decider.chain_acc;
        let tip_id = honest.tip_block.header.id();

        let mut tampered = honest.clone();
        tampered.tip_block.output_notes = attacker_note(b"review-a3-injected-note");
        tampered.tip_block.account_targets = b"review-a3-injected-targets".to_vec();

        assert_eq!(
            tampered.tip_block.id(),
            honest.tip_block.id(),
            "premise: the body edit does not move the block id the binding folds"
        );
        assert_eq!(
            tampered.decider.chain_acc, honest_acc,
            "premise: the body edit does not move the accumulator the proof is bound to"
        );

        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let out = victim.instant_sync(tampered);
        let rid = Node::da_record_id_for_block(&tip_id, 0);
        let (bytes, holds_injected) = injected_into(&victim, rid, b"review-a3-injected-note");
        eprintln!(
            "[review-a3] adopt={out:?} tip_record_bytes={bytes} holds_attacker_note={holds_injected}"
        );

        assert!(
            !matches!(out, AdoptOutcome::Adopted(_)) && !holds_injected,
            "REVIEW REFUTATION — hole A3 is closed for four scalars and OPEN for the bodies the same \
             door applies. `instant_sync` returned {out:?} for a bundle whose ONLY edit is \
             `tip_block.output_notes` / `tip_block.account_targets`, and the victim's record for the \
             certified tip holds the attacker's note = {holds_injected}. The binding is byte-identical \
             (asserted above), so ONE valid proof certifies both bundles — exactly the shape of A3. \
             `sync_binding`'s table row `tip_block | by id` is therefore not the whole answer: the id \
             is `header.id()`, and the header's `output_notes_root` / `account_targets_root` are never \
             checked against the carried body on this path. FIX SPEC — ONE shared site, no per-caller \
             patch: `Node::bundle_blocks_admitted` already visits every block a bundle carries through \
             `Node::header_door_admits`; give that door the BODY-commitment half as well (the same \
             `blake3` roots `consensus::validate_structural` checks for the gossip door), so tip, \
             anchor, ancestors and unfolded blocks are all judged at the one function."
        );
    }

    /// REVIEW ATTACK 2 — the carry arm of the same class. `FoldCarry::digest` folds each carried
    /// block's `(id, blue_work, blue_score)` and the difficulty samples; it does NOT fold the blocks'
    /// bodies. `Node::graft_unfolded_carry` reads `b.account_targets` and `b.output_notes` off the
    /// carried block and files them. The serve side deliberately BLANKS `unfolded` notes, so the
    /// attacker is adding bytes the honest bundle never carried.
    /// ROOT-LAYER: asserted on `FoldCarry::digest` (the value the binding folds) and on the victim's
    /// stored record — the producer of the certified digest and the consumer of the carried bytes.
    /// MEASURED: see the module doc; the number this test prints is the verdict.
    /// MUST-STAY-GREEN: nothing — this test adds no production code.
    /// cons: none — one serving node, one bundle, one adopt; f(fixed constants).
    #[test]
    fn review_a3_the_carried_blocks_bodies_are_not_bound_by_the_carry_digest() {
        let mut a = served_node("c");
        let served = bundle_of(&mut a);
        // G11b: the honest serve is CONSTANT — it carries no unfolded window (the backlog rides the follow page). The
        // carry arm of the door still exists on the receive side, so the attacker supplies the window itself: a REAL
        // block above the served anchor, with the server's own blue data, in the carry slot — then edits its body.
        assert!(served.fold_carry.unfolded.is_empty(), "setup: the constant bundle carries no unfolded window");
        let (above, _) = a
            .whole_blocks_after_locator(&[served.tip_block.id()], 32, 1 << 20, &[], &[])
            .expect("the server holds its served anchor");
        let carried = above.into_iter().next().expect("setup: the server holds blocks above its served anchor");
        let h = a.dag().get(&carried.id()).expect("held");
        let (bw, bs) = (h.blue_work, h.blue_score);
        let mut honest = served.clone();
        honest.fold_carry.unfolded.push((carried, bw, bs));
        let honest_digest = honest.fold_carry.digest();
        let victim_id = honest.fold_carry.unfolded[0].0.id();

        let mut tampered = honest.clone();
        tampered.fold_carry.unfolded[0].0.output_notes = attacker_note(b"review-a3-carry-note");
        tampered.fold_carry.unfolded[0].0.account_targets = b"review-a3-carry-targets".to_vec();

        assert_eq!(
            tampered.fold_carry.digest(),
            honest_digest,
            "premise: the carry digest does not move when a carried block's BODY is edited"
        );
        assert_eq!(
            tampered.decider.chain_acc, honest.decider.chain_acc,
            "premise: the accumulator the proof is bound to does not move either"
        );

        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let out = victim.instant_sync(tampered);
        let rid = Node::da_record_id_for_block(&victim_id, 0);
        let (bytes, holds_injected) = injected_into(&victim, rid, b"review-a3-carry-note");
        eprintln!(
            "[review-a3-carry] adopt={out:?} carried_record_bytes={bytes} holds_attacker_note={holds_injected}"
        );

        assert!(
            !holds_injected,
            "REVIEW REFUTATION — a carried block's BODY rides the certified bundle unbound. The carry \
             digest is byte-identical (asserted above) yet the victim's record for a REAL block id now \
             holds the attacker's note. Same FIX SPEC as review attack 1: the body-commitment rules \
             belong at `Node::header_door_admits`, which every carried block already passes through."
        );

        // G11b — THE FOLLOW-PAGE ARM: the honest backlog above the anchor now reaches a joiner on the follow page, so the
        // same body edit on a page body must be refused by the ordinary ingest door and leave nothing installed.
        let mut joiner = testnet_node();
        joiner.set_decider_verifier(Box::new(AcceptAll));
        assert!(matches!(joiner.instant_sync(served), AdoptOutcome::Adopted(_)), "setup: the joiner adopts the honest bundle");
        let mut paged = honest.fold_carry.unfolded[0].0.clone();
        paged.output_notes = attacker_note(b"review-a3-carry-note");
        paged.account_targets = b"review-a3-page-targets".to_vec();
        let ts = paged.header.timestamp + 500;
        let verdict = joiner.ingest_block(paged, ts);
        let (page_bytes, page_holds) = injected_into(&joiner, rid, b"review-a3-carry-note");
        eprintln!("[review-a3-page] ingest={verdict:?} record_bytes={page_bytes} holds_attacker_note={page_holds}");
        assert!(
            !matches!(verdict, crate::relay::RelayOutcome::Added(_)) && !page_holds,
            "REVIEW REFUTATION — a follow-page body edited under a real header was ADMITTED ({verdict:?}) and the joiner's \
             record holds the attacker's note = {page_holds}: the ingest door must check the body against the header roots."
        );
    }

    /// REVIEW ATTACK 3 — the `peaks_hex` row of the completeness table reads "DERIVED-BOUND:
    /// `instant_sync` refuses a spine that does not reproduce `frontier.root`". That derivation is
    /// guarded by `if !bundle.frontier.peaks_hex.is_empty()`, so the DERIVED binding vanishes when a
    /// relay STRIPS the field rather than editing it. This test states what actually happens, so the
    /// table row is judged against behaviour rather than against its own wording.
    /// ROOT-LAYER: asserted on the adopt door's verdict, the place the derivation is performed.
    /// MEASURED: see the module doc; the number this test prints is the verdict.
    /// MUST-STAY-GREEN: nothing — this test adds no production code.
    /// cons: none — one serving node, one bundle, one adopt; f(fixed constants).
    #[test]
    fn review_a3_a_stripped_frontier_spine_is_not_refused_by_the_derived_binding() {
        let mut a = served_node("p");
        let honest = bundle_of(&mut a);
        assert!(
            !honest.frontier.peaks_hex.is_empty(),
            "setup: the honest bundle carries a spine"
        );
        let mut stripped = honest.clone();
        stripped.frontier.peaks_hex = String::new();
        assert_eq!(
            stripped.decider.chain_acc, honest.decider.chain_acc,
            "premise: stripping the spine does not move the binding"
        );

        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let out = victim.instant_sync(stripped);
        eprintln!("[review-a3-peaks] adopt_of_stripped_spine={out:?}");
        assert!(
            !matches!(out, AdoptOutcome::Adopted(_)),
            "REVIEW NOTE — the completeness table calls `peaks_hex` DERIVED-BOUND, but the derivation \
             runs only when the field is NON-EMPTY: a relay that deletes it adopts fine ({out:?}). The \
             adopted accumulator itself IS bound (`frontier.root`), so this is an extensibility/\
             liveness downgrade rather than a state substitution — but 'DERIVED-BOUND' is not what the \
             code does, and the row should say so."
        );
    }
}
