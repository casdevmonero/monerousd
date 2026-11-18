// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! LANE B's OWN PINS for the 2026-09-08 body-binding closure — the HONEST side of the change, and
//! the class the change ITSELF makes possible. The refutation pins are the reviewer's own three
//! attacks in `lane1_adversarial_review_tests`; nothing here restates them.
//!
//! THE CHANGE THESE GUARD, in one sentence: `Node::header_door_admits` — the ONE site the five
//! non-gossip block doors ask for their admission verdict — now takes the BLOCK and runs
//! `consensus::validate_carried_body_commitments`, the same body-commitment list the gossip door
//! runs, in its reduced-carrier form (a PRESENT part must reproduce its header commitment, an
//! ABSENT part applies nothing); and `sync::sync_binding` now HASHES the peak spine it used to call
//! "derived-bound".
//!
//! MEASURED, the reviewer's three attacks on this tree after the change (filtered single-test run,
//! warm dir `~/.cargo-targets/refut-laneB`): `3 passed; 0 failed`, with
//! `[dsync] ⛔ REFUSED a bundle carrying a block this node's header door does not admit` and
//! `[review-a3] adopt=Unverified tip_record_bytes=0 holds_attacker_note=false`,
//! `[review-a3-carry] adopt=Unverified carried_record_bytes=0 holds_attacker_note=false`. BEFORE,
//! as the review filed it: the door took `(header, tx_ids)` and ran NO body rule at any of the five
//! sites, so the tampered bundle adopted and the victim's record for the CERTIFIED TIP held the
//! attacker's note.
//!
//! ⭐ WHAT THE CHANGE MAKES POSSIBLE THAT WAS IMPOSSIBLE BEFORE, which is why this file exists: a
//! door that previously admitted EVERY body now REFUSES one, so the new failure mode is an HONEST
//! object refused — an honest bundle, an honest carry, an honest shell. That corrupts no state but
//! WOULD wedge a joiner off the mesh, because a refused bundle installs nothing and the #29 jump is
//! the only path a fresh node has. `honest_bundle_blocks_are_all_admitted_by_the_body_aware_door`
//! and `an_honest_bundle_carrying_no_spine_still_adopts` are that pin, measured on real produced
//! blocks rather than argued. The SECOND new possibility is a split rule applied at the wrong
//! strength: the reduced form is strictly weaker than the full one, so a future caller swapping it
//! into the gossip door would silently unbind every gossiped body while every other test stayed
//! green — `the_two_body_doors_differ_exactly_on_the_absent_case` pins the difference itself and
//! `the_gossip_door_still_runs_the_full_form` pins that the gossip door did not get the weak arm.
//!
//! ROOT-LAYER: every assertion is on a PRODUCING site — `Node::bundle_blocks_admitted` and
//! `Node::header_door_admits` (which DECIDE admission) and `consensus::validate_*_body_commitments`
//! (which STATE the rule) — never on a downstream reader, because a reader cannot tell an admitted
//! byte from a refused one, which is the whole point of a door.
//! MUST-STAY-GREEN: the #29 DSYNC adopt suite, the family-A and family-D door audits, and the
//! reviewer's three attacks. These tests add no production code and change no behaviour.
//!
//! SCALE: every block is built by `Node::produce`, so each wears this chain's PRODUCTION
//! constant-256 cover shape by construction — nothing here shrinks a cover, a note set or a
//! nullifier set, and no constant is tuned to make anything pass.
//!
//! cons: none — in-memory nodes, one bundle apiece, one adopt each. No store, no walk over history,
//! and no term in chain height, block count or note count.

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use crate::block::Block;
    use crate::decider::{ConsensusVerifier, DeciderBundle};
    use crate::hash::Hash32;
    use crate::node::Node;
    use crate::params::{network_genesis_prefix, ChainParams};
    use crate::sync::AdoptOutcome;

    /// A CHAIN LENGTH (how many blocks the serving node mines before it serves), not a cover count:
    /// it only has to exceed `record_fold_depth` so the bundle carries a real anchor AND a non-empty
    /// carried-block set. Each of these blocks holds the full production cover shape.
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

    /// THE HONEST-PATH PIN for the whole change: a bundle this chain's own serve produced — whose
    /// tip and anchor carry a REDUCED body (`build_sync_bundle` blanks every sidecar) and whose
    /// carry holds shells (`Node::header_shell` blanks all of them) and blanked note payloads — is
    /// ADMITTED whole by the door that now judges bodies, and ADOPTS.
    ///
    /// WHY THIS IS THE PIN AND NOT A FORMALITY: the body-commitment rules in their WHOLE-BODY form
    /// (`consensus::validate_structural`) refuse every one of those objects, because the honest
    /// serve ships bytes the header does not commit to shipping. That is precisely the trap this
    /// change had to avoid, and the difference between the two forms is one bit no amount of reading
    /// can verify.
    /// ROOT-LAYER: asserted on `bundle_blocks_admitted` — the verdict site — and on the adopt
    /// outcome, not on any later reader of the adopted state.
    /// MEASURED (this run, warm dir `~/.cargo-targets/refut-laneB`): see the printed
    /// `[laneB-honest] bundle_blocks_admitted=true adopt=Adopted(..)`. Against it, the reviewer's
    /// tampered twin on the SAME serve prints `adopt=Unverified tip_record_bytes=0` — one door, two
    /// verdicts, which is the whole claim.
    /// MUST-STAY-GREEN: this IS the must-stay-green statement for the #29 DSYNC adopt suite.
    /// cons: none — one serving node, one bundle, one adopt; f(fixed constants).
    #[test]
    fn honest_bundle_blocks_are_all_admitted_by_the_body_aware_door() {
        let mut a = served_node("h");
        let honest = bundle_of(&mut a);
        // G11b: the honest bundle is CONSTANT — its tip and anchor (and their folded ancestors) ride it, never the
        // unfolded window; that window reaches the joiner on the follow page, judged below by the same node's ingest door.
        assert!(honest.fold_carry.unfolded.is_empty(), "setup: the constant bundle carries no unfolded window");
        let served_anchor = honest.tip_block.id();

        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let admitted = victim.bundle_blocks_refusal(&honest).is_none();
        let out = victim.instant_sync(honest);
        eprintln!("[laneB-honest] bundle_blocks_admitted={admitted} adopt={out:?}");
        assert!(
            admitted,
            "REGRESSION — the body-aware door refused an HONEST bundle's blocks. The serve ships a \
             REDUCED body by design (`build_sync_bundle` blanks every sidecar, `unfolded_carry` \
             blanks carried notes, `header_shell` blanks all of them), so the door must run the \
             REDUCED-carrier form `consensus::validate_carried_body_commitments`, never the \
             whole-body `validate_structural`. A refused bundle installs NOTHING and the #29 jump is \
             the only path a fresh node has — this refusal wedges a joiner off the mesh."
        );
        assert!(
            matches!(out, AdoptOutcome::Adopted(_)),
            "REGRESSION — an honest, unedited bundle did not adopt: {out:?}"
        );
        // The honest backlog above the served anchor, page by page from the joiner's locator, oldest first: every body
        // must be admitted (Added) — a refused honest page body wedges the joiner at the anchor exactly as a refused
        // bundle would.
        let (page, _) = a
            .whole_blocks_after_locator(&victim.batch_locator(None), 32, 1 << 20, &[], &[])
            .expect("the server holds the joiner's locator");
        assert!(
            a.dag().get(&served_anchor).map_or(false, |h| h.blue_score > 0) && !page.is_empty(),
            "setup: the server holds honest blocks above its served anchor"
        );
        let mut refused: Vec<String> = Vec::new();
        for b in page {
            let ts = b.header.timestamp + 500;
            let id = b.id();
            match victim.ingest_block(b, ts) {
                crate::relay::RelayOutcome::Added(_) => {}
                other => refused.push(format!("{}: {other:?}", &id.to_hex()[..8])),
            }
        }
        eprintln!("[laneB-honest] follow-page bodies refused: {}", refused.len());
        assert!(refused.is_empty(), "REGRESSION — the ingest door refused HONEST follow-page bodies: {refused:?}");
    }

    /// THE HONEST-PATH PIN for the other half of the change: hashing the peak spine into
    /// `sync::sync_binding` must not refuse a bundle that honestly carries NO spine. The empty spine
    /// is a real value — a chain with nothing folded yet — and it is LENGTH-PREFIXED into the
    /// preimage exactly so it binds as itself rather than as an absence. Without the length prefix
    /// this test is the one that goes red.
    /// ROOT-LAYER: asserted on the adopt verdict, which is the site the binding is compared at.
    /// MEASURED (this run): see the printed `[laneB-emptyspine] adopt=Adopted(..)`; the reviewer's
    /// attack 3, which STRIPS a spine the serve did carry, prints a refusal on the same door.
    /// cons: none — one node, one bundle, one adopt.
    #[test]
    fn an_honest_bundle_carrying_no_spine_still_adopts() {
        let mut a = served_node("s");
        let honest = a
            .build_sync_bundle(
                vec![1u8; 4096],
                crate::sync::FrontierSnapshot {
                    root: *a.note_frontier_root().as_bytes(),
                    height: a.note_frontier_count(),
                    // the honest EMPTY spine, bound as itself: the WIRE encoding of a frontier with count 0 — what
                    // `peaks_hex()` serves for a node that folded nothing. A zero-length string is never served
                    // (`from_peaks_hex("")` is None) and DB-376 refuses it before any state moves.
                    peaks_hex: a.spend_frontier_peaks_hex(),
                },
            )
            .expect("the node serves a bundle");
        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let out = victim.instant_sync(honest);
        eprintln!("[laneB-emptyspine] adopt={out:?}");
        assert!(
            matches!(out, AdoptOutcome::Adopted(_)),
            "REGRESSION — length-prefixing the spine into the preimage must bind the EMPTY spine as \
             a value, not refuse it as an absence: {out:?}"
        );
    }

    /// ⭐ THE RESIDUAL THIS CHANGE LEAVES, MEASURED rather than asserted away. `absent_ok` admits a
    /// STRIPPED body part, so a relay can still SUBTRACT from a certified bundle. This states what
    /// that buys an attacker: nothing FALSE is installed — the victim's record for the certified tip
    /// holds no attacker bytes — and the loss is availability only. The strip case is reported OPEN
    /// on `consensus::body_commitments_admit` and in `sync_binding`'s completeness table; this pin is
    /// what makes that report a number instead of a paragraph, and it is the test that must be
    /// revisited the day the shipped bytes enter the preimage.
    /// ROOT-LAYER: asserted on the adopt verdict and on the victim's stored record — the door's own
    /// outputs — never on a later reader.
    /// MEASURED (this run): see the printed `[laneB-strip]` line; `holds_attacker_note=false` is the
    /// invariant, and `tip_record_bytes` is the availability number the residual costs.
    /// cons: none — one serving node, one bundle, one adopt.
    #[test]
    fn a_stripped_carried_body_injects_nothing_and_is_the_named_open_residual() {
        let mut a = served_node("t");
        let honest = bundle_of(&mut a);
        let tip_id = honest.tip_block.header.id();
        let mut stripped = honest.clone();
        stripped.tip_block.output_notes = Vec::new();
        stripped.tip_block.account_targets = Vec::new();
        assert_eq!(
            stripped.decider.chain_acc, honest.decider.chain_acc,
            "premise: SUBTRACTING body bytes does not move the accumulator the proof is bound to — \
             which is exactly why this residual is real and is reported open"
        );

        let mut victim = testnet_node();
        victim.set_decider_verifier(Box::new(AcceptAll));
        let out = victim.instant_sync(stripped);
        let rid = Node::da_record_id_for_block(&tip_id, 0);
        // ABSENT and EMPTY are different answers and are reported as different answers — no default
        // stands in for "this node holds no record", because that distinction IS the measurement.
        let (present, bytes) = match victim.da_record_notes(rid) {
            Some(stored) => (true, stored.len()),
            None => (false, 0),
        };
        let injected = Hash32::hash(b"laneB-never-carried");
        let holds_foreign = match victim.da_record_notes(rid) {
            Some(stored) => stored
                .chunks(crate::cover::PQ_NOTE_BYTES)
                .any(|c| c.len() >= 32 && &c[..32] == injected.as_bytes()),
            None => false,
        };
        eprintln!(
            "[laneB-strip] adopt={out:?} record_present={present} tip_record_bytes={bytes} \
             holds_bytes_the_sender_never_carried={holds_foreign}"
        );
        assert!(
            !holds_foreign,
            "THE CLASS THAT MUST STAY CLOSED — subtraction may never become substitution. A stripped \
             body must leave the adopter holding FEWER bytes, never bytes no sender ever carried."
        );
    }

    /// THE SPLIT ITSELF, pinned: the two body doors differ on EXACTLY the absent case and nowhere
    /// else. That is the bit a reader cannot verify by reading, and the bit a future edit could
    /// widen without noticing.
    /// ROOT-LAYER: asserted on `consensus::validate_full_body_commitments` /
    /// `validate_carried_body_commitments` — the two functions that STATE the rule, not on a caller.
    /// MEASURED (this run): all three arms below hold on a REAL produced block carrying this chain's
    /// constant letter cover shape — subtract → full REFUSES / reduced ADMITS; alter → BOTH REFUSE.
    /// cons: none — one produced block, six pure calls.
    #[test]
    fn the_two_body_doors_differ_exactly_on_the_absent_case() {
        let mut a = served_node("d");
        let t0 = genesis_ts(&a);
        let full = produce(&mut a, t0 + 60_000 * (CHAIN_BLOCKS + 1), "split");

        // (1) A WHOLE, unedited block: both doors admit it.
        assert!(
            crate::consensus::validate_full_body_commitments(&full).is_ok(),
            "a produced block's own body must satisfy its own header commitments"
        );
        assert!(
            crate::consensus::validate_carried_body_commitments(&full).is_ok(),
            "the reduced form must admit everything the full form admits"
        );

        // (2) The SAME block with a part SUBTRACTED: only the reduced form admits it. The difference
        // is measured on a part that is ACTUALLY CARRIED — the letter set, which `Node::produce`
        // always seals to the constant cover shape — because a part the honest producer left empty
        // has nothing to subtract and would measure nothing.
        assert!(
            !full.letter_set.is_empty(),
            "setup: a produced block always carries the constant letter cover shape"
        );
        let mut stripped: Block = full.clone();
        stripped.letter_set = Vec::new();
        let full_verdict = crate::consensus::validate_full_body_commitments(&stripped);
        let carried_verdict = crate::consensus::validate_carried_body_commitments(&stripped);
        eprintln!(
            "[laneB-split] subtracted: full={full_verdict:?} carried={carried_verdict:?}"
        );
        assert!(
            full_verdict.is_err(),
            "the WHOLE-BODY form must refuse a subtracted part — that is the gossip door's rule"
        );
        assert!(
            carried_verdict.is_ok(),
            "the REDUCED form must admit a subtracted part — that is what lets an honest shell, an \
             honest carry and an honest bundle through the shared door"
        );

        // (3) The same block with a part ALTERED: BOTH doors refuse. This is the class the review's
        // attacks constructed, and the reduced form must not be weak to it.
        let mut altered: Block = full.clone();
        altered.letter_set[0] ^= 0xff;
        assert!(
            crate::consensus::validate_full_body_commitments(&altered).is_err(),
            "the whole-body form must refuse an altered part"
        );
        assert!(
            crate::consensus::validate_carried_body_commitments(&altered).is_err(),
            "THE POINT OF THE WHOLE CHANGE — the reduced form must refuse an ALTERED part. If this \
             ever passes, every non-gossip door is unbound again and the review's attacks land."
        );
    }

    /// AND THE GOSSIP DOOR DID NOT GET THE WEAK ARM. `consensus::validate_structural` is what every
    /// gossiped block passes; splitting the rules created a strictly weaker sibling, and swapping it
    /// in there would unbind every gossiped body at once while every other test in this file stayed
    /// green.
    /// ROOT-LAYER: asserted on `validate_structural` itself — the gossip door's own function.
    /// MEASURED (this run): see the printed `[laneB-gossip] validate_structural(subtracted)=Err(..)`.
    /// cons: none — one produced block, one pure call.
    #[test]
    fn the_gossip_door_still_runs_the_full_form() {
        let mut a = served_node("g");
        let t0 = genesis_ts(&a);
        let full = produce(&mut a, t0 + 60_000 * (CHAIN_BLOCKS + 1), "gossip");
        let params = ChainParams::default();
        let now = full.header.timestamp;
        let mut stripped: Block = full.clone();
        stripped.letter_set = Vec::new();
        let verdict = crate::consensus::validate_structural(&stripped, now, &params);
        eprintln!("[laneB-gossip] validate_structural(subtracted)={verdict:?}");
        assert!(
            verdict.is_err(),
            "REGRESSION — the gossip door must keep the WHOLE-BODY rule. It holds the whole block by \
             construction, so an empty part there is a claim like any other and blake3 of the empty \
             string is its real, checkable value; running the reduced-carrier form here would unbind \
             every gossiped body in one edit."
        );
    }

    /// ⛔⛔ db333-r TAMPER PIN — `FoldCarry::covered` tells the adopter which blocks above the anchor its new state already
    /// counts, so it PLACES them on arrival instead of applying them. A server that drops an entry makes the joiner apply
    /// that block a second time (a nullifier leaf summed twice, a mint applied twice); one that adds an entry makes it skip
    /// a block the state never counted. Either edit must break the certified binding, so the bundle REFUSES.
    /// ROOT-LAYER: asserted on the adopt verdict, the site the binding (`FoldCarry::digest`) is compared at.
    /// cons: none — one serving node, three adopts.
    #[test]
    fn a_bundle_whose_covered_list_is_edited_is_refused() {
        let mut a = served_node("c");
        let honest = bundle_of(&mut a);
        assert!(!honest.fold_carry.covered.is_empty(), "setup: the server holds blocks above its served anchor");
        let mut dropped = honest.clone();
        dropped.fold_carry.covered.pop();
        let mut added = honest.clone();
        added.fold_carry.covered.push(([0xab; 32], 1, 1));
        let verdict = |b: crate::sync::SyncBundle| {
            let mut victim = testnet_node();
            victim.set_decider_verifier(Box::new(AcceptAll));
            victim.instant_sync(b)
        };
        let (h, d, x) = (verdict(honest), verdict(dropped), verdict(added));
        eprintln!("[db333r-tamper] honest={h:?} dropped={d:?} added={x:?}");
        assert!(matches!(h, AdoptOutcome::Adopted(_)), "calibration: the unedited bundle adopts: {h:?}");
        assert!(!matches!(d, AdoptOutcome::Adopted(_)), "⛔ a bundle with a covered entry DROPPED adopted: {d:?}");
        assert!(!matches!(x, AdoptOutcome::Adopted(_)), "⛔ a bundle with a covered entry ADDED adopted: {x:?}");
    }
}
