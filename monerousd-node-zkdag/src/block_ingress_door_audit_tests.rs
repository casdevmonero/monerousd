// Copyright (c) 2026 The MonerousD developers
// Distributed under the MIT software license.
//! FAMILY A — BLOCK / DAG INGRESS: the §9.6 six-question door audit, as pins.
//!
//! WHY THIS FILE EXISTS (charter §9.6, measured 2026-09-07): the block-locator descent added a
//! second way for a block to enter the DAG, carried the merkle and parents-present checks across,
//! and did not carry the PoW check. A fabricated shell entered the DAG claiming work 8.5e37
//! against an honest tip of 295. That omission was closed at
//! `Node::graft_block_shell_from_trusted_id`. THESE PINS HUNT ITS SIBLINGS: every other check the
//! gossip door (`preverify_block` + `consensus::validate_structural` + `validate_contextual`) runs
//! that a non-gossip block door does not, and every consensus-critical field a non-gossip door
//! consumes that nothing binds.
//!
//! Each pin CONSTRUCTS the attack and asserts the refusal. A RED pin here is a CONFIRMED HOLE and
//! IS the fix spec — it is left red deliberately; do not weaken an assertion to make it pass.
//!
//! ROOT-LAYER: this file is an AUDIT, so it adds no fix at all — it asserts at the layer where
//! block ADMISSION is produced (the door body that decides, and the binding a proof certifies),
//! never at a reader. Each pin's assertion is on the DAG itself (did the fabricated id land, which
//! block is the selected tip, what weight does it carry) rather than on any lane's bookkeeping,
//! because the lanes — the page loop, the trusted closure, the want slots, the beacon — are all
//! CONSUMERS of that one decision. The two fix specs the red pins carry are written for the shared
//! producing site (`sync::sync_binding` for the certified weights; the shared shell-door body for
//! the header rules), never for a call site, per §9.5.
//!
//! MEASURED 2026-09-07, this audit's own run (filtered single-test runs, warm dir
//! ~/.cargo-targets/roller-gapterm): three pins GREEN (the unsolicited-shell refusal, the
//! tx-merkle body binding, and the premise halves of the binding pin — the anchor blue SCORE and
//! the fold carry's per-block blue work both move `sync_binding`), and the numbers each red pin
//! prints are in its own assertion message.
//!
//! MUST-STAY-GREEN: every existing block-ingress pin — `a_forged_powless_ancestry_page_is_refused_
//! by_the_descent_door`, `a_wanted_shell_that_cannot_graft_names_its_missing_parents`,
//! `a_forged_bonded_validator_set_breaks_the_sync_binding`, the #29 DSYNC adopt suite and the
//! rolling-restart pins. This file drives only public/crate doors and mutates no shared state.
//!
//! cons: NONE on any cardinal — this file adds no node code and no store. It is test-only
//! (`#![cfg(test)]`), it changes no admission path, and every pin's work is f(FIXED CONSTANTS),
//! never f(history): each pin builds a node whose chain is a NAMED SMALL CONSTANT (2 or 3 produced
//! blocks — the `for i in 0..n` loops below range over that constant, not over any chain length),
//! grafts at most one shell, and adopts at most one bundle. TIME per pin = 2-3 produce grinds plus
//! one door call; SIZE = the same 2-3 blocks a `Node::new` test already holds, dropped at the end
//! of the test. No loop here walks records, notes, ordinals or blocks-since-genesis.

#![cfg(test)]

use crate::block::Block;
use crate::decider::{ConsensusVerifier, DeciderBundle};
use crate::hash::Hash32;
use crate::node::tests::genesis_block;
use crate::node::Node;
use crate::sync::{sync_binding, FoldCarry, FrontierSnapshot, NullifierSnapshot, SyncBundle};

/// A decider that accepts — the pins below are about what rides OUTSIDE the proof, so the proof
/// itself must not be the thing that refuses.
struct AcceptDecider;
impl ConsensusVerifier for AcceptDecider {
    fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
        true
    }
}

/// A node on a real chain of `n` produced blocks. `n` is a FIXED SMALL CONSTANT at every call site
/// (2 or 3); this loop is f(that constant), never f(chain height).
fn mined_node(tag: &str, n: u32) -> Node {
    let mut node = Node::new(genesis_block()).expect("node");
    for i in 0..n {
        let need = node.mempool().required_stamp_bits();
        let tx = crate::node::tests::grind_tx(
            format!("{tag}-{i}").as_bytes(),
            1000,
            vec![Hash32::hash(format!("{tag}-nf-{i}").as_bytes())],
            need,
        );
        let _ = node.ingest_tx_unverified(tx);
        node.produce(5_000 + i as u64 * 1_000, Hash32::hash(b"f"), Hash32::hash(b"r"))
            .expect("produce");
    }
    node
}

/// The `blue_work` the DAG holds for `id`. Panics if the DAG does not hold it — an absent block is
/// never rescued to a default here, because a default would be a weight this audit then reports as
/// fact.
fn work_of(node: &Node, id: &Hash32) -> u128 {
    node.dag()
        .get(id)
        .expect("the DAG holds the block this pin just read a tip id for")
        .blue_work
}

/// A shell built on `parent`, cloning `template`'s header shape and overriding exactly the fields
/// an attacker controls. No `pow_proof`, no witness — a shell is header + tx ids by construction.
fn shell_on(
    template: &crate::block::BlockHeader,
    parent: Hash32,
    work: u128,
    timestamp: u64,
    nonce: u64,
) -> Block {
    let mut h = template.clone();
    h.parents = vec![parent];
    h.work = work;
    h.timestamp = timestamp;
    h.nonce = nonce;
    h.tx_merkle_root = crate::miner::tx_merkle_root(&[]);
    Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
        header: h,
        tx_ids: Vec::new(),
        pow_proof: Vec::new(),
        note_transition: None,
        nullifier_proof: crate::block::NfBlockProof::default(),
        output_notes: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        bond_set: Vec::new(),
        // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
        credit_set: Vec::new(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        cover_transition: None,
        member_transition: None,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// DOOR A05/A06 — `Node::graft_block_shell_from_trusted_id` -> `Dag::add_wanted_shell`
// (the block-locator descent door, the one the 2026-09-07 takeover lived in).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// QUESTION 1 + QUESTION 6 — THE GRIND CHECK IS VACUOUS AT `work <= 1`, AND A SHELL'S OWN
/// WORK NEVER ENTERS ITS OWN `blue_work` ANYWAY.
///
/// THE ATTACK: `pow::hash_meets_target` returns `true` UNCONDITIONALLY for `work <= 1`
/// (`pow.rs:94-96`), so the grind the descent door added costs an attacker NOTHING at `work = 1`.
/// And `Ghostdag::ghostdag_data` computes `blue_work(B) = blue_work(sp) + sum work(mergeset_blues)`
/// — the mergeset INCLUDES the selected parent (`ghostdag.rs:51,84,126-129`) — so a block built on
/// the honest tip T carries `blue_work = T.blue_work + T.header.work`, STRICTLY GREATER than T's,
/// whatever the block's own `work` says. A free `work = 1` shell therefore TAKES THE SELECTED TIP.
///
/// The gossip door refuses this shape at `consensus::validate_contextual` (`consensus.rs:275-281`):
/// `h.work != adaptive_work(dag, sp)` gives `WrongWork`. THAT is the check the descent door does
/// not carry, and without it the grind check it does carry is satisfiable for free.
///
/// COST TO THE ATTACKER: one mined orphan naming a fabricated parent (the Buffered arm writes the
/// want), then one served shell. COST TO THE VICTIM: its fork choice is on a block no peer holds;
/// the block it produces next names that shell as a parent and every honest node refuses it as
/// `UnknownParent` forever.
///
/// ROOT-LAYER: asserted on `Dag::selected_tip` — the value the fork choice PRODUCES — not on the
/// block lane's graft counter, so no lane bookkeeping can make it pass.
/// MUST-STAY-GREEN: the honest heal pins on this same lane (the page-speed descent heal, the
/// wanted-shell parent naming, the buffered-orphan naming); this pin adds no lane behaviour.
/// cons: none — one node of 3 produced blocks and one door call. f(fixed constants).
#[test]
fn a_free_work_one_shell_cannot_take_the_selected_tip_through_the_descent_door() {
    let mut victim = mined_node("descent-tip", 3);
    let honest_tip = victim.selected_tip().expect("the victim has a tip");
    let honest_work = work_of(&victim, &honest_tip);
    let template = victim
        .dag()
        .get(&honest_tip)
        .expect("tip node")
        .header
        .clone();

    // work = 1 means `hash_meets_target` short-circuits to true. No grind, no proof, no cost.
    let shell = shell_on(&template, honest_tip, 1, template.timestamp + 1, 0xA11CE);
    let shell_id = shell.id();
    assert!(
        crate::pow::hash_meets_target(&Hash32::hash(b"anything at all"), 1),
        "the premise: the grind gate is a no-op at work <= 1"
    );

    // The ONE want the Buffered arm hands over for the price of a single mined orphan.
    victim.want_block_by_id(shell_id);
    let landed = victim.graft_block_shell_from_trusted_id(&shell);
    let in_dag = victim.dag().get(&shell_id).is_some();
    let new_tip = victim.selected_tip().expect("a tip");
    let new_work = work_of(&victim, &new_tip);

    assert!(
        !landed && !in_dag && new_tip == honest_tip,
        "A COSTLESS SHELL TOOK THE FORK CHOICE (landed={landed}, in_dag={in_dag}). It carries no \
         `pow_proof`; its `work = 1` makes `hash_meets_target` return true without a single hash \
         of grind; and because GHOSTDAG sums the SELECTED PARENT's work into the child, it now \
         holds blue_work {new_work} against the honest tip's {honest_work}. The gossip door \
         refuses this exact header at `validate_contextual` (`h.work != adaptive_work`); the \
         descent door does not run that check. FIX SPEC: `graft_block_shell_from_trusted_id` must \
         additionally require `block.header.work == crate::miner::adaptive_work(dag, Some(sp))` \
         for the selected parent it is about to be placed under — the same equality the gossip \
         door enforces — or, equivalently, `Dag::add_wanted_shell` must refuse a header whose work \
         is not the DAA-expected value for its parents. THE SHARED SITE ALREADY EXISTS: as of \
         2026-09-07 all four non-gossip block doors route their grind through \
         `Node::header_grind_admits` (node.rs:5904), and that ONE function is where the `work <= 1` \
         escape must be closed — it fixes the descent door, the anchor door and both carry doors \
         in a single edit, which is the §9.5 shape. A bare `header.work <= 1 => refuse` removes \
         the free case; the complete fix is the DAA equality, which needs the parents' selected \
         parent and so belongs in the per-door call beside the placement."
    );
}

/// QUESTION 6 — THE DESCENT DOOR RUNS NO TIMESTAMP CHECK AT ALL.
///
/// The gossip door runs TWO: `validate_structural` refuses `h.timestamp > now + max_ts_drift_ms`
/// (`consensus.rs:134-140`) and `validate_contextual` refuses `h.timestamp <= median_time_past(sp)`
/// (`consensus.rs:262-267`). Neither is carried to the shell door. A shell's timestamp feeds
/// `median_time_past` and `miner::adaptive_work` for every block built above it, so a far-future
/// shell on the selected chain drives THIS node's expected difficulty away from the mesh's — and a
/// node whose `adaptive_work` disagrees with its peers refuses every honest block with `WrongWork`.
/// A chain-splitting input that the paralleled door refuses is a hole until proven otherwise.
///
/// ROOT-LAYER: asserted at the DAG membership of the fabricated id, the value block admission
/// produces; the parity verdict is taken from `consensus::validate_structural` itself, so the
/// comparison is against the real gossip rule and not a restatement of it.
/// MUST-STAY-GREEN: the same honest heal pins as the sibling above.
/// cons: none — one node of 3 produced blocks and one door call. f(fixed constants).
#[test]
fn a_far_future_shell_timestamp_is_refused_by_the_descent_door() {
    let mut victim = mined_node("descent-ts", 3);
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim
        .dag()
        .get(&honest_tip)
        .expect("tip node")
        .header
        .clone();

    // A century into the future — orders of magnitude past `max_ts_drift_ms`.
    let far = template.timestamp + 3_155_760_000_000u64;
    let shell = shell_on(&template, honest_tip, 1, far, 0xB0B);
    let id = shell.id();

    // The gossip door's own verdict on these exact bytes, for the parity record.
    let params = victim.params().clone();
    let structural =
        crate::consensus::validate_structural(&shell, template.timestamp + 1_000, &params);
    assert!(
        structural.is_err(),
        "premise: the gossip door refuses this header ({structural:?})"
    );

    victim.want_block_by_id(id);
    let landed = victim.graft_block_shell_from_trusted_id(&shell);
    assert!(
        !landed && victim.dag().get(&id).is_none(),
        "A SHELL WITH A TIMESTAMP {far} — refused by `validate_structural` on the gossip door \
         ({structural:?}) — ENTERED THE DAG through the descent door, which runs no timestamp \
         check of either kind. Its timestamp is now a `median_time_past` and `adaptive_work` \
         sample for every block placed above it, so this node's expected difficulty diverges from \
         the mesh and it refuses honest blocks with `WrongWork`. FIX SPEC: the shared shell door \
         body must run `consensus::validate_structural` (with the `now_ts` the caller already \
         has) and the MTP half of `validate_contextual` before `Dag::add_wanted_shell`, so ONE set \
         of header rules governs every block entrance."
    );
}

/// PROOF THE DOOR HOLDS — QUESTION 6, a check the descent door DOES carry across.
/// A shell whose id is in no want slot never grafts: this lane cannot widen admission on its own.
///
/// ROOT-LAYER: driven through the wants-gated wrapper, which is where the lane's admission is
/// decided.
/// MUST-STAY-GREEN: this pin IS the must-stay-green for the two red siblings above — any fix they
/// prompt must leave the unsolicited refusal exactly as it is.
/// cons: none — one node of 2 produced blocks, one door call. f(fixed constants).
#[test]
fn an_unsolicited_shell_is_refused_by_the_descent_door() {
    let mut victim = mined_node("descent-unsolicited", 2);
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim
        .dag()
        .get(&honest_tip)
        .expect("tip node")
        .header
        .clone();
    let shell = shell_on(&template, honest_tip, 1, template.timestamp + 1, 0xC0DE);
    // No `want_block_by_id` — the wrapper is the wants-gated entrance.
    assert!(
        !victim.graft_block_shell_from_trusted_id(&shell),
        "a shell in NO want slot must never graft — the lane must not widen admission"
    );
    assert!(
        victim.dag().get(&shell.id()).is_none(),
        "and nothing partial is applied"
    );
}

/// PROOF THE DOOR HOLDS — the tx-merkle binding: a tx list the id-pinned header does not commit to
/// is refused, so a shell cannot smuggle a body past its own id.
///
/// ROOT-LAYER: the check lives in the shared door body, so this drives that body directly.
/// MUST-STAY-GREEN: as above — a fix for the red siblings must not disturb this refusal.
/// cons: none — one node of 2 produced blocks, one door call. f(fixed constants).
#[test]
fn the_descent_door_refuses_a_body_the_header_does_not_commit_to() {
    let mut victim = mined_node("descent-merkle", 2);
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim
        .dag()
        .get(&honest_tip)
        .expect("tip node")
        .header
        .clone();
    let mut shell = shell_on(&template, honest_tip, 1, template.timestamp + 1, 0xD1CE);
    shell.tx_ids = vec![Hash32::hash(b"a tx the header never committed to")];
    let id = shell.id(); // the id is over the HEADER; the body is free
    victim.want_block_by_id(id);
    assert!(
        !victim.graft_block_shell_from_trusted_id(&shell),
        "a tx list the header's merkle root does not commit to must be refused"
    );
    assert!(victim.dag().get(&id).is_none());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// DOOR A07 — `Node::admit_anchor_block` -> `Dag::add_anchor` (the #29 DSYNC adopt).
// The heaviest placement primitive in the tree: on a `(blue_work, id)` win it CLEARS the tip set
// and installs the anchor as the SOLE selected tip, with no parent and no ancestry replayed.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A fixed-shape empty snapshot — 14 named scalar/empty fields, no term in history.
fn empty_nullifier_snapshot() -> NullifierSnapshot {
    NullifierSnapshot {
        applied_one_time_ids: Vec::new(),
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
        membership_tip: (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()),
        root: [0u8; 32],
        count: 0,
        sparse_root: [0u8; 32],
        band: Vec::new(),
        band_next_ordinal: 0,
        band_awaiting: Vec::new(),
        nf_unspent_acc: usdm_decider::poseidon2_compress::zero_digest(),
        nf_cover_conf_acc: [0u8; 32],
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
        dsol_registry_peaks: Vec::new(),
        dsol_registry_count: 0,
        peg_ion_pending: Vec::new(),
        peg_ion_pools: 0,
        peg_ion_usdm_held: 0,
    }
}

/// QUESTION 2 + QUESTION 3 — `anchor_blue_work` AND `blue_work` RIDE A VALID PROOF UNBOUND.
///
/// `sync_binding` (`sync.rs:327-397`) folds the tip, blue SCORE, frontier, nullifier snapshot,
/// genesis commit, anchor ID, anchor blue SCORE and the fold-carry digest into the 16-byte value
/// the decider proof is transcript-bound to. It has NO parameter for `SyncBundle::blue_work` and
/// none for `SyncBundle::anchor_blue_work` — the two `u128`s that DECIDE THE FORK CHOICE:
///
///   * `node.rs:21987` refuses a bundle unless `(bundle.blue_work, tip) > (our_work, our_tip)`;
///   * `node.rs:22622-22626` hands `bundle.anchor_blue_work` to `admit_anchor_block`, which
///     forwards it verbatim to `Dag::add_anchor` (`dag.rs:701-736`) — where it decides the reorg
///     AND is stored as the anchor's `BlockNode::blue_work`, i.e. as this node's permanent fork
///     score for that block.
///
/// So an attacker does not need to forge a chain: it takes ANY bundle that verifies — its own
/// honest one, or one it re-serves — and edits 32 bytes. The proof still verifies, the binding
/// still matches, and the victim installs a sole selected tip whose weight is `u128::MAX`.
///
/// This is the same law `a_forged_bonded_validator_set_breaks_the_sync_binding` (`sync.rs:542`)
/// already enforces for the quorum, and the same law `FoldCarry::digest` already enforces for the
/// CARRIED blocks' blue data — the carry's `(id, bw, bs)` triples ARE folded (`sync.rs:275-292`).
/// The anchor's own blue work is the one that is not.
///
/// ROOT-LAYER: asserted on `sync_binding` itself — the function that PRODUCES the value a proof is
/// transcript-bound to. A check added at the adopt call site would leave every other consumer of
/// the bundle (the serve side, a future adopt lane) reading unbound weights.
/// MUST-STAY-GREEN: `a_forged_bonded_validator_set_breaks_the_sync_binding` and every #29 adopt
/// pin — the two premise assertions below are drawn from the same law those pins state.
/// cons: none — pure hashing of two fixed-shape preimages. No node, no chain, no store.
#[test]
fn a_tampered_anchor_blue_work_breaks_the_sync_binding() {
    let tip = Hash32::hash(b"door-audit-anchor-tip");
    let frontier = FrontierSnapshot {
        root: *Hash32::hash(b"fr").as_bytes(),
        height: 9,
        peaks_hex: String::new(),
    };
    let nullifier = empty_nullifier_snapshot();
    let carry = FoldCarry::default();

    // The binding a peer's proof is transcript-bound to. Everything a joiner ACTS on must move it.
    // ARITY ONLY (lane 2, 2026-09-07): `sync_binding` now takes `blue_work`, `anchor_blue_work` and
    // `anchor_ordinal` as its last three parameters — the fix this pin's own FIX SPEC prescribes. No
    // assertion in this test was changed, weakened or removed; the trailing `9, 9, 0` are this
    // fixture's honest weights and record base.
    let honest = sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 9, &carry.digest(), 9, 9, 0);

    // The anchor's blue SCORE moves it (proof the pin is not vacuous) ...
    assert_ne!(
        honest,
        sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 10, &carry.digest(), 9, 9, 0),
        "premise: the anchor's blue SCORE is bound"
    );
    // ... and so does the fold carry's per-block blue work.
    let mut carry_tampered = FoldCarry::default();
    carry_tampered.ancestors = vec![(genesis_block(), u128::MAX, 1)];
    assert_ne!(
        carry.digest(),
        carry_tampered.digest(),
        "premise: the CARRIED blocks' blue work IS bound by `FoldCarry::digest`"
    );

    // ⭐⭐⭐ THE REFUTATION, WHERE A STALE `panic!` USED TO SIT.
    //
    // This pin declared a CONFIRMED HOLE and ended in an unconditional `panic!`, which is the right
    // shape for a hole that is OPEN. The fix landed 2026-09-07 (`sync_binding`'s last three
    // parameters, folded at the end of the preimage) and the pin's fixture was updated for the new
    // ARITY — but the terminal panic was left behind, so the gate went on failing whether the hole was
    // open or closed. ⛔ A pin that cannot go green cannot report a repair, and after a while nobody
    // reads it: it becomes indistinguishable from a known-red, which is how a CLOSED hole and an OPEN
    // one end up looking the same on a test run.
    //
    // ⭐ THE REPAIR IS NOT DELETING THE PANIC — it is asserting the property the panic was standing in
    // for. Each of the three acted-on numbers must MOVE the binding, and each is asserted separately so
    // a regression names WHICH one came unbound rather than reporting "the binding changed".
    assert_ne!(
        honest,
        sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 9, &carry.digest(), 9, u128::MAX, 0),
        "⛔ `SyncBundle::anchor_blue_work` is UNBOUND. `Dag::add_anchor` stores it verbatim as the \
         anchor's permanent `BlockNode::blue_work` and decides the reorg on it, so a peer edits 16 \
         bytes of a bundle that verifies and the joiner installs a sole selected tip of weight \
         u128::MAX that no honest chain can ever outrank."
    );
    assert_ne!(
        honest,
        sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 9, &carry.digest(), u128::MAX, 9, 0),
        "⛔ `SyncBundle::blue_work` is UNBOUND — it is the figure the NotHeavier fork-choice gate \
         compares against this node's own weight before it adopts anything at all."
    );
    assert_ne!(
        honest,
        sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 9, &carry.digest(), 9, 9, 1),
        "⛔ `anchor_ordinal` is UNBOUND — the anchor's record base rides the same bundle and the \
         adopter acts on it"
    );
    // ⛔ AND THE BINDING MUST NOT BE A BLANKET: the honest triple still reproduces the honest value,
    // so the three assertions above are detecting THESE fields and not merely "something changed".
    assert_eq!(
        honest,
        sync_binding(&tip, 9, &frontier, &nullifier, b"g", &tip, 9, &carry.digest(), 9, 9, 0),
        "the binding is not deterministic on its own honest inputs"
    );
    eprintln!(
        "[door-audit] the fork-choice weights are BOUND: blue_work, anchor_blue_work and \
         anchor_ordinal each move `sync_binding`, and the honest triple reproduces it"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE 2026-09-08 REFUTATION ROUND — the reviewer's two MUST-FIXes, constructed and closed.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A bundle whose anchor AND tip are `hdr` — the minimum shape `Node::bundle_blocks_admitted`
/// judges. Every field outside the two carried blocks is honest, so nothing but the header can be
/// what refuses it.
fn bundle_of(anchor: &Block, genesis_commit: &[u8]) -> SyncBundle {
    let anchor_id = anchor.id();
    // the EMPTY frontier, served as itself: its real root and its wire-encoded (count 0) spine — the only honest
    // frontier for an anchor at position 0 (DB-376: a spine-less serve is a lie).
    let empty = crate::spend_frontier::PoseidonSpendFrontier::new();
    let frontier = FrontierSnapshot {
        root: crate::spend_frontier::leaf_to_cm_bytes(empty.root()),
        height: 0,
        peaks_hex: empty.peaks_hex(),
    };
    let nullifier = empty_nullifier_snapshot();
    let carry = FoldCarry::default();
    let chain_acc = sync_binding(
        &anchor_id,
        7,
        &frontier,
        &nullifier,
        genesis_commit,
        &anchor_id,
        7,
        &carry.digest(),
        1,
        1,
        0,
    );
    crate::sync::with_fixture_cert(SyncBundle {
        join: Default::default(),
        cert: crate::sync::unset_cert(),
        tip_cover_key: None,
        tip_wide_objects: Vec::new(),
        decider: DeciderBundle {
            tip: anchor_id,
            blue_score: 7,
            chain_acc,
            proof: vec![1u8; 4096],
        },
        frontier,
        nullifier,
        tip_block: anchor.clone(),
        blue_work: 1,
        genesis_commit: genesis_commit.to_vec(),
        anchor_block: anchor.clone(),
        anchor_blue_work: 1,
        anchor_blue_score: 7,
        anchor_ordinal: 0,
        fold_carry: carry,
        tips: Vec::new(), // test fixture: no sibling tips beyond the selected one
        anchor_ring: Vec::new(),
        member_ring_commits: Vec::new(),
    })
}

/// ⛔ MUST-FIX 2, THE REVIEWER'S OWN CONSTRUCTION — a never-mined header with `work = 1` and a
/// `tx_merkle_root` that IS `miner::tx_merkle_root` of its own empty tx list passed
/// `Node::bundle_blocks_admitted` whole, because the grind is exact-and-free at `work = 1` and the
/// tx-merkle rule was the only other thing that door asked.
///
/// This pin asserts on the DOOR'S OWN VERDICT (`bundle_blocks_admitted`), not on the adopt outcome,
/// deliberately: the adopt is refused today by the `sync_binding` weight fold, and asserting there
/// would let the door stay open behind a check that is about a different field. The question this
/// pin asks is the reviewer's: does the header door refuse this header.
///
/// ROOT-LAYER: the verdict read here is the one the four non-gossip placements and the DSYNC adopt
/// all consume; a pin on any lane's bookkeeping could be made green by the lane.
/// MUST-STAY-GREEN: this file's existing pins, and every honest adopt (see the sibling pin below —
/// the clause that refuses this header cannot fire on a node whose DAA samples are not the chain's).
/// cons: one node of 2 produced blocks and one door call. f(FIXED CONSTANTS).
#[test]
fn pin_refut_a_work_one_never_mined_anchor_is_refused_by_the_bundle_door() {
    let victim = mined_node("refut-bundle", 2);
    let genesis = victim.dag().genesis().expect("the victim has a genesis");
    let template = victim
        .dag()
        .get(&genesis)
        .expect("the genesis block")
        .header
        .clone();

    // THE ATTACK, exactly as constructed by the reviewer: never mined, no `pow_proof`, `work = 1`,
    // and a tx-merkle root that its own (empty) tx list re-hashes to.
    let fake = shell_on(&template, genesis, 1, template.timestamp + 1, 0xBEEF);
    assert_eq!(
        fake.header.tx_merkle_root,
        crate::miner::tx_merkle_root(&fake.tx_ids),
        "premise: the tx-merkle rule is SATISFIED by this fabrication"
    );
    assert!(
        crate::pow::hash_meets_target(&Hash32::hash(b"anything at all"), 1),
        "premise: the grind is exact, and at work = 1 the target is the whole digest space"
    );
    assert!(
        fake.pow_proof.is_empty(),
        "premise: the fabrication carries no witness at all"
    );

    let bundle = bundle_of(&fake, &crate::params::network_genesis_prefix("testnet"));
    let admitted = victim.bundle_blocks_refusal(&bundle).is_none();
    let (expected, complete) = crate::miner::adaptive_work_checked(victim.dag(), Some(genesis));
    eprintln!(
        "[refut] bundle_blocks_admitted={admitted} declared_work={} expected={expected} \
         daa_sample_complete={complete}",
        fake.header.work
    );
    assert!(
        !admitted,
        "THE BUNDLE DOOR ADMITTED A NEVER-MINED HEADER. It declares work {}, exhibits no grind (the \
         target compare is exact and accepts every digest at work = 1) and carries no `pow_proof`; \
         its tx-merkle root matches its own empty tx list, so that rule does not refuse it either. \
         The binding that must: `header.work` is not a value a sender chooses — it is \
         `miner::adaptive_work(dag, selected_parent)` for the block's OWN parents (expected \
         {expected} here, from a sample this node is entitled to judge by: complete={complete}). \
         That equality now lives in `Node::header_work_is_bound`, the third clause of the ONE shared \
         `header_door_admits`, so it governs the anchor door, both carry doors and this verdict door \
         in one edit — never a per-door copy.",
        fake.header.work
    );
}

/// ⛔ MUST-FIX 1, THE SAME HEADER AT THE ANCHOR DOOR — the door that CLEARS the tip set on a weight
/// win. The four non-gossip callers of the shared door had no work binding at all; this asserts the
/// anchor one now refuses the identical fabrication, so the fix is the CLASS and not one call site.
///
/// ROOT-LAYER: asserted on `Dag::get` for the fabricated id and on `Dag::selected_tip` — the values
/// the fork choice PRODUCES — never on the door's return alone.
/// MUST-STAY-GREEN: `restore_snapshot` (its anchors are this node's own genesis by id and its own
/// mined tips) and the #29 adopt suite.
/// cons: one node of 2 produced blocks, one door call. f(FIXED CONSTANTS).
#[test]
fn pin_refut_a_work_one_never_mined_anchor_is_refused_by_the_anchor_door() {
    let mut victim = mined_node("refut-anchor", 2);
    let genesis = victim.dag().genesis().expect("the victim has a genesis");
    let honest_tip = victim.selected_tip().expect("the victim has a tip");
    let template = victim
        .dag()
        .get(&genesis)
        .expect("the genesis block")
        .header
        .clone();
    let fake = shell_on(&template, genesis, 1, template.timestamp + 1, 0xF00D);
    let fake_id = fake.id();

    let installed = victim.admit_anchor_block(fake, u128::MAX, 7);
    let in_dag = victim.dag().get(&fake_id).is_some();
    let tip_after = victim.selected_tip().expect("a tip");
    eprintln!(
        "[refut] anchor installed={installed} in_dag={in_dag} tip_after={tip_after:?} \
         honest_tip={honest_tip:?}"
    );
    assert!(
        !installed && !in_dag && tip_after == honest_tip,
        "FORK-CHOICE TAKEOVER THROUGH THE ANCHOR DOOR (installed={installed}, in_dag={in_dag}). \
         `Dag::add_anchor` CLEARS the tip set on a weight win, and this header — never mined, no \
         `pow_proof`, `work = 1` — cost nothing to write. The work equality belongs in the ONE \
         shared `header_door_admits` so this door, both carry doors and the DSYNC verdict door are \
         closed by a single edit."
    );
}

/// ⭐ THE HONEST SIDE OF THE SAME CLAUSE — WHAT THE FIX MUST NOT MAKE POSSIBLE.
///
/// A refusal added to four doors can only be safe if it never fires on an honest block, and this
/// crate has MEASURED the failure mode: after one restart, two nodes refused each other's honest
/// blocks with `WrongWork { expected: 5, got: 4 }` in BOTH directions, because a walk that ran off
/// the bottom of what a node held was treated as authority. So the clause binds only while
/// `miner::adaptive_work_checked` reports the sample IS the chain's.
///
/// Both halves are asserted here, because either alone would let the fix be wrong:
/// * an honestly produced header on a node holding its parents is ADMITTED, and the walk that
///   admitted it was COMPLETE (so the clause really ran — a vacuous pass would prove nothing);
/// * a node with no chain to walk reports INCOMPLETE, so the figure it would have judged by is
///   never turned into a refusal.
///
/// ROOT-LAYER: asserted on the shared door's verdict and on the producer of the completeness
/// verdict itself, not on any lane.
/// MUST-STAY-GREEN: this IS the must-stay-green assertion for the two pins above.
/// cons: one node of 3 produced blocks. f(FIXED CONSTANTS).
#[test]
fn pin_refut_the_work_clause_never_refuses_an_honest_header_and_never_judges_a_truncated_sample() {
    let victim = mined_node("refut-honest", 3);
    let tip = victim.selected_tip().expect("the victim has a tip");
    let tip_node = victim.dag().get(&tip).expect("the tip block");
    let sp = tip_node.selected_parent.expect("a produced tip has a parent");
    let honest_header = tip_node.header.clone();

    let (expected, complete) = crate::miner::adaptive_work_checked(victim.dag(), Some(sp));
    eprintln!(
        "[refut] honest header work={} expected={expected} complete={complete}",
        honest_header.work
    );
    assert!(
        complete,
        "the walk from a produced block's own selected parent is genesis-rooted on this node, so \
         the clause is entitled to judge it — if this is false the pin below proves nothing"
    );
    assert_eq!(
        honest_header.work, expected,
        "AN HONEST PRODUCED HEADER WOULD BE REFUSED BY THE NEW WORK CLAUSE. Its `work` is the DAA \
         figure its own producer computed for these same parents; if this node computes a different \
         one from a COMPLETE sample, the clause is not the gossip door's equality and must not ship."
    );

    // The other half: a node with nothing to walk must never hand out a verdict.
    let empty = crate::dag::Dag::new();
    let (seed, seed_complete) = crate::miner::adaptive_work_checked(&empty, None);
    eprintln!("[refut] no-tip walk figure={seed} complete={seed_complete}");
    assert!(
        !seed_complete,
        "A NODE WITH NO CHAIN CLAIMED AUTHORITY OVER A PEER'S DIFFICULTY. `BOOTSTRAP_WORK` is a \
         SEED, not a judgement; reporting it complete would turn every jumped, restored or \
         backfilling node into one that refuses the very blocks that heal it — the measured \
         two-way `WrongWork` after a restart."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// ADVERSARIAL RE-REVIEW 2026-09-08 — the two pins above hardcode the ONE parent value that makes
// the new clause fire. These change that one field to what an attacker actually holds.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A block id this victim has never seen — what an attacker's anchor names, because a DSYNC anchor
/// is BY CONSTRUCTION a block from a chain the adopter does not hold. This is the peer-PLAUSIBLE
/// value; `victim.dag().genesis()` (what both refut pins pass) is the one value that is NOT.
fn parent_the_victim_does_not_hold(victim: &Node) -> Hash32 {
    let p = Hash32::hash(b"a tip on the chain this victim is being asked to jump to");
    assert!(
        !victim.dag().contains(&p),
        "premise: this id is genuinely absent from the victim's DAG"
    );
    p
}

/// ⛔ FRESH ATTACK 1 — THE WORK CLAUSE IS SKIPPED BY THE ONLY PARENT AN ATTACKER WOULD EVER NAME.
///
/// `Node::header_work_is_bound` returns `true` (admit) whenever ANY parent is absent from this
/// node's DAG (`node.rs:6331-6334`). Both `pin_refut_a_work_one_never_mined_anchor_is_refused_*`
/// pins hand the fabrication `victim.dag().genesis()` as its parent — the single value that keeps
/// every parent present and lets the clause run. A DSYNC anchor's parent is, by the definition of
/// DSYNC, a block the adopter does NOT hold. Change that one field and the identical never-mined,
/// `work = 1`, `pow_proof`-less header the two pins refuse is admitted again.
#[test]
fn review_b1_a_never_mined_anchor_whose_parent_is_not_held_passes_the_bundle_door() {
    let victim = mined_node("review-b1", 2);
    let template = victim
        .dag()
        .get(&victim.dag().genesis().expect("genesis"))
        .expect("the genesis block")
        .header
        .clone();
    let unheld = parent_the_victim_does_not_hold(&victim);

    // BYTE-FOR-BYTE the refut pins' fabrication, with ONE field changed: the parent.
    let fake = shell_on(&template, unheld, 1, template.timestamp + 1, 0xBEEF);
    assert!(fake.pow_proof.is_empty(), "premise: no witness at all");

    let bundle = bundle_of(&fake, &crate::params::network_genesis_prefix("testnet"));
    let admitted = victim.bundle_blocks_refusal(&bundle).is_none();
    let work_clause_ran = fake.header.parents.iter().all(|p| victim.dag().contains(p));
    eprintln!(
        "[review-b1] bundle_blocks_admitted={admitted} declared_work={} \
         parents_all_held={work_clause_ran} (the refut pin's fabrication differs ONLY in this field)",
        fake.header.work
    );
    assert!(
        !admitted,
        "THE BUNDLE DOOR STILL ADMITS THE NEVER-MINED HEADER. The work equality added at the shared \
         site is guarded by `header.parents.iter().any(|p| !dag.contains(p)) => return true` \
         (node.rs:6331-6334), and a DSYNC anchor's parent is never held by the adopter — that is \
         what makes it a DSYNC anchor. The two refut pins pass `genesis` as the parent, which is the \
         only value that keeps the guard from firing, so they measure a case the attack does not use."
    );
}

/// ⛔ FRESH ATTACK 2 — THE SAME FIELD AT THE ANCHOR DOOR, WHICH CLEARS THE TIP SET.
///
/// `Node::admit_anchor_block` (`node.rs:6452-6471`) runs `header_door_admits` and then hands the
/// block straight to `Dag::add_anchor` with the caller's `blue_work`. With the work clause skipped,
/// the three surviving clauses are the grind (free at `work = 1`), the structural header rules (no
/// DAG access) and `validate_carried_body_commitments` (every part empty ⇒ `absent_ok` admits).
#[test]
fn review_b2_a_never_mined_anchor_whose_parent_is_not_held_takes_the_tip() {
    let mut victim = mined_node("review-b2", 2);
    let honest_tip = victim.selected_tip().expect("a tip");
    let template = victim
        .dag()
        .get(&victim.dag().genesis().expect("genesis"))
        .expect("the genesis block")
        .header
        .clone();
    let unheld = parent_the_victim_does_not_hold(&victim);
    let fake = shell_on(&template, unheld, 1, template.timestamp + 1, 0xF00D);
    let fake_id = fake.id();

    let installed = victim.admit_anchor_block(fake, u128::MAX, 7);
    let in_dag = victim.dag().get(&fake_id).is_some();
    let tip_after = victim.selected_tip().expect("a tip");
    eprintln!(
        "[review-b2] anchor installed={installed} in_dag={in_dag} tip_after={tip_after:?} \
         honest_tip={honest_tip:?}"
    );
    assert!(
        !installed && !in_dag && tip_after == honest_tip,
        "FORK-CHOICE TAKEOVER THROUGH THE ANCHOR DOOR IS STILL OPEN (installed={installed}, \
         in_dag={in_dag}). Identical to the fabrication \
         `pin_refut_a_work_one_never_mined_anchor_is_refused_by_the_anchor_door` refuses, with the \
         parent changed from the victim's own genesis to an id the victim does not hold."
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// ADVERSARIAL RE-REVIEW OF THE 2026-09-08 WORK-BINDING CLOSURE (refute by default).
// The three pins above assert the closure with ONE attacker value: `work = 1`. These construct
// the same fabrication with the values a real attacker picks instead.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// R1 — THE PIN ABOVE PROVES THE CONSTANT `1`, NOT THE CLASS.
/// The identical never-mined, `pow_proof`-less anchor, declaring the work the HONEST code path
/// itself produces for that parent (`adaptive_work_checked(dag, genesis).0`). The equality clause
/// is satisfied by construction, and the grind at that figure costs ~`expected` hashes.
#[test]
fn rerefut_r1_a_never_mined_anchor_declaring_the_honest_daa_figure_is_refused() {
    let mut victim = mined_node("rerefut-r1", 2);
    let genesis = victim.dag().genesis().expect("genesis");
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim.dag().get(&genesis).expect("genesis block").header.clone();
    let (expected, complete) = crate::miner::adaptive_work_checked(victim.dag(), Some(genesis));

    let mut fake = shell_on(&template, genesis, expected, template.timestamp + 1, 0);
    let mut hashes = 0u64;
    while !victim.header_grind_admits(&fake.header) {
        fake.header.nonce = fake.header.nonce.wrapping_add(1);
        hashes += 1;
        assert!(hashes < 5_000_000, "could not grind at the honest DAA figure {expected}");
    }
    assert!(fake.pow_proof.is_empty(), "premise: no witness at all");
    let fake_id = fake.id();
    let bundle = bundle_of(&fake, &crate::params::network_genesis_prefix("testnet"));
    let admitted = victim.bundle_blocks_refusal(&bundle).is_none();
    let installed = victim.admit_anchor_block(fake, u128::MAX, 7);
    let in_dag = victim.dag().get(&fake_id).is_some();
    let tip_after = victim.selected_tip().expect("tip");
    eprintln!(
        "[rerefut-r1] expected={expected} complete={complete} grind_hashes={hashes} \
         bundle_admitted={admitted} anchor_installed={installed} in_dag={in_dag} \
         tip_after={tip_after:?} honest_tip={honest_tip:?}"
    );
    assert!(
        !admitted && !installed && !in_dag && tip_after == honest_tip,
        "THE WORK EQUALITY IS SATISFIED BY A NEVER-MINED HEADER. Declaring `work = expected` \
         instead of `work = 1` costs {hashes} hashes and no `pow_proof` at all."
    );
}

/// R2 — THE SHARED CLAUSE DOES NOT FIRE ON THE SHAPE THE ATTACK ACTUALLY TAKES.
/// `header_work_is_bound` returns `true` whenever any parent is absent from this DAG — and a DSYNC
/// anchor's parents are absent BY CONSTRUCTION on the node that is adopting it. Same reviewer
/// fabrication, `work = 1`, parent = an id this victim has never held.
#[test]
fn rerefut_r2_a_work_one_anchor_naming_an_unheld_parent_is_refused() {
    let mut victim = mined_node("rerefut-r2", 2);
    let genesis = victim.dag().genesis().expect("genesis");
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim.dag().get(&genesis).expect("genesis block").header.clone();
    let phantom = Hash32::hash(b"a parent id this victim has never held");
    assert!(!victim.dag().contains(&phantom), "premise: the parent is unheld");

    let fake = shell_on(&template, phantom, 1, template.timestamp + 1, 0xC0DE);
    let fake_id = fake.id();
    let bundle = bundle_of(&fake, &crate::params::network_genesis_prefix("testnet"));
    let admitted = victim.bundle_blocks_refusal(&bundle).is_none();
    let installed = victim.admit_anchor_block(fake, u128::MAX, 7);
    let in_dag = victim.dag().get(&fake_id).is_some();
    let tip_after = victim.selected_tip().expect("tip");
    eprintln!(
        "[rerefut-r2] declared_work=1 unheld_parent bundle_admitted={admitted} \
         anchor_installed={installed} in_dag={in_dag} tip_after={tip_after:?} \
         honest_tip={honest_tip:?}"
    );
    assert!(
        !admitted && !installed && !in_dag && tip_after == honest_tip,
        "THE REVIEWER'S ORIGINAL work=1 FABRICATION IS STILL ADMITTED — it only has to name a \
         parent this node does not hold, which is the normal shape of a DSYNC anchor."
    );
}

/// R3 — THE `is_genesis()` EARLY RETURN. A parentless header is exempted from the work clause and
/// from the structural parent rules, and `work = 1` makes the grind free.
#[test]
fn rerefut_r3_a_parentless_second_genesis_shell_is_refused() {
    let mut victim = mined_node("rerefut-r3", 2);
    let genesis = victim.dag().genesis().expect("genesis");
    let honest_tip = victim.selected_tip().expect("tip");
    let template = victim.dag().get(&genesis).expect("genesis block").header.clone();
    let mut fake = shell_on(&template, genesis, 1, template.timestamp + 7, 0xBAD0);
    fake.header.parents = Vec::new();
    assert!(fake.header.is_genesis(), "premise: parentless");
    let fake_id = fake.id();
    assert_ne!(Some(fake_id), victim.dag().genesis(), "premise: NOT this node's own genesis");

    let bundle = bundle_of(&fake, &crate::params::network_genesis_prefix("testnet"));
    let admitted = victim.bundle_blocks_refusal(&bundle).is_none();
    let installed = victim.admit_anchor_block(fake, u128::MAX, 7);
    let in_dag = victim.dag().get(&fake_id).is_some();
    let tip_after = victim.selected_tip().expect("tip");
    eprintln!(
        "[rerefut-r3] parentless work=1 bundle_admitted={admitted} anchor_installed={installed} \
         in_dag={in_dag} tip_after={tip_after:?} honest_tip={honest_tip:?}"
    );
    assert!(
        !admitted && !installed && !in_dag && tip_after == honest_tip,
        "A PARENTLESS SECOND GENESIS IS ADMITTED — `header_work_is_bound` returns true on \
         `is_genesis()` and `validate_header_structural` skips every parent rule for that shape."
    );
}
