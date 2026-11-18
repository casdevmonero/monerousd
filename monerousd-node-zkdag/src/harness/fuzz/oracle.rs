// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE INVARIANT CATALOGUE, EVALUATED AFTER EVERY STEP — AND IT FOLDS, IT NEVER STORES.**
//!
//! ⛔⛔ THE WHOLE POINT OF THIS FILE IS THAT THE CHECKS ARE CONTINUOUS.
//!
//! The tree already has a schedule search (`mesh_schedule_search_tests`) and it asserts its property
//! ONCE, after `drain()`, at the end of the run. That shape cannot see a violation that HEALS: a note
//! that leaves the unspent set and comes back, a record that folds at ordinal 48 and is renumbered to 9,
//! a tip that visits a block nobody mined and then moves off it. Every one of those is a fund-safety
//! event on the way through, and every one is invisible to an end-of-run verdict. **A violation that
//! self-heals before the end is still a violation**, so the oracle runs after EVERY step and the first
//! violation ends the run.
//!
//! | Kind | Assertable when | Invariants |
//! |---|---|---|
//! | **safety / monotone** | after EVERY step, mid-flight included | I-1, I-4, I-5, I-6, I-8, I-15 |
//! | **convergence** | only at a QUIESCENCE point (`Drain`, end of run) | I-3 |
//!
//! Mid-flight the parties legitimately disagree — one holds a block another has not been handed yet — so
//! asserting I-3 continuously would be a false-alarm generator, and a harness that cries wolf is a
//! harness nobody reads. The safety half needs no quiescence: it is about what a SINGLE node did to
//! ITSELF between two adjacent instants, and that is checkable everywhere.
//!
//! ---
//!
//! ## THE ORACLE IS FIXED-WIDTH, AND THAT IS A DESIGN CONSTRAINT, NOT A COMMENT
//!
//! The first draft of this file kept the unspent leaf SET, a per-record ordinal MAP and a spent-note SET.
//! Every one of those grows with the chain, and an instrument that grows with the chain is the very shape
//! this project bans in the code it is testing. So the oracle carries **no collection whose size depends
//! on history**. Every question is answered by a FOLD into a fixed-width accumulator, or by a pure
//! function of the node's CURRENT state:
//!
//! | Question | Stored answer (rejected) | Folded / derived answer (this file) |
//! |---|---|---|
//! | did a note leave `U` unjustified? | keep `U`, diff it | `uns_leaf_count`, one `usize` |
//! | was a note SWAPPED for another? | keep `U`, diff it | `uns_leaf_fold`, a 128-bit order-independent XOR fold |
//! | was a record RENUMBERED? | keep `(party, rid) -> ordinal` | `spine_ordinal_inversions`: the ordinal along the selected spine must STRICTLY INCREASE — a pure function of the DAG this node holds right now, and a *stronger* statement than "it did not change", because it says the numbering IS the DAG position |
//! | did a spent note come BACK? | keep every spent `cm` | `SpentFilter`, a **fixed 128 KiB** Bloom filter with its false-positive rate stated on the type |
//!
//! Total oracle state: `PARTY_FILTERS` × 128 KiB = **512 KiB, on the heap, plus three scalars** — whatever
//! the chain does. Nothing here is reachable from a node, a wire message or a snapshot; the node under
//! test gains not one byte.
//!
//! Every loop below runs over the PARTY COUNT the case fixes before it starts (2..=4,
//! `engine::MAX_PARTIES`) — never over blocks, records, notes or peers. The one walk that touches the
//! chain is the selected-spine walk in `sample`, and it is bounded by the DAG the case itself just made
//! (at most 1 + `engine::MAX_STEPS` × 3 = 145 blocks), not by history.
//!
//! **cons: TIME on the harness side only, and f(the case's fixed constants).** Per party per step: at
//! most 145 indexed reads for the spine and at most `cover::BLOCK_FIXED_NOTE_COUNT` × 145 = 37,120 XOR
//! steps for the leaf fold. Per run: 4×48×37,120 ≈ 7.1e6 XOR steps and 4×48×145 = 27,840 indexed reads
//! — milliseconds. No term contains chain height, peer count, dialer count or caller count.

use crate::consensus_scenarios::Sim;
use crate::harness::fuzz::op::Op;
use crate::hash::Hash32;
use crate::node::Node;

/// splitmix64 finaliser — the mixing function, reused so the folds below have no dependency of their own.
fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Fold a 32-byte commitment to a 128-bit term. Two distinct commitments collide with probability about
/// 2⁻¹²⁸, which is below every other error term in this harness.
fn cm_term(cm: &[u8; 32]) -> u128 {
    let mut lo = 0xC3A5_C85C_97CB_3127u64;
    let mut hi = 0xB492_B66F_BE98_F273u64;
    for chunk in cm.chunks(8) {
        let mut w = 0u64;
        for (k, b) in chunk.iter().enumerate() {
            w |= (*b as u64) << (8 * k);
        }
        lo = mix64(lo ^ w);
        let t = hi.wrapping_add(w);
        hi = mix64((t << 17) | (t >> 47));
    }
    ((hi as u128) << 64) | lo as u128
}

/// Bits in the spent filter — 2²⁰, i.e. a FIXED 128 KiB, whatever the chain does.
const SPENT_FILTER_BITS: u64 = 1 << 20;

/// 64-bit words backing [`SPENT_FILTER_BITS`].
const SPENT_FILTER_WORDS: usize = (SPENT_FILTER_BITS / 64) as usize;

/// **THE SPENT-NOTE FILTER — fixed 128 KiB, forever.**
///
/// A resurrection ("a commitment the chain recorded as spent re-entered the unspent set") is a membership
/// question, and membership is the one question a fold cannot answer. Keeping every spent commitment
/// would make the oracle grow with the chain, so it is a Bloom filter whose size is fixed at compile
/// time: 2²⁰ bits, 4 probes, and it never resizes however long the run is.
///
/// **The error is one-sided and its size is stated rather than hidden.** A miss is CERTAIN ("this note
/// was never spent"); a hit is a strong hint. The size is chosen FROM the case's own bound rather than
/// picked: at most `engine::MAX_STEPS` × `cover::BLOCK_FIXED_NOTE_COUNT` = 48 × 256 = 12,288 insertions,
/// so the false-positive rate is `(1 − e^(−4·12288/1048576))⁴` ≈ **4.4e-6** — below one hit in 200,000
/// probes, which is smaller than the number of probes a whole campaign performs. (At the 8 KiB size this
/// filter was first written with, the same bound gives ≈ 7.7%, which would have made the resurrection
/// oracle useless; the arithmetic is why the constant is what it is.)
///
/// A hit is still reported as a finding the SHRINKER must reproduce: a hit that survives shrinking to a
/// two-op case, deterministically, on a fixed seed, is not a coincidence, and a hit that does not
/// reproduce is dropped by the shrinker on its own — which is how a one-sided error should be handled.
/// ⛔ THE BIT ARRAY IS BOXED, AND THAT IS NOT STYLE.
///
/// BY CONSTRUCTION the catalogue holds `PARTY_FILTERS` = 4 of these, and at `SPENT_FILTER_BITS` = 2²⁰
/// each one is 128 KiB — so an inline array would put 512 KiB of `Oracle` on the stack and move it by
/// value out of `Oracle::new`. A test thread's default stack is 2 MiB, and a debug build does not elide
/// those moves. The bits live on the heap; the FIELD is a pointer to a FIXED-SIZE array, so the structure
/// is still fixed-width and still cannot grow with the chain.
#[derive(Clone)]
pub struct SpentFilter {
    bits: Box<[u64; SPENT_FILTER_WORDS]>,
    inserted: usize,
}

impl SpentFilter {
    pub fn new() -> SpentFilter {
        SpentFilter { bits: Box::new([0u64; SPENT_FILTER_WORDS]), inserted: 0 }
    }

    fn probes(cm: &[u8; 32]) -> [usize; 4] {
        let t = cm_term(cm);
        let a = (t & 0xFFFF_FFFF_FFFF_FFFF) as u64;
        let b = (t >> 64) as u64;
        [
            (mix64(a) % SPENT_FILTER_BITS) as usize,
            (mix64(b) % SPENT_FILTER_BITS) as usize,
            (mix64(a ^ b) % SPENT_FILTER_BITS) as usize,
            (mix64(a.wrapping_add(b)) % SPENT_FILTER_BITS) as usize,
        ]
    }

    pub fn insert(&mut self, cm: &[u8; 32]) {
        for p in SpentFilter::probes(cm) {
            self.bits[p / 64] |= 1u64 << (p % 64);
        }
        self.inserted += 1;
    }

    /// `false` is certain. `true` carries the ≈4.4e-6 false-positive rate stated on the type.
    pub fn may_contain(&self, cm: &[u8; 32]) -> bool {
        for p in SpentFilter::probes(cm) {
            if self.bits[p / 64] & (1u64 << (p % 64)) == 0 {
                return false;
            }
        }
        true
    }

    pub fn inserted(&self) -> usize {
        self.inserted
    }
}

impl Default for SpentFilter {
    fn default() -> SpentFilter {
        SpentFilter::new()
    }
}

/// The consensus-visible state of ONE party at ONE instant, entirely in fixed-width scalars.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sample {
    pub tip: Option<[u8; 32]>,
    /// GHOSTDAG accumulated work at the selected tip — the value the fork choice actually reads.
    pub tip_blue_work: Option<u128>,
    /// Blue work of the tip's selected parent, so a non-monotone step is visible.
    pub parent_blue_work: Option<u128>,
    /// How many parents of the tip this node does NOT hold. Must always be zero.
    pub tip_missing_parents: usize,
    pub uns_root: crate::spend_frontier::Digest4,
    /// `|U|` — how many level-0 leaves the unspent tree holds. A departure or an arrival is a change here.
    pub uns_leaf_count: usize,
    /// An order-independent XOR fold over `U`. Catches the case `uns_leaf_count` cannot: one commitment
    /// SWAPPED for another, which leaves the count identical and the membership completely different.
    pub uns_leaf_fold: u128,
    pub nf_root: [u8; 32],
    pub nf_count: u64,
    pub nf_acc: crate::spend_frontier::Digest4,
    pub membership_tip: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    pub spend_frontier_count: u64,
    pub record_ordinal_top: u64,
    pub dag_len: usize,
    /// Length of the selected-parent chain from the tip.
    pub spine_len: usize,
    /// **I-15, as a pure function of the DAG this node holds right now.** Walking the selected spine from
    /// the tip toward genesis, each record's ordinal must be STRICTLY GREATER than its selected parent's
    /// — because the ordinal IS the DAG position. Any position where it is not is counted here, and the
    /// count must always be zero. This is the memoryless form of "a record was renumbered", and it is
    /// stronger: it does not merely say the number changed, it says the number is not the DAG's.
    pub spine_ordinal_inversions: usize,
    /// ⛔ THE NO-GROWTH PILLAR, SAMPLED — TOTAL ENTRIES ACROSS EVERY NAMED STORE THIS NODE HOLDS.
    ///
    /// Rows D-5 and D-7 exist because a store can grow on input an ATTACKER chose: `btc_watch`'s want
    /// set took any string a caller posted and swept it forever, and the unauthenticated `NoteClue`
    /// arm wrote `pending_tags` under a bound proven for a different writer. Neither is visible in any
    /// root, count or verdict the rest of the catalogue reads — a node can be perfectly correct about
    /// consensus while filling up. Until this existed there was no growth oracle of ANY kind
    /// (`grep -rni census src/harness` → 0), so the class was invisible by construction.
    ///
    /// A SCALAR, DELIBERATELY, NOT A PER-STORE VECTOR. Sample is held per party per step, so a
    /// collection here would be a store of its own with a bound to argue about — the exact shape this
    /// field exists to police. The breakdown is not lost: `check_step` holds `&Sim`, so when this
    /// number moves the detector asks the live node for `da_entry_census_named()` and names the store
    /// in the finding. Diagnosis at failure time, no retained collection.
    pub store_entries_total: usize,
}

/// Read one party's consensus-visible state. Every call is an existing read accessor; nothing is written
/// back to the node, and nothing per-item is retained — the leaf set is FOLDED as it is walked.
pub fn sample(n: &Node) -> Sample {
    // `BlockId` is `Hash32`, a NEWTYPE over `[u8; 32]` that derives `Eq`/`Copy` but NOT `Debug`. The
    // sample keeps the raw array so `Sample` can derive `Debug` and print in a finding; the walk below
    // keeps the `Hash32` because that is what `Dag::get` and `da_record_id_for_block` take.
    let tip_id: Option<Hash32> = n.selected_tip();
    let tip_node = tip_id.as_ref().and_then(|id| n.dag().get(id));
    let tip_blue_work = tip_node.map(|b| b.blue_work);
    let parent_blue_work = tip_node
        .and_then(|b| b.selected_parent)
        .and_then(|p| n.dag().get(&p))
        .map(|b| b.blue_work);
    let tip_missing_parents = match tip_node {
        Some(b) => b.header.parents.iter().filter(|p| !n.dag().contains(p)).count(),
        None => 0,
    };

    // Z1: the unspent tree is gone, so the identity set the oracle folds is the one the node still
    // holds — the REAL NOTE COMMITMENTS in its records. Same two scalars, same fold, nothing per note
    // retained; bounded by the case's own records.
    let leaves = live_leaves(n);
    let uns_leaf_count = leaves.len();
    let mut uns_leaf_fold = 0u128;
    for cm in leaves.iter() {
        uns_leaf_fold ^= cm_term(cm);
    }

    // The spine walk folds into two counters as it goes. Bounded by the DAG this case itself made, so a
    // cycle — itself a defect — cannot hang the harness.
    let mut spine_len = 0usize;
    let mut spine_ordinal_inversions = 0usize;
    let cap = n.dag().len() + 1;
    let mut cur: Option<Hash32> = tip_id;
    let mut child_ord: Option<u64> = None;
    while let Some(id) = cur {
        spine_len += 1;
        if spine_len > cap {
            break;
        }
        let ord = n.da_record_ordinal(Node::da_record_id_for_block(&id, 0));
        // Walking tip -> genesis, a child's ordinal must be strictly greater than its parent's. Two
        // records that are both folded and out of order on the SAME spine is the record-spine fork.
        if let (Some(c), Some(p)) = (child_ord, ord) {
            if c <= p {
                spine_ordinal_inversions += 1;
            }
        }
        if ord.is_some() {
            child_ord = ord;
        }
        cur = n.dag().get(&id).and_then(|b| b.selected_parent);
    }

    Sample {
        tip: tip_id.map(|h| h.0),
        store_entries_total: n.da_entry_census_named().iter().map(|(_, e, _)| *e).sum(),
        tip_blue_work,
        parent_blue_work,
        tip_missing_parents,
        uns_root: usdm_decider::poseidon2_compress::lanes_of(&[u64::from_le_bytes(n.nullifier_root()[..8].try_into().unwrap_or_default()), 0, 0, 0]),
        uns_leaf_count,
        uns_leaf_fold,
        nf_root: n.nullifier_root(),
        nf_count: n.nullifier_count(),
        nf_acc: n.nf_unspent_acc(),
        membership_tip: n.membership_tip(),
        spend_frontier_count: n.spend_frontier_count(),
        record_ordinal_top: n.da_record_ordinal_top(),
        dag_len: n.dag().len(),
        spine_len,
        spine_ordinal_inversions,
    }
}

/// Sample every party. Bounded by `engine::MAX_PARTIES`, the party count the case fixes before it runs.
pub fn sample_all(sim: &Sim) -> Vec<Sample> {
    let mut out: Vec<Sample> = Vec::new();
    for n in sim.parties.iter() {
        out.push(sample(n));
    }
    out
}

/// Z1: every REAL note commitment a party still holds a record for — the identity set that replaced the
/// unspent map's leaves. A transient job input, consumed inside the step that asks for it and never
/// retained by the oracle. Bounded by the records the case itself produced.
fn live_leaves(n: &Node) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = Vec::new();
    // ⛔⛔⛔ THE PAIR IS `(ORDINAL, RECORD_ID)`, AND THIS READ IT BACKWARDS.
    //
    // `ordinal_rows_for_test` collects `da_ord_rev_mem` as `(o, r)` — ordinal FIRST. Destructured as
    // `(rid, _ord)`, every lookup below handed `da_record_notes` an ORDINAL (0, 1, 2, …) where it wants a
    // record id, so it missed every time and `live_leaves` returned EMPTY FOR EVERY NODE, ALWAYS.
    //
    // MEASURED 2026-09-24, `i8_custody…` build diagnostic — a party that had planted 12 real notes and
    // folded 25 records at the tip:
    //   `of 12 planted record(s): 0 took an ordinal on party 0, 0 of those answer for their bytes`
    //   `party 0's 25 ordinal row(s): 25 answer for NO bytes … ordinal rids: [0, 1, 2]`
    //
    // ⛔ WHAT THAT COST: `uns_leaf_count` is this vector's length, and I-8 CUSTODY-NOTE-DESTROYED — "a
    // note left the unspent set with NO spend accounting for it", the plainest funds-loss shape there is —
    // fires on a DECREASE in it. A count that is always zero can never decrease. The catalogue has called
    // that oracle "already written and correct" for as long as row C-H3 has been missed; it was reading an
    // empty set, which is the same silence a clean chain produces.
    for (_ordinal, rid) in n.ordinal_rows_for_test() {
        let Some(notes) = n.da_record_notes(rid) else { continue };
        let notes: Vec<Vec<u8>> = notes.chunks(crate::cover::PQ_NOTE_BYTES).map(|c| c.to_vec()).collect();
        let seed = crate::cover::public_idle_seed_note(rid);
        for note in notes.iter() {
            if note.len() >= 32 && note.as_slice() != &seed[..] && note[..32] != [0u8; 32] {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&note[..32]);
                out.push(cm);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Seed the spent filter with the commitment a `Spend` removed.
///
/// The oracle does not keep the previous leaf set, so the departed identity is recovered from bytes the
/// NODE already holds: a single-note spend is the overwhelmingly common case, and for it the fold delta
/// IS that note's term, so the note is named by matching the term against the party's own recorded DA
/// notes. When no single commitment explains the delta (a multi-note spend) the filter is left untouched
/// and the run reports a THINNER resurrection oracle rather than a wrong one — `spent_filter_stats` is
/// what makes that visible instead of silent.
fn seed_spent_from_delta(filter: &mut SpentFilter, node: &Node, delta: u128) {
    if delta == 0 {
        return;
    }
    // `da_recorded_notes` hands back one RECORD BLOB per address, and a record blob is a concatenation of
    // fixed-width note payloads — `cover::PQ_NOTE_BYTES` each, laid out `note_cm(32) ‖ ML-KEM ct ‖
    // enc_amount ‖ view_tag`. Reading the first 32 bytes of the BLOB would name only the record's first
    // note and miss every other one, so the blob is walked in note-sized strides and each note's own
    // commitment is tested.
    let stride = crate::cover::PQ_NOTE_BYTES;
    for (_addr, blob) in node.da_recorded_notes() {
        for chunk in blob.chunks(stride) {
            if chunk.len() < 32 {
                continue;
            }
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&chunk[..32]);
            if cm_term(&cm) == delta {
                filter.insert(&cm);
                return;
            }
        }
    }
}

/// One violation. `invariant` is the catalogue id and is the SHRINK TARGET: the shrinker keeps reducing
/// only while the same id keeps coming back, so a minimised case reproduces the same finding and not
/// merely "some failure".
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub invariant: &'static str,
    /// Index of the step that produced it, 0-based, into the op sequence.
    pub step: usize,
    /// The op that produced it.
    pub op: Option<Op>,
    /// The party it was observed on. `usize::MAX` for a cross-party finding.
    pub party: usize,
    pub detail: String,
}

impl Finding {
    fn at(invariant: &'static str, step: usize, op: Option<Op>, party: usize, detail: String) -> Finding {
        Finding { invariant, step, op, party, detail }
    }
}

/// One spent-note filter per party. `engine::MAX_PARTIES` is 4; this is stated as its own constant so a
/// mismatch is a compile error in `check_step` rather than a silently ignored party.
pub const PARTY_FILTERS: usize = 4;

/// The catalogue. Total state: `PARTY_FILTERS` × 128 KiB = 512 KiB and three scalars, whatever the chain
/// does.
pub struct Oracle {
    /// ⛔ ONE FILTER PER PARTY, AND THAT IS NOT AN OPTIMISATION — IT IS WHAT MAKES THE RESURRECTION
    /// ORACLE SOUND.
    ///
    /// BY CONSTRUCTION a single shared filter is wrong in a mesh: `Sim::spend` deletes the note on the
    /// spending party inside the `Spend` step and QUEUES the carrying block for every other party, which
    /// only applies it on a later `Deliver`/`Burst`/`Drain`. So between those two steps a peer's unspent
    /// set legitimately still contains a commitment the shared filter has already recorded as spent, and
    /// that peer's next arrival would probe a set containing it and report a resurrection that did not
    /// happen — an alarm produced by ordinary propagation, not by a defect.
    ///
    /// Keyed by party, the question becomes the sound one: *did a note that left THIS party's unspent set
    /// come back to THIS party?* Propagation order cannot produce that, and the
    /// receive-fold-that-did-not-consult-the-deletion-sidecar shape still does.
    spent: [SpentFilter; PARTY_FILTERS],
    /// Departures excused because the step was a certified-prefix adopt, reported rather than silently
    /// allowed — see [`Oracle::jump_excused_departures`].
    jump_excused: usize,
    /// How many arrivals the spent filter has been asked about, so a hit rate is reportable.
    resurrection_probes: usize,
    /// ⭐ THE AUTHORISED-DEPARTURE BUDGET — one integer, and the reason the custody oracle is not either
    /// a false-alarm generator or toothless.
    ///
    /// A spend deletes a note on the SPENDING party immediately and on every peer LATER, when the block
    /// carrying the deletion is handed over — and that hand-over is a `Deliver`, a `Burst` or a `Drain`.
    /// Naively, "a note left `U` on a `Deliver`" would therefore fire on every honest spend that ever
    /// propagates. The two wrong ways out are both worse than the problem: adding `Deliver` to the ops
    /// that may remove would excuse a FORGED deletion page arriving by exactly that route (which is the
    /// hole this oracle exists for), and keeping the departed commitments to match them up would be a
    /// store that grows with the chain.
    ///
    /// So the chain-recorded spends are counted, not kept: a spend of `d` notes authorises `d` later
    /// departures on each of the other parties, and any departure that cannot draw on that budget is
    /// unexplained — a note destroyed with no spend behind it anywhere in the schedule.
    ///
    /// The residual is stated rather than hidden: a forged deletion that lands while a genuine spend's
    /// budget is still outstanding is absorbed by it. That is a false NEGATIVE, never a false positive,
    /// and `authorised_departures_unclaimed` reports the leftover so a run can say how much cover
    /// existed.
    authorised_departures: usize,
}

impl Oracle {
    pub fn new() -> Oracle {
        Oracle {
            spent: [
                SpentFilter::new(),
                SpentFilter::new(),
                SpentFilter::new(),
                SpentFilter::new(),
            ],
            jump_excused: 0,
            resurrection_probes: 0,
            authorised_departures: 0,
        }
    }

    /// Authorised departures a run never claimed. A large number means a lot of cover existed for a
    /// forged deletion to hide behind, and that belongs in the report rather than in a silence.
    pub fn authorised_departures_unclaimed(&self) -> usize {
        self.authorised_departures
    }

    /// How many unspent-set departures were excused because the step was a certified-prefix adopt.
    /// A run reporting a large number here is a run whose custody coverage was thin, and the number
    /// belongs in the report rather than in a silence.
    pub fn jump_excused_departures(&self) -> usize {
        self.jump_excused
    }

    /// How many commitments the per-party filters hold in total, and how many leaves were tested against
    /// them. A run that reports `(0, n)` has a resurrection oracle with NO reach — it never saw a spend it
    /// could attribute — and that is a fact about the run's coverage, not a pass.
    pub fn spent_filter_stats(&self) -> (usize, usize) {
        let mut held = 0usize;
        for f in self.spent.iter() {
            held += f.inserted();
        }
        (held, self.resurrection_probes)
    }

    /// ⭐⭐⭐ THE CONTINUOUS CHECK. Run after EVERY step, against the instant before it.
    ///
    /// Returns the FIRST violation. Order is chosen so the most legible cause is reported first: a
    /// hostile op that moved state, then custody, then conservation, then numbering, then fork choice,
    /// then liveness.
    pub fn check_step(
        &mut self,
        step: usize,
        op: Op,
        before: &[Sample],
        after: &[Sample],
        sim: &Sim,
    ) -> Option<Finding> {
        let parties = before.len().max(1);

        // -------------------------------------------------------------------------------------------
        // I-1 / I-4 / I-5 — A HOSTILE OP MOVES NOTHING, ON ANY PARTY.
        //
        // The strongest single assertion in the catalogue, and it needs no interpretation: the ONLY
        // correct outcome of a forged bundle, a forged sidecar page, a wrong-work block or a replayed
        // bundle is refusal, so every consensus-visible value on every party must be byte-identical
        // across the step. One comparison covers conservation (nothing minted), fork choice (no tip
        // moved), growth (no counter advanced) and numbering (no ordinal written).
        // -------------------------------------------------------------------------------------------
        if op.is_hostile() {
            let actor = match op.party() {
                Some(p) => Some((p as usize) % parties),
                None => None,
            };
            for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
                let actor_mined = actor == Some(i) && op.actor_produces_an_honest_block();
                if actor_mined {
                    // ⛔ NO IDENTITY CHECK ON THIS ONE PARTY, AND THE REASON IS MEASURED FROM THE ENGINE,
                    // NOT ASSUMED: `Sim::invalid` calls `produce` on party `i` before it forges anything,
                    // and a produced block grafts `cover::BLOCK_FIXED_NOTE_COUNT` cover notes into that
                    // party's unspent tree. So on an `Invalid` step the actor's tip, DAG, unspent count
                    // AND unspent root all move for an entirely honest reason, and there is no
                    // before/after pair in this step that separates the mine from the forgery.
                    //
                    // The actor is NOT left uncovered. `Sim::invalid` asserts, for EVERY party including
                    // this one, that the forged block is neither `Added` nor able to move `dag().tips()`,
                    // and that assertion runs as this step's own verdict — an `Err` from it is reported by
                    // the engine before the oracle is even consulted. Saying "covered there, not here" is
                    // the honest description; pretending to check it here would be the decoration.
                } else if a.store_entries_total > b.store_entries_total
                    && a.dag_len == b.dag_len
                {
                    // ⛔⛔⛔ I-NG NO-GROWTH — A HOSTILE ACTION MUST LEAVE NO FOOTPRINT (rows D-5, D-7).
                    //
                    // A SPECIFIC DIAGNOSIS MUST BEAT THE GENERIC ONE, and this arm sits above the
                    // catch-all below for exactly that reason. MEASURED, by the refutation lane the day
                    // this detector landed: with I-NG placed AFTER the catch-all it could never fire —
                    // `b != a` is true whenever the census moves, so every unbounded-growth finding was
                    // reported as "the state tuple changed in a field this reporter does not name".
                    // The oracle was not wrong, it was SHADOWED, and a campaign would have printed a
                    // shrug where it should have printed "an attacker chose what this node holds".
                    //
                    // The discriminator is `dag_len` unchanged: a hostile op may legitimately grow the
                    // stores of a party that ACCEPTED A BLOCK during it (`Sim::invalid` has the actor
                    // PRODUCE a real block before forging a copy). Growth with no chain work behind it
                    // is the defect — entries a caller's bytes created, backed by no block.
                    let census: Vec<String> = sim
                        .parties
                        .get(i)
                        .map(|n| {
                            n.da_entry_census_named()
                                .into_iter()
                                .filter(|(_, entries, _)| *entries > 0)
                                .map(|(name, entries, bytes)| format!("{name}={entries} ({bytes} B)"))
                                .collect()
                        })
                        .unwrap_or_default();
                    return Some(Finding::at(
                        "I-NG HOSTILE-ACTION-GREW-A-STORE",
                        step,
                        Some(op),
                        i,
                        format!(
                            "a HOSTILE op grew this node's total held entries {} -> {} (+{}) with the \
                             DAG unchanged — growth no block paid for. An attacker must never be able \
                             to choose what this node HOLDS: it is invisible to every root and count \
                             the rest of the catalogue reads, and it is paid forever. Live per-store \
                             census: [{}]. Fix at the WRITER — the set a node sweeps or stages must be \
                             one it PRODUCED, never one a caller named.",
                            b.store_entries_total,
                            a.store_entries_total,
                            a.store_entries_total - b.store_entries_total,
                            census.join(", ")
                        ),
                    ));
                } else if b != a {
                    return Some(Finding::at(
                        "I-1/I-4/I-5 HOSTILE-OP-MOVED-STATE",
                        step,
                        Some(op),
                        i,
                        describe_delta(b, a),
                    ));
                }
            }
        }

        // The party this op names, resolved once, so the per-party checks below can tell the ACTOR of a
        // hostile op from its victims.
        let actor_party = match op.party() {
            Some(p) => Some((p as usize) % parties),
            None => None,
        };

        // Per-party safety, mid-flight included. One pass over the fixed party count.
        for (i, (b, a)) in before.iter().zip(after.iter()).enumerate() {
            // On an `Invalid` step the actor really mined a block, and a produced block grafts
            // `cover::BLOCK_FIXED_NOTE_COUNT` cover notes into its own unspent tree. That arrival has a
            // namable chain-authorised justifier — the block it just produced — so for THIS party on THIS
            // step the op does carry notes. Every other party on the same step, and every party on the
            // other three hostile ops, is unaffected by this.
            let mined_here = actor_party == Some(i) && op.actor_produces_an_honest_block();
            let may_add = op.may_add_to_unspent() || mined_here;
            let may_remove = op.may_remove_from_unspent() || mined_here;
            // I-8 CUSTODY — a note leaves the unspent set ONLY against a chain-recorded spend. This is
            // the oracle for the forged-deletion-set shape (a page whose `del_cms` names a commitment the
            // victim really holds): the note is gone, no transaction and no block explain it, and the
            // fold reproduces the root by construction so no root check can notice.
            //
            // A departure on an op that carries no spend of its own must DRAW ON the budget a real spend
            // left behind (see `authorised_departures`). One that cannot is unexplained.
            if a.uns_leaf_count < b.uns_leaf_count && !may_remove {
                let lost = b.uns_leaf_count - a.uns_leaf_count;
                if self.authorised_departures >= lost {
                    self.authorised_departures -= lost;
                    // This departure IS explained — a real spend paid for it. Record what left THIS party
                    // so a later arrival of the same commitment on THIS party is recognisable as a
                    // resurrection. Seeding here rather than only at the spend is what gives every peer's
                    // filter the deletions it actually applied.
                    if i < PARTY_FILTERS {
                        if let Some(node) = sim.parties.get(i) {
                            let delta = b.uns_leaf_fold ^ a.uns_leaf_fold;
                            seed_spent_from_delta(&mut self.spent[i], node, delta);
                        }
                    }
                } else {
                    let unexplained = lost - self.authorised_departures;
                    return Some(Finding::at(
                        "I-8 CUSTODY-NOTE-DESTROYED",
                        step,
                        Some(op),
                        i,
                        format!(
                            "{unexplained} of {lost} commitment(s) left the unspent set ({} -> {}) with \
                             no chain-recorded spend anywhere in this schedule to explain them — no \
                             transaction, no block, and the fold still reproduces the root",
                            b.uns_leaf_count, a.uns_leaf_count
                        ),
                    ));
                }
            }

            // I-1 CONSERVATION — every arrival has a namable chain-authorised justifier. The justifier
            // here is the OP: only an op that can carry a note into a node may explain an arrival. A
            // commitment that enters the unspent set on a `Drop` or a `Forget` — neither of which carries
            // anything — is a member of U the chain never committed to.
            if a.uns_leaf_count > b.uns_leaf_count && !may_add {
                return Some(Finding::at(
                    "I-1 CONSERVATION-UNJUSTIFIED-ARRIVAL",
                    step,
                    Some(op),
                    i,
                    format!(
                        "{} commitment(s) entered the unspent set on an op that carries none ({} -> {})",
                        a.uns_leaf_count - b.uns_leaf_count,
                        b.uns_leaf_count,
                        a.uns_leaf_count
                    ),
                ));
            }

            // I-12 / I-8 SWAP — the count is identical and the MEMBERSHIP is not. A substitution leaves
            // every count-based check green, which is exactly why the fold exists beside the count.
            if a.uns_leaf_count == b.uns_leaf_count
                && a.uns_leaf_fold != b.uns_leaf_fold
                && !may_remove
                && !may_add
            {
                return Some(Finding::at(
                    "I-8/I-12 UNSPENT-SET-SWAPPED",
                    step,
                    Some(op),
                    i,
                    format!(
                        "the unspent set kept {} members and changed membership on an op that carries \
                         nothing (fold {:032x} -> {:032x})",
                        a.uns_leaf_count, b.uns_leaf_fold, a.uns_leaf_fold
                    ),
                ));
            }

            // I-8 RESTART FUND SAFETY — going through the checkpoint must not move a single leaf. A
            // restart is a pure re-derivation of the same state; if the unspent set or its root differs
            // across it, some funds were held only in RAM and the next crash is a loss.
            let restarted_here = matches!(op, Op::Restart(p) if (p as usize) % parties == i);
            if restarted_here
                && (b.uns_leaf_count != a.uns_leaf_count
                    || b.uns_leaf_fold != a.uns_leaf_fold
                    || b.uns_root != a.uns_root)
            {
                return Some(Finding::at(
                    "I-8 RESTART-CHANGED-THE-UNSPENT-SET",
                    step,
                    Some(op),
                    i,
                    format!(
                        "restart moved the unspent set: {} leaves -> {} leaves, fold {:032x} -> {:032x}",
                        b.uns_leaf_count, a.uns_leaf_count, b.uns_leaf_fold, a.uns_leaf_fold
                    ),
                ));
            }

            if matches!(op, Op::Jump(..)) && a.uns_leaf_count < b.uns_leaf_count {
                self.jump_excused += b.uns_leaf_count - a.uns_leaf_count;
            }

            // A certified-prefix adopt REPLACES this party's state wholesale, so what its filter learned
            // about the history it just discarded no longer describes it. Clearing is the fail-SAFE
            // direction: it can only cost the oracle reach (a missed resurrection), never invent one.
            if matches!(op, Op::Jump(..)) && i < PARTY_FILTERS {
                self.spent[i] = SpentFilter::new();
            }

            // I-15 ONE NUMBERING — the ordinal IS the DAG position, so along the selected spine it must
            // strictly increase. The measured record-spine fork (one node folding a record at ordinal 48
            // and its peer at 9) shows up here as an inversion. A pure function of the node's current
            // DAG: no history is kept, and the check is sound at any instant, mid-flight included.
            //
            // Asserted as a STEP DELTA — "this step introduced an inversion" — rather than as an absolute
            // "there are none". The two differ in exactly one way and it matters: the absolute form makes
            // every later step of a run red once anything has gone wrong once, and it also turns any
            // structural property of the numbering that this harness has not yet MEASURED into a blanket
            // failure that hides everything else. The delta form names the step that broke it, which is
            // what a reproducer needs, and the absolute count still rides in `Outcome` for the report.
            if a.spine_ordinal_inversions > b.spine_ordinal_inversions {
                return Some(Finding::at(
                    "I-15 RECORD-ORDINAL-IS-NOT-THE-DAG-POSITION",
                    step,
                    Some(op),
                    i,
                    format!(
                        "this step introduced {} ordinal inversion(s) on the selected spine ({} -> {} \
                         over a {}-block spine): a record's ordinal no longer exceeds its selected \
                         parent's, so the numbering is not the DAG's position",
                        a.spine_ordinal_inversions - b.spine_ordinal_inversions,
                        b.spine_ordinal_inversions,
                        a.spine_ordinal_inversions,
                        a.spine_len
                    ),
                ));
            }

            // ⛔⛔⛔ A WEDGE IS A FINDING WITH NO TIP MOVE (register class A, D-02). This detector used to
            // sit INSIDE the `a.tip != b.tip` gate below, and saturating the weight is precisely what
            // FREEZES the tip: once a node's selected tip carries `u128::MAX`, every honest block is
            // `NotHeavier` forever and the tip never moves again. So the antecedent excluded exactly the
            // outcome the detector exists to catch. MEASURED on lane F's first self-mint run: the
            // bundle was `Adopted` and the oracle said `None`.
            //
            // Checked on the AFTER state alone, with no comparison to `before`, because the defect is a
            // STATE this node must never be in — not a transition it must never make. A node already
            // wedged when the step began is still wedged, and reporting it late beats never.
            if a.tip_blue_work == Some(u128::MAX) {
                return Some(Finding::at(
                    "I-4 TIP-WEIGHT-SATURATED",
                    step,
                    Some(op),
                    i,
                    "the selected tip carries blue_work = u128::MAX — a permanent NotHeavier wedge: \
                     every honest block from here on is refused as lighter, so this node's tip can \
                     never move again. That is a halt, and it is reachable by editing two u128s in a \
                     bundle nobody has to mine."
                        .to_string(),
                ));
            }

            // I-4 FORK CHOICE INTEGRITY — only a block this node HOLDS COMPLETE can be the tip, and the
            // weight that put it there must be a DERIVED value, not a wire-supplied one. Asserted on what
            // the fork choice PRODUCES (`selected_tip`, the stored `blue_work`), never on an adopt
            // outcome — an unbound weight is exactly what makes an outcome unreliable.
            if a.tip != b.tip {
                if a.tip_missing_parents > 0 {
                    return Some(Finding::at(
                        "I-4 TIP-ON-A-BLOCK-WITH-ABSENT-PARENTS",
                        step,
                        Some(op),
                        i,
                        format!(
                            "the new selected tip has {} parent(s) this node does not hold",
                            a.tip_missing_parents
                        ),
                    ));
                }
                if let (Some(w), Some(p)) = (a.tip_blue_work, a.parent_blue_work) {
                    if w < p {
                        return Some(Finding::at(
                            "I-4 TIP-WEIGHT-NOT-MONOTONE",
                            step,
                            Some(op),
                            i,
                            format!("selected tip blue_work {w} is below its own selected parent's {p}"),
                        ));
                    }
                }
            }

            // I-6 FAIL-CLOSED — refuse the ITEM, never the chain's progress. A node that has lost its tip,
            // or whose DAG has shrunk, has refused its own history.
            if b.tip.is_some() && a.tip.is_none() {
                return Some(Finding::at(
                    "I-6 NODE-LOST-ITS-SELECTED-TIP",
                    step,
                    Some(op),
                    i,
                    "the node held a selected tip and now holds none".to_string(),
                ));
            }
            if a.dag_len < b.dag_len && !matches!(op, Op::Jump(..) | Op::Restart(_)) {
                return Some(Finding::at(
                    "I-5/I-6 DAG-SHRANK",
                    step,
                    Some(op),
                    i,
                    format!("the DAG lost blocks: {} -> {}", b.dag_len, a.dag_len),
                ));
            }
        }

        // -------------------------------------------------------------------------------------------
        // I-1 / I-2 RESURRECTION — a commitment the chain recorded as SPENT re-entered the unspent set.
        //
        // The receive fold that did not consult the deletion sidecar is exactly this shape, and it heals
        // on the next fold, so only a continuous check can see it. The filter's one-sided error is stated
        // on `SpentFilter`: a hit is reported, and the shrinker is what confirms it.
        // -------------------------------------------------------------------------------------------
        for (i, ((b, a), node)) in
            before.iter().zip(after.iter()).zip(sim.parties.iter()).enumerate()
        {
            if i >= PARTY_FILTERS {
                continue;
            }
            if a.uns_leaf_count <= b.uns_leaf_count {
                continue; // nothing arrived on this party this step
            }
            if self.spent[i].inserted() == 0 {
                continue; // this party has never had a note leave, so nothing can have come back
            }
            for cm in live_leaves(node) {
                self.resurrection_probes += 1;
                if self.spent[i].may_contain(&cm) {
                    return Some(Finding::at(
                        "I-1/I-2 SPENT-NOTE-RESURRECTED",
                        step,
                        Some(op),
                        i,
                        format!(
                            "a commitment that LEFT THIS PARTY's unspent set against a chain-recorded \
                             spend is in it again (commitment {}, this party's filter holds {} \
                             departure(s), ~4.4e-6 false-positive rate — the shrinker confirms)",
                            hex16(&cm),
                            self.spent[i].inserted()
                        ),
                    ));
                }
            }
        }

        // A `Spend` is the schedule's chain-recorded departure. The spending party's own deletion is
        // recorded into ITS filter here; every peer's copy is recorded into THEIRS when the carrying block
        // reaches them (the custody branch above). Identities are read once and folded straight into the
        // fixed-width filter — none of them is kept.
        if matches!(op, Op::Spend(_)) {
            let peers = parties.saturating_sub(1);
            for (i, ((b, a), node)) in
                before.iter().zip(after.iter()).zip(sim.parties.iter()).enumerate()
            {
                if a.uns_leaf_count >= b.uns_leaf_count {
                    continue;
                }
                let deleted = b.uns_leaf_count - a.uns_leaf_count;
                // Each of the OTHER parties must see this same deletion once the block carrying it is
                // handed over, and that hand-over is a `Deliver`/`Burst`/`Drain`. Authorise exactly that
                // many later departures — a count, never the commitments themselves.
                self.authorised_departures += deleted * peers;
                if i < PARTY_FILTERS {
                    let delta = b.uns_leaf_fold ^ a.uns_leaf_fold;
                    seed_spent_from_delta(&mut self.spent[i], node, delta);
                }
            }
        }

        None
    }

    /// ⭐ I-3 STATE = f(CHAIN) — asserted only at a QUIESCENCE point.
    ///
    /// Two nodes fed the same accepted blocks must reach BYTE-IDENTICAL roots. Every field of the tuple
    /// is compared, not a summary: a root that differs in one limb is a fork.
    pub fn check_quiescent(&self, step: usize, op: Option<Op>, samples: &[Sample]) -> Option<Finding> {
        let Some(first) = samples.first() else { return None };
        for (i, s) in samples.iter().enumerate().skip(1) {
            let mut diffs: Vec<String> = Vec::new();
            if s.tip != first.tip {
                diffs.push("selected_tip".to_string());
            }
            if s.uns_root != first.uns_root {
                diffs.push(format!(
                    "unspent_note_root {} vs {}",
                    hex_d4(&first.uns_root),
                    hex_d4(&s.uns_root)
                ));
            }
            if s.uns_leaf_fold != first.uns_leaf_fold {
                diffs.push(format!(
                    "unspent membership fold {:032x} vs {:032x}",
                    first.uns_leaf_fold, s.uns_leaf_fold
                ));
            }
            if s.nf_root != first.nf_root {
                diffs.push("nullifier_root".to_string());
            }
            if s.nf_count != first.nf_count {
                diffs.push(format!("nullifier_count {} vs {}", first.nf_count, s.nf_count));
            }
            if s.nf_acc != first.nf_acc {
                diffs.push("nf_unspent_acc".to_string());
            }
            if s.membership_tip != first.membership_tip {
                diffs.push("membership_tip".to_string());
            }
            if s.record_ordinal_top != first.record_ordinal_top {
                diffs.push(format!(
                    "da_record_ordinal_top {} vs {}",
                    first.record_ordinal_top, s.record_ordinal_top
                ));
            }
            if !diffs.is_empty() {
                return Some(Finding::at(
                    "I-3 STATE-IS-NOT-A-FUNCTION-OF-THE-CHAIN",
                    step,
                    op,
                    i,
                    format!("party 0 and party {i} diverge on: {}", diffs.join(", ")),
                ));
            }
        }
        None
    }
}

impl Default for Oracle {
    fn default() -> Oracle {
        Oracle::new()
    }
}

/// Did anything that HOLDS VALUE move between two instants? `None` when nothing did; otherwise the names
/// of the fields that did.
///
/// The subset is the ledger, and nothing else: the unspent set (its size, its membership fold and its
/// root), the spent set (root and count), the nullifier accumulator, and the membership tip. It excludes
/// `selected_tip`, `dag_len`, `spine_len` and the record-ordinal top — those move whenever a node
/// legitimately mines or takes delivery, and they carry no value on their own.
///
/// Used for the ONE party in the ONE hostile op that legitimately mines while it attacks (see
/// `Op::actor_produces_an_honest_block`). Everywhere else the catalogue demands full byte-identity.
fn value_bearing_delta(b: &Sample, a: &Sample) -> Option<String> {
    let mut moved: Vec<String> = Vec::new();
    if b.uns_leaf_count != a.uns_leaf_count {
        moved.push(format!("unspent leaves {} -> {}", b.uns_leaf_count, a.uns_leaf_count));
    }
    if b.uns_leaf_fold != a.uns_leaf_fold {
        moved.push("the unspent membership fold".to_string());
    }
    if b.uns_root != a.uns_root {
        moved.push(format!("unspent_note_root {} -> {}", hex_d4(&b.uns_root), hex_d4(&a.uns_root)));
    }
    if b.nf_root != a.nf_root {
        moved.push("nullifier_root".to_string());
    }
    if b.nf_count != a.nf_count {
        moved.push(format!("nullifier_count {} -> {}", b.nf_count, a.nf_count));
    }
    if b.nf_acc != a.nf_acc {
        moved.push("nf_unspent_acc".to_string());
    }
    if b.membership_tip != a.membership_tip {
        moved.push("membership_tip".to_string());
    }
    if moved.is_empty() {
        return None;
    }
    Some(moved.join(", "))
}

/// Name every field of the state tuple that moved — so a hostile-op finding says WHAT moved, not merely
/// that something did.
fn describe_delta(b: &Sample, a: &Sample) -> String {
    let mut moved: Vec<String> = Vec::new();
    if b.tip != a.tip {
        moved.push("selected_tip".to_string());
    }
    if b.tip_blue_work != a.tip_blue_work {
        moved.push(format!("tip blue_work {:?} -> {:?}", b.tip_blue_work, a.tip_blue_work));
    }
    if b.uns_root != a.uns_root {
        moved.push(format!("unspent_note_root {} -> {}", hex_d4(&b.uns_root), hex_d4(&a.uns_root)));
    }
    if b.uns_leaf_count != a.uns_leaf_count {
        moved.push(format!("unspent leaves {} -> {}", b.uns_leaf_count, a.uns_leaf_count));
    }
    if b.uns_leaf_fold != a.uns_leaf_fold {
        moved.push("the unspent membership fold".to_string());
    }
    if b.nf_root != a.nf_root {
        moved.push("nullifier_root".to_string());
    }
    if b.nf_count != a.nf_count {
        moved.push(format!("nullifier_count {} -> {}", b.nf_count, a.nf_count));
    }
    if b.nf_acc != a.nf_acc {
        moved.push("nf_unspent_acc".to_string());
    }
    if b.membership_tip != a.membership_tip {
        moved.push("membership_tip".to_string());
    }
    if b.spend_frontier_count != a.spend_frontier_count {
        moved.push(format!(
            "spend_frontier_count {} -> {}",
            b.spend_frontier_count, a.spend_frontier_count
        ));
    }
    if b.record_ordinal_top != a.record_ordinal_top {
        moved.push(format!("da_record_ordinal_top {} -> {}", b.record_ordinal_top, a.record_ordinal_top));
    }
    if b.store_entries_total != a.store_entries_total {
        // The generic reporter names every field it knows; an unnamed one produces the "Sample gained
        // a field and `describe_delta` was not extended" shrug, which is how a real finding turns into
        // a message nobody can act on.
        moved.push(format!(
            "held store entries {} -> {}",
            b.store_entries_total, a.store_entries_total
        ));
    }
    if b.dag_len != a.dag_len {
        moved.push(format!("dag_len {} -> {}", b.dag_len, a.dag_len));
    }
    if b.spine_len != a.spine_len {
        moved.push(format!("selected spine {} -> {}", b.spine_len, a.spine_len));
    }
    if b.spine_ordinal_inversions != a.spine_ordinal_inversions {
        moved.push("the spine's ordinal ordering".to_string());
    }
    if moved.is_empty() {
        // The tuple compared unequal but no named field moved — the comparison and the description have
        // drifted apart. Say so loudly rather than reporting an empty reason.
        return "the state tuple changed in a field this reporter does not name — `Sample` gained a \
                field and `describe_delta` was not extended"
            .to_string();
    }
    format!("a refused adversarial action moved: {}", moved.join(", "))
}

/// Eight bytes of a PUBLIC on-chain note commitment, in a harness report that never leaves the
/// developer's machine. Never a key, an amount, an address or an owner.
fn hex16(cm: &[u8; 32]) -> String {
    let mut s = String::new();
    for b in cm.iter().take(8) {
        s = format!("{s}{b:02x}");
    }
    s
}

fn hex_d4(d: &crate::spend_frontier::Digest4) -> String {
    format!("{:016x}{:016x}", d[0], d[1])
}
