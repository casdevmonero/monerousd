// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ FOLD-NOT-HOLD ABSENCE INTAKE (brick C3) — THE WALLET HALF OF THE SOLE SPEND AUTHORITY.
//!
//! ⛔⛔⛔ DB-284 (2026-09-27) — THIS MODULE IS NO LONGER ON THE MONEY PATH. What follows was written when the
//! recursive carrier was the node's sole spend authority. Since DB-217 the gate's authority is a live-root copath per
//! padded tag, and it says so: *"The recursive carrier is not an authority (DB-213c)"*. A wallet spend now carries the
//! node-built shape (the base-state witness plus the submit node's copaths; `fetch_spend_copaths` /
//! `base_state_absence_hex` in lib.rs), so no send waits on a fold here. MEASURED before: a fresh process's first send
//! refused 51 of 51 in 600 s waiting on this carrier. What this module still produces is DISPLAY: `authority` feeds the
//! balance's Ready/Settled, and `settled_within` feeds DB-273's change allocation. Since 2026-10-30 the follower VERIFIES
//! each note's span with the chain's own pure-Poseidon accumulator rule instead of proving it (a proof per owned note per
//! block, read by no one, made a mining wallet unusable); `witness`/`witness_at_tip` were deleted with the prover — they had no
//! caller on the send path.
//!
//! ## What this closes
//!
//! The node's spend gate says it in as many words: *"the recursive carrier is the SOLE spend authority
//! (the node holds no tree to answer from), so nothing can settle without it"*. Until this module the
//! wallet built NONE — `spend_one_note_to` shipped `nullifier_absence_hex: ""` — so **every
//! wallet-originated spend was refused at the door**, and the balance read 0.00 for the same reason seen
//! from the display side: spendability was asked of `/get_nf_copath`, a lane that cannot answer.
//!
//! DB-153 settles which lane is real: *"the chain's only committed nullifier state is the fold"*, so a
//! Merkle non-membership copath has nothing in consensus to verify against and *"a wallet folding a served
//! copath is trusting one node's local view, by construction"* — which the trustless pillar forbids. The
//! kill list's end 1 is therefore the direction: **the wallet takes spend authority from the A_tip absence
//! lane, the only committed thing.** This module is that lane on the wallet side.
//!
//! ## The contract this change carries
//!
//! ROOT-LAYER: the value being produced here is SPEND AUTHORITY, and the node states where it is produced:
//! *"the recursive carrier is the SOLE spend authority (the node holds no tree to answer from)"*. The
//! producer of that value for a wallet-originated spend is the WALLET — nobody else can build it without
//! becoming a witness server, which the trustless pillar forbids. Patching where the value is READ (the
//! balance filter, or the node's `/get_nf_copath` serve) is exactly the cheap fix that has been tried and
//! refuted three times: the copath lane has nothing in consensus to verify against (DB-153 — *"the chain's
//! only committed nullifier state is the fold"*), so every read-side repair produces a confident wrong
//! answer. This module builds the value at its producer.
//!
//! MEASURED: ecosystem gate run 8yFZ28, before → the wallet's own detect found `1 owned total,
//! 2500000000 atomic spendable` and the balance summary immediately answered `0 owned, 0 atomic
//! spendable` in the same process, 3 invocations running; the gate failed with `balance never reached
//! 25.0 spendable on :47791 (last: 0.0)`; and 0 wallet spends could be admitted at all, because
//! `spend_one_note_to` shipped `nullifier_absence_hex: ""`, which the door answers with `[nf-gate]
//! REJECT: N input(s) carried NO absence proof`. After → the carrier is built and attached, so the
//! authority question is answered by the lane that decides it.
//!
//! MUST-STAY-GREEN: `rpc_http::pool_without_gossip_tests::*` (the faucet credit reaching a second node),
//! `chain_action_manifest_tests::no_handler_performs_a_consensus_transition_without_publishing_it`, both
//! `consensus_corpus` replays, `icp_order_book_half` / `icp_peg_ratio_census`, and every wallet test that
//! does not touch this lane — this module ADDS a producer and removes no check anywhere.
//!
//! ## The shape
//!
//! `build_fold_absence_carry` (lib.rs) already knew how to fold — but it folded on the **send path**,
//! which is the time growth the owner banned outright: *"No blockchain has sends that take longer as the
//! chain grows."* Measured at 42–96 ms/block, 1.2–2.9 s of a ~4 s send. It was left with ZERO callers
//! rather than fixed, which is why no wallet spend carried a carrier at all.
//!
//! Here the carrier is maintained by the same stream-following loop the wallet already runs to find its
//! notes: each block the node serves is stepped into every watched carrier as it arrives, so the carrier
//! stands on the live tip and a send attaches it with one `finalize()`.
//!
//! **Where it starts is the chain's answer, not this wallet's, and the distance is a protocol constant.**
//! A carrier is rooted at the node's CERTIFIED FOLD BASE (`/get_nf_fold_inputs` → `base_acc`), which now
//! advances as each block crosses `Dag::horizon_blue_score` — a pure function of the DAG that every node
//! derives identically, and the same boundary the block window is cut at. So the span this follower folds
//! is exactly the window: at most `keep_depth` blocks (`2*merge_depth_cap + daa_sample_len +
//! DAG_PRUNE_KEEP_MARGIN`, all protocol constants), with no term in chain age. `span_len` is served beside
//! it so the distance is MEASURED rather than assumed.
//!
//! The fold is COMMUTATIVE (`nf_unspent_step_new_acc` is a wrapping sum of domain-separated Poseidon
//! leaves), so `A_tip == base ⊕ window` holds whatever order the window's blocks arrived in — which is
//! what makes the span reproducible without replaying an order nobody records.
//!
//! O1-INFINITY-REVIEWED: per block, per watched note, one `step()` over the FIXED
//! `TX_FIXED_NULLIFIER_COUNT` cover width. Retained state is `watched · width` digests plus one
//! constant-size WHIR proof each. No term in chain height, spent-set total or peer count.
//!
//! ## Nothing is written down
//!
//! The carrier is RECONSTRUCTED FROM THE REPLICATED STREAM, never read back from a file this wallet wrote.
//! That is the class-J rule and the right shape here regardless: the DA is the ledger, and a carrier
//! resumed from local bytes would be local-storage authority sitting on the money path.
//! ([[feedback_no_growth_any_axis]])
//!
//! ## Trustless
//!
//! Self-built from the replicated block stream any node serves — `/get_nf_fold_inputs` is a CONSTANT
//! broadcast, never a by-nullifier query, so there is no which-item handout. The serving node is never
//! trusted: the fold either reaches the node's published A_tip or the carrier is not used, and the node
//! re-verifies the finished proof against its own accumulator. A lying node can only make its own user's
//! send fail closed, never forge one. No witness server, no set only one party holds.
//! ([[feedback_always_trustless]])
//!
//! ## Privacy
//!
//! The batched set is the constant-width cover in which the real spend is indistinguishable from this
//! wallet's own secret-seeded decoys, and it is held in this process only. Every diagnostic below emits
//! block counts and branch names — never a tag, amount, key, owner or ordering.
//! ([[feedback_digital_cash_pillar]])

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[cfg(test)]
use usdm_decider::nf_sparse_air::NfAbsenceBatchCarrier;
use usdmd_node::spend_frontier::Digest4;

/// How many blocks one `/get_nf_fold_inputs` request asks for. A PAGE SIZE, not a stopping point — the
/// follower consumes pages while the node hands them back. A fixed protocol-shaped constant.
const FOLD_PAGE: u64 = 64;

/// One owned nullifier's maintained carrier.
struct Maintained {
    /// The tx's CONSTANT-WIDTH settled tag set — the real spend plus this wallet's own decoys. The gate
    /// demands absence for every settled tag, so the carrier is batched over the whole width.
    padded: Vec<[u8; 32]>,
    nf_limbs: Vec<Digest4>,
    /// The chain's certified fold base this carrier is rooted at. The node accepts a proof rooted at
    /// genesis or at its own certified jump base and nothing else, so this is READ from the node, never
    /// chosen here. `(zero, 0)` until the first page names it (`based`).
    base: (Digest4, u64),
    based: bool,
    /// ⭐ THE ACCUMULATOR this note's folded blocks reach from `base` — VERIFIED, never proven (2026-10-30). Each block
    /// steps it by the chain's own pure-Poseidon rule (`nf_unspent_step_new_acc` over the block's tag digest), and a
    /// block holding one of `nf_limbs` marks the note settled — the exact verdicts the recursive carrier gave, which
    /// were proofs nobody read: since DB-284 this module feeds only the balance display, and a proof per owned note per
    /// block made a mining wallet (one reward note per block) spend whole cores proving (MEASURED: 951 reward notes,
    /// `nf_carrier::follow_once` a full thread, the balance summary 470 s). Same trust: both compare the same served
    /// span against the same served A_tip.
    acc: Digest4,
    /// WHICH blocks of the span this carrier has folded, by block id — never a position.
    ///
    /// ⛔ A POSITION CANNOT WORK HERE. The span is the block window plus the in-flight set, and both
    /// shift as blocks age out and the base absorbs them, so an offset silently renames which block it
    /// points at. The fold is COMMUTATIVE, so order is irrelevant and identity is the only thing that
    /// matters: fold each block exactly once, in whatever order it is served. Bounded by the span.
    ///
    /// ⭐ SHARED, NEVER COPIED PER NOTE (user 2026-11-22: "why does my wallet keep crashing automatically when i leave it
    /// running? i need you to fix the root cause"). MEASURED (~/.monerousd-walletwatch, the installed 0.3.3 wallet against the
    /// live origin): 6,100 owned notes (6,096 SAT mining rewards, one a block) each rooted their own carrier over a 12,189-block
    /// span — 6,100 identical sets of 12,189 block ids — and the process went 90 MB → 8,830 MB in three minutes; the memory
    /// guards then killed it. The fold depends only on the base and the blocks (`nf_unspent_step_new_acc(acc, pre, td)`), so
    /// every carrier with the same base and the same blocks holds the SAME set and the SAME accumulator: they share one `Arc`
    /// here, and `apply_page` folds each distinct set once. Memory: one span per distinct set (in practice one or two) plus a
    /// small record per note, never notes × span. SAFE AT SCALE: a node's reward notes grow with the chain; this term no longer does.
    folded: Arc<BTreeSet<[u8; 32]>>,
    /// A `step()` refused: some member of this set settled on chain. Fail-closed and STICKY — the carrier
    /// is never silently re-rooted around a settled member, because that is precisely how a batch would
    /// hide one member's double spend.
    settled: bool,
    /// Whether this carrier stands on the node's published A_tip, i.e. whether a send may attach it.
    caught_up: bool,
    /// ⭐ DB-246 — the TIP ANTICHAIN of the page this carrier stands on the tip of (`tips_hex`, served under
    /// the same lock as that page's `a_tip`). A carrier caught up on that page folded exactly `closure(tips)`
    /// above the base, so these ids let ANY node that holds them derive the exact gap to its own live A_tip
    /// and admit a witness a few blocks old. Empty = the exact-live rule only (a node that serves no tips).
    tips: Vec<[u8; 32]>,
    /// ⭐ DB-252 — the PUBLIC `tip_blue_score` of the page this carrier stands on the tip of (`None` when the node
    /// serves none). The follower's next ask is keyed by the quantum it falls in, never by this exact value.
    stood_score: Option<u64>,
}

/// What the wallet can say about one owned nullifier's spend authority RIGHT NOW.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    /// The carrier stands on the chain's tip: this note can be spent now.
    Ready,
    /// The carrier is still following the stream. `blocks_behind` is a LIVENESS figure, never a verdict on
    /// the note, which is untouched and stays spendable at any depth.
    Building { blocks_behind: u64 },
    /// A member of this note's settled set is spent on chain. The note cannot be spent again.
    Settled,
    /// This wallet is not maintaining a carrier for that nullifier (it has not been watched yet).
    NotWatched,
}

static CARRIERS: Mutex<BTreeMap<[u8; 32], Maintained>> = Mutex::new(BTreeMap::new());
static FOLLOWER_RUNNING: AtomicBool = AtomicBool::new(false);
/// Follower passes COMPLETED since the process started — the clock `settled_within` waits on. A pass is
/// one page read + one fold of every watched carrier; progress is counted in passes, never in seconds.
static PASSES: AtomicU64 = AtomicU64::new(0);
/// How many blocks stand between the certified base and the tip, as of the last page — the liveness signal
/// behind `Building`, so the UI can say "still following" instead of "unspendable". It is the block
/// window's length: chain-shape only, bounded by `keep_depth`, and already public.
static SPAN_LEN: AtomicU64 = AtomicU64::new(0);

/// ⭐⭐ THE PUBLISHED VIEW — readers never queue behind the fold (the performance cardinal: an immutable published
/// snapshot, not the writer's mutex).
///
/// The follower applies a page while holding [`CARRIERS`], and a FRESH carrier's first page folds its whole span, so
/// every `authority()` read (the balance mask, the send's own balance poll) used to wait on that lock for the fold.
/// Readers now read THIS small map (one verdict per watched nullifier, published by the follower after each page and
/// by `watch` at once), and `watch` queues new carriers in [`PENDING_WATCH`] for the follower to take in. Neither
/// ever touches [`CARRIERS`].
/// ROOT-LAYER: the lock is held by the producer (the follower's fold); the readers are moved off it, and the fold
/// itself is unchanged (it still folds exactly what it folded, under its own lock).
/// MEASURED: before → a real pair ([probe279], run279/send_w3.log.stderr, 2026-09-27 11:17–11:19): "[carrier] rooted
/// … 163 block(s) of span to fold", then "standing … after 163 folded block(s)" 119 s later; the payer's send took
/// 119,755 ms, of which the detection pass inside it took 119,021 ms against 66 ms for the same pass a moment
/// earlier. After → the pin `a_reader_is_never_blocked_by_a_fold_in_progress` (this round) and the probe re-run.
/// MUST-STAY-GREEN: every carrier pin (the fold, re-root, DB-246 tips, DB-252 cursor) — `apply_page` is unchanged;
/// `authority` returns exactly what it returned for a carrier the follower has applied a page to.
/// O1-FOOTPRINT-REVIEWED: one `Authority` (≤ 16 B) per watched nullifier, the same key set as [`CARRIERS`].
static VIEW: Mutex<BTreeMap<[u8; 32], Authority>> = Mutex::new(BTreeMap::new());

/// Carriers `watch` asked for that the follower has not taken in yet (it drains this at the start of each pass).
static PENDING_WATCH: Mutex<Vec<([u8; 32], Vec<[u8; 32]>)>> = Mutex::new(Vec::new());

/// The authority one maintained carrier states — the one rule `publish_view` applies.
fn authority_of(m: &Maintained) -> Authority {
    if m.settled {
        return Authority::Settled;
    }
    if m.caught_up {
        return Authority::Ready;
    }
    Authority::Building {
        blocks_behind: SPAN_LEN
            .load(Ordering::Relaxed)
            .saturating_sub(m.folded.len() as u64),
    }
}

/// Publish every held carrier's authority into [`VIEW`] (the follower calls this with [`CARRIERS`] held, after a page).
/// Only held carriers are written, so a `watch` that arrived during the fold keeps its `Building` entry.
fn publish_view(held: &BTreeMap<[u8; 32], Maintained>) {
    let mut v = VIEW.lock().unwrap_or_else(|e| e.into_inner());
    for (nf, m) in held {
        v.insert(*nf, authority_of(m));
    }
}

/// Queue `nf` for maintenance and publish it as `Building` at once, without touching [`CARRIERS`]. Idempotent:
/// `false` when the nullifier is already watched (published or queued).
fn enqueue_watch(nf: [u8; 32], padded: Vec<[u8; 32]>) -> bool {
    {
        let mut v = VIEW.lock().unwrap_or_else(|e| e.into_inner());
        if v.contains_key(&nf) {
            return false;
        }
        v.insert(nf, Authority::Building { blocks_behind: SPAN_LEN.load(Ordering::Relaxed) });
    }
    PENDING_WATCH.lock().unwrap_or_else(|e| e.into_inner()).push((nf, padded));
    true
}

/// ⭐ REGISTER an owned nullifier for maintenance. Idempotent, cheap, and safe to call on every scan: the
/// follower does the folding, not this call. `padded` is the tx's constant-width settled set, derived by
/// the caller from the note's own key material (never from the nullifier, which is public once spent).
///
/// A note becomes spendable the moment its carrier stands on the tip, so watching at FIRST SIGHTING is
/// what makes the balance readable — not watching at send time, which puts the fold back on the money path.
pub fn watch(nf: [u8; 32], padded: Vec<[u8; 32]>) {
    if padded.is_empty() || padded[0] != nf {
        // Fail-closed: the real spend must be the set's FIRST member, which is what `aligned_padded_tags`
        // builds and what the submit door re-derives. A set that does not start with it would carry a
        // proof bound to a claim this wallet is not making.
        return;
    }
    // ⭐ THE FOLLOWER IS STARTED BY THE FIRST THING THAT NEEDS IT, not by whichever entry point remembered.
    // The app, the e2e harness and a test all reach spend authority through `watch`, so starting here is
    // the one rule that covers every one of them — the same reasoning that moved the node's own start out
    // of `ensure_node`'s lazy path. Idempotent.
    spawn(crate::node_url);
    // Published as `Building` at once and queued for the follower: never waits on a fold in progress (see [`VIEW`]).
    enqueue_watch(nf, padded);
}

/// A fresh, unrooted carrier for one constant-width settled set — rooted by the first page that names a base.
fn maintained_for(padded: Vec<[u8; 32]>) -> Maintained {
    let nf_limbs: Vec<Digest4> = padded
        .iter()
        .map(usdm_decider::nf_sparse_air::nf_to_limbs)
        .collect();
    Maintained {
        padded,
        nf_limbs,
        base: (usdmd_node::spend_frontier::empty_leaf(), 0),
        based: false,
        acc: usdmd_node::spend_frontier::empty_leaf(),
        folded: Arc::new(BTreeSet::new()),
        settled: false,
        caught_up: false,
        tips: Vec::new(),
        stood_score: None,
    }
}

/// How many nullifiers this wallet is maintaining a carrier for — the AUDIT hook. Retained cost is
/// `watched · width`, with no term in chain height.
pub fn watched() -> usize {
    // The count reads the published view, not the fold's lock: every watched nullifier has a VIEW entry from the
    // moment `watch` returns, queued or folded.
    // ROOT-LAYER: the view is the published side of the one producer (the follower); this only counts it.
    // MEASURED: before → a reader behind a 163-block fold waited 119,021 ms ([probe279]); after → the reader pin.
    // MUST-STAY-GREEN: the audit hook's count (one per watched nullifier, as before).
    VIEW.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// The follower's pass cadence when it stands on the tip (the sleep in [`spawn`]'s loop).
const PASS_SLEEP_MS: u64 = 250;
/// The follower's own worst-case pass: one `/get_nf_fold_inputs` read (its agent's 20 s timeout) plus the
/// sleep. Only the dead-follower failsafe in [`settled_within`] reads it.
const WORST_PASS_MS: u64 = 20_000 + PASS_SLEEP_MS;

/// ⭐ DB-273 (D) — WHETHER `nf` SETTLES ON CHAIN WITHIN `passes` COMPLETED FOLLOWER PASSES: the carrier folds
/// the block that spends it and reports [`Authority::Settled`]. The send path asks this about its PREVIOUS
/// accepted spend's input before taking a new dense change index. `false` means "not observed settled yet" (still
/// in flight, or dropped) — never a guess either way. Counted in follower passes, with the same
/// wall-clock failsafe only for a follower thread that has died.
pub fn settled_within(nf: &[u8; 32], passes: u64) -> bool {
    let start = PASSES.load(Ordering::SeqCst);
    let failsafe =
        std::time::Instant::now() + std::time::Duration::from_millis(passes.saturating_mul(WORST_PASS_MS));
    loop {
        if authority(nf) == Authority::Settled {
            return true;
        }
        if PASSES.load(Ordering::SeqCst) >= start.saturating_add(passes) || std::time::Instant::now() >= failsafe {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
}

/// ⭐ SPENDABILITY WITHOUT THE COPATH LANE. The question the wallet actually needs answered — "may I spend
/// this note?" — asked of the authority that decides it, instead of `/get_nf_copath`, which by DB-153
/// cannot answer on a live chain and whose refusal surfaced to the user as a 0.00 balance.
/// Read from the published [`VIEW`], never from [`CARRIERS`]: a fold in progress cannot make this wait.
/// ROOT-LAYER: the verdict is produced by the follower (`publish_view`, with `authority_of` — the rule this function
/// applied inline before); this is only its reader, moved off the fold's lock.
/// MEASURED: before → 119,021 ms for one detection pass behind a fold ([probe279]); after → the reader pin.
/// MUST-STAY-GREEN: the same verdict for every carrier the follower has applied a page to; NotWatched otherwise.
pub fn authority(nf: &[u8; 32]) -> Authority {
    match VIEW.lock().unwrap_or_else(|e| e.into_inner()).get(nf) {
        Some(a) => *a,
        None => Authority::NotWatched,
    }
}

/// Decode a served limb array into this chain's digest. A served value that is not EXACTLY the digest's
/// own lane count is not this chain's, and is refused rather than reduced into range.
///
/// ⛔ THE LITERAL `4` WAS WRONG AND IT MADE EVERY CALLER DEAD. `Digest4` is a NAME, not a width: it is
/// `poseidon2_compress::Digest`, which is `[u64; DIGEST_LANES]` with `DIGEST_LANES == 8`. The wallet's
/// existing decoders test `arr.len() != 4` against an 8-limb serve, so they return `None` unconditionally —
/// which is why `fetch_fold_base` reported "no certified fold base served yet" on a chain that serves one
/// every time. Comparing against the array we are about to fill cannot drift again.
fn served_limbs(v: Option<&serde_json::Value>) -> Option<Digest4> {
    let arr = v?.as_array()?;
    let mut out = usdmd_node::spend_frontier::empty_leaf();
    if arr.len() != out.len() {
        return None;
    }
    for (i, limb) in out.iter_mut().enumerate() {
        *limb = arr[i].as_u64()?;
    }
    Some(out)
}

/// ONE follow pass: take the span the node serves and step every watched carrier over the blocks it has
/// not folded yet. Returns `true` if any carrier advanced — the caller sleeps when it did not.
///
/// The span is consumed by EVERY carrier from ONE read, so N watched notes cost one request, not N.
pub fn follow_once(agent: &ureq::Agent, node_url: &str) -> bool {
    {
        // Take in the carriers `watch` queued (see [`VIEW`]); the follower is the one writer of CARRIERS.
        // ROOT-LAYER: the follower is the producer of carrier state, so it alone moves a queued watch into it.
        // MEASURED: before → `watch` took the CARRIERS lock and waited out a 119 s fold ([probe279]); after → the
        // reader pin this round. MUST-STAY-GREEN: a watched carrier is folded from the next pass, as before.
        let queued = std::mem::take(&mut *PENDING_WATCH.lock().unwrap_or_else(|e| e.into_inner()));
        if !queued.is_empty() {
            let mut held = CARRIERS.lock().unwrap_or_else(|e| e.into_inner());
            for (nf, padded) in queued {
                held.entry(nf).or_insert_with(|| maintained_for(padded));
            }
        }
    }
    {
        // Nothing watched ⇒ nothing to do. Never take a span no carrier will consume.
        let held = CARRIERS.lock().unwrap_or_else(|e| e.into_inner());
        if held.values().all(|m| m.settled) {
            return false;
        }
    }
    // ⭐ DB-252 — ASK ONLY FOR WHAT IS NEW, KEYED BY PUBLIC TIME. When every carrier still being maintained
    // stands on a page, ask for the span blocks scored above the start of the PREVIOUS blue-score quantum of the
    // oldest stand: every follower that stood during the same quantum sends the same number, so the ask reveals
    // no more than its arrival time (a tips cursor would chain one follower's polls into a session — refuted
    // 06:39). Any other state (a carrier just watched, one re-rooting, one behind) asks for the whole span.
    // MEASURED 2026-09-26 (runSEND246): the whole-span page grew 2.57 -> 7.34 MB over 137 s (~16 KB/block) and
    // passes ran 30-63 s apart under load, so a witness was 63 of the ring's 64 blocks old at submit.
    // cons: none — a node that does not know the field serves the whole span, and the carrier still stands
    // only when its own sum equals the served `a_tip`, so a page missing a late low-score block leaves it
    // un-ready and the next pass asks for the whole span (self-correcting, fail-closed).
    let above: Option<u64> = above_blue_score(&CARRIERS.lock().unwrap_or_else(|e| e.into_inner()));
    let mut ask = serde_json::json!({ "from": 0, "count": 16_384 });
    if let Some(b) = above {
        ask["above_blue_score"] = serde_json::json!(b);
    }
    let page: serde_json::Value = match agent
        .post(&format!("{node_url}/get_nf_fold_inputs"))
        .send_json(ask)
        .and_then(|r| r.into_json::<serde_json::Value>().map_err(|e| e.into()))
    {
        Ok(v) => v,
        Err(_) => return false, // the node is unreachable; every carrier is untouched and retries.
    };
    SPAN_LEN.store(
        page.get("span_len").and_then(|v| v.as_u64()).unwrap_or(0),
        Ordering::Relaxed,
    );
    let mut held = CARRIERS.lock().unwrap_or_else(|e| e.into_inner());
    let advanced = apply_page(&mut held, &page);
    publish_view(&held);
    advanced
}

/// DB-252: the blue-score cursor to ask ABOVE — the start of the previous [`NF_RECENT_BLOCKS`]-wide quantum of
/// the OLDEST page an unsettled carrier stands on, or `None` (ask for the whole span) when any unsettled carrier
/// is not standing, or the served score is unknown, or the chain is younger than two quanta. The quantum is
/// DB-246's own ring span, so the page cursor and the gate's recent window are ONE constant and cannot drift.
fn above_blue_score(held: &BTreeMap<[u8; 32], Maintained>) -> Option<u64> {
    let q = usdmd_node::nf_sparse::NF_RECENT_BLOCKS as u64;
    let mut oldest: Option<u64> = None;
    for m in held.values().filter(|m| !m.settled) {
        if !m.caught_up {
            return None;
        }
        let s = m.stood_score?;
        oldest = Some(oldest.map_or(s, |o| o.min(s)));
    }
    (oldest? / q).checked_sub(1).map(|prev| prev * q)
}

/// Apply ONE served page to every maintained carrier: re-root on a base change, fold each block not yet
/// folded (by id), and decide readiness against the `a_tip` served WITH the span. Pure over its inputs —
/// no network, no global — so a pin can drive it with a page it built. Returns `true` if any carrier folded.
fn apply_page(held: &mut BTreeMap<[u8; 32], Maintained>, page: &serde_json::Value) -> bool {
    let Some(base) =
        served_limbs(page.get("base_acc")).zip(page.get("base_seq").and_then(|v| v.as_u64()))
    else {
        return false;
    };
    let a_tip = served_limbs(page.get("a_tip"));
    // DB-252: the page's PUBLIC selected-tip blue score (JSON null when the node has none to serve).
    let tip_blue_score: Option<u64> = page.get("tip_blue_score").and_then(|v| v.as_u64());
    // ⭐ DB-246 — the span's TIP ANTICHAIN, taken by the node under the same lock as `a_tip`. Strict like the
    // span entries below: an id that is not exactly 32 bytes refuses the WHOLE page, because a carrier must
    // never carry a coordinate it could not have folded. A node that serves no `tips_hex` (pre-DB-246) is
    // answered by the exact-live rule alone, which is what an empty list asks for.
    let mut tips: Vec<[u8; 32]> = Vec::new();
    if let Some(v) = page.get("tips_hex") {
        let Some(arr) = v.as_array() else {
            return false;
        };
        for t in arr {
            let Some(id) = t
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
            else {
                return false;
            };
            tips.push(id);
        }
    }

    // Parse the span ONCE: `(block id, block_pre, tags)` per entry. A malformed entry is refused rather
    // than skipped — a span with a hole cannot reach A_tip, and folding it anyway would leave a carrier
    // that looks advanced and can never be finalized.
    let mut span: Vec<([u8; 32], Digest4, Vec<[u8; 32]>)> = Vec::new();
    for b in page
        .get("blocks")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
    {
        let Some(id) = b
            .get("id_hex")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|v| <[u8; 32]>::try_from(v.as_slice()).ok())
        else {
            return false;
        };
        let Some(pre) = served_limbs(b.get("block_pre")) else {
            return false;
        };
        let Some(raw) = b
            .get("tags_hex")
            .and_then(|v| v.as_str())
            .and_then(|h| hex::decode(h).ok())
        else {
            return false;
        };
        if raw.len() % 32 != 0 {
            return false;
        }
        span.push((
            id,
            pre,
            raw.chunks_exact(32)
                .map(|c| {
                    let mut t = [0u8; 32];
                    t.copy_from_slice(c);
                    t
                })
                .collect(),
        ));
    }

    // ⭐ ONE PASS OVER EACH BLOCK, SHARED BY EVERY NOTE: its tags' limbs (the set a member is looked up in) and its tag digest
    // (the accumulator's step input) are computed once per block, never once per note per block — a mining wallet watches
    // one note per reward, and per-note hashing of every block tag kept the follower on a full core (MEASURED: 470 notes).
    // ⭐ AND ONCE PER BLOCK ACROSS PASSES (lane stable 2026-11-01, chain speed — what a sender waits for). A pass whose
    // carriers are not all standing asks the WHOLE span (≥ `NF_RECENT_BLOCKS` = 64 blocks, 256 tags each), and every block's
    // limbs and fold digest were recomputed every pass: the decider's content memo holds two generations of 32, so a cyclic
    // walk over a longer span missed on every lookup.
    // ROOT-LAYER: this is the one producer of each block's folded inputs for every carrier the follower maintains; the
    // memo below it is shared with the node and is not where a wallet's per-pass repetition can be removed.
    // MEASURED: 2,139 of the send's 4,012 main-thread samples were `follow_once`, 1,247 of them in the memo's compute path
    // (stable/wsample/53893.txt, the wallet process of the post-adopt journey's send); after: the next journey's sample.
    // MUST-STAY-GREEN: identical inputs in identical order (a carrier's sum must equal the served A_tip); the wallet's
    // nf_carrier and spend pins; the post-adopt journey's sends.
    // The inputs are a function of the block's served `(pre, tags)`, so they are kept by `(id, pre, blake3(tags))` — a
    // re-served block with any other pre or tag bytes misses and is recomputed — for exactly the blocks of the CURRENT page
    // (rebuilt from it each pass: bounded by the span, never by height), and the misses are computed in parallel (each
    // block's inputs are independent). cons: one blake3 of a block's tag bytes per pass (≈ 8 KB, microseconds) and ≤ one
    // span of cached sets in RAM.
    let folded_inputs: Vec<(std::collections::HashSet<Digest4>, Digest4)> = {
        use rayon::prelude::*;
        type Key = ([u8; 32], Digest4, [u8; 32]);
        static INPUTS: Mutex<Vec<(Key, (std::collections::HashSet<Digest4>, Digest4))>> = Mutex::new(Vec::new());
        let keys: Vec<Key> = span
            .iter()
            .map(|(id, pre, tags)| {
                let mut h = blake3::Hasher::new();
                for t in tags {
                    h.update(t);
                }
                (*id, *pre, *h.finalize().as_bytes())
            })
            .collect();
        let prior = std::mem::take(&mut *INPUTS.lock().unwrap_or_else(|e| e.into_inner()));
        let held: std::collections::HashMap<Key, (std::collections::HashSet<Digest4>, Digest4)> = prior.into_iter().collect();
        let out: Vec<(std::collections::HashSet<Digest4>, Digest4)> = span
            .par_iter()
            .zip(keys.par_iter())
            .map(|((_, pre, tags), k)| match held.get(k) {
                Some(v) => v.clone(),
                None => {
                    let limbs = tags.iter().map(usdm_decider::nf_sparse_air::nf_to_limbs).collect();
                    (limbs, usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(tags, *pre))
                }
            })
            .collect();
        *INPUTS.lock().unwrap_or_else(|e| e.into_inner()) = keys.into_iter().zip(out.iter().cloned()).collect();
        out
    };
    let mut advanced = false;
    // one line per page, never one per note (6,100 notes printed 6,100 identical lines a page — MEASURED 2026-11-22)
    let (mut rerooted, mut restepped) = (0usize, 0usize);
    for m in held.values_mut() {
        if m.settled {
            continue;
        }
        // ⛔ A BASE CHANGE VOIDS THE FOLD. The carrier is a recursive proof ROOTED at the base, so when
        // the base steps (the chain's quantized horizon boundary moved, or this node DSYNC-adopted)
        // everything folded so far belongs to a statement that no longer starts where the gate checks.
        // Re-root and fold the new span — the node still accepts the PREVIOUS base meanwhile, which is
        // what keeps a note spendable while its carrier is rebuilt.
        if !m.based || m.base != base {
            if m.based {
                restepped += 1;
            } else {
                rerooted += 1;
            }
            m.base = base;
            m.based = true;
            m.folded = Arc::new(BTreeSet::new());
            m.caught_up = false;
            m.tips.clear();
            m.stood_score = None;
            m.acc = base.0;
        }
    }
    if rerooted + restepped > 0 {
        eprintln!(
            "[carrier] {} note(s) rooted at the node's certified base ({} block(s) already absorbed below the chain's \
             horizon boundary; {} block(s) of span to fold){}",
            rerooted + restepped,
            base.1,
            span.len(),
            if restepped > 0 { " — the base stepped, so the previous fold is re-rooted" } else { "" }
        ); // DIGITAL-CASH-PRIVACY-REVIEWED: block counts only; no tag, amount, key or owner.
    }
    // ⭐ ONE FOLD PER DISTINCT SET, SHARED BY ITS NOTES (see `Maintained::folded`). Carriers whose sets are the same `Arc`
    // (or all empty, at this base) folded exactly the same blocks, so they hold the same accumulator: the group's new blocks
    // are folded ONCE, and each block's tags are looked up in the group's member map, so finding which note a block spends
    // costs the block's tags, not notes × tags. Per note the rule is unchanged: a block holding one of a note's tags settles
    // it (sticky, fail-closed); every other note steps the shared accumulator and shares the shared set.
    {
        let mut groups: std::collections::HashMap<usize, Vec<[u8; 32]>> = std::collections::HashMap::new();
        for (nf, m) in held.iter() {
            if !m.settled {
                let key = if m.folded.is_empty() { 0 } else { Arc::as_ptr(&m.folded) as usize };
                groups.entry(key).or_default().push(*nf);
            }
        }
        for members in groups.into_values() {
            let first = &held[&members[0]];
            let (mut acc, mut set) = (first.acc, (*first.folded).clone());
            let mut by_limb: std::collections::HashMap<Digest4, Vec<[u8; 32]>> = std::collections::HashMap::new();
            for nf in &members {
                for l in &held[nf].nf_limbs {
                    by_limb.entry(*l).or_default().push(*nf);
                }
            }
            let mut spent: BTreeSet<[u8; 32]> = BTreeSet::new();
            let mut grew = false;
            for ((id, pre, _tags), (tag_limbs, td)) in span.iter().zip(folded_inputs.iter()) {
                if set.contains(id) {
                    continue; // already folded — identity, never position
                }
                // the chain's own rule, verified: a block holding a member settles that note; the accumulator steps
                // for every note this block does not settle (a settled note stops, as before, and is never re-rooted)
                for l in tag_limbs {
                    if let Some(hit) = by_limb.get(l) {
                        for nf in hit {
                            spent.insert(*nf);
                        }
                    }
                }
                acc = usdm_decider::nf_sparse_air::nf_unspent_step_new_acc(acc, *pre, *td);
                set.insert(*id);
                grew = true;
            }
            if grew {
                advanced = true;
            }
            if !spent.is_empty() {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a count only — never a tag, amount, key or owner.
                eprintln!(
                    "[carrier] {} note(s) have a member of their settled set spent on chain — refusing to prove otherwise; \
                     they report SPENT",
                    spent.len()
                );
            }
            let shared = Arc::new(set);
            for nf in &members {
                let m = held.get_mut(nf).expect("a member of its own group");
                if spent.contains(nf) {
                    m.settled = true;
                    m.caught_up = false;
                } else {
                    m.acc = acc;
                    m.folded = Arc::clone(&shared);
                }
            }
        }
    }
    let mut stood = (0usize, 0usize);
    for m in held.values_mut() {
        // Readiness is decided against the A_tip served WITH this span, so the comparison is at one
        // instant rather than racing the next block.
        //
        // ⛔ A ZERO-STEP CARRIER IS NEVER READY. `finalize()` on one returns `None`, so calling it ready
        // would make the send fail with no diagnostic at all — the exact silent boundary that cost
        // several runs to attribute.
        if !m.settled && !m.folded.is_empty() {
            let at_tip = a_tip.is_some_and(|t| t == m.acc);
            if at_tip && !m.caught_up {
                stood = (stood.0 + 1, m.folded.len());
            }
            m.caught_up = at_tip;
            if at_tip {
                // The tips of THIS page: the carrier folded exactly `closure(tips)` above the base.
                m.tips = tips.clone();
                m.stood_score = tip_blue_score;
            }
        }
    }
    if stood.0 > 0 {
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts only — never a tag, amount, key or owner.
        eprintln!("[carrier] {} note(s) standing on the chain tip after {} folded block(s) — they can be spent", stood.0, stood.1);
    }
    advanced
}

/// ⭐ START THE FOLLOWER. One background thread for the whole wallet: it follows the replicated fold
/// stream and steps every watched carrier, so the send path never folds anything. Idempotent.
///
/// It never blocks a UI call and never holds the carrier lock across a network read — the page is taken
/// first, then applied.
pub fn spawn(node_url: impl Fn() -> String + Send + 'static) {
    if FOLLOWER_RUNNING.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(move || {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(20))
            .build();
        loop {
            let url = node_url();
            let progressed = if url.is_empty() {
                false
            } else {
                follow_once(&agent, &url)
            };
            PASSES.fetch_add(1, Ordering::SeqCst);
            // Standing on the tip (or nothing watched) ⇒ poll at the block cadence. No clock ever decides
            // that a note is unspendable; this only paces the loop.
            if !progressed {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ PERFORMANCE CARDINAL — a reader is never blocked by a fold in progress. Another thread holds [`CARRIERS`]
    /// (what the follower does for a fresh carrier's whole first span: 119 s on a real pair, [probe279]); meanwhile a
    /// new watch is queued and published, `authority` answers `Building`, a repeat watch is idempotent, and the audit
    /// count answers — all within 500 ms. CALIBRATION: with the old readers (they took CARRIERS) each call would wait
    /// out the 1.5 s hold, so this bound fails on the pre-fix code.
    /// ROOT-LAYER: drives the real readers against the real lock the producer holds.
    /// MEASURED: before → 119,021 ms for a detection pass behind a fold ([probe279]); after → this pin's elapsed.
    /// MUST-STAY-GREEN: every other carrier pin (the fold path is unchanged).
    /// TWO-PARTY-REVIEWED: a concurrency property INSIDE one wallet process (its follower thread against its own
    /// readers); no boundary between parties is crossed. The cross-party half is the real-node payee A/B ([probe279]).
    #[test]
    fn a_reader_is_never_blocked_by_a_fold_in_progress() {
        let nf = [0xA7u8; 32];
        let padded = vec![nf, [0xA8u8; 32]];
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let _fold = CARRIERS.lock().unwrap_or_else(|e| e.into_inner());
            held_tx.send(()).expect("signal the hold");
            std::thread::sleep(std::time::Duration::from_millis(1_500));
        });
        held_rx.recv().expect("the fold holds the carriers now");
        let t = std::time::Instant::now();
        assert!(enqueue_watch(nf, padded.clone()), "a new watch is queued and published");
        assert!(matches!(authority(&nf), Authority::Building { .. }), "published as Building at once");
        assert!(!enqueue_watch(nf, padded), "a repeat watch is idempotent");
        assert!(watched() >= 1, "the audit count answers");
        let took = t.elapsed();
        assert!(took < std::time::Duration::from_millis(500), "readers took {took:?} while a fold held the carriers");
        holder.join().expect("the hold ends");
    }

    /// The follower TAKES IN a queued watch and PUBLISHES its verdict after a page: driven through `follow_once` against
    /// a scripted node whose page names no base (so nothing folds), the queued carrier enters [`CARRIERS`] and the
    /// view still reads `Building` — the reader never saw a gap between the queue and the fold.
    /// TWO-PARTY-REVIEWED: the follower and its own view inside ONE wallet; the scripted node only serves the page read.
    #[test]
    fn the_follower_takes_in_a_queued_watch_and_publishes_it() {
        let nf = [0xB3u8; 32];
        assert!(enqueue_watch(nf, vec![nf, [0xB4u8; 32]]), "queued");
        let (base, seen) = crate::db284_spend_evidence_tests::recorder(vec![(
            200,
            serde_json::json!({"status": "OK", "blocks": [], "span_len": 0}).to_string(),
        )]);
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(5)).build();
        let _ = follow_once(&agent, &base);
        assert!(CARRIERS.lock().unwrap_or_else(|e| e.into_inner()).contains_key(&nf), "the follower took it in");
        assert!(matches!(authority(&nf), Authority::Building { .. }), "and its published verdict is Building");
        assert_eq!(seen.lock().unwrap().len(), 1, "one page asked");
    }

    /// ⛔ THE REFUTATION THAT MATTERS: a wallet that has folded NOTHING must not claim spend authority.
    /// This is the shape that produced "sealing…" and then silence — `finalize()` on a zero-step carrier
    /// returns `None`, so a `Ready` verdict there surfaces as an unexplained send failure.
    #[test]
    fn a_carrier_that_has_folded_nothing_carries_no_authority_and_says_so() {
        let nf = [7u8; 32];
        let padded: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut t = nf;
                t[31] = i;
                t
            })
            .collect();
        let real = padded[0];
        watch(real, padded.clone());
        assert_ne!(
            authority(&real),
            Authority::Ready,
            "a carrier at its base has folded nothing — it must never claim to stand on the tip"
        );
        assert!(
            matches!(authority(&real), Authority::Building { .. }),
            "an unfolded carrier is BUILDING, never Ready and never a verdict that the note is spent"
        );
        // And a set whose first member is not the real spend is refused outright — proving absence for a
        // tag this wallet is not spending would bind the carrier to a claim it is not making.
        let bogus = [9u8; 32];
        watch(bogus, vec![[8u8; 32], bogus]);
        assert_eq!(
            authority(&bogus),
            Authority::NotWatched,
            "the real spend must be the settled set's first member, as the submit door re-derives it"
        );
    }

    /// ⭐⭐ DB-246 (wallet half) — THE WITNESS CARRIES THE TIP ANTICHAIN OF THE PAGE ITS CARRIER STANDS ON.
    ///
    /// The absence door admits a witness a few blocks old only by deriving the exact gap from `closure(tips)`
    /// to its own live A_tip; a witness with no tips can only ever match the live tip exactly, which a real
    /// send — seconds of proving — misses (MEASURED 2026-09-26, node 465d473d: 3 of 3 submits refused, "the
    /// carried absence proof ends at a tip that is NOT this node's live accumulator").
    /// RED before this change: `witness()` built `tips: Vec::new()` whatever the page served.
    /// Hermetic: a LOCAL carrier map and a page built here, folded for real (one batched step), no node and no
    /// global follower. Tamper arms: a malformed tip refuses the WHOLE page (nothing folds, nothing stands on
    /// the tip); a page from a node that serves no tips yields a witness with none — the exact-live rule,
    /// never an invented coordinate.
    #[test]
    fn db246_a_caught_up_carrier_carries_the_tip_antichain_of_the_page_it_stands_on() {
        let nf = [0x46u8; 32];
        let padded: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut t = nf;
                t[31] = i;
                t
            })
            .collect();
        let base = usdmd_node::spend_frontier::empty_leaf();
        let pre = usdm_decider::nf_sparse_air::nf_to_limbs(&[0xE1u8; 32]);
        let tags = usdmd_node::cover::nullifier_wire_fill(&[], &[0xB7u8; 32]);
        // The A_tip a carrier reaches by folding exactly this block, computed by an INDEPENDENT carrier.
        let mut probe = NfAbsenceBatchCarrier::new(maintained_for(padded.clone()).nf_limbs, base);
        assert!(probe.step(&tags, pre), "an honest block folds the whole width");
        let a_tip = probe.acc();
        let id = [0x77u8; 32];
        let limbs = |d: &Digest4| serde_json::Value::Array(d.iter().map(|v| serde_json::json!(v)).collect());
        let tags_hex: String = tags.iter().map(hex::encode).collect();
        let page = |tips: Option<serde_json::Value>| {
            let mut p = serde_json::json!({
                "status": "OK",
                "base_acc": limbs(&base),
                "base_seq": 0,
                "a_tip": limbs(&a_tip),
                "span_len": 1,
                "blocks": [ { "id_hex": hex::encode(id), "block_pre": limbs(&pre), "tags_hex": tags_hex.clone() } ],
            });
            if let Some(t) = tips {
                p["tips_hex"] = t;
            }
            p
        };
        let fresh = || {
            let mut m = BTreeMap::new();
            m.insert(nf, maintained_for(padded.clone()));
            m
        };

        let mut held = fresh();
        assert!(apply_page(&mut held, &page(Some(serde_json::json!([hex::encode(id)])))), "the page folds");
        assert_eq!(authority_of(&held[&nf]), Authority::Ready, "the carrier stands on the page's a_tip");
        assert_eq!(held[&nf].acc, a_tip, "its verified accumulator is the one the independent PROVING carrier reached");
        assert_eq!(held[&nf].tips, vec![id], "it carries the tips of the page it stands on");
        assert_eq!(held[&nf].base.0, base, "rooted at the base the page named");

        // TAMPER: a malformed tip refuses the WHOLE page.
        let mut held = fresh();
        assert!(!apply_page(&mut held, &page(Some(serde_json::json!(["abcd"])))));
        assert_ne!(authority_of(&held[&nf]), Authority::Ready, "a refused page stands no carrier on any tip");
        assert!(held[&nf].folded.is_empty(), "and folds nothing");

        // A node that serves no tips: the witness carries none.
        let mut held = fresh();
        assert!(apply_page(&mut held, &page(None)), "the page folds");
        assert_eq!(authority_of(&held[&nf]), Authority::Ready, "the carrier stands on the page's a_tip");
        assert!(held[&nf].tips.is_empty(), "no served tips ⇒ no carried tips (the exact-live rule)");
    }

    /// ⭐⭐ 2026-10-30 — A MINING WALLET FOLLOWS THE CHAIN WITHOUT PROVING: a thousand watched notes (a miner's reward notes)
    /// follow a four-block page in well under the time ONE proving carrier spends per block (MEASURED before: 951 reward notes
    /// kept `follow_once` on a full core and the balance summary at 470 s). Every note's verified accumulator equals the one
    /// an independent PROVING carrier reaches, so the verdicts are the prover's. TAMPER: a block that holds one note's real
    /// nullifier settles exactly that note and no other.
    /// TWO-PARTY-REVIEWED: pure local fold arithmetic over a page built here (the node's serve is pinned node-side).
    #[test]
    fn a_thousand_watched_notes_follow_a_page_without_proving_and_a_spent_member_settles_only_its_note() {
        let base = usdmd_node::spend_frontier::empty_leaf();
        let set = |i: u32| -> Vec<[u8; 32]> {
            (0..4u8)
                .map(|k| {
                    let mut t = [0u8; 32];
                    t[..4].copy_from_slice(&i.to_le_bytes());
                    t[31] = k;
                    t
                })
                .collect()
        };
        let blocks: Vec<([u8; 32], Digest4, Vec<[u8; 32]>)> = (0..4u8)
            .map(|b| ([0x90 | b; 32], usdm_decider::nf_sparse_air::nf_to_limbs(&[b ^ 0x5A; 32]), usdmd_node::cover::nullifier_wire_fill(&[], &[b; 32])))
            .collect();
        let mut probe = NfAbsenceBatchCarrier::new(maintained_for(set(0)).nf_limbs, base);
        for (_, pre, tags) in &blocks {
            assert!(probe.step(tags, *pre), "CALIBRATION: an honest block folds");
        }
        let a_tip = probe.acc();
        let ids: Vec<[u8; 32]> = blocks.iter().map(|b| b.0).collect();
        let mut held: BTreeMap<[u8; 32], Maintained> = BTreeMap::new();
        for i in 0..1_000u32 {
            let p = set(i);
            held.insert(p[0], maintained_for(p));
        }
        let t = std::time::Instant::now();
        assert!(apply_page(&mut held, &served_page(base, a_tip, &blocks, &ids, 7)), "the page folds");
        let ms = t.elapsed().as_millis();
        assert!(ms < 5_000, "⛔ a thousand watched notes took {ms} ms to follow four blocks — the follower is proving again");
        assert!(held.values().all(|m| m.acc == a_tip && authority_of(m) == Authority::Ready), "every note stands on the proving carrier's tip");
        // ⭐ THE ROOT-CAUSE PIN (2026-11-22, the wallet killed at 6,228 / 8,830 MB): notes folded from the same base share
        // ONE folded set. On the per-note code each carrier owned its own copy.
        let first = &held.values().next().expect("a held note").folded;
        assert!(
            held.values().all(|m| Arc::ptr_eq(&m.folded, first)),
            "⛔ the notes hold separate copies of one folded set — the per-note copy is back"
        );
        // TAMPER: a block that spends note 7's nullifier
        let spent = set(7)[2];
        let mut tags = blocks[0].2.clone();
        tags[0] = spent;
        let bad = vec![(blocks[0].0, blocks[0].1, tags)];
        let mut held: BTreeMap<[u8; 32], Maintained> = BTreeMap::new();
        for i in 0..16u32 {
            let p = set(i);
            held.insert(p[0], maintained_for(p));
        }
        let _ = apply_page(&mut held, &served_page(base, a_tip, &bad, &[bad[0].0], 7));
        for (k, m) in &held {
            if *k != set(7)[0] {
                assert_ne!(authority_of(m), Authority::Settled, "⛔ a note no block spent reads settled");
            }
        }
        assert_eq!(authority_of(&held[&set(7)[0]]), Authority::Settled, "⛔ a block holding note 7's nullifier did not settle it");
    }

    /// A served page, built the way `/get_nf_fold_inputs` serves one: `(id, block_pre, tags)` per block.
    fn served_page(
        base: Digest4,
        a_tip: Digest4,
        blocks: &[([u8; 32], Digest4, Vec<[u8; 32]>)],
        tips: &[[u8; 32]],
        tip_blue_score: u64,
    ) -> serde_json::Value {
        let limbs = |d: &Digest4| serde_json::Value::Array(d.iter().map(|v| serde_json::json!(v)).collect());
        serde_json::json!({
            "status": "OK",
            "base_acc": limbs(&base),
            "base_seq": 0,
            "a_tip": limbs(&a_tip),
            "span_len": blocks.len(),
            "tips_hex": tips.iter().map(hex::encode).collect::<Vec<_>>(),
            "tip_blue_score": tip_blue_score,
            "blocks": blocks
                .iter()
                .map(|(id, pre, tags)| serde_json::json!({
                    "id_hex": hex::encode(id),
                    "block_pre": limbs(pre),
                    "tags_hex": tags.iter().map(hex::encode).collect::<String>(),
                }))
                .collect::<Vec<_>>(),
        })
    }

    /// ⭐ DB-252 — THE FOLLOWER'S CURSOR IS A FUNCTION OF PUBLIC TIME, AND ONLY WHEN IT IS TRUE OF EVERY CARRIER.
    /// It is the start of the PREVIOUS 64-wide blue-score quantum of the OLDEST stand, so two followers that stood
    /// anywhere in one quantum send the same number (a tips cursor chained polls into a session — refuted 06:39);
    /// a carrier just watched, one behind, or an unknown score asks for the whole span; a settled carrier does not
    /// hold the others back; a chain younger than two quanta has no previous quantum and asks for the whole span.
    /// TWO-PARTY-REVIEWED: this pins ONE party's arithmetic (which cursor the wallet may send); the node that
    /// answers `above_blue_score` is pinned node-side by DB-252's own pins (lane-db224-carriage) and on a real pair.
    #[test]
    fn db252_the_follower_asks_above_a_public_quantum_only_when_every_carrier_stands() {
        let q = usdmd_node::nf_sparse::NF_RECENT_BLOCKS as u64;
        let set = |b: u8| -> Vec<[u8; 32]> {
            (0..4u8)
                .map(|i| {
                    let mut t = [b; 32];
                    t[31] = i;
                    t
                })
                .collect()
        };
        let standing = |b: u8, score: u64| {
            let mut m = maintained_for(set(b));
            m.caught_up = true;
            m.tips = vec![[b; 32]];
            m.stood_score = Some(score);
            m
        };
        let mut held: BTreeMap<[u8; 32], Maintained> = BTreeMap::new();
        assert_eq!(above_blue_score(&held), None, "nothing maintained ⇒ nothing to ask above");
        held.insert([0xA0; 32], standing(0xA0, 5 * q + 7));
        assert_eq!(above_blue_score(&held), Some(4 * q), "the start of the PREVIOUS quantum of the stand");
        let mut twin: BTreeMap<[u8; 32], Maintained> = BTreeMap::new();
        twin.insert([0xA0; 32], standing(0xA0, 5 * q + (q - 1)));
        assert_eq!(above_blue_score(&twin), above_blue_score(&held), "anywhere in one quantum ⇒ the same cursor");
        held.insert([0xA1; 32], standing(0xA1, 3 * q + 1));
        assert_eq!(above_blue_score(&held), Some(2 * q), "the OLDEST stand decides");
        held.insert([0xA2; 32], maintained_for(set(0xA2)));
        assert_eq!(above_blue_score(&held), None, "a carrier just watched needs the whole span");
        let mut done = maintained_for(set(0xA2));
        done.settled = true;
        held.insert([0xA2; 32], done);
        assert_eq!(above_blue_score(&held), Some(2 * q), "a settled carrier does not hold the others back");
        let mut unknown = standing(0xA3, 0);
        unknown.stood_score = None;
        held.insert([0xA3; 32], unknown);
        assert_eq!(above_blue_score(&held), None, "an unknown served score ⇒ the whole span");
        let mut young: BTreeMap<[u8; 32], Maintained> = BTreeMap::new();
        young.insert([0xB0; 32], standing(0xB0, q + 3));
        assert_eq!(above_blue_score(&young), Some(0), "one full quantum behind ⇒ above 0");
        young.insert([0xB0; 32], standing(0xB0, q - 1));
        assert_eq!(above_blue_score(&young), None, "no previous quantum ⇒ the whole span");
    }

    /// ⭐ DB-252 — A DELTA PAGE AFTER A FULL PAGE STANDS THE CARRIER ON THE NEW TIP; A LYING DELTA CANNOT.
    /// Folded for real (two batched steps). Page 1 serves block A in full; page 2 serves ONLY block B with the
    /// A_tip over {A, B} and tips {B}: the carrier stands, carries {B}, and has folded exactly {A, B}. TAMPER: a
    /// delta whose `a_tip` also covers a block C it never serves leaves the carrier NOT standing — a short or
    /// lying page can never make it attest, because it stands only when its own sum equals the served tip.
    /// TWO-PARTY-REVIEWED: the pages here stand in for the serving node so the WALLET's fold rule is pinned in
    /// isolation; the two-party half (a real node's delta page, then its door admitting the witness) is DB-252's
    /// node pins plus the real-node send probe, run when the node half lands.
    #[test]
    fn db252_a_delta_page_after_a_full_page_stands_the_carrier_on_the_new_tip() {
        let nf = [0x52u8; 32];
        let padded: Vec<[u8; 32]> = (0..4u8)
            .map(|i| {
                let mut t = nf;
                t[31] = i;
                t
            })
            .collect();
        let base = usdmd_node::spend_frontier::empty_leaf();
        let block = |b: u8| -> ([u8; 32], Digest4, Vec<[u8; 32]>) {
            (
                [b; 32],
                usdm_decider::nf_sparse_air::nf_to_limbs(&[b ^ 0xF0; 32]),
                usdmd_node::cover::nullifier_wire_fill(&[], &[b; 32]),
            )
        };
        let (a, b, c) = (block(0xA1), block(0xB2), block(0xC3));
        // The A_tips an independent carrier reaches over {A} and {A, B} and {A, B, C}.
        let mut probe = NfAbsenceBatchCarrier::new(maintained_for(padded.clone()).nf_limbs, base);
        assert!(probe.step(&a.2, a.1));
        let tip_a = probe.acc();
        assert!(probe.step(&b.2, b.1));
        let tip_ab = probe.acc();
        assert!(probe.step(&c.2, c.1));
        let tip_abc = probe.acc();

        let q = usdmd_node::nf_sparse::NF_RECENT_BLOCKS as u64;
        let mut held = BTreeMap::new();
        held.insert(nf, maintained_for(padded.clone()));
        assert!(apply_page(&mut held, &served_page(base, tip_a, &[a.clone()], &[a.0], 3 * q + 5)));
        assert_eq!(above_blue_score(&held), Some(2 * q), "standing on page 1 ⇒ ask above the previous quantum");
        assert!(
            apply_page(&mut held, &served_page(base, tip_ab, &[b.clone()], &[b.0], 3 * q + 9)),
            "the delta folds"
        );
        assert_eq!(authority_of(&held[&nf]), Authority::Ready, "the delta stands the carrier on the new tip");
        assert_eq!(held[&nf].acc, tip_ab, "its verified accumulator is the proving carrier's over {{A, B}}");
        assert_eq!(held[&nf].tips, vec![b.0], "it carries the tips of the page it now stands on");
        assert_eq!(held[&nf].stood_score, Some(3 * q + 9), "and records that page's public score");
        assert_eq!(*held[&nf].folded, [a.0, b.0].into_iter().collect::<BTreeSet<_>>(), "exactly {{A, B}} folded");

        // TAMPER: a delta that claims {A, B, C} but serves only B.
        let mut held = BTreeMap::new();
        held.insert(nf, maintained_for(padded));
        assert!(apply_page(&mut held, &served_page(base, tip_a, &[a.clone()], &[a.0], 3 * q + 5)));
        assert!(apply_page(&mut held, &served_page(base, tip_abc, &[b.clone()], &[c.0], 3 * q + 9)));
        assert_ne!(authority_of(&held[&nf]), Authority::Ready, "a lying delta never makes the carrier stand on the tip");
        assert_eq!(above_blue_score(&held), None, "and the next pass asks for the whole span (self-correcting)");
    }
}
