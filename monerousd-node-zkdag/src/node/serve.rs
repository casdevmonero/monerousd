// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! serve — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// The fold of the block roots this node SERVES — the value a spender folding `/membership_roots` lands
    /// on, and therefore the endpoint its carrier names.
    pub fn served_membership_acc(&self) -> crate::spend_frontier::Digest4 {
        self.served_membership_acc
    }

    /// ⭐⭐⭐ DB-380 — THE CHAIN-QUALITY SIGNAL (user 2026-10-04: "Eclipse attacks or other attacks should not be able to
    /// effect our network if we plan for the worst"). An eclipsed node sees ONLY the adversary's chain, so no "heavier"
    /// rule can help it; what it CAN read, from the chain alone, is the work that chain carries. The retarget
    /// (`miner::adaptive_work_checked`) moves the work target by at most `DAA_CLAMP` per block, and a private chain mined
    /// with hash share `h` must either let its difficulty fall by `1/h` across the window or produce blocks `1/h` slower
    /// than the target spacing. Both are read here off the DAA window this node already holds (`daa_sample_len` headers,
    /// a fixed protocol constant — bounded by construction, no history term):
    /// - `work_ratio_x1000`: the oldest work over the newest (≥ 1000 × `DAA_CLAMP` ⇒ difficulty fell ≥ 4× in one
    ///   window — the honest mesh produces that only by losing ≥ 75 % of its miners inside ~30 s, and withholding
    ///   "settled" is right then too);
    /// - `rate_ratio_x1000`: blue blocks observed per target spacing (≤ [`Self::view_rate_floor_x1000`] ⇒ the chain runs
    ///   at a quarter of the target rate, within the estimator's 3σ margin — DB-380 §7).
    /// `degraded` is a NODE-LOCAL verdict about this node's own view: every settlement answer must carry it (DB-380 §3b),
    /// the wallet shows it, and nothing here ever authors a chain correction (a node's local failure never decides the
    /// chain). A view with fewer than two samples, or no tip, is degraded by rule: nothing has been read yet.
    /// cons: one walk over the fixed window per call; no state. Pinned RED-first by the eclipse simulation
    /// (`eclipse_a_victim_fed_only_a_private_chain_…`, netsim) and by its honest-view calibration arm.
    pub fn view_quality(&self) -> ViewQuality {
        let Some(tip) = self.selected_tip() else {
            return ViewQuality { samples: 0, work_ratio_x1000: 0, rate_ratio_x1000: 0, degraded: true };
        };
        {
            let p = self.relay.dag().params();
            let full = p.daa_sample_len.max(p.mtp_sample_len as u64) as usize; // the length `daa_window_below` walks to
            Self::view_quality_of(&self.daa_window_below(&tip), p.target_spacing_ms, full)
        }
    }

    /// The verdict over one DAA window (newest first), the pure core of [`Self::view_quality`].
    pub(crate) fn view_quality_of(w: &[crate::dag::DaaSample], target_spacing_ms: u64, full_len: usize) -> ViewQuality {
        if w.len() < 2 {
            return ViewQuality { samples: w.len(), work_ratio_x1000: 0, rate_ratio_x1000: 0, degraded: true };
        }
        let (newest, oldest) = (w[0], w[w.len() - 1]);
        let clamp = crate::miner::DAA_CLAMP;
        // `header.work` is the DIFFICULTY (`adaptive_work_checked` lowers it when blocks run slow): the arm reads how far it
        // FELL — oldest over newest. DB-380 §7: it read newest over oldest, firing on honest hash growth and blind to the
        // fall an eclipsed hash minority produces.
        let work_ratio_x1000 = (oldest.1.saturating_mul(1000) / newest.1.max(1)).min(u64::MAX as u128) as u64;
        let actual_ms = newest.0.saturating_sub(oldest.0).max(1) as u128;
        let blue_span = (newest.2.saturating_sub(oldest.2) as u128).max(w.len() as u128 - 1);
        let expected_blocks = (actual_ms / target_spacing_ms.max(1) as u128).max(1);
        let rate_ratio_x1000 = (blue_span.saturating_mul(1000) / expected_blocks).min(u64::MAX as u128) as u64;
        // ⛔ A-F108 (lane speed5, 2026-11-19) — THE HASH ARM: work arriving per unit of time (block rate × difficulty, as a
        // share of the target's), Bitcoin Core's `PartitionCheck` signal. Since every node paces its own production to the rate
        // the DAG shows (A-F60/A-F67) and the DAA lowers the difficulty in step, an eclipsed minority no longer runs at a quarter
        // of the rate: MEASURED (netsim eclipse, main 7023c4b8, ten parties, two eclipsed) victim rate 0.666 of target and work
        // fallen 3.333× inside the window — neither arm fired — while its hash share was 0.666 / 3.333 = 0.20; the honest origin
        // read 1.052 / 1.111 = 0.95. Pacing cannot raise this product: producing faster only lowers the difficulty in step.
        // Same floor as the rate arm (the 1/DAA_CLAMP class plus z = 3 of the window's estimator), node-local, never a halt.
        // AI RESISTANT: (b) code and economics — an attacker evades it only by bringing the hash the honest mesh has.
        // cons: an honest mesh that loses ~2/3 of its hash within one window reads degraded until the window turns over
        //   ("confirming" in the wallet, 0 bytes on the wire). NOT CONFIRMED: an eclipse longer than the window whose oldest
        //   sample is already eclipse-era reads work_ratio ~1 again; a longer-memory reference is owed.
        // ⛔ A-F109 (lane speed5, 2026-11-19): the hash arm reads a FULL window only. A window shorter than the DAA's is a chain
        // younger than one window (`daa_window_below` walks to genesis), whose difficulty is still descending from its
        // bootstrap value: a fall the honest chain itself makes. MEASURED (netsim eclipse, lane 1a707384, t = 40 s, tips 11):
        // the honest origin's 5-sample window read rate 0.733, difficulty fallen 1.777×, hash 0.41 ≤ the 5-sample floor 0.625, DEGRADED.
        // cons: for a chain's first DAA window (60 blocks in production) only the rate and work arms judge the view; an
        // eclipse needs a chain to eclipse, and the arms that ran before A-F108 still run there.
        let hash_x1000 = (rate_ratio_x1000 as u128).saturating_mul(1000) / (work_ratio_x1000 as u128).max(1);
        let hash_low = w.len() >= full_len && hash_x1000 <= Self::view_rate_floor_x1000(w.len());
        let degraded = work_ratio_x1000 as u128 >= clamp * 1000
            || rate_ratio_x1000 as u128 <= Self::view_rate_floor_x1000(w.len())
            || hash_low;
        ViewQuality { samples: w.len(), work_ratio_x1000, rate_ratio_x1000, degraded }
    }

    /// The rate arm's floor, ×1000, for a window of `samples`: the 1/`DAA_CLAMP` class boundary plus z = 3 of the
    /// estimator's relative standard deviation 1/√(n−1) (n−1 Poisson intervals) — `class · (1 + 3/√(n−1))`, 443 at the
    /// netsim window (16), 347 at the production window (60). A floor AT the boundary missed half the views AT it, and
    /// a k-producer chain whose PoW does not bind runs at k/8 of the target (4 s relay floor ÷ 500 ms), so the 2-producer
    /// eclipse sits exactly there (MEASURED 0.231 / 0.327 on one commit and seed; DB-380 §7). Borrowed shape: Bitcoin
    /// Core's `PartitionCheck` alarms on a Poisson tail, not on the mean. Inputs are protocol constants only.
    /// cons: an honest mesh with < ~2.8 of the 8 producers the target needs reads degraded at the production window
    /// (was ≤ 2) — node-local "confirming", 0 bytes on the wire, never a halt.
    pub(crate) fn view_rate_floor_x1000(samples: usize) -> u128 {
        const Z: u128 = 3;
        let class = 1000 / crate::miner::DAA_CLAMP;
        let sd_inv_x1000 = ((samples.max(2) as u128 - 1) * 1_000_000).isqrt();
        class + class * Z * 1000 / sd_inv_x1000
    }

    /// ⭐⭐⭐ DB-161 — THE POSITION THIS NODE SERVES, DEFINED ONCE.
    ///
    /// ALWAYS this node's own FOLD ROOT once it has folded — the highest position it has folded through and
    /// can therefore cover completely; the selected tip only before the first fold. Before DB-161 the serve
    /// simply REFUSED past the carry's reach, which deadlocked a mesh where no peer was caught up (measured:
    /// 6,855 refusals against 6,085 asks, zero adopts, both heights frozen); DB-161 then served the fold root
    /// only past LIVE_LANE_DEPTH unfolded and the SELECTED TIP below it, with every unfolded body carried.
    ///
    /// ⛔ G11b (2026-10-22): that carried backlog made the bundle unfolded × block wire — bounded by
    /// 512 × 132 KB = 68 MB, past the 16 MiB bulk frame and the ≤ 1.8 MB cardinal BY CONSTRUCTION (measured at
    /// 10 validators: 2,739 refusals of 17–57 MB bundles, every joiner stranded on a stale served bundle,
    /// scratchpad/verify/launch-leg1-20261022-2057.log). BORROWED, cited: Kaspa's pruning point — the certified
    /// state is served AT the fold root — and Bitcoin headers-first / getblocks — the blocks above it ride the
    /// kind-9 follow-page lane this node already runs (`follow_page_after_locator`, `CBlockLocator`, DB-446),
    /// BLOCK_BATCH_MAX bodies per page from the adopter's own locator. The bundle is constant at every lag.
    ///
    /// ⛔ EVERY SIDE OF THE BUNDLE MUST READ THIS. `current_chain_acc` hardcoded `selected_tip()` while
    /// the bundle chose the fold root, so the cached proof and the served bundle described DIFFERENT tips
    /// and the binding assert fired on the first fold-behind serve. Two derivations of one value is the
    /// same error as a second numbering.
    pub fn served_tip(&self) -> Option<crate::block::BlockId> {
        // The anchor is the fold cursor when this node has one, else the highest selected-chain block whose
        // record is folded (genesis at worst): the one position a checkpoint and a bundle stand on. MEASURED
        // (g11b-green-20261022-2215.log): gating on the cursor alone served the SELECTED tip with the bodies
        // cleared on a node that had folded records without a cursor — 16 adopt pins red on that mismatch.
        self.fold_anchor_block().or_else(|| self.selected_tip())
    }

    /// The carry that rides the position [`Self::served_tip`] names.
    ///
    /// `unfolded` was the ONLY part that grew with the fold lag — the O(N) term DB-139 measured at 26 MB and
    /// G11b at 17–57 MB. The served position is the fold root, so there is nothing above it to carry: the
    /// backlog is paged by the adopter over the follow lane instead (see `served_tip`). `window`
    /// (daa_sample_len samples) and `ancestors` (depth x width) are fixed and the adopter's difficulty/MTP
    /// walk needs them. cons: the adopter reaches the live tip ceil(lag / BLOCK_BATCH_MAX) page round trips
    /// after the adopt instead of at the adopt (~12 s at lag 187; it was never, past the frame).
    pub(crate) fn served_carry(&self) -> crate::sync::FoldCarry {
        let mut carry = self.unfolded_carry();
        carry.unfolded.clear();
        carry.sidecars.clear();
        carry
    }

    pub fn served_block_count(&self) -> u64 {
        self.served_seq
    }

    /// The ABSOLUTE leaf index of the first leaf the record at `addr` contributed to the global spend
    /// frontier. A note in that record sits at `start + its offset within the record` — no width constant.
    /// ⭐⭐⭐ THE RESOLVER THIS FILE HAS CITED FOR MONTHS AND NEVER HAD. `cm -> record address`, O(1).
    ///
    /// Twelve lines above `note_target_addr`, this file says in its own words: *"Two comments in this file
    /// cite `da_seq_at_note_cm` as the thing that resolves a note's position at any age — THAT FUNCTION DOES
    /// NOT EXIST; the resolver was described and never built."* It still did not exist. The index it would
    /// read — one entry per filed note, written the instant an address resolves — was already here.
    ///
    /// MEASURED 2026-08-11, live two-wallet/two-node run at height 12,171, the failure this closes:
    ///     [receive-capture] untracked owned note at record 18446744073709551615/slot 0 — declined by the node
    /// `18446744073709551615` is `u64::MAX`, the unknown-position sentinel. The wallet held a note it had
    /// decapped and owned, could not name WHERE it sat, asked for a witness at a nonsense address, and was
    /// refused — so the note was never witnessed and every spend reported it untracked. A note you own and
    /// cannot spend is FUND LOSS, and it was caused by a lookup that was documented instead of written.
    ///
    /// This is the accepted O(1) shape: WRITE IT DOWN, THEN LOOK IT UP. One hash lookup whose cost depends on
    /// the key width alone — never on height, block count, note count, or how long ago the note arrived. It
    /// therefore answers at ANY age, which is exactly the property an aging bound would destroy.
    /// ⭐⭐⭐ THE ONE SIDECAR COORDINATE RESOLVER. Every sidecar (oli tags, nf tags, del_cms, recv_cms)
    /// is stored under the WRITER-returned canonical record address; readers arrive holding any of THREE
    /// coordinates — that address, a dense ordinal, or a sub-0 block-derived guess. Five separate
    /// per-site translations shipped this session (wire fns, settle derivation, rebuild retry,
    /// apply-dedup, serve read) and a SIXTH miss still lost one record's sidecars (MEASURED 2026-08-13:
    /// rid=7125886510714600 held on the peer, never adopted by the restarted node — its serve read
    /// resolved a different coordinate than the writer stored). This helper is the single translation
    /// all of them converge on: resolve to the address that actually HOLDS sidecar or record data, in a
    /// fixed probe order, never a guess. Cost: at most four indexed map reads per call — no walk, no
    /// state, no growth term.
    /// ⛔⛔⛔ READ-ONLY SERVE ONLY — NEVER AN ADMISSION. This is the ONE place a coordinate is still
    /// allowed to be tried in both spaces, and it is allowed there for exactly one reason: a SERVE
    /// hands bytes out. It grants nothing, moves no unspent set, and a coordinate it guesses wrong
    /// answers with an empty page. The ADMISSION path resolves NOTHING — [`RecAddr::from_wire`] takes
    /// a peer's `rid` at face value — because there a wrong guess lends an honest chain-bound
    /// record's authority to an attacker's bytes (see [`rec_coord`]).
    /// ROOT-LAYER: behaviour unchanged for its one caller (`node_runtime::rt_addr_for`); what changed
    /// is that the three resolvers it used to silently compete with no longer exist.
    /// MUST-STAY-GREEN: the range/by-ordinal serve pins — a serve that stops finding a record's
    /// sidecars is the measured 2026-08-13 sixth-coordinate miss, and none of this touches it.
    pub(crate) fn serve_addr_for_coord(&self, key: u64) -> RecAddr {
        let probe = RecAddr::local(key);
        // 1. Already an address holding sidecar data? Done.
        if self.da_tags_mem.contains_key(&key) {
            return probe;
        }
        // 2. An address this node has a record for (ordinal map knows it)? It IS the coordinate.
        if self.da_record_ordinal(key).is_some() {
            return probe;
        }
        // 3. A dense ordinal? Its address is the coordinate — through THE ONE BRIDGE.
        if let Some(a) = self.record_addr_at_ordinal(RecOrd::new(key)) {
            return a;
        }
        // ⛔ THE OLD FOURTH PROBE IS GONE AND IT WAS NEVER REACHABLE: it read `da_ord_rev_mem` (the
        // ORDINAL→address map) under a comment claiming it read the address→ordinal one, and step 3
        // already reads that same map. It could only fire when step 3 had returned. A dead branch
        // whose comment names the wrong map is precisely how a resolver drifts from its readers.
        probe
    }

    /// ⭐⭐⭐ Z1 (2026-09-22) — THE SERVE READINESS VERDICT, replacing the deletion model's
    /// `unspent_serve_ready`. There is no per-note tree to rebuild any more, so "can this node be trusted
    /// to serve and to be rolled" is exactly three facts about its own fold, each O(1) to read:
    ///   * its record spine is not STALE (a fold that stopped cannot vouch for what it holds);
    ///   * it owes no record (`missing_record_count() == 0` — by-id byte wants, payload holes, backlog);
    ///   * its fold is within one live lane of its own tip (a node far behind is honest, not ready).
    /// A rolling restart reads this on the FIRST node before stopping the second (run 27's measured
    /// mutual-hole class), and the deploy gate reads it as "history_complete".
    pub fn serve_ready(&self) -> bool {
        !self.spine_stale
            && self.missing_record_count() == 0
            && self
                .da_record_ordinal_top()
                .saturating_sub(self.served_seq)
                <= crate::node_runtime::LIVE_CATCH_UP_DEPTH
    }


    /// The accumulator `/membership_roots` SERVES. A wallet folds this stream and proves against the
    /// result, so a party holding one the chain does not derive refuses the very proof its own stream
    /// taught the wallet to build — measured on a real cross-device send as `MEMBERSHIP_PROOF_INVALID`
    /// with nothing wrong on either side.
    pub fn served_membership_acc_for_audit(&self) -> crate::spend_frontier::Digest4 {
        self.served_membership_acc
    }

    /// ⭐ P1 — the accumulator follows the band's LIVE root: after a drain, and after a rewind (the door took the un-applied
    /// inserts back out of the held view). One function, so every site that moves the band moves the view's authority
    /// with it.
    pub(super) fn view_follow_band_root(&mut self) {
        let live = self.band_door.band_root();
        if let Some(acc) =
            crate::nf_sparse::SparseNfAcc::adopt_merkle_root(crate::spend_frontier::leaf_to_cm_bytes(live))
        {
            self.sparse_acc = acc;
        }
    }

    pub fn served_seq(&self) -> u64 {
        self.served_seq
    }

    /// ⭐ DB-316c: THE ONE VERIFICATION PREFIX OF A SERVED #29 BUNDLE, run before either door reads a certified field.
    /// `instant_sync` (the adopt) and `repivot_from_bundle` (the pivot recovery) both call it, so the two doors cannot
    /// drift apart. The decider + certificate verify (`adopt_sync_bundle`) and the genesis check follow it at both call
    /// sites.
    pub(super) fn served_bundle_prefix_refusal(&self, bundle: &SyncBundle) -> Result<crate::join_proof::JoinVerdict, AdoptOutcome> {
        // A spine that does not reproduce the root the bundle certifies is a lying or broken peer: refuse
        // the WHOLE bundle before anything moves (adopting its DAG anchor without its spine would leave
        // this node standing on a state it cannot fold from — the adversary search found exactly that).
        // ⛔⛔⛔ DB-376 (2026-10-04): the spine must also DECODE and be the spine AT the anchor's position — an EMPTY
        // spine is no longer exempt (`peaks_hex()` is fixed-width, so an empty string is never an honest serve; the
        // old exemption let a stripped spine install the anchor's POSITION over this node's own shorter frontier, and
        // the next fold wedged at the leaf law). The ONE predicate, shared with `sync::adopt_sync_bundle`
        // (docs/DB-376-SPINELESS-BUNDLE-REFUSAL.md).
        if !crate::sync::frontier_spine_binds(&bundle.frontier, bundle.anchor_ordinal) {
            eprintln!(
                "[dsync] ⛔ REFUSED a bundle whose note-frontier spine does not decode, does not reproduce its certified \
                 root, or is not the spine at its anchor's position — nothing adopted (a position without its spine \
                 would wedge this node's fold at the leaf law; a peer cannot steer our accumulator)"
            ); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string; no root, count, note, amount, key or owner.
            return Err(AdoptOutcome::FrontierUnbound);
        }
        // ⛔ THE CARRIED BLOCKS GO THROUGH THE ONE HEADER DOOR FIRST (see `bundle_blocks_admitted`):
        // a bundle carrying a block that was never mined — or whose tx list its own header does not
        // commit to — is refused WHOLE, before any certified field is installed. Refusing here rather
        // than at each placement is what makes the VERDICT fail closed: an anchor the DAG rejects used
        // to leave `Adopted` standing, and the quorum, the spent-state and the record roots landed on
        // it anyway (family-D pins D-2 / D-3).
        let verdict = match self.join_verdict(bundle) {
            Ok(v) => v,
            Err(why) => {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a refusal name; no root, note, amount or owner.
                eprintln!("[dsync] ⛔ REFUSED a bundle by the join door: {why:?} — nothing adopted");
                return Err(AdoptOutcome::CertificateUnproven);
            }
        };
        if let Some(why) = self.bundle_blocks_refusal(bundle) {
            eprintln!(
                "[dsync] ⛔ REFUSED a bundle carrying a block this node's header door does not admit \
                 ({why}) — nothing adopted"
            );
            return Err(AdoptOutcome::Unverified);
        }
        // A-F49: the join door's verdict is what authenticates a bundle that carries no decider proof or certificate
        // (`sync::adopt_sync_bundle`); it is handed on, never re-derived.
        Ok(verdict)
    }

    /// ⛔ G11c — THE SERVED POSITION IS ONE THE SERVED SPINE STANDS AT (§9.6 (6): parity with the adopt door's DB-376
    /// `frontier_spine_binds`, which refuses a spine whose leaf count is not exactly anchor_ordinal × 256). Read by both
    /// writers of the binding (`current_chain_acc`, `draft_sync_bundle`) in place of the bare row.
    /// MEASURED (real leg 4, main 2279431, sim-20261023-092259.log): a server stopped MID-BATCH (a member folded, its
    /// chain block's step waiting, so the spine stands one record past `fold_chain_tip`'s row: 571 vs 570) bound and
    /// served its LIVE spine under the anchor's position; every adopter refused it `FrontierUnbound` and the joiner's
    /// fold stayed wedged (bond never seated). Mid-batch the serve now builds nothing new: `build_sync_response` keeps
    /// serving the bundle it froze at the last batch boundary (a certified position), and builds again once the batch
    /// completes. Pin: `canonical_record_fold_tests::…::a_node_stopped_mid_batch_serves_only_bundles_an_adopter_can_take`.
    /// cons: none — one multiply and one compare per serve; the only bundles it withholds are ones every honest adopter
    /// refuses (a full frame + a prove saved per refused serve).
    pub(crate) fn served_anchor_position(
        &self,
        anchor: &crate::block::BlockId,
        frontier: &FrontierSnapshot,
    ) -> Option<u64> {
        let position = self.certified_fold_base_position(anchor)?;
        // TEST ONLY (`Node::set_hostile_frontier_serve_for_test`, always false in production builds): a rogue prover binds a
        // frontier that is not its anchor's; the ADOPTER's door is what the DB-376 / DB-296 pins judge.
        if Self::hostile_frontier_serve_for_test() {
            return Some(position);
        }
        (frontier.height == position.saturating_mul(crate::cover::BLOCK_FIXED_NOTE_COUNT as u64)).then_some(position)
    }

    /// G11c: this node's fold stands MID-BATCH — its fold anchor holds a certified row, but the spine is not at it — so no
    /// bundle can bind here until the batch completes. The serve answers `Building` (its callers' Building arms serve the
    /// last installed bundle under DB-403's extendability check), never `Ready` with a cache that skipped that check.
    pub(crate) fn serve_waits_mid_batch(&self, frontier: &FrontierSnapshot) -> bool {
        self.fold_anchor_block().map_or(false, |anchor| {
            self.certified_fold_base_position(&anchor).is_some()
                && self.served_anchor_position(&anchor, frontier).is_none()
        })
    }

}
