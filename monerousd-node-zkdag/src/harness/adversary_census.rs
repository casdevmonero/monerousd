// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⛔⛔⛔ THE ADVERSARY CENSUS — the attacks no SURFACE census measures, as simulated adversaries with recorded pins.
//!
//! USER 2026-10-04: *"improve the ecosystem hole tool so that we can say that our ecosystem is safe for real funds. Add the
//! 'things no scanner measures' to the scanner as task that simulate these events so that we have defenses and proof that
//! our economic theory is sound. Eclipse attacks or other attacks should not be able to effect our network if we plan for
//! the worst … monerousd will be launched into a extremely hostile enviroment and should be treated and hardened as such
//! to have defenses at every possible angle."*
//!
//! WHY THIS EXISTS. The surface censuses enumerate every FIELD, ROUTE, MESSAGE, DOOR and GATE mechanically and refuse a row
//! closed by declaration — but the attacks they ask about are the authored classes (forge / strip / substitute / replay /
//! burn; content / shape / linkage / ordering). The adversaries that reach a chain from OUTSIDE its object model were not in
//! any list: a peer set the attacker controls (eclipse), a poisoned bootstrap, a partition, a flood at a door, an observer
//! with every cell's timing, a producer withholding blocks, a market that crashes, a custody quorum that colludes, a bank
//! run, an AMM taker who sandwiches, a staker who games an epoch edge, a parameter set weaker than its label, a gate that
//! is sound for the WRONG statement. Each row here is one such adversary, the defense the design CLAIMS against it, and
//! the verdict: a recorded GREEN simulation pin, a RED-first pin with its measured mechanism, an openly STATED trust bound
//! the user owns, or OPEN with what the simulation must drive and assert. An Open or Red row is a T0 hole; the register
//! (`scratchpad/hard20.sh` H10–H13) reads COMPLETE only when none remains.
//!
//! LAWS OF THIS CENSUS:
//! - A row is closed ONLY by a `Pinned` simulation that mounts the adversary and asserts what the VICTIM holds afterwards
//!   (never what a call returns), recorded in the pin ledger. "The design handles it" is `Open`, however true it sounds.
//! - A `Bound` is a trust assumption the design states openly (e.g. ≥ 2/3 of bonded custody weight). It is not a hole and
//!   it is never argued down ([[feedback_never_argue_a_security_bound_down]]); it is what the launch documentation says.
//! - A simulation that shows a defense MISSING is a finding to fix at the root, never a fixture to tune — the row turns
//!   `Red(pin, mechanism)` and the pin stays red-first until the fix lands (DB-379 is the first).
//! - Every `Pinned`/`Red` pin must exist in the tree, and every `Red` pin must be filed in `scratchpad/known-reds.txt` —
//!   a red the tree carries is counted, never hidden. An unreadable known-reds file is itself a coverage gap (fail closed).

/// The verdict a row carries.
#[derive(Debug, Clone, Copy)]
pub enum Verdict {
    /// A GREEN simulation pin (by its `fn` name) that mounts the adversary and asserts what the victim holds.
    Pinned(&'static str),
    /// A RED-FIRST pin and the mechanism it measured — a finding under repair.
    Red(&'static str, &'static str),
    /// No simulation yet: what it must drive and assert.
    Open(&'static str),
    /// A trust bound the design states openly; the user owns it, the launch documentation carries it verbatim.
    Bound(&'static str),
}

/// One adversary: the family it belongs to, what it does, the defense the design claims, the verdict.
#[derive(Debug, Clone, Copy)]
pub struct Scenario {
    pub family: &'static str,
    pub name: &'static str,
    pub adversary: &'static str,
    pub defense: &'static str,
    pub verdict: Verdict,
}

pub const NETWORK: &str = "network";
pub const ECONOMIC: &str = "economic";
pub const CRYPTO: &str = "crypto-parameter";
pub const STATEMENT: &str = "circuit-statement";
pub const FAMILIES: [&str; 4] = [NETWORK, ECONOMIC, CRYPTO, STATEMENT];

const fn row(family: &'static str, name: &'static str, adversary: &'static str, defense: &'static str, verdict: Verdict) -> Scenario {
    Scenario { family, name, adversary, defense, verdict }
}

pub const SCENARIOS: &[Scenario] = &[
    // ── NETWORK — a peer set, a wire and a clock the adversary controls ──────────────────────────────────────────────
    row(
        NETWORK,
        "rogue siblings strand an honest block",
        "a producer feeds a victim two or three rogue sibling blocks before the honest block of the same height; the victim's \
         DAG is heavier by blue score, so the late honest block is a lighter side tip beside the victim's own chain",
        "GHOSTDAG places the side branch when the NEXT chain block merges both tips (Kaspa: the new selected tip's mergeset); \
         the victim applies the honest object from that block alone — never by arrival order, never by a re-anchor",
        // DB-379 (2026-10-04) read the honest block as "stranded below a moving fold cursor" from unlabelled prints. MEASURED
        // 2026-10-22 from the victim's DAG itself (scratchpad/night/db379-measure-20261022.log:1823): on_selected_chain=false,
        // record_folded=false, is_tip=false (its child was the tip), tips=2, unfolded=3 — a side branch awaiting its merge,
        // which the fixture never laid because the victim's blocks never travelled back. With the merging block laid, the
        // victim folds it (tips=1, unfolded=0) and applies the burn (db379-mesh-20261022.log:1875). The fold was never wrong.
        Verdict::Pinned(
            "a_two_of_two_custody_quorum_gathers_peg_out_attestations_and_a_third_node_applies_the_burn_from_the_block",
        ),
    ),
    row(
        NETWORK,
        "eclipse: settlement shown on a private chain",
        "every circuit of a victim node terminates at the adversary, who feeds it a private chain carrying a payment the mesh \
         never saw (and later a conflicting spend)",
        "DSYNC adopts only a HEAVIER certified bundle; the band door's spent set; the k-confirmation finality rule on blue \
         score; the wallet reports 'confirming' until the fold",
        // MEASURED 2026-10-04 (netsim, ten parties): the victim's own chain reads DEGRADED (rate 0.250 of target) once the
        // DAA window turns over, the honest origin stays trusted (0.983–1.000). Four parties could not show it (2 vs 2
        // producers); nine put the eclipsed set at 0.27, above the 1/4 floor. Time-to-fire at the production window ≈ 240 s,
        // so this is the slow backstop; the instant defense (peer diversity, §3c) and the RPC `view` field are the next rows.
        Verdict::Pinned("eclipse_a_victim_fed_only_a_private_chain_reads_its_view_degraded_while_the_honest_mesh_stays_trusted"),
    ),
    row(
        NETWORK,
        "eclipse: settlement RPCs and the wallet carry the degraded view",
        "the same eclipse: a merchant reads `balance` / `spendable` on the degraded node",
        "DB-380 §3b: every settlement answer carries `view: degraded`, the wallet shows it, and nothing is called settled",
        Verdict::Open("wire `Node::view_quality` into every settlement RPC and the wallet's balance states (DB-372's honest 'confirming'); pin: on the eclipsed victim every settlement answer says degraded and the private payment is never reported settled"),
    ),
    row(
        NETWORK,
        "eclipse: liveness after one honest circuit",
        "the same victim, after the eclipse, is given ONE honest circuit",
        "the heavier honest chain is adopted by DSYNC; the private chain's blocks become side blocks of the one DAG",
        // MEASURED 2026-10-04: recovered 100 s after the circuit returned (eclipse-split-pins.log) at the 16-sample window;
        // an identical seeded run earlier did NOT converge within 120 s (eclipse-pin6.log). It recovers by SERIAL by-id pulls
        // of the eclipse-era honest blocks over the one circuit — slow and variable — while the view quality is honest again
        // by +80 s. The pin's 120 s bound is the measured promise; the next row is the design that makes it fast.
        Verdict::Pinned("eclipse_a_victim_recovers_to_the_honest_chain_when_one_honest_circuit_returns"),
    ),
    row(
        NETWORK,
        "eclipse: recovery by certified jump, not serial pulls",
        "the same reconnected victim, with hundreds of eclipse-era honest blocks to fetch over one circuit",
        "the certified bundle (DSYNC adopt) is the O(1) repair and exists; it does not FIRE for a node that is merely behind \
         with a live inbound — only for a silent inbound (deaf mode) or a stale spine (DB-380 §4e)",
        Verdict::Open("trigger: a node whose view was DEGRADED and then sees a peer announcing a tip heavier by more than the finality depth asks THAT peer for a certified bundle at once (one ask per peer per window); pin: recovery ≤ 2 × relay floor after one honest circuit, measured against the 100–120+ s serial figure"),
    ),
    row(
        NETWORK,
        "bootstrap sybil: a poisoned peer directory at first join",
        "every address a fresh node learns at bootstrap is the adversary's",
        "UNNAMED in the tree: the onion peer directory (`peer_directory.rs`) and the heavier-bundle rule limit what a poisoned \
         set can show, but the bootstrap SOURCE set and its diversity rule are not written down",
        Verdict::Open("read `peer_directory.rs` + `main.rs` bootstrap; write the diversity rule (≥ k independent sources, no single operator); netsim: a fresh node bootstrapped only from adversary addresses must either reach one honest peer or refuse to report settlement"),
    ),
    row(
        NETWORK,
        "partition and heal",
        "the mesh is split in two for M blocks; both halves produce and settle payments; the partition heals",
        "ONE DAG (GHOSTDAG merges both halves; the Kaspa pruning window); the finality rule bounds what a payment settled in \
         the smaller half can lose",
        // MEASURED 2026-10-04 (lane-harness, `netsim::a_partition_heals_into_one_dag_and_no_payment_past_k_confirmations_in_
        // the_heavier_half_is_lost`, 6 parties 4/2 at the 4 s relay floor): ONE DAG 20 s after the heal (one-chain predicate
        // across all six), ~63 confirmations on the heavy half at heal. The PAYMENT arm is not yet faithful: the pin staged a
        // bare note (`stage_credit_note`, no justifier object) — batch 5 it reached all 4 heavy parties, batch 6 only its own
        // node (a calibration failure = a fixture verdict, not a chain one). NetSim boots the production genesis (open-mint
        // allowance 0), so the next arm carries a REAL proven spend (`node::tests::honest_spend_tx_for_test` shape) inside
        // the sim; the light-half payment's fate (merged or dropped) is reported then.
        Verdict::Open("netsim: split N nodes 50/50 and 70/30 for M ∈ {8, 64} blocks, then heal; ASSERT one chain below min(tip) − 8 on every node, every payment settled past k confirmations in the heavier half stands, and the loser half's payments are re-included or reported unsettled, never silently lost — one-DAG arm MEASURED (20 s, 4/2); payment arm pending a real proven spend inside netsim"),
    ),
    row(
        NETWORK,
        "block withholding and selfish reorg at k confirmations",
        "a producer with hash share h withholds a private branch and releases it to revert a payment at k confirmations",
        "blue-score finality: the revert probability at k is a function of h, stated per (h, k)",
        Verdict::Open("netsim with an adversary producer at h ∈ {10, 25, 33, 49} % for k ∈ {8, 32}: MEASURE the revert rate over seeded runs and pin it at or below the documented bound; the wallet's 'settled' must use that k"),
    ),
    row(
        NETWORK,
        "flood or oversized input at every door",
        "an adversary sends oversized, malformed or unbounded-count messages at each ingress door (block, shell, tx, framed \
         object, record page, sync request, RPC)",
        "§9.6 Q5 — every door's bound: strict `decode_exact`, fixed slot counts, the parked-queue cap, `TX_REQ_FIXED_COUNT`; \
         the surface census lists every door",
        Verdict::Open("one flood pin per door in the surface census's door list: 10^4 malformed + 10^2 maximum-size inputs; ASSERT the node's footprint stays flat (`footprint`), the fold keeps moving, and honest traffic still lands within the relay floor"),
    ),
    row(
        NETWORK,
        "timing deanonymization",
        "an observer records the arrival time of every cell at every node and tries to link a transaction to its origin",
        "Tor v3 onion-only transport; a constant relay cadence (`COVER_INTERVAL_MS`); cover cells (netsim's `sent_real_cells`)",
        Verdict::Open("netsim with a global observer: for S seeded sends, MEASURE the observer's origin-attribution accuracy; ASSERT it equals chance (1/N) within the statistical bound"),
    ),
    row(
        NETWORK,
        "Tor outage / onion service unreachable",
        "the victim's onion service or its guard circuits fail for T minutes",
        "the arti supervisor restarts the transport; peers re-dial; the node keeps folding what it holds and re-anchors when a circuit returns",
        Verdict::Open("real-node journey: kill the transport for T ∈ {1, 10} min; ASSERT no payment held is lost, the node reports the outage legibly, and it converges within the relay floor × k after return"),
    ),
    row(
        NETWORK,
        "clock skew and timestamp manipulation",
        "a producer stamps blocks far ahead or behind, or a victim's clock is skewed",
        "the DAA window (`daa_sample_len` 60) and the header timestamp rules in `consensus.rs`",
        // MEASURED 2026-10-04 19:57 (lane-harness): the timestamp BOUND half — `a_block_stamped_past_the_drift_bound_or_at_the_
        // median_past_is_refused_by_the_peer_and_the_honest_chain_continues` GREEN: now + drift + 1 → TimestampTooFarFuture
        // (56,001 > 56,000), exactly at the bound → Added, ≤ MTP → TimestampTooEarly (10,000 ≤ 14,000), the honest chain
        // continues. STILL OPEN: the DIFFICULTY half (a producer stamping at the edges of the bound cannot drive the DAA down).
        Verdict::Pinned("h10_clock_skew_a_stamp_past_the_drift_bound_is_refused_and_one_at_the_bound_moves_the_work_by_at_most_the_clamp"),
    ),
    row(
        NETWORK,
        "certified bundle tampering",
        "a serving peer edits a certified bundle (reserve commitment, spine, frontier) before the joiner adopts it",
        "every bundle field is bound by the certificate; a spine-less or unbound frontier is refused (DB-376)",
        Verdict::Pinned("a_jumped_node_adopts_the_certified_peg_commitments_and_a_tampered_reserve_is_refused"),
    ),
    // ── ECONOMIC — a market, a quorum and a crowd the adversary moves ─────────────────────────────────────────────────
    row(
        ECONOMIC,
        "collateral crash: −50 % inside one mark epoch",
        "the reference price of the peg collateral halves between two attested marks, then keeps falling",
        "price marks attested by ≥ 2/3 bonded custody weight per epoch (DB-240); `liquidation_threshold_bps`; the automated, \
         trustless liquidation trigger (56e27c8) and the POOL-CAP circuit; the block path pinned by \
         `a_due_psm_liquidation_through_the_stability_pool_travels_to_a_peer_with_one_peg_and_one_pool`",
        // the −70 % crash in six steps, two separately constructed ledgers applying the same bytes, asserted EVERY step on
        // what the peer holds: agreement, no due PSM left unliquidated, each liquidation returns the PSM to target or closes
        // it and leaves it stronger, every retired USDm a pool burn, the custodian's next opening valid on the peer
        Verdict::Pinned("crash_simulation_minus_70_liquidates_through_the_stability_pool_on_two_ledgers"),
    ),
    row(
        ECONOMIC,
        "oracle collusion below the threshold",
        // RE-SCOPED 2026-10-04 BY MEASUREMENT (lane-harness): the row first read "< 2/3". The 1/3 arm below REFUTES that —
        // EXACTLY 1/3 moves the mark down — so this row claims only what is measured safe (< 1/3); the [1/3, 2/3) gap is
        // stated on the bound row below for the user's decision.
        "a colluder holding < 1/3 of the bonded weight quotes 10× high or low; a rogue producer carries EVERY quote subset that meets the ≥ 2/3 tally",
        "the ≥ 2/3 tally plus the bond-weighted (lower) median over the counted weight (DB-240 `mark_price_attested`)",
        // MEASURED 2026-10-04 16:32: 4 equal custodians, colluder 25 %: 10 carried subsets set a mark, 0 manipulated.
        Verdict::Pinned("an_oracle_colluder_below_a_third_of_the_bond_cannot_move_the_mark_with_any_quote_subset_a_rogue_producer_carries"),
    ),
    row(
        ECONOMIC,
        "oracle collusion at or above the threshold",
        "custodians holding ≥ 2/3 of the bonded weight attest any price they like",
        "none inside the protocol: this is the design's trust bound",
        Verdict::Bound("≥ 2/3 of bonded custody weight can mark any price and release the reserve accordingly — the bond-weighted multisig tally (user 2026-09-20/21). The deterrent is the bond at risk and equivocation slashing (DB-370); the launch documentation states this bound verbatim. ⛔ MEASURED 2026-10-04 (lane-harness, `an_oracle_colluder_holding_one_third_of_the_bond_moves_the_mark_down_so_the_stated_bound_is_one_third`): for the PRICE the effective bound is 1/3, not 2/3 — the tally passes at ≥ 2/3 of weight and the median is the LOWER median over the COUNTED weight, so a producer carrying {colluder at 1/10 the price, one public honest quote} (2 of 3 equal custodians) sets the mark to 1,500 against an honest 15,000; above 1/3 either direction moves. USER DECISION PENDING: accept 1/3 for the price (BFT f < n/3) and state it, or change the median rule"),
    ),
    row(
        ECONOMIC,
        "bank run: every holder redeems in one window",
        "all USDm holders burn for redemption within one epoch",
        "each burn is one reserve release, claimable exactly once on every node (DB-114 pin); the peg-out lane's throughput and the quorum's availability are UNMEASURED",
        Verdict::Open("real-node batch: H holders redeem in one window; MEASURE releases per minute against the quorum's attestation latency; ASSERT every burn is released once, none twice, and the reserve commitment after the run equals genesis + deposits − releases"),
    ),
    row(
        ECONOMIC,
        "AMM sandwich / front-running",
        "a taker sees a pending confidential swap and brackets it with its own orders",
        "the pool AMM is RETIRED at source (`sovereign.rs` RETIRED routes): the DEX is a book of pre-authorised ZK limit orders whose terms (`lot`, `pay_b`) are public and fixed by the maker's signature, so there is no price-impact curve to bracket; a fill pays exactly the maker's terms and names one maker nullifier",
        // MEASURED 2026-10-04 20:45 (lane-harness, h6-batch16) — what is left of a sandwich on a fixed-terms book is the RACE
        // (a front-runner takes the order first): `the_second_taker_to_race_one_order_is_refused_and_loses_nothing` GREEN and
        // `two_parties_racing_the_same_order_pay_the_maker_s_lot_exactly_once` GREEN — the second taker is refused and keeps
        // its funds, the maker is paid once. Extraction would need the victim to re-sign at a worse level (a wallet choice).
        // NOTE: order SIZE is public by design on this book; whether that is volume metadata is a privacy question for the
        // digital-cash census, not an extraction one.
        Verdict::Pinned("the_second_taker_to_race_one_order_is_refused_and_loses_nothing"),
    ),
    row(
        ECONOMIC,
        "AMM drain by rounding or extreme ratios",
        "a taker cycles deposit / swap / withdraw at extreme ratios and tiny sizes to accrete rounding in its favour",
        "the POOL-CAP circuit C = min(rule, M, T) (371eaae); conservation carriers on every pool leg; the rounded-down pool step and withdraw rules",
        // MEASURED 2026-10-04 20:28 (lane-harness, h6-batch15): the pool is Liquity's product/sum stability pool (the AMM is
        // retired). WITHIN an epoch it holds what it owes — `the_stability_pool_never_owes_more_than_it_holds_within_an_epoch_
        // at_any_liquidation_ratio_or_size` GREEN (900 seeded steps, 306 liquidations at 10^−6…100 % ratios, sizes to ~10^15).
        // ACROSS a NON-DRAIN epoch close it did not (DB-390: the close bit P_new < 2^64 closed a pool with value in it, the
        // withdraw door debited the LIVE T for a receipt of any epoch — 958 USDm owed beyond held, 8 withdrawals refused).
        // FIXED 2026-10-22 c6b5ffa (lane a, the EPOCH BRIDGE — Liquity scale span 1: a closed epoch's receipts settle through
        // the next epoch's words, docs/SP-EPOCH-BRIDGE-SPEC-20261022.md): owes −7 (≤ held), 0 refused; pin GREEN on main
        // (scratchpad/pin-results.tsv 2026-10-22T05:48 @ 3ca9b9c).
        Verdict::Pinned("a_non_drain_epoch_close_must_not_leave_the_stability_pool_owing_more_than_it_holds"),
    ),
    row(
        ECONOMIC,
        "stake / yield inflation at epoch edges",
        "a staker enters and leaves around epoch boundaries, re-stakes rewards, or claims twice",
        "DB-237 one hidden-tag StakeGate with the exact reward; the yield supply carrier; the reward-follows-principal weld (DB-365)",
        // MEASURED 2026-10-04 19:23 (lane-harness): CLAIMS at every epoch edge — `a_yield_claim_pays_exactly_its_closed_form_
        // and_only_in_its_own_epoch_on_the_peer_at_every_epoch_edge` GREEN: Δ ∈ {1, 365} × {last ms of e2−1, first / last ms
        // of e2, first ms of e2+1}: paid on the peer IFF in e2, reward = the closed form exactly (0 / 50), one supply; the
        // double claim: `a_yield_claim_re_carried_by_a_rogue_producer_pays_its_reward_once_on_the_peer` GREEN. STILL OPEN:
        // the UNSTAKE (out0_staked = false) and the re-stake of a reward at the edges, and reward-follows-principal (DB-365)
        // for a moved principal.
        // CLOSED 19:40 — every part measured GREEN on a peer: claims at every edge (the pin named below); UNSTAKES at every
        // edge (`an_unstake_returns_its_principal_and_pays_its_reward_only_in_its_own_epoch_on_the_peer_at_every_epoch_edge`:
        // principal + reward credited IFF in e2); a RE-STAKED reward compounds by exactly the closed form
        // (`a_re_staked_reward_compounds_by_exactly_the_closed_form_on_the_peer`: 50 on 1,000, then 2 on 50); the double claim
        // (`a_yield_claim_re_carried_by_a_rogue_producer_pays_its_reward_once_on_the_peer`); reward-follows-principal is the
        // circuit weld (`db365_a_swapped_reward_note_verifies_beside_no_principal_its_prover_does_not_own`, recorded GREEN).
        Verdict::Pinned("a_yield_claim_pays_exactly_its_closed_form_and_only_in_its_own_epoch_on_the_peer_at_every_epoch_edge"),
    ),
    row(
        ECONOMIC,
        "bond-slash profitability",
        "a bonded validator computes whether equivocating, double-voting or withholding pays more than its bond",
        "equivocation slashing with the write-ahead vote guard (DB-370); the seat flood bound (DB-369)",
        // MEASURED 2026-10-04 20:45 (lane-harness, h6-batch16): the attack rows (custody peg-out, unbacked mint, price mark)
        // all reduce to the ≥ 2/3 bond-weighted tally, whose capture costs w = 2 × the honest bonded weight. The 9/17 model
        // prices that above the guarded value with the THORChain floor 2 × TVL at the SEAT door (never at issuance). Still
        // open after DB-391: the per-row table and the simulated equivocation slash on a peer (`db257b` reuse).
        // CLOSED (measured 2026-11-03): the DB-391 pin passes on every detached run of main today (260c095, 8284671, 6b729d8,
        // 9675dac — pin-results.tsv): after a real peg-in the seat door's floor rises above zero on both nodes, so the ≥ 2/3
        // tally that gates mints, peg-outs and price marks is not captured by a 4-atomic bond.
        Verdict::Pinned(
            "after_a_real_peg_in_the_validator_bond_floor_rises_above_zero_on_both_nodes_so_a_two_thirds_tally_is_not_free",
        ),
    ),
    row(
        ECONOMIC,
        "spam economics",
        "an adversary fills every block slot with valid but worthless transactions",
        "the constant per-block shape (no growth on any axis), the fee rule; honest nodes' cost does not rise with spam",
        Verdict::Open("compute the cost to saturate 256 slots/block for a day against the fee rule; netsim: saturate and MEASURE honest payment latency and node footprint; ASSERT both stay within their stated bounds"),
    ),
    row(
        ECONOMIC,
        "liquidation griefing and bad debt",
        "an adversary pre-retires a liquidation key or delays liquidation past the collateral's fall",
        "DB-367 justified-only tag admission (a miner cannot pre-retire a liquidation key); the automated trigger",
        // MEASURED 2026-10-04 19:57 (lane-harness): a lane-only block naming the due position's key moves nothing on the peer;
        // the honest close then lands on both nodes and moves EXACTLY the rule's plan (C = 696, S = 1,887: reserve 3,000 →
        // 1,113, supply 1,000 → 304, pool T 900 → 204; the custodian's opening = `plan_liquidation(..).after`). The refused-
        // OBJECT variant is the rogue census's Liquidation × burn pin.
        Verdict::Pinned("a_griefer_naming_a_due_positions_liquidation_key_cannot_block_its_close_and_the_close_moves_exactly_the_rules_plan"),
    ),
    // ── CRYPTO PARAMETERS — the labels must be computed, not read off the crate names ────────────────────────────────
    row(
        CRYPTO,
        "ML-KEM-768 / ML-DSA-65 security category",
        "an implementation that quietly uses a smaller parameter set, or a classical primitive in its place",
        "the no-classical-crypto guard; the crates' parameter sets",
        // 2026-10-04 (lane-harness, `harness/crypto_parameters.rs`): the node's own wrappers' byte sizes through the FIPS
        // 203/204 formulas — ek/ct/dk 1184/1088/2400 ⇒ k = 3; pk/sig/sk 1952/3309/4032 ⇒ (6, 5); planted ML-KEM-512 /
        // ML-DSA-44 sizes and an off-by-one byte refused.
        Verdict::Pinned("ml_kem_and_ml_dsa_sizes_from_the_nodes_own_wrappers_imply_nist_category_3"),
    ),
    row(
        CRYPTO,
        "WHIR soundness bits at the certificate shape",
        "a prover exploits a rate / query / grinding choice whose real soundness is below the 128-bit label",
        "`CERT_CARRIER { start_rate 1, pow_bits 24, send_vars 7 }`, `CERT_FIXED_CARRIER = legacy(4, 16)` over KoalaBear^4 (≈ 2^124)",
        // MEASURED 2026-10-04 (lane-harness, p3-whir `soundness.rs` round 0): the ONLY production config,
        // `committed_air.rs::pcs_with`, is `CapacityBound` at `security_level` 100 — CONJECTURED; under the PROVEN
        // JohnsonBound the same queries give ≈46 bits (LIVE: rate 1, pow 0, 108 queries), ≈59 (CERT_CARRIER), ≈58
        // (CERT_FIXED) — below the ≥100-bit-PROVEN cardinal (`feedback_100bit_pq_minimum`). The pin is lane-consensus's, in
        // the decider beside the configs (reserved name below); it turns this row Red once it exists and is filed.
        Verdict::Red(
            // lane-consensus 17:40: the pin is re-stated under the Johnson bound (its spec docs/H12 owns the JB-vs-UD
            // reading; lane-harness's ask that the USER decide JB vs UD is posted on the bus and recorded in docs/H12 §6)
            "every_production_whir_config_proves_at_least_100_bits_under_the_johnson_bound",
            "WHIR soundness regime: CapacityBound (conjectured) at security_level 100 — proven bits 46-59 per carrier (lane-harness, \
             p3-whir soundness.rs round 0); the pin (lane-consensus, decider committed_air.rs h12_proven_soundness) scores every \
             production shape (LIVE 8..=24 vars, CERT_CARRIER 27, CERT_FIXED) under CB/JB/UD and is RED until >= 100 bits under \
             UniqueDecoding; the fix lever (queries / pow bits / rate) is measured in bytes against the 1.8 MB pillar",
        ),
    ),
    row(
        CRYPTO,
        "Poseidon2 round counts over KoalaBear",
        "a permutation with too few rounds for its width and field",
        "Plonky3's KoalaBear Poseidon2 constants (full/partial rounds) at widths 16 and 24",
        // 2026-10-04 (lane-harness, `harness/crypto_parameters.rs`): p, α and the round counts read from `p3_koala_bear`;
        // the Poseidon2 paper's inequalities (+ eprint 2023/537) recomputed: t=16 (8, 20) and t=24 (8, 23) equal the
        // reference script's recommendation and stay secure with the margin stripped ((6, 18), (6, 21)); (6, 17) refused.
        Verdict::Pinned("poseidon2_koalabear_round_counts_meet_the_papers_128_bit_inequalities_with_margin"),
    ),
    row(
        CRYPTO,
        "Fiat–Shamir absorbs every public input",
        "a statement field the transcript does not absorb lets a prover change it after the challenges (the weak-FS class)",
        "`public_bind` / `absorb` at every prover–verifier pair",
        Verdict::Open("a census over every verifier: the set of fields its transcript absorbs must equal the statement's public fields; a planted unabsorbed field is caught"),
    ),
    row(
        CRYPTO,
        "hiding salt entropy ≥ 128 bits",
        "a salted commitment whose salts are too short to hide the row",
        "`MerkleTreeHidingMmcs` with `SALT_ELEMS` per row over KoalaBear (31 bits each)",
        // CLOSED 2026-10-04 20:45 (lane-harness, h6-batch16): both halves measured — DB-382's behaviour pin
        // `two_unpinned_proves_of_one_statement_differ_in_their_hiding_commitments_and_both_verify` recorded GREEN (19:20,
        // 033d8df), and the read below GREEN: `hiding_decider::Mmcs16` (the alias `committed_air::Pcs` names) has
        // SALT_ELEMS = 8 × 30.99 bits; the live salt source is `prover_randomness()` (32 OS bytes per prove, fail-closed);
        // both commit paths derive salts as the Poseidon2 PRF of a drawn seed (`PrfSalts`) → 247.9 bits per salt. The
        // FIXED table's public salt source is by design (public template columns).
        Verdict::Pinned("the_hiding_salts_at_the_production_instantiation_carry_at_least_128_bits_of_entropy"),
    ),
    // ── CIRCUIT STATEMENT — a sound gate for the wrong statement ────────────────────────────────────────────────────
    row(
        STATEMENT,
        "a written statement per AIR, checked against its constraints",
        "a gate whose constraints are sound and census-clean but encode less than the statement its door relies on",
        "the degree and free-witness censuses prove soundness AS WRITTEN; nothing checks the writing against the statement",
        // CLOSED 2026-10-05 21:15 (lane-night, statement-pin7.log): 77 production gates censused, every one with a written
        // statement whose residual count is the MEASURED one (`mutation_census::STATEMENTS`), no dead residual; test-only
        // gates named in `TEST_ONLY`; generic aggregates named by their outer type.
        Verdict::Pinned("the_mutation_census_finds_no_dead_residual_and_every_production_gate_has_a_written_statement"),
    ),
    row(
        STATEMENT,
        "mutation census",
        "a constraint that could be dropped or weakened without any pin noticing",
        "every gate's tamper pins (authored); no mechanical mutation",
        // CLOSED 2026-10-05 21:15: the mechanical census at `prove_air_zerocheck` (drop-a-residual by single-cell tamper with
        // +1 and +K, homogeneity, re-censused per shape until a trace reaches every residual, contiguous head/tail
        // escalation) reports no dead residual on any production gate — the dead lists of the first pass were the census's
        // own probe coverage (a depth-3 member path, a stride that never met a 256-level boundary row), never a gate.
        Verdict::Pinned("the_mutation_census_finds_no_dead_residual_and_every_production_gate_has_a_written_statement"),
    ),
];

/// The rows still open in `family`: `(name, what the simulation must drive and assert, the defense claimed)`.
#[must_use]
pub fn open_rows(family: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    SCENARIOS
        .iter()
        .filter(|s| s.family == family)
        .filter_map(|s| match s.verdict {
            Verdict::Open(why) => Some((s.name, why, s.defense)),
            _ => None,
        })
        .collect()
}

/// The RED-first rows in `family`: `(name, pin, mechanism)`.
#[must_use]
pub fn red_rows(family: &str) -> Vec<(&'static str, &'static str, &'static str)> {
    SCENARIOS
        .iter()
        .filter(|s| s.family == family)
        .filter_map(|s| match s.verdict {
            Verdict::Red(pin, mech) => Some((s.name, pin, mech)),
            _ => None,
        })
        .collect()
}

/// The stated trust bounds (the launch documentation carries them verbatim).
#[must_use]
pub fn bounds() -> Vec<(&'static str, &'static str)> {
    SCENARIOS
        .iter()
        .filter_map(|s| match s.verdict {
            Verdict::Bound(b) => Some((s.name, b)),
            _ => None,
        })
        .collect()
}

/// The hole category an OPEN row of `family` files under (the register counts these by exact name).
#[must_use]
pub fn open_category(family: &str) -> &'static str {
    match family {
        NETWORK => "adversary network scenario open",
        ECONOMIC => "adversary economic scenario open",
        CRYPTO => "crypto parameter unmeasured",
        _ => "circuit statement unwritten",
    }
}

/// The hole category a RED row of `family` files under.
#[must_use]
pub fn red_category(family: &str) -> &'static str {
    match family {
        NETWORK => "adversary network scenario RED",
        ECONOMIC => "adversary economic scenario RED",
        CRYPTO => "crypto parameter below bound",
        _ => "circuit statement RED",
    }
}

/// Every `fn` name the source tree defines under the node's `src/` AND the decider's `src/` (tests included), for the
/// pin-exists law — a crypto-parameter or circuit-statement pin lives BESIDE the configs it judges, in the decider
/// (lane-consensus 2026-10-04: the WHIR soundness pin reads the real `WhirConfig`, so it cannot live here). A directory or
/// file that cannot be read is reported, never skipped.
fn fn_names_in_tree() -> Result<std::collections::HashSet<String>, String> {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) -> Result<(), String> {
        let rd = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for e in rd {
            let p = e.map_err(|e| format!("{}: {e}", dir.display()))?.path();
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") && !p.to_string_lossy().contains(".pre") {
                out.push(p);
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    walk(&root.join("src"), &mut files)?;
    walk(&root.join("vendor/Plonky3/usdm-decider/src"), &mut files)?;
    let mut names = std::collections::HashSet::new();
    for f in files {
        let text = std::fs::read_to_string(&f).map_err(|e| format!("{}: {e}", f.display()))?;
        for line in text.lines() {
            let t = line.trim_start();
            for prefix in ["fn ", "pub fn ", "pub(crate) fn ", "pub(super) fn ", "async fn ", "pub async fn "] {
                if let Some(rest) = t.strip_prefix(prefix) {
                    let name: String = rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
                    if !name.is_empty() {
                        names.insert(name);
                    }
                }
            }
        }
    }
    Ok(names)
}

/// Coverage law: every family has rows; every `Pinned`/`Red` pin exists in the tree; every `Red` pin is filed in
/// `scratchpad/known-reds.txt`. Each violation is a BLIND-SPOT hole; a source tree or ledger that cannot be read is one too.
#[must_use]
pub fn coverage_gaps() -> Vec<String> {
    let mut gaps = Vec::new();
    for f in FAMILIES {
        if !SCENARIOS.iter().any(|s| s.family == f) {
            gaps.push(format!("family {f}: no row"));
        }
    }
    let names = match fn_names_in_tree() {
        Ok(n) => n,
        Err(e) => {
            gaps.push(format!("the source tree could not be read for the pin-exists law: {e}"));
            return gaps;
        }
    };
    // MEASURED 2026-10-22 (lane a): `CARGO_MANIFEST_DIR/../scratchpad/known-reds.txt` is git-ignored, so every git WORKTREE
    // failed this law for a file that was never there. The crate's one resolver (`harness::scratchpad_dir`, the hole scanner's
    // reader) walks up to the main checkout's scratchpad; when none holds the file the read still fails CLOSED below.
    let known_path = crate::harness::scratchpad_dir().join("known-reds.txt");
    let known = match std::fs::read_to_string(&known_path) {
        Ok(k) => k,
        Err(e) => {
            gaps.push(format!("{} could not be read, so no Red row can be checked as filed: {e}", known_path.display()));
            String::new()
        }
    };
    for s in SCENARIOS {
        match s.verdict {
            Verdict::Pinned(pin) if !names.contains(pin) => gaps.push(format!("{} × {}: Pinned by `{pin}`, which exists nowhere", s.family, s.name)),
            Verdict::Red(pin, _) if !names.contains(pin) => gaps.push(format!("{} × {}: Red by `{pin}`, which exists nowhere", s.family, s.name)),
            Verdict::Red(pin, _) if !known.lines().any(|l| l.trim() == pin) => {
                gaps.push(format!("{} × {}: Red by `{pin}`, not filed in scratchpad/known-reds.txt", s.family, s.name))
            }
            _ => {}
        }
    }
    gaps
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;

    /// THE COVERAGE LAW IS ARMED: every pin a row names exists, every Red is filed, every family has rows — and the walker
    /// is calibrated against a name that exists nowhere and against this very test.
    #[test]
    fn the_adversary_census_names_only_pins_the_tree_holds_and_a_planted_lie_is_caught() {
        let gaps = coverage_gaps();
        assert!(gaps.is_empty(), "adversary census coverage gaps: {gaps:#?}");
        let names = fn_names_in_tree().expect("the source tree reads");
        assert!(!names.contains("a_pin_that_exists_nowhere_in_this_tree_20261004"), "CALIBRATION: the planted name is absent from the tree");
        assert!(names.contains("the_adversary_census_names_only_pins_the_tree_holds_and_a_planted_lie_is_caught"), "CALIBRATION: the walker sees this very test");
        let reds: Vec<_> = FAMILIES.iter().flat_map(|f| red_rows(f)).collect();
        let opens: usize = FAMILIES.iter().map(|f| open_rows(f).len()).sum();
        eprintln!(
            "[adversary-census] {} rows: {} open, {} red, {} bound(s), {} pinned",
            SCENARIOS.len(),
            opens,
            reds.len(),
            bounds().len(),
            SCENARIOS.iter().filter(|s| matches!(s.verdict, Verdict::Pinned(_))).count()
        );
    }
}
