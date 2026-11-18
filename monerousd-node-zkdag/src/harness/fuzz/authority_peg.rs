// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! **THE PEG AUTHORITY MANIFEST — WHOSE STATE IS EACH FIELD OF THE HIGHEST REAL-MONEY SURFACE?**
//!
//! `src/harness/fuzz/authority.rs` answers *"is this field the chain's or mine?"* once for every field
//! of `struct Node`. It answers it for `peg` as ONE field — `ChainDerived`, covered by the cold-peer
//! verdict through three reads (`reserve_commit`, `minted_commit`, the ratio census).
//!
//! ⛔ THAT IS NOT COVERAGE OF THE PEG, AND THE DIFFERENCE IS THE POINT OF THIS FILE. `PegLedger` had
//! **11 fields** when this file was written (the census below prints today's count). Three of them are read by the verdict; the other eight are exactly the shape §F of the
//! kill list names — *local state read as truth* — at the surface where real BTC and XMR enter and
//! leave. `POST /register_wrapped_asset` sat open for months for precisely this reason: from inside a
//! node a locally-set value is indistinguishable from a chain-set one, so nothing could see it until
//! something COMPARED it against a node fed only blocks.
//!
//! Every field here is money:
//!
//! | field | what a divergence costs |
//! |---|---|
//! | `reserve_commit` | the committed collateral behind every USDm — believe you are backed when you are not |
//! | `minted_commit` | the circulating total every >=2/3 solvency gate is computed against |
//! | `reserve_hwm_commit` | the ceiling a liquidation re-mark may not exceed — raise it and an UP-MARK-then-mint becomes provable |
//! | `wrapped_assets` | ⭐ kill-list item 5 lives here: a ratio decides how much USDm may exist per unit of collateral |
//! | `ratio_bps` / `redeem_floor_bps` / `yield_rate_bps` | the RULES — a node with different ones authorizes value moves its peers refuse |
//! | `spent_burns` | `authorize_reserve_release` pays the FOREIGN leg against this set: an entry with no burn behind it is real BTC leaving with no USDm destroyed |
//! | `confidential_deposit_ids` | one confirmed deposit mints exactly once — or does not |
//! | `liquidated` | one position closes exactly once per epoch — or its collateral is seized twice |
//! | `released` | one burn authorizes at most one foreign payout — **and this one is NOT RULED ON; see its entry** |
//! | `sat_issued` | ⭐ SATOSHI: the issued SAT total the 21,000,000 cap is checked against — a smaller one credits rewards past the cap the chain reached |
//! | `pendulum_epoch_next` / `pendulum_share_bps` | ⭐ SATOSHI §10.8: the pendulum's epoch snapshot — a different share pays custody yield at a rate the peers refuse |
//!
//! ── WHAT A CLASSIFICATION IS ─────────────────────────────────────────────────────────────────────
//! A FUNDS-SAFETY CLAIM, not a label. `ChainDerived` asserts *a node fed only blocks must reach this
//! same value*; `LocalCache` asserts *per-node divergence here is FINE*. On the peg the second one is
//! the dangerous direction: blessing divergence on a replay set is blessing a double payout. So a field
//! nobody can honestly rule on stays `Unclassified` — counted, capped, shrink-only — with the reason in
//! its comment. A wrong ruling is worse than an honest "not yet".
//!
//! ⛔ MEASURED, AND WORTH SAYING OUT LOUD: **there are ZERO `LocalCache` fields in `PegLedger`.** Every
//! remaining field is consensus-persisted. The struct's own doc comment still describes four
//! `#[serde(skip)]` custodian working fields (`positions` / `reserve` / `minted_usdm` /
//! `earned_fee_surplus_usdm`) — those fields NO LONGER EXIST; the commitment-only rework removed them.
//! The comment is stale, not the classification.
//!
//! ⛔ SCOPE, stated rather than implied: [`peg_divergences`] is a PURE FUNCTION over two ledgers. It
//! says whether a party's peg agrees with a peg derived some other way; it does not itself derive one
//! from blocks. Wiring it to the cold replay inside `Sim::cold_peer_verdict` is the next brick and is
//! NOT claimed here — `consensus_scenarios.rs` is held by another crew this session.

use crate::harness::fuzz::authority::Authority;
use crate::peg::PegLedger;

/// Every field of `struct PegLedger`, with who decides it. Ordered as the struct declares them, so a
/// reader can hold the two side by side.
pub const PEG_AUTHORITY_MANIFEST: &[(&str, Authority)] = &[
    // The two value-hiding digests that ARE the peg. Advanced only by `peg_in_confidential`,
    // `peg_out_confidential`, `claim_reserve_yield` and `liquidate_confidential` — every one gated on a
    // >=2/3 bonded ML-DSA threshold and/or a WHIR carrier proven against the persisted pair. A node
    // holding either value the chain did not produce is lying to its holders about whether their USDm
    // is redeemable.
    // ⛔ THE RETENTION ENDOWMENT'S COMMITMENT. It is the pot every miner's storage payout is drawn
    // from (`pay_miner_from_endowment`) and every retention fee credits (`credit_retention_endowment`),
    // so a node holding a value the chain did not produce would pay out of a balance nobody funded —
    // the same shape as a reserve commit nobody attested. It is therefore CHAIN-DERIVED by construction.
    //
    // ⛔ AND IT IS NOT WIRED YET, WHICH IS WHY IT IS DECLARED BEFORE IT MOVES. Both doors exist and
    // NEITHER is called from production: a public endowment balance would re-publish the real note
    // count that the 256-slot cover padding exists to hide, so the credit/payout pair waits on a
    // committed endowment-transition carrier. Declaring it now means the day it starts moving, the
    // divergence census already knows which side decides it.
    ("retention_endowment_commit", Authority::ChainDerived),
    ("reserve_commit", Authority::ChainDerived),
    ("minted_commit", Authority::ChainDerived),
    // THE REPLAY GUARDS. `spent_burns` is the sharpest field in the struct:
    // `Node::authorize_reserve_release` releases the FOREIGN asset only for a nullifier this set holds,
    // so an entry the chain never produced is BTC leaving custody with no USDm destroyed behind it, and
    // a MISSING entry is a user's redemption refused. Either direction is a funds event, so the set has
    // to be a function of the chain.
    ("spent_burns", Authority::ChainDerived),
    // One confirmed foreign deposit mints exactly once. A node whose set is short of the chain's mints
    // a second time against a deposit that has already paid out — free issuance.
    ("confidential_deposit_ids", Authority::ChainDerived),
    // §DD interim: the ids ONE block's objects inserted, drained after every apply — a local scratch list.
    ("applied_ids", Authority::LocalCache),
    // THE RULES. Not state — the yardstick every peg gate is measured against. A node applying a
    // different mint ratio, redeem floor or yield rate authorizes value moves its peers refuse, and
    // every gate it runs agrees with itself perfectly because they all share the wrong yardstick. That
    // is the batch-3 `params` argument, at the surface where the numbers actually move money.
    //
    // ⛔ NOTE, and it is the "two copies of the rules" question the kill list found in the node:
    // `ratio_bps` here is a SECOND copy of `ChainParams::mint_ratio_bps`. Both are declared
    // `ChainDerived` — by this manifest and by `authority.rs` — which is the only consistent ruling,
    // and it means a divergence between the two copies is a finding for whichever comparison sees it
    // first, not a matter of taste.
    ("ratio_bps", Authority::ChainDerived),
    ("yield_rate_bps", Authority::ChainDerived),
    ("redeem_floor_bps", Authority::ChainDerived),
    // ⛔⛔ NOT RULED ON — AND THE REASON IS NOT LAZINESS.
    //
    // `released` is the single-use guard on the WITHDRAWAL's foreign-settlement leg: one burned
    // nullifier authorizes at most one real BTC/XMR payout. Its only writer is
    // `POST /authorize_reserve_release` — an RPC route, >=2/3-PQ-cert-gated but with NO BLOCK anywhere
    // — and the set IS consensus-persisted (it serializes into both the disk state and the DSYNC
    // bundle).
    //
    // Ruling it `ChainDerived` would assert a block-carried class that does not exist: nothing in the
    // tree publishes a release, so EVERY honest node would diverge and the claim would be false on day
    // one. Ruling it `LocalCache` would assert that per-node divergence here is FINE — which blesses
    // replaying one >=2/3 cert at a second node whose set is empty, getting a second `Authorized`, and
    // draining the reserve twice for one burn. That is the E-7 shape ("the burn was LOCAL and never
    // travelled; the lot paid out twice") pointed at real custody.
    //
    // The honest answer is that the design has not said WHERE the single-use guard is authoritative —
    // on this chain, or at the custodian's foreign signer, which is the party that actually broadcasts
    // the payout. Until it does, this stays counted and capped, and NOTHING compares it: a comparison
    // encodes the very claim being declined.
    ("released", Authority::Unclassified),
    // The per-asset PSMs — ⭐ KILL-LIST ITEM 5's HOME. A wrapped asset's ratio decides how much may be
    // minted against a unit of that collateral, and `POST /register_wrapped_asset` writes it with no
    // threshold, no vote and no block. Declaring the map `ChainDerived` is what makes that write a
    // FINDING instead of a comment in a route handler.
    ("wrapped_assets", Authority::ChainDerived),
    // The bound the liquidation door may not exceed. `liquidate_confidential` deliberately cannot raise
    // it — but a node that simply HOLDS a higher one gets the same effect without touching the door,
    // and an UP-MARK past collateral that was never deposited becomes provable. That is the exact
    // inflation the ge256 high-water bound exists to make impossible.
    ("reserve_hwm_commit", Authority::ChainDerived),
    // Positions closed by the liquidation door. Its own source says a repeat "arrives as BYTES FROM A
    // PEER — a re-broadcast of the block-carried object", and `chain_object::Class::Liquidation = 6` is
    // that object: so this set IS block-derived by design, and two nodes that disagree about it seize
    // one position's collateral twice.
    ("liquidated", Authority::ChainDerived),
    // ⛔⛔⛔ DB-124's HOME. What one external atomic unit is WORTH decides how much USDm may be issued
    // against a deposit — the same authority question `wrapped_assets` carries for the ratio, on the
    // other operand of the same inequality. Before this field existed the peg had no price at all and
    // counted one piconero as one USDm atomic unit, so 1 XMR could mint ~$6.67B at the 150% ratio.
    // `mark_price_attested` (driven by a block-carried `Class::PriceMark`) is its ONLY writer, so it is
    // ChainDerived by construction; declaring it here is what makes any future local write a FINDING.
    ("price_marks", Authority::ChainDerived),
    // ⭐ LIQUIDATION SPEC §10 — the stability pools' committed words (T, P, S, epoch). Written ONLY by the block-carried
    // pool classes at their fold (`Class::PoolDeposit`, `Class::PoolWithdraw`, then the liquidation) and adopted from the
    // certified bundle; a node holding a pool
    // the chain never produced would key a receipt to a snapshot no deposit made, or retire debt against USDm the pool
    // does not hold. ChainDerived by construction, compared from the same change.
    ("pools", Authority::ChainDerived),
    // LIQUIDATION §10 — each CLOSED pool epoch's closing `(P, S)` words. Written ONLY by the liquidation door when a
    // block-carried liquidation drains the pool, and adopted from the certified bundle (they ride `pool_census` beside
    // the current words). A party holding a close the chain never made would let that epoch's receipts withdraw against
    // a product and sum no liquidation produced. Compared by the same census comparison as `pools`.
    ("pool_closes", Authority::ChainDerived),
    // ⭐ SATOSHI — the issued SAT total under the 21,000,000 cap. Written ONLY by the reward fold (`credit_sat_reward`, driven
    // by the block-carried `Class::SatoshiReward`) and adopted from the certified bundle (`adopt_certified_sat`). A party
    // holding a smaller total credits rewards past the cap the chain reached — SAT issued on that node that no peer counts —
    // and a larger one refuses rewards every peer credits. The pendulum's share is keyed on it too.
    ("sat_issued", Authority::ChainDerived),
    // ⭐ SATOSHI §10.8 — the pendulum's epoch snapshot `(epoch + 1, bonders' share)`. Written ONLY at the first fold step of a
    // stake epoch from that step's pre-state, and adopted from the certified bundle. A party holding a different share pays
    // custody yield at a rate its peers refuse, or refuses claims they credit.
    ("pendulum_epoch_next", Authority::ChainDerived),
    ("pendulum_share_bps", Authority::ChainDerived),
    // ⭐ §BR (2026-10-28/29) — the §BR build's ledger words: the four fee pools (§BR-14), the miner-pool quarter (§BR-11),
    // the bonders' yield index and accrual (§BR-3 17.6), the set-aside flag (§BR-13), the deployment ledger and release
    // attestations (§BR-10), the stakers' paid-out commitment and epoch pool snapshot (§BR-3 17.6). Every one is written
    // only by a journaled fold step, carried by the certified bundle (`PegBrWords`) and compared by `peg_divergences`.
    // §BR-12 L1: the contract-state root — written only by a journaled fold step from a deploy's or a call's carried path,
    // carried by the certified bundle (`PegBrWords`), compared by `peg_divergences`.
    ("contract_state_root", Authority::ChainDerived),
    ("fee_pool_stakers", Authority::ChainDerived),
    ("fee_pool_bonders", Authority::ChainDerived),
    ("fee_pool_surplus", Authority::ChainDerived),
    ("fee_pool_miner", Authority::ChainDerived),
    ("miner_quarter_next", Authority::ChainDerived),
    ("miner_rate", Authority::ChainDerived),
    ("miner_accrual", Authority::ChainDerived),
    ("miner_quarter_start", Authority::ChainDerived),
    ("bond_yield_lo", Authority::ChainDerived),
    ("bond_yield_hi", Authority::ChainDerived),
    ("bonder_accrual", Authority::ChainDerived),
    ("set_aside_applied", Authority::ChainDerived),
    ("deployments", Authority::ChainDerived),
    ("release_attestations", Authority::ChainDerived),
    ("stake_paid_commit", Authority::ChainDerived),
    ("stakers_snap_epoch_next", Authority::ChainDerived),
    ("stakers_snap_pool", Authority::ChainDerived),
    ("price_history", Authority::ChainDerived),
    // ⭐ §BR-9a — the epoch-key ledger: written only by a journaled fold step (the epoch tick and `Class::EpochKeyDeal`),
    // carried by the certified bundle (`PegBrWords`). A party holding another roster, key sum or dealer record seals cash-out
    // tickets to a key no custody can open, or refuses deals its peers apply.
    ("epoch_keys", Authority::ChainDerived),
    // ⭐ §19.4 — the epoch anchors: pushed only by the canonical fold step (an anchor ordinal's spine root), cut back by a
    // rewind, journaled, carried in `PegBrWords`. A party holding another anchor set admits a cash-out claim its peers refuse
    // (or refuses one they burn) — compared by the §BR census, refuted below.
    ("epoch_anchors", Authority::ChainDerived),
    // §BR-3 17.5 (the repayment pot, the open theft loss, the owed, the haircut) and §BR-8 B8-a (the decoy epoch, credit,
    // budget, spent and the open obligations): written only by journaled fold steps, carried in `PegBrWords`, compared
    // by the §BR census and refuted below (`peg_br_ledger_word_comparison_fires_on_each_word_alone`).
    ("repayment_sat_pot", Authority::ChainDerived),
    ("theft_loss_open_sats", Authority::ChainDerived),
    ("repayment_owed_atomic", Authority::ChainDerived),
    ("haircut_remainder_atomic", Authority::ChainDerived),
    ("haircut_events", Authority::ChainDerived),
    ("decoy_epoch_next", Authority::ChainDerived),
    ("decoy_credit", Authority::ChainDerived),
    ("decoy_budget", Authority::ChainDerived),
    ("decoy_spent", Authority::ChainDerived),
    ("open_decoys", Authority::ChainDerived),
    // §BR-4/§BR-7: the debt-unit book — fold-written, carried in `PegBrWords`, refuted below.
    ("unit_book", Authority::ChainDerived),
    ("defi_book", Authority::ChainDerived),
    // SAFE AT SCALE, stage three (spec §3f): the custody key record (`Class::VaultKey` takes and retires, journaled) and
    // the bonders' cost words (raised by `Class::ReserveCost`, paid down by the fee credit of every fold step) — carried
    // in `PegBrWords`, compared by the §BR census and refuted below.
    ("vault_keys", Authority::ChainDerived),
    // spec §3g.1: the parts at rest (`Class::VaultRebalance` carves, takes and cancels, journaled) — carried in
    // `PegBrWords::vault_parts`, compared by the §BR census and refuted below.
    ("vault_parts", Authority::ChainDerived),
    ("custody_cost_debt", Authority::ChainDerived),
    ("custody_cost_retired", Authority::ChainDerived),
    // IonSwap pools (lane goods; declared 2026-11-12 by the lane that added them, after the manifest pins read them
    // missing): the pending orders, the pool layer's USDm word and the pool count. Fold-written, journaled, carried in
    // `PegBrWords::ion` and bound by the bundle's digest, so the §BR census compares them (`br_census()` holds them);
    // refuted in `peg_br_ledger_word_comparison_fires_on_each_word_alone`.
    ("ion_pending", Authority::ChainDerived),
    ("ion_usdm_held", Authority::ChainDerived),
    ("ion_pools", Authority::ChainDerived),
    // The USDm fee part the settlements of the fold step being folded owe the fee pools, drained into that same step's
    // one fee credit (`take_ion_fee_credit`): one step's scratch, never persisted, carried or served (`applied_ids`' class).
    ("ion_fee_credit", Authority::LocalCache),
    // A-F31 / A-F34 (lane goods): the TOKEN REGISTRY, every created asset's descriptor leaf in one accumulator. Fold-written
    // by a creation, journaled and un-done with its step (`PegUndo::dsol_tokens`), carried in the snapshot and the
    // certified bundle beside the ledger (`sync_binding`). A mint is admitted only for an asset whose creation it holds,
    // so a party holding another registry mints what its peers refuse. Compared by its root and count in
    // `peg_divergences`; refuted in `the_token_registry_comparison_fires_on_one_creation_more`.
    ("dsol_tokens", Authority::ChainDerived),
];

/// The ceiling on `Unclassified` peg fields. **MAY BE LOWERED, NEVER RAISED.**
///
/// ⛔ NOT A CHOSEN NUMBER — A MEASUREMENT taken 2026-09-09 by reading every writer of every field:
///     11 fields in `struct PegLedger` − 10 whose writer makes the authority decidable = **1**
///     (`released`, whose only writer is an RPC route with no block, and whose ruling the design has
///     not made — see its manifest entry for why BOTH available rulings would be false today).
///
/// Lowering it is the work, and for `released` the work is a DESIGN decision, not a test: either the
/// release joins the block-carried class (then it is `ChainDerived` and gets a comparison) or the
/// single-use guard is stated to be authoritative at the custodian's foreign signer (then it is
/// `LocalCache`, and the second-node cert replay needs its own answer).
pub const MAX_PEG_UNCLASSIFIED: usize = 1;

/// The `ChainDerived` peg fields [`peg_divergences`] ACTUALLY COMPARES today.
///
/// ⛔⛔⛔ THE GAP THIS LIST EXISTS TO MEASURE. `ChainDerived` is a CLAIM, and a claim nothing compares
/// reads as covered while protecting nothing — worse than an honest `Unclassified`, which at least
/// counts itself. A field enters this list ONLY together with the refutation that proves its
/// comparison can go red; every name below has one in this file.
pub const PEG_COLD_COMPARED: &[&str] = &[
    // Added with the field itself (2026-09-23) rather than after it — a ChainDerived field that lands
    // uncompared joins the "nothing would notice" pile, which is how kill-list item 5 stayed invisible.
    "retention_endowment_commit",
    "reserve_commit",
    "minted_commit",
    "reserve_hwm_commit",
    "ratio_bps",
    "yield_rate_bps",
    "redeem_floor_bps",
    "wrapped_assets",
    "price_marks",
    "spent_burns",
    "confidential_deposit_ids",
    // LIQUIDATION §10: added with the field (2026-10-02), its refutation beside the others below.
    "pools",
    // LIQUIDATION §10 v2: the closed epochs ride the same census; refuted beside `pools` below.
    "pool_closes",
    // SATOSHI: added with the fields' carriage (2026-10-05); refuted below.
    "sat_issued",
    "pendulum_epoch_next",
    "pendulum_share_bps",
    // §BR: added with the fields' carriage (2026-10-29); compared as one census, refuted below.
    // §BR-12 L1 (2026-11-01): the contract-state root, carried in `PegBrWords`.
    "contract_state_root",
    "fee_pool_stakers",
    "fee_pool_bonders",
    "fee_pool_surplus",
    "fee_pool_miner",
    "miner_quarter_next",
    "miner_rate",
    "miner_accrual",
    "miner_quarter_start",
    "bond_yield_lo",
    "bond_yield_hi",
    "bonder_accrual",
    "set_aside_applied",
    "deployments",
    "release_attestations",
    "stake_paid_commit",
    "stakers_snap_epoch_next",
    "stakers_snap_pool",
    "price_history",
    // §BR-9a: added with the field (2026-10-29); refuted in `peg_br_ledger_word_comparison_fires_on_each_word_alone`.
    "epoch_keys",
    // §19.4: added with the field (2026-11-01); refuted in `peg_br_ledger_word_comparison_fires_on_each_word_alone`.
    "epoch_anchors",
    // §BR-3 17.5 + §BR-8 B8-a: compared in the same §BR census, refuted below.
    "repayment_sat_pot",
    "theft_loss_open_sats",
    "repayment_owed_atomic",
    "haircut_remainder_atomic",
    "haircut_events",
    "decoy_epoch_next",
    "decoy_credit",
    "decoy_budget",
    "decoy_spent",
    "open_decoys",
    "unit_book",
    "defi_book",
    // SAFE AT SCALE, stage three: compared in the same §BR census (`PegBrWords::vault_keys`, words 23 and 24), refuted below.
    "vault_keys",
    "vault_parts",
    "custody_cost_debt",
    "custody_cost_retired",
    // IonSwap pools: compared in the same §BR census (`PegBrWords::ion`), refuted with it.
    "ion_pending",
    "ion_usdm_held",
    "ion_pools",
    // the token registry: its own comparison by root and count, refuted on its own.
    "dsol_tokens",
];

/// The ceiling on `ChainDerived` peg fields NOT yet compared. **MAY BE LOWERED, NEVER RAISED.**
///
/// ⛔ NOT A CHOSEN NUMBER — A MEASUREMENT taken 2026-09-09 from this file:
///     10 fields declared `ChainDerived` − 9 named in [`PEG_COLD_COMPARED`] = **1**.
///
/// The one is `liquidated`, and it is uncompared for a REASON recorded in `src/peg.rs` rather than
/// invented here: an `is_liquidated` read accessor was written at that site and DELETED before
/// shipping, because a second reader of that set is precisely the shape a future caller wires up
/// INSTEAD of going through the door. The set has exactly ONE reader — the door — and the only way to
/// learn a position's state is to ask it. Adding a reader to make this number 0 would overturn another
/// author's deliberate, documented ruling in order to flatter a count, which is the same failure as a
/// wrong classification. Closing it wants the door itself to publish a census, or the comparison to
/// ride the block-carried `Class::Liquidation` objects instead of the set.
///
/// It is written down rather than computed so that ADDING a chain-derived field cannot silently raise
/// the backlog: a new declaration pushes the live count past this ceiling and fails.
pub const MAX_UNCHECKED_PEG_CHAIN_DERIVED: usize = 1;

/// Push one divergence, phrased so a reader lands in the right subsystem AND knows what it costs.
fn note(out: &mut Vec<String>, what: &str, chain: String, node: String, cost: &str) {
    out.push(format!(
        "{what}: a ledger derived from the CHAIN holds {chain}, this party holds {node}. {cost}"
    ));
}

/// ⛔ THE PEG COMPARISON — every `ChainDerived` field named in [`PEG_COLD_COMPARED`], checked against a
/// ledger derived some other way, with the funds consequence attached to each finding.
///
/// `chain` is whatever the caller can defend as the chain's answer — in the harness, the peg of a node
/// fed ONLY blocks. `node` is the party under audit. `burn_probes` are nullifiers the caller has
/// evidence for; membership is compared for each.
///
/// ⛔ WHAT THIS DOES NOT SEE, said plainly rather than left for someone to discover:
///   * `spent_burns` and `confidential_deposit_ids` are compared by SIZE plus the supplied probes. Two
///     sets of EQUAL SIZE holding different entries, none of them named by a probe, stay invisible.
///     Sizes are the established standard here (the cold-peer verdict compares
///     `order_book_len_for_audit` the same way, for the same privacy reason: a size is chain-public,
///     the entries are not) — it is a bound, and it is written down as one.
///   * `released` is NOT compared, deliberately. See its manifest entry.
///   * `liquidated` is NOT compared. See [`MAX_UNCHECKED_PEG_CHAIN_DERIVED`].
pub fn peg_divergences(chain: &PegLedger, node: &PegLedger, burn_probes: &[[u8; 32]]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if chain.reserve_commit() != node.reserve_commit() {
        note(
            &mut out,
            "peg reserve commitment",
            format!("{:?}", chain.reserve_commit()),
            format!("{:?}", node.reserve_commit()),
            "That digest is the committed collateral behind every USDm in existence. A party holding a \
             reserve figure the chain did not produce believes it is backed when it is not, which is \
             the whole of a stablecoin failure.",
        );
    }
    // ⛔ THE RETENTION ENDOWMENT. Declared ChainDerived when it was added, so it is compared here from
    // the same change rather than joining the "not yet compared" pile — a chain-derived field with no
    // comparison is a peg value a node could hold that no block produced, with nothing to notice.
    if chain.retention_endowment_commit() != node.retention_endowment_commit() {
        note(
            &mut out,
            "retention endowment commitment",
            format!("{:?}", chain.retention_endowment_commit()),
            format!("{:?}", node.retention_endowment_commit()),
            "That digest is the pot every miner's storage payout is drawn from. A party holding an \
             endowment figure the chain did not produce would pay out of a balance nobody funded, or \
             refuse a payout the chain already authorised — issuance in one direction, a broken \
             promise to the operator storing the data in the other.",
        );
    }
    if chain.minted_commit() != node.minted_commit() {
        note(
            &mut out,
            "peg minted (circulating supply) commitment",
            format!("{:?}", chain.minted_commit()),
            format!("{:?}", node.minted_commit()),
            "Every >=2/3 solvency gate is computed against the circulating total. A party that commits \
             to a smaller one will authorize mints the reserve cannot cover.",
        );
    }
    if chain.reserve_hwm_commit() != node.reserve_hwm_commit() {
        note(
            &mut out,
            "peg reserve high-water mark",
            format!("{:?}", chain.reserve_hwm_commit()),
            format!("{:?}", node.reserve_hwm_commit()),
            "The high-water mark is the ceiling a liquidation re-mark may never exceed. A party holding \
             a higher one can prove an UP-MARK to collateral that was never deposited, and then mint \
             against it — the up-mark-then-mint inflation the ge256 bound exists to make unprovable.",
        );
    }
    if chain.ratio_bps() != node.ratio_bps() {
        note(
            &mut out,
            "peg mint collateral ratio",
            format!("{} bps", chain.ratio_bps()),
            format!("{} bps", node.ratio_bps()),
            "This is a RULE, not state. A party with a lower ratio authorizes mints its peers refuse, \
             against collateral that does not cover them — and every gate on that node agrees with \
             itself perfectly, because they are all measured against the same wrong yardstick.",
        );
    }
    if chain.redeem_floor_bps() != node.redeem_floor_bps() {
        note(
            &mut out,
            "peg redeem solvency floor",
            format!("{} bps", chain.redeem_floor_bps()),
            format!("{} bps", node.redeem_floor_bps()),
            "The floor is the line below which a redemption stops being provable. A party holding a \
             lower one lets a Sell draw the reserve past full backing, and the USDm left behind is no \
             longer redeemable for a dollar.",
        );
    }
    if chain.yield_rate_bps() != node.yield_rate_bps() {
        note(
            &mut out,
            "peg reserve-yield rate",
            format!("{} bps", chain.yield_rate_bps()),
            format!("{} bps", node.yield_rate_bps()),
            "`claim_reserve_yield` proves `yield <= stake*rate` against this number. A party holding a \
             higher one accepts a self-minted yield its peers reject: USDm created against nothing.",
        );
    }

    // ── THE PRICE MARKS (DB-124) ─────────────────────────────────────────────────────────────────
    // The other operand of the solvency inequality. Two nodes agreeing on every ratio and every
    // commitment still disagree about whether the peg is solvent if they price a unit differently.
    if chain.price_mark_census() != node.price_mark_census() {
        note(
            &mut out,
            "price-mark census",
            format!("{:?}", chain.price_mark_census()),
            format!("{:?}", node.price_mark_census()),
            "A price mark decides what a deposit is WORTH, so it decides how much USDm may be issued \
             against it. A node standing on a mark the chain never set is measuring solvency against \
             its own number — and before DB-124 there was no mark at all, so the peg counted one \
             piconero as one USDm atomic unit and 1 XMR could mint ~$6.67 BILLION at the 150% ratio.",
        );
    }
    // ── THE STABILITY POOLS (LIQUIDATION §10) ─────────────────────────────────────────────────────
    if chain.pool_census() != node.pool_census() {
        note(
            &mut out,
            "stability-pool census",
            format!("{:?}", chain.pool_census()),
            format!("{:?}", node.pool_census()),
            "A pool's words decide every deposit's snapshot and every liquidation's retire leg. A party holding pool \
             words the chain never produced keys receipts to a snapshot no deposit made, or retires supply against USDm \
             the pool does not hold — a receipt that withdraws more than it paid in, or debt retired by nothing.",
        );
    }
    // ── SATOSHI (SAT) ─────────────────────────────────────────────────────────────
    let (chain_issued, chain_pendulum) = chain.sat_census();
    let (node_issued, node_pendulum) = node.sat_census();
    if chain_issued != node_issued {
        note(
            &mut out,
            "SAT issued total",
            format!("{chain_issued}"),
            format!("{node_issued}"),
            "The 21,000,000 cap is checked against this total. A party holding a smaller one credits rewards past the cap \
             the chain reached — SAT on that node that no peer counts — and a larger one refuses rewards every peer credits.",
        );
    }
    if chain_pendulum != node_pendulum {
        note(
            &mut out,
            "SAT pendulum snapshot",
            format!("{chain_pendulum:?}"),
            format!("{node_pendulum:?}"),
            "The bonders' share decides the custody-yield rate of the whole epoch. A party holding a different snapshot pays \
             claims its peers refuse, or refuses claims they credit.",
        );
    }
    // ── §BR (the pools, quarters, yield index, set-aside, deployments, attestations, stake snapshot) ──────────────
    let (chain_br, node_br) = (chain.br_census(), node.br_census());
    if chain_br != node_br {
        note(
            &mut out,
            "§BR ledger words",
            format!("{:?}", chain_br.words),
            format!("{:?}", node_br.words),
            "The fee pools pay the miner payouts, the bonders' yield and the stake rewards; the quarter and index words decide \
             what each claim is owed; the deployment ledger decides which rules are enforced. A party holding other words pays \
             claims its peers refuse, or refuses claims they apply.",
        );
    }
    // ── THE TOKEN REGISTRY (A-F31 / A-F34): every created asset's descriptor, one accumulator ──────────────────────
    let (chain_tok, node_tok) = ((chain.dsol_tokens().root_bytes(), chain.dsol_tokens().count()), (node.dsol_tokens().root_bytes(), node.dsol_tokens().count()));
    if chain_tok != node_tok {
        note(
            &mut out,
            "token registry",
            format!("{chain_tok:?}"),
            format!("{node_tok:?}"),
            "A mint is admitted only for an asset whose creation the registry holds. A party holding another registry admits \
             a supply its peers refuse, or refuses one they credit: an asset's whole supply on one node and none on another.",
        );
    }
    // ── THE WRAPPED-ASSET PSMs ───────────────────────────────────────────────────────────────────
    // The census first, because it is the read that makes kill-list item 5 visible; then each asset's
    // own digests, because a matching census with different commitments is a different (and quieter)
    // failure — the ratios agree while the collateral behind them does not.
    if chain.collateral_ratio_census() != node.collateral_ratio_census() {
        note(
            &mut out,
            "wrapped-asset collateral ratio census",
            format!("{:?}", chain.collateral_ratio_census()),
            format!("{:?}", node.collateral_ratio_census()),
            "A collateral ratio decides how much USDm may be minted against an asset, and \
             `POST /register_wrapped_asset` writes it with NO threshold, NO governance vote and NO \
             block (kill-list item 5). Dropping a volatile asset from 15000 to 10000 removes the 150% \
             buffer — 50% more USDm against the same collateral.",
        );
    }
    let mut assets: Vec<u32> = chain
        .collateral_ratio_census()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    for (id, _) in node.collateral_ratio_census() {
        if !assets.contains(&id) {
            assets.push(id);
        }
    }
    assets.sort_unstable();
    for id in assets {
        if chain.wrapped_asset_commits(id) != node.wrapped_asset_commits(id) {
            note(
                &mut out,
                &format!("wrapped-asset PSM commitments (asset {id})"),
                format!("{:?}", chain.wrapped_asset_commits(id)),
                format!("{:?}", node.wrapped_asset_commits(id)),
                "Each wrapped asset is an independent PSM with its own reserve and circulating \
                 digests. A party holding a pair the chain did not produce is wrong about what backs \
                 that wrapped token, in exactly the way it could be wrong about USDm.",
            );
        }
        if chain.wrapped_asset_hwm_commit(id) != node.wrapped_asset_hwm_commit(id) {
            note(
                &mut out,
                &format!("wrapped-asset reserve high-water mark (asset {id})"),
                format!("{:?}", chain.wrapped_asset_hwm_commit(id)),
                format!("{:?}", node.wrapped_asset_hwm_commit(id)),
                "The per-asset high-water mark bounds a liquidation re-mark of THAT asset by the \
                 collateral really deposited for it. A higher one lets the one liquidation door mark a \
                 wrapped PSM up past collateral it never held.",
            );
        }
    }

    // ── THE REPLAY GUARDS ────────────────────────────────────────────────────────────────────────
    if chain.spent_burn_count_for_audit() != node.spent_burn_count_for_audit() {
        note(
            &mut out,
            "burned-USDm nullifier set size",
            format!("{} entries", chain.spent_burn_count_for_audit()),
            format!("{} entries", node.spent_burn_count_for_audit()),
            "`Node::authorize_reserve_release` releases the FOREIGN asset only against a nullifier this \
             set holds. An entry the chain never produced is real BTC/XMR leaving custody with no USDm \
             destroyed behind it; a missing one is a holder's redemption refused.",
        );
    }
    for nf in burn_probes {
        if chain.is_burned(nf) != node.is_burned(nf) {
            note(
                &mut out,
                "burned-USDm nullifier membership",
                format!("burned = {}", chain.is_burned(nf)),
                format!("burned = {}", node.is_burned(nf)),
                "One party will authorize a foreign reserve release for this nullifier and the other \
                 will not. Whichever is wrong, one burn has stopped meaning exactly one payout.",
            );
        }
    }
    if chain.confidential_deposit_id_count_for_audit() != node.confidential_deposit_id_count_for_audit()
    {
        note(
            &mut out,
            "confidential peg-in deposit-id set size",
            format!("{} entries", chain.confidential_deposit_id_count_for_audit()),
            format!("{} entries", node.confidential_deposit_id_count_for_audit()),
            "This set makes one confirmed foreign deposit mint exactly once. A party short of the \
             chain's will mint a second time against a deposit that has already paid out.",
        );
    }

    out
}

#[cfg(all(test, feature = "pins-harness"))]
mod manifest {
    use super::*;
    use crate::peg::{DEFAULT_MINT_RATIO_BPS, DEFAULT_REDEEM_FLOOR_BPS};

    /// wBTC — a VOLATILE wrapped asset, registered at the 150% buffer.
    const WBTC: u32 = 1;
    /// wDAI — a vetted STABLECOIN, registered at 1:1 (exempt from the volatility buffer).
    const WDAI: u32 = 3;
    /// An asset id the honest ledger never registers — used to build a PSM one side has and the other
    /// does not.
    const WETH: u32 = 9;

    /// Parse the field names of `struct PegLedger` straight out of the source.
    ///
    /// ⭐ SOURCE-ABSENCE TECHNIQUE, copied from `authority::manifest::node_fields` on purpose. A missing
    /// classification is an ABSENCE, and an absence has no runtime handle to observe — reading the
    /// source is the only way it becomes assertable at all. Same parse, same failure mode if the
    /// struct's shape changes, and the non-vacuity assertion in the caller is what catches that.
    fn peg_fields() -> Vec<String> {
        let src = include_str!("../../peg.rs");
        let start = src
            .find("pub struct PegLedger {")
            .expect("struct PegLedger exists");
        let mut depth = 0usize;
        let mut end = start;
        for (k, ch) in src[start..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        for line in src[start..end].lines() {
            let mut t = line.trim_start();
            if line.len() - t.len() != 4 || t.starts_with("//") || t.starts_with("/*") {
                continue;
            }
            if let Some(rest) = t.strip_prefix("pub(crate) ") {
                t = rest;
            } else if let Some(rest) = t.strip_prefix("pub ") {
                t = rest;
            }
            if let Some(colon) = t.find(':') {
                let name = t[..colon].trim();
                if !name.is_empty() && name.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
                {
                    out.push(name.to_string());
                }
            }
        }
        out
    }

    /// An honest ledger: exactly what the live node constructs (`PegLedger::genesis(15_000)`, the call
    /// at `Node::new`), walked through REAL public doors so the baseline is not an empty struct.
    ///
    /// Built by CALLING THIS TWICE rather than by cloning, so the negative controls prove the
    /// comparison is silent on two INDEPENDENTLY derived ledgers — which is the real question — and not
    /// merely on a memcpy of one.
    fn honest_ledger() -> PegLedger {
        let mut l = PegLedger::genesis(DEFAULT_MINT_RATIO_BPS);
        l.register_wrapped_asset(WBTC, 15_000); // volatile — carries the 150% buffer
        l.register_wrapped_asset(WDAI, 10_000); // vetted stablecoin — exempt, 1:1
        l.set_redeem_floor_bps(11_000); // governance raised the buffer above the 100% line
        l.set_yield_rate_bps(500); // the carried rate word (the certified bundle carries it)
        assert!(l.credit_sat_reward(4_159_090), "SATOSHI: the honest chain issued one reward"); // a non-zero issued total
        assert!(l.snapshot_pendulum(3, 4_159_090), "SATOSHI: and snapshotted epoch 3 with every issued SAT bonded");
        l
    }

    /// The nullifiers the comparison is handed evidence for. The second is the one a refutation forges.
    fn probes() -> Vec<[u8; 32]> {
        vec![[0x11u8; 32], [0x22u8; 32]]
    }

    /// ⛔⛔⛔ NO FIELD OF THE PEG MAY EXIST WITHOUT AN ANSWER TO "WHOSE STATE IS THIS?"
    #[test]
    fn every_peg_ledger_field_declares_whose_state_it_is() {
        let fields = peg_fields();
        assert!(
            fields.len() >= 8,
            "the source parse found only {} field(s) — `struct PegLedger`'s shape changed and this test \
             is reading the wrong thing. Repair the parse; a manifest checked against nothing is worse \
             than no manifest, because it reads as coverage.",
            fields.len()
        );

        let missing: Vec<&String> = fields
            .iter()
            .filter(|f| !PEG_AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "⛔ {} FIELD(S) ADDED TO `struct PegLedger` WITH NO AUTHORITY DECLARED: {missing:?}\n\n\
             This is the surface where real BTC and XMR enter and leave. Every field must say whether \
             the CHAIN decides it or this NODE does, because that answer decides whether a door reading \
             it is reading consensus or reading itself — which is how `POST /register_wrapped_asset` \
             set a collateral ratio unseen for months. Add the field to PEG_AUTHORITY_MANIFEST as \
             `ChainDerived` (and give it a comparison in `peg_divergences` plus a refutation below) or \
             as `LocalCache`. `Unclassified` is honest if you genuinely cannot rule — but it is capped.",
            missing.len()
        );

        let stale: Vec<&str> = PEG_AUTHORITY_MANIFEST
            .iter()
            .map(|(n, _)| *n)
            .filter(|n| !fields.iter().any(|f| f.as_str() == *n))
            .collect();
        assert!(
            stale.is_empty(),
            "⛔ the manifest names {} field(s) that no longer exist: {stale:?}. A manifest that drifts \
             from the struct is a list nobody can trust in either direction — delete them.",
            stale.len()
        );

        println!(
            "[authority_peg] {} fields · {} chain-derived · {} local cache · {} UNCLASSIFIED",
            fields.len(),
            PEG_AUTHORITY_MANIFEST
                .iter()
                .filter(|(_, a)| *a == Authority::ChainDerived)
                .count(),
            PEG_AUTHORITY_MANIFEST
                .iter()
                .filter(|(_, a)| *a == Authority::LocalCache)
                .count(),
            PEG_AUTHORITY_MANIFEST
                .iter()
                .filter(|(_, a)| *a == Authority::Unclassified)
                .count(),
        );
    }

    /// ⭐⭐ THE MANIFEST CHECK ITSELF IS REFUTED — it must be able to SEE an unclassified field.
    ///
    /// A manifest test that cannot detect a missing entry reports green forever while the gap it exists
    /// to close reopens. The negative half matters equally: the REAL field list must come back fully
    /// covered, or the positive result would just mean the manifest is empty.
    #[test]
    fn the_peg_manifest_check_detects_a_field_it_does_not_carry() {
        let synthetic: Vec<String> = vec![
            "reserve_commit".to_string(),
            "a_peg_field_nobody_classified".to_string(),
        ];
        let found: Vec<&String> = synthetic
            .iter()
            .filter(|f| !PEG_AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "⛔ THE PEG MANIFEST CHECK IS BLIND: handed a field list containing a name the manifest does \
             NOT carry, it reported {found:?}. Then a field can be added to the peg with no ruling on \
             whose state it is and nothing objects — at the mint and redeem surface."
        );
        assert_eq!(
            found[0], "a_peg_field_nobody_classified",
            "the check must name the UNCOVERED field, not an arbitrary one"
        );

        // NEGATIVE HALF — the real struct must come back fully covered.
        let real = peg_fields();
        let uncovered = real
            .iter()
            .filter(|f| !PEG_AUTHORITY_MANIFEST.iter().any(|(n, _)| *n == f.as_str()))
            .count();
        assert_eq!(
            uncovered, 0,
            "{uncovered} real peg field(s) are uncovered — see the sibling test for the list"
        );
    }

    /// ⛔⛔ THE RATCHET — the undecided peg backlog may only shrink.
    #[test]
    fn the_peg_unclassified_backlog_only_shrinks() {
        let undecided: Vec<&str> = PEG_AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == Authority::Unclassified)
            .map(|(n, _)| *n)
            .collect();
        println!(
            "[authority_peg] {} UNCLASSIFIED (ceiling {}): {undecided:?}",
            undecided.len(),
            MAX_PEG_UNCLASSIFIED
        );
        assert!(
            undecided.len() <= MAX_PEG_UNCLASSIFIED,
            "⛔ THE UNDECIDED PEG BACKLOG GREW: {} unclassified field(s) against a ceiling of {}. This \
             number may be LOWERED and never raised — a peg field arriving without a ruling on whose \
             state it is is how a value that no block produced becomes authority at a mint or redeem \
             door.\n\nUndecided: {undecided:?}",
            undecided.len(),
            MAX_PEG_UNCLASSIFIED
        );
    }

    /// ⛔⛔⛔ A PEG FIELD DECLARED "THE CHAIN'S" MUST EVENTUALLY BE COMPARED AGAINST THE CHAIN.
    #[test]
    fn every_chain_derived_peg_field_is_or_will_be_compared() {
        let declared: Vec<&str> = PEG_AUTHORITY_MANIFEST
            .iter()
            .filter(|(_, a)| *a == Authority::ChainDerived)
            .map(|(n, _)| *n)
            .collect();
        let unchecked: Vec<&&str> = declared
            .iter()
            .filter(|n| !PEG_COLD_COMPARED.contains(n))
            .collect();
        println!(
            "[authority_peg] {} declared chain-derived · {} compared · {} NOT YET COMPARED (ceiling {})",
            declared.len(),
            PEG_COLD_COMPARED.len(),
            unchecked.len(),
            MAX_UNCHECKED_PEG_CHAIN_DERIVED
        );

        // Every compared name must actually BE a declared chain-derived field, or the count flatters
        // itself — and a comparison over something the node legitimately owns reports phantoms.
        for name in PEG_COLD_COMPARED {
            assert!(
                declared.contains(name),
                "⛔ `{name}` is listed as compared but is NOT declared ChainDerived in the peg \
                 manifest. Either the comparison checks something the node legitimately owns (phantom \
                 findings) or the manifest is wrong. Both are worse than the gap this test measures."
            );
        }

        assert!(
            unchecked.len() <= MAX_UNCHECKED_PEG_CHAIN_DERIVED,
            "⛔ THE UNCHECKED CHAIN-DERIVED PEG SURFACE GREW: {} field(s) are declared to be the \
             CHAIN's and are never compared, against a ceiling of {}. Every one is a peg field where a \
             node could hold a value no block produced and nothing would notice — which is exactly how \
             kill-list item 5 stayed invisible. This number may be LOWERED and never raised.\n\n\
             Not yet compared: {unchecked:?}",
            unchecked.len(),
            MAX_UNCHECKED_PEG_CHAIN_DERIVED
        );
    }

    /// ⭐⭐⭐ THE NEGATIVE CONTROL FOR EVERY COMPARISON, AND THE PROOF IT IS NOT A STUB.
    ///
    /// Two ledgers built by the SAME real door sequence, independently, must produce NO finding. A
    /// comparison that reports on an honest pair is worse than none: it is noise on the mint and redeem
    /// surface, and noise trains its readers to ignore the one run where the reserve really did diverge
    /// (the D-21 lesson).
    ///
    /// The second half is what makes the first mean anything — `peg_divergences` must be shown capable
    /// of producing output at all, or `Vec::new()` would pass the silence check forever.
    #[test]
    fn the_peg_comparison_is_silent_on_two_honest_ledgers_and_is_not_a_stub() {
        let chain = honest_ledger();
        let node = honest_ledger();
        let clean = peg_divergences(&chain, &node, &probes());
        assert!(
            clean.is_empty(),
            "⛔ THE PEG COMPARISON REPORTS ON TWO HONEST LEDGERS: {clean:?}. Both were built by the \
             same real door sequence from `PegLedger::genesis`, so nothing diverged and nothing may be \
             reported."
        );

        // NON-VACUITY — a comparison that always returns empty passes the line above forever.
        let other = PegLedger::genesis(DEFAULT_MINT_RATIO_BPS); // no assets, default floor and rate
        assert_ne!(
            other.collateral_ratio_census(),
            chain.collateral_ratio_census(),
            "the two ledgers must actually differ, or the assertion below proves nothing"
        );
        let fired = peg_divergences(&chain, &other, &probes());
        assert!(
            !fired.is_empty(),
            "⛔ `peg_divergences` RETURNED NOTHING for two ledgers that demonstrably differ (one has \
             two registered wrapped assets and a retuned floor and rate, the other has none of them). \
             Then it is a stub, every 'the peg agrees' result in this file is vacuous, and the silence \
             above says nothing at all."
        );
    }

    /// ⭐⭐⭐ THE TWO DIGESTS THAT *ARE* THE PEG — EACH COMPARISON PROVEN TO FIRE.
    ///
    /// `reserve_commit` is the committed collateral behind every USDm; `minted_commit` is what every
    /// >=2/3 solvency gate is computed against. These already ride the cold-peer verdict; they are
    /// refuted HERE too because this file's comparison is a different code path, and a comparison
    /// nobody has made go red is a comment with a test name no matter who else checks the same field.
    #[test]
    fn peg_reserve_and_minted_commitment_comparisons_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL.
        assert!(
            peg_divergences(&honest_ledger(), &honest_ledger(), &probes()).is_empty(),
            "⛔ A COMMITMENT COMPARISON REPORTS ON AN HONEST PAIR — see the dedicated negative control"
        );

        // 1. THE RESERVE COMMITMENT.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.reserve_commit();
        node.initialize_solvency_commitments(usdm_decider::poseidon2_compress::lanes_of(&[0xDEAD_BEEFu64, 1, 2, 3]), node.minted_commit());
        assert_ne!(
            node.reserve_commit(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the reserve commitment is unchanged, so the \
             assertion below would pass for the wrong reason. Repair the construction, never the \
             assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("peg reserve commitment")),
            "⛔ THE RESERVE-COMMITMENT COMPARISON CANNOT FIRE. A party holds a committed collateral \
             figure the chain did not produce — it believes every USDm in existence is backed by \
             something the chain never saw deposited — and the comparison reported {fired:?}."
        );

        // 2. THE MINTED (CIRCULATING SUPPLY) COMMITMENT.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.minted_commit();
        node.initialize_solvency_commitments(node.reserve_commit(), usdm_decider::poseidon2_compress::lanes_of(&[7u64, 7, 7, 7]));
        assert_ne!(
            node.minted_commit(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the minted commitment is unchanged. Repair the \
             construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired
                .iter()
                .any(|d| d.contains("peg minted (circulating supply) commitment")),
            "⛔ THE MINTED-COMMITMENT COMPARISON CANNOT FIRE. A party committed to a circulating total \
             the chain did not produce, so every solvency threshold it computes is measured against a \
             supply nobody else believes in. Reported: {fired:?}"
        );
    }

    /// ⭐⭐⭐ SATOSHI — the issued SAT total and the pendulum snapshot, EACH PROVEN TO FIRE, and each ALONE.
    ///
    /// Driven through the REAL public setter `adopt_certified_sat` — the write a forged or stale bundle would make with no
    /// reward fold behind it. NEGATIVE CONTROL: the honest pair (which issued SAT and holds a non-default snapshot) is silent.
    #[test]
    fn peg_sat_issuance_and_pendulum_comparisons_each_fire_when_they_diverge() {
        let honest = honest_ledger();
        assert!(peg_divergences(&honest, &honest_ledger(), &probes()).is_empty(), "NEGATIVE CONTROL: the honest pair is silent");
        let (issued, pendulum) = honest.sat_census();
        assert!(issued > 0 && pendulum != (0, 10_000), "CALIBRATION: the honest ledger issued SAT and holds a snapshot");
        let moved = |i: u64, p: (u64, u32)| {
            let mut node = honest_ledger();
            node.adopt_certified_sat(i, p);
            assert_eq!(node.sat_census(), (i, p), "⛔ THE VIOLATING STATE WAS NEVER BUILT. Repair the construction, never the assertion.");
            peg_divergences(&honest_ledger(), &node, &probes())
        };
        let fired = moved(issued - 1, pendulum);
        assert!(fired.iter().any(|d| d.contains("SAT issued total")), "⛔ THE ISSUED-TOTAL COMPARISON CANNOT FIRE: {fired:?}");
        assert!(!fired.iter().any(|d| d.contains("SAT pendulum snapshot")), "only the moved word is reported: {fired:?}");
        let fired = moved(issued, (pendulum.0, pendulum.1 / 2));
        assert!(fired.iter().any(|d| d.contains("SAT pendulum snapshot")), "⛔ A MOVED SHARE IS INVISIBLE: {fired:?}");
        assert!(!fired.iter().any(|d| d.contains("SAT issued total")), "only the moved word is reported: {fired:?}");
        let fired = moved(issued, (pendulum.0 + 1, pendulum.1));
        assert!(fired.iter().any(|d| d.contains("SAT pendulum snapshot")), "⛔ A MOVED SNAPSHOT EPOCH IS INVISIBLE: {fired:?}");
    }

    /// ⭐⭐⭐ §BR — the §BR ledger words, PROVEN TO FIRE: each word moved alone through the REAL adopt door (the write a
    /// forged or stale bundle makes with no fold behind it), the paid-out commitment, and the deployment ledger. NEGATIVE
    /// CONTROL: the honest pair is silent.
    #[test]
    fn peg_br_ledger_word_comparison_fires_on_each_word_alone() {
        let honest = honest_ledger();
        assert!(peg_divergences(&honest, &honest_ledger(), &probes()).is_empty(), "NEGATIVE CONTROL: the honest pair is silent");
        let base = honest.br_census();
        let moved = |w: crate::peg::PegBrWords| {
            let mut node = honest_ledger();
            node.adopt_certified_br(&w);
            assert_eq!(node.br_census(), w, "⛔ THE VIOLATING STATE WAS NEVER BUILT. Repair the construction, never the assertion.");
            peg_divergences(&honest_ledger(), &node, &probes())
        };
        for i in 0..base.words.len() {
            let mut w = base.clone();
            w.words[i] = w.words[i].wrapping_add(1);
            let fired = moved(w);
            assert!(fired.iter().any(|d| d.contains("§BR ledger words")), "⛔ §BR WORD {i} MOVED INVISIBLY: {fired:?}");
        }
        let mut w = base.clone();
        w.stake_paid_commit[0] ^= 1;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A MOVED PAID-OUT COMMITMENT IS INVISIBLE");
        let mut w = base.clone();
        w.deployments.update_needed = !w.deployments.update_needed;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A MOVED DEPLOYMENT LEDGER IS INVISIBLE");
        // §BR-9a: the epoch-key ledger (the state `Class::EpochKeyDeal` writes) — a moved epoch and a forged roster each fire
        let mut w = base.clone();
        w.epoch_keys.current_next += 1;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A MOVED EPOCH-KEY EPOCH IS INVISIBLE");
        let mut w = base.clone();
        w.epoch_keys.tick(7, &[[9u8; 32]]);
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED EPOCH-KEY ROSTER IS INVISIBLE");
        // §19.4: a forged epoch anchor (a root a claim could prove a note under) fires
        let mut w = base.clone();
        w.epoch_anchors.push((1, 1, usdm_decider::poseidon2_compress::lanes_of(&[7, 7])));
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED EPOCH ANCHOR IS INVISIBLE");
        let mut w = base;
        let mut forged = crate::price_history::PriceHistory::default();
        assert!(forged.fold(144, 1), "a forged one-unit history");
        w.price_history.push((u32::MAX, forged));
        assert!(moved(w.clone()).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED PRICE HISTORY (TWAP / LOW) IS INVISIBLE");
        // IonSwap pools: the pending orders, the layer word and the pool count, each moved alone
        let mut w = honest.br_census();
        w.ion.2 += 1;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED POOL COUNT IS INVISIBLE");
        let mut w = honest.br_census();
        w.ion.1 += 1;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED POOL-LAYER USDm WORD IS INVISIBLE");
        let mut w = honest.br_census();
        w.open_decoys.push(([0xdeu8; 32], crate::decoy_tx::OpenDecoy { vid: [1u8; 32], sats: 10_000, txid: [2u8; 32], vout: 3, due_tick: 9 }));
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED OPEN DECOY OBLIGATION IS INVISIBLE");
        let mut w = honest.br_census();
        w.unit_book.open_unit(&crate::debt_units::UnitTerms { k: 40, l: 1, day: 0, epoch: 0 }, 0).expect("a forged unit");
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED DEBT UNIT IS INVISIBLE");
        let mut w = honest.br_census();
        w.unit_book.liquidate_band(40);
        w.unit_book.band_epoch[41] += 1;
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED BAND EPOCH IS INVISIBLE");
        // SAFE AT SCALE, stage three: a forged custody key row (a key that would hold a leaver's collateral, or name a
        // deposit address nobody recorded) fires; the two cost words are words 23 and 24 of the loop above
        let mut w = honest.br_census();
        w.vault_keys.push((0, vec![crate::peg::VaultKeyRow { members: vec![[7u8; 32]], btc: crate::peg::VaultBtcKey::default(), xmr_address: Vec::new(), since_tick: 1, replaced_tick: None, mixed_tick: 0 }]));
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED CUSTODY KEY ROW IS INVISIBLE");
        // spec §3g.1: a forged part at rest (one that would let a take add a part no carve took out) fires
        let mut w = honest.br_census();
        let leg = crate::peg::PartLeg { asset: 0, part: Default::default(), from_post: Default::default() };
        w.vault_parts.push((1, crate::peg::VaultPart { into: 0, opened_tick: 1, legs: vec![leg] }));
        assert!(moved(w).iter().any(|d| d.contains("§BR ledger words")), "⛔ A FORGED PART AT REST IS INVISIBLE");
    }

    /// The TOKEN REGISTRY, PROVEN TO FIRE (A-F31 / A-F34; declared `ChainDerived` 2026-11-12 by lane goods): a party
    /// holding one creation the chain never made reads a different registry, and the comparison names it. NEGATIVE
    /// CONTROL: the same creation on both sides is silent.
    /// TWO-PARTY-REVIEWED: two ledgers, the chain's and the party's, compared by the census itself.
    #[test]
    fn the_token_registry_comparison_fires_on_one_creation_more() {
        let token = |symbol: &str| crate::dsol::DsolContract {
            id: crate::hash::Hash32::hash(symbol.as_bytes()),
            version: 2,
            kind: crate::dsol::DsolKind::Token,
            symbol: symbol.to_string(),
            name: "registry census".to_string(),
            verified: false,
            logo: crate::hash::Hash32([0u8; 32]),
        };
        let (mut chain, mut party) = (honest_ledger(), honest_ledger());
        chain.dsol_tokens_mut().register(&token("ONE"));
        party.dsol_tokens_mut().register(&token("ONE"));
        assert!(peg_divergences(&chain, &party, &probes()).is_empty(), "NEGATIVE CONTROL: one creation on both sides is silent");
        party.dsol_tokens_mut().register(&token("FORGED"));
        assert!(
            peg_divergences(&chain, &party, &probes()).iter().any(|d| d.contains("token registry")),
            "⛔ A REGISTRY HOLDING A CREATION THE CHAIN NEVER MADE IS INVISIBLE"
        );
    }

    /// ⭐⭐⭐ THE RULES — mint ratio, redeem floor, yield rate — EACH PROVEN TO FIRE.
    ///
    /// These are the batch-3 `params` argument at the surface where the numbers move real money: a
    /// party with different rules is not disagreeing about STATE, it is applying a different yardstick
    /// to the same block, and nothing downstream can see it because every gate it runs agrees with
    /// itself perfectly.
    ///
    /// Two of the three are driven through the REAL public setters, which is the honest driver — those
    /// setters are exactly what a governance-shaped write would call, with no block behind it.
    #[test]
    fn peg_rule_parameter_comparisons_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL.
        assert!(
            peg_divergences(&honest_ledger(), &honest_ledger(), &probes()).is_empty(),
            "⛔ A RULE COMPARISON REPORTS ON AN HONEST PAIR — see the dedicated negative control"
        );

        // 1. THE MINT COLLATERAL RATIO — halved, the shape a wrong `ChainParams` copy produces.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.ratio_bps();
        node.force_ratio_bps_for_audit(before / 2);
        assert_ne!(
            node.ratio_bps(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the mint ratio is still {before} bps. Repair the \
             construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("peg mint collateral ratio")),
            "⛔ THE MINT-RATIO COMPARISON CANNOT FIRE. A party is running with a HALVED collateral \
             ratio: it will authorize mints its peers refuse, against collateral that does not cover \
             them. Reported: {fired:?}"
        );

        // 2. THE REDEEM SOLVENCY FLOOR — driven through the real governance setter.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.redeem_floor_bps();
        node.set_redeem_floor_bps(DEFAULT_REDEEM_FLOOR_BPS);
        assert_ne!(
            node.redeem_floor_bps(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the redeem floor is still {before} bps — the \
             honest ledger must be built at a floor ABOVE the default for this mutation to move it. \
             Repair the construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("peg redeem solvency floor")),
            "⛔ THE REDEEM-FLOOR COMPARISON CANNOT FIRE. A party holding a lower floor lets a Sell draw \
             the reserve further down than the chain permits, and the USDm left behind stops being \
             redeemable for a dollar. Reported: {fired:?}"
        );

        // 3. THE RESERVE-YIELD RATE — the number `claim_reserve_yield` proves `yield <= stake*rate`
        //    against. Driven through the real setter.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.yield_rate_bps();
        node.set_yield_rate_bps(before + 4_500);
        assert_ne!(
            node.yield_rate_bps(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the yield rate is still {before} bps. Repair the \
             construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("peg reserve-yield rate")),
            "⛔ THE YIELD-RATE COMPARISON CANNOT FIRE. A party holding a higher rate accepts a \
             self-minted yield its peers reject — USDm created against nothing, on the door whose whole \
             gate is `yield <= stake*rate`. Reported: {fired:?}"
        );

        // 4. THE STABILITY POOLS (LIQUIDATION §10) — a party holding pool words the chain never produced. Driven
        //    through the ledger's own writer.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let mut w = node.pool_words(crate::peg::NATIVE_PEG_ASSET_ID);
        w.epoch += 1;
        node.set_pool_words(crate::peg::NATIVE_PEG_ASSET_ID, w);
        assert_ne!(
            node.pool_census(),
            chain.pool_census(),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the pools still agree. Repair the construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("stability-pool census")),
            "⛔ THE POOL COMPARISON CANNOT FIRE. A party holding pool words the chain never produced keys receipts to a \
             snapshot no deposit made. Reported: {fired:?}"
        );

        // 5. A CLOSED POOL EPOCH the chain never closed — through the ledger's only non-door writer (the bundle adopt).
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let cur = node.pool_words(crate::peg::NATIVE_PEG_ASSET_ID);
        let forged_close = crate::peg::PoolWords { epoch: cur.epoch, ..cur };
        node.adopt_certified_pools(&[
            (crate::peg::NATIVE_PEG_ASSET_ID, crate::peg::PoolWords { epoch: cur.epoch + 1, ..cur }),
            (crate::peg::NATIVE_PEG_ASSET_ID, forged_close),
        ]);
        assert_eq!(
            node.closed_pool_words(crate::peg::NATIVE_PEG_ASSET_ID, cur.epoch),
            Some(forged_close),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the node holds no close. Repair the construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("stability-pool census")),
            "⛔ THE CLOSED-EPOCH COMPARISON CANNOT FIRE. A party holding a close the chain never made lets that epoch's \
             receipts withdraw against words no liquidation produced. Reported: {fired:?}"
        );
    }

    /// ⭐⭐⭐ THE WRAPPED-ASSET PSMs AND THE HIGH-WATER MARK — EACH PROVEN TO FIRE.
    ///
    /// The census half is driven EXACTLY as `POST /register_wrapped_asset` drives it: the same
    /// `register_wrapped_asset(asset_id, ratio_bps)` call the route handler makes, with no threshold, no
    /// governance vote and no block anywhere. wBTC is volatile and must carry the 150% buffer; 10000 is
    /// 1:1, so this is the "50% more USDm against the same collateral" case.
    #[test]
    fn the_price_mark_comparison_fires_when_two_parties_price_a_unit_differently() {
        // NEGATIVE CONTROL — an honest pair must stay silent, or "it fired" means nothing.
        assert!(
            peg_divergences(&honest_ledger(), &honest_ledger(), &probes()).is_empty(),
            "⛔ THE PRICE-MARK COMPARISON REPORTS ON AN HONEST PAIR — see the dedicated negative control"
        );

        // DRIVE THE HOLE: one party stands on a mark the other does not hold at all. This is the state a
        // node reaches by applying a `Class::PriceMark` its peer has not seen, and — before DB-124 — the
        // state EVERY node was permanently in, because no mark existed and the door compared raw atomic
        // counts instead.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.price_mark_census();
        // Driven through the REAL door — there is deliberately no local setter for a mark, which is the
        // whole design: `mark_price_attested` is the only writer, so this drives the production path
        // rather than a test-only back door that could diverge from it.
        let custodians: Vec<crate::bridge::Custodian> =
            (0..2u8).map(|i| crate::bridge::Custodian::generate(&[70 + i; 32])).collect();
        let mut vs = crate::validator::ValidatorSet::new();
        for c in &custodians {
            vs.admit(c.id(), 5000, 0).unwrap();
        }
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, crate::peg::NATIVE_PEG_ASSET_ID, 15_000));
                crate::price_mark_tx::PriceQuote { price: 15_000, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        assert_eq!(
            node.mark_price_attested(1, crate::peg::NATIVE_PEG_ASSET_ID, &quotes, &vs, &crate::pqauth::MlDsaVerifier),
            crate::peg::PegOutcome::PriceMarked(15_000),
            "the real door sets the mark this refutation diverges on"
        );
        assert_ne!(
            node.price_mark_census(),
            before,
            "⛔ THE HOLE WAS NOT DRIVEN: the price-mark census is unchanged. Repair the driver, never \
             the assertion."
        );

        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("price-mark census")),
            "⛔ THE PRICE-MARK COMPARISON CANNOT FIRE. Two parties priced the same unit differently and \
             nothing objected — then the harness cannot see a disagreement about the number that \
             decides how much USDm may exist per unit of collateral. Reported: {fired:?}"
        );
    }

    #[test]
    fn peg_wrapped_asset_and_hwm_comparisons_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL.
        assert!(
            peg_divergences(&honest_ledger(), &honest_ledger(), &probes()).is_empty(),
            "⛔ A WRAPPED-ASSET COMPARISON REPORTS ON AN HONEST PAIR — see the dedicated negative \
             control"
        );

        // 1. THE RATIO CENSUS — kill-list item 5, driven the way the RPC route drives it.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.collateral_ratio_census();
        node.register_wrapped_asset(WBTC, 10_000);
        assert_ne!(
            node.collateral_ratio_census(),
            before,
            "⛔ THE HOLE WAS NOT DRIVEN: the ratio census is unchanged after the same call the RPC route \
             makes. Repair the driver, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired
                .iter()
                .any(|d| d.contains("wrapped-asset collateral ratio census")),
            "⛔ THE RATIO-CENSUS COMPARISON CANNOT FIRE. A collateral ratio was set on one ledger with \
             NO threshold, NO governance vote and NO block — exactly what `POST \
             /register_wrapped_asset` does today — and nothing objected. Then the harness cannot see an \
             unauthenticated write to the number that decides how much USDm may exist. Reported: \
             {fired:?}"
        );

        // 2. THE PER-ASSET PSM DIGESTS — a party missing an asset the chain registered is wrong about
        //    what backs that token, and the census alone is not what says so: the commitments and the
        //    per-asset high-water mark each need their own comparison or they are decoration.
        let mut chain = honest_ledger();
        let node = honest_ledger();
        assert!(
            node.wrapped_asset_commits(WETH).is_none(),
            "the honest ledger must NOT already know this asset, or the divergence below is not the \
             one being described"
        );
        chain.register_wrapped_asset(WETH, 15_000);
        assert_ne!(
            chain.wrapped_asset_commits(WETH),
            node.wrapped_asset_commits(WETH),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: both ledgers answer the same for this asset's \
             commitments. Repair the construction, never the assertion."
        );
        assert_ne!(
            chain.wrapped_asset_hwm_commit(WETH),
            node.wrapped_asset_hwm_commit(WETH),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: both ledgers answer the same for this asset's \
             high-water mark. Repair the construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired
                .iter()
                .any(|d| d.contains("wrapped-asset PSM commitments (asset 9)")),
            "⛔ THE PER-ASSET PSM COMPARISON CANNOT FIRE. The chain registered a wrapped asset and \
             seeded its confidential PSM; the party has no such PSM, so it is wrong about what backs \
             that token in exactly the way it could be wrong about USDm. Reported: {fired:?}"
        );
        assert!(
            fired
                .iter()
                .any(|d| d.contains("wrapped-asset reserve high-water mark (asset 9)")),
            "⛔ THE PER-ASSET HIGH-WATER-MARK COMPARISON CANNOT FIRE. That mark is the bound a \
             liquidation re-mark of THAT asset may never exceed; a party that disagrees about it lets \
             the one liquidation door mark a wrapped PSM up past collateral it never held. Reported: \
             {fired:?}"
        );

        // 3. THE NATIVE RESERVE HIGH-WATER MARK — the up-mark-then-mint ceiling.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.reserve_hwm_commit();
        node.force_reserve_hwm_commit_for_audit([u64::MAX; 8]);
        assert_ne!(
            node.reserve_hwm_commit(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the high-water mark is unchanged. Repair the \
             construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired.iter().any(|d| d.contains("peg reserve high-water mark")),
            "⛔ THE HIGH-WATER-MARK COMPARISON CANNOT FIRE. `liquidate_confidential` is built so the \
             door cannot raise its own ceiling — but a party that simply HOLDS a higher one gets the \
             same effect without touching the door: an UP-MARK to collateral that was never deposited \
             becomes provable, and then mintable against. Reported: {fired:?}"
        );
    }

    /// ⭐⭐⭐ THE REPLAY GUARDS — THE SHARPEST FIELDS IN THE STRUCT, EACH PROVEN TO FIRE.
    ///
    /// `spent_burns` is where a peg divergence stops being an accounting disagreement and becomes real
    /// BTC leaving custody: `Node::authorize_reserve_release` refuses the foreign payout unless
    /// `is_burned` says yes, so an entry the chain never produced pays out an asset with no USDm
    /// destroyed behind it. BOTH halves of that comparison are refuted — the SIZE census and the
    /// membership probe — because two sets of equal size holding different entries are invisible to the
    /// first, and a set the probes do not name is invisible to the second.
    #[test]
    fn peg_replay_guard_comparisons_each_fire_when_they_diverge() {
        // NEGATIVE CONTROL.
        assert!(
            peg_divergences(&honest_ledger(), &honest_ledger(), &probes()).is_empty(),
            "⛔ A REPLAY-GUARD COMPARISON REPORTS ON AN HONEST PAIR — see the dedicated negative control"
        );

        // 1. A BURN THE CHAIN NEVER RECORDED — caught by the size census AND named by a probe.
        let chain = honest_ledger();
        let mut node = honest_ledger();
        let before = node.spent_burn_count_for_audit();
        let forged = probes()[1];
        assert!(
            node.force_spent_burn_for_audit(forged),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the set already held this nullifier, so nothing \
             was forged. Repair the construction, never the assertion."
        );
        assert_ne!(
            node.spent_burn_count_for_audit(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the burn set still holds {before} entries. Repair \
             the construction, never the assertion."
        );
        assert_ne!(
            node.is_burned(&forged),
            chain.is_burned(&forged),
            "the two ledgers must actually disagree about THIS nullifier, or the membership half of \
             the comparison is being asserted about a state that does not exist"
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired
                .iter()
                .any(|d| d.contains("burned-USDm nullifier set size")),
            "⛔ THE BURN-SET SIZE COMPARISON CANNOT FIRE. A party holds a burned-USDm nullifier the \
             chain never produced, and `authorize_reserve_release` will pay the FOREIGN leg against it \
             — real BTC/XMR leaving the reserve with no USDm destroyed. Reported: {fired:?}"
        );
        assert!(
            fired
                .iter()
                .any(|d| d.contains("burned-USDm nullifier membership")),
            "⛔ THE BURN MEMBERSHIP PROBE CANNOT FIRE. The size census alone cannot see two sets of \
             equal size holding different entries, so if the probe half is blind the comparison is \
             bounded by a count and nothing else. Reported: {fired:?}"
        );

        // 2. A DEPOSIT ID CONSUMED THAT THE PARTY NEVER SAW — the other direction of the same class: a
        //    party SHORT of the chain's set mints a second time against a deposit already paid out.
        let mut chain = honest_ledger();
        let node = honest_ledger();
        let before = chain.confidential_deposit_id_count_for_audit();
        assert!(
            chain.force_confidential_deposit_id_for_audit([0x5Au8; 32]),
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the deposit-id set already held it. Repair the \
             construction, never the assertion."
        );
        assert_ne!(
            chain.confidential_deposit_id_count_for_audit(),
            before,
            "⛔ THE VIOLATING STATE WAS NEVER BUILT: the deposit-id set still holds {before} entries. \
             Repair the construction, never the assertion."
        );
        let fired = peg_divergences(&chain, &node, &probes());
        assert!(
            fired
                .iter()
                .any(|d| d.contains("confidential peg-in deposit-id set size")),
            "⛔ THE DEPOSIT-ID COMPARISON CANNOT FIRE. The chain has consumed a deposit id this party \
             has not, so the party will mint a SECOND time against a foreign deposit that already paid \
             out — free issuance, at the door where real BTC and XMR enter. Reported: {fired:?}"
        );
    }
}


