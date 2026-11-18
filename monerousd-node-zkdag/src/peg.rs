// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! BIDIRECTIONAL PEG — the sound reserve ledger behind Buy-USDm (peg-in / mint) AND redeem (peg-out / burn),
//! for BTC and XMR, designed so USER FUNDS CANNOT BE LOST. Every value move is gated by the SAME real ≥2/3
//! bonded-validator ML-DSA threshold that secures the mint ([[crate::psm]]) — no single party can mint, burn,
//! or move the reserve.
//!
//! The model is a per-deposit COLLATERAL POSITION (matches the wallet's "deposit $1,500 in BTC → 1,000 USDm"):
//!   • PEG-IN  (mint):  a user deposits `deposit_units` of an asset (a unique `deposit_id`). A ≥2/3 threshold
//!     attests the confirmed deposit; the ledger opens a position and mints `deposit_value × 10000 / ratio`
//!     USDm (150% over-collateralized: you always lock MORE value than you mint). Reserve += deposit_units.
//!   • PEG-OUT (burn): the user BURNS the position's USDm (a real one-time nullifier, so it is destroyed and can
//!     never be double-spent). A ≥2/3 threshold attests the burn; the ledger closes the position and returns the
//!     user's FULL original `deposit_units` to their external address. Reserve -= deposit_units. minted -= usdm.
//!
//! FUNDS-SAFETY THEOREMS (all adversarially tested below, for BTC + XMR, both directions):
//!   1. SOLVENCY (over-collateralized always):  Σ reserve_value ≥ minted_usdm × ratio.  The reserve can always
//!      cover every circulating USDm at the peg — a user's USDm is always redeemable.
//!   2. NO FREE MINT:      a mint requires a ≥2/3 ML-DSA threshold over a UNIQUE deposit_id — no deposit ⇒ no
//!      mint, and the same deposit can never mint twice.
//!   3. NO DOUBLE-BURN / NO STUCK COLLATERAL:  a burn requires a ≥2/3 threshold + a UNIQUE USDm nullifier and
//!      only closes an OPEN position — a position redeems exactly once, returning exactly its deposit.
//!   4. NO OVER-REDEEM:    peg-out returns exactly the position's `deposit_units` (never more) and only from a
//!      reserve that holds them — the bridge can never pay out more than it custodies.
//!   5. CONSERVATION (perfect round-trip):  peg_in(D) then peg_out(D) returns reserve + minted-supply to their
//!      start and hands the user back their FULL deposit — zero value created or lost. Safe to deposit real BTC/XMR.
//!
//! The ONLY simulated step (test-gated, user-authorized) is the EXTERNAL chain event itself (the BTC/XMR deposit
//! confirming, and the withdrawal tx broadcasting). Every MonerousD-side gate — the threshold, the nullifier, the
//! solvency + conservation arithmetic — is REAL and enforced here.

use std::collections::HashSet;

use crate::pqauth::{pubkey_id, PqVerifier};
use crate::psm::{BondQuorum, MintAttestor};

/// A supported bridge asset (external chain). secp256k1/ed25519 custody lives at the bridge endpoint only.
pub const ASSETS: [&str; 2] = ["BTC", "XMR"];

// Re-exported from the zero-dep `peg_arith` module so Kani can prove this arithmetic path-included.
pub use crate::peg_arith::{fee_split, fee_split_at, miner_rate, withdrawal_fee_bps, WITHDRAW_FEE_MIN_BPS, WITHDRAW_FEE_MAX_BPS};

/// The outcome of a peg operation — only `Ok*` moves value; everything else fails CLOSED (no value moves).
#[derive(Debug, PartialEq, Eq)]
pub enum PegOutcome {
    /// ⭐ §BR-3 17.5: a custody theft's repayment applied — the reserve booked the loss, the buffer and the pool retired their
    /// layers, the pot's share is owed by its sales, any remainder is a public haircut event.
    TheftRepaid,
    /// Peg-in authorized: this many USDm atomic units were minted to the user.
    Minted(u128),
    /// Peg-out authorized: this many external-asset units are released to the user's withdrawal address.
    Redeemed(u128),
    /// CONFIDENTIAL peg-in authorized (#75): the commitment transition verified and the digest was advanced.
    /// Carries NO amount — the node learns no value (the mint is proven over hidden totals). This is the
    /// outcome of the confidential wire path; observers + the node see only the opaque commitment swap.
    ConfidentialMinted,
    /// CONFIDENTIAL peg-out authorized (#75): the reduction verified and the digest was advanced. No amount.
    ConfidentialRedeemed,
    /// LIQUIDATION authorized: an under-collateralized position was CLOSED by the protocol — the committed reserve
    /// was re-marked DOWN to the crashed market value of the collateral it still holds and the position can never
    /// be closed again. Carries NO amount (the re-mark is proven over hidden values). The holder's already-minted
    /// USDm is untouched: `minted_commit` is structurally excluded from this door.
    Liquidated,
    /// A wrapped-asset PSM's collateral ratio was SET by a ≥2/3-attested, block-carried registration
    /// ([`PegLedger::register_wrapped_asset_attested`]). Carries no amount — a registration moves no
    /// value itself; it fixes the ratio every later mint against that asset is measured by.
    WrappedAssetRegistered,
    /// DB-124: the door set this asset's price mark to the bond-weighted median of the attested quotes.
    /// Carries the mark so the apply seam can report it without a second read.
    PriceMarked(u128),
    /// ⭐ CONFIDENTIAL peg-in VERIFIED against THIS node's persisted state and PUBLISHED as a chain object
    /// (`Class::PegIn`) — nothing moved yet. The digests advance and the note is credited on EVERY node,
    /// this one included, when a block carries it (`apply_chain_peg_in`). This is what makes one foreign
    /// deposit mint ONCE on the network: two custodians on a transient fork can both publish, and the
    /// chain's order applies exactly one (the second is `Replay` everywhere). MEASURED before this
    /// variant existed (2026-09-17, two real nodes): node1, never having grafted node0's mint, minted the
    /// same deposit on its own ledger at execute — the local-mutation shape the cardinal forbids.
    ConfidentialPublished,
    /// The ≥2/3 bonded-validator ML-DSA threshold did not authorize the exact operation → rejected.
    InsufficientThreshold,
    /// A deposit_id that already opened a position (no double-mint) / a nullifier already burned (no
    /// double-burn) / a peg-out on a missing-or-closed position → rejected fail-closed.
    Replay,
    /// Unknown asset, a malformed amount, or a would-be over-redeem → rejected.
    BadRequest,
    /// FUNDS-LOSS-IMPOSSIBLE bond backstop: the mint would push the reserve (value-at-risk) above half the bonded
    /// weight, so the bond would no longer be ≥ 2× the reserve → rejected. A depositor is only ever admitted while
    /// the forfeitable bond over-covers the reserve, so a rogue quorum always loses more than it can steal.
    Underbonded,
}

/// The bidirectional peg reserve ledger. Sound by construction: every mutation is threshold-gated + preserves
/// solvency; a rejected op mutates NOTHING (fail-closed), so a failed/partial bridge op can never lose funds.
///
/// #75 — the CONSENSUS-PERSISTED state is COMMITMENT-ONLY: only the value-hiding `reserve_commit`/`minted_commit`
/// digests + the replay nullifiers + `ratio_bps` + the per-unit reward indices serialize. The custodian's runtime
/// books below (`positions`/`reserve`/`minted_usdm`/`earned_fee_surplus_usdm`) are `#[serde(skip)]` — they NEVER
/// enter the postcard snapshot (which is BOTH the #106 disk state AND the #29 DSYNC wire bundle), so a joining
/// node, an operator inspecting their disk, or any adversary reading the snapshot learns ZERO supply / reserve /
/// total. They are the CUSTODIAN'S PRIVATE working state (the party that holds the reserve legitimately knows the
/// amounts) — used to build the confidential carriers + the economics; a fresh/reloaded node starts them EMPTY
/// (Default) with the confidential commitment path as the source of truth. Skipping them ALSO removes a growth
/// axis (per-deposit `positions` / per-asset `reserve`) from the snapshot (no-growth pillar).
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PegLedger {
    /// O1-FOOTPRINT-REVIEWED: bounded by BLOCK_FIXED_TX_COUNT — the one-time ids ONE block's objects
    /// inserted (deposit 0 / burn 1 / release 2 / liquidated 3), drained by the node after every apply so an
    /// adopt can forget the ids of blocks the certified chain abandoned (§DD interim; §DD-b moves these ids
    /// into the nullifier slots). Never persisted, never served.
    #[serde(skip)]
    applied_ids: Vec<([u8; 32], u8)>,
    // #75 — the peg's ENTIRE state is COMMITMENT-ONLY. There is NO supply counter, NO reserve total, NO surplus
    // meter, NO per-unit reward index anywhere — supply is ABSENT by design ([[feedback_no_counters_no_plaintext_transparency]]).
    // The reserve total and the circulating total live ONLY as value-hiding Poseidon commitments (opaque 4-limb
    // digests): a node/operator/adversary reading ANY surface learns ZERO value/supply/total. Each op (peg-in,
    // peg-out, reserve-yield claim) advances the pair via a WHIR-bound carrier proof over HIDDEN amounts; the node
    // VERIFIES + swaps the digest, never computing a value.
    reserve_commit: crate::spend_frontier::Digest4,
    minted_commit: crate::spend_frontier::Digest4,
    /// ⭐ §BR-12 L1 — THE CONTRACT-STATE ROOT (`crate::contract_state`): one word, the whole of what the node holds about
    /// every deployed contract. A fold-written word like the pools, so it rides the ledger's image (a rewind restores it),
    /// the checkpoint and the certified bundle (`PegBrWords`), and the field censuses, with no new carriage of its own.
    /// A ledger written before the word existed decodes to the EMPTY tree's root (the chain had no contracts).
    #[serde(default = "contract_state_empty_root")]
    contract_state_root: crate::spend_frontier::Digest4,
    // Replay guards — hashes/nullifiers, NOT values (disclose no amount): the burned USDm note nullifiers (no
    // double-burn / double reserve-yield claim) + the confidential-peg-in deposit ids (no double-mint).
    spent_burns: HashSet<[u8; 32]>,
    #[serde(default)]
    confidential_deposit_ids: HashSet<[u8; 32]>,
    // Required over-collateralization (15000 = 150%). A consensus POLICY parameter, not a value.
    ratio_bps: u32,
    // Reserve-yield rate in bps (e.g. 500 = 5% per epoch). A governance POLICY parameter (an interest rate), not a
    // value/supply — the `stake·rate` bound each staker's confidential self-minted yield is proven against
    // in-circuit ([`crate::peg::PegLedger::verify_reserve_yield_claim`], usdm_decider::…::verify_yield_mint_carrier).
    #[serde(default)]
    yield_rate_bps: u32,
    // The REDEEM (peg-out) solvency floor in bps (10000 = 100%). A governance POLICY parameter, DISTINCT from
    // `ratio_bps` (the 15000/150% MINT over-collateralization): a deposit must always over-collateralize to 150% on
    // the way IN, but a Sell may draw the reserve buffer DOWN to this floor on the way OUT — with the withdraw fee
    // rising as backing falls (disincentivizing the drain; the fee stays in the reserve, replenishing the buffer).
    // A redemption whose post-state would fall below it is UNPROVABLE (the peg-out carrier's ratio constraint fails),
    // so every USDm always stays redeemable for exactly $1 of reserve — 100% is the true-solvency line and no holder
    // ever loses principal. Below 100% stays hard-blocked (genuine insolvency). Governance-tunable at runtime.
    #[serde(default = "default_redeem_floor_bps")]
    redeem_floor_bps: u32,
    // Reserve RELEASES already authorized (the withdrawal's foreign-settlement leg). A burned USDm nullifier
    // authorizes AT MOST ONE foreign reserve release: this set makes the release single-use so one burn can never
    // drain the reserve twice ([`crate::node::Node::settle_reserve_release_observed`]). A hash set, not a value — it
    // discloses no amount. Kept distinct from `spent_burns` so the burn (USDm destroyed) and the release (foreign
    // asset paid out under a ≥2/3 PQ cert) are separately, idempotently tracked.
    #[serde(default)]
    released: HashSet<[u8; 32]>,
    // Per-asset WRAPPED-asset PSMs (the IonSwap bridge): asset_id -> its own confidential PSM (reserve_commit,
    // minted_commit, ratio_bps). Each wrapped asset (wBTC/wETH/wDAI) is an INDEPENDENT PSM reusing the SAME bond-weighted multisig tally
    // custody + WHIR solvency carrier as USDm, but minting the wrapped token instead of USDm. A STABLECOIN registers
    // at ratio 10000 (100%, 1:1 — exempt from the 150% volatility buffer); a VOLATILE asset at 15000 (150%). Bounded
    // by the governance-registered asset set (O(1), like `bond_locked`), NOT O(notes). Commitment-only — no per-asset
    // supply/reserve counter, ever ([[project_ionswap_wrapped_asset_bridge]] [[feedback_no_counters_no_plaintext_transparency]]).
    #[serde(default)]
    wrapped_assets: std::collections::BTreeMap<u32, WrappedAsset>,
    // ── LIQUIDATION (the collateral re-mark door) ────────────────────────────────────────────────────────────
    // The RESERVE HIGH-WATER MARK commitment: an opaque digest of the largest reserve total this ledger has been
    // able to prove was actually DEPOSITED-AND-NOT-YET-RELEASED. It is advanced by (and only by) the non-liquidation
    // value paths — a peg-in raises it with the deposit, a peg-out lowers it with the release, both by simply
    // tracking `new_reserve_commit` (see [`PegLedger::apply_confidential_peg_in`]). The LIQUIDATION door may
    // re-mark the committed reserve anywhere in `[0, HWM]` but can NEVER commit to more collateral than was
    // really deposited — that ge256 constraint is what makes an UP-MARK-then-mint inflation attack UNPROVABLE
    // (§9.6 Q3). A commitment, not a value: it discloses no amount.
    #[serde(default)]
    reserve_hwm_commit: crate::spend_frontier::Digest4,
    // Positions CLOSED by the liquidation door — the per-position replay set (§9.6 Q4's set, kept DISTINCT from
    // `spent_burns` so a liquidation key can never be mistaken for a real USDm burn by
    // [`PegLedger::is_burned`]/`authorize_reserve_release`). Hashes, not values. Same shape + same growth class as
    // the existing `released` set.
    #[serde(default)]
    liquidated: HashSet<[u8; 32]>,
    // ⭐ LIQUIDATION SPEC §10 — each PSM's STABILITY POOL as committed words `(T, P, S)` and its public epoch. Absent ⇒ the
    // deterministic genesis words (`PoolWords::genesis`). Bounded by the registered PSM set (like `wrapped_assets`), never
    // by deposits: a deposit's snapshot lives in its RECEIPT's key, not here. Carried in the certified bundle.
    #[serde(default)]
    pools: std::collections::BTreeMap<u32, PoolWords>,
    // LIQUIDATION §10 — the CLOSING `(P, S)` words of every closed pool epoch, keyed `(asset, epoch)`: a receipt of a closed
    // epoch withdraws against them (Liquity's epoch shape, spec §9.3). One entry per CLOSE, and a close needs a liquidation
    // that drains the pool's product below 2^64 — an economic event, never a function of height, blocks or notes.
    // O1-INFINITY-REVIEWED: bounded by the number of pool closes (each one a full-drain liquidation), 2 digests + 12 B each;
    // the spec's accepted con (§9.3 "one committed pair per closed epoch"). Rides the certified bundle inside `pool_census`.
    #[serde(default)]
    pool_closes: std::collections::BTreeMap<(u32, u64), PoolWords>,
    // ⛔⛔⛔ DB-124 — WHAT ONE EXTERNAL ATOMIC UNIT IS WORTH, per asset, as the bonded set last attested it.
    // Set ONLY by `mark_price_attested` (a block-carried `Class::PriceMark`), never from a socket: the mark
    // decides how much USDm may be issued against a deposit, so a node that took it from an RPC would be
    // minting against a number the chain never set — the identical argument `wrapped_assets` carries for
    // `ratio_bps`. `#[serde(default)]` so an older snapshot loads with NO marks, which is the fail-closed
    // state: `priced_value` returns None and the mint refuses until the chain sets one.
    // NO-GROWTH: one entry per REGISTERED asset — a governance-scale set with no term in height, blocks,
    // notes or spends, exactly like `wrapped_assets` beside it. Prices are chain-public by definition (every
    // node must agree on them to agree on solvency); no amount, owner or key is in here.
    #[serde(default)]
    price_marks: std::collections::BTreeMap<u32, crate::price_mark_tx::PriceMark>,
    // ⛔⛔⛔ THE RETENTION ENDOWMENT — the pool that pays miners to keep note data, and the ONLY source
    // of a miner reward on a zero-issuance chain. A COMMITMENT, never a cleartext balance: notes are
    // cover-padded to a constant 256 per block so an observer cannot count the real ones, and a public
    // pool balance rising by `real_count x fee` would re-publish that count by arithmetic. Opened only
    // by the doors that move it, which prove `economics::payout_is_funded` in-circuit exactly as the
    // 150% rule is proven. Genesis is a commitment to ZERO — the chain starts owing nothing and holding
    // nothing, and every atomic unit in here arrived from a fee somebody paid.
    // NO-GROWTH: one digest, forever. No term in height, notes or spends.
    #[serde(default)]
    retention_endowment_commit: crate::spend_frontier::Digest4,
    // ⭐ SATOSHI (docs/SATOSHI-NATIVE-TOKEN.md) — the base units of SAT issued so far. The ONE public counter here, and it
    // counts nothing private: every SAT reward's amount is a public function of public consensus data (the schedule at the
    // carrying block's parent key), so this total is what any observer computes from the chain anyway; it reveals no USDm
    // amount, supply or reserve. It lives in the ledger because the ledger is what the objects fold journals, rewinds,
    // persists and certifies — the cap must hold across a reorg, a restart and a jump exactly like every peg word.
    // DIGITAL-CASH-PRIVACY-REVIEWED: a public schedule's running sum; no value, identity, linkage or owner.
    // NO-GROWTH: one u64, forever.
    #[serde(default)]
    sat_issued: u64,
    // ⭐ SATOSHI §10.8 / §10.12 — THE PENDULUM'S SNAPSHOT OF THE LAST CLOSED EPOCH: `(epoch + 1, bonders' share in bps)`, taken
    // at epoch `e`'s CLOSE (the first fold step of `e + 1`, before its objects) from the ELIGIBLE custody aggregate of `e` and
    // `sat_issued` (§10.11 H1: weight never at risk through `e` moves nothing), so the rate the yield index adds is one number.
    // In the ledger because the ledger is what the objects fold journals, rewinds, persists and certifies — a rewind across an
    // epoch boundary restores the previous snapshot exactly. Public by construction (a function of public figures).
    // DIGITAL-CASH-PRIVACY-REVIEWED: two public numbers derived from public consensus state; no value, identity or owner.
    // NO-GROWTH: one u64 + one u32, overwritten per epoch, never a history.
    /// The snapshot's epoch PLUS ONE (0 = no snapshot yet), so epoch 0 is snapshotted like every other.
    #[serde(default)]
    pendulum_epoch_next: u64,
    #[serde(default)]
    pendulum_share_bps: u32,
    // ⭐ §BR-14 (2026-10-28) — THE CHAIN'S FEE POOLS: every applied USDm spend's flat network fee (and every applied burn's),
    // split 40 % stakers · 25 % SAT bonders · 25 % surplus buffer · 10 % miner pool (`fee_split`, the remainder to the
    // surplus buffer so the four sum exactly). Chain state, a pure function of the folded chain (Ethereum's STF shape):
    // journaled, rewound, persisted and certified with every other word here, SERVED TO NOBODY — no RPC, record or block
    // field carries them. A node already verifies every spend it relays and tells a ledger's spend rows from its cover by
    // the block's key, so these totals tell a node nothing it does not hold; no observer outside the node set ever sees
    // them. §BR-3 and §BR-11 spend them. NO-GROWTH: four u64, forever.
    // DIGITAL-CASH-PRIVACY-REVIEWED: node-internal chain state, never on a wire or a route.
    #[serde(default)]
    fee_pool_stakers: u64,
    #[serde(default)]
    fee_pool_bonders: u64,
    #[serde(default)]
    fee_pool_surplus: u64,
    #[serde(default)]
    fee_pool_miner: u64,
    // ⭐ §BR-11 (2026-10-28) — THE MINER POOL'S QUARTER: the payout quarter + 1 (0 = none yet), the per-block rate it pays, the
    // miner share credited during it, and the fold ordinal its first step took (so the closing step counts the quarter's
    // blocks as an ordinal span — nothing counted per block). Chain state like the pools: journaled, rewound, persisted,
    // certified; served to nobody. NO-GROWTH: four u64, forever.
    // DIGITAL-CASH-PRIVACY-REVIEWED: node-internal chain state, never on a wire or a route.
    #[serde(default)]
    miner_quarter_next: u64,
    #[serde(default)]
    miner_rate: u64,
    #[serde(default)]
    miner_accrual: u64,
    #[serde(default)]
    miner_quarter_start: u64,
    // ⭐ §BR-3 17.6 (2026-10-29) — THE BONDERS' YIELD INDEX: Y = Σ over closed quarters of (the bonders' pool credit of the
    // quarter × 2⁶⁴ / the total custody weight at its close) — USDm-atomic per SAT-atomic of weight, 64 fractional bits, as
    // two u64 words (lo, hi). Every unit of custody weight (own or delegated) earns `w·ΔY / 2⁶⁴`; a delegation's note names
    // the Y it last settled at, a seat keeps its own. `bonder_accrual` is the bonders' share credited in the open quarter (a
    // quarter that closes on zero weight carries it). Journaled, rewound, persisted, certified like the pools; served to
    // nobody. NO-GROWTH: three u64, forever.
    // DIGITAL-CASH-PRIVACY-REVIEWED: node-internal chain state, never on a wire or a route.
    #[serde(default)]
    bond_yield_lo: u64,
    #[serde(default)]
    bond_yield_hi: u64,
    #[serde(default)]
    bonder_accrual: u64,
    // ⭐ §BR-13 (2026-10-29) — 1 once the canonical SAT set-aside has applied (it applies exactly once, ever). Journaled,
    // rewound, persisted, certified like the pools. NO-GROWTH: one u64.
    // DIGITAL-CASH-PRIVACY-REVIEWED: node-internal chain state; whether the set-aside exists is public by its bytes anyway.
    #[serde(default)]
    set_aside_applied: u64,
    // ⭐ §BR-10 (2026-10-29) — the signalled-deployment ledger (`deployment::DeploymentLedger`): the open window's counts and
    // every deployment's state, a function of the canonical fold. Empty and still at genesis (no deployment exists). Journaled,
    // rewound, persisted, certified like the pools. NO-GROWTH: one counter per deployment + one validator set per open window.
    // DIGITAL-CASH-PRIVACY-REVIEWED: public block versions and public validator signals only.
    #[serde(default)]
    deployments: crate::deployment::DeploymentLedger,
    // ⭐ §BR-10 (2026-10-29) — each release builder's LATEST attestation (`release_attestation_tx`), keyed by builder id.
    // Bounded by the builder set compiled into the release. Informational chain state; journaled, persisted, certified.
    // DIGITAL-CASH-PRIVACY-REVIEWED: public builder signatures over public release hashes.
    #[serde(default)]
    release_attestations: std::collections::BTreeMap<[u8; 32], crate::release_attestation_tx::ReleaseAttestationTx>,
    // ⭐ §BR-3 17.6, the stakers' half (2026-10-29) — the committed TOTAL the stakers' pool has paid out as stake rewards
    // (`solvency_commit_256(paid, blind)`), advanced by each stake claim's supply step, which proves `paid ≤ the pool's
    // public inflow` (`fee_pools().stakers`): the reward comes from fees already out of circulation, never from a new mint.
    // The custodians hold the opening (their sealed reward legs advance it). NO-GROWTH: one digest.
    // DIGITAL-CASH-PRIVACY-REVIEWED: a commitment; no reward amount is ever public.
    #[serde(default = "genesis_stake_paid_commit")]
    stake_paid_commit: crate::spend_frontier::Digest4,
    // ⭐ §BR-3 17.6 (stakers' half) — THE STAKE EPOCH'S POOL SNAPSHOT: the stakers' pool inflow (`fee_pool_stakers`) as it
    // stood when the first folded block of stake epoch `stakers_snap_epoch_next − 1` began its step (before that block's own
    // objects and fees). Every claim of that epoch is bounded by it, so the bound is one figure every node derives from the
    // canonical fold, and NO wire field carries the pool (the pools are served to nobody — the stake header names only its
    // public epoch). Monotone: a later-folded block of an earlier epoch never moves it back. NO-GROWTH: two u64, overwritten.
    // DIGITAL-CASH-PRIVACY-REVIEWED: node-internal chain state like the pools it copies, never on a wire or a route.
    #[serde(default)]
    stakers_snap_epoch_next: u64,
    #[serde(default)]
    stakers_snap_pool: u64,
    // ⭐ §BR-4 (2026-10-29) — EACH ASSET'S PRICE HISTORY: the 7-day TWAP and the 30-day low over the certified marks
    // (`price_history`), folded when a later-epoch mark supersedes the standing one (so arrival order inside an epoch never
    // enters it). Bounded by the registered-asset set; 43 words per asset. Journaled, persisted, carried (`PegBrWords`).
    // DIGITAL-CASH-PRIVACY-REVIEWED: a function of the public certified marks only.
    #[serde(default)]
    price_history: std::collections::BTreeMap<u32, crate::price_history::PriceHistory>,
    // ⭐ §BR-9a (2026-10-29) — THE EPOCH-KEY LEDGER (`epoch_deal_tx::EpochKeyLedger`): the hourly epochs [current, current
    // + 26], each with the custody roster snapshotted when its dealing hour opened, its summed public key and its dealers'
    // records — a function of the canonical fold (`Class::EpochKeyDeal` applies, the first fold step of each epoch prunes and
    // opens). Journaled, persisted, carried (`PegBrWords`). NO-GROWTH: at most 27 epochs (≈ 6 KB of key + 32 B per roster
    // member per dealer each). DIGITAL-CASH-PRIVACY-REVIEWED: lattice public keys, the public custody set and hash
    // commitments; no epoch secret and no share is ever chain state.
    #[serde(default)]
    epoch_keys: crate::epoch_deal_tx::EpochKeyLedger,
    // ⭐ §19.4 (lane defi, 2026-11-01) — THE EPOCH ANCHORS: (fold ordinal, chain-time slot, spend-frontier root) at the first fold
    // step of each later [`EPOCH_ANCHOR_MS`] slot of the chain clock, the newest [`EPOCH_ANCHORS_KEPT`] of them — the roots a cash-out CLAIM's member leg may anchor
    // to, so a claim proven hours before its batch still verifies at the batch (the anchor ring reaches only
    // `merge_depth_cap` steps). A function of the canonical fold (pushed at the step, cut back on a rewind), persisted and
    // carried + bound (`PegBrWords`), so a node that adopted a bundle judges a claim exactly as one that folded every step.
    // Sound for any age: the note set only grows, and spent-ness is the nullifier set's. NO-GROWTH: ≤ 158 × 80 B ≈ 12.6 KB.
    // DIGITAL-CASH-PRIVACY-REVIEWED: public spine roots every node computes; no note, owner or amount.
    #[serde(default)]
    epoch_anchors: std::collections::VecDeque<(u64, u64, crate::spend_frontier::Digest4)>,
    // ⭐ §BR-3 17.5 (2026-10-29) — LAYERED REPAYMENT OF A CUSTODY THEFT (docs/BR-3-17-5-LAYERED-REPAYMENT-SPEC-20261029.md):
    // the repayment pot (the offenders' slashed SAT, sold at the floor — never destroyed), the stolen sats not yet booked by a
    // repayment, the USDm the pot's sales still owe the supply (layer 1 booked, not yet retired), and the loss shared by every
    // holder (layer 4) with its event count. Chain state like the pools: journaled, rewound, persisted, carried; a function
    // of the public theft objects and repayments. NO-GROWTH: five u64, forever.
    // DIGITAL-CASH-PRIVACY-REVIEWED: a theft's loss is a public Bitcoin transaction and bonds are public; no holder's value.
    #[serde(default)]
    repayment_sat_pot: u64,
    #[serde(default)]
    theft_loss_open_sats: u64,
    #[serde(default)]
    repayment_owed_atomic: u64,
    #[serde(default)]
    haircut_remainder_atomic: u64,
    #[serde(default)]
    haircut_events: u64,
    // ⭐ §BR-8 B8-a (2026-10-29) — CONDITIONAL DECOYS (`decoy_tx`): the decoy epoch + 1, the surplus-buffer credit of the current
    // epoch, the budget this epoch may spend (`DECOY_FEE_SHARE_BPS` of the previous epoch's credit), what it spent, and the open
    // decoy obligations (bounded by `DECOY_OPEN_MAX` + one batch). Chain state like the pools: journaled, rewound, persisted,
    // carried. NO-GROWTH: four u64 and a bounded map.
    // DIGITAL-CASH-PRIVACY-REVIEWED: custody's own public decoy outputs and the protocol's own surplus; no user's value.
    #[serde(default)]
    decoy_epoch_next: u64,
    #[serde(default)]
    decoy_credit: u64,
    #[serde(default)]
    decoy_budget: u64,
    #[serde(default)]
    decoy_spent: u64,
    // ⭐ SAFE AT SCALE, stage three (spec §3f R6, 2026-11-11) — WHO PAYS A RE-KEY: `custody_cost_debt` is what the bonders
    // owe for the foreign fees their custody paid to move its own coins (USDm atomic, raised by every booked
    // `Class::ReserveCost` at the chain's own price), paid down FIRST out of the bonders' share of every fee before any
    // of it reaches their pool; `custody_cost_retired` is the running total so paid (supply retired: the fee was burned
    // from its payer's note and is credited to nobody). Never a reserve, a pool or a user's note. Journaled, rewound,
    // persisted, carried. NO-GROWTH: two u64, forever.
    // DIGITAL-CASH-PRIVACY-REVIEWED: custody's own public foreign fees (public on their own chains); no user's value.
    #[serde(default)]
    custody_cost_debt: u64,
    #[serde(default)]
    custody_cost_retired: u64,
    #[serde(default)]
    open_decoys: std::collections::BTreeMap<[u8; 32], crate::decoy_tx::OpenDecoy>,
    // ⭐ §BR-4/§BR-7 (2026-10-29) — BORROWING AS STANDARD DEBT UNITS (`debt_units`): each cell's open count (256) and each
    // band's epoch (64) — a unit's note binds its own day and band epoch, so no per-unit row exists anywhere. Chain state:
    // journaled, rewound, persisted, carried. NO-GROWTH: 2.5 KB constant.
    // DIGITAL-CASH-PRIVACY-REVIEWED: counts of IDENTICAL units (public by design, §10.1); no owner, no position (a position's
    // units open one per object at sealed random delays).
    #[serde(default)]
    unit_book: crate::debt_units::UnitBook,
    // ⭐ §BR-15 §18.8 (lane defi, 2026-11-02) — THE DeFi BOOK (`defi_batch::DefiBook`): the custody roster the pool is shared
    // among, each custodian's pool commitment, the open batch and its orders, the last tick. A function of the canonical fold
    // (`Class::DefiOrder/DefiSettle/DefiExpire` apply), journaled, rewound, persisted, carried. NO-GROWTH: the open batch's
    // orders only (cleared every batch) and one commitment per custodian. DIGITAL-CASH-PRIVACY-REVIEWED: hash commitments to
    // shares and to burned amounts, a public tick; never an amount, a share or a depth.
    #[serde(default)]
    defi_book: Vec<crate::defi_batch::DefiBook>,
    // ⭐ SAFE AT SCALE, stage three (spec §3f R1, R4; lane vaults 2026-11-11) — THE CUSTODY KEY RECORD: for each vault, the
    // member sets whose keys hold its coins — its current key (the deposit address) and the replaced keys still alive
    // ([`VaultKeyRow`]). A function of the canonical fold (`Class::VaultKey` apply), journaled, rewound, persisted,
    // carried. It is what "no key outlives its bond" is read from: a leaver's collateral returns only when no row names it.
    // NO-GROWTH: per VAULT, at most `VAULT_KEYS_ALIVE_MAX` rows of at most sixteen ids and one bounded address — the order
    // of the seat map; nothing per deposit, per coin or per block.
    // DIGITAL-CASH-PRIVACY-REVIEWED: custodian ids and a custody address — public chain structure (the validator set and
    // the reserve's own address); no user, amount, note or deposit.
    #[serde(default)]
    vault_keys: std::collections::BTreeMap<u32, Vec<VaultKeyRow>>,
    // ⭐ SAFE AT SCALE, stage three (spec §3g.1; lane vaults 2026-11-12) — THE PARTS AT REST: for each GIVING vault, the
    // part a carve took out of its ledgers and the vault it is for ([`VaultPart`]), until that vault takes it or the
    // giver takes it back. A function of the canonical fold (`Class::VaultRebalance` apply), journaled, rewound,
    // persisted, carried. While a vault has one, it carries nothing on its own word (`vault_ride_holds`).
    // NO-GROWTH: at most one per VAULT, of at most four legs of two pairs — the order of the seat map; nothing per
    // deposit, per coin or per block.
    // DIGITAL-CASH-PRIVACY-REVIEWED: vault indexes, a block score and commitments; no total, user, note or address.
    #[serde(default)]
    vault_parts: std::collections::BTreeMap<u32, VaultPart>,
    // ⭐ A-F31 (lane goods, 2026-11-11) — THE TOKEN REGISTRY: every created token's and NFT's descriptor, folded into one
    // append-only accumulator (a count and at most `dsol::MMR_MAX_PEAKS` peaks). A creation's fold appends its descriptor
    // (`Class::AssetCreate`); a mint proves its asset is in it.
    // WHAT WAS WRONG: it was a field of the node beside this ledger, written by the fold and restored by NO rewind. A
    // reorg that re-folded a creation's step appended the same descriptor again, so a node that saw the reorg held two
    // leaves where a node that did not held one: two registry roots on one chain, and the creator's honest mint (its
    // path built against one leaf) refused at its fold on the node that reorged (MEASURED 2026-11-11, in process,
    // `rogue_role_pins::a_creation_laid_by_a_rogue_naming_a_victim_creator_gives_the_rogue_no_issuance_on_the_peer` RED
    // at its control: the honest mint's note in 0 records).
    // THE RULE: state a fold-applied object writes lives in THIS ledger, whose undo is exhaustive by construction
    // (`undo_to` destructures every field), so it is journaled per step, rewound, unwound on a refused fold, restored by
    // the supply turnstile, and carried by a checkpoint's undo chain, with every other ledger word.
    // `#[serde(skip)]`: the snapshot and the certified bundle already carry it as count + peaks beside the ledger
    // (`NodeSnapshot::dsol_registry_*`, bound into `sync_binding`); one carried encoding, unchanged.
    // NO-GROWTH: a u128 and at most 128 peaks of 36 B, at any number of assets. BORROWED: Ethereum's state as a function
    // of the chain (a reorg re-executes from the fork point against the pre-state); Bitcoin's undo data per block.
    // DIGITAL-CASH-PRIVACY-REVIEWED: digests of public asset descriptors; no holder, amount or note.
    #[serde(skip)]
    dsol_tokens: crate::dsol::DsolRegistry,
    // ⭐ IONSWAP POOLS (lane goods, 2026-11-11; `ion_pool_tx`) — THE PENDING ORDERS and THE LAYER WORD.
    // `ion_pending`: every pool order the fold applied (its inputs burned) that no settlement has paid yet, in the fold's
    // own order. A settlement takes EVERY pending order of its pool at or before its stated step, so what a batch is can
    // be recomputed by every node and no former can leave an order out. `ion_usdm_held`: the USDm the pool layer took in
    // less what it paid out; a settlement that would take it below zero is refused, so a fault in the pool arithmetic is
    // bounded by what the layer holds and never reaches a cash note (BORROWED: Zcash's turnstile between value pools).
    // A pool's own state is NOT here: it is a leaf of `contract_state_root`, so this ledger holds 32 bytes for all pools.
    // Journaled, rewound, persisted, carried and bound (`PegBrWords`). NO-GROWTH: at most `ion_pool_tx::ION_PENDING_MAX`
    // orders of about 1.4 KB (orders in flight, each with the sealed part of its payout notes; an order past the bound is
    // refused with nothing burned) and one u64: about 350 KB at the very most, a few KB in ordinary use.
    // DIGITAL-CASH-PRIVACY-REVIEWED: an order's public words (kind, sizes, floor, a one-time payout key, a locator clue);
    // no note, wallet or owner is named, and the payout key is used once.
    #[serde(default)]
    ion_pending: Vec<crate::ion_pool_tx::IonPending>,
    #[serde(default)]
    ion_usdm_held: u64,
    // `ion_pools`: HOW MANY POOLS EXIST (a pool's first settlement inserts its leaf and adds one; nothing ever removes a
    // pool). The chain keeps a pool's row as a leaf of `contract_state_root`, and a leaf does not say whether it is a
    // pool's; this count is what lets a node that took the tree's leaves from peers know it holds EVERY pool's row
    // (`Node::ion_cache_is_current`): a peer that served true leaves and withheld rows leaves the count short.
    // Journaled, rewound, persisted, carried and bound with the two words above. One u64.
    #[serde(default)]
    ion_pools: u64,
    // The USDm fee part a settlement applied in the step being folded owes the fee pools; drained by the fold into the
    // step's one fee credit (`take_ion_fee_credit`). One step's scratch, like `applied_ids`: never persisted or served.
    #[serde(skip)]
    ion_fee_credit: u64,
}

/// ⭐ §BR — THE §BR LEDGER WORDS THE CERTIFIED BUNDLE CARRIES (`PegLedger::br_census` / `adopt_certified_br`), bound into
/// `sync_binding` by [`PegBrWords::digest`]. One struct for the whole class, so the next §BR word joins it here and rides the
/// bundle with no new bundle field.
/// DIGITAL-CASH-PRIVACY-REVIEWED: the bundle is served to a joining NODE, which derives every one of these from the blocks
/// it verifies (the pools are counts of fee payers a node already tells from cover by the block's key, §15); no wallet
/// route serves them.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PegBrWords {
    /// `[stakers, bonders, surplus, miner pools, miner quarter next, miner rate, miner accrual, miner quarter start, bond
    /// yield lo, bond yield hi, bonder accrual, set-aside applied, stakers' snapshot epoch + 1, stakers' snapshot pool, §BR-3
    /// 17.5 repayment pot, open theft loss, repayment owed, haircut remainder, haircut events, §BR-8 decoy epoch + 1, decoy
    /// epoch credit, decoy budget, decoy budget spent, custody cost debt, custody cost retired]`.
    pub words: [u64; 25],
    /// §BR-12 L1: the contract-state root (an empty tree's root for a bundle written before the word existed).
    #[serde(default = "contract_state_empty_root")]
    pub contract_state_root: crate::spend_frontier::Digest4,
    pub stake_paid_commit: crate::spend_frontier::Digest4,
    pub deployments: crate::deployment::DeploymentLedger,
    pub release_attestations: Vec<([u8; 32], crate::release_attestation_tx::ReleaseAttestationTx)>,
    /// §BR-4: each asset's price history (the TWAP and low words).
    pub price_history: Vec<(u32, crate::price_history::PriceHistory)>,
    /// §BR-9a: the epoch-key ledger (rosters, summed public keys, dealer records).
    #[serde(default)]
    pub epoch_keys: crate::epoch_deal_tx::EpochKeyLedger,
    /// §BR-8: the open decoy obligations.
    #[serde(default)]
    pub open_decoys: Vec<([u8; 32], crate::decoy_tx::OpenDecoy)>,
    /// §BR-4/§BR-7: the debt-unit book.
    #[serde(default)]
    pub unit_book: crate::debt_units::UnitBook,
    /// §BR-15: the DeFi book.
    #[serde(default)]
    pub defi_book: Vec<crate::defi_batch::DefiBook>,
    /// §19.4: the epoch anchors (fold ordinal, chain-time slot, spend-frontier root), oldest first.
    #[serde(default)]
    pub epoch_anchors: Vec<(u64, u64, crate::spend_frontier::Digest4)>,
    /// SAFE AT SCALE, stage three: the custody key record, by vault (`PegLedger::vault_keys`).
    #[serde(default)]
    pub vault_keys: Vec<(u32, Vec<VaultKeyRow>)>,
    /// SAFE AT SCALE, stage three: the parts at rest, by giving vault (`PegLedger::vault_parts`).
    #[serde(default)]
    pub vault_parts: Vec<(u32, VaultPart)>,
    /// IonSwap pools: the pending orders, the layer word and the pool count (`PegLedger::ion_pending`, `ion_usdm_held`,
    /// `ion_pools`). A joiner without the first two would refuse every settlement its peers apply.
    #[serde(default)]
    pub ion: (Vec<crate::ion_pool_tx::IonPending>, u64, u64),
}

/// The root of the contract-state tree with no contract in it — what every ledger starts from.
fn contract_state_empty_root() -> crate::spend_frontier::Digest4 {
    crate::contract_state::empty_root()
}

impl PegBrWords {
    /// The fixed-width digest `sync_binding` binds (domain-separated blake3 over the canonical postcard bytes): a forged
    /// word, commitment, deployment state or attestation changes it.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_stdvec(self).unwrap_or_default();
        let mut h = blake3::Hasher::new();
        h.update(b"USDMD-PEG-BR-WORDS-v1");
        h.update(&(bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
        *h.finalize().as_bytes()
    }
}

/// ⭐ §BR-4 — how far the 10-minute mark may stray from the 7-day TWAP before a liquidation step is refused (spec §1 item 7:
/// "refused when it strays far from the 7-day average"): 25 %. A mark beyond the band acts only once the move has PERSISTED
/// for [`crate::price_history::GUARD_PERSIST_EPOCHS`] closed epochs on the same side (MakerDAO's OSM hour) — MEASURED
/// 2026-11-01 (lane defi, the crash pin): the band alone refused EVERY liquidation once a real move passed 25 % until the 7-day
/// average caught up, so a crash like BTC's 2020-03-12 (−50 % in a day) would have left the PSM unliquidated for days.
pub const LIQ_TWAP_BAND_BPS: u64 = 2_500;

/// The public genesis blind of the stakers' pool paid-out total (its genesis VALUE is public: zero).
pub const GENESIS_STAKE_PAID_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_7374_6b70, 0x6765_6e5f_7a65_726f]);
/// The PUBLIC blind the stakers' pool's public inflow is committed under for the supply step's bound: every node computes
/// `solvency_commit_256(inflow, STAKERS_POOL_PUBLIC_BLIND)` itself, so the bound hides nothing and invents nothing.
pub const STAKERS_POOL_PUBLIC_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_7374_6b69, 0x7075_626c_6963_5f69]);
fn genesis_stake_paid_commit() -> crate::spend_frontier::Digest4 {
    usdm_decider::confidential_solvency::solvency_commit_256(usdm_decider::confidential_solvency::u256_from_u64(0), GENESIS_STAKE_PAID_BLIND)
}
/// The commitment of the stakers' pool inflow `pool_in` under the public blind.
#[must_use]
pub fn stakers_pool_in_commit(pool_in: u64) -> crate::spend_frontier::Digest4 {
    usdm_decider::confidential_solvency::solvency_commit_256(usdm_decider::confidential_solvency::u256_from_u64(pool_in), STAKERS_POOL_PUBLIC_BLIND)
}

/// ⭐ §BR-3 17.6 — the yield `weight` earned between index `from` and `to`: ⌊weight · (to − from) / 2⁶⁴⌋, exact (the
/// difference is split into its whole and fractional 64-bit halves so no product overflows), 0 when `to ≤ from`.
#[must_use]
pub fn bond_yield_between(weight: u128, from: u128, to: u128) -> u64 {
    let d = to.saturating_sub(from);
    let (hi, lo) = (d >> 64, d & u128::from(u64::MAX));
    let whole = weight.saturating_mul(hi);
    let frac = weight.saturating_mul(lo) >> 64;
    u64::try_from(whole.saturating_add(frac)).unwrap_or(u64::MAX)
}

/// ⭐ §BR-14 — the four fee pools' balances (atomic USDm), read by the pins and the §BR-3/§BR-11 payers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FeePools {
    pub stakers: u64,
    pub bonders: u64,
    pub surplus: u64,
    pub miner: u64,
}

impl FeePools {
    /// Their sum — what the credits put in, exactly (`fee_split` conserves).
    #[must_use]
    pub fn total(&self) -> u128 {
        u128::from(self.stakers) + u128::from(self.bonders) + u128::from(self.surplus) + u128::from(self.miner)
    }
}

/// One wrapped-asset confidential PSM — the value-hiding reserve+minted digests + its over-collateralization ratio.
/// Commitment-only (no counters). Reused pattern from the USDm peg; `ratio_bps` is 15000 for a volatile asset or
/// 10000 for a vetted stablecoin (a stable asset needs no volatility buffer, so it is exempt from the 150%).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WrappedAsset {
    reserve_commit: crate::spend_frontier::Digest4,
    minted_commit: crate::spend_frontier::Digest4,
    ratio_bps: u32,
    /// This asset's own reserve HIGH-WATER MARK commitment — the per-asset mirror of
    /// [`PegLedger::reserve_hwm_commit`], so the ONE liquidation door bounds a wrapped-asset re-mark by the
    /// collateral REALLY deposited for THAT asset (never another's). Advanced only by the wrapped mint path.
    #[serde(default)]
    reserve_hwm_commit: crate::spend_frontier::Digest4,
}

/// The default REDEEM floor: 10000 bps = 100%, the true-solvency line. A Sell may draw the reserve buffer down to
/// exactly full backing (every USDm still redeemable for $1) but no further. Governance may retune it upward (a
/// larger safety buffer) at runtime without re-genesis; it can never be lowered below 100% at the constraint level
/// because a peg-out that leaves the post-state below full backing is genuine insolvency.
/// The genesis-default MINT over-collateralization ratio (bps): 15000 = 150%. THE consensus policy parameter every
/// peg-in / wrapped-asset mint proves against ([`PegLedger::orchestrate_peg_in`], [`PegLedger::orchestrate_wrapped_mint`]);
/// governance may retune it at runtime. Exposed so the node's sovereign server can compute a mint/burn QUOTE natively
/// (Pillar C — the node IS the backend) instead of proxying to a VPS.
pub const DEFAULT_MINT_RATIO_BPS: u32 = 15_000;
/// The genesis-default REDEEM (peg-out) solvency floor (bps): 10000 = 100% — a Sell redeems exactly $1 of reserve per
/// USDm (full backing, never below). Governance may retune upward, never below 100% at the constraint level.
pub const DEFAULT_REDEEM_FLOOR_BPS: u32 = 10_000;
pub fn default_redeem_floor_bps() -> u32 {
    DEFAULT_REDEEM_FLOOR_BPS
}

#[cfg(test)]
thread_local! {
    /// DB-124 FIXTURE PRICE: on by default on every test thread, so the pre-DB-124 fixtures (one USDm atomic per deposit atomic
    /// unit) keep their arithmetic; a real mark or TWAP always wins over it (it is the LAST fallback), and a pin that measures
    /// the unpriced, fail-closed door turns it off on its own thread with [`unprice_fixtures_for_test`].
    static FIXTURE_UNIT_PRICE: std::cell::Cell<bool> = const { std::cell::Cell::new(true) };
}

/// The test-only last-resort price (`None` in every non-test build: an unpriced asset proves no mint and no release).
#[cfg(test)]
fn fixture_unit_price() -> Option<u128> {
    FIXTURE_UNIT_PRICE.with(std::cell::Cell::get).then_some(crate::liquidation::PRICE_SCALE)
}
#[cfg(not(test))]
fn fixture_unit_price() -> Option<u128> {
    None
}

/// Turn the fixture price off on this test thread (the pin then measures the real, unpriced door).
#[cfg(test)]
pub fn unprice_fixtures_for_test() {
    FIXTURE_UNIT_PRICE.with(|f| f.set(false));
}

#[cfg(test)]
impl PegLedger {
    /// TEST — stand this ledger on a price mark for `asset_id` directly (a pin that seats its custodians by fixture has
    /// no quorum to run the real quote door with; the door has its own pins).
    pub fn set_price_mark_for_test(&mut self, asset_id: u32, price: u128, epoch_id: u64) {
        self.price_marks.insert(asset_id, crate::price_mark_tx::PriceMark { price, epoch_id });
    }
}

/// ⛔⛔ DB-417 — WHAT TURNS THE PEG LEDGER AFTER ONE FOLD STEP BACK INTO THE LEDGER BEFORE IT, on every field the snapshot
/// serializes and on nothing else: the before-value of each word or commitment the step moved, the ids each id set gained
/// (taken back out) and lost (put back), and the before-entry of each map key the step changed (`None` = absent before).
/// It is the persisted form of the node's object fold journal (`persist::PegCarry`): a checkpoint writes one per journaled
/// step, chained back from the snapshot's own ledger, so a restarted node rebuilds the exact before-images and can still
/// un-fold a step its fold made before the restart — the bond class's journal rule (`BondFoldStep`) and the directory's
/// (`DirFoldStep`), which carry only what each step touched, never the whole set.
/// O1-FOOTPRINT-REVIEWED: one entry per word, id or key a single fold step moved — bounded by the step's objects
/// (`BLOCK_FIXED_TX_COUNT`), never by the ledger's size or the chain's height.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PegUndo {
    /// `(field, before)` for each commitment the step moved: 0 reserve, 1 minted, 2 reserve high-water mark, 3 retention endowment.
    digests: Vec<(u8, crate::spend_frontier::Digest4)>,
    /// `(field, before)` for each word the step moved: 0 ratio, 1 yield rate, 2 redeem floor, 3 SAT issued, 4 pendulum
    /// epoch, 5 pendulum share, 6–9 the §BR-14 fee pools (stakers, bonders, surplus, miner), 10–13 the §BR-11 miner quarter
    /// (quarter + 1, rate, accrual, start ordinal).
    words: Vec<(u8, u64)>,
    /// `(field, ids to put back, ids to take out)` for each id set the step moved: 0 spent burns, 1 confidential deposit
    /// ids, 2 released, 3 liquidated. Sorted, so one undo has one encoding.
    sets: Vec<(u8, Vec<[u8; 32]>, Vec<[u8; 32]>)>,
    wrapped_assets: Vec<(u32, Option<WrappedAsset>)>,
    pools: Vec<(u32, Option<PoolWords>)>,
    pool_closes: Vec<((u32, u64), Option<PoolWords>)>,
    price_marks: Vec<(u32, Option<crate::price_mark_tx::PriceMark>)>,
    /// §BR-10: the deployment ledger's before-image, when the step moved it.
    #[serde(default)]
    deployments: Option<crate::deployment::DeploymentLedger>,
    /// §BR-10: the release-attestation registry's before-entries.
    #[serde(default)]
    release_attestations: Vec<([u8; 32], Option<crate::release_attestation_tx::ReleaseAttestationTx>)>,
    /// §BR-4: the price histories' before-entries.
    #[serde(default)]
    price_history: Vec<(u32, Option<crate::price_history::PriceHistory>)>,
    /// §BR-9a: the epoch-key ledger's before-image, when the step moved it.
    #[serde(default)]
    epoch_keys: Option<crate::epoch_deal_tx::EpochKeyLedger>,
    /// §19.4: the epoch anchors' before-image, when the step moved them.
    #[serde(default)]
    epoch_anchors: Option<std::collections::VecDeque<(u64, u64, crate::spend_frontier::Digest4)>>,
    /// §BR-8: the open decoys' before-entries.
    #[serde(default)]
    open_decoys: Vec<([u8; 32], Option<crate::decoy_tx::OpenDecoy>)>,
    /// §BR-4/§BR-7: the unit book before the step (only when it moved).
    #[serde(default)]
    unit_book: Option<crate::debt_units::UnitBook>,
    /// §BR-15: the DeFi book before the step (only when it moved).
    #[serde(default)]
    defi_book: Option<Vec<crate::defi_batch::DefiBook>>,
    /// SAFE AT SCALE, stage three: the custody key record's before-entries, by vault.
    #[serde(default)]
    vault_keys: Vec<(u32, Option<Vec<VaultKeyRow>>)>,
    /// SAFE AT SCALE, stage three: the parts at rest before the step, by giving vault.
    #[serde(default)]
    vault_parts: Vec<(u32, Option<VaultPart>)>,
    /// A-F31: the token registry before the step (only when a creation registered in it), as its count and peaks.
    #[serde(default)]
    dsol_tokens: Option<(u128, Vec<(u32, [u8; 32])>)>,
    /// IonSwap pools: the pending orders, the layer word and the pool count before the step (only when the step moved one).
    #[serde(default)]
    ion: Option<(Vec<crate::ion_pool_tx::IonPending>, u64, u64)>,
}

impl PegUndo {
    /// The step moved nothing the snapshot serializes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.digests.is_empty()
            && self.words.is_empty()
            && self.sets.is_empty()
            && self.wrapped_assets.is_empty()
            && self.pools.is_empty()
            && self.pool_closes.is_empty()
            && self.price_marks.is_empty()
            && self.deployments.is_none()
            && self.release_attestations.is_empty()
            && self.price_history.is_empty()
            && self.epoch_keys.is_none()
            && self.epoch_anchors.is_none()
            && self.open_decoys.is_empty()
            && self.unit_book.is_none()
            && self.defi_book.is_none()
            && self.vault_keys.is_empty()
            && self.vault_parts.is_empty()
            && self.dsol_tokens.is_none()
            && self.ion.is_none()
    }
}

/// The before-entry of every key whose value differs between `before` and `after` (`None` = the key was absent before).
fn map_undo<K: Ord + Clone, V: Clone + PartialEq>(
    before: &std::collections::BTreeMap<K, V>,
    after: &std::collections::BTreeMap<K, V>,
) -> Vec<(K, Option<V>)> {
    let keys: std::collections::BTreeSet<&K> = before.keys().chain(after.keys()).collect();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(|k| ((*k).clone(), before.get(k).cloned()))
        .collect()
}

/// Put every key of `undo` back to its before-entry.
fn map_apply<K: Ord + Clone, V: Clone>(map: &mut std::collections::BTreeMap<K, V>, undo: &[(K, Option<V>)]) {
    for (k, v) in undo {
        match v {
            Some(v) => {
                map.insert(k.clone(), v.clone());
            }
            None => {
                map.remove(k);
            }
        }
    }
}

/// One word field of the ledger, with its value typed as the field holds it.
enum PegWord {
    Ratio(u32),
    YieldRate(u32),
    RedeemFloor(u32),
    SatIssued(u64),
    PendulumEpoch(u64),
    PendulumShare(u32),
    FeePool(u8, u64),
}

impl PegWord {
    /// The typed word of an undo entry; `None` for a field tag this build does not know or a value its field cannot hold.
    fn of(field: u8, w: u64) -> Option<Self> {
        let narrow = u32::try_from(w).ok();
        match field {
            0 => narrow.map(Self::Ratio),
            1 => narrow.map(Self::YieldRate),
            2 => narrow.map(Self::RedeemFloor),
            3 => Some(Self::SatIssued(w)),
            4 => Some(Self::PendulumEpoch(w)),
            5 => narrow.map(Self::PendulumShare),
            6..=30 => Some(Self::FeePool(field, w)), // 29, 30: the custody cost words (SAFE AT SCALE §3f R6)
            _ => None,
        }
    }
}

impl PegLedger {
    /// ⛔⛔ DB-417 — the undo that turns `self` (the ledger after a step) back into `before` on every serialized field
    /// ([`PegUndo`]). Empty exactly when the two ledgers agree on every field the snapshot carries.
    /// ROOT-LAYER: the object fold journal is PRODUCED by the fold step (`push_objects_journal`) and lost at the checkpoint,
    /// which carried the bond and directory journals but not this one (`resume_from_checkpoint` set the floor to the resume
    /// point). The checkpoint is where the journal must be written; this is its encoding, beside the fields it encodes.
    /// MEASURED: sweep simpar-20261007-180330 — both reds (0x3 T1.7, 0xa T3) began with `[fold-conflict] a rewind reached
    /// below the peg ledger's fold journal` 1–2 records under node 0's resume point, right after its restart
    /// (t=877 s at served 443; t=1309 s at served 706), then a stale-spine adopt the journey could not recover from.
    /// MUST-STAY-GREEN: db274_p4b_a_rewind_below_the_object_journal_floor_marks_the_spine_stale (the floor rule itself),
    /// the db270 fold-record round trips, every peg / DEX / SAT fold pin.
    #[must_use]
    pub fn undo_to(&self, before: &PegLedger) -> PegUndo {
        // EXHAUSTIVE ON PURPOSE (no `..`): a field added to the ledger stops this compiling until its undo is written, so the
        // persisted journal can never silently skip a field a fold step moves.
        let PegLedger {
            applied_ids: _, // `#[serde(skip)]`: one apply's scratch, drained after every apply; never persisted or served
            reserve_commit,
            minted_commit,
            contract_state_root,
            spent_burns,
            confidential_deposit_ids,
            ratio_bps,
            yield_rate_bps,
            redeem_floor_bps,
            released,
            wrapped_assets,
            reserve_hwm_commit,
            liquidated,
            pools,
            pool_closes,
            price_marks,
            retention_endowment_commit,
            sat_issued,
            pendulum_epoch_next,
            pendulum_share_bps,
            fee_pool_stakers,
            fee_pool_bonders,
            fee_pool_surplus,
            fee_pool_miner,
            miner_quarter_next,
            miner_rate,
            miner_accrual,
            miner_quarter_start,
            bond_yield_lo,
            bond_yield_hi,
            bonder_accrual,
            set_aside_applied,
            deployments,
            release_attestations,
            stake_paid_commit,
            stakers_snap_epoch_next,
            stakers_snap_pool,
            price_history,
            epoch_keys,
            epoch_anchors,
            repayment_sat_pot,
            theft_loss_open_sats,
            repayment_owed_atomic,
            haircut_remainder_atomic,
            haircut_events,
            decoy_epoch_next,
            decoy_credit,
            decoy_budget,
            decoy_spent,
            custody_cost_debt,
            custody_cost_retired,
            open_decoys,
            unit_book,
            defi_book,
            vault_keys,
            vault_parts,
            dsol_tokens,
            ion_pending,
            ion_usdm_held,
            ion_pools,
            ion_fee_credit: _, // `#[serde(skip)]`: one step's scratch, drained inside the step; never persisted or served
        } = before;
        let mut u = PegUndo::default();
        for (field, b, a) in [
            (0u8, reserve_commit, &self.reserve_commit),
            (1, minted_commit, &self.minted_commit),
            (2, reserve_hwm_commit, &self.reserve_hwm_commit),
            (3, retention_endowment_commit, &self.retention_endowment_commit),
            (4, stake_paid_commit, &self.stake_paid_commit),
            // §BR-12 L1: the contract-state root a deploy or a call moved, undone with every other ledger word
            (5, contract_state_root, &self.contract_state_root),
        ] {
            if b != a {
                u.digests.push((field, *b));
            }
        }
        for (field, b, a) in [
            (0u8, u64::from(*ratio_bps), u64::from(self.ratio_bps)),
            (1, u64::from(*yield_rate_bps), u64::from(self.yield_rate_bps)),
            (2, u64::from(*redeem_floor_bps), u64::from(self.redeem_floor_bps)),
            (3, *sat_issued, self.sat_issued),
            (4, *pendulum_epoch_next, self.pendulum_epoch_next),
            (5, u64::from(*pendulum_share_bps), u64::from(self.pendulum_share_bps)),
            (6, *fee_pool_stakers, self.fee_pool_stakers),
            (7, *fee_pool_bonders, self.fee_pool_bonders),
            (8, *fee_pool_surplus, self.fee_pool_surplus),
            (9, *fee_pool_miner, self.fee_pool_miner),
            (10, *miner_quarter_next, self.miner_quarter_next),
            (11, *miner_rate, self.miner_rate),
            (12, *miner_accrual, self.miner_accrual),
            (13, *miner_quarter_start, self.miner_quarter_start),
            (14, *bond_yield_lo, self.bond_yield_lo),
            (15, *bond_yield_hi, self.bond_yield_hi),
            (16, *bonder_accrual, self.bonder_accrual),
            (17, *set_aside_applied, self.set_aside_applied),
            (18, *stakers_snap_epoch_next, self.stakers_snap_epoch_next),
            (19, *stakers_snap_pool, self.stakers_snap_pool),
            (20, *repayment_sat_pot, self.repayment_sat_pot),
            (21, *theft_loss_open_sats, self.theft_loss_open_sats),
            (22, *repayment_owed_atomic, self.repayment_owed_atomic),
            (23, *haircut_remainder_atomic, self.haircut_remainder_atomic),
            (24, *haircut_events, self.haircut_events),
            (25, *decoy_epoch_next, self.decoy_epoch_next),
            (26, *decoy_credit, self.decoy_credit),
            (27, *decoy_budget, self.decoy_budget),
            (28, *decoy_spent, self.decoy_spent),
            (29, *custody_cost_debt, self.custody_cost_debt),
            (30, *custody_cost_retired, self.custody_cost_retired),
        ] {
            if b != a {
                u.words.push((field, b));
            }
        }
        for (field, b, a) in [
            (0u8, spent_burns, &self.spent_burns),
            (1, confidential_deposit_ids, &self.confidential_deposit_ids),
            (2, released, &self.released),
            (3, liquidated, &self.liquidated),
        ] {
            let mut put_back: Vec<[u8; 32]> = b.difference(a).copied().collect();
            let mut take_out: Vec<[u8; 32]> = a.difference(b).copied().collect();
            if !put_back.is_empty() || !take_out.is_empty() {
                put_back.sort_unstable();
                take_out.sort_unstable();
                u.sets.push((field, put_back, take_out));
            }
        }
        u.wrapped_assets = map_undo(wrapped_assets, &self.wrapped_assets);
        u.pools = map_undo(pools, &self.pools);
        u.pool_closes = map_undo(pool_closes, &self.pool_closes);
        u.price_marks = map_undo(price_marks, &self.price_marks);
        u.deployments = (deployments != &self.deployments).then(|| deployments.clone());
        u.release_attestations = map_undo(release_attestations, &self.release_attestations);
        u.price_history = map_undo(price_history, &self.price_history);
        u.epoch_keys = (epoch_keys != &self.epoch_keys).then(|| epoch_keys.clone());
        u.epoch_anchors = (epoch_anchors != &self.epoch_anchors).then(|| epoch_anchors.clone());
        u.open_decoys = map_undo(open_decoys, &self.open_decoys);
        u.unit_book = (unit_book != &self.unit_book).then(|| unit_book.clone());
        u.defi_book = (defi_book != &self.defi_book).then(|| defi_book.clone());
        u.vault_keys = map_undo(vault_keys, &self.vault_keys);
        u.vault_parts = map_undo(vault_parts, &self.vault_parts);
        // A-F31: the registry is append-only, so a different count is a different registry
        u.dsol_tokens = (dsol_tokens.count() != self.dsol_tokens.count()).then(|| dsol_tokens.parts());
        u.ion = (ion_pending != &self.ion_pending || *ion_usdm_held != self.ion_usdm_held || *ion_pools != self.ion_pools)
            .then(|| (ion_pending.clone(), *ion_usdm_held, *ion_pools));
        u
    }

    /// ⛔⛔ DB-417 — apply `u` (from [`Self::undo_to`]) to this ledger, turning it back into the ledger before that step.
    /// `false`, with NOTHING changed, when the undo names a field this build does not know or a word its field cannot hold
    /// (a foreign or corrupt journal): the caller then keeps no journal, and a rewind below its resume point marks the spine
    /// stale, exactly as before the journal was carried.
    #[must_use]
    pub fn apply_undo(&mut self, u: &PegUndo) -> bool {
        let Some(words) = u.words.iter().map(|(f, w)| PegWord::of(*f, *w)).collect::<Option<Vec<PegWord>>>() else {
            return false;
        };
        if u.digests.iter().any(|(f, _)| *f > 5) || u.sets.iter().any(|(f, _, _)| *f > 3) {
            return false;
        }
        // A-F31: a carried registry image that does not describe its own count is a foreign or corrupt journal
        let tokens = match &u.dsol_tokens {
            Some((count, peaks)) => match crate::dsol::DsolRegistry::from_parts(*count, peaks) {
                Some(r) => Some(r),
                None => return false,
            },
            None => None,
        };
        if let Some(r) = tokens {
            self.dsol_tokens = r;
        }
        if let Some((pending, held, pools)) = &u.ion {
            self.ion_pending = pending.clone();
            self.ion_usdm_held = *held;
            self.ion_pools = *pools;
        }
        for (field, d) in &u.digests {
            match field {
                0 => self.reserve_commit = *d,
                1 => self.minted_commit = *d,
                2 => self.reserve_hwm_commit = *d,
                3 => self.retention_endowment_commit = *d,
                4 => self.stake_paid_commit = *d,
                _ => self.contract_state_root = *d, // 5, §BR-12 L1
            }
        }
        for w in words {
            match w {
                PegWord::Ratio(v) => self.ratio_bps = v,
                PegWord::YieldRate(v) => self.yield_rate_bps = v,
                PegWord::RedeemFloor(v) => self.redeem_floor_bps = v,
                PegWord::SatIssued(v) => self.sat_issued = v,
                PegWord::PendulumEpoch(v) => self.pendulum_epoch_next = v,
                PegWord::PendulumShare(v) => self.pendulum_share_bps = v,
                PegWord::FeePool(f, v) => match f {
                    6 => self.fee_pool_stakers = v,
                    7 => self.fee_pool_bonders = v,
                    8 => self.fee_pool_surplus = v,
                    9 => self.fee_pool_miner = v,
                    10 => self.miner_quarter_next = v,
                    11 => self.miner_rate = v,
                    12 => self.miner_accrual = v,
                    13 => self.miner_quarter_start = v,
                    14 => self.bond_yield_lo = v,
                    15 => self.bond_yield_hi = v,
                    16 => self.bonder_accrual = v,
                    17 => self.set_aside_applied = v,
                    18 => self.stakers_snap_epoch_next = v,
                    19 => self.stakers_snap_pool = v,
                    20 => self.repayment_sat_pot = v,
                    21 => self.theft_loss_open_sats = v,
                    22 => self.repayment_owed_atomic = v,
                    23 => self.haircut_remainder_atomic = v,
                    24 => self.haircut_events = v,
                    25 => self.decoy_epoch_next = v,
                    26 => self.decoy_credit = v,
                    27 => self.decoy_budget = v,
                    28 => self.decoy_spent = v,
                    29 => self.custody_cost_debt = v,
                    _ => self.custody_cost_retired = v, // 30
                },
            }
        }
        for (field, put_back, take_out) in &u.sets {
            let set = match field {
                0 => &mut self.spent_burns,
                1 => &mut self.confidential_deposit_ids,
                2 => &mut self.released,
                _ => &mut self.liquidated,
            };
            for id in take_out {
                set.remove(id);
            }
            set.extend(put_back.iter().copied());
        }
        map_apply(&mut self.wrapped_assets, &u.wrapped_assets);
        map_apply(&mut self.pools, &u.pools);
        map_apply(&mut self.pool_closes, &u.pool_closes);
        map_apply(&mut self.price_marks, &u.price_marks);
        map_apply(&mut self.price_history, &u.price_history);
        map_apply(&mut self.open_decoys, &u.open_decoys);
        map_apply(&mut self.vault_keys, &u.vault_keys);
        map_apply(&mut self.vault_parts, &u.vault_parts);
        if let Some(b) = &u.unit_book {
            self.unit_book = b.clone();
        }
        if let Some(b) = &u.defi_book {
            self.defi_book = b.clone();
        }
        if let Some(d) = &u.deployments {
            self.deployments = d.clone();
        }
        map_apply(&mut self.release_attestations, &u.release_attestations);
        if let Some(e) = &u.epoch_keys {
            self.epoch_keys = e.clone();
        }
        if let Some(a) = &u.epoch_anchors {
            self.epoch_anchors = a.clone();
        }
        true
    }
}

/// Domain-separated PEG-IN attestation message — binds the UNIQUE deposit id, the post-state reserve and
/// minted COMMITMENTS, the committed mint delta, the recipient and the proposal nonce, so a threshold
/// signature cannot be replayed to a different deposit, transition, recipient or proposal.
///
/// ⛔ WHAT THIS MESSAGE DOES **NOT** BIND, corrected 2026-09-22 (DB-124). This doc used to claim it bound
/// "the deposited amount + the ATTESTED PRICE", and concluded "over-mint is impossible". Read the body: the
/// statement is `deposit_id || new_reserve_commit || new_minted_commit || delta_commit || recipient ||
/// proposal_nonce`. There is NO price in it and no cleartext amount — that description belonged to the v1
/// message and survived the move to the confidential v3 statement as a false claim about funds safety, which
/// is worse than no comment at all: an auditor who reads "over-mint is impossible" stops looking.
///
/// Over-mint WAS possible. Every custodian re-derives the commitments from the SAME sealed delta, so a
/// proposal pairing a tiny `deposit_value` with an enormous `mint` produced commitments that matched on
/// every custodian and passed. The quorum bounds WHO may authorise a transition; it never said what the
/// deposit was WORTH. That is now enforced one layer down, at each custodian's own sign decision, by
/// [`PegLedger::mint_is_covered_by_priced_deposit`] against the chain's ≥2/3-attested
/// [`crate::price_mark_tx`] mark — so the "decentralized price oracle" this comment described finally
/// exists, as an object the block carries rather than as a sentence.
pub fn peg_in_confidential_msg(
    deposit_id: &[u8; 32],
    new_reserve_commit: &crate::spend_frontier::Digest4,
    new_minted_commit: &crate::spend_frontier::Digest4,
    // DB-80: the committed mint delta the two carriers agree on — attested, so the publisher cannot pair
    // the attested commitments with another mint-validity carrier's commitment.
    delta_commit: &crate::spend_frontier::Digest4,
    recipient: &[u8; 32],
    // ⭐ THE PROPOSAL INSTANCE (v2, 2026-09-17). Without it a custodian's signature over
    // `(deposit, commits, recipient)` stayed valid for EVERY executor that ever proposed that exact
    // transition — and on a real mesh a peer re-presented one executor's stale signature (a gossip
    // re-delivery) to complete a second executor's quorum for the same deposit (seat journey run 7). The
    // executor draws this nonce once per proposal; it rides the `Class::PegIn` object so every node
    // rebuilds the same statement at apply, and a signature never outlives the proposal it was for.
    proposal_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 32 + 64 + 64 + 32 + 32);
    // v3 (DB-80): the delta commitment is in the statement. v4 (F-LEG, 2026-11-11): `recipient` here is
    // `peg_in_signed_recipient` — the recipient bound to the sealed legs — at every site; the tag moves with it, so a v3
    // signature (legs unbound) can never complete a v4 object.
    m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.in.conf.v4"));
    m.extend_from_slice(deposit_id);
    for x in new_reserve_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in new_minted_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in delta_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(recipient);
    m.extend_from_slice(proposal_nonce);
    m
}

/// IonSwap CONFIDENTIAL WRAPPED-MINT attestation message. The ≥2/3 threshold signs THIS, binding the wrapped
/// `asset_id` + the UNIQUE foreign deposit id + the NEW committed pair (reserve/minted digests AFTER the mint) +
/// the recipient. The asset-id + deposit-id binding makes an attestation single-use for exactly one wrap of
/// exactly one asset from exactly one deposit — it can't be replayed to a different asset, deposit, or recipient.
/// Domain-separated from `musdm.peg.in.conf.v1` so a USDm peg-in attestation can never authorize a wrapped mint.
pub fn wrapped_mint_confidential_msg(
    asset_id: u32,
    deposit_id: &[u8; 32],
    new_reserve_commit: &crate::spend_frontier::Digest4,
    new_minted_commit: &crate::spend_frontier::Digest4,
    // DB-80b: the committed mint delta both carriers open — attested, so the publisher cannot pair the
    // attested transition with another asset-mint-validity carrier's figure. The amount is never here.
    delta_commit: &crate::spend_frontier::Digest4,
    recipient: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(24 + 4 + 32 + 64 + 64 + 32);
    // v3 (F-LEG, 2026-11-11): `recipient` here is `peg_in_signed_recipient` (the recipient bound to the sealed legs)
    m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.wrap.mint.conf.v3"));
    m.extend_from_slice(&asset_id.to_le_bytes());
    m.extend_from_slice(deposit_id);
    for x in new_reserve_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in new_minted_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in delta_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(recipient);
    m
}

/// DB-93 (2026-09-19) — THE DEPOSIT ID IS A FUNCTION OF THE DEPOSIT'S OWN RESERVE ADDRESS (per-swap,
/// threshold-custodied, single-use), never a value the requester chooses. The replay guard
/// (`confidential_deposit_ids`) keys on the deposit id; until now the wallet chose it (`blake3("peg-in:" ‖
/// swap_id)`), and each custodian's only deposit check was "does this address hold ≥ the sealed value" — an
/// address is never consumed, so ONE deposit could mint under a fresh id as often as asked: unbacked USDm against
/// a reserve that believed itself whole. Borrowed from tBTC v2 (the deposit key is a function of the deposit's
/// own on-chain identity; every deposit address is single-use) and THORChain (an observation is keyed by its
/// inbound tx). Each swap gets its own per-swap reserve address (a fresh nonce under the t-of-n group key), so
/// one mint per address is one mint per deposit. The wallet, the request door, the custodian's lane step and
/// the attesting custodian each compute this function of the sealed address and refuse any other id.
/// Privacy: a funded reserve address is public on Bitcoin, so linking a mint OBJECT to its deposit is the
/// bridge's inherent transparency (Zcash's t→z shielding has the same edge); the USDm note is confidential.
/// ⭐⭐⭐ DB-273 §17 — THE PEG-IN RECIPIENT IS A COMMITMENT TO ITS OWNER CLUE: `recipient = H(domain ‖ deposit_id ‖
/// owner_clue_digest(clue))`. The recipient is already inside the quorum's signed statement
/// ([`peg_in_confidential_msg`] / [`wrapped_mint_confidential_msg`]), so binding the clue HERE puts it under the
/// custodians' signatures with no new field in the statement or the proposal (condition 4: the attesters sign over the
/// clue before anything mints). `peg_in_tx::decode` refuses an object whose carried clue does not open its recipient,
/// or that carries none (condition 1), so a relay that strips or replaces the clue gets a refused object, never a
/// note settled unfiled.
/// Per-deposit: two mints by one wallet name two unrelated recipients (the property the v1 tag had).
/// cons: none — one hash, no field added to the statement; the clue rides the object once (`omr::Clue::BYTES`, the
/// same bytes the note's own OLI record already carried in the tx sidecar), and the (bucket 32 + ek 1,184 + len 2) B
/// account target it replaces leaves the transaction.
#[must_use]
pub fn peg_in_recipient(deposit_id: &[u8; 32], owner_clue: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/peg-in/recipient/v2");
    h.update(deposit_id);
    h.update(&crate::oli::owner_clue_digest(owner_clue));
    *h.finalize().as_bytes()
}

/// ⭐ F-LEG FOR A DEPOSIT (finding A-F18's class, the mint half; 2026-11-11) — WHAT THE QUORUM SIGNS IN THE RECIPIENT'S
/// PLACE: the recipient bound to the sealed legs the object carries. Every statement site of a mint
/// ([`peg_in_confidential_msg`] v4, [`wrapped_mint_confidential_msg`] v3) passes this value where it passed the bare
/// recipient: the proposal a custodian signs (`PegInProposal::statement`), the executor's own signature, the publish
/// check and the block apply — each over the legs IT holds (the proposal's, the object's).
///
/// WHAT WAS OPEN (docs/BRIDGE-CUSTODY-OBJECTS-20261110.md, rows PegIn and WrappedMint): the statement bound the deposit
/// id, the pairs after, the committed mint and the recipient — and none of the per-custodian envelopes. A leg is sealed
/// to a PUBLIC ML-KEM key, so anyone holding the signed object could seal a leg of their own to a custodian and re-frame
/// it: the signatures still verified, the mint still applied, and that custodian booked the reserve coin, the sweep
/// authority and the opening its re-sealed leg named (or none: its opening went stale and it could sign nothing more).
/// The cash-out closed the same hole in v7 (`peg_out_tx::signed_redeem_commit`); this is the same bind, same place.
///
/// §9.6, the PegIn and WrappedMint doors (admission changes): (1) proof of work: the object's pool stamp, unchanged;
/// (2) proof/signature: the quorum's ML-DSA signatures are now tallied over a statement that names every envelope
/// byte, by the same `vault_signed` rule; (3) value: nothing new can mint — the statement is narrower, never wider;
/// (4) replay: the deposit id's set, unchanged; a re-sealed copy is a different statement with no signatures;
/// (5) bounded work: one blake3 over at most `PEG_ATTEST_SEALED_MAX` envelopes of `sealed_len()` bytes, before any
/// signature is verified; (6) parity: the cash-out door binds its legs the same way (v7) — the two doors now agree;
/// (7) scale: the hashed bytes are the envelopes the object already carries — sixteen per vault when a vault signs
/// alone, the bonded set's otherwise (the object's own size, not a new term); nothing per height; (8) AI RESISTANT:
/// protected by (b) code and economics — the custody quorum's signatures — as the mint already was; what a lying
/// executor still controls is what it seals to a custodian that does not sign, and that custodian now checks its leg
/// against the object before it books anything (`Node::mint_leg_checked`); a persuasive message gains nothing: no
/// person is asked.
/// cons: one hash per statement; a signature given under v3 completes no v4 object (the tags moved), so a mint in
/// flight across the upgrade is proposed again.
/// BORROWED: this tree's own cash-out bind (v7, lane owed); Bitcoin's SIGHASH_ALL — a signature covers every output
/// the transaction carries, so nobody edits one after the signers signed.
#[must_use]
pub fn peg_in_signed_recipient(recipient: &[u8; 32], sealed: &[([u8; 32], Vec<u8>)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/peg-in/signed-recipient/v1");
    h.update(recipient);
    h.update(&(sealed.len() as u64).to_le_bytes());
    for (id, blob) in sealed {
        h.update(id);
        h.update(&(blob.len() as u64).to_le_bytes());
        h.update(blob);
    }
    *h.finalize().as_bytes()
}

#[must_use]
pub fn deposit_id_for_reserve_address(reserve_address: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/peg-in/deposit-id-from-reserve-address/v1");
    h.update(reserve_address.trim().as_bytes());
    *h.finalize().as_bytes()
}

/// The per-asset replay key for a wrapped-asset foreign deposit — `blake3(domain || asset_id || deposit_id)`.
/// Namespaces the wrapped deposit into the SAME persisted `confidential_deposit_ids` replay set as USDm peg-ins
/// WITHOUT collision: a wrapped deposit id can never equal a raw USDm deposit id, and asset A's deposit can never
/// equal asset B's — so one persisted no-double-mint guard covers USDm + every wrapped asset (no extra snapshot field).
pub fn wrapped_deposit_key(asset_id: u32, deposit_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-WRAP-DEP-ID");
    h.update(&asset_id.to_le_bytes());
    h.update(deposit_id);
    *h.finalize().as_bytes()
}

/// #75 — CONFIDENTIAL PEG-OUT attestation message. Binds the UNIQUE burned USDm nullifier + the NEW committed
/// state (reserve/minted digests AFTER the reduction) + the external withdrawal address. The threshold attests
/// the commitment transition, never the burned or released amount; the reduction's validity (conservation +
/// post-state ≥150% backing, no drain) is the WHIR-bound carrier verified alongside.
/// DB-110 (2026-09-19): COMMIT TO THE PEG-OUT'S DESTINATION ADDRESS. The address itself rides only the
/// per-custodian sealed `PegOutDelta`; the chain object and the attested message carry this commitment, so no
/// node and no chain observer learns which Bitcoin address a burn pays (the leak the user named: "my goal is
/// for the transparent chain peg out assets to also be unlinkable to the person cashing them out"). A keyed
/// hash, not the solvency commitment, because an address is a byte string rather than a u256 — and because it
/// enters no ZK carrier, so this costs no circuit change. Binding: the blind is 32 bytes of the redeemer's own
/// entropy, so a guessed address cannot be confirmed against the commitment without it.
#[must_use]
/// §BR-1 (2026-10-28): the commitment binds the piece's `pay_after` beside its destination — the earliest chain height
/// the piece may be paid at (the privacy delay the wallet drew), so every custodian signs one delay and no payout can
/// move it. v2 of the domain: a v1 commitment never equals a v2 one.
pub fn redeem_commit(redeem_to: &[u8], pay_after: u64, r_blind: &crate::spend_frontier::Digest4) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/peg-out/redeem-commit/v2");
    h.update(&crate::spend_frontier::digest_to_lane_bytes(r_blind));
    h.update(&(redeem_to.len() as u64).to_le_bytes());
    h.update(redeem_to);
    h.update(&pay_after.to_le_bytes());
    *h.finalize().as_bytes()
}

/// §BR-1: the furthest a redeem's sealed `pay_after` (chain-time ms, `Node::chain_time_ms`) may lie past the chain clock —
/// 24 hours (spec §3.4's cap). A longer delay is a request the executor and every attestor refuse; a shorter one is the
/// user's own draw. It was 172,800 blocks, "24 hours of 500 ms blocks": 24 DAYS at the real rate (about 5 a minute).
pub const PAY_AFTER_MAX_MS: u64 = 86_400_000;

/// ⭐ §19.4 — the CHAIN-TIME spacing of the epoch anchors a cash-out claim anchors its member leg to: the first fold step in
/// each later 10-minute slot of the chain clock (`Node::chain_time_ms_at`) is one. A wallet waits at most this long after its
/// staged piece folds before its claim can be proven, at any block rate. It was 1,200 fold steps, "10 min at the 500 ms
/// target": 4 hours at the real rate (MEASURED 2026-11-08, real nodes: a fast cash-out sat staged its whole 20 minutes).
pub const EPOCH_ANCHOR_MS: u64 = 600_000;

/// ⭐ §19.4 — how many epoch anchors the fold keeps: enough to cover the longest pay-after plus two reward epochs (the batch
/// at the end of the piece's epoch, and the epoch a claim was proven in), so every claim's anchor is still held at its batch.
/// 158 anchors (about 9 KB), at any block rate.
pub const EPOCH_ANCHORS_KEPT: usize = ((PAY_AFTER_MAX_MS + 2 * crate::epoch_deal_tx::EPOCH_MS) / EPOCH_ANCHOR_MS) as usize + 2;

/// ⭐ B15 — the blind of a peg-out's burn commitment: derived from the piece's leg blind (sealed to every custodian, held by the
/// requester), so the requester, every attesting custodian and the executor form ONE commitment without another secret.
#[must_use]
pub fn peg_out_burn_blind(leg_blind: &crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/peg-out/burn-blind/v1");
    h.update(&crate::spend_frontier::digest_to_lane_bytes(leg_blind));
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// ⭐ B15 — the burn commitment a peg-out of `burn` USDm atomic under leg blind `leg_blind` opens (the committed burn carrier's
/// and the burn-bound solvency carrier's one number).
#[must_use]
pub fn peg_out_burn_commit(burn: u128, leg_blind: &crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
    usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(burn), peg_out_burn_blind(leg_blind))
}

/// TEST — a cash-out's proof bundle over a FRESH test note: the committed burn of `burn` (its burned output opened for
/// `redeem_commit` and `leg_blind`), the §19.5b cover proven from the custodian's `openings` of BOTH bridge ledgers with
/// `mover` paying, and a one-byte membership field the LEDGER door never reads. A real one-step membership exists only
/// against a node's own member tree (a fresh test note is in none); the node's fold verifies it, and the two-custodian
/// peg-out pin carries a real one end to end. Returns `(proof bytes, nullifier, leaf_commit, change_cm, header pair, the
/// openings after)`; `None` when a carrier does not prove.
#[cfg(test)]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn peg_out_proofs_for_test(
    peg: &PegLedger,
    openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
    mover: u32,
    release: u128,
    burn: u64,
    leg_blind: &crate::spend_frontier::Digest4,
    redeem_commit: &[u8; 32],
) -> Option<(
    Vec<u8>,
    [u8; 32],
    crate::spend_frontier::Digest4,
    [u8; 32],
    (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
)> {
    peg_out_proofs_for_test_at(0, peg, openings, mover, release, burn, leg_blind, redeem_commit)
}

/// [`peg_out_proofs_for_test`] for a burn paid by vault `vault` (its own bridge ledgers; the proofs name its ledger).
#[cfg(test)]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn peg_out_proofs_for_test_at(
    vault: u32,
    peg: &PegLedger,
    openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
    mover: u32,
    release: u128,
    burn: u64,
    leg_blind: &crate::spend_frontier::Digest4,
    redeem_commit: &[u8; 32],
) -> Option<(
    Vec<u8>,
    [u8; 32],
    crate::spend_frontier::Digest4,
    [u8; 32],
    (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
)> {
    use usdm_decider::poseidon2_compress::lanes_of;
    use usdm_decider::whir_rec_block as wr;
    let fee = wr::PROTOCOL_FEE_ATOMIC;
    let value_in = burn.checked_add(fee)?.checked_add(1_000)?;
    let w = wr::SpendValidityWitness {
        value_in,
        owner: wr::NoteOwner::from_test_key(lanes_of(&[0x15B, burn, 1, 1])),
        value_out: value_in - fee,
        fee,
        lc_blind: lanes_of(&[0x15B, 2, 2, 2]),
        out0_value: burn,
        out0_opening: crate::cashout_ticket::burn_out_opening(redeem_commit, leg_blind),
        out1_value: 1_000,
        out1_opening: lanes_of(&[0x15B, 3, 3, 3]),
    };
    let (burn_carrier, cms, nf, lc, bc) = wr::prove_burn_validity_committed_bytes(&w, &peg_out_burn_blind(leg_blind))?;
    if bc != peg_out_burn_commit(u128::from(burn), leg_blind) {
        return None;
    }
    let (solvency, hr, hm, after) =
        peg.orchestrate_cover_at(vault, false, mover, openings, release, u128::from(burn), leg_blind, &peg_out_burn_blind(leg_blind), None)?;
    let proofs = crate::peg_out_tx::PegOutProofs {
        solvency,
        burn_commit: bc,
        out0_cm: crate::spend_frontier::leaf_to_cm_bytes(cms[0]),
        burn: burn_carrier,
        membership: vec![1u8],
        tip: Vec::new(),
        coin: vault_ledger(vault, NATIVE_PEG_ASSET_ID),
    };
    Some((proofs.encode()?, crate::spend_frontier::leaf_to_cm_bytes(nf), lc, crate::spend_frontier::leaf_to_cm_bytes(cms[1]), (hr, hm), after))
}

/// TEST — a genesis ledger whose NATIVE pair stands at `(reserve, minted)` under `(rb, mb)` (Monero's own ledger at its
/// genesis), and the openings of both bridge ledgers the custodians hold there (§19.5b: every peg proves from both).
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn ledger_at_for_test(
    ratio_bps: u32,
    reserve: u128,
    rb: crate::spend_frontier::Digest4,
    minted: u128,
    mb: crate::spend_frontier::Digest4,
) -> (PegLedger, [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2]) {
    let mut peg = PegLedger::genesis(ratio_bps);
    let (r, m) = PegLedger::commits_of_opening(reserve, rb, minted, mb);
    peg.initialize_solvency_commitments(r, m);
    let (xr, xm) = psm_genesis_blinds(XMR_PEG_ASSET_ID);
    (peg, [(reserve, rb, minted, mb), (0, xr, 0, xm)])
}

pub fn peg_out_confidential_msg(
    usdm_nullifier: &[u8; 32],
    new_reserve_commit: &crate::spend_frontier::Digest4,
    new_minted_commit: &crate::spend_frontier::Digest4,
    // DB-110: the COMMITMENT to the destination address, never the address (see `redeem_commit`). ⭐ v6 (2026-11-01): on a
    // ticketed cash-out every caller passes `peg_out_tx::signed_redeem_commit` — the ticketed commitment bound to the ticket
    // bytes and epoch ciphertext the object carries — so a swapped ticket part voids the quorum's signatures.
    redeem_commit: &[u8; 32],
    // ⭐ v2 (2026-09-17): the executor's PROPOSAL NONCE rides the statement, exactly as the peg-in's
    // does — a signature a custodian gave one redeem proposal can never complete a later proposal
    // for the same nullifier that a peer re-delivers (the §DA-5 shape, one lane over).
    proposal_nonce: &[u8; 32],
    // ⭐ The burned note's cross-bind commit (§BB for the redeem): what every attesting custodian
    // verified the burn carrier against, so the object that carries it cannot swap it after the
    // quorum signed — the block door justifies the note's deletion by exactly this value.
    leaf_commit: &crate::spend_frontier::Digest4,
    // ⭐ v4 (DB-273 §19.3 L2): the CHANGE note's owner — `peg_out_tx::change_owner_of(clue)`, the canonical clue digest
    // (all-zero when no change note rides). Signed, so a relay that strips or replaces the carried clue voids the object.
    change_owner: &[u8; 32],
    // ⛔⛔⛔ v5 (DB-365): the CHANGE note's COMMITMENT — `leaf_to_cm_bytes(out1_cm)`, the out1 the burn carrier binds with
    // conservation and every attesting custodian verified it against. v4 signed the change's owner clue but never its
    // commitment, so a relay re-framed an honest, quorum-signed peg-out with a change note of its OWN (MEASURED: a
    // 10⁹-unit note justified on a peer fed only the block). `peg_out_tx::decode` refuses a carried change note whose
    // commitment is not this value.
    change_cm: &[u8; 32],
) -> Vec<u8> {
    let redeem_to: &[u8] = redeem_commit;
    let mut m = Vec::with_capacity(24 + 32 + 64 + 32 + 64 + 32 + 32 + redeem_to.len());
    // v7 (F-LEG, 2026-11-10): `redeem_commit` here is `peg_out_tx::signed_redeem_commit`, which now binds the sealed legs
    // too; the tag moves with it, so a v6 signature (legs unbound) can never complete a v7 object.
    m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.out.conf.v7"));
    m.extend_from_slice(usdm_nullifier);
    for x in new_reserve_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    for x in new_minted_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(proposal_nonce);
    for x in leaf_commit {
        m.extend_from_slice(&x.to_le_bytes());
    }
    m.extend_from_slice(change_owner);
    m.extend_from_slice(change_cm);
    m.push(0);
    m.extend_from_slice(redeem_to);
    m
}

// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE LIQUIDATION / COLLATERAL RE-MARK DOOR — closing the classic stablecoin liquidation danger
// ══════════════════════════════════════════════════════════════════════════════════════════════════════════════
//
// THE FAILURE MODE THIS EXISTS TO CLOSE, WITH NUMBERS. `peg_out_confidential` returns the position's FULL ORIGINAL
// deposit. A position opens at the 150% mint ratio: a deposit worth $150 of BTC mints 100 USDm. Let BTC fall 33.4%.
// The collateral is now worth $99.90 while the holder holds 100 USDm. Redeeming means burning 100 USDm (worth $100)
// to get back $99.90 of BTC — a losing trade. The rational holder ABANDONS the position: they keep the USDm, which
// is worth MORE than the collateral behind it, and never redeems. The collateral stays in the reserve but the
// liability never retires. Repeat that across a book and the reserve backs less than the USDm outstanding — and
// then the 100%-backing hard block in [`PegLedger::peg_out_confidential`] (`redeem_floor_bps`) fires on the HONEST
// redeemers who did show up, while every abandoner already walked. The safety check punishes the wrong people.
// Nothing in the peg closed a position for undercollateralization; the ONLY close was voluntary redemption.
//
// THE CURE — ONE DOOR. A position whose mark-to-market backing falls below the LIQUIDATION THRESHOLD is closed by
// the protocol, on the same >=2/3 bonded ML-DSA quorum that already prices peg-in and peg-out: the collateral is
// SEIZED (it stays in the reserve; it is not returned), the position's liability is retired against it, and the
// holder KEEPS the USDm they already minted. That is exactly the trade the abandoner would have taken anyway — but
// taken at the threshold (backing still ABOVE 100%) instead of below it, so the surplus between the seized
// collateral and the retired liability stays in the reserve FOREVER. That surplus is why the peg STRENGTHENS:
// every liquidation raises the aggregate ratio for the holders who stay (see [`crate::liquidation`], pin 5).
//
// COST — NO PILLAR IS TRADED, with the arithmetic for the only axis that could grow.
//   • PRIVACY / digital-cash: unchanged. Every new field is a commitment or a hash; the door learns no value, no
//     identity, no linkage, and `revalue_msg` carries digests only. No counter, no total, no plaintext amount.
//   • NO-GROWTH: `reserve_hwm_commit` is 32 B FIXED per PSM — f(registered assets), never f(history). The
//     `liquidated` replay set is 32 B per CLOSED POSITION, and that position ALREADY cost 32 B in
//     `confidential_deposit_ids` when it opened, so this adds NO NEW growth AXIS: it at most doubles an existing
//     per-position class. 32 B x 100,000 lifetime positions = 3.2 MB, one-time per position — never per block,
//     never per note, never per peer. (Contrast a per-EPOCH re-mark set, which WOULD be f(time) — refused.)
//   • SOUNDNESS: cons: none. Nothing existing is relaxed. The door ADDS two in-circuit ge256 constraints on a path
//     that previously did not exist at all, and `minted_commit` is structurally absent from it, so the one
//     inflation direction (mint against a re-marked-up reserve) has no encoding here to attempt.
//   • SCALE: the door runs exactly two `verify_peg_in_carrier` calls over the decider's fixed-shape AIR trace
//     (`1 << REC_DECIDER_FOLDING` rows, 4-limb commitments) — the SAME verification the peg-in door already
//     performs on every mint, so this lane changes the shape of the peg's per-op verification not at all.
//     [`MAX_REVALUATION_CARRIER_BYTES`] is a malformed-input guard on the wire blob and nothing more: it refuses
//     an oversized byte string, never an owned note and never a real position.
//
// WHY THE THRESHOLD IS DERIVED, NOT SETTABLE — see [`PegLedger::liquidation_threshold_bps`].

/// The NATIVE (USDm) peg's asset id for the liquidation door — the door is ONE function over every PSM, and this
/// is how the native reserve is addressed. Wrapped assets use their registered `asset_id` (which is never 0,
/// because [`PegLedger::register_wrapped_asset`] is the only way an id enters `wrapped_assets`, and the native peg
/// is not in that map).
pub const NATIVE_PEG_ASSET_ID: u32 = 0;

/// ⭐ THE MONERO PEG'S ASSET ID (`ASSETS[1]`) — Monero's OWN ledger: a PSM of its own whose reserve counts PICONERO, priced
/// by the XMR mark (the onion price relays quote it as `price_relay::XMR_ASSET_ID`, this same id), minting and redeeming
/// USDm exactly like the native ledger does for satoshis. BORROWED: THORChain's per-asset pools — one pool per external
/// asset, each valued by its own price, none ever counting another's units. Born at genesis on every node
/// ([`PegLedger::genesis`]); its ratio is retuned only by the attested registration door.
pub const XMR_PEG_ASSET_ID: u32 = 1;

/// ⭐ §19.5b — the bridge ledgers a peg's cover moves together, in the ONE order every carrier, header and door uses.
pub const BRIDGE_LEDGERS: [u32; 2] = [NATIVE_PEG_ASSET_ID, XMR_PEG_ASSET_ID];
/// ⭐ §18.14 — THE COIN LEDGERS the direct SAT pools trade: one atom on the chain per satoshi or piconero in custody, no price read and no stablecoin backing. A deposit mints
/// one through the wrapped door under the bridge's own checks; a burn pays it out on its own chain. A chain with no launch position registers neither.
pub const COIN_BTC_ASSET_ID: u32 = 2;
pub const COIN_XMR_ASSET_ID: u32 = 3;
pub const COIN_LEDGERS: [u32; 2] = [COIN_BTC_ASSET_ID, COIN_XMR_ASSET_ID];
/// A coin ledger's ratio: one for one, exempt from the volatile buffer because nothing it mints is a dollar.
pub const COIN_RATIO_BPS: u32 = 10_000;

// ═══════════════════════════ ⭐⭐⭐ SAFE AT SCALE — EVERY CUSTODY VAULT HAS ITS OWN LEDGERS ═══════════════════════════
// docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3c. The bonded custodians are cut into vaults of at most 16
// (`custody_vaults`). A hidden total can only be moved by a prover that holds its opening, so ONE hidden reserve shared by
// every vault would let any one vault's quorum advance it and withhold the new opening — every other vault could then
// prove nothing, and the bridge would stop for everyone (a stall bought with eleven bonds). So each vault moves only
// ledgers of its own: the `(reserve, minted)` pair of custody-funded asset `a` held by vault `v` is the PSM
// `vault_ledger(v, a)`. Vault 0's ledgers ARE the asset ids themselves (the native fields, `wrapped_assets[1..=3]`), so a
// chain with one vault — sixteen custodians or fewer — is byte for byte the chain it was. A higher vault's pairs live in
// `wrapped_assets` under the composite id, born at first use on the genesis-zero commitments of that id
// (`psm_genesis_blinds`), and ride the snapshot, the certified bundle, the journal and the supply gate as every registered
// ledger already does. Price, ratio, liquidation rule and stability pool are the ASSET's (`ledger_asset`): one mark and
// one pool per coin, whatever vault holds it.
// BORROWED: THORChain's Asgard vaults (each vault its own balances per asset, one pool per asset above them); state
// sharding by writer (no writer can stall a shard it does not own).
// SCALE: state = one pair per (vault, custody-funded asset) = 4 × ⌈bonded custodians / 16⌉ pairs; nothing per item or per
// height. A peg object's bytes, signatures and envelopes are its vault's (≤ 16), whatever the bonded set.

/// The mark of a composite (vault ≥ 1) ledger id. No registered asset id carries it (`register_wrapped_asset` refuses).
pub const VAULT_LEDGER_BIT: u32 = 0x8000_0000;
/// The highest vault index an id can carry (23 bits: 134 million custodians at 16 a vault).
pub const VAULT_INDEX_MAX: u32 = (1 << 23) - 1;
/// The bits under which a custodian keeps its merge and rebalance openings beside its asset seals (`Node::MERGE_HELD`,
/// `Node::REBALANCE_PART`, `REBALANCE_POST`, `REBALANCE_IN`, each `bit | ledger kind`). No registered asset id carries one
/// (`register_wrapped_asset` refuses), so no asset's seal is ever one of those openings.
pub const CUSTODIAN_SLOT_BITS: u32 = 0x7800_0000;

/// The ledger of custody-funded `asset` in vault `vault`: the asset id itself for vault 0, the composite id above it.
#[must_use]
pub fn vault_ledger(vault: u32, asset: u32) -> u32 {
    if vault == 0 {
        asset
    } else {
        VAULT_LEDGER_BIT | ((vault & VAULT_INDEX_MAX) << 8) | (asset & 0xff)
    }
}

/// The asset a ledger id counts (its price, ratio, rule and pool): the id itself unless it is a composite.
#[must_use]
pub fn ledger_asset(id: u32) -> u32 {
    if id & VAULT_LEDGER_BIT != 0 {
        id & 0xff
    } else {
        id
    }
}

/// The vault a ledger id belongs to: 0 unless it is a composite.
#[must_use]
pub fn ledger_vault(id: u32) -> u32 {
    if id & VAULT_LEDGER_BIT != 0 {
        (id & !VAULT_LEDGER_BIT) >> 8
    } else {
        0
    }
}

/// Is `id` a well-formed composite: vault ≥ 1, a custody-funded asset, and the ONE spelling of that pair? Anything else
/// carrying the mark is no ledger at all (fail closed: no pair, no price, no rule).
#[must_use]
pub fn is_vault_ledger(id: u32) -> bool {
    id & VAULT_LEDGER_BIT != 0 && ledger_asset_checked(id).is_some()
}

/// The asset of a WELL-FORMED ledger id: a plain id is its own asset; a composite answers only when it names a vault ≥ 1
/// and one of the four custody-funded assets in the one spelling [`vault_ledger`] writes.
#[must_use]
pub fn ledger_asset_checked(id: u32) -> Option<u32> {
    if id & VAULT_LEDGER_BIT == 0 {
        return Some(id);
    }
    let a = id & 0xff;
    (ledger_vault(id) >= 1 && CUSTODY_LEDGER_KINDS.contains(&a) && vault_ledger(ledger_vault(id), a) == id).then_some(a)
}

/// ⭐ THE CUSTODY-FUNDED LEDGER KINDS a custody vault keeps — every asset whose ledger is minted against a coin the
/// custody script controls: the bridge ledgers ([`BRIDGE_LEDGERS`]), then the coin ledgers ([`COIN_LEDGERS`]), in
/// ascending id order. THE ONE LIST the vault lifecycle reads — which ledger ids a vault may keep
/// ([`ledger_asset_checked`]), which ledgers a merge carries ([`MergeLeg`]), which openings a hand-over asks for
/// (`node::opening_share`), whether a vault stands behind anything (`PegLedger::vault_ledgers_moved`) — so a new
/// bridged coin (Ether, Zcash, Solana) joins every one of them by joining this list, never by an edit at each reader.
/// When the coin registry (`bridge_assets::COINS`) lands, this list is built from it and nothing else changes.
/// A kind is under 256: a vault's ledger id carries it in eight bits ([`vault_ledger`]). Pinned in
/// `the_custody_ledger_kinds_are_the_bridge_and_coin_ledgers_ascending_and_fit_a_vault_ledger_id`.
/// SAFE AT SCALE: a constant per CHAIN (one entry per bridged coin), never per node, user or height.
pub const CUSTODY_LEDGER_KINDS: &[u32] = &[NATIVE_PEG_ASSET_ID, XMR_PEG_ASSET_ID, COIN_BTC_ASSET_ID, COIN_XMR_ASSET_ID];

/// ⭐ ONE LEDGER KIND OF A VAULT MERGE (`Class::VaultMerge`): the asset the ledger counts (a [`CUSTODY_LEDGER_KINDS`]
/// entry), the RECEIVING ledger's pair after, and the two sum proofs — `into.reserve + from.reserve = post.reserve` and
/// the same for the minted supply — each against the chain's own two pairs. A merge carries one leg for every ledger
/// kind the retiring vault moved and none for any other, in ascending asset order: one encoding, and a kind added to
/// the list needs no new field anywhere.
/// A merge's receiving pair after for one ledger kind: `(kind, (reserve commitment, minted commitment))`.
pub type MergePost = (u32, (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4));

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MergeLeg {
    pub asset: u32,
    pub post: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `vault_merge_tx::decode`.
    pub reserve_sum: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `vault_merge_tx::decode`.
    pub minted_sum: Vec<u8>,
}

/// A commitment pair of one ledger: `(reserve commitment, minted commitment)`.
pub type LedgerPair = (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4);
/// A custodian's opening of one ledger pair: `(reserve, its blind, minted, its blind)`.
pub type LedgerOpening = (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4);

/// ⭐ ONE LEDGER KIND OF ONE STEP OF A VAULT REBALANCE (`Class::VaultRebalance`; spec §3g.1): the asset the ledger
/// counts (a [`CUSTODY_LEDGER_KINDS`] entry), the pair AFTER of the one ledger the step moves, and two sum proofs
/// against the chain's own pair of that ledger, for the reserve word and for the minted word:
///   • a CARVE (`part` stated): `post + part = the giver's pair now` — the part leaves the giver's ledger;
///   • a TAKE (`part` absent, it is the slot's): `the receiver's pair now + part = post`;
///   • a CANCEL (`part` absent, it is the slot's): `the giver's pair now + part = post`.
/// The ONE part commitment a carve states is the one a take or a cancel adds back, so nothing is created or lost.
/// A step carries at most one leg per kind, ascending.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RebalanceLeg {
    pub asset: u32,
    /// The part that leaves — stated by a carve and by no other step (the decode holds the shape).
    pub part: Option<LedgerPair>,
    pub post: LedgerPair,
    /// O1-FOOTPRINT-REVIEWED: each bounded by `SolvencyProof::MAX_PROOF_BYTES` in `vault_rebalance_tx::decode`.
    pub reserve_sum: Vec<u8>,
    pub minted_sum: Vec<u8>,
}

/// What a rebalance step states for one ledger kind: `(kind, the part when the step is a carve, the pair after)`.
pub type RebalancePost = (u32, Option<LedgerPair>, LedgerPair);

/// ⭐ ONE LEDGER KIND OF A PART AT REST in a giving vault's slot ([`VaultPart`]): the part's commitments and the
/// giver's pair as the carve left it — what a custodian of the receiving vault checks a handed opening against, so
/// the part's proportion is read from commitments the chain itself recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PartLeg {
    pub asset: u32,
    pub part: LedgerPair,
    pub from_post: LedgerPair,
}

/// ⭐ SAFE AT SCALE, stage three (spec §3g.1) — A PART AT REST: what a carve took out of vault `from`'s ledgers
/// (`PegLedger::vault_parts[from]`), until vault `into` takes it or `from` takes it back. `opened_tick` is the chain
/// tick (`Node::chain_tick_at`, A-F60) of the block whose fold carved it (a cancel waits one rotation day from it).
/// NO-GROWTH: at most one per vault, of at most `CUSTODY_LEDGER_KINDS.len()` legs.
/// DIGITAL-CASH-PRIVACY-REVIEWED: two vault indexes, a block score and commitments — no total, user, note or address.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultPart {
    pub into: u32,
    pub opened_tick: u64,
    /// O1-FOOTPRINT-REVIEWED: at most `CUSTODY_LEDGER_KINDS.len()` legs (`vault_part_shaped`).
    pub legs: Vec<PartLeg>,
}

/// Does a carried slot hold the record's own shape: at least one leg, each a custody-funded kind, ascending?
#[must_use]
pub fn vault_part_shaped(p: &VaultPart) -> bool {
    !p.legs.is_empty()
        && p.legs.len() <= CUSTODY_LEDGER_KINDS.len()
        && p.legs.iter().all(|l| CUSTODY_LEDGER_KINDS.contains(&l.asset))
        && p.legs.windows(2).all(|w| w[0].asset < w[1].asset)
}

/// ⭐ SAFE AT SCALE, stage three (spec §3f R1) — ONE CUSTODY KEY of a vault: the member set whose keys hold coins of that
/// vault. Its Bitcoin leaf is a function of the members (`btc_tx::custody_leaf`); its Monero wallet's main address is
/// what the members' own wallets reported. A vault's CURRENT key is its deposit address; a REPLACED key stays alive
/// while it may still hold coins or be paid (its address window), and is retired by its vault once both are over.
/// WHY THE CHAIN HOLDS IT: a Bitcoin reserve coin stays under the leaf of the set that was live when it was deposited,
/// and a Monero wallet belongs to one member set — so a custodian that left still holds a key to old coins until they
/// are swept. "No key outlives its bond" (R4) is read from these rows: a leaver's collateral returns only when no row
/// names it. Proven first in `models/custody-lifecycle/src/keys.rs` (invariant K1; without the gate the search goes red).
/// O1-FOOTPRINT-REVIEWED: at most the chain's attestor ceiling of ids (sixteen on a chain of vaults) and an address of at
/// most [`VAULT_KEY_ADDRESS_MAX`] bytes; at most [`VAULT_KEYS_ALIVE_MAX`] rows per vault.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultKeyRow {
    /// sorted by id, no id twice
    pub members: Vec<[u8; 32]>,
    /// THE BITCOIN LEAF this key is ([`VaultBtcKey`]): the leaf the members' custody points and bond weights formed on the
    /// chain at the take's fold. A leaf is a function of points AND weights, so the member list alone does not name it:
    /// the vault's Bitcoin deposit address stays this leaf's until the next take, whatever bonds do in between.
    pub btc: VaultBtcKey,
    /// the Monero main address the members' wallets reported for this set (empty on a chain with no Monero custody)
    pub xmr_address: Vec<u8>,
    /// the chain tick (`Node::chain_tick_at`) of the block whose fold made it the vault's key, raised to one past the
    /// previous row's so it names the key alone. ⭐ A-F60: every word of this row that dates something is a TICK of the
    /// chain's clock, never a blue score: the address window, the retire wait and the rotation period are times, and a
    /// blue score read as a time is right only at the target pace.
    pub since_tick: u64,
    /// the chain tick of the block whose fold replaced it; `None` while it is the current key
    pub replaced_tick: Option<u64>,
    /// ⭐ R5 (spec §3f.2) — WHEN THIS VAULT LAST MIXED: the chain tick of the fold step at which the chain's rotation
    /// rule last swapped custodians between this vault and a partner (`custody_vaults::rotations`); 0 for a vault that
    /// never mixed. A word of the VAULT kept on its current key row: every take carries it forward
    /// ([`PegLedger::vault_key_take`]) and only the rotation step writes it ([`PegLedger::vault_mark_mixed`]). It is
    /// what makes a vault stay due until it mixes — a re-key for any other cause (a member left, a delegation moved a
    /// slot of the leaf) refreshes the key and not this word, so no such re-key can stand in for the mix.
    pub mixed_tick: u64,
}

/// ⭐ A VAULT'S BITCOIN KEY AS THE CHAIN FORMS IT: the hash of the k-of-n custody leaf, and the leaf's inputs — each
/// seat's x-only custody point with its bond weight, as `Node::custody_members_of_vault` lists them at the take's fold
/// (`btc_tx::custody_leaf(members).leaf_hash == leaf`; both empty and zero when no seat has a custody point). A chain
/// fact every node derives alike and hands the ledger (as it hands the carrying block's blue score): the ledger keeps
/// it and never interprets it. The inputs ride the record so ANY node — one that joined yesterday, one that restarted —
/// rebuilds a key's leaf, and so its deposit addresses, from the chain alone, never from a set it happened to see live.
/// O1-FOOTPRINT-REVIEWED: at most the chain's attestor ceiling of (point, weight) pairs — 48 bytes per seat of one key.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultBtcKey {
    pub leaf: [u8; 32],
    pub members: Vec<([u8; 32], u128)>,
}

/// The most keys of one vault alive at once: the current one and the replaced ones not yet retired. A vault at the
/// bound retires a replaced key before it takes another, so a run of re-keys cannot grow the record.
pub const VAULT_KEYS_ALIVE_MAX: usize = 4;
/// The longest Monero address the record keeps (a standard address is 95 characters, an integrated one 106).
pub const VAULT_KEY_ADDRESS_MAX: usize = 128;

/// Is `rows` a vault's key record in its one shape: at most the alive bound, each row's members sorted with no id twice
/// and none empty, each address inside its bound, rows in the order they became the key, and at most one current key —
/// the last? What a carried record must satisfy before a node installs it.
#[must_use]
pub fn vault_key_rows_shaped(rows: &[VaultKeyRow]) -> bool {
    !rows.is_empty()
        && rows.len() <= VAULT_KEYS_ALIVE_MAX
        && rows.iter().all(|k| {
            !k.members.is_empty()
                && k.members.len() <= crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS
                && k.members.windows(2).all(|w| w[0] < w[1])
                && k.xmr_address.len() <= VAULT_KEY_ADDRESS_MAX
                && k.btc.members.len() <= crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS
                && k.replaced_tick.is_none_or(|r| r >= k.since_tick)
        })
        && rows.windows(2).all(|w| w[0].since_tick < w[1].since_tick)
        && rows.iter().rev().skip(1).all(|k| k.replaced_tick.is_some())
        // R5: the vault's last mix is carried forward by each take and only ever raised on the current row
        && rows.windows(2).all(|w| w[0].mixed_tick <= w[1].mixed_tick)
}

/// The two bridge ledgers a peg of vault `vault` moves together, in [`BRIDGE_LEDGERS`] order.
#[must_use]
pub fn bridge_ledgers_of(vault: u32) -> [u32; 2] {
    [vault_ledger(vault, NATIVE_PEG_ASSET_ID), vault_ledger(vault, XMR_PEG_ASSET_ID)]
}

/// ⭐ WHAT A PEG OBJECT SAYS ABOUT THE VAULT IT RIDES — the bytes of the deposit's old `bond_backstop` field, which has
/// been empty on every object since the global backstop was retired (2026-09-17). The backstop returns per vault, as a
/// bound on what one vault's quorum may sign for alone, never as a gate on a deposit:
///   • empty bytes — vault 0, signed by two thirds of ALL bonded weight: every object a one-vault chain makes;
///   • `vault` with no proofs — the deposit lands on `vault`'s ledgers and two thirds of ALL bonded weight signed it;
///   • `vault` with proofs — two thirds of `vault`'s OWN weight signed it, and the two proofs show that the USDm the
///     vault stands behind after this mint — the minted totals of its two bridge ledgers, added (`sum`, into the
///     one-object commitment `sum_commit`) — is no more than its slashed bonds would repay (`bound`,
///     [`PegLedger::vault_authority_usdm`]). The bound is on the ledgers' own totals, so nothing shadows them and nothing
///     drifts; both ledgers enter, so the object never says which coin came in.
/// A deposit a vault's bonds cannot cover is never refused or held: it is signed the first way.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultRide {
    pub vault: u32,
    /// The commitment to the sum of the vault's two post minted totals (all zero when no proofs ride).
    pub sum_commit: crate::spend_frontier::Digest4,
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `decode` — the sum proof, or empty.
    pub sum: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `decode` — the bound proof, or empty.
    pub bound: Vec<u8>,
}

impl VaultRide {
    /// Vault 0 under the whole bonded set: what empty bytes mean.
    #[must_use]
    pub fn whole() -> Self {
        Self::of(0)
    }
    /// Vault `vault` under the whole bonded set (no proofs).
    #[must_use]
    pub fn of(vault: u32) -> Self {
        VaultRide { vault, sum_commit: Default::default(), sum: Vec::new(), bound: Vec::new() }
    }
    /// Does the vault's own quorum sign alone (the bound proofs ride)?
    #[must_use]
    pub fn by_vault(&self) -> bool {
        !self.sum.is_empty() && !self.bound.is_empty()
    }
    /// The field's bytes: empty for [`Self::whole`], so a one-vault chain's objects are unchanged.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        if *self == Self::whole() {
            return Vec::new();
        }
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// One canonical, bounded reading (strict full consumption). `None` for bytes that are neither empty nor a ride:
    /// the object is refused, never read as vault 0.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return Some(Self::whole());
        }
        let r: Self = crate::chain_object::decode_exact(bytes)?;
        let max = crate::solvency::SolvencyProof::MAX_PROOF_BYTES;
        let both = r.by_vault();
        let neither = r.sum.is_empty() && r.bound.is_empty() && r.sum_commit == crate::spend_frontier::Digest4::default();
        (r.vault <= VAULT_INDEX_MAX && (both || neither) && r.sum.len() <= max && r.bound.len() <= max && r != Self::whole()).then_some(r)
    }
}

/// The public blind a vault's cover is committed under in its bound proof (a public amount: every node recomputes it).
pub const VAULT_COVER_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_7661_756c, 0x636f_7665_7262_6c64]);

/// ⭐ §19.5b — what a peg object's carrier bytes are: the two-ledger cover proof and BOTH bridge ledgers' post pairs (in
/// [`BRIDGE_LEDGERS`] order). The header pair is their hash ([`PegLedger::cover_header_pair`]), so the custodians' signatures
/// over the header bind all four.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverBlob {
    /// O1-FOOTPRINT-REVIEWED: bounded by `SolvencyProof::MAX_PROOF_BYTES` in `decode`.
    pub carrier: Vec<u8>,
    pub posts: [(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2],
}

impl CoverBlob {
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical, bounded blob (strict full-consumption decode).
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let b: Self = crate::chain_object::decode_exact(bytes)?;
        (!b.carrier.is_empty() && b.carrier.len() <= crate::solvency::SolvencyProof::MAX_PROOF_BYTES).then_some(b)
    }
}

/// ⭐ EVERY PSM'S OWN GENESIS BLINDS `(reserve, minted)`. The native ledger keeps the well-known pair; every other ledger
/// takes the same words with its asset id folded in, so no two ledgers ever start on the same commitment. ⛔ Before
/// 2026-11-01 every wrapped ledger was born under the NATIVE blinds, so a fresh wrapped ledger's `(reserve, minted)` was
/// byte-identical to the native genesis pair — a proof against one opened the other, and a peg-out's own proof could not
/// say which ledger it pays from. Public constants (genesis facts any observer derives); the blinds turn secret at the
/// first real deposit, exactly as on the native ledger.
#[must_use]
pub fn psm_genesis_blinds(asset_id: u32) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
    if asset_id == NATIVE_PEG_ASSET_ID {
        return (GENESIS_PEG_RESERVE_BLIND, GENESIS_PEG_MINTED_BLIND);
    }
    let a = u64::from(asset_id) << 32;
    (
        usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_5f72_7376, 0x6765_6e5f_7a65_726f ^ a]),
        usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_5f6d_6e74, 0x6765_6e5f_7a65_726f ^ a]),
    )
}

/// The malformed-input size guard on a revaluation carrier (§9.6 Q5), checked BEFORE a byte is parsed. A carrier
/// is exactly TWO WHIR sub-proofs plus a 4-byte length frame, and a WHIR proof is sized by the security parameter
/// alone ([`crate::solvency::SolvencyProof::MAX_PROOF_BYTES`], the same bound the light decider enforces). It
/// refuses an oversized blob, never a real position.
pub const MAX_REVALUATION_CARRIER_BYTES: usize = 2 * crate::solvency::SolvencyProof::MAX_PROOF_BYTES + 4;

/// LIQUIDATION §10 — the stability pool's discount on seized collateral, spec §2.2 `DELTA` (10 %): the depositors buy the
/// seized collateral at `(1 − DELTA)` of the mark, the pool's reward for standing ready to retire debt. A protocol constant
/// (spec §2.5 (6)), never a runtime input. `LiqRule::admissible` refuses a ratio it cannot serve: at the native 150 % mint
/// ratio `RHO_TARGET · (1 − DELTA) = 1.35 > 1`; a 1:1 PSM (ratio = floor) has no buffer to restore and is never liquidated.
pub const LIQ_POOL_DISCOUNT_BPS: u64 = 1_000;

/// ⭐ The LIQUIDATION attestation message — `musdm.peg.revalue.v2`, the extended statement of spec §10.2 (3). The ≥2/3
/// bonded quorum signs THIS, binding the epoch, the PSM, the unique close id, the MARK the rule was evaluated at, the
/// state the five legs were proven against (the PSM's reserve and supply commitments and the pool's `(T, P, S)` words and
/// epoch — so a signature is valid against exactly ONE ledger state), and every commitment the object moves the chain to.
///
/// DOMAIN SEPARATION IS LOAD-BEARING: `v2` can never be a `v1` re-mark, a `musdm.peg.in.conf.v1` or a
/// `musdm.peg.out.conf.v2` message; every field after the prefix is length-fixed, so no two classes collide.
pub fn revalue_msg(
    h: &crate::liquidation_tx::LiquidationHeader,
    old_reserve_commit: &crate::spend_frontier::Digest4,
    old_minted_commit: &crate::spend_frontier::Digest4,
    pool: &PoolWords,
    mark: u64,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(20 + 8 + 4 + 32 + 8 + 8 + 1 + 12 * 8 * usdm_decider::poseidon2_compress::DIGEST_LANES);
    m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.revalue.v2"));
    m.extend_from_slice(&h.epoch_id.to_le_bytes());
    m.extend_from_slice(&h.asset_id.to_le_bytes());
    m.extend_from_slice(&h.position_id);
    m.extend_from_slice(&mark.to_le_bytes());
    m.extend_from_slice(&pool.epoch.to_le_bytes());
    m.push(u8::from(h.pool_close));
    for d in [
        old_reserve_commit,
        old_minted_commit,
        &pool.t,
        &pool.p,
        &pool.s,
        &h.retired_commit,
        &h.seized_commit,
        &h.new_reserve_commit,
        &h.new_minted_commit,
        &h.new_pool_t,
        &h.new_pool_p,
        &h.new_pool_s,
    ] {
        for x in d {
            m.extend_from_slice(&x.to_le_bytes());
        }
    }
    m
}

/// A custodian's opening of ONE PSM and its stability pool — the values and blinds the five liquidation legs are proven
/// from. Passed transiently, never stored on-ledger (the same contract as the peg's own openings).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiquidationOpening {
    pub reserve: u128,
    pub reserve_blind: crate::spend_frontier::Digest4,
    pub minted: u128,
    pub minted_blind: crate::spend_frontier::Digest4,
    pub pool_t: u128,
    pub pool_t_blind: crate::spend_frontier::Digest4,
    pub pool_p: usdm_decider::confidential_solvency::U256,
    pub pool_p_blind: crate::spend_frontier::Digest4,
    pub pool_s: usdm_decider::confidential_solvency::U256,
    pub pool_s_blind: crate::spend_frontier::Digest4,
}

/// The NATIVE TWIN of one liquidation: what the rule decides from an opening, every blind the legs use, every commitment
/// the object carries, and the opening AFTER it. Deterministic in the opening and the rule, so every custodian holding the
/// opening derives the SAME plan — the same commitments to sign, and the same next opening to keep at the fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiquidationPlan {
    /// USDm retired from the pool and from the supply.
    pub c: u128,
    /// Collateral seized from the reserve, owed to the pool's depositors through `S`.
    pub s: u128,
    /// `[c, s, new_reserve, new_minted, new_t, p_new, s_new]` blinds.
    pub blinds: [crate::spend_frontier::Digest4; 7],
    pub p_new: usdm_decider::confidential_solvency::U256,
    pub s_new: usdm_decider::confidential_solvency::U256,
    /// The pool step's epoch-close bit: `P_new < 2^64` (a drain gives `P_new = 0`).
    pub close: bool,
    /// The custodian's opening after the liquidation (a closed epoch restarts at the public `P = 2^128`, `S = 0`).
    pub after: LiquidationOpening,
}

impl LiquidationPlan {
    /// The commitments the liquidation object carries, in header order:
    /// `[DC, DS, new_reserve, new_minted, new_T, P_new, S_new]`.
    #[must_use]
    pub fn commits(&self, o: &LiquidationOpening) -> [crate::spend_frontier::Digest4; 7] {
        use usdm_decider::confidential_solvency::solvency_commit_256;
        let b = &self.blinds;
        [
            solvency_commit_256(u256_from_u128(self.c), b[0]),
            solvency_commit_256(u256_from_u128(self.s), b[1]),
            solvency_commit_256(u256_from_u128(o.reserve - self.s), b[2]),
            solvency_commit_256(u256_from_u128(o.minted - self.c), b[3]),
            solvency_commit_256(u256_from_u128(o.pool_t - self.c), b[4]),
            solvency_commit_256(self.p_new, b[5]),
            solvency_commit_256(self.s_new, b[6]),
        ]
    }
}

/// The liquidation's blind seed: blake3 over EVERY blind of the opening plus its values. Each opening blind past genesis is
/// a secret only the bonded custodians hold, so the seed (and every blind derived from it) is secret too; deriving from a
/// single, possibly-public blind (a fresh epoch's `P` blind is a public constant) would let an observer brute-force `C`.
fn liquidation_seed(o: &LiquidationOpening) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-LIQ-SEED-v1");
    for d in [&o.reserve_blind, &o.minted_blind, &o.pool_t_blind, &o.pool_p_blind, &o.pool_s_blind] {
        for x in d {
            h.update(&x.to_le_bytes());
        }
    }
    for v in [o.reserve, o.minted, o.pool_t] {
        h.update(&v.to_le_bytes());
    }
    for w in o.pool_p.iter().chain(o.pool_s.iter()) {
        h.update(&w.to_le_bytes());
    }
    *h.finalize().as_bytes()
}

pub fn liquidation_blind(seed: &[u8; 32], i: u8) -> crate::spend_frontier::Digest4 {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-LIQ-BLIND-v1");
    h.update(seed);
    h.update(&[i]);
    usdm_decider::poseidon2_compress::hash32_to_digest(h.finalize().as_bytes())
}

/// ⭐ THE NATIVE TWIN — plan one liquidation of `o` under `rule`. `None` when the PSM is not due (the ONE amount rule,
/// `confidential_solvency::liquidation_amount`), when the pool cannot cover the retire (`C > T`: no partial regime yet —
/// the PSM stays open and its mints stay refused until the pool grows), or when a value does not fit.
#[must_use]
/// TEST — plants an undeclared supply mover in the bounty door (the turnstile's RED-first defect). Per thread.
#[cfg(test)]
thread_local! {
    pub static PLANT_BOUNTY_MOVES_SUPPLY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// ⭐⭐ §BR-10 (spec §8 item 5) — THE SUPPLY WORDS a fold step may move: the native reserve and supply commitments, the issued
/// SAT total, and every wrapped asset's reserve and supply commitments. Read before and after each class object applies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SupplyWords {
    pub native: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    pub sat_issued: u64,
    pub wrapped: Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)>,
}

/// ⭐⭐ §BR-10 — THE SUPPLY TURNSTILE'S ONE RULE (Bitcoin's coinbase rule and Zcash's ZIP-209 turnstile, applied per class): a
/// class object may move a supply word only if its class is that word's door — the native reserve and supply only by a peg-in,
/// a peg-out or a liquidation; the issued SAT only upward and only by the mining reward; a wrapped asset's words only by its
/// mint, its registration or a liquidation. Any value that enters by another path is refused.
#[must_use]
pub fn supply_move_allowed(class: crate::chain_object::Class, before: &SupplyWords, after: &SupplyWords) -> bool {
    use crate::chain_object::Class as C;
    let native = before.native != after.native;
    let sat = before.sat_issued != after.sat_issued;
    // ⛔ §19.5a/§19.5b (lane defi, 2026-11-01): Monero's ledger is a BRIDGE ledger kept in the wrapped map — its words are a
    // peg's to move (every peg moves both bridge ledgers through the cover), never a wrapped mint's. MEASURED: before, every
    // peg moving it (a Monero mint since 9ee96cd; every peg under the cover) was refused here at the fold.
    let words_of = |w: &SupplyWords, bridge: bool| -> Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        w.wrapped.iter().filter(|(id, ..)| PegLedger::is_bridge_ledger(*id) == bridge).copied().collect()
    };
    let bridge = words_of(before, true) != words_of(after, true);
    // §18.14: a coin ledger's words also move by its burn
    let coins_of = |w: &SupplyWords| -> Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> { w.wrapped.iter().filter(|(id, ..)| PegLedger::is_coin_ledger(*id)).copied().collect() };
    let others_of = |w: &SupplyWords| -> Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> { w.wrapped.iter().filter(|(id, ..)| !PegLedger::is_bridge_ledger(*id) && !PegLedger::is_coin_ledger(*id)).copied().collect() };
    let coin = coins_of(before) != coins_of(after);
    let wrapped = others_of(before) != others_of(after);
    // SAFE AT SCALE: a vault merge moves the custody-funded words of exactly two vaults (the native pair when one of
    // them is vault 0, the bridge and coin ledgers of both) — each sum proven against the chain's own pairs at its door
    // (`PegLedger::check_vault_merge`), so the words move and their total does not. It never moves another asset's.
    // A reserve cost lowers ONE bridge ledger's reserve (the native words when it is vault 0's Bitcoin ledger) by a
    // proven public fee at its own door (`PegLedger::check_reserve_cost`); it never touches a coin or wrapped ledger.
    // A REBALANCE step (spec §3g.1) moves the custody-funded words of ONE vault — a carve out of the giver's ledgers into
    // its slot, a take into the receiver's, a cancel back into the giver's — each sum proven against the chain's own pair
    // and the slot's one part commitment at its door (`PegLedger::check_vault_carve` / `_take` / `_cancel`), so the words
    // move and, with the slot, their total does not. It never moves another asset's.
    (!native || matches!(class, C::PegIn | C::PegOut | C::Liquidation | C::TheftRepayment | C::PotFill | C::UnitOpen | C::UnitClose | C::VaultMerge | C::VaultRebalance | C::ReserveCost))
        // a unit open IS a peg-in (its mint verifies the cover at `peg_in_confidential_for`), so it moves both bridge ledgers too
        && (!bridge || matches!(class, C::PegIn | C::PegOut | C::Liquidation | C::UnitOpen | C::VaultMerge | C::VaultRebalance | C::ReserveCost))
        && (!sat || (class == C::SatoshiReward && after.sat_issued > before.sat_issued))
        && (!wrapped || matches!(class, C::WrappedMint | C::WrappedAssetRegister | C::Liquidation))
        && (!coin || matches!(class, C::WrappedMint | C::PegOut | C::VaultMerge | C::VaultRebalance))
}

pub fn plan_liquidation(o: &LiquidationOpening, rule: &usdm_decider::confidential_solvency::LiqRule) -> Option<LiquidationPlan> {
    use usdm_decider::confidential_solvency as cs;
    // the capped rule: C = min(⌈N/Q⌉, M, T) — a pool smaller than the rule's retire is burned whole (a PARTIAL
    // liquidation; the epoch then closes, and the PSM stays under its target with its mints refused until the pool grows)
    let (c, s) = cs::liquidation_amount_capped(u256_from_u128(o.reserve), u256_from_u128(o.minted), u256_from_u128(o.pool_t), rule)?;
    let (c, s) = (u128_of_u256(c)?, u128_of_u256(s)?);
    let left_t = o.pool_t.checked_sub(c)?;
    let (new_r, new_m) = (o.reserve.checked_sub(s)?, o.minted.checked_sub(c)?);
    let (p_new, s_new, close) = cs::pool_step(u256_from_u128(o.pool_t), u256_from_u128(c), u256_from_u128(s), o.pool_p, o.pool_s)?;
    let seed = liquidation_seed(o);
    let blinds: [crate::spend_frontier::Digest4; 7] = core::array::from_fn(|i| liquidation_blind(&seed, i as u8));
    let after = LiquidationOpening {
        reserve: new_r,
        reserve_blind: blinds[2],
        minted: new_m,
        minted_blind: blinds[3],
        pool_t: left_t,
        pool_t_blind: blinds[4],
        pool_p: if close { POOL_P_SCALE } else { p_new },
        pool_p_blind: if close { GENESIS_POOL_P_BLIND } else { blinds[5] },
        pool_s: if close { [0; 4] } else { s_new },
        pool_s_blind: if close { GENESIS_POOL_S_BLIND } else { blinds[6] },
    };
    Some(LiquidationPlan { c, s, blinds, p_new, s_new, close, after })
}

fn u128_of_u256(v: usdm_decider::confidential_solvency::U256) -> Option<u128> {
    (v[2] == 0 && v[3] == 0).then_some(u128::from(v[0]) | (u128::from(v[1]) << 64))
}

/// PROVE the five legs of a planned liquidation (the bonded builder; every leg is WHIR, verified by every node at the
/// fold). Welded by equal commitments: the amount carrier's `DC`/`DS` are the pool transition's, the pool step's, the
/// retire leg's and the seize leg's deltas, and its `(DD, DM)` are the PSM's current commitments. `None` if any leg is
/// unprovable — which the door would refuse anyway.
#[must_use]
pub fn build_liquidation_legs(
    o: &LiquidationOpening,
    plan: &LiquidationPlan,
    rule: &usdm_decider::confidential_solvency::LiqRule,
) -> Option<crate::liquidation_tx::LiquidationLegs> {
    use usdm_decider::confidential_solvency as cs;
    let b = &plan.blinds;
    let (c, s) = (u256_from_u128(plan.c), u256_from_u128(plan.s));
    let amount = cs::prove_liquidation_amount_carrier(
        u256_from_u128(o.reserve),
        u256_from_u128(o.minted),
        u256_from_u128(o.pool_t),
        &[o.reserve_blind, o.minted_blind, b[0], b[1], o.pool_t_blind],
        rule,
    )?;
    if (amount.c, amount.s) != (c, s) {
        return None; // the carrier's rule and the twin disagree — never ship a mixed object
    }
    let (pool_transition, _) =
        cs::prove_transition_carrier(u256_from_u128(o.pool_t - plan.c), c, &[b[4], b[0], o.pool_t_blind], cs::TransitionDomain::StabilityPool)?;
    let step = cs::prove_pool_step_carrier(&cs::PoolStepOpening {
        t: u256_from_u128(o.pool_t),
        c,
        s_c: s,
        p_old: o.pool_p,
        s_old: o.pool_s,
        blinds: [o.pool_t_blind, b[0], b[1], o.pool_p_blind, b[5], o.pool_s_blind, b[6]],
    })?;
    let (retire, _) = cs::prove_transition_carrier(u256_from_u128(o.minted - plan.c), c, &[b[3], b[0], o.minted_blind], cs::TransitionDomain::Retire)?;
    let (seize, _) = cs::prove_transition_carrier(u256_from_u128(o.reserve - plan.s), s, &[b[2], b[1], o.reserve_blind], cs::TransitionDomain::Seize)?;
    Some(crate::liquidation_tx::LiquidationLegs { amount: amount.bytes, pool_transition, pool_step: step.bytes, retire, seize })
}

/// The per-position, per-epoch, per-asset LIQUIDATION replay key — `blake3(domain || epoch || asset || position)`.
/// Domain-separated so a liquidation key can NEVER equal a real USDm burn nullifier. That is why the door records
/// it in its OWN `liquidated` set and not in `spent_burns`: [`PegLedger::is_burned`] gates the foreign reserve
/// release, and a liquidation must never be able to authorize one.
/// ⛔⛔⛔ DB-274 P4b B1 (docs/DB-274 §8.17/§8.18) — A ONE-TIME ID IS ITS OBJECT'S OWN NULLIFIER (Zcash's shape).
///
/// `PegIn`, `WrappedMint` and `Liquidation` had NO own nullifier: their only replay guard was this ledger's
/// `confidential_deposit_ids` / `liquidated` set, and a bundle-synced node receives only the 512-id §DD ring. So a
/// producer re-carrying a public, historical object minted again on any node that jumped past it. As a nullifier the id
/// rides the block lane (DB-278, `chain_object::object_own_nullifiers`), the canonical fold decides the first carrier
/// wins and strips every later one's notes (`respend_decide_at_fold`), and a joiner's certified band refuses it as it
/// refuses a note's second spend. Derived from EXACTLY the key the replay set keeps today (`kind` = the `applied_ids`
/// tag: 0 deposit — native deposit id or `wrapped_deposit_key`, already namespaced — and 3 liquidation), so the two
/// guards can never disagree about which object is "the same".
#[must_use]
pub fn one_time_id_nf(kind: u8, key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-PEG-ONE-TIME-NF-v1");
    h.update(&[kind]);
    h.update(key);
    crate::cover::canonical_tag_of_hash(h.finalize().as_bytes())
}

/// The `applied_ids` / [`one_time_id_nf`] kind of a deposit (native or wrapped).
pub const ONE_TIME_DEPOSIT: u8 = 0;
/// The `applied_ids` / [`one_time_id_nf`] kind of a liquidation close.
pub const ONE_TIME_LIQUIDATION: u8 = 3;
/// DB-388 (rogue-role census, AssetCreate × replay, 2026-10-04): the one-time id of an ASSET CREATION — its own derived
/// `asset_id`. A re-carried creation used to APPEND a duplicate descriptor leaf to every node's registry (`DsolRegistry::
/// register`, no replay refusal: the class retired no id of its own), so a producer grew the registry and moved its root
/// at will. As a nullifier the id rides the creation's lane and the spent set refuses the second carrier.
pub const ONE_TIME_ASSET_CREATE: u8 = 4;
/// §BR-3 17.5: the one-time id of a theft repayment — its `repay_id`, a function of the state it moves.
pub const ONE_TIME_THEFT_REPAY: u8 = 5;
/// §BR-8: the one-time id of a decoy batch (its payout's txid) and of a decoy return (its outpoint's key).
pub const ONE_TIME_DECOY_BATCH: u8 = 6;
pub const ONE_TIME_DECOY_RETURN: u8 = 7;
/// SAFE AT SCALE: the one-time id of a reserve cost — its ledger and the foreign transaction whose fee it books
/// ([`PegLedger::reserve_cost_key`]); 8 and 9 are the contract layer's (`dsol_deploy_tx`, `dsol_fee_update_tx`).
pub const ONE_TIME_RESERVE_COST: u8 = 10;

pub fn liquidation_key(epoch_id: u64, asset_id: u32, position_id: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"USDMD-LIQ-CLOSE-V1");
    h.update(&epoch_id.to_le_bytes());
    h.update(&asset_id.to_le_bytes());
    h.update(position_id);
    *h.finalize().as_bytes()
}

/// Domain-separated POOLED PEG-OUT (redeem/burn ANY USDm against the pooled reserve) attestation message — binds
/// the asset + the UNIQUE burned USDm nullifier + the burned USDm amount + the external withdrawal address, so a
/// threshold signature authorizes exactly one pooled redemption of exactly one destroyed note, for exactly this
/// amount, to exactly this address (it can't be replayed to a different amount, asset, or recipient).
/// ⭐ THE ONE BONDED-QUORUM TALLY — `pub(crate)` so a new attested class REUSES it instead of growing a
/// second one. Every peg door already goes through this function; `bridge_credit_tx` now does too.
/// ⛔ A SECOND TALLY IS A SECOND SET OF RULES: the distinct-attestor set, the zero-weight skip for
/// unbonded keys and the bounded verify count below are the definition of the quorum, and a copy drifts.
/// DB-77: does this set of DISTINCT bonded ids carry ≥2/3 of the bonded weight? The same arithmetic as
/// [`threshold_ok`] with the signatures left out — the lane's cheap "is it time to publish?" pre-check
/// (the publish itself re-runs the full signed tally at every door).
#[must_use]
pub fn quorum_weight_met(quorum: &dyn BondQuorum, ids: &[[u8; 32]]) -> bool {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut attested: u128 = 0;
    for id in ids {
        if !seen.insert(*id) {
            continue;
        }
        attested = attested.saturating_add(quorum.bond_of(id));
    }
    let total = quorum.total_bond();
    crate::quorum_math::two_thirds_met(attested, total)
}
/// What the ONE tally learned: which attestors actually counted (by index, with their bonded weight) and
/// whether they carry the >=2/3 super-majority. `None` from [`tally_attestors`] means a signature that
/// COULD have counted failed to verify — fail-closed, never a partial count.
pub struct Tally {
    /// `(index into the attestor slice, bonded weight)` for each DISTINCT, BONDED, verified attestor.
    pub counted: Vec<(usize, u128)>,
    /// The >=2/3 super-majority verdict, computed in exactly one place.
    pub met: bool,
}

/// ⛔⛔⛔ DB-387 (USER RULING 2026-10-04, fix A) — THE PRICE MARK'S ONE THRESHOLD: the counted weight is STRICTLY MORE than two
/// thirds of the bonded weight (`2f + 1` of `3f + 1`), where every yes/no attestation keeps `met` (≥ 2/3, the custody ruling).
/// Read by the APPLY (`mark_price_attested`) and by the PUBLISHER (`QuoteBook::quorum_quotes`). MEASURED 2026-10-05: DB-387
/// tightened the apply only, so a node holding exactly 2/3 published a mark every node — itself included — refused (db240's
/// and db245's preconditions): one rule at two sites, the §9.5 trap.
#[must_use]
pub fn mark_tally_clears(tally: &Tally, total_bond: u128) -> bool {
    let attested: u128 = tally.counted.iter().fold(0u128, |a, (_, w)| a.saturating_add(*w));
    crate::quorum_math::more_than_two_thirds(attested, total_bond)
}

/// ⭐ THE ONE BONDED-QUORUM TALLY, in the shape both message kinds need.
///
/// [`threshold_ok`] is now a thin wrapper over this with a CONSTANT message, so every existing door keeps
/// byte-identical behaviour. DB-124's price door passes a PER-ATTESTOR message instead, because each
/// custodian signs its own number — and it must not get a second set of rules to do that. The
/// distinct-attestor set, the zero-weight skip, the bounded verify count and the >=2/3 arithmetic are
/// defined HERE and nowhere else.
pub fn tally_attestors(
    quorum: &dyn BondQuorum,
    verifier: &dyn PqVerifier,
    attestors: &[MintAttestor],
    msg_for: &dyn Fn(usize) -> Vec<u8>,
) -> Option<Tally> {
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut attested: u128 = 0;
    let mut counted: Vec<(usize, u128)> = Vec::new();
    // ⛔ BOUNDED WORK (§9.6 Q5) — SAME FIX AS `psm::authorize_confidential_mint`, SAME REASON.
    //
    // WHAT PRODUCES THE CONDITION: `attestors` reaches every caller of this function from the WIRE — it is
    // the attestation vector of a peg-in / peg-out / re-mark / price-mark request. The repeats and unbonded
    // keys are the sender's own bytes; no producer inside this crate writes them, so there is nothing to
    // delete at a source this node controls.
    // CAN IT BE DELETED: no, and nothing caps the length — `BondQuorum` has `bond_of` and `total_bond` and
    // no cardinality — so this loop was one ML-DSA verify per attacker-chosen element, on the door that
    // authorises every reserve movement.
    // WHY THE BRANCHES STAY: the bound is the definition of the quorum, not a special case beside it. Only
    // a DISTINCT, BONDED attestor can add weight, so only those two are worth a signature check, and the
    // verify count is now bounded by the bonded set — which grows only by posting real bond.
    // NO VERDICT CHANGES: repeats and unbonded keys contributed zero weight before and zero now; a
    // malformed entry that could never have counted no longer fails the operation around it.
    // MUST-STAY-GREEN: the peg funds-safety theorems (solvency, no-free-mint, both directions, BTC + XMR),
    // `undercollateralized_proof_is_rejected`.
    for (i, a) in attestors.iter().enumerate() {
        let id = pubkey_id(&a.pubkey);
        // Already counted — its signature cannot change the verdict.
        if !seen.insert(id) {
            continue;
        }
        // Zero bond is zero weight by the quorum's own definition, so this signature cannot change the
        // verdict either. Checked BEFORE the verify: that ordering is the bounded-work fix.
        let w = quorum.bond_of(&id);
        if w == 0 {
            continue;
        }
        if !verifier.verify(&a.pubkey, &msg_for(i), &a.sig) {
            return None; // fail-closed on a bad signature that COULD have counted
        }
        attested = attested.saturating_add(w);
        counted.push((i, w));
    }
    let total = quorum.total_bond();
    Some(Tally { counted, met: crate::quorum_math::two_thirds_met(attested, total) })
}

pub fn threshold_ok(
    quorum: &dyn BondQuorum,
    verifier: &dyn PqVerifier,
    msg: &[u8],
    attestors: &[MintAttestor],
) -> bool {
    // ONE set of rules: this is `tally_attestors` with a CONSTANT message. A `None` (a signature that
    // could have counted and did not verify) is `false` here, exactly as the pre-refactor loop returned.
    tally_attestors(quorum, verifier, attestors, &|_| msg.to_vec()).is_some_and(|t| t.met)
}

/// FUNDS-LOSS-IMPOSSIBLE bond backstop — the WELL-KNOWN (non-secret) blind for committing the consensus-known total
/// bonded weight, so the mint gate can prove `bond ≥ 2× reserve` against it. The bond total is already
/// consensus-known via the ≥2/3 threshold tally, so committing it under a non-secret blind reveals nothing new; the
/// RESERVE (value-at-risk) stays confidential.
pub const BOND_BACKSTOP_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x424f_4e44_4241_434b, 0x5354_4f50_7075_6231]);

/// A `u128` amount widened to the confidential-solvency VALUE width.
///
/// ⛔⛔⛔ THE RETURN TYPE IS `U256`, NOT A DIGEST, AND THAT DISTINCTION IS NEW. Before §AG both were
/// `[u64; 4]`, so this compiled either way and the confusion cost nothing. The digest is now 8 lanes
/// (248 bits ⇒ 124-bit collision resistance) while a 256-bit amount is still four 64-bit limbs of plain
/// arithmetic — widening this to 8 lanes would have silently changed what `add256`/`ge256` mean. ⭐ "four
/// elements" is not a type: a value's width follows what it MEANS, never what it used to share a shape with.
pub fn u256_from_u128(v: u128) -> usdm_decider::confidential_solvency::U256 {
    [v as u64, (v >> 64) as u64, 0, 0]
}

/// The WELL-KNOWN (non-secret), deterministic genesis blinds for the two confidential-solvency commitments. At
/// genesis the reserve AND the circulating total are BOTH zero — a fact any observer can already derive (a fresh
/// chain has backed nothing, issued nothing) — so the genesis commitments are commitments to ZERO under these
/// non-secret blinds. This is a deterministic per-network CONSTANT (the committed value is literally 0: no stored
/// amount): it exists ONLY to give the confidential peg a well-defined zero-STATE to advance FROM, so the FIRST
/// real peg-in has a matching OLD commitment to prove against. A raw all-zero digest is NOT any
/// `solvency_commit_256(0, blind)`, so without this seed the first-ever mint on a fresh chain is unprovable (the
/// carrier's old-commit can never equal the all-zero digest). After the first real deposit the NEW blinds are SECRET, so every
/// nonzero total is hiding-committed and an observer learns nothing beyond the already-derivable genesis zero. The
/// custodian orchestrator that builds carriers uses these SAME constants for the first peg-in. Domain-separated so
/// the two zero-commitments differ.
pub const GENESIS_PEG_RESERVE_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_5f72_7376, 0x6765_6e5f_7a65_726f]);
pub const GENESIS_PEG_MINTED_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_5f6d_6e74, 0x6765_6e5f_7a65_726f]);

/// LIQUIDATION SPEC §10 — one PSM's stability pool: `T` (the pool's USDm), `P` (Liquity's running product, scale 2^128) and
/// `S` (its running sum) as COMMITTED words (a public `P` would publish each liquidation's share of the hidden aggregate),
/// and the public epoch counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PoolWords {
    pub t: crate::spend_frontier::Digest4,
    pub p: crate::spend_frontier::Digest4,
    pub s: crate::spend_frontier::Digest4,
    pub epoch: u64,
}

/// The genesis blinds of the pool words: public constants, like the peg's genesis blinds (the genesis VALUES are public —
/// an empty pool, `P = 2^128`, `S = 0`); every later word is re-blinded by the executor's fresh blinds.
pub const GENESIS_POOL_T_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_706f_6f74, 0x6765_6e5f_7a65_726f]);
pub const GENESIS_POOL_P_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_706f_6f70, 0x6765_6e5f_7a65_726f]);
pub const GENESIS_POOL_S_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_706f_6f73, 0x6765_6e5f_7a65_726f]);
/// Liquity's `P` scale: a fresh epoch's `P`.
pub const POOL_P_SCALE: usdm_decider::confidential_solvency::U256 = [0, 0, 1, 0]; // 2^128

/// H11 §2.5 — one source of a receipt's epoch bridge (docs/SP-EPOCH-BRIDGE-SPEC-20261022.md).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BridgeSource {
    /// The pool's live `(P, S)` words.
    Live,
    /// A closed epoch's closing words.
    Closed(u64),
    /// A fresh epoch's public opening `(2^128, 0)`.
    Opening,
}

/// ⭐ H11 §2.5 — THE ONE SELECTION RULE: the two `(P, S)` sources a receipt of pool epoch `receipt_epoch` settles through
/// (`cs::pool_bridge(first, second)`) on a pool at `pool_epoch` — Liquity's scale span. A close restarts the pool at the
/// opening and CARRIES its residual `T`, so a closed epoch's receipts must keep absorbing the next epoch's retires and
/// gains through their closing words: frozen at them, the residual was paid to them AND retired by the next epoch
/// (MEASURED 958 USDm owed beyond the pool, `rogue_role_pins::a_non_drain_epoch_close_…`).
/// - the live epoch: `(Live, Opening)` — the identity bridge, so every withdrawal has one shape;
/// - one close behind: `(Closed(e), Live)`;
/// - two or more behind: `(Closed(e), Closed(e + 1))` — Liquity's span-1 truncation (both closing `P` are under 2^64, so
///   nothing compounds; what later epochs would add is under `d · 2^-64`, dust the pool keeps).
///
/// `None` for an epoch the pool has not reached. Borrowed from Liquity v1 `StabilityPool` (`currentScale`,
/// `getCompoundedStakeFromSnapshots`, `_getCollateralGainFromSnapshots`).
#[must_use]
pub fn receipt_bridge_sources(receipt_epoch: u64, pool_epoch: u64) -> Option<(BridgeSource, BridgeSource)> {
    match receipt_epoch.cmp(&pool_epoch) {
        std::cmp::Ordering::Equal => Some((BridgeSource::Live, BridgeSource::Opening)),
        std::cmp::Ordering::Less if receipt_epoch + 1 == pool_epoch => Some((BridgeSource::Closed(receipt_epoch), BridgeSource::Live)),
        std::cmp::Ordering::Less => Some((BridgeSource::Closed(receipt_epoch), BridgeSource::Closed(receipt_epoch + 1))),
        std::cmp::Ordering::Greater => None,
    }
}

impl PoolWords {
    /// The genesis words of every PSM's pool: an empty pool, `P = 2^128`, `S = 0`, epoch 0.
    #[must_use]
    pub fn genesis() -> Self {
        use usdm_decider::confidential_solvency::solvency_commit_256;
        PoolWords {
            t: solvency_commit_256([0; 4], GENESIS_POOL_T_BLIND),
            p: solvency_commit_256(POOL_P_SCALE, GENESIS_POOL_P_BLIND),
            s: solvency_commit_256([0; 4], GENESIS_POOL_S_BLIND),
            epoch: 0,
        }
    }
}

impl PegLedger {
    pub fn new(ratio_bps: u32) -> Self {
        PegLedger {
            applied_ids: Vec::new(),
            // DB-124: a fresh ledger holds NO marks. That is the fail-closed start — `priced_value`
            // returns None and the mint refuses until the chain attests a price.
            price_marks: std::collections::BTreeMap::new(),
            // The endowment starts committed to ZERO: nothing collected, nothing owed.
            retention_endowment_commit: usdm_decider::poseidon2_compress::zero_digest(),
            reserve_commit: usdm_decider::poseidon2_compress::zero_digest(),
            minted_commit: usdm_decider::poseidon2_compress::zero_digest(),
            contract_state_root: contract_state_empty_root(),
            spent_burns: HashSet::new(),
            confidential_deposit_ids: HashSet::new(),
            ratio_bps,
            yield_rate_bps: 0,
            redeem_floor_bps: default_redeem_floor_bps(),
            released: HashSet::new(),
            wrapped_assets: std::collections::BTreeMap::new(),
            reserve_hwm_commit: usdm_decider::poseidon2_compress::zero_digest(),
            liquidated: HashSet::new(),
            pools: std::collections::BTreeMap::new(),
            pool_closes: std::collections::BTreeMap::new(),
            // genesis issues no SAT: every unit enters as a block's mining reward
            sat_issued: 0,
            pendulum_epoch_next: 0,
            pendulum_share_bps: 10_000,
            fee_pool_stakers: 0,
            fee_pool_bonders: 0,
            fee_pool_surplus: 0,
            fee_pool_miner: 0,
            miner_quarter_next: 0,
            miner_rate: 0,
            miner_accrual: 0,
            miner_quarter_start: 0,
            bond_yield_lo: 0,
            bond_yield_hi: 0,
            bonder_accrual: 0,
            set_aside_applied: 0,
            deployments: crate::deployment::DeploymentLedger::default(),
            release_attestations: std::collections::BTreeMap::new(),
            stake_paid_commit: genesis_stake_paid_commit(),
            stakers_snap_epoch_next: 0,
            stakers_snap_pool: 0,
            price_history: std::collections::BTreeMap::new(),
            epoch_keys: crate::epoch_deal_tx::EpochKeyLedger::default(),
            epoch_anchors: std::collections::VecDeque::new(),
            repayment_sat_pot: 0,
            theft_loss_open_sats: 0,
            repayment_owed_atomic: 0,
            haircut_remainder_atomic: 0,
            haircut_events: 0,
            decoy_epoch_next: 0,
            decoy_credit: 0,
            decoy_budget: 0,
            decoy_spent: 0,
            custody_cost_debt: 0,
            custody_cost_retired: 0,
            open_decoys: std::collections::BTreeMap::new(),
            unit_book: crate::debt_units::UnitBook::default(),
            defi_book: crate::defi_launch::genesis_books(),
            vault_keys: std::collections::BTreeMap::new(),
            vault_parts: std::collections::BTreeMap::new(),
            dsol_tokens: crate::dsol::DsolRegistry::new(),
            ion_pending: Vec::new(),
            ion_usdm_held: 0,
            ion_pools: 0,
            ion_fee_credit: 0,
        }
    }

    /// IonSwap pools — the orders the fold applied that no settlement has paid yet, in the fold's order.
    #[must_use]
    pub fn ion_pending(&self) -> &[crate::ion_pool_tx::IonPending] {
        &self.ion_pending
    }

    /// IonSwap pools — the USDm the pool layer holds (taken in by orders, less what settlements paid out).
    #[must_use]
    pub fn ion_usdm_held(&self) -> u64 {
        self.ion_usdm_held
    }

    /// IonSwap pools — AN ORDER APPLIES: it joins the pending list and the USDm it burned joins the layer word. `false`,
    /// with nothing changed, when the list has no room for it (the pool's share of this step, or the whole list) or
    /// the word would pass its width; the fold then refuses the order and nothing of it is spent.
    #[must_use]
    pub fn ion_take_order(&mut self, order: crate::ion_pool_tx::IonPending, usdm_in: u64) -> bool {
        let here = self.ion_pending.iter().filter(|o| o.token == order.token && o.step == order.step).count();
        if self.ion_pending.len() >= crate::ion_pool_tx::ION_PENDING_MAX || here >= crate::ion_pool_tx::ION_STEP_ORDERS_MAX {
            return false;
        }
        let Some(held) = self.ion_usdm_held.checked_add(usdm_in) else {
            return false;
        };
        self.ion_usdm_held = held;
        self.ion_pending.push(order);
        true
    }

    /// IonSwap pools — A SETTLEMENT APPLIES (its verdict was `IonSettleTx::verdict`'s, against this ledger's own root and
    /// pending orders): the layer word falls by what the batch pays out and by its USDm fee part, the pool's pending
    /// orders at or before `cutoff` leave the list, and the contract-state root moves to `root_after`. `false`, with
    /// NOTHING changed, when the batch would pay out more USDm than the pool layer holds — the turnstile. `opens`: the
    /// settlement INSERTS the pool's leaf (the pool had none), so the pool count rises by one.
    #[must_use]
    /// `forwards`: the second legs of the batch's swaps (`ion_pool_tx::IonSettled::forwards`), appended as pending
    /// orders of their own pools at `fold_step`, or at the first later step where that pool still takes an order (a
    /// step takes `ION_STEP_ORDERS_MAX` of a pool, direct orders and second legs together). Each takes the pending
    /// slot its own sale just left, so the list never grows by a settlement.
    #[allow(clippy::too_many_arguments)]
    pub fn ion_apply_settlement(
        &mut self,
        token: &[u8; 32],
        cutoff: u64,
        root_after: crate::spend_frontier::Digest4,
        usdm_paid: u64,
        usdm_fees: u64,
        opens: bool,
        fold_step: u64,
        forwards: &[crate::ion_pool_tx::IonPending],
    ) -> bool {
        let Some(held) = usdm_paid.checked_add(usdm_fees).and_then(|out| self.ion_usdm_held.checked_sub(out)) else {
            return false;
        };
        let Some(credit) = self.ion_fee_credit.checked_add(usdm_fees) else {
            return false;
        };
        let Some(pools) = self.ion_pools.checked_add(u64::from(opens)) else {
            return false;
        };
        self.ion_pools = pools;
        self.ion_usdm_held = held;
        self.ion_fee_credit = credit;
        self.ion_pending.retain(|o| o.token != *token || o.step > cutoff);
        for f in forwards {
            let mut f = f.clone();
            let taken = |step: u64, pending: &[crate::ion_pool_tx::IonPending]| pending.iter().filter(|o| o.token == f.token && o.step == step).count();
            let mut step = fold_step;
            while taken(step, &self.ion_pending) >= crate::ion_pool_tx::ION_STEP_ORDERS_MAX {
                step = step.saturating_add(1);
            }
            f.step = step;
            self.ion_pending.push(f);
        }
        self.contract_state_root = root_after;
        true
    }

    /// IonSwap pools — how many pools exist (each a leaf of the contract-state root with a row).
    #[must_use]
    pub fn ion_pools(&self) -> u64 {
        self.ion_pools
    }

    /// IonSwap pools — the USDm fee part the settlements of the step being folded owe the fee pools, taken once.
    pub fn take_ion_fee_credit(&mut self) -> u64 {
        std::mem::take(&mut self.ion_fee_credit)
    }

    /// A-F50 — adopt the certified bundle's IonSwap pool book (a jump), replacing this ledger's.
    pub fn adopt_certified_ion(
        &mut self,
        pending: Vec<crate::ion_pool_tx::IonPending>,
        usdm_held: u64,
        pools: u64,
    ) {
        self.ion_pending = pending;
        self.ion_usdm_held = usdm_held;
        self.ion_pools = pools;
    }

    /// A-F31 — the token registry (every created asset's descriptor in one accumulator). Chain state of this ledger.
    #[must_use]
    pub fn dsol_tokens(&self) -> &crate::dsol::DsolRegistry {
        &self.dsol_tokens
    }

    /// A-F31 — the registry's one fold writer (a creation's apply) and its two restores (a checkpoint, a certified
    /// bundle) reach it here; nothing else writes it.
    pub fn dsol_tokens_mut(&mut self) -> &mut crate::dsol::DsolRegistry {
        &mut self.dsol_tokens
    }

    /// ⭐ §BR-14 — the four fee pools (node-internal chain state; never served).
    #[must_use]
    pub fn fee_pools(&self) -> FeePools {
        FeePools {
            stakers: self.fee_pool_stakers,
            bonders: self.fee_pool_bonders,
            surplus: self.fee_pool_surplus,
            miner: self.fee_pool_miner,
        }
    }

    /// ⭐ §BR-14 — CREDIT `fee` (atomic USDm) to the pools by [`fee_split`]. All four move or none: `false` (nothing moved)
    /// only if a pool would pass `u64::MAX` (1.8e11 USDm — unreachable; refused rather than wrapped, so no credit is
    /// ever lost or invented silently). Called once per fold step with that step's applied fee payers.
    #[must_use]
    pub fn credit_fee_pools(&mut self, fee: u64) -> bool {
        self.credit_fee_pools_at(fee, 0)
    }

    /// ⭐ §BR-3 17.1 — [`Self::credit_fee_pools`] at halving `era` (the carrying block's parent key's era): the split steps
    /// the miner pool's share up from the stakers' as the block reward halves (`peg_arith::fee_split_at`).
    #[must_use]
    pub fn credit_fee_pools_at(&mut self, fee: u64, era: u64) -> bool {
        self.credit_fee_pools_capped(fee, era, u64::MAX)
    }

    /// ⭐ §BR-3 17.6 — [`Self::credit_fee_pools_at`] with the surplus buffer's target `surplus_cap` (spec §1 item 6): the
    /// buffer's share credits the buffer only up to the target and the overflow joins the stakers' share in the same step,
    /// so the four credits still sum to `fee` exactly. A buffer already at or above the target sends its whole share on.
    ///
    /// ⭐ SAFE AT SCALE, stage three (spec §3f R6) — THE BONDERS' SHARE PAYS THEIR CUSTODY'S DEBT FIRST: while
    /// `custody_cost_debt` stands, the bonders' share of this fee pays it down before any of it reaches their pool, and
    /// what it pays is RETIRED (credited to nobody: the fee already left its payer's note). The stakers', the buffer's
    /// and the miners' shares are untouched, so a re-key is paid by the secured and by nothing else. The credits then
    /// sum to `fee` less what was retired, and `custody_cost_retired` rises by exactly that.
    /// AI RESISTANT: (b) code every node runs in the fold over public words; no object, no signer.
    #[must_use]
    pub fn credit_fee_pools_capped(&mut self, fee: u64, era: u64, surplus_cap: u64) -> bool {
        let (st, bo, su, mi) = fee_split_at(fee, era);
        let pays = bo.min(self.custody_cost_debt);
        let Some(retired) = self.custody_cost_retired.checked_add(pays) else {
            return false;
        };
        let bo = bo - pays;
        let room = surplus_cap.saturating_sub(self.fee_pool_surplus);
        let to_buffer = su.min(room);
        let Some(st) = st.checked_add(su - to_buffer) else {
            return false;
        };
        let su = to_buffer;
        let (Some(a), Some(b), Some(c), Some(d)) = (
            self.fee_pool_stakers.checked_add(st),
            self.fee_pool_bonders.checked_add(bo),
            self.fee_pool_surplus.checked_add(su),
            self.fee_pool_miner.checked_add(mi),
        ) else {
            return false;
        };
        let (Some(accrual), Some(bonder_accrual)) = (self.miner_accrual.checked_add(mi), self.bonder_accrual.checked_add(bo)) else {
            return false;
        };
        (self.fee_pool_stakers, self.fee_pool_bonders, self.fee_pool_surplus, self.fee_pool_miner) = (a, b, c, d);
        self.miner_accrual = accrual; // §BR-11: the miner share credited during the current quarter
        self.bonder_accrual = bonder_accrual; // §BR-3 17.6: the bonders' share credited during the current quarter
        self.custody_cost_debt -= pays; // R6: `pays` is at most the debt
        self.custody_cost_retired = retired;
        true
    }

    /// ⭐ R6 — what the bonders owe for their custody's foreign fees (USDm atomic), and the running total their income
    /// has paid (retired supply).
    #[must_use]
    pub fn custody_cost_debt(&self) -> (u64, u64) {
        (self.custody_cost_debt, self.custody_cost_retired)
    }

    /// ⭐ R6 — A BOOKED RESERVE COST BECOMES THE BONDERS' DEBT: `cost` foreign atoms of ledger asset `asset_id`, priced at
    /// the chain's own seven-day price of that asset (the mark where no history stands yet), raise the debt. Called by
    /// the fold step that applied the `Class::ReserveCost` object, on every node alike. A ledger with no price at all
    /// raises nothing (it has minted nothing: a mint reads the same price). Saturating: a debt past `u64::MAX` USDm
    /// atomic (1.8e11 USDm) is unreachable.
    /// CHAIN-OBJECT: called only from the apply of the `Class::ReserveCost` object a block carries.
    pub fn raise_custody_cost_debt(&mut self, asset_id: u32, cost: u64) -> u64 {
        let price = self.twap7(asset_id).filter(|p| *p > 0);
        let usdm = price.map_or(0, |p| u64::try_from(u128::from(cost).saturating_mul(p) / crate::liquidation::PRICE_SCALE).unwrap_or(u64::MAX));
        self.custody_cost_debt = self.custody_cost_debt.saturating_add(usdm);
        usdm
    }

    /// ⭐ §BR-10 — each builder's latest release attestation.
    #[must_use]
    pub fn release_attestations(&self) -> &std::collections::BTreeMap<[u8; 32], crate::release_attestation_tx::ReleaseAttestationTx> {
        &self.release_attestations
    }
    /// ⭐ §BR-10 — keep `t` as its builder's latest attestation.
    pub fn record_release_attestation(&mut self, t: &crate::release_attestation_tx::ReleaseAttestationTx) {
        self.release_attestations.insert(t.builder(), t.clone());
    }

    /// ⭐ §BR-10 — the deployment ledger.
    #[must_use]
    pub fn deployments(&self) -> &crate::deployment::DeploymentLedger {
        &self.deployments
    }
    /// ⭐ §BR-10 — the deployment ledger, for the fold step that counts a block or a validator signal.
    pub fn deployments_mut(&mut self) -> &mut crate::deployment::DeploymentLedger {
        &mut self.deployments
    }

    /// ⭐ §BR-9a — the epoch-key ledger.
    #[must_use]
    pub fn epoch_keys(&self) -> &crate::epoch_deal_tx::EpochKeyLedger {
        &self.epoch_keys
    }
    /// ⭐ §BR-9a — the epoch-key ledger, for the fold step that ticks an epoch or applies a deal.
    pub fn epoch_keys_mut(&mut self) -> &mut crate::epoch_deal_tx::EpochKeyLedger {
        &mut self.epoch_keys
    }

    /// ⭐ §BR-13 — has the canonical SAT set-aside applied?
    #[must_use]
    pub fn set_aside_applied(&self) -> bool {
        self.set_aside_applied != 0
    }
    /// ⭐ §BR-13 — mark the set-aside applied (the fold door calls it once, after every rule passed).
    pub fn mark_set_aside_applied(&mut self) {
        self.set_aside_applied = 1;
    }

    /// ⭐ §BR-3 17.6 — the bonders' yield index Y (64 fractional bits).
    #[must_use]
    pub fn bond_yield_index(&self) -> u128 {
        (u128::from(self.bond_yield_hi) << 64) | u128::from(self.bond_yield_lo)
    }

    /// ⭐ §BR-3 17.6 — CLOSE the bonders' quarter (beside the §BR-11 roll, in the same journaled step): Y rises by the quarter's
    /// bonders credit over `total_weight` (the custody total at the close) and the accrual restarts. A zero total carries the
    /// accrual to the next quarter (nobody was bonded to earn it). `false` when nothing moved.
    pub fn bond_yield_roll(&mut self, total_weight: u128) -> bool {
        if total_weight == 0 || self.bonder_accrual == 0 {
            return false;
        }
        let Some(y) = self.bond_yield_index().checked_add((u128::from(self.bonder_accrual) << 64) / total_weight) else {
            return false; // unreachable (2⁶⁴ USDm per SAT unit); refused rather than wrapped
        };
        self.bond_yield_lo = y as u64;
        self.bond_yield_hi = (y >> 64) as u64;
        self.bonder_accrual = 0;
        true
    }

    /// ⭐ §BR-3 17.6 — PAY `amount` of bonders' yield out of the bonders' pool; `false` (nothing moved) if the pool cannot
    /// cover it. The index only rises by credited amounts and every payout floors, so the pool covers every entitlement.
    #[must_use]
    /// ⭐ §BR-10 — PAY a bug bounty from the surplus buffer: never more than it holds (nothing moves otherwise); the supply does
    /// not move (fee USDm already out of circulation reaches the reporter's note).
    #[must_use]
    pub fn pay_bounty(&mut self, amount: u64) -> bool {
        match self.fee_pool_surplus.checked_sub(amount) {
            Some(left) if amount > 0 => {
                self.fee_pool_surplus = left;
                // TEST — the planted defect the supply turnstile must catch: a door that moves a supply word it does not own
                #[cfg(test)]
                if PLANT_BOUNTY_MOVES_SUPPLY.with(std::cell::Cell::get) {
                    self.sat_issued = self.sat_issued.saturating_add(1);
                }
                true
            }
            _ => false,
        }
    }

    pub fn pay_bond_yield(&mut self, amount: u64) -> bool {
        match self.fee_pool_bonders.checked_sub(amount) {
            Some(left) => {
                self.fee_pool_bonders = left;
                true
            }
            None => false,
        }
    }

    /// ⭐ §BR-11 — does a fold step of `quarter` close the current payout quarter (or open the first)?
    #[must_use]
    pub fn miner_quarter_rolls(&self, quarter: u64) -> bool {
        quarter.saturating_add(1) > self.miner_quarter_next
    }

    /// ⭐ §BR-11 — CLOSE the payout quarter at the first fold step of `quarter` (fold ordinal `ordinal`): the next quarter pays
    /// `miner_rate(accrual, blocks)` per block, where `blocks` is the closed quarter's ordinal span; the accrual restarts.
    /// The very first quarter opens with rate 0 (nothing credited yet). Returns whether anything moved (the caller journals
    /// the step before calling).
    pub fn miner_quarter_roll(&mut self, quarter: u64, ordinal: u64) -> bool {
        if !self.miner_quarter_rolls(quarter) {
            return false;
        }
        self.miner_rate = if self.miner_quarter_next == 0 {
            0
        } else {
            miner_rate(self.miner_accrual, ordinal.saturating_sub(self.miner_quarter_start))
        };
        self.miner_accrual = 0;
        self.miner_quarter_start = ordinal;
        self.miner_quarter_next = quarter + 1;
        true
    }

    /// ⭐ §BR-11 — the payout quarter (if one is open) and its per-block rate.
    #[must_use]
    pub fn miner_payout_rate(&self) -> Option<(u64, u64)> {
        self.miner_quarter_next.checked_sub(1).map(|q| (q, self.miner_rate))
    }

    /// ⭐ §BR-11 — PAY one block's payout from the miner pool: exactly the open quarter's rate, for a block of that quarter,
    /// never more than the pool holds and never a zero payout. `false` (nothing moved) otherwise — the pool never goes
    /// negative and nothing is minted.
    #[must_use]
    pub fn pay_miner_payout(&mut self, quarter: u64, amount: u64) -> bool {
        let Some((q, rate)) = self.miner_payout_rate() else { return false };
        if q != quarter || rate == 0 || amount != rate {
            return false;
        }
        match self.fee_pool_miner.checked_sub(amount) {
            Some(left) => {
                self.fee_pool_miner = left;
                true
            }
            None => false,
        }
    }

    /// SAT issued so far, in base units (public by construction — see the field).
    #[must_use]
    pub fn sat_issued(&self) -> u64 {
        self.sat_issued
    }

    /// ⭐ SATOSHI §10.8 / §10.12 — the pendulum snapshot of the last CLOSED stake epoch: `(epoch, bonders' share in bps)`.
    #[must_use]
    pub fn pendulum_snapshot(&self) -> Option<(u64, u32)> {
        self.pendulum_epoch_next.checked_sub(1).map(|e| (e, self.pendulum_share_bps))
    }
    /// Take the snapshot for the CLOSED `epoch` from `securing` (its eligible custody aggregate, §10.12) and this ledger's
    /// `sat_issued`, only when `epoch` is later than the one held — so it happens once per epoch, at its close, and never
    /// moves backward. Returns whether it moved (the caller journals the step before calling).
    pub fn snapshot_pendulum(&mut self, epoch: u64, securing: u128) -> bool {
        let next = epoch.saturating_add(1);
        if next <= self.pendulum_epoch_next {
            return false; // this epoch (or a later one) is already snapshotted: once per epoch, never backward
        }
        self.pendulum_epoch_next = next;
        self.pendulum_share_bps = crate::satoshi::bonder_share_bps(securing, u128::from(self.sat_issued));
        true
    }
    /// ⭐ SATOSHI — the ledger's SAT words exactly as the certified bundle carries them: `(issued total, (pendulum epoch + 1,
    /// bonders' share bps))`. The raw words, not `pendulum_snapshot`'s decoded form, so a carried "no snapshot yet" stays one.
    #[must_use]
    pub fn sat_census(&self) -> (u64, (u64, u32)) {
        (self.sat_issued, (self.pendulum_epoch_next, self.pendulum_share_bps))
    }

    /// ⭐⭐ §BR-10 — the supply words, as the turnstile reads them around each class object.
    #[must_use]
    pub fn supply_words(&self) -> SupplyWords {
        SupplyWords {
            native: (self.reserve_commit, self.minted_commit),
            sat_issued: self.sat_issued,
            wrapped: self.wrapped_assets.iter().map(|(id, a)| (*id, a.reserve_commit, a.minted_commit)).collect(),
        }
    }

    /// ⭐⭐ §BR-10 — THE TURNSTILE'S BEFORE-IMAGE of one class object: every ledger word and map EXCEPT the five replay sets
    /// (applied ids, spent burns, confidential deposit ids, releases, liquidations), which only ever grow with history and
    /// are never copied per object. A refused object's restore then undoes every value it moved (supply, pools, buffers,
    /// pool and price words); an id it added to a replay set stays, which only refuses a re-apply (the safe direction).
    /// cons: one clone of the ledger's bounded words per class object at the fold (none on the wire).
    pub fn turnstile_image(&mut self) -> PegLedger {
        let sets = (
            std::mem::take(&mut self.applied_ids),
            std::mem::take(&mut self.spent_burns),
            std::mem::take(&mut self.confidential_deposit_ids),
            std::mem::take(&mut self.released),
            std::mem::take(&mut self.liquidated),
        );
        let image = self.clone();
        self.applied_ids = sets.0;
        self.spent_burns = sets.1;
        self.confidential_deposit_ids = sets.2;
        self.released = sets.3;
        self.liquidated = sets.4;
        image
    }

    /// ⭐⭐ §BR-10 — the turnstile's REFUSAL: the ledger goes back to `image` (from [`Self::turnstile_image`]) with this
    /// ledger's own replay sets kept. SUPPLY-RESTORE: a rewind to a before-image this step took — it can only undo a move.
    pub fn restore_turnstile_image(&mut self, mut image: PegLedger) {
        image.applied_ids = std::mem::take(&mut self.applied_ids);
        image.spent_burns = std::mem::take(&mut self.spent_burns);
        image.confidential_deposit_ids = std::mem::take(&mut self.confidential_deposit_ids);
        image.released = std::mem::take(&mut self.released);
        image.liquidated = std::mem::take(&mut self.liquidated);
        *self = image;
    }

    /// ⭐⭐ §BR-10 — put only the supply words back (the rule pin's restore check).
    pub fn restore_supply_words(&mut self, w: &SupplyWords) {
        self.reserve_commit = w.native.0;
        self.minted_commit = w.native.1;
        self.sat_issued = w.sat_issued;
        let keep: std::collections::BTreeSet<u32> = w.wrapped.iter().map(|(id, ..)| *id).collect();
        self.wrapped_assets.retain(|id, _| keep.contains(id));
        for (id, r, m) in &w.wrapped {
            if let Some(a) = self.wrapped_assets.get_mut(id) {
                a.reserve_commit = *r;
                a.minted_commit = *m;
            }
        }
    }
    /// ⭐ SATOSHI — the ADOPT half of a decider-certified bundle (`NullifierSnapshot::peg_sat_issued` / `peg_pendulum`, bound
    /// into `sync_binding`): a jumper never folded the rewards or the epoch boundary it skipped, so it installs the chain's
    /// words verbatim, exactly as `adopt_certified` installs the reserve.
    pub fn adopt_certified_sat(&mut self, sat_issued: u64, pendulum: (u64, u32)) {
        self.sat_issued = sat_issued;
        self.pendulum_epoch_next = pendulum.0;
        self.pendulum_share_bps = pendulum.1;
    }
    /// ⭐ §BR — the ledger words the §BR build added, exactly as the certified bundle carries them (`PegBrWords`): the four
    /// fee pools, the miner-pool quarter words, the bonders' yield index and accrual, the set-aside flag, the stake epoch's
    /// pool snapshot, the stakers' paid-out commitment, the deployment ledger and the release attestations.
    #[must_use]
    pub fn br_census(&self) -> PegBrWords {
        PegBrWords {
            words: [
                self.fee_pool_stakers,
                self.fee_pool_bonders,
                self.fee_pool_surplus,
                self.fee_pool_miner,
                self.miner_quarter_next,
                self.miner_rate,
                self.miner_accrual,
                self.miner_quarter_start,
                self.bond_yield_lo,
                self.bond_yield_hi,
                self.bonder_accrual,
                self.set_aside_applied,
                self.stakers_snap_epoch_next,
                self.stakers_snap_pool,
                self.repayment_sat_pot,
                self.theft_loss_open_sats,
                self.repayment_owed_atomic,
                self.haircut_remainder_atomic,
                self.haircut_events,
                self.decoy_epoch_next,
                self.decoy_credit,
                self.decoy_budget,
                self.decoy_spent,
                self.custody_cost_debt,
                self.custody_cost_retired,
            ],
            contract_state_root: self.contract_state_root,
            stake_paid_commit: self.stake_paid_commit,
            deployments: self.deployments.clone(),
            release_attestations: self.release_attestations.iter().map(|(k, v)| (*k, v.clone())).collect(),
            price_history: self.price_history.iter().map(|(k, v)| (*k, v.clone())).collect(),
            epoch_keys: self.epoch_keys.clone(),
            open_decoys: self.open_decoys.iter().map(|(k, v)| (*k, *v)).collect(),
            unit_book: self.unit_book.clone(),
            defi_book: self.defi_book.clone(),
            epoch_anchors: self.epoch_anchors.iter().copied().collect(),
            vault_keys: self.vault_keys.iter().map(|(k, v)| (*k, v.clone())).collect(),
            vault_parts: self.vault_parts.iter().map(|(k, v)| (*k, v.clone())).collect(),
            ion: (self.ion_pending.clone(), self.ion_usdm_held, self.ion_pools),
        }
    }

    /// ⭐ §BR-4 — asset `asset_id`'s 7-day time-weighted average price over its closed price epochs (`price_history`), or its
    /// standing mark while no epoch has closed. `None` while the chain has never priced it.
    #[must_use]
    pub fn twap7(&self, asset_id: u32) -> Option<u128> {
        self.price_history
            .get(&asset_id)
            .and_then(crate::price_history::PriceHistory::twap7)
            .or_else(|| self.price_marks.get(&asset_id).map(|m| m.price))
            .or_else(fixture_unit_price)
    }

    /// ⭐ §BR-4 — asset `asset_id`'s lowest price over the last 30 days: the history's low and the standing mark, whichever is
    /// lower. `None` while the chain has never priced it.
    #[must_use]
    pub fn low30(&self, asset_id: u32) -> Option<u128> {
        let hist = self.price_history.get(&asset_id).and_then(crate::price_history::PriceHistory::low30);
        let mark = self.price_marks.get(&asset_id).map(|m| m.price);
        match (hist, mark) {
            (Some(h), Some(m)) => Some(h.min(m)),
            (h, m) => h.or(m),
        }
    }
    /// ⭐ §BR — the ADOPT half of a decider-certified bundle (`NullifierSnapshot::peg_br`, bound into `sync_binding` by its
    /// digest): a jumper never folded the fees, quarters, claims or windows it skipped, so it installs the chain's words
    /// verbatim — exactly as `adopt_certified_sat` installs the issued total. Without it a jumper holds empty pools and
    /// refuses every pool-paid claim its peers apply.
    /// §BR-12 L1 — the contract-state root this ledger holds (the one word of every deployed contract).
    #[must_use]
    pub fn contract_state_root(&self) -> crate::spend_frontier::Digest4 {
        self.contract_state_root
    }

    /// §BR-12 L1 — the fold writes the root a deploy or a call produced from its carried path (`contract_state::insert_root`
    /// / `update_root` decided it); nothing else writes this word.
    pub fn set_contract_state_root(&mut self, root: crate::spend_frontier::Digest4) {
        self.contract_state_root = root;
    }

    pub fn adopt_certified_br(&mut self, w: &PegBrWords) {
        [
            self.fee_pool_stakers,
            self.fee_pool_bonders,
            self.fee_pool_surplus,
            self.fee_pool_miner,
            self.miner_quarter_next,
            self.miner_rate,
            self.miner_accrual,
            self.miner_quarter_start,
            self.bond_yield_lo,
            self.bond_yield_hi,
            self.bonder_accrual,
            self.set_aside_applied,
            self.stakers_snap_epoch_next,
            self.stakers_snap_pool,
            self.repayment_sat_pot,
            self.theft_loss_open_sats,
            self.repayment_owed_atomic,
            self.haircut_remainder_atomic,
            self.haircut_events,
            self.decoy_epoch_next,
            self.decoy_credit,
            self.decoy_budget,
            self.decoy_spent,
            self.custody_cost_debt,
            self.custody_cost_retired,
        ] = w.words;
        self.contract_state_root = w.contract_state_root;
        self.stake_paid_commit = w.stake_paid_commit;
        #[cfg(test)]
        let table = self.deployments.test_table.take();
        self.deployments = w.deployments.clone();
        #[cfg(test)]
        {
            self.deployments.test_table = table;
        }
        self.release_attestations = w.release_attestations.iter().cloned().collect();
        self.price_history = w.price_history.iter().cloned().collect();
        self.epoch_keys = w.epoch_keys.clone();
        self.open_decoys = w.open_decoys.iter().copied().collect();
        self.unit_book = w.unit_book.clone();
        self.defi_book = w.defi_book.clone();
        self.epoch_anchors = w.epoch_anchors.iter().copied().collect();
        // SAFE AT SCALE, stage three: the key record as carried — only rows that hold the record's own shape (sorted
        // members, a bounded address, at most the alive bound per vault, one current key and it the last)
        self.vault_keys = w.vault_keys.iter().filter(|(_, rows)| vault_key_rows_shaped(rows)).cloned().collect();
        // …and the parts at rest, only those that hold the slot's own shape (kinds in their one order)
        self.vault_parts = w.vault_parts.iter().filter(|(_, p)| vault_part_shaped(p)).cloned().collect();
        // IonSwap pools: the pending orders and the layer word, verbatim (bound by the digest); a list longer than the
        // ledger could hold came from no fold and is not adopted
        if w.ion.0.len() <= crate::ion_pool_tx::ION_PENDING_MAX {
            self.ion_pending = w.ion.0.clone();
            self.ion_usdm_held = w.ion.1;
            self.ion_pools = w.ion.2;
        }
    }

    /// ⭐ §19.4 — the epoch anchors (fold ordinal, chain-time slot, spend-frontier root), oldest first.
    #[must_use]
    pub fn epoch_anchors(&self) -> &std::collections::VecDeque<(u64, u64, crate::spend_frontier::Digest4)> {
        &self.epoch_anchors
    }

    /// ⭐ §19.4 — is `root` one of the kept epoch anchors (a root a claim's member leg may name)?
    #[must_use]
    pub fn holds_epoch_anchor(&self, root: &crate::spend_frontier::Digest4) -> bool {
        self.epoch_anchors.iter().any(|(_, _, r)| r == root)
    }

    /// ⭐ §19.4 — the fold step at `ordinal`, standing at chain time `chain_ms` (`Node::chain_time_ms_at` of its block), produced
    /// `root`: kept as an anchor when it is the first step in a later [`EPOCH_ANCHOR_MS`] slot than the newest kept anchor's (a
    /// re-fold of the same ordinal replaces its entry), the oldest dropped past [`EPOCH_ANCHORS_KEPT`]. Every node folds the same
    /// blocks in the same order, so every node keeps the same anchors. Returns whether it was kept.
    pub fn push_epoch_anchor(&mut self, ordinal: u64, chain_ms: u64, root: crate::spend_frontier::Digest4) -> bool {
        let slot = chain_ms / EPOCH_ANCHOR_MS;
        self.epoch_anchors.retain(|(o, _, _)| *o < ordinal);
        if ordinal == 0 || self.epoch_anchors.back().is_some_and(|(_, s, _)| *s >= slot) {
            return false;
        }
        self.epoch_anchors.push_back((ordinal, slot, root));
        while self.epoch_anchors.len() > EPOCH_ANCHORS_KEPT {
            self.epoch_anchors.pop_front();
        }
        true
    }

    /// ⭐ §19.4 — a fold rewind evicted every ordinal from `first_evict` on: its anchors described the old order.
    pub fn trim_epoch_anchors_from(&mut self, first_evict: u64) {
        self.epoch_anchors.retain(|(o, _, _)| *o < first_evict);
    }

    /// ⭐ SATOSHI — credit one block's mining reward against the hard cap. Refused (nothing moves) when it would take the
    /// issued total past `satoshi::SATOSHI_CAP`; the fold then strips the reward's note like any refused object's.
    pub fn credit_sat_reward(&mut self, amount: u64) -> bool {
        // §BR-13: the reward door is capped at the REWARD cap (19M); the supply cap (21M) is rewards + the set-aside bound.
        match self.sat_issued.checked_add(amount) {
            Some(total) if total <= crate::satoshi::SAT_REWARD_CAP => {
                self.sat_issued = total;
                true
            }
            _ => false,
        }
    }

    /// LIQUIDATION §10 — the stability-pool words of PSM `asset_id`. A PSM whose pool never moved holds the genesis words
    /// by definition (they are a pure function of the protocol constants), so absence IS the genesis state.
    #[must_use]
    pub fn pool_words(&self, asset_id: u32) -> PoolWords {
        // SAFE AT SCALE: ONE pool per asset — a vault's ledger of that asset is liquidated into the same pool
        match self.pools.get(&ledger_asset(asset_id)) {
            Some(w) => *w,
            None => PoolWords::genesis(), // never moved: the genesis words, by definition
        }
    }

    /// The registered wrapped assets (each with its own reserve and minted commitments).
    #[must_use]
    pub fn wrapped_asset_ids(&self) -> Vec<u32> {
        self.wrapped_assets.keys().copied().collect()
    }

    /// TEST SEAM — set the native peg's reserve and minted commitments and the stakers' paid-out commitment directly (a pin
    /// stands two ledgers on the same moved custody state without driving mints and stakes).
    #[cfg(test)]
    pub fn set_custody_commits_for_test(&mut self, reserve: crate::spend_frontier::Digest4, minted: crate::spend_frontier::Digest4, paid: crate::spend_frontier::Digest4) {
        self.reserve_commit = reserve;
        self.minted_commit = minted;
        self.stake_paid_commit = paid;
    }

    /// The assets whose pool words have moved from genesis (a pool never moved opens with the public genesis opening).
    #[must_use]
    pub fn pool_asset_ids(&self) -> Vec<u32> {
        self.pools.keys().copied().collect()
    }

    /// TEST SEAM — set one pool's words directly (a pin stands two ledgers on the same moved pool without driving deposits).
    #[cfg(test)]
    pub fn set_pool_words_for_test(&mut self, asset_id: u32, w: PoolWords) {
        self.pools.insert(asset_id, w);
    }

    /// LIQUIDATION §10 — advance one PSM's pool words (the deposit / withdrawal / liquidation applies, after their gates).
    pub fn set_pool_words(&mut self, asset_id: u32, w: PoolWords) {
        self.pools.insert(ledger_asset(asset_id), w);
    }

    /// The pool words the certified bundle carries: every PSM whose pool ever moved (its CURRENT epoch's words, sorted by
    /// asset), then every CLOSED epoch's closing words (sorted by asset, epoch). One vector, so the bundle shape is unchanged:
    /// an asset's entry with the highest epoch is its current pool, every lower one a closed epoch.
    #[must_use]
    pub fn pool_census(&self) -> Vec<(u32, PoolWords)> {
        self.pools.iter().map(|(a, w)| (*a, *w)).chain(self.pool_closes.iter().map(|((a, _), w)| (*a, *w))).collect()
    }

    /// Adopt the certified bundle's pool words (a jump), replacing this ledger's: per asset, the highest epoch is the
    /// current pool and every other entry a closed epoch (the inverse of [`Self::pool_census`]).
    pub fn adopt_certified_pools(&mut self, pools: &[(u32, PoolWords)]) {
        let mut current: std::collections::BTreeMap<u32, PoolWords> = std::collections::BTreeMap::new();
        let mut closes = std::collections::BTreeMap::new();
        for (a, w) in pools {
            match current.get(a) {
                Some(cur) if cur.epoch >= w.epoch => {
                    closes.insert((*a, w.epoch), *w);
                }
                Some(cur) => {
                    closes.insert((*a, cur.epoch), *cur);
                    current.insert(*a, *w);
                }
                None => {
                    current.insert(*a, *w);
                }
            }
        }
        self.pools = current;
        self.pool_closes = closes;
    }

    /// LIQUIDATION §10 — the closing words of PSM `asset_id`'s CLOSED pool epoch `epoch` (a receipt of that epoch withdraws
    /// against its `(P, S)`), or `None` when that epoch never closed.
    #[must_use]
    pub fn closed_pool_words(&self, asset_id: u32, epoch: u64) -> Option<PoolWords> {
        self.pool_closes.get(&(ledger_asset(asset_id), epoch)).copied()
    }

    /// H11 §2.5 — the `(P, S)` commitments of one bridge source of PSM `asset_id` (the live words, a closed epoch's
    /// closing words, or the public opening), `None` for a closed epoch this ledger does not hold.
    #[must_use]
    pub fn bridge_source_words(&self, asset_id: u32, src: BridgeSource) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        let w = match src {
            BridgeSource::Live => self.pool_words(asset_id),
            BridgeSource::Closed(e) => self.closed_pool_words(asset_id, e)?,
            BridgeSource::Opening => PoolWords::genesis(),
        };
        Some((w.p, w.s))
    }

    /// H11 §2.5 — the four source commitments `[P₁, S₁, P₂, S₂]` a receipt of pool `epoch` is bridged from, by the ONE
    /// selection rule ([`receipt_bridge_sources`]) — what every node verifies a withdrawal's bridge carrier against.
    #[must_use]
    pub fn receipt_bridge_words(&self, asset_id: u32, epoch: u64) -> Option<[crate::spend_frontier::Digest4; 4]> {
        let (first, second) = receipt_bridge_sources(epoch, self.pool_words(asset_id).epoch)?;
        let ((p1, s1), (p2, s2)) = (self.bridge_source_words(asset_id, first)?, self.bridge_source_words(asset_id, second)?);
        Some([p1, s1, p2, s2])
    }

    /// Is this USDm nullifier a REAL, already-recorded peg-out burn? The reserve's foreign-settlement leg releases
    /// funds ONLY against a burn that actually destroyed the matching USDm (conservation: no reserve leaves without
    /// a burn), so [`crate::node::Node::settle_reserve_release_observed`] gates on this. Reads a replay hash-set, not a
    /// value — discloses no amount.
    pub fn is_burned(&self, usdm_nullifier: &[u8; 32]) -> bool {
        self.spent_burns.contains(usdm_nullifier)
    }

    /// LIQUIDATION §10.2 — a stability-pool withdrawal applied at its fold AUTHORIZES the release of its collateral gain:
    /// its receipt nullifier becomes an owed release the payout lane may pay ONCE (the same `spent_burns` / `released`
    /// pair a peg-out uses — one authorization set, one paid-once set). The amount is the withdraw carrier's hidden gain,
    /// opened only by the custodians from their sealed leg; a zero gain authorizes a release nobody books. Bounded by
    /// the conservation of the pool: every gain is `d · (S_now − S_dep) / P_dep` rounded down, so all gains together never
    /// exceed the collateral the liquidations seized. The only caller is the pool withdrawal's fold apply.
    pub fn authorize_pool_gain_release(&mut self, receipt_nullifier: [u8; 32]) {
        if self.spent_burns.insert(receipt_nullifier) {
            self.applied_ids.push((receipt_nullifier, 1));
        }
    }

    /// Claim the ONE foreign reserve release a burned USDm nullifier is entitled to. Returns `true` the first time
    /// (records it), `false` on every repeat — so a single burn can NEVER authorize two foreign releases (no reserve
    /// double-drain). Idempotent + fail-closed; the set holds hashes, not values.
    /// DB-114: is this burn's foreign payout still OWED? The obligation is derived, never remembered: a
    /// burn the chain recorded and no release has claimed is money that left this chain and has not arrived
    /// on the other one. Both sets persist, so a restart cannot forget it, and nothing ages it out.
    #[must_use]
    pub fn release_pending(&self, usdm_nullifier: &[u8; 32]) -> bool {
        self.spent_burns.contains(usdm_nullifier) && !self.released.contains(usdm_nullifier)
    }

    pub fn mark_released(&mut self, usdm_nullifier: [u8; 32]) -> bool {
        self.applied_ids.push((usdm_nullifier, 2));
        self.released.insert(usdm_nullifier)
    }

    /// Genesis ledger: the confidential-solvency commitments seeded to commitment-to-ZERO under the WELL-KNOWN
    /// genesis blinds ([`GENESIS_PEG_RESERVE_BLIND`]/[`GENESIS_PEG_MINTED_BLIND`]), so the FIRST confidential peg-in
    /// has a well-defined zero-state to prove FROM. The LIVE node uses THIS (never [`Self::new`], whose raw `[0;4]`
    /// digests match no real `solvency_commit_256` output ⇒ the first-ever mint would fail-closed as unprovable).
    /// Sound: the committed value is 0 (a genesis fact any observer can derive); hiding only begins to matter once a
    /// nonzero secret total exists (after the first real deposit advances the pair under secret blinds).
    /// ⭐ IS THE RESERVE ZERO? Decidable on every node WITHOUT opening the hiding commitment: the zero
    /// state is the known constant `solvency_commit(0, GENESIS_PEG_RESERVE_BLIND)` that `genesis` seeds,
    /// and after the first real deposit the blind is secret, so no non-zero total can ever equal it.
    /// Conservation (P6) proves a full peg-out returns to exactly this constant, so the answer is true
    /// again when there is nothing left to secure.
    ///
    /// This is what makes the adaptive bond rule (`bond >= 2 x reserve`) evaluable at its zero point:
    /// `Class::MembershipBond` is free exactly while this holds.
    pub fn reserve_is_zero(&self) -> bool {
        // ONE spelling of "zero", the same call `genesis` makes — a second spelling of a constant is how
        // two nodes disagree about whether a seat is free.
        self.reserve_commit
            == usdm_decider::confidential_solvency::solvency_commit_256(
                usdm_decider::confidential_solvency::u256_from_u64(0),
                GENESIS_PEG_RESERVE_BLIND,
            )
    }

    pub fn genesis(ratio_bps: u32) -> Self {
        let mut l = Self::new(ratio_bps);
        let zero = usdm_decider::confidential_solvency::u256_from_u64(0);
        l.reserve_commit = usdm_decider::confidential_solvency::solvency_commit_256(
            zero,
            GENESIS_PEG_RESERVE_BLIND,
        );
        l.minted_commit = usdm_decider::confidential_solvency::solvency_commit_256(
            zero,
            GENESIS_PEG_MINTED_BLIND,
        );
        // The HWM starts AT the genesis-zero reserve: at genesis nothing has ever been deposited, so the
        // liquidation door's `new_reserve <= HWM` bound is a bound by ZERO — no re-mark is provable until a
        // real peg-in raises it. Fail-closed by construction.
        l.reserve_hwm_commit = l.reserve_commit;
        // ⭐ Monero's own ledger exists from height 0 on every node (all forks at height 1, TESTNET == PRODUCTION): a
        // Monero deposit mints only here, priced by the XMR mark, and a Monero cash-out redeems only from here.
        l.register_wrapped_asset(XMR_PEG_ASSET_ID, ratio_bps);
        l
    }

    /// The required over-collateralization ratio (bps; 15000 = 150%). A consensus POLICY parameter, not a value —
    /// the custodian orchestration needs it to build a yield-mint carrier that verifies against the SAME ratio the
    /// node's `claim_reserve_yield` gate enforces.
    pub fn ratio_bps(&self) -> u32 {
        self.ratio_bps
    }

    /// The ledger's carried rate word (the certified bundle and the frozen persistence formats carry it). ⛔ DB-237: NO
    /// reward reads it — the stake rule's rate is `ChainParams::stake_reward_apr_bps`, checked at the fold.
    pub fn yield_rate_bps(&self) -> u32 {
        self.yield_rate_bps
    }
    /// TEST — set the carried rate word (the authority fuzz builds a ledger that diverges on it).
    #[cfg(test)]
    pub fn set_yield_rate_bps(&mut self, rate_bps: u32) {
        self.yield_rate_bps = rate_bps;
    }

    /// The redeem (peg-out) solvency floor policy (bps; 10000 = 100%); a governance param, not a value. A Sell may
    /// draw the reserve buffer down to this floor — below the 150% MINT ratio — with the withdraw fee rising as
    /// backing falls; `set_redeem_floor_bps` tunes it. See [`default_redeem_floor_bps`].
    pub fn redeem_floor_bps(&self) -> u32 {
        self.redeem_floor_bps
    }
    /// Governance retune of the redeem floor. Clamped to a minimum of 10000 bps (100%): the floor can never be set
    /// below full backing, because a peg-out that leaves the post-state under 100% is genuine insolvency (some USDm
    /// would become unredeemable). Governance may only raise it (a larger safety buffer), never below the true line.
    pub fn set_redeem_floor_bps(&mut self, floor_bps: u32) {
        self.redeem_floor_bps = floor_bps.max(10_000);
    }

    /// Register (governance) a wrapped-asset PSM (IonSwap bridge). `ratio_bps` = 15000 for a VOLATILE asset
    /// (wBTC/wETH — the 150% buffer absorbs price drops) or 10000 for a vetted STABLECOIN (wDAI — 1:1 stable needs
    /// no volatility buffer, so it is EXEMPT from the 150%). Clamped to >=10000: no wrapped asset may mint below 1:1
    /// backing (genuine insolvency). First registration inits the asset's confidential commitments to genesis-0;
    /// re-registering only RETUNES the ratio (governance may re-class a de-pegged stablecoin as volatile at 15000).
    pub fn register_wrapped_asset(&mut self, asset_id: u32, ratio_bps: u32) {
        use usdm_decider::confidential_solvency as cs;
        if asset_id & VAULT_LEDGER_BIT != 0 {
            return; // SAFE AT SCALE: the composite ids are the vaults' own ledgers — never an asset anyone registers or retunes
        }
        if asset_id & CUSTODIAN_SLOT_BITS != 0 {
            // a custodian keeps its merge and rebalance openings beside its asset seals under these bits (`Node::MERGE_HELD`,
            // `REBALANCE_*`); an asset id carrying one would share a seal with them
            return;
        }
        let ratio_bps = ratio_bps.max(10_000);
        let zero = cs::u256_from_u64(0);
        let (rb, mb) = psm_genesis_blinds(asset_id);
        let e = self
            .wrapped_assets
            .entry(asset_id)
            .or_insert_with(|| WrappedAsset {
                reserve_commit: cs::solvency_commit_256(zero, rb),
                minted_commit: cs::solvency_commit_256(zero, mb),
                ratio_bps,
                // the asset's HWM starts AT its genesis-zero reserve: nothing has been deposited yet, so a
                // re-mark of an empty PSM is bounded by zero (fail-closed — there is no collateral to mark).
                reserve_hwm_commit: cs::solvency_commit_256(zero, rb),
            });
        e.ratio_bps = ratio_bps; // governance retune (re-class a de-pegged stablecoin as volatile)
    }

    /// ⛔⛔⛔ THE DOMAIN-SEPARATED MESSAGE A WRAPPED-ASSET REGISTRATION IS ATTESTED OVER.
    ///
    /// Binds the PREVIOUS ratio as well as the new one — the same COMMITMENT-CHAIN shape
    /// `revalue_msg` uses for the re-mark, and it is what makes this object replay-proof with NO new
    /// persisted state: an attestation authorises exactly one transition `prev -> new` for one asset in
    /// one epoch, so re-playing an old registration names a `prev` that no longer matches this node's
    /// ledger and is refused. `prev_ratio_bps` is 0 for a FIRST registration (the asset is unknown).
    /// ⭐⭐⭐ THE MESSAGE A BRIDGE CREDIT'S BONDED ATTESTORS SIGN.
    ///
    /// ⛔⛔⛔ WHY THIS EXISTS: until it did, `chain_object::admissible`'s `Class::BridgeCredit` arm
    /// decoded the payload, compared the amount to `genesis_mint_allowance` and returned true —
    /// **nothing asked WHO may issue a credit** (`value_creation`'s `Authority::Missing`). On a
    /// value-bearing network the allowance is 0, so the class was unsatisfiable: safe by accident, and
    /// it also meant the bridge could not credit a deposit on mainnet at all. The arm's own comment said
    /// the bonded-threshold arm "MUST land" for mainnet to open.
    ///
    /// DOMAIN-SEPARATED AND FULLY BINDING, exactly like the peg messages beside it: an attestation over
    /// one deposit cannot be replayed onto another asset, another amount, another note or another
    /// deposit id. The note COMMITMENT is bound rather than the note bytes, so the signature covers
    /// exactly what is credited without carrying a payload.
    /// ⛔ DB-273 §17 — `owner_clue` is bound by its canonical digest ([`crate::oli::owner_clue_digest`]): a relay
    /// that strips or swaps the credit's owner changes the message, so the quorum's signatures no longer verify
    /// (v2 of the domain; v1 bound no owner). MEASURED RED before: `db273_s17_a_peer_does_not_credit_a_copy_whose_
    /// owner_a_relay_stripped` (B credited the stripped copy).
    pub fn bridge_credit_msg(
        deposit_id: &[u8; 32],
        asset_tag: &[u64; 3],
        amount: u64,
        note_cm: &[u8; 32],
        owner_clue: &[u8],
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(32 + 32 + 24 + 8 + 32 + 32);
        m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.bridge-credit.v2"));
        m.extend_from_slice(deposit_id);
        for t in asset_tag {
            m.extend_from_slice(&t.to_le_bytes());
        }
        m.extend_from_slice(&amount.to_le_bytes());
        m.extend_from_slice(note_cm);
        m.extend_from_slice(&crate::oli::owner_clue_digest(owner_clue));
        m
    }

    pub fn wrapped_register_msg(
        epoch_id: u64,
        asset_id: u32,
        prev_ratio_bps: u32,
        ratio_bps: u32,
    ) -> Vec<u8> {
        let mut m = Vec::with_capacity(32 + 8 + 4 + 4 + 4);
        m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.wrapped-register.v1"));
        m.extend_from_slice(&epoch_id.to_le_bytes());
        m.extend_from_slice(&asset_id.to_le_bytes());
        m.extend_from_slice(&prev_ratio_bps.to_le_bytes());
        m.extend_from_slice(&ratio_bps.to_le_bytes());
        m
    }

    /// ⛔⛔⛔ THE ONLY DOOR THAT MAY SET A WRAPPED ASSET'S COLLATERAL RATIO — ≥2/3 BONDED, CHAIN-CARRIED.
    ///
    /// WHAT WAS WRONG. `register_wrapped_asset` was reachable from `POST /register_wrapped_asset` with no
    /// threshold, no vote and no block, and `ratio_bps` decides how much USDm may be minted against an
    /// asset — setting a volatile asset to 10000 removes the 150% buffer, so 50% more USDm is mintable
    /// against the same collateral. That the RPC binds loopback only is NOT a mitigation: it bounds WHO
    /// can trigger it, not what it is. The ratio is a CONSENSUS value (it is fed into the mint carrier),
    /// so a node that takes it from a socket is minting against a number the chain never set — the
    /// "local state decides consensus" root error this tree has already paid for once, when a DEX fill's
    /// burn stayed local and a maker's lot paid out twice. This module's own census says it plainly: "a
    /// node fed only blocks derives the ratios the CHAIN set. Any party that disagrees is minting against
    /// a number a socket supplied."
    ///
    /// THE BORROW: MakerDAO/Ethereum — a collateral parameter is changed only by an authorised on-chain
    /// action, never by an operator's local command. The mechanism is this tree's OWN proven one, the
    /// same division of labour `liquidate_confidential` uses: the object rides a BLOCK
    /// ([`crate::wrapped_asset_tx`], `Class::WrappedAssetRegister`), and the value moves only here,
    /// behind the ≥2/3 bonded ML-DSA tally over [`Self::wrapped_register_msg`].
    ///
    /// REPLAY is closed WITHOUT new state by the commitment chain: the attested message names the
    /// PREVIOUS ratio, and this door refuses unless it equals what this node currently holds. An old
    /// registration replayed after a retune names a stale `prev` and moves nothing. A first registration
    /// names `prev = 0`, which only matches an asset this node has never registered.
    ///
    /// FAIL-CLOSED on every arm, and it never halts the chain: a refused object leaves the ledger exactly
    /// as it was and the block still grafts.
    /// cons: one message build (≈50 bytes) and one bonded tally per registration object — a
    /// governance-scale event, not a per-block or per-note cost. No new persisted field, so no snapshot
    /// schema bump and no frozen door.
    pub fn register_wrapped_asset_attested(
        &mut self,
        epoch_id: u64,
        asset_id: u32,
        prev_ratio_bps: u32,
        ratio_bps: u32,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        // THE COMMITMENT CHAIN — this authorisation is for the transition THIS node is standing on.
        // `None` (unregistered) reads as 0, so a first registration must attest `prev = 0`.
        if asset_id & VAULT_LEDGER_BIT != 0 {
            return PegOutcome::BadRequest; // SAFE AT SCALE: a vault's own ledger is never registered or retuned as an asset
        }
        let current = self.wrapped_assets.get(&asset_id).map(|a| a.ratio_bps).unwrap_or(0);
        if current != prev_ratio_bps {
            return PegOutcome::Replay;
        }
        // A registration that changes nothing is refused rather than silently accepted: it would burn a
        // fresh attestation over a no-op transition, and the door's whole contract is that an attestation
        // authorises a MOVE.
        if ratio_bps.max(10_000) == current {
            return PegOutcome::BadRequest;
        }
        let msg = Self::wrapped_register_msg(epoch_id, asset_id, prev_ratio_bps, ratio_bps);
        if !threshold_ok(quorum, verifier, &msg, attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        self.register_wrapped_asset(asset_id, ratio_bps);
        PegOutcome::WrappedAssetRegistered
    }

    /// The domain-separated message ONE custodian signs to attest ONE price. The price is IN the message,
    /// so a quote cannot be lifted off one mark and replayed onto another asset, epoch or number.
    pub fn price_mark_msg(epoch_id: u64, asset_id: u32, price: u128) -> Vec<u8> {
        let mut m = Vec::with_capacity(32 + 8 + 4 + 16);
        m.extend_from_slice(&crate::pqauth::node_statement(b"musdm.peg.price-mark.v1"));
        m.extend_from_slice(&epoch_id.to_le_bytes());
        m.extend_from_slice(&asset_id.to_le_bytes());
        m.extend_from_slice(&price.to_le_bytes());
        m
    }

    /// ⛔⛔⛔ THE ONLY DOOR THAT MAY SET AN ASSET'S PRICE — >=2/3 BONDED, CHAIN-CARRIED, MEDIAN-REDUCED.
    ///
    /// WHAT WAS WRONG. There was no price at all: the peg counted one atomic unit of the deposited asset
    /// as one USDm atomic unit, for every asset, and the 150% backing check compared those raw counts. The
    /// ratio check was sound and the UNIT was not, so 1 XMR (1e12 piconero) could mint on the order of
    /// $6.67 BILLION against ~$150 of collateral — an unbounded theft from every other USDm holder, since
    /// they are all backed by the same reserve.
    ///
    /// Each quote is verified against ITS OWN signed price through the shared [`tally_attestors`], so this
    /// door gets no second set of quorum rules; only the message differs. The accepted mark is the
    /// BOND-WEIGHTED MEDIAN of the counted quotes, which (module header of [`crate::price_mark_tx`]) lands
    /// inside the honest spread whenever byzantine bonded weight is under 1/3 — the same assumption every
    /// other door here already rests on.
    ///
    /// FAIL-CLOSED, and the chain never halts: a bad signature that could have counted, weight not STRICTLY above 2/3
    /// (DB-387: the mark's own tally is `2f + 1` of `3f + 1`, so a colluder holding exactly one third cannot set it),
    /// a non-advancing epoch, or no derivable median all leave the previous mark exactly where it was and
    /// change nothing else. A refused mark refuses that asset's next MINT; it never stops block production
    /// and never blocks a REDEMPTION (see `priced_value`).
    pub fn mark_price_attested(
        &mut self,
        epoch_id: u64,
        asset_id: u32,
        quotes: &[crate::price_mark_tx::PriceQuote],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> PegOutcome {
        // THE REPLAY GUARD — ONE TOTAL ORDER, SO GRAFT ORDER CANNOT DECIDE (DB-245). A later epoch wins;
        // within an epoch the smaller `price_rank` wins; the standing mark is the MAXIMUM of every valid mark
        // applied. The old rule kept the FIRST mark of an epoch, and since DB-240 two quorate nodes publish
        // two valid marks for one epoch with different medians, which concurrent blocks deliver in either
        // order — so two honest nodes stood on two prices. A maximum does not depend on arrival order, and a
        // re-broadcast of the standing mark has an equal rank, so it is refused exactly as before. An EARLIER
        // epoch is refused here, before a single signature is verified; a same-epoch mark needs its median,
        // so it is judged after the tally below. That tally is bounded work: quotes sign (epoch, asset, price),
        // never the mark, so copied genuine quotes are cache hits in the node's own verified quote book
        // (`price_quote::BookVerifier`, which `Node::mark_price_attested` passes here). A forged mark costs
        // one real verify, as at every other attested door.
        if let Some(cur) = self.price_marks.get(&asset_id) {
            if epoch_id < cur.epoch_id {
                return PegOutcome::Replay;
            }
        }
        let attestors = crate::price_mark_tx::as_attestors(quotes);
        let only: Vec<MintAttestor> = attestors.iter().map(|(_, a)| a.clone()).collect();
        let prices: Vec<u128> = attestors.iter().map(|(p, _)| *p).collect();
        let Some(tally) = tally_attestors(quorum, verifier, &only, &|i| {
            Self::price_mark_msg(epoch_id, asset_id, prices[i])
        }) else {
            return PegOutcome::InsufficientThreshold; // a signature that could have counted did not verify
        };
        // ⛔⛔⛔ DB-387 (H11 oracle census, USER RULING 2026-10-04 — fix A): the MARK's tally is STRICTLY MORE THAN two thirds
        // of the bonded weight — `2f + 1` of `3f + 1` — not the `≥ 2/3` every yes/no attestation uses. MEASURED (lane-harness,
        // `an_oracle_colluder_holding_one_third_of_the_bond_moves_the_mark_down_…`): three equal custodians, the colluder
        // holding EXACTLY 1/3 quoting 10× low, a producer carrying {colluder, one honest}: 2 of 3 met `attested·3 ≥ total·2`
        // and the lower median handed the colluder the mark — every peer stood on 1,500 against 15,000, a liquidation lever.
        // The module's proof needs the byzantine share of the ATTESTING set strictly under 1/2; at `t = 1/3, a = 2/3` it is
        // exactly 1/2. Strictly more than 2/3 attesting restores `t/a < 1/2` for every `t ≤ 1/3`, so the median is honest by
        // the existing argument. `threshold_ok` (reserve movements, a yes/no vote) keeps its ≥ 2/3 — the user's custody ruling.
        // Cons (accepted by the user): with three custodians all three must quote, else the last mark stands; with four,
        // three (unchanged). Fail-closed: a mark that does not clear it leaves the previous mark exactly where it was.
        if !mark_tally_clears(&tally, quorum.total_bond()) {
            return PegOutcome::InsufficientThreshold;
        }
        let mut weighted: Vec<(u128, u128)> =
            tally.counted.iter().map(|(i, w)| (prices[*i], *w)).collect();
        let Some(price) = crate::price_mark_tx::bond_weighted_median(&mut weighted) else {
            // No counted weight ⇒ no median. Inventing one would be a price nobody attested.
            return PegOutcome::InsufficientThreshold;
        };
        if let Some(cur) = self.price_marks.get(&asset_id) {
            if epoch_id == cur.epoch_id && !crate::price_mark_tx::outranks(epoch_id, asset_id, price, cur.price) {
                return PegOutcome::Replay; // the standing mark is at least this one in the order
            }
        }
        // §BR-4: a later epoch closes the standing mark's epoch — it joins the asset's history (TWAP + low) now, final
        if let Some(cur) = self.price_marks.get(&asset_id).copied() {
            if epoch_id > cur.epoch_id {
                let _ = self.price_history.entry(asset_id).or_default().fold(cur.epoch_id, cur.price);
            }
        }
        self.price_marks.insert(asset_id, crate::price_mark_tx::PriceMark { price, epoch_id });
        // ⭐ §BR-4/§BR-7: a GUARDED mark (inside LIQ_TWAP_BAND_BPS of the 7-day average — one epoch's outlier liquidates
        // nothing) below a band's floor liquidates that band: permissionless, applied at the fold in canonical order, every
        // input public. The forfeited collateral stays in the reserve; the cancelled debt's USDm stays in circulation.
        if asset_id == NATIVE_PEG_ASSET_ID && self.mark_is_guarded(asset_id, price) {
            let _ = self.unit_book.liquidate_below(price);
        }
        PegOutcome::PriceMarked(price)
    }

    /// The liquidation guard (§BR-4 spec §1 item 7): a mark acts on a liquidation only within `LIQ_TWAP_BAND_BPS` of the 7-day
    /// average. With no closed price epoch yet there is no average to stray from, and NO liquidation runs (a launch's first
    /// marks cannot liquidate anyone).
    #[must_use]
    pub fn mark_is_guarded(&self, asset_id: u32, mark: u128) -> bool {
        self.mark_guard(asset_id, mark).unwrap_or(false)
    }

    /// ⭐ §BR-4 — THE ONE LIQUIDATION GUARD (shared by [`Self::liquidation_rule`] and [`Self::mark_is_guarded`]): `None` while
    /// no price epoch has closed (no average to stray from); otherwise `Some(true)` iff the mark lies within
    /// [`LIQ_TWAP_BAND_BPS`] of the 7-day average, OR the move beyond the band has PERSISTED for
    /// [`crate::price_history::GUARD_PERSIST_EPOCHS`] closed epochs on the same side (`PriceHistory::move_persisted`).
    /// ROOT-LAYER: the band and the persistence rule are decided here, once, for both readers.
    /// MEASURED: before — `liquidation::tests::crash_simulation_minus_70…` RED at step 3 (mark 0.585 vs TWAP 0.795, refused for
    /// the rest of the crash); after — the pin restated over the guard delay passes, and the outlier pins still refuse.
    /// MUST-STAY-GREEN: `mints_and_redemptions_read_the_twap_and_an_outlier_mark_cannot_liquidate`, the §BR-7 band refuters,
    /// the flash-price census.
    /// The history's own 7-day average (no standing-mark fallback) — what the guard strays from; for the crash pin's independent
    /// recomputation of the guard.
    #[cfg(test)]
    pub fn price_history_twap7_for_test(&self, asset_id: u32) -> Option<u128> {
        self.price_history.get(&asset_id).and_then(crate::price_history::PriceHistory::twap7)
    }

    #[must_use]
    pub fn mark_guard(&self, asset_id: u32, mark: u128) -> Option<bool> {
        let hist = self.price_history.get(&asset_id)?;
        let t = hist.twap7()?;
        let band = t.saturating_mul(u128::from(LIQ_TWAP_BAND_BPS)) / 10_000;
        Some(mark.abs_diff(t) <= band || hist.move_persisted(t, LIQ_TWAP_BAND_BPS, mark))
    }

    /// §BR-4 B4-2 — open one unit and spend its Bitcoin deposit's id (the fold dry-ran the open first). A refusal here would
    /// mean the dry run and the apply disagree, which they cannot (same book, same inputs, no step between).
    pub fn open_unit_spending_base(&mut self, t: &crate::debt_units::UnitTerms, today: u64, base: &[u8; 32]) {
        if self.unit_book.open_unit(t, today).is_ok() {
            self.confidential_deposit_ids.insert(*base);
            self.applied_ids.push((*base, 0));
        }
    }

    /// §BR-4/§BR-7 — the debt-unit book (public counts and band epochs).
    #[must_use]
    pub fn unit_book(&self) -> &crate::debt_units::UnitBook {
        &self.unit_book
    }

    /// §BR-15: the DeFi book.
    #[must_use]
    pub fn defi_book(&self) -> &crate::defi_batch::DefiBook {
        static EMPTY: std::sync::OnceLock<crate::defi_batch::DefiBook> = std::sync::OnceLock::new();
        self.defi_book.first().unwrap_or_else(|| EMPTY.get_or_init(crate::defi_batch::DefiBook::default))
    }

    /// ⭐ §18.14 — a pair's book.
    #[must_use]
    pub fn defi_book_of(&self, pair: u8) -> Option<&crate::defi_batch::DefiBook> {
        self.defi_book.get(pair as usize)
    }

    /// §BR-15: a pair's book, for the fold's applies only (`defi_batch::apply_chain_defi`).
    pub fn defi_book_mut(&mut self, pair: u8) -> Option<&mut crate::defi_batch::DefiBook> {
        self.defi_book.get_mut(pair as usize)
    }

    /// ⭐ THE ENDOWMENT'S COMMITMENT — what this node stands on. Opaque: no amount is disclosed.
    pub fn retention_endowment_commit(&self) -> crate::spend_frontier::Digest4 {
        self.retention_endowment_commit
    }

    /// DB-357 part 1 — a DSYNC adopt installs the CERTIFIED endowment commitment verbatim, exactly as
    /// [`Self::adopt_certified_wrapped_assets`] installs the registry: the bundle binds it (`sync_binding`), and a
    /// jumper that kept its own would stand on a different endowment from every node that watched the chain.
    pub fn adopt_certified_retention_endowment(&mut self, commit: crate::spend_frontier::Digest4) {
        self.retention_endowment_commit = commit;
    }

    /// ⛔⛔⛔ CREDIT THE ENDOWMENT — the note-creation door's half of the retention fee.
    ///
    /// Takes the OPENING (the balance and its blind) because the balance is committed, advances it by
    /// `paid`, and re-commits. Conservation is checked against [`crate::economics`] rather than restated
    /// here, so the credit door and the payout door cannot disagree about what "conserves" means.
    ///
    /// `None` when the stated opening does not open this ledger's committed endowment (fail-closed: a
    /// stale opening credits nothing) or when conservation would not hold.
    pub fn credit_retention_endowment(
        &mut self,
        balance: u128,
        blind: crate::spend_frontier::Digest4,
        paid: u128,
    ) -> Option<u128> {
        if Self::endowment_commit_of(balance, blind) != self.retention_endowment_commit {
            return None; // the opening does not open what this node holds
        }
        let after = balance.checked_add(paid)?;
        if !crate::economics::retention_fee_conserves(paid, balance, after) {
            return None;
        }
        self.retention_endowment_commit = Self::endowment_commit_of(after, blind);
        Some(after)
    }

    /// ⛔⛔⛔ PAY A MINER FROM THE ENDOWMENT — the ONLY way value reaches a miner, and it cannot mint.
    ///
    /// Proves [`crate::economics::payout_is_funded`] before anything moves: the endowment pays only what
    /// it already holds. An over-payout is REFUSED, never clamped — a clamp would silently mint the
    /// difference, which is precisely the zero-issuance property this chain holds by absence.
    pub fn pay_miner_from_endowment(
        &mut self,
        balance: u128,
        blind: crate::spend_frontier::Digest4,
        payout: u128,
    ) -> Option<u128> {
        if Self::endowment_commit_of(balance, blind) != self.retention_endowment_commit {
            return None;
        }
        let after = crate::economics::endowment_after_payout(balance, payout)?;
        self.retention_endowment_commit = Self::endowment_commit_of(after, blind);
        Some(after)
    }

    /// The endowment's commitment for an opening — ONE derivation, shared by both doors, so a credit and
    /// a payout can never commit the same balance two different ways.
    #[must_use]
    pub fn endowment_commit_of(balance: u128, blind: crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
        // The SAME commitment primitive the reserve and minted totals use — one derivation for every
        // confidential balance on this ledger, so no door invents a second way to commit a number.
        usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(balance), blind)
    }

    /// ⭐⭐ DB-251 — INSTALL THE CHAIN'S CERTIFIED PRICE MARKS VERBATIM at a #29 adopt, replacing this node's own. A
    /// jumped node's marks are stale by definition, exactly like the ratio `adopt_certified` replaces. Besides
    /// `mark_price_attested` this is the ONLY writer of `price_marks`. It is not a second door for a mark: the
    /// bundle's certificate binds these values (`sync_binding`), where a mark object's quorum tally binds its own.
    pub fn adopt_certified_price_marks(&mut self, marks: &[(u32, u128, u64)]) {
        self.price_marks = marks
            .iter()
            .map(|(asset, price, epoch)| (*asset, crate::price_mark_tx::PriceMark { price: *price, epoch_id: *epoch }))
            .collect();
    }

    /// ⭐ DB-271 — the chain's wrapped-asset registry, sorted by asset id (a `BTreeMap` walk): what a certified bundle
    /// carries. O1-FOOTPRINT-REVIEWED: bounded by the registered-asset set, like `price_marks`.
    #[allow(clippy::type_complexity)]
    pub fn wrapped_asset_census(
        &self,
    ) -> Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, u32, crate::spend_frontier::Digest4)> {
        self.wrapped_assets
            .iter()
            .map(|(id, a)| (*id, a.reserve_commit, a.minted_commit, a.ratio_bps, a.reserve_hwm_commit))
            .collect()
    }

    /// ⭐ DB-271 — install the CERTIFIED wrapped-asset registry at an adopt, REPLACING this node's own: the certified
    /// state is the chain's, and the local map is a cache of it.
    #[allow(clippy::type_complexity)]
    pub fn adopt_certified_wrapped_assets(
        &mut self,
        assets: &[(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, u32, crate::spend_frontier::Digest4)],
    ) {
        self.wrapped_assets = assets
            .iter()
            .map(|(id, reserve, minted, ratio, hwm)| {
                (
                    *id,
                    WrappedAsset {
                        reserve_commit: *reserve,
                        minted_commit: *minted,
                        ratio_bps: *ratio,
                        reserve_hwm_commit: *hwm,
                    },
                )
            })
            .collect();
    }

    /// The mark this node stands on for an asset, or None if the chain has never set one.
    pub fn price_mark_for(&self, asset_id: u32) -> Option<crate::price_mark_tx::PriceMark> {
        self.price_marks.get(&asset_id).copied()
    }

    /// ⭐ §BR-1 / §19.4 / §19.5 item 1 — THE ONE RELEASE RULE every peg-out door reads (the proposer, each attesting
    /// custodian, the executor, the route): the burn must be ONE rung of the cash-out ladder (`peg_pool::is_usd_denom`), and
    /// the release is that burn priced at the paying ledger's reference price — satoshis from the native ledger, piconero
    /// from Monero's ([`XMR_PEG_ASSET_ID`]). Every piece of one rung that a batch burns therefore pays the SAME amount on
    /// either chain, and custody reads only "a $D piece" (§19.5: the exact-burn Monero exception is deleted). `None` refuses
    /// the burn before anything moves (not a rung, no price, nothing to release, or a release past u64).
    #[must_use]
    pub fn peg_out_release(&self, burn_atomic: u128, redeem_to: &str) -> Option<u128> {
        // ⭐ §18.14: a coin note pays atom for atom, one rung at a time, and reads no price
        if let Some(coin) = crate::cashout_ticket::coin_ledger_of(redeem_to) {
            return u64::try_from(burn_atomic).ok().filter(|b| crate::peg_pool::coin_denoms(coin).contains(b)).map(u128::from);
        }
        // §BR-5 B5-d: a zero burn releases nothing — custody's REFUND of an escrow the price outran (its change returns the
        // escrow less the fee to its owner); nothing leaves the reserve
        if burn_atomic == 0 {
            return Some(0);
        }
        if !u64::try_from(burn_atomic).is_ok_and(crate::peg_pool::is_usd_denom) {
            return None;
        }
        self.release_sats_for_burn(Self::peg_out_asset_for(redeem_to), burn_atomic).filter(|r| *r > 0 && u64::try_from(*r).is_ok())
    }

    /// Is `redeem_to` a Monero destination — a Monero address, or the §BR-5 `KIND_XMR` a ticketed leg names in its place?
    /// The ONE spelling every peg-out door reads to pick the ledger a cash-out pays from.
    #[must_use]
    pub fn is_monero_destination(redeem_to: &str) -> bool {
        crate::bridge::is_monero_address(redeem_to) || redeem_to.starts_with(crate::cashout_ticket::KIND_XMR) || redeem_to == crate::cashout_ticket::KIND_COIN_XMR
    }

    /// Is `asset_id` a ledger the bridge funds from a foreign chain's deposit address — the native (Bitcoin) ledger or
    /// Monero's? (Other registered ledgers are minted by their own attested doors.)
    #[must_use]
    pub fn is_bridge_ledger(asset_id: u32) -> bool {
        // SAFE AT SCALE: a vault's own bridge ledger (`vault_ledger`) is one too — judged by the asset it counts
        matches!(ledger_asset_checked(asset_id), Some(NATIVE_PEG_ASSET_ID | XMR_PEG_ASSET_ID))
    }

    /// Is `asset_id` a §18.14 coin ledger?
    #[must_use]
    pub fn is_coin_ledger(asset_id: u32) -> bool {
        ledger_asset_checked(asset_id).is_some_and(|a| COIN_LEDGERS.contains(&a))
    }

    /// ⭐⭐ A-F69 (lane goodshalt, 2026-11-15) — IS A MINT ON `asset_id` PRICED ON A STALE MARK? True for a ledger priced by its
    /// asset's mark (a bridge ledger: Bitcoin's, Monero's, or a vault's of either — the ledgers [`Self::reference_price`] reads
    /// a TWAP for) whose standing mark misses the last closed price epoch (`epoch_id + 1 < current_epoch`: the bonded quorum
    /// marked no price for a whole epoch). Never for a coin ledger or a wrapped asset (one atom for one atom, no price), and
    /// never when the asset has no mark at all (then there is no backing and the mint is refused at every door already).
    ///
    /// MEASURED why (finding A-F69, read 2026-11-15): `price_mark_tx.rs` promised that a stale mark refuses that asset's mint
    /// and no door read a mark's age. The mark tally clears only STRICTLY above 2/3 of bond ([`mark_tally_clears`], DB-387), so
    /// one of three equal custodians gone dark stops the marks; the 7-day TWAP then ends at the last folded mark
    /// (`PriceHistory::twap7`), and every mint kept pricing at it — a deposit made after a fall past the mint ratio's margin
    /// (150 %: a third) would mint USDm the reserve does not back.
    /// WHY AN EPOCH AND NOT A DURATION: the rule says what the quorum did ("no mark for a whole price epoch"), so it holds at the
    /// chain's real pace whatever a block takes; no clock and no block time is assumed.
    /// Read by `Node::issuance_hold_for`, beside DB-122 F6's solvency hold: a custodian attests no NEW issuance while it is true.
    /// Redemption never reads it (the cardinal: a holder always gets out, at the last accepted mark).
    /// AI RESISTANCE: (b) code, enforced by every honest custodian's attestation; a mint needs ≥ 2/3 of them, so it is refused
    ///   whenever the bonded set is the honest majority the price itself already assumes (t < 1/3, `price_mark_tx`).
    /// cons: a price epoch the relays miss entirely holds that ledger's mints until the next mark (the deposit waits inside its
    ///   3-day mint window and is reclaimable after a week, `btc_tx::DEPOSIT_MINT_WINDOW_CONFS`); one map read per attestation.
    #[must_use]
    pub fn mint_price_stale(&self, asset_id: u32, current_epoch: u64) -> bool {
        if !Self::is_bridge_ledger(asset_id) {
            return false;
        }
        ledger_asset_checked(asset_id)
            .and_then(|a| self.price_marks.get(&a))
            .is_some_and(|m| m.epoch_id.saturating_add(1) < current_epoch)
    }

    /// Does a mint on `asset_id` take its coin from a deposit address the custody script must control: a bridge ledger's, or a coin ledger's?
    #[must_use]
    pub fn is_custody_funded(asset_id: u32) -> bool {
        Self::is_bridge_ledger(asset_id) || Self::is_coin_ledger(asset_id)
    }

    /// Is `asset_id` funded by Bitcoin deposits (co-signed sweeps, the Bitcoin solvency hold)?
    #[must_use]
    pub fn is_bitcoin_funded(asset_id: u32) -> bool {
        matches!(ledger_asset_checked(asset_id), Some(NATIVE_PEG_ASSET_ID | COIN_BTC_ASSET_ID))
    }

    /// ⛔ THE UNIT CLASS: does a deposit at `reserve_address` belong on ledger `asset_id`? A Monero address only on Monero's
    /// ledger, any other address only on the native one; a ledger the bridge does not fund is not judged here.
    #[must_use]
    pub fn deposit_unit_matches(asset_id: u32, reserve_address: &str) -> bool {
        let asset = ledger_asset(asset_id);
        if Self::is_coin_ledger(asset_id) {
            return (asset == COIN_XMR_ASSET_ID) == crate::bridge::is_monero_address(reserve_address);
        }
        !Self::is_bridge_ledger(asset_id) || (asset == XMR_PEG_ASSET_ID) == crate::bridge::is_monero_address(reserve_address)
    }

    /// ⭐ §19.5b — the bridge ledger a deposit at `reserve_address` mints on: Monero's own for a Monero address, the native one
    /// otherwise. The ONE spelling every custodian reads from its SEALED leg (the public request and proposal name asset 0 for
    /// both, so no relaying node learns which coin is coming in).
    #[must_use]
    pub fn bridge_ledger_of(reserve_address: &str) -> u32 {
        if crate::bridge::is_monero_address(reserve_address) {
            XMR_PEG_ASSET_ID
        } else {
            NATIVE_PEG_ASSET_ID
        }
    }

    /// The ledger a cash-out to `redeem_to` pays from: Monero's own for a Monero destination, the native one otherwise.
    #[must_use]
    pub fn peg_out_asset_for(redeem_to: &str) -> u32 {
        if let Some(coin) = crate::cashout_ticket::coin_ledger_of(redeem_to) {
            return coin;
        }
        if Self::is_monero_destination(redeem_to) {
            XMR_PEG_ASSET_ID
        } else {
            NATIVE_PEG_ASSET_ID
        }
    }

    /// ⭐ THE PRICED VALUE OF A DEPOSIT — `units * price / PRICE_SCALE`, the ONE conversion from an external
    /// asset's atomic units into the USDm-atomic units solvency is measured in.
    ///
    /// `None` when the chain has set no mark for this asset. That is the FAIL-CLOSED answer and the whole
    /// point: a caller with no price must refuse to mint rather than fall back to counting atomic units,
    /// which is precisely the bug DB-124 names. There is deliberately no default, no 1:1 fallback and no
    /// "assume parity" branch — any of those would silently restore the inflation.
    ///
    /// ⛔ THE MARK'S AGE IS NOT CHECKED HERE, AND THAT IS DELIBERATE. Freshness is the MINT's business; a
    /// REDEMPTION must price against whatever the last accepted mark is, however old. Gating withdrawal on
    /// a fresh quorum would let the bonded set trap a holder's funds by simply not attesting, which the
    /// cardinal ("the bond must NEVER block genuine issuance or withdrawal") forbids.
    /// §BR-1 / §BR-4: the external atomic units (sats for BTC) a burn of `burn_atomic` USDm releases at the chain's
    /// certified mark — `burn × PRICE_SCALE / price`, floored — or `None` while the chain stands on no mark for the asset
    /// (fail closed, legibly: nothing is priced by guess). Until 2026-10-28 the exit lane released `burn` units 1:1, so a
    /// USDm atomic unit bought a sat; the redemption floor (spec §1.3: 1 USDm redeems $1 of BTC) is this function.
    #[must_use]
    pub fn release_sats_for_burn(&self, asset_id: u32, burn_atomic: u128) -> Option<u128> {
        let price = self.reference_price(asset_id)?;
        if price == 0 {
            return None;
        }
        Some(burn_atomic.saturating_mul(crate::liquidation::PRICE_SCALE) / price)
    }

    /// ⭐ DB-470 / §19.4 — THE RELEASE A LADDER BURN MAY TAKE: the $1 release while the reserve covers it, else the burn's
    /// EXACT pro-rata share `burn × reserve / minted` — on every ledger. A pro-rata redemption leaves `reserve / minted`
    /// unchanged, so every piece of one rung in an under-100 % batch is paid the same amount (the crowd survives a crash);
    /// rounding down to the satoshi ladder is gone with that ladder. `None` when nothing positive fits or an operand overflows.
    #[must_use]
    pub fn release_within_share_for(_asset_id: u32, release: u128, burn: u128, reserve: u128, minted: u128) -> Option<u128> {
        let share_num = burn.checked_mul(reserve)?;
        if release.checked_mul(minted)? <= share_num {
            return Some(release);
        }
        Some(share_num / minted.max(1)).filter(|r| *r > 0)
    }

    /// ⭐⭐ DB-124 (lane funds 2026-10-29) — THE PRICED BACKING every peg carrier proves and every door verifies: `ratio` at the
    /// asset's reference price (the 7-day TWAP). `None` while the chain has never priced the asset — no mint and no release
    /// proves then (fail-closed on the item; the custodian re-proves at the next publish, `peg_lane_completions_due`).
    #[must_use]
    pub fn backing(&self, asset_id: u32, ratio_bps: u64) -> Option<usdm_decider::confidential_solvency::Backing> {
        let price = self.reference_price(asset_id).filter(|p| *p > 0)?;
        Some(usdm_decider::confidential_solvency::Backing { ratio_bps, price })
    }

    /// ⭐ §BR-4 (spec §1 item 7) — THE PRICE MINTS AND REDEMPTIONS ARE JUDGED AT: the asset's 7-day time-weighted average
    /// over its closed price epochs (`twap7`), never the live mark — so one epoch's quote cannot swing a mint or a redemption.
    /// It is the standing mark only while no epoch has closed (launch). `None` while the chain has never priced the asset.
    #[must_use]
    pub fn reference_price(&self, asset_id: u32) -> Option<u128> {
        // §18.14: a coin ledger's unit IS its coin — one atom for one atom, whatever a dollar is worth, so no relay can stop it.
        // A registered WRAPPED asset is the same: a wrapped note is one atom of the coin its deposits arrive in (its minted
        // total counts wrapped notes, never USDm), so its backing, its mint cover and its release are unit for unit. Read
        // off its own mark it had none, so no wrapped mint ever proved or was signed (MEASURED 2026-11-08, real nodes:
        // wrapped.py, both custodians refused under DB-124, then the solvency transition did not prove).
        if Self::is_coin_ledger(asset_id) || (!Self::is_bridge_ledger(asset_id) && self.wrapped_assets.contains_key(&asset_id)) {
            return Some(crate::liquidation::PRICE_SCALE);
        }
        // SAFE AT SCALE: a vault's bridge ledger is priced by its ASSET's mark — one mark per coin, whatever vault holds it
        self.twap7(ledger_asset_checked(asset_id)?)
    }

    /// The mint ratio ledger `id` is held to: the native ledger's own, a registered ledger's, or — for a vault's ledger —
    /// its ASSET's. `None` for a ledger the chain does not know.
    #[must_use]
    pub fn ledger_ratio_bps(&self, id: u32) -> Option<u32> {
        match ledger_asset_checked(id)? {
            NATIVE_PEG_ASSET_ID => Some(self.ratio_bps),
            asset => self.wrapped_assets.get(&asset).map(|a| a.ratio_bps),
        }
    }

    pub fn priced_value(&self, asset_id: u32, units: u128) -> Option<u128> {
        let price = self.reference_price(asset_id)?;
        Some(units.saturating_mul(price) / crate::liquidation::PRICE_SCALE)
    }

    /// The registered over-collateralization ratio for a wrapped asset (10000 stablecoin / 15000 volatile), or None
    /// if the asset is not registered. A stablecoin's 10000 IS the exemption from the 150% (proven by the tamper test).
    /// ⛔ THE COLLATERAL-RATIO CENSUS — every registered wrapped asset and the ratio it mints against.
    ///
    /// This is the ONE read that makes the `POST /register_wrapped_asset` hole VISIBLE to the harness.
    /// That route calls `register_wrapped_asset(asset_id, ratio_bps)` with no threshold, no governance
    /// vote and no block, and `ratio_bps` decides how much USDm may be minted against an asset —
    /// setting a volatile asset to 10000 removes the 150% buffer, so 50% more USDm is mintable against
    /// the same collateral. Until now nothing could SEE that, because a locally-set ratio looks
    /// identical to a chain-set one from inside the node.
    ///
    /// A node fed only blocks derives the ratios the CHAIN set. Any party that disagrees is minting
    /// against a number a socket supplied.
    ///
    /// cons: one walk of a map bounded by the number of REGISTERED ASSETS — a governance-scale figure
    /// fixed by the chain, with no term in height, blocks or notes. Ids and ratios are chain-public by
    /// definition (every node must agree on them to agree on solvency); no amount or owner is exposed.
    /// ⛔ THE PRICE-MARK CENSUS — every asset and the mark it is priced at, with the epoch that set it.
    ///
    /// The read that makes a locally-set price VISIBLE. A mark decides how much USDm may be issued per
    /// unit of collateral, so a node standing on a different mark from the chain is measuring solvency
    /// against a number the chain never set — the identical argument [`Self::collateral_ratio_census`]
    /// carries for `ratio_bps`, on the field that was outright missing until DB-124.
    ///
    /// cons: one walk of a map bounded by the REGISTERED ASSET set — governance scale, no term in height,
    /// blocks or notes. Prices are chain-public by definition; no amount or owner is exposed.
    pub fn price_mark_census(&self) -> Vec<(u32, u128, u64)> {
        self.price_marks.iter().map(|(id, m)| (*id, m.price, m.epoch_id)).collect()
    }

    pub fn collateral_ratio_census(&self) -> Vec<(u32, u32)> {
        self.wrapped_assets
            .iter()
            .map(|(id, a)| (*id, a.ratio_bps))
            .collect()
    }

    /// ⭐ THE REQUIRED OVER-COLLATERALIZATION RATIO FOR ONE ASSET — native or wrapped, ONE definition.
    ///
    /// The native peg uses its own `ratio_bps`; a registered wrapped asset uses the one its registration
    /// attested (10000 for a vetted stablecoin, 15000 for a volatile asset). An UNREGISTERED wrapped asset
    /// has no ratio and returns None — a caller must refuse rather than guess, which is the same
    /// fail-closed contract `priced_value` carries for a missing price mark.
    pub fn required_ratio_bps(&self, asset_id: u32) -> Option<u32> {
        self.ledger_ratio_bps(asset_id)
    }

    /// ⛔⛔⛔ DB-124 — IS THIS MINT COVERED BY THE DEPOSIT'S **PRICED** VALUE AT THE REQUIRED RATIO?
    ///
    /// `deposit_atomic * price / PRICE_SCALE >= mint * ratio_bps / 10000`, evaluated without division so no
    /// rounding rule can be disagreed about across nodes.
    ///
    /// `false` when the chain has attested NO price for this asset, and that is the point: before this
    /// existed the peg compared a deposit's ATOMIC COUNT against the mint, so one piconero backed one USDm
    /// atomic unit and 1 XMR could mint ~$6.67 BILLION against ~$150 of collateral. There is deliberately
    /// no 1:1 fallback — a fallback IS the bug.
    #[must_use]
    pub fn mint_is_covered_by_priced_deposit(&self, asset_id: u32, deposit_atomic: u128, mint: u128) -> bool {
        let (Some(priced), Some(ratio)) =
            (self.priced_value(asset_id, deposit_atomic), self.required_ratio_bps(asset_id))
        else {
            return false;
        };
        priced.saturating_mul(10_000) >= mint.saturating_mul(ratio as u128)
    }

    pub fn wrapped_asset_ratio_bps(&self, asset_id: u32) -> Option<u32> {
        self.wrapped_assets.get(&asset_id).map(|a| a.ratio_bps)
    }

    /// The wrapped asset's persisted confidential commitments (opaque digests; no value learned). None if unregistered.
    pub fn wrapped_asset_commits(&self, asset_id: u32) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        // one reader for every non-native ledger: a vault's ledger nothing has moved answers its genesis pair
        if asset_id == NATIVE_PEG_ASSET_ID {
            return None;
        }
        self.psm_commits(asset_id).map(|(r, m, _)| (r, m))
    }

    /// CUSTODIAN wrapped-asset MINT orchestration — the per-asset mirror of [`Self::orchestrate_peg_in`]: from the
    /// custodian's transient opening, prove a `+deposit / +mint` transition for `asset_id` that keeps >= THAT asset's
    /// `ratio_bps` backing (UNPROVABLE otherwise — no under-collateralized wrap; no inflation). Volatile assets need
    /// 150%, a stablecoin mints at 1:1. `None` if the asset is unregistered, the mint over-issues vs the ratio, or
    /// the passed opening does not match the asset's persisted commitments (fail-closed).
    pub fn orchestrate_wrapped_mint(
        &self,
        asset_id: u32,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        // DB-80b: the requester's mint-delta blind; the carrier opens `delta_commit = commit(mint, d_blind)`
        d_blind: crate::spend_frontier::Digest4,
    ) -> Option<(
        Vec<u8>,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
    )> {
        use usdm_decider::confidential_solvency as cs;
        // ⛔ the unit class: a bridge ledger's minted total counts USDm only — it mints through the PegIn door, never a wrapped note
        if Self::is_bridge_ledger(asset_id) {
            return None;
        }
        let (ratio_bps, reserve_commit, minted_commit) = self.wrapped_state(asset_id)?;
        let (_nrv, nr_blind, _nmv, nm_blind) =
            Self::opening_after_wrapped_mint(r_val, r_blind, m_val, m_blind, deposit, mint, &d_blind);
        let (carrier, commits_d) = cs::prove_peg_in_carrier_delta(
            u256_from_u128(r_val),
            u256_from_u128(m_val),
            u256_from_u128(deposit),
            u256_from_u128(mint),
            r_blind,
            m_blind,
            nr_blind,
            nm_blind,
            d_blind,
            self.backing(asset_id, ratio_bps as u64)?,
        )?;
        let commits = commits_d.base;
        if commits.reserve_commit != reserve_commit || commits.minted_commit != minted_commit {
            return None;
        }
        Some((
            carrier,
            commits.new_reserve_commit,
            commits.new_minted_commit,
            nr_blind,
            nm_blind,
            commits_d.delta_commit,
        ))
    }

    /// Verify a wrapped-asset mint carrier against `asset_id`'s persisted commitments + ratio (the consensus gate,
    /// mirror of `verify_confidential_peg_in`), and on success ADVANCE the asset's digests. Fail-closed (returns
    /// false, mutates NOTHING) if the asset is unregistered or the carrier does not verify — no inflation.
    pub fn verify_and_apply_wrapped_mint(
        &mut self,
        asset_id: u32,
        carrier: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
    ) -> bool {
        if Self::is_bridge_ledger(asset_id) {
            return false; // a bridge ledger mints USDm through the PegIn door, never a wrapped note
        }
        let Some((ratio, old_rc, old_mc)) = self.wrapped_state(asset_id) else { return false };
        // DB-80b: the carrier opens FIVE commitments — the transition and the committed mint delta the
        // asset-mint-validity carrier binds the note to. No amount is a public input.
        let Some(backing) = self.backing(asset_id, ratio as u64) else { return false };
        if !usdm_decider::confidential_solvency::verify_peg_in_carrier_delta(
            carrier,
            backing,
            old_rc,
            old_mc,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
        ) {
            return false;
        }
        let Some(a) = self.psm_entry_mut(asset_id) else { return false };
        a.reserve_commit = new_reserve_commit;
        a.minted_commit = new_minted_commit;
        a.reserve_hwm_commit = new_reserve_commit; // per-asset HWM maintenance (see the native path's note)
        true
    }

    /// `(ratio, reserve commit, minted commit)` of a NON-NATIVE ledger a wrapped-mint door acts on: a registered asset's
    /// own, or — SAFE AT SCALE — a vault's ledger of a registered asset (the asset's ratio, the vault's own pair, its
    /// genesis pair until something moves it). `None` for the native id and for a ledger the chain does not know.
    fn wrapped_state(&self, id: u32) -> Option<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        if id == NATIVE_PEG_ASSET_ID {
            return None;
        }
        let ratio = self.ledger_ratio_bps(id)?;
        let (reserve, minted, _) = self.psm_commits(id)?;
        Some((ratio, reserve, minted))
    }

    /// The IonSwap CONFIDENTIAL WRAPPED-MINT wire path — the exact tally-gated mirror of [`Self::peg_in_confidential`],
    /// but minting a WRAPPED asset (wBTC/wETH/wDAI) instead of USDm. The custodian supplies the WHIR-bound wrapped-mint
    /// carrier + the NEW committed pair for `asset_id`; the ledger (1) rejects a replayed foreign deposit (per-asset,
    /// domain-namespaced so a wrapped deposit id can never collide with a USDm one or a different asset's), (2) requires
    /// the ≥2/3 bonded-validator ML-DSA-65 threshold over a message that BINDS the asset id + deposit id + the new
    /// commitment pair + recipient (so an attestation for one asset/deposit can't be replayed to another), and (3)
    /// verifies + advances the asset's confidential-solvency pair at THAT asset's ratio (150% volatile / 100% stable —
    /// an under-collateralized wrap is UNPROVABLE). Learns NO deposit/mint value. A rejected mint mutates NOTHING.
    ///
    /// NOTE — value-at-risk bond backstop: USDm's `peg_in_confidential` also gates on a bond ≥ 2× the reserve, denominated
    /// in the native bond unit. A wrapped asset's reserve is in the FOREIGN asset's own units (BTC sats, ETH wei), so a
    /// unit-matched backstop needs the per-asset bridge-value bond ([[project_92_tvl_bond_model]] / task #92's oracle);
    /// bolting the native-unit backstop onto a foreign-unit commit would be an UNSOUND unit mismatch, so it is the tracked
    /// follow-on — not silently dropped. This brick's soundness floor is the three gates above (confirmed foreign deposit
    /// at the node's deposit gate + ≥2/3 threshold + the ratio-bound solvency carrier).
    #[allow(clippy::too_many_arguments)]
    pub fn wrapped_mint_confidential(
        &mut self,
        asset_id: u32,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        if self.wrapped_state(asset_id).is_none() || Self::is_bridge_ledger(asset_id) {
            return PegOutcome::BadRequest; // asset not registered (or a bridge ledger, which mints USDm through PegIn only)
        }
        let dep_key = wrapped_deposit_key(asset_id, &deposit_id);
        if self.wrapped_deposit_minted(asset_id, &deposit_id) {
            return PegOutcome::Replay; // this foreign deposit already minted — this asset or any other — never twice
        }
        let msg = wrapped_mint_confidential_msg(
            asset_id,
            &deposit_id,
            &new_reserve_commit,
            &new_minted_commit,
            &delta_commit,
            &recipient,
        );
        if !Self::wrapped_mint_signed(asset_id, quorum, verifier, &msg, attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        // verify + advance the asset's confidential-solvency pair at its own ratio (fail-closed on a bad carrier)
        if !self.verify_and_apply_wrapped_mint(
            asset_id,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
        ) {
            return PegOutcome::BadRequest;
        }
        self.confidential_deposit_ids.insert(dep_key);
        self.applied_ids.push((dep_key, 0));
        self.confidential_deposit_ids.insert(deposit_id);
        self.applied_ids.push((deposit_id, 0));
        PegOutcome::ConfidentialMinted
    }

    /// The node's persisted CONFIDENTIAL SOLVENCY commitments — the value-hiding Poseidon digests of the reserve
    /// total and the circulating total. Opaque 4-limb digests; a re-executing node reads NO value from them.
    /// §DD interim: the one-time ids the last applied block(s) inserted, drained.
    /// §DD-b: install the one-time ids a certified bundle carries (the chain applied them) so this node
    /// refuses their replay exactly as a node that applied the blocks would. CHAIN-PUBLISH-REVIEWED: the
    /// adopt half of a decider-certified bundle; nothing local is authored.
    pub fn adopt_one_time_ids(&mut self, ids: &[([u8; 32], u8)]) {
        for (id, kind) in ids {
            match kind {
                0 => {
                    self.confidential_deposit_ids.insert(*id);
                }
                1 => {
                    self.spent_burns.insert(*id);
                }
                2 => {
                    self.released.insert(*id);
                }
                _ => {
                    self.liquidated.insert(*id);
                }
            }
        }
    }

    pub fn take_applied_one_time_ids(&mut self) -> Vec<([u8; 32], u8)> {
        std::mem::take(&mut self.applied_ids)
    }

    /// §DD interim: forget a one-time id whose transition is NOT on the chain this node now follows (the
    /// block that applied it was abandoned by a jump). Local set = f(followed chain) again.
    /// CHAIN-PUBLISH-REVIEWED: the adopt half — removing what the certified chain does not contain.
    pub fn forget_one_time_id(&mut self, id: &[u8; 32], kind: u8) {
        match kind {
            0 => {
                self.confidential_deposit_ids.remove(id);
            }
            1 => {
                self.spent_burns.remove(id);
            }
            2 => {
                self.released.remove(id);
            }
            _ => {
                self.liquidated.remove(id);
            }
        }
    }

    /// §DD: install a certified view after a jump. The commitments and parameters become the chain's; the
    /// one-time-use id sets stay as they are (a jumper's are incomplete by construction — kill list §DD
    /// names the accumulator they must move into).
    /// CHAIN-PUBLISH-REVIEWED: the ADOPT half of a decider-certified bundle — the chain's own state,
    /// verified by the whole-chain certificate and bound by `sync_binding`; nothing local is authored.
    pub fn adopt_certified(
        &mut self,
        reserve: crate::spend_frontier::Digest4,
        minted: crate::spend_frontier::Digest4,
        hwm: crate::spend_frontier::Digest4,
        ratio_bps: u32,
        redeem_floor_bps: u32,
        yield_rate_bps: u32,
    ) {
        self.reserve_commit = reserve;
        self.minted_commit = minted;
        self.reserve_hwm_commit = hwm;
        self.ratio_bps = ratio_bps;
        self.redeem_floor_bps = redeem_floor_bps;
        self.yield_rate_bps = yield_rate_bps;
    }

    pub fn reserve_commit(&self) -> crate::spend_frontier::Digest4 {
        self.reserve_commit
    }
    pub fn minted_commit(&self) -> crate::spend_frontier::Digest4 {
        self.minted_commit
    }

    /// Seed the confidential-solvency commitments at cutover (or genesis): the value-hiding digests of the
    /// genuine current reserve + circulating totals. A generic node receives these opaque digests; it never
    /// receives the totals. Idempotent — sets the persisted pair the peg-in transition then advances.
    pub fn initialize_solvency_commitments(
        &mut self,
        reserve_commit: crate::spend_frontier::Digest4,
        minted_commit: crate::spend_frontier::Digest4,
    ) {
        self.reserve_commit = reserve_commit;
        self.minted_commit = minted_commit;
        // Seeding the ledger's genuine current reserve ALSO seeds the high-water mark: at cutover the committed
        // reserve IS the collateral really held, so it is exactly the bound a later liquidation re-mark may not
        // exceed. Seeding it here (rather than leaving `[0;4]`) is what keeps the door usable after a cutover
        // while still refusing an up-mark past real collateral.
        self.reserve_hwm_commit = reserve_commit;
    }

    /// #75 brick 3d — the CONFIDENTIAL peg-in solvency gate. The node VERIFIES the custodian threshold's
    /// WHIR-bound [`usdm_decider::confidential_solvency::verify_peg_in_carrier`] proof — conservation (no hidden
    /// issuance) + 150% backing of the NEW total state, all proven over HIDDEN 256-bit amounts whose openings are
    /// cryptographically bound to the commitments — against the node's OWN persisted OLD commitments + the block's
    /// claimed NEW commitments. It NEVER recomputes or learns a total. A proof built for any other (old/new)
    /// commitment pair is rejected (the commitment-pin constraint AND the transcript statement bind both diverge).
    /// This is the verify path that replaces the plaintext `is_solvent` RECOMPUTE.
    #[must_use]
    pub fn verify_confidential_peg_in(
        &self,
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
    ) -> bool {
        self.verify_confidential_peg_in_for(carrier_bytes, new_reserve_commit, new_minted_commit, delta_commit, None)
    }

    /// ⭐ DB-470 — the backing a MINT proves of its OWN deposit: the PSM's ratio at the chain's reference price, or a debt unit's
    /// 110 % at its band's floor (`debt_units::collateral_sats` is exactly that rule). `None` while the rule cannot form (no
    /// price, or a unit with no such size or band) — fail-closed on the item.
    #[must_use]
    pub fn mint_backing(&self, unit: Option<&crate::debt_units::UnitTerms>) -> Option<usdm_decider::confidential_solvency::Backing> {
        match unit {
            None => self.backing(NATIVE_PEG_ASSET_ID, self.ratio_bps as u64),
            // A unit's rule, EXACT: its own deposit covers its whole collateral `c` (the 110 % floor rounded up to a payout piece,
            // `debt_units::collateral_sats`) — the amount its close releases, so no close can release a sat its open did not
            // bring. Written in the gate's form `deposit·BPS·price ≥ mint·ratio·SCALE` with `price = U` and
            // `ratio = c·BPS / SCALE` (an integer: `c` is a multiple of 10,000 sats and SCALE is 10^6): with `mint = U` it is
            // exactly `deposit ≥ c`.
            Some(t) => {
                let u = t.unit_atomic()?;
                let c = crate::debt_units::collateral_sats(usize::from(t.l), usize::from(t.k));
                let scale = u128::from(usdm_decider::confidential_solvency::LIQ_PRICE_SCALE);
                let num = c.checked_mul(10_000)?;
                if num % scale != 0 {
                    return None;
                }
                Some(usdm_decider::confidential_solvency::Backing { ratio_bps: u64::try_from(num / scale).ok()?, price: u })
            }
        }
    }

    /// [`Self::mint_backing`] on bridge ledger `asset_id`: the native ledger's (a debt unit's rule included), or Monero's own
    /// ratio at the XMR reference price. A debt unit rides only the native ledger; `None` otherwise (fail closed).
    #[must_use]
    pub fn mint_backing_for(&self, asset_id: u32, unit: Option<&crate::debt_units::UnitTerms>) -> Option<usdm_decider::confidential_solvency::Backing> {
        if asset_id == NATIVE_PEG_ASSET_ID {
            return self.mint_backing(unit);
        }
        if unit.is_some() || !Self::is_bridge_ledger(asset_id) {
            return None;
        }
        // a vault's own bridge ledger mints at its asset's ratio and price (`ledger_ratio_bps`, `reference_price`)
        self.backing(asset_id, u64::from(self.ledger_ratio_bps(asset_id)?))
    }

    /// ⭐ THE LEDGER A PEG-IN MINTS ON, READ FROM ITS OWN PROOF — the peg-in mirror of [`Self::peg_out_psm`]: the bridge
    /// ledger (native or Monero's) whose `(reserve, minted)` pair the solvency carrier verifies against at that ledger's own
    /// mint backing. The `PegIn` object names no asset; distinct genesis blinds ([`psm_genesis_blinds`]) and secret later
    /// blinds leave at most one ledger whose pair verifies. NEW-DOOR CHECKLIST (§9.6): the caller checks the replay set and
    /// the ≥ 2/3 bonded signatures first; value enters only through the verified carrier at THAT ledger's mark (a Monero
    /// deposit priced on the satoshi ledger does not verify there); work ≤ one verify per bridge ledger (two).
    #[must_use]
    #[cfg(test)]
    pub fn peg_in_psm(
        &self,
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<u32> {
        [NATIVE_PEG_ASSET_ID, XMR_PEG_ASSET_ID].into_iter().find(|id| {
            let Some((reserve, minted, _)) = self.psm_commits(*id) else { return false };
            let Some(backing) = self.mint_backing_for(*id, unit) else { return false };
            usdm_decider::confidential_solvency::verify_peg_in_carrier_delta(
                carrier_bytes,
                backing,
                reserve,
                minted,
                new_reserve_commit,
                new_minted_commit,
                delta_commit,
            )
        })
    }

    /// The peg-in carrier verified at the mint's own backing ([`Self::mint_backing`]).
    #[must_use]
    pub fn verify_confidential_peg_in_for(
        &self,
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> bool {
        // DB-80: the carrier opens FIVE commitments — the four state commitments and the committed mint
        // delta the mint-validity carrier binds the note to. No amount is a public input.
        // DB-124: verified at the chain's reference price at this fold step (the custodian proved at its own; a TWAP that moved
        // in between refuses this copy and the custodian re-proves at the next publish).
        self.verify_cover(true, carrier_bytes, (new_reserve_commit, new_minted_commit), delta_commit, unit).is_some()
    }

    /// Advance the persisted confidential-solvency commitments to the proof's NEW digests. MUST be called ONLY
    /// after [`Self::verify_confidential_peg_in`] accepts — the node swaps the opaque digest pair and learns no
    /// value. This is the confidential analogue of `minted_usdm += mint` / `reserve += deposit`, with no total
    /// ever materialized in consensus state.
    pub fn apply_confidential_peg_in(
        &mut self,
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
    ) {
        self.reserve_commit = new_reserve_commit;
        self.minted_commit = new_minted_commit;
        // HIGH-WATER MARK maintenance — the ONE place the HWM moves. Every caller of this function is a
        // NON-liquidation value path (peg-in adds a real deposit, peg-out removes a real release), and on both the
        // committed reserve IS the collateral genuinely deposited-and-not-yet-released. Tracking it here makes the
        // HWM a CONSERVATIVE upper bound: a peg-in raises it by exactly the deposit, a peg-out lowers it by exactly
        // the release (tighter than the true historical high — never looser), and the LIQUIDATION door never
        // touches it, so after a re-mark `reserve < HWM` and a later re-mark is bounded by real collateral.
        self.reserve_hwm_commit = new_reserve_commit;
    }

    /// The custodian OPENING after a peg-in of `(deposit, mint)` — `(reserve value, reserve blind, minted value,
    /// minted blind)` — the ONE spelling of the blind chain `orchestrate_peg_in` proves under. Every custodian
    /// that learns the delta (`crate::peg_attest`) advances its private opening with exactly this, so a quorum
    /// stays able to re-derive and attest the next transition from the same chain order.
    /// ⛔⛔ PRIVACY (2026-10-02): `leg_blind` is the op's SEALED blind (the requester's `d_blind`), secret to the requester
    /// and the bonded custodians. Without it the chain started at the PUBLIC genesis blinds and every later blind was
    /// `H(prev, amounts)`: an observer brute-forced each peg-in's mint (the depositor's note value) step by step.
    #[must_use]
    pub fn opening_after_peg_in(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4) {
        (
            r_val.saturating_add(deposit),
            Self::next_op_blind(b"USDMD-PEGIN-RSV-BLIND-v2", &r_blind, leg_blind, deposit, mint),
            m_val.saturating_add(mint),
            Self::next_op_blind(b"USDMD-PEGIN-MNT-BLIND-v2", &m_blind, leg_blind, deposit, mint),
        )
    }

    /// The custodian OPENING after a peg-out of `(release, burn)` — the peg-out twin of
    /// [`Self::opening_after_peg_in`], the ONE spelling `orchestrate_peg_out` proves under and every custodian
    /// applies when the block carrying the burn grafts.
    /// DB-77: the wrapped-asset blind schedule (`USDMD-WRAP-*`), ONE definition shared by the prove
    /// (`orchestrate_wrapped_mint`), the proposer/attester derivation and the block-apply advance.
    #[must_use]
    pub fn opening_after_wrapped_mint(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4) {
        (
            r_val.saturating_add(deposit),
            Self::next_op_blind(b"USDMD-WRAP-RSV-BLIND-v2", &r_blind, leg_blind, deposit, mint),
            m_val.saturating_add(mint),
            Self::next_op_blind(b"USDMD-WRAP-MNT-BLIND-v2", &m_blind, leg_blind, deposit, mint),
        )
    }
    /// DB-77: the commitments a wrapped mint advances to, from an opening, without proving.
    #[must_use]
    pub fn commits_after_wrapped_mint(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        let (nrv, nr, nmv, nm) = Self::opening_after_wrapped_mint(r_val, r_blind, m_val, m_blind, deposit, mint, leg_blind);
        Self::commits_of_opening(nrv, nr, nmv, nm)
    }
    /// `leg_blind` is the peg-out's SEALED redeem blind (`PegOutDelta::r_blind`), secret to the redeemer and the custodians.
    #[must_use]
    pub fn opening_after_peg_out(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        release: u128,
        burn: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4) {
        (
            r_val.saturating_sub(release),
            Self::next_op_blind(b"USDMD-PEGOUT-RSV-BLIND-v2", &r_blind, leg_blind, release, burn),
            m_val.saturating_sub(burn),
            Self::next_op_blind(b"USDMD-PEGOUT-MNT-BLIND-v2", &m_blind, leg_blind, release, burn),
        )
    }

    /// The ONE advance of a peg total's blind by an op: `H(domain, prev, leg_blind, a, b)`, the op's sealed `leg_blind`
    /// breaking the public-genesis chain (the node's `op_advance_blind` twin for the pool and stake totals).
    pub fn next_op_blind(
        domain: &[u8],
        prev: &crate::spend_frontier::Digest4,
        leg_blind: &crate::spend_frontier::Digest4,
        a: u128,
        b: u128,
    ) -> crate::spend_frontier::Digest4 {
        let mut h = blake3::Hasher::new();
        h.update(domain);
        for x in prev.iter().chain(leg_blind.iter()) {
            h.update(&x.to_le_bytes());
        }
        h.update(&a.to_le_bytes());
        h.update(&b.to_le_bytes());
        usdm_decider::poseidon2_compress::hash32_to_digest(h.finalize().as_bytes())
    }

    /// CUSTODIAN MINT ORCHESTRATION — build the confidential peg-in carrier the depositor's wallet CANNOT (it holds
    /// no reserve secret). The custodian passes its CURRENT private opening — the `r_val`/`m_val` witness value +
    /// `r_blind`/`m_blind`, held off-ledger and passed TRANSIENTLY exactly as a wallet passes a note opening to
    /// prove a spend, NEVER a stored on-ledger counter — and this proves a `ratio`-collateralized `+deposit / +mint`
    /// transition under FRESH blinds. Returns the WHIR carrier + the NEW committed digests (for
    /// [`Self::peg_in_confidential`]) + the new blinds (the custodian folds them into its next opening). `None` if
    /// under-collateralized (UNPROVABLE — no inflation path) or the opening does not match the node's persisted
    /// commitments (a drifted book) → fail-closed.
    /// DB-77: the commitments a peg-in ADVANCES TO, derived from an opening WITHOUT proving — what a
    /// proposer states and an attester re-derives. Before this, both proposer and attester ran the
    /// full WHIR solvency prove (`orchestrate_peg_in`) only to read the two digests off its public
    /// inputs: seconds of lock-held proving per custodian per request. The prove belongs to the ONE
    /// publish; the commitments are a function of the opening alone.
    #[must_use]
    pub fn commits_after_peg_in(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        use usdm_decider::confidential_solvency as cs;
        let (nrv, nr, nmv, nm) = Self::opening_after_peg_in(r_val, r_blind, m_val, m_blind, deposit, mint, leg_blind);
        (
            cs::solvency_commit_256(u256_from_u128(nrv), nr),
            cs::solvency_commit_256(u256_from_u128(nmv), nm),
        )
    }
    /// DB-77: the peg-out twin of [`Self::commits_after_peg_in`].
    #[must_use]
    pub fn commits_after_peg_out(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        release: u128,
        burn: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        use usdm_decider::confidential_solvency as cs;
        let (nrv, nr, nmv, nm) = Self::opening_after_peg_out(r_val, r_blind, m_val, m_blind, release, burn, leg_blind);
        (
            cs::solvency_commit_256(u256_from_u128(nrv), nr),
            cs::solvency_commit_256(u256_from_u128(nmv), nm),
        )
    }
    /// The commitments an opening currently stands at (both digests), for the "does this custodian's
    /// opening open the chain's commitments?" check every proposer and attester runs first.
    #[must_use]
    pub fn commits_of_opening(
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
    ) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        use usdm_decider::confidential_solvency as cs;
        (
            cs::solvency_commit_256(u256_from_u128(r_val), r_blind),
            cs::solvency_commit_256(u256_from_u128(m_val), m_blind),
        )
    }
    /// DB-77: has this foreign deposit already minted this WRAPPED asset (chain state, applied from blocks)?
    #[must_use]
    pub fn wrapped_deposit_minted(&self, asset_id: u32, deposit_id: &[u8; 32]) -> bool {
        // ⛔ ONE FOREIGN DEPOSIT PAYS OUT ONCE, ACROSS EVERY ASSET: the base id is the deposit's own (`deposit_id_for_reserve_address`), so a coin a USDm mint counted is refused
        // here, and a wrapped mint inserts it too, so the USDm door refuses the coin a wrapped mint counted. Keyed per asset alone, one real deposit could mint both.
        self.confidential_deposit_ids.contains(deposit_id) || self.confidential_deposit_ids.contains(&wrapped_deposit_key(asset_id, deposit_id))
    }
    /// DB-77: the VERIFY-ONLY twin of [`Self::wrapped_mint_confidential`] — every gate, no write. The
    /// executor runs this before PUBLISHING the `Class::WrappedMint` object; the ledger moves only when a
    /// block carries it (`apply_chain_wrapped_mint`), on every node alike. Before this the wrapped mint
    /// APPLIED LOCALLY on the executor and pooled afterwards — the §DA local-mutation shape (an executor
    /// whose object never rides a block holds a ledger no peer shares).
    #[allow(clippy::too_many_arguments)]
    pub fn check_wrapped_mint_confidential(
        &self,
        asset_id: u32,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        // ⛔ the unit class: a bridge ledger's minted total counts USDm only — never a wrapped note
        if Self::is_bridge_ledger(asset_id) {
            return PegOutcome::BadRequest;
        }
        let Some((ratio_bps, reserve_commit, minted_commit)) = self.wrapped_state(asset_id) else {
            return PegOutcome::BadRequest;
        };
        if self.wrapped_deposit_minted(asset_id, &deposit_id) {
            return PegOutcome::Replay;
        }
        let msg = wrapped_mint_confidential_msg(
            asset_id,
            &deposit_id,
            &new_reserve_commit,
            &new_minted_commit,
            &delta_commit,
            &recipient,
        );
        if !Self::wrapped_mint_signed(asset_id, quorum, verifier, &msg, attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        let Some(backing) = self.backing(asset_id, ratio_bps as u64) else {
            eprintln!("[wrapped-mint] ⛔ not published: the asset's backing ratio is not representable");
            return PegOutcome::BadRequest;
        };
        if !usdm_decider::confidential_solvency::verify_peg_in_carrier_delta(
            carrier_bytes,
            backing,
            reserve_commit,
            minted_commit,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
        ) {
            eprintln!("[wrapped-mint] ⛔ not published: the solvency carrier does not verify against the asset's chain commitments");
            return PegOutcome::BadRequest;
        }
        PegOutcome::ConfidentialPublished
    }
    #[allow(clippy::too_many_arguments)]
    /// DB-80: the ONE prove of a peg-in, with the mint delta COMMITTED (`d_blind` from the depositor's
    /// sealed request). Returns `(carrier, new_reserve_commit, new_minted_commit, nr_blind, nm_blind,
    /// delta_commit)`; the amount is a private witness of the carrier and nothing else.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn orchestrate_peg_in(
        &self,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        d_blind: crate::spend_frontier::Digest4,
    ) -> Option<(
        Vec<u8>,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
    )> {
        self.orchestrate_peg_in_for(r_val, r_blind, m_val, m_blind, deposit, mint, d_blind, None)
    }

    /// The custodian's peg-in prove at the mint's own backing ([`Self::mint_backing`]) — the single-ledger carrier, kept for
    /// the carrier-level pins only (every door verifies the §19.5b cover, [`Self::orchestrate_cover`]).
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn orchestrate_peg_in_for(
        &self,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        d_blind: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<(
        Vec<u8>,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
    )> {
        self.orchestrate_peg_in_at(NATIVE_PEG_ASSET_ID, r_val, r_blind, m_val, m_blind, deposit, mint, d_blind, unit)
    }

    /// The custodian's peg-in prove on bridge ledger `asset_id` (the native one, or Monero's own) at that mint's backing
    /// ([`Self::mint_backing_for`]) — one blind schedule for every bridge ledger (`opening_after_peg_in`).
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn orchestrate_peg_in_at(
        &self,
        asset_id: u32,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        deposit: u128,
        mint: u128,
        d_blind: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<(
        Vec<u8>,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
    )> {
        use usdm_decider::confidential_solvency as cs;
        if !Self::is_bridge_ledger(asset_id) {
            return None;
        }
        let (_nrv, nr_blind, _nmv, nm_blind) =
            Self::opening_after_peg_in(r_val, r_blind, m_val, m_blind, deposit, mint, &d_blind);
        let (carrier, commits) = cs::prove_peg_in_carrier_delta(
            u256_from_u128(r_val),
            u256_from_u128(m_val),
            u256_from_u128(deposit),
            u256_from_u128(mint),
            r_blind,
            m_blind,
            nr_blind,
            nm_blind,
            d_blind,
            self.mint_backing_for(asset_id, unit)?,
        )?;
        let (reserve_commit, minted_commit, _) = self.psm_commits(asset_id)?;
        if commits.base.reserve_commit != reserve_commit || commits.base.minted_commit != minted_commit {
            return None;
        }
        Some((
            carrier,
            commits.base.new_reserve_commit,
            commits.base.new_minted_commit,
            nr_blind,
            nm_blind,
            commits.delta_commit,
        ))
    }

    /// ⭐⭐ §19.5b — THE BLIND THE LEDGER THAT DOES NOT MOVE STEPS UNDER: derived from the peg's own sealed leg blind (every
    /// custodian holds it) and the ledger, so each custodian advances its opening of BOTH bridge ledgers alike, and the
    /// non-moving ledger's new pair is as unguessable as the moving one's.
    #[must_use]
    pub fn cover_leg_blind(asset_id: u32, leg_blind: &crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
        let mut h = blake3::Hasher::new_derive_key("USDMD-COVER-LEG-BLIND-v1");
        h.update(&asset_id.to_le_bytes());
        h.update(&crate::spend_frontier::digest_to_lane_bytes(leg_blind));
        crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
    }

    /// ⭐⭐ §19.5b — EVERY BRIDGE LEDGER'S OPENING AFTER A PEG on `mover` (in [`BRIDGE_LEDGERS`] order): the mover by the peg's
    /// deltas `(a, b)` under its leg blind (`(deposit, mint)` for a peg-in, `(release, burn)` for a peg-out), the other by zero
    /// under [`Self::cover_leg_blind`]. The ONE schedule the prover, every attestor and the block-apply advance all follow.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn openings_after_cover(
        peg_in: bool,
        mover: u32,
        openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
        a: u128,
        b: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2] {
        Self::openings_after_cover_at(0, peg_in, mover, openings, a, b, leg_blind)
    }

    /// [`Self::openings_after_cover`] for the bridge ledgers of vault `vault` ([`bridge_ledgers_of`]); `mover` is the
    /// ASSET that moved (`NATIVE_PEG_ASSET_ID` or `XMR_PEG_ASSET_ID`). The ledger that does not move steps under the blind
    /// of its OWN id, so two vaults' still ledgers never step alike.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn openings_after_cover_at(
        vault: u32,
        peg_in: bool,
        mover: u32,
        openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
        a: u128,
        b: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2] {
        let ledgers = bridge_ledgers_of(vault);
        core::array::from_fn(|i| {
            let (rv, rb, mv, mb) = openings[i];
            let id = ledgers[i];
            let (da, db, leg) = if BRIDGE_LEDGERS[i] == mover { (a, b, *leg_blind) } else { (0, 0, Self::cover_leg_blind(id, leg_blind)) };
            if peg_in {
                Self::opening_after_peg_in(rv, rb, mv, mb, da, db, &leg)
            } else {
                Self::opening_after_peg_out(rv, rb, mv, mb, da, db, &leg)
            }
        })
    }

    /// ⭐⭐ §19.5b — THE ONE PAIR a peg's header, its signed statement and its proposal carry: each lane the Poseidon pair of
    /// the two bridge ledgers' post commitments (reserve lane, minted lane). It binds all four without naming which moved.
    #[must_use]
    pub fn cover_header_pair(posts: &[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        (
            usdm_decider::whir_rec_block::poseidon_pair(posts[0].0, posts[1].0),
            usdm_decider::whir_rec_block::poseidon_pair(posts[0].1, posts[1].1),
        )
    }

    /// The post pairs of every bridge ledger after the openings move as `after` says.
    #[must_use]
    pub fn cover_posts(after: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2]) -> [(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2] {
        core::array::from_fn(|i| Self::commits_of_opening(after[i].0, after[i].1, after[i].2, after[i].3))
    }

    /// ⭐ §19.5b — THE BACKINGS a cover is proven and verified at, in [`BRIDGE_LEDGERS`] order, from chain state alone (so the
    /// verifier needs no hint of which ledger moved): a peg-in at each ledger's mint backing (a debt unit's terms ride the
    /// native ledger only), a peg-out at the redeem floor. A ledger the chain has never priced backs nothing, so it cannot be
    /// the mover; its zero leg is checked at a unit-price placeholder (any backing admits a zero transition).
    #[must_use]
    pub fn cover_backings(&self, peg_in: bool, unit: Option<&crate::debt_units::UnitTerms>) -> Option<[usdm_decider::confidential_solvency::Backing; 2]> {
        let floor = u64::from(self.redeem_floor_bps);
        let of = |id: u32| -> Option<usdm_decider::confidential_solvency::Backing> {
            if peg_in {
                self.mint_backing_for(id, if id == NATIVE_PEG_ASSET_ID { unit } else { None })
            } else {
                self.backing(id, floor)
            }
        };
        let native = of(NATIVE_PEG_ASSET_ID)?;
        let xmr = match of(XMR_PEG_ASSET_ID) {
            Some(b) => b,
            None => usdm_decider::confidential_solvency::Backing::at_unit_price(floor),
        };
        Some([native, xmr])
    }

    /// The bridge ledgers' CURRENT pairs, in [`BRIDGE_LEDGERS`] order.
    fn cover_currents(&self) -> Option<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]> {
        self.cover_currents_at(0)
    }

    /// The CURRENT pairs of vault `vault`'s two bridge ledgers ([`bridge_ledgers_of`]).
    fn cover_currents_at(&self, vault: u32) -> Option<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]> {
        let [native, xmr] = bridge_ledgers_of(vault);
        let n = self.psm_commits(native)?;
        let x = self.psm_commits(xmr)?;
        Some([(n.0, n.1), (x.0, x.1)])
    }

    /// ⭐⭐ §19.5b — THE CUSTODIAN'S COVER PROVE: a peg on `mover` from this custodian's openings of BOTH bridge ledgers. Returns
    /// the object's carrier bytes (a [`CoverBlob`]: the proof and both post pairs), the header pair ([`Self::cover_header_pair`])
    /// and both ledgers' advanced openings. `delta_blind` is the blind of the object's one delta commitment (the mint's
    /// `d_blind`; the burn's `peg_out_burn_blind(leg)`). `None` when an opening does not open the chain's pair, a leg's rule
    /// refuses, or a ledger is unpriced and asked to move.
    #[allow(clippy::too_many_arguments)]
    pub fn orchestrate_cover(
        &self,
        peg_in: bool,
        mover: u32,
        openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
        a: u128,
        b: u128,
        leg_blind: &crate::spend_frontier::Digest4,
        delta_blind: &crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<(Vec<u8>, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2])> {
        self.orchestrate_cover_at(0, peg_in, mover, openings, a, b, leg_blind, delta_blind, unit)
    }

    /// [`Self::orchestrate_cover`] on the bridge ledgers of vault `vault`, from a custodian's openings of THAT vault's
    /// pairs. `mover` is the asset that moves. The same proof, rule and backings: only the pairs it opens are the vault's.
    #[allow(clippy::too_many_arguments)]
    pub fn orchestrate_cover_at(
        &self,
        vault: u32,
        peg_in: bool,
        mover: u32,
        openings: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
        a: u128,
        b: u128,
        leg_blind: &crate::spend_frontier::Digest4,
        delta_blind: &crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<(Vec<u8>, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2])> {
        use usdm_decider::confidential_solvency as cs;
        if !BRIDGE_LEDGERS.contains(&mover) {
            return None;
        }
        // the mover must be priced for real (the placeholder backs only a zero leg)
        if peg_in {
            self.mint_backing_for(mover, if mover == NATIVE_PEG_ASSET_ID { unit } else { None })?;
        } else {
            self.backing(mover, u64::from(self.redeem_floor_bps))?;
        }
        let currents = self.cover_currents_at(vault)?;
        for i in 0..2 {
            if Self::commits_of_opening(openings[i].0, openings[i].1, openings[i].2, openings[i].3) != currents[i] {
                return None;
            }
        }
        let after = Self::openings_after_cover_at(vault, peg_in, mover, openings, a, b, leg_blind);
        let backings = self.cover_backings(peg_in, unit)?;
        let legs: [cs::CoverLeg; 2] = core::array::from_fn(|i| {
            let moves = BRIDGE_LEDGERS[i] == mover;
            cs::CoverLeg {
                reserve: u256_from_u128(openings[i].0),
                minted: u256_from_u128(openings[i].2),
                delta_reserve: u256_from_u128(if moves { a } else { 0 }),
                delta_minted: u256_from_u128(if moves { b } else { 0 }),
                r_blind: openings[i].1,
                m_blind: openings[i].3,
                nr_blind: after[i].1,
                nm_blind: after[i].3,
                backing: backings[i],
            }
        });
        let kind = if peg_in { cs::CoverKind::PegIn } else { cs::CoverKind::PegOut };
        let (carrier, commits) = cs::prove_cover_carrier(kind, &legs, *delta_blind)?;
        let posts: [(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2] =
            core::array::from_fn(|i| (commits.legs[i].new_reserve_commit, commits.legs[i].new_minted_commit));
        if posts != Self::cover_posts(&after) {
            return None;
        }
        let blob = CoverBlob { carrier, posts }.encode()?;
        let (hr, hm) = Self::cover_header_pair(&posts);
        Some((blob, hr, hm, after))
    }

    /// ⭐⭐ §19.5b — THE DOOR'S COVER VERIFY (every node): the blob's two post pairs hash to the signed header pair, and its proof
    /// verifies against BOTH bridge ledgers' CURRENT pairs, both chain-derived backings and the object's one delta commitment.
    /// Returns both post pairs to apply. NEW-DOOR CHECKLIST (§9.6): (1)/(2) PoW and the ≥ 2/3 signatures over the header pair
    /// are the caller's, before this; (3) value moves only through the verified cover — each leg inside its own rule, the
    /// sum exactly the committed delta; (4) replay is the caller's set (deposit ids / spent burns); (5) work: one verify,
    /// one decode, two hashes; (6) parity with the single-ledger door it replaces: the same per-ledger gate, backing and delta
    /// binding, now for both ledgers in one proof — and no ledger is named.
    #[must_use]
    pub fn verify_cover(
        &self,
        peg_in: bool,
        blob_bytes: &[u8],
        header: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
        delta_commit: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]> {
        self.verify_cover_at(0, peg_in, blob_bytes, header, delta_commit, unit)
    }

    /// [`Self::verify_cover`] against the CURRENT pairs of vault `vault`'s bridge ledgers. The proof binds those pairs, and
    /// no two ledgers ever stand on one pair (each is born under its own id's blinds), so a cover proven for one vault
    /// verifies against no other: naming another vault refuses the object, it never moves that vault.
    #[must_use]
    pub fn verify_cover_at(
        &self,
        vault: u32,
        peg_in: bool,
        blob_bytes: &[u8],
        header: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
        delta_commit: crate::spend_frontier::Digest4,
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Option<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]> {
        use usdm_decider::confidential_solvency as cs;
        let blob = CoverBlob::decode(blob_bytes)?;
        if Self::cover_header_pair(&blob.posts) != header {
            return None;
        }
        let currents = self.cover_currents_at(vault)?;
        let backings = self.cover_backings(peg_in, unit)?;
        let commits = cs::CoverCommits {
            legs: core::array::from_fn(|i| cs::TransitionCommits {
                reserve_commit: currents[i].0,
                minted_commit: currents[i].1,
                new_reserve_commit: blob.posts[i].0,
                new_minted_commit: blob.posts[i].1,
            }),
            delta_commit,
        };
        let kind = if peg_in { cs::CoverKind::PegIn } else { cs::CoverKind::PegOut };
        cs::verify_cover_carrier(&blob.carrier, kind, &commits, backings).then_some(blob.posts)
    }

    /// ⭐ §19.5b — advance BOTH bridge ledgers to a verified cover's post pairs (each with its high-water mark, the one apply).
    fn apply_cover(&mut self, posts: &[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]) {
        self.apply_cover_at(0, posts);
    }

    /// [`Self::apply_cover`] for vault `vault`'s bridge ledgers (a higher vault's pair is born at its first apply).
    fn apply_cover_at(&mut self, vault: u32, posts: &[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]) {
        for (i, id) in bridge_ledgers_of(vault).iter().enumerate() {
            self.apply_psm_transition(*id, posts[i].0, posts[i].1);
        }
    }

    /// DB-80: the committed mint delta every custodian derives from its sealed `(mint, d_blind)` — what a
    /// proposal carries and what the mint-validity carrier binds the note to.
    #[must_use]
    pub fn mint_delta_commit(mint: u128, d_blind: crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
        usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(mint), d_blind)
    }

    /// CUSTODIAN REDEEM ORCHESTRATION — the peg-out mirror: prove a `-release / -burn` reduction whose release is worth at
    /// most the burn at the redeem floor and at most its pro-rata share of the reserve (DB-470, UNPROVABLE otherwise — no drain,
    /// and no cash-out frozen by the system's ratio). Same transient-opening contract as
    /// [`Self::orchestrate_peg_in`]. `None` if release/burn exceed the opening, the reduction drops below backing,
    /// or the opening does not match the persisted commitments.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub fn orchestrate_peg_out(
        &self,
        // the ledger the cash-out pays from (`peg_out_asset_for`): the native one, or Monero's own
        asset_id: u32,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        release: u128,
        burn: u128,
        // the peg-out's sealed redeem blind (`PegOutDelta::r_blind`): the blind schedule's secret input
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> Option<(Vec<u8>, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        use usdm_decider::confidential_solvency as cs;
        if release > r_val || burn > m_val {
            return None;
        }
        let (_nrv, nr_blind, _nmv, nm_blind) =
            Self::opening_after_peg_out(r_val, r_blind, m_val, m_blind, release, burn, leg_blind);
        let (carrier, commits, _burn_commit) = cs::prove_peg_out_carrier_delta(
            u256_from_u128(r_val),
            u256_from_u128(m_val),
            u256_from_u128(release),
            u256_from_u128(burn),
            r_blind,
            m_blind,
            nr_blind,
            nm_blind,
            peg_out_burn_blind(leg_blind),
            self.backing(asset_id, self.redeem_floor_bps as u64)?,
        )?;
        let (reserve_commit, minted_commit, _) = self.psm_commits(asset_id)?;
        if commits.reserve_commit != reserve_commit || commits.minted_commit != minted_commit {
            return None;
        }
        Some((
            carrier,
            commits.new_reserve_commit,
            commits.new_minted_commit,
            nr_blind,
            nm_blind,
        ))
    }

    /// #75 — the CONFIDENTIAL PEG-IN (mint) wire path. NO cleartext amount anywhere: the caller (the custodian
    /// threshold, which confirmed the real deposit) supplies the WHIR-bound peg-in carrier + the NEW committed
    /// state; the node checks (a) replay, (b) the ≥2/3 bonded threshold over the commitment-binding message, and
    /// (c) the carrier (conservation + 150% backing over HIDDEN totals) against its OWN persisted commitments,
    /// then advances the opaque digest pair. It learns NO deposit value / mint value / total. A rejected mint
    /// mutates NOTHING (fail-closed). The caller records the recipient's confidential note on success.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::too_many_arguments)]
    pub fn peg_in_confidential(
        &mut self,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        bond_backstop_bytes: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        self.peg_in_confidential_for(deposit_id, carrier_bytes, new_reserve_commit, new_minted_commit, delta_commit, recipient, proposal_nonce, bond_backstop_bytes, quorum, verifier, attestors, None)
    }

    /// The mutating peg-in at the mint's own backing ([`Self::mint_backing`]).
    #[allow(clippy::too_many_arguments)]
    pub fn peg_in_confidential_for(
        &mut self,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        bond_backstop_bytes: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> PegOutcome {
        // SAFE AT SCALE: the old backstop field carries the deposit's VAULT RIDE (`VaultRide`): empty on every object of a
        // one-vault chain. Bytes that are neither empty nor a ride refuse the object — never read as vault 0.
        let Some(ride) = VaultRide::decode(bond_backstop_bytes) else { return PegOutcome::BadRequest };
        let verdict = self.check_peg_in_psm(
            &ride,
            deposit_id,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
            recipient,
            proposal_nonce,
            quorum,
            verifier,
            attestors,
            unit,
        );
        let posts = match verdict {
            Ok(p) => p,
            Err(o) => return o,
        };
        // ⛔⛔⛔ THE BOND IS NOT A GATE ON THE USER'S MONEY — REMOVED 2026-09-17 BY EXPLICIT DECISION.
        //
        // user: "the bond shouldnt prevent genuine issuance at all. It should also not prevent genuine
        // withdrawls. users should be able to deposit and withdraw as much as they want down to the 100%
        // backed level."
        //
        // This used to refuse the mint with `Underbonded` unless `total_bond >= 2 x new_reserve`. MEASURED on
        // two REAL peered nodes: `validators:0` plus a CONFIRMED BTC deposit answered `UNDERBONDED` and issued
        // nothing — **a depositor's real BTC accepted into the bonded set's custody with no USDm issued against it**,
        // which is the worst failure a stablecoin has. It also made the chain unbootstrappable: no USDm ⇒ no
        // bond ⇒ no USDm.
        //
        // ⭐ THE MODEL, STATED SO NOBODY RE-DERIVES THE OLD ONE. The depositor's BTC **is** the reserve: it
        // sits in threshold custody and comes back on exit. The reserve BACKS ITSELF. The validator bond is a
        // forfeitable security deposit against validator THEFT, so it governs slashing size, reward weight and
        // how much the set can be trusted with — never whether a user may deposit or withdraw.
        //
        // ⛔ WHAT THIS DOES NOT REMOVE, AND THE DISTINCTION IS THE WHOLE POINT: the SOLVENCY proof above
        // (`verify_confidential_peg_in`) is untouched, and it is the no-inflation gate — the mint must still
        // prove against this node's persisted commitments, so USDm can never be issued without real backing.
        // A reader auditing this hunk should check that line is still there; removing IT would be a pillar
        // breach, and removing THIS one is an economic-policy change the owner made deliberately.
        //
        // ⛔ AND BE HONEST ABOUT THE COST: the old rule made theft "funds-loss-IMPOSSIBLE" (reserve always
        // <= half the forfeitable bond). Without it the anti-theft guarantee becomes economic rather than
        // absolute — slashing still exists and still forfeits a colluder's bond, but a set may now custody
        // more than it has staked. That is the accepted trade for never trapping a user's deposit.
        // ⛔ NOT VERIFIED, AND SAY SO PLAINLY. `verify_bond_backstop` now has ZERO call sites; slashing does
        // NOT use this carrier (it forfeits bond against a ≥2/3 threshold cert in `validator::slash`). The
        // field remains on the wire only because removing it is an encoding change that lands separately.
        // A comment claiming a dead proof is still load-bearing is how a retired gate gets re-cited as
        // protection it no longer provides.
        // ⭐ 2026-11-10, SAFE AT SCALE: the field is read again, as something else — the deposit's `VaultRide`. It is still
        // no gate on a deposit: a ride bounds what ONE VAULT's quorum may sign for alone, and a deposit past that bound is
        // signed by the whole bonded set exactly as every deposit was (`vault_signed`).
        // §19.5b: BOTH bridge ledgers of the deposit's vault advance to the cover's post pairs (no ledger is named)
        self.apply_cover_at(ride.vault, &posts);
        self.confidential_deposit_ids.insert(deposit_id);
        self.applied_ids.push((deposit_id, 0));
        PegOutcome::ConfidentialMinted
    }

    /// ⭐ THE CHECKS ALONE, MUTATING NOTHING — the executor's door (`Node::peg_in_confidential`), which
    /// publishes on `ConfidentialPublished` and applies only when a block carries the object. ONE spelling:
    /// the mutating `peg_in_confidential` above is exactly this followed by the apply, so the graft door
    /// and the publish door can never disagree about what is admissible.
    #[allow(clippy::too_many_arguments)]
    pub fn check_peg_in_confidential(
        &self,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        self.check_peg_in_confidential_for(deposit_id, carrier_bytes, new_reserve_commit, new_minted_commit, delta_commit, recipient, proposal_nonce, quorum, verifier, attestors, None)
    }

    /// The peg-in checks at the mint's own backing ([`Self::mint_backing`]: the PSM's, or a debt unit's).
    #[allow(clippy::too_many_arguments)]
    pub fn check_peg_in_confidential_for(
        &self,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> PegOutcome {
        self.check_peg_in_confidential_riding(&[], deposit_id, carrier_bytes, new_reserve_commit, new_minted_commit, delta_commit, recipient, proposal_nonce, quorum, verifier, attestors, unit)
    }

    /// [`Self::check_peg_in_confidential_for`] for a deposit riding vault `ride_bytes` ([`VaultRide`]; empty = vault 0 under
    /// the whole bonded set, every object a one-vault chain makes). The checks alone, mutating nothing.
    #[allow(clippy::too_many_arguments)]
    pub fn check_peg_in_confidential_riding(
        &self,
        ride_bytes: &[u8],
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> PegOutcome {
        let Some(ride) = VaultRide::decode(ride_bytes) else { return PegOutcome::BadRequest };
        match self.check_peg_in_psm(&ride, deposit_id, carrier_bytes, new_reserve_commit, new_minted_commit, delta_commit, recipient, proposal_nonce, quorum, verifier, attestors, unit) {
            Ok(_) => PegOutcome::ConfidentialPublished,
            Err(o) => o,
        }
    }

    /// ⭐⭐ SAFE AT SCALE — WHAT THE BRIDGE LEDGERS OF ONE VAULT MAY STAND BEHIND TOGETHER ON THEIR QUORUM'S WORD ALONE, in
    /// USDm atomic: what the vault's cheapest signing set forfeits (`forfeit_sat`, bond units — `custody_vaults::forfeit`)
    /// valued at the chain's own price for slashed bond ([`Self::repayment_sat_floor`]: the lower of SAT's 7-day average
    /// and its 30-day low, at the repayment haircut). So whatever a vault's quorum signed for alone, its slashed bonds
    /// repay by the valuation the repayment ladder itself uses. Half of the figure while the chain keeps coin ledgers
    /// (the other half bounds them, [`Self::vault_authority_coin`]). `None` while SAT is unpriced: a vault's word alone
    /// then carries nothing, and every deposit is signed by the whole bonded set, as before vaults.
    /// cons: a vault's unused coin authority cannot back a USDm deposit (the split is fixed; one weighted-sum proof would
    /// share it and is not built). A deposit past the figure is not refused: the whole set signs it.
    #[must_use]
    pub fn vault_authority_usdm(&self, forfeit_sat: u128) -> Option<u128> {
        let whole = forfeit_sat.checked_mul(self.repayment_sat_floor()?)? / crate::liquidation::PRICE_SCALE;
        let coins = COIN_LEDGERS.iter().any(|c| self.wrapped_assets.contains_key(c));
        Some(if coins { whole / 2 } else { whole })
    }

    /// [`Self::vault_authority_usdm`] for ONE coin ledger of a vault, in the coin's own atoms: a quarter of the vault's
    /// figure, at the coin's reference price (Bitcoin's or Monero's 7-day average). `None` while SAT or the coin is
    /// unpriced, or for an id that is not a coin ledger.
    #[must_use]
    pub fn vault_authority_coin(&self, coin: u32, forfeit_sat: u128) -> Option<u128> {
        let underlying = match ledger_asset_checked(coin)? {
            COIN_BTC_ASSET_ID => NATIVE_PEG_ASSET_ID,
            COIN_XMR_ASSET_ID => XMR_PEG_ASSET_ID,
            _ => return None,
        };
        let price = self.twap7(underlying).filter(|p| *p > 0)?;
        let quarter = forfeit_sat.checked_mul(self.repayment_sat_floor()?)? / crate::liquidation::PRICE_SCALE / 4;
        Some(quarter.checked_mul(crate::liquidation::PRICE_SCALE)? / price)
    }

    /// The public commitment a bound proof stands on: `amount` under [`VAULT_COVER_BLIND`], recomputed by every node.
    #[must_use]
    pub fn vault_cover_commit(amount: u128) -> crate::spend_frontier::Digest4 {
        usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(amount), VAULT_COVER_BLIND)
    }

    /// The blind of a ride's one-object sum commitment: derived from the two ledgers' post minted blinds (secret to the
    /// vault's custodians, fresh at each peg), so every custodian of the vault forms the same ride from its own openings.
    #[must_use]
    pub fn vault_sum_blind(mb_blind: &crate::spend_frontier::Digest4, mx_blind: &crate::spend_frontier::Digest4) -> crate::spend_frontier::Digest4 {
        let mut h = blake3::Hasher::new_derive_key("USDMD-VAULT-SUM-BLIND-v1");
        h.update(&crate::spend_frontier::digest_to_lane_bytes(mb_blind));
        h.update(&crate::spend_frontier::digest_to_lane_bytes(mx_blind));
        crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
    }

    /// ⭐ THE CUSTODIAN'S RIDE PROVE: from its openings of vault `vault`'s two bridge ledgers AFTER a mint (`after`, in
    /// [`BRIDGE_LEDGERS`] order — what [`Self::orchestrate_cover_at`] returned), the two proofs that let the vault's quorum
    /// sign the deposit alone. `None` when the vault would stand behind more than its authority — the deposit then rides
    /// [`VaultRide::of`] and the whole bonded set signs it — or while SAT is unpriced.
    #[must_use]
    pub fn prove_vault_ride(
        &self,
        vault: u32,
        forfeit_sat: u128,
        after: &[(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2],
    ) -> Option<VaultRide> {
        use usdm_decider::confidential_solvency as cs;
        let authority = self.vault_authority_usdm(forfeit_sat)?;
        let stood = after[0].2.checked_add(after[1].2)?;
        // past its authority, or with a part at rest in its slot (spec §3g.1; `vault_ride_holds` refuses it): the whole set signs
        if stood > authority || self.vault_parts.contains_key(&vault) {
            return None;
        }
        let s_blind = Self::vault_sum_blind(&after[0].3, &after[1].3);
        let (sum, commits) = cs::prove_transition_carrier(u256_from_u128(after[0].2), u256_from_u128(after[1].2), &[after[0].3, after[1].3, s_blind], cs::TransitionDomain::VaultSum)?;
        let zero = cs::u256_from_u64(0);
        let (bound, _) = cs::prove_peg_in_carrier(
            u256_from_u128(authority),
            u256_from_u128(stood),
            zero,
            zero,
            VAULT_COVER_BLIND,
            s_blind,
            VAULT_COVER_BLIND,
            s_blind,
            cs::Backing::at_unit_price(10_000),
        )?;
        Some(VaultRide { vault, sum_commit: commits[2], sum, bound })
    }

    /// ⭐ THE DOOR'S RIDE VERIFY: `ride`'s two proofs against the post pairs the cover just proved for the vault's bridge
    /// ledgers — the sum commitment opens to the two post minted totals added, and the vault's public authority is at
    /// least that sum (the plain carrier at one for one, both sides standing still: the authority under the public blind
    /// on the reserve side, the sum on the minted side). Fail closed on an unpriced SAT, another vault's totals, a sum that
    /// leaves a ledger out, or a figure past the authority.
    #[must_use]
    fn vault_ride_holds(&self, ride: &VaultRide, forfeit_sat: u128, posts: &[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]) -> bool {
        use usdm_decider::confidential_solvency as cs;
        // ⭐ spec §3g.1: A VAULT WITH A PART AT REST CARRIES NOTHING ON ITS OWN WORD. The part's coins are under its key
        // until they are sent and its ledgers no longer count them, so its two totals understate what it holds: its
        // deposits are the whole set's to sign until the slot closes (as they were while it stood past its bound).
        // Without this, two thirds of a vault could carve its ledger to a vault that never consents, read as empty,
        // and take a second ledger of deposits alone — twice what its bonds repay.
        if self.vault_parts.contains_key(&ride.vault) {
            return false;
        }
        let Some(authority) = self.vault_authority_usdm(forfeit_sat) else { return false };
        if !cs::verify_transition_carrier(&ride.sum, &[posts[0].1, posts[1].1, ride.sum_commit], cs::TransitionDomain::VaultSum) {
            return false;
        }
        let cover = Self::vault_cover_commit(authority);
        cs::verify_peg_in_carrier(&ride.bound, cs::Backing::at_unit_price(10_000), cover, ride.sum_commit, cover, ride.sum_commit)
    }

    /// ⭐⭐ SAFE AT SCALE — THE ONE RULE FOR WHOSE SIGNATURES CARRY A PEG OF A VAULT, read by every peg door. `Ok(None)`: two
    /// thirds of the WHOLE bonded weight signed `msg` (every object of a one-vault chain; a deposit past a vault's
    /// authority). `Ok(Some(forfeit))`: two thirds of the vault's OWN weight signed it — the caller then holds the object to
    /// what that vault may do alone (a mint: [`Self::vault_ride_holds`]; a burn: nothing more, it can only pay from its
    /// own ledgers). A vault that does not exist, or a quorum that knows no vaults asked for a vault's word, is refused.
    /// §9.6: (2) the same ONE tally (`tally_attestors`) either way; (5) the signatures verified are bounded by the quorum
    /// read — a vault's sixteen, or the bonded set's on the whole-set path; (7) SCALE: a vault-signed object's signature
    /// work and bytes do not grow with the bonded set; (8) AI RESISTANT: who signed is (b) code and economics — a tally
    /// of ML-DSA signatures over a statement each signer's own node derives from its own openings and watcher — and
    /// what a vault's signers may do on their own word is held by (a) proofs every node checks: the cover against that
    /// vault's own pairs, and the ride (its two minted totals add to no more than its public authority). A lying
    /// prover gains nothing: a ride over other totals, another vault's pairs or a made-up authority fails its own
    /// verify (pinned, `safe_at_scale_a_vault_signs_a_deposit_alone…`). A persuasive message gains nothing: nothing a
    /// proposal says is signed unless the signer re-derives it.
    fn vault_signed(ride_vault: u32, by_vault: bool, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, msg: &[u8], attestors: &[MintAttestor]) -> Result<Option<u128>, PegOutcome> {
        if ride_vault >= quorum.vault_count() {
            return Err(PegOutcome::BadRequest); // no such vault on this chain
        }
        if by_vault {
            let Some((own, forfeit)) = quorum.vault(ride_vault) else { return Err(PegOutcome::BadRequest) };
            // a vault under half strength never carries a deposit on its own word: a seat fills one custodian at a time,
            // so a young or thinned vault can be one machine — its "two thirds" would be a person, not a committee
            if own.members.len() < crate::custody_vaults::VAULT_MIN {
                return Err(PegOutcome::BadRequest);
            }
            return if threshold_ok(&own, verifier, msg, attestors) { Ok(Some(forfeit)) } else { Err(PegOutcome::InsufficientThreshold) };
        }
        if !threshold_ok(quorum, verifier, msg, attestors) {
            return Err(PegOutcome::InsufficientThreshold);
        }
        // With more than one vault, the whole set's signers outside the vault are WITNESSES: each saw the deposit and
        // judged its priced cover, and none holds the vault's openings. The vault's own two thirds are the signers who
        // re-derived the pair the object moves the vault's ledgers to — so they are required beside the whole set's.
        if quorum.vault_count() > 1 {
            let Some((own, _)) = quorum.vault(ride_vault) else { return Err(PegOutcome::BadRequest) };
            if !threshold_ok(&own, verifier, msg, attestors) {
                return Err(PegOutcome::InsufficientThreshold);
            }
        }
        Ok(None)
    }

    /// ⭐ SAFE AT SCALE — whose signatures carry a WRAPPED mint on ledger `asset_id`. A coin ledger is custody-funded: the
    /// coin arrives at a vault's deposit address and lands on that vault's own coin ledger, so it is signed as a deposit
    /// the whole set carries ([`Self::vault_signed`], no ride: two thirds of the whole bonded weight and, with more than one
    /// vault, two thirds of that vault's own). Any other registered asset is minted by its own attested door under the
    /// whole set, as it was. On a one-vault chain both are the one tally they always were.
    /// cons: a coin deposit on a chain of more than one vault is always signed by the whole set — the coin ledgers have no
    /// ride yet ([`Self::vault_authority_coin`] is their bound; the object has no field to carry its proof).
    fn wrapped_mint_signed(asset_id: u32, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, msg: &[u8], attestors: &[MintAttestor]) -> bool {
        if Self::is_custody_funded(asset_id) {
            Self::vault_signed(ledger_vault(asset_id), false, quorum, verifier, msg, attestors).is_ok()
        } else {
            threshold_ok(quorum, verifier, msg, attestors)
        }
    }

    // ── SAFE AT SCALE: THE VAULT MERGE (`Class::VaultMerge`, `vault_merge_tx`) — a vault thinned under half strength
    //    hands its ledgers to another vault, so its last custodian never leaves a ledger nobody can move. ──────────────

    /// The pair of vault `vault`'s ledger of `asset`, when the chain keeps that ledger kind (a coin ledger exists only on a
    /// chain that registered the coin).
    #[must_use]
    pub fn vault_pair(&self, vault: u32, asset: u32) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        self.ledger_ratio_bps(asset)?;
        self.psm_commits(vault_ledger(vault, asset)).map(|(r, m, _)| (r, m))
    }

    /// The pair vault `vault`'s ledger of `asset` is born on: zero under the genesis blinds of its own id.
    #[must_use]
    pub fn vault_genesis_pair(vault: u32, asset: u32) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        use usdm_decider::confidential_solvency as cs;
        let zero = cs::u256_from_u64(0);
        let (rb, mb) = psm_genesis_blinds(vault_ledger(vault, asset));
        Some((cs::solvency_commit_256(zero, rb), cs::solvency_commit_256(zero, mb)))
    }

    /// Does vault `vault` stand on a ledger that has moved — any pair that is not its own genesis pair? A vault whose
    /// ledgers all stand at genesis holds nothing and stands behind nothing: its last custodian may leave.
    #[must_use]
    pub fn vault_ledgers_moved(&self, vault: u32) -> bool {
        CUSTODY_LEDGER_KINDS.iter().any(|a| self.vault_ledger_moved(vault, *a))
    }

    /// Does vault `vault`'s ledger of `asset` stand moved: a pair the chain keeps that is not its own genesis pair?
    #[must_use]
    pub fn vault_ledger_moved(&self, vault: u32, asset: u32) -> bool {
        self.vault_pair(vault, asset).is_some_and(|p| Some(p) != Self::vault_genesis_pair(vault, asset))
    }

    /// ⭐ THE RELEASE — what the RETIRING vault's custodians sign for a merge (and, when no bound proof rides, two thirds
    /// of the whole bonded set): "vault `from`'s ledgers, as the chain holds them, go to vault `into`, as the chain holds
    /// its." Every field is a chain fact the signer's own node derives — the two vaults and, for each ledger kind the
    /// chain keeps, both vaults' current pairs — so nothing is handed to a signer, and the signature is good for exactly
    /// one merge of exactly these ledgers (a replay names pairs the chain no longer holds).
    #[must_use]
    pub fn vault_merge_release_msg(&self, from: u32, into: u32) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-merge.release.v1");
        self.vault_merge_pre_state(&mut m, from, into);
        m
    }

    /// ⭐ THE ACCEPTANCE — what the RECEIVING vault's custodians sign: the release's own pre-state and the receiving
    /// pairs after, which each of them derived from its own openings of both vaults' ledgers
    /// ([`Self::opening_after_vault_merge`]). The vault that will stand behind the USDm and hold the coins names the
    /// totals it takes on; the sum proofs hold it to them.
    #[must_use]
    pub fn vault_merge_msg(&self, from: u32, into: u32, legs: &[MergeLeg]) -> Vec<u8> {
        let posts: Vec<MergePost> = legs.iter().map(|l| (l.asset, l.post)).collect();
        self.vault_merge_accept_msg(from, into, &posts)
    }

    /// [`Self::vault_merge_msg`] from the pairs after alone (`(ledger kind, pair)`, ascending) — what a custodian of
    /// the receiving vault signs in the merge lane BEFORE any proof exists: the pairs are a pure function of its own
    /// two openings (`opening_after_vault_merge`), and the proofs are not part of the statement.
    #[must_use]
    pub fn vault_merge_accept_msg(&self, from: u32, into: u32, posts: &[MergePost]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-merge.accept.v1");
        self.vault_merge_pre_state(&mut m, from, into);
        // the pairs after, each under the ledger kind it is the pair of (the proofs are not signed: the door checks them)
        m.extend_from_slice(&(posts.len() as u32).to_le_bytes());
        for (asset, post) in posts {
            m.extend_from_slice(&asset.to_le_bytes());
            Self::push_pair(&mut m, Some(*post));
        }
        m
    }

    fn push_pair(m: &mut Vec<u8>, p: Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)>) {
        match p {
            Some((r, mi)) => {
                m.push(1);
                m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&r));
                m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&mi));
            }
            None => m.push(0),
        }
    }

    /// The two vaults and both vaults' current pairs of every ledger kind ([`CUSTODY_LEDGER_KINDS`]), each under its
    /// kind's id, as this chain holds them.
    fn vault_merge_pre_state(&self, m: &mut Vec<u8>, from: u32, into: u32) {
        m.extend_from_slice(&from.to_le_bytes());
        m.extend_from_slice(&into.to_le_bytes());
        m.extend_from_slice(&(CUSTODY_LEDGER_KINDS.len() as u32).to_le_bytes());
        for a in CUSTODY_LEDGER_KINDS {
            m.extend_from_slice(&a.to_le_bytes());
            Self::push_pair(m, self.vault_pair(from, *a));
            Self::push_pair(m, self.vault_pair(into, *a));
        }
    }

    /// ⭐ THE CUSTODIAN'S MERGE PROVE, from its openings of BOTH vaults' ledgers of one kind (`into` first): the merge's
    /// leg for that kind (the receiving ledger's new pair and the two sums' proofs) and the receiving ledger's opening
    /// after. The new blinds are derived from both old blinds, so every custodian that holds both openings forms the
    /// same pair. `None` when an opening does not open the chain's pair, or a sum overflows.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn prove_vault_merge_leg(
        &self,
        from: u32,
        into: u32,
        asset: u32,
        into_open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
        from_open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
    ) -> Option<(MergeLeg, (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4))> {
        use usdm_decider::confidential_solvency as cs;
        if Self::commits_of_opening(into_open.0, into_open.1, into_open.2, into_open.3) != self.vault_pair(into, asset)?
            || Self::commits_of_opening(from_open.0, from_open.1, from_open.2, from_open.3) != self.vault_pair(from, asset)?
        {
            return None;
        }
        let after = Self::opening_after_vault_merge(into_open, from_open)?;
        let (r, rc) = cs::prove_transition_carrier(u256_from_u128(into_open.0), u256_from_u128(from_open.0), &[into_open.1, from_open.1, after.1], cs::TransitionDomain::VaultMerge)?;
        let (m, mc) = cs::prove_transition_carrier(u256_from_u128(into_open.2), u256_from_u128(from_open.2), &[into_open.3, from_open.3, after.3], cs::TransitionDomain::VaultMerge)?;
        Some((MergeLeg { asset, post: (rc[2], mc[2]), reserve_sum: r, minted_sum: m }, after))
    }

    /// The receiving ledger's opening after a merge, from both vaults' openings of one ledger kind (`into` first): the
    /// totals added, under blinds derived from both old blinds — secret to whoever holds both openings, and the same for
    /// every such holder, so each custodian of the receiving vault advances to the one pair the object states. `None`
    /// when a sum does not fit.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn opening_after_vault_merge(
        into_open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
        from_open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
    ) -> Option<(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4)> {
        let blind = |tag: &str, a: &crate::spend_frontier::Digest4, b: &crate::spend_frontier::Digest4| {
            let mut h = blake3::Hasher::new_derive_key(tag);
            h.update(&crate::spend_frontier::digest_to_lane_bytes(a));
            h.update(&crate::spend_frontier::digest_to_lane_bytes(b));
            crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
        };
        Some((
            into_open.0.checked_add(from_open.0)?,
            blind("USDMD-VAULT-MERGE-R-v1", &into_open.1, &from_open.1),
            into_open.2.checked_add(from_open.2)?,
            blind("USDMD-VAULT-MERGE-M-v1", &into_open.3, &from_open.3),
        ))
    }

    /// ⭐⭐ THE MERGE DOOR, the checks alone. `from`'s ledgers are merged into `into`'s: one [`MergeLeg`] for every
    /// ledger kind ([`CUSTODY_LEDGER_KINDS`]) the retiring vault moved and none for any other, in ascending asset order;
    /// a leg states the receiving pair after and proves `into.reserve + from.reserve = post.reserve` and the same for
    /// the minted supply, against the chain's own pairs. The door reads the list of kinds, never a fixed slot: a coin
    /// added to the bridge is merged by the same door.
    /// §9.6: (1) PoW — the carrying block's; (2) signatures — two thirds of the RETIRING vault's own weight over the
    /// release ([`Self::vault_merge_release_msg`]: it gives its ledgers up) and two thirds of the RECEIVING vault's over
    /// the acceptance ([`Self::vault_merge_msg`]: it takes them on — it will stand behind that USDm and hold those
    /// coins), each list tallied against its own statement, and two proofs per leg; (3) value — none is created: each
    /// sum is proven against both chain pairs, so the receiving ledger gains exactly what the retiring one held, and a
    /// merge that leaves a moved ledger behind (a missing leg) is refused whole — the retiring vault never keeps a
    /// ledger its custodians may then walk away from; (4) replay — the proofs and the message name the chain's current
    /// pairs, which the apply changes; (5) work — two tallies of at most sixteen and two proof verifies per ledger
    /// kind: a fixed bound (`CUSTODY_LEDGER_KINDS.len()`, a protocol constant); (6) parity with the liquidation door
    /// (the other object that moves a ledger's pair on custodians' signatures and proofs with no note): the signed
    /// message binds the pre-state, the proofs are checked against chain state, a rejection moves nothing; (7) SCALE —
    /// two vaults, whatever the bonded set on the two-vault path; at most one leg per entry of the protocol's list of
    /// bridged coins, the same at any number of nodes, users, notes or blocks.
    /// A merge is allowed only OUT of a vault at half strength or under
    /// (`custody_vaults::VAULT_MIN` members or fewer — the size at which a member may no longer leave it, so the vault
    /// can always hand its ledgers on before it thins): a fuller vault's ledgers stay its own.
    /// THE RECEIVING VAULT'S BOUND — parity with the deposit door, which lets a vault's quorum take on USDm alone only
    /// within what its bonds repay ([`Self::vault_ride_holds`]): the two vaults' quorums carry a merge alone only with a
    /// ride proving the receiving vault's bridge ledgers AFTER the merge stay inside its authority, and only when no coin
    /// ledger moves (a coin ledger has no ride). Otherwise two thirds of the whole bonded weight sign it as well — or a
    /// merge would be the way around the deposit door's bound (two quorums concentrating what four had to hold).
    /// AI RESISTANT: (a) a proof every node checks — the sums and the bound are statements verified against the chain's
    /// own pairs; the signatures add consent (who gives up, who takes on), never a value. A lying prover that states a
    /// receiving pair that is not the sum, or a bound the totals exceed, fails the carrier's own verify; a persuasive
    /// message gains nothing: each signer signs the message its own node derives from its own chain's pairs.
    #[allow(clippy::too_many_arguments)]
    pub fn check_vault_merge(
        &self,
        from: u32,
        into: u32,
        legs: &[MergeLeg],
        ride_bytes: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        release: &[MintAttestor],
        accept: &[MintAttestor],
    ) -> PegOutcome {
        let (from_q, into_q, into_forfeit, ride) = match self.vault_merge_shape(from, into, legs, ride_bytes, quorum) {
            Ok(x) => x,
            Err(o) => return o,
        };
        // the signatures first (the cheaper work), then the proofs: the retiring vault's two thirds over the RELEASE,
        // the receiving vault's two thirds over the ACCEPTANCE — two lists, each tallied against its own statement
        let (release_msg, accept_msg) = (self.vault_merge_release_msg(from, into), self.vault_merge_msg(from, into, legs));
        if !threshold_ok(&from_q, verifier, &release_msg, release) || !threshold_ok(&into_q, verifier, &accept_msg, accept) {
            return PegOutcome::InsufficientThreshold;
        }
        // no bound proof: two thirds of the whole bonded weight sign the release beside the retiring vault's own
        if !ride.by_vault() && !threshold_ok(quorum, verifier, &release_msg, release) {
            return PegOutcome::InsufficientThreshold;
        }
        self.vault_merge_proofs(from, into, legs, &ride, into_forfeit)
    }

    /// ⭐ WHAT A CUSTODIAN CHECKS BEFORE IT SIGNS A PROPOSED MERGE — everything [`Self::check_vault_merge`] checks that
    /// needs no signature, against THIS node's own chain: the two vaults and the strength rule, the retiring vault's
    /// ledgers moved, every sum proof, and the receiving vault's bound when one rides. `Ok(alone)`: the statement
    /// holds, and `alone` says the two vaults' quorums carry it (a bound proof rides) rather than the whole set too.
    /// The ONE definition both the signer and the door read (the door adds its tallies between the two halves).
    pub fn vault_merge_statement_holds(&self, from: u32, into: u32, legs: &[MergeLeg], ride_bytes: &[u8], quorum: &dyn BondQuorum) -> Result<bool, PegOutcome> {
        let (_, _, into_forfeit, ride) = self.vault_merge_shape(from, into, legs, ride_bytes, quorum)?;
        match self.vault_merge_proofs(from, into, legs, &ride, into_forfeit) {
            PegOutcome::ConfidentialPublished => Ok(ride.by_vault()),
            other => Err(other),
        }
    }

    /// Are `legs` in the one order a merge carries them: at least one, each a custody-funded ledger kind, strictly
    /// ascending by asset (so no kind twice), at most one per kind? The decode and the door both read this.
    #[must_use]
    pub fn merge_legs_in_order(legs: &[MergeLeg]) -> bool {
        !legs.is_empty()
            && legs.len() <= CUSTODY_LEDGER_KINDS.len()
            && legs.iter().all(|l| CUSTODY_LEDGER_KINDS.contains(&l.asset))
            && legs.windows(2).all(|w| w[0].asset < w[1].asset)
    }

    /// The merge's shape: two distinct vaults that exist, the retiring one at half strength or under with a member, the
    /// receiving one with a member, the retiring vault's ledgers moved, legs in their one order, and ride bytes that are
    /// a bound proof or nothing (one encoding).
    #[allow(clippy::type_complexity)]
    fn vault_merge_shape(&self, from: u32, into: u32, legs: &[MergeLeg], ride_bytes: &[u8], quorum: &dyn BondQuorum) -> Result<(crate::psm::VaultQuorum, crate::psm::VaultQuorum, u128, VaultRide), PegOutcome> {
        if from == into || !Self::merge_legs_in_order(legs) || quorum.vault_count() <= 1 || from >= quorum.vault_count() || into >= quorum.vault_count() {
            return Err(PegOutcome::BadRequest);
        }
        let (Some((from_q, _)), Some((into_q, into_forfeit))) = (quorum.vault(from), quorum.vault(into)) else { return Err(PegOutcome::BadRequest) };
        if from_q.members.is_empty() || from_q.members.len() > crate::custody_vaults::VAULT_MIN || into_q.members.is_empty() {
            return Err(PegOutcome::BadRequest); // a vault past half strength keeps its own ledgers; an empty vault signs nothing
        }
        if !self.vault_ledgers_moved(from) {
            return Err(PegOutcome::Replay); // nothing to merge: the retiring vault's ledgers stand at genesis (already merged)
        }
        if self.vault_part_names(from) {
            // spec §3g.1: a part at rest out of the retiring vault, or for it, would name a vault that holds no ledgers
            // after this merge — the slot closes first (its take, or its giver's cancel)
            return Err(PegOutcome::BadRequest);
        }
        let ride = VaultRide::decode(ride_bytes).ok_or(PegOutcome::BadRequest)?;
        if !ride.by_vault() && !ride_bytes.is_empty() {
            return Err(PegOutcome::BadRequest); // one encoding: a merge carries a bound proof or no ride bytes at all
        }
        Ok((from_q, into_q, into_forfeit, ride))
    }

    /// The merge's proofs against the chain's own pairs: the receiving vault's bound when one rides, and every sum —
    /// EXACTLY one leg for each ledger kind the retiring vault moved, and none for a kind it did not (a kind the chain
    /// does not keep, or a retiring ledger still on its own genesis pair, which any node recomputes: it holds nothing
    /// to merge and the receiving ledger stays as it is).
    fn vault_merge_proofs(&self, from: u32, into: u32, legs: &[MergeLeg], ride: &VaultRide, into_forfeit: u128) -> PegOutcome {
        use usdm_decider::confidential_solvency as cs;
        let leg_of = |asset: u32| legs.iter().find(|l| l.asset == asset);
        if ride.by_vault() {
            // the two quorums alone: the receiving vault stays inside its authority, proven over its bridge pairs AFTER —
            // and only when every leg is a bridge ledger's (a coin ledger has no ride)
            if ride.vault != into || legs.iter().any(|l| !BRIDGE_LEDGERS.contains(&l.asset)) {
                return PegOutcome::BadRequest;
            }
            let (Some(n), Some(x)) = (
                leg_of(BRIDGE_LEDGERS[0]).map(|l| l.post).or_else(|| self.vault_pair(into, BRIDGE_LEDGERS[0])),
                leg_of(BRIDGE_LEDGERS[1]).map(|l| l.post).or_else(|| self.vault_pair(into, BRIDGE_LEDGERS[1])),
            ) else {
                return PegOutcome::BadRequest;
            };
            if !self.vault_ride_holds(ride, into_forfeit, &[n, x]) {
                return PegOutcome::BadRequest;
            }
        }
        let mut proven = 0usize;
        for a in CUSTODY_LEDGER_KINDS {
            match (self.vault_ledger_moved(from, *a), leg_of(*a)) {
                (true, Some(leg)) => {
                    let (Some(f), Some(t)) = (self.vault_pair(from, *a), self.vault_pair(into, *a)) else { return PegOutcome::BadRequest };
                    if !cs::verify_transition_carrier(&leg.reserve_sum, &[t.0, f.0, leg.post.0], cs::TransitionDomain::VaultMerge)
                        || !cs::verify_transition_carrier(&leg.minted_sum, &[t.1, f.1, leg.post.1], cs::TransitionDomain::VaultMerge)
                    {
                        return PegOutcome::BadRequest;
                    }
                    proven += 1;
                }
                (false, None) => {}
                // a moved ledger with no leg (it would be left behind), or a leg for a ledger that holds nothing
                _ => return PegOutcome::BadRequest,
            }
        }
        if proven != legs.len() {
            return PegOutcome::BadRequest; // a leg naming a kind outside the list was judged by nothing
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE MERGE, applied (the block's fold): [`Self::check_vault_merge`], then the receiving ledgers stand on the posts
    /// and the retiring vault's ledgers are back at their genesis pairs (a composite entry leaves the map; vault 0's own
    /// words return to zero under their genesis blinds). A rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultMerge` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_merge(
        &mut self,
        from: u32,
        into: u32,
        legs: &[MergeLeg],
        ride_bytes: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        release: &[MintAttestor],
        accept: &[MintAttestor],
    ) -> PegOutcome {
        use usdm_decider::confidential_solvency as cs;
        let verdict = self.check_vault_merge(from, into, legs, ride_bytes, quorum, verifier, release, accept);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        let zero = cs::u256_from_u64(0);
        for leg in legs {
            let (a, p) = (&leg.asset, leg.post);
            // the receiving ledger takes the sum (its high-water mark with it, as a deposit's apply does)
            self.apply_psm_transition(vault_ledger(into, *a), p.0, p.1);
            // the retiring ledger returns to its genesis pair
            let gone = vault_ledger(from, *a);
            if is_vault_ledger(gone) {
                self.wrapped_assets.remove(&gone);
            } else {
                let (rb, mb) = psm_genesis_blinds(gone);
                let (r0, m0) = (cs::solvency_commit_256(zero, rb), cs::solvency_commit_256(zero, mb));
                if gone == NATIVE_PEG_ASSET_ID {
                    self.reserve_commit = r0;
                    self.minted_commit = m0;
                    self.reserve_hwm_commit = r0;
                } else if let Some(w) = self.wrapped_assets.get_mut(&gone) {
                    w.reserve_commit = r0;
                    w.minted_commit = m0;
                    w.reserve_hwm_commit = r0;
                }
            }
        }
        PegOutcome::ConfidentialMinted
    }

    // ── SAFE AT SCALE, stage three: THE REBALANCE (`Class::VaultRebalance`, `vault_rebalance_tx`; spec §3g.1) — part of
    //    one vault's ledgers moves to another vault, by proof and in three steps: a deposit is never refused, so a vault
    //    can stand past what its own bonds repay, and that state must not rest. The giver CARVES the part out of its
    //    ledgers into its slot; the coins follow the slot; the receiver TAKES it once its own source shows the coins —
    //    or the giver CANCELS a part nobody consented to. BORROWED: THORChain's vault migration (the old vault's
    //    outbound is its debit, the new vault's observed inbound its credit); IBC (escrow, then mint). ───────────────

    /// Are `legs` in the one order a rebalance step carries them: at least one, each a custody-funded ledger kind,
    /// strictly ascending by asset (so no kind twice)? The decode and the doors both read this.
    #[must_use]
    pub fn rebalance_legs_in_order(legs: &[RebalanceLeg]) -> bool {
        !legs.is_empty()
            && legs.len() <= CUSTODY_LEDGER_KINDS.len()
            && legs.iter().all(|l| CUSTODY_LEDGER_KINDS.contains(&l.asset))
            && legs.windows(2).all(|w| w[0].asset < w[1].asset)
    }

    /// What a rebalance step states for each ledger kind — `(kind, the part when it is a carve, the pair after)` —
    /// which is all its statement names beside the chain's own state.
    #[must_use]
    pub fn rebalance_posts(legs: &[RebalanceLeg]) -> Vec<RebalancePost> {
        legs.iter().map(|l| (l.asset, l.part, l.post)).collect()
    }

    /// The part at rest in vault `from`'s slot, when it has one.
    #[must_use]
    pub fn vault_part(&self, from: u32) -> Option<&VaultPart> {
        self.vault_parts.get(&from)
    }

    /// Every part at rest, as `(giving vault, part)` — what a custody lane walks to find the parts FOR its own vault.
    /// SAFE AT SCALE: at most one per vault.
    pub fn vault_parts_all(&self) -> impl Iterator<Item = (u32, &VaultPart)> {
        self.vault_parts.iter().map(|(v, p)| (*v, p))
    }

    /// Does a part at rest name `vault`, as its giver or as the vault it is for? (A retiring vault is not merged
    /// while one does: the slot would name a vault that no longer holds ledgers.)
    #[must_use]
    pub fn vault_part_names(&self, vault: u32) -> bool {
        self.vault_parts.iter().any(|(from, p)| *from == vault || p.into == vault)
    }

    /// One digest of vault `from`'s slot as this chain holds it (all zero bytes of input when it has none): what a
    /// take, a cancel and a consent bind, so each is good for exactly this part and no other.
    #[must_use]
    pub fn vault_part_digest(&self, from: u32) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("musdm.peg.vault-part.v1");
        h.update(&from.to_le_bytes());
        match self.vault_parts.get(&from) {
            None => {
                h.update(&[0]);
            }
            Some(p) => {
                h.update(&[1]);
                h.update(&p.into.to_le_bytes());
                h.update(&p.opened_tick.to_le_bytes());
                h.update(&(p.legs.len() as u32).to_le_bytes());
                for l in &p.legs {
                    h.update(&l.asset.to_le_bytes());
                    for d in [&l.part.0, &l.part.1, &l.from_post.0, &l.from_post.1] {
                        h.update(&crate::spend_frontier::digest_to_lane_bytes(d));
                    }
                }
            }
        }
        *h.finalize().as_bytes()
    }

    /// One vault's current pairs of every ledger kind ([`CUSTODY_LEDGER_KINDS`]), each under its kind's id, as this
    /// chain holds them — the pre-state a rebalance step of that vault names.
    fn vault_pre_state(&self, m: &mut Vec<u8>, vault: u32) {
        m.extend_from_slice(&vault.to_le_bytes());
        m.extend_from_slice(&(CUSTODY_LEDGER_KINDS.len() as u32).to_le_bytes());
        for a in CUSTODY_LEDGER_KINDS {
            m.extend_from_slice(&a.to_le_bytes());
            Self::push_pair(m, self.vault_pair(vault, *a));
        }
    }

    fn push_rebalance_posts(m: &mut Vec<u8>, posts: &[RebalancePost]) {
        m.extend_from_slice(&(posts.len() as u32).to_le_bytes());
        for (asset, part, post) in posts {
            m.extend_from_slice(&asset.to_le_bytes());
            Self::push_pair(m, *part);
            Self::push_pair(m, Some(*post));
        }
    }

    /// ⭐ THE CARVE — what the GIVING vault's custodians sign: the vault it is for, their own vault's pairs as the
    /// chain holds them, and for each ledger kind the part and their pair after — everything a custodian of the
    /// giving vault derives from its own opening and the part's values (`giver_opening_after_rebalance`). Good for
    /// exactly one carve of exactly these ledgers: a replay names pairs the chain no longer holds.
    #[must_use]
    pub fn vault_carve_msg(&self, from: u32, into: u32, posts: &[RebalancePost]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-rebalance.carve.v1");
        m.extend_from_slice(&into.to_le_bytes());
        self.vault_pre_state(&mut m, from);
        Self::push_rebalance_posts(&mut m, posts);
        m
    }

    /// ⭐ THE TAKE — what the RECEIVING vault's custodians sign (and, when no bound proof rides, two thirds of the
    /// whole bonded set): the slot as the chain holds it, their own vault's pairs now, and their pair after for each
    /// kind. Each signs only when its own openings give these pairs and ITS OWN SOURCE shows the part's coins under
    /// its vault's key (`Node`'s lane; the door sees the bound, by proof). The slot's digest names the giver, so a
    /// take is good for that one part; its own apply removes the slot.
    #[must_use]
    pub fn vault_take_msg(&self, from: u32, posts: &[RebalancePost]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-rebalance.take.v1");
        m.extend_from_slice(&self.vault_part_digest(from));
        self.vault_pre_state(&mut m, self.vault_parts.get(&from).map_or(u32::MAX, |p| p.into));
        Self::push_rebalance_posts(&mut m, posts);
        m
    }

    /// ⭐ THE CANCEL — what the GIVING vault's custodians sign to take back a part nobody took: the slot as the chain
    /// holds it, their own vault's pairs now, and their pair after for each kind. A custodian signs it only when its
    /// own lanes signed no coin move for the slot (`Node`'s lane); the door holds the wait.
    #[must_use]
    pub fn vault_cancel_msg(&self, from: u32, posts: &[RebalancePost]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-rebalance.cancel.v1");
        m.extend_from_slice(&self.vault_part_digest(from));
        self.vault_pre_state(&mut m, from);
        Self::push_rebalance_posts(&mut m, posts);
        m
    }

    /// ⭐ THE CONSENT — a LANE statement, never carried by an object: what the RECEIVING vault's custodians sign to say
    /// "send them": the slot as the chain holds it and which of their vault's keys the coins go to (`key_since_tick`,
    /// the key record's own name for a key). The giving vault's signers move coins only to a key two thirds of the
    /// receiver's seats named this way, and only while the chain still holds that slot and that key as current.
    #[must_use]
    pub fn vault_part_consent_msg(&self, from: u32, key_since_tick: u64) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-rebalance.consent.v1");
        m.extend_from_slice(&self.vault_part_digest(from));
        m.extend_from_slice(&key_since_tick.to_le_bytes());
        m
    }

    fn rebalance_blind(tag: &str, a: &crate::spend_frontier::Digest4, b: &crate::spend_frontier::Digest4, v: u128) -> crate::spend_frontier::Digest4 {
        let mut h = blake3::Hasher::new_derive_key(tag);
        h.update(&crate::spend_frontier::digest_to_lane_bytes(a));
        h.update(&crate::spend_frontier::digest_to_lane_bytes(b));
        h.update(&v.to_le_bytes());
        crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
    }

    /// A CARVE'S OPENINGS, from the giver's own opening and the part's values alone: `(the part's opening, the giver's
    /// opening after)`. Every blind is derived from the giver's own blinds and the part's values, so every custodian
    /// of the giving vault forms the one pair the carve states. `None` when the giver holds less than the part.
    #[must_use]
    pub fn giver_opening_after_rebalance(from_open: LedgerOpening, part: (u128, u128)) -> Option<(LedgerOpening, LedgerOpening)> {
        let b = Self::rebalance_blind;
        let part_open: LedgerOpening = (
            part.0,
            b("USDMD-VAULT-REBALANCE-PART-R-v1", &from_open.1, &from_open.3, part.0),
            part.1,
            b("USDMD-VAULT-REBALANCE-PART-M-v1", &from_open.1, &from_open.3, part.1),
        );
        let from_after: LedgerOpening = (
            from_open.0.checked_sub(part.0)?,
            b("USDMD-VAULT-REBALANCE-FROM-R-v1", &from_open.1, &from_open.3, part.0),
            from_open.2.checked_sub(part.1)?,
            b("USDMD-VAULT-REBALANCE-FROM-M-v1", &from_open.1, &from_open.3, part.1),
        );
        Some((part_open, from_after))
    }

    /// THE OPENING OF A LEDGER THE SLOT'S PART IS ADDED TO — the receiver's at a take, the giver's own at a cancel:
    /// from its opening now and the part's opening. The blinds are derived from the ledger's own blinds and the
    /// part's, so every custodian of that vault that holds the part's opening forms the one pair the step states, and
    /// nobody outside the vault can (the ledger's own blinds are its custodians'). `None` when a sum does not fit.
    #[must_use]
    pub fn receiver_opening_after_rebalance(into_open: LedgerOpening, part_open: LedgerOpening) -> Option<LedgerOpening> {
        let b = Self::rebalance_blind;
        Some((
            into_open.0.checked_add(part_open.0)?,
            b("USDMD-VAULT-REBALANCE-INTO-R-v1", &into_open.1, &part_open.1, part_open.0),
            into_open.2.checked_add(part_open.2)?,
            b("USDMD-VAULT-REBALANCE-INTO-M-v1", &into_open.3, &part_open.3, part_open.2),
        ))
    }

    /// The part of a vault's ledger a rebalance moves, as a shift: AN EIGHTH, always (spec §3g.2).
    pub const REBALANCE_PART_SHIFT: u32 = 3;

    /// ⭐⭐ WHAT A VAULT PAST ITS BOUND OWES TO MOVE (spec §3g.2) — a pure function of the vault's own openings of its two
    /// bridge ledgers ([`BRIDGE_LEDGERS`] order) and its authority ([`Self::vault_authority_usdm`] of its forfeit), so
    /// every custodian of the GIVING vault names the same part from its own opening; a custodian of the RECEIVING vault
    /// holds it to exactly that eighth ([`Self::parts_are_one_fraction`]). `None` while the vault stands inside its
    /// authority (the two minted totals, added, at or under it).
    ///   • The part is AN EIGHTH of BOTH words of BOTH bridge ledgers, each floored, whatever the excess: the same
    ///     fraction of reserve and of minted, so the vault cannot shed USDm and keep its coins. A ledger whose eighth is
    ///     nothing in both words gets no leg.
    ///   • Why an eighth and never more (MEASURED by the custody lifecycle model, 2026-11-12, before any of it ran): as
    ///     first built the part was the smallest of an eighth, a quarter and a half that brought the giver inside, so a
    ///     vault at twice its bound always asked for a half — and when no vault had room for a half it stood past its
    ///     bound for ever, though several could each take an eighth. Each round leaves a vault seven eighths of what it
    ///     held (ln 2 / ln (8/7) ≈ 5.2 rounds a doubling of the excess); it stays past its bound only while no vault of
    ///     eight has room for an eighth of it (model invariant I8).
    /// `[(reserve, minted); 2]` in [`BRIDGE_LEDGERS`] order. Coin ledgers are not moved by this rule (they have their
    /// own bound, [`Self::vault_authority_coin`], and no ride): named in the spec as not built.
    #[must_use]
    pub fn rebalance_part_due(open: &[LedgerOpening; 2], authority: u128) -> Option<[(u128, u128); 2]> {
        let stood = open[0].2.checked_add(open[1].2)?;
        if stood <= authority {
            return None;
        }
        let k = Self::REBALANCE_PART_SHIFT;
        let part = [(open[0].0 >> k, open[0].2 >> k), (open[1].0 >> k, open[1].2 >> k)];
        (part != [(0, 0), (0, 0)]).then_some(part)
    }

    /// Is each part, read from its opening and the giver's opening as the carve left it (`(part, from_post)` per ledger
    /// kind), EXACTLY AN EIGHTH, floored, of both words of that ledger as it stood before the carve
    /// ([`Self::REBALANCE_PART_SHIFT`])? What a custodian of the receiving vault checks before it keeps a handed part,
    /// and so before it consents: a part that sheds minted USDm and keeps its coins, or the reverse, or is any other
    /// share of the ledger than the rule owes, is refused here. `false` for no parts.
    #[must_use]
    pub fn parts_are_one_fraction(parts: &[(LedgerOpening, LedgerOpening)]) -> bool {
        let k = Self::REBALANCE_PART_SHIFT;
        !parts.is_empty()
            && parts.iter().all(|(part, post)| matches!((post.0.checked_add(part.0), post.2.checked_add(part.2)), (Some(r), Some(m)) if part.0 == r >> k && part.2 == m >> k))
    }

    /// ⭐ THE GIVING CUSTODIAN'S CARVE PROVE for one ledger kind, from its own opening of its vault's ledger and the
    /// part's values: the leg (the part, its pair after, `after + part = now` for both words), the part's opening and
    /// its own opening after. `None` when the opening does not open the chain's pair or the ledger holds less.
    #[must_use]
    pub fn prove_vault_carve_leg(&self, from: u32, asset: u32, from_open: LedgerOpening, part: (u128, u128)) -> Option<(RebalanceLeg, LedgerOpening, LedgerOpening)> {
        use usdm_decider::confidential_solvency as cs;
        if Self::commits_of_opening(from_open.0, from_open.1, from_open.2, from_open.3) != self.vault_pair(from, asset)? {
            return None;
        }
        let (p, after) = Self::giver_opening_after_rebalance(from_open, part)?;
        let d = cs::TransitionDomain::VaultRebalance;
        let u = u256_from_u128;
        // after + part = now (the "now" blinds are the chain's own pair's)
        let (rs, rc) = cs::prove_transition_carrier(u(after.0), u(p.0), &[after.1, p.1, from_open.1], d)?;
        let (ms, mc) = cs::prove_transition_carrier(u(after.2), u(p.2), &[after.3, p.3, from_open.3], d)?;
        Some((RebalanceLeg { asset, part: Some((rc[1], mc[1])), post: (rc[0], mc[0]), reserve_sum: rs, minted_sum: ms }, p, after))
    }

    /// ⭐ THE PROVE OF A STEP THAT ADDS THE SLOT'S PART BACK to ledger `(vault, asset)` — the receiving custodian's
    /// TAKE (`vault` = the vault the slot is for) or the giving custodian's CANCEL (`vault` = `from`) — from its own
    /// opening of that ledger and the part's opening: the leg (the pair after, `now + part = after` for both words)
    /// and its own opening after. `None` unless vault `from` has a slot with a leg of this kind that `part_open` opens
    /// and `now_open` opens the chain's pair of the ledger.
    #[must_use]
    pub fn prove_vault_part_added_leg(&self, from: u32, vault: u32, asset: u32, now_open: LedgerOpening, part_open: LedgerOpening) -> Option<(RebalanceLeg, LedgerOpening)> {
        use usdm_decider::confidential_solvency as cs;
        let slot = self.vault_parts.get(&from)?.legs.iter().find(|l| l.asset == asset)?;
        if Self::commits_of_opening(part_open.0, part_open.1, part_open.2, part_open.3) != slot.part
            || Self::commits_of_opening(now_open.0, now_open.1, now_open.2, now_open.3) != self.vault_pair(vault, asset)?
        {
            return None;
        }
        let after = Self::receiver_opening_after_rebalance(now_open, part_open)?;
        let d = cs::TransitionDomain::VaultRebalance;
        let u = u256_from_u128;
        let (rs, rc) = cs::prove_transition_carrier(u(now_open.0), u(part_open.0), &[now_open.1, part_open.1, after.1], d)?;
        let (ms, mc) = cs::prove_transition_carrier(u(now_open.2), u(part_open.2), &[now_open.3, part_open.3, after.3], d)?;
        Some((RebalanceLeg { asset, part: None, post: (rc[2], mc[2]), reserve_sum: rs, minted_sum: ms }, after))
    }

    /// ⭐⭐ THE CARVE DOOR, the checks alone (spec §3g.1, step 1). Part of `from`'s ledgers leaves them for vault
    /// `into`: at most one [`RebalanceLeg`] per ledger kind, ascending, each for a kind the giver's ledger stands
    /// moved in; a leg states the part and the giver's pair after and proves `after + part = now` for the reserve
    /// word and the minted word, against the chain's own pair. The part then rests in the giver's slot.
    /// §9.6: (1) PoW — the carrying block's. (2) signatures — two thirds of the GIVING vault's weight over
    /// [`Self::vault_carve_msg`]; two proofs per kind. (3) value — none is created or lost: what the giver's ledger
    /// loses is exactly the commitment the slot then holds, and only a take or a cancel, each proven over that same
    /// commitment, adds it back, once. (4) replay — the statement and the proofs name the giver's current pairs, which
    /// the apply moves; a vault with a part at rest carves no second one. (5) work — one tally of at most sixteen and
    /// two verifies per ledger kind, a protocol constant. (6) parity with the merge door's retiring half: the vaults
    /// exist and differ ✓; both have a member ✓; kinds in their one order ✓; every proof against chain pairs ✓; the
    /// giver's tally ✓. NOT carried, by purpose: the merge's strength rule (a rebalance is for a vault of any
    /// strength; one at half strength or under with moved ledgers still owes its merge) and the receiver's bound,
    /// which is the take's — until then the part is nobody's word: a vault with a part at rest carries nothing alone
    /// ([`Self::vault_ride_holds`]). (7) SCALE — one vault's signers whatever the bonded set; one slot per vault.
    /// (8) AI RESISTANT — (a) for conservation: a lying prover whose pair after and part do not add to the chain's
    /// pair fails a verify. (b), the receiving vault's two thirds, for the proportion between a part's two words
    /// ([`Self::parts_are_one_fraction`], checked before they consent to be sent the coins): bounded by the two
    /// vaults' own bonds; making it (a) needs a product statement in the decider, named in the spec as the upgrade.
    pub fn check_vault_carve(&self, from: u32, into: u32, legs: &[RebalanceLeg], quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        use usdm_decider::confidential_solvency as cs;
        if from == into || !Self::rebalance_legs_in_order(legs) || quorum.vault_count() <= 1 || from >= quorum.vault_count() || into >= quorum.vault_count() {
            return PegOutcome::BadRequest;
        }
        let (Some((from_q, _)), Some((into_q, _))) = (quorum.vault(from), quorum.vault(into)) else { return PegOutcome::BadRequest };
        if from_q.members.is_empty() || into_q.members.is_empty() {
            return PegOutcome::BadRequest; // an empty vault signs nothing and is sent nothing
        }
        if self.vault_parts.contains_key(&from) {
            return PegOutcome::Replay; // one part at rest per vault: this vault's slot is taken
        }
        if self.vault_parts.values().any(|p| p.into == into) {
            // one part at rest FOR a vault too: what a receiving custodian holds of other vaults' parts is one slot per
            // ledger kind, whatever the number of vaults (SAFE AT SCALE)
            return PegOutcome::Replay;
        }
        if legs.iter().any(|l| l.part.is_none() || !self.vault_ledger_moved(from, l.asset)) {
            return PegOutcome::BadRequest; // a carve states its part; a ledger that stands at genesis holds nothing to give
        }
        if !threshold_ok(&from_q, verifier, &self.vault_carve_msg(from, into, &Self::rebalance_posts(legs)), sigs) {
            return PegOutcome::InsufficientThreshold;
        }
        let d = cs::TransitionDomain::VaultRebalance;
        for leg in legs {
            let (Some(part), Some(now)) = (leg.part, self.vault_pair(from, leg.asset)) else { return PegOutcome::BadRequest };
            // after + part = now, both words, against the chain's own pair
            if !cs::verify_transition_carrier(&leg.reserve_sum, &[leg.post.0, part.0, now.0], d) || !cs::verify_transition_carrier(&leg.minted_sum, &[leg.post.1, part.1, now.1], d) {
                return PegOutcome::BadRequest;
            }
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE CARVE, applied (the block's fold, at the carrying block's blue score): [`Self::check_vault_carve`], then
    /// the giver's ledgers stand on the pairs after and the part rests in its slot. A rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultRebalance` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_carve(&mut self, from: u32, into: u32, legs: &[RebalanceLeg], tick: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        let verdict = self.check_vault_carve(from, into, legs, quorum, verifier, sigs);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        let mut slot = Vec::with_capacity(legs.len());
        for leg in legs {
            let Some(part) = leg.part else { return PegOutcome::BadRequest };
            slot.push(PartLeg { asset: leg.asset, part, from_post: leg.post });
            self.apply_psm_transition(vault_ledger(from, leg.asset), leg.post.0, leg.post.1);
        }
        self.vault_parts.insert(from, VaultPart { into, opened_tick: tick, legs: slot });
        PegOutcome::ConfidentialMinted
    }

    /// The legs of a step that adds vault `from`'s slot back to `vault`'s ledgers (a take, a cancel), held to the slot:
    /// exactly one per slot leg, the same kinds in the same order, none stating a part, and `now + the slot's part =
    /// after` for both words against the chain's own pair of `vault`'s ledger.
    fn vault_part_added_holds(&self, slot: &VaultPart, vault: u32, legs: &[RebalanceLeg]) -> bool {
        use usdm_decider::confidential_solvency as cs;
        let d = cs::TransitionDomain::VaultRebalance;
        legs.len() == slot.legs.len()
            && legs.iter().zip(slot.legs.iter()).all(|(leg, s)| {
                leg.asset == s.asset
                    && leg.part.is_none()
                    && self.vault_pair(vault, leg.asset).is_some_and(|now| {
                        cs::verify_transition_carrier(&leg.reserve_sum, &[now.0, s.part.0, leg.post.0], d) && cs::verify_transition_carrier(&leg.minted_sum, &[now.1, s.part.1, leg.post.1], d)
                    })
            })
    }

    /// ⭐⭐ THE TAKE DOOR, the checks alone (spec §3g.1, step 3). The vault a slot is for adds the slot's part to its
    /// own ledgers: one [`RebalanceLeg`] per slot leg stating its pair after and proving `now + part = after` for both
    /// words, the part being the SLOT'S OWN commitment.
    /// §9.6: (1) PoW — the carrying block's. (2) signatures — two thirds of the RECEIVING vault's weight over
    /// [`Self::vault_take_msg`]; two proofs per kind; the receiver's bound proof over its bridge pairs after, or with
    /// none two thirds of the whole bonded weight over the same statement. (3) value — the receiver gains exactly the
    /// commitment the carve took from the giver, once: the apply removes the slot. (4) replay — the statement names
    /// the slot (gone after) and the receiver's current pairs. (5) work — one tally of at most sixteen (or the whole
    /// set's list), two verifies per kind and the ride's two. (6) parity with the merge door's receiving half: the
    /// vault exists with a member ✓; kinds in their one order ✓ (the slot's); every proof against chain pairs ✓; the
    /// receiver's bound proof after or the whole set ✓; a vault under half strength carries nothing on its own word ✓
    /// (`vault_signed`'s rule, read here); the receiver's tally ✓. (7) SCALE — one vault's signers whatever the bonded
    /// set. (8) AI RESISTANT — (a) for conservation and the receiver's bound; (b), the receiver's two thirds, for
    /// "the coins arrived" (each signer's own source), bounded by that vault's own bonds: a vault that takes a part
    /// whose coins it does not hold has made its own ledger count coins it lacks.
    pub fn check_vault_take(&self, from: u32, legs: &[RebalanceLeg], ride_bytes: &[u8], quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        let Some(slot) = self.vault_parts.get(&from) else { return PegOutcome::Replay }; // no part at rest: taken or cancelled
        let into = slot.into;
        if into >= quorum.vault_count() {
            return PegOutcome::BadRequest; // the vault it was for is gone: the giver's cancel is what remains
        }
        let Some((into_q, into_forfeit)) = quorum.vault(into) else { return PegOutcome::BadRequest };
        if into_q.members.is_empty() {
            return PegOutcome::BadRequest;
        }
        let Some(ride) = VaultRide::decode(ride_bytes) else { return PegOutcome::BadRequest };
        if !ride.by_vault() && !ride_bytes.is_empty() {
            return PegOutcome::BadRequest; // one encoding: a bound proof or no ride bytes at all
        }
        let msg = self.vault_take_msg(from, &Self::rebalance_posts(legs));
        if !threshold_ok(&into_q, verifier, &msg, sigs) {
            return PegOutcome::InsufficientThreshold;
        }
        if ride.by_vault() {
            // the receiver alone: at least half strength, bridge ledgers only (a coin ledger has no ride), and its two
            // bridge totals AFTER inside its authority
            if ride.vault != into || into_q.members.len() < crate::custody_vaults::VAULT_MIN || legs.iter().any(|l| !BRIDGE_LEDGERS.contains(&l.asset)) {
                return PegOutcome::BadRequest;
            }
            let after = |asset: u32| legs.iter().find(|l| l.asset == asset).map(|l| l.post).or_else(|| self.vault_pair(into, asset));
            let (Some(n), Some(x)) = (after(BRIDGE_LEDGERS[0]), after(BRIDGE_LEDGERS[1])) else { return PegOutcome::BadRequest };
            if !self.vault_ride_holds(&ride, into_forfeit, &[n, x]) {
                return PegOutcome::BadRequest;
            }
        } else if !threshold_ok(quorum, verifier, &msg, sigs) {
            return PegOutcome::InsufficientThreshold; // no bound proof: two thirds of the whole bonded weight sign it too
        }
        if !self.vault_part_added_holds(slot, into, legs) {
            return PegOutcome::BadRequest;
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE TAKE, applied (the block's fold): [`Self::check_vault_take`], then the receiver's ledgers stand on the
    /// pairs after and the slot is gone. A rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultRebalance` object the block carries.
    pub fn vault_take(&mut self, from: u32, legs: &[RebalanceLeg], ride_bytes: &[u8], quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        let verdict = self.check_vault_take(from, legs, ride_bytes, quorum, verifier, sigs);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        let Some(slot) = self.vault_parts.remove(&from) else { return PegOutcome::Replay };
        for leg in legs {
            self.apply_psm_transition(vault_ledger(slot.into, leg.asset), leg.post.0, leg.post.1);
        }
        PegOutcome::ConfidentialMinted
    }

    /// ⭐⭐ THE CANCEL DOOR, the checks alone (spec §3g.1). The giving vault adds its slot's part back to its own
    /// ledgers, once `window` chain ticks have passed since the carve (one rotation day, `Node::vault_key_window_ticks`
    /// — the time a receiver has to consent and a coin to confirm; derived, never tuned).
    /// §9.6: (1) PoW — the carrying block's. (2) two thirds of the GIVING vault's weight over
    /// [`Self::vault_cancel_msg`]; two proofs per kind. (3) value — the giver regains exactly the commitment its carve
    /// took, once: the apply removes the slot, so a part is never both cancelled and taken. (4) replay — the statement
    /// names the slot and the giver's current pairs. (5) work — one tally of at most sixteen, two verifies per kind.
    /// (6) parity with the take: the same sums over the same slot; no bound proof, because the giver stood behind
    /// this part before its carve and its ride is refused while the slot is open either way. (7) SCALE — one vault's
    /// signers. (8) AI RESISTANT — (a) for conservation and the wait; (b), the giver's two thirds, for "no coin was
    /// sent" (each signer's own lanes), bounded by that vault's own bonds: a vault that cancels after sending has
    /// made its own ledger count coins it gave away.
    #[allow(clippy::too_many_arguments)]
    pub fn check_vault_cancel(&self, from: u32, legs: &[RebalanceLeg], tick: u64, window: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        let Some(slot) = self.vault_parts.get(&from) else { return PegOutcome::Replay };
        if tick < slot.opened_tick.saturating_add(window) {
            return PegOutcome::BadRequest; // the receiver's day is not over
        }
        let Some((from_q, _)) = quorum.vault(from).filter(|_| from < quorum.vault_count()) else { return PegOutcome::BadRequest };
        if from_q.members.is_empty() {
            return PegOutcome::BadRequest;
        }
        if !threshold_ok(&from_q, verifier, &self.vault_cancel_msg(from, &Self::rebalance_posts(legs)), sigs) {
            return PegOutcome::InsufficientThreshold;
        }
        if !self.vault_part_added_holds(slot, from, legs) {
            return PegOutcome::BadRequest;
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE CANCEL, applied (the block's fold): [`Self::check_vault_cancel`], then the giver's ledgers stand on the
    /// pairs after and the slot is gone. A rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultRebalance` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_cancel(&mut self, from: u32, legs: &[RebalanceLeg], tick: u64, window: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, sigs: &[MintAttestor]) -> PegOutcome {
        let verdict = self.check_vault_cancel(from, legs, tick, window, quorum, verifier, sigs);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        self.vault_parts.remove(&from);
        for leg in legs {
            self.apply_psm_transition(vault_ledger(from, leg.asset), leg.post.0, leg.post.1);
        }
        PegOutcome::ConfidentialMinted
    }

    // ── SAFE AT SCALE, stage three: THE CUSTODY KEY RECORD (`Class::VaultKey`, `vault_key_tx`; spec §3f R1, R2, R4) —
    //    which member sets' keys hold a vault's coins, so a deposit address has one source and a leaver's collateral
    //    returns only when no alive key names it. ───────────────────────────────────────────────────────────────────

    /// Vault `vault`'s alive keys, oldest first; the last one, when it has no `replaced_tick`, is the current key.
    #[must_use]
    pub fn vault_keys(&self, vault: u32) -> &[VaultKeyRow] {
        self.vault_keys.get(&vault).map_or(&[], Vec::as_slice)
    }

    /// Every alive key of every vault, as `(vault, row)` — what a custody lane walks to find the keys that name ITS
    /// own point (a custodian that left is still named by its old vault's keys until they are retired).
    /// SAFE AT SCALE: vaults × at most `VAULT_KEYS_ALIVE_MAX` rows.
    pub fn vault_keys_all(&self) -> impl Iterator<Item = (u32, &VaultKeyRow)> {
        self.vault_keys.iter().flat_map(|(v, rows)| rows.iter().map(move |k| (*v, k)))
    }

    /// Vault `vault`'s current key: its deposit address.
    #[must_use]
    pub fn vault_key_current(&self, vault: u32) -> Option<&VaultKeyRow> {
        self.vault_keys(vault).last().filter(|k| k.replaced_tick.is_none())
    }

    /// Does any alive key NAME `id`? (What the record says; whether a named custodian's collateral is HELD is
    /// [`Self::vault_key_holds`].) False on a chain whose custody never recorded a key: the chain as it was.
    #[must_use]
    pub fn vault_key_names(&self, id: &[u8; 32]) -> bool {
        self.vault_keys.values().flatten().any(|k| k.members.binary_search(id).is_ok())
    }

    /// ⭐⭐ R4, THE RELEASE GATE'S RULE — IS `id` HELD BY AN ALIVE CUSTODY KEY at chain tick `tick`? A key that names a
    /// custodian holds its collateral only while that key can hold or receive coins the ledger counts:
    ///   • its vault's ledgers stand MOVED — coins may sit under any of that vault's alive keys, so every custodian a
    ///     row names is held until the vault retires that row (`vault_key_retire`: its members' own statement);
    ///   • or its vault stands behind nothing but still has a member and the key is the vault's CURRENT one, or was
    ///     replaced less than `window_ticks` ago — a deposit can still be minted to its address.
    /// It does NOT hold when the vault stands on its genesis ledgers and the key can no longer be paid: replaced with
    /// its window passed, or of a vault with no member left (nobody can mint under it). So no retire statement is
    /// needed where there is provably nothing to retire, and a custodian is never held by a vault that can no longer
    /// act and holds nothing. FOUND 2026-11-11 while writing this gate's own pin: with "any alive row holds", the last
    /// custodian of a custody set that never took a deposit could never have its bond back (its vault had no member
    /// left to retire the key that named it).
    /// What remains held for good: a custodian named by a key of a vault whose ledgers moved and that then lost every
    /// member — coins nobody can move; only forced exits reach it (the unbond rule refuses the last voluntary leave).
    /// SAFE AT SCALE: one pass over the record (vaults × at most four rows × sixteen ids) per release that is due.
    /// AI RESISTANT: (b) code read from chain state every node holds alike — the record, the ledgers' pairs, the seats.
    #[must_use]
    pub fn vault_key_holds(&self, id: &[u8; 32], tick: u64, window_ticks: u64, quorum: &dyn BondQuorum) -> bool {
        !self.vault_keys_holding(id, tick, window_ticks, quorum).is_empty()
    }

    /// ⭐ R4b (spec §3f) — THE VAULTS WHOSE ALIVE KEYS HOLD `id`, by the gate's own rule above (the one site of that
    /// rule: [`Self::vault_key_holds`] is "this list is not empty"), in rising vault order. It is what the gate's
    /// counterweight reads: a vault that still holds a leaver whose window has passed pays that leaver its members'
    /// own yield (`ValidatorSet::divert_own_yield`).
    /// SAFE AT SCALE: the same one pass (vaults × at most four rows × sixteen ids). CACHE-ONLY: a read of chain state.
    #[must_use]
    pub fn vault_keys_holding(&self, id: &[u8; 32], tick: u64, window_ticks: u64, quorum: &dyn BondQuorum) -> Vec<u32> {
        self.vault_keys
            .iter()
            .filter(|(vault, rows)| {
                let mut named = rows.iter().filter(|k| k.members.binary_search(id).is_ok()).peekable();
                if named.peek().is_none() {
                    return false;
                }
                if self.vault_ledgers_moved(**vault) {
                    return true;
                }
                let seated = quorum.vault(**vault).is_some_and(|(q, _)| !q.members.is_empty());
                seated && named.any(|k| k.replaced_tick.is_none_or(|r| tick < r.saturating_add(window_ticks)))
            })
            .map(|(vault, _)| *vault)
            .collect()
    }

    /// The digest of vault `vault`'s alive keys as this chain holds them — the pre-state a key statement binds, so a
    /// signature is good for exactly one change of exactly this record (the apply changes it: a replay names a record
    /// the chain no longer holds).
    #[must_use]
    pub fn vault_keys_digest(&self, vault: u32) -> [u8; 32] {
        // v2 (R5): each row's `mixed_tick` is part of the record a statement binds — the verifier checks the WHOLE record
        // (AI RESISTANT), so a take or a retire signed before a mix names a record the chain no longer holds. A mix only
        // ever marks a SETTLED vault (one row, no take pending), so no honest statement is in flight when the word moves.
        let mut h = blake3::Hasher::new_derive_key("musdm.peg.vault-keys.v2");
        h.update(&vault.to_le_bytes());
        for k in self.vault_keys(vault) {
            h.update(&k.mixed_tick.to_le_bytes());
            h.update(&(k.members.len() as u32).to_le_bytes());
            for m in &k.members {
                h.update(m);
            }
            h.update(&k.btc.leaf);
            h.update(&(k.xmr_address.len() as u32).to_le_bytes());
            h.update(&k.xmr_address);
            h.update(&k.since_tick.to_le_bytes());
            h.update(&[u8::from(k.replaced_tick.is_some())]);
            h.update(&k.replaced_tick.unwrap_or(0).to_le_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// ⭐ WHAT A VAULT'S MEMBERS SIGN TO TAKE A KEY: the vault, the Bitcoin leaf the signer's OWN node derives for the
    /// vault's seats (`btc_leaf`: never carried by the object — a signer whose chain forms another leaf signs another
    /// message, and its signature counts for nothing at the door), the member set (which must be the vault's members
    /// on the signer's own chain), the Monero address their own wallets report for that set, and the record's pre-state.
    #[must_use]
    pub fn vault_key_take_msg(&self, vault: u32, btc: &VaultBtcKey, members: &[[u8; 32]], xmr_address: &[u8]) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-key.take.v2");
        m.extend_from_slice(&vault.to_le_bytes());
        m.extend_from_slice(&btc.leaf); // the leaf's hash commits to its inputs (`btc_tx::custody_leaf`)
        m.extend_from_slice(&(members.len() as u32).to_le_bytes());
        for id in members {
            m.extend_from_slice(id);
        }
        m.extend_from_slice(&(xmr_address.len() as u32).to_le_bytes());
        m.extend_from_slice(xmr_address);
        m.extend_from_slice(&self.vault_keys_digest(vault));
        m
    }

    /// ⭐ WHAT A VAULT'S CURRENT MEMBERS SIGN TO RETIRE A REPLACED KEY: the vault, that key (by the chain tick it became
    /// the key at), and the record's pre-state. Each signs only when its OWN source shows no coin left under that key.
    #[must_use]
    pub fn vault_key_retire_msg(&self, vault: u32, since_tick: u64) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.vault-key.retire.v1");
        m.extend_from_slice(&vault.to_le_bytes());
        m.extend_from_slice(&since_tick.to_le_bytes());
        m.extend_from_slice(&self.vault_keys_digest(vault));
        m
    }

    /// ⭐⭐ THE KEY DOOR, TAKE — the checks alone. The vault's members state the key of exactly their set.
    /// §9.6: (1) PoW — the carrying block's; (2) signatures — two thirds of the vault's own weight over the statement
    /// each signer's node derives ([`Self::vault_key_take_msg`]); (3) value — none moves, no ledger word changes;
    /// (4) replay — the statement binds the record's pre-state, which the apply changes, and the same member set as the
    /// current key is refused outright; (5) work — one tally of at most one vault's members and a digest of at most
    /// [`VAULT_KEYS_ALIVE_MAX`] rows; (6) parity with the registration door (the other attested object that moves a
    /// registry and no value): the signed message binds the pre-state, a rejection moves nothing; (7) SCALE — one vault,
    /// whatever the bonded set, the deposits in flight or the height; (8) AI RESISTANT — (b) code and economics: the
    /// members attest their OWN wallets' address. A quorum that lies names an address it does not hold together, and
    /// what is deposited there is minted on the ledger its own bonds stand behind — the loss is bounded by that vault's
    /// bonds like every vault statement; a persuasive message gains nothing, because a signer signs only the member set
    /// its own chain seats and the address its own wallet reports. The statement that would make it (a): a proof that
    /// the address is the multisig of exactly these members' keys — Monero has no such proof for a third party today.
    /// Refused unless `members` is exactly the vault's member set on THIS chain, differs from the current key's, and
    /// the vault holds fewer than [`VAULT_KEYS_ALIVE_MAX`] keys (it retires one first).
    /// `btc_leaf` is THIS node's own derivation of the vault's Bitcoin leaf (`Node::vault_btc_leaf`: the seats' custody
    /// points and bond weights on this chain) — a chain fact the caller's node computes, like the carrying block's
    /// blue score; the statement is formed over it, so the signers attested exactly the leaf this node derives.
    pub fn check_vault_key_take(&self, vault: u32, btc_leaf: &VaultBtcKey, members: &[[u8; 32]], xmr_address: &[u8], quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, attestors: &[MintAttestor]) -> PegOutcome {
        let Some((vq, _)) = quorum.vault(vault) else { return PegOutcome::BadRequest };
        let mut seated: Vec<[u8; 32]> = vq.members.iter().map(|(id, _)| *id).collect();
        seated.sort_unstable();
        if members.is_empty() || members != seated.as_slice() || xmr_address.len() > VAULT_KEY_ADDRESS_MAX {
            return PegOutcome::BadRequest; // a stranger added, a member dropped, or no member set at all
        }
        if btc_leaf.members.len() > crate::bridge_credit_tx::MAX_CREDIT_ATTESTORS {
            return PegOutcome::BadRequest;
        }
        // ⛔ A-F33: a key is its members, its Bitcoin leaf (by HASH) and its Monero address. The record also keeps the
        // leaf's inputs (each point and bond weight at the take), and a weight change that moves no slot of the sixty
        // leaves the leaf exactly as it was: taking "another" key then would replace the current row by one with the
        // same leaf, and the retire rule (no coin under that leaf) could never free the replaced row. Same key: Replay.
        if self.vault_key_current(vault).is_some_and(|k| k.members == members && k.btc.leaf == btc_leaf.leaf && k.xmr_address == xmr_address) {
            return PegOutcome::Replay;
        }
        if self.vault_keys(vault).len() >= VAULT_KEYS_ALIVE_MAX {
            return PegOutcome::BadRequest;
        }
        if !threshold_ok(&vq, verifier, &self.vault_key_take_msg(vault, btc_leaf, members, xmr_address), attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE TAKE, applied at the fold of the block at chain tick `tick`: the key the vault had is replaced from this
    /// block (it stays alive: R2, make before break), and the new one is the vault's deposit address. A rejection
    /// moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultKey` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_key_take(&mut self, vault: u32, btc_leaf: &VaultBtcKey, members: &[[u8; 32]], xmr_address: &[u8], tick: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, attestors: &[MintAttestor]) -> PegOutcome {
        let verdict = self.check_vault_key_take(vault, btc_leaf, members, xmr_address, quorum, verifier, attestors);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        let keys = self.vault_keys.entry(vault).or_default();
        if let Some(k) = keys.last_mut() {
            if k.replaced_tick.is_none() {
                k.replaced_tick = Some(tick.max(k.since_tick));
            }
        }
        // a key is named by `since_tick` (the retire door finds it by that): strictly rising within a vault, so two
        // takes folded at one chain tick are still two names
        let since_tick = keys.last().map_or(tick, |k| tick.max(k.since_tick.saturating_add(1)));
        // R5: the vault's last mix is the vault's word, not the key's — the new current row carries it on
        let mixed_tick = keys.last().map_or(0, |k| k.mixed_tick);
        keys.push(VaultKeyRow { members: members.to_vec(), btc: btc_leaf.clone(), xmr_address: xmr_address.to_vec(), since_tick, replaced_tick: None, mixed_tick });
        PegOutcome::ConfidentialMinted
    }

    /// ⭐ R5 (spec §3f.2) — WHEN VAULT `vault` LAST MIXED, in chain ticks; 0 when it never did (or holds no key).
    #[must_use]
    pub fn vault_mixed_tick(&self, vault: u32) -> u64 {
        self.vault_key_current(vault).map_or(0, |k| k.mixed_tick)
    }

    /// ⭐ R5 — MARK VAULT `vault` MIXED at chain tick `tick`: the rotation step's one write to the ledger, on the vault's
    /// current key row (a vault with no current key is never chosen: it is not settled). `true` when a word moved.
    /// CHAIN-OBJECT: no object carries it — it is the consequence, at one fold step, of chain state every node holds
    /// (the seats, this record, the debt word, the folded block's id and blue score: `Node::vault_rotations_at_fold`),
    /// written inside that step's journal exactly as the hour's key tick and the quarter's roll are.
    /// O1-INFINITY-REVIEWED: one word of a row the record already holds (at most `VAULT_KEYS_ALIVE_MAX` rows per
    /// vault); no row is added and nothing is keyed by height, block or note.
    pub fn vault_mark_mixed(&mut self, vault: u32, tick: u64) -> bool {
        match self.vault_keys.get_mut(&vault).and_then(|rows| rows.last_mut()).filter(|k| k.replaced_tick.is_none()) {
            Some(k) => {
                k.mixed_tick = tick.max(1);
                true
            }
            None => false,
        }
    }

    /// ⭐⭐ THE KEY DOOR, RETIRE — the checks alone. Two thirds of the vault's CURRENT members state that a replaced key
    /// is finished. The chain checks what it can see: the key is replaced (never the current one), and its address
    /// window — `window_ticks` chain ticks since it was replaced, the chain's own measure — has passed, so no handed-
    /// out address of it is still minted. That no coin is left under it is each signer's own check against its own
    /// source (the same trust as every statement of that vault, bounded by its bonds). §9.6 as the take's; (4) replay —
    /// the retired row is gone and the pre-state moved.
    pub fn check_vault_key_retire(&self, vault: u32, since_tick: u64, tick: u64, window_ticks: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, attestors: &[MintAttestor]) -> PegOutcome {
        let Some((vq, _)) = quorum.vault(vault) else { return PegOutcome::BadRequest };
        let Some(k) = self.vault_keys(vault).iter().find(|k| k.since_tick == since_tick && k.replaced_tick.is_some()) else {
            // no such replaced key: already retired, or the current key (which is never retired)
            return if self.vault_key_current(vault).is_some_and(|k| k.since_tick == since_tick) { PegOutcome::BadRequest } else { PegOutcome::Replay };
        };
        if tick < k.replaced_tick.unwrap_or(u64::MAX).saturating_add(window_ticks) {
            return PegOutcome::BadRequest; // its handed-out addresses may still be paid
        }
        if !threshold_ok(&vq, verifier, &self.vault_key_retire_msg(vault, since_tick), attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE RETIRE, applied: the replaced key leaves the record, and a custodian it named is no longer held by it
    /// (R4). A rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::VaultKey` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn vault_key_retire(&mut self, vault: u32, since_tick: u64, tick: u64, window_ticks: u64, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, attestors: &[MintAttestor]) -> PegOutcome {
        let verdict = self.check_vault_key_retire(vault, since_tick, tick, window_ticks, quorum, verifier, attestors);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        if let Some(keys) = self.vault_keys.get_mut(&vault) {
            if let Some(i) = keys.iter().position(|k| k.since_tick == since_tick && k.replaced_tick.is_some()) {
                keys.remove(i);
            }
            if keys.is_empty() {
                self.vault_keys.remove(&vault);
            }
        }
        PegOutcome::ConfidentialRedeemed
    }

    // ── SAFE AT SCALE: THE RESERVE COST (`Class::ReserveCost`, `reserve_cost_tx`) — a vault's reserve falls by the fee
    //    its custody paid a foreign chain to move the vault's OWN coins (a re-key when its members change, a merge). ──

    /// A cost at or under this many foreign atoms carries no bound proof; a larger one proves the reserve it leaves is
    /// at least [`Self::RESERVE_COST_DIVISOR`] times it. Bitcoin: 100,000 sats — a 1,000 vB consolidation at 100 sat/vB,
    /// a congested mempool's rate. Monero: 0.01 XMR — a hundred times its default-priority fee. Protocol constants: a
    /// reserve small enough that an ordinary sweep fee is more than a hundredth of it can still book that fee.
    #[must_use]
    pub fn reserve_cost_floor(ledger: u32) -> Option<u64> {
        match ledger_asset_checked(ledger)? {
            NATIVE_PEG_ASSET_ID => Some(100_000),
            XMR_PEG_ASSET_ID => Some(10_000_000_000),
            _ => None,
        }
    }
    /// Past the floor, one cost is at most one part in this many of the reserve it leaves.
    pub const RESERVE_COST_DIVISOR: u128 = 100;

    /// The public blind a cost's amount is committed under (a public amount: every node recomputes the commitment).
    pub const RESERVE_COST_BLIND: crate::spend_frontier::Digest4 = usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_7273_7663, 0x636f_7374_5f62_6c64]);

    /// The public commitment to `amount` under [`Self::RESERVE_COST_BLIND`].
    #[must_use]
    pub fn reserve_cost_commit(amount: u128) -> crate::spend_frontier::Digest4 {
        usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(amount), Self::RESERVE_COST_BLIND)
    }

    /// The one-time id a cost retires: its ledger and the foreign transaction whose fee it books — the spent set
    /// refuses a second object for the same foreign transaction (`chain_object::object_own_nullifiers`).
    #[must_use]
    pub fn reserve_cost_key(ledger: u32, txid: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new_derive_key("MonerousD reserve cost v1");
        h.update(&ledger.to_le_bytes());
        h.update(txid);
        *h.finalize().as_bytes()
    }

    /// ⭐ What the vault's custodians sign for a cost: the ledger, the public fee, the foreign transaction that paid it,
    /// the ledger's pair AS THE CHAIN HOLDS IT and the reserve after. Each signer's own node derives every field (its
    /// own source shows the transaction and its fee; its own opening gives the reserve after), so nothing is handed to
    /// it, and the signature is good for exactly one booking against exactly this state.
    #[must_use]
    pub fn reserve_cost_msg(&self, ledger: u32, cost: u64, txid: &[u8; 32], post_reserve: &crate::spend_frontier::Digest4) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.reserve-cost.v1");
        m.extend_from_slice(&ledger.to_le_bytes());
        m.extend_from_slice(&cost.to_le_bytes());
        m.extend_from_slice(txid);
        Self::push_pair(&mut m, self.psm_commits(ledger).map(|(r, mi, _)| (r, mi)));
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(post_reserve));
        m
    }

    /// The ledger's opening after a cost: the reserve less the fee under a blind derived from the old blind and the
    /// foreign transaction (secret to the vault's custodians, the same for each of them); the minted side untouched.
    /// `None` when the fee is more than the reserve.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn opening_after_reserve_cost(
        open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
        cost: u64,
        txid: &[u8; 32],
    ) -> Option<(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4)> {
        let mut h = blake3::Hasher::new_derive_key("USDMD-RESERVE-COST-R-v1");
        h.update(&crate::spend_frontier::digest_to_lane_bytes(&open.1));
        h.update(txid);
        Some((open.0.checked_sub(u128::from(cost))?, crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes()), open.2, open.3))
    }

    /// ⭐ THE CUSTODIAN'S COST PROVE, from its opening of `ledger`: the reserve commitment after, the proof that the
    /// reserve after plus the public fee is the reserve the chain holds, the bound proof (empty at or under the
    /// floor), and the opening after. `None` when the opening does not open the chain's pair, the fee is zero or more
    /// than the reserve, or past the floor the reserve left is under [`Self::RESERVE_COST_DIVISOR`] times the fee.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn prove_reserve_cost(
        &self,
        ledger: u32,
        open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
        cost: u64,
        txid: &[u8; 32],
    ) -> Option<(crate::spend_frontier::Digest4, Vec<u8>, Vec<u8>, (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4))> {
        let (r, m, _) = self.psm_commits(ledger)?;
        if Self::commits_of_opening(open.0, open.1, open.2, open.3) != (r, m) {
            return None;
        }
        Self::prove_reserve_cost_from(ledger, open, cost, txid)
    }

    /// [`Self::prove_reserve_cost`]'s proving half, a function of the opening alone (no ledger read), so the lane can
    /// run it on a worker thread: the caller has already checked that `open` opens the chain's pair.
    #[allow(clippy::type_complexity)]
    #[must_use]
    pub fn prove_reserve_cost_from(
        ledger: u32,
        open: (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4),
        cost: u64,
        txid: &[u8; 32],
    ) -> Option<(crate::spend_frontier::Digest4, Vec<u8>, Vec<u8>, (u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4))> {
        use usdm_decider::confidential_solvency as cs;
        let floor = Self::reserve_cost_floor(ledger)?;
        if cost == 0 {
            return None;
        }
        let after = Self::opening_after_reserve_cost(open, cost, txid)?;
        let (sum, commits) = cs::prove_transition_carrier(u256_from_u128(after.0), u256_from_u128(u128::from(cost)), &[after.1, Self::RESERVE_COST_BLIND, open.1], cs::TransitionDomain::ReserveCost)?;
        let bound = if cost <= floor {
            Vec::new()
        } else {
            let scaled = u128::from(cost).checked_mul(Self::RESERVE_COST_DIVISOR)?;
            let zero = cs::u256_from_u64(0);
            cs::prove_peg_in_carrier(u256_from_u128(after.0), u256_from_u128(scaled), zero, zero, after.1, Self::RESERVE_COST_BLIND, after.1, Self::RESERVE_COST_BLIND, cs::Backing::at_unit_price(10_000))?.0
        };
        Some((commits[0], sum, bound, after))
    }

    /// ⭐⭐ THE RESERVE-COST DOOR, the checks alone. Vault ledger `ledger`'s reserve falls by the PUBLIC `cost` (foreign
    /// atoms — the fee of foreign transaction `txid`, public on its own chain) to `post_reserve`; its minted side stands.
    /// §9.6: (1) PoW — the carrying block's; (2) signatures — two thirds of the ledger's own vault over
    /// [`Self::reserve_cost_msg`] (the burn door's rule, [`Self::burn_signed`]: the custodians who hold that vault's
    /// coins and openings; each signs only after its OWN source shows the transaction moving the vault's coins to the
    /// vault's own addresses at that fee), and the proofs; (3) value — none is created: the reserve only FALLS, by a
    /// proven public amount, and never under what the bound allows; nothing is minted or released to anyone on this
    /// chain; (4) replay — the one-time id of `(ledger, txid)` in the spent set, and the message binds the pair the
    /// apply changes; (5) work — one tally over a vault's sixteen at most, two proof verifies; (6) parity with the burn
    /// door, the other object that lowers a vault's reserve on its own quorum's word: the same tally, a proof against
    /// the chain's own pair, a rejection moves nothing — and where a burn's fall is bounded by the note it destroys, a
    /// cost's is bounded here (the floor, then one part in a hundred of the reserve left); (7) SCALE — one vault,
    /// whatever the bonded set; one object per foreign transaction.
    /// AI RESISTANT: (a) a proof every node checks for the arithmetic (the reserve after plus the public fee IS the
    /// reserve before; past the floor the reserve after is a hundred times the fee) and (b) code and economics for
    /// whether the fee was really paid: a vault's quorum that books fees nobody paid lowers only ITS OWN vault's
    /// reserve, by at most the bound per foreign transaction it names — less than the same quorum can take by signing
    /// the coins away, which its bonds answer for. A lying prover (a reserve after that is not the difference, a bound
    /// over other totals) fails the carrier's own verify; a persuasive message gains nothing: a signer derives the fee
    /// from its own source and the reserve after from its own opening.
    /// Only a BRIDGE ledger books a cost (Bitcoin's custody holds the coin ledger's sats too; its fee is booked on the
    /// vault's Bitcoin bridge ledger).
    #[allow(clippy::too_many_arguments)]
    pub fn check_reserve_cost(
        &self,
        ledger: u32,
        cost: u64,
        txid: &[u8; 32],
        post_reserve: crate::spend_frontier::Digest4,
        sum: &[u8],
        bound: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        use usdm_decider::confidential_solvency as cs;
        let Some(floor) = Self::reserve_cost_floor(ledger) else { return PegOutcome::BadRequest };
        let Some((r, _m, _)) = self.psm_commits(ledger) else { return PegOutcome::BadRequest };
        if cost == 0 || (cost <= floor) != bound.is_empty() {
            return PegOutcome::BadRequest; // one encoding: a bound proof exactly when the cost is past the floor
        }
        let msg = self.reserve_cost_msg(ledger, cost, txid, &post_reserve);
        if !Self::burn_signed(ledger_vault(ledger), quorum, verifier, &msg, attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        let fee = Self::reserve_cost_commit(u128::from(cost));
        if !cs::verify_transition_carrier(sum, &[post_reserve, fee, r], cs::TransitionDomain::ReserveCost) {
            return PegOutcome::BadRequest;
        }
        if !bound.is_empty() {
            let Some(scaled) = u128::from(cost).checked_mul(Self::RESERVE_COST_DIVISOR) else { return PegOutcome::BadRequest };
            let cap = Self::reserve_cost_commit(scaled);
            if !cs::verify_peg_in_carrier(bound, cs::Backing::at_unit_price(10_000), post_reserve, cap, post_reserve, cap) {
                return PegOutcome::BadRequest;
            }
        }
        PegOutcome::ConfidentialPublished
    }

    /// ⭐ THE RESERVE COST, applied (the block's fold): [`Self::check_reserve_cost`], then the ledger's reserve stands on
    /// `post_reserve` and its minted side where it was. The high-water mark is not raised (the reserve fell). A
    /// rejection moves nothing.
    /// CHAIN-OBJECT: the `Class::ReserveCost` object the block carries.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_cost(
        &mut self,
        ledger: u32,
        cost: u64,
        txid: &[u8; 32],
        post_reserve: crate::spend_frontier::Digest4,
        sum: &[u8],
        bound: &[u8],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        let verdict = self.check_reserve_cost(ledger, cost, txid, post_reserve, sum, bound, quorum, verifier, attestors);
        if !matches!(verdict, PegOutcome::ConfidentialPublished) {
            return verdict;
        }
        let Some((_, m, _)) = self.psm_commits(ledger) else { return PegOutcome::BadRequest };
        self.set_psm_commits(ledger, post_reserve, m);
        PegOutcome::ConfidentialRedeemed
    }

    /// ⭐ SAFE AT SCALE — the rule of [`Self::vault_signed`] / [`Self::burn_signed`] with the signatures left out: do these
    /// DISTINCT signer ids suffice for a peg of vault `vault`? The lane's cheap "is it time to publish?" pre-check; the
    /// publish itself re-runs the full signed tally at every door. `alone`: a deposit its vault's quorum carries under a
    /// ride. `burn`: a cash-out (its paying vault's own two thirds). Otherwise the whole set's two thirds and, with more
    /// than one vault, the vault's own beside them.
    #[must_use]
    pub fn signer_ids_suffice(quorum: &dyn BondQuorum, vault: u32, alone: bool, burn: bool, ids: &[[u8; 32]]) -> bool {
        if vault >= quorum.vault_count() {
            return false;
        }
        if quorum.vault_count() <= 1 {
            return quorum_weight_met(quorum, ids);
        }
        let own = quorum.vault(vault).is_some_and(|(q, _)| quorum_weight_met(&q, ids));
        if burn || alone {
            return own;
        }
        own && quorum_weight_met(quorum, ids)
    }

    /// [`Self::check_peg_in_confidential_for`] answering WHICH bridge ledger the verified mint lands on — the apply's one verify.
    #[allow(clippy::too_many_arguments)]
    fn check_peg_in_psm(
        &self,
        ride: &VaultRide,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        delta_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
        unit: Option<&crate::debt_units::UnitTerms>,
    ) -> Result<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2], PegOutcome> {
        if self.confidential_deposit_ids.contains(&deposit_id) {
            return Err(PegOutcome::Replay); // this deposit already minted — never twice
        }
        let msg = peg_in_confidential_msg(
            &deposit_id,
            &new_reserve_commit,
            &new_minted_commit,
            &delta_commit,
            &recipient,
            &proposal_nonce,
        );
        // SAFE AT SCALE: the whole set's signatures, or the vault's own with its bound (`vault_signed`, the one rule)
        let own = Self::vault_signed(ride.vault, ride.by_vault(), quorum, verifier, &msg, attestors)?;
        // §19.5b: the two-ledger cover over both bridge ledgers' persisted state — the vault's own pairs — or reject
        let posts = self.verify_cover_at(ride.vault, true, carrier_bytes, (new_reserve_commit, new_minted_commit), delta_commit, unit).ok_or(PegOutcome::BadRequest)?;
        if let Some(forfeit) = own {
            // the vault signed alone: after this mint it stands behind no more than its slashed bonds repay
            if !self.vault_ride_holds(ride, forfeit, &posts) {
                return Err(PegOutcome::BadRequest);
            }
        }
        Ok(posts)
    }

    /// Has this deposit already minted on the chain this node holds? (The replay key.)
    #[must_use]
    pub fn deposit_minted(&self, deposit_id: &[u8; 32]) -> bool {
        self.confidential_deposit_ids.contains(deposit_id)
    }

    /// #75 — the CONFIDENTIAL PEG-OUT (redeem/burn) wire path. NO cleartext amount: the caller supplies the
    /// WHIR-bound peg-out carrier + the NEW committed state; the node checks replay (the burned USDm nullifier),
    /// the ≥2/3 threshold over the commitment-binding message, and the carrier (conservation + post-state ≥150%
    /// backing, no drain — over HIDDEN totals) against its persisted commitments, then advances the digest pair
    /// and records the nullifier spent. Learns no burn / release value. A rejected redeem mutates NOTHING.
    #[allow(clippy::too_many_arguments)]
    pub fn peg_out_confidential(
        &mut self,
        usdm_nullifier: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        // DB-110: the COMMITMENT to the destination (`peg::redeem_commit`), never the destination.
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        // DB-273 §19.3 L2: the change note's owner digest the v4 statement binds.
        change_owner: &[u8; 32],
        // DB-365: the change note's commitment the v5 statement binds.
        change_cm: &[u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        let verdict = self.check_peg_out_psm(
            usdm_nullifier,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            redeem_commit,
            proposal_nonce,
            leaf_commit,
            change_owner,
            change_cm,
            quorum,
            verifier,
            attestors,
        );
        let posts = match verdict {
            Ok(p) => p,
            Err(o) => return o,
        };
        // CHAIN-OBJECT: the `Class::PegOut` object the block carries names the ledger it pays from in its own proofs
        let Some(p) = crate::peg_out_tx::PegOutProofs::decode(carrier_bytes) else { return PegOutcome::BadRequest };
        match posts {
            // §19.5b: BOTH bridge ledgers of the paying vault advance to the cover's post pairs (no asset is named)
            Some(posts) => self.apply_cover_at(ledger_vault(p.coin), &posts),
            // §18.14: a coin burn moves only its coin's pair (the check read the coin off the same bytes)
            None => self.apply_psm_transition(p.coin, new_reserve_commit, new_minted_commit),
        }
        self.spent_burns.insert(usdm_nullifier);
        self.applied_ids.push((usdm_nullifier, 1));
        PegOutcome::ConfidentialRedeemed
    }

    /// ⭐ THE PEG-OUT CHECKS ALONE, MUTATING NOTHING — the executor's door; the mutating
    /// `peg_out_confidential` above is exactly this followed by the apply (one spelling, two doors).
    #[allow(clippy::too_many_arguments)]
    pub fn check_peg_out_confidential(
        &self,
        usdm_nullifier: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        // DB-110: the COMMITMENT to the destination, never the destination (`peg::redeem_commit`).
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        // DB-273 §19.3 L2: the change note's owner digest the v4 statement binds.
        change_owner: &[u8; 32],
        // DB-365: the change note's commitment the v5 statement binds.
        change_cm: &[u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        match self.check_peg_out_psm(usdm_nullifier, carrier_bytes, new_reserve_commit, new_minted_commit, redeem_commit, proposal_nonce, leaf_commit, change_owner, change_cm, quorum, verifier, attestors) {
            Ok(_) => PegOutcome::ConfidentialPublished,
            Err(o) => o,
        }
    }

    /// [`Self::check_peg_out_confidential`] answering WHICH ledger the verified peg-out pays from — the apply's one verify.
    #[allow(clippy::too_many_arguments)]
    /// THE QUORUM'S SIGNATURE ON ONE CONFIDENTIAL PEG-OUT, on its own: two thirds of `quorum`'s bonded weight signed the v6
    /// statement over exactly these values. The ONE spelling the ledger door (`check_peg_out_psm`) and a custodian's leg
    /// recovery after an adopt (`Node::recover_peg_out_leg`) both read, so the two can never check different statements.
    /// Reads no ledger state: it says who signed what, never whether the burn applied (the door's replay set says that).
    /// ⭐ SAFE AT SCALE: `ledger` is the ledger the burn pays from (`PegOutProofs::coin`: 0 or a coin id for vault 0, a
    /// composite for a higher vault). A burn is carried by two thirds of the paying VAULT's own weight
    /// ([`Self::burn_signed`]). No bound rides a burn: it can only pay from the vault's own ledgers, which its cover
    /// proof opens, and it lowers what the vault stands behind.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn peg_out_attestation_holds(
        ledger: u32,
        usdm_nullifier: &[u8; 32],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        change_owner: &[u8; 32],
        change_cm: &[u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> bool {
        let msg = peg_out_confidential_msg(
            usdm_nullifier,
            &new_reserve_commit,
            &new_minted_commit,
            redeem_commit,
            proposal_nonce,
            &leaf_commit,
            change_owner,
            change_cm,
        );
        Self::burn_signed(ledger_vault(ledger), quorum, verifier, &msg, attestors)
    }

    /// ⭐ SAFE AT SCALE — whose signatures carry a BURN paid by vault `vault`: two thirds of THAT VAULT's own weight, the
    /// custodians who hold its ledgers' openings, its sealed legs and its coins' keys. On a one-vault chain the vault is
    /// the whole bonded set and this is the tally it always was. A vault that does not exist carries nothing. (Signers of
    /// other vaults add nothing to a burn: they can open none of it.) Work: one tally, over the vault's sixteen at most.
    /// CHAIN-OBJECT: the signatures are the `Class::PegOut` object's own, carried by the block; this reads who signed it
    /// against the chain-derived bonded set and moves nothing.
    #[must_use]
    pub fn burn_signed(vault: u32, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier, msg: &[u8], attestors: &[MintAttestor]) -> bool {
        if vault >= quorum.vault_count() {
            return false;
        }
        if quorum.vault_count() <= 1 {
            return threshold_ok(quorum, verifier, msg, attestors);
        }
        quorum.vault(vault).is_some_and(|(own, _)| threshold_ok(&own, verifier, msg, attestors))
    }

    fn check_peg_out_psm(
        &self,
        usdm_nullifier: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        // DB-110: the COMMITMENT to the destination, never the destination (`peg::redeem_commit`).
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        // DB-273 §19.3 L2: the change note's owner digest the v4 statement binds.
        change_owner: &[u8; 32],
        // DB-365: the change note's commitment the v5 statement binds.
        change_cm: &[u8; 32],
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> Result<Option<[(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4); 2]>, PegOutcome> {
        if self.spent_burns.contains(&usdm_nullifier) {
            return Err(PegOutcome::Replay); // this USDm note already burned — never twice
        }
        // SAFE AT SCALE: the object's proofs name the ledger it pays from, and so the vault whose signatures carry it —
        // read before the tally (one bounded decode), verified below
        let Some(proofs) = crate::peg_out_tx::PegOutProofs::decode(carrier_bytes) else { return Err(PegOutcome::BadRequest) };
        if !Self::peg_out_attestation_holds(
            proofs.coin,
            &usdm_nullifier,
            new_reserve_commit,
            new_minted_commit,
            redeem_commit,
            proposal_nonce,
            leaf_commit,
            change_owner,
            change_cm,
            quorum,
            verifier,
            attestors,
        ) {
            return Err(PegOutcome::InsufficientThreshold);
        }
        // ⭐ B15: the object's proofs — the committed burn destroys exactly what the burn-bound solvency carrier retires
        // CHAIN-OBJECT: the `Class::PegOut` object the block carries — this is that object's verify (it mutates nothing;
        // the apply follows it in `peg_out_confidential`, at the fold of the block that carries the object)
        if !proofs.burn_verifies(&usdm_nullifier, leaf_commit, change_cm) {
            return Err(PegOutcome::BadRequest); // not a burn of the signed note into the signed change, of the committed amount
        }
        // §19.5b: the two-ledger cover (no drain on either ledger, retiring exactly this burn), or reject
        // ⭐ §18.14 — a coin burn: its own ledger's transition at one for one, so no burn can release what the coin's reserve does not hold
        // (`coin` 0, or a higher vault's composite of asset 0, is USDm's cash-out: the cover over that vault's bridge ledgers)
        let Some(asset) = ledger_asset_checked(proofs.coin) else { return Err(PegOutcome::BadRequest) };
        if asset != NATIVE_PEG_ASSET_ID {
            let (Some((reserve, minted, _)), Some(backing)) = (self.psm_commits(proofs.coin), self.backing(proofs.coin, u64::from(COIN_RATIO_BPS))) else {
                return Err(PegOutcome::BadRequest);
            };
            if !Self::is_coin_ledger(proofs.coin)
                || !usdm_decider::confidential_solvency::verify_peg_out_carrier_delta(&proofs.solvency, backing, reserve, minted, new_reserve_commit, new_minted_commit, proofs.burn_commit)
            {
                return Err(PegOutcome::BadRequest);
            }
            return Ok(None);
        }
        self.verify_cover_at(ledger_vault(proofs.coin), false, &proofs.solvency, (new_reserve_commit, new_minted_commit), proofs.burn_commit, None).map(Some).ok_or(PegOutcome::BadRequest)
    }

    /// ⭐ §18.14 — a coin burn's solvency carrier from this custodian's opening of the coin's ledger: `(carrier, new reserve commit, new minted commit)`. `None` when it does not open the ledger, or
    /// the release or the burn exceeds it.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_coin_out(
        &self,
        coin: u32,
        r_val: u128,
        r_blind: crate::spend_frontier::Digest4,
        m_val: u128,
        m_blind: crate::spend_frontier::Digest4,
        release: u128,
        burn: u128,
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> Option<(Vec<u8>, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        use usdm_decider::confidential_solvency as cs;
        if !Self::is_coin_ledger(coin) || release > r_val || burn > m_val {
            return None;
        }
        let (_nrv, nr_blind, _nmv, nm_blind) = Self::opening_after_peg_out(r_val, r_blind, m_val, m_blind, release, burn, leg_blind);
        let (carrier, commits, _burn_commit) = cs::prove_peg_out_carrier_delta(
            u256_from_u128(r_val),
            u256_from_u128(m_val),
            u256_from_u128(release),
            u256_from_u128(burn),
            r_blind,
            m_blind,
            nr_blind,
            nm_blind,
            peg_out_burn_blind(leg_blind),
            self.backing(coin, u64::from(COIN_RATIO_BPS))?,
        )?;
        let (reserve_commit, minted_commit, _) = self.psm_commits(coin)?;
        if commits.reserve_commit != reserve_commit || commits.minted_commit != minted_commit {
            return None;
        }
        Some((carrier, commits.new_reserve_commit, commits.new_minted_commit))
    }

    /// ⭐ THE LEDGER A PEG-OUT PAYS FROM, READ FROM ITS OWN PROOF. The burn-bound solvency carrier opens one ledger's
    /// `(reserve, minted)` pair at that ledger's own redeem backing (its own mark): the ledger whose pair it verifies against
    /// IS the ledger it pays from, so the object names no asset on the wire. Ledgers are born under distinct genesis blinds
    /// ([`psm_genesis_blinds`]) and every later blind is secret, so at most one ledger's pair verifies. `None` when none
    /// does (fail closed: the object is refused, the chain keeps producing).
    ///
    /// NEW-DOOR CHECKLIST (§9.6) for this read inside the PegOut door: (1)/(2) the object's PoW and its ≥ 2/3 bonded
    /// signatures are checked by the caller BEFORE this runs (`check_peg_out_confidential`'s `threshold_ok`); (3) value moves
    /// only through the verified carrier, against the ledger it opens — a Monero burn cannot release from the Bitcoin ledger
    /// (its pair does not verify there) and the reverse; (4) replay: `spent_burns`, unchanged; (5) work: at most one carrier
    /// verify per registered ledger (two in production), reached only by a signed object; (6) parity: the same verify, backing
    /// and burn binding the single-ledger door ran, now per ledger.
    #[must_use]
    #[cfg(test)]
    pub fn peg_out_psm(
        &self,
        proofs: &crate::peg_out_tx::PegOutProofs,
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
    ) -> Option<u32> {
        std::iter::once(NATIVE_PEG_ASSET_ID).chain(self.wrapped_assets.keys().copied()).find(|id| {
            let Some((reserve, minted, _)) = self.psm_commits(*id) else { return false };
            let Some(backing) = self.backing(*id, self.redeem_floor_bps as u64) else { return false };
            usdm_decider::confidential_solvency::verify_peg_out_carrier_delta(
                &proofs.solvency,
                backing,
                reserve,
                minted,
                new_reserve_commit,
                new_minted_commit,
                proofs.burn_commit,
            )
        })
    }

    /// Advance ledger `asset_id` to a verified peg-in or peg-out's new pair, its high-water mark with it (the native path's
    /// rule, [`Self::apply_confidential_peg_in`]) — the one apply both value paths share for every ledger.
    fn apply_psm_transition(
        &mut self,
        asset_id: u32,
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
    ) {
        if asset_id == NATIVE_PEG_ASSET_ID {
            self.apply_confidential_peg_in(new_reserve_commit, new_minted_commit);
        } else if let Some(a) = self.psm_entry_mut(asset_id) {
            a.reserve_commit = new_reserve_commit;
            a.minted_commit = new_minted_commit;
            a.reserve_hwm_commit = new_reserve_commit;
        }
    }

    /// The ledger whose `(reserve, minted)` pair is exactly `(reserve, minted)` now — how a custodian, after a block applied a
    /// peg-out, learns which of its openings the burn advanced. `None` when no ledger stands on that pair.
    #[must_use]
    #[cfg(test)]
    pub fn psm_standing_on(&self, reserve: crate::spend_frontier::Digest4, minted: crate::spend_frontier::Digest4) -> Option<u32> {
        std::iter::once(NATIVE_PEG_ASSET_ID)
            .chain(self.wrapped_assets.keys().copied())
            .find(|id| self.psm_commits(*id).is_some_and(|(r, m, _)| r == reserve && m == minted))
    }

    /// Has this USDm burn already redeemed on the chain this node holds? (The replay key.)
    #[must_use]
    pub fn burn_redeemed(&self, usdm_nullifier: &[u8; 32]) -> bool {
        self.spent_burns.contains(usdm_nullifier)
    }

    /// ⭐ §BR-3 17.6 (stakers' half) — the committed total the stakers' pool has paid out.
    #[must_use]
    pub fn stake_paid_commit(&self) -> crate::spend_frontier::Digest4 {
        self.stake_paid_commit
    }

    /// ⭐ §BR-3 17.6 (stakers' half) — whether the fold step of a block in stake epoch `epoch` takes the epoch's pool
    /// snapshot (the first folded block of a later epoch than the one held).
    #[must_use]
    pub fn stakers_snapshot_due(&self, epoch: u64) -> bool {
        epoch.saturating_add(1) > self.stakers_snap_epoch_next
    }
    /// Take stake epoch `epoch`'s pool snapshot (the inflow now, before the block's own step) when it is due; returns
    /// whether it moved. The caller journals the step first.
    pub fn snapshot_stakers_pool(&mut self, epoch: u64) -> bool {
        if !self.stakers_snapshot_due(epoch) {
            return false;
        }
        self.stakers_snap_epoch_next = epoch.saturating_add(1);
        self.stakers_snap_pool = self.fee_pool_stakers;
        true
    }
    /// The stakers' pool snapshot of stake epoch `epoch`, if it is the one held: the inflow every claim of that epoch is
    /// bounded by (`None` before the epoch's first block folds — a claim then waits for it).
    #[must_use]
    pub fn stakers_pool_snapshot(&self, epoch: u64) -> Option<u64> {
        (self.stakers_snap_epoch_next == epoch.saturating_add(1)).then_some(self.stakers_snap_pool)
    }

    /// ⭐ §BR-3 17.6 (stakers' half) — A STAKE REWARD IS PAID FROM THE STAKERS' POOL. The supply carrier proves
    /// `paid + reward = new_paid` with the reward opening the stake carrier's `reward_commit`, and `new_paid ≤ inflow` (the
    /// yield-mint shape at a 100 % ratio, the "reserve" side being the epoch `e_now` pool snapshot committed under the public
    /// blind, recomputed here from this node's own ledger — no wire field states it). The USDm supply commitment does not
    /// move: the reward replaces fees already out of circulation. `false` (nothing moved) otherwise, including a claim whose
    /// epoch's snapshot this ledger does not hold.
    pub fn apply_stake_supply(
        &mut self,
        carrier_bytes: &[u8],
        reward_commit: crate::spend_frontier::Digest4,
        new_paid_commit: crate::spend_frontier::Digest4,
        e_now: u64,
    ) -> bool {
        // DIGITAL-CASH-PRIVACY-REVIEWED: verify-gate not a serve/query — the object supplies opaque commitments and its public
        // epoch; the node verifies + advances a commitment and learns no reward amount.
        let Some(pool_in) = self.stakers_pool_snapshot(e_now) else {
            return false; // not this epoch's snapshot (a claim of another epoch)
        };
        let commits = usdm_decider::confidential_solvency::YieldMintCommits {
            yield_commit: reward_commit,
            minted_commit: self.stake_paid_commit,
            new_minted_commit: new_paid_commit,
            reserve_commit: stakers_pool_in_commit(pool_in),
        };
        // both sides are USDm (paid against the stakers' pool snapshot): a unit price is the rule's own semantics, not a stub
        if !usdm_decider::confidential_solvency::verify_yield_mint_carrier(carrier_bytes, usdm_decider::confidential_solvency::Backing::at_unit_price(10_000), &commits) {
            return false;
        }
        self.stake_paid_commit = new_paid_commit;
        true
    }

    // ── LIQUIDATION: the ONE door ────────────────────────────────────────────────────────────────────────────

    /// The three committed digests of ONE PSM — `(reserve, minted, reserve_high_water_mark)` — for the native peg
    /// (`asset_id == NATIVE_PEG_ASSET_ID`) or a registered wrapped asset. `None` for an unregistered asset.
    /// EXISTS SO THERE IS ONE READER: the liquidation door is a single function over every PSM, and this is how it
    /// reads whichever one it is acting on. Opaque digests — no value is returned.
    fn psm_commits(&self, asset_id: u32) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        if asset_id == NATIVE_PEG_ASSET_ID {
            return Some((
                self.reserve_commit,
                self.minted_commit,
                self.reserve_hwm_commit,
            ));
        }
        if let Some(a) = self.wrapped_assets.get(&asset_id) {
            return Some((a.reserve_commit, a.minted_commit, a.reserve_hwm_commit));
        }
        // SAFE AT SCALE: a vault's ledger nothing has moved yet stands on its own genesis-zero pair (never another
        // ledger's: the id is folded into the blinds), exactly as it will be born at its first apply
        Self::vault_ledger_genesis(asset_id).map(|a| (a.reserve_commit, a.minted_commit, a.reserve_hwm_commit))
    }

    /// The pair a vault's ledger is born on: zero under [`psm_genesis_blinds`] of its own id. `None` unless `id` is a
    /// well-formed composite ([`is_vault_ledger`]). The stored ratio is a placeholder nothing reads
    /// ([`Self::ledger_ratio_bps`] answers the asset's).
    fn vault_ledger_genesis(id: u32) -> Option<WrappedAsset> {
        use usdm_decider::confidential_solvency as cs;
        if !is_vault_ledger(id) {
            return None;
        }
        let zero = cs::u256_from_u64(0);
        let (rb, mb) = psm_genesis_blinds(id);
        let reserve_commit = cs::solvency_commit_256(zero, rb);
        Some(WrappedAsset { reserve_commit, minted_commit: cs::solvency_commit_256(zero, mb), ratio_bps: 10_000, reserve_hwm_commit: reserve_commit })
    }

    /// The stored pair of ledger `id`, creating a vault's ledger at its genesis pair the first time something moves it.
    fn psm_entry_mut(&mut self, id: u32) -> Option<&mut WrappedAsset> {
        if !self.wrapped_assets.contains_key(&id) {
            let born = Self::vault_ledger_genesis(id)?;
            self.wrapped_assets.insert(id, born);
        }
        self.wrapped_assets.get_mut(&id)
    }

    /// Advance ONE PSM's `(reserve, minted)` commitment pair and NOTHING else — the single write the liquidation
    /// door performs. Deliberately cannot touch `reserve_hwm_commit` (the bound the next re-mark is measured
    /// against), so the door can never raise its own ceiling. Private: the ONLY caller is
    /// [`Self::liquidate_confidential`], and both directions it may move are ge256-constrained downward there.
    fn set_psm_commits(
        &mut self,
        asset_id: u32,
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
    ) {
        if asset_id == NATIVE_PEG_ASSET_ID {
            self.reserve_commit = new_reserve_commit;
            self.minted_commit = new_minted_commit;
            return;
        }
        if let Some(a) = self.psm_entry_mut(asset_id) {
            a.reserve_commit = new_reserve_commit;
            a.minted_commit = new_minted_commit;
        }
    }

    /// The native peg's reserve HIGH-WATER-MARK commitment (opaque digest). The bound a liquidation re-mark may
    /// never exceed.
    pub fn reserve_hwm_commit(&self) -> crate::spend_frontier::Digest4 {
        self.reserve_hwm_commit
    }

    /// A wrapped asset's own reserve high-water-mark commitment, or `None` if the asset is unregistered.
    pub fn wrapped_asset_hwm_commit(&self, asset_id: u32) -> Option<crate::spend_frontier::Digest4> {
        self.wrapped_assets
            .get(&asset_id)
            .map(|a| a.reserve_hwm_commit)
    }

    // An `is_liquidated` read accessor was written here and DELETED rather than shipped: nothing outside a
    // test called it, and a pub "have we closed this?" query is precisely the shape a future caller wires up
    // INSTEAD of going through the door — two readers of one set, able to disagree. The `liquidated` set has
    // exactly ONE reader, the door itself, and the only way to learn a position's state is to ask the door:
    // it answers `Replay` for a position that is closed. The pins assert that answer.

    /// THE PER-ASSET LIQUIDATION THRESHOLD (bps) — the mark-to-market backing at which a position is closed by the
    /// protocol instead of being left to be abandoned.
    ///
    /// IT IS DERIVED, NOT SETTABLE, AND THAT IS THE POINT. It is the MIDPOINT of this asset's own solvency
    /// buffer: `floor + (ratio - floor)/2`, where `ratio` is the asset's governance-tunable MINT
    /// over-collateralization (15000 for a volatile asset, 10000 for a vetted stablecoin) and `floor` is the
    /// governance-tunable REDEEM floor (10000 = the true-solvency line). Defaults: native/volatile
    /// `10000 + (15000-10000)/2 = 12500` (125%); a vetted stablecoin registered at 10000 gets 10000 — a 1:1 asset
    /// has NO volatility buffer to split, so it is only ever closed at genuine insolvency, which is correct.
    ///
    /// ROOT-LAYER: derived at the layer where the two parameters it depends on are PRODUCED (`ratio_bps` at mint
    /// authorization, `redeem_floor_bps` at the redeem gate) rather than stored as a third copy that could drift
    /// from either. A stored threshold would be a read-site value with two silent producers.
    /// MEASURED: `grep -rn "liquidation_threshold" src/` = 0 hits before this diff (no threshold existed anywhere,
    /// so there is no producer this can contradict) -> exactly 1 definition after.
    /// MUST-STAY-GREEN: `redeem_two_tier_floor_sells_below_150_but_never_below_100` and
    /// `wrapped_asset_per_asset_ratio_stablecoin_exempt_from_150` — this function only READS those two params and
    /// writes nothing.
    ///
    /// WHY THE MIDPOINT AND NOT A CHOSEN NUMBER (§9.5 — never tune a constant): the threshold must sit strictly
    /// between the floor (below it there is nothing left to seize) and the mint ratio (at or above it every
    /// freshly opened position would be liquidated on the day it opened). The midpoint is the unique point that
    /// MAXIMISES THE MINIMUM distance to both failure boundaries — the largest price move the system can absorb
    /// before either boundary is hit. Derived from the protocol's own two existing parameters, not chosen to pass
    /// a test.
    ///
    /// WHY THERE IS NO SETTER — §9.6 Q1's measured hole. `rpc_http.rs` POST `/register_wrapped_asset` reaches
    /// [`Self::register_wrapped_asset`] with NO threshold, NO governance vote and NO block: today anyone who can
    /// reach the RPC port sets a wrapped asset's collateral ratio. A liquidation threshold shipped as a settable
    /// field would inherit exactly that hole — and a settable threshold is a seizure knob. Deriving it means there
    /// is no field to set, so the hole cannot be inherited: the ONLY way to move a threshold is to move
    /// `ratio_bps` or `redeem_floor_bps`, which are already on the bicameral governance path
    /// ([`crate::governance::ParamChange::SetMintRatioBps`], `try_enact` at 2/3-of-both) and already
    /// constitutionally floored (`constitutional_check` refuses a mint ratio below 110%, and
    /// [`Self::set_redeem_floor_bps`] clamps the floor at 100%). Per-asset, governance-tunable, zero new surface.
    ///
    /// Returns 0 (never liquidatable) for an unregistered asset — fail-closed.
    pub fn liquidation_threshold_bps(&self, asset_id: u32) -> u32 {
        let Some(ratio) = self.ledger_ratio_bps(asset_id) else { return 0 };
        let floor = self.redeem_floor_bps;
        if ratio <= floor {
            return floor; // a 1:1 asset has no buffer to split — close only at the true-solvency line
        }
        floor + (ratio - floor) / 2
    }

    /// LIQUIDATION §10 — the rule PSM `asset_id` is liquidated under, read entirely from consensus state: the chain's
    /// folded price MARK (`p`), the pool discount [`LIQ_POOL_DISCOUNT_BPS`], the asset's own mint ratio as the target the
    /// liquidation restores, and its derived [`Self::liquidation_threshold_bps`] as the due line. `None` (not liquidatable,
    /// fail-closed) for an unregistered asset, an asset the chain has never priced, a mark past `u64`, or a rule
    /// `LiqRule::admissible` refuses (a 1:1 PSM has no buffer for a discounted seizure to restore).
    #[must_use]
    pub fn liquidation_rule(&self, asset_id: u32) -> Option<usdm_decider::confidential_solvency::LiqRule> {
        let ratio = self.ledger_ratio_bps(asset_id)?;
        // a vault's ledger is liquidated under its ASSET's mark and guard
        let asset_id = ledger_asset_checked(asset_id)?;
        let mark = self.price_marks.get(&asset_id)?.price;
        // §BR-4 (spec §1 item 7): a liquidation step uses the 10-minute mark, REFUSED while it strays more than
        // LIQ_TWAP_BAND_BPS from the 7-day average UNLESS the move has persisted for the guard's hour (`mark_guard`) — one
        // epoch's outlier cannot trigger a cascade; a real crash is liquidated one hour after it crosses the band. Before any
        // epoch has closed the 7-day average IS the standing mark (a fixture ledger, a launch's first mark): the rule stands.
        if self.mark_guard(asset_id, mark) == Some(false) {
            return None;
        }
        let p = u64::try_from(mark).ok()?;
        let rule = usdm_decider::confidential_solvency::LiqRule {
            p,
            delta_bps: LIQ_POOL_DISCOUNT_BPS,
            rho_target_bps: u64::from(ratio),
            rho_liq_bps: u64::from(self.liquidation_threshold_bps(asset_id)),
        };
        rule.admissible().then_some(rule)
    }

    /// The v2 attestation message for `h` over THIS ledger's current state — the ONE place it is formed, for the door's
    /// tally and for every bonded signer, so a signer and the door can never sign/check different bytes. `None` when the
    /// PSM is unregistered or has no admissible rule (nothing to liquidate).
    #[must_use]
    pub fn liquidation_attest_msg(&self, h: &crate::liquidation_tx::LiquidationHeader) -> Option<Vec<u8>> {
        let (reserve, minted, _) = self.psm_commits(h.asset_id)?;
        let rule = self.liquidation_rule(h.asset_id)?;
        Some(revalue_msg(h, &reserve, &minted, &self.pool_words(h.asset_id), rule.p))
    }

    /// ⭐ VERIFY the five liquidation legs against THIS ledger's state — the ONE verification site, shared by the door
    /// and by any pre-check, so the two can never disagree. Every commitment a leg is checked against that the object
    /// does not carry is read HERE from consensus state (the PSM's reserve and supply, the pool's `(T, P, S)`, the rule
    /// from the folded mark), so a caller cannot supply a favourable one. The weld is by equal commitments:
    ///   (1) amount   `[reserve, minted, DC, DS, T]` under the rule — the PSM is DUE and `(C, S)` is the ONE capped rule's
    ///                value (`C = min(⌈N/Q⌉, M, T)`: a pool smaller than the retire is burned whole);
    ///   (2) pool     `[new_T, DC, T]` (StabilityPool) — the pool burns exactly `C`;
    ///   (3) step     `[T, DC, DS, P, P_new, S, S_new]` + `close` — the depositors' product and sum move by `(C, S)`;
    ///   (4) retire   `[new_minted, DC, minted]` (Retire) — the supply falls by exactly the `C` the pool burned;
    ///   (5) seize    `[new_reserve, DS, reserve]` (Seize) — the reserve falls by exactly the `S` the pool is owed.
    #[must_use]
    pub fn verify_liquidation_legs(
        &self,
        h: &crate::liquidation_tx::LiquidationHeader,
        legs: &crate::liquidation_tx::LiquidationLegs,
    ) -> bool {
        use usdm_decider::confidential_solvency as cs;
        let (Some((reserve, minted, _)), Some(rule)) = (self.psm_commits(h.asset_id), self.liquidation_rule(h.asset_id)) else {
            return false;
        };
        let pool = self.pool_words(h.asset_id);
        let (dc, ds) = (h.retired_commit, h.seized_commit);
        cs::verify_liquidation_amount_carrier(&legs.amount, &[reserve, minted, dc, ds, pool.t], &rule)
            && cs::verify_transition_carrier(&legs.pool_transition, &[h.new_pool_t, dc, pool.t], cs::TransitionDomain::StabilityPool)
            && cs::verify_pool_step_carrier(&legs.pool_step, &[pool.t, dc, ds, pool.p, h.new_pool_p, pool.s, h.new_pool_s], h.pool_close)
            && cs::verify_transition_carrier(&legs.retire, &[h.new_minted_commit, dc, minted], cs::TransitionDomain::Retire)
            && cs::verify_transition_carrier(&legs.seize, &[h.new_reserve_commit, ds, reserve], cs::TransitionDomain::Seize)
    }

    /// ⭐ THE LIQUIDATION DOOR — THE ONE SHARED FUNCTION through which every close-for-undercollateralization
    /// passes, for the native USDm peg and for every wrapped-asset PSM alike. There is no second encoding of a
    /// position close: [`Self::psm_commits`] is the only reader and [`Self::set_psm_reserve_commit`] the only
    /// writer, both private to this door.
    ///
    /// ROOT-LAYER: this is where the value is PRODUCED, not where it is read. A position's collateral and its
    /// liability exist in exactly one place — the PSM's `(reserve_commit, minted_commit)` pair on this struct —
    /// and this file is the only code that may move either. Closing a position anywhere else (a wallet-side
    /// adjustment, a node-side reconciliation, an RPC handler that "corrects" the reserve) would pass its own test
    /// and silently disagree with the peg-in and peg-out doors that share this state. Hence ONE function, and the
    /// two accessors it uses are private to it.
    /// MEASURED: `grep -c liquidate_confidential` -> rpc_http.rs 0, node.rs 0, chain_object.rs 0 before this diff;
    /// rpc_http.rs 0, node.rs 0, chain_object.rs 0 after it — the door adds no route and no second encoding, and
    /// its only callers are this file's pins plus [`crate::liquidation`]'s sweep.
    /// MUST-STAY-GREEN: the peg's funds-safety theorem tests (`confidential_peg_in_verify_gate`,
    /// `custodian_orchestrates_confidential_mint_and_redeem_from_its_opening`,
    /// `redeem_two_tier_floor_sells_below_150_but_never_below_100`,
    /// `wrapped_asset_per_asset_ratio_stablecoin_exempt_from_150`, `confidential_peg_in_out_wire_path_e2e`,
    /// `confidential_reserve_yield_claim_gate`) — this door adds a path and relaxes none of theirs.
    ///
    /// WHAT IT DOES (v2, spec §10 — Liquity's stability pool, borrowed). When the chain's folded mark puts the PSM under
    /// its due line, the stability pool BURNS `C` USDm its depositors pre-deposited (the pool's `T` falls by `C`), the
    /// circulating supply falls by the SAME `C` (the retire leg — real USDm destroyed, never a supply mark-down with the
    /// notes still circulating), the reserve falls by `S` (the seize leg), and the depositors' running product `P` and
    /// sum `S` move so each depositor's compounded USDm shrinks pro rata and each is owed its share of the `S` seized
    /// collateral, paid at withdrawal. `(C, S)` is the ONE amount rule's value at the mark — the least retire that
    /// restores the target ratio, and the least collateral whose discounted value covers it — so a liquidation can
    /// neither seize more than the rule nor retire less, and the pool buys the collateral at the `DELTA` discount.
    ///
    /// ══ §9.6 THE NEW-DOOR CHECKLIST, answered honestly ═══════════════════════════════════════════════════════
    ///
    /// **Q1 — PROOF OF WORK. n/a on this path, and structurally so.** This is not a DAG ingress: it is a framed
    /// consensus object admitted through the existing `chain_object` `MAGIC||CLASS||payload` mempool class, so the
    /// block carrying it already passed the header gate (`hash_meets_target` + the PQ-VDF heartbeat) at the block
    /// door. The door verifies no grind and must not need to. THE HOLE THAT MAKES THIS QUESTION LOAD-BEARING:
    /// reachability. MEASURED on this lane's own surface — `rpc_http.rs` POST `/register_wrapped_asset` calls
    /// [`Self::register_wrapped_asset`] with no threshold, no vote and no block. RULING, enforced here: no RPC
    /// route may set a threshold or advance a commitment on this path. The threshold has no setter at all
    /// ([`Self::liquidation_threshold_bps`] is derived), and this function's only write is gated on a >=2/3
    /// attestation, so the only caller is a holder of a real quorum attestation. The object rides a block as
    /// `Class::Liquidation` ([`crate::node::objects::liquidation_tx::apply_chain_liquidation`]).
    ///
    /// **Q2 — PROOF / SIGNATURE. TWO independent authorisations, neither sufficient alone, both verified HERE.**
    /// (a) The SAME >=2/3 bonded ML-DSA threshold that already gates peg-in and peg-out — [`threshold_ok`] over
    /// the domain-separated [`revalue_msg`] (`musdm.peg.revalue.v2`), so no peg-in, peg-out or v1 re-mark attestation
    /// the quorum already signed can be replayed as a liquidation.
    /// (b) The five WHIR legs, re-verified by THIS node through [`Self::verify_liquidation_legs`] against ITS OWN
    /// persisted PSM and pool commitments and the rule from ITS OWN folded mark — nothing is taken on trust.
    /// WHAT NEITHER PROOF COVERS, stated plainly: no circuit can prove the MARK is the true market price. The mark is
    /// the chain's bond-weighted median of bonded quotes ([`Self::mark_price_attested`], DB-124/DB-245), discharged
    /// economically by the bond, as on every priced door.
    ///
    /// **Q3 — CONSERVATION. This path can neither create USDm nor reserve, and every unit it destroys is accounted.**
    /// The retire leg proves `new_minted + C = minted` and the pool leg proves `new_T + C = T` over the SAME `DC`, so the
    /// supply falls by exactly the USDm the pool burns — no USDm leaves circulation without a holder's pool deposit
    /// paying for it (the v1 re-mark lowered the supply with the notes still out: a hidden inflation). The seize leg
    /// proves `new_reserve + S = reserve` and the pool step moves the depositors' `S` sum by that SAME `DS`, so the
    /// reserve falls by exactly what the pool is owed. Each new total is range-bound non-negative, so neither leg can
    /// overdraw. The amount carrier proves `(C, S)` is the rule's value for a DUE PSM: a healthy PSM is UNPROVABLE.
    ///
    /// **Q4 — REPLAY. Refused twice.** (i) THE COMMITMENT CHAIN: every leg is verified against the CURRENT reserve,
    /// supply and pool words, and applying advances all of them under blinds derived from the custodians' secret opening
    /// ([`plan_liquidation`]), so the same bytes can never verify twice. (ii) A real SET: the domain-separated
    /// [`liquidation_key`] is recorded in `self.liquidated` (and travels as the object's own nullifier, DB-274 P4b B1), so
    /// one close id applies exactly ONCE. Kept DISTINCT from `spent_burns` — a liquidation must never authorize a release.
    ///
    /// **Q5 — BOUNDED WORK.** [`crate::liquidation_tx::decode`] refuses an empty leg, a leg past the constant WHIR proof
    /// bound, or an attestation list past the producing set BEFORE anything is verified. The cheap checks (the replay
    /// set, the rule) run first; then one threshold tally bounded by `attestors.len()`; then exactly five fixed-shape
    /// WHIR verifies. The door walks no map and allocates nothing.
    ///
    /// **Q6 — PARITY WITH THE DOOR IT PARALLELS: [`Self::peg_out_confidential`]** (the other door that reduces the
    /// reserve). That door runs FIVE checks; here is each, and whether this path carries it.
    ///   1. Replay set on a unique one-time tag — CARRIED (`liquidated` + [`liquidation_key`]).
    ///   2. >=2/3 bonded ML-DSA threshold over a domain-separated, commitment-binding message — CARRIED, same
    ///      [`threshold_ok`], own domain string, binding the before AND after state.
    ///   3. A WHIR carrier verified against the node's OWN persisted commitments — CARRIED, five of them.
    ///   4. Advance the persisted digests — CARRIED: reserve, supply, and the pool words.
    ///   5. Record the one-time tag — CARRIED.
    ///   Peg-out's CONSERVATION (`reserve − release`, `minted − burn`) is carried as the seize and retire legs, and
    ///   STRENGTHENED: the burn here is welded to the pool's `T` by an equal commitment.
    /// ═════════════════════════════════════════════════════════════════════════════════════════════════════════
    ///
    /// Fail-closed throughout: any rejection mutates NOTHING.
    pub fn liquidate_confidential(
        &mut self,
        h: &crate::liquidation_tx::LiquidationHeader,
        legs: &crate::liquidation_tx::LiquidationLegs,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        // (0) Resolve the PSM this door acts on — native or one registered wrapped asset. ONE body, one reader.
        if self.psm_commits(h.asset_id).is_none() {
            return PegOutcome::BadRequest; // unregistered asset — nothing to liquidate
        }
        // (1) Q5 — an empty leg is no proof; the per-leg size bound already ran at the decode.
        if [&legs.amount, &legs.pool_transition, &legs.pool_step, &legs.retire, &legs.seize].iter().any(|l| l.is_empty()) {
            return PegOutcome::BadRequest;
        }
        // (2) Q4(ii) — the SET: this close id already applied.
        //
        // WHAT PRODUCES THE REPEAT, and why this branch is not a patch over a bug of ours:
        //   1. THE CAUSE IS OUTSIDE THIS TREE. A second close of the same position arrives as BYTES FROM A PEER —
        //      a re-broadcast of the block-carried object, a fork replaying the same object on a second branch,
        //      or an adversary deliberately submitting it twice to seize a position's collateral twice. There is
        //      no writer of ours emitting a duplicate; there is nothing in our code to delete.
        //   2. IT CANNOT BE DELETED, and the repeat is NOT empty or identical-and-harmless. Measured by
        //      `liquidation_replay_closes_a_position_exactly_once`: the second attempt can carry a FRESHLY BUILT,
        //      fully valid carrier and a FRESH >=2/3 attestation over the ADVANCED state — bytes that differ from
        //      the first in every field and that the commitment chain alone would accept. Dropping this set would
        //      let one position be seized twice.
        //   3. SO IT STAYS, and it is the cheap check on purpose: it runs before the threshold verify and before
        //      the WHIR verify, so a flood of replays costs a hash and a set lookup, never a proof.
        let key = liquidation_key(h.epoch_id, h.asset_id, &h.position_id);
        if self.liquidated.contains(&key) {
            return PegOutcome::Replay;
        }
        // (3) Q2(a) — the >=2/3 bonded ML-DSA threshold over the v2 message, which binds the state the legs were proven
        //     against and the rule from THIS node's folded mark (an unpriced PSM or an inadmissible rule has no message:
        //     it is not liquidatable).
        let Some(msg) = self.liquidation_attest_msg(h) else {
            return PegOutcome::BadRequest;
        };
        let pool = self.pool_words(h.asset_id);
        // SAFE AT SCALE: a liquidation moves TWO hidden states — the ledger of the vault that keeps the coins, whose
        // opening only that vault's custodians hold, and the asset's ONE stability pool, whose opening every custodian
        // holds. So a custody-funded ledger's liquidation is signed like a deposit the whole set carries
        // (`vault_signed`, no ride): two thirds of the whole bonded weight (they judge the pool's legs) and, with more than
        // one vault, two thirds of the vault's own (they judge the ledger's). On a one-vault chain: the one tally, as it was.
        // CHAIN-OBJECT: the `Class::Liquidation` object the block carries — its own signatures, read against the
        // chain-derived bonded set; nothing moves before the legs verify below.
        let signed = if Self::is_custody_funded(h.asset_id) {
            Self::vault_signed(ledger_vault(h.asset_id), false, quorum, verifier, &msg, attestors).is_ok()
        } else {
            threshold_ok(quorum, verifier, &msg, attestors)
        };
        if !signed {
            return PegOutcome::InsufficientThreshold;
        }
        // (5) Q2(b) + Q3 — the five WHIR legs through the ONE verification site.
        if !self.verify_liquidation_legs(h, legs) {
            return PegOutcome::BadRequest;
        }
        // (6) APPLY — the PSM's pair, the pool's words (a CLOSE keeps the closing `(P, S)` for the epoch's receipts and
        //     restarts the pool at the public `P = 2^128`, `S = 0`), and the replay set. `reserve_hwm_commit` is untouched.
        self.set_psm_commits(h.asset_id, h.new_reserve_commit, h.new_minted_commit);
        let moved = PoolWords { t: h.new_pool_t, p: h.new_pool_p, s: h.new_pool_s, epoch: pool.epoch };
        if h.pool_close {
            self.pool_closes.insert((ledger_asset(h.asset_id), pool.epoch), moved);
            let fresh = PoolWords::genesis();
            self.set_pool_words(h.asset_id, PoolWords { t: h.new_pool_t, p: fresh.p, s: fresh.s, epoch: pool.epoch + 1 });
        } else {
            self.set_pool_words(h.asset_id, moved);
        }
        self.liquidated.insert(key);
        self.applied_ids.push((key, 3));
        PegOutcome::Liquidated
    }

    // ── AUDIT-ONLY FORCERS — TEST BUILDS ONLY ────────────────────────────────────────────────────────────────
    //
    // ⛔ THESE ARE NOT DOORS. Each writes a peg field with NO threshold, NO carrier and NO block behind it —
    // which is precisely the defect class the audit hunts ("local state read as truth"). They exist for ONE
    // reason: `harness::fuzz::authority_peg` declares each of these fields to be the CHAIN's, and a declaration
    // nothing can be made to CONTRADICT is a comment with a test name. Building the contradicting state is the
    // only way to prove the comparison that guards the field is not blind.
    //
    // Every field below already lacks a production writer ON PURPOSE (`ratio_bps` is a consensus policy
    // parameter, `reserve_hwm_commit` is the bound the liquidation door may not raise, `spent_burns` is only
    // ever written by a >=2/3-attested peg-out or yield claim) — so a `#[cfg(test)]` forcer is the ONLY way to
    // express the violation without weakening a real gate. The name says "audit" at every call site,
    // deliberately, so nothing production-shaped can ever grow a call to one.

    /// ⛔ AUDIT ONLY — force the MINT collateral ratio with no governance path behind it.
    ///
    /// The violating state for the `ratio_bps` comparison: a node applying a different over-collateralization
    /// rule to the same block. It authorizes mints its peers refuse, against collateral that does not cover
    /// them, and every gate on that node agrees with itself perfectly because they share the wrong yardstick.
    #[cfg(test)]
    pub fn force_ratio_bps_for_audit(&mut self, ratio_bps: u32) {
        self.ratio_bps = ratio_bps;
    }

    /// ⛔ AUDIT ONLY — force the reserve HIGH-WATER MARK, the ceiling a liquidation re-mark may not exceed.
    ///
    /// The violating state for the `reserve_hwm_commit` comparison. `liquidate_confidential` deliberately
    /// cannot raise this bound; a node that simply HOLDS a higher one has the same effect without ever
    /// touching the door — it can prove an UP-MARK past collateral that was never deposited, which is the
    /// up-mark-then-mint inflation §9.6 Q3 exists to make unprovable.
    #[cfg(test)]
    pub fn force_reserve_hwm_commit_for_audit(&mut self, hwm: crate::spend_frontier::Digest4) {
        self.reserve_hwm_commit = hwm;
    }

    /// ⛔ AUDIT ONLY — how many burned-USDm nullifiers this ledger holds. A COUNT, never the entries.
    ///
    /// The same shape and the same privacy rule as `Node::order_book_len_for_audit`, which the cold-peer
    /// verdict already rides: a SIZE is chain-public (every node must agree on it to agree about what has
    /// been spent), the entries are not, and no amount or owner is exposed by either. Read-only, and it
    /// cannot answer "is THIS note burned?" — [`Self::is_burned`] stays the one door for that question.
    #[cfg(test)]
    pub fn spent_burn_count_for_audit(&self) -> usize {
        self.spent_burns.len()
    }

    /// ⛔ AUDIT ONLY — how many confidential peg-in deposit ids this ledger has consumed. A COUNT only.
    ///
    /// The replay guard that makes one foreign deposit mint exactly once. Two nodes that disagree about its
    /// size disagree about which deposits have already been minted, and the one holding fewer will mint
    /// against a deposit that already paid out.
    #[cfg(test)]
    pub fn confidential_deposit_id_count_for_audit(&self) -> usize {
        self.confidential_deposit_ids.len()
    }

    /// ⛔ AUDIT ONLY — record a burned-USDm nullifier with no burn behind it. Returns whether it was new.
    ///
    /// The violating state for the `spent_burns` comparison, and the sharpest of them:
    /// [`crate::node::Node::settle_reserve_release_observed`] gates the FOREIGN payout leg on [`Self::is_burned`],
    /// so a node holding an entry the chain never produced will authorize real BTC/XMR leaving the reserve
    /// with no destroyed USDm behind it. The return value is the non-vacuity handle — `false` means the set
    /// already held it and nothing was built.
    #[cfg(test)]
    pub fn force_spent_burn_for_audit(&mut self, usdm_nullifier: [u8; 32]) -> bool {
        self.spent_burns.insert(usdm_nullifier)
    }

    /// ⛔ AUDIT ONLY — consume a confidential peg-in deposit id with no deposit behind it. Returns whether
    /// it was new (the non-vacuity handle).
    ///
    /// The violating state for the `confidential_deposit_ids` comparison. The set exists so one confirmed
    /// foreign deposit mints exactly once; a node whose set disagrees with the chain's either mints against
    /// a deposit that already paid out, or refuses a depositor their first and only mint.
    #[cfg(test)]
    pub fn force_confidential_deposit_id_for_audit(&mut self, deposit_id: [u8; 32]) -> bool {
        self.confidential_deposit_ids.insert(deposit_id)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::bridge::Custodian;
    use crate::pqauth::MlDsaVerifier;
    use crate::validator::ValidatorSet;

    // #75 brick 3d: the node's CONFIDENTIAL peg-in verify gate — the node VERIFIES a WHIR-BOUND peg-in carrier
    // over HIDDEN 256-bit amounts (never recomputing supply), against ITS OWN persisted commitments. A valid
    // 150% mint verifies + advances the digest; a proof for a DIFFERENT claimed new state rejects; an over-mint
    // is UNPROVABLE (no inflation path). This replaces the plaintext `is_solvent` recompute — the node holds only
    // opaque commitments, never a total.
    #[test]
    fn confidential_peg_in_verify_gate() {
        use usdm_decider::confidential_solvency as cs;
        let (r_blind, m_blind) = (
            usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
        );
        // the node's persisted OLD state: reserve 1500 backs 1000 minted at exactly 150% — held as opaque digests.
        let (mut peg, openings) = super::ledger_at_for_test(15_000, 1_500, r_blind, 1_000, m_blind);
        // the custodian threshold proves a 150%-collateralized peg-in: +1500 reserve, +1000 minted — §19.5b: as the cover over
        // BOTH bridge ledgers. DB-80: the mint delta rides COMMITTED (`d_blind` is the requester's blind).
        let d_blind = usdm_decider::poseidon2_compress::lanes_of(&[17, 18, 19, 20]);
        let (bytes, new_rc, new_mc, after) = peg
            .orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &openings, 1_500, 1_000, &d_blind, &d_blind, None)
            .expect("custodian threshold proves a 150%-collateralized mint");
        let delta_commit = PegLedger::mint_delta_commit(1_000, d_blind);
        assert!(
            peg.verify_confidential_peg_in(&bytes, new_rc, new_mc, delta_commit),
            "node VERIFIES the confidential mint against its persisted commitments (no recompute)"
        );
        // a proof advanced to a DIFFERENT claimed new minted commitment REJECTS.
        let mut wrong = new_mc;
        wrong[0] ^= 1;
        assert!(!peg.verify_confidential_peg_in(&bytes, new_rc, wrong, delta_commit), "a tampered claimed new commitment REJECTS");
        // DB-80 REFUTATION: the same carrier under a DIFFERENT claimed delta commitment REJECTS — the committed mint figure is
        // bound by the proof, so a note proving another amount cannot be paired with this transition.
        let other_delta = PegLedger::mint_delta_commit(1_001, d_blind);
        assert!(!peg.verify_confidential_peg_in(&bytes, new_rc, new_mc, other_delta), "a carrier paired with another mint-delta commitment REJECTS");
        // apply advances the persisted digest pairs of BOTH bridge ledgers (the confidential minted_usdm += mint).
        let posts = peg.verify_cover(true, &bytes, (new_rc, new_mc), delta_commit, None).expect("the door's verify");
        peg.apply_cover(&posts);
        assert_eq!((peg.reserve_commit(), peg.minted_commit()), posts[0], "persisted native commitments advanced");
        assert_eq!(PegLedger::commits_of_opening(after[0].0, after[0].1, after[0].2, after[0].3), posts[0], "the opening opens them");
        assert_eq!((after[0].0, after[0].2), (3_000, 2_000));
        // an over-mint (mint 1001 vs a 1500 deposit at 150%) is UNPROVABLE — the gate has NO inflation path.
        assert!(
            peg.orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &after, 1_500, 1_001, &d_blind, &d_blind, None).is_none(),
            "over-mint is UNPROVABLE — the confidential gate is fail-closed"
        );
        let _ = cs::u256_from_u64(0);
    }

    // CUSTODIAN ORCHESTRATION — the node builds the confidential mint/redeem carrier FROM ITS OWN OPENING (the
    // depositor's wallet cannot: it has no reserve secret). Proves the orchestrated carrier verifies against the
    // persisted commitments, the opening carries forward across ops, and over-mint / over-drain are fail-closed.
    #[test]
    fn custodian_orchestrates_confidential_mint_and_redeem_from_its_opening() {
        use usdm_decider::confidential_solvency as cs;
        // GENESIS state: both bridge ledgers at 0 / 0 under their genesis blinds — the openings the custodian holds off-ledger.
        let (mut peg, o0) = super::ledger_at_for_test(15_000, 0, GENESIS_PEG_RESERVE_BLIND, 0, GENESIS_PEG_MINTED_BLIND);
        // 1) The NODE orchestrates a 150% mint (deposit 3000 → mint 2000) from its OWN openings; the wallet supplies NO carrier.
        let d1 = usdm_decider::poseidon2_compress::lanes_of(&[0xd1, 0, 0, 1]);
        let (carrier, new_rc, new_mc, o1) = peg
            .orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &o0, 3_000, 2_000, &d1, &d1, None)
            .expect("custodian orchestrates a 150%-backed mint from its opening");
        let dc1 = PegLedger::mint_delta_commit(2_000, d1);
        // 2) The orchestrated carrier VERIFIES against the node's persisted commitments (the real consensus gate).
        assert!(peg.verify_confidential_peg_in(&carrier, new_rc, new_mc, dc1), "orchestrated carrier verifies");
        // 3) apply + carry the openings forward (shadowed locals, never a stored counter).
        let posts = peg.verify_cover(true, &carrier, (new_rc, new_mc), dc1, None).expect("verifies");
        peg.apply_cover(&posts);
        assert_eq!(peg.reserve_commit(), posts[0].0);
        assert_eq!(cs::solvency_commit_256(cs::u256_from_u64(o1[0].0 as u64), o1[0].1), posts[0].0, "opening stays consistent with the committed digest");
        assert_eq!((o1[0].0, o1[0].2, o1[1].0, o1[1].2), (3_000, 2_000, 0, 0), "the native opening moved, Monero's by zero");
        // 4) The NEXT mint orchestrates from the ADVANCED openings (proves they carry forward correctly).
        let d2 = usdm_decider::poseidon2_compress::lanes_of(&[0xd2, 0, 0, 2]);
        let (c2, rc2, mc2, _) = peg
            .orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &o1, 1_500, 1_000, &d2, &d2, None)
            .expect("second mint orchestrates from the advanced opening");
        assert!(
            peg.verify_confidential_peg_in(&c2, rc2, mc2, PegLedger::mint_delta_commit(1_000, d2)),
            "second orchestrated carrier verifies against the advanced state"
        );
        // ⛔ the stale (genesis) openings prove nothing once the chain moved
        assert!(peg.orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &o0, 1_500, 1_000, &d2, &d2, None).is_none(), "⛔ a stale opening proved");
        // 5) An UNDER-collateralized mint (mint 2001 vs a 3000 deposit at 150% ⇒ needs ≤2000) is UNPROVABLE → None.
        assert!(
            peg.orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &o1, 3_000, 2_001, &d2, &d2, None).is_none(),
            "over-mint orchestration is fail-closed (no inflation)"
        );
        // 6) A REDEEM orchestrates the mirror reduction at $1 of reserve per USDm (release 200 / burn 200); a release worth
        //    more than its burn is UNPROVABLE (DB-470: the per-transaction cap) — the old aggregate gate let 300 / 200 through.
        let bb = peg_out_burn_blind(&d1);
        assert!(peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &o1, 200, 200, &d1, &bb, None).is_some(), "custodian orchestrates a $1-per-USDm redeem");
        assert!(peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &o1, 300, 200, &d1, &bb, None).is_none(), "⛔ DB-470: a release worth more than its burn proved");
        assert!(peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &o1, 3_000, 200, &d1, &bb, None).is_none(), "over-drain redeem is fail-closed");
    }

    // ⭐ DB-470 — THE REDEMPTION RULE IS PER TRANSACTION: a burn releases at most $1 of reserve per USDm (the redeem floor) and at
    // most its pro-rata share of the reserve. Above 100 % every holder redeems exactly $1 whatever the system's ratio (a price drop
    // never freezes a cash-out); under 100 % each burn takes exactly its share, so no early redeemer drains a later one. The
    // peg-out is HOLDER-AGNOSTIC — it sees only an opaque burn + commitment reduction, never who redeems or which note.
    #[test]
    fn redeem_is_one_dollar_per_usdm_and_pro_rata_under_100() {
        use usdm_decider::confidential_solvency as cs;
        let _ = cs::u256_from_u64(0); // (cs used for the commitment types the orchestration returns)
                                      // Reach a real 150%-backed state (reserve 3000 backs 2000 minted) via the SAME proven orchestration path the
                                      // custodian uses live — no hand-set counter.
        let mut peg = PegLedger::genesis(15_000);
        assert_eq!(
            peg.ratio_bps(),
            15_000,
            "MINT ratio stays 150% — deposits always over-collateralize on the way IN"
        );
        assert_eq!(
            peg.redeem_floor_bps(),
            10_000,
            "REDEEM floor defaults to 100% — the true-solvency line"
        );
        let (xr, xm) = psm_genesis_blinds(XMR_PEG_ASSET_ID);
        let o0 = [(0u128, GENESIS_PEG_RESERVE_BLIND, 0u128, GENESIS_PEG_MINTED_BLIND), (0u128, xr, 0u128, xm)];
        let d0 = usdm_decider::poseidon2_compress::lanes_of(&[0xd0, 0, 0, 3]);
        let (carrier, new_rc, new_mc, o1) = peg
            .orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &o0, 3_000, 2_000, &d0, &d0, None)
            .expect("150%-backed mint from genesis opening");
        let dc0 = PegLedger::mint_delta_commit(2_000, d0);
        assert!(peg.verify_confidential_peg_in(&carrier, new_rc, new_mc, dc0));
        let posts = peg.verify_cover(true, &carrier, (new_rc, new_mc), dc0, None).expect("verifies");
        peg.apply_cover(&posts);
        let bb = peg_out_burn_blind(&d0);

        // (A) ⛔⛔ DB-470 — A REDEMPTION IS $1 OF RESERVE PER USDm, NEVER THE BUFFER. Until 2026-10-29 this test ALLOWED release 500
        //     against burn 100 (the post state cleared 100 %): one holder took $5 of reserve per USDm — the surplus every other
        //     holder's $1 rests on. The per-transaction cap refuses it; the $1 redemption from the same state proves.
        assert!(
            peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &o1, 500, 100, &d0, &bb, None).is_none(),
            "⛔ DB-470: a redemption took $5 of reserve per USDm burned"
        );
        assert!(
            peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &o1, 100, 100, &d0, &bb, None).is_some(),
            "a $1-per-USDm redemption proves"
        );

        // (B) UNDER 100 % NO CASH-OUT IS FROZEN AND NONE TAKES ANOTHER HOLDER'S SHARE: at an 80 % state (2,400 backing 3,000 — a
        //     price crash, no exploit) the burn's pro-rata share (100 × 2,400 / 3,000 = 80) proves; $1 (100) does not.
        // measured on the carrier at the crashed totals (the custodians' opening is the only place the totals exist)
        let (cr, cm) = (2_400u128, 3_000u128);
        let floor = cs::Backing::at_unit_price(10_000);
        let u = cs::u256_from_u64;
        let (rb, mb) = (usdm_decider::poseidon2_compress::lanes_of(&[1]), usdm_decider::poseidon2_compress::lanes_of(&[2]));
        let (nrb, nmb) = (usdm_decider::poseidon2_compress::lanes_of(&[3]), usdm_decider::poseidon2_compress::lanes_of(&[4]));
        assert!(
            cs::prove_peg_out_carrier(u(cr as u64), u(cm as u64), u(80), u(100), rb, mb, nrb, nmb, floor).is_some(),
            "⛔ DB-470: a fair pro-rata cash-out at an 80 % system was refused"
        );
        assert!(
            cs::prove_peg_out_carrier(u(cr as u64), u(cm as u64), u(100), u(100), rb, mb, nrb, nmb, floor).is_none(),
            "⛔ DB-470: under 100 % a $1 cash-out took the later holders' share"
        );
        assert_eq!(PegLedger::release_within_share_for(NATIVE_PEG_ASSET_ID, 100, 100, cr, cm), Some(80), "under 100 %: the exact pro-rata share");
        assert_eq!(PegLedger::release_within_share_for(XMR_PEG_ASSET_ID, 100, 100, cr, cm), Some(80), "the same rule on Monero's ledger");
        assert_eq!(PegLedger::release_within_share_for(NATIVE_PEG_ASSET_ID, 100, 100, 3_000, 2_000), Some(100), "solvent: the $1 release stands");

        // (C) THE ADAPTIVE FEE RISES AS BACKING FALLS — the convex (u²) utilization curve: drawing a larger share of
        //     the reserve costs a strictly higher fee, disincentivizing the drain (the fee stays IN the reserve,
        //     replenishing the buffer). This is the "fees simply rise" mechanism, sound by construction.
        let fee_small = withdrawal_fee_bps(3_000, 500, 50, 9_000);
        let fee_large = withdrawal_fee_bps(3_000, 1_500, 50, 9_000);
        assert!(
            fee_large > fee_small,
            "the withdraw fee rises convexly as the redemption draws the reserve buffer down"
        );

        // (D) GOVERNANCE CANNOT LOWER THE FLOOR BELOW 100% (clamped to the true line) but CAN raise it (bigger buffer).
        peg.set_redeem_floor_bps(5_000);
        assert_eq!(
            peg.redeem_floor_bps(),
            10_000,
            "a below-100% floor set is clamped up to 100% — the line can't move down"
        );
        peg.set_redeem_floor_bps(12_000);
        assert_eq!(
            peg.redeem_floor_bps(),
            12_000,
            "governance may RAISE the redeem floor (a larger safety buffer)"
        );
    }

    // WRAPPED-ASSET per-asset mint (IonSwap bridge): each asset has its OWN ratio. A VOLATILE asset (wBTC, 15000)
    // needs 150%; a STABLECOIN (wDAI, 10000) mints at 1:1 (EXEMPT from the 150% buffer). Under-collateralization vs
    // the asset's ratio is UNPROVABLE (no inflation). Per-asset isolation: one asset's mint never touches another's.
    #[test]
    fn wrapped_asset_per_asset_ratio_stablecoin_exempt_from_150() {
        const WBTC: u32 = 3; // 1 is Monero's bridge ledger
        const WDAI: u32 = 2;
        let mut peg = PegLedger::genesis(15_000);
        peg.register_wrapped_asset(WBTC, 15_000); // volatile
        peg.register_wrapped_asset(WDAI, 10_000); // stablecoin — 100%, exempt from the 150%
        assert_eq!(peg.wrapped_asset_ratio_bps(WBTC), Some(15_000));
        assert_eq!(
            peg.wrapped_asset_ratio_bps(WDAI),
            Some(10_000),
            "a stablecoin registers at 100% (fee-exempt)"
        );
        // a stablecoin can NEVER be set below 1:1 (clamped to 10000) — no sub-1:1 backing insolvency.
        peg.register_wrapped_asset(WDAI, 5_000);
        assert_eq!(
            peg.wrapped_asset_ratio_bps(WDAI),
            Some(10_000),
            "a sub-1:1 ratio is clamped to 100% (true-solvency floor)"
        );

        // Every mint below is orchestrated from the SAME fresh genesis-0 opening (orchestrate is &self — no mutation), under
        // the wrapped ledger's OWN genesis blinds.
        let (rb, mb) = psm_genesis_blinds(WBTC);
        let (rbd, mbd) = psm_genesis_blinds(WDAI);
        let (r0, m0) = (0u128, 0u128);
        let wdb = usdm_decider::poseidon2_compress::lanes_of(&[0xdbu64, 0x80, 0xb, 0x1]); // DB-80b: the requester's blind

        // (A) VOLATILE wBTC needs 150%: deposit 1500 -> mint 1000 (150%) PROVES; deposit 1000 -> mint 1000 (100%) does NOT.
        assert!(
            peg.orchestrate_wrapped_mint(WBTC, r0, rb, m0, mb, 1_500, 1_000, wdb)
                .is_some(),
            "a 150%-backed wBTC wrap proves"
        );
        assert!(
            peg.orchestrate_wrapped_mint(WBTC, r0, rb, m0, mb, 1_000, 1_000, wdb)
                .is_none(),
            "a 100%-backed wBTC wrap is UNPROVABLE (volatile needs 150%)"
        );

        // (B) STABLECOIN wDAI is EXEMPT from 150%: deposit 1000 -> mint 1000 (1:1) PROVES; deposit 900 -> mint 1000 (<100%) does NOT.
        assert!(
            peg.orchestrate_wrapped_mint(WDAI, r0, rbd, m0, mbd, 1_000, 1_000, wdb)
                .is_some(),
            "a 1:1 wDAI wrap proves (stablecoin exempt from 150%)"
        );
        assert!(
            peg.orchestrate_wrapped_mint(WDAI, r0, rbd, m0, mbd, 900, 1_000, wdb)
                .is_none(),
            "a sub-1:1 wDAI wrap is UNPROVABLE (below true solvency)"
        );

        // (C) an UNREGISTERED asset cannot mint (fail-closed).
        assert!(
            peg.orchestrate_wrapped_mint(999, r0, rb, m0, mb, 2_000, 1_000, wdb)
                .is_none(),
            "an unregistered asset cannot mint"
        );

        // (D) VERIFY + APPLY is per-asset + no cross-asset inflation, and no double-mint.
        let (c, rc, mc, _, _, dc) = peg
            .orchestrate_wrapped_mint(WDAI, r0, rbd, m0, mbd, 1_000, 1_000, wdb)
            .expect("wDAI mint");
        assert_eq!(dc, PegLedger::mint_delta_commit(1_000, wdb), "the wrapped carrier opens commit(mint, d_blind)");
        let wbtc_before = peg.wrapped_asset_commits(WBTC).unwrap();
        // DB-80b REFUTATION: the same carrier under another delta commitment REJECTS (and moves nothing)
        assert!(
            !peg.verify_and_apply_wrapped_mint(WDAI, &c, rc, mc, PegLedger::mint_delta_commit(1_001, wdb)),
            "a wrapped carrier paired with another mint-delta commitment REJECTS"
        );
        assert!(
            peg.verify_and_apply_wrapped_mint(WDAI, &c, rc, mc, dc),
            "the wDAI wrap verifies + advances"
        );
        assert_eq!(
            peg.wrapped_asset_commits(WBTC).unwrap(),
            wbtc_before,
            "applying a wDAI mint does NOT touch wBTC (per-asset isolation)"
        );
        assert!(
            !peg.verify_and_apply_wrapped_mint(WDAI, &c, rc, mc, dc),
            "replaying the SAME wrap carrier is rejected (no double-mint)"
        );
    }

    // #75 — the full CONFIDENTIAL PEG-IN + PEG-OUT WIRE PATH: threshold-attest the COMMITMENT transition (never an
    // amount) + verify the WHIR-bound carrier, advancing the opaque digest. No cleartext deposit/mint/burn value
    // touches the ledger op. Replay + a bad threshold fail closed; the reduction verifies the round-trip.
    #[test]
    fn confidential_peg_in_out_wire_path_e2e() {
        use usdm_decider::confidential_solvency as cs;
        let (custodians, vs) = quorum();
        let (r_blind, m_blind, nr_blind) = (
            usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]),
            usdm_decider::poseidon2_compress::lanes_of(&[5, 6, 7, 8]),
            usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]),
        );
        // persisted current state: reserve 3000 backs 2000 minted (exactly 150%), as opaque digests.
        let (mut peg, openings) = super::ledger_at_for_test(15_000, 3_000, r_blind, 2_000, m_blind);
        // CONFIDENTIAL PEG-IN: custodian mints +900 reserve / +600 minted → 3900/2600 (still ≥150%), as the §19.5b cover.
        // DB-80: the +600 rides as a commitment under the requester's blind.
        let d_blind = usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]);
        let (in_bytes, in_rc, in_mc, after_in) = peg
            .orchestrate_cover(true, NATIVE_PEG_ASSET_ID, &openings, 900, 600, &d_blind, &d_blind, None)
            .expect("confidential mint proves");
        let in_delta = PegLedger::mint_delta_commit(600, d_blind);
        let in_posts = CoverBlob::decode(&in_bytes).expect("a cover blob").posts;
        let did = [7u8; 32];
        let rcpt = [9u8; 32];
        let nonce = [0x5eu8; 32];
        let in_msg = peg_in_confidential_msg(
            &did,
            &in_rc,
            &in_mc,
            &in_delta,
            &rcpt,
            &nonce,
        );
        // FUNDS-LOSS-IMPOSSIBLE bond backstop: the quorum bonds 10000 total, the new reserve is 3900, so
        // 10000 ≥ 2×3900 PROVES — the mint is admitted only while the bond over-covers the reserve.
        let (backstop, _) = cs::prove_peg_in_carrier(
            cs::u256_from_u64(10_000),
            cs::u256_from_u64(3_900),
            cs::u256_from_u64(0),
            cs::u256_from_u64(0),
            super::BOND_BACKSTOP_BLIND,
            nr_blind,
            super::BOND_BACKSTOP_BLIND,
            nr_blind,
            cs::Backing::at_unit_price(20_000),
        )
        .expect("bond backstop proves (bond ≥ 2× reserve)");
        // a WRONG threshold (empty) fails closed — no mint. (The field the old backstop rode is the deposit's vault ride
        // now: empty on a one-vault chain.)
        assert!(matches!(
            peg.peg_in_confidential(did, &in_bytes, in_rc, in_mc, in_delta, rcpt, nonce, &[], &vs, &MlDsaVerifier, &[]),
            PegOutcome::InsufficientThreshold
        ));
        // the real ≥2/3 threshold over the COMMITMENT message authorizes it.
        let att = attest(&custodians, &in_msg);
        // ⛔ SAFE AT SCALE: bytes in the ride field that are no ride — here the retired backstop's own proof — refuse the
        // object; they are never read as "vault 0"
        assert!(
            matches!(peg.peg_in_confidential(did, &in_bytes, in_rc, in_mc, in_delta, rcpt, nonce, &backstop, &vs, &MlDsaVerifier, &att), PegOutcome::BadRequest),
            "⛔ a deposit whose ride field holds something that is no ride was taken"
        );
        assert!(matches!(
            peg.peg_in_confidential(did, &in_bytes, in_rc, in_mc, in_delta, rcpt, nonce, &[], &vs, &MlDsaVerifier, &att),
            PegOutcome::ConfidentialMinted
        ));
        assert_eq!(peg.reserve_commit(), in_posts[0].0, "persisted reserve digest advanced (no amount seen)");
        assert_eq!(peg.minted_commit(), in_posts[0].1);
        assert_eq!(peg.psm_commits(XMR_PEG_ASSET_ID).map(|c| (c.0, c.1)), Some(in_posts[1]), "§19.5b: Monero's pair stepped too");
        // a mint that would push the reserve ABOVE half the bond is UNBONDED → rejected (funds-loss-impossible gate):
        // bond 10000, a claimed reserve of 6000 needs 12000 bond → the backstop is UNPROVABLE.
        assert!(
            cs::prove_peg_in_carrier(
                cs::u256_from_u64(10_000),
                cs::u256_from_u64(6_000),
                cs::u256_from_u64(0),
                cs::u256_from_u64(0),
                super::BOND_BACKSTOP_BLIND,
                nr_blind,
                super::BOND_BACKSTOP_BLIND,
                nr_blind,
                cs::Backing::at_unit_price(20_000)
            )
            .is_none(),
            "reserve above bond/2 → the bond backstop is UNPROVABLE (funds-loss-impossible)"
        );
        // REPLAY the same deposit id → rejected, mutates nothing.
        assert!(matches!(
            peg.peg_in_confidential(did, &in_bytes, in_rc, in_mc, in_delta, rcpt, nonce, &[], &vs, &MlDsaVerifier, &att),
            PegOutcome::Replay
        ));
        // CONFIDENTIAL PEG-OUT: redeem 200 reserve / burn 200 USDm from 3900/2600 → 3700/2400 — $1 of reserve per USDm at
        // the REDEEM floor (10000 = 100 %), the per-transaction cap (DB-470); the old fixture released 300 for 200, which the
        // aggregate gate admitted and the cap refuses (`redeem_is_one_dollar_per_usdm_and_pro_rata_under_100`).
        // ⭐ B15: the cash-out carries its proof bundle — the committed burn and the burn-bound carrier
        let leg = usdm_decider::poseidon2_compress::lanes_of(&[0xb7, 1, 1, 1]);
        let (out_bytes, nf, out_lc, out_cm, (out_rc, out_mc), _) =
            super::peg_out_proofs_for_test(&peg, &after_in, NATIVE_PEG_ASSET_ID, 200, 200, &leg, &[0xb7u8; 32])
                .expect("confidential redeem proves from the CURRENT persisted state");
        let out_posts = CoverBlob::decode(&crate::peg_out_tx::PegOutProofs::decode(&out_bytes).expect("proofs").solvency).expect("a cover").posts;
        let out_msg = peg_out_confidential_msg(
            &nf,
            &out_rc,
            &out_mc,
            &[0xb7u8; 32], &[0u8; 32], &out_lc, &[0u8; 32], &out_cm);
        let out_att = attest(&custodians, &out_msg);
        assert!(matches!(
            peg.peg_out_confidential(
                nf,
                &out_bytes,
                out_rc,
                out_mc,
                &[0xb7u8; 32], &[0u8; 32], out_lc, &[0u8; 32], &out_cm,
                &vs,
                &MlDsaVerifier,
                &out_att
            ),
            PegOutcome::ConfidentialRedeemed
        ));
        assert_eq!(peg.reserve_commit(), out_posts[0].0, "persisted reserve digest reduced (no amount seen)");
        // a serialized snapshot of the ledger discloses NO plaintext reserve/minted total — only opaque digests.
        let snap = postcard::to_stdvec(&peg).expect("serialize");
        // 3900/2600/3700/2400 as LE bytes must NOT appear as any 16-byte value aggregate in the persisted state.
        for total in [3_900u128, 2_600, 3_700, 2_400, 900, 600] {
            assert!(
                !snap.windows(16).any(|w| w == total.to_le_bytes()),
                "no plaintext total {} in the serialized ledger",
                total
            );
        }
    }

    // ── LIQUIDATION v2 DOOR PINS (spec §10) ────────────────────────────────────────────────────────────────
    //
    // A PSM at reserve 3000 / minted 2000 and a stability pool of `t` USDm, priced by the chain's own mark through the
    // real ≥2/3 quote door. The custodian's opening builds the five legs; TWO independently constructed ledgers (A and
    // a peer B) apply the same bytes, and every assertion is on what a ledger HOLDS.
    struct LiqV2 {
        a: PegLedger,
        b: PegLedger,
        open: LiquidationOpening,
        custodians: Vec<Custodian>,
    }

    fn liq_v2(t: u128, mark: u128) -> (LiqV2, ValidatorSet) {
        use usdm_decider::confidential_solvency as cs;
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let (custodians, vs) = quorum();
        let open = LiquidationOpening {
            reserve: 3_000,
            reserve_blind: l(&[21, 22, 23, 24]),
            minted: 2_000,
            minted_blind: l(&[31, 32, 33, 34]),
            pool_t: t,
            pool_t_blind: l(&[41, 42, 43, 44]),
            pool_p: POOL_P_SCALE,
            pool_p_blind: GENESIS_POOL_P_BLIND,
            pool_s: [0; 4],
            pool_s_blind: GENESIS_POOL_S_BLIND,
        };
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, NATIVE_PEG_ASSET_ID, mark));
                crate::price_mark_tx::PriceQuote { price: mark, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        let ledger = || {
            let mut p = PegLedger::new(15_000);
            p.initialize_solvency_commitments(
                cs::solvency_commit_256(u256_from_u128(open.reserve), open.reserve_blind),
                cs::solvency_commit_256(u256_from_u128(open.minted), open.minted_blind),
            );
            let g = PoolWords::genesis();
            p.set_pool_words(NATIVE_PEG_ASSET_ID, PoolWords { t: cs::solvency_commit_256(u256_from_u128(t), open.pool_t_blind), ..g });
            assert_eq!(
                p.mark_price_attested(1, NATIVE_PEG_ASSET_ID, &quotes, &vs, &MlDsaVerifier),
                PegOutcome::PriceMarked(mark),
                "CALIBRATION: the chain marks the price through its own door"
            );
            p
        };
        let (a, b) = (ledger(), ledger());
        (LiqV2 { a, b, open, custodians }, vs)
    }

    /// The custodian's build — the plan, the header, the five legs — and the quorum's signatures over the v2 message.
    fn build_v2(
        f: &LiqV2,
        id: u8,
    ) -> (LiquidationPlan, crate::liquidation_tx::LiquidationHeader, crate::liquidation_tx::LiquidationLegs, Vec<MintAttestor>) {
        let rule = f.a.liquidation_rule(NATIVE_PEG_ASSET_ID).expect("the PSM has a rule at the chain's mark");
        let plan = plan_liquidation(&f.open, &rule).expect("CALIBRATION: the PSM is due at this mark and the pool covers it");
        let [retired_commit, seized_commit, new_reserve_commit, new_minted_commit, new_pool_t, new_pool_p, new_pool_s] = plan.commits(&f.open);
        let h = crate::liquidation_tx::LiquidationHeader {
            epoch_id: 1,
            asset_id: NATIVE_PEG_ASSET_ID,
            position_id: [id; 32],
            retired_commit,
            seized_commit,
            new_reserve_commit,
            new_minted_commit,
            new_pool_t,
            new_pool_p,
            new_pool_s,
            pool_close: plan.close,
        };
        let legs = build_liquidation_legs(&f.open, &plan, &rule).expect("the five legs prove");
        let att = attest(&f.custodians, &f.a.liquidation_attest_msg(&h).expect("the PSM has a message"));
        (plan, h, legs, att)
    }

    // PIN 1 — a DUE PSM is liquidated through the stability pool on TWO ledgers: the pool burns `C`, the supply retires
    // the SAME `C`, the reserve releases `S` to the pool's sum, both ledgers hold one state, the post-state sits at the
    // target ratio, the custodian's next opening opens what the chain holds, and the same object never applies twice.
    #[test]
    fn a_due_psm_is_liquidated_through_the_stability_pool_on_two_ledgers() {
        let (mut f, vs) = liq_v2(2_500, 750_000);
        assert_eq!(f.a.liquidation_threshold_bps(NATIVE_PEG_ASSET_ID), 12_500, "the DERIVED due line (no settable field)");
        let (plan, h, legs, att) = build_v2(&f, 0xC1);
        let (d, m, p) = (f.open.reserve, f.open.minted, 750_000u128);
        assert!(plan.c > 0 && plan.c <= f.open.pool_t && plan.s > 0 && plan.s <= d, "CALIBRATION: a real retire the pool covers");
        assert!(
            (d - plan.s) * p * 10_000 >= 15_000 * (m - plan.c) * crate::liquidation::PRICE_SCALE,
            "the post-state is back at the 150 % target: reserve {} at mark {p} vs supply {}",
            d - plan.s,
            m - plan.c
        );
        for (who, n) in [("A", &mut f.a), ("B", &mut f.b)] {
            assert_eq!(n.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "{who} applies it");
            assert_eq!((n.reserve_commit(), n.minted_commit()), (h.new_reserve_commit, h.new_minted_commit), "{who}: the PSM moved");
            assert_eq!(
                n.pool_words(NATIVE_PEG_ASSET_ID),
                PoolWords { t: h.new_pool_t, p: h.new_pool_p, s: h.new_pool_s, epoch: 0 },
                "{who}: the pool moved by the same (C, S)"
            );
            assert_eq!(
                n.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att),
                PegOutcome::Replay,
                "⛔ {who} applied one liquidation twice"
            );
        }
        assert_eq!(f.a.pool_census(), f.b.pool_census(), "⛔⛔⛔ two pools after one liquidation");
        assert_eq!((f.a.reserve_commit(), f.a.minted_commit()), (f.b.reserve_commit(), f.b.minted_commit()), "⛔⛔⛔ two PSMs");
        // the custodian's next opening opens exactly what the chain now holds — it can build the next one
        let x = plan.after;
        assert_eq!(
            PegLedger::commits_of_opening(x.reserve, x.reserve_blind, x.minted, x.minted_blind),
            (f.a.reserve_commit(), f.a.minted_commit()),
            "the custodian's advanced PSM opening opens the chain"
        );
        let opened = PoolWords {
            t: usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(x.pool_t), x.pool_t_blind),
            p: usdm_decider::confidential_solvency::solvency_commit_256(x.pool_p, x.pool_p_blind),
            s: usdm_decider::confidential_solvency::solvency_commit_256(x.pool_s, x.pool_s_blind),
            epoch: 0,
        };
        assert_eq!(opened, f.a.pool_words(NATIVE_PEG_ASSET_ID), "the custodian's advanced pool opening opens the chain");
    }

    // PIN 2 — NO FREE SEIZURE (refutes the 2026-09-08 red team's R1 against the new door). A HEALTHY PSM has no
    // liquidation at all (the amount leg is UNPROVABLE); at a due mark, no quorum, a minority signature, any swapped leg,
    // a header claiming another seizure or another close, and a second object built against the advanced state are each
    // REFUSED with nothing moved — and after every refusal the honest object still applies (no refusal strands the PSM).
    #[test]
    fn a_healthy_psm_or_a_forged_liquidation_moves_nothing() {
        use usdm_decider::confidential_solvency as cs;
        let (healthy, _) = liq_v2(2_500, 1_000_000); // 3000 at 1.0 vs 2000 = 150 %: far above the 125 % due line
        let rule = healthy.a.liquidation_rule(NATIVE_PEG_ASSET_ID).expect("a rule");
        let o = healthy.open;
        assert!(plan_liquidation(&o, &rule).is_none(), "a healthy PSM plans no liquidation");
        assert!(
            cs::prove_liquidation_amount_carrier(u256_from_u128(o.reserve), u256_from_u128(o.minted), u256_from_u128(o.pool_t), &[o.reserve_blind; 5], &rule).is_none(),
            "⛔ the amount leg PROVED for a healthy PSM — a free seizure"
        );
        let (mut f, vs) = liq_v2(2_500, 750_000);
        let (plan, h, legs, att) = build_v2(&f, 0xC2);
        let before = (f.a.reserve_commit(), f.a.minted_commit(), f.a.pool_census());
        let still = |n: &PegLedger, why: &str| {
            assert_eq!((n.reserve_commit(), n.minted_commit(), n.pool_census()), before, "⛔ {why} moved the ledger");
        };
        assert_eq!(f.a.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &[]), PegOutcome::InsufficientThreshold, "no quorum");
        assert_eq!(f.a.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att[..1]), PegOutcome::InsufficientThreshold, "1 of 2");
        still(&f.a, "a refused quorum");
        for i in 0..5 {
            let mut forged = legs.clone();
            let each = [&legs.amount, &legs.pool_transition, &legs.pool_step, &legs.retire, &legs.seize];
            let swap = each[(i + 1) % 5].clone();
            *[&mut forged.amount, &mut forged.pool_transition, &mut forged.pool_step, &mut forged.retire, &mut forged.seize][i] = swap;
            assert_eq!(f.a.liquidate_confidential(&h, &forged, &vs, &MlDsaVerifier, &att), PegOutcome::BadRequest, "⛔ leg {i} swapped verified");
        }
        still(&f.a, "a swapped leg");
        // a header claiming one unit LESS seized (the reserve keeps more than the pool is owed), re-signed by the quorum
        let mut less = h;
        less.seized_commit = cs::solvency_commit_256(u256_from_u128(plan.s - 1), plan.blinds[1]);
        let less_att = attest(&f.custodians, &f.a.liquidation_attest_msg(&less).expect("msg"));
        assert_eq!(f.a.liquidate_confidential(&less, &legs, &vs, &MlDsaVerifier, &less_att), PegOutcome::BadRequest, "⛔ a short seizure");
        let mut flipped = h;
        flipped.pool_close = !h.pool_close;
        let flip_att = attest(&f.custodians, &f.a.liquidation_attest_msg(&flipped).expect("msg"));
        assert_eq!(f.a.liquidate_confidential(&flipped, &legs, &vs, &MlDsaVerifier, &flip_att), PegOutcome::BadRequest, "⛔ a flipped close");
        still(&f.a, "a forged header");
        assert_eq!(f.a.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "the honest object still applies");
        // a SECOND close (fresh id, fresh signatures over the ADVANCED state) of legs proven against the OLD state
        let mut again = h;
        again.position_id = [0xC9; 32];
        let again_att = attest(&f.custodians, &f.a.liquidation_attest_msg(&again).expect("msg"));
        let after = (f.a.reserve_commit(), f.a.minted_commit(), f.a.pool_census());
        assert_eq!(f.a.liquidate_confidential(&again, &legs, &vs, &MlDsaVerifier, &again_att), PegOutcome::BadRequest, "⛔ seized twice");
        assert_eq!((f.a.reserve_commit(), f.a.minted_commit(), f.a.pool_census()), after, "⛔ a stale object moved the ledger");
    }

    // PIN 3 — a liquidation that DRAINS the pool closes its epoch: the epoch's closing `(P, S)` is kept for its
    // receipts, the next epoch restarts at the public `P = 2^128`, `S = 0`, both ledgers agree, and the certified
    // bundle's one pool vector round-trips both (a joiner adopts the closed epoch too).
    #[test]
    fn a_liquidation_that_drains_the_pool_closes_its_epoch_and_keeps_the_closing_words() {
        let (probe, _) = liq_v2(2_500, 750_000);
        let rule = probe.a.liquidation_rule(NATIVE_PEG_ASSET_ID).expect("a rule");
        let c = plan_liquidation(&probe.open, &rule).expect("due").c;
        let (mut f, vs) = liq_v2(c, 750_000); // the pool holds EXACTLY the retire
        let (plan, h, legs, att) = build_v2(&f, 0xC3);
        assert!(plan.close && h.pool_close, "CALIBRATION: a full drain closes the epoch (P_new = 0)");
        let fresh = PoolWords::genesis();
        for (who, n) in [("A", &mut f.a), ("B", &mut f.b)] {
            assert_eq!(n.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "{who} applies the drain");
            assert_eq!(
                n.pool_words(NATIVE_PEG_ASSET_ID),
                PoolWords { t: h.new_pool_t, p: fresh.p, s: fresh.s, epoch: 1 },
                "{who}: the next epoch restarts at the public P = 2^128, S = 0"
            );
            assert_eq!(
                n.closed_pool_words(NATIVE_PEG_ASSET_ID, 0),
                Some(PoolWords { t: h.new_pool_t, p: h.new_pool_p, s: h.new_pool_s, epoch: 0 }),
                "⛔⛔⛔ {who} lost the closed epoch's words — its receipts could never withdraw"
            );
        }
        let mut joiner = PegLedger::new(15_000);
        joiner.adopt_certified_pools(&f.a.pool_census());
        assert_eq!(joiner.pool_census(), f.b.pool_census(), "the bundle's pool vector round-trips the current AND the closed epoch");
        assert_eq!(joiner.closed_pool_words(NATIVE_PEG_ASSET_ID, 0), f.a.closed_pool_words(NATIVE_PEG_ASSET_ID, 0), "the joiner holds the close");
    }

    // A real 2-of-2 charter quorum of distinct ML-DSA validators (the test holds their keys, as the orchestrator).
    fn quorum() -> (Vec<Custodian>, ValidatorSet) {
        let custodians: Vec<Custodian> = (0..2u8)
            .map(|i| Custodian::generate(&[40 + i; 32]))
            .collect();
        let mut vs = ValidatorSet::new();
        for c in &custodians {
            vs.admit(c.id(), 5000, 0).unwrap();
        }
        (custodians, vs)
    }

    fn attest(custodians: &[Custodian], msg: &[u8]) -> Vec<MintAttestor> {
        custodians.iter().map(|c| c.attest(msg)).collect()
    }

    // ── SAFE AT SCALE: CUSTODY VAULTS AT THE LEDGER (docs/BRIDGE-SCALE-VAULTS-SPEC-20261110.md §3c) ─────────────────────
    // Every pin here has TWO parties: the custodian's ledger A, which proves, and a peer's ledger B, built on its own, which
    // verifies and applies the same bytes. Every assertion of a transition is on what B holds.

    type Opening2 = [(u128, crate::spend_frontier::Digest4, u128, crate::spend_frontier::Digest4); 2];

    /// `n` custodians bonded 5,000 each (all active from height 0, so seniority is id order), on a genesis ledger where SAT
    /// is marked at two USDm atomic per SAT atomic: a repayment floor of one for one after the haircut.
    fn vault_fixture(n: usize) -> (Vec<Custodian>, ValidatorSet, PegLedger) {
        // these pins measure what is built on the cut: turned on for this test's own thread (`custody_vaults::CUT_LIVE`
        // says whether a chain cuts; `the_cut_is_live…` pins what a chain does today)
        crate::custody_vaults::TEST_CUT_LIVE.with(|c| c.set(true));
        let custodians: Vec<Custodian> = (0..n)
            .map(|i| {
                let mut seed = [0x5au8; 32];
                seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
                Custodian::generate(&seed)
            })
            .collect();
        let (vs, peg) = vault_party(&custodians);
        (custodians, vs, peg)
    }

    /// ONE PARTY's own state for a set of custodians it knows by their public ids alone: its validator set (each bonded
    /// 5,000) and its genesis ledger with SAT marked. Called once per party, so A and B share no object.
    fn vault_party(custodians: &[Custodian]) -> (ValidatorSet, PegLedger) {
        let mut vs = ValidatorSet::new();
        for c in custodians {
            vs.admit(c.id(), 5_000, 0).unwrap();
        }
        // the fixture's seats, as a carrier would hand them: custodian i on seat i — so vault k is custodians 16k … 16k + 15
        // and a pin names its vaults' sizes (the chain's own seating is the draw, pinned in `custody_vaults`)
        vs.import_custody_seats(custodians.iter().enumerate().map(|(i, c)| (c.id(), i as u64)).collect());
        let mut peg = PegLedger::genesis(15_000);
        peg.price_marks.insert(SAT_PRICE_ASSET_ID, crate::price_mark_tx::PriceMark { price: 2 * crate::liquidation::PRICE_SCALE, epoch_id: 1 });
        (vs, peg)
    }

    /// The custodians of vault `v`, as the fixture holds their keys.
    fn vault_members<'a>(custodians: &'a [Custodian], vs: &ValidatorSet, v: usize) -> Vec<&'a Custodian> {
        let ids = vs.custody_vaults()[v].clone();
        custodians.iter().filter(|c| ids.contains(&c.id())).collect()
    }

    /// What a vault's custodian holds before anything moved its bridge ledgers: zero under each ledger's own genesis blinds.
    fn vault_genesis_openings(v: u32) -> Opening2 {
        let l = bridge_ledgers_of(v);
        let ((br, bm), (xr, xm)) = (psm_genesis_blinds(l[0]), psm_genesis_blinds(l[1]));
        [(0, br, 0, bm), (0, xr, 0, xm)]
    }

    fn sign_all(who: &[&Custodian], msg: &[u8]) -> Vec<MintAttestor> {
        who.iter().map(|c| c.attest(msg)).collect()
    }

    /// ⛔⛔ SAFE AT SCALE — A VAULT'S LEDGERS ARE ITS OWN. Each (vault, custody-funded asset) pair is its own PSM, born on its
    /// own genesis pair; a cover proven for one vault verifies against no other, an opening of one vault proves on no other,
    /// and a vault's apply moves nothing of another's — on the peer. The pairs ride the registry the snapshot and the
    /// certified bundle already carry. A malformed composite id is no ledger at all, and nobody registers one.
    #[test]
    fn safe_at_scale_a_vaults_ledgers_are_its_own_and_another_vaults_proof_never_moves_them() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        for a in [NATIVE_PEG_ASSET_ID, XMR_PEG_ASSET_ID, COIN_BTC_ASSET_ID, COIN_XMR_ASSET_ID] {
            assert_eq!(vault_ledger(0, a), a, "vault 0's ledgers are the asset ids themselves: a one-vault chain is unchanged");
            for v in [1u32, 2, 17, 1_000, VAULT_INDEX_MAX] {
                let id = vault_ledger(v, a);
                assert!(is_vault_ledger(id) && ledger_vault(id) == v && ledger_asset(id) == a && ledger_asset_checked(id) == Some(a), "vault {v} asset {a} round-trips");
                assert_eq!(PegLedger::is_bridge_ledger(id), PegLedger::is_bridge_ledger(a), "a vault's ledger is classed by its asset");
                assert_eq!(PegLedger::is_coin_ledger(id), PegLedger::is_coin_ledger(a));
            }
        }
        // party A: the custodian's ledger (it proves). party B: a peer's, built on its own (it verifies and applies).
        let a = PegLedger::genesis(15_000);
        let mut b = PegLedger::genesis(15_000);
        for bad in [VAULT_LEDGER_BIT, VAULT_LEDGER_BIT | 1, VAULT_LEDGER_BIT | (1 << 8) | 4, VAULT_LEDGER_BIT | (1 << 8) | 0xff] {
            assert!(!is_vault_ledger(bad) && ledger_asset_checked(bad).is_none(), "⛔ {bad:#x} read as a ledger");
            assert!(!PegLedger::is_bridge_ledger(bad) && !PegLedger::is_coin_ledger(bad) && b.psm_commits(bad).is_none() && b.reference_price(bad).is_none(), "⛔ a malformed composite has a class, a pair or a price");
        }
        let pair = |p: &PegLedger, id: u32| p.psm_commits(id).map(|c| (c.0, c.1)).expect("a pair");
        let (g0, g1, g2) = (pair(&b, NATIVE_PEG_ASSET_ID), pair(&b, vault_ledger(1, NATIVE_PEG_ASSET_ID)), pair(&b, vault_ledger(2, NATIVE_PEG_ASSET_ID)));
        assert!(g0 != g1 && g1 != g2 && g0 != g2, "⛔ two vaults' ledgers were born on one pair: a proof for one would open the other");
        let carried_before = b.wrapped_asset_census().len();

        // a deposit on vault 1, proven on A from vault 1's own openings
        let d = l(&[0x51, 1, 1, 1]);
        let open1 = vault_genesis_openings(1);
        let (blob, hr, hm, after) =
            a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &open1, 1_500, 1_000, &d, &d, None).expect("vault 1's custodian proves a deposit from its own openings");
        let delta = PegLedger::mint_delta_commit(1_000, d);
        assert!(b.verify_cover_at(1, true, &blob, (hr, hm), delta, None).is_some(), "CALIBRATION: the peer verifies vault 1's proof on vault 1");
        assert!(b.verify_cover_at(0, true, &blob, (hr, hm), delta, None).is_none(), "⛔ vault 1's proof verified against vault 0's ledgers");
        assert!(b.verify_cover_at(2, true, &blob, (hr, hm), delta, None).is_none(), "⛔ vault 1's proof verified against vault 2's ledgers");
        assert!(
            a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(0), 1_500, 1_000, &d, &d, None).is_none(),
            "⛔ an opening of vault 0 proved a deposit on vault 1"
        );
        let posts = b.verify_cover_at(1, true, &blob, (hr, hm), delta, None).expect("the peer's verify answers the posts");
        b.apply_cover_at(1, &posts);
        assert_eq!(pair(&b, NATIVE_PEG_ASSET_ID), g0, "⛔ vault 1's deposit moved vault 0's Bitcoin ledger on the peer");
        assert_eq!(pair(&b, vault_ledger(2, NATIVE_PEG_ASSET_ID)), g2, "⛔ … or vault 2's");
        assert_eq!((pair(&b, vault_ledger(1, NATIVE_PEG_ASSET_ID)), pair(&b, vault_ledger(1, XMR_PEG_ASSET_ID))), (posts[0], posts[1]), "the peer holds vault 1's two bridge ledgers on the cover's posts");
        assert_eq!(PegLedger::cover_posts(&after), posts, "…which the custodian's advanced openings open");
        assert_eq!(b.wrapped_asset_census().len(), carried_before + 2, "the vault's two pairs ride the registry the bundle and the snapshot carry");
        assert!(b.supply_words().wrapped.iter().any(|(id, ..)| *id == vault_ledger(1, NATIVE_PEG_ASSET_ID)), "…and the supply gate's words");
        // price, ratio and rule are the asset's
        assert_eq!(b.ledger_ratio_bps(vault_ledger(1, NATIVE_PEG_ASSET_ID)), Some(15_000));
        assert_eq!(b.reference_price(vault_ledger(1, XMR_PEG_ASSET_ID)), b.reference_price(XMR_PEG_ASSET_ID));
        assert_eq!(b.ledger_ratio_bps(vault_ledger(1, COIN_BTC_ASSET_ID)), None, "a coin the chain never registered has no ledger in any vault");
        // the next peg continues from the advanced openings, on the other asset, against the peer's state
        assert!(b.orchestrate_cover_at(1, true, XMR_PEG_ASSET_ID, &after, 3_000, 2_000, &d, &d, None).is_some(), "vault 1's next deposit proves from its advanced openings");
        // nobody registers or retunes a composite
        let before = b.wrapped_asset_census();
        b.register_wrapped_asset(vault_ledger(3, NATIVE_PEG_ASSET_ID), 10_000);
        assert_eq!(b.wrapped_asset_census(), before, "⛔ a vault's ledger id was registered as an asset");
        let (custodians, vs) = quorum();
        let reg = PegLedger::wrapped_register_msg(1, vault_ledger(1, XMR_PEG_ASSET_ID), 10_000, 20_000);
        assert!(
            matches!(b.register_wrapped_asset_attested(1, vault_ledger(1, XMR_PEG_ASSET_ID), 10_000, 20_000, &vs, &MlDsaVerifier, &attest(&custodians, &reg)), PegOutcome::BadRequest),
            "⛔ a signed registration retuned a vault's ledger"
        );
    }

    /// ⛔⛔ SAFE AT SCALE — ONE VAULT'S QUORUM SIGNS A DEPOSIT ALONE ONLY WITHIN WHAT ITS OWN SLASHED BONDS REPAY. Twenty-four
    /// custodians are two vaults by their seats (16 + 8). The custodian's ledger A proves; the peer's ledger B — its own validator set and
    /// ledger — judges and applies. CALIBRATION: six of vault 1's eight sign a deposit on vault 1 with its ride, and B takes
    /// it. REFUSED on B: fewer than two thirds of the vault; the vault's quorum with no ride (the whole set is then needed);
    /// another vault's quorum; the ride or the proofs pointed at another vault; a vault that does not exist; swapped or
    /// foreign proofs; a deposit past the vault's authority under a ride proven for a smaller one, or under a bound proven
    /// against a larger authority than the chain computes; any ride while SAT is unpriced. NEVER REFUSED: the deposit past
    /// the authority, signed by two thirds of the whole set. The burn mirror: the paying vault's own quorum carries its
    /// burn; another vault's does not; the burn cannot be re-pointed at another vault's ledgers; and a vault that took
    /// nothing in proves no release.
    #[test]
    fn safe_at_scale_a_vault_signs_a_deposit_alone_only_within_what_its_bonds_repay() {
        use usdm_decider::confidential_solvency as cs;
        let l = usdm_decider::poseidon2_compress::lanes_of;
        // party A (the custodian: proves) and party B (a peer with its own validator set and ledger: judges and applies)
        let (custodians, vs_a, mut a) = vault_fixture(24);
        let (vs, mut b) = vault_party(&custodians);
        assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 8], "twenty-four custodians are two vaults: seats 0–15 and 16–23");
        assert_eq!(vs.custody_vaults(), vs_a.custody_vaults(), "both parties hold the same vaults from the same seats");
        let (v0, v1) = (vault_members(&custodians, &vs, 0), vault_members(&custodians, &vs, 1));
        let (_, forfeit1) = crate::psm::BondQuorum::vault(&vs_a, 1).expect("vault 1 exists");
        assert_eq!(forfeit1, 26_667, "eight bonds of 5,000: two thirds of the vault's weight, rounded up, is its cheapest signing set");
        assert_eq!(a.vault_authority_usdm(forfeit1), Some(26_667), "…valued at the repayment floor (one for one here)");

        let d = l(&[0x52, 1, 1, 1]);
        let open1 = vault_genesis_openings(1);
        let (blob, hr, hm, after) = a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &open1, 1_500, 1_000, &d, &d, None).expect("the deposit proves");
        let delta = PegLedger::mint_delta_commit(1_000, d);
        let (did, rcpt, nonce) = ([0x61u8; 32], [0x62u8; 32], [0x63u8; 32]);
        let msg = peg_in_confidential_msg(&did, &hr, &hm, &delta, &rcpt, &nonce);
        let ride = a.prove_vault_ride(1, forfeit1, &after).expect("within the vault's authority the ride proves");
        let ride_bytes = ride.encode();
        eprintln!("[vault-ride] {} B on the deposit object (sum proof {} B + bound proof {} B)", ride_bytes.len(), ride.sum.len(), ride.bound.len());
        assert_eq!(VaultRide::decode(&ride_bytes).as_ref(), Some(&ride), "one encoding");
        assert_eq!(VaultRide::decode(&[]), Some(VaultRide::whole()), "empty bytes are vault 0 under the whole set");
        assert!(VaultRide::whole().encode().is_empty(), "…and a one-vault chain's objects carry no ride bytes");
        let check = |peer: &PegLedger, ride: &[u8], att: &[MintAttestor]| peer.check_peg_in_confidential_riding(ride, did, &blob, hr, hm, delta, rcpt, nonce, &vs, &MlDsaVerifier, att, None);
        let own6 = sign_all(&v1[..6], &msg);
        // two thirds of the whole set (sixteen of twenty-four) WITH two thirds of vault 1 among them — and more without
        let whole12: Vec<&Custodian> = v1[..6].iter().chain(v0[..10].iter()).copied().collect();
        let whole12_without: Vec<&Custodian> = v0.iter().chain(v1[..3].iter()).copied().collect();
        assert!(matches!(check(&b, &ride_bytes, &own6), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of vault 1 sign its deposit alone, under its ride");
        assert!(matches!(check(&b, &ride_bytes, &sign_all(&v1[..5], &msg)), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the vault carried a deposit");
        assert!(matches!(check(&b, &VaultRide::of(1).encode(), &own6), PegOutcome::InsufficientThreshold), "⛔ a vault's quorum carried a deposit with no bound on it");
        assert!(matches!(check(&b, &ride_bytes, &sign_all(&v0[..11], &msg)), PegOutcome::InsufficientThreshold), "⛔ another vault's quorum carried vault 1's deposit");
        let on = |v: u32| {
            let mut r = ride.clone();
            r.vault = v;
            r.encode()
        };
        assert!(matches!(check(&b, &on(0), &sign_all(&v0[..11], &msg)), PegOutcome::BadRequest), "⛔ vault 1's deposit moved vault 0's ledgers under vault 0's quorum");
        assert!(matches!(check(&b, &on(2), &own6), PegOutcome::BadRequest), "⛔ a vault that does not exist carried a deposit");
        let mut swapped = ride.clone();
        std::mem::swap(&mut swapped.sum, &mut swapped.bound);
        assert!(matches!(check(&b, &swapped.encode(), &own6), PegOutcome::BadRequest), "⛔ swapped proofs were taken");
        let mut foreign = ride.clone();
        foreign.sum_commit = PegLedger::vault_cover_commit(1);
        assert!(matches!(check(&b, &foreign.encode(), &own6), PegOutcome::BadRequest), "⛔ a sum commitment that is not this object's was taken");
        let mut unpriced = b.clone();
        unpriced.price_marks.remove(&SAT_PRICE_ASSET_ID);
        assert!(matches!(check(&unpriced, &ride_bytes, &own6), PegOutcome::BadRequest), "⛔ SAT is unpriced and a vault's word alone carried a deposit");
        assert!(matches!(check(&unpriced, &VaultRide::of(1).encode(), &sign_all(&whole12, &msg)), PegOutcome::ConfidentialPublished), "…while the whole set still signs it");

        // A DEPOSIT PAST THE VAULT'S AUTHORITY (a mint of 30,000 against 26,667)
        let d2 = l(&[0x53, 1, 1, 1]);
        let (blob2, hr2, hm2, after2) = a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &open1, 45_000, 30_000, &d2, &d2, None).expect("the deposit itself is fully backed and proves");
        assert!(a.prove_vault_ride(1, forfeit1, &after2).is_none(), "CALIBRATION: past its authority a vault forms no ride");
        let delta2 = PegLedger::mint_delta_commit(30_000, d2);
        let did2 = [0x64u8; 32];
        let msg2 = peg_in_confidential_msg(&did2, &hr2, &hm2, &delta2, &rcpt, &nonce);
        let check2 = |peer: &PegLedger, ride: &[u8], att: &[MintAttestor]| peer.check_peg_in_confidential_riding(ride, did2, &blob2, hr2, hm2, delta2, rcpt, nonce, &vs, &MlDsaVerifier, att, None);
        let own6b = sign_all(&v1[..6], &msg2);
        assert!(matches!(check2(&b, &ride_bytes, &own6b), PegOutcome::BadRequest), "⛔ LYING PROVER: a ride proven for a smaller deposit carried a larger one");
        let u = |v: u128| super::u256_from_u128(v);
        let s_blind = PegLedger::vault_sum_blind(&after2[0].3, &after2[1].3);
        let (sum2, c2) = cs::prove_transition_carrier(u(after2[0].2), u(after2[1].2), &[after2[0].3, after2[1].3, s_blind], cs::TransitionDomain::VaultSum).expect("the honest sum proves");
        let (bound_lie, _) = cs::prove_peg_in_carrier(u(40_000), u(30_000), u(0), u(0), VAULT_COVER_BLIND, s_blind, VAULT_COVER_BLIND, s_blind, cs::Backing::at_unit_price(10_000))
            .expect("a bound against an authority the prover made up proves");
        let lie = VaultRide { vault: 1, sum_commit: c2[2], sum: sum2, bound: bound_lie };
        assert!(matches!(check2(&b, &lie.encode(), &own6b), PegOutcome::BadRequest), "⛔ LYING PROVER: a bound against a made-up authority carried the deposit");
        assert!(
            cs::prove_peg_in_carrier(u(26_667), u(30_000), u(0), u(0), VAULT_COVER_BLIND, s_blind, VAULT_COVER_BLIND, s_blind, cs::Backing::at_unit_price(10_000)).is_none(),
            "⛔ the bound proved for a sum past the vault's real authority"
        );
        assert!(matches!(check2(&b, &VaultRide::of(1).encode(), &sign_all(&whole12, &msg2)), PegOutcome::ConfidentialPublished), "⛔ a deposit past a vault's authority was REFUSED: two thirds of the whole set signed it");
        let whole11: Vec<&Custodian> = v1[..6].iter().chain(v0[..9].iter()).copied().collect();
        assert!(matches!(check2(&b, &VaultRide::of(1).encode(), &sign_all(&whole11, &msg2)), PegOutcome::InsufficientThreshold), "⛔ fifteen of twenty-four is not two thirds of the whole set");

        // A VAULT UNDER HALF STRENGTH NEVER SIGNS ALONE (seats fill one custodian at a time): at seventeen custodians the
        // young vault is ONE custodian — its ride proves, its "quorum" signs, and the peer refuses; the whole set carries it
        {
            let (c17, vs17_a, a17) = vault_fixture(17);
            let (vs17, b17) = vault_party(&c17);
            assert_eq!(vs17.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 1], "seventeen custodians: a full vault and one custodian on seat 16");
            let (w0, w1) = (vault_members(&c17, &vs17, 0), vault_members(&c17, &vs17, 1));
            let (_, f1) = crate::psm::BondQuorum::vault(&vs17_a, 1).expect("vault 1 exists");
            let d3 = l(&[0x56, 1, 1, 1]);
            let (blob3, hr3, hm3, after3) = a17.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &open1, 1_500, 1_000, &d3, &d3, None).expect("the deposit proves");
            let delta3 = PegLedger::mint_delta_commit(1_000, d3);
            let msg3 = peg_in_confidential_msg(&did, &hr3, &hm3, &delta3, &rcpt, &nonce);
            let ride3 = a17.prove_vault_ride(1, f1, &after3).expect("a mint of 1,000 is inside one bond's authority, so the ride itself proves").encode();
            let check3 = |ride: &[u8], att: &[MintAttestor]| b17.check_peg_in_confidential_riding(ride, did, &blob3, hr3, hm3, delta3, rcpt, nonce, &vs17, &MlDsaVerifier, att, None);
            assert!(matches!(check3(&ride3, &sign_all(&w1, &msg3)), PegOutcome::BadRequest), "⛔ ONE custodian carried a deposit on its own word: a vault under half strength signed alone");
            let whole: Vec<&Custodian> = w1.iter().chain(w0[..11].iter()).copied().collect();
            assert!(matches!(check3(&VaultRide::of(1).encode(), &sign_all(&whole, &msg3)), PegOutcome::ConfidentialPublished), "…while the whole set, with that vault's own member, still carries it");
        }
        assert!(
            matches!(check2(&b, &VaultRide::of(1).encode(), &sign_all(&whole12_without, &msg2)), PegOutcome::InsufficientThreshold),
            "⛔ two thirds of the whole set carried a deposit WITHOUT two thirds of the vault whose ledgers it moves (its witnesses hold none of that vault's openings)"
        );

        // THE APPLY, on both parties from the same bytes: the peer's vault 1 ledgers move, its vault 0 stands
        let b_v0_before = (b.reserve_commit(), b.minted_commit());
        assert!(matches!(a.peg_in_confidential(did, &blob, hr, hm, delta, rcpt, nonce, &ride_bytes, &vs_a, &MlDsaVerifier, &own6), PegOutcome::ConfidentialMinted), "A applies its own object");
        assert!(matches!(b.peg_in_confidential(did, &blob, hr, hm, delta, rcpt, nonce, &ride_bytes, &vs, &MlDsaVerifier, &own6), PegOutcome::ConfidentialMinted), "the peer applies the vault-signed deposit");
        let posts = CoverBlob::decode(&blob).expect("a cover").posts;
        assert_eq!(b.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)).map(|c| (c.0, c.1)), Some(posts[0]), "the peer holds vault 1's Bitcoin ledger advanced");
        assert_eq!(b.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)), a.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)), "both parties hold the same pair");
        assert_eq!((b.reserve_commit(), b.minted_commit()), b_v0_before, "⛔ vault 1's deposit moved vault 0 on the peer");
        assert!(b.deposit_minted(&did), "the peer holds the deposit as minted");
        assert!(matches!(b.peg_in_confidential(did, &blob, hr, hm, delta, rcpt, nonce, &ride_bytes, &vs, &MlDsaVerifier, &own6), PegOutcome::Replay), "the deposit mints once");

        // THE BURN MIRROR, proven on A, judged and applied on B
        let leg = l(&[0xb8, 1, 1, 1]);
        let rc = [0xb8u8; 32];
        let (out_bytes, nf, out_lc, out_cm, (orc, omc), _) =
            super::peg_out_proofs_for_test_at(1, &a, &after, NATIVE_PEG_ASSET_ID, 200, 200, &leg, &rc).expect("vault 1 redeems from its own ledgers");
        let out_msg = peg_out_confidential_msg(&nf, &orc, &omc, &rc, &[0u8; 32], &out_lc, &[0u8; 32], &out_cm);
        let burn = |peer: &PegLedger, bytes: &[u8], att: &[MintAttestor]| peer.check_peg_out_confidential(nf, bytes, orc, omc, &rc, &[0u8; 32], out_lc, &[0u8; 32], &out_cm, &vs, &MlDsaVerifier, att);
        let burn6 = sign_all(&v1[..6], &out_msg);
        assert!(matches!(burn(&b, &out_bytes, &burn6), PegOutcome::ConfidentialPublished), "CALIBRATION: the paying vault's own quorum carries its burn");
        assert!(matches!(burn(&b, &out_bytes, &sign_all(&v1[..5], &out_msg)), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the paying vault carried a burn");
        assert!(matches!(burn(&b, &out_bytes, &sign_all(&v0[..11], &out_msg)), PegOutcome::InsufficientThreshold), "⛔ another vault's quorum carried vault 1's burn");
        assert!(matches!(burn(&b, &out_bytes, &sign_all(&whole12, &out_msg)), PegOutcome::ConfidentialPublished), "more signers than the vault's own change nothing");
        assert!(
            matches!(burn(&b, &out_bytes, &sign_all(&whole12_without, &out_msg)), PegOutcome::InsufficientThreshold),
            "⛔ two thirds of the whole set carried a burn WITHOUT two thirds of the vault that pays it"
        );
        let mut p = crate::peg_out_tx::PegOutProofs::decode(&out_bytes).expect("proofs");
        p.coin = 0;
        let on0 = p.encode().expect("encodes");
        // CHAIN-OBJECT: the same `Class::PegOut` check on the peer, re-pointed at vault 0's ledgers under vault 0's quorum.
        assert!(matches!(burn(&b, &on0, &sign_all(&v0[..11], &out_msg)), PegOutcome::BadRequest), "⛔ vault 1's burn was paid from vault 0's ledgers");
        assert!(!matches!(burn(&b, &on0, &burn6), PegOutcome::ConfidentialPublished), "⛔ …under vault 1's signatures");
        assert!(
            super::peg_out_proofs_for_test_at(0, &a, &vault_genesis_openings(0), NATIVE_PEG_ASSET_ID, 200, 200, &leg, &rc).is_none(),
            "⛔ a vault that took nothing in proved a release"
        );
        let out_posts = CoverBlob::decode(&crate::peg_out_tx::PegOutProofs::decode(&out_bytes).expect("proofs").solvency).expect("a cover").posts;
        assert!(matches!(b.peg_out_confidential(nf, &out_bytes, orc, omc, &rc, &[0u8; 32], out_lc, &[0u8; 32], &out_cm, &vs, &MlDsaVerifier, &burn6), PegOutcome::ConfidentialRedeemed), "the peer applies vault 1's burn");
        assert_eq!(b.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)).map(|c| (c.0, c.1)), Some(out_posts[0]), "the peer holds vault 1's Bitcoin ledger reduced");
        assert_eq!((b.reserve_commit(), b.minted_commit()), b_v0_before, "⛔ vault 1's burn moved vault 0 on the peer");
        assert!(b.burn_redeemed(&nf), "the peer holds the burn as redeemed");
    }

    /// ⛔ THE CUT IS LIVE (`custody_vaults::CUT_LIVE`, spec §3e.4 and §3g), AND THIS PIN IS WHAT SAYS SO: on a chain as it
    /// runs — not only on a pin's own thread — sixteen custodians are one vault, the seventeenth seat opens a second, and a
    /// hundred and sixty are ten vaults of sixteen; each vault's quorum is two thirds of its OWN members, so a vault's word
    /// weighs what its members' bonds weigh and no more. What lets it be live: every stage of a changing vault is built and
    /// pinned — a vault's ledgers and their openings handed to a new member (`opening_share`), its coins re-keyed and swept
    /// (`btc_payout` consolidation, `xmr_sweep`), a thinned vault merged (`Class::VaultMerge`), the weekly rotation (R5), a
    /// vault past its bound rebalanced (`Class::VaultRebalance`). Up to sixteen custodians nothing differs from before.
    /// CONTROL: a deposit naming a vault the set does not have is still no object (party B: a peer's own ledger and set).
    #[test]
    fn the_cut_is_live_so_sixteen_custodians_are_one_vault_and_more_are_cut_into_vaults_of_at_most_sixteen() {
        use crate::psm::BondQuorum;
        assert!(crate::custody_vaults::CUT_LIVE, "⛔ the cut is not live: the lifecycle it needs is built and pinned");
        for (n, want) in [(16usize, vec![16usize]), (17, vec![16, 1]), (160, vec![16; 10])] {
            let mut vs = ValidatorSet::new();
            let ids: Vec<[u8; 32]> = (0..n)
                .map(|i| {
                    let mut id = [0x77u8; 32];
                    id[..8].copy_from_slice(&(i as u64).to_le_bytes());
                    id
                })
                .collect();
            for id in &ids {
                vs.admit(*id, 5_000, 0).unwrap();
            }
            // the fixture's seats, as a carrier hands them: custodian i on seat i (the chain's own seating is the draw)
            vs.import_custody_seats(ids.iter().enumerate().map(|(i, id)| (*id, i as u64)).collect());
            assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), want, "{n} custodians");
            assert_eq!(vs.vault_count() as usize, want.len());
            for v in 0..want.len() as u32 {
                let (own, _) = vs.vault(v).expect("each vault answers");
                assert_eq!(own.total_bond(), 5_000 * want[v as usize] as u128, "⛔ vault {v} of {n} weighs other than its own members");
            }
            assert!(vs.vault(want.len() as u32).is_none(), "⛔ a vault past the last answered");
        }
        // CONTROL: a deposit naming a vault the set does not have is no object on this chain
        let (custodians, vs) = quorum();
        let b = PegLedger::genesis(15_000);
        let a = PegLedger::genesis(15_000);
        let d = usdm_decider::poseidon2_compress::lanes_of(&[0x55, 1, 1, 1]);
        let open1 = [(0, psm_genesis_blinds(vault_ledger(1, 0)).0, 0, psm_genesis_blinds(vault_ledger(1, 0)).1), (0, psm_genesis_blinds(vault_ledger(1, 1)).0, 0, psm_genesis_blinds(vault_ledger(1, 1)).1)];
        let (blob, hr, hm, _) = a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &open1, 1_500, 1_000, &d, &d, None).expect("a cover on vault 1's ledgers proves");
        let delta = PegLedger::mint_delta_commit(1_000, d);
        let (did, rcpt, nonce) = ([0x81u8; 32], [0x82u8; 32], [0x83u8; 32]);
        let att = attest(&custodians, &peg_in_confidential_msg(&did, &hr, &hm, &delta, &rcpt, &nonce));
        assert!(
            matches!(b.check_peg_in_confidential_riding(&VaultRide::of(1).encode(), did, &blob, hr, hm, delta, rcpt, nonce, &vs, &MlDsaVerifier, &att, None), PegOutcome::BadRequest),
            "⛔ a deposit landed on a second vault's ledgers on a chain that has one vault"
        );
        assert!(!b.deposit_minted(&did) && b.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)).map(|c| (c.0, c.1)) == a.psm_commits(vault_ledger(1, NATIVE_PEG_ASSET_ID)).map(|c| (c.0, c.1)), "the peer holds nothing of it");
    }

    /// A verifier that counts the signatures it is asked to check.
    struct Counting(std::cell::Cell<usize>);
    impl crate::pqauth::PqVerifier for Counting {
        fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            self.0.set(self.0.get() + 1);
            crate::pqauth::PqVerifier::verify(&MlDsaVerifier, pubkey, msg, sig)
        }
    }

    /// ⭐⭐ SAFE AT SCALE, MEASURED AT THE LIMIT, THE LIMIT PLUS ONE AND TEN TIMES IT: the same deposit at 16, 17 and 160
    /// bonded custodians, taken by the most junior vault that takes deposits (at 17 that is still vault 0: the seventeenth
    /// custodian sits alone on seat 16 and its vault takes none) — proven on the custodian's ledger A, judged and applied
    /// on a peer's ledger B. What B verifies and what the object carries for it do not grow with the bonded set: at most
    /// eleven signatures, at most sixteen verifies, one ride of a fixed size. CONTROL: the same deposit signed by the whole
    /// set of 160 needs 107 signatures — the cost a vault-signed object does not pay.
    #[test]
    fn safe_at_scale_one_deposit_costs_the_same_at_16_17_and_160_custodians() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let mut rows: Vec<(usize, usize, usize, usize, usize)> = Vec::new();
        for n in [16usize, 17, 160] {
            let (custodians, vs_a, a) = vault_fixture(n);
            let (vs, mut b) = vault_party(&custodians);
            let vaults = vs.custody_vaults();
            let v = vaults.iter().rposition(|m| m.len() > crate::custody_vaults::VAULT_MIN).expect("a vault that takes deposits");
            let members = vault_members(&custodians, &vs, v);
            let (own, forfeit) = crate::psm::BondQuorum::vault(&vs_a, v as u32).expect("the vault exists");
            let total = crate::psm::BondQuorum::total_bond(&own);
            let need = (1..=members.len()).find(|k| (*k as u128) * 5_000 * 3 >= total * 2).expect("a quorum exists");
            let d = l(&[0x54, n as u64, 1, 1]);
            let (blob, hr, hm, after) =
                a.orchestrate_cover_at(v as u32, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(v as u32), 1_500, 1_000, &d, &d, None).expect("the deposit proves");
            let delta = PegLedger::mint_delta_commit(1_000, d);
            let (did, rcpt, nonce) = ([0x71u8; 32], [0x72u8; 32], [0x73u8; 32]);
            let msg = peg_in_confidential_msg(&did, &hr, &hm, &delta, &rcpt, &nonce);
            // one vault is the whole set: no ride. More than one: the vault's own quorum under its ride.
            let ride = if vaults.len() == 1 { Vec::new() } else { a.prove_vault_ride(v as u32, forfeit, &after).expect("the ride proves").encode() };
            let att = sign_all(&members[..need], &msg);
            if n == 160 {
                // CONTROL, before the apply: the whole set's path at this size
                // 107 signers: the vault's own eleven and ninety-six witnesses from the other vaults
                let whole: Vec<&Custodian> = members[..need].iter().copied().chain(custodians.iter().filter(|c| !members.iter().any(|m| m.id() == c.id())).take(107 - need)).collect();
                let all = sign_all(&whole, &msg);
                let c2 = Counting(std::cell::Cell::new(0));
                assert!(
                    matches!(b.check_peg_in_confidential_riding(&VaultRide::of(v as u32).encode(), did, &blob, hr, hm, delta, rcpt, nonce, &vs, &c2, &all, None), PegOutcome::ConfidentialPublished),
                    "CONTROL: two thirds of all 160 carry the same deposit"
                );
                assert_eq!(c2.0.get(), 107 + need, "CONTROL: the whole-set path verifies a signature per signer of the bonded set, then the vault's own again");
                assert!(
                    matches!(b.check_peg_in_confidential_riding(&VaultRide::of(v as u32).encode(), did, &blob, hr, hm, delta, rcpt, nonce, &vs, &MlDsaVerifier, &all[..106], None), PegOutcome::InsufficientThreshold),
                    "⛔ 106 of 160 is under two thirds"
                );
            }
            let counter = Counting(std::cell::Cell::new(0));
            assert!(
                matches!(b.peg_in_confidential(did, &blob, hr, hm, delta, rcpt, nonce, &ride, &vs, &counter, &att), PegOutcome::ConfidentialMinted),
                "{n} custodians: the peer applies the deposit the junior vault's quorum signed"
            );
            let posts = CoverBlob::decode(&blob).expect("a cover").posts;
            assert_eq!(b.psm_commits(vault_ledger(v as u32, NATIVE_PEG_ASSET_ID)).map(|c| (c.0, c.1)), Some(posts[0]), "{n} custodians: the peer holds the vault's ledger advanced");
            let sig_bytes: usize = att.iter().map(|x| x.pubkey.len() + x.sig.len()).sum();
            eprintln!("[vault-scale] {n} custodians, {} vault(s): {need} signer(s), {} verify call(s), {sig_bytes} B of signatures, ride {} B", vaults.len(), counter.0.get(), ride.len());
            rows.push((n, vaults.len(), need, counter.0.get(), ride.len()));
        }
        assert_eq!(rows.iter().map(|r| r.1).collect::<Vec<_>>(), vec![1, 2, 10], "16 custodians are one vault, 17 are two (sixteen seats and one), 160 are ten");
        for r in &rows {
            assert!(
                r.2 <= crate::custody_vaults::quorum(crate::custody_vaults::VAULT_MAX) && r.3 <= crate::custody_vaults::VAULT_MAX,
                "⛔ {} custodians: {} signers, {} verifies — the door's work grew with the bonded set",
                r.0,
                r.2,
                r.3
            );
        }
        assert_eq!(rows[0].4, 0, "one vault: the object carries no ride, as before vaults");
        assert_eq!(rows[1].4, rows[2].4, "⛔ the ride's size changed between 17 and 160 custodians");
    }

    /// THE ONE LIST of custody-funded ledger kinds is the bridge ledgers then the coin ledgers, ascending, each small
    /// enough for a vault's ledger id — and a kind outside it is no vault's ledger. A coin added to the bridge joins the
    /// two lists it belongs to and this one; every reader of the vault lifecycle follows.
    // TWO-PARTY-REVIEWED: a constant's shape has one endpoint by nature; what is built on it is pinned across two
    // parties in `safe_at_scale_a_vault_at_half_strength_merges_into_another_and_nothing_is_created`.
    #[test]
    fn the_custody_ledger_kinds_are_the_bridge_and_coin_ledgers_ascending_and_fit_a_vault_ledger_id() {
        let both: Vec<u32> = BRIDGE_LEDGERS.iter().chain(COIN_LEDGERS.iter()).copied().collect();
        assert_eq!(CUSTODY_LEDGER_KINDS, both.as_slice(), "⛔ the vault lifecycle's list is not the bridge ledgers then the coin ledgers");
        assert!(CUSTODY_LEDGER_KINDS.windows(2).all(|w| w[0] < w[1]), "⛔ the list is not strictly ascending: a merge's legs would have two orders");
        for a in CUSTODY_LEDGER_KINDS {
            assert!(*a < 256, "⛔ a ledger kind does not fit the eight bits a vault's ledger id gives it");
            assert!(PegLedger::is_custody_funded(*a), "⛔ a listed kind is not custody-funded");
            assert_eq!(ledger_asset_checked(vault_ledger(5, *a)), Some(*a), "a vault's ledger of a listed kind is a ledger");
        }
        let outside = (0u32..256).find(|a| !CUSTODY_LEDGER_KINDS.contains(a)).expect("a kind outside the list");
        assert_eq!(ledger_asset_checked(vault_ledger(5, outside)), None, "⛔ a vault kept a ledger of a kind outside the list");
        assert!(!PegLedger::merge_legs_in_order(&[]), "a merge of nothing is no merge");
    }

    /// ⛔⛔ SAFE AT SCALE — A VAULT AT HALF STRENGTH HANDS ITS LEDGERS TO ANOTHER VAULT, AND NOTHING IS CREATED. Forty
    /// custodians are three vaults by their seats (16 + 16 + 8). The custodian's ledger A proves; the peer's ledger B — its
    /// own validator set and ledger — judges and applies. Vault 2 (eight members) and vault 0 each took a deposit.
    /// CALIBRATION: two thirds of EACH vault sign the merge of vault 2 into vault 0, under the receiving vault's bound
    /// proof, and B takes it. REFUSED on B: either vault's quorum alone; under two thirds of one; the two quorums with no
    /// bound proof (seventeen of forty is not the whole set's two thirds); a sum proof removed; a LYING PROVER's receiving
    /// pair that is not the sum; a proof under another domain; a bound proven for the receiving vault BEFORE the merge; a
    /// merge out of a full vault; a vault merged into itself or into one that does not exist. NEVER REFUSED: the merge
    /// with no bound proof, signed by two thirds of the whole set as well. THE APPLY, on both parties from the same
    /// bytes: B holds vault 0 on the stated pairs, vault 2 back on its genesis pairs, vault 1 untouched; the merged
    /// openings open B's pairs and prove vault 0's next deposit; the same merge again is a replay. THEN vault 0 itself
    /// thins to eight and merges into vault 1: B holds the chain's own native words back at genesis.
    #[test]
    fn safe_at_scale_a_vault_at_half_strength_merges_into_another_and_nothing_is_created() {
        use crate::psm::BondQuorum;
        use usdm_decider::confidential_solvency as cs;
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let (custodians, mut vs_a, mut a) = vault_fixture(40);
        let (mut vs, mut b) = vault_party(&custodians);
        assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 16, 8], "forty custodians: seats 0–15, 16–31, 32–39");
        assert_eq!(vs.custody_merge_target(2), Some(0), "the fullest other vault, the lowest index among equals, takes vault 2's ledgers");
        let (v0, v1, v2) = (vault_members(&custodians, &vs, 0), vault_members(&custodians, &vs, 1), vault_members(&custodians, &vs, 2));
        let pair = |p: &PegLedger, v: u32, asset: u32| p.vault_pair(v, asset).expect("a pair");
        // a deposit on a vault, proven on A and applied on BOTH parties from the same bytes
        let deposit = |a: &mut PegLedger, b: &mut PegLedger, v: u32, open: &Opening2, dep: u128, mint: u128, tag: u64| -> Opening2 {
            let d = l(&[0x57, tag, 1, 1]);
            let (blob, hr, hm, after) = a.orchestrate_cover_at(v, true, NATIVE_PEG_ASSET_ID, open, dep, mint, &d, &d, None).expect("the deposit proves");
            let delta = PegLedger::mint_delta_commit(mint, d);
            for p in [a, b] {
                let posts = p.verify_cover_at(v, true, &blob, (hr, hm), delta, None).expect("each party verifies the cover against its own pairs");
                p.apply_cover_at(v, &posts);
            }
            after
        };
        let after2 = deposit(&mut a, &mut b, 2, &vault_genesis_openings(2), 1_500, 1_000, 2);
        let after0 = deposit(&mut a, &mut b, 0, &vault_genesis_openings(0), 3_000, 2_000, 0);
        assert!(b.vault_ledgers_moved(2) && b.vault_ledgers_moved(0) && !b.vault_ledgers_moved(1), "CALIBRATION: the peer holds vaults 0 and 2 moved, vault 1 on its genesis pairs");
        let v1_before = (pair(&b, 1, NATIVE_PEG_ASSET_ID), pair(&b, 1, XMR_PEG_ASSET_ID));

        // THE MERGE OF VAULT 2 INTO VAULT 0, proven on A from both vaults' openings
        let leg = |p: &PegLedger, i: usize| p.prove_vault_merge_leg(2, 0, CUSTODY_LEDGER_KINDS[i], after0[i], after2[i]).expect("a holder of both openings proves the sum");
        let ((l0, m0), (l1, m1)) = (leg(&a, 0), leg(&a, 1));
        let (p0, p1) = (l0.post, l1.post);
        assert!(a.prove_vault_merge_leg(2, 0, NATIVE_PEG_ASSET_ID, after0[0], vault_genesis_openings(2)[0]).is_none(), "⛔ an opening that does not open the retiring vault's pair proved a merge");
        // one leg per ledger kind the retiring vault moved (a deposit moves both bridge ledgers), in ascending asset order
        let legs = vec![l0, l1];
        // the two statements: the retiring vault's RELEASE (chain facts alone) and the receiving vault's ACCEPTANCE
        let (rel, msg) = (a.vault_merge_release_msg(2, 0), a.vault_merge_msg(2, 0, &legs));
        assert_eq!((rel.clone(), msg.clone()), (b.vault_merge_release_msg(2, 0), b.vault_merge_msg(2, 0, &legs)), "each party derives both statements from its own chain's pairs");
        let merged: Opening2 = [m0, m1];
        assert_eq!((merged[0].0, merged[0].2, merged[1].2), (after0[0].0 + after2[0].0, after0[0].2 + after2[0].2, after0[1].2 + after2[1].2), "the merged openings are the totals added");
        let (_, forfeit0) = vs_a.vault(0).expect("vault 0 exists");
        let ride = a.prove_vault_ride(0, forfeit0, &merged).expect("after the merge vault 0 stands inside its authority, so its bound proves").encode();
        let (from6, into11) = (sign_all(&v2[..6], &rel), sign_all(&v0[..11], &msg));
        let check = |peer: &PegLedger, vs: &ValidatorSet, from: u32, into: u32, legs: &[MergeLeg], ride: &[u8], release: &[MintAttestor], accept: &[MintAttestor]| {
            peer.check_vault_merge(from, into, legs, ride, vs, &MlDsaVerifier, release, accept)
        };
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &from6, &into11), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of each vault carry the merge under the receiving vault's bound");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &from6, &[]), PegOutcome::InsufficientThreshold), "⛔ the retiring vault alone moved its ledgers onto another vault");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &[], &into11), PegOutcome::InsufficientThreshold), "⛔ the receiving vault alone took another vault's ledgers");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &sign_all(&v2[..5], &rel), &into11), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the retiring vault carried a merge");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &from6, &sign_all(&v0[..10], &msg)), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the receiving vault carried a merge");
        // each list is tallied against its OWN statement: the receiving vault's quorum signing the release accepts nothing,
        // and the retiring vault's quorum signing the acceptance releases nothing
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &from6, &sign_all(&v0[..11], &rel)), PegOutcome::InsufficientThreshold), "⛔ a release signature was counted as an acceptance of the totals");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&ride, &sign_all(&v2[..6], &msg), &into11), PegOutcome::InsufficientThreshold), "⛔ an acceptance signature was counted as the retiring vault's release");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&[], &from6, &into11), PegOutcome::InsufficientThreshold), "⛔ two vaults' quorums (17 of 40) carried a merge with no bound on the receiving vault");
        // the whole set's two thirds (27 of 40) sign the release beside the retiring vault's own: never refused
        let whole: Vec<MintAttestor> = from6.iter().cloned().chain(sign_all(&v0[..11], &rel)).chain(sign_all(&v1[..10], &rel)).collect();
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&[], &whole, &into11), PegOutcome::ConfidentialPublished), "⛔ a merge the whole set released was refused for want of a bound proof");
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&[], &whole[..26], &into11), PegOutcome::InsufficientThreshold), "⛔ 26 of 40 is under two thirds");
        // STRIP: a sum proof removed
        let mut stripped = legs.clone();
        stripped[0].minted_sum.clear();
        assert!(matches!(check(&b, &vs, 2, 0, &stripped, &ride, &from6, &into11), PegOutcome::BadRequest), "⛔ a merge with a sum proof removed moved the peer's ledgers");
        // A LEDGER LEFT BEHIND: a merge of one of the two moved ledgers, signed over its own statement by the receiving
        // vault and released by the whole set — the retiring vault would keep a moved ledger its custodians could then
        // walk away from. And the list's one order: a kind twice, the kinds reversed, a kind the chain does not keep.
        let one_leg = sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &legs[..1]));
        assert!(matches!(check(&b, &vs, 2, 0, &legs[..1], &[], &whole, &one_leg), PegOutcome::BadRequest), "⛔ a merge that left a moved ledger behind was taken");
        let twice = vec![legs[0].clone(), legs[0].clone()];
        assert!(matches!(check(&b, &vs, 2, 0, &twice, &[], &whole, &sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &twice))), PegOutcome::BadRequest), "⛔ one ledger kind was merged twice in one object");
        let reversed = vec![legs[1].clone(), legs[0].clone()];
        assert!(matches!(check(&b, &vs, 2, 0, &reversed, &[], &whole, &sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &reversed))), PegOutcome::BadRequest), "⛔ a second encoding of the same merge (its legs reversed) was taken");
        let mut stray = legs.clone();
        stray.push(MergeLeg { asset: COIN_BTC_ASSET_ID, ..legs[0].clone() });
        assert!(matches!(check(&b, &vs, 2, 0, &stray, &[], &whole, &sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &stray))), PegOutcome::BadRequest), "⛔ a leg for a ledger that holds nothing was taken");
        let mut unknown = legs.clone();
        unknown.push(MergeLeg { asset: 200, ..legs[0].clone() });
        assert!(matches!(check(&b, &vs, 2, 0, &unknown, &[], &whole, &sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &unknown))), PegOutcome::BadRequest), "⛔ a leg naming no custody-funded ledger kind was taken");
        // SUBSTITUTE under the honest signatures: the acceptance binds the pairs after
        let mut swapped = legs.clone();
        swapped[0].post = p1;
        swapped[1].post = p0;
        assert!(matches!(check(&b, &vs, 2, 0, &swapped, &ride, &from6, &into11), PegOutcome::InsufficientThreshold), "⛔ the signatures carried receiving pairs they never named");
        // LYING PROVER: well-formed, false in one place — a receiving minted total five more than the sum, proven as the
        // honest sum of two values the prover chose, signed over ITS OWN statement by both quorums
        let u = |v: u128| super::u256_from_u128(v);
        let (lie_m, lie_c) = cs::prove_transition_carrier(u(after0[0].2), u(after2[0].2 + 5), &[after0[0].3, after2[0].3, m0.3], cs::TransitionDomain::VaultMerge).expect("the prover's own sum proves");
        let mut lie = legs.clone();
        lie[0].post = (p0.0, lie_c[2]);
        lie[0].minted_sum = lie_m;
        let lie_accept = sign_all(&v0[..11], &b.vault_merge_msg(2, 0, &lie));
        assert!(matches!(check(&b, &vs, 2, 0, &lie, &[], &whole, &lie_accept), PegOutcome::BadRequest), "⛔ LYING PROVER: a receiving total that is not the sum was taken — five USDm atomic created by a merge");
        // a proof of the honest sum under ANOTHER domain is no merge proof
        let (other, oc) = cs::prove_transition_carrier(u(after0[0].2), u(after2[0].2), &[after0[0].3, after2[0].3, m0.3], cs::TransitionDomain::VaultSum).expect("the sum proves under the ride's domain");
        assert_eq!(oc[2], p0.1, "CALIBRATION: the same statement, another domain");
        let mut cross = legs.clone();
        cross[0].minted_sum = other;
        assert!(matches!(check(&b, &vs, 2, 0, &cross, &ride, &from6, &into11), PegOutcome::BadRequest), "⛔ a proof made for another door was taken as a merge proof");
        // a bound proven for the receiving vault BEFORE the merge says nothing about it after
        let stale_ride = a.prove_vault_ride(0, forfeit0, &after0).expect("the bound before the merge proves").encode();
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&stale_ride, &from6, &into11), PegOutcome::BadRequest), "⛔ LYING PROVER: a bound over the receiving vault's old totals carried the merge");
        let mut other_vault = VaultRide::decode(&ride).expect("a ride");
        other_vault.vault = 1;
        assert!(matches!(check(&b, &vs, 2, 0, &legs,&other_vault.encode(), &from6, &into11), PegOutcome::BadRequest), "⛔ a bound naming another vault carried the merge");
        // only OUT of a vault at half strength or under; never into itself or into nothing
        let full_rel: Vec<MintAttestor> = [&v0[..11], &v1[..11], &v2[..6]].iter().flat_map(|s| sign_all(s, &b.vault_merge_release_msg(0, 1))).collect();
        assert!(matches!(check(&b, &vs, 0, 1, &legs,&[], &full_rel, &sign_all(&v1[..11], &b.vault_merge_msg(0, 1, &legs))), PegOutcome::BadRequest), "⛔ a full vault's ledgers were merged away");
        assert!(matches!(check(&b, &vs, 2, 2, &legs,&ride, &from6, &into11), PegOutcome::BadRequest), "⛔ a vault merged into itself");
        assert!(matches!(check(&b, &vs, 2, 3, &legs,&ride, &from6, &into11), PegOutcome::BadRequest), "⛔ a vault merged into one that does not exist");

        // THE APPLY, on both parties from the same bytes
        let census_before = b.wrapped_asset_census().len();
        assert!(matches!(a.vault_merge(2, 0, &legs,&ride, &vs_a, &MlDsaVerifier, &from6, &into11), PegOutcome::ConfidentialMinted), "A applies its own object");
        assert!(matches!(b.vault_merge(2, 0, &legs,&ride, &vs, &MlDsaVerifier, &from6, &into11), PegOutcome::ConfidentialMinted), "the peer applies the merge");
        assert_eq!((pair(&b, 0, NATIVE_PEG_ASSET_ID), pair(&b, 0, XMR_PEG_ASSET_ID)), (p0, p1), "the peer holds vault 0 on the stated pairs");
        assert_eq!((pair(&b, 0, NATIVE_PEG_ASSET_ID), pair(&b, 0, XMR_PEG_ASSET_ID)), (pair(&a, 0, NATIVE_PEG_ASSET_ID), pair(&a, 0, XMR_PEG_ASSET_ID)), "both parties hold the same pairs");
        assert_eq!(PegLedger::cover_posts(&merged), [p0, p1], "…which the merged openings (the totals added) open: nothing created, nothing lost");
        assert!(!b.vault_ledgers_moved(2), "the peer holds vault 2 back on its genesis pairs");
        assert_eq!(Some(pair(&b, 2, NATIVE_PEG_ASSET_ID)), PegLedger::vault_genesis_pair(2, NATIVE_PEG_ASSET_ID));
        assert_eq!(b.wrapped_asset_census().len(), census_before - 2, "the retired vault's two ledgers left the registry the snapshot and the bundle carry");
        assert_eq!((pair(&b, 1, NATIVE_PEG_ASSET_ID), pair(&b, 1, XMR_PEG_ASSET_ID)), v1_before, "⛔ the merge moved a third vault on the peer");
        assert!(matches!(b.vault_merge(2, 0, &legs,&ride, &vs, &MlDsaVerifier, &from6, &into11), PegOutcome::Replay), "the same merge again is a replay: the retiring vault holds nothing");
        assert!(b.orchestrate_cover_at(0, true, NATIVE_PEG_ASSET_ID, &merged, 1_500, 1_000, &l(&[0x58, 1, 1, 1]), &l(&[0x58, 1, 1, 1]), None).is_some(), "vault 0's next deposit proves from the merged openings against the peer's state");
        assert!(b.orchestrate_cover_at(2, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(2), 1_500, 1_000, &l(&[0x59, 1, 1, 1]), &l(&[0x59, 1, 1, 1]), None).is_some(), "…and vault 2 starts again from its genesis openings");

        // VAULT 0 ITSELF THINS TO EIGHT AND MERGES INTO VAULT 1: the chain's own native words return to genesis
        for c in &v0[8..] {
            assert!(vs_a.remove(&c.id()).is_some() && vs.remove(&c.id()).is_some(), "a fixture exit on both parties");
        }
        assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![8, 16, 8], "eight left vault 0: every other vault's members are who they were");
        assert_eq!(vs.custody_merge_target(0), Some(1));
        let open1 = vault_genesis_openings(1);
        let leg0 = |i: usize| a.prove_vault_merge_leg(0, 1, CUSTODY_LEDGER_KINDS[i], open1[i], merged[i]).expect("the sum proves");
        let ((k0, n0), (k1, n1)) = (leg0(0), leg0(1));
        let (q0, q1) = (k0.post, k1.post);
        let legs01 = vec![k0, k1];
        let (_, forfeit1) = vs_a.vault(1).expect("vault 1 exists");
        let ride01 = a.prove_vault_ride(1, forfeit1, &[n0, n1]).expect("vault 1's bound after the merge proves").encode();
        let (rel01, acc01) = (sign_all(&v0[..6], &b.vault_merge_release_msg(0, 1)), sign_all(&v1[..11], &b.vault_merge_msg(0, 1, &legs01)));
        assert!(matches!(b.vault_merge(0, 1, &legs01, &ride01, &vs, &MlDsaVerifier, &rel01, &acc01), PegOutcome::ConfidentialMinted), "the peer applies vault 0's merge into vault 1");
        assert!(b.reserve_is_zero() && !b.vault_ledgers_moved(0), "the peer holds the chain's own native words back on their genesis pair");
        assert_eq!((pair(&b, 1, NATIVE_PEG_ASSET_ID), pair(&b, 1, XMR_PEG_ASSET_ID)), (q0, q1), "…and vault 1 on the stated pairs");
        assert_eq!(n0.2 + n1.2, 3_000, "every USDm atomic the two deposits minted is in vault 1's ledgers now: 1,000 + 2,000");
    }

    /// ⛔⛔ SAFE AT SCALE, stage three (spec §3g.1; `Class::VaultRebalance`) — PART OF A VAULT'S LEDGER IS CARVED OUT,
    /// TAKEN BY ANOTHER VAULT OR TAKEN BACK, AND NOTHING IS CREATED. Forty custodians, three vaults (16 + 16 + 8). The
    /// custodian's ledger A proves; the peer's ledger B — its own validator set and ledger — judges and applies. Vault 0
    /// took a deposit (3,000 reserve, 2,000 minted).
    /// THE CARVE, half of vault 0's Bitcoin bridge ledger for vault 1. CALIBRATION: two thirds of the giver, out of a
    /// FULL vault (the merge door's strength rule is not this door's). REFUSED on B: under two thirds; the receiver's
    /// quorum; a leg with no part; a sum removed; a LYING PROVER whose ledger loses five less than the part; a true sum
    /// under the merge's domain; a ledger the giver holds nothing of; a vault for itself or for nothing. THE APPLY on
    /// both: the giver on the pair after, the part in its slot, the receiver untouched; a second carve out of the vault
    /// refused; A VAULT WITH A PART AT REST CARRIES NOTHING ON ITS OWN WORD (its ride is refused, one that held before
    /// the carve included).
    /// THE TAKE by vault 1. CALIBRATION: two thirds of the receiver under its bound after. REFUSED: the giver's quorum; a
    /// carve's signatures; under two thirds; two thirds of the vault with no bound (and NOT refused under the whole set's
    /// two thirds); a LYING PROVER whose receiver gains five more than the slot's part; a leg that states a part of its
    /// own; a bound before the take, or naming another vault; a slot that does not exist. THE APPLY on both: the
    /// receiver on its pair after, the slot gone, the two ledgers adding to the deposit; the same take again refused;
    /// the giver's word restored.
    /// THE CANCEL of a second carve (a quarter, for vault 2). REFUSED: inside the rotation day; the receiver's quorum.
    /// THE APPLY: the giver back to its total, the slot gone; a take of the cancelled slot refused. THE SLOT TRAVELS AND
    /// REWINDS: a joiner adopting B's carried words holds B's slot; an undo to before the carve empties it.
    /// TWO-PARTY-REVIEWED: every verdict and every pair is read on B, which holds its own set and ledger.
    #[test]
    fn safe_at_scale_part_of_a_vaults_ledger_moves_to_another_vault_and_nothing_is_created() {
        use crate::psm::BondQuorum;
        use usdm_decider::confidential_solvency as cs;
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let (custodians, vs_a, mut a) = vault_fixture(40);
        let (vs, mut b) = vault_party(&custodians);
        let (v0, v1, v2) = (vault_members(&custodians, &vs, 0), vault_members(&custodians, &vs, 1), vault_members(&custodians, &vs, 2));
        let pair = |p: &PegLedger, v: u32, asset: u32| p.vault_pair(v, asset).expect("a pair");
        let commits = |x: LedgerOpening| PegLedger::commits_of_opening(x.0, x.1, x.2, x.3);
        let d = l(&[0x5b, 1, 1, 1]);
        let (blob, hr, hm, after0) = a.orchestrate_cover_at(0, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(0), 3_000, 2_000, &d, &d, None).expect("the deposit proves");
        for p in [&mut a, &mut b] {
            let posts = p.verify_cover_at(0, true, &blob, (hr, hm), PegLedger::mint_delta_commit(2_000, d), None).expect("each party verifies the cover");
            p.apply_cover_at(0, &posts);
        }
        let open1 = vault_genesis_openings(1);
        let (v1_xmr, v0_xmr, v2_native) = (pair(&b, 1, XMR_PEG_ASSET_ID), pair(&b, 0, XMR_PEG_ASSET_ID), pair(&b, 2, NATIVE_PEG_ASSET_ID));
        let (_, forfeit0) = vs_a.vault(0).expect("vault 0 exists");
        let (_, forfeit1) = vs_a.vault(1).expect("vault 1 exists");
        let u = |v: u128| super::u256_from_u128(v);
        let dom = cs::TransitionDomain::VaultRebalance;
        // a ride vault 0 proves BEFORE the carve, over its two pairs then — it holds then
        let pre_ride = VaultRide::decode(&a.prove_vault_ride(0, forfeit0, &after0).expect("vault 0 stands inside its authority").encode()).expect("a ride");
        let posts0 = [commits(after0[0]), commits(after0[1])];
        assert!(b.vault_ride_holds(&pre_ride, forfeit0, &posts0), "CALIBRATION: vault 0's own word carries its deposits");

        // ── THE CARVE: half of vault 0's Bitcoin bridge ledger for vault 1, proven on A from its own opening ──
        let (leg, part, from_after) = a.prove_vault_carve_leg(0, NATIVE_PEG_ASSET_ID, after0[0], (1_500, 1_000)).expect("a giving custodian proves its carve");
        assert_eq!((part.0, part.2, from_after.0, from_after.2), (1_500, 1_000, 1_500, 1_000), "half leaves, half stays");
        // the door takes any part its sums prove (a half here); the RECEIVER holds a part to exactly the eighth the rule owes
        assert!(!PegLedger::parts_are_one_fraction(&[(part, from_after)]), "⛔ a half was read as the eighth the rule owes");
        let (eighth, rest) = PegLedger::giver_opening_after_rebalance(after0[0], (375, 250)).expect("an eighth derives");
        assert!(PegLedger::parts_are_one_fraction(&[(eighth, rest)]), "CALIBRATION: an eighth of both words is the part the rule owes");
        assert!(!PegLedger::parts_are_one_fraction(&[((375, eighth.1, 200, eighth.3), (2_625, rest.1, 1_800, rest.3))]), "⛔ a part that sheds less USDm than coins read as the eighth");
        assert!(a.prove_vault_carve_leg(0, NATIVE_PEG_ASSET_ID, after0[0], (3_001, 0)).is_none(), "⛔ more than the giver holds was proven carved");
        assert!(a.prove_vault_carve_leg(0, NATIVE_PEG_ASSET_ID, open1[0], (0, 0)).is_none(), "⛔ an opening that does not open the giver's pair proved a carve");
        let legs = vec![leg];
        let posts = PegLedger::rebalance_posts(&legs);
        let carve_msg = a.vault_carve_msg(0, 1, &posts);
        assert_eq!(carve_msg, b.vault_carve_msg(0, 1, &posts), "each party derives the statement from its own chain's pairs");
        let from11 = sign_all(&v0[..11], &carve_msg);
        let carve = |peer: &PegLedger, from: u32, into: u32, legs: &[RebalanceLeg], sigs: &[MintAttestor]| peer.check_vault_carve(from, into, legs, &vs, &MlDsaVerifier, sigs);
        let signed_carve = |legs: &[RebalanceLeg]| sign_all(&v0[..11], &b.vault_carve_msg(0, 1, &PegLedger::rebalance_posts(legs)));
        assert!(matches!(carve(&b, 0, 1, &legs, &from11), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of the giver carve a part out of a full vault");
        assert!(matches!(carve(&b, 0, 1, &legs, &sign_all(&v0[..10], &carve_msg)), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the giver carved a part");
        assert!(matches!(carve(&b, 0, 1, &legs, &sign_all(&v1[..11], &carve_msg)), PegOutcome::InsufficientThreshold), "⛔ the receiving vault carved a part out of the giver's ledger");
        let mut no_part = legs.clone();
        no_part[0].part = None;
        assert!(matches!(carve(&b, 0, 1, &no_part, &signed_carve(&no_part)), PegOutcome::BadRequest), "⛔ a carve that states no part was taken");
        let mut stripped = legs.clone();
        stripped[0].minted_sum.clear();
        assert!(matches!(carve(&b, 0, 1, &stripped, &from11), PegOutcome::BadRequest), "⛔ a carve with a sum proof removed was taken");
        // LYING PROVER: the giver's minted total falls by five less than the part — its own sum, honestly proven
        let (lie_sum, lie_c) = cs::prove_transition_carrier(u(from_after.2 + 5), u(part.2), &[from_after.3, part.3, after0[0].3], dom).expect("the prover's own sum proves");
        let mut lie = legs.clone();
        lie[0].post.1 = lie_c[0];
        lie[0].minted_sum = lie_sum;
        assert!(matches!(carve(&b, 0, 1, &lie, &signed_carve(&lie)), PegOutcome::BadRequest), "⛔ LYING PROVER: the giver's ledger lost five USDm atomic less than the part it carved");
        // a TRUE sum proven under the merge's domain is no rebalance proof
        let (other, oc) = cs::prove_transition_carrier(u(from_after.2), u(part.2), &[from_after.3, part.3, after0[0].3], cs::TransitionDomain::VaultMerge).expect("the same sum, another domain");
        assert_eq!(oc[0], legs[0].post.1, "CALIBRATION: the same statement, another domain");
        let mut cross = legs.clone();
        cross[0].minted_sum = other;
        assert!(matches!(carve(&b, 0, 1, &cross, &from11), PegOutcome::BadRequest), "⛔ a proof made for the merge door was taken as a carve proof");
        let mut stray = legs.clone();
        stray.push(RebalanceLeg { asset: COIN_BTC_ASSET_ID, ..legs[0].clone() });
        assert!(matches!(carve(&b, 0, 1, &stray, &signed_carve(&stray)), PegOutcome::BadRequest), "⛔ a part of a ledger that holds nothing was carved");
        assert!(matches!(carve(&b, 0, 0, &legs, &from11), PegOutcome::BadRequest), "⛔ a vault carved a part for itself");
        assert!(matches!(carve(&b, 0, 3, &legs, &from11), PegOutcome::BadRequest), "⛔ a part was carved for a vault that does not exist");

        // THE CARVE, applied on both parties from the same bytes, at the carrying block's blue score
        assert!(matches!(a.vault_carve(0, 1, &legs, 100, &vs_a, &MlDsaVerifier, &from11), PegOutcome::ConfidentialMinted), "A applies its own carve");
        assert!(matches!(b.vault_carve(0, 1, &legs, 100, &vs, &MlDsaVerifier, &from11), PegOutcome::ConfidentialMinted), "the peer applies the carve");
        assert_eq!(pair(&b, 0, NATIVE_PEG_ASSET_ID), legs[0].post, "the peer holds the giver on its pair after");
        assert_eq!(commits(from_after), legs[0].post, "…which the giving custodian's opening after opens");
        assert_eq!(pair(&b, 1, NATIVE_PEG_ASSET_ID), commits(open1[0]), "⛔ the receiver's ledger moved before it took anything");
        let slot = b.vault_part(0).expect("the part rests in the giver's slot").clone();
        assert_eq!((slot.into, slot.opened_tick, slot.legs.clone()), (1, 100, vec![PartLeg { asset: NATIVE_PEG_ASSET_ID, part: commits(part), from_post: legs[0].post }]), "the slot names the vault it is for, its block and the part");
        assert_eq!(a.vault_part(0), Some(&slot), "both parties hold one slot");
        assert!(matches!(carve(&b, 0, 1, &legs, &from11), PegOutcome::Replay), "⛔ a second part was carved out of a vault with one at rest");
        assert!(!b.vault_ride_holds(&pre_ride, forfeit0, &posts0), "⛔ a vault with a part at rest still carried a deposit on its own word");
        assert!(a.prove_vault_ride(0, forfeit0, &[from_after, after0[1]]).is_none(), "⛔ a vault with a part at rest proved a ride");

        // ── THE TAKE by vault 1, from its own opening and the part it was handed ──
        let (tleg, into_after) = a.prove_vault_part_added_leg(0, 1, NATIVE_PEG_ASSET_ID, open1[0], part).expect("a receiving custodian proves its take");
        assert_eq!((into_after.0, into_after.2), (1_500, 1_000), "the part arrives");
        assert!(a.prove_vault_part_added_leg(0, 1, NATIVE_PEG_ASSET_ID, open1[0], from_after).is_none(), "⛔ an opening that is not the slot's part proved a take");
        assert!(a.prove_vault_part_added_leg(2, 1, NATIVE_PEG_ASSET_ID, open1[0], part).is_none(), "⛔ a take of a slot that does not exist proved");
        let tlegs = vec![tleg];
        let tposts = PegLedger::rebalance_posts(&tlegs);
        let take_msg = b.vault_take_msg(0, &tposts);
        assert_eq!(take_msg, a.vault_take_msg(0, &tposts), "each party derives the take from its own chain's slot and pairs");
        let into11 = sign_all(&v1[..11], &take_msg);
        let ride = a.prove_vault_ride(1, forfeit1, &[into_after, open1[1]]).expect("after the take vault 1 stands inside its authority").encode();
        let take = |peer: &PegLedger, from: u32, legs: &[RebalanceLeg], ride: &[u8], sigs: &[MintAttestor]| peer.check_vault_take(from, legs, ride, &vs, &MlDsaVerifier, sigs);
        assert!(matches!(take(&b, 0, &tlegs, &ride, &into11), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of the receiver take the part under its bound after");
        assert!(matches!(take(&b, 0, &tlegs, &ride, &sign_all(&v0[..11], &take_msg)), PegOutcome::InsufficientThreshold), "⛔ the giving vault took its own part into another vault");
        assert!(matches!(take(&b, 0, &tlegs, &ride, &sign_all(&v1[..11], &carve_msg)), PegOutcome::InsufficientThreshold), "⛔ signatures over the carve were counted as the receiver's take");
        assert!(matches!(take(&b, 0, &tlegs, &ride, &sign_all(&v1[..10], &take_msg)), PegOutcome::InsufficientThreshold), "⛔ under two thirds of the receiver took a part");
        assert!(matches!(take(&b, 0, &tlegs, &[], &into11), PegOutcome::InsufficientThreshold), "⛔ the receiver's quorum (11 of 40) took a part with no bound on it");
        let whole: Vec<MintAttestor> = [&v0[..11], &v1[..11], &v2[..5]].iter().flat_map(|s| sign_all(s, &take_msg)).collect();
        assert!(matches!(take(&b, 0, &tlegs, &[], &whole), PegOutcome::ConfidentialPublished), "⛔ a take the whole set signed (27 of 40) was refused for want of a bound proof");
        // LYING PROVER: the receiver's minted total grows by five more than the slot's part
        let (lie_sum, lie_c) = cs::prove_transition_carrier(u(open1[0].2), u(part.2 + 5), &[open1[0].3, part.3, into_after.3], dom).expect("the prover's own sum proves");
        let mut lie = tlegs.clone();
        lie[0].post.1 = lie_c[2];
        lie[0].minted_sum = lie_sum;
        let lie_sigs: Vec<MintAttestor> = [&v0[..11], &v1[..11], &v2[..5]].iter().flat_map(|s| sign_all(s, &b.vault_take_msg(0, &PegLedger::rebalance_posts(&lie)))).collect();
        assert!(matches!(take(&b, 0, &lie, &[], &lie_sigs), PegOutcome::BadRequest), "⛔ LYING PROVER: the receiver gained five USDm atomic more than the slot's part");
        let mut stated = tlegs.clone();
        stated[0].part = Some(slot.legs[0].part);
        let stated_sigs = sign_all(&v1[..11], &b.vault_take_msg(0, &PegLedger::rebalance_posts(&stated)));
        assert!(matches!(take(&b, 0, &stated, &ride, &stated_sigs), PegOutcome::BadRequest), "⛔ a take that states a part of its own was taken");
        let stale = a.prove_vault_ride(1, forfeit1, &open1).expect("vault 1's bound before the take proves").encode();
        assert!(matches!(take(&b, 0, &tlegs, &stale, &into11), PegOutcome::BadRequest), "⛔ LYING PROVER: a bound over the receiver's old totals carried the take");
        let mut other_vault = VaultRide::decode(&ride).expect("a ride");
        other_vault.vault = 2;
        assert!(matches!(take(&b, 0, &tlegs, &other_vault.encode(), &into11), PegOutcome::BadRequest), "⛔ a bound naming another vault carried the take");
        assert!(matches!(take(&b, 2, &tlegs, &ride, &into11), PegOutcome::Replay), "⛔ a take of a slot nobody carved was taken");

        // THE TAKE, applied on both parties from the same bytes
        assert!(matches!(a.vault_take(0, &tlegs, &ride, &vs_a, &MlDsaVerifier, &into11), PegOutcome::ConfidentialMinted), "A applies its own take");
        assert!(matches!(b.vault_take(0, &tlegs, &ride, &vs, &MlDsaVerifier, &into11), PegOutcome::ConfidentialMinted), "the peer applies the take");
        assert_eq!((pair(&b, 0, NATIVE_PEG_ASSET_ID), pair(&b, 1, NATIVE_PEG_ASSET_ID)), (legs[0].post, tlegs[0].post), "the peer holds both vaults on the stated pairs");
        assert_eq!(commits(into_after), tlegs[0].post, "…which the receiving custodian's opening after opens");
        assert!(b.vault_part(0).is_none() && a.vault_part(0).is_none(), "⛔ the slot outlived its take");
        assert_eq!((from_after.0 + into_after.0, from_after.2 + into_after.2), (3_000, 2_000), "⛔ the two ledgers no longer add to what the deposit made: nothing created, nothing lost");
        assert_eq!((pair(&b, 1, XMR_PEG_ASSET_ID), pair(&b, 0, XMR_PEG_ASSET_ID), pair(&b, 2, NATIVE_PEG_ASSET_ID)), (v1_xmr, v0_xmr, v2_native), "⛔ the move touched a ledger it does not name");
        assert!(matches!(b.vault_take(0, &tlegs, &ride, &vs, &MlDsaVerifier, &into11), PegOutcome::Replay), "⛔ REPLAY: the same take added the part again");
        assert!(a.prove_vault_ride(0, forfeit0, &[from_after, after0[1]]).is_some(), "the giver's own word carries its deposits again once its slot closed");
        let dd = l(&[0x5c, 1, 1, 1]);
        assert!(b.orchestrate_cover_at(0, true, NATIVE_PEG_ASSET_ID, &[from_after, after0[1]], 1_500, 1_000, &dd, &dd, None).is_some(), "the giver's next deposit proves from its opening after");
        assert!(b.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &[into_after, open1[1]], 1_500, 1_000, &dd, &dd, None).is_some(), "…and the receiver's from its own");

        // ── THE CANCEL of a second carve: a quarter of what vault 0 holds now, for vault 2, which never takes it ──
        let (leg2, part2, after2) = a.prove_vault_carve_leg(0, NATIVE_PEG_ASSET_ID, from_after, (1_500 >> 2, 1_000 >> 2)).expect("the second carve proves");
        let legs2 = vec![leg2];
        let sigs2 = sign_all(&v0[..11], &b.vault_carve_msg(0, 2, &PegLedger::rebalance_posts(&legs2)));
        for (p, q) in [(&mut a, &vs_a), (&mut b, &vs)] {
            assert!(matches!(p.vault_carve(0, 2, &legs2, 200, q, &MlDsaVerifier, &sigs2), PegOutcome::ConfidentialMinted), "each party applies the second carve");
        }
        let (cleg, back) = a.prove_vault_part_added_leg(0, 0, NATIVE_PEG_ASSET_ID, after2, part2).expect("the giver proves its cancel");
        assert_eq!((back.0, back.2), (1_500, 1_000), "the giver is whole again");
        let clegs = vec![cleg];
        let cancel_msg = b.vault_cancel_msg(0, &PegLedger::rebalance_posts(&clegs));
        assert_ne!(cancel_msg, b.vault_take_msg(0, &PegLedger::rebalance_posts(&clegs)), "a cancel and a take of one slot are two statements");
        let csigs = sign_all(&v0[..11], &cancel_msg);
        let window = 50;
        let cancel = |peer: &PegLedger, blue: u64, sigs: &[MintAttestor]| peer.check_vault_cancel(0, &clegs, blue, window, &vs, &MlDsaVerifier, sigs);
        assert!(matches!(cancel(&b, 249, &csigs), PegOutcome::BadRequest), "⛔ a part was taken back inside the receiver's day");
        assert!(matches!(cancel(&b, 250, &sign_all(&v2[..6], &cancel_msg)), PegOutcome::InsufficientThreshold), "⛔ the receiving vault took the giver's part back for it");
        assert!(matches!(cancel(&b, 250, &csigs), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of the giver take an untaken part back after the day");
        for (p, q) in [(&mut a, &vs_a), (&mut b, &vs)] {
            assert!(matches!(p.vault_cancel(0, &clegs, 250, window, q, &MlDsaVerifier, &csigs), PegOutcome::ConfidentialMinted), "each party applies the cancel");
        }
        assert_eq!(pair(&b, 0, NATIVE_PEG_ASSET_ID), commits(back), "the peer holds the giver on its pair after the cancel");
        assert!(b.vault_part(0).is_none(), "⛔ the slot outlived its cancel");
        let late = a.prove_vault_part_added_leg(0, 2, NATIVE_PEG_ASSET_ID, vault_genesis_openings(2)[0], part2);
        assert!(late.is_none(), "⛔ a take of a cancelled part proved");
        assert!(matches!(b.check_vault_take(0, &clegs, &[], &vs, &MlDsaVerifier, &csigs), PegOutcome::Replay), "⛔ a cancelled part was taken as well");

        // THE SLOT TRAVELS AND REWINDS: a third carve, carried to a joiner and undone
        let (leg3, _, _) = a.prove_vault_carve_leg(0, NATIVE_PEG_ASSET_ID, back, (1_500 >> 3, 1_000 >> 3)).expect("the third carve proves");
        let legs3 = vec![leg3];
        let sigs3 = sign_all(&v0[..11], &b.vault_carve_msg(0, 1, &PegLedger::rebalance_posts(&legs3)));
        let before3 = b.clone();
        assert!(matches!(b.vault_carve(0, 1, &legs3, 300, &vs, &MlDsaVerifier, &sigs3), PegOutcome::ConfidentialMinted), "the peer applies a third carve");
        let mut joiner = PegLedger::genesis(15_000);
        joiner.adopt_certified_br(&b.br_census());
        assert_eq!(joiner.vault_part(0), b.vault_part(0), "⛔ a node that adopts the carried words does not hold the slot");
        let mut words = b.br_census();
        words.vault_parts[0].1.legs.clear();
        let mut fooled = PegLedger::genesis(15_000);
        fooled.adopt_certified_br(&words);
        assert!(fooled.vault_part(0).is_none(), "⛔ a carried slot of no leg was installed");
        let undo = b.undo_to(&before3);
        assert!(b.apply_undo(&undo), "the undo names only fields this build knows");
        assert!(b.vault_part(0).is_none() && b.vault_pair(0, NATIVE_PEG_ASSET_ID) == before3.vault_pair(0, NATIVE_PEG_ASSET_ID), "⛔ a rewound ledger still holds the part the rewound block carved");
    }

    /// ⭐ SAFE AT SCALE, stage three (spec §3g.2) — WHAT A VAULT PAST ITS BOUND OWES TO MOVE is AN EIGHTH of both words of
    /// both bridge ledgers, whatever the excess; nothing while it stands inside; nothing when the eighth is nothing. And
    /// the receiver's check holds a handed part to exactly that eighth (`parts_are_one_fraction`).
    /// CALIBRATION of the rule it replaced (the smallest of ⅛, ¼, ½ that brings the giver inside): at 2,000 against 1,200
    /// that rule owed a half; this one owes an eighth, and the next round the next (the custody lifecycle model's
    /// `a_vault_far_past_its_bound_lands_inside_it_by_eighths_where_no_vault_could_take_a_half` is why).
    // TWO-PARTY-REVIEWED: a pure rule over a custodian's own openings (the giver's custodians and the receiver's each
    // recompute it from the same openings); what is built on it crosses nodes in the rebalance lane's pin.
    #[test]
    fn a_vault_past_its_bound_owes_an_eighth_of_both_words_each_round_and_the_receiver_holds_a_part_to_exactly_that() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let open = |r0: u128, m0: u128, r1: u128, m1: u128| -> [LedgerOpening; 2] { [(r0, l(&[1, 1, 1, 1]), m0, l(&[2, 1, 1, 1])), (r1, l(&[3, 1, 1, 1]), m1, l(&[4, 1, 1, 1]))] };
        let due = |o: &[LedgerOpening; 2], authority: u128| PegLedger::rebalance_part_due(o, authority);
        let one = open(3_000, 2_000, 0, 0);
        assert_eq!(due(&one, 2_000), None, "a vault at its authority owes nothing");
        assert_eq!(due(&one, 5_000), None, "…nor one far inside it");
        assert_eq!(due(&one, 1_800), Some([(375, 250), (0, 0)]), "2,000 against 1,800: an eighth (250) leaves 1,750");
        assert_eq!(due(&one, 1_200), Some([(375, 250), (0, 0)]), "⛔ 2,000 against 1,200: an eighth, not the half the first rule owed");
        assert_eq!(due(&one, 1), Some([(375, 250), (0, 0)]), "far past its bound, still an eighth a round");
        let two = open(3_000, 2_000, 800, 400);
        assert_eq!(due(&two, 2_200), Some([(375, 250), (100, 50)]), "⛔ both ledgers give an eighth of each word");
        // ROUNDS: a vault at twice its bound lands inside in ⌈ln 2 / ln (8/7)⌉ = 6 eighths
        let mut r = open(4_000, 2_000, 0, 0);
        let mut rounds = 0;
        while let Some(p) = due(&r, 1_000) {
            r[0].0 -= p[0].0;
            r[0].2 -= p[0].1;
            rounds += 1;
            assert!(rounds <= 6, "a vault at twice its bound is still past it after {rounds} eighths");
        }
        assert!(r[0].2 <= 1_000 && rounds == 6, "six eighths bring 2,000 inside 1,000 ({} after {rounds})", r[0].2);
        // the receiver's check: the part handed over against the giver's opening as the carve left it
        for (o, authority) in [(&one, 1_800u128), (&two, 2_200), (&open(3_333, 2_221, 777, 409), 2_000)] {
            let part = due(o, authority).expect("past its authority");
            for (i, (pr, pm)) in part.iter().enumerate() {
                if (*pr, *pm) == (0, 0) {
                    continue;
                }
                let (p, after) = PegLedger::giver_opening_after_rebalance(o[i], (*pr, *pm)).expect("the eighth derives");
                assert!(PegLedger::parts_are_one_fraction(&[(p, after)]), "⛔ ledger {i}: the receiver refused the eighth the rule owes");
                assert!(*pr <= o[i].0 && *pm <= o[i].2, "a part is never more than the ledger holds");
                let (q, qa) = PegLedger::giver_opening_after_rebalance(o[i], (pr.saturating_mul(2), pm.saturating_mul(2))).expect("a quarter derives");
                assert!(!PegLedger::parts_are_one_fraction(&[(q, qa)]), "⛔ ledger {i}: the receiver kept a quarter as the eighth");
            }
        }
        assert_eq!(due(&open(1, 1, 0, 0), 0), None, "a part of nothing is no move");
    }

    /// ⛔⛔ SAFE AT SCALE, stage three — A VAULT TAKES THE KEY OF ITS MEMBERS AND RETIRES THE ONE IT REPLACED, ONLY ON ITS
    /// OWN QUORUM'S WORD AND ONLY FOR THE MEMBER SET THE CHAIN SEATS (`Class::VaultKey`; spec §3f R1, R2, R4). Twenty-four
    /// custodians, two vaults (16 + 8). The custodian's ledger A forms each statement; the peer's ledger B — its own
    /// validator set and ledger — judges and applies.
    /// CALIBRATION: before any key, no custodian is named (the release gate holds nobody); six of vault 1's eight take
    /// the key of exactly their set, and B takes it. REFUSED on B: FORGE — five of eight; vault 0's quorum signing vault
    /// 1's statement. SUBSTITUTE — a member list with a stranger added, or a member dropped (each signed over its own
    /// statement by the six); another Monero address under the honest signatures. REPLAY — the same take again.
    /// THE APPLY on both parties: the record names every member of vault 1 and nobody of vault 0.
    /// A MEMBER LEAVES: a take that still names it is refused; the seven take their key — the old one is REPLACED AND
    /// STILL ALIVE, so the leaver is still named. RETIRE, refused on B: inside the address window; the current key;
    /// under two thirds; a statement signed before the record moved. Taken after the window: the leaver is named by
    /// nothing. REPLAY of the retire: refused. THE ALIVE BOUND: a vault holding four keys takes no fifth until it
    /// retires one. THE RECORD TRAVELS AND REWINDS: a ledger adopting B's carried words holds B's record (a row whose
    /// members are out of order is dropped whole); an undo to the state before the first take puts every row back.
    #[test]
    fn safe_at_scale_a_vault_takes_and_retires_its_custody_key_only_by_its_own_quorum_and_for_the_chains_own_seats() {
        let (custodians, mut vs_a, mut a) = vault_fixture(24);
        let (mut vs, mut b) = vault_party(&custodians);
        assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 8]);
        let (v0, v1) = (vault_members(&custodians, &vs, 0), vault_members(&custodians, &vs, 1));
        let ids = |who: &[&Custodian]| -> Vec<[u8; 32]> {
            let mut v: Vec<[u8; 32]> = who.iter().map(|c| c.id()).collect();
            v.sort_unstable();
            v
        };
        let genesis = b.clone();
        let addr = b"4-the-address-vault-one-wallets-report".to_vec();
        // the Bitcoin leaf each party's NODE derives for the vault's seats (a ledger party is handed it, as it is the
        // carrying block's blue score): the same on A and B, and never read from the statement
        let leaf = VaultBtcKey { leaf: [0x1eu8; 32], members: vec![([0x21u8; 32], 5_000), ([0x22u8; 32], 5_000)] };
        let set1 = ids(&v1);
        assert!(custodians.iter().all(|c| !b.vault_key_names(&c.id())), "CALIBRATION: a chain that recorded no key names nobody — the release gate holds nobody");
        let take = a.vault_key_take_msg(1, &leaf,&set1, &addr);
        assert_eq!(take, b.vault_key_take_msg(1, &leaf,&set1, &addr), "each party derives the statement from its own record");
        let six = sign_all(&v1[..6], &take);
        let check = |peer: &PegLedger, vs: &ValidatorSet, members: &[[u8; 32]], address: &[u8], sigs: &[MintAttestor]| peer.check_vault_key_take(1, &leaf,members, address, vs, &MlDsaVerifier, sigs);
        assert!(matches!(check(&b, &vs, &set1, &addr, &six), PegOutcome::ConfidentialPublished), "CALIBRATION: six of the vault's eight take the key of their own set");
        // FORGE
        assert!(matches!(check(&b, &vs, &set1, &addr, &sign_all(&v1[..5], &take)), PegOutcome::InsufficientThreshold), "⛔ FORGE: five of eight took a key for the vault");
        assert!(matches!(check(&b, &vs, &set1, &addr, &sign_all(&v0[..11], &take)), PegOutcome::InsufficientThreshold), "⛔ FORGE: another vault's quorum named this vault's key");
        // SUBSTITUTE: the member list is the CHAIN's, never the statement's
        let mut stranger = set1.clone();
        stranger.push(v0[0].id());
        stranger.sort_unstable();
        assert!(matches!(check(&b, &vs, &stranger, &addr, &sign_all(&v1[..6], &b.vault_key_take_msg(1, &leaf,&stranger, &addr))), PegOutcome::BadRequest), "⛔ SUBSTITUTE: a key naming a custodian of another vault was taken");
        let dropped: Vec<[u8; 32]> = set1[1..].to_vec();
        assert!(matches!(check(&b, &vs, &dropped, &addr, &sign_all(&v1[..6], &b.vault_key_take_msg(1, &leaf,&dropped, &addr))), PegOutcome::BadRequest), "⛔ SUBSTITUTE: a key that leaves a seated member out was taken");
        assert!(matches!(check(&b, &vs, &set1, b"4-another-address", &six), PegOutcome::InsufficientThreshold), "⛔ SUBSTITUTE: the signatures carried an address they never named");
        // signers whose own nodes formed ANOTHER Bitcoin leaf signed another statement: it counts for nothing here
        let other_leaf = sign_all(&v1[..6], &b.vault_key_take_msg(1, &VaultBtcKey { leaf: [0x77u8; 32], ..leaf.clone() }, &set1, &addr));
        assert!(matches!(check(&b, &vs, &set1, &addr, &other_leaf), PegOutcome::InsufficientThreshold), "⛔ SUBSTITUTE: signatures over a Bitcoin leaf this node does not derive carried a key");
        // THE APPLY, on both parties from the same statement
        assert!(matches!(a.vault_key_take(1, &leaf,&set1, &addr, 100, &vs_a, &MlDsaVerifier, &six), PegOutcome::ConfidentialMinted), "A applies its own statement");
        assert!(matches!(b.vault_key_take(1, &leaf,&set1, &addr, 100, &vs, &MlDsaVerifier, &six), PegOutcome::ConfidentialMinted), "the peer takes the key");
        assert_eq!(b.vault_keys(1), a.vault_keys(1), "both parties hold the same record");
        assert_eq!(b.vault_key_current(1).map(|k| (k.members.clone(), k.xmr_address.clone(), k.since_tick)), Some((set1.clone(), addr.clone(), 100)));
        assert!(v1.iter().all(|c| b.vault_key_names(&c.id())) && v0.iter().all(|c| !b.vault_key_names(&c.id())), "the record names vault 1's members and nobody else");
        assert!(matches!(b.vault_key_take(1, &leaf,&set1, &addr, 101, &vs, &MlDsaVerifier, &six), PegOutcome::Replay), "⛔ REPLAY: the same take moved the record again");
        assert_eq!(b.vault_keys(1).len(), 1);

        // A MEMBER LEAVES vault 1 (a fixture exit on both parties): seven are seated
        let leaver = v1[7];
        assert!(vs_a.remove(&leaver.id()).is_some() && vs.remove(&leaver.id()).is_some());
        let v1: Vec<&Custodian> = v1[..7].to_vec();
        let set7 = ids(&v1);
        assert!(matches!(check(&b, &vs, &set1, &addr, &sign_all(&v1[..6], &b.vault_key_take_msg(1, &leaf,&set1, &addr))), PegOutcome::BadRequest), "⛔ a key that still names a custodian who left was taken");
        let addr7 = b"4-the-address-of-the-seven".to_vec();
        let take7 = sign_all(&v1[..5], &b.vault_key_take_msg(1, &leaf,&set7, &addr7));
        assert!(matches!(a.vault_key_take(1, &leaf,&set7, &addr7, 200, &vs_a, &MlDsaVerifier, &take7), PegOutcome::ConfidentialMinted));
        assert!(matches!(b.vault_key_take(1, &leaf,&set7, &addr7, 200, &vs, &MlDsaVerifier, &take7), PegOutcome::ConfidentialMinted), "five of seven take the key of the seven");
        assert_eq!(b.vault_keys(1).iter().map(|k| (k.since_tick, k.replaced_tick)).collect::<Vec<_>>(), vec![(100, Some(200)), (200, None)], "the old key is replaced and still alive (make before break)");
        assert!(b.vault_key_names(&leaver.id()), "⛔ the leaver is no longer named while the key it holds is alive: its collateral would return with its key live");
        // THE GATE'S RULE on a vault that stands behind nothing (no deposit ever moved vault 1's ledgers here): the leaver
        // is held while the key that names it can still be paid — its address window — and by nothing after; a seated
        // member named by the current key is held whenever asked (a deposit could be minted to its key the same block)
        assert!(!b.vault_ledgers_moved(1), "PRECONDITION: vault 1 stands on its genesis ledgers");
        assert!(b.vault_key_holds(&leaver.id(), 249, 50, &vs), "the leaver is held inside the replaced key's address window");
        assert!(!b.vault_key_holds(&leaver.id(), 250, 50, &vs), "⛔ a custodian named only by a key that can no longer be paid, of a vault that stands behind nothing, is still held");
        assert!(b.vault_key_holds(&v1[0].id(), 10_000, 50, &vs), "a member named by the vault's current key is held");
        assert!(!b.vault_key_holds(&v0[0].id(), 0, 50, &vs), "a custodian no key names is never held");

        // RETIRE
        let window = 50u64;
        let retire = |peer: &PegLedger, vs: &ValidatorSet, since: u64, blue: u64, sigs: &[MintAttestor]| peer.check_vault_key_retire(1, since, blue, window, vs, &MlDsaVerifier, sigs);
        let rmsg = b.vault_key_retire_msg(1, 100);
        assert_eq!(rmsg, a.vault_key_retire_msg(1, 100));
        let five = sign_all(&v1[..5], &rmsg);
        assert!(matches!(retire(&b, &vs, 100, 249, &five), PegOutcome::BadRequest), "⛔ a replaced key was retired inside its address window: a handed-out address could still be paid");
        assert!(matches!(retire(&b, &vs, 200, 10_000, &sign_all(&v1[..5], &b.vault_key_retire_msg(1, 200))), PegOutcome::BadRequest), "⛔ the vault's current key was retired: it would have no deposit address");
        assert!(matches!(retire(&b, &vs, 100, 250, &sign_all(&v1[..4], &rmsg)), PegOutcome::InsufficientThreshold), "⛔ four of seven retired a key");
        assert!(matches!(retire(&b, &vs, 100, 250, &sign_all(&v0[..11], &rmsg)), PegOutcome::InsufficientThreshold), "⛔ another vault's quorum retired this vault's key");
        // a statement signed BEFORE the record moved (against the one-key record, by the eight's quorum) names another pre-state
        let stale = sign_all(&v1[..5], &genesis.vault_key_retire_msg(1, 100));
        assert!(matches!(retire(&b, &vs, 100, 250, &stale), PegOutcome::InsufficientThreshold), "⛔ a signature over another state of the record retired a key");
        assert!(matches!(retire(&b, &vs, 100, 250, &five), PegOutcome::ConfidentialPublished), "after the window, five of seven retire the replaced key");
        assert!(matches!(a.vault_key_retire(1, 100, 250, window, &vs_a, &MlDsaVerifier, &five), PegOutcome::ConfidentialRedeemed));
        assert!(matches!(b.vault_key_retire(1, 100, 250, window, &vs, &MlDsaVerifier, &five), PegOutcome::ConfidentialRedeemed), "the peer retires it");
        assert!(!b.vault_key_names(&leaver.id()) && v1.iter().all(|c| b.vault_key_names(&c.id())), "the leaver is named by nothing; the seven still are");
        assert_eq!(b.vault_keys(1), a.vault_keys(1));
        assert!(matches!(b.vault_key_retire(1, 100, 251, window, &vs, &MlDsaVerifier, &five), PegOutcome::Replay), "⛔ REPLAY: the retired key was retired again");

        // THE RECORD TRAVELS: a ledger adopting B's carried words holds B's record; a mis-shaped row is dropped whole
        let mut words = b.br_census();
        let (mut joiner, mut fooled) = (PegLedger::genesis(15_000), PegLedger::genesis(15_000));
        joiner.adopt_certified_br(&words);
        assert_eq!(joiner.vault_keys(1), b.vault_keys(1), "⛔ a node that adopts the carried words does not hold the key record");
        assert_eq!(joiner.vault_keys_digest(1), b.vault_keys_digest(1));
        words.vault_keys[0].1[0].members.reverse();
        assert_ne!(words.digest(), b.br_census().digest(), "the certified digest binds every row");
        fooled.adopt_certified_br(&words);
        assert!(fooled.vault_keys(1).is_empty(), "⛔ a carried row with its members out of order was installed");

        // THE ALIVE BOUND: three more members leave one by one, each followed by a take and no retire — four keys alive
        let mut seated = v1.clone();
        for (n, blue) in [(6usize, 300u64), (5, 400), (4, 500)] {
            let gone = seated.pop().expect("a member");
            assert!(vs.remove(&gone.id()).is_some());
            let set = ids(&seated);
            let quorum = 2 * n / 3 + 1; // more than two thirds of equal bonds
            let sigs = sign_all(&seated[..quorum], &b.vault_key_take_msg(1, &leaf,&set, b"4-next"));
            assert!(matches!(b.vault_key_take(1, &leaf,&set, b"4-next", blue, &vs, &MlDsaVerifier, &sigs), PegOutcome::ConfidentialMinted), "{n} seated members take their key");
        }
        assert_eq!(b.vault_keys(1).len(), VAULT_KEYS_ALIVE_MAX);
        let gone = seated.pop().expect("a member");
        assert!(vs.remove(&gone.id()).is_some());
        let set = ids(&seated);
        let sigs = sign_all(&seated[..2], &b.vault_key_take_msg(1, &leaf,&set, b"4-fifth"));
        assert!(matches!(b.vault_key_take(1, &leaf,&set, b"4-fifth", 600, &vs, &MlDsaVerifier, &sigs), PegOutcome::BadRequest), "⛔ a fifth alive key was taken: the record would grow with every re-key");
        assert!(vault_key_rows_shaped(b.vault_keys(1)), "the record keeps its one shape");

        // THE RECORD REWINDS with the object fold: an undo to the state before the first take puts every row back
        let undo = b.undo_to(&genesis);
        assert!(b.apply_undo(&undo), "the undo names only fields this build knows");
        assert!(b.vault_keys(1).is_empty() && custodians.iter().all(|c| !b.vault_key_names(&c.id())), "⛔ a rewound ledger still holds keys the rewound blocks recorded");
    }

    /// ⭐⭐ SAFE AT SCALE, stage three (spec §3f R6) — THE BONDERS' SHARE PAYS THEIR CUSTODY'S DEBT FIRST, AND NOTHING ELSE
    /// PAYS IT. Two ledgers take the same fees, fold step by fold step: one owes a re-key's fee, the twin owes nothing.
    ///   • the debt is the fee at the chain's own price (500 atoms at 2.0 = 1,000);
    ///   • at every credit the stakers', the buffer's and the miners' pools are EQUAL on both ledgers — a re-key never
    ///     takes from a pool that is not the bonders' own;
    ///   • the bonders' pool and accrual lag the twin's by exactly what was retired, the debt falls by the same, and
    ///     credits plus retired equal the fees paid in: nothing is lost and nothing is invented;
    ///   • once the debt is paid the bonders' share credits their pool in full again.
    /// TWO-PARTY-REVIEWED: ledger arithmetic of one fold step — a pure function of public words every node holds
    /// alike; the cross-node half (the debt raised on a peer by a block's `Class::ReserveCost`) is
    /// `node::vault_pins::safe_at_scale_a_fee_that_left_custody_is_booked_by_the_vaults_own_custodians_and_becomes_the_bonders_debt_on_the_peer`.
    #[test]
    fn safe_at_scale_the_bonders_share_pays_their_custodys_debt_first_and_no_other_pool_pays() {
        let mut owing = PegLedger::new(15_000);
        let mut twin = PegLedger::new(15_000);
        for l in [&mut owing, &mut twin] {
            l.set_price_mark_for_test(NATIVE_PEG_ASSET_ID, 2 * crate::liquidation::PRICE_SCALE, 1);
        }
        assert_eq!(owing.raise_custody_cost_debt(NATIVE_PEG_ASSET_ID, 500), 1_000, "the fee at the chain's own price");
        assert_eq!(owing.custody_cost_debt(), (1_000, 0));
        let (mut paid_in, mut cleared_at) = (0u64, None);
        for (step, fee) in [1_000u64, 1_000, 1_000, 1_000, 1_003, 7, 1_000].into_iter().enumerate() {
            assert!(owing.credit_fee_pools_capped(fee, 0, u64::MAX) && twin.credit_fee_pools_capped(fee, 0, u64::MAX));
            paid_in += fee;
            let (o, t) = (owing.fee_pools(), twin.fee_pools());
            assert_eq!((o.stakers, o.surplus, o.miner), (t.stakers, t.surplus, t.miner), "⛔ step {step}: a pool that is not the bonders' paid for the re-key");
            let (debt, retired) = owing.custody_cost_debt();
            assert_eq!(debt + retired, 1_000, "what was owed is what is still owed plus what was retired");
            assert_eq!(o.bonders + retired, t.bonders, "⛔ step {step}: the bonders' pool is not the twin's less exactly what their share retired");
            assert_eq!(o.stakers + o.bonders + o.surplus + o.miner + retired, paid_in, "⛔ step {step}: the credits and the retired do not sum to the fees paid in");
            if debt == 0 && cleared_at.is_none() {
                cleared_at = Some(step);
            }
        }
        // a quarter of each fee is the bonders' share: 250 a step clears 1,000 at the fourth
        assert_eq!(cleared_at, Some(3), "the debt clears when the bonders' own share has covered it");
        assert_eq!(owing.custody_cost_debt(), (0, 1_000));
        assert_eq!(twin.custody_cost_debt(), (0, 0), "a ledger that owed nothing retired nothing");
        // the journal carries both words: a rewind to before the cost restores them
        let mut before = PegLedger::new(15_000);
        before.set_price_mark_for_test(NATIVE_PEG_ASSET_ID, 2 * crate::liquidation::PRICE_SCALE, 1);
        let mut raised = before.clone();
        let _ = raised.raise_custody_cost_debt(NATIVE_PEG_ASSET_ID, 500);
        assert!(raised.credit_fee_pools_capped(400, 0, u64::MAX));
        assert_eq!(raised.custody_cost_debt(), (900, 100));
        let undo = raised.undo_to(&before);
        assert!(raised.apply_undo(&undo), "⛔ the journal refused the cost words (a rewind below a re-key would mark the spine stale)");
        assert_eq!(raised.custody_cost_debt(), (0, 0), "⛔ a rewind did not restore the cost words");
        let (r, b) = (raised.fee_pools(), before.fee_pools());
        assert_eq!((r.stakers, r.bonders, r.surplus, r.miner), (b.stakers, b.bonders, b.surplus, b.miner));
    }

    /// ⛔⛔ A-F31 — THE TOKEN REGISTRY IS UNDONE WITH ITS STEP. A step that registers a creation carries the registry's
    /// before-image in its undo; applying the undo restores it exactly, and the undo survives its persisted encoding (a
    /// checkpoint's journal). CALIBRATION: a step that registers nothing carries no registry image.
    /// TAMPER: an image whose peaks do not describe its count is refused with nothing changed.
    #[test]
    fn af31_the_token_registry_is_undone_with_its_step_and_a_bad_image_is_refused() {
        let token = |symbol: &str| crate::dsol::DsolContract {
            id: crate::hash::Hash32::hash(symbol.as_bytes()),
            version: 2,
            kind: crate::dsol::DsolKind::Token,
            symbol: symbol.to_string(),
            name: "af31".to_string(),
            verified: false,
            logo: crate::hash::Hash32([0u8; 32]),
        };
        let mut before = PegLedger::new(15_000);
        before.dsol_tokens_mut().register(&token("ONE"));
        let mut after = before.clone();
        assert!(after.undo_to(&before).is_empty(), "CALIBRATION: a step that registers nothing carries no registry image");
        after.dsol_tokens_mut().register(&token("TWO"));
        after.dsol_tokens_mut().register(&token("THREE"));
        assert_ne!(after.dsol_tokens().root_bytes(), before.dsol_tokens().root_bytes(), "CALIBRATION: the step moved the registry");
        let undo = after.undo_to(&before);
        assert!(!undo.is_empty(), "⛔ A-F31: a step that registered creations carries no registry image — a rewind keeps them");
        // the checkpoint's encoding of the journal entry
        let carried: PegUndo = postcard::from_bytes(&postcard::to_allocvec(&undo).expect("encodes")).expect("decodes");
        let mut rewound = after.clone();
        assert!(rewound.apply_undo(&carried), "the undo names only what this build knows");
        assert_eq!(rewound.dsol_tokens().parts(), before.dsol_tokens().parts(), "⛔ A-F31: the rewind did not restore the registry");
        // TAMPER: one peak dropped, the count kept
        let mut bad = undo.clone();
        if let Some((_, peaks)) = bad.dsol_tokens.as_mut() {
            peaks.clear();
        }
        let mut untouched = after.clone();
        assert!(!untouched.apply_undo(&bad), "⛔ A-F31: a registry image that does not describe its count was applied");
        assert_eq!(untouched.dsol_tokens().parts(), after.dsol_tokens().parts(), "⛔ a refused undo changed the registry");
    }

    /// ⛔⛔ SAFE AT SCALE — A VAULT'S RESERVE FALLS BY A FOREIGN FEE ONLY BY PROOF AND ITS OWN QUORUM (`Class::ReserveCost`).
    /// Twenty-four custodians, two vaults (16 + 8); vault 1 holds a reserve of 30,000,000. The custodian's ledger A
    /// proves; the peer's ledger B — its own validator set and ledger — judges and applies.
    /// CALIBRATION: a fee of 300 (under the floor: no bound proof) signed by six of vault 1's eight is taken.
    /// REFUSED on B: FORGE — under two thirds of the vault, or another vault's quorum; SUBSTITUTE — a fee the signatures
    /// never named, and (LYING PROVER, signed over its own statement) a stated fee smaller than what the reserve fell by,
    /// or a reserve after that hides five more; STRIP — a fee past the floor with its bound proof removed; a bound proven
    /// for a smaller fee; a fee more than a hundredth of the reserve it leaves (it does not prove at all); the proof
    /// pointed at another vault's ledger; a coin or wrapped ledger. THE APPLY on both parties: B holds the reserve on
    /// the stated commitment and the minted side where it was; the advanced opening opens it and proves the vault's
    /// next deposit. REPLAY: the same object again moves nothing. And on a chain of one vault the whole set signs it.
    #[test]
    fn safe_at_scale_a_vaults_reserve_falls_by_a_foreign_fee_only_by_proof_and_its_own_quorum() {
        use usdm_decider::confidential_solvency as cs;
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let (custodians, vs_a, mut a) = vault_fixture(24);
        let (vs, mut b) = vault_party(&custodians);
        assert_eq!(vs.custody_vaults().iter().map(Vec::len).collect::<Vec<_>>(), vec![16, 8]);
        let (v0, v1) = (vault_members(&custodians, &vs, 0), vault_members(&custodians, &vs, 1));
        let ledger = vault_ledger(1, NATIVE_PEG_ASSET_ID);
        // vault 1 takes a deposit, applied on both parties from the same bytes
        let d = l(&[0x5a, 1, 1, 1]);
        let (blob, hr, hm, after1) = a.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(1), 30_000_000, 20_000_000, &d, &d, None).expect("the deposit proves");
        for p in [&mut a, &mut b] {
            let posts = p.verify_cover_at(1, true, &blob, (hr, hm), PegLedger::mint_delta_commit(20_000_000, d), None).expect("each party verifies the cover");
            p.apply_cover_at(1, &posts);
        }
        let open = after1[0];
        let pair = |p: &PegLedger, id: u32| p.psm_commits(id).map(|c| (c.0, c.1)).expect("a pair");
        let before = pair(&b, ledger);
        let floor = PegLedger::reserve_cost_floor(ledger).expect("a Bitcoin bridge ledger has a floor");
        let txid = [0x71u8; 32];
        let check = |peer: &PegLedger, ledger: u32, cost: u64, post: crate::spend_frontier::Digest4, sum: &[u8], bound: &[u8], att: &[MintAttestor]| {
            peer.check_reserve_cost(ledger, cost, &txid, post, sum, bound, &vs, &MlDsaVerifier, att)
        };

        // UNDER THE FLOOR
        let (post, sum, bound, after) = a.prove_reserve_cost(ledger, open, 300, &txid).expect("a custodian that opens the ledger proves the cost");
        assert!(bound.is_empty(), "a fee under the floor carries no bound proof");
        assert_eq!((after.0, after.2), (open.0 - 300, open.2), "the reserve less the fee; the minted side untouched");
        let msg = a.reserve_cost_msg(ledger, 300, &txid, &post);
        assert_eq!(msg, b.reserve_cost_msg(ledger, 300, &txid, &post), "each party derives the one statement from its own chain's pair");
        let own6 = sign_all(&v1[..6], &msg);
        assert!(matches!(check(&b, ledger, 300, post, &sum, &bound, &own6), PegOutcome::ConfidentialPublished), "CALIBRATION: two thirds of the vault book its own sweep's fee");
        assert!(matches!(check(&b, ledger, 300, post, &sum, &bound, &sign_all(&v1[..5], &msg)), PegOutcome::InsufficientThreshold), "⛔ FORGE: under two thirds of the vault lowered its reserve");
        assert!(matches!(check(&b, ledger, 300, post, &sum, &bound, &sign_all(&v0[..11], &msg)), PegOutcome::InsufficientThreshold), "⛔ FORGE: another vault's quorum lowered vault 1's reserve");
        assert!(matches!(check(&b, ledger, 299, post, &sum, &bound, &own6), PegOutcome::InsufficientThreshold), "⛔ SUBSTITUTE: the signatures carried a fee they never named");
        // LYING PROVER, each signed over its own statement by the vault's real quorum:
        // (1) the stated fee is smaller than what the reserve fell by
        let lie1 = sign_all(&v1[..6], &b.reserve_cost_msg(ledger, 299, &txid, &post));
        assert!(matches!(check(&b, ledger, 299, post, &sum, &bound, &lie1), PegOutcome::BadRequest), "⛔ LYING PROVER: a reserve that fell by 300 was booked as a fee of 299");
        // (2) the reserve after hides five more than the fee
        let u = |v: u128| super::u256_from_u128(v);
        let (sum_lie, c_lie) = cs::prove_transition_carrier(u(open.0 - 305), u(305), &[after.1, PegLedger::RESERVE_COST_BLIND, open.1], cs::TransitionDomain::ReserveCost).expect("the prover's own sum proves");
        let lie2 = sign_all(&v1[..6], &b.reserve_cost_msg(ledger, 300, &txid, &c_lie[0]));
        assert!(matches!(check(&b, ledger, 300, c_lie[0], &sum_lie, &bound, &lie2), PegOutcome::BadRequest), "⛔ LYING PROVER: a reserve after that hides five more than the fee was taken");
        // the proof pointed at another vault's ledger, under that vault's quorum
        let on0 = sign_all(&v0[..11], &b.reserve_cost_msg(NATIVE_PEG_ASSET_ID, 300, &txid, &post));
        assert!(matches!(check(&b, NATIVE_PEG_ASSET_ID, 300, post, &sum, &bound, &on0), PegOutcome::BadRequest), "⛔ vault 1's proof lowered vault 0's reserve");
        for not_a_bridge_ledger in [COIN_BTC_ASSET_ID, vault_ledger(1, COIN_BTC_ASSET_ID), 7] {
            assert!(matches!(check(&b, not_a_bridge_ledger, 300, post, &sum, &bound, &own6), PegOutcome::BadRequest), "⛔ ledger {not_a_bridge_ledger:#x} booked a custody cost");
        }

        // PAST THE FLOOR: the bound rides, and is checked
        let big = floor + 50_000;
        let (post_b, sum_b, bound_b, _) = a.prove_reserve_cost(ledger, open, big, &txid).expect("a fee past the floor proves with its bound: the reserve left is far more than a hundred times it");
        assert!(!bound_b.is_empty());
        let own6b = sign_all(&v1[..6], &b.reserve_cost_msg(ledger, big, &txid, &post_b));
        assert!(matches!(check(&b, ledger, big, post_b, &sum_b, &bound_b, &own6b), PegOutcome::ConfidentialPublished), "CALIBRATION: a fee past the floor is taken with its bound");
        assert!(matches!(check(&b, ledger, big, post_b, &sum_b, &[], &own6b), PegOutcome::BadRequest), "⛔ STRIP: a fee past the floor was taken with its bound proof removed");
        assert!(matches!(check(&b, ledger, 300, post, &sum, &bound_b, &own6), PegOutcome::BadRequest), "⛔ a bound proof rode a fee under the floor (two encodings of one cost)");
        let huge = 400_000u64; // the reserve it would leave (29,600,000) is under a hundred times it
        assert!(a.prove_reserve_cost(ledger, open, huge, &txid).is_none(), "⛔ a fee more than a hundredth of the reserve it leaves proved");
        let after_huge = PegLedger::opening_after_reserve_cost(open, huge, &txid).expect("the arithmetic itself fits");
        let (sum_h, c_h) = cs::prove_transition_carrier(u(after_huge.0), u(u128::from(huge)), &[after_huge.1, PegLedger::RESERVE_COST_BLIND, open.1], cs::TransitionDomain::ReserveCost).expect("the honest sum proves");
        let own6h = sign_all(&v1[..6], &b.reserve_cost_msg(ledger, huge, &txid, &c_h[0]));
        assert!(matches!(check(&b, ledger, huge, c_h[0], &sum_h, &bound_b, &own6h), PegOutcome::BadRequest), "⛔ LYING PROVER: a bound proven for a smaller fee carried a larger one");

        // THE APPLY, on both parties from the same bytes
        assert!(matches!(a.reserve_cost(ledger, 300, &txid, post, &sum, &bound, &vs_a, &MlDsaVerifier, &own6), PegOutcome::ConfidentialRedeemed), "A applies its own object");
        assert!(matches!(b.reserve_cost(ledger, 300, &txid, post, &sum, &bound, &vs, &MlDsaVerifier, &own6), PegOutcome::ConfidentialRedeemed), "the peer books the cost");
        assert_eq!(pair(&b, ledger), (post, before.1), "the peer holds the reserve on the stated commitment and the minted side where it was");
        assert_eq!(pair(&b, ledger), pair(&a, ledger), "both parties hold the same pair");
        assert_eq!(PegLedger::commits_of_opening(after.0, after.1, after.2, after.3), pair(&b, ledger), "the advanced opening (the reserve less 300) opens the peer's pair");
        assert_eq!(pair(&b, NATIVE_PEG_ASSET_ID), pair(&PegLedger::genesis(15_000), NATIVE_PEG_ASSET_ID), "⛔ vault 1's cost moved vault 0 on the peer");
        let d2 = l(&[0x5b, 1, 1, 1]);
        assert!(b.orchestrate_cover_at(1, true, NATIVE_PEG_ASSET_ID, &[after, after1[1]], 1_500, 1_000, &d2, &d2, None).is_some(), "the vault's next deposit proves from the advanced opening against the peer's state");
        // REPLAY: the statement names the pair the apply moved
        assert!(!matches!(b.reserve_cost(ledger, 300, &txid, post, &sum, &bound, &vs, &MlDsaVerifier, &own6), PegOutcome::ConfidentialRedeemed), "⛔ REPLAY: one foreign fee was booked twice");
        assert_eq!(pair(&b, ledger), (post, before.1), "the replay moved nothing on the peer");

        // ON A CHAIN OF ONE VAULT the whole set signs it, as it signs a burn
        let (c3, vs3_a, mut a3) = vault_fixture(3);
        let (vs3, mut b3) = vault_party(&c3);
        let d3 = l(&[0x5c, 1, 1, 1]);
        let (blob3, hr3, hm3, after3) = a3.orchestrate_cover_at(0, true, NATIVE_PEG_ASSET_ID, &vault_genesis_openings(0), 1_500, 1_000, &d3, &d3, None).expect("the deposit proves");
        for p in [&mut a3, &mut b3] {
            let posts = p.verify_cover_at(0, true, &blob3, (hr3, hm3), PegLedger::mint_delta_commit(1_000, d3), None).expect("verifies");
            p.apply_cover_at(0, &posts);
        }
        let (post3, sum3, bound3, _) = a3.prove_reserve_cost(NATIVE_PEG_ASSET_ID, after3[0], 200, &txid).expect("proves");
        let all3: Vec<&Custodian> = c3.iter().collect();
        let msg3 = b3.reserve_cost_msg(NATIVE_PEG_ASSET_ID, 200, &txid, &post3);
        assert!(matches!(b3.check_reserve_cost(NATIVE_PEG_ASSET_ID, 200, &txid, post3, &sum3, &bound3, &vs3, &MlDsaVerifier, &sign_all(&all3[..1], &msg3)), PegOutcome::InsufficientThreshold), "⛔ one of three lowered the reserve");
        assert!(matches!(b3.reserve_cost(NATIVE_PEG_ASSET_ID, 200, &txid, post3, &sum3, &bound3, &vs3, &MlDsaVerifier, &sign_all(&all3[..2], &msg3)), PegOutcome::ConfidentialRedeemed), "two of three (two thirds of the whole set) book it on a one-vault chain");
        let _ = vs3_a;
    }

    /// ⛔⛔ PRIVACY (2026-10-02) — A PEG-IN'S MINT CANNOT BE REOPENED FROM PUBLIC DATA. CALIBRATION: under the old schedule
    /// `H(prev, deposit, mint)` from the PUBLIC genesis blind, a brute force over the mint (the depositor's note value)
    /// reopens the supply commitment. REFUTATION: with the sealed delta blind mixed in, the same brute force finds nothing.
    #[test]
    fn a_peg_in_supply_cannot_be_reopened_from_public_data() {
        use usdm_decider::confidential_solvency::solvency_commit_256;
        let old_blind = |mint: u128| {
            let mut h = blake3::Hasher::new();
            h.update(b"USDMD-PEGIN-MNT-BLIND");
            for x in GENESIS_PEG_MINTED_BLIND {
                h.update(&x.to_le_bytes());
            }
            h.update(&(mint * 3 / 2).to_le_bytes());
            h.update(&mint.to_le_bytes());
            usdm_decider::poseidon2_compress::hash32_to_digest(h.finalize().as_bytes())
        };
        let observer = |c: crate::spend_frontier::Digest4| (1u128..=10_000).find(|m| solvency_commit_256(u256_from_u128(*m), old_blind(*m)) == c);
        assert_eq!(
            observer(solvency_commit_256(u256_from_u128(2_000), old_blind(2_000))),
            Some(2_000),
            "CALIBRATION: the old schedule leaks the mint to a brute force over public data"
        );
        let sealed = usdm_decider::poseidon2_compress::lanes_of(&[0x51, 0x52, 0x53, 0x54]);
        let (_, _, mv, mb) =
            PegLedger::opening_after_peg_in(0, GENESIS_PEG_RESERVE_BLIND, 0, GENESIS_PEG_MINTED_BLIND, 3_000, 2_000, &sealed);
        assert_eq!(observer(solvency_commit_256(u256_from_u128(mv), mb)), None, "⛔⛔ the supply reopened from public data");
    }

    /// ⛔⛔⛔ THE MONERO UNIT CLASS (lane defi, 2026-11-01) — THE BITCOIN LEDGER NEVER PRICES A MONERO AMOUNT. Production
    /// marks the native ledger with BITCOIN's price (the relays quote asset 0 as BTC: USD × 1e6 per satoshi). Under that
    /// mark, MEASURED here: a 1 XMR deposit's 1e12 piconero read as satoshis prices at $600,000,000, and a 100 USDm burn to
    /// a Monero destination released 1e10 units (0.01 XMR ≈ $1.50) — the native door counted one unit of a foreign chain as
    /// one of its own. The fix is at the one shared release site: the native ledger releases NOTHING to a Monero address or
    /// ticket kind (every reader refuses before a burn), while a Bitcoin destination is still priced and laddered; a Monero
    /// deposit's attestation is refused at the custodian (`Node`'s native-ledger rule) and its address is not issued.
    #[test]
    fn the_bitcoin_ledger_never_prices_a_monero_amount() {
        super::unprice_fixtures_for_test(); // the unpriced door is what this measures
        let (custodians, vs) = quorum();
        let mut peg = PegLedger::new(15_000);
        let asset = NATIVE_PEG_ASSET_ID;
        let btc_mark: u128 = 60_000 * crate::liquidation::PRICE_SCALE; // $60,000 per BTC: USDm-atomic per sat × 1e6
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, asset, btc_mark));
                crate::price_mark_tx::PriceQuote { price: btc_mark, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        assert_eq!(peg.mark_price_attested(1, asset, &quotes, &vs, &MlDsaVerifier), PegOutcome::PriceMarked(btc_mark));
        // the measured hole: piconero read as satoshis
        let one_xmr: u128 = 1_000_000_000_000;
        assert_eq!(peg.priced_value(asset, one_xmr), Some(60_000_000_000_000_000), "1 XMR read as 1e12 sats prices at $600,000,000");
        let usdm_100: u128 = 10_000_000_000;
        // a real mainnet standard address: network byte 18, spend and view keys, Keccak checksum (Monero's own encoding)
        let xmr_addr = {
            use sha3::Digest as _;
            let mut payload = vec![18u8];
            payload.extend_from_slice(&[7u8; 32]);
            payload.extend_from_slice(&[9u8; 32]);
            let sum = sha3::Keccak256::digest(&payload);
            payload.extend_from_slice(&sum[..4]);
            crate::bridge::cn_base58_encode(&payload)
        };
        assert!(crate::bridge::is_monero_address(&xmr_addr), "CALIBRATION: the destination is a Monero address");
        for to in [xmr_addr.as_str(), crate::cashout_ticket::KIND_XMR] {
            assert_eq!(peg.peg_out_release(usdm_100, to), None, "⛔ a Monero cash-out was priced with no XMR mark (to {to})");
        }
        // a Bitcoin destination is untouched: $100 at $60,000 is a priced release (the ladder decides whether it is a piece)
        assert_eq!(peg.release_sats_for_burn(asset, usdm_100), Some(166_666));
        assert_eq!(peg.peg_out_release(0, crate::cashout_ticket::KIND_XMR), Some(0), "a zero burn still releases nothing");
        // ⭐ the XMR mark prices a Monero cash-out in PICONERO from Monero's own ledger: $100 at $150/XMR = 0.6667 XMR
        let xmr_mark: u128 = 15_000; // USDm-atomic per piconero × 1e6 at $150
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, XMR_PEG_ASSET_ID, xmr_mark));
                crate::price_mark_tx::PriceQuote { price: xmr_mark, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        assert_eq!(peg.mark_price_attested(1, XMR_PEG_ASSET_ID, &quotes, &vs, &MlDsaVerifier), PegOutcome::PriceMarked(xmr_mark));
        for to in [xmr_addr.as_str(), crate::cashout_ticket::KIND_XMR] {
            assert_eq!(peg.peg_out_release(usdm_100, to), Some(666_666_666_666), "$100 to {to} releases 0.6667 XMR in piconero");
        }
        assert_eq!(PegLedger::peg_out_asset_for(&xmr_addr), XMR_PEG_ASSET_ID);
        assert_eq!(PegLedger::peg_out_asset_for("tb1qexampleexampleexampleexampleexample0"), NATIVE_PEG_ASSET_ID);
        // ⛔ the deposit unit class: a Monero deposit belongs on Monero's ledger only, a Bitcoin one on the native only
        assert!(PegLedger::deposit_unit_matches(XMR_PEG_ASSET_ID, &xmr_addr));
        assert!(!PegLedger::deposit_unit_matches(NATIVE_PEG_ASSET_ID, &xmr_addr), "⛔ a Monero deposit on the satoshi ledger");
        assert!(!PegLedger::deposit_unit_matches(XMR_PEG_ASSET_ID, "tb1qexampleexampleexampleexampleexample0"), "⛔ a Bitcoin deposit on Monero's ledger");
    }

    /// ⭐⭐⭐ MONERO'S OWN LEDGER, END TO END ON THE LEDGER (lane defi, 2026-11-01): born at genesis under its own blinds; a
    /// 1 XMR deposit mints $100 of USDm at the XMR mark (150 % backing in piconero); a cash-out redeems piconero from Monero's
    /// ledger. ⭐ §19.5b: each moves BOTH bridge ledgers through the cover — neither pair stands still, so the chain never says
    /// which coin moved; the peer verifies and applies the same cover. TAMPERS THAT REJECT: an over-issuing mint; a cover
    /// against another mint or another header pair; a wrapped-note mint on Monero's ledger; a release worth twice its burn;
    /// Monero's release drawn on the native ledger; a cover retiring another burn.
    #[test]
    fn the_monero_ledger_mints_and_redeems_piconero_at_the_xmr_mark() {
        use usdm_decider::confidential_solvency as cs;
        let (custodians, vs) = quorum();
        let mut peg = PegLedger::genesis(15_000);
        // the PEER: a separately constructed ledger that applies the same bytes — what one ledger accepts, the other must
        let mut peer_node = PegLedger::genesis(15_000);
        // born at genesis, on its own pair — never the native ledger's
        let (n_r, n_m, _) = peg.psm_commits(NATIVE_PEG_ASSET_ID).expect("native ledger");
        let (x_r, x_m, _) = peg.psm_commits(XMR_PEG_ASSET_ID).expect("⛔ Monero's ledger is not born at genesis");
        assert_ne!((n_r, n_m), (x_r, x_m), "⛔ two ledgers share one genesis pair — a proof against one opens the other");
        let (rb, mb) = psm_genesis_blinds(XMR_PEG_ASSET_ID);
        assert_eq!(PegLedger::commits_of_opening(0, rb, 0, mb), (x_r, x_m), "the genesis opening opens Monero's genesis pair");
        assert_eq!(psm_genesis_blinds(NATIVE_PEG_ASSET_ID), (GENESIS_PEG_RESERVE_BLIND, GENESIS_PEG_MINTED_BLIND), "the native pair is unchanged");
        for (asset, price) in [(NATIVE_PEG_ASSET_ID, 60_000 * crate::liquidation::PRICE_SCALE), (XMR_PEG_ASSET_ID, 15_000u128)] {
            let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
                .iter()
                .map(|c| {
                    let a = c.attest(&PegLedger::price_mark_msg(1, asset, price));
                    crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
                })
                .collect();
            assert_eq!(peg.mark_price_attested(1, asset, &quotes, &vs, &MlDsaVerifier), PegOutcome::PriceMarked(price));
            assert_eq!(peer_node.mark_price_attested(1, asset, &quotes, &vs, &MlDsaVerifier), PegOutcome::PriceMarked(price));
        }
        let one_xmr: u128 = 1_000_000_000_000; // $150 at the mark
        let usdm_100: u128 = 10_000_000_000; // $100 — exactly 150 % backed
        let d_blind = usdm_decider::poseidon2_compress::lanes_of_const(&[0x11, 0x22, 0x33, 0x44]);
        // ⭐ §19.5b: every peg moves BOTH bridge ledgers (the cover) — the custodian proves from its openings of both
        let openings = [(0u128, GENESIS_PEG_RESERVE_BLIND, 0u128, GENESIS_PEG_MINTED_BLIND), (0u128, rb, 0u128, mb)];
        // TAMPER: $101 against $150 is under 150 % — no proof
        assert!(peg.orchestrate_cover(true, XMR_PEG_ASSET_ID, &openings, one_xmr, usdm_100 + 100_000_000, &d_blind, &d_blind, None).is_none(), "⛔ an over-issuing Monero mint proved");
        let (blob, new_rc, new_mc, after) = peg
            .orchestrate_cover(true, XMR_PEG_ASSET_ID, &openings, one_xmr, usdm_100, &d_blind, &d_blind, None)
            .expect("1 XMR mints $100 at 150 %");
        let delta = PegLedger::mint_delta_commit(usdm_100, d_blind);
        let posts = peg.verify_cover(true, &blob, (new_rc, new_mc), delta, None).expect("the PegIn door verifies the cover");
        assert_eq!(peer_node.verify_cover(true, &blob, (new_rc, new_mc), delta, None), Some(posts), "the peer verifies the same cover");
        // TAMPER: another delta, another header pair — refused
        assert!(peg.verify_cover(true, &blob, (new_rc, new_mc), PegLedger::mint_delta_commit(usdm_100 + 1, d_blind), None).is_none(), "⛔ a cover verified against another mint");
        assert!(peg.verify_cover(true, &blob, (new_mc, new_rc), delta, None).is_none(), "⛔ a cover verified under another header pair");
        // TAMPER: a wrapped note never mints on a bridge ledger
        assert!(peg.orchestrate_wrapped_mint(XMR_PEG_ASSET_ID, 0, rb, 0, mb, one_xmr, usdm_100, d_blind).is_none(), "⛔ a wrapped note minted on Monero's ledger");
        peg.apply_cover(&posts);
        peer_node.apply_cover(&posts);
        assert_ne!(peg.psm_commits(NATIVE_PEG_ASSET_ID).map(|c| (c.0, c.1)), Some((n_r, n_m)), "⛔ §19.5b: a Monero mint left the native pair standing (it names its ledger)");
        assert_ne!(peg.psm_commits(XMR_PEG_ASSET_ID).map(|c| (c.0, c.1)), Some((x_r, x_m)), "the Monero pair moved");
        assert_eq!(peer_node.psm_commits(XMR_PEG_ASSET_ID), peg.psm_commits(XMR_PEG_ASSET_ID), "the two ledgers hold one Monero ledger");
        assert_eq!(peer_node.psm_commits(NATIVE_PEG_ASSET_ID), peg.psm_commits(NATIVE_PEG_ASSET_ID), "and one native ledger");
        assert_eq!(after[1].0, one_xmr, "the Monero opening holds the deposit");
        assert_eq!((after[0].0, after[0].2), (0, 0), "the native opening moved by zero");
        let (r_val, m_val) = (one_xmr, usdm_100);
        // §19.5 item 1: a Monero cash-out is a dollar rung too — custody reads only "a $D piece"
        assert_eq!(peg.peg_out_release(5_000_000_000, crate::cashout_ticket::KIND_XMR), None, "⛔ a $50 burn, not a rung, released piconero");
        // CASH-OUT: burn $10 (one rung), release its piconero at the XMR mark from Monero's ledger
        let burn: u128 = 1_000_000_000;
        let release = peg.peg_out_release(burn, crate::cashout_ticket::KIND_XMR).expect("priced at the XMR mark");
        assert_eq!(release, 66_666_666_666, "$10 at $150/XMR");
        let release = PegLedger::release_within_share_for(XMR_PEG_ASSET_ID, release, burn, r_val, m_val).expect("solvent");
        let leg = usdm_decider::poseidon2_compress::lanes_of_const(&[0x55, 0x66, 0x77, 0x88]);
        let bb = peg_out_burn_blind(&leg);
        // TAMPER: releasing more than the burn is worth at the redeem floor does not prove
        assert!(peg.orchestrate_cover(false, XMR_PEG_ASSET_ID, &after, release * 2, burn, &leg, &bb, None).is_none(), "⛔ a Monero peg-out released twice its burn");
        // TAMPER: Monero's piconero drawn from the native ledger (which holds no reserve) does not prove
        assert!(peg.orchestrate_cover(false, NATIVE_PEG_ASSET_ID, &after, release, burn, &leg, &bb, None).is_none(), "⛔ Monero's release drew on the native ledger");
        let (out_blob, out_rc, out_mc, _out_after) = peg
            .orchestrate_cover(false, XMR_PEG_ASSET_ID, &after, release, burn, &leg, &bb, None)
            .expect("the cash-out proves on Monero's ledger");
        let out_posts = peg.verify_cover(false, &out_blob, (out_rc, out_mc), peg_out_burn_commit(burn, &leg), None).expect("the PegOut door verifies the cover");
        assert_eq!(peer_node.verify_cover(false, &out_blob, (out_rc, out_mc), peg_out_burn_commit(burn, &leg), None), Some(out_posts));
        // TAMPER: the burn commitment swapped — no cover retires another burn
        assert!(peg.verify_cover(false, &out_blob, (out_rc, out_mc), peg_out_burn_commit(burn + 1, &leg), None).is_none(), "⛔ a peg-out retiring another burn verified");
        let before = (peg.psm_commits(NATIVE_PEG_ASSET_ID), peg.psm_commits(XMR_PEG_ASSET_ID));
        peg.apply_cover(&out_posts);
        peer_node.apply_cover(&out_posts);
        assert_ne!(peg.psm_commits(NATIVE_PEG_ASSET_ID), before.0, "⛔ §19.5b: a Monero cash-out left the native pair standing");
        assert_ne!(peg.psm_commits(XMR_PEG_ASSET_ID), before.1);
        assert_eq!(peer_node.psm_commits(XMR_PEG_ASSET_ID), peg.psm_commits(XMR_PEG_ASSET_ID), "the cash-out leaves both ledgers on one pair");
        let _ = cs::u256_from_u64(0);
    }

    /// ⛔⛔⛔ DB-124 — THE INFLATION, ARMED AND THEN REFUSED. The calibration half proves the attack is
    /// real against the OLD rule (atomic counts), the refutation half proves the new gate fires.
    ///
    /// Real units: USDm has 8 decimals, so 1 USDm = 1e8 atomic. XMR has 12, so 1 XMR = 1e12 piconero. At
    /// XMR = $150 one piconero is worth 0.015 USDm-atomic, i.e. a mark of `15_000` at `PRICE_SCALE` 1e6.
    #[test]
    fn a_one_xmr_deposit_cannot_mint_billions_once_the_price_mark_gates_it() {
        super::unprice_fixtures_for_test(); // REFUTATION 1 measures the unpriced door
        let (custodians, vs) = quorum();
        let mut peg = PegLedger::new(15_000);
        let asset = NATIVE_PEG_ASSET_ID;

        let one_xmr_piconero: u128 = 1_000_000_000_000;
        // What the UNPRICED rule allowed: the deposit's ATOMIC COUNT was the reserve, so at 150% the
        // mintable figure was 1e12 * 10000/15000 = 666_666_666_666 USDm-atomic = $6,666.67 BILLION-scale
        // over-issue against ~$150 of real collateral.
        let unpriced_mintable = one_xmr_piconero.saturating_mul(10_000) / 15_000;
        assert_eq!(unpriced_mintable, 666_666_666_666, "the attack figure is what the old rule permitted");

        // ── REFUTATION 1: with NO mark the door refuses everything. Fail-closed, no 1:1 fallback.
        assert!(
            !peg.mint_is_covered_by_priced_deposit(asset, one_xmr_piconero, 1),
            "with no attested price, even a 1-atomic mint is refused — a fallback IS the bug"
        );

        // ── Set a real mark through the REAL door: 1 piconero = 0.015 USDm-atomic.
        let price: u128 = 15_000;
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = custodians
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, asset, price));
                crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        let v = MlDsaVerifier;
        assert_eq!(
            peg.mark_price_attested(1, asset, &quotes, &vs, &v),
            PegOutcome::PriceMarked(price),
            "the bonded set marks the price through the one door"
        );

        // 1 XMR is worth 1e12 * 15_000 / 1e6 = 15_000_000_000 USDm-atomic = $150.00 exactly.
        assert_eq!(peg.priced_value(asset, one_xmr_piconero), Some(15_000_000_000));

        // ── REFUTATION 2: the attack figure is now REFUSED.
        assert!(
            !peg.mint_is_covered_by_priced_deposit(asset, one_xmr_piconero, unpriced_mintable),
            "the 666_666_666_666 over-issue the unpriced rule allowed is REFUSED once the mark gates it"
        );

        // ── The honest mint still passes: $150 of collateral backs $100 of USDm at 150%.
        let honest = 10_000_000_000u128; // $100.00 in USDm-atomic
        assert!(
            peg.mint_is_covered_by_priced_deposit(asset, one_xmr_piconero, honest),
            "an honest mint inside the ratio is unaffected — this gate refuses over-issue, not issuance"
        );
        // And one atomic unit past the ratio is refused, so the boundary is the ratio and not a rounding.
        assert!(
            !peg.mint_is_covered_by_priced_deposit(asset, one_xmr_piconero, honest + 1),
            "one atomic unit past the 150% line is refused — the boundary is exact"
        );
    }

    /// SATOSHI §10.8 — the pendulum snapshot is taken ONCE per epoch from the step's pre-state, never moves backward, starts at
    /// "none", snapshots epoch 0 like any other, and reads the ledger's own issued SAT.
    #[test]
    fn the_pendulum_snapshot_is_taken_once_per_epoch_from_the_pre_state_and_never_moves_backward() {
        let mut peg = PegLedger::new(DEFAULT_MINT_RATIO_BPS);
        assert_eq!(peg.pendulum_snapshot(), None, "no snapshot before the first fold step");
        assert!(peg.credit_sat_reward(3_000));
        assert!(peg.snapshot_pendulum(0, 2_000), "epoch 0 is snapshotted");
        assert_eq!(peg.pendulum_snapshot(), Some((0, 5_000)), "2,000 bonded of 3,000 issued ⇒ 50/50");
        assert!(!peg.snapshot_pendulum(0, 100), "⛔ a second snapshot in the same epoch");
        assert_eq!(peg.pendulum_snapshot(), Some((0, 5_000)), "the epoch's rate did not move inside it");
        assert!(peg.snapshot_pendulum(7, 900));
        assert_eq!(peg.pendulum_snapshot(), Some((7, 10_000)), "≤ one third bonded ⇒ everything to bonders");
        assert!(!peg.snapshot_pendulum(6, 3_000), "⛔ an earlier epoch moved the snapshot backward");
        assert_eq!(peg.pendulum_snapshot(), Some((7, 10_000)));
    }

    /// A mark may only move FORWARD. A re-broadcast of a mark this node already stands on must not
    /// re-apply, or a stale price could be replayed onto a live ledger.
    #[test]
    fn a_price_mark_cannot_be_replayed_at_the_same_or_an_earlier_epoch() {
        let (custodians, vs) = quorum();
        let mut peg = PegLedger::new(15_000);
        let v = MlDsaVerifier;
        let mk = |epoch: u64, price: u128| -> Vec<crate::price_mark_tx::PriceQuote> {
            custodians
                .iter()
                .map(|c| {
                    let a = c.attest(&PegLedger::price_mark_msg(epoch, NATIVE_PEG_ASSET_ID, price));
                    crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
                })
                .collect()
        };
        assert_eq!(
            peg.mark_price_attested(5, NATIVE_PEG_ASSET_ID, &mk(5, 20_000), &vs, &v),
            PegOutcome::PriceMarked(20_000)
        );
        assert_eq!(
            peg.mark_price_attested(5, NATIVE_PEG_ASSET_ID, &mk(5, 20_000), &vs, &v),
            PegOutcome::Replay,
            "a re-broadcast of the mark this node stands on cannot re-apply"
        );
        // ⛔ DB-245: this arm used to assert that ANY different same-epoch mark is refused — first-wins, which
        // is the arrival-order dependence DB-245 removes. A different valid mark for the same epoch is decided
        // by the one total order: refused if it does not outrank, installed if it does, and the mark it
        // displaced can then never come back.
        let outranks = |p: u128, q: u128| crate::price_mark_tx::outranks(5, NATIVE_PEG_ASSET_ID, p, q);
        let loser = (20_001..=40_000u128).find(|p| !outranks(*p, 20_000)).expect("a price that does not outrank");
        let winner = (20_001..=40_000u128).find(|p| outranks(*p, 20_000)).expect("a price that outranks");
        assert_eq!(
            peg.mark_price_attested(5, NATIVE_PEG_ASSET_ID, &mk(5, loser), &vs, &v),
            PegOutcome::Replay,
            "a same-epoch mark that does not outrank the standing one is refused"
        );
        assert_eq!(
            peg.mark_price_attested(5, NATIVE_PEG_ASSET_ID, &mk(5, winner), &vs, &v),
            PegOutcome::PriceMarked(winner),
            "a same-epoch mark that outranks the standing one replaces it, whatever arrived first"
        );
        assert_eq!(
            peg.mark_price_attested(5, NATIVE_PEG_ASSET_ID, &mk(5, 20_000), &vs, &v),
            PegOutcome::Replay,
            "the displaced mark cannot come back: the standing mark only moves up the order"
        );
        assert_eq!(
            peg.mark_price_attested(4, NATIVE_PEG_ASSET_ID, &mk(4, 99_999), &vs, &v),
            PegOutcome::Replay,
            "an earlier epoch cannot re-mark"
        );
        assert_eq!(
            peg.price_mark_for(NATIVE_PEG_ASSET_ID).map(|m| m.price),
            Some(winner),
            "the mark this node stands on is the maximum of the order, untouched by every refusal"
        );
    }

    /// ⭐ §BR-4 — A CLOSED PRICE EPOCH JOINS THE TWAP AND THE LOW; AN OPEN ONE NEVER DOES, WHATEVER ARRIVED FIRST. Real
    /// attested marks through the one door: epoch 144 at 20,000 (two same-epoch marks in either order), then epoch 288 at
    /// 30,000. Until epoch 288 arrives the history is empty and the TWAP reads the standing mark; after it, epoch 144's
    /// standing mark (the order's maximum, not the first arrival) is folded, and two ledgers fed the same-epoch pair in
    /// opposite orders hold the SAME history. TAMPER: a ledger folding the first arrival of an open epoch would hold the
    /// loser's price in its low — refuted by the cross-order equality.
    #[test]
    fn a_closed_price_epoch_joins_the_twap_and_the_low_and_an_open_one_never_does() {
        let (custodians, vs) = quorum();
        let v = MlDsaVerifier;
        let mk = |epoch: u64, price: u128| -> Vec<crate::price_mark_tx::PriceQuote> {
            custodians
                .iter()
                .map(|c| {
                    let a = c.attest(&PegLedger::price_mark_msg(epoch, NATIVE_PEG_ASSET_ID, price));
                    crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
                })
                .collect()
        };
        let outranks = |p: u128, q: u128| crate::price_mark_tx::outranks(144, NATIVE_PEG_ASSET_ID, p, q);
        let low = (19_000..=20_000u128).find(|p| !outranks(*p, 20_000) && outranks(20_000, *p)).expect("a lower-ranked price");
        let mut ab = PegLedger::new(15_000);
        let mut ba = PegLedger::new(15_000);
        for (l, order) in [(&mut ab, [low, 20_000]), (&mut ba, [20_000, low])] {
            for p in order {
                let _ = l.mark_price_attested(144, NATIVE_PEG_ASSET_ID, &mk(144, p), &vs, &v);
            }
            assert_eq!(l.price_mark_for(NATIVE_PEG_ASSET_ID).map(|m| m.price), Some(20_000), "CALIBRATION: the order's maximum stands");
            assert_eq!(l.br_census().price_history, vec![], "⛔ an OPEN epoch's mark entered the history");
            assert_eq!(l.twap7(NATIVE_PEG_ASSET_ID), Some(20_000), "no closed epoch: the TWAP reads the standing mark");
            assert_eq!(
                l.mark_price_attested(288, NATIVE_PEG_ASSET_ID, &mk(288, 30_000), &vs, &v),
                PegOutcome::PriceMarked(30_000)
            );
        }
        assert_eq!(ab.br_census(), ba.br_census(), "⛔ arrival order inside an epoch changed the folded history");
        assert_eq!(ab.twap7(NATIVE_PEG_ASSET_ID), Some(20_000), "the one closed epoch is the TWAP");
        assert_eq!(ab.low30(NATIVE_PEG_ASSET_ID), Some(20_000), "⛔ the low holds a price that never stood at its epoch's close");
        assert_eq!(ab.price_mark_for(NATIVE_PEG_ASSET_ID).map(|m| m.price), Some(30_000), "the new mark stands, unfolded");
    }

    /// ⭐ §BR-4 (spec §1 item 7) — MINTS AND REDEMPTIONS ARE JUDGED AT THE 7-DAY TWAP, AND A LIQUIDATION AT AN OUTLIER MARK IS
    /// REFUSED. Real attested marks: epoch 144 at 20,000, then epoch 288 at 40,000 (a doubling inside ten minutes). The
    /// redemption floor (`release_sats_for_burn`) and the mint gate (`priced_value`) read 20,000 (the closed epoch's TWAP), not the
    /// live 40,000; the liquidation rule is refused while the mark strays 100 % from the TWAP (band 25 %) and admitted once a mark
    /// inside the band stands. TAMPER: the pre-switch rule (the live mark) would release half the sats for the same burn.
    #[test]
    fn mints_and_redemptions_read_the_twap_and_an_outlier_mark_cannot_liquidate() {
        let (custodians, vs) = quorum();
        let v = MlDsaVerifier;
        let mk = |epoch: u64, price: u128| -> Vec<crate::price_mark_tx::PriceQuote> {
            custodians
                .iter()
                .map(|c| {
                    let a = c.attest(&PegLedger::price_mark_msg(epoch, NATIVE_PEG_ASSET_ID, price));
                    crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
                })
                .collect()
        };
        let mut peg = PegLedger::new(15_000);
        assert_eq!(peg.mark_price_attested(144, NATIVE_PEG_ASSET_ID, &mk(144, 20_000), &vs, &v), PegOutcome::PriceMarked(20_000));
        assert_eq!(peg.mark_price_attested(288, NATIVE_PEG_ASSET_ID, &mk(288, 40_000), &vs, &v), PegOutcome::PriceMarked(40_000));
        assert_eq!(peg.reference_price(NATIVE_PEG_ASSET_ID), Some(20_000), "the reference price is the closed epoch's TWAP");
        let burn = 1_000_000u128;
        let at = |p: u128| burn * crate::liquidation::PRICE_SCALE / p;
        assert_eq!(peg.release_sats_for_burn(NATIVE_PEG_ASSET_ID, burn), Some(at(20_000)), "⛔ a redemption read the live mark");
        assert_ne!(at(20_000), at(40_000), "CALIBRATION: the two rules differ");
        assert_eq!(peg.priced_value(NATIVE_PEG_ASSET_ID, 100), Some(100 * 20_000 / crate::liquidation::PRICE_SCALE), "⛔ a mint read the live mark");
        assert!(peg.liquidation_rule(NATIVE_PEG_ASSET_ID).is_none(), "⛔ a mark 100 % off the TWAP could liquidate");
        assert_eq!(peg.mark_price_attested(432, NATIVE_PEG_ASSET_ID, &mk(432, 22_000), &vs, &v), PegOutcome::PriceMarked(22_000));
        let twap = peg.reference_price(NATIVE_PEG_ASSET_ID).expect("held");
        assert!(22_000u128.abs_diff(twap) * 10_000 <= twap * u128::from(LIQ_TWAP_BAND_BPS), "CALIBRATION: 22,000 is inside the band of {twap}");
        assert!(peg.liquidation_rule(NATIVE_PEG_ASSET_ID).is_some(), "a mark inside the band admits the liquidation rule");
    }

    /// ⭐⭐ §BR-4/§BR-7 REFUTER 5 AT THE MARK DOOR — A GUARDED MARK BELOW A BAND LIQUIDATES IT, ON EVERY LEDGER ALIKE; AN OUTLIER
    /// LIQUIDATES NOTHING. Two ledgers hold the same units (band 40 and band 30) and are fed the same attested marks: two epochs
    /// at 10 % above band 40's floor (the TWAP), then a mark one unit under band 40's floor (inside the 25 % guard). Both
    /// liquidate exactly band 40 (its epoch closes, its count empties) and keep band 30; their books are byte-equal. TAMPER: a
    /// third ledger fed an OUTLIER (half the TWAP, outside the guard) liquidates nothing, and a ledger with no closed epoch
    /// (launch) liquidates nothing even at a mark under every band.
    #[test]
    fn a_guarded_mark_below_a_band_liquidates_it_on_every_ledger_and_an_outlier_liquidates_nothing() {
        use crate::debt_units::{band_price_word, UnitTerms};
        let (custodians, vs) = quorum();
        let v = MlDsaVerifier;
        let mk = |epoch: u64, price: u128| -> Vec<crate::price_mark_tx::PriceQuote> {
            custodians
                .iter()
                .map(|c| {
                    let a = c.attest(&PegLedger::price_mark_msg(epoch, NATIVE_PEG_ASSET_ID, price));
                    crate::price_mark_tx::PriceQuote { price, pubkey: a.pubkey, sig: a.sig }
                })
                .collect()
        };
        let near = UnitTerms { k: 40, l: 1, day: 0, epoch: 0 };
        let safe = UnitTerms { k: 30, l: 1, day: 0, epoch: 0 };
        let fresh = || {
            let mut l = PegLedger::new(15_000);
            l.unit_book.open_unit(&near, 0).expect("opens");
            l.unit_book.open_unit(&safe, 0).expect("opens");
            l
        };
        let above = band_price_word(40) * 11 / 10;
        let under = band_price_word(40) - 1;
        let (mut a, mut b, mut outlier, mut launch) = (fresh(), fresh(), fresh(), fresh());
        for l in [&mut a, &mut b, &mut outlier] {
            assert_eq!(l.mark_price_attested(144, NATIVE_PEG_ASSET_ID, &mk(144, above), &vs, &v), PegOutcome::PriceMarked(above));
            assert_eq!(l.mark_price_attested(288, NATIVE_PEG_ASSET_ID, &mk(288, above), &vs, &v), PegOutcome::PriceMarked(above));
            assert_eq!(l.unit_book().open_in(40, 1), Some(1), "CALIBRATION: no mark under the band yet");
        }
        for l in [&mut a, &mut b] {
            assert_eq!(l.mark_price_attested(432, NATIVE_PEG_ASSET_ID, &mk(432, under), &vs, &v), PegOutcome::PriceMarked(under));
            assert_eq!(l.unit_book().open_in(40, 1), Some(0), "⛔ a guarded mark under the band left its unit open");
            assert_eq!(l.unit_book().epoch_of(40), Some(1), "⛔ the liquidated band's epoch did not close");
            assert_eq!(l.unit_book().open_in(30, 1), Some(1), "⛔ a band under the mark was liquidated");
        }
        assert_eq!(a.br_census(), b.br_census(), "⛔ two ledgers fed the same marks hold different books");
        let half = above / 2;
        assert_eq!(outlier.mark_price_attested(432, NATIVE_PEG_ASSET_ID, &mk(432, half), &vs, &v), PegOutcome::PriceMarked(half));
        assert_eq!(outlier.unit_book().open_in(40, 1), Some(1), "⛔ an outlier mark (outside the guard) liquidated a band");
        assert_eq!(outlier.unit_book().open_in(30, 1), Some(1), "⛔ an outlier mark liquidated a band");
        assert_eq!(launch.mark_price_attested(144, NATIVE_PEG_ASSET_ID, &mk(144, 1), &vs, &v), PegOutcome::PriceMarked(1));
        assert_eq!(launch.unit_book().principal(), crate::debt_units::UNIT_ATOMIC[1] * 2, "⛔ a launch mark with no TWAP liquidated");
    }

    /// ⛔ AN UNBONDED CROWD CANNOT SET A PRICE. Weight decides, and a signature from a key with no bond
    /// adds none — so a mark needs >=2/3 of REAL bonded weight, exactly like every other attested door.
    #[test]
    fn unbonded_signers_cannot_move_a_price_mark() {
        let (_c, vs) = quorum();
        let mut peg = PegLedger::new(15_000);
        let v = MlDsaVerifier;
        let strangers: Vec<Custodian> = (0..8u8).map(|i| Custodian::generate(&[200 + i; 32])).collect();
        let quotes: Vec<crate::price_mark_tx::PriceQuote> = strangers
            .iter()
            .map(|c| {
                let a = c.attest(&PegLedger::price_mark_msg(1, NATIVE_PEG_ASSET_ID, 1));
                crate::price_mark_tx::PriceQuote { price: 1, pubkey: a.pubkey, sig: a.sig }
            })
            .collect();
        assert_eq!(
            peg.mark_price_attested(1, NATIVE_PEG_ASSET_ID, &quotes, &vs, &v),
            PegOutcome::InsufficientThreshold,
            "eight unbonded signatures carry zero weight"
        );
        assert_eq!(peg.price_mark_for(NATIVE_PEG_ASSET_ID), None, "and no mark was set");
    }

    /// The real ML-DSA verifier with a tally of how many signature checks the door paid for. It holds
    /// no collection — it forwards to [`MlDsaVerifier`] and counts — so the verdict this pin observes
    /// is the production one, not a double's opinion of it.
    struct CountingMlDsa {
        calls: std::sync::atomic::AtomicUsize,
    }
    impl PqVerifier for CountingMlDsa {
        fn verify(&self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            MlDsaVerifier.verify(pubkey, msg, sig)
        }
    }
    impl CountingMlDsa {
        fn new() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn paid(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    /// ⛔ PIN — PADDING A CASH-OUT'S ATTESTATION VECTOR MUST NOT BLOCK THE CASH-OUT, ON EITHER PARTY.
    ///
    /// PAST-CHATS-CHECKED: the twin of `psm::tests::
    /// the_mint_doors_signature_work_is_bounded_by_the_bonded_set_on_every_party`, which cites the
    /// house bounded-work shape `pin_d5_the_btc_deposit_watch_set_must_be_bounded_against_a_hostile_
    /// caller`. `threshold_ok` is the SHARED gate under peg-in, peg-out and re-mark, so the same
    /// ordering defect sat under all three; this pin stands on the PEG-OUT door because that is the
    /// user's cash-out path, where a refusal is a person unable to get their money out.
    ///
    /// WHAT IS ASSERTED, AND WHY IT NEEDS NO VALID CARRIER: `peg_out_confidential` runs the ≥2/3
    /// threshold BEFORE it verifies the WHIR redeem carrier, so a deliberately invalid carrier
    /// separates the two answers cleanly — `InsufficientThreshold` means the attestation gate refused,
    /// `BadRequest` means the gate PASSED and the carrier was then rejected. This pin therefore reads
    /// the threshold gate's verdict directly, with no proving cost and nothing invented: the expected
    /// answer is COMPUTED by the honest attestation, never written down.
    ///
    /// WHY TWO PARTIES: the redeem threshold is a consensus decision. If attacker-appended junk could
    /// change what one node decides, two honest nodes would disagree about whether a redemption is
    /// authorized — an attacker-triggered split on the reserve-release path. Both parties are built
    /// and both are asked.
    ///
    /// MEASURED 2026-09-08 against the PRE-FIX ordering (verify before dedupe/bond), on a faithful
    /// reproduction of this loop: a 252-element hostile vector cost 202 verifies and returned
    /// UNAUTHENTICATED where the honest subset alone returned authorized. On this door that verdict
    /// is `InsufficientThreshold` — a legitimate holder's redemption refused because someone appended
    /// keys that carry no bond and could never have counted. That is funds-availability, not just CPU.
    #[test]
    fn padding_a_redeem_attestation_cannot_refuse_the_redeem_or_unbound_its_work_on_every_party() {
        // ONE charter, admitted independently by each party. `Custodian::generate` draws a FRESH
        // ML-DSA keypair (the seed argument feeds only the secp bridge point), so calling `quorum()`
        // twice would produce two DIFFERENT charters and every attestation would read as unbonded —
        // the parties must admit the SAME custodians to be views of one validator set.
        let (custodians, ctl_vs) = quorum();
        let vs_of = |cs: &[Custodian]| {
            let mut vs = ValidatorSet::new();
            for c in cs {
                vs.admit(c.id(), 5000, 0).expect("admit the charter custodian");
            }
            vs
        };
        let nf = [0xC7u8; 32];
        let (new_rc, new_mc) = (usdm_decider::poseidon2_compress::lanes_of(&[9, 9, 9, 9]), usdm_decider::poseidon2_compress::lanes_of(&[8, 8, 8, 8]));
        let msg = peg_out_confidential_msg(&nf, &new_rc, &new_mc, &[0xb7u8; 32], &[0u8; 32], &usdm_decider::poseidon2_compress::zero_digest(), &[0u8; 32], &[0u8; 32]);

        // The honest attestation: the full 2-of-2 charter quorum over this exact redemption.
        let honest = attest(&custodians, &msg);

        // The attacker's padding — appended to that same honest attestation, changing nothing that
        // can count: the first honest attestor repeated 200×, then 51 keys carrying no bond at all.
        let mut padded = honest.clone();
        for _ in 0..200 {
            padded.push(honest[0].clone());
        }
        for n in 100u8..=150 {
            padded.push(MintAttestor {
                pubkey: vec![n; 40],
                sig: vec![0u8; 8],
            });
        }

        // A carrier that cannot verify, so the door's answer reports the THRESHOLD gate's verdict:
        // InsufficientThreshold = the attestation was refused; BadRequest = it passed.
        let junk_carrier = vec![0u8; 64];

        // The expectation is COMPUTED, on its own party, from the honest attestation alone.
        let ctl_pq = CountingMlDsa::new();
        let expected = PegLedger::new(15_000).peg_out_confidential(
            nf,
            &junk_carrier,
            new_rc,
            new_mc,
            &[0xb7u8; 32], &[0u8; 32], usdm_decider::poseidon2_compress::zero_digest(), &[0u8; 32], &[0u8; 32],
            &ctl_vs,
            &ctl_pq,
            &honest);
        assert!(
            !matches!(expected, PegOutcome::InsufficientThreshold),
            "PRECONDITION: the honest 2-of-2 attestation must clear the threshold gate, so that a \
             later InsufficientThreshold can only mean the padding caused it (got {expected:?})"
        );

        for name in ["party_a", "party_b"] {
            let vs = vs_of(&custodians); // each party's own view of the SAME bonded charter
            let pq = CountingMlDsa::new();
            let verdict = PegLedger::new(15_000).peg_out_confidential(
                nf,
                &junk_carrier,
                new_rc,
                new_mc,
                &[0xb7u8; 32], &[0u8; 32], usdm_decider::poseidon2_compress::zero_digest(), &[0u8; 32], &[0u8; 32],
                &vs,
                &pq,
                &padded);

            assert_eq!(
                verdict, expected,
                "⛔ PADDING REFUSED A CASH-OUT on {name}: the padded attestation carries the SAME \
                 distinct bonded custodians as the honest one, so it must decide identically \
                 ({expected:?}). If junk appended by anyone can turn a valid redemption into \
                 InsufficientThreshold, a holder is blocked from getting their money out by a party \
                 that posted no bond and could never have counted — and two honest nodes handed the \
                 same request would disagree about whether the reserve may be released."
            );
            assert!(
                pq.paid() <= vs.len(),
                "⛔ BOUNDED WORK VIOLATED (§9.6 Q5, redeem door) on {name}: {paid} ML-DSA verifies \
                 for {n} caller-chosen attestors against a bonded charter of {bonded} (the honest \
                 attestation paid {ctl}). `threshold_ok` is the shared gate under peg-in, peg-out and \
                 re-mark, so the caller would be choosing this node's CPU cost on EVERY reserve \
                 movement. FIX SPEC: only a DISTINCT, BONDED attestor can add weight, so the dedupe \
                 (`seen.insert`) and the zero-bond test (`quorum.bond_of(&id) == 0`) must BOTH \
                 precede `verifier.verify` in `threshold_ok`. The verify count is then bounded by the \
                 bonded set, which grows only by posting real bond. Do not cap the vector's length: a \
                 length cap is a refusal bound, and an honest charter that outgrows it would be \
                 locked out of its own reserve.",
                paid = pq.paid(),
                n = padded.len(),
                bonded = vs.len(),
                ctl = ctl_pq.paid()
            );
        }
    }

    // DB-237: the stake reward's SUPPLY STEP — the node verifies the WHIR carrier against its persisted commitments and the
    // stake carrier's reward commitment, and advances minted_commit. No pool, no index, no counter — the node learns no
    // stake / reward / total.
    #[test]
    /// ⭐ §BR-3 17.6 — THE SURPLUS BUFFER FILLS TO ITS TARGET, THEN ITS SHARE FLOWS TO THE STAKERS. A target of 300: the
    /// first fee of 1,000 credits the buffer its 250; the second fills it to 300 and the other 200 of its share joins the
    /// stakers' 400; the third sends the whole 250 on. The four credits sum to every fee exactly. TAMPER: crediting past
    /// the target (the uncapped split) would leave the buffer at 750 — refuted against the capped ledger.
    fn the_surplus_buffer_fills_to_its_target_then_its_share_flows_to_the_stakers() {
        let mut peg = PegLedger::genesis(15_000);
        let mut uncapped = PegLedger::genesis(15_000);
        for k in 1..=3u64 {
            assert!(peg.credit_fee_pools_capped(1_000, 0, 300));
            assert!(uncapped.credit_fee_pools_at(1_000, 0));
            assert_eq!(peg.fee_pools().total(), u128::from(k * 1_000), "⛔ the capped split lost or invented a credit");
        }
        let p = peg.fee_pools();
        assert_eq!(p.surplus, 300, "⛔ the buffer passed its target");
        assert_eq!(p.stakers, 3 * 400 + 450, "the overflow (200 + 250) joined the stakers");
        assert_eq!((p.bonders, p.miner), (750, 300), "the bonders' and miner's shares never move");
        assert_eq!(uncapped.fee_pools().surplus, 750, "CALIBRATION: the uncapped split fills past the target");
    }

    #[test]
    /// ⭐ §BR-3 17.6 (stakers' half) — A STAKE REWARD IS PAID FROM THE STAKERS' POOL, NEVER ABOVE ITS INFLOW, AND THE USDm
    /// SUPPLY DOES NOT MOVE. The pool is credited by fees and snapshotted at the epoch's first block; a reward of 100 against a
    /// snapshot of 400 advances the paid-out commitment by exactly the hidden reward and leaves the supply commitment where
    /// it was. TAMPERS: a supply step read against another reward, a claim of another epoch, a carrier over an inflow the
    /// chain never credited, a replayed step, and a reward the inflow cannot cover (the carrier does not even build) are
    /// each refused with nothing moved.
    fn the_stake_reward_is_paid_from_the_stakers_pool_never_above_its_inflow_and_the_supply_does_not_move() {
        use usdm_decider::confidential_solvency as cs;
        let (yb, npb) = (usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), usdm_decider::poseidon2_compress::lanes_of(&[9, 10, 11, 12]));
        let mut peg = PegLedger::genesis(15_000);
        assert!(peg.credit_fee_pools(1_000)); // the stakers' 40 % = 400
        let e: u64 = 20_000;
        assert_eq!(peg.stakers_pool_snapshot(e), None, "no snapshot before the epoch's first block");
        assert!(peg.snapshot_stakers_pool(e), "the epoch's first block takes the snapshot");
        assert!(peg.credit_fee_pools(1_000), "fees inside the epoch credit the pool, not the snapshot");
        let pool_in = peg.stakers_pool_snapshot(e).expect("held");
        assert_eq!(pool_in, 400);
        assert!(!peg.snapshot_stakers_pool(e) && !peg.snapshot_stakers_pool(e - 1), "once per epoch, never backward");
        let supply_before = peg.minted_commit();
        let prove = |reward: u64, inflow: u64| {
            cs::prove_yield_mint_carrier(
                cs::u256_from_u64(inflow),
                cs::u256_from_u64(0),
                cs::u256_from_u64(reward),
                yb,
                GENESIS_STAKE_PAID_BLIND,
                npb,
                STAKERS_POOL_PUBLIC_BLIND,
                cs::Backing::at_unit_price(10_000),
            )
        };
        assert!(prove(401, pool_in).is_none(), "⛔ a reward above the pool's inflow built a carrier");
        let (bytes, c) = prove(100, pool_in).expect("a reward inside the inflow proves");
        assert_eq!(c.minted_commit, peg.stake_paid_commit(), "proved against the persisted paid-out total");
        assert_eq!(c.reserve_commit, stakers_pool_in_commit(pool_in), "and the public inflow under the public blind");
        let other = cs::solvency_commit_256(cs::u256_from_u64(101), yb);
        assert!(!peg.apply_stake_supply(&bytes, other, c.new_minted_commit, e), "⛔ a step read against another reward verified");
        assert!(!peg.apply_stake_supply(&bytes, c.yield_commit, c.new_minted_commit, e - 1), "⛔ a claim of another epoch verified");
        let (big, cb) = prove(500, 800).expect("a reward inside a larger, uncredited inflow proves");
        assert!(!peg.apply_stake_supply(&big, cb.yield_commit, cb.new_minted_commit, e), "⛔ a carrier over an inflow the chain never credited verified");
        assert_eq!(peg.stake_paid_commit(), c.minted_commit, "a refused step advanced the paid-out total");
        assert!(peg.apply_stake_supply(&bytes, c.yield_commit, c.new_minted_commit, e), "the node verifies and advances");
        assert_eq!(peg.stake_paid_commit(), c.new_minted_commit, "the paid-out total advanced by the hidden reward");
        assert_eq!(peg.minted_commit(), supply_before, "⛔ the USDm supply moved: the reward must come from the pool, not a mint");
        assert!(!peg.apply_stake_supply(&bytes, c.yield_commit, c.new_minted_commit, e), "⛔ a replayed supply step verified");
    }

    // ══ ADVERSARIAL REFUTATION PINS (2026-09-08 red team) ══════════════════════════════════════════════════════
    // These are ATTACKS, not confirmations. Each one drives the REAL door with a REAL >=2/3 ML-DSA quorum and a
    // REAL WHIR carrier, and asserts the outcome the shipped code actually produces.

    // PIN 4 — A POOL SMALLER THAN THE RULE'S RETIRE LIQUIDATES PARTIALLY on two ledgers: C = T exactly (the pool burned
    // whole, closing its epoch), S the least collateral covering it; the PSM is left STRONGER but still under the target
    // (its mints stay refused until the pool grows) — never left unliquidated, never over-burned.
    #[test]
    fn a_pool_smaller_than_the_retire_liquidates_partially_on_two_ledgers() {
        let (mut f, vs) = liq_v2(500, 750_000);
        let rule = f.a.liquidation_rule(NATIVE_PEG_ASSET_ID).expect("a rule");
        let (c_rule, _) = usdm_decider::confidential_solvency::liquidation_amount(u256_from_u128(3_000), u256_from_u128(2_000), &rule).expect("due");
        assert!(c_rule[0] > 500, "CALIBRATION: the rule wants more than the pool holds ({})", c_rule[0]);
        let (plan, h, legs, att) = build_v2(&f, 0xC4);
        assert_eq!(plan.c, 500, "the pool is burned whole");
        assert!(plan.close && h.pool_close, "a pool burned whole closes its epoch");
        let (d, m, p) = (3_000u128, 2_000u128, 750_000u128);
        let before = d * p * 10_000 / (m * crate::liquidation::PRICE_SCALE);
        let after = (d - plan.s) * p * 10_000 / ((m - plan.c) * crate::liquidation::PRICE_SCALE);
        assert!(after > before && after < 15_000, "STRONGER ({before} → {after} bps) but still under the 150 % target");
        let (node_a, peer_node) = (&mut f.a, &mut f.b);
        for n in [node_a, peer_node] {
            assert_eq!(n.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "the partial liquidation applies");
            assert_eq!((n.reserve_commit(), n.minted_commit()), (h.new_reserve_commit, h.new_minted_commit));
            assert_eq!(n.pool_words(NATIVE_PEG_ASSET_ID).epoch, 1, "the drained epoch closed");
        }
        assert_eq!(f.a.pool_census(), f.b.pool_census(), "⛔⛔⛔ two pools after one partial liquidation");
    }

    // R1 (v2) — FREE SEIZURE is refuted by `a_healthy_psm_or_a_forged_liquidation_moves_nothing`: the v1 door never
    // consulted the due line and let two independent legs seize a healthy reserve; the v2 amount leg is UNPROVABLE for a
    // healthy PSM and welds the seize to the retire through `(DC, DS)`.
    //
    // R2 (v2) — THE UNDER-FLOOR DEAD-END. The v1 door's post-state floor leg made every honest close of an under-floor
    // book UNPROVABLE, and the only mark it still took ERASED liability with no burn. v2 has no floor leg: an under-floor
    // PSM takes the FULL regime (Liquity's under-100 % liquidation — the pool retires the whole supply and takes the whole
    // reserve), and every retired unit is a pool burn on `T` by the same `DC`.
    #[test]
    fn refut_v2_an_under_floor_psm_is_still_closable_and_every_retired_unit_is_a_pool_burn() {
        let (f, vs) = liq_v2(2_500, 600_000); // 3000 at 0.6 = 1800 of value vs 2000 of supply: 90 %, under the floor
        assert!(
            !crate::liquidation::aggregate_solvent(1_800, 2_000, f.a.redeem_floor_bps()),
            "CALIBRATION: the PSM is under the 100 % floor at this mark"
        );
        let (plan, h, legs, att) = build_v2(&f, 0xEE);
        assert_eq!((plan.c, plan.s), (f.open.minted, f.open.reserve), "the FULL regime: the whole supply retires, the whole reserve is seized");
        let (pool_t, LiqV2 { a: mut node_a, b: mut peer_node, .. }) = (f.open.pool_t, f);
        assert_eq!(node_a.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "⛔ the under-floor PSM is LOCKED");
        assert_eq!(peer_node.liquidate_confidential(&h, &legs, &vs, &MlDsaVerifier, &att), PegOutcome::Liquidated, "the peer applies it");
        let zero = |b: crate::spend_frontier::Digest4| usdm_decider::confidential_solvency::solvency_commit_256([0; 4], b);
        for n in [&node_a, &peer_node] {
            assert_eq!(n.minted_commit(), zero(plan.blinds[3]), "the whole supply retired");
            assert_eq!(n.reserve_commit(), zero(plan.blinds[2]), "the whole reserve went to the pool");
            assert_eq!(
                n.pool_words(NATIVE_PEG_ASSET_ID).t,
                usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(pool_t - plan.c), plan.blinds[4]),
                "⛔⛔⛔ the supply retired USDm the pool did not burn"
            );
        }
    }

}

// ⛔⛔⛔ THERE IS NO `From<PegLedgerV32> for PegLedger` AND NO `From<WrappedAssetV32>` (2026-09-12, §AG).
//
// They were the only constructors of the live peg types from a frozen checkpoint, and a checkpoint is
// exactly what can no longer cross the hash change: `reserve_commit`/`minted_commit` in a v32 file are
// `solvency_commit_256` values of the RETIRED one-round `MDS·(l + 7·r)^7` that kill list §AG measured as
// invertible, while the live ones are values of the truncated Poseidon2 permutation. Reading one as the
// other would install a supply state that no mint, redemption or backstop proof can ever open — the
// stablecoin's own commitments, silently unopenable. Their absence is what makes `persist::load`'s
// pre-fork refusal TOTAL rather than merely the default path.

#[cfg(all(test, feature = "pins-core"))]
mod supply_turnstile_tests {
    use super::*;
    use crate::chain_object::Class as C;

    /// ⭐⭐ §BR-10 — THE SUPPLY TURNSTILE'S RULE over every word and every class: the native words move only through a peg-in,
    /// a peg-out or a liquidation; the issued SAT only upward and only through the mining reward; a wrapped asset's words only
    /// through its mint, its registration or a liquidation; a step that moves nothing is always allowed. CALIBRATION: each
    /// door is allowed its own word (the rule is not "refuse everything").
    #[test]
    fn the_supply_turnstile_lets_each_supply_word_move_only_through_its_door() {
        let d = |b: u8| crate::spend_frontier::cm_bytes_to_root(&crate::spend_frontier::canonical_filler_bytes(b)).unwrap();
        let base = SupplyWords { native: (d(1), d(2)), sat_issued: 100, wrapped: vec![(7, d(3), d(4))] };
        let native = SupplyWords { native: (d(5), d(2)), ..base.clone() };
        let sat_up = SupplyWords { sat_issued: 101, ..base.clone() };
        let sat_down = SupplyWords { sat_issued: 99, ..base.clone() };
        let wrapped = SupplyWords { wrapped: vec![(7, d(3), d(6))], ..base.clone() };
        let classes = [
            C::PegIn, C::PegOut, C::Liquidation, C::SatoshiReward, C::WrappedMint, C::WrappedAssetRegister, C::BountyPayout,
            C::MinerPayout, C::YieldClaim, C::PoolDeposit, C::PoolWithdraw, C::AssetSpend, C::OrderFill, C::PriceMark,
            C::TheftRepayment, C::PotFill, C::DecoyBatch, C::DecoyReturn, C::UnitOpen, C::UnitClose, C::VaultMerge, C::ReserveCost, C::VaultKey,
            C::VaultRebalance,
        ];
        for c in classes {
            assert!(supply_move_allowed(c, &base, &base), "a step that moves nothing is allowed for {c:?}");
            assert_eq!(supply_move_allowed(c, &base, &native), matches!(c, C::PegIn | C::PegOut | C::Liquidation | C::TheftRepayment | C::PotFill | C::UnitOpen | C::UnitClose | C::VaultMerge | C::VaultRebalance | C::ReserveCost), "native words × {c:?}");
            assert_eq!(supply_move_allowed(c, &base, &sat_up), c == C::SatoshiReward, "issued SAT up × {c:?}");
            assert!(!supply_move_allowed(c, &base, &sat_down), "⛔ the issued SAT fell through {c:?}");
            assert_eq!(
                supply_move_allowed(c, &base, &wrapped),
                matches!(c, C::WrappedMint | C::WrappedAssetRegister | C::Liquidation),
                "wrapped words × {c:?}"
            );
            // ⭐ §19.5b: Monero's ledger (a bridge ledger in the wrapped map) moves only by a peg or a liquidation — never a wrapped mint
            let mut xmr = base.clone();
            xmr.wrapped.push((XMR_PEG_ASSET_ID, d(10), d(11)));
            let mut xmr_moved = xmr.clone();
            xmr_moved.wrapped.retain(|(id, ..)| *id != XMR_PEG_ASSET_ID);
            xmr_moved.wrapped.push((XMR_PEG_ASSET_ID, d(12), d(11)));
            // SAFE AT SCALE: a vault merge is one more door for the custody-funded words (native, bridge, coin) and never
            // for another wrapped asset's (asserted above: asset 7 stays shut to it)
            assert_eq!(supply_move_allowed(c, &xmr, &xmr_moved), matches!(c, C::PegIn | C::PegOut | C::Liquidation | C::UnitOpen | C::VaultMerge | C::VaultRebalance | C::ReserveCost), "⛔ Monero's ledger words × {c:?}");
            let mut coin = base.clone();
            coin.wrapped.push((vault_ledger(1, COIN_BTC_ASSET_ID), d(13), d(14)));
            let mut coin_gone = coin.clone();
            coin_gone.wrapped.retain(|(id, ..)| *id != vault_ledger(1, COIN_BTC_ASSET_ID));
            assert_eq!(supply_move_allowed(c, &coin, &coin_gone), matches!(c, C::WrappedMint | C::PegOut | C::VaultMerge | C::VaultRebalance), "⛔ a vault's coin ledger words × {c:?}");
        }
        // the restore puts every word back, and drops a wrapped asset the refused object added
        let mut l = PegLedger::genesis(15_000);
        let before = l.supply_words();
        l.sat_issued += 5;
        l.minted_commit = d(9);
        l.restore_supply_words(&before);
        assert_eq!(l.supply_words(), before, "the refused object's moves are undone");
    }
}


// ═══════════════════════════════ ⭐⭐⭐ §BR-3 17.5 — LAYERED REPAYMENT OF A CUSTODY THEFT ═══════════════════════════════
// docs/BR-3-17-5-LAYERED-REPAYMENT-SPEC-20261029.md; the object is `theft_repayment_tx` (its module doc holds the legs).

/// SAT's price-mark asset id: custody quotes SAT/USDm like any priced asset (`price_quote`), and its 7-day TWAP and 30-day low
/// (`price_history`) value the repayment pot. `"SAT\0"` read as a little-endian u32, far from the registered PSM ids.
pub const SAT_PRICE_ASSET_ID: u32 = u32::from_le_bytes(*b"SAT\0");
/// The repayment pot's haircut at launch (spec §2 item 5: ≥ 50 %, governed only tighter): the pot is valued at half the
/// floor price, so a thin SAT market cannot overstate what the slashed bond repays.
pub const REPAYMENT_HAIRCUT_BPS: u128 = 5_000;
/// The public blind every node commits a PUBLIC amount of the repayment under (`public_amount_commit`).
pub const THEFT_PUBLIC_BLIND: crate::spend_frontier::Digest4 =
    usdm_decider::poseidon2_compress::lanes_of_const(&[0x7573_646d_7468_6566, 0x7075_626c_6963_626c]);

/// The solvency commitment of a PUBLIC amount under the protocol's public blind — what every node recomputes for the
/// repayment's public legs (the loss, the buffer's retire, case A's pool burn, case B's remainder).
#[must_use]
pub fn public_amount_commit(v: u128) -> crate::spend_frontier::Digest4 {
    usdm_decider::confidential_solvency::solvency_commit_256(u256_from_u128(v), THEFT_PUBLIC_BLIND)
}

/// ⭐ THE LADDER'S SPLIT — `[L, V1, B, rest]` in USDm atomic for a theft of `loss_sats` at the BTC TWAP `btc_twap` (USDm-atomic
/// per sat × `PRICE_SCALE`), the pot of `pot_sat` SAT-atomic valued at `sat_floor` (or nothing while SAT is unpriced) and the
/// surplus buffer `buffer`: `L = loss × twap`, `V1 = min(pot × floor, L)`, `B = min(buffer, L − V1)`, `rest = L − V1 − B`.
/// Pure, so every node computes the same split; `None` when `L` does not fit a u64 (refused, never wrapped).
#[must_use]
pub fn theft_split(loss_sats: u64, btc_twap: u128, sat_floor: Option<u128>, pot_sat: u64, buffer: u64) -> Option<[u64; 4]> {
    let l = u64::try_from(u128::from(loss_sats).checked_mul(btc_twap)? / crate::liquidation::PRICE_SCALE).ok()?;
    let v1_full = sat_floor.map_or(0u128, |f| u128::from(pot_sat).saturating_mul(f) / crate::liquidation::PRICE_SCALE);
    let v1 = u64::try_from(v1_full.min(u128::from(l))).ok()?;
    let b = buffer.min(l - v1);
    Some([l, v1, b, l - v1 - b])
}

/// The plan of one repayment from a custodian's opening: every amount, every blind, the commitments it carries and the
/// opening after. Deterministic in the opening and the split, so every custodian holding the opening derives the same one.
#[derive(Clone, Debug)]
pub struct TheftRepayPlan {
    pub loss_sats: u64,
    pub split: [u64; 4],
    /// The pool's burn `C` (= `min(T, rest)`).
    pub c: u128,
    pub remainder: u64,
    pub case_a: bool,
    /// `[new_reserve, mid_minted, DC, new_T, P', S', new_minted]` blinds.
    pub blinds: [crate::spend_frontier::Digest4; 7],
    pub p_new: usdm_decider::confidential_solvency::U256,
    pub s_new: usdm_decider::confidential_solvency::U256,
    pub close: bool,
    pub after: LiquidationOpening,
}

pub fn theft_repay_blind(seed: &[u8; 32], i: u8) -> crate::spend_frontier::Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/theft-repay/blind/v1");
    h.update(seed);
    h.update(&[i]);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

/// Plan the repayment of `loss_sats` under `split` from opening `o` (the native PSM and its pool). `None` when the opening
/// cannot pay it (the reserve below the loss, the supply below a retire) — the door would refuse such an object anyway.
#[must_use]
pub fn plan_theft_repayment(o: &LiquidationOpening, split: [u64; 4], loss_sats: u64) -> Option<TheftRepayPlan> {
    use usdm_decider::confidential_solvency as cs;
    let [_, _, b, rest] = split;
    let mut pre = liquidation_seed(o).to_vec();
    pre.extend_from_slice(&loss_sats.to_le_bytes());
    for w in split {
        pre.extend_from_slice(&w.to_le_bytes());
    }
    let seed = *blake3::hash(&pre).as_bytes();
    let mut bl: [crate::spend_frontier::Digest4; 7] = core::array::from_fn(|i| theft_repay_blind(&seed, i as u8));
    let new_r = o.reserve.checked_sub(u128::from(loss_sats))?;
    let mid = o.minted.checked_sub(u128::from(b))?;
    if b == 0 {
        bl[1] = o.minted_blind; // no buffer retire: the mid supply IS the current supply
    }
    let (c, case_a) = if rest == 0 { (0u128, true) } else { (o.pool_t.min(u128::from(rest)), o.pool_t >= u128::from(rest)) };
    let remainder = u64::try_from(u128::from(rest) - c).ok()?;
    if rest > 0 && (case_a || c == 0) {
        bl[2] = THEFT_PUBLIC_BLIND; // case A: DC = Pub(C); an empty pool: DC = Pub(0)
    }
    if rest > 0 && !case_a {
        bl[3] = THEFT_PUBLIC_BLIND; // case B: the pool is exhausted, new_T = Pub(0)
    }
    let new_t = o.pool_t - c;
    let (p_new, s_new, close) = if c > 0 {
        cs::pool_step(u256_from_u128(o.pool_t), u256_from_u128(c), u256_from_u128(0), o.pool_p, o.pool_s)?
    } else {
        (o.pool_p, o.pool_s, false)
    };
    let new_m = mid.checked_sub(c)?;
    if rest == 0 {
        bl[6] = bl[1]; // no pool layer: the supply after is the mid supply
    }
    let (p_after, p_blind, s_after, s_blind) = if close {
        (POOL_P_SCALE, GENESIS_POOL_P_BLIND, [0; 4], GENESIS_POOL_S_BLIND)
    } else if c > 0 {
        (p_new, bl[4], s_new, bl[5])
    } else {
        (o.pool_p, o.pool_p_blind, o.pool_s, o.pool_s_blind)
    };
    let after = LiquidationOpening {
        reserve: new_r,
        reserve_blind: bl[0],
        minted: new_m,
        minted_blind: bl[6],
        pool_t: new_t,
        pool_t_blind: if rest == 0 { o.pool_t_blind } else { bl[3] },
        pool_p: p_after,
        pool_p_blind: p_blind,
        pool_s: s_after,
        pool_s_blind: s_blind,
    };
    Some(TheftRepayPlan { loss_sats, split, c, remainder, case_a, blinds: bl, p_new, s_new, close, after })
}

impl TheftRepayPlan {
    /// The commitments the header carries: `[DC, new_reserve, mid_minted, new_minted, new_T, P', S']` (the pool's words are
    /// the current ones when no pool layer runs).
    #[must_use]
    pub fn commits(&self, o: &LiquidationOpening, pool: &PoolWords) -> [crate::spend_frontier::Digest4; 7] {
        use usdm_decider::confidential_solvency::solvency_commit_256;
        let b = &self.blinds;
        let [_, _, buf, rest] = self.split;
        let pooled = rest > 0;
        [
            if pooled { solvency_commit_256(u256_from_u128(self.c), b[2]) } else { [0; usdm_decider::poseidon2_compress::DIGEST_LANES] },
            solvency_commit_256(u256_from_u128(self.after.reserve), b[0]),
            solvency_commit_256(u256_from_u128(o.minted - u128::from(buf)), b[1]),
            solvency_commit_256(u256_from_u128(self.after.minted), b[6]),
            if pooled { solvency_commit_256(u256_from_u128(self.after.pool_t), b[3]) } else { pool.t },
            if self.c > 0 { solvency_commit_256(self.p_new, b[4]) } else { pool.p },
            if self.c > 0 { solvency_commit_256(self.s_new, b[5]) } else { pool.s },
        ]
    }
}

/// PROVE the legs of a planned repayment (the executing custodian, off the node lock). `None` if any leg is unprovable.
#[must_use]
pub fn build_theft_repayment_legs(o: &LiquidationOpening, plan: &TheftRepayPlan) -> Option<crate::theft_repayment_tx::TheftRepaymentLegs> {
    use usdm_decider::confidential_solvency as cs;
    let b = &plan.blinds;
    let [_, _, buf, rest] = plan.split;
    let pb = THEFT_PUBLIC_BLIND;
    let (seize, _) = cs::prove_transition_carrier(
        u256_from_u128(plan.after.reserve),
        u256_from_u128(u128::from(plan.loss_sats)),
        &[b[0], pb, o.reserve_blind],
        cs::TransitionDomain::Seize,
    )?;
    let mid = o.minted - u128::from(buf);
    let retire_buffer = if buf > 0 {
        cs::prove_transition_carrier(u256_from_u128(mid), u256_from_u128(u128::from(buf)), &[b[1], pb, o.minted_blind], cs::TransitionDomain::Retire)?.0
    } else {
        Vec::new()
    };
    let mut legs = crate::theft_repayment_tx::TheftRepaymentLegs { seize, retire_buffer, ..Default::default() };
    if rest > 0 {
        let c = u256_from_u128(plan.c);
        legs.pool_transition =
            cs::prove_transition_carrier(u256_from_u128(o.pool_t - plan.c), c, &[b[3], b[2], o.pool_t_blind], cs::TransitionDomain::StabilityPool)?.0;
        if plan.c > 0 {
            legs.pool_step = cs::prove_pool_step_carrier(&cs::PoolStepOpening {
                t: u256_from_u128(o.pool_t),
                c,
                s_c: u256_from_u128(0),
                p_old: o.pool_p,
                s_old: o.pool_s,
                blinds: [o.pool_t_blind, b[2], pb, o.pool_p_blind, b[4], o.pool_s_blind, b[5]],
            })?
            .bytes;
        }
        legs.retire_pool = cs::prove_transition_carrier(u256_from_u128(mid - plan.c), c, &[b[6], b[2], b[1]], cs::TransitionDomain::Retire)?.0;
        if plan.remainder > 0 {
            legs.remainder = cs::prove_transition_carrier(
                u256_from_u128(u128::from(plan.remainder)),
                c,
                &[pb, b[2], pb],
                cs::TransitionDomain::Retire,
            )?
            .0;
        }
    }
    Some(legs)
}

impl PegLedger {
    /// ⭐ §BR-3 17.5 layer 1 — a theft's slash folds: the slashed SAT moves into the repayment pot (always), and the loss is
    /// booked for the ladder ONCE per theft (`key`: `theft_tx::theft_loss_key`, recorded in the one-time set). `false` when the
    /// loss was already booked or would pass its u64 bound (the slash itself stands either way).
    pub fn book_theft(&mut self, slashed: u128, loss_sats: u64, key: &[u8; 32]) -> bool {
        self.repayment_sat_pot = u64::try_from(u128::from(self.repayment_sat_pot).saturating_add(slashed)).unwrap_or(u64::MAX);
        if self.liquidated.contains(key) {
            return false;
        }
        match self.theft_loss_open_sats.checked_add(loss_sats) {
            Some(v) => {
                self.theft_loss_open_sats = v;
                self.liquidated.insert(*key);
                true
            }
            None => false,
        }
    }

    /// `[pot SAT, open loss sats, owed USDm, haircut remainder USDm, haircut events]` — node-internal chain state.
    #[must_use]
    pub fn theft_repay_words(&self) -> [u64; 5] {
        [self.repayment_sat_pot, self.theft_loss_open_sats, self.repayment_owed_atomic, self.haircut_remainder_atomic, self.haircut_events]
    }

    /// The pot's floor price: `min(twap7, low30)(SAT) × haircut`; `None` while SAT is unpriced (the pot then books nothing).
    #[must_use]
    pub fn repayment_sat_floor(&self) -> Option<u128> {
        let (a, b) = (self.twap7(SAT_PRICE_ASSET_ID)?, self.low30(SAT_PRICE_ASSET_ID)?);
        Some(a.min(b) * REPAYMENT_HAIRCUT_BPS / 10_000)
    }

    /// The split of repaying `loss_sats` NOW, from this ledger's words. `None` while BTC is unpriced.
    #[must_use]
    pub fn theft_split_now(&self, loss_sats: u64) -> Option<[u64; 4]> {
        theft_split(loss_sats, self.twap7(NATIVE_PEG_ASSET_ID)?, self.repayment_sat_floor(), self.repayment_sat_pot, self.fee_pool_surplus)
    }

    /// The one-time id of a repayment of the current state: the reserve, the supply, the pool and the open loss — so the same
    /// bytes never repay twice, and a stale object (the state moved) names an id the door no longer forms.
    #[must_use]
    pub fn theft_repay_id(&self) -> [u8; 32] {
        let pool = self.pool_words(NATIVE_PEG_ASSET_ID);
        let mut h = blake3::Hasher::new_derive_key("MUSD/theft-repay-id/v1");
        for d in [self.reserve_commit, self.minted_commit, pool.t, pool.p, pool.s] {
            h.update(&crate::spend_frontier::digest_to_lane_bytes(&d));
        }
        h.update(&self.theft_loss_open_sats.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// The message every bonded custodian signs for `h` over THIS ledger's state (formed here only, never read from a wire).
    #[must_use]
    pub fn theft_repay_attest_msg(&self, h: &crate::theft_repayment_tx::TheftRepaymentHeader) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.theft-repay.v1");
        m.extend_from_slice(&postcard::to_stdvec(h).unwrap_or_default());
        m.extend_from_slice(&self.theft_repay_id());
        m
    }

    /// ⭐ VERIFY the repayment's legs against THIS ledger (the one verification site). The public amounts are recomputed
    /// here (`theft_split_now`), every commitment a leg is checked against that the object does not carry is read here.
    #[must_use]
    pub fn verify_theft_repayment_legs(
        &self,
        h: &crate::theft_repayment_tx::TheftRepaymentHeader,
        legs: &crate::theft_repayment_tx::TheftRepaymentLegs,
    ) -> bool {
        use usdm_decider::confidential_solvency as cs;
        if h.loss_sats == 0 || h.loss_sats > self.theft_loss_open_sats || h.repay_id != self.theft_repay_id() {
            return false;
        }
        let Some(split) = self.theft_split_now(h.loss_sats) else { return false };
        if split != h.split {
            return false;
        }
        let [_, _, b, rest] = split;
        let (reserve, minted, pool) = (self.reserve_commit, self.minted_commit, self.pool_words(NATIVE_PEG_ASSET_ID));
        let pubc = |v: u64| public_amount_commit(u128::from(v));
        if !cs::verify_transition_carrier(&legs.seize, &[h.new_reserve_commit, pubc(h.loss_sats), reserve], cs::TransitionDomain::Seize) {
            return false;
        }
        let buffer_ok = if b > 0 {
            cs::verify_transition_carrier(&legs.retire_buffer, &[h.mid_minted_commit, pubc(b), minted], cs::TransitionDomain::Retire)
        } else {
            legs.retire_buffer.is_empty() && h.mid_minted_commit == minted
        };
        if !buffer_ok {
            return false;
        }
        if rest == 0 {
            return legs.pool_transition.is_empty()
                && legs.pool_step.is_empty()
                && legs.retire_pool.is_empty()
                && legs.remainder.is_empty()
                && h.new_minted_commit == h.mid_minted_commit
                && (h.new_pool_t, h.new_pool_p, h.new_pool_s) == (pool.t, pool.p, pool.s)
                && !h.pool_close
                && h.pool_c == 0
                && h.remainder == 0;
        }
        let dc = h.pool_retired_commit;
        if !cs::verify_transition_carrier(&legs.pool_transition, &[h.new_pool_t, dc, pool.t], cs::TransitionDomain::StabilityPool)
            || !cs::verify_transition_carrier(&legs.retire_pool, &[h.new_minted_commit, dc, h.mid_minted_commit], cs::TransitionDomain::Retire)
        {
            return false;
        }
        // the depositors' product and sum move by the burn (no collateral reaches the pool); an empty pool's burn is Pub(0)
        let step_ok = if dc == pubc(0) {
            legs.pool_step.is_empty() && (h.new_pool_p, h.new_pool_s) == (pool.p, pool.s) && !h.pool_close
        } else {
            cs::verify_pool_step_carrier(&legs.pool_step, &[pool.t, dc, pubc(0), pool.p, h.new_pool_p, pool.s, h.new_pool_s], h.pool_close)
        };
        if !step_ok {
            return false;
        }
        if h.remainder == 0 {
            // case A: the pool covers the rest — the burn is the public rest; the pool's size stays hidden (T ≥ C proven)
            h.pool_c == rest && dc == pubc(rest) && legs.remainder.is_empty()
        } else {
            // case B: the pool is exhausted (new_T = Pub(0)) and the remainder is the rest less the hidden burn
            h.pool_c == 0
                && h.remainder <= rest
                && h.new_pool_t == pubc(0)
                && cs::verify_transition_carrier(&legs.remainder, &[pubc(h.remainder), dc, pubc(rest)], cs::TransitionDomain::Retire)
        }
    }

    /// ⭐⭐⭐ THE THEFT REPAYMENT DOOR. §9.6: (1) PoW — n/a (a framed object; its block passed the header gate); (2) the ≥2/3
    /// bonded ML-DSA tally over `theft_repay_attest_msg` AND every leg re-verified against this node's own commitments;
    /// (3) conservation — the seize leg books exactly the attested loss out of the reserve, the buffer retire and the pool
    /// burn take USDm out of circulation that real holders (the protocol's surplus, the pool's depositors) gave up, and the
    /// split is recomputed here, so nothing is created; (4) replay — the `repay_id` (a function of the moved state) in the
    /// one-time set and as the object's own nullifier; (5) bounded — decode's constant caps, one tally, ≤ 6 fixed-shape
    /// verifies; (6) parity with the liquidation door — same tally, same pool-word advance (a drain closes the epoch), same
    /// one-time set, plus a seize leg of a PUBLIC amount. Fail-closed: a refusal mutates nothing.
    pub fn repay_theft_confidential(
        &mut self,
        h: &crate::theft_repayment_tx::TheftRepaymentHeader,
        legs: &crate::theft_repayment_tx::TheftRepaymentLegs,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
        attestors: &[MintAttestor],
    ) -> PegOutcome {
        let key = h.repay_id;
        if self.liquidated.contains(&key) {
            return PegOutcome::Replay;
        }
        let msg = self.theft_repay_attest_msg(h);
        if !threshold_ok(quorum, verifier, &msg, attestors) {
            return PegOutcome::InsufficientThreshold;
        }
        if !self.verify_theft_repayment_legs(h, legs) {
            return PegOutcome::BadRequest;
        }
        let [_, v1, b, rest] = h.split;
        let (Some(surplus), Some(open), Some(owed)) = (
            self.fee_pool_surplus.checked_sub(b),
            self.theft_loss_open_sats.checked_sub(h.loss_sats),
            self.repayment_owed_atomic.checked_add(v1),
        ) else {
            return PegOutcome::BadRequest;
        };
        let haircut = self.haircut_remainder_atomic.checked_add(h.remainder);
        let Some(haircut) = haircut else { return PegOutcome::BadRequest };
        self.set_psm_commits(NATIVE_PEG_ASSET_ID, h.new_reserve_commit, h.new_minted_commit);
        if rest > 0 {
            let pool = self.pool_words(NATIVE_PEG_ASSET_ID);
            let moved = PoolWords { t: h.new_pool_t, p: h.new_pool_p, s: h.new_pool_s, epoch: pool.epoch };
            if h.pool_close {
                self.pool_closes.insert((NATIVE_PEG_ASSET_ID, pool.epoch), moved);
                let fresh = PoolWords::genesis();
                self.set_pool_words(NATIVE_PEG_ASSET_ID, PoolWords { t: h.new_pool_t, p: fresh.p, s: fresh.s, epoch: pool.epoch + 1 });
            } else {
                self.set_pool_words(NATIVE_PEG_ASSET_ID, moved);
            }
        }
        self.fee_pool_surplus = surplus;
        self.theft_loss_open_sats = open;
        self.repayment_owed_atomic = owed;
        if h.remainder > 0 {
            self.haircut_remainder_atomic = haircut;
            self.haircut_events = self.haircut_events.saturating_add(1);
        }
        self.liquidated.insert(key);
        self.applied_ids.push((key, ONE_TIME_THEFT_REPAY));
        PegOutcome::TheftRepaid
    }
}

impl PegLedger {
    /// ⭐ §BR-3 17.5 layer 1 realized — the message every bonded custodian signs for a pot fill: the request, the supply
    /// now and the supply after the retire (formed here only).
    #[must_use]
    pub fn pot_fill_msg(&self, request_digest: &[u8; 32], new_minted: &crate::spend_frontier::Digest4) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.pot-fill.v1");
        m.extend_from_slice(request_digest);
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&self.minted_commit));
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(new_minted));
        m
    }

    /// The fill's price rule at THIS ledger: the pot holds `s` and `s` SAT costs at least `x` USDm at the floor
    /// (`s × floor ≤ x × PRICE_SCALE`). `false` while SAT is unpriced (the pot is not offered).
    #[must_use]
    pub fn pot_fill_price_ok(&self, x: u64, s: u64) -> bool {
        let Some(floor) = self.repayment_sat_floor().filter(|f| *f > 0) else { return false };
        s <= self.repayment_sat_pot && u128::from(s).saturating_mul(floor) <= u128::from(x).saturating_mul(crate::liquidation::PRICE_SCALE)
    }

    /// ⭐⭐ THE POT FILL DOOR (the custody half; the node checked the buyer's carriers and membership first). §9.6 on
    /// `pot_fill_tx`: the price rule, the ≥ 2/3 tally over `pot_fill_msg`, the retire leg `[new_minted, Pub(X), minted]`;
    /// then the supply retires `X`, the pot gives `S`, and the owed falls by `min(X, owed)`. Fail-closed: a refusal moves
    /// nothing.
    pub fn pot_fill_door(
        &mut self,
        t: &crate::pot_fill_tx::PotFillTx,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> Result<(), &'static str> {
        use usdm_decider::confidential_solvency as cs;
        if !self.pot_fill_price_ok(t.burn_usdm, t.sat_out) {
            return Err("the fill takes more SAT than the pot holds or pays under the floor");
        }
        let msg = self.pot_fill_msg(&t.request_digest(), &t.new_minted_commit);
        if !threshold_ok(quorum, verifier, &msg, &t.attestors_list()) {
            return Err("no ≥2/3 of the bonded weight signs this fill's retire");
        }
        if !cs::verify_transition_carrier(
            &t.retire_leg,
            &[t.new_minted_commit, public_amount_commit(u128::from(t.burn_usdm)), self.minted_commit],
            cs::TransitionDomain::Retire,
        ) {
            return Err("the retire leg does not take exactly the burned USDm out of the supply");
        }
        let reserve = self.reserve_commit;
        self.set_psm_commits(NATIVE_PEG_ASSET_ID, reserve, t.new_minted_commit);
        self.repayment_sat_pot -= t.sat_out;
        self.repayment_owed_atomic = self.repayment_owed_atomic.saturating_sub(t.burn_usdm);
        Ok(())
    }
}

impl PegLedger {
    /// ⭐ §BR-4 B4-3 — the message ≥ 2/3 of custody signs over a unit close: the request, and both transitions from THIS ledger's
    /// commitments.
    #[must_use]
    pub fn unit_close_msg(
        &self,
        request_digest: &[u8; 32],
        new_minted: &crate::spend_frontier::Digest4,
        new_reserve: &crate::spend_frontier::Digest4,
    ) -> Vec<u8> {
        let mut m = crate::pqauth::node_statement(b"musdm.peg.unit-close.v1");
        m.extend_from_slice(request_digest);
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&self.minted_commit));
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(new_minted));
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&self.reserve_commit));
        m.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(new_reserve));
        m
    }

    /// ⭐⭐ §BR-4 B4-3 — THE LEDGER'S HALF OF A UNIT CLOSE (the node has verified the burns and their memberships): the day's
    /// exact debt, the tally, both legs against THIS ledger, then every move. Returns the close's terms. Nothing moves on a
    /// refusal.
    pub fn unit_close_door(
        &mut self,
        t: &crate::unit_close_tx::UnitCloseTx,
        today: u64,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> Result<crate::debt_units::CloseTerms, &'static str> {
        use usdm_decider::confidential_solvency as cs;
        let ct = self.unit_book.close_terms(&t.terms, today).ok_or("the unit's terms do not close on this day")?;
        if ct.sats == 0 {
            return Err("the unit's band was liquidated: its collateral went to the reserve and nothing is released");
        }
        if ct.debt_atomic != u128::from(t.debt_atomic) {
            return Err("the burn is not the unit's debt on the carrying block's day");
        }
        let u = t.terms.unit_atomic().ok_or("no such unit size")?;
        let pieces = crate::unit_close_tx::release_pieces(&t.terms).ok_or("the collateral does not split into payout pieces")?;
        let interest = u64::try_from(ct.interest_atomic).map_err(|_| "the interest does not fit")?;
        let digest = t.request_digest().ok_or("the close names no change reference")?;
        let msg = self.unit_close_msg(&digest, &t.new_minted_commit, &t.new_reserve_commit);
        if !threshold_ok(quorum, verifier, &msg, &t.attestors_list()) {
            return Err("no ≥2/3 of the bonded weight signs this close's legs");
        }
        if !cs::verify_transition_carrier(&t.retire_leg, &[t.new_minted_commit, public_amount_commit(u), self.minted_commit], cs::TransitionDomain::Retire) {
            return Err("the retire leg does not take exactly the unit's debt out of the supply");
        }
        if !cs::verify_transition_carrier(&t.release_leg, &[t.new_reserve_commit, public_amount_commit(ct.sats), self.reserve_commit], cs::TransitionDomain::Seize) {
            return Err("the release leg does not take exactly the unit's collateral out of the reserve");
        }
        if self.fee_pool_stakers.checked_add(interest).is_none() {
            return Err("the stakers' pool would overflow");
        }
        let mut book = self.unit_book.clone();
        book.close_unit(&t.terms)?;
        // every check passed: move
        self.unit_book = book;
        self.set_psm_commits(NATIVE_PEG_ASSET_ID, t.new_reserve_commit, t.new_minted_commit);
        self.fee_pool_stakers += interest;
        // the parent key (the ticket's) and each piece's key are owed releases, exactly as a split cash-out's pieces are
        self.spent_burns.insert(t.unit_nullifier);
        for i in 0..pieces.len() {
            self.spent_burns.insert(crate::unit_close_tx::piece_key(&t.unit_nullifier, i));
        }
        Ok(ct)
    }

    /// ⭐ §BR-8 B8-a — a fold step credited `surplus_delta` to the surplus buffer in decoy epoch `epoch`: a later epoch rolls the
    /// budget (`DECOY_FEE_SHARE_BPS` of the closing epoch's credit) and starts a fresh credit.
    pub fn note_decoy_credit(&mut self, epoch: u64, surplus_delta: u64) {
        if epoch.saturating_add(1) > self.decoy_epoch_next {
            self.decoy_budget = self.decoy_credit.saturating_mul(crate::decoy_tx::DECOY_FEE_SHARE_BPS) / 10_000;
            self.decoy_credit = 0;
            self.decoy_spent = 0;
            self.decoy_epoch_next = epoch.saturating_add(1);
        }
        self.decoy_credit = self.decoy_credit.saturating_add(surplus_delta);
    }

    /// What this decoy epoch may still spend on decoy fees (USDm atomic).
    #[must_use]
    pub fn decoy_budget_left(&self) -> u64 {
        self.decoy_budget.saturating_sub(self.decoy_spent)
    }

    /// The open decoy obligations (custody's public decoy outputs).
    #[must_use]
    pub fn open_decoys(&self) -> Vec<crate::decoy_tx::OpenDecoy> {
        self.open_decoys.values().copied().collect()
    }

    /// ⭐⭐ THE DECOY BATCH DOOR. §9.6: (1) PoW — n/a (a framed object); (2) ≥ 2/3 of bonded custody over the batch statement and
    /// every decoy naming a bonded validator; (3) value — moves no supply: the batch's decoy fees come out of the epoch's budget
    /// and the surplus buffer (the protocol's own fees, never the reserve's principal), the decoys become obligations; (4)
    /// replay — the payout's id is the object's own nullifier, and a booked outpoint is never booked twice; (5) bounded — ≤
    /// BATCH_MAX decoys, the open map past its bound by at most one batch; (6) parity with the liquidation and bounty doors (the
    /// custody tally). A batch is booked even past the budget (the decoys already exist on Bitcoin; their obligations must be
    /// tracked): the spent word saturates at the budget and the buffer pays at most what it holds.
    pub fn decoy_batch_door(
        &mut self,
        t: &crate::decoy_tx::DecoyBatchTx,
        // the carrying block's CHAIN TICK (`Node::chain_tick_at`): the decoy's return deadline is a time (A-F60's class)
        carrying_tick: u64,
        quorum: &dyn BondQuorum,
        verifier: &dyn PqVerifier,
    ) -> Result<(), &'static str> {
        let msg = crate::decoy_tx::DecoyBatchTx::statement(&t.payout_txid, &t.decoys, t.fee_usdm);
        if !threshold_ok(quorum, verifier, &msg, &t.attestors_list()) {
            return Err("no ≥2/3 of the bonded weight signs this decoy batch");
        }
        if t.decoys.iter().any(|d| quorum.bond_of(&d.vid) == 0) {
            return Err("a decoy names a validator with no bond");
        }
        if self.open_decoys.len() + t.decoys.len() > crate::decoy_tx::DECOY_OPEN_MAX + crate::peg_pool::BATCH_MAX {
            return Err("the open decoys are past their bound");
        }
        if t.decoys.iter().any(|d| self.open_decoys.contains_key(&crate::decoy_tx::decoy_key(&t.payout_txid, d.vout))) {
            return Err("a decoy outpoint is already booked");
        }
        let pay = t.fee_usdm.min(self.fee_pool_surplus);
        self.fee_pool_surplus -= pay;
        self.decoy_spent = self.decoy_spent.saturating_add(t.fee_usdm).min(self.decoy_budget.max(self.decoy_spent));
        for d in &t.decoys {
            self.open_decoys.insert(
                crate::decoy_tx::decoy_key(&t.payout_txid, d.vout),
                crate::decoy_tx::OpenDecoy { vid: d.vid, sats: d.sats, txid: t.payout_txid, vout: d.vout, due_tick: carrying_tick.saturating_add(crate::decoy_tx::DECOY_RETURN_TICKS) },
            );
        }
        Ok(())
    }

    /// ⭐ THE DECOY RETURN DOOR: ≥ 2/3 of custody attest the decoy came back to the reserve; the obligation closes.
    pub fn decoy_return_door(&mut self, t: &crate::decoy_tx::DecoyReturnTx, quorum: &dyn BondQuorum, verifier: &dyn PqVerifier) -> Result<(), &'static str> {
        let key = crate::decoy_tx::decoy_key(&t.txid, t.vout);
        if !self.open_decoys.contains_key(&key) {
            return Err("no open decoy at this outpoint");
        }
        let msg = crate::decoy_tx::DecoyReturnTx::statement(&t.txid, t.vout, &t.return_txid);
        if !threshold_ok(quorum, verifier, &msg, &t.attestors_list()) {
            return Err("no ≥2/3 of the bonded weight attests this return");
        }
        self.open_decoys.remove(&key);
        Ok(())
    }

    /// §BR-8: a theft certificate naming an unreturned decoy (`decoy_tx::decoy_theft_statement`) closes its obligation — the
    /// slash and the §BR-3 17.5 repayment take its place. Only a certificate that names the decoy's OWN validator among its
    /// offenders closes it (a certificate slashing someone else leaves the obligation open on its holder).
    pub fn close_decoy_by_theft(&mut self, statement: &[u8], offenders: &[[u8; 32]]) {
        let hit = self
            .open_decoys
            .iter()
            .find(|(_, d)| crate::decoy_tx::decoy_theft_statement(&d.txid, d.vout) == statement && offenders.contains(&d.vid))
            .map(|(k, _)| *k);
        if let Some(k) = hit {
            self.open_decoys.remove(&k);
        }
    }
}

/// §BR-4 B4-3 — the two blinds a close's legs advance to: every custodian holding the opening derives the same pair, so they sign
/// one transition. `(minted blind, reserve blind)`.
#[must_use]
pub fn unit_close_blinds(o: &LiquidationOpening, request_digest: &[u8; 32]) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
    let leg = |domain: &str| {
        let mut h = blake3::Hasher::new_derive_key(domain);
        h.update(&liquidation_seed(o));
        h.update(request_digest);
        crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
    };
    (leg("MUSD/unit-close/minted-blind/v1"), leg("MUSD/unit-close/reserve-blind/v1"))
}

/// The blind of a pot fill's new supply commitment, derived from the custodians' secret opening and the request — every
/// custodian holding the opening derives the same one.
#[must_use]
pub fn pot_fill_blind(o: &LiquidationOpening, request_digest: &[u8; 32]) -> crate::spend_frontier::Digest4 {
    let mut h = blake3::Hasher::new_derive_key("MUSD/pot-fill/blind/v1");
    h.update(&liquidation_seed(o));
    h.update(request_digest);
    crate::spend_frontier::cm_bytes_to_leaf(h.finalize().as_bytes())
}

#[cfg(all(test, feature = "pins-core"))]
mod af69_stale_mark_tests {
    use super::*;

    /// ⭐⭐ A-F69 — A MINT IS HELD WHILE ITS LEDGER'S MARK MISSES A WHOLE PRICE EPOCH, AND NOTHING ELSE IS.
    /// Bitcoin's mark stands at epoch 10: fresh in epochs 10 and 11 (the mark of the epoch just closed may still be
    /// travelling), stale from 12. Monero's ledger and a vault's Bitcoin ledger read their own asset's mark the same way. A coin
    /// ledger and a wrapped asset read no price, so they are never held; an asset with no mark is not "stale" (it has no
    /// backing at all, refused at every door already). The redemption read, `reference_price`, is unchanged by staleness: a
    /// holder is priced at the last accepted mark.
    #[test]
    fn af69_a_mint_on_a_stale_mark_is_held_and_redemption_still_prices() {
        let mut p = PegLedger::new(15_000);
        assert!(!p.mint_price_stale(NATIVE_PEG_ASSET_ID, 50), "no mark: nothing to call stale (no backing at all)");
        p.set_price_mark_for_test(NATIVE_PEG_ASSET_ID, 5 * crate::liquidation::PRICE_SCALE, 10);
        p.set_price_mark_for_test(XMR_PEG_ASSET_ID, 3 * crate::liquidation::PRICE_SCALE, 10);
        for (epoch, stale) in [(0u64, false), (10, false), (11, false), (12, true), (500, true)] {
            assert_eq!(p.mint_price_stale(NATIVE_PEG_ASSET_ID, epoch), stale, "Bitcoin's mark at epoch 10, chain at {epoch}");
            assert_eq!(p.mint_price_stale(XMR_PEG_ASSET_ID, epoch), stale, "Monero's mark at epoch 10, chain at {epoch}");
            assert_eq!(p.mint_price_stale(vault_ledger(1, NATIVE_PEG_ASSET_ID), epoch), stale, "a vault's Bitcoin ledger reads Bitcoin's mark");
            assert!(!p.mint_price_stale(COIN_BTC_ASSET_ID, epoch), "a coin ledger is one atom for one atom: never held");
        }
        assert!(!p.mint_price_stale(u32::MAX, u64::MAX), "a malformed ledger id names no priced ledger");
        assert!(p.mint_price_stale(NATIVE_PEG_ASSET_ID, u64::MAX), "the last epoch the chain can name is past any mark: no overflow");
        p.set_price_mark_for_test(COIN_XMR_ASSET_ID, 1, u64::MAX);
        assert!(!p.mint_price_stale(NATIVE_PEG_ASSET_ID, 9), "a chain behind its mark (a jumped node) is not stale");
        // redemption reads the last mark however old it is
        assert_eq!(p.reference_price(NATIVE_PEG_ASSET_ID), Some(5 * crate::liquidation::PRICE_SCALE), "the standing mark prices a redemption");
        // the next epoch's mark lifts the hold at once
        p.set_price_mark_for_test(NATIVE_PEG_ASSET_ID, 4 * crate::liquidation::PRICE_SCALE, 499);
        assert!(!p.mint_price_stale(NATIVE_PEG_ASSET_ID, 500), "a mark of the epoch just closed is fresh");
        assert!(p.mint_price_stale(XMR_PEG_ASSET_ID, 500), "one asset's mark never freshens another's");
    }
}

#[cfg(test)]
mod theft_split_tests {
    use super::*;

    /// The split conserves the loss exactly at every size, and each layer is capped by what it holds (the Kani harness
    /// below proves it for every input).
    #[test]
    fn the_theft_split_conserves_the_loss_and_caps_every_layer() {
        let btc = 70_000 * crate::liquidation::PRICE_SCALE / 1_000; // 70 USDm-atomic per sat × scale … any price
        for (loss, pot, floor, buf) in [(100_000_000u64, 0u64, None, 0u64), (100_000_000, 10_000_000_000, Some(500_000), 1_000_000), (1, u64::MAX, Some(u128::MAX >> 64), u64::MAX), (5_000, 7, Some(3), 2)] {
            let [l, v1, b, rest] = theft_split(loss, btc, floor, pot, buf).unwrap();
            assert_eq!(v1 + b + rest, l, "the layers sum to the loss");
            assert!(b <= buf && v1 <= l, "each layer within what it holds");
            if floor.is_none() {
                assert_eq!(v1, 0, "an unpriced pot books nothing");
            }
        }
        assert!(theft_split(u64::MAX, u128::MAX, None, 0, 0).is_none(), "a loss past the u64 bound is refused, never wrapped");
    }
}

#[cfg(kani)]
mod theft_split_kani {
    /// Kani: for every theft, price, pot, floor and buffer the four layers sum to the loss and each is within its cap.
    #[kani::proof]
    fn theft_split_conserves() {
        let (loss, pot, buf): (u64, u64, u64) = (kani::any(), kani::any(), kani::any());
        let (twap, floor): (u64, u64) = (kani::any(), kani::any());
        if let Some([l, v1, b, rest]) = super::theft_split(loss, u128::from(twap), Some(u128::from(floor)), pot, buf) {
            assert!(u128::from(v1) + u128::from(b) + u128::from(rest) == u128::from(l));
            assert!(b <= buf && v1 <= l);
        }
    }
}
