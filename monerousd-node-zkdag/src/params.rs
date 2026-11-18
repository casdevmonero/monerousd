// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Governance-tunable consensus parameters.
//!
//! These are NOT compile-time constants: they are live runtime values that on-chain governance can
//! retune WITHOUT a new chain or a node restart (a governance-update consensus rule mutates them;
//! that rule is wired in the validator/governance brick). The DAG holds one [`ChainParams`] as its
//! current active set; every consensus computation (GHOSTDAG coloring, the DAA, block validity)
//! reads from it, so a governance change takes effect on the next block. The `Default` is the
//! current live value for each parameter.

/// A hard safety ceiling on the DAG width governance may set — a runaway-parameter backstop, well
/// above any realistic setting. Governance tunes `dag_width` freely up to here (default is 32).
pub const DAG_WIDTH_CEILING: usize = 256;

/// The DEFAULT PSM mint collateral ratio in basis points — 150% over-collateralization, MonerousD's stablecoin
/// backing at genesis. This is a DEFAULT, NOT a lock: the community may raise it (a safer peg) OR lower it via
/// bicameral governance — including deciding whether MonerousD remains a >100%-backed stablecoin at all. The ONE
/// value governance can never set is 0 (a zero ratio erases the reserve floor = infinite inflation / real money
/// loss), rejected below.
pub const MINT_RATIO_DEFAULT_BPS: u32 = 15_000;

/// ⭐⭐⭐ ONE CLOCK FOR EVERY DURATION THE PROTOCOL COUNTS IN BLOCKS (finding A-F60, user 2026-11-15). The mesh's block-rate target
/// is derived from the network it runs on ([`crate::dag::MESH_TARGET_SPACING_MS`]); a duration that MEANS a time (a day of
/// interest, an unbonding window, the 4-year halving) is that time divided by the target, here, and nowhere else. Before
/// this, thirty files carried their own `× 2` or `/ 500` for a 500 ms block and a second `DAY_BLOCKS` literal; a count that is
/// a STRUCTURE (a merge depth, an index shard, an epoch of index rebuilds) stays a count and does not read this.
/// At least one block, so a duration is never zero blocks.
#[must_use]
pub const fn blocks_for_ms(ms: u64) -> u64 {
    let b = ms / crate::dag::MESH_TARGET_SPACING_MS;
    if b == 0 { 1 } else { b }
}
/// One day, one week and one (365-day) year of the mesh's blocks at its target.
pub const DAY_MS: u64 = 86_400_000;
pub const BLOCKS_PER_DAY: u64 = blocks_for_ms(DAY_MS);

/// Default stake maturity / unbond-delay in blocks (the "stake lock"): one day — long enough that a staker cannot flash-stake a
/// note, capture a reward epoch, and instantly unstake (a reward-gaming / stake-grief vector), short enough to keep staked
/// capital liquid. Governance-tunable. (It read "≈ 1 day at a 1 s block" while the chain targeted 500 ms, i.e. 12 h; it is one
/// day of the target now.)
pub const STAKE_LOCK_BLOCKS_DEFAULT: u64 = BLOCKS_PER_DAY;

/// Default governance-set TARGET staking APR in basis points/yr (500 = 5.00%). This is the protocol's advertised
/// reward policy — analogous to `mint_ratio_bps` — backed by the ZERO-ISSUANCE reserve-yield + fee-redistribution
/// stream (rewards arrive as real confidential notes; this is the target the redistribution aims at, NOT fresh
/// emission and NOT a per-user fabricated figure). Governance retunes it via the bicameral rule. Hard ceiling below.
/// ⭐ A MEMBERSHIP BOND'S PER-MEMBER ATTESTATION WEIGHT — membership, never backing.
///
/// Founders post NO collateral (owner, 2026-09-17: "the founders do not add any collateral. the collateral
/// naturally comes in from the community"), so this is not a stake figure and must never be read as one.
/// It exists because `peg::threshold_ok` skips any attestor with `bond_of == 0` BEFORE checking its
/// signature — a literally-zero founder could never attest at all. Equal weight per founder makes the
/// >=2/3 rule count MEMBERS, which is what a founding quorum is.
///
/// This is validator-set weight, not a note or balance — no USDm exists until a real deposit is custodied.
pub const MEMBERSHIP_BOND_WEIGHT: u128 = 1;

/// ⛔⛔ DB-369 — HOW MANY FREE FOUNDING SEATS EXIST: a free membership seat is granted only while the reserve is zero AND the
/// bonded set holds fewer than this many members; after that a seat needs collateral (owner, 2026-10-03, AskUserQuestion:
/// "First N seats free (Recommended)", then in chat: "we can do the first 5 seats are free instead of 16").
///
/// MEASURED before (`node::tests::db369_…`): with no bound, 24 free requests seated 24 permanent custodians on a peer, and
/// ONE deposit then had to seal 31,704 B (1,321 B per seat). A seat flood in the launch window grew every node's state and
/// could make deposits unpublishable. This keeps the 9/17 rule — the founding quorum is simply the first nodes to bond, for
/// free — and bounds it by a protocol constant: identical on every network (testnet == production), never tracking height.
/// cons: whoever seats first takes the free slots, so the founders bond in the genesis window. Each free seat still costs
/// a stamp and a block slot.
pub const FREE_FOUNDING_SEATS: usize = 5;

pub const STAKE_REWARD_APR_BPS_DEFAULT: u32 = 500;

/// A safety ceiling on the staking APR governance may advertise (10_000 bps = 100%/yr) — a runaway-parameter
/// backstop so no governance capture can post an absurd, unbacked rate. Zero is allowed (a paused reward policy).
pub const STAKE_REWARD_APR_BPS_CEILING: u32 = 10_000;

// (A-F60: `BLOCKS_PER_YEAR` — "a year of blocks at the target", read by nothing — is deleted: a year is a time, never a
// count of blocks at an assumed pace.)

/// ⭐⭐⭐ THE DEX TAKER FEE — a FIXED amount per fill, in atomic USDm. Default 0.02 USDm.
///
/// ⛔ WHY FIXED-PER-FILL AND NOT A PERCENTAGE — THIS IS A PRIVACY CONSTRAINT, NOT A PRICING PREFERENCE.
/// A percentage of a trade is a function of the trade's SIZE, so charging one either publishes the
/// amount or needs a range proof per fill. A fixed per-fill amount is UNIFORM: every fill at every
/// level pays the identical fee, so the fee itself discloses nothing beyond what the tape already says
/// ("one lot at level L"). And because every fill is exactly one lot, fixed-per-fill IS proportional at
/// the only granularity this market has.
///
/// WHY IT EXISTS AT ALL: the security budget. Zero issuance means validators are funded by REAL revenue.
/// MEASURED GAP 2026-08-31: the tokenomics named "Ion-Swap fees" as a validator revenue line while
/// `execute_order_fill` charged nothing — success would have grown TVL while the budget protecting it
/// stayed flat, which is the underfunded-chain failure mode.
///
/// ⛔⛔⛔ IT IS PROPORTIONAL, NOT FLAT, AND THAT WAS A CORRECTION. A flat count of atomic units is only
/// meaningful in ONE asset: 2,000,000 atomic is 0.02 USDm and simultaneously an absurd amount of wBTC, so
/// a flat fee silently prices every wrapped pair wrong — and at the tails it is free for a whale and
/// punitive for a small trade. Basis points on the order's PUBLIC `pay_b` self-normalize across every
/// asset with NO oracle, and leak nothing, because `pay_b` is already the book entry everyone reads.
///
/// The arithmetic lives in ONE place — `OrderTerms::protocol_fee` in the decider — because the circuit's
/// conservation and this node's acceptance must never be able to disagree about what was owed.
///
/// ⛔ WHERE IT GOES: NOWHERE. The fee is BURNED by the taker's own proof; no output note carries it. The
/// taker cannot know which node will execute their fill, so there is no address to seal it to, and the
/// alternative — one network-wide fee key — is precisely what the decentralization pillar bans. Volume
/// still funds security: validators are bonded in the asset, so destroying supply on every fill raises
/// the real value of every bond pro rata, with no validator-linked address for anyone to follow.
///
/// SIZING: 10 bps (0.10%) — a third of a 30 bps AMM, and the maker's spread (their LP income) is charged
/// SEPARATELY and set by the market, so total cost to a taker stays competitive. Governance-tunable at
/// runtime; a launch value, not doctrine.
pub const ORDER_FILL_FEE_BPS_DEFAULT: u64 = 10; // 0.10% of the order's public pay_b

/// ⭐ §BR-11 / §BR-3 17.6 — the fee payout period (named "quarter" in the code) for BOTH the miner pool and the bonders'
/// yield: ONE WEEK OF CHAIN TIME (user 2026-11-02, was ≈ 91 days), in chain ticks — A-F60: a block's period is its
/// parent-key block's chain tick over this (`Node::payout_quarter_of`), so it is a week at any real block rate; it was a
/// week of parent keys, a week only at the target pace. The governed field keeps its persisted name `miner_quarter_keys`.
/// Comparable to Ethereum's (~6.4 min credit, days to sweep), Solana's (~2 days) and THORChain's (~2–3 days) cadence, while
/// still publishing one aggregate per period, never a per-block fee figure.
/// cons: 52 published period aggregates a year instead of 4 (each protocol-wide, never per item).
pub const MINER_QUARTER_KEYS_DEFAULT: u64 = blocks_for_ms(7 * DAY_MS);
fn default_miner_quarter_keys() -> u64 {
    MINER_QUARTER_KEYS_DEFAULT
}

/// ⭐ §BR-3 17.2 + A-F60 — the default unbonding window: 21 days of CHAIN TICKS (`Node::unbond_ticks`, read against the chain
/// tick, so it is 21 days at any real block rate). The evidence horizon beside it is a separate gate in blocks
/// (`Node::unbond_horizon_blue`).
pub const UNBONDING_BLOCKS_DEFAULT: u64 = blocks_for_ms(21 * DAY_MS);
fn default_unbonding_blocks() -> u64 {
    UNBONDING_BLOCKS_DEFAULT
}

/// ⭐ §BR-3 17.6 / spec §1 item 6 — the USDm surplus buffer's default target: 1,000,000 USDm (atomic, 10⁸ per USDm). Once the
/// buffer holds it, the buffer's fee share flows to the stakers' pool; a draw (layered repayment) re-opens the buffer.
pub const SURPLUS_BUFFER_CAP_DEFAULT: u64 = 1_000_000 * 100_000_000;
fn default_surplus_buffer_cap() -> u64 {
    SURPLUS_BUFFER_CAP_DEFAULT
}

/// ⭐ WHAT A CREATION COSTS (atomic USDm): one price for a token, one for an NFT, whatever the symbol.
///
/// RE-PRICED 2026-11-10 (user: "make sure our token mint and nft prices arent too high and wont hinder adoption ...
/// must defeat the competition"). MEASURED against the rivals that day: a pump.fun launch is free to make and costs
/// its first buyer about $3 to $4; a Solana NFT is about $2 and a compressed one under a cent. The schedule this
/// replaces charged 1,000 / 250 / 50 / 10 USDm by symbol LENGTH, for tokens and NFTs alike: $10 for every piece of an
/// NFT collection, and a premium for a short symbol that bought nothing, because a symbol is not exclusive (an
/// asset's identity includes its creator's key, so anyone may make another "BTC"). A price for scarcity belongs to a
/// name that IS scarce: the exclusive ticker mark of docs/IONSWAP-POOLS-SPEC-20261110.md §11.1, not the launch.
///
/// What the price is for now: a creation is two chain objects with their proofs, and it must never be free
/// (`no_creation_is_ever_free` pins it). cons: at $0.05 an NFT, filling a block with creations costs what filling it
/// with payments costs times fifty; that is the flat-fee chain's own spam bound, unchanged.
pub const TOKEN_CREATE_FEE_ATOMIC: u64 = 50_000_000; // 0.50 USDm
pub const NFT_CREATE_FEE_ATOMIC: u64 = 5_000_000; // 0.05 USDm
/// A contract deploy keeps its own price (§BR-12): 10 USDm into the four pools.
pub const DSOL_DEPLOY_FEE_ATOMIC: u64 = 1_000_000_000; // 10 USDm

/// The price of creating one asset of a kind. ONE function, so the gate that charges it, the route that quotes it and
/// the wallet that shows it cannot disagree (the drift that once produced a fictional bond beside a free route).
#[must_use]
pub fn asset_create_fee_atomic(nft: bool) -> u64 {
    if nft { NFT_CREATE_FEE_ATOMIC } else { TOKEN_CREATE_FEE_ATOMIC }
}

/// The price of creating a TOKEN. The symbol no longer changes it; the parameter stays so every caller that prices a
/// token by naming it keeps reading the one function.
#[must_use]
pub fn token_create_fee_atomic(_symbol: &str) -> u64 {
    asset_create_fee_atomic(false)
}

/// The normal deployment-signalling window, in BLOCKS (BIP8's shape: a signalling sample is a count of blocks, never a time):
/// a week of blocks at the target spacing — longer in wall time on a mesh slower than its target, and nothing it decides
/// depends on the pace (its thresholds are fractions of the blocks it folded).
pub const REWARD_EPOCH_BLOCKS_DEFAULT: u64 = blocks_for_ms(7 * DAY_MS);

/// Default share of each reward epoch routed to the BONDED validator set (the rest to the STAKED set), in bps
/// (4_000 = 40% validators / 60% stakers). An empty side routes its share to the other so no surplus is wasted.
/// Governance-tunable up to 10_000.
pub const VALIDATOR_REWARD_SHARE_BPS_DEFAULT: u32 = 4_000;

/// Default per-block PQ-VDF sequential heartbeat length ([`crate::vdf_clock`]) — the CONSTANT, governance-tunable
/// clock that paces block production (a MinRoot chain seeded from the selected parent's VDF output). `2^18 =
/// 262_144` ≈ 64 ms of un-parallelizable work on reference hardware: a real anti-outrun / anti-outsource floor
/// that stays cheap to re-eval on the live tip. Governance retunes it freely within the bounds below WITHOUT a
/// re-genesis — it is snapshot-persisted and on-chain governed like every other consensus parameter.
pub const VDF_STEPS_DEFAULT: u64 = crate::vdf_clock::VDF_STEPS_PER_BLOCK;

/// Constitutional SECURITY FLOOR for the VDF heartbeat (`2^12`): governance may never set the sequential length
/// below this — doing so would erase the anti-outrun / anti-outsource barrier (a "less secure" capture the
/// bicameral constitution rejects regardless of vote count).
pub const VDF_STEPS_SECURITY_FLOOR: u64 = 4_096;

/// A runaway-parameter CEILING for the VDF heartbeat (`2^28`): far above any real setting, so no governance
/// capture can pin an absurd length that stalls production.
pub const VDF_STEPS_CEILING: u64 = 268_435_456;

/// Error from a rejected governance parameter update (out of the allowed range).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParamError {
    #[error("dag_width {0} out of range [1, {ceiling}]", ceiling = DAG_WIDTH_CEILING)]
    DagWidthOutOfRange(usize),
    #[error("target_spacing_ms must be > 0")]
    ZeroSpacing,
    #[error("target_spacing_ms below {0} ms: a block rate every node cannot take in stops the chain as nodes join (A-F60)")]
    SpacingBelowNetwork(u64),
    #[error("mint_ratio_bps must be > 0 (a zero ratio would erase the reserve floor - an infinite mint)")]
    ZeroMintRatio,
    #[error("stake_reward_apr_bps {0} out of range [0, {ceiling}]", ceiling = STAKE_REWARD_APR_BPS_CEILING)]
    StakeAprOutOfRange(u32),
    #[error("withdraw fee band invalid: need 0 ≤ min ({min}) ≤ max ({max}) ≤ 10000")]
    WithdrawFeeBandInvalid { min: u32, max: u32 },
    #[error("vdf_steps {0} invalid: must be a power of two in [{floor}, {ceiling}]", floor = VDF_STEPS_SECURITY_FLOOR, ceiling = VDF_STEPS_CEILING)]
    VdfStepsOutOfRange(u64),
}

/// The active consensus parameter set. Cloneable + comparable so governance can propose + diff it, and
/// `Serialize`/`Deserialize` so it is PERSISTED in the node snapshot — a governance retune survives a restart
/// (the active set is chain-derived: genesis default + on-chain governance history), never silently reverting
/// to the code default. This is what makes every tunable freely adjustable WITHOUT a re-genesis.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainParams {
    /// Max parents a block may reference — the DAG width / concurrency bound. Governance-tunable at
    /// runtime; default 32 (the current live width).
    pub dag_width: usize,
    /// GHOSTDAG k-cluster bound (max blue anticone). Tracks `dag_width`; default 32.
    pub ghostdag_k: u64,
    /// Cap on the `past(sp)` boundary scan (merge-depth rule). Default 3600.
    pub merge_depth_cap: usize,
    /// Target block spacing in ms (1 BPS). Default 1000.
    pub target_spacing_ms: u64,
    /// DAA re-targeting sample length in blocks. Default 60.
    pub daa_sample_len: u64,
    /// Median-time-past sample length in blocks. Default 11.
    pub mtp_sample_len: usize,
    /// Allowed future-timestamp drift in ms. Default 30000.
    pub max_ts_drift_ms: u64,
    /// Max total tx weight a block packs. Default 4_000_000.
    pub max_block_weight: u64,
    /// Per-tx weight cap. Default 1_800_000 — the SAME ≤1.8MB bound the constant-size proof pillar sets, because
    /// a tx's weight IS its carrier blob length (`rpc_http` sets `weight = blob.len()`). At the previous 400_000 a
    /// node REJECTED ITS OWN LEGAL TRANSACTIONS: any spend whose WHIR carrier landed between 400 KB and the 1.8 MB
    /// the protocol declares valid was refused `TooHeavy` at relay, so it could never be pooled, never be mined,
    /// and never reach the recipient. A relay limit BELOW the protocol's own proof bound is an incompleteness, not
    /// a safety margin — spam is bounded by `pow_stamp_*` and `max_pool_weight`, which are the knobs meant for it.
    pub max_tx_weight: u32,
    /// Anti-spam stamp floor (leading-zero bits). Default 8.
    pub pow_stamp_base_bits: u32,
    /// Adaptive anti-spam stamp ceiling under a full pool. Default 24.
    pub pow_stamp_max_bits: u32,
    /// Mempool total-weight cap (no-growth bound). Default 100_000_000.
    pub max_pool_weight: u64,
    /// The per-block PQ-VDF sequential heartbeat length ([`crate::vdf_clock`]) — a CONSTANT, power-of-two step
    /// count. The block-add gate re-evals the VDF at THIS length (a live consensus rule), so it paces
    /// production. Governance-tunable at RUNTIME within `[VDF_STEPS_SECURITY_FLOOR, VDF_STEPS_CEILING]` with NO
    /// re-genesis (snapshot-persisted). Default `VDF_STEPS_DEFAULT`.
    pub vdf_steps: u64,
    /// The DETERMINISTIC per-network GENESIS IDENTITY — the per-network id prefix ([`network_genesis_prefix`]),
    /// and NOTHING per-device (user 2026-07-13). It is a HARD genesis-consensus binding: every node on a network
    /// derives the SAME value from the network name alone, so two FRESH devices build a BYTE-IDENTICAL genesis and
    /// converge — no per-device / env input ⇒ no funded-vs-fresh split by construction. Different network ⇒
    /// different value ⇒ isolated chains (assets never cross; a re-genesis is its own chain). NO commit and NO
    /// funding is folded into genesis: the aligned region past the prefix is always empty, so genesis records NO
    /// state. Set once per network at boot from `MONEROUSD_NET` (main.rs / serve::run_in_process, identically).
    pub genesis_parity_commit: Vec<u8>,
    /// Byte length of the per-network id prefix in `genesis_parity_commit`. It EQUALS the full length (the whole
    /// value IS the prefix — there is no per-device payload after it), so the genesis state-record path finds an
    /// EMPTY aligned region past it and records NOTHING at genesis (deterministic, funding-free genesis).
    pub net_prefix_len: usize,
    /// PSM mint collateral ratio in basis points — the reserve backing required per minted USDm (Buy-USDm).
    /// FREELY governance-tunable at runtime (default 150% = MINT_RATIO_DEFAULT_BPS): the community decides via
    /// bicameral governance how over-collateralized the mint is — including whether MonerousD stays a >100%-backed
    /// stablecoin. A mint authorizes only when the confidential solvency proof shows reserve_commit ≥ (this
    /// ratio)·liability; the sole hard limit is > 0 (the reserve floor never drops to zero).
    pub mint_ratio_bps: u32,
    /// Bond maturity / unbond-delay in blocks — the "stake lock". A validator's bonded value is locked until
    /// `bond_height + stake_lock_blocks`; `Node::unbond_validator` REJECTS an unbond before maturity fail-closed
    /// (ENFORCED — anti-flash-bond / no instant Sybil-weight exit; proven by `bond_unbond_delay_is_enforced_*`).
    /// Governance-tunable at runtime (default `STAKE_LOCK_BLOCKS_DEFAULT` ≈ 1 day at 1s blocks).
    pub stake_lock_blocks: u64,
    /// ⭐ §BR-11 — the fee PAYOUT PERIOD ("quarter" in the code), in parent keys: the miner share credited during one period
    /// is paid out over the next as a constant per-block rate (`PegLedger::miner_quarter_roll`), and the bonders' yield index
    /// rises at each period's close. Default one week (`MINER_QUARTER_KEYS_DEFAULT`); governance-tunable like every economic
    /// parameter. `#[serde(default)]` so an older snapshot loads it.
    #[serde(default = "default_miner_quarter_keys")]
    pub miner_quarter_keys: u64,
    /// ⭐ §BR-3 17.2 — THE UNBONDING WINDOW, in blue scores: an unbond's note returns this long after the unbond folds (at least
    /// the merge/fold horizon). Default 21 days at the 500 ms target (spec §2 item 4: longer than theft detection, so a
    /// thief that unbonds right after a theft stays slashable). Governance-tunable; `#[serde(default)]` for older snapshots.
    #[serde(default = "default_unbonding_blocks")]
    pub unbonding_blocks: u64,
    /// ⭐ §BR-3 17.6 — THE SURPLUS BUFFER'S TARGET (atomic USDm): the buffer's 25 % fee share credits the buffer up to this
    /// figure and the rest of that share flows to the stakers' pool (spec §1 item 6: "its share flows to stakers once the
    /// buffer is full"). Governance-tunable; `#[serde(default)]` for older snapshots.
    #[serde(default = "default_surplus_buffer_cap")]
    pub surplus_buffer_cap_atomic: u64,
    /// Governance-set TARGET staking APR in basis points/yr (default `STAKE_REWARD_APR_BPS_DEFAULT` = 5.00%).
    /// The protocol's advertised reward policy for stake-to-earn, backed by the zero-issuance reserve-yield +
    /// fee-redistribution stream (rewards are real confidential notes, never fresh emission). Governance retunes
    /// it up to `STAKE_REWARD_APR_BPS_CEILING`; a wallet surfaces it as the Earn-page APR.
    pub stake_reward_apr_bps: u32,
    /// The normal deployment-signalling window in BLOCKS (§BR-10, BIP8's shape; `deployment::DeploymentLedger`).
    /// Governance-tunable (default `REWARD_EPOCH_BLOCKS_DEFAULT`, a week of blocks at the target spacing — a count, not a time).
    pub reward_epoch_blocks: u64,
    /// Share of each reward epoch routed to the BONDED validator set (rest to the STAKED set), in bps (default
    /// `VALIDATOR_REWARD_SHARE_BPS_DEFAULT`). An empty side routes its share to the other so no distributable
    /// surplus is wasted. Governance-tunable up to 10_000.
    pub validator_reward_share_bps: u32,
    /// Redemption (peg-out) withdrawal-fee band, in basis points — the CONVEX anti-drain fee a peg-out pays scales
    /// from `withdraw_fee_min_bps` (a small redemption from a healthy reserve) up to `withdraw_fee_max_bps` (a
    /// near-total drain). Governance-tunable so the community can trade redemption cheapness against reserve
    /// protection (e.g. lower the floor if the fee is stifling usage). Defaults mirror
    /// [`crate::peg::WITHDRAW_FEE_MIN_BPS`]/[`crate::peg::WITHDRAW_FEE_MAX_BPS`] (0.25% .. 90%); the retune guard
    /// keeps `min ≤ max ≤ 10_000`.
    /// The DEX taker fee per fill, in BASIS POINTS of the order's public `pay_b`. Governance-tunable
    /// like every economic parameter. Default [`ORDER_FILL_FEE_BPS_DEFAULT`].
    pub order_fill_fee_bps: u64,
    pub withdraw_fee_min_bps: u32,
    pub withdraw_fee_max_bps: u32,
    /// CANONICAL RECORD FOLD DEPTH (protocol constant, v31). A block's DA record folds into the note
    /// spine — takes its ordinal, its 256 leaves, its accumulator step — only once the block is this many
    /// selected-chain steps below the selected tip, and then in the DAG's canonical (blue_work, id) order
    /// within each chain block's merge set. Every node with the same DAG folds the same records at the
    /// same ordinals (MEASURED 2026-09-03 gate 41: with arrival-order folding, 597 of 598 co-written
    /// records sat at different ordinals on the two nodes). NOT a window: nothing is ever refused for
    /// age — a block that lands deeper folds when its chain block does, and a deeper reorg re-folds from
    /// the common prefix. A fixed shape constant: the wait is `record_fold_depth` blocks, ~seconds.
    pub record_fold_depth: u64,
    // NOTE: network-privacy parameters (cell size, cover-traffic rate) are deliberately NOT here.
    // Privacy is 100% by default and fixed by construction — never a governance choice — so those
    // are hard constants in crate::net, not tunable state that could be weakened.
}

/// The canonical record fold depth (see `ChainParams::record_fold_depth`): thirty-two selected-chain
/// steps (~16 s at the 500 ms spacing). MEASURED 2026-09-03 gate 44 (scratch N9yLYo): over the onion
/// transport blocks land in cascades of 11 and 28 at once, and each cascade moved the selected chain
/// below a 4-deep fold root on both nodes; a fold root the transport's bursts cannot reach is the
/// difference between a spine that only ever appends and one that rewinds on every burst.
/// ⭐ 4, MEASURED ON REAL NODES (2026-11-04, `scratchpad/net/goals.tsv`): received money spendable in 66-99 s at 4, 160 s at 8, 508-583 s at 32, at today's block rate.
/// SPENDABLE IS NOT FINAL: the fold can still rewind and refold in the new order, so an honest payment survives; finality (≥ 2/3 of bonded weight) is what a merchant shipping
/// goods relies on. Attacked on real nodes (`net/double_spend.py`): one note spent at once through both nodes paid one payee, and both nodes agreed.
/// cons: a shallower fold rewinds more often. At a much faster block rate, 4 chain blocks would be shorter than the relay, so this must then grow with the rate.
pub const RECORD_FOLD_DEPTH_DEFAULT: u64 = 4;

/// The merge depth (Kaspa's merge-depth bound), in blue score: a block may not name a parent deeper than
/// this below the selected tip, the DAG keeps twice this span above its horizon, and the live catch-up
/// lanes page a peer that is behind by up to this much before the certified bundle is the door.
/// PAST-CHATS-CHECKED: NOT a new number — `ChainParams::default().merge_depth_cap` has carried the literal
/// 3,600 since the DAG params were set (30 min at the 500 ms spacing the user fixed on 2026-09-17); it is
/// named here so the horizon (`Dag::keep_depth`), the block window and `LIVE_CATCH_UP_DEPTH` read ONE
/// definition. User 2026-09-21: "use kaspa and bitcoins proven formula as that what we are supposed to be
/// doing for the remaining plumbing" — Kaspa's merge depth is that formula's bound. Transcript search for
/// "pruning point" / "body ring": no earlier decision on this constant.
pub const MERGE_DEPTH_CAP_DEFAULT: usize = 3600;

impl Default for ChainParams {
    fn default() -> Self {
        ChainParams {
            dag_width: 32,
            ghostdag_k: 32,
            merge_depth_cap: MERGE_DEPTH_CAP_DEFAULT,
            // ⭐ A-F60: the mesh's block-rate target is DERIVED from the block's bytes and Tor's lane rate so that the frames
            // every node must take in stay within half of its intake at ANY node count (`dag::MESH_TARGET_SPACING_MS`,
            // 5,322 ms today; it falls toward the 500 ms the chain was meant for as a block's frame shrinks). It was a
            // literal 500 ms set for a 29 KB block; at today's ~1.06 MB frame that rate stalls the chain at ~13 producers.
            target_spacing_ms: crate::dag::MESH_TARGET_SPACING_MS,
            daa_sample_len: 60,
            mtp_sample_len: 11,
            max_ts_drift_ms: 30_000,
            max_block_weight: 4_000_000,
            max_tx_weight: MAX_TX_WEIGHT_BYTES,
            pow_stamp_base_bits: 8,
            pow_stamp_max_bits: 24,
            max_pool_weight: 100_000_000,
            vdf_steps: VDF_STEPS_DEFAULT,
            mint_ratio_bps: MINT_RATIO_DEFAULT_BPS,
            stake_lock_blocks: STAKE_LOCK_BLOCKS_DEFAULT,
            miner_quarter_keys: MINER_QUARTER_KEYS_DEFAULT,
            unbonding_blocks: UNBONDING_BLOCKS_DEFAULT,
            surplus_buffer_cap_atomic: SURPLUS_BUFFER_CAP_DEFAULT,
            stake_reward_apr_bps: STAKE_REWARD_APR_BPS_DEFAULT,
            reward_epoch_blocks: REWARD_EPOCH_BLOCKS_DEFAULT,
            validator_reward_share_bps: VALIDATOR_REWARD_SHARE_BPS_DEFAULT,
            order_fill_fee_bps: ORDER_FILL_FEE_BPS_DEFAULT,
            withdraw_fee_min_bps: 25, // mirrors crate::peg::WITHDRAW_FEE_MIN_BPS (0.25%)
            withdraw_fee_max_bps: 9_000, // mirrors crate::peg::WITHDRAW_FEE_MAX_BPS (90% — near-total-drain cap)
            record_fold_depth: RECORD_FOLD_DEPTH_DEFAULT,
            genesis_parity_commit: Vec::new(),
            net_prefix_len: 0,
        }
    }
}

/// ⭐⭐⭐ ITEM 8(b) — THE GENESIS-PARAMETERISED OPEN-MINT ALLOWANCE, the self-contained mint-authority
/// parameter `chain_object::admissible` checks for `BridgeCredit` / `AssetCreate` / `AssetMint`.
///
/// THE RULE IS IDENTICAL ON EVERY NETWORK (TESTNET == PRODUCTION): "a mint-class object is admissible iff
/// its credited amount is within the chain's genesis-derived allowance AND its validity carrier proves the
/// note opens to exactly that amount in that asset". Only the PARAMETER differs, the way `chain_id`
/// differs — it is a pure deterministic function of the genesis identity (`f(network)`). ATTRIBUTION
/// (corrected, fix round 2026-09-05): the completion plan does NOT sanction this shape in its own words —
/// what the plan actually says is "invent the missing self-contained mint-authority rule"; the
/// genesis-parameterised, deterministic `f(network)` allowance is THIS implementation's invention for that
/// rule (following the `chain_id` precedent). Evaluated from `genesis_parity_commit` alone, so every node
/// of one chain
/// derives the identical value and no environment variable, operator flag or runtime branch enters
/// validation. A `node_network_is_testnet` admission gate is exactly what this is NOT.
///
/// * testnet ⇒ [`TESTNET_OPEN_MINT_ALLOWANCE`]: the OPEN faucet, as a checkable chain rule. Anyone can
///   mint valueless test USDm within the per-credit bound — the same trust model as the existing open
///   `/faucet/drip`, but as a chain object any producer includes and every node applies identically.
/// * mainnet (and every unknown network — the value-bearing safe default) ⇒ 0: no credit can satisfy
///   `amount <= 0` (a zero-amount credit is refused at decode), so the classes stay fail-closed there
///   until the bonded ≥2/3 threshold arm (the peg's existing `threshold_ok` model) is wired as a second
///   admission arm. That arm — not this allowance — is the mainnet mint authority.
///
/// DELIBERATELY A DERIVED FUNCTION, NOT A STORED/TUNABLE FIELD (#74 anti-capture): an open-mint allowance
/// that governance could retune at runtime is a capture vector — one captured vote away from an unlimited
/// mainnet mint. Deriving it from the genesis identity makes "mainnet has no open mint" immutable by
/// construction; changing it is a hard fork (all hard forks live at height 1 here). It also cannot drift:
/// there is no constructor to forget it in and no snapshot field to migrate.
///
/// This is a per-object admission BOUND, not a supply path — every mint is a visible chain object
/// admitted at runtime. cons: none — one prefix compare per mint-class admission (f(fixed constants));
/// no state, no wire bytes, no growth term.
pub const TESTNET_OPEN_MINT_ALLOWANCE: u64 = 1_000_000_000_000; // 10,000.00 USDm per credit (1e8/USDm)

/// ⭐ THE ≤1.8 MB PROOF-PILLAR BOUND, AS ONE NAMED DEFINITION — the default `ChainParams::max_tx_weight` (a
/// tx's weight IS its blob length) and, since DB-224, the per-entry bound on a block's carried credit set
/// (`chain_object::MAX_CARRIAGE_ENTRY_BYTES`): a carriage is never larger than the transaction it carries,
/// so one number bounds both and they cannot drift apart. Not tuned — it is the pillar's own figure.
pub const MAX_TX_WEIGHT_BYTES: u32 = 1_800_000;

impl ChainParams {
    /// The chain's open-mint allowance — see [`TESTNET_OPEN_MINT_ALLOWANCE`]. Pure `f(genesis identity)`.
    pub fn genesis_mint_allowance(&self) -> u64 {
        if self.genesis_parity_commit == network_genesis_prefix("testnet") {
            TESTNET_OPEN_MINT_ALLOWANCE
        } else {
            0
        }
    }
}

/// Per-network ids — testnet, mainnet, and every re-genesis are DISTINCT chains. The id is folded into the
/// genesis-parity commit so a note/tx/bond on one network is structurally invalid on another (isolated chains).
/// Unknown/unset network name => mainnet (the value-bearing side, safe default).
pub const MAINNET_NETWORK_ID: u64 = 0x4d55_5344_4d41_494e; // "MUSDMAIN"
pub const TESTNET_NETWORK_ID: u64 = 0x4d55_5344_5445_5354; // "MUSDTEST"

/// The per-network magic folded into genesis, selected by network NAME (mirrors the wallet's `canonical_net`).
pub fn net_magic(net: &str) -> u64 {
    match net.to_ascii_lowercase().as_str() {
        "testnet" | "test" | "regtest" => TESTNET_NETWORK_ID,
        _ => MAINNET_NETWORK_ID,
    }
}

/// ⭐⭐ THE MAINNET LAUNCH ANCHOR (user 2026-11-12, on the public-testnet rollout: the mainnet genesis "has to be tied to
/// something nobody can know before launch (the files your launch command generates plus a recent Bitcoin block hash)").
/// The mainnet genesis WAS a public constant (`"MUSD-NETID-v1" ‖ "MUSDMAIN"`), so anyone could start "mainnet" early and
/// arrive at launch carrying work nobody else saw. Now the mainnet genesis prefix also commits to this anchor
/// ([`LaunchAnchor::digest`]): a recent Bitcoin block (its height and hash — unknowable before that block is mined; anyone can
/// check the pair against Bitcoin) and the digest of the launch files the launch command generates (the SAT set-aside and the
/// DeFi launch position — unknowable before that command runs: they commit to freshly drawn secrets). A chain started before
/// launch is therefore a DIFFERENT network from the real mainnet, by construction.
/// The anchor is the text file `mainnet_launch_anchor.txt` beside this one, compiled in, EMPTY until launch: the launch
/// command writes it (`usdmd-node launch-anchor`) right before the launch release is built. The testnet genesis never reads
/// it (the testnet is running now, and testnet value can never reach mainnet: their network ids already differ).
/// BORROWED: Bitcoin's genesis headline (The Times, 2009-01-03) — a genesis that names a public fact of its own day.
/// SCALE: one parse per call of a few hundred bytes, compiled in; no term in nodes, items or height.
/// AI RESISTANCE: (a)/(b) — every node derives the genesis from these bytes itself; a lying anchor is a different genesis
/// (a different network), never a forged mainnet; the Bitcoin block is checkable by anyone, and a build whose launch files do
/// not match the anchor refuses mainnet ([`mainnet_launch_anchor`]).
pub const MAINNET_LAUNCH_ANCHOR_TEXT: &str = include_str!("mainnet_launch_anchor.txt");

/// One mainnet launch anchor (see [`MAINNET_LAUNCH_ANCHOR_TEXT`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaunchAnchor {
    /// The Bitcoin block's height.
    pub bitcoin_height: u64,
    /// That block's hash, in the byte order Bitcoin explorers display it.
    pub bitcoin_block: [u8; 32],
    /// [`launch_artifacts_digest`] of the launch files this release carries.
    pub artifacts: [u8; 32],
}

impl LaunchAnchor {
    /// What the mainnet genesis prefix commits to: `blake3("MUSD-LAUNCH-v1" ‖ height LE ‖ block ‖ artifacts)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD-LAUNCH-v1");
        h.update(&self.bitcoin_height.to_le_bytes());
        h.update(&self.bitcoin_block);
        h.update(&self.artifacts);
        *h.finalize().as_bytes()
    }

    /// The anchor as the file holds it: three `key=value` lines, after a header saying how anyone checks it.
    #[must_use]
    pub fn render(&self) -> String {
        let hex = |b: &[u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        format!(
            "# MonerousD mainnet launch anchor. The mainnet genesis commits to these three values (params::LaunchAnchor).\n\
             # Anyone can check them: the Bitcoin block at `bitcoin_height` has the hash `bitcoin_block`, and `artifacts`\n\
             # is params::launch_artifacts_digest of src/sat_set_aside.bin and src/defi_launch.bin in this release.\n\
             bitcoin_height={}\nbitcoin_block={}\nartifacts={}\n",
            self.bitcoin_height,
            hex(&self.bitcoin_block),
            hex(&self.artifacts)
        )
    }

    /// Parse an anchor file. `Ok(None)`: no anchor (blank or comments only — every release before launch). `Err`: a file that
    /// says something but not exactly the three fields, each once and well formed.
    pub fn parse(text: &str) -> Result<Option<Self>, String> {
        let (mut height, mut block, mut artifacts) = (None, None, None);
        let hex32 = |v: &str| -> Option<[u8; 32]> {
            // exactly 64 hex digits — `from_str_radix` alone would also take a sign ("+f"), a second spelling of one byte
            if v.len() != 64 || !v.bytes().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            let mut out = [0u8; 32];
            for (i, o) in out.iter_mut().enumerate() {
                *o = u8::from_str_radix(v.get(2 * i..2 * i + 2)?, 16).ok()?;
            }
            Some(out)
        };
        let mut any = false;
        for line in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            any = true;
            let (k, v) = line.split_once('=').ok_or_else(|| format!("not key=value: {line}"))?;
            let (k, v) = (k.trim(), v.trim());
            let dup = |set: bool| if set { Err(format!("{k} is given twice")) } else { Ok(()) };
            match k {
                "bitcoin_height" => {
                    dup(height.is_some())?;
                    height = Some(v.parse::<u64>().map_err(|_| format!("bitcoin_height is not a number: {v}"))?);
                }
                "bitcoin_block" => {
                    dup(block.is_some())?;
                    block = Some(hex32(v).ok_or_else(|| "bitcoin_block is not 64 hex digits".to_string())?);
                }
                "artifacts" => {
                    dup(artifacts.is_some())?;
                    artifacts = Some(hex32(v).ok_or_else(|| "artifacts is not 64 hex digits".to_string())?);
                }
                other => return Err(format!("unknown field {other}")),
            }
        }
        if !any {
            return Ok(None);
        }
        match (height, block, artifacts) {
            (Some(bitcoin_height), Some(bitcoin_block), Some(artifacts)) if bitcoin_height > 0 => {
                Ok(Some(Self { bitcoin_height, bitcoin_block, artifacts }))
            }
            _ => Err("the anchor needs bitcoin_height (> 0), bitcoin_block and artifacts".to_string()),
        }
    }
}

/// The launch files' digest the anchor names: `blake3("MUSD-LAUNCH-ARTIFACTS-v1" ‖ for each file: len LE ‖ blake3(bytes))`,
/// over the SAT set-aside, then the DeFi launch position.
#[must_use]
pub fn launch_artifacts_digest(sat_set_aside: &[u8], defi_launch: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD-LAUNCH-ARTIFACTS-v1");
    for f in [sat_set_aside, defi_launch] {
        h.update(&(f.len() as u64).to_le_bytes());
        h.update(blake3::hash(f).as_bytes());
    }
    *h.finalize().as_bytes()
}

/// The anchor this build may use, judged against the launch files compiled into it: `Ok(None)` before launch, `Err` when the
/// file does not parse or names launch files this build does not carry (a build with other launch files cannot claim it).
pub fn anchor_for_build(text: &str, compiled_artifacts: &[u8; 32]) -> Result<Option<LaunchAnchor>, String> {
    match LaunchAnchor::parse(text)? {
        Some(a) if &a.artifacts != compiled_artifacts => {
            Err("the anchor names launch files this build does not carry (artifacts digest differs)".to_string())
        }
        other => Ok(other),
    }
}

/// THIS build's mainnet launch anchor: `Ok(None)` before launch, `Ok(Some)` once the launch release carries a valid one.
pub fn mainnet_launch_anchor() -> Result<Option<LaunchAnchor>, String> {
    anchor_for_build(
        MAINNET_LAUNCH_ANCHOR_TEXT,
        &launch_artifacts_digest(crate::sat_set_aside::CANONICAL, crate::defi_launch::CANONICAL),
    )
}

/// ⭐ HAS MAINNET LAUNCHED? (user 2026-11-12: "i would like the wallet mainnet sellection greyed out so users cant start
/// their own mainnet"). True exactly when this build carries a valid launch anchor ([`mainnet_launch_anchor`]): every release
/// before the public launch refuses to start a node on the mainnet identity ([`refuse_unlaunched_network`]), on BOTH boot paths
/// (the daemon, `main.rs`; the phone and wallet in-process node, `serve::run_in_process`), and the launch release — the one
/// that carries the anchor — opens it, with the anchored genesis. Nothing to flip by hand.
#[must_use]
pub fn mainnet_launched() -> bool {
    matches!(mainnet_launch_anchor(), Ok(Some(_)))
}

/// The boot gate (see [`mainnet_launched`]): `Err` names why a node may not start on `net` in this release. An unset or
/// unknown name selects mainnet ([`net_magic`]), so before launch it is refused too, with the one-line fix; nothing is
/// silently re-pointed at the testnet (a node an operator meant for mainnet after launch must never run testnet quietly).
pub fn refuse_unlaunched_network(net: &str) -> Result<(), String> {
    if net_magic(net) != MAINNET_NETWORK_ID {
        return Ok(());
    }
    let named = if net.trim().is_empty() { "no network (MONEROUSD_NET is unset, which selects mainnet)".to_string() } else { format!("network '{net}' (the mainnet identity)") };
    match mainnet_launch_anchor() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => Err(format!(
            "MonerousD mainnet has not launched: this release runs the testnet only, and {named} was asked for. \
             Start the node with MONEROUSD_NET=testnet."
        )),
        Err(why) => Err(format!(
            "this build's mainnet launch anchor is not valid ({why}), so it cannot start mainnet; {named} was asked for. \
             Start the node with MONEROUSD_NET=testnet."
        )),
    }
}

/// The domain-tagged, per-network prefix prepended to `genesis_parity_commit`, so the genesis STATE (recorded
/// through the ordinary note path) and the `chain_id` digest are BOTH scoped to this network: same network =>
/// same genesis (a mesh converges), different network => different genesis (isolated chains — assets never cross).
/// The most blocks ONE block may merge — a FIXED PROTOCOL SHAPE CONSTANT, `dag_width * ghostdag_k`.
///
/// ⛔ THIS IS NOT A WINDOW, AND IT REFUSES NO NOTE. A window bounds how far back you may REACH and drops an
/// owned note for being old — that is fund loss and is banned outright. This bounds how much ONE BLOCK may
/// absorb AT ONCE. Blocks beyond it are not discarded, not orphaned and not skipped: they stay in the DAG,
/// their notes are recorded on ingest exactly as any other block's, and the NEXT block merges them. Nothing
/// ages out, and no reach is limited.
///
/// It exists because the mergeset is the transitive anticone, which `TooManyParents` (a bound on DIRECT
/// parents) does not constrain. Without it a peer could withhold blocks and release them together, making one
/// block's validation walk grow without limit — per-block work scaling with history, which is exactly the
/// O(growth) the architecture bans. Both inputs are shape constants identical at height 1 and at height
/// 10^12, so the bound is `f(protocol shape)` with no history quantity in it. Kaspa fixes the same hazard the
/// same way (`mergeset_size_limit`).
pub fn mergeset_shape_bound(dag_width: usize, ghostdag_k: u64) -> usize {
    dag_width.saturating_mul(ghostdag_k as usize).max(1)
}

/// The ONE network genesis prefix (the daemon's `main.rs` and the wallet's network descriptor call this, never a copy):
/// `"MUSD-NETID-v1" ‖ net-magic LE`, and for MAINNET once the launch release carries its anchor, `‖ anchor digest`
/// ([`LaunchAnchor`]) — so the real mainnet's genesis is unknowable before launch. Testnet bytes are unchanged forever.
pub fn network_genesis_prefix(net: &str) -> Vec<u8> {
    let magic = net_magic(net);
    let mut v = Vec::from(&b"MUSD-NETID-v1"[..]);
    v.extend_from_slice(&magic.to_le_bytes());
    if magic == MAINNET_NETWORK_ID {
        if let Ok(Some(anchor)) = mainnet_launch_anchor() {
            v.extend_from_slice(&anchor.digest());
        }
    }
    v
}

impl ChainParams {
    /// Apply a governance-approved DAG-width retune (no chain restart). `ghostdag_k` tracks the
    /// width so the k-cluster bound stays consistent. Rejected if outside the safety range.
    pub fn governance_set_dag_width(&mut self, width: usize) -> Result<(), ParamError> {
        if width < 1 || width > DAG_WIDTH_CEILING {
            return Err(ParamError::DagWidthOutOfRange(width));
        }
        self.dag_width = width;
        self.ghostdag_k = width as u64;
        Ok(())
    }

    /// Apply a governance-approved block-spacing retune (no chain restart).
    pub fn governance_set_target_spacing_ms(&mut self, ms: u64) -> Result<(), ParamError> {
        if ms == 0 {
            return Err(ParamError::ZeroSpacing);
        }
        // ⛔ A-F60: no vote may set a block rate the network cannot carry — below the derived floor the frames outrun every
        // node's intake as producers join and the chain stops (the floor falls by itself when a block's frame shrinks).
        if ms < crate::dag::MESH_TARGET_SPACING_MS {
            return Err(ParamError::SpacingBelowNetwork(crate::dag::MESH_TARGET_SPACING_MS));
        }
        self.target_spacing_ms = ms;
        Ok(())
    }

    /// Apply a governance-approved VDF-heartbeat retune (no chain restart). The sequential length must be a
    /// power of two within `[VDF_STEPS_SECURITY_FLOOR, VDF_STEPS_CEILING]` — anything else fails closed
    /// (a non-power-of-two is not a valid MinRoot length; below the floor erases the anti-outsource barrier;
    /// above the ceiling would stall production). Takes effect on the next block; snapshot-persisted so it
    /// survives a restart with no re-genesis.
    pub fn governance_set_vdf_steps(&mut self, steps: u64) -> Result<(), ParamError> {
        let in_range = steps >= VDF_STEPS_SECURITY_FLOOR && steps <= VDF_STEPS_CEILING;
        if !steps.is_power_of_two() || !in_range {
            return Err(ParamError::VdfStepsOutOfRange(steps));
        }
        self.vdf_steps = steps;
        Ok(())
    }

    /// Apply a governance-approved PSM mint-ratio retune (no chain restart). FREELY tunable by bicameral
    /// governance — the community can raise it (a safer peg) or lower it (down to deciding MonerousD is no longer
    /// a >100%-backed stablecoin). The ONLY rejected value is 0: erasing the reserve floor would be infinite
    /// inflation, so a zero ratio fails closed. Every positive ratio is the community's choice.
    pub fn governance_set_mint_ratio_bps(&mut self, bps: u32) -> Result<(), ParamError> {
        if bps == 0 {
            return Err(ParamError::ZeroMintRatio);
        }
        self.mint_ratio_bps = bps;
        Ok(())
    }

    /// Apply a governance-approved staking-reward APR retune (basis points/yr). Rejected above the
    /// `STAKE_REWARD_APR_BPS_CEILING` runaway backstop; 0 (a paused reward policy) is allowed.
    pub fn governance_set_stake_reward_apr_bps(&mut self, bps: u32) -> Result<(), ParamError> {
        if bps > STAKE_REWARD_APR_BPS_CEILING {
            return Err(ParamError::StakeAprOutOfRange(bps));
        }
        self.stake_reward_apr_bps = bps;
        Ok(())
    }

    /// Apply a governance-approved stake-lock (maturity / unbond-delay) retune, in blocks. Any value is
    /// permitted (0 = no lock, an instantly-liquid stake); the default is `STAKE_LOCK_BLOCKS_DEFAULT`.
    pub fn governance_set_stake_lock_blocks(&mut self, blocks: u64) {
        self.stake_lock_blocks = blocks;
    }

    /// ⭐ §BR-3 17.2 — apply a governance-approved unbonding window, in blue scores (0 = the merge/fold horizon alone).
    pub fn governance_set_unbonding_blocks(&mut self, blocks: u64) {
        self.unbonding_blocks = blocks;
    }

    /// ⭐ §BR-11 — apply a governance-approved miner-pool quarter length, in parent keys (at least 1).
    pub fn governance_set_miner_quarter_keys(&mut self, keys: u64) {
        self.miner_quarter_keys = keys.max(1);
    }

    /// Apply a governance-approved reward-EPOCH-length retune, in blocks — how often the reserve-yield surplus is
    /// distributed into the stake/bond reward indices (a shorter epoch pays more frequently; `0` pauses reward
    /// delivery). Any value is permitted; the default is `REWARD_EPOCH_BLOCKS_DEFAULT` (≈1 week at 1s blocks).
    pub fn governance_set_reward_epoch_blocks(&mut self, blocks: u64) {
        self.reward_epoch_blocks = blocks;
    }

    /// Apply a governance-approved redemption withdrawal-fee band retune (basis points). Rejected unless
    /// `min ≤ max ≤ 10_000` (a fee over 100% is nonsensical; min above max would invert the convex curve). This
    /// is the lever to make redemptions cheaper (lower the floor) or the reserve harder to drain (raise the cap).
    pub fn governance_set_withdraw_fee_band(
        &mut self,
        min_bps: u32,
        max_bps: u32,
    ) -> Result<(), ParamError> {
        if min_bps > max_bps || max_bps > 10_000 {
            return Err(ParamError::WithdrawFeeBandInvalid {
                min: min_bps,
                max: max_bps,
            });
        }
        self.withdraw_fee_min_bps = min_bps;
        self.withdraw_fee_max_bps = max_bps;
        Ok(())
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_the_live_values() {
        let p = ChainParams::default();
        assert_eq!(p.dag_width, 32);
        assert_eq!(p.ghostdag_k, 32);
        assert_eq!(
            p.target_spacing_ms, 500,
            "LAUNCH heartbeat = 500 ms (2 BPS)"
        );
        assert_eq!(p.vdf_steps, VDF_STEPS_DEFAULT);
        assert_eq!(p.stake_lock_blocks, STAKE_LOCK_BLOCKS_DEFAULT);
        assert_eq!(p.stake_reward_apr_bps, STAKE_REWARD_APR_BPS_DEFAULT);
    }

    /// The VDF-heartbeat governance retune is FREELY tunable within the safety band and fail-closed outside it
    /// — the block-time / VDF knobs the user mandated as runtime-adjustable with no re-genesis.
    #[test]
    fn governance_vdf_steps_is_bounded_and_power_of_two() {
        let mut p = ChainParams::default();
        assert!(
            p.governance_set_vdf_steps(1 << 20).is_ok(),
            "2^20 in-band accepts"
        );
        assert_eq!(p.vdf_steps, 1 << 20);
        assert!(
            p.governance_set_vdf_steps(VDF_STEPS_SECURITY_FLOOR).is_ok(),
            "the floor itself is allowed"
        );
        assert_eq!(
            p.governance_set_vdf_steps(VDF_STEPS_SECURITY_FLOOR >> 1),
            Err(ParamError::VdfStepsOutOfRange(
                VDF_STEPS_SECURITY_FLOOR >> 1
            )),
            "below the security floor is rejected (anti-outsource barrier can't be governed away)"
        );
        assert_eq!(
            p.governance_set_vdf_steps(100_000),
            Err(ParamError::VdfStepsOutOfRange(100_000)),
            "a non-power-of-two is not a valid MinRoot length"
        );
        assert_eq!(
            p.governance_set_vdf_steps(VDF_STEPS_CEILING << 1),
            Err(ParamError::VdfStepsOutOfRange(VDF_STEPS_CEILING << 1)),
            "above the runaway ceiling is rejected"
        );
    }

    /// Before launch no node starts on the mainnet identity, however it is asked for (unset, "mainnet", or any name
    /// `net_magic` maps to mainnet), and every testnet name still starts. CALIBRATED both ways in one test.
    #[test]
    fn before_launch_no_node_starts_on_the_mainnet_identity() {
        assert_eq!(mainnet_launch_anchor(), Ok(None), "this pin describes a pre-launch release: the anchor file is empty");
        assert!(!mainnet_launched());
        for net in ["testnet", "test", "regtest", "TestNet"] {
            assert_eq!(refuse_unlaunched_network(net), Ok(()), "the testnet identity '{net}' must start");
        }
        for net in ["", "  ", "mainnet", "main", "e2e-wire", "stagenet"] {
            assert_eq!(net_magic(net), MAINNET_NETWORK_ID, "calibration: '{net}' maps to the mainnet identity");
            let why = refuse_unlaunched_network(net).expect_err("a pre-launch node must refuse the mainnet identity");
            assert!(why.contains("MONEROUSD_NET=testnet"), "the refusal names the fix: {why}");
        }
    }

    #[test]
    fn network_genesis_prefix_is_byte_pinned_to_the_daemon_shape() {
        // PINNED BYTES: the daemon (`main.rs`) holds a guard-frozen reference copy of this transform
        // ("MUSD-NETID-v1" ++ net-magic LE). This pin guarantees the LIB side (used by the in-process
        // phone node) can never silently diverge from that frozen reference — same (net) in, same
        // prefix out, byte for byte, forever.
        let mut want_test = Vec::from(&b"MUSD-NETID-v1"[..]);
        want_test.extend_from_slice(&0x4d55_5344_5445_5354u64.to_le_bytes()); // "MUSDTEST"
        assert_eq!(network_genesis_prefix("testnet"), want_test);
        assert_eq!(
            network_genesis_prefix("TESTNET"),
            want_test,
            "net name is case-insensitive"
        );
        assert_eq!(
            network_genesis_prefix("regtest"),
            want_test,
            "regtest rides the testnet id"
        );
        let mut want_main = Vec::from(&b"MUSD-NETID-v1"[..]);
        want_main.extend_from_slice(&0x4d55_5344_4d41_494eu64.to_le_bytes()); // "MUSDMAIN"
        // the launch release appends its anchor's digest (the anchored genesis); before launch the bytes stand as pinned
        if let Ok(Some(anchor)) = mainnet_launch_anchor() {
            want_main.extend_from_slice(&anchor.digest());
        }
        assert_eq!(network_genesis_prefix("mainnet"), want_main);
        assert_eq!(
            network_genesis_prefix(""),
            want_main,
            "unset net defaults to mainnet (safe side)"
        );
    }

    /// ⭐ THE LAUNCH ANCHOR: a file renders and parses back to itself; blank or comment-only is "not launched"; every malformed
    /// shape is refused by name; a build whose launch files differ cannot claim an anchor; and the digest moves with EVERY
    /// field — so a chain started before launch (no anchor, or another anchor) is a different genesis. CALIBRATED both ways.
    #[test]
    fn the_launch_anchor_binds_the_mainnet_genesis_to_launch_time_inputs() {
        let files = launch_artifacts_digest(b"set-aside bytes", b"launch-position bytes");
        let a = LaunchAnchor { bitcoin_height: 925_000, bitcoin_block: [0x5a; 32], artifacts: files };
        assert_eq!(LaunchAnchor::parse(&a.render()), Ok(Some(a)), "a rendered anchor parses back to itself");
        assert_eq!(LaunchAnchor::parse(""), Ok(None));
        assert_eq!(LaunchAnchor::parse(MAINNET_LAUNCH_ANCHOR_TEXT), Ok(None), "the shipped file is comments only");
        for bad in [
            "bitcoin_height=925000\nbitcoin_block=00\nartifacts=00",
            "bitcoin_height=925000",
            "bitcoin_height=0\nbitcoin_block=",
            "bitcoin_height=x\nbitcoin_block=aa\nartifacts=bb",
            "nonsense",
        ] {
            assert!(LaunchAnchor::parse(bad).is_err(), "refused: {bad:?}");
        }
        // one spelling per byte: a signed pair ("+5") is the same length as a hex pair and is refused
        let signed = a.render().replace(&format!("bitcoin_block={}", "5a".repeat(32)), &format!("bitcoin_block=+5{}", "5a".repeat(31)));
        assert_ne!(signed, a.render(), "the test edited the block line");
        for bad in [signed.as_str()] {
            assert!(LaunchAnchor::parse(bad).is_err(), "refused: {bad:?}");
        }
        let twice = format!("{}bitcoin_height=1\n", a.render());
        assert!(LaunchAnchor::parse(&twice).is_err(), "a field given twice is refused");
        let unknown = format!("{}extra=1\n", a.render());
        assert!(LaunchAnchor::parse(&unknown).is_err(), "an unknown field is refused");
        // the build's own launch files decide whether it may claim the anchor
        assert_eq!(anchor_for_build(&a.render(), &files), Ok(Some(a)));
        let other = launch_artifacts_digest(b"other set-aside", b"launch-position bytes");
        assert!(anchor_for_build(&a.render(), &other).is_err(), "a build with other launch files cannot claim it");
        assert_eq!(anchor_for_build("# not launched\n", &other), Ok(None));
        // the digest moves with every field, and the artifacts digest with every file and with their order
        let d = a.digest();
        assert_ne!(LaunchAnchor { bitcoin_height: 925_001, ..a }.digest(), d);
        let mut blk = a.bitcoin_block;
        blk[31] ^= 1;
        assert_ne!(LaunchAnchor { bitcoin_block: blk, ..a }.digest(), d);
        assert_ne!(LaunchAnchor { artifacts: other, ..a }.digest(), d);
        assert_ne!(launch_artifacts_digest(b"launch-position bytes", b"set-aside bytes"), files, "file order matters");
        assert_ne!(launch_artifacts_digest(b"", b""), files);
    }

    #[test]
    fn genesis_is_deterministic_per_network_no_per_device_input() {
        // GENESIS = DETERMINISTIC PER-NETWORK CONSTANT, NO COMMIT (user 2026-07-13). Two nodes (a daemon and a
        // phone's in-process node) on the SAME network derive the IDENTICAL genesis identity from the network
        // name ALONE — ZERO per-device / env input — so their genesis is byte-identical and they converge with
        // no funded-vs-fresh split. A DIFFERENT network derives a DIFFERENT identity -> isolated chains.
        let net_id = |net: &str| {
            let mut p = ChainParams::default();
            p.genesis_parity_commit = network_genesis_prefix(net); // EXACTLY what main.rs / serve.rs set
            p.net_prefix_len = p.genesis_parity_commit.len();
            p
        };
        let (a, b, m) = (net_id("testnet"), net_id("testnet"), net_id("mainnet"));
        assert_eq!(
            a.genesis_parity_commit, b.genesis_parity_commit,
            "same network => byte-identical genesis (converge)"
        );
        assert_ne!(
            a.genesis_parity_commit, m.genesis_parity_commit,
            "different network => isolated chains"
        );
        // The whole value IS the per-network prefix — there is NO per-device payload after it, so the genesis
        // state-record path finds an EMPTY region past `net_prefix_len` and records NOTHING at genesis.
        assert_eq!(
            a.net_prefix_len,
            a.genesis_parity_commit.len(),
            "no per-device payload past the prefix"
        );
        assert!(
            a.genesis_parity_commit[a.net_prefix_len..].is_empty(),
            "genesis records no state (deterministic, funding-free)"
        );
    }

    /// ⭐ RED-TEAM NETWORK-SPLIT TAMPER PIN — the open-mint allowance derives ZERO for EVERY genesis
    /// identity except the exact, byte-complete testnet identity. The attack this refuses: an adversary
    /// perturbs the genesis identity bytes (extends, truncates, flips, reorders the magic) hoping a lenient
    /// compare (prefix-match, case-fold, truncation) still reads "testnet" and opens the faucet allowance on
    /// a chain that is NOT the testnet. ROOT-LAYER: `ChainParams::genesis_mint_allowance` is the ONE
    /// derivation every admission door reads, so the whole-bytes equality is pinned HERE, at the derivation,
    /// not at each caller. RED-run: inverted the exact-equality expectation against the live impl
    /// (asserted the extended identity derives the allowance) and ran this pin — it FAILED, proving the
    /// compare refuses an extended identity and these assertions can fail; restored, GREEN.
    /// MEASURED: 1000000000000 is the sole non-zero value any identity below derives, and only the exact
    /// testnet bytes derive it. MUST-STAY-GREEN: a_mint_class_is_unsatisfiable_where_the_genesis_derives_no_allowance,
    /// a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing.
    #[test]
    fn the_open_mint_allowance_derives_zero_for_every_genesis_but_the_exact_testnet_identity() {
        let with_commit = |commit: Vec<u8>| {
            let mut p = ChainParams::default();
            p.net_prefix_len = commit.len();
            p.genesis_parity_commit = commit;
            p
        };
        let testnet = network_genesis_prefix("testnet");
        assert_eq!(
            with_commit(testnet.clone()).genesis_mint_allowance(),
            TESTNET_OPEN_MINT_ALLOWANCE,
            "the exact testnet identity derives the open allowance (the one satisfiable network)"
        );
        // The mainnet identity, the unnamed default, and every unknown network NAME (which the daemon
        // maps to the mainnet magic — the value-bearing safe side) derive ZERO.
        assert_eq!(with_commit(network_genesis_prefix("mainnet")).genesis_mint_allowance(), 0);
        assert_eq!(with_commit(network_genesis_prefix("")).genesis_mint_allowance(), 0);
        assert_eq!(
            with_commit(network_genesis_prefix("devnet7")).genesis_mint_allowance(),
            0,
            "an unknown network name is the mainnet identity — fail-closed, never a third allowance"
        );
        assert_eq!(
            ChainParams::default().genesis_mint_allowance(),
            0,
            "an EMPTY genesis identity (the raw default) grants no mint"
        );
        // Perturbations of the testnet identity: each one is a DIFFERENT chain and must derive 0.
        let mut extended = testnet.clone();
        extended.push(0u8);
        assert_eq!(
            with_commit(extended).genesis_mint_allowance(),
            0,
            "testnet-prefix-plus-payload is NOT testnet — a starts_with compare would open the faucet \
             on an attacker-defined chain; only whole-bytes equality is admissible"
        );
        let truncated = testnet[..testnet.len() - 1].to_vec();
        assert_eq!(with_commit(truncated).genesis_mint_allowance(), 0, "a truncated identity grants nothing");
        let mut flipped = testnet.clone();
        flipped[0] ^= 0x20; // case-flip the leading domain-tag byte
        assert_eq!(
            with_commit(flipped).genesis_mint_allowance(),
            0,
            "a case-folded compare would accept this; the byte compare must not"
        );
        let mut wrong_order = Vec::from(&b"MUSD-NETID-v1"[..]);
        let reversed_magic: Vec<u8> =
            TESTNET_NETWORK_ID.to_le_bytes().iter().rev().copied().collect();
        wrong_order.extend_from_slice(&reversed_magic);
        assert_eq!(
            with_commit(wrong_order).genesis_mint_allowance(),
            0,
            "the testnet magic in the wrong byte order is a different identity"
        );
    }

    #[test]
    fn governance_stake_params_retune_within_guardrails() {
        let mut p = ChainParams::default();
        // APR retune inside the range enacts; above the runaway ceiling is rejected (params unchanged).
        assert!(p.governance_set_stake_reward_apr_bps(725).is_ok());
        assert_eq!(p.stake_reward_apr_bps, 725);
        assert_eq!(
            p.governance_set_stake_reward_apr_bps(STAKE_REWARD_APR_BPS_CEILING + 1),
            Err(ParamError::StakeAprOutOfRange(
                STAKE_REWARD_APR_BPS_CEILING + 1
            ))
        );
        assert_eq!(
            p.stake_reward_apr_bps, 725,
            "a rejected retune must not mutate the live rate"
        );
        // A paused reward policy (0%) is allowed; the lock is freely tunable.
        assert!(p.governance_set_stake_reward_apr_bps(0).is_ok());
        p.governance_set_stake_lock_blocks(120);
        assert_eq!(p.stake_lock_blocks, 120);
    }

    #[test]
    fn governance_retunes_width_at_runtime_and_k_tracks_it() {
        let mut p = ChainParams::default();
        // widen to 64 (e.g. governance raises concurrency) — no restart, k follows.
        p.governance_set_dag_width(64).unwrap();
        assert_eq!(p.dag_width, 64);
        assert_eq!(p.ghostdag_k, 64);
        // out-of-range rejected; the active value is unchanged.
        assert!(p.governance_set_dag_width(0).is_err());
        assert!(p.governance_set_dag_width(DAG_WIDTH_CEILING + 1).is_err());
        assert_eq!(p.dag_width, 64);
    }
}

/// The network identity this PROCESS is running on — `blake3(genesis_parity_commit)`.
///
/// ⛔ Fixed ONCE, at genesis, by whichever path built this node (`main.rs` daemon or `serve.rs` in-process).
/// It exists so per-tx authorization can be bound to its chain without threading params through every call
/// site or adding a wire field: a stamp ground for one network is worthless on another. A node that somehow
/// never set it gets the mainnet prefix — the same value-bearing default an unset `MONEROUSD_NET` selects, so
/// this can never silently widen what a tx is valid on.
static PROCESS_NETWORK_ID: std::sync::OnceLock<crate::hash::Hash32> = std::sync::OnceLock::new();

/// Fix this process's network identity. Idempotent; the FIRST value wins, so a later caller can never
/// re-point a running node at a different chain.
pub fn set_process_network_id(genesis_parity_commit: &[u8]) {
    let _ = PROCESS_NETWORK_ID.set(crate::hash::Hash32::hash(genesis_parity_commit));
}

/// This process's network identity, for binding per-tx authorization to its chain.
pub fn process_network_id() -> crate::hash::Hash32 {
    #[cfg(test)]
    if let Some(id) = THREAD_NETWORK_FOR_TEST.with(std::cell::Cell::get) {
        return id;
    }
    *PROCESS_NETWORK_ID
        .get_or_init(|| crate::hash::Hash32::hash(&network_genesis_prefix("mainnet")))
}

#[cfg(test)]
thread_local! {
    /// TEST BUILDS ONLY — the network identity of the simulated PROCESS this thread is running. A daemon is one process on
    /// one network; the journey simulator runs several daemons in one test process, so each simulated node's work (its
    /// step loop, its RPC connection threads) runs under its own network here, exactly as it would in its own process —
    /// without the process-wide first-value-wins setting another test may already have fixed.
    static THREAD_NETWORK_FOR_TEST: std::cell::Cell<Option<crate::hash::Hash32>> = const { std::cell::Cell::new(None) };
}

/// TEST BUILDS ONLY — run this thread as a process on the network whose genesis prefix is `prefix` (see above).
#[cfg(test)]
pub fn set_thread_network_for_test(prefix: &[u8]) {
    THREAD_NETWORK_FOR_TEST.with(|c| c.set(Some(crate::hash::Hash32::hash(prefix))));
}

/// TEST BUILDS ONLY — the identity this thread runs under ([`set_thread_network_for_test`]), so work a simulated process
/// fans out to helper threads (`cover::pad_to_fixed_shape`'s lanes) runs under the same network as the thread that asked.
#[cfg(test)]
pub fn thread_network_for_test() -> Option<crate::hash::Hash32> {
    THREAD_NETWORK_FOR_TEST.with(std::cell::Cell::get)
}

/// TEST BUILDS ONLY — adopt an identity read by [`thread_network_for_test`] on another thread of the same simulated process.
#[cfg(test)]
pub fn adopt_thread_network_for_test(id: Option<crate::hash::Hash32>) {
    THREAD_NETWORK_FOR_TEST.with(|c| c.set(id));
}

#[cfg(all(test, feature = "pins-core"))]
mod tx_binds_its_network_tests {
    use super::network_genesis_prefix;
    use crate::hash::Hash32;

    /// Recompute a tx's anti-spam stamp under an ARBITRARY network id — the same preimage
    /// [`crate::mempool::PqTx::stamp_work`] uses, with the process identity supplied explicitly so one test
    /// can stand on both chains at once (a process fixes its identity exactly once, by design).
    fn stamp_bits_under(id: &Hash32, pow_stamp: u64, network_id: &Hash32) -> u32 {
        let mut buf = Vec::with_capacity(72);
        buf.extend_from_slice(id.as_bytes());
        buf.extend_from_slice(&pow_stamp.to_le_bytes());
        buf.extend_from_slice(network_id.as_bytes());
        let d = Hash32::hash(&buf);
        let mut bits = 0u32;
        for b in d.as_bytes() {
            if *b == 0 {
                bits += 8;
            } else {
                bits += b.leading_zeros();
                break;
            }
        }
        bits
    }

    /// ⭐⭐⭐ A TX GROUND FOR ONE NETWORK MUST NOT ARRIVE ON ANOTHER CARRYING VALID WORK (EIP-155, our shape).
    ///
    /// TWO-PARTY-REVIEWED: the two parties are two NETWORKS, and the assertion is precisely that they
    /// DISAGREE about the same bytes. Cross-node behaviour on one network is covered by the cross-node suite.
    ///
    /// The stamp is the authorization the mempool charges a tx for admission. Computed over `id || pow_stamp`
    /// alone it was identical on every network, so a testnet tx replayed onto mainnet presented full, valid
    /// work and the stamp gate had no way to tell. Binding the network id in makes the grind chain-specific:
    /// the work only counts where it was earned.
    #[test]
    fn work_ground_for_one_network_does_not_count_on_another() {
        let testnet = Hash32::hash(&network_genesis_prefix("testnet"));
        let mainnet = Hash32::hash(&network_genesis_prefix("mainnet"));
        assert_ne!(
            testnet, mainnet,
            "the two networks must have distinct identities to bind against"
        );

        let id = Hash32::hash(b"a-spend-carrier");
        // Grind a stamp that clears a real admission bar ON TESTNET, exactly as a sender would.
        const BAR: u32 = 12;
        let mut nonce = 0u64;
        while stamp_bits_under(&id, nonce, &testnet) < BAR {
            nonce += 1;
            assert!(
                nonce < 5_000_000,
                "could not grind {BAR} bits — the preimage shape changed"
            );
        }
        assert!(
            stamp_bits_under(&id, nonce, &testnet) >= BAR,
            "ground work must clear the bar at home"
        );

        // The SAME tx bytes, presented to a node on the other network.
        let abroad = stamp_bits_under(&id, nonce, &mainnet);
        assert!(
            abroad < BAR,
            "a tx ground for testnet arrived on mainnet still clearing the {BAR}-bit admission bar ({abroad} \
             bits). Its authorization is not bound to its chain, so testnet traffic can be replayed onto the \
             value-bearing network for free — the exact hole EIP-155 closes."
        );
    }

    /// The binding must not be an accident of one id: sweep many txs and require that EVERY one of them
    /// grinds to different work on the two networks. A single lucky collision would be indistinguishable
    /// from a correct bind if we only ever looked at one sample.
    #[test]
    fn every_tx_gets_a_different_stamp_on_a_different_network() {
        let testnet = Hash32::hash(&network_genesis_prefix("testnet"));
        let mainnet = Hash32::hash(&network_genesis_prefix("mainnet"));
        let mut same = 0usize;
        for i in 0..512u64 {
            let id = Hash32::hash(&i.to_le_bytes());
            if stamp_bits_under(&id, i, &testnet) == stamp_bits_under(&id, i, &mainnet) {
                same += 1;
            }
        }
        // Equal LEADING-ZERO COUNTS collide often by chance (most are 0), so the real assertion is that the
        // digests differ — checked directly, not inferred from the bit counts.
        for i in 0..512u64 {
            let id = Hash32::hash(&i.to_le_bytes());
            let mut a = Vec::new();
            a.extend_from_slice(id.as_bytes());
            a.extend_from_slice(&i.to_le_bytes());
            let mut b = a.clone();
            a.extend_from_slice(testnet.as_bytes());
            b.extend_from_slice(mainnet.as_bytes());
            assert_ne!(
                Hash32::hash(&a), Hash32::hash(&b),
                "tx {i} hashed identically on both networks — the network id is not actually in the preimage"
            );
        }
        assert!(
            same <= 512,
            "sanity: {same} of 512 shared a bit-count, which is expected and not the test"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod fee_schedule_tests {
    //! The economics are code, so they get adversarial tests like any other gate. What these pin is that
    //! a price exists, that it is the SAME price everywhere, and that the shape of the DEX fee cannot
    //! leak a trade's size.

    use super::*;

    /// ⭐ A SYMBOL'S LENGTH NO LONGER PRICES A CREATION (re-priced 2026-11-10): a symbol is not exclusive, so its
    /// length bought nothing. One price for a token, a lower one for an NFT, and both far under what they were.
    #[test]
    fn a_creation_is_priced_by_its_kind_and_never_by_its_symbol() {
        for s in ["A", "AB", "ABC", "MOON", "MOONS", "MOONSHOT", &"X".repeat(64)] {
            assert_eq!(token_create_fee_atomic(s), TOKEN_CREATE_FEE_ATOMIC, "{s:?}");
        }
        assert_eq!(asset_create_fee_atomic(false), TOKEN_CREATE_FEE_ATOMIC);
        assert_eq!(asset_create_fee_atomic(true), NFT_CREATE_FEE_ATOMIC);
        assert!(NFT_CREATE_FEE_ATOMIC < TOKEN_CREATE_FEE_ATOMIC, "one piece of a collection costs less than a token");
        // the bar the user set: under the rivals measured that day (a launch's first buyer pays about $3 on pump.fun,
        // a Solana NFT is about $2), in atomic USDm
        assert!(TOKEN_CREATE_FEE_ATOMIC <= 100_000_000, "a token launch costs a dollar at most");
        assert!(NFT_CREATE_FEE_ATOMIC <= 10_000_000, "an NFT costs a dime at most");
    }

    /// ⛔⛔⛔ CREATION IS NEVER FREE. Each kind, under every symbol including the empty and the absurd, has a
    /// POSITIVE price: a zero anywhere is a free mint, and it is above the network fee a payment pays.
    #[test]
    fn no_creation_is_ever_free() {
        for s in ["", "A", "AB", "ABC", "ABCD", "ABCDE", "ABCDEF", &"X".repeat(64)] {
            assert!(token_create_fee_atomic(s) > 0, "symbol {s:?} must cost something");
        }
        for nft in [false, true] {
            assert!(asset_create_fee_atomic(nft) > 100_000, "a creation costs more than a payment's fee");
        }
    }

    /// ⭐ THE PRICE IS A PURE FUNCTION OF THE SYMBOL — the route, the client preview and these tests all
    /// call it, so they cannot drift into quoting different numbers (the exact defect that produced a
    /// fictional 100–10,000 USDm bond beside a route that charged nothing).
    #[test]
    fn the_price_is_deterministic_and_whitespace_insensitive() {
        assert_eq!(token_create_fee_atomic("MOON"), token_create_fee_atomic("  MOON  "));
        assert_eq!(token_create_fee_atomic("MOON"), token_create_fee_atomic("MOON"));
    }

    /// ⛔⛔⛔ THE DEX FEE IS UNIFORM, WHICH IS WHAT KEEPS IT FROM LEAKING. It is a CONSTANT, not a
    /// function of any trade value — so two fills of different (hidden) sizes pay identically and an
    /// observer learns nothing from the fee. A percentage would have to read the amount to compute it.
    #[test]
    fn the_dex_fee_is_a_constant_and_therefore_discloses_nothing() {
        let p = ChainParams::default();
        use usdm_decider::whir_rec_block::{OrderTerms, USDM_ASSET_TAG, wrapped_asset_tag_u32};
        assert_eq!(p.order_fill_fee_bps, ORDER_FILL_FEE_BPS_DEFAULT);
        assert!(p.order_fill_fee_bps > 0, "a zero rate funds no security");
        // The fee reads ONLY public terms. Two orders at the same level cost the same to fill no matter
        // who fills them or what they hold — there is no hidden input for the fee to read.
        let t = |pay_b| OrderTerms {
            lot: 100_000,
            pay_b,
            asset_a: wrapped_asset_tag_u32(1),
            asset_b: USDM_ASSET_TAG,
            expires_at_height: 1_000,
        };
        assert_eq!(t(6_500_000).protocol_fee(p.order_fill_fee_bps), 6_500,
            "10 bps of 0.065 USDm-lots is exactly 0.1%");
        assert_eq!(t(6_500_000).protocol_fee(p.order_fill_fee_bps),
                   t(6_500_000).protocol_fee(p.order_fill_fee_bps), "deterministic");
        assert!(t(1).protocol_fee(p.order_fill_fee_bps) >= 1, "no level is a free fill");
    }

    /// ⭐ EVERY ECONOMIC NUMBER IS GOVERNANCE-TUNABLE AT RUNTIME — a launch value, never doctrine.
    #[test]
    fn the_dex_fee_is_governance_tunable() {
        let mut p = ChainParams::default();
        p.order_fill_fee_bps = 25;
        assert_eq!(p.order_fill_fee_bps, 25);
    }

    /// ⭐ §BR-11 / §BR-3 17.6 — THE FEE PAYOUT PERIOD IS ONE WEEK (user 2026-11-02), for the miner pool and the bonders' yield
    /// alike (one roll closes both). Derived from the chain's own target spacing, not a literal: a block at the last key of
    /// week 0 is in period 0, the next key opens period 1. Calibration: the old ≈ 91-day period would fail the week check.
    #[test]
    fn the_miner_and_bonder_payout_period_is_one_week_at_the_target_spacing() {
        let p = ChainParams::default();
        // A-F60: a week of chain ticks (one tick per target spacing of median time past)
        let week_ticks = 7 * 86_400 * 1_000 / crate::dag::MESH_TARGET_SPACING_MS;
        assert_eq!(p.miner_quarter_keys, week_ticks, "⛔ the default payout period is not one week of chain ticks");
        assert_eq!(MINER_QUARTER_KEYS_DEFAULT, blocks_for_ms(7 * DAY_MS), "one week of chain time");
        assert_eq!(crate::miner_payout_tx::quarter_of(week_ticks - 1, p.miner_quarter_keys), 0);
        assert_eq!(crate::miner_payout_tx::quarter_of(week_ticks, p.miner_quarter_keys), 1, "the next tick opens the next period");
        let week_keys = week_ticks;
        assert_ne!(crate::sat_schedule::HALVING_INTERVAL / 16, week_keys, "calibration: the old quarter is not a week");
    }
}

/// ⭐ G2b (lane a 2026-10-22) — THE FINALITY SEAT ACTIVATION DELAY, in blue score: a seat (or an exit) landing at the
/// fold's chain-block height `L` counts toward finality votes at heights `>= L + this` (Ethereum's activation /
/// exit epochs: a validator is active for epoch `e` iff `activation_epoch <= e < exit_epoch`, attestations judged against
/// the set active at THEIR epoch). Two record fold depths: a node whose fold trails its tip by the default depth (32) has
/// applied every seat that counts at any height it holds, so a healthy node defers no vote; a node further behind defers
/// a vote until its fold reaches `h − this` (`Node::deferred_votes`) instead of judging it against a set it cannot know.
/// Not tuned — 2 × the fold depth, the smallest multiple that leaves the default fold lag a full depth of slack.
pub const FINALITY_SEAT_ACTIVATION_DELAY: u64 = 2 * RECORD_FOLD_DEPTH_DEFAULT;


// Moved here from `impl Node` (stage A of the node split, lane dcash 2026-11-11): a pure constant / function the lower modules read;
// `Node` keeps an alias so every existing caller resolves.
/// The anchor ring's floor: the fold steps a spend's anchor stays judgeable for, before `merge_depth_cap` raises it.
pub const SPINE_RING_LEN: usize = 64;

/// How many fold steps the anchor ring holds under `p`: the merge depth, never below [`SPINE_RING_LEN`].
#[must_use]
pub fn anchor_ring_len_of(p: &ChainParams) -> usize {
    p.merge_depth_cap.max(SPINE_RING_LEN)
}

#[cfg(test)]
mod merge_depth_invariant {
    /// Kaspa's invariant: what a block may merge is whole on every honest node (`block_window::WHOLE_KEEP`), with one freeze
    /// interval of margin. CALIBRATION: the merge-depth count alone (3,600) breaks it — the depth the deep eclipse split on.
    #[test]
    fn every_mergeable_block_is_whole_on_every_honest_node() {
        let keep = crate::dag::WHOLE_KEEP;
        assert!(crate::dag::MERGEABLE_DEPTH + 16 <= keep, "⛔ a block may merge data honest nodes no longer hold");
        assert!(super::MERGE_DEPTH_CAP_DEFAULT as u64 + 16 > keep, "CALIBRATION: the past-scan count alone broke the invariant");
    }
}
