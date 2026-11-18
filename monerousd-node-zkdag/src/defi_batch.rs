// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.8) — THE PRIVATE DeFi LAYER'S CHAIN OBJECTS: sealed orders, the audited batch settlement, the expiry
//! of a batch nobody settled, and the claim that pays an order (or refunds it) without naming it.
//!
//! **The pair.** SAT (X) / USDm (Y) against the keyless pool the custody set holds as Shamir shares of 2^255 − 19
//! (`usdm_decider::br15_audit`). A buy pays USDm and is paid `⌊y / p_{t+1}⌋` SAT at its batch's tick (`defi_clear`).
//!
//! **The life of an order.**
//! 1. [`DefiOrderTx`] — the owner burns a USDm note (the peg-out's committed burn, borrowed: the amount stays a commitment
//!    `bc`), deals its two Shamir sharings to the custody roster (`OrderDealing`, sealed to each custodian), and proves the
//!    shares open to `bc` (`order_share_circuit`). The fold appends `(bc, share commitments)` to the OPEN batch.
//! 2. [`DefiSettleTx`] — the custody set's settlement of that batch: the tick, every custodian's phase-1 digest, published
//!    openings and audit proof (`custodian_audit_prove`), and its new pool commitment. Every node forms each audit's
//!    circuit from public data, verifies every proof, checks every published sharing (degree, constant), then INSERTS one
//!    claim leaf per order (`claim_leaf(bc, d_{t+1}, n_{t+1})`) into the note set and opens the next batch.
//! 3. [`DefiExpireTx`] — a batch not settled within [`EXPIRE_MS`] of chain time from its open is expired by anyone: its orders'
//!    REFUND leaves (`claim_leaf(bc, 1, 1)`) enter the note set, the pool is unchanged, the next batch opens.
//! 4. [`DefiClaimTx`] — the owner proves (`claim_circuit`) its order's fill against a leaf its member leg proves is in the
//!    note set, spends the order's ONE nullifier, and mints the SAT (or the refunded USDm) as a committed asset mint. The claim
//!    names no order, no batch and no tick.
//!
//! **What the chain shows (separation clause, spec §18.1):** one tick per batch, every batch; never volume, depth or fills.
//! NO GROWTH: node state is the open batch's orders (cleared at every settlement or expiry) and one pool commitment per
//! custodian; a settled order's right lives as a leaf in the note set like any note.
//! O1-INFINITY-REVIEWED: every loop here walks the OPEN batch's orders (at most the orders [`BATCH_STEPS`] fold steps of blocks
//! carry, cleared every batch) or the custody roster ([`MAX_ROSTER`]) — fixed bounds, never the chain's history or total.
//!
//! ROOT-LAYER: these are the objects' own decode rules and verdicts — where the chain DECIDES an order, a settlement, an
//! expiry or a claim; the fold applies only what a verdict accepted, and the decider's circuits are the proofs' producers.
//! MEASURED: the decider pins this module verifies against — the audit (2^22 rows, verified against the formed circuit), the
//! claim (16,384 rows, 87 ms), the order's shares (65,536 rows at n = 7); the node pins land with the fold integration.
//! MUST-STAY-GREEN: every `br15_*` pin of `usdm_decider::br15_audit`; the peg-out burn door this order's burn borrows.
//!
//! BORROWED: Penumbra's batch swap and SwapClaim (orders sealed into a batch, claimed at the batch price by the owner);
//! Uniswap v2's curve and v3's ticks; Zcash's nullifier set (one claim per order); Baum–Damgård–Orlandi 2014 publicly
//! auditable MPC (each custodian proves its own steps). None — novel crypto: the audited-pair settlement.

use p3_field::{PrimeCharacteristicRing, PrimeField64};
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// How many fold steps a batch gathers orders (2 s at the 500 ms target): buyers hand their order slots to the custody set,
/// which publishes the batch's [`SLOTS`] at the close (spec §18.12); a slot that misses a batch rides the next one.
pub const BATCH_STEPS: u64 = 4;
/// ⭐ §18.14 — THE PAIRS: SAT/BTC (0) and SAT/XMR (1), one book, one price and one batch each, SAT the hub.
pub const PAIRS: u8 = 2;

/// The asset a pair's Y side is: its coin ledger's note.
#[must_use]
pub fn pair_y_tag(pair: u8) -> [u64; 3] {
    usdm_decider::whir_rec_block::wrapped_asset_tag_u32(if pair == 0 { crate::peg::COIN_BTC_ASSET_ID } else { crate::peg::COIN_XMR_ASSET_ID })
}
/// How long after it opens a batch may still be settled, on the CHAIN CLOCK (median-time-past of the carrying block,
/// `Node::chain_time_ms_at`); past it, anyone expires it (every order refunds). It was 120 fold steps, "60 s at the
/// target", and the chain has never run at the target: at the measured ~5 blocks a minute it was ~20 min, and it would
/// shrink with every gain in block rate. MEASURED 2026-11-08/09 on real nodes (two custodians, Tor, one machine shared by
/// up to ten nodes at load 50–180): honest engine runs took 895–1,790 s, several batches closing with the run 20–50 s short
/// and every order refunded. The window is 1.5 × the worst honest run measured (1,790 s), so an honest batch settles
/// before anyone may expire it at any block rate. cons: a batch whose custody set is offline refunds 45 min after it
/// opened, and its pair's next batch opens then.
pub const EXPIRE_MS: u64 = 45 * 60_000;

#[cfg(test)]
thread_local! {
    /// Test seam: a pin's settlement window, so a two-node pin that steps its blocks 600 ms apart reaches an expiry.
    /// Production always reads [`EXPIRE_MS`].
    pub static TEST_EXPIRE_MS: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// The settlement window, [`EXPIRE_MS`] (a test may shorten it on its own thread).
#[must_use]
pub fn expire_ms() -> u64 {
    #[cfg(test)]
    if let Some(n) = TEST_EXPIRE_MS.with(std::cell::Cell::get) {
        return n;
    }
    EXPIRE_MS
}
/// The custody roster's bound (the share proof and the audit grow with it).
pub const MAX_ROSTER: usize = 64;
/// A sealed share's width, exact (every order's sealed shares are byte-shape-identical): one ML-KEM-768 ciphertext, a 16-byte
/// tag and the masked line shares and salt (`defi_custody::SHARE_PLAIN_BYTES`: the X line and one Y line per maximum-price bucket).
pub const SEALED_BYTES: usize = 1_088 + 16 + 32 * ba::ORDER_LINES + 16;
/// Any one proof's bound (the WHIR committed argument's largest measured proof is ~150 KB).
pub const MAX_PROOF_BYTES: usize = 1 << 20;

/// A published share-field element on the wire: four little-endian 64-bit words.
pub type Word = [u64; 4];

/// ⭐ FIXED-WIDTH DIGEST LANES on the wire (a user's order and claim): each KoalaBear lane as exactly 4 little-endian bytes —
/// never a varint — so an object's byte length is a function of its shape alone (DIGITAL CASH: constant shape; MEASURED by
/// `br15_only_the_clearing_price_is_opened`: two orders of different amounts encoded 9,588 and 9,587 bytes under varints). A
/// lane at or above the field's modulus is refused (one object, one encoding: no second spelling of a lane).
const KOALA_P: u64 = 0x7F00_0001;
fn lane_bytes(v: u64) -> [u8; 4] {
    u32::try_from(v).unwrap_or(u32::MAX).to_le_bytes()
}
fn lane_of(b: &[u8]) -> Option<u64> {
    let v = u64::from(u32::from_le_bytes(b.try_into().ok()?));
    (v < KOALA_P).then_some(v)
}
mod lanes8 {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u64; 8], s: S) -> Result<S::Ok, S::Error> {
        let mut b = [0u8; 32];
        for (i, x) in v.iter().enumerate() {
            b[4 * i..4 * i + 4].copy_from_slice(&super::lane_bytes(*x));
        }
        serde::Serialize::serialize(&b, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u64; 8], D::Error> {
        let b = <[u8; 32]>::deserialize(d)?;
        let mut out = [0u64; 8];
        for (i, x) in out.iter_mut().enumerate() {
            *x = super::lane_of(&b[4 * i..4 * i + 4]).ok_or_else(|| D::Error::custom("a digest lane at or above the field modulus"))?;
        }
        Ok(out)
    }
}
mod lanes4v {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[[u64; 4]], s: S) -> Result<S::Ok, S::Error> {
        let rows: Vec<[u8; 16]> = v
            .iter()
            .map(|r| {
                let mut b = [0u8; 16];
                for (i, x) in r.iter().enumerate() {
                    b[4 * i..4 * i + 4].copy_from_slice(&super::lane_bytes(*x));
                }
                b
            })
            .collect();
        serde::Serialize::serialize(&rows, s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u64; 4]>, D::Error> {
        let rows = <Vec<[u8; 16]>>::deserialize(d)?;
        rows.iter()
            .map(|b| {
                let mut out = [0u64; 4];
                for (i, x) in out.iter_mut().enumerate() {
                    *x = super::lane_of(&b[4 * i..4 * i + 4]).ok_or_else(|| D::Error::custom("a commitment lane at or above the field modulus"))?;
                }
                Ok(out)
            })
            .collect()
    }
}

/// One order of the open batch, as the book holds it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BookOrder {
    /// the burned amount's commitment `bc = solvency_commit_256(a, a_blind)`
    pub amount_commit: [u64; 8],
    /// the order's maximum-price bucket, committed under the same blind (`br15_audit::limit_commit`) — hidden
    pub limit_commit: [u64; 8],
    /// one share commitment per custodian of the book's roster (in roster order)
    pub share_commits: Vec<[u64; 4]>,
}

/// ⭐ THE BOOK: the custody roster the pool is shared among, its threshold, each custodian's pool commitment, the open batch
/// and its orders, and the last tick. A function of the canonical fold; journaled with the peg ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiBook {
    /// ⭐ §18.14 — which pair this book trades ([`PAIRS`])
    pub pair: u8,
    /// custody ids, in the order their shares are evaluated (custodian i at x = i + 1)
    pub roster: Vec<[u8; 32]>,
    /// O1-FOOTPRINT-REVIEWED: each custodian's ML-KEM-768 custody key (roster order, at most `MAX_ROSTER`) — what an order
    /// seals its shares to (`defi_custody::seal_dealing`).
    pub eks: Vec<Vec<u8>>,
    pub t: u32,
    /// custodian i's commitment to its pool shares (`br15_audit::pool_commit_of`)
    pub pool_commits: Vec<[u64; 4]>,
    /// ⭐ EARN STEP 1 — custodian i's commitment to its share of the pair's FEE LINE Φ (`br15_audit::fee_commit`): born at the
    /// launch as the public zero ([`launch_fee_commits`]), moved only by an audited settlement (`Φ + φ_s + φ_b`) and carried
    /// across a custody handover with the pool. What a provider's income is paid from (Earn step 2). No node ever learns Φ:
    /// a fee line in the clear would be the pair's cumulative volume. O1-FOOTPRINT-REVIEWED: one per roster member
    /// (`MAX_ROSTER`), the same bound as `pool_commits`.
    #[serde(default)]
    pub fee_commits: Vec<[u64; 4]>,
    pub batch: u64,
    /// the fold ordinal at which the open batch opened
    pub opened_at: u64,
    /// the chain clock (unix ms) of the fold step that opened the open batch — what [`EXPIRE_MS`] counts from; 0 until the
    /// first DeFi object of a batch that opened at launch folds, which stamps it
    #[serde(default)]
    pub opened_ms: u64,
    /// O1-FOOTPRINT-REVIEWED: the OPEN batch's orders only — at most what [`BATCH_STEPS`] fold steps of blocks carry, cleared
    /// at every settlement or expiry; a settled order lives on as a note-set leaf, never here.
    pub orders: Vec<BookOrder>,
    /// whether the open batch's slots (spec §18.12) have applied — every one of its [`SLOT_PARTS`] parts, once per batch
    #[serde(default)]
    pub slotted: bool,
    /// which of the open batch's slot parts have applied (bit p = part p)
    #[serde(default)]
    pub slot_parts: u8,
    pub last_tick: i64,
    /// whether the last closed batch EXPIRED (its orders refund) rather than settled at `last_tick` — what a wallet reads to
    /// learn its batch's outcome
    #[serde(default)]
    pub last_expired: bool,
    /// ⭐ THE OPEN BATCH'S HELD SETTLEMENT PARTS (spec §18.11): a settlement too large for one transaction travels as CHUNKS,
    /// each verified on its own as it folds; slot i holds custodian i's verified part (the first one to verify) until the
    /// closing chunk completes the batch. O1-FOOTPRINT-REVIEWED: at most one slot per roster member (`MAX_ROSTER`), cleared at
    /// every settlement or expiry.
    #[serde(default)]
    pub pending: Vec<Option<HeldPart>>,
    /// ⭐ THE OPEN CUSTODY HANDOVER (spec §18.11, `defi_handover`): the bonded custody set the pool moves to, the dealings and
    /// acceptances so far; while `frozen`, no order and no settlement applies (every dealing is over one pool).
    #[serde(default)]
    pub handover: Option<crate::defi_handover::Handover>,
    /// ⭐ §18.14 — whether the last settled batch's sells counted (the floor bit it opened), what a seller's wallet reads
    #[serde(default)]
    pub last_sells: bool,
    /// ⭐ §18.15 — the pair's price history, what the wallet's chart draws: the closed list's one price per batch, nothing else
    #[serde(default)]
    pub prices: PriceHistory,
    /// ⭐ EARN STEP 3 — the pair's INCOME INDEX: SAT per unit × 2^INCOME_SHIFT, public, raised only by a folded `EarnEpoch`
    /// (one protocol-wide rate per window, docs/COIN-POOL-DEPOSITS-SPEC-20261111.md "Step 3 REFUTED … the replacement"). No
    /// leaf names it: every ORDER carries its batch's opening snapshot ([`DefiBook::batch_index`]), so a deposit's units enter
    /// at it and a withdrawal is paid `u·(now − entry)`. 0 until the first raise.
    #[serde(default)]
    pub income_index: u64,
    /// ⭐ EARN STEP 3 — custodian i's commitment to its share of the CLOSED window's lines (E_c, A_c), beside `fee_commits`
    /// (now over the open fee state B, E, A): born at the launch as public zeros, moved by the batch that closes a window and
    /// the batch that merges it, carried across a handover. No batch touches it between the close and the merge, so the
    /// EarnEpoch's audit over it never meets a moved commitment. O1-FOOTPRINT-REVIEWED: one per roster member (`MAX_ROSTER`).
    #[serde(default)]
    pub close_commits: Vec<[u64; 4]>,
    /// ⭐ EARN STEP 3 — THE OPEN BATCH'S SNAPSHOT, taken when it OPENED ([`DefiBook::next_batch`]): the income index every
    /// order of it carries (and the slots refuse an order made for another); the raised rate it merges (`Some(dG)` for the
    /// first batch after a raise); whether it closes the window, is the pair's deposit batch (the only batch whose deposits
    /// count), and samples presence (an Earn batch while the pair samples). A raise that folds while a batch is open changes
    /// none of these: the batch's custody run and its settlement's verdict read the same snapshot.
    #[serde(default)]
    pub batch_index: u64,
    #[serde(default)]
    pub merge_dg: Option<u64>,
    #[serde(default)]
    pub close_out: bool,
    #[serde(default)]
    pub deposits: bool,
    #[serde(default)]
    pub sample: bool,
    /// ⭐ EARN STEP 3 — the pair's window counters: windows closed, raised (by a folded EarnEpoch), and whose deposit batch
    /// settled — `raised ≤ closed ≤ raised + 1` and `deposited ≤ raised`; the chain-clock window of the last close; whether
    /// the pair samples presence (from its deposit batch's settlement to its next close; on from the launch)
    #[serde(default)]
    pub closed: u64,
    #[serde(default)]
    pub raised: u64,
    #[serde(default)]
    pub deposited: u64,
    #[serde(default)]
    pub close_window: u64,
    #[serde(default)]
    pub sampling: bool,
    /// ⭐ EARN STEP 3 — the presence weight's PUBLIC side: Σ over the open window's samples of `2/r'` per unit (× 2^32, toward
    /// the pool: `r' = sqrt_up(a + 1)` at each Earn tick), and the closed window's, which the raise multiplies by the rate
    #[serde(default)]
    pub w_open: u128,
    #[serde(default)]
    pub w_closed: u128,
    /// ⭐ EARN STEP 3 — a raise's rate awaiting this pair's next batch to open, which merges it ([`DefiBook::next_batch`])
    #[serde(default)]
    pub pending_dg: Option<u64>,
    /// ⭐ EARN STEP 3 — THE EARNEPOCH'S HELD PARTS (pair 0's book holds them for the protocol): an EarnEpoch too large for one
    /// transaction travels as chunks, as a settlement does; slot i holds custodian i's verified part until the closing chunk.
    /// O1-FOOTPRINT-REVIEWED: at most one slot per roster member (`MAX_ROSTER`), cleared at every raise.
    #[serde(default)]
    pub epoch_pending: Vec<Option<HeldEpochPart>>,
}

/// A custodian's verified part of an EarnEpoch, held until the closing chunk: the header it verified under and what it
/// published.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeldEpochPart {
    pub header: [u8; 32],
    pub published: Vec<(Word, Vec<Word>, Vec<Word>)>,
}

/// ⭐ EARN STEP 3 — one Earn sample's public weight `⌊2·2^32 / r'⌋` per unit, `r' = defi_earn::sqrt_up(tick + 1)` (a unit's SAT
/// value is at least `2/r'` at a tick that brackets the pool's ratio: the c'-bound `X ≥ S/√p`), rounded down — toward the pool.
#[must_use]
pub fn sample_weight(tick: i64) -> u128 {
    let (un, ud) = crate::defi_earn::sqrt_up(tick + 1);
    if un == 0 {
        return 0;
    }
    (ud << 33) / un
}

/// Points kept at each resolution of [`PriceHistory`].
pub const PRICE_POINTS: usize = 120;
/// Resolutions of [`PriceHistory`]: a point every batch, every 8, 64, 512, 4096.
pub const PRICE_LEVELS: usize = 5;
/// Batches between points, each resolution to the next.
pub const PRICE_LEVEL_STEP: u64 = 8;

/// ⭐ §18.15 THE PRICE HISTORY: `(block time in seconds, tick)` rings, a function of the canonical fold, so a joining node and a restarted one hold the chart with no store of its own.
/// Fixed size: [`PRICE_LEVELS`] rings of [`PRICE_POINTS`] points, the oldest overwritten, never a term in height or trades.
/// Cons: at most 4.8 kB per pair in the journaled ledger, 9.6 kB for the two pairs, constant for ever; no block bytes.
/// DIGITAL-CASH-PRIVACY-REVIEWED: holds the price the separation clause already publishes every batch and the carrying block's own time; no volume, depth, order or owner.
/// BORROWED: RRDtool's round-robin archives (fixed rings at falling resolution).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PriceHistory {
    /// batches recorded, what picks the rings a new point enters
    pub count: u64,
    pub levels: Vec<Vec<(u32, i32)>>,
}

impl PriceHistory {
    /// One closed batch's price at its carrying block's time.
    pub fn record(&mut self, secs: u32, tick: i32) {
        self.count = self.count.saturating_add(1);
        self.levels.resize(PRICE_LEVELS, Vec::new());
        let mut every = 1u64;
        for ring in &mut self.levels {
            if self.count % every == 0 {
                if ring.len() == PRICE_POINTS {
                    ring.remove(0);
                }
                ring.push((secs, tick));
            }
            every = every.saturating_mul(PRICE_LEVEL_STEP);
        }
    }
}

/// A block stamp's units per second.
const BLOCK_TS_PER_SEC: u64 = 1_000;

/// A block stamp's whole seconds, as the price rings hold them.
fn block_secs(block_ts: u64) -> u32 {
    u32::try_from(block_ts / BLOCK_TS_PER_SEC).unwrap_or(u32::MAX)
}

/// A custodian's verified part of a settlement, held until the closing chunk: the settlement header it verified under
/// (`DefiSettleTx::header`), what it published and its new pool commitment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HeldPart {
    pub header: [u8; 32],
    pub published: Vec<(Word, Vec<Word>, Vec<Word>)>,
    pub new_pool: [u64; 4],
    /// ⭐ Earn step 1 — its new fee commitment
    pub new_fee: [u64; 4],
    /// ⭐ Earn step 3 — its new close commitment
    #[serde(default)]
    pub new_close: [u64; 4],
}

fn f4(v: &[u64; 4]) -> [Fa4; 4] {
    core::array::from_fn(|i| Fa4::from_u64(v[i]))
}
pub fn u4(v: &[Fa4; 4]) -> [u64; 4] {
    core::array::from_fn(|i| v[i].as_canonical_u64())
}

impl DefiBook {
    /// Whether the book is live (a roster holds the pool).
    #[must_use]
    pub fn is_open(&self) -> bool {
        !self.roster.is_empty()
            && self.pool_commits.len() == self.roster.len()
            && self.fee_commits.len() == self.roster.len()
            && self.close_commits.len() == self.roster.len()
            && self.eks.len() == self.roster.len()
    }
    /// The batch is closed for orders at `ordinal`.
    #[must_use]
    pub fn batch_closed(&self, ordinal: u64) -> bool {
        ordinal >= self.opened_at.saturating_add(BATCH_STEPS)
    }
    /// The batch may be expired at fold `ordinal`, chain time `chain_ms`: closed, and [`EXPIRE_MS`] of chain time since it
    /// opened (never before its open is stamped).
    #[must_use]
    pub fn batch_expired(&self, ordinal: u64, chain_ms: u64) -> bool {
        self.batch_closed(ordinal) && self.opened_ms != 0 && chain_ms >= self.opened_ms.saturating_add(expire_ms())
    }
    /// The next batch opens at fold `ordinal`, chain time `chain_ms` (the carrying block's own stamp: every node the same), and
    /// ⭐ Earn step 3 takes its SNAPSHOT ([`DefiBook::batch_index`] and the fee-state kind): it merges a raise that folded since
    /// the last opening; it is the pair's deposit batch when a raise has folded since the last deposit batch settled; it closes
    /// the window once the chain clock is past the last close's window, the last window was raised and its deposit batch
    /// settled; it samples when it is an Earn batch and the pair samples.
    pub fn next_batch(&mut self, ordinal: u64, chain_ms: u64) {
        self.batch += 1;
        self.opened_at = ordinal;
        self.orders.clear();
        self.slotted = false;
        self.slot_parts = 0;
        self.pending.clear();
        // a handover opened during the closed batch freezes the pool from this boundary
        if let Some(h) = self.handover.as_mut() {
            h.frozen = true;
        }
        self.open_snapshot(chain_ms);
    }

    /// ⭐ EARN STEP 3 — the open batch's snapshot (see [`DefiBook::next_batch`]); the launch takes it for batch 0.
    /// CHAIN-OBJECT: a function of the book, which only folded objects move, and of the carrying block's stamp.
    pub fn open_snapshot(&mut self, chain_ms: u64) {
        self.batch_index = self.income_index;
        self.merge_dg = self.pending_dg.take();
        // the deposit batch is the first TRADING batch to open after a raise: an Earn batch clears no trade and its leaf counts
        // no deposit, so one opening first would spend the hour's deposit window on a batch where no deposit can count
        self.deposits = self.raised > self.deposited && !crate::defi_earn::is_earn_batch(self.batch);
        let window = chain_ms / crate::defi_earn::EARN_WINDOW_MS;
        // the first window starts at the first opening the chain clock stamps (the launch's batch 0 knows no time yet)
        if self.close_window == 0 {
            self.close_window = window;
        }
        self.close_out = !self.deposits && self.closed == self.raised && self.deposited == self.raised && window > self.close_window;
        self.sample = crate::defi_earn::is_earn_batch(self.batch) && self.sampling;
    }

    /// The open batch's fee-state kind, as its audit circuit is formed.
    #[must_use]
    pub fn fee_kind(&self) -> ba::FeeKind {
        ba::FeeKind { merge: self.merge_dg.is_some(), close_out: self.close_out, sample: self.sample, deposits: self.deposits }
    }
    /// Whether the pool is frozen for a custody handover (no order, no settlement applies).
    #[must_use]
    pub fn frozen(&self) -> bool {
        self.handover.as_ref().is_some_and(|h| h.frozen)
    }
}

// ───────────────────────────── the order (a slot) ─────────────────────────────

/// ⭐ A SEALED ORDER SLOT (spec §18.12) — a buy of SAT with USDm, or a custody COVER (amount 0). It never travels alone: the
/// custody set carries exactly [`SLOTS`] of them per batch in its [`DefiSlotsTx`]. §9.6: (1) PoW — the carrying block;
/// (2) the share proof (`order_share_circuit`: the spend of a USDm note of exactly the amount — or, hidden, a cover of amount 0
/// — the amount and limit commitments, the shares) and the member leg of the spent leaf (`Node::member_leg_object_verdict`,
/// binder = the nullifier, cross-bind = `leaf_commit`); (3) value: the spent note's USDm leaves circulation into the pool's Y;
/// nothing is minted; (4) replay: the nullifier, refused by the spent set (a cover's lives in its own domain); (5) bounded:
/// one proof of the roster's size, one leg; (6) parity with the spend door: the same member leg, the same nullifier rule
/// `P(nk, cm)`, the same spent set — the base fee is paid by the payment that made the exact-amount note.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiOrderTx {
    /// ⭐ §18.14 — the pair its note's two possible assets are; the side stays hidden
    pub pair: u8,
    #[serde(with = "lanes8")]
    pub amount_commit: [u64; 8],
    /// the order's MAXIMUM PRICE (spec §18.10), hidden: the commitment to its bucket (`br15_audit::limit_commit`)
    #[serde(with = "lanes8")]
    pub limit_commit: [u64; 8],
    /// O1-FOOTPRINT-REVIEWED: one per custodian, bounded by [`MAX_ROSTER`] in `decode`.
    #[serde(with = "lanes4v")]
    pub share_commits: Vec<[u64; 4]>,
    /// the §BR-9a epoch whose released key wraps the shares and the one encapsulation to it
    pub epoch: u64,
    pub epoch_ct: Vec<u8>,
    /// O1-FOOTPRINT-REVIEWED: one ML-KEM-sealed share set per custodian, in roster order, bounded in `decode`.
    pub sealed: Vec<Vec<u8>>,
    pub share_proof: Vec<u8>,
    /// the spent note's nullifier and the member leg's cross-bind
    #[serde(with = "lanes8")]
    pub nullifier: [u64; 8],
    #[serde(with = "lanes8")]
    pub leaf_commit: [u64; 8],
    pub member_carrier: Vec<u8>,
    pub member_tuple: Vec<u8>,
    /// ⭐ EARN STEP 3 — the income index of the batch this order was made for, as it OPENED (`DefiBook::batch_index`). EVERY
    /// order carries it (a trade's proof binds it to nothing; a deposit's names it as its entry, a withdrawal's as its
    /// "now"), so it says nothing about the kind; the slots refuse an order made for a batch that opened at another.
    pub index: u64,
}

/// A claim leaf as a carried note payload: its commitment bytes, the rest of the note slot zero (no ciphertext — the owner
/// finds its leaf by computing it, never by a scan).
#[must_use]
pub fn leaf_note_payload(leaf: &[u64; 8]) -> Vec<u8> {
    let mut v = vec![0u8; crate::cover::PQ_NOTE_BYTES];
    v[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(*leaf));
    v
}

/// ⭐ The bytes an order's share proof is bound to: its epoch and epoch ciphertext, and every sealed share
/// (`OrderDealing::binding`) — a rogue relay or publisher that swaps any of them breaks the order's proof. No batch: a slot
/// is placed in whichever batch's slots take it (its nullifier refuses a second placement).
#[must_use]
pub fn sealed_binding(epoch: u64, epoch_ct: &[u8], sealed: &[Vec<u8>]) -> [u64; 8] {
    let mut h = blake3::Hasher::new_derive_key("USDMD-BR15-ORDER-SEALED-BIND-v3");
    h.update(&epoch.to_le_bytes());
    h.update(blake3::hash(epoch_ct).as_bytes());
    for s in sealed {
        h.update(blake3::hash(s).as_bytes());
    }
    let b = h.finalize();
    core::array::from_fn(|i| u64::from(u32::from_le_bytes(b.as_bytes()[4 * i..4 * i + 4].try_into().unwrap_or([0; 4]))) & ((1 << 30) - 1))
}

impl DefiOrderTx {
    /// The canonical encoding; `None` only if serialization itself fails (never a silent empty object).
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// The slot's bounded shape: a roster of 1..=MAX_ROSTER shares, each sealed at the one width, one epoch ciphertext, the
    /// proofs bounded.
    #[must_use]
    pub fn shaped(&self) -> bool {
        let n = self.share_commits.len();
        n > 0
            && n <= MAX_ROSTER
            && self.sealed.len() == n
            && self.sealed.iter().all(|s| s.len() == SEALED_BYTES)
            && self.epoch_ct.len() == crate::epoch_key::CT_BYTES
            && self.share_proof.len() <= MAX_PROOF_BYTES
            && self.member_carrier.len() <= MAX_PROOF_BYTES
            && self.member_tuple.len() <= 256
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        t.shaped().then_some(t)
    }
    /// The stateless half: the share proof (the spend of its note — or, hidden, a cover — the amount and limit commitments,
    /// the shares) against the carried commitments; its circuit is formed from the roster size and threshold, never taken
    /// from the publisher.
    #[must_use]
    pub fn self_valid(&self, t: u32) -> Option<&'static str> {
        let io = ba::order_share_io(
            &self.amount_commit,
            &self.limit_commit,
            &self.share_commits.iter().map(f4).collect::<Vec<_>>(),
            &sealed_binding(self.epoch, &self.epoch_ct, &self.sealed),
            &self.nullifier,
            &self.leaf_commit,
            self.index,
        );
        if self.pair >= PAIRS || self.index >> ba::INDEX_BITS != 0 {
            return Some("the order names no pair");
        }
        let Some(r1cs) = ba::order_share_r1cs(self.share_commits.len(), t as usize, crate::satoshi::asset_tag(), pair_y_tag(self.pair)) else {
            return Some("the order's share circuit cannot form for this roster");
        };
        if !usdm_decider::spartan_ccs::verify_committed(&r1cs, &io, &self.share_proof) {
            return Some("the order does not spend a note of its amount into shares of it");
        }
        None
    }
}

// ───────────────────────────── the batch's slots (spec §18.12) ─────────────────────────────

/// ⭐ HOW MANY ORDERS AND HOW MANY CLAIMS EVERY BATCH CARRIES — a protocol constant, whatever traded: real ones (oldest first)
/// and custody covers to fill. An order or claim past the K-th waits for the next batch.
pub const SLOTS: usize = 8;

/// ⭐ HOW MANY PARTS A BATCH'S SLOTS TRAVEL IN (spec §18.12) — a protocol constant. MEASURED 2026-11-02: one slot with its real
/// member leg is ~267 KB, so a batch's 2 × [`SLOTS`] slots are 4.27 MB, past one transaction (`MAX_TX_WEIGHT_BYTES` 1.8 MB)
/// and one block (4.0 MB). Four parts of [`PART_SLOTS`] orders and [`PART_SLOTS`] claims are ~1.07 MB each, and every batch
/// carries all four, so the count stays a constant. BORROWED: the chunked settlement beside it (spec §18.11).
pub const SLOT_PARTS: usize = 4;
/// Orders (and claims) per part.
pub const PART_SLOTS: usize = SLOTS / SLOT_PARTS;
const _: () = assert!(SLOTS % SLOT_PARTS == 0 && SLOT_PARTS <= 8, "the parts split the slots evenly and fit the book's bitmask");

/// ⭐ ONE PART OF THE BATCH'S SLOTS (spec §18.12): exactly [`PART_SLOTS`] orders and [`PART_SLOTS`] claims, real or cover, and
/// every batch carries all [`SLOT_PARTS`] parts — the one way an order or a claim reaches the chain, so a batch's count is a
/// constant. §9.6: (1) PoW — the carrying block; (2) every order's share proof and member leg, every claim's relation, mint and
/// member leg — each verified as a lone one was; (3) value: each order moves its note's USDm into the pool, each claim mints
/// exactly its fill or refund (a cover: 0); (4) replay: every nullifier once (the spent set, and no two within the object);
/// each part of a batch applies once (the book's `slot_parts` bitmask); (5) bounded: 2 × [`PART_SLOTS`] items, each bounded;
/// (6) parity with the lone order and claim doors: every check of both, item by item.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiSlotsTx {
    /// ⭐ §18.14 — the pair these slots belong to
    pub pair: u8,
    pub batch: u64,
    /// which of the batch's [`SLOT_PARTS`] parts this is
    pub part: u8,
    /// O1-FOOTPRINT-REVIEWED: exactly [`PART_SLOTS`], checked in `decode`.
    pub orders: Vec<DefiOrderTx>,
    /// O1-FOOTPRINT-REVIEWED: exactly [`PART_SLOTS`], checked in `decode`.
    pub claims: Vec<DefiClaimTx>,
}

impl DefiSlotsTx {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical encoding of one part: exactly [`PART_SLOTS`] orders and claims, each its own bounded shape.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        if usize::from(t.part) >= SLOT_PARTS
            || t.orders.len() != PART_SLOTS
            || t.claims.len() != PART_SLOTS
            || !t.orders.iter().all(DefiOrderTx::shaped)
            || !t.claims.iter().all(DefiClaimTx::shaped)
            || t.pair >= PAIRS
            || t.orders.iter().any(|o| o.pair != t.pair)
            || t.claims.iter().any(|c| c.pair != t.pair)
        {
            return None;
        }
        Some(t)
    }
    /// A batch's [`SLOTS`] orders and [`SLOTS`] claims as its [`SLOT_PARTS`] parts, in order; `None` unless both are exactly
    /// [`SLOTS`].
    #[must_use]
    pub fn parts(pair: u8, batch: u64, orders: Vec<DefiOrderTx>, claims: Vec<DefiClaimTx>) -> Option<Vec<Self>> {
        if orders.len() != SLOTS || claims.len() != SLOTS {
            return None;
        }
        let (mut os, mut cs) = (orders.into_iter(), claims.into_iter());
        (0..SLOT_PARTS)
            .map(|p| {
                Some(Self {
                    pair,
                    batch,
                    part: u8::try_from(p).ok()?,
                    orders: os.by_ref().take(PART_SLOTS).collect(),
                    claims: cs.by_ref().take(PART_SLOTS).collect(),
                })
            })
            .collect()
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiSlots, &p))
    }
    /// Every nullifier the slots retire (the orders', then the claims'), as the spent set's keys.
    #[must_use]
    pub fn nullifiers(&self) -> Vec<[u8; 32]> {
        self.orders.iter().map(|o| o.nullifier).chain(self.claims.iter().map(|c| c.nullifier)).map(crate::spend_frontier::leaf_to_cm_bytes).collect()
    }
    /// The notes the slots carry: each claim's minted note.
    #[must_use]
    pub fn notes(&self) -> Vec<Vec<u8>> {
        self.claims.iter().map(|c| c.note.clone()).collect()
    }
    /// ⭐ THE STATELESS HALF against `book`: the batch is the open one, its slots not yet applied and the batch closed for
    /// intake; no nullifier twice; every order's proof against the roster's shape; every claim's relation and mint. (Each
    /// item's member leg is the fold door's: it reads the node's ring.)
    pub fn verdict(&self, book: &DefiBook, ordinal: u64) -> Result<(), &'static str> {
        if !book.is_open() {
            return Err("the book holds no pool");
        }
        if self.pair != book.pair || self.batch != book.batch || book.slotted || book.slot_parts & (1u8 << self.part) != 0 {
            return Err("the slots are not for the open batch (or this part of them already applied)");
        }
        if !book.batch_closed(ordinal) {
            return Err("the batch is still gathering orders");
        }
        if book.frozen() {
            return Err("the pool is frozen for a custody handover");
        }
        let nfs = self.nullifiers();
        let mut seen = std::collections::HashSet::with_capacity(nfs.len());
        if !nfs.iter().all(|n| seen.insert(*n)) {
            return Err("a nullifier appears twice among the slots");
        }
        for o in &self.orders {
            if o.share_commits.len() != book.roster.len() {
                return Err("an order deals one share per custodian of the roster");
            }
            // ⭐ EARN STEP 3 — an order rides only the batch it was made for: its carried index is this batch's opening
            // snapshot (a deposit's entry and a withdrawal's "now" are that index). CHAIN-OBJECT: the slot object's own order
            // field against the book's snapshot.
            if o.index != book.batch_index {
                return Err("an order was made for a batch that opened at another income index");
            }
            if let Some(why) = o.self_valid(book.t) {
                return Err(why);
            }
        }
        for c in &self.claims {
            if let Some(why) = c.self_valid() {
                return Err(why);
            }
        }
        Ok(())
    }
}

/// The book after one verified part: its orders join the batch's in FOLD order (the canonical order every node folds in), the
/// part applies once, and the batch is slotted when every part has. Returns the index of the part's first order in the book.
pub fn apply_slots(book: &mut DefiBook, t: &DefiSlotsTx) -> usize {
    let first = book.orders.len();
    book.orders
        .extend(t.orders.iter().map(|o| BookOrder { amount_commit: o.amount_commit, limit_commit: o.limit_commit, share_commits: o.share_commits.clone() }));
    book.slot_parts |= 1u8 << t.part;
    book.slotted = usize::try_from(book.slot_parts.count_ones()).is_ok_and(|c| c == SLOT_PARTS);
    first
}

// ───────────────────────────── the settlement ─────────────────────────────

/// What one custodian publishes in a settlement (its phase-1 digest is the settlement's `phase1[i]`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CustodianPart {
    /// O1-FOOTPRINT-REVIEWED: exactly AUDIT_STATEMENTS entries of (w, AUDIT_REPS s, AUDIT_REPS u), checked in `decode`.
    pub published: Vec<(Word, Vec<Word>, Vec<Word>)>,
    pub new_pool: [u64; 4],
    /// ⭐ Earn steps 1 + 3 — its new fee commitment (the open fee state B, E, A), audited with the pool's
    pub new_fee: [u64; 4],
    /// ⭐ Earn step 3 — its new close commitment (the closed window's E_c, A_c)
    pub new_close: [u64; 4],
    pub audit: Vec<u8>,
}

/// ⭐ THE BATCH SETTLEMENT — whole, or one CHUNK of it (spec §18.11). §9.6: (1) PoW — the carrying block; (2) every carried
/// custodian's audit, verified against a circuit this node FORMS from public data (`AuditVerifier`: `audit_r1cs`'s circuit,
/// replayed, its matrices never laid) under the challenges of the
/// settlement's whole phase-1 vector (so a chunk verifies alone), and — at the CLOSING chunk — every published sharing's
/// degree and constant over all n parts (`sharing_holds`): the tick and the booking are proven, never trusted, whoever
/// publishes; (3) value: no note is minted here — the closing chunk's claim LEAVES enter the note set, each spendable only by
/// its order's owner through `claim_circuit` at exactly its fill; the pool moves only to the audited new commitments; (4)
/// replay: the batch must be the book's open batch, and each custodian's slot holds one part (the first that verified); (5)
/// bounded: one audit per carried custodian, at most `MAX_ROSTER` held parts; (6) parity with the peg-out quorum door: every
/// custodian's part is required (all n — a missing part leaves the batch to expire and refund).
/// A settlement whose parts fit one transaction is ONE chunk (`first = 0`, closing); a larger one is published as
/// [`DefiSettleTx::chunks`], every chunk but the last carrying no leaves, the last applied only once the others are held.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiSettleTx {
    /// ⭐ §18.14 — the pair this settles
    pub pair: u8,
    pub batch: u64,
    pub tick: i64,
    /// ⭐ §18.14 — THE ONE BIT THE FLOOR OPENS: whether the batch's sells count. Off when they would pay below the pool's Y floor: buyers clear as if no sell came, every seller gets its
    /// own X back, and the next batch tries again, so no sell can stop a buyer.
    pub sells: bool,
    /// ⭐⭐ FINDING A-F46 — THE LOWEST BUCKET THAT FILLS: the tick's own `defi_clear::j_min(base, tick)`, or one above it when
    /// the bucket whose cap sits at `tick + 1` was turned off — its demand would have lifted the price past its own maximum,
    /// so it can fill at no tick, and a price it alone supported would pay the sellers from a pool that never got its coin.
    /// Every bucket from here up fills at the tick; the audited bounds are over exactly their demand; every node checks it
    /// is at or above the tick's own (no bucket that cannot fill is ever counted) and the leaf carries it.
    pub j_min: u64,
    /// ⭐ THE COMPLAINT SET (GJKR's complaint phase, borrowed): the indices (ascending, into the batch's orders) of the orders
    /// some custodian could not open — a sealed share that does not decrypt to the share its commitment names. They are left
    /// out of the clearing and REFUND (their leaf is the refund leaf), so one malformed order never stalls a batch.
    /// O1-FOOTPRINT-REVIEWED: at most one entry per order of the open batch, checked in `verdict`.
    pub excluded: Vec<u32>,
    /// O1-FOOTPRINT-REVIEWED: every custodian's phase-1 digest, roster order (bounded by [`MAX_ROSTER`] in `decode`) — the
    /// challenges' transcript, so each chunk's audits verify on their own.
    pub phase1: Vec<[u64; 4]>,
    /// the roster index of this chunk's first part
    pub first: u32,
    /// O1-FOOTPRINT-REVIEWED: custodians `first..first + parts.len()`, bounded by [`MAX_ROSTER`] in `decode`.
    pub parts: Vec<CustodianPart>,
    /// O1-FOOTPRINT-REVIEWED: one claim leaf per order of the batch on the CLOSING chunk (the block carries what applies it),
    /// none on any other; the fold requires them to equal the leaves its own book derives.
    pub leaves: Vec<[u64; 8]>,
}

/// What a settlement chunk did at the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettleStep {
    /// its parts are held; the batch waits for the rest
    Held,
    /// it closed the batch: these leaves enter the note set
    Closed(Vec<[u64; 8]>),
}

/// The settlement's Fiat–Shamir transcript: the batch, the tick, the complaint set and every phase-1 digest in roster order.
#[must_use]
/// CHAIN-OBJECT: every field is the folded `DefiSettleTx`'s own (its tick, sells bit and A-F46 `j_min` included), so every
/// node derives the same challenges from the block's object.
pub fn settle_transcript(pair: u8, batch: u64, tick: i64, sells: bool, j_min: u64, excluded: &[u32], phase1: &[[u64; 4]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(34 + 4 * excluded.len() + 32 * phase1.len());
    v.push(pair);
    v.push(u8::from(sells));
    v.extend_from_slice(&batch.to_le_bytes());
    v.extend_from_slice(&tick.to_le_bytes());
    v.extend_from_slice(&j_min.to_le_bytes());
    v.extend_from_slice(&(excluded.len() as u64).to_le_bytes());
    for e in excluded {
        v.extend_from_slice(&e.to_le_bytes());
    }
    for d in phase1 {
        for w in d {
            v.extend_from_slice(&w.to_le_bytes());
        }
    }
    v
}

/// The buckets a settlement's lowest filling bucket `j_min` names: `j_min` and every one above it (an upward-closed set, as
/// `defi_clear::fill_select` is).
#[must_use]
pub fn fills_from(j_min: u64) -> [bool; ba::ORDER_BUCKETS] {
    core::array::from_fn(|j| j as u64 >= j_min)
}

/// The audited statements of a tick (`br15_audit::batch_statements` over the tick's exact ratios) and the buckets each
/// demand sums. ⭐ FINDING A-F46: BOTH rows sum the buckets that FILL — `j_min` and up ([`fills_from`]) — so the price is
/// bounded on both sides by the demand that executes (the plain rule, `defi_clear`'s invariant pins). The lower bound once
/// summed the buckets that fill one tick DOWN, and a buy past its own cap then set the sellers' price and refunded.
/// ⭐ Earn step 3: `dg` is the rate the batch merges (`DefiBook::merge_dg`, 0 when it merges nothing — the merge rows then pin
/// the allocation to 0).
#[must_use]
pub fn statements_for(tick: i64, j_min: u64, dg: u64) -> ([([Word; ba::AUDIT_VALUES], Word); ba::AUDIT_STATEMENTS], [[bool; ba::ORDER_BUCKETS]; 2]) {
    let w = |v: u128| -> Word { [v as u64, (v >> 64) as u64, 0, 0] };
    let (n0, d0) = crate::defi_clear::tick_ratio(tick);
    let (n1, d1) = crate::defi_clear::tick_ratio(tick + 1);
    let fills = fills_from(j_min);
    (ba::batch_statements(&w(n0), &w(d0), &w(n1), &w(d1), &w(u128::from(dg))), [fills, fills])
}

/// ⭐ EARN STEP 2 PIECE 6 — an EARN batch's withdrawal rates at its tick `a` (which brackets the pool's own ratio): units →
/// SAT at `1/r'`, `r' = defi_earn::sqrt_up(a + 1) ≥ √p_{a+1}`, as the leaf's buy slot `(d', n')`; units → coin at `r =
/// defi_earn::sqrt_down(a) ≤ √p_a`, as its sell slot `(n_r, d_r)`. Each at most the unit's pro-rata share (`defi_earn`'s pins).
#[must_use]
pub fn earn_rates(tick: i64) -> ((u128, u128), (u128, u128)) {
    let (un, ud) = crate::defi_earn::sqrt_up(tick + 1);
    ((ud, un), crate::defi_earn::sqrt_down(tick))
}

/// The leaf an Earn batch inserts for every one of its orders: with its withdrawals PAID, the Earn leaf (refund semantics for
/// every trade and deposit — `j_min = ORDER_BUCKETS`, no sell fills — and the two withdrawal rates); with them off (a floor
/// would bind), the plain refund leaf, where every withdrawal's position rolls on. No index: a withdrawal's "now" rides its
/// own limit commitment. CHAIN-OBJECT: the tick and the paid bit are the folded `DefiSettleTx`'s own (`tick`, `sells`); the
/// fold requires the carried leaves to equal these.
#[must_use]
pub fn earn_leaf(amount_commit: &[u64; 8], limit_commit: &[u64; 8], tick: i64, paid: bool) -> [u64; 8] {
    if !paid {
        return refund_leaf(amount_commit, limit_commit);
    }
    let ((pn, pd), (sn, sd)) = earn_rates(tick);
    ba::claim_leaf_x(amount_commit, limit_commit, pn, pd, ba::ORDER_BUCKETS as u64, sn, sd, ba::LeafExtra { earn: true, dep: false })
}

/// ⭐ EARN STEP 2 PIECE 6 — an Earn batch's audited statements at its tick `a`, its opening index `index` (what every
/// withdrawal of it carries as its "now") and the rate `dg` it merges (`br15_audit::earn_statements`): the tick over the pool
/// alone, the two withdrawal bookings at [`earn_rates`], both floors after them, the income booking, the backing's turnstile
/// and the merge. No bucket is summed in an Earn batch.
#[must_use]
pub fn earn_statements_for(tick: i64, index: u64, dg: u64) -> [([Word; ba::AUDIT_VALUES], Word); ba::AUDIT_STATEMENTS] {
    let w = |v: u128| -> Word { [v as u64, (v >> 64) as u64, 0, 0] };
    let (n0, d0) = crate::defi_clear::tick_ratio(tick);
    let (n1, d1) = crate::defi_clear::tick_ratio(tick + 1);
    let ((sp, sq), (cp, cq)) = earn_rates(tick);
    ba::earn_statements(&w(n0), &w(d0), &w(n1), &w(d1), &w(sq), &w(sp), &w(cp), &w(cq), &w(u128::from(index)), &w(u128::from(dg)))
}

/// The sellers' price at a batch's tick: `p_t`, or `(0, 1)` when its sells did not fit above the pool's floor and every seller gets its own X back.
#[must_use]
pub fn sell_price(tick: i64, sells: bool) -> (u128, u128) {
    if sells { crate::defi_clear::tick_ratio(tick) } else { (0, 1) }
}

/// The claim leaf of an order at its batch's tick: the price `⌊y · d_{t+1} / n_{t+1}⌋` pays a buyer at, the settlement's lowest
/// filling bucket `j_min` (A-F46: the settlement's own, never re-derived from the tick) and the sellers' price — the same leaf
/// for every order of the batch's commitments, whichever side or bucket it named.
#[must_use]
pub fn claim_leaf_at(amount_commit: &[u64; 8], limit_commit: &[u64; 8], tick: i64, j_min: u64, sells: bool) -> [u64; 8] {
    claim_leaf_at_x(amount_commit, limit_commit, tick, j_min, sells, false)
}

/// [`claim_leaf_at`] with the batch's DEPOSIT lane (Earn step 3: `dep` — a deposit batch whose sells counted, where every
/// deposit counted; `false` is exactly the old leaf). CHAIN-OBJECT: computed from a folded settlement's own fields and the
/// book's opening snapshot.
#[must_use]
pub fn claim_leaf_at_x(amount_commit: &[u64; 8], limit_commit: &[u64; 8], tick: i64, j_min: u64, sells: bool, dep: bool) -> [u64; 8] {
    let (n1, d1) = crate::defi_clear::tick_ratio(tick + 1);
    let (sn, sd) = sell_price(tick, sells);
    ba::claim_leaf_x(amount_commit, limit_commit, d1, n1, j_min, sn, sd, ba::LeafExtra { earn: false, dep })
}

/// ⭐ A settlement's leaves, one per order in book order: the leaf at `tick` and `j_min`, or — for an order in the complaint
/// set — its refund leaf. ⭐ Earn step 3: a deposit batch's leaves carry the deposit lane when its sells counted (exactly
/// when the audit summed its deposits). CHAIN-OBJECT: `tick`, `j_min`, `sells` and `excluded` are the folded
/// `DefiSettleTx`'s own and the deposit flag the book's opening snapshot; the fold requires its carried leaves to equal these.
#[must_use]
pub fn settle_leaves(book: &DefiBook, tick: i64, j_min: u64, sells: bool, excluded: &[u32]) -> Vec<[u64; 8]> {
    book.orders
        .iter()
        .enumerate()
        .map(|(k, o)| {
            if excluded.binary_search(&(k as u32)).is_ok() {
                refund_leaf(&o.amount_commit, &o.limit_commit)
            } else if crate::defi_earn::is_earn_batch(book.batch) {
                // ⭐ an Earn batch: `sells` is its withdrawals-paid bit
                earn_leaf(&o.amount_commit, &o.limit_commit, tick, sells)
            } else {
                claim_leaf_at_x(&o.amount_commit, &o.limit_commit, tick, j_min, sells, book.deposits && sells)
            }
        })
        .collect()
}

/// The refund leaf of an order of an expired batch (or of the complaint set): `a` back, at `(1, 1)`, nothing filling.
#[must_use]
pub fn refund_leaf(amount_commit: &[u64; 8], limit_commit: &[u64; 8]) -> [u64; 8] {
    ba::claim_leaf_x(amount_commit, limit_commit, 1, 1, ba::ORDER_BUCKETS as u64, 0, 1, ba::LeafExtra::default())
}

impl DefiSettleTx {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        let end = (t.first as usize).checked_add(t.parts.len())?;
        if t.parts.is_empty() || t.phase1.is_empty() || t.phase1.len() > MAX_ROSTER || end > t.phase1.len() || t.tick.abs() >= crate::defi_clear::TICK_RANGE {
            return None;
        }
        let shaped = t.parts.iter().all(|p| {
            p.audit.len() <= MAX_PROOF_BYTES
                && p.published.len() == ba::AUDIT_STATEMENTS
                && p.published.iter().all(|(_, s, u)| s.len() == ba::AUDIT_REPS && u.len() == ba::AUDIT_REPS)
        });
        shaped.then_some(t)
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiSettle, &p))
    }
    /// The settlement's header: what every chunk of one settlement shares (its batch, tick, complaint set, phase-1 vector).
    #[must_use]
    pub fn header(&self) -> [u8; 32] {
        // CHAIN-OBJECT: the header is over this settlement object's own carried fields
        *blake3::Hasher::new_derive_key("USDMD-BR15-SETTLE-HEADER-v1").update(&settle_transcript(self.pair, self.batch, self.tick, self.sells, self.j_min, &self.excluded, &self.phase1)).finalize().as_bytes()
    }
    /// Whether this chunk closes its settlement (it carries the last custodian's part).
    #[must_use]
    pub fn closes(&self) -> bool {
        self.first as usize + self.parts.len() == self.phase1.len()
    }

    /// ⭐ THE CHUNKS a settlement is published as: consecutive parts, each chunk's bytes within `max_bytes` (a transaction's
    /// weight), the leaves on the last chunk only. A settlement that fits is one chunk, itself. `None` if one part alone does
    /// not fit (a part is one audit, far below a transaction).
    #[must_use]
    pub fn chunks(&self, max_bytes: usize) -> Option<Vec<DefiSettleTx>> {
        let mut out = Vec::new();
        let mut first = 0usize;
        while first < self.parts.len() {
            let mut end = first + 1;
            let shell = |a: usize, b: usize, closing: bool| DefiSettleTx {
                pair: self.pair,
                batch: self.batch,
                tick: self.tick,
                sells: self.sells,
                j_min: self.j_min,
                excluded: self.excluded.clone(),
                phase1: self.phase1.clone(),
                first: u32::try_from(self.first as usize + a).unwrap_or(u32::MAX),
                parts: self.parts[a..b].to_vec(),
                leaves: if closing { self.leaves.clone() } else { Vec::new() },
            };
            if shell(first, end, end == self.parts.len()).wire()?.len() > max_bytes {
                return None;
            }
            while end < self.parts.len() && shell(first, end + 1, end + 1 == self.parts.len()).wire()?.len() <= max_bytes {
                end += 1;
            }
            out.push(shell(first, end, end == self.parts.len()));
            first = end;
        }
        Some(out)
    }

    /// ⭐ THE WHOLE SETTLEMENT'S VERDICT against `book` (the node's own; no chunks held): `Ok(claim leaves)` when it is one closing
    /// chunk of every part and it verifies; a fixed reason otherwise. Pure.
    pub fn verdict(&self, book: &DefiBook) -> Result<Vec<[u64; 8]>, &'static str> {
        match self.chunk_verdict(book)? {
            SettleStep::Closed(leaves) => Ok(leaves),
            SettleStep::Held => Err("the settlement is a chunk: it closes nothing on its own"),
        }
    }

    /// ⭐ ONE CHUNK'S VERDICT against `book` (its held parts included): `Held` when its parts verify and its slots are free;
    /// `Closed(leaves)` when it is the closing chunk, every earlier slot holds a part of THIS settlement's header, and every
    /// published sharing over all n parts holds. Pure — the fold applies only after it.
    pub fn chunk_verdict(&self, book: &DefiBook) -> Result<SettleStep, &'static str> {
        if !book.is_open() {
            return Err("the book holds no pool");
        }
        if self.batch != book.batch || self.pair != book.pair {
            return Err("the settlement is not for the open batch");
        }
        // a settlement over a batch only SOME of whose slot parts applied would leave out the orders of the parts still to come
        // while an applied part already spent its notes: every part, or none (a batch with none spent nothing and holds no order)
        if book.slot_parts != 0 && !book.slotted {
            return Err("the batch's slots have applied only in part");
        }
        if book.frozen() {
            return Err("the pool is frozen for a custody handover");
        }
        let n = book.roster.len();
        if self.phase1.len() != n {
            return Err("the settlement names a phase-1 digest per custodian of the roster");
        }
        if self.excluded.windows(2).any(|w| w[0] >= w[1]) || self.excluded.last().is_some_and(|e| *e as usize >= book.orders.len()) {
            return Err("the complaint set is not ascending indices of the batch's orders");
        }
        let header = self.header();
        let first = self.first as usize;
        for k in first..first + self.parts.len() {
            if book.pending.get(k).is_some_and(Option::is_some) {
                return Err("a custodian's slot already holds its part of this batch");
            }
        }
        // ⭐ A-F46: every bucket the settlement counts must fill at its tick (its cap at or above the price its buyers pay).
        // CHAIN-OBJECT: `j_min` is this settlement object's own carried field, checked against the book's public tick.
        if self.j_min > ba::ORDER_BUCKETS as u64 || self.j_min < crate::defi_clear::j_min(book.last_tick, self.tick) {
            return Err("the settlement counts a bucket that does not fill at its tick (its lowest filling bucket is below the tick's own)");
        }
        let included: Vec<&BookOrder> = book.orders.iter().enumerate().filter(|(k, _)| self.excluded.binary_search(&(*k as u32)).is_err()).map(|(_, o)| o).collect();
        let ch = ba::AuditChallenges::derive(&settle_transcript(self.pair, self.batch, self.tick, self.sells, self.j_min, &self.excluded, &self.phase1));
        // ⭐ EARN STEP 2 PIECE 6 — an Earn batch (by its public number) is audited against the Earn statements at its tick and
        // the batch's opening index; its `sells` is its withdrawals-paid bit and its lowest filling bucket is "none".
        // ⭐ EARN STEP 3 — every batch is audited at its own fee-state kind and merge rate, both snapshotted when it opened.
        // CHAIN-OBJECT: the batch number, tick and bit are this settlement object's own; the index, kind and rate are the
        // book's opening snapshot, which only folded objects move.
        let earn = crate::defi_earn::is_earn_batch(self.batch);
        if earn && self.j_min != ba::ORDER_BUCKETS as u64 {
            return Err("an Earn batch fills no bucket (its lowest filling bucket must be none)");
        }
        let dg = book.merge_dg.unwrap_or(0);
        let (forms, select) = if earn {
            (earn_statements_for(self.tick, book.batch_index, dg), [[false; ba::ORDER_BUCKETS]; 2])
        } else {
            statements_for(self.tick, self.j_min, dg)
        };
        // ⭐ the audit's matrices are never laid (one custody audit is 133 M entries, 3.1 GB laid — MEASURED 2026-11-15, finding
        // A-F61): its public shape is formed once, and each part's proof is checked against a replay of the same circuit (793 MB
        // whole-process peak). ONE AUDIT IN MEMORY PER PROCESS: the replays run under the decider's AUDIT_GATE until every part
        // is checked (a custodian proving its own audit on this node waits, or makes this wait). The verdict is unchanged.
        let _one_audit = ba::audit_gate();
        let Some(verifier) = ba::AuditVerifier::new(included.len(), select, self.sells, earn, book.fee_kind(), &ch, &forms) else {
            return Err("the audit circuit cannot form");
        };
        for (k, part) in self.parts.iter().enumerate() {
            let i = first + k;
            let published: Vec<ba::AuditPublished> =
                part.published.iter().map(|(w, s, u)| ba::AuditPublished { w: *w, s: s.clone(), u: u.clone() }).collect();
            let order_commits: Vec<[Fa4; 4]> = included.iter().map(|o| f4(&o.share_commits[i])).collect();
            let io = ba::audit_io(
                &f4(&book.pool_commits[i]),
                &f4(&book.fee_commits[i]),
                &f4(&book.close_commits[i]),
                &order_commits,
                &f4(&self.phase1[i]),
                &f4(&part.new_pool),
                &f4(&part.new_fee),
                &f4(&part.new_close),
                &ch,
                &forms,
                &published,
            );
            if !verifier.verify(&io, &part.audit) {
                return Err("a custodian's audit does not verify");
            }
        }
        if !self.closes() {
            return if self.leaves.is_empty() { Ok(SettleStep::Held) } else { Err("only the closing chunk carries the leaves") };
        }
        // the closing chunk: every earlier slot holds a part of this header; every sharing over all n parts holds
        let mut all: Vec<&Vec<(Word, Vec<Word>, Vec<Word>)>> = Vec::with_capacity(n);
        for k in 0..first {
            match book.pending.get(k).and_then(Option::as_ref) {
                Some(h) if h.header == header => all.push(&h.published),
                _ => return Err("the closing chunk arrived before every other part of its settlement was held"),
            }
        }
        all.extend(self.parts.iter().map(|p| &p.published));
        let t = book.t as usize;
        for si in 0..ba::AUDIT_STATEMENTS {
            // published words are read as field elements (a non-canonical representative reduces to the same element)
            let col = |f: &dyn Fn(&(Word, Vec<Word>, Vec<Word>)) -> Word| -> Vec<Word> { all.iter().map(|p| ba::fadd(&f(&p[si]), &[0; 4])).collect() };
            if !ba::sharing_holds(&col(&|p| p.0), t, true) {
                return Err("a statement's weighted sum does not open to zero (the tick or the booking is not the rule's)");
            }
            for r in 0..ba::AUDIT_REPS {
                if !ba::sharing_holds(&col(&|p| p.1[r]), 2 * t, true) {
                    return Err("a statement's bits are not bits");
                }
                if !ba::sharing_holds(&col(&|p| p.2[r]), t, false) {
                    return Err("a statement's bit sharings are not of degree t");
                }
            }
        }
        // CHAIN-OBJECT: the leaves this settlement object's own tick, j_min, sells and complaint set name
        let leaves = settle_leaves(book, self.tick, self.j_min, self.sells, &self.excluded);
        if leaves != self.leaves {
            return Err("the carried claim leaves are not the batch's");
        }
        Ok(SettleStep::Closed(leaves))
    }
}

// ───────────────────────────── the expiry ─────────────────────────────

/// ⭐ THE EXPIRY of a batch no settlement reached. §9.6: (1) PoW — the carrying block; (2) no proof: its only claim is a fact
/// every node checks from its own book (the open batch is past its settlement window); (3) value: refund LEAVES only, each
/// worth exactly its order's burned amount through the claim circuit at (1, 1); the pool does not move; (4) replay: the batch
/// must be the open one; (5) bounded: one leaf per order of the batch; (6) parity with the settlement: the same leaves'
/// shape, the same next-batch step.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiExpireTx {
    /// ⭐ §18.14 — the pair
    pub pair: u8,
    pub batch: u64,
    /// O1-FOOTPRINT-REVIEWED: one refund leaf per order of the batch, equal to the book's (checked at the fold).
    pub leaves: Vec<[u64; 8]>,
}

impl DefiExpireTx {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        crate::chain_object::decode_exact(bytes)
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiExpire, &p))
    }
    /// `Ok(refund leaves)` when the batch is the open one and past its window at fold `ordinal`, chain time `chain_ms`.
    pub fn verdict(&self, book: &DefiBook, ordinal: u64, chain_ms: u64) -> Result<Vec<[u64; 8]>, &'static str> {
        if self.batch != book.batch || self.pair != book.pair {
            return Err("the expiry is not for the open batch");
        }
        if !book.batch_expired(ordinal, chain_ms) {
            return Err("the batch is still within its settlement window");
        }
        let leaves: Vec<[u64; 8]> = book.orders.iter().map(|o| refund_leaf(&o.amount_commit, &o.limit_commit)).collect();
        if leaves != self.leaves {
            return Err("the carried refund leaves are not the batch's");
        }
        Ok(leaves)
    }
}

// ───────────────────────────── the EarnEpoch (Earn step 3) ─────────────────────────────

/// What one custodian publishes in an EarnEpoch (its phase-1 digest is the object's `phase1[i]`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochPart {
    /// O1-FOOTPRINT-REVIEWED: exactly `EPOCH_STATEMENTS` entries of (w, AUDIT_REPS s, AUDIT_REPS u), checked in `decode`.
    pub published: Vec<(Word, Vec<Word>, Vec<Word>)>,
    pub audit: Vec<u8>,
}

/// ⭐⭐ EARN STEP 3 — THE EARNEPOCH: the one protocol-wide income rate of a window, over every pair's CLOSED window
/// (docs/COIN-POOL-DEPOSITS-SPEC-20261111.md, "Step 3 REFUTED … the replacement"). Whole, or one CHUNK of it, as a settlement.
/// §9.6: (1) PoW — the carrying block; (2) every carried custodian's audit (`br15_audit::epoch_audit_circuit`) against a
/// circuit this node FORMS from public data under the challenges of the whole phase-1 vector, over the close commitments
/// the books hold for it, and at the CLOSING chunk every published sharing over all n parts (`sharing_holds`): the rate is
/// proven the largest the window's fees pay, never trusted; (3) value: none moves here — the fold raises each pair's PUBLIC
/// index by `⌊dG·W_c/2^K⌋` and hands `dG` to each pair's next batch, whose audit merges `⌊dG·2A_c/2^K⌋` into the backing
/// (Σ ≤ the closed fees by statement 1), and every income claim is bounded by that backing (the Earn turnstile); (4)
/// replay: the books' counters — every pair must have closed exactly one window past its last raise, and `raise` must be
/// that raise; each slot holds one part; (5) bounded: one audit per carried custodian over `PAIRS` close commitments, at most
/// `MAX_ROSTER` held parts; (6) parity with the settlement door: the same audit framework, chunking and sharing checks.
/// SAFE AT SCALE: one object per window, whatever the users or positions. AI RESISTANT: (a) — the statements; a lying
/// custody set's rate fails a sharing check on every node.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiEarnEpochTx {
    /// the books' common raise count this EarnEpoch completes (each pair's `raised`; its `closed` is one more)
    pub raise: u64,
    pub dg: u64,
    /// O1-FOOTPRINT-REVIEWED: every custodian's phase-1 digest, roster order (bounded by [`MAX_ROSTER`] in `decode`)
    pub phase1: Vec<[u64; 4]>,
    pub first: u32,
    /// O1-FOOTPRINT-REVIEWED: custodians `first..first + parts.len()`, bounded by [`MAX_ROSTER`] in `decode`
    pub parts: Vec<EpochPart>,
}

/// The EarnEpoch's Fiat–Shamir transcript: its raise, its rate, every phase-1 digest in roster order.
/// CHAIN-OBJECT: every field is the folded `DefiEarnEpochTx`'s own.
#[must_use]
pub fn epoch_transcript(raise: u64, dg: u64, phase1: &[[u64; 4]]) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + 32 * phase1.len());
    v.extend_from_slice(b"EARN");
    v.extend_from_slice(&raise.to_le_bytes());
    v.extend_from_slice(&dg.to_le_bytes());
    for d in phase1 {
        for w in d {
            v.extend_from_slice(&w.to_le_bytes());
        }
    }
    v
}

impl DefiEarnEpochTx {
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        let end = (t.first as usize).checked_add(t.parts.len())?;
        if t.parts.is_empty() || t.phase1.is_empty() || t.phase1.len() > MAX_ROSTER || end > t.phase1.len() || t.dg > ba::EARN_DG_MAX {
            return None;
        }
        let shaped = t.parts.iter().all(|p| {
            p.audit.len() <= MAX_PROOF_BYTES
                && p.published.len() == ba::EPOCH_STATEMENTS
                && p.published.iter().all(|(_, s, u)| s.len() == ba::AUDIT_REPS && u.len() == ba::AUDIT_REPS)
        });
        shaped.then_some(t)
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiEarnEpoch, &p))
    }
    /// What every chunk of one EarnEpoch shares. CHAIN-OBJECT: over this object's own carried fields.
    #[must_use]
    pub fn header(&self) -> [u8; 32] {
        *blake3::Hasher::new_derive_key("USDMD-BR15-EARN-EPOCH-HEADER-v1").update(&epoch_transcript(self.raise, self.dg, &self.phase1)).finalize().as_bytes()
    }
    #[must_use]
    pub fn closes(&self) -> bool {
        self.first as usize + self.parts.len() == self.phase1.len()
    }
    /// The chunks it is published as (consecutive parts, each chunk within `max_bytes`); `None` if one part alone does not fit.
    #[must_use]
    pub fn chunks(&self, max_bytes: usize) -> Option<Vec<DefiEarnEpochTx>> {
        let mut out = Vec::new();
        let mut first = 0usize;
        let shell = |a: usize, b: usize| DefiEarnEpochTx {
            raise: self.raise,
            dg: self.dg,
            phase1: self.phase1.clone(),
            first: u32::try_from(self.first as usize + a).unwrap_or(u32::MAX),
            parts: self.parts[a..b].to_vec(),
        };
        while first < self.parts.len() {
            let mut end = first + 1;
            if shell(first, end).wire()?.len() > max_bytes {
                return None;
            }
            while end < self.parts.len() && shell(first, end + 1).wire()?.len() <= max_bytes {
                end += 1;
            }
            out.push(shell(first, end));
            first = end;
        }
        Some(out)
    }
    /// ⭐ ONE CHUNK'S VERDICT against every pair's book (`books[p]` is pair p's; pair 0's holds the held parts): `Ok(false)`
    /// held, `Ok(true)` closing — every earlier slot holds a part of THIS header and every sharing over all n parts holds.
    /// Pure — the fold applies only after it.
    pub fn verdict(&self, books: &[DefiBook]) -> Result<bool, &'static str> {
        if books.len() != usize::from(PAIRS) {
            return Err("an EarnEpoch spans every pair's book");
        }
        let b0 = &books[0];
        for b in books {
            if !b.is_open() || b.roster != b0.roster || b.t != b0.t {
                return Err("every pair's book must be open under one custody roster");
            }
            if b.frozen() {
                return Err("a pool is frozen for a custody handover");
            }
            // CHAIN-OBJECT: this object's own `raise` against each book's counters, which only folded objects move
            if b.raised != self.raise || b.closed != self.raise.saturating_add(1) {
                return Err("an EarnEpoch raises the window every pair has closed and not yet raised");
            }
        }
        let n = b0.roster.len();
        if self.phase1.len() != n {
            return Err("the EarnEpoch names a phase-1 digest per custodian of the roster");
        }
        let header = self.header();
        let first = self.first as usize;
        for k in first..first + self.parts.len() {
            // CHAIN-CARRIES-REVIEWED: `epoch_pending` is BOOK state (journaled with the peg ledger, rebuilt by every node's
            // fold), filled only by folded chunks of this same object kind — exactly the settlement's `pending` slots; each
            // chunk is a chain object the block carries, so no node applies from a slot another node lacks.
            if b0.epoch_pending.get(k).is_some_and(Option::is_some) {
                return Err("a custodian's slot already holds its part of this EarnEpoch");
            }
        }
        let forms = ba::epoch_statements(books.len(), self.dg).ok_or("the EarnEpoch's statements cannot form")?;
        let ch = ba::AuditChallenges::derive_n(&epoch_transcript(self.raise, self.dg, &self.phase1), ba::EPOCH_STATEMENTS);
        let r1cs = ba::epoch_r1cs(books.len(), &ch, &forms).ok_or("the EarnEpoch's audit circuit cannot form")?;
        for (k, part) in self.parts.iter().enumerate() {
            let i = first + k;
            let published: Vec<ba::AuditPublished> = part.published.iter().map(|(w, s, u)| ba::AuditPublished { w: *w, s: s.clone(), u: u.clone() }).collect();
            let commits: Vec<[Fa4; 4]> = books.iter().map(|b| f4(&b.close_commits[i])).collect();
            let io = ba::epoch_io(&commits, &f4(&self.phase1[i]), &ch, &forms, &published);
            if !usdm_decider::spartan_ccs::verify_committed(&r1cs, &io, &part.audit) {
                return Err("a custodian's EarnEpoch audit does not verify");
            }
        }
        if !self.closes() {
            return Ok(false);
        }
        let mut all: Vec<&Vec<(Word, Vec<Word>, Vec<Word>)>> = Vec::with_capacity(n);
        for k in 0..first {
            // CHAIN-CARRIES-REVIEWED: the held parts are book state filled by folded chunks (see above), never a RAM slot
            match b0.epoch_pending.get(k).and_then(Option::as_ref) {
                Some(h) if h.header == header => all.push(&h.published),
                _ => return Err("the closing chunk arrived before every other part of its EarnEpoch was held"),
            }
        }
        all.extend(self.parts.iter().map(|p| &p.published));
        let t = b0.t as usize;
        for si in 0..ba::EPOCH_STATEMENTS {
            let col = |f: &dyn Fn(&(Word, Vec<Word>, Vec<Word>)) -> Word| -> Vec<Word> { all.iter().map(|p| ba::fadd(&f(&p[si]), &[0; 4])).collect() };
            if !ba::sharing_holds(&col(&|p| p.0), t, true) {
                return Err("an EarnEpoch statement does not open to zero (the rate is not the window's)");
            }
            for r in 0..ba::AUDIT_REPS {
                if !ba::sharing_holds(&col(&|p| p.1[r]), 2 * t, true) {
                    return Err("an EarnEpoch statement's bits are not bits");
                }
                if !ba::sharing_holds(&col(&|p| p.2[r]), t, false) {
                    return Err("an EarnEpoch statement's bit sharings are not of degree t");
                }
            }
        }
        Ok(true)
    }
}

/// ⭐ Earn step 3 — whether every pair's book has closed exactly one window past a common raise (`Some(raise)`), what an
/// EarnEpoch completes. CHAIN-OBJECT: a function of the books, which only folded objects move.
#[must_use]
pub fn epoch_due(books: &[DefiBook]) -> Option<u64> {
    let first = books.first()?;
    let raise = first.raised;
    (books.len() == usize::from(PAIRS) && books.iter().all(|b| b.is_open() && b.raised == raise && b.closed == raise.saturating_add(1) && !b.frozen())).then_some(raise)
}

/// ⭐ EARN STEP 3 — the raise a pair's index takes at rate `dg` over its closed window's public weight: `⌊dg·W_c / 2^K⌋`.
#[must_use]
pub fn index_raise(dg: u64, w_closed: u128) -> u64 {
    u64::try_from(u128::from(dg).saturating_mul(w_closed) >> ba::EARN_RATE_BITS).unwrap_or(u64::MAX)
}

/// The books after a verified EarnEpoch chunk: a held chunk fills its custodians' slots (pair 0's book); the closing chunk
/// RAISES every pair — its index by [`index_raise`] (the open batch keeps its opening snapshot), its raise counter, and the
/// rate it hands its next batch to merge — and clears the held parts.
/// CHAIN-OBJECT: the folded `DefiEarnEpochTx` and the held parts its earlier chunks carried.
pub fn apply_earn_epoch(books: &mut [DefiBook], t: &DefiEarnEpochTx, closing: bool) {
    let n = books.first().map_or(0, |b| b.roster.len());
    if !closing {
        if let Some(b0) = books.first_mut() {
            if b0.epoch_pending.len() != n {
                b0.epoch_pending = vec![None; n];
            }
            let header = t.header();
            for (k, p) in t.parts.iter().enumerate() {
                // CHAIN-CARRIES-REVIEWED: writing the folded chunk's own parts into book state (journaled), as a settlement's
                // held parts are written; the block carried them
                if let Some(slot) = b0.epoch_pending.get_mut(t.first as usize + k) {
                    *slot = Some(HeldEpochPart { header, published: p.published.clone() });
                }
            }
        }
        return;
    }
    for b in books.iter_mut() {
        b.income_index = b.income_index.saturating_add(index_raise(t.dg, b.w_closed)).min((1u64 << ba::INDEX_BITS) - 1);
        b.raised = b.raised.saturating_add(1);
        b.pending_dg = Some(t.dg);
        b.w_closed = 0;
    }
    if let Some(b0) = books.first_mut() {
        b0.epoch_pending.clear();
    }
}

// ───────────────────────────── the claim ─────────────────────────────

/// ⭐ THE CLAIM (or refund) — names no order. §9.6: (1) PoW — the carrying block and the tx stamp; (2) the claim relation
/// (`claim_circuit`, of a fixed shape), the member leg of its leaf (`Node::member_leg_object_verdict`, cross-bound by
/// `leaf_commit` and the claim nullifier) and the committed asset mint of its note (`verify_asset_mint_validity_committed_bytes`
/// against `out_commit`); (3) value: the minted amount is exactly its order's fill (or its burned amount) — the relation pins
/// it, the leaf exists only for a settled (or expired) order; (4) replay: the claim nullifier `P(a_blind, ·)`, ONE per order,
/// refused by the spent set — a claim and a refund of the same order cannot both pay; (5) bounded: one relation, one leg, one
/// mint; (6) parity with the cash-out claim (§19.4): the same anonymous member leg at an anchor, the same nullifier set.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DefiClaimTx {
    /// ⭐ §18.14 — the pair whose assets it mints
    pub pair: u8,
    #[serde(with = "lanes8")]
    pub nullifier: [u64; 8],
    #[serde(with = "lanes8")]
    pub leaf_commit: [u64; 8],
    #[serde(with = "lanes8")]
    pub out_commit: [u64; 8],
    /// ⭐ §18.14 — true: it mints the pair's coin (a seller's fill, a buyer's money back); false: it mints SAT (a buyer's fill, a seller's SAT back). The asset, never the side.
    pub pays_y: bool,
    pub claim_proof: Vec<u8>,
    pub member_carrier: Vec<u8>,
    pub member_tuple: Vec<u8>,
    pub mint_carrier: Vec<u8>,
    /// the minted note (its commitment first), as every credited note rides
    pub note: Vec<u8>,
    pub owner_clue: Vec<u8>,
}

impl DefiClaimTx {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// The claim's bounded shape.
    #[must_use]
    pub fn shaped(&self) -> bool {
        self.pair < PAIRS
            && self.claim_proof.len() <= MAX_PROOF_BYTES
            && self.member_carrier.len() <= MAX_PROOF_BYTES
            && self.member_tuple.len() <= 256
            && self.mint_carrier.len() <= MAX_PROOF_BYTES
            && self.note.len() == crate::cover::PQ_NOTE_BYTES
            && self.owner_clue.len() == crate::peg_in_tx::OWNER_CLUE_MAX
    }
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        t.shaped().then_some(t)
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiClaim, &p))
    }
    /// The asset this claim mints: the pair's coin or SAT.
    #[must_use]
    pub fn asset(&self) -> [u64; 3] {
        if self.pays_y { pair_y_tag(self.pair) } else { crate::satoshi::asset_tag() }
    }
    /// The note's commitment.
    #[must_use]
    pub fn note_cm(&self) -> Option<crate::spend_frontier::Digest4> {
        crate::spend_frontier::note_cm_of(&self.note)
    }
    /// The stateless half: the claim relation (its circuit's shape is fixed) and the committed mint of the note.
    #[must_use]
    pub fn self_valid(&self) -> Option<&'static str> {
        let io = ba::claim_io(&self.nullifier, &self.leaf_commit, &self.out_commit, self.pays_y);
        let Some(r1cs) = ba::claim_r1cs() else { return Some("the claim circuit cannot form") };
        if !usdm_decider::spartan_ccs::verify_committed(&r1cs, &io, &self.claim_proof) {
            return Some("the claim relation does not verify (an over-claim, or a leaf no settlement inserted)");
        }
        let Some(cm) = self.note_cm() else { return Some("the claim carries no note") };
        if !usdm_decider::whir_rec_block::verify_asset_mint_validity_committed_bytes(&self.mint_carrier, cm, self.asset(), self.out_commit) {
            return Some("the minted note does not open to the claimed amount");
        }
        None
    }
    /// The claim's nullifier as the spent set's 32-byte key.
    #[must_use]
    pub fn own_nullifiers(&self) -> Vec<[u8; 32]> {
        vec![crate::spend_frontier::leaf_to_cm_bytes(self.nullifier)]
    }
}

/// The book after a verified settlement chunk: a held chunk fills its custodians' slots; the closing chunk moves the pool to
/// every custodian's new commitment (the held ones, then its own), records the tick and opens the next batch.
pub fn apply_settlement(book: &mut DefiBook, t: &DefiSettleTx, ordinal: u64, block_ts: u64) {
    let n = book.roster.len();
    if !t.closes() {
        if book.pending.len() != n {
            book.pending = vec![None; n];
        }
        let header = t.header();
        for (k, p) in t.parts.iter().enumerate() {
            if let Some(slot) = book.pending.get_mut(t.first as usize + k) {
                *slot = Some(HeldPart { header, published: p.published.clone(), new_pool: p.new_pool, new_fee: p.new_fee, new_close: p.new_close });
            }
        }
        return;
    }
    // CHAIN-OBJECT: the folded DefiSettleTx's closing chunk (`t`) and the held parts its earlier chunks carried — the pool, fee
    // and close commitments move only as the block's settlement object says, after `chunk_verdict` found every earlier slot held
    let held: Vec<([u64; 4], [u64; 4], [u64; 4])> = book
        .pending
        .iter()
        .take(t.first as usize)
        .map(|h| h.as_ref().map_or(([0; 4], [0; 4], [0; 4]), |h| (h.new_pool, h.new_fee, h.new_close)))
        .collect();
    let all: Vec<([u64; 4], [u64; 4], [u64; 4])> = held.into_iter().chain(t.parts.iter().map(|p| (p.new_pool, p.new_fee, p.new_close))).collect();
    book.pool_commits = all.iter().map(|c| c.0).collect();
    book.fee_commits = all.iter().map(|c| c.1).collect();
    book.close_commits = all.iter().map(|c| c.2).collect();
    book.last_tick = t.tick;
    book.last_expired = false;
    book.last_sells = t.sells;
    book.prices.record(block_secs(block_ts), i32::try_from(t.tick).unwrap_or(0));
    // ⭐ EARN STEP 3 — the window's public side, as the batch's snapshot says it moved (the audit moved the shares alike): a
    // sample adds this Earn tick's weight; the deposit batch starts the window's sampling; the close freezes the window's
    // weight for its raise and stops sampling. CHAIN-OBJECT: the settlement object's own tick and the book's opening snapshot.
    if book.sample {
        book.w_open = book.w_open.saturating_add(sample_weight(t.tick));
    }
    if book.deposits {
        book.deposited = book.raised;
        book.sampling = true;
    }
    if book.close_out {
        book.closed = book.closed.saturating_add(1);
        book.close_window = block_ts / crate::defi_earn::EARN_WINDOW_MS;
        book.sampling = false;
        book.w_closed = book.w_open;
        book.w_open = 0;
    }
    book.next_batch(ordinal, block_ts);
}

/// The book after an expiry: the next batch (the pool unchanged). A handover the frozen batch did not complete is dropped
/// (the old roster keeps the pool; the next Open retries). ⭐ Earn step 3: nothing the expired batch's snapshot named happened
/// — a merge it was to make is handed to the next batch, which also takes up its deposit batch or its close again.
pub fn apply_expiry(book: &mut DefiBook, ordinal: u64, block_ts: u64) {
    if book.frozen() {
        book.handover = None;
    }
    book.last_expired = true;
    book.last_sells = false;
    book.prices.record(block_secs(block_ts), i32::try_from(book.last_tick).unwrap_or(0));
    // CHAIN-OBJECT: the folded expiry object; the merge the expired batch was to carry waits for the next one
    if book.merge_dg.is_some() {
        book.pending_dg = book.merge_dg.take();
    }
    book.next_batch(ordinal, block_ts);
}

/// A custodian's pool commitment over its four lines (X, Y, F_X, F_Y), as the book stores it.
#[must_use]
pub fn pool_commit(lines: &[Word; ba::POOL_LINES], salt: &[Fa4; 4]) -> [u64; 4] {
    u4(&ba::chain_commit(lines, salt))
}

/// ⭐ Earn steps 1 + 3 — a custodian's fee-state commitment over its shares of the open lines (B, E, A).
#[must_use]
pub fn fee_commit(lines: &[Word; ba::FEE_LINES], salt: &[Fa4; 4]) -> [u64; 4] {
    u4(&ba::fee_commit(lines, salt))
}

/// ⭐ Earn step 3 — a custodian's close commitment over its shares of the closed window's lines (E_c, A_c).
#[must_use]
pub fn close_commit(lines: &[Word; ba::CLOSE_LINES], salt: &[Fa4; 4]) -> [u64; 4] {
    u4(&ba::close_commit(lines, salt))
}

/// ⭐ Earn steps 1 + 3 — the launch's fee commitments of pair `pair` for a roster of `n`: each custodian's shares of PUBLIC
/// zeros (every share of a public zero is zero) under the salt every node derives (`br15_audit::launch_fee_salt`) — no
/// dealer, nothing secret.
#[must_use]
pub fn launch_fee_commits(pair: u8, n: usize) -> Vec<[u64; 4]> {
    (0..n).map(|i| fee_commit(&[[0; 4]; ba::FEE_LINES], &ba::launch_fee_salt(pair, i))).collect()
}

/// ⭐ Earn step 3 — the launch's close commitments (public zeros, `br15_audit::launch_close_salt`).
#[must_use]
pub fn launch_close_commits(pair: u8, n: usize) -> Vec<[u64; 4]> {
    (0..n).map(|i| close_commit(&[[0; 4]; ba::CLOSE_LINES], &ba::launch_close_salt(pair, i))).collect()
}

/// An order share's commitment over its lines (X, then each bucket's Y), as the order carries it.
#[must_use]
pub fn order_commit(lines: &[Word], salt: &[Fa4; 4]) -> [u64; 4] {
    u4(&ba::chain_commit(lines, salt))
}

// ───────────────────────────── the fold door ─────────────────────────────

/// What applying a DeFi object did at the fold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefiApply {
    NotDefi,
    Applied,
    Refused(&'static str),
}


/// A DeFi object that spends nothing (a settlement, an expiry) as a transaction: its blob, its content id, and the anti-spam
/// stamp ground exactly as `price_mark_tx::as_pq_tx` grinds it (a bare blob with `pow_stamp 0` is refused at the door).
#[must_use]
pub fn as_pq_tx(blob: Vec<u8>, stamp_bits: u32) -> crate::mempool::PqTx {
    let mut tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: Vec::new(),
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(),
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    // Bounded BY CONSTRUCTION: 2^stamp_bits expected tries.
    let mut s = 0u64;
    loop {
        tx.pow_stamp = s;
        if tx.stamp_work() >= stamp_bits {
            break;
        }
        s = s.wrapping_add(1);
    }
    tx
}

/// ⭐ WHERE AN ORDER'S FILL IS (a wallet learning its batch's outcome): its refund leaf, or its batch's leaf at a tick and a
/// lowest filling bucket, among the note commitments this node's held records name — `Some(None)` refunded,
/// `Some(Some((t, j_min)))` settled (the claim then pays the fill, or the amount back if the order's bucket is below `j_min`),
/// `None` not (yet) held. `tick` narrows the search to the batch's known tick; without it, every tick of the range.
/// O1-INFINITY-REVIEWED: the tick range and the bucket count are protocol constants, the held records the node's bounded window.
#[must_use]
pub fn find_fill(held: &std::collections::HashSet<[u8; 32]>, amount_commit: &[u64; 8], limit_commit: &[u64; 8], tick: Option<i64>) -> Option<Option<(i64, u64, bool)>> {
    find_fill_x(held, amount_commit, limit_commit, tick).map(|x| x.0)
}

/// ⭐ EARN — [`find_fill`] with the leaf's own lanes: `(outcome, earn, dep)` — an Earn leaf is `Some((tick, ORDER_BUCKETS,
/// true))` with `earn`; a deposit batch's leaf whose sells counted has `dep`. No leaf names an income index (the order
/// carries its own), so a wallet finds its leaf from what it placed, however long it was away.
/// O1-INFINITY-REVIEWED: the bounded tick range, the bucket count and the two lanes are protocol constants.
#[must_use]
pub fn find_fill_x(held: &std::collections::HashSet<[u8; 32]>, amount_commit: &[u64; 8], limit_commit: &[u64; 8], tick: Option<i64>) -> Option<(Option<(i64, u64, bool)>, bool, bool)> {
    let has = |leaf: [u64; 8]| held.contains(&crate::spend_frontier::leaf_to_cm_bytes(leaf));
    if has(refund_leaf(amount_commit, limit_commit)) {
        return Some((None, false, false));
    }
    let at = |t: i64| -> Option<(Option<(i64, u64, bool)>, bool, bool)> {
        if has(earn_leaf(amount_commit, limit_commit, t, true)) {
            return Some((Some((t, ba::ORDER_BUCKETS as u64, true)), true, false));
        }
        [(true, true), (true, false), (false, false)].into_iter().find_map(|(sells, dep)| {
            (0..=ba::ORDER_BUCKETS as u64).find(|j| has(claim_leaf_at_x(amount_commit, limit_commit, t, *j, sells, dep))).map(|j| (Some((t, j, sells)), false, dep))
        })
    };
    match tick {
        Some(t) => at(t),
        None => (-crate::defi_clear::TICK_RANGE..crate::defi_clear::TICK_RANGE - 1).find_map(at),
    }
}

// ───────────────────────────── the end-to-end pins (two nodes) ─────────────────────────────
