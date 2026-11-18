// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.8) — THE CUSTODY RUNTIME: the computation the custody set runs BETWEEN its members to settle a batch,
//! over Shamir shares of 2^255 − 19 with no dealer and no party that ever holds a pool side, an order or a sum in the clear.
//!
//! **One batch, end to end** ([`run_batch`]):
//! 1. each custodian sums its own shares — pool `X`, `Y`, every order's `(x, y)` → `ΣX = X + ΔX`, `ΣY = Y + ΔY` (local);
//! 2. the staged tick search (`defi_clear::tick_search`): one comparison bit per candidate tick opens, each a bit every
//!    observer derives from the final tick — the tick is the ONLY value the chain learns;
//! 3. the booking over shares: `q_Y = ⌈ΔX·n_t / d_t⌉` (d_t a power of two: one exact truncation) and
//!    `q_X = ⌊W·R / 2^(152+u)⌋ + 2` with `W = ΔY·d_{t+1}`, `n_{t+1} = m·2^u`, `R = ⌈2^152 / m⌉`, W split at 2^76 so every
//!    product stays inside the masked width — `q·n − Δ·d` in `[0, d)` and `(0, 3n)`, inside the audited `[0, 4n)`. An empty
//!    batch (no orders: a public fact) books `q = 0` exactly. Cons, quantified: a traded batch's `q_X` over-books by at most
//!    3 SAT base units nobody claims — ≤ 3 × 8,640 batches/day = 0.095 SAT/year leaves the pool's books (SAT supply only
//!    falls; no one is paid it); the exact ceiling would add one comparison set (≈ 9 online rounds, ≈ 4.5 s over onion links);
//! 4. the audit's bits: every statement `z` (linear in the shared values, public coefficients) is bit-decomposed over shares
//!    (`bits_many`), and the masks are dealt by every custodian and summed (`Party::deal_sum`);
//! 5. each custodian forms its own `AuditWitness` from ITS shares only, commits phase 1, and — after the Fiat–Shamir challenges
//!    over every phase-1 digest — proves its audit; the settlement carries every part and the claim leaves.
//!
//! What a custodian sees: its own shares, the masked openings (`v + r` with a 40-bit statistical mask, DN07's `xy + r`), the
//! tick search's comparison bits — nothing below a third of the roster learns a value (honest majority `t = ⌊(n − 1)/3⌋`).
//!
//! Entropy: every run is keyed by 32 bytes from the OS (or the simulator's stream when one is installed) — [`custody_entropy`].
//!
//! ROOT-LAYER: the custody set's own computation — the chain decides nothing here; `DefiSettleTx::verdict` decides the result.
//! MEASURED: `br15_the_custody_runtime_settles_a_batch_over_shares_and_every_node_accepts_it` (rounds, bytes, CPU printed).
//! MUST-STAY-GREEN: every `br15_*` pin of `defi_clear`, `defi_batch` and `usdm_decider::br15_audit`.
//!
//! BORROWED: Damgård–Nielsen 2007 (multiplication), Damgård–Fitzi–Kiltz–Nielsen–Toft 2006 (bits), Catrina–Saxena 2010 and
//! Catrina–de Hoogh 2010 (truncation, log-depth comparison), Granlund–Montgomery 1994 (division by an invariant through a
//! reciprocal), Baum–Damgård–Orlandi 2014 (each party proves its own steps). None — novel crypto: the audited-pair settlement.

use crate::defi_batch::{self as db, CustodianPart, DefiBook, DefiOrderTx, DefiSettleTx, Word};
use crate::defi_clear::{self as dc, F255};
use crate::defi_mpc_net::{ceil_pow2_over, Comm, MemComm, NetResult, Party};
use p3_field::PrimeCharacteristicRing;
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// What custodian i holds between batches: its shares of the pool's four lines — X, Y and the floors F_X, F_Y (spec §18.10)
/// — and the salt of its last commitment; (Earn steps 1 + 3) its shares of the pair's open fee state (the backing B, the
/// window's fresh fees E and sampled presence A) and their salt; and its shares of the closed window's lines (E_c, A_c) and
/// their salt.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CustodianState {
    pub lines: [Word; ba::POOL_LINES],
    pub salt: [Fa4; 4],
    pub fee: [Word; ba::FEE_LINES],
    pub fee_salt: [Fa4; 4],
    pub close: [Word; ba::CLOSE_LINES],
    pub close_salt: [Fa4; 4],
}

impl CustodianState {
    /// Its pool commitment (what the book holds for it).
    #[must_use]
    pub fn commit(&self) -> [u64; 4] {
        db::pool_commit(&self.lines, &self.salt)
    }
    /// Its fee commitment (what the book's `fee_commits` holds for it).
    #[must_use]
    pub fn fee_commit(&self) -> [u64; 4] {
        db::fee_commit(&self.fee, &self.fee_salt)
    }
    /// Its close commitment (what the book's `close_commits` holds for it).
    #[must_use]
    pub fn close_commit(&self) -> [u64; 4] {
        db::close_commit(&self.close, &self.close_salt)
    }
    /// Whether all three of its commitments are the ones the book holds for custodian `i` (a strict equality on each; a slot
    /// the book lacks is never matched).
    #[must_use]
    pub fn is_the_books(&self, book: &DefiBook, i: usize) -> bool {
        book.pool_commits.get(i).is_some_and(|c| *c == self.commit())
            && book.fee_commits.get(i).is_some_and(|c| *c == self.fee_commit())
            && book.close_commits.get(i).is_some_and(|c| *c == self.close_commit())
    }
    /// The state a custodian captures from the LAUNCH: its pool shares under their salt, and the launch fee state and closed
    /// lines — its shares of public zeros, under the salts every node derives (`br15_audit::launch_fee_salt`,
    /// `launch_close_salt`), whose commitments the launch book holds (`defi_batch::launch_fee_commits`, `launch_close_commits`).
    #[must_use]
    pub fn at_launch(lines: [Word; ba::POOL_LINES], salt: [Fa4; 4], pair: u8, i: usize) -> Self {
        CustodianState {
            lines,
            salt,
            fee: [ba::fsmall(0); ba::FEE_LINES],
            fee_salt: ba::launch_fee_salt(pair, i),
            close: [ba::fsmall(0); ba::CLOSE_LINES],
            close_salt: ba::launch_close_salt(pair, i),
        }
    }
    /// Its state lines in the order a handover re-shares them: the pool's, then the fee state, then the closed lines.
    #[must_use]
    pub fn state_lines(&self) -> [Word; ba::STATE_LINES] {
        core::array::from_fn(|l| {
            if l < ba::FEE_AT {
                self.lines[l]
            } else if l < ba::CLOSE_AT {
                self.fee[l - ba::FEE_AT]
            } else {
                self.close[l - ba::CLOSE_AT]
            }
        })
    }
}

/// ⭐ Earn steps 1 + 3 — A HANDOVER SUB-SHARE as a new custodian captures it: its share of every state line (the pool's four,
/// the fee state's three, the closed window's two) and the dealer's salt for it, opened from the one sealed-share shape with
/// all nine slots used.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubShare {
    pub lines: [Word; ba::STATE_LINES],
    pub salt: [Fa4; 4],
}

impl SubShare {
    /// The sub-share commitment a dealing publishes for it.
    #[must_use]
    pub fn commit(&self) -> [u64; 4] {
        db::u4(&ba::chain_commit(&self.lines, &self.salt))
    }
}

/// One order's share as custodian i opened it from its sealed share: its line shares (X, then each maximum-price bucket's Y)
/// and the owner's salt.
pub type OrderShare = ([Word; ba::ORDER_LINES], [Fa4; 4]);

/// The tick search's first-stage window around the last tick (and every later stage's split).
pub const SEARCH_WIDTH: usize = 15;

/// The booking reciprocal's precision: `R = ⌈2^RECIP_BITS / m⌉` for a mantissa `m ∈ [2^23, 2^24)` — every `W = ΔY·d_{t+1}`
/// below `2^RECIP_BITS` (sums below 2^64, `d ≤ 2^88`) books within three units.
pub const RECIP_BITS: u32 = 152;
/// Where `W` is split so each product with `R` (`< 2^130`) stays below `2^206`, inside the masked width (`206 + 40 < 255`).
pub const SPLIT_BITS: u32 = 76;

/// 32 bytes of entropy: the simulator's stream when one is installed on this thread, else the OS's. `None` if neither answers.
#[must_use]
pub fn custody_entropy() -> Option<[u8; 32]> {
    let mut b = [0u8; 32];
    if crate::budget_clock::sim_entropy_fill(&mut b) {
        return Some(b);
    }
    use std::io::Read as _;
    std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)).ok()?;
    Some(b)
}

fn f(v: &Word) -> F255 {
    F255(*v)
}

/// A degree-`t` sharing of `v` at x = 1..=n from the coefficients `cs` (`v` the constant).
fn eval_shares(v: &Word, cs: &[Word], n: usize) -> Vec<Word> {
    let c: Vec<Word> = std::iter::once(*v).chain(cs.iter().copied()).collect();
    (1..=n as u64).map(|x| ba::poly_eval(&c, x)).collect()
}

/// A sealed order share's plaintext: every line's share (32 bytes each) and the salt (four 4-byte field elements).
pub const SHARE_PLAIN_BYTES: usize = 32 * ba::ORDER_LINES + 16;
const SALT_AT: usize = 32 * ba::ORDER_LINES;
const SEAL_TAG_BYTES: usize = 16;

fn share_plain(s: &OrderShare) -> [u8; SHARE_PLAIN_BYTES] {
    use p3_field::PrimeField64;
    let mut out = [0u8; SHARE_PLAIN_BYTES];
    for (k, word) in s.0.iter().flatten().enumerate() {
        out[8 * k..8 * k + 8].copy_from_slice(&word.to_le_bytes());
    }
    for (k, e) in s.1.iter().enumerate() {
        out[SALT_AT + 4 * k..SALT_AT + 4 + 4 * k].copy_from_slice(&(e.as_canonical_u64() as u32).to_le_bytes());
    }
    out
}
fn share_of_plain(p: &[u8; SHARE_PLAIN_BYTES]) -> Option<OrderShare> {
    let word = |o: usize| -> Word { core::array::from_fn(|k| u64::from_le_bytes(p[o + 8 * k..o + 8 * k + 8].try_into().unwrap_or([0; 8]))) };
    let lines: [Word; ba::ORDER_LINES] = core::array::from_fn(|l| word(32 * l));
    // a share is a reduced field element; a salt element is a canonical KoalaBear element
    if lines.iter().any(|x| ba::fadd(x, &[0; 4]) != *x) {
        return None;
    }
    let mut salt = [Fa4::ZERO; 4];
    for (k, e) in salt.iter_mut().enumerate() {
        let v = u32::from_le_bytes(p[SALT_AT + 4 * k..SALT_AT + 4 + 4 * k].try_into().ok()?);
        *e = Fa4::from_u64(u64::from(v));
    }
    // a salt element is canonical (one encoding per share): re-encoding gives back the bytes
    if share_plain(&(lines, salt))[SALT_AT..] != p[SALT_AT..] {
        return None;
    }
    Some((lines, salt))
}
fn seal_stream(ss: &[u8], ct: &[u8]) -> [u8; SHARE_PLAIN_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/br15-order-share/stream/v1");
    h.update(ss);
    h.update(ct);
    let mut out = [0u8; SHARE_PLAIN_BYTES];
    h.finalize_xof().fill(&mut out);
    out
}
fn seal_tag(ss: &[u8], body: &[u8]) -> [u8; SEAL_TAG_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/br15-order-share/tag/v1");
    h.update(ss);
    h.update(body);
    let mut t = [0u8; SEAL_TAG_BYTES];
    t.copy_from_slice(&h.finalize().as_bytes()[..SEAL_TAG_BYTES]);
    t
}
/// A sealed order share's width: ML-KEM-768 ciphertext ‖ tag ‖ masked plaintext.
#[must_use]
pub fn sealed_share_len() -> usize {
    crate::pqkem::ciphertext_len() + SEAL_TAG_BYTES + SHARE_PLAIN_BYTES
}

/// The epoch layer's keystream for custodian `i`'s share under the order's epoch key `k` (all zero bytes XOR nothing: the
/// launch pool's genesis shares carry no epoch layer — there is no epoch at genesis).
fn epoch_stream(k: &[u8; 32], i: usize) -> [u8; SHARE_PLAIN_BYTES] {
    let mut out = [0u8; SHARE_PLAIN_BYTES];
    blake3::Hasher::new_derive_key("MUSD/br15-order-share/epoch-layer/v1").update(k).update(&(i as u64).to_le_bytes()).finalize_xof().fill(&mut out);
    out
}

fn seal_plain(ek: &[u8], plain: &[u8; SHARE_PLAIN_BYTES]) -> Option<Vec<u8>> {
    let (ss, ct) = crate::pqkem::encapsulate(ek)?;
    let ks = seal_stream(&ss, &ct);
    let body: Vec<u8> = plain.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect();
    let mut out = ct;
    out.extend_from_slice(&seal_tag(&ss, &body));
    out.extend_from_slice(&body);
    Some(out)
}

/// ⭐ SEAL one custodian's share to its ML-KEM-768 custody key (`MembershipBondHeader::kem_ek`): `ct ‖ tag ‖ masked share` —
/// the epoch deal's sealing shape (`epoch_deal_tx::seal_share`), borrowed. The launch pool's genesis shares use this bare
/// layer; an order's shares go through [`seal_dealing`], which adds the epoch layer.
#[must_use]
pub fn seal_order_share(ek: &[u8], s: &OrderShare) -> Option<Vec<u8>> {
    seal_plain(ek, &share_plain(s))
}

fn open_plain(dk: &[u8], sealed: &[u8]) -> Option<[u8; SHARE_PLAIN_BYTES]> {
    if sealed.len() != sealed_share_len() {
        return None;
    }
    let (ct, rest) = sealed.split_at(crate::pqkem::ciphertext_len());
    let (tag, body) = rest.split_at(SEAL_TAG_BYTES);
    let ss = crate::pqkem::decapsulate(ct, dk)?;
    if seal_tag(&ss, body) != tag {
        return None;
    }
    let ks = seal_stream(&ss, ct);
    let mut p = [0u8; SHARE_PLAIN_BYTES];
    for (o, (b, k)) in p.iter_mut().zip(body.iter().zip(ks.iter())) {
        *o = b ^ k;
    }
    Some(p)
}

/// ⭐ OPEN a bare-sealed share (the launch pool's) with this custodian's decapsulation key. `None` when it is not ours,
/// malformed, or does not decode to a share.
#[must_use]
pub fn open_order_share(dk: &[u8], sealed: &[u8]) -> Option<OrderShare> {
    share_of_plain(&open_plain(dk, sealed)?)
}

/// ⭐ SEAL a custodian's launch-pool shares to its custody key, in the one sealed-share shape (the pool's four lines in the
/// first four line slots, the last slot zero — every sealed share on the chain is byte-shape-identical).
#[must_use]
pub fn seal_pool_share(ek: &[u8], lines: &[Word; ba::POOL_LINES], salt: &[Fa4; 4]) -> Option<Vec<u8>> {
    let slots: [Word; ba::ORDER_LINES] = core::array::from_fn(|l| lines.get(l).copied().unwrap_or([0; 4]));
    seal_order_share(ek, &(slots, *salt))
}

/// ⭐ OPEN a sealed launch-pool share with this custodian's decapsulation key (its last line slot must be zero): the pool's
/// lines and their salt. `None` when it is not ours or does not decode.
#[must_use]
pub fn open_pool_share(dk: &[u8], sealed: &[u8]) -> Option<([Word; ba::POOL_LINES], [Fa4; 4])> {
    let (lines, salt) = open_order_share(dk, sealed)?;
    if lines[ba::POOL_LINES..].iter().any(|l| *l != [0; 4]) {
        return None;
    }
    Some((core::array::from_fn(|l| lines[l]), salt))
}

/// ⭐ Earn step 1 — SEAL a handover sub-share (the pool's four lines and the fee line) to a new custodian's key, in the same
/// sealed-share shape: all [`ba::ORDER_LINES`] slots used, byte-shape-identical to every other sealed share.
#[must_use]
pub fn seal_sub_share(ek: &[u8], s: &SubShare) -> Option<Vec<u8>> {
    let slots: [Word; ba::ORDER_LINES] = core::array::from_fn(|l| s.lines.get(l).copied().unwrap_or([0; 4]));
    seal_order_share(ek, &(slots, s.salt))
}

/// ⭐ Earn step 1 — OPEN a sealed handover sub-share with this custodian's decapsulation key. `None` when it is not ours.
#[must_use]
pub fn open_sub_share(dk: &[u8], sealed: &[u8]) -> Option<SubShare> {
    let (lines, salt) = open_order_share(dk, sealed)?;
    if lines[ba::STATE_LINES..].iter().any(|l| *l != [0; 4]) {
        return None;
    }
    Some(SubShare { lines: core::array::from_fn(|l| lines[l]), salt })
}

/// ⭐ THE ORDER'S EPOCH KEY `k` (what a custodian recovers with the released epoch secret): `epoch_key::decapsulate` of the
/// order's epoch ciphertext under its epoch's public key. Once the epoch's secret is erased (§BR-9a step d, two epochs on)
/// no custody key opens the order's shares again.
#[must_use]
pub fn order_epoch_key(pk: &crate::epoch_key::EpochPublicKey, sk: &crate::epoch_key::EpochSecretKey, order: &crate::defi_batch::DefiOrderTx) -> Option<[u8; 32]> {
    crate::epoch_key::decapsulate(pk, sk, &order.epoch_ct)
}

/// ⭐ What custodian `i` captures from an order at the instant it applies (AGENTS.md §6: a witness is captured at arrival): its
/// sealed share opened with its own ML-KEM key AND the order's epoch key `k`, checked against the order's share commitment
/// `i`. `None` — the share is not this custodian's to hold (the order goes to the batch's complaint set and refunds).
#[must_use]
pub fn capture_order_share(dk: &[u8], k: &[u8; 32], i: usize, order: &crate::defi_batch::DefiOrderTx) -> Option<OrderShare> {
    let s = open_epoch_order_share(dk, k, i, order.sealed.get(i)?)?;
    (db::order_commit(&s.0, &s.1) == *order.share_commits.get(i)?).then_some(s)
}

/// Custodian `i`'s sealed share of an order, opened with its custody key `dk` and the order's epoch key `k` — not yet tied to any
/// order: the share's commitment names its order ([`db::order_commit`] against an order's `share_commits[i]`), never the position
/// it was filed at.
#[must_use]
pub fn open_epoch_order_share(dk: &[u8], k: &[u8; 32], i: usize, sealed: &[u8]) -> Option<OrderShare> {
    let mut p = open_plain(dk, sealed)?;
    for (b, m) in p.iter_mut().zip(epoch_stream(k, i).iter()) {
        *b ^= m;
    }
    share_of_plain(&p)
}

/// ⭐ THE OWNER'S SEALING of a dealt order to the roster's custody keys (roster order), under the order's epoch key `k`: each
/// share is masked by `k`'s keystream, then sealed to its custodian's ML-KEM key — opening it needs BOTH that custodian's key
/// and the epoch's released secret (forward secrecy: after the epoch is erased, a stolen custody key opens no past order).
#[must_use]
pub fn seal_dealing(d: &ba::OrderDealing, eks: &[Vec<u8>], k: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    if eks.len() != d.salts.len() {
        return None;
    }
    eks.iter()
        .enumerate()
        .map(|(i, ek)| {
            let mut p = share_plain(&(dealing_lines(d, i), d.salts[i]));
            for (b, m) in p.iter_mut().zip(epoch_stream(k, i).iter()) {
                *b ^= m;
            }
            seal_plain(ek, &p)
        })
        .collect()
}

/// Custodian `i`'s line shares of a dealing, as the fixed array the sealing carries.
#[must_use]
pub fn dealing_lines(d: &ba::OrderDealing, i: usize) -> [Word; ba::ORDER_LINES] {
    let v = d.shares(i);
    core::array::from_fn(|l| v.get(l).copied().unwrap_or([0; 4]))
}

/// What an order's DeFi half is: the dealing, the share commitments, the epoch ciphertext, the sealed shares, the share proof.
pub type OrderParts = (ba::OrderDealing, Vec<[u64; 4]>, Vec<u8>, Vec<Vec<u8>>, Vec<u8>);

/// ⭐ AN ORDER'S DeFi PARTS for the owner's wallet (Buy SAT): the dealing of `amount` at maximum-price bucket `bucket` (spec
/// §18.10; its limit commitment is `dealing.limit_commit()`) among the roster of custody keys `eks`,
/// one encapsulation to the custody's released key of epoch `epoch` (`epoch_pk`: the epoch BEFORE the running one, which the
/// custodians hold now and erase two epochs on), each share sealed under it and its custodian's key, and the share proof
/// bound to the batch, the epoch, the epoch ciphertext and every sealed share. The wallet adds its committed burn of `amount`
/// under `amount_blind` and the burn's member leg (`DefiOrderTx`).
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn order_parts(
    pair: u8,
    on_x: bool,
    eks: &[Vec<u8>],
    t: u32,
    epoch: u64,
    epoch_pk: &crate::epoch_key::EpochPublicKey,
    amount: u64,
    bucket: usize,
    amount_blind: [u64; 8],
    owner: [[u64; 8]; 3],
    lc_blind: [u64; 8],
    index: u64,
    key: &[u8; 32],
) -> Option<OrderParts> {
    order_parts_kind(pair, OrderKind::Trade { sell: on_x }, eks, t, epoch, epoch_pk, amount, bucket, amount_blind, owner, lc_blind, index, key)
}

/// ⭐ EARN STEP 2 — what an order IS (a witness: its shares and proof never say): a trade (a sell of SAT or a buy of SAT), a
/// SAT DEPOSIT (half sold through the batch, the rest joining the pool), or a WITHDRAWAL of a position's units.
#[derive(Clone, Debug)]
pub enum OrderKind {
    Trade { sell: bool },
    Deposit,
    Withdraw(ba::PositionWitness),
}

/// [`order_parts`] for every [`OrderKind`]: a deposit spends a SAT note of exactly `amount`; a withdrawal spends no note but
/// its position (`owner` unused), `amount` its units — at most [`ba::PositionWitness::units_max`]. `index` is the income
/// index of the batch the order is made for, as it opened (`DefiBook::batch_index`, the node's `/defi_book` names it): every
/// order carries it, and a deposit's entry and a withdrawal's "now" are it.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn order_parts_kind(
    pair: u8,
    kind: OrderKind,
    eks: &[Vec<u8>],
    t: u32,
    epoch: u64,
    epoch_pk: &crate::epoch_key::EpochPublicKey,
    amount: u64,
    bucket: usize,
    amount_blind: [u64; 8],
    owner: [[u64; 8]; 3],
    lc_blind: [u64; 8],
    index: u64,
    key: &[u8; 32],
) -> Option<OrderParts> {
    if eks.is_empty() || eks.len() > db::MAX_ROSTER || t as usize != (eks.len() - 1) / 3 || bucket >= ba::ORDER_BUCKETS {
        return None;
    }
    let on_x = matches!(kind, OrderKind::Trade { sell: true } | OrderKind::Deposit);
    let mut d = deal_order_on(pair, on_x, amount, bucket, amount_blind, eks.len(), t as usize, key);
    d.index = index;
    match kind {
        OrderKind::Trade { .. } => {}
        OrderKind::Deposit => d.deposit = true,
        OrderKind::Withdraw(pos) => {
            if pos.units_max().is_none_or(|m| amount > m) {
                return None;
            }
            d.withdraw = Some(pos);
        }
    }
    d.owner = owner;
    d.lc_blind = lc_blind;
    let mut m = [0u8; 32];
    Draw::new(key, b"USDMD-BR15-ORDER-EPOCH-MSG-v1").0.fill(&mut m);
    let (k, epoch_ct) = crate::epoch_key::encapsulate(epoch_pk, &m);
    let sealed = seal_dealing(&d, eks, &k)?;
    d.binding = db::sealed_binding(epoch, &epoch_ct, &sealed);
    let (r1cs, io, w) = ba::order_share_circuit(&d)?;
    let proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w)?;
    let commits = d.share_commits().iter().map(u4).collect();
    Some((d, commits, epoch_ct, sealed, proof))
}

/// ⭐ A CLAIM'S PROOF for the owner's wallet: the claim relation over `cw` (`br15_audit::claim_circuit`). `None` for a
/// witness that does not hold (an over-claim proves nothing).
#[must_use]
pub fn claim_proof(cw: &ba::ClaimWitness) -> Option<Vec<u8>> {
    let (r1cs, io, w) = ba::claim_circuit(cw)?;
    if !r1cs.is_satisfied(&r1cs.lay_z(&io, &w)?) {
        return None;
    }
    usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w)
}

/// The claim of an order of `amount` at maximum-price bucket `bucket`, at its batch's outcome — `Some((tick, j_min))` settled
/// (the lowest bucket that filled), `None` expired: `(p_num, p_den, j_min, out)` — the leaf's price and lowest filling bucket,
/// and what the claim mints: a settled buy whose bucket filled is paid its fill `g = ⌊a·d_{t+1}/n_{t+1}⌋` SAT less the fee
/// `⌈g·f⌉` (Earn step 1, `br15_audit::buy_paid`), one whose maximum was below the price — or of an expired batch — gets `a`
/// USDm back, whole.
#[must_use]
pub fn fill_of(amount: u64, bucket: usize, outcome: Option<(i64, u64)>) -> Option<(u128, u128, u64, u64)> {
    let (p_num, p_den, j_min) = match outcome {
        Some((t, j)) => {
            let (n1, d1) = dc::tick_ratio(t + 1);
            (d1, n1, j)
        }
        None => (1, 1, ba::ORDER_BUCKETS as u64),
    };
    let out = if bucket as u64 >= j_min && outcome.is_some() { ba::buy_paid(amount, p_num, p_den)? } else { amount };
    Some((p_num, p_den, j_min, out))
}

/// ⭐ §18.14 — A CLAIM'S TERMS at its batch's outcome: `Some((tick, j_min, sells))` settled, `None` expired: `(p_num, p_den, j_min, s_num, s_den, out)`: what its leaf names and what it mints.
/// A buyer: its fill `g = ⌊a·d_{t+1}/n_{t+1}⌋` SAT less `⌈g·f⌉` if its bucket filled, else its coin back, whole. A seller:
/// `⌊(a − ⌈a·f⌉)·n_t/d_t⌋` of the coin if the batch's sells counted, else its SAT back, whole (Earn step 1: the fee is on
/// the SAT leg, `f = 131/2^16`, and a refund pays none).
#[must_use]
pub fn claim_terms(amount: u64, bucket: usize, sell: bool, outcome: Option<(i64, u64, bool)>) -> Option<(u128, u128, u64, u128, u128, u64)> {
    let (p_num, p_den, j_min, (s_num, s_den)) = match outcome {
        Some((t, j, sells)) => {
            let (n1, d1) = dc::tick_ratio(t + 1);
            (d1, n1, j, db::sell_price(t, sells))
        }
        None => (1, 1, ba::ORDER_BUCKETS as u64, (0, 1)),
    };
    let out = if sell {
        if s_num == 0 { amount } else { ba::sell_paid(amount, s_num, s_den)? }
    } else if bucket as u64 >= j_min {
        ba::buy_paid(amount, p_num, p_den)?
    } else {
        amount
    };
    Some((p_num, p_den, j_min, s_num, s_den, out))
}

/// Uniform field words from an entropy key (a dealer's polynomial coefficients, a salt).
struct Draw(blake3::OutputReader);
impl Draw {
    fn new(key: &[u8; 32], ctx: &[u8]) -> Self {
        Draw(blake3::Hasher::new_keyed(key).update(ctx).finalize_xof())
    }
    fn u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.0.fill(&mut b);
        u64::from_le_bytes(b)
    }
    fn word(&mut self) -> Word {
        // 254 uniform bits, reduced (a pattern at or above p is ≈ 2^-250 likely; `fadd` reduces it anyway)
        ba::fadd(&[self.u64(), self.u64(), self.u64(), self.u64() >> 2], &[0; 4])
    }
    fn salt(&mut self) -> [Fa4; 4] {
        core::array::from_fn(|_| Fa4::from_u64(self.u64()))
    }
}

/// ⭐ AN ORDER'S DEALING (the owner's side, the wallet's Buy SAT): a buy of `amount` USDm at maximum-price bucket `bucket`,
/// its [`ba::ORDER_LINES`] degree-`t` sharings among `n` custodians (the amount on the bucket's Y line, every other line a
/// sharing of 0 — every order carries every line) and one salt per custodian, all from `key`.
#[must_use]
pub fn deal_order(amount: u64, bucket: usize, amount_blind: [u64; 8], n: usize, t: usize, key: &[u8; 32]) -> ba::OrderDealing {
    deal_order_on(0, false, amount, bucket, amount_blind, n, t, key)
}

/// ⭐ §18.14 — an order's dealing on `pair`: a sell of `amount` SAT (`on_x`), or a buy with `amount` of the pair's coin. Every line is dealt either way, so the shares never say which.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn deal_order_on(pair: u8, on_x: bool, amount: u64, bucket: usize, amount_blind: [u64; 8], n: usize, t: usize, key: &[u8; 32]) -> ba::OrderDealing {
    let mut d = Draw::new(key, b"USDMD-BR15-ORDER-DEAL-v2");
    ba::OrderDealing {
        amount,
        amount_blind,
        bucket,
        on_x,
        deposit: false,
        withdraw: None,
        x_tag: crate::satoshi::asset_tag(),
        y_tag: db::pair_y_tag(pair),
        coeffs: (0..ba::ORDER_LINES).map(|_| (0..t).map(|_| d.word()).collect()).collect(),
        salts: (0..n).map(|_| d.salt()).collect(),
        binding: [0; 8],
        owner: [[0; 8]; 3],
        lc_blind: [0; 8],
        cover: None,
        index: 0,
    }
}

/// ⭐ EARN STEP 2 — a SAT DEPOSIT's dealing on `pair`: `⌊a/2⌋` on the sold line (a sell the search prices), the rest on
/// the join line. Every line is dealt, as for every order.
#[must_use]
pub fn deal_deposit_on(pair: u8, amount: u64, amount_blind: [u64; 8], n: usize, t: usize, key: &[u8; 32]) -> ba::OrderDealing {
    ba::OrderDealing { deposit: true, ..deal_order_on(pair, true, amount, 0, amount_blind, n, t, key) }
}

/// ⭐ THE POOL'S DEALING (spec §18.10): degree-`t` sharings of the pool's four lines `(X, Y, F_X, F_Y)` among `n` custodians,
/// each custodian's salt, and (Earn step 1) the fee line as the launch holds it — the public zero under the launch fee salts
/// of `pair` ([`CustodianState::at_launch`]), so a dealt book's `fee_commits` are `defi_batch::launch_fee_commits(pair, n)`.
/// Every party but the dealer sees one share of each line.
#[must_use]
pub fn deal_pool_on(pair: u8, lines: [u64; ba::POOL_LINES], n: usize, t: usize, key: &[u8; 32]) -> Vec<CustodianState> {
    let mut d = Draw::new(key, b"USDMD-BR15-POOL-DEAL-v2");
    let shares: Vec<Vec<Word>> = lines
        .iter()
        .map(|v| {
            let cs: Vec<Word> = (0..t).map(|_| d.word()).collect();
            eval_shares(&ba::fsmall(*v), &cs, n)
        })
        .collect();
    (0..n).map(|i| CustodianState::at_launch(core::array::from_fn(|l| shares[l][i]), d.salt(), pair, i)).collect()
}

/// [`deal_pool_on`] for pair 0.
#[must_use]
pub fn deal_pool(lines: [u64; ba::POOL_LINES], n: usize, t: usize, key: &[u8; 32]) -> Vec<CustodianState> {
    deal_pool_on(0, lines, n, t, key)
}

/// ⭐ THE BOOKING OVER SHARES at `tick`, on one custodian's engine: `(q_X, q_Y)` with `q_X·n1 − ΔY·d1 ∈ (0, 3·n1)` and
/// `q_Y·d0 − ΔX·n0 ∈ [0, d0)`. q_Y: `d0 = 2^k` — `⌈ΔX·n0 / 2^k⌉`, one exact truncation. q_X: `n1 = m·2^u` — with
/// `R = ⌈2^152/m⌉` and `W = ΔY·d1` split as `h·2^76 + l`, `q0 = ⌊h·R / 2^(76+u)⌋ + ⌊l·R / 2^(152+u)⌋` lies in
/// `(W/n1 − 2, W/n1 + W/2^152)` and `q_X = q0 + 2`. Two truncation sets: `{ΔX·n0, W→h}` then `{h·R, l·R}`.
pub fn book_outflows<C: Comm>(p: &mut Party<C>, dx: F255, dy: F255, tick: i64) -> NetResult<(F255, F255)> {
    let (n0, d0) = dc::tick_ratio(tick);
    let (_, d1) = dc::tick_ratio(tick + 1);
    let (m1, e1) = dc::tick_mantissa(tick + 1);
    let k0 = d0.trailing_zeros();
    let u1 = u32::try_from(e1.max(0)).map_err(|_| "a tick exponent does not fit")?;
    let recip = ceil_pow2_over(RECIP_BITS, m1);
    let wv = dy.mul(F255::from_u128(d1));
    // ⌈v / 2^k⌉ = ⌊(v + 2^k − 1) / 2^k⌋: exact, one truncation (a batch with no sells books 0, never a unit of dust)
    let vy_up = dx.mul(F255::from_u128(n0)).add(F255::pow2(k0).sub(F255::ONE));
    let first = p.trunc_many(&[(vy_up, k0, 154), (wv, SPLIT_BITS, RECIP_BITS)])?;
    let (q_y, h) = (first[0], first[1]);
    let l = wv.sub(h.mul(F255::pow2(SPLIT_BITS)));
    // h, l < 2^76 and R < 2^129 + 1: each product below 2^206
    let bound = (RECIP_BITS - SPLIT_BITS) + (RECIP_BITS - 23) + 1;
    let second = p.trunc_many(&[(h.mul(recip), SPLIT_BITS + u1, bound), (l.mul(recip), RECIP_BITS + u1, bound)])?;
    Ok((second[0].add(second[1]).add(F255::from_u128(2)), q_y))
}

/// What a batch run produced: the settlement, every custodian's next state and the run's measured cost.
pub struct BatchRun {
    pub settle: DefiSettleTx,
    pub next: Vec<CustodianState>,
    /// the network hops the slowest custodian waited on (the run's latency over onion links: hops × one link's latency)
    pub hops: u64,
    pub online_bytes: u64,
}

/// One custodian's result of a batch: its published part, its next state, and what every custodian agreed (the tick, the
/// complaint set).
pub struct PartyOut {
    /// ⭐ §18.14 — whether the batch's sells counted
    pub sells: bool,
    /// ⭐ A-F46 — the batch's lowest filling bucket ([`clear_tick`])
    pub j_min: u64,
    pub part: CustodianPart,
    pub next: CustodianState,
    pub tick: i64,
    pub excluded: Vec<u32>,
    /// every custodian's phase-1 digest (the settlement's transcript), roster order
    pub phase1: Vec<[u64; 4]>,
}

/// ⭐ Earn step 1 — one fee booking's truncation item: `⌊v·f⌋` as `(v·FEE_NUM, FEE_SHIFT, K255)` for `Party::trunc_many` (v
/// below 2^146 — a batch's sums are below 2^80 — so `v·131` stays inside the 154-bit masked width).
fn fee_item(v: F255) -> (F255, u32, u32) {
    (v.mul(F255::from_u128(u128::from(ba::FEE_NUM))), ba::FEE_SHIFT, dc::K255)
}

fn draw_salt<C: Comm>(p: &mut Party<C>) -> [Fa4; 4] {
    core::array::from_fn(|_| Fa4::from_u64(p.draw_u64()))
}

/// ⭐⭐ FINDING A-F46 — THE BATCH'S TICK AND ITS LOWEST FILLING BUCKET, over the pool's X side `sx` (the sells in, their fee
/// out), its Y share `py` and each bucket's demand `by`: the largest tick at which the demand that FILLS there lifts the price
/// to it, so both audited bounds are over the demand that executes (the plain rule, whose invariant `defi_clear`'s pins hold).
/// The fill set steps only at the lowest filling bucket's cap: where that cap is `t + 1`, ONE opened comparison asks whether
/// the bucket's demand lifts the price past `t + 1` — if it does, the bucket can fill at no tick (at `t` it overshoots, above
/// it the price passes its maximum), so it is turned off for the batch and the tick searched once more over the buckets
/// above it, whose caps all lie past `t + 1` (no second step, no second bit). Before this, the search counted the buckets
/// that fill one tick DOWN, and such a bucket set the price at its own cap, did not fill, and the sellers were paid that
/// price from a pool that never got its coin. Returns `(tick, j_min)`.
/// SAFE AT SCALE: one comparison and at most one more search per batch, whatever the orders or the custody set.
/// AI RESISTANT: (a) — the audit's statements 1 and 2 bound the price over exactly the counted buckets, and every node
/// refuses a `j_min` below the tick's own; a custody set that turns a bucket off without cause refunds orders, never pays one.
fn clear_tick<C: Comm>(p: &mut Party<C>, sx: F255, py: F255, by: &[F255; ba::ORDER_BUCKETS], base: i64) -> NetResult<(i64, u64)> {
    let demand = |from: u64, t: i64| -> F255 {
        let sel = dc::fill_select(base, t);
        (0..ba::ORDER_BUCKETS).filter(|j| *j as u64 >= from && sel[*j]).fold(F255::ZERO, |a, j| a.add(by[j]))
    };
    let tick = p.tick_search(sx, &|t| py.add(demand(0, t)), base, SEARCH_WIDTH)?;
    let jm = dc::j_min(base, tick);
    if (jm as usize) < ba::ORDER_BUCKETS && !dc::bucket_fills(base, jm as usize, tick + 1) {
        let (ys, xs) = dc::candidate_scales(tick + 1);
        let ge = p.geq_many(&[(py.add(demand(0, tick)).mul(ys), sx.mul(xs))])?;
        let t = p.t;
        let past = p.open_many(&ge, t)?;
        if past.first() == Some(&F255::ONE) {
            let from = jm + 1;
            let again = p.tick_search(sx, &|t| py.add(demand(from, t)), base, SEARCH_WIDTH)?;
            return Ok((again, from));
        }
    }
    Ok((tick, jm))
}

/// ⭐ ONE AUDIT PER PROCESS (lane af58, 2026-11-15) — the decider's one gate ([`ba::AUDIT_GATE`]), under which every custody
/// run in this process forms and proves its audit ([`run_party`]'s `prove_gate`): a custodian node's lane (`defi_lane`), every
/// in-process run ([`run_batch`]), the settlement verdict's rebuilt circuit and the decider's own tests share it, so one process
/// never holds two audits' circuits at once, whichever path or test thread asks. A run's n parties used to form n at once (a
/// node test binary at 25.5 GB reset this Mac on 2026-11-15); one 2^22-row audit alone peaks at 7,403 MB.
/// SCALE: a machine's audit memory is one audit, constant in the roster size and in the runs it hosts; a custodian on its
/// own machine never waits on it. AI RESISTANT: (b) ordinary code; it decides only WHEN a proof is made, never what is proved.
pub use usdm_decider::br15_audit::AUDIT_GATE;

/// ⭐⭐ ONE CUSTODIAN'S BATCH: its own pool state `me` (its commitment must be the book's), the shares IT captured of the batch's
/// orders (`None` — its sealed share did not open), its engine over its links to the others. Every custodian runs this in
/// lockstep; the complaint set is every order some custodian could not open (each announces its own); the tick search, the
/// booking and the audit's bits run over shares; each custodian builds its OWN audit witness, commits phase 1, and — after the
/// challenges over everyone's phase-1 digest — forms and proves its audit (`prove_gate` serializes both, forming included, for
/// parties sharing one machine, so one machine holds one audit at a time; separate machines need none).
pub fn run_party<C: Comm>(p: &mut Party<C>, book: &DefiBook, me: &CustodianState, mine: &[Option<OrderShare>], prove_gate: &std::sync::Mutex<()>) -> NetResult<PartyOut> {
    let i = p.comm.me();
    let t = p.t;
    if !me.is_the_books(book, i) || book.t as usize != t || mine.len() != book.orders.len() {
        return Err("this custodian's state does not match the book");
    }
    // 1. the complaint round: each custodian announces which orders it holds a share of
    let held: Vec<bool> = mine.iter().zip(&book.orders).map(|(s, o)| s.as_ref().is_some_and(|(l, salt)| db::order_commit(l, salt) == o.share_commits[i])).collect();
    let flags = p.broadcast(held.iter().map(|h| if *h { F255::ONE } else { F255::ZERO }).collect())?;
    let excluded: Vec<u32> = (0..book.orders.len()).filter(|k| flags.iter().any(|f| f[*k] != F255::ONE)).map(|k| k as u32).collect();
    let orders: Vec<OrderShare> = mine.iter().enumerate().filter(|(k, _)| excluded.binary_search(&(*k as u32)).is_err()).filter_map(|(_, s)| *s).collect();
    // ⭐ EARN STEP 2 PIECE 6 — an EARN batch (every `defi_earn::EARN_EVERY`-th, by its public number) clears no trade
    if crate::defi_earn::is_earn_batch(book.batch) {
        return run_earn_party(p, book, me, &orders, excluded, prove_gate);
    }
    // 2. the sums, local: ΔX and each bucket's Y; the tick, with the demand at each candidate the buckets that fill one tick
    //    down (spec §18.10 — a public selection, no comparison per order)
    let dx_all = orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[0])));
    let by: [F255; ba::ORDER_BUCKETS] = core::array::from_fn(|j| orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[1 + j]))));
    let base = book.last_tick;
    let demand = |sel: [bool; ba::ORDER_BUCKETS]| by.iter().zip(sel).fold(F255::ZERO, |a, (v, on)| if on { a.add(*v) } else { a });
    let [px, py, fx, fy] = me.lines.map(|l| f(&l));
    let mut dx = dx_all;
    // ⭐ EARN STEP 1 — the sellers' fee `φ_s = ⌊ΔX·f⌋` (ba::FEE_NUM / 2^FEE_SHIFT), one exact truncation over shares, taken
    // BEFORE the price (the pool's X is `X + ΔX − φ_s`, Uniswap's amountInWithFee); an empty clearing books nothing
    // ⭐ EARN STEP 2 — the deposits' halves (a deposit's sold half is a sell: they count exactly when the sells do), and
    // their own fee `φ_d = ⌊ΣDS·f⌋`, truncated in the same call as φ_s
    // ⭐ EARN STEP 3 — and only in the pair's DEPOSIT batch (the book's opening snapshot): anywhere else every deposit's leaf
    // returns its SAT whole, so its lines are not summed
    let (mut ds, mut dj) = if book.deposits {
        (
            orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[ba::DEPOSIT_SOLD_LINE]))),
            orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[ba::DEPOSIT_JOIN_LINE]))),
        )
    } else {
        (F255::ZERO, F255::ZERO)
    };
    let (mut phis, mut phid) = if orders.is_empty() {
        (F255::ZERO, F255::ZERO)
    } else {
        let both = p.trunc_many(&[fee_item(dx), fee_item(ds)])?;
        (both[0], both[1])
    };
    let deposits_in = ds.sub(phid);
    // ⭐ A-F46 — the tick over the demand that fills there, and the lowest bucket that does ([`clear_tick`]); both audit rows
    // sum exactly those buckets. Earn step 2: the pool's X side carries the deposits' sold halves, less their fee.
    let (mut tick, mut j_min) = clear_tick(p, px.add(dx).sub(phis).add(deposits_in), py, &by, base)?;
    let mut dy2 = demand(db::fills_from(j_min));
    let mut dy1 = dy2;
    // 3. the booking (an empty clearing — a public fact — books nothing); the sellers are booked over what entered the pool
    let (mut qx, mut qy) = if orders.is_empty() { (F255::ZERO, F255::ZERO) } else { book_outflows(p, dx.sub(phis), dy2, tick)? };
    // ⭐ §18.14 — THE ONE BIT THE FLOOR OPENS: do this batch's sells fit above the pool's Y floor? If not, they are off: the tick and the booking are run again over the buyers alone, so
    // a sell past the pool's real coin returns as SAT and stops no buyer. Opening this bit tells only what the price at the floor already shows.
    // ⭐ Earn step 1 — the buyers' fee `φ_b = ⌊q_X·f⌋` rides the floor bit's truncation call (the bit is itself one
    // truncation: `geq_many`'s lifted difference), so a batch with orders runs one call more than before, not two.
    let mut sells = true;
    let mut phib = F255::ZERO;
    if !orders.is_empty() {
        let l = dc::K255 - 1;
        let floor_z = py.add(dy2).sub(qy.add(fy)).add(F255::pow2(l));
        let both = p.trunc_many(&[(floor_z, l, dc::K255), fee_item(qx)])?;
        phib = both[1];
        let bit = p.open_many(&both[..1], t)?;
        if bit.first() != Some(&F255::ONE) {
            sells = false;
            dx = F255::ZERO;
            phis = F255::ZERO;
            // ⭐ Earn step 2 — a deposit's sold half is a sell: with the sells off the deposits are off too (refunded whole)
            (ds, dj, phid) = (F255::ZERO, F255::ZERO, F255::ZERO);
            (tick, j_min) = clear_tick(p, px, py, &by, base)?;
            dy2 = demand(db::fills_from(j_min));
            dy1 = dy2;
            (qx, qy) = book_outflows(p, dx, dy2, tick)?;
            phib = p.trunc_many(&[fee_item(qx)])?[0];
        }
    }
    // ⭐ EARN STEP 3 — the merge's allocation, when this batch opened after a raise
    let alloc = merge_alloc(p, book, me)?;
    // 4. the audit's bits (one masked decomposition at the widest statement's width; a narrower statement keeps its low bits —
    //    an honest z below 2^AUDIT_BITS has zeros above) and masks
    let (forms, select) = db::statements_for(tick, j_min, book.merge_dg.unwrap_or(0));
    // ⭐ Earn steps 2–3: a trading batch pays no withdrawal and no income (ΣWU, ΣWUI, Ψ are 0 here)
    let z = F255::ZERO;
    let fs = fee_vals(me, alloc);
    let vals = [px, py, dx, dy1, dy2, qx, qy, fx, fy, phis, phib, ds, dj, phid, z, z, z, fs[0], fs[1], fs[2], fs[3], fs[4], fs[5]];
    let shared = AuditInputs { forms, select, sells, earn: false, vals, booked: [qx, qy], fees: [phis, phib, phid, z], alloc, tick, j_min };
    audit_and_prove(p, book, me, &orders, shared, excluded, prove_gate)
}

/// ⭐ EARN STEP 3 — the fee state's six audited values over this custodian's shares: the open lines (B, E, A), the closed
/// lines (E_c, A_c), and the merge's allocation.
fn fee_vals(me: &CustodianState, alloc: F255) -> [F255; 6] {
    [f(&me.fee[0]), f(&me.fee[1]), f(&me.fee[2]), f(&me.close[0]), f(&me.close[1]), alloc]
}

/// ⭐⭐ EARN STEP 3 — THE MERGE'S ALLOCATION over shares: in the first batch after a raise (`book.merge_dg`), `⌊dG·2A_c / 2^K⌋`
/// — one exact truncation of a public multiple of this custodian's closed-presence share (the audit's merge rows pin it to the
/// unit); 0 in every other batch, with no round.
/// SAFE AT SCALE: one truncation per raise per pair, whatever the providers. AI RESISTANT: (a) — the merge statements.
fn merge_alloc<C: Comm>(p: &mut Party<C>, book: &DefiBook, me: &CustodianState) -> NetResult<F255> {
    let Some(dg) = book.merge_dg else { return Ok(F255::ZERO) };
    let v = f(&me.close[1]).mul(F255::from_u128(2 * u128::from(dg)));
    Ok(p.trunc_many(&[(v, ba::EARN_RATE_BITS, dc::K255)])?[0])
}

/// ⭐⭐ EARN STEP 2 PIECE 6 — ONE CUSTODIAN'S EARN BATCH. No trade and no deposit counts (each refunds at the Earn leaf); the
/// tick is searched over the pool ALONE, so it brackets the pool's own ratio; the withdrawals' units ΣWU are paid at its two
/// roots — `W_X = ⌈ΣWU·d'/n'⌉` SAT (`defi_batch::earn_rates`) and `W_Y = ⌈ΣWU·n_r/d_r⌉` coin, each over-booked by under 4
/// units — and their income `Ψ = ⌈(I·ΣWU − ΣWUI)/2^INCOME_SHIFT⌉` from the fee line. ONE opened bit, the withdrawals-paid
/// bit: both pool floors and the fee line hold after the payouts (each custodian opens the three comparisons; the chain sees
/// only their AND, as the settlement's `sells`). With it off nothing is paid and every withdrawal's position rolls on.
/// SAFE AT SCALE: one tick search, three bookings, one comparison round per Earn batch, whatever the withdrawals.
/// AI RESISTANT: (a) — the audit's Earn statements pin every booking; the claim relation pays each withdrawal its own units
/// at the leaf's rates; a custody set that turns the bit off without cause rolls positions, never pays one.
fn run_earn_party<C: Comm>(
    p: &mut Party<C>,
    book: &DefiBook,
    me: &CustodianState,
    orders: &[OrderShare],
    excluded: Vec<u32>,
    prove_gate: &std::sync::Mutex<()>,
) -> NetResult<PartyOut> {
    let [px, py, fx, fy] = me.lines.map(|l| f(&l));
    // ⭐ EARN STEP 3 — the merge (if this batch opened after a raise) comes first: the backing the turnstile reads is B + alloc
    let alloc = merge_alloc(p, book, me)?;
    let backing = f(&me.fee[0]).add(alloc);
    let mut wu = orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[ba::WITHDRAW_UNITS_LINE])));
    let mut wui = orders.iter().fold(F255::ZERO, |a, s| a.add(f(&s.0[ba::WITHDRAW_INDEX_LINE])));
    let base = book.last_tick;
    // the pool's own ratio, bracketed: the plain test with no demand at all
    let tick = p.tick_search(px, &|_| py, base, SEARCH_WIDTH)?;
    // the batch's OPENING index: what every withdrawal of it carries as its "now"
    let index = F255::from_u128(u128::from(book.batch_index));
    let (mut wx, mut wy, mut psi) = (F255::ZERO, F255::ZERO, F255::ZERO);
    let mut paid = false;
    if !orders.is_empty() {
        // SAT at 1/r', r' = sqrt_up(tick + 1) = tick k's price: book_outflows' buy side books ⌈v·d_k/n_k⌉ at its `tick + 1`
        let k = -(-(tick + 1)).div_euclid(2) + 1;
        wx = book_outflows(p, F255::ZERO, wu, k - 1)?.0;
        // coin at r = sqrt_down(tick) = tick m's price: its sell side books ⌈v·n_m/d_m⌉
        let m = tick.div_euclid(2) - 1;
        wy = book_outflows(p, wu, F255::ZERO, m)?.1;
        // the income, ⌈(I·ΣWU − ΣWUI)/2^32⌉ (I·ΣWU ≥ ΣWUI: every withdrawal's entry is at most the index now)
        let inc = wu.mul(index).sub(wui).add(F255::pow2(ba::INCOME_SHIFT).sub(F255::ONE));
        psi = p.trunc_many(&[(inc, ba::INCOME_SHIFT, dc::K255)])?[0];
        // the paid bit: X − W_X − F_X ≥ 0, Y − W_Y − F_Y ≥ 0 and B + alloc − Ψ ≥ 0, each a lifted difference's top bit
        let l = dc::K255 - 1;
        let lift = |v: F255| (v.add(F255::pow2(l)), l, dc::K255);
        let bits = p.trunc_many(&[lift(px.sub(wx).sub(fx)), lift(py.sub(wy).sub(fy)), lift(backing.sub(psi))])?;
        let t = p.t;
        let opened = p.open_many(&bits, t)?;
        paid = opened.iter().all(|b| *b == F255::ONE);
        if !paid {
            (wx, wy, psi, wu, wui) = (F255::ZERO, F255::ZERO, F255::ZERO, F255::ZERO, F255::ZERO);
        }
    }
    let forms = db::earn_statements_for(tick, book.batch_index, book.merge_dg.unwrap_or(0));
    let z = F255::ZERO;
    let fs = fee_vals(me, alloc);
    let vals = [px, py, z, z, z, wx, wy, fx, fy, z, z, z, z, z, wu, wui, psi, fs[0], fs[1], fs[2], fs[3], fs[4], fs[5]];
    let shared = AuditInputs {
        forms,
        select: [[false; ba::ORDER_BUCKETS]; 2],
        sells: paid,
        earn: true,
        vals,
        booked: [wx, wy],
        fees: [z, z, z, psi],
        alloc,
        tick,
        j_min: ba::ORDER_BUCKETS as u64,
    };
    audit_and_prove(p, book, me, orders, shared, excluded, prove_gate)
}

/// What a batch's audit is over, a trading batch's or an Earn batch's alike: the statements' public forms, the public
/// selection and bits, the 23 committed values over this custodian's shares, the bookings, fee bookings and the merge's
/// allocation. The fee-state kind is the book's opening snapshot (`DefiBook::fee_kind`).
pub struct AuditInputs {
    pub forms: [([Word; ba::AUDIT_VALUES], Word); ba::AUDIT_STATEMENTS],
    pub select: [[bool; ba::ORDER_BUCKETS]; 2],
    /// a trading batch's floor bit; an Earn batch's withdrawals-paid bit
    pub sells: bool,
    pub earn: bool,
    pub vals: [F255; ba::AUDIT_VALUES],
    pub booked: [F255; 2],
    pub fees: [F255; 4],
    pub alloc: F255,
    pub tick: i64,
    pub j_min: u64,
}

/// ⭐ THE AUDIT TAIL every batch shares: the statements' bits and masks over shares, this custodian's witness, phase 1, the
/// challenges over everyone's phase-1 digest, its audit proof and its next state.
fn audit_and_prove<C: Comm>(
    p: &mut Party<C>,
    book: &DefiBook,
    me: &CustodianState,
    orders: &[OrderShare],
    a: AuditInputs,
    excluded: Vec<u32>,
    prove_gate: &std::sync::Mutex<()>,
) -> NetResult<PartyOut> {
    let t = p.t;
    let AuditInputs { forms, select, sells, earn, vals, booked, fees, alloc, tick, j_min } = a;
    let kind = book.fee_kind();
    let zs: Vec<F255> = forms.iter().map(|(cs, c0)| cs.iter().zip(vals).fold(f(c0), |acc, (c, v)| acc.add(f(c).mul(v)))).collect();
    let bits = p.bits_many(&zs, ba::WIDE_BITS as u32)?;
    let per = 1 + 2 * ba::AUDIT_REPS;
    let mut mask_items = Vec::with_capacity(ba::AUDIT_STATEMENTS * per);
    for _ in 0..ba::AUDIT_STATEMENTS {
        mask_items.push((F255::ZERO, t));
        mask_items.extend((0..ba::AUDIT_REPS).map(|_| (F255::ZERO, 2 * t)));
        for _ in 0..ba::AUDIT_REPS {
            let r = p.draw_field();
            mask_items.push((r, t));
        }
    }
    let masks = p.deal_sum(&mask_items)?;
    // 5. this custodian's witness, phase 1, the challenges, its audit
    let w = ba::AuditWitness {
        pool: me.lines,
        pool_salt: me.salt,
        orders: orders.iter().map(|(l, salt)| (l.to_vec(), *salt)).collect(),
        select,
        sells,
        earn,
        booked: [booked[0].0, booked[1].0],
        fee: me.fee,
        fee_salt: me.fee_salt,
        close: me.close,
        close_salt: me.close_salt,
        fees: [fees[0].0, fees[1].0, fees[2].0, fees[3].0],
        alloc: alloc.0,
        merge: kind.merge,
        close_out: kind.close_out,
        sample: kind.sample,
        deposits: kind.deposits,
        statements: (0..ba::AUDIT_STATEMENTS)
            .map(|si| {
                let m = &masks[si * per..(si + 1) * per];
                ba::AuditStatement {
                    coeffs: forms[si].0,
                    c0: forms[si].1,
                    bits: bits[si].iter().take(ba::statement_bits(si)).map(|b| b.0).collect(),
                    w_mask: m[0].0,
                    s_masks: m[1..=ba::AUDIT_REPS].iter().map(|x| x.0).collect(),
                    u_masks: m[1 + ba::AUDIT_REPS..].iter().map(|x| x.0).collect(),
                }
            })
            .collect(),
        new_pool_salt: draw_salt(p),
        new_fee_salt: draw_salt(p),
        new_close_salt: draw_salt(p),
        phase1_salt: draw_salt(p),
    };
    let my_phase1 = u4(&ba::phase1_digest(&w));
    let all = p.broadcast(my_phase1.iter().map(|v| F255::from_u128(u128::from(*v))).collect())?;
    let phase1: Vec<[u64; 4]> = all.iter().map(|m| core::array::from_fn(|k| m[k].0[0])).collect();
    // CHAIN-OBJECT: the transcript of the settlement this run publishes (its tick, sells bit and j_min ride the DefiSettleTx)
    let ch = ba::AuditChallenges::derive(&db::settle_transcript(book.pair, book.batch, tick, sells, j_min, &excluded, &phase1));
    // ONE AUDIT IN MEMORY PER MACHINE (lane af58, 2026-11-15): the circuit is FORMED inside `prove_gate` too, so parties sharing
    // one machine hold one audit at a time, not n. MEASURED: with the circuit formed outside the gate, every party built its
    // system at once — `br15_a_buyer_measures_the_depth_never_the_position` (n = 4) passed 5.2 GB within 14 s, and a node test
    // binary at 25.5 GB reset this Mac on 2026-11-15. No message is exchanged from here to the end of the run, so holding the
    // gate while forming cannot deadlock the lockstep.
    // ⭐ AND ITS MATRICES ARE NEVER LAID (lane vaults-earn3, finding A-F61): `custodian_audit_prove` streams the circuit (one
    // custody audit is 133 M entries, 3.1 GB laid — MEASURED 2026-11-15; streamed, the prove's whole-process peak is 793 MB).
    // SCALE: one machine's peak is one streamed audit, a constant in the roster size n.
    let audit = {
        let _one = prove_gate.lock().unwrap_or_else(|e| e.into_inner());
        ba::custodian_audit_prove(&w, &ch).ok_or("this custodian's audit does not prove")?.1
    };
    let next = CustodianState {
        lines: ba::new_pool_shares(&w),
        salt: w.new_pool_salt,
        fee: ba::new_fee_shares(&w),
        fee_salt: w.new_fee_salt,
        close: ba::new_close_shares(&w),
        close_salt: w.new_close_salt,
    };
    let part = CustodianPart {
        published: ba::audit_published(&w, &ch).into_iter().map(|pb| (pb.w, pb.s, pb.u)).collect(),
        new_pool: next.commit(),
        new_fee: next.fee_commit(),
        new_close: next.close_commit(),
        audit,
    };
    Ok(PartyOut { sells, j_min, part, next, tick, excluded, phase1 })
}

/// ⭐⭐ THE CUSTODY SET SETTLES ITS OPEN BATCH — the in-process run of the custodians' protocol: each custodian on ITS OWN thread
/// with its own engine, its own entropy (derived per custodian from `key`) and only its own column of shares, linked by
/// channels ([`MemComm`]). `custodians[i]` is custodian i's state, `orders[o][i]` the share custodian i captured of the
/// book's order `o` (`None`: its sealed share did not open — the order joins the complaint set and refunds). Returns the
/// settlement every node's `DefiSettleTx::verdict` decides, or why the set cannot settle (the batch then expires and every
/// order refunds — a failed run never moves value).
pub fn run_batch(book: &DefiBook, custodians: &[CustodianState], orders: &[Vec<Option<OrderShare>>], key: &[u8; 32]) -> Result<BatchRun, &'static str> {
    let n = book.roster.len();
    if !book.is_open() || custodians.len() != n || n == 0 || n > db::MAX_ROSTER {
        return Err("the custody set does not match the book's roster");
    }
    if orders.len() != book.orders.len() || orders.iter().any(|o| o.len() != n) {
        return Err("the order shares do not match the book's open batch");
    }
    let gate = &AUDIT_GATE;
    let outs: Vec<NetResult<(PartyOut, u64, u64)>> = std::thread::scope(|scope| {
        let handles: Vec<_> = MemComm::mesh(n)
            .into_iter()
            .enumerate()
            .map(|(i, comm)| {
                let me = &custodians[i];
                let mine: Vec<Option<OrderShare>> = orders.iter().map(|o| o[i]).collect();
                let own_key = *blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-CUSTODIAN-ENTROPY-v1").update(&(i as u64).to_le_bytes()).finalize().as_bytes();
                scope.spawn(move || {
                    let mut p = Party::new(comm, &own_key);
                    run_party(&mut p, book, me, &mine, gate).map(|o| (o, p.hops, p.sent_elements))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or(Err("a custodian's run panicked"))).collect()
    });
    let outs: Vec<(PartyOut, u64, u64)> = outs.into_iter().collect::<NetResult<_>>()?;
    let (tick, sells, j_min, excluded, phase1) = (outs[0].0.tick, outs[0].0.sells, outs[0].0.j_min, outs[0].0.excluded.clone(), outs[0].0.phase1.clone());
    if outs.iter().any(|(o, _, _)| o.tick != tick || o.sells != sells || o.j_min != j_min || o.excluded != excluded || o.phase1 != phase1) {
        return Err("the custodians did not agree on the tick, the fill set, the complaint set or the transcript");
    }
    // CHAIN-OBJECT: the leaves of the DefiSettleTx built below (its own tick, j_min, sells, complaint set)
    let leaves = db::settle_leaves(book, tick, j_min, sells, &excluded);
    let hops = outs.iter().map(|o| o.1).max().unwrap_or(0);
    let online_bytes = outs.iter().map(|o| o.2).sum::<u64>() * 32;
    let (parts, next): (Vec<CustodianPart>, Vec<CustodianState>) = outs.into_iter().map(|(o, _, _)| (o.part, o.next)).unzip();
    let settle = DefiSettleTx { pair: book.pair, batch: book.batch, tick, sells, j_min, excluded, phase1, first: 0, parts, leaves };
    // the custody set checks its own settlement as every node will before it publishes it: a batch whose buys would take the
    // pool below a floor (spec §18.10: the launch position's real SAT is spent) has no audit that verifies — it is not
    // published, and the batch expires and refunds
    settle.verdict(book)?;
    Ok(BatchRun { settle, next, hops, online_bytes })
}

// ───────────────────────────── the EarnEpoch's run (Earn step 3) ─────────────────────────────

/// One custodian's result of an EarnEpoch: the rate every custodian found, its published part, the run's transcript.
pub struct EpochOut {
    pub dg: u64,
    pub part: db::EpochPart,
    pub phase1: Vec<[u64; 4]>,
}

/// ⭐⭐ EARN STEP 3 — ONE CUSTODIAN'S EARNEPOCH over every pair's CLOSED window (`books[p]` and `closed[p]` its own shares of
/// pair p's (E_c, A_c), each opening that book's close commitment for this custodian). The protocol-wide rate `dG = ⌊2^K·F /
/// (2V)⌋` (F = ΣE_c, V = ΣA_c, linear over the shares) is found BIT BY BIT, highest first: each step one comparison
/// `2^K·F ≥ cand·2V`, opened — the chain learns the rate and nothing else (not F, not V, not any pair's part). Then the two
/// statements' bits and masks, phase 1, the challenges over every custodian's digest, its audit
/// (`br15_audit::epoch_audit_circuit`). The closed lines move nothing here: each pair's next batch merges them.
/// SAFE AT SCALE: `EARN_RATE_BITS + 8` comparisons and one audit per window, whatever the users, positions or orders.
/// AI RESISTANT: (a) — every node checks the statements; a custodian that steers the search fails its sharing check.
pub fn run_epoch_party<C: Comm>(
    p: &mut Party<C>,
    books: &[DefiBook],
    closed: &[([Word; ba::CLOSE_LINES], [Fa4; 4])],
    raise: u64,
    prove_gate: &std::sync::Mutex<()>,
) -> NetResult<EpochOut> {
    let i = p.comm.me();
    let t = p.t;
    if books.is_empty() || books.len() != closed.len() || books.len() > ba::EPOCH_PAIRS_MAX {
        return Err("an EarnEpoch spans every pair's closed window");
    }
    for (b, (lines, salt)) in books.iter().zip(closed) {
        if b.close_commits.get(i) != Some(&db::close_commit(lines, salt)) || b.raised != raise || b.closed != raise.saturating_add(1) {
            return Err("this custodian's closed lines are not the book's window awaiting its raise");
        }
    }
    let fees = closed.iter().fold(F255::ZERO, |a, (l, _)| a.add(f(&l[0])));
    let presence = closed.iter().fold(F255::ZERO, |a, (l, _)| a.add(f(&l[1])));
    let lhs = fees.mul(F255::pow2(ba::EARN_RATE_BITS));
    let mut dg = 0u64;
    for bit in (0..ba::EARN_RATE_BITS + 8).rev() {
        let cand = dg | (1u64 << bit);
        if cand > ba::EARN_DG_MAX {
            continue;
        }
        let ge = p.geq_many(&[(lhs, presence.mul(F255::from_u128(2 * u128::from(cand))))])?;
        if p.open_many(&ge, t)?.first() == Some(&F255::ONE) {
            dg = cand;
        }
    }
    let forms = ba::epoch_statements(books.len(), dg).ok_or("the EarnEpoch's statements cannot form")?;
    let mut vals = [F255::ZERO; ba::AUDIT_VALUES];
    for (k, (lines, _)) in closed.iter().enumerate() {
        vals[2 * k] = f(&lines[0]);
        vals[2 * k + 1] = f(&lines[1]);
    }
    let zs: Vec<F255> = forms.iter().map(|(cs, c0)| cs.iter().zip(vals).fold(f(c0), |acc, (c, v)| acc.add(f(c).mul(v)))).collect();
    let bits = p.bits_many(&zs, ba::WIDE_BITS as u32)?;
    let per = 1 + 2 * ba::AUDIT_REPS;
    let mut mask_items = Vec::with_capacity(ba::EPOCH_STATEMENTS * per);
    for _ in 0..ba::EPOCH_STATEMENTS {
        mask_items.push((F255::ZERO, t));
        mask_items.extend((0..ba::AUDIT_REPS).map(|_| (F255::ZERO, 2 * t)));
        for _ in 0..ba::AUDIT_REPS {
            let r = p.draw_field();
            mask_items.push((r, t));
        }
    }
    let masks = p.deal_sum(&mask_items)?;
    let w = ba::EpochWitness {
        close: closed.to_vec(),
        statements: (0..ba::EPOCH_STATEMENTS)
            .map(|si| {
                let m = &masks[si * per..(si + 1) * per];
                ba::AuditStatement {
                    coeffs: forms[si].0,
                    c0: forms[si].1,
                    bits: bits[si].iter().take(ba::statement_bits(si)).map(|b| b.0).collect(),
                    w_mask: m[0].0,
                    s_masks: m[1..=ba::AUDIT_REPS].iter().map(|x| x.0).collect(),
                    u_masks: m[1 + ba::AUDIT_REPS..].iter().map(|x| x.0).collect(),
                }
            })
            .collect(),
        phase1_salt: draw_salt(p),
    };
    let my_phase1 = u4(&ba::epoch_phase1_digest(&w));
    let all = p.broadcast(my_phase1.iter().map(|v| F255::from_u128(u128::from(*v))).collect())?;
    let phase1: Vec<[u64; 4]> = all.iter().map(|m| core::array::from_fn(|k| m[k].0[0])).collect();
    // CHAIN-OBJECT: the transcript of the EarnEpoch this run publishes (its raise and rate ride the DefiEarnEpochTx)
    let ch = ba::AuditChallenges::derive_n(&db::epoch_transcript(raise, dg, &phase1), ba::EPOCH_STATEMENTS);
    let (r1cs, io, wit) = ba::epoch_audit_circuit(&w, &ch).ok_or("this custodian's EarnEpoch audit circuit does not form")?;
    let audit = {
        let _one = prove_gate.lock().unwrap_or_else(|e| e.into_inner());
        usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &wit).ok_or("this custodian's EarnEpoch audit does not prove")?
    };
    let part = db::EpochPart { published: ba::epoch_published(&w, &ch).into_iter().map(|pb| (pb.w, pb.s, pb.u)).collect(), audit };
    Ok(EpochOut { dg, part, phase1 })
}

/// ⭐ THE CUSTODY SET RAISES A WINDOW — the in-process run of [`run_epoch_party`] (each custodian on its own thread, its own
/// engine and entropy, only its own closed-line shares: `closed[i][p]` custodian i's of pair p). Returns the EarnEpoch every
/// node's `DefiEarnEpochTx::verdict` decides, after checking it as every node will.
pub fn run_epoch(books: &[DefiBook], closed: &[Vec<([Word; ba::CLOSE_LINES], [Fa4; 4])>], key: &[u8; 32]) -> Result<db::DefiEarnEpochTx, &'static str> {
    let n = books.first().map_or(0, |b| b.roster.len());
    if n == 0 || closed.len() != n || closed.iter().any(|c| c.len() != books.len()) {
        return Err("the custody set does not match the books' roster");
    }
    let raise = books[0].raised;
    // one audit per process, as every custody run (`AUDIT_GATE`)
    let gate = &AUDIT_GATE;
    let outs: Vec<NetResult<EpochOut>> = std::thread::scope(|scope| {
        let handles: Vec<_> = MemComm::mesh(n)
            .into_iter()
            .enumerate()
            .map(|(i, comm)| {
                let mine = &closed[i];
                let own_key = *blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-EPOCH-ENTROPY-v1").update(&(i as u64).to_le_bytes()).finalize().as_bytes();
                scope.spawn(move || {
                    let mut p = Party::new(comm, &own_key);
                    run_epoch_party(&mut p, books, mine, raise, gate)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or(Err("a custodian's EarnEpoch run panicked"))).collect()
    });
    let outs: Vec<EpochOut> = outs.into_iter().collect::<NetResult<_>>()?;
    let (dg, phase1) = (outs[0].dg, outs[0].phase1.clone());
    if outs.iter().any(|o| o.dg != dg || o.phase1 != phase1) {
        return Err("the custodians did not agree on the rate or the transcript");
    }
    let parts = outs.into_iter().map(|o| o.part).collect();
    let tx = db::DefiEarnEpochTx { raise, dg, phase1, first: 0, parts };
    if !tx.verdict(books)? {
        return Err("an EarnEpoch of every part did not close");
    }
    Ok(tx)
}

/// A member leg for any leaf this node holds, bound to `binder` and `blind`: `(the leaf, carrier, tuple bytes, cross-bind)`.
pub type CoverLeg = ([u64; 8], Vec<u8>, Vec<u8>, [u64; 8]);

/// ⭐ A COVER ORDER (spec §18.12): amount 0 in a random bucket, dealt and sealed to the roster under the epoch key exactly as
/// a buyer's order, its proof the cover branch of the one order relation (any held leaf, the nullifier in the cover domain),
/// its member leg real. Byte- and proof-shape-identical to a buyer's slot. `None` when no leg can be built yet.
pub fn cover_order(
    book: &DefiBook,
    epoch: u64,
    epoch_pk: &crate::epoch_key::EpochPublicKey,
    leg: &dyn Fn([u64; 8], [u64; 8]) -> Option<CoverLeg>,
    key: &[u8; 32],
) -> Option<DefiOrderTx> {
    let mut draw = Draw::new(key, b"USDMD-BR15-COVER-ORDER-v1");
    let secret: [u64; 8] = core::array::from_fn(|_| draw.u64() & 0x3FFF_FFFF);
    let lc_blind: [u64; 8] = core::array::from_fn(|_| draw.u64() & 0x3FFF_FFFF);
    let a_blind: [u64; 8] = core::array::from_fn(|_| draw.u64() & 0x3FFF_FFFF);
    let nf = usdm_decider::whir_rec_block::poseidon_pair(secret, ba::ORDER_COVER_DOMAIN);
    let (leaf, carrier, tuple, lc) = leg(nf, lc_blind)?;
    let bucket = (draw.u64() % ba::ORDER_BUCKETS as u64) as usize;
    let mut d = deal_order_on(book.pair, false, 0, bucket, a_blind, book.eks.len(), book.t as usize, key);
    d.cover = Some((leaf, secret));
    d.lc_blind = lc_blind;
    // ⭐ Earn step 3 — a cover carries its batch's opening index, as every order does (a cover is a buy of 0: its lanes are 0)
    d.index = book.batch_index;
    if d.spend_publics().2 != lc {
        return None;
    }
    let mut m = [0u8; 32];
    draw.0.fill(&mut m);
    let (k, epoch_ct) = crate::epoch_key::encapsulate(epoch_pk, &m);
    let sealed = seal_dealing(&d, &book.eks, &k)?;
    d.binding = db::sealed_binding(epoch, &epoch_ct, &sealed);
    let (r1cs, io, w) = ba::order_share_circuit(&d)?;
    let share_proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w)?;
    Some(DefiOrderTx {
        pair: book.pair,
        amount_commit: d.amount_commit(),
        limit_commit: d.limit_commit(),
        share_commits: d.share_commits().iter().map(u4).collect(),
        epoch,
        epoch_ct,
        sealed,
        share_proof,
        nullifier: nf,
        leaf_commit: lc,
        member_carrier: carrier,
        member_tuple: tuple,
        index: book.batch_index,
    })
}

/// ⭐ A COVER CLAIM (spec §18.12): mints 0 (SAT or USDm at random) to an unspendable note, its proof the cover branch of the
/// one claim relation, its member leg real over any held leaf. Shape-identical to an owner's claim.
pub fn cover_claim(pair: u8, leg: &dyn Fn([u64; 8], [u64; 8]) -> Option<CoverLeg>, key: &[u8; 32]) -> Option<db::DefiClaimTx> {
    let mut draw = Draw::new(key, b"USDMD-BR15-COVER-CLAIM-v1");
    let lane = |d: &mut Draw| -> [u64; 8] { core::array::from_fn(|_| d.u64() & 0x3FFF_FFFF) };
    let (secret, lc_blind, out_blind, a_blind) = (lane(&mut draw), lane(&mut draw), lane(&mut draw), lane(&mut draw));
    let nf = usdm_decider::whir_rec_block::poseidon_pair(secret, ba::CLAIM_COVER_DOMAIN);
    let (leaf, carrier, tuple, lc) = leg(nf, lc_blind)?;
    let refund = draw.u64() & 1 == 1;
    let cw = ba::ClaimWitness {
        amount: 0,
        amount_blind: a_blind,
        bucket: 0,
        sell: false, deposit: false, withdraw: false, leg: 0, extra: ba::LeafExtra::default(), entry: 0, now: 0,
        p_num: 1,
        p_den: 1,
        j_min: u64::from(refund),
        s_num: 0,
        s_den: 1,
        out: 0,
        out_blind,
        lc_blind,
        cover: Some((leaf, secret)),
    };
    let (pnf, plc, oc, prefund) = cw.publics();
    if pnf != nf || plc != lc || prefund != refund {
        return None;
    }
    let claim_proof = claim_proof(&cw)?;
    let asset = if refund { db::pair_y_tag(pair) } else { crate::satoshi::asset_tag() };
    let owner = lane(&mut draw);
    let (mint, cm, dc) = usdm_decider::whir_rec_block::prove_asset_mint_validity_committed_bytes(0, asset, &owner, &out_blind)?;
    if dc != oc {
        return None;
    }
    let mut note = crate::cover::cover_note()?.to_vec();
    note[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cm));
    // a real claim's clue is this wide (`oli::tag_clue_bytes_v2`) and uniform, so a cover's must be: MEASURED 2026-11-04, a 256-byte bound here refused every real claim on real nodes, and
    // a 48-byte cover beside a real clue would have shown which slot was real
    let mut owner_clue = vec![0u8; crate::peg_in_tx::OWNER_CLUE_MAX];
    draw.0.fill(&mut owner_clue);
    Some(db::DefiClaimTx { pair, nullifier: nf, leaf_commit: lc, out_commit: oc, pays_y: refund, claim_proof, member_carrier: carrier, member_tuple: tuple, mint_carrier: mint, note, owner_clue })
}

fn u4(v: &[Fa4; 4]) -> [u64; 4] {
    use p3_field::PrimeField64;
    core::array::from_fn(|i| v[i].as_canonical_u64())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open(shares: &[Word], t: usize) -> Word {
        // Lagrange at 0 over the first t + 1 points
        let k = t + 1;
        (0..k).fold([0; 4], |acc, i| {
            let xi = (i + 1) as u64;
            let wgt = (0..k).filter(|j| *j != i).fold(ba::fsmall(1), |a, j| {
                let xj = (j + 1) as u64;
                ba::fmul(&ba::fmul(&a, &ba::fsmall(xj)), &ba::finv(&ba::fsub(&ba::fsmall(xj), &ba::fsmall(xi))))
            });
            ba::fadd(&acc, &ba::fmul(&wgt, &shares[i]))
        })
    }
    fn small(v: &Word) -> u128 {
        assert!(v[2] == 0 && v[3] == 0, "an opened value is small");
        u128::from(v[0]) | (u128::from(v[1]) << 64)
    }

    /// Run `f` on every custodian of an `n`-party mesh, each on its own thread with its own engine; their results in order.
    fn on_mesh<T: Send>(n: usize, f: impl Fn(&mut Party<MemComm>) -> T + Sync) -> Vec<T> {
        std::thread::scope(|s| {
            let hs: Vec<_> = MemComm::mesh(n)
                .into_iter()
                .enumerate()
                .map(|(i, c)| {
                    let f = &f;
                    s.spawn(move || f(&mut Party::new(c, &[i as u8 + 1; 32])))
                })
                .collect();
            hs.into_iter().map(|h| h.join().expect("a party's thread")).collect()
        })
    }
    /// This party's share of `v`, dealt by party 0.
    fn shared(p: &mut Party<MemComm>, v: u128) -> F255 {
        let mine = if p.comm.me() == 0 { F255::from_u128(v) } else { F255::ZERO };
        let t = p.t;
        p.deal_sum(&[(mine, t)]).expect("deals")[0]
    }

    /// ⭐ THE BOOKING OVER SHARES IS INSIDE THE AUDITED BAND at every tick shape, on 7 custodians each holding only its share:
    /// for sums across the whole tick range (both mantissa shapes, `u > 0` and `d > 2^23`), the opened `q_X` satisfies
    /// `q_X·n1 − ΔY·d1 ∈ (0, 3·n1)` and `q_Y` is the exact ceiling, `q_Y·d0 − ΔX·n0 ∈ [0, d0)` — inside the statements'
    /// [0, 4n); with no sells `q_Y` is exactly 0. Every custodian opens the same values.
    /// CALIBRATION: `q_X − 3` falls below the band (the band rejects an under-booking).
    #[test]
    fn br15_the_booking_over_shares_lands_inside_the_audited_band() {
        let ticks = [-44_000i64, -20_000, -700, -1, 0, 1, 693, 20_000, 44_000];
        let sums = |k: usize| (1_000_003u64 * (k as u64 + 1), (u64::MAX >> 2) / (k as u64 + 2));
        let runs = on_mesh(7, |p| {
            let mut out = Vec::new();
            for (k, tick) in ticks.iter().enumerate() {
                let (dxv, dyv) = sums(k);
                let (dx, dy) = (shared(p, u128::from(dxv)), shared(p, u128::from(dyv)));
                let (qx, qy) = book_outflows(p, dx, dy, *tick).expect("books");
                let t = p.t;
                out.push(p.open_many(&[qx, qy], t).expect("opens"));
            }
            let (z, dy) = (shared(p, 0), shared(p, 5_000));
            let (_, qy) = book_outflows(p, z, dy, 693).expect("books");
            let t = p.t;
            out.push(p.open_many(&[qy], t).expect("opens"));
            out
        });
        assert!(runs.iter().all(|r| *r == runs[0]), "⛔ the custodians opened different values");
        let big = |a: u128, b: u128| F255::from_u128(a).mul(F255::from_u128(b));
        let sub_small = |a: F255, b: F255| -> Option<u128> {
            let dlt = a.sub(b);
            (dlt.0[2] == 0 && dlt.0[3] == 0 && (dlt.0[1] >> 63) == 0).then(|| dlt.low_u128())
        };
        for (k, tick) in ticks.iter().enumerate() {
            let (dxv, dyv) = sums(k);
            let (qx, qy) = (runs[0][k][0], runs[0][k][1]);
            let (n0, d0) = dc::tick_ratio(*tick);
            let (n1, d1) = dc::tick_ratio(tick + 1);
            let gx = sub_small(big(qx.low_u128(), n1), big(u128::from(dyv), d1)).expect("q_X·n1 ≥ ΔY·d1");
            assert!(gx > 0 && gx < 3 * n1, "⛔ tick {tick}: q_X over-books by {gx} (n1 = {n1})");
            let gy = sub_small(big(qy.low_u128(), d0), big(u128::from(dxv), n0)).expect("q_Y·d0 ≥ ΔX·n0");
            assert!(gy < d0, "⛔ tick {tick}: q_Y over-books by {gy} (d0 = {d0}) — not the exact ceiling");
            assert!(sub_small(big(qx.low_u128() - 3, n1), big(u128::from(dyv), d1)).is_none(), "CALIBRATION: q_X − 3 under-books at tick {tick}");
        }
        assert_eq!(runs[0][ticks.len()][0], F255::ZERO, "⛔ a batch with no sells booked USDm out of the pool");
    }

    /// ⭐ THE CUSTODIAN ENGINE'S BITS AND TRUNCATION over shares agree with the integers, on 4 custodians each holding only its
    /// share (calibration of the two primitives the audit and the booking stand on).
    #[test]
    fn br15_bits_and_truncation_over_shares_are_exact() {
        let vals = [0u128, 1, 2, (1 << 91) + 12_345, (1 << 92) - 1, 0xDEAD_BEEF_F00D];
        let runs = on_mesh(4, |p| {
            let sh: Vec<F255> = vals.iter().map(|v| shared(p, *v)).collect();
            let t = p.t;
            let bits = p.bits_many(&sh, 92).expect("bits");
            let opened_bits: Vec<Vec<F255>> = bits.iter().map(|b| p.open_many(b, t).expect("opens")).collect();
            let tr = p.trunc_many(&sh.iter().map(|s| (*s, 17u32, 92u32)).collect::<Vec<_>>()).expect("truncates");
            let opened_tr = p.open_many(&tr, t).expect("opens");
            let past = p.trunc_many(&[(sh[3], 100, 92)]).expect("truncates");
            let opened_past = p.open_many(&past, t).expect("opens");
            (opened_bits, opened_tr, opened_past)
        });
        let (bits, tr, past) = &runs[0];
        for (v, bs) in vals.iter().zip(bits) {
            for (k, b) in bs.iter().enumerate() {
                assert_eq!(*b, F255::from_u128((v >> k) & 1), "⛔ bit {k} of {v}");
            }
        }
        for (v, o) in vals.iter().zip(tr) {
            assert_eq!(*o, F255::from_u128(v >> 17), "⛔ ⌊{v} / 2^17⌋");
        }
        assert_eq!(past[0], F255::ZERO, "a truncation past the bound is 0");
    }

    /// The plain rule's tick with maximum-price buckets (spec §18.10), in integers: the largest `t` at which the pool's Y plus
    /// the buckets that fill one tick down reaches `p_t`.
    fn rule_tick_buckets(x: u128, y: u128, orders: &[(usize, u64)], base: i64) -> i64 {
        let d = |t: i64| -> u128 { orders.iter().filter(|(j, _)| dc::bucket_fills(base, *j, t)).map(|(_, a)| u128::from(*a)).sum() };
        let (mut lo, mut hi) = (-dc::TICK_RANGE, dc::TICK_RANGE);
        while hi - lo > 1 {
            let mid = lo + (hi - lo) / 2;
            if dc::candidate_holds(x, y + d(mid - 1), mid) {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        lo
    }

    fn book_of(custodians: &[CustodianState], t: usize, last_tick: i64) -> DefiBook {
        let n = custodians.len();
        DefiBook {
            pair: 0,
            roster: (0..n).map(|i| [i as u8 + 1; 32]).collect(),
            eks: vec![vec![0; 1_184]; n],
            t: t as u32,
            pool_commits: custodians.iter().map(CustodianState::commit).collect(),
            fee_commits: custodians.iter().map(CustodianState::fee_commit).collect(),
            batch: 0,
            opened_at: 0,
            opened_ms: 0,
            orders: Vec::new(),
            last_tick,
            last_expired: false,
            last_sells: false,
            prices: Default::default(),
            income_index: 0,
            pending: Vec::new(),
            slotted: false,
            slot_parts: 0,
            handover: None,
            close_commits: custodians.iter().map(CustodianState::close_commit).collect(),
            sampling: true,
            ..DefiBook::default()
        }
    }

    fn shares_of(dealings: &[ba::OrderDealing], n: usize) -> Vec<Vec<Option<OrderShare>>> {
        dealings.iter().map(|dl| (0..n).map(|i| Some((dealing_lines(dl, i), dl.salts[i]))).collect()).collect()
    }

    /// ⭐⭐ THE CUSTODY RUNTIME SETTLES A BATCH OVER SHARES AND EVERY NODE ACCEPTS IT: a pool dealt among n = 4 custodians,
    /// three sealed buys dealt by their owners — one with NO maximum, one at +10 %, one at +2 % — one `run_batch`; no party
    /// ever holds a sum, an order, a pool side or a bucket. The batch moves the price ≈ 7 %: the +2 % order does not fill (it
    /// refunds through the same leaf), the others do. The settlement passes `DefiSettleTx::verdict` (every audit verified
    /// against the circuit the node forms), its tick is the bucket rule's, the new pool opens to `(X − q_X, Y + ΔY₂)` with
    /// the invariant kept, and the next batch's run starts from the custodians' new states.
    /// TAMPER: a custodian whose state does not open its commitment and a settlement whose tick is moved (every audit then
    /// fails) are refused; orders whose shares do not open are the COMPLAINT set — they refund while the batch settles, and a
    /// complaint set altered after the audits is refused.
    #[test]
    fn br15_the_custody_runtime_settles_a_batch_over_shares_and_every_node_accepts_it() {
        let (n, t) = (4usize, 1usize);
        let (pool_x, pool_y) = (2_000_000u64, 1_000_000u64);
        let key = |k: u8| [k; 32];
        let custodians = deal_pool([pool_x, pool_y, 0, 0], n, t, &key(1));
        let base = dc::rule_tick(u128::from(pool_x), u128::from(pool_y));
        let mut book = book_of(&custodians, t, base);
        let orders: [(usize, u64); 3] = [(3, 50_000), (1, 12_345), (0, 7_000)];
        let dealings: Vec<ba::OrderDealing> = orders
            .iter()
            .enumerate()
            .map(|(k, (j, a))| deal_order(*a, *j, [0x0D, k as u64, 1, 2, 3, 4, 5, 6], n, t, &key(10 + k as u8)))
            .collect();
        for dl in &dealings {
            book.orders.push(db::BookOrder { amount_commit: dl.amount_commit(), limit_commit: dl.limit_commit(), share_commits: dl.share_commits().iter().map(u4).collect() });
        }
        let shares = shares_of(&dealings, n);

        let t0 = std::time::Instant::now();
        let out = run_batch(&book, &custodians, &shares, &key(2)).expect("the custody set settles its batch");
        let cpu = t0.elapsed();
        let want = rule_tick_buckets(u128::from(pool_x), u128::from(pool_y), &orders, base);
        assert_eq!(out.settle.tick, want, "⛔ the runtime's tick is not the bucket rule's");
        assert!(!dc::bucket_fills(base, 0, want) && dc::bucket_fills(base, 1, want), "PRECONDITION: the +2 % order is above its maximum, the +10 % one fills");
        assert_eq!(out.settle.verdict(&book), Ok(out.settle.leaves.clone()), "⛔ a node refuses the runtime's settlement");
        let line = |l: usize| small(&open(&out.next.iter().map(|c| c.lines[l]).collect::<Vec<_>>(), t));
        let (nx, ny) = (line(0), line(1));
        let filled: u64 = orders.iter().filter(|(j, _)| dc::bucket_fills(base, *j, want)).map(|(_, a)| *a).sum();
        assert_eq!(ny, u128::from(pool_y + filled), "the pool's Y gained exactly the FILLED buys (the +2 % order's USDm is not the pool's)");
        assert!(nx * ny >= u128::from(pool_x) * u128::from(pool_y), "⛔ the pool's invariant fell");
        let paid: u128 = orders.iter().filter(|(j, _)| dc::bucket_fills(base, *j, want)).map(|(_, a)| dc::buyer_claim(u128::from(*a), want).expect("fits")).sum();
        let q_x = u128::from(pool_x) - nx;
        assert!(q_x >= paid, "⛔ the pool booked less X than its buyers' fills");
        // ⭐ EARN STEP 1 — the fee line took exactly ⌊q_X·f⌋ out of the q_X the pool paid, and the buyers' claims (each its fill
        // less ⌈g·f⌉) plus the fee line never take more than q_X
        // (the fee state's fresh line E: a trading batch's fees land there)
        let fee = small(&open(&out.next.iter().map(|c| c.fee[1]).collect::<Vec<_>>(), t));
        assert_eq!(fee, ba::batch_fee(q_x), "⛔ the fee line is not ⌊q_X·f⌋");
        assert!(fee > 0, "CALIBRATION: this batch's buys pay a fee");
        let claims: u128 = orders
            .iter()
            .filter(|(j, _)| dc::bucket_fills(base, *j, want))
            .map(|(_, a)| u128::from(ba::buy_paid(*a, dc::tick_ratio(want + 1).1, dc::tick_ratio(want + 1).0).expect("fits")))
            .sum();
        assert!(claims + fee <= q_x, "⛔ the buyers' claims and the fee line took more than the pool paid");
        // each order's claim from the ONE leaf: the filled ones the SAT less the fee, the +2 % one its USDm back
        for (dl, (j, a)) in dealings.iter().zip(&orders) {
            let (_, _, jm, out_v) = fill_of(*a, *j, Some((want, dc::j_min(base, want)))).expect("fits");
            if dc::bucket_fills(base, *j, want) {
                let g = u64::try_from(dc::buyer_claim(u128::from(*a), want).expect("fits")).expect("fits");
                assert_eq!(out_v, g - ba::claim_fee(g), "a filled order's claim is its fill less its fee");
            } else {
                assert_eq!(out_v, *a, "an order above its maximum is refunded in full");
            }
            assert_eq!(jm, dc::j_min(base, want));
            let leaf = db::claim_leaf_at(&dl.amount_commit(), &dl.limit_commit(), want, dc::j_min(base, want), true);
            assert!(out.settle.leaves.contains(&leaf), "every order's leaf is the batch's one shape");
        }
        eprintln!(
            "[br15-custody] n={n} t={t} orders={} tick={} (base {base}) · {} network hops (each a send to every custodian and a receive from each) · {:.2} MB sent by all custodians · {:.1} s wall (each custodian on its own thread; MPC + {n} audits)",
            orders.len(),
            out.settle.tick,
            out.hops,
            out.online_bytes as f64 / 1e6,
            cpu.as_secs_f64()
        );

        // TAMPER: a custodian state that is not the chain's, an order share that does not open, a moved tick
        let mut bad = custodians.clone();
        bad[2].lines[0] = ba::fadd(&bad[2].lines[0], &ba::fsmall(1));
        assert!(run_batch(&book, &bad, &shares, &key(3)).is_err(), "⛔ a custodian off its commitment ran a batch");
        // a share off its commitment (a malformed sealed share) is a COMPLAINT: that order refunds, the batch still settles
        let mut bad_shares = shares.clone();
        if let Some(s) = bad_shares[1][0].as_mut() {
            s.0[2] = ba::fadd(&s.0[2], &ba::fsmall(1));
        }
        bad_shares[2][3] = None;
        let partial = run_batch(&book, &custodians, &bad_shares, &key(3)).expect("a batch with complaints still settles");
        assert_eq!(partial.settle.excluded, vec![1, 2], "the unopenable orders are the complaint set");
        assert_eq!(partial.settle.verdict(&book), Ok(partial.settle.leaves.clone()), "⛔ a node refused a settlement with complaints");
        assert_eq!(partial.settle.leaves[1], db::refund_leaf(&book.orders[1].amount_commit, &book.orders[1].limit_commit), "a complained order refunds");
        assert_eq!(
            partial.settle.leaves[0],
            db::claim_leaf_at(&book.orders[0].amount_commit, &book.orders[0].limit_commit, partial.settle.tick, partial.settle.j_min, true),
            "the others fill"
        );
        let mut hidden = partial.settle.clone();
        hidden.excluded = vec![1];
        hidden.leaves = db::settle_leaves(&book, hidden.tick, hidden.j_min, true, &hidden.excluded);
        assert!(hidden.verdict(&book).is_err(), "⛔ a complaint set altered after the audits passed");
        let mut moved = out.settle.clone();
        moved.tick += 1;
        moved.leaves = db::settle_leaves(&book, moved.tick, moved.j_min, true, &[]);
        assert!(moved.verdict(&book).is_err(), "⛔ a settlement at a moved tick passed");

        // the next batch starts from the custodians' new states
        let mut book2 = book.clone();
        book2.pool_commits = out.next.iter().map(CustodianState::commit).collect();
        book2.fee_commits = out.next.iter().map(CustodianState::fee_commit).collect();
        book2.close_commits = out.next.iter().map(CustodianState::close_commit).collect();
        book2.batch = 1;
        book2.orders.clear();
        book2.last_tick = out.settle.tick;
        let out2 = run_batch(&book2, &out.next, &[], &key(4)).expect("an empty batch settles");
        assert_eq!(out2.settle.verdict(&book2), Ok(Vec::new()), "the next batch settles from the new states");
        assert_eq!(out2.settle.tick, dc::rule_tick(nx, ny), "the next tick is the new pool's price");
    }

    /// ⭐⭐ §18.10 — THE POOL NEVER SELLS PAST ITS FLOOR: a launch-shaped pool (depth 1,000,000 X of which only 10,000 are real:
    /// F_X = 990,000) facing a buy that would take 20,000 X has no settlement the custody set can publish (its X-floor statement
    /// has no bits — the run refuses its own settlement, the batch expires and refunds); a buy inside the real SAT settles and
    /// the floor rides along unchanged.
    /// CALIBRATION: the same buys against a pool with no floor settle (the refusal is the floor's).
    #[test]
    fn br15_the_pool_never_sells_past_its_floor() {
        let (n, t) = (4usize, 1usize);
        let key = |k: u8| [k; 32];
        let (depth, real) = (1_000_000u64, 10_000u64);
        let floored = deal_pool([depth, depth, depth - real, depth], n, t, &key(1));
        let open_pool = deal_pool([depth, depth, 0, 0], n, t, &key(1));
        let base = dc::rule_tick(u128::from(depth), u128::from(depth));
        let run = |custodians: &[CustodianState], amount: u64| {
            let mut book = book_of(custodians, t, base);
            let dl = deal_order(amount, 3, [0x0E; 8], n, t, &key(9));
            book.orders.push(db::BookOrder { amount_commit: dl.amount_commit(), limit_commit: dl.limit_commit(), share_commits: dl.share_commits().iter().map(u4).collect() });
            run_batch(&book, custodians, &shares_of(&[dl], n), &key(2))
        };
        // ≈ 20,400 X out of a depth of 1,000,000 at price 1: more than the 10,000 real
        assert!(run(&open_pool, 20_833).is_ok(), "CALIBRATION: with no floor the buy settles");
        assert!(run(&floored, 20_833).is_err(), "⛔ the pool sold past its X floor");
        let inside = run(&floored, 5_000).expect("a buy inside the real SAT settles");
        let fx = small(&open(&inside.next.iter().map(|c| c.lines[2]).collect::<Vec<_>>(), t));
        assert_eq!(fx, u128::from(depth - real), "the floor rides along unchanged");
    }

    /// ⭐⭐ EARN STEP 2 — A DEPOSIT JOINS THE POOL, ITS SOLD HALF'S FEE GOES TO THE FEE LINE, AND NO COIN LEAVES: a batch holding
    /// only a SAT deposit of 100,000 settles; the pool's X grows by both halves less `φ_d = ⌊50,000·131/2^16⌋ = 99` (and at
    /// most the booking's 4 units of dust), its coin does not move, and the fee line holds exactly φ_d. Opened from every
    /// custodian's next shares. CALIBRATION: the same batch with the deposit as a plain sell pays coin out of the pool.
    /// TWO-PARTY-REVIEWED: four custodian parties each run their own `run_party` over their own links (`run_batch`).
    #[test]
    fn earn_a_deposit_joins_the_pool_and_its_fee_reaches_the_fee_line() {
        let (n, t) = (4usize, 1usize);
        let key = |k: u8| [k; 32];
        let depth = 1_000_000u64;
        let pool = deal_pool([depth, depth, 0, 0], n, t, &key(1));
        let base = dc::rule_tick(u128::from(depth), u128::from(depth));
        let run = |dl: ba::OrderDealing| {
            let mut book = book_of(&pool, t, base);
            // ⭐ Earn step 3 — the hour's DEPOSIT batch (the first trading batch after a raise): the only one whose deposits count
            book.raised = 1;
            book.deposits = true;
            book.orders.push(db::BookOrder { amount_commit: dl.amount_commit(), limit_commit: dl.limit_commit(), share_commits: dl.share_commits().iter().map(u4).collect() });
            let out = run_batch(&book, &pool, &shares_of(&[dl], n), &key(2)).expect("the batch settles");
            let line = |k: usize| small(&open(&out.next.iter().map(|c| c.lines[k]).collect::<Vec<_>>(), t));
            // the fee state (B, E, A): a trading batch's fees land on the open window's fresh line E
            let fee = small(&open(&out.next.iter().map(|c| c.fee[1]).collect::<Vec<_>>(), t));
            (line(0), line(1), fee)
        };
        let (x, y, fee) = run(deal_deposit_on(0, 100_000, [0x61; 8], n, t, &key(7)));
        let phi_d = u128::from(ba::batch_fee(50_000) as u64);
        assert_eq!(phi_d, 99);
        let joined = u128::from(depth) + 100_000 - phi_d;
        assert!(x <= joined && x + 4 >= joined, "⛔ the deposit's SAT did not join the pool: X = {x}, want {joined} less at most 4");
        assert_eq!(y, u128::from(depth), "⛔ coin left the pool for a deposit");
        assert_eq!(fee, phi_d, "⛔ the deposit's sold half's fee is not on the fee line");
        let (_, y_sell, _) = run(deal_order_on(0, true, 100_000, 0, [0x62; 8], n, t, &key(8)));
        assert!(y_sell < u128::from(depth), "CALIBRATION: a plain sell pays coin out of the pool");
    }

    /// ⭐⭐ FINDING A-F46 — A CAPPED BUY THAT DOES NOT FILL NEVER SETS THE SELLERS' PRICE. A pool at price 1 (depth 1,000,000 on
    /// each side, no floors); one batch carries a SELL of 100,000 SAT and a BUY of 700,000 coin in bucket 2 (+50 %, cap tick
    /// 406). The buy's demand would lift the price past its own cap, so it cannot fill; the batch must not pay the seller a
    /// price only that refunded demand supported. Measured by the pool's own invariant, opened from the custodians' next
    /// shares: `X''·Y'' ≥ X·Y` (the plain rule's soundness, `defi_clear::br15_settling_each_side_at_its_tick_edge_keeps_the_invariant`).
    /// CALIBRATION: the same sell with the buy in the no-maximum bucket (it fills) keeps the invariant.
    /// TWO-PARTY-REVIEWED: four custodian parties each run their own `run_party` over their own links (`run_batch`); the
    /// assertion opens the pool from EVERY custodian's next share — what the set jointly holds — never from one party's view.
    #[test]
    fn a_capped_buy_that_does_not_fill_never_sets_the_sellers_price() {
        let (n, t) = (4usize, 1usize);
        let key = |k: u8| [k; 32];
        let depth = 1_000_000u64;
        let pool = deal_pool([depth, depth, 0, 0], n, t, &key(1));
        let base = dc::rule_tick(u128::from(depth), u128::from(depth));
        let run = |bucket: usize| {
            let mut book = book_of(&pool, t, base);
            let sell = deal_order_on(0, true, 100_000, 0, [0x51; 8], n, t, &key(7));
            let buy = deal_order_on(0, false, 700_000, bucket, [0x52; 8], n, t, &key(8));
            for dl in [&sell, &buy] {
                book.orders.push(db::BookOrder { amount_commit: dl.amount_commit(), limit_commit: dl.limit_commit(), share_commits: dl.share_commits().iter().map(u4).collect() });
            }
            let out = run_batch(&book, &pool, &shares_of(&[sell, buy], n), &key(2)).expect("the batch settles");
            let line = |k: usize| small(&open(&out.next.iter().map(|c| c.lines[k]).collect::<Vec<_>>(), t));
            (out.settle.tick, line(0), line(1))
        };
        let k = u128::from(depth) * u128::from(depth);
        let (_, x, y) = run(3);
        assert!(x * y >= k, "CALIBRATION: a filled buy and a sell keep the invariant ({x}·{y})");
        let (tick, x, y) = run(2);
        assert!(x * y >= k, "⛔ A-F46: the batch settled at tick {tick} (base {base}) on a buy that did not fill and paid its seller from a pool left at {x}·{y} < {k}");
    }

    /// ⭐⭐⭐ EARN, THE WHOLE HOUR ON THE CUSTODY RUNTIME: a SAT deposit and a buy settle in the pair's DEPOSIT batch (the deposit's
    /// leaf is its POSITION: the leaf the settlement inserted carries the deposit lane), the pair's next EARN batch samples the
    /// pool's presence, the first batch past the hour CLOSES the window, ONE EarnEpoch run by the four custodians over BOTH
    /// pairs' closed windows opens the window's one rate and raises the pair's index, the pair's next batch MERGES the window's
    /// allocation into the backing, and at the next Earn batch the position's WITHDRAWAL settles: its SAT claim pays its share at
    /// the Earn rate PLUS its income `⌊u·(I_now − I_entry) / 2^32⌋ > 0`, and its coin claim pays its coin share. Every settlement
    /// and the EarnEpoch pass every node's verdict (each audit verified against the circuit a node forms); the empty batches
    /// between pass by the chain's own expiry door (no settlement reached them). The window's fees are what the income is paid
    /// from: the backing after the merge covers every withdrawal of the window (the turnstile row), and the income paid is at
    /// most the fees the window took.
    /// LYING CLAIM: the withdrawal's SAT claim one unit above its SAT and income has no witness.
    /// TWO-PARTY-REVIEWED: four custodian parties each run their own `run_party` / `run_epoch_party` over their own links; every
    /// verdict is the one a node runs over the public objects.
    #[test]
    fn earn_the_whole_hour_deposit_sample_close_raise_merge_and_a_withdrawal_paid_its_income() {
        let (n, t) = (4usize, 1usize);
        let key = |k: u8| [k; 32];
        let depth = 1_000_000u64;
        let w0 = 1_000u64;
        let at = |window: u64, k: u64| window * crate::defi_earn::EARN_WINDOW_MS + 1_000 * k;
        let pool = deal_pool([depth, depth, 0, 0], n, t, &key(1));
        let base = dc::rule_tick(u128::from(depth), u128::from(depth));
        // pair 0, at the first raise's deposit batch (the launch hour's window closed with nothing in it and was raised: every
        // fee and closed line is the launch's public zero)
        let mut book = book_of(&pool, t, base);
        book.raised = 1;
        book.closed = 1;
        book.close_window = w0;
        book.batch = 1;
        book.open_snapshot(at(w0, 1));
        assert!(book.deposits && !book.sample && !book.close_out && book.merge_dg.is_none(), "PRECONDITION: batch 1 is the hour's deposit batch");
        let mut states = pool.clone();
        // the deposit batch: a 100,000 SAT deposit and a buy, both carrying the batch's opening index
        let blind_d = [0x71; 8];
        let mut dep = deal_deposit_on(0, 100_000, blind_d, n, t, &key(7));
        dep.index = book.batch_index;
        let mut buy = deal_order_on(0, false, 40_000, 3, [0x72; 8], n, t, &key(8));
        buy.index = book.batch_index;
        let settle_on = |book: &mut DefiBook, states: &mut Vec<CustodianState>, dls: &[ba::OrderDealing], seed: u8, ts: u64| -> (DefiSettleTx, Vec<[u64; 8]>) {
            for dl in dls {
                book.orders.push(db::BookOrder { amount_commit: dl.amount_commit(), limit_commit: dl.limit_commit(), share_commits: dl.share_commits().iter().map(u4).collect() });
            }
            let run = run_batch(book, states, &shares_of(dls, n), &key(seed)).expect("the batch settles");
            let leaves = run.settle.verdict(book).expect("⛔ a node refused the settlement");
            db::apply_settlement(book, &run.settle, u64::from(seed), ts);
            *states = run.next;
            (run.settle, leaves)
        };
        let (s1, leaves1) = settle_on(&mut book, &mut states, &[dep.clone(), buy], 2, at(w0, 2));
        assert!(s1.sells, "PRECONDITION: the deposit batch's sells counted");
        // the leaf's buy price is `(d_{t+1}, n_{t+1})` (`claim_leaf_at_x`'s spelling)
        let (n1, d1) = dc::tick_ratio(s1.tick + 1);
        let (sn, sd) = db::sell_price(s1.tick, s1.sells);
        let pos = ba::PositionWitness {
            x: 100_000,
            x_blind: blind_d,
            bucket: 0,
            from_withdrawal: false,
            entry: dep.index,
            now: 0,
            p_num: d1,
            p_den: n1,
            j_min: s1.j_min,
            s_num: sn,
            s_den: sd,
            extra: ba::LeafExtra { earn: false, dep: true },
        };
        assert_eq!(leaves1[0], pos.leaf(), "⛔ the deposit's leaf is not its position (the deposit lane did not ride its leaf)");
        let units = pos.units_max().expect("a counted deposit is a position");
        assert!(units > 0, "the position holds units");
        let fees_window = small(&open(&states.iter().map(|c| c.fee[1]).collect::<Vec<_>>(), t));
        assert!(fees_window > 0, "CALIBRATION: the deposit batch took fees for the window");
        assert!(book.sampling && book.deposited == book.raised, "the deposit batch starts the window's sampling");
        // batches 2..=6 pass by the expiry door (none reached a settlement); batch 7 is the pair's Earn batch: it samples
        for b in 2..=6u64 {
            assert_eq!(book.batch, b);
            db::apply_expiry(&mut book, 10 + b, at(w0, 10 + b));
        }
        assert!(book.sample, "PRECONDITION: batch 7, an Earn batch of a sampling window, samples the pool's presence");
        let (s7, _) = settle_on(&mut book, &mut states, &[], 17, at(w0 + 1, 1));
        let presence = small(&open(&states.iter().map(|c| c.fee[2]).collect::<Vec<_>>(), t));
        assert!(presence > 0, "⛔ the Earn batch's sample did not add the pool's presence");
        assert_eq!(book.w_open, db::sample_weight(s7.tick), "the window's public weight is the Earn tick's");
        // batch 8 opened past the hour: it CLOSES the window (its fees and presence move to the closed lines)
        assert!(book.close_out, "PRECONDITION: the first batch past the hour closes the window");
        settle_on(&mut book, &mut states, &[], 18, at(w0 + 1, 2));
        assert_eq!((book.closed, book.raised), (2, 1), "one window closed past the last raise");
        let closed0: Vec<([Word; ba::CLOSE_LINES], [Fa4; 4])> = states.iter().map(|c| (c.close, c.close_salt)).collect();
        assert_eq!(small(&open(&closed0.iter().map(|c| c.0[0]).collect::<Vec<_>>(), t)), fees_window, "the closed window holds the hour's fees");
        // pair 1 idle all hour: its window closed with its launch zeros
        let mut idle = book_of(&pool, t, base);
        idle.pair = 1;
        idle.close_commits = db::launch_close_commits(1, n);
        idle.raised = 1;
        idle.closed = 2;
        let closed1: Vec<([Word; ba::CLOSE_LINES], [Fa4; 4])> = (0..n).map(|i| ([[0; 4]; ba::CLOSE_LINES], ba::launch_close_salt(1, i))).collect();
        let mut books = vec![book.clone(), idle];
        assert_eq!(db::epoch_due(&books), Some(1), "PRECONDITION: every pair closed the window past raise 1");
        // ⭐ THE EARNEPOCH: four custodians, both pairs' closed windows, one rate
        let closed: Vec<Vec<([Word; ba::CLOSE_LINES], [Fa4; 4])>> = (0..n).map(|i| vec![closed0[i], closed1[i]]).collect();
        let epoch = run_epoch(&books, &closed, &key(30)).expect("the EarnEpoch runs");
        assert_eq!(epoch.verdict(&books), Ok(true), "⛔ a node refused the EarnEpoch");
        let want_dg = (u128::from(fees_window) << ba::EARN_RATE_BITS) / (2 * presence);
        assert_eq!(u128::from(epoch.dg), want_dg.min(u128::from(ba::EARN_DG_MAX)), "⛔ the EarnEpoch's rate is not ⌊2^K·ΣE_c / (2·ΣA_c)⌋");
        let w_closed = book.w_closed;
        db::apply_earn_epoch(&mut books, &epoch, true);
        book = books[0].clone();
        let raise = db::index_raise(epoch.dg, w_closed);
        assert!(raise > 0 && book.income_index == raise, "⛔ the pair's index did not rise by the window's rate times its weight");
        // batch 9 opened before the raise (no merge): it passes by the expiry door; batch 10 MERGES the window's allocation
        db::apply_expiry(&mut book, 19, at(w0 + 1, 3));
        assert_eq!(book.merge_dg, Some(epoch.dg), "PRECONDITION: the batch after the raise merges its rate");
        let backing_before = small(&open(&states.iter().map(|c| c.fee[0]).collect::<Vec<_>>(), t));
        settle_on(&mut book, &mut states, &[], 20, at(w0 + 1, 4));
        let backing = small(&open(&states.iter().map(|c| c.fee[0]).collect::<Vec<_>>(), t));
        let alloc = (u128::from(epoch.dg) * 2 * presence) >> ba::EARN_RATE_BITS;
        assert_eq!(backing, backing_before + alloc, "⛔ the merge did not move the window's allocation into the backing");
        assert!(alloc <= fees_window, "⛔ the window allocated more than its fees");
        // batches 11..=14 pass by; batch 15 is the Earn batch where the position withdraws
        for b in 11..=14u64 {
            assert_eq!(book.batch, b);
            db::apply_expiry(&mut book, 20 + b, at(w0 + 1, 10 + b));
        }
        assert!(crate::defi_earn::is_earn_batch(book.batch) && book.batch_index == raise, "PRECONDITION: an Earn batch opened at the raised index");
        let blind_w = [0x73; 8];
        let mut wd = deal_order_on(0, false, units, 0, blind_w, n, t, &key(9));
        wd.withdraw = Some(pos.clone());
        wd.index = book.batch_index;
        let (s15, leaves15) = settle_on(&mut book, &mut states, &[wd.clone()], 35, at(w0 + 1, 40));
        assert!(s15.sells, "⛔ the Earn batch did not pay its withdrawals");
        let ((pn, pd), (cn, cd)) = db::earn_rates(s15.tick);
        let claim = |leg: u8| ba::ClaimWitness {
            amount: units,
            amount_blind: blind_w,
            bucket: 0,
            sell: false,
            deposit: false,
            withdraw: true,
            leg,
            extra: ba::LeafExtra { earn: true, dep: false },
            entry: pos.entry,
            now: wd.index,
            p_num: pn,
            p_den: pd,
            j_min: ba::ORDER_BUCKETS as u64,
            s_num: cn,
            s_den: cd,
            out: 0,
            out_blind: [0x0B; 8],
            lc_blind: [0x1C; 8],
            cover: None,
        };
        let mut sat = claim(0);
        assert_eq!(sat.leaf(), leaves15[0], "⛔ the withdrawal's claim does not open the leaf the Earn batch inserted");
        let income = sat.income().expect("the index rose");
        assert!(income > 0, "⛔ the withdrawal earned no income over the hour");
        assert_eq!(u128::from(income), (u128::from(units) * u128::from(raise)) >> ba::INCOME_SHIFT, "the income is ⌊u·ΔI / 2^32⌋");
        assert!(u128::from(income) <= fees_window, "⛔ the income paid exceeds the window's fees");
        sat.out = sat.paid().expect("fits");
        let (r1cs, io, w) = ba::claim_circuit(&sat).expect("the SAT claim builds");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).expect("lays")), "⛔ the withdrawal's SAT and income claim has no witness");
        let lie = ba::ClaimWitness { out: sat.out + 1, ..sat.clone() };
        let (r1cs, io, w) = ba::claim_circuit(&lie).expect("builds");
        assert!(!r1cs.is_satisfied(&r1cs.lay_z(&io, &w).expect("lays")), "⛔ LYING CLAIM: one unit above the SAT and income has a witness");
        let mut coin = claim(1);
        coin.out = coin.paid().expect("fits");
        let (r1cs, io, w) = ba::claim_circuit(&coin).expect("the coin claim builds");
        assert!(r1cs.is_satisfied(&r1cs.lay_z(&io, &w).expect("lays")), "⛔ the withdrawal's coin claim has no witness");
        assert!(coin.out > 0, "the coin claim pays the position's coin share");
    }
}
