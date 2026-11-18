// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐ §BR-15 (spec §18.11) — THE CUSTODY HANDOVER: the DeFi pool moves from the custody roster that holds it to the bonded
//! custody set the chain names now, as Shamir shares the whole way — no custodian, old or new, ever holds a pool line.
//!
//! **The shape (Herzberg–Jarecki–Krawczyk–Yung 1995 proactive resharing / Desmedt–Jajodia 1997 redistribution, borrowed).**
//! 1. [`DefiHandoverTx::Open`] — anyone, when the bonded custody set (`ValidatorSet::bonded_custodian_eks`, at most
//!    `MAX_ROSTER`, id order) differs from the book's roster: the book records the new roster; at the next batch boundary the
//!    pool FREEZES (no order, no settlement) so every dealing is over one pool.
//! 2. [`DefiHandoverTx::Deal`] — each OLD custodian re-shares its four pool-line shares to the new roster on degree-t'
//!    polynomials, publishes one sub-share commitment per new custodian, seals each sub-share to that custodian's ML-KEM key,
//!    and proves (`br15_audit::handover_deal_circuit`) the constants are exactly what its own pool commitment holds.
//! 3. [`DefiHandoverTx::Accept`] — each NEW custodian, once every old custodian has dealt, combines its sub-shares at the old
//!    roster's Lagrange coefficients and proves (`handover_accept_circuit`) its new pool commitment opens that combination.
//! 4. The last acceptance switches the book: roster, keys, threshold, pool commitments; the batch reopens for orders.
//! A handover that does not complete is dropped by the paused batch's expiry (the old roster keeps the pool).
//!
//! §9.6, every body: (1) PoW — the carrying block; (2) Open: the node's own canonical bonded set; Deal/Accept: their proofs
//! against circuits this node forms from (n, n', t'); (3) value: the new shares are a degree-t' sharing of the SAME pool (the
//! acceptance relation) — nothing is minted, nothing paid; (4) replay: one deal per old slot, one acceptance per new slot,
//! one handover at a time; (5) bounded: n' commitments and sealed shares per deal, n openings per acceptance (both ≤
//! `MAX_ROSTER`); (6) parity with the settlement: every custodian's part is required, a stall expires (refunds nothing —
//! no order is admitted while frozen).
//!
//! cons, quantified: the pool is frozen from the batch boundary until the last acceptance folds — one dealing and one
//! acceptance proof per custodian (each well under 2 s, MEASURED in `br15_the_custody_handover_moves_the_same_pool_to_a_new_roster`)
//! plus a few blocks; only when the bonded set changes. An order placed in that window is refused unspent (the wallet says why).
//!
//! ROOT-LAYER: the objects' own rules — where the chain decides a handover; the custody lane produces them.
//! MEASURED: the decider pin above and `br15_the_custody_hands_the_pool_to_a_new_roster_and_the_new_roster_settles`.
//! MUST-STAY-GREEN: every `br15_*` pin.

use crate::defi_batch::{self as db, DefiBook, Word};
use crate::defi_custody::{self as dcu, CustodianState};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use usdm_decider::br15_audit as ba;
use usdm_decider::hiding_decider::Fa4;

/// An open handover: the new roster's keys and threshold, each old custodian's sub-share commitments (once dealt), each new
/// custodian's new pool commitment (once accepted), and whether the pool is frozen for it yet.
/// O1-FOOTPRINT-REVIEWED: at most `MAX_ROSTER` × `MAX_ROSTER` commitments, cleared when the handover completes or is dropped.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Handover {
    pub new_eks: Vec<Vec<u8>>,
    pub new_t: u32,
    pub subs: Vec<Option<Vec<[u64; 4]>>>,
    /// each new custodian's (new pool, new fee, new close commitment) once accepted (Earn steps 1 + 3: the fee state and the
    /// closed window move with the pool)
    pub accepts: Vec<Option<([u64; 4], [u64; 4], [u64; 4])>>,
    pub frozen: bool,
}

impl Handover {
    /// Every old custodian has dealt.
    #[must_use]
    pub fn dealt(&self) -> bool {
        self.subs.iter().all(Option::is_some)
    }
}

/// ⭐ ONE HANDOVER OBJECT.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DefiHandoverTx {
    /// the new roster (the bonded custody set's keys, in its canonical order)
    Open { pair: u8, batch: u64, new_eks: Vec<Vec<u8>> },
    /// old custodian `from`'s dealing: one sub-share commitment and one sealed sub-share per new custodian, and its proof
    Deal { pair: u8, batch: u64, from: u32, subs: Vec<[u64; 4]>, sealed: Vec<Vec<u8>>, proof: Vec<u8> },
    /// new custodian `to`'s acceptance: its new pool, fee and close commitments (Earn steps 1 + 3) and its proof
    Accept { pair: u8, batch: u64, to: u32, new_pool: [u64; 4], new_fee: [u64; 4], new_close: [u64; 4], proof: Vec<u8> },
}

fn f4(v: &[u64; 4]) -> [Fa4; 4] {
    core::array::from_fn(|i| Fa4::from_u64(v[i]))
}
fn u4(v: &[Fa4; 4]) -> [u64; 4] {
    core::array::from_fn(|i| v[i].as_canonical_u64())
}

/// The bytes a dealing's proof is bound to: its batch, its dealer and every sealed sub-share.
#[must_use]
pub fn deal_binding(batch: u64, from: u32, sealed: &[Vec<u8>]) -> [u64; 8] {
    let mut h = blake3::Hasher::new_derive_key("USDMD-BR15-HANDOVER-DEAL-BIND-v1");
    h.update(&batch.to_le_bytes());
    h.update(&from.to_le_bytes());
    for s in sealed {
        h.update(blake3::hash(s).as_bytes());
    }
    let b = h.finalize();
    core::array::from_fn(|i| u64::from(u32::from_le_bytes(b.as_bytes()[4 * i..4 * i + 4].try_into().unwrap_or([0; 4]))) & ((1 << 30) - 1))
}

/// The canonical new roster from the bonded custody set (id order), at most `MAX_ROSTER` keys.
#[must_use]
pub fn canonical_roster(bonded: &[([u8; 32], Vec<u8>)]) -> Vec<Vec<u8>> {
    bonded.iter().take(db::MAX_ROSTER).map(|(_, ek)| ek.clone()).collect()
}

impl DefiHandoverTx {
    /// The canonical encoding; `None` only if serialization itself fails.
    #[must_use]
    pub fn encode(&self) -> Option<Vec<u8>> {
        postcard::to_allocvec(self).ok()
    }
    /// One canonical, bounded encoding.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let t: Self = crate::chain_object::decode_exact(bytes)?;
        let ok = match &t {
            Self::Open { new_eks, .. } => !new_eks.is_empty() && new_eks.len() <= db::MAX_ROSTER && new_eks.iter().all(|k| k.len() == crate::defi_launch::EK_BYTES),
            Self::Deal { subs, sealed, proof, .. } => {
                !subs.is_empty() && subs.len() <= db::MAX_ROSTER && sealed.len() == subs.len() && sealed.iter().all(|s| s.len() == db::SEALED_BYTES) && proof.len() <= db::MAX_PROOF_BYTES
            }
            Self::Accept { proof, .. } => proof.len() <= db::MAX_PROOF_BYTES,
        };
        ok.then_some(t)
    }
    #[must_use]
    pub fn wire(&self) -> Option<Vec<u8>> {
        self.encode().map(|p| crate::chain_object::frame(crate::chain_object::Class::DefiHandover, &p))
    }
    /// ⭐ §18.14 — the pair whose pool this hands over.
    #[must_use]
    pub fn pair(&self) -> u8 {
        match self {
            Self::Open { pair, .. } | Self::Deal { pair, .. } | Self::Accept { pair, .. } => *pair,
        }
    }
    fn batch(&self) -> u64 {
        match self {
            Self::Open { batch, .. } | Self::Deal { batch, .. } | Self::Accept { batch, .. } => *batch,
        }
    }

    /// ⭐ THE VERDICT against `book` (the node's own) and the node's canonical new roster (for an Open). Pure.
    pub fn verdict(&self, book: &DefiBook, canonical: &[Vec<u8>]) -> Result<(), &'static str> {
        if !book.is_open() {
            return Err("the book holds no pool");
        }
        if self.batch() != book.batch || self.pair() != book.pair {
            return Err("the handover object is not for the open batch");
        }
        match self {
            Self::Open { new_eks, .. } => {
                if book.handover.is_some() {
                    return Err("a handover is already open");
                }
                if new_eks.as_slice() != canonical {
                    return Err("the new roster is not the chain's bonded custody set");
                }
                if *new_eks == book.eks {
                    return Err("the roster is already the bonded custody set");
                }
                Ok(())
            }
            Self::Deal { from, subs, sealed, proof, batch, .. } => {
                let h = book.handover.as_ref().filter(|h| h.frozen).ok_or("no frozen handover is open")?;
                let i = *from as usize;
                if h.subs.get(i).is_none_or(Option::is_some) {
                    return Err("this old custodian has already dealt (or is not on the roster)");
                }
                if subs.len() != h.new_eks.len() {
                    return Err("the dealing names a sub-share per new custodian");
                }
                let shape = ba::handover_deal_r1cs(h.new_eks.len(), h.new_t as usize).ok_or("the dealing circuit cannot form")?;
                let io = ba::handover_deal_io(
                    &f4(&book.pool_commits[i]),
                    &f4(&book.fee_commits[i]),
                    &f4(&book.close_commits[i]),
                    &subs.iter().map(f4).collect::<Vec<_>>(),
                    &deal_binding(*batch, *from, sealed),
                );
                if !usdm_decider::spartan_ccs::verify_committed(&shape, &io, proof) {
                    return Err("the dealing does not hand over the shares its pool, fee and close commitments hold");
                }
                Ok(())
            }
            Self::Accept { to, new_pool, new_fee, new_close, proof, .. } => {
                let h = book.handover.as_ref().filter(|h| h.frozen).ok_or("no frozen handover is open")?;
                if !h.dealt() {
                    return Err("an acceptance before every old custodian has dealt");
                }
                let j = *to as usize;
                if h.accepts.get(j).is_none_or(Option::is_some) {
                    return Err("this new custodian has already accepted (or is not on the new roster)");
                }
                let subs: Vec<[Fa4; 4]> = h.subs.iter().map(|s| s.as_ref().and_then(|v| v.get(j)).map_or([Fa4::ZERO; 4], f4)).collect();
                let shape = ba::handover_accept_r1cs(book.roster.len()).ok_or("the acceptance circuit cannot form")?;
                if !usdm_decider::spartan_ccs::verify_committed(&shape, &ba::handover_accept_io(&subs, &f4(new_pool), &f4(new_fee), &f4(new_close)), proof) {
                    return Err("the acceptance's new pool, fee state or closed window is not the combination of its sub-shares");
                }
                Ok(())
            }
        }
    }
}

/// ⭐ The book after a verified handover object: an Open records the new roster (frozen from the next batch boundary — at once
/// if the open batch holds no order); a Deal fills its slot; the last Accept switches the book to the new roster and reopens
/// the batch at `ordinal`.
pub fn apply_handover(book: &mut DefiBook, t: &DefiHandoverTx, ordinal: u64) {
    match t {
        DefiHandoverTx::Open { new_eks, .. } => {
            let n2 = new_eks.len();
            book.handover = Some(Handover {
                new_eks: new_eks.clone(),
                new_t: u32::try_from((n2 - 1) / 3).unwrap_or(0),
                subs: vec![None; book.roster.len()],
                accepts: vec![None; n2],
                frozen: book.orders.is_empty() && book.pending.is_empty(),
            });
        }
        DefiHandoverTx::Deal { from, subs, .. } => {
            if let Some(slot) = book.handover.as_mut().and_then(|h| h.subs.get_mut(*from as usize)) {
                *slot = Some(subs.clone());
            }
        }
        DefiHandoverTx::Accept { to, new_pool, new_fee, new_close, .. } => {
            let Some(h) = book.handover.as_mut() else { return };
            if let Some(slot) = h.accepts.get_mut(*to as usize) {
                *slot = Some((*new_pool, *new_fee, *new_close));
            }
            if h.accepts.iter().all(Option::is_some) {
                let h = book.handover.take().unwrap_or_else(|| unreachable_handover());
                book.roster = h.new_eks.iter().map(|k| crate::defi_launch::custody_id(k)).collect();
                book.eks = h.new_eks;
                book.t = h.new_t;
                let accepted: Vec<([u64; 4], [u64; 4], [u64; 4])> = h.accepts.into_iter().flatten().collect();
                book.pool_commits = accepted.iter().map(|a| a.0).collect();
                book.fee_commits = accepted.iter().map(|a| a.1).collect();
                book.close_commits = accepted.iter().map(|a| a.2).collect();
                // ⭐ Earn step 3 — an EarnEpoch's parts held under the old roster can never close under the new one
                book.epoch_pending.clear();
                book.opened_at = ordinal;
            }
        }
    }
}

#[cold]
fn unreachable_handover() -> Handover {
    Handover { new_eks: Vec::new(), new_t: 0, subs: Vec::new(), accepts: Vec::new(), frozen: false }
}

// ───────────────────────────── the custodians' halves ─────────────────────────────

/// ⭐ AN OLD CUSTODIAN'S DEALING of its pool state `me` (custodian `from` of the book) to the handover's new roster: the
/// sub-shares, their commitments, each sealed to its new custodian's key, the proof. `None` if the state is not the book's.
#[must_use]
pub fn deal(book: &DefiBook, me: &CustodianState, from: u32, key: &[u8; 32]) -> Option<DefiHandoverTx> {
    let h = book.handover.as_ref()?;
    if !me.is_the_books(book, from as usize) {
        return None;
    }
    let mut draw = blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-HANDOVER-DEAL-v1").finalize_xof();
    let mut word = || -> Word {
        let mut b = [0u8; 32];
        draw.fill(&mut b);
        let l: Word = core::array::from_fn(|k| u64::from_le_bytes(b[8 * k..8 * k + 8].try_into().unwrap_or([0; 8])));
        ba::fadd(&[l[0], l[1], l[2], l[3] >> 2], &[0; 4])
    };
    let n2 = h.new_eks.len();
    let coeffs: Vec<Vec<Word>> = (0..ba::STATE_LINES).map(|_| (0..h.new_t as usize).map(|_| word()).collect()).collect();
    let salts: Vec<[Fa4; 4]> = (0..n2).map(|_| core::array::from_fn(|_| Fa4::from_u64(word()[0] & 0x3FFF_FFFF))).collect();
    let mut d = ba::HandoverDealing { lines: me.state_lines(), salt: me.salt, fee_salt: me.fee_salt, close_salt: me.close_salt, coeffs, salts, binding: [0; 8] };
    let sealed: Vec<Vec<u8>> =
        (0..n2).map(|j| dcu::seal_sub_share(&h.new_eks[j], &dcu::SubShare { lines: d.shares(j), salt: d.salts[j] })).collect::<Option<_>>()?;
    d.binding = deal_binding(book.batch, from, &sealed);
    let (r1cs, io, w) = ba::handover_deal_circuit(&d)?;
    let proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w)?;
    Some(DefiHandoverTx::Deal { pair: book.pair, batch: book.batch, from, subs: d.sub_commits().iter().map(u4).collect(), sealed, proof })
}

/// ⭐ What new custodian `j` captures from old custodian `from`'s dealing: its sealed sub-share opened with its own key and
/// checked against the dealing's commitment for it. `None` — not this custodian's.
#[must_use]
pub fn capture(dk: &[u8], j: usize, deal: &DefiHandoverTx) -> Option<dcu::SubShare> {
    let DefiHandoverTx::Deal { subs, sealed, .. } = deal else { return None };
    let st = dcu::open_sub_share(dk, sealed.get(j)?)?;
    (st.commit() == *subs.get(j)?).then_some(st)
}

/// ⭐ NEW CUSTODIAN `to`'s ACCEPTANCE from its captured sub-shares (old roster order): its new state (the pool's lines and the
/// fee line, each under a fresh salt) and the object.
#[must_use]
pub fn accept(book: &DefiBook, to: u32, subs: &[dcu::SubShare], key: &[u8; 32]) -> Option<(DefiHandoverTx, CustodianState)> {
    if subs.len() != book.roster.len() {
        return None;
    }
    let mut draw = blake3::Hasher::new_keyed(key).update(b"USDMD-BR15-HANDOVER-ACCEPT-v1").finalize_xof();
    let mut fresh = || -> [Fa4; 4] {
        core::array::from_fn(|_| {
            let mut b = [0u8; 4];
            draw.fill(&mut b);
            Fa4::from_u64(u64::from(u32::from_le_bytes(b) & 0x3FFF_FFFF))
        })
    };
    let (salt, fee_salt, close_salt) = (fresh(), fresh(), fresh());
    let a = ba::HandoverAccept { subs: subs.iter().map(|s| (s.lines, s.salt)).collect(), new_salt: salt, new_fee_salt: fee_salt, new_close_salt: close_salt };
    let (r1cs, io, w) = ba::handover_accept_circuit(&a)?;
    let proof = usdm_decider::spartan_ccs::prove_committed(&r1cs, &io, &w)?;
    let (pool, fee, close) = ba::split_state(&a.lines());
    let next = CustodianState { lines: pool, salt, fee, fee_salt, close, close_salt };
    Some((
        DefiHandoverTx::Accept { pair: book.pair, batch: book.batch, to, new_pool: next.commit(), new_fee: next.fee_commit(), new_close: next.close_commit(), proof },
        next,
    ))
}
