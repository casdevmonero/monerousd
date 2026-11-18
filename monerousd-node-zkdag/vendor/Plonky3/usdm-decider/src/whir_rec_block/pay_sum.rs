// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE INCOME PROOF — "these notes pay address R, and together they hold exactly T", in ONE proof, shown to one
//! verifier the user picks (the user 2026-11-09: proof tags, so a business can prove income; 2026-11-10: one switch,
//! proof on demand). It is the payment proof ([`super::pay_proof`]) over many notes at once, with one difference that
//! matters: THE AMOUNT OF EACH NOTE STAYS PRIVATE. The verifier learns the listed commitments, their count and the
//! total, and nothing about how the total splits.
//!
//! Borrowed shapes: Monero's `get_reserve_proof` (many outputs, one total, one message), the designated-verifier
//! proof of Jakobsson, Sako and Impagliazzo (1996), and the running-sum column every STARK ledger uses. The
//! cryptography is the chain's own.
//!
//! THE STATEMENT. Public: the commitments `cm_0 … cm_{n-1}` (chain data), the recipient's address key, the asset, the
//! total `T`, the verifier's key `V` and a context digest. One row per note. A row shows
//!
//! ```text
//!     cm_i == P(limbs(a_i), P([asset tag, 0…], P(spk_R, seed_i)))  for an amount a_i and a seed the prover knows
//!  OR the prover knows v with V == P(v, [VERIFIER, 0…])
//! ```
//!
//! and the rows together show `a_0 + … + a_{n-1} == T` over the integers:
//!
//!   * each amount limb is sixteen bit-bound cells, so a limb is below 2^16 and is the commitment's own limb;
//!   * four running sums (one per limb) start at zero on the first row and add the row's limb on every step;
//!   * on the last row the four sums are joined to the public total's limbs through three carries, each ten bit-bound
//!     cells. Every quantity in those equations is below 2^27 and the field is above 2^30, so they hold over the
//!     integers and the total cannot wrap;
//!   * a row past the listed notes (the table is padded to a power of two) is forced to amount zero.
//!
//! The listed commitments enter as a PUBLIC column: the gate evaluates its multilinear extension at the zerocheck's own
//! point, so there is nothing for a prover to choose. A verifier refuses a list that names one note twice.
//!
//! WHAT IT NEVER SHOWS: any single amount, the recipient's other notes, a nullifier, a balance beyond `T`, or any key.
//! No node sees a proof and no chain byte is written. The verifier separately checks that each `cm_i` is on the chain.
//!
//! cons: none on the chain. Off the chain one proof per statement of up to [`PAY_SUM_MAX_NOTES`] notes; bytes and
//! milliseconds are measured by `pay_sum_tests::the_income_proof_is_measured`.

use super::*;

/// Domain word of an income proof's public bind ("PAYS").
pub const PAY_SUM_DOMAIN: u64 = 0x5041_5953;
/// The most notes one proof lists. A longer list is several proofs, each with its own total.
// PRODUCTION-SCALE-REVIEWED: a bound on ONE off-chain statement's table (2^8 rows), not a chain or wallet limit; the
// carry width below is sized from it, and a wallet with more notes makes more than one proof.
pub const PAY_SUM_MAX_NOTES: usize = 256;

/// The limbs an amount is committed in ([`note_value_lanes`]) and the bits of one.
// PRODUCTION-SCALE-REVIEWED: the note commitment's own shape (four 16-bit limbs), fixed by `note_value_lanes`.
const LIMBS: usize = 4;
// PRODUCTION-SCALE-REVIEWED: the note commitment's own limb width, fixed by `note_value_lanes`.
const LIMB_BITS: usize = 16;
/// Bits of one carry. A limb sum over [`PAY_SUM_MAX_NOTES`] rows is below 2^24, so a carry is below 2^9.
// PRODUCTION-SCALE-REVIEWED: derived from the row bound above (2^8 rows of 16-bit limbs carry at most 9 bits).
const CARRY_BITS: usize = 10;

// ---- the row
/// The branch bit: 1 = the note opens as stated, 0 = the prover holds the verifier's secret.
const PS_REAL: usize = 0;
/// The note's seed.
const PS_SEED: usize = PS_REAL + 1;
/// `o = P(spk_R, seed)`.
const PS_O_BLK: usize = PS_SEED + DIGEST_LANES;
/// `k = P([asset tag, 0…], o)`.
const PS_K_BLK: usize = PS_O_BLK + POSE_BLK;
/// `cm' = P(limbs(a), k)`.
const PS_CM_BLK: usize = PS_K_BLK + POSE_BLK;
/// The verifier's secret.
const PS_VSK: usize = PS_CM_BLK + POSE_BLK;
/// `V' = P(v, [VERIFIER, 0…])`.
const PS_V_BLK: usize = PS_VSK + DIGEST_LANES;
/// The amount's bits, limb by limb, low bit first.
const PS_BITS: usize = PS_V_BLK + POSE_BLK;
/// The running limb sums BEFORE this row.
const PS_ACC: usize = PS_BITS + LIMBS * LIMB_BITS;
/// The three carries' bits, read on the last row.
const PS_CARRY: usize = PS_ACC + LIMBS;
/// The row's width.
pub const PAY_SUM_WIDTH: usize = PS_CARRY + (LIMBS - 1) * CARRY_BITS;

/// What an income proof states.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomeStatement {
    /// The listed notes' commitments, as the chain records them, in the order the proof lays them.
    pub cms: Vec<Digest>,
    /// The recipient's address key.
    pub recipient_spk: Digest,
    /// What the listed notes hold together, in atomic units.
    pub total: u64,
    /// The asset (`USDM_ASSET_TAG` for USDm).
    pub asset_tag: [u64; 3],
    /// The key of the one verifier this proof is for.
    pub verifier_key: Digest,
    /// What the proof answers: the verifier's challenge and whatever it names.
    pub context: Digest,
}

impl IncomeStatement {
    /// Is the list one this class proves: at least one note, at most [`PAY_SUM_MAX_NOTES`], none named twice?
    fn well_formed(&self) -> bool {
        let distinct: std::collections::HashSet<&Digest> = self.cms.iter().collect();
        !self.cms.is_empty() && self.cms.len() <= PAY_SUM_MAX_NOTES && distinct.len() == self.cms.len()
    }

    /// The rows the table lays for this list: the count padded to a power of two, never below the light carrier's.
    fn rows(&self) -> usize {
        self.cms.len().next_power_of_two().max(LIGHT_CARRIER_ROWS)
    }

    fn tag_lanes(&self) -> Digest {
        let mut t = [0u64; DIGEST_LANES];
        t[..self.asset_tag.len()].copy_from_slice(&self.asset_tag);
        t
    }
}

/// The commitment a note of `amount` for `recipient_spk` opens to under `seed`: the chain's own spelling.
fn note_cm(st: &IncomeStatement, amount: u64, seed: &Digest) -> Digest {
    let o = owner_opening(&st.recipient_spk, seed);
    let k = poseidon_pair(st.tag_lanes(), o);
    poseidon_pair(crate::poseidon2_compress::lanes_of(&note_value_lanes(amount)), k)
}

#[derive(Clone)]
struct PaySumGate {
    gamma: Ea4,
    /// The listed commitments, in order: the public column.
    cms: Vec<[Ea4; DIGEST_LANES]>,
    /// log2 of the rows the table lays (the blinding half is one more variable, the point's first).
    data_vars: usize,
    spk: [Ea4; DIGEST_LANES],
    tag: [Ea4; DIGEST_LANES],
    verifier_key: [Ea4; DIGEST_LANES],
    /// The public total's four limbs.
    total: [Ea4; LIMBS],
}

fn ea(v: u64) -> Ea4 {
    Ea4::from(Fa4::from_u64(v))
}

impl PaySumGate {
    fn of(st: &IncomeStatement, gamma: Ea4) -> Self {
        let lanes = |d: &Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| ea(d[i])) };
        let t = note_value_lanes(st.total);
        PaySumGate {
            gamma,
            cms: st.cms.iter().map(lanes).collect(),
            data_vars: st.rows().trailing_zeros() as usize,
            spk: lanes(&st.recipient_spk),
            tag: lanes(&st.tag_lanes()),
            verifier_key: lanes(&st.verifier_key),
            total: core::array::from_fn(|c| ea(t[c])),
        }
    }

    /// Every law of the row, unbatched. `x[0]` is the blinding half's variable; the rest index the laid rows, high
    /// bit first (the convention of `cyclic_shift_sigma`).
    fn build(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let one = Ea4::ONE;
        if x.len() != self.data_vars + 1 || self.cms.is_empty() || self.cms.len() > (1usize << self.data_vars) {
            // a point of another shape is not this class's: one law that never holds
            return vec![one];
        }
        // the indicator of each laid row at this point, so a public value per row is a function of the point alone
        let mut w: Vec<Ea4> = vec![one];
        for xk in &x[1..] {
            let mut next = Vec::with_capacity(w.len() * 2);
            for v in &w {
                next.push(*v * (one - *xk));
                next.push(*v * *xk);
            }
            w = next;
        }
        let listed = self.cms.len();
        let act = w[..listed].iter().fold(Ea4::ZERO, |s, v| s + *v);
        let pub_cm: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| self.cms.iter().zip(&w).fold(Ea4::ZERO, |s, (cm, v)| s + cm[c] * *v));
        let is_first = w[0];
        let is_last = w[w.len() - 1];
        let not_last = one - is_last;

        let out = crate::pow_pq_air::PERM_OUT;
        let mut rs: Vec<Ea4> = Vec::new();
        let real = local[PS_REAL];
        rs.push(real * (real - one));
        for blk in [PS_O_BLK, PS_K_BLK, PS_CM_BLK, PS_V_BLK] {
            crate::pow_pq_air::push_perm_residuals(local, blk, &mut rs);
        }
        // the amount's limbs, each the sum of its own bit-bound cells
        let limb: [Ea4; LIMBS] = core::array::from_fn(|c| (0..LIMB_BITS).fold(Ea4::ZERO, |s, b| s + local[PS_BITS + c * LIMB_BITS + b] * ea(1 << b)));
        for i in 0..LIMBS * LIMB_BITS {
            let bit = local[PS_BITS + i];
            rs.push(bit * (bit - one));
        }
        for c in 0..DIGEST_LANES {
            // o = P(spk_R, seed)
            rs.push(local[PS_O_BLK + c] - self.spk[c]);
            rs.push(local[PS_O_BLK + DIGEST_LANES + c] - local[PS_SEED + c]);
            // k = P(tag, o)
            rs.push(local[PS_K_BLK + c] - self.tag[c]);
            rs.push(local[PS_K_BLK + DIGEST_LANES + c] - local[PS_O_BLK + out + c]);
            // cm' = P(limbs(a), k): the amount's lanes are the row's own limbs, the rest zero
            let lane = if c < LIMBS { limb[c] } else { Ea4::ZERO };
            rs.push(local[PS_CM_BLK + c] - lane);
            rs.push(local[PS_CM_BLK + DIGEST_LANES + c] - local[PS_K_BLK + out + c]);
            // V' = P(v, [VERIFIER, 0…])
            rs.push(local[PS_V_BLK + c] - local[PS_VSK + c]);
            let dom = if c == 0 { ea(PAY_VERIFIER_DOMAIN) } else { Ea4::ZERO };
            rs.push(local[PS_V_BLK + DIGEST_LANES + c] - dom);
            // one branch holds on a listed row: its note opens to the listed commitment, or the prover holds the
            // verifier's secret
            rs.push(act * real * (local[PS_CM_BLK + out + c] - pub_cm[c]));
            rs.push((one - real) * (local[PS_V_BLK + out + c] - self.verifier_key[c]));
        }
        // the running sums: zero on the first row, plus the row's limb on every step; a row past the list adds nothing
        let sigma = crate::air_zerocheck::cyclic_shift_sigma(x);
        for c in 0..LIMBS {
            rs.push((one - act) * limb[c]);
            rs.push(is_first * local[PS_ACC + c]);
            rs.push(not_last * (at(PS_ACC + c, &sigma) - local[PS_ACC + c] - limb[c]));
        }
        // the last row joins the four sums to the public total through three bit-bound carries
        let carry: [Ea4; LIMBS - 1] =
            core::array::from_fn(|c| (0..CARRY_BITS).fold(Ea4::ZERO, |s, b| s + local[PS_CARRY + c * CARRY_BITS + b] * ea(1 << b)));
        for i in 0..(LIMBS - 1) * CARRY_BITS {
            let bit = local[PS_CARRY + i];
            rs.push(bit * (bit - one));
        }
        let base = ea(1 << LIMB_BITS);
        for c in 0..LIMBS {
            let carry_in = if c == 0 { Ea4::ZERO } else { carry[c - 1] };
            let carry_out = if c + 1 < LIMBS { carry[c] } else { Ea4::ZERO };
            rs.push(is_last * (local[PS_ACC + c] + limb[c] + carry_in - self.total[c] - base * carry_out));
        }
        rs
    }
}

impl crate::air_zerocheck::AirConstraint for PaySumGate {
    /// MEASURED by the degree census (3): the hash rows' own cube, and a square times a row's weight. The next-row
    /// read of the running sums is a rotated column, degree one like any cell, so the declaration is the laws' own
    /// and a round samples 6 points where the old `nvars + 1` declaration sampled 11.
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let (mut acc, mut gp) = (Ea4::ZERO, Ea4::ONE);
        for r in self.build(local, at, x) {
            acc += gp * r;
            gp *= self.gamma;
        }
        acc
    }
    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        self.build(local, at, x)
    }
    fn is_row_local(&self) -> bool {
        false
    }
    /// The one rotated run the sum reads: the four running sums of the next row.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some((PS_ACC..PS_ACC + LIMBS).collect())
    }
    /// The seed and the verifier's secret are HIDING witnesses, each read by its block's input weld; no column is free.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

fn pay_sum_bind(st: &IncomeStatement) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(PAY_SUM_DOMAIN), Fa4::from_u64(st.cms.len() as u64)];
    let fixed = [st.recipient_spk, st.tag_lanes(), st.verifier_key, st.context, crate::poseidon2_compress::lanes_of(&note_value_lanes(st.total))];
    for d in fixed.iter().chain(st.cms.iter()) {
        b.extend(d.iter().map(|v| Fa4::from_u64(*v)));
    }
    b
}

/// What one row lays: its branch, its note and the verifier secret it names.
#[derive(Clone, Copy)]
struct RowWitness {
    real: bool,
    amount: u64,
    seed: Digest,
    vsk: Digest,
}

/// The table for `rows` under `st`, laid exactly as given (no check that it is true: the gate decides).
fn pay_sum_cols(st: &IncomeStatement, rows: &[RowWitness]) -> Vec<Vec<Fa4>> {
    let f = |d: &Digest| -> DigestF { to_f(d) };
    let out_of = |row: &[Fa4], blk: usize| -> DigestF { core::array::from_fn(|c| row[blk + crate::pow_pq_air::PERM_OUT + c]) };
    let dom = f(&crate::poseidon2_compress::lanes_of(&[PAY_VERIFIER_DOMAIN]));
    let total = note_value_lanes(st.total);
    let mut acc = [0u64; LIMBS];
    let mut table: Vec<Vec<Fa4>> = Vec::with_capacity(rows.len());
    for (i, w) in rows.iter().enumerate() {
        let mut row = vec![Fa4::ZERO; PAY_SUM_WIDTH];
        row[PS_REAL] = Fa4::from_u64(u64::from(w.real));
        row[PS_SEED..PS_SEED + DIGEST_LANES].copy_from_slice(&f(&w.seed));
        row[PS_VSK..PS_VSK + DIGEST_LANES].copy_from_slice(&f(&w.vsk));
        crate::pow_pq_air::lay_perm_row_flat(&mut row, PS_O_BLK, pose_state(&f(&st.recipient_spk), &f(&w.seed)));
        let o = out_of(&row, PS_O_BLK);
        crate::pow_pq_air::lay_perm_row_flat(&mut row, PS_K_BLK, pose_state(&f(&st.tag_lanes()), &o));
        let k = out_of(&row, PS_K_BLK);
        let limbs = note_value_lanes(w.amount);
        crate::pow_pq_air::lay_perm_row_flat(&mut row, PS_CM_BLK, pose_state(&f(&crate::poseidon2_compress::lanes_of(&limbs)), &k));
        crate::pow_pq_air::lay_perm_row_flat(&mut row, PS_V_BLK, pose_state(&f(&w.vsk), &dom));
        for c in 0..LIMBS {
            for b in 0..LIMB_BITS {
                row[PS_BITS + c * LIMB_BITS + b] = Fa4::from_u64((limbs[c] >> b) & 1);
            }
            row[PS_ACC + c] = Fa4::from_u64(acc[c]);
        }
        if i + 1 == rows.len() {
            // the carries that join the sums to the stated total (whatever it is: a false total leaves a law unmet)
            let mut carry = 0u64;
            for c in 0..LIMBS - 1 {
                carry = (acc[c] + limbs[c] + carry).saturating_sub(total[c]) >> LIMB_BITS;
                for b in 0..CARRY_BITS {
                    row[PS_CARRY + c * CARRY_BITS + b] = Fa4::from_u64((carry >> b) & 1);
                }
            }
        }
        for c in 0..LIMBS {
            acc[c] += limbs[c];
        }
        table.push(row);
    }
    (0..PAY_SUM_WIDTH).map(|c| table.iter().map(|row| row[c]).collect()).collect()
}

fn prove_pay_sum(st: &IncomeStatement, rows: &[RowWitness]) -> Option<Vec<u8>> {
    if !st.well_formed() || rows.len() != st.rows() {
        return None;
    }
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_chained_bytes(pay_sum_cols(st, rows), move |g: Ea4| PaySumGate::of(&st2, g), &pay_sum_bind(st))
}

/// PROVE income: the recipient, holding each listed note's `(amount, seed)` in the statement's order, shows `st` to
/// the verifier it names. `None` when a note does not open to its listed commitment, when the amounts do not sum to
/// the stated total, or when the list is not one this class proves (never a proof of a false statement).
#[must_use]
pub fn prove_income(st: &IncomeStatement, notes: &[(u64, Digest)]) -> Option<Vec<u8>> {
    if !st.well_formed() || notes.len() != st.cms.len() {
        return None;
    }
    if notes.iter().zip(&st.cms).any(|((amount, seed), cm)| note_cm(st, *amount, seed) != *cm) {
        return None;
    }
    let sum = notes.iter().try_fold(0u64, |s, (amount, _)| s.checked_add(*amount))?;
    if sum != st.total {
        return None;
    }
    let mut rows: Vec<RowWitness> = Vec::with_capacity(st.rows());
    for (amount, seed) in notes {
        rows.push(RowWitness { real: true, amount: *amount, seed: *seed, vsk: fresh_lc_blind()? });
    }
    // rows past the list: a fresh note of amount zero, so they are no tell in any transcript
    while rows.len() < st.rows() {
        rows.push(RowWitness { real: true, amount: 0, seed: fresh_lc_blind()?, vsk: fresh_lc_blind()? });
    }
    prove_pay_sum(st, &rows)
}

/// THE VERIFIER'S OWN BRANCH: with its secret `vsk` it makes an accepting proof of ANY statement naming its key, which
/// is what makes a proof passed on worthless. `None` when `vsk` is not the secret behind `st.verifier_key`.
#[must_use]
pub fn simulate_income(st: &IncomeStatement, vsk: &Digest) -> Option<Vec<u8>> {
    if !st.well_formed() || pay_verifier_key(vsk) != st.verifier_key {
        return None;
    }
    let mut rows: Vec<RowWitness> = Vec::with_capacity(st.rows());
    for i in 0..st.rows() {
        rows.push(RowWitness { real: false, amount: if i == 0 { st.total } else { 0 }, seed: fresh_lc_blind()?, vsk: *vsk });
    }
    prove_pay_sum(st, &rows)
}

/// VERIFY an income proof against the statement the verifier itself wrote down (its own key, its own challenge in
/// `context`). True means: for every listed note one of the two branches held, and the amounts sum to the total. For
/// the named verifier the branch is the first. A list that names a note twice is refused before the proof is read.
#[must_use]
pub fn verify_income(bytes: &[u8], st: &IncomeStatement) -> bool {
    if bytes.is_empty() || !st.well_formed() {
        return false;
    }
    let st2 = st.clone();
    crate::committed_air::verify_air_blinded_chained_bytes(
        bytes,
        move |g: Ea4| PaySumGate::of(&st2, g),
        &pay_sum_bind(st),
        (st.rows().trailing_zeros() as usize, PAY_SUM_WIDTH),
    )
}

#[cfg(test)]
mod pay_sum_tests;
