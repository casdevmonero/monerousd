// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE PAYMENT PROOF — "this note pays address R the amount A", shown to ONE verifier the user picks and worthless to
//! everyone else (docs/PAYMENT-PROOFS-SPEC-20261109.md §2; the user 2026-11-09: proof tags, so a business can prove
//! income). Borrowed shapes: Monero's `get_tx_proof` / `check_tx_proof` (one output, one verifier) and the
//! designated-verifier proof of Jakobsson, Sako and Impagliazzo (1996). The cryptography is the chain's own.
//!
//! THE STATEMENT. Public: the note commitment `cm` (chain data), the recipient's address key `spk_R`, the amount `A`,
//! the asset tag, the verifier's key `V`, and a context digest (the verifier's challenge, an invoice
//! reference). The proof shows
//!
//! ```text
//!     cm == P(limbs(A), P([asset tag, 0…], P(spk_R, seed)))  for a seed the prover knows
//!  OR the prover knows v with V == P(v, [VERIFIER, 0…])
//! ```
//!
//! and never which. The payer knows `seed` because it sealed the note; the payee knows it because it opened the note.
//! So a payment proof and a receipt proof are this one statement, made by either side.
//!
//! WHY THE SECOND BRANCH. Only the named verifier knows `v`, and it knows it made no proof, so for it the first
//! branch held. Anyone else shown the bytes must allow that the verifier made them through the second branch
//! ([`simulate_payment`] does exactly that, for ANY statement), so the bytes prove nothing once passed on. A user who
//! wants a proof anyone can check names a verifier key nobody can hold ([`public_verifier_key`]).
//!
//! WHAT IT NEVER SHOWS: the payer's or payee's other notes, the nullifier (so the verifier cannot see the note's
//! later spend), a balance, or any key. No node sees a proof and no chain byte is written. The verifier separately
//! checks that `cm` is on the chain, through its wallet's ordinary cover-shaped read.
//!
//! cons: none on the chain (zero bytes, zero node work). Off the chain one proof per payment disclosed; bytes and
//! milliseconds are measured by `pay_proof_tests::the_payment_proof_is_measured`.

use super::*;

/// Domain word of a payment proof's public bind ("PAYP").
pub const PAY_PROOF_DOMAIN: u64 = 0x5041_5950;
/// Domain lane of a verifier's key ("VRFY"), so a verifier key is no other compression's output.
pub const PAY_VERIFIER_DOMAIN: u64 = 0x5652_4659;

// ---- the row
/// The branch bit: 1 = the note opens as stated, 0 = the prover holds the verifier's secret.
const PP_REAL: usize = 0;
/// The note's seed.
const PP_SEED: usize = PP_REAL + 1;
/// `o = P(spk_R, seed)`.
const PP_O_BLK: usize = PP_SEED + DIGEST_LANES;
/// `k = P([asset tag, 0…], o)`.
const PP_K_BLK: usize = PP_O_BLK + POSE_BLK;
/// `cm' = P(limbs(A), k)`.
const PP_CM_BLK: usize = PP_K_BLK + POSE_BLK;
/// The verifier's secret.
const PP_VSK: usize = PP_CM_BLK + POSE_BLK;
/// `V' = P(v, [VERIFIER, 0…])`.
const PP_V_BLK: usize = PP_VSK + DIGEST_LANES;
/// The row's width.
pub const PAY_PROOF_WIDTH: usize = PP_V_BLK + POSE_BLK;

/// What a payment proof states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStatement {
    /// The note's commitment, as the chain records it.
    pub cm: Digest,
    /// The recipient's address key.
    pub recipient_spk: Digest,
    /// The amount, in atomic units.
    pub amount: u64,
    /// The asset (`USDM_ASSET_TAG` for USDm).
    pub asset_tag: [u64; 3],
    /// The key of the one verifier this proof is for.
    pub verifier_key: Digest,
    /// What the proof answers: the verifier's challenge and whatever it names (an invoice, a period).
    pub context: Digest,
}

/// The key a verifier publishes for the secret `v` it keeps.
#[must_use]
pub fn pay_verifier_key(v: &Digest) -> Digest {
    poseidon_pair(*v, crate::poseidon2_compress::lanes_of(&[PAY_VERIFIER_DOMAIN]))
}

/// A verifier key NOBODY holds a secret for: the all-zero digest is the output of no compression anyone can invert
/// to, so a proof under it can only have come through the first branch and anyone may check it. A user chooses this,
/// in plain words, when a proof is meant to be passed on (a court filing, a public receipt).
#[must_use]
pub fn public_verifier_key() -> Digest {
    [0; DIGEST_LANES]
}

fn tag_lanes(st: &PaymentStatement) -> Digest {
    let mut t = [0u64; DIGEST_LANES];
    t[..st.asset_tag.len()].copy_from_slice(&st.asset_tag);
    t
}

/// The commitment the statement's `(amount, asset, kind, recipient)` opens to under `seed`.
#[must_use]
pub fn payment_note_cm(st: &PaymentStatement, seed: &Digest) -> Digest {
    let o = owner_opening(&st.recipient_spk, seed);
    let k = poseidon_pair(tag_lanes(st), o);
    poseidon_pair(crate::poseidon2_compress::lanes_of(&note_value_lanes(st.amount)), k)
}

#[derive(Clone)]
struct PayProofGate {
    gamma: Ea4,
    cm: [Ea4; DIGEST_LANES],
    spk: [Ea4; DIGEST_LANES],
    limbs: [Ea4; DIGEST_LANES],
    tag: [Ea4; DIGEST_LANES],
    verifier_key: [Ea4; DIGEST_LANES],
}

impl PayProofGate {
    fn of(st: &PaymentStatement, gamma: Ea4) -> Self {
        let ea = |d: &Digest| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|i| Ea4::from(Fa4::from_u64(d[i]))) };
        PayProofGate {
            gamma,
            cm: ea(&st.cm),
            spk: ea(&st.recipient_spk),
            limbs: ea(&crate::poseidon2_compress::lanes_of(&note_value_lanes(st.amount))),
            tag: ea(&tag_lanes(st)),
            verifier_key: ea(&st.verifier_key),
        }
    }

    fn residuals(&self, local: &crate::air_zerocheck::Row<'_>) -> Vec<Ea4> {
        let one = Ea4::ONE;
        let out = crate::pow_pq_air::PERM_OUT;
        let mut rs: Vec<Ea4> = Vec::new();
        let real = local[PP_REAL];
        rs.push(real * (real - one));
        for blk in [PP_O_BLK, PP_K_BLK, PP_CM_BLK, PP_V_BLK] {
            crate::pow_pq_air::push_perm_residuals(local, blk, &mut rs);
        }
        for c in 0..DIGEST_LANES {
            // o = P(spk_R, seed)
            rs.push(local[PP_O_BLK + c] - self.spk[c]);
            rs.push(local[PP_O_BLK + DIGEST_LANES + c] - local[PP_SEED + c]);
            // k = P(tag, o)
            rs.push(local[PP_K_BLK + c] - self.tag[c]);
            rs.push(local[PP_K_BLK + DIGEST_LANES + c] - local[PP_O_BLK + out + c]);
            // cm' = P(limbs(A), k)
            rs.push(local[PP_CM_BLK + c] - self.limbs[c]);
            rs.push(local[PP_CM_BLK + DIGEST_LANES + c] - local[PP_K_BLK + out + c]);
            // V' = P(v, [VERIFIER, 0…])
            rs.push(local[PP_V_BLK + c] - local[PP_VSK + c]);
            let dom = if c == 0 { Ea4::from(Fa4::from_u64(PAY_VERIFIER_DOMAIN)) } else { Ea4::ZERO };
            rs.push(local[PP_V_BLK + DIGEST_LANES + c] - dom);
            // one branch holds: the note opens as stated, or the prover holds the verifier's secret
            rs.push(real * (local[PP_CM_BLK + out + c] - self.cm[c]));
            rs.push((one - real) * (local[PP_V_BLK + out + c] - self.verifier_key[c]));
        }
        rs
    }
}

impl crate::air_zerocheck::AirConstraint for PayProofGate {
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for r in self.residuals(local) {
            acc += gp * r;
            gp *= self.gamma;
        }
        acc
    }
    fn is_row_local(&self) -> bool {
        true
    }
    /// The seed and the verifier's secret are HIDING witnesses: each is read by its block's input weld, and the
    /// branch a prover is not on leaves its witness the prover's to choose (that is the designated-verifier shape).
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

fn pay_proof_bind(st: &PaymentStatement) -> Vec<Fa4> {
    let mut b = vec![Fa4::from_u64(PAY_PROOF_DOMAIN)];
    for d in [
        st.cm,
        st.recipient_spk,
        crate::poseidon2_compress::lanes_of(&note_value_lanes(st.amount)),
        tag_lanes(st),
        st.verifier_key,
        st.context,
    ] {
        b.extend(d.iter().map(|v| Fa4::from_u64(*v)));
    }
    b
}

fn pay_proof_row(st: &PaymentStatement, real: bool, seed: &Digest, vsk: &Digest) -> Vec<Fa4> {
    let mut row = vec![Fa4::ZERO; PAY_PROOF_WIDTH];
    let f = |d: &Digest| -> DigestF { to_f(d) };
    row[PP_REAL] = Fa4::from_u64(u64::from(real));
    row[PP_SEED..PP_SEED + DIGEST_LANES].copy_from_slice(&f(seed));
    row[PP_VSK..PP_VSK + DIGEST_LANES].copy_from_slice(&f(vsk));
    let out_of = |row: &[Fa4], blk: usize| -> DigestF { core::array::from_fn(|c| row[blk + crate::pow_pq_air::PERM_OUT + c]) };
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PP_O_BLK, pose_state(&f(&st.recipient_spk), &f(seed)));
    let o = out_of(&row, PP_O_BLK);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PP_K_BLK, pose_state(&f(&tag_lanes(st)), &o));
    let k = out_of(&row, PP_K_BLK);
    let limbs = f(&crate::poseidon2_compress::lanes_of(&note_value_lanes(st.amount)));
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PP_CM_BLK, pose_state(&limbs, &k));
    let dom = f(&crate::poseidon2_compress::lanes_of(&[PAY_VERIFIER_DOMAIN]));
    crate::pow_pq_air::lay_perm_row_flat(&mut row, PP_V_BLK, pose_state(&f(vsk), &dom));
    row
}

fn prove_pay_row(st: &PaymentStatement, row: Vec<Fa4>) -> Option<Vec<u8>> {
    let cols: Vec<Vec<Fa4>> = (0..row.len()).map(|c| vec![row[c]; LIGHT_CARRIER_ROWS]).collect();
    let st2 = *st;
    crate::committed_air::prove_air_blinded_bytes(cols, move |g: Ea4| PayProofGate::of(&st2, g), &pay_proof_bind(st))
}

/// Fresh lanes for the witness of the branch a prover is not on, so that branch's cells are not a tell in any
/// transcript an implementation might leak. `None` when the OS source refuses.
fn fresh_witness() -> Option<Digest> {
    fresh_lc_blind()
}

/// PROVE a payment: the payer or the payee, holding the note's `seed`, shows `st` to the verifier it names.
/// `None` when the note does not open as stated under `seed` (never a proof of a false statement).
#[must_use]
pub fn prove_payment(st: &PaymentStatement, seed: &Digest) -> Option<Vec<u8>> {
    if payment_note_cm(st, seed) != st.cm {
        return None;
    }
    prove_pay_row(st, pay_proof_row(st, true, seed, &fresh_witness()?))
}

/// THE VERIFIER'S OWN BRANCH: with its secret `vsk` it makes an accepting proof of ANY statement naming its key. This
/// is what makes a proof passed on worthless, and it is why a verifier must never treat as evidence a proof it could
/// have made itself. `None` when `vsk` is not the secret behind `st.verifier_key`.
#[must_use]
pub fn simulate_payment(st: &PaymentStatement, vsk: &Digest) -> Option<Vec<u8>> {
    if pay_verifier_key(vsk) != st.verifier_key {
        return None;
    }
    prove_pay_row(st, pay_proof_row(st, false, &fresh_witness()?, vsk))
}

/// VERIFY a payment proof against the statement the verifier itself wrote down (its own key, its own challenge in
/// `context`). True means: one of the two branches held. For the named verifier that is the first.
#[must_use]
pub fn verify_payment(bytes: &[u8], st: &PaymentStatement) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let st2 = *st;
    crate::committed_air::verify_air_blinded_bytes(
        bytes,
        move |g: Ea4| PayProofGate::of(&st2, g),
        &pay_proof_bind(st),
        (LIGHT_CARRIER_ROWS.trailing_zeros() as usize, PAY_PROOF_WIDTH),
    )
}

#[cfg(test)]
mod pay_proof_tests;
