// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐⭐⭐ LANE C — CIRCUIT SOUNDNESS. THE ADVERSARY THAT ASKS WHETHER THE PROOFS CONSTRAIN WHAT THEY CLAIM.
//!
//! Nothing in this project had ever attacked the ZK layer as a LIAR. Every existing proof test asks
//! "does the honest proof verify, and does a FLIPPED BYTE reject" — which measures the WHIR engine's
//! tamper-resistance and NOTHING about whether the statement being proven is the statement the chain
//! needs. Those are different questions, and only the second one decides whether funds are safe:
//!
//!   * a proof engine can be perfectly sound while the AIR it proves constrains nothing;
//!   * a proof can be perfectly bound to its public inputs while those inputs are declared by the
//!     very party the proof is supposed to constrain;
//!   * a verifier can return `true` for a statement that is TRUE and IRRELEVANT.
//!
//! ⛔ THE THREE QUESTIONS THIS LANE ASKS, in the order a break matters:
//!
//!   1. PROVE-FALSE ([`prove_false`]) — can an ACCEPTING proof be produced for a FALSE statement?
//!      Unbalanced amounts, a note that is in no tree, a nullifier that derives from no spent note,
//!      an invented public input. Every one must fail to PROVE or fail to VERIFY. A success is a
//!      total break.
//!   2. CONSTRAINT COVERAGE ([`constraint_coverage`]) — for each public input and each witness
//!      column, mutate it AFTER witness generation and confirm the verifier REJECTS. An input that
//!      can be changed with the proof still verifying is UNCONSTRAINED, and this lane reports it as
//!      a break naming the exact input.
//!   3. BINDING ([`binding`]) — is the proof bound to the STATEMENT IT IS PRESENTED WITH? This is
//!      the D01 shape: `decider_prove_light(chain_acc)` taking one argument means the proof may not
//!      be about the chain at all. Each pin there states precisely what acceptance IMPLIES and what
//!      it does NOT.
//!
//! ⛔ WHY A PIN HERE IS ALLOWED TO BE GREEN WHILE NAMING A BREAK. A pin that measures a hole asserts
//! the HOLE, so it stays green until the hole is CLOSED, and the day it closes the pin goes red and
//! its failure text names the closure. That is deliberate: a lane whose findings vanish the moment
//! someone patches a symptom is a lane that cannot be trusted to have measured anything. Every such
//! pin is listed in [`pins::OPEN_BREAKS`] with the exact input or statement it names.
//!
//! ⛔ INEXPRESSIBLE ATTACKS ARE DECLARED, NEVER SKIPPED. [`pins::INEXPRESSIBLE`] names every attack
//! this lane wanted to run and could not, with the exact API reason. A silent gap here is a gap in
//! the chain.
//!
//! ⛔ NO PIN IN THIS LANE MOVES ANY STATE. Every attack is a pure function of bytes the attacker
//! controls: it proves carriers, calls production verifiers and calls the pure admission rule
//! `chain_object::admissible`. Nothing here constructs a `Node`, touches a datadir, or opens a
//! socket, so the lane can run on a loaded machine without confounding any other lane's measurement.

pub mod binding;
pub mod constraint_coverage;
pub mod pins;
pub mod prove_false;

use p3_field::PrimeCharacteristicRing;
use p3_field::integers::QuotientMap;
use usdm_decider::hiding_decider::Fa4;

/// The KoalaBear prime the whole decider works in: `2^31 - 2^24 + 1`. Every `u64` amount a gate
/// reads has been through the field's integer quotient map, i.e. REDUCED MOD THIS. It is the single
/// most important number in this lane: an "amount" constraint written as a field identity is an
/// identity MOD `KOALABEAR_P`, not over the integers, unless a range constraint says otherwise —
/// and the amount gates on the send path carry no range constraint (pin C-3).
pub const KOALABEAR_P: u64 = 2_130_706_433;

/// One amount as the decider sees it. The name says what the conversion DOES: it is not an
/// injection from `u64`, it is a reduction, and the whole of pin C-3 turns on that.
pub fn amount_as_field_element(v: u64) -> Fa4 {
    Fa4::from_int(v)
}

/// MEASURE (never assume) that [`KOALABEAR_P`] really is the modulus the amount columns reduce by,
/// and that the reduction is lossy in exactly the way pin C-3 exploits. Every field-wrap verdict in
/// this lane rests on this, so it is checked rather than commented.
pub fn koalabear_modulus_is_measured() -> bool {
    amount_as_field_element(KOALABEAR_P) == Fa4::ZERO
        && amount_as_field_element(KOALABEAR_P + 1) == Fa4::ONE
        && amount_as_field_element(1) != Fa4::ZERO
        && amount_as_field_element(KOALABEAR_P + 7) == amount_as_field_element(7)
}

/// A 32-row trace column of a single repeated value — the row-replication padding shape the direct
/// engine requires (height a power of two ≥ `2^REC_DECIDER_FOLDING`; row-LOCAL constraints are
/// preserved exactly by replication, which is why the engine pads this way).
pub fn amount_column_32(v: u64) -> Vec<Fa4> {
    vec![amount_as_field_element(v); 32]
}

/// The transcript public bind the production send carrier uses — rebuilt here from the crate's own
/// PUBLIC constant rather than borrowed from the private helper, so this lane sees exactly what an
/// attacker sees from outside the crate. THAT IT IS A ONE-ELEMENT CONSTANT is the finding: there is
/// no slot in it for a nullifier, an output commitment, an anchor root, or a chain id.
pub fn send_carrier_public_bind() -> [Fa4; 1] {
    [Fa4::from_int(usdm_decider::SPEND_CARRIER_DOMAIN)]
}

#[cfg(all(test, feature = "pins-harness"))]
mod modulus_pin {
    /// PIN C-0 — the lane's own foundation: the amount columns reduce mod KoalaBear.
    #[test]
    fn c0_amount_columns_reduce_mod_koalabear() {
        assert!(
            super::koalabear_modulus_is_measured(),
            "LANE C rests on the amount columns being KoalaBear elements; if this fails, every \
             field-wrap verdict in this lane must be re-derived for the new field before it is cited"
        );
        println!(
            "[C-0] amount columns reduce mod p = {} (2^31 - 2^24 + 1)",
            super::KOALABEAR_P
        );
    }
}
