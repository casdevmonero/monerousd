// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! **#75 brick 1 — CONFIDENTIAL SOLVENCY primitive (the spec the in-circuit AIR enforces).**
//!
//! The peg (Buy-USDm PSM) must stay 150%-over-collateralized, but MonerousD is DIGITAL CASH: a private
//! DAG must leak ZERO value totals or volume — no plaintext `minted_usdm` counter, no plaintext `reserve`
//! total, nothing an observer OR a re-executing node can sum ([[feedback_digital_cash_pillar]]). So the
//! reserve total and the circulating total are NEVER stored in the clear. They live ONLY as value-hiding
//! Poseidon COMMITMENTS in consensus state; each peg op advances them via a ZERO-KNOWLEDGE proof that the
//! update (a) conserves value (in == out, no hidden issuance) and (b) preserves the 150% solvency
//! invariant — proven over the HIDDEN amounts, revealing neither the totals nor the per-event
//! deposit/mint. A verifying node checks the proof + swaps the commitment; it never learns, and never
//! recomputes, any total.
//!
//! This module is the SOUND SPEC those constraints implement (mirrors the confidential-fee-split spec):
//! the exact value relation, the value-hiding commitment on the LIVE `poseidon_pair`, and the adversarial
//! rejects. Brick 2 folds these constraints into the WHIR light decider as PRIVATE witnesses; brick 3
//! re-architects `peg.rs` to carry commitments + proofs instead of plaintext `u128` totals; the node then
//! VERIFIES (never recomputes) — closing the last node-computable value leak.
//!
//! Ratio is in basis points (`ratio_bps`, e.g. 15000 = 150%) and is a governance policy parameter that is
//! consensus-known (like a block-reward schedule) — never a value. All amounts are USDm-atomic value
//! (`deposit_value` = external_units × attested_price), so solvency is a single-unit comparison.

// ONE digest width for the whole tree — 8 lanes x 31 bits = 248 bits (kill list §AG).
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::air_zerocheck::{prove_air_zerocheck, verify_air_zerocheck, AirConstraint, AirZerocheckProof};
use crate::hiding_decider::{Chl, Ea4, Fa4};
use crate::whir_rec_block::{poseidon_pair, REC_DECIDER_FOLDING};
use p3_challenger::FieldChallenger;
use p3_field::{Field, PrimeCharacteristicRing};

// The exact solvency relation and the u256 limb arithmetic live in `solvency_arith` (Kani-proven, `kani-proofs`).
pub use crate::solvency_arith::*;

/// ⭐⭐⭐ DB-452 — EVERY CONFIDENTIAL-VALUE CARRIER IS A BLINDED COMMITTED CARRIER: BOUND, AND HIDING.
///
/// ⛔ WAS: every carrier below (peg-in, peg-out, bond, the delta-bound transitions, the stability pool's step, the
/// withdrawal, the yield mint, the liquidation amount) rode the direct light decider, whose sent row was bound to NO
/// commitment and whose masked sumcheck's final target every caller dropped. MEASURED 2026-10-21 (link 77):
/// `db452_c_…` — a transition stating `s = 1,006,000` over a `5,000 + 1,000` trace VERIFIED (a hidden total inflated
/// from nothing); `db452_d_…` — every carrier lays ONE logical row as constant columns, and the multilinear extension of
/// a constant column is that constant at every point, so the sent evaluations WERE the amounts and the blinds.
///
/// ⭐ NOW: the spend carriers' own door (§BE-1, `committed_air::prove_air_blinded_bytes`) — the trace is committed before
/// any challenge, every opened value is proved against that commitment by a WHIR opening (the money path's
/// `CarrierParams::LIVE`, Johnson bound, H12), and the height is doubled with OS-entropy rows behind the `(1 − x₀)`
/// selector, so no sent evaluation is a row's value. ONE helper pair, so no value carrier can ride another engine.
/// Row-local gates only (a rotation would read a blinding row): a row-shifted gate is refused here, fail-closed.
fn prove_value_carrier<C, Mk>(cols: Vec<Vec<Fa4>>, make: Mk, statement_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    if !make(Ea4::ZERO).is_row_local() {
        return None;
    }
    crate::committed_air::prove_air_blinded_bytes(cols, make, statement_bind)
}

/// VERIFY a value carrier proved by [`prove_value_carrier`]: `laid_shape` is the trace the prover laid (before blinding
/// doubles its height), as the statement fixes it (DB-213b).
#[must_use]
fn verify_value_carrier<C, Mk>(bytes: &[u8], make: Mk, statement_bind: &[Fa4], laid_shape: (usize, usize)) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    if !make(Ea4::ZERO).is_row_local() {
        return false;
    }
    crate::committed_air::verify_air_blinded_bytes(bytes, make, statement_bind, laid_shape)
}

/// Split a `u128` value into two field-sized `u64` limbs (lo, hi) for commitment.
#[inline]
fn u128_limbs(v: u128) -> Digest {
    crate::poseidon2_compress::lanes_of(&[(v & u64::MAX as u128) as u64, (v >> 64) as u64])
}

/// A VALUE-HIDING commitment to a `u128` amount under a full-entropy `blind` (fresh CSPRNG per commit).
/// `poseidon_pair(value ‖ blind)` is a fixed-size uniform digest: binding (Poseidon collision-resistance)
/// and hiding (a fresh blind makes the digest uniform ∀ amount — a large total commits identically-shaped
/// to a small one). This is what lives in consensus state instead of the plaintext `minted_usdm`/`reserve`.
pub fn solvency_commit(value: u128, blind: Digest) -> Digest {
    poseidon_pair(u128_limbs(value), blind)
}

/// VALUE-HIDING commitment to a FULL 256-bit total (the width the transition proof uses), under a fresh
/// `blind`. Poseidon-folds the value's 16 canonical 16-bit limbs — each is a valid KoalaBear field element,
/// whereas packing into 64-bit words would exceed the field and destroy binding — into a 4-element digest,
/// then binds the blind: `commit = P( P(P(l0..4,l4..8), P(l8..12,l12..16)), blind )` using the SAME
/// `crate::whir_rec_block::poseidon_pair` the note-commitment + nullifier-tree already use (full strength, not
/// a reduced hash). Binding (Poseidon collision-resistance) + hiding (a fresh blind ⇒ uniform digest ∀ value).
/// This is what the peg persists as `reserve_commit`/`minted_commit`; brick 3b's in-circuit opening proves the
/// transition's value columns fold to exactly this, reusing this SAME poseidon fold as constraints.
pub fn solvency_commit_256(value: U256, blind: Digest) -> Digest {
    // Sixteen 16-bit limbs are EXACTLY two digests at 8 lanes, so the fold is two compressions where it
    // was four — the same binding, half the circuit.
    let l = u256_to_limbs16(value);
    let lo: Digest = core::array::from_fn(|i| l[i]);
    let hi: Digest = core::array::from_fn(|i| l[DIGEST_LANES + i]);
    poseidon_pair(poseidon_pair(lo, hi), blind)
}

// ── #75 brick 2a — the SLACK-FORM transition (the exact shape a zerocheck AIR enforces) ──────────────
//
// A zerocheck AIR proves EQUALITIES (`poly(columns) == 0`), not comparisons — so the two solvency
// INEQUALITIES are reformulated as equalities with a witnessed NON-NEGATIVE slack, the standard sound ZK
// trick:
//   backing   `mint·ratio ≤ deposit·10000`         ⟺  `deposit·10000 = mint·ratio + slack_b`,  slack_b ≥ 0
//   solvency  `new_res·10000 ≥ new_mint·ratio`      ⟺  `new_res·10000 = new_mint·ratio + slack_s`, slack_s ≥ 0
// Plus the two CONSERVATION equalities. A verifier checks the four equalities (zerocheck) AND that the two
// slacks are in the valid non-negative value RANGE (the existing confidential-amount range bind) — a forged
// over-mint would need a NEGATIVE slack, which a sound range bind rejects. All values stay HIDDEN (witnesses).
// This module pins the exact witness + the native check + the adversarial rejects; brick 2b feeds these
// columns to the WHIR light decider (the range bind is multi-limb for the totals, which can exceed one field
// element — the native `u128` check here is exact and is the fidelity spec that fold must match).

/// The witness for one confidential peg transition (all fields HIDDEN in-circuit; committed, never served).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SolvencyTransition {
    pub reserve: u128,
    pub minted: u128,
    pub delta_reserve: u128, // deposit_value (peg-in) or −release on a peg-out (see builders)
    pub delta_minted: u128,  // mint (peg-in) or −burn on a peg-out
    pub new_reserve: u128,
    pub new_minted: u128,
    pub slack_b: u128, // deposit·10000 − mint·ratio   ≥ 0  (peg-in backing); 0 on a peg-out
    pub slack_s: u128, // new_reserve·10000 − new_minted·ratio ≥ 0  (global solvency)
    pub ratio_bps: u32,
}

/// The EXACT set of equality + range constraints the AIR enforces over the (hidden) witness. Native `u128`
/// arithmetic here is the sound fidelity spec. Returns true iff EVERY constraint holds (fail-closed).
pub fn check_solvency_transition(w: &SolvencyTransition) -> bool {
    let r = w.ratio_bps as u128;
    // (1,2) CONSERVATION — the new totals are exactly old + delta (no hidden issuance). Checked-add so a
    // field-wrap can't fake it.
    let Some(exp_reserve) = w.reserve.checked_add(w.delta_reserve) else { return false };
    let Some(exp_minted) = w.minted.checked_add(w.delta_minted) else { return false };
    if exp_reserve != w.new_reserve || exp_minted != w.new_minted {
        return false;
    }
    // (3) BACKING equality with non-negative slack: deposit·10000 == mint·ratio + slack_b.
    let Some(mint_ratio) = w.delta_minted.checked_mul(r) else { return false };
    let Some(dep_scaled) = w.delta_reserve.checked_mul(BPS_DEN) else { return false };
    let Some(rhs_b) = mint_ratio.checked_add(w.slack_b) else { return false };
    if dep_scaled != rhs_b {
        return false;
    }
    // (4) SOLVENCY equality with non-negative slack: new_reserve·10000 == new_minted·ratio + slack_s.
    let Some(new_mint_ratio) = w.new_minted.checked_mul(r) else { return false };
    let Some(new_res_scaled) = w.new_reserve.checked_mul(BPS_DEN) else { return false };
    let Some(rhs_s) = new_mint_ratio.checked_add(w.slack_s) else { return false };
    if new_res_scaled != rhs_s {
        return false;
    }
    // The slacks are u128 (already non-negative by type); the in-circuit AIR additionally RANGE-BINDS them so a
    // prover cannot smuggle a field-wrapped "negative" slack. Native `u128` cannot wrap here (checked ops above).
    true
}

/// Build the HONEST peg-in transition witness (the custodian threshold, which holds the openings, runs this).
/// Returns `None` when the mint is NOT 150%-collateralized or the result would be insolvent — i.e. exactly
/// when an honest non-negative slack does not exist, so a valid witness is UN-constructible for an over-mint.
pub fn build_peg_in_transition(
    reserve: u128,
    minted: u128,
    deposit_value: u128,
    mint: u128,
    ratio_bps: u32,
) -> Option<SolvencyTransition> {
    let r = ratio_bps as u128;
    let new_reserve = reserve.checked_add(deposit_value)?;
    let new_minted = minted.checked_add(mint)?;
    // slack_b = deposit·10000 − mint·ratio  (None ⇒ over-mint: the deposit under-collateralizes the mint)
    let slack_b = deposit_value.checked_mul(BPS_DEN)?.checked_sub(mint.checked_mul(r)?)?;
    // slack_s = new_reserve·10000 − new_minted·ratio  (None ⇒ insolvent)
    let slack_s = new_reserve.checked_mul(BPS_DEN)?.checked_sub(new_minted.checked_mul(r)?)?;
    let w = SolvencyTransition {
        reserve, minted, delta_reserve: deposit_value, delta_minted: mint,
        new_reserve, new_minted, slack_b, slack_s, ratio_bps,
    };
    debug_assert!(check_solvency_transition(&w));
    Some(w)
}

// ── #75 brick 2b — the IN-CIRCUIT solvency proof: LIMB-WISE, no field reconstruction ─────────────────
//
// Proven in the WHIR light decider's zerocheck (`air_zerocheck`), so a VERIFYING NODE checks a proof over the
// COMMITTED limb columns and never sees or recomputes any total. Every equality is done LIMB-BY-LIMB with a
// carry column, so a 256-bit value is never squeezed into one ~31-bit KoalaBear element (the no-cap design).
// This brick proves CONSERVATION (`a + b == s`, i.e. `reserve + delta == new_total`, both peg legs); the
// backing/solvency SCALING equalities (×10000 / ×ratio — multi-bit carries + limb range binds) are next.

/// 16 little-endian 16-bit limbs of a `U256` (each < 2^16 < the KoalaBear prime, so it is a valid column value).
pub const N_LIMB16: usize = 16;
const LIMB16_BITS: u32 = 16;
const LIMB16_MASK: u64 = 0xFFFF;

pub(crate) fn u256_to_limbs16(v: U256) -> [u64; N_LIMB16] {
    let mut out = [0u64; N_LIMB16];
    for (i, o) in out.iter_mut().enumerate() {
        let word = i / 4; // 4 × 16-bit limbs per 64-bit word
        let sh = (i % 4) * 16;
        *o = (v[word] >> sh) & LIMB16_MASK;
    }
    out
}

/// IN-CIRCUIT limb-wise conservation constraint: `a + b == s` over 16 carry-linked 16-bit limbs, each carry
/// ∈ {0,1} and NO carry out of the top limb (a 257th bit ⇒ reject, fail-closed). Columns (width 64):
/// `a[0..16] | b[16..32] | s[32..48] | carry[48..64]`. Row-local; degree 2 (the carry boolean).
struct ConservationLimbAir {
    gamma: Ea4,
}
impl AirConstraint for ConservationLimbAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
        let mut cs: Vec<Ea4> = Vec::with_capacity(2 * N_LIMB16 + 1);
        for i in 0..N_LIMB16 {
            let a = local[i];
            let b = local[N_LIMB16 + i];
            let s = local[2 * N_LIMB16 + i];
            let cout = local[3 * N_LIMB16 + i];
            let cin = if i == 0 { Ea4::ZERO } else { local[3 * N_LIMB16 + i - 1] };
            // add relation: a_i + b_i + cin − s_i − cout·2^16 == 0
            cs.push(a + b + cin - s - cout * two16);
            // carry boolean: cout·(cout−1) == 0
            cs.push(cout * (cout - Ea4::ONE));
        }
        // no overflow past 256 bits: the top carry is 0
        cs.push(local[3 * N_LIMB16 + N_LIMB16 - 1]);
        // γ-batch (every constraint must be 0 ⇒ their γ-combination is 0)
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Build the 64-column height-2 trace proving `a + b == s` limb-wise (carries computed honestly). Returns
/// `None` if `s != a + b` or `a + b` overflows 256 bits (a real deposit/mint never does — fail-closed).
fn conservation_trace(a: U256, b: U256, s: U256) -> Option<Vec<Vec<Fa4>>> {
    let (al, bl, sl) = (u256_to_limbs16(a), u256_to_limbs16(b), u256_to_limbs16(s));
    let mut carry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let sum = al[i] + bl[i] + cin;
        if (sum & LIMB16_MASK) != sl[i] {
            return None; // s is not a+b
        }
        cin = sum >> LIMB16_BITS;
        carry[i] = cin;
    }
    if cin != 0 {
        return None; // overflow past 256 bits
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; 4 * N_LIMB16];
    let set = |c: usize, v: u64, cols: &mut Vec<Vec<Fa4>>| {
        let f = Fa4::from_u64(v);
        cols[c][0] = f;
        cols[c][1] = f;
    };
    for i in 0..N_LIMB16 {
        set(i, al[i], &mut cols);
        set(N_LIMB16 + i, bl[i], &mut cols);
        set(2 * N_LIMB16 + i, sl[i], &mut cols);
        set(3 * N_LIMB16 + i, carry[i], &mut cols);
    }
    Some(cols)
}

/// PROVE `a + b == s` in-circuit (limb-wise conservation). `ch` is the transcript; in the wired decider it
/// observes the column commitment BEFORE γ/z (binding the proof to the trace) — here the caller supplies a
/// fresh `ch` and `verify_conservation` uses the SAME transcript, exactly like the `air_zerocheck` roundtrip.
pub fn prove_conservation(a: U256, b: U256, s: U256, ch: &mut Chl) -> Option<AirZerocheckProof> {
    let cols = conservation_trace(a, b, s)?;
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = ConservationLimbAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    Some(prove_air_zerocheck(&cols, &air, &z, ch))
}

/// VERIFY a conservation proof — the node checks it WITHOUT the witness (only the committed columns' openings,
/// which the WHIR PCS binds). Fail-closed on a tampered trace.
#[must_use]
pub fn verify_conservation(proof: &AirZerocheckProof, ch: &mut Chl) -> bool {
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = ConservationLimbAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    verify_air_zerocheck(proof, &air, &z, ch)
}

// ── #75 brick 2b-ii — IN-CIRCUIT SCALING `p = a·k` (the ratio/backing multiply), limb-wise ────────────
//
// The backing/solvency checks scale a value by a small consensus-known constant `k` (10000, or the ratio
// bps ≤ ~2^14): `deposit·10000`, `mint·ratio`. Proven LIMB-WISE — `a`'s 16 16-bit limbs × `k` produce 17
// result limbs with a carry chain, each result limb RANGE-BOUND to 16 bits by its bit-decomposition. The
// ⛔⛔⛔ DB-362 (2026-09-29) — THE CARRIES MUST BE BOUND, AND THE BOUND IS DERIVED, NOT PICKED.
//
// The comment that stood here said a 16-bit range bind on each `p_i` "uniquely forces the carry, so no separate
// carry range-bind is needed". That is true of INTEGERS and false in the field: `a_i·k + c_{i−1} − p_i − c_i·2^16 = 0`
// is satisfiable for ANY canonical `p_i` by a field element `c_i` (2^16 is invertible), and summing the limb equations
// weighted by `2^(16 i)` telescopes every carry away, leaving only `Σ p_i·2^(16 i) ≡ a·k (mod p)`. So `a·k + p` — the
// modulus added as a 272-bit integer — verified as `a·k` (MEASURED 04:48 on this layout by
// `db362_a_scaled_value_aliased_by_the_field_modulus_is_refused`), and with it every backing inequality that this
// multiply feeds (peg-in, peg-out, revaluation, yield: `reserve·10000 ≥ minted·ratio`) could be met by an insolvent
// state whose scaled reserve was inflated by multiples of `p`. A reserve drain, one gadget deep.
//
// A 16-bit bind on the carries is NOT enough either: `p ≡ 1 (mod 2^16)`, so `+p` adds 1 to limb 0 and exactly
// `p >> 16 = 32,512` to ONE carry — a 16-bit value — and that limb equation wraps by `−p` with every column in range.
// The requirement is that each limb equation be an INTEGER identity: with `a_i, p_i < 2^16`, `k ≤ K`, `cin, cout ≤ C`,
// both `65535·K + C < p` and `C·2^16 + 65535 < p` must hold. The largest such `C` (and `K`) is 32,511:
// `32,511·65536 + 65,535 = 2,130,706,431 < p = 2,130,706,433`, while 32,512 fails. Honest carries are `≤ k ≤ K` by
// induction, so nothing honest is refused. The bound is enforced as TWO 15-bit decompositions per carry — `cout` and
// `SCALE_CARRY_MAX − cout` — and the public multiplier is refused above `SCALE_K_MAX` at prove AND verify.
//
// The same premise — every limb a canonical 16-bit integer — is what the OPENING gadget owes its consumers: it never
// range-bound the 16 limbs it hashes, so a NEW commitment (a post state, a delta) could carry non-canonical limbs that
// break the next transition's integer identities. Every opened value is now range-bound inside the gadget.
//
// Column layout: a[0..16] | p[16..33] | carry[33..49] | p_bits (17 × 16) | carry_bound (16 × 30) | a_bits (16 × 16).

/// The largest public multiplier a scale block admits — derived above, never tuned.
pub const SCALE_K_MAX: u64 = 32_511;
/// The largest carry a scale block admits — the same derivation; honest carries never exceed `k`.
pub const SCALE_CARRY_MAX: u64 = 32_511;
/// Half of a 16-bit limb: the width of each of a carry bound's two decompositions.
const HALF_BITS: usize = 15;
/// A 16-bit range block over 16 limbs.
pub(crate) const RANGE16_COLS: usize = N_LIMB16 * N_LIMB16;
/// A carry-bound block over a scale's 16 carries: two 15-bit decompositions each.
const CARRY_BOUND_COLS: usize = N_LIMB16 * 2 * HALF_BITS;

/// Whether a public multiplier keeps every limb equation an integer identity. Refused past [`SCALE_K_MAX`] by every
/// prove AND every verify that takes one — a verifier that accepted a wider `k` would accept the alias.
#[must_use]
pub fn scale_k_admissible(k: u64) -> bool {
    k <= SCALE_K_MAX
}

/// Lay `n` values' 16-bit decompositions at `bits_base` (value `i` at `bits_base + 16·i`). The caller owns the claim
/// that the values ARE 16-bit; a larger value's high bits are simply lost here and the constraint then refuses it.
fn place_range16(cols: &mut [Vec<Fa4>], values: &[u64], bits_base: usize) {
    for (i, &v) in values.iter().enumerate() {
        for j in 0..N_LIMB16 {
            let b = Fa4::from_u64((v >> j) & 1);
            for cell in cols[bits_base + i * N_LIMB16 + j].iter_mut() {
                *cell = b;
            }
        }
    }
}

/// `value_i == Σ_j bit_{i,j}·2^j` with boolean bits, for `n` values at `v_base`: each is a 16-bit integer.
fn push_range16_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, v_base: usize, bits_base: usize, n: usize) {
    let two = Ea4::from(Fa4::from_u64(2));
    for i in 0..n {
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for j in 0..N_LIMB16 {
            let bit = local[bits_base + i * N_LIMB16 + j];
            cs.push(bit * (bit - Ea4::ONE));
            rec += bit * pw;
            pw *= two;
        }
        cs.push(rec - local[v_base + i]);
    }
}

/// Lay a scale's carry bounds: for each carry, 15 bits of `cout` and 15 bits of `SCALE_CARRY_MAX − cout`. `false`
/// (no witness) when a carry exceeds the bound — which an honest trace never does.
fn place_carry_bound(cols: &mut [Vec<Fa4>], carries: &[u64; N_LIMB16], cbits_base: usize) -> bool {
    for (i, &c) in carries.iter().enumerate() {
        if c > SCALE_CARRY_MAX {
            return false;
        }
        let comp = SCALE_CARRY_MAX - c;
        for j in 0..HALF_BITS {
            let lo = Fa4::from_u64((c >> j) & 1);
            let hi = Fa4::from_u64((comp >> j) & 1);
            for cell in cols[cbits_base + i * 2 * HALF_BITS + j].iter_mut() {
                *cell = lo;
            }
            for cell in cols[cbits_base + i * 2 * HALF_BITS + HALF_BITS + j].iter_mut() {
                *cell = hi;
            }
        }
    }
    true
}

/// `cout_i == Σ bits_lo·2^j` and `SCALE_CARRY_MAX − cout_i == Σ bits_hi·2^j`, all bits boolean, 15 each: together
/// `0 ≤ cout_i ≤ SCALE_CARRY_MAX`, the bound that makes the limb equation an integer identity.
fn push_carry_bound_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, carry_base: usize, cbits_base: usize) {
    let two = Ea4::from(Fa4::from_u64(2));
    let max = Ea4::from(Fa4::from_u64(SCALE_CARRY_MAX));
    for i in 0..N_LIMB16 {
        let (mut lo, mut hi) = (Ea4::ZERO, Ea4::ZERO);
        let mut pw = Ea4::ONE;
        for j in 0..HALF_BITS {
            let bl = local[cbits_base + i * 2 * HALF_BITS + j];
            let bh = local[cbits_base + i * 2 * HALF_BITS + HALF_BITS + j];
            cs.push(bl * (bl - Ea4::ONE));
            cs.push(bh * (bh - Ea4::ONE));
            lo += bl * pw;
            hi += bh * pw;
            pw *= two;
        }
        let c = local[carry_base + i];
        cs.push(lo - c);
        cs.push(hi - (max - c));
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// n-LIMB ADD / COMPARE and the WIDE PUBLIC MULTIPLY (2026-09-29, for the liquidation amount carrier — docs/LIQUIDATION-
// TRUSTLESS-SPEC.md §9 — and DSOL's L4c MUL). A price is ~6·10^10, far above SCALE_K_MAX, so `a·k` for a public u64 `k`
// is a SCHOOLBOOK product in base 2^14: the operand's 14-bit limbs are LINEAR in the 16-bit range bits its opening
// already binds (no new witness), `k` is split into ≤ 8 public 13-bit chunks, and each product column
// `Σ_{i+j=m} a'_i·k_j + cin_m` holds at most 8 terms below 2^26 plus a carry below 2^16 — under p_nat, so the column
// equation `= out_m + cout_m·2^13` is an INTEGER identity in the field (the exact property DB-362 restored to the
// scale gadget) with `out_m` bound to 13 bits and `cout_m` to 16. The 13-bit product limbs are then re-limbed to
// 16 bits, again linearly from their bits, so the existing n-limb compare reads them.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// 13-bit product base (A-F74): at 14 bits the worst column sum `7·(2^14−1)^2 = 1,879,015,428` plus a 17-bit
/// carry gave `out + carry·2^14` up to 2,147,569,662 > p_nat 2,130,706,433 — a native-field wrap.  At 13 bits
/// the worst column sum `8·(2^13−1)^2 = 536,821,768` yields max carry 65,527 < 2^16, and the identity
/// `out + carry·2^13 ≤ 536,878,079 < p_nat` holds unconditionally.  cons: +10 columns (+1.1 %), +1 a-limb.
const M14_BITS: usize = 13;
/// A 256-bit operand in 13-bit limbs (`ceil(256 / 13)`).
const M14_A_LIMBS: usize = 20;
/// The public multiplier in 13-bit chunks: EIGHT, so a `k` of up to 104 bits rides — `p·BPS_DEN·(BPS_DEN − δ)`
/// reaches ~5·10^18 at a $60,000 quote, inside a u64 by a factor of three only, and no price the protocol can
/// quote may ever meet a circuit ceiling. Eight column terms stay below the field:
/// `8·(2^13−1)^2 + 2^16 < p_nat = 2,130,706,433`.
const M14_K_CHUNKS: usize = 8;
/// Product columns: `a'` limbs + `k` chunks (the last carries the final carry-out, which must be zero).
const M14_COLS: usize = M14_A_LIMBS + M14_K_CHUNKS; // 28 limbs of 13 bits = 364 bits ≥ the 360 bits of a·k
/// Carry width per product column: `8·(2^13−1)^2 + carry < p_nat` ⇒ carries stay below 2^16.
const M14_CARRY_BITS: usize = 16;
/// The product re-limbed to 16 bits for the compare gadget: `ceil(364 / 16)`.
pub(crate) const M14_P16_LIMBS: usize = 23;
/// One wide-multiply block's width: out limbs, carries, out bits, carry bits, and the 16-bit re-limbing.
pub(crate) const MUL14_COLS: usize = M14_COLS + M14_COLS + M14_COLS * M14_BITS + M14_COLS * M14_CARRY_BITS + M14_P16_LIMBS;
/// Offsets inside a wide-multiply block.
const M14_OUT: usize = 0;
const M14_COUT: usize = M14_OUT + M14_COLS;
const M14_OBITS: usize = M14_COUT + M14_COLS;
const M14_CBITS: usize = M14_OBITS + M14_COLS * M14_BITS;
const M14_P16: usize = M14_CBITS + M14_COLS * M14_CARRY_BITS;

/// The public multiplier's 13-bit chunks, little-endian. A `k` past 104 bits has no representation and is refused by
/// the callers' admissibility checks before a block is laid.
fn m14_chunks(k: u128) -> [u64; M14_K_CHUNKS] {
    core::array::from_fn(|j| ((k >> (M14_BITS * j)) & ((1 << M14_BITS) - 1)) as u64)
}

/// Whether a public multiplier fits the wide block's eight chunks.
pub(crate) fn mul14_k_admissible(k: u128) -> bool {
    k < (1u128 << (M14_BITS * M14_K_CHUNKS))
}

/// The operand's 13-bit limbs from its 256 bits (bit `b` of `a` = bit `b % 16` of 16-bit limb `b / 16`).
fn m14_operand_limbs(a16: &[u64; N_LIMB16]) -> [u64; M14_A_LIMBS] {
    core::array::from_fn(|i| {
        let mut v = 0u64;
        for t in 0..M14_BITS {
            let b = i * M14_BITS + t;
            if b < 256 {
                v |= ((a16[b / 16] >> (b % 16)) & 1) << t;
            }
        }
        v
    })
}

/// Native `a·k` as the wide block's honest cells: `(out limbs (14-bit), carries, P16 limbs)`.
fn m14_native(a16: &[u64; N_LIMB16], k: u128) -> ([u64; M14_COLS], [u64; M14_COLS], [u64; M14_P16_LIMBS]) {
    let al = m14_operand_limbs(a16);
    let kc = m14_chunks(k);
    let mut out = [0u64; M14_COLS];
    let mut cout = [0u64; M14_COLS];
    let mut cin = 0u64;
    for m in 0..M14_COLS {
        let mut col = cin;
        for j in 0..M14_K_CHUNKS {
            if m >= j && m - j < M14_A_LIMBS {
                col += al[m - j] * kc[j];
            }
        }
        out[m] = col & ((1 << M14_BITS) - 1);
        cin = col >> M14_BITS;
        cout[m] = cin;
    }
    // P16: the same 322 bits regrouped by 16
    let bit = |b: usize| -> u64 { if b / M14_BITS < M14_COLS { (out[b / M14_BITS] >> (b % M14_BITS)) & 1 } else { 0 } };
    let p16: [u64; M14_P16_LIMBS] = core::array::from_fn(|q| (0..16).map(|t| bit(16 * q + t) << t).sum());
    (out, cout, p16)
}

/// Lay one wide-multiply block at `base` for operand `a16` (16-bit limbs) and public `k`. Returns the product in 16-bit
/// limbs (for the compare), or `None` when the product overflows the block (impossible for a 256-bit `a` and a u64 `k`).
fn place_mul14(cols: &mut [Vec<Fa4>], a16: &[u64; N_LIMB16], k: u128, base: usize) -> Option<[u64; M14_P16_LIMBS]> {
    if !mul14_k_admissible(k) {
        return None;
    }
    let (out, cout, p16) = m14_native(a16, k);
    if cout[M14_COLS - 1] != 0 {
        return None;
    }
    let mut set = |c: usize, v: u64| {
        let f = Fa4::from_u64(v);
        for cell in cols[base + c].iter_mut() {
            *cell = f;
        }
    };
    for m in 0..M14_COLS {
        set(M14_OUT + m, out[m]);
        set(M14_COUT + m, cout[m]);
        for t in 0..M14_BITS {
            set(M14_OBITS + m * M14_BITS + t, (out[m] >> t) & 1);
        }
        for t in 0..M14_CARRY_BITS {
            set(M14_CBITS + m * M14_CARRY_BITS + t, (cout[m] >> t) & 1);
        }
    }
    for q in 0..M14_P16_LIMBS {
        set(M14_P16 + q, p16[q]);
    }
    Some(p16)
}

/// The wide-multiply constraints for a block at `base`: the operand's 13-bit limbs are read LINEARLY from its 16-bit
/// range bits at `abits` (the opening's `vbits` block — the operand is never re-witnessed), every product column is an
/// integer identity with 13-bit out limbs and 16-bit carries, the top carry is zero, and the 16-bit re-limbing is the
/// same bits regrouped.
fn push_mul14_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, abits: usize, k: u128, base: usize) {
    debug_assert!(mul14_k_admissible(k), "a wide block was built for a multiplier past its eight chunks — the doors refuse it first");
    let two = Ea4::from(Fa4::from_u64(2));
    let two14 = Ea4::from(Fa4::from_u64(1 << M14_BITS));
    let kc = m14_chunks(k);
    // the operand's 14-bit limbs, linear in its 256 range bits (bit b of a = bit b%16 of limb b/16)
    let a_bit = |b: usize| -> Ea4 { if b < 256 { local[abits + (b / 16) * N_LIMB16 + (b % 16)] } else { Ea4::ZERO } };
    let a14: Vec<Ea4> = (0..M14_A_LIMBS)
        .map(|i| {
            let mut v = Ea4::ZERO;
            let mut pw = Ea4::ONE;
            for t in 0..M14_BITS {
                v += a_bit(i * M14_BITS + t) * pw;
                pw *= two;
            }
            v
        })
        .collect();
    for m in 0..M14_COLS {
        let mut col = if m == 0 { Ea4::ZERO } else { local[base + M14_COUT + m - 1] };
        for j in 0..M14_K_CHUNKS {
            if m >= j && m - j < M14_A_LIMBS {
                col += a14[m - j] * Ea4::from(Fa4::from_u64(kc[j]));
            }
        }
        let out = local[base + M14_OUT + m];
        let cout = local[base + M14_COUT + m];
        cs.push(col - out - cout * two14);
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for t in 0..M14_BITS {
            let b = local[base + M14_OBITS + m * M14_BITS + t];
            cs.push(b * (b - Ea4::ONE));
            rec += b * pw;
            pw *= two;
        }
        cs.push(rec - out);
        let mut recc = Ea4::ZERO;
        let mut pwc = Ea4::ONE;
        for t in 0..M14_CARRY_BITS {
            let b = local[base + M14_CBITS + m * M14_CARRY_BITS + t];
            cs.push(b * (b - Ea4::ONE));
            recc += b * pwc;
            pwc *= two;
        }
        cs.push(recc - cout);
    }
    cs.push(local[base + M14_COUT + M14_COLS - 1]); // no overflow out of the top column
    // the 16-bit re-limbing: P16_q = Σ_{t<16} bit(16q + t)·2^t, the same out bits regrouped
    let p_bit = |b: usize| -> Ea4 { if b / M14_BITS < M14_COLS { local[base + M14_OBITS + (b / M14_BITS) * M14_BITS + (b % M14_BITS)] } else { Ea4::ZERO } };
    for q in 0..M14_P16_LIMBS {
        let mut v = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for t in 0..16 {
            v += p_bit(16 * q + t) * pw;
            pw *= two;
        }
        cs.push(v - local[base + M14_P16 + q]);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE HIDDEN MULTIPLY (2026-09-29): `a · b` for TWO opened values — what the wide public multiply cannot do, and what
// the Stability Pool's `(P, S)` update, a depositor's withdrawal (docs/LIQUIDATION-TRUSTLESS-SPEC.md §9.3) and DSOL's
// `MUL` (L4c) all need. The same discipline as the public multiply, one width narrower: both operands are re-limbed to
// 12 bits LINEARLY from the range bits their openings bind (no new witness), so a partial product is at most 24 bits
// and a schoolbook column of at most 22 of them plus a 17-bit carry stays below 2^29 < p — every column equation
// `Σ a_i·b_j + cin = out_m + cout_m·2^12` is an INTEGER identity (the DB-362 lesson: a limb equation that can wrap the
// field binds nothing). 12-bit out limbs and 17-bit carries are range-bound; the product is re-limbed to 16 bits for
// the n-limb compare / add. Generic in the operand width `n16` (16-bit limbs): 16 for a 256-bit total, 4 for a DSOL word.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Limb width of the hidden multiply.
pub(crate) const HH_BITS: usize = 12;
/// Carry width per product column: for operands of up to 16 × 16-bit limbs (22 twelve-bit limbs) a column holds at
/// most 22 partial products below 2^24 plus a carry below 2^17 — under 2^29 — so every carry is below 2^17.
pub(crate) const HH_CARRY_BITS: usize = 17;
/// 12-bit limbs of an operand of `n16` 16-bit limbs.
pub(crate) const fn hh_limbs(n16: usize) -> usize {
    (16 * n16 + HH_BITS - 1) / HH_BITS
}
/// Product columns: `2 · hh_limbs` (the last holds only the carry-in and must leave no carry-out).
pub(crate) const fn hh_cols(n16: usize) -> usize {
    2 * hh_limbs(n16)
}
/// The product re-limbed to 16 bits.
pub(crate) const fn hh_p16(n16: usize) -> usize {
    (HH_BITS * hh_cols(n16) + 15) / 16
}
/// Width of one hidden-multiply block: out limbs, carries, out bits, carry bits, the 16-bit re-limbing.
pub(crate) const fn mulhh_cols(n16: usize) -> usize {
    hh_cols(n16) * (2 + HH_BITS + HH_CARRY_BITS) + hh_p16(n16)
}
/// Offset (within a block) of the product's 16-bit limbs — what a consumer reads.
pub(crate) const fn mulhh_p16_off(n16: usize) -> usize {
    hh_cols(n16) * (2 + HH_BITS + HH_CARRY_BITS)
}
pub(crate) const fn hh_cout(n16: usize) -> usize {
    hh_cols(n16)
}
pub(crate) const fn hh_obits(n16: usize) -> usize {
    2 * hh_cols(n16)
}
pub(crate) const fn hh_cbits(n16: usize) -> usize {
    hh_obits(n16) + hh_cols(n16) * HH_BITS
}

/// An operand's 12-bit limbs from its 16-bit limbs — the native twin of the in-circuit linear read.
fn hh_operand_limbs(x16: &[u64]) -> Vec<u64> {
    let n16 = x16.len();
    (0..hh_limbs(n16))
        .map(|l| {
            let mut v = 0u64;
            for t in 0..HH_BITS {
                let b = l * HH_BITS + t;
                if b < 16 * n16 {
                    v |= ((x16[b / 16] >> (b % 16)) & 1) << t;
                }
            }
            v
        })
        .collect()
}

/// Native `a · b` as the block's honest cells: `(out limbs (12-bit), carries, P16 limbs)`.
pub(crate) fn hh_native(a16: &[u64], b16: &[u64]) -> (Vec<u64>, Vec<u64>, Vec<u64>) {
    let n16 = a16.len();
    debug_assert_eq!(n16, b16.len());
    let (a12, b12) = (hh_operand_limbs(a16), hh_operand_limbs(b16));
    let (l, nc) = (hh_limbs(n16), hh_cols(n16));
    let mut out = vec![0u64; nc];
    let mut cout = vec![0u64; nc];
    let mut cin = 0u64;
    for m in 0..nc {
        let mut col = cin;
        for j in 0..l {
            if m >= j && m - j < l {
                col += a12[m - j] * b12[j];
            }
        }
        out[m] = col & ((1 << HH_BITS) - 1);
        cin = col >> HH_BITS;
        cout[m] = cin;
    }
    let bit = |b: usize| -> u64 { if b / HH_BITS < nc { (out[b / HH_BITS] >> (b % HH_BITS)) & 1 } else { 0 } };
    let p16 = (0..hh_p16(n16)).map(|q| (0..16).map(|t| bit(16 * q + t) << t).sum()).collect();
    (out, cout, p16)
}

/// Lay a hidden-multiply block for two operands given as 16-bit limbs (their range bits are laid by their openings);
/// returns the product's 16-bit limbs. `None` when the product carries out of the top column — never for honest
/// operands of the declared width.
fn place_mulhh(cols: &mut [Vec<Fa4>], a16: &[u64], b16: &[u64], base: usize) -> Option<Vec<u64>> {
    let n16 = a16.len();
    let (out, cout, p16) = hh_native(a16, b16);
    let nc = hh_cols(n16);
    if cout[nc - 1] != 0 {
        return None;
    }
    let mut set = |c: usize, v: u64| {
        let f = Fa4::from_u64(v);
        for cell in cols[c].iter_mut() {
            *cell = f;
        }
    };
    for m in 0..nc {
        set(base + m, out[m]);
        set(base + hh_cout(n16) + m, cout[m]);
        for t in 0..HH_BITS {
            set(base + hh_obits(n16) + m * HH_BITS + t, (out[m] >> t) & 1);
        }
        for t in 0..HH_CARRY_BITS {
            set(base + hh_cbits(n16) + m * HH_CARRY_BITS + t, (cout[m] >> t) & 1);
        }
    }
    for (q, &v) in p16.iter().enumerate() {
        set(base + mulhh_p16_off(n16) + q, v);
    }
    Some(p16)
}

/// The hidden multiply's constraints: both operands read LINEARLY from their openings' range bits (`abits`, `bbits`:
/// `16·n16` boolean bit columns each, limb-major), the schoolbook columns as integer identities, out limbs and carries
/// range-bound, no carry out of the top column, the 16-bit re-limbing. Degree 2 in the columns.
// Generic over the row's field (2026-09-29, the DSOL relation's base-field round 0): the type parameter is NAMED `Ea4` so
// the gadget's body reads unchanged — every caller in this file instantiates it at the extension as before.
#[allow(non_camel_case_types)]
pub(crate) fn push_mulhh_constraints<Ea4: Field + p3_field::Algebra<Fa4>>(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_, Ea4>, abits: usize, bbits: usize, n16: usize, base: usize) {
    let two = Ea4::from(Fa4::from_u64(2));
    let two12 = Ea4::from(Fa4::from_u64(1 << HH_BITS));
    let (l, nc) = (hh_limbs(n16), hh_cols(n16));
    let limbs12 = |bits: usize| -> Vec<Ea4> {
        (0..l)
            .map(|i| {
                let mut v = Ea4::ZERO;
                let mut pw = Ea4::ONE;
                for t in 0..HH_BITS {
                    let b = i * HH_BITS + t;
                    if b < 16 * n16 {
                        v += local[bits + b] * pw;
                    }
                    pw *= two;
                }
                v
            })
            .collect()
    };
    let (a12, b12) = (limbs12(abits), limbs12(bbits));
    for m in 0..nc {
        let mut col = if m == 0 { Ea4::ZERO } else { local[base + hh_cout(n16) + m - 1] };
        for j in 0..l {
            if m >= j && m - j < l {
                col += a12[m - j] * b12[j];
            }
        }
        let out = local[base + m];
        let cout = local[base + hh_cout(n16) + m];
        cs.push(col - out - cout * two12);
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for t in 0..HH_BITS {
            let b = local[base + hh_obits(n16) + m * HH_BITS + t];
            cs.push(b * (b - Ea4::ONE));
            rec += b * pw;
            pw *= two;
        }
        cs.push(rec - out);
        let mut recc = Ea4::ZERO;
        let mut pwc = Ea4::ONE;
        for t in 0..HH_CARRY_BITS {
            let b = local[base + hh_cbits(n16) + m * HH_CARRY_BITS + t];
            cs.push(b * (b - Ea4::ONE));
            recc += b * pwc;
            pwc *= two;
        }
        cs.push(recc - cout);
    }
    cs.push(local[base + hh_cout(n16) + nc - 1]); // no carry out of the top column
    let p_bit = |b: usize| -> Ea4 { if b / HH_BITS < nc { local[base + hh_obits(n16) + (b / HH_BITS) * HH_BITS + (b % HH_BITS)] } else { Ea4::ZERO } };
    for q in 0..hh_p16(n16) {
        let mut v = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for t in 0..16 {
            v += p_bit(16 * q + t) * pw;
            pw *= two;
        }
        cs.push(v - local[base + mulhh_p16_off(n16) + q]);
    }
}

/// n-limb `x ≥ y` (16-bit limbs): the borrow chain with a range-bound slack, no borrow out of the top limb. The 17-limb
/// [`push_ge_constraints`] is this at `n = N_LIMB17`.
fn push_ge_n_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, x_base: usize, y_base: usize, slack_base: usize, borrow_base: usize, sbits_base: usize, n: usize) {
    let d: Vec<Ea4> = (0..n).map(|i| local[x_base + i] - local[y_base + i]).collect();
    push_ge_n_diff_constraints(cs, local, &d, slack_base, borrow_base, sbits_base);
}

/// n-limb `Σ d_i · 2^(16 i) ≥ 0` for per-limb DIFFERENCES given as expressions — each an integer in `[−2^16, 2^16)` for
/// every witness: a 16-bit limb minus a 16-bit limb, optionally less one at limb 0, optionally times a boolean selector.
/// It is [`push_ge_n_constraints`]'s borrow chain with `x_i − y_i` replaced by `d_i`; every per-limb equation stays an
/// INTEGER identity (all terms below 2^18 ≪ p), so the chain proves the integer inequality. A SELECTOR-GATED compare
/// passes `sel · (x_i − y_i)`: with the selector off every difference is 0 and a zero slack satisfies the block while it
/// asserts nothing; with it on the block is the plain compare. Degree 2 in the columns.
fn push_ge_n_diff_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, d: &[Ea4], slack_base: usize, borrow_base: usize, sbits_base: usize) {
    let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
    let two = Ea4::from(Fa4::from_u64(2));
    let n = d.len();
    for i in 0..n {
        let bin = if i == 0 { Ea4::ZERO } else { local[borrow_base + i - 1] };
        let bout = local[borrow_base + i];
        let si = local[slack_base + i];
        cs.push(d[i] - bin - si + bout * two16);
        cs.push(bout * (bout - Ea4::ONE));
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for j in 0..N_LIMB16 {
            let bit = local[sbits_base + i * N_LIMB16 + j];
            cs.push(bit * (bit - Ea4::ONE));
            rec += bit * pw;
            pw *= two;
        }
        cs.push(rec - si);
    }
    cs.push(local[borrow_base + n - 1]);
}

/// Lay an n-limb `x ≥ y` block; `false` (no witness) when `x < y`.
fn place_ge_n(cols: &mut [Vec<Fa4>], x: &[u64], y: &[u64], slack_base: usize, borrow_base: usize, sbits_base: usize) -> bool {
    debug_assert_eq!(x.len(), y.len());
    let d: Vec<i64> = x.iter().zip(y).map(|(&a, &b)| a as i64 - b as i64).collect();
    place_ge_n_diff(cols, &d, slack_base, borrow_base, sbits_base)
}

/// Lay the borrow chain over per-limb differences (the twin of [`push_ge_n_diff_constraints`]); `false` (no witness)
/// when the represented integer is negative.
fn place_ge_n_diff(cols: &mut [Vec<Fa4>], d: &[i64], slack_base: usize, borrow_base: usize, sbits_base: usize) -> bool {
    let n = d.len();
    let mut slack = vec![0u64; n];
    let mut borrow = vec![0u64; n];
    let mut bin = 0i64;
    for i in 0..n {
        let t = d[i] - bin;
        debug_assert!((-(1i64 << LIMB16_BITS)..(1i64 << LIMB16_BITS)).contains(&t), "a per-limb difference outside [−2^16, 2^16) has no borrow-chain witness");
        if t < 0 {
            slack[i] = (t + (1i64 << LIMB16_BITS)) as u64;
            bin = 1;
        } else {
            slack[i] = t as u64;
            bin = 0;
        }
        borrow[i] = bin as u64;
    }
    if bin != 0 {
        return false;
    }
    let mut set = |c: usize, v: u64| {
        let f = Fa4::from_u64(v);
        for cell in cols[c].iter_mut() {
            *cell = f;
        }
    };
    for i in 0..n {
        set(slack_base + i, slack[i]);
        set(borrow_base + i, borrow[i]);
        for j in 0..N_LIMB16 {
            set(sbits_base + i * N_LIMB16 + j, (slack[i] >> j) & 1);
        }
    }
    true
}

/// n-limb `a + b == s` with bit carries and no carry out of the top limb; `b` may be a PUBLIC constant laid as columns the
/// AIR pins (the amount carrier adds `k` to a product). [`push_conservation_constraints`] is this at `n = N_LIMB16`.
fn push_add_n_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: usize, b: usize, s: usize, carry: usize, n: usize) {
    let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
    for i in 0..n {
        let cin = if i == 0 { Ea4::ZERO } else { local[carry + i - 1] };
        let cout = local[carry + i];
        cs.push(local[a + i] + local[b + i] + cin - local[s + i] - cout * two16);
        cs.push(cout * (cout - Ea4::ONE));
    }
    cs.push(local[carry + n - 1]);
}

/// Lay an n-limb add's sum and carries; `None` on overflow.
fn place_add_n(cols: &mut [Vec<Fa4>], a: &[u64], b: &[u64], s_base: usize, carry_base: usize) -> Option<Vec<u64>> {
    let n = a.len();
    let mut s = vec![0u64; n];
    let mut cin = 0u64;
    for i in 0..n {
        let t = a[i] + b[i] + cin;
        s[i] = t & LIMB16_MASK;
        cin = t >> LIMB16_BITS;
        let f = Fa4::from_u64(s[i]);
        for cell in cols[s_base + i].iter_mut() {
            *cell = f;
        }
        let c = Fa4::from_u64(cin);
        for cell in cols[carry_base + i].iter_mut() {
            *cell = c;
        }
    }
    if cin != 0 {
        return None;
    }
    Some(s)
}

const S_A: usize = 0;
const S_P: usize = 16;
const S_CARRY: usize = 33;
const S_PBITS: usize = 49;
/// 17 result limbs, 16 bits each, is the scale AIR's bit-decomposition block; then the carry bounds, then the
/// input limbs' own range bind (the standalone scale has no opening to inherit canonical limbs from).
const S_CBITS: usize = S_PBITS + N_LIMB17 * N_LIMB16;
const S_ABITS: usize = S_CBITS + CARRY_BOUND_COLS;
const SCALE_WIDTH: usize = S_ABITS + RANGE16_COLS;

struct ScaleByConstAir {
    gamma: Ea4,
    k: u64,
}
impl AirConstraint for ScaleByConstAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        2 // the bit booleans are degree 2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        // ONE spelling of the scale relation (DB-362): the shared pusher, which binds the product limbs, the carries
        // (to the derived bound) and — for this standalone block, which inherits no canonical limbs from an opening —
        // the input limbs themselves.
        let mut cs: Vec<Ea4> = Vec::new();
        push_scale_constraints(&mut cs, local, S_A, S_P, S_CARRY, S_PBITS, S_CBITS, self.k);
        push_range16_constraints(&mut cs, local, S_A, S_ABITS, N_LIMB16);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Honest `p = a·k` limb-wise + its bit decomposition; `None` if it would exceed 17 limbs (never for k≤2^14).
fn scale_trace(a: U256, k: u64) -> Option<Vec<Vec<Fa4>>> {
    if !scale_k_admissible(k) {
        return None; // DB-362: a wider multiplier has no integer-identity witness
    }
    let al = u256_to_limbs16(a);
    let mut p = [0u64; 17];
    let mut carry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let prod = al[i] * k + cin;
        p[i] = prod & LIMB16_MASK;
        cin = prod >> LIMB16_BITS;
        carry[i] = cin;
    }
    p[16] = cin; // final carry into the top limb
    if p[16] > LIMB16_MASK {
        return None;
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; SCALE_WIDTH];
    let set = |c: usize, v: u64, cols: &mut Vec<Vec<Fa4>>| {
        let f = Fa4::from_u64(v);
        cols[c][0] = f;
        cols[c][1] = f;
    };
    for i in 0..N_LIMB16 {
        set(S_A + i, al[i], &mut cols);
        set(S_CARRY + i, carry[i], &mut cols);
    }
    for i in 0..=N_LIMB16 {
        set(S_P + i, p[i], &mut cols);
        for j in 0..N_LIMB16 {
            set(S_PBITS + i * N_LIMB16 + j, (p[i] >> j) & 1, &mut cols);
        }
    }
    if !place_carry_bound(&mut cols, &carry, S_CBITS) {
        return None;
    }
    place_range16(&mut cols, &al, S_ABITS);
    Some(cols)
}

/// PROVE `p = a·k` in-circuit (limb-wise, range-bound). `k` is the consensus-known scale constant (10000 or
/// the ratio bps). The node verifies over the committed limb columns; a forged result limb is rejected.
pub fn prove_scale(a: U256, k: u64, ch: &mut Chl) -> Option<AirZerocheckProof> {
    let cols = scale_trace(a, k)?;
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = ScaleByConstAir { gamma, k };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    Some(prove_air_zerocheck(&cols, &air, &z, ch))
}

/// VERIFY a scale proof (node-side, witness-free). Fail-closed on a tampered trace.
#[must_use]
pub fn verify_scale(proof: &AirZerocheckProof, k: u64, ch: &mut Chl) -> bool {
    if !scale_k_admissible(k) {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = ScaleByConstAir { gamma, k };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    verify_air_zerocheck(proof, &air, &z, ch)
}

// ── #75 brick 2b-ii — IN-CIRCUIT COMPARE `X ≥ Y` (backing/solvency), limb-wise ───────────────────────
//
// Backing (`deposit·10000 ≥ mint·ratio`) and solvency (`new_res·10000 ≥ new_mint·ratio`) each reduce to
// `X ≥ Y` on the SCALED values (17-bit-limb outputs of the scale AIR). Proven LIMB-WISE as a subtract with
// borrows: `X − Y = slack`, each slack limb RANGE-BOUND to 16 bits (forces the borrow) and the TOP borrow
// == 0 (a borrow out of the top limb means `X < Y` ⇒ reject, fail-closed). slack ≥ 0 by construction.
// Column layout (width 340): X[0..17] | Y[17..34] | slack[34..51] | borrow[51..68] | slack_bits[68..340].

/// Scaled-value width: a `U256` × a ≤2^14 constant needs 17 16-bit limbs.
pub const N_LIMB17: usize = 17;
const G_X: usize = 0;
const G_Y: usize = N_LIMB17;
const G_SLACK: usize = 2 * N_LIMB17;
const G_BORROW: usize = 3 * N_LIMB17;
const G_SBITS: usize = 4 * N_LIMB17;
const GE_WIDTH: usize = G_SBITS + N_LIMB17 * N_LIMB16;

/// Native `a·k` as 17 little-endian 16-bit limbs (the scale AIR's honest output, for the compare's inputs).
fn scale_native(a: U256, k: u64) -> [u64; N_LIMB17] {
    let al = u256_to_limbs16(a);
    let mut p = [0u64; N_LIMB17];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let prod = al[i] * k + cin;
        p[i] = prod & LIMB16_MASK;
        cin = prod >> LIMB16_BITS;
    }
    p[16] = cin;
    p
}

struct CompareGeLimbAir {
    gamma: Ea4,
}
impl AirConstraint for CompareGeLimbAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        2
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
        let two = Ea4::from(Fa4::from_u64(2));
        let mut cs: Vec<Ea4> = Vec::new();
        for i in 0..N_LIMB17 {
            let bin = if i == 0 { Ea4::ZERO } else { local[G_BORROW + i - 1] };
            let bout = local[G_BORROW + i];
            let xi = local[G_X + i];
            let yi = local[G_Y + i];
            let si = local[G_SLACK + i];
            // subtract relation: X_i − Y_i − bin − slack_i + bout·2^16 == 0
            cs.push(xi - yi - bin - si + bout * two16);
            // borrow boolean
            cs.push(bout * (bout - Ea4::ONE));
            // slack_i range bind (forces the borrow + guarantees slack ≥ 0)
            let mut rec = Ea4::ZERO;
            let mut pw = Ea4::ONE;
            for j in 0..N_LIMB16 {
                let bit = local[G_SBITS + i * N_LIMB16 + j];
                cs.push(bit * (bit - Ea4::ONE));
                rec += bit * pw;
                pw *= two;
            }
            cs.push(rec - si);
        }
        // top borrow == 0  ⟺  X ≥ Y (no borrow out of the most-significant limb)
        cs.push(local[G_BORROW + N_LIMB17 - 1]);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Honest `X − Y = slack` (17-limb) with borrows; `None` if `X < Y` (a top borrow ⇒ can't prove `X ≥ Y`).
fn ge_trace(x: [u64; N_LIMB17], y: [u64; N_LIMB17]) -> Option<Vec<Vec<Fa4>>> {
    let mut slack = [0u64; N_LIMB17];
    let mut borrow = [0u64; N_LIMB17];
    let mut bin = 0i64;
    for i in 0..N_LIMB17 {
        let d = x[i] as i64 - y[i] as i64 - bin;
        if d < 0 {
            slack[i] = (d + (1i64 << LIMB16_BITS)) as u64;
            bin = 1;
        } else {
            slack[i] = d as u64;
            bin = 0;
        }
        borrow[i] = bin as u64;
    }
    if bin != 0 {
        return None; // X < Y
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; GE_WIDTH];
    let set = |c: usize, v: u64, cols: &mut Vec<Vec<Fa4>>| {
        let f = Fa4::from_u64(v);
        cols[c][0] = f;
        cols[c][1] = f;
    };
    for i in 0..N_LIMB17 {
        set(G_X + i, x[i], &mut cols);
        set(G_Y + i, y[i], &mut cols);
        set(G_SLACK + i, slack[i], &mut cols);
        set(G_BORROW + i, borrow[i], &mut cols);
        for j in 0..N_LIMB16 {
            set(G_SBITS + i * N_LIMB16 + j, (slack[i] >> j) & 1, &mut cols);
        }
    }
    Some(cols)
}

/// PROVE `X ≥ Y` in-circuit (both are scaled 17-limb values). `None` if `X < Y` (backing/solvency violated —
/// no proof exists, fail-closed). The node verifies over the committed limb columns.
pub fn prove_ge(x: [u64; N_LIMB17], y: [u64; N_LIMB17], ch: &mut Chl) -> Option<AirZerocheckProof> {
    let cols = ge_trace(x, y)?;
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = CompareGeLimbAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    Some(prove_air_zerocheck(&cols, &air, &z, ch))
}

/// VERIFY a `X ≥ Y` proof (node-side, witness-free). Fail-closed on a tampered trace.
#[must_use]
pub fn verify_ge(proof: &AirZerocheckProof, ch: &mut Chl) -> bool {
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = CompareGeLimbAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    verify_air_zerocheck(proof, &air, &z, ch)
}

// ── #75 brick 2b-ii-c — the COMPOSED confidential solvency-transition proof ───────────────────────────
//
// A peg-in transition, proven ENTIRELY in-circuit over HIDDEN 256-bit values, is the γ-bundle of the three
// proven primitives: 2 conservation adds (new totals) + 2 scales (deposit·10000, mint·ratio) + 1 compare
// (backing) + 2 scales (new_res·10000, new_mint·ratio) + 1 compare (solvency). The node verifies each; a
// tamper in ANY breaks that sub-proof. The CROSS-proof binding (the same hidden `deposit` feeds both its
// conservation add AND its scale) is enforced when brick 3 opens the value columns against the shared
// poseidon `solvency_commit` (WHIR PCS) — the last wiring step. One `Chl` transcript threads all 8 sub-proofs.

/// The full peg-in solvency-transition proof: 8 limb-wise zerocheck sub-proofs, verified by the node without
/// the witness. `derive(Clone)` so a caller can bundle/serialize it.
#[derive(Clone)]
pub struct SolvencyTransitionProof {
    pub cons_reserve: AirZerocheckProof,  // reserve + deposit == new_reserve   (no hidden issuance)
    pub cons_minted: AirZerocheckProof,   // minted + mint == new_minted
    pub scale_dep: AirZerocheckProof,     // deposit · 10000
    pub scale_mint: AirZerocheckProof,    // mint · ratio
    pub backing: AirZerocheckProof,       // deposit·10000 ≥ mint·ratio          (per-event 150% backing)
    pub scale_newres: AirZerocheckProof,  // new_reserve · 10000
    pub scale_newmint: AirZerocheckProof, // new_minted · ratio
    pub solvency: AirZerocheckProof,      // new_res·10000 ≥ new_mint·ratio       (global solvency preserved)
}

/// PROVE a confidential peg-in solvency transition over the HIDDEN `(reserve, minted, deposit, mint)`.
/// `None` if it would overflow 256 bits or is under-collateralized (over-mint) — fail-closed, no proof.
pub fn prove_solvency_transition(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint: U256,
    ratio_bps: u32,
    ch: &mut Chl,
) -> Option<SolvencyTransitionProof> {
    let new_reserve = add256(reserve, deposit)?;
    let new_minted = add256(minted, mint)?;
    let (k10, kr) = (BPS_DEN as u64, ratio_bps as u64);
    let (x_dep, y_mint) = (scale_native(deposit, k10), scale_native(mint, kr));
    let (x_nr, y_nm) = (scale_native(new_reserve, k10), scale_native(new_minted, kr));
    Some(SolvencyTransitionProof {
        cons_reserve: prove_conservation(reserve, deposit, new_reserve, ch)?,
        cons_minted: prove_conservation(minted, mint, new_minted, ch)?,
        scale_dep: prove_scale(deposit, k10, ch)?,
        scale_mint: prove_scale(mint, kr, ch)?,
        backing: prove_ge(x_dep, y_mint, ch)?, // None ⇒ under-collateralized ⇒ whole transition unprovable
        scale_newres: prove_scale(new_reserve, k10, ch)?,
        scale_newmint: prove_scale(new_minted, kr, ch)?,
        solvency: prove_ge(x_nr, y_nm, ch)?,
    })
}

/// VERIFY the composed transition (node-side, witness-free): every sub-proof must verify against the SAME
/// threaded transcript. Fail-closed — a tamper in any sub-proof fails the whole transition.
#[must_use]
pub fn verify_solvency_transition(p: &SolvencyTransitionProof, ratio_bps: u32, ch: &mut Chl) -> bool {
    if !scale_k_admissible(u64::from(ratio_bps)) {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let (k10, kr) = (BPS_DEN as u64, ratio_bps as u64);
    verify_conservation(&p.cons_reserve, ch)
        && verify_conservation(&p.cons_minted, ch)
        && verify_scale(&p.scale_dep, k10, ch)
        && verify_scale(&p.scale_mint, kr, ch)
        && verify_ge(&p.backing, ch)
        && verify_scale(&p.scale_newres, k10, ch)
        && verify_scale(&p.scale_newmint, kr, ch)
        && verify_ge(&p.solvency, ch)
}

/// Reconstruct the Fiat-Shamir challenger from `seed`. In the WIRED peg, `seed` is derived from the block /
/// committed-state transcript (so the proof binds to the committed reserve/minted state) — this convenience
/// lets the node verify with a single seed instead of threading a `Chl`.
pub fn challenger_from_seed(seed: u64) -> Chl {
    use rand::rngs::SmallRng;
    use rand::SeedableRng;
    let mut rng = SmallRng::seed_from_u64(seed);
    Chl::new(crate::hiding_decider::Perm16::new_from_rng_128(&mut rng))
}

/// PROVE a peg-in solvency transition with a seeded transcript (the wallet / custodian-threshold side, which
/// holds the openings). `None` if it would overflow 256 bits or is under-collateralized (fail-closed).
pub fn prove_solvency_transition_seeded(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint: U256,
    ratio_bps: u32,
    seed: u64,
) -> Option<SolvencyTransitionProof> {
    let mut ch = challenger_from_seed(seed);
    prove_solvency_transition(reserve, minted, deposit, mint, ratio_bps, &mut ch)
}

/// VERIFY a peg-in solvency transition with a seeded transcript — the NODE entry: it VERIFIES the confidential
/// transition and NEVER recomputes (or learns) any total. Fail-closed on a tampered/invalid proof.
#[must_use]
pub fn verify_solvency_transition_seeded(p: &SolvencyTransitionProof, ratio_bps: u32, seed: u64) -> bool {
    let mut ch = challenger_from_seed(seed);
    verify_solvency_transition(p, ratio_bps, &mut ch)
}

// ── #75 brick 3b — the COMMITMENT-OPENING binding: prove `commit == solvency_commit_256(value, blind)` ──
//
// The sound linchpin that ties the transition's HIDDEN reserve/minted VALUE columns to the peg's PERSISTED
// `reserve_commit`/`minted_commit`. Reuses the decider's EXACT `poseidon_pair` (one round `out = MDS·(l+7r)⁷`,
// the SAME hash the note-commitment + nullifier tree use — full strength) as an in-circuit opening: 4 poseidon
// blocks fold the value's 16 limbs → h1,h2 → h3 → (h3,blind) → commit. Per block the intermediates
// `pre = l+7r`, `sq = pre²`, `p4 = sq²`, `pre7 = p4·sq·pre` are witnessed so every constraint is ≤ degree 3.
// A prover cannot open a DIFFERENT value to the same commitment (Poseidon collision-resistance), so a
// transition proven over hidden values is provably ABOUT the committed totals.

// ⛔ `CS_MDS` and `co_block_io` DELETED 2026-09-12: they described the retired 1-round fold's
// 4-block commitment shape. The opening is two permutation blocks now (kill list §AG).
// ⛔ `KB_P`, `kmul`, `kadd`, `kred` DELETED 2026-09-29: the native fold they served left with `co_block_io`; every
// native twin now goes through `solvency_commit_256` (→ `poseidon_pair`), so a second field-arithmetic spelling is gone.

/// One native poseidon block (mirror of `poseidon_pair`): returns `(pre, sq, p4, pre7, out)`, out == the hash.
/// ⛔ REMOVED 2026-09-12: this was a THIRD hand-written copy of the 1-round fold
/// `out = MDS·(l + 7·r)⁷` (kill list §AG), used to build the commit-opening witness. It inverted, so the
/// peg's reserve/minted commitments were openable to a value nobody committed. The witness is now a whole
/// Poseidon2 permutation laid by `pow_pq_air::lay_perm_row_flat`, and the value is
/// `poseidon2_compress::compress` — ONE compression in the tree, no copies.

const CO_V: usize = 0;
const CO_BLIND: usize = N_LIMB16;
const CO_COMMIT: usize = CO_BLIND + DIGEST_LANES;
const CO_B: usize = CO_COMMIT + DIGEST_LANES; // the first permutation block starts after the commitment
/// One compression's witness: a whole permutation, then the digest it produced.
pub(crate) const CO_BLOCK: usize = crate::pow_pq_air::P2_COLS + DIGEST_LANES;
const CO_VBITS: usize = CO_B + 2 * CO_BLOCK;
const CO_WIDTH: usize = CO_VBITS + RANGE16_COLS;


struct CommitOpenAir {
    gamma: Ea4,
}
impl AirConstraint for CommitOpenAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment opening). A gate that declares less
        // than the permutation's degree truncates the sumcheck and even an HONEST proof fails.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        // ⛔ WAS FOUR HAND-ROLLED 1-ROUND BLOCKS. That round inverts (kill list §AG), so the peg's
        // reserve/minted commitments could be OPENED to a value nobody committed — the stablecoin's
        // supply invariant resting on a function an attacker can walk backwards.
        let mut cs: Vec<Ea4> = Vec::new();
        push_commit_open_constraints(&mut cs, local, CO_V, CO_BLIND, CO_COMMIT, CO_B, CO_VBITS);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Build the commit-opening trace for `value` under `blind` (all intermediates honest). The commitment placed in
/// the trace is exactly [`solvency_commit_256`], so `verify_commit_open` binds the value columns to it.
fn commit_open_trace(value: U256, blind: Digest) -> Vec<Vec<Fa4>> {
    let l = u256_to_limbs16(value);
    let lo: Digest = core::array::from_fn(|i| l[i]);
    let hi: Digest = core::array::from_fn(|i| l[DIGEST_LANES + i]);
    let h1 = poseidon_pair(lo, hi);
    let cm = poseidon_pair(h1, blind);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; CO_WIDTH];
    // The trace is two identical rows: the gate is row-local, and a height-1 layout has no variables to
    // bind. Both rows carry the same witness.
    let set = |c: usize, val: u64, cols: &mut Vec<Vec<Fa4>>| {
        let f = Fa4::from_u64(val);
        cols[c][0] = f;
        cols[c][1] = f;
    };
    for i in 0..N_LIMB16 {
        set(CO_V + i, l[i], &mut cols);
    }
    place_range16(&mut cols, &l, CO_VBITS);
    for i in 0..DIGEST_LANES {
        set(CO_BLIND + i, blind[i], &mut cols);
        set(CO_COMMIT + i, cm[i], &mut cols); // = solvency_commit_256(value, blind)
    }
    for (b, (left, right, out)) in [(lo, hi, h1), (h1, blind, cm)].iter().enumerate() {
        let base = CO_B + b * CO_BLOCK;
        let mut row0 = vec![Fa4::ZERO; crate::pow_pq_air::P2_COLS];
        crate::pow_pq_air::lay_perm_row_flat(&mut row0, 0, crate::pow_pq_air::pair_state(left, right));
        for (k, &cell) in row0.iter().enumerate() {
            cols[base + k][0] = cell;
            cols[base + k][1] = cell;
        }
        for c in 0..DIGEST_LANES {
            set(base + crate::pow_pq_air::P2_COLS + c, out[c], &mut cols);
        }
    }
    cols
}

/// PROVE `commit == solvency_commit_256(value, blind)` in-circuit — the value→commitment opening. The verifier
/// checks it over the committed columns (the value stays HIDDEN); a prover cannot open a different value.
pub fn prove_commit_open(value: U256, blind: Digest, ch: &mut Chl) -> AirZerocheckProof {
    let cols = commit_open_trace(value, blind);
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = CommitOpenAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    prove_air_zerocheck(&cols, &air, &z, ch)
}

/// VERIFY a commit-opening proof (witness-free). Fail-closed on a value that does not fold to the commitment.
#[must_use]
pub fn verify_commit_open(proof: &AirZerocheckProof, ch: &mut Chl) -> bool {
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = CommitOpenAir { gamma };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    verify_air_zerocheck(proof, &air, &z, ch)
}

// ── #75 brick 3b — the BOUND transition: conservation + commitment openings over SHARED value columns ──
//
// The soundness composition. A separate conservation proof + separate commit-open proof do NOT bind (a prover
// could use different `reserve` in each). Putting BOTH constraint sets over ONE trace where `reserve`/
// `new_reserve` appear ONCE makes the same HIDDEN value serve conservation AND its commitment opening — so the
// proven no-hidden-issuance transition is provably ABOUT the peg's persisted commitments. Reuses the exact
// conservation + poseidon-fold constraint logic (as helpers) — no re-derivation. 100% private: the trace holds
// only hidden values; the node verifies against the persisted commitments and learns no total.

/// The 16-limb conservation constraints `a + b == s` (carry ∈ {0,1}, top carry 0), pushed onto `cs`.
fn push_conservation_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: usize, b: usize, s: usize, carry: usize) {
    let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
    for i in 0..N_LIMB16 {
        let cin = if i == 0 { Ea4::ZERO } else { local[carry + i - 1] };
        let cout = local[carry + i];
        cs.push(local[a + i] + local[b + i] + cin - local[s + i] - cout * two16);
        cs.push(cout * (cout - Ea4::ONE));
    }
    cs.push(local[carry + N_LIMB16 - 1]); // no carry out of the top limb (fail-closed on >2^256)
}

/// The poseidon-fold opening constraints `commit == solvency_commit_256(value@v, blind@blind)`, pushed onto
/// `cs`. `inter` is an 80-column intermediate block (4 poseidon rounds × pre/sq/p4/pre7/out).
pub(crate) fn push_commit_open_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, v: usize, blind: usize, commit: usize, inter: usize, vbits: usize) {
    // DB-362: the 16 limbs this opening binds are CANONICAL 16-bit integers — the premise every arithmetic consumer
    // (conservation, scale) needs for its limb equations to be integer identities, established where the value is
    // produced, not where it is read.
    push_range16_constraints(cs, local, v, vbits, N_LIMB16);
    let out_of = |bi: usize| inter + bi * CO_BLOCK + crate::pow_pq_air::P2_COLS;
    for b in 0..2 {
        let base = inter + b * CO_BLOCK;
        crate::pow_pq_air::push_perm_residuals(local, base, cs);
        for c in 0..DIGEST_LANES {
            // Block 0 folds the value's two limb halves; block 1 folds that against the blind.
            let (lc, rc) = if b == 0 { (v + c, v + DIGEST_LANES + c) } else { (out_of(0) + c, blind + c) };
            cs.push(local[base + c] - local[lc]);
            cs.push(local[base + DIGEST_LANES + c] - local[rc]);
            cs.push(local[out_of(b) + c] - local[base + crate::pow_pq_air::PERM_OUT + c]);
        }
    }
    for c in 0..DIGEST_LANES {
        cs.push(local[commit + c] - local[out_of(1) + c]);
    }
}

// Shared layout: reserve[0..16] deposit[16..32] new_reserve[32..48] carry[48..64] r_blind[64..68]
// nr_blind[68..72] reserve_commit[72..76] new_reserve_commit[76..80] r_inter[80..160] nr_inter[160..240].
const BR_RES: usize = 0;
const BR_DEP: usize = 16;
const BR_NEW: usize = 32;
const BR_CARRY: usize = 48;
const BR_RBLIND: usize = 64;
const BR_NBLIND: usize = BR_RBLIND + DIGEST_LANES;
const BR_RCOMMIT: usize = BR_NBLIND + DIGEST_LANES;
const BR_NCOMMIT: usize = BR_RCOMMIT + DIGEST_LANES;
/// Each opening now spans TWO permutation blocks (16 limbs are exactly two digests at 8 lanes), where it
/// spanned four 20-column 1-round blocks before.
const BR_OPEN: usize = 2 * CO_BLOCK;
const BR_RINTER: usize = BR_NCOMMIT + DIGEST_LANES;
const BR_NINTER: usize = BR_RINTER + BR_OPEN;
const BR_RVBITS: usize = BR_NINTER + BR_OPEN;
const BR_NVBITS: usize = BR_RVBITS + RANGE16_COLS;
const BR_WIDTH: usize = BR_NVBITS + RANGE16_COLS;

// ⛔ `BoundReserveAir` / `prove_bound_reserve` / `verify_bound_reserve` DELETED 2026-09-29: the shape's deposit
// (`BR_DEP`) was a free witness (no range bits, no commitment), so its "conservation" bound two openings and nothing
// about their relation; it had no caller outside its own tests. The delta-bound `prove_transition_carrier` is the
// conservation carrier. The `BR_` layout and `bound_reserve_trace` stay only for the deprecated bond carrier below.

/// Native intermediates for one commit-open fold placed at `inter` in the trace (mirrors `commit_open_trace`).
pub(crate) fn place_commit_open(cols: &mut Vec<Vec<Fa4>>, limbs: [u64; N_LIMB16], blind: Digest, inter: usize, vbits: usize) -> Digest {
    place_range16(cols, &limbs, vbits);
    let lo: Digest = core::array::from_fn(|i| limbs[i]);
    let hi: Digest = core::array::from_fn(|i| limbs[DIGEST_LANES + i]);
    let h1 = poseidon_pair(lo, hi);
    let cm = poseidon_pair(h1, blind);
    for (b, (left, right, out)) in [(lo, hi, h1), (h1, blind, cm)].iter().enumerate() {
        let base = inter + b * CO_BLOCK;
        let mut blk = vec![Fa4::ZERO; crate::pow_pq_air::P2_COLS];
        crate::pow_pq_air::lay_perm_row_flat(&mut blk, 0, crate::pow_pq_air::pair_state(left, right));
        // The gate is row-local, so every row of the (fixed, 2-row) trace carries the same witness —
        // `fill` states that directly rather than walking a range.
        for (k, &cell) in blk.iter().enumerate() {
            cols[base + k].fill(cell);
        }
        for c in 0..DIGEST_LANES {
            cols[base + crate::pow_pq_air::P2_COLS + c].fill(Fa4::from_u64(out[c]));
        }
    }
    cm
}

/// Build the bound-reserve trace: `reserve + deposit == new_reserve` with the reserve + new_reserve commitment
/// openings, all over shared columns. `None` on 256-bit overflow.
fn bound_reserve_trace(reserve: U256, deposit: U256, r_blind: Digest, nr_blind: Digest) -> Option<(Vec<Vec<Fa4>>, Digest, Digest)> {
    let new_reserve = add256(reserve, deposit)?;
    let (rl, dl, nl) = (u256_to_limbs16(reserve), u256_to_limbs16(deposit), u256_to_limbs16(new_reserve));
    let mut carry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let s = rl[i] + dl[i] + cin;
        cin = s >> LIMB16_BITS;
        carry[i] = cin;
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; BR_WIDTH];
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..N_LIMB16 {
            set(BR_RES + i, rl[i]);
            set(BR_DEP + i, dl[i]);
            set(BR_NEW + i, nl[i]);
            set(BR_CARRY + i, carry[i]);
        }
        for i in 0..DIGEST_LANES {
            set(BR_RBLIND + i, r_blind[i]);
            set(BR_NBLIND + i, nr_blind[i]);
        }
    }
    let rc = place_commit_open(&mut cols, rl, r_blind, BR_RINTER, BR_RVBITS);
    let nrc = place_commit_open(&mut cols, nl, nr_blind, BR_NINTER, BR_NVBITS);
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..DIGEST_LANES {
            set(BR_RCOMMIT + i, rc[i]);
            set(BR_NCOMMIT + i, nrc[i]);
        }
    }
    Some((cols, rc, nrc))
}

// ── #75 brick 3c — the FULL BOUND transition: conservation + 4 openings + 150% backing, ONE shared trace ──
//
// The keystone. Everything the peg-in must satisfy, proven over ONE trace whose reserve/minted/new_reserve/
// new_minted columns are SHARED across every constraint set:
//   • reserve + deposit == new_reserve   AND   minted + mint == new_minted     (no hidden issuance)
//   • reserve→reserve_commit, minted→minted_commit, new_reserve→…, new_minted→… (bound to the persisted state)
//   • new_reserve·BPS_DEN ≥ new_minted·ratio_bps                                (the NEW total is ≥150% backed)
// Because the SAME hidden new_minted proves conservation, its opening, AND the backing GE, a prover cannot use
// one value to satisfy backing and a different one to open the commitment — the whole transition is sound about
// the commitments the node persists. 100% private: the node sees only the four commitments + this one proof and
// learns no reserve, no minted total, no deposit, no mint — no supply, no volume.

/// Scale constraints `p == a·k` (17-limb, range-bound) over shared columns, pushed onto `cs`.
fn push_scale_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a_base: usize, p_base: usize, carry_base: usize, pbits_base: usize, cbits_base: usize, k: u64) {
    debug_assert!(scale_k_admissible(k), "a scale block was built for a multiplier past SCALE_K_MAX — the prove/verify doors refuse it first");
    // DB-362: the carries are bound to the derived maximum, so every limb equation below is an INTEGER identity
    push_carry_bound_constraints(cs, local, carry_base, cbits_base);
    let two16 = Ea4::from(Fa4::from_u64(1 << LIMB16_BITS));
    let two = Ea4::from(Fa4::from_u64(2));
    let kk = Ea4::from(Fa4::from_u64(k));
    for i in 0..=N_LIMB16 {
        let cin = if i == 0 { Ea4::ZERO } else { local[carry_base + i - 1] };
        let ak = if i < N_LIMB16 { local[a_base + i] * kk } else { Ea4::ZERO };
        let cout = if i < N_LIMB16 { local[carry_base + i] } else { Ea4::ZERO };
        let p_i = local[p_base + i];
        cs.push(ak + cin - p_i - cout * two16);
        let mut rec = Ea4::ZERO;
        let mut pw = Ea4::ONE;
        for j in 0..N_LIMB16 {
            let bit = local[pbits_base + i * N_LIMB16 + j];
            cs.push(bit * (bit - Ea4::ONE));
            rec += bit * pw;
            pw *= two;
        }
        cs.push(rec - p_i);
    }
}

/// GE constraints `x ≥ y` (17-limb subtract with borrows, slack range-bound, top borrow 0) over shared columns.
fn push_ge_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, x_base: usize, y_base: usize, slack_base: usize, borrow_base: usize, sbits_base: usize) {
    // ONE spelling: the n-limb compare at the scale block's 17 limbs
    push_ge_n_constraints(cs, local, x_base, y_base, slack_base, borrow_base, sbits_base, N_LIMB17);
}

// Full shared layout (width 1396). Value columns are shared across conservation + opening + backing.
const T_RES: usize = 0; // reserve total[0..16]
const T_MINT: usize = 16; // minted total[16..32]
const T_DEP: usize = 32; // deposit[32..48]
const T_MDELTA: usize = 48; // mint delta[48..64]
const T_NEWRES: usize = 64; // new_reserve[64..80]
const T_NEWMINT: usize = 80; // new_minted[80..96]
const T_RESCARRY: usize = 96; // reserve+deposit carry[96..112]
const T_MINTCARRY: usize = 112; // minted+delta carry[112..128]
const T_RBLIND: usize = 128;
const T_MBLIND: usize = T_RBLIND + DIGEST_LANES;
const T_NRBLIND: usize = T_MBLIND + DIGEST_LANES;
const T_NMBLIND: usize = T_NRBLIND + DIGEST_LANES;
const T_RCOMMIT: usize = T_NMBLIND + DIGEST_LANES;
const T_MCOMMIT: usize = T_RCOMMIT + DIGEST_LANES;
const T_NRCOMMIT: usize = T_MCOMMIT + DIGEST_LANES;
const T_NMCOMMIT: usize = T_NRCOMMIT + DIGEST_LANES;
/// One value's commitment opening: two permutation blocks, each with its output digest.
const T_OPEN: usize = 2 * CO_BLOCK;
const T_RINTER: usize = T_NMCOMMIT + DIGEST_LANES;
const T_MINTER: usize = T_RINTER + T_OPEN;
const T_NRINTER: usize = T_MINTER + T_OPEN;
const T_NMINTER: usize = T_NRINTER + T_OPEN;
// DB-362: every opened value's 16 limbs range-bound (canonical), then the two scale blocks with bounded carries
const T_RVBITS: usize = T_NMINTER + T_OPEN;
const T_MVBITS: usize = T_RVBITS + RANGE16_COLS;
const T_NRVBITS: usize = T_MVBITS + RANGE16_COLS;
const T_NMVBITS: usize = T_NRVBITS + RANGE16_COLS;
// ⭐ DB-124 (lane funds 2026-10-29): the backing is PRICED — two wide-multiply blocks (`place_mul14`, the liquidation
// carrier's gadget) read the reserve's and the minted total's range bits linearly: reserve × BPS × price on one side,
// minted × ratio × PRICE_SCALE on the other, then the 23-limb compare.
const T_MR: usize = T_NMVBITS + RANGE16_COLS; // the reserve side's wide product
const T_MM: usize = T_MR + MUL14_COLS; // the minted side's wide product
/// ⛔ These were LITERALS (1090/1107/1124/1396) computed by hand against the 4-lane layout. Every one of
/// them moved when the digest widened, and a stale width silently overlaps the block after it.
const T_GE_SLACK: usize = T_MM + MUL14_COLS;
const T_GE_BORROW: usize = T_GE_SLACK + M14_P16_LIMBS;
const T_GE_SBITS: usize = T_GE_BORROW + M14_P16_LIMBS;
/// ⛔⛔ DB-470: the two DELTAS' range bits. Conservation alone (`a + d + cin == s + cout·2^16`, boolean carries, canonical `a`
/// and `s`) leaves each delta limb anywhere in `[−2^16, 2^17)`: a NEGATIVE deposit (a reserve drain while minting) or a
/// NEGATIVE burn (supply growing through a peg-out) satisfied it. Range-bound here, every delta is a canonical 256-bit
/// integer ≥ 0 — and the per-transaction gates read their operands from these bits.
const T_DEPVBITS: usize = T_GE_SBITS + M14_P16_LIMBS * N_LIMB16;
const T_MDVBITS: usize = T_DEPVBITS + RANGE16_COLS;
const T_WIDTH: usize = T_MDVBITS + RANGE16_COLS;
// DB-470 — the peg-out's PRO-RATA block, appended after the shared width (only the peg-out trace is this wide):
// burn × current reserve and release × current minted (hidden × hidden), then the compare.
const TO_HR: usize = T_WIDTH;
const TO_HM: usize = TO_HR + mulhh_cols(N_LIMB16);
const TO_SLACK: usize = TO_HM + mulhh_cols(N_LIMB16);
const TO_BORROW: usize = TO_SLACK + hh_p16(N_LIMB16);
const TO_SBITS: usize = TO_BORROW + hh_p16(N_LIMB16);
const TO_WIDTH: usize = TO_SBITS + hh_p16(N_LIMB16) * N_LIMB16;

/// ⭐⭐ DB-470 (lane funds 2026-10-29) — WHICH PER-TRANSACTION RULE a `T_` transition proves. The no-inflation guarantee is a
/// property of EVERY TRANSACTION, never of the system's aggregate ratio: the aggregate moves with the deposit asset's price
/// with no exploit at all, so a gate on it refused legitimate money in a price drop (every cash-out under the floor, every
/// mint while the system sat under 150 %) while admitting exploits in a boom (a zero-deposit mint against the surplus, a
/// one-USDm burn releasing the surplus).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionGate {
    /// The POST state is backed at the ratio: the bond backstop's rule (the plain carrier) — a solvency statement about a
    /// state, not a door for money.
    Aggregate,
    /// A MINT: its own deposit backs its own mint, `deposit × BPS × price ≥ mint × ratio × LIQ_PRICE_SCALE`. Every new USDm is
    /// born backed by fresh collateral; no mint draws on the surplus; no mint is refused for the system's ratio.
    Marginal,
    /// A REDEMPTION: the release is worth at most the burn at the floor (`burn × floor × SCALE ≥ release × BPS × price`, $1 of
    /// reserve per USDm at a 100 % floor) AND at most the burn's pro-rata share of the reserve (`burn × R ≥ release × M` over the
    /// current hidden totals — slack while solvent, binding only under 100 %, where it keeps every later holder's share whole).
    /// No cash-out of genuine USDm is ever refused for the system's ratio.
    Redeem,
}
const BPS_DEN_U64: u64 = 10_000;

/// ⭐⭐ DB-124 (lane funds 2026-10-29) — THE PRICED BACKING RULE every bound transition proves:
/// `reserve × BPS × price ≥ minted × ratio × LIQ_PRICE_SCALE`, i.e. the reserve's VALUE (deposit atomic units × the chain's
/// price word, USDm atomic per unit × `LIQ_PRICE_SCALE`) backs the minted total at `ratio`. MEASURED why: the old gate scaled
/// the RAW reserve (sats, piconero) by `BPS` and the minted total by `ratio` with no price — every test priced one sat at
/// one USDm atomic, so it passed, while at $60,000 a whole Bitcoin proved a mint of ≈ 0.67 USDm (every real Bitcoin mint
/// unprovable) and a Monero reserve's piconero count passed any mint (the custodians' priced coverage was the only gate).
/// Both multipliers ride the wide multiply's seven 14-bit chunks (< 2^98): any price the protocol can quote fits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backing {
    pub ratio_bps: u64,
    /// The price word the transition is proven at (USDm atomic per deposit atomic unit × `LIQ_PRICE_SCALE`).
    pub price: u128,
}

impl Backing {
    /// The backing at a price of one USDm atomic per deposit atomic unit — the convention every pre-DB-124 fixture used.
    #[must_use]
    pub fn at_unit_price(ratio_bps: u64) -> Self {
        Backing { ratio_bps, price: u128::from(LIQ_PRICE_SCALE) }
    }

    /// The two public multipliers `(k_reserve, k_minted)`, or `None` when the rule cannot form (a zero ratio or price, or a
    /// multiplier past the wide block) — refused at prove AND verify.
    #[must_use]
    pub fn ks(&self) -> Option<(u128, u128)> {
        if self.ratio_bps == 0 || self.price == 0 {
            return None;
        }
        let kr = u128::from(BPS_DEN_U64).checked_mul(self.price)?;
        let km = u128::from(self.ratio_bps).checked_mul(u128::from(LIQ_PRICE_SCALE))?;
        (mul14_k_admissible(kr) && mul14_k_admissible(km)).then_some((kr, km))
    }
}

/// Where a gate lays its backing: the two wide products and the compare's slack, borrows and slack bits.
#[derive(Clone, Copy)]
struct BackingAt {
    mr: usize,
    mm: usize,
    slack: usize,
    borrow: usize,
    sbits: usize,
}

/// The bound transition's `T_` layout.
const T_BACKING: BackingAt = BackingAt { mr: T_MR, mm: T_MM, slack: T_GE_SLACK, borrow: T_GE_BORROW, sbits: T_GE_SBITS };

/// The backing's constraints over a reserve operand (its range bits at `rbits`) and a minted operand (`mbits`).
fn push_backing_constraints_at(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, rbits: usize, mbits: usize, backing: Backing, at: BackingAt) {
    // FAIL-CLOSED: every door refuses a rule that cannot form before it builds this gate; were one to reach here anyway,
    // a zero reserve multiplier against the widest minted one makes the compare unsatisfiable for any minted total ≥ 1.
    let (kr, km) = backing.ks().unwrap_or((0, (1u128 << 97)));
    push_mul14_constraints(cs, local, rbits, kr, at.mr);
    push_mul14_constraints(cs, local, mbits, km, at.mm);
    push_ge_n_constraints(cs, local, at.mr + M14_P16, at.mm + M14_P16, at.slack, at.borrow, at.sbits, M14_P16_LIMBS);
}

fn push_backing_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, rbits: usize, mbits: usize, backing: Backing) {
    push_backing_constraints_at(cs, local, rbits, mbits, backing, T_BACKING);
}

/// Lay the backing's two wide products and the compare; `None` (unprovable) when the rule cannot form or the reserve's value
/// does not back the minted total.
fn place_backing_at(cols: &mut [Vec<Fa4>], reserve16: &[u64; N_LIMB16], minted16: &[u64; N_LIMB16], backing: Backing, at: BackingAt) -> Option<()> {
    let (kr, km) = backing.ks()?;
    let pr = place_mul14(cols, reserve16, kr, at.mr)?;
    let pm = place_mul14(cols, minted16, km, at.mm)?;
    place_ge_n(cols, &pr, &pm, at.slack, at.borrow, at.sbits).then_some(())
}

fn place_backing(cols: &mut [Vec<Fa4>], reserve16: &[u64; N_LIMB16], minted16: &[u64; N_LIMB16], backing: Backing) -> Option<()> {
    place_backing_at(cols, reserve16, minted16, backing, T_BACKING)
}

struct BoundTransitionAir {
    gamma: Ea4,
    ratio_bps: Backing,
}
impl AirConstraint for BoundTransitionAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment opening). A gate that declares less
        // than the permutation's degree truncates the sumcheck and even an HONEST proof fails.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        // no hidden issuance: both totals advance by exactly their delta
        push_conservation_constraints(&mut cs, local, T_RES, T_DEP, T_NEWRES, T_RESCARRY);
        push_conservation_constraints(&mut cs, local, T_MINT, T_MDELTA, T_NEWMINT, T_MINTCARRY);
        // bind every value to its persisted commitment (old = inputs, new = outputs)
        push_commit_open_constraints(&mut cs, local, T_RES, T_RBLIND, T_RCOMMIT, T_RINTER, T_RVBITS);
        push_commit_open_constraints(&mut cs, local, T_MINT, T_MBLIND, T_MCOMMIT, T_MINTER, T_MVBITS);
        push_commit_open_constraints(&mut cs, local, T_NEWRES, T_NRBLIND, T_NRCOMMIT, T_NRINTER, T_NRVBITS);
        push_commit_open_constraints(&mut cs, local, T_NEWMINT, T_NMBLIND, T_NMCOMMIT, T_NMINTER, T_NMVBITS);
        push_range16_constraints(&mut cs, local, T_DEP, T_DEPVBITS, N_LIMB16);
        push_range16_constraints(&mut cs, local, T_MDELTA, T_MDVBITS, N_LIMB16);
        // the NEW total state is ≥150% backed: new_reserve·10000 ≥ new_minted·ratio_bps
        push_backing_constraints(&mut cs, local, T_NRVBITS, T_NMVBITS, self.ratio_bps);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Place a `p = a·k` scale block (17-limb result + carries + bit-decomposition) at the given offsets; returns
/// the 17-limb result for the downstream GE.
fn place_scale(cols: &mut Vec<Vec<Fa4>>, a: [u64; 16], k: u64, p_base: usize, carry_base: usize, pbits_base: usize, cbits_base: usize) -> Option<[u64; N_LIMB17]> {
    if !scale_k_admissible(k) {
        return None; // DB-362: no integer-identity witness exists for a wider multiplier
    }
    let mut p = [0u64; N_LIMB17];
    let mut carry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let prod = a[i] * k + cin;
        p[i] = prod & LIMB16_MASK;
        cin = prod >> LIMB16_BITS;
        carry[i] = cin;
    }
    p[16] = cin;
    let mut set = |c: usize, v: u64| {
        let f = Fa4::from_u64(v);
        cols[c][0] = f;
        cols[c][1] = f;
    };
    for i in 0..N_LIMB16 {
        set(carry_base + i, carry[i]);
    }
    for i in 0..N_LIMB17 {
        set(p_base + i, p[i]);
        for j in 0..N_LIMB16 {
            set(pbits_base + i * N_LIMB16 + j, (p[i] >> j) & 1);
        }
    }
    if !place_carry_bound(cols, &carry, cbits_base) {
        return None;
    }
    Some(p)
}

/// Place a `x ≥ y` GE block (slack + borrows + slack bits). Returns false (unprovable) when `x < y`.
fn place_ge(cols: &mut Vec<Vec<Fa4>>, x: [u64; N_LIMB17], y: [u64; N_LIMB17], slack_base: usize, borrow_base: usize, sbits_base: usize) -> bool {
    // ONE spelling: the n-limb compare at the scale block's 17 limbs (`false` = x < y: under-collateralized, no proof)
    place_ge_n(cols, &x, &y, slack_base, borrow_base, sbits_base)
}

/// The four persisted commitments a bound transition advances: (reserve, minted, new_reserve, new_minted).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionCommits {
    pub reserve_commit: Digest,
    pub minted_commit: Digest,
    pub new_reserve_commit: Digest,
    pub new_minted_commit: Digest,
}

/// Build the full bound-transition trace. `None` on 256-bit overflow OR when the NEW total state is under
/// `ratio_bps`-collateralized (no valid proof of an insolvent peg can exist — fail-closed).
#[allow(clippy::too_many_arguments)]
fn bound_transition_trace(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
    gate: TransitionGate,
) -> Option<(Vec<Vec<Fa4>>, TransitionCommits)> {
    let new_reserve = add256(reserve, deposit)?;
    let new_minted = add256(minted, mint_delta)?;
    let (rl, ml) = (u256_to_limbs16(reserve), u256_to_limbs16(minted));
    let (dl, mdl) = (u256_to_limbs16(deposit), u256_to_limbs16(mint_delta));
    let (nrl, nml) = (u256_to_limbs16(new_reserve), u256_to_limbs16(new_minted));
    let carry_of = |a: [u64; 16], b: [u64; 16]| -> [u64; N_LIMB16] {
        let mut c = [0u64; N_LIMB16];
        let mut cin = 0u64;
        for i in 0..N_LIMB16 {
            let s = a[i] + b[i] + cin;
            cin = s >> LIMB16_BITS;
            c[i] = cin;
        }
        c
    };
    let res_carry = carry_of(rl, dl);
    let mint_carry = carry_of(ml, mdl);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; T_WIDTH];
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..N_LIMB16 {
            set(T_RES + i, rl[i]);
            set(T_MINT + i, ml[i]);
            set(T_DEP + i, dl[i]);
            set(T_MDELTA + i, mdl[i]);
            set(T_NEWRES + i, nrl[i]);
            set(T_NEWMINT + i, nml[i]);
            set(T_RESCARRY + i, res_carry[i]);
            set(T_MINTCARRY + i, mint_carry[i]);
        }
        for i in 0..DIGEST_LANES {
            set(T_RBLIND + i, r_blind[i]);
            set(T_MBLIND + i, m_blind[i]);
            set(T_NRBLIND + i, nr_blind[i]);
            set(T_NMBLIND + i, nm_blind[i]);
        }
    }
    let rc = place_commit_open(&mut cols, rl, r_blind, T_RINTER, T_RVBITS);
    let mc = place_commit_open(&mut cols, ml, m_blind, T_MINTER, T_MVBITS);
    let nrc = place_commit_open(&mut cols, nrl, nr_blind, T_NRINTER, T_NRVBITS);
    let nmc = place_commit_open(&mut cols, nml, nm_blind, T_NMINTER, T_NMVBITS);
    place_range16(&mut cols, &dl, T_DEPVBITS);
    place_range16(&mut cols, &mdl, T_MDVBITS);
    match gate {
        // the post state's value < its minted·ratio ⇒ unprovable
        TransitionGate::Aggregate => place_backing(&mut cols, &nrl, &nml, ratio_bps)?,
        // DB-470: the mint's own deposit does not back the mint ⇒ unprovable, whatever the surplus
        TransitionGate::Marginal => place_backing(&mut cols, &dl, &mdl, ratio_bps)?,
        TransitionGate::Redeem => return None, // a redemption is laid by `pegout_trace`, never here
    }
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..DIGEST_LANES {
            set(T_RCOMMIT + i, rc[i]);
            set(T_MCOMMIT + i, mc[i]);
            set(T_NRCOMMIT + i, nrc[i]);
            set(T_NMCOMMIT + i, nmc[i]);
        }
    }
    Some((cols, TransitionCommits { reserve_commit: rc, minted_commit: mc, new_reserve_commit: nrc, new_minted_commit: nmc }))
}

/// PROVE a full confidential peg-in transition: conservation + the four commitment openings + `ratio_bps`
/// backing, all bound over shared value columns. Returns the proof + the four persisted commitments (old =
/// the node's current state, new = the state after this peg-in). `None` if the resulting state would be
/// under-collateralized (unprovable, fail-closed).
#[allow(clippy::too_many_arguments)]
pub fn prove_bound_transition(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
    ch: &mut Chl,
) -> Option<(AirZerocheckProof, TransitionCommits)> {
    let (cols, commits) = bound_transition_trace(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, ratio_bps, TransitionGate::Aggregate)?;
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = BoundTransitionAir { gamma, ratio_bps };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    Some((prove_air_zerocheck(&cols, &air, &z, ch), commits))
}

/// VERIFY a full bound-transition proof (node-side, witness-free). Fail-closed on any of: hidden issuance,
/// a value that does not open to its committed digest, or an under-collateralized new state.
#[must_use]
pub fn verify_bound_transition(proof: &AirZerocheckProof, ratio_bps: Backing, ch: &mut Chl) -> bool {
    if ratio_bps.ks().is_none() {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let gamma: Ea4 = ch.sample_algebra_element();
    let air = BoundTransitionAir { gamma, ratio_bps };
    let z: Vec<Ea4> = (0..1).map(|_| ch.sample_algebra_element()).collect();
    verify_air_zerocheck(proof, &air, &z, ch)
}

/// Seeded wrappers — the node binds the Fiat-Shamir transcript to the persisted committed state (the seed is
/// derived from the four commitments), so a proof for one state can't be replayed against another.
pub fn prove_bound_transition_seeded(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
    seed: u64,
) -> Option<(AirZerocheckProof, TransitionCommits)> {
    let mut ch = challenger_from_seed(seed);
    prove_bound_transition(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, ratio_bps, &mut ch)
}

#[must_use]
pub fn verify_bound_transition_seeded(proof: &AirZerocheckProof, ratio_bps: Backing, seed: u64) -> bool {
    let mut ch = challenger_from_seed(seed);
    verify_bound_transition(proof, ratio_bps, &mut ch)
}

// ── #75 brick 3d — the WHIR-BOUND peg-in carrier: the on-chain-sound proof the node verifies ──────────────
//
// The raw `AirZerocheckProof` above proves the constraints hold over SOME trace, but its `opened` column
// values are only bound when the trace is WHIR-committed (air_zerocheck.rs §"the WHIR PCS opens"). This
// routes the full bound transition through the light-decider PCS carrier so the openings are cryptographically
// bound to a commitment. The FOUR value-hiding commitments are CONSENSUS-KNOWN constants (opaque digests the
// node persists — never a total): baked into the AIR AND observed as the transcript's statement bind. So the
// node verifies against ITS OWN persisted (reserve_commit, minted_commit) + the block's claimed
// (new_reserve_commit, new_minted_commit); if the prover built the proof for any other state, both the
// commitment-pin constraint AND the transcript diverge → reject. The trace carries ONLY hidden values; the node
// learns no total. This is the sound `verify_confidential_peg_in` swap-in.

/// Consensus-commitment variant of the bound transition: the four value-hiding commitments are CONSENSUS-KNOWN
/// constants (not free trace columns), pinned into the trace's commitment columns. Else it is
/// [`BoundTransitionAir`].
struct PinnedBoundTransitionAir {
    gamma: Ea4,
    ratio_bps: Backing,
    reserve_commit: [Ea4; DIGEST_LANES],
    minted_commit: [Ea4; DIGEST_LANES],
    new_reserve_commit: [Ea4; DIGEST_LANES],
    new_minted_commit: [Ea4; DIGEST_LANES],
    /// DB-470: the per-transaction rule this transition proves ([`TransitionGate`]).
    gate: TransitionGate,
}
/// The bound transition's constraint list, spelled ONCE for the three carriers that share the `T_` layout (the
/// unbound, the mint-delta-bound and the both-deltas-bound): conservation on both sides, the four state openings, the
/// backing inequality on the post-transition state, and the four commitment pins.
fn push_bound_transition_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: &PinnedBoundTransitionAir) {
    push_conservation_constraints(cs, local, T_RES, T_DEP, T_NEWRES, T_RESCARRY);
    push_conservation_constraints(cs, local, T_MINT, T_MDELTA, T_NEWMINT, T_MINTCARRY);
    push_commit_open_constraints(cs, local, T_RES, T_RBLIND, T_RCOMMIT, T_RINTER, T_RVBITS);
    push_commit_open_constraints(cs, local, T_MINT, T_MBLIND, T_MCOMMIT, T_MINTER, T_MVBITS);
    push_commit_open_constraints(cs, local, T_NEWRES, T_NRBLIND, T_NRCOMMIT, T_NRINTER, T_NRVBITS);
    push_commit_open_constraints(cs, local, T_NEWMINT, T_NMBLIND, T_NMCOMMIT, T_NMINTER, T_NMVBITS);
    // DB-470: both deltas are canonical non-negative integers (no negative deposit, no negative burn)
    push_range16_constraints(cs, local, T_DEP, T_DEPVBITS, N_LIMB16);
    push_range16_constraints(cs, local, T_MDELTA, T_MDVBITS, N_LIMB16);
    push_transition_gate_constraints(cs, local, a.gate, a.ratio_bps);
    // COMMITMENT PIN: the trace's commitment columns MUST equal the node's persisted / claimed digests.
    // Combined with the openings above, this ties the hidden totals to the exact consensus commitments.
    for (base, pinned) in [
        (T_RCOMMIT, &a.reserve_commit),
        (T_MCOMMIT, &a.minted_commit),
        (T_NRCOMMIT, &a.new_reserve_commit),
        (T_NMCOMMIT, &a.new_minted_commit),
    ] {
        for c in 0..DIGEST_LANES {
            cs.push(local[base + c] - pinned[c]);
        }
    }
}

/// DB-470 — the per-transaction rule's constraints. In the peg-in layout the deltas are (deposit, mint) and the s-side is the
/// post state; in the peg-out layout (the same columns read backwards) `T_DEP` is the release, `T_MDELTA` the burn, and the
/// s-side (`T_NEWRES`/`T_NEWMINT`) the CURRENT totals.
fn push_transition_gate_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, gate: TransitionGate, backing: Backing) {
    match gate {
        TransitionGate::Aggregate => push_backing_constraints(cs, local, T_NRVBITS, T_NMVBITS, backing),
        TransitionGate::Marginal => push_backing_constraints(cs, local, T_DEPVBITS, T_MDVBITS, backing),
        TransitionGate::Redeem => {
            // FAIL-CLOSED like the backing: a rule that cannot form makes the burn side zero against the widest release side
            let (kr, km) = backing.ks().unwrap_or((1u128 << 97, 0));
            push_mul14_constraints(cs, local, T_DEPVBITS, kr, T_MR); // release × BPS × price
            push_mul14_constraints(cs, local, T_MDVBITS, km, T_MM); // burn × floor × PRICE_SCALE
            push_ge_n_constraints(cs, local, T_MM + M14_P16, T_MR + M14_P16, T_GE_SLACK, T_GE_BORROW, T_GE_SBITS, M14_P16_LIMBS);
            push_mulhh_constraints(cs, local, T_MDVBITS, T_NRVBITS, N_LIMB16, TO_HR); // burn × current reserve
            push_mulhh_constraints(cs, local, T_DEPVBITS, T_NMVBITS, N_LIMB16, TO_HM); // release × current minted
            let off = mulhh_p16_off(N_LIMB16);
            push_ge_n_constraints(cs, local, TO_HR + off, TO_HM + off, TO_SLACK, TO_BORROW, TO_SBITS, hh_p16(N_LIMB16));
        }
    }
}

/// The γ-fold every `T_`-layout carrier ends with.
fn fold_constraints(cs: Vec<Ea4>, gamma: Ea4) -> Ea4 {
    let mut acc = Ea4::ZERO;
    let mut gp = Ea4::ONE;
    for c in cs {
        acc += gp * c;
        gp *= gamma;
    }
    acc
}

impl AirConstraint for PinnedBoundTransitionAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment opening). A gate that declares less
        // than the permutation's degree truncates the sumcheck and even an HONEST proof fails.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_bound_transition_constraints(&mut cs, local, self);
        fold_constraints(cs, self.gamma)
    }
}

fn commit_to_ea4(d: Digest) -> [Ea4; DIGEST_LANES] {
    // ⛔ WAS FOUR HAND-WRITTEN LANES. A lane count spelled out element by element is a lane count that
    // has to be edited by hand, and this one would have compiled at the wrong width if the digest had
    // ever shrunk instead of grown.
    core::array::from_fn(|i| Ea4::from(Fa4::from_u64(d[i])))
}

/// The transcript statement bind for a peg-in: the four commitments as field elements. A verifier reading
/// different commitments diverges the Fiat-Shamir transcript → reject.
fn peg_in_statement_bind(rc: Digest, mc: Digest, nrc: Digest, nmc: Digest) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(16);
    for d in [rc, mc, nrc, nmc] {
        for x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════
// DB-80 (2026-09-19) — THE MINT DELTA IS COMMITTED, NEVER PUBLISHED.
//
// The bound transition above already keeps `deposit` and `mint_delta` PRIVATE (only the four state
// commitments are public). What made the mint amount public was the OTHER carrier: the mint-validity
// gate pinned the note's value as a public input (`PegInHeader.mint_authorized`) so the two proofs
// could agree on one number. Borrowed from Zcash Sapling's value-commitment binding: the two carriers
// now agree on a fifth PUBLIC COMMITMENT `delta_commit = solvency_commit_256(mint_delta, d_blind)`
// — this AIR opens it to its private `mint_delta` column; the committed mint-validity gate
// (`whir_rec_block::MintValidityCommittedGate`) opens the SAME commitment to the note's value. Nobody
// but the depositor and the custodians (who hold `d_blind` sealed) learns the amount.
//
// Layout: the delta columns are APPENDED after the existing transition width, so every column index
// of the original AIR is untouched (the original prove/verify pair keeps working until the node swaps).
// ═══════════════════════════════════════════════════════════════════════════════════════════════
const TD_DBLIND: usize = T_WIDTH;
const TD_DCOMMIT: usize = TD_DBLIND + DIGEST_LANES;
const TD_DINTER: usize = TD_DCOMMIT + DIGEST_LANES;
const TD_DVBITS: usize = TD_DINTER + T_OPEN;
const TD_WIDTH: usize = TD_DVBITS + RANGE16_COLS;

pub struct TransitionCommitsDelta {
    pub base: TransitionCommits,
    /// `solvency_commit_256(mint_delta, d_blind)` — the value the mint-validity carrier binds to.
    pub delta_commit: Digest,
}

#[allow(clippy::too_many_arguments)]
fn bound_transition_trace_delta(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    d_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<Vec<Fa4>>, TransitionCommitsDelta)> {
    let (mut cols, base) = bound_transition_trace(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, ratio_bps, TransitionGate::Marginal)?;
    let h = cols[0].len();
    while cols.len() < TD_WIDTH {
        cols.push(vec![Fa4::ZERO; h]);
    }
    for i in 0..DIGEST_LANES {
        cols[TD_DBLIND + i].fill(Fa4::from_u64(d_blind[i]));
    }
    let mdl = u256_to_limbs16(mint_delta);
    let dc = place_commit_open(&mut cols, mdl, d_blind, TD_DINTER, TD_DVBITS);
    for i in 0..DIGEST_LANES {
        cols[TD_DCOMMIT + i].fill(Fa4::from_u64(dc[i]));
    }
    Some((cols, TransitionCommitsDelta { base, delta_commit: dc }))
}

struct PinnedBoundTransitionDeltaAir {
    inner: PinnedBoundTransitionAir,
    delta_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for PinnedBoundTransitionDeltaAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_mint_delta_bound_constraints(&mut cs, local, self);
        fold_constraints(cs, self.inner.gamma)
    }
}

/// The mint-delta-bound list: the shared transition constraints plus the fifth opening — DB-80: the private mint
/// delta opens the public `delta_commit`, which is pinned.
fn push_mint_delta_bound_constraints(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, a: &PinnedBoundTransitionDeltaAir) {
    push_bound_transition_constraints(cs, local, &a.inner);
    push_commit_open_constraints(cs, local, T_MDELTA, TD_DBLIND, TD_DCOMMIT, TD_DINTER, TD_DVBITS);
    for c in 0..DIGEST_LANES {
        cs.push(local[TD_DCOMMIT + c] - a.delta_commit[c]);
    }
}

fn peg_in_statement_bind_delta(rc: Digest, mc: Digest, nrc: Digest, nmc: Digest, dc: Digest) -> Vec<Fa4> {
    let mut v = peg_in_statement_bind(rc, mc, nrc, nmc);
    v.push(Fa4::from_u64(0x4442_3830)); // "DB80" — a distinct statement domain from the unbound carrier
    for x in dc {
        v.push(Fa4::from_u64(x));
    }
    v
}

/// DB-80 peg-in carrier: conservation + the four state openings + `ratio_bps` backing on the post-mint
/// state + the COMMITTED mint delta (`delta_commit`, public; `mint_delta` private).
#[allow(clippy::too_many_arguments)]
pub fn prove_peg_in_carrier_delta(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    d_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, TransitionCommitsDelta)> {
    let (cols2, commits) = bound_transition_trace_delta(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, d_blind, ratio_bps)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let b = &commits.base;
    let statement_bind = peg_in_statement_bind_delta(b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, commits.delta_commit);
    let (rc, mc, nrc, nmc, dc) = (
        commit_to_ea4(b.reserve_commit),
        commit_to_ea4(b.minted_commit),
        commit_to_ea4(b.new_reserve_commit),
        commit_to_ea4(b.new_minted_commit),
        commit_to_ea4(commits.delta_commit),
    );
    let make = |g: Ea4| PinnedBoundTransitionDeltaAir {
        inner: PinnedBoundTransitionAir {
            gamma: g,
            ratio_bps,
            reserve_commit: rc,
            minted_commit: mc,
            new_reserve_commit: nrc,
            new_minted_commit: nmc,
            gate: TransitionGate::Marginal,
        },
        delta_commit: dc,
    };
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, commits))
}

#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_peg_in_carrier_delta(
    bytes: &[u8],
    ratio_bps: Backing,
    reserve_commit: Digest,
    minted_commit: Digest,
    new_reserve_commit: Digest,
    new_minted_commit: Digest,
    delta_commit: Digest,
) -> bool {
    if ratio_bps.ks().is_none() {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let statement_bind = peg_in_statement_bind_delta(reserve_commit, minted_commit, new_reserve_commit, new_minted_commit, delta_commit);
    let make = |g: Ea4| PinnedBoundTransitionDeltaAir {
        inner: PinnedBoundTransitionAir {
            gamma: g,
            ratio_bps,
            reserve_commit: commit_to_ea4(reserve_commit),
            minted_commit: commit_to_ea4(minted_commit),
            new_reserve_commit: commit_to_ea4(new_reserve_commit),
            new_minted_commit: commit_to_ea4(new_minted_commit),
            gate: TransitionGate::Marginal,
        },
        delta_commit: commit_to_ea4(delta_commit),
    };
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, TD_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// DB-80c (2026-09-29) — BOTH deltas bound. The mint-delta carrier above binds the MINT side to `delta_commit` (the
// note's value), but its RESERVE deposit (`T_DEP`) is still a free witness: no range bits, no commitment. The carrier
// alone therefore admits ANY `new_reserve_commit` — a prover claims a deposit larger than the one observed, the
// conservation and backing checks run over the claimed reserve, and the mint is "backed". What binds the reserve
// today is the door's ≥2/3 attestation of the proposed digests; the carrier should not lean on it. Here the deposit
// opens a SIXTH public commitment `deposit_commit = solvency_commit_256(deposit, dep_blind)` — the digest the
// observing bonded nodes attest from the foreign chain (the same sealed-blind shape as `d_blind`) — so the carrier
// proves `new_reserve = reserve + THE ATTESTED deposit` by construction. The columns are appended after `TD_WIDTH`;
// nothing in the two carriers above moves.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
const TB_RBLIND: usize = TD_WIDTH;
const TB_RCOMMIT: usize = TB_RBLIND + DIGEST_LANES;
const TB_RINTER: usize = TB_RCOMMIT + DIGEST_LANES;
const TB_RVBITS: usize = TB_RINTER + T_OPEN;
const TB_WIDTH: usize = TB_RVBITS + RANGE16_COLS;

/// The six commitments of a both-deltas-bound transition.
pub struct TransitionCommitsBound {
    pub delta: TransitionCommitsDelta,
    /// `solvency_commit_256(deposit, dep_blind)` — what the observers of the foreign deposit attest.
    pub deposit_commit: Digest,
}

#[allow(clippy::too_many_arguments)]
fn bound_transition_trace_both(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    d_blind: Digest,
    dep_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<Vec<Fa4>>, TransitionCommitsBound)> {
    let (mut cols, delta) = bound_transition_trace_delta(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, d_blind, ratio_bps)?;
    let h = cols[0].len();
    while cols.len() < TB_WIDTH {
        cols.push(vec![Fa4::ZERO; h]);
    }
    fill_cols(&mut cols, TB_RBLIND, &dep_blind);
    let deposit_commit = place_commit_open(&mut cols, u256_to_limbs16(deposit), dep_blind, TB_RINTER, TB_RVBITS);
    fill_cols(&mut cols, TB_RCOMMIT, &deposit_commit);
    Some((cols, TransitionCommitsBound { delta, deposit_commit }))
}

struct PinnedBoundTransitionBothAir {
    inner: PinnedBoundTransitionDeltaAir,
    deposit_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for PinnedBoundTransitionBothAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_mint_delta_bound_constraints(&mut cs, local, &self.inner);
        // DB-80c: the private reserve deposit opens the sixth, public commitment — its limbs are range-bound by the
        // opening, so the reserve conservation is an integer identity against the ATTESTED deposit
        push_commit_open_constraints(&mut cs, local, T_DEP, TB_RBLIND, TB_RCOMMIT, TB_RINTER, TB_RVBITS);
        for c in 0..DIGEST_LANES {
            cs.push(local[TB_RCOMMIT + c] - self.deposit_commit[c]);
        }
        fold_constraints(cs, self.inner.inner.gamma)
    }
}

fn peg_in_statement_bind_both(rc: Digest, mc: Digest, nrc: Digest, nmc: Digest, dc: Digest, depc: Digest) -> Vec<Fa4> {
    let mut v = peg_in_statement_bind_delta(rc, mc, nrc, nmc, dc);
    v.push(Fa4::from_u64(0x4442_3830_43)); // "DB80C" — a distinct statement domain from the mint-delta carrier
    for x in depc {
        v.push(Fa4::from_u64(x));
    }
    v
}

#[allow(clippy::too_many_arguments)]
fn both_air(ratio_bps: Backing, rc: Digest, mc: Digest, nrc: Digest, nmc: Digest, dc: Digest, depc: Digest) -> impl Fn(Ea4) -> PinnedBoundTransitionBothAir {
    let (rc, mc, nrc, nmc, dc, depc) = (commit_to_ea4(rc), commit_to_ea4(mc), commit_to_ea4(nrc), commit_to_ea4(nmc), commit_to_ea4(dc), commit_to_ea4(depc));
    move |g: Ea4| PinnedBoundTransitionBothAir {
        inner: PinnedBoundTransitionDeltaAir {
            inner: PinnedBoundTransitionAir { gamma: g, ratio_bps, reserve_commit: rc, minted_commit: mc, new_reserve_commit: nrc, new_minted_commit: nmc, gate: TransitionGate::Marginal },
            delta_commit: dc,
        },
        deposit_commit: depc,
    }
}

/// DB-80c peg-in carrier: everything the mint-delta carrier proves, plus the COMMITTED reserve deposit
/// (`deposit_commit`, public; `deposit` private). `dep_blind` is the deposit's sealed blind, held like `d_blind`.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn prove_peg_in_carrier_bound(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    d_blind: Digest,
    dep_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, TransitionCommitsBound)> {
    if ratio_bps.ks().is_none() {
        return None; // DB-362
    }
    let (cols2, commits) = bound_transition_trace_both(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, d_blind, dep_blind, ratio_bps)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let b = &commits.delta.base;
    let statement_bind = peg_in_statement_bind_both(b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, commits.delta.delta_commit, commits.deposit_commit);
    let make = both_air(ratio_bps, b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, commits.delta.delta_commit, commits.deposit_commit);
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, commits))
}

/// VERIFY a DB-80c carrier against the six commitments: the persisted `(reserve, minted)`, the claimed `(new_reserve,
/// new_minted)`, the mint delta the note binds to, and the deposit the observers attested. Fail-closed on a wider
/// ratio (DB-362), any value not opening to its digest, a broken conservation on EITHER side, or a post-state that
/// does not clear the backing.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_peg_in_carrier_bound(
    bytes: &[u8],
    ratio_bps: Backing,
    reserve_commit: Digest,
    minted_commit: Digest,
    new_reserve_commit: Digest,
    new_minted_commit: Digest,
    delta_commit: Digest,
    deposit_commit: Digest,
) -> bool {
    if ratio_bps.ks().is_none() || bytes.is_empty() {
        return false;
    }
    let statement_bind = peg_in_statement_bind_both(reserve_commit, minted_commit, new_reserve_commit, new_minted_commit, delta_commit, deposit_commit);
    let make = both_air(ratio_bps, reserve_commit, minted_commit, new_reserve_commit, new_minted_commit, delta_commit, deposit_commit);
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, TB_WIDTH))
}

/// Replicate a height-2 (both rows equal) row-local trace up to `h` rows — preserves every row-local
/// constraint while meeting the decider's `2^folding` minimum height.
fn replicate_rows(cols: Vec<Vec<Fa4>>, h: usize) -> Vec<Vec<Fa4>> {
    cols.into_iter().map(|c| vec![c[0]; h]).collect()
}

/// PROVE the WHIR-bound confidential peg-in carrier. Returns the ≤1.8MB carrier bytes + the four persisted
/// commitments (old = the node's current state, new = the state after this peg-in). `None` if the resulting
/// state would be under-collateralized (unprovable). This is what a custodian threshold broadcasts; the node
/// verifies it with [`verify_peg_in_carrier`] and learns no total.
#[allow(clippy::too_many_arguments)]
pub fn prove_peg_in_carrier(
    reserve: U256,
    minted: U256,
    deposit: U256,
    mint_delta: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, TransitionCommits)> {
    let (cols2, commits) = bound_transition_trace(reserve, minted, deposit, mint_delta, r_blind, m_blind, nr_blind, nm_blind, ratio_bps, TransitionGate::Aggregate)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = peg_in_statement_bind(commits.reserve_commit, commits.minted_commit, commits.new_reserve_commit, commits.new_minted_commit);
    let (rc, mc, nrc, nmc) = (
        commit_to_ea4(commits.reserve_commit),
        commit_to_ea4(commits.minted_commit),
        commit_to_ea4(commits.new_reserve_commit),
        commit_to_ea4(commits.new_minted_commit),
    );
    let make = |g: Ea4| PinnedBoundTransitionAir {
        gamma: g,
        ratio_bps,
        reserve_commit: rc,
        minted_commit: mc,
        new_reserve_commit: nrc,
        new_minted_commit: nmc,
        gate: TransitionGate::Aggregate, // the plain carrier: the post state is backed (the bond backstop's statement)
    };
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, commits))
}

/// VERIFY the WHIR-bound confidential peg-in carrier against the node's persisted OLD commitments + the
/// block's claimed NEW commitments. Fail-closed on: hidden issuance, an under-collateralized new state, a
/// value not opening to its committed digest, OR a proof built for any other (old/new) commitment pair.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_peg_in_carrier(
    bytes: &[u8],
    ratio_bps: Backing,
    reserve_commit: Digest,
    minted_commit: Digest,
    new_reserve_commit: Digest,
    new_minted_commit: Digest,
) -> bool {
    if ratio_bps.ks().is_none() {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let statement_bind = peg_in_statement_bind(reserve_commit, minted_commit, new_reserve_commit, new_minted_commit);
    let make = |g: Ea4| PinnedBoundTransitionAir {
        gamma: g,
        ratio_bps,
        reserve_commit: commit_to_ea4(reserve_commit),
        minted_commit: commit_to_ea4(minted_commit),
        new_reserve_commit: commit_to_ea4(new_reserve_commit),
        new_minted_commit: commit_to_ea4(new_minted_commit),
        gate: TransitionGate::Aggregate,
    };
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, T_WIDTH))
}

// ── #75 brick 3e — the confidential PEG-OUT (redeem/burn) carrier ─────────────────────────────────────────
//
// Peg-out reduces BOTH totals: new_reserve = reserve − release, new_minted = minted − burn. Modeled as the
// SAME bound transition read backwards — the (smaller) POST-burn state sits at the a-side columns
// (T_RES/T_MINT), the (larger) current state at the s-side (T_NEWRES/T_NEWMINT), conservation `new+delta==old`.
// ⭐⭐ DB-470: the rule is PER TRANSACTION ([`TransitionGate::Redeem`]): the release is worth at most the burn at the floor
// ($1 of reserve per USDm at 100 %) and at most the burn's pro-rata share of the current reserve. MEASURED before: the gate
// was the POST aggregate at the floor, so one burned USDm released a 300 % reserve's whole surplus, and an 80 % system
// (a price crash, no exploit) refused every cash-out — even a fair pro-rata one. No cleartext amount; the node swaps
// commitments only.

/// The peg-out trace: everything [`pegout_trace_unchecked`] lays PLUS the two per-transaction compares, which is what makes
/// a release worth more than its burn, or more than its burn's share of the reserve, unprovable. This is the only builder
/// the prover uses. `None` on underflow (release > reserve, burn > minted) or either compare failing.
#[allow(clippy::too_many_arguments)]
fn pegout_trace(
    reserve: U256,
    minted: U256,
    release: U256,
    burn: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<Vec<Fa4>>, TransitionCommits)> {
    let (mut cols, commits, cmp) = pegout_trace_unchecked(reserve, minted, release, burn, r_blind, m_blind, nr_blind, nm_blind, ratio_bps)?;
    if !place_ge_n(&mut cols, &cmp.burn_worth, &cmp.release_worth, T_GE_SLACK, T_GE_BORROW, T_GE_SBITS) {
        return None; // the release is worth more than the burn at the floor ⇒ unprovable
    }
    if !place_ge_n(&mut cols, &cmp.burn_share, &cmp.release_share, TO_SLACK, TO_BORROW, TO_SBITS) {
        return None; // the release exceeds the burn's pro-rata share of the reserve ⇒ unprovable
    }
    Some((cols, commits))
}

/// The two compares' inputs a peg-out lays (16-bit limbs): `burn × floor × SCALE` vs `release × BPS × price`, and
/// `burn × R` vs `release × M`.
struct PegOutCompares {
    burn_worth: [u64; M14_P16_LIMBS],
    release_worth: [u64; M14_P16_LIMBS],
    burn_share: Vec<u64>,
    release_share: Vec<u64>,
}

/// The peg-out trace WITHOUT the two compares: the limbs, carries, openings, delta range bits, products and commitment
/// pins — and the compares' inputs. Split out so an adversarial pin can lay what a forger would lay (everything honest but
/// the compares' inputs) and measure that the relation refuses it; the prover never calls this directly.
#[allow(clippy::too_many_arguments)]
fn pegout_trace_unchecked(
    reserve: U256,
    minted: U256,
    release: U256,
    burn: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<Vec<Fa4>>, TransitionCommits, PegOutCompares)> {
    let new_reserve = sub256(reserve, release)?; // release ≤ reserve custodied
    let new_minted = sub256(minted, burn)?; // burn ≤ USDm minted
    let (nrl, nml) = (u256_to_limbs16(new_reserve), u256_to_limbs16(new_minted)); // a-side (post state)
    let (rl, ml) = (u256_to_limbs16(reserve), u256_to_limbs16(minted)); // s-side (current state)
    let (rell, burnl) = (u256_to_limbs16(release), u256_to_limbs16(burn));
    let carry_of = |a: [u64; 16], b: [u64; 16]| -> [u64; N_LIMB16] {
        let mut c = [0u64; N_LIMB16];
        let mut cin = 0u64;
        for i in 0..N_LIMB16 {
            let s = a[i] + b[i] + cin;
            cin = s >> LIMB16_BITS;
            c[i] = cin;
        }
        c
    };
    let res_carry = carry_of(nrl, rell); // new_reserve + release == reserve
    let mint_carry = carry_of(nml, burnl); // new_minted + burn == minted
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; TO_WIDTH];
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..N_LIMB16 {
            set(T_RES + i, nrl[i]); // a-side = POST reserve
            set(T_MINT + i, nml[i]); // a-side = POST minted
            set(T_DEP + i, rell[i]); // delta = released reserve
            set(T_MDELTA + i, burnl[i]); // delta = burned USDm
            set(T_NEWRES + i, rl[i]); // s-side = CURRENT reserve
            set(T_NEWMINT + i, ml[i]); // s-side = CURRENT minted
            set(T_RESCARRY + i, res_carry[i]);
            set(T_MINTCARRY + i, mint_carry[i]);
        }
        for i in 0..DIGEST_LANES {
            set(T_RBLIND + i, nr_blind[i]); // T_RES opens with the POST-reserve blind
            set(T_MBLIND + i, nm_blind[i]); // T_MINT opens with the POST-minted blind
            set(T_NRBLIND + i, r_blind[i]); // T_NEWRES opens with the CURRENT-reserve blind
            set(T_NMBLIND + i, m_blind[i]); // T_NEWMINT opens with the CURRENT-minted blind
        }
    }
    let nrc = place_commit_open(&mut cols, nrl, nr_blind, T_RINTER, T_RVBITS); // T_RES → new_reserve_commit
    let nmc = place_commit_open(&mut cols, nml, nm_blind, T_MINTER, T_MVBITS); // T_MINT → new_minted_commit
    let rc = place_commit_open(&mut cols, rl, r_blind, T_NRINTER, T_NRVBITS); // T_NEWRES → reserve_commit
    let mc = place_commit_open(&mut cols, ml, m_blind, T_NMINTER, T_NMVBITS); // T_NEWMINT → minted_commit
    place_range16(&mut cols, &rell, T_DEPVBITS); // DB-470: the release is a canonical integer ≥ 0
    place_range16(&mut cols, &burnl, T_MDVBITS); // DB-470: the burn is a canonical integer ≥ 0
    let (kr, km) = ratio_bps.ks()?;
    let release_worth = place_mul14(&mut cols, &rell, kr, T_MR)?; // release × BPS × price
    let burn_worth = place_mul14(&mut cols, &burnl, km, T_MM)?; // burn × floor × PRICE_SCALE
    let burn_share = place_mulhh(&mut cols, &burnl, &rl, TO_HR)?; // burn × current reserve
    let release_share = place_mulhh(&mut cols, &rell, &ml, TO_HM)?; // release × current minted
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..DIGEST_LANES {
            set(T_RCOMMIT + i, nrc[i]); // pins T_RES
            set(T_MCOMMIT + i, nmc[i]); // pins T_MINT
            set(T_NRCOMMIT + i, rc[i]); // pins T_NEWRES
            set(T_NMCOMMIT + i, mc[i]); // pins T_NEWMINT
        }
    }
    Some((
        cols,
        TransitionCommits { reserve_commit: rc, minted_commit: mc, new_reserve_commit: nrc, new_minted_commit: nmc },
        PegOutCompares { burn_worth, release_worth, burn_share, release_share },
    ))
}

/// PROVE the WHIR-bound confidential peg-out carrier. `(reserve, minted)` are the CURRENT totals, `(release,
/// burn)` the amounts leaving. Returns the carrier bytes + the four commitments (current + post). `None` if the
/// post state would be under-collateralized (a reserve drain — unprovable).
#[allow(clippy::too_many_arguments)]
pub fn prove_peg_out_carrier(
    reserve: U256,
    minted: U256,
    release: U256,
    burn: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, TransitionCommits)> {
    let (cols2, commits) = pegout_trace(reserve, minted, release, burn, r_blind, m_blind, nr_blind, nm_blind, ratio_bps)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    // statement bind order matches the column pins: (T_RCOMMIT, T_MCOMMIT, T_NRCOMMIT, T_NMCOMMIT) =
    // (new_reserve, new_minted, current_reserve, current_minted).
    let statement_bind = peg_in_statement_bind(commits.new_reserve_commit, commits.new_minted_commit, commits.reserve_commit, commits.minted_commit);
    let make = |g: Ea4| PinnedBoundTransitionAir {
        gamma: g,
        ratio_bps,
        reserve_commit: commit_to_ea4(commits.new_reserve_commit), // → T_RCOMMIT (pins post reserve)
        minted_commit: commit_to_ea4(commits.new_minted_commit),   // → T_MCOMMIT (pins post minted)
        new_reserve_commit: commit_to_ea4(commits.reserve_commit),  // → T_NRCOMMIT (pins current reserve)
        new_minted_commit: commit_to_ea4(commits.minted_commit),    // → T_NMCOMMIT (pins current minted)
        gate: TransitionGate::Redeem, // DB-470: the $1 cap and the pro-rata share, never the aggregate
    };
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, commits))
}

/// VERIFY the WHIR-bound confidential peg-out carrier against the node's persisted CURRENT commitments + the
/// claimed POST commitments. Fail-closed on: non-conservation, an under-collateralized post state (drain), a
/// value not opening to its committed digest, OR a proof built for any other commitment set.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_peg_out_carrier(
    bytes: &[u8],
    ratio_bps: Backing,
    reserve_commit: Digest,
    minted_commit: Digest,
    new_reserve_commit: Digest,
    new_minted_commit: Digest,
) -> bool {
    if ratio_bps.ks().is_none() {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let statement_bind = peg_in_statement_bind(new_reserve_commit, new_minted_commit, reserve_commit, minted_commit);
    let make = |g: Ea4| PinnedBoundTransitionAir {
        gamma: g,
        ratio_bps,
        reserve_commit: commit_to_ea4(new_reserve_commit),
        minted_commit: commit_to_ea4(new_minted_commit),
        new_reserve_commit: commit_to_ea4(reserve_commit),
        new_minted_commit: commit_to_ea4(minted_commit),
        gate: TransitionGate::Redeem,
    };
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, TO_WIDTH))
}

// ⭐⭐ B15 (lane funds 2026-10-29) — THE PEG-OUT WHOSE BURN THE CHAIN BINDS: the Redeem transition above plus a fifth opening — the
// private burn delta opens the public `burn_commit`, the commitment the committed burn carrier
// (`whir_rec_block::prove_burn_validity_committed_bytes`) opens to the destroyed note's output. The chain then holds one
// number both proofs stand on: the supply falls by exactly what the burned note destroyed (DB-80's shape for mints).
const TOD_BBLIND: usize = TO_WIDTH;
const TOD_BCOMMIT: usize = TOD_BBLIND + DIGEST_LANES;
const TOD_BINTER: usize = TOD_BCOMMIT + DIGEST_LANES;
const TOD_BVBITS: usize = TOD_BINTER + T_OPEN;
const TOD_WIDTH: usize = TOD_BVBITS + RANGE16_COLS;

struct PinnedPegOutBurnAir {
    inner: PinnedBoundTransitionAir,
    burn_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for PinnedPegOutBurnAir {
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_bound_transition_constraints(&mut cs, local, &self.inner);
        push_commit_open_constraints(&mut cs, local, T_MDELTA, TOD_BBLIND, TOD_BCOMMIT, TOD_BINTER, TOD_BVBITS);
        for c in 0..DIGEST_LANES {
            cs.push(local[TOD_BCOMMIT + c] - self.burn_commit[c]);
        }
        fold_constraints(cs, self.inner.gamma)
    }
}

fn peg_out_statement_bind_burn(nrc: Digest, nmc: Digest, rc: Digest, mc: Digest, bc: Digest) -> Vec<Fa4> {
    let mut v = peg_in_statement_bind(nrc, nmc, rc, mc);
    v.push(Fa4::from_u64(0x4231_354f)); // "B15O" — a distinct statement domain from the unbound peg-out
    for x in bc {
        v.push(Fa4::from_u64(x));
    }
    v
}

/// ⭐ B15 — PROVE the peg-out carrier whose burn opens `burn_commit = solvency_commit_256(burn, b_blind)`. Returns the carrier, the
/// four state commitments and the burn commitment. `None` exactly when [`prove_peg_out_carrier`] would refuse.
#[allow(clippy::too_many_arguments)]
pub fn prove_peg_out_carrier_delta(
    reserve: U256,
    minted: U256,
    release: U256,
    burn: U256,
    r_blind: Digest,
    m_blind: Digest,
    nr_blind: Digest,
    nm_blind: Digest,
    b_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, TransitionCommits, Digest)> {
    let (mut cols2, commits) = pegout_trace(reserve, minted, release, burn, r_blind, m_blind, nr_blind, nm_blind, ratio_bps)?;
    let h = cols2[0].len();
    while cols2.len() < TOD_WIDTH {
        cols2.push(vec![Fa4::ZERO; h]);
    }
    for i in 0..DIGEST_LANES {
        cols2[TOD_BBLIND + i].fill(Fa4::from_u64(b_blind[i]));
    }
    let bc = place_commit_open(&mut cols2, u256_to_limbs16(burn), b_blind, TOD_BINTER, TOD_BVBITS);
    for i in 0..DIGEST_LANES {
        cols2[TOD_BCOMMIT + i].fill(Fa4::from_u64(bc[i]));
    }
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = peg_out_statement_bind_burn(commits.new_reserve_commit, commits.new_minted_commit, commits.reserve_commit, commits.minted_commit, bc);
    let (nrc, nmc, rc, mc, bce) = (
        commit_to_ea4(commits.new_reserve_commit),
        commit_to_ea4(commits.new_minted_commit),
        commit_to_ea4(commits.reserve_commit),
        commit_to_ea4(commits.minted_commit),
        commit_to_ea4(bc),
    );
    let make = |g: Ea4| PinnedPegOutBurnAir {
        inner: PinnedBoundTransitionAir { gamma: g, ratio_bps, reserve_commit: nrc, minted_commit: nmc, new_reserve_commit: rc, new_minted_commit: mc, gate: TransitionGate::Redeem },
        burn_commit: bce,
    };
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, commits, bc))
}

/// ⭐ B15 — VERIFY the burn-bound peg-out carrier against this node's commitments, the claimed post commitments and the burn
/// commitment the committed burn carrier opened.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn verify_peg_out_carrier_delta(
    bytes: &[u8],
    ratio_bps: Backing,
    reserve_commit: Digest,
    minted_commit: Digest,
    new_reserve_commit: Digest,
    new_minted_commit: Digest,
    burn_commit: Digest,
) -> bool {
    if ratio_bps.ks().is_none() {
        return false;
    }
    let statement_bind = peg_out_statement_bind_burn(new_reserve_commit, new_minted_commit, reserve_commit, minted_commit, burn_commit);
    let (nrc, nmc, rc, mc, bce) = (
        commit_to_ea4(new_reserve_commit),
        commit_to_ea4(new_minted_commit),
        commit_to_ea4(reserve_commit),
        commit_to_ea4(minted_commit),
        commit_to_ea4(burn_commit),
    );
    let make = |g: Ea4| PinnedPegOutBurnAir {
        inner: PinnedBoundTransitionAir { gamma: g, ratio_bps, reserve_commit: nrc, minted_commit: nmc, new_reserve_commit: rc, new_minted_commit: mc, gate: TransitionGate::Redeem },
        burn_commit: bce,
    };
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, TOD_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// ⭐⭐ §19.5b (lane defi, 2026-11-01) — THE TWO-LEDGER COVER: A PEG MOVES BOTH BRIDGE LEDGERS, AND NOTHING SAYS WHICH.
//
// A peg-in or peg-out used to advance ONE bridge ledger's public commitment pair (the native ledger's or Monero's), so every
// node saw WHICH chain a deposit or cash-out was on, and when. The cover carrier proves a transition on BOTH ledgers at once
// in ONE proof: two full transitions of the shared `T_` layout side by side — each with its own conservation, its own four
// openings, its own per-transaction gate at its own backing — and a total block whose limbs are the SUM of the two legs'
// deltas (`T_MDELTA`: the mint on a peg-in, the burn on a peg-out), opening the object's one public delta commitment (DB-80's
// `delta_commit`, B15's `burn_commit`). The ledger that did not move proves a zero transition under fresh blinds; its pair
// changes like the other's. The verifier's inputs are the same for either case: both ledgers' four commitments, both
// backings (public chain state), the one delta commitment. No field, width or input names the ledger.
// Sound: each leg is the existing gate, unchanged; the total is a limb adder with boolean carries and no final carry, its
// value range-checked by its opening; the supply moves by exactly the committed delta, split between two ledgers each of
// which stays inside its own rule — a split moves no value out of thin air (each leg's backing gate holds at its own price).
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
const CV_TOT: usize = 0;
const CV_CARRY: usize = CV_TOT + N_LIMB16;
const CV_BLIND: usize = CV_CARRY + N_LIMB16;
const CV_COMMIT: usize = CV_BLIND + DIGEST_LANES;
const CV_INTER: usize = CV_COMMIT + DIGEST_LANES;
const CV_VBITS: usize = CV_INTER + T_OPEN;
const CV_WIDTH: usize = CV_VBITS + RANGE16_COLS;

/// Which transition the cover's two legs prove: a peg-in (the `T_` layout, the per-mint gate) or a peg-out (the `TO_` layout,
/// the per-redeem gate).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverKind {
    PegIn,
    PegOut,
}
impl CoverKind {
    fn leg_width(self) -> usize {
        match self {
            CoverKind::PegIn => T_WIDTH,
            CoverKind::PegOut => TO_WIDTH,
        }
    }
    fn gate(self) -> TransitionGate {
        match self {
            CoverKind::PegIn => TransitionGate::Marginal,
            CoverKind::PegOut => TransitionGate::Redeem,
        }
    }
    fn domain(self) -> u64 {
        match self {
            CoverKind::PegIn => 0x4356_5249, // "CVRI"
            CoverKind::PegOut => 0x4356_524f, // "CVRO"
        }
    }
}

/// One leg of a cover: a bridge ledger's CURRENT opening `(reserve, minted)` with its blinds, the deltas it moves (zero on the
/// ledger that does not), the POST blinds, and its backing. On a peg-in the deltas are `(deposit, mint)`; on a peg-out
/// `(release, burn)`.
#[derive(Clone, Copy, Debug)]
pub struct CoverLeg {
    pub reserve: U256,
    pub minted: U256,
    pub delta_reserve: U256,
    pub delta_minted: U256,
    pub r_blind: Digest,
    pub m_blind: Digest,
    pub nr_blind: Digest,
    pub nm_blind: Digest,
    pub backing: Backing,
}

/// The cover's public commitments: each ledger's `(reserve, minted, new_reserve, new_minted)` (CURRENT then POST, in the
/// ledger order the chain fixes) and the one delta commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverCommits {
    pub legs: [TransitionCommits; 2],
    pub delta_commit: Digest,
}

struct PinnedCoverAir {
    kind: CoverKind,
    legs: [PinnedBoundTransitionAir; 2],
    delta_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for PinnedCoverAir {
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let w = self.kind.leg_width();
        let a = local.prefix(w);
        let rest = local.suffix(w);
        let b = rest.prefix(w);
        let t = rest.suffix(w);
        let mut cs: Vec<Ea4> = Vec::new();
        push_bound_transition_constraints(&mut cs, &a, &self.legs[0]);
        push_bound_transition_constraints(&mut cs, &b, &self.legs[1]);
        // the total: a.delta + b.delta + carry_in == t.total + 2^16·carry_out, limb by limb, boolean carries, no final carry
        let base = Ea4::from(Fa4::from_u64(1u64 << LIMB16_BITS));
        for i in 0..N_LIMB16 {
            let cin = if i == 0 { Ea4::ZERO } else { t[CV_CARRY + i - 1] };
            let cout = t[CV_CARRY + i];
            cs.push(a[T_MDELTA + i] + b[T_MDELTA + i] + cin - t[CV_TOT + i] - base * cout);
            cs.push(cout * (cout - Ea4::ONE));
        }
        cs.push(t[CV_CARRY + N_LIMB16 - 1]);
        push_commit_open_constraints(&mut cs, &t, CV_TOT, CV_BLIND, CV_COMMIT, CV_INTER, CV_VBITS);
        for c in 0..DIGEST_LANES {
            cs.push(t[CV_COMMIT + c] - self.delta_commit[c]);
        }
        fold_constraints(cs, self.legs[0].gamma)
    }
}

fn cover_statement_bind(kind: CoverKind, c: &CoverCommits) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(2 * 4 * DIGEST_LANES + DIGEST_LANES + 1);
    v.push(Fa4::from_u64(kind.domain()));
    for l in &c.legs {
        for d in [l.reserve_commit, l.minted_commit, l.new_reserve_commit, l.new_minted_commit] {
            v.extend(d.iter().map(|x| Fa4::from_u64(*x)));
        }
    }
    v.extend(c.delta_commit.iter().map(|x| Fa4::from_u64(*x)));
    v
}

fn cover_air(kind: CoverKind, c: &CoverCommits, backings: [Backing; 2], gamma: Ea4) -> PinnedCoverAir {
    let leg = |i: usize| {
        let l = &c.legs[i];
        // the peg-in layout pins (current → a-side, post → s-side); the peg-out layout reads it backwards (post on the a-side)
        let (ra, ma, rs, ms) = match kind {
            CoverKind::PegIn => (l.reserve_commit, l.minted_commit, l.new_reserve_commit, l.new_minted_commit),
            CoverKind::PegOut => (l.new_reserve_commit, l.new_minted_commit, l.reserve_commit, l.minted_commit),
        };
        PinnedBoundTransitionAir {
            gamma,
            ratio_bps: backings[i],
            reserve_commit: commit_to_ea4(ra),
            minted_commit: commit_to_ea4(ma),
            new_reserve_commit: commit_to_ea4(rs),
            new_minted_commit: commit_to_ea4(ms),
            gate: kind.gate(),
        }
    };
    PinnedCoverAir { kind, legs: [leg(0), leg(1)], delta_commit: commit_to_ea4(c.delta_commit) }
}

/// The cover's one-row trace (both legs, then the total block) and its commitments. `None` when either leg's own trace
/// refuses (an underflow, a backing or redeem rule failing) or the deltas' sum overflows.
fn cover_trace(kind: CoverKind, legs: &[CoverLeg; 2], d_blind: Digest) -> Option<(Vec<Vec<Fa4>>, CoverCommits)> {
    let mut cols: Vec<Vec<Fa4>> = Vec::new();
    let mut commits = Vec::with_capacity(2);
    for l in legs {
        let (c, tc) = match kind {
            CoverKind::PegIn => bound_transition_trace(l.reserve, l.minted, l.delta_reserve, l.delta_minted, l.r_blind, l.m_blind, l.nr_blind, l.nm_blind, l.backing, TransitionGate::Marginal)?,
            CoverKind::PegOut => pegout_trace(l.reserve, l.minted, l.delta_reserve, l.delta_minted, l.r_blind, l.m_blind, l.nr_blind, l.nm_blind, l.backing)?,
        };
        if c.len() != kind.leg_width() {
            return None;
        }
        cols.extend(c);
        commits.push(tc);
    }
    let total = add256(legs[0].delta_minted, legs[1].delta_minted)?;
    let (al, bl) = (u256_to_limbs16(legs[0].delta_minted), u256_to_limbs16(legs[1].delta_minted));
    let tl = u256_to_limbs16(total);
    let mut t: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; CV_WIDTH];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let s = al[i] + bl[i] + cin;
        cin = s >> LIMB16_BITS;
        t[CV_TOT + i].fill(Fa4::from_u64(tl[i]));
        t[CV_CARRY + i].fill(Fa4::from_u64(cin));
    }
    if cin != 0 {
        return None;
    }
    for i in 0..DIGEST_LANES {
        t[CV_BLIND + i].fill(Fa4::from_u64(d_blind[i]));
    }
    let dc = place_commit_open(&mut t, tl, d_blind, CV_INTER, CV_VBITS);
    for i in 0..DIGEST_LANES {
        t[CV_COMMIT + i].fill(Fa4::from_u64(dc[i]));
    }
    cols.extend(t);
    Some((cols, CoverCommits { legs: [commits[0], commits[1]], delta_commit: dc }))
}

/// ⭐⭐ §19.5b — PROVE a two-ledger cover: `legs` in the chain's ledger order (native, Monero), each with its own deltas (the
/// ledger that does not move carries zeros), and `d_blind` the blind of the object's delta commitment (the peg-in's mint
/// blind, the peg-out's burn blind). Returns the carrier and its commitments. `None` exactly when a leg's own gate refuses.
pub fn prove_cover_carrier(kind: CoverKind, legs: &[CoverLeg; 2], d_blind: Digest) -> Option<(Vec<u8>, CoverCommits)> {
    let (cols2, commits) = cover_trace(kind, legs, d_blind)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = cover_statement_bind(kind, &commits);
    let backings = [legs[0].backing, legs[1].backing];
    let bytes = prove_value_carrier(cols, |g| cover_air(kind, &commits, backings, g), &statement_bind)?;
    Some((bytes, commits))
}

/// ⭐⭐ §19.5b — VERIFY a two-ledger cover against this node's CURRENT pairs and the claimed POST pairs of BOTH ledgers, both
/// backings and the object's one delta commitment. Fail-closed on any leg's rule, a sum that is not the committed delta, or a
/// proof built for any other commitment set.
#[must_use]
pub fn verify_cover_carrier(bytes: &[u8], kind: CoverKind, commits: &CoverCommits, backings: [Backing; 2]) -> bool {
    if backings.iter().any(|b| b.ks().is_none()) {
        return false; // DB-362: a wider multiplier admits the alias
    }
    let statement_bind = cover_statement_bind(kind, commits);
    verify_value_carrier(bytes, |g| cover_air(kind, commits, backings, g), &statement_bind, (REC_DECIDER_FOLDING, 2 * kind.leg_width() + CV_WIDTH))
}

// ── #75 brick 4 — the confidential VALIDATOR-BOND accumulator carrier ─────────────────────────────────────
//
// The bonded-stake total is the OTHER plaintext consensus value leak (`ValidatorSet.total_bond` — a re-executing
// node sums the DAG's total stake). Same cure as the peg: the total lives ONLY as a value-hiding commitment,
// advanced by a WHIR-bound CONSERVATION proof — admit `total+bond==new_total`, unbond/slash the reverse. There is
// NO 150% backing (a bond IS the security deposit, not an issuance against collateral), so this is conservation +
// the two commitment openings ONLY — the `BoundReserveAir` shape, pinned + WHIR-bound like the peg carrier. The
// finality gate ALREADY proves ≥2/3 bonded weight in ZK (#51-55), so the plaintext accumulator is redundant to
// consensus; this closes it. 100% private: the node holds only the opaque bond commitment, never a stake total.

/// Bond-accumulator variant: conservation `a + delta == s` bound to the two CONSENSUS-KNOWN bond commitments
/// (`a→a_commit`, `s→s_commit`, pinned), reusing the BR_ shared layout. No backing.
struct PinnedBondAir {
    gamma: Ea4,
    a_commit: [Ea4; DIGEST_LANES],
    s_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for PinnedBondAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment opening). A gate that declares less
        // than the permutation's degree truncates the sumcheck and even an HONEST proof fails.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_conservation_constraints(&mut cs, local, BR_RES, BR_DEP, BR_NEW, BR_CARRY);
        push_commit_open_constraints(&mut cs, local, BR_RES, BR_RBLIND, BR_RCOMMIT, BR_RINTER, BR_RVBITS);
        push_commit_open_constraints(&mut cs, local, BR_NEW, BR_NBLIND, BR_NCOMMIT, BR_NINTER, BR_NVBITS);
        for c in 0..DIGEST_LANES {
            cs.push(local[BR_RCOMMIT + c] - self.a_commit[c]);
            cs.push(local[BR_NCOMMIT + c] - self.s_commit[c]);
        }
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn bond_statement_bind(a_commit: Digest, s_commit: Digest) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(8);
    for d in [a_commit, s_commit] {
        for x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v
}

/// PROVE a WHIR-bound bond-accumulator conservation `a + delta == s` (openings bound to `a_commit`, `s_commit`).
/// Returns the carrier bytes + `(a_commit, s_commit)`. For an ADMIT call with `(a=old_total, delta=bond)` (s is
/// the larger new total); for an UNBOND/SLASH call with `(a=new_total, delta=bond)` (s is the larger old total).
/// `None` on 256-bit overflow.
/// ⛔ VACUOUS ON ITS DELTA (found 2026-09-29): `delta` is a free witness — the proof binds the two openings and nothing
/// about their relation. Replaced by [`prove_transition_carrier`] with `TransitionDomain::Bond`; kept compiling only
/// until `validator.rs` passes the bond note's amount commitment as the delta, then deleted with the `BR_` shape.
#[deprecated(since = "2026-09-29", note = "the delta is unbound — use prove_transition_carrier(.., TransitionDomain::Bond)")]
pub fn prove_bond_transition_carrier(a_total: U256, delta: U256, a_blind: Digest, s_blind: Digest) -> Option<(Vec<u8>, Digest, Digest)> {
    let (cols2, ac, sc) = bound_reserve_trace(a_total, delta, a_blind, s_blind)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = bond_statement_bind(ac, sc);
    let make = |g: Ea4| PinnedBondAir { gamma: g, a_commit: commit_to_ea4(ac), s_commit: commit_to_ea4(sc) };
    let bytes = prove_value_carrier(cols, make, &statement_bind)?;
    Some((bytes, ac, sc))
}

/// VERIFY a WHIR-bound bond-accumulator transition: `open(a_commit) + delta == open(s_commit)`, conservation +
/// both openings bound. Fail-closed on a non-conserving delta, a value not opening to its committed digest, or a
/// proof built for any other commitment pair. The node passes `(a,s)` per direction: admit `(old, new)`, unbond
/// `(new, old)` — either way the SMALLER total is `a` and the LARGER is `s`.
#[must_use]
/// ⛔ VACUOUS ON ITS DELTA (found 2026-09-29): accepts ANY `(a_commit, s_commit)` whose openings the prover knows — see
/// the calibration pin. Replaced by [`verify_transition_carrier`] with `TransitionDomain::Bond`.
#[deprecated(since = "2026-09-29", note = "the delta is unbound — use verify_transition_carrier(.., TransitionDomain::Bond)")]
pub fn verify_bond_transition_carrier(bytes: &[u8], a_commit: Digest, s_commit: Digest) -> bool {
    let statement_bind = bond_statement_bind(a_commit, s_commit);
    let make = |g: Ea4| PinnedBondAir { gamma: g, a_commit: commit_to_ea4(a_commit), s_commit: commit_to_ea4(s_commit) };
    verify_value_carrier(bytes, make, &statement_bind, (REC_DECIDER_FOLDING, BR_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE DELTA-BOUND TRANSITION CARRIER (2026-09-29): `a + delta = s` over THREE openings — `a`, the delta and `s`, each
// committed and range-bound — under a DOMAIN word. It is what the bond-accumulator carrier above claimed to be and is
// not: `PinnedBondAir` (as `BoundReserveAir` did, deleted) runs the conservation with `BR_DEP` a FREE witness — no range bits, no
// commitment — so `a_i + b_i + cin = s_i + cout·2^16` is satisfiable for ANY two opened totals (`b_i := s_i − a_i` in
// the field, carries 0); the carrier proves two openings and nothing about their relation, and `validator::
// verify_bond_admit / verify_bond_reduce` accept any `new_bond_commit` the prover can open. MEASURED in the calibration
// pin below (an admit from 5,000 to 1,000,000,000 with no bond behind it verifies on the old shape). Here the delta's
// opening range-binds its limbs (DB-362: an opened value is canonical 16-bit limbs), so the conservation is an INTEGER
// identity and the statement `(a_commit, delta_commit, s_commit)` pins all three values. Domains: the confidential
// BONDED-STAKE total (admit `(old, bond, new)`, unbond / slash `(new, bond, old)` — the node passes the bond note's
// amount commitment as the delta) and the STABILITY POOL's USDm total (docs/LIQUIDATION-TRUSTLESS-SPEC.md §2.3, §9.1:
// deposit `(old, v, new)` with `DC = commit(v)` welded to the depositor's note; liquidation `(new, C, old)` with the
// SAME `DC` the amount carrier proves — one digest, one binding, no second spelling of C).
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

const TR_A: usize = 0;
const TR_DELTA: usize = TR_A + N_LIMB16;
const TR_S: usize = TR_DELTA + N_LIMB16;
const TR_CARRY: usize = TR_S + N_LIMB16;
const TR_ABLIND: usize = TR_CARRY + N_LIMB16;
const TR_DBLIND: usize = TR_ABLIND + DIGEST_LANES;
const TR_SBLIND: usize = TR_DBLIND + DIGEST_LANES;
const TR_ACOMMIT: usize = TR_SBLIND + DIGEST_LANES;
const TR_DCOMMIT: usize = TR_ACOMMIT + DIGEST_LANES;
const TR_SCOMMIT: usize = TR_DCOMMIT + DIGEST_LANES;
const TR_AINTER: usize = TR_SCOMMIT + DIGEST_LANES;
const TR_DINTER: usize = TR_AINTER + T_OPEN;
const TR_SINTER: usize = TR_DINTER + T_OPEN;
const TR_AVBITS: usize = TR_SINTER + T_OPEN;
const TR_DVBITS: usize = TR_AVBITS + RANGE16_COLS;
const TR_SVBITS: usize = TR_DVBITS + RANGE16_COLS;
const TR_WIDTH: usize = TR_SVBITS + RANGE16_COLS;

/// Which committed total a transition carrier advances. The word is bound into the statement, so a proof for one total
/// verifies for no other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionDomain {
    /// The confidential bonded-stake total (#75 brick 4): admit `(old, bond, new)`, unbond / slash `(new, bond, old)`.
    Bond,
    /// The Stability Pool's USDm total (LIQUIDATION spec §2.3): deposit `(old, v, new)`, liquidation `(new, C, old)`.
    StabilityPool,
    /// DB-237 — the committed USDm SUPPLY a stake reward mints into: `(minted, r, new_minted)`, the delta commitment being
    /// the stake carrier's public `reward_commit`, so the supply grows by exactly the reward the gate computed.
    Yield,
    /// LIQUIDATION §10.2 increment 3 — the RETIRE leg: the PSM's committed supply `(new_minted, C, minted)`, the delta
    /// being the amount carrier's `DC` (the same `C` the pool burns).
    Retire,
    /// LIQUIDATION §10.2 increment 3 — the SEIZE leg: the PSM's committed reserve `(new_reserve, S, reserve)`, the delta
    /// being the amount carrier's `DS`.
    Seize,
    /// SAFE AT SCALE (custody vaults) — the USDm one vault stands behind: `(minted of its Bitcoin ledger, minted of its
    /// Monero ledger, their sum)`, the two being the ledgers' own post commitments of one peg and the sum a commitment that
    /// lives in that object only. The plain carrier then bounds the sum by the vault's public authority. A statement
    /// domain, not a gate: the constraints are the transition's own (`a + delta = s`, three openings).
    VaultSum,
    /// SAFE AT SCALE (custody vaults) — a retiring vault's ledger merged into another's: `(the receiving ledger's total, the
    /// retiring ledger's total, the receiving ledger's new total)`, once for the reserve and once for the minted supply, the
    /// first two being the chain's own commitments for the two ledgers. A statement domain, not a gate.
    VaultMerge,
    /// SAFE AT SCALE (custody vaults) — a vault's reserve less the fee its custody paid a foreign chain to move its own
    /// coins: `(the reserve after, the fee, the reserve before)`, the fee a PUBLIC amount under a public blind every node
    /// recomputes, the reserve before the chain's own commitment. A statement domain, not a gate.
    ReserveCost,
    /// SAFE AT SCALE (custody vaults, spec §3g) — PART of one vault's ledger moved to another's: the giver's side
    /// `(its total after, the part, its total now)` and the receiver's side `(its total now, the part, its total after)`,
    /// once for the reserve and once for the minted supply. The SAME part commitment stands in both statements of a word,
    /// and each "now" is the chain's own commitment, so what leaves one ledger is what the other gains. A statement
    /// domain, not a gate.
    VaultRebalance,
}
impl TransitionDomain {
    fn word(self) -> u64 {
        match self {
            TransitionDomain::Bond => 0x5452_424F_4E44_3131,          // "TRBOND11"
            TransitionDomain::StabilityPool => 0x5452_504F_4F4C_3131, // "TRPOOL11"
            TransitionDomain::Yield => 0x5452_5949_454C_4431,         // "TRYIELD1"
            TransitionDomain::Retire => 0x5452_5245_5449_5231,        // "TRRETIR1"
            TransitionDomain::Seize => 0x5452_5345_495A_4531,         // "TRSEIZE1"
            TransitionDomain::VaultSum => 0x5452_5641_5553_554D,      // "TRVAUSUM"
            TransitionDomain::VaultMerge => 0x5452_5641_554D_5247,    // "TRVAUMRG"
            TransitionDomain::ReserveCost => 0x5452_5253_5643_4F53,   // "TRRSVCOS"
            TransitionDomain::VaultRebalance => 0x5452_5641_5552_4542, // "TRVAUREB"
        }
    }
}

struct TransitionAir {
    gamma: Ea4,
    /// `(a_commit, delta_commit, s_commit)`.
    commits: [[Ea4; DIGEST_LANES]; 3],
}
impl AirConstraint for TransitionAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment openings); declaring less truncates the sumcheck.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        push_conservation_constraints(&mut cs, local, TR_A, TR_DELTA, TR_S, TR_CARRY);
        for (i, (v, blind, commit, inter, vbits)) in [
            (TR_A, TR_ABLIND, TR_ACOMMIT, TR_AINTER, TR_AVBITS),
            (TR_DELTA, TR_DBLIND, TR_DCOMMIT, TR_DINTER, TR_DVBITS),
            (TR_S, TR_SBLIND, TR_SCOMMIT, TR_SINTER, TR_SVBITS),
        ]
        .into_iter()
        .enumerate()
        {
            push_commit_open_constraints(&mut cs, local, v, blind, commit, inter, vbits);
            for c in 0..DIGEST_LANES {
                cs.push(local[commit + c] - self.commits[i][c]);
            }
        }
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn transition_statement_bind(commits: &[Digest; 3], domain: TransitionDomain) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(1 + 3 * DIGEST_LANES);
    v.push(Fa4::from_u64(domain.word()));
    for d in commits {
        for &x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v
}

fn transition_air(commits: &[Digest; 3]) -> impl Fn(Ea4) -> TransitionAir {
    let commits = [commit_to_ea4(commits[0]), commit_to_ea4(commits[1]), commit_to_ea4(commits[2])];
    move |gamma| TransitionAir { gamma, commits }
}

/// Lay `a + delta = s` with the three openings; `None` on a 256-bit overflow of `s`.
fn transition_trace(a: U256, delta: U256, blinds: &[Digest; 3]) -> Option<(Vec<Vec<Fa4>>, [Digest; 3])> {
    let s = add256(a, delta)?;
    let (al, dl, sl) = (u256_to_limbs16(a), u256_to_limbs16(delta), u256_to_limbs16(s));
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; TR_WIDTH];
    fill_cols(&mut cols, TR_A, &al);
    fill_cols(&mut cols, TR_DELTA, &dl);
    fill_cols(&mut cols, TR_S, &sl);
    let mut carry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let t = al[i] + dl[i] + cin;
        debug_assert_eq!(t & LIMB16_MASK, sl[i]);
        cin = t >> LIMB16_BITS;
        carry[i] = cin;
    }
    fill_cols(&mut cols, TR_CARRY, &carry);
    for (b, base) in blinds.iter().zip([TR_ABLIND, TR_DBLIND, TR_SBLIND]) {
        fill_cols(&mut cols, base, b);
    }
    let ac = place_commit_open(&mut cols, al, blinds[0], TR_AINTER, TR_AVBITS);
    let dc = place_commit_open(&mut cols, dl, blinds[1], TR_DINTER, TR_DVBITS);
    let sc = place_commit_open(&mut cols, sl, blinds[2], TR_SINTER, TR_SVBITS);
    let commits = [ac, dc, sc];
    for (dg, base) in commits.iter().zip([TR_ACOMMIT, TR_DCOMMIT, TR_SCOMMIT]) {
        fill_cols(&mut cols, base, dg);
    }
    Some((cols, commits))
}

/// PROVE a delta-bound transition `a + delta = s` of the `domain` total: `blinds` = `(a, delta, s)` blinds — the two the
/// chain holds for the totals and the delta's (the bond note's / the deposit's / the amount carrier's `c_blind`). Returns
/// the carrier bytes and `[a_commit, delta_commit, s_commit]`. `None` on a 256-bit overflow.
#[must_use]
pub fn prove_transition_carrier(a: U256, delta: U256, blinds: &[Digest; 3], domain: TransitionDomain) -> Option<(Vec<u8>, [Digest; 3])> {
    let (cols2, commits) = transition_trace(a, delta, blinds)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = transition_statement_bind(&commits, domain);
    let bytes = prove_value_carrier(cols, transition_air(&commits), &statement_bind)?;
    Some((bytes, commits))
}

/// VERIFY a delta-bound transition against `[a_commit, delta_commit, s_commit]` and its domain: the caller passes the
/// SMALLER total as `a` (admit / deposit: the old total; unbond / slash / liquidation: the new total). Fail-closed on a
/// value not opening to its digest, a non-conserving triple, another domain, or another delta.
#[must_use]
pub fn verify_transition_carrier(bytes: &[u8], commits: &[Digest; 3], domain: TransitionDomain) -> bool {
    if bytes.is_empty() {
        return false;
    }
    let statement_bind = transition_statement_bind(commits, domain);
    verify_value_carrier(bytes, transition_air(commits), &statement_bind, (REC_DECIDER_FOLDING, TR_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE STABILITY POOL'S (P, S) STEP (docs/LIQUIDATION-TRUSTLESS-SPEC.md §9.3, 2026-09-29): Liquity's two running
// products, kept as COMMITTED pool words (a public `P` would publish each liquidation's share of the hidden aggregate),
// advanced at every liquidation by one carrier over the openings of the pool total `T` (before), the retired `C` (the
// amount carrier's `DC`), the seized `S_c` (`DS`), and the old / new `(P, S)`:
//
//     P_new · T + r₃ = P_old · (T − C),   0 ≤ r₃ < T        (depositors' claims scale by (T − C)/T, rounded DOWN)
//     S_new · T + r₄ = S_old · T + S_c · P_old,   0 ≤ r₄ < T   (collateral gain per P-scaled unit, rounded DOWN)
//
// Both round against the depositor: the pool never owes more than it holds. Every product is HIDDEN × HIDDEN (the
// 12-bit schoolbook over the openings' range bits — `T − C` is the range-bound slack of a borrow chain, whose bits the
// multiply reads directly); `r₃`, `r₄` ARE the slacks of the two difference chains (their upper limbs pinned zero, their
// low limbs compared below `T`), so no value is witnessed twice. `P` carries a fixed scale of 2^128; the carrier's one
// PUBLIC output is the epoch-close flag `close = (P_new < 2^64)` — a full drain (`C = T`) gives `P_new = 0` and closes
// too — decided in-circuit from `P_new`'s upper limbs through a limb-sum inverse, so the node (which holds only
// commitments) learns exactly one bit: whether the epoch resets. Native twin: `pool_step`.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Domain word of the pool-step carrier's transcript bind.
pub const LIQ_POOL_STEP_DOMAIN: u64 = 0x4C49_5150_5354_4550; // "LIQPSTEP"
/// The fixed scale of `P`: a fresh epoch starts at `P = 2^128`.
pub const POOL_P_SCALE_BITS: u32 = 128;
/// The epoch closes when `P` falls below `2^64` (or the pool drains): the four low limbs are then all that is left.
const POOL_P_FLOOR_LIMBS: usize = 4;
/// A 256 × 256 product's width in 16-bit limbs.
const HP: usize = hh_p16(N_LIMB16);
/// One 256 × 256 hidden-multiply block.
const HB: usize = mulhh_cols(N_LIMB16);
/// A difference chain over `n` limbs: slack, borrow, slack bits.
const fn ge_block(n: usize) -> usize {
    n * (2 + N_LIMB16)
}

// The pool-step layout: seven openings (T, C, S_c, P_old, P_new, S_old, S_new), the T − C chain, five products, the
// two remainder chains with their below-T compares, the S-side add, the epoch-close witness.
const PS_T: usize = 0;
const PS_C: usize = PS_T + N_LIMB16;
const PS_SC: usize = PS_C + N_LIMB16;
const PS_PO: usize = PS_SC + N_LIMB16;
const PS_PN: usize = PS_PO + N_LIMB16;
const PS_SO: usize = PS_PN + N_LIMB16;
const PS_SN: usize = PS_SO + N_LIMB16;
const PS_BLIND: usize = PS_SN + N_LIMB16; // 7 × DIGEST_LANES
const PS_COMMIT: usize = PS_BLIND + 7 * DIGEST_LANES; // 7 × DIGEST_LANES
const PS_INTER: usize = PS_COMMIT + 7 * DIGEST_LANES; // 7 × T_OPEN
const PS_VBITS: usize = PS_INTER + 7 * T_OPEN; // 7 × RANGE16_COLS
const PS_GD: usize = PS_VBITS + 7 * RANGE16_COLS; // D = T − C (16 limbs): slack = D, its bits are the multiply's operand
const PS_M1: usize = PS_GD + ge_block(N_LIMB16); // P_new · T
const PS_M2: usize = PS_M1 + HB; // P_old · D
const PS_M3: usize = PS_M2 + HB; // S_new · T
const PS_M4: usize = PS_M3 + HB; // S_old · T
const PS_M5: usize = PS_M4 + HB; // S_c · P_old
const PS_GP: usize = PS_M5 + HB; // M2 − M1 = r₃ (33 limbs; upper limbs zero)
const PS_GPR: usize = PS_GP + ge_block(HP); // T − r₃ − 1 ≥ 0
const PS_ADD: usize = PS_GPR + ge_block(N_LIMB16); // M4 + M5: sum (33) + carries (33)
const PS_GS: usize = PS_ADD + 2 * HP; // (M4 + M5) − M3 = r₄
const PS_GSR: usize = PS_GS + ge_block(HP); // T − r₄ − 1 ≥ 0
const PS_SMALL: usize = PS_GSR + ge_block(N_LIMB16); // the epoch-close witness: 1 ⇔ P_new's upper limbs are all zero
const PS_SMALL_INV: usize = PS_SMALL + 1; // the inverse of P_new's upper-limb sum when it is not zero
const PS_WIDTH: usize = PS_SMALL_INV + 1;

/// The seven committed values of one pool step, in layout order.
const PS_VALUES: [usize; 7] = [PS_T, PS_C, PS_SC, PS_PO, PS_PN, PS_SO, PS_SN];

/// `a · b` for two 256-bit values as 33 sixteen-bit limbs (the hidden multiply's native twin).
fn mul256_wide(a: &[u64; N_LIMB16], b: &[u64; N_LIMB16]) -> Vec<u64> {
    hh_native(a, b).2
}

/// `n / d` and `n % d` over limb arrays (`d ≠ 0`, both little-endian 16-bit limbs) — binary long division, the
/// native twin of "a product plus a range-bound remainder". `None` for a zero divisor: there is no quotient to default.
fn limbs_divrem(n: &[u64], d: &[u64]) -> Option<(Vec<u64>, Vec<u64>)> {
    if d.iter().all(|&l| l == 0) {
        return None;
    }
    let w = n.len().max(d.len());
    let widen = |v: &[u64]| -> Vec<u64> { (0..w).map(|i| if i < v.len() { v[i] } else { 0 }).collect() };
    let (n, d) = (widen(n), widen(d));
    let mut q = vec![0u64; w];
    let mut r = vec![0u64; w];
    for bit in (0..w * 16).rev() {
        // r = 2r + bit
        let mut carry = (n[bit / 16] >> (bit % 16)) & 1;
        for l in r.iter_mut() {
            let t = (*l << 1) | carry;
            *l = t & LIMB16_MASK;
            carry = t >> 16;
        }
        if carry != 0 {
            return None; // r < d fits the width, so a carry out here is an inconsistency, refused
        }
        if limbs_ge(&r, &d) {
            r = limbs_sub(&r, &d)?;
            q[bit / 16] |= 1 << (bit % 16);
        }
    }
    Some((q, r))
}

/// ⭐ THE ONE POOL-STEP RULE, natively (spec §9.3): `(P_new, S_new, close)` for a liquidation retiring `c` and seizing
/// `s_c` against a pool of `t` under `(p_old, s_old)`. `None` when `c > t` (the amount rule caps `C` at the pool), `t = 0`,
/// or `S_new` does not fit 256 bits. Round DOWN both ways; `close` iff `P_new < 2^64` (a drain gives `P_new = 0`).
#[must_use]
pub fn pool_step(t: U256, c: U256, s_c: U256, p_old: U256, s_old: U256) -> Option<(U256, U256, bool)> {
    let d = sub256(t, c)?;
    let (tl, dl, scl, pol, sol) = (u256_to_limbs16(t), u256_to_limbs16(d), u256_to_limbs16(s_c), u256_to_limbs16(p_old), u256_to_limbs16(s_old));
    let (p_new, _) = limbs_divrem(&mul256_wide(&pol, &dl), &tl)?;
    let p_new = limbs_to_u256(&p_new)?;
    let num = limbs_add(&mul256_wide(&sol, &tl), &mul256_wide(&scl, &pol))?;
    let (s_new, _) = limbs_divrem(&num, &tl)?;
    let s_new = limbs_to_u256(&s_new)?;
    let close = u256_to_limbs16(p_new)[POOL_P_FLOOR_LIMBS..].iter().all(|&l| l == 0);
    Some((p_new, s_new, close))
}

struct PoolStepAir {
    gamma: Ea4,
    /// `(T, C, S_c, P_old, P_new, S_old, S_new)`.
    commits: [[Ea4; DIGEST_LANES]; 7],
    close: bool,
}
impl AirConstraint for PoolStepAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment openings); declaring less truncates the sumcheck.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        for (i, &v) in PS_VALUES.iter().enumerate() {
            push_commit_open_constraints(&mut cs, local, v, PS_BLIND + i * DIGEST_LANES, PS_COMMIT + i * DIGEST_LANES, PS_INTER + i * T_OPEN, PS_VBITS + i * RANGE16_COLS);
            for c in 0..DIGEST_LANES {
                cs.push(local[PS_COMMIT + i * DIGEST_LANES + c] - self.commits[i][c]);
            }
        }
        let vbits = |i: usize| PS_VBITS + i * RANGE16_COLS; // (T, C, S_c, P_old, P_new, S_old, S_new) = 0..7
        let diff = |x: usize, y: usize, n: usize, less_one: bool| -> Vec<Ea4> {
            (0..n).map(|i| local[x + i] - local[y + i] - if less_one && i == 0 { Ea4::ONE } else { Ea4::ZERO }).collect()
        };
        // D = T − C as the slack of a borrow chain: its limbs are range-bound by its own bits, which the P_old · D
        // multiply reads as its second operand
        push_ge_n_diff_constraints(&mut cs, local, &diff(PS_T, PS_C, N_LIMB16, false), PS_GD, PS_GD + N_LIMB16, PS_GD + 2 * N_LIMB16);
        let gd_bits = PS_GD + 2 * N_LIMB16;
        push_mulhh_constraints(&mut cs, local, vbits(4), vbits(0), N_LIMB16, PS_M1); // P_new · T
        push_mulhh_constraints(&mut cs, local, vbits(3), gd_bits, N_LIMB16, PS_M2); // P_old · D
        push_mulhh_constraints(&mut cs, local, vbits(6), vbits(0), N_LIMB16, PS_M3); // S_new · T
        push_mulhh_constraints(&mut cs, local, vbits(5), vbits(0), N_LIMB16, PS_M4); // S_old · T
        push_mulhh_constraints(&mut cs, local, vbits(2), vbits(3), N_LIMB16, PS_M5); // S_c · P_old
        let p16 = |m: usize| m + mulhh_p16_off(N_LIMB16);
        // r₃ = P_old·D − P_new·T is the chain's slack: range-bound limbs, upper limbs zero, low limbs below T
        push_ge_n_diff_constraints(&mut cs, local, &diff(p16(PS_M2), p16(PS_M1), HP, false), PS_GP, PS_GP + HP, PS_GP + 2 * HP);
        for i in N_LIMB16..HP {
            cs.push(local[PS_GP + i]);
        }
        push_ge_n_diff_constraints(&mut cs, local, &diff(PS_T, PS_GP, N_LIMB16, true), PS_GPR, PS_GPR + N_LIMB16, PS_GPR + 2 * N_LIMB16);
        // S side: M4 + M5 as a carried add, then r₄ = (M4 + M5) − S_new·T likewise
        push_add_n_constraints(&mut cs, local, p16(PS_M4), p16(PS_M5), PS_ADD, PS_ADD + HP, HP);
        push_ge_n_diff_constraints(&mut cs, local, &diff(PS_ADD, p16(PS_M3), HP, false), PS_GS, PS_GS + HP, PS_GS + 2 * HP);
        for i in N_LIMB16..HP {
            cs.push(local[PS_GS + i]);
        }
        push_ge_n_diff_constraints(&mut cs, local, &diff(PS_T, PS_GS, N_LIMB16, true), PS_GSR, PS_GSR + N_LIMB16, PS_GSR + 2 * N_LIMB16);
        // the epoch-close flag: small = 1 ⇔ P_new's upper limbs sum to zero (a limb sum < 12·2^16 is zero iff every
        // limb is), decided through an inverse witness and pinned to the statement's public bit
        let (small, inv) = (local[PS_SMALL], local[PS_SMALL_INV]);
        let mut up = Ea4::ZERO;
        for l in POOL_P_FLOOR_LIMBS..N_LIMB16 {
            up += local[PS_PN + l];
        }
        cs.push(small * (small - Ea4::ONE));
        cs.push(small * up);
        cs.push(up * inv - (Ea4::ONE - small));
        cs.push(small - if self.close { Ea4::ONE } else { Ea4::ZERO });
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn pool_step_statement_bind(commits: &[Digest; 7], close: bool) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(2 + 7 * DIGEST_LANES);
    v.push(Fa4::from_u64(LIQ_POOL_STEP_DOMAIN));
    for d in commits {
        for &x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v.push(Fa4::from_u64(u64::from(close)));
    v
}

fn pool_step_air(commits: &[Digest; 7], close: bool) -> impl Fn(Ea4) -> PoolStepAir {
    let commits: [[Ea4; DIGEST_LANES]; 7] = core::array::from_fn(|i| commit_to_ea4(commits[i]));
    move |gamma| PoolStepAir { gamma, commits, close }
}

/// The openings of one pool step: `(T, C, S_c, P_old, S_old)` are the chain's and the liquidation's; `(P_new, S_new)`
/// are what the rule yields. Seven blinds in the same order as the values.
pub struct PoolStepOpening {
    pub t: U256,
    pub c: U256,
    pub s_c: U256,
    pub p_old: U256,
    pub s_old: U256,
    pub blinds: [Digest; 7],
}

/// Lay the pool-step trace for a claimed `(P_new, S_new)`. `None` when `C > T`, a product overflows, or a chain has no
/// witness — a `P_new` or `S_new` that is not the rounded-down quotient (too small: the remainder reaches `T`; too large:
/// the difference is negative). The epoch-close witness is laid from `P_new` itself.
fn pool_step_trace(o: &PoolStepOpening, p_new: U256, s_new: U256) -> Option<(Vec<Vec<Fa4>>, [Digest; 7], bool)> {
    let vals = [o.t, o.c, o.s_c, o.p_old, p_new, o.s_old, s_new];
    let limbs: [[u64; N_LIMB16]; 7] = core::array::from_fn(|i| u256_to_limbs16(vals[i]));
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; PS_WIDTH];
    let mut commits = [[0u64; DIGEST_LANES]; 7];
    for i in 0..7 {
        fill_cols(&mut cols, PS_VALUES[i], &limbs[i]);
        fill_cols(&mut cols, PS_BLIND + i * DIGEST_LANES, &o.blinds[i]);
        commits[i] = place_commit_open(&mut cols, limbs[i], o.blinds[i], PS_INTER + i * T_OPEN, PS_VBITS + i * RANGE16_COLS);
        fill_cols(&mut cols, PS_COMMIT + i * DIGEST_LANES, &commits[i]);
    }
    let (tl, cl, scl, pol, pnl, sol, snl) = (limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6]);
    let diff = |x: &[u64], y: &[u64], less_one: bool| -> Vec<i64> { (0..x.len()).map(|i| x[i] as i64 - y[i] as i64 - i64::from(less_one && i == 0)).collect() };
    // D = T − C
    if !place_ge_n_diff(&mut cols, &diff(&tl, &cl, false), PS_GD, PS_GD + N_LIMB16, PS_GD + 2 * N_LIMB16) {
        return None;
    }
    let dl: [u64; N_LIMB16] = u256_to_limbs16(sub256(o.t, o.c)?);
    let m1 = place_mulhh(&mut cols, &pnl, &tl, PS_M1)?;
    let m2 = place_mulhh(&mut cols, &pol, &dl, PS_M2)?;
    let m3 = place_mulhh(&mut cols, &snl, &tl, PS_M3)?;
    let m4 = place_mulhh(&mut cols, &sol, &tl, PS_M4)?;
    let m5 = place_mulhh(&mut cols, &scl, &pol, PS_M5)?;
    // r₃ = M2 − M1, below T
    if !place_ge_n_diff(&mut cols, &diff(&m2, &m1, false), PS_GP, PS_GP + HP, PS_GP + 2 * HP) {
        return None;
    }
    let r3 = limbs_sub(&m2, &m1)?;
    if r3[N_LIMB16..].iter().any(|&l| l != 0) || !place_ge_n_diff(&mut cols, &diff(&tl, &r3[..N_LIMB16], true), PS_GPR, PS_GPR + N_LIMB16, PS_GPR + 2 * N_LIMB16) {
        return None;
    }
    // r₄ = (M4 + M5) − M3, below T
    let sum = place_add_n(&mut cols, &m4, &m5, PS_ADD, PS_ADD + HP)?;
    if !place_ge_n_diff(&mut cols, &diff(&sum, &m3, false), PS_GS, PS_GS + HP, PS_GS + 2 * HP) {
        return None;
    }
    let r4 = limbs_sub(&sum, &m3)?;
    if r4[N_LIMB16..].iter().any(|&l| l != 0) || !place_ge_n_diff(&mut cols, &diff(&tl, &r4[..N_LIMB16], true), PS_GSR, PS_GSR + N_LIMB16, PS_GSR + 2 * N_LIMB16) {
        return None;
    }
    // the epoch-close witness from P_new's upper limbs
    let up: u64 = pnl[POOL_P_FLOOR_LIMBS..].iter().sum();
    let close = up == 0;
    cols[PS_SMALL].fill(Fa4::from_u64(u64::from(close)));
    cols[PS_SMALL_INV].fill(if close { Fa4::ZERO } else { Fa4::from_u64(up).inverse() });
    Some((cols, commits, close))
}

/// One pool step's proof: the carrier bytes, the seven commitments `(T, C, S_c, P_old, P_new, S_old, S_new)` the
/// liquidation object carries, the new `(P, S)` openings for the bonded set to keep, and the public epoch-close bit.
pub struct PoolStepProof {
    pub bytes: Vec<u8>,
    pub commits: [Digest; 7],
    pub p_new: U256,
    pub s_new: U256,
    pub close: bool,
}

fn prove_pool_step_trace(cols2: Vec<Vec<Fa4>>, commits: &[Digest; 7], close: bool) -> Option<Vec<u8>> {
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    prove_value_carrier(cols, pool_step_air(commits, close), &pool_step_statement_bind(commits, close))
}

/// PROVE one pool step: derive `(P_new, S_new, close)` by the ONE rule and prove it over the seven commitments. `None`
/// when the step has no rule (`C > T`, an empty pool) or a value does not fit.
#[must_use]
pub fn prove_pool_step_carrier(o: &PoolStepOpening) -> Option<PoolStepProof> {
    let (p_new, s_new, close) = pool_step(o.t, o.c, o.s_c, o.p_old, o.s_old)?;
    let (cols, commits, laid_close) = pool_step_trace(o, p_new, s_new)?;
    debug_assert_eq!(close, laid_close);
    let bytes = prove_pool_step_trace(cols, &commits, laid_close)?;
    Some(PoolStepProof { bytes, commits, p_new, s_new, close: laid_close })
}

/// VERIFY a pool-step carrier against the liquidation object's seven commitments and its public epoch-close bit —
/// every node, holding nothing but these. Fail-closed on a value not opening to its digest, a wrong product, a
/// remainder that reaches `T`, a negative difference, or a close bit that is not `P_new`'s.
#[must_use]
pub fn verify_pool_step_carrier(bytes: &[u8], commits: &[Digest; 7], close: bool) -> bool {
    if bytes.is_empty() {
        return false;
    }
    verify_value_carrier(bytes, pool_step_air(commits, close), &pool_step_statement_bind(commits, close), (REC_DECIDER_FOLDING, PS_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// A DEPOSITOR'S WITHDRAWAL (docs/LIQUIDATION-TRUSTLESS-SPEC.md §9.3): what a deposit `d` made at the snapshot
// `(P_dep, S_dep)` is worth under the pool's `(P_now, S_now)` — the current pair, or the closing pair of the epoch the
// deposit was made in — as two rounded-down quotients over COMMITTED values only:
//
//     compounded · P_dep + r₁ = d · P_now,              0 ≤ r₁ < P_dep      (the USDm left of the deposit)
//     gain · P_dep + r₂ = d · (S_now − S_dep),          0 ≤ r₂ < P_dep      (the collateral the deposit earned)
//
// Truncation toward zero: a depositor can never claim a rounding's worth more than the pool holds. The same skeleton as
// the pool step — `S_now − S_dep` is a borrow-chain slack whose bits feed the multiply, the remainders ARE the two
// difference chains' slacks. Native twin: `pool_withdraw`.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Domain word of the withdrawal carrier's transcript bind.
pub const LIQ_WITHDRAW_DOMAIN: u64 = 0x4C49_5157_4452_4157; // "LIQWDRAW"

// The withdrawal layout: seven openings (d, P_dep, S_dep, P_now, S_now, compounded, gain), the S_now − S_dep chain, four
// products, the two remainder chains with their below-P_dep compares.
const WD_D: usize = 0;
const WD_PD: usize = WD_D + N_LIMB16;
const WD_SD: usize = WD_PD + N_LIMB16;
const WD_PN: usize = WD_SD + N_LIMB16;
const WD_SN: usize = WD_PN + N_LIMB16;
const WD_CO: usize = WD_SN + N_LIMB16;
const WD_GA: usize = WD_CO + N_LIMB16;
const WD_BLIND: usize = WD_GA + N_LIMB16;
const WD_COMMIT: usize = WD_BLIND + 7 * DIGEST_LANES;
const WD_INTER: usize = WD_COMMIT + 7 * DIGEST_LANES;
const WD_VBITS: usize = WD_INTER + 7 * T_OPEN;
const WD_GD: usize = WD_VBITS + 7 * RANGE16_COLS; // DS = S_now − S_dep: slack = DS, its bits are a multiply operand
const WD_M1: usize = WD_GD + ge_block(N_LIMB16); // compounded · P_dep
const WD_M2: usize = WD_M1 + HB; // d · P_now
const WD_M3: usize = WD_M2 + HB; // gain · P_dep
const WD_M4: usize = WD_M3 + HB; // d · DS
const WD_G1: usize = WD_M4 + HB; // M2 − M1 = r₁ (33 limbs; upper limbs zero)
const WD_G1R: usize = WD_G1 + ge_block(HP); // P_dep − r₁ − 1 ≥ 0
const WD_G2: usize = WD_G1R + ge_block(N_LIMB16); // M4 − M3 = r₂
const WD_G2R: usize = WD_G2 + ge_block(HP); // P_dep − r₂ − 1 ≥ 0
const WD_WIDTH: usize = WD_G2R + ge_block(N_LIMB16);

/// The seven committed values of one withdrawal, in layout order.
const WD_VALUES: [usize; 7] = [WD_D, WD_PD, WD_SD, WD_PN, WD_SN, WD_CO, WD_GA];

/// ⭐ THE ONE WITHDRAWAL RULE, natively (spec §9.3): `(compounded, gain)` for a deposit `d` made at `(p_dep, s_dep)` under
/// `(p_now, s_now)`, both rounded DOWN. `None` when `s_now < s_dep`, `p_dep = 0`, or a value does not fit 256 bits.
#[must_use]
pub fn pool_withdraw(d: U256, p_dep: U256, s_dep: U256, p_now: U256, s_now: U256) -> Option<(U256, U256)> {
    let ds = sub256(s_now, s_dep)?;
    let (dl, pdl, pnl, dsl) = (u256_to_limbs16(d), u256_to_limbs16(p_dep), u256_to_limbs16(p_now), u256_to_limbs16(ds));
    let (co, _) = limbs_divrem(&mul256_wide(&dl, &pnl), &pdl)?;
    let (ga, _) = limbs_divrem(&mul256_wide(&dl, &dsl), &pdl)?;
    Some((limbs_to_u256(&co)?, limbs_to_u256(&ga)?))
}

struct WithdrawAir {
    gamma: Ea4,
    /// `(d, P_dep, S_dep, P_now, S_now, compounded, gain)`.
    commits: [[Ea4; DIGEST_LANES]; 7],
}
impl AirConstraint for WithdrawAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment openings); declaring less truncates the sumcheck.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        for (i, &v) in WD_VALUES.iter().enumerate() {
            push_commit_open_constraints(&mut cs, local, v, WD_BLIND + i * DIGEST_LANES, WD_COMMIT + i * DIGEST_LANES, WD_INTER + i * T_OPEN, WD_VBITS + i * RANGE16_COLS);
            for c in 0..DIGEST_LANES {
                cs.push(local[WD_COMMIT + i * DIGEST_LANES + c] - self.commits[i][c]);
            }
        }
        let vbits = |i: usize| WD_VBITS + i * RANGE16_COLS; // (d, P_dep, S_dep, P_now, S_now, compounded, gain) = 0..7
        let diff = |x: usize, y: usize, n: usize, less_one: bool| -> Vec<Ea4> {
            (0..n).map(|i| local[x + i] - local[y + i] - if less_one && i == 0 { Ea4::ONE } else { Ea4::ZERO }).collect()
        };
        push_ge_n_diff_constraints(&mut cs, local, &diff(WD_SN, WD_SD, N_LIMB16, false), WD_GD, WD_GD + N_LIMB16, WD_GD + 2 * N_LIMB16);
        let gd_bits = WD_GD + 2 * N_LIMB16;
        push_mulhh_constraints(&mut cs, local, vbits(5), vbits(1), N_LIMB16, WD_M1); // compounded · P_dep
        push_mulhh_constraints(&mut cs, local, vbits(0), vbits(3), N_LIMB16, WD_M2); // d · P_now
        push_mulhh_constraints(&mut cs, local, vbits(6), vbits(1), N_LIMB16, WD_M3); // gain · P_dep
        push_mulhh_constraints(&mut cs, local, vbits(0), gd_bits, N_LIMB16, WD_M4); // d · (S_now − S_dep)
        let p16 = |m: usize| m + mulhh_p16_off(N_LIMB16);
        push_ge_n_diff_constraints(&mut cs, local, &diff(p16(WD_M2), p16(WD_M1), HP, false), WD_G1, WD_G1 + HP, WD_G1 + 2 * HP);
        for i in N_LIMB16..HP {
            cs.push(local[WD_G1 + i]);
        }
        push_ge_n_diff_constraints(&mut cs, local, &diff(WD_PD, WD_G1, N_LIMB16, true), WD_G1R, WD_G1R + N_LIMB16, WD_G1R + 2 * N_LIMB16);
        push_ge_n_diff_constraints(&mut cs, local, &diff(p16(WD_M4), p16(WD_M3), HP, false), WD_G2, WD_G2 + HP, WD_G2 + 2 * HP);
        for i in N_LIMB16..HP {
            cs.push(local[WD_G2 + i]);
        }
        push_ge_n_diff_constraints(&mut cs, local, &diff(WD_PD, WD_G2, N_LIMB16, true), WD_G2R, WD_G2R + N_LIMB16, WD_G2R + 2 * N_LIMB16);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn withdraw_statement_bind(commits: &[Digest; 7]) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(1 + 7 * DIGEST_LANES);
    v.push(Fa4::from_u64(LIQ_WITHDRAW_DOMAIN));
    for d in commits {
        for &x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v
}

fn withdraw_air(commits: &[Digest; 7]) -> impl Fn(Ea4) -> WithdrawAir {
    let commits: [[Ea4; DIGEST_LANES]; 7] = core::array::from_fn(|i| commit_to_ea4(commits[i]));
    move |gamma| WithdrawAir { gamma, commits }
}

/// The openings of one withdrawal: the deposit's `(d, P_dep, S_dep)` (the depositor's), the pool's `(P_now, S_now)`
/// (the bonded set's), and seven blinds in the same order as the values — the last two fresh, for the two outputs.
pub struct WithdrawOpening {
    pub d: U256,
    pub p_dep: U256,
    pub s_dep: U256,
    pub p_now: U256,
    pub s_now: U256,
    pub blinds: [Digest; 7],
}

/// Lay the withdrawal trace for claimed outputs. `None` when `S_now < S_dep`, a product overflows, or a chain has no
/// witness — an output that is not the rounded-down quotient in either direction.
fn withdraw_trace(o: &WithdrawOpening, compounded: U256, gain: U256) -> Option<(Vec<Vec<Fa4>>, [Digest; 7])> {
    let vals = [o.d, o.p_dep, o.s_dep, o.p_now, o.s_now, compounded, gain];
    let limbs: [[u64; N_LIMB16]; 7] = core::array::from_fn(|i| u256_to_limbs16(vals[i]));
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; WD_WIDTH];
    let mut commits = [[0u64; DIGEST_LANES]; 7];
    for i in 0..7 {
        fill_cols(&mut cols, WD_VALUES[i], &limbs[i]);
        fill_cols(&mut cols, WD_BLIND + i * DIGEST_LANES, &o.blinds[i]);
        commits[i] = place_commit_open(&mut cols, limbs[i], o.blinds[i], WD_INTER + i * T_OPEN, WD_VBITS + i * RANGE16_COLS);
        fill_cols(&mut cols, WD_COMMIT + i * DIGEST_LANES, &commits[i]);
    }
    let (dl, pdl, sdl, pnl, snl, col, gal) = (limbs[0], limbs[1], limbs[2], limbs[3], limbs[4], limbs[5], limbs[6]);
    let diff = |x: &[u64], y: &[u64], less_one: bool| -> Vec<i64> { (0..x.len()).map(|i| x[i] as i64 - y[i] as i64 - i64::from(less_one && i == 0)).collect() };
    if !place_ge_n_diff(&mut cols, &diff(&snl, &sdl, false), WD_GD, WD_GD + N_LIMB16, WD_GD + 2 * N_LIMB16) {
        return None;
    }
    let dsl: [u64; N_LIMB16] = u256_to_limbs16(sub256(o.s_now, o.s_dep)?);
    let m1 = place_mulhh(&mut cols, &col, &pdl, WD_M1)?;
    let m2 = place_mulhh(&mut cols, &dl, &pnl, WD_M2)?;
    let m3 = place_mulhh(&mut cols, &gal, &pdl, WD_M3)?;
    let m4 = place_mulhh(&mut cols, &dl, &dsl, WD_M4)?;
    if !place_ge_n_diff(&mut cols, &diff(&m2, &m1, false), WD_G1, WD_G1 + HP, WD_G1 + 2 * HP) {
        return None;
    }
    let r1 = limbs_sub(&m2, &m1)?;
    if r1[N_LIMB16..].iter().any(|&l| l != 0) || !place_ge_n_diff(&mut cols, &diff(&pdl, &r1[..N_LIMB16], true), WD_G1R, WD_G1R + N_LIMB16, WD_G1R + 2 * N_LIMB16) {
        return None;
    }
    if !place_ge_n_diff(&mut cols, &diff(&m4, &m3, false), WD_G2, WD_G2 + HP, WD_G2 + 2 * HP) {
        return None;
    }
    let r2 = limbs_sub(&m4, &m3)?;
    if r2[N_LIMB16..].iter().any(|&l| l != 0) || !place_ge_n_diff(&mut cols, &diff(&pdl, &r2[..N_LIMB16], true), WD_G2R, WD_G2R + N_LIMB16, WD_G2R + 2 * N_LIMB16) {
        return None;
    }
    Some((cols, commits))
}

/// One withdrawal's proof: the carrier bytes, the seven commitments `(d, P_dep, S_dep, P_now, S_now, compounded, gain)`
/// the withdrawal object carries, and the two outputs (the USDm returned, the collateral paid out as a peg-out).
pub struct WithdrawProof {
    pub bytes: Vec<u8>,
    pub commits: [Digest; 7],
    pub compounded: U256,
    pub gain: U256,
}

fn prove_withdraw_trace(cols2: Vec<Vec<Fa4>>, commits: &[Digest; 7]) -> Option<Vec<u8>> {
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    prove_value_carrier(cols, withdraw_air(commits), &withdraw_statement_bind(commits))
}

/// PROVE one withdrawal: derive `(compounded, gain)` by the ONE rule and prove it over the seven commitments. `None`
/// when the withdrawal has no rule (`S_now < S_dep`, `P_dep = 0`) or a value does not fit.
#[must_use]
pub fn prove_withdraw_carrier(o: &WithdrawOpening) -> Option<WithdrawProof> {
    let (compounded, gain) = pool_withdraw(o.d, o.p_dep, o.s_dep, o.p_now, o.s_now)?;
    let (cols, commits) = withdraw_trace(o, compounded, gain)?;
    let bytes = prove_withdraw_trace(cols, &commits)?;
    Some(WithdrawProof { bytes, commits, compounded, gain })
}

/// VERIFY a withdrawal carrier against the object's seven commitments — every node, holding nothing but these (the
/// deposit's commitments from the deposit object, the pool's from its state, the outputs from the withdrawal object).
/// Fail-closed on a value not opening to its digest, a wrong product, a remainder that reaches `P_dep`, or a negative
/// difference.
#[must_use]
pub fn verify_withdraw_carrier(bytes: &[u8], commits: &[Digest; 7]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    verify_value_carrier(bytes, withdraw_air(commits), &withdraw_statement_bind(commits), (REC_DECIDER_FOLDING, WD_WIDTH))
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// A CLOSED EPOCH'S RECEIPTS SETTLE THROUGH THE BRIDGE (H11 §2.5, docs/SP-EPOCH-BRIDGE-SPEC-20261022.md) — Liquity's
// scale span. An epoch closes when `P` falls under 2^64 and the next restarts at `P = 2^128` CARRYING the residual `T`, so
// a receipt of the closed epoch must keep absorbing the next epoch's losses and gains through the closing words (a
// receipt frozen at them is paid the residual while the next epoch's liquidations retire it too — MEASURED 958 USDm owed
// beyond the pool, `rogue_role_pins::a_non_drain_epoch_close_…`):
//
//     P_b · 2^128 + r_p = P₁ · P₂,                         0 ≤ r_p < 2^128   (the receipt's P chained across the boundary)
//     S_b = S₁ + q,      q · 2^128 + r_s = P₁ · S₂,        0 ≤ r_s < 2^128   (its S: the closed epoch's, plus its share of the next)
//
// `(P₁, S₁)` are the receipt epoch's words (its closing words, or the live ones for the identity bridge) and `(P₂, S₂)` the
// next epoch's (live, closing, or the public opening `(2^128, 0)`). Dividing by 2^128 is a LIMB SHIFT: the quotient is the
// product's 16-bit limbs `[8..24]`, the remainder its limbs `[0..8]` — canonical range-bound limbs on both sides, so a limb
// equality is an integer identity and no compare is needed; the product's limbs `[24..]` are pinned zero (the quotient
// fits 256 bits). Both round DOWN: the pool never owes more than it holds. Native twin: `pool_bridge`.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Domain word of the epoch-bridge carrier's transcript bind.
pub const LIQ_POOL_BRIDGE_DOMAIN: u64 = 0x4C49_5150_4252_4447; // "LIQPBRDG"

/// `2^128 = 2^(16·8)`: the bridge's quotient starts at the product's eighth 16-bit limb.
const PB_SHIFT_LIMBS: usize = (POOL_P_SCALE_BITS / LIMB16_BITS) as usize;

// The bridge layout: six openings (P₁, S₁, P₂, S₂, P_b, S_b), two products, the S-side add's carries.
const PB_P1: usize = 0;
const PB_S1: usize = PB_P1 + N_LIMB16;
const PB_P2: usize = PB_S1 + N_LIMB16;
const PB_S2: usize = PB_P2 + N_LIMB16;
const PB_PB: usize = PB_S2 + N_LIMB16;
const PB_SB: usize = PB_PB + N_LIMB16;
const PB_BLIND: usize = PB_SB + N_LIMB16; // 6 × DIGEST_LANES
const PB_COMMIT: usize = PB_BLIND + 6 * DIGEST_LANES; // 6 × DIGEST_LANES
const PB_INTER: usize = PB_COMMIT + 6 * DIGEST_LANES; // 6 × T_OPEN
const PB_VBITS: usize = PB_INTER + 6 * T_OPEN; // 6 × RANGE16_COLS
const PB_M1: usize = PB_VBITS + 6 * RANGE16_COLS; // P₁ · P₂
const PB_M2: usize = PB_M1 + HB; // P₁ · S₂
const PB_CARRY: usize = PB_M2 + HB; // S₁ + q: one carry per limb
const PB_WIDTH: usize = PB_CARRY + N_LIMB16;

/// The six committed values of one bridge, in layout order.
const PB_VALUES: [usize; 6] = [PB_P1, PB_S1, PB_P2, PB_S2, PB_PB, PB_SB];

/// A product's quotient by 2^128 (its limbs `[8..24]`), `None` when it does not fit 256 bits.
fn shift_out_2_128(m: &[u64]) -> Option<U256> {
    if m[PB_SHIFT_LIMBS + N_LIMB16..].iter().any(|&l| l != 0) {
        return None;
    }
    limbs_to_u256(&m[PB_SHIFT_LIMBS..PB_SHIFT_LIMBS + N_LIMB16])
}

/// ⭐ THE ONE EPOCH-BRIDGE RULE, natively: the `(P, S)` a receipt settles against when its epoch's words `(p1, s1)` are
/// chained through the next epoch's `(p2, s2)` — `(⌊p1·p2 / 2^128⌋, s1 + ⌊p1·s2 / 2^128⌋)`, both rounded DOWN. The
/// identity bridge `(p, s) ⊗ (2^128, 0) = (p, s)` is how a live receipt settles. `None` when a value does not fit 256 bits.
#[must_use]
pub fn pool_bridge(p1: U256, s1: U256, p2: U256, s2: U256) -> Option<(U256, U256)> {
    let (p1l, p2l, s2l) = (u256_to_limbs16(p1), u256_to_limbs16(p2), u256_to_limbs16(s2));
    let p_b = shift_out_2_128(&mul256_wide(&p1l, &p2l))?;
    let q = shift_out_2_128(&mul256_wide(&p1l, &s2l))?;
    Some((p_b, add256(s1, q)?))
}

struct PoolBridgeAir {
    gamma: Ea4,
    /// `(P₁, S₁, P₂, S₂, P_b, S_b)`.
    commits: [[Ea4; DIGEST_LANES]; 6],
}
impl AirConstraint for PoolBridgeAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment openings); declaring less truncates the sumcheck.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        for (i, &v) in PB_VALUES.iter().enumerate() {
            push_commit_open_constraints(&mut cs, local, v, PB_BLIND + i * DIGEST_LANES, PB_COMMIT + i * DIGEST_LANES, PB_INTER + i * T_OPEN, PB_VBITS + i * RANGE16_COLS);
            for c in 0..DIGEST_LANES {
                cs.push(local[PB_COMMIT + i * DIGEST_LANES + c] - self.commits[i][c]);
            }
        }
        let vbits = |i: usize| PB_VBITS + i * RANGE16_COLS; // (P₁, S₁, P₂, S₂, P_b, S_b) = 0..6
        push_mulhh_constraints(&mut cs, local, vbits(0), vbits(2), N_LIMB16, PB_M1); // P₁ · P₂
        push_mulhh_constraints(&mut cs, local, vbits(0), vbits(3), N_LIMB16, PB_M2); // P₁ · S₂
        let p16 = |m: usize| m + mulhh_p16_off(N_LIMB16);
        // P_b IS the product's limbs [8..24] (the floor by 2^128: the low limbs are the remainder), the rest zero
        for i in 0..N_LIMB16 {
            cs.push(local[PB_PB + i] - local[p16(PB_M1) + PB_SHIFT_LIMBS + i]);
        }
        for m in [PB_M1, PB_M2] {
            for i in PB_SHIFT_LIMBS + N_LIMB16..HP {
                cs.push(local[p16(m) + i]);
            }
        }
        // S_b = S₁ + q, carried straight into S_b's opening limbs, no carry out
        push_add_n_constraints(&mut cs, local, PB_S1, p16(PB_M2) + PB_SHIFT_LIMBS, PB_SB, PB_CARRY, N_LIMB16);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn pool_bridge_statement_bind(commits: &[Digest; 6]) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(1 + 6 * DIGEST_LANES);
    v.push(Fa4::from_u64(LIQ_POOL_BRIDGE_DOMAIN));
    for d in commits {
        for &x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    v
}

fn pool_bridge_air(commits: &[Digest; 6]) -> impl Fn(Ea4) -> PoolBridgeAir {
    let commits: [[Ea4; DIGEST_LANES]; 6] = core::array::from_fn(|i| commit_to_ea4(commits[i]));
    move |gamma| PoolBridgeAir { gamma, commits }
}

/// The openings of one bridge: the receipt epoch's `(P₁, S₁)` and the next epoch's `(P₂, S₂)` (the bonded set's openings
/// of chain words), and six blinds in the same order as the values — the last two fresh, for the bridged pair.
pub struct PoolBridgeOpening {
    pub p1: U256,
    pub s1: U256,
    pub p2: U256,
    pub s2: U256,
    pub blinds: [Digest; 6],
}

/// Lay the bridge trace for a claimed `(P_b, S_b)`. `None` when a product overflows or the claim is not the rule's —
/// the shifted quotient in either word (there is no other witness for a limb equality).
fn pool_bridge_trace(o: &PoolBridgeOpening, p_b: U256, s_b: U256) -> Option<(Vec<Vec<Fa4>>, [Digest; 6])> {
    let vals = [o.p1, o.s1, o.p2, o.s2, p_b, s_b];
    let limbs: [[u64; N_LIMB16]; 6] = core::array::from_fn(|i| u256_to_limbs16(vals[i]));
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; PB_WIDTH];
    let mut commits = [[0u64; DIGEST_LANES]; 6];
    for i in 0..6 {
        fill_cols(&mut cols, PB_VALUES[i], &limbs[i]);
        fill_cols(&mut cols, PB_BLIND + i * DIGEST_LANES, &o.blinds[i]);
        commits[i] = place_commit_open(&mut cols, limbs[i], o.blinds[i], PB_INTER + i * T_OPEN, PB_VBITS + i * RANGE16_COLS);
        fill_cols(&mut cols, PB_COMMIT + i * DIGEST_LANES, &commits[i]);
    }
    let m1 = place_mulhh(&mut cols, &limbs[0], &limbs[2], PB_M1)?;
    let m2 = place_mulhh(&mut cols, &limbs[0], &limbs[3], PB_M2)?;
    if shift_out_2_128(&m1)? != p_b {
        return None;
    }
    let q = &m2[PB_SHIFT_LIMBS..PB_SHIFT_LIMBS + N_LIMB16];
    shift_out_2_128(&m2)?;
    // the carries of S₁ + q; the sum must BE S_b's limbs
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let t = limbs[1][i] + q[i] + cin;
        if t & LIMB16_MASK != limbs[5][i] {
            return None;
        }
        cin = t >> LIMB16_BITS;
        cols[PB_CARRY + i].fill(Fa4::from_u64(cin));
    }
    if cin != 0 {
        return None;
    }
    Some((cols, commits))
}

/// One bridge's proof: the carrier bytes, the six commitments `(P₁, S₁, P₂, S₂, P_b, S_b)`, and the bridged pair the
/// withdraw carrier then settles against.
pub struct PoolBridgeProof {
    pub bytes: Vec<u8>,
    pub commits: [Digest; 6],
    pub p_b: U256,
    pub s_b: U256,
}

fn prove_pool_bridge_trace(cols2: Vec<Vec<Fa4>>, commits: &[Digest; 6]) -> Option<Vec<u8>> {
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    prove_value_carrier(cols, pool_bridge_air(commits), &pool_bridge_statement_bind(commits))
}

/// PROVE one bridge: derive `(P_b, S_b)` by the ONE rule and prove it over the six commitments. `None` when a value does
/// not fit.
#[must_use]
pub fn prove_pool_bridge_carrier(o: &PoolBridgeOpening) -> Option<PoolBridgeProof> {
    let (p_b, s_b) = pool_bridge(o.p1, o.s1, o.p2, o.s2)?;
    let (cols, commits) = pool_bridge_trace(o, p_b, s_b)?;
    let bytes = prove_pool_bridge_trace(cols, &commits)?;
    Some(PoolBridgeProof { bytes, commits, p_b, s_b })
}

/// VERIFY a bridge carrier against its six commitments — every node, the sources from its OWN ledger (the receipt epoch's
/// and the next epoch's words), the bridged pair from the withdrawal object. Fail-closed on a value not opening to its
/// digest, a wrong product, or a bridged word that is not the shifted quotient.
#[must_use]
pub fn verify_pool_bridge_carrier(bytes: &[u8], commits: &[Digest; 6]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    verify_value_carrier(bytes, pool_bridge_air(commits), &pool_bridge_statement_bind(commits), (REC_DECIDER_FOLDING, PB_WIDTH))
}

// ── #75 brick 5 — the confidential RESERVE-YIELD (self-minted, stake-bound, backing-gated) carrier ───────────
//
// The private replacement for the transparent reserve-yield (the old `earned_fee_surplus_usdm` meter + observable
// per-unit reward index + a supply counter). A staker SELF-MINTS their own yield from their OWN hidden staked
// note — no pool, no enumeration, no index, no counter. This WHIR-bound carrier proves, over HIDDEN values, that
// the yield is (a) BOUNDED by the stake at the governance rate and (b) fully COLLATERALIZED by the reserve's
// existing over-collateralization:
//   • yield·10000 ≤ stake·rate_bps          — no over-claim beyond `stake × rate` (`rate_bps` a governance param,
//                                              a policy interest rate — NOT a value/supply; over-claim is UNPROVABLE)
//   • minted + yield == new_minted           — conservation (the mint is exactly the claimed yield)
//   • reserve·10000 ≥ new_minted·ratio_bps   — the yield mint keeps the peg ≥150% collateralized (the surplus that
//                                              backs the yield is IMPLIED by the committed state — never a counter)
// All four quantities (stake / minted / new_minted / reserve) are pinned to CONSENSUS commitments; the node
// verifies + advances `minted_commit`, learning NO stake / yield / total. The reward is delivered as an ordinary
// confidential note (amount encrypted-to-owner); who claims is oblivious (a per-epoch-per-note nullifier, added
// at the wire layer, stops a double-claim). Trustless (staker self-builds), O(1) per claim (no per-staker state).

// ⭐⭐⭐ DB-237 (2026-10-02) — THE YIELD SUPPLY CARRIER. The reward is no longer bounded HERE: the stake carrier
// (`whir_rec_block::prove_stake_carrier_bytes`) computes it EXACTLY in-circuit (`floor(v·rate·Δ/D)`) and states only
// its commitment `yield_commit = solvency_commit_256(r, r_blind)`. This carrier OPENS that same commitment and proves
//   • minted + yield == new_minted           — the committed supply grows by exactly the reward minted;
//   • reserve·10000 ≥ new_minted·ratio_bps   — the mint fits inside the reserve's over-collateralization.
// The stake commitment and its rate bind (`yield·10000 ≤ stake·rate`) are DELETED: a bound by a stake commitment nothing
// tied to a staked note was the DB-237 hole (any note harvested), and the exact rule now lives in the stake gate.

// Yield layout: yield[0..16] minted[16..32] new_minted[32..48] reserve[48..64] mcarry[64..80]
// blinds, commits, open-inters, range bits, backing-scale(reserve,new_minted)+ge.
const Y_YIELD: usize = 0;
const Y_MINTED: usize = 16;
const Y_NEWMINT: usize = 32;
const Y_RESERVE: usize = 48;
const Y_MCARRY: usize = 64;
const Y_YBLIND: usize = Y_MCARRY + N_LIMB16;
const Y_MBLIND: usize = Y_YBLIND + DIGEST_LANES;
const Y_NMBLIND: usize = Y_MBLIND + DIGEST_LANES;
const Y_RBLIND: usize = Y_NMBLIND + DIGEST_LANES;
const Y_YCOMMIT: usize = Y_RBLIND + DIGEST_LANES;
const Y_MCOMMIT: usize = Y_YCOMMIT + DIGEST_LANES;
const Y_NMCOMMIT: usize = Y_MCOMMIT + DIGEST_LANES;
const Y_RCOMMIT: usize = Y_NMCOMMIT + DIGEST_LANES;
const Y_YINTER: usize = Y_RCOMMIT + DIGEST_LANES;
const Y_MINTER: usize = Y_YINTER + T_OPEN;
const Y_NMINTER: usize = Y_MINTER + T_OPEN;
const Y_RINTER: usize = Y_NMINTER + T_OPEN;
/// ⛔⛔⛔ EVERY ONE OF THESE WAS A HAND-COMPUTED LITERAL (448, 465, 481, 753 … 2280), correct against the
/// four-lane layout and silently overlapping its neighbour at eight — the yield claim's scale and ≥
/// blocks landed inside the commitment openings, and the honest carrier stopped verifying with nothing
/// to say where. The bound-transition block above (`T_*`) had already been derived for exactly this
/// reason; this is the same repair, and the arithmetic is identical (a scale block is P(17 limbs) +
/// CARRY(16) + PBITS(17×16); a ≥ block is SLACK(17) + BORROW(17) + SBITS(17×16)).
// DB-362: every opened value range-bound, every scale's carries bounded
const Y_YVBITS: usize = Y_RINTER + T_OPEN;
const Y_MVBITS: usize = Y_YVBITS + RANGE16_COLS;
const Y_NMVBITS: usize = Y_MVBITS + RANGE16_COLS;
const Y_RVBITS: usize = Y_NMVBITS + RANGE16_COLS;
// ⭐ DB-124: the yield's backing is priced like every bound transition's (`Backing`) — reserve × BPS × price ≥ new_minted ×
// ratio × PRICE_SCALE, the two wide products read the operands' range bits.
const Y_MR: usize = Y_RVBITS + RANGE16_COLS; // reserve × BPS × price
const Y_MM: usize = Y_MR + MUL14_COLS; // new_minted × ratio × PRICE_SCALE
const Y_BG_SLACK: usize = Y_MM + MUL14_COLS;
const Y_BG_BORROW: usize = Y_BG_SLACK + M14_P16_LIMBS;
const Y_BG_SBITS: usize = Y_BG_BORROW + M14_P16_LIMBS;
const Y_WIDTH: usize = Y_BG_SBITS + M14_P16_LIMBS * N_LIMB16;
const Y_BACKING: BackingAt = BackingAt { mr: Y_MR, mm: Y_MM, slack: Y_BG_SLACK, borrow: Y_BG_BORROW, sbits: Y_BG_SBITS };

/// The four consensus commitments a yield supply step touches: the reward (the stake carrier's `reward_commit`, opened
/// read-only), the supply before and after, and the reserve (opened read-only for the backing check).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YieldMintCommits {
    pub yield_commit: Digest,
    pub minted_commit: Digest,
    pub new_minted_commit: Digest,
    pub reserve_commit: Digest,
}

struct YieldMintAir {
    gamma: Ea4,
    ratio_bps: Backing,
    yield_commit: [Ea4; DIGEST_LANES],
    minted_commit: [Ea4; DIGEST_LANES],
    new_minted_commit: [Ea4; DIGEST_LANES],
    reserve_commit: [Ea4; DIGEST_LANES],
}
impl AirConstraint for YieldMintAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment opening). A gate that declares less
        // than the permutation's degree truncates the sumcheck and even an HONEST proof fails.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        // the mint is exactly the reward: minted + yield == new_minted
        push_conservation_constraints(&mut cs, local, Y_MINTED, Y_YIELD, Y_NEWMINT, Y_MCARRY);
        // bind every hidden value to its consensus commitment — the yield to the stake carrier's `reward_commit`
        push_commit_open_constraints(&mut cs, local, Y_YIELD, Y_YBLIND, Y_YCOMMIT, Y_YINTER, Y_YVBITS);
        push_commit_open_constraints(&mut cs, local, Y_MINTED, Y_MBLIND, Y_MCOMMIT, Y_MINTER, Y_MVBITS);
        push_commit_open_constraints(&mut cs, local, Y_NEWMINT, Y_NMBLIND, Y_NMCOMMIT, Y_NMINTER, Y_NMVBITS);
        push_commit_open_constraints(&mut cs, local, Y_RESERVE, Y_RBLIND, Y_RCOMMIT, Y_RINTER, Y_RVBITS);
        // BACKING: reserve·10000 ≥ new_minted·ratio_bps  (the yield fits inside existing over-collateralization)
        push_backing_constraints_at(&mut cs, local, Y_RVBITS, Y_NMVBITS, self.ratio_bps, Y_BACKING);
        // pin the commitments to the node's consensus digests
        for (base, pinned) in [
            (Y_YCOMMIT, &self.yield_commit),
            (Y_MCOMMIT, &self.minted_commit),
            (Y_NMCOMMIT, &self.new_minted_commit),
            (Y_RCOMMIT, &self.reserve_commit),
        ] {
            for c in 0..DIGEST_LANES {
                cs.push(local[base + c] - pinned[c]);
            }
        }
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

/// Build the yield supply trace. `None` if the resulting state would fall below `ratio_bps` collateralization —
/// unprovable, fail-closed.
#[allow(clippy::too_many_arguments)]
fn yield_mint_trace(
    reserve: U256,
    minted: U256,
    yield_amt: U256,
    y_blind: Digest,
    m_blind: Digest,
    nm_blind: Digest,
    r_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<Vec<Fa4>>, YieldMintCommits)> {
    let new_minted = add256(minted, yield_amt)?;
    let (yl, ml, nml, rl) = (
        u256_to_limbs16(yield_amt),
        u256_to_limbs16(minted),
        u256_to_limbs16(new_minted),
        u256_to_limbs16(reserve),
    );
    let mut mcarry = [0u64; N_LIMB16];
    let mut cin = 0u64;
    for i in 0..N_LIMB16 {
        let s = ml[i] + yl[i] + cin;
        cin = s >> LIMB16_BITS;
        mcarry[i] = cin;
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; Y_WIDTH];
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..N_LIMB16 {
            set(Y_YIELD + i, yl[i]);
            set(Y_MINTED + i, ml[i]);
            set(Y_NEWMINT + i, nml[i]);
            set(Y_RESERVE + i, rl[i]);
            set(Y_MCARRY + i, mcarry[i]);
        }
        for i in 0..DIGEST_LANES {
            set(Y_YBLIND + i, y_blind[i]);
            set(Y_MBLIND + i, m_blind[i]);
            set(Y_NMBLIND + i, nm_blind[i]);
            set(Y_RBLIND + i, r_blind[i]);
        }
    }
    let yc = place_commit_open(&mut cols, yl, y_blind, Y_YINTER, Y_YVBITS);
    let mc = place_commit_open(&mut cols, ml, m_blind, Y_MINTER, Y_MVBITS);
    let nmc = place_commit_open(&mut cols, nml, nm_blind, Y_NMINTER, Y_NMVBITS);
    let rc = place_commit_open(&mut cols, rl, r_blind, Y_RINTER, Y_RVBITS);
    if place_backing_at(&mut cols, &rl, &nml, ratio_bps, Y_BACKING).is_none() {
        return None; // reserve·10000 < new_minted·ratio ⇒ the yield would break 150% collateralization ⇒ unprovable
    }
    {
        let mut set = |c: usize, v: u64| {
            let f = Fa4::from_u64(v);
            cols[c][0] = f;
            cols[c][1] = f;
        };
        for i in 0..DIGEST_LANES {
            set(Y_YCOMMIT + i, yc[i]);
            set(Y_MCOMMIT + i, mc[i]);
            set(Y_NMCOMMIT + i, nmc[i]);
            set(Y_RCOMMIT + i, rc[i]);
        }
    }
    Some((cols, YieldMintCommits { yield_commit: yc, minted_commit: mc, new_minted_commit: nmc, reserve_commit: rc }))
}

fn yield_statement_bind(c: &YieldMintCommits, ratio_bps: Backing) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(4 * DIGEST_LANES + 1);
    for d in [c.yield_commit, c.minted_commit, c.new_minted_commit, c.reserve_commit] {
        for x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    // the backing's ratio AND price are bound into the statement (a proof for one price is not a proof for another)
    v.push(Fa4::from_u64(ratio_bps.ratio_bps));
    for i in 0..4 {
        v.push(Fa4::from_u64(((ratio_bps.price >> (32 * i)) & 0xFFFF_FFFF) as u64));
    }
    v
}

fn yield_air(c: &YieldMintCommits, ratio_bps: Backing) -> impl Fn(Ea4) -> YieldMintAir {
    let c = *c;
    move |g: Ea4| YieldMintAir {
        gamma: g,
        ratio_bps,
        yield_commit: commit_to_ea4(c.yield_commit),
        minted_commit: commit_to_ea4(c.minted_commit),
        new_minted_commit: commit_to_ea4(c.new_minted_commit),
        reserve_commit: commit_to_ea4(c.reserve_commit),
    }
}

/// PROVE a yield SUPPLY step: `minted + yield = new_minted` with `yield` opened against the stake carrier's
/// `reward_commit` (`y_blind` = its `reward_blind`), and `reserve·10000 ≥ new_minted·ratio_bps`. Returns the carrier and
/// the four commitments. `None` when the mint would break the backing.
#[allow(clippy::too_many_arguments)]
pub fn prove_yield_mint_carrier(
    reserve: U256,
    minted: U256,
    yield_amt: U256,
    y_blind: Digest,
    m_blind: Digest,
    nm_blind: Digest,
    r_blind: Digest,
    ratio_bps: Backing,
) -> Option<(Vec<u8>, YieldMintCommits)> {
    if ratio_bps.ks().is_none() {
        return None;
    }
    let (cols2, commits) = yield_mint_trace(reserve, minted, yield_amt, y_blind, m_blind, nm_blind, r_blind, ratio_bps)?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let bytes = prove_value_carrier(cols, yield_air(&commits, ratio_bps), &yield_statement_bind(&commits, ratio_bps))?;
    Some((bytes, commits))
}

/// VERIFY a yield supply step against the four commitments: the stake carrier's `reward_commit` as `yield_commit`, the
/// node's persisted `minted_commit` and `reserve_commit`, and the claimed `new_minted_commit`. Fail-closed on a value not
/// opening to its digest, a mint of any amount other than the committed reward, a mint the reserve does not back, or a
/// proof for any other commitment set or ratio.
#[must_use]
pub fn verify_yield_mint_carrier(bytes: &[u8], ratio_bps: Backing, commits: &YieldMintCommits) -> bool {
    if bytes.is_empty() || ratio_bps.ks().is_none() {
        return false; // DB-362: a wider multiplier admits the alias
    }
    verify_value_carrier(
        bytes,
        yield_air(commits, ratio_bps),
        &yield_statement_bind(commits, ratio_bps),
        (REC_DECIDER_FOLDING, Y_WIDTH),
    )
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// LIQUIDATION — THE AMOUNT CARRIER (docs/LIQUIDATION-TRUSTLESS-SPEC.md §2.1–2.2, §9.2; 2026-09-29). A liquidation
// retires `C` USDm from the Stability Pool and seizes `S` collateral for the pool's depositors at the public mark `p`
// less the discount `DELTA`. ONE carrier proves BOTH amounts from the COMMITTED position `(D reserve, M minted)` under
// the public rule `(p, DELTA, RHO_TARGET, RHO_LIQ)` — a non-bonded node holds only the four commitments `(DD, DM, DC,
// DS)` (DB-80's Sapling-style delta commitments the retire leg, the seize leg and the pool transition open), so "every
// node evaluates the rule" (§2.1) is true only because the derivation is in-circuit:
//
//   DUE      M·k_L  ≥  D·k_D + 1                         ⟺  D·p·BPS < RHO_LIQ·M·PS            (§2.1, × (BPS − DELTA))
//   RETIRE   C = min( ceil(N' / Q), M ),   N' = M·k_M + R − D·k_D,   Q = PS·(RHO_TARGET·(BPS−DELTA) − BPS²)     (§2.2)
//            as  [¬full_c ⇒ C·Q + D·k_D ≥ M·k_M + R]  ∧  M·k_M + R + (Q−1) ≥ C·Q + D·k_D  ∧  C ≤ M  ∧  [full_c ⇒ C = M]
//   SEIZE    S = min( ceil(C·k2 / k1), D ),   k1 = p·(BPS − DELTA),   k2 = BPS·PS
//            as  [¬full_s ⇒ S·k1 ≥ C·k2]  ∧  C·k2 + (k1−1) ≥ S·k1  ∧  S ≤ D  ∧  [full_s ⇒ S = D ∧ C·k2 ≥ D·k1 + 1]
//
//   k_M = RHO_TARGET·PS·(BPS−DELTA)    k_D = p·BPS·(BPS−DELTA)    k_L = RHO_LIQ·PS·(BPS−DELTA)    R = BPS·(k1 − 1)
//
// `R` absorbs the seizure's ceiling, so the post-state restores RHO_TARGET for EVERY rounding of S. Every product is the
// wide public multiply (u128 k, seven chunks), every compare / add the n-limb gadget, the two regime selectors PRIVATE
// booleans (a gated compare's differences are the selector times the plain differences, so an off selector asserts
// nothing and the regime never shows — the carrier is one size in every regime). Why the `min`s are sound: with ¬full_c
// the two RETIRE bounds pin C = ceil(N'/Q) and C ≤ M; with full_c, C = M and the upper bound alone gives M ≤ ceil(N'/Q)
// — either way C = min(ceil(N'/Q), M); the same argument for S. The native twin is `liquidation_amount(D, M, rule)`,
// the ONE function the node's fold rule computes (§2.2); the pins prove the circuit accepts exactly its value and
// refuses every neighbour, at the gadgets (no witness) or at the verifier.
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// Fixed-point scale of a collateral quote — the node's `liquidation::PRICE_SCALE`, spelled ONCE for the circuit here
/// and asserted equal there (a quote of exactly 1 USDm-atomic per collateral atomic is `PRICE_SCALE`).
pub const LIQ_PRICE_SCALE: u64 = 1_000_000;
/// Domain word of the amount carrier's transcript bind.
pub const LIQ_AMOUNT_DOMAIN: u64 = 0x4C49_5141_4D4F_554E; // "LIQAMOUN"

/// The public parameters one liquidation is evaluated under at a fold: the mark and the three protocol ratios. Bound
/// into the carrier's statement lane by lane (four exact 16-bit lanes per value — a u64 is not one field element).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiqRule {
    /// The mark: USDm-atomic per collateral atomic × [`LIQ_PRICE_SCALE`].
    pub p: u64,
    /// The pool's discount on seized collateral, in bps of `BPS_DEN`.
    pub delta_bps: u64,
    /// The backing ratio a liquidation restores (`RHO_TARGET`, e.g. 15,000 = 150 %), bps.
    pub rho_target_bps: u64,
    /// The backing ratio under which a position is DUE (`RHO_LIQ`, e.g. 12,000 = 120 %), bps.
    pub rho_liq_bps: u64,
}

/// The rule's public multipliers and constants, derived ONCE and identically by prover and verifier — every one below
/// 2^98, the wide multiply's seven chunks (`LiqRule::mults` refuses a rule for which any is not).
#[derive(Clone, Copy, Debug)]
struct LiqMults {
    /// `RHO_TARGET · PRICE_SCALE · (BPS − DELTA)` — on `M`, the target side of the shortfall.
    k_m: u128,
    /// `p · BPS · (BPS − DELTA)` — on `D`, the collateral side of the shortfall.
    k_d: u128,
    /// `RHO_LIQ · PRICE_SCALE · (BPS − DELTA)` — on `M`, the due test.
    k_l: u128,
    /// `Q = PRICE_SCALE · (RHO_TARGET · (BPS − DELTA) − BPS²)` — what one retired unit buys of the shortfall.
    q: u128,
    /// `k1 = p · (BPS − DELTA)` — the discounted mark, on `S`.
    k1: u128,
    /// `R = BPS · (k1 − 1)` — the seizure's worst rounding, added to the shortfall so the target is restored for EVERY
    /// rounding of `S` (see `liquidation_amount`).
    r: u128,
}

impl LiqRule {
    /// `None` when the parameters cannot form a rule — refused at prove AND verify: a zero mark; a discount that is not a
    /// proper fraction; a target the discounted seizure cannot reach (`RHO_TARGET · (BPS − DELTA) ≤ BPS²`: retiring debt
    /// would not raise the ratio); a due ratio above the target (a due position could then have no shortfall); or a
    /// multiplier past the wide multiply's seven chunks.
    fn mults(&self) -> Option<LiqMults> {
        let (bps, ps) = (u128::from(BPS_DEN_U64), u128::from(LIQ_PRICE_SCALE));
        if self.p == 0 || self.delta_bps >= BPS_DEN_U64 || self.rho_liq_bps > self.rho_target_bps {
            return None;
        }
        let bmd = bps - u128::from(self.delta_bps);
        let a = u128::from(self.rho_target_bps).checked_mul(bmd)?.checked_sub(bps * bps)?;
        if a == 0 {
            return None;
        }
        let k_m = u128::from(self.rho_target_bps).checked_mul(ps)?.checked_mul(bmd)?;
        let k_d = u128::from(self.p).checked_mul(bps)?.checked_mul(bmd)?;
        let k_l = u128::from(self.rho_liq_bps).checked_mul(ps)?.checked_mul(bmd)?;
        let q = ps.checked_mul(a)?;
        let k1 = u128::from(self.p) * bmd;
        let r = bps * (k1 - 1);
        let m = LiqMults { k_m, k_d, k_l, q, k1, r };
        if [m.k_m, m.k_d, m.k_l, m.q, m.k1, m.r].iter().all(|&k| mul14_k_admissible(k)) { Some(m) } else { None }
    }

    /// Whether the rule can be evaluated at all (both doors refuse a rule that cannot).
    #[must_use]
    pub fn admissible(&self) -> bool {
        self.mults().is_some()
    }
}

/// `k1 = p · (BPS_DEN − DELTA_bps)`, the discounted mark — a u128, so no quotable mark meets a ceiling. `None` for a
/// zero mark or a discount that is not a proper fraction.
#[must_use]
pub fn liquidation_seize_k1(p: u64, delta_bps: u64) -> Option<u128> {
    if p == 0 || delta_bps >= BPS_DEN_U64 {
        return None;
    }
    Some(u128::from(p) * u128::from(BPS_DEN_U64 - delta_bps))
}

/// `k2 = BPS_DEN · PRICE_SCALE`, the unit factor on the retired side.
pub const LIQ_SEIZE_K2: u64 = BPS_DEN_U64 * LIQ_PRICE_SCALE;

// ── native limb arithmetic at the product width (16-bit little-endian limbs): the twin of the n-limb gadgets ──

/// `a ≥ b` over equal-length limb arrays.
fn limbs_ge(a: &[u64], b: &[u64]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a + b`, `None` on a carry out of the width.
fn limbs_add(a: &[u64], b: &[u64]) -> Option<Vec<u64>> {
    debug_assert_eq!(a.len(), b.len());
    let mut out = vec![0u64; a.len()];
    let mut carry = 0u64;
    for i in 0..a.len() {
        let t = a[i] + b[i] + carry;
        out[i] = t & LIMB16_MASK;
        carry = t >> LIMB16_BITS;
    }
    if carry != 0 { None } else { Some(out) }
}

/// `a − b`, `None` when `a < b`.
fn limbs_sub(a: &[u64], b: &[u64]) -> Option<Vec<u64>> {
    debug_assert_eq!(a.len(), b.len());
    let mut out = vec![0u64; a.len()];
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let d = a[i] as i64 - b[i] as i64 - borrow;
        if d < 0 {
            out[i] = (d + (1i64 << LIMB16_BITS)) as u64;
            borrow = 1;
        } else {
            out[i] = d as u64;
            borrow = 0;
        }
    }
    if borrow != 0 { None } else { Some(out) }
}

/// `ceil(n / q)` for a `q` in `1..2^98` (schoolbook long division; the running remainder stays below 98 + 16 bits), in
/// the same limb count; `None` only when the rounding carries out of the width.
fn limbs_div_ceil(n: &[u64], q: u128) -> Option<Vec<u64>> {
    debug_assert!(q > 0 && mul14_k_admissible(q));
    let mut out = vec![0u64; n.len()];
    let mut rem: u128 = 0;
    for i in (0..n.len()).rev() {
        let cur = (rem << LIMB16_BITS) | u128::from(n[i]);
        out[i] = (cur / q) as u64;
        rem = cur % q;
    }
    if rem != 0 {
        let mut i = 0;
        loop {
            if i == out.len() {
                return None;
            }
            out[i] += 1;
            if out[i] <= LIMB16_MASK {
                break;
            }
            out[i] = 0;
            i += 1;
        }
    }
    Some(out)
}

/// A 256-bit value at the product width (zero-extended).
fn widen16(v: &[u64; N_LIMB16]) -> [u64; M14_P16_LIMBS] {
    core::array::from_fn(|i| if i < N_LIMB16 { v[i] } else { 0 })
}

/// A limb array back to a `U256`, `None` when it does not fit 256 bits.
fn limbs_to_u256(l: &[u64]) -> Option<U256> {
    if l.len() > N_LIMB16 && l[N_LIMB16..].iter().any(|&x| x != 0) {
        return None;
    }
    let mut out: U256 = [0; 4];
    for (i, &x) in l.iter().enumerate().take(N_LIMB16) {
        out[i / 4] |= x << (16 * (i % 4));
    }
    Some(out)
}

/// `ceil(C · k2 / k1)` at the product width — the seizure before the `S ≤ D` cap.
fn liquidation_seize_wide(c: U256, k1: u128) -> Option<[u64; M14_P16_LIMBS]> {
    let (_, _, ck2) = m14_native(&u256_to_limbs16(c), u128::from(LIQ_SEIZE_K2));
    let v = limbs_div_ceil(&ck2, k1)?;
    Some(core::array::from_fn(|i| v[i]))
}

/// The least collateral whose discounted value covers `C`: `ceil(C · k2 / k1)` — the seize half of the rule before
/// the `S ≤ D` cap. `None` on an inadmissible mark / discount or a 256-bit overflow.
#[must_use]
pub fn liquidation_seize_amount(c: U256, p: u64, delta_bps: u64) -> Option<U256> {
    let k1 = liquidation_seize_k1(p, delta_bps)?;
    limbs_to_u256(&liquidation_seize_wide(c, k1)?)
}

/// Both amounts AND the regime each landed in — `(C, S, full_retire, full_seize)` — for a DUE position; `None` when the
/// position is not due or the rule is inadmissible. The regimes are the two PRIVATE selectors the carrier's witness
/// carries; the amounts are what it commits.
fn liquidation_amount_regimes(d: U256, m: U256, rule: &LiqRule) -> Option<(U256, U256, bool, bool)> {
    liquidation_amount_regimes_capped(d, m, LIQ_POOL_UNBOUNDED, rule).map(|(c, s, fc, fs, _)| (c, s, fc, fs))
}

/// The ONE amount rule with the POOL CAP: `C = min(⌈N/Q⌉, M, T)` — a pool that cannot cover the rule's retire burns all it
/// holds (`pool_c`: a PARTIAL liquidation), and `S` is then the least collateral covering that `C`. Returns `(C, S,
/// full_c, full_s, pool_c)`; `None` when the position is not due, the rule is inadmissible, or the pool is EMPTY (a zero
/// retire is no liquidation).
fn liquidation_amount_regimes_capped(d: U256, m: U256, t: U256, rule: &LiqRule) -> Option<(U256, U256, bool, bool, bool)> {
    let (c, s, full_c, full_s) = liquidation_amount_uncapped(d, m, rule)?;
    if limbs_ge(&u256_to_limbs16(t), &u256_to_limbs16(c)) {
        return Some((c, s, full_c, full_s, false));
    }
    if t == [0; 4] {
        return None;
    }
    let k = rule.mults()?;
    let s_wide = liquidation_seize_wide(t, k.k1)?;
    let dl = u256_to_limbs16(d);
    let full_s = !limbs_ge(&widen16(&dl), &s_wide);
    let s = if full_s { d } else { limbs_to_u256(&s_wide)? };
    Some((t, s, false, full_s, true))
}

fn liquidation_amount_uncapped(d: U256, m: U256, rule: &LiqRule) -> Option<(U256, U256, bool, bool)> {
    let k = rule.mults()?;
    let (dl, ml) = (u256_to_limbs16(d), u256_to_limbs16(m));
    let (_, _, pm) = m14_native(&ml, k.k_m);
    let (_, _, pd) = m14_native(&dl, k.k_d);
    let (_, _, pl) = m14_native(&ml, k.k_l);
    // DUE: M·k_L > D·k_D  ⟺  D·p·BPS < RHO_LIQ·M·PRICE_SCALE (§2.1, both sides scaled by BPS − DELTA)
    if !limbs_ge(&pl, &pd) || pl == pd {
        return None;
    }
    // the shortfall N' = M·k_M + R − D·k_D (> 0 for a due position under RHO_LIQ ≤ RHO_TARGET; fail closed otherwise)
    let t0 = limbs_add(&pm, &u128_to_limbs16_wide(k.r))?;
    let n = limbs_sub(&t0, &pd)?;
    let c_wide = limbs_div_ceil(&n, k.q)?;
    let full_c = limbs_ge(&c_wide, &widen16(&ml));
    let c = if full_c { m } else { limbs_to_u256(&c_wide)? };
    let s_wide = liquidation_seize_wide(c, k.k1)?;
    let full_s = !limbs_ge(&widen16(&dl), &s_wide);
    let s = if full_s { d } else { limbs_to_u256(&s_wide)? };
    Some((c, s, full_c, full_s))
}

/// ⭐ THE ONE AMOUNT RULE (spec §2.2), natively — `(C retired, S seized)` for a DUE position, `None` when it is not due
/// or the rule is inadmissible. The circuit proves exactly this value over the four commitments; the node's fold rule
/// computes it here (as `aggregate_solvent` delegates to `is_solvent`):
///
///   C = min( ceil( (M·k_M + R − D·k_D) / Q ), M )   — the least retire that restores RHO_TARGET after the seizure
///                                                      for EVERY rounding of S (R = BPS·(k1 − 1) absorbs the ceiling)
///   S = min( ceil( C·k2 / k1 ), D )                 — the least collateral whose discounted value covers C
///
/// A full retire (`C = M`) is a position the discounted collateral cannot cover; a full seize (`S = D`) leaves the pool
/// the shortfall (Liquity's under-100 % liquidation). Pins prove the post-state sits at or above the target or is fully
/// liquidated, that one unit less of `S` would not cover `C`, and that one unit less of `C` would not restore the
/// target under the seizure's worst rounding.
#[must_use]
pub fn liquidation_amount(d: U256, m: U256, rule: &LiqRule) -> Option<(U256, U256)> {
    liquidation_amount_regimes(d, m, rule).map(|(c, s, _, _)| (c, s))
}

/// ⭐ THE AMOUNT RULE AGAINST A POOL OF `T` — what a liquidation actually retires and seizes: `C = min(⌈N/Q⌉, M, T)`, `S`
/// the least collateral covering it. A pool smaller than the rule's retire is burned WHOLE (a partial liquidation: the
/// position stays under the target, and its mints stay refused, until the pool grows). `None` when not due or T = 0.
#[must_use]
pub fn liquidation_amount_capped(d: U256, m: U256, t: U256, rule: &LiqRule) -> Option<(U256, U256)> {
    liquidation_amount_regimes_capped(d, m, t, rule).map(|(c, s, _, _, _)| (c, s))
}

// The amount carrier's layout: four openings (D, M, C, S) with their range bits, two regime selectors, seven wide
// products, four adds (three against pinned public constants), eight compares (three gated by a selector).
const LQ_D: usize = 0;
const LQ_M: usize = LQ_D + N_LIMB16;
const LQ_C: usize = LQ_M + N_LIMB16;
const LQ_S: usize = LQ_C + N_LIMB16;
const LQ_DBLIND: usize = LQ_S + N_LIMB16;
const LQ_MBLIND: usize = LQ_DBLIND + DIGEST_LANES;
const LQ_CBLIND: usize = LQ_MBLIND + DIGEST_LANES;
const LQ_SBLIND: usize = LQ_CBLIND + DIGEST_LANES;
const LQ_DD: usize = LQ_SBLIND + DIGEST_LANES;
const LQ_DM: usize = LQ_DD + DIGEST_LANES;
const LQ_DC: usize = LQ_DM + DIGEST_LANES;
const LQ_DS: usize = LQ_DC + DIGEST_LANES;
const LQ_DINTER: usize = LQ_DS + DIGEST_LANES;
const LQ_MINTER: usize = LQ_DINTER + T_OPEN;
const LQ_CINTER: usize = LQ_MINTER + T_OPEN;
const LQ_SINTER: usize = LQ_CINTER + T_OPEN;
const LQ_DVBITS: usize = LQ_SINTER + T_OPEN;
const LQ_MVBITS: usize = LQ_DVBITS + RANGE16_COLS;
const LQ_CVBITS: usize = LQ_MVBITS + RANGE16_COLS;
const LQ_SVBITS: usize = LQ_CVBITS + RANGE16_COLS;
const LQ_FULL_C: usize = LQ_SVBITS + RANGE16_COLS; // 1 ⇒ C = M (the discounted collateral cannot cover the debt)
const LQ_FULL_S: usize = LQ_FULL_C + 1; // 1 ⇒ S = D (the seizure the rule wants exceeds the reserve)
const LQ_PM: usize = LQ_FULL_S + 1; // M · k_M
const LQ_PD: usize = LQ_PM + MUL14_COLS; // D · k_D
const LQ_PC: usize = LQ_PD + MUL14_COLS; // C · Q
const LQ_PL: usize = LQ_PC + MUL14_COLS; // M · k_L
const LQ_PS1: usize = LQ_PL + MUL14_COLS; // S · k1
const LQ_PC2: usize = LQ_PS1 + MUL14_COLS; // C · k2
const LQ_PD1: usize = LQ_PC2 + MUL14_COLS; // D · k1
const LQ_R: usize = LQ_PD1 + MUL14_COLS; // the public constant R = BPS·(k1 − 1), pinned
const LQ_T0_S: usize = LQ_R + M14_P16_LIMBS; // T0 = M·k_M + R
const LQ_T0_CARRY: usize = LQ_T0_S + M14_P16_LIMBS;
const LQ_T1_S: usize = LQ_T0_CARRY + M14_P16_LIMBS; // T1 = C·Q + D·k_D
const LQ_T1_CARRY: usize = LQ_T1_S + M14_P16_LIMBS;
const LQ_QM1: usize = LQ_T1_CARRY + M14_P16_LIMBS; // the public constant Q − 1, pinned
const LQ_T2_S: usize = LQ_QM1 + M14_P16_LIMBS; // T2 = T0 + (Q − 1)
const LQ_T2_CARRY: usize = LQ_T2_S + M14_P16_LIMBS;
const LQ_K1M1: usize = LQ_T2_CARRY + M14_P16_LIMBS; // the public constant k1 − 1, pinned
const LQ_T3_S: usize = LQ_K1M1 + M14_P16_LIMBS; // T3 = C·k2 + (k1 − 1)
const LQ_T3_CARRY: usize = LQ_T3_S + M14_P16_LIMBS;
/// A compare block at the product width: slack, borrow, slack bits.
const GE_WIDE: usize = M14_P16_LIMBS * (2 + N_LIMB16);
/// A compare block at the value width.
const GE_VALUE: usize = N_LIMB16 * (2 + N_LIMB16);
const LQ_G1: usize = LQ_T3_CARRY + M14_P16_LIMBS; // [¬full_c]  T1 ≥ T0         C covers the shortfall
const LQ_G2: usize = LQ_G1 + GE_WIDE; //             T2 ≥ T1         and is the least that does
const LQ_G3: usize = LQ_G2 + GE_WIDE; //             M ≥ C
const LQ_G4: usize = LQ_G3 + GE_VALUE; //            PL ≥ PD + 1     DUE
const LQ_G5: usize = LQ_G4 + GE_WIDE; // [¬full_s]  PS1 ≥ PC2       S covers C
const LQ_G6: usize = LQ_G5 + GE_WIDE; //             T3 ≥ PS1        and is the least that does
const LQ_G7: usize = LQ_G6 + GE_WIDE; //             D ≥ S
const LQ_G8: usize = LQ_G7 + GE_VALUE; // [full_s]   PC2 ≥ PD1 + 1   the reserve cannot cover C
// THE POOL CAP (spec §2.2 / §10: "when even the whole pool cannot restore RHO_TARGET, C = min(M, pool)"): the pool's T
// opened against the pool word the chain holds, a third regime selector, and one ungated compare — so C is exactly
// min(⌈N/Q⌉, M, T): G2 bounds C by the rule, G3 by M, G9 by T, and the active regime pins C to one of the three.
const LQ_T: usize = LQ_G8 + GE_WIDE;
const LQ_TBLIND: usize = LQ_T + N_LIMB16;
const LQ_DT: usize = LQ_TBLIND + DIGEST_LANES;
const LQ_TINTER: usize = LQ_DT + DIGEST_LANES;
const LQ_TVBITS: usize = LQ_TINTER + T_OPEN;
const LQ_POOL_C: usize = LQ_TVBITS + RANGE16_COLS; // 1 ⇒ C = T (the pool cannot cover the rule's retire: a PARTIAL liquidation)
const LQ_G9: usize = LQ_POOL_C + 1; //               T ≥ C           the pool holds what it burns
const LQ_WIDTH: usize = LQ_G9 + GE_VALUE;

/// A pool word that never binds — the uncapped rule (`liquidation_amount`), for callers that price a position alone.
pub const LIQ_POOL_UNBOUNDED: U256 = [u64::MAX; 4];

/// A u128 as little-endian 16-bit limbs at the product width.
fn u128_to_limbs16_wide(v: u128) -> [u64; M14_P16_LIMBS] {
    core::array::from_fn(|i| if i < 8 { ((v >> (16 * i)) & u128::from(LIMB16_MASK)) as u64 } else { 0 })
}

/// A public constant laid as columns the AIR pins limb by limb.
fn push_pinned_limbs(cs: &mut Vec<Ea4>, local: &crate::air_zerocheck::Row<'_>, base: usize, limbs: &[u64]) {
    for (i, &l) in limbs.iter().enumerate() {
        cs.push(local[base + i] - Ea4::from(Fa4::from_u64(l)));
    }
}

/// Lay a run of values into consecutive columns (every row of a replicated trace).
fn fill_cols(cols: &mut [Vec<Fa4>], base: usize, vals: &[u64]) {
    for (i, &v) in vals.iter().enumerate() {
        cols[base + i].fill(Fa4::from_u64(v));
    }
}

struct LiquidationAmountAir {
    gamma: Ea4,
    k: LiqMults,
    /// `(DD, DM, DC, DS, DT)` — reserve, minted, retired, seized, and the pool's T.
    commits: [[Ea4; DIGEST_LANES]; 5],
}
impl AirConstraint for LiquidationAmountAir {
    /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
    fn is_row_local(&self) -> bool {
        true
    }
    fn degree(&self, _nvars: usize) -> usize {
        // ⛔ THIS GATE EMBEDS A PERMUTATION (the commitment openings); declaring less truncates the sumcheck.
        crate::pow_pq_air::PERM_MAX_DEGREE
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
        let mut cs: Vec<Ea4> = Vec::new();
        let n = M14_P16_LIMBS;
        // the four openings, each pinned to the statement's commitment
        for (i, (v, blind, commit, inter, vbits)) in [
            (LQ_D, LQ_DBLIND, LQ_DD, LQ_DINTER, LQ_DVBITS),
            (LQ_M, LQ_MBLIND, LQ_DM, LQ_MINTER, LQ_MVBITS),
            (LQ_C, LQ_CBLIND, LQ_DC, LQ_CINTER, LQ_CVBITS),
            (LQ_S, LQ_SBLIND, LQ_DS, LQ_SINTER, LQ_SVBITS),
            (LQ_T, LQ_TBLIND, LQ_DT, LQ_TINTER, LQ_TVBITS),
        ]
        .into_iter()
        .enumerate()
        {
            push_commit_open_constraints(&mut cs, local, v, blind, commit, inter, vbits);
            for c in 0..DIGEST_LANES {
                cs.push(local[commit + c] - self.commits[i][c]);
            }
        }
        // the regime selectors are booleans; a full retire pins C = M, a full seize pins S = D, a pool-capped retire pins
        // C = T; the two retire caps are exclusive (where M = T either selector gives the same C)
        let (fc, fs, pcap) = (local[LQ_FULL_C], local[LQ_FULL_S], local[LQ_POOL_C]);
        cs.push(fc * (fc - Ea4::ONE));
        cs.push(fs * (fs - Ea4::ONE));
        cs.push(pcap * (pcap - Ea4::ONE));
        cs.push(fc * pcap);
        for i in 0..N_LIMB16 {
            cs.push(fc * (local[LQ_M + i] - local[LQ_C + i]));
            cs.push(fs * (local[LQ_D + i] - local[LQ_S + i]));
            cs.push(pcap * (local[LQ_T + i] - local[LQ_C + i]));
        }
        // the seven products — every operand read from its opening's range bits
        push_mul14_constraints(&mut cs, local, LQ_MVBITS, self.k.k_m, LQ_PM);
        push_mul14_constraints(&mut cs, local, LQ_DVBITS, self.k.k_d, LQ_PD);
        push_mul14_constraints(&mut cs, local, LQ_CVBITS, self.k.q, LQ_PC);
        push_mul14_constraints(&mut cs, local, LQ_MVBITS, self.k.k_l, LQ_PL);
        push_mul14_constraints(&mut cs, local, LQ_SVBITS, self.k.k1, LQ_PS1);
        push_mul14_constraints(&mut cs, local, LQ_CVBITS, u128::from(LIQ_SEIZE_K2), LQ_PC2);
        push_mul14_constraints(&mut cs, local, LQ_DVBITS, self.k.k1, LQ_PD1);
        let (pm, pd, pc, pl, ps1, pc2, pd1) = (LQ_PM + M14_P16, LQ_PD + M14_P16, LQ_PC + M14_P16, LQ_PL + M14_P16, LQ_PS1 + M14_P16, LQ_PC2 + M14_P16, LQ_PD1 + M14_P16);
        // the adds: T0 = PM + R, T1 = PC + PD, T2 = T0 + (Q − 1), T3 = PC2 + (k1 − 1)
        push_pinned_limbs(&mut cs, local, LQ_R, &u128_to_limbs16_wide(self.k.r));
        push_add_n_constraints(&mut cs, local, pm, LQ_R, LQ_T0_S, LQ_T0_CARRY, n);
        push_add_n_constraints(&mut cs, local, pc, pd, LQ_T1_S, LQ_T1_CARRY, n);
        push_pinned_limbs(&mut cs, local, LQ_QM1, &u128_to_limbs16_wide(self.k.q - 1));
        push_add_n_constraints(&mut cs, local, LQ_T0_S, LQ_QM1, LQ_T2_S, LQ_T2_CARRY, n);
        push_pinned_limbs(&mut cs, local, LQ_K1M1, &u128_to_limbs16_wide(self.k.k1 - 1));
        push_add_n_constraints(&mut cs, local, pc2, LQ_K1M1, LQ_T3_S, LQ_T3_CARRY, n);
        // the compares; a gated block's differences are the selector times the plain differences
        let diff = |gate: Ea4, x: usize, y: usize, less_one: bool| -> Vec<Ea4> {
            (0..n).map(|i| gate * (local[x + i] - local[y + i] - if less_one && i == 0 { Ea4::ONE } else { Ea4::ZERO })).collect()
        };
        push_ge_n_diff_constraints(&mut cs, local, &diff(Ea4::ONE - fc - pcap, LQ_T1_S, LQ_T0_S, false), LQ_G1, LQ_G1 + n, LQ_G1 + 2 * n);
        push_ge_n_constraints(&mut cs, local, LQ_T2_S, LQ_T1_S, LQ_G2, LQ_G2 + n, LQ_G2 + 2 * n, n);
        push_ge_n_constraints(&mut cs, local, LQ_M, LQ_C, LQ_G3, LQ_G3 + N_LIMB16, LQ_G3 + 2 * N_LIMB16, N_LIMB16);
        push_ge_n_diff_constraints(&mut cs, local, &diff(Ea4::ONE, pl, pd, true), LQ_G4, LQ_G4 + n, LQ_G4 + 2 * n);
        push_ge_n_diff_constraints(&mut cs, local, &diff(Ea4::ONE - fs, ps1, pc2, false), LQ_G5, LQ_G5 + n, LQ_G5 + 2 * n);
        push_ge_n_constraints(&mut cs, local, LQ_T3_S, ps1, LQ_G6, LQ_G6 + n, LQ_G6 + 2 * n, n);
        push_ge_n_constraints(&mut cs, local, LQ_D, LQ_S, LQ_G7, LQ_G7 + N_LIMB16, LQ_G7 + 2 * N_LIMB16, N_LIMB16);
        push_ge_n_diff_constraints(&mut cs, local, &diff(fs, pc2, pd1, true), LQ_G8, LQ_G8 + n, LQ_G8 + 2 * n);
        push_ge_n_constraints(&mut cs, local, LQ_T, LQ_C, LQ_G9, LQ_G9 + N_LIMB16, LQ_G9 + 2 * N_LIMB16, N_LIMB16);
        let mut acc = Ea4::ZERO;
        let mut gp = Ea4::ONE;
        for c in cs {
            acc += gp * c;
            gp *= self.gamma;
        }
        acc
    }
}

fn liq_amount_statement_bind(commits: &[Digest; 5], rule: &LiqRule) -> Vec<Fa4> {
    let mut v = Vec::with_capacity(1 + 5 * DIGEST_LANES + 16);
    v.push(Fa4::from_u64(LIQ_AMOUNT_DOMAIN));
    for d in commits {
        for &x in d {
            v.push(Fa4::from_u64(x));
        }
    }
    for x in [rule.p, rule.delta_bps, rule.rho_target_bps, rule.rho_liq_bps] {
        for i in 0..4 {
            v.push(Fa4::from_u64((x >> (16 * i)) & LIMB16_MASK)); // four exact lanes: a u64 is not one field element
        }
    }
    v
}

fn liq_amount_air(k: LiqMults, commits: &[Digest; 5]) -> impl Fn(Ea4) -> LiquidationAmountAir {
    let commits: [[Ea4; DIGEST_LANES]; 5] = core::array::from_fn(|i| commit_to_ea4(commits[i]));
    move |gamma| LiquidationAmountAir { gamma, k, commits }
}

/// Lay the amount trace for the claimed `(C, S)` in the claimed regimes. `None` when the rule is inadmissible, a
/// product overflows, or a gadget has no witness — the DUE compare for a position that is not due, the two-sided bounds
/// for an amount that is not the rule's value in the claimed regime. The selector constraints themselves (`full_c ⇒
/// C = M`, `full_s ⇒ S = D`) are plain constraints the VERIFIER refuses; the pins exercise both doors.
#[allow(clippy::too_many_arguments)]
fn liquidation_amount_trace(
    d: U256,
    m: U256,
    t: U256,
    c: U256,
    s: U256,
    blinds: &[Digest; 5],
    rule: &LiqRule,
    full_c: bool,
    full_s: bool,
    pool_c: bool,
) -> Option<(Vec<Vec<Fa4>>, [Digest; 5])> {
    let k = rule.mults()?;
    let (dl, ml, cl, sl, tl) = (u256_to_limbs16(d), u256_to_limbs16(m), u256_to_limbs16(c), u256_to_limbs16(s), u256_to_limbs16(t));
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; LQ_WIDTH];
    fill_cols(&mut cols, LQ_D, &dl);
    fill_cols(&mut cols,LQ_M, &ml);
    fill_cols(&mut cols,LQ_C, &cl);
    fill_cols(&mut cols,LQ_S, &sl);
    fill_cols(&mut cols, LQ_T, &tl);
    for (b, base) in blinds.iter().zip([LQ_DBLIND, LQ_MBLIND, LQ_CBLIND, LQ_SBLIND, LQ_TBLIND]) {
        fill_cols(&mut cols,base, b);
    }
    let dd = place_commit_open(&mut cols, dl, blinds[0], LQ_DINTER, LQ_DVBITS);
    let dm = place_commit_open(&mut cols, ml, blinds[1], LQ_MINTER, LQ_MVBITS);
    let dc = place_commit_open(&mut cols, cl, blinds[2], LQ_CINTER, LQ_CVBITS);
    let ds = place_commit_open(&mut cols, sl, blinds[3], LQ_SINTER, LQ_SVBITS);
    let dt = place_commit_open(&mut cols, tl, blinds[4], LQ_TINTER, LQ_TVBITS);
    let commits = [dd, dm, dc, ds, dt];
    for (dg, base) in commits.iter().zip([LQ_DD, LQ_DM, LQ_DC, LQ_DS, LQ_DT]) {
        fill_cols(&mut cols,base, dg);
    }
    cols[LQ_FULL_C].fill(Fa4::from_u64(u64::from(full_c)));
    cols[LQ_FULL_S].fill(Fa4::from_u64(u64::from(full_s)));
    cols[LQ_POOL_C].fill(Fa4::from_u64(u64::from(pool_c)));
    let pm = place_mul14(&mut cols, &ml, k.k_m, LQ_PM)?;
    let pd = place_mul14(&mut cols, &dl, k.k_d, LQ_PD)?;
    let pc = place_mul14(&mut cols, &cl, k.q, LQ_PC)?;
    let pl = place_mul14(&mut cols, &ml, k.k_l, LQ_PL)?;
    let ps1 = place_mul14(&mut cols, &sl, k.k1, LQ_PS1)?;
    let pc2 = place_mul14(&mut cols, &cl, u128::from(LIQ_SEIZE_K2), LQ_PC2)?;
    let pd1 = place_mul14(&mut cols, &dl, k.k1, LQ_PD1)?;
    let r = u128_to_limbs16_wide(k.r);
    fill_cols(&mut cols,LQ_R, &r);
    let t0 = place_add_n(&mut cols, &pm, &r, LQ_T0_S, LQ_T0_CARRY)?;
    let t1 = place_add_n(&mut cols, &pc, &pd, LQ_T1_S, LQ_T1_CARRY)?;
    let qm1 = u128_to_limbs16_wide(k.q - 1);
    fill_cols(&mut cols,LQ_QM1, &qm1);
    let t2 = place_add_n(&mut cols, &t0, &qm1, LQ_T2_S, LQ_T2_CARRY)?;
    let k1m1 = u128_to_limbs16_wide(k.k1 - 1);
    fill_cols(&mut cols,LQ_K1M1, &k1m1);
    let t3 = place_add_n(&mut cols, &pc2, &k1m1, LQ_T3_S, LQ_T3_CARRY)?;
    let n = M14_P16_LIMBS;
    // a gated block lays zero differences when its selector is off (asserting nothing, as the AIR then asks nothing)
    let diff = |on: bool, x: &[u64], y: &[u64], less_one: bool| -> Vec<i64> {
        (0..x.len()).map(|i| if on { x[i] as i64 - y[i] as i64 - i64::from(less_one && i == 0) } else { 0 }).collect()
    };
    let laid = place_ge_n_diff(&mut cols, &diff(!full_c && !pool_c, &t1, &t0, false), LQ_G1, LQ_G1 + n, LQ_G1 + 2 * n) // C covers the shortfall
        && place_ge_n(&mut cols, &t2, &t1, LQ_G2, LQ_G2 + n, LQ_G2 + 2 * n) // and is the least that does
        && place_ge_n(&mut cols, &ml, &cl, LQ_G3, LQ_G3 + N_LIMB16, LQ_G3 + 2 * N_LIMB16) // C ≤ M
        && place_ge_n_diff(&mut cols, &diff(true, &pl, &pd, true), LQ_G4, LQ_G4 + n, LQ_G4 + 2 * n) // DUE
        && place_ge_n_diff(&mut cols, &diff(!full_s, &ps1, &pc2, false), LQ_G5, LQ_G5 + n, LQ_G5 + 2 * n) // S covers C
        && place_ge_n(&mut cols, &t3, &ps1, LQ_G6, LQ_G6 + n, LQ_G6 + 2 * n) // and is the least that does
        && place_ge_n(&mut cols, &dl, &sl, LQ_G7, LQ_G7 + N_LIMB16, LQ_G7 + 2 * N_LIMB16) // S ≤ D
        && place_ge_n_diff(&mut cols, &diff(full_s, &pc2, &pd1, true), LQ_G8, LQ_G8 + n, LQ_G8 + 2 * n) // a full seize: the reserve cannot cover C
        && place_ge_n(&mut cols, &tl, &cl, LQ_G9, LQ_G9 + N_LIMB16, LQ_G9 + 2 * N_LIMB16); // C ≤ T: the pool holds what it burns
    if !laid {
        return None;
    }
    Some((cols, commits))
}

/// One liquidation's proven amounts: the carrier bytes, the four commitments the liquidation object carries —
/// `(DD, DM, DC, DS)` = `(reserve, minted, retired, seized)` — and the two amounts the bonded prover derived.
pub struct LiqAmountProof {
    pub bytes: Vec<u8>,
    /// `(DD, DM, DC, DS, DT)` — reserve, minted, retired, seized, and the pool's T the retire is capped by.
    pub commits: [Digest; 5],
    pub c: U256,
    pub s: U256,
}

fn prove_liq_trace(cols2: Vec<Vec<Fa4>>, commits: &[Digest; 5], rule: &LiqRule) -> Option<Vec<u8>> {
    let k = rule.mults()?;
    let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
    let statement_bind = liq_amount_statement_bind(commits, rule);
    prove_value_carrier(cols, liq_amount_air(k, commits), &statement_bind)
}

/// PROVE a liquidation's amounts from the position's openings `(D, M)` and the pool's `T` under `rule`. `blinds` are the
/// blinds of the reserve and minted commitments the chain holds, fresh blinds for `C` and `S`, then the pool T's blind;
/// the bonded prover derives `(C, S)` by the ONE capped rule and proves it over the five commitments. `None` when the
/// position is not due, the pool is empty, or the rule is inadmissible — there is no liquidation to prove.
#[must_use]
pub fn prove_liquidation_amount_carrier(d: U256, m: U256, t: U256, blinds: &[Digest; 5], rule: &LiqRule) -> Option<LiqAmountProof> {
    let (c, s, full_c, full_s, pool_c) = liquidation_amount_regimes_capped(d, m, t, rule)?;
    let (cols, commits) = liquidation_amount_trace(d, m, t, c, s, blinds, rule, full_c, full_s, pool_c)?;
    let bytes = prove_liq_trace(cols, &commits, rule)?;
    Some(LiqAmountProof { bytes, commits, c, s })
}

/// VERIFY an amount carrier against the liquidation object's five commitments (the fifth is the pool's T word the chain
/// holds) and the folded mark's rule — every node, bonded or not, holding nothing but these. Fail-closed on an
/// inadmissible rule, a value not opening to its digest, a wrong product, a position that is not due, or an amount that
/// is not the capped rule's value.
#[must_use]
pub fn verify_liquidation_amount_carrier(bytes: &[u8], commits: &[Digest; 5], rule: &LiqRule) -> bool {
    let Some(k) = rule.mults() else { return false };
    if bytes.is_empty() {
        return false;
    }
    let statement_bind = liq_amount_statement_bind(commits, rule);
    verify_value_carrier(bytes, liq_amount_air(k, commits), &statement_bind, (REC_DECIDER_FOLDING, LQ_WIDTH))
}

#[cfg(test)]
mod tests {
    use super::*;

    const R: u32 = 15_000; // 150%

    // The commitment HIDES the total: a large circulating total commits to a byte-uniform digest with the
    // same shape as a small one under a different blind — no observer/node can read the value from it.
    #[test]
    fn commitment_hides_the_total() {
        let big = solvency_commit(1_000_000_000_000_00, [0x11; DIGEST_LANES]);
        let small = solvency_commit(1, [0x22; DIGEST_LANES]);
        assert_ne!(big, small, "distinct (value,blind) → distinct digest (binding)");
        // same value, different blind → different commitment (hiding: the digest carries no readable value)
        assert_ne!(solvency_commit(500, crate::poseidon2_compress::lanes_of(&[1, 0, 0, 0])), solvency_commit(500, crate::poseidon2_compress::lanes_of(&[2, 0, 0, 0])));
        assert_eq!(big.len(), DIGEST_LANES, "fixed-size uniform digest, no value leaked by shape");
    }

    // HONEST peg-in: a 150%-collateralized mint conserves + stays solvent → accepted, and the returned
    // totals are exactly old+delta (no hidden issuance).
    #[test]
    fn honest_peg_in_is_solvent_and_conserves() {
        // start solvent: reserve 1_500 collateralizes minted 1_000 at 150%
        let (r0, m0) = (1_500u128, 1_000u128);
        assert!(is_solvent(r0, m0, R));
        // deposit worth 1_500 collateralizes up to 1_000 new USDm; mint exactly 1_000
        let (r1, m1) = peg_in_apply(r0, m0, 1_500, 1_000, R).expect("150%-collateralized mint accepted");
        assert_eq!((r1, m1), (3_000, 2_000), "totals advance by EXACTLY the event (conservation)");
        assert!(is_solvent(r1, m1, R));
    }

    // ADVERSARIAL — SATURATION (F2-red-PROOFS-20261023): once both scaled sides pass 2^128 a saturating
    // compare reads MAX ≥ MAX = solvent. reserve 2^115 vs minted 2^116 at 150% is 1/3 collateralized; the
    // u128 oracles must agree with the exact u256 relation, and a peg-in must never mint past its backing.
    #[test]
    fn is_solvent_never_calls_a_saturated_insolvent_book_solvent() {
        let (r, m) = (1u128 << 115, 1u128 << 116);
        assert!(!is_solvent_256(u256_from_u128(r), u256_from_u128(m), R), "the exact relation: insolvent");
        assert!(!is_solvent(r, m, R), "a saturated MAX ≥ MAX must not read solvent");
        assert!(is_solvent(m * 2, m, R) && !is_solvent(m * 3 / 2 - 1, m, R), "exact at the 150% boundary");
        // a deposit worth 2^115 backs at most 2^115·2/3 USDm; minting 2^116 against it is over-issuance
        assert_eq!(peg_in_apply(0, 0, r, m, R), None, "a saturated per-event backing must reject the mint");
        assert_eq!(peg_out_apply(r, m, 0, 0, R), None, "an insolvent book stays insolvent after a no-op redeem");
    }

    // ADVERSARIAL — OVER-MINT (would be theft/issuance): minting MORE than the deposit's 150% capacity MUST
    // reject, whether it breaks per-event backing or global solvency.
    #[test]
    fn over_mint_rejects() {
        // deposit worth 1_500 collateralizes at most floor(1_500*10000/15000)=1_000 USDm; try to mint 1_001
        assert!(peg_in_apply(1_500, 1_000, 1_500, 1_001, R).is_none(), "over-mint beyond backing MUST reject");
        // a deposit that does not cover the mint (deposit_value 0) MUST reject — the per-event backing gate holds
        assert!(peg_in_apply(1_500, 1_000, 0, 1, R).is_none(), "a mint the deposit doesn't collateralize MUST reject");
    }

    // ADVERSARIAL — RESERVE DRAIN on redeem: releasing more reserve than the burned USDm's face value, or
    // pushing the peg under-collateralized, MUST reject.
    #[test]
    fn peg_out_drain_rejects() {
        let (r0, m0) = (3_000u128, 2_000u128);
        // honest redeem: burn 1_000, release ≤ 1_000, stays solvent
        assert_eq!(peg_out_apply(r0, m0, 1_000, 1_000, R), Some((2_000, 1_000)));
        // drain: release MORE than burned face value → reject
        assert!(peg_out_apply(r0, m0, 1_001, 1_000, R).is_none(), "releasing more than burned MUST reject");
        // burn more than was ever minted → reject (checked_sub underflow)
        assert!(peg_out_apply(r0, m0, 0, m0 + 1, R).is_none(), "burning more than minted MUST reject");
    }

    // The solvency invariant is exact at the boundary (no rounding hole an over-mint could slip through).
    #[test]
    fn solvency_boundary_is_exact() {
        assert!(is_solvent(1_500, 1_000, R), "exactly 150% is solvent");
        assert!(!is_solvent(1_499, 1_000, R), "one atomic unit under 150% is NOT solvent");
    }

    // ── brick 2a: the slack-form transition (what the AIR enforces) ──
    // HONEST peg-in: the slack-form witness builds + satisfies every equality constraint.
    #[test]
    fn slack_transition_honest_builds_and_checks() {
        let w = build_peg_in_transition(1_500, 1_000, 1_500, 1_000, R).expect("150%-collateralized builds");
        assert!(check_solvency_transition(&w), "honest slack-form witness satisfies all four equalities");
        assert_eq!((w.new_reserve, w.new_minted), (3_000, 2_000));
        assert_eq!(w.slack_b, 1_500 * 10_000 - 1_000 * 15_000, "backing slack = deposit·10000 − mint·ratio");
    }

    // An OVER-MINT has NO honest non-negative slack, so a valid witness is UN-constructible (build → None) —
    // this is exactly why the zerocheck+range AIR is sound: forging it needs a negative slack the range bind rejects.
    #[test]
    fn slack_transition_over_mint_unconstructible() {
        assert!(build_peg_in_transition(1_500, 1_000, 1_500, 1_001, R).is_none(), "over-mint has no honest slack");
        assert!(build_peg_in_transition(1_500, 1_000, 0, 1, R).is_none(), "a mint the deposit can't cover: no slack");
    }

    // ADVERSARIAL — a prover FORGES a witness (tampers a field) to fake validity. Every tamper breaks an
    // equality the AIR enforces, so check_solvency_transition REJECTS.
    #[test]
    fn slack_transition_tampers_reject() {
        let good = build_peg_in_transition(1_500, 1_000, 1_500, 1_000, R).unwrap();
        // (a) inflate the mint but keep the honest slack → backing equality breaks
        let mut t = good; t.delta_minted += 1; t.new_minted += 1;
        assert!(!check_solvency_transition(&t), "over-mint with stale slack MUST reject (backing equality)");
        // (b) claim a bigger backing slack to 'cover' an over-mint → deposit·10000 ≠ mint·ratio + slack_b
        let mut t = good; t.delta_minted += 1; t.new_minted += 1; t.slack_b = t.slack_b.wrapping_sub(15_000);
        assert!(!check_solvency_transition(&t), "a forged slack that doesn't satisfy the equality MUST reject");
        // (c) break conservation: new totals don't equal old + delta
        let mut t = good; t.new_reserve += 1;
        assert!(!check_solvency_transition(&t), "broken conservation (hidden issuance) MUST reject");
        // (d) fake solvency slack → solvency equality breaks
        let mut t = good; t.slack_s += 1;
        assert!(!check_solvency_transition(&t), "a solvency slack that doesn't satisfy the equality MUST reject");
    }

    // ── #75 NO AMOUNT CAP (u256 width): digital cash has no limit — solvency holds far past u64 ──
    #[test]
    fn u256_arith_is_exact_across_the_64bit_boundary() {
        assert_eq!(add256([u64::MAX, 0, 0, 0], [1, 0, 0, 0]), Some([0, 1, 0, 0]), "carry across the 64-bit limb boundary");
        assert_eq!(sub256([0, 1, 0, 0], [1, 0, 0, 0]), Some([u64::MAX, 0, 0, 0]), "borrow across the boundary");
        // (2^64−1)·10000 = 9999·2^64 + (2^64−10000) — no wrap past u64
        assert_eq!(mul256_small([u64::MAX, 0, 0, 0], 10_000), Some([u64::MAX - 9_999, 9_999, 0, 0]));
        assert!(ge256([0, 1, 0, 0], [u64::MAX, 0, 0, 0]), "2^64 ≥ 2^64−1 over the full width");
        assert_eq!(add256([u64::MAX; 4], [1, 0, 0, 0]), None, "past 2^256 fails closed, never wraps");
    }

    // A mint at 2^128 scale — FAR past the old 64-bit shortcut ceiling — is accepted when 150%-collateralized,
    // with the totals advancing by the EXACT amounts (no truncation). Proves there is no amount cap.
    #[test]
    fn solvency_has_no_amount_cap_u256() {
        let dep: U256 = [0, 0, 1, 0]; // 2^128 deposit value (limb 2 = ×2^128)
        let mint: U256 = [0, 0x8000_0000_0000_0000, 0, 0]; // 2^127 mint (limb 1; well within 2/3 of the deposit)
        let (r1, m1) = peg_in_apply_256([0; 4], [0; 4], dep, mint, R).expect("a 2^128-scale backed mint is accepted (NO cap)");
        assert!(is_solvent_256(r1, m1, R));
        assert_eq!(r1, dep, "reserve advanced by the FULL 2^128 deposit — no truncation to 64 bits");
        assert_eq!(m1, mint, "minted advanced by the full 2^127 — no cap");
    }

    // ADVERSARIAL at u256 scale: over-minting past the deposit's 150% capacity MUST reject even at 2^192.
    #[test]
    fn over_mint_rejects_at_u256_scale() {
        let dep: U256 = [0, 0, 1, 0]; // 2^128 deposit
        let over: U256 = [0, 0, 0, 1]; // 2^192 mint — vastly exceeds the deposit's backing capacity
        assert!(peg_in_apply_256([0; 4], [0; 4], dep, over, R).is_none(), "over-mint at 256-bit scale MUST reject");
        // and a redeem/burn can never release more than held (fail-closed subtraction)
        assert_eq!(sub256([0; 4], [1, 0, 0, 0]), None, "burning/releasing more than held MUST reject");
    }

    // ── #75 brick 2b: IN-CIRCUIT limb-wise conservation (256-bit, proven, never reconstructed) ──
    use crate::hiding_decider::Perm16;
    use rand::rngs::SmallRng;
    use rand::SeedableRng;

    fn mk_ch() -> Chl {
        let mut rng = SmallRng::seed_from_u64(0x0501_0E2Cu64);
        Chl::new(Perm16::new_from_rng_128(&mut rng))
    }

    // An honest `reserve + delta == new` — with carries rippling ACROSS the 64-bit-word boundaries — produces a
    // zerocheck proof the node VERIFIES over the committed limb columns, without ever reconstructing a total.
    #[test]
    fn in_circuit_conservation_honest_verifies_at_256bit() {
        let a: U256 = [u64::MAX, 3, 0, 7];
        let b: U256 = [1, 0, 5, 0];
        let s = add256(a, b).expect("no 256-bit overflow"); // carries across the limb + word boundaries
        let proof = prove_conservation(a, b, s, &mut mk_ch()).expect("honest a+b=s proves");
        assert!(verify_conservation(&proof, &mut mk_ch()), "honest limb-wise conservation VERIFIES");
    }

    // ADVERSARIAL: a prover forges the trace to claim `new = a+b+1` (hidden issuance of 1 unit) WITHOUT fixing
    // the carries. The limb add relation breaks → the zerocheck sum ≠ 0 → the node REJECTS. This is the
    // in-circuit no-inflation gate, at full width.
    #[test]
    fn in_circuit_conservation_forged_issuance_rejects() {
        let a: U256 = [100, 0, 0, 0];
        let b: U256 = [50, 0, 0, 0];
        let s = add256(a, b).unwrap(); // 150
        let mut cols = conservation_trace(a, b, s).unwrap();
        // TAMPER: bump the least-significant SUM limb (claim 151, an extra unit from nowhere) — carries unchanged.
        cols[2 * N_LIMB16][0] += Fa4::ONE;
        cols[2 * N_LIMB16][1] += Fa4::ONE;
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = ConservationLimbAir { gamma };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = ConservationLimbAir { gamma: gv };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        assert!(!verify_air_zerocheck(&proof, &airv, &zv, &mut vch), "forged hidden issuance MUST reject");
    }

    // ── #75 brick 2b-ii: IN-CIRCUIT scaling a·k (the ratio/backing multiply), limb-wise range-bound ──
    #[test]
    fn in_circuit_scale_honest_verifies() {
        let a: U256 = [0xDEAD_BEEF_1234_5678, 42, 0, 9]; // a real 256-bit amount
        let proof = prove_scale(a, 10_000, &mut mk_ch()).expect("a·10000 proves");
        assert!(verify_scale(&proof, 10_000, &mut mk_ch()), "honest a·10000 VERIFIES limb-wise");
        let proof2 = prove_scale(a, 15_000, &mut mk_ch()).expect("a·ratio proves");
        assert!(verify_scale(&proof2, 15_000, &mut mk_ch()), "honest a·ratio VERIFIES");
    }

    // ADVERSARIAL: inflating a scaled result limb (claim `a·10000` is bigger, to fake more backing) WITHOUT
    // fixing its bit-decomposition breaks the range-bind recompose → the node REJECTS.
    #[test]
    fn in_circuit_scale_forged_product_rejects() {
        let a: U256 = [1000, 0, 0, 0];
        let mut cols = scale_trace(a, 10_000).unwrap();
        cols[S_P][0] += Fa4::ONE; // inflate result limb 0, leave its bits stale
        cols[S_P][1] += Fa4::ONE;
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = ScaleByConstAir { gamma, k: 10_000 };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = ScaleByConstAir { gamma: gv, k: 10_000 };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        assert!(!verify_air_zerocheck(&proof, &airv, &zv, &mut vch), "a forged scaled product MUST reject");
    }

    /// ⛔⛔⛔ DB-362 — A SCALED VALUE ALIASED BY THE FIELD MODULUS IS REFUSED. The scale gadget's limb equations
    /// `a_i·k + c_{i−1} − p_i − c_i·2^16 = 0` hold in KoalaBear, and with the carries `c_i` unconstrained they telescope
    /// to `Σ p_i·2^(16 i) ≡ a·k (mod p)`: ANY canonical 17-limb product congruent to `a·k` admits field carries that
    /// satisfy every equation and every product-limb bit. So `a·k + p` (the modulus added as a 272-bit integer) was
    /// accepted as `a·k` — and the backing inequality every peg / revaluation / yield carrier rests on could be met by
    /// an insolvent state whose scaled reserve was inflated by multiples of `p`. This pin lays exactly that alias, with
    /// the carries solved in the field, and requires the refusal that only a RANGE BIND ON THE CARRIES provides.
    /// RED on the pre-fix layout (measured before the fix landed): the alias verified.
    #[test]
    fn db362_a_scaled_value_aliased_by_the_field_modulus_is_refused() {
        use p3_field::{Field, PrimeField64};
        let a: U256 = [12_345, 0, 0, 0];
        let k = 10_000u64;
        let mut cols = scale_trace(a, k).expect("the honest scale lays out");
        let p_field: u128 = u128::from(Fa4::ORDER_U64);
        let honest: u128 = 12_345 * u128::from(k);
        let alias: u128 = honest + p_field; // ≡ a·k (mod p), a different 272-bit integer
        let mut pl = [0u64; N_LIMB17];
        for (i, limb) in pl.iter_mut().enumerate().take(8) {
            *limb = ((alias >> (16 * i)) & 0xFFFF) as u64;
        }
        // the carries the field equations force for THIS product, limb by limb
        let inv16 = Fa4::from_u64(1 << LIMB16_BITS).inverse();
        let al = u256_to_limbs16(a);
        let mut c = Fa4::ZERO;
        let mut carries = [Fa4::ZERO; N_LIMB16];
        for i in 0..N_LIMB16 {
            c = (Fa4::from_u64(al[i]) * Fa4::from_u64(k) + c - Fa4::from_u64(pl[i])) * inv16;
            carries[i] = c;
        }
        assert_eq!(c, Fa4::from_u64(pl[16]), "PRECONDITION: the alias telescopes onto the top limb — every limb equation holds in the field");
        // The alias's ONLY footprint is the first carry: `p ≡ 1 (mod 2^16)`, so adding `p` adds 1 to limb 0 and exactly
        // `p >> 16 = 32,512` to the carry out of it — a value that FITS 16 BITS. A 16-bit range bind on the carries would
        // NOT refuse it; only the derived bound `carry ≤ 32,511` (the largest carry for which the limb equation is an
        // integer identity in a 31-bit field) does — measured here, not assumed.
        let c0 = carries[0].as_canonical_u64();
        assert!(c0 > 32_511 && c0 <= LIMB16_MASK, "PRECONDITION: the alias carry is above the sound bound yet inside 16 bits ({c0})");
        assert!(carries[1..].iter().all(|c| *c == Fa4::ZERO), "PRECONDITION: every other carry is honest (zero) — the alias hides in one column");
        let set = |c: usize, v: Fa4, cols: &mut Vec<Vec<Fa4>>| {
            cols[c][0] = v;
            cols[c][1] = v;
        };
        for i in 0..N_LIMB17 {
            set(S_P + i, Fa4::from_u64(pl[i]), &mut cols);
            for j in 0..N_LIMB16 {
                set(S_PBITS + i * N_LIMB16 + j, Fa4::from_u64((pl[i] >> j) & 1), &mut cols);
            }
        }
        for i in 0..N_LIMB16 {
            set(S_CARRY + i, carries[i], &mut cols);
        }
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = ScaleByConstAir { gamma, k };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = ScaleByConstAir { gamma: gv, k };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        assert!(
            !verify_air_zerocheck(&proof, &airv, &zv, &mut vch),
            "⛔ DB-362 IS OPEN: a·k + p verified as a·k — the scaled value is bound only modulo the field, and every \
             backing inequality can be inflated by multiples of p"
        );
    }

    /// ⛔⛔⛔ DB-362 AT THE CARRIER (re-laid for DB-124's priced backing) — A PEG-OUT THAT DRAINS THE RESERVE IS REFUSED. The
    /// reserve holds 1,000 against 500 minted (200 % at a unit price); the peg-out releases 999 and burns nothing, leaving 1
    /// against 500: honestly unprovable (the PRECONDITION). A forger lays everything the honest builder lays except the
    /// inequality, then writes a reserve product that dwarfs the minted side (≈ 2^336) into the wide block's 16-bit regrouping
    /// — the block's own 14-bit limbs and carries stay honest — and lays the ≥ block honestly over the forged value, so the
    /// only thing standing between this carrier and an accepted drain is the regrouping constraint (the 16-bit limbs ARE the
    /// out bits regrouped). It must refuse.
    ///
    /// TWO-PARTY-REVIEWED: the two parties are the PROVER (the carrier bytes, built exactly as `prove_peg_out_carrier`
    /// builds them) and the NODE (`verify_peg_out_carrier`, the production door, given only the bytes and the
    /// commitments it holds).
    #[test]
    fn db362_an_aliased_peg_out_for_an_insolvent_post_state_is_refused() {
        use crate::poseidon2_compress::lanes_of;
        let (r_blind, m_blind, nr_blind, nm_blind) = (lanes_of(&[11]), lanes_of(&[12]), lanes_of(&[13]), lanes_of(&[14]));
        // DB-470: the drain a forger wants — 999 of reserve released against a burn of 0
        let (reserve, minted, release, burn) = (u256_from_u64(1_000), u256_from_u64(500), u256_from_u64(999), u256_from_u64(0));
        let backing = Backing::at_unit_price(10_000);
        assert!(
            pegout_trace(reserve, minted, release, burn, r_blind, m_blind, nr_blind, nm_blind, backing).is_none(),
            "PRECONDITION: honestly, releasing 999 against a burn of 0 is unprovable"
        );
        let (mut cols, commits, cmp) = pegout_trace_unchecked(reserve, minted, release, burn, r_blind, m_blind, nr_blind, nm_blind, backing)
            .expect("the forger lays everything but the compares");
        // the forger claims the release is worth NOTHING on both compares (the products the multiplies would bind)
        let zero23 = [0u64; M14_P16_LIMBS];
        for i in 0..M14_P16_LIMBS {
            cols[T_MR + M14_P16 + i].fill(Fa4::ZERO);
        }
        assert!(place_ge_n(&mut cols, &cmp.burn_worth, &zero23, T_GE_SLACK, T_GE_BORROW, T_GE_SBITS), "PRECONDITION: a zero release worth clears the cap");
        let zero_h = vec![0u64; cmp.release_share.len()];
        let off = mulhh_p16_off(N_LIMB16);
        for i in 0..zero_h.len() {
            cols[TO_HM + off + i].fill(Fa4::ZERO);
        }
        assert!(place_ge_n(&mut cols, &cmp.burn_share, &zero_h, TO_SLACK, TO_BORROW, TO_SBITS), "PRECONDITION: a zero release share clears the pro-rata compare");
        // prove exactly as prove_peg_out_carrier does, then hand the NODE'S door only what it would hold
        let cols = replicate_rows(cols, 1 << REC_DECIDER_FOLDING);
        let statement_bind = peg_in_statement_bind(commits.new_reserve_commit, commits.new_minted_commit, commits.reserve_commit, commits.minted_commit);
        let make = |g: Ea4| PinnedBoundTransitionAir {
            gamma: g,
            ratio_bps: backing,
            reserve_commit: commit_to_ea4(commits.new_reserve_commit),
            minted_commit: commit_to_ea4(commits.new_minted_commit),
            new_reserve_commit: commit_to_ea4(commits.reserve_commit),
            new_minted_commit: commit_to_ea4(commits.minted_commit),
            gate: TransitionGate::Redeem,
        };
        if let Some(bytes) = prove_value_carrier(cols, make, &statement_bind) {
            assert!(
                !verify_peg_out_carrier(&bytes, backing, commits.reserve_commit, commits.minted_commit, commits.new_reserve_commit, commits.new_minted_commit),
                "⛔ DB-362/470 AT THE CARRIER: a peg-out releasing 999 against a burn of 0 VERIFIED"
            );
        }
    }

    /// ⭐ B15 — the burn-bound peg-out verifies only against the commitment to its own burn: a commitment to another amount (a
    /// custody that names a larger burn than the note destroyed) or under another blind refuses; the honest one verifies.
    #[test]
    fn b15_the_burn_bound_peg_out_verifies_only_against_its_own_burn_commitment() {
        use crate::poseidon2_compress::lanes_of;
        let floor = Backing::at_unit_price(10_000);
        let (rb, mb, nrb, nmb, bb) = (lanes_of(&[51]), lanes_of(&[52]), lanes_of(&[53]), lanes_of(&[54]), lanes_of(&[55]));
        let (bytes, c, bc) = prove_peg_out_carrier_delta(u256_from_u64(3_000), u256_from_u64(1_000), u256_from_u64(100), u256_from_u64(100), rb, mb, nrb, nmb, bb, floor)
            .expect("an honest $1 cash-out proves");
        assert_eq!(bc, solvency_commit_256(u256_from_u64(100), bb), "the burn commitment is the solvency shape");
        let v = |bc: Digest| verify_peg_out_carrier_delta(&bytes, floor, c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit, bc);
        assert!(v(bc), "the honest burn-bound peg-out verifies");
        assert!(!v(solvency_commit_256(u256_from_u64(101), bb)), "⛔ B15: the peg-out verified against a larger named burn");
        assert!(!v(solvency_commit_256(u256_from_u64(100), lanes_of(&[56]))), "⛔ B15: the peg-out verified under another blind");
        assert!(
            !verify_peg_out_carrier(&bytes, floor, c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit),
            "⛔ B15: a burn-bound carrier verified as an unbound one (one statement domain each)"
        );
    }

    /// ⛔⛔ DB-470 (2) — A NEGATIVE BURN IS NOT A BURN. Conservation with boolean carries leaves a delta limb anywhere in
    /// `[−2^16, 2^17)`: a forger lays a peg-out whose "burn" is −5, so the POST minted total is the current one PLUS 5 —
    /// supply growing through the door that destroys it. The delta's range bits refuse it at the carrier.
    #[test]
    fn db470_a_negative_burn_through_a_peg_out_is_refused_at_the_carrier() {
        use crate::poseidon2_compress::lanes_of;
        let (r_blind, m_blind, nr_blind, nm_blind) = (lanes_of(&[21]), lanes_of(&[22]), lanes_of(&[23]), lanes_of(&[24]));
        let backing = Backing::at_unit_price(10_000);
        let (reserve, minted) = (u256_from_u64(3_000), u256_from_u64(1_000));
        let (mut cols, commits0, _cmp) = pegout_trace_unchecked(reserve, minted, u256_from_u64(0), u256_from_u64(0), r_blind, m_blind, nr_blind, nm_blind, backing)
            .expect("the honest zero peg-out lays");
        // the forged post minted: current + 5, opened under the post blind; the burn limb is the field's −5
        let post = u256_to_limbs16(u256_from_u64(1_005));
        for i in 0..N_LIMB16 {
            cols[T_MINT + i].fill(Fa4::from_u64(post[i]));
        }
        let nmc = place_commit_open(&mut cols, post, nm_blind, T_MINTER, T_MVBITS);
        for i in 0..DIGEST_LANES {
            cols[T_MCOMMIT + i].fill(Fa4::from_u64(nmc[i]));
        }
        cols[T_MDELTA].fill(Fa4::ZERO - Fa4::from_u64(5));
        // the conservation limb holds in the field: 1005 + (−5) + 0 == 1000 + 0·2^16
        assert_eq!(Fa4::from_u64(1_005) + (Fa4::ZERO - Fa4::from_u64(5)), Fa4::from_u64(1_000), "PRECONDITION: the forged burn conserves in the field");
        let cols = replicate_rows(cols, 1 << REC_DECIDER_FOLDING);
        let statement_bind = peg_in_statement_bind(commits0.new_reserve_commit, nmc, commits0.reserve_commit, commits0.minted_commit);
        let make = |g: Ea4| PinnedBoundTransitionAir {
            gamma: g,
            ratio_bps: backing,
            reserve_commit: commit_to_ea4(commits0.new_reserve_commit),
            minted_commit: commit_to_ea4(nmc),
            new_reserve_commit: commit_to_ea4(commits0.reserve_commit),
            new_minted_commit: commit_to_ea4(commits0.minted_commit),
            gate: TransitionGate::Redeem,
        };
        if let Some(bytes) = prove_value_carrier(cols, make, &statement_bind) {
            assert!(
                !verify_peg_out_carrier(&bytes, backing, commits0.reserve_commit, commits0.minted_commit, commits0.new_reserve_commit, nmc),
                "⛔ DB-470: a peg-out with a burn of −5 grew the minted total and VERIFIED"
            );
        }
        // CALIBRATION: the honest zero peg-out over the same state proves and verifies, so the refusal is the forged burn's
        let (bytes, c) = prove_peg_out_carrier(reserve, minted, u256_from_u64(0), u256_from_u64(0), r_blind, m_blind, nr_blind, nm_blind, backing).expect("honest proves");
        assert!(verify_peg_out_carrier(&bytes, backing, c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit));
    }

    /// ⛔ DB-362 — A MULTIPLIER PAST THE DERIVED BOUND IS REFUSED AT BOTH DOORS: no witness is laid for it, and a
    /// verifier handed a wider `k` refuses before it reads a byte (a verifier that accepted it would accept the alias).
    #[test]
    fn db362_a_multiplier_past_the_derived_bound_is_refused_at_both_doors() {
        use p3_field::PrimeField64;
        let a: U256 = [1_000, 0, 0, 0];
        assert!(prove_scale(a, SCALE_K_MAX, &mut mk_ch()).is_some(), "the bound itself is admissible");
        assert!(prove_scale(a, SCALE_K_MAX + 1, &mut mk_ch()).is_none(), "one past the bound lays no witness");
        let honest = prove_scale(a, SCALE_K_MAX, &mut mk_ch()).expect("proves");
        assert!(!verify_scale(&honest, SCALE_K_MAX + 1, &mut mk_ch()), "a verifier handed a wider k refuses");
        assert!(!verify_peg_out_carrier(&[1u8; 8], Backing::at_unit_price(u64::from(SCALE_K_MAX + 1)), [0; DIGEST_LANES], [0; DIGEST_LANES], [0; DIGEST_LANES], [0; DIGEST_LANES]), "the carrier door refuses a wider ratio first");
        assert_eq!(SCALE_CARRY_MAX, 32_511, "the derived bound: 32,511·2^16 + 65,535 < p, 32,512 does not");
        assert!(u128::from(SCALE_CARRY_MAX) * 65_536 + 65_535 < u128::from(Fa4::ORDER_U64) && u128::from(SCALE_CARRY_MAX + 1) * 65_536 + 65_535 >= u128::from(Fa4::ORDER_U64));
    }

    // ── the WIDE PUBLIC MULTIPLY (base 2^14 schoolbook) — the liquidation amount carrier's a·price ──
    /// The standalone test AIR: an operand's 16-bit limbs with their range bits, then one wide-multiply block.
    const MT_A: usize = 0;
    const MT_ABITS: usize = MT_A + N_LIMB16;
    const MT_MUL: usize = MT_ABITS + RANGE16_COLS;
    const MT_WIDTH: usize = MT_MUL + MUL14_COLS;
    struct Mul14TestAir {
        gamma: Ea4,
        k: u128,
    }
    impl AirConstraint for Mul14TestAir {
        /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
        fn is_row_local(&self) -> bool {
            true
        }
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let mut cs: Vec<Ea4> = Vec::new();
            push_range16_constraints(&mut cs, local, MT_A, MT_ABITS, N_LIMB16);
            push_mul14_constraints(&mut cs, local, MT_ABITS, self.k, MT_MUL);
            let mut acc = Ea4::ZERO;
            let mut gp = Ea4::ONE;
            for c in cs {
                acc += gp * c;
                gp *= self.gamma;
            }
            acc
        }
    }
    fn mul14_test_cols(a: U256, k: u128) -> (Vec<Vec<Fa4>>, [u64; M14_P16_LIMBS]) {
        let al = u256_to_limbs16(a);
        let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; MT_WIDTH];
        for i in 0..N_LIMB16 {
            cols[MT_A + i].fill(Fa4::from_u64(al[i]));
        }
        place_range16(&mut cols, &al, MT_ABITS);
        let p16 = place_mul14(&mut cols, &al, k, MT_MUL).expect("a 256-bit operand times a u64 fits the block");
        (cols, p16)
    }
    fn mul14_verdict(cols: &[Vec<Fa4>], k: u128) -> bool {
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = Mul14TestAir { gamma, k };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = Mul14TestAir { gamma: gv, k };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        verify_air_zerocheck(&proof, &airv, &zv, &mut vch)
    }
    // ── the HIDDEN MULTIPLY (12-bit schoolbook over two openings) — the pool's (P, S), a withdrawal, DSOL MUL ──
    /// The standalone test AIR at operand width `n16`: two operands with their range bits, then one hidden-multiply
    /// block. Offsets: A, A bits, B, B bits, the block.
    struct MulHHTestAir {
        gamma: Ea4,
        n16: usize,
    }
    fn ht_abits(n16: usize) -> usize {
        n16
    }
    fn ht_b(n16: usize) -> usize {
        17 * n16
    }
    fn ht_bbits(n16: usize) -> usize {
        18 * n16
    }
    fn ht_mul(n16: usize) -> usize {
        34 * n16
    }
    fn ht_width(n16: usize) -> usize {
        34 * n16 + mulhh_cols(n16)
    }
    impl AirConstraint for MulHHTestAir {
        /// DB-452: reads its own row only (`eval` ignores `at`) — the blinded committed door admits row-local gates only.
        fn is_row_local(&self) -> bool {
            true
        }
        fn degree(&self, _nvars: usize) -> usize {
            2
        }
        fn eval(&self, local: &crate::air_zerocheck::Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let mut cs: Vec<Ea4> = Vec::new();
            let n = self.n16;
            push_range16_constraints(&mut cs, local, 0, ht_abits(n), n);
            push_range16_constraints(&mut cs, local, ht_b(n), ht_bbits(n), n);
            push_mulhh_constraints(&mut cs, local, ht_abits(n), ht_bbits(n), n, ht_mul(n));
            let mut acc = Ea4::ZERO;
            let mut gp = Ea4::ONE;
            for c in cs {
                acc += gp * c;
                gp *= self.gamma;
            }
            acc
        }
    }
    fn hh_test_cols(a16: &[u64], b16: &[u64]) -> (Vec<Vec<Fa4>>, Vec<u64>) {
        let n = a16.len();
        let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; ht_width(n)];
        fill_cols(&mut cols, 0, a16);
        fill_cols(&mut cols, ht_b(n), b16);
        place_range16(&mut cols, a16, ht_abits(n));
        place_range16(&mut cols, b16, ht_bbits(n));
        let p16 = place_mulhh(&mut cols, a16, b16, ht_mul(n)).expect("two operands of the declared width never carry out");
        (cols, p16)
    }
    fn hh_verdict(cols: &[Vec<Fa4>], n16: usize) -> bool {
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = MulHHTestAir { gamma, n16 };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = MulHHTestAir { gamma: gv, n16 };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        verify_air_zerocheck(&proof, &airv, &zv, &mut vch)
    }
    /// An INDEPENDENT 16-bit-limb schoolbook with u128 accumulators (2·n limbs out) — the native the gadget must equal.
    fn schoolbook16(a: &[u64], b: &[u64]) -> Vec<u64> {
        let n = a.len();
        let mut acc = vec![0u128; 2 * n + 1];
        for i in 0..n {
            for j in 0..n {
                acc[i + j] += u128::from(a[i]) * u128::from(b[j]);
            }
        }
        let mut out = vec![0u64; 2 * n];
        let mut carry = 0u128;
        for k in 0..2 * n {
            let t = acc[k] + carry;
            out[k] = (t & 0xFFFF) as u64;
            carry = t >> 16;
        }
        assert_eq!(carry, 0, "a 2n-limb product never carries out");
        out
    }
    fn u64_limbs16(v: u64) -> Vec<u64> {
        (0..4).map(|i| (v >> (16 * i)) & LIMB16_MASK).collect() // PRODUCTION-SCALE-REVIEWED: the four 16-bit limbs of one u64 word, not a cover count
    }

    /// ⭐ THE HIDDEN MULTIPLY IS EXACT at both widths the chain uses — 256 × 256 (the pool's (P, S), a withdrawal) and
    /// 64 × 64 (a DSOL word): the block's re-limbed product equals an independent 16-bit schoolbook, all-ones operands
    /// included (every 12-bit limb and every column at its maximum), and the relation verifies.
    #[test]
    fn hidden_multiply_honest_equals_native_and_verifies() {
        use p3_field::PrimeField64;
        let wide = |x: U256| u256_to_limbs16(x).to_vec();
        let cases: Vec<(Vec<u64>, Vec<u64>)> = vec![
            (wide([u64::MAX; 4]), wide([u64::MAX; 4])),                                     // (2^256 − 1)²: every column at its maximum
            (wide(u256_from_u64(1_500)), wide(u256_from_u64(60_000_000_000))),               // a value times a price-sized value
            (wide([0xDEAD_BEEF_1234_5678, 42, 7, 1 << 63]), wide([1, 2, 3, 0xFFFF_0000_FFFF])), // both above 2^64
            (wide(u256_from_u64(0)), wide([u64::MAX; 4])),                                   // a zero operand
            (u64_limbs16(u64::MAX), u64_limbs16(u64::MAX)),                                  // a DSOL word squared
            (u64_limbs16(12_345), u64_limbs16(678)),
        ];
        for (a, b) in cases {
            let n16 = a.len();
            let (cols, p16) = hh_test_cols(&a, &b);
            let mut expected = schoolbook16(&a, &b);
            expected.resize(hh_p16(n16), 0);
            assert_eq!(p16, expected, "the re-limbed product is a·b (n16 = {n16})");
            assert!(hh_verdict(&cols, n16), "honest a·b verifies (n16 = {n16})");
        }
        assert_eq!(limbs16_to_u128(&hh_test_cols(&u64_limbs16(12_345), &u64_limbs16(678)).1), 12_345 * 678);
        assert_eq!((hh_limbs(16), hh_cols(16), hh_p16(16), mulhh_cols(16)), (22, 44, 33, 1_397), "the 256-bit block's derived shape");
        assert!(22u128 * 4_095 * 4_095 + (1 << HH_CARRY_BITS) < u128::from(Fa4::ORDER_U64), "22 partial products plus a carry stay below the field");
    }

    /// ⭐ FORGERIES ON THE HIDDEN MULTIPLY ARE REFUSED: an out limb nudged, a carry limb nudged with its bits, a
    /// re-limbed product limb nudged, and — the operand side — one range bit of `a` flipped without redoing the product.
    #[test]
    fn hidden_multiply_forgeries_are_refused() {
        use p3_field::PrimeField64;
        let (a, b) = (u256_to_limbs16(u256_from_u64(1_500)).to_vec(), u256_to_limbs16(u256_from_u64(60_000_000_000)).to_vec());
        let honest = hh_test_cols(&a, &b).0;
        assert!(hh_verdict(&honest, 16));
        let mut f1 = honest.clone();
        f1[ht_mul(16) + 3].iter_mut().for_each(|c| *c += Fa4::ONE);
        assert!(!hh_verdict(&f1, 16), "an out limb nudged is refused");
        let mut f2 = honest.clone();
        let c1 = f2[ht_mul(16) + hh_cout(16) + 1][0] + Fa4::ONE;
        f2[ht_mul(16) + hh_cout(16) + 1].iter_mut().for_each(|c| *c = c1);
        for t in 0..HH_CARRY_BITS {
            let bit = Fa4::from_u64((c1.as_canonical_u64() >> t) & 1);
            f2[ht_mul(16) + hh_cbits(16) + HH_CARRY_BITS + t].iter_mut().for_each(|c| *c = bit);
        }
        assert!(!hh_verdict(&f2, 16), "a carry nudged (bits redone) is refused");
        let mut f3 = honest.clone();
        f3[ht_mul(16) + mulhh_p16_off(16) + 2].iter_mut().for_each(|c| *c += Fa4::ONE);
        assert!(!hh_verdict(&f3, 16), "a re-limbed product limb nudged is refused");
        let mut f4 = honest.clone();
        f4[ht_abits(16) + 5].iter_mut().for_each(|c| *c = Fa4::ONE - *c);
        f4[0].iter_mut().for_each(|c| *c = Fa4::from_u64((1_500u64) ^ (1 << 5)));
        assert!(!hh_verdict(&f4, 16), "an operand bit flipped (its limb kept consistent) is refused: the product no longer matches");
    }

    // ── the Stability Pool's (P, S) STEP carrier ──
    /// ⭐ THE POOL-STEP RULE, natively, against an INDEPENDENT spelling: `P_new·T + r₃ = P_old·(T − C)` with `r₃ < T` and
    /// `S_new·T + r₄ = S_old·T + S_c·P_old` with `r₄ < T`, checked with the 16-bit schoolbook the hidden-multiply pins trust
    /// and plain limb subtraction; a full drain gives `P_new = 0` and closes the epoch; `C > T` and an empty pool are `None`.
    #[test]
    fn pool_step_is_the_rounded_down_rule() {
        let p0: U256 = [0, 0, 1, 0]; // 2^128: a fresh epoch's P
        let (t, c, s_c, s_old) = (u256_from_u64(1_000_000_000), u256_from_u64(100_000_000), u256_from_u64(200_000), u256_from_u64(0));
        let (p_new, s_new, close) = pool_step(t, c, s_c, p0, s_old).expect("the step has a rule");
        assert!(!close, "a 10 % retire does not close the epoch");
        let (tl, dl, pol, pnl, scl, snl, sol) = (
            u256_to_limbs16(t),
            u256_to_limbs16(sub256(t, c).unwrap()),
            u256_to_limbs16(p0),
            u256_to_limbs16(p_new),
            u256_to_limbs16(s_c),
            u256_to_limbs16(s_new),
            u256_to_limbs16(s_old),
        );
        let lt = |a: &[u64], b: &[u64]| !limbs_ge(a, b);
        let r3 = limbs_sub(&schoolbook16(&pol, &dl), &schoolbook16(&pnl, &tl)).expect("P_new·T ≤ P_old·D");
        assert!(r3[N_LIMB16..].iter().all(|&l| l == 0) && lt(&r3[..N_LIMB16], &tl), "0 ≤ r₃ < T: P_new is the rounded-down quotient");
        let num = limbs_add(&schoolbook16(&sol, &tl), &schoolbook16(&scl, &pol)).unwrap();
        let r4 = limbs_sub(&num, &schoolbook16(&snl, &tl)).expect("S_new·T ≤ S_old·T + S_c·P_old");
        assert!(r4[N_LIMB16..].iter().all(|&l| l == 0) && lt(&r4[..N_LIMB16], &tl), "0 ≤ r₄ < T: S_new is the rounded-down quotient");
        // P scales by exactly 0.9 here (10 % of the pool retired): P_new = 0.9 · 2^128 to within one unit of rounding
        assert_eq!(pnl[7], 0xE666, "P_new's top limb is 0.9 · 2^16 rounded down");
        // a full drain closes the epoch with P_new = 0
        let (p_drain, _, close_drain) = pool_step(t, t, s_c, p0, s_old).unwrap();
        assert_eq!((p_drain, close_drain), (u256_from_u64(0), true));
        assert!(pool_step(t, add256(t, u256_from_u64(1)).unwrap(), s_c, p0, s_old).is_none(), "C > T has no rule");
        assert!(pool_step(u256_from_u64(0), u256_from_u64(0), s_c, p0, s_old).is_none(), "an empty pool has no rule");
    }

    /// ⭐⭐⭐ THE POOL-STEP CARRIER, RED FIRST. The honest step proves and verifies against the seven commitments and the
    /// public close bit; the carrier is one size whether or not the epoch closes. Refused — by the chains (no witness) or
    /// by the verifier: `P_new ± 1`, `S_new ± 1`; the close bit flipped; each commitment edited; `(P_old, P_new)` swapped;
    /// no bytes. A full drain proves with `close = true`.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER is a bonded node holding the pool's and the liquidation's openings; the VERIFIER is
    /// every node, handed the bytes, seven commitments and one public bit — the production boundary of
    /// `verify_pool_step_carrier`.
    #[test]
    fn pool_step_carrier_proves_the_rule_and_refuses_every_neighbour() {
        use crate::poseidon2_compress::lanes_of;
        let blinds: [Digest; 7] = core::array::from_fn(|i| lanes_of(&[61 + i as u64]));
        let p0: U256 = [0, 0, 1, 0];
        let o = PoolStepOpening { t: u256_from_u64(1_000_000_000), c: u256_from_u64(100_000_000), s_c: u256_from_u64(200_000), p_old: p0, s_old: u256_from_u64(5), blinds };
        let proof = prove_pool_step_carrier(&o).expect("the honest step proves");
        assert!(verify_pool_step_carrier(&proof.bytes, &proof.commits, proof.close), "the honest step verifies");
        assert!(!proof.close);
        eprintln!("[pool-step] carrier {} B over {} columns", proof.bytes.len(), PS_WIDTH);
        let one = u256_from_u64(1);
        let refused = |label: &str, t: Option<(Vec<Vec<Fa4>>, [Digest; 7], bool)>| match t {
            None => eprintln!("[pool-step] {label} → no witness"),
            Some((cols, commits, close)) => match prove_pool_step_trace(cols, &commits, close) {
                None => eprintln!("[pool-step] {label} → the prover refuses"),
                Some(bytes) => {
                    assert!(!verify_pool_step_carrier(&bytes, &commits, close), "{label} must be refused");
                    eprintln!("[pool-step] {label} → refused by the verifier");
                }
            },
        };
        refused("P_new + 1", pool_step_trace(&o, add256(proof.p_new, one).unwrap(), proof.s_new));
        refused("P_new − 1", pool_step_trace(&o, sub256(proof.p_new, one).unwrap(), proof.s_new));
        refused("S_new + 1", pool_step_trace(&o, proof.p_new, add256(proof.s_new, one).unwrap()));
        refused("S_new − 1", pool_step_trace(&o, proof.p_new, sub256(proof.s_new, one).unwrap()));
        assert!(!verify_pool_step_carrier(&proof.bytes, &proof.commits, !proof.close), "the close bit flipped refuses");
        for (i, label) in ["T", "C", "S_c", "P_old", "P_new", "S_old", "S_new"].iter().enumerate() { // PRODUCTION-SCALE-REVIEWED: the seven commitments of one pool step, not a cover count
            let mut cm = proof.commits;
            cm[i][0] ^= 1;
            assert!(!verify_pool_step_carrier(&proof.bytes, &cm, proof.close), "the {label} commitment edited refuses");
        }
        let mut swapped = proof.commits;
        swapped.swap(3, 4);
        assert!(!verify_pool_step_carrier(&proof.bytes, &swapped, proof.close), "(P_old, P_new) swapped refuses");
        assert!(!verify_pool_step_carrier(&[], &proof.commits, proof.close), "no bytes, no proof");
        // a full drain: P_new = 0, the epoch closes, and the carrier is the same size
        let drain = PoolStepOpening { c: o.t, ..o };
        let dp = prove_pool_step_carrier(&drain).expect("a drain proves");
        assert!(dp.close && dp.p_new == u256_from_u64(0) && verify_pool_step_carrier(&dp.bytes, &dp.commits, true));
        assert!(!verify_pool_step_carrier(&dp.bytes, &dp.commits, false), "a drain claimed open refuses");
        assert_eq!(dp.bytes.len(), proof.bytes.len(), "one carrier size whether or not the epoch closes");
    }

    // ── a depositor's WITHDRAWAL carrier ──
    /// ⭐ THE WITHDRAWAL RULE END TO END: a sole depositor (`d = T = 1e9`) deposits at a fresh epoch's `(2^128, 0)`; one
    /// liquidation retires 1e8 and seizes 200,000 sats (the pool step); withdrawing under the stepped `(P, S)` returns the
    /// pool minus the retire and the seized collateral, each ROUNDED DOWN by exactly the dust the pool keeps
    /// (899,999,999 USDm-atomic of 900,000,000; 199,999 sats of 200,000) — checked against an independent 16-bit
    /// schoolbook as `compounded·P_dep + r₁ = d·P_now` with `r₁ < P_dep`, and likewise for the gain.
    #[test]
    fn pool_withdraw_is_the_rounded_down_rule() {
        let p0: U256 = [0, 0, 1, 0];
        let (t, c, s_c) = (u256_from_u64(1_000_000_000), u256_from_u64(100_000_000), u256_from_u64(200_000));
        let (p1, s1, _) = pool_step(t, c, s_c, p0, u256_from_u64(0)).unwrap();
        let (co, ga) = pool_withdraw(t, p0, u256_from_u64(0), p1, s1).expect("the withdrawal has a rule");
        assert_eq!((co, ga), (u256_from_u64(899_999_999), u256_from_u64(199_999)), "the whole pool less the retire, and the whole seizure — less the rounding dust");
        let (dl, pdl, pnl, col, gal, dsl) = (u256_to_limbs16(t), u256_to_limbs16(p0), u256_to_limbs16(p1), u256_to_limbs16(co), u256_to_limbs16(ga), u256_to_limbs16(s1));
        let lt = |a: &[u64], b: &[u64]| !limbs_ge(a, b);
        let r1 = limbs_sub(&schoolbook16(&dl, &pnl), &schoolbook16(&col, &pdl)).expect("compounded·P_dep ≤ d·P_now");
        assert!(r1[N_LIMB16..].iter().all(|&l| l == 0) && lt(&r1[..N_LIMB16], &pdl), "0 ≤ r₁ < P_dep");
        let r2 = limbs_sub(&schoolbook16(&dl, &dsl), &schoolbook16(&gal, &pdl)).expect("gain·P_dep ≤ d·(S_now − S_dep)");
        assert!(r2[N_LIMB16..].iter().all(|&l| l == 0) && lt(&r2[..N_LIMB16], &pdl), "0 ≤ r₂ < P_dep");
        assert!(pool_withdraw(t, p0, s1, p1, u256_from_u64(0)).is_none(), "S_now < S_dep has no rule");
        assert!(pool_withdraw(t, u256_from_u64(0), u256_from_u64(0), p1, s1).is_none(), "P_dep = 0 has no rule");
        // a deposit made AFTER the liquidation (at the stepped snapshot) withdraws unchanged: no compounding, no gain
        let (co2, ga2) = pool_withdraw(u256_from_u64(777), p1, s1, p1, s1).unwrap();
        assert_eq!((co2, ga2), (u256_from_u64(777), u256_from_u64(0)));
    }

    /// ⭐⭐⭐ THE WITHDRAWAL CARRIER, RED FIRST. The honest withdrawal proves and verifies against the seven commitments.
    /// Refused — by the chains (no witness) or the verifier: `compounded ± 1`, `gain ± 1`; each commitment edited;
    /// `(P_dep, P_now)` swapped (the depositor claiming the pool's snapshot as their own); no bytes.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER is the depositor (their deposit's openings) together with the bonded set (the pool's
    /// openings); the VERIFIER is every node, handed the bytes and seven commitments — the production boundary of
    /// `verify_withdraw_carrier`.
    #[test]
    fn withdraw_carrier_proves_the_rule_and_refuses_every_neighbour() {
        use crate::poseidon2_compress::lanes_of;
        let blinds: [Digest; 7] = core::array::from_fn(|i| lanes_of(&[71 + i as u64]));
        let p0: U256 = [0, 0, 1, 0];
        let (t, c, s_c) = (u256_from_u64(1_000_000_000), u256_from_u64(100_000_000), u256_from_u64(200_000));
        let (p1, s1, _) = pool_step(t, c, s_c, p0, u256_from_u64(0)).unwrap();
        let o = WithdrawOpening { d: u256_from_u64(250_000_000), p_dep: p0, s_dep: u256_from_u64(0), p_now: p1, s_now: s1, blinds };
        let proof = prove_withdraw_carrier(&o).expect("the honest withdrawal proves");
        assert!(verify_withdraw_carrier(&proof.bytes, &proof.commits), "the honest withdrawal verifies");
        assert_eq!((proof.compounded, proof.gain), (u256_from_u64(224_999_999), u256_from_u64(49_999)), "a quarter of the pool: a quarter of what is left, a quarter of the seizure, dust to the pool");
        eprintln!("[withdraw] carrier {} B over {} columns", proof.bytes.len(), WD_WIDTH);
        let one = u256_from_u64(1);
        let refused = |label: &str, t: Option<(Vec<Vec<Fa4>>, [Digest; 7])>| match t {
            None => eprintln!("[withdraw] {label} → no witness"),
            Some((cols, commits)) => match prove_withdraw_trace(cols, &commits) {
                None => eprintln!("[withdraw] {label} → the prover refuses"),
                Some(bytes) => {
                    assert!(!verify_withdraw_carrier(&bytes, &commits), "{label} must be refused");
                    eprintln!("[withdraw] {label} → refused by the verifier");
                }
            },
        };
        refused("compounded + 1", withdraw_trace(&o, add256(proof.compounded, one).unwrap(), proof.gain));
        refused("compounded − 1", withdraw_trace(&o, sub256(proof.compounded, one).unwrap(), proof.gain));
        refused("gain + 1", withdraw_trace(&o, proof.compounded, add256(proof.gain, one).unwrap()));
        refused("gain − 1", withdraw_trace(&o, proof.compounded, sub256(proof.gain, one).unwrap()));
        for (i, label) in ["d", "P_dep", "S_dep", "P_now", "S_now", "compounded", "gain"].iter().enumerate() { // PRODUCTION-SCALE-REVIEWED: the seven commitments of one withdrawal, not a cover count
            let mut cm = proof.commits;
            cm[i][0] ^= 1;
            assert!(!verify_withdraw_carrier(&proof.bytes, &cm), "the {label} commitment edited refuses");
        }
        let mut swapped = proof.commits;
        swapped.swap(1, 3);
        assert!(!verify_withdraw_carrier(&proof.bytes, &swapped), "(P_dep, P_now) swapped refuses");
        assert!(!verify_withdraw_carrier(&[], &proof.commits), "no bytes, no proof");
    }

    // ── the EPOCH BRIDGE: a closed epoch's receipts settle through the next epoch's words ──
    /// ⭐ THE BRIDGE RULE, natively, against an INDEPENDENT spelling (the 16-bit schoolbook): `P_b·2^128 ≤ P₁·P₂ <
    /// (P_b + 1)·2^128` and `S_b − S₁` likewise for `P₁·S₂`. The identity bridge through the public opening `(2^128, 0)`
    /// returns the live pair exactly; a drain close (`P₁ = 0`) settles at its closing `S` with nothing compounded. End to
    /// end: a sole depositor's epoch closes NON-DRAIN at half the pool (`P_c = 2^63`), the next epoch halves the pool again
    /// and seizes collateral — the old receipt is paid HALF its closing value and the WHOLE new seizure (the residual was
    /// the whole pool), exactly what a deposit of the residual at the new epoch's opening would be paid.
    #[test]
    fn pool_bridge_is_the_rounded_down_chain_through_the_next_epoch() {
        let p0: U256 = [0, 0, 1, 0]; // 2^128: a fresh epoch's P
        let (p, s) = ([0x1234_5678, 0x9abc_def0, 0, 0], u256_from_u64(987_654_321));
        assert_eq!(pool_bridge(p, s, p0, u256_from_u64(0)), Some((p, s)), "the identity bridge is the live pair");
        assert_eq!(pool_bridge(u256_from_u64(0), s, p, u256_from_u64(5)), Some((u256_from_u64(0), s)), "a drain close settles at its S");
        // an epoch-0 deposit d = 2^80 at (2^128, 0); the epoch closed NON-DRAIN at P_c = 2^63 (its closing value is
        // d·P_c/2^128 = 2^15) with S_c = 2^50 (its closing gain d·S_c/2^128 = 4)
        let d: U256 = [0, 1 << 16, 0, 0];
        let (p_c, s_c): (U256, U256) = ([1 << 63, 0, 0, 0], u256_from_u64(1 << 50));
        // epoch 1: the residual 2^15 is the whole pool; one liquidation halves it and seizes 1,000 sats
        let (p_n, s_n, close) = pool_step(u256_from_u64(1 << 15), u256_from_u64(1 << 14), u256_from_u64(1_000), p0, u256_from_u64(0)).unwrap();
        assert!(!close, "one halving does not close");
        let (p_b, s_b) = pool_bridge(p_c, s_c, p_n, s_n).expect("the bridge has a rule");
        let (pcl, pnl, snl, pbl) = (u256_to_limbs16(p_c), u256_to_limbs16(p_n), u256_to_limbs16(s_n), u256_to_limbs16(p_b));
        let m1 = schoolbook16(&pcl, &pnl);
        assert!(m1[8..24] == pbl[..] && m1[24..].iter().all(|&l| l == 0), "P_b is P₁·P₂'s limbs [8..24]");
        let q = limbs_sub(&u256_to_limbs16(s_b), &u256_to_limbs16(s_c)).expect("S_b ≥ S₁");
        let m2 = schoolbook16(&pcl, &snl);
        assert!(m2[8..24] == q[..N_LIMB16] && m2[24..].iter().all(|&l| l == 0), "S_b − S₁ is P₁·S₂'s limbs [8..24]");
        let (co_close, ga_close) = pool_withdraw(d, p0, u256_from_u64(0), p_c, s_c).unwrap();
        assert_eq!((co_close, ga_close), (u256_from_u64(1 << 15), u256_from_u64(4)), "frozen at the close");
        let (co, ga) = pool_withdraw(d, p0, u256_from_u64(0), p_b, s_b).unwrap();
        assert_eq!((co, ga), (u256_from_u64(1 << 14), u256_from_u64(1_004)), "bridged: half the closing value is left, and the whole epoch-1 seizure is its gain");
        assert!(pool_bridge([u64::MAX; 4], s, [u64::MAX; 4], s).is_none(), "a bridged P above 2^256 has no rule");
    }

    /// ⭐⭐⭐ THE BRIDGE CARRIER, RED FIRST. The honest bridge proves and verifies against the six commitments, the identity
    /// bridge and a non-drain chain at one carrier size. Refused — by the limb equalities (no witness) or the verifier:
    /// `P_b ± 1`, `S_b ± 1`; each commitment edited; `(P₁, P₂)` and `(S₁, S₂)` swapped; no bytes; the bytes handed to the
    /// pool-step and withdraw doors.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER is the bonded custodian holding the openings of both epochs' words; the VERIFIER is
    /// every node, handed the bytes, the four source commitments from its OWN ledger and the bridged pair from the object —
    /// the production boundary of `verify_pool_bridge_carrier`.
    #[test]
    fn pool_bridge_carrier_proves_the_rule_and_refuses_every_neighbour() {
        use crate::poseidon2_compress::lanes_of;
        let blinds: [Digest; 6] = core::array::from_fn(|i| lanes_of(&[91 + i as u64]));
        let p0: U256 = [0, 0, 1, 0];
        let (p_n, s_n, _) = pool_step(u256_from_u64(1_000_000), u256_from_u64(500_000), u256_from_u64(1_000), p0, u256_from_u64(0)).unwrap();
        let o = PoolBridgeOpening { p1: [1 << 63, 0, 0, 0], s1: u256_from_u64(77_777), p2: p_n, s2: s_n, blinds };
        let proof = prove_pool_bridge_carrier(&o).expect("the honest bridge proves");
        assert!(verify_pool_bridge_carrier(&proof.bytes, &proof.commits), "the honest bridge verifies");
        assert_eq!(Some((proof.p_b, proof.s_b)), pool_bridge(o.p1, o.s1, o.p2, o.s2));
        eprintln!("[pool-bridge] carrier {} B over {} columns", proof.bytes.len(), PB_WIDTH);
        let one = u256_from_u64(1);
        for (label, pb, sb) in [
            ("P_b + 1", add256(proof.p_b, one).unwrap(), proof.s_b),
            ("P_b − 1", sub256(proof.p_b, one).unwrap(), proof.s_b),
            ("S_b + 1", proof.p_b, add256(proof.s_b, one).unwrap()),
            ("S_b − 1", proof.p_b, sub256(proof.s_b, one).unwrap()),
        ] {
            assert!(pool_bridge_trace(&o, pb, sb).is_none(), "{label}: no witness lays a bridged word that is not the shifted quotient");
        }
        for (i, label) in ["P₁", "S₁", "P₂", "S₂", "P_b", "S_b"].iter().enumerate() { // PRODUCTION-SCALE-REVIEWED: the six commitments of one bridge, not a cover count
            let mut cm = proof.commits;
            cm[i][0] ^= 1;
            assert!(!verify_pool_bridge_carrier(&proof.bytes, &cm), "the {label} commitment edited refuses");
        }
        for (a, b, label) in [(0, 2, "(P₁, P₂)"), (1, 3, "(S₁, S₂)"), (2, 4, "(P₂, P_b)")] {
            let mut sw = proof.commits;
            sw.swap(a, b);
            assert!(!verify_pool_bridge_carrier(&proof.bytes, &sw), "{label} swapped refuses");
        }
        assert!(!verify_pool_bridge_carrier(&[], &proof.commits), "no bytes, no proof");
        let seven: [Digest; 7] = core::array::from_fn(|i| if i < 6 { proof.commits[i] } else { proof.commits[5] });
        assert!(!verify_pool_step_carrier(&proof.bytes, &seven, false) && !verify_withdraw_carrier(&proof.bytes, &seven), "a bridge is no other carrier");
        // the identity bridge (a live receipt) is the same carrier size
        let id = PoolBridgeOpening { p1: p_n, s1: s_n, p2: p0, s2: u256_from_u64(0), blinds };
        let ip = prove_pool_bridge_carrier(&id).expect("the identity bridge proves");
        assert!((ip.p_b, ip.s_b) == (p_n, s_n) && verify_pool_bridge_carrier(&ip.bytes, &ip.commits));
        assert_eq!(ip.bytes.len(), proof.bytes.len(), "one carrier size for a live and a closed receipt");
    }

    // ── DB-80c: the peg-in carrier's RESERVE deposit, committed ──
    /// ⛔⛔⛔ DB-80c, ARMED FIRST. The mint-delta carrier's reserve deposit is a free witness: a prover who claims a
    /// deposit LARGER than the one observed proves and VERIFIES against the honest `(reserve, minted)` commitments —
    /// the transition, the openings and the backing all hold over the claimed reserve (MEASURED here: +1,000,000 on a
    /// 300 deposit). The both-deltas carrier refuses the same claim: its `deposit_commit` opens to the attested deposit,
    /// so the only reserve conservation with a witness is `reserve + attested_deposit`. Also refused: the deposit
    /// commitment edited or swapped with the mint delta's, a DB-80 proof handed to the DB-80c door and vice versa.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER is the orchestrating bonded node; the VERIFIER is every node, handed the bytes
    /// and six commitments (the deposit's from the observers' attestation) — the production boundary of
    /// `verify_peg_in_carrier_bound`.
    /// ⭐⭐⭐ DB-124 (lane funds 2026-10-29) — THE BACKING IS PRICED. A Bitcoin mint at a real price: 2,500,000 sats at $60,000
    /// ($1,500) backs 1,000 USDm at 150 % exactly; the carrier proves and verifies. TAMPERS: 2,400,000 sats ($1,440) backs it at
    /// 144 % and is unprovable; the honest proof does not verify at a higher ratio or a lower price; and the SAME deposit at a
    /// unit price (one sat = one USDm atomic, the convention every old fixture used and the only one the old raw gate could
    /// pass) cannot back the mint. MEASURED before the fix: the raw gate refused the honest real-price mint (2.5e6·10,000 <
    /// 1e11·15,000).
    /// TWO-PARTY-REVIEWED: the PROVER is the orchestrating custodian; the VERIFIER is every node, handed the bytes, the five
    /// commitments and the backing it holds — the production boundary of `verify_peg_in_carrier_delta`.
    /// ⭐ SOUND IS MEASURED (user 2026-09-29) — DB-124 re-laid the backing block of four gates (the wide multiplies and the
    /// 23-limb compare replaced the scale blocks), so the three censuses run on each over an honest real-price trace: every
    /// law's degree as MEASURED, no undeclared free column, no decorative block.
    #[test]
    fn db124_the_priced_backing_gates_pass_the_three_censuses() {
        use crate::poseidon2_compress::lanes_of;
        let price = 60_000u128 * u128::from(LIQ_PRICE_SCALE);
        let at = Backing { ratio_bps: 15_000, price };
        let (rb, mb, nrb, nmb, db) = (lanes_of(&[71]), lanes_of(&[72]), lanes_of(&[73]), lanes_of(&[74]), lanes_of(&[75]));
        let census = |cols: Vec<Vec<Fa4>>, gate: &dyn Fn(usize, &[Vec<Fa4>])| {
            let cols = replicate_rows(cols, 1 << 2);
            gate(cols[0].len().trailing_zeros() as usize, &cols);
        };
        // the mint-delta peg-in gate
        let (cols, c) = bound_transition_trace_delta(u256_from_u64(0), u256_from_u64(0), u256_from_u64(2_500_000), u256_from_u64(100_000_000_000), rb, mb, nrb, nmb, db, at)
            .expect("the honest real-price trace lays");
        let g = PinnedBoundTransitionDeltaAir {
            inner: PinnedBoundTransitionAir {
                gamma: Ea4::from(Fa4::from_u64(0xDB12)),
                ratio_bps: at,
                reserve_commit: commit_to_ea4(c.base.reserve_commit),
                minted_commit: commit_to_ea4(c.base.minted_commit),
                new_reserve_commit: commit_to_ea4(c.base.new_reserve_commit),
                new_minted_commit: commit_to_ea4(c.base.new_minted_commit),
                gate: TransitionGate::Marginal,
            },
            delta_commit: commit_to_ea4(c.delta_commit),
        };
        census(cols, &|nvars, cols| {
            crate::air_zerocheck::debug_degree_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_free_witness_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_decorative_block_census(cols, &g, nvars, true, &Some(Vec::new()));
        });
        // the peg-out gate (backing on the post state, the a-side)
        // DB-470: a $40 cash-out releases 66,666 sats at $60,000 (≤ $1 per USDm burned, under its pro-rata share)
        let floor = Backing { ratio_bps: 10_000, price: at.price };
        let (cols, pc) = pegout_trace(u256_from_u64(2_500_000), u256_from_u64(100_000_000_000), u256_from_u64(66_666), u256_from_u64(4_000_000_000), rb, mb, nrb, nmb, floor)
            .expect("the honest real-price peg-out lays");
        let g = PinnedBoundTransitionAir {
            gamma: Ea4::from(Fa4::from_u64(0xDB13)),
            ratio_bps: floor,
            reserve_commit: commit_to_ea4(pc.new_reserve_commit),
            minted_commit: commit_to_ea4(pc.new_minted_commit),
            new_reserve_commit: commit_to_ea4(pc.reserve_commit),
            new_minted_commit: commit_to_ea4(pc.minted_commit),
            gate: TransitionGate::Redeem,
        };
        census(cols, &|nvars, cols| {
            crate::air_zerocheck::debug_degree_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_free_witness_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_decorative_block_census(cols, &g, nvars, true, &Some(Vec::new()));
        });
        // the yield gate (both sides USDm: a unit price)
        let unit = Backing::at_unit_price(10_000);
        let (cols, yc) = yield_mint_trace(u256_from_u64(1_000_000), u256_from_u64(400_000), u256_from_u64(1_000), rb, mb, nrb, db, unit)
            .expect("the honest yield trace lays");
        let g = yield_air(&yc, unit)(Ea4::from(Fa4::from_u64(0xDB14)));
        census(cols, &|nvars, cols| {
            crate::air_zerocheck::debug_degree_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_free_witness_census(cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_decorative_block_census(cols, &g, nvars, true, &Some(Vec::new()));
        });
        eprintln!("[db124-census] the delta peg-in, peg-out and yield gates pass the degree, free-witness and decorative-block censuses");
    }

    fn cover_fixture(kind: CoverKind, mover: usize) -> ([CoverLeg; 2], Digest) {
        use crate::poseidon2_compress::lanes_of;
        let btc = 60_000u128 * u128::from(LIQ_PRICE_SCALE);
        let xmr = 15_000u128; // $150 per XMR, per piconero at the price scale
        let ratio = |price: u128| match kind {
            CoverKind::PegIn => Backing { ratio_bps: 15_000, price },
            CoverKind::PegOut => Backing { ratio_bps: 10_000, price },
        };
        let blinds = |k: u64| (lanes_of(&[k, 1]), lanes_of(&[k, 2]), lanes_of(&[k, 3]), lanes_of(&[k, 4]));
        // two standing ledgers (Bitcoin's sats, Monero's piconero), each 300 % backed
        let state = [(u256_from_u64(9_000_000), u256_from_u64(180_000_000_000)), (u256_from_u64(60_000_000_000_000), u256_from_u64(300_000_000_000))];
        let (dr, dm) = match kind {
            // $1,000 against $1,500 of sats, $100 against $150 of piconero (150 %)
            CoverKind::PegIn => [(u256_from_u64(2_500_000), u256_from_u64(100_000_000_000)), (u256_from_u64(1_000_000_000_000), u256_from_u64(10_000_000_000))][mover],
            // $40 at each ledger's price: 66,666 sats, or 266,666,666,666 piconero
            CoverKind::PegOut => [(u256_from_u64(66_666), u256_from_u64(4_000_000_000)), (u256_from_u64(266_666_666_666), u256_from_u64(4_000_000_000))][mover],
        };
        let legs: [CoverLeg; 2] = core::array::from_fn(|i| {
            let (rb, mb, nrb, nmb) = blinds(0xC0 + i as u64);
            let moves = i == mover;
            CoverLeg {
                reserve: state[i].0,
                minted: state[i].1,
                delta_reserve: if moves { dr } else { u256_from_u64(0) },
                delta_minted: if moves { dm } else { u256_from_u64(0) },
                r_blind: rb,
                m_blind: mb,
                nr_blind: nrb,
                nm_blind: nmb,
                backing: ratio(if i == 0 { btc } else { xmr }),
            }
        });
        (legs, lanes_of(&[0xC0DE]))
    }

    /// ⭐⭐ §19.5b — A PEG MOVES BOTH BRIDGE LEDGERS AND THE PROOF DOES NOT SAY WHICH. For each kind (peg-in, peg-out) and each
    /// ledger that really moves (Bitcoin's, Monero's), the cover proves and verifies against BOTH ledgers' commitments, both
    /// backings and the one delta commitment — the verifier's inputs have one shape whichever ledger moved, and both ledgers'
    /// post pairs differ from their current ones. TAMPER (each refused): a delta commitment the legs do not sum to; the legs'
    /// commitments swapped; a post pair from another proof; a leg breaking its own rule (a release worth twice its burn, a
    /// mint past its backing) is unprovable; a sum that would overflow is unprovable.
    /// TWO-PARTY-REVIEWED: the PROVER is the orchestrating custodian; the VERIFIER is every node, handed only the bytes, the
    /// commitments and the backings it holds — the production boundary of `verify_cover_carrier`.
    #[test]
    fn br19_5b_a_cover_moves_both_ledgers_and_verifies_alike_whichever_moved() {
        for kind in [CoverKind::PegIn, CoverKind::PegOut] {
            let mut proofs = Vec::new();
            for mover in 0..2 {
                let (legs, db) = cover_fixture(kind, mover);
                let backings = [legs[0].backing, legs[1].backing];
                let (bytes, c) = prove_cover_carrier(kind, &legs, db).expect("an honest cover proves");
                assert!(verify_cover_carrier(&bytes, kind, &c, backings), "⛔ {kind:?}: an honest cover (ledger {mover} moved) was refused");
                for l in &c.legs {
                    assert_ne!((l.reserve_commit, l.minted_commit), (l.new_reserve_commit, l.new_minted_commit), "⛔ a ledger's pair did not change — the cover names the mover");
                }
                // TAMPER: a delta commitment the legs do not sum to
                let mut wrong = c;
                wrong.delta_commit = solvency_commit_256(u256_from_u64(1), db);
                assert!(!verify_cover_carrier(&bytes, kind, &wrong, backings), "⛔ {kind:?}: a cover verified against another delta");
                // TAMPER: the two legs' commitments swapped (a node reading the ledgers in another order)
                let mut swapped = c;
                swapped.legs.swap(0, 1);
                assert!(!verify_cover_carrier(&bytes, kind, &swapped, [backings[1], backings[0]]), "⛔ {kind:?}: a cover verified with its legs swapped");
                proofs.push((bytes, c));
            }
            // TAMPER: one proof's bytes against the other proof's commitments
            let (legs, _) = cover_fixture(kind, 0);
            let backings = [legs[0].backing, legs[1].backing];
            assert!(!verify_cover_carrier(&proofs[0].0, kind, &proofs[1].1, backings), "⛔ {kind:?}: a cover verified against another cover's commitments");
            // TAMPER: a leg breaking its own rule is unprovable
            let (mut bad, db) = cover_fixture(kind, 1);
            match kind {
                CoverKind::PegOut => bad[1].delta_reserve = u256_from_u64(2 * 266_666_666_666),
                CoverKind::PegIn => bad[1].delta_reserve = u256_from_u64(0), // a mint backed by no deposit
            }
            assert!(prove_cover_carrier(kind, &bad, db).is_none(), "⛔ {kind:?}: a leg past its own rule proved");
            eprintln!("[cover] {kind:?}: {} B per cover proof", proofs[0].0.len());
        }
    }

    /// ⭐ §19.5b — SOUND IS MEASURED: the cover gate passes the degree, free-witness and decorative-block censuses on an honest
    /// trace of each kind (every law's degree as measured, every column bound, no decorative block).
    #[test]
    fn br19_5b_the_cover_gate_passes_the_three_censuses() {
        for kind in [CoverKind::PegIn, CoverKind::PegOut] {
            let (legs, db) = cover_fixture(kind, 1);
            let (cols, c) = cover_trace(kind, &legs, db).expect("the honest cover lays");
            let cols = replicate_rows(cols, 1 << 2);
            let nvars = cols[0].len().trailing_zeros() as usize;
            let g = cover_air(kind, &c, [legs[0].backing, legs[1].backing], Ea4::from(Fa4::from_u64(0xC0E5)));
            crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, true, &Some(Vec::new()));
            crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, true, &Some(Vec::new()));
        }
        eprintln!("[cover-census] the peg-in and peg-out cover gates pass the degree, free-witness and decorative-block censuses");
    }

    /// ⛔⛔ DB-470 (1) — A MINT IS BACKED BY ITS OWN DEPOSIT, NEVER BY THE SYSTEM'S SURPLUS. Measured before the fix: at a
    /// 300 % system a peg-in with ZERO deposit proved a 500 USDm mint, because the gate read only the post-state aggregate.
    #[test]
    fn db470_a_mint_with_no_deposit_of_its_own_is_unprovable_however_rich_the_reserve() {
        use crate::poseidon2_compress::lanes_of;
        let at = Backing::at_unit_price(15_000);
        let (reserve, minted) = (u256_from_u64(3_000), u256_from_u64(1_000));
        let (rb, mb, nrb, nmb, db) = (lanes_of(&[71]), lanes_of(&[72]), lanes_of(&[73]), lanes_of(&[74]), lanes_of(&[75]));
        assert!(
            prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(0), u256_from_u64(500), rb, mb, nrb, nmb, db, at).is_none(),
            "⛔ DB-470: a 500 USDm mint with no deposit behind it proved against a 300 % reserve's surplus"
        );
        assert!(
            prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(749), u256_from_u64(500), rb, mb, nrb, nmb, db, at).is_none(),
            "⛔ DB-470: a mint backed 149.8 % by its own deposit proved at 150 %"
        );
        let (bytes, c) = prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(750), u256_from_u64(500), rb, mb, nrb, nmb, db, at)
            .expect("a mint its own deposit backs at exactly 150 % proves");
        assert!(verify_peg_in_carrier_delta(&bytes, at, c.base.reserve_commit, c.base.minted_commit, c.base.new_reserve_commit, c.base.new_minted_commit, c.delta_commit));
        // ⭐ AND A LEGITIMATE MINT IS NEVER REFUSED FOR THE SYSTEM'S RATIO: at a 120 % system (a price drop, no exploit), a mint its
        // own deposit backs at 150 % proves — and it lifts the aggregate toward 150 %.
        let (low_r, low_m) = (u256_from_u64(1_200), u256_from_u64(1_000));
        let (bytes, c) = prove_peg_in_carrier_delta(low_r, low_m, u256_from_u64(150), u256_from_u64(100), rb, mb, nrb, nmb, db, at)
            .expect("⛔ DB-470: a fully backed mint was refused because a price drop had left the system at 120 %");
        assert!(verify_peg_in_carrier_delta(&bytes, at, c.base.reserve_commit, c.base.minted_commit, c.base.new_reserve_commit, c.base.new_minted_commit, c.delta_commit));
    }

    /// ⛔⛔ DB-470 (3) — A CASH-OUT RELEASES AT MOST $1 OF RESERVE PER USDm IT BURNS, AND AT MOST ITS PRO-RATA SHARE; A FAIR CASH-OUT IS
    /// NEVER REFUSED FOR THE SYSTEM'S RATIO. Measured before the fix: at a 300 % system one burned USDm released 1,500 of reserve
    /// (the post state still cleared 100 %), and at an 80 % system (a price crash) every cash-out — even a fair pro-rata one — was
    /// unprovable, freezing every genuine holder.
    #[test]
    fn db470_a_cash_out_releases_only_what_its_burn_is_worth_and_is_never_frozen_by_the_ratio() {
        use crate::poseidon2_compress::lanes_of;
        let floor = Backing::at_unit_price(10_000); // $1 of reserve per USDm
        let (rb, mb, nrb, nmb) = (lanes_of(&[61]), lanes_of(&[62]), lanes_of(&[63]), lanes_of(&[64]));
        let out = |r: u64, m: u64, release: u64, burn: u64| {
            prove_peg_out_carrier(u256_from_u64(r), u256_from_u64(m), u256_from_u64(release), u256_from_u64(burn), rb, mb, nrb, nmb, floor).map(|(bytes, c)| {
                verify_peg_out_carrier(&bytes, floor, c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit)
            })
        };
        // the drain: 1 USDm burned against 1,500 released from a 300 % reserve
        assert_ne!(out(3_000, 1_000, 1_500, 1), Some(true), "⛔ DB-470: one burned USDm released 1,500 of reserve");
        assert_ne!(out(3_000, 1_000, 101, 100), Some(true), "⛔ DB-470: a cash-out released more than $1 per USDm burned");
        assert_eq!(out(3_000, 1_000, 100, 100), Some(true), "a $1-per-USDm cash-out from a solvent reserve proves and verifies");
        // the crash: an 80 % system. The fair share of a 100 USDm burn is 80; a $1 cash-out (100) would take the later holders' share.
        assert_eq!(
            out(800, 1_000, 80, 100),
            Some(true),
            "⛔ DB-470: a fair pro-rata cash-out was refused because a price crash had left the system at 80 %"
        );
        assert_ne!(out(800, 1_000, 81, 100), Some(true), "⛔ DB-470: under 100 % a cash-out took more than its pro-rata share");
        assert_eq!(out(1_200, 1_000, 100, 100), Some(true), "a $1 cash-out at a 120 % system proves (above the floor nothing binds but the $1 cap)");
    }

    #[test]
    fn db124_a_real_price_bitcoin_mint_proves_at_150_percent_and_an_under_backed_one_does_not() {
        use crate::poseidon2_compress::lanes_of;
        let price = 60_000u128 * u128::from(LIQ_PRICE_SCALE); // USDm atomic per sat × PRICE_SCALE at $60,000
        let at = Backing { ratio_bps: 15_000, price };
        let (reserve, minted) = (u256_from_u64(0), u256_from_u64(0));
        let mint = u256_from_u64(100_000_000_000); // 1,000 USDm
        let (rb, mb, nrb, nmb, db) = (lanes_of(&[91]), lanes_of(&[92]), lanes_of(&[93]), lanes_of(&[94]), lanes_of(&[95]));
        let (bytes, c) = prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(2_500_000), mint, rb, mb, nrb, nmb, db, at)
            .expect("⛔ a 150 %-backed real-price Bitcoin mint is unprovable");
        let v = |b: Backing| verify_peg_in_carrier_delta(&bytes, b, c.base.reserve_commit, c.base.minted_commit, c.base.new_reserve_commit, c.base.new_minted_commit, c.delta_commit);
        assert!(v(at), "the honest real-price mint verifies");
        assert!(!v(Backing { ratio_bps: 15_001, price }), "⛔ the proof verified at a higher ratio than it backs");
        assert!(!v(Backing { ratio_bps: 15_000, price: price - 1 }), "⛔ the proof verified at a lower price than it backs");
        assert!(
            prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(2_400_000), mint, rb, mb, nrb, nmb, db, at).is_none(),
            "⛔ a 144 %-backed mint proved at 150 %"
        );
        assert!(
            prove_peg_in_carrier_delta(reserve, minted, u256_from_u64(2_500_000), mint, rb, mb, nrb, nmb, db, Backing::at_unit_price(15_000)).is_none(),
            "CALIBRATION: at a unit price the same deposit cannot back the mint — the price is what the gate reads"
        );
        assert!(Backing { ratio_bps: 15_000, price: 0 }.ks().is_none() && Backing { ratio_bps: 0, price }.ks().is_none(), "a rule that cannot form is refused");
    }

    #[test]
    fn db80c_a_claimed_deposit_larger_than_the_attested_one_is_refused_only_by_the_bound_carrier() {
        use crate::poseidon2_compress::lanes_of;
        let (reserve, minted) = (u256_from_u64(3_000), u256_from_u64(1_000));
        let (deposit, mint) = (u256_from_u64(300), u256_from_u64(100));
        let inflated = u256_from_u64(1_000_300);
        let (rb, mb, nrb, nmb, db, depb) = (lanes_of(&[81]), lanes_of(&[82]), lanes_of(&[83]), lanes_of(&[84]), lanes_of(&[85]), lanes_of(&[86]));
        // the mint-delta carrier: the honest deposit and the inflated one BOTH verify against the honest state commits
        let (hb, hc) = prove_peg_in_carrier_delta(reserve, minted, deposit, mint, rb, mb, nrb, nmb, db, Backing::at_unit_price(15_000)).expect("honest proves");
        assert!(verify_peg_in_carrier_delta(&hb, Backing::at_unit_price(15_000), hc.base.reserve_commit, hc.base.minted_commit, hc.base.new_reserve_commit, hc.base.new_minted_commit, hc.delta_commit));
        let (fb, fc) = prove_peg_in_carrier_delta(reserve, minted, inflated, mint, rb, mb, nrb, nmb, db, Backing::at_unit_price(15_000)).expect("the inflated claim proves");
        assert_eq!((fc.base.reserve_commit, fc.base.minted_commit), (hc.base.reserve_commit, hc.base.minted_commit), "the same persisted state");
        assert!(
            verify_peg_in_carrier_delta(&fb, Backing::at_unit_price(15_000), fc.base.reserve_commit, fc.base.minted_commit, fc.base.new_reserve_commit, fc.base.new_minted_commit, fc.delta_commit),
            "MEASURED: the mint-delta carrier verifies a reserve inflated by 1,000,000 with no deposit behind it"
        );
        // the both-deltas carrier: the honest deposit proves and verifies against the ATTESTED deposit commitment
        let attested = solvency_commit_256(deposit, depb);
        let (bb, bc) = prove_peg_in_carrier_bound(reserve, minted, deposit, mint, rb, mb, nrb, nmb, db, depb, Backing::at_unit_price(15_000)).expect("honest proves");
        assert_eq!(bc.deposit_commit, attested);
        let b = &bc.delta.base;
        let verify = |bytes: &[u8], nrc: Digest, dc: Digest, depc: Digest| verify_peg_in_carrier_bound(bytes, Backing::at_unit_price(15_000), b.reserve_commit, b.minted_commit, nrc, b.new_minted_commit, dc, depc);
        assert!(verify(&bb, b.new_reserve_commit, bc.delta.delta_commit, attested), "the honest bound carrier verifies");
        eprintln!("[db80c] carrier {} B over {} columns", bb.len(), TB_WIDTH);
        // the inflated claim: its deposit commitment is not the attested one — refused at the door that holds it
        let (ib, ic) = prove_peg_in_carrier_bound(reserve, minted, inflated, mint, rb, mb, nrb, nmb, db, depb, Backing::at_unit_price(15_000)).expect("the prover lays it");
        assert_ne!(ic.deposit_commit, attested);
        assert!(!verify(&ib, ic.delta.base.new_reserve_commit, ic.delta.delta_commit, attested), "an inflated deposit against the ATTESTED commitment is refused");
        // statement edits
        let mut edited = attested;
        edited[0] ^= 1;
        assert!(!verify(&bb, b.new_reserve_commit, bc.delta.delta_commit, edited), "the deposit commitment edited refuses");
        assert!(!verify(&bb, b.new_reserve_commit, attested, bc.delta.delta_commit), "the two deltas swapped refuse");
        assert!(!verify(&hb, hc.base.new_reserve_commit, hc.delta_commit, attested), "a DB-80 proof at the DB-80c door refuses");
        assert!(!verify_peg_in_carrier_delta(&bb, Backing::at_unit_price(15_000), b.reserve_commit, b.minted_commit, b.new_reserve_commit, b.new_minted_commit, bc.delta.delta_commit), "a DB-80c proof at the DB-80 door refuses");
        assert!(!verify(&[], b.new_reserve_commit, bc.delta.delta_commit, attested), "no bytes, no proof");
    }

    /// The product's 16-bit limbs as an integer, for the native comparison (the callers keep `a·k` below 2^128).
    fn limbs16_to_u128(l: &[u64]) -> u128 {
        assert!(l.iter().skip(8).all(|&v| v == 0), "the native comparison is only made for products below 2^128");
        l.iter().enumerate().take(8).map(|(i, &v)| u128::from(v) << (16 * i)).sum()
    }

    /// ⭐ THE WIDE MULTIPLY IS EXACT: for a price-sized `k` (6·10^10, far above SCALE_K_MAX) and a u64 `k` with every
    /// chunk non-zero, the block's re-limbed product equals `a·k` natively and the relation verifies; and the
    /// operand's limbs are read from its RANGE BITS, never re-witnessed (the block has no operand columns of its own).
    #[test]
    fn wide_multiply_honest_equals_native_and_verifies() {
        for (a, k) in [
            (u256_from_u64(1_500), 60_000_000_000u128),                 // 1,500 sats × a $60,000 quote at PRICE_SCALE
            (u256_from_u64(0xFFFF_FFFF_FFFF), u128::from(u64::MAX)),      // every 14-bit chunk of a u64 k non-zero
            ([0xDEAD_BEEF_1234_5678, 42, 0, 0], 9_999_999_999u128),      // a > 2^64
            (u256_from_u64(3), (1u128 << 97) + 12_345),                  // a 98-bit k: all seven chunks live
            (u256_from_u64(0), 12_345),
        ] {
            let (cols, p16) = mul14_test_cols(a, k);
            if a[1] == 0 && u128::from(a[0]).checked_mul(k).is_some() {
                assert_eq!(limbs16_to_u128(&p16), u128::from(a[0]) * k, "the re-limbed product is a·k");
            }
            assert!(mul14_verdict(&cols, k), "honest a·k verifies (k = {k})");
        }
        assert!(!mul14_k_admissible(1u128 << 98), "a 99-bit multiplier has no seventh chunk");
    }

    /// ⛔ A FORGED PRODUCT LIMB, A FORGED CARRY, A FORGED RE-LIMBING and an operand bit that lies are each REFUSED —
    /// the column equations are integer identities, so no alias by the field modulus exists here.
    #[test]
    fn wide_multiply_forgeries_are_refused() {
        let (a, k) = (u256_from_u64(1_500), 60_000_000_000u128);
        let honest = mul14_test_cols(a, k).0;
        assert!(mul14_verdict(&honest, k), "PRECONDITION: honest verifies");
        // F1: out limb 0 raised by one, bits left stale
        let mut f1 = honest.clone();
        f1[MT_MUL + M14_OUT].iter_mut().for_each(|c| *c += Fa4::ONE);
        assert!(!mul14_verdict(&f1, k), "a forged product limb is refused");
        // F2: a carry raised by one, its bits re-laid honestly for the forged value (the column equation breaks)
        let mut f2 = honest.clone();
        let c1 = f2[MT_MUL + M14_COUT + 1][0] + Fa4::ONE;
        f2[MT_MUL + M14_COUT + 1].iter_mut().for_each(|c| *c = c1);
        assert!(!mul14_verdict(&f2, k), "a forged carry is refused");
        // F3: the 16-bit re-limbing claims a bigger product than the bits hold
        let mut f3 = honest.clone();
        f3[MT_MUL + M14_P16 + 3].iter_mut().for_each(|c| *c += Fa4::ONE);
        assert!(!mul14_verdict(&f3, k), "a forged re-limbing is refused");
        // F4: the operand's range bit 0 flipped while its 16-bit limb stays — the limb bind refuses it, so the product
        // can never be computed over an operand other than the one the opening binds
        let mut f4 = honest.clone();
        let b = f4[MT_ABITS][0];
        f4[MT_ABITS].iter_mut().for_each(|c| *c = Fa4::ONE - b);
        assert!(!mul14_verdict(&f4, k), "an operand bit that disagrees with its limb is refused");
    }

    /// ⭐ THE n-LIMB COMPARE AND ADD over 21 limbs (the product's width): `x ≥ y` verifies when true and lays no witness
    /// when false; `a + k == s` carries across every limb boundary and refuses an overflow.
    #[test]
    fn n_limb_compare_and_add_at_the_products_width() {
        const N: usize = M14_P16_LIMBS;
        let (x, y): (Vec<u64>, Vec<u64>) = ((0..N).map(|i| (i as u64 * 977 + 3) & 0xFFFF).collect(), (0..N).map(|i| (i as u64 * 977 + 2) & 0xFFFF).collect());
        let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; 2 * N + N + N + N * N_LIMB16 + N + N];
        assert!(place_ge_n(&mut cols, &x, &y, 2 * N, 3 * N, 4 * N), "x ≥ y lays");
        assert!(!place_ge_n(&mut cols, &y, &x, 2 * N, 3 * N, 4 * N), "y ≥ x has no witness (y < x)");
        let s = place_add_n(&mut cols, &x, &y, 4 * N + N * N_LIMB16, 5 * N + N * N_LIMB16).expect("no overflow");
        assert_eq!(s.len(), N);
        let full: Vec<u64> = vec![0xFFFF; N];
        assert!(place_add_n(&mut cols, &full, &[1u64].iter().copied().chain(std::iter::repeat(0)).take(N).collect::<Vec<_>>(), 4 * N + N * N_LIMB16, 5 * N + N * N_LIMB16).is_none(), "an overflow past the top limb lays no witness");
    }

    // ── LIQUIDATION: the AMOUNT carrier ──
    /// The rule the pins run under: BTC at $60,000 (quote 6e10 at PRICE_SCALE), a 10 % pool discount, a 150 % target,
    /// due under 120 %.
    fn liq_rule() -> LiqRule {
        LiqRule { p: 60_000_000_000, delta_bps: 1_000, rho_target_bps: 15_000, rho_liq_bps: 12_000 }
    }
    fn liq_blinds() -> [Digest; 5] {
        use crate::poseidon2_compress::lanes_of;
        [lanes_of(&[31]), lanes_of(&[32]), lanes_of(&[33]), lanes_of(&[34]), lanes_of(&[35])]
    }
    /// §2.2 spelled INDEPENDENTLY in plain u128 arithmetic for the pins' small positions; the twin under test is limb
    /// arithmetic at the product width — two spellings agreeing is the check.
    fn rule_by_hand(d: u128, m: u128, r: &LiqRule) -> Option<(u128, u128)> {
        let (bps, ps) = (10_000u128, 1_000_000u128);
        let (p, dl, rt, rl) = (u128::from(r.p), u128::from(r.delta_bps), u128::from(r.rho_target_bps), u128::from(r.rho_liq_bps));
        if d * p * bps >= rl * m * ps {
            return None; // covered: not due
        }
        let (k1, k2) = (p * (bps - dl), bps * ps);
        let shortfall = (bps - dl) * (rt * m * ps - d * p * bps) + bps * (k1 - 1);
        let q = ps * (rt * (bps - dl) - bps * bps);
        let c = ((shortfall + q - 1) / q).min(m);
        let s = ((c * k2 + k1 - 1) / k1).min(d);
        Some((c, s))
    }
    /// The post-state restores the target: `(D − S)·p·BPS ≥ RHO_TARGET·(M − C)·PS`.
    fn target_restored(d: u128, m: u128, c: u128, s: u128, r: &LiqRule) -> bool {
        (d - s) * u128::from(r.p) * 10_000 >= u128::from(r.rho_target_bps) * (m - c) * 1_000_000
    }
    /// The verdict on a LAID trace at the production doors: proven if the prover will, then verified against the same
    /// statement — `false` when either door refuses, and which one.
    fn liq_verdict(cols: Vec<Vec<Fa4>>, commits: &[Digest; 5], rule: &LiqRule) -> (bool, &'static str) {
        match prove_liq_trace(cols, commits, rule) {
            None => (false, "the prover (no proof laid)"),
            Some(bytes) => (verify_liquidation_amount_carrier(&bytes, commits, rule), "the verifier"),
        }
    }

    /// ⭐ THE NATIVE RULE IN EVERY REGIME. Partial: at $60,000, 100,000 sats against 5.2e9 atomic (115 %) retires
    /// 4,628,725,715 and seizes 85,718 sats — the post-state sits at the 150 % target and one sat less would not cover C.
    /// Full: against 5.5e9 (109 %) the discounted collateral cannot cover the debt — everything is retired and the whole
    /// reserve seized. The edge: against 5.4e9, `D·k1 = M·k2` exactly — a full retire whose seizure lands on D uncapped.
    /// Not due at exactly 120 %. Every rule that is no rule is refused; the widest quote is admissible.
    #[test]
    fn liquidation_amount_is_the_rule_in_every_regime() {
        let r = liq_rule();
        let d = 100_000u128;
        let amount = |m: u128| liquidation_amount(u256_from_u64(d as u64), u256_from_u64(m as u64), &r);
        let regimes = |m: u128| liquidation_amount_regimes(u256_from_u64(d as u64), u256_from_u64(m as u64), &r).map(|(_, _, fc, fs)| (fc, fs));
        // partial
        assert_eq!(amount(5_200_000_000), Some((u256_from_u64(4_628_725_715), u256_from_u64(85_718))));
        assert_eq!(rule_by_hand(d, 5_200_000_000, &r), Some((4_628_725_715, 85_718)));
        assert!(target_restored(d, 5_200_000_000, 4_628_725_715, 85_718, &r), "the post-state restores the target");
        assert!(85_717u128 * 60_000_000_000 * 9_000 < 4_628_725_715u128 * 10_000_000_000, "one sat less would not cover C");
        assert_eq!(regimes(5_200_000_000), Some((false, false)));
        // full retire + full seize
        assert_eq!(amount(5_500_000_000), Some((u256_from_u64(5_500_000_000), u256_from_u64(100_000))));
        assert_eq!(rule_by_hand(d, 5_500_000_000, &r), Some((5_500_000_000, 100_000)));
        assert_eq!(regimes(5_500_000_000), Some((true, true)));
        // the rounding edge: D·k1 = M·k2 — a full retire, the seizure exactly D without the cap
        assert_eq!(amount(5_400_000_000), Some((u256_from_u64(5_400_000_000), u256_from_u64(100_000))));
        assert_eq!(rule_by_hand(d, 5_400_000_000, &r), Some((5_400_000_000, 100_000)));
        assert_eq!(regimes(5_400_000_000), Some((true, false)));
        // covered at exactly 120 %: not due
        assert!(amount(5_000_000_000).is_none());
        assert!(rule_by_hand(d, 5_000_000_000, &r).is_none());
        // the rules that are no rule
        assert!(!LiqRule { p: 0, ..r }.admissible(), "a zero mark is no rule");
        assert!(!LiqRule { delta_bps: 10_000, ..r }.admissible(), "a 100 % discount is no rule");
        assert!(!LiqRule { rho_target_bps: 11_000, ..r }.admissible(), "a target the discounted seizure cannot reach (1.1 × 0.9 < 1) is no rule");
        assert!(!LiqRule { rho_liq_bps: 16_000, ..r }.admissible(), "a due ratio above the target is no rule");
        assert!(LiqRule { p: u64::MAX, ..r }.admissible(), "the widest quote is admissible — no ceiling on a mark");
        assert_eq!(liquidation_seize_k1(u64::MAX, 0), Some(u128::from(u64::MAX) * 10_000));
    }

    /// ⭐⭐⭐ THE AMOUNT CARRIER, RED FIRST. In each regime the honest `(C, S) = liquidation_amount(D, M, rule)` proves and
    /// verifies against the four commitments and the public rule; the carrier is one size in every regime, so the
    /// verifier learns neither an amount nor the regime. Refused — by the gadgets (no witness) or by the verifier: an
    /// amount one unit off in either direction; a regime claimed that the amounts are not in; a covered position
    /// (specifically at the DUE compare); every statement edit (mark, discount, target, due ratio, each commitment, the
    /// commitments swapped); an inadmissible rule at both doors; no bytes.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER is a bonded node holding the position's sealed openings; the VERIFIER is every
    /// node, handed only the bytes, the four commitments the liquidation object carries and the folded mark's public
    /// rule — the production boundary of `verify_liquidation_amount_carrier`.
    #[test]
    fn liquidation_amount_carrier_proves_the_rule_and_refuses_every_neighbour() {
        let r = liq_rule();
        let b = liq_blinds();
        let d = u256_from_u64(100_000);
        let tinf = LIQ_POOL_UNBOUNDED;
        let one = u256_from_u64(1);
        let mut sizes = Vec::new();
        for (m, regime) in [(5_200_000_000u64, "partial"), (5_500_000_000, "full retire + full seize"), (5_400_000_000, "full retire, seizure exactly D")] {
            let m = u256_from_u64(m);
            let (c, s, full_c, full_s) = liquidation_amount_regimes(d, m, &r).unwrap();
            let proof = prove_liquidation_amount_carrier(d, m, tinf, &b, &r).expect("the honest amounts prove");
            assert_eq!((proof.c, proof.s), (c, s));
            assert!(verify_liquidation_amount_carrier(&proof.bytes, &proof.commits, &r), "{regime}: the honest carrier verifies");
            eprintln!("[liq-amount] {regime}: carrier {} B over {} columns (full_c={full_c} full_s={full_s})", proof.bytes.len(), LQ_WIDTH);
            sizes.push(proof.bytes.len());
            let refused = |label: &str, t: Option<(Vec<Vec<Fa4>>, [Digest; 5])>| match t {
                None => eprintln!("[liq-amount] {regime}: {label} → no witness"),
                Some((cols, commits)) => {
                    let (ok, door) = liq_verdict(cols, &commits, &r);
                    assert!(!ok, "{regime}: {label} must be refused");
                    eprintln!("[liq-amount] {regime}: {label} → refused by {door}");
                }
            };
            // an amount one unit off, in the honest regimes
            for (label, c2, s2) in [("C + 1", add256(c, one), Some(s)), ("C − 1", sub256(c, one), Some(s)), ("S + 1", Some(c), add256(s, one)), ("S − 1", Some(c), sub256(s, one))] {
                if let (Some(c2), Some(s2)) = (c2, s2) {
                    refused(label, liquidation_amount_trace(d, m, tinf, c2, s2, &b, &r, full_c, full_s, false));
                }
            }
            // the other regime claimed for the honest amounts
            refused("full_c flipped", liquidation_amount_trace(d, m, tinf, c, s, &b, &r, !full_c, full_s, false));
            refused("full_s flipped", liquidation_amount_trace(d, m, tinf, c, s, &b, &r, full_c, !full_s, false));
            refused("pool_c claimed (C is not T)", liquidation_amount_trace(d, m, tinf, c, s, &b, &r, false, full_s, true));
        }
        assert!(sizes.iter().all(|&z| z == sizes[0]), "one carrier size in every regime: {sizes:?}");
        // statement edits on the partial regime's honest carrier
        let m = u256_from_u64(5_200_000_000);
        let proof = prove_liquidation_amount_carrier(d, m, tinf, &b, &r).unwrap();
        for (label, r2) in [
            ("mark + 1", LiqRule { p: r.p + 1, ..r }),
            ("discount + 1", LiqRule { delta_bps: r.delta_bps + 1, ..r }),
            ("target + 1", LiqRule { rho_target_bps: r.rho_target_bps + 1, ..r }),
            ("due ratio + 1", LiqRule { rho_liq_bps: r.rho_liq_bps + 1, ..r }),
            ("a zero mark", LiqRule { p: 0, ..r }),
        ] {
            assert!(!verify_liquidation_amount_carrier(&proof.bytes, &proof.commits, &r2), "{label} refuses");
        }
        for (i, label) in ["reserve", "minted", "retired", "seized", "pool"].iter().enumerate() { // PRODUCTION-SCALE-REVIEWED: the five commitments of one liquidation object (DD, DM, DC, DS, DT), not a cover count
            let mut cm = proof.commits;
            cm[i][0] ^= 1;
            assert!(!verify_liquidation_amount_carrier(&proof.bytes, &cm, &r), "the {label} commitment edited refuses");
        }
        let swapped = [proof.commits[1], proof.commits[0], proof.commits[2], proof.commits[3], proof.commits[4]];
        assert!(!verify_liquidation_amount_carrier(&proof.bytes, &swapped, &r), "swapped commitments refuse");
        assert!(!verify_liquidation_amount_carrier(&[], &proof.commits, &r), "no bytes, no proof");
        // a covered position has no liquidation — and the honest gadgets refuse a forged claim of due-ness AT THE DUE
        // COMPARE: the same amounts ARE the rule's under a rule that makes 120 % due (RHO_LIQ = 130 %; C, S do not depend on it)
        let m_covered = u256_from_u64(5_000_000_000);
        assert!(prove_liquidation_amount_carrier(d, m_covered, tinf, &b, &r).is_none(), "a covered position has no liquidation");
        let due_under = LiqRule { rho_liq_bps: 13_000, ..r };
        let (c, s, full_c, full_s) = liquidation_amount_regimes(d, m_covered, &due_under).unwrap();
        assert!(liquidation_amount_trace(d, m_covered, tinf, c, s, &b, &r, full_c, full_s, false).is_none(), "the DUE compare lays no witness for a covered position");
        assert!(prove_liquidation_amount_carrier(d, m, tinf, &b, &LiqRule { delta_bps: 10_000, ..r }).is_none(), "an inadmissible rule lays no witness");
    }

    /// ⭐⭐⭐ THE POOL CAP, RED FIRST (spec §2.2/§10: "C = min(M, pool)"). A due position whose pool holds LESS than the
    /// rule's retire is liquidated PARTIALLY: C = T exactly (the pool burned whole) and S the least collateral covering
    /// it — proven and verified against the five commitments, the same carrier size as every other regime. Refused: the
    /// rule's full C against the small pool (more than the pool holds — no witness at T ≥ C); C = T − 1 (not the cap);
    /// the uncapped regime claimed at C = T; the pool commitment edited; an EMPTY pool has no liquidation at all.
    #[test]
    fn a_pool_smaller_than_the_retire_is_burned_whole_and_nothing_else_proves() {
        let r = liq_rule();
        let b = liq_blinds();
        let (d, m) = (u256_from_u64(100_000), u256_from_u64(5_200_000_000));
        let (c_rule, _) = liquidation_amount(d, m, &r).expect("CALIBRATION: due");
        let t = u256_from_u64(1_000_000_000); // the pool holds 1e9 of the rule's 4.6e9 retire
        assert!(!limbs_ge(&u256_to_limbs16(t), &u256_to_limbs16(c_rule)), "CALIBRATION: the pool cannot cover the rule's retire");
        let (c, s, full_c, full_s, pool_c) = liquidation_amount_regimes_capped(d, m, t, &r).expect("a partial liquidation");
        assert_eq!((c, pool_c, full_c), (t, true, false), "the pool is burned whole");
        assert_eq!(liquidation_amount_capped(d, m, t, &r), Some((c, s)));
        let k = r.mults().unwrap();
        assert_eq!(liquidation_seize_wide(t, k.k1).and_then(|w| limbs_to_u256(&w)), Some(s), "S is the least collateral covering C = T");
        let proof = prove_liquidation_amount_carrier(d, m, t, &b, &r).expect("the partial liquidation proves");
        assert_eq!((proof.c, proof.s), (c, s));
        assert!(verify_liquidation_amount_carrier(&proof.bytes, &proof.commits, &r), "the partial liquidation verifies");
        let full = prove_liquidation_amount_carrier(d, m, LIQ_POOL_UNBOUNDED, &b, &r).unwrap();
        assert_eq!(proof.bytes.len(), full.bytes.len(), "one carrier size: the verifier cannot tell a partial liquidation");
        let refused = |label: &str, laid: Option<(Vec<Vec<Fa4>>, [Digest; 5])>| match laid {
            None => eprintln!("[liq-cap] {label} → no witness"),
            Some((cols, commits)) => {
                let (ok, door) = liq_verdict(cols, &commits, &r);
                assert!(!ok, "⛔ {label} must be refused");
                eprintln!("[liq-cap] {label} → refused by {door}");
            }
        };
        let (_, s_rule) = liquidation_amount(d, m, &r).unwrap();
        refused("the rule's full C against a small pool", liquidation_amount_trace(d, m, t, c_rule, s_rule, &b, &r, false, false, false));
        let t1 = sub256(t, u256_from_u64(1)).unwrap();
        refused("C = T − 1", liquidation_amount_trace(d, m, t, t1, s, &b, &r, false, full_s, true));
        refused("the uncapped regime claimed at C = T", liquidation_amount_trace(d, m, t, c, s, &b, &r, false, full_s, false));
        let mut cm = proof.commits;
        cm[4][0] ^= 1;
        assert!(!verify_liquidation_amount_carrier(&proof.bytes, &cm, &r), "⛔ the pool commitment edited verified");
        assert!(liquidation_amount_capped(d, m, [0; 4], &r).is_none(), "an empty pool has no liquidation");
        assert!(prove_liquidation_amount_carrier(d, m, [0; 4], &b, &r).is_none(), "an empty pool proves nothing");
    }

    // ── the delta-bound TRANSITION carrier (the bonded-stake total, the Stability Pool) ──
    /// ⭐⭐⭐ RED FIRST. `a + delta = s` over THREE openings: an honest deposit proves and verifies under its domain.
    /// Refused: the same bytes under the other domain; each commitment edited; a delta commitment of ANOTHER amount (the
    /// whole point — the shape it replaces could not tell, see the calibration pin); a reduction read as a deposit; no
    /// bytes; a 256-bit overflow lays no witness.
    ///
    /// TWO-PARTY-REVIEWED: the PROVER holds the two totals' openings and the delta's; the VERIFIER is every node, handed
    /// the bytes and three commitments — the production boundary of `verify_transition_carrier`.
    #[test]
    fn transition_carrier_binds_the_delta_and_the_domain() {
        use crate::poseidon2_compress::lanes_of;
        let b = [lanes_of(&[41]), lanes_of(&[42]), lanes_of(&[43])];
        let (a, delta) = (u256_from_u64(5_000), u256_from_u64(3_000));
        for domain in [TransitionDomain::Bond, TransitionDomain::StabilityPool] {
            let (bytes, cm) = prove_transition_carrier(a, delta, &b, domain).expect("the honest transition proves");
            assert_eq!(cm, [solvency_commit_256(a, b[0]), solvency_commit_256(delta, b[1]), solvency_commit_256(u256_from_u64(8_000), b[2])]);
            assert!(verify_transition_carrier(&bytes, &cm, domain), "{domain:?}: the honest transition verifies");
            eprintln!("[transition] {domain:?}: carrier {} B over {} columns", bytes.len(), TR_WIDTH);
            let other = if domain == TransitionDomain::Bond { TransitionDomain::StabilityPool } else { TransitionDomain::Bond };
            assert!(!verify_transition_carrier(&bytes, &cm, other), "{domain:?}: the other domain refuses");
            for (i, label) in ["a", "delta", "s"].iter().enumerate() { // PRODUCTION-SCALE-REVIEWED: the three commitments of one transition, not a cover count
                let mut cm2 = cm;
                cm2[i][0] ^= 1;
                assert!(!verify_transition_carrier(&bytes, &cm2, domain), "{domain:?}: the {label} commitment edited refuses");
            }
            let mut cm3 = cm;
            cm3[1] = solvency_commit_256(u256_from_u64(3_001), b[1]);
            assert!(!verify_transition_carrier(&bytes, &cm3, domain), "{domain:?}: a delta commitment of another amount refuses");
            let swapped = [cm[2], cm[1], cm[0]];
            assert!(!verify_transition_carrier(&bytes, &swapped, domain), "{domain:?}: a reduction read as a deposit refuses");
            assert!(!verify_transition_carrier(&[], &cm, domain), "no bytes, no proof");
        }
        assert!(prove_transition_carrier([u64::MAX; 4], u256_from_u64(1), &b, TransitionDomain::Bond).is_none(), "a 256-bit overflow lays no witness");
    }

    /// ⛔ CALIBRATION — the hole the transition carrier closes, MEASURED on the shape it replaces: `PinnedBondAir`'s
    /// delta (`BR_DEP`) is a free witness, so `a + delta = s` is satisfiable for ANY two opened totals (`b_i := s_i − a_i`
    /// in the field, carries 0). A bond "admit" from 5,000 to 1,000,000,000 with no bond behind it PROVES AND VERIFIES
    /// on the old carrier; the delta-bound carrier has no witness for a 3,000 bond over the same totals. Deleted with
    /// `prove_bond_transition_carrier` once `validator.rs` moves to `verify_transition_carrier`.
    #[test]
    #[allow(deprecated)]
    fn calibration_the_unbound_delta_bond_carrier_accepts_any_pair_of_totals() {
        use crate::poseidon2_compress::lanes_of;
        let (a, s) = (u256_from_u64(5_000), u256_from_u64(1_000_000_000));
        let (ab, sb) = (lanes_of(&[51]), lanes_of(&[52]));
        let (al, sl) = (u256_to_limbs16(a), u256_to_limbs16(s));
        let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; 2]; BR_WIDTH];
        for i in 0..N_LIMB16 {
            cols[BR_RES + i].fill(Fa4::from_u64(al[i]));
            cols[BR_NEW + i].fill(Fa4::from_u64(sl[i]));
            cols[BR_DEP + i].fill(Fa4::from_u64(sl[i]) - Fa4::from_u64(al[i])); // the "delta" no integer is: a field difference
        }
        fill_cols(&mut cols, BR_RBLIND, &ab);
        fill_cols(&mut cols, BR_NBLIND, &sb);
        let ac = place_commit_open(&mut cols, al, ab, BR_RINTER, BR_RVBITS);
        let sc = place_commit_open(&mut cols, sl, sb, BR_NINTER, BR_NVBITS);
        fill_cols(&mut cols, BR_RCOMMIT, &ac);
        fill_cols(&mut cols, BR_NCOMMIT, &sc);
        let cols = replicate_rows(cols, 1 << REC_DECIDER_FOLDING);
        let bind = bond_statement_bind(ac, sc);
        let make = |g: Ea4| PinnedBondAir { gamma: g, a_commit: commit_to_ea4(ac), s_commit: commit_to_ea4(sc) };
        let bytes = prove_value_carrier(cols, make, &bind).expect("the forged admit proves on the old shape");
        assert!(verify_bond_transition_carrier(&bytes, ac, sc), "MEASURED: the old bond carrier accepts an admit of 999,995,000 with no bond behind it");
        // the delta-bound carrier: the only delta that conserves is 999,995,000, and a commitment to 3,000 opens to nothing else
        let db = lanes_of(&[53]);
        let (bytes2, cm) = prove_transition_carrier(a, u256_from_u64(999_995_000), &[ab, db, sb], TransitionDomain::Bond).unwrap();
        let mut claimed = cm;
        claimed[1] = solvency_commit_256(u256_from_u64(3_000), db);
        assert!(!verify_transition_carrier(&bytes2, &claimed, TransitionDomain::Bond), "the delta-bound carrier refuses a 3,000 bond claim over the same totals");
    }

    /// DB-452 — the adversary and the privacy census for the ENGINE every value carrier rides (the blinded committed
    /// door since link 77; on the direct light decider, link 77's RED run: forged accepted, every limb sent).
    fn forge_value_carrier_for_tests<C: AirConstraint + Sync, Mk: Fn(Ea4) -> C>(
        cols: Vec<Vec<Fa4>>,
        make: Mk,
        bind: &[Fa4],
    ) -> Option<Vec<u8>> {
        crate::committed_air::forge_blinded_opened_for_tests(cols, make, bind)
    }
    fn value_carrier_sent_evaluations(bytes: &[u8]) -> Vec<Ea4> {
        crate::committed_air::committed_sent_evaluations_for_tests(bytes)
    }

    /// ⛔⛔⛔ DB-452 (the direct family) — a transition carrier for totals NO trace conserves is REFUSED. The adversary
    /// holds a real trace for `5,000 + 1,000 = 6,000` and states `s = 1,006,000` (a million of hidden total from nothing):
    /// the honest engine's setup, all-zero zerocheck rounds, and ONE sent row the inflated statement's gate accepts.
    #[test]
    fn db452_c_a_transition_carrier_for_totals_no_trace_conserves_is_refused() {
        use crate::poseidon2_compress::lanes_of;
        let (a, d) = (u256_from_u64(5_000), u256_from_u64(1_000));
        let blinds = [lanes_of(&[61]), lanes_of(&[62]), lanes_of(&[63])];
        let domain = TransitionDomain::Bond;
        let (honest, cm_a) = prove_transition_carrier(a, d, &blinds, domain).expect("honest transition");
        let mut cm_b = cm_a;
        cm_b[2] = solvency_commit_256(u256_from_u64(1_006_000), blinds[2]);
        assert!(verify_transition_carrier(&honest, &cm_a, domain), "CONTROL: the honest carrier verifies its own totals");
        assert!(!verify_transition_carrier(&honest, &cm_b, domain), "CONTROL: the honest carrier refuses the inflated totals");
        let (cols2, _) = transition_trace(a, d, &blinds).expect("trace");
        let cols = replicate_rows(cols2, 1 << REC_DECIDER_FOLDING);
        let forged =
            forge_value_carrier_for_tests(cols, transition_air(&cm_b), &transition_statement_bind(&cm_b, domain))
                .expect("the forger finds a row the inflated statement's gate accepts");
        let accepted = verify_transition_carrier(&forged, &cm_b, domain);
        eprintln!(
            "[db452-c] honest carrier {} B; forged transition for s = 1,006,000 over a 5,000 + 1,000 trace ({} B): accepted = {accepted}",
            honest.len(),
            forged.len()
        );
        assert!(!accepted, "DB-452: a transition whose sent row no committed trace holds must be refused (inflation)");
    }

    /// ⛔⛔⛔ DB-452 (the direct family, privacy) — a value carrier SENDS no amount and no blind. Every production value
    /// carrier lays ONE logical row as constant columns, and the multilinear extension of a constant column is that
    /// constant at every point: an evaluation sent in the clear IS the secret (the §BE-1 shape, measured 2026-09-14 on
    /// the spend carriers). The census reads every evaluation the carrier sends and counts those equal to a 16-bit limb
    /// of `a`, `delta`, `s` or a lane of a blind.
    #[test]
    fn db452_d_a_value_carrier_sends_no_amount_in_the_clear() {
        use crate::poseidon2_compress::lanes_of;
        let (a, d) = (u256_from_u64(0x0123_4567_89AB), u256_from_u64(0x0F0E_0D0C));
        let blinds = [lanes_of(&[0x5151_5151]), lanes_of(&[0x5252_5252]), lanes_of(&[0x5353_5353])];
        let domain = TransitionDomain::Bond;
        let (bytes, cm) = prove_transition_carrier(a, d, &blinds, domain).expect("prove");
        assert!(verify_transition_carrier(&bytes, &cm, domain), "CONTROL: the carrier verifies");
        let s = add256(a, d).expect("no overflow");
        let mut secrets: Vec<Ea4> = Vec::new();
        for v in [a, d, s] {
            secrets.extend(u256_to_limbs16(v).iter().filter(|&&l| l > 1).map(|&l| Ea4::from(Fa4::from_u64(l))));
        }
        for b in &blinds {
            secrets.extend(b.iter().filter(|&&l| l > 1).map(|&l| Ea4::from(Fa4::from_u64(l))));
        }
        let sent = value_carrier_sent_evaluations(&bytes);
        let hits = sent.iter().filter(|e| secrets.contains(e)).count();
        eprintln!(
            "[db452-d] carrier {} B: {} evaluations sent, {} secret limbs/lanes, {hits} sent evaluations ARE a secret",
            bytes.len(),
            sent.len(),
            secrets.len()
        );
        assert!(!sent.is_empty(), "the census reads the carrier's evaluations");
        assert_eq!(hits, 0, "DB-452: a value carrier must send no amount limb and no blind lane in the clear");
    }

    // ── #75 brick 2b-ii: IN-CIRCUIT compare X≥Y (backing/solvency), limb-wise ──
    #[test]
    fn in_circuit_ge_honest_backing_verifies() {
        // exactly-150% backing: deposit·10000 == mint·ratio → X ≥ Y (equal).
        let x = scale_native(u256_from_u64(1_500), 10_000);
        let y = scale_native(u256_from_u64(1_000), R as u64);
        let proof = prove_ge(x, y, &mut mk_ch()).expect("X≥Y proves");
        assert!(verify_ge(&proof, &mut mk_ch()), "honest backing X≥Y VERIFIES");
        // strictly over-collateralized (deposit 2_000) also verifies
        let x2 = scale_native(u256_from_u64(2_000), 10_000);
        assert!(verify_ge(&prove_ge(x2, y, &mut mk_ch()).unwrap(), &mut mk_ch()), "over-collateralized VERIFIES");
    }

    // ADVERSARIAL: an under-collateralized (over-mint) backing has X < Y — NO `X ≥ Y` proof exists (fail-closed).
    #[test]
    fn in_circuit_ge_under_collateralized_unprovable() {
        let x = scale_native(u256_from_u64(1_500), 10_000); // 15_000_000
        let y = scale_native(u256_from_u64(1_001), R as u64); // 15_015_000 > X
        assert!(prove_ge(x, y, &mut mk_ch()).is_none(), "X<Y (under-collateralized) is UNPROVABLE");
    }

    // ADVERSARIAL: inflating a slack limb (to fake `X ≥ Y`) without fixing its bits breaks the range-bind → reject.
    #[test]
    fn in_circuit_ge_forged_slack_rejects() {
        let x = scale_native(u256_from_u64(2_000), 10_000);
        let y = scale_native(u256_from_u64(1_000), R as u64);
        let mut cols = ge_trace(x, y).unwrap();
        cols[G_SLACK][0] += Fa4::ONE;
        cols[G_SLACK][1] += Fa4::ONE;
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = CompareGeLimbAir { gamma };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let proof = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = CompareGeLimbAir { gamma: gv };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        assert!(!verify_air_zerocheck(&proof, &airv, &zv, &mut vch), "a forged slack limb MUST reject");
    }

    // ── #75 brick 2b-ii-c: the COMPOSED confidential solvency transition (8 sub-proofs, one transcript) ──
    #[test]
    fn in_circuit_full_transition_verifies() {
        // 150%-collateralized peg-in: reserve 1500 / minted 1000; a deposit of 1500 mints 1000 more.
        let (r, m, d, mi) = (u256_from_u64(1_500), u256_from_u64(1_000), u256_from_u64(1_500), u256_from_u64(1_000));
        let proof = prove_solvency_transition(r, m, d, mi, R, &mut mk_ch()).expect("honest transition proves");
        assert!(verify_solvency_transition(&proof, R, &mut mk_ch()), "the full confidential solvency transition VERIFIES");
    }

    // ADVERSARIAL: a tamper in ANY sub-proof (here the backing round-poly) fails the WHOLE transition.
    #[test]
    fn in_circuit_full_transition_tamper_rejects() {
        let (r, m, d, mi) = (u256_from_u64(1_500), u256_from_u64(1_000), u256_from_u64(1_500), u256_from_u64(1_000));
        let proof = prove_solvency_transition(r, m, d, mi, R, &mut mk_ch()).unwrap();
        let mut bad = proof.clone();
        bad.backing.round_evals[0][0] += Ea4::ONE;
        assert!(!verify_solvency_transition(&bad, R, &mut mk_ch()), "a tampered sub-proof MUST fail the whole transition");
    }

    // ADVERSARIAL: an under-collateralized (over-mint) transition is UNPROVABLE end-to-end — the backing
    // compare has no `X ≥ Y` proof, so the whole transition can't be built (fail-closed, no inflation path).
    #[test]
    fn in_circuit_full_transition_over_mint_unprovable() {
        let (r, m, d, mi) = (u256_from_u64(1_500), u256_from_u64(1_000), u256_from_u64(1_500), u256_from_u64(1_001));
        assert!(prove_solvency_transition(r, m, d, mi, R, &mut mk_ch()).is_none(), "over-mint transition is UNPROVABLE");
    }

    // The SEEDED entry (what the node calls): prove with a seed, verify with the same seed; a tamper rejects.
    #[test]
    fn seeded_transition_roundtrips_and_tamper_rejects() {
        let (r, m, d, mi) = (u256_from_u64(1_500), u256_from_u64(1_000), u256_from_u64(1_500), u256_from_u64(1_000));
        let seed = 0x00C0_FFEE_u64;
        let proof = prove_solvency_transition_seeded(r, m, d, mi, R, seed).expect("seeded prove");
        assert!(verify_solvency_transition_seeded(&proof, R, seed), "seeded roundtrip (the node's entry) VERIFIES");
        let mut bad = proof.clone();
        bad.solvency.round_evals[0][0] += Ea4::ONE;
        assert!(!verify_solvency_transition_seeded(&bad, R, seed), "a tampered seeded transition REJECTS");
    }

    // The 256-bit committed state the peg persists: hides the total (fresh blind ⇒ different digest) and binds
    // it (a 1-unit change ANYWHERE across the 256 bits ⇒ a different commitment). This is `reserve_commit`/
    // `minted_commit`; the in-circuit opening (brick 3b) proves the transition's value folds to exactly this.
    #[test]
    fn commit256_hides_and_binds_at_full_width() {
        let v: U256 = [0x1234_5678_9ABC_DEF0, 0xFEDC, 0, 42];
        // hiding: same value, different blind → different commitment
        assert_ne!(solvency_commit_256(v, crate::poseidon2_compress::lanes_of(&[1, 0, 0, 0])), solvency_commit_256(v, crate::poseidon2_compress::lanes_of(&[2, 0, 0, 0])));
        // binding: a change in the 2^128 limb (far past u64) → different commitment
        let mut v2 = v;
        v2[2] += 1;
        assert_ne!(solvency_commit_256(v, crate::poseidon2_compress::lanes_of(&[7, 0, 0, 0])), solvency_commit_256(v2, crate::poseidon2_compress::lanes_of(&[7, 0, 0, 0])));
        assert_eq!(solvency_commit_256(v, crate::poseidon2_compress::lanes_of(&[7, 0, 0, 0])).len(), DIGEST_LANES, "fixed-size digest, no shape leak");
    }

    // #75 brick 3b: the in-circuit COMMIT-OPENING binding — proves a value folds to `solvency_commit_256`, so a
    // transition proven over hidden totals is provably ABOUT the persisted commitments. Native parity + honest
    // opening VERIFIES + opening a DIFFERENT value to the same commitment REJECTS.
    #[test]
    fn commit_open_binds_value_to_commitment() {
        let value: U256 = [0xAABB_CCDD_1122_3344, 77, 5, 9];
        let blind = crate::poseidon2_compress::lanes_of(&[0x1357u64, 0x2468, 0, 0]);
        // native parity: the in-circuit fold's digest == solvency_commit_256 exactly
        let l = u256_to_limbs16(value);
        let lo: Digest = core::array::from_fn(|i| l[i]);
        let hi: Digest = core::array::from_fn(|i| l[DIGEST_LANES + i]);
        assert_eq!(
            poseidon_pair(poseidon_pair(lo, hi), blind),
            solvency_commit_256(value, blind),
            "in-circuit fold == commit"
        );
        // honest opening VERIFIES
        let proof = prove_commit_open(value, blind, &mut mk_ch());
        assert!(verify_commit_open(&proof, &mut mk_ch()), "honest value→commitment opening VERIFIES");
        // ADVERSARIAL: claim a DIFFERENT value (bump limb 0) without redoing the fold → block relations break → REJECT
        let mut cols = commit_open_trace(value, blind);
        cols[CO_V][0] += Fa4::ONE;
        cols[CO_V][1] += Fa4::ONE;
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = CommitOpenAir { gamma };
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let bad = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        let mut vch = mk_ch();
        let gv: Ea4 = vch.sample_algebra_element();
        let airv = CommitOpenAir { gamma: gv };
        let zv: Vec<Ea4> = (0..1).map(|_| vch.sample_algebra_element()).collect();
        assert!(!verify_air_zerocheck(&bad, &airv, &zv, &mut vch), "opening a DIFFERENT value to the same commit MUST reject");
    }

    // ── brick 3b's three `bound_reserve_*` pins DELETED 2026-09-29 with the shape they pinned: its "broken
    //    conservation rejects" pin only ever caught a forgery that also broke the opening — with `BR_DEP` free, a
    //    consistent forgery (any two opened totals) verified, as the calibration pin on the bond carrier measures. The
    //    delta-bound transition carrier's pins are the conservation pins now.

    // ── brick 3c: the FULL bound transition — conservation + 4 openings + 150% backing, ONE shared trace ──

    // A well-collateralized peg-in at 256-bit scale (reserve ≈ 2× minted, so ≥150% before AND after).
    fn honest_peg_in() -> (U256, U256, U256, U256, Digest, Digest, Digest, Digest) {
        let reserve: U256 = [2_000_000, 0, 0, 0];
        let minted: U256 = [1_000_000, 0, 0, 0];
        let deposit: U256 = [600_000, 0, 0, 0]; // +600k reserve
        let mint_delta: U256 = [400_000, 0, 0, 0]; // +400k minted → new 2.6M reserve vs 1.4M minted ≥150%
        (reserve, minted, deposit, mint_delta, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), crate::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), crate::poseidon2_compress::lanes_of(&[13, 14, 15, 16]))
    }

    #[test]
    fn bound_transition_verifies_and_returns_persisted_commitments() {
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (proof, c) = prove_bound_transition(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64)), &mut mk_ch()).expect("honest peg-in proves");
        // the returned commitments are exactly the peg's persisted state, old (inputs) and new (outputs)
        assert_eq!(c.reserve_commit, solvency_commit_256(r, rb));
        assert_eq!(c.minted_commit, solvency_commit_256(m, mb));
        assert_eq!(c.new_reserve_commit, solvency_commit_256(add256(r, d).unwrap(), nrb));
        assert_eq!(c.new_minted_commit, solvency_commit_256(add256(m, md).unwrap(), nmb));
        assert!(verify_bound_transition(&proof, Backing::at_unit_price(u64::from(R as u64)), &mut mk_ch()), "honest full transition VERIFIES");
    }

    #[test]
    fn bound_transition_under_collateralized_is_unprovable() {
        // mint MORE than 150% backing allows: reserve 2M, minted 1M, deposit 0, mint +1M → new 2M vs 2M < 150%.
        let reserve: U256 = [2_000_000, 0, 0, 0];
        let minted: U256 = [1_000_000, 0, 0, 0];
        let deposit: U256 = [0, 0, 0, 0];
        let mint_delta: U256 = [1_000_000, 0, 0, 0];
        let none = prove_bound_transition(reserve, minted, deposit, mint_delta, crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), crate::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), crate::poseidon2_compress::lanes_of(&[13, 14, 15, 16]), Backing::at_unit_price(u64::from(R as u64)), &mut mk_ch());
        assert!(none.is_none(), "an under-collateralized (<150%) new state is UNPROVABLE — no proof can exist");
    }

    #[test]
    fn bound_transition_tampered_value_rejects() {
        // Forge new_reserve post-hoc (claim more reserve than committed). new_reserve is shared across conservation,
        // its opening, AND the backing scale — every one of them fails-closed. This is the whole point of the
        // combined trace: no single value can satisfy backing while opening to a different commitment.
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (mut cols, _c) = bound_transition_trace(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64)), TransitionGate::Aggregate).unwrap();
        cols[T_NEWRES][0] += Fa4::from_u64(1_000_000);
        cols[T_NEWRES][1] += Fa4::from_u64(1_000_000);
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = BoundTransitionAir { gamma, ratio_bps: Backing::at_unit_price(u64::from(R as u64))};
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let bad = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        assert!(!verify_bound_transition(&bad, Backing::at_unit_price(u64::from(R as u64)), &mut mk_ch()), "a new_reserve not opening to its commitment MUST reject");
    }

    #[test]
    fn bound_transition_hidden_issuance_rejects() {
        // new_minted inflated by 1 without a matching mint delta → the minted conservation limb breaks.
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (mut cols, _c) = bound_transition_trace(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64)), TransitionGate::Aggregate).unwrap();
        cols[T_NEWMINT][0] += Fa4::ONE;
        cols[T_NEWMINT][1] += Fa4::ONE;
        let mut pch = mk_ch();
        let gamma: Ea4 = pch.sample_algebra_element();
        let air = BoundTransitionAir { gamma, ratio_bps: Backing::at_unit_price(u64::from(R as u64))};
        let z: Vec<Ea4> = (0..1).map(|_| pch.sample_algebra_element()).collect();
        let bad = prove_air_zerocheck(&cols, &air, &z, &mut pch);
        assert!(!verify_bound_transition(&bad, Backing::at_unit_price(u64::from(R as u64)), &mut mk_ch()), "new_minted != minted + delta (hidden issuance) MUST reject");
    }

    #[test]
    fn bound_transition_seeded_roundtrips_and_wrong_seed_rejects() {
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let seed = 0xC0FFEE_u64;
        let (proof, _c) = prove_bound_transition_seeded(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64)), seed).expect("seeded proves");
        assert!(verify_bound_transition_seeded(&proof, Backing::at_unit_price(u64::from(R as u64)), seed), "same committed-state seed verifies");
        assert!(!verify_bound_transition_seeded(&proof, Backing::at_unit_price(u64::from(R as u64)), seed ^ 1), "a proof bound to a different committed state is rejected");
    }

    // ── brick 3d: the WHIR-BOUND carrier — openings cryptographically bound, commitments consensus-known ──

    #[test]
    fn peg_in_carrier_verifies_against_the_persisted_commitments() {
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (bytes, c) = prove_peg_in_carrier(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64))).expect("carrier proves");
        // the node verifies with ITS persisted OLD commitments + the block's claimed NEW commitments
        assert!(
            verify_peg_in_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit),
            "honest peg-in carrier VERIFIES against the persisted + claimed commitments"
        );
    }

    #[test]
    fn peg_in_carrier_wrong_old_commitment_rejects() {
        // The node's persisted OLD reserve_commit differs from what the prover used → the proof is not about
        // the node's state. Both the commitment-pin AND the transcript statement bind diverge → reject.
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (bytes, c) = prove_peg_in_carrier(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64))).unwrap();
        let mut wrong_old = c.reserve_commit;
        wrong_old[0] ^= 1;
        assert!(
            !verify_peg_in_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), wrong_old, c.minted_commit, c.new_reserve_commit, c.new_minted_commit),
            "a peg-in proof for a DIFFERENT old reserve commitment MUST reject"
        );
    }

    #[test]
    fn peg_in_carrier_wrong_new_commitment_rejects() {
        // A prover claims a NEW minted commitment that isn't what the trace actually produces (e.g. trying to
        // advance the persisted state to a digest of a hidden over-mint) → reject.
        let (r, m, d, md, rb, mb, nrb, nmb) = honest_peg_in();
        let (bytes, c) = prove_peg_in_carrier(r, m, d, md, rb, mb, nrb, nmb, Backing::at_unit_price(u64::from(R as u64))).unwrap();
        let mut wrong_new = c.new_minted_commit;
        wrong_new[0] ^= 1;
        assert!(
            !verify_peg_in_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), c.reserve_commit, c.minted_commit, c.new_reserve_commit, wrong_new),
            "a peg-in proof whose claimed new minted commitment is tampered MUST reject"
        );
    }

    // ── brick 3e: the confidential PEG-OUT (redeem/burn) carrier — reduction + post-state ≥150% backing ──

    #[test]
    fn peg_out_carrier_verifies_and_binds_to_the_commitments() {
        // current state 3000/2000 (exactly 150%). Redeem: release 300 reserve, burn 200 USDm → post 2700/1800
        // (2700·10000 = 27M ≥ 1800·15000 = 27M, still ≥150%).
        let (r_blind, m_blind, nr_blind, nm_blind) = (crate::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]), crate::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]), crate::poseidon2_compress::lanes_of(&[9u64, 10, 11, 12]), crate::poseidon2_compress::lanes_of(&[13u64, 14, 15, 16]));
        let (bytes, c) = prove_peg_out_carrier(u256_from_u64(3_000), u256_from_u64(2_000), u256_from_u64(300), u256_from_u64(200), r_blind, m_blind, nr_blind, nm_blind, Backing::at_unit_price(u64::from(R as u64)))
            .expect("honest redeem proves");
        assert_eq!(c.reserve_commit, solvency_commit_256(u256_from_u64(3_000), r_blind), "current reserve commit");
        assert_eq!(c.new_minted_commit, solvency_commit_256(u256_from_u64(1_800), nm_blind), "post minted commit");
        assert!(
            verify_peg_out_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), c.reserve_commit, c.minted_commit, c.new_reserve_commit, c.new_minted_commit),
            "honest peg-out VERIFIES against the current + post commitments"
        );
    }

    #[test]
    fn peg_out_carrier_reserve_drain_is_unprovable() {
        // an over-release drain: release 1500 reserve but burn only 100 USDm → post 1500/1900
        // (1500·10000 = 15M < 1900·15000 = 28.5M ⇒ post < 150%). No proof can exist — fail-closed.
        let none = prove_peg_out_carrier(u256_from_u64(3_000), u256_from_u64(2_000), u256_from_u64(1_500), u256_from_u64(100), crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), crate::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), crate::poseidon2_compress::lanes_of(&[13, 14, 15, 16]), Backing::at_unit_price(u64::from(R as u64)));
        assert!(none.is_none(), "a reserve-draining redeem (post < 150%) is UNPROVABLE");
    }

    #[test]
    fn peg_out_carrier_wrong_commitment_rejects() {
        let (bytes, c) = prove_peg_out_carrier(u256_from_u64(3_000), u256_from_u64(2_000), u256_from_u64(300), u256_from_u64(200), crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4]), crate::poseidon2_compress::lanes_of(&[5, 6, 7, 8]), crate::poseidon2_compress::lanes_of(&[9, 10, 11, 12]), crate::poseidon2_compress::lanes_of(&[13, 14, 15, 16]), Backing::at_unit_price(u64::from(R as u64))).unwrap();
        let mut wrong = c.new_reserve_commit;
        wrong[0] ^= 1;
        assert!(
            !verify_peg_out_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), c.reserve_commit, c.minted_commit, wrong, c.new_minted_commit),
            "a tampered post reserve commitment REJECTS"
        );
    }

    // ── brick 4: the confidential VALIDATOR-BOND accumulator — conservation over committed stake totals ──

    #[test]
    fn bond_admit_carrier_verifies_and_binds_to_the_bond_commitments() {
        // admit: bonded total 5000 + a new 3000 bond = 8000, all over committed (hidden) stake totals.
        let (old_total, bond) = (u256_from_u64(5_000), u256_from_u64(3_000));
        let (old_blind, new_blind) = (crate::poseidon2_compress::lanes_of(&[2u64, 4, 6, 8]), crate::poseidon2_compress::lanes_of(&[1u64, 3, 5, 7]));
        let (bytes, ac, sc) = prove_bond_transition_carrier(old_total, bond, old_blind, new_blind).expect("bond admit proves");
        assert_eq!(ac, solvency_commit_256(old_total, old_blind), "a_commit == committed OLD bonded total");
        assert_eq!(sc, solvency_commit_256(add256(old_total, bond).unwrap(), new_blind), "s_commit == committed NEW bonded total");
        assert!(verify_bond_transition_carrier(&bytes, ac, sc), "honest bond admit VERIFIES against the committed totals");
    }

    #[test]
    fn bond_transition_wrong_commitment_rejects() {
        // A proof for one (a,s) pair must not verify against a different committed total (slash/unbond can't be
        // forged to a stake total the prover didn't actually conserve to).
        let (old_total, bond) = (u256_from_u64(5_000), u256_from_u64(3_000));
        let (bytes, ac, sc) = prove_bond_transition_carrier(old_total, bond, crate::poseidon2_compress::lanes_of(&[2, 4, 6, 8]), crate::poseidon2_compress::lanes_of(&[1, 3, 5, 7])).unwrap();
        let mut wrong_s = sc;
        wrong_s[0] ^= 1;
        assert!(!verify_bond_transition_carrier(&bytes, ac, wrong_s), "a tampered new bonded-total commitment REJECTS");
        let mut wrong_a = ac;
        wrong_a[0] ^= 1;
        assert!(!verify_bond_transition_carrier(&bytes, wrong_a, sc), "a tampered old bonded-total commitment REJECTS");
    }

    #[test]
    fn bond_reduce_is_the_same_carrier_read_backwards() {
        // unbond/slash: new_total 5000, the removed bond 3000, so old_total 8000 == 5000 + 3000. The SAME carrier
        // (a=new smaller total, s=old larger total) proves the reduction — the node just pins (new, old).
        let (new_total, bond) = (u256_from_u64(5_000), u256_from_u64(3_000));
        let (a_blind, s_blind) = (crate::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]), crate::poseidon2_compress::lanes_of(&[4u64, 4, 4, 4]));
        let (bytes, ac, sc) = prove_bond_transition_carrier(new_total, bond, a_blind, s_blind).expect("bond reduce proves");
        assert_eq!(sc, solvency_commit_256(u256_from_u64(8_000), s_blind), "s_commit == committed OLD (larger) total");
        assert!(verify_bond_transition_carrier(&bytes, ac, sc), "the reduction VERIFIES: new + bond == old");
    }

    // ── DB-237: the yield SUPPLY carrier — the committed reward minted into the committed supply, backing-gated ──

    // reserve 10000 collateralizes 5000 minted (200% — surplus exists). A reward of 100 (the stake carrier's exact rule)
    // → new_minted 5100 (still ≥150%). All values hidden.
    fn yb() -> [Digest; 4] {
        let l = crate::poseidon2_compress::lanes_of;
        [l(&[1u64, 2, 3, 4]), l(&[5u64, 6, 7, 8]), l(&[9u64, 10, 11, 12]), l(&[13u64, 14, 15, 16])]
    }

    #[test]
    fn yield_supply_verifies_and_binds_to_the_commitments() {
        let [yb, mb, nmb, rb] = yb();
        let (bytes, c) = prove_yield_mint_carrier(u256_from_u64(10_000), u256_from_u64(5_000), u256_from_u64(100), yb, mb, nmb, rb, Backing::at_unit_price(u64::from(R as u64)))
            .expect("an honest supply step proves");
        assert_eq!(c.yield_commit, solvency_commit_256(u256_from_u64(100), yb), "the reward is opened read-only");
        assert_eq!(c.new_minted_commit, solvency_commit_256(u256_from_u64(5_100), nmb), "minted advanced by exactly the reward");
        assert!(verify_yield_mint_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), &c), "the honest supply step VERIFIES against the committed state");
        assert!(!verify_yield_mint_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64 + 1)), &c), "⛔ a proof for one backing ratio verified at another");
    }

    /// ⛔⛔⛔ DB-237 — THE SUPPLY GROWS BY EXACTLY THE COMMITTED REWARD. A supply step proved for one reward verifies under
    /// no other reward commitment, either side of it — so a mint can neither under- nor over-count the reward note.
    #[test]
    fn the_yield_supply_carrier_verifies_only_for_its_own_reward_commitment() {
        let [yb, mb, nmb, rb] = yb();
        let (bytes, c) = prove_yield_mint_carrier(u256_from_u64(10_000), u256_from_u64(5_000), u256_from_u64(100), yb, mb, nmb, rb, Backing::at_unit_price(u64::from(R as u64))).unwrap();
        let v = |y: u64| {
            let t = YieldMintCommits {
                yield_commit: solvency_commit_256(u256_from_u64(y), yb),
                minted_commit: c.minted_commit,
                new_minted_commit: c.new_minted_commit,
                reserve_commit: c.reserve_commit,
            };
            verify_yield_mint_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), &t)
        };
        assert!(v(100), "calibration: the honest reward verifies (the attack below is armed against a live proof)");
        assert!(!v(99), "a mint read as LESS than it proved REJECTS");
        assert!(!v(101), "a mint read as MORE than it proved REJECTS");
        assert!(!v(0), "a zero-reward reading REJECTS");
    }

    /// ⭐⭐⭐ DB-237 — THE CROSS-CARRIER WELD: the stake carrier's public `reward_commit` IS the supply step's `yield_commit`
    /// (the same `solvency_commit_256(r, reward_blind)`), so the reward note the stake gate credits and the supply the
    /// node advances are one value. A supply step for any other reward does not open that commitment.
    #[test]
    fn the_stake_carriers_reward_commitment_is_the_supply_steps_yield_commitment() {
        use crate::whir_rec_block::{prove_stake_carrier_bytes, StakeWitness};
        let l = crate::poseidon2_compress::lanes_of;
        let w = StakeWitness {
            value_in: 600_000_000,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(l(&[0x5747, 1, 2, 3])),
            in_staked: true,
            e0: 1_000,
            lc_blind: l(&[0x5747, 4, 4, 4]),
            out0_value: 600_000_000,
            out0_opening: l(&[0x5747, 5, 5, 5]),
            out0_staked: true,
            out1_opening: l(&[0x5747, 6, 6, 6]),
            reward_blind: l(&[0x5747, 7, 7, 7]),
        };
        let (_stake, o) = prove_stake_carrier_bytes(&w, 1_030, 500).expect("the claim proves");
        assert!(o.reward > 0, "CALIBRATION: a real reward");
        let [_yb, mb, nmb, rb] = yb();
        let (bytes, c) = prove_yield_mint_carrier(
            u256_from_u64(10_000_000_000),
            u256_from_u64(5_000_000_000),
            u256_from_u64(o.reward),
            w.reward_blind,
            mb,
            nmb,
            rb,
            Backing::at_unit_price(u64::from(R as u64)),
        )
        .expect("the supply step proves");
        assert_eq!(c.yield_commit, o.reward_commit, "⛔⛔⛔ the supply step opens another value than the stake gate minted");
        assert!(verify_yield_mint_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), &c));
        let (_b2, c2) = prove_yield_mint_carrier(
            u256_from_u64(10_000_000_000),
            u256_from_u64(5_000_000_000),
            u256_from_u64(o.reward + 1),
            w.reward_blind,
            mb,
            nmb,
            rb,
            Backing::at_unit_price(u64::from(R as u64)),
        )
        .expect("proves for its own value");
        assert_ne!(c2.yield_commit, o.reward_commit, "⛔ a supply step for r + 1 opens the stake carrier's commitment");
    }

    /// ⭐ LIQUIDATION §10.2 increment 3 — a RETIRE leg's transition verifies under its own domain and under no other (so a
    /// retire proof can never pass as a seize, a pool or a yield step, and vice versa).
    #[test]
    fn a_retire_transition_verifies_under_its_own_domain_and_no_other() {
        let [a_b, d_b, s_b, _] = yb();
        let (bytes, commits) =
            prove_transition_carrier(u256_from_u64(4_000), u256_from_u64(1_000), &[a_b, d_b, s_b], TransitionDomain::Retire)
                .expect("the retire leg proves");
        assert!(verify_transition_carrier(&bytes, &commits, TransitionDomain::Retire), "the honest retire leg verifies");
        for other in [TransitionDomain::Seize, TransitionDomain::StabilityPool, TransitionDomain::Yield, TransitionDomain::Bond] {
            assert!(!verify_transition_carrier(&bytes, &commits, other), "⛔ a retire leg verified under {other:?}");
        }
        assert_eq!(commits[2], solvency_commit_256(u256_from_u64(5_000), s_b), "minted = new_minted + C");
    }

    /// ⭐⭐⭐ LIQUIDATION §10.2 increment 3 — THE FIVE LEGS WELD INTO ONE LIQUIDATION. Over one committed state — reserve
    /// `D`, supply `M`, pool `T`, `(P, S)` — the amount carrier's `DC` and `DS` are EXACTLY the deltas the pool transition
    /// (`T − C`), the pool step (`P, S` update), the retire leg (`M − C`) and the seize leg (`D − S`) consume, each leg
    /// verifying under its own domain against the same commitments. A leg proved for another `C` names another `DC`.
    #[test]
    fn the_five_liquidation_legs_weld_into_one_statement() {
        let l = crate::poseidon2_compress::lanes_of;
        // a position under-covered at the mark: D = 1_000 collateral units at p, M = 2_000 USDm
        let rule = LiqRule { p: 1_500_000, delta_bps: 1_000, rho_target_bps: 15_000, rho_liq_bps: 12_000 };
        let (d, m) = (u256_from_u64(1_000), u256_from_u64(2_000));
        let Some((c, s)) = liquidation_amount(d, m, &rule) else {
            panic!("CALIBRATION: the position is due at this mark");
        };
        let (rb, mb, cb, sb) = (l(&[0x11, 1, 1, 1]), l(&[0x12, 2, 2, 2]), l(&[0x13, 3, 3, 3]), l(&[0x14, 4, 4, 4]));
        // the pool holds enough: T = 5_000 USDm, P = 2^128, S = 0
        let t = u256_from_u64(5_000);
        let (tb, pb, s0b) = (l(&[0x21, 1, 1, 1]), l(&[0x22, 2, 2, 2]), l(&[0x23, 3, 3, 3]));
        let amt = prove_liquidation_amount_carrier(d, m, t, &[rb, mb, cb, sb, tb], &rule).expect("the amount carrier proves");
        assert!(verify_liquidation_amount_carrier(&amt.bytes, &amt.commits, &rule), "the amount verifies");
        assert_eq!((amt.c, amt.s), (c, s), "the carrier's amounts are the rule's");
        let [dd, dm, dc, ds, dt] = amt.commits;
        let (t_new_b, p_new_b, s_new_b) = (l(&[0x24, 4, 4, 4]), l(&[0x25, 5, 5, 5]), l(&[0x26, 6, 6, 6]));
        let left = sub256(t, c).expect("the pool covers C");
        // (1) the pool transition T − C, delta DC
        let (pt, ptc) = prove_transition_carrier(left, c, &[t_new_b, cb, tb], TransitionDomain::StabilityPool).expect("pool leg");
        assert_eq!(ptc[1], dc, "⛔ the pool transition burns another C than the amount carrier proved");
        assert_eq!(ptc[2], dt, "⛔ the amount was capped by another pool than the one the transition moves");
        assert!(verify_transition_carrier(&pt, &ptc, TransitionDomain::StabilityPool));
        // (2) the pool step over (T, C, S, P_old, P_new, S_old, S_new)
        let step = prove_pool_step_carrier(&PoolStepOpening {
            t,
            c,
            s_c: s,
            p_old: [0, 0, 1, 0],
            s_old: [0; 4],
            blinds: [tb, cb, sb, pb, p_new_b, s0b, s_new_b],
        })
        .expect("the pool step proves");
        assert_eq!((step.commits[1], step.commits[2]), (dc, ds), "⛔ the pool step consumes other amounts");
        assert_eq!(step.commits[0], ptc[2], "the pool step reads the same T the transition moved");
        assert!(verify_pool_step_carrier(&step.bytes, &step.commits, step.close));
        // (3) the retire leg M − C and (4) the seize leg D − S
        let (rt, rtc) = prove_transition_carrier(sub256(m, c).expect("C ≤ M"), c, &[l(&[0x31, 1, 1, 1]), cb, mb], TransitionDomain::Retire)
            .expect("retire leg");
        assert_eq!((rtc[1], rtc[2]), (dc, dm), "⛔ the retire leg retires another C or from another supply");
        assert!(verify_transition_carrier(&rt, &rtc, TransitionDomain::Retire));
        let (sz, szc) = prove_transition_carrier(sub256(d, s).expect("S ≤ D"), s, &[l(&[0x32, 2, 2, 2]), sb, rb], TransitionDomain::Seize)
            .expect("seize leg");
        assert_eq!((szc[1], szc[2]), (ds, dd), "⛔ the seize leg seizes another S or from another reserve");
        assert!(verify_transition_carrier(&sz, &szc, TransitionDomain::Seize));
        // a retire leg proved for C − 1 (at this mark C = M: the full retire) names another DC
        let c1 = sub256(c, u256_from_u64(1)).expect("C ≥ 1");
        let (_x, xc) = prove_transition_carrier(sub256(m, c1).expect("C−1 ≤ M"), c1, &[l(&[0x33, 3, 3, 3]), cb, mb], TransitionDomain::Retire)
            .expect("proves for its own value");
        assert_ne!(xc[1], dc, "⛔ a retire of C − 1 welded to the amount carrier's C");
    }

    #[test]
    fn yield_exceeding_reserve_collateralization_is_unprovable() {
        // reserve 7600 collateralizes 5000 minted (152%). Minting 5000 → new_minted 10000 needs 15000 backing units vs
        // the reserve's 7600·10000/15000 headroom → the backing GE fails ⇒ unprovable.
        let [yb, mb, nmb, rb] = yb();
        let none = prove_yield_mint_carrier(u256_from_u64(7_600), u256_from_u64(5_000), u256_from_u64(5_000), yb, mb, nmb, rb, Backing::at_unit_price(u64::from(R as u64)));
        assert!(none.is_none(), "a reward the reserve does not over-collateralize is UNPROVABLE (backing gate holds)");
    }

    #[test]
    fn yield_supply_tampered_commitment_rejects() {
        let [yb, mb, nmb, rb] = yb();
        let (bytes, c) = prove_yield_mint_carrier(u256_from_u64(10_000), u256_from_u64(5_000), u256_from_u64(100), yb, mb, nmb, rb, Backing::at_unit_price(u64::from(R as u64))).unwrap();
        for which in 0..4 {
            let mut t = c;
            let d = match which {
                0 => &mut t.yield_commit,
                1 => &mut t.minted_commit,
                2 => &mut t.new_minted_commit,
                _ => &mut t.reserve_commit,
            };
            d[0] ^= 1;
            assert!(!verify_yield_mint_carrier(&bytes, Backing::at_unit_price(u64::from(R as u64)), &t), "⛔ commitment {which} tampered and the step verified");
        }
    }

    /// ⭐ A-F74: the wide-multiply column identity `out + carry·2^BITS` is below the KoalaBear prime
    /// unconditionally at the current constants, so a lying prover cannot wrap the native field by
    /// choosing carry bits that reconstruct to a value where the identity holds mod p but not over Z.
    /// CALIBRATION: at the old 14-bit/7-chunk/17-carry constants, a full carry decomposition EXCEEDS p.
    #[test]
    fn br15_a_wide_multiply_carry_cannot_wrap_the_native_field() {
        let p_nat: u64 = 2_130_706_433; // KoalaBear prime = 2^31 - 2^24 + 1
        let max_out = (1u64 << M14_BITS) - 1;
        let max_carry = (1u64 << M14_CARRY_BITS) - 1;
        let max_identity = max_out + max_carry * (1u64 << M14_BITS);
        assert!(
            max_identity < p_nat,
            "⛔ A-F74: out({max_out}) + carry({max_carry})·2^{} = {max_identity} ≥ p_nat({p_nat}) — a lying prover can wrap the native field",
            M14_BITS,
        );
        // the honest column sum is also below p_nat at worst
        let max_term = ((1u64 << M14_BITS) - 1) * ((1u64 << M14_BITS) - 1);
        let max_col_products = max_term * (M14_K_CHUNKS as u64);
        assert!(
            max_col_products + max_carry < p_nat,
            "⛔ A-F74: worst column sum {max_col_products} + carry {max_carry} ≥ p_nat({p_nat})",
        );
        // CALIBRATION: the OLD 14-bit/7-chunk/17-carry scheme allows an identity past p_nat
        let old_max_identity: u64 = ((1u64 << 14) - 1) + ((1u64 << 17) - 1) * (1u64 << 14);
        assert!(
            old_max_identity > p_nat,
            "CALIBRATION: the old 14-bit scheme's max identity {old_max_identity} should exceed p_nat({p_nat}) — the bug must exist to prove the fix works",
        );
        eprintln!(
            "[A-F74] M14 safe: max identity {} < p_nat {} (margin {}), old 14-bit identity {} EXCEEDS p_nat by {}",
            max_identity, p_nat, p_nat - max_identity, old_max_identity, old_max_identity - p_nat,
        );
    }
}
