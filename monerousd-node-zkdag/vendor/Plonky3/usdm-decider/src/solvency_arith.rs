// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE PEG'S VALUE ARITHMETIC — the exact solvency relation and the 256-bit limb operations every confidential
//! value transition (peg-in, peg-out, the stability pool, the yield mint) computes its new totals with. Pure and
//! dependency-free, so `kani-proofs` path-includes this very file and proves it over every input (§PROOFS
//! 2026-10-24); `confidential_solvency` re-exports it, so every caller keeps its path.

/// Basis-point denominator (10000 bps = 100%).
pub const BPS_DEN: u128 = 10_000;

/// The SOLVENCY INVARIANT over hidden totals: `reserve_value ≥ minted × ratio_bps / 10000`, i.e. the
/// reserve over-collateralizes the circulating USDm at the required ratio. Written cross-multiplied to stay
/// in exact integer arithmetic (no division/rounding). Must hold after EVERY op — the fund-safety invariant.
/// Both scaled sides are compared at u256 (a u128 × u32 never overflows 256 bits): a saturating u128
/// compare read MAX ≥ MAX = solvent for a 1/3-backed book once both sides passed 2^128.
#[inline]
pub fn is_solvent(reserve_value: u128, minted: u128, ratio_bps: u32) -> bool {
    scaled_ge(reserve_value, BPS_DEN as u64, minted, ratio_bps as u64)
}

/// `a·ka ≥ b·kb`, exact at u256.
fn scaled_ge(a: u128, ka: u64, b: u128, kb: u64) -> bool {
    match (mul256_small(u256_from_u128(a), ka), mul256_small(u256_from_u128(b), kb)) {
        (Some(l), Some(r)) => ge256(l, r),
        _ => false, // unreachable for u128 × u64; fail-closed regardless
    }
}

/// PEG-IN (mint): the SOUND per-event constraint the ZK proof enforces over the HIDDEN
/// `(reserve_value, minted, deposit_value, mint)`. Returns the new hidden totals iff the update is valid:
///  1. CONSERVATION (in == out, no hidden issuance): the new totals are EXACTLY the old totals plus this
///     event — `new_reserve = reserve_value + deposit_value`, `new_minted = minted + mint`. The proof binds
///     the deltas to the committed deposit/mint; nothing appears from nowhere.
///  2. PER-EVENT BACKING: `mint × ratio_bps ≤ deposit_value × 10000` — this deposit fully collateralizes
///     the USDm it mints at the required ratio (a local gate: the mint never exceeds the deposit's capacity).
///  3. GLOBAL SOLVENCY PRESERVED: `is_solvent(new_reserve, new_minted, ratio_bps)`.
/// Fail-closed: any violated clause returns `None` (the block's peg op is rejected, nothing mutates).
pub fn peg_in_apply(
    reserve_value: u128,
    minted: u128,
    deposit_value: u128,
    mint: u128,
    ratio_bps: u32,
) -> Option<(u128, u128)> {
    let new_reserve = reserve_value.checked_add(deposit_value)?; // conservation (overflow = reject)
    let new_minted = minted.checked_add(mint)?;
    // per-event backing: this deposit fully collateralizes its mint at the required ratio
    if !scaled_ge(deposit_value, BPS_DEN as u64, mint, ratio_bps as u64) {
        return None;
    }
    // global solvency preserved after applying the event
    if !is_solvent(new_reserve, new_minted, ratio_bps) {
        return None;
    }
    Some((new_reserve, new_minted))
}

/// PEG-OUT (burn/redeem): the SOUND per-event constraint over the HIDDEN totals. Burning `burn` USDm
/// releases `release_value` of reserve; the new totals must CONSERVE (`new_minted = minted − burn`,
/// `new_reserve = reserve_value − release_value`) and REMAIN SOLVENT. A redeem can never release more
/// reserve than the burned USDm's face value, and can never push the peg under-collateralized. Fail-closed.
pub fn peg_out_apply(
    reserve_value: u128,
    minted: u128,
    release_value: u128,
    burn: u128,
    ratio_bps: u32,
) -> Option<(u128, u128)> {
    let new_reserve = reserve_value.checked_sub(release_value)?; // release ≤ reserve held
    let new_minted = minted.checked_sub(burn)?; // burn ≤ USDm previously minted
    // A redeem must not release MORE value than the backing it retires (no reserve drain): the released
    // value is capped at the burned USDm's face value (1 USDm redeems ≤ 1 USDm of reserve).
    if release_value > burn {
        return None;
    }
    if !is_solvent(new_reserve, new_minted, ratio_bps) {
        return None;
    }
    Some((new_reserve, new_minted))
}

// ── #75 NO AMOUNT CAP — solvency at the note's real u256 width (limb-wise, no field reconstruction) ──
//
// DIGITAL CASH HAS NO AMOUNT LIMIT. The note `enc_amount` is 256-bit, so an amount / reserve / minted total
// is any value in `[0, 2^256)` — ~10^77, beyond any conceivable economy, and widenable by adding limbs (a
// FIXED limb count ⇒ still O(1), no per-value circuit growth — the no-growth pillar). The `u128` functions
// above are the small-value fast reference; THIS is the width the in-circuit AIR (brick 2b) proves over,
// doing every add / subtract / multiply LIMB-BY-LIMB with carries so a value is NEVER reconstructed into one
// ~124-bit field element (that reconstruction is what imposed the earlier 64-bit shortcut ceiling — gone).
// Fail-closed: any op whose result would exceed the fixed width returns `None` (the peg op is rejected),
// never a wrapped/aliased value.

/// A 256-bit unsigned value as four little-endian `u64` limbs (limb 0 = least significant). Matches the
/// note's 32-byte `enc_amount`. Widen by extending the limb count (fixed ⇒ O(1)).
pub type U256 = [u64; 4];

/// `a + b`, or `None` on 256-bit overflow (fail-closed — a real deposit/mint never overflows 256 bits).
pub fn add256(a: U256, b: U256) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    if carry != 0 { None } else { Some(out) }
}

/// `a − b`, or `None` if `a < b` (fail-closed — never release/burn more reserve/USDm than held/minted).
pub fn sub256(a: U256, b: U256) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut borrow = 0i128;
    for i in 0..4 {
        let d = a[i] as i128 - b[i] as i128 - borrow;
        if d < 0 {
            out[i] = (d + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            out[i] = d as u64;
            borrow = 0;
        }
    }
    if borrow != 0 { None } else { Some(out) }
}

/// `a × k` for a small `k` (the ratio / 10000, ~2^14), or `None` on 256-bit overflow (fail-closed).
pub fn mul256_small(a: U256, k: u64) -> Option<U256> {
    let mut out = [0u64; 4];
    let mut carry = 0u128;
    for i in 0..4 {
        let p = a[i] as u128 * k as u128 + carry;
        out[i] = p as u64;
        carry = p >> 64;
    }
    if carry != 0 { None } else { Some(out) }
}

/// `a ≥ b` over the full 256-bit width.
pub fn ge256(a: U256, b: U256) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// Solvency at u256 width: `reserve·10000 ≥ minted·ratio` (both sides 256-bit, NO reconstruction into one
/// field element). A scaled side that overflows 256 bits is treated as NOT solvent (fail-closed).
pub fn is_solvent_256(reserve_value: U256, minted: U256, ratio_bps: u32) -> bool {
    match (mul256_small(reserve_value, BPS_DEN as u64), mul256_small(minted, ratio_bps as u64)) {
        (Some(r), Some(m)) => ge256(r, m),
        _ => false,
    }
}

/// PEG-IN at u256 width — the SAME sound relation as `peg_in_apply`, with NO amount cap (values up to
/// 2^256). Fail-closed on any overflow. Returns the new `(reserve, minted)` iff conservation + per-event
/// 150% backing + global solvency all hold.
pub fn peg_in_apply_256(
    reserve_value: U256,
    minted: U256,
    deposit_value: U256,
    mint: U256,
    ratio_bps: u32,
) -> Option<(U256, U256)> {
    let new_reserve = add256(reserve_value, deposit_value)?; // conservation (overflow ⇒ reject)
    let new_minted = add256(minted, mint)?;
    // per-event backing: mint·ratio ≤ deposit·10000
    let mint_ratio = mul256_small(mint, ratio_bps as u64)?;
    let dep_scaled = mul256_small(deposit_value, BPS_DEN as u64)?;
    if !ge256(dep_scaled, mint_ratio) {
        return None;
    }
    if !is_solvent_256(new_reserve, new_minted, ratio_bps) {
        return None;
    }
    Some((new_reserve, new_minted))
}

/// A small `u64` as a `U256`.
pub fn u256_from_u64(v: u64) -> U256 {
    [v, 0, 0, 0]
}

/// A `u128` as a `U256` (little-endian limbs, as `ge256` reads them).
pub fn u256_from_u128(v: u128) -> U256 {
    [v as u64, (v >> 64) as u64, 0, 0]
}
