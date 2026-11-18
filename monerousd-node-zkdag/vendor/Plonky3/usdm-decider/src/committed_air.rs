// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐⭐⭐ THE COMMITTED AIR CARRIER — an AIR proof whose OPENED VALUES ARE BOUND TO A COMMITMENT.
//!
//! ⛔⛔⛔ WHY THIS EXISTS. MEASURED 2026-09-14 (§BD-2, §BD-3): the direct light decider
//! (`whir_rec_block::prove_air_direct_light_decider_bytes`) commits the trace to NOTHING. Its
//! `AirDirectBundle` carries `openings` as plain numbers, `verify_air_zerocheck` evaluates the AIR on
//! them, and `verify_hvzk` drops the masked sumcheck's residual target (`(point, _target)`) — so the
//! one value that could have tied those numbers to a committed polynomial is thrown away. Consequences,
//! each measured with an honest control passing through the identical construction:
//!
//! * a bound merged recursion step over ZERO evals with honestly-derived `r` VERIFIES (31,709 B);
//! * a one-table IVC step — the whole-chain certificate the join door adopts — VERIFIES with NO inner
//!   proof at all while claiming 2^100 of work from a chain that never existed (135,315 B);
//! * the entire opening half of a merged row can be zeroed and the step still verifies.
//!
//! The fix is not another cross-tie. A cross-tie binds a cell to another cell in the same object; what
//! was missing is the binding from those cells to a COMMITMENT the verifier opens. This module supplies
//! exactly that, and nothing else changes: the same `AirConstraint`, the same zerocheck, the same
//! challenger order — with the trace committed BEFORE any challenge is drawn and the zerocheck's opened
//! values proven to be that commitment's true evaluations at the zerocheck's own point.
//!
//! ⭐ IT REUSES THE PROVEN PCS RATHER THAN INVENTING ONE. `p3_whir`'s multilinear PCS is complete,
//! sound, hiding under the salted MMCS, ~79 ms release prove and ≤1.8 MB — pinned by
//! `whir::pcs::tests::whir_pcs_commits_and_verifies_under_hiding_mmcs`. Reinventing a commitment scheme
//! is exactly what [[feedback_borrow_proven_chains_no_rederiving]] forbids; the crypto here is the
//! WELD between an AIR zerocheck and that PCS's opening.
//!
//! ## What a verifier checks, in order (and every input is PUBLIC)
//! 1. the statement (`public_bind`) is observed FIRST, so every challenge below is a function of it;
//! 2. the TRACE COMMITMENT is observed — before `gamma`, before `z`, before any `r`;
//! 3. the zerocheck round chain holds and `eq(z,r)·C_γ(opened) == claim_last`;
//! 4. ⭐ the opened values ARE the committed polynomial's evaluations at `r` — the WHIR opening proof,
//!    checked against the commitment from (2). This is the step the direct path has no object for.
//!
//! ⛔ A ZERO ROW CANNOT PASS (4): it would have to be the true evaluation of a committed trace, and the
//! commitment was fixed before `r` existed.

use crate::air_zerocheck::{prove_air_zerocheck, verify_air_zerocheck, AirConstraint, AirZerocheckProof, Row};
use crate::whir_rec_block::absorb_shifted_openings;
use crate::hiding_decider::{Chl, CompressHash, Ea4, Fa4, Mmcs16, Perm16, SpongeHash};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Mmcs;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::layout::{Layout, PrefixProver, Table, Verifier as LayoutVerifier};
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};
use p3_whir::pcs::prover::WhirProver;
use p3_whir::pcs::verifier::WhirVerifier;
use p3_whir::pcs::proof::WhirProof;
use rand::{Rng, RngExt, SeedableRng};
use rand::rngs::SmallRng;
use serde::{Deserialize, Serialize};

pub type Dft16 = Radix2DFTSmallBatch<Fa4>;
pub type Pcs = WhirProver<Ea4, Fa4, Dft16, Mmcs16, Chl, PrefixProver<Fa4, Ea4>>;

/// The folding factor for a committed AIR carrier. Constant — the shape must be identical on both
/// sides and derivable from public data alone.
pub const COMMITTED_FOLDING: usize = 4;
/// Security level, matching the PCS's own pinned configuration.
pub const COMMITTED_SECURITY: usize = 100;
/// The starting inverse rate, as the proven configuration uses.
pub const COMMITTED_START_RATE: usize = 1;
/// The proximity regime every production carrier is SIZED in — part of the carrier's public shape, so both sides derive
/// the same query counts. ⛔ H12 (lane-harness, 2026-10-04): this is `CapacityBound`, p3-whir's CONJECTURED regime (RS
/// codes list-decodable up to capacity with mutual correlated agreement), so `COMMITTED_SECURITY` holds only if the
/// conjecture does. MEASURED by `h12_proven_soundness` with the library's own `soundness.rs`: the live carriers score
/// 15–46 bits and the certificate ~59 under the regimes the library labels proven (JohnsonBound: theorem-backed list
/// decoding up to the Johnson radius; UniqueDecoding: no assumption). The pin stays RED until the regime and the
/// per-carrier rates/grinds that reach ≥ 100 PROVEN land with their measured bytes and rows
/// (`h12_cost_of_proven_security_by_regime_rate_and_grind`).
/// 2026-10-04 (H12 step 5): the LIVE carrier no longer reads this — it is sized under `JohnsonBound` (`CarrierParams::LIVE`).
/// What still reads it is the recursive CERTIFICATE (`CERT_CARRIER`, `CERT_FIXED_CARRIER`) and the program pins'
/// `legacy()` shapes: the certificate under the Johnson bound needs T = 2^15, which needs the stream-and-commit register
/// banks (§12). Until then the H12 pin's certificate rows stay RED — the open row, said here, never hidden.
pub const COMMITTED_REGIME: SecurityAssumption = SecurityAssumption::CapacityBound;
/// The PUBLIC domain seed both sides build their permutation and MMCS from — the same shape
/// `whir_rec_block::REC_DECIDER_SEED` plays for the direct path, so a carrier proved on one device
/// verifies on every other.
/// The largest trace height a carrier may DECLARE, as a power-of-two exponent.
///
/// ⛔ NOT A WINDOW ON ANYTHING REAL — it is the point past which `1usize << nvars` stops being a number.
/// A 2^32-row trace is 4 billion rows; nothing in this protocol lays one, and every shape at or beyond
/// the shift width is an attacker's number rather than a prover's. Bounding the DECLARATION is what
/// keeps a hostile shape a refusal instead of an unwind.
pub const MAX_STATEABLE_NVARS: usize = 32;

pub const COMMITTED_AIR_SEED: u64 = 0x_C011_17ED_A180_u64;

/// A committed AIR carrier: the trace commitment, the zerocheck, and the PCS opening proof that binds
/// the zerocheck's opened values to that commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct CommittedAirBundle {
    /// `(nvars, width)` of the single table — PUBLIC shape a verifier rebuilds its layout from.
    pub shape: (usize, usize),
    /// The Merkle commitment to the encoded trace, fixed BEFORE any challenge is drawn.
    pub commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    /// The AIR zerocheck: round evals, the challenge point, and the opened row at that point.
    pub zc: AirZerocheckProof,
    /// The WHIR opening proof binding `zc.opened` to `commitment` at the point `zc.r` (C3a: its paths in fixed slots).
    #[serde(with = "crate::light_commit::slotted_whir")]
    pub open: WhirProof<Fa4, Ea4, Mmcs16>,
}

fn round_log_inv_rates(num_variables: usize, folding_factor: &FoldingFactor) -> Vec<usize> {
    let (num_rounds, _) = folding_factor.compute_number_of_rounds(num_variables);
    let mut rates = Vec::with_capacity(num_rounds);
    let mut rate = COMMITTED_START_RATE;
    for round in 0..num_rounds {
        rate += folding_factor.at_round(round) - 1;
        rates.push(rate);
    }
    rates
}

/// The MMCS and DFT both sides build identically. The salt rng is the PROVER's blinding source; the
/// verifier never salts, so its rng seed is irrelevant to soundness and fixed for determinism.
fn mmcs() -> Mmcs16 {
    // DB-382: the salt rng is the PROVER's blinding source — fresh OS entropy per prove, never a public constant
    mmcs_with(crate::whir_rec_block::prover_randomness())
}
/// The MMCS over a GIVEN salt source. DB-382: the salts are the prover's blinding, drawn from `salt_rng` at each
/// commit. A prover that must REBUILD a commitment it already absorbed (the certificate's witness,
/// `spartan_ccs::prove_committed_inner`: committed, dropped for RAM, rebuilt for the opening) builds both PCS from the
/// same per-prove SECRET seed (`whir_rec_block::fresh_prover_seed`), so the rebuilt root is the absorbed one — the
/// equality of two hiding commitments comes from a shared secret, never from a public constant.
pub(crate) fn mmcs_with(salt_rng: SmallRng) -> Mmcs16 {
    let mut rng = SmallRng::seed_from_u64(COMMITTED_AIR_SEED);
    let perm = Perm16::new_from_rng_128(&mut rng);
    Mmcs16::new(SpongeHash::new(perm.clone()), CompressHash::new(perm), 0, salt_rng)
}
/// The salt source of the FIXED table's commitment — the ONE public salt source, by design.
/// DIGITAL-CASH-PRIVACY-REVIEWED: the fixed table is the release's own template columns (`FixedColumns`), public data
/// every node holds; its commitment root is a release constant the verifier program captures (`CertParams::fixed_root`),
/// so every prover must lay the SAME tree, on every machine. A salt over public data hides nothing and leaks nothing.
/// The witness and every live carrier salt from `prover_randomness()` (OS entropy per prove, DB-382).
pub(crate) fn fixed_table_salts() -> SmallRng {
    SmallRng::seed_from_u64(COMMITTED_AIR_SEED + 7)
}

/// The two size levers of a committed carrier's WHIR opening: the starting log inverse rate (more
/// redundancy → fewer queries per security bit) and the Fiat–Shamir grinding bits (each replaces one query
/// bit). `LIVE` is what the chain runs; the `_with` provers exist so the carrier's byte size can be MEASURED
/// per parameter set on the real statements (user 2026-09-17: keep the 500 ms block time, shrink the proof
/// bytes — an empty block was 128 KB, 94 KB of it this carrier at rate 1 / pow 0).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CarrierParams {
    pub start_rate: usize,
    pub pow_bits: usize,
    /// The variable count at which the prover sends the final polynomial's coefficients: `LEGACY_SEND_VARS` (6, the
    /// WHIR crate's constant — every live carrier) keeps `FoldingFactor::Constant`; a larger value drops the deepest
    /// folding rounds under `FoldingFactor::ConstantSendAt` (the recursive certificate: 7, so its 27-variable
    /// witness grinds at most 2^30 per round instead of 2^35 — spec §M5, census 2026-09-28).
    pub send_vars: usize,
    /// The proximity regime the carrier's query counts are derived in (H12) — `COMMITTED_REGIME` for every production
    /// carrier; the cost instrument builds candidates in the proven regimes.
    pub regime: SecurityAssumption,
    /// H12 path B (user ruling 2026-10-04): the FIRST round's folding factor. `COMMITTED_FOLDING` (4) keeps the constant
    /// schedule every live carrier has; a wider first fold (5: 32-value leaves) is what admits the certificate's 2^28-word
    /// witness under the two-adicity (`vars + start_rate − first_fold ≤ 24`) and buys proven bits per query at a lower rate.
    pub first_fold: usize,
    /// H12 path B: how much the inverse rate GROWS per WHIR round (log2). `COMMITTED_FOLDING − 1` (3) is p3-whir's default
    /// (`rate += folding − 1`); a gentler step keeps ρ larger in the deep rounds, where the Johnson prox-gaps term `ρ^(−3/2)`
    /// is what forces the fold grinds (MEASURED 2026-10-04: +3 → grinds up to 2^35; +2 → ≤ 2^25 at the certificate's shape).
    pub rate_growth: usize,
    /// The largest FOLD grind (bits) this carrier's shape may ask: `pcs_with_salts` steps `rate_growth` down, per stacked
    /// arity, until every fold grind fits. `ONE_WORD_GRIND_CEILING` (24, ~1 s per grind) for the money path's `LIVE`
    /// carriers; `FIELD_GRIND_LIMIT` (30, the grinder's own `2^bits < p` bound) for every other carrier, so a shape that
    /// fits today keeps its schedule byte for byte and a shape that would panic the grinder steps down instead.
    pub max_fold_grind: usize,
    /// ⭐ SPEED R4-G (2026-11-10) — size each folding sub-round's grind at the code that fold acts on
    /// (`WhirConfig::with_fold_grinds_at_the_folded_code`: sub-round `s` of a group is scored and ground at
    /// `num_variables − s`) instead of every sub-round at the group's start. `false` keeps the configuration
    /// `WhirConfig::new` derives, bit for bit — every carrier a CIRCUIT verifies (`whir_program` lays one grind figure
    /// per folding group) and every proof already made under one. `true` only where the verifier is native and reads
    /// the per-fold list: the light decider's rounds ([`crate::light_commit::LIGHT_COMMIT_PARAMS`], the two proofs a
    /// block costs). The shape — folds, rates, queries, bytes — is the same either way; only the difficulty of each
    /// fold's proof of work differs, and `proven_bits` scores every sub-round against the same 100 bits.
    pub fold_grind_per_fold: bool,
}
/// The one-word grinder's ceiling `F::bits() − 7` on KoalaBear (certificate §11): one grind at 24 bits measured 1,012 ms
/// (DB-452). Pinned equal to the field-derived value by `every_production_whir_config_grinds_within_its_ceiling`.
pub const ONE_WORD_GRIND_CEILING: usize = 24;
/// The grinder's hard bound: the largest `bits` with `2^bits < p` on KoalaBear (`grinding_challenger.rs` asserts it; ≥ 31
/// panics). Pinned against the field order by `every_production_whir_config_grinds_within_its_ceiling`.
pub const FIELD_GRIND_LIMIT: usize = 30;
/// The WHIR crate's coefficient-sending threshold, the one every live carrier folds down to.
pub const LEGACY_SEND_VARS: usize = 6;
impl CarrierParams {
    /// ⭐⭐⭐ H12 STEP 5 (USER RULING 2026-10-04, docs/H12-WHIR-PROVEN-SOUNDNESS.md §10): every live carrier — the money
    /// path's block and spend proofs — is sized ≥ `COMMITTED_SECURITY` PROVEN under the JOHNSON BOUND (theorem-backed list
    /// decoding), never the capacity conjecture: rate 1/4 (0.93 proven bits per query against 0.43 at rate 1/2) and 16
    /// query-grinding bits. MEASURED by the cost instrument (§7): 91,772 B (+8%) and 207 ms (2.3×) per prove against the
    /// conjectured rate-1/2 carrier. Two-adicity: `vars + 2 − 4 ≤ 24` holds through the 24-variable production cap.
    /// Cons: +8% carrier bytes, 2.3× prove time (user-accepted with the ruling). The certificate's carriers stay
    /// `COMMITTED_REGIME` until the stream-and-commit banks (§12) let the T = 2^15 Johnson-bound certificate fit.
    pub const LIVE: CarrierParams = CarrierParams {
        start_rate: 2,
        pow_bits: 16,
        send_vars: LEGACY_SEND_VARS,
        regime: SecurityAssumption::JohnsonBound,
        first_fold: COMMITTED_FOLDING,
        rate_growth: COMMITTED_FOLDING - 1,
        // ⭐ A CARRIER'S GRIND IS WHAT A SEND WAITS ON (2026-11-04, real nodes). A fold grind of b bits costs 2^b hashes per folded variable, and a carrier is proved on the
        // payer's own device. The schedule's growth steps down to meet this ceiling and `WhirConfig::new` re-sizes the queries for the same 100 bits, so soundness is
        // unchanged. cons: more queries, so a larger carrier (bytes measured at the landing).
        max_fold_grind: 16,
        // the in-circuit WHIR verifier (`whir_program`) checks a carrier's folds at one figure per folding group
        fold_grind_per_fold: false,
    };
    /// `start_rate` and `pow_bits` at the legacy threshold — the shape every carrier had before `send_vars` existed.
    pub const fn legacy(start_rate: usize, pow_bits: usize) -> Self {
        CarrierParams {
            start_rate,
            pow_bits,
            send_vars: LEGACY_SEND_VARS,
            regime: COMMITTED_REGIME,
            first_fold: COMMITTED_FOLDING,
            rate_growth: COMMITTED_FOLDING - 1,
            max_fold_grind: FIELD_GRIND_LIMIT,
            fold_grind_per_fold: false,
        }
    }
    /// Does this carrier use the constant folding schedule (`Constant` / `ConstantSendAt`) — every live carrier today — or
    /// a per-round one (a wider first fold, path B)? The FOLDING is constant whenever the first fold is; the inverse
    /// rate's growth per round is a separate lever applied to either schedule (`pcs_with_salts`). DB-452 (2026-10-21): a
    /// light-decider round at first fold 4 and growth 2 has no remainder for a per-round schedule to place, and its
    /// stacked arity can sit below `first_fold + send_vars`, where the per-round form refuses to exist.
    pub const fn constant_schedule(&self) -> bool {
        self.first_fold == COMMITTED_FOLDING
    }
}
/// ⭐ LANE AGG (the tree): what a circuit that verifies a committed-door proof of COMMITTED shape `(nvars, width)` needs of
/// its PCS — the stacked arity and the WHIR configuration — derived exactly as the doors derive them (`pcs_with` over the
/// stacked arity `verify_committed_body` / `verify_chained_body` compute). `None` for a shape no door admits.
#[must_use]
pub fn door_whir_config(shape: (usize, usize), params: CarrierParams) -> Option<(usize, p3_whir::parameters::WhirConfig<Ea4, Fa4, Chl>)> {
    let (nvars, width) = shape;
    if nvars < COMMITTED_FOLDING || nvars > MAX_STATEABLE_NVARS || width == 0 {
        return None;
    }
    let stacked = {
        let t = Table::new((0..width).map(|_| Poly::<Fa4>::new(vec![Fa4::ZERO; 1 << nvars])).collect());
        PrefixProver::<Fa4, Ea4>::new_witness(vec![t], params.first_fold).num_variables()
    };
    // the two-adicity guard `WhirConfig::new` asserts (whir/src/parameters/whir.rs:166, "Increase folding_factor_0"):
    // a shape past it is one no door can configure — refused here, never a panic (MEASURED: (16, 1454) panicked agg_w1)
    if stacked + params.start_rate > <Fa4 as p3_field::TwoAdicField>::TWO_ADICITY + params.first_fold {
        return None;
    }
    Some((stacked, pcs_with(stacked, params).config.clone()))
}

/// ⭐ LANE AGG (the SSA door, usdm-agg `ssa_door`): the committed door's PCS for a stacked arity and its challenger, built
/// exactly as every committed door builds them (`pcs_with`, `challenger`) — one derivation, so the SSA door's transcript
/// and opening are the committed door's.
#[must_use]
pub fn door_pcs(stacked_nvars: usize, params: CarrierParams) -> Pcs {
    pcs_with(stacked_nvars, params)
}

/// The committed door's challenger (a public constant permutation).
#[must_use]
pub fn door_challenger() -> Chl {
    challenger()
}

/// The chained door's next-row columns for `constraint` (lane agg: a circuit replays the door's shift bind over them).
#[must_use]
pub fn door_next_cols<C: AirConstraint>(constraint: &C, width: usize) -> Option<Vec<usize>> {
    next_row_columns(constraint, width)
}

pub(crate) fn pcs_with(stacked_nvars: usize, params: CarrierParams) -> Pcs {
    pcs_with_salts(stacked_nvars, params, crate::whir_rec_block::prover_randomness())
}
/// `pcs_with` over a GIVEN salt source (DB-382, see `mmcs_with`): the certificate prover's two commits of one witness,
/// and the fixed table's public salts.
pub(crate) fn pcs_with_salts(stacked_nvars: usize, params: CarrierParams, salt_rng: SmallRng) -> Pcs {
    let folding_factor = if params.constant_schedule() {
        // the legacy threshold keeps the legacy variant: its Fiat–Shamir domain separator is every live proof's
        if params.send_vars == LEGACY_SEND_VARS { FoldingFactor::Constant(COMMITTED_FOLDING) } else { FoldingFactor::ConstantSendAt(COMMITTED_FOLDING, params.send_vars) }
    } else {
        // H12 path B — a per-round schedule: the first fold as declared, then EXACTLY `COMMITTED_FOLDING` per round (the
        // only later-round leaf width the verifier program is written for), the final polynomial sent at `send_vars` plus
        // whatever remainder keeps every later fold at 4 (`FoldingFactor::PerRoundSendAt`). MEASURED 2026-10-04 19:34: the
        // first form put the remainder into the LAST fold and the program met a 2-value final leaf it has no schedule for.
        // One derivation from `(stacked_nvars, first_fold, send_vars)` on both sides.
        assert!(stacked_nvars >= params.first_fold + params.send_vars, "a per-round schedule needs at least its first fold plus the final polynomial");
        let after_first = stacked_nvars - params.first_fold;
        let (full, rem) = if after_first > params.send_vars {
            ((after_first - params.send_vars) / COMMITTED_FOLDING, (after_first - params.send_vars) % COMMITTED_FOLDING)
        } else {
            (0, 0)
        };
        let mut folds = vec![params.first_fold];
        folds.extend(core::iter::repeat(COMMITTED_FOLDING).take(full));
        FoldingFactor::PerRoundSendAt(folds, params.send_vars + rem)
    };
    let config_at = |growth: usize| {
        let mut rates = Vec::new();
        let (num_rounds, _) = folding_factor.compute_number_of_rounds(stacked_nvars);
        let mut rate = params.start_rate;
        for round in 0..num_rounds {
            // the inverse rate grows by `growth` per round, never faster than the round's fold admits (`folding − 1`)
            rate += growth.min(folding_factor.at_round(round) - 1);
            rates.push(rate);
        }
        let whir = ProtocolParameters {
            hiding: true,
            security_level: COMMITTED_SECURITY,
            pow_bits: params.pow_bits,
            round_log_inv_rates: rates,
            folding_factor: folding_factor.clone(),
            soundness_type: params.regime,
            starting_log_inv_rate: params.start_rate,
        };
        WhirConfig::new(stacked_nvars, whir)
    };
    // ⛔ THE GROWTH IS A CEILING. At growth 3 `LIVE` derives fold grinds that the one-word grinder cannot pay — the
    // Johnson prox-gaps term `ρ^(−3/2)` in the deep rounds (DB-452). The shape is the largest growth ≤ `rate_growth`
    // whose every FOLD grind stays within `params.max_fold_grind`, derived from `(stacked_nvars, params)` alone,
    // identically by prover and verifier. `WhirConfig::new` still sizes the queries for `COMMITTED_SECURITY` in the
    // same regime, so the security target is unchanged; the cost is extra queries at the stepped-down shapes only.
    // ROOT-LAYER: `pcs_with_salts` is the one producer of every carrier's WHIR schedule (prove, verify, the light
    // rounds, the certificate) — the class fix for DB-452's one-site fix (`LIGHT_COMMIT_PARAMS`, growth 1 by hand).
    // MEASURED 2026-10-26 (a config-only sweep of `pcs_with(v, LIVE)`, scratchpad/verify/grind-measure.log), before:
    // LIVE fold grinds 27 / 31 / 35 / 38 bits at 19 / 23 / 25 / 26 stacked variables; the 26-variable band sub-carrier
    // (2^16 × 561) panicked the grinder (`1 << bits < p`) after 232 s. After: pinned ≤ 24 at every production shape by
    // `every_production_whir_config_grinds_within_its_ceiling`.
    // MUST-STAY-GREEN: every shape already inside its ceiling (LIVE ≤ 18 variables, the light rounds, both certificate
    // carriers under `FIELD_GRIND_LIMIT`) keeps its schedule byte for byte — the step-down never runs for them; H12's
    // ≥ 100 JB bits at every shape.
    let mut growth = params.rate_growth;
    loop {
        let cfg = config_at(growth);
        if growth == 0 || max_fold_grind_bits(&cfg) <= params.max_fold_grind {
            // SPEED R4-G: the SHAPE (growth, rates, queries, bytes) is chosen above from the group figures, exactly as
            // before; a carrier that asks for it then grinds each fold at the code that fold acts on. One derivation
            // from `(stacked_nvars, params)`, so the prover and the verifier hold the same list.
            let cfg = if params.fold_grind_per_fold { cfg.with_fold_grinds_at_the_folded_code() } else { cfg };
            return Pcs::new(cfg, Dft16::default(), mmcs_with(salt_rng));
        }
        growth -= 1;
    }
}

/// The largest FOLD grind a WHIR config asks (the starting fold, every round's fold, the final fold) — the term the
/// rate schedule controls; query grinds are `pow_bits` as declared.
#[must_use]
pub fn max_fold_grind_bits(cfg: &WhirConfig<Ea4, Fa4, Chl>) -> usize {
    cfg.round_parameters
        .iter()
        .map(|r| r.folding_pow_bits)
        .chain([cfg.starting_folding_pow_bits, cfg.final_folding_pow_bits])
        .max()
        .expect("the starting and final folds are always present")
}
fn pcs_for(stacked_nvars: usize) -> Pcs {
    pcs_with(stacked_nvars, CarrierParams::LIVE)
}

/// A fresh challenger. The permutation is a PUBLIC constant — both sides build the same one.
fn challenger() -> Chl {
    // SPEED G1: the committed carriers grind on the GPU where there is one (`gpu_grind::install`, once per process).
    let _ = crate::gpu_grind::install();
    let mut rng = SmallRng::seed_from_u64(COMMITTED_AIR_SEED);
    Chl::new(Perm16::new_from_rng_128(&mut rng))
}

/// ⭐⭐⭐ THE BLINDING WRAPPER — what makes a committed carrier HIDE as well as BIND (§BE-1).
///
/// ⛔⛔⛔ THE LEAK, MEASURED 2026-09-14 on a real depth-64 spend carrier: every amount
/// (`value_in`, `value_out`, `fee`, both outputs) and the SPENT NOTE'S LEAF — 8/8 lanes — appear in
/// the carrier's opened values IN THE CLEAR, readable by the admitting node and by any peer that
/// fetches the body. The cause is not the commitment; it is the SHAPE. A production carrier holds ONE
/// logical row replicated up the trace, and the multilinear extension of a CONSTANT column equals that
/// constant at EVERY point — so the opening at a random `r` is the secret itself.
///
/// ⭐ THE FIX, AND WHY IT IS SOUND. Double the height: the caller's rows go in the FIRST half, fresh
/// randomness in the SECOND. The constraint is multiplied by the selector `(1 − x[0])`, where `x[0]` is
/// the MOST-significant hypercube variable (`prove_air_zerocheck` folds variable 0 first and puts the
/// low half at `x=0`), so it is 1 on every real row and 0 on every blinding row. The AIR is therefore
/// enforced EXACTLY where the caller's data lives and nowhere else, while `MLE_j(r)` now mixes the
/// random rows and reveals nothing about any single row.
///
/// ⛔ THE SELECTOR IS NOT A COMMITTED COLUMN, AND THAT IS THE POINT. A prover-supplied selector could
/// be set to zero everywhere, satisfying any constraint trivially. `(1 − x[0])` is a function of the
/// zerocheck's OWN point, which the verifier holds, so there is nothing for a prover to choose.
///
/// ⛔⛔⛔ ROW-SHIFTED AIRs ARE REFUSED, BY MEASUREMENT NOT BY HOPE. The rotation `(i+1) % height` is
/// taken over the FULL trace, so the last real row's "next" becomes a blinding row and a transition
/// constraint there would be evaluated against randomness. A census of this crate (2026-09-14) found 17
/// row-shifted AIRs across 11 files, and `FoldConstraint` is the one in `whir_rec_block`. Every
/// VALUE-CARRYING gate — `SpendValidityGate`, `MintValidityGate`, `AssetSpendValidityGate`,
/// `AssetMintValidityGate`, `MakerHalfGate`, `TakerHalfGate` — is row-LOCAL, which is why this wrapper
/// covers exactly the carriers that leak user funds. A caller whose AIR reads `at(..)` must not use it.
#[derive(Clone)]
pub struct Blinded<C: AirConstraint + Sync> {
    /// Public so a recursion can rebuild the SAME wrapped constraint the shipped carrier was proved
    /// against — a second, equivalent wrapper is two spellings of one circuit (§AO).
    pub inner: C,
}

impl<C: AirConstraint + Sync> AirConstraint for Blinded<C> {
    fn degree(&self, nvars: usize) -> usize {
        // One more than the inner AIR: the selector is linear in the point.
        self.inner.degree(nvars) + 1
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        // `x[0]` is the MSB of the row index: rows 0..h−1 (the caller's data) have x[0] = 0.
        let sel = Ea4::ONE - x[0];
        sel * self.inner.eval(local, at, x)
    }
    /// The selector distributes over the residuals, so an aggregate folding them against γ-power columns
    /// sees the SAME wrapped circuit the shipped carrier was proved against — not an unblinded twin.
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        let sel = Ea4::ONE - x[0];
        self.inner.residuals(local, at, x).into_iter().map(|r| sel * r).collect()
    }
    /// The wrapper has a base-field path exactly when its inner gate has one. On a base-field row and point the
    /// selector is a base-field value, so the wrapped value is the inner gate's base value times it: the same value
    /// `eval` gives on that row lifted, and the same proof bytes. A gate with no base path keeps the default.
    fn has_base_eval(&self) -> bool {
        self.inner.has_base_eval()
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        self.inner.eval_base(local, at, x) * (Fa4::ONE - x[0])
    }
    /// The blinding selector reads the POINT, never a shifted column — so this is row-local exactly
    /// when the AIR it wraps is.
    fn is_row_local(&self) -> bool {
        self.inner.is_row_local()
    }
    /// The wrapper reads exactly the rotated run its inner gate declares — a wrapper answering `None` here
    /// while its inner names a run is two spellings of one circuit (§AO): the zerocheck prover would then fold
    /// EVERY column at every sample point (`air_zerocheck`: `None ⇒ all of them`) for a gate that reads 26.
    /// Same sums, same proof bytes; the work is the difference. MEASURED 2026-09-28 on the member-path class.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        self.inner.shifted_cols()
    }
    /// ⭐ DB-376 — the wrapper adds ROWS (the blinding half), never columns, so its inner gate's free-column
    /// declaration is the wrapper's, column for column. MEASURED 2026-10-03: answering the default `None` here dropped
    /// `SpendValidityGate`'s own declaration (the claim region a no-claim class leaves unread), and the strict census
    /// refused those 173 cells in the bond class's settlement step (`db376_…_inner_gate_never_reads`).
    fn free_columns(&self) -> Option<Vec<usize>> {
        self.inner.free_columns()
    }
}

/// Extend `cols` to twice the height, filling the second half with fresh randomness drawn from the OS.
/// ⛔ The randomness must be REAL: a deterministic pad is a pad every observer can subtract off, which
/// would leave the opening as revealing as before while looking blinded.
pub(crate) fn blind_cols<R: Rng>(cols: Vec<Vec<Fa4>>, rng: &mut R) -> Vec<Vec<Fa4>> {
    cols.into_iter()
        .map(|mut c| {
            let h = c.len();
            c.reserve(h);
            for _ in 0..h {
                c.push(Fa4::from_u64(u64::from(rng.random::<u32>())));
            }
            c
        })
        .collect()
}

/// PROVE a BLINDED committed carrier — binding (§BF) AND hiding (§BE-1) — for a ROW-LOCAL AIR.
///
/// The caller passes its trace and its constraint exactly as for [`prove_air_committed_bytes`]; the
/// blinding rows and the selector are added here, so no AIR has to know about them. Verify with
/// [`verify_air_blinded_bytes`], which rebuilds the same wrapper from public shape alone.
#[must_use]
pub fn prove_air_blinded_bytes<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    // ⛔ FAIL-CLOSED ON ENTROPY. `SysRng` is the OS source and it is FALLIBLE; if it cannot be read,
    // this refuses to prove rather than blinding with something predictable. A carrier that looks
    // blinded but is not would leak exactly as much as an unblinded one, with nobody looking.
    let mut rng = SmallRng::try_from_rng(&mut rand::rngs::SysRng::default()).ok()?;
    let blinded = blind_cols(cols, &mut rng);
    prove_air_committed_bytes(blinded, move |g: Ea4| Blinded { inner: make_constraint(g) }, public_bind)
}

/// VERIFY a blinded committed carrier. The wrapper is rebuilt from the same public data the prover
/// used, so a carrier proved without blinding cannot pass here and vice versa.
#[must_use]
pub fn verify_air_blinded_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    // ⛔ DB-213b — the shape of the trace the CALLER lays, before blinding doubles its height.
    laid_shape: (usize, usize),
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let Some(committed_nvars) = laid_shape.0.checked_add(1) else {
        return false;
    };
    verify_air_committed_bytes(
        bytes,
        move |g: Ea4| Blinded { inner: make_constraint(g) },
        public_bind,
        (committed_nvars, laid_shape.1),
    )
}

// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
// THE CHAINED DOOR — a blinded committed carrier for an AIR whose rows READ THE NEXT ROW (2026-11-10, lane goods).
//
// ⛔ WHY IT EXISTS, MEASURED. The doors above bind ONE thing to the commitment: the opened row at `r`. A gate that
// reads the next row is scored against `zc.shifted_opened`, and those values are only absorbed into the transcript,
// never opened. `forge_blinded_next_row_for_tests` is the prover that uses it: an honest commitment, an honest opened
// row, all-zero rounds, and ONE next-row opening moved until the gate reads zero. Through `verify_air_blinded_bytes`
// it verifies for any statement of a gate with a law `next(c) - …` (pins: income nobody received; a delivery notice
// no carrier signed). The doors above say "for a ROW-LOCAL AIR" for this reason; this door is the one for the rest.
//
// THE FIX IS THE CRATE'S OWN, BORROWED: the shift bind of `light_commit` (`prove_shift_bind` / `verify_shift_bind`),
// which the batch light decider runs on every table that is not row-local. The next-row values the gate reads are sent,
// absorbed, and then PROVEN to be the committed columns' own: with `f = Σ_j λ^j · col_j` over the gate's next-row
// columns, one sumcheck shows `Σ_y S(r, y) · f(y) = Σ_j λ^j · next_j` (`S` = "y is the row after x",
// `light_commit::shift_mle`), and it ends in ONE opening of those columns at a fresh point `ρ`, a claim of the same
// opening proof that binds the row at `r`.
//
// WHAT IT COSTS: two extension values per next-row column (its next-row value and its value at `ρ`) and three per
// row variable for the sumcheck, and it SAVES the 16 bytes per column of the WHOLE table that the other doors send as
// next-row openings. Nothing is opened in the clear: `ρ` is a fresh random point, so the opening there mixes the
// blinding rows exactly as the opening at `r` does.
// ════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// A chained carrier: the commitment, the zerocheck, the gate's next-row values with their shift bind, and the opening
/// proof for all of it.
#[derive(Clone, Serialize, Deserialize)]
pub struct ChainedAirBundle {
    /// `(nvars, width)` of the committed (blinded) table.
    pub shape: (usize, usize),
    pub commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    /// The zerocheck. Its `shifted_opened` is EMPTY on the wire: the gate's next-row values ride in `next`.
    pub zc: AirZerocheckProof,
    /// The next-row value at `r` of each column the gate reads on the next row (its `shifted_cols`, in order).
    pub next: Vec<Ea4>,
    /// The shift bind's rounds: per row variable, the round polynomial at 0, 1, 2.
    pub bind_rounds: Vec<Vec<Ea4>>,
    /// Those columns at the shift bind's point `ρ`.
    pub bind_opened: Vec<Ea4>,
    /// C3a: the opening's paths in fixed slots.
    #[serde(with = "crate::light_commit::slotted_whir")]
    pub open: WhirProof<Fa4, Ea4, Mmcs16>,
}

/// The columns a gate reads on the next row, as a door can use them: named, in rising order, inside the table.
fn next_row_columns<C: AirConstraint>(constraint: &C, width: usize) -> Option<Vec<usize>> {
    let cols = constraint.shifted_cols()?;
    (!cols.is_empty() && cols.windows(2).all(|w| w[0] < w[1]) && cols.last().is_some_and(|c| *c < width)).then_some(cols)
}

/// The shift bind's two tables over the cube: `f = Σ_j λ^j · col_j` over the next-row columns, and the weight of each
/// row as "the row after the one `r` names" (`S(r, y) = eq(r, y - 1)` on the cube, the last row wrapping to the first).
fn shift_bind_tables(cols: &[Vec<Fa4>], next_cols: &[usize], r: &[Ea4], lambda: Ea4) -> (Vec<Ea4>, Vec<Ea4>) {
    let size = 1usize << r.len();
    let mut f = vec![Ea4::ZERO; size];
    let mut power = Ea4::ONE;
    for c in next_cols {
        for (acc, v) in f.iter_mut().zip(&cols[*c]) {
            *acc += power * *v;
        }
        power *= lambda;
    }
    let eq_r = crate::air_zerocheck::eq_z_hypercube(r);
    let s = (0..size).map(|i| eq_r[(i + size - 1) % size]).collect();
    (f, s)
}

/// One round of the shift bind: `Σ s·f` over the half the next variable splits, at 0, 1 and 2.
fn shift_bind_round(s: &[Ea4], f: &[Ea4]) -> [Ea4; 3] {
    let half = s.len() / 2;
    let mut h = [Ea4::ZERO; 3];
    for i in 0..half {
        let (s0, s1, f0, f1) = (s[i], s[i + half], f[i], f[i + half]);
        h[0] += s0 * f0;
        h[1] += s1 * f1;
        h[2] += (s1.double() - s0) * (f1.double() - f0);
    }
    h
}

/// `Σ_j λ^j · values_j`.
fn lambda_fold(values: &[Ea4], lambda: Ea4) -> Ea4 {
    values.iter().rev().fold(Ea4::ZERO, |acc, v| acc * lambda + *v)
}

/// PROVE a blinded committed carrier for an AIR that reads the next row. As [`prove_air_blinded_bytes`], and the
/// next-row values the gate reads are bound to the commitment by the shift bind. The gate must name its next-row
/// columns (`shifted_cols`).
#[must_use]
pub fn prove_air_blinded_chained_bytes<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let mut rng = SmallRng::try_from_rng(&mut rand::rngs::SysRng::default()).ok()?;
    prove_chained_with(blind_cols(cols, &mut rng), move |g: Ea4| Blinded { inner: make_constraint(g) }, public_bind)
}

/// PROVE a chained carrier with NO blinding rows, for a table that holds no secret (the nullifier band's sub-carrier:
/// public tags and public roots). The same door as [`prove_air_blinded_chained_bytes`] in every other respect: the
/// next-row values the gate reads are bound to the commitment by the shift bind. It exists because blinding doubles the
/// table, and a carrier already at the commitment's size limit (`vars + start_rate − first_fold ≤ 24`) cannot take the
/// extra variable. ⛔ Never for a table with a wallet's secret in it: the row opened at `r` is not hidden here.
#[must_use]
pub fn prove_air_chained_bytes<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    prove_chained_with(cols, make_constraint, public_bind)
}

/// The chained door's one prover: `cols` are the columns as COMMITTED (blinding rows already added, or none) and
/// `make_constraint` builds the gate as SCORED (under the blinding selector, or bare).
fn prove_chained_with<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let params = CarrierParams::LIVE;
    let width = cols.len();
    let h = cols.first().map(Vec::len).unwrap_or(0);
    if width == 0 || h == 0 || !h.is_power_of_two() || cols.iter().any(|c| c.len() != h) {
        return None;
    }
    let nvars = h.trailing_zeros() as usize;
    if nvars < COMMITTED_FOLDING {
        return None;
    }
    let laid = cols.clone();
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = pcs_with(witness.num_variables(), params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, params.first_fold, params.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let next_cols = next_row_columns(&constraint, width)?;
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let mut zc = prove_air_zerocheck(&laid, &constraint, &z, &mut chl);
    // the row at r: a claim on the commitment
    let all: Vec<usize> = (0..width).collect();
    let _ = layout.eval_at(0, &all, &Point::new(zc.r.clone()), &mut chl);
    // the next-row values the gate read, sent and absorbed, then bound: one sumcheck down to one opening at ρ
    let next: Vec<Ea4> = next_cols.iter().map(|c| zc.shifted_opened.get(*c).copied()).collect::<Option<Vec<Ea4>>>()?;
    absorb_shifted_openings(&mut chl, &next);
    let lambda: Ea4 = chl.sample_algebra_element();
    let (mut f, mut s) = shift_bind_tables(&laid, &next_cols, &zc.r, lambda);
    let (mut bind_rounds, mut rho) = (Vec::with_capacity(nvars), Vec::with_capacity(nvars));
    for _ in 0..nvars {
        let round = shift_bind_round(&s, &f);
        absorb_shifted_openings(&mut chl, &round);
        let c: Ea4 = chl.sample_algebra_element();
        s = crate::air_zerocheck::fold_one_var(&s, c);
        f = crate::air_zerocheck::fold_one_var(&f, c);
        bind_rounds.push(round.to_vec());
        rho.push(c);
    }
    let bind_opened = layout.eval_at(0, &next_cols, &Point::new(rho), &mut chl);
    zc.shifted_opened = Vec::new();
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    postcard::to_allocvec(&ChainedAirBundle { shape: (nvars, width), commitment, zc, next, bind_rounds, bind_opened, open }).ok()
}

/// VERIFY a chained carrier against the statement's gate, bind and LAID shape (before blinding doubles the height).
/// The next-row values the gate is scored against are the carrier's `next`, and the shift bind proves them to be the
/// committed columns' own, through an opening that is a claim of the same opening proof as the row at `r`.
/// Fail-closed; never panics.
#[must_use]
pub fn verify_air_blinded_chained_bytes<C, Mk>(bytes: &[u8], make_constraint: Mk, public_bind: &[Fa4], laid_shape: (usize, usize)) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let Some(committed_nvars) = laid_shape.0.checked_add(1) else { return false };
    verify_chained_with(bytes, move |g: Ea4| Blinded { inner: make_constraint(g) }, public_bind, (committed_nvars, laid_shape.1))
}

/// VERIFY a chained carrier proved with no blinding rows ([`prove_air_chained_bytes`]): the statement's shape is the
/// committed shape, and the gate is scored bare. Fail-closed; never panics.
#[must_use]
pub fn verify_air_chained_bytes<C, Mk>(bytes: &[u8], make_constraint: Mk, public_bind: &[Fa4], shape: (usize, usize)) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    verify_chained_with(bytes, make_constraint, public_bind, shape)
}

/// The chained door's one verifier, against the COMMITTED shape and the gate as scored.
fn verify_chained_with<C, Mk>(bytes: &[u8], make_constraint: Mk, public_bind: &[Fa4], committed_shape: (usize, usize)) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    verify_chained_recording(bytes, make_constraint, public_bind, committed_shape, None)
}

/// ⭐ C4 (lane c4, 2026-11-13) — VERIFY a blinded chained carrier AND return the STIR query positions its verifier drew,
/// per query group in proof order. A producer that authenticates the carrier's openings in-circuit needs them; the wire
/// form never carries them (the verifier re-derives them from the transcript). `None` unless the carrier verifies, so a
/// position list is only ever read off a carrier this node accepted.
#[must_use]
pub fn drawn_queries_of_blinded_chained_carrier<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
) -> Option<Vec<Vec<usize>>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    stir_groups_of_blinded_chained_carrier(bytes, make_constraint, public_bind, laid_shape)
        .map(|g| g.into_iter().map(|r| r.indices).collect())
}

/// The record of a STIR query group, as the WHIR verifier saw it (C4).
pub type StirGroup = p3_whir::pcs::verifier::StirGroupRecord<Ea4, <Mmcs16 as Mmcs<Fa4>>::Commitment>;

/// ⭐ C4 — VERIFY a blinded chained carrier AND return every STIR query group as its verifier saw it: the root each group
/// opens, the positions drawn, the folding point, each query's weight in the group's claim, the folds and the claim
/// (`p3_whir::pcs::verifier::StirGroupRecord`). `None` unless the carrier verifies.
#[must_use]
pub fn stir_groups_of_blinded_chained_carrier<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
) -> Option<Vec<StirGroup>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let committed_nvars = laid_shape.0.checked_add(1)?;
    let record = core::cell::RefCell::new(Vec::new());
    verify_chained_recording(
        bytes,
        move |g: Ea4| Blinded { inner: make_constraint(g) },
        public_bind,
        (committed_nvars, laid_shape.1),
        Some(&record),
    )
    .then(|| record.into_inner())
}

fn verify_chained_recording<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    committed_shape: (usize, usize),
    drawn: Option<&core::cell::RefCell<Vec<StirGroup>>>,
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    verify_chained_claims(bytes, make_constraint, public_bind, committed_shape, drawn, None)
}


// ── lane agg — THE LEVEL AGGREGATE'S DOOR MODES (crate::agg_mode; docs/LEVEL-AGGREGATE-SPEC-20261115.md §10) ──────────────
// The two door bodies below call [`agg_door`] first on every TOP-LEVEL call (no recorder, no claims). `Off` returns
// `None` and the body runs exactly as today; `Record` verifies the full carrier and records its core, claims, group
// statements and openings; `Core` accepts only a `CoreCarrier`, verifies its core against its claims and records the
// group statements the block's openings tables must prove. Taken from lane c4's stage A (`c4_statements`, `c4_openings`,
// 2026-11-13), used at block scale instead of sealing every carrier at the door (§14.1f refuted the per-carrier seal).

fn agg_decode_whole<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let (v, rest) = postcard::take_from_bytes::<T>(bytes).ok()?;
    rest.is_empty().then_some(v)
}

fn agg_is_core(open: &WhirProof<Fa4, Ea4, Mmcs16>) -> bool {
    open.rounds.iter().all(|r| r.queries.is_empty())
        && open.final_queries.is_empty()
        && open.query_indices.len() == open.rounds.len() + 1
        && open.query_indices.iter().all(Vec::is_empty)
}

fn agg_strip(open: &mut WhirProof<Fa4, Ea4, Mmcs16>) {
    for r in &mut open.rounds {
        r.queries.clear();
    }
    open.final_queries.clear();
    open.query_indices = vec![Vec::new(); open.rounds.len() + 1];
}

/// One claim per query group (every round, then the final group), from the groups the verifier recorded.
fn agg_claims(groups: &[StirGroup], rounds: usize) -> Vec<Ea4> {
    let mut claims: Vec<Ea4> = groups.iter().map(|g| g.claim).collect();
    claims.resize(rounds + 1, Ea4::ZERO);
    claims
}

/// The openings table's statement of each non-empty recorded group (lane c4's `c4_statements`).
fn agg_statements(groups: &[StirGroup]) -> Option<Vec<crate::stir_group_air::GroupStatement>> {
    use p3_field::Field;
    let mut out = Vec::with_capacity(groups.len());
    for g in groups {
        if g.indices.is_empty() {
            if g.claim != Ea4::ZERO {
                return None;
            }
            continue;
        }
        if !g.leaves.is_power_of_two() || g.leaves < 2 || g.coeffs.len() != g.indices.len() {
            return None;
        }
        let gamma_shift = g.coeffs[0];
        let gamma = match g.coeffs.get(1) {
            Some(&c1) => c1 * gamma_shift.try_inverse()?,
            None => Ea4::ONE,
        };
        let mut c = gamma_shift;
        for &k in &g.coeffs {
            if k != c {
                return None;
            }
            c *= gamma;
        }
        let [root] = g.root.as_ref() else { return None };
        let weights = crate::stir_group_air::fold_weights(&Point::new(g.point.clone()), g.extension);
        out.push(crate::stir_group_air::GroupStatement {
            root: *root,
            row_words: weights.len(),
            depth: g.leaves.trailing_zeros() as usize,
            positions: g.indices.clone(),
            weights,
            gamma,
            gamma_shift,
            claim: g.claim,
        });
    }
    Some(out)
}

/// Each non-empty group's openings, as the table lays them (lane c4's `c4_openings`).
fn agg_openings(
    open: &WhirProof<Fa4, Ea4, Mmcs16>,
    commitment: &<Mmcs16 as Mmcs<Fa4>>::Commitment,
    groups: &[StirGroup],
) -> Option<Vec<Vec<crate::stir_group_air::QueryOpening>>> {
    use crate::stir_group_air::{QueryOpening, SALT_WORDS};
    let drawn: Vec<Vec<usize>> = groups.iter().map(|g| g.indices.clone()).collect();
    let opened = crate::c4_openings::group_openings(open, commitment, &drawn)?;
    opened
        .iter()
        .filter(|g| !g.openings.is_empty())
        .map(|g| {
            g.openings
                .iter()
                .map(|o| {
                    let split = o.values.len().checked_sub(SALT_WORDS)?;
                    let (words, salt) = o.values.split_at(split);
                    Some(QueryOpening { words: words.to_vec(), salt: salt.try_into().ok()?, siblings: o.path.iter().map(|p| p.sibling).collect() })
                })
                .collect()
        })
        .collect()
}

/// The aggregate's door hook for one bundle type. `verify(bytes, record, claims)` is the door's own body; `open_of` and
/// `strip` read and strip the bundle's WHIR opening. `None` = mode `Off`: the caller runs its body as today.
fn agg_door<B: serde::Serialize + serde::de::DeserializeOwned>(
    bytes: &[u8],
    open_of: impl Fn(&B) -> (&WhirProof<Fa4, Ea4, Mmcs16>, &<Mmcs16 as Mmcs<Fa4>>::Commitment),
    strip: impl Fn(&mut B),
    verify: impl FnOnce(&[u8], Option<&core::cell::RefCell<Vec<StirGroup>>>, Option<&[Ea4]>) -> bool,
) -> Option<bool> {
    use crate::agg_mode::{push, CoreCarrier, Mode, Recorded, CORE_TAG};
    match crate::agg_mode::mode() {
        Mode::Off => None,
        Mode::Record => {
            let rec = core::cell::RefCell::new(Vec::new());
            if !verify(bytes, Some(&rec), None) {
                return Some(false);
            }
            let groups = rec.into_inner();
            let Ok(mut b) = postcard::from_bytes::<B>(bytes) else { return Some(false) };
            let (open, commitment) = open_of(&b);
            let (Some(st), Some(op)) = (agg_statements(&groups), agg_openings(open, commitment, &groups)) else { return Some(false) };
            let claims = agg_claims(&groups, open.rounds.len());
            strip(&mut b);
            let Ok(core) = postcard::to_allocvec(&CoreCarrier { tag: CORE_TAG, core: b, claims }) else { return Some(false) };
            push(Recorded { digest: *blake3::hash(bytes).as_bytes(), core, groups: st, openings: op });
            Some(true)
        }
        Mode::Core => {
            let Some(cc) = agg_decode_whole::<CoreCarrier<B>>(bytes) else { return Some(false) };
            if cc.tag != CORE_TAG || !agg_is_core(open_of(&cc.core).0) {
                return Some(false);
            }
            let Ok(core) = postcard::to_allocvec(&cc.core) else { return Some(false) };
            let rec = core::cell::RefCell::new(Vec::new());
            if !verify(&core, Some(&rec), Some(&cc.claims)) {
                return Some(false);
            }
            let Some(st) = agg_statements(&rec.into_inner()) else { return Some(false) };
            push(Recorded { digest: *blake3::hash(bytes).as_bytes(), core: Vec::new(), groups: st, openings: Vec::new() });
            Some(true)
        }
    }
}

/// The chained door's entry: the aggregate's mode hook on a top-level call (lane agg), then the one body.
fn verify_chained_claims<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    committed_shape: (usize, usize),
    drawn: Option<&core::cell::RefCell<Vec<StirGroup>>>,
    claims: Option<&[Ea4]>,
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    if drawn.is_none() && claims.is_none() {
        let mode_verdict = agg_door::<ChainedAirBundle>(
            bytes,
            |b| (&b.open, &b.commitment),
            |b| agg_strip(&mut b.open),
            |by, rec, cl| verify_chained_body(by, &make_constraint, public_bind, committed_shape, rec, cl),
        );
        if let Some(v) = mode_verdict {
            return v;
        }
    }
    verify_chained_body(bytes, make_constraint, public_bind, committed_shape, drawn, claims)
}

/// The chained door's one verifier body: the full carrier (`claims` = `None`) or its core against proven group claims.
fn verify_chained_body<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    committed_shape: (usize, usize),
    drawn: Option<&core::cell::RefCell<Vec<StirGroup>>>,
    claims: Option<&[Ea4]>,
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let Ok(b) = postcard::from_bytes::<ChainedAirBundle>(bytes) else { return false };
    // the STATEMENT's shape first, and the carrier's own lengths against it, before anything is sized by them
    if b.shape != committed_shape {
        return false;
    }
    let (nvars, width) = b.shape;
    if nvars < COMMITTED_FOLDING
        || nvars > MAX_STATEABLE_NVARS
        || width == 0
        || b.zc.opened.len() != width
        || b.zc.r.len() != nvars
        || b.zc.round_evals.len() != nvars
        || !b.zc.shifted_opened.is_empty()
        || b.bind_rounds.len() != nvars
        || b.bind_rounds.iter().any(|round| round.len() != 3)
    {
        return false;
    }
    let params = CarrierParams::LIVE;
    let shapes = vec![p3_sumcheck::table::TableShape::new(nvars, width)];
    let stacked_nvars = {
        let t = Table::new((0..width).map(|_| Poly::<Fa4>::new(vec![Fa4::ZERO; 1 << nvars])).collect());
        PrefixProver::<Fa4, Ea4>::new_witness(vec![t], params.first_fold).num_variables()
    };
    let pcs = pcs_with(stacked_nvars, params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    chl.observe(b.commitment.clone());
    for mask_commit in &b.open.hvzk_mask_commits {
        chl.observe(mask_commit.clone());
    }
    let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
    if b.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples {
        return false;
    }
    for &eval in &b.open.initial_ood_answers {
        lv.add_virtual_eval(eval, &mut chl);
    }
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let Some(next_cols) = next_row_columns(&constraint, width) else { return false };
    if b.next.len() != next_cols.len() || b.bind_opened.len() != next_cols.len() {
        return false;
    }
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    // the gate is scored against the SENT next-row values; a column it reads on the next row is one it named
    let mut next = vec![Ea4::ZERO; width];
    for (value, c) in b.next.iter().zip(&next_cols) {
        next[*c] = *value;
    }
    let zc = AirZerocheckProof { round_evals: b.zc.round_evals.clone(), opened: b.zc.opened.clone(), r: b.zc.r.clone(), shifted_opened: next };
    if !verify_air_zerocheck(&zc, &constraint, &z, &mut chl) {
        return false;
    }
    // the row at r is the commitment's own …
    let all: Vec<usize> = (0..width).collect();
    lv.add_claim_at(0, &all, &b.zc.opened, &Point::new(b.zc.r.clone()), &mut chl);
    // … and so are the next-row values: the shift bind, ending in the next-row columns' opening at ρ
    absorb_shifted_openings(&mut chl, &b.next);
    let lambda: Ea4 = chl.sample_algebra_element();
    let mut claim = lambda_fold(&b.next, lambda);
    let mut rho = Vec::with_capacity(nvars);
    for round in &b.bind_rounds {
        if round[0] + round[1] != claim {
            return false;
        }
        absorb_shifted_openings(&mut chl, round);
        let c: Ea4 = chl.sample_algebra_element();
        claim = crate::air_zerocheck::lagrange_eval(round, c);
        rho.push(c);
    }
    lv.add_claim_at(0, &next_cols, &b.bind_opened, &Point::new(rho.clone()), &mut chl);
    if claim != crate::light_commit::shift_mle(&b.zc.r, &rho) * lambda_fold(&b.bind_opened, lambda) {
        return false;
    }
    let alpha: Ea4 = chl.sample_algebra_element();
    let pcs_constraint = lv.constraint(alpha);
    let mut claimed = Ea4::ZERO;
    pcs_constraint.combine_evals(&mut claimed);
    let mut v = WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
    if let Some(d) = drawn {
        v = v.recording(d);
    }
    if let Some(c) = claims {
        v = v.with_group_claims(c);
    }
    v.verify(&b.open, &mut chl, &b.commitment, pcs_constraint, claimed).is_ok()
}

/// ⭐ C4 STAGE A — a blinded chained carrier's CORE: the carrier with every query opening removed (the bytes a peer
/// receives; the openings are proven in the block's openings table). `None` when the bytes are not a chained carrier.
#[must_use]
pub fn core_of_chained_carrier(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut b: ChainedAirBundle = postcard::from_bytes(bytes).ok()?;
    for r in &mut b.open.rounds {
        r.queries.clear();
    }
    b.open.final_queries.clear();
    b.open.query_indices = vec![Vec::new(); b.open.rounds.len() + 1];
    postcard::to_allocvec(&b).ok()
}

/// ⭐ C4 STAGE A — VERIFY a blinded chained carrier's CORE against one proven claim per query group (rounds, then the
/// final group): the unchanged verifier with the openings' contribution taken from `claims`
/// (`WhirVerifier::with_group_claims`). Returns the groups as the verifier saw them — the statement the block's
/// openings table must prove — or `None` (fail-closed) when the core does not verify against those claims.
#[must_use]
pub fn verify_blinded_chained_core<C, Mk>(
    core: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
    claims: &[Ea4],
) -> Option<Vec<StirGroup>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let committed_nvars = laid_shape.0.checked_add(1)?;
    let record = core::cell::RefCell::new(Vec::new());
    verify_chained_claims(
        core,
        move |g: Ea4| Blinded { inner: make_constraint(g) },
        public_bind,
        (committed_nvars, laid_shape.1),
        Some(&record),
        Some(claims),
    )
    .then(|| record.into_inner())
}

/// ⭐ THE LEVEL AGGREGATE (lane agg, docs/LEVEL-AGGREGATE-SPEC-20261115.md) — the BLINDED COMMITTED door's three
/// stage-A reads, the row-local twins of the chained door's above (the membership carrier is the class that uses this door).
/// VERIFY a full blinded committed carrier and return every STIR query group as its verifier saw it; `None` unless it
/// verifies, so a group record is only ever read off a carrier this node accepted.
#[must_use]
pub fn stir_groups_of_blinded_committed_carrier<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
) -> Option<Vec<StirGroup>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let committed_nvars = laid_shape.0.checked_add(1)?;
    let record = core::cell::RefCell::new(Vec::new());
    verify_committed_claims(
        bytes,
        move |g: Ea4| Blinded { inner: make_constraint(g) },
        public_bind,
        CarrierParams::LIVE,
        (committed_nvars, laid_shape.1),
        Some(&record),
        None,
    )
    .then(|| record.into_inner())
}

/// A committed carrier's CORE: every query opening removed (what a peer holds of an aggregated payment's carrier).
#[must_use]
pub fn core_of_committed_carrier(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    for r in &mut b.open.rounds {
        r.queries.clear();
    }
    b.open.final_queries.clear();
    b.open.query_indices = vec![Vec::new(); b.open.rounds.len() + 1];
    postcard::to_allocvec(&b).ok()
}

/// VERIFY a blinded committed carrier's CORE against one proven claim per query group (rounds, then the final group).
/// Returns the groups as the verifier saw them — the statement the block's openings table must prove — or `None`.
#[must_use]
pub fn verify_blinded_committed_core<C, Mk>(
    core: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
    claims: &[Ea4],
) -> Option<Vec<StirGroup>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let committed_nvars = laid_shape.0.checked_add(1)?;
    let record = core::cell::RefCell::new(Vec::new());
    verify_committed_claims(
        core,
        move |g: Ea4| Blinded { inner: make_constraint(g) },
        public_bind,
        CarrierParams::LIVE,
        (committed_nvars, laid_shape.1),
        Some(&record),
        Some(claims),
    )
    .then(|| record.into_inner())
}

/// ⛔ TEST-ONLY ADVERSARY for the chained door: the prover of [`forge_blinded_next_row_for_tests`] against THIS door.
/// An honest commitment and an honest opened row, all-zero zerocheck rounds, and one SENT next-row value moved until
/// the gate reads zero at `r`. It then lies its way through the shift bind as far as a prover can: every round is the
/// honest one with its value at 0 moved so the round chain holds for the lie, and the opening at `ρ` is the real one,
/// proven by the real opening proof. What is left is the bind's last line, `claim == S(r, ρ) · f(ρ)`, where `f(ρ)` is
/// the commitment's own: a door that checks it refuses the carrier.
#[cfg(test)]
pub(crate) fn forge_blinded_chained_for_tests<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    use p3_field::Field as _;
    let cols = blind_cols(cols, &mut SmallRng::seed_from_u64(0x5417_F7ED));
    let width = cols.len();
    let height = cols.first()?.len();
    let nvars = height.trailing_zeros() as usize;
    let params = CarrierParams::LIVE;
    let laid = cols.clone();
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = pcs_with(witness.num_variables(), params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, params.first_fold, params.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = Blinded { inner: make_constraint(gamma) };
    let next_cols = next_row_columns(&constraint, width)?;
    let _z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let per = constraint.degree(nvars) + 2;
    let (mut round_evals, mut r) = (Vec::with_capacity(nvars), Vec::with_capacity(nvars));
    for _ in 0..nvars {
        let h = vec![Ea4::ZERO; per];
        chl.observe_algebra_slice(&h);
        r.push(chl.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    // honest: the row at r (recorded as the real claim), and the columns' true next-row values at r
    let all: Vec<usize> = (0..width).collect();
    let opened = layout.eval_at(0, &all, &Point::new(r.clone()), &mut chl);
    let truth: Vec<Ea4> = next_cols
        .iter()
        .map(|c| {
            let rotated: Vec<Fa4> = (0..height).map(|i| laid[*c][(i + 1) % height]).collect();
            crate::air_zerocheck::mle_eval(&rotated, &r)
        })
        .collect();
    // the lie: one sent next-row value moved until the gate, scored as the verifier scores it, reads zero
    let mut next = truth.clone();
    let eval = |sent: &[Ea4]| -> Ea4 {
        let mut row = vec![Ea4::ZERO; width];
        for (value, c) in sent.iter().zip(&next_cols) {
            row[*c] = *value;
        }
        let oob = crate::air_zerocheck::OobLatch::new();
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { row.get(c).copied().unwrap_or(Ea4::ZERO) };
        constraint.eval(&Row::new(&opened, &oob), &at, &r)
    };
    let f0 = eval(&next);
    if f0 == Ea4::ZERO {
        return None; // the table satisfies the statement at r: there is nothing to forge
    }
    let mut solved = false;
    for i in 0..next.len() {
        let kept = next[i];
        next[i] = kept + Ea4::ONE;
        let slope = eval(&next) - f0;
        if slope != Ea4::ZERO {
            next[i] = kept - f0 * slope.inverse();
            if eval(&next) == Ea4::ZERO {
                solved = true;
                break;
            }
        }
        next[i] = kept;
    }
    if !solved {
        return None;
    }
    // the shift bind, lied through: each round is the honest table's with its value at 0 moved to keep the chain
    absorb_shifted_openings(&mut chl, &next);
    let lambda: Ea4 = chl.sample_algebra_element();
    let (mut f, mut s) = shift_bind_tables(&laid, &next_cols, &r, lambda);
    let mut claim = lambda_fold(&next, lambda);
    let (mut bind_rounds, mut rho) = (Vec::with_capacity(nvars), Vec::with_capacity(nvars));
    for _ in 0..nvars {
        let mut round = shift_bind_round(&s, &f);
        round[0] = claim - round[1];
        absorb_shifted_openings(&mut chl, &round);
        let c: Ea4 = chl.sample_algebra_element();
        claim = crate::air_zerocheck::lagrange_eval(&round, c);
        s = crate::air_zerocheck::fold_one_var(&s, c);
        f = crate::air_zerocheck::fold_one_var(&f, c);
        bind_rounds.push(round.to_vec());
        rho.push(c);
    }
    let bind_opened = layout.eval_at(0, &next_cols, &Point::new(rho), &mut chl);
    let zc = AirZerocheckProof { round_evals, shifted_opened: Vec::new(), opened, r };
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    postcard::to_allocvec(&ChainedAirBundle { shape: (nvars, width), commitment, zc, next, bind_rounds, bind_opened, open }).ok()
}

/// ⛔ TEST-ONLY: the laid (pre-blinding) shape a blinded carrier DECLARES — what every verify read before
/// DB-213b. For tests whose subject is not the shape and for calibration arms measuring an unpinned engine; no
/// shipped binary carries it.
#[cfg(test)]
#[must_use]
pub(crate) fn declared_blinded_laid_shape_for_tests(bytes: &[u8]) -> (usize, usize) {
    let (n, w) = declared_committed_shape_for_tests(bytes);
    (n.saturating_sub(1), w)
}

/// ⛔ TEST-ONLY: the shape a committed carrier DECLARES (see [`declared_blinded_laid_shape_for_tests`]).
#[cfg(test)]
#[must_use]
pub(crate) fn declared_committed_shape_for_tests(bytes: &[u8]) -> (usize, usize) {
    postcard::from_bytes::<CommittedAirBundle>(bytes).map(|b| b.shape).unwrap_or((0, 0))
}

/// ⛔ TEST-ONLY ADVERSARY (DB-452, the direct-family forgery PORTED to the blinded committed door): a carrier for the
/// statement `make_constraint` / `public_bind` over a laid trace `cols` that does NOT satisfy it. The honest prover in its
/// exact transcript order — blinding rows, the commitment, its OOD answers, γ, z, and the WHIR opening of the claim the
/// committed table really makes at `r` — and the ONE lie of `whir_rec_block::forge_direct_light_decider_for_tests`:
/// all-zero zerocheck rounds and a SENT row the statement's gate accepts at their point, absorbed exactly as the
/// verifier's `add_claim_at` absorbs it. A door that binds the sent row to the commitment refuses it.
#[cfg(test)]
pub(crate) fn forge_blinded_opened_for_tests<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let base: Vec<Ea4> = cols.iter().map(|c| Ea4::from(c[0])).collect();
    let cols = blind_cols(cols, &mut SmallRng::seed_from_u64(0xDB45_2C));
    let width = cols.len();
    let nvars = cols.first()?.len().trailing_zeros() as usize;
    let params = CarrierParams::LIVE;
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = pcs_with(witness.num_variables(), params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, params.first_fold, params.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers =
        (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = Blinded { inner: make_constraint(gamma) };
    let _z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let per = constraint.degree(nvars) + 2;
    let mut round_evals = Vec::with_capacity(nvars);
    let mut r = Vec::with_capacity(nvars);
    for _ in 0..nvars {
        let h = vec![Ea4::ZERO; per];
        chl.observe_algebra_slice(&h);
        r.push(chl.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    let opened = crate::air_zerocheck::solve_opened_for_tests(&constraint, &base, &r)?;
    // The layout records the claim the committed table REALLY makes at r (so the opening below is the honest prover's),
    // on a scratch transcript; the main transcript absorbs the SENT row, as the verifier will.
    let all: Vec<usize> = (0..width).collect();
    let _ = layout.eval_at(0, &all, &Point::new(r.clone()), &mut chl.clone());
    chl.observe_algebra_slice(&opened);
    // no next-row opening: the door's one encoding carries none (2026-11-10), so the lie is the sent row alone
    let zc = AirZerocheckProof { round_evals, shifted_opened: Vec::new(), opened, r };
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    postcard::to_allocvec(&CommittedAirBundle { shape: (nvars, width), commitment, zc, open }).ok()
}

/// ⛔ TEST-ONLY ADVERSARY (2026-11-10, the next-row class): a carrier for the statement `make_constraint` / `public_bind`
/// over a laid trace `cols` that does NOT satisfy it, from a prover that lies ONLY in the next-row openings. Everything
/// the door binds is honest: the commitment, its OOD answers, and the opened row, which IS the committed table's own
/// evaluation at `r` and is opened by the real opening proof. The lie is all-zero zerocheck rounds and next-row
/// openings chosen so the gate vanishes at `r` (a gate with a law `next(c) − …` is affine in that opening, so one
/// opening moved along it zeroes the batched value). A door that takes next-row openings from the wire without tying
/// them to the commitment accepts it for ANY statement of a gate that reads the next row. `None` when the gate reads
/// no next-row cell affinely (a row-local gate: there is nothing to lie about).
#[cfg(test)]
pub(crate) fn forge_blinded_next_row_for_tests<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    use p3_field::Field as _;
    let cols = blind_cols(cols, &mut SmallRng::seed_from_u64(0x5417_F7ED));
    let width = cols.len();
    let height = cols.first()?.len();
    let nvars = height.trailing_zeros() as usize;
    let params = CarrierParams::LIVE;
    let laid = cols.clone();
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = pcs_with(witness.num_variables(), params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, params.first_fold, params.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = Blinded { inner: make_constraint(gamma) };
    let _z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let per = constraint.degree(nvars) + 2;
    let (mut round_evals, mut r) = (Vec::with_capacity(nvars), Vec::with_capacity(nvars));
    for _ in 0..nvars {
        let h = vec![Ea4::ZERO; per];
        chl.observe_algebra_slice(&h);
        r.push(chl.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    // honest: the committed table's own row at r, and its own next-row values at r
    let opened: Vec<Ea4> = laid.iter().map(|c| crate::air_zerocheck::mle_eval(c, &r)).collect();
    let mut next: Vec<Ea4> = laid
        .iter()
        .map(|c| {
            let rotated: Vec<Fa4> = (0..height).map(|i| c[(i + 1) % height]).collect();
            crate::air_zerocheck::mle_eval(&rotated, &r)
        })
        .collect();
    // the lie: one next-row opening moved until the gate reads zero
    let eval = |next: &[Ea4]| -> Ea4 {
        let oob = crate::air_zerocheck::OobLatch::new();
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { next.get(c).copied().unwrap_or(Ea4::ZERO) };
        constraint.eval(&Row::new(&opened, &oob), &at, &r)
    };
    let f0 = eval(&next);
    if f0 != Ea4::ZERO {
        let candidates = constraint.shifted_cols().unwrap_or_else(|| (0..width).collect());
        let mut solved = false;
        for j in candidates {
            let kept = next[j];
            let mut f = [f0; 4];
            for t in 1..4u64 {
                next[j] = kept + Ea4::from(Fa4::from_u64(t));
                f[t as usize] = eval(&next);
            }
            let slope = f[1] - f[0];
            if slope != Ea4::ZERO && f[2] - f[1] == slope && f[3] - f[2] == slope {
                next[j] = kept - f0 * slope.inverse();
                if eval(&next) == Ea4::ZERO {
                    solved = true;
                    break;
                }
            }
            next[j] = kept;
        }
        if !solved {
            return None;
        }
    }
    let all: Vec<usize> = (0..width).collect();
    let _ = layout.eval_at(0, &all, &Point::new(r.clone()), &mut chl);
    let zc = AirZerocheckProof { round_evals, shifted_opened: next, opened, r };
    absorb_shifted_openings(&mut chl, &zc.shifted_opened);
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    postcard::to_allocvec(&CommittedAirBundle { shape: (nvars, width), commitment, zc, open }).ok()
}

/// ⛔ TEST-ONLY ADVERSARY (audit 2026-11-10, the block door): A CARRIER NOBODY PROVED. The commitment is of a GARBAGE
/// table; the zerocheck rounds are all zero; the challenges are the real transcript's own; and ONE cell of the OPENED ROW
/// is moved until the gate reads zero at `r`. The real opening proof is of the garbage table, so the per-transaction door
/// ([`verify_air_blinded_bytes`]) refuses these bytes: the opened row is not the committed table's. A reader that takes
/// the opened row from the BYTES and never checks the opening (a block aggregate laying this carrier as a bound step)
/// has no such refusal. `None` when no opened cell enters the gate affinely.
#[cfg(test)]
pub(crate) fn forge_blinded_opened_row_for_tests<C, Mk>(cols: Vec<Vec<Fa4>>, make_constraint: Mk, public_bind: &[Fa4]) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    use p3_field::Field as _;
    let cols = blind_cols(cols, &mut SmallRng::seed_from_u64(0x0BE7_ED01));
    let width = cols.len();
    let height = cols.first()?.len();
    let nvars = height.trailing_zeros() as usize;
    let params = CarrierParams::LIVE;
    let laid = cols.clone();
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let pcs = pcs_with(witness.num_variables(), params);
    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    let (mut layout, commitment, merkle_data) =
        PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, &mut chl, witness, params.first_fold, params.start_rate);
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(&mut chl)).collect();
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = Blinded { inner: make_constraint(gamma) };
    let _z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let per = constraint.degree(nvars) + 2;
    let (mut round_evals, mut r) = (Vec::with_capacity(nvars), Vec::with_capacity(nvars));
    for _ in 0..nvars {
        let h = vec![Ea4::ZERO; per];
        chl.observe_algebra_slice(&h);
        r.push(chl.sample_algebra_element::<Ea4>());
        round_evals.push(h);
    }
    // the garbage table's own row at r (this door's encoding carries no next row: the gate is scored with none)
    let mut opened: Vec<Ea4> = laid.iter().map(|c| crate::air_zerocheck::mle_eval(c, &r)).collect();
    let _ = height;
    // the lie: one OPENED cell moved until the gate reads zero
    let eval = |opened: &[Ea4]| -> Ea4 {
        let oob = crate::air_zerocheck::OobLatch::new();
        let at = |_c: usize, _p: &[Ea4]| -> Ea4 { Ea4::ZERO };
        constraint.eval(&Row::new(opened, &oob), &at, &r)
    };
    let f0 = eval(&opened);
    if f0 != Ea4::ZERO {
        let mut solved = false;
        for j in 0..width {
            let kept = opened[j];
            let mut f = [f0; 4];
            for t in 1..4u64 {
                opened[j] = kept + Ea4::from(Fa4::from_u64(t));
                f[t as usize] = eval(&opened);
            }
            let slope = f[1] - f[0];
            if slope != Ea4::ZERO && f[2] - f[1] == slope && f[3] - f[2] == slope {
                opened[j] = kept - f0 * slope.inverse();
                if eval(&opened) == Ea4::ZERO {
                    solved = true;
                    break;
                }
            }
            opened[j] = kept;
        }
        if !solved {
            return None;
        }
    }
    let all: Vec<usize> = (0..width).collect();
    let _ = layout.eval_at(0, &all, &Point::new(r.clone()), &mut chl);
    let zc = AirZerocheckProof { round_evals, shifted_opened: Vec::new(), opened, r };
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    postcard::to_allocvec(&CommittedAirBundle { shape: (nvars, width), commitment, zc, open }).ok()
}

/// ⛔ TEST-ONLY (DB-452 privacy census): every evaluation a committed carrier SENDS — the opened row, the next-row
/// openings and the commitment's OOD answers.
#[cfg(test)]
pub(crate) fn committed_sent_evaluations_for_tests(bytes: &[u8]) -> Vec<Ea4> {
    let Ok(b) = postcard::from_bytes::<CommittedAirBundle>(bytes) else { return Vec::new() };
    b.zc.opened.into_iter().chain(b.zc.shifted_opened).chain(b.open.initial_ood_answers).collect()
}

/// PROVE an AIR over `cols` with its opened values BOUND to a commitment of the trace.
///
/// `public_bind` is the statement: observed first, so a proof for one statement cannot be replayed for
/// another. Returns `None` fail-closed on any malformed shape.
#[must_use]
pub fn prove_air_committed_bytes<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    prove_air_committed_bytes_with(cols, make_constraint, public_bind, CarrierParams::LIVE)
}
#[must_use]
pub fn prove_air_committed_bytes_with<C, Mk>(
    cols: Vec<Vec<Fa4>>,
    make_constraint: Mk,
    public_bind: &[Fa4],
    params: CarrierParams,
) -> Option<Vec<u8>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let width = cols.len();
    let h = cols.first().map(Vec::len).unwrap_or(0);
    if width == 0 || h == 0 || !h.is_power_of_two() || cols.iter().any(|c| c.len() != h) {
        return None; // fail-closed: a ragged or empty trace has no shape a verifier can rebuild
    }
    let nvars = h.trailing_zeros() as usize;
    if nvars < COMMITTED_FOLDING {
        return None; // fail-closed: the trace must be at least the folding floor
    }
    let cols_for_zc = cols.clone();
    let table = Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect());
    let witness = PrefixProver::<Fa4, Ea4>::new_witness(vec![table], params.first_fold);
    let stacked_nvars = witness.num_variables();
    let pcs = pcs_with(stacked_nvars, params);

    let mut chl = challenger();
    // C4 PROBE (2026-11-13): phase times to this process's own log, behind the progress switch the light prover uses
    let progress = std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok();
    let t_commit = std::time::Instant::now();
    // 1. THE STATEMENT FIRST.
    for &f in public_bind {
        chl.observe(f);
    }
    // 2. THE TRACE COMMITMENT, before any challenge exists.
    let (mut layout, commitment, merkle_data) = PrefixProver::<Fa4, Ea4>::commit(
        &pcs.dft,
        &pcs.mmcs,
        &mut chl,
        witness,
        params.first_fold,
        params.start_rate,
    );
    // 2b. THE COMMITMENT'S OUT-OF-DOMAIN ANSWERS — the adapter's `open` draws these first, and the
    //     verifier replays them first; a divergence here desynchronises every challenge below.
    let mut open = pcs.config.empty_proof();
    open.initial_ood_answers = (0..pcs.config.commitment_ood_samples)
        .map(|_| layout.add_virtual_eval(&mut chl))
        .collect();
    // 3. THE ZEROCHECK, on challenges drawn AFTER the commitment.
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = make_constraint(gamma);
    // ⛔ THIS DOOR CARRIES NO NEXT-ROW OPENING (2026-11-10, the next-row class closed at the door). It binds ONE thing
    // to the commitment, the row at `r`; a next-row value sent beside it would be a number the sender chose
    // (`forge_blinded_next_row_for_tests`: income nobody received, a notice no carrier signed, a tag nobody owned, a
    // note in no tree). So none is sent, and the verifier scores the gate with none: a gate that reads the next row
    // is refused there, for an honest prover as for a forger. Such a gate goes through the chained door
    // ([`prove_air_blinded_chained_bytes`]); one that names its next-row columns is refused here, before any work.
    if constraint.shifted_cols().is_some_and(|c| !c.is_empty()) {
        return None;
    }
    let commit_ms = t_commit.elapsed().as_millis();
    let t_zc = std::time::Instant::now();
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    let mut zc = prove_air_zerocheck(&cols_for_zc, &constraint, &z, &mut chl);
    zc.shifted_opened = Vec::new();
    let zc_ms = t_zc.elapsed().as_millis();
    let t_open = std::time::Instant::now();
    // 4. THE CLAIM AT THE ZEROCHECK'S OWN POINT — this is what the opening proof will bind.
    let all: Vec<usize> = (0..width).collect();
    let pt_r = Point::new(zc.r.clone());
    let _ = layout.eval_at(0, &all, &pt_r, &mut chl);
    // 5. THE OPENING PROOF.
    pcs.prove(&mut open, &mut chl, layout, merkle_data);
    if progress {
        eprintln!(
            "[committed-phase] 2^{nvars} rows x {width} cols (stacked arity {stacked_nvars}): commit {commit_ms} ms, zerocheck {zc_ms} ms, opening {} ms",
            t_open.elapsed().as_millis()
        );
    }
    postcard::to_allocvec(&CommittedAirBundle { shape: (nvars, width), commitment, zc, open }).ok()
}

/// VERIFY a committed AIR carrier. Every structural input is PUBLIC (the shape rides the bundle and is
/// checked against the constraint's own arity), so the circuit and the layout are rebuilt from the
/// statement rather than taken from the prover's object. Fail-closed; never panics.
#[must_use]
pub fn verify_air_committed_bytes<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    expected_shape: (usize, usize),
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    verify_air_committed_bytes_with(bytes, make_constraint, public_bind, CarrierParams::LIVE, expected_shape)
}
#[must_use]
pub fn verify_air_committed_bytes_with<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    params: CarrierParams,
    // ⛔ DB-213b — the statement's `(nvars, width)`; the carrier's own declaration is refused unless equal.
    expected_shape: (usize, usize),
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    verify_committed_claims(bytes, make_constraint, public_bind, params, expected_shape, None, None)
}

/// The committed door's entry: the aggregate's mode hook on a top-level call (lane agg), then the one body.
fn verify_committed_claims<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    params: CarrierParams,
    expected_shape: (usize, usize),
    record: Option<&core::cell::RefCell<Vec<StirGroup>>>,
    claims: Option<&[Ea4]>,
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    if record.is_none() && claims.is_none() {
        let mode_verdict = agg_door::<CommittedAirBundle>(
            bytes,
            |b| (&b.open, &b.commitment),
            |b| agg_strip(&mut b.open),
            |by, rec, cl| verify_committed_body(by, &make_constraint, public_bind, params, expected_shape, rec, cl),
        );
        if let Some(v) = mode_verdict {
            return v;
        }
    }
    verify_committed_body(bytes, make_constraint, public_bind, params, expected_shape, record, claims)
}

/// The committed door's one verifier body: the full carrier (`claims` = `None`) or its CORE against one proven claim per
/// query group (lane agg, the level aggregate: the block's openings table proves those claims). `record` copies every
/// STIR query group as the verifier saw it. Neither option changes a verdict on a full carrier.
fn verify_committed_body<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    params: CarrierParams,
    expected_shape: (usize, usize),
    record: Option<&core::cell::RefCell<Vec<StirGroup>>>,
    claims: Option<&[Ea4]>,
) -> bool
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let b: CommittedAirBundle = match postcard::from_bytes::<CommittedAirBundle>(bytes) {
        Ok(b) => b,
        Err(e) => {
            if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
                eprintln!("[committed-air] FAIL at decode: {e:?}");
            }
            return false;
        }
    };
    // ⛔⛔⛔ DB-213b — THE STATEMENT'S SHAPE, BEFORE ANYTHING BELOW IS SIZED BY THE CARRIER'S.
    //
    // The stacked-arity computation below lays a `width × 2^nvars` zero table, and `nvars` was the carrier's
    // number up to MAX_STATEABLE_NVARS = 32: a few hundred bytes declaring (32, 1) made the verifier allocate
    // 2^32 cells — at every door that verifies a committed carrier off the wire. Only the caller knows the
    // statement, so the caller states the shape and anything else is refused here, first.
    if b.shape != expected_shape {
        if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
            eprintln!("[committed-air] FAIL at step 0: shape {:?} is not the statement's {:?}", b.shape, expected_shape);
        }
        return false;
    }
    let (nvars, width) = b.shape;
    // ⛔⛔⛔ THE SHAPE IS A REMOTE PARTY'S NUMBER, AND EVERY ALLOCATION BELOW IS SIZED BY IT.
    //
    // MEASURED by `lane_e_shape_fuzz::e1_no_attacker_chosen_shape_panics_or_verifies` the moment item 1
    // pointed it at this door: a carrier declaring `width = usize::MAX` made this function UNWIND with
    // "capacity overflow" — `(0..width).collect()` and the `1 << nvars` column polys are both reached
    // before anything cross-checks the declaration. A panic in a verifier on remote bytes is a
    // denial-of-service, not a refusal, and E-1's whole premise is that a carrier declaring its own
    // trace shape must be REFUSED rather than believed.
    //
    // So the declaration is cross-checked against what the bundle actually SHIPS, first, before a single
    // allocation is sized by it. `zc.opened` names every committed column and `zc.r` one challenge per
    // variable, so both lengths are the shape, stated twice by the prover — and a liar disagrees here.
    if nvars < COMMITTED_FOLDING
        || nvars > MAX_STATEABLE_NVARS
        || width == 0
        || b.zc.opened.len() != width
        || b.zc.r.len() != nvars
        || b.zc.round_evals.len() != nvars
        // ⛔ ONE ENCODING, AND IT HAS NO NEXT-ROW OPENING (2026-11-10). This door binds the row at `r` and nothing
        // else, so a carrier that ships next-row openings is refused before anything reads them; the zerocheck below
        // then scores the gate against an EMPTY next row, and a gate that reads one is refused by its own latch.
        || !b.zc.shifted_opened.is_empty()
    {
        if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
            eprintln!(
                "[committed-air] FAIL at step 0: shape ({nvars},{width}) vs opened {} r {} rounds {} next-row {}",
                b.zc.opened.len(),
                b.zc.r.len(),
                b.zc.round_evals.len(),
                b.zc.shifted_opened.len()
            );
        }
        return false;
    }
    let shapes = vec![p3_sumcheck::table::TableShape::new(nvars, width)];
    let stacked_nvars = {
        // The stacked arity is a public function of the shape — recomputed, never trusted.
        let t = Table::new((0..width).map(|_| Poly::<Fa4>::new(vec![Fa4::ZERO; 1 << nvars])).collect());
        PrefixProver::<Fa4, Ea4>::new_witness(vec![t], params.first_fold).num_variables()
    };
    let pcs = pcs_with(stacked_nvars, params);

    let mut chl = challenger();
    for &f in public_bind {
        chl.observe(f);
    }
    chl.observe(b.commitment.clone());
    for mask_commit in &b.open.hvzk_mask_commits {
        chl.observe(mask_commit.clone());
    }
    let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
    if b.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples {
        if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
            eprintln!("[committed-air] FAIL at step 2b: ood {} != {}", b.open.initial_ood_answers.len(), pcs.config.commitment_ood_samples);
        }
        return false; // fail-closed: the OOD count is public; a short list desynchronises the replay
    }
    for &eval in &b.open.initial_ood_answers {
        lv.add_virtual_eval(eval, &mut chl);
    }
    let gamma: Ea4 = chl.sample_algebra_element();
    let constraint = make_constraint(gamma);
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    // 3. The zerocheck: the round chain AND `eq(z,r)·C_γ(opened) == claim_last`.
    if !verify_air_zerocheck(&b.zc, &constraint, &z, &mut chl) {
        if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
            eprintln!("[committed-air] FAIL at step 3: the zerocheck");
        }
        return false;
    }
    // 4/5. The opened values must BE the commitment's evaluations at `r`.
    let all: Vec<usize> = (0..width).collect();
    let pt_r = Point::new(b.zc.r.clone());
    if b.zc.opened.len() != width {
        if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
            eprintln!("[committed-air] FAIL at step 4: opened {} != width {width}", b.zc.opened.len());
        }
        return false; // fail-closed: the opened row must name every committed column
    }
    lv.add_claim_at(0, &all, &b.zc.opened, &pt_r, &mut chl);
    let alpha: Ea4 = chl.sample_algebra_element();
    let pcs_constraint = lv.constraint(alpha);
    let mut claimed = Ea4::ZERO;
    pcs_constraint.combine_evals(&mut claimed);
    let mut v = WhirVerifier::new(&pcs.config, &pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
    if let Some(r) = record {
        v = v.recording(r);
    }
    if let Some(c) = claims {
        v = v.with_group_claims(c);
    }
    match v.verify(&b.open, &mut chl, &b.commitment, pcs_constraint, claimed) {
        Ok(_) => true,
        Err(e) => {
            if std::env::var("COMMITTED_AIR_TRACE").is_ok() {
                eprintln!("[committed-air] FAIL at step 4/5: the PCS opening — {e:?}");
            }
            false
        }
    }
}

/// H12 — WHIR SOUNDNESS IS MEASURED IN THE PROVEN REGIME (lane-harness finding 2026-10-04; user cardinal
/// `feedback_100bit_pq_minimum`: ≥ 100-bit PROVEN for every production proof). `pcs_with` targets `COMMITTED_SECURITY`
/// under `SecurityAssumption::CapacityBound` — in p3-whir's own words a CONJECTURE (RS codes decodable up to capacity with
/// mutual correlated agreement) — so the query counts it derives reach 100 bits only if the conjecture holds. This module
/// takes every PRODUCTION shape exactly as `pcs_with` builds it and re-scores its ACTUAL numbers (queries, grinds, OOD
/// samples, per round) under the regimes the library labels assumption-free (`UniqueDecoding`) and theorem-backed
/// (`JohnsonBound`: list decoding up to the Johnson radius, BCSS25 proximity gaps). The scoring is p3-whir's own
/// `soundness.rs`, called with the regime swapped — nothing re-derived here.
pub mod proven_bits {
    use super::*;
    use p3_field::Field;

    /// Every production proof shape by name, with its weakest term scored under the theorem-backed regime: what a running node
    /// reports at `/proof_bits`, so the 100-bit floor is read off the shapes the binary actually builds.
    pub fn report() -> Vec<(String, f64, String)> {
        production_shapes()
            .into_iter()
            .map(|(name, cfg)| {
                let (bits, term) = scored_bits(&cfg, proven_regime(&cfg));
                (name, bits, term)
            })
            .collect()
    }

    /// ⭐ SPEED R10 — THE THEOREM-BACKED REGIME A SHAPE IS SCORED IN: the Johnson regime it was BUILT in when it was
    /// built in one, `JohnsonBound` otherwise (a shape sized under the capacity conjecture is re-scored at the proven
    /// regime's reference slack, as H12 always has). A Johnson regime is one slack `eta` of the same theorem
    /// (`SecurityAssumption::JohnsonBoundWide`), and a shape's query counts and fold grinds are sized together AT its
    /// slack: scored at another slack, either its queries or its folds are credited with bits they were not given. Any
    /// slack gives a valid bound, so the score in the built regime is a proven floor, not a choice of the kinder one —
    /// `every_production_whir_config_proves_at_least_100_bits_under_the_johnson_bound` also prints what each shape scores
    /// at the other slack.
    pub(crate) fn proven_regime(cfg: &WhirConfig<Ea4, Fa4, Chl>) -> SecurityAssumption {
        match cfg.params.soundness_type {
            SecurityAssumption::JohnsonBoundWide => SecurityAssumption::JohnsonBoundWide,
            _ => SecurityAssumption::JohnsonBound,
        }
    }

    /// The weakest soundness term (bits) of `cfg` when its actual numbers are scored under `regime`, and that term's name.
    /// Every term `WhirConfig::new` budgets is scored: commitment OOD, the starting fold, each round's queries (+ its
    /// query grind), combination, OOD and fold (+ its fold grind), the final queries (+ grind) and the final fold.
    pub(crate) fn scored_bits(cfg: &WhirConfig<Ea4, Fa4, Chl>, regime: SecurityAssumption) -> (f64, String) {
        let fb = Ea4::bits();
        let ud = matches!(regime, SecurityAssumption::UniqueDecoding);
        let (nv0, r0) = (cfg.num_variables, cfg.params.starting_log_inv_rate);
        let mut worst = (f64::INFINITY, String::new());
        let mut take = |name: String, bits: f64| {
            if bits < worst.0 {
                worst = (bits, name);
            }
        };
        if !ud {
            take("commitment ood".into(), regime.ood_error(nv0, r0, fb, cfg.commitment_ood_samples));
        }
        // ⭐ SPEED R4-G: EVERY FOLDING SUB-ROUND IS SCORED AT THE CODE ITS GRIND WAS SIZED AT. A configuration built by
        // `WhirConfig::new` alone sizes a whole group at its start (`nv`), and is scored there — its numbers are what they
        // were. One sized per fold (`fold_grinds`) grinds sub-round `s` against the code with `nv − s` variables
        // (`with_fold_grinds_at_the_folded_code` names the argument), so sub-round `s` is scored at `nv − s` with ITS grind:
        // a sub-round ground one bit short of its bound scores under the target here, on every production shape.
        let per_fold = cfg.fold_grinds.is_some();
        let fold_bits = |nv: usize, rate: usize, s: usize, grind: usize| {
            let at = if per_fold { nv - s } else { nv };
            regime.prox_gaps_error(at, rate, fb, 2).min(regime.fold_sumcheck_error(fb, at, rate)) + grind as f64
        };
        for (i, grind) in cfg.starting_fold_grinds().into_iter().enumerate() {
            take(format!("starting fold, sub-round {} (+{grind} grind)", i + 1), fold_bits(nv0, r0, i + 1, grind));
        }
        let mut rate = r0;
        for (i, rc) in cfg.round_parameters.iter().enumerate() {
            take(
                format!("round {i} queries ({} at rate 1/{}, +{} grind)", rc.num_queries, 1usize << rate, rc.pow_bits),
                regime.queries_error(rate, rc.num_queries) + rc.pow_bits as f64,
            );
            take(
                format!("round {i} combination"),
                regime.queries_combination_error(fb, rc.num_variables, rc.log_inv_rate, rc.ood_samples, rc.num_queries) + rc.pow_bits as f64,
            );
            if !ud {
                take(format!("round {i} ood"), regime.ood_error(rc.num_variables, rc.log_inv_rate, fb, rc.ood_samples));
            }
            for (j, grind) in cfg.round_fold_grinds(i).into_iter().enumerate() {
                take(
                    format!("round {i} fold, sub-round {} (+{grind} grind)", j + 1),
                    fold_bits(rc.num_variables, rc.log_inv_rate, j + 1, grind),
                );
            }
            rate = rc.log_inv_rate;
        }
        take(
            format!("final queries ({} at rate 1/{}, +{} grind)", cfg.final_queries, 1usize << rate, cfg.final_pow_bits),
            regime.queries_error(rate, cfg.final_queries) + cfg.final_pow_bits as f64,
        );
        take("final fold".into(), (fb - 1) as f64 + cfg.final_folding_pow_bits as f64);
        worst
    }

    /// Every production shape: the LIVE carrier at every stacked variable count an AIR carrier can declare below the
    /// two-adicity, the certificate's witness carrier and its fixed-table carrier at their exact release shapes.
    pub(crate) fn production_shapes() -> Vec<(String, WhirConfig<Ea4, Fa4, Chl>)> {
        use crate::certificate_door::{CertParams, CERT_CARRIER, CERT_FIXED_CARRIER, CERT_T_BITS};
        let mut shapes: Vec<(String, WhirConfig<Ea4, Fa4, Chl>)> =
            (8..=26).map(|v| (format!("LIVE carrier, {v} vars"), pcs_with(v, CarrierParams::LIVE).config)).collect();
        // every light arity the round admits (8..=26), each at the rate `light_params` gives it (1/8 up to 25, 1/4 at 26)
        shapes.extend((8..=26).filter(|&v| crate::light_commit::light_arity_admissible(v)).map(|v| {
            let p = crate::light_commit::light_params(v);
            (format!("LIGHT_COMMIT_PARAMS at rate 1/2^{}, {v} vars", p.start_rate), pcs_with(v, p).config)
        }));
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the certificate shapes settle");
        let w_vars = CERT_T_BITS + crate::universal_row::V_BITS;
        shapes.push((format!("CERT_CARRIER witness, {w_vars} vars"), pcs_with(w_vars, CERT_CARRIER).config));
        shapes.push((format!("CERT_FIXED_CARRIER fixed table, {} vars", p.fixed_vars), pcs_with(p.fixed_vars, CERT_FIXED_CARRIER).config));
        shapes
    }

}

#[cfg(test)]
mod h12_proven_soundness {
    use super::proven_bits::*;
    use super::*;
    use p3_field::Field;

    /// RED until every production shape can actually be ground: no grind a production config asks may exceed the
    /// one-word grinder's ceiling (≥ 31 bits panics the grinder; MEASURED 2026-10-26: `LIVE` at growth 3 asked fold
    /// grinds 31–38 bits at 23–26 stacked variables, and the 26-variable band sub-carrier panicked after 232 s). Prints
    /// each shape's rate schedule, queries and grinds — the per-shape cost record.
    #[test]
    fn every_production_whir_config_grinds_within_its_ceiling() {
        use p3_field::PrimeField64;
        assert_eq!(ONE_WORD_GRIND_CEILING, <Fa4 as Field>::bits() - 7, "the one-word grinder's ceiling is F::bits() − 7");
        assert!((1u64 << FIELD_GRIND_LIMIT) < Fa4::ORDER_U64 && (1u64 << (FIELD_GRIND_LIMIT + 1)) >= Fa4::ORDER_U64, "the grinder's hard bound");
        let mut reds = Vec::new();
        for (name, cfg) in production_shapes() {
            let fold = max_fold_grind_bits(&cfg);
            let query = cfg.round_parameters.iter().map(|r| r.pow_bits).chain([cfg.final_pow_bits]).max().expect("the final queries are always present");
            // the money path's carriers (LIVE and the light rounds built on it) are held to the one-word ceiling
            let cap = if name.starts_with("LIVE") || name.starts_with("LIGHT") { ONE_WORD_GRIND_CEILING } else { FIELD_GRIND_LIMIT };
            eprintln!(
                "[grind] {name}: rates {:?} | rounds (q, qgrind, fgrind) {:?} | final q {} grind {} | start fold {} | max fold {fold} query {query} (cap {cap})",
                cfg.params.round_log_inv_rates,
                cfg.round_parameters.iter().map(|r| (r.num_queries, r.pow_bits, r.folding_pow_bits)).collect::<Vec<_>>(),
                cfg.final_queries,
                cfg.final_pow_bits,
                cfg.starting_folding_pow_bits
            );
            if fold.max(query) > cap {
                reds.push(format!("{name}: fold grind {fold}, query grind {query} bits > {cap}"));
            }
        }
        assert!(reds.is_empty(), "⛔ {} production shape(s) ask a grind above their ceiling:\n  {}", reds.len(), reds.join("\n  "));
    }

    /// MEASUREMENT (run explicitly, release): what reaching `COMMITTED_SECURITY` PROVEN costs. For each regime the library
    /// labels proven, each candidate (start rate, query grind) and each production shape: the query vector, the score in
    /// the candidate's own regime (≥ target by construction), and — for the certificate — the verifier-program row
    /// ESTIMATE (≈ 30 rows per WHIR query, census 2026-09-28: 16,414 rows at queries [87, 21, 12, 9] + 7 against 16,382
    /// usable at T = 2^14), and — for the live carrier — the REAL proof bytes and prove time of a 3-column AIR at 2^10 and
    /// 2^14 rows. The two-adicity cap (`vars + rate − folding_0 ≤ 24`) refuses some certificate candidates; they print as
    /// refused. Output feeds the H12 decision (regime + per-carrier rate/grind) measured against the 1.8 MB pillar.
    #[test]
    #[ignore]
    fn h12_cost_of_proven_security_by_regime_rate_and_grind() {
        use crate::certificate_door::{CertParams, CERT_CARRIER, CERT_FIXED_CARRIER, CERT_T_BITS};
        use super::gates::{honest_cols, make};
        use SecurityAssumption::{CapacityBound, JohnsonBound, UniqueDecoding};
        let target = COMMITTED_SECURITY as f64;
        let pb = [Fa4::from_u64(0x412), Fa4::from_u64(1)];
        let regimes = [("CB", CapacityBound), ("JB", JohnsonBound), ("UD", UniqueDecoding)];
        // LIVE carriers: real proves at two heights per candidate
        for (rname, regime) in regimes {
            for (rate, pow) in [(1usize, 0usize), (1, 16), (2, 0), (2, 16), (3, 16), (3, 20)] {
                let params = CarrierParams { regime, ..CarrierParams::legacy(rate, pow) };
                let mut line = format!("[h12-cost] LIVE {rname} rate 1/{} grind {pow:>2}:", 1usize << rate);
                for h_bits in [10usize, 14] {
                    let cols = honest_cols(1 << h_bits);
                    let t = std::time::Instant::now();
                    let bytes = prove_air_committed_bytes_with(cols, make(), &pb, params).expect("the candidate proves");
                    let ms = t.elapsed().as_millis();
                    let ok = verify_air_committed_bytes_with(&bytes, make(), &pb, params, declared_committed_shape_for_tests(&bytes));
                    assert!(ok, "the candidate's own proof must verify");
                    let (nvars, _) = declared_committed_shape_for_tests(&bytes);
                    let cfg = pcs_with(nvars, params).config;
                    let (own, _) = scored_bits(&cfg, regime);
                    assert!(own + 1.0 >= target, "a candidate must reach the target in its own regime ({own:.1})");
                    line.push_str(&format!(
                        " | 2^{h_bits} rows ({nvars} vars): {} B, {ms} ms, queries {:?}+{}, own-regime {own:.1}",
                        bytes.len(),
                        cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
                        cfg.final_queries
                    ));
                }
                eprintln!("{line}");
            }
        }
        // the CERTIFICATE: shapes only (a 2^27 witness is not proven here), rows estimated from the census slope
        let p = CertParams::new(CERT_T_BITS, CERT_CARRIER, CERT_FIXED_CARRIER).expect("the certificate shapes settle");
        let w_vars = CERT_T_BITS + crate::universal_row::V_BITS;
        const ROWS_AT_CENSUS: f64 = 16_414.0; // queries [87, 21, 12, 9] + 7 at CERT_CARRIER (20 bits), 2026-09-28 run 2
        const QUERIES_AT_CENSUS: f64 = 87.0 + 21.0 + 12.0 + 9.0 + 7.0;
        const ROWS_PER_QUERY: f64 = 30.0;
        const USABLE_ROWS: f64 = 16_382.0;
        for (rname, regime) in regimes {
            for (rate, pow, send) in [(1usize, 24usize, 7usize), (1, 28, 7), (1, 32, 7), (2, 24, 7), (2, 28, 7)] {
                let params = CarrierParams { send_vars: send, regime, ..CarrierParams::legacy(rate, pow) };
                let Ok(cfg) = std::panic::catch_unwind(|| pcs_with(w_vars, params).config) else {
                    eprintln!("[h12-cost] CERT witness {rname} rate 1/{} grind {pow}: REFUSED by WhirConfig::new (two-adicity: {w_vars} + {rate} − 4 > 24)", 1usize << rate);
                    continue;
                };
                let (own, _) = scored_bits(&cfg, regime);
                let total_q: usize = cfg.round_parameters.iter().map(|r| r.num_queries).sum::<usize>() + cfg.final_queries;
                let rows_est = ROWS_AT_CENSUS + (total_q as f64 - QUERIES_AT_CENSUS) * ROWS_PER_QUERY;
                eprintln!(
                    "[h12-cost] CERT witness {rname} rate 1/{} grind {pow:>2} send {send}: queries {:?}+{} = {total_q}, own-regime {own:.1}, fold grinds {:?}, rows ≈ {rows_est:.0} vs {USABLE_ROWS:.0} usable → {}",
                    1usize << rate,
                    cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
                    cfg.final_queries,
                    cfg.round_parameters.iter().map(|r| r.folding_pow_bits).collect::<Vec<_>>(),
                    if rows_est <= USABLE_ROWS { "FITS the T = 2^14 fixpoint (estimate)" } else { "DOES NOT FIT (estimate)" }
                );
            }
            for (rate, pow) in [(4usize, 16usize), (4, 24), (4, 28)] {
                let params = CarrierParams { regime, ..CarrierParams::legacy(rate, pow) };
                let cfg = pcs_with(p.fixed_vars, params).config;
                let (own, _) = scored_bits(&cfg, regime);
                eprintln!(
                    "[h12-cost] CERT fixed {rname} rate 1/{} grind {pow:>2}: queries {:?}+{}, own-regime {own:.1}",
                    1usize << rate,
                    cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
                    cfg.final_queries
                );
            }
        }
    }

    /// MEASUREMENT (config only, seconds): the CERTIFICATE's shape search under the proven regimes.
    /// MEASURED 2026-10-04 16:3x by `h12_cost_of_proven_security_by_regime_rate_and_grind`: at 27 vars, rate 1/2 (the
    /// only rate folding 4 admits), JohnsonBound needs 268 queries (rows ≈ 20,374 > 16,382 usable) and fold grinds
    /// [25, 28, 32, 35] bits — a 2^35 grind is hours; the fixed table under JB doubles its queries too ([40, 23, 16] + 12).
    /// ROOT-LAYER: the numbers are read from `WhirConfig::new`, the one producer of every round's queries and grinds, on
    /// `ProtocolParameters` built here directly — two levers `CarrierParams` cannot express: a ROUND-0 FOLDING FACTOR of 5
    /// or 6 (27 + 2 − 5 = 24 admits rate 1/4 at ~0.93 proven bits per query instead of 0.43; at 28 vars = T = 2^15 it is
    /// the only admissible shape at all, doubling the row budget) and a GENTLER RATE SCHEDULE (the default grows the inverse
    /// rate by folding − 1 per round; a smaller step keeps ρ larger in the deep rounds, where the Johnson prox-gaps term
    /// `ρ^(−3/2)` is what forces the fold grinds). MUST-STAY-GREEN: no production config is touched — `pcs_with` and every
    /// carrier constant stay as they are until a candidate measured here is chosen and landed with its own pins.
    /// Per candidate: queries per round, fold grinds (max must stay ≤ 30, the carrier's own cap), the own-regime score, and
    /// the verifier-row ESTIMATE (≈ 30 rows per query, census 2026-09-28; each 16 elements of leaf beyond the first adds
    /// ~1 row per round-0 query).
    #[test]
    #[ignore]
    fn h12_certificate_shape_search() {
        use SecurityAssumption::{JohnsonBound, UniqueDecoding};
        let target = COMMITTED_SECURITY as f64;
        const ROWS_AT_CENSUS: f64 = 16_414.0;
        const QUERIES_AT_CENSUS: f64 = 87.0 + 21.0 + 12.0 + 9.0 + 7.0;
        const ROWS_PER_QUERY: f64 = 30.0;
        // (name, witness vars, usable rows at that T, start rate, folding per phase). `FoldingFactor::PerRound` folds until
        // ≤ MAX_NUM_VARIABLES_TO_SEND_COEFFS (6) variables remain, so every schedule sums to vars − 6: 4 rounds + a final
        // 6-variable polynomial (today's carrier sends at 7 via ConstantSendAt; the one-variable difference is 64 vs 128
        // final coefficients). The two-adicity gate is `vars + start_rate − folds[0] ≤ 24` at every shape below.
        let shapes: [(&str, usize, f64, usize, Vec<usize>); 5] = [
            ("T=2^14 fold 4 first, rate 1/2 (today's rate)", 27, 16_382.0, 1, vec![4, 4, 4, 4, 5]),
            ("T=2^14 fold 5 first, rate 1/4", 27, 16_382.0, 2, vec![5, 4, 4, 4, 4]),
            ("T=2^14 fold 6 first, rate 1/8", 27, 16_382.0, 3, vec![6, 4, 4, 4, 3]),
            ("T=2^15 fold 5 first, rate 1/2", 28, 32_766.0, 1, vec![5, 4, 4, 4, 5]),
            ("T=2^15 fold 6 first, rate 1/4", 28, 32_766.0, 2, vec![6, 4, 4, 4, 4]),
        ];
        for (rname, regime) in [("JB", JohnsonBound), ("UD", UniqueDecoding)] {
            for (sname, w_vars, usable, start_rate, folds) in &shapes {
                for growth in [3usize, 2, 1] {
                    for pow in [24usize, 28] {
                        let mut rates = Vec::new();
                        let mut rate = *start_rate;
                        for f in &folds[..folds.len() - 1] {
                            rate += growth.min(*f - 1);
                            rates.push(rate);
                        }
                        let params = ProtocolParameters {
                            hiding: true,
                            security_level: COMMITTED_SECURITY,
                            pow_bits: pow,
                            round_log_inv_rates: rates.clone(),
                            folding_factor: FoldingFactor::PerRound(folds.clone()),
                            soundness_type: regime,
                            starting_log_inv_rate: *start_rate,
                        };
                        let Ok(cfg) = std::panic::catch_unwind(|| WhirConfig::<Ea4, Fa4, Chl>::new(*w_vars, params)) else {
                            eprintln!("[h12-cert] {rname} {sname} growth +{growth} grind {pow}: REFUSED by WhirConfig::new");
                            continue;
                        };
                        let (own, ow) = scored_bits(&cfg, regime);
                        let queries: Vec<usize> = cfg.round_parameters.iter().map(|r| r.num_queries).collect();
                        let grinds: Vec<usize> = cfg.round_parameters.iter().map(|r| r.folding_pow_bits).collect();
                        let round0_q = queries.first().copied().expect("the certificate has at least one WHIR round");
                        let total_q: usize = queries.iter().sum::<usize>() + cfg.final_queries;
                        let leaf_extra = (1usize << folds[0]) / 16 - 1;
                        let rows_est = ROWS_AT_CENSUS + (total_q as f64 - QUERIES_AT_CENSUS) * ROWS_PER_QUERY + (round0_q * leaf_extra) as f64;
                        let max_grind = grinds.iter().copied().chain([cfg.starting_folding_pow_bits]).max().expect("at least the starting fold");
                        eprintln!(
                            "[h12-cert] {rname} {sname} growth +{growth} grind {pow}: rates {rates:?} queries {queries:?}+{} = {total_q}, fold grinds {grinds:?} (start {}), max grind 2^{max_grind} {}, own-regime {own:.1} ({ow}), rows ≈ {rows_est:.0} vs {usable:.0} → {}",
                            cfg.final_queries,
                            cfg.starting_folding_pow_bits,
                            if max_grind <= 30 { "OK" } else { "TOO SLOW" },
                            if rows_est <= *usable { "FITS (estimate)" } else { "DOES NOT FIT (estimate)" }
                        );
                        assert!(own + 1.0 >= target, "a candidate reaches the target in its own regime ({own:.1})");
                    }
                }
            }
        }
    }

    /// RED until every production shape scores ≥ `COMMITTED_SECURITY` bits under the JOHNSON BOUND — the user's ruling of
    /// 2026-10-04 (AskUserQuestion, after the measured costs in docs/H12-WHIR-PROVEN-SOUNDNESS.md): the Johnson bound is the
    /// launch standard (its core theorem — proximity gaps for RS codes up to the Johnson radius, BCIKS20/BCSS25 — is
    /// proven; the one documented assumption is mutual correlated agreement up to that radius), and UNIQUE DECODING — the
    /// regime the library labels free of every assumption — is the post-launch hardening step, tracked as its own census
    /// row. Both scores are printed; the unique-decoding one is the record for that row. A shape that does not even reach
    /// its own sizing regime's target is a construction bug and fails on its own line.
    #[test]
    fn every_production_whir_config_proves_at_least_100_bits_under_the_johnson_bound() {
        use SecurityAssumption::{JohnsonBound, UniqueDecoding};
        let target = COMMITTED_SECURITY as f64;
        let mut reds = Vec::new();
        let mut wide_shapes = 0usize;
        for (name, cfg) in production_shapes() {
            let (own, ow) = scored_bits(&cfg, cfg.params.soundness_type);
            // SPEED R10: the Johnson regime the shape was built in (`proven_regime`); `JohnsonBound` for every other.
            let proven = proven_regime(&cfg);
            let (jb, jw) = scored_bits(&cfg, proven);
            let (ud, uw) = scored_bits(&cfg, UniqueDecoding);
            eprintln!(
                "[h12] {name}: queries {:?} + {} final — sized under {:?} {own:.1} ({ow}) | {proven:?} {jb:.1} ({jw}) | UniqueDecoding {ud:.1} ({uw})",
                cfg.round_parameters.iter().map(|r| r.num_queries).collect::<Vec<_>>(),
                cfg.final_queries,
                cfg.params.soundness_type
            );
            assert!(own + 1.0 >= target, "{name}: the config does not reach its own sizing regime's target: {own:.1} bits ({ow})");
            if jb < target {
                reds.push(format!("{name}: {jb:.1} bits under the Johnson bound at its slack ({proven:?}; weakest: {jw}); {ud:.1} under unique decoding ({uw})"));
            }
            // ⛔ SPEED R10 — A SLACK IS ONE ACCOUNT, NOT TWO. A shape built at the wider slack has fewer grind bits on
            // its folds than the reference slack asks (2.43 fewer, less at most one of rounding) and more queries than
            // it asks; scored at the reference slack its folds fall short. So its 100 bits cannot be reached by
            // picking, per term, whichever slack is kinder — and its query count is exactly what its own slack asks.
            if proven == SecurityAssumption::JohnsonBoundWide {
                wide_shapes += 1;
                let (at_reference, why) = scored_bits(&cfg, JohnsonBound);
                if cfg.starting_fold_grinds().iter().any(|g| *g > 0) {
                    assert!(
                        at_reference < target,
                        "⛔ {name}: built at the wider slack it still scores {at_reference:.1} bits at the reference slack ({why}) — its folds are ground deeper than its own regime asks"
                    );
                }
                // and one query fewer in its first round is under the target in its own regime
                if let Some(first) = cfg.round_parameters.first() {
                    let mut cut = cfg.clone();
                    cut.round_parameters[0].num_queries = first.num_queries - 1;
                    let (bits, weakest) = scored_bits(&cut, proven);
                    assert!(bits < target && weakest.starts_with("round 0 queries"), "⛔ {name}: one first-round query fewer still scores {bits:.1} bits ({weakest}) — the count is not what the slack asks");
                }
            }
        }
        assert!(wide_shapes > 0, "CALIBRATION: the light decider's shapes are built at the wider slack");
        assert!(
            reds.is_empty(),
            "⛔ H12: {} production WHIR shape(s) are below {} bits under the JOHNSON BOUND (the user's launch standard) — the target holds only under the CapacityBound CONJECTURE:\n  {}",
            reds.len(),
            COMMITTED_SECURITY,
            reds.join("\n  ")
        );
    }
}

#[cfg(test)]
mod gates {
    use super::*;
    use crate::air_zerocheck::Row;

    /// A minimal row-local AIR: `col0 + col1 - col2 == 0`. Real enough to forge against, small enough
    /// that a failure is the MECHANISM and not the AIR.
    pub(super) struct SumGate {
        gamma: Ea4,
    }
    impl AirConstraint for SumGate {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let _ = self.gamma;
            local[0] + local[1] - local[2]
        }
    }
    pub(super) fn make() -> impl Fn(Ea4) -> SumGate + Clone {
        |gamma: Ea4| SumGate { gamma }
    }

    pub(super) fn honest_cols(h: usize) -> Vec<Vec<Fa4>> {
        let a: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64(i as u64 + 1)).collect();
        let b: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64((i as u64 + 1) * 3)).collect();
        let c: Vec<Fa4> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        vec![a, b, c]
    }

    /// ⭐⭐⭐ THE GATE §BD-2 AND §BD-3 EXIST FOR: an AIR carrier whose opened values are BOUND.
    ///
    /// CONTROL FIRST — the honest carrier proves and verifies, so every refusal below is the binding
    /// and not a broken construction. Then the exact forgery that passes the DIRECT path: a
    /// self-consistent zerocheck over values the prover chose, with no committed trace behind them.
    #[test]
    fn a_committed_carrier_verifies_and_a_forged_opening_is_refused() {
        let pb = [Fa4::from_u64(0xBD_2), Fa4::from_u64(7)];
        let cols = honest_cols(1 << 10);
        let t = std::time::Instant::now();
        let bytes = prove_air_committed_bytes(cols, make(), &pb).expect("the honest AIR proves");
        let prove_ms = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let ok = verify_air_committed_bytes(&bytes, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&bytes));
        eprintln!(
            "[committed-air] CONTROL: honest carrier proves {prove_ms} ms, verifies {} ms, {} B, ok={ok}",
            t.elapsed().as_millis(),
            bytes.len()
        );
        assert!(ok, "CONTROL FAILED: the honest committed carrier must verify");

        // ⛔ A DIFFERENT STATEMENT must refuse — the bind is observed before the commitment.
        let other = [Fa4::from_u64(0xBD_2), Fa4::from_u64(8)];
        assert!(
            !verify_air_committed_bytes(&bytes, make(), &other, crate::committed_air::declared_committed_shape_for_tests(&bytes)),
            "⛔ a carrier verified under a statement it was not proved for"
        );

        // ⛔⛔⛔ THE §BD-2 FORGERY, EXACTLY: tamper the opened row so the zerocheck still closes but the
        // values are no longer the committed trace's. In the direct path this passes; here the opening
        // proof is checked against a commitment fixed before `r` existed.
        let mut b: CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        b.zc.opened[0] += Ea4::ONE;
        b.zc.opened[2] += Ea4::ONE; // keeps col0+col1-col2 == 0, so the AIR itself is still satisfied
        let forged = postcard::to_allocvec(&b).expect("re-encodes");
        let v = verify_air_committed_bytes(&forged, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&forged));
        eprintln!("[committed-air] AIR-CONSISTENT tampered opening (col0+1, col2+1): verifies={v}");
        assert!(
            !v,
            "⛔⛔⛔ §BD-2 IS NOT CLOSED: an opened row the committed trace does not contain still \
             verifies. The opening proof is not binding the zerocheck's values to the commitment."
        );

        // ⛔ AND A SUBSTITUTED COMMITMENT must refuse — a prover cannot point at someone else's trace.
        let other_cols = {
            let mut c = honest_cols(1 << 10);
            c[0][0] += Fa4::ONE;
            c[2][0] += Fa4::ONE;
            c
        };
        let other_bytes =
            prove_air_committed_bytes(other_cols, make(), &pb).expect("a second honest carrier");
        let ob: CommittedAirBundle = postcard::from_bytes(&other_bytes).expect("decodes");
        let mut swapped: CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        swapped.commitment = ob.commitment;
        let sv = verify_air_committed_bytes(
            &postcard::to_allocvec(&swapped).expect("re-encodes"),
            make(),
            &pb,
            crate::committed_air::declared_committed_shape_for_tests(&postcard::to_allocvec(&swapped).expect("re-encodes")),
        );
        eprintln!("[committed-air] SUBSTITUTED commitment: verifies={sv}");
        assert!(!sv, "⛔ a carrier verified against a commitment it was not proved for");
    }

    /// ⭐⭐⭐ DB-382 (T0 PRIVACY, 2026-10-04): the hiding commitment's salts and the HVZK masks are the prover's
    /// BLINDING. They were seeded from PUBLIC constants (`COMMITTED_AIR_SEED + 7` here, `REC_DECIDER_SEED + 1 / + 7` on
    /// the direct path), so every salt was recomputable by anyone and the "hiding" leaves could be dictionary-tested
    /// against witness guesses. Each prove now draws 256 OS bits (`whir_rec_block::fresh_prover_seed`).
    /// CONTROL first: under ONE pinned seed two proves are byte-identical, so the difference measured next is the
    /// blinding's and not the prover's. Then UNPINNED: two proves of the SAME statement differ in their commitment
    /// roots and in their bytes, and BOTH verify — the root is no function of the words alone.
    #[test]
    fn two_unpinned_proves_of_one_statement_differ_in_their_hiding_commitments_and_both_verify() {
        let pb = [Fa4::from_u64(0xDB_382), Fa4::from_u64(1)];
        let shape = |b: &[u8]| crate::committed_air::declared_committed_shape_for_tests(b);
        let (p1, p2) = {
            let _pinned = crate::whir_rec_block::pin_prover_seed_for_test(Some([0x82u8; 32]));
            (
                prove_air_committed_bytes(honest_cols(1 << 10), make(), &pb).expect("proves (pinned blinding)"),
                prove_air_committed_bytes(honest_cols(1 << 10), make(), &pb).expect("proves again (pinned blinding)"),
            )
        };
        assert!(
            p1 == p2,
            "CONTROL FAILED: two proves under one pinned blinding seed differ ({} vs {} B) — the prover itself is \
             nondeterministic, so a difference between fresh-blinding proves would prove nothing",
            p1.len(),
            p2.len()
        );
        let _fresh = crate::whir_rec_block::pin_prover_seed_for_test(None);
        let a = prove_air_committed_bytes(honest_cols(1 << 10), make(), &pb).expect("proves (fresh blinding)");
        let b = prove_air_committed_bytes(honest_cols(1 << 10), make(), &pb).expect("proves again (fresh blinding)");
        let ab: CommittedAirBundle = postcard::from_bytes(&a).expect("decodes");
        let bb: CommittedAirBundle = postcard::from_bytes(&b).expect("decodes");
        assert!(
            postcard::to_allocvec(&ab.commitment).expect("encodes") != postcard::to_allocvec(&bb.commitment).expect("encodes"),
            "⛔ DB-382: two proves of one statement laid the SAME hiding commitment — the salts are a function of public \
             data, and the commitment hides nothing"
        );
        assert!(a != b, "⛔ DB-382: two proves of one statement are byte-identical — no fresh blinding was drawn");
        assert!(verify_air_committed_bytes(&a, make(), &pb, shape(&a)), "the first freshly-blinded proof must verify");
        assert!(verify_air_committed_bytes(&b, make(), &pb, shape(&b)), "the second freshly-blinded proof must verify");
        assert!(verify_air_committed_bytes(&p1, make(), &pb, shape(&p1)), "the pinned control proof must verify");
        eprintln!(
            "[db382] pinned pair byte-identical ({} B); two fresh-blinding proves differ in their commitment root and bytes; all three verify",
            p1.len()
        );
    }

    /// ⭐⭐⭐ THE §BD-2 FORGERY ITSELF, AT THIS LAYER. The direct path accepts a zerocheck whose opened
    /// row the prover simply chose (measured: zero evals with honestly-derived `r` verify). Here the
    /// same freedom is attempted: take an honest carrier and replace its ENTIRE opened row with zeros,
    /// keeping everything else. The AIR `col0+col1-col2` is satisfied by zeros, so nothing but the
    /// commitment can refuse it.
    #[test]
    fn the_exact_forgery_that_passes_the_direct_path_is_refused_here() {
        let pb = [Fa4::from_u64(0xBD_2F)];
        let bytes = prove_air_committed_bytes(honest_cols(1 << 10), make(), &pb).expect("proves");
        assert!(
            verify_air_committed_bytes(&bytes, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&bytes)),
            "CONTROL: the honest carrier must verify, or the refusal below proves nothing"
        );
        let mut b: CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        for v in b.zc.opened.iter_mut() {
            *v = Ea4::ZERO;
        }
        for v in b.zc.shifted_opened.iter_mut() {
            *v = Ea4::ZERO;
        }
        let forged = postcard::to_allocvec(&b).expect("re-encodes");
        let v = verify_air_committed_bytes(&forged, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&forged));
        eprintln!("[committed-air] §BD-2 ZERO-ROW forgery (the direct path accepts this): verifies={v}");
        assert!(
            !v,
            "⛔⛔⛔ §BD-2 IS NOT CLOSED: a zero opened row — the exact object the direct light decider \
             accepts — still verifies. The commitment is not binding the zerocheck."
        );
    }

    /// ⛔⛔⛔ THE §BE-1 QUESTION AT THIS LAYER: does a committed carrier still carry its witness?
    /// A constant column's multilinear extension equals that constant EVERYWHERE, so a height-1
    /// trace replicated up the rows opens to its own secret at any point. This measures whether a
    /// REAL (non-constant) trace's openings still expose row values.
    #[test]
    fn a_committed_carriers_openings_are_scanned_for_the_trace_values() {
        let pb = [Fa4::from_u64(0xBE_1)];
        let h = 1usize << 10;
        // Distinctive values so a hit cannot be chance.
        let a: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64(0x5AFE_0000 + i as u64)).collect();
        let b: Vec<Fa4> = (0..h).map(|i| Fa4::from_u64(0x6BEEF_00 + i as u64)).collect();
        let c: Vec<Fa4> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        let secrets: Vec<u64> = a
            .iter()
            .chain(b.iter())
            .map(|v| <Fa4 as p3_field::PrimeField64>::as_canonical_u64(v))
            .collect();
        let bytes =
            prove_air_committed_bytes(vec![a, b, c], make(), &pb).expect("proves");
        let bundle: CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
        let mut limbs: Vec<u64> = Vec::new();
        for v in bundle.zc.opened.iter().chain(bundle.zc.shifted_opened.iter()) {
            for &x in <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v) {
                limbs.push(<Fa4 as p3_field::PrimeField64>::as_canonical_u64(&x));
            }
        }
        let hits = secrets.iter().filter(|s| limbs.contains(s)).count();
        eprintln!(
            "[committed-air] §BE-1 scan: {} trace values, {} opened limbs, IN THE CLEAR={hits}",
            secrets.len(),
            limbs.len()
        );
        assert_eq!(
            hits, 0,
            "⛔⛔⛔ a committed carrier still carries {hits} of its own trace values in the clear"
        );
    }
}

/// ⭐ §BF-SIZE — DOES THE COMMITTED CARRIER HOLD AT PRODUCTION SHAPE, AND IS TALL CHEAPER THAN WIDE?
///
/// The production spend-validity carrier is 12,885 columns × 32 rows — the depth-64 Merkle path unrolled
/// sideways. The SAME cell count as a tall trace of ~200 columns × 2,048 rows. A commitment is a Merkle
/// tree over cells, and the zerocheck's opened row is ONE value PER COLUMN, so the shape decides both the
/// prove cost and how much the opening reveals. Measured, not argued.
///
/// Run: cargo test -p usdm-decider --release bf_shape_probe -- --ignored --nocapture
#[cfg(test)]
mod bf_shape_probe {
    use super::*;
    use crate::air_zerocheck::Row;

    struct Sum3 {
        gamma: Ea4,
    }
    impl AirConstraint for Sum3 {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let _ = self.gamma;
            // One residual per column triple, so WIDTH is real work rather than dead columns.
            let mut acc = Ea4::ZERO;
            let mut i = 0usize;
            while i + 2 < local.len() {
                acc += local[i] + local[i + 1] - local[i + 2];
                i += 3;
            }
            acc
        }
    }

    fn cols_for(width: usize, height: usize) -> Vec<Vec<Fa4>> {
        let mut cols: Vec<Vec<Fa4>> = Vec::with_capacity(width);
        for c in 0..width {
            cols.push(
                (0..height)
                    .map(|r| Fa4::from_u64(((c as u64) << 20) ^ (r as u64 + 1)))
                    .collect(),
            );
        }
        // Make every third column the sum of the two before it, so the AIR is satisfied.
        let mut i = 0usize;
        while i + 2 < width {
            for r in 0..height {
                cols[i + 2][r] = cols[i][r] + cols[i + 1][r];
            }
            i += 3;
        }
        cols
    }

    #[test]
    #[ignore] // measurement probe
    fn bf_shape_probe() {
        let pb = [Fa4::from_u64(0xBF_51_2E)];
        for (label, width, height) in [
            ("TALL   ~200 x 2048", 201usize, 2048usize),
            ("SQUARE ~800 x 512", 801usize, 512usize),
            ("WIDE  12885 x 32 (production spend carrier)", 12_885usize, 32usize),
        ] {
            let cells = width * height;
            let cols = cols_for(width, height);
            let t = std::time::Instant::now();
            let made = prove_air_committed_bytes(cols, |g: Ea4| Sum3 { gamma: g }, &pb);
            let pm = t.elapsed().as_millis();
            match made {
                Some(bytes) => {
                    let t = std::time::Instant::now();
                    let ok = verify_air_committed_bytes(&bytes, |g: Ea4| Sum3 { gamma: g }, &pb, crate::committed_air::declared_committed_shape_for_tests(&bytes));
                    eprintln!(
                        "[bf-shape] {label}: {cells} cells → prove {pm} ms · verify {} ms · {} B · ok={ok}",
                        t.elapsed().as_millis(),
                        bytes.len()
                    );
                }
                None => eprintln!("[bf-shape] {label}: {cells} cells → prover REFUSED after {pm} ms"),
            }
        }
    }
}

/// ⛔⛔⛔ §BG — THE DIRECT PATH DOES NOT ENFORCE AN AIR; IT ENFORCES ONE γ-LINEAR COMBINATION OF IT.
///
/// `verify_air_zerocheck` closes with `eq(z,r)·C_γ(opened) == claim_last`. `C_γ` is the γ-power batch of
/// the AIR's residuals, `opened` is NEVER observed into the transcript before `r` is drawn, and γ is
/// sampled BEFORE the row is chosen. So a prover who knows γ can pick a row whose individual residuals
/// are all WRONG while their γ-combination is exactly right — one equation, many unknowns.
///
/// For a spend carrier that means: violate conservation, keep the batch at zero, and the gate that
/// decides whether a spend is real says yes. This gate constructs that row explicitly on both paths.
#[cfg(test)]
mod gamma_cancellation {
    use super::*;
    use crate::air_zerocheck::Row;
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes, AirDirectBundle,
    };

    /// TWO independent residuals, γ-batched — the shape every real AIR has.
    struct TwoSums {
        gamma: Ea4,
    }
    impl AirConstraint for TwoSums {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let r0 = local[0] + local[1] - local[2]; // "conservation"
            let r1 = local[3] + local[4] - local[5]; // "the other gate"
            r0 + self.gamma * r1
        }
    }
    fn make() -> impl Fn(Ea4) -> TwoSums + Clone {
        |gamma: Ea4| TwoSums { gamma }
    }

    fn honest(h: usize) -> Vec<Vec<Fa4>> {
        let mk = |k: u64| -> Vec<Fa4> { (0..h).map(|i| Fa4::from_u64(k * 1000 + i as u64 + 1)).collect() };
        let (a, b, d, e) = (mk(1), mk(2), mk(4), mk(5));
        let c: Vec<Fa4> = a.iter().zip(b.iter()).map(|(x, y)| *x + *y).collect();
        let f: Vec<Fa4> = d.iter().zip(e.iter()).map(|(x, y)| *x + *y).collect();
        vec![a, b, c, d, e, f]
    }

    /// The γ that BOTH sides derive. The forger reads it exactly as the verifier will.
    fn gamma_of_direct(bytes: &[u8], pb: &[Fa4]) -> Ea4 {
        // The extractor replays the verifier's transcript and hands back the same challenges it draws;
        // the forger needs only γ, which is sampled before any row value is observed.
        let b: AirDirectBundle = postcard::from_bytes(bytes).expect("decodes");
        let (_v, _o, _nv, _per) = crate::whir_rec_block::extract_air_direct_carrier_rows(bytes, pb)
            .expect("the forger replays the public transcript");
        // `extract_air_direct_carrier_rows` exposes the round data; γ itself is re-derivable from the
        // same walk, so recompute it here the way the verifier does.
        let _ = b;
        crate::whir_rec_block::gamma_of_air_direct_carrier(bytes, pb).expect("γ is public")
    }

    #[test]
    fn a_row_that_violates_every_constraint_but_cancels_in_gamma_is_measured_on_both_paths() {
        let pb = [Fa4::from_u64(0xB6), Fa4::from_u64(11)];
        let h = 1usize << 10;

        // ── THE DIRECT PATH (what production uses today) ──────────────────────────────────────────
        let d_bytes = prove_air_direct_light_decider_selfcontained_bytes(honest(h), make(), &pb)
            .expect("the honest AIR proves on the direct path");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&d_bytes, make(), &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&d_bytes)),
            "CONTROL: the honest direct carrier must verify"
        );
        let gamma = gamma_of_direct(&d_bytes, &pb);
        let mut fb: AirDirectBundle = postcard::from_bytes(&d_bytes).expect("decodes");
        // r0 += γ  and  r1 += −1  ⇒  batch += γ + γ·(−1) = 0. Both gates now BROKEN, batch untouched.
        fb.zc.opened[0] += gamma;
        fb.zc.opened[3] -= Ea4::ONE;
        let forged_direct = postcard::to_allocvec(&fb).expect("re-encodes");
        let direct_passes =
            verify_air_direct_light_decider_selfcontained_bytes(&forged_direct, make(), &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&forged_direct));

        // ── THE COMMITTED PATH (§BF) ──────────────────────────────────────────────────────────────
        let c_bytes = prove_air_committed_bytes(honest(h), make(), &pb)
            .expect("the honest AIR proves on the committed path");
        assert!(
            verify_air_committed_bytes(&c_bytes, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&c_bytes)),
            "CONTROL: the honest committed carrier must verify"
        );
        let mut cb: CommittedAirBundle = postcard::from_bytes(&c_bytes).expect("decodes");
        let cgamma = crate::whir_rec_block::gamma_of_air_direct_carrier(&c_bytes, &pb)
            .unwrap_or(gamma); // shape differs; the attack does not depend on which γ is used
        cb.zc.opened[0] += cgamma;
        cb.zc.opened[3] -= Ea4::ONE;
        let forged_committed = postcard::to_allocvec(&cb).expect("re-encodes");
        let committed_passes = verify_air_committed_bytes(&forged_committed, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&forged_committed));

        eprintln!(
            "[§BG] TAMPERED γ-cancelling row: direct path verifies={direct_passes} · committed path verifies={committed_passes}"
        );
        // ⭐ BOTH REFUSE A TAMPER. The direct path binds `zc.opened` INDIRECTLY: `add_claim_at` observes
        // it, so changing it moves every later challenge and `prover_rand` no longer matches. That is a
        // real binding and this pin records it — the direct path's weakness is NOT tampering.
        assert!(!direct_passes, "a tampered direct carrier must be refused");
        assert!(!committed_passes, "a tampered committed carrier must be refused");

        // ⛔⛔⛔ THE ATTACK THAT ACTUALLY WORKS — A FRESHLY PROVED FORGERY, NOT A TAMPER.
        //
        // §BD-2/§BD-3 never tampered with anything: they LAID a trace of their choosing and proved it
        // honestly. The proof is then internally consistent by construction, so no transcript binding
        // can notice. What decides soundness is whether the AIR's STATEMENT is vacuous for that trace.
        // For the recursion AIR it is (zeros satisfy a sumcheck-replay relation). Measured here on
        // BOTH paths with the same AIR, so the comparison is exact.
        let zero_trace: Vec<Vec<Fa4>> = (0..6).map(|_| vec![Fa4::ZERO; h]).collect();
        let d_zero = prove_air_direct_light_decider_selfcontained_bytes(zero_trace.clone(), make(), &pb)
            .map(|b| verify_air_direct_light_decider_selfcontained_bytes(&b, make(), &pb, crate::whir_rec_block::declared_direct_shape_for_tests(&b)));
        let c_zero = prove_air_committed_bytes(zero_trace, make(), &pb)
            .map(|b| verify_air_committed_bytes(&b, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&b)));
        eprintln!(
            "[§BG] FRESHLY PROVED zero trace (the real §BD-2 shape): direct={d_zero:?} committed={c_zero:?}"
        );
        // ⛔ This is NOT a defect of either path for THIS AIR — a zero row genuinely satisfies
        // `col0+col1-col2 == 0`, so an honest prover may prove it. It is recorded to make the
        // distinction explicit and to stop anyone reading the committed path as a fix for §BD-2:
        // ⭐⭐⭐ A COMMITMENT BINDS A PROVER TO A TRACE. IT DOES NOT MAKE A VACUOUS STATEMENT MEANINGFUL.
        // §BD-2/§BD-3 close only when the recursion AIR constrains `claimed_final` against the opened
        // values and anchors the opening chain — see docs/FUNDS-LOSS-KILL-LIST.md §BD-2.
    }
}

#[cfg(test)]
mod blinding_gates {
    use super::*;
    use crate::air_zerocheck::Row;

    /// A NON-HOMOGENEOUS row-local AIR shaped like every value-carrying gate: the public statement
    /// enters its own constraint. `col0 + col1 - col2 == PUB`.
    struct ValueGate {
        gamma: Ea4,
        pub_val: Ea4,
    }
    impl AirConstraint for ValueGate {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let _ = self.gamma;
            local[0] + local[1] - local[2] - self.pub_val
        }
    }
    const PUB: u64 = 4242;
    fn make() -> impl Fn(Ea4) -> ValueGate + Clone {
        move |gamma: Ea4| ValueGate { gamma, pub_val: Ea4::from(Fa4::from_u64(PUB)) }
    }

    /// THE PRODUCTION SHAPE: one logical row replicated up the trace — exactly what the real spend
    /// carrier does, and exactly why its MLE opens to the secret at every point.
    fn constant_trace(h: usize, v_in: u64, v_out: u64) -> (Vec<Vec<Fa4>>, Vec<u64>) {
        let c2 = v_in + v_out - PUB;
        (
            vec![vec![Fa4::from_u64(v_in); h], vec![Fa4::from_u64(v_out); h], vec![Fa4::from_u64(c2); h]],
            vec![v_in, v_out, c2],
        )
    }

    fn secrets_in_the_clear(bytes: &[u8], secrets: &[u64]) -> usize {
        let b: CommittedAirBundle = postcard::from_bytes(bytes).expect("decodes");
        let mut limbs: Vec<u64> = Vec::new();
        for v in b.zc.opened.iter().chain(b.zc.shifted_opened.iter()) {
            for &x in <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v) {
                limbs.push(<Fa4 as p3_field::PrimeField64>::as_canonical_u64(&x));
            }
        }
        secrets.iter().filter(|s| limbs.contains(s)).count()
    }

    /// ⭐⭐⭐ §BE-1 AT THE SHAPE THAT LEAKS — the gate this whole item exists for.
    ///
    /// CALIBRATION FIRST: an UNBLINDED committed carrier over a constant trace must expose its own
    /// values, or this test is not measuring the §BE-1 leak. Then the blinded one must expose none,
    /// and must still verify, and must still REFUSE a trace that breaks the AIR.
    #[test]
    fn a_blinded_carrier_hides_a_constant_traces_values_and_still_refuses_a_bad_one() {
        let pb = [Fa4::from_u64(PUB)];
        let h = 1usize << 10;
        // Distinctive amounts so a hit cannot be chance.
        let (cols, secrets) = constant_trace(h, 1_000_000_007, 999_999_937);

        // ── CALIBRATION: unblinded, the production shape leaks. ───────────────────────────────────
        let plain = prove_air_committed_bytes(cols.clone(), make(), &pb).expect("proves");
        assert!(verify_air_committed_bytes(&plain, make(), &pb, crate::committed_air::declared_committed_shape_for_tests(&plain)), "the unblinded carrier verifies");
        let leaked = secrets_in_the_clear(&plain, &secrets);
        eprintln!("[blind] CALIBRATION — UNBLINDED constant trace: {leaked}/{} values in the clear", secrets.len());
        assert_eq!(
            leaked,
            secrets.len(),
            "⛔ CALIBRATION FAILED: the unblinded carrier did NOT leak, so this test cannot show that \
             blinding fixes anything. Re-measure §BE-1 before trusting the result below."
        );

        // ── THE FIX: blinded. ─────────────────────────────────────────────────────────────────────
        let t = std::time::Instant::now();
        let blinded = prove_air_blinded_bytes(cols, make(), &pb).expect("the blinded carrier proves");
        let pm = t.elapsed().as_millis();
        let t = std::time::Instant::now();
        let ok = verify_air_blinded_bytes(&blinded, make(), &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&blinded));
        let hidden = secrets_in_the_clear(&blinded, &secrets);
        eprintln!(
            "[blind] BLINDED constant trace: prove {pm} ms · verify {} ms · {} B · verifies={ok} · values in the clear={hidden}/{}",
            t.elapsed().as_millis(), blinded.len(), secrets.len()
        );
        assert!(ok, "⛔ the blinded carrier must still VERIFY — hiding may not cost soundness");
        assert_eq!(
            hidden, 0,
            "⛔⛔⛔ §BE-1 IS NOT CLOSED: {hidden} of the trace's own values still ride the carrier in \
             the clear after blinding."
        );

        // ── AND HIDING MAY NOT BUY PERMISSIVENESS: a trace that BREAKS the AIR must still be refused.
        let bad = {
            let (mut c, _) = constant_trace(h, 1_000_000_007, 999_999_937);
            c[2][0] += Fa4::ONE; // one row now violates col0+col1−col2 == PUB
            c
        };
        let refused = prove_air_blinded_bytes(bad, make(), &pb)
            .map(|b| verify_air_blinded_bytes(&b, make(), &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&b)));
        eprintln!("[blind] AIR-VIOLATING trace under blinding: {refused:?}");
        assert!(
            refused != Some(true),
            "⛔⛔⛔ THE BLINDING SELECTOR SWALLOWED A REAL VIOLATION. `(1 − x[0])` must be 1 on every \
             row the caller supplied; if a broken row passes, the selector is exempting real data."
        );

        // ⛔⛔⛔ PROBE THE SELECTOR CONVENTION AT ITS SHARPEST POINT — THE LAST REAL ROW.
        //
        // `(1 − x[0])` is 1 on the caller's rows only if `x[0]` is the MOST-significant variable. If the
        // convention were the other way, the exempted rows would be interleaved and HALF the caller's
        // data would go unconstrained — a violation in row 0 might still be caught while one at the
        // boundary sails through. So break the LAST real row specifically.
        let bad_last = {
            let (mut c, _) = constant_trace(h, 1_000_000_007, 999_999_937);
            c[2][h - 1] += Fa4::ONE;
            c
        };
        let last_verdict = prove_air_blinded_bytes(bad_last, make(), &pb)
            .map(|b| verify_air_blinded_bytes(&b, make(), &pb, crate::committed_air::declared_blinded_laid_shape_for_tests(&b)));
        eprintln!("[blind] violation in the LAST REAL ROW (h−1): {last_verdict:?}");
        assert!(
            last_verdict != Some(true),
            "⛔⛔⛔ THE SELECTOR EXEMPTS THE CALLER'S OWN LAST ROW — `x[0]` is not the variable this \
             wrapper assumes, and half the supplied trace is unconstrained."
        );

        // ⛔⛔⛔ AND SCAN THE WHOLE PROOF, NOT JUST THE OPENED ROW. The PCS answers queries with codeword
        // symbols; if any of them carried a raw trace cell, hiding the opened row would move the leak
        // rather than close it. The §BE-1 scan is only honest if it covers every byte that ships.
        let whole = {
            let mut hits = 0usize;
            for sec in &secrets {
                let needle = Fa4::from_u64(*sec);
                let bytes_of = postcard::to_allocvec(&needle).expect("a field element serialises");
                if blinded
                    .windows(bytes_of.len())
                    .any(|w| w == bytes_of.as_slice())
                {
                    hits += 1;
                }
            }
            hits
        };
        eprintln!("[blind] WHOLE-PROOF byte scan for the trace's values: {whole}/{} found", secrets.len());
        assert_eq!(
            whole, 0,
            "⛔⛔⛔ a trace value appears SOMEWHERE in the blinded proof's bytes — blinding the opened \
             row moved the leak instead of closing it."
        );

        // ── AND THE BLINDING MUST BE FRESH: two proofs of the SAME trace must differ.
        let (again_cols, _) = constant_trace(h, 1_000_000_007, 999_999_937);
        let second = prove_air_blinded_bytes(again_cols, make(), &pb).expect("proves again");
        eprintln!(
            "[blind] two blinded proofs of the SAME trace differ: {}",
            second != blinded
        );
        assert_ne!(
            second, blinded,
            "⛔⛔⛔ THE BLINDING IS DETERMINISTIC — every observer can subtract it off. Real OS entropy \
             is the whole point; a fixed pad is decoration."
        );
    }
}

/// ⭐ §BJ COST PROBE — HOW BIG IS AN IN-CIRCUIT WHIR OPENING VERIFICATION?
///
/// Item 2's remaining part (c) needs the inner PCS opening checked INSIDE the outer circuit. For a
/// hash-based PCS that means Merkle-path verification in-circuit, and the only honest way to know
/// whether that fits the pillars is to count the compressions a REAL opening actually carries.
///
/// Run: cargo test -p usdm-decider --release bj_opening_cost -- --ignored --nocapture
#[cfg(test)]
mod bj_opening_cost {
    use super::*;
    use crate::air_zerocheck::Row;

    struct G {
        gamma: Ea4,
        pub_val: Ea4,
    }
    impl AirConstraint for G {
        fn degree(&self, _nvars: usize) -> usize {
            1
        }
        fn eval(&self, local: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            let _ = self.gamma;
            local[0] + local[1] - local[2] - self.pub_val
        }
    }

    /// ⭐⭐⭐ §BK-2 — WHAT PART (c3) IS ACTUALLY UP AGAINST. (c1)+(c2) remove a prover's freedom to
    /// INVENT a leaf. They do not remove its freedom to PICK WHICH leaf, and that freedom closes only if
    /// the query indices the circuit consumes are provably the Fiat-Shamir ones.
    ///
    /// ⛔ THE SAMPLER IS RECURSION-HOSTILE BY CONSTRUCTION, AND UPSTREAM ALREADY SAYS SO IN ITS OWN
    /// DOC. `whir::pcs::utils::get_challenge_stir_queries` draws until it has `t` DISTINCT indices — a
    /// data-dependent rejection loop — over `sample_uniform_bits::<true>`, which is ITSELF a
    /// data-dependent field-side rejection loop — and then SORTS. An AIR has fixed rows; none of those
    /// three shapes is a circuit. Upstream's own note on that function recommends preferring `n`
    /// independent draws (duplicates allowed) over `n` distinct ones for recursion-friendliness, and
    /// records that the WHIR paper's `(1 - delta)^t` bound is over INDEPENDENT draws — distinctness only
    /// lets `t` shrink slightly for the same security. So the security budget was never spending the
    /// distinctness in the first place.
    ///
    /// This probe MEASURES the loop rather than reasoning about it: how many draws a real committed
    /// carrier's query phase costs, and how many of those are rejections a circuit would have to carry
    /// as witnesses. The answer decides whether (c3) is a bounded-rejection circuit or a sampler change.
    #[test]
    #[ignore] // measurement probe
    fn bk2_query_sampler_rejection_cost() {
        use p3_challenger::{CanSampleUniformBits, FieldChallenger};
        // A challenger seeded exactly as the carrier seeds its own, so the draw sequence is the real one.
        let mut ch = challenger();
        ch.observe_slice(&[Fa4::from_u64(0xBC2), Fa4::from_u64(7)]);
        for (label, domain_bits, t) in [
            ("round 0", 11usize, 160usize),
            ("round 1", 9usize, 160usize),
            ("final  ", 7usize, 160usize),
        ] {
            let folded = 1usize << domain_bits;
            let target = t.min(folded);
            let mut queries: Vec<usize> = Vec::with_capacity(target);
            let mut draws = 0usize;
            let mut dup_rejects = 0usize;
            // A hard bound so a pathological transcript fails loudly instead of spinning: a circuit
            // would need exactly such a bound as a public parameter.
            let cap = 64 * target + 4096;
            while queries.len() < target && draws < cap {
                draws += 1;
                let q = ch.sample_uniform_bits::<true>(domain_bits).expect("RESAMPLE loops internally");
                if queries.contains(&q) {
                    dup_rejects += 1;
                } else {
                    queries.push(q);
                }
            }
            assert_eq!(queries.len(), target, "{label}: the sampler must reach its target within the cap");
            eprintln!(
                "[bk2] {label}: folded domain 2^{domain_bits} = {folded} · t = {target} · draws {draws}                  · duplicate rejections {dup_rejects} ({:.1}% overdraw)",
                100.0 * dup_rejects as f64 / target as f64
            );
        }
        eprintln!(
            "[bk2] a circuit must carry EVERY draw (accepted and rejected) as a witness row, plus the              field-side rejections inside `sample_uniform_bits`, plus a permutation argument for the              final sort. The duplicate-rejection count above is the DISTINCTNESS overhead alone."
        );

        // ── THE PRODUCTION SAMPLER, THE SAME THREE ROUNDS ───────────────────────────────────────────
        // §BK-3's replacement, measured on the same shapes: `stir_queries_fixed_time` draws exactly `t`
        // indices with replacement (2026-09-27: the with-replacement form, so the recursive verifier's
        // index gadget is `draw_below` on a power-of-two domain), each draw `DRAW_ELEMS` samples — the
        // draw count is a function of the SHAPE ALONE, so the trace height is fixed and no cap exists.
        use p3_challenger::CanSample;
        let mut ch2 = challenger();
        ch2.observe_slice(&[Fa4::from_u64(0xBC2), Fa4::from_u64(7)]);
        for (label, domain_bits, t) in [
            ("round 0", 11usize, 160usize),
            ("round 1", 9usize, 160usize),
            ("final  ", 7usize, 128usize),
        ] {
            let n = 1usize << domain_bits;
            let mut twin = ch2.clone();
            let picked = p3_whir::pcs::utils::stir_queries_fixed_time::<_, Fa4, Ea4>(n, 0, t, &mut ch2);
            // the twin consumes exactly t · DRAW_ELEMS samples and then agrees with the sampler's challenger
            for _ in 0..t * p3_whir::pcs::utils::DRAW_ELEMS {
                let _: Fa4 = twin.sample();
            }
            let (a, b): (Fa4, Fa4) = (twin.sample(), ch2.sample());
            assert_eq!(a, b, "{label}: the sampler consumed a sample count other than t · DRAW_ELEMS");
            assert_eq!(picked.len(), t, "{label}: wrong query count");
            assert!(picked.iter().all(|&q| q < n), "{label}: an index left the folded domain");
            eprintln!(
                "[bk2/sampler] {label}: folded domain 2^{domain_bits} - t = {} - draws {} (x{} field \
                 elements each) - rejections 0 - UNBOUNDED LOOPS 0",
                picked.len(),
                t,
                p3_whir::pcs::utils::DRAW_ELEMS
            );
        }
    }

    #[test]
    #[ignore] // measurement probe
    fn bj_opening_cost() {
        let pb = [Fa4::from_u64(99)];
        let mk = move |g: Ea4| G { gamma: g, pub_val: Ea4::from(Fa4::from_u64(99)) };
        for (label, width, height) in [
            ("small        3 x 1024", 3usize, 1024usize),
            ("tall       201 x 2048", 201usize, 2048usize),
            ("production 12885 x 32", 12_885usize, 32usize),
        ] {
            let mut cols: Vec<Vec<Fa4>> = (0..width)
                .map(|c| (0..height).map(|r| Fa4::from_u64(((c as u64) << 18) ^ (r as u64 + 1))).collect())
                .collect();
            for r in 0..height {
                cols[2][r] = cols[0][r] + cols[1][r] - Fa4::from_u64(99);
            }
            let Some(bytes) = prove_air_committed_bytes(cols, mk, &pb) else {
                eprintln!("[bj] {label}: prover refused");
                continue;
            };
            let b: CommittedAirBundle = postcard::from_bytes(&bytes).expect("decodes");
            // Count what an in-circuit verifier would have to recompute: every Merkle sibling digest in
            // every query opening, across every WHIR round plus the final queries. One compression per
            // sibling, one Poseidon2 permutation per compression.
            let mut queries = 0usize;
            let mut siblings = 0usize;
            let mut leaf_values = 0usize;
            let mut count = |q: &p3_whir::pcs::proof::QueryOpening<
                Fa4,
                Ea4,
                <Mmcs16 as Mmcs<Fa4>>::Proof,
            >| {
                queries += 1;
                match q {
                    p3_whir::pcs::proof::QueryOpening::Base { values, proof } => {
                        leaf_values += values.len();
                        siblings += proof.1.len();
                        leaf_values += proof.0.iter().map(Vec::len).sum::<usize>();
                    }
                    p3_whir::pcs::proof::QueryOpening::Extension { values, proof } => {
                        leaf_values += values.len() * 4;
                        siblings += proof.1.len();
                        leaf_values += proof.0.iter().map(Vec::len).sum::<usize>();
                    }
                }
            };
            for rnd in &b.open.rounds {
                for q in &rnd.queries {
                    count(q);
                }
            }
            for q in &b.open.final_queries {
                count(q);
            }
            eprintln!(
                "[bj] {label}: proof {} B · rounds {} · query openings {queries} · Merkle siblings {siblings} · leaf field elems {leaf_values}",
                bytes.len(),
                b.open.rounds.len()
            );
            eprintln!(
                "[bj] {label}: IN-CIRCUIT COST ≈ {siblings} Poseidon2 compressions (one per sibling) + the leaf hashes"
            );
        }
    }
}

/// ⭐ THE COMMITTED CARRIER'S TRANSCRIPT, REPLAYED — γ and z, from PUBLIC data alone.
///
/// The twin of `whir_rec_block::transcript_of_air_direct_carrier`, for the path item 1 moved the
/// production spend carrier onto. A recursion that consumes a committed carrier needs these two values,
/// and they must be derived the way the VERIFIER derives them or the outer step is asserting something
/// about a transcript nobody ran.
///
/// ⭐⭐⭐ THIS IS WHERE THE 63× LIVES (§BP). The direct path absorbs the ENTIRE opening — 7,944 field
/// elements for a production spend — before it can name γ. Here the challenger observes the public bind,
/// then ONE COMMITMENT, then the OOD answers: 49 elements. That is the whole reason a bound multi-carrier
/// aggregate is affordable at block cadence, and it is why item 1 gates §BA/§BB and the weld.
#[must_use]
pub fn transcript_of_committed_carrier(
    bytes: &[u8],
    public_bind: &[Fa4],
) -> Option<(Ea4, Vec<Ea4>)> {
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    let mut chl = challenger();
    committed_prefix_with(&b, public_bind, &mut chl)
}

/// The SAME replay, on a [`Recording`] challenger — the exact absorb/squeeze sequence a circuit must
/// lay as sponge rows.
///
/// ⭐ ONE BODY, NOT TWO. `transcript_of_committed_carrier` and this differ only in which challenger they
/// hand to [`committed_prefix_with`], so the recording cannot describe a walk the replay does not take.
/// §BS is what makes that mandatory: a hand-written mirror of this schedule reproduced 0 of 6 challenges.
#[must_use]
pub fn transcript_events_of_committed_carrier(
    bytes: &[u8],
    public_bind: &[Fa4],
) -> Option<(Vec<ChlEvent>, Ea4, Vec<Ea4>)> {
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    let mut rec = Recording::new(challenger());
    let (gamma, z) = committed_prefix_with(&b, public_bind, &mut rec)?;
    Some((rec.log().to_vec(), gamma, z))
}

/// The WHOLE walk a recursion has to weld — the prefix AND the zerocheck's round chain, recorded.
///
/// ⭐⭐⭐ THE ROUND CHAIN IS RUN, NOT MODELLED. A weld ties the inner round EVALS and the inner round
/// CHALLENGES to cells, so the recording has to reach them — and the honest way to reach them is to call
/// the REAL `verify_air_zerocheck` on the REAL constraint, not to write down what it probably absorbs.
/// §BS is the receipt for that caution: a hand-written mirror of the PREFIX alone reproduced 0 of 6
/// challenges.
///
/// Returns the event log, γ, z, and the round challenges the walk actually produced — the caller is
/// expected to check those against the carrier's own `zc.r`, which is the only proof the recording is a
/// true account.
#[must_use]
pub fn full_transcript_events_of_committed_carrier<C, Mk>(
    bytes: &[u8],
    public_bind: &[Fa4],
    make_constraint: Mk,
) -> Option<(Vec<ChlEvent>, Ea4, Vec<Ea4>, Vec<Ea4>)>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    let mut rec = Recording::new(challenger());
    let (gamma, z) = committed_prefix_with(&b, public_bind, &mut rec)?;
    let constraint = make_constraint(gamma);
    if !crate::air_zerocheck::verify_air_zerocheck_with(&b.zc, &constraint, &z, &mut rec) {
        return None; // fail-closed: a walk through a zerocheck that does not hold is not a transcript
    }
    Some((rec.log().to_vec(), gamma, z, b.zc.r.clone()))
}

/// The committed verifier's transcript prefix — everything up to and including `z`, which is all a
/// recursion needs to name a carrier's challenges. Generic over the challenger so the plain replay and
/// the recording one are the same walk.
fn committed_prefix_with<Ch>(
    b: &CommittedAirBundle,
    public_bind: &[Fa4],
    chl: &mut Ch,
) -> Option<(Ea4, Vec<Ea4>)>
where
    Ch: p3_challenger::FieldChallenger<Fa4> + p3_challenger::GrindingChallenger<Witness = Fa4>,
    Ch: p3_challenger::CanObserve<<Mmcs16 as p3_commit::Mmcs<Fa4>>::Commitment>,
{
    carrier_prefix_with(&CarrierPrefix { shape: b.shape, commitment: &b.commitment, zc: &b.zc, open: &b.open }, public_bind, chl)
}

/// What the transcript prefix reads of a carrier, whichever door made it: the plain door and the chained door run the
/// SAME walk up to `z` (statement, commitment, OOD answers, γ, z), so a recursion reads both through this one view.
struct CarrierPrefix<'a> {
    shape: (usize, usize),
    commitment: &'a <Mmcs16 as Mmcs<Fa4>>::Commitment,
    zc: &'a AirZerocheckProof,
    open: &'a WhirProof<Fa4, Ea4, Mmcs16>,
}

/// The transcript prefix of [`committed_prefix_with`], over the door-independent view.
fn carrier_prefix_with<Ch>(b: &CarrierPrefix<'_>, public_bind: &[Fa4], chl: &mut Ch) -> Option<(Ea4, Vec<Ea4>)>
where
    Ch: p3_challenger::FieldChallenger<Fa4> + p3_challenger::GrindingChallenger<Witness = Fa4>,
    Ch: p3_challenger::CanObserve<<Mmcs16 as p3_commit::Mmcs<Fa4>>::Commitment>,
{
    let (nvars, width) = b.shape;
    // Fail-closed on exactly the shape the verifier's step 0 refuses — this function sizes the same
    // allocations from the same remote number, so it needs the same guard, not a weaker one.
    if nvars < COMMITTED_FOLDING
        || nvars > MAX_STATEABLE_NVARS
        || width == 0
        || b.zc.opened.len() != width
        || b.zc.r.len() != nvars
        || b.zc.round_evals.len() != nvars
    {
        return None;
    }
    // The stacked arity is a public function of the shape — recomputed here the way
    // `verify_air_committed_bytes` recomputes it, never trusted from the wire.
    let stacked_nvars = {
        let t = Table::new((0..width).map(|_| Poly::<Fa4>::new(vec![Fa4::ZERO; 1 << nvars])).collect());
        PrefixProver::<Fa4, Ea4>::new_witness(vec![t], COMMITTED_FOLDING).num_variables()
    };
    let pcs = pcs_for(stacked_nvars);
    for &f in public_bind {
        chl.observe(f);
    }
    chl.observe(b.commitment.clone());
    for mask_commit in &b.open.hvzk_mask_commits {
        chl.observe(mask_commit.clone());
    }
    let shapes = vec![p3_sumcheck::table::TableShape::new(nvars, width)];
    let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&shapes, PrefixProver::<Fa4, Ea4>::strategy());
    if b.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples {
        return None; // fail-closed: the OOD count is public; a short list desynchronises the replay
    }
    for &eval in &b.open.initial_ood_answers {
        lv.add_virtual_eval(eval, chl);
    }
    let gamma: Ea4 = chl.sample_algebra_element();
    let z: Vec<Ea4> = (0..nvars).map(|_| chl.sample_algebra_element()).collect();
    Some((gamma, z))
}

/// The zerocheck a committed carrier carries — its round evaluations, challenges and opened row. A
/// recursion needs these as trace cells; exposing them here keeps ONE reader of the bundle's shape.
#[must_use]
pub fn zerocheck_of_committed_carrier(bytes: &[u8]) -> Option<(AirZerocheckProof, (usize, usize))> {
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    Some((b.zc, b.shape))
}

/// The same two readers for a CHAINED carrier ([`prove_air_blinded_chained_bytes`]): its zerocheck, the next-row values
/// its gate read (one per column of the gate's `shifted_cols`, in order) and its shape; and its γ and z. A class has ONE
/// door, so a reader is told which layout its class uses and never tries both.
#[must_use]
pub fn zerocheck_of_chained_carrier(bytes: &[u8]) -> Option<(AirZerocheckProof, Vec<Ea4>, (usize, usize))> {
    let b: ChainedAirBundle = postcard::from_bytes(bytes).ok()?;
    if !b.zc.shifted_opened.is_empty() {
        return None; // the chained layout's next-row values ride in `next`, never in the zerocheck
    }
    Some((b.zc, b.next, b.shape))
}

/// γ and z of a chained carrier, replayed from public data: the plain door's own prefix walk.
#[must_use]
pub fn transcript_of_chained_carrier(bytes: &[u8], public_bind: &[Fa4]) -> Option<(Ea4, Vec<Ea4>)> {
    let b: ChainedAirBundle = postcard::from_bytes(bytes).ok()?;
    let mut chl = challenger();
    carrier_prefix_with(&CarrierPrefix { shape: b.shape, commitment: &b.commitment, zc: &b.zc, open: &b.open }, public_bind, &mut chl)
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════
// THE TRANSCRIPT RECORDER — §BS's answer to "the committed schedule cannot be transcribed"
// ═══════════════════════════════════════════════════════════════════════════════════════════════════

/// One thing a challenger did. The weld lays sponge ROWS, so it needs the ORDER and the COUNTS, not
/// just the challenges the replay ends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChlEvent {
    /// One base field element absorbed.
    Observe,
    /// One base field element squeezed.
    Sample,
}

/// A challenger that does exactly what the one it wraps does, and writes down every absorb and squeeze
/// as it happens.
///
/// ⭐⭐⭐ WHY THIS EXISTS RATHER THAN A SECOND HAND MODEL. §BS measured the honest attempt: mirroring
/// `verify_air_committed_bytes` by reading it reproduced **0 of 6** of a real carrier's challenges. The
/// PCS's own commit/claim path touches the challenger in ways the verifier's source does not show. A
/// transcription can only ever be right by luck and stays right only until someone edits the verifier
/// without editing its mirror; a RECORDING is right by construction and cannot drift.
#[derive(Clone)]
pub struct Recording<C> {
    inner: C,
    /// O1-FOOTPRINT-REVIEWED: bounded by COMMITTED_FOLDING (one transcript, length fixed by the WHIR config).
    log: Vec<ChlEvent>,
    /// O1-FOOTPRINT-REVIEWED: bounded by COMMITTED_FOLDING (the same transcript, absorbed elements).
    absorbed: Vec<Fa4>,
}

impl<C> Recording<C> {
    #[must_use]
    pub fn new(inner: C) -> Self {
        Self { inner, log: Vec::new(), absorbed: Vec::new() }
    }
    /// The events, in the order they happened.
    #[must_use]
    pub fn log(&self) -> &[ChlEvent] {
        &self.log
    }
    /// Every element absorbed, in absorb order — the VALUES a sponge must replay, not just how many.
    #[must_use]
    pub fn absorbed(&self) -> &[Fa4] {
        &self.absorbed
    }
}

impl<C, T> p3_challenger::CanObserve<T> for Recording<C>
where
    C: p3_challenger::CanObserve<T>,
    T: ObservedWidth,
{
    fn observe(&mut self, value: T) {
        // One `observe` of a digest is several base elements on the wire; the type says how many, so the
        // count is taken from the value rather than assumed to be one.
        for e in value.observed_elems() {
            self.log.push(ChlEvent::Observe);
            self.absorbed.push(e);
        }
        self.inner.observe(value);
    }
}

/// How many base field elements one `observe` of this type absorbs. Implemented for exactly the types
/// this crate's transcripts absorb, so a new one cannot be counted wrong by default.
pub trait ObservedWidth {
    fn observed_width(&self) -> usize {
        self.observed_elems().len()
    }
    /// The elements themselves, in absorb order — so a reconstruction can be checked VALUE by value.
    fn observed_elems(&self) -> Vec<Fa4>;
}
impl ObservedWidth for Fa4 {
    fn observed_elems(&self) -> Vec<Fa4> {
        vec![*self]
    }
}
impl<const N: usize> ObservedWidth for [Fa4; N] {
    fn observed_elems(&self) -> Vec<Fa4> {
        self.to_vec()
    }
}
impl<const N: usize, const M: usize> ObservedWidth for [[Fa4; N]; M] {
    fn observed_elems(&self) -> Vec<Fa4> {
        self.iter().flatten().copied().collect()
    }
}
impl<const N: usize> ObservedWidth for p3_symmetric::MerkleCap<Fa4, [Fa4; N]> {
    fn observed_elems(&self) -> Vec<Fa4> {
        // A cap is a LAYER, not a root: its length is `2^cap_height`. Assuming one digest here is
        // exactly the kind of guess §BS measured failing.
        self.as_ref().iter().flatten().copied().collect()
    }
}

impl<C, T> p3_challenger::CanSample<T> for Recording<C>
where
    C: p3_challenger::CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.log.push(ChlEvent::Sample);
        self.inner.sample()
    }
}

impl<C> p3_challenger::CanSampleBits<usize> for Recording<C>
where
    C: p3_challenger::CanSampleBits<usize>,
{
    fn sample_bits(&mut self, bits: usize) -> usize {
        // `sample_bits` squeezes one field element and masks it.
        self.log.push(ChlEvent::Sample);
        self.inner.sample_bits(bits)
    }
}

impl<C> p3_challenger::FieldChallenger<Fa4> for Recording<C> where
    C: p3_challenger::FieldChallenger<Fa4> + Sync
{
}

impl<C> p3_challenger::GrindingChallenger for Recording<C>
where
    C: p3_challenger::GrindingChallenger<Witness = Fa4>,
{
    type Witness = Fa4;
    fn grind(&mut self, bits: usize) -> Self::Witness {
        self.inner.grind(bits)
    }
    /// The exhaustion-reporting search runs on the inner challenger (a clone of this recorder carries a clone of
    /// it), so the trait's default two-word `grind_wide` — which observes `hi` and `lo` through THIS recorder and
    /// therefore logs them — advances `hi` exactly as the plain challenger does.
    fn try_grind(&mut self, bits: usize) -> Option<Self::Witness> {
        self.inner.try_grind(bits)
    }
}

/// The recorded walk, in the `(absorb_lens, samples_after)` shape the weld's sponge planner takes.
///
/// `transcript_bind_air::plan` consumes exactly this pair: how many elements each absorb burst carries,
/// and how many limbs are squeezed after it. A flat event log is the same information, so the conversion
/// is a grouping and nothing more — which is the point. The DIRECT path derives its pair from
/// `schedule_lens`, a hand-written formula; this one is derived from what the challenger actually did.
///
/// ⛔ A leading squeeze is impossible in a Fiat-Shamir transcript that binds its statement first, and a
/// trailing absorb with nothing squeezed after it lives in no row — both are refused rather than padded.
#[must_use]
pub fn committed_schedule_of_events(log: &[ChlEvent]) -> Option<(Vec<usize>, Vec<usize>)> {
    if log.first() != Some(&ChlEvent::Observe) {
        return None; // the statement is absorbed before any challenge exists
    }
    let (mut lens, mut samples) = (Vec::new(), Vec::new());
    let (mut abs, mut samp) = (0usize, 0usize);
    for e in log {
        match e {
            ChlEvent::Observe => {
                if samp > 0 {
                    lens.push(abs);
                    samples.push(samp);
                    abs = 0;
                    samp = 0;
                }
                abs += 1;
            }
            ChlEvent::Sample => samp += 1,
        }
    }
    if samp == 0 {
        return None; // a trailing absorb nothing squeezed after lives in no row
    }
    lens.push(abs);
    samples.push(samp);
    Some((lens, samples))
}

/// Base limbs in one extension element — the unit every challenge and every absorbed `Ea4` is counted in.
pub const EXT_LIMBS: usize = 4;

/// Field elements in one Merkle digest — the unit a commitment cap is counted in.
pub const DIGEST_ELEMS_PER_CAP_ENTRY: usize = 8;

/// The committed transcript's schedule, from the SHAPE alone.
///
/// ⭐⭐⭐ WHY A FORMULA AT ALL, WHEN THERE IS A RECORDER. An OUTER verifier does not hold the inner
/// carrier — that is what recursion IS — so it cannot record the inner walk. It has to derive the same
/// cells from public numbers. So the formula exists, and it is PROVEN rather than guessed:
/// `committed_schedule_lens_matches_the_recorded_walk` runs the recorder on a real production carrier
/// and demands this reproduce it exactly. §BS is why that gate is not optional — a schedule written by
/// reading the verifier reproduced 0 of 6 challenges.
///
/// The bursts, in order:
/// ```text
/// [ public bind ‖ commitment ]            -> one OOD point
/// [ OOD answer_i ]  (ood times)           -> the next OOD point, and after the LAST one, γ then z
/// [ round evals_k ] (nvars times)         -> that round's challenge r_k
/// ```
///
/// ⛔ `width` DOES NOT APPEAR, and that is the whole of §BP in one line: the direct schedule absorbs the
/// entire opening — `width * EXT_LIMBS` elements — before it can name γ. This one absorbs a COMMITMENT.
#[must_use]
pub fn committed_schedule_lens(
    nvars: usize,
    per: usize,
    pb_len: usize,
    ood: usize,
    commitment_elems: usize,
) -> Option<(Vec<usize>, Vec<usize>)> {
    if nvars == 0 || per == 0 || ood == 0 {
        return None; // fail-closed: a walk with no rounds or no OOD sample is not this transcript
    }
    let mut lens = vec![pb_len + commitment_elems];
    let mut samples = vec![EXT_LIMBS];
    for i in 0..ood {
        lens.push(EXT_LIMBS);
        // After the LAST OOD answer the verifier draws γ and then every z_k; after the others, just the
        // next OOD point.
        samples.push(if i + 1 == ood { EXT_LIMBS * (1 + nvars) } else { EXT_LIMBS });
    }
    for _ in 0..nvars {
        lens.push(per * EXT_LIMBS);
        samples.push(EXT_LIMBS);
    }
    Some((lens, samples))
}

/// The public numbers `committed_schedule_lens` needs that are not the AIR's own shape: how many OOD
/// samples the configuration draws, and how many field elements its commitment absorbs. Both are
/// functions of the WHIR config and the trace shape, so an outer verifier derives them without the
/// carrier.
#[must_use]
pub fn committed_schedule_params(nvars: usize, width: usize) -> Option<(usize, usize)> {
    if nvars < COMMITTED_FOLDING || nvars > MAX_STATEABLE_NVARS || width == 0 {
        return None;
    }
    let stacked_nvars = {
        let t = Table::new((0..width).map(|_| Poly::<Fa4>::new(vec![Fa4::ZERO; 1 << nvars])).collect());
        PrefixProver::<Fa4, Ea4>::new_witness(vec![t], COMMITTED_FOLDING).num_variables()
    };
    let pcs = pcs_for(stacked_nvars);
    // The commitment is a Merkle CAP — `2^cap_height` digests of 8 elements — and OUR mmcs fixes the
    // height (`mmcs()` passes it), so the element count is public. Read it off the object rather than
    // from the literal, so a change to `mmcs()` moves this with it.
    let cap_elems = (1usize << mmcs().cap_height()) * DIGEST_ELEMS_PER_CAP_ENTRY;
    Some((pcs.config.commitment_ood_samples, cap_elems))
}

/// The elements a committed carrier's transcript absorbs, grouped into the bursts
/// [`committed_schedule_lens`] describes — the VALUES to put in the sponge's absorb cells, where the
/// schedule gives only the counts.
///
/// ⛔ THE ORDER IS THE STATEMENT. It is the verifier's order — statement, commitment, OOD answers, then
/// each round's evals — and `committed_weld_tables` refuses outright if the burst lengths disagree with
/// the public schedule, so a prover cannot pad or reorder its way into different cells.
#[must_use]
pub fn committed_absorb_bursts(bytes: &[u8], public_bind: &[Fa4]) -> Option<Vec<Vec<Fa4>>> {
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    Some(carrier_absorb_bursts(&CarrierPrefix { shape: b.shape, commitment: &b.commitment, zc: &b.zc, open: &b.open }, public_bind))
}

/// [`committed_absorb_bursts`] for a CHAINED carrier: the same walk (statement, commitment, OOD answers, each round's
/// evals); what the chained door absorbs after the last round is past the point a recursion welds.
#[must_use]
pub fn chained_absorb_bursts(bytes: &[u8], public_bind: &[Fa4]) -> Option<Vec<Vec<Fa4>>> {
    let b: ChainedAirBundle = postcard::from_bytes(bytes).ok()?;
    Some(carrier_absorb_bursts(&CarrierPrefix { shape: b.shape, commitment: &b.commitment, zc: &b.zc, open: &b.open }, public_bind))
}

fn carrier_absorb_bursts(b: &CarrierPrefix<'_>, public_bind: &[Fa4]) -> Vec<Vec<Fa4>> {
    let limbs = |e: &Ea4| -> Vec<Fa4> {
        <Ea4 as p3_field::BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e)[..EXT_LIMBS].to_vec()
    };
    let mut first = public_bind.to_vec();
    // The commitment is a CAP — a layer of digests — so every element of every digest is absorbed.
    for d in b.commitment.as_ref() {
        first.extend_from_slice(d);
    }
    let mut out = vec![first];
    for e in &b.open.initial_ood_answers {
        out.push(limbs(e));
    }
    for h in &b.zc.round_evals {
        out.push(h.iter().flat_map(limbs).collect());
    }
    out
}

/// Every element a committed carrier's FULL transcript absorbs, RECORDED — the ground truth
/// [`committed_absorb_bursts`] is checked against.
///
/// ⛔ A reconstruction of absorbed VALUES is the same class of guess as a reconstruction of absorbed
/// COUNTS, and §BS measured what that is worth. So the values have a recording too.
#[must_use]
pub fn recorded_absorbs_of_committed_carrier<C, Mk>(
    bytes: &[u8],
    public_bind: &[Fa4],
    make_constraint: Mk,
) -> Option<Vec<Fa4>>
where
    C: AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let b: CommittedAirBundle = postcard::from_bytes(bytes).ok()?;
    let mut rec = Recording::new(challenger());
    let (gamma, z) = committed_prefix_with(&b, public_bind, &mut rec)?;
    let constraint = make_constraint(gamma);
    if !crate::air_zerocheck::verify_air_zerocheck_with(&b.zc, &constraint, &z, &mut rec) {
        return None;
    }
    Some(rec.absorbed().to_vec())
}

/// ⭐ DB-371 INSTRUMENT — the base commitment's MEMORY at the certificate's size, measured per variant in its own
/// process (the OS footprint peak is lifetime-monotonic, so one variant per run: `DB371_VARIANT=dense|split<s>`).
///
/// WHY: the streamed attempt (scratchpad/db371s2-attempt1.patch) made the genesis-certificate prove WORSE — peak 8,424 MB
/// vs 7,996, `core` 7,953 vs 6,404 (scratchpad/db371-profile.tsv) — although it holds no codeword. This names where the
/// commit's memory goes before the next design: the transient PEAK during the commit and the footprint it LEAVES behind
/// (prover data held, then dropped), at the real shape — 2^27 coefficients, f = 4, rate 1/2, the salted Mmcs16.
/// - `dense`: the production path (transpose, pad to 2^24 rows, `dft_batch`, `commit_matrix`).
/// - `split<s>`: 2^(1+s) sub-cosets of 2^(23−s) rows, each the folded coefficients through `coset_dft_batch`, hashed by
///   `MerkleTree::new_streamed` with its rows' salts appended; s = 0 is attempt 1's shape.
/// An instrument: it decides nothing and asserts only that the variant parsed and the tree has the dense height.
#[cfg(test)]
mod db371_commit_memory {
    use super::*;
    use p3_dft::TwoAdicSubgroupDft;
    use p3_field::{Field, TwoAdicField};
    use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixView};
    use p3_matrix::Matrix;
    use p3_merkle_tree::MerkleTree;

    type Packed = <Fa4 as Field>::Packing;

    /// The shape the streamed tree opens from — never opened by the instrument, so it stores nothing.
    struct Shape(usize, usize);
    impl Matrix<Fa4> for Shape {
        fn width(&self) -> usize {
            self.0
        }
        fn height(&self) -> usize {
            self.1
        }
        #[allow(refining_impl_trait)]
        unsafe fn row_unchecked(&self, _r: usize) -> std::vec::IntoIter<Fa4> {
            vec![Fa4::ZERO; self.0].into_iter()
        }
    }

    #[test]
    #[ignore = "instrument: 2^27 coefficients (512 MiB) + the commit; run one variant per process with DB371_VARIANT"]
    fn db371_commit_memory_by_variant() {
        let variant = std::env::var("DB371_VARIANT").unwrap_or_else(|_| "dense".to_string());
        let (n, f, rho) = (27usize, COMMITTED_FOLDING, COMMITTED_START_RATE);
        let k = n - f;
        let height = 1usize << (k + rho);
        // an instrument that cannot read the footprint must not print zeros that look like a measurement
        let fp = || crate::spartan_ccs::process_footprint_mb().expect("the OS footprint tool reads this process");
        let mut rng = SmallRng::seed_from_u64(371);
        let coeffs: Vec<Fa4> = (0..1usize << n).map(|_| rng.random()).collect();
        let base = fp();
        let t = std::time::Instant::now();
        let dft = Dft16::default();
        let (held, rows) = if variant == "dense" {
            let mut padded = RowMajorMatrixView::new(&coeffs, 1 << k).transpose();
            padded.pad_to_height(height, Fa4::ZERO);
            let encoded = dft.dft_batch(padded).to_row_major_matrix();
            let (_root, data) = mmcs().commit_matrix(encoded);
            let rows = mmcs().get_max_height(&data);
            (fp(), rows)
        } else {
            let s: usize = variant.strip_prefix("split").and_then(|x| x.parse().ok()).expect("DB371_VARIANT=dense|split<s>");
            let cosets = 1usize << (rho + s);
            let m = 1usize << (k - s); // rows per sub-coset
            let mut prng = SmallRng::seed_from_u64(COMMITTED_AIR_SEED);
            let perm = Perm16::new_from_rng_128(&mut prng);
            let (h, c) = (SpongeHash::new(perm.clone()), CompressHash::new(perm));
            let salts = RowMajorMatrix::<Fa4>::rand(&mut rng, height, 8);
            let omega = Fa4::two_adic_generator(k + rho);
            let width = 1usize << f;
            let tree = MerkleTree::<Fa4, Fa4, Shape, 2, 8>::new_streamed::<Packed, Packed, _, _, _>(
                &h,
                &c,
                Shape(width + 8, height),
                cosets,
                |_, ci| {
                    // b[u][col] = Σ_q a[col][u + q·m] · z^q, z = ω^(ci·m): the coset's evaluations are coset_dft(b, ω^ci)
                    let z = omega.exp_u64((ci * m) as u64);
                    let mut b = vec![Fa4::ZERO; m * width];
                    for col in 0..width {
                        let a = &coeffs[col << k..(col + 1) << k];
                        let mut zq = Fa4::ONE;
                        for q in 0..1usize << s {
                            for u in 0..m {
                                b[u * width + col] += a[u + q * m] * zq;
                            }
                            zq *= z;
                        }
                    }
                    let evals = dft.coset_dft_batch(RowMajorMatrix::new(b, width), omega.exp_u64(ci as u64)).to_row_major_matrix();
                    let mut values = Vec::with_capacity(m * (width + 8));
                    for (j, row) in evals.values.chunks(width).enumerate() {
                        values.extend_from_slice(row);
                        values.extend(salts.row(ci + cosets * j).unwrap());
                    }
                    RowMajorMatrix::new(values, width + 8)
                },
            );
            // `new_streamed` asserts every coset's height and width itself; the root proves the tree was built
            let _root = tree.root();
            (fp(), height)
        };
        let after = fp();
        eprintln!(
            "[db371-instr] {variant}: base {} MB (coefficients); commit {:.1?}; held {} MB; lifetime peak {} MB; after drop {} MB; rows {rows}",
            base.0, t.elapsed(), held.0, held.1.max(after.1), after.0
        );
        assert_eq!(rows, height, "the tree has the codeword's height");
    }

    /// ⭐ DB-371 INSTRUMENT, ROUND 1 — the extension-field commitment the WHIR opening makes after its first fold, at the
    /// certificate's shape: 2^23 folded `Ea4` coefficients, folding 4, round-1 rate 1/16 (`committed_rates`: 1 + 3), so a
    /// 2^23 × 16 codeword of 16-byte elements = 2 GiB — `commit_extension`'s body replicated (transpose, pad,
    /// `dft_algebra_batch`, `ExtensionMmcs::commit_matrix` over the salted Mmcs16). MEASURED why: after step 2 the
    /// genesis-certificate peak is set inside `open_w` (3,681 → 7,371 MB); this names whether round 1 is that transient.
    #[test]
    #[ignore = "instrument: a 2 GiB extension codeword; run alone"]
    fn db371_round1_extension_commit_memory() {
        // an instrument that cannot read the footprint must not print zeros that look like a measurement
        let fp = || crate::spartan_ccs::process_footprint_mb().expect("the OS footprint tool reads this process");
        let (nv, f, log_rate) = (23usize, COMMITTED_FOLDING, 4usize);
        let mut rng = SmallRng::seed_from_u64(372);
        let poly: Vec<Ea4> = (0..1usize << nv).map(|_| rng.random()).collect();
        let base = fp();
        let t = std::time::Instant::now();
        let height = 1usize << (nv - f + log_rate);
        // `DB371_VARIANT=streamed` measures the path `commit_extension` takes since step 3 (the lazy codeword over the
        // folded coefficients, `coset_dft_algebra_batch` per sub-coset); the default is the dense path it replaced. Both
        // then open 100 rows: the opening is where a lazy row's recompute would show as TIME.
        let streamed = std::env::var("DB371_VARIANT").ok().as_deref() == Some("streamed");
        let ext = p3_commit::ExtensionMmcs::<Fa4, Ea4, Mmcs16>::new(mmcs());
        let rows = if streamed {
            use p3_sumcheck::commit::CodewordRows;
            use p3_sumcheck::strategy::VariableOrder;
            let dft = Dft16::default();
            let lazy = CodewordRows::<Fa4, Ea4>::new(std::sync::Arc::new(Poly::new(poly.clone())), VariableOrder::Prefix, f, log_rate);
            let sub_cosets = lazy.sub_cosets();
            let (_root, data) = ext.commit_streamed(lazy, sub_cosets, |rows, j| {
                let (folded, shift) = rows.sub_coset_input(j);
                dft.coset_dft_algebra_batch(folded, shift)
            });
            let held = fp();
            let committed = t.elapsed();
            let t_open = std::time::Instant::now();
            for i in 0..100usize {
                let _ = ext.open_batch((i * 2_654_435_761) % height, &data);
            }
            eprintln!(
                "[db371-instr] round-1 ext STREAMED: poly {} MB; {sub_cosets} sub-cosets; committed (held) {} MB in {committed:.1?}; 100 openings {:.1?}",
                base.0, held.0, t_open.elapsed()
            );
            ext.get_max_height(&data)
        } else {
            let mut padded = RowMajorMatrixView::new(&poly, 1 << (nv - f)).transpose();
            padded.pad_to_height(height, Ea4::ZERO);
            let padded_at = fp();
            let encoded = Dft16::default().dft_algebra_batch(padded).to_row_major_matrix();
            let encoded_at = fp();
            let (_root, data) = ext.commit_matrix(encoded);
            let held = fp();
            let committed = t.elapsed();
            let t_open = std::time::Instant::now();
            for i in 0..100usize {
                let _ = ext.open_batch((i * 2_654_435_761) % height, &data);
            }
            eprintln!(
                "[db371-instr] round-1 ext DENSE: poly {} MB; padded {} MB; encoded {} MB; committed (held) {} MB in {committed:.1?}; 100 openings {:.1?}",
                base.0, padded_at.0, encoded_at.0, held.0, t_open.elapsed()
            );
            ext.get_max_height(&data)
        };
        let after = fp();
        eprintln!("[db371-instr] round-1 ext: total {:.1?}; lifetime peak {} MB; after drop {} MB", t.elapsed(), after.1, after.0);
        assert_eq!(rows, height, "the round-1 tree has the codeword's height");
    }
}

/// ⭐ SPEED C3a PIN (lane speed4, 2026-11-12) — a payment carrier's WHIR paths ride in fixed slots
/// (`light_commit::slotted_whir`): the carrier still verifies, its bytes shrink against the per-query form, its length is
/// a function of its class alone, and every slot tamper is refused.
#[cfg(test)]
mod c3a_slotted_carrier_tests {
    use super::*;
    use crate::light_commit::slotted_whir::Wire;

    /// The chained bundle as it is on the wire, with the slotted opening laid open.
    #[derive(Serialize, Deserialize)]
    struct RawChained {
        shape: (usize, usize),
        commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
        zc: AirZerocheckProof,
        next: Vec<Ea4>,
        bind_rounds: Vec<Vec<Ea4>>,
        bind_opened: Vec<Ea4>,
        open: Wire,
    }
    /// The same bundle in the per-query form it had before C3a.
    #[derive(Serialize)]
    struct OldChained<'a> {
        shape: (usize, usize),
        commitment: &'a <Mmcs16 as Mmcs<Fa4>>::Commitment,
        zc: &'a AirZerocheckProof,
        next: &'a Vec<Ea4>,
        bind_rounds: &'a Vec<Vec<Ea4>>,
        bind_opened: &'a Vec<Ea4>,
        open: &'a WhirProof<Fa4, Ea4, Mmcs16>,
    }
    #[derive(Serialize)]
    struct OldCommitted<'a> {
        shape: (usize, usize),
        commitment: &'a <Mmcs16 as Mmcs<Fa4>>::Commitment,
        zc: &'a AirZerocheckProof,
        open: &'a WhirProof<Fa4, Ea4, Mmcs16>,
    }

    fn old_chained_len(bytes: &[u8]) -> usize {
        let b: ChainedAirBundle = postcard::from_bytes(bytes).expect("decodes");
        postcard::to_allocvec(&OldChained {
            shape: b.shape, commitment: &b.commitment, zc: &b.zc, next: &b.next, bind_rounds: &b.bind_rounds,
            bind_opened: &b.bind_opened, open: &b.open,
        })
        .expect("encodes")
        .len()
    }

    fn member() -> (Vec<u8>, crate::member_path_gate::MemberTuple) {
        use crate::member_path_gate::{prove_member_path_carrier, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(100 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| (0x5A3C_96E1u64 >> (i % 32)) & 1 == 1).collect();
        prove_member_path_carrier(d(1), &siblings, &dirs, d(2), d(3), d(4)).expect("the member path proves")
    }

    #[test]
    fn c3a_a_payment_carrier_sends_its_paths_once_in_fixed_slots_and_every_slot_tamper_is_refused() {
        use crate::member_path_gate::verify_member_path_carrier;
        // 1. the member path carrier (chained door): verifies, smaller, constant length
        let (m, t) = member();
        assert!(verify_member_path_carrier(&m, &t), "the slotted member carrier verifies");
        let (m2, t2) = member();
        assert!(verify_member_path_carrier(&m2, &t2), "a second proof of the class verifies");
        assert_eq!(m.len(), m2.len(), "⛔ a slotted carrier's length must be its class's, never which paths met");
        let old_m = old_chained_len(&m);
        // 2. the spend-or-decoy carrier (chained door, the tag-set class)
        let bound = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let tags: Vec<_> = (0..8u64).map(|s| crate::nf_sparse_air::cover_tag_native(bound, s)).collect();
        let wit = vec![crate::nf_sparse_air::TagWitness::Decoy; 8];
        let s = crate::nf_sparse_air::prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("spend_or_decoy proves");
        assert!(crate::nf_sparse_air::verify_spend_or_decoy_bytes(&s, &tags), "the slotted tag-set carrier verifies");
        let old_s = old_chained_len(&s);
        // 3. the membership carrier (plain committed door, production depth 32)
        let siblings: Vec<_> =
            (0..32u64).map(|i| crate::poseidon2_compress::lanes_of(&[i * 4 + 1, i * 4 + 2, i * 4 + 3, i * 4 + 4])).collect();
        let dirs: Vec<bool> = (0..32u64).map(|i| (0x0A5C_3F17u64 >> (i % 32)) & 1 == 1).collect();
        let w = crate::whir_rec_block::MembershipWitness { leaf: crate::poseidon2_compress::lanes_of(&[7, 8, 9, 10]), siblings, dirs };
        let (c, root) = crate::whir_rec_block::prove_membership_carrier_bytes(&w).expect("membership proves");
        assert!(crate::whir_rec_block::verify_membership_carrier_bytes(&c, root, 32), "the slotted membership carrier verifies");
        let cb: CommittedAirBundle = postcard::from_bytes(&c).expect("decodes");
        let old_c = postcard::to_allocvec(&OldCommitted { shape: cb.shape, commitment: &cb.commitment, zc: &cb.zc, open: &cb.open })
            .expect("encodes")
            .len();
        eprintln!(
            "[c3a] member_carrier {old_m} -> {} B · spend_or_decoy {old_s} -> {} B · membership_carrier {old_c} -> {} B",
            m.len(), s.len(), c.len()
        );
        assert!(m.len() < old_m && s.len() < old_s && c.len() < old_c, "⛔ the slotted form must be smaller than the per-query form");

        // 4. tampers on the slotted wire, each refused
        let raw: RawChained = postcard::from_bytes(&m).expect("the slotted wire lays open");
        let enc = |r: &RawChained| postcard::to_allocvec(r).expect("encodes");
        let g = raw.open.groups.iter().position(|g| !g.slots.is_empty()).expect("CALIBRATION: a group with slots");
        let read = raw.open.groups[g].slots.iter().position(|d| *d != [Fa4::ZERO; 8]).expect("CALIBRATION: a slot a query reads");
        let unread = raw.open.groups[g].slots.iter().position(|d| *d == [Fa4::ZERO; 8]);
        // a read slot's digest flipped
        let mut a: RawChained = postcard::from_bytes(&m).unwrap();
        a.open.groups[g].slots[read][0] += Fa4::ONE;
        assert!(!verify_member_path_carrier(&enc(&a), &t), "⛔ a flipped slot digest must be refused");
        // a nonzero digest in a slot no query reads
        if let Some(u) = unread {
            let mut b: RawChained = postcard::from_bytes(&m).unwrap();
            b.open.groups[g].slots[u][3] = Fa4::ONE;
            assert!(!verify_member_path_carrier(&enc(&b), &t), "⛔ a filled unread slot must be refused (one encoding)");
        }
        // one slot too many, one too few
        let mut c1: RawChained = postcard::from_bytes(&m).unwrap();
        c1.open.groups[g].slots.push([Fa4::ZERO; 8]);
        assert!(!verify_member_path_carrier(&enc(&c1), &t), "⛔ a slot too many must be refused");
        let mut c2: RawChained = postcard::from_bytes(&m).unwrap();
        c2.open.groups[g].slots.pop();
        assert!(!verify_member_path_carrier(&enc(&c2), &t), "⛔ a slot too few must be refused");
        // a query's position moved
        let mut d: RawChained = postcard::from_bytes(&m).unwrap();
        d.open.groups[g].positions[0] ^= 1;
        assert!(!verify_member_path_carrier(&enc(&d), &t), "⛔ a moved query position must be refused");
        // a different level count
        let mut e: RawChained = postcard::from_bytes(&m).unwrap();
        e.open.groups[g].levels = e.open.groups[g].levels.wrapping_add(1);
        assert!(!verify_member_path_carrier(&enc(&e), &t), "⛔ another level count must be refused");
        // CONTROL: the untouched wire re-encodes byte for byte and verifies
        assert_eq!(enc(&raw), m, "CONTROL: laying the wire open and closing it changes nothing");
    }
}

/// ⭐ SPEED C3 PROBE (lane speed4, 2026-11-12) — where a payment carrier's bytes go: the zerocheck, the shift bind, and
/// the WHIR opening split into sumcheck, OOD, per-query leaf values, per-query salts and Merkle siblings, and the siblings
/// that are the SAME digest at the same round (a shared path node a multi-opening would send once).
#[cfg(test)]
mod c3_probe {
    use super::*;
    use std::collections::HashSet;

    fn split(label: &str, bytes: &[u8]) {
        let b: ChainedAirBundle = postcard::from_bytes(bytes).expect("decodes");
        let sz = |v: postcard::Result<Vec<u8>>| v.map(|x| x.len()).unwrap_or(0);
        let zc = sz(postcard::to_allocvec(&b.zc));
        let zc_open = b.zc.opened.len();
        let bind = sz(postcard::to_allocvec(&b.bind_rounds)) + sz(postcard::to_allocvec(&b.bind_opened)) + sz(postcard::to_allocvec(&b.next));
        let whir = sz(postcard::to_allocvec(&b.open));
        let sc = sz(postcard::to_allocvec(&b.open.initial_sumcheck))
            + b.open.rounds.iter().map(|r| sz(postcard::to_allocvec(&r.sumcheck))).sum::<usize>()
            + sz(postcard::to_allocvec(&b.open.final_sumcheck))
            + sz(postcard::to_allocvec(&b.open.final_poly));
        let (mut q, mut vals, mut salts, mut sibs, mut uniq, mut qbytes) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut groups: Vec<&Vec<p3_whir::pcs::proof::QueryOpening<Fa4, Ea4, <Mmcs16 as Mmcs<Fa4>>::Proof>>> =
            b.open.rounds.iter().map(|r| &r.queries).collect();
        groups.push(&b.open.final_queries);
        for (gi, g) in groups.iter().enumerate() {
            let mut seen: HashSet<(usize, Vec<u8>)> = HashSet::new();
            let (mut gv, mut gs) = (0usize, 0usize);
            for o in g.iter() {
                q += 1;
                qbytes += sz(postcard::to_allocvec(o));
                let (n, proof) = match o {
                    p3_whir::pcs::proof::QueryOpening::Base { values, proof } => (values.len(), proof),
                    p3_whir::pcs::proof::QueryOpening::Extension { values, proof } => (values.len() * 4, proof),
                };
                vals += n;
                gv += n;
                salts += proof.0.iter().map(Vec::len).sum::<usize>();
                sibs += proof.1.len();
                gs += proof.1.len();
                for (lvl, s) in proof.1.iter().enumerate() {
                    if seen.insert((lvl, postcard::to_allocvec(s).unwrap_or_default())) {
                        uniq += 1;
                    }
                }
            }
            eprintln!("[c3p] {label}: group {gi}: {} queries · {gv} leaf elems · {gs} siblings (depth {})", g.len(),
                g.first().map(|o| match o { p3_whir::pcs::proof::QueryOpening::Base { proof, .. } | p3_whir::pcs::proof::QueryOpening::Extension { proof, .. } => proof.1.len() }).unwrap_or(0));
        }
        eprintln!(
            "[c3p] {label}: TOTAL {} B · shape {:?} · zc {zc} B (opened {zc_open} cols) · bind {bind} B · whir {whir} B = sumcheck+final {sc} B + queries {qbytes} B ({q} openings: leaf {vals} elems = {} B, salts {salts} elems = {} B, siblings {sibs} = {} B, distinct siblings {uniq} = {} B)",
            bytes.len(), b.shape, vals * 4, salts * 4, sibs * 32, uniq * 32
        );
    }

    /// ⭐ SPEED C4 PROBE — what a producer pays to prove hashing IN a proof: the tag-set carrier lays FOUR Poseidon2-16
    /// permutations per row (the tag, the chain step, two decoy derivations), so timing it at three heights gives the
    /// in-circuit permutation rate on this machine, and two scales tell its constant from its slope. C4's producer rate
    /// is that rate over the permutations one payment's verification needs (the `split` counts above: one compression per
    /// sibling, one sponge pass per opened leaf).
    #[test]
    #[ignore] // measurement probe
    fn c4_the_in_circuit_permutation_rate_on_this_machine() {
        let bound = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        for w in [256usize, 1024, 4096] {
            let tags: Vec<_> = (0..w as u64).map(|s| crate::nf_sparse_air::cover_tag_native(bound, s)).collect();
            let wit = vec![crate::nf_sparse_air::TagWitness::Decoy; w];
            let t = std::time::Instant::now();
            let p = crate::nf_sparse_air::prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("proves");
            let ms = t.elapsed().as_secs_f64() * 1e3;
            let perms = 4 * w;
            eprintln!(
                "[c4p] {w} rows · {perms} in-circuit perms · prove {ms:.0} ms · {:.0} perms/s · {} B",
                perms as f64 / (ms / 1e3), p.len()
            );
        }
    }

    #[test]
    #[ignore] // measurement probe
    fn c3_where_a_payment_carriers_bytes_go() {
        let (m, _) = crate::member_path_gate::null_member_carrier().expect("member carrier");
        split("member_carrier", &m);
        let bound = crate::poseidon2_compress::lanes_of(&[7u64, 8, 9, 10]);
        let tags: Vec<_> = (0..8u64).map(|s| crate::nf_sparse_air::cover_tag_native(bound, s)).collect();
        let wit = vec![crate::nf_sparse_air::TagWitness::Decoy; 8];
        let s = crate::nf_sparse_air::prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("spend_or_decoy");
        split("spend_or_decoy", &s);
    }
}

/// ⭐ SPEED C4 PROBE 2 (lane speed4, 2026-11-12) — the in-circuit Poseidon2 rate a PRODUCER would pay folding public proof
/// data: a narrow, unblinded table of one permutation per row (`pow_pq_air::build_perm_chain`, the production constants),
/// proved by the committed door, GPU on (`gpu_grind::install`) and at the slice's threads; three heights, so the constant
/// is told from the slope. The tag-set carrier probe (`c4_the_in_circuit_permutation_rate_on_this_machine`) is the wide,
/// blinded upper bound; this is the narrow lower bound a dedicated aggregation table would sit near.
#[cfg(test)]
mod c4_probe2 {
    #[test]
    #[ignore] // measurement probe
    fn c4_a_narrow_unblinded_permutation_table_on_every_core_and_the_gpu() {
        let gpu = crate::gpu_grind::install();
        let threads = rayon::current_num_threads();
        let seed = [p3_koala_bear::KoalaBear::new(7); crate::pow_pq_air::WIDTH];
        for rows in [1usize << 10, 1 << 12, 1 << 14] {
            let cols = crate::pow_pq_air::build_perm_chain(seed, rows);
            let t = std::time::Instant::now();
            let p = crate::committed_air::prove_air_committed_bytes(cols, crate::pow_pq_air::make_perm_constraint(), &[])
                .expect("the permutation table proves");
            let s = t.elapsed().as_secs_f64();
            eprintln!(
                "[c4p2] {rows} perms · {} cols · {threads} thread(s) · gpu {gpu} · prove {:.0} ms · {:.0} perms/s · {} B",
                crate::pow_pq_air::P2_COLS, s * 1e3, rows as f64 / s, p.len()
            );
        }
    }
}

/// ⭐ SPEED C4 PROBE 3 (lane speed4, 2026-11-13) — the producer's own parameters. A block aggregate is proved by a NODE (GPU
/// grinds, a native verifier), so it is a light-decider round (`light_commit::LIGHT_COMMIT_PARAMS`: the wide Johnson regime,
/// rate growth 1, grind ceiling 24), not a payer's carrier (`CarrierParams::LIVE`: the phone's grind ceiling of 16, which steps
/// the schedule down into more rounds and queries). The same narrow permutation table under both, at two heights, with the
/// phase split printed (`MONEROUSD_PROVE_PROGRESS=1`); threads are the caller's (`RAYON_NUM_THREADS`).
#[cfg(test)]
mod c4_probe3 {
    #[test]
    #[ignore] // measurement probe
    fn c4_the_permutation_rate_under_the_producers_own_parameters() {
        let gpu = crate::gpu_grind::install();
        let threads = rayon::current_num_threads();
        let seed = [p3_koala_bear::KoalaBear::new(7); crate::pow_pq_air::WIDTH];
        for (label, params) in [("light", crate::light_commit::LIGHT_COMMIT_PARAMS), ("live", crate::committed_air::CarrierParams::LIVE)] {
            for rows in [1usize << 12, 1 << 14] {
                let cols = crate::pow_pq_air::build_perm_chain(seed, rows);
                let t = std::time::Instant::now();
                let p = crate::committed_air::prove_air_committed_bytes_with(cols, crate::pow_pq_air::make_perm_constraint(), &[], params)
                    .expect("the permutation table proves");
                let s = t.elapsed().as_secs_f64();
                eprintln!(
                    "[c4p3] {label} · {rows} perms · {threads} thread(s) · gpu {} · prove {:.0} ms · {:.0} perms/s · {} B",
                    gpu.split(':').next().unwrap_or(""), s * 1e3, rows as f64 / s, p.len()
                );
            }
        }
    }
}
