//! MonerousD Protocol — `nf_band_air`: the aggregate-ready keyed shard sub-carrier of DB-353 SHAPE (2) — **a PINS-ONLY
//! MEASURING INSTRUMENT, not a production door.**
//!
//! ⛔ SHAPE (2) WAS REFUTED BY THIS MODULE'S OWN MEASUREMENT (2026-09-29 22:2x, `band_subcarrier_proves_verifies_and_refuses_every_tamper`):
//! the COMMITTED sub-carrier at the production cover (65,536 rows × 561 columns) proves in 179.9 s / 170,169 B / verify
//! 355 ms — ≈ 2.7 ms per row — against the DIRECT keyed carrier's 3.7 s / 20 KB (0.056 ms per row). A block is ~65k rows
//! whoever proves it, so per-shard sub-carriers aggregated through `settlement_delta` mean MINUTES of committed proving per
//! block mesh-wide. Production uses SHAPE (3) instead (`docs/DB-353-BAND-DOOR-SPEC.md` §8b, §10): one direct keyed carrier
//! per block, `k`-chained (`nf_sparse_air::prove_chained_band_transition`), applied by the node's `nf_sparse::BandDoor`.
//! This module stays so the refutation stays MEASURABLE (its three pins re-run the number) and so the aggregate-ready
//! layout is on record for any future inner gate; nothing in the node reaches it.
//!
//! The shape it measures: for each shard `s` the block's admitted tags touch, a HOLDER of `s` proves the sub-transition
//! `pre_root_s → post_root_s` for exactly that shard's keys (`docs/DB-353-SOUND-SHARDING-CARRIER-SPEC.md` §8–§9, §12),
//! and a later producer AGGREGATES the touched shards' sub-carriers through the settlement-aggregate shape
//! (`settlement_delta`: one bound step per sub-carrier row). The sub-carrier is the same nested block gate as
//! `nf_sparse_air::SparseBlockGate` — two Poseidon2 chains per row, the running-root carry, the KEY binding of every
//! insert to the public key digest — laid out for the aggregate:
//!
//! - **Every next-row read sits in ONE contiguous run** (`K_SHIFT_LO .. K_SHIFT_LO + K_SHIFT_N`): the aggregate carries
//!   an inner gate's rotation as the run its `shifted_cols()` declares, so the wide permutation blocks live after it.
//! - **Public inputs are extension-field values** (`SparsePubs<Ea4>`) built from the aggregate row's own tuple cells by
//!   the per-row factory, with a base-field copy kept when the carrier stands alone (the zerocheck's base round 0).
//! - **No integer selector on a public value.** The nested gate bound its post root at `bind_at` (a point selector
//!   built from an INTEGER the verifier knows). In an aggregate the per-row count is a CELL, so the count enters as a
//!   field value: a committed `live` flag (1 for the real inserts, then 0), boolean, monotone at boundaries, and a
//!   running counter whose end is bound to the public `n_real`. The running root advances only through live inserts;
//!   padding inserts prove non-membership of their (irrelevant) keys against the final root and move nothing.
//! - **`residuals()` is exposed**, so the outer bound step folds them against the row's own γ-power chain.
//!
//! The transcript bind is `[BAND_DOMAIN, pre(8), post(8), keys_digest(8), n_real, 0 × 7]` — one domain word and a
//! `BAND_TUPLE_VALS` tuple of four digests' width, a legal chain stride (`settlement_delta::chain_stride_is_exact`).

use crate::air_zerocheck::{cyclic_shift_sigma, AirConstraint, Row};
use crate::hiding_decider::{Ea4, Fa4};
use crate::nf_sparse_air::{
    emit_chain_row_at, empty_leaf_native, fkred, key_lanes_of, keys_digest_absorb_inputs, keys_digest_init, lane_end_level,
    lane_start_level, native_sparse_insert_transition, nf_bit, push_chain_residuals_at, spent_leaf_native, SparseInsertWitness,
    KEY_LANES, NF_SPARSE_DEPTH,
};
use crate::nullifier_insert_air::poseidon_pair_native;
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use crate::pow_pq_air::{P2_COLS, P2_CONSTRAINT_DEGREE, PERM_OUT};
use p3_field::PrimeCharacteristicRing;

/// Fold-level bits: the low `LEVEL_BITS` of the row index are the level `l` (DEPTH = 256 = 2^8), the high bits the insert.
const LEVEL_BITS: usize = 8;
const _: () = assert!(1 << LEVEL_BITS == NF_SPARSE_DEPTH);

// ── the layout: the contiguous next-row-read run first, the wide blocks after it ──────────────────────────────────
/// The shared sibling at this level.
pub const K_SIB: usize = 0;
/// The direction bit (the KEY's bit at this level); read at the next row by the lane doubling law.
pub const K_DIR: usize = K_SIB + DIGEST_LANES;
/// The empty-leaf chain's accumulator in; the spent-leaf chain's; both read at the next row (the σ carry).
pub const K_AINE: usize = K_DIR + 1;
pub const K_AINS: usize = K_AINE + DIGEST_LANES;
/// The running root `R_i` (constant across an insert's rows; advances at a live boundary).
pub const K_RROOT: usize = K_AINS + DIGEST_LANES;
/// The lane accumulator and the nine frozen lane values (the key binding, `nf_sparse_air` §3).
pub const K_KACC: usize = K_RROOT + DIGEST_LANES;
pub const K_KEY: usize = K_KACC + 1;
/// `live`: 1 for the real inserts, 0 for the padding; `CNT`: live inserts before this one.
pub const K_LIVE: usize = K_KEY + KEY_LANES;
pub const K_CNT: usize = K_LIVE + 1;
/// The running key digest entering the row.
pub const K_DIN: usize = K_CNT + 1;
/// The contiguous run every next-row read falls in: `K_DIR ..= K_DIN + DIGEST_LANES − 1`.
pub const K_SHIFT_LO: usize = K_DIR;
pub const K_SHIFT_N: usize = K_DIN + DIGEST_LANES - K_DIR;
/// The permutation blocks and accumulator outs, after the run.
pub const K_P2E: usize = K_DIN + DIGEST_LANES;
pub const K_AOUTE: usize = K_P2E + P2_COLS;
pub const K_P2S: usize = K_AOUTE + DIGEST_LANES;
pub const K_AOUTS: usize = K_P2S + P2_COLS;
pub const K_P2D: usize = K_AOUTS + DIGEST_LANES;
/// The band sub-carrier trace's width.
pub const BAND_COLS: usize = K_P2D + P2_COLS;
const _: () = assert!(K_KEY + KEY_LANES == K_LIVE, "the lanes sit between the accumulator and the live flag");

/// The shifted run the aggregate's bound step carries for this class: `(lo, n)` for `BoundLayout::shifted_lo/shifted`.
#[must_use]
pub const fn band_shifted_run() -> (usize, usize) {
    (K_SHIFT_LO, K_SHIFT_N)
}

/// The domain word every band sub-carrier's transcript opens with — the class separator the aggregate checks on every row.
#[must_use]
pub fn band_domain() -> Fa4 {
    Fa4::from_u64(0x0042_414e_4453_4844) // "BANDSHD"
}
/// The per-row public tuple: `pre ‖ post ‖ keys_digest ‖ n_real ‖ zero pad` — FOUR digests' width, a legal chain stride.
pub const BAND_TUPLE_VALS: usize = 4 * DIGEST_LANES; // PRODUCTION-SCALE-REVIEWED: a tuple WIDTH (four digest lanes' worth), not a block or cover count

/// The sub-carrier's public inputs, in the field the row lives in: base for a standalone carrier's round 0, the
/// extension when built from an aggregate row's cells.
#[derive(Clone, Copy, Debug)]
pub struct SparsePubs<F> {
    pub pre: [F; DIGEST_LANES],
    pub post: [F; DIGEST_LANES],
    pub keys_digest: [F; DIGEST_LANES],
    pub n_real: F,
}

impl SparsePubs<Fa4> {
    /// From the native values: the roots and digest as canonical u64 lanes, the real count as an integer.
    #[must_use]
    pub fn from_native(pre: Digest, post: Digest, keys_digest: Digest, n_real: usize) -> Self {
        let f = |d: Digest| -> [Fa4; DIGEST_LANES] { core::array::from_fn(|c| fkred(d[c])) };
        Self { pre: f(pre), post: f(post), keys_digest: f(keys_digest), n_real: Fa4::from_u64(n_real as u64) }
    }
    /// Lifted into the extension.
    #[must_use]
    pub fn lift(&self) -> SparsePubs<Ea4> {
        let l = |a: [Fa4; DIGEST_LANES]| -> [Ea4; DIGEST_LANES] { core::array::from_fn(|c| Ea4::from(a[c])) };
        SparsePubs { pre: l(self.pre), post: l(self.post), keys_digest: l(self.keys_digest), n_real: Ea4::from(self.n_real) }
    }
    /// The transcript bind: `[BAND_DOMAIN, pre, post, keys_digest, n_real, zero pad]`.
    #[must_use]
    pub fn statement_bind(&self) -> Vec<Fa4> {
        let mut b = vec![band_domain()];
        b.extend_from_slice(&self.pre);
        b.extend_from_slice(&self.post);
        b.extend_from_slice(&self.keys_digest);
        b.push(self.n_real);
        b.extend(core::iter::repeat_n(Fa4::ZERO, DIGEST_LANES - 1));
        debug_assert_eq!(b.len(), 1 + BAND_TUPLE_VALS);
        b
    }
}

/// `γ^0 … γ^k` for the band gate's residuals: three permutation blocks and every law below (≈ 205 beyond the blocks).
#[must_use]
pub fn band_powers(gamma: Ea4) -> Vec<Ea4> {
    let n = 3 * crate::pow_pq_air::perm_residual_count() + 256;
    let mut v = Vec::with_capacity(n);
    let mut p = Ea4::ONE;
    for _ in 0..n {
        v.push(p);
        p *= gamma;
    }
    v
}

/// The band sub-carrier's gate. Standalone (`with_base`) it folds its residuals with its own γ powers and has a base-field
/// round 0; inside the aggregate (`from_cells`) its publics are the row's cells and the bound step folds the residuals.
pub struct SparseBandGate {
    pub gamma: Ea4,
    pub gpow: Vec<Ea4>,
    pub pubs: SparsePubs<Ea4>,
    /// The base-field publics of a standalone carrier — `None` when built from an aggregate row's (extension) cells.
    pub base: Option<SparsePubs<Fa4>>,
}

impl SparseBandGate {
    /// A standalone sub-carrier's gate over native publics.
    #[must_use]
    pub fn with_base(gamma: Ea4, pubs: SparsePubs<Fa4>) -> Self {
        Self { gamma, gpow: band_powers(gamma), pubs: pubs.lift(), base: Some(pubs) }
    }
    /// The aggregate's per-row gate: publics are the row's own tuple cells; γ is the row's power chain, not a constant.
    #[must_use]
    pub fn from_cells(pubs: SparsePubs<Ea4>) -> Self {
        Self { gamma: Ea4::ZERO, gpow: Vec::new(), pubs, base: None }
    }

    /// Every law of the relation, GENERIC over the field the row lives in (the type parameter is NAMED `Ea4` so the laws
    /// read as they do everywhere else in this crate); the residual count is a constant of the class (no data-dependent
    /// push), which `settlement_delta::class_residual_count` relies on.
    #[allow(non_camel_case_types, clippy::too_many_lines)]
    pub fn residuals_in<Ea4>(local: &Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4], pubs: &SparsePubs<Ea4>) -> Vec<Ea4>
    where
        Ea4: p3_field::Field + p3_field::Algebra<Fa4>,
    {
        let one = Ea4::ONE;
        let zero = Ea4::from(Fa4::ZERO);
        let mut rs: Vec<Ea4> = Vec::with_capacity(3 * crate::pow_pq_air::perm_residual_count() + 224);
        // per-row: the direction boolean and both chains (input welds, permutation, OUTPUT weld)
        let dir = local[K_DIR];
        rs.push(dir * (one - dir));
        push_chain_residuals_at(local, K_SIB, K_DIR, K_AINE, K_P2E, K_AOUTE, &mut rs);
        push_chain_residuals_at(local, K_SIB, K_DIR, K_AINS, K_P2S, K_AOUTS, &mut rs);
        // selectors over the HIGH-bit-first row index: low LEVEL_BITS = fold level, high bits = insert index
        let nvars = x.len();
        let mut is_level0 = one;
        let mut is_boundary = one;
        for k in (nvars - LEVEL_BITS)..nvars {
            is_level0 = is_level0 * (one - x[k]);
            is_boundary = is_boundary * x[k];
        }
        let mut is_first_insert = one;
        let mut is_last_insert = one;
        for x_k in x.iter().take(nvars - LEVEL_BITS) {
            is_first_insert = is_first_insert * (one - *x_k);
            is_last_insert = is_last_insert * *x_k;
        }
        let not_boundary = one - is_boundary;
        let not_last = one - is_last_insert;
        let level_is = |l: usize| -> Ea4 {
            let mut p = one;
            for (b, x_k) in x[nvars - LEVEL_BITS..].iter().enumerate() {
                let bit = (l >> (LEVEL_BITS - 1 - b)) & 1;
                p = p * if bit == 1 { *x_k } else { one - *x_k };
            }
            p
        };
        let sigma = cyclic_shift_sigma(x);
        let live = local[K_LIVE];
        let live_n = at(K_LIVE, &sigma);
        let cnt = local[K_CNT];
        let cnt_n = at(K_CNT, &sigma);
        let sp = spent_leaf_native();
        // ── the chains, the running root, the endpoints ─────────────────────────────────────────────────────────────
        for c in 0..DIGEST_LANES {
            let aine = local[K_AINE + c];
            let ains = local[K_AINS + c];
            let aoe = local[K_AOUTE + c];
            let aos = local[K_AOUTS + c];
            let rr = local[K_RROOT + c];
            let rr_n = at(K_RROOT + c, &sigma);
            // level 0: seed reset
            rs.push(is_level0 * (aine - zero));
            rs.push(is_level0 * (ains - Ea4::from(fkred(sp[c]))));
            // boundary: NON-MEMBERSHIP — the empty-fold hits the CURRENT root R_i
            rs.push(is_boundary * (aoe - rr));
            // first insert: running root == pre
            rs.push(is_first_insert * (rr - pubs.pre[c]));
            // within an insert: chain the fold AND carry the running root unchanged
            rs.push(not_boundary * (at(K_AINE + c, &sigma) - aoe));
            rs.push(not_boundary * (at(K_AINS + c, &sigma) - aos));
            rs.push(not_boundary * (rr_n - rr));
            // the root after this insert: the spent fold when live, unchanged when padding
            let after = rr + live * (aos - rr);
            // boundary, not the last insert: the next insert's running root
            rs.push(is_boundary * not_last * (rr_n - after));
            // the last insert's boundary binds the PUBLIC post root
            rs.push(is_boundary * is_last_insert * (after - pubs.post[c]));
        }
        // ── live and the count: a field-valued real count, no integer selector ──────────────────────────────────────
        rs.push(live * (one - live)); // boolean
        rs.push(is_first_insert * is_level0 * (live - one)); // insert 0 is real (a sub-carrier exists only for a touched shard)
        rs.push(not_boundary * (live_n - live)); // frozen within an insert
        rs.push(is_boundary * not_last * (one - live) * live_n); // monotone: once padding, always padding
        rs.push(is_first_insert * is_level0 * cnt); // the count starts at zero
        rs.push(not_boundary * (cnt_n - cnt)); // frozen within an insert
        rs.push(is_boundary * not_last * (cnt_n - cnt - live)); // advances by the live flag at each boundary
        rs.push(is_boundary * is_last_insert * (cnt + live - pubs.n_real)); // and ends at the PUBLIC real count
        // ── the key binding: lanes accumulate the key's bits, frozen, absorbed into the digest chain ─────────────────
        let kacc = local[K_KACC];
        let mut lane_start_any = zero;
        let mut lane_end_any = zero;
        for j in 0..KEY_LANES {
            let start = level_is(lane_start_level(j));
            let end = level_is(lane_end_level(j));
            lane_start_any = lane_start_any + start;
            lane_end_any = lane_end_any + end;
            rs.push(end * (local[K_KEY + j] - kacc)); // hand-over at the lane's last level
            rs.push(not_boundary * (at(K_KEY + j, &sigma) - local[K_KEY + j])); // frozen across the insert
        }
        rs.push(lane_start_any * (kacc - dir));
        rs.push((one - lane_end_any) * (at(K_KACC, &sigma) - (kacc + kacc) - at(K_DIR, &sigma)));
        // the digest chain: level 254 absorbs live·lanes 0..7, level 255 (the boundary) absorbs live·lane 8 + REAL/PAD
        let sel254 = level_is(NF_SPARSE_DEPTH - 2);
        let sel255 = is_boundary;
        crate::pow_pq_air::push_perm_residuals(local, K_P2D, &mut rs);
        let init = keys_digest_init();
        let real_d = Ea4::from(Fa4::from_u64(crate::nf_sparse_air::KEYS_DIGEST_REAL));
        let pad_d = Ea4::from(Fa4::from_u64(crate::nf_sparse_air::KEYS_DIGEST_PAD));
        for c in 0..DIGEST_LANES {
            let din = local[K_DIN + c];
            let din_n = at(K_DIN + c, &sigma);
            let left = local[K_P2D + c];
            let right = local[K_P2D + DIGEST_LANES + c];
            let out_c = local[K_P2D + PERM_OUT + c];
            rs.push(is_first_insert * is_level0 * (din - Ea4::from(fkred(init[c]))));
            rs.push(left - din);
            let r254 = live * local[K_KEY + c];
            let r255 = if c == 0 {
                live * local[K_KEY + KEY_LANES - 1]
            } else if c == 1 {
                pad_d + live * (real_d - pad_d)
            } else {
                zero
            };
            rs.push(right - (sel254 * r254 + sel255 * r255));
            rs.push((one - sel254 - sel255) * (din_n - din));
            rs.push(sel254 * (din_n - out_c));
            rs.push(sel255 * not_last * (din_n - out_c));
            rs.push(sel255 * is_last_insert * (out_c - pubs.keys_digest[c]));
        }
        rs
    }
}

impl AirConstraint for SparseBandGate {
    fn degree(&self, _nvars: usize) -> usize {
        // MEASURED by the degree census (`band_gate_passes_the_three_censuses`): 3 — the permutation cube; every other law
        // is a product of point selectors (degree 1 per variable) with at most two cells.
        P2_CONSTRAINT_DEGREE
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let rs = Self::residuals_in::<Ea4>(local, at, x, &self.pubs);
        let mut out = Ea4::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }
    /// The aggregate folds these against the row's own γ-power chain.
    fn residuals(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Vec<Ea4> {
        Self::residuals_in::<Ea4>(local, at, x, &self.pubs)
    }
    fn has_base_eval(&self) -> bool {
        self.base.is_some()
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let base = self.base.as_ref().expect("eval_base is only reached when has_base_eval() said so");
        let at2 = |c: usize, _p: &[Fa4]| -> Fa4 { at(c) };
        let rs = Self::residuals_in::<Fa4>(local, &at2, x, base);
        let mut out = Ea4::ZERO;
        for (k, r) in rs.into_iter().enumerate() {
            out += self.gpow[k] * r;
        }
        out
    }
    /// The next-row reads: the one contiguous run the aggregate carries as this class's rotation.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        Some((K_SHIFT_LO..K_SHIFT_LO + K_SHIFT_N).collect())
    }
    /// Every cell is read by a law; the census refuses a free one.
    fn free_columns(&self) -> Option<Vec<usize>> {
        Some(Vec::new())
    }
}

/// Lay the band trace: `inserts.len()` a power of two, the first `real_n` REAL (they advance the running root), the rest
/// padding whose keys the digest ignores and whose inserts move nothing — every padding witness must still be a valid
/// non-membership against the FINAL root (the caller builds them against the tree after the real inserts). Returns
/// `(cols, post_root, keys_digest)`.
pub fn sparse_band_cols(inserts: &[SparseInsertWitness], pre_root: Digest, real_n: usize) -> Option<(Vec<Vec<Fa4>>, Digest, Digest)> {
    let n = inserts.len();
    if n == 0 || !n.is_power_of_two() || real_n == 0 || real_n > n {
        return None;
    }
    let depth = NF_SPARSE_DEPTH;
    let mut rows: Vec<Vec<Fa4>> = Vec::with_capacity(n * depth);
    let mut running = pre_root;
    let mut din = keys_digest_init();
    let mut cnt = 0u64;
    for (idx, w) in inserts.iter().enumerate() {
        let live = idx < real_n;
        let post = native_sparse_insert_transition(w, running)?; // non-membership against the CURRENT root, then the flip
        let mut acc_e = empty_leaf_native();
        let mut acc_s = spent_leaf_native();
        let lanes = key_lanes_of(&w.key);
        let (r254, r255) = keys_digest_absorb_inputs(&lanes, live);
        let mut kacc = 0u64;
        for l in 0..depth {
            let mut row = vec![Fa4::ZERO; BAND_COLS];
            let sib = w.copath[l];
            let dir = nf_bit(&w.key, l) as u64;
            for c in 0..DIGEST_LANES {
                row[K_SIB + c] = fkred(sib[c]);
                row[K_RROOT + c] = fkred(running[c]);
                row[K_DIN + c] = fkred(din[c]);
            }
            row[K_DIR] = Fa4::from_u64(dir);
            acc_e = emit_chain_row_at(&mut row, K_AINE, K_P2E, K_AOUTE, acc_e, sib, dir);
            acc_s = emit_chain_row_at(&mut row, K_AINS, K_P2S, K_AOUTS, acc_s, sib, dir);
            let lane_start = (0..KEY_LANES).any(|j| lane_start_level(j) == l);
            kacc = if lane_start { dir } else { (kacc << 1) | dir };
            row[K_KACC] = Fa4::from_u64(kacc);
            for j in 0..KEY_LANES {
                row[K_KEY + j] = lanes[j];
            }
            row[K_LIVE] = Fa4::from_u64(u64::from(live));
            row[K_CNT] = Fa4::from_u64(cnt);
            let right: Digest = if l == depth - 2 {
                r254
            } else if l == depth - 1 {
                r255
            } else {
                [0u64; DIGEST_LANES]
            };
            crate::pow_pq_air::lay_perm_row_flat(&mut row, K_P2D, crate::pow_pq_air::pair_state(&din, &right));
            if l >= depth - 2 {
                din = poseidon_pair_native(din, right);
            }
            rows.push(row);
        }
        if live {
            running = post;
            cnt += 1;
        }
    }
    let cols: Vec<Vec<Fa4>> = (0..BAND_COLS).map(|c| rows.iter().map(|r| r[c]).collect()).collect();
    Some((cols, running, din))
}

/// PROVE a shard's sub-transition as a COMMITTED carrier (the format the settlement aggregate consumes): the real inserts
/// first, padding to a power of two after. Returns `(carrier, post_root, keys_digest, public_bind)`; the door recomputes
/// the digest from the header's tags (`keys_digest_of` over the shard's KEYS at `inserts.len()`) and the roots from its
/// running band — nothing here is taken from the prover.
pub fn prove_shard_subcarrier_bytes(inserts: &[SparseInsertWitness], pre_root: Digest, real_n: usize) -> Option<(Vec<u8>, Digest, Digest, Vec<Fa4>)> {
    let (cols, post, kd) = sparse_band_cols(inserts, pre_root, real_n)?;
    let pubs = SparsePubs::from_native(pre_root, post, kd, real_n);
    let bind = pubs.statement_bind();
    let make = move |g: Ea4| SparseBandGate::with_base(g, pubs);
    // ⛔ THE CHAINED DOOR (2026-11-10, found by the door census): this gate reads the next row (`band_shifted_run`), and the
    // plain committed door binds only the row at `r` — it now carries no next-row value and refuses a gate that reads one.
    // The chained door proves the next-row values to be the committed columns' own. NO blinding rows: this table holds
    // public tags and public roots (it was never blinded), and at its width a second half of blinding rows does not
    // fit the commitment's size limit (MEASURED 2026-11-10: the blinded chained door panicked `Increase folding_factor_0`).
    let bytes = crate::committed_air::prove_air_chained_bytes(cols, make, &bind)?;
    Some((bytes, post, kd, bind))
}

/// VERIFY a shard sub-carrier standing alone against the door's own `(pre, post, keys_digest, n_real, n)`. Fail-closed on
/// every decode / shape / constraint / bind mismatch.
#[must_use]
pub fn verify_shard_subcarrier_bytes(bytes: &[u8], pre_root: Digest, post_root: Digest, keys_digest: Digest, n_real: usize, n: usize) -> bool {
    if bytes.is_empty() || n == 0 || !n.is_power_of_two() || n_real == 0 || n_real > n {
        return false;
    }
    let Some(rows) = n.checked_mul(NF_SPARSE_DEPTH) else { return false };
    let pubs = SparsePubs::from_native(pre_root, post_root, keys_digest, n_real);
    let bind = pubs.statement_bind();
    let make = move |g: Ea4| SparseBandGate::with_base(g, pubs);
    crate::committed_air::verify_air_chained_bytes(bytes, make, &bind, (rows.trailing_zeros() as usize, BAND_COLS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nf_sparse_air::{empty_subtree_native, keys_digest_of, PRODUCTION_BLOCK_COVER};

    fn nf_from(seed: u64) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        b[8] = 0xBA;
        b[9] = 0x4D;
        b
    }

    /// A reference tree over the spent keys: the memo oracle of `nf_sparse_air`'s tests, kept minimal.
    #[derive(Default)]
    struct RefTree {
        nodes: std::collections::HashMap<(usize, [u8; 32]), Digest>,
    }
    impl RefTree {
        fn canon(nf: &[u8; 32], level: usize) -> [u8; 32] {
            let mut p = *nf;
            let full = level >> 3;
            for b in p.iter_mut().take(full) {
                *b = 0;
            }
            if level & 7 != 0 {
                p[full] &= !((1u8 << (level & 7)) - 1);
            }
            p
        }
        fn node_at(&self, level: usize, canon: &[u8; 32]) -> Digest {
            match self.nodes.get(&(level, *canon)) {
                Some(d) => *d,
                None => empty_subtree_native(level),
            }
        }
        fn root(&self) -> Digest {
            self.node_at(NF_SPARSE_DEPTH, &[0u8; 32])
        }
        fn copath(&self, nf: &[u8; 32]) -> Vec<Digest> {
            (0..NF_SPARSE_DEPTH)
                .map(|level| {
                    let mut sib = *nf;
                    sib[level >> 3] ^= 1u8 << (level & 7);
                    self.node_at(level, &Self::canon(&sib, level))
                })
                .collect()
        }
        fn insert_and_witness(&mut self, nf: &[u8; 32]) -> Vec<Digest> {
            let copath = self.copath(nf);
            self.nodes.insert((0, *nf), spent_leaf_native());
            for level in 1..=NF_SPARSE_DEPTH {
                let bit = nf_bit(nf, level - 1);
                let with_nf = Self::canon(nf, level - 1);
                let mut sib = *nf;
                sib[(level - 1) >> 3] ^= 1u8 << ((level - 1) & 7);
                let sib_canon = Self::canon(&sib, level - 1);
                let (l, r) = if bit == 0 { (with_nf, sib_canon) } else { (sib_canon, with_nf) };
                let h = poseidon_pair_native(self.node_at(level - 1, &l), self.node_at(level - 1, &r));
                self.nodes.insert((level, Self::canon(nf, level)), h);
            }
            copath
        }
    }

    /// `keys` real keys inserted in order, then `pad` padding witnesses built against the FINAL tree (valid
    /// non-membership, never applied) — the shape a holder lays for a shard.
    fn lay_inserts(keys: &[[u8; 32]], pad: usize) -> (Vec<SparseInsertWitness>, Digest, Digest) {
        let mut refs = RefTree::default();
        let pre = refs.root();
        let mut inserts: Vec<SparseInsertWitness> = keys.iter().map(|k| SparseInsertWitness { key: *k, copath: refs.insert_and_witness(k) }).collect();
        let post = refs.root();
        for p in 0..pad as u64 {
            let k = nf_from(0xFADE_0000 + p);
            inserts.push(SparseInsertWitness { key: k, copath: refs.copath(&k) }); // NOT inserted: a padding witness
        }
        (inserts, pre, post)
    }

    fn eval_at_row(cols: &[Vec<Fa4>], gate: &SparseBandGate, r: usize) -> Ea4 {
        let nvars = cols[0].len().trailing_zeros() as usize;
        let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
        let local: Vec<Ea4> = (0..cols.len()).map(|c| Ea4::from(cols[c][r])).collect();
        let at = |col: usize, pt: &[Ea4]| -> Ea4 {
            let mut row = 0usize;
            for (k, pk) in pt.iter().enumerate().take(nvars) {
                if *pk == Ea4::ONE {
                    row |= 1 << (nvars - 1 - k);
                }
            }
            Ea4::from(cols[col][row])
        };
        let oob = crate::air_zerocheck::OobLatch::new();
        let v = gate.eval(&Row::new(&local, &oob), &at, &x);
        assert!(!oob.hit(), "fixture row is narrower than the gate reads: it read {}", oob.report());
        v
    }

    /// ⭐ The band gate under the crate's three structural censuses, directly on a production-cover trace (no prove).
    #[test]
    fn band_gate_passes_the_three_censuses() {
        let keys: Vec<[u8; 32]> = (0..PRODUCTION_BLOCK_COVER as u64).map(|i| nf_from(0xBA4D_0000 + i)).collect();
        let (inserts, pre, post) = lay_inserts(&keys, 0);
        let (cols, post2, kd) = sparse_band_cols(&inserts, pre, keys.len()).expect("the honest trace lays");
        assert_eq!(post, post2);
        let nvars = cols[0].len().trailing_zeros() as usize;
        let gate = SparseBandGate::with_base(Ea4::from(Fa4::from_u64(0xBA4D)), SparsePubs::from_native(pre, post, kd, keys.len()));
        let row_local = gate.is_row_local();
        let shifted = if row_local { Some(Vec::new()) } else { gate.shifted_cols() };
        let t0 = std::time::Instant::now();
        crate::air_zerocheck::debug_degree_census(&cols, &gate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_free_witness_census(&cols, &gate, nvars, row_local, &shifted);
        crate::air_zerocheck::debug_decorative_block_census(&cols, &gate, nvars, row_local, &shifted);
        eprintln!("[band-census] degree + free-witness + decorative-block censuses passed in {} ms", t0.elapsed().as_millis());
    }

    /// ⭐⭐⭐ DIRECT EVALUATION at the production cover with padding: the honest trace vanishes on every row; a padding
    /// insert that claims to be live is refused; a claimed real count off by one is refused by the count bind; a
    /// different key under the header's digest is refused at the chain's end; forged lanes are refused at the hand-over; a
    /// forged accumulator at the doubling. Each refusal names its row.
    #[test]
    fn band_direct_eval_binds_keys_counts_and_the_root_only_through_live_inserts() {
        let zero = Ea4::ZERO;
        let n = PRODUCTION_BLOCK_COVER;
        let real = n - 3; // three padding inserts at the production cover: the count law has work to do
        let keys: Vec<[u8; 32]> = (0..real as u64).map(|i| nf_from(0xBA4D_1000 + i)).collect();
        let (inserts, pre, post) = lay_inserts(&keys, n - real);
        let (cols, post2, kd) = sparse_band_cols(&inserts, pre, real).expect("the honest trace lays");
        assert_eq!(post, post2, "the post root is the tree after the REAL inserts only");
        assert_eq!(kd, keys_digest_of(&keys, n), "the lay's digest is the door's native recompute over the real keys at n");
        let rows = cols[0].len();
        assert_eq!(rows, n * NF_SPARSE_DEPTH);
        let gamma = Ea4::from(Fa4::from_u64(0xBA4D_1));
        let gate = SparseBandGate::with_base(gamma, SparsePubs::from_native(pre, post, kd, real));
        let t0 = std::time::Instant::now();
        for r in 0..rows {
            assert_eq!(eval_at_row(&cols, &gate, r), zero, "honest band trace: row {r} satisfies the gate");
            if r % 8192 == 8191 {
                eprintln!("[band] honest rows {}/{rows} vanish ({} ms)", r + 1, t0.elapsed().as_millis());
            }
        }
        // (E) a real count off by one: the count bind at the last row refuses
        let gate_e = SparseBandGate::with_base(gamma, SparsePubs::from_native(pre, post, kd, real + 1));
        assert_ne!(eval_at_row(&cols, &gate_e, rows - 1), zero, "(E) n_real + 1 is refused at the count bind");
        assert_eq!(eval_at_row(&cols, &gate_e, rows - 2), zero, "(E) every other row is untouched");
        // (F) a padding insert that claims to be live on all its rows: refused at its boundary (the carry now demands
        // the spent fold, the count moves, and the monotone law sees a rise)
        let mut cols_f = cols.clone();
        let pad0 = real * NF_SPARSE_DEPTH;
        for r in pad0..pad0 + NF_SPARSE_DEPTH {
            cols_f[K_LIVE][r] = Fa4::ONE;
        }
        assert_ne!(eval_at_row(&cols_f, &gate, pad0 + NF_SPARSE_DEPTH - 1), zero, "(F) a padding insert claiming live is refused at its boundary");
        // (B) a different key at insert 0's slot under the header's digest: refused at the chain's end only
        let mut forged_keys = keys.clone();
        forged_keys[0] = nf_from(0xBA4D_FFFF);
        let (f_inserts, f_pre, f_post) = lay_inserts(&forged_keys, n - real);
        assert_eq!(f_pre, pre);
        let (cols_b, _, kd_b) = sparse_band_cols(&f_inserts, f_pre, real).expect("the forged block lays");
        assert_ne!(kd_b, kd);
        let gate_b = SparseBandGate::with_base(gamma, SparsePubs::from_native(pre, f_post, kd, real));
        assert_ne!(eval_at_row(&cols_b, &gate_b, rows - 1), zero, "(B) refused at the digest bind");
        assert_eq!(eval_at_row(&cols_b, &gate_b, NF_SPARSE_DEPTH - 1), zero, "(B) insert 0's boundary is internally consistent");
        // (C) forge the frozen lanes to the header key's while the bits walk the forged key: the hand-over refuses
        let honest_lanes = key_lanes_of(&keys[0]);
        let forged_lanes = key_lanes_of(&forged_keys[0]);
        let first_diff = (0..KEY_LANES).find(|&j| honest_lanes[j] != forged_lanes[j]).expect("the keys differ in some lane");
        let mut cols_c = cols_b.clone();
        for j in 0..KEY_LANES {
            for r in 0..NF_SPARSE_DEPTH {
                cols_c[K_KEY + j][r] = honest_lanes[j];
            }
        }
        let end_row = lane_end_level(first_diff);
        assert_ne!(eval_at_row(&cols_c, &gate_b, end_row), zero, "(C) forged lanes refused at lane {first_diff}'s end");
        // (D) also forge the accumulator at that lane's end: the doubling law refuses one row earlier
        let mut cols_d = cols_c.clone();
        cols_d[K_KACC][end_row] = honest_lanes[first_diff];
        assert!(end_row > lane_start_level(first_diff));
        assert_ne!(eval_at_row(&cols_d, &gate_b, end_row - 1), zero, "(D) the doubling law refuses the jump");
    }

    /// ⭐⭐⭐ THE COMMITTED SUB-CARRIER on the production path: proves and verifies against the door's own values; a changed
    /// digest, a wrong real count, a wrong post root, an empty carrier and a wrong shape are refused; a position forgery
    /// verifies under its own digest and is refused under the header's. Prints `[band-cost]`.
    #[test]
    fn band_subcarrier_proves_verifies_and_refuses_every_tamper() {
        let n = PRODUCTION_BLOCK_COVER;
        let real = n - 1;
        let keys: Vec<[u8; 32]> = (0..real as u64).map(|i| nf_from(0xBA4D_2000 + i)).collect();
        let (inserts, pre, post) = lay_inserts(&keys, n - real);
        let t0 = std::time::Instant::now();
        let (bytes, post2, kd, bind) = prove_shard_subcarrier_bytes(&inserts, pre, real).expect("the sub-carrier proves");
        let prove_ms = t0.elapsed().as_millis();
        assert_eq!(post, post2);
        assert_eq!(kd, keys_digest_of(&keys, n));
        assert_eq!(bind.len(), 1 + BAND_TUPLE_VALS);
        assert_eq!(bind[0], band_domain());
        let t1 = std::time::Instant::now();
        assert!(verify_shard_subcarrier_bytes(&bytes, pre, post, kd, real, n), "the honest sub-carrier verifies");
        eprintln!("[band-cost] N={n} (real {real}) prove {prove_ms} ms, {} B, verify {} ms", bytes.len(), t1.elapsed().as_millis());
        assert!(bytes.len() <= 1_800_000);
        let mut bad_kd = kd;
        bad_kd[2] = crate::nullifier_insert_air::kadd(bad_kd[2], 1);
        assert!(!verify_shard_subcarrier_bytes(&bytes, pre, post, bad_kd, real, n), "a changed digest is refused");
        assert!(!verify_shard_subcarrier_bytes(&bytes, pre, post, kd, real - 1, n), "a wrong real count is refused");
        let mut bad_post = post;
        bad_post[0] = crate::nullifier_insert_air::kadd(bad_post[0], 1);
        assert!(!verify_shard_subcarrier_bytes(&bytes, pre, bad_post, kd, real, n), "a wrong post root is refused");
        assert!(!verify_shard_subcarrier_bytes(&[], pre, post, kd, real, n), "an empty carrier is refused");
        assert!(!verify_shard_subcarrier_bytes(&bytes, pre, post, kd, real, n / 2), "a wrong shape is refused");
        // the position forgery
        let mut forged_keys = keys.clone();
        forged_keys[0] = nf_from(0xBA4D_EEEE);
        let (f_inserts, _, f_post) = lay_inserts(&forged_keys, n - real);
        let (f_bytes, f_post2, f_kd, _) = prove_shard_subcarrier_bytes(&f_inserts, pre, real).expect("the forged block is an honest transition of its own keys");
        assert_eq!(f_post, f_post2);
        assert!(verify_shard_subcarrier_bytes(&f_bytes, pre, f_post, f_kd, real, n), "under its OWN digest it verifies");
        assert!(!verify_shard_subcarrier_bytes(&f_bytes, pre, f_post, kd, real, n), "REFUSED under the header's digest");
    }
}
