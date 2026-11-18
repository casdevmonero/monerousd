// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// Protocol: MonerousD — post-quantum private block-DAG. Module: SPEED C4, step 1 (lane c4, 2026-11-13).

//! ⭐ C4 STEP 1 — A PAYMENT CARRIER'S WHIR OPENINGS, AUTHENTICATED IN-CIRCUIT.
//!
//! WHY. Every node downloads every payment's ~310 KB of carriers to check them natively (the bandwidth law, speed spec
//! §14): that byte count, not the block cap, is the chain's throughput limit. C4 moves the check INSIDE the block proof so
//! a node holds ≈ 1.3 KB a payment. The expensive half of checking a WHIR opening is its query openings — each leaf's
//! sponge and its Merkle path, ~3,300 Poseidon2 permutations a carrier (§BJ) — and `opening_auth_air` already proves that
//! half as ROWS of one narrow table (leaf sponge + path, the tie row-local, §AJ). This module is the bridge from a REAL
//! carrier to that table: it reads each query group's openings and the root they open, in the exact encoding the hiding
//! MMCS hashes (the opened values then the 8-word salt; an extension round's values flattened to base coefficients), at
//! the positions the carrier's own verifier drew (`committed_air::drawn_queries_of_blinded_chained_carrier`).
//!
//! WHAT IS STATED. One statement per query group: "these openings, whose value fold at `fold_point` is `open_fold`,
//! authenticate against `root`". The root is round `g`'s own (the carrier's commitment for round 0, round `g − 1`'s for
//! round `g`, the last round's for the final queries) — the order `WhirVerifier::verify` checks them in.
//!
//! ⛔ THE FOLD POINT. `opening_auth_air` is sound for the VALUES only at a point the prover cannot pick after laying them
//! (its own header: a Horner fold at a known point is linear). Step 1 states the openings beside a verifier that still
//! holds the values natively and refolds them itself, so the point here is public data fixed by the carrier before any
//! table exists ([`group_fold_point`]). C4 step 2 draws it from the block aggregate's own transcript, after the table's
//! commitment, which is what lets a peer drop the values.
//!
//! SCALE (SAFE AT SCALE): per carrier a constant of the WHIR configuration (queries × depth); nothing grows with the bonded
//! set or height. AI RESISTANT: (a) a proof — the opening-auth AIR, verified by the light decider; a lying prover's table
//! names a root the path does not reach, or a fold its values do not make, and is refused.

use crate::committed_air::ChainedAirBundle;
use crate::hiding_decider::{Ea4, Fa4, Mmcs16};
use crate::merkle_path_air::PathStep;
use crate::opening_auth_air::Opening;
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_whir::pcs::proof::{QueryOpening, WhirProof};

/// One Merkle digest.
pub type Digest8 = [Fa4; 8];

/// One query group's openings and the root every one of them must reach.
#[derive(Clone)]
pub struct GroupOpenings {
    pub root: Digest8,
    pub openings: Vec<Opening>,
}

impl GroupOpenings {
    /// Rows of real work this group lays (its sponge blocks plus its path levels).
    #[must_use]
    pub fn rows(&self) -> usize {
        self.openings.iter().map(Opening::rows).sum()
    }
}

fn single_root(c: &<Mmcs16 as Mmcs<Fa4>>::Commitment) -> Option<Digest8> {
    match c.roots() {
        [r] => Some(*r),
        _ => None, // a cap of more than one digest is not a shape this step states
    }
}

/// Every query group of a WHIR opening, as `opening_auth_air` openings against the root each group opens. `drawn` is the
/// verifier's own position list (one entry per group, each group's queries in proof order). `None` (fail-closed) when the
/// group count, a group's length, a root or a path's length does not match.
#[must_use]
pub fn group_openings(
    open: &WhirProof<Fa4, Ea4, Mmcs16>,
    commitment: &<Mmcs16 as Mmcs<Fa4>>::Commitment,
    drawn: &[Vec<usize>],
) -> Option<Vec<GroupOpenings>> {
    let n = open.rounds.len();
    if drawn.len() != n + 1 {
        return None;
    }
    let root_of = |g: usize| -> Option<Digest8> {
        if g == 0 {
            single_root(commitment)
        } else {
            single_root(open.rounds.get(g - 1)?.commitment.as_ref()?)
        }
    };
    let mut out = Vec::with_capacity(n + 1);
    for g in 0..=n {
        let queries = if g < n { &open.rounds[g].queries } else { &open.final_queries };
        let idx = &drawn[g];
        if queries.len() != idx.len() {
            return None;
        }
        let root = root_of(g)?;
        let mut openings = Vec::with_capacity(queries.len());
        for (q, &index) in queries.iter().zip(idx) {
            let (mut values, proof) = match q {
                QueryOpening::Base { values, proof } => (values.clone(), proof),
                QueryOpening::Extension { values, proof } => (<Ea4 as BasedVectorSpace<Fa4>>::flatten_to_base(values.clone()), proof),
            };
            let (salts, siblings) = proof;
            // the hiding MMCS hashes the opened row then its salt (one matrix per WHIR round)
            let [salt] = salts.as_slice() else { return None };
            values.extend_from_slice(salt);
            let path: Vec<PathStep> =
                siblings.iter().enumerate().map(|(l, s)| PathStep { sibling: *s, bit: (index >> l) & 1 == 1 }).collect();
            openings.push(Opening { values, path });
        }
        out.push(GroupOpenings { root, openings });
    }
    Some(out)
}

/// Step 1's fold point for group `g`: public, fixed by the carrier's own commitment before any table is laid. Step 2
/// replaces it with a point the aggregate's transcript draws after the table's commitment (module header).
#[must_use]
pub fn group_fold_point(commitment_root: &Digest8, g: usize) -> Fa4 {
    let mut acc = Fa4::from_u64(0x4334_4f50 + g as u64); // "C4OP" ‖ group
    for v in commitment_root {
        acc = acc * Fa4::from_u64(0x1_0001) + *v;
    }
    acc
}

/// A blinded chained carrier's openings, read off a carrier THIS node's verifier accepted (the positions come from that
/// verification). `None` unless the carrier verifies and every group extracts.
#[must_use]
pub fn chained_carrier_openings<C, Mk>(
    bytes: &[u8],
    make_constraint: Mk,
    public_bind: &[Fa4],
    laid_shape: (usize, usize),
) -> Option<(Digest8, Vec<GroupOpenings>)>
where
    C: crate::air_zerocheck::AirConstraint + Sync,
    Mk: Fn(Ea4) -> C,
{
    let drawn = crate::committed_air::drawn_queries_of_blinded_chained_carrier(bytes, make_constraint, public_bind, laid_shape)?;
    let b: ChainedAirBundle = postcard::from_bytes(bytes).ok()?;
    let groups = group_openings(&b.open, &b.commitment, &drawn)?;
    Some((single_root(&b.commitment)?, groups))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_path_air::fold_path;
    use crate::opening_auth_air::{build_trace_multi, leaf_hash, make_constraint, open_fold_at, ROW_COLS, SEED};
    use crate::whir_rec_block::{prove_air_direct_light_decider_selfcontained_bytes, verify_air_direct_light_decider_selfcontained_bytes};

    const BIND: [Fa4; 1] = [Fa4::new(0x4334_3031)]; // "C401"

    fn member() -> (Vec<u8>, crate::member_path_gate::MemberTuple) {
        use crate::member_path_gate::{prove_member_path_carrier, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(100 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| (0x5A3C_96E1u64 >> (i % 32)) & 1 == 1).collect();
        prove_member_path_carrier(d(1), &siblings, &dirs, d(2), d(3), d(4)).expect("the member path proves")
    }

    fn member_openings(bytes: &[u8], t: &crate::member_path_gate::MemberTuple) -> Option<(Digest8, Vec<GroupOpenings>)> {
        use crate::member_path_gate::{member_path_gate, MEMBER_PATH_COLS, MEMBER_PATH_DEPTH};
        chained_carrier_openings(bytes, member_path_gate(t), &t.bind(), (MEMBER_PATH_DEPTH.trailing_zeros() as usize, MEMBER_PATH_COLS))
    }

    /// Prove one group's opening-auth table; `(proof, nvars)`.
    fn prove_group(g: &GroupOpenings, point: Fa4) -> Option<(Vec<u8>, usize, Fa4)> {
        let rows = g.rows().next_power_of_two().max(32);
        let fold = open_fold_at(point, &g.openings.iter().flat_map(|o| o.values.clone()).collect::<Vec<_>>());
        let (trace, root) = build_trace_multi(SEED, point, &g.openings, rows)?;
        if root != g.root {
            return None; // the table reaches another root: the openings are not this group's
        }
        let proof = prove_air_direct_light_decider_selfcontained_bytes(trace, make_constraint(SEED, root, point, fold), &BIND)?;
        Some((proof, rows.trailing_zeros() as usize, fold))
    }

    fn verify_group(proof: &[u8], root: Digest8, point: Fa4, fold: Fa4, nvars: usize) -> bool {
        verify_air_direct_light_decider_selfcontained_bytes(proof, make_constraint(SEED, root, point, fold), &BIND, (nvars, ROW_COLS))
    }

    /// ⭐ C4 STEP 1 PIN: a REAL member carrier's every query opening, read at the positions its own verifier drew, refolds
    /// natively to the root its group opens (the encoding is the MMCS's own), and proves and verifies as opening-auth
    /// tables; a flipped sibling, a flipped leaf value and a foreign root are each refused. Prints rows, ms and bytes.
    #[test]
    fn c4_a_real_carriers_openings_authenticate_in_circuit_and_every_tamper_is_refused() {
        let (bytes, t) = member();
        assert!(crate::member_path_gate::verify_member_path_carrier(&bytes, &t), "CONTROL: the carrier verifies natively");
        let (croot, groups) = member_openings(&bytes, &t).expect("⛔ the carrier's openings did not extract at its drawn positions");
        assert!(groups.len() >= 2, "CALIBRATION: a WHIR opening has a round group and a final group");
        // native calibration: every path reaches its group's root from the MMCS's own leaf hash
        for (gi, g) in groups.iter().enumerate() {
            for (qi, o) in g.openings.iter().enumerate() {
                let reached = fold_path(SEED, leaf_hash(SEED, &o.values), &o.path);
                assert_eq!(reached, g.root, "⛔ group {gi} query {qi}: the extracted opening does not reach its round's root");
            }
        }
        let (mut rows, mut bytes_out, t0) = (0usize, 0usize, std::time::Instant::now());
        let mut proofs = Vec::new();
        for (gi, g) in groups.iter().enumerate() {
            let point = group_fold_point(&croot, gi);
            let (p, nvars, fold) = prove_group(g, point).expect("⛔ a real group's openings did not prove");
            assert!(verify_group(&p, g.root, point, fold, nvars), "⛔ group {gi}: an honest opening-auth proof was refused");
            rows += g.rows();
            bytes_out += p.len();
            proofs.push((p, nvars, fold, point));
        }
        let ms = t0.elapsed().as_millis();
        eprintln!(
            "[c4-1] member carrier {} B: {} groups, {} openings, {rows} rows of work, {ms} ms to prove+verify, {bytes_out} B of auth proofs ({} thread(s))",
            bytes.len(),
            groups.len(),
            groups.iter().map(|g| g.openings.len()).sum::<usize>(),
            rayon::current_num_threads()
        );
        // TAMPER 1 — a flipped sibling: the table reaches another root, so no proof for the true root exists
        let mut g = groups[0].clone();
        g.openings[0].path[0].sibling[0] += Fa4::ONE;
        assert!(prove_group(&g, group_fold_point(&croot, 0)).is_none(), "⛔ a flipped sibling still reached the root");
        // TAMPER 2 — the honest builder refuses a flipped leaf value outright (its segment reaches another root) …
        let mut g = groups[0].clone();
        g.openings[0].values[0] += Fa4::ONE;
        let point = group_fold_point(&croot, 0);
        let rows0 = g.rows().next_power_of_two().max(32);
        assert!(build_trace_multi(SEED, point, &g.openings, rows0).is_none(), "⛔ the builder laid a segment that reaches another root");
        // … so the LYING PROVER lays the honest table and moves one absorbed value cell after it: refused
        let g = &groups[0];
        let rows0 = g.rows().next_power_of_two().max(32);
        let (mut trace, root) = build_trace_multi(SEED, point, &g.openings, rows0).expect("the honest table lays");
        trace[crate::opening_auth_air::ABS_OFF][0] += Fa4::ONE;
        let honest_fold = proofs[0].2;
        // a prover that asserts its own constraint refuses by panicking: that is a refusal too, never a proof
        let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prove_air_direct_light_decider_selfcontained_bytes(trace, make_constraint(SEED, root, point, honest_fold), &BIND)
        }))
        .ok()
        .flatten();
        assert!(
            forged.map_or(true, |p| !verify_group(&p, groups[0].root, point, honest_fold, proofs[0].1)),
            "⛔ a flipped leaf value authenticated against the true root"
        );
        // TAMPER 3 — an honest proof against a foreign root: refused
        let mut foreign = groups[0].root;
        foreign[0] += Fa4::ONE;
        assert!(!verify_group(&proofs[0].0, foreign, proofs[0].3, proofs[0].2, proofs[0].1), "⛔ an opening proof verified against a foreign root");
        // CALIBRATION — the drawn positions are the verifier's: a carrier that does not verify yields none
        let mut bad = bytes.clone();
        let mid = bad.len() / 2;
        bad[mid] ^= 1;
        assert!(member_openings(&bad, &t).is_none(), "⛔ positions were read off a carrier the verifier refused");
    }
}
