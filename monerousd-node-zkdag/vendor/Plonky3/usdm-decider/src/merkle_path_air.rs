// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐⭐⭐ THE MERKLE PATH AS CONSTRAINTS — the core an in-circuit PCS opening needs (§BD-2 part (c)).
//!
//! ⛔⛔⛔ WHY. §BD-2's part (b) (`crate::recursion_bound`) made the outer step evaluate the INNER AIR on
//! the opened row, so a row of zeros can no longer close the chain. It left one freedom, probed and
//! recorded: nothing ties `opened` to a COMMITTED inner trace, so a prover who can produce ANY single
//! row satisfying the inner AIR still passes. Closing that means verifying the inner PCS opening inside
//! the circuit, and for a hash-based PCS that is Merkle-path verification.
//!
//! ⭐ IT IS AFFORDABLE, MEASURED RATHER THAN ASSUMED. A real committed carrier's opening carries
//! **2,471 Merkle siblings** at the decider's configuration — and the count is IDENTICAL for a
//! 201×2048 trace and the 12,885×32 production shape, because it is a function of the WHIR config
//! (rounds × queries × depth), never of the trace. One sibling is one compression is one Poseidon2-16
//! permutation, and `crate::sponge_chain_air` already constrains 6,464 of them in ~2.6 s. So the
//! opening fits; it was never the blocker people assumed.
//!
//! ## The relation, exactly
//! `CompressHash` is `TruncatedPermutation<Perm16, 2, 8, 16>`: a compression takes TWO 8-element
//! digests, permutes the 16-wide state, and truncates to the first 8. A path fold is therefore
//!
//! ```text
//! node_{k+1} = compress( node_k , sib_k )   ordered by the index bit b_k
//! ```
//!
//! and this AIR carries one compression per row: the permutation itself (delegated to the SAME
//! `Poseidon2Air` the sponge uses — ONE definition, never a second hand-written copy), the sibling and
//! the index bit as committed cells, and the chaining that makes the rows one path.
//!
//! ⛔ THE ORDER IS THE WHOLE POINT. A fold that ignores `b_k` accepts a path with the siblings on the
//! wrong side, which is a DIFFERENT leaf reaching the same root — so the bit is constrained boolean and
//! the placement is a selector on it, never an unchecked convention.
//!
//! ⛔ ROW-SHIFTED BY CONSTRUCTION, so this AIR must NOT be used with the §BE-1 blinding wrapper
//! (`committed_air::prove_air_blinded_bytes`) — that wrapper's doc names the same restriction from the
//! other side. A path's privacy comes from the opening being of a hiding commitment, not from padding.

use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};
use crate::sponge_chain_air::{constants_for_seed, perm_for_seed, OUTPUT_OFF, P2_COLS, RATE, WIDTH};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols};
use p3_symmetric::Permutation;

const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;
type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;
type P2Air = Poseidon2Air<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    WIDTH,
    SBOX_DEGREE,
    SBOX_REGISTERS,
    HALF_FULL_ROUNDS,
    PARTIAL_ROUNDS,
>;

/// ⛔ WHICH PERMUTATION. A path AIR is only meaningful against the MMCS that actually built the tree it
/// claims to authenticate, and this crate pins DIFFERENT permutation seeds per proof family. Part (c)
/// verifies the COMMITTED carrier's opening, so this is the committed carrier's seed — not the direct
/// path's `REC_DECIDER_SEED`. `the_air_compresses_exactly_what_the_carriers_mmcs_compresses` is the
/// calibration gate that holds the two together; without it this module would prove a hash nothing uses.
pub const CARRIER_SEED: u64 = crate::committed_air::COMMITTED_AIR_SEED;

/// A digest is `RATE` field elements — the same 8 the MMCS compresses.
pub const DIGEST: usize = RATE;
/// The permutation's input block starts at column 0 (mirroring `sponge_chain_air`).
const INPUT_OFF: usize = 0;
/// The running node — the value that climbs the path. Committed so the chaining is row-local.
pub const NODE_OFF: usize = P2_COLS;
/// The sibling at this level.
pub const SIB_OFF: usize = NODE_OFF + DIGEST;
/// The index bit at this level: 0 = the node is the LEFT input, 1 = it is the RIGHT input.
pub const BIT_OFF: usize = SIB_OFF + DIGEST;
/// Total committed columns per row.
pub const ROW_COLS: usize = BIT_OFF + 1;

/// One level of a Merkle authentication path, as the prover lays it.
#[derive(Clone, Copy, Debug)]
pub struct PathStep {
    pub sibling: [KoalaBear; DIGEST],
    /// `false` = this node is the LEFT input to the compression, `true` = the RIGHT.
    pub bit: bool,
}

/// Fold a leaf up a path natively — the value the circuit must agree with. Public so a caller derives
/// the expected root the same way on both sides, rather than two copies drifting apart.
#[must_use]
pub fn fold_path(seed: u64, leaf: [KoalaBear; DIGEST], path: &[PathStep]) -> [KoalaBear; DIGEST] {
    let perm = perm_for_seed(seed);
    let mut node = leaf;
    for st in path {
        let mut state = [KoalaBear::ZERO; WIDTH];
        let (l, r) = if st.bit { (st.sibling, node) } else { (node, st.sibling) };
        state[..DIGEST].copy_from_slice(&l);
        state[DIGEST..].copy_from_slice(&r);
        let out = perm.permute(state);
        node.copy_from_slice(&out[..DIGEST]);
    }
    node
}

/// ⭐ THE PADDING, AS A FUNCTION BOTH SIDES CALL. `build_trace` folds `rows` levels whatever the path's
/// real length, continuing past its end with a zero sibling. That continuation is part of the statement,
/// so the native reference has to perform it identically or the two would drift — this is the ONE place
/// the convention is written down, and `the_native_fold_and_the_laid_trace_agree` is what holds it.
#[must_use]
pub fn padded_path(path: &[PathStep], rows: usize) -> Vec<PathStep> {
    (0..rows)
        .map(|i| {
            path.get(i).copied().unwrap_or(PathStep { sibling: [KoalaBear::ZERO; DIGEST], bit: false })
        })
        .collect()
}

/// Lay the trace for one path. `rows` must be a power of two and at least `path.len()`; the tail
/// repeats the final node with a zero sibling so every row is a well-formed compression and the last
/// row's output is the root the caller expects.
///
/// ⛔ PADDING CONTINUES THE FOLD, IT DOES NOT REPEAT A ROW. A repeated row would have
/// `next.node != this.output`, which is exactly the chaining residual this AIR enforces — the same trap
/// `sponge_chain_air`'s own padding comment records paying for.
#[must_use]
pub fn build_trace(
    seed: u64,
    leaf: [KoalaBear; DIGEST],
    path: &[PathStep],
    rows: usize,
) -> Option<(Vec<Vec<Fa4>>, [KoalaBear; DIGEST])> {
    if !rows.is_power_of_two() || path.len() > rows {
        return None; // fail-closed: the shape is public and must be stateable
    }
    let consts = constants_for_seed(seed);
    let perm = perm_for_seed(seed);
    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; rows]; ROW_COLS];
    let mut node = leaf;
    for slot in 0..rows {
        // Beyond the real path the fold CONTINUES with a zero sibling, so the chain never breaks.
        let st = path.get(slot).copied().unwrap_or(PathStep {
            sibling: [KoalaBear::ZERO; DIGEST],
            bit: false,
        });
        let (l, r) = if st.bit { (st.sibling, node) } else { (node, st.sibling) };
        let mut state = [KoalaBear::ZERO; WIDTH];
        state[..DIGEST].copy_from_slice(&l);
        state[DIGEST..].copy_from_slice(&r);

        let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(state, &consts);
        for (col, v) in filled.iter().enumerate() {
            cols[col][slot] = *v;
        }
        for j in 0..DIGEST {
            cols[NODE_OFF + j][slot] = node[j];
            cols[SIB_OFF + j][slot] = st.sibling[j];
        }
        cols[BIT_OFF][slot] = if st.bit { KoalaBear::ONE } else { KoalaBear::ZERO };

        let out = perm.permute(state);
        node.copy_from_slice(&out[..DIGEST]);
    }
    Some((cols, node))
}

/// The path relation as an AIR. `leaf` and `root` are PUBLIC — a verifier supplies them, so the circuit
/// proves "this leaf reaches this root", which is the only statement an opening needs.
pub struct MerklePathConstraint {
    pub gamma: Ea4,
    /// ⛔ THE SAME WRAPPER `sponge_chain_air` USES — the bare `Poseidon2Air` is a `p3_air::Air`, whose
    /// constraints live in the AIR's OWN column frame; `WholeChainMainConstraint` is what compiles those
    /// symbolic constraints into this crate's `AirConstraint` and re-maps the variable indices into the
    /// WIDER committed row. Delegating to it is what keeps ONE definition of the permutation.
    pub p2: crate::whole_chain::WholeChainMainConstraint,
    pub leaf: [Fa4; DIGEST],
    pub root: [Fa4; DIGEST],
}

impl AirConstraint for MerklePathConstraint {
    fn degree(&self, nvars: usize) -> usize {
        // The permutation's own degree dominates: every residual added below is at most degree 2 in the
        // committed cells, and the first/last selectors are functions of the POINT, which the zerocheck
        // already carries for every AIR (`sponge_chain_air` has the identical shape and the same bound).
        self.p2.degree(nvars)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        // The permutation itself — delegated, never re-derived.
        let mut acc = self.p2.eval(local, at, x);
        let g = self.gamma;
        let push = |acc: &mut Ea4, r: Ea4| {
            *acc = *acc * g + r;
        };
        // The SAME first/last idiom `sponge_chain_air` uses: both are functions of the zerocheck's own
        // point, so there is nothing here for a prover to choose.
        let mut is_first = Ea4::ONE;
        let mut is_last = Ea4::ONE;
        for &xk in x.iter() {
            is_first *= Ea4::ONE - xk;
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;

        // 1. THE INDEX BIT IS A BIT. Without this a prover reads a "bit" of 1/2 and blends both orders.
        let b = local[BIT_OFF];
        push(&mut acc, b * (Ea4::ONE - b));

        // 2. THE PLACEMENT — which side of the compression the node sits on, selected by the bit.
        for j in 0..DIGEST {
            let node = local[NODE_OFF + j];
            let sib = local[SIB_OFF + j];
            let left = local[INPUT_OFF + j];
            let right = local[INPUT_OFF + DIGEST + j];
            push(&mut acc, left - ((Ea4::ONE - b) * node + b * sib));
            push(&mut acc, right - ((Ea4::ONE - b) * sib + b * node));
        }

        // 3. THE CHAIN — the next row climbs from this row's output. This is what makes the rows ONE
        //    path rather than a bag of unrelated compressions.
        for j in 0..DIGEST {
            let next_node = at(NODE_OFF + j, &[]);
            push(&mut acc, is_trans * (next_node - local[OUTPUT_OFF + j]));
        }

        // 4. THE ENDPOINTS — the statement. The first row starts at the PUBLIC leaf; the last row's
        //    output is the PUBLIC root.
        for j in 0..DIGEST {
            push(&mut acc, is_first * (local[NODE_OFF + j] - Ea4::from(self.leaf[j])));
            push(&mut acc, is_last * (local[OUTPUT_OFF + j] - Ea4::from(self.root[j])));
        }
        acc
    }
}

/// Build the constraint for a given public statement. Both sides call this, so the circuit a prover
/// satisfies is the circuit a verifier rebuilds.
#[must_use]
pub fn make_constraint(
    seed: u64,
    leaf: [KoalaBear; DIGEST],
    root: [KoalaBear; DIGEST],
) -> impl Fn(Ea4) -> MerklePathConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;

    let air = P2Air::new(constants_for_seed(seed));
    // The permutation AIR's own width is `P2_COLS` (`Poseidon2Cols::borrow` asserts it), so its symbolic
    // constraints are generated in THAT frame; `SymLeafLayout { w: ROW_COLS }` below re-maps the same
    // variable indices into the wider committed row. Every Poseidon2 index is < P2_COLS so it lands on
    // the same column, while the next-row half is offset by the REAL row width. Identical to the sponge.
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: P2_COLS,
        num_public_values: 0,
        num_periodic_columns: 0,
        ..Default::default()
    };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |gamma: Ea4| MerklePathConstraint {
        gamma,
        p2: crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: ROW_COLS, preproc_w: 0, npub: 0 },
            ROW_COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        ),
        leaf,
        root,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };
    use p3_field::PrimeCharacteristicRing;

    const BIND: [Fa4; 1] = [KoalaBear::new(0x4d_4b_50_54)]; // "MKPT"
    /// The WHIR `nvars >= 5` floor this crate pins the same way everywhere — a proof-system shape.
    const ROWS: usize = 32;
    /// A real authentication depth that does NOT fill the trace, so the padding convention is exercised
    /// rather than assumed away by a path that happens to be exactly `ROWS` long.
    const DEPTH: usize = 20;

    fn kb(v: u64) -> KoalaBear {
        KoalaBear::from_u64(v)
    }
    fn digest(s: u64) -> [KoalaBear; DIGEST] {
        core::array::from_fn(|i| kb(s + i as u64))
    }
    /// A path whose index bits are a MIXED pattern — all-zero bits would make the left/right selector
    /// untestable, which is precisely the freedom this AIR exists to remove.
    fn path() -> Vec<PathStep> {
        (0..DEPTH)
            .map(|k| PathStep { sibling: digest(1000 + 10 * k as u64), bit: k % 3 == 1 || k % 5 == 2 })
            .collect()
    }
    fn leaf() -> [KoalaBear; DIGEST] {
        digest(7)
    }

    /// ⭐⭐⭐ THE CALIBRATION THAT MAKES EVERY OTHER GATE HERE MEAN SOMETHING. This AIR is only useful if
    /// the compression it constrains is the compression the CARRIER'S MMCS actually used to build the
    /// tree. Nothing about a green path proof says that — a circuit over the wrong permutation proves a
    /// hash nothing in this tree computes, and would sail through all the adversarial gates below.
    ///
    /// ⛔ THE SAME TRAP `sponge_chain_air`'s own header records paying for: an earlier gate there compared
    /// against the PUBLISHED KoalaBear constants and passed while binding a permutation no proof uses.
    #[test]
    fn the_air_compresses_exactly_what_the_carriers_mmcs_compresses() {
        use p3_symmetric::PseudoCompressionFunction;
        // Built the way `committed_air::mmcs()` builds it, off the SAME seed — this is the object whose
        // openings part (c) has to verify.
        let compress = crate::hiding_decider::CompressHash::new(perm_for_seed(CARRIER_SEED).clone());
        let node = digest(31);
        let sib = digest(91);
        for bit in [false, true] {
            let mine = fold_path(CARRIER_SEED, node, &[PathStep { sibling: sib, bit }]);
            let (l, r) = if bit { (sib, node) } else { (node, sib) };
            let theirs: [KoalaBear; DIGEST] = compress.compress([l, r]);
            assert_eq!(
                mine, theirs,
                "⛔ THE CIRCUIT'S COMPRESSION IS NOT THE MMCS'S COMPRESSION at bit={bit}. Every path \
                 proof this module produces would be about a hash the carrier never computed."
            );
        }
        // And the two ORDERS must actually differ, or "ordered by the index bit" is vacuous here.
        assert_ne!(
            compress.compress([node, sib]),
            compress.compress([sib, node]),
            "the compression must not be symmetric, or the index bit carries no information"
        );
        eprintln!("[merkle-path] circuit compression == carrier MMCS compression, both orders");
    }

    /// The laid trace's endpoint and the native reference must be the SAME value — including the padding
    /// continuation. Two spellings of one fold is how §AO started.
    #[test]
    fn the_native_fold_and_the_laid_trace_agree() {
        let p = path();
        let (_, root) = build_trace(CARRIER_SEED, leaf(), &p, ROWS).expect("shape is stateable");
        assert_eq!(
            root,
            fold_path(CARRIER_SEED, leaf(), &padded_path(&p, ROWS)),
            "⛔ the trace's root and the native padded fold disagree — two spellings of one fold"
        );
        assert_ne!(
            root,
            fold_path(CARRIER_SEED, leaf(), &p),
            "the padding must actually continue the fold, or `padded_path` is untested here"
        );
        eprintln!("[merkle-path] native fold == laid trace endpoint, padding included");
    }

    fn honest() -> (Vec<Vec<Fa4>>, [KoalaBear; DIGEST], [KoalaBear; DIGEST]) {
        let l = leaf();
        let (t, root) = build_trace(CARRIER_SEED, l, &path(), ROWS).expect("shape is stateable");
        (t, l, root)
    }

    /// CONTROL. An honest path proves, and a verifier that shares NO object with the prover — it rebuilt
    /// the circuit from the public statement alone — accepts. If this ever fails the two sides are not
    /// deriving the same circuit and nothing below is interpretable.
    #[test]
    fn an_honest_path_proves_and_an_independently_built_verifier_accepts() {
        let (trace, l, root) = honest();
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(CARRIER_SEED, l, root),
            &BIND,
        )
        .expect("an honest Merkle path proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_constraint(CARRIER_SEED, l, root),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)
            ),
            "an independently-derived verifier must accept an honest path"
        );
        eprintln!(
            "[merkle-path] {DEPTH}-level path in {ROWS} rows x {ROW_COLS} cols; verifier accepted {} byte(s)",
            proof.len()
        );
    }

    /// ⭐⭐⭐ A FRESHLY PROVED FORGERY, NOT A TAMPER. §BG's lesson: a tampered witness failing proves the
    /// prover is consistent, not that the statement binds. Here the forger is HONEST — it lays a perfect
    /// trace for a DIFFERENT leaf and proves it — and the verifier, holding the true (leaf, root), must
    /// still refuse. That is the property an opening needs: the path speaks about ONE leaf.
    #[test]
    fn a_verifier_holding_the_true_statement_refuses_a_perfect_proof_of_a_different_leaf() {
        let (_, l, root) = honest();
        let other = digest(70_007);
        assert_ne!(other, l, "the counterfactual leaf must differ");
        let (ft, froot) =
            build_trace(CARRIER_SEED, other, &path(), ROWS).expect("shape is stateable");
        assert_ne!(froot, root, "a different leaf must reach a different root, or this proves nothing");
        // CALIBRATION: the forger's own statement is TRUE and its proof is real.
        let fproof = prove_air_direct_light_decider_selfcontained_bytes(
            ft,
            make_constraint(CARRIER_SEED, other, froot),
            &BIND,
        )
        .expect("the forger's own (leaf, root) is honest and proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(CARRIER_SEED, other, froot),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "the forgery must be a REAL proof of its own statement, or the refusal below is trivial"
        );
        // THE GATE: the same real proof, checked against the statement the verifier actually holds.
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(CARRIER_SEED, l, root),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "⛔ THE PATH DOES NOT BIND ITS LEAF: a verifier holding the true (leaf, root) accepted a \
             proof about a different leaf entirely."
        );
        eprintln!("[merkle-path] a real proof of a different leaf was refused against the true statement");
    }

    /// ⭐⭐⭐ THE ORDER GATE. A fold that ignores `b_k` accepts the SAME siblings on the wrong side — a
    /// different leaf position reaching a claimed root. The forger flips every index bit, lays a fully
    /// honest trace for that, and proves it. The verifier holding the true root must refuse.
    #[test]
    fn flipping_the_index_bits_is_a_different_statement_and_is_refused() {
        let (_, l, root) = honest();
        let flipped: Vec<PathStep> =
            path().iter().map(|st| PathStep { sibling: st.sibling, bit: !st.bit }).collect();
        let (ft, froot) = build_trace(CARRIER_SEED, l, &flipped, ROWS).expect("shape is stateable");
        assert_ne!(
            froot, root,
            "flipping the index bits must move the root, or the placement selector is decorative"
        );
        let fproof = prove_air_direct_light_decider_selfcontained_bytes(
            ft,
            make_constraint(CARRIER_SEED, l, froot),
            &BIND,
        )
        .expect("the flipped path is internally honest and proves its own root");
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &fproof,
                make_constraint(CARRIER_SEED, l, root),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&fproof)
            ),
            "⛔ INDEX ORDER IS NOT BOUND: the same leaf and the same siblings on the OTHER side were \
             accepted against the true root."
        );
        eprintln!("[merkle-path] a bit-flipped path (same leaf, same siblings) was refused");
    }

    /// A verifier that is handed the true leaf but the WRONG root refuses — the root is a statement the
    /// prover cannot move, which is what makes the AIR usable as an opening check.
    #[test]
    fn a_verifier_expecting_a_different_root_refuses_an_honest_path() {
        let (trace, l, root) = honest();
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(CARRIER_SEED, l, root),
            &BIND,
        )
        .expect("an honest Merkle path proves");
        let mut wrong = root;
        wrong[3] += KoalaBear::ONE;
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(
                &proof,
                make_constraint(CARRIER_SEED, l, wrong),
                &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)
            ),
            "⛔ THE ROOT IS NOT BOUND: a verifier expecting a different root accepted the path"
        );
        eprintln!("[merkle-path] a verifier expecting a different root refused");
    }

    /// ⭐⭐ THE VACUITY SHAPE THAT BROKE §BD-2/§BD-3. There, a trace of ZEROS satisfied a HOMOGENEOUS
    /// recursion AIR, so a forger proved 2^100 work with no inner proof at all. This AIR is
    /// NON-homogeneous by construction — the public leaf and root sit inside its own residuals as
    /// constants — so the zero trace is a non-zero constraint. Probe it rather than assert it.
    #[test]
    fn the_all_zero_trace_is_refused() {
        let (_, l, root) = honest();
        let zeros: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; ROWS]; ROW_COLS];
        // A prover CAN try; either it cannot produce bytes, or the verifier refuses them. Both are the
        // door being shut — what would be fatal is bytes that verify.
        let attempt = prove_air_direct_light_decider_selfcontained_bytes(
            zeros,
            make_constraint(CARRIER_SEED, l, root),
            &BIND,
        );
        let accepted = attempt.is_some_and(|b| {
            verify_air_direct_light_decider_selfcontained_bytes(
                &b,
                make_constraint(CARRIER_SEED, l, root),
                &BIND,
                crate::whir_rec_block::declared_direct_shape_for_tests(&b),
            )
        });
        assert!(
            !accepted,
            "⛔ THE ZERO TRACE VERIFIES — this AIR is homogeneous and says nothing, exactly the §BD-3 \
             break where a zero witness certified an unbounded claim."
        );
        eprintln!("[merkle-path] the all-zero trace was refused");
    }

    /// ⭐⭐ THE COST AT THE REAL OPENING SCALE, MEASURED ON THIS CIRCUIT — not extrapolated. §BJ counted
    /// **2,471 Merkle siblings** in one committed-carrier opening and argued from `sponge_chain_air`'s
    /// 6,464 permutations that a path AIR would fit. That was a proxy. This runs the actual AIR at a row
    /// count that covers the real sibling count and prints what it costs.
    ///
    /// `#[ignore]` because it is a measurement, not a gate: run it with `--ignored` when the number
    /// matters. A gate that takes minutes stops being run, and a gate nobody runs is not a gate.
    #[test]
    #[ignore = "measurement: run with --ignored"]
    fn the_cost_of_a_real_opening_scale_path_is_measured() {
        /// Covers §BJ's measured 2,471 siblings per committed-carrier opening with room to spare.
        const BIG: usize = 4096;
        let deep: Vec<PathStep> = (0..2471)
            .map(|k| PathStep { sibling: digest(10 * k as u64 + 3), bit: k % 2 == 0 })
            .collect();
        let l = leaf();
        let t0 = std::time::Instant::now();
        let (trace, root) = build_trace(CARRIER_SEED, l, &deep, BIG).expect("shape is stateable");
        let lay = t0.elapsed();
        let t1 = std::time::Instant::now();
        let proof = prove_air_direct_light_decider_selfcontained_bytes(
            trace,
            make_constraint(CARRIER_SEED, l, root),
            &BIND,
        )
        .expect("an opening-scale path proves");
        let prove = t1.elapsed();
        let t2 = std::time::Instant::now();
        let ok = verify_air_direct_light_decider_selfcontained_bytes(
            &proof,
            make_constraint(CARRIER_SEED, l, root),
            &BIND,
            crate::whir_rec_block::declared_direct_shape_for_tests(&proof),
        );
        let ver = t2.elapsed();
        assert!(ok, "the opening-scale path must verify");
        eprintln!(
            "[merkle-path §BJ] {} siblings in {BIG} rows x {ROW_COLS} cols — lay {:?}, prove {:?}, \
             verify {:?}, {} byte(s)",
            deep.len(),
            lay,
            prove,
            ver,
            proof.len()
        );
    }

    /// Every single-cell alteration a forger would want, each refused. These are the WEAKER evidence
    /// (see §BG) but they localise which residual is doing the work, so a future edit that deletes one
    /// is caught here rather than in production.
    #[test]
    fn every_single_cell_forgery_in_the_path_is_refused() {
        let cases: [(&str, usize, usize); 6] = [
            ("the running node mid-path", NODE_OFF + 2, 9),
            ("a sibling", SIB_OFF + 5, 11),
            ("the index bit", BIT_OFF, 4),
            ("a permutation input", INPUT_OFF + 1, 6),
            ("a permutation output", OUTPUT_OFF + 3, 6),
            ("the first row's node (the leaf)", NODE_OFF, 0),
        ];
        for (what, col, row) in cases {
            let (mut bad, l, root) = honest();
            bad[col][row] += KoalaBear::ONE;
            let accepted = prove_air_direct_light_decider_selfcontained_bytes(
                bad,
                make_constraint(CARRIER_SEED, l, root),
                &BIND,
            )
            .is_some_and(|b| {
                verify_air_direct_light_decider_selfcontained_bytes(
                    &b,
                    make_constraint(CARRIER_SEED, l, root),
                    &BIND,
                    crate::whir_rec_block::declared_direct_shape_for_tests(&b),
                )
            });
            assert!(!accepted, "⛔ a forgery of {what} (col {col}, row {row}) was ACCEPTED");
            eprintln!("[merkle-path] refused a forgery of {what}");
        }
    }
}
