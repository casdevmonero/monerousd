// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⛔⛔⛔ DB-213c — THE FORGERY CENSUS: what each production verifier accepts from a prover holding NO witness.
//!
//! DB-213b found a verifier that read its statement's SHAPE from the prover's carrier. Auditing every
//! production verify entry the node calls for that class turned up a wider one: verifiers whose outer AIR
//! never states the inner statement at all. The recursive folds (`merged_fixed_step`, the settlement
//! aggregate) constrain only the inner sumcheck round chain and the masked-opening chain over values laid
//! in WITNESS rows — the inner challenges, the inner constraint `C(opened)`, and the inner public bind are
//! not in any row the verifier can see. The height-1 sparse fold constrains only a boolean selector.
//!
//! Each arm here is the hostile object: built with NO inner witness, from public values alone, against a
//! statement the honest prover REFUSES. Arms M, A, B and F MEASURE that the named verifier ACCEPTS it — they
//! are CALIBRATION pins of a vacuous verifier, and each names the authority that now refutes the forgery in its
//! place (M2 for membership; the node's DB-217 Unspent gate for absence; the node's tag recompute for the block
//! carriers). Arm C (the compact block carriers) is gone with its verifiers, 2026-10-26: the node refuses a block
//! carrying any `NfBlockProof::carrier` (`node::pins::a_block_carrying_a_compact_nullifier_carrier_is_refused…`). If one of these verifiers is ever made sound its arm goes RED, and must then become a refutation.
//! Arms M2 and M3 are refutations: the sound one-step membership verify refuses the forgery and the re-shaped walk.

use crate::hiding_decider::{Ea4, Fa4};
use crate::poseidon2_compress::{lanes_of, Digest, DIGEST_LANES};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

/// A trace that satisfies `FixedDegreeMergedStepConstraint` with NO inner proof behind it: every inner round
/// eval is zero (so `h(0)+h(1) == 0 == claim`), every `r_k` is zero with the prefix/suffix products the
/// recurrences force, every claim and the final claim are zero, and the masked-opening half is all zero
/// (`c1 = target − 2c0 − Σc = 0`, `horner(0, γ) = 0`). Nothing in it depends on any witness — only on the
/// public `(out_bind, extra)` the verifier recomputes.
fn forged_merged_fixed_step(nvars0: usize, per0: usize, out_bind: &[Fa4], extra: &[Ea4]) -> Option<Vec<u8>> {
    let (split, width, height) = crate::whir_rec_block::merged_fixed_shape(nvars0, per0, 1);
    let rounds = crate::whir_rec_block::REC_DECIDER_FOLDING;
    let wire_size = crate::whir_rec_block::REC_DECIDER_ELL_ZK.max(3) - 1;
    let l_o = rounds * (wire_size + 1) + rounds + 1;
    let x = |j: usize| Ea4::from(Fa4::from_u64(j as u64));
    let r = Ea4::ZERO;
    let mut fv: Vec<Ea4> = Vec::new();
    fv.extend(vec![Ea4::ZERO; nvars0 * per0]); // evals
    fv.extend(vec![r; nvars0]); // r_k
    fv.extend(vec![Ea4::ZERO; nvars0]); // claim_k = lagrange(0, r) = 0
    for _ in 0..nvars0 {
        let mut pj = Ea4::ONE;
        for j in 0..per0 {
            fv.push(pj); // P_{k,j} = Π_{m<j}(r − m)
            pj *= r - x(j);
        }
    }
    for _ in 0..nvars0 {
        let mut sv = vec![Ea4::ONE; per0];
        for j in (0..per0 - 1).rev() {
            sv[j] = sv[j + 1] * (r - x(j + 1)); // S_{k,j} = Π_{m>j}(r − m)
        }
        fv.extend(sv);
    }
    fv.push(Ea4::ZERO); // cf
    let ov = vec![Ea4::ZERO; l_o];
    assert_eq!(fv.len() * 4, split, "the forged validity half must match the verifier's split");
    assert_eq!((fv.len() + ov.len()) * 4, width, "the forged row must match the verifier's width");
    let mut cols = vec![vec![Fa4::ZERO; height]; width];
    for i in 0..height {
        let mut c = 0usize;
        for v in fv.iter().chain(ov.iter()) {
            for &limb in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(v) {
                cols[c][i] = limb;
                c += 1;
            }
        }
    }
    let make = crate::whir_rec_block::merged_fixed_step_make(nvars0, per0, split, extra.to_vec());
    crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(cols, make, out_bind)
}

fn tag_bytes(seed: u64) -> [u8; 32] {
    *blake3::hash(&seed.to_le_bytes()).as_bytes()
}

// ⛔ M — NOTE MEMBERSHIP (RETIRED 2026-09-27). This arm measured that `verify_note_membership_chain`, the recursive
// membership fold, accepted a witness-free proof for a leaf in no block (the census's founding finding). The fold
// and its verifier are now DELETED at source (`NoteMembershipCarrier::step` tracks the accumulator natively; the
// one membership authority is `verify_note_membership_one_step`, arm M2 below). A census arm over a verifier that
// no longer exists would measure nothing, so the arm goes with it.

/// ⛔ A — NULLIFIER ABSENCE (single). The node's spend gate admits on `verify_nf_absence_*` when the spender
/// carries a proof; a proof here for a nullifier SPENT in the tip block is a double spend.
#[test]
fn census_a_the_absence_fold_certifies_a_nullifier_spent_in_the_tip_block() {
    use crate::nf_sparse_air::*;
    let spent = tag_bytes(0xDB21_3A01);
    let tags = vec![tag_bytes(0xDB21_3A00), spent, tag_bytes(0xDB21_3A02)];
    let nf = nf_to_limbs(&spent);
    let genesis = lanes_of(&[0xDB21_3A10]);
    let bp = lanes_of(&[0xDB21_3A11]);
    // CALIBRATION — the honest carrier cannot fold the block that spent this nullifier.
    let mut honest = NfAbsenceCarrier::new(nf, genesis);
    assert!(!honest.step(&tags, bp), "calibration: the honest carrier must refuse a block that spent nf");
    let td = sparse_fold_digest_nfs(&tags, bp);
    let tip_acc = nf_unspent_step_new_acc(genesis, bp, td);
    let out_bind = nf_absence_chain_bind(nf, genesis, genesis, bp, td, tip_acc);
    let extra = nf_absence_acc_residual(genesis, bp, td, tip_acc);
    let forged = forged_merged_fixed_step(5, 6, &out_bind, &extra).expect("the witness-free trace proves");
    let accepted = verify_nf_absence_chain(&forged, nf, genesis, genesis, bp, td, tip_acc);
    println!(
        "[DB-213c A] forged absence ({} B) for a nullifier IN the tip block's tags: verify_nf_absence_chain = {accepted}",
        forged.len()
    );
    // CALIBRATION of the vacuity. The spend authority is the node's DB-217 gate (a POSITIVE Unspent verdict from
    // the committed sparse root for every tag); this verifier must never admit on its own.
    assert!(
        accepted,
        "the absence fold REFUSED a witness-free proof — if it has been made sound, turn this arm into a refutation"
    );
}

/// ⛔ B — NULLIFIER ABSENCE (batch), the shape `Node`'s spend gate actually calls.
#[test]
fn census_b_the_batch_absence_fold_certifies_a_spent_member() {
    use crate::nf_sparse_air::*;
    let spent = tag_bytes(0xDB21_3B01);
    let tags = vec![tag_bytes(0xDB21_3B00), spent];
    let nfs = vec![nf_to_limbs(&spent), nf_to_limbs(&tag_bytes(0xDB21_3B77))];
    let genesis = lanes_of(&[0xDB21_3B10]);
    let bp = lanes_of(&[0xDB21_3B11]);
    let mut honest = NfAbsenceBatchCarrier::new(nfs.clone(), genesis);
    assert!(!honest.step(&tags, bp), "calibration: the honest batch carrier must refuse a spent member");
    let td = sparse_fold_digest_nfs(&tags, bp);
    let tip_acc = nf_unspent_step_new_acc(genesis, bp, td);
    let out_bind = nf_absence_batch_chain_bind(&nfs, genesis, genesis, bp, td, tip_acc);
    let extra = nf_absence_acc_residual(genesis, bp, td, tip_acc);
    let forged = forged_merged_fixed_step(5, 6, &out_bind, &extra).expect("the witness-free trace proves");
    let accepted = verify_nf_absence_batch_chain(&forged, &nfs, genesis, genesis, bp, td, tip_acc);
    println!(
        "[DB-213c B] forged batch absence ({} B), member spent in the tip block: verify_nf_absence_batch_chain = {accepted}",
        forged.len()
    );
    // CALIBRATION of the vacuity — see arm A: the node's DB-217 gate is the authority, not this proof.
    assert!(
        accepted,
        "the batch absence fold REFUSED a witness-free proof — if it has been made sound, turn this arm into a refutation"
    );
}

/// ⛔ F — THE HEIGHT-1 SPARSE FOLD. Its gate is `sel·(sel−1)`; `(pre, post, digest)` ride only the transcript.
#[test]
fn census_f_the_height1_fold_certifies_any_endpoints() {
    use crate::nf_sparse_air::*;
    let pre = lanes_of(&[0xDB21_3F10]);
    let lie = lanes_of(&[0xDB21_3F11]);
    let digest = sparse_fold_digest_nfs(&[tag_bytes(0xDB21_3F00)], pre);
    // No insert witness at all: the "prover" is handed endpoints and signs whatever it is told.
    let fold = prove_sparse_fold_height1_bytes(&[], pre, lie).expect("proves");
    let ok = verify_sparse_fold_height1_bytes(&fold, pre, lie, sparse_fold_digest_nfs(&[], pre));
    let ok2 = {
        let f2 = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(
            {
                let mut cols = vec![vec![Fa4::ZERO; 32]; 3 * DIGEST_LANES + 1];
                cols[3 * DIGEST_LANES][0] = Fa4::ONE;
                cols
            },
            |_g: Ea4| SparseFoldGate,
            &{
                let mut b = vec![Fa4::from_u64(SPARSE_FOLD_DOMAIN)];
                for v in pre.iter().chain(lie.iter()).chain(digest.iter()) {
                    b.push(Fa4::from_u64(crate::nullifier_insert_air::kred(*v)));
                }
                b
            },
        )
        .expect("proves");
        verify_sparse_fold_height1_bytes(&f2, pre, lie, digest)
    };
    println!("[DB-213c F] height-1 fold with NO inserts, false post: verify = {ok}, with a real tag digest = {ok2}");
    // CALIBRATION of the vacuity: the node's authority is its own recompute from the carried tags.
    assert!(ok && ok2, "the height-1 fold REFUSED a false post — if made sound, turn this arm into a refutation");
}

// ── DB-213c REFUTATION LANE — the SOUND one-step membership verify ───────────────────────────────────────────────

/// A 256-leaf record and the in-block copath of leaf `i` — the shape `NoteMembershipCarrier::attach_membership`
/// consumes (dir = true ⇔ our node is the RIGHT child, as `refold_in_block` reads it).
fn record_and_copath(i: usize) -> (Vec<Digest>, Digest, Vec<Digest>, Vec<bool>) {
    use crate::nullifier_insert_air::poseidon_pair_native as pp;
    let leaves: Vec<Digest> = (0..256u64).map(|k| lanes_of(&[0xDB21_3D00, k, k ^ 0x5A])).collect();
    let mut levels = vec![leaves.clone()];
    while levels.last().unwrap().len() > 1 {
        let next = levels.last().unwrap().chunks(2).map(|p| pp(p[0], p[1])).collect();
        levels.push(next);
    }
    let root = levels.last().unwrap()[0];
    let (mut sibs, mut dirs, mut idx) = (Vec::new(), Vec::new(), i);
    for lvl in &levels[..levels.len() - 1] {
        sibs.push(lvl[idx ^ 1]);
        dirs.push(idx & 1 == 1);
        idx >>= 1;
    }
    (leaves, root, sibs, dirs)
}

/// M2 — the census-M forgery (a witness-free RECURSIVE proof) is refused by the one-step verifier, and the honest
/// one-step carrier verifies: the new authority separates the two, which the old one could not.
#[test]
fn census_m2_one_step_membership_refuses_the_forgery_and_accepts_the_honest_note() {
    use crate::note_membership_air::*;
    let (leaves, root, sibs, dirs) = record_and_copath(77);
    let leaf = leaves[77];
    let binder = lanes_of(&[0xDB21_3D01]); // the spend's nullifier
    let blind = lanes_of(&[0xDB21_3B1D]); // DB-363: the spender's per-send blinding (a fixture value)
    let genesis = [0u64; DIGEST_LANES];
    // HONEST — the carrier a wallet builds, finalized as the one-step direct proof.
    let mut carrier = NoteMembershipCarrier::new(leaf, root, genesis, binder, blind);
    assert!(carrier.attach_membership(leaf, &sibs, &dirs), "the honest copath refolds to the record root");
    let (proof, acc, prev, tip_root) = carrier.finalize_one_step().expect("an attached step finalizes");
    let commit = carrier.leaf_commitment();
    assert_eq!((prev, tip_root), (genesis, root));
    assert_eq!(acc, note_membership_step_new_acc(genesis, root), "the tip is one fold from genesis");
    let honest = verify_note_membership_one_step(&proof, commit, binder, root);
    // Each public input moved alone must refuse — the statement names ONE note, ONE spend, ONE record.
    let wrong_binder = verify_note_membership_one_step(&proof, commit, lanes_of(&[0xDB21_3D02]), root);
    let wrong_root = verify_note_membership_one_step(&proof, commit, binder, lanes_of(&[0xDB21_3D03]));
    let wrong_commit = verify_note_membership_one_step(&proof, lanes_of(&[0xDB21_3D04]), binder, root);
    // A byte string that is no carrier at all — the shape the retired fold's forgery had — must refuse: the
    // one-step verifier decodes fail-closed and the census-M object no longer has a verifier to fool.
    let fabricated = lanes_of(&[0xDB21_3C01, 0xF00D]);
    assert!(!leaves.contains(&fabricated));
    let f_commit = note_leaf_commitment(fabricated, binder, blind);
    let garbage = vec![0xA5u8; 4096];
    let garbage_accepts = verify_note_membership_one_step(&garbage, f_commit, binder, root);
    println!(
        "[DB-213c M2] honest one-step ({} B) = {honest}; wrong binder = {wrong_binder}, wrong root = {wrong_root}, \
         wrong commit = {wrong_commit}; a non-carrier byte string for a leaf in no block = {garbage_accepts}",
        proof.len()
    );
    assert!(honest, "the honest one-step membership proof must verify");
    assert!(!wrong_binder && !wrong_root && !wrong_commit, "a moved public input must refuse");
    assert!(!garbage_accepts, "⛔ the one-step verifier accepted a non-carrier byte string");
}

/// M3 — DB-213b ON THE MEMBERSHIP WALK: the same honest walk laid over 16 rows (8 levels + 8 pass-through rows)
/// satisfies every constraint, so an engine reading the carrier's own shape ACCEPTS it — a second byte string for
/// one statement, and on a row-shifted AIR the row count is the walk bound. The pinned verifier refuses it.
#[test]
fn census_m3_a_re_shaped_membership_walk_is_refused_by_the_pinned_verifier() {
    use crate::note_membership_air::*;
    let (leaves, root, sibs, dirs) = record_and_copath(5);
    let leaf = leaves[5];
    let binder = lanes_of(&[0xDB21_3D11]);
    let blind = lanes_of(&[0xDB21_3B1D]); // DB-363: the per-send blinding, a fixture value
    let commit = note_leaf_commitment(leaf, binder, blind);
    let eight = member_step_cols(leaf, &sibs, &dirs, binder, blind);
    let mut cols: Vec<Vec<Fa4>> = eight
        .iter()
        .map(|c| {
            let mut v = c.clone();
            v.resize(16, Fa4::ZERO);
            v
        })
        .collect();
    for row in 8..16 {
        // A pass-through row exactly as `member_step_cols` lays one: fold inactive, acc carried, leaf repeated.
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_FOLD, row, crate::pow_pq_air::pair_state(&root, &root));
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_COMMIT, row, crate::pow_pq_air::pair_state(&leaf, &binder));
        // DB-363: the outer cross-bind block and the blinding lanes, exactly as `member_step_cols` lays them
        let inner = crate::nullifier_insert_air::poseidon_pair_native(leaf, binder);
        crate::pow_pq_air::lay_perm_row_at(&mut cols, MS_COMMIT2, row, crate::pow_pq_air::pair_state(&inner, &blind));
        for c in 0..DIGEST_LANES {
            cols[MS_SIB + c][row] = Fa4::ZERO;
            cols[MS_ACC_IN + c][row] = Fa4::from_u64(root[c]);
            cols[MS_ACC_OUT + c][row] = Fa4::from_u64(root[c]);
            cols[MS_WLEAF + c][row] = Fa4::from_u64(leaf[c]);
            cols[MS_BLIND + c][row] = Fa4::from_u64(blind[c]);
        }
        cols[MS_DIR][row] = Fa4::ZERO;
        cols[MS_ACTIVE][row] = Fa4::ZERO;
    }
    let commit_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(commit[c]).into());
    let binder_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(binder[c]).into());
    let root_ea: [Ea4; DIGEST_LANES] = core::array::from_fn(|c| Fa4::from_u64(root[c]).into());
    let make =
        move |g: Ea4| NoteMemberStepGate { gamma: g, leaf_commit: commit_ea, binder: binder_ea, block_root: root_ea };
    let bind = note_member_step_bind(commit, root);
    let tall = crate::whir_rec_block::prove_air_direct_light_decider_selfcontained_bytes(cols, make, &bind)
        .expect("the prover builds whatever shape it is handed");
    let unpinned = crate::whir_rec_block::verify_air_direct_light_decider_selfcontained_bytes(&tall, make, &bind, crate::whir_rec_block::declared_direct_shape_for_tests(&tall));
    let pinned = verify_note_membership_one_step(&tall, commit, binder, root);
    println!("[DB-213c M3] 16-row walk: engine on the carrier's own shape = {unpinned}; pinned one-step verify = {pinned}");
    assert!(unpinned, "calibration: every constraint holds on the 16-row walk, so the unpinned engine accepts it");
    assert!(!pinned, "⛔ the pinned one-step verifier accepted a carrier whose shape the statement does not fix");
}
