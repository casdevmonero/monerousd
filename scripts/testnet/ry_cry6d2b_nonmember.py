# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct ImtNonMembershipAir" not in s:
    anc = "// CRY-6d-2b-i: IMT low-leaf membership."
    if s.count(anc) != 1: print("FATAL nonmember anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-2b-ii: reusable comparison constraint block (the CompareAir logic) at column offset `base`,
// binding the recomposed operands a,b to caller-supplied EXPRESSIONS a_t,b_t (the shared columns) rather
// than to public values. Proves a < b via b-a-1>=0 over 16x 16-bit sub-limbs. CMP_W columns wide.
fn cmp_block<AB>(builder: &mut AB, local: &[AB::Var], bse: usize, a_t: &[AB::Expr; DIGEST], b_t: &[AB::Expr; DIGEST])
where AB: AirBuilder<F = F> {
    let a_sub = |k: usize| local[bse + CMP_A_SUB + k];
    let a_bit = |k: usize, j: usize| local[bse + CMP_A_BITS + k * 16 + j];
    let b_sub = |k: usize| local[bse + CMP_B_SUB + k];
    let b_bit = |k: usize, j: usize| local[bse + CMP_B_BITS + k * 16 + j];
    let d = |k: usize| local[bse + CMP_D + k];
    let d_bit = |k: usize, j: usize| local[bse + CMP_D_BITS + k * 16 + j];
    let borrow = |k: usize| local[bse + CMP_BORROW + k];
    for k in 0..CMP_SUBLIMBS {
        let mut acca = AB::Expr::ZERO; let mut accb = AB::Expr::ZERO; let mut accd = AB::Expr::ZERO;
        for j in 0..16 {
            let ba = a_bit(k, j); builder.assert_zero(ba.into() * (ba.into() - AB::Expr::ONE)); acca = acca + ba.into() * AB::Expr::from_u64(1u64 << j);
            let bb = b_bit(k, j); builder.assert_zero(bb.into() * (bb.into() - AB::Expr::ONE)); accb = accb + bb.into() * AB::Expr::from_u64(1u64 << j);
            let bd = d_bit(k, j); builder.assert_zero(bd.into() * (bd.into() - AB::Expr::ONE)); accd = accd + bd.into() * AB::Expr::from_u64(1u64 << j);
        }
        builder.assert_eq(a_sub(k), acca);
        builder.assert_eq(b_sub(k), accb);
        builder.assert_eq(d(k), accd);
        let bo = borrow(k); builder.assert_zero(bo.into() * (bo.into() - AB::Expr::ONE));
    }
    for e in 0..DIGEST {
        builder.assert_eq(a_sub(2 * e).into() + a_sub(2 * e + 1).into() * AB::Expr::from_u64(1u64 << 16), a_t[e].clone());
        builder.assert_eq(b_sub(2 * e).into() + b_sub(2 * e + 1).into() * AB::Expr::from_u64(1u64 << 16), b_t[e].clone());
    }
    for k in 0..CMP_SUBLIMBS {
        let borrow_in = if k == 0 { AB::Expr::ZERO } else { borrow(k - 1).into() };
        let lsb_one = if k == 0 { AB::Expr::ONE } else { AB::Expr::ZERO };
        builder.assert_zero(b_sub(k).into() - a_sub(k).into() - borrow_in - lsb_one + borrow(k).into() * AB::Expr::from_u64(1u64 << 16) - d(k).into());
    }
    builder.assert_zero(borrow(CMP_SUBLIMBS - 1).into());
}

/// CRY-6d-2b-ii: MONOLITHIC IMT non-membership. Proves a low leaf L={value,next_idx,next_value} is in the
/// tree at `anchor` AND value < nf < next_value (so nf is absent — it falls in L's gap). value/next_value
/// are WITNESS in the C1 sponge lanes and bound to the two comparisons by SHARED COLUMNS (not buses); nf is
/// public. Layout: C1 leaf sponge (3 perms) | C2 Merkle | C3 cmp(value<nf) | C4 cmp(nf<next_value).
#[derive(Clone)]
pub struct ImtNonMembershipAir {
    pub depth: usize,
}

impl ImtNonMembershipAir {
    fn c3_off(&self) -> usize { IMT_C2_OFF + self.depth * MERKLE_LEVEL_W }
    fn c4_off(&self) -> usize { self.c3_off() + CMP_W }
}

impl BaseAir<F> for ImtNonMembershipAir {
    fn width(&self) -> usize { IMT_C2_OFF + self.depth * MERKLE_LEVEL_W + 2 * CMP_W }
    fn num_public_values(&self) -> usize { DIGEST + DIGEST }   // anchor || nf
}

impl<AB> Air<AB> for ImtNonMembershipAir
where
    AB: AirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let w = self.width();
        let local: Vec<AB::Var> = builder.main().current_slice()[..w].to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let c1_in = |p: usize, j: usize| local[p * (2 * WIDTH) + j];
        let c1_out = |p: usize, j: usize| local[p * (2 * WIDTH) + WIDTH + j];
        let c2 = |k: usize| IMT_C2_OFF + k * MERKLE_LEVEL_W;
        let cur = |k: usize, j: usize| local[c2(k) + j];
        let sib = |k: usize, j: usize| local[c2(k) + DIGEST + j];
        let bit = |k: usize| local[c2(k) + 2 * DIGEST];
        let m_in = |k: usize, p: usize, j: usize| local[c2(k) + 2 * DIGEST + 1 + p * (2 * WIDTH) + j];
        let m_out = |k: usize, p: usize, j: usize| local[c2(k) + 2 * DIGEST + 1 + p * (2 * WIDTH) + WIDTH + j];

        // ── C1: imt_leaf_hash sponge (3 perms), data is WITNESS in the lanes. ──
        builder.assert_eq(c1_in(0, 0), AB::Expr::from_u64(DS_NF_IMT_LEAF));
        for j in RATE..WIDTH { builder.assert_zero(c1_in(0, j)); }
        for j in RATE..WIDTH { builder.assert_eq(c1_in(1, j), c1_out(0, j)); }
        for j in 2..WIDTH { builder.assert_eq(c1_in(2, j), c1_out(1, j)); }

        // ── C2: Merkle membership. ──
        for k in 0..self.depth {
            let b = bit(k);
            builder.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
            builder.assert_eq(m_in(k, 0, 0), AB::Expr::from_u64(DS_MERKLE));
            for j in RATE..WIDTH { builder.assert_zero(m_in(k, 0, j)); }
            for j in 0..RATE - 1 {
                let left_j = cur(k, j).into() + b.into() * (sib(k, j).into() - cur(k, j).into());
                builder.assert_eq(m_in(k, 0, 1 + j), left_j);
            }
            let left7 = cur(k, RATE - 1).into() + b.into() * (sib(k, RATE - 1).into() - cur(k, RATE - 1).into());
            builder.assert_eq(m_in(k, 1, 0), left7);
            for j in 0..RATE - 1 {
                let right_j = sib(k, j).into() + b.into() * (cur(k, j).into() - sib(k, j).into());
                builder.assert_eq(m_in(k, 1, 1 + j), right_j);
            }
            let right7 = sib(k, RATE - 1).into() + b.into() * (cur(k, RATE - 1).into() - sib(k, RATE - 1).into());
            builder.assert_eq(m_in(k, 2, 0), right7);
            for j in RATE..WIDTH {
                builder.assert_eq(m_in(k, 1, j), m_out(k, 0, j));
                builder.assert_eq(m_in(k, 2, j), m_out(k, 1, j));
            }
            for j in 1..RATE { builder.assert_eq(m_in(k, 2, j), m_out(k, 1, j)); }
            if k > 0 { for j in 0..DIGEST { builder.assert_eq(cur(k, j), m_out(k - 1, 2, j)); } }
        }
        for j in 0..DIGEST { builder.assert_eq(cur(0, j), c1_out(IMT_PERMS - 1, j)); }
        for j in 0..DIGEST { builder.assert_eq(m_out(self.depth - 1, 2, j), pis[j]); }

        // ── shared-column operands: value lanes, next_value lanes, nf public. ──
        let mut value_t: Vec<AB::Expr> = Vec::with_capacity(DIGEST);
        for e in 0..7 { value_t.push(c1_in(0, 1 + e).into()); }
        value_t.push(c1_in(1, 0).into());
        let mut nv_t: Vec<AB::Expr> = Vec::with_capacity(DIGEST);
        for e in 0..6 { nv_t.push(c1_in(1, 2 + e).into()); }
        nv_t.push(c1_in(2, 0).into()); nv_t.push(c1_in(2, 1).into());
        let nf_t: Vec<AB::Expr> = (0..DIGEST).map(|e| pis[DIGEST + e].into()).collect();
        let value_a: [AB::Expr; DIGEST] = value_t.try_into().ok().unwrap();
        let nv_a: [AB::Expr; DIGEST] = nv_t.try_into().ok().unwrap();
        let nf_a: [AB::Expr; DIGEST] = nf_t.try_into().ok().unwrap();

        // ── C3: value < nf ;  C4: nf < next_value. ──
        cmp_block(builder, &local, self.c3_off(), &value_a, &nf_a);
        cmp_block(builder, &local, self.c4_off(), &nf_a, &nv_a);

        // delegate the C1 + C2 permutations to the shared Poseidon table.
        for p in 0..IMT_PERMS {
            let off = p * (2 * WIDTH);
            let fields: Vec<AB::Var> = local[off..off + 2 * WIDTH].to_vec();
            builder.push_interaction(POSEIDON_HASH_BUS, fields, AB::Expr::ONE, 1);
        }
        for k in 0..self.depth {
            for p in 0..3 {
                let off = c2(k) + 2 * DIGEST + 1 + p * (2 * WIDTH);
                let fields: Vec<AB::Var> = local[off..off + 2 * WIDTH].to_vec();
                builder.push_interaction(POSEIDON_HASH_BUS, fields, AB::Expr::ONE, 1);
            }
        }
    }
}

/// Compute the 832 CompareAir witness columns proving a < b (sub-limbs, bits, diff, borrows).
fn compute_cmp_columns(a: &[F; DIGEST], b: &[F; DIGEST]) -> Vec<F> {
    let ab = publics_to_bytes(a); let bb = publics_to_bytes(b);
    let au = |e: usize| u32::from_le_bytes([ab[4*e], ab[4*e+1], ab[4*e+2], ab[4*e+3]]);
    let bu = |e: usize| u32::from_le_bytes([bb[4*e], bb[4*e+1], bb[4*e+2], bb[4*e+3]]);
    let mut a_sub = [0i64; CMP_SUBLIMBS]; let mut b_sub = [0i64; CMP_SUBLIMBS];
    for e in 0..DIGEST {
        a_sub[2*e] = (au(e) & 0xFFFF) as i64; a_sub[2*e+1] = ((au(e) >> 16) & 0xFFFF) as i64;
        b_sub[2*e] = (bu(e) & 0xFFFF) as i64; b_sub[2*e+1] = ((bu(e) >> 16) & 0xFFFF) as i64;
    }
    let mut d = [0i64; CMP_SUBLIMBS]; let mut bor = [0i64; CMP_SUBLIMBS]; let mut bin = 0i64;
    for k in 0..CMP_SUBLIMBS {
        let lsb_one = if k == 0 { 1 } else { 0 };
        let rhs = b_sub[k] - a_sub[k] - bin - lsb_one;
        let (bo, dd) = if rhs < 0 { (1i64, rhs + (1i64 << 16)) } else { (0i64, rhs) };
        d[k] = dd; bor[k] = bo; bin = bo;
    }
    let mut row: Vec<F> = Vec::with_capacity(CMP_W);
    for k in 0..CMP_SUBLIMBS { row.push(F::from_u64(a_sub[k] as u64)); }
    for k in 0..CMP_SUBLIMBS { for j in 0..16 { row.push(F::from_u64(((a_sub[k] >> j) & 1) as u64)); } }
    for k in 0..CMP_SUBLIMBS { row.push(F::from_u64(b_sub[k] as u64)); }
    for k in 0..CMP_SUBLIMBS { for j in 0..16 { row.push(F::from_u64(((b_sub[k] >> j) & 1) as u64)); } }
    for k in 0..CMP_SUBLIMBS { row.push(F::from_u64(d[k] as u64)); }
    for k in 0..CMP_SUBLIMBS { for j in 0..16 { row.push(F::from_u64(((d[k] >> j) & 1) as u64)); } }
    for k in 0..CMP_SUBLIMBS { row.push(F::from_u64(bor[k] as u64)); }
    row
}

/// Build + prove + verify IMT non-membership of `nf` via low leaf L. Returns true iff it verifies (which
/// requires value < nf < next_value AND L in the tree). A present/out-of-gap nf has no valid witness.
pub fn prove_verify_imt_nonmembership(value: [F; DIGEST], next_index: u64, next_value: [F; DIGEST], nf: [F; DIGEST], siblings: Vec<[F; DIGEST]>, index: usize) -> bool {
    let depth = siblings.len();
    let mut pre = Vec::with_capacity(18);
    pre.push(F::from_u64(DS_NF_IMT_LEAF)); pre.extend_from_slice(&value); pre.push(F::from_u64(next_index)); pre.extend_from_slice(&next_value);
    let c1 = run_sponge(&pre);
    let merkle = merkle_path_run(c1.digest, &siblings, index);
    let anchor = merkle.root;

    let cmw = IMT_C2_OFF + depth * MERKLE_LEVEL_W + 2 * CMP_W;
    let mut row: Vec<F> = Vec::with_capacity(cmw);
    for p in 0..IMT_PERMS { row.extend_from_slice(&c1.states_in[p]); row.extend_from_slice(&c1.states_out[p]); }
    for lvl in &merkle.levels {
        row.extend_from_slice(&lvl.cur); row.extend_from_slice(&lvl.sib); row.push(lvl.bit);
        for p in 0..3 { row.extend_from_slice(&lvl.perms_in[p]); row.extend_from_slice(&lvl.perms_out[p]); }
    }
    row.extend_from_slice(&compute_cmp_columns(&value, &nf));   // C3: value < nf
    row.extend_from_slice(&compute_cmp_columns(&nf, &next_value)); // C4: nf < next_value
    let trace = RowMajorMatrix::new(row, cmw);

    let mut perm_inputs = c1.states_in.clone(); perm_inputs.extend_from_slice(&merkle.perm_inputs);
    let constants = poseidon2_constants();
    let (source_airs, source_traces) = build_source_chunks(&perm_inputs, &constants);
    let consumer = SpendCircuitAir::ImtNonMembership(ImtNonMembershipAir { depth });
    let config = crate::build_config();
    let mut pvs: Vec<F> = anchor.to_vec(); pvs.extend_from_slice(&nf);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in source_airs.iter().zip(source_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &trace, public_values: pvs.clone() });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = source_airs.clone(); airs.push(consumer.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; source_airs.len()]; allpvs.push(pvs);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

/// CRY-6d-2b-ii gate: nf in the gap (value<nf<next_value) proves absent; nf outside the gap / equal to a
/// boundary has no valid witness and is rejected.
pub fn imt_nonmembership_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sibs = vec![mk(2), mk(3), mk(4), mk(5)];
    let (value, nidx, nv) = (mk(30), 1u64, mk(70));
    if !prove_verify_imt_nonmembership(value, nidx, nv, mk(50), sibs.clone(), 5) { return false; } // 30<50<70 absent
    if prove_verify_imt_nonmembership(value, nidx, nv, mk(80), sibs.clone(), 5) { return false; }  // 80>70: out of gap
    if prove_verify_imt_nonmembership(value, nidx, nv, mk(20), sibs.clone(), 5) { return false; }  // 20<30: out of gap
    if prove_verify_imt_nonmembership(value, nidx, nv, mk(30), sibs, 5) { return false; }          // ==value: not <
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("ImtNonMembershipAir added")
else: print("ImtNonMembershipAir present; skip")

ev = "    ImtLeafMembership(ImtLeafMembershipAir),\n"
if "    ImtNonMembership(ImtNonMembershipAir),\n" not in s:
    if s.count(ev) < 1: print("FATAL enum anchor"); sys.exit(1)
    s = s.replace(ev, ev + "    ImtNonMembership(ImtNonMembershipAir),\n", 1)
    for a0, a1 in [
        ("            Self::ImtLeafMembership(a) => <ImtLeafMembershipAir as BaseAir<F>>::width(a),\n",
         "            Self::ImtNonMembership(a) => <ImtNonMembershipAir as BaseAir<F>>::width(a),\n"),
        ("            Self::ImtLeafMembership(a) => <ImtLeafMembershipAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::ImtNonMembership(a) => <ImtNonMembershipAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::ImtLeafMembership(a) => a.eval(builder),\n",
         "            Self::ImtNonMembership(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
else: print("enum present; skip")
open(c, "w").write(s)

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_imt_nonmembership_selftest" not in fs:
    fs = fs.replace("    compare_selftest, imt_membership_selftest,", "    compare_selftest, imt_membership_selftest, imt_nonmembership_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_imt_membership_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_imt_nonmembership_selftest() -> i32 { if imt_nonmembership_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi nonmember added")
else: print("ffi nonmember present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_imt_nonmembership_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_imt_membership_selftest(void);", "int32_t pqpool_imt_membership_selftest(void);\nint32_t pqpool_imt_nonmembership_selftest(void);", 1)); print("ffi.h nonmember added")
else: print("ffi.h nonmember present; skip")
print("DONE")
