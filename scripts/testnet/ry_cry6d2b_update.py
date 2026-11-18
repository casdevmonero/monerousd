# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct MerkleUpdateAir" not in s:
    anc = "// CRY-6d-2b-ii: reusable comparison constraint block"
    if s.count(anc) != 1: print("FATAL update anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-2b-iii: Merkle UPDATE — folds leaf_old and leaf_new up the SAME path (shared siblings+bits) to
// root_old and root_new respectively. This is the L->L' low-leaf update of the IMT insert (root_old->root_mid).
// Per level: shared [sib, bit] + (cur_old + 3 node-hash perms) + (cur_new + 3 node-hash perms).
#[derive(Clone)]
pub struct MerkleUpdateAir {
    pub depth: usize,
}

const MU_SIB: usize = 0;
const MU_BIT: usize = DIGEST;
const MU_CUR_O: usize = DIGEST + 1;
const MU_PERMS_O: usize = MU_CUR_O + DIGEST;            // 3 perms * 2 * WIDTH = 96
const MU_CUR_N: usize = MU_PERMS_O + 3 * 2 * WIDTH;
const MU_PERMS_N: usize = MU_CUR_N + DIGEST;
const MU_LEVEL_W: usize = MU_PERMS_N + 3 * 2 * WIDTH;   // 8+1+8+96+8+96 = 217

impl BaseAir<F> for MerkleUpdateAir {
    fn width(&self) -> usize { self.depth * MU_LEVEL_W }
    fn num_public_values(&self) -> usize { 4 * DIGEST }    // root_old || root_new || leaf_old || leaf_new
}

impl<AB> Air<AB> for MerkleUpdateAir
where
    AB: AirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let w = self.depth * MU_LEVEL_W;
        let local: Vec<AB::Var> = builder.main().current_slice()[..w].to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let lv = |k: usize| k * MU_LEVEL_W;
        let sib = |k: usize, j: usize| local[lv(k) + MU_SIB + j];
        let bit = |k: usize| local[lv(k) + MU_BIT];
        let cur_o = |k: usize, j: usize| local[lv(k) + MU_CUR_O + j];
        let mo_in = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_O + p * (2 * WIDTH) + j];
        let mo_out = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_O + p * (2 * WIDTH) + WIDTH + j];
        let cur_n = |k: usize, j: usize| local[lv(k) + MU_CUR_N + j];
        let mn_in = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_N + p * (2 * WIDTH) + j];
        let mn_out = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_N + p * (2 * WIDTH) + WIDTH + j];

        for k in 0..self.depth {
            let b = bit(k);
            builder.assert_zero(b.into() * (b.into() - AB::Expr::ONE));
            // ---- OLD fold ----
            builder.assert_eq(mo_in(k, 0, 0), AB::Expr::from_u64(DS_MERKLE));
            for j in RATE..WIDTH { builder.assert_zero(mo_in(k, 0, j)); }
            for j in 0..RATE - 1 {
                let lj = cur_o(k, j).into() + b.into() * (sib(k, j).into() - cur_o(k, j).into());
                builder.assert_eq(mo_in(k, 0, 1 + j), lj);
            }
            let l7 = cur_o(k, RATE - 1).into() + b.into() * (sib(k, RATE - 1).into() - cur_o(k, RATE - 1).into());
            builder.assert_eq(mo_in(k, 1, 0), l7);
            for j in 0..RATE - 1 {
                let rj = sib(k, j).into() + b.into() * (cur_o(k, j).into() - sib(k, j).into());
                builder.assert_eq(mo_in(k, 1, 1 + j), rj);
            }
            let r7 = sib(k, RATE - 1).into() + b.into() * (cur_o(k, RATE - 1).into() - sib(k, RATE - 1).into());
            builder.assert_eq(mo_in(k, 2, 0), r7);
            for j in RATE..WIDTH { builder.assert_eq(mo_in(k, 1, j), mo_out(k, 0, j)); builder.assert_eq(mo_in(k, 2, j), mo_out(k, 1, j)); }
            for j in 1..RATE { builder.assert_eq(mo_in(k, 2, j), mo_out(k, 1, j)); }
            if k > 0 { for j in 0..DIGEST { builder.assert_eq(cur_o(k, j), mo_out(k - 1, 2, j)); } }
            // ---- NEW fold (same bit + sib) ----
            builder.assert_eq(mn_in(k, 0, 0), AB::Expr::from_u64(DS_MERKLE));
            for j in RATE..WIDTH { builder.assert_zero(mn_in(k, 0, j)); }
            for j in 0..RATE - 1 {
                let lj = cur_n(k, j).into() + b.into() * (sib(k, j).into() - cur_n(k, j).into());
                builder.assert_eq(mn_in(k, 0, 1 + j), lj);
            }
            let l7n = cur_n(k, RATE - 1).into() + b.into() * (sib(k, RATE - 1).into() - cur_n(k, RATE - 1).into());
            builder.assert_eq(mn_in(k, 1, 0), l7n);
            for j in 0..RATE - 1 {
                let rj = sib(k, j).into() + b.into() * (cur_n(k, j).into() - sib(k, j).into());
                builder.assert_eq(mn_in(k, 1, 1 + j), rj);
            }
            let r7n = sib(k, RATE - 1).into() + b.into() * (cur_n(k, RATE - 1).into() - sib(k, RATE - 1).into());
            builder.assert_eq(mn_in(k, 2, 0), r7n);
            for j in RATE..WIDTH { builder.assert_eq(mn_in(k, 1, j), mn_out(k, 0, j)); builder.assert_eq(mn_in(k, 2, j), mn_out(k, 1, j)); }
            for j in 1..RATE { builder.assert_eq(mn_in(k, 2, j), mn_out(k, 1, j)); }
            if k > 0 { for j in 0..DIGEST { builder.assert_eq(cur_n(k, j), mn_out(k - 1, 2, j)); } }
        }
        // leaves + roots bound to publics: [root_old || root_new || leaf_old || leaf_new]
        for j in 0..DIGEST {
            builder.assert_eq(cur_o(0, j), pis[2 * DIGEST + j]);          // leaf_old
            builder.assert_eq(cur_n(0, j), pis[3 * DIGEST + j]);          // leaf_new
            builder.assert_eq(mo_out(self.depth - 1, 2, j), pis[j]);      // root_old
            builder.assert_eq(mn_out(self.depth - 1, 2, j), pis[DIGEST + j]); // root_new
        }
        for k in 0..self.depth {
            for p in 0..3 {
                let oo = lv(k) + MU_PERMS_O + p * (2 * WIDTH);
                let fo: Vec<AB::Var> = local[oo..oo + 2 * WIDTH].to_vec();
                builder.push_interaction(POSEIDON_HASH_BUS, fo, AB::Expr::ONE, 1);
                let no = lv(k) + MU_PERMS_N + p * (2 * WIDTH);
                let fn_: Vec<AB::Var> = local[no..no + 2 * WIDTH].to_vec();
                builder.push_interaction(POSEIDON_HASH_BUS, fn_, AB::Expr::ONE, 1);
            }
        }
    }
}

/// Prove + verify a Merkle update: leaf_old@(siblings,index) gives root_old, leaf_new same path gives
/// root_new. tamper=true claims a wrong root_new. Returns true iff the honest update verifies.
pub fn prove_verify_merkle_update(leaf_old: [F; DIGEST], leaf_new: [F; DIGEST], siblings: Vec<[F; DIGEST]>, index: usize, tamper: bool) -> bool {
    let depth = siblings.len();
    let run_o = merkle_path_run(leaf_old, &siblings, index);
    let run_n = merkle_path_run(leaf_new, &siblings, index);
    let mut row: Vec<F> = Vec::with_capacity(depth * MU_LEVEL_W);
    for k in 0..depth {
        row.extend_from_slice(&run_o.levels[k].sib);
        row.push(run_o.levels[k].bit);
        row.extend_from_slice(&run_o.levels[k].cur);
        for p in 0..3 { row.extend_from_slice(&run_o.levels[k].perms_in[p]); row.extend_from_slice(&run_o.levels[k].perms_out[p]); }
        row.extend_from_slice(&run_n.levels[k].cur);
        for p in 0..3 { row.extend_from_slice(&run_n.levels[k].perms_in[p]); row.extend_from_slice(&run_n.levels[k].perms_out[p]); }
    }
    let trace = RowMajorMatrix::new(row, depth * MU_LEVEL_W);
    let mut perm_inputs: Vec<[F; WIDTH]> = Vec::new();
    for k in 0..depth { for p in 0..3 { perm_inputs.push(run_o.levels[k].perms_in[p]); } for p in 0..3 { perm_inputs.push(run_n.levels[k].perms_in[p]); } }
    let constants = poseidon2_constants();
    let (source_airs, source_traces) = build_source_chunks(&perm_inputs, &constants);
    let consumer = SpendCircuitAir::MerkleUpdate(MerkleUpdateAir { depth });
    let config = crate::build_config();
    let mut root_new = run_n.root; if tamper { root_new[0] += F::ONE; }
    let mut pvs: Vec<F> = run_o.root.to_vec(); pvs.extend_from_slice(&root_new); pvs.extend_from_slice(&leaf_old); pvs.extend_from_slice(&leaf_new);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in source_airs.iter().zip(source_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &trace, public_values: pvs.clone() });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = source_airs.clone(); airs.push(consumer.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; source_airs.len()]; allpvs.push(pvs);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

/// CRY-6d-2b-iii gate: an honest dual-fold update verifies; a wrong root_new is rejected.
pub fn merkle_update_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sibs = vec![mk(2), mk(3), mk(4), mk(5)];
    if !prove_verify_merkle_update(mk(40), mk(41), sibs.clone(), 5, false) { return false; }
    if prove_verify_merkle_update(mk(40), mk(41), sibs, 5, true) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("MerkleUpdateAir added")
else: print("MerkleUpdateAir present; skip")

ev = "    ImtNonMembership(ImtNonMembershipAir),\n"
if "    MerkleUpdate(MerkleUpdateAir),\n" not in s:
    if s.count(ev) < 1: print("FATAL enum anchor"); sys.exit(1)
    s = s.replace(ev, ev + "    MerkleUpdate(MerkleUpdateAir),\n", 1)
    for a0, a1 in [
        ("            Self::ImtNonMembership(a) => <ImtNonMembershipAir as BaseAir<F>>::width(a),\n",
         "            Self::MerkleUpdate(a) => <MerkleUpdateAir as BaseAir<F>>::width(a),\n"),
        ("            Self::ImtNonMembership(a) => <ImtNonMembershipAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::MerkleUpdate(a) => <MerkleUpdateAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::ImtNonMembership(a) => a.eval(builder),\n",
         "            Self::MerkleUpdate(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
else: print("enum present; skip")
open(c, "w").write(s)

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_merkle_update_selftest" not in fs:
    fs = fs.replace("    compare_selftest, imt_membership_selftest, imt_nonmembership_selftest,", "    compare_selftest, imt_membership_selftest, imt_nonmembership_selftest, merkle_update_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_imt_nonmembership_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_merkle_update_selftest() -> i32 { if merkle_update_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi update added")
else: print("ffi update present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_merkle_update_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_imt_nonmembership_selftest(void);", "int32_t pqpool_imt_nonmembership_selftest(void);\nint32_t pqpool_merkle_update_selftest(void);", 1)); print("ffi.h update added")
else: print("ffi.h update present; skip")
print("DONE")
