# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct ImtInsertAir" not in s:
    anc = "// CRY-6d-2b-iii: Merkle UPDATE"
    if s.count(anc) != 1: print("FATAL insert anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-2b-iii ASSEMBLY helpers: the 3-perm IMT leaf sponge STRUCTURE (domain/capacity/chaining/carry;
// data lanes left as witness for the caller to bind) and the dual-fold (two leaves up one shared path).
fn imt_sponge_struct<AB: AirBuilder<F = F>>(builder: &mut AB, local: &[AB::Var], b: usize) {
    let ci = |p: usize, j: usize| local[b + p * (2 * WIDTH) + j];
    let co = |p: usize, j: usize| local[b + p * (2 * WIDTH) + WIDTH + j];
    builder.assert_eq(ci(0, 0), AB::Expr::from_u64(DS_NF_IMT_LEAF));
    for j in RATE..WIDTH { builder.assert_zero(ci(0, j)); }
    for j in RATE..WIDTH { builder.assert_eq(ci(1, j), co(0, j)); }
    for j in 2..WIDTH { builder.assert_eq(ci(2, j), co(1, j)); }
}

fn mu_fold<AB: AirBuilder<F = F>>(builder: &mut AB, local: &[AB::Var], b: usize, depth: usize) {
    let lv = |k: usize| b + k * MU_LEVEL_W;
    let sib = |k: usize, j: usize| local[lv(k) + MU_SIB + j];
    let bit = |k: usize| local[lv(k) + MU_BIT];
    let cur_o = |k: usize, j: usize| local[lv(k) + MU_CUR_O + j];
    let mo_in = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_O + p * (2 * WIDTH) + j];
    let mo_out = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_O + p * (2 * WIDTH) + WIDTH + j];
    let cur_n = |k: usize, j: usize| local[lv(k) + MU_CUR_N + j];
    let mn_in = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_N + p * (2 * WIDTH) + j];
    let mn_out = |k: usize, p: usize, j: usize| local[lv(k) + MU_PERMS_N + p * (2 * WIDTH) + WIDTH + j];
    for k in 0..depth {
        let bb = bit(k);
        builder.assert_zero(bb.into() * (bb.into() - AB::Expr::ONE));
        builder.assert_eq(mo_in(k, 0, 0), AB::Expr::from_u64(DS_MERKLE));
        for j in RATE..WIDTH { builder.assert_zero(mo_in(k, 0, j)); }
        for j in 0..RATE - 1 { let lj = cur_o(k, j).into() + bb.into() * (sib(k, j).into() - cur_o(k, j).into()); builder.assert_eq(mo_in(k, 0, 1 + j), lj); }
        let l7 = cur_o(k, RATE - 1).into() + bb.into() * (sib(k, RATE - 1).into() - cur_o(k, RATE - 1).into()); builder.assert_eq(mo_in(k, 1, 0), l7);
        for j in 0..RATE - 1 { let rj = sib(k, j).into() + bb.into() * (cur_o(k, j).into() - sib(k, j).into()); builder.assert_eq(mo_in(k, 1, 1 + j), rj); }
        let r7 = sib(k, RATE - 1).into() + bb.into() * (cur_o(k, RATE - 1).into() - sib(k, RATE - 1).into()); builder.assert_eq(mo_in(k, 2, 0), r7);
        for j in RATE..WIDTH { builder.assert_eq(mo_in(k, 1, j), mo_out(k, 0, j)); builder.assert_eq(mo_in(k, 2, j), mo_out(k, 1, j)); }
        for j in 1..RATE { builder.assert_eq(mo_in(k, 2, j), mo_out(k, 1, j)); }
        if k > 0 { for j in 0..DIGEST { builder.assert_eq(cur_o(k, j), mo_out(k - 1, 2, j)); } }
        builder.assert_eq(mn_in(k, 0, 0), AB::Expr::from_u64(DS_MERKLE));
        for j in RATE..WIDTH { builder.assert_zero(mn_in(k, 0, j)); }
        for j in 0..RATE - 1 { let lj = cur_n(k, j).into() + bb.into() * (sib(k, j).into() - cur_n(k, j).into()); builder.assert_eq(mn_in(k, 0, 1 + j), lj); }
        let l7n = cur_n(k, RATE - 1).into() + bb.into() * (sib(k, RATE - 1).into() - cur_n(k, RATE - 1).into()); builder.assert_eq(mn_in(k, 1, 0), l7n);
        for j in 0..RATE - 1 { let rj = sib(k, j).into() + bb.into() * (cur_n(k, j).into() - sib(k, j).into()); builder.assert_eq(mn_in(k, 1, 1 + j), rj); }
        let r7n = sib(k, RATE - 1).into() + bb.into() * (cur_n(k, RATE - 1).into() - sib(k, RATE - 1).into()); builder.assert_eq(mn_in(k, 2, 0), r7n);
        for j in RATE..WIDTH { builder.assert_eq(mn_in(k, 1, j), mn_out(k, 0, j)); builder.assert_eq(mn_in(k, 2, j), mn_out(k, 1, j)); }
        for j in 1..RATE { builder.assert_eq(mn_in(k, 2, j), mn_out(k, 1, j)); }
        if k > 0 { for j in 0..DIGEST { builder.assert_eq(cur_n(k, j), mn_out(k - 1, 2, j)); } }
    }
}

// CRY-6d-2b-iii: the FULL IMT insert of nf. Proves root_old -> root_new is a valid insertion: low leaf L
// in root_old with value<nf<next_value (non-membership), L->L'={value,new_idx,nf} update (root_mid), and
// Q={nf,L.next_idx,L.next_value} appended at an empty slot (root_new). Columns: SP_L|SP_Lp|SP_Q sponges,
// MU1 (L/L' dual-fold -> root_old/root_mid), MU2 (empty/Q dual-fold -> root_mid/root_new), C3|C4 compares.
// All cross-block binding is SHARED COLUMNS. nf is public here; in the SpendAir compose it becomes witness.
#[derive(Clone)]
pub struct ImtInsertAir {
    pub depth: usize,
}

impl ImtInsertAir {
    fn mu1(&self) -> usize { 3 * (3 * 2 * WIDTH) }                  // after SP_L|SP_Lp|SP_Q (96 each)
    fn mu2(&self) -> usize { self.mu1() + self.depth * MU_LEVEL_W }
    fn c3(&self) -> usize { self.mu2() + self.depth * MU_LEVEL_W }
    fn c4(&self) -> usize { self.c3() + CMP_W }
}

impl BaseAir<F> for ImtInsertAir {
    fn width(&self) -> usize { 3 * (3 * 2 * WIDTH) + 2 * self.depth * MU_LEVEL_W + 2 * CMP_W }
    fn num_public_values(&self) -> usize { DIGEST + DIGEST + DIGEST }   // root_old(anchor) || root_new || nf
}

impl<AB> Air<AB> for ImtInsertAir
where
    AB: AirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let w = self.width();
        let local: Vec<AB::Var> = builder.main().current_slice()[..w].to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let (spl, splp, spq) = (0usize, 3 * 2 * WIDTH, 2 * (3 * 2 * WIDTH));
        let (mu1, mu2, c3, c4) = (self.mu1(), self.mu2(), self.c3(), self.c4());
        let leaf_of = |b: usize, j: usize| local[b + 2 * (2 * WIDTH) + WIDTH + j];   // sponge leaf = perm2 out digest
        // sponge data-lane accessors (within a sponge block b)
        let val = |b: usize, e: usize| if e < 7 { local[b + 1 + e] } else { local[b + 2 * WIDTH + 0] };
        let nidx = |b: usize| local[b + 2 * WIDTH + 1];
        let nv = |b: usize, e: usize| if e < 6 { local[b + 2 * WIDTH + 2 + e] } else { local[b + 2 * 2 * WIDTH + (e - 6)] };
        // MU fold accessors
        let mu_leaf_o = |b: usize, j: usize| local[b + MU_CUR_O + j];
        let mu_leaf_n = |b: usize, j: usize| local[b + MU_CUR_N + j];
        let mu_root_o = |b: usize, j: usize| local[b + (self.depth - 1) * MU_LEVEL_W + MU_PERMS_O + 2 * (2 * WIDTH) + WIDTH + j];
        let mu_root_n = |b: usize, j: usize| local[b + (self.depth - 1) * MU_LEVEL_W + MU_PERMS_N + 2 * (2 * WIDTH) + WIDTH + j];

        // ── sponge structures ──
        imt_sponge_struct(builder, &local, spl);
        imt_sponge_struct(builder, &local, splp);
        imt_sponge_struct(builder, &local, spq);
        // ── dual folds ──
        mu_fold(builder, &local, mu1, self.depth);
        mu_fold(builder, &local, mu2, self.depth);

        // ── data bindings (the heart: maintain the value-chain + bind the insert) ──
        let nf = |e: usize| pis[2 * DIGEST + e];
        for e in 0..DIGEST {
            // L' = {value=L.value, next_idx=witness, next_value=nf}
            builder.assert_eq(val(splp, e), val(spl, e));
            builder.assert_eq(nv(splp, e), nf(e).into());
            // Q = {value=nf, next_idx=L.next_idx, next_value=L.next_value}
            builder.assert_eq(val(spq, e), nf(e).into());
            builder.assert_eq(nv(spq, e), nv(spl, e));
        }
        builder.assert_eq(nidx(spq), nidx(spl));
        // ── leaf <-> fold bottom bindings ──
        for j in 0..DIGEST {
            builder.assert_eq(mu_leaf_o(mu1, j), leaf_of(spl, j));      // MU1 old leaf = L
            builder.assert_eq(mu_leaf_n(mu1, j), leaf_of(splp, j));     // MU1 new leaf = L'
            builder.assert_zero(mu_leaf_o(mu2, j));                     // MU2 old leaf = EMPTY (append slot)
            builder.assert_eq(mu_leaf_n(mu2, j), leaf_of(spq, j));      // MU2 new leaf = Q
        }
        // ── root bindings + root_mid chain ──
        for j in 0..DIGEST {
            builder.assert_eq(mu_root_o(mu1, j), pis[j]);               // root_old == anchor
            builder.assert_eq(mu_root_n(mu1, j), mu_root_o(mu2, j));    // root_mid: L'-fold top == empty-fold top
            builder.assert_eq(mu_root_n(mu2, j), pis[DIGEST + j]);      // root_new public
        }
        // ── gap comparisons (shared columns): value < nf < next_value ──
        let value_a: [AB::Expr; DIGEST] = (0..DIGEST).map(|e| val(spl, e).into()).collect::<Vec<_>>().try_into().ok().unwrap();
        let nv_a: [AB::Expr; DIGEST] = (0..DIGEST).map(|e| nv(spl, e).into()).collect::<Vec<_>>().try_into().ok().unwrap();
        let nf_a: [AB::Expr; DIGEST] = (0..DIGEST).map(|e| nf(e).into()).collect::<Vec<_>>().try_into().ok().unwrap();
        cmp_block(builder, &local, c3, &value_a, &nf_a);
        cmp_block(builder, &local, c4, &nf_a, &nv_a);

        // ── delegate all sponge + fold permutations to the shared Poseidon table ──
        for b in [spl, splp, spq] {
            for p in 0..IMT_PERMS { let off = b + p * (2 * WIDTH); let f: Vec<AB::Var> = local[off..off + 2 * WIDTH].to_vec(); builder.push_interaction(POSEIDON_HASH_BUS, f, AB::Expr::ONE, 1); }
        }
        for b in [mu1, mu2] {
            for k in 0..self.depth {
                for p in 0..3 {
                    let oo = b + k * MU_LEVEL_W + MU_PERMS_O + p * (2 * WIDTH); let fo: Vec<AB::Var> = local[oo..oo + 2 * WIDTH].to_vec(); builder.push_interaction(POSEIDON_HASH_BUS, fo, AB::Expr::ONE, 1);
                    let no = b + k * MU_LEVEL_W + MU_PERMS_N + p * (2 * WIDTH); let fnn: Vec<AB::Var> = local[no..no + 2 * WIDTH].to_vec(); builder.push_interaction(POSEIDON_HASH_BUS, fnn, AB::Expr::ONE, 1);
                }
            }
        }
    }
}

/// Build + prove + verify a full IMT insert of nf via low leaf L (value, next_idx, next_value) at L_idx,
/// L' update + Q append at an empty new_idx. tamper claims a wrong root_new. Returns true iff it verifies.
pub fn prove_verify_imt_insert(value: [F; DIGEST], next_idx: u64, next_value: [F; DIGEST], nf: [F; DIGEST], l_idx: usize, new_idx: usize, depth: usize, tamper: bool) -> bool {
    let pre = |v: &[F; DIGEST], ni: u64, nvv: &[F; DIGEST]| -> Vec<F> { let mut p = Vec::with_capacity(18); p.push(F::from_u64(DS_NF_IMT_LEAF)); p.extend_from_slice(v); p.push(F::from_u64(ni)); p.extend_from_slice(nvv); p };
    let sp_l = run_sponge(&pre(&value, next_idx, &next_value));
    let sp_lp = run_sponge(&pre(&value, new_idx as u64, &nf));                 // L' = {value, new_idx, nf}
    let sp_q = run_sponge(&pre(&nf, next_idx, &next_value));                    // Q  = {nf, L.next_idx, L.next_value}
    let leaf_l = sp_l.digest; let leaf_lp = sp_lp.digest; let leaf_q = sp_q.digest;
    // tree T_mid: L' at l_idx, empty elsewhere -> gives the shared paths.
    let mut leaves = vec![[F::ZERO; DIGEST]; 1usize << depth];
    leaves[l_idx] = leaf_lp;
    let (_root_mid_t, levels) = ry_build_tree(&leaves, depth);
    let sibs_l = ry_tree_path(&levels, l_idx, depth);
    let sibs_q = ry_tree_path(&levels, new_idx, depth);
    let r_old = merkle_path_run(leaf_l, &sibs_l, l_idx);
    let r_mid = merkle_path_run(leaf_lp, &sibs_l, l_idx);
    let r_mid2 = merkle_path_run([F::ZERO; DIGEST], &sibs_q, new_idx);          // empty@new_idx -> root_mid
    let r_new = merkle_path_run(leaf_q, &sibs_q, new_idx);
    // assemble: SP_L|SP_Lp|SP_Q | MU1(L/L') | MU2(empty/Q) | C3 | C4
    let mut row: Vec<F> = Vec::new();
    for sp in [&sp_l, &sp_lp, &sp_q] { for p in 0..IMT_PERMS { row.extend_from_slice(&sp.states_in[p]); row.extend_from_slice(&sp.states_out[p]); } }
    let push_mu = |row: &mut Vec<F>, ro: &MerklePathRun, rn: &MerklePathRun| {
        for k in 0..depth {
            row.extend_from_slice(&ro.levels[k].sib); row.push(ro.levels[k].bit);
            row.extend_from_slice(&ro.levels[k].cur); for p in 0..3 { row.extend_from_slice(&ro.levels[k].perms_in[p]); row.extend_from_slice(&ro.levels[k].perms_out[p]); }
            row.extend_from_slice(&rn.levels[k].cur); for p in 0..3 { row.extend_from_slice(&rn.levels[k].perms_in[p]); row.extend_from_slice(&rn.levels[k].perms_out[p]); }
        }
    };
    push_mu(&mut row, &r_old, &r_mid);
    push_mu(&mut row, &r_mid2, &r_new);
    row.extend_from_slice(&compute_cmp_columns(&value, &nf));
    row.extend_from_slice(&compute_cmp_columns(&nf, &next_value));
    let air_w = 3 * (3 * 2 * WIDTH) + 2 * depth * MU_LEVEL_W + 2 * CMP_W;
    let trace = RowMajorMatrix::new(row, air_w);

    let mut perm_inputs: Vec<[F; WIDTH]> = Vec::new();
    for sp in [&sp_l, &sp_lp, &sp_q] { perm_inputs.extend_from_slice(&sp.states_in); }
    for (ro, rn) in [(&r_old, &r_mid), (&r_mid2, &r_new)] {
        for k in 0..depth { for p in 0..3 { perm_inputs.push(ro.levels[k].perms_in[p]); } for p in 0..3 { perm_inputs.push(rn.levels[k].perms_in[p]); } }
    }
    let constants = poseidon2_constants();
    let (source_airs, source_traces) = build_source_chunks(&perm_inputs, &constants);
    let consumer = SpendCircuitAir::ImtInsert(ImtInsertAir { depth });
    let config = crate::build_config();
    let mut root_new = r_new.root; if tamper { root_new[0] += F::ONE; }
    let mut pvs: Vec<F> = r_old.root.to_vec(); pvs.extend_from_slice(&root_new); pvs.extend_from_slice(&nf);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in source_airs.iter().zip(source_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &trace, public_values: pvs.clone() });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = source_airs.clone(); airs.push(consumer.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; source_airs.len()]; allpvs.push(pvs);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

/// CRY-6d-2b-iii gate: an honest insert (root_old->root_new adding nf) verifies; a wrong root_new rejects.
pub fn imt_insert_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    if !prove_verify_imt_insert(mk(30), 1, mk(70), mk(50), 5, 9, 4, false) { return false; }
    if prove_verify_imt_insert(mk(30), 1, mk(70), mk(50), 5, 9, 4, true) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("ImtInsertAir added")
else: print("ImtInsertAir present; skip")

ev = "    MerkleUpdate(MerkleUpdateAir),\n"
if "    ImtInsert(ImtInsertAir),\n" not in s:
    if s.count(ev) < 1: print("FATAL enum anchor"); sys.exit(1)
    s = s.replace(ev, ev + "    ImtInsert(ImtInsertAir),\n", 1)
    for a0, a1 in [
        ("            Self::MerkleUpdate(a) => <MerkleUpdateAir as BaseAir<F>>::width(a),\n",
         "            Self::ImtInsert(a) => <ImtInsertAir as BaseAir<F>>::width(a),\n"),
        ("            Self::MerkleUpdate(a) => <MerkleUpdateAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::ImtInsert(a) => <ImtInsertAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::MerkleUpdate(a) => a.eval(builder),\n",
         "            Self::ImtInsert(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
else: print("enum present; skip")
open(c, "w").write(s)

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_imt_insert_selftest" not in fs:
    fs = fs.replace("merkle_update_selftest,", "merkle_update_selftest, imt_insert_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_merkle_update_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_imt_insert_selftest() -> i32 { if imt_insert_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi insert added")
else: print("ffi insert present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_imt_insert_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_merkle_update_selftest(void);", "int32_t pqpool_merkle_update_selftest(void);\nint32_t pqpool_imt_insert_selftest(void);", 1)); print("ffi.h insert added")
else: print("ffi.h insert present; skip")
print("DONE")
