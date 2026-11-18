# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "nf_from_bus" not in s:
    # 1) struct field
    s = s.replace("pub struct ImtInsertAir {\n    pub depth: usize,\n}",
                  "pub struct ImtInsertAir {\n    pub depth: usize,\n    pub nf_from_bus: bool,\n}", 1)
    # 2) width
    s = s.replace("fn width(&self) -> usize { 3 * (3 * 2 * WIDTH) + 2 * self.depth * MU_LEVEL_W + 2 * CMP_W }",
                  "fn width(&self) -> usize { 3 * (3 * 2 * WIDTH) + 2 * self.depth * MU_LEVEL_W + 2 * CMP_W + if self.nf_from_bus { DIGEST } else { 0 } }", 1)
    # 3) num_public_values (ImtInsert's)
    s = s.replace("    fn num_public_values(&self) -> usize { DIGEST + DIGEST + DIGEST }   // root_old(anchor) || root_new || nf",
                  "    fn num_public_values(&self) -> usize { if self.nf_from_bus { DIGEST + DIGEST } else { DIGEST + DIGEST + DIGEST } }   // root_old||root_new(||nf if public)", 1)
    # 4) nf accessor -> conditional, returns Expr
    s = s.replace("        let nf = |e: usize| pis[2 * DIGEST + e];",
                  "        let nf = |e: usize| -> AB::Expr { if self.nf_from_bus { local[c4 + CMP_W + e].into() } else { pis[2 * DIGEST + e].into() } };", 1)
    # 5) usages: nf(e).into() -> nf(e)
    s = s.replace("builder.assert_eq(nv(splp, e), nf(e).into());", "builder.assert_eq(nv(splp, e), nf(e));", 1)
    s = s.replace("builder.assert_eq(val(spq, e), nf(e).into());", "builder.assert_eq(val(spq, e), nf(e));", 1)
    s = s.replace("(0..DIGEST).map(|e| nf(e).into()).collect::<Vec<_>>()", "(0..DIGEST).map(|e| nf(e)).collect::<Vec<_>>()", 1)
    # 6) receive nf from bus (insert before the push_interaction delegation comment)
    rec_anc = "        // ── delegate all sponge + fold permutations to the shared Poseidon table ──"
    rec = ("        if self.nf_from_bus {\n"
           "            let nfcols: Vec<AB::Var> = (0..DIGEST).map(|e| local[c4 + CMP_W + e]).collect();\n"
           "            builder.push_interaction(NS_LEAF_BUS, nfcols, AB::Expr::ONE, 1); // receive nf (bound to sender)\n"
           "        }\n")
    if s.count(rec_anc) != 1: print("FATAL rec anchor x%d" % s.count(rec_anc)); sys.exit(1)
    s = s.replace(rec_anc, rec + rec_anc, 1)
    # 7) existing consumer construction
    s = s.replace("let consumer = SpendCircuitAir::ImtInsert(ImtInsertAir { depth });",
                  "let consumer = SpendCircuitAir::ImtInsert(ImtInsertAir { depth, nf_from_bus: false });", 1)
    print("ImtInsertAir nf_from_bus added")
else: print("nf_from_bus present; skip")

# NfSourceAir + private prove/verify + selftest, before imt_insert_selftest
if "pub struct NfSourceAir" not in s:
    anc = "/// CRY-6d-2b-iii gate: an honest insert"
    if s.count(anc) != 1: print("FATAL src anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-3: a stub nf SENDER on NS_LEAF_BUS (stands in for SpendBatchAir's emit), used to validate that
// ImtInsertAir can receive nf PRIVATELY (only roots public). In production SpendBatchAir is the sender.
#[derive(Clone)]
pub struct NfSourceAir;
impl BaseAir<F> for NfSourceAir {
    fn width(&self) -> usize { DIGEST }
    fn num_public_values(&self) -> usize { 0 }
}
impl<AB> Air<AB> for NfSourceAir where AB: AirBuilder<F = F> + InteractionBuilder {
    fn eval(&self, builder: &mut AB) {
        let local: Vec<AB::Var> = builder.main().current_slice()[..DIGEST].to_vec();
        let nfcols: Vec<AB::Var> = (0..DIGEST).map(|j| local[j]).collect();
        builder.push_interaction(NS_LEAF_BUS, nfcols, -AB::Expr::ONE, 1); // send nf
    }
}

/// CRY-6d-3: full IMT insert with nf PRIVATE (received from NS_LEAF_BUS, sent by NfSourceAir). Only
/// root_old/root_new are public; nf never appears in the public inputs. Returns true iff it verifies.
pub fn prove_verify_imt_insert_private(value: [F; DIGEST], next_idx: u64, next_value: [F; DIGEST], nf: [F; DIGEST], l_idx: usize, new_idx: usize, depth: usize, tamper: bool) -> bool {
    let pre = |v: &[F; DIGEST], ni: u64, nvv: &[F; DIGEST]| -> Vec<F> { let mut p = Vec::with_capacity(18); p.push(F::from_u64(DS_NF_IMT_LEAF)); p.extend_from_slice(v); p.push(F::from_u64(ni)); p.extend_from_slice(nvv); p };
    let sp_l = run_sponge(&pre(&value, next_idx, &next_value));
    let sp_lp = run_sponge(&pre(&value, new_idx as u64, &nf));
    let sp_q = run_sponge(&pre(&nf, next_idx, &next_value));
    let (leaf_l, leaf_lp, leaf_q) = (sp_l.digest, sp_lp.digest, sp_q.digest);
    let mut leaves = vec![[F::ZERO; DIGEST]; 1usize << depth];
    leaves[l_idx] = leaf_lp;
    let (_rm, levels) = ry_build_tree(&leaves, depth);
    let sibs_l = ry_tree_path(&levels, l_idx, depth);
    let sibs_q = ry_tree_path(&levels, new_idx, depth);
    let r_old = merkle_path_run(leaf_l, &sibs_l, l_idx);
    let r_mid = merkle_path_run(leaf_lp, &sibs_l, l_idx);
    let r_mid2 = merkle_path_run([F::ZERO; DIGEST], &sibs_q, new_idx);
    let r_new = merkle_path_run(leaf_q, &sibs_q, new_idx);
    let mut row: Vec<F> = Vec::new();
    for sp in [&sp_l, &sp_lp, &sp_q] { for p in 0..IMT_PERMS { row.extend_from_slice(&sp.states_in[p]); row.extend_from_slice(&sp.states_out[p]); } }
    let push_mu = |row: &mut Vec<F>, ro: &MerklePathRun, rn: &MerklePathRun| {
        for k in 0..depth {
            row.extend_from_slice(&ro.levels[k].sib); row.push(ro.levels[k].bit);
            row.extend_from_slice(&ro.levels[k].cur); for p in 0..3 { row.extend_from_slice(&ro.levels[k].perms_in[p]); row.extend_from_slice(&ro.levels[k].perms_out[p]); }
            row.extend_from_slice(&rn.levels[k].cur); for p in 0..3 { row.extend_from_slice(&rn.levels[k].perms_in[p]); row.extend_from_slice(&rn.levels[k].perms_out[p]); }
        }
    };
    push_mu(&mut row, &r_old, &r_mid); push_mu(&mut row, &r_mid2, &r_new);
    row.extend_from_slice(&compute_cmp_columns(&value, &nf));
    row.extend_from_slice(&compute_cmp_columns(&nf, &next_value));
    row.extend_from_slice(&nf);   // nf witness columns (received from the bus)
    let air_w = 3 * (3 * 2 * WIDTH) + 2 * depth * MU_LEVEL_W + 2 * CMP_W + DIGEST;
    let trace = RowMajorMatrix::new(row, air_w);
    let nf_trace = RowMajorMatrix::new(nf.to_vec(), DIGEST);

    let mut perm_inputs: Vec<[F; WIDTH]> = Vec::new();
    for sp in [&sp_l, &sp_lp, &sp_q] { perm_inputs.extend_from_slice(&sp.states_in); }
    for (ro, rn) in [(&r_old, &r_mid), (&r_mid2, &r_new)] { for k in 0..depth { for p in 0..3 { perm_inputs.push(ro.levels[k].perms_in[p]); } for p in 0..3 { perm_inputs.push(rn.levels[k].perms_in[p]); } } }
    let constants = poseidon2_constants();
    let (source_airs, source_traces) = build_source_chunks(&perm_inputs, &constants);
    let consumer = SpendCircuitAir::ImtInsert(ImtInsertAir { depth, nf_from_bus: true });
    let nf_air = SpendCircuitAir::NfSource(NfSourceAir);
    let config = crate::build_config();
    let mut root_new = r_new.root; if tamper { root_new[0] += F::ONE; }
    let mut pvs: Vec<F> = r_old.root.to_vec(); pvs.extend_from_slice(&root_new);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in source_airs.iter().zip(source_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &trace, public_values: pvs.clone() });
    instances.push(StarkInstance { air: &nf_air, trace: &nf_trace, public_values: vec![] });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = source_airs.clone(); airs.push(consumer.clone()); airs.push(nf_air.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; source_airs.len()]; allpvs.push(pvs); allpvs.push(vec![]);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

pub fn imt_insert_private_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    if !prove_verify_imt_insert_private(mk(30), 1, mk(70), mk(50), 5, 9, 4, false) { return false; }
    if prove_verify_imt_insert_private(mk(30), 1, mk(70), mk(50), 5, 9, 4, true) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("NfSourceAir + private insert added")
else: print("NfSourceAir present; skip")

ev = "    ImtInsert(ImtInsertAir),\n"
if "    NfSource(NfSourceAir),\n" not in s:
    s = s.replace(ev, ev + "    NfSource(NfSourceAir),\n", 1)
    for a0, a1 in [
        ("            Self::ImtInsert(a) => <ImtInsertAir as BaseAir<F>>::width(a),\n",
         "            Self::NfSource(a) => <NfSourceAir as BaseAir<F>>::width(a),\n"),
        ("            Self::ImtInsert(a) => <ImtInsertAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::NfSource(a) => <NfSourceAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::ImtInsert(a) => a.eval(builder),\n",
         "            Self::NfSource(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
else: print("enum present; skip")
open(c, "w").write(s)

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_imt_insert_private_selftest" not in fs:
    fs = fs.replace("merkle_update_selftest, imt_insert_selftest,", "merkle_update_selftest, imt_insert_selftest, imt_insert_private_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_imt_insert_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_imt_insert_private_selftest() -> i32 { if imt_insert_private_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi private added")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_imt_insert_private_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_imt_insert_selftest(void);", "int32_t pqpool_imt_insert_selftest(void);\nint32_t pqpool_imt_insert_private_selftest(void);", 1)); print("ffi.h private added")
print("DONE")
