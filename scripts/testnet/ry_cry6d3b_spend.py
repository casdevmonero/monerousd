# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct CmtSinkAir" not in s:
    anc = "// CRY-6d-3: a stub nf SENDER on NS_LEAF_BUS"
    if s.count(anc) != 1: print("FATAL anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-3b: a sink that RECEIVES out_cm from CMT_LEAF_BUS, balancing SpendBatchAir's emit when we are
// validating only the nf->IMT binding (the real output cmt-append is the consensus tree, 6c-2/6e).
#[derive(Clone)]
pub struct CmtSinkAir;
impl BaseAir<F> for CmtSinkAir {
    fn width(&self) -> usize { DIGEST }
    fn num_public_values(&self) -> usize { 0 }
}
impl<AB> Air<AB> for CmtSinkAir where AB: AirBuilder<F = F> + InteractionBuilder {
    fn eval(&self, builder: &mut AB) {
        let local: Vec<AB::Var> = builder.main().current_slice()[..DIGEST].to_vec();
        let cols: Vec<AB::Var> = (0..DIGEST).map(|j| local[j]).collect();
        builder.push_interaction(CMT_LEAF_BUS, cols, AB::Expr::ONE, 1); // receive out_cm
    }
}

// CRY-6d-3b: build the ImtInsertAir(nf_from_bus) trace + sources for inserting `nf`, using a sentinel low
// leaf {value=0, next_value=bracket(nf)} that brackets any nf (0 < nf < bracket). Returns (trace, source
// airs, source traces, root_old, root_new) for batching with a SpendBatchAir that SENDS nf.
fn build_imt_insert_artifacts_for_nf(nf: [F; DIGEST], depth: usize) -> (RowMajorMatrix<F>, Vec<SpendCircuitAir>, Vec<RowMajorMatrix<F>>, [F; DIGEST], [F; DIGEST]) {
    let value = [F::ZERO; DIGEST];
    let mut next_value = [F::ZERO; DIGEST]; next_value[DIGEST - 1] = nf[DIGEST - 1] + F::ONE; // bracket > nf (MSB elem)
    let (next_idx, l_idx, new_idx) = (0u64, 5usize, 9usize);
    let pre = |v: &[F; DIGEST], ni: u64, nvv: &[F; DIGEST]| -> Vec<F> { let mut p = Vec::with_capacity(18); p.push(F::from_u64(DS_NF_IMT_LEAF)); p.extend_from_slice(v); p.push(F::from_u64(ni)); p.extend_from_slice(nvv); p };
    let sp_l = run_sponge(&pre(&value, next_idx, &next_value));
    let sp_lp = run_sponge(&pre(&value, new_idx as u64, &nf));
    let sp_q = run_sponge(&pre(&nf, next_idx, &next_value));
    let (leaf_l, leaf_lp, leaf_q) = (sp_l.digest, sp_lp.digest, sp_q.digest);
    let mut leaves = vec![[F::ZERO; DIGEST]; 1usize << depth]; leaves[l_idx] = leaf_lp;
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
    row.extend_from_slice(&nf);
    let air_w = 3 * (3 * 2 * WIDTH) + 2 * depth * MU_LEVEL_W + 2 * CMP_W + DIGEST;
    let trace = RowMajorMatrix::new(row, air_w);
    let mut perm_inputs: Vec<[F; WIDTH]> = Vec::new();
    for sp in [&sp_l, &sp_lp, &sp_q] { perm_inputs.extend_from_slice(&sp.states_in); }
    for (ro, rn) in [(&r_old, &r_mid), (&r_mid2, &r_new)] { for k in 0..depth { for p in 0..3 { perm_inputs.push(ro.levels[k].perms_in[p]); } for p in 0..3 { perm_inputs.push(rn.levels[k].perms_in[p]); } } }
    let constants = poseidon2_constants();
    let (src_airs, src_traces) = build_source_chunks(&perm_inputs, &constants);
    (trace, src_airs, src_traces, r_old.root, r_new.root)
}

/// CRY-6d-3b: the REAL reserve-yield spend — a SpendBatchAir proving a coinbase note is spent (membership
/// + sk-knowledge + nf derivation) SENDS its nf on NS_LEAF_BUS; ImtInsertAir RECEIVES it and inserts it
/// into the IMT nullifier set (non-membership + insert). LogUp forces the inserted nf == the SPENT note's
/// nf, and nf is never public. out_cm is sunk (its real cmt-append is consensus, 6c-2). Returns verify.
#[allow(clippy::too_many_arguments)]
pub fn prove_verify_reserve_yield_spend(
    spend: (u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], Vec<[F; DIGEST]>, usize, u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], u64, u64, FullSpendTamper),
    depth: usize, tamper_ns: bool,
) -> bool {
    let (sa, spend_trace, src_airs, src_traces, pvs) = build_spend_artifacts(spend.0, spend.1, spend.2, spend.3, spend.4, spend.5, spend.6, spend.7, spend.8, spend.9, spend.10, spend.11, spend.12, spend.13, spend.14);
    let nf: [F; DIGEST] = pvs[DIGEST..2 * DIGEST].try_into().unwrap();
    let out_cm: [F; DIGEST] = pvs[2 * DIGEST..3 * DIGEST].try_into().unwrap();
    let anchor = pvs[0..DIGEST].to_vec();
    let chain = pvs[4 * DIGEST + 1]; let fee = pvs[4 * DIGEST];
    let spend_w = <SpendAir as BaseAir<F>>::width(&sa);
    let row_w = spend_w + 1 + 2 * WIDTH24;
    let mut state_in = [F::ZERO; WIDTH24]; for j in 0..DIGEST { state_in[j] = nf[j]; state_in[DIGEST + j] = out_cm[j]; }
    let state_out = native_perm_24_output(state_in);
    let mut batch_row: Vec<F> = spend_trace.values[0..spend_w].to_vec(); batch_row.push(fee); batch_row.extend_from_slice(&state_in); batch_row.extend_from_slice(&state_out);
    let batch_trace = RowMajorMatrix::new(batch_row, row_w);
    let batch_air = SpendCircuitAir::SpendBatch(SpendBatchAir { spend: sa.clone(), emit_leaf_buses: true });
    let final_state = native_perm_24_output(state_in);
    let commitment = [final_state[RATE24 - 1], final_state[RATE24 - 2], final_state[RATE24 - 3], final_state[RATE24 - 4]];
    let mut batch_pvs = anchor.clone(); batch_pvs.push(chain); batch_pvs.extend_from_slice(&commitment);
    let chal_source_trace = poseidon2_trace_24(vec![state_in], &poseidon2_constants_24());
    let chal_source_air = SpendCircuitAir::Poseidon2Source24(Poseidon2Source24Air(P2Air24::new(poseidon2_constants_24())));

    let (imt_trace, imt_src_airs, imt_src_traces, root_old, root_new0) = build_imt_insert_artifacts_for_nf(nf, depth);
    let mut root_new = root_new0; if tamper_ns { root_new[0] += F::ONE; }
    let mut imt_pvs: Vec<F> = root_old.to_vec(); imt_pvs.extend_from_slice(&root_new);
    let cmt_sink_trace = RowMajorMatrix::new(out_cm.to_vec(), DIGEST);

    let config = crate::build_config();
    let consumer = SpendCircuitAir::ImtInsert(ImtInsertAir { depth, nf_from_bus: true });
    let cmt_sink = SpendCircuitAir::CmtSink(CmtSinkAir);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in src_airs.iter().zip(src_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &chal_source_air, trace: &chal_source_trace, public_values: vec![] });
    instances.push(StarkInstance { air: &batch_air, trace: &batch_trace, public_values: batch_pvs.clone() });
    for (a, t) in imt_src_airs.iter().zip(imt_src_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &imt_trace, public_values: imt_pvs.clone() });
    instances.push(StarkInstance { air: &cmt_sink, trace: &cmt_sink_trace, public_values: vec![] });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = src_airs.clone(); airs.push(chal_source_air.clone()); airs.push(batch_air.clone());
    airs.extend(imt_src_airs.iter().cloned()); airs.push(consumer.clone()); airs.push(cmt_sink.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; src_airs.len()]; allpvs.push(vec![]); allpvs.push(batch_pvs);
    for _ in 0..imt_src_airs.len() { allpvs.push(vec![]); } allpvs.push(imt_pvs); allpvs.push(vec![]);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

/// CRY-6d-3b gate: an honest reserve-yield spend (nf bound to the spent note, inserted into IMT) verifies;
/// a tampered ns_root rejects.
pub fn reserve_yield_spend_compose_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sp = (1_000_000u64, 5u32, mk(6), mk(7), mk(8), vec![mk(2), mk(3), mk(4), mk(5)], 0b1010usize, 999_000u64, 5u32, mk(9), mk(10), mk(11), 1000u64, 42u64, FullSpendTamper::None);
    if !prove_verify_reserve_yield_spend(sp.clone(), 4, false) { return false; }
    if prove_verify_reserve_yield_spend(sp, 4, true) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("reserve-yield spend compose added")
else: print("present; skip")

ev = "    NfSource(NfSourceAir),\n"
if "    CmtSink(CmtSinkAir),\n" not in s:
    s = s.replace(ev, ev + "    CmtSink(CmtSinkAir),\n", 1)
    for a0, a1 in [
        ("            Self::NfSource(a) => <NfSourceAir as BaseAir<F>>::width(a),\n",
         "            Self::CmtSink(a) => <CmtSinkAir as BaseAir<F>>::width(a),\n"),
        ("            Self::NfSource(a) => <NfSourceAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::CmtSink(a) => <CmtSinkAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::NfSource(a) => a.eval(builder),\n",
         "            Self::CmtSink(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
open(c, "w").write(s)

f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_reserve_yield_spend_compose_selftest" not in fs:
    fs = fs.replace("imt_insert_private_selftest,", "imt_insert_private_selftest, reserve_yield_spend_compose_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_imt_insert_private_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_reserve_yield_spend_compose_selftest() -> i32 { if reserve_yield_spend_compose_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi added")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_reserve_yield_spend_compose_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_imt_insert_private_selftest(void);", "int32_t pqpool_imt_insert_private_selftest(void);\nint32_t pqpool_reserve_yield_spend_compose_selftest(void);", 1)); print("ffi.h added")
print("DONE")
