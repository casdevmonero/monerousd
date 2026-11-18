# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
f = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool/src/circuit.rs"
s = open(f).read()
if "prove_reserve_yield_spend_bundle_v2" in s:
    print("v2 already present; skip"); sys.exit(0)

V2 = r'''/// CRY-6 public-nf: PROVE a reserve-yield spend with the nullifier PUBLIC (no IMT). The bundle =
/// SpendBatchAir(nf_public) + CmtSink — proves the coinbase note is spent (membership + sk + nf-derivation)
/// and EXPOSES nf in batch_pvs (anchor‖chain‖commitment‖nf). The daemon keeps a nullifier SET and rejects
/// duplicates (Zcash/Monero model) — which makes multi-spend work. imt_pvs is empty; imt_depth 0.
#[allow(clippy::too_many_arguments)]
pub fn prove_reserve_yield_spend_bundle_v2(
    spend: (u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], Vec<[F; DIGEST]>, usize, u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], u64, u64, FullSpendTamper),
) -> ReserveYieldSpendBundle {
    let spend_depth = spend.5.len();
    let (sa, spend_trace, src_airs, src_traces, pvs) = build_spend_artifacts(spend.0, spend.1, spend.2, spend.3, spend.4, spend.5, spend.6, spend.7, spend.8, spend.9, spend.10, spend.11, spend.12, spend.13, spend.14);
    let nf: [F; DIGEST] = pvs[DIGEST..2*DIGEST].try_into().unwrap();
    let out_cm: [F; DIGEST] = pvs[2*DIGEST..3*DIGEST].try_into().unwrap();
    let anchor = pvs[0..DIGEST].to_vec(); let chain = pvs[4*DIGEST+1]; let fee = pvs[4*DIGEST];
    let spend_w = <SpendAir as BaseAir<F>>::width(&sa);
    let row_w = spend_w + 1 + 2*WIDTH24;
    let mut state_in = [F::ZERO; WIDTH24]; for j in 0..DIGEST { state_in[j]=nf[j]; state_in[DIGEST+j]=out_cm[j]; }
    let state_out = native_perm_24_output(state_in);
    let mut batch_row: Vec<F> = spend_trace.values[0..spend_w].to_vec(); batch_row.push(fee); batch_row.extend_from_slice(&state_in); batch_row.extend_from_slice(&state_out);
    let batch_trace = RowMajorMatrix::new(batch_row, row_w);
    let batch_air = SpendCircuitAir::SpendBatch(SpendBatchAir { spend: sa.clone(), emit_leaf_buses: true, nf_public: true });
    let final_state = native_perm_24_output(state_in);
    let commitment = [final_state[RATE24-1], final_state[RATE24-2], final_state[RATE24-3], final_state[RATE24-4]];
    let mut batch_pvs = anchor.clone(); batch_pvs.push(chain); batch_pvs.extend_from_slice(&commitment); batch_pvs.extend_from_slice(&nf);
    let chal_source_trace = poseidon2_trace_24(vec![state_in], &poseidon2_constants_24());
    let chal_source_air = SpendCircuitAir::Poseidon2Source24(Poseidon2Source24Air(P2Air24::new(poseidon2_constants_24())));
    let cmt_sink_trace = RowMajorMatrix::new(out_cm.to_vec(), DIGEST);
    let config = crate::build_config();
    let cmt_sink = SpendCircuitAir::CmtSink(CmtSinkAir);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in src_airs.iter().zip(src_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &chal_source_air, trace: &chal_source_trace, public_values: vec![] });
    instances.push(StarkInstance { air: &batch_air, trace: &batch_trace, public_values: batch_pvs.clone() });
    instances.push(StarkInstance { air: &cmt_sink, trace: &cmt_sink_trace, public_values: vec![] });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let proof_bytes = postcard::to_allocvec(&proof).expect("serialize ry spend v2 proof");
    ReserveYieldSpendBundle { proof_bytes, batch_pvs, imt_pvs: vec![], spend_depth, imt_depth: 0 }
}

/// CRY-6 public-nf: verify a v2 (public-nf, no-IMT) bundle from bytes — the daemon path.
pub fn verify_reserve_yield_spend_bundle_v2(b: &ReserveYieldSpendBundle) -> bool {
    if b.batch_pvs.len() != DIGEST + 1 + 4 + DIGEST { return false; }
    let config = crate::build_config();
    let proof = match postcard::from_bytes(&b.proof_bytes) { Ok(p) => p, Err(_) => return false };
    let dz = [F::ZERO; DIGEST];
    let mut airs: Vec<SpendCircuitAir> = Vec::new();
    let mut traces: Vec<RowMajorMatrix<F>> = Vec::new();
    let mut pvs: Vec<Vec<F>> = Vec::new();
    let dummy_sibs: Vec<[F; DIGEST]> = vec![dz; b.spend_depth];
    let (sa, _t, sa_airs, sa_traces, _p) = build_spend_artifacts(2, 0, dz, dz, dz, dummy_sibs, 0, 1, 0, dz, dz, dz, 1, 0, FullSpendTamper::None);
    let spend_w = <SpendAir as BaseAir<F>>::width(&sa);
    let row_w = spend_w + 1 + 2 * WIDTH24;
    for (a, t) in sa_airs.iter().zip(sa_traces.iter()) { airs.push(a.clone()); traces.push(RowMajorMatrix::new(vec![F::ZERO; t.values.len()], t.width)); pvs.push(vec![]); }
    airs.push(SpendCircuitAir::Poseidon2Source24(Poseidon2Source24Air(P2Air24::new(poseidon2_constants_24()))));
    traces.push(poseidon2_trace_24(vec![[F::ZERO; WIDTH24]; 1], &poseidon2_constants_24())); pvs.push(vec![]);
    airs.push(SpendCircuitAir::SpendBatch(SpendBatchAir { spend: sa, emit_leaf_buses: true, nf_public: true }));
    traces.push(RowMajorMatrix::new(vec![F::ZERO; row_w], row_w)); pvs.push(b.batch_pvs.clone());
    airs.push(SpendCircuitAir::CmtSink(CmtSinkAir));
    traces.push(RowMajorMatrix::new(vec![F::ZERO; DIGEST], DIGEST)); pvs.push(vec![]);
    let instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = airs.iter().zip(traces.iter()).zip(pvs.iter()).map(|((a, t), p)| StarkInstance { air: a, trace: t, public_values: p.clone() }).collect();
    let pd = ProverData::from_instances(&config, &instances);
    verify_batch(&config, &airs, &proof, &pvs, &pd.common).is_ok()
}

/// CRY-6 public-nf: extract the PUBLIC nullifier (batch_pvs[anchor+chain+commitment ..]) — the daemon's set key.
pub fn reserve_yield_spend_nullifier_bytes(bundle: &[u8]) -> Option<Vec<u8>> {
    let b = ReserveYieldSpendBundle::deserialize_bundle(bundle).ok()?;
    if b.batch_pvs.len() != DIGEST + 1 + 4 + DIGEST { return None; }
    Some(publics_to_bytes(&b.batch_pvs[DIGEST + 1 + 4 .. DIGEST + 1 + 4 + DIGEST]))
}

/// CRY-6 public-nf wallet builder (v2): build a public-nf coinbase-note spend bundle from an owned note.
#[allow(clippy::too_many_arguments)]
pub fn prove_reserve_yield_coinbase_spend_bundle_v2(
    sk_bytes: &[u8], rho_bytes: &[u8], rcm_bytes: &[u8], value: u64, asset: u32,
    cmt_notes: &[u8], leaf_index: usize, cmt_depth: usize, out_pk_bytes: &[u8], fee: u64, chain_id: u64,
) -> Option<ReserveYieldSpendBundle> {
    if sk_bytes.len() != DIGEST * 4 || rho_bytes.len() != DIGEST * 4 || rcm_bytes.len() != DIGEST * 4 || out_pk_bytes.len() != DIGEST * 4 { return None; }
    if value < fee || cmt_notes.len() % 32 != 0 || cmt_depth == 0 || cmt_depth > 16 { return None; }
    let count = cmt_notes.len() / 32;
    if count == 0 || leaf_index >= count || count > (1usize << cmt_depth) { return None; }
    let sk = ry_bytes_to_digest(sk_bytes); let rho = ry_bytes_to_digest(rho_bytes); let rcm = ry_bytes_to_digest(rcm_bytes);
    let out_pk = ry_bytes_to_digest(out_pk_bytes);
    let pk_d = own_null_run(sk, rho).pk_d;
    let note_cm = run_sponge(&note_commit_preimage(value, asset, &pk_d, &rho, &rcm)).digest;
    if ry_bytes_to_digest(&cmt_notes[leaf_index * 32..leaf_index * 32 + 32]) != note_cm { return None; }
    let sib_bytes = ry_note_tree_path_bytes(cmt_notes, cmt_depth, leaf_index)?;
    let siblings: Vec<[F; DIGEST]> = (0..cmt_depth).map(|k| ry_bytes_to_digest(&sib_bytes[k * 32..k * 32 + 32])).collect();
    let dom = |tag: u64, seed: &[F; DIGEST]| -> [F; DIGEST] { let mut p = Vec::with_capacity(1 + DIGEST); p.push(F::from_u64(tag)); p.extend_from_slice(seed); run_sponge(&p).digest };
    let out_rho = dom(0x6f75745f72686f, &rho);
    let out_rcm = dom(0x6f75745f72636d, &rcm);
    let sp = (value, asset, rcm, sk, rho, siblings, leaf_index, value - fee, asset, out_pk, out_rho, out_rcm, fee, chain_id, FullSpendTamper::None);
    Some(prove_reserve_yield_spend_bundle_v2(sp))
}

/// CRY-6 public-nf MULTI-SPEND gate: two DISTINCT coinbase notes are each spent; the daemon nullifier-set
/// accepts BOTH (multi-spend works) and rejects a REPLAY of the first (nf already in set). Also asserts the
/// two nullifiers are distinct and each bundle verifies + its anchor == the daemon cmt-tree root.
pub fn reserve_yield_spend_multispend_selftest() -> bool {
    let mkb = |x: u64| -> Vec<u8> { let mut v = vec![0u8; DIGEST * 4]; v[0..8].copy_from_slice(&x.to_le_bytes()); v };
    let cmt_depth = 4usize;
    let note_cm_of = |sk_b: &[u8], rho_b: &[u8], rcm_b: &[u8], value: u64| -> [F; DIGEST] {
        let sk = ry_bytes_to_digest(sk_b); let rho = ry_bytes_to_digest(rho_b); let rcm = ry_bytes_to_digest(rcm_b);
        let pk_d = own_null_run(sk, rho).pk_d;
        run_sponge(&note_commit_preimage(value, 0, &pk_d, &rho, &rcm)).digest
    };
    // same miner sk; two DIFFERENT coinbase notes (rho/rcm from heights 1 and 2) -> two different nf
    let sk_b = mkb(0xC0FFEE);
    let der = |h: u64| -> (Vec<u8>, Vec<u8>) { let i = h - 1; let mut rho = vec![0u8; DIGEST*4]; let mut rcm = vec![0u8; DIGEST*4]; for j in 0..32 { rho[j] = ((j as u64 + 5 + i) & 0xFF) as u8; rcm[j] = ((j as u64 + 9 + i) & 0xFF) as u8; } (rho, rcm) };
    let (rho1, rcm1) = der(1); let (rho2, rcm2) = der(2);
    let cm1 = note_cm_of(&sk_b, &rho1, &rcm1, 12345);
    let cm2 = note_cm_of(&sk_b, &rho2, &rcm2, 12345);
    let mut cmt_notes = publics_to_bytes(&cm1); cmt_notes.extend_from_slice(&publics_to_bytes(&cm2)); // 2-note tree
    let cmt_root = match ry_note_tree_root_bytes(&cmt_notes, cmt_depth) { Some(r) => r, None => return false };
    let opk = mkb(0xBEEF);
    let b1 = match prove_reserve_yield_coinbase_spend_bundle_v2(&sk_b, &rho1, &rcm1, 12345, 0, &cmt_notes, 0, cmt_depth, &opk, 2345, 7) { Some(b) => b, None => return false };
    let b2 = match prove_reserve_yield_coinbase_spend_bundle_v2(&sk_b, &rho2, &rcm2, 12345, 0, &cmt_notes, 1, cmt_depth, &opk, 2345, 7) { Some(b) => b, None => return false };
    if !verify_reserve_yield_spend_bundle_v2(&b1) || !verify_reserve_yield_spend_bundle_v2(&b2) { return false; }
    // anchors both equal the (shared) cmt-tree root over [cm1, cm2]
    if publics_to_bytes(&b1.batch_pvs[0..DIGEST]) != cmt_root || publics_to_bytes(&b2.batch_pvs[0..DIGEST]) != cmt_root { return false; }
    let nf1 = publics_to_bytes(&b1.batch_pvs[DIGEST+1+4 .. DIGEST+1+4+DIGEST]);
    let nf2 = publics_to_bytes(&b2.batch_pvs[DIGEST+1+4 .. DIGEST+1+4+DIGEST]);
    if nf1 == nf2 { return false; } // distinct notes -> distinct nullifiers
    // daemon nullifier-set: accept-if-new
    let mut set: Vec<Vec<u8>> = Vec::new();
    let mut accept = |nf: &Vec<u8>| -> bool { if set.iter().any(|x| x == nf) { false } else { set.push(nf.clone()); true } };
    if !accept(&nf1) { return false; } // spend 1 accepted
    if !accept(&nf2) { return false; } // spend 2 accepted -> MULTI-SPEND
    if accept(&nf1) { return false; }  // replay of spend 1 REJECTED
    true
}

'''
anchor = "/// CRY-6e: produce a fixed reserve-yield spend bundle's serialized bytes (for the C++ ABI smoke).\npub fn prove_test_reserve_yield_spend_bytes() -> Vec<u8> {"
if s.count(anchor) != 1: print("FATAL anchor x%d" % s.count(anchor)); sys.exit(1)
s = s.replace(anchor, V2 + anchor, 1)
open(f, "w").write(s)
print("circuit.rs: v2 public-nf prove/verify/nf-extract/wallet/multispend added")
