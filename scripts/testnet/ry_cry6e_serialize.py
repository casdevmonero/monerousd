# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct ReserveYieldSpendBundle" not in s:
    anc = "/// CRY-6d-3b gate: an honest reserve-yield spend"
    if s.count(anc) != 1: print("FATAL anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6e: serializable reserve-yield spend bundle + verify-from-bytes (the daemon's consensus bridge).
// Carries the proof + the two public-value vectors + the structural depths needed to reconstruct the air
// list for verification (mirrors SettlementProofBundle). nf is NOT carried (it is private/witness).
pub struct ReserveYieldSpendBundle {
    pub proof_bytes: Vec<u8>,
    pub batch_pvs: Vec<F>,   // SpendBatchAir publics: cmt_anchor || chain || commitment(4)
    pub imt_pvs: Vec<F>,     // ImtInsertAir publics: ns_root_old || ns_root_new
    pub spend_depth: usize,  // cmt-tree (spend membership) depth
    pub imt_depth: usize,    // IMT nullifier-set depth
}

impl ReserveYieldSpendBundle {
    pub fn serialize_bundle(&self) -> Vec<u8> {
        use p3_field::PrimeField32;
        let mut out = Vec::new();
        out.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.proof_bytes);
        let put = |out: &mut Vec<u8>, v: &[F]| { out.extend_from_slice(&(v.len() as u32).to_le_bytes()); for f in v { out.extend_from_slice(&f.as_canonical_u32().to_le_bytes()); } };
        put(&mut out, &self.batch_pvs);
        put(&mut out, &self.imt_pvs);
        out.extend_from_slice(&(self.spend_depth as u64).to_le_bytes());
        out.extend_from_slice(&(self.imt_depth as u64).to_le_bytes());
        out
    }
    pub fn deserialize_bundle(bytes: &[u8]) -> Result<Self, &'static str> {
        use p3_field::PrimeCharacteristicRing;
        let mut pos = 0usize;
        let need = |pos: usize, n: usize| -> Result<(), &'static str> { if bytes.len() < pos + n { Err("ry bundle truncated") } else { Ok(()) } };
        need(pos, 4)?; let pl = u32::from_le_bytes(bytes[pos..pos+4].try_into().unwrap()) as usize; pos += 4;
        need(pos, pl)?; let proof_bytes = bytes[pos..pos+pl].to_vec(); pos += pl;
        let mut get_vec = |pos: &mut usize| -> Result<Vec<F>, &'static str> {
            need(*pos, 4)?; let l = u32::from_le_bytes(bytes[*pos..*pos+4].try_into().unwrap()) as usize; *pos += 4;
            need(*pos, l*4)?; let mut v = Vec::with_capacity(l);
            for _ in 0..l { let x = u32::from_le_bytes(bytes[*pos..*pos+4].try_into().unwrap()); v.push(F::from_u64(x as u64)); *pos += 4; }
            Ok(v)
        };
        let batch_pvs = get_vec(&mut pos)?;
        let imt_pvs = get_vec(&mut pos)?;
        need(pos, 16)?;
        let spend_depth = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) as usize; pos += 8;
        let imt_depth = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()) as usize;
        Ok(ReserveYieldSpendBundle { proof_bytes, batch_pvs, imt_pvs, spend_depth, imt_depth })
    }
}

/// CRY-6e: PROVE a reserve-yield spend and return the serializable bundle (proof + publics + depths).
#[allow(clippy::too_many_arguments)]
pub fn prove_reserve_yield_spend_bundle(
    spend: (u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], Vec<[F; DIGEST]>, usize, u64, u32, [F; DIGEST], [F; DIGEST], [F; DIGEST], u64, u64, FullSpendTamper),
    depth: usize,
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
    let batch_air = SpendCircuitAir::SpendBatch(SpendBatchAir { spend: sa.clone(), emit_leaf_buses: true });
    let final_state = native_perm_24_output(state_in);
    let commitment = [final_state[RATE24-1], final_state[RATE24-2], final_state[RATE24-3], final_state[RATE24-4]];
    let mut batch_pvs = anchor.clone(); batch_pvs.push(chain); batch_pvs.extend_from_slice(&commitment);
    let chal_source_trace = poseidon2_trace_24(vec![state_in], &poseidon2_constants_24());
    let chal_source_air = SpendCircuitAir::Poseidon2Source24(Poseidon2Source24Air(P2Air24::new(poseidon2_constants_24())));
    let (imt_trace, imt_src_airs, imt_src_traces, root_old, root_new) = build_imt_insert_artifacts_for_nf(nf, depth);
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
    let proof_bytes = postcard::to_allocvec(&proof).expect("serialize ry spend proof");
    ReserveYieldSpendBundle { proof_bytes, batch_pvs, imt_pvs, spend_depth, imt_depth: depth }
}

/// CRY-6e: VERIFY a reserve-yield spend bundle from its parts — reconstructs the air list (dummy traces,
/// real dimensions) from the depths and re-runs verify_batch. This is what the daemon calls per spend tx.
pub fn verify_reserve_yield_spend_bundle(b: &ReserveYieldSpendBundle) -> bool {
    if b.batch_pvs.len() != DIGEST + 1 + 4 || b.imt_pvs.len() != 2 * DIGEST { return false; }
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
    airs.push(SpendCircuitAir::SpendBatch(SpendBatchAir { spend: sa, emit_leaf_buses: true }));
    traces.push(RowMajorMatrix::new(vec![F::ZERO; row_w], row_w)); pvs.push(b.batch_pvs.clone());
    let (imt_trace, imt_src_airs, imt_src_traces, _ro, _rn) = build_imt_insert_artifacts_for_nf(dz, b.imt_depth);
    for (a, t) in imt_src_airs.iter().zip(imt_src_traces.iter()) { airs.push(a.clone()); traces.push(RowMajorMatrix::new(vec![F::ZERO; t.values.len()], t.width)); pvs.push(vec![]); }
    airs.push(SpendCircuitAir::ImtInsert(ImtInsertAir { depth: b.imt_depth, nf_from_bus: true }));
    traces.push(RowMajorMatrix::new(vec![F::ZERO; imt_trace.values.len()], imt_trace.width)); pvs.push(b.imt_pvs.clone());
    airs.push(SpendCircuitAir::CmtSink(CmtSinkAir));
    traces.push(RowMajorMatrix::new(vec![F::ZERO; DIGEST], DIGEST)); pvs.push(vec![]);
    let instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = airs.iter().zip(traces.iter()).zip(pvs.iter()).map(|((a, t), p)| StarkInstance { air: a, trace: t, public_values: p.clone() }).collect();
    let pd = ProverData::from_instances(&config, &instances);
    verify_batch(&config, &airs, &proof, &pvs, &pd.common).is_ok()
}

/// CRY-6e round-trip gate: prove -> serialize -> deserialize -> verify-from-bytes (the daemon path).
pub fn reserve_yield_spend_bundle_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sp = (1_000_000u64, 5u32, mk(6), mk(7), mk(8), vec![mk(2), mk(3), mk(4), mk(5)], 0b1010usize, 999_000u64, 5u32, mk(9), mk(10), mk(11), 1000u64, 42u64, FullSpendTamper::None);
    let bundle = prove_reserve_yield_spend_bundle(sp, 4);
    let bytes = bundle.serialize_bundle();
    let b2 = match ReserveYieldSpendBundle::deserialize_bundle(&bytes) { Ok(b) => b, Err(_) => return false };
    if !verify_reserve_yield_spend_bundle(&b2) { return false; }
    // tamper: flip a root byte -> reject.
    let mut b3 = ReserveYieldSpendBundle::deserialize_bundle(&bytes).unwrap();
    b3.imt_pvs[DIGEST] += F::ONE;
    if verify_reserve_yield_spend_bundle(&b3) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("ReserveYieldSpendBundle serialize+verify added")
else: print("present; skip")
open(c, "w").write(s)

# FFI: daemon verify + round-trip selftest
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_reserve_yield_spend_verify" not in fs:
    fs = fs.replace("    reserve_yield_spend_compose_selftest,", "    reserve_yield_spend_compose_selftest, reserve_yield_spend_bundle_selftest, ReserveYieldSpendBundle,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_reserve_yield_spend_compose_selftest() -> i32 {'
    fn2 = '''#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_bundle_selftest() -> i32 { if reserve_yield_spend_bundle_selftest() { 1 } else { 0 } }

/// CRY-6e: the DAEMON's verify — deserialize a reserve-yield spend bundle and verify it. 1=valid, 0=invalid/malformed.
#[no_mangle]
pub extern "C" fn pqpool_reserve_yield_spend_verify(bundle: *const u8, bundle_len: usize) -> i32 {
    if bundle.is_null() { return -1; }
    let s = unsafe { core::slice::from_raw_parts(bundle, bundle_len) };
    match ReserveYieldSpendBundle::deserialize_bundle(s) {
        Ok(b) => if verify_reserve_yield_spend_bundle(&b) { 1 } else { 0 },
        Err(_) => 0,
    }
}

'''
    fs = fs.replace(anc2, fn2 + anc2, 1); open(f, "w").write(fs); print("ffi verify+selftest added")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_reserve_yield_spend_verify" not in hs:
    add = ("int32_t pqpool_reserve_yield_spend_bundle_selftest(void);\n"
           "int32_t pqpool_reserve_yield_spend_verify(const uint8_t* bundle, size_t bundle_len);\n")
    open(h, "w").write(hs.replace("int32_t pqpool_reserve_yield_spend_compose_selftest(void);", "int32_t pqpool_reserve_yield_spend_compose_selftest(void);\n" + add, 1)); print("ffi.h added")
print("DONE")
