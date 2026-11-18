// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────────────────
// ReserveYieldCoinbaseAir — Confidential Reserve-Yield Coinbase (move-1 reward).
// APPEND to pqpool/src/circuit.rs (same module: reuses F, WIDTH, RATE, DIGEST,
// VALUE_LIMBS, V64_PERMS, NOTE_COMMIT_PERMS, V64_FINAL_BLOCK_LEN, FINAL_BLOCK_LEN,
// DS_V64_CM, DS_NOTE_CM, POSEIDON_HASH_BUS, v64_commit_preimage, note_commit_preimage,
// run_sponge, poseidon2_*, SpendCircuitAir, StarkInstance, ProverData, prove_batch,
// verify_batch, build_config, MyConfig, BatchProof, RowMajorMatrix, AB traits).
//
// DERIVATION (vs TransitionBindAir): identical SUB/MAX/ADD/commitment machinery,
// EXCEPT `bound` (the reward) is NOT a public AIR field — it is a hidden 4th
// committed value `cm_b = H(DS_V64_CM ‖ b[4] ‖ rcmb[4])`. With `k` large the curve
// flatlines: q=(N−x)>>k = 0 < b ⇒ w = max(q,b) = b. So the reward w = b is a FIXED,
// HIDDEN, x-INDEPENDENT value (CE-10 universal interval via 64-bit decomp, CE-11
// decoupled+blinded). Role map: x=S_new, w=r(=b), y=S_old ⇒ S_new+r=S_old i.e.
// S_new=S_old−r (CE-14 conservation). note_cm = the reward note (CE-10 indistinguishable).
// S_new∈[0,N] (SUB top-exact) ⇒ no over-draw. Proof pruned; only cm_y(=cm_S_new of NEXT
// block's cm_x) threads. Must run under the HidingFriPcs ZK config (CE-12) + STARK binding (CE-13).

// width: CMX 64 ‖ CMY 64 ‖ NOTE 128 ‖ CMB 64 ‖ DUMMY 32 ‖ RBITS 64 ‖ SUBCARRY 3 ‖ DIFF 64 ‖ BOR 4 ‖ ADDCARRY 3 = 490
const RY_CMX: usize = 0;
const RY_CMY: usize = V64_PERMS * 2 * WIDTH;            // 64
const RY_NOTE: usize = 2 * V64_PERMS * 2 * WIDTH;       // 128
const RY_CMB: usize = RY_NOTE + NOTE_COMMIT_PERMS * 2 * WIDTH; // 256
const RY_DUMMY: usize = RY_CMB + V64_PERMS * 2 * WIDTH;  // 320  one Poseidon block: bus power-of-two padding
const RY_RBITS: usize = RY_DUMMY + 2 * WIDTH;           // 352
const RY_SUBCARRY: usize = RY_RBITS + 64;               // 416
const RY_DIFF: usize = RY_SUBCARRY + 3;                 // 419
const RY_BOR: usize = RY_DIFF + 64;                     // 483
const RY_ADDCARRY: usize = RY_BOR + 4;                  // 487
const RY_W: usize = RY_ADDCARRY + 3;                    // 490
const RY_PERMS: usize = 3 * V64_PERMS + NOTE_COMMIT_PERMS; // 10 (x,y,b each V64_PERMS=2; note=4)
const RY_TOTAL_PERMS: usize = 16;                       // RY_PERMS padded to a power of two (source-trace requirement)
const RY_PAD: usize = RY_TOTAL_PERMS - RY_PERMS;        // 6 identical dummy permutations (LogUp-balanced)

#[derive(Clone)]
pub struct ReserveYieldCoinbaseAir {
    pub k: usize,        // PUBLIC: large (e.g. 63) so the curve flatlines to the hidden bound
    pub modulus: u64,    // PUBLIC: N (curve domain; does NOT reveal the reward)
}

impl BaseAir<F> for ReserveYieldCoinbaseAir {
    fn width(&self) -> usize { RY_W }
    fn num_public_values(&self) -> usize { 4 * DIGEST } // cm_x ‖ cm_y ‖ note_cm ‖ cm_b
}

impl<AB> Air<AB> for ReserveYieldCoinbaseAir
where
    AB: AirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let cols: Vec<AB::Var> = builder.main().current_slice()[..RY_W].to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let cmx_in = |k: usize, j: usize| cols[RY_CMX + k * (2 * WIDTH) + j];
        let cmx_out = |k: usize, j: usize| cols[RY_CMX + k * (2 * WIDTH) + WIDTH + j];
        let cmy_in = |k: usize, j: usize| cols[RY_CMY + k * (2 * WIDTH) + j];
        let cmy_out = |k: usize, j: usize| cols[RY_CMY + k * (2 * WIDTH) + WIDTH + j];
        let note_in = |k: usize, j: usize| cols[RY_NOTE + k * (2 * WIDTH) + j];
        let note_out = |k: usize, j: usize| cols[RY_NOTE + k * (2 * WIDTH) + WIDTH + j];
        let cmb_in = |k: usize, j: usize| cols[RY_CMB + k * (2 * WIDTH) + j];
        let cmb_out = |k: usize, j: usize| cols[RY_CMB + k * (2 * WIDTH) + WIDTH + j];

        // ---- cm_x = H(DS_V64_CM ‖ x[4] ‖ rcmx[4]), public pis[0..8] ----
        for j in RATE..WIDTH { builder.assert_zero(cmx_in(0, j)); }
        builder.assert_eq(cmx_in(0, 0), AB::Expr::from_u64(DS_V64_CM));
        for k in 1..V64_PERMS { for j in RATE..WIDTH { builder.assert_eq(cmx_in(k, j), cmx_out(k - 1, j)); } }
        for j in V64_FINAL_BLOCK_LEN..RATE { builder.assert_eq(cmx_in(V64_PERMS - 1, j), cmx_out(V64_PERMS - 2, j)); }
        for j in 0..DIGEST { builder.assert_eq(cmx_out(V64_PERMS - 1, j), pis[j]); }
        // ---- cm_y = H(DS_V64_CM ‖ y[4] ‖ rcmy[4]), public pis[8..16] ----
        for j in RATE..WIDTH { builder.assert_zero(cmy_in(0, j)); }
        builder.assert_eq(cmy_in(0, 0), AB::Expr::from_u64(DS_V64_CM));
        for k in 1..V64_PERMS { for j in RATE..WIDTH { builder.assert_eq(cmy_in(k, j), cmy_out(k - 1, j)); } }
        for j in V64_FINAL_BLOCK_LEN..RATE { builder.assert_eq(cmy_in(V64_PERMS - 1, j), cmy_out(V64_PERMS - 2, j)); }
        for j in 0..DIGEST { builder.assert_eq(cmy_out(V64_PERMS - 1, j), pis[DIGEST + j]); }
        // ---- note_cm = H(DS_NOTE_CM ‖ w[4] ‖ asset ‖ pk_d ‖ rho ‖ rcm), public pis[16..24] ----
        for j in RATE..WIDTH { builder.assert_zero(note_in(0, j)); }
        builder.assert_eq(note_in(0, 0), AB::Expr::from_u64(DS_NOTE_CM));
        for k in 1..NOTE_COMMIT_PERMS { for j in RATE..WIDTH { builder.assert_eq(note_in(k, j), note_out(k - 1, j)); } }
        for j in FINAL_BLOCK_LEN..RATE { builder.assert_eq(note_in(NOTE_COMMIT_PERMS - 1, j), note_out(NOTE_COMMIT_PERMS - 2, j)); }
        for j in 0..DIGEST { builder.assert_eq(note_out(NOTE_COMMIT_PERMS - 1, j), pis[2 * DIGEST + j]); }
        // ---- cm_b = H(DS_V64_CM ‖ b[4] ‖ rcmb[4]), public pis[24..32]  (the HIDDEN reward bound) ----
        for j in RATE..WIDTH { builder.assert_zero(cmb_in(0, j)); }
        builder.assert_eq(cmb_in(0, 0), AB::Expr::from_u64(DS_V64_CM));
        for k in 1..V64_PERMS { for j in RATE..WIDTH { builder.assert_eq(cmb_in(k, j), cmb_out(k - 1, j)); } }
        for j in V64_FINAL_BLOCK_LEN..RATE { builder.assert_eq(cmb_in(V64_PERMS - 1, j), cmb_out(V64_PERMS - 2, j)); }
        for j in 0..DIGEST { builder.assert_eq(cmb_out(V64_PERMS - 1, j), pis[3 * DIGEST + j]); }

        // ---- arithmetic over hidden x (cm_x lanes 1..5), y (cm_y), b (cm_b), r=N-x bits ----
        for g in 0..64 { let b = cols[RY_RBITS + g]; builder.assert_zero(b.into() * (b.into() - AB::Expr::ONE)); }
        // SUB: x + r == N  (=> r = N - x, x <= N, x range-bound to [0,N])
        for i in 0..VALUE_LIMBS {
            let mut r_i = AB::Expr::ZERO;
            for j in 0..16 { r_i = r_i + cols[RY_RBITS + i * 16 + j].into() * AB::Expr::from_u64(1u64 << j); }
            let x_i: AB::Expr = cmx_in(0, 1 + i).into();
            let n_i = AB::Expr::from_u64((self.modulus >> (16 * i)) & 0xffff);
            let c_in = if i == 0 { AB::Expr::ZERO } else { cols[RY_SUBCARRY + i - 1].into() };
            if i < VALUE_LIMBS - 1 {
                let c = cols[RY_SUBCARRY + i];
                builder.assert_zero(c.into() * (c.into() - AB::Expr::ONE));
                builder.assert_eq(x_i + r_i + c_in, n_i + c.into() * AB::Expr::from_u64(1u64 << 16));
            } else { builder.assert_eq(x_i + r_i + c_in, n_i); }
        }
        // MAX: borrow-subtraction of internal q=(r>>k) minus b  (b from cm_b lanes — HIDDEN, not public)
        for i in 0..VALUE_LIMBS {
            let mut q_i = AB::Expr::ZERO;
            for j in 0..16 { let g = i * 16 + j + self.k; if g < 64 { q_i = q_i + cols[RY_RBITS + g].into() * AB::Expr::from_u64(1u64 << j); } }
            let mut d_i = AB::Expr::ZERO;
            for j in 0..16 { let b = cols[RY_DIFF + i * 16 + j]; builder.assert_zero(b.into() * (b.into() - AB::Expr::ONE)); d_i = d_i + b.into() * AB::Expr::from_u64(1u64 << j); }
            let bor_i = cols[RY_BOR + i];
            builder.assert_zero(bor_i.into() * (bor_i.into() - AB::Expr::ONE));
            let bound_i: AB::Expr = cmb_in(0, 1 + i).into(); // HIDDEN bound limb i (was public self.bound)
            let bor_in = if i == 0 { AB::Expr::ZERO } else { cols[RY_BOR + i - 1].into() };
            builder.assert_eq(q_i - bound_i - bor_in + bor_i.into() * AB::Expr::from_u64(1u64 << 16), d_i);
        }
        // ADD x + w == y, BIND note value == w, where w_i = q_i + bor_top*(b_i - q_i) = max(q,b) limb i
        let bor_top = cols[RY_BOR + VALUE_LIMBS - 1];
        for i in 0..VALUE_LIMBS {
            let mut q_i = AB::Expr::ZERO;
            for j in 0..16 { let g = i * 16 + j + self.k; if g < 64 { q_i = q_i + cols[RY_RBITS + g].into() * AB::Expr::from_u64(1u64 << j); } }
            let bound_i: AB::Expr = cmb_in(0, 1 + i).into();
            let w_i = q_i.clone() + bor_top.into() * (bound_i - q_i);
            builder.assert_eq(note_in(0, 1 + i), w_i.clone());
            let x_i: AB::Expr = cmx_in(0, 1 + i).into();
            let y_i: AB::Expr = cmy_in(0, 1 + i).into();
            let c_in = if i == 0 { AB::Expr::ZERO } else { cols[RY_ADDCARRY + i - 1].into() };
            if i < VALUE_LIMBS - 1 {
                let c = cols[RY_ADDCARRY + i];
                builder.assert_zero(c.into() * (c.into() - AB::Expr::ONE));
                builder.assert_eq(x_i + w_i + c_in, y_i + c.into() * AB::Expr::from_u64(1u64 << 16));
            } else { builder.assert_eq(x_i + w_i + c_in, y_i); }
        }
        // every real commitment permutation (RY_PERMS=10) must exist in the Poseidon2 table
        for k in 0..RY_PERMS {
            let base = k * (2 * WIDTH);
            let fields: Vec<AB::Var> = cols[base..base + 2 * WIDTH].to_vec();
            builder.push_interaction(POSEIDON_HASH_BUS, fields, AB::Expr::ONE, 1);
        }
        // RY_PAD dummy receives matching the source-trace power-of-two padding (keeps the LogUp bus balanced)
        let dummy: Vec<AB::Var> = cols[RY_DUMMY..RY_DUMMY + 2 * WIDTH].to_vec();
        for _ in 0..RY_PAD {
            builder.push_interaction(POSEIDON_HASH_BUS, dummy.clone(), AB::Expr::ONE, 1);
        }
    }
}

/// Prove the confidential reserve-yield draw: hidden S_old=S_new+r, r=b (the hidden epoch reward, k large),
/// b bound to cm_b, r bound to the output note. honest callers pass note_value=b and y = x + b.
/// Build the (consumer_trace, source_trace, public-cm) for one confidential reserve-yield draw.
/// Config-INDEPENDENT (pure Poseidon trace) — the SAME traces feed both the plain (soundness) and the
/// ZK/hiding (privacy) configs, so the two gates test the identical circuit with zero drift.
// CRY-5: the canonical placeholder note used by the soundness tests + the daemon selftest.
// Production callers (the coinbase producer) pass the MINER's note instead (pk_d from the miner's
// PQ stealth address). Held here as a single source so the test note can't drift.
fn ry_test_note() -> (u32, [F; DIGEST], [F; DIGEST], [F; DIGEST]) {
    let pk_d: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(101 + i as u64));
    let rho: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(201 + i as u64));
    let rcm: [F; DIGEST] = core::array::from_fn(|i| F::from_u64(301 + i as u64));
    (7u32, pk_d, rho, rcm)
}

fn reserve_yield_traces(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],
    note_value: u64, y_override: Option<u64>,
    asset: u32, pk_d: [F; DIGEST], rho: [F; DIGEST], rcm: [F; DIGEST],
) -> (RowMajorMatrix<F>, RowMajorMatrix<F>, Vec<F>) {
    let r = modulus - x;
    let q = r >> k;
    let w = q.max(b);
    let y = y_override.unwrap_or(x + w);
    let preimage_x = v64_commit_preimage(x, &rcmx);
    let preimage_y = v64_commit_preimage(y, &rcmy);
    let preimage_b = v64_commit_preimage(b, &rcmb);
    // CRY-5: note preimage fields (asset, pk_d, rho, rcm) are caller-supplied — the MINER's note
    // (pk_d from the miner's PQ stealth address; rho/rcm per-coinbase randomness; value=note_value=r).
    let preimage_note = note_commit_preimage(note_value, asset, &pk_d, &rho, &rcm);
    let run_x = run_sponge(&preimage_x);
    let run_y = run_sponge(&preimage_y);
    let run_note = run_sponge(&preimage_note);
    let run_b = run_sponge(&preimage_b);
    let mut row: Vec<F> = Vec::with_capacity(RY_W);
    for kk in 0..V64_PERMS { row.extend_from_slice(&run_x.states_in[kk]); row.extend_from_slice(&run_x.states_out[kk]); }
    for kk in 0..V64_PERMS { row.extend_from_slice(&run_y.states_in[kk]); row.extend_from_slice(&run_y.states_out[kk]); }
    for kk in 0..NOTE_COMMIT_PERMS { row.extend_from_slice(&run_note.states_in[kk]); row.extend_from_slice(&run_note.states_out[kk]); }
    for kk in 0..V64_PERMS { row.extend_from_slice(&run_b.states_in[kk]); row.extend_from_slice(&run_b.states_out[kk]); }
    // dummy Poseidon block (input‖perm(input)); the source pads RY_PAD identical copies for power-of-two height
    let dummy_in = [F::ZERO; WIDTH];
    let dummy_out = poseidon2_table_output(dummy_in);
    row.extend_from_slice(&dummy_in); row.extend_from_slice(&dummy_out);
    for g in 0..64 { row.push(F::from_u64((r >> g) & 1)); }
    let mut cp = 0u64;
    for i in 0..3 { let a = (x >> (16 * i)) & 0xffff; let rr = (r >> (16 * i)) & 0xffff; cp = (a + rr + cp) >> 16; row.push(F::from_u64(cp)); }
    let mut bor = 0i64; let mut dl = [0u64; 4]; let mut bs = [0u64; 4];
    for i in 0..4 {
        let qi = ((q >> (16 * i)) & 0xffff) as i64;
        let bi = ((b >> (16 * i)) & 0xffff) as i64;
        let tmp = qi - bi - bor;
        if tmp < 0 { dl[i] = (tmp + 65536) as u64; bs[i] = 1; bor = 1; } else { dl[i] = tmp as u64; bs[i] = 0; bor = 0; }
    }
    for i in 0..4 { for j in 0..16 { row.push(F::from_u64((dl[i] >> j) & 1)); } }
    for i in 0..4 { row.push(F::from_u64(bs[i])); }
    let mut ap = 0u64;
    for i in 0..3 { let a = (x >> (16 * i)) & 0xffff; let m = (w >> (16 * i)) & 0xffff; ap = (a + m + ap) >> 16; row.push(F::from_u64(ap)); }
    let trace = RowMajorMatrix::new(row, RY_W);
    let constants = poseidon2_constants();
    let mut source_inputs = run_x.states_in.clone();
    source_inputs.extend_from_slice(&run_y.states_in);
    source_inputs.extend_from_slice(&run_note.states_in);
    source_inputs.extend_from_slice(&run_b.states_in);
    for _ in 0..RY_PAD { source_inputs.push(dummy_in); } // pad to RY_TOTAL_PERMS=16 (power of two)
    let source_trace = poseidon2_trace(source_inputs, &constants);
    let mut cm = run_x.digest.to_vec();
    cm.extend_from_slice(&run_y.digest);
    cm.extend_from_slice(&run_note.digest);
    cm.extend_from_slice(&run_b.digest);
    (trace, source_trace, cm)
}

/// Prove the confidential reserve-yield draw under the plain (soundness) config → postcard bytes + public cm.
/// (FFI shape; soundness-equivalent to the ZK path which uses the same traces.)
pub fn reserve_yield_prove_bytes(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],
    note_value: u64, y_override: Option<u64>,
) -> (Vec<u8>, Vec<F>) {
    let (trace, source_trace, cm) =
        { let (rya, ryp, ryh, ryc) = ry_test_note(); reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, rya, ryp, ryh, ryc) };
    let source_air = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let config = crate::build_config();
    let instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = vec![
        StarkInstance { air: &source_air, trace: &source_trace, public_values: vec![] },
        StarkInstance { air: &air, trace: &trace, public_values: cm.clone() },
    ];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    (postcard::to_allocvec(&proof).expect("postcard"), cm)
}

/// CE-12 PRIVACY gate: prove + verify the SAME draw under the HIDING / statistical-ZK config
/// (`crate::build_zk_config` → `HidingFriPcs`, `is_zk=1`). The witness (reward r, surplus S, blindings)
/// is masked + per-fold-randomized so the proof reveals nothing beyond the public commitments. In-memory
/// (no postcard) — the FIRST batch+ZK integration; mirrors `pqpool_zk_selftest`'s prove/verify shape.
/// Returns whether prove→verify round-trips (honest) / is rejected (adversarial).
pub fn reserve_yield_prove_verify_zk(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],
    note_value: u64, y_override: Option<u64>,
) -> bool {
    let (trace, source_trace, cm) =
        { let (rya, ryp, ryh, ryc) = ry_test_note(); reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, rya, ryp, ryh, ryc) };
    let source_air = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let config = crate::build_zk_config_lfp0(); // HidingFriPcs, is_zk=1, log_final_poly_len=0 (tiny-trace-friendly)
    let instances: Vec<StarkInstance<'_, crate::ZkConfig, SpendCircuitAir>> = vec![
        StarkInstance { air: &source_air, trace: &source_trace, public_values: vec![] },
        StarkInstance { air: &air, trace: &trace, public_values: cm.clone() },
    ];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    // fresh airs for verify (the instances above still borrow source_air/air)
    let v_source = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let v_air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let airs = vec![v_source, v_air];
    let pvs = vec![vec![], cm];
    verify_batch(&config, &airs, &proof, &pvs, &prover_data.common).is_ok()
}

pub fn reserve_yield_verify_bytes(proof_bytes: &[u8], publics: &[F], k: usize, modulus: u64) -> bool {
    if publics.len() != 4 * DIGEST { return false; }
    let proof: BatchProof<crate::MyConfig> = match postcard::from_bytes(proof_bytes) { Ok(p) => p, Err(_) => return false };
    let config = crate::build_config();
    let source_air = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let airs = vec![source_air, air];
    let dummy_source = poseidon2_trace(vec![[F::ZERO; WIDTH]; RY_TOTAL_PERMS], &poseidon2_constants());
    let dummy_consumer = RowMajorMatrix::new(vec![F::ZERO; RY_W], RY_W);
    let dummy_instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = vec![
        StarkInstance { air: &airs[0], trace: &dummy_source, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &dummy_consumer, public_values: publics.to_vec() },
    ];
    let prover_data = ProverData::from_instances(&config, &dummy_instances);
    let pvs = vec![vec![], publics.to_vec()];
    verify_batch(&config, &airs, &proof, &pvs, &prover_data.common).is_ok()
}

/// PRODUCTION shape: prove under the HIDING/ZK config (`build_zk_config_lfp0`, HidingFriPcs) → postcard bytes
/// + public cm. This is what the daemon/FFI ships on-chain — witness-hidden AND byte-serializable.
pub fn reserve_yield_prove_zk_bytes(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx: [F; VALUE_LIMBS], rcmy: [F; VALUE_LIMBS], rcmb: [F; VALUE_LIMBS],
    note_value: u64, y_override: Option<u64>,
) -> (Vec<u8>, Vec<F>) {
    let (trace, source_trace, cm) =
        { let (rya, ryp, ryh, ryc) = ry_test_note(); reserve_yield_traces(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override, rya, ryp, ryh, ryc) };
    let source_air = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let config = crate::build_zk_config_lfp0();
    let instances: Vec<StarkInstance<'_, crate::ZkConfig, SpendCircuitAir>> = vec![
        StarkInstance { air: &source_air, trace: &source_trace, public_values: vec![] },
        StarkInstance { air: &air, trace: &trace, public_values: cm.clone() },
    ];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    (postcard::to_allocvec(&proof).expect("postcard zk"), cm)
}

/// Verify a hiding/ZK reserve-yield proof from bytes (mirrors `reserve_yield_verify_bytes` over `ZkConfig`).
pub fn reserve_yield_verify_zk_bytes(proof_bytes: &[u8], publics: &[F], k: usize, modulus: u64) -> bool {
    if publics.len() != 4 * DIGEST { return false; }
    let proof: BatchProof<crate::ZkConfig> = match postcard::from_bytes(proof_bytes) { Ok(p) => p, Err(_) => return false };
    let config = crate::build_zk_config_lfp0();
    let source_air = SpendCircuitAir::Poseidon2Source(Poseidon2SourceAir(P2Air::new(poseidon2_constants())));
    let air = SpendCircuitAir::ReserveYieldCoinbase(ReserveYieldCoinbaseAir { k, modulus });
    let airs = vec![source_air, air];
    let dummy_source = poseidon2_trace(vec![[F::ZERO; WIDTH]; RY_TOTAL_PERMS], &poseidon2_constants());
    let dummy_consumer = RowMajorMatrix::new(vec![F::ZERO; RY_W], RY_W);
    let dummy_instances: Vec<StarkInstance<'_, crate::ZkConfig, SpendCircuitAir>> = vec![
        StarkInstance { air: &airs[0], trace: &dummy_source, public_values: vec![] },
        StarkInstance { air: &airs[1], trace: &dummy_consumer, public_values: publics.to_vec() },
    ];
    let prover_data = ProverData::from_instances(&config, &dummy_instances);
    let pvs = vec![vec![], publics.to_vec()];
    verify_batch(&config, &airs, &proof, &pvs, &prover_data.common).is_ok()
}

/// FFI marshaling (miner side): blinding bytes (3 × `VALUE_LIMBS*4`=16, 4-byte-LE u32 limbs) → ZK prove →
/// (postcard proof bytes, publics bytes = 4*DIGEST × 4-byte-LE = 128). Mirrors `transition_bind_prove_raw`.
pub fn reserve_yield_prove_zk_raw(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx_bytes: &[u8], rcmy_bytes: &[u8], rcmb_bytes: &[u8],
    note_value: u64,
) -> Option<(Vec<u8>, Vec<u8>)> {
    if rcmx_bytes.len() != VALUE_LIMBS * 4
        || rcmy_bytes.len() != VALUE_LIMBS * 4
        || rcmb_bytes.len() != VALUE_LIMBS * 4
    {
        return None;
    }
    let to_rcm = |bb: &[u8]| -> [F; VALUE_LIMBS] {
        let mut a = [F::ZERO; VALUE_LIMBS];
        for i in 0..VALUE_LIMBS {
            let o = i * 4;
            a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o + 1], bb[o + 2], bb[o + 3]]) as u64);
        }
        a
    };
    let (proof, publics) = reserve_yield_prove_zk_bytes(
        k, modulus, b, x, to_rcm(rcmx_bytes), to_rcm(rcmy_bytes), to_rcm(rcmb_bytes), note_value, None);
    Some((proof, publics_to_bytes(&publics)))
}

/// FFI marshaling (verifier side): verify a ZK reserve-yield proof from raw bytes (publics = 4*DIGEST*4 = 128).
pub fn reserve_yield_verify_zk_raw(proof_bytes: &[u8], publics_bytes: &[u8], k: usize, modulus: u64) -> bool {
    if publics_bytes.len() != 4 * DIGEST * 4 {
        return false;
    }
    let publics: Vec<F> = publics_bytes
        .chunks_exact(4)
        .map(|c| F::from_u64(u32::from_le_bytes([c[0], c[1], c[2], c[3]]) as u64))
        .collect();
    reserve_yield_verify_zk_bytes(proof_bytes, &publics, k, modulus)
}

/// FFI startup health check: prove + verify an honest ZK reserve-yield draw (fixed blindings) → bool.
pub fn reserve_yield_zk_selftest(k: usize, modulus: u64, b: u64, x: u64) -> bool {
    let rcmx: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 1);
    let rcmy: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 17);
    let rcmb: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 33);
    let w = ((modulus - x) >> k).max(b); // honest reward = note value
    match reserve_yield_prove_zk_raw(k, modulus, b, x, &rcmx, &rcmy, &rcmb, w) {
        Some((proof, publics)) => reserve_yield_verify_zk_raw(&proof, &publics, k, modulus),
        None => false,
    }
}

#[cfg(test)]
mod reserve_yield_tests {
    use super::*;
    fn run(k: usize, modulus: u64, b: u64, x: u64, note_value: u64, y_override: Option<u64>) -> bool {
        let rcmx = [F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let rcmy = [F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        let rcmb = [F::from_u64(9), F::from_u64(10), F::from_u64(11), F::from_u64(12)];
        let (proof, pubs) = reserve_yield_prove_bytes(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override);
        reserve_yield_verify_bytes(&proof, &pubs, k, modulus)
    }
    #[test]
    fn reserve_yield_sound() {
        let k = 63usize;                          // curve flatlines: q=(N-x)>>63 = 0 < b ⇒ w=b (fixed reward)
        let modulus = 0x0001_0000_0000_0000u64;   // N < 2^63 neutral placeholder
        let b = 12345u64;                          // hidden fixed reward (neutral placeholder)
        // HONEST: two different surpluses x ⇒ SAME reward w=b (decoupled), conservation holds
        let x1 = 0x0000_5000_3000_1000u64;
        assert!(run(k, modulus, b, x1, b, Some(x1 + b)), "honest draw #1 verifies (w=b, y=x+b)");
        let x2 = 0x0000_2000_2000_2000u64;
        assert!(run(k, modulus, b, x2, b, Some(x2 + b)), "honest draw #2 (different surplus) verifies — r decoupled from x");
        // ADVERSARIAL: over-reward (note_value=b+1 but bound commits to b) ⇒ note-binding fails ⇒ REJECT
        assert!(!run(k, modulus, b, x1, b + 1, Some(x1 + b + 1)), "over-reward (note≠b) MUST reject");
        // ADVERSARIAL: wrong y (claim S_old too large) ⇒ ADD fails ⇒ REJECT
        assert!(!run(k, modulus, b, x1, b, Some(x1 + b + 1)), "inflated y (S_old) MUST reject");
        eprintln!("RESERVE_YIELD_OK: fixed hidden reward, decoupled, conservation + adversarial gate pass");
    }
    fn run_zk(k: usize, modulus: u64, b: u64, x: u64, note_value: u64, y_override: Option<u64>) -> bool {
        let rcmx = [F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let rcmy = [F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        let rcmb = [F::from_u64(9), F::from_u64(10), F::from_u64(11), F::from_u64(12)];
        reserve_yield_prove_verify_zk(k, modulus, b, x, rcmx, rcmy, rcmb, note_value, y_override)
    }
    #[test]
    fn reserve_yield_zk_sound() {
        // CE-12 PRIVACY: the IDENTICAL circuit + traces, now proven under the HIDING (statistical-ZK)
        // config (HidingFriPcs, is_zk=1) — witness (reward r, surplus S) masked. Same four assertions.
        let k = 63usize;
        let modulus = 0x0001_0000_0000_0000u64;
        let b = 12345u64;
        let x1 = 0x0000_5000_3000_1000u64;
        let x2 = 0x0000_2000_2000_2000u64;
        assert!(run_zk(k, modulus, b, x1, b, Some(x1 + b)), "ZK honest draw #1 verifies (witness hidden)");
        assert!(run_zk(k, modulus, b, x2, b, Some(x2 + b)), "ZK honest draw #2 (different surplus) verifies");
        assert!(!run_zk(k, modulus, b, x1, b + 1, Some(x1 + b + 1)), "ZK over-reward MUST reject");
        assert!(!run_zk(k, modulus, b, x1, b, Some(x1 + b + 1)), "ZK inflated y MUST reject");
        eprintln!("RESERVE_YIELD_ZK_OK: HidingFriPcs batch prove/verify — witness-hiding + adversarial gate pass");
    }
    #[test]
    fn reserve_yield_zk_bytes_sound() {
        // On-chain prerequisite: the HIDING proof must postcard-SERIALIZE and roundtrip-verify from bytes.
        let k = 63usize;
        let modulus = 0x0001_0000_0000_0000u64;
        let b = 12345u64;
        let rcmx = [F::from_u64(1), F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let rcmy = [F::from_u64(5), F::from_u64(6), F::from_u64(7), F::from_u64(8)];
        let rcmb = [F::from_u64(9), F::from_u64(10), F::from_u64(11), F::from_u64(12)];
        let x1 = 0x0000_5000_3000_1000u64;
        let (proof, pubs) = reserve_yield_prove_zk_bytes(k, modulus, b, x1, rcmx, rcmy, rcmb, b, Some(x1 + b));
        assert!(!proof.is_empty(), "zk proof serialized to bytes");
        assert!(reserve_yield_verify_zk_bytes(&proof, &pubs, k, modulus), "zk bytes roundtrip verifies");
        let mut bad = pubs.clone();
        bad[0] = bad[0] + F::from_u64(1);
        assert!(!reserve_yield_verify_zk_bytes(&proof, &bad, k, modulus), "tampered publics MUST reject");
        eprintln!("RESERVE_YIELD_ZK_BYTES_OK: zk proof postcard-serializes ({} bytes) + roundtrip + tamper-reject", proof.len());
    }
    #[test]
    fn reserve_yield_zk_raw_sound() {
        // FFI marshaling layer: byte-blindings -> ZK prove -> byte-publics -> verify, + adversarial reject.
        let k = 63usize;
        let modulus = 0x0001_0000_0000_0000u64;
        let b = 12345u64;
        let x1 = 0x0000_5000_3000_1000u64;
        assert!(reserve_yield_zk_selftest(k, modulus, b, x1), "zk raw selftest roundtrips");
        let rcmx: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 1);
        let rcmy: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 17);
        let rcmb: [u8; VALUE_LIMBS * 4] = core::array::from_fn(|i| (i as u8) + 33);
        let (proof, pubs) =
            reserve_yield_prove_zk_raw(k, modulus, b, x1, &rcmx, &rcmy, &rcmb, b + 1).unwrap();
        assert_eq!(pubs.len(), 4 * DIGEST * 4, "publics marshaled to 128 bytes");
        assert!(!reserve_yield_verify_zk_raw(&proof, &pubs, k, modulus), "raw over-reward MUST reject");
        eprintln!("RESERVE_YIELD_ZK_RAW_OK: FFI-marshaled prove/verify + 128B publics + adversarial reject");
    }
}
