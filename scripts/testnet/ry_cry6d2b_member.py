# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

if "pub struct ImtLeafMembershipAir" not in s:
    anc = "// CRY-6d-2a: in-circuit 256-bit comparison."
    if s.count(anc) != 1: print("FATAL member anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-2b-i: IMT low-leaf membership. Proves an indexed-Merkle-tree leaf L={value, next_index,
// next_value} (its hash imt_leaf_hash(L)) is a member of the tree at `anchor`, with value/next_index/
// next_value bound to the leaf preimage AND exposed as public values so the gap-comparison (6d-2b-ii)
// can consume them. Adapts CommitMembershipAir: 3 C1 sponge perms (18-element preimage, DS_NF_IMT_LEAF)
// + C2 Merkle membership (identical). Preimage lanes: perm0=[DS,v0..v6], perm1=[v7,nidx,nv0..nv5],
// perm2=[nv6,nv7,carry..]. Every permutation is delegated to the shared Poseidon table.
#[derive(Clone)]
pub struct ImtLeafMembershipAir {
    pub depth: usize,
}

const IMT_PERMS: usize = 3;                                   // ceil(18/RATE) for the 18-element leaf preimage
const IMT_C2_OFF: usize = IMT_PERMS * 2 * WIDTH;             // C2 starts after 3 C1 perms

impl BaseAir<F> for ImtLeafMembershipAir {
    fn width(&self) -> usize { IMT_C2_OFF + self.depth * MERKLE_LEVEL_W }
    fn num_public_values(&self) -> usize { DIGEST + DIGEST + 1 + DIGEST }   // anchor || value || next_idx || next_value
}

impl<AB> Air<AB> for ImtLeafMembershipAir
where
    AB: AirBuilder<F = F> + InteractionBuilder,
{
    fn eval(&self, builder: &mut AB) {
        let w = IMT_C2_OFF + self.depth * MERKLE_LEVEL_W;
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
        // public accessors
        let p_val = |j: usize| pis[DIGEST + j];                 // value[0..8]
        let p_nidx = pis[2 * DIGEST];                          // next_index
        let p_nv = |j: usize| pis[2 * DIGEST + 1 + j];          // next_value[0..8]

        // ── C1: imt_leaf_hash sponge (3 perms), domain DS_NF_IMT_LEAF, data bound to publics. ──
        builder.assert_eq(c1_in(0, 0), AB::Expr::from_u64(DS_NF_IMT_LEAF));
        for j in 0..7 { builder.assert_eq(c1_in(0, 1 + j), p_val(j)); }      // value[0..7]
        for j in RATE..WIDTH { builder.assert_zero(c1_in(0, j)); }           // capacity starts 0
        builder.assert_eq(c1_in(1, 0), p_val(7));                           // value[7]
        builder.assert_eq(c1_in(1, 1), p_nidx);                            // next_index
        for j in 0..6 { builder.assert_eq(c1_in(1, 2 + j), p_nv(j)); }       // next_value[0..6]
        for j in RATE..WIDTH { builder.assert_eq(c1_in(1, j), c1_out(0, j)); } // capacity chain
        builder.assert_eq(c1_in(2, 0), p_nv(6));                           // next_value[6]
        builder.assert_eq(c1_in(2, 1), p_nv(7));                           // next_value[7]
        for j in 2..WIDTH { builder.assert_eq(c1_in(2, j), c1_out(1, j)); }   // final-block carry + capacity
        // leaf = c1_out(IMT_PERMS-1, 0..8)

        // ── C2: Merkle membership (identical to CommitMembershipAir). ──
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
            if k > 0 {
                for j in 0..DIGEST { builder.assert_eq(cur(k, j), m_out(k - 1, 2, j)); }
            }
        }
        // LINK: C2 leaf (cur_0) == C1 leaf digest.
        for j in 0..DIGEST { builder.assert_eq(cur(0, j), c1_out(IMT_PERMS - 1, j)); }
        // anchor == final-level digest.
        for j in 0..DIGEST { builder.assert_eq(m_out(self.depth - 1, 2, j), pis[j]); }
        // delegate every permutation to the shared Poseidon table.
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

/// Build + prove + verify IMT leaf membership. tamper=true uses a witness value != the public value, so
/// both the C1 data-binding and the Merkle path fail. Returns true iff the honest membership verifies.
pub fn prove_verify_imt_membership(value: [F; DIGEST], next_index: u64, next_value: [F; DIGEST], siblings: Vec<[F; DIGEST]>, index: usize, tamper: bool) -> bool {
    let depth = siblings.len();
    let preimage = |v: &[F; DIGEST]| -> Vec<F> {
        let mut p = Vec::with_capacity(18);
        p.push(F::from_u64(DS_NF_IMT_LEAF)); p.extend_from_slice(v); p.push(F::from_u64(next_index)); p.extend_from_slice(&next_value); p
    };
    let leaf = run_sponge(&preimage(&value)).digest;
    let honest_anchor = merkle_path_run(leaf, &siblings, index).root;
    let mut eff = value; if tamper { eff[0] += F::ONE; }
    let c1 = run_sponge(&preimage(&eff));
    let merkle = merkle_path_run(c1.digest, &siblings, index);

    let mut row: Vec<F> = Vec::with_capacity(IMT_C2_OFF + depth * MERKLE_LEVEL_W);
    for p in 0..IMT_PERMS { row.extend_from_slice(&c1.states_in[p]); row.extend_from_slice(&c1.states_out[p]); }
    for lvl in &merkle.levels {
        row.extend_from_slice(&lvl.cur); row.extend_from_slice(&lvl.sib); row.push(lvl.bit);
        for p in 0..3 { row.extend_from_slice(&lvl.perms_in[p]); row.extend_from_slice(&lvl.perms_out[p]); }
    }
    let trace = RowMajorMatrix::new(row, IMT_C2_OFF + depth * MERKLE_LEVEL_W);
    let mut perm_inputs = c1.states_in.clone(); perm_inputs.extend_from_slice(&merkle.perm_inputs);
    let constants = poseidon2_constants();
    let (source_airs, source_traces) = build_source_chunks(&perm_inputs, &constants);
    let consumer = SpendCircuitAir::ImtLeafMembership(ImtLeafMembershipAir { depth });
    let config = crate::build_config();
    let mut pvs: Vec<F> = honest_anchor.to_vec();
    pvs.extend_from_slice(&value); pvs.push(F::from_u64(next_index)); pvs.extend_from_slice(&next_value);
    let mut instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> = Vec::new();
    for (a, t) in source_airs.iter().zip(source_traces.iter()) { instances.push(StarkInstance { air: a, trace: t, public_values: vec![] }); }
    instances.push(StarkInstance { air: &consumer, trace: &trace, public_values: pvs.clone() });
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    let mut airs: Vec<SpendCircuitAir> = source_airs.clone(); airs.push(consumer.clone());
    let mut allpvs: Vec<Vec<F>> = vec![vec![]; source_airs.len()]; allpvs.push(pvs);
    verify_batch(&config, &airs, &proof, &allpvs, &prover_data.common).is_ok()
}

/// CRY-6d-2b-i gate: an honest IMT leaf member verifies; a tampered leaf is rejected.
pub fn imt_membership_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    let sibs = vec![mk(2), mk(3), mk(4), mk(5)];
    if !prove_verify_imt_membership(mk(42), 3, mk(99), sibs.clone(), 5, false) { return false; }
    if prove_verify_imt_membership(mk(42), 3, mk(99), sibs, 5, true) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("ImtLeafMembershipAir added")
else: print("ImtLeafMembershipAir present; skip")

# enum + 3 dispatch arms (mirror CommitMembership).
ev = "    CommitMembership(CommitMembershipAir),\n"
if "    ImtLeafMembership(ImtLeafMembershipAir),\n" not in s:
    if s.count(ev) < 1: print("FATAL enum anchor"); sys.exit(1)
    s = s.replace(ev, ev + "    ImtLeafMembership(ImtLeafMembershipAir),\n", 1)
    for a0, a1 in [
        ("            Self::CommitMembership(a) => <CommitMembershipAir as BaseAir<F>>::width(a),\n",
         "            Self::ImtLeafMembership(a) => <ImtLeafMembershipAir as BaseAir<F>>::width(a),\n"),
        ("            Self::CommitMembership(a) => <CommitMembershipAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::ImtLeafMembership(a) => <ImtLeafMembershipAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::CommitMembership(a) => a.eval(builder),\n",
         "            Self::ImtLeafMembership(a) => a.eval(builder),\n"),
    ]:
        if s.count(a0) != 1: print("FATAL dispatch:", a0.strip()); sys.exit(1)
        s = s.replace(a0, a0 + a1, 1)
    print("enum + dispatch added")
else: print("enum present; skip")
open(c, "w").write(s)

# FFI selftest + header.
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_imt_membership_selftest" not in fs:
    fs = fs.replace("    compare_selftest,", "    compare_selftest, imt_membership_selftest,", 1)
    anc2 = '#[no_mangle]\npub extern "C" fn pqpool_compare_selftest() -> i32 {'
    fs = fs.replace(anc2, '#[no_mangle]\npub extern "C" fn pqpool_imt_membership_selftest() -> i32 { if imt_membership_selftest() { 1 } else { 0 } }\n\n' + anc2, 1)
    open(f, "w").write(fs); print("ffi member added")
else: print("ffi member present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_imt_membership_selftest" not in hs:
    open(h, "w").write(hs.replace("int32_t pqpool_compare_selftest(void);", "int32_t pqpool_compare_selftest(void);\nint32_t pqpool_imt_membership_selftest(void);", 1)); print("ffi.h member added")
else: print("ffi.h member present; skip")
print("DONE")
