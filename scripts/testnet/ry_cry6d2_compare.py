# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
base = "/root/MoneroUSD-clean/monero/"
c = base + "external/Plonky3/pqpool/src/circuit.rs"; s = open(c).read()

# 1) Align IMT value_lt to the SAME integer order the circuit uses: value = Σ elem[e]·(2^32)^e,
#    element 0 least significant (so element 7 is the MSB). Compare from the MSB down.
old_lt = "    fn value_lt(a: &[F; DIGEST], b: &[F; DIGEST]) -> bool { publics_to_bytes(a) < publics_to_bytes(b) }"
new_lt = '''    fn value_lt(a: &[F; DIGEST], b: &[F; DIGEST]) -> bool {
        // Shared order with CompareAir: value = sum_e elem[e]*(2^32)^e (elem 0 = least significant),
        // each elem the canonical u32. Compare from the most-significant element (7) down.
        let ab = publics_to_bytes(a); let bb = publics_to_bytes(b);
        for e in (0..DIGEST).rev() {
            let av = u32::from_le_bytes([ab[4*e], ab[4*e+1], ab[4*e+2], ab[4*e+3]]);
            let bv = u32::from_le_bytes([bb[4*e], bb[4*e+1], bb[4*e+2], bb[4*e+3]]);
            if av != bv { return av < bv; }
        }
        false
    }'''
if old_lt in s:
    s = s.replace(old_lt, new_lt, 1); print("value_lt aligned")
elif "Shared order with CompareAir" in s: print("value_lt already aligned; skip")
else: print("FATAL value_lt anchor"); sys.exit(1)

# 2) CompareAir + prove_verify_compare + compare_selftest, inserted before imt_nullifier_selftest.
if "pub struct CompareAir" not in s:
    anc = "/// CRY-6d gate: the IMT nullifier set has correct sorted-set"
    if s.count(anc) != 1: print("FATAL compare anchor x%d" % s.count(anc)); sys.exit(1)
    fn = '''// CRY-6d-2a: in-circuit 256-bit comparison. Proves a < b for a,b in [F;DIGEST] as  b - a - 1 >= 0
// (a range proof: if a >= b the borrow underflows and the final-borrow==0 constraint is unsatisfiable,
// so no proof exists). Each of the 8 DIGEST field-elements is split into 2x16-bit sub-limbs so the
// borrow weight 2^16 << p (BabyBear) and never wraps the field (the value-wrap hole BalanceAir warns
// of). Sub-limb order matches value_lt: sub-limb 0 = element 0 low half (least significant).
#[derive(Clone)]
pub struct CompareAir;

const CMP_SUBLIMBS: usize = 2 * DIGEST;                       // 16 sub-limbs (2 per digest element)
const CMP_A_SUB: usize = 0;
const CMP_A_BITS: usize = CMP_A_SUB + CMP_SUBLIMBS;           // 16
const CMP_B_SUB: usize = CMP_A_BITS + CMP_SUBLIMBS * 16;      // 272
const CMP_B_BITS: usize = CMP_B_SUB + CMP_SUBLIMBS;           // 288
const CMP_D: usize = CMP_B_BITS + CMP_SUBLIMBS * 16;          // 544
const CMP_D_BITS: usize = CMP_D + CMP_SUBLIMBS;               // 560
const CMP_BORROW: usize = CMP_D_BITS + CMP_SUBLIMBS * 16;     // 816
const CMP_W: usize = CMP_BORROW + CMP_SUBLIMBS;               // 832

impl BaseAir<F> for CompareAir {
    fn width(&self) -> usize { CMP_W }
    fn num_public_values(&self) -> usize { 2 * DIGEST }       // a[0..8] || b[0..8]
}

impl<AB> Air<AB> for CompareAir
where
    AB: AirBuilder<F = F>,
{
    fn eval(&self, builder: &mut AB) {
        let local: Vec<AB::Var> = builder.main().current_slice()[..CMP_W].to_vec();
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();
        let a_sub = |k: usize| local[CMP_A_SUB + k];
        let a_bit = |k: usize, j: usize| local[CMP_A_BITS + k * 16 + j];
        let b_sub = |k: usize| local[CMP_B_SUB + k];
        let b_bit = |k: usize, j: usize| local[CMP_B_BITS + k * 16 + j];
        let d = |k: usize| local[CMP_D + k];
        let d_bit = |k: usize, j: usize| local[CMP_D_BITS + k * 16 + j];
        let borrow = |k: usize| local[CMP_BORROW + k];

        // range-check every sub-limb of a, b, d to [0, 2^16) via its 16 bits; borrow is boolean.
        for k in 0..CMP_SUBLIMBS {
            let mut acca = AB::Expr::ZERO;
            let mut accb = AB::Expr::ZERO;
            let mut accd = AB::Expr::ZERO;
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
        // bind the sub-limbs to the public digests: pis[e] == a_sub[2e] + a_sub[2e+1]*2^16.
        for e in 0..DIGEST {
            builder.assert_eq(a_sub(2 * e).into() + a_sub(2 * e + 1).into() * AB::Expr::from_u64(1u64 << 16), pis[e]);
            builder.assert_eq(b_sub(2 * e).into() + b_sub(2 * e + 1).into() * AB::Expr::from_u64(1u64 << 16), pis[DIGEST + e]);
        }
        // borrow subtraction of (b - a - 1): per sub-limb  b - a - borrow_in - [k==0] + borrow_out*2^16 == d.
        for k in 0..CMP_SUBLIMBS {
            let borrow_in = if k == 0 { AB::Expr::ZERO } else { borrow(k - 1).into() };
            let lsb_one = if k == 0 { AB::Expr::ONE } else { AB::Expr::ZERO };
            builder.assert_zero(
                b_sub(k).into() - a_sub(k).into() - borrow_in - lsb_one
                    + borrow(k).into() * AB::Expr::from_u64(1u64 << 16) - d(k).into(),
            );
        }
        // no final underflow  <=>  b - a - 1 >= 0  <=>  a < b.
        builder.assert_zero(borrow(CMP_SUBLIMBS - 1).into());
    }
}

/// Build the CompareAir witness row + prove + verify. Returns true iff a < b verifies. For a >= b the
/// honest borrow chain ends with final-borrow == 1, violating the final constraint, so verify rejects.
pub fn prove_verify_compare(a: &[F; DIGEST], b: &[F; DIGEST]) -> bool {
    let ab = publics_to_bytes(a);
    let bb = publics_to_bytes(b);
    let a_u32 = |e: usize| u32::from_le_bytes([ab[4*e], ab[4*e+1], ab[4*e+2], ab[4*e+3]]);
    let b_u32 = |e: usize| u32::from_le_bytes([bb[4*e], bb[4*e+1], bb[4*e+2], bb[4*e+3]]);
    let mut a_sub = [0i64; CMP_SUBLIMBS];
    let mut b_sub = [0i64; CMP_SUBLIMBS];
    for e in 0..DIGEST {
        a_sub[2*e] = (a_u32(e) & 0xFFFF) as i64; a_sub[2*e+1] = ((a_u32(e) >> 16) & 0xFFFF) as i64;
        b_sub[2*e] = (b_u32(e) & 0xFFFF) as i64; b_sub[2*e+1] = ((b_u32(e) >> 16) & 0xFFFF) as i64;
    }
    let mut d = [0i64; CMP_SUBLIMBS];
    let mut bor = [0i64; CMP_SUBLIMBS];
    let mut bin = 0i64;
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
    let trace = RowMajorMatrix::new(row, CMP_W);

    let air = SpendCircuitAir::Compare(CompareAir);
    let config = crate::build_config();
    let mut pvs: Vec<F> = a.to_vec(); pvs.extend_from_slice(b);
    let instances: Vec<StarkInstance<'_, crate::MyConfig, SpendCircuitAir>> =
        vec![StarkInstance { air: &air, trace: &trace, public_values: pvs.clone() }];
    let prover_data = ProverData::from_instances(&config, &instances);
    let proof = prove_batch(&config, &instances, &prover_data);
    verify_batch(&config, &[air.clone()], &proof, &[pvs], &prover_data.common).is_ok()
}

/// CRY-6d-2a gate: a<b verifies; a==b and a>b are unprovable; the most-significant differing element
/// decides (multi-limb order matches value_lt).
pub fn compare_selftest() -> bool {
    let mk = |x: u64| -> [F; DIGEST] { let mut v = [F::ZERO; DIGEST]; v[0] = F::from_u64(x); v };
    if !prove_verify_compare(&mk(30), &mk(50)) { return false; }   // 30 < 50
    if prove_verify_compare(&mk(50), &mk(50)) { return false; }    // equal: not <
    if prove_verify_compare(&mk(70), &mk(50)) { return false; }    // 70 > 50: not <
    let mut ha = mk(999); ha[3] = F::from_u64(5);
    let mut hb = mk(1);   hb[3] = F::from_u64(6);                  // element 3 (more significant): 5 < 6
    if !prove_verify_compare(&ha, &hb) { return false; }
    let mut ha2 = mk(1);  ha2[3] = F::from_u64(9);
    let mut hb2 = mk(999); hb2[3] = F::from_u64(2);                // element 3: 9 > 2  => a > b: not <
    if prove_verify_compare(&ha2, &hb2) { return false; }
    true
}

'''
    s = s.replace(anc, fn + anc, 1); print("CompareAir added")
else: print("CompareAir present; skip")

# 3) enum variant + 3 dispatch arms.
ev = "    Range(RangeAir),\n"
if "    Compare(CompareAir),\n" not in s:
    s = s.replace(ev, ev + "    Compare(CompareAir),\n", 1)
    for arm in [
        ("            Self::Range(a) => <RangeAir as BaseAir<F>>::width(a),\n",
         "            Self::Compare(a) => <CompareAir as BaseAir<F>>::width(a),\n"),
        ("            Self::Range(a) => <RangeAir as BaseAir<F>>::num_public_values(a),\n",
         "            Self::Compare(a) => <CompareAir as BaseAir<F>>::num_public_values(a),\n"),
        ("            Self::Range(a) => a.eval(builder),\n",
         "            Self::Compare(a) => a.eval(builder),\n"),
    ]:
        if s.count(arm[0]) != 1: print("FATAL dispatch anchor:", arm[0].strip()); sys.exit(1)
        s = s.replace(arm[0], arm[0] + arm[1], 1)
    print("enum + dispatch added")
else: print("enum present; skip")

open(c, "w").write(s)

# 4) FFI selftest + header.
f = base + "external/Plonky3/pqpool_ffi/src/lib.rs"; fs = open(f).read()
if "pqpool_compare_selftest" not in fs:
    io = "    imt_nullifier_selftest,"
    fs = fs.replace(io, io + "\n    compare_selftest,", 1)
    anc2 = "#[no_mangle]\npub extern \"C\" fn pqpool_imt_nullifier_selftest() -> i32 {"
    fn2 = ('''#[no_mangle]
pub extern "C" fn pqpool_compare_selftest() -> i32 { if compare_selftest() { 1 } else { 0 } }

''' + anc2)
    fs = fs.replace(anc2, fn2, 1); open(f, "w").write(fs); print("ffi compare added")
else: print("ffi compare present; skip")
h = base + "external/Plonky3/pqpool_ffi/include/pqpool_ffi.h"; hs = open(h).read()
if "pqpool_compare_selftest" not in hs:
    ha = "int32_t pqpool_imt_nullifier_selftest(void);"
    open(h, "w").write(hs.replace(ha, "int32_t pqpool_compare_selftest(void);\n" + ha, 1)); print("ffi.h compare added")
else: print("ffi.h compare present; skip")
print("DONE")
