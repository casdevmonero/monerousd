# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
p = "external/Plonky3/pqpool/src/circuit.rs"
s = open(p).read()
if "reserve_yield_prove_zk_raw_note" in s:
    print("present; skip"); sys.exit(0)
anc = "/// FFI marshaling (verifier side): verify a ZK reserve-yield proof from raw bytes"
if s.count(anc) != 1:
    print("FATAL anchor x%d" % s.count(anc)); sys.exit(1)
fn = '''/// FFI marshaling (note-aware): like reserve_yield_prove_zk_raw but with the MINER's note fields
/// (asset + pk_d/rho/rcm as DIGEST*4=32 LE bytes each) so note_cm commits the miner's reward note.
pub fn reserve_yield_prove_zk_raw_note(
    k: usize, modulus: u64, b: u64, x: u64,
    rcmx_bytes: &[u8], rcmy_bytes: &[u8], rcmb_bytes: &[u8],
    note_value: u64,
    asset: u32, pk_d_bytes: &[u8], rho_bytes: &[u8], rcm_bytes: &[u8],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if rcmx_bytes.len() != VALUE_LIMBS * 4 || rcmy_bytes.len() != VALUE_LIMBS * 4 || rcmb_bytes.len() != VALUE_LIMBS * 4
        || pk_d_bytes.len() != DIGEST * 4 || rho_bytes.len() != DIGEST * 4 || rcm_bytes.len() != DIGEST * 4 {
        return None;
    }
    let to_rcm = |bb: &[u8]| -> [F; VALUE_LIMBS] {
        let mut a = [F::ZERO; VALUE_LIMBS];
        for i in 0..VALUE_LIMBS { let o = i * 4; a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o+1], bb[o+2], bb[o+3]]) as u64); }
        a
    };
    let to_note = |bb: &[u8]| -> [F; DIGEST] {
        let mut a = [F::ZERO; DIGEST];
        for i in 0..DIGEST { let o = i * 4; a[i] = F::from_u64(u32::from_le_bytes([bb[o], bb[o+1], bb[o+2], bb[o+3]]) as u64); }
        a
    };
    let (proof, publics) = reserve_yield_prove_zk_bytes(
        k, modulus, b, x, to_rcm(rcmx_bytes), to_rcm(rcmy_bytes), to_rcm(rcmb_bytes), note_value, None,
        asset, to_note(pk_d_bytes), to_note(rho_bytes), to_note(rcm_bytes));
    Some((proof, publics_to_bytes(&publics)))
}

'''
s = s.replace(anc, fn + anc, 1)
open(p, "w").write(s)
print("reserve_yield_prove_zk_raw_note added")
