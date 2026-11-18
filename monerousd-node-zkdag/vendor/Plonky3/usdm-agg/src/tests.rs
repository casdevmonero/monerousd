// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! The verifier row's pins: every row kind runs, the trace satisfies the constraint on every row in the base field,
//! the proof verifies, and each lie is refused; the row's own gate is a program (the fixpoint the tree needs).

use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use usdm_decider::hiding_decider::{Ea4, Fa4};

use crate::isa::*;
use crate::vm::*;

fn f(v: u64) -> Fa4 {
    Fa4::from_u64(v)
}
fn word(vals: &[u64]) -> [Fa4; ND] {
    let mut w = [Fa4::ZERO; ND];
    for (i, v) in vals.iter().enumerate() {
        w[i] = f(*v);
    }
    w
}
fn alu(a: SrcA, b: SrcB, c: Option<SrcC>, wr: Option<u8>, zero: bool, kc: Ea4) -> Option<Alu> {
    Some(Alu { a, b, c, wr, zero, kc })
}

/// A program that uses every row kind, and its stream.
fn every_kind() -> (Vec<Instr>, Vec<[Fa4; ND]>) {
    let mut p = Vec::new();
    let mut d = Vec::new();
    let neg1 = -Ea4::ONE;
    // 0: a fresh transcript absorbing eight words
    p.push(Instr { clr: true, kind: Some(Kind::Reset), am: 0xFF, ..Default::default() });
    d.push(word(&[1, 2, 3, 4, 5, 6, 7, 8]));
    // 1: two challenges off that duplexing (pop order: lanes 7..4, then 3..0)
    p.push(Instr { alu: [alu(SrcA::One, SrcB::Ch(0), None, Some(0), false, Ea4::ZERO), alu(SrcA::One, SrcB::Ch(4), None, Some(1), false, Ea4::ZERO)], ..Default::default() });
    d.push(word(&[]));
    // 2: absorb four words; X2 = X0·X1 + 5; X3 = the stream's D[4..8]
    p.push(Instr {
        kind: Some(Kind::Duplex),
        am: 0x0F,
        alu: [alu(SrcA::X(0), SrcB::X(1), Some(SrcC::Kc), Some(2), false, Ea4::from(f(5))), alu(SrcA::One, SrcB::Dx(1), None, Some(3), false, Ea4::ZERO)],
        ..Default::default()
    });
    d.push(word(&[9, 10, 11, 12, 101, 102, 103, 104]));
    // 3–4: a leaf sponge over twelve words
    p.push(Instr { kind: Some(Kind::Leaf0), am: 0xFF, ..Default::default() });
    d.push(word(&[21, 22, 23, 24, 25, 26, 27, 28]));
    p.push(Instr { kind: Some(Kind::LeafN), am: 0x0F, ..Default::default() });
    d.push(word(&[29, 30, 31, 32]));
    // 5: decompose S lane 6 (its low 2 bits into the draw), then start a walk at generator 7
    p.push(Instr { kind: Some(Kind::Bits), bsel: Some(6), acc: Some(2), ..Default::default() });
    d.push(word(&[]));
    p.push(Instr { kind: Some(Kind::Draw), kg: f(7), ..Default::default() });
    d.push(word(&[]));
    // 6–7: two Merkle levels
    p.push(Instr { kind: Some(Kind::Comp), ..Default::default() });
    d.push(word(&[41, 42, 43, 44, 45, 46, 47, 48]));
    p.push(Instr { kind: Some(Kind::Comp), ..Default::default() });
    d.push(word(&[51, 52, 53, 54, 55, 56, 57, 58]));
    // 8: X4 = g^index; push X3
    p.push(Instr { kind: Some(Kind::Push), px: Some(3), alu: [alu(SrcA::One, SrcB::Var, None, Some(4), false, Ea4::ZERO), None], ..Default::default() });
    d.push(word(&[]));
    // 9: pop it back (previous digest = the cleared stack), X5 = the popped value, and assert it is X3
    p.push(Instr {
        kind: Some(Kind::Pop),
        alu: [alu(SrcA::One, SrcB::Dx(2), None, Some(5), false, Ea4::ZERO), alu(SrcA::X(3), SrcB::Kc, Some(SrcC::Dx(2)), None, true, neg1)],
        ..Default::default()
    });
    d.push(word(&[0, 0, 0, 0, 0, 0, 0, 0, 101, 102, 103, 104]));
    // 10–11: one word absorbed into the statement AND the transcript (tied), 12: the statement's last absorb
    p.push(Instr { kind: Some(Kind::Io), am: 0xFF, tie: true, ..Default::default() });
    d.push(word(&[61, 62, 63, 64, 65, 66, 67, 68]));
    p.push(Instr { kind: Some(Kind::Duplex), am: 0xFF, ..Default::default() });
    d.push(word(&[61, 62, 63, 64, 65, 66, 67, 68]));
    p.push(Instr { kind: Some(Kind::Io), am: 0x0F, stmt: true, ..Default::default() });
    d.push(word(&[71, 72, 73, 74]));
    (p, d)
}

#[test]
fn agg_v1_every_row_kind_runs_satisfies_proves_and_each_lie_is_refused() {
    let (prog, d) = every_kind();
    let (cols, io) = execute(&prog, &d, 32).expect("the program runs");
    trace_satisfies(&cols, &io).expect("every row satisfies the constraint");
    // the executor's own values, read back
    let x = |k: usize, row: usize| -> Ea4 { ea(&core::array::from_fn::<Fa4, 4, _>(|t| cols[X + 4 * k + t][row])) };
    assert_eq!(x(5, 11), x(3, 11), "the popped value is the pushed one");
    let t = cols[0].len();
    let t0 = std::time::Instant::now();
    let (bytes, io2, shape) = prove_vm(&prog, &d, 32).expect("the trace proves");
    let prove_ms = t0.elapsed().as_millis();
    assert_eq!(io, io2);
    let t1 = std::time::Instant::now();
    assert!(verify_vm(&bytes, &prog, &io, shape), "the honest proof verifies");
    let verify_ms = t1.elapsed().as_millis();
    println!("[agg-v1] {} rows × {} columns: proof {} B, prove {prove_ms} ms, verify {verify_ms} ms", t, WIDTH_VM, bytes.len());

    // LIE 1 — another program: one flag moved (a challenge read at another alignment)
    let mut other = prog.clone();
    other[1].alu[0] = alu(SrcA::One, SrcB::Ch(1), None, Some(0), false, Ea4::ZERO);
    assert!(!verify_vm(&bytes, &other, &io, shape), "LIE 1: a proof of one program is refused as another's");
    // LIE 2 — another statement
    let mut io_bad = io;
    io_bad[0] += Fa4::ONE;
    assert!(!verify_vm(&bytes, &prog, &io_bad, shape), "LIE 2: another statement digest is refused");
    // LIE 3 — a moved register cell (X2 on row 4): the trace breaks one transition; the door refuses whatever it proves
    let mut bad = cols.clone();
    bad[X + 8][4] += Fa4::ONE;
    assert!(trace_satisfies(&bad, &io).is_err(), "the twin check sees the moved cell");
    let ioe: [Ea4; RATE] = core::array::from_fn(|i| Ea4::from(io[i]));
    if let Some(b3) = usdm_decider::committed_air::prove_air_chained_bytes(bad, move |g: Ea4| VmGate { gamma: g, io: ioe }, &vm_bind(&io)) {
        assert!(!verify_vm(&b3, &prog, &io, shape), "LIE 3: a moved register is refused");
    }
    // LIE 4 — a pop of a value never pushed: the executor lays pops from its own stack, so lay the lie in the trace
    let mut bad4 = cols.clone();
    bad4[D + 8][10] += Fa4::ONE;
    assert!(trace_satisfies(&bad4, &io).is_err(), "the twin check sees the false pop");
    if let Some(b4) = usdm_decider::committed_air::prove_air_chained_bytes(bad4, move |g: Ea4| VmGate { gamma: g, io: ioe }, &vm_bind(&io)) {
        assert!(!verify_vm(&b4, &prog, &io, shape), "LIE 4: a false pop is refused");
    }
    // LIE 5 — a non-canonical bit decomposition: lay B' = v + p's bits on the Bits row (if v + p < 2^31)
    let v = cols[S + 6][5].as_canonical_u64();
    if v + Fa4::ORDER_U64 < (1u64 << 31) {
        let mut bad5 = cols.clone();
        let w = v + Fa4::ORDER_U64;
        for l in 0..NB {
            bad5[B + l][6] = f(w >> l & 1);
        }
        assert!(trace_satisfies(&bad5, &io).is_err(), "LIE 5: a second spelling of a sample is refused");
    }
}

#[test]
fn agg_v2_the_verifier_rows_own_gate_is_a_program() {
    use usdm_decider::air_zerocheck::{AirConstraint, Row, RowGuard};
    use usdm_decider::gate_trace::{trace, Sym};
    let w = WIDTH_VM;
    let shifted: Vec<usize> = (SHIFT_LO..SHIFT_HI).collect();
    let ns = shifted.len();
    let prog = trace(w + ns + RATE, |ins| {
        let oob = usdm_decider::air_zerocheck::OobLatch::new();
        let row = Row::new(&ins[..w], &oob);
        let next: Vec<Sym> = ins[w..w + ns].to_vec();
        let at = |c: usize, _p: &[Sym]| next[c - SHIFT_LO];
        let io: [Sym; RATE] = core::array::from_fn(|i| ins[w + ns + i]);
        VmGate::<Sym> { gamma: Sym::ZERO, io }.residuals(&row, &at, &[])
    })
    .expect("the gate traces");
    let mut rng: u64 = 0x5EED;
    let mut rnd = || {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let l: [Fa4; 4] = core::array::from_fn(|i| f((rng >> (8 * i)) % Fa4::ORDER_U64));
        Ea4::from_basis_coefficients_slice(&l).expect("limbs")
    };
    let opened: Vec<Ea4> = (0..w).map(|_| rnd()).collect();
    let next: Vec<Ea4> = (0..ns).map(|_| rnd()).collect();
    let io: [Ea4; RATE] = core::array::from_fn(|_| rnd());
    let g = RowGuard::new();
    let row: Row<'_> = g.row(&opened);
    let nn = next.clone();
    let at = move |c: usize, _p: &[Ea4]| nn[c - SHIFT_LO];
    let want = VmGate { gamma: Ea4::ZERO, io }.residuals(&row, &at, &[]);
    let mut ins = opened.clone();
    ins.extend_from_slice(&next);
    ins.extend_from_slice(&io);
    let got = prog.eval(&ins).expect("the program runs");
    assert_eq!(got, want, "the traced gate is the gate");
    let gamma = rnd();
    let folded = VmGate { gamma, io }.eval(&row, &at, &[]);
    assert_eq!(prog.eval_folded(&ins, gamma), Some(folded));
    let c = prog.cost();
    println!("[agg-v2] the verifier row's gate: {} residuals, {} ops ({} mul, {} linear, {} konst)", prog.outputs.len(), prog.ops.len(), c.muls, c.linear, c.konsts);
}


fn kc_load(dst: u8, v: Ea4) -> Option<Alu> {
    alu(SrcA::One, SrcB::Kc, None, Some(dst), false, v)
}

/// Load registers from constants, two a row.
fn load_rows(p: &mut Vec<Instr>, d: &mut Vec<[Fa4; ND]>, regs: &[(u8, Ea4)]) {
    for pair in regs.chunks(2) {
        let mut i = Instr::default();
        for (u, (k, v)) in pair.iter().enumerate() {
            i.alu[u] = kc_load(*k, *v);
        }
        p.push(i);
        d.push([Fa4::ZERO; ND]);
    }
}

fn rand_ea(seed: &mut u64) -> Ea4 {
    let mut l = [Fa4::ZERO; 4];
    for t in 0..4 {
        *seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        l[t] = f((*seed >> 17) % Fa4::ORDER_U64);
    }
    Ea4::from_basis_coefficients_slice(&l).expect("limbs")
}

#[test]
fn agg_v3_the_chip_folds_a_permutation_blocks_residuals_exactly_as_the_air() {
    // An INNER proof's opened block: 164 random extension values (an opened row is not a valid trace row).
    let mut seed = 0xC41Bu64;
    let cells: Vec<Ea4> = (0..P2).map(|_| rand_ea(&mut seed)).collect();
    let gamma = rand_ea(&mut seed);
    let goff = rand_ea(&mut seed); // the γ power the block starts at in its gate
    // the AIR's own residuals (production constants, the carriers' inner permutation)
    let guard = usdm_decider::air_zerocheck::RowGuard::new();
    let row: usdm_decider::air_zerocheck::Row<'_> = guard.row(&cells);
    let mut want_rs = Vec::new();
    usdm_decider::pow_pq_air::push_perm_residuals(&row, 0, &mut want_rs);
    let (mut want, mut pw) = (Ea4::ZERO, goff);
    for r in &want_rs {
        want += pw * *r;
        pw *= gamma;
    }
    let rc = usdm_decider::pow_pq_air::production_constants();
    let mut p = Vec::new();
    let mut d = Vec::new();
    p.push(Instr { clr: true, cclr: true, ..Default::default() });
    d.push([Fa4::ZERO; ND]);
    let mut regs: Vec<(u8, Ea4)> = (0..16).map(|k| ((X_GAMMA_POW + k) as u8, gamma.exp_u64(k as u64))).collect();
    regs.push((X_G16 as u8, gamma.exp_u64(16)));
    regs.push((X_GP as u8, goff));
    load_rows(&mut p, &mut d, &regs);
    // stream the block's limbs, 8 a row, firing the chip on the row after each group's last limb
    let limbs: Vec<Fa4> = cells.iter().flat_map(|c| c.as_basis_coefficients_slice().to_vec()).collect();
    let rows = limbs.len() / RATE; // 82
    let mut chip_at: std::collections::BTreeMap<usize, (Chip, [Fa4; WIDTH])> = std::collections::BTreeMap::new();
    let wrow = |value_end: usize| value_end * 4 / RATE; // the stream row after a group ending at value `value_end`
    chip_at.insert(wrow(16), (Chip::Init, [Fa4::ZERO; WIDTH]));
    for j in 0..4 {
        chip_at.insert(wrow(32 + 16 * j), (Chip::Full, rc.beginning_full_round_constants[j]));
    }
    for k in 0..10 {
        let mut c = [Fa4::ZERO; WIDTH];
        c[0] = rc.partial_round_constants[2 * k];
        c[1] = rc.partial_round_constants[2 * k + 1];
        chip_at.insert(wrow(80 + 2 * k + 2), (Chip::Part, c));
    }
    for j in 0..4 {
        chip_at.insert(wrow(100 + 16 * (j + 1)), (Chip::Full, rc.ending_full_round_constants[j]));
    }
    for rr in 0..=rows {
        let mut i = Instr { wsh: rr < rows, ..Default::default() };
        if let Some((c, k)) = chip_at.get(&rr) {
            i.chip = Some(*c);
            i.rc = *k;
            i.off = 0;
        }
        let mut w = [Fa4::ZERO; ND];
        if rr < rows {
            w[..RATE].copy_from_slice(&limbs[RATE * rr..RATE * rr + RATE]);
        }
        p.push(i);
        d.push(w);
    }
    // read CACC and assert it is the AIR's fold
    p.push(Instr { alu: [alu(SrcA::One, SrcB::Cacc, Some(SrcC::Kc), None, true, -want), None], ..Default::default() });
    d.push([Fa4::ZERO; ND]);
    p.push(Instr { kind: Some(Kind::Io), am: 0x01, stmt: true, ..Default::default() });
    d.push([Fa4::ZERO; ND]);
    let (cols, io) = execute(&p, &d, 32).expect("the chip's sum is the AIR's (the executor asserts it)");
    trace_satisfies(&cols, &io).expect("every chip row satisfies the constraint");
    // a lie: one opened cell moved — the asserted fold no longer holds
    let mut d2 = d.clone();
    d2[12][3] += Fa4::ONE;
    assert!(execute(&p, &d2, 32).is_err(), "a moved opened cell moves the chip's sum");
    let (bytes, io2, shape) = prove_vm(&p, &d, 32).expect("the chip trace proves");
    assert!(verify_vm(&bytes, &p, &io2, shape), "the chip's proof verifies");
    println!("[agg-v3] one permutation block folded by the chip in {} rows; proof {} B", p.len(), bytes.len());
}

#[test]
fn agg_v4_logup_reads_balance_only_against_the_table() {
    let mut seed = 0x10_60u64;
    let rho = rand_ea(&mut seed);
    let beta = rand_ea(&mut seed);
    let vals: Vec<Ea4> = (0..4).map(|_| rand_ea(&mut seed)).collect();
    // table: address k holds vals[k], read (k+1) times; reads: in another order
    let reads: Vec<usize> = vec![3, 0, 2, 1, 3, 2, 3, 1, 2, 3];
    let build = |lie: bool| -> (Vec<Instr>, Vec<[Fa4; ND]>) {
        let mut p = Vec::new();
        let mut d = Vec::new();
        p.push(Instr { clr: true, lclr: true, ..Default::default() });
        d.push([Fa4::ZERO; ND]);
        load_rows(&mut p, &mut d, &[(X_RHO as u8, rho), (X_BETA as u8, beta)]);
        let mut terms: Vec<(usize, Ea4, Fa4)> = (0..4).map(|k| (k, vals[k], f(k as u64 + 1))).collect();
        for (n, &k) in reads.iter().enumerate() {
            let v = if lie && n == 4 { vals[k] + Ea4::ONE } else { vals[k] };
            terms.push((k, v, Fa4::NEG_ONE));
        }
        for pair in terms.chunks(2) {
            let mut i = Instr::default();
            let mut w = [Fa4::ZERO; ND];
            for (q, (k, v, m)) in pair.iter().enumerate() {
                i.lu[q] = Some(Lu { addr: f(*k as u64), mult: *m });
                w[4 * q..4 * q + 4].copy_from_slice(v.as_basis_coefficients_slice());
            }
            p.push(i);
            d.push(w);
        }
        p.push(Instr { alu: [alu(SrcA::One, SrcB::Lacc, None, None, true, Ea4::ZERO), None], ..Default::default() });
        d.push([Fa4::ZERO; ND]);
        p.push(Instr { kind: Some(Kind::Io), am: 0x01, stmt: true, ..Default::default() });
        d.push([Fa4::ZERO; ND]);
        (p, d)
    };
    let (p, d) = build(false);
    let (cols, io) = execute(&p, &d, 32).expect("honest reads balance");
    trace_satisfies(&cols, &io).expect("every logUp row satisfies the constraint");
    let (bytes, io2, shape) = prove_vm(&p, &d, 32).expect("proves");
    assert!(verify_vm(&bytes, &p, &io2, shape));
    let (pl, dl) = build(true);
    assert!(execute(&pl, &dl, 32).is_err(), "a read of a value the table does not hold leaves the sum nonzero");
}


/// Emit an inner transcript's absorption of `vals` (four limbs each) as Reset/Duplex rows with WSH, 8 lanes a row,
/// returning the rows and the limb each lane carried. `start` limbs of padding go first (a pending buffer).
fn absorb_rows(b: &mut crate::gate_eval::Builder, vals: &[Ea4], fresh: bool, pad: usize) -> Vec<(usize, [Option<usize>; RATE])> {
    let mut limbs: Vec<Option<(usize, Fa4)>> = vec![None; pad];
    for (v, e) in vals.iter().enumerate() {
        for (t, l) in e.as_basis_coefficients_slice().iter().enumerate() {
            limbs.push(Some((4 * v + t, *l)));
        }
    }
    let mut out = Vec::new();
    for (n, chunk) in limbs.chunks(RATE).enumerate() {
        let mut w = [Fa4::ZERO; ND];
        let mut map = [None; RATE];
        for (l, c) in chunk.iter().enumerate() {
            if let Some((idx, v)) = c {
                w[l] = *v;
                map[l] = Some(*idx);
            }
        }
        let kind = if n == 0 && fresh { Kind::Reset } else { Kind::Duplex };
        let row = b.push(Instr { kind: Some(kind), am: 0xFF, wsh: true, ..Default::default() }, w);
        out.push((row, map));
    }
    out
}

fn gate_in_circuit(label: &str, gp: &usdm_decider::gate_trace::GateProgram, lay: &usdm_decider::gate_trace::GateInputs, publics: &[Ea4], want_of: &dyn Fn(&[Ea4], &[Ea4], &[Ea4], Ea4) -> Ea4, pad: usize) {
    use crate::gate_eval::{with_publics, Builder, GateEval};
    let mut seed = 0xD1_5EEDu64 ^ (lay.width as u64);
    let opened: Vec<Ea4> = (0..lay.width).map(|_| rand_ea(&mut seed)).collect();
    let next: Vec<Ea4> = (0..lay.shifted.len()).map(|_| rand_ea(&mut seed)).collect();
    let x: Vec<Ea4> = (0..lay.nvars).map(|_| rand_ea(&mut seed)).collect();
    let gamma = rand_ea(&mut seed);
    let want = want_of(&opened, &next, &x, gamma);
    let g = with_publics(gp, lay.publics_at(), publics);
    let ev = GateEval::compile(&g, lay, false).expect("the gate compiles");
    let inputs = lay.assemble(&opened, &next, &x, publics).expect("layout");
    let build = |opened: &[Ea4], pass2_inputs: &[Ea4]| -> Builder {
        let mut b = Builder::default();
        b.push(Instr { clr: true, cclr: true, ..Default::default() }, [Fa4::ZERO; ND]);
        let mut i = Instr::default();
        i.alu[0] = Some(Alu { a: SrcA::One, b: SrcB::Kc, c: None, wr: Some(0), zero: false, kc: gamma });
        b.push(i, [Fa4::ZERO; ND]);
        ev.emit_pass1(&mut b, &inputs);
        ev.emit_gamma(&mut b, 0);
        // twelve quiet rows so the first block's start power has rows of its own
        for _ in 0..12 {
            b.push(Instr::default(), [Fa4::ZERO; ND]);
        }
        let rows = absorb_rows(&mut b, opened, true, pad);
        b.push(Instr::default(), [Fa4::ZERO; ND]);
        b.push(Instr::default(), [Fa4::ZERO; ND]);
        ev.decorate(&mut b, &rows, 0, lay.width).expect("the opened row decorates");
        if !next.is_empty() {
            for _ in 0..12 {
                b.push(Instr::default(), [Fa4::ZERO; ND]);
            }
            let nrows = absorb_rows(&mut b, &next, false, 0);
            b.push(Instr::default(), [Fa4::ZERO; ND]);
            b.push(Instr::default(), [Fa4::ZERO; ND]);
            ev.decorate(&mut b, &nrows, lay.width, next.len()).expect("the next row decorates");
        }
        for (k, xv) in x.iter().enumerate() {
            let mut i = Instr::default();
            i.alu[0] = Some(Alu { a: SrcA::One, b: SrcB::Kc, c: None, wr: Some(1), zero: false, kc: *xv });
            b.push(i, [Fa4::ZERO; ND]);
            ev.emit_x_term(&mut b, k, 1, *xv);
        }
        ev.emit_pass2(&mut b, pass2_inputs);
        let mut i = Instr::default();
        i.alu[0] = Some(Alu { a: SrcA::X(19), b: SrcB::One, c: Some(SrcC::Kc), wr: None, zero: true, kc: -want });
        b.push(i, [Fa4::ZERO; ND]);
        b.push(Instr { kind: Some(Kind::Io), am: 0x01, stmt: true, ..Default::default() }, [Fa4::ZERO; ND]);
        b
    };
    let b = build(&opened, &inputs);
    let (cols, io) = execute(&b.prog, &b.stream, 32).expect("the in-circuit C_γ is the native one (the executor asserts it)");
    trace_satisfies(&cols, &io).expect("every row satisfies the constraint");
    let (bytes, io2, shape) = prove_vm(&b.prog, &b.stream, 32).expect("proves");
    assert!(verify_vm(&bytes, &b.prog, &io2, shape), "{label}: the proof verifies");
    // LIE A: one opened cell of a permutation block moved in the absorption only — the chip's fold no longer matches
    let mut moved = opened.clone();
    moved[ev.blocks[0].base + 20] += Ea4::ONE;
    let ba = build(&moved, &inputs);
    assert!(execute(&ba.prog, &ba.stream, 32).is_err(), "{label}: a moved block cell is refused");
    // LIE A2: one opened value pass 2 reads, moved in the absorption only — the table no longer holds the read value
    if let Some(&r0) = ev.reads.iter().find(|&&r| (r as usize) < lay.width) {
        let mut moved = opened.clone();
        moved[r0 as usize] += Ea4::ONE;
        let ba = build(&moved, &inputs);
        assert!(execute(&ba.prog, &ba.stream, 32).is_err(), "{label}: an absorbed value that is not the read one is refused");
    }
    // LIE B: one READ moved in pass 2 only — the sponge no longer lands where pass 1 left it
    let k = ev.reads[0] as usize;
    let mut inputs_b = inputs.clone();
    inputs_b[k] += Ea4::ONE;
    let bb = build(&opened, &inputs_b);
    assert!(execute(&bb.prog, &bb.stream, 32).is_err(), "{label}: a pass-2 read that pass 1 did not hash is refused");
    println!(
        "[agg-d1] {label}: width {} → {} blocks, {} reads, {} rows ({} trace), proof {} B",
        lay.width,
        ev.blocks.len(),
        ev.reads.len(),
        b.prog.len(),
        cols[0].len(),
        bytes.len()
    );
}

#[test]
fn agg_d1_an_inner_gate_evaluated_in_circuit_is_its_native_value() {
    use usdm_decider::air_zerocheck::{AirConstraint, Row, RowGuard};
    use usdm_decider::gate_trace::with_opaque_perms;
    let mut seed = 0xA66_D1u64;
    let d8 = |seed: &mut u64| -> [Ea4; 8] { core::array::from_fn(|_| rand_ea(seed)) };
    // the member leg (chained: next-row values; reads x)
    let mg = usdm_decider::member_path_gate::MemberPathGate { gamma: Ea4::ZERO, leaf_commit: d8(&mut seed), binder: d8(&mut seed), root: d8(&mut seed) };
    let (mw, mn) = usdm_decider::member_path_gate::member_path_shape();
    let (gp, lay) = with_opaque_perms(|| usdm_decider::gate_trace::member_path_program(mw, mn)).expect("traces");
    let publics = usdm_decider::gate_trace::member_path_publics(&mg);
    let lay2 = lay.clone();
    let want = move |o: &[Ea4], n: &[Ea4], x: &[Ea4], g: Ea4| -> Ea4 {
        let gate = usdm_decider::member_path_gate::MemberPathGate { gamma: g, ..mg.clone() };
        let guard = RowGuard::new();
        let row: Row<'_> = guard.row(o);
        let sh = lay2.shifted.clone();
        let nn = n.to_vec();
        let at = move |c: usize, _p: &[Ea4]| sh.iter().position(|&s| s == c).map_or(Ea4::ZERO, |k| nn[k]);
        gate.eval(&row, &at, x)
    };
    gate_in_circuit("member-leg", &gp, &lay, &publics, &want, 0);
    // the cover arm (chained, 721 columns, four blocks), absorbed behind four pending lanes (a misaligned stream)
    let cg = usdm_decider::nf_sparse_air::CoverOrSpendGate { gamma: Ea4::ZERO, tag_digest: d8(&mut seed) };
    let (cw, cn) = usdm_decider::nf_sparse_air::cover_or_spend_shape(32);
    let (gp, lay) = with_opaque_perms(|| usdm_decider::gate_trace::cover_or_spend_program(cw, cn)).expect("traces");
    let publics = usdm_decider::gate_trace::cover_or_spend_publics(&cg);
    let lay3 = lay.clone();
    let want = move |o: &[Ea4], n: &[Ea4], x: &[Ea4], g: Ea4| -> Ea4 {
        let gate = usdm_decider::nf_sparse_air::CoverOrSpendGate { gamma: g, ..cg.clone() };
        let guard = RowGuard::new();
        let row: Row<'_> = guard.row(o);
        let sh = lay3.shifted.clone();
        let nn = n.to_vec();
        let at = move |c: usize, _p: &[Ea4]| sh.iter().position(|&s| s == c).map_or(Ea4::ZERO, |k| nn[k]);
        gate.eval(&row, &at, x)
    };
    gate_in_circuit("cover-arm", &gp, &lay, &publics, &want, 4);
}


#[test]
fn agg_w0_the_whir_shapes_a_tree_verifies() {
    // Read off the doors' own configuration builder: what one query, one round and one proof cost in circuit.
    let params = usdm_decider::committed_air::CarrierParams::LIVE;
    let (sw, sn) = (usdm_decider::whir_rec_block::note_spend_row_width(), usdm_decider::whir_rec_block::LIGHT_CARRIER_ROWS.trailing_zeros() as usize + 1);
    let (mw, mn) = usdm_decider::member_path_gate::member_path_shape();
    let (cw, cn) = usdm_decider::nf_sparse_air::cover_or_spend_shape(32);
    for (name, shape) in [("note-spend", (sn, sw)), ("member-leg", (mn, mw)), ("cover-arm", (cn, cw)), ("verifier-row 2^14", (14, WIDTH_VM)), ("verifier-row 2^15", (15, WIDTH_VM))] {
        let Some((stacked, cfg)) = usdm_decider::committed_air::door_whir_config(shape, params) else {
            println!("[agg-w0] {name}: shape {shape:?} — no door admits it");
            continue;
        };
        let mut total_q = 0usize;
        let mut line = String::new();
        for (r, rp) in cfg.round_parameters.iter().enumerate() {
            total_q += rp.num_queries;
            line += &format!(" r{r}: vars {} fold {} q {} ood {} dom 2^{} pow {} fpow {};", rp.num_variables, rp.folding_factor, rp.num_queries, rp.ood_samples, rp.domain_size.trailing_zeros(), rp.pow_bits, rp.folding_pow_bits);
        }
        let fc = cfg.final_round_config();
        total_q += fc.num_queries;
        println!(
            "[agg-w0] {name}: shape {shape:?} stacked {stacked}; ood0 {}; fold0 {} grinds {:?};{line} final: vars {} q {} dom 2^{} pow {}; final sumcheck {} rounds pow {}; queries {total_q}",
            cfg.commitment_ood_samples,
            cfg.folding_factor(0),
            cfg.starting_fold_grinds(),
            fc.num_variables,
            fc.num_queries,
            fc.domain_size.trailing_zeros(),
            fc.pow_bits,
            cfg.final_sumcheck_rounds,
            cfg.final_folding_pow_bits
        );
    }
}

/// ⭐ THE RECURSION THRESHOLD, MEASURED (spec §12): what verifying ONE proof costs in verifier rows, for the shapes a tree
/// verifies, against the rows one proof can hold. `emit_whir_verify` is laid with no proof (the program is a function of
/// the configuration alone, pin c8) and its rows counted by kind; the verifier row's own gate is compiled the way a merge
/// evaluates a child (`GateEval::compile_with_combo`) and its pass-2 length counted. A merge closes only if its children's
/// verifications fit beside each other in one proof: `fan_in × (whir + gate + door) ≤ 2^max_rows`.
#[test]
fn agg_w1_what_verifying_one_proof_costs_in_rows() {
    use crate::verify_prog::Asm;
    use crate::verify_whir::emit_whir_verify;
    use usdm_decider::committed_air::{door_whir_config, CarrierParams};
    let live = CarrierParams::LIVE;
    let mut wide = live;
    wide.first_fold = 6;
    let (sw, sn) = (usdm_decider::whir_rec_block::note_spend_row_width(), usdm_decider::whir_rec_block::LIGHT_CARRIER_ROWS.trailing_zeros() as usize + 1);
    let (mw, mn) = usdm_decider::member_path_gate::member_path_shape();
    let (cw, cn) = usdm_decider::nf_sparse_air::cover_or_spend_shape(32);
    let cases: Vec<(&str, (usize, usize), CarrierParams)> = vec![
        ("note-spend", (sn, sw), live),
        ("member-leg", (mn, mw), live),
        ("cover-arm", (cn, cw), live),
        ("vm 2^12 x 1454", (12, WIDTH_VM), live),
        ("vm 2^13 x 1454", (13, WIDTH_VM), live),
        ("vm 2^14 x 1454", (14, WIDTH_VM), live),
        ("vm 2^15 x 1454", (15, WIDTH_VM), live),
        ("vm 2^16 x 1454", (16, WIDTH_VM), live),
        ("vm 2^15 x 512", (15, 512), live),
        ("vm 2^16 x 256", (16, 256), live),
        ("vm 2^17 x 512 ff6", (17, 512), wide),
    ];
    // the verifier row's own gate, as a merge evaluates a child: pass-2 steps and blocks
    use usdm_decider::gate_trace::{trace, with_opaque_perms, GateInputs, Sym};
    let w = WIDTH_VM;
    let shifted: Vec<usize> = (SHIFT_LO..SHIFT_HI).collect();
    let ns = shifted.len();
    let lay = GateInputs { width: w, shifted: shifted.clone(), nvars: 15, publics: RATE };
    let gp = with_opaque_perms(|| {
        trace(lay.total(), |ins| {
            let oob = usdm_decider::air_zerocheck::OobLatch::new();
            let row = usdm_decider::air_zerocheck::Row::new(&ins[..w], &oob);
            let next: Vec<Sym> = ins[w..w + ns].to_vec();
            let at = |c: usize, _p: &[Sym]| next[c - SHIFT_LO];
            let io: [Sym; RATE] = core::array::from_fn(|i| ins[lay.publics_at() + i]);
            VmGate::<Sym> { gamma: Sym::ZERO, io }.residuals(&row, &at, &[])
        })
    })
    .expect("the verifier row's gate traces");
    let pubs: Vec<Ea4> = vec![Ea4::ZERO; RATE];
    let flags: Vec<u32> = (FLAGS as u32..WIDTH_VM as u32).collect();
    match crate::gate_eval::GateEval::compile_with_combo(&crate::gate_eval::with_publics(&gp, lay.publics_at(), &pubs), &lay, false, &flags) {
        Ok(ev) => {
            let mut b = crate::gate_eval::Builder::default();
            ev.emit_pass1(&mut b, &[]);
            let p1 = b.len();
            ev.emit_pass2(&mut b, &[]);
            println!("[agg-w1] the verifier row's gate in a merge: {} blocks, {} reads, pass 1 {} rows, pass 2 {} rows", ev.blocks.len(), ev.reads.len(), p1, b.len() - p1);
        }
        Err(e) => println!("[agg-w1] the verifier row's gate does not compile for a merge: {e}"),
    }
    // the three carrier gates, as a leaf evaluates them (blinded doors)
    {
        let one = [1u64; 8];
        let sp = usdm_decider::gate_trace::note_spend_statement(one, one, one, one, one, one, 1, 0).expect("a statement the door admits");
        let lays: Vec<(&str, Option<(usdm_decider::gate_trace::GateProgram, GateInputs)>, Vec<Ea4>)> = vec![
            ("note-spend", with_opaque_perms(|| usdm_decider::gate_trace::spend_validity_program(&sp.gate, sp.laid_shape.1, sp.laid_shape.0 + 1)), sp.publics.clone()),
            ("member-leg", with_opaque_perms(|| usdm_decider::gate_trace::member_path_program(mw, mn)), Vec::new()),
            ("cover-arm", with_opaque_perms(|| usdm_decider::gate_trace::cover_or_spend_program(cw, cn)), Vec::new()),
        ];
        for (name, gl, pubs) in lays {
            let Some((gp, lay)) = gl else {
                println!("[agg-w1] {name}: the gate does not trace");
                continue;
            };
            let pubs = if pubs.len() == lay.publics { pubs } else { vec![Ea4::ZERO; lay.publics] };
            match crate::gate_eval::GateEval::compile(&crate::gate_eval::with_publics(&gp, lay.publics_at(), &pubs), &lay, true) {
                Ok(ev) => {
                    let mut b = crate::gate_eval::Builder::default();
                    ev.emit_pass1(&mut b, &[]);
                    let p1 = b.len();
                    ev.emit_pass2(&mut b, &[]);
                    println!("[agg-w1] {name} gate in a leaf: width {}, {} blocks, {} reads, pass 1 {} rows, pass 2 {} rows", lay.width, ev.blocks.len(), ev.reads.len(), p1, b.len() - p1);
                }
                Err(e) => println!("[agg-w1] {name}: the gate does not compile: {e}"),
            }
        }
    }
    for (name, shape, params) in cases {
        let Some((stacked, cfg)) = door_whir_config(shape, params) else {
            println!("[agg-w1] {name}: shape {shape:?} — no door admits it");
            continue;
        };
        let mut asm = Asm::new();
        let mut noop = |_: &mut Asm, _: &[u8], _: u8| {};
        match emit_whir_verify(&mut asm, &cfg, None, 0, &mut noop) {
            Err(e) => println!("[agg-w1] {name}: shape {shape:?} stacked {stacked}: the program refuses this configuration: {e}"),
            Ok(()) => {
                let prog = &asm.b.prog;
                let count = |k: Kind| prog.iter().filter(|i| i.kind == Some(k)).count();
                let units = prog.iter().filter(|i| i.kind.is_none()).count();
                let cap_rows = (1usize << 26) / shape.1.next_power_of_two();
                println!(
                    "[agg-w1] {name}: shape {shape:?} stacked {stacked}: WHIR verify {} rows (comp {}, leaf {}, duplex {}, bits {}, draw {}, push {}, pop {}, unit-only {}); one proof of this width holds {} rows",
                    prog.len(),
                    count(Kind::Comp),
                    count(Kind::Leaf0) + count(Kind::LeafN),
                    count(Kind::Duplex) + count(Kind::Reset),
                    count(Kind::Bits),
                    count(Kind::Draw),
                    count(Kind::Push),
                    count(Kind::Pop),
                    units,
                    cap_rows
                );
            }
        }
    }
}
