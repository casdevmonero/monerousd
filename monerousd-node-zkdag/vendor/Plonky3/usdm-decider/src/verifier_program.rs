//! The PROGRAM BUILDER — compiles a verifier's operations into universal-row instructions (`universal_row.rs`)
//! plus the proof-word stream. The program depends only on the proof's SHAPE (the PCS/Spartan configuration),
//! the stream only on the proof's words; the row's program hash binds the former, Fiat–Shamir the latter.
//!
//! This file holds the transcript scheduler: it mirrors `DuplexChallenger`'s buffers (an input buffer of up to
//! RATE words, an output buffer popped from the end, cleared by an observe) and lays each duplexing, pop and
//! Ea4/STIR quad onto rows — including a quad split across a duplexing (pops of the old buffer in one row, a
//! bare duplexing and the remaining pops in the next), which the row's latches and `TSUM` were built for.
//!
//! ROOT-LAYER: the schedule is produced HERE from the challenger's own rules, never inferred from values.
//! MEASURED: pin `random_transcript_schedules_match_the_deciders_challenger` — 12 random interleavings of
//! observes, Ea4 samples and STIR draws reproduce every `Chl` challenge and every `draw_below` index.
//! MUST-STAY-GREEN: the universal-row pins.

use crate::hiding_decider::Fa4;
use crate::spartan_gadgets::RATE;
use crate::universal_row::{flag, RowFlags, NPOPU, NSTREAM};
use p3_field::PrimeCharacteristicRing;

/// Where a produced value lives: the step AFTER which the register holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct After {
    pub row: usize,
}

pub struct ProgramBuilder {
    pub rows: Vec<RowFlags>,
    pub stream: Vec<[Fa4; NSTREAM]>,
    cur: RowFlags,
    cur_d: [Fa4; NSTREAM],
    cur_d_used: usize,
    cur_perm: bool,
    cur_units: usize,
    cur_quad: bool,
    cur_open: bool,
    /// The challenger's input buffer (words observed since the last duplexing).
    pending: Vec<Fa4>,
    /// The challenger's output buffer size: the next pop reads slot `out_avail − 1`.
    out_avail: usize,
    /// Flags for the row that emits the NEXT duplexing (an absorbed Ea4's register move rides its duplexing row).
    on_duplex: Vec<usize>,
    /// Flags for the row AFTER the next duplexing row (the absorbed value's register is read there).
    on_duplex_next: Vec<usize>,
    /// Flags for the next NEW row (a value latched into `E[0]` is consumed by the row after).
    on_next: Vec<usize>,
    /// `(flag, rows left)`: a flag repeated on that many upcoming new rows (a bank restored across other work).
    repeat: Vec<(usize, usize)>,
}

impl Default for ProgramBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramBuilder {
    pub fn new() -> Self {
        ProgramBuilder {
            rows: Vec::new(),
            stream: Vec::new(),
            cur: RowFlags::default(),
            cur_d: [Fa4::ZERO; NSTREAM],
            cur_d_used: 0,
            cur_perm: false,
            cur_units: 0,
            cur_quad: false,
            cur_open: false,
            pending: Vec::new(),
            out_avail: 0,
            on_duplex: Vec::new(),
            on_duplex_next: Vec::new(),
            on_next: Vec::new(),
            repeat: Vec::new(),
        }
    }
    /// A builder whose challenger model starts mid-transcript: `pending` words buffered, `out_avail` slots left.
    pub fn with_transcript_state(pending: Vec<Fa4>, out_avail: usize) -> Self {
        let mut pb = Self::new();
        pb.pending = pending;
        pb.out_avail = out_avail;
        pb
    }
    /// The index the row being assembled will have.
    pub fn cur_row(&self) -> usize {
        self.rows.len()
    }
    /// Close the row being assembled (if any) and start a fresh one, applying the deferred `on_next` flags.
    pub fn new_row(&mut self) {
        if self.cur_open {
            // O1-INFINITY-REVIEWED: one entry per program row — the fixed verifier program, f(the proof SHAPE).
            self.rows.push(core::mem::take(&mut self.cur));
            self.stream.push(core::mem::replace(&mut self.cur_d, [Fa4::ZERO; NSTREAM]));
        }
        self.cur_d_used = 0;
        self.cur_perm = false;
        self.cur_units = 0;
        self.cur_quad = false;
        self.cur_open = true;
        for i in core::mem::take(&mut self.on_next) {
            self.cur.set(i);
        }
        for (fl, left) in self.repeat.iter_mut() {
            self.cur.set(*fl);
            *left -= 1;
        }
        self.repeat.retain(|&(_, left)| left > 0);
    }
    /// Set `fl` on the next `n` new rows.
    pub fn repeat_on_next_rows(&mut self, fl: usize, n: usize) {
        if n > 0 {
            self.repeat.push((fl, n));
        }
    }
    /// Open fresh rows until no repeated flag is pending (a bank restore must finish before its bank is read).
    pub fn drain_repeats(&mut self) {
        while !self.repeat.is_empty() {
            self.new_row();
        }
    }
    /// Flags for the row after the row that absorbs the currently pending words.
    pub fn on_duplex_next(&mut self, flags: &[usize]) {
        self.on_duplex_next.extend_from_slice(flags);
    }
    /// Start a fresh row and return it for flag setting (arithmetic-only rows).
    pub fn row(&mut self) -> &mut RowFlags {
        self.new_row();
        &mut self.cur
    }
    /// The row being assembled, for flag setting.
    pub fn cur(&mut self) -> &mut RowFlags {
        self.ensure_open();
        &mut self.cur
    }
    /// Flags for the next new row.
    pub fn on_next(&mut self, flags: &[usize]) {
        self.on_next.extend_from_slice(flags);
    }
    /// Flags for the row that absorbs the currently pending words (the next duplexing).
    pub fn on_duplex(&mut self, flags: &[usize]) {
        self.on_duplex.extend_from_slice(flags);
    }
    /// The challenger's pending-word count (the next observed Ea4 lands at `D_ext[pending / 4]`).
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    fn ensure_open(&mut self) {
        if !self.cur_open {
            self.new_row();
        }
    }
    /// A row with a free permutation slot and `words` free stream slots from 0.
    fn perm_row(&mut self, words: usize) {
        self.ensure_open();
        if self.cur_perm || self.cur_d_used > 0 || (words > 0 && self.cur_units > 0) {
            self.new_row();
        }
        self.cur_perm = true;
        self.cur_d_used = self.cur_d_used.max(words);
    }
    /// Duplex the pending words (a bare duplexing when none): pops in a row read the POST-duplexing buffer, so a
    /// row that already popped from the old buffer cannot also host this duplexing.
    fn emit_duplex(&mut self) {
        self.ensure_open();
        if self.cur_perm || self.cur_units > 0 || self.cur_d_used > 0 {
            self.new_row();
        }
        self.cur_perm = true;
        self.cur.set(flag::M_ABSORB);
        for (k, &w) in self.pending.iter().enumerate() {
            self.cur.set(flag::A + k);
            self.cur_d[k] = w;
        }
        self.cur_d_used = self.pending.len();
        self.pending.clear();
        self.out_avail = RATE;
        for i in core::mem::take(&mut self.on_duplex) {
            self.cur.set(i);
        }
        let next = core::mem::take(&mut self.on_duplex_next);
        self.on_next.extend(next);
    }
    /// `challenger.sample()` whose value nobody reads (the STIR pow checkpoint): the slot is consumed, no unit.
    pub fn pop_discard(&mut self) {
        self.ensure_open();
        if !self.pending.is_empty() || self.out_avail == 0 {
            self.emit_duplex();
        }
        self.out_avail -= 1;
    }
    /// `challenger.check_witness(bits, w)` with `bits > 0`, the witness already observed by the caller: ONE pop into
    /// unit 0 of a row whose units are free, flagged `kind` (`POW_INIT` with the run's first round-table slot, or
    /// `POW_FOLD`/`POW_QUERY` with the round's slot, as the one-hot `rf`) so the row asserts the sample's low `bits`
    /// are zero. The next quad opens a fresh row.
    pub fn pop_pow(&mut self, kind: usize, rf: Option<usize>) {
        assert!(kind == flag::POW_INIT || kind == flag::POW_FOLD || kind == flag::POW_QUERY, "a pow kind flag");
        assert!(rf.is_some(), "every pow count is a round-table entry selected by the one-hot");
        self.ensure_open();
        if !self.pending.is_empty() || self.out_avail == 0 {
            self.emit_duplex();
        }
        if self.cur_units > 0 {
            self.new_row();
        }
        let slot = self.out_avail - 1;
        self.out_avail -= 1;
        self.cur.pop(0, slot);
        self.cur_units = 1;
        self.cur.set(kind);
        if let Some(r) = rf {
            assert!(r < crate::universal_row::NROUNDS);
            self.cur.set(flag::rf(r));
        }
        // ⛔ FOUND 2026-09-28 (fixpoint4, row 4171): the round one-hot makes `kmask` this round's `k` bits, so the
        // popped sample's masked value joins the STIR running sum `TSUM` — carried from the last draw (four masked
        // values, up to 2^26 − 4 at k = 24), the fifth addend overflowed the row's 26-bit decomposition and an HONEST
        // certificate step was refused with probability ≈ 1/2. A pow row needs no running sum and every draw starts
        // with its own `TCLEAR`, so the pow row clears it: `TSUM' = the sample's masked value` (< 2^24). Pinned by
        // `universal_row::tests::a_pow_row_after_a_wide_draw_does_not_overflow_the_running_sum` (RED before this line).
        self.cur.set(flag::TCLEAR);
        self.cur_quad = true;
    }
    /// `challenger.observe_algebra_element(e)`: four words.
    pub fn observe_ext(&mut self, e: crate::hiding_decider::Ea4) {
        use p3_field::BasedVectorSpace;
        for c in 0..4 {
            self.observe(e.as_basis_coefficients_slice()[c]);
        }
    }
    /// One leaf block: up to RATE stream words absorbed into `H` (reset when `first`). One permutation row.
    pub fn leaf_block(&mut self, block: &[Fa4], first: bool) {
        assert!(!block.is_empty() && block.len() <= RATE);
        self.perm_row(block.len());
        self.cur.set(flag::M_LEAF);
        if first {
            self.cur.set(flag::H_RESET);
        }
        for (k, &w) in block.iter().enumerate() {
            self.cur.set(flag::A + k);
            self.cur_d[k] = w;
        }
    }
    /// `challenger.observe(word)`: buffer it; a full buffer duplexes; the output buffer is cleared.
    pub fn observe(&mut self, word: Fa4) {
        self.out_avail = 0;
        self.pending.push(word);
        if self.pending.len() == RATE {
            self.emit_duplex();
        }
    }
    pub fn observe_slice(&mut self, words: &[Fa4]) {
        for &w in words {
            self.observe(w);
        }
    }
    /// One pop into unit `c` of the current row (after a duplexing if the challenger would duplex).
    fn pop_into_unit(&mut self, c: usize) {
        self.ensure_open();
        if !self.pending.is_empty() || self.out_avail == 0 {
            self.emit_duplex();
        }
        let slot = self.out_avail - 1;
        self.out_avail -= 1;
        self.cur.pop(c, slot);
        self.cur_units = c + 1;
    }
    /// Start a quad (an Ea4 sample or a STIR draw): one per row.
    fn start_quad(&mut self) {
        self.ensure_open();
        if self.cur_quad {
            self.new_row();
        }
        self.cur_quad = true;
    }
    /// `challenger.sample_algebra_element()`: four pops latched into `E[0]`, coefficient `c` from unit `c`.
    /// Returns the row after which `E[0]` holds the challenge.
    pub fn sample_ext(&mut self) -> After {
        self.start_quad();
        for c in 0..NPOPU {
            self.pop_into_unit(c);
            self.cur.set(flag::LATCH + c);
            self.cur_quad = true;
        }
        After { row: self.cur_row() }
    }
    /// `draw_below(2^k)` for round `round` (whose `k` the row reads from its round table): four pops masked and
    /// summed (`TCLEAR` on the first row, `STIR` on the last, the round one-hot on every row of the quad).
    /// Returns the row after which `B` holds the index.
    pub fn draw(&mut self, round: usize) -> After {
        assert!(round < crate::universal_row::NROUNDS);
        self.start_quad();
        let first = self.cur_row();
        self.cur.set(flag::rf(round));
        self.cur.set(flag::TCLEAR);
        for c in 0..NPOPU {
            self.pop_into_unit(c);
            if self.cur_row() != first {
                self.cur.set(flag::rf(round));
            }
            self.cur_quad = true;
        }
        self.cur.set(flag::STIR);
        After { row: self.cur_row() }
    }
    /// A Merkle leaf: blocks of RATE stream words absorbed into `H` (reset on the first block).
    pub fn leaf(&mut self, words: &[Fa4]) {
        for (i, block) in words.chunks(RATE).enumerate() {
            self.leaf_block(block, i == 0);
        }
    }
    /// One Merkle compression with `sibling`, consuming `B[0]`; `check` asserts the root against `R`.
    pub fn compress(&mut self, sibling: &[Fa4; RATE], check: bool) {
        self.perm_row(RATE);
        self.cur.set(flag::M_MERKLE).set(flag::BSHIFT);
        if check {
            self.cur.set(flag::ROOT_CHECK);
        }
        self.cur_d[..RATE].copy_from_slice(sibling);
    }
    /// Capture `root` into `R` (a row whose stream slots 0..8 are free).
    pub fn capture_root(&mut self, root: &[Fa4; RATE]) {
        self.ensure_open();
        if self.cur_d_used > 0 {
            self.new_row();
        }
        self.cur.set(flag::R_CAPTURE);
        self.cur_d[..RATE].copy_from_slice(root);
        self.cur_d_used = RATE;
    }
    /// M5: start a row of its OWN — the open row is closed if it carries anything. The acc-step rows sequence register
    /// moves and hash blocks whose inputs are the PREVIOUS row's outputs; a hash block merged onto a move row would read
    /// the registers before the move (MEASURED 2026-09-28: the outer PROD row merged onto the `X0 ‖ X1 ← acc'` move row
    /// and hashed the summary leftovers instead).
    fn fresh_row(&mut self) {
        self.ensure_open();
        if self.cur != RowFlags::default() || self.cur_d_used > 0 || self.cur_perm || self.cur_units > 0 {
            self.new_row();
        }
    }
    /// H12 §12 C: push `VAR` (this query's g^index) on the VB stack — a `BANK_ABSORB` row of its own (it takes the
    /// row's permutation; register moves set on it read the registers before the push).
    pub fn bank_absorb(&mut self) {
        self.fresh_row();
        self.perm_row(0);
        self.cur.set(flag::BANK_ABSORB);
    }
    /// H12 §12 C: pop the VB stack into VB's tail — a `BANK_UNWIND` row of its own; its nine stream words are the
    /// honest prover's (`universal_row::emulate` supplies them from the pushes).
    pub fn bank_unwind(&mut self) {
        self.fresh_row();
        self.perm_row(RATE + 1);
        self.cur.set(flag::BANK_UNWIND);
    }
    /// H12 §12 C (F half): push `X[0]` (a round's fold) on the FK stack — a `BANK_ABSORB ∧ FBANK` row of its own.
    pub fn f_absorb(&mut self) {
        self.fresh_row();
        self.perm_row(0);
        self.cur.set(flag::BANK_ABSORB).set(flag::FBANK);
    }
    /// H12 §12 C (F half): pop the FK stack — a `BANK_UNWIND ∧ FBANK` row of its own; its stream words `D[4..16]`
    /// (the fold in `D_ext[1]`, the previous digest in `D[8..16]`) are the honest prover's; moves set on it read them.
    pub fn f_unwind(&mut self) {
        self.fresh_row();
        self.perm_row(NSTREAM);
        self.cur.set(flag::BANK_UNWIND).set(flag::FBANK);
    }
    /// M5: a plain row (no permutation) of its own carrying `words` in stream slots `0..8` — register loads
    /// (`XM_ADD_DA`, `XM_ADD_DBASE`, `AM_BASEPAIR`) and captures set on it read them.
    pub fn stream_words(&mut self, words: &[Fa4; RATE]) {
        self.fresh_row();
        self.cur_d[..RATE].copy_from_slice(words);
        self.cur_d_used = RATE;
    }
    /// M5: one PRODUCTION compression `H ← perm_prod([X0 ‖ X1 ‖ words])` on a row of its own — `M_MERKLE ∧ M_LEAF`
    /// selects the production constants and the `[eight register coefficients ‖ eight stream words]` input, exactly
    /// `poseidon2_compress::compress(left, right)` with `left` in the registers. Register moves set on this row read the
    /// OLD `X0 ‖ X1`, so the same row may load new values into them.
    pub fn prod_block(&mut self, words: &[Fa4; RATE]) {
        self.fresh_row();
        self.perm_row(RATE);
        self.cur.set(flag::M_MERKLE).set(flag::M_LEAF);
        self.cur_d[..RATE].copy_from_slice(words);
    }
    /// M5: one Merkle-constant compression `H ← perm_merkle([H ‖ words])` on a row of its own, with NO `BSHIFT` — a
    /// state-hash chain block; the caller has zeroed `B` (`B[0] = 0` selects the `[H ‖ D]` order).
    pub fn merkle_block(&mut self, words: &[Fa4; RATE]) {
        self.fresh_row();
        self.perm_row(RATE);
        self.cur.set(flag::M_MERKLE);
        self.cur_d[..RATE].copy_from_slice(words);
    }
    /// Set a flag on the row being assembled (register moves, bank ops, asserts the caller sequences).
    pub fn flag(&mut self, i: usize) -> &mut Self {
        self.ensure_open();
        self.cur.set(i);
        self
    }
    /// Finish: close the open row and append one idle row (the last row's flags are outside the program hash).
    pub fn finish(mut self) -> (Vec<RowFlags>, Vec<[Fa4; NSTREAM]>) {
        self.new_row();
        self.new_row();
        (self.rows, self.stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiding_decider::Ea4;
    use crate::universal_row::{emulate, RowParams, B_OFF, E_OFF, NB, NREG, V_BITS};
    use p3_challenger::{CanObserve, FieldChallenger};
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_whir::pcs::utils::draw_below;

    fn perm_for(seed: u64) -> crate::hiding_decider::Perm16 {
        use rand::SeedableRng;
        crate::hiding_decider::Perm16::new_from_rng_128(&mut rand::rngs::SmallRng::seed_from_u64(seed))
    }

    /// ⭐⭐⭐ THE SCHEDULER PIN: random interleavings of observes (1..12 words), Ea4 samples and STIR draws — every
    /// alignment and every split — reproduce the challenger's values: `E[0]` after each sample row equals
    /// `Chl::sample_algebra_element`, `B` after each draw row equals `draw_below`.
    #[test]
    fn random_transcript_schedules_match_the_deciders_challenger() {
        let p = RowParams::decider(core::array::from_fn(|r| Fa4::from_u64(1000 + r as u64)), [12, 20, 8, 4, 1, 24, 6, 6, 6, 6], 3);
        let seed = crate::whir_rec_block::REC_DECIDER_SEED ^ 0x5041_5254_4E31;
        let io = [Fa4::ZERO; crate::universal_row::IO_LEN];
        let v = 1usize << V_BITS;
        let mut total_rows = 0usize;
        for run in 0..12u64 {
            let mut st = run.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(0xD1B5_4A32);
            let mut rnd = |m: u64| {
                st ^= st << 13;
                st ^= st >> 7;
                st ^= st << 17;
                st % m
            };
            let mut native = crate::hiding_decider::Chl::new(perm_for(seed));
            let mut pb = ProgramBuilder::new();
            enum Want {
                Ext(After, Ea4),
                Idx(After, usize),
            }
            let mut wants: Vec<Want> = Vec::new();
            for _ in 0..24 {
                match rnd(3) {
                    0 => {
                        let n = 1 + rnd(12) as usize;
                        let words: Vec<Fa4> = (0..n).map(|_| Fa4::from_u64(rnd(1 << 30))).collect();
                        for &w in &words {
                            native.observe(w);
                        }
                        pb.observe_slice(&words);
                    }
                    1 => {
                        let want: Ea4 = native.sample_algebra_element();
                        let at = pb.sample_ext();
                        wants.push(Want::Ext(at, want));
                    }
                    _ => {
                        let round = rnd(crate::universal_row::NROUNDS as u64) as usize;
                        let want = draw_below::<_, Fa4>(&mut native, 1usize << p.ks[round]);
                        let at = pb.draw(round);
                        wants.push(Want::Idx(at, want));
                    }
                }
            }
            let (program, stream) = pb.finish();
            total_rows += program.len();
            let tr = emulate(&p, &io, [Fa4::ZERO; NREG], &program, &stream);
            // registers AFTER row r = the locals of step r + 1 (the hand-off), or the final registers
            let regs_after = |r: usize| -> Vec<Fa4> {
                if r + 1 < tr.steps {
                    tr.w[(r + 1) * v..(r + 1) * v + NREG].to_vec()
                } else {
                    tr.final_regs.to_vec()
                }
            };
            for (i, w) in wants.iter().enumerate() {
                match w {
                    Want::Ext(at, want) => {
                        let regs = regs_after(at.row);
                        let got = Ea4::from_basis_coefficients_fn(|c| regs[E_OFF + c]);
                        assert_eq!(got, *want, "run {run} op {i}: Ea4 sample after row {} differs from Chl", at.row);
                    }
                    Want::Idx(at, want) => {
                        let regs = regs_after(at.row);
                        let got = (0..NB).fold(0usize, |acc, l| acc | ((regs[B_OFF + l] == Fa4::ONE) as usize) << l);
                        assert_eq!(got, *want, "run {run} op {i}: draw after row {} differs from draw_below", at.row);
                    }
                }
            }
        }
        eprintln!("[program] 12 random transcript schedules ({total_rows} rows) reproduce every Chl challenge and draw_below index");
    }
}
