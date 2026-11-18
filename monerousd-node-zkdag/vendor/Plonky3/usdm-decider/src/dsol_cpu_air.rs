// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE DSOL MACHINE AS CONSTRAINTS — arbitrary contract execution, proven.
//!
//! [`crate::dsol_vm`] defines the machine and emits a witness. This module is the other half: the gates
//! that decide whether a witness is an execution the machine could have made. Together they are the
//! private execution layer — a caller proves *"I ran THIS contract from THIS storage root and it produced
//! THESE effects"*, and every node verifies that without learning the arguments, the intermediate values,
//! the strings, or the branch taken.
//!
//! # The statement
//!
//! ```text
//! (code_id, entry_sel, argv_digest, storage_pre, storage_post, effects_digest, ret_digest, height_log2)
//! ```
//!
//! Public, and bound at the transcript start. Everything else is witness.
//!
//! # The laws, and why each exists
//!
//! Each is written against a forgery it must refuse; the tamper pins at the bottom drive each one.
//!
//! * **L1 SELECTORS** — the opcode and micro-step selectors are one-hot booleans and agree with the
//!   `op`/`micro` columns. Without it a prover blends two opcodes' transition rules and lands on a state
//!   neither allows.
//! * **L2 FETCH** — `(pc, op, imm)` is a row of the contract's OWN program. This is the law that makes
//!   the proof about a CONTRACT rather than about an arbitrary computation, and it is a LogUp lookup into
//!   the public ROM because it is the one relation a row-local gate cannot express.
//! * **L3 STACK** — the next row's stack is this row's stack moved by exactly what the opcode does. The
//!   whole stack is committed in every row, so there is no stack memory argument to get wrong.
//! * **L4 ALU** — arithmetic is over 16-bit limbs with declared carries, every result limb is recomposed
//!   from its own bits (which is what proves it stayed in range without a lookup), and the operands are
//!   constrained to be WORDS. That last part is not decoration: the layout below holds zero in the ALU
//!   columns of a row whose operand is a string, so without the tag law a prover could put a string on
//!   the stack and have the arithmetic read it as zero.
//! * **L5 CONTROL** — the pc advances by the instruction's own width, or to the immediate on a taken
//!   branch, and nowhere else.
//! * **L6 SPONGE** — capacity carries, rate is overwritten by the staged lanes, and the permutation block
//!   is the real Poseidon2 one. This is the same law [`crate::sponge_chain_air`] proves, re-emitted here
//!   for three concurrent sponges.
//! * **L7 PACKING** — a fed byte lands in the lane and sub-position its fill counter names, and the byte
//!   is a byte. This is the byte-string layer's whole soundness: a `CONCAT` output is the digest of the
//!   bytes its verifiers re-checked *because the same committed byte advanced both sponges in one row*.
//! * **L8 STORAGE** — an access is a `mk::LEAF` row hashing `compress(key, value)` from the key and value the
//!   row holds, then exactly `STORAGE_DEPTH` `mk::PATH` rows (a write lays each level twice: pre-image, then
//!   post-image through the SAME sibling); the direction bits rebuild the key lane by lane, the pre-image
//!   folds to the row's root, a write's post-image becomes the next root, and a read's result is the value
//!   whose leaf was proven. So a read cannot move the root, cannot answer for another key's slot, and cannot
//!   return a value the root does not hold; a write moves the root only where its key sits. A `MAP_*` slot key is
//!   derived IN-CIRCUIT on the access's KEYD row — its block hashes the two string operands into the key every row
//!   that follows uses (L8b part 1); a STRING value's half of the leaf is hashed on a SVAL row before its LEAF row and
//!   a read of a string slot lands the string (L8b part 2).
//! * **L9 EFFECTS** — an effect opcode lays its effect's leaf as `mk::EFX` rows, one Poseidon2 block per
//!   stage of ONE shared schedule (`dsol_vm::efx_plan`), every block's inputs being named sources the row
//!   holds (stack operands, sponge A's digest, the statement's contract id, domain constants, carries) and
//!   the last block folding the leaf into the accumulator, which carries on every other row. So a prover
//!   cannot record an effect the execution did not issue, nor drop, reorder or alter one. A `SYSCALL`'s result
//!   is produced through sponge C, so its effect records the digest of the bytes the execution consumed (L9b);
//!   `MAP_STORE_PRIV` is REFUSED until L8b gives its derived key a source.
//! * **L10 BOUNDARY** — row 0 is the entrypoint with the argv on the stack; the last row RETURNs; and the
//!   statement's public values are the ones the trace actually ended on.
//!
//! # ⛔ NOTHING HERE RESCUES A MALFORMED WITNESS WITH A DEFAULT
//!
//! The first draft of the layout below returned `0` in three places: a stack slot holding a string read
//! as the word zero, a truncated instruction's immediate read as zero, and a division by zero answered
//! with zero. Every one of those is a silent default standing where a REFUSAL belongs — and a layout that
//! launders a malformed witness into well-formed columns is strictly worse than one that panics, because
//! the proof still verifies. All three now return `None`, and the two that a prover could reach anyway
//! (`ALU on a string`, `DIV by zero`) additionally carry a CONSTRAINT, because a layout-side refusal only
//! binds the honest prover.
//!
//! # NO GROWTH
//!
//! Width is f(the protocol's own constants) — stack depth, locals, sponge width, digest lanes, the
//! Poseidon2 block. Height is the call's step count, bounded by [`crate::dsol_vm::STEP_BUDGET_MAX`].
//! Neither has a term in chain height, block count, note count, peer count or DAG width. A verifying node
//! does ONE light-decider verify over that fixed shape and stores nothing.

use crate::dsol_vm::{
    self, mk, op, Step, VmTrace, BYTES_PER_LANE, LOCALS_MAX, RATE, SPONGES, STACK_DEPTH,
};
use crate::hiding_decider::Fa4;
use crate::poseidon2_compress::{Digest, DIGEST_LANES};
use p3_field::{Field, PrimeCharacteristicRing};

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The opcode universe the circuit constrains. ⛔ DERIVED FROM THE MACHINE, not restated: a new opcode
// that the machine runs and this list forgets would be an opcode with NO transition law, which the
// `every_opcode_the_machine_can_run_has_a_selector` pin refuses.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Every opcode this circuit has a law for, in selector order.
pub const OPS: [u8; 51] = [
    op::PUSH_U64,
    op::PUSH_BYTES,
    op::POP,
    op::DUP,
    op::SWAP,
    op::ADD_U64,
    op::SUB_U64,
    op::MUL_U64,
    op::DIV_U64,
    op::MOD_U64,
    op::LT,
    op::EQ,
    op::NOT,
    op::AND,
    op::OR,
    op::JUMP,
    op::JUMPI,
    op::RETURN,
    op::REVERT,
    op::SLOAD,
    op::SSTORE,
    op::SSTORE_PRIV,
    op::COMMIT_U64,
    op::NULLIFIER,
    op::SYSCALL,
    op::MSG_SENDER,
    op::BLOCK_NUMBER,
    op::CONTRACT_ID,
    op::TX_HASH,
    op::POSEIDON,
    op::EMIT,
    op::LOCAL_GET,
    op::LOCAL_SET,
    op::ALLOC_LOCALS,
    op::U64_FROM_BYTES,
    op::U64_TO_BYTES,
    op::MAP_LOAD,
    op::MAP_STORE,
    op::MAP_STORE_PRIV,
    op::BYTES_LEN,
    op::STR_EQ,
    op::CONCAT,
    op::U64_TO_DEC_STR,
    op::MSG_SUBADDRESS,
    op::MUL_HI,
    op::ADC,
    op::SBB,
    op::DIVMOD128,
    op::CALL,
    op::LIBCALL,
    op::BOUND,
];

/// Selector count for the opcode one-hot.
pub const NOPS: usize = OPS.len();

/// The opcodes whose transition is the ALU's: two word operands in, one word out.
pub const ALU_OPS: [u8; 13] = [
    op::ADD_U64,
    op::SUB_U64,
    op::MUL_U64,
    op::DIV_U64,
    op::MOD_U64,
    op::LT,
    op::EQ,
    op::AND,
    op::OR,
    op::MUL_HI,
    op::ADC,
    op::SBB,
    op::DIVMOD128,
];

/// The index of `o` in [`OPS`].
#[must_use]
pub fn op_index(o: u8) -> Option<usize> {
    OPS.iter().position(|&x| x == o)
}

/// Micro-step kinds the one-hot covers: PLAIN, FEED, PERM, FINISH, PATH, LEAF, EFX, KEYD, SVAL, CMT, BOUND.
pub const NMICRO: usize = 11;

/// Limbs a `u64` occupies in the field, and the width of each. 4 × 16 = 64 exactly — no slack limb that
/// could hold a value the recomposition never sees.
pub const W_LIMBS: usize = 4;
/// Bits per word limb. `2^16 + 2^16 < p` for KoalaBear, so a limb sum plus a carry cannot wrap the field
/// and hide itself.
pub const W_BITS: usize = 16;

/// Cells one stack/local slot occupies: a type tag, the word as limbs, the string digest, the length.
pub const SLOT_W: usize = 1 + W_LIMBS + DIGEST_LANES + 1;
/// Offset of the type tag inside a slot (0 = word, 1 = string).
pub const SLOT_TAG: usize = 0;
/// Offset of the word limbs inside a slot.
pub const SLOT_W0: usize = 1;
/// Offset of the string digest inside a slot.
pub const SLOT_D0: usize = 1 + W_LIMBS;
/// Offset of the string length inside a slot.
pub const SLOT_LEN: usize = 1 + W_LIMBS + DIGEST_LANES;

/// The Poseidon2 state width the sponges run at — the tree's one permutation.
pub const SP_WIDTH: usize = 2 * RATE;

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Column layout. Every offset is COMPUTED from the one before it, so inserting a group cannot silently
// overlap another (the `§CM` class: a hand-listed column set broke sixteen tests from one cause).
// ─────────────────────────────────────────────────────────────────────────────────────────────────

pub const C_PC: usize = 0;
pub const C_OP: usize = C_PC + 1;
/// The instruction's immediate as FOUR 16-bit limbs — the whole 64-bit `PUSH_U64` literal rides the fetch bus, so the
/// word a push lands is bound to the program byte for byte. (Before 2026-09-29 only the LOW limb was fetched and the
/// other 48 bits of a pushed word were bound by nothing.) Other opcodes' immediates fit limb 0 (u16) or limbs 0–1 (u32).
pub const C_IMM: usize = C_OP + 1;
pub const C_IMM_LIMBS: usize = 4;
pub const C_SP: usize = C_IMM + C_IMM_LIMBS;
/// `sp` a second time, as a one-hot over `0..=STACK_DEPTH`, so L3's "sp ≥ pops" and "sp < STACK_DEPTH before a push"
/// are selector sums and never a range argument. `Σ s·spselₛ == C_SP` ties the two.
pub const C_SPSEL: usize = C_SP + 1;
pub const C_OPSEL: usize = C_SPSEL + STACK_DEPTH + 1;
pub const C_MICRO: usize = C_OPSEL + NOPS;
pub const C_STACK: usize = C_MICRO + NMICRO;
pub const C_LOCALS: usize = C_STACK + STACK_DEPTH * SLOT_W;
pub const C_SPSTATE: usize = C_LOCALS + LOCALS_MAX * SLOT_W;
pub const C_SPLANES: usize = C_SPSTATE + SPONGES * SP_WIDTH;
pub const C_SPFILL: usize = C_SPLANES + SPONGES * RATE;
/// A one-hot over the fill counter, so "this byte lands in lane `fill/3` at sub-position `fill%3`" is a
/// linear selection rather than a division the field cannot perform.
pub const C_FILLSEL: usize = C_SPFILL + SPONGES;
/// Distinct staged-byte counts a sponge can hold: `0..=BYTES_PER_BLOCK`. A FULL block is a state — it is the pre-state
/// of the PERM row that absorbs it (`Machine::feed_byte` permutes when `fill == BYTES_PER_BLOCK`). MEASURED 2026-09-29:
/// this was `0..BYTES_PER_BLOCK` (24 states), which no pin had reached until the first 32-byte produce (a NULLIFIER's
/// tag) filled a block; the honest PERM row carried `fill = 24` and the layout REFUSED it. The landing law never lands a
/// byte at position 24 (a FEED at a full block is impossible: the machine permutes first), so the extra state is only
/// ever the PERM row's.
pub const FILL_STATES: usize = RATE * BYTES_PER_LANE + 1;
pub const C_BYTE: usize = C_FILLSEL + SPONGES * FILL_STATES;
pub const C_BYTEBITS: usize = C_BYTE + 1;
pub const C_FEED: usize = C_BYTEBITS + 8;
/// Permutation selector: one slot per sponge plus "no sponge permutes this row".
pub const C_PERMSEL: usize = C_FEED + SPONGES;
pub const C_REMAIN: usize = C_PERMSEL + SPONGES + 1;
pub const C_SROOT: usize = C_REMAIN + 1;
pub const C_EACC: usize = C_SROOT + DIGEST_LANES;
pub const C_PSIB: usize = C_EACC + DIGEST_LANES;
pub const C_PDIR: usize = C_PSIB + DIGEST_LANES;
pub const C_POLD: usize = C_PDIR + 1;
pub const C_PNEW: usize = C_POLD + DIGEST_LANES;
/// S2 (2026-09-29) — the content-law block, replacing the 32-byte shift window `C_HB` and the truncated `C_ACC` that no
/// law read. `C_S2ACC`: the carried content accumulators ([`dsol_vm::Step::s2acc`]) — zero on the row that opens the
/// opcode's accumulating sponge, advanced by each byte's [`dsol_vm::s2_accumulate`] contribution, frozen otherwise.
/// `C_S2SCR`: per-row scratch — the one-hot of the locals index on a `LOCAL_GET` / `LOCAL_SET` row, the sixteen length
/// bits on a `BYTES_LEN` row. `C_S2INV`: per-row inverse witnesses (STR_EQ's nine, a digest producer's eight canonicity
/// inverses, U64_TO_DEC_STR's non-empty witness). `C_FB`: per sponge, "still in its first block" (1 from its open until
/// its first PERM). `C_CPH`: CONCAT's phase (0 until B opens).
pub const C_S2ACC: usize = C_PNEW + DIGEST_LANES;
pub const C_S2SCR: usize = C_S2ACC + dsol_vm::S2_ACC;
pub const S2_SCR: usize = 16;
pub const C_S2INV: usize = C_S2SCR + S2_SCR;
pub const S2_INV: usize = 9;
pub const C_FB: usize = C_S2INV + S2_INV;
pub const C_CPH: usize = C_FB + SPONGES;
pub const C_ALU_A: usize = C_CPH + 1;
pub const C_ALU_B: usize = C_ALU_A + W_LIMBS;
pub const C_ALU_R: usize = C_ALU_B + W_LIMBS;
pub const C_ALU_CARRY: usize = C_ALU_R + W_LIMBS;
pub const C_ALU_BITS: usize = C_ALU_CARRY + W_LIMBS;
/// L5 CONTROL's branch witness: `C_TAKEN` is the JUMPI decision (boolean) and `C_TAKEN_INV` the inverse of the
/// popped word's LIMB SUM `S = Σ limbₗ` (< 2^18, so `S == 0` in the field iff the word is zero — a plain field
/// reduction of the u64 would alias `p` to zero). `S · inv = taken`, `(1 − taken) · S = 0`. Zero on every other row.
/// L4b's witnesses: `C_EQINV[l]` inverts the l-th DIFFERENCE limb on an EQ row (zero when the limb is zero), and
/// `C_NZINV[0..2]` invert the two operands' LIMB SUMS (< 2^18, so a zero sum means a zero word — never a field
/// reduction of the u64) on AND / OR / NOT rows. Zero on every other row.
/// DEGREE 6 (2026-09-29): the per-limb EQ inverses became ONE limb-sum inverse plus a committed flag, and the two non-zero
/// tests commit their flags too — `all_zero = Π(1 − r_l·inv_l)` inside the landing law was per-variable degree 11 (the
/// law-degree census found it against the declared 8; it only ever verified because its excess vanished on the traces
/// proven so far); with the flags the landing law is 5. The same six columns.
pub const C_EQINV: usize = C_ALU_BITS + W_LIMBS * W_BITS;
/// `[Σ_l r_l = 0]` on an EQ row: the difference is zero iff its limb sum is (each limb is bit-ranged below 2^16, so four
/// limbs stay below 2^18 < p and the field sum is zero only when every limb is).
pub const C_EQFLAG: usize = C_EQINV + 1;
pub const C_NZINV: usize = C_EQFLAG + 1;
/// `[Σ a ≠ 0]`, `[Σ b ≠ 0]`: the committed non-zero flags of the two operands' limb sums.
pub const C_NZ: usize = C_NZINV + 2;
pub const C_TAKEN: usize = C_NZ + 2;
pub const C_TAKEN_INV: usize = C_TAKEN + 1;
/// L6's OPEN flags, one per sponge: this row's pre-state of sponge `s` is a freshly opened `init(len)` (the machine
/// resets a sponge between rows, so the reset is a flag on the first row that sees it, never a row of its own).
/// (The step COUNTER that sat here until 2026-09-29 bound the statement's PUBLIC exact row count to the trace; the exact
/// count was a branch / loop-count side channel and is private now — the statement carries the table's height class.)
pub const C_OPEN: usize = C_TAKEN_INV + 1;
/// The length of the string this opcode PRODUCES through sponge C (0 when it produces none): what sponge C opens
/// with, what `remaining` counts down from, and what the pushed string's `len` must equal.
pub const C_PLEN: usize = C_OPEN + SPONGES;
/// The shared Poseidon2 permutation block: ONE per row, serving whichever sponge or path level this row
/// drives. A block per sponge would triple the widest group in the table for no soundness gain, because
/// only one of them advances in any row.
/// L2's multiplicity column (H6, 2026-09-29): `1` on every row the trace occupies — row 0 through the RETURN's final
/// row — and `0` on every padding row after it. The fetch bus reads THIS column as the CPU side's multiplicity
/// (`BusMult::Column(C_REAL)`), tied at `r*` to the side table, so which rows are asked of the ROM is decided by the
/// laws below and never by the prover: a forged row cannot be hidden by calling it padding.
pub const C_REAL: usize = C_PLEN + 1;
/// L8 STORAGE — the access columns. `C_PPHASE`: which image this LEAF / PATH row hashes (0 pre, 1 post; a write lays
/// every level twice). `C_PPRES`: the slot exists in the pre-state (an absent slot's leaf is the empty digest and
/// reads 0). `C_PKEY`: the access key, bound to the stack operand and rebuilt from the path's direction bits.
/// `C_PVAL`: the pre-image value as `[tag, limb0..limb3]`, carried onto the FINISH row so a read's pushed result is
/// the value whose leaf was proven. `C_KACC`: per-lane key-bit accumulators (`acc' = 2·acc + bit`, MSB first).
/// `C_KLANE`: the one-hot of the lane the current level's bit belongs to, rotating one lane per level.
pub const C_PPHASE: usize = C_REAL + 1;
pub const C_PPRES: usize = C_PPHASE + 1;
pub const C_PKEY: usize = C_PPRES + 1;
pub const C_PVAL: usize = C_PKEY + DIGEST_LANES;
/// L8b part 2 — a STRING-valued slot: the pre-image string's digest and length beside `C_PVAL` (whose tag is then 1),
/// and the value half the LEAF block consumes (`dsol_vm::leaf_value_lanes`): a word's limb encoding, or the SVAL row's
/// block output carried onto the LEAF row.
pub const C_PVDIG: usize = C_PVAL + 1 + W_LIMBS;
pub const C_PVLEN: usize = C_PVDIG + DIGEST_LANES;
pub const C_PVLANES: usize = C_PVLEN + 1;
pub const C_KACC: usize = C_PVLANES + DIGEST_LANES;
pub const C_KLANE: usize = C_KACC + DIGEST_LANES;
/// L9 EFFECTS — the fold columns. `C_ESTAGE`: the one-hot of which stage of its effect's schedule ([`dsol_vm::efx_plan`])
/// an `EFX` row is. `C_ETMP` / `C_ETMP2`: the two carries an earlier stage wrote (`EfxSrc::Tmp0` / `Tmp1`), before the row.
pub const C_ESTAGE: usize = C_KLANE + DIGEST_LANES;
pub const C_ETMP: usize = C_ESTAGE + dsol_vm::EFX_STAGES_MAX;
pub const C_ETMP2: usize = C_ETMP + DIGEST_LANES;
/// L4c / L4d MULTIPLY / DIVIDE (2026-09-29) — the hidden-multiply block and its witnesses, all zero on other rows.
/// `C_MD_XBITS`: the 64 range bits of the block's first operand `X` — `A` on MUL, `R` (the quotient) on DIV, the free
/// quotient on MOD. `C_MD_BBITS`: `B`'s 64 range bits. `C_MD_BLK`: the 12-bit schoolbook `X · B`
/// ([`crate::confidential_solvency::push_mulhh_constraints`] at word width). `C_MD_REMBITS`: the remainder's 64 range
/// bits (`REM` — a witness on DIV, `R` on MOD). `C_MD_ACARRY`: the bit carries of `A = X·B + REM`. `C_MD_SLACK /
/// C_MD_BORROW / C_MD_SBITS`: the borrow chain of `B − REM − 1 ≥ 0`.
/// H1 (2026-09-29): the digest of a `PUSH_BYTES` row's literal — a ROM constant the fetch bus carries in its KEY, so
/// the string a literal lands IS the program's literal at that pc (the verifier digests it itself when it rebuilds the
/// ROM). Zero on every other row, where the ROM's literal lanes are zero too.
/// A `CALL`'s callee binding (plan item 2, 2026-09-29): `H(H(callee_storage_pre, callee_storage_post), callee_effects)`,
/// laid from the host's answer and frozen across the opcode's rows; the effects fold reads it (`EfxSrc::Callee`), and the
/// node recomputes it from the callee's statement when it authorises the call.
pub const C_CALLEE: usize = C_ETMP2 + DIGEST_LANES;
/// A `LIBCALL`'s library effects digest (the library's own `effects_digest`), frozen across the opcode's rows; the
/// library's POST root rides `C_CALLEE` on those rows and is what the caller's storage root jumps to at the FINISH.
pub const C_LIBEFX: usize = C_CALLEE + DIGEST_LANES;
/// CONTINUATIONS (plan item 5, 2026-09-29) — the boundary fold. `C_BSTATE`: the running fold before a BOUND row (zero on a
/// run's first row); the row's block absorbs group `bstage` of the carried state ([`dsol_vm::bound_lanes`] — pc, sp, the
/// stack, the locals, the storage root, the effects fold) and its output is the next row's fold. `C_BSHI` / `C_BSLO`:
/// the stage as TWO one-hots of radix 8 (`stage = 8·hi + lo`), so selecting group k is the degree-2 product
/// `hi[k / 8] · lo[k % 8]` — DEGREE 6 (2026-09-29): six stage BITS made the selector a degree-6 product, the fold-input
/// law degree 8 and cost 472 six-factor products per evaluation (a third of the relation's time); the one-hots make that
/// law degree 4 and 67 products per lane. `C_BOUT`: 0 for the in-run (opens a continued segment at row 0), 1 for the
/// out-run (closes one at the last row). `C_BEND`: the out-run's LAST row — committed as `bout · [stage = last]` (its own
/// law) so the real-flag law (H6) reads it at degree 1: written inline there it made that law degree 9 against the
/// declared 8, and the honest continued segment's proof mis-interpolated (found 2026-09-29; the row diagnostic cannot
/// see a degree). `C_WADV`: `pwrite · phase` on a PATH row (a write's post-image level) committed, so the PATH → PATH
/// laws read their stay / advance gate at degree 1 (two of them were 7). `C_DZINV`: the inverse of a decimal digit row's
/// digit (zero for the digit 0), so the "a leading zero only in the string 0" law reads `1 − digit·inv` (degree 2)
/// instead of the four-bit product (it was 8). `C_FETCH`: the fetch bus's multiplicity — `real · (1 − bound)`, so
/// boundary rows fetch no instruction.
pub const C_BSTATE: usize = C_LIBEFX + DIGEST_LANES;
pub const BSTAGE_RADIX: usize = 8;
pub const C_BSHI: usize = C_BSTATE + DIGEST_LANES;
pub const C_BSLO: usize = C_BSHI + BSTAGE_RADIX;
pub const C_BOUT: usize = C_BSLO + BSTAGE_RADIX;
pub const C_BEND: usize = C_BOUT + 1;
pub const C_WADV: usize = C_BEND + 1;
pub const C_DZINV: usize = C_WADV + 1;
/// `Σ_i sel_i · open_{acc_sponge(i)}` committed — 1 on the row where an accumulating opcode opens the sponge its content
/// accumulators follow (the machine zeroes them there), so the S2 frame's freeze law reads "the next row resets" at degree
/// 1 through `at`. Found 2026-09-29 by the row diagnostic: a digest producer opens sponge C MID-opcode, after permuting
/// sponge A, so "the previous row was final" is not the exemption — the next row's reset is, exactly as the original
/// (degree-8) frame law had it.
pub const C_S2RST: usize = C_DZINV + 1;
pub const C_FETCH: usize = C_S2RST + 1;
pub const C_LIT: usize = C_FETCH + 1;

/// The carried-state column absorbed at lane `d` of boundary group `k`, in the ONE order [`dsol_vm::bound_lanes`] lays
/// its lanes; `None` past the state (the padding lanes are zero).
#[must_use]
pub const fn bound_col(k: usize, d: usize) -> Option<usize> {
    let i = k * DIGEST_LANES + d;
    let stack_end = 2 + STACK_DEPTH * SLOT_W;
    let locals_end = stack_end + LOCALS_MAX * SLOT_W;
    if i == 0 {
        Some(C_PC)
    } else if i == 1 {
        Some(C_SP)
    } else if i < stack_end {
        Some(stack_at((i - 2) / SLOT_W, (i - 2) % SLOT_W))
    } else if i < locals_end {
        Some(local_at((i - stack_end) / SLOT_W, (i - stack_end) % SLOT_W))
    } else if i < locals_end + DIGEST_LANES {
        Some(C_SROOT + (i - locals_end))
    } else if i < locals_end + 2 * DIGEST_LANES {
        Some(C_EACC + (i - locals_end - DIGEST_LANES))
    } else {
        None
    }
}
pub const C_MD_XBITS: usize = C_LIT + DIGEST_LANES;
pub const C_MD_BBITS: usize = C_MD_XBITS + W_LIMBS * W_BITS;
pub const C_MD_BLK: usize = C_MD_BBITS + W_LIMBS * W_BITS;
/// Columns of the word-width hidden-multiply block.
pub const MD_BLK_COLS: usize = crate::confidential_solvency::mulhh_cols(W_LIMBS);
pub const C_MD_REMBITS: usize = C_MD_BLK + MD_BLK_COLS;
pub const C_MD_ACARRY: usize = C_MD_REMBITS + W_LIMBS * W_BITS;
/// The `A = X·B + REM` chain runs over EIGHT limbs (WIDE, 2026-09-29): a `DIVMOD128` dividend is 128 bits (`lo` on the
/// ALU wire, `hi` read from the stack), and on DIV / MOD / decimal rows the upper four limbs of A are zero — the chain
/// then proves the product's upper limbs zero by itself (a limb of 2^16 − 1 with a carry would need a carry OUT).
pub const C_MD_SLACK: usize = C_MD_ACARRY + 2 * W_LIMBS;
pub const C_MD_BORROW: usize = C_MD_SLACK + W_LIMBS;
pub const C_MD_SBITS: usize = C_MD_BORROW + W_LIMBS;
pub const C_P2: usize = C_MD_SBITS + W_LIMBS * W_BITS;
/// Total committed width.
pub const CPU_COLS: usize = C_P2 + crate::pow_pq_air::P2_COLS;

/// Where a stack slot's group starts.
#[must_use]
pub const fn stack_at(slot: usize, off: usize) -> usize {
    C_STACK + slot * SLOT_W + off
}
/// Where a locals slot's group starts.
#[must_use]
pub const fn local_at(slot: usize, off: usize) -> usize {
    C_LOCALS + slot * SLOT_W + off
}
/// Where sponge `s`'s permutation state starts.
#[must_use]
pub const fn sp_state(s: usize, i: usize) -> usize {
    C_SPSTATE + s * SP_WIDTH + i
}
/// Where sponge `s`'s staged rate lanes start.
#[must_use]
pub const fn sp_lane(s: usize, i: usize) -> usize {
    C_SPLANES + s * RATE + i
}
/// Sponge `s`'s fill one-hot at staged-byte count `k`.
#[must_use]
pub const fn fill_sel(s: usize, k: usize) -> usize {
    C_FILLSEL + s * FILL_STATES + k
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Reading the program. ⛔ EVERY ONE OF THESE REFUSES RATHER THAN DEFAULTING — see the module header.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The immediate a row's opcode carries: a jump target, a locals index, a syscall number, a literal
/// length, or zero for an opcode that takes none. Read from the CODE, so the fetch lookup binds it along
/// with the opcode.
///
/// `None` when the instruction is TRUNCATED. A zero here would let a truncated `JUMP` bind to target 0 —
/// a jump the program does not contain, admitted by a default.
#[must_use]
pub fn imm_of(code: &[u8], pc: u32, o: u8) -> Option<u64> {
    let at = pc as usize + 1;
    let u32_at = |at: usize| -> Option<u64> {
        code.get(at..at + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    };
    let u16_at = |at: usize| -> Option<u64> {
        code.get(at..at + 2).map(|b| u64::from(u16::from_le_bytes([b[0], b[1]])))
    };
    match o {
        op::JUMP | op::JUMPI | op::CALL | op::LIBCALL => u32_at(at),
        op::LOCAL_GET | op::LOCAL_SET | op::ALLOC_LOCALS | op::SYSCALL | op::PUSH_BYTES => u16_at(at),
        // The whole 64-bit literal. It does not fit one field element, so the ROM and the CPU row both carry it as
        // FOUR 16-bit limbs (`C_IMM_LIMBS`) and the fetch bus binds every limb — L3's PUSH law then lands exactly
        // these limbs on the stack.
        op::PUSH_U64 => code
            .get(at..at + 8)
            .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])),
        _ => Some(0),
    }
}

/// How many bytes an instruction occupies — the pc advance for a straight-line step. `None` on a
/// truncated instruction, for the same reason as [`imm_of`].
#[must_use]
pub fn op_width(code: &[u8], pc: u32, o: u8) -> Option<u32> {
    let extra = if o == op::PUSH_BYTES {
        let at = pc as usize + 1;
        u32::from(u16::from_le_bytes([*code.get(at)?, *code.get(at + 1)?]))
    } else {
        0
    };
    Some(base_width(o) as u32 + extra)
}

/// The FIXED part of an instruction's width — ONE table shared by [`op_width`] (the layout) and the L5 CONTROL law
/// (the gate), so the pc advance the circuit enforces is the pc advance the machine takes. `PUSH_BYTES` adds its
/// 16-bit length, which is its immediate (`imm_of`), on top.
#[must_use]
pub const fn base_width(o: u8) -> u64 {
    match o {
        op::PUSH_U64 => 9,
        op::JUMP | op::JUMPI | op::CALL | op::LIBCALL => 5,
        op::PUSH_BYTES | op::LOCAL_GET | op::LOCAL_SET | op::ALLOC_LOCALS | op::SYSCALL => 3,
        _ => 1,
    }
}

/// The ALU's own answer for an opcode — the ONE definition the layout and the gate share.
///
/// `None` for a division or modulus by zero. The machine refuses `DivByZero` before such a row can exist,
/// and the gate below ALSO constrains `b != 0` on those two opcodes: a layout-side refusal binds only an
/// honest prover, so the law has to live in the circuit too.
#[must_use]
pub fn alu_result(o: u8, a: u64, b: u64) -> Option<u64> {
    Some(match o {
        op::ADD_U64 => a.wrapping_add(b),
        op::SUB_U64 => a.wrapping_sub(b),
        op::MUL_U64 => a.wrapping_mul(b),
        op::MUL_HI => ((u128::from(a) * u128::from(b)) >> 64) as u64,
        op::DIV_U64 => a.checked_div(b)?,
        op::MOD_U64 => a.checked_rem(b)?,
        op::LT => u64::from(a < b),
        op::EQ => u64::from(a == b),
        op::AND => u64::from(a != 0 && b != 0),
        op::OR => u64::from(a != 0 || b != 0),
        _ => 0,
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Trace layout
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Reduce a `u64` into the field the way every other AIR in this crate does.
#[inline]
fn f(v: u64) -> Fa4 {
    Fa4::from_u64(crate::nullifier_insert_air::kred(v))
}

/// Write one slot's cells.
fn lay_slot(row: &mut [Fa4], base: usize, v: &dsol_vm::VmVal) {
    match v {
        dsol_vm::VmVal::Word(w) => {
            row[base + SLOT_TAG] = Fa4::ZERO;
            for l in 0..W_LIMBS {
                row[base + SLOT_W0 + l] = f((w >> (W_BITS * l)) & ((1 << W_BITS) - 1));
            }
            for d in 0..DIGEST_LANES {
                row[base + SLOT_D0 + d] = Fa4::ZERO;
            }
            row[base + SLOT_LEN] = Fa4::ZERO;
        }
        dsol_vm::VmVal::Str { digest, len } => {
            row[base + SLOT_TAG] = Fa4::ONE;
            for l in 0..W_LIMBS {
                row[base + SLOT_W0 + l] = Fa4::ZERO;
            }
            for d in 0..DIGEST_LANES {
                row[base + SLOT_D0 + d] = f(digest[d]);
            }
            row[base + SLOT_LEN] = f(u64::from(*len));
        }
    }
}

/// ⭐⭐⭐ LAY THE WHOLE EXECUTION INTO A COMMITTED TABLE.
///
/// `rows` must be a power of two at least as large as the trace. Rows past the end REPLICATE the final
/// row, so a row-local gate still holds on them and a transition gate sees no movement — the same
/// padding-by-replication the batch decider's own doc requires.
///
/// `None` rather than a default on ANY malformed step: an opcode with no selector, a truncated
/// instruction, an arithmetic row whose operand is a string. See the module header.
#[must_use]
pub fn build_cpu_trace(t: &VmTrace, code: &[u8], rows: usize) -> Option<Vec<Vec<Fa4>>> {
    if !rows.is_power_of_two() || t.steps.len() > rows || t.steps.is_empty() {
        return None;
    }
    let mut cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; rows]; CPU_COLS];
    let mut row = vec![Fa4::ZERO; CPU_COLS];
    for r in 0..rows {
        let s = t.steps.get(r).or_else(|| t.steps.last())?;
        lay_row(&mut row, s, code)?;
        for c in 0..CPU_COLS {
            cols[c][r] = row[c];
        }
        // the one column padding does NOT replicate: a padding row is not real
        cols[C_REAL][r] = if r < t.steps.len() { Fa4::ONE } else { Fa4::ZERO };
        // the fetch multiplicity: a real row that is not a boundary row (boundary rows fetch no instruction)
        cols[C_FETCH][r] = if r < t.steps.len() && s.micro != mk::BOUND { Fa4::ONE } else { Fa4::ZERO };
    }
    Some(cols)
}

fn lay_row(row: &mut [Fa4], s: &Step, code: &[u8]) -> Option<()> {
    row.iter_mut().for_each(|c| *c = Fa4::ZERO);
    for k in 0..SPONGES {
        row[C_OPEN + k] = if s.open[k] { Fa4::ONE } else { Fa4::ZERO };
    }
    row[C_PLEN] = f(u64::from(s.plen));
    row[C_PC] = f(u64::from(s.pc));
    row[C_OP] = f(u64::from(s.op));
    let imm = imm_of(code, s.pc, s.op)?;
    for l in 0..C_IMM_LIMBS {
        row[C_IMM + l] = f((imm >> (W_BITS * l)) & ((1 << W_BITS) - 1));
    }
    if s.op == op::PUSH_BYTES {
        // H1: the literal's digest rides the row (and the fetch-bus key) — the same digest the ROM holds for this pc
        let start = s.pc as usize + 3;
        let lit = dsol_vm::str_digest(code.get(start..start.checked_add(imm as usize)?)?);
        for d in 0..DIGEST_LANES {
            row[C_LIT + d] = f(lit[d]);
        }
    }
    row[C_SP] = f(u64::from(s.sp));
    if s.sp as usize > STACK_DEPTH {
        return None; // a depth the stack does not have is a refusal, never a default
    }
    row[C_SPSEL + s.sp as usize] = Fa4::ONE;
    row[C_OPSEL + op_index(s.op)?] = Fa4::ONE;
    if s.micro as usize >= NMICRO {
        return None;
    }
    if s.micro == mk::KEYD && keyd_operands(s).is_none() {
        return None; // L8b: a key-derivation row needs two string operands — a refusal, never a zero block
    }
    if s.micro == mk::CMT && (s.op != op::COMMIT_U64 || s.sp < 2 || s.stack[1].as_word().is_none() || s.stack[0].as_word().is_some()) {
        return None; // S2-4: a commitment row is COMMIT_U64's, over a word below a blinding string — a refusal, never a zero block
    }
    row[C_MICRO + s.micro as usize] = Fa4::ONE;
    for i in 0..STACK_DEPTH {
        lay_slot(row, stack_at(i, 0), &s.stack[i]);
    }
    for i in 0..LOCALS_MAX {
        lay_slot(row, local_at(i, 0), &s.locals[i]);
    }
    for sp in 0..SPONGES {
        for i in 0..SP_WIDTH {
            row[sp_state(sp, i)] = f(s.sponges[sp].state[i]);
        }
        for i in 0..RATE {
            row[sp_lane(sp, i)] = f(s.sponges[sp].lanes[i]);
        }
        row[C_SPFILL + sp] = f(u64::from(s.sponges[sp].fill));
        let fk = s.sponges[sp].fill as usize;
        if fk >= FILL_STATES {
            return None; // a staged count past a full block is not a state the sponge has
        }
        row[fill_sel(sp, fk)] = Fa4::ONE;
    }
    row[C_BYTE] = f(u64::from(s.byte));
    for b in 0..8 {
        row[C_BYTEBITS + b] = f(u64::from((s.byte >> b) & 1));
    }
    for sp in 0..SPONGES {
        row[C_FEED + sp] = if s.feed[sp] { Fa4::ONE } else { Fa4::ZERO };
    }
    if s.perm > SPONGES {
        return None;
    }
    row[C_PERMSEL + s.perm] = Fa4::ONE;
    row[C_REMAIN] = f(u64::from(s.remaining));
    for d in 0..DIGEST_LANES {
        row[C_SROOT + d] = f(s.storage_root[d]);
        row[C_EACC + d] = f(s.effects_acc[d]);
        row[C_PSIB + d] = f(s.path_sib[d]);
        row[C_POLD + d] = f(s.path_old[d]);
        row[C_PNEW + d] = f(s.path_new[d]);
        row[C_PKEY + d] = f(s.path_key[d]);
        row[C_KACC + d] = f(s.kacc[d]);
    }
    row[C_PDIR] = if s.path_dir { Fa4::ONE } else { Fa4::ZERO };
    row[C_PPHASE] = if s.path_phase { Fa4::ONE } else { Fa4::ZERO };
    row[C_PPRES] = if s.path_present { Fa4::ONE } else { Fa4::ZERO };
    match s.path_val {
        dsol_vm::VmVal::Word(w) => {
            row[C_PVAL] = Fa4::ZERO;
            for l in 0..W_LIMBS {
                row[C_PVAL + 1 + l] = f((w >> (W_BITS * l)) & ((1 << W_BITS) - 1));
            }
        }
        dsol_vm::VmVal::Str { digest, len } => {
            // L8b part 2: a string-valued pre-image rides as its digest and length; its value half is hashed on a SVAL row
            row[C_PVAL] = Fa4::ONE;
            for d in 0..DIGEST_LANES {
                row[C_PVDIG + d] = f(digest[d]);
            }
            row[C_PVLEN] = f(u64::from(len));
        }
    }
    if s.micro == mk::LEAF {
        // the value half this LEAF row's block consumes — ONE encoding with the machine (`leaf_value_lanes`)
        let val = if s.path_phase { s.stack[0] } else { s.path_val };
        for (d, &l) in dsol_vm::leaf_value_lanes(&val).iter().enumerate() {
            row[C_PVLANES + d] = f(l);
        }
    }
    if s.micro == mk::SVAL {
        let val = if s.path_phase { s.stack[0] } else { s.path_val };
        if !matches!(val, dsol_vm::VmVal::Str { .. }) {
            return None; // L8b: a value-half row exists only for a string value — a refusal, never a zero block
        }
    }
    if usize::from(s.klane) < DIGEST_LANES {
        row[C_KLANE + usize::from(s.klane)] = Fa4::ONE;
    }
    if usize::from(s.estage) < dsol_vm::EFX_STAGES_MAX {
        row[C_ESTAGE + usize::from(s.estage)] = Fa4::ONE;
    }
    for d in 0..DIGEST_LANES {
        row[C_ETMP + d] = f(s.etmp[0][d]);
        row[C_ETMP2 + d] = f(s.etmp[1][d]);
    }
    // S2: the content accumulators, the first-block flags and CONCAT's phase, as the machine carried them into the row
    for i in 0..dsol_vm::S2_ACC {
        row[C_S2ACC + i] = f(s.s2acc[i]);
    }
    for d in 0..DIGEST_LANES {
        row[C_CALLEE + d] = f(s.callee[d]);
        row[C_LIBEFX + d] = f(s.lib_effects[d]);
        row[C_BSTATE + d] = f(s.bstate[d]);
    }
    if usize::from(s.bstage) >= dsol_vm::BOUND_GROUPS || (s.micro != mk::BOUND && (s.bstage != 0 || s.bout)) {
        return None; // a boundary stage past the state, or boundary scratch on a row that is not a boundary row
    }
    if s.micro == mk::BOUND {
        row[C_BSHI + usize::from(s.bstage) / BSTAGE_RADIX] = Fa4::ONE;
        row[C_BSLO + usize::from(s.bstage) % BSTAGE_RADIX] = Fa4::ONE;
    }
    row[C_BOUT] = if s.bout { Fa4::ONE } else { Fa4::ZERO };
    row[C_WADV] = if s.path_phase && matches!(s.op, op::SSTORE | op::SSTORE_PRIV | op::MAP_STORE | op::MAP_STORE_PRIV) { Fa4::ONE } else { Fa4::ZERO };
    row[C_S2RST] = match dsol_vm::acc_sponge(s.op) {
        Some(sp) if s.open[sp] => Fa4::ONE,
        _ => Fa4::ZERO,
    };
    row[C_BEND] = if s.bout && usize::from(s.bstage) == dsol_vm::BOUND_GROUPS - 1 { Fa4::ONE } else { Fa4::ZERO };
    for k in 0..SPONGES {
        row[C_FB + k] = if s.fb[k] { Fa4::ONE } else { Fa4::ZERO };
    }
    row[C_CPH] = if s.cph { Fa4::ONE } else { Fa4::ZERO };
    if matches!(s.op, op::LOCAL_GET | op::LOCAL_SET) {
        // S2: the locals index as a one-hot — the immediate names a slot below LOCALS_MAX or the machine refused the run
        let k = imm as usize;
        if k >= LOCALS_MAX {
            return None;
        }
        row[C_S2SCR + k] = Fa4::ONE;
    }
    if s.op == op::BYTES_LEN {
        // S2: the top string's length as sixteen bits — the landed word's range proof (the machine's STR_BYTES_MAX is
        // 4,096, so an honest length always fits; a longer one is a refusal, never a truncation)
        let len = match s.stack[0] {
            dsol_vm::VmVal::Str { len, .. } if s.sp > 0 => u64::from(len),
            _ => return None,
        };
        if len >= 1 << S2_SCR {
            return None;
        }
        for k in 0..S2_SCR {
            row[C_S2SCR + k] = f((len >> k) & 1);
        }
    }
    if s.op == op::U64_TO_DEC_STR && s.open[dsol_vm::SPONGE_C] && s.plen != 0 {
        // S2-3: the non-empty witness on the row that opens C — the produced length's inverse (an empty decimal has none,
        // and the law refuses it: 0 · 0 ≠ 1)
        row[C_S2INV] = f(u64::from(s.plen)).inverse();
    }
    let digest_target_row = (s.op == op::POSEIDON && s.micro == mk::FINISH)
        || (s.op == op::NULLIFIER && s.micro == mk::EFX && s.estage == 2)
        || (s.op == op::COMMIT_U64 && s.micro == mk::CMT);
    if digest_target_row {
        // S2-4: the canonicity witnesses on the row whose law reads the produced lanes — the inverse of (127 − the lane's
        // top 7 bits), zero when they are all one (the law then demands zero low bits: the lane is exactly p − 1)
        for d in 0..DIGEST_LANES {
            let hi7 = s.s2acc[DIGEST_LANES + d];
            if hi7 != 127 {
                row[C_S2INV + d] = (f(127) - f(hi7)).inverse();
            }
        }
    }
    if s.op == op::STR_EQ {
        // S2: the inverse witness of ONE non-zero difference between the two strings (the eight digest lanes, then the
        // lengths) — all zero when they are equal, which is exactly when the landed `eq` may be 1
        let (a, b) = match (s.stack[0], s.stack[1]) {
            (dsol_vm::VmVal::Str { digest: da, len: la }, dsol_vm::VmVal::Str { digest: db, len: lb }) if s.sp > 1 => ((da, la), (db, lb)),
            _ => return None,
        };
        let mut diffs: Vec<Fa4> = (0..DIGEST_LANES).map(|i| f(a.0[i]) - f(b.0[i])).collect();
        diffs.push(f(u64::from(a.1)) - f(u64::from(b.1)));
        if let Some(k) = diffs.iter().position(|d| *d != Fa4::ZERO) {
            row[C_S2INV + k] = diffs[k].inverse();
        }
    }
    if s.op == op::JUMPI {
        // L5: the branch decision and its witness, from the popped WORD's limb sum — never from a field reduction of
        // the u64, which would read `p` as zero. A string condition is a refusal (`as_word` is `None`), never a default.
        let c = s.stack[0].as_word()?;
        let sum: u64 = (0..W_LIMBS).map(|l| (c >> (W_BITS * l)) & ((1 << W_BITS) - 1)).sum();
        row[C_TAKEN] = if sum != 0 { Fa4::ONE } else { Fa4::ZERO };
        row[C_TAKEN_INV] = if sum != 0 { f(sum).inverse() } else { Fa4::ZERO };
    }
    lay_alu(row, s)?;
    lay_perm(row, s);
    Some(())
}

/// The ALU operands and result for a row, in 16-bit limbs with declared carries.
///
/// ⛔ REFUSES an arithmetic row whose operand is a STRING. The first draft read such a slot as the word
/// zero, which is a silent default standing where a refusal belongs: it would lay well-formed columns for
/// a row the machine would never produce.
/// A word's limb sum as a field element's inverse (zero for the zero word): the L4b non-zero witness.
fn limb_sum_inverse(v: u64) -> Fa4 {
    let sum: u64 = (0..W_LIMBS).map(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)).sum();
    if sum == 0 { Fa4::ZERO } else { f(sum).inverse() }
}

fn lay_alu(row: &mut [Fa4], s: &Step) -> Option<()> {
    if s.op == op::NOT {
        // L4b: NOT reads one WORD (the top) and lands `a == 0`; its witness is the limb-sum inverse of `a`.
        if s.sp < 1 {
            return None;
        }
        let a = s.stack[0].as_word()?;
        for l in 0..W_LIMBS {
            row[C_ALU_A + l] = f((a >> (W_BITS * l)) & ((1 << W_BITS) - 1));
        }
        row[C_NZINV] = limb_sum_inverse(a);
        row[C_NZ] = if a != 0 { Fa4::ONE } else { Fa4::ZERO };
        return Some(());
    }
    if s.op == op::U64_TO_DEC_STR && s.micro == mk::FEED && s.feed[dsol_vm::SPONGE_C] {
        // S2-3: one digit row = one division step of the block: A = P' = 10·P + digit, X = P (the accumulator before
        // the digit), B = 10, REM = digit. A byte outside '0'..='9' or a step past a word is a refusal, never a zero block.
        let p = (0..W_LIMBS).fold(0u64, |v, l| v | (s.s2acc[l] << (W_BITS * l)));
        let digit = u64::from(s.byte).checked_sub(48).filter(|d| *d < 10)?;
        let next = p.checked_mul(10)?.checked_add(digit)?;
        let limbs = |v: u64| -> [u64; W_LIMBS] { core::array::from_fn(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)) };
        let (la, lb, lp) = (limbs(next), limbs(10), limbs(p));
        for l in 0..W_LIMBS {
            row[C_ALU_A + l] = f(la[l]);
            row[C_ALU_B + l] = f(lb[l]);
            row[C_ALU_R + l] = f(lp[l]);
        }
        lay_muldiv(row, op::U64_TO_DEC_STR, u128::from(next), 10, p)?;
        return Some(());
    }
    if lay_wide(row, s)? {
        return Some(());
    }
    let is_alu = ALU_OPS.contains(&s.op);
    if !is_alu {
        return Some(()); // the ALU group stays zero, and the gate below reads it only under `is_alu`
    }
    if s.sp < 2 {
        return None;
    }
    let b = s.stack[0].as_word()?;
    let a = s.stack[1].as_word()?;
    // L4b: LT and EQ are decided by the SUB chain, so their R is the wrapping DIFFERENCE `a − b` (its borrow-out is LT,
    // its all-zero limbs are EQ); AND / OR read the two limb-sum inverses. ADD / SUB / MUL / DIV / MOD keep R = result.
    let r = match s.op {
        op::LT | op::EQ => a.wrapping_sub(b),
        _ => alu_result(s.op, a, b)?,
    };
    let limbs =
        |v: u64| -> [u64; W_LIMBS] { core::array::from_fn(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)) };
    let (la, lb, lr) = (limbs(a), limbs(b), limbs(r));
    if s.op == op::EQ {
        // the difference's limb sum (< 2^18) and its inverse; the flag says the sum — hence the difference — is zero
        let r_sum: u64 = lr.iter().sum();
        row[C_EQINV] = if r_sum == 0 { Fa4::ZERO } else { f(r_sum).inverse() };
        row[C_EQFLAG] = if r_sum == 0 { Fa4::ONE } else { Fa4::ZERO };
    }
    if matches!(s.op, op::AND | op::OR) {
        row[C_NZINV] = limb_sum_inverse(a);
        row[C_NZINV + 1] = limb_sum_inverse(b);
        row[C_NZ] = if a != 0 { Fa4::ONE } else { Fa4::ZERO };
        row[C_NZ + 1] = if b != 0 { Fa4::ONE } else { Fa4::ZERO };
    }
    for l in 0..W_LIMBS {
        row[C_ALU_A + l] = f(la[l]);
        row[C_ALU_B + l] = f(lb[l]);
        row[C_ALU_R + l] = f(lr[l]);
        // the result's range bits are read by the compare chain (LT / EQ, `is_cmp`) and the additive chain (ADD / SUB,
        // `is_chainop`; ADC / SBB lay theirs in the wide path); on any other ALU row no law reads them, so they stay zero —
        // the free-witness census found them live on a MUL row (2026-09-29): a value the prover wrote that nothing
        // constrains is a witness with no statement. (A first cut skipped ADD / SUB too and the L4a pin refused the honest
        // sum — the chain law reads them.)
        if matches!(s.op, op::LT | op::EQ | op::ADD_U64 | op::SUB_U64) {
            for j in 0..W_BITS {
                row[C_ALU_BITS + l * W_BITS + j] = f((lr[l] >> j) & 1);
            }
        }
    }
    // Carries for the additive ops: `a + b` and `a - b` are the two the limb chain describes. The other
    // ALU opcodes are decided by their own gates and leave this chain at zero.
    let mut carry = 0u64;
    for l in 0..W_LIMBS {
        // ADD: carry out of `a + b + carry_in`. SUB: BORROW out of `a - b - borrow_in`, which is 1
        // exactly when the limb would go negative. Both are booleans, and the gate below holds them so.
        carry = match s.op {
            op::ADD_U64 => (la[l] + lb[l] + carry) >> W_BITS,
            op::SUB_U64 | op::LT | op::EQ => u64::from(la[l] < lb[l] + carry),
            _ => 0,
        };
        row[C_ALU_CARRY + l] = f(carry);
    }
    if matches!(s.op, op::MUL_U64 | op::MUL_HI | op::DIV_U64 | op::MOD_U64) {
        lay_muldiv(row, s.op, u128::from(a), b, r)?;
    }
    Some(())
}

/// WIDE (2026-09-29): the three-operand word primitives — `ADC` / `SBB` (a below b below the carry in; the L4a chain
/// with that carry in, the result and the carry out landed by their own laws) and `DIVMOD128` (hi below lo below d; the
/// L4c/d block as a division of the 128-bit dividend). Laid before the two-operand ALU path, which does not know them.
fn lay_wide(row: &mut [Fa4], s: &Step) -> Option<bool> {
    if !matches!(s.op, op::ADC | op::SBB | op::DIVMOD128) {
        return Some(false);
    }
    if s.sp < 3 {
        return None;
    }
    let top = s.stack[0].as_word()?;
    let mid = s.stack[1].as_word()?;
    let bot = s.stack[2].as_word()?;
    let limbs = |v: u64| -> [u64; W_LIMBS] { core::array::from_fn(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)) };
    if s.op == op::DIVMOD128 {
        let (d, lo, hi) = (top, mid, bot);
        if d == 0 || hi >= d {
            return None; // the machine refuses these; a row for them has no satisfying assignment
        }
        let n = (u128::from(hi) << 64) | u128::from(lo);
        let q = (n / u128::from(d)) as u64;
        let (la, lb, lq) = (limbs(lo), limbs(d), limbs(q));
        for l in 0..W_LIMBS {
            row[C_ALU_A + l] = f(la[l]);
            row[C_ALU_B + l] = f(lb[l]);
            row[C_ALU_R + l] = f(lq[l]);
        }
        lay_muldiv(row, op::DIVMOD128, n, d, q)?;
        return Some(true);
    }
    let (cin, b, a) = (top, mid, bot);
    if cin > 1 {
        return None;
    }
    let (la, lb) = (limbs(a), limbs(b));
    let mut carry = cin;
    for l in 0..W_LIMBS {
        row[C_ALU_A + l] = f(la[l]);
        row[C_ALU_B + l] = f(lb[l]);
        let (r, c) = if s.op == op::ADC {
            let t = la[l] + lb[l] + carry;
            (t & ((1 << W_BITS) - 1), t >> W_BITS)
        } else {
            let t = la[l].wrapping_sub(lb[l]).wrapping_sub(carry);
            (t & ((1 << W_BITS) - 1), u64::from(la[l] < lb[l] + carry))
        };
        row[C_ALU_R + l] = f(r);
        row[C_ALU_CARRY + l] = f(c);
        for j in 0..W_BITS {
            row[C_ALU_BITS + l * W_BITS + j] = f((r >> j) & 1);
        }
        carry = c;
    }
    Some(true)
}

/// L4c / L4d: the hidden-multiply block and its witnesses on a MUL / DIV / MOD row. `x` is the block's first operand
/// (`a` on MUL, the quotient on DIV and MOD), `rem` the remainder (`0` on MUL, where the chain is not read). `None`
/// when the row is not an integer identity `a = x·b + rem` with `rem < b` — the machine never produces such a row.
fn lay_muldiv(row: &mut [Fa4], o: u8, a: u128, b: u64, r: u64) -> Option<()> {
    use crate::confidential_solvency::{hh_cbits, hh_cols, hh_cout, hh_native, hh_obits, mulhh_p16_off, HH_BITS, HH_CARRY_BITS};
    let limbs = |v: u64| -> [u64; W_LIMBS] { core::array::from_fn(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)) };
    // A is 128 bits on a DIVMOD128 row (hi, lo) and a word everywhere else; the chain below runs over its eight limbs
    let al: [u64; 2 * W_LIMBS] = core::array::from_fn(|l| ((a >> (W_BITS * l)) & ((1 << W_BITS) - 1)) as u64);
    let (x, rem) = match o {
        op::MUL_U64 | op::MUL_HI => (u64::try_from(a).ok()?, 0u64),
        // a decimal digit row (S2-3) is a division of the next accumulator by 10: the quotient is the accumulator before
        // the digit, the remainder the digit; DIVMOD128 divides the 128-bit dividend — the quotient is the landed word
        op::DIV_U64 | op::U64_TO_DEC_STR | op::DIVMOD128 => (r, u64::try_from(a.checked_rem(u128::from(b))?).ok()?),
        op::MOD_U64 => (u64::try_from(a.checked_div(u128::from(b))?).ok()?, r),
        _ => return None,
    };
    let (xl, bl, reml) = (limbs(x), limbs(b), limbs(rem));
    if o == op::U64_TO_DEC_STR {
        // S2-3's leading-zero law reads `1 − digit·inv`: the digit is REM's low four bits (REM < 10 by the block)
        let digit = reml[0] & 0xF;
        row[C_DZINV] = if digit == 0 { Fa4::ZERO } else { f(digit).inverse() };
    }
    for l in 0..W_LIMBS {
        for j in 0..W_BITS {
            row[C_MD_XBITS + l * W_BITS + j] = f((xl[l] >> j) & 1);
            row[C_MD_BBITS + l * W_BITS + j] = f((bl[l] >> j) & 1);
            row[C_MD_REMBITS + l * W_BITS + j] = f((reml[l] >> j) & 1);
        }
    }
    let (out, cout, p16) = hh_native(&xl, &bl);
    for m in 0..hh_cols(W_LIMBS) {
        row[C_MD_BLK + m] = f(out[m]);
        row[C_MD_BLK + hh_cout(W_LIMBS) + m] = f(cout[m]);
        for t in 0..HH_BITS {
            row[C_MD_BLK + hh_obits(W_LIMBS) + m * HH_BITS + t] = f((out[m] >> t) & 1);
        }
        for t in 0..HH_CARRY_BITS {
            row[C_MD_BLK + hh_cbits(W_LIMBS) + m * HH_CARRY_BITS + t] = f((cout[m] >> t) & 1);
        }
    }
    for (q, &v) in p16.iter().enumerate() {
        row[C_MD_BLK + mulhh_p16_off(W_LIMBS) + q] = f(v);
    }
    if o != op::MUL_U64 && o != op::MUL_HI {
        let mut cin = 0u64;
        let mut bin = 0i64;
        for l in 0..2 * W_LIMBS {
            // the A = X·B + REM chain over eight limbs (REM has none above the fourth)
            let t = p16[l] + if l < W_LIMBS { reml[l] } else { 0 } + cin;
            if t & ((1 << W_BITS) - 1) != al[l] {
                return None;
            }
            cin = t >> W_BITS;
            row[C_MD_ACARRY + l] = f(cin);
        }
        for l in 0..W_LIMBS {
            let d = bl[l] as i64 - reml[l] as i64 - i64::from(l == 0) - bin;
            let (sl, bo) = if d < 0 { ((d + (1i64 << W_BITS)) as u64, 1i64) } else { (d as u64, 0i64) };
            bin = bo;
            row[C_MD_SLACK + l] = f(sl);
            row[C_MD_BORROW + l] = f(bo as u64);
            for j in 0..W_BITS {
                row[C_MD_SBITS + l * W_BITS + j] = f((sl >> j) & 1);
            }
        }
        if cin != 0 || bin != 0 || p16[2 * W_LIMBS..].iter().any(|&v| v != 0) {
            return None;
        }
    }
    Some(())
}

/// The permutation block this row drives: the sponge that permutes, or the storage level that folds, or
/// an idle block. One block, one function — the selector says which.
fn lay_perm(row: &mut [Fa4], s: &Step) {
    use p3_koala_bear::KoalaBear;
    let st: [KoalaBear; SP_WIDTH] = if s.micro == mk::PERM && s.perm < SPONGES {
        let slot = &s.sponges[s.perm];
        let mut v = slot.state;
        v[..RATE].copy_from_slice(&slot.lanes);
        core::array::from_fn(|i| KoalaBear::from_u64(v[i]))
    } else if s.micro == mk::PATH {
        // the image of this row's phase, beside its sibling on the side the key bit says
        let node = if s.path_phase { s.path_new } else { s.path_old };
        let (l, r) = if s.path_dir { (s.path_sib, node) } else { (node, s.path_sib) };
        crate::pow_pq_air::pair_state(&l, &r)
    } else if s.micro == mk::LEAF {
        // the slot leaf: the key beside the encoded value — the pre-image value (φ0) or the written stack top (φ1)
        let val = if s.path_phase { s.stack[0] } else { s.path_val };
        crate::pow_pq_air::pair_state(&s.path_key, &dsol_vm::leaf_value_lanes(&val))
    } else if s.micro == mk::EFX {
        // one block of the effects fold: the two inputs the machine resolved from the schedule (the laws re-derive them)
        crate::pow_pq_air::pair_state(&s.efx_in[0], &s.efx_in[1])
    } else if s.micro == mk::KEYD {
        // L8b: a mapped access's key derivation — (base, key) from the two string operands below the value
        match keyd_operands(s) {
            Some((base, key)) => crate::pow_pq_air::pair_state(&base, &key),
            None => unreachable!("lay_row refuses a KEYD row whose operands are not two strings before this block is laid"),
        }
    } else if s.micro == mk::SVAL {
        // L8b part 2: a string value's half — the pre-image's (φ0) or the written top's (φ1) digest beside [1, len]
        let val = if s.path_phase { s.stack[0] } else { s.path_val };
        match val {
            dsol_vm::VmVal::Str { digest, len } => crate::pow_pq_air::pair_state(&digest, &crate::poseidon2_compress::lanes_of(&[1, u64::from(len)])),
            dsol_vm::VmVal::Word(_) => unreachable!("lay_row refuses a SVAL row whose value is a word before this block is laid"),
        }
    } else if s.micro == mk::CMT {
        // S2-4: the commitment — [DOM_COMMIT, the value's four limbs] beside the blinding string's digest (sponge A, closed)
        match s.stack[1].as_word() {
            Some(value) => crate::pow_pq_air::pair_state(&dsol_vm::commit_preimage_lanes(value), &s.sponges[dsol_vm::SPONGE_A].digest()),
            None => unreachable!("lay_row refuses a CMT row whose value is not a word before this block is laid"),
        }
    } else if s.micro == mk::BOUND {
        // continuations: the boundary fold so far beside this stage's group of the carried state (the machine's lane order)
        let lanes = dsol_vm::bound_lanes(s.pc, s.sp, &s.stack, &s.locals, &s.storage_root, &s.effects_acc);
        crate::pow_pq_air::pair_state(&s.bstate, &dsol_vm::bound_group(&lanes, usize::from(s.bstage)))
    } else {
        core::array::from_fn(|_| KoalaBear::ZERO)
    };
    crate::pow_pq_air::lay_perm_row_flat(row, C_P2, st);
}

/// The `(base, key)` string digests a KEYD row hashes: MAP_LOAD reads slots 1 and 0, a MAP_STORE / MAP_STORE_PRIV reads
/// slots 2 and 1 (its value sits on top). `None` when the row is not a mapped access or an operand is not a string.
fn keyd_operands(s: &Step) -> Option<(Digest, Digest)> {
    let (b, k) = match s.op {
        op::MAP_LOAD => (1usize, 0usize),
        op::MAP_STORE | op::MAP_STORE_PRIV => (2, 1),
        _ => return None,
    };
    if usize::from(s.sp) <= b {
        return None;
    }
    let digest = |n: usize| match s.stack[n] {
        dsol_vm::VmVal::Str { digest, .. } => Some(digest),
        dsol_vm::VmVal::Word(_) => None,
    };
    Some((digest(b)?, digest(k)?))
}

#[cfg(test)]
mod layout_tests {
    use super::*;

    /// ⭐ EVERY OPCODE THE MACHINE CAN RUN HAS A SELECTOR. An opcode the machine executes and this
    /// circuit has no selector for is an opcode with NO transition law — the trace would simply fail to
    /// lay, which is fail-closed, but it means a contract that compiles cannot be proven and nobody knows
    /// why. The list is checked against the machine's own refusals rather than against a second hand list.
    #[test]
    fn every_opcode_the_machine_can_run_has_a_selector_and_the_layout_does_not_overlap() {
        // The two the machine refuses by name are the two that may be absent.
        let unprovable = [op::SHA3, op::EXT_CALL_TAIL];
        for o in [
            op::PUSH_U64, op::PUSH_BYTES, op::POP, op::DUP, op::SWAP, op::ADD_U64, op::SUB_U64,
            op::MUL_U64, op::DIV_U64, op::MOD_U64, op::LT, op::EQ, op::NOT, op::AND, op::OR, op::JUMP,
            op::JUMPI, op::RETURN, op::REVERT, op::SLOAD, op::SSTORE, op::SSTORE_PRIV, op::COMMIT_U64,
            op::NULLIFIER, op::SYSCALL, op::MSG_SENDER, op::BLOCK_NUMBER, op::CONTRACT_ID, op::TX_HASH,
            op::POSEIDON, op::EMIT, op::LOCAL_GET, op::LOCAL_SET, op::ALLOC_LOCALS, op::U64_FROM_BYTES,
            op::U64_TO_BYTES, op::MAP_LOAD, op::MAP_STORE, op::MAP_STORE_PRIV, op::BYTES_LEN,
            op::STR_EQ, op::CONCAT, op::U64_TO_DEC_STR, op::MSG_SUBADDRESS, op::MUL_HI, op::ADC, op::SBB,
            op::DIVMOD128, op::CALL, op::LIBCALL,
        ] {
            if unprovable.contains(&o) {
                continue;
            }
            assert!(
                op_index(o).is_some(),
                "⛔ opcode 0x{o:02x} runs on the machine and has NO circuit selector — a contract using \
                 it compiles and then cannot be proven, with nothing telling its author why"
            );
        }
        // The layout groups must not overlap — each offset is the previous plus its own width.
        assert!(C_P2 + crate::pow_pq_air::P2_COLS == CPU_COLS, "the P2 block ends the row");
        assert!(C_IMM + C_IMM_LIMBS == C_SP, "the four immediate limbs sit before sp");
        assert!(C_SPSEL + STACK_DEPTH + 1 == C_OPSEL, "the sp one-hot sits before the opcode selectors");
        assert!(C_ALU_BITS + W_LIMBS * W_BITS == C_EQINV, "the range bits sit before the EQ inverses");
        assert!(
            C_S2ACC == C_PNEW + DIGEST_LANES && C_S2SCR == C_S2ACC + dsol_vm::S2_ACC && C_S2INV == C_S2SCR + S2_SCR && C_FB == C_S2INV + S2_INV && C_CPH == C_FB + SPONGES && C_ALU_A == C_CPH + 1,
            "S2: accumulators, scratch, inverses, first-block flags, CONCAT's phase, then the ALU wires"
        );
        assert!(dsol_vm::S2_ACC == 2 * DIGEST_LANES && S2_SCR == LOCALS_MAX && S2_SCR == W_BITS && S2_INV == DIGEST_LANES + 1, "S2: the accumulator, scratch and inverse widths are what their laws index");
        assert!(C_EQINV + 1 == C_EQFLAG && C_EQFLAG + 1 == C_NZINV && C_NZINV + 2 == C_NZ && C_NZ + 2 == C_TAKEN, "the EQ inverse and flag, the two non-zero inverses and flags, then the L5 branch witness");
        for &o in OPS.iter() {
            assert!(dsol_vm::stack_effect(o).is_some(), "⛔ opcode 0x{o:02x} has a selector but no stack effect");
        }
        assert!(dsol_vm::stack_effect(op::SHA3).is_none() && dsol_vm::stack_effect(op::EXT_CALL_TAIL).is_none(), "the two unprovable opcodes have no stack effect");
        assert!(C_TAKEN_INV + 1 == C_OPEN, "the branch witness pair sits before the open flags (the step counter is gone: the row count is private)");
        assert!(C_OPEN + SPONGES == C_PLEN, "the open flags sit before the produced length");
        assert!(C_PLEN + 1 == C_REAL, "the produced length sits before the real-row flag");
        assert!(C_REAL + 1 == C_PPHASE, "the real-row flag sits before the storage access columns");
        assert!(C_PPHASE + 1 == C_PPRES && C_PPRES + 1 == C_PKEY, "phase, presence, then the key");
        assert!(C_PKEY + DIGEST_LANES == C_PVAL && C_PVAL + 1 + W_LIMBS == C_PVDIG && C_PVDIG + DIGEST_LANES == C_PVLEN && C_PVLEN + 1 == C_PVLANES && C_PVLANES + DIGEST_LANES == C_KACC, "the key, the tagged value, the pre-image string, the value half, the accumulators");
        assert!(C_KACC + DIGEST_LANES == C_KLANE && C_KLANE + DIGEST_LANES == C_ESTAGE, "the accumulators, the lane one-hot, then the effect stages");
        assert!(C_ESTAGE + dsol_vm::EFX_STAGES_MAX == C_ETMP && C_ETMP + DIGEST_LANES == C_ETMP2, "the stage one-hot, then the two carries");
        assert!(C_ETMP2 + DIGEST_LANES == C_CALLEE && C_CALLEE + DIGEST_LANES == C_LIBEFX && C_LIBEFX + DIGEST_LANES == C_BSTATE, "the carries, the callee binding, the library effects, then the boundary fold");
        assert!(C_BSTATE + DIGEST_LANES == C_BSHI && C_BSHI + BSTAGE_RADIX == C_BSLO && C_BSLO + BSTAGE_RADIX == C_BOUT && C_BOUT + 1 == C_BEND && C_BEND + 1 == C_WADV && C_WADV + 1 == C_DZINV && C_DZINV + 1 == C_S2RST && C_S2RST + 1 == C_FETCH && C_FETCH + 1 == C_LIT && C_LIT + DIGEST_LANES == C_MD_XBITS, "the fold, its two stage one-hots, the in/out flag, the out-run's last-row flag, the write-advance flag, the digit inverse, the accumulator-reset flag, the fetch multiplicity, the literal digest, then the multiply / divide group");
        assert!(BSTAGE_RADIX * BSTAGE_RADIX >= dsol_vm::BOUND_GROUPS && dsol_vm::BOUND_GROUPS == 59 && dsol_vm::SLOT_LANES == SLOT_W, "two radix-8 one-hots cover the 59 boundary groups; a slot's lanes are its columns");
        // the fold's column order IS the machine's lane order: every carried column appears exactly once, in place
        let mut seen = std::collections::HashSet::new();
        for k in 0..dsol_vm::BOUND_GROUPS {
            for d in 0..DIGEST_LANES {
                if let Some(c) = bound_col(k, d) {
                    assert!(seen.insert(c), "boundary column {c} absorbed twice");
                }
            }
        }
        assert_eq!(seen.len(), dsol_vm::BOUND_LANES, "the boundary fold absorbs pc, sp, every stack and local column, the root and the effects fold");
        assert!(seen.contains(&C_PC) && seen.contains(&C_SP) && seen.contains(&stack_at(15, SLOT_LEN)) && seen.contains(&local_at(15, SLOT_LEN)) && seen.contains(&(C_SROOT + 7)) && seen.contains(&(C_EACC + 7)));
        assert!(fetch_bus().sides.iter().all(|s| s.cols.len() == FETCH_KEY_LEN) && ROM_LIT + DIGEST_LANES == ROM_COLS, "the fetch key is (pc, op, imm limbs, literal lanes) on both sides, and the ROM row ends with the literal");
        assert!(C_MD_XBITS + W_LIMBS * W_BITS == C_MD_BBITS && C_MD_BBITS + W_LIMBS * W_BITS == C_MD_BLK, "X's and B's range bits, then the hidden-multiply block");
        assert!(MD_BLK_COLS == 381 && C_MD_BLK + MD_BLK_COLS == C_MD_REMBITS && C_MD_REMBITS + W_LIMBS * W_BITS == C_MD_ACARRY, "the block (12 columns × 31 + 9 re-limbed limbs), the remainder's bits, the carries");
        assert!(C_MD_ACARRY + 2 * W_LIMBS == C_MD_SLACK && C_MD_SLACK + W_LIMBS == C_MD_BORROW && C_MD_BORROW + W_LIMBS == C_MD_SBITS, "eight chain carries, slack, borrows, slack bits");
        assert!(crate::confidential_solvency::hh_p16(W_LIMBS) == 2 * W_LIMBS + 1, "the 64×64 block re-limbs its product to nine 16-bit limbs: eight for the 128-bit product, one always zero");
        assert!(C_MD_SBITS + W_LIMBS * W_BITS == C_P2, "the multiply / divide group sits before the P2 block");
        assert!(NMICRO == 11 && (mk::EFX as usize) < NMICRO && (mk::LEAF as usize) < NMICRO && (mk::KEYD as usize) < NMICRO && (mk::CMT as usize) < NMICRO && (mk::BOUND as usize) < NMICRO && (mk::SVAL as usize) < NMICRO, "every micro kind the machine emits has a selector");
        for o in [op::NULLIFIER, op::EMIT, op::SYSCALL, op::SSTORE_PRIV, op::MAP_STORE_PRIV, op::CALL, op::LIBCALL] {
            let plan = dsol_vm::efx_plan(o);
            assert!(!plan.is_empty() && plan.len() <= dsol_vm::EFX_STAGES_MAX, "every effect opcode has a schedule within the stage width");
            assert!(plan.last().map(|s| s.out) == Some(dsol_vm::EfxDst::Acc), "a schedule's LAST stage folds the accumulator");
            assert!(plan[..plan.len() - 1].iter().all(|s| s.out != dsol_vm::EfxDst::Acc), "and only the last stage does");
        }
        assert!(C_P2 + crate::pow_pq_air::P2_COLS == CPU_COLS, "the P2 block is the row's tail, so `local.suffix(C_P2)` is exactly one block");
        assert!(C_STACK + STACK_DEPTH * SLOT_W == C_LOCALS, "the stack does not run into the locals");
        eprintln!(
            "[dsol-cpu] CPU_COLS = {CPU_COLS} (stack {} + locals {} + sponges {} + P2 {})",
            STACK_DEPTH * SLOT_W,
            LOCALS_MAX * SLOT_W,
            SPONGES * (SP_WIDTH + RATE + 1),
            crate::pow_pq_air::P2_COLS
        );
        assert!(
            CPU_COLS <= crate::whir_rec_block::AIR_DIRECT_MAX_WIDTH,
            "the VM row must fit the widest carrier this verifier decodes"
        );
    }

    /// ⭐ A REAL EXECUTION LAYS INTO THE TABLE — and the ALU refusals actually fire.
    #[test]
    fn a_real_execution_lays_into_a_power_of_two_table() {
        let code = {
            let mut out = vec![dsol_vm::DSOL_VERSION];
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
            out.extend_from_slice(&13u32.to_le_bytes());
            out.push(op::POP);
            out.push(op::PUSH_U64);
            out.extend_from_slice(&7u64.to_le_bytes());
            out.push(op::PUSH_U64);
            out.extend_from_slice(&6u64.to_le_bytes());
            out.push(op::MUL_U64);
            out.push(op::RETURN);
            out
        };
        let t = dsol_vm::run(
            &code,
            "main",
            b"",
            dsol_vm::VmCtx::default(),
            dsol_vm::StorageTrie::default(),
            1 << 16,
            &mut dsol_vm::NoHost,
        )
        .expect("the program runs");
        let rows = t.steps.len().next_power_of_two().max(32);
        let cols = build_cpu_trace(&t, &code, rows).expect("an honest execution lays out");
        assert_eq!(cols.len(), CPU_COLS, "every column is present");
        assert_eq!(cols[0].len(), rows, "the table is a power of two tall");
        // The MUL row really carries its operands as limbs — a table that laid zeros would prove nothing.
        let mul = t.steps.iter().position(|s| s.op == op::MUL_U64).expect("the program multiplies");
        assert_eq!(cols[C_ALU_A][mul], f(7), "operand a is the value under the top");
        assert_eq!(cols[C_ALU_B][mul], f(6), "operand b is the top of the stack");
        assert_eq!(cols[C_ALU_R][mul], f(42), "and the result limb is the product");
        eprintln!("[dsol-cpu] a {}-step execution laid into {rows} x {CPU_COLS}", t.steps.len());
    }

    /// ⛔ THE THREE SILENT DEFAULTS, REFUSED. Each one was in the first draft of this file as a `0`.
    #[test]
    fn a_malformed_row_is_refused_rather_than_defaulted() {
        // A truncated JUMP has no immediate — a zero here would bind it to target 0.
        assert_eq!(imm_of(&[op::JUMP, 1, 2], 0, op::JUMP), None, "a truncated jump has no immediate");
        assert_eq!(op_width(&[op::PUSH_BYTES], 0, op::PUSH_BYTES), None, "a truncated literal has no width");
        // Division by zero has no answer — not zero.
        assert_eq!(alu_result(op::DIV_U64, 10, 0), None, "div by zero is refused");
        assert_eq!(alu_result(op::MOD_U64, 10, 0), None, "mod by zero is refused");
        assert_eq!(alu_result(op::DIV_U64, 10, 3), Some(3), "and the honest case still answers");
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────────
// THE CPU ROW RELATION — the laws as ONE γ-batched constraint over a CPU row
// ───────────────────────────────────────────────────────────────────────────────────────────────────

use crate::air_zerocheck::{AirConstraint, Row};
use crate::hiding_decider::Ea4;

/// The DSOL CPU row relation: the module doc's laws, γ-batched Horner-style (`acc = acc·γ + residual`, one γ-power
/// per residual, so Schwartz–Zippel bounds a forgery in ANY single residual — the batching
/// [`crate::sponge_chain_air::SpongeChainConstraint`] uses).
///
/// ⛔ LANDED LAWS, HONESTLY NAMED (2026-09-29): **L1 SELECTORS**, **L2 FETCH** (the bus, the H5 ROM law, the H6
/// multiplicity column), **L3 STACK**, **L4a ADD/SUB**, **L4b LT/EQ/AND/OR/NOT**, **L4c/L4d MUL/DIV/MOD** (the hidden
/// multiply at word width, below), **L5 CONTROL**, **L6 SPONGES**, **L7 PACKING**, **L8a STORAGE** (word slots), **L9
/// EFFECTS**, **L10 BOUNDARY**, **H1** (a PUSH_BYTES literal is the program's: its digest rides the ROM row and the
/// fetch-bus key) and **H4** (the whole call context — `cid`, caller, subaddress, tx hash, block number — is in the
/// statement and each context opcode lands it), **L9b** (a SYSCALL's result is produced through sponge C and its effect
/// reads that digest), **L8b** (a `MAP_*` slot key is derived in-circuit on the access's KEYD row; a STRING value's leaf
/// half is hashed on a SVAL row and a read lands the string), **S2** (the content laws, 2026-09-29: the produce COUNT and
/// CONCAT's ORDER, LOCALS, the word ↔ bytes conversions, BYTES_LEN, STR_EQ, the decimal string as one division step per
/// digit, and the digest producers' canonical byte forms with COMMIT_U64's own CMT row — the census that found the eight
/// unbound relations is in the plan doc). Each law lands with its RED-first tamper pin (`l1_…`, `l3_…`, `l4a_…`, `l4b_…`,
/// `l4cd_…`, `l5_…`, `h1_…`, `h4_…`, `l9b_…`, `l8b_…`, `s2_…`).
///
/// # L3 STACK
/// A row's stack columns are the PRE-state of its opcode (the machine records the row, then pops and pushes). On an
/// opcode's final row the next row's stack is this row's moved by `dsol_vm::stack_effect(op) = (pops, pushes)`: slots
/// `k ≥ pushes` come from slot `k + pops − pushes` (ZERO word from below the bottom), `sp` moves by `pushes − pops`,
/// `sp ≥ pops` and no push at a full stack (both read off the sp one-hot), SWAP permutes the top two, and non-final
/// rows freeze everything. The pushed VALUE (slot 0) is each opcode's own law: PUSH_U64 lands the four fetched limbs as
/// a WORD, DUP a copy of the top, ADD/SUB their result (L4a). Every other slot-0 value is still open.
///
/// # L4a ALU — ADD / SUB (the two the limb-carry chain describes)
/// On an `ADD_U64` / `SUB_U64` row: the operand limbs `A`, `B` are the two top stack slots (`a` below, `b` on top),
/// both tagged WORD; each carry (borrow) is a bit; `aₗ + bₗ + cₗ₋₁ = rₗ + 2¹⁶·cₗ` (SUB: `aₗ − bₗ − cₗ₋₁ = rₗ − 2¹⁶·cₗ`),
/// the top carry dropped (wrapping); every result limb is recomposed from its own 16 booleans, which IS its range
/// proof; and the result lands on the NEXT row's top slot as a WORD. LT/EQ/AND/OR/NOT ride L4b (the SUB chain and
/// limb-sum inverses); MUL/DIV/MOD ride L4c/L4d.
///
/// # L4c / L4d ALU — MUL / DIV / MOD (the hidden multiply at word width)
/// On a `MUL_U64` / `DIV_U64` / `MOD_U64` row the operands `A`, `B` are the two top stack slots, both WORDS; `B`'s 64
/// range bits recompose to `B`; the block `C_MD_BLK` is [`crate::confidential_solvency::push_mulhh_constraints`] over
/// `X`'s and `B`'s range bits (12-bit limbs, integer column identities, the product re-limbed to 16 bits). MUL: `X = A`
/// and `R` is the product's low four limbs (wrapping — the high half is not pinned). DIV / MOD: `A = X·B + REM` as a
/// bit-carry limb chain with no carry out, the product's upper limbs zero, and `B − REM − 1 ≥ 0` as a borrow chain with
/// a range-bound slack and no borrow out (so `REM < B` and `B ≠ 0`); DIV lands `X`, MOD lands `REM`. The result lands
/// on the NEXT row's top slot as a WORD.
///
/// # L1 SELECTORS
/// * every opcode selector `C_OPSEL + i` is boolean, exactly one is set, and `Σ selᵢ · OPS[i] == C_OP` — so the opcode
///   the transition laws key on IS the opcode the fetch bus checked against the program;
/// * every micro-step selector `C_MICRO + k` is boolean and exactly one is set (the one-hot IS the micro encoding;
///   there is no separate micro column to disagree with).
///
/// Without L1 a prover blends two opcodes' (or two micro-steps') transition rules and lands on a state neither allows.
/// Padding rows replicate the final row (`build_cpu_trace`), so a row-local law holds on them unchanged.
///
/// # L5 CONTROL (a transition law: reads the NEXT row's `pc`, `op`, `imm`)
/// * a multi-row opcode's non-final rows (FEED / PERM / PATH) freeze `pc`, `op`, `imm` into the next row;
/// * on an opcode's final row (PLAIN / FINISH) the next `pc` is `pc + width`, with `width = base_width(op)` plus the
///   16-bit length for `PUSH_BYTES` — ONE table with the layout's `op_width`;
/// * `JUMP`: next `pc = imm`. `JUMPI`: the popped slot is a WORD, its limb sum `S` decides `taken` through the witnessed
///   non-zero test `S·inv = taken`, `(1−taken)·S = 0`, and next `pc = taken·imm + (1−taken)·(pc+5)`;
/// * `RETURN` / `REVERT` impose nothing forward (they end the trace; L10 pins the boundary), and every transition is
///   gated by `is_trans = 1 − Π xₖ` so the cyclic wrap from the last row to row 0 imposes nothing.
///
/// Without L5 a prover skips or repeats instructions, takes a branch on a zero condition, or lands anywhere.
pub struct DsolCpuConstraint {
    pub gamma: Ea4,
    /// The statement this call is proven under — L10 reads its values at row 0 and the last row, and the
    /// transcript binds the same values (`DsolStatement::bind`), so gate and bind cannot disagree.
    pub stmt: DsolStatement,
    /// The Poseidon2 block law over the row's tail (`local.suffix(C_P2)`), under the production constants — the same
    /// permutation the machine's sponges run (`sponge_chain_air::p2_block_constraint`). L6 binds its input to a
    /// permuting sponge's `lanes ‖ capacity` and the next state to its output; L8 will bind it to a path level.
    pub p2: crate::whole_chain::WholeChainMainConstraint,
    /// `γ^0 … γ^LAW_CAPACITY` ([`gamma_powers`]): the j-th law takes γ^j, the block γ^LAW_CAPACITY.
    pub gpow: Vec<Ea4>,
}

#[cfg(test)]
thread_local! {
    /// The row-level diagnostic's recorder (`first_unsatisfied_row`): while armed, every NON-ZERO residual the CPU relation
    /// folds is noted with the source line of the law that pushed it.
    static RESIDUAL_PROBE: std::cell::RefCell<Option<Vec<(u32, Ea4)>>> = const { std::cell::RefCell::new(None) };
}

/// Whether any probe is armed — one relaxed load per law when it is not, so a test-build measurement of the relation's
/// cost (the perf pin) is the production cost and not 6,000 thread-local lookups per row.
#[cfg(test)]
static PROBE_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Census mode: record EVERY residual, zero ones included, so a law whose residual is identically zero — a law that
/// constrains nothing — is visible as a run of zeros instead of an absence.
#[cfg(test)]
static PROBE_ZEROS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Arm the residual probe on this thread: every non-zero residual folded from now on is recorded with its source line.
#[cfg(test)]
fn probe_arm() {
    RESIDUAL_PROBE.with(|p| *p.borrow_mut() = Some(Vec::new()));
    PROBE_ZEROS.store(false, std::sync::atomic::Ordering::Relaxed);
    PROBE_ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Arm the probe in census mode: every residual is recorded, zero or not, in push order.
#[cfg(test)]
fn probe_arm_all() {
    RESIDUAL_PROBE.with(|p| *p.borrow_mut() = Some(Vec::new()));
    PROBE_ZEROS.store(true, std::sync::atomic::Ordering::Relaxed);
    PROBE_ARMED.store(true, std::sync::atomic::Ordering::Relaxed);
}

/// Disarm the probe and hand back what it recorded, in push order.
#[cfg(test)]
fn probe_take() -> Vec<(u32, Ea4)> {
    PROBE_ARMED.store(false, std::sync::atomic::Ordering::Relaxed);
    PROBE_ZEROS.store(false, std::sync::atomic::Ordering::Relaxed);
    RESIDUAL_PROBE.with(|p| p.borrow_mut().take()).expect("the probe was armed")
}

/// Note one folded residual for the diagnostic — a no-op outside test builds, one relaxed load when no probe is armed.
#[inline(always)]
fn residual_probe(line: u32, r: Ea4) {
    #[cfg(test)]
    if PROBE_ARMED.load(std::sync::atomic::Ordering::Relaxed) {
        let zeros = PROBE_ZEROS.load(std::sync::atomic::Ordering::Relaxed);
        RESIDUAL_PROBE.with(|p| {
            if let Some(v) = p.borrow_mut().as_mut() {
                if zeros || r != Ea4::ZERO {
                    v.push((line, r));
                }
            }
        });
    }
    #[cfg(not(test))]
    {
        let _ = (line, r);
    }
}

/// The CPU relation's own per-variable degree — MEASURED by the law-degree census (`every_law_stays_within_the_declared_degree`:
/// forward differences along a random line, every law by source line) and asserted by the DEBUG prover on every zerocheck
/// round. The maximum is 6: L7's lane landing `is_trans · (1 − next_open) · [(1 − perm)·lane + feed · byte · fillsel]`, the
/// L9 effect-stage laws, the PATH → PATH laws, the S2 frame. The zerocheck samples `degree + 2` points per round, so this
/// number is the prover's cost knob: 10 → 8 samples on 2026-09-29 (−20 % of the zerocheck). It had been 8 through a
/// literal on the Poseidon2 block (whose laws are degree 3); the census also found one law at 11 (the logic landing's
/// `Π(1 − r_l·inv_l)`) that had only ever verified because its excess vanished on the traces proven so far.
pub const DSOL_LAW_DEGREE: usize = 6;

impl AirConstraint for DsolCpuConstraint {
    fn degree(&self, nvars: usize) -> usize {
        self.p2.degree(nvars).max(DSOL_LAW_DEGREE)
    }
    /// L5 reads the next row's `pc`, `op`, `imm` — declared here so the prover folds exactly those three shifted
    /// columns (an undeclared `at` panics the prove, never stands over a stale value).
    fn is_row_local(&self) -> bool {
        false
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        // L5: pc / op / the four imm limbs. L3: sp and EVERY stack slot column (the shift law reads the whole next
        // stack). L4a's landing slot is inside the stack range. L10: the step counter. L6/L7: every sponge's state,
        // lanes, fill and open flag, the produce countdown and length. L2/H6: the real-row flag.
        let mut v = vec![C_PC, C_OP, C_SP, C_REMAIN, C_PLEN, C_REAL, C_PDIR, C_PPHASE, C_PPRES];
        v.extend((0..C_IMM_LIMBS).map(|l| C_IMM + l));
        // L8: the next row's opcode selectors and micro kind (a storage opcode's run must start on a LEAF row and a path
        // must exit into its FINISH), the storage root, the path images, the key, the tagged value, the accumulators
        v.extend(C_OPSEL..C_OPSEL + NOPS);
        v.extend(C_MICRO..C_MICRO + NMICRO);
        v.extend(C_SROOT..C_SROOT + DIGEST_LANES);
        v.extend(C_PSIB..C_PSIB + DIGEST_LANES);
        v.extend(C_POLD..C_POLD + DIGEST_LANES);
        v.extend(C_PNEW..C_PNEW + DIGEST_LANES);
        v.extend(C_PKEY..C_PKEY + DIGEST_LANES);
        v.extend(C_PVAL..C_PVAL + 1 + W_LIMBS);
        // L8b part 2: the pre-image string's digest and length, and the value half a SVAL row hands its LEAF row
        v.extend(C_PVDIG..C_PVDIG + DIGEST_LANES);
        v.push(C_PVLEN);
        v.extend(C_PVLANES..C_PVLANES + DIGEST_LANES);
        v.extend(C_KACC..C_KACC + DIGEST_LANES);
        v.extend(C_KLANE..C_KLANE + DIGEST_LANES);
        // L9: the effects accumulator, the stage one-hot and the two carries
        v.extend(C_EACC..C_EACC + DIGEST_LANES);
        v.extend(C_ESTAGE..C_ESTAGE + dsol_vm::EFX_STAGES_MAX);
        v.extend(C_ETMP..C_ETMP + DIGEST_LANES);
        v.extend(C_ETMP2..C_ETMP2 + DIGEST_LANES);
        v.extend(C_CALLEE..C_CALLEE + DIGEST_LANES); // a CALL's callee binding / a LIBCALL's post root is frozen across its rows
        v.extend(C_LIBEFX..C_LIBEFX + DIGEST_LANES); // a LIBCALL's library effects digest is frozen across its rows
        // continuations: the boundary fold advances, the stage counts, the in/out flag holds, the next micro kind and
        // real flag decide a run's edges
        v.extend(C_BSTATE..C_BSTATE + DIGEST_LANES);
        v.extend(C_BSHI..C_BSHI + 2 * BSTAGE_RADIX);
        v.push(C_S2RST); // the S2 frame's freeze law is exempt into a row that resets the accumulators
        v.push(C_BOUT);
        v.extend(C_STACK..C_STACK + STACK_DEPTH * SLOT_W);
        v.extend(C_SPSTATE..C_SPSTATE + SPONGES * SP_WIDTH);
        v.extend(C_SPLANES..C_SPLANES + SPONGES * RATE);
        v.extend(C_SPFILL..C_SPFILL + SPONGES);
        v.extend(C_OPEN..C_OPEN + SPONGES);
        // S2: the content accumulators (the frame reads the next row's), the first-block flags, CONCAT's phase, and
        // EVERY locals column (the locals frame reads the whole next locals array)
        v.extend(C_S2ACC..C_S2ACC + dsol_vm::S2_ACC);
        v.extend(C_FB..C_FB + SPONGES);
        v.push(C_CPH);
        v.extend(C_LOCALS..C_LOCALS + LOCALS_MAX * SLOT_W);
        Some(v)
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        self.eval_in::<Ea4>(local, at, x)
    }
    fn has_base_eval(&self) -> bool {
        true
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let at2 = |c: usize, _p: &[Fa4]| -> Fa4 { at(c) };
        self.eval_in::<Fa4>(local, &at2, x)
    }
}

/// The extension field the γ-batched value lives in — named apart from the laws' field in [`DsolCpuConstraint::eval_in`].
type Ext = crate::hiding_decider::Ea4;

/// Powers of γ available to the laws: the census counts ~6,800 pushes per row; a push past this is a panic, never a
/// silent wrap, and the census asserts the count stays below it.
pub const LAW_CAPACITY: usize = 8192;

/// `γ^0 … γ^LAW_CAPACITY`, computed once per gate.
#[must_use]
pub fn gamma_powers(gamma: Ext) -> Vec<Ext> {
    let mut v = Vec::with_capacity(LAW_CAPACITY + 1);
    let mut p = Ext::ONE;
    for _ in 0..=LAW_CAPACITY {
        v.push(p);
        p *= gamma;
    }
    v
}

impl DsolCpuConstraint {
    /// ⭐ THE RELATION, GENERIC OVER THE FIELD ITS ROW LIVES IN — instantiated at `Ea4` (the verifier, the row diagnostic,
    /// the prover's rounds ≥ 1) and at `Fa4` (the prover's round 0, whose folded rows are base-field at the integer sample
    /// points). The type parameter is NAMED `Ea4` on purpose: the two thousand lines of laws below were written against the
    /// extension type and read unchanged in both instantiations — every `Ea4::ONE`, `Ea4::from_u64`, `-> Ea4` is the row's
    /// field. What is NOT the row's field is the batched value: `Ext` (the real extension), which the laws' residuals enter
    /// through extension-by-base products (`Ext: Algebra<Ea4>`), so a base-field row costs base-field arithmetic (MEASURED
    /// 2026-09-29: sixteen base multiplies per extension multiply).
    ///
    /// BATCHING: `acc = block · γ^LAW_CAPACITY + Σ_j γ^j · r_j` — the j-th push takes γ^j from the precomputed table, and the
    /// Poseidon2 block (itself γ-batched over its own roots) sits above every law's power, so no law's residual can cancel
    /// a block constraint's (disjoint powers). Prover and verifier evaluate this same function, so the value is the same
    /// on both sides, and identical whether the row came lifted or base.
    #[allow(non_camel_case_types)]
    pub fn eval_in<Ea4>(&self, local: &Row<'_, Ea4>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ext
    where
        Ea4: Field + p3_field::Algebra<Fa4>,
        Ext: p3_field::Algebra<Ea4>,
    {
        // The Poseidon2 block law first, on the row's tail, lifted to the extension (its compiled tape is extension-typed)
        // under the row's own out-of-range latch.
        let mut p2_vals = [Ext::ZERO; crate::pow_pq_air::P2_COLS];
        for (i, v) in p2_vals.iter_mut().enumerate() {
            *v = Ext::from(local[C_P2 + i]);
        }
        let p2_row = Row::new(&p2_vals, local.latch());
        let at_p2 = |c: usize, _p: &[Ext]| -> Ext { Ext::from(at(c + C_P2, &[])) };
        let x_ext: Vec<Ext> = x.iter().map(|v| Ext::from(*v)).collect();
        let mut acc = self.p2.eval(&p2_row, &at_p2, &x_ext) * self.gpow[LAW_CAPACITY];
        // every law is folded through here with the SOURCE LINE of its push, so the row-level diagnostic can name the
        // law that refused an honest row — not "a law fired somewhere" (the probe records only in test builds); the j-th
        // push takes γ^j
        let next_pow = core::cell::Cell::new(0usize);
        let gpow = &self.gpow;
        let push = |acc: &mut Ext, line: u32, r: Ea4| {
            residual_probe(line, Ext::from(r));
            let j = next_pow.get();
            next_pow.set(j + 1);
            *acc += gpow[j] * r;
        };
        // ── L1 SELECTORS ──────────────────────────────────────────────────────────────────────
        let mut sum = Ea4::ZERO;
        let mut code = Ea4::ZERO;
        for (i, &o) in OPS.iter().enumerate() {
            let s = local[C_OPSEL + i];
            push(&mut acc, line!(),s * (Ea4::ONE - s)); // boolean
            sum += s;
            code += s * Ea4::from_u64(u64::from(o));
        }
        push(&mut acc, line!(),sum - Ea4::ONE); // exactly one
        push(&mut acc, line!(),code - local[C_OP]); // and it names the opcode the fetch bus checked
        let mut msum = Ea4::ZERO;
        for k in 0..NMICRO {
            let m = local[C_MICRO + k];
            push(&mut acc, line!(),m * (Ea4::ONE - m));
            msum += m;
        }
        push(&mut acc, line!(),msum - Ea4::ONE);

        // ── L5 CONTROL ────────────────────────────────────────────────────────────────────────
        let mut is_last = Ea4::ONE;
        for &xk in x {
            is_last *= xk;
        }
        let is_trans = Ea4::ONE - is_last;
        let micro = |k: u8| local[C_MICRO + k as usize];
        let sel = |o: u8| local[C_OPSEL + op_index(o).expect("every control opcode is in OPS")];
        let cont = micro(mk::FEED) + micro(mk::PERM) + micro(mk::PATH) + micro(mk::LEAF) + micro(mk::EFX) + micro(mk::KEYD) + micro(mk::SVAL) + micro(mk::CMT) + micro(mk::BOUND);
        let final_row = micro(mk::PLAIN) + micro(mk::FINISH);
        let (pc, opc) = (local[C_PC], local[C_OP]);
        let (npc, nop) = (at(C_PC, &[]), at(C_OP, &[]));
        let imm_l: [Ea4; C_IMM_LIMBS] = core::array::from_fn(|l| local[C_IMM + l]);
        // a u32 immediate (jump targets) is limbs 0–1; a u16 one (lengths, indices) is limb 0
        let imm = imm_l[0] + imm_l[1] * Ea4::from_u64(1 << W_BITS);
        // (i) a multi-row opcode continues: pc, op, imm are frozen until its final row. A boundary in-run's EXIT into the
        //     instruction it resumes keeps pc and frees op / imm (the resumed instruction fetches its own; the BOUND
        //     pseudo-opcode is never fetched).
        let bound_exit = micro(mk::BOUND) * (Ea4::ONE - at(C_MICRO + mk::BOUND as usize, &[]));
        push(&mut acc, line!(),is_trans * cont * (npc - pc));
        push(&mut acc, line!(),is_trans * cont * (Ea4::ONE - bound_exit) * (nop - opc));
        for l in 0..C_IMM_LIMBS {
            push(&mut acc, line!(),is_trans * cont * (Ea4::ONE - bound_exit) * (at(C_IMM + l, &[]) - imm_l[l]));
        }
        // (ii) the JUMPI decision is a witnessed non-zero test of the popped WORD's limb sum
        let sel_ji = sel(op::JUMPI);
        let slot0 = stack_at(0, 0);
        let mut s_sum = Ea4::ZERO;
        for l in 0..W_LIMBS {
            s_sum += local[slot0 + SLOT_W0 + l];
        }
        let taken = local[C_TAKEN];
        let inv = local[C_TAKEN_INV];
        push(&mut acc, line!(),sel_ji * local[slot0 + SLOT_TAG]); // the condition is a WORD (tag 0)
        push(&mut acc, line!(),sel_ji * taken * (Ea4::ONE - taken));
        push(&mut acc, line!(),sel_ji * (s_sum * inv - taken));
        push(&mut acc, line!(),sel_ji * (Ea4::ONE - taken) * s_sum);
        // (iii) pc advance on an opcode's final row: straight-line by the instruction's own width, JUMP to imm,
        //       JUMPI by the decision; RETURN / REVERT impose nothing forward
        let mut straight = Ea4::ZERO;
        for (i, &o) in OPS.iter().enumerate() {
            if matches!(o, op::JUMP | op::JUMPI | op::RETURN | op::REVERT) {
                continue;
            }
            let mut width = Ea4::from_u64(base_width(o));
            if o == op::PUSH_BYTES {
                width += imm_l[0]; // the u16 length
            }
            straight += local[C_OPSEL + i] * (npc - pc - width);
        }
        push(&mut acc, line!(),is_trans * final_row * straight);
        // a jump target is a u32: limbs 2 and 3 of its immediate are zero
        let sel_j = sel(op::JUMP);
        push(&mut acc, line!(),(sel_j + sel_ji) * imm_l[2]);
        push(&mut acc, line!(),(sel_j + sel_ji) * imm_l[3]);
        push(&mut acc, line!(),is_trans * sel_j * (npc - imm));
        push(
            &mut acc,
            line!(),
            is_trans * sel_ji * (npc - taken * imm - (Ea4::ONE - taken) * (pc + Ea4::from_u64(5))),
        );

        // ── L4a ALU: ADD / SUB ────────────────────────────────────────────────────────────────
        let sel_add = sel(op::ADD_U64);
        let sel_sub = sel(op::SUB_U64);
        let is_addsub = sel_add + sel_sub;
        // WIDE (2026-09-29): ADC / SBB run the SAME chain with the carry / borrow IN read from the top word (0 or 1) and
        // the carry / borrow OUT landed beside the result — the primitives multi-precision code is built from
        let (sel_adc, sel_sbb) = (sel(op::ADC), sel(op::SBB));
        let is_adcsbb = sel_adc + sel_sbb;
        let is_chainop = is_addsub + is_adcsbb;
        let (s0, s1, s2) = (stack_at(0, 0), stack_at(1, 0), stack_at(2, 0));
        push(&mut acc, line!(),is_addsub * local[s0 + SLOT_TAG]); // b (top) is a WORD
        push(&mut acc, line!(),is_addsub * local[s1 + SLOT_TAG]); // a (below) is a WORD
        push(&mut acc, line!(),is_adcsbb * local[s0 + SLOT_TAG]); // ADC / SBB: the carry in (top), b, a are WORDS ...
        push(&mut acc, line!(),is_adcsbb * local[s1 + SLOT_TAG]);
        push(&mut acc, line!(),is_adcsbb * local[s2 + SLOT_TAG]);
        let cin = local[s0 + SLOT_W0];
        push(&mut acc, line!(),is_adcsbb * cin * (Ea4::ONE - cin)); // ... and the carry in is 0 or 1
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),is_adcsbb * local[s0 + SLOT_W0 + l]);
        }
        let two16 = Ea4::from_u64(1 << W_BITS);
        let mut carry_in = is_adcsbb * cin;
        for l in 0..W_LIMBS {
            let a = local[C_ALU_A + l];
            let b = local[C_ALU_B + l];
            let r = local[C_ALU_R + l];
            let c = local[C_ALU_CARRY + l];
            push(&mut acc, line!(),is_addsub * (a - local[s1 + SLOT_W0 + l])); // the operands ARE the stack's words
            push(&mut acc, line!(),is_addsub * (b - local[s0 + SLOT_W0 + l]));
            push(&mut acc, line!(),is_adcsbb * (a - local[s2 + SLOT_W0 + l])); // ADC / SBB: a below b below the carry
            push(&mut acc, line!(),is_adcsbb * (b - local[s1 + SLOT_W0 + l]));
            push(&mut acc, line!(),is_chainop * c * (Ea4::ONE - c)); // a carry / borrow is a bit
            push(&mut acc, line!(),(sel_add + sel_adc) * (a + b + carry_in - r - two16 * c));
            push(&mut acc, line!(),(sel_sub + sel_sbb) * (a - b - carry_in - r + two16 * c));
            // the result limb is recomposed from its own 16 bits — that recomposition IS its range proof
            let mut rec = Ea4::ZERO;
            for j in 0..W_BITS {
                let bit = local[C_ALU_BITS + l * W_BITS + j];
                push(&mut acc, line!(),is_chainop * bit * (Ea4::ONE - bit));
                rec += bit * Ea4::from_u64(1 << j);
            }
            push(&mut acc, line!(),is_chainop * (rec - r));
            // the result lands on the next row's top slot (ADD / SUB) or the slot below the carry out (ADC / SBB)
            push(&mut acc, line!(),is_trans * is_addsub * (at(stack_at(0, SLOT_W0 + l), &[]) - r));
            push(&mut acc, line!(),is_trans * is_adcsbb * (at(stack_at(1, SLOT_W0 + l), &[]) - r));
            carry_in = c;
        }
        push(&mut acc, line!(),is_trans * is_addsub * at(stack_at(0, SLOT_TAG), &[])); // ... as a WORD
        // ADC / SBB: the result is a WORD below; the carry / borrow out (the chain's last carry) is a WORD on top
        let land_adc = is_trans * is_adcsbb;
        push(&mut acc, line!(),land_adc * at(stack_at(1, SLOT_TAG), &[]));
        push(&mut acc, line!(),land_adc * at(stack_at(1, SLOT_LEN), &[]));
        push(&mut acc, line!(),land_adc * at(stack_at(0, SLOT_TAG), &[]));
        push(&mut acc, line!(),land_adc * at(stack_at(0, SLOT_LEN), &[]));
        push(&mut acc, line!(),land_adc * (at(stack_at(0, SLOT_W0), &[]) - local[C_ALU_CARRY + W_LIMBS - 1]));
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),land_adc * at(stack_at(0, SLOT_W0 + l), &[]));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),land_adc * at(stack_at(1, SLOT_D0 + d), &[]));
            push(&mut acc, line!(),land_adc * at(stack_at(0, SLOT_D0 + d), &[]));
        }

        // ── L4b ALU: LT / EQ / AND / OR / NOT ───────────────────────────────────────────────────
        // LT and EQ ride the SUB chain over R = a − b (wrapping): LT is the borrow-out, EQ is "every difference limb
        // is zero" through per-limb inverse witnesses. AND / OR / NOT are non-zero tests of the operands' LIMB SUMS
        // (< 2^18, so zero in the field iff the word is zero). Every result lands as a WORD 0/1 on the next top slot.
        let (sel_lt, sel_eq, sel_and, sel_or, sel_not) = (sel(op::LT), sel(op::EQ), sel(op::AND), sel(op::OR), sel(op::NOT));
        let is_cmp = sel_lt + sel_eq;
        let is_logic2 = sel_and + sel_or;
        let two_ops = is_cmp + is_logic2;
        // operands bound to the stack, both WORDS (NOT: the top only)
        push(&mut acc, line!(),(two_ops + sel_not) * local[s0 + SLOT_TAG]);
        push(&mut acc, line!(),two_ops * local[s1 + SLOT_TAG]);
        let mut a_sum = Ea4::ZERO;
        let mut b_sum = Ea4::ZERO;
        let mut r_sum = Ea4::ZERO;
        let mut borrow_in = Ea4::ZERO;
        for l in 0..W_LIMBS {
            let a = local[C_ALU_A + l];
            let b = local[C_ALU_B + l];
            let r = local[C_ALU_R + l];
            let c = local[C_ALU_CARRY + l];
            push(&mut acc, line!(),two_ops * (a - local[s1 + SLOT_W0 + l]));
            push(&mut acc, line!(),sel_not * (a - local[s0 + SLOT_W0 + l]));
            push(&mut acc, line!(),two_ops * (b - local[s0 + SLOT_W0 + l]));
            a_sum += a;
            b_sum += b;
            // the SUB chain for LT / EQ: borrows are bits, R is the wrapping difference with each limb ranged by its bits
            push(&mut acc, line!(),is_cmp * c * (Ea4::ONE - c));
            push(&mut acc, line!(),is_cmp * (a - b - borrow_in - r + two16 * c));
            let mut rec = Ea4::ZERO;
            for j in 0..W_BITS {
                let bit = local[C_ALU_BITS + l * W_BITS + j];
                push(&mut acc, line!(),is_cmp * bit * (Ea4::ONE - bit));
                rec += bit * Ea4::from_u64(1 << j);
            }
            push(&mut acc, line!(),is_cmp * (rec - r));
            borrow_in = c;
            r_sum += r;
        }
        let lt = borrow_in; // the top borrow-out of a − b
        // EQ (degree-6 census, 2026-09-29): ONE committed flag `eq = [Σ r_l = 0]` with one limb-sum inverse — every limb is
        // bit-ranged above, so the sum is below 2^18 and is zero iff every limb is. The is-zero gadget: `eq · Σr = 0` (a
        // non-zero sum forces eq = 0) and `(1 − eq)·(1 − Σr·inv) = 0` (a zero sum forces eq = 1; a non-zero one makes
        // `inv` its inverse). The old per-limb product `Π(1 − r_l·inv_l)` put a degree-9 factor inside the landing law.
        let eq = local[C_EQFLAG];
        push(&mut acc, line!(),sel_eq * eq * (Ea4::ONE - eq));
        push(&mut acc, line!(),sel_eq * eq * r_sum);
        push(&mut acc, line!(),sel_eq * (Ea4::ONE - eq) * (Ea4::ONE - r_sum * local[C_EQINV]));
        // the non-zero tests of the limb sums: committed flags `nz = [Σ ≠ 0]` — `(1 − nz)·Σ = 0` (a non-zero sum forces
        // nz = 1) and `nz·(1 − Σ·inv) = 0` (nz = 1 needs the sum's inverse, so a zero sum forces nz = 0)
        let (inv_a, inv_b) = (local[C_NZINV], local[C_NZINV + 1]);
        let (nz_a, nz_b) = (local[C_NZ], local[C_NZ + 1]);
        let needs_a = is_logic2 + sel_not;
        push(&mut acc, line!(),needs_a * nz_a * (Ea4::ONE - nz_a));
        push(&mut acc, line!(),needs_a * (Ea4::ONE - nz_a) * a_sum);
        push(&mut acc, line!(),needs_a * nz_a * (Ea4::ONE - a_sum * inv_a));
        push(&mut acc, line!(),is_logic2 * nz_b * (Ea4::ONE - nz_b));
        push(&mut acc, line!(),is_logic2 * (Ea4::ONE - nz_b) * b_sum);
        push(&mut acc, line!(),is_logic2 * nz_b * (Ea4::ONE - b_sum * inv_b));
        // the landed WORD 0/1 (every term degree ≤ 3; the landing law below is 5)
        let result = sel_lt * lt + sel_eq * eq + sel_and * nz_a * nz_b + sel_or * (nz_a + nz_b - nz_a * nz_b)
            + sel_not * (Ea4::ONE - nz_a);
        let lands = is_trans * (two_ops + sel_not);
        push(&mut acc, line!(),lands * (at(stack_at(0, SLOT_W0), &[]) - result));
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),lands * at(stack_at(0, SLOT_W0 + l), &[]));
        }
        push(&mut acc, line!(),lands * at(stack_at(0, SLOT_TAG), &[]));

        // ── L4c / L4d ALU: MUL / DIV / MOD (the hidden multiply at word width) ──────────────────
        // `X · B` through confidential_solvency's 12-bit schoolbook over the operands' RANGE BITS: MUL lands the low 64
        // bits of A·B (the high half is simply not pinned — wrapping); DIV and MOD lay `A = X·B + REM` with `REM < B`
        // (so `B ≠ 0` by construction) and the product's upper limbs zero — DIV lands X (the quotient), MOD lands REM.
        let (sel_mul, sel_div, sel_mod) = (sel(op::MUL_U64), sel(op::DIV_U64), sel(op::MOD_U64));
        // WIDE (2026-09-29): MUL_HI lands the product's UPPER four limbs; DIVMOD128 divides a 128-bit (hi, lo) by d —
        // the chain below runs over eight limbs with A's upper four wired to `hi` on DIVMOD128 rows and zero elsewhere
        let (sel_mulhi, sel_dm128) = (sel(op::MUL_HI), sel(op::DIVMOD128));
        let is_dm = sel_div + sel_mod + sel_dm128;
        let is_md = sel_mul + sel_mulhi + is_dm;
        let lands_r = sel_mul + sel_mulhi + sel_div + sel_mod; // every block opcode but DIVMOD128 lands R on the top slot
        push(&mut acc, line!(),sel_dm128 * local[stack_at(2, SLOT_TAG)]); // DIVMOD128: hi (two below the top) is a WORD
        // S2-3: a U64_TO_DEC_STR digit row (a FEED into sponge C) runs the SAME block as ONE division step — `A = X·10 +
        // REM` with X the accumulator before the digit (P), REM = byte − 48 (so `REM < B = 10` IS the digit range) and A
        // the accumulator after it (P' = 10·P + digit, which the accumulator frame lands). The block's laws are gated by
        // `is_blk` / `is_chain` (MUL / DIV / MOD or a digit row); the operand wiring stays per gate.
        let g_dec = sel(op::U64_TO_DEC_STR) * local[C_FEED + dsol_vm::SPONGE_C];
        let is_blk = is_md + g_dec;
        let is_chain = is_dm + g_dec;
        push(&mut acc, line!(),is_md * local[s0 + SLOT_TAG]); // both operands are WORDS
        push(&mut acc, line!(),is_md * local[s1 + SLOT_TAG]);
        let recompose = |base: usize, l: usize| -> Ea4 {
            let mut v = Ea4::ZERO;
            for j in 0..W_BITS {
                v += local[base + l * W_BITS + j] * Ea4::from_u64(1 << j);
            }
            v
        };
        for j in 0..W_LIMBS * W_BITS {
            for base in [C_MD_XBITS, C_MD_BBITS, C_MD_REMBITS] {
                let bit = local[base + j];
                push(&mut acc, line!(),is_blk * bit * (Ea4::ONE - bit));
            }
        }
        let mut md: Vec<Ea4> = Vec::new();
        crate::confidential_solvency::push_mulhh_constraints(&mut md, local, C_MD_XBITS, C_MD_BBITS, W_LIMBS, C_MD_BLK);
        for c in md {
            push(&mut acc, line!(),is_blk * c);
        }
        let p16 = C_MD_BLK + crate::confidential_solvency::mulhh_p16_off(W_LIMBS);
        let mut md_carry = Ea4::ZERO;
        let mut md_borrow = Ea4::ZERO;
        for l in 0..W_LIMBS {
            let (a, b, r) = (local[C_ALU_A + l], local[C_ALU_B + l], local[C_ALU_R + l]);
            push(&mut acc, line!(),is_md * (a - local[s1 + SLOT_W0 + l])); // the operands ARE the stack's words
            push(&mut acc, line!(),is_md * (b - local[s0 + SLOT_W0 + l]));
            let (x, bb, rem) = (recompose(C_MD_XBITS, l), recompose(C_MD_BBITS, l), recompose(C_MD_REMBITS, l));
            push(&mut acc, line!(),is_md * (bb - b)); // B's range bits are B's
            // S2-3 wiring: X = the accumulator before the digit, B = 10, REM = byte − 48 (limb 0; the others zero)
            push(&mut acc, line!(),g_dec * (x - local[C_S2ACC + l]));
            push(&mut acc, line!(),g_dec * (bb - if l == 0 { Ea4::from_u64(10) } else { Ea4::ZERO }));
            push(&mut acc, line!(),g_dec * (rem - if l == 0 { local[C_BYTE] - Ea4::from_u64(48) } else { Ea4::ZERO }));
            push(&mut acc, line!(),(sel_mul + sel_mulhi) * (x - a)); // MUL / MUL_HI: X = A
            push(&mut acc, line!(),(sel_div + sel_dm128) * (x - r)); // DIV / DIVMOD128: X = R, the quotient
            push(&mut acc, line!(),sel_mod * (rem - r)); // MOD: REM = R, the remainder
            push(&mut acc, line!(),sel_mul * (r - local[p16 + l])); // MUL: R is the low 64 bits of X·B
            push(&mut acc, line!(),sel_mulhi * (r - local[p16 + W_LIMBS + l])); // MUL_HI: R is the high 64 bits of X·B
            // DIV / MOD / DIVMOD128 / a decimal digit: A = X·B + REM as a limb chain with bit carries (the lower four
            // limbs here; the upper four, where A is `hi` or zero, follow the loop) ...
            let c = local[C_MD_ACARRY + l];
            push(&mut acc, line!(),is_chain * c * (Ea4::ONE - c));
            push(&mut acc, line!(),is_chain * (local[p16 + l] + rem + md_carry - a - two16 * c));
            md_carry = c;
            // ... and REM < B: B − REM − 1 = slack ≥ 0 by a borrow chain whose slack is range-bound by its own bits
            let (sl, bo) = (local[C_MD_SLACK + l], local[C_MD_BORROW + l]);
            push(&mut acc, line!(),is_chain * bo * (Ea4::ONE - bo));
            let d = bb - rem - if l == 0 { Ea4::ONE } else { Ea4::ZERO };
            push(&mut acc, line!(),is_chain * (d - md_borrow - sl + two16 * bo));
            push(&mut acc, line!(),is_chain * (recompose(C_MD_SBITS, l) - sl));
            md_borrow = bo;
            // the result lands on the next row's top slot (DIVMOD128 lands its two results below)
            push(&mut acc, line!(),is_trans * lands_r * (at(stack_at(0, SLOT_W0 + l), &[]) - r));
        }
        // ... the upper four limbs of the chain: A is `hi` on a DIVMOD128 row, zero on every other chain row (so the
        // product's upper limbs are forced to zero there: a 2^16 − 1 limb with a carry in would need the carry OUT the
        // last law refuses), REM has no upper limbs
        for l in W_LIMBS..2 * W_LIMBS {
            let c = local[C_MD_ACARRY + l];
            let a_hi = sel_dm128 * local[stack_at(2, SLOT_W0 + l - W_LIMBS)];
            push(&mut acc, line!(),is_chain * c * (Ea4::ONE - c));
            push(&mut acc, line!(),is_chain * (local[p16 + l] + md_carry - a_hi - two16 * c));
            md_carry = c;
        }
        push(&mut acc, line!(),is_chain * md_carry); // no carry out: A = X·B + REM holds over the integers below 2^128
        push(&mut acc, line!(),is_chain * md_borrow); // no borrow out: REM < B
        for l in 2 * W_LIMBS..crate::confidential_solvency::hh_p16(W_LIMBS) {
            push(&mut acc, line!(),is_chain * local[p16 + l]); // the product fits 128 bits: the ninth limb is zero
        }
        push(&mut acc, line!(),is_trans * lands_r * at(stack_at(0, SLOT_TAG), &[])); // ... as a WORD
        // DIVMOD128 lands q (= X = R) below and the remainder on top, both WORDS
        let land_dm = is_trans * sel_dm128;
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),land_dm * (at(stack_at(1, SLOT_W0 + l), &[]) - local[C_ALU_R + l]));
            push(&mut acc, line!(),land_dm * (at(stack_at(0, SLOT_W0 + l), &[]) - recompose(C_MD_REMBITS, l)));
        }
        for k in 0..2 {
            push(&mut acc, line!(),land_dm * at(stack_at(k, SLOT_TAG), &[]));
            push(&mut acc, line!(),land_dm * at(stack_at(k, SLOT_LEN), &[]));
            for d in 0..DIGEST_LANES {
                push(&mut acc, line!(),land_dm * at(stack_at(k, SLOT_D0 + d), &[]));
            }
        }

        // ── L3 STACK ──────────────────────────────────────────────────────────────────────────
        // sp twice: as the value C_SP and as a one-hot over 0..=STACK_DEPTH, tied by Σ s·spselₛ == sp.
        let sp = local[C_SP];
        let nsp = at(C_SP, &[]);
        let mut sp_sum = Ea4::ZERO;
        let mut sp_val = Ea4::ZERO;
        for s in 0..=STACK_DEPTH {
            let b = local[C_SPSEL + s];
            push(&mut acc, line!(),b * (Ea4::ONE - b));
            sp_sum += b;
            sp_val += b * Ea4::from_u64(s as u64);
        }
        push(&mut acc, line!(),sp_sum - Ea4::ONE);
        push(&mut acc, line!(),sp_val - sp);
        // "sp < p": the one-hot's low part
        let below = |p: usize| -> Ea4 { (0..p).fold(Ea4::ZERO, |a, s| a + local[C_SPSEL + s]) };
        let full = local[C_SPSEL + STACK_DEPTH];
        // a non-final row freezes sp and the whole stack
        push(&mut acc, line!(),is_trans * cont * (nsp - sp));
        for k in 0..STACK_DEPTH {
            for c in 0..SLOT_W {
                let col = stack_at(k, c);
                push(&mut acc, line!(),is_trans * cont * (at(col, &[]) - local[col]));
            }
        }
        // a final row moves the stack by the opcode's (pops, pushes) — ONE table, `dsol_vm::stack_effect`, which the
        // interpreter asserts against after every opcode. Opcodes are grouped by their (pops, pushes); SWAP (a
        // permutation) is its own law.
        let effects: [(u8, u8); 8] = [(0, 1), (1, 1), (0, 0), (1, 0), (2, 1), (2, 0), (3, 0), (3, 2)];
        let trans_final = is_trans * final_row;
        for &(p, q) in effects.iter() {
            let mut s_pq = Ea4::ZERO;
            for (i, &o) in OPS.iter().enumerate() {
                if o != op::SWAP && dsol_vm::stack_effect(o) == Some((p, q)) {
                    s_pq += local[C_OPSEL + i];
                }
            }
            let (p, q) = (p as usize, q as usize);
            // sp moves by pushes − pops
            push(&mut acc, line!(),trans_final * s_pq * (nsp + Ea4::from_u64(p as u64) - sp - Ea4::from_u64(q as u64)));
            // the machine refuses an underflow (sp < pops) and an overflow (a push at a full stack); so does this row
            if p > 0 {
                push(&mut acc, line!(),s_pq * below(p));
            }
            if q > p {
                push(&mut acc, line!(),s_pq * full);
            }
            // every slot at or above the pushed ones shifts by pops − pushes; what rises from below the bottom is ZERO
            for k in q..STACK_DEPTH {
                let src = k + p - q;
                for c in 0..SLOT_W {
                    let want = if src < STACK_DEPTH { local[stack_at(src, c)] } else { Ea4::ZERO };
                    push(&mut acc, line!(),trans_final * s_pq * (at(stack_at(k, c), &[]) - want));
                }
            }
        }
        // SWAP: the top two trade places, everything else and sp stay
        let sel_swap = sel(op::SWAP);
        push(&mut acc, line!(),sel_swap * below(2));
        push(&mut acc, line!(),trans_final * sel_swap * (nsp - sp));
        for c in 0..SLOT_W {
            push(&mut acc, line!(),trans_final * sel_swap * (at(stack_at(0, c), &[]) - local[stack_at(1, c)]));
            push(&mut acc, line!(),trans_final * sel_swap * (at(stack_at(1, c), &[]) - local[stack_at(0, c)]));
        }
        for k in 2..STACK_DEPTH {
            for c in 0..SLOT_W {
                push(&mut acc, line!(),trans_final * sel_swap * (at(stack_at(k, c), &[]) - local[stack_at(k, c)]));
            }
        }
        // the VALUE a push lands (slot 0 of the next row) is each opcode's own law. Landed here: PUSH_U64 lands the
        // fetched literal as a WORD; DUP lands a copy of the top. (ADD/SUB land in L4a.) The other pushing and
        // transforming opcodes' slot 0 is NOT yet bound — named in the module doc and the plan.
        let sel_pu = sel(op::PUSH_U64);
        push(&mut acc, line!(),trans_final * sel_pu * at(stack_at(0, SLOT_TAG), &[]));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),trans_final * sel_pu * (at(stack_at(0, SLOT_W0 + l), &[]) - imm_l[l]));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),trans_final * sel_pu * at(stack_at(0, SLOT_D0 + d), &[]));
        }
        push(&mut acc, line!(),trans_final * sel_pu * at(stack_at(0, SLOT_LEN), &[]));
        let sel_dup = sel(op::DUP);
        push(&mut acc, line!(),sel_dup * below(1));
        for c in 0..SLOT_W {
            push(&mut acc, line!(),trans_final * sel_dup * (at(stack_at(0, c), &[]) - local[stack_at(0, c)]));
        }
        // H1 (2026-09-29): PUSH_BYTES lands the PROGRAM'S literal as a STRING — its digest is this row's `C_LIT`, which
        // the fetch bus carries in its key, so it is the ROM's (the verifier's own) digest of the literal at this pc;
        // its length is the immediate. Before this law the landed slot was free: a contract's constant storage key or
        // event topic could be swapped for any string the prover liked, invisibly to every other law.
        let sel_pb = sel(op::PUSH_BYTES);
        push(&mut acc, line!(),trans_final * sel_pb * (at(stack_at(0, SLOT_TAG), &[]) - Ea4::ONE));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),trans_final * sel_pb * at(stack_at(0, SLOT_W0 + l), &[]));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),trans_final * sel_pb * (at(stack_at(0, SLOT_D0 + d), &[]) - local[C_LIT + d]));
        }
        push(&mut acc, line!(),trans_final * sel_pb * (at(stack_at(0, SLOT_LEN), &[]) - imm_l[0]));
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),sel_pb * imm_l[l]); // a literal's length is one 16-bit limb
        }

        // ── L10 BOUNDARY ──────────────────────────────────────────────────────────────────────
        let mut is_first = Ea4::ONE;
        for &xk in x {
            is_first *= Ea4::ONE - xk;
        }
        let st = &self.stmt;
        let lane = |v: u64| Ea4::from(f(v));
        // H4 (2026-09-29): the call-context opcodes land the STATEMENT's values. MSG_SENDER / MSG_SUBADDRESS / CONTRACT_ID
        // / TX_HASH push `str_digest(32 context bytes)` as a string of length 32 on one PLAIN row; BLOCK_NUMBER pushes a
        // word. Before this law every one of them landed a free slot: a contract's `msg.sender` check was the prover's
        // to pass, and `CONTRACT_ID` could name another contract than the one the statement's `cid` derives tags under.
        for (o, digest) in [(op::MSG_SENDER, &st.caller), (op::MSG_SUBADDRESS, &st.subaddress), (op::CONTRACT_ID, &st.cid), (op::TX_HASH, &st.tx_hash)] {
            let land = trans_final * sel(o);
            push(&mut acc, line!(),land * (at(stack_at(0, SLOT_TAG), &[]) - Ea4::ONE));
            for l in 0..W_LIMBS {
                push(&mut acc, line!(),land * at(stack_at(0, SLOT_W0 + l), &[]));
            }
            for d in 0..DIGEST_LANES {
                push(&mut acc, line!(),land * (at(stack_at(0, SLOT_D0 + d), &[]) - lane(digest[d])));
            }
            push(&mut acc, line!(),land * (at(stack_at(0, SLOT_LEN), &[]) - lane(32)));
        }
        let land_bn = trans_final * sel(op::BLOCK_NUMBER);
        push(&mut acc, line!(),land_bn * at(stack_at(0, SLOT_TAG), &[]));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),land_bn * (at(stack_at(0, SLOT_W0 + l), &[]) - lane((st.block_number >> (W_BITS * l)) & ((1 << W_BITS) - 1))));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),land_bn * at(stack_at(0, SLOT_D0 + d), &[]));
        }
        push(&mut acc, line!(),land_bn * at(stack_at(0, SLOT_LEN), &[]));
        // row 0 of a FRESH call: the entrypoint; the argv as the ONE string on the stack; clean locals, sponges and
        // accumulators; the effects fold at the machine's zero seed. Row 0 of a CONTINUED segment (continuations, plan
        // item 5) is instead the first row of a boundary in-run whose fold must equal the statement's `state_in` — every
        // carried column (pc, sp, stack, locals, root, effects) is then whatever that fold says. The pre-state storage
        // root and the real flag hold in both modes. `fresh_in` is the statement's, so the verifier builds the same gate.
        let fresh_in = st.state_in == [0u64; DIGEST_LANES];
        let start_gate = if fresh_in { is_first } else { Ea4::ZERO };
        let cont_gate = if fresh_in { Ea4::ZERO } else { is_first };
        push(&mut acc, line!(),cont_gate * (micro(mk::BOUND) - Ea4::ONE));
        push(&mut acc, line!(),start_gate * (pc - lane(u64::from(st.start_pc))));
        push(&mut acc, line!(),start_gate * (sp - Ea4::ONE));
        push(&mut acc, line!(),start_gate * (local[stack_at(0, SLOT_TAG)] - Ea4::ONE));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),start_gate * local[stack_at(0, SLOT_W0 + l)]);
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),start_gate * (local[stack_at(0, SLOT_D0 + d)] - lane(st.argv_digest[d])));
        }
        push(&mut acc, line!(),start_gate * (local[stack_at(0, SLOT_LEN)] - lane(u64::from(st.argv_len))));
        for k in 1..STACK_DEPTH {
            for c in 0..SLOT_W {
                push(&mut acc, line!(),start_gate * local[stack_at(k, c)]);
            }
        }
        for k in 0..LOCALS_MAX {
            for c in 0..SLOT_W {
                push(&mut acc, line!(),start_gate * local[local_at(k, c)]);
            }
        }
        for s in 0..SPONGES {
            for i in 0..SP_WIDTH {
                push(&mut acc, line!(),start_gate * local[sp_state(s, i)]);
            }
            for i in 0..RATE {
                push(&mut acc, line!(),start_gate * local[sp_lane(s, i)]);
            }
            push(&mut acc, line!(),start_gate * local[C_SPFILL + s]);
        }
        push(&mut acc, line!(),start_gate * local[C_REMAIN]);
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_first * (local[C_SROOT + d] - lane(st.storage_pre[d])));
            push(&mut acc, line!(),start_gate * local[C_EACC + d]); // a continued segment's fold carries the effects fold in
        }
        // the RETURN's FINAL row (a word return first PRODUCES its bytes over FEED / PERM rows) is where the real rows
        // end — padding replicates that final row. The exact row count is PRIVATE (2026-09-29): the statement carries
        // only the table's height class, so no counter binds a public count here any more.
        let sel_ret = sel(op::RETURN);
        let ret_final = sel_ret * final_row;
        // L2's multiplicity (H6): `real` is 1 on row 0 and stays 1 through the RETURN's final row, then 0 on every
        // padding row — `real' = real · (1 − ret_final)`. The fetch bus counts exactly the rows this column says are
        // real, so neither a forged row hidden as "padding" nor a padding row promoted to "real" survives.
        push(&mut acc, line!(),is_first * (local[C_REAL] - Ea4::ONE));
        let nreal = at(C_REAL, &[]);
        // continuations: a segment that ends in a CUT has no RETURN — its real rows end with the out-run's last stage
        // (`bout · [stage == BOUND_GROUPS − 1]`; `bout` is 0 off boundary rows, so this names exactly that row)
        let m_bound = micro(mk::BOUND);
        // `[stage = k]` from the two radix-8 one-hots: one product, degree 2
        let stage_is = |k: usize| -> Ea4 { local[C_BSHI + k / BSTAGE_RADIX] * local[C_BSLO + k % BSTAGE_RADIX] };
        // `C_BEND` IS `bout · [stage = last]` (degree 7, every row: off boundary rows `bout` is 0 so the flag is 0), and the
        // real-flag law below reads the committed flag at degree 1. DEGREE CENSUS 2026-09-29: with the product written
        // inline that law was `is_trans · real · bout · six bits` = 9 against the declared 8 — the zerocheck samples deg+2
        // points, so the honest round polynomial mis-interpolated whenever its top coefficient was non-zero, which is
        // TRACE-DEPENDENT: the first segment of the continuations pin verified, the continued one did not, and the
        // row-level diagnostic (which never sees a degree) was clean on both. The debug prover now asserts the declared
        // degree on every round (`air_zerocheck::prove_air_zerocheck`), so this class is named at prove time.
        let bound_end = local[C_BEND];
        push(&mut acc, line!(),bound_end - local[C_BOUT] * stage_is(dsol_vm::BOUND_GROUPS - 1));
        push(&mut acc, line!(),is_trans * (nreal - local[C_REAL] * (Ea4::ONE - ret_final - bound_end)));
        // the fetch bus's multiplicity: a real row that is not a boundary row
        push(&mut acc, line!(),local[C_FETCH] - local[C_REAL] * (Ea4::ONE - m_bound));

        // ── L8 STORAGE — word and STRING values; stack keys and MAP_*-derived keys (L8b) ──────────────────────────
        // A storage access is LEAF(φ0) [LEAF(φ1) on a write] PATH×DEPTH [each level twice on a write] FINISH. The LEAF
        // row hashes `compress(key, value)`; every PATH row folds one image through the sibling on the side its key bit
        // says; the level countdown forces exactly DEPTH levels; the direction bits rebuild the key lane by lane; the
        // pre-image folds to the row's root; a write's post-image becomes the next root; a read's value rides to its
        // FINISH row and is what lands on the stack.
        let one = Ea4::ONE;
        let m_leaf = micro(mk::LEAF);
        let m_path = micro(mk::PATH);
        let m_finish = micro(mk::FINISH);
        let nmicro = |k: u8| at(C_MICRO + k as usize, &[]);
        let (n_leaf, n_path, n_finish) = (nmicro(mk::LEAF), nmicro(mk::PATH), nmicro(mk::FINISH));
        let nsel = |o: u8| at(C_OPSEL + op_index(o).expect("every storage opcode is in OPS"), &[]);
        let sto = |s: &dyn Fn(u8) -> Ea4| -> (Ea4, Ea4, Ea4) {
            (
                s(op::SSTORE) + s(op::SSTORE_PRIV) + s(op::MAP_STORE) + s(op::MAP_STORE_PRIV),
                s(op::SLOAD) + s(op::MAP_LOAD),
                s(op::MAP_LOAD) + s(op::MAP_STORE) + s(op::MAP_STORE_PRIV),
            )
        };
        let (pwrite, is_read, mapped) = sto(&sel);
        let (n_write, n_read, n_mapped) = sto(&nsel);
        let storage = pwrite + is_read;
        let n_storage = n_write + n_read;
        let acc_row = m_leaf + m_path;
        let n_acc = n_leaf + n_path;
        let phase = local[C_PPHASE];
        let nphase = at(C_PPHASE, &[]);
        let present = local[C_PPRES];
        let dir = local[C_PDIR];
        let inp = |i: usize| local[C_P2 + i];
        let out = |i: usize| local[C_P2 + crate::pow_pq_air::PERM_OUT + i];
        // (a) shape: an access row is a storage opcode's and a storage opcode has no other kind of row but its FINISH
        //     (and, for a MAP_* opcode, its ONE key-derivation row); its run starts on a φ0 LEAF row — or on its effect
        //     rows for a private store (L9), or on its KEYD row for a mapped access (L8b); a φ1 row belongs to a write;
        //     booleans
        push(&mut acc, line!(),acc_row * (one - storage));
        push(&mut acc, line!(),storage * (micro(mk::FEED) + micro(mk::PERM) + micro(mk::PLAIN)));
        let priv_store = sel(op::SSTORE_PRIV) + sel(op::MAP_STORE_PRIV);
        let n_efx_row = at(C_MICRO + mk::EFX as usize, &[]);
        let m_keyd = micro(mk::KEYD);
        let n_keyd = nmicro(mk::KEYD);
        let m_sval = micro(mk::SVAL);
        let n_sval = nmicro(mk::SVAL);
        push(&mut acc, line!(),storage * (one - priv_store) * micro(mk::EFX));
        push(&mut acc, line!(),m_keyd * (one - mapped)); // L8b: only a mapped access derives a key
        push(&mut acc, line!(),m_sval * (one - storage)); // L8b part 2: a value-half row is a storage opcode's
        // "the previous opcode ended" is a final row OR a boundary in-run's exit (continuations): a resumed segment's
        // first instruction starts exactly as one after a final row does, so a prover cannot resume mid-run
        let opcode_ended = final_row + m_bound * (one - nmicro(mk::BOUND));
        push(&mut acc, line!(),is_trans * opcode_ended * n_storage * (one - n_leaf - n_efx_row - n_keyd - n_sval));
        push(&mut acc, line!(),is_trans * opcode_ended * n_mapped * (one - n_keyd)); // a mapped run STARTS with its KEYD row
        push(&mut acc, line!(),is_trans * opcode_ended * n_storage * nphase);
        push(&mut acc, line!(),is_first * storage * (one - m_leaf - micro(mk::EFX) - m_keyd - m_sval));
        push(&mut acc, line!(),is_first * mapped * (one - m_keyd));
        push(&mut acc, line!(),is_first * storage * phase);
        push(&mut acc, line!(),acc_row * phase * (one - phase));
        push(&mut acc, line!(),acc_row * present * (one - present));
        push(&mut acc, line!(),m_path * dir * (one - dir));
        push(&mut acc, line!(),acc_row * phase * (one - pwrite));
        // L8b — the KEYD row: its block hashes (base, key) from the two string operands below the value (MAP_LOAD: slots
        // 1, 0; MAP_STORE / MAP_STORE_PRIV: slots 2, 1); its output is the NEXT row's access key; it hands over to the φ0
        // LEAF row, or to a private store's effect rows, across which the key is frozen. Before this row existed every
        // mapped access was refused by law: the circuit had no source for a derived key.
        let (m_load, m_store) = (sel(op::MAP_LOAD), sel(op::MAP_STORE) + sel(op::MAP_STORE_PRIV));
        push(&mut acc, line!(),m_keyd * m_load * (local[stack_at(1, SLOT_TAG)] - one));
        push(&mut acc, line!(),m_keyd * m_load * (local[stack_at(0, SLOT_TAG)] - one));
        push(&mut acc, line!(),m_keyd * m_store * (local[stack_at(2, SLOT_TAG)] - one));
        push(&mut acc, line!(),m_keyd * m_store * (local[stack_at(1, SLOT_TAG)] - one));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),m_keyd * m_load * (inp(d) - local[stack_at(1, SLOT_D0 + d)]));
            push(&mut acc, line!(),m_keyd * m_load * (inp(DIGEST_LANES + d) - local[stack_at(0, SLOT_D0 + d)]));
            push(&mut acc, line!(),m_keyd * m_store * (inp(d) - local[stack_at(2, SLOT_D0 + d)]));
            push(&mut acc, line!(),m_keyd * m_store * (inp(DIGEST_LANES + d) - local[stack_at(1, SLOT_D0 + d)]));
            push(&mut acc, line!(),is_trans * m_keyd * (at(C_PKEY + d, &[]) - out(d)));
            push(&mut acc, line!(),is_trans * micro(mk::EFX) * mapped * (at(C_PKEY + d, &[]) - local[C_PKEY + d]));
        }
        push(&mut acc, line!(),is_trans * m_keyd * priv_store * (one - n_efx_row));
        push(&mut acc, line!(),is_trans * m_keyd * (one - priv_store) * (one - n_leaf - n_sval));
        push(&mut acc, line!(),is_trans * m_keyd * nphase);
        // L8b part 2 — the SVAL row: a STRING value's half, `compress(digest, [1, len])` — the pre-image string's (φ0:
        // `C_PVDIG`, `C_PVLEN`, tag 1) or the written top's (φ1: slot 0, a string) — whose output is the value half the
        // LEAF row that follows consumes; the row carries its LEAF's phase and hands over to that LEAF
        push(&mut acc, line!(),m_sval * phase * (one - phase));
        push(&mut acc, line!(),is_trans * m_sval * (n_leaf - one));
        push(&mut acc, line!(),is_trans * m_sval * (nphase - phase));
        push(&mut acc, line!(),m_sval * (one - phase) * (local[C_PVAL] - one));
        push(&mut acc, line!(),m_sval * phase * (local[stack_at(0, SLOT_TAG)] - one));
        for d in 0..DIGEST_LANES {
            let want = (one - phase) * local[C_PVDIG + d] + phase * local[stack_at(0, SLOT_D0 + d)];
            push(&mut acc, line!(),m_sval * (inp(d) - want));
            push(&mut acc, line!(),is_trans * m_sval * (at(C_PVLANES + d, &[]) - out(d)));
            push(&mut acc, line!(),is_trans * m_sval * phase * (at(C_POLD + d, &[]) - local[C_POLD + d])); // a write's pre-image leaf rides across its φ1 SVAL row
        }
        push(&mut acc, line!(),m_sval * (inp(DIGEST_LANES) - one));
        push(&mut acc, line!(),m_sval * (inp(DIGEST_LANES + 1) - ((one - phase) * local[C_PVLEN] + phase * local[stack_at(0, SLOT_LEN)])));
        for i in 2..DIGEST_LANES {
            push(&mut acc, line!(),m_sval * inp(DIGEST_LANES + i));
        }
        // (b) the key is the STRING operand: SLOAD's slot 0, SSTORE's slot 1 (its value sits on slot 0)
        let ssel = sel(op::SSTORE) + sel(op::SSTORE_PRIV);
        push(&mut acc, line!(),acc_row * sel(op::SLOAD) * (local[stack_at(0, SLOT_TAG)] - one));
        push(&mut acc, line!(),acc_row * ssel * (local[stack_at(1, SLOT_TAG)] - one));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),acc_row * sel(op::SLOAD) * (local[C_PKEY + d] - local[stack_at(0, SLOT_D0 + d)]));
            push(&mut acc, line!(),acc_row * ssel * (local[C_PKEY + d] - local[stack_at(1, SLOT_D0 + d)]));
        }
        // (c) the LEAF row's block hashes [key ‖ value half]; the value half is C_PVLANES — for a WORD the limb encoding
        //     [0, limb0..limb3, 0, 0, 0] of the pre-image (φ0) or the written top (φ1); for a STRING the SVAL row's block
        //     output carried onto this row (L8b part 2), and a LEAF row whose value is a string must FOLLOW its SVAL row;
        //     an absent slot's value is zero; the pre-image tag is a bit
        push(&mut acc, line!(),acc_row * local[C_PVAL] * (one - local[C_PVAL]));
        let vtag = (one - phase) * local[C_PVAL] + phase * local[stack_at(0, SLOT_TAG)];
        for i in 0..DIGEST_LANES {
            push(&mut acc, line!(),m_leaf * (inp(i) - local[C_PKEY + i]));
            push(&mut acc, line!(),m_leaf * (inp(DIGEST_LANES + i) - local[C_PVLANES + i]));
        }
        push(&mut acc, line!(),m_leaf * (one - vtag) * local[C_PVLANES]);
        for l in 0..W_LIMBS {
            let want = (one - phase) * local[C_PVAL + 1 + l] + phase * local[stack_at(0, SLOT_W0 + l)];
            push(&mut acc, line!(),m_leaf * (one - vtag) * (local[C_PVLANES + 1 + l] - want));
        }
        for i in 1 + W_LIMBS..DIGEST_LANES {
            push(&mut acc, line!(),m_leaf * (one - vtag) * local[C_PVLANES + i]);
        }
        let n_vtag = (one - nphase) * at(C_PVAL, &[]) + nphase * at(stack_at(0, SLOT_TAG), &[]);
        push(&mut acc, line!(),is_trans * n_leaf * n_vtag * (one - m_sval));
        push(&mut acc, line!(),is_first * m_leaf * vtag);
        for l in 0..1 + W_LIMBS {
            push(&mut acc, line!(),acc_row * (one - present) * local[C_PVAL + l]);
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),acc_row * (one - present) * local[C_PVDIG + d]);
        }
        push(&mut acc, line!(),acc_row * (one - present) * local[C_PVLEN]);
        // (d) LEAF transitions: φ0 → a write's φ1 LEAF row or a read's first PATH row; φ1 → the first PATH row. The
        //     pre-image leaf is the block's output when the slot is present and the empty digest when it is not; the
        //     post-image leaf is the φ1 block's output. Entering the path: countdown = DEPTH, accumulators 0, the one-hot
        //     on the first level's lane.
        let leaf0 = is_trans * m_leaf * (one - phase);
        let leaf1 = is_trans * m_leaf * phase;
        push(&mut acc, line!(),leaf0 * pwrite * (one - n_leaf - n_sval)); // a write's φ1 LEAF, or the φ1 SVAL row before it
        push(&mut acc, line!(),leaf0 * pwrite * (nphase - one));
        push(&mut acc, line!(),leaf0 * (one - pwrite) * (n_path - one));
        push(&mut acc, line!(),leaf0 * (one - pwrite) * nphase);
        push(&mut acc, line!(),leaf1 * (n_path - one));
        push(&mut acc, line!(),leaf1 * nphase);
        for i in 0..DIGEST_LANES {
            push(&mut acc, line!(),leaf0 * (at(C_POLD + i, &[]) - present * out(i)));
            push(&mut acc, line!(),leaf1 * (at(C_POLD + i, &[]) - local[C_POLD + i]));
            push(&mut acc, line!(),leaf1 * (at(C_PNEW + i, &[]) - out(i)));
        }
        let enter = is_trans * m_leaf * n_path;
        push(&mut acc, line!(),enter * (at(C_REMAIN, &[]) - Ea4::from_u64(dsol_vm::STORAGE_DEPTH as u64)));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),enter * at(C_KACC + d, &[]));
            let first = if d == (dsol_vm::STORAGE_DEPTH - 1) % DIGEST_LANES { one } else { Ea4::ZERO };
            push(&mut acc, line!(),enter * (at(C_KLANE + d, &[]) - first));
        }
        // (e) the access's key, pre-image value (tag, limbs, string digest and length) and presence are frozen across its
        //     rows — the value-half rows included
        let carry = is_trans * (acc_row + m_sval) * (n_acc + n_sval);
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),carry * (at(C_PKEY + d, &[]) - local[C_PKEY + d]));
            push(&mut acc, line!(),carry * (at(C_PVDIG + d, &[]) - local[C_PVDIG + d]));
        }
        for l in 0..1 + W_LIMBS {
            push(&mut acc, line!(),carry * (at(C_PVAL + l, &[]) - local[C_PVAL + l]));
        }
        push(&mut acc, line!(),carry * (at(C_PVLEN, &[]) - local[C_PVLEN]));
        push(&mut acc, line!(),carry * (at(C_PPRES, &[]) - present));
        // (f) a PATH row's block folds the image of its phase through the sibling, on the side the key bit says; a read's
        //     post-image tracks its pre-image; the lane one-hot is a one-hot
        for i in 0..DIGEST_LANES {
            let node = phase * local[C_PNEW + i] + (one - phase) * local[C_POLD + i];
            let sib = local[C_PSIB + i];
            push(&mut acc, line!(),m_path * (inp(i) - (dir * sib + (one - dir) * node)));
            push(&mut acc, line!(),m_path * (inp(DIGEST_LANES + i) - (dir * node + (one - dir) * sib)));
            push(&mut acc, line!(),m_path * (one - pwrite) * (local[C_PNEW + i] - local[C_POLD + i]));
        }
        let mut ksum = Ea4::ZERO;
        for d in 0..DIGEST_LANES {
            let k = local[C_KLANE + d];
            push(&mut acc, line!(),m_path * k * (one - k));
            ksum += k;
        }
        push(&mut acc, line!(),m_path * (ksum - one));
        // (g) PATH → PATH: a write's pre-image row is followed by the SAME level's post-image row (`stay`: same sibling,
        //     side and countdown, the folded pre-image carried); otherwise the next level (`adv`): countdown −1, the folded
        //     images carried, this level's bit landing in its lane, the lane one-hot rotating
        let pp = is_trans * m_path * n_path;
        // `C_WADV` = pwrite · phase committed (degree-6 census, 2026-09-29): stay = pwrite − wadv and adv = 1 − stay are
        // degree 1, so the PATH → PATH laws below are at most 6 (two were 7 with the product inline)
        let wadv = local[C_WADV];
        push(&mut acc, line!(),wadv - pwrite * phase);
        let stay = pwrite - wadv;
        let adv = one - stay;
        push(&mut acc, line!(),pp * stay * (nphase - one));
        push(&mut acc, line!(),pp * stay * (at(C_REMAIN, &[]) - local[C_REMAIN]));
        push(&mut acc, line!(),pp * stay * (at(C_PDIR, &[]) - dir));
        push(&mut acc, line!(),pp * adv * nphase);
        push(&mut acc, line!(),pp * adv * (at(C_REMAIN, &[]) - local[C_REMAIN] + one));
        for i in 0..DIGEST_LANES {
            push(&mut acc, line!(),pp * stay * (at(C_PSIB + i, &[]) - local[C_PSIB + i]));
            push(&mut acc, line!(),pp * stay * (at(C_POLD + i, &[]) - out(i)));
            push(&mut acc, line!(),pp * stay * (at(C_PNEW + i, &[]) - local[C_PNEW + i]));
            push(&mut acc, line!(),pp * adv * (at(C_POLD + i, &[]) - (pwrite * local[C_POLD + i] + (one - pwrite) * out(i))));
            push(&mut acc, line!(),pp * adv * (at(C_PNEW + i, &[]) - out(i)));
        }
        for d in 0..DIGEST_LANES {
            let (k, a) = (local[C_KLANE + d], local[C_KACC + d]);
            push(&mut acc, line!(),pp * stay * (at(C_KACC + d, &[]) - a));
            push(&mut acc, line!(),pp * stay * (at(C_KLANE + d, &[]) - k));
            push(&mut acc, line!(),pp * adv * (at(C_KACC + d, &[]) - a - k * (a + dir)));
            push(&mut acc, line!(),pp * adv * (at(C_KLANE + d, &[]) - local[C_KLANE + (d + 1) % DIGEST_LANES]));
        }
        // (h) the exit: the last PATH row is followed by the opcode's FINISH; exactly DEPTH levels were walked (the
        //     countdown reads 1); a write exits from its post-image row; the last bit lands and the accumulators equal
        //     the key; the pre-image folded to THIS row's root; a write's post-image becomes the NEXT root while the root
        //     carries on every other transition; a read's value rides onto the FINISH row and is what its push lands
        let exit = is_trans * m_path * (one - n_path);
        push(&mut acc, line!(),exit * (n_finish - one));
        push(&mut acc, line!(),exit * (local[C_REMAIN] - one));
        push(&mut acc, line!(),exit * (phase - pwrite));
        for d in 0..DIGEST_LANES {
            let (k, a) = (local[C_KLANE + d], local[C_KACC + d]);
            push(&mut acc, line!(),exit * (a + k * (a + dir) - local[C_PKEY + d]));
        }
        let exit_w = m_path * (one - n_path) * pwrite;
        // a LIBCALL's final row: the caller's root JUMPS to the library's post root the row carries (the library ran
        // against this storage; its proof, matched by the node, says pre = this root and post = that one)
        let lib_final = sel(op::LIBCALL) * final_row;
        for i in 0..DIGEST_LANES {
            let old_folded = pwrite * local[C_POLD + i] + (one - pwrite) * out(i);
            push(&mut acc, line!(),exit * (old_folded - local[C_SROOT + i]));
            push(&mut acc, line!(),is_trans * (at(C_SROOT + i, &[]) - local[C_SROOT + i] - exit_w * (out(i) - local[C_SROOT + i]) - lib_final * (local[C_CALLEE + i] - local[C_SROOT + i])));
        }
        for l in 0..1 + W_LIMBS {
            push(&mut acc, line!(),exit * (at(C_PVAL + l, &[]) - local[C_PVAL + l]));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),exit * (at(C_PVDIG + d, &[]) - local[C_PVDIG + d]));
        }
        push(&mut acc, line!(),exit * (at(C_PVLEN, &[]) - local[C_PVLEN]));
        // a read lands the pre-image as it was: a WORD (tag 0) as its limbs, a STRING (tag 1) as its digest and length
        let fin_read = is_trans * m_finish * is_read;
        let rtag = local[C_PVAL];
        push(&mut acc, line!(),fin_read * (at(stack_at(0, SLOT_TAG), &[]) - rtag));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),fin_read * (at(stack_at(0, SLOT_W0 + l), &[]) - (one - rtag) * local[C_PVAL + 1 + l]));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),fin_read * (at(stack_at(0, SLOT_D0 + d), &[]) - rtag * local[C_PVDIG + d]));
        }
        push(&mut acc, line!(),fin_read * (at(stack_at(0, SLOT_LEN), &[]) - rtag * local[C_PVLEN]));

        // ── L9 EFFECTS — the fold is built from what the row can see, one block per stage ──────────────────────────
        // An effect opcode lays its effect's schedule (`dsol_vm::efx_plan`) as consecutive EFX rows right before its
        // FINISH (a private store: right before its LEAF row); every block's inputs come from named sources — a stack
        // operand, sponge A's digest, the statement's contract id, a domain constant, a carry an earlier stage wrote,
        // the accumulator — and the last stage's output is the next row's accumulator, which carries everywhere else.
        // So a prover can neither record an effect the execution did not issue, nor drop, reorder or alter one.
        // A SYSCALL's result is produced through sponge C, so its `ret` block reads the sponge's digest and the produced
        // length (L9b). MAP_STORE_PRIV (a derived key) has a source the circuit cannot see and is REFUSED, not assumed (L8b).
        let m_efx = micro(mk::EFX);
        let n_efx = nmicro(mk::EFX);
        let eff_of = |s: &dyn Fn(u8) -> Ea4| s(op::NULLIFIER) + s(op::EMIT) + s(op::SYSCALL) + s(op::SSTORE_PRIV) + s(op::MAP_STORE_PRIV) + s(op::CALL) + s(op::LIBCALL);
        let (eff, n_eff) = (eff_of(&sel), eff_of(&nsel));
        let n_priv = nsel(op::SSTORE_PRIV) + nsel(op::MAP_STORE_PRIV);
        let stage = |k: usize| local[C_ESTAGE + k];
        let nstage = |k: usize| at(C_ESTAGE + k, &[]);
        // (a) shape: EFX rows belong to effect opcodes; the one unbound kind is refused; an EMIT's rows are EFX or
        //     FINISH, a NULLIFIER's and a SYSCALL's are FEED / PERM / EFX / FINISH; the stage one-hot is a one-hot;
        //     string operands
        push(&mut acc, line!(),m_efx * (one - eff));
        push(&mut acc, line!(),sel(op::EMIT) * (micro(mk::FEED) + micro(mk::PERM) + micro(mk::PLAIN) + m_path + m_leaf));
        push(&mut acc, line!(),sel(op::NULLIFIER) * (micro(mk::PLAIN) + m_path + m_leaf));
        push(&mut acc, line!(),sel(op::SYSCALL) * (micro(mk::PLAIN) + m_path + m_leaf));
        push(&mut acc, line!(),sel(op::CALL) * (micro(mk::PLAIN) + m_path + m_leaf)); // a CALL's rows are FEED / PERM / EFX / FINISH
        push(&mut acc, line!(),sel(op::LIBCALL) * (micro(mk::PLAIN) + m_path + m_leaf)); // and a LIBCALL's
        // a CALL's callee binding / a LIBCALL's post root and library effects are frozen across the opcode's rows (the fold
        // reads them on their EFX rows; the root jump reads the post root at the FINISH)
        let s_calls = sel(op::CALL) + sel(op::LIBCALL);
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_trans * s_calls * cont * (at(C_CALLEE + d, &[]) - local[C_CALLEE + d]));
            push(&mut acc, line!(),is_trans * sel(op::LIBCALL) * cont * (at(C_LIBEFX + d, &[]) - local[C_LIBEFX + d]));
        }
        let mut esum = Ea4::ZERO;
        for k in 0..dsol_vm::EFX_STAGES_MAX {
            push(&mut acc, line!(),m_efx * stage(k) * (one - stage(k)));
            esum += stage(k);
        }
        push(&mut acc, line!(),m_efx * (esum - one));
        push(&mut acc, line!(),m_efx * sel(op::EMIT) * (local[stack_at(0, SLOT_TAG)] - one));
        push(&mut acc, line!(),m_efx * sel(op::EMIT) * (local[stack_at(1, SLOT_TAG)] - one));
        // (b) position: an effect opcode's FINISH follows its last EFX row — except a private store's, whose FINISH
        //     follows its PATH exit (L8) because its EFX rows come FIRST and hand over to the φ0 LEAF row; every other
        //     effect's last EFX row is followed by its FINISH. (First run 03:59: this law named every effect opcode and
        //     refused the honest SSTORE_PRIV, whose FINISH is preceded by a PATH row.)
        push(&mut acc, line!(),is_trans * n_finish * (n_eff - n_priv) * (one - m_efx));
        // a plain private store starts with its effect rows; a MAPPED private store starts with its KEYD row (L8b)
        push(&mut acc, line!(),is_trans * (final_row + m_bound * (one - nmicro(mk::BOUND))) * nsel(op::SSTORE_PRIV) * (one - n_efx));
        push(&mut acc, line!(),is_first * sel(op::SSTORE_PRIV) * (one - m_efx));
        let efx_exit = is_trans * m_efx * (one - n_efx);
        push(&mut acc, line!(),efx_exit * priv_store * (one - n_leaf - n_sval)); // the φ0 LEAF, or the φ0 SVAL row before it (L8b)
        push(&mut acc, line!(),efx_exit * priv_store * nphase);
        push(&mut acc, line!(),efx_exit * (one - priv_store) * (n_finish - one));
        // (c) stages: the first EFX row of a run is stage 0; +1 per row; the run exits at its schedule's last stage
        push(&mut acc, line!(),is_trans * (one - m_efx) * n_efx * (nstage(0) - one));
        push(&mut acc, line!(),is_first * m_efx * (stage(0) - one));
        let pp_e = is_trans * m_efx * n_efx;
        for k in 0..dsol_vm::EFX_STAGES_MAX - 1 {
            push(&mut acc, line!(),pp_e * (nstage(k + 1) - stage(k)));
        }
        push(&mut acc, line!(),pp_e * stage(dsol_vm::EFX_STAGES_MAX - 1));
        let kinds: [(u8, Ea4); 7] = [
            (op::NULLIFIER, sel(op::NULLIFIER)),
            (op::EMIT, sel(op::EMIT)),
            (op::SSTORE_PRIV, sel(op::SSTORE_PRIV)),
            (op::SYSCALL, sel(op::SYSCALL)),
            (op::MAP_STORE_PRIV, sel(op::MAP_STORE_PRIV)),
            (op::CALL, sel(op::CALL)),
            (op::LIBCALL, sel(op::LIBCALL)),
        ];
        for &(o, ksel) in &kinds {
            let plan = dsol_vm::efx_plan(o);
            push(&mut acc, line!(),efx_exit * ksel * (stage(plan.len() - 1) - one));
        }
        // (d) the blocks: each stage's inputs are its named sources; its output lands in the named carry on the next
        //     row while the other carry holds
        let src = |s: dsol_vm::EfxSrc, d: usize| -> Ea4 {
            use dsol_vm::EfxSrc as S;
            match s {
                S::Const(c) => if d == 0 { lane(c) } else { Ea4::ZERO },
                S::ConstSysOp(c) => match d {
                    0 => lane(c),
                    1 => local[C_IMM],
                    _ => Ea4::ZERO,
                },
                S::SlotDigest(n) => local[stack_at(usize::from(n), SLOT_D0 + d)],
                S::SlotLen(n) => if d == 0 { local[stack_at(usize::from(n), SLOT_LEN)] } else { Ea4::ZERO },
                S::Cid => lane(st.cid[d]),
                S::SpongeA => local[sp_state(dsol_vm::SPONGE_A, d)],
                S::SpongeC => local[sp_state(dsol_vm::SPONGE_C, d)],
                S::Plen => if d == 0 { local[C_PLEN] } else { Ea4::ZERO },
                S::Tmp0 => local[C_ETMP + d],
                S::Tmp1 => local[C_ETMP2 + d],
                S::Acc => local[C_EACC + d],
                S::PKey => local[C_PKEY + d], // L8b: the derived key, carried from the KEYD row
                // a CALL's constant with its u32 immediate (two 16-bit limbs) and the returned length
                S::ConstImmPlen(c) => match d {
                    0 => lane(c),
                    1 => local[C_IMM] + two16 * local[C_IMM + 1],
                    2 => local[C_PLEN],
                    _ => Ea4::ZERO,
                },
                S::Callee => local[C_CALLEE + d],
                // a LIBCALL's constant with its immediate, the returned length and the argument's length (slot 0's)
                S::ConstImmPlenAlen(c) => match d {
                    0 => lane(c),
                    1 => local[C_IMM] + two16 * local[C_IMM + 1],
                    2 => local[C_PLEN],
                    3 => local[stack_at(0, SLOT_LEN)],
                    _ => Ea4::ZERO,
                },
                S::SRoot => local[C_SROOT + d],
                S::LibEffects => local[C_LIBEFX + d],
            }
        };
        for &(o, ksel) in &kinds {
            for (k, step) in dsol_vm::efx_plan(o).iter().enumerate() {
                let g_in = m_efx * ksel * stage(k);
                let g_out = pp_e * ksel * stage(k);
                for d in 0..DIGEST_LANES {
                    push(&mut acc, line!(),g_in * (inp(d) - src(step.left, d)));
                    push(&mut acc, line!(),g_in * (inp(DIGEST_LANES + d) - src(step.right, d)));
                    let (ntmp0, ntmp1) = (at(C_ETMP + d, &[]), at(C_ETMP2 + d, &[]));
                    match step.out {
                        dsol_vm::EfxDst::Tmp0 => {
                            push(&mut acc, line!(),g_out * (ntmp0 - out(d)));
                            push(&mut acc, line!(),g_out * (ntmp1 - local[C_ETMP2 + d]));
                        }
                        dsol_vm::EfxDst::Tmp1 => {
                            push(&mut acc, line!(),g_out * (ntmp1 - out(d)));
                            push(&mut acc, line!(),g_out * (ntmp0 - local[C_ETMP + d]));
                        }
                        dsol_vm::EfxDst::Acc => {} // the last stage: its output is the next accumulator, law (e)
                    }
                }
            }
        }
        // (e) the accumulator advances by the last stage's block and carries on every other transition
        let efx_last = m_efx * (one - n_efx);
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_trans * (at(C_EACC + d, &[]) - local[C_EACC + d] - efx_last * (out(d) - local[C_EACC + d])));
        }
        // the last row: a RETURN and the returned value's digest when the segment ENDS the call (`state_out` zero), the
        // last row of a boundary out-run when it CUTS (continuations); the post-state root and the effects fold in both
        // modes (the out-run's rows are `cont` rows, so they still hold the values at the cut). The row count is private.
        let fresh_out = st.state_out == [0u64; DIGEST_LANES];
        let end_gate = if fresh_out { is_last } else { Ea4::ZERO };
        let cut_gate = if fresh_out { Ea4::ZERO } else { is_last };
        push(&mut acc, line!(),end_gate * (sel_ret - Ea4::ONE));
        push(&mut acc, line!(),cut_gate * (m_bound - Ea4::ONE));
        let tag0 = local[stack_at(0, SLOT_TAG)];
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_last * (local[C_SROOT + d] - lane(st.storage_post[d])));
            push(&mut acc, line!(),is_last * (local[C_EACC + d] - lane(st.effects_digest[d])));
            // a STRING on top returns its own digest; a WORD (or an empty stack) was produced through sponge C (H2)
            // and returns that sponge's digest — the first DIGEST_LANES lanes of its state
            let from_slot = local[stack_at(0, SLOT_D0 + d)];
            let from_sponge = local[sp_state(dsol_vm::SPONGE_C, d)];
            push(&mut acc, line!(),end_gate * (tag0 * from_slot + (Ea4::ONE - tag0) * from_sponge - lane(st.ret_digest[d])));
        }
        // ── CONTINUATIONS (plan item 5): the boundary fold ─────────────────────────────────────────────────────────
        // A boundary run is BOUND_GROUPS rows under the BOUND pseudo-opcode. Each row's block absorbs group `stage` of
        // the carried state (pc, sp, the stack, the locals, the root, the effects fold — `bound_col`, the machine's
        // `bound_lanes` order) into the running fold; the carried columns cannot move under it (BOUND rows are `cont`
        // rows). The in-run starts at row 0 (stage 0, flag 0) and exits at the last stage into the resumed instruction
        // with its fold equal to the statement's `state_in`; the out-run is entered after row 0 (flag 1), runs to the
        // last real row and its fold is the statement's `state_out`. Stage bits and the flag are zero off boundary rows.
        let n_bound = nmicro(mk::BOUND);
        let sel_bound = sel(op::BOUND);
        push(&mut acc, line!(),m_bound * (Ea4::ONE - sel_bound));
        push(&mut acc, line!(),sel_bound * (Ea4::ONE - m_bound));
        let bout = local[C_BOUT];
        push(&mut acc, line!(),bout * (Ea4::ONE - bout));
        push(&mut acc, line!(),bout * (Ea4::ONE - m_bound));
        // the stage's two one-hots: boolean, each summing to `m_bound` (all zero off boundary rows, exactly one set on
        // them, so `8·hi + lo` encodes every stage value once); the run laws below count with that value
        let mut cnt = Ea4::ZERO;
        let mut ncnt = Ea4::ZERO;
        let (mut hi_sum, mut lo_sum) = (Ea4::ZERO, Ea4::ZERO);
        for j in 0..BSTAGE_RADIX {
            let (hi, lo) = (local[C_BSHI + j], local[C_BSLO + j]);
            push(&mut acc, line!(),hi * (Ea4::ONE - hi));
            push(&mut acc, line!(),lo * (Ea4::ONE - lo));
            hi_sum += hi;
            lo_sum += lo;
            cnt += hi * lane((BSTAGE_RADIX * j) as u64) + lo * lane(j as u64);
            ncnt += at(C_BSHI + j, &[]) * lane((BSTAGE_RADIX * j) as u64) + at(C_BSLO + j, &[]) * lane(j as u64);
        }
        push(&mut acc, line!(),hi_sum - m_bound);
        push(&mut acc, line!(),lo_sum - m_bound);
        let last_stage = lane((dsol_vm::BOUND_GROUPS - 1) as u64);
        // a run's first row: stage 0, the fold at zero; at row 0 it is the in-run, entered later it is the out-run
        push(&mut acc, line!(),is_first * m_bound * bout);
        push(&mut acc, line!(),is_first * m_bound * cnt);
        let enters = is_trans * (Ea4::ONE - m_bound) * n_bound;
        push(&mut acc, line!(),enters * (at(C_BOUT, &[]) - Ea4::ONE));
        push(&mut acc, line!(),enters * ncnt);
        push(&mut acc, line!(),enters * (Ea4::ONE - final_row)); // a cut falls only after an opcode's final row
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_first * m_bound * local[C_BSTATE + d]);
            push(&mut acc, line!(),enters * at(C_BSTATE + d, &[]));
        }
        // within a run (real rows): the stage advances, the flag holds, the fold becomes the block's output
        let within = is_trans * m_bound * n_bound * nreal;
        push(&mut acc, line!(),within * (ncnt - cnt - Ea4::ONE));
        push(&mut acc, line!(),within * (at(C_BOUT, &[]) - bout));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),within * (at(C_BSTATE + d, &[]) - out(d)));
        }
        // the block: left = the fold so far, right = the stage's group of the carried state (a padding lane is zero)
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),m_bound * (inp(d) - local[C_BSTATE + d]));
            // Σ_k [stage = k]·col(k, d), factored through the radix: Σ_h hi[h] · (Σ_l lo[l] · col(8h + l, d)) — 67 products
            // per lane at degree 3 (the flat six-bit selector cost 472 seven-factor products per evaluation at degree 7)
            let mut group_lane = Ea4::ZERO;
            for h in 0..BSTAGE_RADIX {
                let mut inner = Ea4::ZERO;
                for l in 0..BSTAGE_RADIX {
                    let k = BSTAGE_RADIX * h + l;
                    if k < dsol_vm::BOUND_GROUPS {
                        if let Some(col) = bound_col(k, d) {
                            inner += local[C_BSLO + l] * local[col];
                        }
                    }
                }
                group_lane += local[C_BSHI + h] * inner;
            }
            push(&mut acc, line!(),m_bound * (inp(DIGEST_LANES + d) - group_lane));
        }
        // the in-run's exit: only the in-run exits into more rows, at the last stage, with the statement's `state_in`
        let exit_in = is_trans * m_bound * (Ea4::ONE - n_bound);
        push(&mut acc, line!(),exit_in * bout);
        push(&mut acc, line!(),exit_in * (cnt - last_stage));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),exit_in * (out(d) - lane(st.state_in[d])));
        }
        // the out-run's end is the last row, at the last stage, with the statement's `state_out`
        push(&mut acc, line!(),is_last * m_bound * (bout - Ea4::ONE));
        push(&mut acc, line!(),is_last * m_bound * (cnt - last_stage));
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),is_last * m_bound * (out(d) - lane(st.state_out[d])));
        }

        // ── L6 SPONGE + L7 PACKING (S1: the sponge machinery; per-opcode content laws are S2) ──────────────
        let m_feed = micro(mk::FEED);
        // permsel: one-hot over SPONGES + 1 (the last means "no permutation this row"); exactly PERM rows permute
        let mut psum = Ea4::ZERO;
        for k in 0..=SPONGES {
            let b = local[C_PERMSEL + k];
            push(&mut acc, line!(),b * (Ea4::ONE - b));
            psum += b;
        }
        push(&mut acc, line!(),psum - Ea4::ONE);
        push(&mut acc, line!(),micro(mk::PERM) - (Ea4::ONE - local[C_PERMSEL + SPONGES]));
        // the byte is its eight bits
        let mut byte_rec = Ea4::ZERO;
        for j in 0..8 {
            let bit = local[C_BYTEBITS + j];
            push(&mut acc, line!(),bit * (Ea4::ONE - bit));
            byte_rec += bit * Ea4::from_u64(1 << j);
        }
        push(&mut acc, line!(),byte_rec - local[C_BYTE]);
        // the produced length is frozen across an opcode's rows; CONCAT's is the two operand lengths' sum, a fixed
        // producer's is its table value, RETURN's is 8 for a word and 0 for an empty stack
        let plen = local[C_PLEN];
        push(&mut acc, line!(),is_trans * cont * (at(C_PLEN, &[]) - plen));
        for (i, &o) in OPS.iter().enumerate() {
            let s_o = local[C_OPSEL + i];
            if o == op::CONCAT {
                push(&mut acc, line!(),s_o * (plen - local[stack_at(0, SLOT_LEN)] - local[stack_at(1, SLOT_LEN)]));
            } else if o == op::RETURN {
                // RETURN produces only for a WORD on top (8 bytes) or an empty stack (0); a STRING on top is returned as
                // it is and produces nothing — MEASURED 02:12: the first cut demanded 8 for every non-empty stack and
                // refused every honest string return.
                let has_top = Ea4::ONE - local[C_SPSEL];
                let word_top = Ea4::ONE - local[stack_at(0, SLOT_TAG)];
                push(&mut acc, line!(),s_o * (plen - Ea4::from_u64(8) * has_top * word_top));
            } else if let Some(fixed) = dsol_vm::produce_len(o) {
                push(&mut acc, line!(),s_o * (plen - Ea4::from_u64(u64::from(fixed))));
            }
        }
        for s in 0..SPONGES {
            let perm_s = local[C_PERMSEL + s];
            let feed_s = local[C_FEED + s];
            let open_s = local[C_OPEN + s];
            let nopen_s = at(C_OPEN + s, &[]);
            push(&mut acc, line!(),feed_s * (Ea4::ONE - feed_s));
            push(&mut acc, line!(),open_s * (Ea4::ONE - open_s));
            push(&mut acc, line!(),feed_s * (Ea4::ONE - m_feed)); // a byte enters a sponge only on a FEED row
            // an OPEN happens only on a row of an opcode that opens this sponge, and the fresh state IS init(len):
            // zero everywhere but the first capacity lane, which holds the length the table names for this opcode
            let mut opener = Ea4::ZERO;
            let mut len_src = Ea4::ZERO;
            for (i, &o) in OPS.iter().enumerate() {
                match dsol_vm::open_source(o, s) {
                    dsol_vm::OpenLen::Never => {}
                    dsol_vm::OpenLen::Slot(k) => {
                        opener += local[C_OPSEL + i];
                        len_src += local[C_OPSEL + i] * local[stack_at(k as usize, SLOT_LEN)];
                    }
                    dsol_vm::OpenLen::Produced => {
                        opener += local[C_OPSEL + i];
                        len_src += local[C_OPSEL + i] * plen;
                    }
                }
            }
            push(&mut acc, line!(),open_s * (Ea4::ONE - opener));
            for i in 0..SP_WIDTH {
                let want = if i == RATE { len_src } else { Ea4::ZERO };
                push(&mut acc, line!(),open_s * (local[sp_state(s, i)] - want));
            }
            for i in 0..RATE {
                push(&mut acc, line!(),open_s * local[sp_lane(s, i)]);
            }
            push(&mut acc, line!(),open_s * local[C_SPFILL + s]);
            // the fill one-hot, tied to its value
            let mut fsum = Ea4::ZERO;
            let mut fval = Ea4::ZERO;
            for k in 0..FILL_STATES {
                let b = local[fill_sel(s, k)];
                push(&mut acc, line!(),b * (Ea4::ONE - b));
                fsum += b;
                fval += b * Ea4::from_u64(k as u64);
            }
            push(&mut acc, line!(),fsum - Ea4::ONE);
            push(&mut acc, line!(),fval - local[C_SPFILL + s]);
            // a PERM row: the block's input is the staged lanes over the rate and the carried capacity; the next
            // state is the block's output. Otherwise the state carries — unless the next row OPENS this sponge afresh.
            for i in 0..SP_WIDTH {
                let want_in = if i < RATE { local[sp_lane(s, i)] } else { local[sp_state(s, i)] };
                push(&mut acc, line!(),perm_s * (local[C_P2 + i] - want_in));
                let nstate = at(sp_state(s, i), &[]);
                push(&mut acc, line!(),is_trans * perm_s * (nstate - local[C_P2 + crate::pow_pq_air::PERM_OUT + i]));
                push(&mut acc, line!(),is_trans * (Ea4::ONE - perm_s) * (Ea4::ONE - nopen_s) * (nstate - local[sp_state(s, i)]));
            }
            // lanes and fill: cleared by a PERM; advanced by a FEED that lands the byte at lane fill/3, sub-position
            // fill%3 (read off the fill one-hot); carried otherwise — all unless the next row opens the sponge
            let nfill_want = (Ea4::ONE - perm_s) * (local[C_SPFILL + s] + feed_s);
            push(&mut acc, line!(),is_trans * (Ea4::ONE - nopen_s) * (at(C_SPFILL + s, &[]) - nfill_want));
            for i in 0..RATE {
                let mut land = Ea4::ZERO;
                for sub in 0..BYTES_PER_LANE {
                    land += local[fill_sel(s, i * BYTES_PER_LANE + sub)] * Ea4::from_u64(1u64 << (8 * sub));
                }
                let want = (Ea4::ONE - perm_s) * (local[sp_lane(s, i)] + feed_s * local[C_BYTE] * land);
                push(&mut acc, line!(),is_trans * (Ea4::ONE - nopen_s) * (at(sp_lane(s, i), &[]) - want));
            }
        }
        // a FEED row feeds at least one sponge
        let (feed_a, feed_b, feed_c) = (local[C_FEED + dsol_vm::SPONGE_A], local[C_FEED + dsol_vm::SPONGE_B], local[C_FEED + dsol_vm::SPONGE_C]);
        push(&mut acc, line!(),m_feed * (Ea4::ONE - feed_a) * (Ea4::ONE - feed_b) * (Ea4::ONE - feed_c));
        // CONCAT: every byte it moves enters C AND exactly one of A / B, so C's content is A's bytes then B's — the
        // consume laws at FINISH (A ≡ slot1's digest, B ≡ slot0's) then fix C's byte count to la + lb with no counter
        let sel_concat = sel(op::CONCAT);
        push(&mut acc, line!(),sel_concat * m_feed * (feed_c - Ea4::ONE));
        push(&mut acc, line!(),sel_concat * m_feed * (feed_a + feed_b - Ea4::ONE));
        // ── S2 SUBSTRATE (2026-09-29; spec: docs/DSOL-BETTER-THAN-SOLIDITY-PLAN.md 'S2 CENSUS + SPEC') ─────────────
        // (a) THE PRODUCE COUNT, every C-producer — CONCAT included, its bytes step the countdown too now: `remaining`
        //     equals the produced length on the row that opens C, steps down by one per byte C takes, is FROZEN on every
        //     other non-final row of the opcode unless the next row re-opens C (a re-open restarts the count, the digest
        //     and the accumulators alike), and reads 0 on the opcode's final row. So C absorbed exactly `plen` bytes
        //     after its LAST open. MEASURED before this: the countdown had only its first two laws and was decorative —
        //     any number of bytes could be fed, and CONCAT was not counted at all.
        let open_c = local[C_OPEN + dsol_vm::SPONGE_C];
        let nopen_c = at(C_OPEN + dsol_vm::SPONGE_C, &[]);
        let nremain = at(C_REMAIN, &[]);
        let mut s_cnt = Ea4::ZERO;
        for (i, &o) in OPS.iter().enumerate() {
            if dsol_vm::open_source(o, dsol_vm::SPONGE_C) == dsol_vm::OpenLen::Produced {
                s_cnt += local[C_OPSEL + i];
            }
        }
        push(&mut acc, line!(),s_cnt * open_c * (local[C_REMAIN] - plen));
        push(&mut acc, line!(),is_trans * s_cnt * feed_c * (nremain - local[C_REMAIN] + Ea4::ONE));
        push(&mut acc, line!(),is_trans * s_cnt * cont * (Ea4::ONE - feed_c) * (Ea4::ONE - nopen_c) * (nremain - local[C_REMAIN]));
        push(&mut acc, line!(),s_cnt * final_row * local[C_REMAIN]);
        // (b) CONCAT's ORDER: `cph` is boolean, 0 on the row C opens (CONCAT's first), and rises exactly when B opens;
        //     A's bytes and A's open belong to phase 0, B's bytes to phase 1. With (a), C's content is A's la bytes and
        //     then B's lb — before this, an interleaving of the two satisfied every law (each sponge saw its own bytes in
        //     order; nothing said A's came first), and junk fed to A before A opened reached C uncounted.
        let cph = local[C_CPH];
        let (open_a, nopen_b) = (local[C_OPEN + dsol_vm::SPONGE_A], at(C_OPEN + dsol_vm::SPONGE_B, &[]));
        push(&mut acc, line!(),cph * (Ea4::ONE - cph));
        push(&mut acc, line!(),sel_concat * open_c * cph);
        push(&mut acc, line!(),is_trans * sel_concat * cont * (at(C_CPH, &[]) - cph - nopen_b));
        push(&mut acc, line!(),sel_concat * feed_a * cph);
        push(&mut acc, line!(),sel_concat * open_a * cph);
        push(&mut acc, line!(),sel_concat * feed_b * (Ea4::ONE - cph));
        // (c) FIRST-BLOCK FLAGS: boolean, 1 on the row a sponge opens, cleared by its PERM, carried otherwise — so a
        //     byte's position in a two-block produce is `fill + 24·(1 − fb)`
        for s in 0..SPONGES {
            let fb = local[C_FB + s];
            push(&mut acc, line!(),fb * (Ea4::ONE - fb));
            push(&mut acc, line!(),local[C_OPEN + s] * (fb - Ea4::ONE));
            push(&mut acc, line!(),is_trans * (Ea4::ONE - at(C_OPEN + s, &[])) * (at(C_FB + s, &[]) - fb * (Ea4::ONE - local[C_PERMSEL + s])));
        }
        // (d) THE CONTENT-ACCUMULATOR FRAME: zero on the row that opens the opcode's accumulating sponge
        //     (`dsol_vm::acc_sponge`), and on every other transition the next row's accumulators are this row's plus
        //     this row's byte's contribution — `dsol_vm::s2_accumulate`, spelled as constraints: a U64_TO_BYTES /
        //     U64_FROM_BYTES byte at position p < 8 (first block, the fill one-hot) lands in limb p/2 at byte p%2; a
        //     digest producer's byte at position p = fill + 24(1 − fb) lands its eight bits at bit 8p+k of the packed
        //     form, i.e. bit (8p+k) mod 31 of lane (8p+k)/31 — the low 24 bits of lane l in acc[l], its top 7 in acc[8+l].
        //     The transition INTO an opening row is exempt (the open law pins the zero). Stale values carry between
        //     opcodes and are never read: every target law reads its own opcode's accumulators after its own open.
        let (fb_a, fb_c) = (local[C_FB + dsol_vm::SPONGE_A], local[C_FB + dsol_vm::SPONGE_C]);
        let mut reset = Ea4::ZERO;
        for (i, &o) in OPS.iter().enumerate() {
            if let Some(s) = dsol_vm::acc_sponge(o) {
                reset += local[C_OPSEL + i] * local[C_OPEN + s];
            }
        }
        let (sel_tb, sel_fbytes) = (sel(op::U64_TO_BYTES), sel(op::U64_FROM_BYTES));
        let s_dig = sel(op::POSEIDON) + sel(op::NULLIFIER) + sel(op::COMMIT_U64);
        let word_land = |s: usize, l: usize| -> Ea4 {
            local[fill_sel(s, 2 * l)] + local[fill_sel(s, 2 * l + 1)] * Ea4::from_u64(256)
        };
        // a digest producer's position selector: the fill one-hot in the first block, the fill one-hot + 24 after it
        let possel = |p: usize| -> Ea4 {
            if p < dsol_vm::BYTES_PER_BLOCK {
                fb_c * local[fill_sel(dsol_vm::SPONGE_C, p)]
            } else {
                (Ea4::ONE - fb_c) * local[fill_sel(dsol_vm::SPONGE_C, p - dsol_vm::BYTES_PER_BLOCK)]
            }
        };
        // DEGREE 6 (2026-09-29): the one frame law `is_trans · (1 − nreset) · (acc' − acc − contrib)` was degree 8 (nreset is a
        // product of next-row selectors, the contributions are five-factor products). It is now THREE laws with degree-1
        // gates: on a sponge-C feed row acc' = acc + (the C sources); on a sponge-A feed row acc' = acc + (the A source); on
        // any other row acc' = acc unless the NEXT row resets (`C_S2RST`, the committed `reset`) — the same exemption the
        // old law had, read at degree 1. A feed row is never followed by a reset (a sponge permutes before anything opens),
        // and a row feeds one sponge, so the C and A laws never both bind. MEASURED before the flag: a digest producer
        // opens sponge C after permuting sponge A, mid-opcode, and a "previous row was final" exemption refused it.
        let rst = local[C_S2RST];
        push(&mut acc, line!(),rst - reset);
        let nrst = at(C_S2RST, &[]);
        for i in 0..dsol_vm::S2_ACC {
            push(&mut acc, line!(),rst * local[C_S2ACC + i]);
            let mut on_c = Ea4::ZERO;
            let mut on_a = Ea4::ZERO;
            if i < W_LIMBS {
                on_c += sel_tb * fb_c * local[C_BYTE] * word_land(dsol_vm::SPONGE_C, i);
                on_a += sel_fbytes * fb_a * local[C_BYTE] * word_land(dsol_vm::SPONGE_A, i);
                // S2-3: a decimal digit row lands the division block's dividend A = 10·P + digit as the next accumulator
                on_c += g_dec * (local[C_ALU_A + i] - local[C_S2ACC + i]);
            }
            let mut dig = Ea4::ZERO;
            for p in 0..32 {
                let mut bits = Ea4::ZERO;
                for k in 0..8 {
                    let g = 8 * p + k;
                    if g < 31 * DIGEST_LANES {
                        let (lane, r) = (g / 31, g % 31);
                        let (target, weight) = if r < 24 { (lane, r) } else { (DIGEST_LANES + lane, r - 24) };
                        if target == i {
                            bits += local[C_BYTEBITS + k] * Ea4::from_u64(1u64 << weight);
                        }
                    }
                }
                if bits != Ea4::ZERO {
                    dig += possel(p) * bits;
                }
            }
            on_c += s_dig * dig;
            let (acc_i, nacc_i) = (local[C_S2ACC + i], at(C_S2ACC + i, &[]));
            push(&mut acc, line!(),is_trans * feed_c * (nacc_i - acc_i - on_c));
            push(&mut acc, line!(),is_trans * feed_a * (nacc_i - acc_i - on_a));
            push(&mut acc, line!(),is_trans * (Ea4::ONE - nrst) * (Ea4::ONE - feed_c) * (Ea4::ONE - feed_a) * (nacc_i - acc_i));
        }
        // (e) LOCALS: the sixteen scratch columns are boolean everywhere and, on a LOCAL_GET / LOCAL_SET row, the one-hot
        //     of the immediate (so the index is below LOCALS_MAX by construction and the immediate is one limb); GET lands
        //     the selected local; SET writes the popped top into the selected local and no other; ALLOC_LOCALS zeroes
        //     them all; every other transition carries the whole array. MEASURED before this: the 224 locals columns had
        //     one law (row 0 = 0) — a contract's local variables were the prover's on every row.
        let (sel_lg, sel_ls, sel_al) = (sel(op::LOCAL_GET), sel(op::LOCAL_SET), sel(op::ALLOC_LOCALS));
        let s_loc = sel_lg + sel_ls;
        let mut scr_sum = Ea4::ZERO;
        let mut scr_idx = Ea4::ZERO;
        for k in 0..S2_SCR {
            let b = local[C_S2SCR + k];
            push(&mut acc, line!(),b * (Ea4::ONE - b));
            scr_sum += b;
            scr_idx += b * Ea4::from_u64(k as u64);
        }
        push(&mut acc, line!(),s_loc * (scr_sum - Ea4::ONE));
        push(&mut acc, line!(),s_loc * (scr_idx - imm_l[0]));
        for l in 1..C_IMM_LIMBS {
            push(&mut acc, line!(),s_loc * imm_l[l]);
        }
        let writes = final_row * (sel_ls + sel_al);
        for k in 0..LOCALS_MAX {
            let b = local[C_S2SCR + k];
            for c in 0..SLOT_W {
                let (cur, nxt) = (local[local_at(k, c)], at(local_at(k, c), &[]));
                push(&mut acc, line!(),is_trans * (Ea4::ONE - writes) * (nxt - cur));
                push(&mut acc, line!(),trans_final * sel_ls * (nxt - cur - b * (local[stack_at(0, c)] - cur)));
                push(&mut acc, line!(),trans_final * sel_al * nxt);
            }
        }
        for c in 0..SLOT_W {
            let mut got = Ea4::ZERO;
            for k in 0..LOCALS_MAX {
                got += local[C_S2SCR + k] * local[local_at(k, c)];
            }
            push(&mut acc, line!(),trans_final * sel_lg * (at(stack_at(0, c), &[]) - got));
        }
        // ── S2-2 TARGETS: the word ↔ bytes conversions, BYTES_LEN, STR_EQ ────────────────────────────────────────────
        // a landed WORD's shape on the next row's top slot: tag 0, no digest, no length (its limbs are each law's own)
        let land_word = |acc: &mut Ext, gate: Ea4| {
            push(acc, line!(), gate * at(stack_at(0, SLOT_TAG), &[]));
            for d in 0..DIGEST_LANES {
                push(acc, line!(), gate * at(stack_at(0, SLOT_D0 + d), &[]));
            }
            push(acc, line!(), gate * at(stack_at(0, SLOT_LEN), &[]));
        };
        // (f) U64_TO_BYTES / U64_FROM_BYTES: the four accumulated limbs ARE the word — the OPERAND's at TO_BYTES's FINISH
        //     (still on the stack there; the produced string lands by the generic law), the LANDED word's at
        //     FROM_BYTES's FINISH. MEASURED before this: the eight bytes TO_BYTES fed were free (any 8-byte string could
        //     be "the bytes of w"), and FROM_BYTES landed any word at all.
        push(&mut acc, line!(),sel_tb * local[stack_at(0, SLOT_TAG)]);
        push(&mut acc, line!(),sel_fbytes * (local[stack_at(0, SLOT_TAG)] - Ea4::ONE));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),sel_tb * m_finish * (local[C_S2ACC + l] - local[stack_at(0, SLOT_W0 + l)]));
            push(&mut acc, line!(),is_trans * sel_fbytes * m_finish * (at(stack_at(0, SLOT_W0 + l), &[]) - local[C_S2ACC + l]));
        }
        land_word(&mut acc, is_trans * sel_fbytes * m_finish);
        // (g) BYTES_LEN: a string on top; its length is the sixteen scratch bits (a 16-bit range proof, so the landed
        //     limb is canonical) and lands as the word's low limb, the other three zero
        let sel_bl = sel(op::BYTES_LEN);
        push(&mut acc, line!(),sel_bl * (local[stack_at(0, SLOT_TAG)] - Ea4::ONE));
        let mut len_rec = Ea4::ZERO;
        for k in 0..S2_SCR {
            len_rec += local[C_S2SCR + k] * Ea4::from_u64(1u64 << k);
        }
        push(&mut acc, line!(),sel_bl * (len_rec - local[stack_at(0, SLOT_LEN)]));
        push(&mut acc, line!(),trans_final * sel_bl * (at(stack_at(0, SLOT_W0), &[]) - local[stack_at(0, SLOT_LEN)]));
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),trans_final * sel_bl * at(stack_at(0, SLOT_W0 + l), &[]));
        }
        land_word(&mut acc, trans_final * sel_bl);
        // (h) STR_EQ: two strings; `eq` is the landed word's low limb and boolean; eq ⇒ every difference (the eight digest
        //     lanes, then the lengths) is zero; ¬eq ⇒ some difference is non-zero, witnessed by Σ dᵢ·invᵢ = 1 (the prover
        //     inverts one non-zero difference). MEASURED before this: `eq` was whatever the prover said.
        let sel_se = sel(op::STR_EQ);
        push(&mut acc, line!(),sel_se * (local[stack_at(0, SLOT_TAG)] - Ea4::ONE));
        push(&mut acc, line!(),sel_se * (local[stack_at(1, SLOT_TAG)] - Ea4::ONE));
        let eq = at(stack_at(0, SLOT_W0), &[]);
        push(&mut acc, line!(),trans_final * sel_se * eq * (Ea4::ONE - eq));
        let mut witness = Ea4::ZERO;
        for i in 0..=DIGEST_LANES {
            let d = if i < DIGEST_LANES {
                local[stack_at(0, SLOT_D0 + i)] - local[stack_at(1, SLOT_D0 + i)]
            } else {
                local[stack_at(0, SLOT_LEN)] - local[stack_at(1, SLOT_LEN)]
            };
            push(&mut acc, line!(),trans_final * sel_se * eq * d);
            witness += d * local[C_S2INV + i];
        }
        push(&mut acc, line!(),trans_final * sel_se * (Ea4::ONE - eq) * (Ea4::ONE - witness));
        for l in 1..W_LIMBS {
            push(&mut acc, line!(),trans_final * sel_se * at(stack_at(0, SLOT_W0 + l), &[]));
        }
        land_word(&mut acc, trans_final * sel_se);
        // ── S2-3 TARGET: U64_TO_DEC_STR ──────────────────────────────────────────────────────────────────────────────
        // (i) a word operand; every digit row is one division step of the L4c/d block (`g_dec` there: X = P, B = 10,
        //     REM = byte − 48 < 10) and the frame lands A = 10·P + digit; the FINISH pins the accumulator to the operand
        //     (P_n = w, so at most 20 digits — a 21st overflows the block); the first digit is non-zero unless the string
        //     is exactly "0" (plen = 1); the string is never empty (plen has an inverse). MEASURED before this: the digits
        //     U64_TO_DEC_STR fed were free — any string at all was "the decimal of w".
        let sel_dec = sel(op::U64_TO_DEC_STR);
        push(&mut acc, line!(),sel_dec * local[stack_at(0, SLOT_TAG)]);
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),sel_dec * m_finish * (local[C_S2ACC + l] - local[stack_at(0, SLOT_W0 + l)]));
        }
        // the digit is REM's low four bits (REM < 10 by the block); `1 − digit·inv` is 1 exactly when the digit is 0 — `inv`
        // is pinned to the digit's inverse whenever the digit is non-zero, so the law reads a degree-2 zero test instead of
        // the four-bit product (degree-6 census: the law was 8, now 6)
        let mut digit = Ea4::ZERO;
        for k in 0..4 {
            digit += local[C_MD_REMBITS + k] * Ea4::from_u64(1 << k);
        }
        let digit_zero = Ea4::ONE - digit * local[C_DZINV];
        push(&mut acc, line!(),g_dec * digit * digit_zero);
        push(&mut acc, line!(),g_dec * local[fill_sel(dsol_vm::SPONGE_C, 0)] * (plen - Ea4::ONE) * digit_zero);
        push(&mut acc, line!(),sel_dec * open_c * (plen * local[C_S2INV] - Ea4::ONE));
        // ── S2-4 TARGETS: the digest producers — POSEIDON, NULLIFIER, COMMIT_U64 ────────────────────────────────────
        // (j) the produced 32 bytes ENCODE the hash: the frame packed their 248 bits into lo24 / hi7 per lane, so
        //     `lane_l = a_l + 2^24·a_{8+l}` (exact — no wrap) must equal the target lane, and the encoding must be the
        //     CANONICAL one: a lane whose top seven bits are all one has zero low bits (the value p − 1), witnessed by
        //     the inverse of (127 − hi7) when they are not (without this, any lane below 2^24 − 1 also encodes as
        //     lane + p — a second byte form of the same digest, and `digest_to_bytes` is injective). Byte 31 is zero.
        //     Targets: POSEIDON at its FINISH = sponge A's closed digest; NULLIFIER at its stage-2 EFX row = Tmp0 (the tag,
        //     H(DOM, H(cid, secret)) — the machine zeroes the carries after the fold); COMMIT_U64 on its CMT row = that
        //     row's block output. MEASURED before this: the bytes each of the three fed were free — a contract's hash,
        //     nullifier string or commitment string was whatever the prover typed.
        let two24 = Ea4::from_u64(1 << 24);
        let c127 = Ea4::from_u64(127);
        let lane_target = |acc: &mut Ext, gate: Ea4, target: &dyn Fn(usize) -> Ea4| {
            for d in 0..DIGEST_LANES {
                let (lo, hi) = (local[C_S2ACC + d], local[C_S2ACC + DIGEST_LANES + d]);
                push(acc, line!(), gate * (lo + two24 * hi - target(d)));
                push(acc, line!(), gate * lo * (Ea4::ONE - (c127 - hi) * local[C_S2INV + d]));
            }
        };
        let (sel_pos, sel_nul, sel_cm) = (sel(op::POSEIDON), sel(op::NULLIFIER), sel(op::COMMIT_U64));
        let m_cmt = micro(mk::CMT);
        lane_target(&mut acc, sel_pos * m_finish, &|d| local[sp_state(dsol_vm::SPONGE_A, d)]);
        lane_target(&mut acc, sel_nul * m_efx * stage(2), &|d| local[C_ETMP + d]);
        lane_target(&mut acc, m_cmt, &|d| out(d));
        push(&mut acc, line!(),s_dig * feed_c * (Ea4::ONE - fb_c) * local[fill_sel(dsol_vm::SPONGE_C, 7)] * local[C_BYTE]); // byte 31 is zero
        // (k) COMMIT_U64's CMT row: it is COMMIT_U64's, its rows are FEED / PERM / CMT / FINISH, exactly one CMT row and it
        //     is the row before the FINISH; its block hashes [DOM_COMMIT, value limbs, 0, 0, 0] with sponge A's digest; the
        //     value is the word below the blinding string
        push(&mut acc, line!(),m_cmt * (Ea4::ONE - sel_cm));
        push(&mut acc, line!(),sel_cm * (micro(mk::PLAIN) + m_path + m_leaf + m_efx + m_keyd + m_sval));
        push(&mut acc, line!(),is_trans * nsel(op::COMMIT_U64) * n_finish * (Ea4::ONE - m_cmt));
        push(&mut acc, line!(),is_trans * m_cmt * (Ea4::ONE - n_finish));
        push(&mut acc, line!(),sel_cm * (local[stack_at(0, SLOT_TAG)] - Ea4::ONE));
        push(&mut acc, line!(),sel_cm * local[stack_at(1, SLOT_TAG)]);
        push(&mut acc, line!(),m_cmt * (inp(0) - lane(dsol_vm::DOM_COMMIT)));
        for l in 0..W_LIMBS {
            push(&mut acc, line!(),m_cmt * (inp(1 + l) - local[stack_at(1, SLOT_W0 + l)]));
        }
        for i in 1 + W_LIMBS..DIGEST_LANES {
            push(&mut acc, line!(),m_cmt * inp(i));
        }
        for d in 0..DIGEST_LANES {
            push(&mut acc, line!(),m_cmt * (inp(DIGEST_LANES + d) - local[sp_state(dsol_vm::SPONGE_A, d)]));
        }
        // ── content laws at an opcode's FINISH row ─────────────────────────────────────────────
        // A re-absorbed string's sponge has been closed by then: its first DIGEST_LANES state lanes must BE the
        // consumed slot's digest — the check the machine makes natively, now in-circuit, and what makes re-supply
        // sound (a delayed open or a skipped byte lands on another digest). A produced string lands on the next row's
        // top slot as Str(sponge C's digest, plen). RETURN produces without pushing (L10 binds its digest).
        let m_finish = micro(mk::FINISH);
        for (i, &o) in OPS.iter().enumerate() {
            let s_o = local[C_OPSEL + i];
            for s in 0..SPONGES {
                if let dsol_vm::OpenLen::Slot(k) = dsol_vm::open_source(o, s) {
                    for d in 0..DIGEST_LANES {
                        push(&mut acc, line!(),s_o * m_finish * (local[sp_state(s, d)] - local[stack_at(k as usize, SLOT_D0 + d)]));
                    }
                }
            }
            if o != op::RETURN && dsol_vm::open_source(o, dsol_vm::SPONGE_C) == dsol_vm::OpenLen::Produced {
                let land = is_trans * s_o * m_finish;
                push(&mut acc, line!(),land * (at(stack_at(0, SLOT_TAG), &[]) - Ea4::ONE));
                for l in 0..W_LIMBS {
                    push(&mut acc, line!(),land * at(stack_at(0, SLOT_W0 + l), &[]));
                }
                for d in 0..DIGEST_LANES {
                    push(&mut acc, line!(),land * (at(stack_at(0, SLOT_D0 + d), &[]) - local[sp_state(dsol_vm::SPONGE_C, d)]));
                }
                push(&mut acc, line!(),land * (at(stack_at(0, SLOT_LEN), &[]) - plen));
            }
        }
        acc
    }
}

// ───────────────────────────────────────────────────────────────────────────────────────────────────
// THE STATEMENT, and the production entry points: prove_dsol_call / verify_dsol_call
// ───────────────────────────────────────────────────────────────────────────────────────────────────

/// THE STATEMENT a DSOL call proof is about — the module doc's public tuple, plus what a verifier needs to rebuild
/// the same gate and tables from bytes it holds itself. The gate is built FROM this struct (`dsol_gate_for`), and the
/// transcript binds it (`bind`), so the boundary laws and the bind cannot name different values. The node's `DsolCallTx`
/// postcard-encodes this type itself (one encoding, no node-side mirror).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsolStatement {
    /// blake3 of the bytecode — the content address the registry holds.
    pub code_id: [u8; 32],
    /// The entrypoint's name hash (`dsol_vm::entry_hash`) and the pc the header maps it to.
    pub entry_sel: u32,
    pub start_pc: u32,
    pub argv_digest: Digest,
    pub argv_len: u32,
    pub storage_pre: Digest,
    pub storage_post: Digest,
    pub effects_digest: Digest,
    pub ret_digest: Digest,
    /// log2 of the CPU table's height (at least 5: 32 rows) — the shape the proof has anyway. The EXACT row count is
    /// PRIVATE (2026-09-29): it said which branch ran and how many loop iterations, the same thing H3's ROM
    /// multiplicities said. A caller may pad every call of a contract to one height (`prove_dsol_call_padded`), so all
    /// its executions share one shape; the padding rows replicate the RETURN row under `C_REAL = 0`.
    pub height_log2: u8,
    /// The call's contract id as the machine hashes it (`str_digest(ctx.contract_id)`) — what a `NULLIFIER` tag is
    /// derived under (L9). The first of the call context's values to enter the statement (H4).
    pub cid: Digest,
    /// The rest of the call context (H4, 2026-09-29): what `MSG_SENDER`, `MSG_SUBADDRESS` and `TX_HASH` land
    /// (`str_digest` of the 32 context bytes, as the machine pushes them) and what `BLOCK_NUMBER` lands. Bound here so
    /// every landing is the NODE's context, never a witness — before, a contract's `msg.sender` check was the prover's
    /// to pass. The caller values ride the PUBLIC statement: the node's DSOL door must hand the machine a
    /// CONTRACT-SCOPED caller pseudonym, never a wallet-linkable id.
    pub caller: Digest,
    pub subaddress: Digest,
    pub tx_hash: Digest,
    pub block_number: u64,
    /// Continuations (plan item 5): the boundary fold this segment opened from — zero for a FRESH call (row 0 obeys the
    /// entry laws), otherwise the predecessor segment's `state_out`, which this segment's in-run must reproduce.
    pub state_in: Digest,
    /// The boundary fold this segment closed with — zero when it ENDS the call with a RETURN (`ret_digest` binds), otherwise
    /// the state its successor must open from.
    pub state_out: Digest,
}

impl DsolStatement {
    /// The public bind, one field element per lane in this fixed order. The verifier recomputes it from the
    /// statement it was handed, so a proof over any other statement fails the transcript before any law runs.
    #[must_use]
    pub fn bind(&self) -> Vec<Fa4> {
        let mut b = Vec::with_capacity(8 + 4 + 4 + 9 * DIGEST_LANES);
        for c in self.code_id.chunks(4) {
            b.push(f(u64::from(u32::from_le_bytes([c[0], c[1], c[2], c[3]]))));
        }
        b.push(f(u64::from(self.entry_sel)));
        b.push(f(u64::from(self.start_pc)));
        b.push(f(u64::from(self.argv_len)));
        b.push(f(u64::from(self.height_log2)));
        for l in 0..W_LIMBS {
            b.push(f((self.block_number >> (W_BITS * l)) & ((1 << W_BITS) - 1))); // four exact lanes: a u64 is not one field element
        }
        for d in [&self.argv_digest, &self.storage_pre, &self.storage_post, &self.effects_digest, &self.ret_digest, &self.cid, &self.caller, &self.subaddress, &self.tx_hash, &self.state_in, &self.state_out] {
            b.extend(d.iter().map(|&l| f(l)));
        }
        b
    }
}

/// The statement an honest execution answers to, from the code, the call, the storage root the run began at, and
/// the trace's own result. `None` on an unknown entrypoint or a size the statement cannot carry.
#[must_use]
pub fn statement_of(code: &[u8], entrypoint: &str, argv: &[u8], storage_pre: Digest, ctx: &dsol_vm::VmCtx, t: &VmTrace) -> Option<DsolStatement> {
    let entry_sel = dsol_vm::entry_hash(entrypoint.as_bytes());
    let start_pc = dsol_vm::parse_entries(code).ok()?.iter().find(|(h, _)| *h == entry_sel).map(|(_, pc)| *pc)?;
    Some(DsolStatement {
        code_id: *blake3::hash(code).as_bytes(),
        entry_sel,
        start_pc,
        argv_digest: dsol_vm::str_digest(argv),
        argv_len: u32::try_from(argv.len()).ok()?,
        storage_pre,
        storage_post: t.run.storage_post,
        effects_digest: t.run.effects_digest,
        ret_digest: t.run.ret_digest,
        height_log2: natural_height_log2(t.steps.len()),
        cid: dsol_vm::str_digest(&ctx.contract_id),
        caller: dsol_vm::str_digest(&ctx.caller_wallet),
        subaddress: dsol_vm::str_digest(&ctx.caller_subaddress),
        tx_hash: dsol_vm::str_digest(&ctx.tx_hash),
        block_number: ctx.block_number,
        state_in: t.run.state_in,
        state_out: t.run.state_out,
    })
}

/// The per-table gate for a DSOL call under `stmt`: table 0 is the CPU (the statement-bound relation above), table 1
/// the public ROM (no row relation of its own — the fetch bus binds it). The verifier builds the SAME closure from
/// the statement it was handed.
#[must_use]
pub fn dsol_gate_for(stmt: DsolStatement, rom: Vec<Vec<Fa4>>) -> impl Fn(usize, Ea4) -> DsolCpuGate + Clone {
    dsol_gate_with(stmt, RomSource::Table(rom))
}

/// [`dsol_gate_for`] with the ROM law reading the CODE itself (D7): the verifier's form — the program is streamed once
/// per evaluation and never laid.
pub fn dsol_gate_for_code(stmt: DsolStatement, code: std::sync::Arc<[u8]>) -> impl Fn(usize, Ea4) -> DsolCpuGate + Clone {
    dsol_gate_with(stmt, RomSource::Code(code))
}

fn dsol_gate_with(stmt: DsolStatement, rom: RomSource) -> impl Fn(usize, Ea4) -> DsolCpuGate + Clone {
    move |i, gamma| {
        if i == 0 {
            DsolCpuGate::Cpu(DsolCpuConstraint {
                gamma,
                stmt: stmt.clone(),
                p2: crate::sponge_chain_air::p2_block_constraint_deg(gamma, crate::pow_pq_air::P2_COLS, crate::pow_pq_air::P2_CONSTRAINT_DEGREE),
                gpow: gamma_powers(gamma),
            })
        } else {
            DsolCpuGate::Rom(RomLaw { gamma, rom: rom.clone() })
        }
    }
}

/// ⛔⛔⛔ H5 — THE ROM LAW: the committed ROM table IS the program, row for row.
///
/// Found 2026-09-29: the ROM is a round-1 table the PROVER commits, and until this law nothing bound its content —
/// the ROM gate was identically zero and the statement carries only `code_id`. A prover committed a ROM holding a
/// forged instruction, the fetch bus found every CPU fetch in it, and "this contract ran" was a claim about
/// whatever ROM the prover liked. The fetch bus binds the CPU to the ROM; THIS binds the ROM to the program.
///
/// The verifier builds `cols` itself from the code it hashed to `code_id` (`build_rom_trace`, padding included), so
/// the law is: for every column `c`, `rom_c(x) − Σ_r eq(x, r)·cols[c][r] = 0` — the committed column's multilinear
/// extension equals the program column's, checked by the same zerocheck every other law rides. Degree 1 in the
/// point and 1 in the column; declared 2. `cols` is `f(program length)`, never of chain state.
pub struct RomLaw {
    pub gamma: Ea4,
    /// Where the program's columns come from — both are the verifier's own, rebuilt from the code it hashed.
    pub rom: RomSource,
}

/// The ROM law's program columns. `Table`: `ROM_COLS` laid columns, each `2^nvars` long (the prover's, and pins').
/// `Code`: the bytecode itself, streamed by [`rom_mle_from_code`] — the VERIFIER's form (D7): its memory is at most
/// `MAX_HEIGHT_LOG2 + 1` partial folds of `ROM_COLS` lanes (fixed constants), never a laid table.
#[derive(Clone)]
pub enum RomSource {
    Table(Vec<Vec<Fa4>>),
    Code(std::sync::Arc<[u8]>),
}

impl RomLaw {
    fn eval(&self, local: &Row<'_>, x: &[Ea4]) -> Ea4 {
        let expect: [Ea4; ROM_COLS] = match &self.rom {
            RomSource::Table(cols) => {
                // The zerocheck's OWN equality table, in its own point convention (`x[0]` is the HIGH bit of the row
                // index — `cyclic_shift_sigma` documents it); a second derivation of the row↔point map here was a
                // bit-reversed ROM that refused every honest program (MEASURED 03:04, first run of this law).
                let eq = crate::air_zerocheck::eq_z_hypercube(x);
                if cols.len() != ROM_COLS || cols.iter().any(|col| col.len() != eq.len()) {
                    return Ea4::ONE; // a law built for another table: a non-zero residual, i.e. a refusal
                }
                std::array::from_fn(|c| cols[c].iter().zip(&eq).fold(Ea4::ZERO, |s, (&v, &e)| s + e * Ea4::from(v)))
            }
            RomSource::Code(code) => match rom_mle_from_code(code, x) {
                Some(v) => v,
                None => return Ea4::ONE, // a program that does not lay out at this table's size: a refusal
            },
        };
        expect.iter().enumerate().fold(Ea4::ZERO, |acc, (c, e)| acc * self.gamma + (local[c] - *e))
    }
}

/// The `(round 1, round 2)` LAID table shapes a DSOL call's carrier MUST declare, from the statement and the program
/// alone.
/// - Round 1: the CPU (`2^cpu_nvars × CPU_COLS`) and the ROM (`2^rom_nvars × ROM_COLS`), as the caller lays them.
/// - Round 2: the fetch bus's ONE bus table (A-F57). It holds both sides' keys, multiplicities and LogUp terms and one
///   running sum, at the taller side's height. Derived by `postcommit_bus::bus_table_shapes`, the engine's own
///   derivation, so the statement and the engine cannot disagree.
/// - The engine blinds every table (one more variable) and appends the ROM's derived counts as a column. Both follow
///   from these shapes and are never sent.
#[must_use]
pub fn dsol_table_shapes(height_log2: u8, prog_len: usize) -> (Vec<(usize, usize)>, Vec<(usize, usize)>) {
    let cpu_nv = usize::from(height_log2);
    let rom_nv = prog_len.next_power_of_two().max(32).trailing_zeros() as usize;
    let laid1 = vec![(cpu_nv, CPU_COLS), (rom_nv, ROM_COLS)];
    let laid2 = crate::postcommit_bus::bus_table_shapes(&laid1, &[fetch_bus()]).unwrap_or_default();
    (laid1, laid2)
}

/// A DSOL call proof as it travels: the carrier bytes, nothing else. H3 (privacy) CLOSED 2026-09-29: the ROM side's
/// multiplicities — how many times each instruction ran, i.e. which branches were taken and how many loop
/// iterations — were a public input this struct carried. They are now a `BusMult::Free` column the prover derives and
/// commits, blinded, with round 1, before α (A-F57). No verifier ever sees them, and no per-side LogUp total rides the
/// carrier either: the bus's verdict is its running sum's boundary laws (A-F72). The CPU side's multiplicities are the
/// committed `C_REAL` column the relation constrains (H6), so nothing about the execution's shape rides beside the bytes.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DsolCallProof {
    pub bytes: Vec<u8>,
}

/// PROVE a DSOL call: run the machine, derive the statement, lay the tables, prove the relation under the statement
/// and the fetch bus. `None` on any refusal of the machine or the prover. Every law of the module doc (L1–L10, H1–H6,
/// S2, the wide primitives) is landed and pinned as of 2026-09-29, so a proof from here is a proof of the WHOLE execution
/// the statement names; what remains outside it is the node's door (verify, apply the effects, never re-execute).
pub fn prove_dsol_call<H: dsol_vm::SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: dsol_vm::VmCtx,
    storage: dsol_vm::StorageTrie,
    budget: u64,
    host: &mut H,
) -> Option<(DsolCallProof, DsolStatement)> {
    prove_dsol_call_padded(code, entrypoint, argv, ctx, storage, budget, host, None)
}

/// The smallest table height class that holds `rows` real rows: at least 32 rows.
#[must_use]
pub fn natural_height_log2(rows: usize) -> u8 {
    rows.next_power_of_two().max(32).trailing_zeros() as u8
}

/// The table height class the verifier accepts: 2^5 (the smallest table) up to the machine's step budget.
pub const MAX_HEIGHT_LOG2: u8 = dsol_vm::STEP_BUDGET_MAX.trailing_zeros() as u8;

/// [`prove_dsol_call`] padded to `height_log2` (`None` = the natural height): a caller that pads EVERY call of a
/// contract to one height gives all its executions one shape, so a verifier learns nothing from the proof's size — the
/// exact row count is already private; this hides the height class too. `None` when the height is below the run's
/// natural class or above [`MAX_HEIGHT_LOG2`].
#[allow(clippy::too_many_arguments)]
pub fn prove_dsol_call_padded<H: dsol_vm::SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: dsol_vm::VmCtx,
    storage: dsol_vm::StorageTrie,
    budget: u64,
    host: &mut H,
    height_log2: Option<u8>,
) -> Option<(DsolCallProof, DsolStatement)> {
    prove_dsol_call_run(code, entrypoint, argv, ctx, storage, budget, host, height_log2).map(|(p, s, _)| (p, s))
}

/// [`prove_dsol_call_padded`] that also hands back the machine's run — the returned bytes and the EFFECT LIST a node
/// needs beside the statement to match a call chain ([`authorize_call_chain`]) and to apply the effects.
#[allow(clippy::too_many_arguments)]
pub fn prove_dsol_call_run<H: dsol_vm::SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: dsol_vm::VmCtx,
    storage: dsol_vm::StorageTrie,
    budget: u64,
    host: &mut H,
    height_log2: Option<u8>,
) -> Option<(DsolCallProof, DsolStatement, dsol_vm::VmRun)> {
    let storage_pre = storage.root();
    let ctx_for_stmt = ctx.clone();
    let t = dsol_vm::run(code, entrypoint, argv, ctx, storage, budget, host).ok()?;
    let (proof, stmt) = prove_trace(code, entrypoint, argv, storage_pre, &ctx_for_stmt, &t, height_log2)?;
    Some((proof, stmt, t.run))
}

/// Prove ONE machine trace (a whole call or one segment of it): the statement from the trace, the tables at the height
/// class (`height_log2`: `None` = the natural class), the relation under the statement and the fetch bus.
fn prove_trace(code: &[u8], entrypoint: &str, argv: &[u8], storage_pre: Digest, ctx: &dsol_vm::VmCtx, t: &VmTrace, height_log2: Option<u8>) -> Option<(DsolCallProof, DsolStatement)> {
    let mut stmt = statement_of(code, entrypoint, argv, storage_pre, ctx, t)?;
    if let Some(h) = height_log2 {
        if h < stmt.height_log2 || h > MAX_HEIGHT_LOG2 {
            return None;
        }
        stmt.height_log2 = h;
    }
    let prog = decode_program(code)?;
    let (shapes1, _) = dsol_table_shapes(stmt.height_log2, prog.len());
    let (cpu_rows, rom_rows) = (1usize << shapes1[0].0, 1usize << shapes1[1].0);
    let cpu = build_cpu_trace(t, code, cpu_rows)?;
    let rom = build_rom_trace(&prog, rom_rows)?;
    let buses = vec![fetch_bus()];
    let gate = dsol_gate_for(stmt.clone(), rom.clone());
    let bytes = crate::postcommit_bus::prove_postcommit_bus_bytes(vec![cpu, rom], &gate, &buses, &stmt.bind())?;
    Some((DsolCallProof { bytes }, stmt))
}

/// Prove one SEGMENT of a call (continuations, plan item 5): run the machine from `resume` (or fresh), cutting at the
/// first opcode boundary after `cut_after` rows (or to the RETURN), and prove that segment's trace. Hands back the proof,
/// the statement (`state_in` / `state_out` bind the segment's ends), the run (its effect list) and the [`dsol_vm::Resume`]
/// its successor starts from (`None` when it returned). A wallet chains segments until the machine returns; the node
/// authorises the chain with [`authorize_segment_chain`].
#[allow(clippy::too_many_arguments)]
pub fn prove_dsol_segment<H: dsol_vm::SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: dsol_vm::VmCtx,
    storage: dsol_vm::StorageTrie,
    budget: u64,
    host: &mut H,
    resume: Option<dsol_vm::Resume>,
    cut_after: Option<usize>,
    height_log2: Option<u8>,
) -> Option<(DsolCallProof, DsolStatement, dsol_vm::VmRun, Option<dsol_vm::Resume>)> {
    // a continued segment starts from the storage its predecessor left (the resume carries it); `storage` is the fresh start's
    let storage_pre = match &resume {
        Some(r) => r.storage.root(),
        None => storage.root(),
    };
    let ctx_for_stmt = ctx.clone();
    let (t, next) = dsol_vm::run_segment(code, entrypoint, argv, ctx, storage, budget, host, resume, cut_after).ok()?;
    let (proof, stmt) = prove_trace(code, entrypoint, argv, storage_pre, &ctx_for_stmt, &t, height_log2)?;
    Some((proof, stmt, t.run, next))
}

/// ⭐⭐⭐ THE NODE'S RULE FOR A SEGMENT CHAIN (continuations), as the pure function its door calls: every segment's proof
/// verifies against the ONE code; the first opens fresh (`state_in` zero) and the last ends in a RETURN (`state_out`
/// zero); each segment's `state_out` is the next one's `state_in` and is never zero in between; the code id, entrypoint,
/// argument, context (`cid`, `caller`, `subaddress`, `tx_hash`, `block_number`) are the same throughout; `storage_post`
/// hands to `storage_pre`; and each segment's effect list, folded from its predecessor's `effects_digest`, is its own
/// `effects_digest` — the concatenation of the lists is what the node applies. Any break refuses the WHOLE chain.
pub fn authorize_segment_chain(segments: &[ProvenCall<'_>], code_of: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>) -> bool {
    let Some(first) = segments.first() else { return false };
    let Some(code) = code_of(&first.stmt.code_id) else { return false };
    let zero = [0u64; DIGEST_LANES];
    if first.stmt.state_in != zero || segments[segments.len() - 1].stmt.state_out != zero {
        return false;
    }
    let mut prev_effects = zero;
    for (i, s) in segments.iter().enumerate() {
        if !verify_dsol_call(s.proof, &code, s.stmt) || dsol_vm::fold_effects_from(&prev_effects, s.effects) != s.stmt.effects_digest {
            return false;
        }
        prev_effects = s.stmt.effects_digest;
        if i > 0 {
            let p = segments[i - 1].stmt;
            let same_call = p.code_id == s.stmt.code_id
                && p.entry_sel == s.stmt.entry_sel
                && p.start_pc == s.stmt.start_pc
                && p.argv_digest == s.stmt.argv_digest
                && p.argv_len == s.stmt.argv_len
                && p.cid == s.stmt.cid
                && p.caller == s.stmt.caller
                && p.subaddress == s.stmt.subaddress
                && p.tx_hash == s.stmt.tx_hash
                && p.block_number == s.stmt.block_number;
            if !same_call || p.state_out == zero || p.state_out != s.stmt.state_in || p.storage_post != s.stmt.storage_pre {
                return false;
            }
        }
    }
    true
}

/// One proven call in a chain as a node holds it: the proof, its statement, and the effect list the prover ships (the
/// statement carries only the list's fold).
pub struct ProvenCall<'a> {
    pub proof: &'a DsolCallProof,
    pub stmt: &'a DsolStatement,
    pub effects: &'a [dsol_vm::Effect],
}

/// ⭐⭐⭐ THE NODE'S RULE FOR A CALL CHAIN (plan item 2), as the pure function its door calls. The circuit proves each
/// contract ISSUED its calls; this AUTHORISES them: every proof verifies against the code its statement names, every
/// effect list folds to its statement's `effects_digest`, every `Call` effect is matched by exactly one callee statement
/// (the callee's code id as a string digest, the entrypoint, the argument digest and length, the returned digest, and the
/// binding `H(H(storage_pre, storage_post), effects_digest)`), the callee's `caller` is the CALLING CONTRACT's `cid` (never a
/// user), a contract's `cid` is its code id (content-addressed), every callee proof is reached by exactly one effect, and
/// **a callee whose code id is already on its call path is refused — re-entry is impossible by construction**: a
/// contract's storage root is locked while it has a call in flight, so a re-entering statement could only name a stale
/// `storage_pre`. `code_of` hands back the bytecode for a code id (the registry's lookup). `resolve` maps the callee
/// string a `Call` effect named (as its digest) to the code id it means NOW: a governance-owned upgrade POINTER resolves
/// to the code id authorised at this block (the node's pointer table); a raw 32-byte code id resolves to itself when the
/// hook answers `None`. Any unmatched effect, unmatched callee, foreign caller, mismatched binding or failed proof refuses
/// the WHOLE chain.
pub fn authorize_call_chain(
    root: &ProvenCall<'_>,
    callees: &[ProvenCall<'_>],
    code_of: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    resolve: &dyn Fn(&Digest) -> Option<[u8; 32]>,
) -> bool {
    // a content-addressed root: its identity is its code (the shape the plan's item 2 wrote)
    let root_cid = dsol_vm::str_digest(&root.stmt.code_id);
    authorize_call_chain_bound(root, callees, code_of, resolve, &root_cid)
}

/// ⭐ §BR-12 L2 (docs/DSOL-NODE-DOOR-SPEC.md §12) — [`authorize_call_chain`] with the ROOT's identity supplied by the caller:
/// the chain's contract-state leaf binds `code_id` to a `cid` that is a function of the deploying transaction (two instances of
/// one code are two contracts), so the node — which verified that leaf against its root — names the cid the root must carry.
/// The callee rule (`callee.caller == the calling contract's cid`) and the re-entry refusal are unchanged.
pub fn authorize_call_chain_bound(
    root: &ProvenCall<'_>,
    callees: &[ProvenCall<'_>],
    code_of: &dyn Fn(&[u8; 32]) -> Option<Vec<u8>>,
    resolve: &dyn Fn(&Digest) -> Option<[u8; 32]>,
    root_cid: &Digest,
) -> bool {
    let sound = |c: &ProvenCall<'_>| -> bool {
        let Some(code) = code_of(&c.stmt.code_id) else { return false };
        verify_dsol_call(c.proof, &code, c.stmt) && dsol_vm::fold_effects(c.effects) == c.stmt.effects_digest
    };
    if root.stmt.cid != *root_cid || !sound(root) || !callees.iter().all(sound) {
        return false;
    }
    let mut used = vec![false; callees.len()];
    // the path holds STORAGE identities (cids): a plain callee's storage is locked while it is in flight; a library shares
    // its caller's storage by design and is admitted only through a LibCall effect
    fn walk(
        node: &ProvenCall<'_>,
        callees: &[ProvenCall<'_>],
        used: &mut [bool],
        path: &mut Vec<Digest>,
        resolve: &dyn Fn(&Digest) -> Option<[u8; 32]>,
    ) -> bool {
        // what every call effect names: the callee (a pointer the node resolves to today's code id, or a raw code id —
        // itself), the entrypoint, the argument and the return
        let common = |c: &ProvenCall<'_>, code_id: &Digest, entry_sel: u32, argv: &Digest, argv_len: u32, ret: &Digest| -> bool {
            let named = match resolve(code_id) {
                Some(id) => id == c.stmt.code_id,
                None => dsol_vm::str_digest(&c.stmt.code_id) == *code_id,
            };
            named && c.stmt.entry_sel == entry_sel && c.stmt.argv_digest == *argv && c.stmt.argv_len == argv_len && c.stmt.ret_digest == *ret
        };
        for e in node.effects {
            match e {
                dsol_vm::Effect::Call { code_id, entry_sel, argv, argv_len, ret, callee, .. } => {
                    let Some(idx) = callees.iter().enumerate().position(|(i, c)| {
                        !used[i]
                            && common(c, code_id, *entry_sel, argv, *argv_len, ret)
                            && dsol_vm::callee_binding(&c.stmt.storage_pre, &c.stmt.storage_post, &c.stmt.effects_digest) == *callee
                            && c.stmt.caller == node.stmt.cid
                            && c.stmt.cid == dsol_vm::str_digest(&c.stmt.code_id)
                    }) else {
                        return false; // an issued call no callee statement answers for
                    };
                    let c = &callees[idx];
                    if path.contains(&c.stmt.cid) {
                        return false; // re-entry into a contract whose storage is in flight
                    }
                    used[idx] = true;
                    path.push(c.stmt.cid);
                    if !walk(c, callees, used, path, resolve) {
                        return false;
                    }
                    path.pop();
                }
                dsol_vm::Effect::LibCall { code_id, entry_sel, argv, argv_len, ret, pre, post, effects, .. } => {
                    let Some(idx) = callees.iter().enumerate().position(|(i, c)| {
                        !used[i]
                            && common(c, code_id, *entry_sel, argv, *argv_len, ret)
                            && c.stmt.storage_pre == *pre
                            && c.stmt.storage_post == *post
                            && c.stmt.effects_digest == *effects
                            && c.stmt.cid == node.stmt.cid // the library IS the caller's storage and identity ...
                            && c.stmt.caller == node.stmt.caller // ... and sees the caller's caller
                    }) else {
                        return false;
                    };
                    used[idx] = true;
                    // the library's cid is the caller's, already on the path: nothing to push — its own nested plain
                    // calls back into any storage on the path are refused exactly as the caller's would be
                    if !walk(&callees[idx], callees, used, path, resolve) {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }
    let mut path = vec![root.stmt.cid];
    walk(root, callees, &mut used, &mut path, resolve) && used.iter().all(|u| *u)
}

/// The resolver for chains that name callees by RAW code id only (no upgrade pointers): every callee string resolves to
/// itself — the matcher then checks `str_digest(code_id) == the named digest`.
#[must_use]
pub fn no_pointers(_named: &Digest) -> Option<[u8; 32]> {
    None
}

/// VERIFY a DSOL call proof against the code the verifier holds and the statement it was handed: the code must hash
/// to `stmt.code_id`, the header must map `entry_sel` to `start_pc`, the ROM is rebuilt from the code and becomes
/// the ROM law (H5), every table shape comes from the statement, and the gate is rebuilt from the statement. Nothing
/// is read off the carrier — not even a multiplicity (H6/H3).
#[must_use]
pub fn verify_dsol_call(proof: &DsolCallProof, code: &[u8], stmt: &DsolStatement) -> bool {
    if *blake3::hash(code).as_bytes() != stmt.code_id {
        return false;
    }
    let Ok(entries) = dsol_vm::parse_entries(code) else { return false };
    if !entries.iter().any(|&(h, pc)| h == stmt.entry_sel && pc == stmt.start_pc) {
        return false;
    }
    // D7: COUNT the program by the one walk — refused at `DSOL_ROM_ROWS_MAX`, nothing laid
    let Some(prog_len) = walk_program(code, |_| {}) else { return false };
    // the height class is bounded before it sizes anything: a hostile statement cannot make the verifier allocate
    if stmt.height_log2 < natural_height_log2(1) || stmt.height_log2 > MAX_HEIGHT_LOG2 {
        return false;
    }
    let (shapes1, shapes2) = dsol_table_shapes(stmt.height_log2, prog_len);
    // the verifier's OWN ROM, streamed from the code it hashed: what the committed one must equal, row for row (H5)
    let buses = vec![fetch_bus()];
    let gate = dsol_gate_for_code(stmt.clone(), std::sync::Arc::from(code));
    crate::postcommit_bus::verify_postcommit_bus_bytes(&proof.bytes, &gate, &buses, &stmt.bind(), &shapes1, &shapes2)
}

/// The per-table gate a DSOL call is proven under: constraint table 0 is the CPU (the relation above); table 1 is
/// the ROM, whose one law ([`RomLaw`], H5) is that it IS the program the verifier rebuilt from the code — the fetch
/// bus (L2) then binds the CPU to it.
pub enum DsolCpuGate {
    Cpu(DsolCpuConstraint),
    Rom(RomLaw),
}

impl AirConstraint for DsolCpuGate {
    fn degree(&self, nvars: usize) -> usize {
        match self {
            DsolCpuGate::Cpu(c) => c.degree(nvars),
            DsolCpuGate::Rom(_) => 2, // degree 1 in the point, 1 in the column
        }
    }
    fn eval(&self, local: &Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        match self {
            DsolCpuGate::Cpu(c) => c.eval(local, at, x),
            DsolCpuGate::Rom(r) => r.eval(local, x),
        }
    }
    fn is_row_local(&self) -> bool {
        match self {
            DsolCpuGate::Cpu(c) => c.is_row_local(),
            DsolCpuGate::Rom(_) => true,
        }
    }
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        match self {
            DsolCpuGate::Cpu(c) => c.shifted_cols(),
            DsolCpuGate::Rom(_) => Some(Vec::new()),
        }
    }
    fn has_base_eval(&self) -> bool {
        matches!(self, DsolCpuGate::Cpu(_))
    }
    fn eval_base(&self, local: &Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        match self {
            DsolCpuGate::Cpu(c) => c.eval_base(local, at, x),
            DsolCpuGate::Rom(_) => unreachable!("the ROM law has no base path"),
        }
    }
}


// ─────────────────────────────────────────────────────────────────────────────────────────────────
// L2 FETCH — the law that makes a proof be about a CONTRACT
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The ROM table's columns: the program counter, the opcode, the instruction's immediate and — H1 — the digest of a
/// `PUSH_BYTES` literal (zero lanes on every other instruction). The SAME four the CPU row carries, so the bus key is a
/// tuple both sides already hold.
pub const ROM_PC: usize = 0;
pub const ROM_OP: usize = 1;
/// The immediate's four 16-bit limbs, the same split the CPU row carries (`C_IMM_LIMBS`).
pub const ROM_IMM: usize = 2;
/// The literal digest's lanes (H1).
pub const ROM_LIT: usize = ROM_IMM + C_IMM_LIMBS;
pub const ROM_COLS: usize = ROM_LIT + DIGEST_LANES;
/// The fetch-bus key length: pc, op, the immediate's limbs, the literal digest's lanes — ONE spelling for both sides
/// and for the side tables' declared width.
pub const FETCH_KEY_LEN: usize = 2 + C_IMM_LIMBS + DIGEST_LANES;

/// Every instruction position in a contract's bytecode, decoded once.
///
/// ⭐⭐⭐ THE PROGRAM IS PUBLIC, AND THAT IS WHY THIS WORKS. A contract is content-addressed: its id is
/// the blake3 of these very bytes, and the chain's token registry holds that id. So a verifier can build
/// this table itself from bytes it already has, and the fetch bus then says *"every instruction the CPU
/// executed is one of THESE"* — which is the difference between proving a computation happened and
/// proving THIS CONTRACT ran. Nothing private lives here; the privacy is in the arguments and the
/// intermediate values, which never leave the CPU table.
///
/// Walks the instruction stream from the end of the entry-point header, so a `PUSH_BYTES` literal's
/// bytes are never mistaken for opcodes. `None` on a malformed program — a truncated instruction, an
/// opcode the circuit has no law for, or a stream that does not land exactly on its end.
#[must_use]
pub fn decode_program(code: &[u8]) -> Option<Vec<(u32, u8, u64, Digest)>> {
    let mut out = Vec::new();
    walk_program(code, |ins| out.push(ins))?;
    Some(out)
}

/// ⛔ D7 (DSOL door review, 2026-09-30) — THE ROM'S CEILING: a program holds at most `2^MAX_HEIGHT_LOG2` instructions,
/// the one table-class ceiling every table the verifier accepts obeys (the CPU's is checked on the statement). Before
/// this bound the verifier's size check was vacuous (`rom_rows` was DERIVED from `prog.len()`, so `prog.len() > rom_rows`
/// could never hold): a 16 MB frame of one-byte opcodes decoded to 2^24 instructions and the verifier materialised a
/// 2^24-row ROM plus a 2^24 equality table from OUTSIDE bytes. The walk refuses at the ceiling, before it lays anything.
pub const DSOL_ROM_ROWS_MAX: usize = 1 << MAX_HEIGHT_LOG2;

/// THE one instruction walk — [`decode_program`] collects it, the verifier's streamed ROM law ([`RomSource::Code`])
/// consumes it without laying the program. Hands `each` every instruction in order and returns the count; `None` on a
/// malformed program or one past [`DSOL_ROM_ROWS_MAX`] (refused at the first instruction over, nothing laid).
fn walk_program(code: &[u8], mut each: impl FnMut((u32, u8, u64, Digest))) -> Option<usize> {
    let entries = dsol_vm::parse_entries(code).ok()?;
    let hdr = 5 + entries.len() * 8;
    let mut n = 0usize;
    let mut pc = hdr;
    while pc < code.len() {
        if n >= DSOL_ROM_ROWS_MAX {
            return None;
        }
        let o = code[pc];
        // An opcode with no selector has no transition law, so a program containing one could never be
        // proven anyway; refusing here says so at decode time instead of at a mystifying zerocheck.
        op_index(o)?;
        let imm = imm_of(code, pc as u32, o)?;
        let w = op_width(code, pc as u32, o)? as usize;
        // H1: a PUSH_BYTES row's literal digest is a ROM constant — the verifier digests the literal itself here.
        let lit: Digest = if o == op::PUSH_BYTES {
            let start = pc.checked_add(3)?;
            dsol_vm::str_digest(code.get(start..start.checked_add(imm as usize)?)?)
        } else {
            [0; DIGEST_LANES]
        };
        each((pc as u32, o, imm, lit));
        n += 1;
        pc = pc.checked_add(w)?;
    }
    if pc != code.len() {
        return None; // the last instruction ran off the end
    }
    Some(n)
}

/// One ROM row, in the column order of [`ROM_COLS`] — the ONE spelling [`build_rom_trace`] lays and the streamed law
/// folds.
fn rom_row((pc, o, imm, lit): (u32, u8, u64, Digest)) -> [Fa4; ROM_COLS] {
    let mut row = [Fa4::ZERO; ROM_COLS];
    row[ROM_PC] = f(u64::from(pc));
    row[ROM_OP] = f(u64::from(o));
    for l in 0..C_IMM_LIMBS {
        row[ROM_IMM + l] = f((imm >> (W_BITS * l)) & ((1 << W_BITS) - 1));
    }
    for d in 0..DIGEST_LANES {
        row[ROM_LIT + d] = f(lit[d]);
    }
    row
}

/// The program's ROM columns' multilinear extensions at `x`, STREAMED from the code: rows arrive in order and fold
/// pairwise as their sibling completes (row bit `ℓ` binds `x[n−1−ℓ]`, the [`crate::air_zerocheck::eq_z_hypercube`]
/// convention — `x[0]` is the HIGH bit), padding rows repeat the final instruction as [`build_rom_trace`] lays them.
/// O(rows · ROM_COLS) work and O(n · ROM_COLS) memory. `None` on a malformed program, an empty one, or one longer than
/// `2^n` rows.
fn rom_mle_from_code(code: &[u8], x: &[Ea4]) -> Option<[Ea4; ROM_COLS]> {
    let n = x.len();
    if n > usize::from(MAX_HEIGHT_LOG2) {
        return None;
    }
    let rows = 1usize << n;
    let mut stack: Vec<(usize, [Ea4; ROM_COLS])> = Vec::with_capacity(n + 1);
    let fold_in = |stack: &mut Vec<(usize, [Ea4; ROM_COLS])>, row: [Fa4; ROM_COLS]| {
        let mut cur = (0usize, row.map(Ea4::from));
        while let Some(&(lvl, a)) = stack.last() {
            if lvl != cur.0 || lvl >= n {
                break;
            }
            stack.pop();
            let z = x[n - 1 - lvl];
            let one_m_z = Ea4::ONE - z;
            let mut folded = [Ea4::ZERO; ROM_COLS];
            for c in 0..ROM_COLS {
                folded[c] = a[c] * one_m_z + cur.1[c] * z;
            }
            cur = (lvl + 1, folded);
        }
        stack.push(cur);
    };
    let mut last = None;
    let mut folded_rows = 0usize;
    let count = walk_program(code, |ins| {
        if folded_rows < rows {
            last = Some(ins);
            fold_in(&mut stack, rom_row(ins));
            folded_rows += 1;
        }
    })?;
    let over = count > folded_rows;
    if over || count == 0 || count > rows {
        return None;
    }
    let pad = rom_row(last?);
    for _ in count..rows {
        fold_in(&mut stack, pad);
    }
    match stack.as_slice() {
        [(lvl, v)] if *lvl == n => Some(*v),
        _ => None,
    }
}

/// The ROM as a committed table of `rows` (a power of two). Padding rows repeat the FINAL instruction
/// and carry multiplicity zero, so they contribute nothing to the bus.
#[must_use]
// H1 (2026-09-29) — the ROM row carries the literal digest.
// ROOT-LAYER: the ROM is where a program's constants are PRODUCED for the circuit — the verifier rebuilds it from the
//   code it hashed, so the literal's digest is the verifier's own here; the CPU row only READS it (through the bus key)
//   and the landing law pins the slot to what it read. Fixing at the slot alone would pin a slot to a free column.
// MEASURED: the pin `h1_a_swapped_literal_digest_is_refused` — under the old key (no literal lanes) both literal
//   forgeries prove AND verify (armed 2/2); with the lanes the same two must be refused (the pin's assertion, run at
//   this landing).
// MUST-STAY-GREEN: every `fetch_tests` pin (the bus with the wider key), the layout census, dsol_vm, postcommit_bus.
pub fn build_rom_trace(prog: &[(u32, u8, u64, Digest)], rows: usize) -> Option<Vec<Vec<Fa4>>> {
    if prog.is_empty() || !rows.is_power_of_two() || prog.len() > rows {
        return None;
    }
    let mut cols = vec![vec![Fa4::ZERO; rows]; ROM_COLS];
    let last = *prog.last()?;
    for r in 0..rows {
        // padding rows repeat the FINAL instruction (multiplicity zero on the bus), as the doc above states
        let row = rom_row(if r < prog.len() { prog[r] } else { last });
        for (c, v) in row.into_iter().enumerate() {
            cols[c][r] = v;
        }
    }
    Some(cols)
}

// DELETED 2026-09-29 (H6): `fetch_multiplicities`, which handed the bus two caller-built multiplicity vectors — the
// CPU's `−1` per real row and the ROM's per-instruction counts. Neither was tied to anything a verifier checked, so a
// prover could zero a forged row's multiplicity and the bus never asked about it; the ROM counts also rode the proof
// as public inputs (H3). The CPU side's multiplicities are now the relation-constrained `C_REAL` column, the ROM
// side's are derived by the bus prover from the CPU's committed keys (`postcommit_bus::derive_side_multiplicities`),
// and a fetch of a key the ROM does not hold is refused there, by name, at prove time.

/// The fetch bus, ready for [`crate::postcommit_bus::prove_postcommit_bus_bytes`]: table 0 is the CPU, table 1 the
/// ROM, and the key is the `(pc, op, imm)` tuple both already commit.
///
/// * CPU side: its multiplicity IS the committed [`C_REAL`] column (`BusMult::Column`), `1` on every row the trace
///   occupies and `0` on padding by the L2/H6 laws in [`DsolCpuConstraint`]; tied at `r*` like the keys. Each real
///   row is asked of the ROM, and only real rows are.
/// * ROM side: derived and committed by the prover (`BusMult::Free`) — minus the number of real CPU rows that fetched
///   each instruction, `0` on padding — and never public.
///
/// The bus balances iff every real `(pc, op, imm)` the CPU executed is a row of the ROM; the ROM law (H5) makes the
/// ROM the program. Takes nothing: there is no caller-supplied multiplicity left to take.
#[must_use]
pub fn fetch_bus() -> crate::postcommit_bus::BusSpec {
    use crate::postcommit_bus::{BusMult, BusSide, BusSpec};
    // ONE key shape for both sides: pc, op, the immediate's limbs, the literal digest's lanes (H1).
    let key = |pc: usize, o: usize, imm: usize, lit: usize| -> Vec<usize> {
        let mut v = vec![pc, o];
        v.extend((0..C_IMM_LIMBS).map(|l| imm + l));
        v.extend((0..DIGEST_LANES).map(|d| lit + d));
        debug_assert_eq!(v.len(), FETCH_KEY_LEN);
        v
    };
    BusSpec {
        sides: vec![
            BusSide { table: 0, cols: key(C_PC, C_OP, C_IMM, C_LIT), mult: BusMult::Column(C_FETCH) },
            BusSide { table: 1, cols: key(ROM_PC, ROM_OP, ROM_IMM, ROM_LIT), mult: BusMult::Free },
        ],
    }
}

#[cfg(test)]
mod fetch_tests {
    use super::*;
    use crate::air_zerocheck::{AirConstraint, Row};
    use crate::hiding_decider::Ea4;
    use crate::postcommit_bus::{prove_postcommit_bus_bytes, verify_postcommit_bus_bytes};

    /// ⛔ THIS GATE CONSTRAINS NOTHING, ON PURPOSE, AND THAT IS THE LIMIT OF WHAT THE PIN BELOW CLAIMS.
    ///
    /// L2 FETCH is one law of ten. These pins measure THAT law — that every instruction the trace
    /// executed is one the contract's own program contains — and nothing else. The stack, ALU, control,
    /// sponge, packing, storage, effects and boundary laws (L1, L3–L10) are not written yet, so a
    /// carrier that passes here is NOT a proven execution. Naming that here keeps the pin from reading
    /// as more than it is.
    struct FetchOnlyGate;
    impl AirConstraint for FetchOnlyGate {
        fn degree(&self, _nvars: usize) -> usize {
            8
        }
        fn eval(&self, _l: &Row<'_>, _at: &dyn Fn(usize, &[Ea4]) -> Ea4, _x: &[Ea4]) -> Ea4 {
            Ea4::ZERO
        }
    }
    fn gates(_i: usize, _g: Ea4) -> FetchOnlyGate {
        FetchOnlyGate
    }

    const BIND: [Fa4; 1] = [Fa4::new(0x4453_4C46)]; // "DSLF"

    /// A real DSOL program: drop the argv, multiply, return.
    fn program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&7u64.to_le_bytes());
        out.push(op::PUSH_U64);
        out.extend_from_slice(&6u64.to_le_bytes());
        out.push(op::MUL_U64);
        out.push(op::RETURN);
        out
    }

    fn run_it(code: &[u8]) -> VmTrace {
        dsol_vm::run(
            code,
            "main",
            b"",
            dsol_vm::VmCtx::default(),
            dsol_vm::StorageTrie::default(),
            1 << 16,
            &mut dsol_vm::NoHost,
        )
        .expect("the program runs")
    }

    /// The statement of a `run_it` execution (entry "main", empty argv, the default trie's root as `storage_pre`, the
    /// default context).
    fn stmt_for(code: &[u8], argv: &[u8], t: &VmTrace) -> DsolStatement {
        statement_of(code, "main", argv, dsol_vm::StorageTrie::default().root(), &dsol_vm::VmCtx::default(), t).expect("the statement derives")
    }

    /// ⭐⭐⭐ L2 FETCH, MEASURED END TO END: a real execution's fetches balance against the contract's
    /// OWN program, and a fetch of an instruction the program does not contain is REFUSED.
    ///
    /// This is the law that makes a private execution proof be about a CONTRACT. Without it the circuit
    /// proves that *some* computation happened; with it, that THIS bytecode ran.
    #[test]
    fn a_real_execution_fetches_only_instructions_its_own_program_contains() {
        let code = program();
        let prog = decode_program(&code).expect("the program decodes");
        assert!(prog.len() >= 5, "the program has real instructions to fetch: {}", prog.len());
        let t = run_it(&code);

        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let cpu = build_cpu_trace(&t, &code, cpu_rows).expect("the execution lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("the program lays out");
        let buses = vec![fetch_bus()];

        let proof = prove_postcommit_bus_bytes(vec![cpu, rom], gates, &buses, &BIND)
            .expect("an honest execution's fetch bus proves");
        assert!(
            verify_postcommit_bus_bytes(&proof, gates, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&proof).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&proof).1),
            "an independently-derived verifier must accept an honest execution's fetches"
        );
        eprintln!(
            "[dsol-fetch] {} steps over a {}-instruction program ⇒ {} byte(s)",
            t.steps.len(),
            prog.len(),
            proof.len()
        );

        // ⛔ THE ATTACK: the trace claims to have executed an opcode at a pc the program holds, but with
        // a DIFFERENT opcode than the program has there. The CPU table commits the forged pair, and the
        // ROM cannot receive it.
        let mut forged = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        forged[C_OP][0] = f(u64::from(op::REVERT));
        let rom2 = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses2 = vec![fetch_bus()];
        match prove_postcommit_bus_bytes(vec![forged, rom2], gates, &buses2, &BIND) {
            Some(p) => assert!(
                !verify_postcommit_bus_bytes(&p, gates, &buses2, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                "⛔ A FETCH THE PROGRAM DOES NOT CONTAIN VERIFIED. The proof would then be about a \
                 computation, not about this contract — which is the entire point of L2."
            ),
            None => {}
        }
    }

    /// `POP; PUSH_BYTES "k"; PUSH_U64 42; SSTORE; PUSH_BYTES "k"; SLOAD; POP; PUSH_U64 1; RETURN` — a write, then a read
    /// of the same word slot. The read's result is POPPED, so a forged read touches exactly the access rows, the FINISH
    /// row and the POP row's stack — and nothing downstream (the statement stays the honest one).
    fn storage_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        let key = b"k";
        let push_key = |out: &mut Vec<u8>| {
            out.push(op::PUSH_BYTES);
            out.extend_from_slice(&(key.len() as u16).to_le_bytes());
            out.extend_from_slice(key);
        };
        out.push(op::POP);
        push_key(&mut out);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&42u64.to_le_bytes());
        out.push(op::SSTORE);
        push_key(&mut out);
        out.push(op::SLOAD);
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// Re-lay one row's Poseidon2 block in a column-major table from a fresh permutation input — what a forger who
    /// rewrites a path row must do to keep the block itself honest, so the refusal below is the STORAGE law's.
    fn relay_block(t: &mut [Vec<Fa4>], r: usize, state: [p3_koala_bear::KoalaBear; crate::pow_pq_air::WIDTH]) {
        let mut tmp = vec![Fa4::ZERO; CPU_COLS];
        crate::pow_pq_air::lay_perm_row_flat(&mut tmp, C_P2, state);
        for c in C_P2..CPU_COLS {
            t[c][r] = tmp[c];
        }
    }

    /// `POP; PUSH_BYTES "topic"; PUSH_BYTES "data"; EMIT; PUSH_BYTES "secret"; NULLIFIER; POP; PUSH_BYTES "k"; PUSH_U64 7;
    /// SSTORE_PRIV; PUSH_U64 1; RETURN` — the three provable effect kinds, in order: an event, a nullifier, a private slot.
    fn effects_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        let push_bytes = |out: &mut Vec<u8>, b: &[u8]| {
            out.push(op::PUSH_BYTES);
            out.extend_from_slice(&(b.len() as u16).to_le_bytes());
            out.extend_from_slice(b);
        };
        out.push(op::POP);
        push_bytes(&mut out, b"topic");
        push_bytes(&mut out, b"data");
        out.push(op::EMIT);
        push_bytes(&mut out, b"secret");
        out.push(op::NULLIFIER);
        out.push(op::POP);
        push_bytes(&mut out, b"k");
        out.push(op::PUSH_U64);
        out.extend_from_slice(&7u64.to_le_bytes());
        out.push(op::SSTORE_PRIV);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// THE FORGER'S FOLD (test-only): re-derive the effects fold over a CPU table from `from_row` on, exactly as a forger
    /// must to keep every block honest — each EFX row's inputs are resolved from the schedule's sources as the TRACE
    /// holds them, with `override_in(row, side)` substituting one; its block is re-laid; its carries and the running
    /// accumulator are rewritten; the final accumulator (the forged statement's `effects_digest`) is returned. `drop_at`
    /// names the last-stage row whose fold is NOT applied (a dropped effect).
    ///
    /// ROOT-LAYER: the PRODUCTION derivation of the fold is `Machine::effect_rows` over the ONE schedule `efx_plan`, and
    /// the circuit's L9 laws constrain that same schedule; this helper is the ADVERSARY's computation over that schedule
    /// (an inconsistent forgery would be refused by the block law and prove nothing about the effects law), which is why
    /// it lives in the test module and nowhere else.
    /// MEASURED: over the honest table it reproduces the statement's digest and rewrites nothing (asserted below every
    /// run); the four forgeries it builds are armed 4/4 under a law-free gate and refused 4/4 under the relation.
    /// MUST-STAY-GREEN: every `fetch_tests` pin (L1, L3, L4a, L4b, L5, L6/L7, L8, L10, H5, H6) and the `dsol_vm` pins.
    fn refold(
        t: &mut [Vec<Fa4>],
        steps: &[Step],
        cid: crate::poseidon2_compress::Digest,
        from_row: usize,
        override_in: &dyn Fn(usize, usize) -> Option<crate::poseidon2_compress::Digest>,
        drop_at: Option<usize>,
    ) -> crate::poseidon2_compress::Digest {
        use crate::poseidon2_compress::{compress, lanes_of, Digest};
        use p3_field::PrimeField64;
        let rows = t[0].len();
        let mut acc: Digest = core::array::from_fn(|d| t[C_EACC + d][from_row].as_canonical_u64());
        let mut tmp: [Digest; 2] = [[0u64; DIGEST_LANES]; 2];
        for r in from_row..rows {
            for d in 0..DIGEST_LANES {
                t[C_EACC + d][r] = f(acc[d]);
            }
            let Some(s) = steps.get(r) else { continue };
            if s.micro != mk::EFX {
                continue;
            }
            let k = usize::from(s.estage);
            let step = dsol_vm::efx_plan(s.op)[k];
            if k == 0 {
                tmp = [[0u64; DIGEST_LANES]; 2];
            }
            for d in 0..DIGEST_LANES {
                t[C_ETMP + d][r] = f(tmp[0][d]);
                t[C_ETMP2 + d][r] = f(tmp[1][d]);
            }
            let slot = |n: u8| match s.stack[usize::from(n)] {
                dsol_vm::VmVal::Str { digest, len } => (digest, len),
                dsol_vm::VmVal::Word(_) => panic!("the schedule names a string operand"),
            };
            let resolve = |src: dsol_vm::EfxSrc, side: usize| -> Digest {
                use dsol_vm::EfxSrc as S;
                match src {
                    S::Const(c) => lanes_of(&[c]),
                    S::ConstSysOp(c) => lanes_of(&[c, 0]),
                    S::SlotDigest(n) => slot(n).0,
                    S::SlotLen(n) => lanes_of(&[u64::from(slot(n).1)]),
                    S::Cid => cid,
                    S::SpongeA => s.sponges[dsol_vm::SPONGE_A].digest(),
                    S::SpongeC => s.sponges[dsol_vm::SPONGE_C].digest(),
                    S::Plen => lanes_of(&[u64::from(s.plen)]),
                    S::Tmp0 => tmp[0],
                    S::Tmp1 => tmp[1],
                    S::Acc => acc,
                    S::PKey => s.path_key,
                    // the L9 pins' programs issue no CALL; a CALL's immediate would come from the code, as `ConstSysOp`'s does
                    S::ConstImmPlen(c) => lanes_of(&[c, 0, u64::from(s.plen)]),
                    S::Callee => s.callee,
                    S::ConstImmPlenAlen(c) => lanes_of(&[c, 0, u64::from(s.plen), 0]),
                    S::SRoot => s.storage_root,
                    S::LibEffects => s.lib_effects,
                }
            };
            // the forger's substitution, where the pin asked for one; the honest source everywhere else
            let l = match override_in(r, 0) {
                Some(forged) => forged,
                None => resolve(step.left, 0),
            };
            let rr = match override_in(r, 1) {
                Some(forged) => forged,
                None => resolve(step.right, 1),
            };
            relay_block(t, r, crate::pow_pq_air::pair_state(&l, &rr));
            let out = compress(&l, &rr);
            match step.out {
                dsol_vm::EfxDst::Tmp0 => tmp[0] = out,
                dsol_vm::EfxDst::Tmp1 => tmp[1] = out,
                dsol_vm::EfxDst::Acc => {
                    if drop_at != Some(r) {
                        acc = out;
                    }
                }
            }
        }
        acc
    }

    /// THE ROW-LEVEL DIAGNOSTIC behind a refused honest carrier: evaluate the CPU relation on every hypercube row of a
    /// laid table exactly as the zerocheck does (this row, the cyclic next row, the row's point HIGH-bit-first) and name
    /// the first row whose γ-batched residual is non-zero, with its opcode, micro kind and effect stage. A refusal
    /// without this is "a law fired somewhere"; with it, it is a line.
    fn first_unsatisfied_row(gate: &DsolCpuConstraint, table: &[Vec<Fa4>], steps: &[Step]) -> Option<(usize, String)> {
        let rows = table[0].len();
        let nv = rows.trailing_zeros() as usize;
        let oob = crate::air_zerocheck::OobLatch::new();
        for r in 0..rows {
            let vals: Vec<Ea4> = table.iter().map(|c| Ea4::from(c[r])).collect();
            let row = Row::new(&vals, &oob);
            let nxt = (r + 1) % rows;
            let at = |c: usize, _p: &[Ea4]| -> Ea4 { Ea4::from(table[c][nxt]) };
            let x: Vec<Ea4> = (0..nv).map(|k| if (r >> (nv - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
            let residual = gate.eval(&row, &at, &x);
            if residual != Ea4::ZERO {
                use p3_field::PrimeField64;
                // the block's own residual, apart from the laws': a non-zero block says the LAYOUT of the permutation
                // trace is wrong on this row; a zero block says a LAW is
                let block = gate.p2.eval(&row.suffix(C_P2), &|c: usize, p: &[Ea4]| at(c + C_P2, p), &x);
                // the LAWS that refused, by source line: arm the probe, fold the row once more, read it back
                probe_arm();
                let _ = gate.eval(&row, &at, &x);
                let recorded = probe_take();
                let lines: Vec<u32> = recorded.iter().map(|(l, _)| *l).collect();
                let dump = |rr: usize| -> String {
                    let v = |c: usize| table[c][rr].as_canonical_u64();
                    let fills: Vec<u64> = (0..SPONGES).map(|s| v(C_SPFILL + s)).collect();
                    let feeds: Vec<u64> = (0..SPONGES).map(|s| v(C_FEED + s)).collect();
                    let opens: Vec<u64> = (0..SPONGES).map(|s| v(C_OPEN + s)).collect();
                    let perm: Vec<u64> = (0..=SPONGES).map(|s| v(C_PERMSEL + s)).collect();
                    let micro: Vec<u64> = (0..NMICRO).map(|k| v(C_MICRO + k)).collect();
                    let stage: Vec<u64> = (0..dsol_vm::EFX_STAGES_MAX).map(|k| v(C_ESTAGE + k)).collect();
                    format!(
                        "row {rr}: pc {} op 0x{:02x} micro {micro:?} sp {} byte {} feeds {feeds:?} perm {perm:?} opens {opens:?} fills {fills:?} remain {} plen {} acc0 {} real {} stage {stage:?} slot0.tag {} slot0.len {}",
                        v(C_PC), v(C_OP), v(C_SP), v(C_BYTE), v(C_REMAIN), v(C_PLEN), v(C_S2ACC), v(C_REAL), v(stack_at(0, SLOT_TAG)), v(stack_at(0, SLOT_LEN))
                    )
                };
                let what = match steps.get(r) {
                    Some(s) => format!(
                        "op 0x{:02x} micro {} stage {} sp {}; block residual zero: {}; LAWS REFUSING (source lines) {lines:?}; {}; NEXT {}",
                        s.op, s.micro, s.estage, s.sp, block == Ea4::ZERO, dump(r), dump(nxt)
                    ),
                    None => format!("padding; block residual zero: {}; LAWS REFUSING (source lines) {lines:?}; {}", block == Ea4::ZERO, dump(r)),
                };
                return Some((r, what));
            }
        }
        None
    }

    /// ⛔⛔⛔ L9 EFFECTS, RED FIRST. The honest event + nullifier + private-store program proves and verifies under the
    /// whole relation, and `refold` over the honest table reproduces the statement's digest (the pin's own fold agrees
    /// with the machine's). Four forgeries, each keeping every Poseidon2 block honest, the carries consistent and the
    /// fetch bus balanced, each presented under the statement a cheating prover would claim: (F1) the NULLIFIER's tag
    /// derived from a secret other than the one sponge A re-absorbed; (F2) the EMIT's data digest swapped for another
    /// string's; (F3) the EMIT dropped from the fold (its blocks laid, its result never applied); (F4) the accumulator
    /// nudged on two plain rows and back (the statement unchanged). CALIBRATION: under a gate with no laws all four
    /// prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across PROOF BYTES; the verifier's gate is built from the public statement and
    /// the program, never from the prover's trace.
    #[test]
    fn l9_a_foreign_secret_a_swapped_operand_a_dropped_effect_and_a_nudged_fold_are_refused() {
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let code = effects_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        assert_eq!(t.run.ret, 1u64.to_le_bytes().to_vec(), "the program returns 1");
        assert_eq!(t.run.effects.len(), 3, "an event, a nullifier and a private slot were recorded");
        assert!(matches!(t.run.effects[0], dsol_vm::Effect::Event { .. }) && matches!(t.run.effects[1], dsol_vm::Effect::Nullifier { .. }) && matches!(t.run.effects[2], dsol_vm::Effect::PrivateSlot { .. }));
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let stmt = stmt_for(&code, b"", &t);
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        if let DsolCpuGate::Cpu(c) = g(0, Ea4::from_u64(0x1234_5678)) {
            if let Some((r, what)) = first_unsatisfied_row(&c, &honest, &t.steps) {
                panic!("⛔ the honest effects program violates the relation at row {r} ({what}) of {}", t.steps.len());
            }
        }
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("the honest effects program satisfies L9 with every other law");
        assert!(verify_ok(&p, &g, &buses), "the honest event + nullifier + private store verifies");
        let n_efx = t.steps.iter().filter(|s| s.micro == mk::EFX).count();
        eprintln!("[dsol-l9] honest: {} rows ({n_efx} EFX rows), {} B", t.steps.len(), p.len());
        // the pin's own fold over the honest table reproduces the statement
        let mut check = honest.clone();
        let refolded = refold(&mut check, &t.steps, stmt.cid, 0, &|_, _| None, None);
        assert_eq!(refolded, stmt.effects_digest, "PRECONDITION: refolding the honest table reproduces the statement's digest");
        assert_eq!(check, honest, "PRECONDITION: and rewrites nothing");

        let rows_of = |o: u8| -> Vec<usize> { t.steps.iter().enumerate().filter(|(_, s)| s.op == o && s.micro == mk::EFX).map(|(r, _)| r).collect() };
        let (emit, null, priv_) = (rows_of(op::EMIT), rows_of(op::NULLIFIER), rows_of(op::SSTORE_PRIV));
        assert_eq!((emit.len(), null.len(), priv_.len()), (4, 4, 2), "the schedules' row counts");
        let forged_stmt = |digest: crate::poseidon2_compress::Digest| DsolStatement { effects_digest: digest, ..stmt.clone() };

        // F1: the nullifier's secret is not the one sponge A holds
        let mut f1 = honest.clone();
        let other = dsol_vm::str_digest(b"another secret");
        let d1 = refold(&mut f1, &t.steps, stmt.cid, null[0], &|r, side| (r == null[0] && side == 1).then_some(other), None);
        assert_ne!(d1, stmt.effects_digest);
        // F2: the event's data is another string's digest
        let mut f2 = honest.clone();
        let other_data = dsol_vm::str_digest(b"other data");
        let d2 = refold(&mut f2, &t.steps, stmt.cid, emit[0], &|r, side| (r == emit[1] && side == 0).then_some(other_data), None);
        assert_ne!(d2, stmt.effects_digest);
        // F3: the event is dropped from the fold
        let mut f3 = honest.clone();
        let d3 = refold(&mut f3, &t.steps, stmt.cid, emit[0], &|_, _| None, Some(emit[3]));
        assert_ne!(d3, stmt.effects_digest);
        // F4: the accumulator nudged on two plain rows between the nullifier and the private store, and back
        let mut f4 = honest.clone();
        let (a, b) = (null[3] + 2, null[3] + 3); // the POP after the nullifier's FINISH, and the PUSH_BYTES that follows
        assert!(t.steps[a].micro != mk::EFX && t.steps[b].micro != mk::EFX && b < priv_[0], "two plain rows before the private store's effect");
        f4[C_EACC][a] += Fa4::ONE;
        f4[C_EACC][b] += Fa4::ONE;

        let forgeries: [(&str, Vec<Vec<Fa4>>, DsolStatement); 4] = [
            ("a nullifier derived from a foreign secret", f1, forged_stmt(d1)),
            ("an event whose data digest is another string's", f2, forged_stmt(d2)),
            ("an event dropped from the fold", f3, forged_stmt(d3)),
            ("the fold nudged on plain rows", f4, stmt.clone()),
        ];
        let mut armed = 0usize;
        for (name, fcpu, fstmt) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p, &buses) {
                    armed += 1;
                }
            }
            let gf = dsol_gate_for(fstmt.clone(), rom.clone());
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &gf, &buses, &BIND) {
                assert!(!verify_ok(&p, &gf, &buses), "⛔ L9 IS OPEN: {name} verified");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: every effects forgery must prove and verify WITHOUT the laws");
        eprintln!("[dsol-l9] 4 effects forgeries armed without L9, all refused with it");
    }

    /// ⛔⛔⛔ L8 STORAGE, RED FIRST. The honest write-then-read program proves and verifies under the whole relation.
    /// Four forgeries, each of which keeps every Poseidon2 block honest and the fetch bus balanced: (F1) the read returns
    /// 43 for a slot holding 42 — the LEAF block hashes the value the row claims, so the pre-image no longer folds to the
    /// root; (F2) the write's new root is not the folded post-image — every later row carries a different root; (F3) the
    /// read's path stops one level short — the countdown reads 0 at the exit; (F4) THE ABSENCE FORGERY: the read claims
    /// key `k` is absent and returns 0 by walking ANOTHER key's (honestly empty) path — every block honest, the fold
    /// reaching the real root, the countdown exact — refused only because the direction bits must rebuild THE KEY.
    /// CALIBRATION: under a gate with no laws all four prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across PROOF BYTES; the verifier's gate is built from the public statement and
    /// the program, never from the prover's trace.
    #[test]
    fn l8_a_forged_read_a_forged_root_a_short_path_and_another_keys_path_are_refused() {
        use crate::poseidon2_compress::compress;
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let code = storage_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        assert_eq!(t.run.ret, 1u64.to_le_bytes().to_vec(), "the program returns 1");
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("the honest storage program satisfies L8 with every other law");
        assert!(verify_ok(&p, &g, &buses), "the honest write-then-read verifies");
        let n_path = t.steps.iter().filter(|s| s.micro == mk::PATH).count();
        eprintln!("[dsol-l8] honest: {} rows ({n_path} PATH rows, {} of {cpu_rows}), {} B", t.steps.len(), t.steps.len(), p.len());

        // the row map of the read
        let depth = dsol_vm::STORAGE_DEPTH;
        let leaf = t.steps.iter().position(|s| s.op == op::SLOAD && s.micro == mk::LEAF).expect("the read's LEAF row");
        let paths: Vec<usize> = t.steps.iter().enumerate().filter(|(_, s)| s.op == op::SLOAD && s.micro == mk::PATH).map(|(r, _)| r).collect();
        assert_eq!(paths.len(), depth, "a read walks exactly the depth");
        assert_eq!(paths[0], leaf + 1, "the path follows the LEAF row");
        let fin = t.steps.iter().position(|s| s.op == op::SLOAD && s.micro == mk::FINISH).expect("the read's FINISH row");
        assert_eq!(fin, paths[depth - 1] + 1, "the FINISH follows the last PATH row");
        let pop = fin + 1;
        assert_eq!((t.steps[pop].op, t.steps[pop].stack[0]), (op::POP, dsol_vm::VmVal::Word(42)), "the POP consumes the 42 that was read");
        let wexit = t.steps.iter().rposition(|s| s.op == op::SSTORE && s.micro == mk::PATH).expect("the write's last PATH row");

        // F1: the read returns 43
        let mut f1 = honest.clone();
        for r in leaf..=fin {
            f1[C_PVAL + 1][r] = f(43);
        }
        f1[stack_at(0, SLOT_W0)][pop] = f(43);
        let leaf_state = crate::pow_pq_air::pair_state(&t.steps[leaf].path_key, &dsol_vm::leaf_value_lanes(&dsol_vm::VmVal::Word(43)));
        relay_block(&mut f1, leaf, leaf_state);
        // F2: the write's new root is not the folded post-image (lane 0 moved on every row after the write's exit)
        let mut f2 = honest.clone();
        for r in wexit + 1..cpu_rows {
            f2[C_SROOT][r] += Fa4::ONE;
        }
        // F3: the read's countdown starts at DEPTH−1, so it reads 0 at the exit
        let mut f3 = honest.clone();
        for &r in &paths {
            f3[C_REMAIN][r] -= Fa4::ONE;
        }
        // F4: absence claimed along ANOTHER key's path. The trie after the write holds exactly (k, 42); k2 is absent, so
        // the empty leaf folds along k2's siblings to the real root. Everything but the direction bits' meaning is honest.
        let k = t.steps[leaf].path_key;
        assert_eq!(k, dsol_vm::str_digest(b"k"), "the read's key is the literal's digest");
        let mut trie = dsol_vm::StorageTrie::default();
        trie.insert_checked(&k, dsol_vm::VmVal::Word(42)).expect("the write");
        assert_eq!(trie.root(), t.steps[leaf].storage_root, "the pin's trie is the trace's post-write state");
        let k2 = dsol_vm::str_digest(b"other");
        assert!(trie.get(&k2).is_none(), "k2 is absent");
        let sibs2 = trie.path(&k2);
        let mut f4 = honest.clone();
        for r in leaf..=fin {
            f4[C_PPRES][r] = Fa4::ZERO;
            for l in 0..1 + W_LIMBS {
                f4[C_PVAL + l][r] = Fa4::ZERO;
            }
        }
        relay_block(&mut f4, leaf, crate::pow_pq_air::pair_state(&k, &dsol_vm::leaf_value_lanes(&dsol_vm::VmVal::Word(0))));
        let mut node = [0u64; DIGEST_LANES];
        let mut kacc = [0u64; DIGEST_LANES];
        let mut klane = (depth - 1) % DIGEST_LANES;
        for (l, &r) in paths.iter().enumerate() {
            let bit_index = depth - 1 - l;
            let (sib, dir) = (sibs2[bit_index], dsol_vm::key_bit(&k2, bit_index));
            for d in 0..DIGEST_LANES {
                f4[C_PSIB + d][r] = f(sib[d]);
                f4[C_POLD + d][r] = f(node[d]);
                f4[C_PNEW + d][r] = f(node[d]);
                f4[C_KACC + d][r] = f(kacc[d]);
                f4[C_KLANE + d][r] = if d == klane { Fa4::ONE } else { Fa4::ZERO };
            }
            f4[C_PDIR][r] = if dir { Fa4::ONE } else { Fa4::ZERO };
            let (lft, rgt) = if dir { (sib, node) } else { (node, sib) };
            relay_block(&mut f4, r, crate::pow_pq_air::pair_state(&lft, &rgt));
            node = compress(&lft, &rgt);
            kacc[klane] = (kacc[klane] << 1) | u64::from(dir);
            klane = (klane + DIGEST_LANES - 1) % DIGEST_LANES;
        }
        assert_eq!(node, trie.root(), "PRECONDITION: k2's empty path folds to the real root");
        assert_eq!(kacc, k2, "PRECONDITION: the forged path's bits rebuild k2, not k");
        for l in 0..W_LIMBS {
            f4[stack_at(0, SLOT_W0 + l)][pop] = Fa4::ZERO;
        }

        let forgeries = [
            ("a read returning 43 for a slot holding 42", f1),
            ("a write whose new root is not the folded post-image", f2),
            ("a read one level short", f3),
            ("absence claimed along another key's path", f4),
        ];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p, &buses) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_ok(&p, &g, &buses), "⛔ L8 IS OPEN: {name} verified");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: every storage forgery must prove and verify WITHOUT the laws");
        eprintln!("[dsol-l8] 4 storage forgeries armed without L8, all refused with it");
    }

    /// ⛔⛔⛔ H5 — A COMMITTED ROM THAT IS NOT THE VERIFIER'S PROGRAM IS REFUSED, RED FIRST. Two programs, A and B,
    /// differing in one immediate. B's honest trace against B's committed ROM: (1) verifies under a ROM law built
    /// from B — the honest arm; (2) CALIBRATION: under a gate with NO ROM law it verifies for a verifier who holds A,
    /// because the fetch bus only ever asked whether the CPU matched the ROM, never whether the ROM was the program —
    /// this is the hole as it stood before 2026-09-29; (3) under the ROM law built from A it is REFUSED, whether the
    /// carrier was proven under that law or under none.
    ///
    /// TWO-PARTY-REVIEWED: the capability is prove → verify across PROOF BYTES with the verifier's law built from the
    /// program it holds, never from the carrier; `verify_dsol_call` is where the production verifier derives that
    /// program from the code whose blake3 the statement names.
    #[test]
    fn h5_a_committed_rom_that_is_not_the_verifiers_program_is_refused() {
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let code_a = program();
        let mut code_b = code_a.clone();
        code_b[24..32].copy_from_slice(&9u64.to_le_bytes()); // the second PUSH_U64's immediate: 6 → 9
        let prog_a = decode_program(&code_a).expect("A decodes");
        let prog_b = decode_program(&code_b).expect("B decodes");
        assert_eq!(prog_a.len(), prog_b.len(), "same instruction count");
        assert_eq!(prog_a.iter().zip(&prog_b).filter(|(x, y)| x != y).count(), 1, "the two programs differ in exactly one instruction");
        let t = run_it(&code_b);
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog_b.len().next_power_of_two().max(32);
        let cpu = build_cpu_trace(&t, &code_b, cpu_rows).expect("B lays out");
        let rom_b = build_rom_trace(&prog_b, rom_rows).expect("B's ROM lays out");
        let rom_a = build_rom_trace(&prog_a, rom_rows).expect("A's ROM lays out");
        assert_ne!(rom_a, rom_b, "the two ROM tables differ");
        let buses = vec![fetch_bus()];
        let stmt = stmt_for(&code_b, b"", &t);
        // (1) honest
        let g_b = dsol_gate_for(stmt.clone(), rom_b.clone());
        let p = prove_postcommit_bus_bytes(vec![cpu.clone(), rom_b.clone()], &g_b, &buses, &BIND)
            .expect("B's honest trace satisfies the relation and the ROM law built from B");
        assert!(verify_ok(&p, &g_b, &buses), "the honest arm verifies");
        // (2) CALIBRATION — no ROM law: the bus balances (B's CPU against B's ROM) and a verifier holding A accepts
        let p_free = prove_postcommit_bus_bytes(vec![cpu.clone(), rom_b.clone()], gates, &buses, &BIND).expect("proves without the law");
        assert!(verify_free(&p_free, &buses), "CALIBRATION: without the ROM law, a ROM that is program B verifies for a verifier who holds A");
        // (3) the ROM law built from A refuses B's ROM
        let g_a = dsol_gate_for(stmt.clone(), rom_a.clone());
        if let Some(p) = prove_postcommit_bus_bytes(vec![cpu.clone(), rom_b.clone()], &g_a, &buses, &BIND) {
            assert!(!verify_ok(&p, &g_a, &buses), "⛔ H5 IS OPEN: a committed ROM that is not the verifier's program verified");
        }
        assert!(!verify_ok(&p_free, &g_a, &buses), "⛔ H5 IS OPEN: a carrier proven under no ROM law verified under A's");
        eprintln!("[dsol-h5] honest {} B; a foreign ROM armed without the ROM law, refused with it", p.len());
    }

    /// ⛔ D7 — THE VERIFIER'S ROM IS STREAMED FROM THE CODE and it is the SAME law. (1) At points off the hypercube the
    /// streamed MLE equals the laid table's, for programs with a literal (H1), with padding, and at a larger table class
    /// than the program's own. (2) H5 through the production form: the prover's carrier for B verifies under B's STREAMED
    /// law and is refused under A's, whether proven under the law or under none.
    ///
    /// TWO-PARTY-REVIEWED: prove (the prover's laid ROM) → verify across PROOF BYTES under the verifier's law streamed from
    /// the code it holds — the two forms `verify_dsol_call` and `prove_trace` use.
    #[test]
    fn d7_the_streamed_rom_law_is_the_laid_one_and_refuses_a_foreign_program() {
        let mut lit = Vec::new();
        push_bytes(&mut lit, b"a literal the ROM digests");
        lit.extend_from_slice(&[op::POP, op::PUSH_U64, 7, 0, 0, 0, 0, 0, 0, 0, op::RETURN]);
        for code in [program(), program_of(&lit)] {
            let prog = decode_program(&code).expect("decodes");
            for extra in 0..2 {
                let nv = prog.len().next_power_of_two().max(32).trailing_zeros() as usize + extra;
                let rom = build_rom_trace(&prog, 1 << nv).expect("lays out");
                for seed in 0..3u64 {
                    let x: Vec<Ea4> = (0..nv as u64).map(|i| Ea4::from(f(seed * 1_000_003 + i * 7_919 + 11))).collect();
                    let eq = crate::air_zerocheck::eq_z_hypercube(&x);
                    let laid: Vec<Ea4> =
                        rom.iter().map(|col| col.iter().zip(&eq).fold(Ea4::ZERO, |s, (&v, &e)| s + e * Ea4::from(v))).collect();
                    let streamed = rom_mle_from_code(&code, &x).expect("streams");
                    assert_eq!(streamed.to_vec(), laid, "⛔ the streamed ROM is not the laid ROM (nv {nv}, seed {seed})");
                }
            }
            assert!(rom_mle_from_code(&code, &[Ea4::ONE; 1]).is_none(), "a table too small for the program is refused");
        }
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let code_a = program();
        let mut code_b = code_a.clone();
        code_b[24..32].copy_from_slice(&9u64.to_le_bytes()); // the second PUSH_U64's immediate: 6 → 9
        let prog_b = decode_program(&code_b).expect("B decodes");
        let t = run_it(&code_b);
        let cpu = build_cpu_trace(&t, &code_b, t.steps.len().next_power_of_two().max(32)).expect("B lays out");
        let rom_b = build_rom_trace(&prog_b, prog_b.len().next_power_of_two().max(32)).expect("B's ROM lays out");
        let buses = vec![fetch_bus()];
        let stmt = stmt_for(&code_b, b"", &t);
        let p = prove_postcommit_bus_bytes(vec![cpu.clone(), rom_b.clone()], &dsol_gate_for(stmt.clone(), rom_b.clone()), &buses, &BIND)
            .expect("B's honest trace proves under the laid law");
        let streamed_b = dsol_gate_for_code(stmt.clone(), std::sync::Arc::from(code_b.as_slice()));
        let streamed_a = dsol_gate_for_code(stmt.clone(), std::sync::Arc::from(code_a.as_slice()));
        assert!(verify_ok(&p, &streamed_b, &buses), "⛔ the prover's carrier does not verify under B's STREAMED law");
        assert!(!verify_ok(&p, &streamed_a, &buses), "⛔ H5 IS OPEN under the streamed law: B's ROM verified for a verifier holding A");
        let p_free = prove_postcommit_bus_bytes(vec![cpu, rom_b], gates, &buses, &BIND).expect("proves without the law");
        assert!(!verify_ok(&p_free, &streamed_a, &buses), "⛔ H5 IS OPEN under the streamed law: a law-free carrier verified");
    }

    /// ⛔ D7 — THE ROM'S CEILING, RED FIRST (on `.preD7RomBound-20260930` the walk had no bound and `verify_dsol_call`'s
    /// size check was vacuous): a program one instruction past `DSOL_ROM_ROWS_MAX` is refused by the walk and by
    /// `decode_program` — before anything is laid. At the ceiling the walk still counts. `verify_dsol_call` counts by
    /// this same walk (and the streamed law walks it again), so there is no second decoder to bound.
    #[test]
    fn d7_a_program_past_the_rom_ceiling_is_refused_before_anything_is_laid() {
        let at = program_of(&vec![op::POP; DSOL_ROM_ROWS_MAX]);
        assert_eq!(walk_program(&at, |_| {}), Some(DSOL_ROM_ROWS_MAX), "CALIBRATION: a program AT the ceiling walks");
        let over = program_of(&vec![op::POP; DSOL_ROM_ROWS_MAX + 1]);
        assert_eq!(walk_program(&over, |_| {}), None, "⛔ the walk counted past the ROM ceiling");
        assert!(decode_program(&over).is_none(), "⛔ decode_program laid a program past the ROM ceiling");
    }

    /// ⛔⛔⛔ H6 — THE CPU SIDE'S MULTIPLICITY IS A LAW, NOT A CHOICE, RED FIRST. The fetch bus counts the rows the
    /// `C_REAL` column says are real; before 2026-09-29 that count was a vector the prover handed the bus and nothing
    /// tied. Four forgeries, each of which BALANCES the bus (the ROM side is derived from whatever the CPU says it
    /// fetched): (F1) row 0 called padding; (F2) a real middle row called padding; (F3) the first padding row called
    /// real (it replicates the RETURN row, a real ROM key); (F4) THE ATTACK — a forged instruction on row 2 (a REVERT
    /// the program lacks) hidden by calling that row padding. CALIBRATION: under a gate without the real laws all
    /// four prove AND verify — the bus is doing exactly its job. Under the relation every one is refused.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across PROOF BYTES; the verifier's gate and bus spec come from the public
    /// statement and `fetch_bus()`, which takes no multiplicity from anyone.
    #[test]
    fn h6_a_real_row_called_padding_or_a_padding_row_called_real_is_refused() {
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let code = program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let steps = t.steps.len();
        assert!(steps + 1 < cpu_rows, "there is padding to promote: {steps} real rows of {cpu_rows}");
        assert!(!prog.iter().any(|&(_, o, _, _)| o == op::REVERT), "the program has no REVERT to hide behind");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("the honest program satisfies the real laws");
        assert!(verify_ok(&p, &g, &buses), "honest verifies");
        let mut f1 = honest.clone();
        f1[C_REAL][0] = Fa4::ZERO;
        let mut f2 = honest.clone();
        f2[C_REAL][2] = Fa4::ZERO;
        let mut f3 = honest.clone();
        f3[C_REAL][steps] = Fa4::ONE;
        let mut f4 = honest.clone();
        f4[C_REAL][2] = Fa4::ZERO;
        f4[C_FETCH][2] = Fa4::ZERO; // the bus's multiplicity (continuations moved it off `real`: boundary rows fetch nothing)
        f4[C_OP][2] = f(u64::from(op::REVERT));
        let forgeries = [
            ("row 0 called padding", f1),
            ("a real row called padding", f2),
            ("a padding row called real", f3),
            ("a forged instruction hidden as padding", f4),
        ];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            // CALIBRATION — the bus balances and, without the real laws, verifies.
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p, &buses) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_ok(&p, &g, &buses), "⛔ H6 IS OPEN: {name} verified under the real laws");
            }
        }
        assert_eq!(
            armed,
            forgeries.len(),
            "CALIBRATION: every forgery must balance the bus and verify WITHOUT the real laws — the bus counts what the \
             column says, so the law on the column is what refuses"
        );
        eprintln!("[dsol-h6] honest {} B ({steps} rows); 4 multiplicity forgeries armed without the real laws, all refused with them", p.len());
    }

    /// ⭐ L1 SELECTORS, RED FIRST. An honest execution satisfies the CPU row relation under the real gate, and three
    /// forgeries of row 0 are REFUSED: two opcode selectors set (a blended transition rule), the selector moved to an
    /// opcode other than the one in `C_OP` (the laws would key on an opcode the fetch bus never checked), and two
    /// micro-step selectors set. CALIBRATION: under `FetchOnlyGate` — the gate the L2 pin deliberately uses — every one
    /// of these forgeries proves and verifies, because that gate constrains nothing; the same three forgeries are run
    /// there first so the pin shows the attack ARMED before showing it refused.
    #[test]
    fn l1_a_blended_or_disagreeing_selector_row_is_refused() {
        let code = program();
        let prog = decode_program(&code).expect("the program decodes");
        let t = run_it(&code);
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("the execution lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("the program lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let honest_i = op_index(t.steps[0].op).expect("row 0's opcode has a selector");
        let other_i = (honest_i + 1) % NOPS;
        let other_k = (t.steps[0].micro as usize + 1) % NMICRO;
        let mut two_ops = honest.clone();
        two_ops[C_OPSEL + other_i][0] = Fa4::ONE;
        let mut moved = honest.clone();
        moved[C_OPSEL + honest_i][0] = Fa4::ZERO;
        moved[C_OPSEL + other_i][0] = Fa4::ONE;
        let mut two_micro = honest.clone();
        two_micro[C_MICRO + other_k][0] = Fa4::ONE;
        let forgeries = [("two opcode selectors", two_ops), ("selector disagrees with C_OP", moved), ("two micro selectors", two_micro)];

        // CALIBRATION — the attack is armed under a gate that constrains nothing.
        let mut armed = 0usize;
        for (_, f) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![f.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_postcommit_bus_bytes(&p, gates, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1) {
                    armed += 1;
                }
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without L1 every selector forgery verifies");

        // THE LAW — honest verifies, every forgery is refused.
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("an honest execution satisfies L1");
        assert!(
            verify_postcommit_bus_bytes(&p, &g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
            "an honest execution verifies under L1"
        );
        for (name, f) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![f.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(
                    !verify_postcommit_bus_bytes(&p, &g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                    "⛔ L1 FORGERY VERIFIED: {name}"
                );
            }
        }
        eprintln!("[dsol-l1] honest {} B; {} selector forgeries armed without L1, all refused with it", p.len(), armed);
    }

    /// A branching program with a multi-row opcode: `PUSH_U64 cond; JUMPI 45; PUSH_U64 1; PUSH_U64 2; [45:] PUSH_BYTES
    /// "ab"; PUSH_BYTES "cd"; CONCAT; RETURN`. `cond = 0` runs every instruction; `cond = 1` skips the two pushes.
    /// CONCAT re-supplies both strings byte by byte (FEED rows), permutes, and finishes — the multi-row shape the
    /// continuation law is about.
    fn branch_program(cond: u64) -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::PUSH_U64); // 13
        out.extend_from_slice(&cond.to_le_bytes());
        out.push(op::JUMPI); // 22
        out.extend_from_slice(&45u32.to_le_bytes());
        out.push(op::PUSH_U64); // 27
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::PUSH_U64); // 36
        out.extend_from_slice(&2u64.to_le_bytes());
        out.push(op::PUSH_BYTES); // 45
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(b"ab");
        out.push(op::PUSH_BYTES); // 50
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(b"cd");
        out.push(op::CONCAT); // 55
        out.push(op::RETURN); // 56
        assert_eq!(out.len(), 57, "the branch program's layout is what its jump target assumes");
        out
    }

    // `rebalanced_multiplicities` DELETED 2026-09-29 (H6): the bus prover derives the ROM side's counts from the CPU's
    // committed keys, so a forgery that renames a row to another REAL instruction rebalances by construction.

    /// ⭐ L5 CONTROL, RED FIRST. Both branches of the program prove and verify under the CPU relation. Three forgeries
    /// that L1 and the fetch bus CANNOT see are refused only by L5: (F1) a FEED row of CONCAT renamed to the RETURN
    /// instruction (a real instruction, bus rebalanced) — the continuation / advance law; (F2) the not-taken JUMPI's
    /// decision flipped to taken with a forged inverse — the witnessed non-zero test; (F3) the rows of `PUSH_U64 1`
    /// and `PUSH_U64 2` swapped whole (same multiset, so the bus balances) — the pc advance. CALIBRATION: under the
    /// constraint-free `FetchOnlyGate` all three prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: the capability is prove → verify across PROOF BYTES; the verifier builds its own gate from
    /// the public statement and reads only the bytes plus `declared_postcommit_shapes_for_tests` (never the prover's
    /// trace), which is the exact boundary a node stands on against a wallet's call. The second endpoint proper —
    /// `verify_dsol_call` on two real nodes — is phase 1's completion bar and lands with the last law, not with this one.
    #[test]
    fn l5_a_skipped_or_reordered_instruction_and_a_forged_branch_are_refused() {
        let verify_ok = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, g, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        // Both branches, honest.
        for cond in [0u64, 1] {
            let code = branch_program(cond);
            let prog = decode_program(&code).expect("decodes");
            let t = run_it(&code);
            let cpu_rows = t.steps.len().next_power_of_two().max(32);
            let rom_rows = prog.len().next_power_of_two().max(32);
            let cpu = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
            let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
            let buses = vec![fetch_bus()];
            let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
            let p = prove_postcommit_bus_bytes(vec![cpu, rom], &g, &buses, &BIND)
                .unwrap_or_else(|| panic!("the honest cond={cond} branch satisfies L1+L5 ({} rows)", t.steps.len()));
            assert!(verify_ok(&p, &g, &buses), "the honest cond={cond} branch verifies");
            eprintln!("[dsol-l5] cond={cond}: {} steps, proof {} B", t.steps.len(), p.len());
        }
        // The not-taken trace is the forgery base.
        let code = branch_program(0);
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        assert_eq!(t.steps[1].op, op::JUMPI, "row 1 is the JUMPI");
        assert_eq!((t.steps[2].pc, t.steps[3].pc), (27, 36), "rows 2 and 3 are the two straight pushes");
        let feed = t.steps.iter().position(|s| s.micro == mk::FEED).expect("CONCAT lays FEED rows");
        // F1: a FEED row renamed to the RETURN instruction (pc 56), selectors kept consistent so L1 holds.
        let mut f1 = honest.clone();
        f1[C_PC][feed] = f(56);
        f1[C_OP][feed] = f(u64::from(op::RETURN));
        for l in 0..C_IMM_LIMBS {
            f1[C_IMM + l][feed] = Fa4::ZERO;
        }
        for i in 0..NOPS {
            f1[C_OPSEL + i][feed] = Fa4::ZERO;
        }
        f1[C_OPSEL + op_index(op::RETURN).unwrap()][feed] = Fa4::ONE;
        // F2: the branch decision flipped to taken on a zero condition, inverse forged to 1.
        let mut f2 = honest.clone();
        f2[C_TAKEN][1] = Fa4::ONE;
        f2[C_TAKEN_INV][1] = Fa4::ONE;
        // F3: rows 2 and 3 swapped whole.
        let mut f3 = honest.clone();
        for c in 0..CPU_COLS {
            f3[c].swap(2, 3);
        }
        let forgeries = [("FEED row renamed to RETURN", f1), ("JUMPI taken on a zero condition", f2), ("straight rows swapped", f3)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            let buses = vec![fetch_bus()];
            // CALIBRATION — armed under a gate that constrains nothing (the bus balances by construction).
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p, &buses) {
                    armed += 1;
                }
            }
            // THE LAW — refused.
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_ok(&p, &g, &buses), "⛔ L5 FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every control forgery verifies");
        eprintln!("[dsol-l5] {} control forgeries armed without L5, all refused with it", armed);
    }

    /// `POP; PUSH_U64 7; PUSH_U64 6; ADD; PUSH_U64 5; SUB; RETURN` → 8. Rows: 0 POP, 1 PUSH, 2 PUSH, 3 ADD, 4 PUSH,
    /// 5 SUB, 6 RETURN.
    fn alu_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&7u64.to_le_bytes());
        out.push(op::PUSH_U64);
        out.extend_from_slice(&6u64.to_le_bytes());
        out.push(op::ADD_U64);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&5u64.to_le_bytes());
        out.push(op::SUB_U64);
        out.push(op::RETURN);
        out
    }

    /// ⭐ L4a ALU ADD/SUB, RED FIRST. The honest program verifies; four forgeries invisible to L1, L5 and the fetch
    /// bus are refused: (F1) the ADD result limb 0 raised by one with its bits and the next row's slot moved along
    /// (the carry chain); (F2) the ADD row's first carry flipped (a bit that lies); (F3) one result bit flipped
    /// (the recomposition / range proof); (F4) the SUB row's top operand re-tagged as a STRING (the WORD law).
    /// CALIBRATION: under the constraint-free `FetchOnlyGate` all four prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES, verifier-side gate rebuilt from the statement (see the
    /// L5 pin); the two-node `verify_dsol_call` endpoint is phase 1's completion bar.
    #[test]
    fn l4a_a_wrong_sum_carry_bit_or_string_operand_is_refused() {
        let code = alu_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        assert!(t.steps.len() >= 7, "seven single-row steps, then the word RETURN produces its bytes: {}", t.steps.len());
        assert_eq!((t.steps[3].op, t.steps[5].op), (op::ADD_U64, op::SUB_U64), "rows 3 and 5 are ADD and SUB");
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("the honest ADD/SUB program satisfies L1+L4a+L5");
        assert!(verify_with(&p, &g), "the honest ADD/SUB program verifies");
        // F1: result limb 0 of the ADD row is 14 instead of 13, bits and the landing slot moved along.
        let mut f1 = honest.clone();
        f1[C_ALU_R][3] = f(14);
        for j in 0..W_BITS {
            f1[C_ALU_BITS + j][3] = f((14u64 >> j) & 1);
        }
        f1[stack_at(0, SLOT_W0)][4] = f(14);
        // F2: the first carry of the ADD row flipped.
        let mut f2 = honest.clone();
        f2[C_ALU_CARRY][3] = Fa4::ONE - f2[C_ALU_CARRY][3];
        // F3: one result bit flipped (bit 5 of limb 0: 13 = 0b1101 has it clear).
        let mut f3 = honest.clone();
        f3[C_ALU_BITS + 5][3] = Fa4::ONE;
        // F4: the SUB row's top operand re-tagged as a string.
        let mut f4 = honest.clone();
        f4[stack_at(0, SLOT_TAG)][5] = Fa4::ONE;
        let forgeries = [("ADD sum off by one", f1), ("ADD carry flipped", f2), ("result bit flipped", f3), ("SUB operand tagged as a string", f4)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_with(&p, &g), "⛔ L4a FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every ALU forgery verifies");
        eprintln!("[dsol-l4a] honest {} B; {} ALU forgeries armed without L4a, all refused with it", p.len(), armed);
    }

    /// `POP; PUSH 7; PUSH 6; MUL; PUSH 100; PUSH 7; DIV; PUSH 100; PUSH 7; MOD; PUSH u64::MAX; PUSH 2; MUL; RETURN` —
    /// 42, 14, 2 and the wrapping 2^64 − 2, then the word RETURN.
    fn muldiv_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        for (a, b, o) in [(7u64, 6u64, op::MUL_U64), (100, 7, op::DIV_U64), (100, 7, op::MOD_U64), (u64::MAX, 2, op::MUL_U64)] {
            out.push(op::PUSH_U64);
            out.extend_from_slice(&a.to_le_bytes());
            out.push(op::PUSH_U64);
            out.extend_from_slice(&b.to_le_bytes());
            out.push(o);
        }
        out.push(op::RETURN);
        out
    }

    /// ⭐ L4c / L4d ALU MUL / DIV / MOD, RED FIRST. The honest program (7·6 = 42; 100 / 7 = 14; 100 % 7 = 2; MAX·2
    /// wraps to 2^64 − 2) verifies; four forgeries invisible to L1, L3, L5 and the fetch bus are refused: (F1) the MUL
    /// result raised by one with its landing (the product's low limbs pin R); (F2) the DIV quotient raised by one with
    /// its bits, block and landing redone (15·7 + 2 ≠ 100 — the add chain); (F3) the MOD remainder 9 with the quotient 13
    /// (13·7 + 9 = 100 holds, REM < B does not — the borrow chain's final borrow, laid limb-honestly so only that law
    /// refuses); (F4) one of B's range bits flipped on the MUL row (B's bits are B's). CALIBRATION: under the
    /// constraint-free gate all four prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES, the verifier's gate rebuilt from the statement.
    #[test]
    fn l4cd_a_wrong_product_quotient_remainder_or_operand_bit_is_refused() {
        use crate::confidential_solvency::{hh_cbits, hh_cols, hh_cout, hh_native, hh_obits, mulhh_p16_off, HH_BITS, HH_CARRY_BITS};
        let code = muldiv_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let row_of = |o: u8, nth: usize| t.steps.iter().enumerate().filter(|(_, s)| s.op == o).nth(nth).map(|(i, _)| i).expect("the opcode runs");
        let (mul_row, div_row, mod_row, wrap_row) = (row_of(op::MUL_U64, 0), row_of(op::DIV_U64, 0), row_of(op::MOD_U64, 0), row_of(op::MUL_U64, 1));
        assert_eq!(t.steps[mul_row + 1].stack[0].as_word(), Some(42));
        assert_eq!(t.steps[div_row + 1].stack[0].as_word(), Some(14));
        assert_eq!(t.steps[mod_row + 1].stack[0].as_word(), Some(2));
        assert_eq!(t.steps[wrap_row + 1].stack[0].as_word(), Some(u64::MAX.wrapping_mul(2)), "MUL wraps");
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND).expect("the honest MUL/DIV/MOD program satisfies the CPU relation");
        assert!(verify_with(&p, &g), "the honest MUL/DIV/MOD program verifies");
        // forging one row of a column-major table: operand bits, the X·B block, the result and its landing
        let limbs = |v: u64| -> [u64; W_LIMBS] { core::array::from_fn(|l| (v >> (W_BITS * l)) & ((1 << W_BITS) - 1)) };
        let lay_bits = |cols: &mut Vec<Vec<Fa4>>, base: usize, row: usize, v: u64| {
            let vl = limbs(v);
            for l in 0..W_LIMBS {
                for j in 0..W_BITS {
                    cols[base + l * W_BITS + j][row] = f((vl[l] >> j) & 1);
                }
            }
        };
        let lay_block = |cols: &mut Vec<Vec<Fa4>>, row: usize, x: u64, b: u64| {
            let (out, cout, p16) = hh_native(&limbs(x), &limbs(b));
            for m in 0..hh_cols(W_LIMBS) {
                cols[C_MD_BLK + m][row] = f(out[m]);
                cols[C_MD_BLK + hh_cout(W_LIMBS) + m][row] = f(cout[m]);
                for t in 0..HH_BITS {
                    cols[C_MD_BLK + hh_obits(W_LIMBS) + m * HH_BITS + t][row] = f((out[m] >> t) & 1);
                }
                for t in 0..HH_CARRY_BITS {
                    cols[C_MD_BLK + hh_cbits(W_LIMBS) + m * HH_CARRY_BITS + t][row] = f((cout[m] >> t) & 1);
                }
            }
            for (q, &v) in p16.iter().enumerate() {
                cols[C_MD_BLK + mulhh_p16_off(W_LIMBS) + q][row] = f(v);
            }
        };
        let lay_result = |cols: &mut Vec<Vec<Fa4>>, row: usize, r: u64| {
            let rl = limbs(r);
            for l in 0..W_LIMBS {
                cols[C_ALU_R + l][row] = f(rl[l]);
                cols[stack_at(0, SLOT_W0 + l)][row + 1] = f(rl[l]);
            }
        };
        // F1: the MUL result 43 with its landing; the block still says 42.
        let mut f1 = honest.clone();
        lay_result(&mut f1, mul_row, 43);
        // F2: the DIV quotient 15 — bits, block and landing redone; 15·7 + 2 = 107 ≠ 100.
        let mut f2 = honest.clone();
        lay_result(&mut f2, div_row, 15);
        lay_bits(&mut f2, C_MD_XBITS, div_row, 15);
        lay_block(&mut f2, div_row, 15, 7);
        // F3: the MOD remainder 9 with the quotient 13 — 13·7 + 9 = 100 holds; REM < B does not. The borrow chain is
        // laid limb-honestly (a borrow through every limb), so only the FINAL borrow refuses.
        let mut f3 = honest.clone();
        lay_result(&mut f3, mod_row, 9);
        lay_bits(&mut f3, C_MD_REMBITS, mod_row, 9);
        lay_bits(&mut f3, C_MD_XBITS, mod_row, 13);
        lay_block(&mut f3, mod_row, 13, 7);
        let (bl, reml) = (limbs(7), limbs(9));
        let mut bin = 0i64;
        for l in 0..W_LIMBS {
            let d = bl[l] as i64 - reml[l] as i64 - i64::from(l == 0) - bin;
            let (sl, bo) = if d < 0 { ((d + (1i64 << W_BITS)) as u64, 1i64) } else { (d as u64, 0i64) };
            bin = bo;
            f3[C_MD_SLACK + l][mod_row] = f(sl);
            f3[C_MD_BORROW + l][mod_row] = f(bo as u64);
            for j in 0..W_BITS {
                f3[C_MD_SBITS + l * W_BITS + j][mod_row] = f((sl >> j) & 1);
            }
        }
        assert_eq!(bin, 1, "the forged remainder borrows out of the top limb");
        // F4: bit 0 of B's range bits flipped on the MUL row (6 = 0b110 has it clear).
        let mut f4 = honest.clone();
        f4[C_MD_BBITS][mul_row] = Fa4::ONE;
        let forgeries = [("MUL result off by one", f1), ("DIV quotient off by one", f2), ("MOD remainder ≥ B", f3), ("B range bit flipped", f4)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_with(&p, &g), "⛔ L4c/d FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every multiply / divide forgery verifies");
        eprintln!("[dsol-l4cd] honest {} B over {CPU_COLS} columns; {} forgeries armed without L4c/d, all refused with it", p.len(), armed);
    }

    /// `POP; PUSH_BYTES "owner"; POP; PUSH_U64 1; RETURN` — a literal pushed and dropped: nothing but H1 binds it.
    fn literal_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        out.push(op::PUSH_BYTES);
        out.extend_from_slice(&5u16.to_le_bytes());
        out.extend_from_slice(b"owner");
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// ⭐⭐⭐ H1 — A PUSH_BYTES LITERAL IS THE PROGRAM'S, RED FIRST. Found 2026-09-29: the ROM row carried `(pc, op, len)`
    /// only, so the string a `PUSH_BYTES` landed was a free witness — a contract's constant storage key or event topic
    /// could be swapped for any string the prover liked, invisibly to every other law. Now the ROM row (the verifier's
    /// own digest of the literal at that pc) and the fetch-bus key carry the digest, and the landing law pins the slot to
    /// it. Refused: (F1) the landed slot's digest swapped for `"other"`'s with `C_LIT` honest (the landing law); (F2)
    /// `C_LIT` and the slot both swapped (the bus: no ROM row holds that key, so the prover cannot even balance it).
    /// CALIBRATION: under the constraint-free gate and a bus keyed the OLD way (no literal lanes) both forgeries prove
    /// and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES, the verifier's ROM and gate rebuilt from the code.
    #[test]
    fn h1_a_swapped_literal_digest_is_refused() {
        let code = literal_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let pb = t.steps.iter().position(|s| s.op == op::PUSH_BYTES).expect("the literal is pushed");
        let owner = dsol_vm::str_digest(b"owner");
        assert_eq!(prog[1].3, owner, "the ROM carries the literal's digest");
        match t.steps[pb + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, len } => assert_eq!((digest, len), (owner, 5), "the machine landed the literal"),
            _ => panic!("the literal lands as a string"),
        }
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8], buses: &[crate::postcommit_bus::BusSpec]| {
            verify_postcommit_bus_bytes(p, gates, buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND).expect("the honest literal program satisfies the CPU relation");
        assert!(verify_with(&p, &g), "the honest literal program verifies");
        let other = dsol_vm::str_digest(b"other");
        // F1: the landed slot's digest swapped, C_LIT honest.
        let mut f1 = honest.clone();
        for d in 0..DIGEST_LANES {
            f1[stack_at(0, SLOT_D0 + d)][pb + 1] = f(other[d]);
        }
        // F2: C_LIT and the landed slot both swapped.
        let mut f2 = f1.clone();
        for d in 0..DIGEST_LANES {
            f2[C_LIT + d][pb] = f(other[d]);
        }
        // the OLD key — no literal lanes — for the calibration
        let old_bus = {
            use crate::postcommit_bus::{BusMult, BusSide, BusSpec};
            vec![BusSpec {
                sides: vec![
                    BusSide { table: 0, cols: (0..C_IMM_LIMBS).fold(vec![C_PC, C_OP], |mut v, l| { v.push(C_IMM + l); v }), mult: BusMult::Column(C_REAL) },
                    BusSide { table: 1, cols: (0..C_IMM_LIMBS).fold(vec![ROM_PC, ROM_OP], |mut v, l| { v.push(ROM_IMM + l); v }), mult: BusMult::Free },
                ],
            }]
        };
        let mut armed = 0usize;
        for (name, fcpu) in [("slot digest swapped", f1), ("C_LIT and slot swapped", f2)].iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &old_bus, &BIND) {
                if verify_free(&p, &old_bus) {
                    armed += 1;
                }
            }
            match prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                None => eprintln!("[dsol-h1] {name}: the prover refuses (no ROM row holds the key)"),
                Some(p) => assert!(!verify_with(&p, &g), "⛔ H1 FORGERY VERIFIED: {name}"),
            }
        }
        assert_eq!(armed, 2, "CALIBRATION: with the old key and no landing law both literal forgeries verify");
        eprintln!("[dsol-h1] honest {} B; 2 literal forgeries armed the old way, both refused now", p.len());
    }

    /// `POP; MSG_SENDER; POP; MSG_SUBADDRESS; POP; CONTRACT_ID; POP; TX_HASH; POP; BLOCK_NUMBER; POP; PUSH_U64 1; RETURN`
    /// — every call-context value pushed and dropped: nothing but H4 binds them.
    fn context_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        for o in [op::MSG_SENDER, op::MSG_SUBADDRESS, op::CONTRACT_ID, op::TX_HASH, op::BLOCK_NUMBER] {
            out.push(o);
            out.push(op::POP);
        }
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// ⭐⭐⭐ H4 — THE CALL CONTEXT IS THE STATEMENT'S, RED FIRST. Found 2026-09-29: `MSG_SENDER / MSG_SUBADDRESS /
    /// CONTRACT_ID / TX_HASH` pushed `remember(ctx bytes)` on a PLAIN row and `BLOCK_NUMBER` a word, with no landing law —
    /// every one landed a free slot, so a contract's `msg.sender` gate was the prover's to pass. Now the statement carries
    /// the whole context and each landing pins its slot. Refused: (F1) the landed `MSG_SENDER` digest swapped for another
    /// caller's; (F2) `BLOCK_NUMBER` landing 78 for 77; (F3) the honest proof verified under a statement naming another
    /// caller (the transcript). CALIBRATION: under the constraint-free gate F1 and F2 prove and verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES, the verifier's gate rebuilt from the statement it was handed.
    #[test]
    fn h4_a_swapped_caller_or_block_number_is_refused() {
        let code = context_program();
        let prog = decode_program(&code).expect("decodes");
        let ctx = dsol_vm::VmCtx { contract_id: [0xC1; 32], block_number: 77, tx_hash: [0x7A; 32], caller_wallet: [0xCA; 32], caller_subaddress: [0x5B; 32] };
        let t = dsol_vm::run(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost).expect("the program runs");
        let stmt = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t).expect("the statement derives");
        assert_eq!((stmt.caller, stmt.block_number), (dsol_vm::str_digest(&[0xCA; 32]), 77));
        let row_of = |o: u8| t.steps.iter().position(|s| s.op == o).expect("the opcode runs");
        let (sender_row, bn_row) = (row_of(op::MSG_SENDER), row_of(op::BLOCK_NUMBER));
        match t.steps[sender_row + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, len } => assert_eq!((digest, len), (stmt.caller, 32), "the machine landed the caller"),
            _ => panic!("the caller lands as a string"),
        }
        assert_eq!(t.steps[bn_row + 1].stack[0].as_word(), Some(77), "the machine landed the block number");
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &stmt.bind()).expect("the honest context program satisfies the CPU relation");
        assert!(verify_with(&p, &g), "the honest context program verifies");
        // F3: the same bytes under a statement naming another caller
        let other = dsol_vm::str_digest(&[0xCB; 32]);
        let stmt2 = DsolStatement { caller: other, ..stmt.clone() };
        let g2 = dsol_gate_for(stmt2.clone(), rom.clone());
        assert!(!verify_postcommit_bus_bytes(&p, &g2, &buses, &stmt2.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1), "another caller in the statement refuses");
        // F1: the landed caller digest swapped
        let mut f1 = honest.clone();
        for d in 0..DIGEST_LANES {
            f1[stack_at(0, SLOT_D0 + d)][sender_row + 1] = f(other[d]);
        }
        // F2: the landed block number 78
        let mut f2 = honest.clone();
        f2[stack_at(0, SLOT_W0)][bn_row + 1] = f(78);
        let mut armed = 0usize;
        for (name, fcpu) in [("caller digest swapped", f1), ("block number off by one", f2)].iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &stmt.bind()) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &stmt.bind()) {
                assert!(!verify_with(&p, &g), "⛔ H4 FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, 2, "CALIBRATION: without the CPU relation both context forgeries verify");
        eprintln!("[dsol-h4] honest {} B; 2 context forgeries armed without H4, both refused with it; another caller in the statement refused", p.len());
    }

    /// ⭐ DSOL §6b A1/A2 — THE CALLER AND TX-HASH DERIVATIONS ARE ONE SPELLING, AND THEY ARE WHAT THE STATEMENT BINDS.
    /// A call run under `caller_wallet = dsol_caller_wallet(pk_c)` and `tx_hash = dsol_tx_hash(fee_nf)` yields a statement
    /// whose `caller` is `dsol_caller_digest(pk_c)` and whose `tx_hash` is `str_digest(dsol_tx_hash(fee_nf))` — the two
    /// values the node's door recomputes. REFUSALS (each a value a door compares and must find different): another key
    /// (one byte moved), another fee nullifier, a key of the wrong length (no caller at all), and the undomained
    /// `blake3(fee_nf)`.
    /// TWO-PARTY-REVIEWED: the wallet (prover side, `statement_of` over its run) and the door (the same public derivations
    /// over the carried `pk_c` and fee spend) are the two parties; the door itself lands with the DSOL node door.
    #[test]
    fn a1_a2_the_caller_and_tx_hash_derivations_are_one_spelling_and_land_in_the_statement() {
        let pk: Vec<u8> = (0..dsol_vm::DSOL_CALLER_PK_BYTES).map(|i| (i * 7 + 3) as u8).collect();
        let mut pk2 = pk.clone();
        pk2[dsol_vm::DSOL_CALLER_PK_BYTES - 1] ^= 1;
        let fee_nf = [0x11u8; 32];
        let caller = dsol_vm::dsol_caller_wallet(&pk).expect("an ML-DSA-65-sized key names a caller");
        assert_eq!(dsol_vm::dsol_caller_wallet(&pk), Some(caller), "one key, one caller");
        assert_ne!(dsol_vm::dsol_caller_wallet(&pk2), Some(caller), "⛔ a key with one byte moved named the same caller");
        assert!(dsol_vm::dsol_caller_wallet(&pk[..pk.len() - 1]).is_none(), "⛔ a short key named a caller");
        assert!(dsol_vm::dsol_caller_wallet(&[pk.clone(), vec![0]].concat()).is_none(), "⛔ a long key named a caller");
        let tx_hash = dsol_vm::dsol_tx_hash(&fee_nf);
        assert_ne!(dsol_vm::dsol_tx_hash(&[0x12; 32]), tx_hash, "⛔ another fee nullifier gave the same tx hash");
        assert_ne!(tx_hash, *blake3::hash(&fee_nf).as_bytes(), "the tx hash is domain-separated from a bare hash");
        // the statement the wallet proves under those two values
        let code = context_program();
        let sub = dsol_vm::dsol_caller_subaddress(&pk).expect("an ML-DSA-65-sized key names a subaddress");
        assert_ne!(sub, caller, "the subaddress is domain-separated from the caller identity");
        assert!(dsol_vm::dsol_caller_subaddress(&pk[..pk.len() - 1]).is_none(), "⛔ a short key named a subaddress");
        let ctx = dsol_vm::VmCtx { contract_id: [0xC1; 32], block_number: 64, tx_hash, caller_wallet: caller, caller_subaddress: sub };
        let t = dsol_vm::run(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost).expect("the program runs");
        let stmt = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t).expect("the statement derives");
        assert_eq!(Some(stmt.caller), dsol_vm::dsol_caller_digest(&pk), "the statement binds the door's caller digest");
        assert_eq!(Some(stmt.subaddress), dsol_vm::dsol_caller_subaddress_digest(&pk), "the statement binds the door's subaddress digest");
        assert_ne!(Some(stmt.subaddress), dsol_vm::dsol_caller_subaddress_digest(&pk2), "⛔ another key's subaddress matched");
        assert_ne!(Some(stmt.caller), dsol_vm::dsol_caller_digest(&pk2), "⛔ a door comparing another key's digest would accept");
        assert_eq!(stmt.tx_hash, dsol_vm::str_digest(&tx_hash), "the statement binds the door's tx hash");
        assert_ne!(stmt.tx_hash, dsol_vm::str_digest(&dsol_vm::dsol_tx_hash(&[0x12; 32])), "⛔ another fee spend's tx hash matched");
    }

    /// A host that answers every syscall with the argv reversed — enough to make a SYSCALL row real.
    struct EchoHost;
    impl dsol_vm::SyscallHost for EchoHost {
        fn call(&mut self, _sys_op: u16, argv: &[u8]) -> Option<Vec<u8>> {
            Some(argv.iter().rev().copied().collect())
        }
    }
    /// `POP; PUSH_BYTES "ping"; SYSCALL 7; POP; PUSH_U64 1; RETURN` — the host answers "gnip".
    fn syscall_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        out.push(op::PUSH_BYTES);
        out.extend_from_slice(&4u16.to_le_bytes());
        out.extend_from_slice(b"ping");
        out.push(op::SYSCALL);
        out.extend_from_slice(&7u16.to_le_bytes());
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// ⭐⭐⭐ L9b — A SYSCALL'S RESULT IS PRODUCED THROUGH SPONGE C, RED FIRST. Until now a SYSCALL row was REFUSED by law:
    /// the host's answer was cached off-circuit and the effect leaf's `ret` had no source. Now the machine produces the
    /// answer through sponge C (FEED / PERM rows the circuit checks), the effect's `ret` stage reads sponge C's digest and
    /// the produced length, and the FINISH lands `Str(sponge C, plen)`. The honest program PROVES and VERIFIES (the L9b
    /// claim); refused: (F1) the `ret` stage's left input lanes swapped for another digest (the source law, and the block
    /// behind it); (F2) the landed result slot's digest swapped (the FINISH content law); (F3) the proof under a statement
    /// with another effects digest (the transcript). CALIBRATION: F1 and F2 verify under the constraint-free gate. The node
    /// re-runs the syscall at apply and compares `ret`: the circuit proves ISSUED, the node AUTHORISES (dsol_vm's safety
    /// argument, unchanged).
    #[test]
    fn l9b_a_syscall_result_is_produced_through_sponge_c() {
        let code = syscall_program();
        let prog = decode_program(&code).expect("decodes");
        let t = dsol_vm::run(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut EchoHost).expect("the syscall program runs");
        let stmt = stmt_for(&code, b"", &t);
        let sys = t.steps.iter().position(|s| s.op == op::SYSCALL).expect("the syscall runs");
        let fin = t.steps.iter().rposition(|s| s.op == op::SYSCALL).expect("its FINISH row");
        assert_eq!(t.steps[fin].micro, mk::FINISH, "the syscall's last row is its FINISH");
        let gnip = dsol_vm::str_digest(b"gnip");
        match t.steps[fin + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, len } => assert_eq!((digest, len), (gnip, 4), "the host's answer landed as sponge C produced it"),
            _ => panic!("the result lands as a string"),
        }
        let efx_rows: Vec<usize> = (sys..=fin).filter(|&r| t.steps[r].micro == mk::EFX).collect();
        assert_eq!(efx_rows.len(), dsol_vm::efx_plan(op::SYSCALL).len(), "one EFX row per schedule stage");
        assert!((sys..=fin).any(|r| t.steps[r].micro == mk::FEED), "the answer was FED through a sponge, not cached");
        let ret_row = efx_rows[2]; // stage 2: (SpongeC, Plen) → Tmp1
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate, bind: &[Fa4]| {
            verify_postcommit_bus_bytes(p, g, &buses, bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &stmt.bind()).expect("the honest syscall program satisfies the CPU relation");
        assert!(verify_with(&p, &g, &stmt.bind()), "a SYSCALL program verifies");
        let other = dsol_vm::str_digest(b"other");
        // F3: another effects digest in the statement
        let stmt2 = DsolStatement { effects_digest: other, ..stmt.clone() };
        let g2 = dsol_gate_for(stmt2.clone(), rom.clone());
        assert!(!verify_with(&p, &g2, &stmt2.bind()), "another effects digest in the statement refuses");
        // F1: the ret stage's left input lanes swapped
        let mut f1 = honest.clone();
        for d in 0..DIGEST_LANES {
            f1[C_P2 + d][ret_row] = f(other[d]);
        }
        // F2: the landed result slot's digest swapped
        let mut f2 = honest.clone();
        for d in 0..DIGEST_LANES {
            f2[stack_at(0, SLOT_D0 + d)][fin + 1] = f(other[d]);
        }
        let mut armed = 0usize;
        for (name, fcpu) in [("ret stage input swapped", f1), ("landed result swapped", f2)].iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &stmt.bind()) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &stmt.bind()) {
                assert!(!verify_with(&p, &g, &stmt.bind()), "⛔ L9b FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, 2, "CALIBRATION: without the CPU relation both syscall forgeries verify");
        eprintln!("[dsol-l9b] honest {} B ({} rows, {} EFX); 2 syscall forgeries armed without L9b, both refused with it", p.len(), t.steps.len(), efx_rows.len());
    }

    /// `POP; PUSH_BYTES "m"; PUSH_BYTES "k"; PUSH_U64 42; MAP_STORE[_PRIV]; PUSH_BYTES "m"; PUSH_BYTES "k"; MAP_LOAD; POP;
    /// PUSH_U64 1; RETURN` — a mapped write, then a mapped read of the same slot.
    fn map_program(private: bool) -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        let push_str = |out: &mut Vec<u8>, s: &[u8]| {
            out.push(op::PUSH_BYTES);
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s);
        };
        push_str(&mut out, b"m");
        push_str(&mut out, b"k");
        out.push(op::PUSH_U64);
        out.extend_from_slice(&42u64.to_le_bytes());
        out.push(if private { op::MAP_STORE_PRIV } else { op::MAP_STORE });
        push_str(&mut out, b"m");
        push_str(&mut out, b"k");
        out.push(op::MAP_LOAD);
        out.push(op::POP);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// ⭐⭐⭐ L8b PART 1 — A MAPPED SLOT'S KEY IS DERIVED IN-CIRCUIT, RED FIRST. Until now every `MAP_*` access was refused
    /// by law (the circuit had no source for `map_slot(base, key)`). Now each mapped access opens with ONE key-derivation
    /// row whose block hashes the two string operands, and its output is the key every LEAF / PATH row (and a private
    /// store's effect rows) carries. The honest write-then-read programs PROVE and VERIFY (the L8b claim), the read lands
    /// 42, and the statement's post-root is the trie holding 42 at the derived slot. Refused: (F1) the derived key nudged
    /// on the row after a KEYD row (the carry); (F2) the KEYD block's two inputs swapped (the operand laws).
    /// CALIBRATION: both verify under the constraint-free gate.
    #[test]
    fn l8b_a_mapped_slot_key_is_derived_in_circuit() {
        for private in [false, true] {
            let code = map_program(private);
            let prog = decode_program(&code).expect("decodes");
            let t = run_it(&code);
            let stmt = stmt_for(&code, b"", &t);
            let slot = dsol_vm::map_slot(&dsol_vm::str_digest(b"m"), &dsol_vm::str_digest(b"k"));
            let mut trie = dsol_vm::StorageTrie::default();
            trie.insert_checked(&slot, dsol_vm::VmVal::Word(42)).expect("the slot inserts");
            assert_eq!(stmt.storage_post, trie.root(), "the mapped write landed at the DERIVED slot");
            let keyd: Vec<usize> = t.steps.iter().enumerate().filter(|(_, s)| s.micro == mk::KEYD).map(|(i, _)| i).collect();
            assert_eq!(keyd.len(), 2, "one key-derivation row per mapped access");
            let load_keyd = t.steps.iter().position(|s| s.op == op::MAP_LOAD).expect("the load runs");
            assert_eq!(t.steps[load_keyd].micro, mk::KEYD, "a mapped access opens with its KEYD row");
            let load_fin = t.steps.iter().rposition(|s| s.op == op::MAP_LOAD).unwrap();
            assert_eq!(t.steps[load_fin + 1].stack[0].as_word(), Some(42), "the mapped read landed the written word");
            let cpu_rows = t.steps.len().next_power_of_two().max(32);
            let rom_rows = prog.len().next_power_of_two().max(32);
            let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
            let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
            let buses = vec![fetch_bus()];
            let g = dsol_gate_for(stmt.clone(), rom.clone());
            let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
                verify_postcommit_bus_bytes(p, g, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
            };
            let verify_free = |p: &[u8]| {
                verify_postcommit_bus_bytes(p, gates, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
            };
            let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &stmt.bind()).expect("the honest mapped program satisfies the CPU relation");
            assert!(verify_with(&p, &g), "a MAP_{} program verifies", if private { "STORE_PRIV + MAP_LOAD" } else { "STORE + MAP_LOAD" });
            // F1: the derived key nudged on the row after the load's KEYD row
            let mut f1 = honest.clone();
            f1[C_PKEY][load_keyd + 1] += Fa4::ONE;
            // F2: the load's KEYD block inputs swapped (key, base)
            let mut f2 = honest.clone();
            for d in 0..DIGEST_LANES {
                let (a, b) = (f2[C_P2 + d][load_keyd], f2[C_P2 + DIGEST_LANES + d][load_keyd]);
                f2[C_P2 + d][load_keyd] = b;
                f2[C_P2 + DIGEST_LANES + d][load_keyd] = a;
            }
            let mut armed = 0usize;
            for (name, fcpu) in [("derived key nudged", f1), ("KEYD inputs swapped", f2)].iter() {
                if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &stmt.bind()) {
                    if verify_free(&p) {
                        armed += 1;
                    }
                }
                if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &stmt.bind()) {
                    assert!(!verify_with(&p, &g), "⛔ L8b FORGERY VERIFIED: {name}");
                }
            }
            assert_eq!(armed, 2, "CALIBRATION: without the CPU relation both key forgeries verify");
            eprintln!("[dsol-l8b] private={private}: honest {} B ({} rows, 2 KEYD); 2 key forgeries armed without L8b, both refused with it", p.len(), t.steps.len());
        }
    }

    /// `POP; PUSH_BYTES "k"; PUSH_BYTES "hello"; SSTORE; PUSH_BYTES "k"; SLOAD; POP; PUSH_BYTES "k"; PUSH_BYTES "bye";
    /// SSTORE; PUSH_U64 1; RETURN` — a string written into an absent slot, read back, then overwritten by another string.
    fn string_slot_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        let push_str = |out: &mut Vec<u8>, s: &[u8]| {
            out.push(op::PUSH_BYTES);
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s);
        };
        push_str(&mut out, b"k");
        push_str(&mut out, b"hello");
        out.push(op::SSTORE);
        push_str(&mut out, b"k");
        out.push(op::SLOAD);
        out.push(op::POP);
        push_str(&mut out, b"k");
        push_str(&mut out, b"bye");
        out.push(op::SSTORE);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&1u64.to_le_bytes());
        out.push(op::RETURN);
        out
    }

    /// ⭐⭐⭐ L8b PART 2 — A STRING-VALUED SLOT, RED FIRST. Until now a string value in storage was refused by law (the LEAF
    /// block had no source for `compress(digest, [1, len])`). Now each string value's half is hashed on its own SVAL row
    /// before the LEAF row that consumes it, the pre-image string rides beside the tagged value, and a read lands the
    /// string. The honest write / read / overwrite program PROVES and VERIFIES (the L8b-2 claim): four SVAL rows (a write
    /// into an absent slot: one; the read: one; the overwrite: two), the read lands `Str("hello", 5)`, the post-root is
    /// the trie holding "bye" at "k". Refused: (F1) the read's landed digest swapped (the landing law); (F2) the read's
    /// SVAL block input swapped for another string's digest (the input law); (F3) a LEAF row's value half nudged (the
    /// carry). CALIBRATION: all three verify under the constraint-free gate.
    #[test]
    fn l8b_a_string_valued_slot_round_trips_and_lands() {
        let code = string_slot_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let stmt = stmt_for(&code, b"", &t);
        let (k, hello, bye) = (dsol_vm::str_digest(b"k"), dsol_vm::str_digest(b"hello"), dsol_vm::str_digest(b"bye"));
        let mut trie = dsol_vm::StorageTrie::default();
        trie.insert_checked(&k, dsol_vm::VmVal::Str { digest: bye, len: 3 }).expect("the slot inserts");
        assert_eq!(stmt.storage_post, trie.root(), "the overwrite landed the second string at the key");
        let sval: Vec<usize> = t.steps.iter().enumerate().filter(|(_, s)| s.micro == mk::SVAL).map(|(i, _)| i).collect();
        assert_eq!(sval.len(), 4, "one value-half row per string value: write 1, read 1, overwrite 2");
        let load_first = t.steps.iter().position(|s| s.op == op::SLOAD).expect("the load runs");
        assert_eq!(t.steps[load_first].micro, mk::SVAL, "a read of a string slot opens with its SVAL row");
        let load_fin = t.steps.iter().rposition(|s| s.op == op::SLOAD).unwrap();
        match t.steps[load_fin + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, len } => assert_eq!((digest, len), (hello, 5), "the read landed the string"),
            _ => panic!("a string slot lands a string"),
        }
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        // the row-level diagnostic first: a refusal names its row, opcode, micro kind and stage, never "a law fired"
        if let DsolCpuGate::Cpu(c) = g(0, Ea4::from_u64(0x1234_5678)) {
            if let Some((r, what)) = first_unsatisfied_row(&c, &honest, &t.steps) {
                panic!("⛔ the honest string-slot program violates the relation at row {r} ({what}) of {}", t.steps.len());
            }
        }
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &stmt.bind()).expect("the honest string-slot program satisfies the CPU relation");
        assert!(verify_with(&p, &g), "a string-valued storage program verifies");
        // F1: the read's landed digest swapped for "bye"'s
        let mut f1 = honest.clone();
        for d in 0..DIGEST_LANES {
            f1[stack_at(0, SLOT_D0 + d)][load_fin + 1] = f(bye[d]);
        }
        // F2: the read's SVAL block input (the pre-image digest) swapped for "bye"'s, C_PVDIG untouched
        let mut f2 = honest.clone();
        for d in 0..DIGEST_LANES {
            f2[C_P2 + d][load_first] = f(bye[d]);
        }
        // F3: the read's LEAF row value half nudged
        let mut f3 = honest.clone();
        f3[C_PVLANES][load_first + 1] += Fa4::ONE;
        let mut armed = 0usize;
        for (name, fcpu) in [("landed digest swapped", f1), ("SVAL input swapped", f2), ("LEAF value half nudged", f3)].iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &stmt.bind()) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &stmt.bind()) {
                assert!(!verify_with(&p, &g), "⛔ L8b-2 FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, 3, "CALIBRATION: without the CPU relation every string-slot forgery verifies");
        eprintln!("[dsol-l8b2] honest {} B ({} rows, 4 SVAL); 3 string-slot forgeries armed without L8b-2, all refused with it", p.len(), t.steps.len());
    }

    /// ⭐ L3 STACK, RED FIRST, on `alu_program` (POP; PUSH 7; PUSH 6; ADD; PUSH 5; SUB; RETURN — sp 1,0,1,2,1,2,1).
    /// Four forgeries invisible to the fetch bus, L1, L4a and L5 are refused only by L3: (F1) the word PUSH 7 landed
    /// grows a HIGH limb (7 + 2¹⁶) — before this landing nothing bound a pushed word's upper 48 bits; (F2) the ADD
    /// row's sp claims 5 (value and one-hot) — the previous row's sp law; (F3) row 0 (the POP) claims sp = 0 — the
    /// underflow law, on a row with no predecessor to contradict it; (F4) the 13 that ADD landed is 12 by the time
    /// SUB reads it below the top — the shift law. CALIBRATION: under the constraint-free gate all four verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES with the verifier's gate rebuilt from the statement (see
    /// the L5 pin); the two-node `verify_dsol_call` endpoint is phase 1's completion bar.
    #[test]
    fn l3_a_grown_word_a_lying_sp_an_underflow_and_a_moved_slot_are_refused() {
        let code = alu_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let sps: Vec<u8> = t.steps.iter().map(|s| s.sp).collect();
        assert_eq!(&sps[..7], &[1, 0, 1, 2, 1, 2, 1], "the pre-state sp of the first seven rows (the word RETURN then produces its bytes)");
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt_for(&code, b"", &t), rom.clone());
        let verify_with = |p: &[u8], g: &dyn Fn(usize, Ea4) -> DsolCpuGate| {
            verify_postcommit_bus_bytes(p, g, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let verify_free = |p: &[u8]| {
            verify_postcommit_bus_bytes(p, gates, &buses, &BIND, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(p).1)
        };
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &BIND)
            .expect("the honest program satisfies L1+L3+L4a+L5");
        assert!(verify_with(&p, &g), "the honest program verifies");
        // F1: row 2 (PUSH 6's pre-state) shows the 7 that PUSH 7 landed — give it a high limb.
        let mut f1 = honest.clone();
        f1[stack_at(0, SLOT_W0 + 1)][2] = Fa4::ONE;
        // F2: the ADD row (3) claims sp = 5, value and one-hot together.
        let mut f2 = honest.clone();
        f2[C_SP][3] = f(5);
        f2[C_SPSEL + 2][3] = Fa4::ZERO;
        f2[C_SPSEL + 5][3] = Fa4::ONE;
        // F3: row 0 (POP of the argv) claims an empty stack.
        let mut f3 = honest.clone();
        f3[C_SP][0] = Fa4::ZERO;
        f3[C_SPSEL + 1][0] = Fa4::ZERO;
        f3[C_SPSEL][0] = Fa4::ONE;
        // F4: row 5 (SUB's pre-state) shows the 13 below the top — make it 12 there only.
        let mut f4 = honest.clone();
        f4[stack_at(1, SLOT_W0)][5] = f(12);
        let forgeries = [("pushed word grew a high limb", f1), ("sp lies on the ADD row", f2), ("underflow on row 0", f3), ("a slot moved between rows", f4)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &BIND) {
                if verify_free(&p) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &BIND) {
                assert!(!verify_with(&p, &g), "⛔ L3 FORGERY VERIFIED: {name}");
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every stack forgery verifies");
        eprintln!("[dsol-l3] honest {} B; {} stack forgeries armed without L3, all refused with it", p.len(), armed);
    }

    /// ⛔⛔⛔ A-F55's VALUE QUESTION (RED first): the CPU call proof's engine (`postcommit_bus`) bound the CPU gate's opened
    /// row through the same hiding verifier the direct engine used (`add_claim_at` + `verify_hvzk`), and the direct engine's
    /// solved-row liar passed the blob door on 2026-11-13. MEASURED 2026-11-15 (lane af57): with its forge sending the
    /// next-row values in the form the door verifies, this liar VERIFIED on that engine (95,908 B); before, its compact form
    /// was refused by a length check alone. A-F57 replaced the engine (light_commit). So the liar is run HERE, on the CPU leg, which is what fixes a
    /// contract's `storage_post`: the honest CPU and ROM tables of a real call, a statement whose `storage_post` the run
    /// never reached, and the CPU table's zerocheck sent as zero rounds plus a SOLVED opened row
    /// (`postcommit_bus::forge_postcommit_opened_for_tests`; the ROM table and the fetch bus honest). The production verifier
    /// must refuse it.
    /// TWO-PARTY-REVIEWED: the two parties are the lying prover and `verify_dsol_call`, which rebuilds the ROM, the shapes,
    /// the gate and the bind from the code and the statement alone — the boundary a node stands on against a wallet's call.
    #[test]
    fn af55_a_call_proof_for_a_storage_post_the_run_never_reached_is_refused_from_a_solved_row_liar() {
        let code = alu_program();
        let (proof, stmt) = prove_dsol_call(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost)
            .expect("an honest call proves");
        assert!(verify_dsol_call(&proof, &code, &stmt), "CONTROL: the honest call verifies");
        let t = dsol_vm::run(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost).expect("runs");
        let prog = decode_program(&code).expect("decodes");
        let (shapes1, _) = dsol_table_shapes(stmt.height_log2, prog.len());
        let cpu = build_cpu_trace(&t, &code, 1usize << shapes1[0].0).expect("lays the CPU table");
        let rom = build_rom_trace(&prog, 1usize << shapes1[1].0).expect("lays the ROM");
        let mut lie = stmt.clone();
        lie.storage_post[0] ^= 1;
        assert!(!verify_dsol_call(&proof, &code, &lie), "CONTROL: the honest proof does not speak for the lie");
        let gate = dsol_gate_for(lie.clone(), rom.clone());
        let forged = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::postcommit_bus::forge_postcommit_opened_for_tests(vec![cpu.clone(), rom.clone()], &gate, &[fetch_bus()], &lie.bind(), 0)
        }))
        .ok()
        .flatten();
        let passes = forged.as_ref().is_some_and(|b| verify_dsol_call(&DsolCallProof { bytes: b.clone() }, &code, &lie));
        eprintln!("[af55-cpu] the CPU leg's solved-row liar: {} B, verify_dsol_call={passes}", forged.as_ref().map_or(0, Vec::len));
        assert!(forged.is_some(), "CALIBRATION: the liar could not solve a row for the CPU gate, so this pin measures nothing");
        assert!(!passes, "⛔⛔⛔ A-F55 VALUE HOLE: a contract call proof for a storage_post the run never reached VERIFIED");
    }

    /// ⛔⛔⛔ A-F57 — THE DSOL CALL DOOR'S OPENED ROW IS THE COMMITTED TRACE'S (finding A-F57, scratchpad/net/findings.tsv;
    /// spec docs/AF57-POSTCOMMIT-BUS-BINDING-SPEC-20261115.md).
    ///
    /// **The liar.** A-F55's lying prover at the production door:
    /// - the honest CPU and ROM tables of a real call, committed honestly;
    /// - the fetch bus honest;
    /// - every next-row value the commitment's own, with its shift bind;
    /// - and ONE lie: the CPU table's zerocheck sent as zero rounds with its opened row SOLVED so the gate holds under a
    ///   statement whose `storage_post` the run never reached.
    ///
    /// **RED measured on the old engine** (2026-11-15, lane af57, scratchpad af57_red2a.out): this liar VERIFIED at
    /// `verify_dsol_call`, 95,908 B, `verify_dsol_call=true`. That engine's masked sumcheck dropped its final target
    /// (`whir::pcs::hiding::verify_hvzk`, `.map(|(point, _target)| point)`) and opened no commitment.
    ///
    /// **This engine** commits both rounds (`light_commit`) and discharges every claim with a WHIR opening.
    ///
    /// **CALIBRATION:** the door's whole claims replay accepts the liar (the shapes, α/β, every tie, every zerocheck, every
    /// shift bind), so the refusal is the opening's and nothing else's.
    ///
    /// The honest call proof's bytes and prove time are printed: the cons of the change, measured.
    ///
    /// TWO-PARTY-REVIEWED: the parties are the lying prover and `verify_dsol_call`, which rebuilds the ROM, the shapes, the
    /// gate and the bind from the code and the statement alone.
    #[test]
    fn af57_a_call_proof_whose_opened_row_is_solved_not_committed_is_refused_by_its_opening() {
        let code = alu_program();
        let t0 = std::time::Instant::now();
        let (proof, stmt) = prove_dsol_call(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost)
            .expect("an honest call proves");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_dsol_call(&proof, &code, &stmt), "CONTROL: the honest call verifies");
        eprintln!("[af57] honest call proof: {} B, prove {prove_ms} ms, verify {} ms (height class 2^{})", proof.bytes.len(), t1.elapsed().as_millis(), stmt.height_log2);
        let t = dsol_vm::run(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost).expect("runs");
        let prog = decode_program(&code).expect("decodes");
        let (shapes1, shapes2) = dsol_table_shapes(stmt.height_log2, prog.len());
        let cpu = build_cpu_trace(&t, &code, 1usize << shapes1[0].0).expect("lays the CPU table");
        let rom = build_rom_trace(&prog, 1usize << shapes1[1].0).expect("lays the ROM");
        let mut lie = stmt.clone();
        lie.storage_post[0] ^= 1;
        assert!(!verify_dsol_call(&proof, &code, &lie), "CONTROL: the honest proof does not speak for the lie");
        let gate = dsol_gate_for(lie.clone(), rom.clone());
        let weak = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::postcommit_bus::forge_postcommit_opened_for_tests(vec![cpu.clone(), rom.clone()], &gate, &[fetch_bus()], &lie.bind(), 0)
        }))
        .ok()
        .flatten()
        .expect("CALIBRATION: the liar solves a row for the CPU gate");
        // the door's own gate and shapes, as verify_dsol_call rebuilds them from the code and the lying statement
        let door_gate = dsol_gate_for_code(lie.clone(), std::sync::Arc::from(&code[..]));
        assert!(
            crate::postcommit_bus::claims_replay_accepts_for_tests(&weak, &door_gate, &[fetch_bus()], &lie.bind(), &shapes1, &shapes2),
            "CALIBRATION: the door's replay accepts every claim the liar makes; only the opening can refuse it"
        );
        let passes = verify_dsol_call(&DsolCallProof { bytes: weak.clone() }, &code, &lie);
        eprintln!("[af57] the solved-row liar: {} B, verify_dsol_call={passes}", weak.len());
        assert!(!passes, "⛔⛔⛔ A-F57 SOUNDNESS HOLE: a contract call proof for a storage_post the run never reached VERIFIED");
    }

    /// ⭐ L10 BOUNDARY + THE PRODUCTION ENTRY POINTS, RED FIRST. `prove_dsol_call` / `verify_dsol_call` accept the
    /// word-returning `alu_program` (its RETURN now PRODUCES the 8 bytes through sponge C — H2) and the string-returning
    /// `branch_program`. Refused: every single-field edit of the statement (verifier side: the bind and the laws), other
    /// code, and four trace forgeries under the HONEST statement that only the boundary laws see — row 0's sp, a row-0
    /// argv digest lane, the last row's effects fold, the step counter. CALIBRATION for the trace forgeries: under the
    /// constraint-free gate with the same bind all four verify.
    ///
    /// TWO-PARTY-REVIEWED: `verify_dsol_call` rebuilds the ROM, every table shape, the CPU multiplicities, the gate and
    /// the bind from the CODE and the STATEMENT alone and reads nothing off the carrier — the exact boundary a node
    /// stands on against a wallet's call. Two real nodes verifying one wallet's call is phase 1's completion bar.
    #[test]
    fn l10_the_statement_is_bound_at_both_ends_and_the_entry_points_verify() {
        let mut host = dsol_vm::NoHost;
        for (name, code, want) in [
            ("word return", alu_program(), dsol_vm::str_digest(&8u64.to_le_bytes())),
            ("string return", branch_program(1), dsol_vm::str_digest(b"abcd")),
        ] {
            let (proof, stmt) = prove_dsol_call(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut host)
                .expect("an honest call proves on the production entry point");
            assert!(verify_dsol_call(&proof, &code, &stmt), "an honest {name} call verifies on the production entry point");
            assert_eq!(stmt.ret_digest, want, "{name}: the statement's return digest is the returned value's");
            let mut edits: Vec<(&str, DsolStatement)> = Vec::new();
            let mut s = stmt.clone(); s.code_id[0] ^= 1; edits.push(("code_id", s));
            let mut s = stmt.clone(); s.entry_sel ^= 1; edits.push(("entry_sel", s));
            let mut s = stmt.clone(); s.start_pc += 1; edits.push(("start_pc", s));
            let mut s = stmt.clone(); s.argv_digest[0] ^= 1; edits.push(("argv_digest", s));
            let mut s = stmt.clone(); s.argv_len += 1; edits.push(("argv_len", s));
            let mut s = stmt.clone(); s.storage_pre[0] ^= 1; edits.push(("storage_pre", s));
            let mut s = stmt.clone(); s.storage_post[0] ^= 1; edits.push(("storage_post", s));
            let mut s = stmt.clone(); s.effects_digest[0] ^= 1; edits.push(("effects_digest", s));
            let mut s = stmt.clone(); s.ret_digest[0] ^= 1; edits.push(("ret_digest", s));
            let mut s = stmt.clone(); s.height_log2 += 1; edits.push(("height_log2", s));
            for (field, s) in &edits {
                assert!(!verify_dsol_call(&proof, &code, s), "⛔ {name}: a statement with a forged {field} VERIFIED");
            }
            assert!(!verify_dsol_call(&proof, &code[..code.len() - 1], &stmt), "{name}: other code is refused");
            // the exact row count is private: a call PADDED to four times its natural height proves and verifies with
            // every other statement field equal, and the two proofs differ only in shape
            let (padded, pstmt) = prove_dsol_call_padded(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, Some(stmt.height_log2 + 2)).expect("the padded call proves");
            assert!(verify_dsol_call(&padded, &code, &pstmt), "{name}: the padded call verifies");
            assert_eq!(DsolStatement { height_log2: stmt.height_log2, ..pstmt.clone() }, stmt, "{name}: padding changes nothing but the height class");
            if stmt.height_log2 > natural_height_log2(1) {
                assert!(prove_dsol_call_padded(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, Some(stmt.height_log2 - 1)).is_none(), "{name}: a height below the run's natural class is refused");
            }
            assert!(prove_dsol_call_padded(&code, "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, Some(MAX_HEIGHT_LOG2 + 1)).is_none(), "{name}: a height above the budget's class is refused");
            eprintln!("[dsol-l10] {name}: height 2^{}, {} B (padded to 2^{}: {} B), {} statement edits refused", stmt.height_log2, proof.bytes.len(), pstmt.height_log2, padded.bytes.len(), edits.len());
        }
        // Trace forgeries under the HONEST statement — only the boundary laws can see these.
        let code = alu_program();
        let t = run_it(&code);
        let stmt = stmt_for(&code, b"", &t);
        let bind = stmt.bind();
        let prog = decode_program(&code).expect("decodes");
        let (shapes1, _) = dsol_table_shapes(natural_height_log2(t.steps.len()), prog.len());
        let (cpu_rows, rom_rows) = (1usize << shapes1[0].0, 1usize << shapes1[1].0);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        let last = t.steps.len() - 1;
        let mut f1 = honest.clone();
        f1[C_SP][0] = f(2);
        f1[C_SPSEL + 1][0] = Fa4::ZERO;
        f1[C_SPSEL + 2][0] = Fa4::ONE;
        let mut f2 = honest.clone();
        f2[stack_at(0, SLOT_D0)][0] += Fa4::ONE;
        let mut f3 = honest.clone();
        for r in last..cpu_rows {
            f3[C_EACC][r] += Fa4::ONE;
        }
        // F4: a PADDING row claims to be real (the row count is private, so `C_REAL`'s fall after the RETURN's final row
        // is what fixes where the real rows end)
        assert!(last + 1 < cpu_rows, "the program leaves padding rows to forge");
        let mut f4 = honest.clone();
        f4[C_REAL][cpu_rows - 1] = Fa4::ONE;
        let forgeries = [("row 0 claims sp = 2", f1), ("row 0 argv digest lane", f2), ("last row's effects fold", f3), ("a padding row claims real", f4)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &bind) {
                if verify_postcommit_bus_bytes(&p, gates, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &bind) {
                assert!(
                    !verify_postcommit_bus_bytes(&p, &g, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                    "⛔ L10 FORGERY VERIFIED: {name}"
                );
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every boundary forgery verifies");
        eprintln!("[dsol-l10] {} boundary forgeries armed without L10, all refused with it", armed);
    }

    /// ⭐ L6 SPONGE + L7 PACKING (S1), RED FIRST, on `branch_program(0)` (CONCAT re-absorbs "ab" and "cd" through A and
    /// B while producing "abcd" through C; the string RETURN) and `alu_program` (the word RETURN produces 8 bytes).
    /// Both verify under the whole relation with the Poseidon2 block law embedded. Five forgeries that only the sponge
    /// laws see are refused: (F1) a sponge's state lane changed on a FEED row (the carry law); (F2) the length a sponge
    /// was opened with (the open law — `init(len)`); (F3) a PERM row's block input lane (the block binding); (F4) a byte
    /// landed at another sub-position (the fill one-hot and the landing law); (F5) the produce countdown. CALIBRATION:
    /// under the constraint-free gate all five verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES with the verifier's gate rebuilt from the statement (see
    /// the L5 pin); two real nodes verifying one wallet's call is phase 1's completion bar.
    #[test]
    fn l6_l7_an_unwarranted_sponge_jump_open_block_landing_or_countdown_is_refused() {
        for (name, code) in [("CONCAT + string return", branch_program(0)), ("word return", alu_program())] {
            let prog = decode_program(&code).expect("decodes");
            let t = run_it(&code);
            let stmt = stmt_for(&code, b"", &t);
            let bind = stmt.bind();
            let (shapes1, _) = dsol_table_shapes(natural_height_log2(t.steps.len()), prog.len());
            let (cpu_rows, rom_rows) = (1usize << shapes1[0].0, 1usize << shapes1[1].0);
            let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
            let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
            let buses = vec![fetch_bus()];
            let g = dsol_gate_for(stmt.clone(), rom.clone());
            let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &bind)
                .unwrap_or_else(|| panic!("the honest {name} program satisfies the relation with the sponge laws ({} rows)", t.steps.len()));
            assert!(
                verify_postcommit_bus_bytes(&p, &g, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                "the honest {name} program verifies"
            );
            // rows the forgeries target
            let feeds: Vec<usize> = t.steps.iter().enumerate().filter(|(_, s)| s.micro == mk::FEED).map(|(r, _)| r).collect();
            let open_row = t.steps.iter().position(|s| s.open.iter().any(|&o| o)).expect("a sponge opens");
            let open_sponge = t.steps[open_row].open.iter().position(|&o| o).expect("which sponge");
            let perm_row = t.steps.iter().position(|s| s.micro == mk::PERM).expect("a PERM row");
            let second_feed = feeds[1];
            let fed_sponge = t.steps[second_feed].feed.iter().position(|&f| f).expect("the fed sponge");
            let produce_feed = t.steps.iter().position(|s| s.micro == mk::FEED && s.feed[dsol_vm::SPONGE_C]).expect("a produce/concat feed into C");
            let mut f1 = honest.clone();
            f1[sp_state(fed_sponge, RATE + 1)][second_feed] += Fa4::ONE;
            let mut f2 = honest.clone();
            f2[sp_state(open_sponge, RATE)][open_row] += Fa4::ONE;
            let mut f3 = honest.clone();
            f3[C_P2][perm_row] += Fa4::ONE;
            let mut f4 = honest.clone();
            let fill = t.steps[second_feed].sponges[fed_sponge].fill as usize;
            f4[fill_sel(fed_sponge, fill)][second_feed] = Fa4::ZERO;
            f4[fill_sel(fed_sponge, fill + 1)][second_feed] = Fa4::ONE;
            f4[C_SPFILL + fed_sponge][second_feed] = f(fill as u64 + 1);
            // F5 is the law each program actually has: a PRODUCER's countdown (`remaining` off by one on a byte fed to C)
            // for the word return; for CONCAT — whose byte count is fixed by the A/B digest checks, not by a counter —
            // a byte that reaches A or B but NOT C (the pairing law).
            let mut f5 = honest.clone();
            let f5_name = if t.steps.iter().any(|s| s.op == op::CONCAT) {
                f5[C_FEED + dsol_vm::SPONGE_C][produce_feed] = Fa4::ZERO;
                "a CONCAT byte that skips C"
            } else {
                f5[C_REMAIN][produce_feed] += Fa4::ONE;
                "produce countdown"
            };
            let forgeries = [("state jumped on a FEED row", f1), ("opened with another length", f2), ("PERM block input lane", f3), ("byte landed at the next sub-position", f4), (f5_name, f5)];
            let mut armed = 0usize;
            for (fname, fcpu) in forgeries.iter() {
                if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &bind) {
                    if verify_postcommit_bus_bytes(&p, gates, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1) {
                        armed += 1;
                    }
                }
                if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &bind) {
                    assert!(
                        !verify_postcommit_bus_bytes(&p, &g, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                        "⛔ L6/L7 FORGERY VERIFIED ({name}): {fname}"
                    );
                }
            }
            assert_eq!(armed, forgeries.len(), "CALIBRATION ({name}): without the CPU relation every sponge forgery verifies");
            eprintln!("[dsol-l6l7] {name}: {} rows, {} B; {} sponge forgeries armed without L6/L7, all refused with it", t.steps.len(), p.len(), armed);
        }
    }

    /// `POP; PUSH 5; PUSH 7; LT; PUSH 3; PUSH 3; EQ; AND; PUSH 0; OR; NOT; RETURN` → 5<7 = 1, 3==3 = 1, 1∧1 = 1,
    /// 1∨0 = 1, ¬1 = 0. Rows: 0 POP, 1 PUSH, 2 PUSH, 3 LT, 4 PUSH, 5 PUSH, 6 EQ, 7 AND, 8 PUSH, 9 OR, 10 NOT, 11 RETURN.
    fn logic_program() -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::POP);
        for (o, v) in [(op::PUSH_U64, 5u64), (op::PUSH_U64, 7)] {
            out.push(o);
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(op::LT);
        for v in [3u64, 3] {
            out.push(op::PUSH_U64);
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.push(op::EQ);
        out.push(op::AND);
        out.push(op::PUSH_U64);
        out.extend_from_slice(&0u64.to_le_bytes());
        out.push(op::OR);
        out.push(op::NOT);
        out.push(op::RETURN);
        out
    }

    /// ⭐ L4b ALU LT / EQ / AND / OR / NOT, RED FIRST. The honest program verifies (its word return produces its bytes);
    /// four forgeries only L4b sees are refused: (F1) LT lands 0 for 5 < 7 (the borrow-out); (F2) EQ lands 0 for 3 == 3
    /// with the inverse witnesses claiming a non-zero difference; (F3) AND lands 0 with the second operand's non-zero
    /// witness zeroed; (F4) NOT lands 1 for ¬1 with its witness zeroed. CALIBRATION: under the constraint-free gate all
    /// four verify.
    ///
    /// TWO-PARTY-REVIEWED: prove → verify across proof BYTES with the verifier's gate rebuilt from the statement (see
    /// the L5 pin); two real nodes verifying one wallet's call is phase 1's completion bar.
    #[test]
    fn l4b_a_wrong_compare_or_logic_result_is_refused() {
        let code = logic_program();
        let prog = decode_program(&code).expect("decodes");
        let t = run_it(&code);
        let ops: Vec<u8> = t.steps.iter().take(12).map(|s| s.op).collect();
        assert_eq!(&ops[3..11], &[op::LT, op::PUSH_U64, op::PUSH_U64, op::EQ, op::AND, op::PUSH_U64, op::OR, op::NOT], "the row map");
        assert_eq!(t.run.ret_digest, dsol_vm::str_digest(&0u64.to_le_bytes()), "the program returns 0");
        let stmt = stmt_for(&code, b"", &t);
        let bind = stmt.bind();
        let (shapes1, _) = dsol_table_shapes(natural_height_log2(t.steps.len()), prog.len());
        let (cpu_rows, rom_rows) = (1usize << shapes1[0].0, 1usize << shapes1[1].0);
        let honest = build_cpu_trace(&t, &code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &bind).expect("the honest logic program satisfies L4b");
        assert!(
            verify_postcommit_bus_bytes(&p, &g, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
            "the honest logic program verifies"
        );
        // F1: the LT result (row 3 lands on row 4's top) claims 0
        let mut f1 = honest.clone();
        f1[stack_at(0, SLOT_W0)][4] = Fa4::ZERO;
        // F2: the EQ result claims 0 and every difference limb "is non-zero" by witness
        let mut f2 = honest.clone();
        f2[stack_at(0, SLOT_W0)][7] = Fa4::ZERO;
        f2[C_EQFLAG][6] = Fa4::ZERO; // the flag says "not equal" for 3 == 3 …
        f2[C_EQINV][6] = Fa4::ONE; // … with an inverse witness that would make a zero sum look inverted
        // F3: AND claims 0 with b's non-zero flag and witness zeroed
        let mut f3 = honest.clone();
        f3[stack_at(0, SLOT_W0)][8] = Fa4::ZERO;
        f3[C_NZ + 1][7] = Fa4::ZERO;
        f3[C_NZINV + 1][7] = Fa4::ZERO;
        // F4: NOT claims 1 with a's non-zero flag and witness zeroed
        let mut f4 = honest.clone();
        f4[stack_at(0, SLOT_W0)][11] = Fa4::ONE;
        f4[C_NZ][10] = Fa4::ZERO;
        f4[C_NZINV][10] = Fa4::ZERO;
        let forgeries = [("LT lands 0 for 5 < 7", f1), ("EQ lands 0 for 3 == 3", f2), ("AND lands 0 with a zeroed witness", f3), ("NOT lands 1 with a zeroed witness", f4)];
        let mut armed = 0usize;
        for (name, fcpu) in forgeries.iter() {
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], gates, &buses, &bind) {
                if verify_postcommit_bus_bytes(&p, gates, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1) {
                    armed += 1;
                }
            }
            if let Some(p) = prove_postcommit_bus_bytes(vec![fcpu.clone(), rom.clone()], &g, &buses, &bind) {
                assert!(
                    !verify_postcommit_bus_bytes(&p, &g, &buses, &bind, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
                    "⛔ L4b FORGERY VERIFIED: {name}"
                );
            }
        }
        assert_eq!(armed, forgeries.len(), "CALIBRATION: without the CPU relation every compare/logic forgery verifies");
        eprintln!("[dsol-l4b] honest {} B ({} rows); {} compare/logic forgeries armed without L4b, all refused with it", p.len(), t.steps.len(), armed);
    }

    /// ⛔ A PROGRAM THE CIRCUIT CANNOT DESCRIBE IS REFUSED AT DECODE, not at a mystifying zerocheck.
    #[test]
    fn a_program_with_an_unprovable_opcode_or_a_truncated_tail_does_not_decode() {
        let hdr = 5 + 8;
        let head = |body: &[u8]| {
            let mut out = vec![dsol_vm::DSOL_VERSION];
            out.extend_from_slice(&1u32.to_le_bytes());
            out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
            out.extend_from_slice(&(hdr as u32).to_le_bytes());
            out.extend_from_slice(body);
            out
        };
        assert!(decode_program(&head(&[op::SHA3, op::RETURN])).is_none(), "SHA3 has no circuit law");
        assert!(decode_program(&head(&[op::JUMP, 1, 2])).is_none(), "a truncated jump does not decode");
        assert!(decode_program(&head(&[op::POP, op::RETURN])).is_some(), "an honest program does decode");
    }

    /// ⛔ A `PUSH_BYTES` LITERAL IS DATA, NOT CODE. If the decoder walked byte by byte it would read a
    /// literal's bytes as opcodes and the ROM would hold instructions the program does not have.
    #[test]
    fn a_literals_bytes_are_never_decoded_as_instructions() {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::PUSH_BYTES);
        out.extend_from_slice(&3u16.to_le_bytes());
        // Three bytes that ARE valid opcodes — the trap a byte-by-byte decoder falls into.
        out.extend_from_slice(&[op::RETURN, op::REVERT, op::POP]);
        out.push(op::RETURN);
        let prog = decode_program(&out).expect("decodes");
        assert_eq!(prog.len(), 2, "one literal push and one return — the literal is not three opcodes");
        assert_eq!(prog[0].1, op::PUSH_BYTES, "the first instruction is the push");
        assert_eq!(prog[1].1, op::RETURN, "and the second is the return past the literal");
    }

    // ───────────────────────────── S2 — THE CONTENT LAWS, and the forger that measures them ─────────────────────────────

    /// One row of a forger's schedule for a producing opcode's run.
    #[derive(Clone, Copy)]
    enum Sched {
        /// A FEED row: the byte, the sponges it enters, and the sponges that OPEN on this row (with their lengths).
        Feed { byte: u8, to: [bool; SPONGES], open: [Option<usize>; SPONGES] },
        /// A PERM row of sponge `s`, with the sponges that open on it.
        Perm { s: usize, open: [Option<usize>; SPONGES] },
        /// The FINISH row.
        Finish,
        /// The honest row `row` kept as it is (an EFX / CMT row), carrying the forger's sponges, flags and accumulators.
        Keep { row: usize },
    }

    /// The honest run's rows `first..=last` as a schedule — replaying it through `forge_run` reproduces the honest steps
    /// exactly (the pins assert so), and the forger then edits the bytes it wants to lie about.
    fn sched_from(honest: &[Step], first: usize, last: usize) -> Vec<Sched> {
        (first..=last)
            .map(|r| {
                let s = &honest[r];
                let open: [Option<usize>; SPONGES] = core::array::from_fn(|k| if s.open[k] { Some(s.sponges[k].state[RATE] as usize) } else { None });
                match s.micro {
                    mk::FEED => Sched::Feed { byte: s.byte, to: s.feed, open },
                    mk::PERM => Sched::Perm { s: s.perm, open },
                    mk::FINISH => Sched::Finish,
                    _ => Sched::Keep { row: r },
                }
            })
            .collect()
    }

    /// ⭐ THE FORGER'S RE-SIMULATION. Rebuild the rows `first..=last` of ONE opcode's run (its first row through its
    /// FINISH) from a schedule of the forger's choosing, driving the three sponges with the machine's own `SpongeSlot`,
    /// the machine's own `s2_accumulate` and the same countdown / first-block / phase bookkeeping — so every sponge law,
    /// the count frame and the accumulator frame hold by construction wherever the schedule is a lawful sequence, and
    /// only the law the forgery targets can object. Row-invariant fields (pc, op, stack, locals, roots) come from the
    /// honest run's first row; the sponges' stale pre-states from the row before it. Returns the new step list and the
    /// digest sponge C holds at the end; the caller lands the forged result on the rows that follow.
    fn forge_run(honest: &[Step], first: usize, last: usize, sched: &[Sched]) -> (Vec<Step>, Digest) {
        use dsol_vm::{acc_sponge, s2_accumulate, SpongeSlot, SPONGE_B, SPONGE_C};
        let op = honest[first].op;
        let prev = &honest[first - 1];
        let mut st = honest[first].clone();
        st.sponges = prev.sponges;
        st.fb = prev.fb;
        st.cph = if op == op::CONCAT { false } else { prev.cph };
        st.remaining = prev.remaining;
        st.s2acc = prev.s2acc;
        st.open = [false; SPONGES];
        let mut out: Vec<Step> = honest[..first].to_vec();
        let apply_open = |st: &mut Step, open: &[Option<usize>; SPONGES]| {
            for s in 0..SPONGES {
                if let Some(len) = open[s] {
                    st.sponges[s] = SpongeSlot::opened(len);
                    st.open[s] = true;
                    st.fb[s] = true;
                    if s == SPONGE_C {
                        st.remaining = len as u32;
                    }
                    if s == SPONGE_B {
                        st.cph = true;
                    }
                    if acc_sponge(op) == Some(s) {
                        st.s2acc = [0u64; dsol_vm::S2_ACC];
                    }
                }
            }
        };
        for row in sched {
            match *row {
                Sched::Feed { byte, to, open } => {
                    apply_open(&mut st, &open);
                    st.micro = mk::FEED;
                    st.byte = byte;
                    st.feed = to;
                    st.perm = SPONGES;
                    out.push(st.clone());
                    for s in 0..SPONGES {
                        if to[s] {
                            s2_accumulate(op, s, usize::from(st.sponges[s].fill), st.fb[s], byte, &mut st.s2acc);
                            st.sponges[s].feed(byte);
                            if s == SPONGE_C {
                                st.remaining = st.remaining.wrapping_sub(1);
                            }
                        }
                    }
                }
                Sched::Perm { s, open } => {
                    apply_open(&mut st, &open);
                    st.micro = mk::PERM;
                    st.byte = 0;
                    st.feed = [false; SPONGES];
                    st.perm = s;
                    out.push(st.clone());
                    st.sponges[s].perm();
                    st.fb[s] = false;
                }
                Sched::Finish => {
                    // the honest FINISH row is the template (it alone may carry a changed effects fold or path value);
                    // the sponges, flags, countdown and accumulators are the forger's
                    let mut k = honest[last].clone();
                    k.sponges = st.sponges;
                    k.fb = st.fb;
                    k.cph = st.cph;
                    k.remaining = st.remaining;
                    k.s2acc = st.s2acc;
                    k.open = st.open;
                    k.micro = mk::FINISH;
                    k.byte = 0;
                    k.feed = [false; SPONGES];
                    k.perm = SPONGES;
                    out.push(k);
                }
                Sched::Keep { row } => {
                    let mut k = honest[row].clone();
                    k.sponges = st.sponges;
                    k.fb = st.fb;
                    k.cph = st.cph;
                    k.remaining = st.remaining;
                    k.s2acc = st.s2acc;
                    k.open = st.open;
                    out.push(k);
                }
            }
            st.open = [false; SPONGES];
        }
        let produced = st.sponges[SPONGE_C].digest();
        // the rows after the run carry the forger's sponge states, flags and accumulators (stale carries are what the
        // laws expect between opcodes); the machine resets the countdown at a finish
        for r in last + 1..honest.len() {
            let mut s = honest[r].clone();
            s.sponges = st.sponges;
            s.fb = st.fb;
            s.cph = st.cph;
            s.remaining = 0;
            s.s2acc = st.s2acc;
            out.push(s);
        }
        (out, produced)
    }

    /// A forged trace's statement: the honest run with the returned digest the forger claims.
    fn forged_trace(t: &VmTrace, steps: Vec<Step>, ret_digest: Digest) -> VmTrace {
        VmTrace { steps, run: dsol_vm::VmRun { ret_digest, ..t.run.clone() } }
    }

    /// The honest string landing on every row after `last`: the top slot holds the produced string, which the forger
    /// swaps for the string ITS sponge C produced (same length).
    fn land_forged_string(steps: &mut [Step], last: usize, from: Digest, to: Digest) {
        for s in steps.iter_mut().skip(last + 1) {
            if let dsol_vm::VmVal::Str { digest, len } = s.stack[0] {
                if digest == from {
                    s.stack[0] = dsol_vm::VmVal::Str { digest: to, len };
                }
            }
        }
    }

    fn push_bytes(out: &mut Vec<u8>, s: &[u8]) {
        out.push(op::PUSH_BYTES);
        out.extend_from_slice(&(s.len() as u16).to_le_bytes());
        out.extend_from_slice(s);
    }

    fn program_of(body: &[u8]) -> Vec<u8> {
        let hdr = 5 + 8;
        let mut out = vec![dsol_vm::DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// Does a proof over `table` under the CONSTRAINT-FREE gate verify (is a forgery ARMED)? A prover that refuses the
    /// table IS a refusal — the same reading every pin in this module makes of `prove_postcommit_bus_bytes` returning
    /// nothing.
    fn proves_free(table: &[Vec<Fa4>], rom: &[Vec<Fa4>], stmt: &DsolStatement) -> bool {
        let buses = vec![fetch_bus()];
        match prove_postcommit_bus_bytes(vec![table.to_vec(), rom.to_vec()], gates, &buses, &stmt.bind()) {
            Some(p) => verify_postcommit_bus_bytes(&p, gates, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
            None => false,
        }
    }

    /// Does a proof over `table` under the REAL gate (rebuilt from `stmt` and the ROM, as a verifier would) verify?
    fn proves_real(table: &[Vec<Fa4>], rom: &[Vec<Fa4>], stmt: &DsolStatement) -> bool {
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.to_vec());
        match prove_postcommit_bus_bytes(vec![table.to_vec(), rom.to_vec()], &g, &buses, &stmt.bind()) {
            Some(p) => verify_postcommit_bus_bytes(&p, &g, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
            None => false,
        }
    }

    /// Is the forgery ARMED (verifies under the constraint-free gate) and REFUSED (does not under the real gate)?
    fn armed_and_refused(table: &[Vec<Fa4>], rom: &[Vec<Fa4>], stmt: &DsolStatement) -> (bool, bool) {
        (proves_free(table, rom, stmt), !proves_real(table, rom, stmt))
    }

    /// The honest program proves and verifies under the real gate (the row-level diagnostic names any refusal first).
    fn prove_honest(code: &[u8], t: &VmTrace, what: &str) -> (Vec<Vec<Fa4>>, Vec<Vec<Fa4>>, DsolStatement, usize) {
        let prog = decode_program(code).expect("decodes");
        let stmt = stmt_for(code, b"", t);
        let cpu_rows = t.steps.len().next_power_of_two().max(32);
        let rom_rows = prog.len().next_power_of_two().max(32);
        let honest = build_cpu_trace(t, code, cpu_rows).expect("lays out");
        let rom = build_rom_trace(&prog, rom_rows).expect("lays out");
        let buses = vec![fetch_bus()];
        let g = dsol_gate_for(stmt.clone(), rom.clone());
        if let DsolCpuGate::Cpu(c) = g(0, Ea4::from_u64(0x1234_5678)) {
            if let Some((r, why)) = first_unsatisfied_row(&c, &honest, &t.steps) {
                panic!("⛔ the honest {what} program violates the relation at row {r} ({why}) of {}", t.steps.len());
            }
        }
        let p = prove_postcommit_bus_bytes(vec![honest.clone(), rom.clone()], &g, &buses, &stmt.bind()).unwrap_or_else(|| panic!("the honest {what} program satisfies the CPU relation"));
        assert!(
            verify_postcommit_bus_bytes(&p, &g, &buses, &stmt.bind(), &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).0, &crate::postcommit_bus::declared_postcommit_shapes_for_tests(&p).1),
            "the honest {what} program verifies"
        );
        (honest, rom, stmt, p.len())
    }

    /// ⭐⭐⭐ S2-1 — THE PRODUCE COUNT AND CONCAT'S ORDER, RED FIRST, on real forged TRACES (the forger re-runs the sponges
    /// natively, so no sponge law objects — only the new ones). CONCAT("ab", "cd") returns "abcd" honestly. Refused:
    /// (F1) the INTERLEAVING a, c, b, d — A saw "ab", B saw "cd", every digest law holds, C produced "acbd" — by the phase
    /// law (an A byte after B opened); (F2) a JUNK byte fed to A and C before A opens — A still closes on "ab", C absorbed
    /// five bytes — by the count; (F3) a NINTH byte on U64_TO_BYTES's eight-byte produce — by the count. CALIBRATION:
    /// all three verify under the constraint-free gate, and before this landing the count laws did not exist and the
    /// order law did not exist, so F1–F3 were valid executions of the circuit as it stood.
    #[test]
    fn s2_the_produce_count_and_concat_order_are_enforced() {
        use dsol_vm::{SPONGE_A, SPONGE_B, SPONGE_C};
        let mut body = vec![op::POP];
        push_bytes(&mut body, b"ab");
        push_bytes(&mut body, b"cd");
        body.push(op::CONCAT);
        body.push(op::RETURN);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, b"abcd".to_vec(), "the honest concatenation");
        let (_honest, rom, _stmt, bytes) = prove_honest(&code, &t, "CONCAT");
        let first = t.steps.iter().position(|s| s.op == op::CONCAT).expect("CONCAT runs");
        let last = t.steps.iter().rposition(|s| s.op == op::CONCAT).unwrap();
        let kinds: Vec<u8> = t.steps[first..=last].iter().map(|s| s.micro).collect();
        assert_eq!(kinds, vec![mk::FEED, mk::FEED, mk::PERM, mk::FEED, mk::FEED, mk::PERM, mk::PERM, mk::FINISH], "a, b, close A, c (B opens), d, close B, close C, finish");
        let honest_out = dsol_vm::str_digest(b"abcd");
        let ac = [true, false, true];
        let bc = [false, true, true];
        let none = [None, None, None];
        let cpu_rows = |n: usize| n.next_power_of_two().max(32);
        // F1: interleaved — A and B each see their own bytes in order, C sees a c b d
        let f1 = [
            Sched::Feed { byte: b'a', to: ac, open: [Some(2), None, Some(4)] },
            Sched::Feed { byte: b'c', to: bc, open: [None, Some(2), None] },
            Sched::Feed { byte: b'b', to: ac, open: none },
            Sched::Feed { byte: b'd', to: bc, open: none },
            Sched::Perm { s: SPONGE_A, open: none },
            Sched::Perm { s: SPONGE_B, open: none },
            Sched::Perm { s: SPONGE_C, open: none },
            Sched::Finish,
        ];
        // F2: a junk byte into A and C before A opens; A then closes on "ab" as the slot says, C holds five bytes
        let f2 = [
            Sched::Feed { byte: b'x', to: ac, open: [None, None, Some(4)] },
            Sched::Feed { byte: b'a', to: ac, open: [Some(2), None, None] },
            Sched::Feed { byte: b'b', to: ac, open: none },
            Sched::Perm { s: SPONGE_A, open: none },
            Sched::Feed { byte: b'c', to: bc, open: [None, Some(2), None] },
            Sched::Feed { byte: b'd', to: bc, open: none },
            Sched::Perm { s: SPONGE_B, open: none },
            Sched::Perm { s: SPONGE_C, open: none },
            Sched::Finish,
        ];
        let mut armed = 0usize;
        for (name, sched) in [("interleaved a c b d", &f1[..]), ("junk byte before A opens", &f2[..])] {
            let (mut steps, produced) = forge_run(&t.steps, first, last, sched);
            assert_ne!(produced, honest_out, "the forgery produces another string");
            land_forged_string(&mut steps, last, honest_out, produced);
            let ft = forged_trace(&t, steps, produced);
            let fstmt = stmt_for(&code, b"", &ft);
            let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("the forged trace lays out");
            let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
            armed += usize::from(is_armed);
            assert!(refused, "⛔ S2-1 FORGERY VERIFIED: {name}");
        }
        // F3: U64_TO_BYTES feeds a ninth byte into its eight-byte produce
        let word = 0x0102_0304_0506_0708u64;
        let mut body = vec![op::POP, op::PUSH_U64];
        body.extend_from_slice(&word.to_le_bytes());
        body.push(op::U64_TO_BYTES);
        body.push(op::RETURN);
        let code3 = program_of(&body);
        let t3 = run_it(&code3);
        assert_eq!(t3.run.ret, word.to_le_bytes().to_vec(), "the honest LE bytes");
        let (_, rom3, _, _) = prove_honest(&code3, &t3, "U64_TO_BYTES");
        let first3 = t3.steps.iter().position(|s| s.op == op::U64_TO_BYTES).unwrap();
        let last3 = t3.steps.iter().rposition(|s| s.op == op::U64_TO_BYTES).unwrap();
        assert_eq!(last3 - first3 + 1, 10, "eight feeds, close C, finish");
        let honest3 = dsol_vm::str_digest(&word.to_le_bytes());
        let mut f3: Vec<Sched> = Vec::new();
        for (i, b) in word.to_le_bytes().iter().enumerate() {
            f3.push(Sched::Feed { byte: *b, to: [false, false, true], open: if i == 0 { [None, None, Some(8)] } else { none } });
        }
        // MEASURED 08:48: a ZERO ninth byte lands in an empty lane position and leaves the staged lanes — and so the
        // digest — exactly as the honest eight left them (the string's length lives in the sponge's init state, so a
        // trailing zero only changes a string when its length does); the forgery needs a NON-ZERO byte to be a forgery
        f3.push(Sched::Feed { byte: 0x5a, to: [false, false, true], open: none });
        f3.push(Sched::Perm { s: SPONGE_C, open: none });
        f3.push(Sched::Finish);
        let (mut steps, produced) = forge_run(&t3.steps, first3, last3, &f3);
        assert_ne!(produced, honest3, "nine bytes under an eight-byte opening produce a digest no real string has");
        land_forged_string(&mut steps, last3, honest3, produced);
        let ft = forged_trace(&t3, steps, produced);
        let fstmt = stmt_for(&code3, b"", &ft);
        let table = build_cpu_trace(&ft, &code3, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom3, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-1 FORGERY VERIFIED: a ninth byte on an eight-byte produce");
        assert_eq!(armed, 3, "CALIBRATION: without the CPU relation every count / order forgery verifies");
        eprintln!("[dsol-s2-1] honest CONCAT {bytes} B ({} rows); interleaving, junk and a ninth byte armed without S2-1, all refused with it", t.steps.len());
    }

    /// ⭐⭐⭐ S2-1 — LOCALS ARE BOUND, RED FIRST. ALLOC 2; SET 0 := "hi"; SET 1 := "yo"; GET 0; RETURN returns "hi" honestly.
    /// Refused: (F1) the GET lands "yo" (the landing law); (F2) SET 0 stores "yo" and the GET faithfully lands it (the
    /// write law — the stored value must be the popped top); (F3) local 1 changes between the GET and the RETURN (the
    /// frozen law). CALIBRATION: all three verify under the constraint-free gate — and before this landing the 224
    /// locals columns had one law (row 0 = 0), so every one of them was a valid execution.
    #[test]
    fn s2_locals_are_bound() {
        let mut body = vec![op::POP, op::ALLOC_LOCALS];
        body.extend_from_slice(&2u16.to_le_bytes());
        push_bytes(&mut body, b"hi");
        body.push(op::LOCAL_SET);
        body.extend_from_slice(&0u16.to_le_bytes());
        push_bytes(&mut body, b"yo");
        body.push(op::LOCAL_SET);
        body.extend_from_slice(&1u16.to_le_bytes());
        body.push(op::LOCAL_GET);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.push(op::RETURN);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, b"hi".to_vec(), "the local round-trips");
        let (honest, rom, stmt, bytes) = prove_honest(&code, &t, "locals");
        let yo = dsol_vm::str_digest(b"yo");
        let set0 = t.steps.iter().position(|s| s.op == op::LOCAL_SET).unwrap();
        let get0 = t.steps.iter().position(|s| s.op == op::LOCAL_GET).unwrap();
        let ret = t.steps.iter().position(|s| s.op == op::RETURN).unwrap();
        assert_eq!(ret, get0 + 1, "the GET's landing row is the RETURN row");
        let stmt_yo = DsolStatement { ret_digest: yo, ..stmt.clone() };
        // F1: the GET lands "yo"
        let mut f1 = honest.clone();
        for d in 0..DIGEST_LANES {
            f1[stack_at(0, SLOT_D0 + d)][ret] = f(yo[d]);
        }
        // F2: SET 0 stores "yo" (every row after it) and the GET lands what was stored
        let mut f2 = f1.clone();
        for r in set0 + 1..t.steps.len() {
            for d in 0..DIGEST_LANES {
                f2[local_at(0, SLOT_D0 + d)][r] = f(yo[d]);
            }
        }
        // F3: local 1 drifts on the GET → RETURN transition (no write there)
        let mut f3 = honest.clone();
        f3[local_at(1, SLOT_D0)][ret] += Fa4::ONE;
        let mut armed = 0usize;
        for (name, table, st) in [("GET lands another local", &f1, &stmt_yo), ("SET stores another value", &f2, &stmt_yo), ("a local drifts without a write", &f3, &stmt)] {
            let (is_armed, refused) = armed_and_refused(table, &rom, st);
            armed += usize::from(is_armed);
            assert!(refused, "⛔ S2-1 FORGERY VERIFIED: {name}");
        }
        assert_eq!(armed, 3, "CALIBRATION: without the CPU relation every locals forgery verifies");
        eprintln!("[dsol-s2-1] honest locals program {bytes} B ({} rows); three locals forgeries armed without S2-1, all refused with it", t.steps.len());
    }

    /// A U64_TO_BYTES run's schedule for the eight bytes the forger wants produced (open C with 8, eight feeds, close, finish).
    fn to_bytes_sched(bytes: [u8; 8]) -> Vec<Sched> {
        let mut v: Vec<Sched> = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| Sched::Feed { byte: *b, to: [false, false, true], open: if i == 0 { [None, None, Some(8)] } else { [None, None, None] } })
            .collect();
        v.push(Sched::Perm { s: dsol_vm::SPONGE_C, open: [None, None, None] });
        v.push(Sched::Finish);
        v
    }

    /// A program ending in `U64_TO_BYTES; RETURN`, forged so that the WORD the opcode before TO_BYTES landed is `word`
    /// instead (every row from that landing through TO_BYTES's run), and TO_BYTES then honestly produces `word`'s bytes.
    /// Only the earlier opcode's landing law can object. Returns the forged trace and its statement.
    fn forge_landed_word(code: &[u8], t: &VmTrace, landed_at: usize, word: u64) -> (VmTrace, DsolStatement) {
        let tb_first = t.steps.iter().position(|s| s.op == op::U64_TO_BYTES).expect("TO_BYTES runs");
        let tb_last = t.steps.iter().rposition(|s| s.op == op::U64_TO_BYTES).unwrap();
        let (mut steps, produced) = forge_run(&t.steps, tb_first, tb_last, &to_bytes_sched(word.to_le_bytes()));
        for s in steps.iter_mut().take(tb_last + 1).skip(landed_at + 1) {
            s.stack[0] = dsol_vm::VmVal::Word(word);
        }
        let honest_out = match t.steps[tb_last + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, .. } => digest,
            dsol_vm::VmVal::Word(_) => panic!("TO_BYTES lands a string"),
        };
        land_forged_string(&mut steps, tb_last, honest_out, produced);
        let ft = forged_trace(t, steps, produced);
        let st = stmt_for(code, b"", &ft);
        (ft, st)
    }

    /// ⭐⭐⭐ S2-2 — THE WORD ↔ BYTES CONVERSIONS, BYTES_LEN AND STR_EQ ARE BOUND, RED FIRST, on real forged traces. Five
    /// programs, each honest one proving and verifying; five forgeries, each armed under the constraint-free gate and each
    /// refused by exactly the law it targets: (F1) U64_TO_BYTES feeds a flipped byte (the produced string is not the
    /// word's); (F2) U64_FROM_BYTES lands the word with one bit flipped, and TO_BYTES then faithfully produces THAT word;
    /// (F3) BYTES_LEN lands 6 for "hello"; (F4) STR_EQ("ab", "ab") lands 0; (F5) STR_EQ("ab", "ac") lands 1. Before this
    /// landing every one of the five was a valid execution of the circuit.
    #[test]
    fn s2_word_byte_conversions_length_and_string_equality_are_bound() {
        let word = 0x0102_0304_0506_0708u64;
        let cpu_rows = |n: usize| n.next_power_of_two().max(32);
        let mut armed = 0usize;
        // F1: TO_BYTES produces the word's bytes with byte 3 flipped
        let mut body = vec![op::POP, op::PUSH_U64];
        body.extend_from_slice(&word.to_le_bytes());
        body.extend_from_slice(&[op::U64_TO_BYTES, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, word.to_le_bytes().to_vec());
        let (_, rom, _, bytes1) = prove_honest(&code, &t, "U64_TO_BYTES");
        let tb_first = t.steps.iter().position(|s| s.op == op::U64_TO_BYTES).unwrap();
        let tb_last = t.steps.iter().rposition(|s| s.op == op::U64_TO_BYTES).unwrap();
        let mut flipped = word.to_le_bytes();
        flipped[3] ^= 0x80;
        let (mut steps, produced) = forge_run(&t.steps, tb_first, tb_last, &to_bytes_sched(flipped));
        assert_eq!(produced, dsol_vm::str_digest(&flipped), "the forger produced a real string — just not the word's");
        land_forged_string(&mut steps, tb_last, dsol_vm::str_digest(&word.to_le_bytes()), produced);
        let ft = forged_trace(&t, steps, produced);
        let fstmt = stmt_for(&code, b"", &ft);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-2 FORGERY VERIFIED: TO_BYTES produced another string");
        // F2: FROM_BYTES lands the word with bit 0 flipped; TO_BYTES then produces that word's bytes
        let mut body = vec![op::POP];
        push_bytes(&mut body, b"abcdefgh");
        body.extend_from_slice(&[op::U64_FROM_BYTES, op::U64_TO_BYTES, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, b"abcdefgh".to_vec(), "TO_BYTES ∘ FROM_BYTES is the identity on eight bytes");
        let (_, rom, _, _) = prove_honest(&code, &t, "U64_FROM_BYTES");
        let w = u64::from_le_bytes(*b"abcdefgh");
        let fb_fin = t.steps.iter().rposition(|s| s.op == op::U64_FROM_BYTES).unwrap();
        assert_eq!(t.steps[fb_fin + 1].stack[0], dsol_vm::VmVal::Word(w), "FROM_BYTES landed the LE word");
        let (ft, fstmt) = forge_landed_word(&code, &t, fb_fin, w ^ 1);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-2 FORGERY VERIFIED: FROM_BYTES landed another word");
        // F3: BYTES_LEN lands 6 for "hello"
        let mut body = vec![op::POP];
        push_bytes(&mut body, b"hello");
        body.extend_from_slice(&[op::BYTES_LEN, op::U64_TO_BYTES, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, 5u64.to_le_bytes().to_vec());
        let (_, rom, _, _) = prove_honest(&code, &t, "BYTES_LEN");
        let bl = t.steps.iter().position(|s| s.op == op::BYTES_LEN).unwrap();
        let (ft, fstmt) = forge_landed_word(&code, &t, bl, 6);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-2 FORGERY VERIFIED: BYTES_LEN landed 6 for a five-byte string");
        // F4 / F5: STR_EQ lands the wrong boolean, in both directions
        for (other, honest_eq, name) in [(&b"ab"[..], 1u64, "equal strings landed 0"), (&b"ac"[..], 0u64, "unequal strings landed 1")] {
            let mut body = vec![op::POP];
            push_bytes(&mut body, b"ab");
            push_bytes(&mut body, other);
            body.extend_from_slice(&[op::STR_EQ, op::U64_TO_BYTES, op::RETURN]);
            let code = program_of(&body);
            let t = run_it(&code);
            assert_eq!(t.run.ret, honest_eq.to_le_bytes().to_vec(), "the honest equality");
            let (_, rom, _, _) = prove_honest(&code, &t, "STR_EQ");
            let se = t.steps.iter().position(|s| s.op == op::STR_EQ).unwrap();
            let (ft, fstmt) = forge_landed_word(&code, &t, se, 1 - honest_eq);
            let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
            let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
            armed += usize::from(is_armed);
            assert!(refused, "⛔ S2-2 FORGERY VERIFIED: {name}");
        }
        assert_eq!(armed, 5, "CALIBRATION: without the CPU relation every conversion / length / equality forgery verifies");
        eprintln!("[dsol-s2-2] honest TO_BYTES {bytes1} B; five forgeries (a flipped produced byte, a flipped parsed word, len 6 for 'hello', eq 0 for equal, eq 1 for unequal) armed without S2-2, all refused with it");
    }

    /// ⭐⭐⭐ S2-3 — U64_TO_DEC_STR IS BOUND, RED FIRST: each digit row is one division step of the L4c/d block (P' = 10·P +
    /// digit, REM < 10 IS the digit range), the FINISH pins P to the operand, the first digit is non-zero unless the string
    /// is "0", the string is never empty. Honest: 0 → "0", 7 → "7", 1234567890123, u64::MAX (20 digits) prove and verify.
    /// Refused on real forged traces: (F1) "07" for 7 (a leading zero), (F2) "8" for 7 (the wrong digit), (F3) "" for 0
    /// (the empty string). CALIBRATION: all three verify under the constraint-free gate.
    #[test]
    fn s2_the_decimal_string_of_a_word_is_bound() {
        let cpu_rows = |n: usize| n.next_power_of_two().max(32);
        let program = |w: u64| {
            let mut body = vec![op::POP, op::PUSH_U64];
            body.extend_from_slice(&w.to_le_bytes());
            body.extend_from_slice(&[op::U64_TO_DEC_STR, op::RETURN]);
            program_of(&body)
        };
        for w in [0u64, 7, 1_234_567_890_123, u64::MAX] {
            let code = program(w);
            let t = run_it(&code);
            assert_eq!(t.run.ret, w.to_string().into_bytes(), "the honest decimal");
            let (_, _, _, bytes) = prove_honest(&code, &t, "U64_TO_DEC_STR");
            eprintln!("[dsol-s2-3] {w} → \"{w}\" proves at {bytes} B ({} rows)", t.steps.len());
        }
        // the forger's decimal run: the digit bytes (C opens with their count), the close, the finish
        let dec_sched = |digits: &[u8]| -> Vec<Sched> {
            let none = [None, None, None];
            let mut v: Vec<Sched> = digits
                .iter()
                .enumerate()
                .map(|(i, b)| Sched::Feed { byte: *b, to: [false, false, true], open: if i == 0 { [None, None, Some(digits.len())] } else { none } })
                .collect();
            v.push(Sched::Perm { s: dsol_vm::SPONGE_C, open: if digits.is_empty() { [None, None, Some(0)] } else { none } });
            v.push(Sched::Finish);
            v
        };
        let mut armed = 0usize;
        for (w, digits, name) in [(7u64, &b"07"[..], "a leading zero"), (7, &b"8"[..], "the wrong digit"), (0, &b""[..], "the empty string")] {
            let code = program(w);
            let t = run_it(&code);
            let prog = decode_program(&code).expect("decodes");
            let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
            let first = t.steps.iter().position(|s| s.op == op::U64_TO_DEC_STR).unwrap();
            let last = t.steps.iter().rposition(|s| s.op == op::U64_TO_DEC_STR).unwrap();
            let honest_out = dsol_vm::str_digest(w.to_string().as_bytes());
            let sched = dec_sched(digits);
            let (mut steps, produced) = forge_run(&t.steps, first, last, &sched);
            assert_ne!(produced, honest_out, "the forgery produces another string");
            let plen = digits.len() as u32;
            let flast = first + sched.len() - 1; // the forged run's FINISH row
            for s in steps.iter_mut().take(flast + 1).skip(first) {
                s.plen = plen;
            }
            for s in steps.iter_mut().skip(flast + 1) {
                if let dsol_vm::VmVal::Str { digest, .. } = s.stack[0] {
                    if digest == honest_out {
                        s.stack[0] = dsol_vm::VmVal::Str { digest: produced, len: plen };
                    }
                }
            }
            let ft = forged_trace(&t, steps, produced);
            let fstmt = stmt_for(&code, b"", &ft);
            let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("the forged decimal run lays out");
            let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
            armed += usize::from(is_armed);
            assert!(refused, "⛔ S2-3 FORGERY VERIFIED: {name}");
        }
        assert_eq!(armed, 3, "CALIBRATION: without the CPU relation every decimal forgery verifies");
        eprintln!("[dsol-s2-3] four honest decimals prove; a leading zero, a wrong digit and the empty string armed without S2-3, all refused with it");
    }

    /// `digest_to_bytes` WITHOUT the canonical reduction: the 31-bit packing of whatever lanes it is handed — how a forger
    /// spells the alias `lane + p` (top seven bits all one, low bits lane + 1) of a lane below 2^24 − 1.
    fn pack_lanes_raw(lanes: &[u64; DIGEST_LANES]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (lane, &v) in lanes.iter().enumerate() {
            for bit in 0..31 {
                if (v >> bit) & 1 == 1 {
                    let idx = lane * 31 + bit;
                    out[idx >> 3] |= 1 << (idx & 7);
                }
            }
        }
        out
    }

    /// Forge one digest producer's run: replay the honest schedule with the 32 produced bytes replaced by `bytes`
    /// (the k-th C-feed of the produce becomes bytes[k]); land the produced string; return the trace and its statement.
    fn forge_produced_digest(code: &[u8], t: &VmTrace, o: u8, bytes: [u8; 32]) -> (VmTrace, DsolStatement, Digest) {
        let first = t.steps.iter().position(|s| s.op == o).expect("the producer runs");
        let last = t.steps.iter().rposition(|s| s.op == o).unwrap();
        let mut sched = sched_from(&t.steps, first, last);
        let (replay, _) = forge_run(&t.steps, first, last, &sched);
        assert_eq!(replay.len(), t.steps.len(), "the forger's replay of the honest schedule has the honest length");
        if let Some(i) = replay.iter().zip(&t.steps).position(|(a, b)| a != b) {
            panic!("the forger's replay of the honest schedule diverges from the honest run at row {i} (op 0x{:02x} micro {})", t.steps[i].op, t.steps[i].micro);
        }
        let mut k = 0usize;
        for row in sched.iter_mut() {
            if let Sched::Feed { byte, to, .. } = row {
                if to[dsol_vm::SPONGE_C] {
                    *byte = bytes[k];
                    k += 1;
                }
            }
        }
        assert_eq!(k, 32, "a digest producer feeds exactly 32 bytes into C");
        let (mut steps, produced) = forge_run(&t.steps, first, last, &sched);
        let honest_out = match t.steps[last + 1].stack[0] {
            dsol_vm::VmVal::Str { digest, .. } => digest,
            dsol_vm::VmVal::Word(_) => panic!("a digest producer lands a string"),
        };
        assert_ne!(produced, honest_out, "the forgery produces another string");
        land_forged_string(&mut steps, last, honest_out, produced);
        let ft = forged_trace(t, steps, produced);
        let st = stmt_for(code, b"", &ft);
        (ft, st, produced)
    }

    /// ⭐⭐⭐ S2-4 — THE DIGEST PRODUCERS ENCODE THEIR OWN HASH, CANONICALLY, RED FIRST. POSEIDON("…"), NULLIFIER("secret")
    /// and COMMIT_U64(v, "blind") each return the 32-byte `digest_to_bytes` form of the hash the row computed; honest
    /// programs prove and verify (COMMIT_U64 through its new CMT row). Refused on real forged traces: (F1) POSEIDON's
    /// string with one bit flipped (the lane target); (F2) POSEIDON's string as the p-ALIAS of one lane below 2^24 − 1
    /// — every lane target holds mod p, only the canonicity law objects; (F3) NULLIFIER's returned string flipped (its
    /// chain tag is still the true one — the string a contract gets back was the free part); (F4) COMMIT_U64's string
    /// flipped. And the commitment itself: MEASURED that the OLD one-lane pre-image committed `v` and `v + p` identically
    /// (the class the four-limb pre-image closes), and the new one does not. CALIBRATION: F1–F4 verify under the
    /// constraint-free gate.
    #[test]
    fn s2_digest_producers_encode_their_own_hash_canonically() {
        use crate::poseidon2_compress::{compress, digest_to_bytes, lanes_of};
        use p3_field::PrimeField32;
        let p = u64::from(p3_koala_bear::KoalaBear::ORDER_U32);
        let cpu_rows = |n: usize| n.next_power_of_two().max(32);
        let mut armed = 0usize;
        // the commitment: the old pre-image aliased v and v + p; the new one does not
        let (v, blind) = (123_456_789u64, dsol_vm::str_digest(b"blind"));
        assert_eq!(
            compress(&lanes_of(&[dsol_vm::DOM_COMMIT, v]), &blind),
            compress(&lanes_of(&[dsol_vm::DOM_COMMIT, v + p]), &blind),
            "CALIBRATION: a u64 in one 31-bit lane commits v and v + p identically"
        );
        assert_ne!(dsol_vm::vm_commit(v, &blind), dsol_vm::vm_commit(v + p, &blind), "four exact limbs are binding over the word");
        assert_eq!(dsol_vm::vm_commit(v, &blind), compress(&dsol_vm::commit_preimage_lanes(v), &blind), "one spelling of the pre-image");
        // F1: POSEIDON's string with one bit flipped
        let mut body = vec![op::POP];
        push_bytes(&mut body, b"hello");
        body.extend_from_slice(&[op::POSEIDON, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        let tag = dsol_vm::str_digest(b"hello");
        assert_eq!(t.run.ret, digest_to_bytes(&tag).to_vec(), "POSEIDON returns its digest's canonical bytes");
        let (_, rom, _, bytes1) = prove_honest(&code, &t, "POSEIDON");
        let mut flipped = digest_to_bytes(&tag);
        flipped[5] ^= 0x10;
        let (ft, fstmt, _) = forge_produced_digest(&code, &t, op::POSEIDON, flipped);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-4 FORGERY VERIFIED: POSEIDON produced another string");
        // F2: the p-alias of one lane — search a pre-image whose digest has a lane below 2^24 − 1
        let (alias_src, lane) = (0u32..)
            .map(|i| format!("alias-{i}").into_bytes())
            .find_map(|s| {
                let d = dsol_vm::str_digest(&s);
                d.iter().position(|&l| l < (1 << 24) - 1).map(|lane| (s, lane))
            })
            .expect("one string in a few dozen has a small lane");
        let mut body = vec![op::POP];
        push_bytes(&mut body, &alias_src);
        body.extend_from_slice(&[op::POSEIDON, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        let (_, rom, _, _) = prove_honest(&code, &t, "POSEIDON (alias source)");
        let mut aliased = dsol_vm::str_digest(&alias_src);
        aliased[lane] += p; // the SAME field element, another 31-bit spelling
        let alias_bytes = pack_lanes_raw(&aliased);
        assert_ne!(alias_bytes, digest_to_bytes(&dsol_vm::str_digest(&alias_src)), "the alias is a different byte string");
        let (ft, fstmt, _) = forge_produced_digest(&code, &t, op::POSEIDON, alias_bytes);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-4 FORGERY VERIFIED: the non-canonical alias encoding of a lane");
        // F3: NULLIFIER's returned string flipped (the chain tag, folded in-circuit, is untouched)
        let mut body = vec![op::POP];
        push_bytes(&mut body, b"secret");
        body.extend_from_slice(&[op::NULLIFIER, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        let cid = dsol_vm::str_digest(&dsol_vm::VmCtx::default().contract_id);
        let ntag = dsol_vm::vm_nullifier(&cid, &dsol_vm::str_digest(b"secret"));
        assert_eq!(t.run.ret, digest_to_bytes(&ntag).to_vec(), "NULLIFIER returns its tag's canonical bytes");
        let (_, rom, _, _) = prove_honest(&code, &t, "NULLIFIER");
        let mut flipped = digest_to_bytes(&ntag);
        flipped[17] ^= 0x01;
        let (ft, fstmt, _) = forge_produced_digest(&code, &t, op::NULLIFIER, flipped);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-4 FORGERY VERIFIED: NULLIFIER returned another string");
        // F4: COMMIT_U64's string flipped (its CMT row still computes the true commitment)
        let mut body = vec![op::POP, op::PUSH_U64];
        body.extend_from_slice(&v.to_le_bytes());
        push_bytes(&mut body, b"blind");
        body.extend_from_slice(&[op::COMMIT_U64, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        let cm = dsol_vm::vm_commit(v, &blind);
        assert_eq!(t.run.ret, digest_to_bytes(&cm).to_vec(), "COMMIT_U64 returns its commitment's canonical bytes");
        assert_eq!(t.steps.iter().filter(|s| s.micro == mk::CMT).count(), 1, "one commitment row");
        let (_, rom, _, bytes4) = prove_honest(&code, &t, "COMMIT_U64");
        let mut flipped = digest_to_bytes(&cm);
        flipped[0] ^= 0x80;
        let (ft, fstmt, _) = forge_produced_digest(&code, &t, op::COMMIT_U64, flipped);
        let table = build_cpu_trace(&ft, &code, cpu_rows(ft.steps.len())).expect("lays out");
        let (is_armed, refused) = armed_and_refused(&table, &rom, &fstmt);
        armed += usize::from(is_armed);
        assert!(refused, "⛔ S2-4 FORGERY VERIFIED: COMMIT_U64 returned another string");
        assert_eq!(armed, 4, "CALIBRATION: without the CPU relation every digest-producer forgery verifies");
        eprintln!("[dsol-s2-4] POSEIDON {bytes1} B, COMMIT_U64 {bytes4} B (one CMT row); a flipped hash string, the p-alias encoding, a flipped nullifier string and a flipped commitment string armed without S2-4, all refused with it; vm_commit binding over v and v + p");
    }

    /// A program ending in a WORD `RETURN`, forged so that the word an earlier opcode landed (`honest`, first seen after
    /// row `landed_at`) reads `word` on every later row where it sits, and the RETURN then faithfully produces `word`'s
    /// bytes — only the earlier opcode's landing law can object. Operands are chosen so `honest` is unique on the stack.
    fn forge_landed_word_return(code: &[u8], t: &VmTrace, landed_at: usize, honest: u64, word: u64) -> (VmTrace, DsolStatement) {
        assert_ne!(honest, word);
        let ret_first = t.steps.iter().position(|s| s.op == op::RETURN).expect("the RETURN runs");
        let ret_last = t.steps.len() - 1;
        assert_eq!(t.steps[ret_last].micro, mk::FINISH, "a word RETURN ends on its FINISH row");
        let (mut steps, produced) = forge_run(&t.steps, ret_first, ret_last, &to_bytes_sched(word.to_le_bytes()));
        let mut hits = 0usize;
        for s in steps.iter_mut().skip(landed_at + 1) {
            for k in 0..4 {
                if s.stack[k] == dsol_vm::VmVal::Word(honest) {
                    s.stack[k] = dsol_vm::VmVal::Word(word);
                    hits += 1;
                }
            }
        }
        assert!(hits > 0, "the landed word appears after its landing");
        let ft = forged_trace(t, steps, produced);
        let st = stmt_for(code, b"", &ft);
        (ft, st)
    }

    /// ⭐⭐⭐ WIDE ARITHMETIC — THE FOUR WORD PRIMITIVES ARE BOUND, RED FIRST (plan item 4; spec in the plan doc). MUL_HI
    /// lands the product's upper word; ADC / SBB land sum / difference below the carry / borrow out, with the carry in read
    /// from the top; DIVMOD128 lands the quotient below the remainder of a 128-bit dividend, refusing a quotient that does
    /// not fit a word; and `mulDiv(a, b, c) = DIVMOD128(MUL_HI, MUL, c)` equals the native u128 computation. Refused on
    /// real forged traces: (F1) MUL_HI lands the LOW word; (F2) ADC's carry out flipped; (F3) ADC's sum off by one; (F4)
    /// SBB's borrow flipped; (F5) DIVMOD128's quotient + 1 — and the block itself has NO assignment for q + 1 (the chain
    /// refuses to lay) nor for hi ≥ d (the machine refuses by name). CALIBRATION: F1–F5 verify under the constraint-free gate.
    #[test]
    fn wide_word_primitives_mul_hi_adc_sbb_divmod128_are_bound() {
        let cpu_rows = |n: usize| n.next_power_of_two().max(32);
        let push = |body: &mut Vec<u8>, w: u64| {
            body.push(op::PUSH_U64);
            body.extend_from_slice(&w.to_le_bytes());
        };
        let mut armed = 0usize;
        let mut refuse = |code: &[u8], t: &VmTrace, landed_at: usize, honest: u64, word: u64, rom: &[Vec<Fa4>], name: &str| {
            let (ft, fstmt) = forge_landed_word_return(code, t, landed_at, honest, word);
            let table = build_cpu_trace(&ft, code, cpu_rows(ft.steps.len())).expect("the forged trace lays out");
            let (is_armed, refused) = armed_and_refused(&table, rom, &fstmt);
            armed += usize::from(is_armed);
            assert!(refused, "⛔ WIDE FORGERY VERIFIED: {name}");
        };
        // MUL_HI
        let (a, b) = (0xFFFF_FFFF_0000_0001u64, 0x1234_5678_9ABC_DEF0u64);
        let prod = u128::from(a) * u128::from(b);
        let (hi, lo) = ((prod >> 64) as u64, prod as u64);
        let mut body = vec![op::POP];
        push(&mut body, a);
        push(&mut body, b);
        body.extend_from_slice(&[op::MUL_HI, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, hi.to_le_bytes().to_vec(), "MUL_HI is the upper word of the 128-bit product");
        let (_, rom, _, bytes) = prove_honest(&code, &t, "MUL_HI");
        let row = t.steps.iter().position(|s| s.op == op::MUL_HI).unwrap();
        refuse(&code, &t, row, hi, lo, &rom, "MUL_HI landed the low word");
        // ADC: carry out (top) and sum (below)
        let (x, y) = (u64::MAX - 5, 7u64); // x + y + 1 = 2^64 + 2: the sum is 2 with a carry out
        for (drop_carry, honest, other, name) in [(false, 1u64, 0u64, "ADC's carry out flipped"), (true, 2u64, 3u64, "ADC's sum off by one")] {
            let mut body = vec![op::POP];
            push(&mut body, x);
            push(&mut body, y);
            push(&mut body, 1);
            body.push(op::ADC);
            if drop_carry {
                body.push(op::POP);
            }
            body.push(op::RETURN);
            let code = program_of(&body);
            let t = run_it(&code);
            assert_eq!(t.run.ret, honest.to_le_bytes().to_vec(), "ADC's {name}");
            let (_, rom, _, _) = prove_honest(&code, &t, "ADC");
            let row = t.steps.iter().position(|s| s.op == op::ADC).unwrap();
            refuse(&code, &t, row, honest, other, &rom, name);
        }
        // SBB: 0 − 1 − 0 borrows
        let mut body = vec![op::POP];
        push(&mut body, 0);
        push(&mut body, 1);
        push(&mut body, 0);
        body.extend_from_slice(&[op::SBB, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, 1u64.to_le_bytes().to_vec(), "SBB borrows out");
        assert_eq!(t.steps[t.steps.iter().position(|s| s.op == op::SBB).unwrap() + 1].stack[1], dsol_vm::VmVal::Word(u64::MAX), "the difference wraps below the borrow");
        let (_, rom, _, _) = prove_honest(&code, &t, "SBB");
        let row = t.steps.iter().position(|s| s.op == op::SBB).unwrap();
        refuse(&code, &t, row, 1, 0, &rom, "SBB's borrow out flipped");
        // DIVMOD128: (5·2^64 + 7) / 13
        let (dhi, dlo, d) = (5u64, 7u64, 13u64);
        let n = (u128::from(dhi) << 64) | u128::from(dlo);
        let (q, r) = ((n / 13) as u64, (n % 13) as u64);
        let mut body = vec![op::POP];
        push(&mut body, dhi);
        push(&mut body, dlo);
        push(&mut body, d);
        body.extend_from_slice(&[op::DIVMOD128, op::POP, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, q.to_le_bytes().to_vec(), "DIVMOD128's quotient");
        let dm = t.steps.iter().position(|s| s.op == op::DIVMOD128).unwrap();
        assert_eq!(t.steps[dm + 1].stack[0], dsol_vm::VmVal::Word(r), "the remainder lands on top");
        let (_, rom, _, _) = prove_honest(&code, &t, "DIVMOD128");
        refuse(&code, &t, dm, q, q + 1, &rom, "DIVMOD128's quotient + 1");
        // the identity itself has no assignment for q + 1: the chain refuses to lay
        let mut scratch = vec![Fa4::ZERO; CPU_COLS];
        assert!(lay_muldiv(&mut scratch, op::DIVMOD128, n, d, q).is_some(), "the honest quotient lays");
        assert!(lay_muldiv(&mut scratch, op::DIVMOD128, n, d, q + 1).is_none(), "q + 1 satisfies no A = X·B + REM chain");
        // hi ≥ d: the quotient would not fit a word — the machine refuses by name (checked semantics)
        let mut body = vec![op::POP];
        push(&mut body, 13);
        push(&mut body, dlo);
        push(&mut body, d);
        body.extend_from_slice(&[op::DIVMOD128, op::POP, op::RETURN]);
        let over = dsol_vm::run(&program_of(&body), "main", b"", dsol_vm::VmCtx::default(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost);
        assert!(matches!(over, Err(dsol_vm::VmError::Overflow(_))), "hi ≥ d is a checked overflow: {over:?}");
        // mulDiv(a, b, c) = DIVMOD128(MUL_HI(a, b), MUL(a, b), c).q — the AMM primitive, exact
        let c = 0xFFFF_FFFF_FFFF_FFF0u64; // c > hi(a·b), so the quotient fits a word (a·b ≈ 2^124, c ≈ 2^64 ⇒ q ≈ 2^60)
        let expect = (prod / u128::from(c)) as u64;
        assert!(prod / u128::from(c) < 1 << 64 && hi < c, "the quotient fits a word for these operands");
        let mut body = vec![op::POP, op::ALLOC_LOCALS];
        body.extend_from_slice(&2u16.to_le_bytes());
        push(&mut body, a);
        body.push(op::LOCAL_SET);
        body.extend_from_slice(&0u16.to_le_bytes());
        push(&mut body, b);
        body.push(op::LOCAL_SET);
        body.extend_from_slice(&1u16.to_le_bytes());
        for _ in 0..2 {
            body.push(op::LOCAL_GET);
            body.extend_from_slice(&0u16.to_le_bytes());
            body.push(op::LOCAL_GET);
            body.extend_from_slice(&1u16.to_le_bytes());
            body.push(if body.iter().filter(|&&o| o == op::LOCAL_GET).count() == 2 { op::MUL_HI } else { op::MUL_U64 });
        }
        push(&mut body, c);
        body.extend_from_slice(&[op::DIVMOD128, op::POP, op::RETURN]);
        let code = program_of(&body);
        let t = run_it(&code);
        assert_eq!(t.run.ret, expect.to_le_bytes().to_vec(), "mulDiv over four rows equals the native u128 computation");
        let (_, _, _, bytes5) = prove_honest(&code, &t, "mulDiv");
        assert_eq!(armed, 5, "CALIBRATION: without the CPU relation every wide-primitive forgery verifies");
        eprintln!("[dsol-wide] MUL_HI {bytes} B, mulDiv {bytes5} B ({} rows); five forgeries armed without the laws, all refused with them; q + 1 and hi ≥ d have no assignment", t.steps.len());
    }

    /// The keeper's host: answers the book-price syscall (`sys_op` 1, argv "px") with one fixed price and nothing else —
    /// what the node's host does from its own book at apply, where it re-runs the call and compares.
    struct PriceHost(u64);
    impl dsol_vm::SyscallHost for PriceHost {
        fn call(&mut self, sys_op: u16, argv: &[u8]) -> Option<Vec<u8>> {
            (sys_op == 1 && argv == b"px").then(|| self.0.to_le_bytes().to_vec())
        }
    }

    /// ⭐ THE FLAGSHIP'S PREDICATE AS BYTECODE — a stop-loss whose trigger is HIDDEN: argv = trigger (8 LE bytes) ‖ nonce,
    /// and storage "order" holds `COMMIT_U64(trigger, argv)`. The program opens the commitment (a wrong trigger or nonce
    /// REVERTs — no proof exists), reads the PUBLIC book price through a syscall the node re-runs, and EMITs a "stop-fill"
    /// event carrying the commitment iff price ≤ trigger; returns 1 (fired) or 0. Stack depth 3, one local.
    fn conditional_order_program() -> Vec<u8> {
        let mut b: Vec<u8> = Vec::new();
        let imm16 = |b: &mut Vec<u8>, o: u8, k: u16| {
            b.push(o);
            b.extend_from_slice(&k.to_le_bytes());
        };
        imm16(&mut b, op::ALLOC_LOCALS, 1); //                     [argv]
        b.push(op::DUP); //                                         [argv, argv]
        b.push(op::U64_FROM_BYTES); //                              [argv, trigger]
        imm16(&mut b, op::LOCAL_SET, 0); //                         [argv]            local0 = trigger
        imm16(&mut b, op::LOCAL_GET, 0); //                         [argv, trigger]
        b.push(op::SWAP); //                                        [trigger, argv]
        b.push(op::COMMIT_U64); //                                  [cm]              blind = argv (its nonce hides)
        b.push(op::DUP); //                                         [cm, cm]
        push_bytes(&mut b, b"order"); //                            [cm, cm, "order"]
        b.push(op::SLOAD); //                                       [cm, cm, stored]
        b.push(op::STR_EQ); //                                      [cm, eq]
        b.push(op::NOT); //                                         [cm, neq]
        let j_revert = b.len();
        b.push(op::JUMPI); //                                       [cm]              → L_revert on a mismatch
        b.extend_from_slice(&[0u8; 4]);
        push_bytes(&mut b, b"px"); //                               [cm, "px"]
        imm16(&mut b, op::SYSCALL, 1); //                           [cm, price bytes]
        b.push(op::U64_FROM_BYTES); //                              [cm, price]
        imm16(&mut b, op::LOCAL_GET, 0); //                         [cm, price, trigger]
        b.push(op::SWAP); //                                        [cm, trigger, price]
        b.push(op::LT); //                                          [cm, trigger < price]
        let j_nofire = b.len();
        b.push(op::JUMPI); //                                       [cm]              → L_nofire when the price is above
        b.extend_from_slice(&[0u8; 4]);
        push_bytes(&mut b, b"stop-fill"); //                        [cm, topic]
        b.push(op::SWAP); //                                        [topic, cm]
        b.push(op::EMIT); //                                        []                data = cm, topic = "stop-fill"
        b.push(op::PUSH_U64);
        b.extend_from_slice(&1u64.to_le_bytes()); //                [1]
        b.push(op::RETURN);
        let l_nofire = b.len();
        b.push(op::POP); //                                         []
        b.push(op::PUSH_U64);
        b.extend_from_slice(&0u64.to_le_bytes()); //                [0]
        b.push(op::RETURN);
        let l_revert = b.len();
        b.push(op::REVERT);
        let hdr = 13u32; // the v2 header the entry pc counts from
        b[j_revert + 1..j_revert + 5].copy_from_slice(&(hdr + l_revert as u32).to_le_bytes());
        b[j_nofire + 1..j_nofire + 5].copy_from_slice(&(hdr + l_nofire as u32).to_le_bytes());
        program_of(&b)
    }

    /// ⭐⭐⭐ INVISIBLE ORDERS, THE DECIDER HALF, END TO END — the zk-VM's arrival check on a real contract. A hidden stop-loss
    /// fires at price ≤ trigger and not above (the boundary is measured at trigger, trigger − 1000, trigger + 1); a keeper
    /// guessing the trigger or the nonce cannot open the commitment (REVERT: no proof exists); the fired and the quiet
    /// executions PROVE and VERIFY through the production entry points; the public statement and the proof bytes carry
    /// neither the trigger nor the nonce (the statement is digests + the outcome); and the keeper's lie — the syscall said
    /// price = trigger + 1 but the parsed word reads trigger − 1 — is armed under the constraint-free gate and refused by
    /// the relation. What this pin does NOT claim: the node's door (verify instead of re-execute, authorise the fill to the
    /// owner's own note, re-run the price syscall) — that is the node lane's half of the flagship.
    #[test]
    fn a_conditional_order_predicate_fires_exactly_at_its_hidden_trigger() {
        use crate::poseidon2_compress::digest_to_bytes;
        let code = conditional_order_program();
        let trigger = 1_234_567u64;
        let nonce = *b"0123456789abcdef";
        let mut argv = trigger.to_le_bytes().to_vec();
        argv.extend_from_slice(&nonce);
        let cm = dsol_vm::vm_commit(trigger, &dsol_vm::str_digest(&argv));
        let cm_bytes = digest_to_bytes(&cm);
        let mut trie = dsol_vm::StorageTrie::default();
        trie.insert_checked(&dsol_vm::str_digest(b"order"), dsol_vm::VmVal::Str { digest: dsol_vm::str_digest(&cm_bytes), len: 32 }).expect("the order slot");
        let ctx = dsol_vm::VmCtx::default();
        let run = |price: u64, argv: &[u8]| dsol_vm::run(&code, "main", argv, ctx.clone(), trie.clone(), 1 << 16, &mut PriceHost(price));
        let fill_topic = dsol_vm::str_digest(b"stop-fill");
        for (price, fires) in [(trigger, true), (trigger - 1000, true), (trigger + 1, false)] {
            let t = run(price, &argv).expect("the predicate runs");
            assert_eq!(t.run.ret, u64::from(fires).to_le_bytes().to_vec(), "price {price}: fired = {fires}");
            let fill = t.run.effects.iter().any(|e| matches!(e, dsol_vm::Effect::Event { topic, .. } if *topic == fill_topic));
            assert_eq!(fill, fires, "the stop-fill event is emitted exactly when the order fires (price {price})");
        }
        let mut wrong_nonce = argv.clone();
        wrong_nonce[8] ^= 1;
        assert!(matches!(run(trigger - 1, &wrong_nonce), Err(dsol_vm::VmError::Revert)), "a wrong nonce cannot open the commitment");
        let mut wrong_trigger = (trigger + 1).to_le_bytes().to_vec();
        wrong_trigger.extend_from_slice(&nonce);
        assert!(matches!(run(trigger + 2, &wrong_trigger), Err(dsol_vm::VmError::Revert)), "a wrong trigger cannot open the commitment");
        // the row-level diagnostic on the honest firing trace BEFORE anything is proven: a refusal names its law by line
        {
            let t0 = run(trigger, &argv).expect("the predicate runs");
            let prog = decode_program(&code).expect("decodes");
            let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
            let st = statement_of(&code, "main", &argv, trie.root(), &ctx, &t0).expect("derives");
            let table = build_cpu_trace(&t0, &code, t0.steps.len().next_power_of_two().max(32)).expect("lays out");
            if let DsolCpuGate::Cpu(c) = dsol_gate_for(st, rom)(0, Ea4::from_u64(0x1234_5678)) {
                if let Some((r, why)) = first_unsatisfied_row(&c, &table, &t0.steps) {
                    panic!("⛔ the honest predicate trace violates the relation at row {r} ({why}) of {}", t0.steps.len());
                }
            }
        }
        // the production entry points, both outcomes
        let window_free = |hay: &[u8], needle: &[u8]| !hay.windows(needle.len()).any(|w| w == needle);
        let mut sizes = Vec::new();
        for (price, fires) in [(trigger, true), (trigger + 1, false)] {
            let (proof, stmt) = prove_dsol_call(&code, "main", &argv, ctx.clone(), trie.clone(), 1 << 16, &mut PriceHost(price)).expect("the predicate proves");
            assert!(verify_dsol_call(&proof, &code, &stmt), "the trigger proof verifies (price {price})");
            assert_eq!(stmt.ret_digest, dsol_vm::str_digest(&u64::from(fires).to_le_bytes()), "the statement names the outcome");
            let public: Vec<u8> = [&stmt.argv_digest, &stmt.storage_pre, &stmt.storage_post, &stmt.effects_digest, &stmt.ret_digest, &stmt.cid, &stmt.caller, &stmt.subaddress, &stmt.tx_hash]
                .iter()
                .flat_map(|d| digest_to_bytes(d))
                .collect();
            assert!(window_free(&public, &trigger.to_le_bytes()) && window_free(&public, &nonce), "the statement is digests and the outcome — no trigger, no nonce");
            assert!(window_free(&proof.bytes, &trigger.to_le_bytes()) && window_free(&proof.bytes, &nonce), "the proof bytes carry no trigger and no nonce");
            sizes.push(proof.bytes.len());
        }
        // the keeper's lie: the syscall answered trigger + 1 (no fire) and the parsed price word is patched to trigger − 1
        let t = run(trigger + 1, &argv).expect("runs");
        let prog = decode_program(&code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let stmt = statement_of(&code, "main", &argv, trie.root(), &ctx, &t).expect("the statement derives");
        let honest = build_cpu_trace(&t, &code, t.steps.len().next_power_of_two().max(32)).expect("lays out");
        let fb_fins: Vec<usize> = t.steps.iter().enumerate().filter(|(_, s)| s.op == op::U64_FROM_BYTES && s.micro == mk::FINISH).map(|(i, _)| i).collect();
        assert_eq!(fb_fins.len(), 2, "two parses: the trigger from argv, the price from the syscall");
        let land = fb_fins[1] + 1;
        assert_eq!(t.steps[land].stack[0], dsol_vm::VmVal::Word(trigger + 1), "the parsed price lands on top");
        let lt_row = t.steps.iter().position(|s| s.op == op::LT).expect("the compare runs");
        let lie = trigger - 1;
        let mut forged = honest.clone();
        for r in land..=lt_row {
            for k in 0..3 {
                if t.steps[r].stack[k] == dsol_vm::VmVal::Word(trigger + 1) {
                    for l in 0..W_LIMBS {
                        forged[stack_at(k, SLOT_W0 + l)][r] = f((lie >> (W_BITS * l)) & ((1 << W_BITS) - 1));
                    }
                }
            }
        }
        let (is_armed, refused) = armed_and_refused(&forged, &rom, &stmt);
        assert!(is_armed, "CALIBRATION: under the constraint-free gate the keeper's parsed-price lie verifies");
        assert!(refused, "⛔ THE KEEPER'S LIE VERIFIED: a parsed price below the syscall's answer");
        eprintln!(
            "[dsol-conditional] hidden stop-loss: fires at price ≤ {trigger} (boundary measured), reverts on a wrong trigger / nonce; fired proof {} B, quiet proof {} B ({} rows); statement + proof carry no trigger and no nonce; the keeper's parsed-price lie armed without the relation, refused with it",
            sizes[0], sizes[1], t.steps.len()
        );
    }

    // ───────────────────────── SYNC CROSS-CONTRACT CALLS (plan item 2): the chain host, programs and pins ─────────────────────────
    //
    // TWO-PARTY-REVIEWED: the boundary this capability crosses is PROVER → VERIFYING NODE. The prover side here is
    // `ChainHost` (it runs and proves the callees, as a wallet would before shipping a chain); the verifying side is
    // `authorize_call_chain`, the node's rule, fed ONLY what crosses the wire — proof bytes, statements and effect lists —
    // and the code registry both sides hold. The two share no state, so a prover that lies (a swapped callee, a stranger
    // as caller, a re-entering callee) is caught by the other side, which is what each refusal below measures. The
    // two-PROCESS arrival check (a real node's DSOL door verifying a chain a real wallet shipped) is the node lane's half.

    type Registry = std::collections::HashMap<[u8; 32], Vec<u8>>;
    /// Upgrade pointers: a 32-byte pointer NAME → the code id it names now (the node's governance table, in miniature).
    type Pointers = std::collections::HashMap<[u8; 32], [u8; 32]>;

    /// The PROVER's chain host: asked for a callee, it proves that callee itself (recursively, with a fresh host that
    /// knows the same registry and names THIS contract as the caller), keeps every proof it produced, and answers with the
    /// callee's returned bytes and the digests its statement carries — what a wallet does before it ships a chain. It also
    /// answers the DEPLOY syscall (blake3 the shipped code, register it, return the id) and resolves upgrade pointers.
    struct ChainHost {
        codes: Registry,
        pointers: Pointers,
        /// The calling contract's id — a plain callee's `caller_wallet`, and the identity a LIBRARY runs under.
        me: [u8; 32],
        /// This contract's own caller — what a library it calls sees as `caller_wallet` (msg.sender preserved).
        my_caller: [u8; 32],
        collected: Vec<(DsolCallProof, DsolStatement, Vec<dsol_vm::Effect>)>,
        /// F3: name a stranger as the callee's caller.
        foreign_caller: bool,
        /// A library proven under another identity (the node's matcher refuses).
        lib_wrong_cid: bool,
        /// A library run against another trie than the caller's (the machine refuses).
        lib_wrong_trie: bool,
    }
    impl ChainHost {
        fn new(codes: Registry, me: [u8; 32]) -> Self {
            ChainHost { codes, pointers: Pointers::new(), me, my_caller: dsol_vm::VmCtx::default().caller_wallet, collected: Vec::new(), foreign_caller: false, lib_wrong_cid: false, lib_wrong_trie: false }
        }
    }
    impl dsol_vm::SyscallHost for ChainHost {
        fn call(&mut self, sys_op: u16, argv: &[u8]) -> Option<Vec<u8>> {
            if sys_op != dsol_vm::SYS_DEPLOY {
                return None;
            }
            // DEPLOY IS A SYSCALL: the child is registered under blake3(code) and the id is the answer the effect binds
            let id = code_id_of(argv);
            self.codes.insert(id, argv.to_vec());
            Some(id.to_vec())
        }
        fn call_contract(&mut self, named: [u8; 32], entry_sel: u32, argv: &[u8]) -> Option<dsol_vm::CallAnswer> {
            // a pointer name resolves to the code id it names now; a raw code id is itself
            let code_id = match self.pointers.get(&named) {
                Some(id) => *id,
                None => named,
            };
            let code = self.codes.get(&code_id)?.clone();
            if entry_sel != dsol_vm::entry_hash(b"main") {
                return None;
            }
            let ctx = dsol_vm::VmCtx { contract_id: code_id, caller_wallet: if self.foreign_caller { [7u8; 32] } else { self.me }, ..dsol_vm::VmCtx::default() };
            let mut nested = ChainHost { my_caller: self.me, me: code_id, foreign_caller: self.foreign_caller, ..ChainHost::new(self.codes.clone(), code_id) };
            nested.pointers = self.pointers.clone();
            let (proof, stmt, run) = prove_dsol_call_run(&code, "main", argv, ctx, dsol_vm::StorageTrie::default(), 1 << 16, &mut nested, None)?;
            let answer = dsol_vm::CallAnswer { ret: run.ret.clone(), storage_pre: stmt.storage_pre, storage_post: stmt.storage_post, effects_digest: stmt.effects_digest };
            self.collected.push((proof, stmt, run.effects));
            self.collected.append(&mut nested.collected);
            Some(answer)
        }
        fn call_library(&mut self, code_id: [u8; 32], entry_sel: u32, argv: &[u8], storage: dsol_vm::StorageTrie) -> Option<(dsol_vm::CallAnswer, dsol_vm::StorageTrie)> {
            let code = self.codes.get(&code_id)?.clone();
            if entry_sel != dsol_vm::entry_hash(b"main") {
                return None;
            }
            // the library runs under THIS contract's identity, against ITS storage, and sees this contract's caller
            let cid = if self.lib_wrong_cid { [9u8; 32] } else { self.me };
            let ctx = dsol_vm::VmCtx { contract_id: cid, caller_wallet: self.my_caller, ..dsol_vm::VmCtx::default() };
            let mut trie = storage;
            if self.lib_wrong_trie {
                trie.insert_checked(&dsol_vm::str_digest(b"not-the-callers-slot"), dsol_vm::VmVal::Word(1)).expect("the stray slot inserts");
            }
            let mut nested = ChainHost { my_caller: self.my_caller, ..ChainHost::new(self.codes.clone(), self.me) };
            nested.pointers = self.pointers.clone();
            let (proof, stmt, run) = prove_dsol_call_run(&code, "main", argv, ctx, trie, 1 << 16, &mut nested, None)?;
            let answer = dsol_vm::CallAnswer { ret: run.ret.clone(), storage_pre: stmt.storage_pre, storage_post: stmt.storage_post, effects_digest: stmt.effects_digest };
            self.collected.push((proof, stmt, run.effects));
            self.collected.append(&mut nested.collected);
            Some((answer, run.storage))
        }
    }

    fn code_id_of(code: &[u8]) -> [u8; 32] {
        *blake3::hash(code).as_bytes()
    }
    /// The collected callee proofs as the node's chain links.
    fn as_links<'a>(v: &'a [(DsolCallProof, DsolStatement, Vec<dsol_vm::Effect>)]) -> Vec<ProvenCall<'a>> {
        v.iter().map(|(p, s, e)| ProvenCall { proof: p, stmt: s, effects: e }).collect()
    }
    fn ctx_for(code: &[u8]) -> dsol_vm::VmCtx {
        dsol_vm::VmCtx { contract_id: code_id_of(code), ..dsol_vm::VmCtx::default() }
    }
    /// `argv ‖ suffix` — the leaf of a chain.
    fn leaf_program(suffix: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        push_bytes(&mut b, suffix);
        b.extend_from_slice(&[op::CONCAT, op::RETURN]);
        program_of(&b)
    }
    /// `CALL callee(argv) ‖ suffix` — one link of a chain.
    fn caller_program(callee: [u8; 32], suffix: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        push_bytes(&mut b, &callee); //                       [argv, callee]
        b.push(op::SWAP); //                                   [callee, argv]
        b.push(op::CALL);
        b.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes()); // [ret]
        push_bytes(&mut b, suffix);
        b.extend_from_slice(&[op::CONCAT, op::RETURN]);
        program_of(&b)
    }

    /// ⭐⭐⭐ SYNC CROSS-CONTRACT CALLS, RED FIRST (plan item 2's bar: a 3-deep chain with return values proves and
    /// verifies; a re-entrancy attempt is refused). A → B → C with `x` returns "x-c-b-a": every link's proof verifies,
    /// every `Call` effect matches its callee's statement, and `authorize_call_chain` accepts the three. Refused: (F1) the
    /// middle callee swapped for another contract's proof; (F2) a callee dropped, and an orphan callee added; (F3) the
    /// callees proven with a stranger as their caller; (F4) RE-ENTRY — a root R whose callee S calls R back through a
    /// DYNAMIC code id (its argv; a static one is a hash cycle): every proof is sound and every effect matches, and the
    /// chain is refused because R is on its own call path; (F5) a trace forgery on the CALL's binding stage input, armed
    /// under the constraint-free gate and refused by the fold's source law.
    #[test]
    fn sync_cross_contract_calls_chain_and_refuse_reentry() {
        let c_code = leaf_program(b"-c");
        let b_code = caller_program(code_id_of(&c_code), b"-b");
        let a_code = caller_program(code_id_of(&b_code), b"-a");
        let mut codes: Registry = Registry::new();
        for c in [&a_code, &b_code, &c_code] {
            codes.insert(code_id_of(c), c.clone());
        }
        let code_of = |id: &[u8; 32]| codes.get(id).cloned();
        let prove_chain = |code: &[u8], argv: &[u8], foreign: bool| {
            let mut host = ChainHost { foreign_caller: foreign, ..ChainHost::new(codes.clone(), code_id_of(code)) };
            let (proof, stmt, run) = prove_dsol_call_run(code, "main", argv, ctx_for(code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host, None).expect("the chain proves");
            (proof, stmt, run, host.collected)
        };
        let (proof_a, stmt_a, run_a, callees) = prove_chain(&a_code, b"x", false);
        assert_eq!(run_a.ret, b"x-c-b-a".to_vec(), "three return values travelled back up the chain");
        assert_eq!(callees.len(), 2, "B and C were proven on the way");
        let root = ProvenCall { proof: &proof_a, stmt: &stmt_a, effects: &run_a.effects };
        assert!(authorize_call_chain(&root, &as_links(&callees), &code_of, &no_pointers), "the honest 3-deep chain is authorised");
        assert!(run_a.effects.iter().any(|e| matches!(e, dsol_vm::Effect::Call { .. })), "A issued a call");
        // F1: the middle callee swapped for another contract's proof (C run standalone on B's argument)
        let (pc, sc, rc, _) = prove_chain(&c_code, b"x", false);
        let mut swapped: Vec<(DsolCallProof, DsolStatement, Vec<dsol_vm::Effect>)> = callees.iter().map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        let b_idx = swapped.iter().position(|(_, s, _)| s.code_id == code_id_of(&b_code)).expect("B is among the callees");
        swapped[b_idx] = (pc, sc, rc.effects);
        assert!(!authorize_call_chain(&root, &as_links(&swapped), &code_of, &no_pointers), "⛔ a swapped callee was authorised");
        // F2: a callee dropped; an orphan callee added
        let dropped: Vec<_> = callees.iter().filter(|(_, s, _)| s.code_id != code_id_of(&c_code)).map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        assert!(!authorize_call_chain(&root, &as_links(&dropped), &code_of, &no_pointers), "⛔ a chain missing a callee was authorised");
        let mut orphan: Vec<_> = callees.iter().map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        orphan.push(orphan[0].clone());
        assert!(!authorize_call_chain(&root, &as_links(&orphan), &code_of, &no_pointers), "⛔ a chain with an orphan callee proof was authorised");
        // F3: the callees proven with a stranger as their caller
        let (proof_f, stmt_f, run_f, callees_f) = prove_chain(&a_code, b"x", true);
        assert_eq!(run_f.ret, b"x-c-b-a".to_vec(), "the machine does not check callers — the node does");
        let root_f = ProvenCall { proof: &proof_f, stmt: &stmt_f, effects: &run_f.effects };
        assert!(!authorize_call_chain(&root_f, &as_links(&callees_f), &code_of, &no_pointers), "⛔ callees naming a stranger as caller were authorised");
        // F4: RE-ENTRY through a dynamic code id. R("go") calls S with R's own id (CONTRACT_ID); S calls that id with
        // "leaf"; R("leaf") returns without calling. Every proof is sound, every effect matches — and R is on its own path.
        let s_code = {
            let mut b = Vec::new();
            push_bytes(&mut b, b"leaf"); //                          [callee = argv, "leaf"]
            b.push(op::CALL);
            b.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes());
            b.push(op::RETURN);
            program_of(&b)
        };
        let r_code = {
            let mut b = Vec::new();
            b.push(op::DUP); //                                      [argv, argv]
            push_bytes(&mut b, b"leaf"); //                          [argv, argv, "leaf"]
            b.extend_from_slice(&[op::STR_EQ, op::NOT]); //          [argv, not-leaf]
            let j = b.len();
            b.push(op::JUMPI);
            b.extend_from_slice(&[0u8; 4]); //                       [argv]     → L_call when not the leaf
            b.push(op::RETURN); //                                   the leaf: return argv
            let l_call = b.len();
            push_bytes(&mut b, &code_id_of(&s_code)); //             [argv, S]
            b.push(op::CONTRACT_ID); //                              [argv, S, R]
            b.push(op::CALL);
            b.extend_from_slice(&dsol_vm::entry_hash(b"main").to_le_bytes()); // [argv, ret]
            push_bytes(&mut b, b"-r");
            b.extend_from_slice(&[op::CONCAT, op::RETURN]);
            b[j + 1..j + 5].copy_from_slice(&(13 + l_call as u32).to_le_bytes());
            program_of(&b)
        };
        let mut reentry: Registry = Registry::new();
        reentry.insert(code_id_of(&r_code), r_code.clone());
        reentry.insert(code_id_of(&s_code), s_code.clone());
        let mut host = ChainHost::new(reentry.clone(), code_id_of(&r_code));
        let (proof_r, stmt_r, run_r) = prove_dsol_call_run(&r_code, "main", b"go", ctx_for(&r_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host, None).expect("the re-entering chain proves");
        assert_eq!(run_r.ret, b"leaf-r".to_vec(), "R's re-entered self answered the leaf");
        assert_eq!(host.collected.len(), 2, "S and the re-entered R were proven");
        let code_of_re = |id: &[u8; 32]| reentry.get(id).cloned();
        let root_r = ProvenCall { proof: &proof_r, stmt: &stmt_r, effects: &run_r.effects };
        let links_r = as_links(&host.collected);
        for l in &links_r {
            assert!(verify_dsol_call(l.proof, &reentry[&l.stmt.code_id], l.stmt), "every proof of the re-entering chain is sound on its own");
        }
        assert!(!authorize_call_chain(&root_r, &links_r, &code_of_re, &no_pointers), "⛔ RE-ENTRY AUTHORISED: a callee called the root back while its storage was in flight");
        // F5: a trace forgery — the CALL's binding-stage block input nudged; armed under the constraint-free gate,
        // refused by the fold's source law
        let mut host = ChainHost::new(codes.clone(), code_id_of(&a_code));
        let t = dsol_vm::run(&a_code, "main", b"x", ctx_for(&a_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host).expect("A runs");
        let prog = decode_program(&a_code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let stmt = statement_of(&a_code, "main", b"x", dsol_vm::StorageTrie::default().root(), &ctx_for(&a_code), &t).expect("derives");
        let honest = build_cpu_trace(&t, &a_code, t.steps.len().next_power_of_two().max(32)).expect("lays out");
        let bind_row = t.steps.iter().position(|s| s.op == op::CALL && s.micro == mk::EFX && s.estage == 3).expect("the binding stage");
        let mut f5 = honest.clone();
        f5[C_P2 + DIGEST_LANES][bind_row] += Fa4::ONE;
        let (is_armed, refused) = armed_and_refused(&f5, &rom, &stmt);
        assert!(is_armed && refused, "the CALL binding forgery is armed under the constraint-free gate and refused by the relation");
        eprintln!(
            "[dsol-call] A → B → C returns \"x-c-b-a\" ({} B root proof, {} rows; 2 callee proofs) and is authorised; a swapped callee, a dropped callee, an orphan proof, a foreign caller and a RE-ENTRY through a dynamic id are refused; the binding forgery is armed and refused",
            proof_a.bytes.len(), t.steps.len()
        );
    }

    /// ⭐⭐ DEPLOY IS A SYSCALL, UPGRADES ARE POINTERS (plan item 3's decider half). A deployer ships its child's bytecode
    /// through `SYSCALL SYS_DEPLOY`, gets back `blake3(code)` (an effect the node re-derives at apply), and CALLs the child
    /// by that id in the same execution: "hi-kid". The chain is authorised with the child looked up under the returned id;
    /// a registry that ships OTHER code under that id is refused (the callee's proof does not verify against it). A twin
    /// calls a 32-byte POINTER NAME the host resolves to the child: authorised when the node's resolver names the child,
    /// refused when it names another code id, refused when nobody resolves the pointer.
    #[test]
    fn a_contract_deploys_a_child_by_syscall_and_calls_it_by_id_or_pointer() {
        let child = leaf_program(b"-kid");
        let child_id = code_id_of(&child);
        let entry = dsol_vm::entry_hash(b"main");
        let mut b = vec![op::POP];
        push_bytes(&mut b, &child); //                                   [child code]
        b.push(op::SYSCALL);
        b.extend_from_slice(&dsol_vm::SYS_DEPLOY.to_le_bytes()); //     [id]
        push_bytes(&mut b, b"hi"); //                                    [id, "hi"]
        b.push(op::CALL);
        b.extend_from_slice(&entry.to_le_bytes()); //                    [ret]
        b.push(op::RETURN);
        let deployer = program_of(&b);
        let mut host = ChainHost::new(Registry::new(), code_id_of(&deployer));
        host.codes.insert(code_id_of(&deployer), deployer.clone());
        let (proof, stmt, run) = prove_dsol_call_run(&deployer, "main", b"", ctx_for(&deployer), dsol_vm::StorageTrie::default(), 1 << 16, &mut host, None).expect("the deployer proves");
        assert_eq!(run.ret, b"hi-kid".to_vec(), "the deployer called the child it had just deployed");
        assert_eq!(host.codes.get(&child_id), Some(&child), "the deploy registered the child under blake3(code)");
        assert!(
            run.effects.iter().any(|e| matches!(e, dsol_vm::Effect::Syscall { sys_op, ret_len: 32, .. } if *sys_op == dsol_vm::SYS_DEPLOY)),
            "the deploy is a syscall effect the node re-runs (blake3 of the shipped code) and compares"
        );
        let root = ProvenCall { proof: &proof, stmt: &stmt, effects: &run.effects };
        let code_of = |id: &[u8; 32]| host.codes.get(id).cloned();
        assert!(authorize_call_chain(&root, &as_links(&host.collected), &code_of, &no_pointers), "the deploy-then-call chain is authorised");
        let imposter = leaf_program(b"-imposter");
        let wrong = |id: &[u8; 32]| if *id == child_id { Some(imposter.clone()) } else { host.codes.get(id).cloned() };
        assert!(!authorize_call_chain(&root, &as_links(&host.collected), &wrong, &no_pointers), "⛔ other code under the child's id was authorised");
        // a CALL by pointer name
        let mut name = [0u8; 32];
        name[..9].copy_from_slice(b"ptr:child");
        let mut b = vec![op::POP];
        push_bytes(&mut b, &name);
        push_bytes(&mut b, b"yo");
        b.push(op::CALL);
        b.extend_from_slice(&entry.to_le_bytes());
        b.push(op::RETURN);
        let via_ptr = program_of(&b);
        let mut host2 = ChainHost::new(host.codes.clone(), code_id_of(&via_ptr));
        host2.codes.insert(code_id_of(&via_ptr), via_ptr.clone());
        host2.pointers.insert(name, child_id);
        let (p2, s2, r2) = prove_dsol_call_run(&via_ptr, "main", b"", ctx_for(&via_ptr), dsol_vm::StorageTrie::default(), 1 << 16, &mut host2, None).expect("the pointer call proves");
        assert_eq!(r2.ret, b"yo-kid".to_vec(), "the pointer reached the child");
        let root2 = ProvenCall { proof: &p2, stmt: &s2, effects: &r2.effects };
        let name_d = dsol_vm::str_digest(&name);
        let code_of2 = |id: &[u8; 32]| host2.codes.get(id).cloned();
        let resolve_ok = |d: &Digest| (*d == name_d).then_some(child_id);
        let resolve_wrong = |d: &Digest| (*d == name_d).then_some(code_id_of(&via_ptr));
        assert!(authorize_call_chain(&root2, &as_links(&host2.collected), &code_of2, &resolve_ok), "a pointer the node resolves to the child is authorised");
        assert!(!authorize_call_chain(&root2, &as_links(&host2.collected), &code_of2, &resolve_wrong), "⛔ a pointer resolving to another code id was authorised");
        assert!(!authorize_call_chain(&root2, &as_links(&host2.collected), &code_of2, &no_pointers), "⛔ a pointer nobody resolves was authorised");
        eprintln!("[dsol-deploy] deploy-by-syscall then call-by-id returns \"hi-kid\" ({} B) and is authorised; other code under the id refused; a pointer call is authorised only when the resolver names the child", proof.bytes.len());
    }

    /// ⭐⭐⭐ LIBRARY CALLS RUN AGAINST THE CALLER'S STORAGE (the DELEGATECALL shape), RED FIRST. A libcalls L with "v1"; L
    /// stores "v1" under "k" — in A's storage; A's root jumps to L's post root at the LIBCALL's final row and A reads "v1"
    /// back from its own slot: proves, verifies, authorised (A's `storage_post` is the trie the library left, the library
    /// statement carries A's identity and A's roots). Refused: (F1) the post root nudged on the LIBCALL's final row (the
    /// freeze / jump laws; armed under the constraint-free gate); (F2) the library proven under another cid (the node's
    /// matcher); (F3) a host that ran the library against another trie — the machine refuses the call by name, so no proof
    /// exists; (F4) RE-ENTRY THROUGH A LIBRARY: R libcalls S with R's own id, S plain-CALLs it with "leaf" — every proof is
    /// sound and every effect matches, and the chain is refused because R's storage is on the path.
    ///
    /// TWO-PARTY-REVIEWED: as for the CALL pin — the prover side is `ChainHost` (it runs and proves the library, as a
    /// wallet would), the verifying side is `authorize_call_chain` fed only proof bytes, statements and effect lists; the
    /// two share nothing but the code registry, so the library-side lies here (another identity, another trie, a re-entry)
    /// are caught by the other side. The two-process arrival check through a real node's door is the node lane's half.
    #[test]
    fn library_calls_run_against_the_callers_storage_and_reentry_stays_refused() {
        let entry = dsol_vm::entry_hash(b"main");
        let lib = {
            let mut b = Vec::new();
            push_bytes(&mut b, b"k"); //                                    [argv, "k"]
            b.push(op::SWAP); //                                            ["k", argv]
            b.push(op::SSTORE); //                                          []            the CALLER's slot "k" := argv
            push_bytes(&mut b, b"ok");
            b.push(op::RETURN);
            program_of(&b)
        };
        let a_code = {
            let mut b = Vec::new();
            push_bytes(&mut b, &code_id_of(&lib)); //                       [argv, L]
            b.push(op::SWAP); //                                            [L, argv]
            b.push(op::LIBCALL);
            b.extend_from_slice(&entry.to_le_bytes()); //                   ["ok"]
            b.push(op::POP);
            push_bytes(&mut b, b"k");
            b.extend_from_slice(&[op::SLOAD, op::RETURN]); //               the value the library wrote into OUR storage
            program_of(&b)
        };
        let mut codes = Registry::new();
        codes.insert(code_id_of(&lib), lib.clone());
        codes.insert(code_id_of(&a_code), a_code.clone());
        let code_of = |id: &[u8; 32]| codes.get(id).cloned();
        let mut host = ChainHost::new(codes.clone(), code_id_of(&a_code));
        let (proof, stmt, run) = prove_dsol_call_run(&a_code, "main", b"v1", ctx_for(&a_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host, None).expect("A proves");
        assert_eq!(run.ret, b"v1".to_vec(), "A read back what the library wrote into A's storage");
        let mut expect = dsol_vm::StorageTrie::default();
        expect.insert_checked(&dsol_vm::str_digest(b"k"), dsol_vm::VmVal::Str { digest: dsol_vm::str_digest(b"v1"), len: 2 }).expect("inserts");
        assert_eq!(stmt.storage_post, expect.root(), "A's post root is the trie the library left");
        assert_eq!(host.collected.len(), 1, "one library proof");
        let (_, ls, _) = &host.collected[0];
        assert_eq!((ls.cid, ls.storage_pre, ls.storage_post), (stmt.cid, stmt.storage_pre, stmt.storage_post), "the library ran under A's identity between A's roots");
        let root = ProvenCall { proof: &proof, stmt: &stmt, effects: &run.effects };
        assert!(authorize_call_chain(&root, &as_links(&host.collected), &code_of, &no_pointers), "the library call is authorised");
        // F1: the post root nudged on the LIBCALL's final row
        let t = dsol_vm::run(&a_code, "main", b"v1", ctx_for(&a_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut ChainHost::new(codes.clone(), code_id_of(&a_code))).expect("A runs");
        let prog = decode_program(&a_code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let st = statement_of(&a_code, "main", b"v1", dsol_vm::StorageTrie::default().root(), &ctx_for(&a_code), &t).expect("derives");
        let honest = build_cpu_trace(&t, &a_code, t.steps.len().next_power_of_two().max(32)).expect("lays out");
        let fin = t.steps.iter().rposition(|s| s.op == op::LIBCALL).expect("the LIBCALL ran");
        assert_eq!(t.steps[fin].micro, mk::FINISH, "the LIBCALL ends on its FINISH row");
        assert_eq!(t.steps[fin].storage_root, stmt.storage_pre, "the root is the pre root through the LIBCALL's rows ...");
        assert_eq!(t.steps[fin + 1].storage_root, stmt.storage_post, "... and jumps to the library's post root right after");
        let mut f1 = honest.clone();
        f1[C_CALLEE][fin] += Fa4::ONE;
        let (armed, refused) = armed_and_refused(&f1, &rom, &st);
        assert!(armed && refused, "the post-root forgery is armed under the constraint-free gate and refused by the relation");
        // F2: the library proven under another identity — the machine does not check it, the node does
        let mut host2 = ChainHost { lib_wrong_cid: true, ..ChainHost::new(codes.clone(), code_id_of(&a_code)) };
        let (p2, s2, r2) = prove_dsol_call_run(&a_code, "main", b"v1", ctx_for(&a_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host2, None).expect("proves");
        let root2 = ProvenCall { proof: &p2, stmt: &s2, effects: &r2.effects };
        assert!(!authorize_call_chain(&root2, &as_links(&host2.collected), &code_of, &no_pointers), "⛔ a library under another cid was authorised");
        // F3: a host that ran the library against another trie — refused by the machine, no proof exists
        let mut host3 = ChainHost { lib_wrong_trie: true, ..ChainHost::new(codes.clone(), code_id_of(&a_code)) };
        let r3 = dsol_vm::run(&a_code, "main", b"v1", ctx_for(&a_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host3);
        assert!(matches!(r3, Err(dsol_vm::VmError::BadOpcode(_))), "a library that did not run against the caller's storage is refused by the machine: {r3:?}");
        // F4: re-entry through a library. S (a library) plain-CALLs its argument — R's id — with "leaf"; R("leaf") returns
        // without calling. Sound proofs, matching effects, refused: R's storage is on the path and S shares it.
        let s_lib = {
            let mut b = Vec::new();
            push_bytes(&mut b, b"leaf"); //                          [callee = argv, "leaf"]
            b.push(op::CALL);
            b.extend_from_slice(&entry.to_le_bytes());
            b.push(op::RETURN);
            program_of(&b)
        };
        let r_code = {
            let mut b = Vec::new();
            b.push(op::DUP);
            push_bytes(&mut b, b"leaf");
            b.extend_from_slice(&[op::STR_EQ, op::NOT]);
            let j = b.len();
            b.push(op::JUMPI);
            b.extend_from_slice(&[0u8; 4]);
            b.push(op::RETURN); //                                   the leaf: return argv
            let l_call = b.len();
            push_bytes(&mut b, &code_id_of(&s_lib)); //              [argv, S]
            b.push(op::CONTRACT_ID); //                              [argv, S, R]
            b.push(op::LIBCALL);
            b.extend_from_slice(&entry.to_le_bytes()); //            [argv, ret]
            push_bytes(&mut b, b"-r");
            b.extend_from_slice(&[op::CONCAT, op::RETURN]);
            b[j + 1..j + 5].copy_from_slice(&(13 + l_call as u32).to_le_bytes());
            program_of(&b)
        };
        let mut reg = Registry::new();
        reg.insert(code_id_of(&r_code), r_code.clone());
        reg.insert(code_id_of(&s_lib), s_lib.clone());
        let mut host4 = ChainHost::new(reg.clone(), code_id_of(&r_code));
        let (p4, s4, r4) = prove_dsol_call_run(&r_code, "main", b"go", ctx_for(&r_code), dsol_vm::StorageTrie::default(), 1 << 16, &mut host4, None).expect("the re-entering chain proves");
        assert_eq!(r4.ret, b"leaf-r".to_vec(), "the library re-entered R, which answered the leaf");
        assert_eq!(host4.collected.len(), 2, "the library and the re-entered R were proven");
        let links4 = as_links(&host4.collected);
        for l in &links4 {
            assert!(verify_dsol_call(l.proof, &reg[&l.stmt.code_id], l.stmt), "every proof is sound on its own");
        }
        let code_of4 = |id: &[u8; 32]| reg.get(id).cloned();
        let root4 = ProvenCall { proof: &p4, stmt: &s4, effects: &r4.effects };
        assert!(!authorize_call_chain(&root4, &links4, &code_of4, &no_pointers), "⛔ RE-ENTRY THROUGH A LIBRARY AUTHORISED: the library's plain call reached storage in flight");
        eprintln!(
            "[dsol-libcall] A libcalls L which writes into A's storage; A reads it back ({} B, {} rows) and the chain is authorised; the post-root forgery, a library under another cid, a library on another trie and a re-entry through a library are refused",
            proof.bytes.len(), t.steps.len()
        );
    }

    /// ⭐⭐⭐ CONTINUATIONS (plan item 5), RED FIRST: the string-slot program (1,270 rows uncut) is cut into segments of a few
    /// hundred rows at opcode boundaries; every segment proves and verifies on its own, the segments chain (each
    /// `state_out` is the next `state_in`, the roots hand over, the effect lists fold on), the last one RETURNs what the
    /// uncut run returns, and `authorize_segment_chain` accepts them. Refused: (F1) two segments swapped; (F2) a segment
    /// dropped; (F3) a FRESH proof of the whole call inserted as a continuation (its `state_in` is zero mid-chain); (F4) a
    /// boundary block's absorbed lane nudged on an out-run row (the fold's input law; armed under the constraint-free gate).
    ///
    /// TWO-PARTY-REVIEWED: the prover side is `prove_dsol_segment` chained by the wallet's loop below; the verifying side
    /// is `authorize_segment_chain`, fed only proof bytes, statements and effect lists (what a node receives). They share
    /// nothing but the code; a segment that lies about its ends is caught by the other side.
    #[test]
    fn a_call_cut_into_segments_chains_and_equals_the_uncut_run() {
        let code = string_slot_program();
        let uncut = run_it(&code);
        let ctx = dsol_vm::VmCtx::default();
        let code_of = |id: &[u8; 32]| (*id == *blake3::hash(&code).as_bytes()).then(|| code.clone());
        // the row-level diagnostic on the first segment BEFORE anything is proven: a refusal names its law by source line
        let prog = decode_program(&code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let (t1, _) = dsol_vm::run_segment(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, None, Some(300)).expect("runs");
        let st1 = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t1).expect("derives");
        let honest = build_cpu_trace(&t1, &code, t1.steps.len().next_power_of_two().max(32)).expect("lays out");
        if let DsolCpuGate::Cpu(c) = dsol_gate_for(st1.clone(), rom.clone())(0, Ea4::from_u64(0x1234_5678)) {
            if let Some((r, why)) = first_unsatisfied_row(&c, &honest, &t1.steps) {
                panic!("⛔ the honest first segment violates the relation at row {r} ({why}) of {}", t1.steps.len());
            }
        }
        // the wallet's loop: cut every ~300 rows until the machine returns — each segment's trace goes through the row
        // diagnostic before it is proven, so a refusal names its law
        let mut segments: Vec<(DsolCallProof, DsolStatement, Vec<dsol_vm::Effect>)> = Vec::new();
        let mut resume: Option<dsol_vm::Resume> = None;
        let mut final_ret: Option<Vec<u8>> = None;
        for i in 0..16 {
            let storage_pre = match &resume {
                Some(r) => r.storage.root(),
                None => dsol_vm::StorageTrie::default().root(),
            };
            let (t, next) = dsol_vm::run_segment(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, resume.take(), Some(300)).expect("the segment runs");
            let s = statement_of(&code, "main", b"", storage_pre, &ctx, &t).expect("derives");
            let table = build_cpu_trace(&t, &code, t.steps.len().next_power_of_two().max(32)).expect("lays out");
            if let DsolCpuGate::Cpu(c) = dsol_gate_for(s.clone(), rom.clone())(0, Ea4::from_u64(0x1234_5678)) {
                if let Some((r, why)) = first_unsatisfied_row(&c, &table, &t.steps) {
                    panic!("⛔ honest segment {i} violates the relation at row {r} ({why}) of {}", t.steps.len());
                }
            }
            let (p, s) = prove_trace(&code, "main", b"", storage_pre, &ctx, &t, None).expect("the segment proves");
            assert!(verify_dsol_call(&p, &code, &s), "segment {i} verifies on its own");
            segments.push((p, s, t.run.effects.clone()));
            match next {
                Some(n) => resume = Some(n),
                None => {
                    final_ret = Some(t.run.ret.clone());
                    break;
                }
            }
        }
        assert!(segments.len() >= 3, "the call was cut into at least three segments (got {})", segments.len());
        assert_eq!(final_ret.expect("the chain returned"), uncut.run.ret, "the segmented call returns what the uncut run returns");
        let zero = [0u64; DIGEST_LANES];
        assert_eq!(segments[0].1.state_in, zero, "the first segment starts fresh");
        assert_eq!(segments[segments.len() - 1].1.state_out, zero, "the last segment ends in a RETURN");
        for w in segments.windows(2) {
            assert_ne!(w[0].1.state_out, zero, "a cut's fold is never zero");
            assert_eq!(w[0].1.state_out, w[1].1.state_in, "each out-state is the next in-state");
            assert_eq!(w[0].1.storage_post, w[1].1.storage_pre, "the roots hand over");
        }
        assert_eq!(segments[segments.len() - 1].1.storage_post, uncut.run.storage_post, "the chain ends at the uncut run's storage");
        assert_eq!(segments[segments.len() - 1].1.effects_digest, uncut.run.effects_digest, "the chain's effects fold is the uncut run's");
        assert!(authorize_segment_chain(&as_links(&segments), &code_of), "the honest segment chain is authorised");
        // F1: two segments swapped
        let mut swapped: Vec<_> = segments.iter().map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        swapped.swap(1, 2);
        assert!(!authorize_segment_chain(&as_links(&swapped), &code_of), "⛔ a chain with two segments swapped was authorised");
        // F2: a segment dropped
        let mut dropped: Vec<_> = segments.iter().map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        dropped.remove(1);
        assert!(!authorize_segment_chain(&as_links(&dropped), &code_of), "⛔ a chain missing a segment was authorised");
        // F3: a fresh proof of the whole call inserted as a continuation
        let (fp, fs, fr) = prove_dsol_call_run(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost, None).expect("the uncut call proves");
        let mut fresh_mid: Vec<_> = segments.iter().map(|(p, s, e)| (p.clone(), s.clone(), e.clone())).collect();
        fresh_mid[1] = (fp, fs, fr.effects);
        assert!(!authorize_segment_chain(&as_links(&fresh_mid), &code_of), "⛔ a fresh start in the middle of a chain was authorised");
        // F4: a boundary block's absorbed lane nudged on the first segment's out-run
        let bound_rows = t1.steps.iter().filter(|s| s.micro == mk::BOUND).count();
        assert_eq!(bound_rows, dsol_vm::BOUND_GROUPS, "the first segment ends with one boundary run");
        let first_bound = t1.steps.iter().position(|s| s.micro == mk::BOUND).unwrap();
        assert_eq!(t1.steps[first_bound].bstage, 0);
        assert!(t1.steps[first_bound].bout, "the run at the end is the out-run");
        assert_eq!(st1.state_out, segments[0].1.state_out, "the same cut folds to the same state");
        let mut f4 = honest.clone();
        f4[C_P2 + DIGEST_LANES][first_bound + 3] += Fa4::ONE;
        let (armed, refused) = armed_and_refused(&f4, &rom, &st1);
        assert!(armed && refused, "an absorbed lane nudged in the boundary fold is armed under the constraint-free gate and refused by the relation");
        eprintln!(
            "[dsol-continuations] {} segments ({} rows uncut; {} B first proof) chain and return the uncut result; swapped, dropped and fresh-in-the-middle chains refused; a nudged boundary lane refused",
            segments.len(), uncut.steps.len(), segments[0].0.bytes.len()
        );
    }

    /// ⭐ FAST PROVING (plan item 7) — THE BASELINE, MEASURED, NOT ASSUMED: wall-clock ms to run + lay + prove, and to
    /// verify, a small call (14 rows, a 2^5 table) and a real one (the string-slot program, 1,270 rows, a 2^11 table), in
    /// whatever profile this binary was built with (the release number is the one that counts; the line names the
    /// profile). Asserts only what is a claim — both proofs verify; the milliseconds are printed for the plan's
    /// scoreboard. `MONEROUSD_BUS_PROFILE=1` makes the bus prover print its phase split (round-1 commit, bus-table commit,
    /// ties, zerochecks + shift binds, the two openings), which is what names the phase to attack.
    #[test]
    fn fast_proving_baseline_prove_and_verify_ms() {
        let ctx = dsol_vm::VmCtx::default();
        let mut out = Vec::new();
        for (name, code) in [("small", program()), ("string-slot", string_slot_program())] {
            let t = std::time::Instant::now();
            let (p, s) = prove_dsol_call(&code, "main", b"", ctx.clone(), dsol_vm::StorageTrie::default(), 1 << 16, &mut dsol_vm::NoHost).expect("the honest call proves");
            let prove_ms = t.elapsed().as_millis();
            let t = std::time::Instant::now();
            assert!(verify_dsol_call(&p, &code, &s), "{name}: the honest proof verifies");
            let verify_ms = t.elapsed().as_millis();
            out.push(format!("{name}: 2^{} table, {} B, prove {prove_ms} ms, verify {verify_ms} ms", s.height_log2, p.bytes.len()));
        }
        eprintln!("[dsol-perf] {} | profile: {}", out.join("; "), if cfg!(debug_assertions) { "debug" } else { "release" });
        // the pre-prover split: the machine run, the CPU table laying, the ROM and the statement — what a prove spends before
        // the bus prover starts (the bus prover's own split is `MONEROUSD_BUS_PROFILE=1`)
        let code = string_slot_program();
        let t0 = std::time::Instant::now();
        let t = run_it(&code);
        let run_ms = t0.elapsed().as_millis();
        let t0 = std::time::Instant::now();
        let table = build_cpu_trace(&t, &code, t.steps.len().next_power_of_two().max(32)).expect("lays out");
        let lay_ms = t0.elapsed().as_millis();
        let t0 = std::time::Instant::now();
        let prog = decode_program(&code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let _ = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t).expect("derives");
        let rest_ms = t0.elapsed().as_millis();
        eprintln!("[dsol-perf-pre] string-slot: machine run {run_ms} ms ({} steps), CPU table laying {lay_ms} ms ({} x {}), ROM + statement {rest_ms} ms", t.steps.len(), table.len(), table[0].len());
        // the per-evaluation split: the whole relation vs the Poseidon2 block alone, on a folded (off-hypercube) row of
        // the string-slot table, plus the number of laws one row folds (the probe records every NON-ZERO residual; on a
        // row of random values every law's residual is non-zero, so the count is the law count) and the declared degrees
        let stmt = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t).expect("derives");
        let DsolCpuGate::Cpu(gate) = dsol_gate_for(stmt, rom)(0, Ea4::from_u64(0x1234_5678)) else { panic!("table 0 is the CPU") };
        let half = table[0].len() / 2;
        let xj = Ea4::from_u64(3);
        let folded: Vec<Ea4> = table.iter().map(|c| Ea4::from(c[7]) * (Ea4::ONE - xj) + Ea4::from(c[half + 7]) * xj).collect();
        let nxt: Vec<Ea4> = table.iter().map(|c| Ea4::from(c[8]) * (Ea4::ONE - xj) + Ea4::from(c[half + 8]) * xj).collect();
        let oob = crate::air_zerocheck::OobLatch::new();
        let row = Row::new(&folded, &oob);
        let at = |c: usize, _p: &[Ea4]| -> Ea4 { nxt[c] };
        let nv = table[0].len().trailing_zeros() as usize;
        let x: Vec<Ea4> = (0..nv).map(|k| if k == 0 { xj } else { Ea4::from_u64(((7 >> (nv - 1 - k)) & 1) as u64) }).collect();
        let reps = 200u32;
        let t0 = std::time::Instant::now();
        let mut sink = Ea4::ZERO;
        for _ in 0..reps {
            sink += gate.eval(&row, &at, &x);
        }
        let whole_us = t0.elapsed().as_micros() / u128::from(reps);
        let t0 = std::time::Instant::now();
        for _ in 0..reps {
            sink += gate.p2.eval(&row.suffix(C_P2), &|c: usize, p: &[Ea4]| at(c + C_P2, p), &x);
        }
        let block_us = t0.elapsed().as_micros() / u128::from(reps);
        assert_ne!(sink, Ea4::from_u64(0xdead_beef), "the sink keeps the loops honest");
        let random: Vec<Ea4> = (0..CPU_COLS).map(|c| Ea4::from_u64(0x9e37_79b9_7f4a_7c15u64.wrapping_mul(c as u64 + 1) >> 11)).collect();
        let rrow = Row::new(&random, &oob);
        let rat = |c: usize, _p: &[Ea4]| -> Ea4 { random[(c * 7 + 3) % CPU_COLS] };
        probe_arm();
        let _ = gate.eval(&rrow, &rat, &x);
        let laws = probe_take().len();
        eprintln!(
            "[dsol-perf-split] one evaluation of the relation {whole_us} us (the Poseidon2 block alone {block_us} us) on a {}-column folded row; {laws} laws folded per row; declared degree {} (block {}); per_evals {}",
            CPU_COLS, gate.degree(nv), gate.p2.degree(nv), gate.degree(nv) + 2
        );
    }

    /// ⭐ THE LAW-DEGREE CENSUS — a fast deterministic instrument (plan item 7 and the continuations lesson): every law's
    /// per-variable degree, MEASURED, by source line. The relation is evaluated along a random line — the row and the
    /// next row each move linearly in `t`, the point's first coordinate is `t` (so `is_first / is_last / is_trans` count
    /// as the degree-1 factors they are in a sumcheck round) — the probe hands back every law's residual in push order,
    /// and each residual's degree in `t` is read off its forward differences (exact in the field: the (d+1)-th
    /// differences of a degree-d polynomial vanish). The Poseidon2 block is measured the same way. Prints the lines at
    /// the top of the table and asserts the maximum is within the declared `degree()` — the zerocheck samples deg+2
    /// points per round, so one law above the declaration mis-interpolates the honest proof (trace-dependently: the
    /// continuations pin's first segment verified, its continued one did not, with a degree-9 law declared 8).
    /// The layout as `name = start` lines, so a census report's column index resolves to its name (the debug prover's
    /// free-witness and degree censuses name columns by index; this is the map). Prints only.
    #[test]
    fn layout_map_names_every_column_range() {
        let ranges: [(&str, usize); 58] = [
            ("C_PC", C_PC), ("C_OP", C_OP), ("C_IMM", C_IMM), ("C_SP", C_SP), ("C_SPSEL", C_SPSEL), ("C_OPSEL", C_OPSEL),
            ("C_MICRO", C_MICRO), ("C_STACK", C_STACK), ("C_LOCALS", C_LOCALS), ("C_SPSTATE", C_SPSTATE),
            ("C_SPLANES", C_SPLANES), ("C_SPFILL", C_SPFILL), ("C_OPEN", C_OPEN), ("C_FEED", C_FEED), ("C_PERMSEL", C_PERMSEL),
            ("C_BYTE", C_BYTE), ("C_BYTEBITS", C_BYTEBITS), ("C_PLEN", C_PLEN), ("C_REMAIN", C_REMAIN), ("C_FB", C_FB),
            ("C_CPH", C_CPH), ("C_S2ACC", C_S2ACC), ("C_S2SCR", C_S2SCR), ("C_S2INV", C_S2INV), ("C_ALU_A", C_ALU_A),
            ("C_ALU_B", C_ALU_B), ("C_ALU_R", C_ALU_R), ("C_ALU_CARRY", C_ALU_CARRY), ("C_ALU_BITS", C_ALU_BITS),
            ("C_EQINV", C_EQINV), ("C_EQFLAG", C_EQFLAG), ("C_NZINV", C_NZINV), ("C_NZ", C_NZ), ("C_TAKEN", C_TAKEN),
            ("C_TAKEN_INV", C_TAKEN_INV), ("C_REAL", C_REAL), ("C_PPHASE", C_PPHASE), ("C_PPRES", C_PPRES), ("C_PDIR", C_PDIR),
            ("C_SROOT", C_SROOT), ("C_PSIB", C_PSIB), ("C_POLD", C_POLD), ("C_PNEW", C_PNEW), ("C_PKEY", C_PKEY),
            ("C_PVAL", C_PVAL), ("C_PVDIG", C_PVDIG), ("C_PVLEN", C_PVLEN), ("C_PVLANES", C_PVLANES), ("C_KACC", C_KACC),
            ("C_KLANE", C_KLANE), ("C_EACC", C_EACC), ("C_ESTAGE", C_ESTAGE), ("C_ETMP", C_ETMP), ("C_ETMP2", C_ETMP2),
            ("C_CALLEE", C_CALLEE), ("C_LIBEFX", C_LIBEFX), ("C_BSTATE", C_BSTATE), ("C_P2", C_P2),
        ];
        let mut sorted = ranges.to_vec();
        sorted.sort_by_key(|(_, s)| *s);
        let mut out = String::new();
        for w in sorted.windows(2) {
            out.push_str(&format!("{}={}..{} ", w[0].0, w[0].1, w[1].1));
        }
        out.push_str(&format!("{}={}..{}", sorted[sorted.len() - 1].0, sorted[sorted.len() - 1].1, CPU_COLS));
        eprintln!("[dsol-layout] {out}");
    }

    #[test]
    fn every_law_stays_within_the_declared_degree() {
        use std::collections::BTreeMap;
        let code = string_slot_program();
        let t = run_it(&code);
        let ctx = dsol_vm::VmCtx::default();
        let prog = decode_program(&code).expect("decodes");
        let rom = build_rom_trace(&prog, prog.len().next_power_of_two().max(32)).expect("lays out");
        let stmt = statement_of(&code, "main", b"", dsol_vm::StorageTrie::default().root(), &ctx, &t).expect("derives");
        let nv = usize::from(stmt.height_log2);
        // TWO statement modes: a fresh start that RETURNs, and a continued segment that CUTs — the row-0 / last-row laws
        // are gated by the statement (`start_gate` / `cont_gate`, `end_gate` / `cut_gate`), so each mode has laws that
        // are the zero polynomial by design; a law is vacuous only if it is zero in BOTH
        let mut stmt_cont = stmt.clone();
        stmt_cont.state_in = [7u64; DIGEST_LANES];
        stmt_cont.state_out = [9u64; DIGEST_LANES];
        let DsolCpuGate::Cpu(gate) = dsol_gate_for(stmt, rom.clone())(0, Ea4::from_u64(0x2468_ace0)) else { panic!("table 0 is the CPU") };
        let DsolCpuGate::Cpu(gate_cont) = dsol_gate_for(stmt_cont, rom)(0, Ea4::from_u64(0x2468_ace0)) else { panic!("table 0 is the CPU") };
        // a fixed pseudo-random source: the census is deterministic run to run
        let mix = |seed: u64, i: usize| -> u64 { (seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).wrapping_add(i as u64 + 1)).wrapping_mul(0xbf58_476d_1ce4_e5b9) >> 33 };
        let rnd = |seed: u64| -> Vec<Ea4> { (0..CPU_COLS).map(|c| Ea4::from_u64(mix(seed, c))).collect() };
        let (a, b, a2, b2) = (rnd(1), rnd(2), rnd(3), rnd(4));
        let xr: Vec<Ea4> = (0..nv).map(|k| Ea4::from_u64(mix(5, k))).collect();
        const PTS: usize = 16;
        let oob = crate::air_zerocheck::OobLatch::new();
        let mut per_t: Vec<Vec<(u32, Ea4)>> = Vec::with_capacity(PTS);
        let mut per_t_cont: Vec<Vec<(u32, Ea4)>> = Vec::with_capacity(PTS);
        let mut block: Vec<Ea4> = Vec::with_capacity(PTS);
        for tt in 0..PTS {
            // consecutive integers from 2: at t = 0 `is_last` vanishes and at t = 1 `is_first` does, which would drop whole
            // law groups from the probe at one point and break the push-order indexing (forward differences need only a
            // unit step, not a start at zero)
            let tv = Ea4::from_u64(tt as u64 + 2);
            let local: Vec<Ea4> = (0..CPU_COLS).map(|c| a[c] + tv * (b[c] - a[c])).collect();
            let next: Vec<Ea4> = (0..CPU_COLS).map(|c| a2[c] + tv * (b2[c] - a2[c])).collect();
            let mut x = xr.clone();
            x[0] = tv;
            let row = Row::new(&local, &oob);
            let at = |c: usize, _p: &[Ea4]| -> Ea4 { next[c] };
            // census mode: EVERY push is recorded, so a law whose residual is identically zero shows as a run of zeros
            probe_arm_all();
            let _ = gate.eval(&row, &at, &x);
            per_t.push(probe_take());
            probe_arm_all();
            let _ = gate_cont.eval(&row, &at, &x);
            per_t_cont.push(probe_take());
            block.push(gate.p2.eval(&row.suffix(C_P2), &|c: usize, p: &[Ea4]| at(c + C_P2, p), &x));
        }
        let n = per_t[0].len();
        assert!(per_t.iter().chain(per_t_cont.iter()).all(|v| v.len() == n), "the push sequence is the same at every point and in both modes (census mode records every push)");
        // ⛔ VACUITY: a law whose residual is zero at all PTS points of a random line is the zero polynomial (a non-zero
        // polynomial of degree < PTS cannot vanish at PTS distinct points) — it constrains NOTHING, a hole wearing a law's
        // costume. A law zero in one statement mode and live in the other is that mode's gate at work; zero in BOTH is
        // refused, named by source line.
        let vacuous: Vec<(usize, u32)> = (0..n)
            .filter(|&j| per_t.iter().all(|v| v[j].1 == Ea4::ZERO) && per_t_cont.iter().all(|v| v[j].1 == Ea4::ZERO))
            .map(|j| (j, per_t[0][j].0))
            .collect();
        let mut vacuous_lines: BTreeMap<u32, usize> = BTreeMap::new();
        for (_, line) in &vacuous {
            *vacuous_lines.entry(*line).or_insert(0) += 1;
        }
        eprintln!("[dsol-vacuity-census] {n} pushes per row; {} identically-zero residuals on {} source lines: {:?}", vacuous.len(), vacuous_lines.len(), vacuous_lines);
        // the degree of a polynomial from its values at 0..PTS-1: the first level of forward differences that vanishes
        let degree_of = |vals: &[Ea4]| -> usize {
            let mut d: Vec<Ea4> = vals.to_vec();
            for level in 0..PTS {
                if d.iter().all(|v| *v == Ea4::ZERO) {
                    return level.saturating_sub(1);
                }
                d = d.windows(2).map(|w| w[1] - w[0]).collect();
            }
            PTS // never vanished: the degree is at least PTS − 1
        };
        let mut per_line: BTreeMap<u32, (usize, usize)> = BTreeMap::new(); // line → (max degree, laws on that line)
        for j in 0..n {
            let line = per_t[0][j].0;
            assert!(per_t.iter().all(|v| v[j].0 == line), "the push order is the same at every t");
            let vals: Vec<Ea4> = per_t.iter().map(|v| v[j].1).collect();
            let vals_cont: Vec<Ea4> = per_t_cont.iter().map(|v| v[j].1).collect();
            let dg = degree_of(&vals).max(degree_of(&vals_cont));
            let e = per_line.entry(line).or_insert((0, 0));
            e.0 = e.0.max(dg);
            e.1 += 1;
        }
        let block_deg = degree_of(&block);
        let declared = gate.degree(nv);
        let mut table: Vec<(u32, usize, usize)> = per_line.iter().map(|(l, (d, c))| (*l, *d, *c)).collect();
        table.sort_by(|p, q| q.1.cmp(&p.1).then(q.2.cmp(&p.2)));
        let max_law = table.first().map_or(0, |e| e.1);
        let mut hist: BTreeMap<usize, usize> = BTreeMap::new();
        for (_, d, c) in &table {
            *hist.entry(*d).or_insert(0) += c;
        }
        eprintln!(
            "[dsol-degree-census] {n} laws on {} source lines; declared {declared} (block declared {}); MEASURED max law degree {max_law}, block {block_deg}; laws per degree {:?}; top lines (line, degree, laws): {:?}",
            table.len(), gate.p2.degree(nv), hist, &table[..table.len().min(14)]
        );
        assert!(max_law <= declared && block_deg <= declared, "⛔ a law ({max_law}) or the block ({block_deg}) exceeds the declared degree {declared}: the honest proof mis-interpolates");
        assert!(vacuous.is_empty(), "⛔ {} law(s) constrain nothing (identically-zero residuals) on lines {:?}", vacuous.len(), vacuous_lines.keys().collect::<Vec<_>>());
        assert!(n < LAW_CAPACITY, "⛔ {n} pushes per row exceed the γ-power table ({LAW_CAPACITY}); raise LAW_CAPACITY");
    }
}
