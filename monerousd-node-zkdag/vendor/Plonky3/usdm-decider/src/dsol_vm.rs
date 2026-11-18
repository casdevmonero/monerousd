// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE DSOL MACHINE — ONE EXECUTION SEMANTICS, AND IT LIVES WHERE THE CIRCUIT CAN SEE IT.
//!
//! # Why the machine moved into the decider crate
//!
//! A zkVM has two halves that MUST agree: the interpreter a node runs, and the circuit that proves an
//! execution. If they live in different crates and are written twice, they drift — and a drifted pair is
//! the worst failure this tree knows, because the proof then certifies a machine nobody runs. This
//! crate's own history names the class twice (`§AG` had TWO note-commitment encodings; `§AO` had TWO note
//! identities), and both times the cause was one object with two spellings.
//!
//! So the machine is defined ONCE, here, beside the circuit that constrains it. `crate::dsol` in the node
//! is a thin host: it supplies the context and applies the EFFECTS this machine emits. It does not
//! interpret opcodes, because there is only one interpreter.
//!
//! # The shape, and why it is this shape
//!
//! A DSOL stack slot holds either a `u64` or a BYTE STRING. Byte strings are what make a general VM hard
//! to constrain: they are variable length, and every classical zkVM answers that with random-access
//! memory plus a sorted-by-address consistency argument. That is a large, separate subsystem.
//!
//! This machine answers it differently, and the answer is the reason the whole build is tractable:
//!
//! **A byte string on the stack is its POSEIDON2 SPONGE DIGEST plus its length. Any operation that needs
//! the CONTENT re-supplies the content, and the circuit re-absorbs it and checks the digest matches.**
//!
//! Nothing is stored; nothing is addressed; there is no memory table, no sorting argument, and no
//! permutation bus for RAM. The binding comes from Poseidon2 collision resistance, which this tree
//! already relies on for every note commitment and every accumulator. The cost is that content re-supply
//! is O(length) ROWS — paid by the prover (a wallet, once, per call), never by a verifying node, whose
//! work is the fixed light-decider verify.
//!
//! ⛔ THE TRAP THIS AVOIDS, NAMED: a digest-keyed side map that the circuit trusts. If the circuit read a
//! string's bytes from a table it did not re-hash, the prover would choose both the bytes and the digest
//! and `CONCAT` would join strings nobody committed to. Every content read below is therefore paired with
//! an absorb, and `StrTable` exists only on the PROVER side — it is a witness cache, never an input to a
//! constraint. See [`VmTrace::strings`].
//!
//! # What an execution proves
//!
//! ```text
//! statement := (code_id, entry_sel, argv_digest, storage_pre, storage_post, effects_digest, ret_digest)
//! witness   := the step trace (stack images, absorbed bytes, sponge states, storage paths)
//! ```
//!
//! A verifier holding only the statement learns the contract that ran and the state it moved. It does not
//! learn the arguments, the intermediate values, the strings, or which branch was taken — the pillar-1
//! requirement for a private DeFi execution layer.
//!
//! # NO GROWTH
//!
//! Every quantity here is f(the call), never f(chain length / notes / peers / height): the trace is
//! [`VmTrace::steps`] long and bounded by [`STEP_BUDGET_MAX`]; the stack is [`STACK_DEPTH`] slots; a
//! string absorb is `ceil(len / BYTES_PER_BLOCK)` rows and `len` is bounded by [`STR_BYTES_MAX`]. The
//! node stores NONE of it — a call's trace is the caller's witness and is discarded after verification.

use crate::poseidon2_compress::{Digest, DIGEST_LANES};

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Bounds. Every one is a NAMED CONSTANT a gate can cite; none is a magic number at a use site.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Stack slots the machine has. A DSOL contract is a predicate over a handful of values; 16 is far past
/// anything the compiler emits, and a FIXED depth is what removes the need for a memory argument on the
/// stack itself (the whole stack is committed in every row, so a pop cannot read a slot nobody wrote).
pub const STACK_DEPTH: usize = 16;

/// Local-variable frame slots. Same reasoning as the stack: fixed, committed per row.
pub const LOCALS_MAX: usize = 16;

/// Field lanes one sponge block absorbs — the Poseidon2 width-16 permutation's RATE.
pub const RATE: usize = 8;

/// Bytes packed into one field lane. 3 bytes = 24 bits, comfortably inside KoalaBear's 31-bit prime, so a
/// lane is injective on its bytes and no reduction can alias two different triples onto one lane.
pub const BYTES_PER_LANE: usize = 3;

/// Bytes one absorb row consumes.
pub const BYTES_PER_BLOCK: usize = RATE * BYTES_PER_LANE;

/// The longest byte string this machine will carry. A contract that needs more is not a predicate, it is
/// a file system — and an unbounded string length would be a growth axis in the trace.
pub const STR_BYTES_MAX: usize = 4_096;

/// The most steps one call may take. The bound is what makes the trace height a constant of the protocol
/// rather than a function of the program, and it is the anti-DoS budget the interpreter already had.
pub const STEP_BUDGET_MAX: u64 = 1 << 20;

/// Storage-trie depth: a contract's storage is a fixed-depth sparse Merkle tree keyed by the slot digest,
/// so a read or a write costs a path of this many levels and the storage ROOT is 32 bytes at any size.
/// Named once here; the circuit and the host both cite this, never a literal (the depth-mismatch law).
/// ⛔⛔⛔ THE DEPTH IS THE COLLISION BOUND, AND IT IS THE FULL KEY WIDTH — 248 bits, every bit of a
/// canonical digest.
///
/// A sparse trie routes a key by its leading `STORAGE_DEPTH` bits, so any depth SHORTER than the key
/// puts two distinct keys in one bucket once the birthday bound is reached: 2^16 live slots at depth 32,
/// 2^32 at depth 64. Both are numbers a real contract can reach, and the answers available at a short
/// depth are all bad — silently keeping one key gives a WRONG root, and refusing the second makes an
/// honest contract fail for a reason its author cannot see or avoid.
///
/// At the full 248 the question does not arise: two distinct canonical digests differ in some bit, so
/// they diverge somewhere on the path and each has its own leaf. `DIGEST_LANES * 31` is exactly the
/// canonical digest's bit width (`poseidon2_compress::digest_to_bytes` packs 31 bits per lane), so this
/// is DERIVED from the digest encoding rather than chosen — a wider digest moves it automatically.
///
/// The cost is paid by the PROVER and nowhere else: an access is 248 trace rows of one Poseidon
/// compression each, and the node still holds one 32-byte root per contract at any slot count.
pub const STORAGE_DEPTH: usize = DIGEST_LANES * 31;

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Values
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A DSOL stack value. A string is its DIGEST and LENGTH — never its bytes. See the module header for
/// why: the bytes are re-supplied and re-absorbed wherever they are needed, so nothing trusts a side map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmVal {
    Word(u64),
    Str { digest: Digest, len: u32 },
}

impl VmVal {
    /// The empty string — the identity of `CONCAT` and the value every unwritten slot holds.
    #[must_use]
    pub fn empty_str() -> Self {
        VmVal::Str { digest: str_digest(&[]), len: 0 }
    }

    #[must_use]
    pub fn is_word(&self) -> bool {
        matches!(self, VmVal::Word(_))
    }

    /// A value's `u64` reading. A STRING reads as its first 8 bytes little-endian in the interpreter this
    /// machine replaces, and that stays true here — but the circuit can only constrain it through an
    /// absorb, so the compiler emits `U64_FROM_BYTES` explicitly and this is used only where the value is
    /// already a word. Returns `None` for a string so no caller can silently take the old coercion.
    #[must_use]
    pub fn as_word(&self) -> Option<u64> {
        match self {
            VmVal::Word(w) => Some(*w),
            VmVal::Str { .. } => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The string digest — the ONE definition, used by the interpreter, the trace builder and the circuit
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Pack up to [`BYTES_PER_LANE`] bytes into one field-lane value, little-endian. Injective on the triple.
#[must_use]
pub fn pack_lane(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for (i, &x) in b.iter().take(BYTES_PER_LANE).enumerate() {
        v |= u64::from(x) << (8 * i);
    }
    v
}

/// The absorb blocks a string of `len` bytes occupies — ALWAYS at least one, so the empty string has a
/// digest that went through the permutation like every other string (a zero-block empty string would
/// digest to the initial state, which a prover could also reach by other means).
#[must_use]
pub fn str_blocks(len: usize) -> usize {
    if len == 0 {
        1
    } else {
        len.div_ceil(BYTES_PER_BLOCK)
    }
}

/// The initial sponge state for a string of `len` bytes: the LENGTH is the capacity seed.
///
/// ⛔ LENGTH-PREFIXED, DELIBERATELY. With zero padding and no length, `"a"` and `"a\0"` absorb the same
/// lanes and collide. Seeding the capacity with the length separates them without a padding rule, and it
/// means a prover cannot re-interpret a committed string at a different length to make a `STR_EQ` or a
/// `CONCAT` come out its way.
#[must_use]
pub fn str_sponge_init(len: usize) -> [u64; 2 * RATE] {
    let mut st = [0u64; 2 * RATE];
    st[RATE] = len as u64;
    st
}

/// Absorb one block's lanes into a sponge state and permute. The rate lanes are OVERWRITTEN (the
/// challenger's own convention, and the one `sponge_chain_air` constrains), never XORed.
#[must_use]
pub fn str_absorb_block(state: &[u64; 2 * RATE], lanes: &[u64; RATE]) -> [u64; 2 * RATE] {
    let mut st = *state;
    st[..RATE].copy_from_slice(lanes);
    crate::poseidon2_compress::permute_lanes_16(&st)
}

/// The lanes of block `i` of `bytes` — zero-padded past the end.
#[must_use]
pub fn str_block_lanes(bytes: &[u8], block: usize) -> [u64; RATE] {
    let mut lanes = [0u64; RATE];
    let base = block * BYTES_PER_BLOCK;
    for (l, lane) in lanes.iter_mut().enumerate() {
        let off = base + l * BYTES_PER_LANE;
        if off < bytes.len() {
            let end = (off + BYTES_PER_LANE).min(bytes.len());
            *lane = pack_lane(&bytes[off..end]);
        }
    }
    lanes
}

/// ⭐⭐⭐ THE ONE DIGEST OF A BYTE STRING. Every stack slot holding a string holds THIS, the trace's
/// absorb rows reproduce THIS, and the circuit's sponge constraints prove THIS. One definition.
#[must_use]
pub fn str_digest(bytes: &[u8]) -> Digest {
    let mut st = str_sponge_init(bytes.len());
    for b in 0..str_blocks(bytes.len()) {
        st = str_absorb_block(&st, &str_block_lanes(bytes, b));
    }
    let mut d = [0u64; DIGEST_LANES];
    d.copy_from_slice(&st[..DIGEST_LANES]);
    d
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The opcode table. ⛔ THIS IS THE ONE TABLE — `crate::dsol::op` in the node RE-EXPORTS these, it does
// not restate them. Two spellings of one opcode is the `§AG`/`§AO` class, and here it would mean the
// circuit constrains a different machine than the node runs.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

pub mod op {
    pub const PUSH_U64: u8 = 0x01;
    pub const PUSH_BYTES: u8 = 0x02;
    pub const POP: u8 = 0x03;
    pub const DUP: u8 = 0x04;
    pub const SWAP: u8 = 0x05;
    pub const ADD_U64: u8 = 0x10;
    pub const SUB_U64: u8 = 0x11;
    pub const MUL_U64: u8 = 0x12;
    pub const DIV_U64: u8 = 0x13;
    pub const MOD_U64: u8 = 0x14;
    pub const LT: u8 = 0x20;
    pub const EQ: u8 = 0x21;
    pub const NOT: u8 = 0x22;
    pub const AND: u8 = 0x23;
    pub const OR: u8 = 0x24;
    pub const JUMP: u8 = 0x30;
    pub const JUMPI: u8 = 0x31;
    pub const RETURN: u8 = 0x32;
    pub const REVERT: u8 = 0x33;
    pub const SLOAD: u8 = 0x40;
    pub const SSTORE: u8 = 0x41;
    pub const SSTORE_PRIV: u8 = 0x42;
    pub const COMMIT_U64: u8 = 0x50;
    pub const NULLIFIER: u8 = 0x52;
    pub const SYSCALL: u8 = 0x60;
    pub const MSG_SENDER: u8 = 0x70;
    pub const BLOCK_NUMBER: u8 = 0x71;
    pub const CONTRACT_ID: u8 = 0x72;
    pub const TX_HASH: u8 = 0x73;
    pub const SHA3: u8 = 0x80;
    /// ⭐ THE IN-CIRCUIT HASH. `SHA3` is Keccak, whose in-circuit cost is a bit-level permutation table;
    /// it is proven by the separate Keccak precompile. `POSEIDON` is the chain's OWN hash — the same
    /// permutation every note commitment, accumulator and challenger in this tree uses — so a contract
    /// that hashes with it costs a handful of rows in the main table and nothing else. New DSOL code
    /// should hash with this; `SHA3` stays for contracts that must reproduce a foreign digest.
    pub const POSEIDON: u8 = 0x81;
    pub const EMIT: u8 = 0x90;
    pub const LOCAL_GET: u8 = 0xa0;
    pub const LOCAL_SET: u8 = 0xa1;
    pub const ALLOC_LOCALS: u8 = 0xa2;
    pub const U64_FROM_BYTES: u8 = 0xa3;
    pub const U64_TO_BYTES: u8 = 0xa4;
    pub const MAP_LOAD: u8 = 0xa5;
    pub const MAP_STORE: u8 = 0xa6;
    pub const MAP_STORE_PRIV: u8 = 0xa7;
    pub const CONCAT: u8 = 0xa8;
    pub const BYTES_LEN: u8 = 0xa9;
    pub const STR_EQ: u8 = 0xaa;
    pub const EXT_CALL_TAIL: u8 = 0xab;
    pub const U64_TO_DEC_STR: u8 = 0xac;
    pub const MSG_SUBADDRESS: u8 = 0xae;
    /// WIDE ARITHMETIC (plan item 4, 2026-09-29) — the four word primitives multi-precision code is built from, each one
    /// row on the L4 columns. `MUL_HI`: ⌊a·b / 2^64⌋ (with MUL, the exact 128-bit product). `ADC` / `SBB`: pops
    /// `c_in` (top, 0 or 1), `b`, `a`; pushes the sum / difference, then the carry / borrow out on top. `DIVMOD128`: pops
    /// `d` (top), `lo`, `hi`; pushes `q` then `r` (top) with `hi·2^64 + lo = q·d + r`, `r < d` — refused (checked) when
    /// the quotient would not fit a word (`hi ≥ d`) or `d = 0`. `mulDiv(a, b, c)` is `DIVMOD128(MUL_HI, MUL, c)`.
    pub const MUL_HI: u8 = 0xb0;
    pub const ADC: u8 = 0xb1;
    pub const SBB: u8 = 0xb2;
    pub const DIVMOD128: u8 = 0xb3;
    /// SYNCHRONOUS CROSS-CONTRACT CALL (plan item 2, 2026-09-29) — `CALL entry_sel` (imm u32): pops `argv` (top) and the
    /// callee's 32-byte code id (a string); pushes the callee's return string. The callee's execution is ITS OWN
    /// statement: this opcode ISSUES the call as an [`Effect::Call`] (argv, ret through sponge C, and a binding of the
    /// callee's storage roots and effects), and the node AUTHORISES it by verifying the callee's own proof against that
    /// effect ([`crate::dsol_cpu_air::authorize_call_chain`]) — the same split a `SYSCALL` uses, so nothing the callee
    /// did is ever taken from the caller's word.
    pub const CALL: u8 = 0xb4;
    /// LIBRARY CALL — the DELEGATECALL shape (plan item 2, 2026-09-29): `LIBCALL entry_sel` (imm u32) is a `CALL` whose
    /// callee runs against the CALLER's storage under the caller's identity: the library statement's `storage_pre` is the
    /// caller's root at the call, its `storage_post` becomes the caller's root after it (the root JUMPS at this opcode's
    /// final row), its `cid` is the caller's and its `caller` the caller's caller. Issued as an [`Effect::LibCall`], authorised
    /// by the node against the library's own proof; a library's cid is legitimately on the call path (it IS the caller's
    /// storage) and is admitted only through this effect — a plain `CALL` back into it stays refused.
    pub const LIBCALL: u8 = 0xb5;
    /// The BOUNDARY pseudo-opcode (continuations, plan item 5, 2026-09-29) — never in bytecode and never fetched: the
    /// rows of a segment's boundary FOLD carry it so L1's one-hot holds. A boundary run is [`super::BOUND_GROUPS`] rows
    /// (`mk::BOUND`), each absorbing eight lanes of the machine state that crosses a cut (pc, sp, the stack, the locals,
    /// the storage root, the effects fold — [`super::bound_lanes`]) into a running Poseidon2 fold; the fold's result is
    /// the statement's `state_in` (a run at row 0) or `state_out` (a run ending at the last row).
    pub const BOUND: u8 = 0xb6;
}

/// The MICRO-step kinds. One macro opcode expands into one or more of these, and the circuit constrains
/// ONE of these per trace row. The expansion is what makes variable-length byte strings provable without
/// a memory subsystem: a string's content enters the trace one BYTE per row, and every sponge it feeds
/// advances under the same committed byte.
pub mod mk {
    /// A whole opcode in one row: stack/ALU/control. No byte moves, no sponge advances.
    pub const PLAIN: u8 = 0;
    /// One byte of re-supplied content enters up to three sponges (see [`super::Step::feed`]).
    pub const FEED: u8 = 1;
    /// One sponge's staged lanes go through the permutation. No byte moves.
    pub const PERM: u8 = 2;
    /// The opcode's FINAL row: the sponges are closed out and the result lands on the stack.
    pub const FINISH: u8 = 3;
    /// One level of a storage Merkle path: the pre-image node and the post-image node both fold through
    /// the SAME sibling, which is what makes a read unable to move the root and a write able to move it
    /// only where its key sits. A write lays each level TWICE — the old image (`path_phase = false`) then the
    /// new one (`true`) — so one Poseidon2 block per row suffices; a read lays it once.
    pub const PATH: u8 = 4;
    /// The slot LEAF hash of a storage access: `compress(key, encoded value)` — the row's block hashes the
    /// pre-image value (`path_phase = false`) or, on a write's second LEAF row, the post-image value (`true`).
    /// An absent slot's pre-image leaf is the empty digest, so its LEAF row's block output is discarded.
    pub const LEAF: u8 = 5;
    /// One Poseidon2 block of the EFFECTS fold (L9): an effect's leaf is built stage by stage from the operands the
    /// row can see, and the last stage folds it into the running accumulator — [`super::efx_plan`] is the schedule.
    pub const EFX: u8 = 6;
    /// A mapped access's KEY DERIVATION (L8b): the row's block hashes `(base, key)` — the two string operands below the
    /// value — into `map_slot(base, key)`, which is the access key of every row that follows. One per `MAP_*` access,
    /// first in its run.
    pub const KEYD: u8 = 7;
    /// A STRING value's half of a slot leaf (L8b part 2): the row's block hashes `(digest, [1, len])` — the pre-image
    /// string's (`path_phase = false`) or the written top's (`true`) — into the value half the LEAF row that follows
    /// consumes. A word value needs no such row: its half is its own limbs.
    pub const SVAL: u8 = 8;
    /// `COMMIT_U64`'s commitment row (S2-4): after the produce, the row's block hashes `[DOM_COMMIT, v₀..v₃]` (the value's
    /// four 16-bit limbs) with the blinding string's digest (sponge A) — the commitment the produced 32 bytes must encode.
    pub const CMT: u8 = 9;
    /// One row of a segment BOUNDARY fold (continuations): the row's block absorbs eight lanes of the carried machine
    /// state (`bound_lanes`, group `bstage`) into the running fold `bstate`; the carried columns cannot move under it
    /// (a BOUND row is a `cont` row). A run of [`super::BOUND_GROUPS`] such rows at row 0 opens a CONTINUED segment
    /// (the fold must equal the statement's `state_in`); a run ending at the last row closes one (`state_out`).
    pub const BOUND: u8 = 10;
}

/// L9 — where one input of an effects-fold block comes from, as the CIRCUIT can see it on the row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfxSrc {
    /// `lanes_of(&[c])` — a domain constant.
    Const(u64),
    /// `lanes_of(&[c, sys_op])` — a domain constant with the `SYSCALL` immediate in lane 1.
    ConstSysOp(u64),
    /// Stack slot `n`'s string digest.
    SlotDigest(u8),
    /// Stack slot `n`'s string length, as `lanes_of(&[len])`.
    SlotLen(u8),
    /// The call's contract id (`str_digest(ctx.contract_id)`) — a statement value.
    Cid,
    /// Sponge A's closed digest: the `NULLIFIER` secret as the row re-absorbed it.
    SpongeA,
    /// Sponge C's closed digest: the string this opcode PRODUCED (a `SYSCALL` result as the row fed it, L9b).
    SpongeC,
    /// The produced string's length (`plen`), as `lanes_of(&[plen])`.
    Plen,
    /// The first / second carry, written by an earlier stage of the same effect.
    Tmp0,
    Tmp1,
    /// The effects fold before the row.
    Acc,
    /// The access key this opcode derived on its KEYD row (`MAP_STORE_PRIV`, L8b): the row's `C_PKEY`, carried from the
    /// key-derivation block's output.
    PKey,
    /// `lanes_of(&[c, entry_sel, plen])` — a domain constant with a `CALL`'s u32 immediate (its two 16-bit limbs) in
    /// lane 1 and the produced (returned) length in lane 2.
    ConstImmPlen(u64),
    /// The callee binding a `CALL` row carries (`C_CALLEE`): `H(H(callee_storage_pre, callee_storage_post),
    /// callee_effects)` — what the node recomputes from the callee's statement. On a `LIBCALL` row the same columns carry
    /// the library's POST storage root (the caller's root after the call).
    Callee,
    /// `lanes_of(&[c, entry_sel, plen, argv_len])` — a `LIBCALL`'s domain constant with its u32 immediate, the returned
    /// length and the argument's length (slot 0's).
    ConstImmPlenAlen(u64),
    /// The row's OWN storage root (`C_SROOT`) — a `LIBCALL`'s `pre`, the caller's root at the call.
    SRoot,
    /// The library's effects digest a `LIBCALL` row carries (`C_LIBEFX`).
    LibEffects,
}

/// Where an effects-fold block's output lands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfxDst {
    Tmp0,
    Tmp1,
    /// The running fold — only ever the LAST stage.
    Acc,
}

/// One block of the effects fold: `out = compress(left, right)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EfxStep {
    pub left: EfxSrc,
    pub right: EfxSrc,
    pub out: EfxDst,
}

/// The most stages any effect takes (the `SYSCALL` leaf).
pub const EFX_STAGES_MAX: usize = 7;

/// ⭐ L9 — THE ONE EFFECTS-FOLD SCHEDULE, per opcode: the machine emits exactly these blocks ([`Machine::effect_rows`])
/// and asserts their result equals [`effect_leaf`] folded into the accumulator; the circuit constrains exactly these
/// inputs and outputs. Two spellings of this schedule would be two chances for the machine to record what the circuit
/// did not prove. Empty for an opcode that records no effect.
#[must_use]
pub fn efx_plan(o: u8) -> &'static [EfxStep] {
    use EfxDst as D;
    use EfxSrc as S;
    const fn st(left: EfxSrc, right: EfxSrc, out: EfxDst) -> EfxStep {
        EfxStep { left, right, out }
    }
    // `effect_leaf`, block by block:
    //   Nullifier: leaf = H([2], tag), tag = H([DOM], H(cid, secret))
    //   Event:     leaf = H(H([1], topic), H(data, [len]))        topic = slot 1, data = slot 0
    //   PrivateSlot: leaf = H([3], key)                            key = slot 1 (SSTORE_PRIV) / derived (MAP_STORE_PRIV)
    //   Syscall:   leaf = H(H([4, sys_op], H(argv, [alen])), H(ret, [rlen]))
    //   Call:      leaf = H(H([5, entry_sel, rlen], H(code_id, H(argv, [alen]))), H(ret, callee binding))
    //   LibCall:   leaf = the CHAIN H(H(H(H(H(H([6, entry, rlen, alen], H(code_id, argv)), ret), lib effects), pre), post)
    //              (one temp: each stage consumes the previous — six digests and the constants bound in fixed order)
    // and every effect ends with acc' = H(acc, leaf).
    const NULLIFIER: [EfxStep; 4] = [
        st(S::Cid, S::SpongeA, D::Tmp0),
        st(S::Const(DOM_NULLIFIER), S::Tmp0, D::Tmp0),
        st(S::Const(2), S::Tmp0, D::Tmp0),
        st(S::Acc, S::Tmp0, D::Acc),
    ];
    const EMIT: [EfxStep; 4] = [
        st(S::Const(1), S::SlotDigest(1), D::Tmp0),
        st(S::SlotDigest(0), S::SlotLen(0), D::Tmp1),
        st(S::Tmp0, S::Tmp1, D::Tmp0),
        st(S::Acc, S::Tmp0, D::Acc),
    ];
    const SSTORE_PRIV: [EfxStep; 2] = [st(S::Const(3), S::SlotDigest(1), D::Tmp0), st(S::Acc, S::Tmp0, D::Acc)];
    const MAP_STORE_PRIV: [EfxStep; 2] = [st(S::Const(3), S::PKey, D::Tmp0), st(S::Acc, S::Tmp0, D::Acc)];
    const SYSCALL: [EfxStep; 5] = [
        st(S::SlotDigest(0), S::SlotLen(0), D::Tmp0),
        st(S::ConstSysOp(4), S::Tmp0, D::Tmp0),
        st(S::SpongeC, S::Plen, D::Tmp1), // L9b: the result as sponge C produced it, and its length
        st(S::Tmp0, S::Tmp1, D::Tmp0),
        st(S::Acc, S::Tmp0, D::Acc),
    ];
    const CALL: [EfxStep; 6] = [
        st(S::SlotDigest(0), S::SlotLen(0), D::Tmp0), // H(argv, [alen])
        st(S::SlotDigest(1), S::Tmp0, D::Tmp0),       // H(code_id, ·)
        st(S::ConstImmPlen(5), S::Tmp0, D::Tmp0),     // H([5, entry_sel, rlen], ·)
        st(S::SpongeC, S::Callee, D::Tmp1),           // H(ret, callee binding)
        st(S::Tmp0, S::Tmp1, D::Tmp0),
        st(S::Acc, S::Tmp0, D::Acc),
    ];
    const LIBCALL: [EfxStep; 7] = [
        st(S::SlotDigest(1), S::SlotDigest(0), D::Tmp0), // H(code_id, argv)
        st(S::ConstImmPlenAlen(6), S::Tmp0, D::Tmp0),    // H([6, entry_sel, rlen, alen], ·)
        st(S::Tmp0, S::SpongeC, D::Tmp0),                // H(·, ret)
        st(S::Tmp0, S::LibEffects, D::Tmp0),             // H(·, library effects)
        st(S::Tmp0, S::SRoot, D::Tmp0),                  // H(·, pre = the caller's root at the call)
        st(S::Tmp0, S::Callee, D::Tmp0),                 // H(·, post = the library's root after it)
        st(S::Acc, S::Tmp0, D::Acc),
    ];
    match o {
        op::NULLIFIER => &NULLIFIER,
        op::EMIT => &EMIT,
        op::SSTORE_PRIV => &SSTORE_PRIV,
        op::MAP_STORE_PRIV => &MAP_STORE_PRIV,
        op::SYSCALL => &SYSCALL,
        op::CALL => &CALL,
        op::LIBCALL => &LIBCALL,
        _ => &[],
    }
}

/// Sponge slots a row can drive. A is the first operand's verifier, B the second's, C the producer.
pub const SPONGE_A: usize = 0;
pub const SPONGE_B: usize = 1;
pub const SPONGE_C: usize = 2;
pub const SPONGES: usize = 3;

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Errors, context, effects
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A fail-closed abort. The machine NEVER silently succeeds, and every arm here is reachable from a
/// contract a user could write — which is why each one is a distinct value rather than a bool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    StackUnderflow,
    StackOverflow,
    BadOpcode(u8),
    BadBytecode(&'static str),
    UnknownEntrypoint,
    TypeMismatch(&'static str),
    DivByZero,
    BudgetExhausted,
    Revert,
    StringTooLong,
    LocalsOverflow,
    /// A CHECKED arithmetic refusal: the result does not fit a word (`DIVMOD128` with `hi ≥ d`). The call fails —
    /// nothing is proven — exactly as a Solidity 0.8 panic aborts, never a wrapped or truncated value.
    Overflow(&'static str),
    /// The opcode is real but this machine cannot PROVE it, so it refuses rather than running it
    /// unprovably. The only members today are `SHA3` (Keccak needs its own precompile table) and
    /// `EXT_CALL_TAIL` (a cross-contract tail call is its own statement, not a step of this one).
    NotProvable(u8),
    /// The interpreter contradicted one of its own tables (e.g. [`stack_effect`]). Never a bytecode fault: a
    /// refusal that names a drift between the machine and the circuit's description of it.
    Internal(&'static str),
}

/// What a call is executed against: the caller identity the host recovered from a PQ auth proof, the
/// block, and the contract. All PUBLIC-BINDABLE — a verifier is told which contract ran and when.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmCtx {
    pub contract_id: [u8; 32],
    pub block_number: u64,
    pub tx_hash: [u8; 32],
    pub caller_wallet: [u8; 32],
    pub caller_subaddress: [u8; 32],
}

/// Bytes of an ML-DSA-65 public key (FIPS 204, Table 2) — the per-`(seed, cid, index)` caller key a DSOL call carries
/// (DSOL-NODE-DOOR-SPEC §6b A1).
pub const DSOL_CALLER_PK_BYTES: usize = 1952;

/// ⭐ DSOL §6b A1 — THE CALLER IDENTITY A CALL RUNS UNDER: `blake3("MUSD/dsol-caller/v1" ‖ pk_c)`, the 32 bytes the wallet
/// puts in [`VmCtx::caller_wallet`] (what `MSG_SENDER` pushes). The ONE spelling the wallet's call builder and the node's
/// DSOL door share, so the door's `stmt.caller == dsol_caller_digest(pk_c)` compares the value the prover bound.
/// `None` for a key that is not ML-DSA-65-sized — a key that cannot verify the call's signature names no caller.
#[must_use]
pub fn dsol_caller_wallet(pk_c: &[u8]) -> Option<[u8; 32]> {
    if pk_c.len() != DSOL_CALLER_PK_BYTES {
        return None;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/dsol-caller/v1");
    h.update(pk_c);
    Some(*h.finalize().as_bytes())
}

/// The statement's `caller` digest for `pk_c`: [`str_digest`] of [`dsol_caller_wallet`] — exactly what
/// `dsol_cpu_air::statement_of` binds from `VmCtx::caller_wallet`. The node's door refuses a call whose statement names
/// any other value.
#[must_use]
pub fn dsol_caller_digest(pk_c: &[u8]) -> Option<Digest> {
    dsol_caller_wallet(pk_c).map(|w| str_digest(&w))
}

/// ⭐ DSOL §6b A1 — THE CALLER'S SUBADDRESS, the same derivation's second output: `blake3("MUSD/dsol-subaddress/v1" ‖
/// pk_c)`, the 32 bytes the wallet puts in [`VmCtx::caller_subaddress`] (what `MSG_SUBADDRESS` pushes). A public function
/// of `pk_c` so the door re-derives it from the carried key — it never needs the wallet's seed. Domain-separated from
/// [`dsol_caller_wallet`], so a contract cannot confuse the two. `None` for a key that is not ML-DSA-65-sized.
#[must_use]
pub fn dsol_caller_subaddress(pk_c: &[u8]) -> Option<[u8; 32]> {
    if pk_c.len() != DSOL_CALLER_PK_BYTES {
        return None;
    }
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/dsol-subaddress/v1");
    h.update(pk_c);
    Some(*h.finalize().as_bytes())
}

/// The statement's `subaddress` digest for `pk_c`: [`str_digest`] of [`dsol_caller_subaddress`] — what `statement_of`
/// binds from `VmCtx::caller_subaddress`, and what the door compares.
#[must_use]
pub fn dsol_caller_subaddress_digest(pk_c: &[u8]) -> Option<Digest> {
    dsol_caller_subaddress(pk_c).map(|s| str_digest(&s))
}

/// ⭐ DSOL §6b A2 — A CALL'S `tx_hash`: `blake3("MUSD/dsol-tx/v1" ‖ fee_nf)`. Known before proving (the fee spend's
/// nullifier is the wallet's own), unique because the nullifier SET refuses a second use of `fee_nf`, and recomputed by
/// the door from the carried fee spend — never the carrying tx's id, which the statement inside it cannot bind.
#[must_use]
pub fn dsol_tx_hash(fee_nf: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/dsol-tx/v1");
    h.update(fee_nf);
    *h.finalize().as_bytes()
}

/// ⭐⭐⭐ WHAT THE CALL DID, AS A SEQUENCE THE CHAIN CAN APPLY — and the reason a contract cannot mint.
///
/// The circuit proves a contract ISSUED these effects. It does NOT prove they are permitted: a syscall
/// that moves value is authorised by the node's own doors (the peg gates, the asset registry, the
/// nullifier set), against chain state, at apply time. That split is deliberate and it is the whole
/// safety argument of this layer — a contract is a PREDICATE and an EFFECT EMITTER, never a vault and
/// never an authority. A VM that decided its own syscalls would be a chain whose money rules are written
/// by whoever deploys a contract.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Effect {
    /// `EMIT` — a log line. Carries only digests, so an event cannot leak a value the rest of the
    /// machine hides.
    Event { topic: Digest, data: Digest, len: u32 },
    /// `NULLIFIER` — a spend tag the contract produced. The node refuses a duplicate against the chain's
    /// nullifier set, exactly as it does for an ordinary spend.
    Nullifier { tag: Digest },
    /// `SSTORE_PRIV` / `MAP_STORE_PRIV` — the slot is confidential, so the node must never surface it.
    PrivateSlot { key: Digest },
    /// `SYSCALL` — the host operation, its argument digest and the result the contract consumed. The node
    /// re-derives the result from its own state; a mismatch refuses the whole call.
    Syscall { sys_op: u16, argv: Digest, argv_len: u32, ret: Digest, ret_len: u32 },
    /// `CALL` — a synchronous cross-contract call the contract ISSUED: the callee's code id (as the string's digest),
    /// the entrypoint, the argument and the returned string the caller consumed, and `callee` =
    /// `H(H(callee_storage_pre, callee_storage_post), callee_effects_digest)`. The node AUTHORISES it by verifying the
    /// callee's own proof and matching its statement to every field here
    /// ([`crate::dsol_cpu_air::authorize_call_chain`]); a callee already on the call path is refused (re-entry).
    Call { code_id: Digest, entry_sel: u32, argv: Digest, argv_len: u32, ret: Digest, ret_len: u32, callee: Digest },
    /// `LIBCALL` — a library the contract ran against ITS OWN storage under its own identity: the library's code id,
    /// entrypoint, argument and return, the caller's root BEFORE the call (`pre`, the library statement's `storage_pre`),
    /// the root AFTER it (`post`, the library's `storage_post`, which the caller's root jumps to) and the library's own
    /// effects digest. The node authorises it against the library's proof; the library's `cid` is the caller's.
    LibCall { code_id: Digest, entry_sel: u32, argv: Digest, argv_len: u32, ret: Digest, ret_len: u32, pre: Digest, post: Digest, effects: Digest },
}

/// The effects fold from the machine's zero seed: `acc' = H(acc, leaf(e))` per effect, in order — what the statement's
/// `effects_digest` is, and what a node recomputes from the effect list a prover ships.
#[must_use]
pub fn fold_effects(effects: &[Effect]) -> Digest {
    fold_effects_from(&[0u64; DIGEST_LANES], effects)
}

/// The effects fold continued from `seed` — a SEGMENT's effects fold starts from its predecessor's `effects_digest`.
#[must_use]
pub fn fold_effects_from(seed: &Digest, effects: &[Effect]) -> Digest {
    effects.iter().fold(*seed, |acc, e| crate::poseidon2_compress::compress(&acc, &effect_leaf(e)))
}

/// The outcome of a proven call: what the contract returned, what it did, and where its storage ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmRun {
    /// O1-FOOTPRINT-REVIEWED: bounded by STR_BYTES_MAX — a return value is one DSOL string, and the
    /// machine refuses `StringTooLong` before a longer one can exist.
    pub ret: Vec<u8>,
    pub ret_digest: Digest,
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX — one effect costs at least one step, and the
    /// budget is checked before every step, so the sequence cannot outrun it. Held only for the duration
    /// of one call; the node applies it and drops it, storing nothing.
    pub effects: Vec<Effect>,
    /// The running fold over [`Effect`]s — the single 32-byte public value that binds the whole effect
    /// sequence into the statement, so a prover cannot drop or reorder one.
    pub effects_digest: Digest,
    pub storage_post: Digest,
    /// The PROVER-side trie the call left (its root is `storage_post`) — what a caller's machine continues from after a
    /// `LIBCALL`, and what the next call of this contract starts from. O1-FOOTPRINT-REVIEWED: held by the prover for the
    /// duration of a call; the node holds only the root.
    pub storage: StorageTrie,
    /// Continuations: the boundary fold this segment opened from (zero: a fresh start) and closed with (zero: a RETURN).
    pub state_in: Digest,
    pub state_out: Digest,
    pub steps: usize,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The trace row — the witness the circuit constrains, one struct per row
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A sponge slot's whole live state: the 16-lane permutation state, the staged rate lanes being filled a
/// byte at a time, and how many bytes have landed in the staging area.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpongeSlot {
    pub state: [u64; 2 * RATE],
    pub lanes: [u64; RATE],
    /// Bytes staged so far, `0..BYTES_PER_BLOCK`. At [`BYTES_PER_BLOCK`] the slot is DUE and the next row
    /// that touches it must be its [`mk::PERM`].
    pub fill: u8,
}

impl SpongeSlot {
    #[must_use]
    pub fn opened(len: usize) -> Self {
        SpongeSlot { state: str_sponge_init(len), lanes: [0u64; RATE], fill: 0 }
    }
    #[must_use]
    pub fn idle() -> Self {
        SpongeSlot { state: [0u64; 2 * RATE], lanes: [0u64; RATE], fill: 0 }
    }
    /// Stage one byte. The byte lands in lane `fill / BYTES_PER_LANE` at sub-position
    /// `fill % BYTES_PER_LANE` — the same packing [`pack_lane`] performs, expressed one byte at a time so
    /// the circuit can constrain it with a shift rather than a re-pack.
    pub fn feed(&mut self, b: u8) {
        let i = self.fill as usize;
        let lane = i / BYTES_PER_LANE;
        let sub = i % BYTES_PER_LANE;
        self.lanes[lane] += u64::from(b) << (8 * sub);
        self.fill += 1;
    }
    /// Absorb the staged lanes and permute — the one place a sponge's state moves.
    pub fn perm(&mut self) {
        self.state = str_absorb_block(&self.state, &self.lanes);
        self.lanes = [0u64; RATE];
        self.fill = 0;
    }
    /// The digest a closed sponge has produced.
    #[must_use]
    pub fn digest(&self) -> Digest {
        let mut d = [0u64; DIGEST_LANES];
        d.copy_from_slice(&self.state[..DIGEST_LANES]);
        d
    }
}

/// ⭐⭐⭐ ONE TRACE ROW. The circuit's whole job is: given this row and the next, is the transition one
/// the DSOL machine could have made? Every field here becomes committed columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Program counter BEFORE the row.
    pub pc: u32,
    /// The MACRO opcode this row belongs to.
    pub op: u8,
    /// Which [`mk`] kind this row is.
    pub micro: u8,
    /// The whole stack BEFORE the row — committed in full, which is what removes the need for a stack
    /// memory argument.
    pub stack: [VmVal; STACK_DEPTH],
    /// Live stack height BEFORE the row.
    pub sp: u8,
    /// The locals frame BEFORE the row.
    pub locals: [VmVal; LOCALS_MAX],
    /// The three sponge slots BEFORE the row.
    pub sponges: [SpongeSlot; SPONGES],
    /// The content byte this row moves (`mk::FEED` only).
    pub byte: u8,
    /// Which sponges the byte enters. A `CONCAT` feeds the same byte to a verifier AND to the producer,
    /// which is exactly what ties the output string to its inputs — no fingerprint, no second argument.
    pub feed: [bool; SPONGES],
    /// Which sponge permutes this row (`mk::PERM` only); [`SPONGES`] means none.
    pub perm: usize,
    /// Which sponges were OPENED (reset to `SpongeSlot::opened(len)`) between the previous row and this one — this
    /// row's pre-state is the fresh sponge. L6 binds a fresh state to `init(len)` here and refuses any other jump; the
    /// machine sets the flag in `supply` / `produce` / CONCAT's own open, never by a row of its own.
    pub open: [bool; SPONGES],
    /// ⭐ S2 — THE CONTENT ACCUMULATORS, before the row: what this opcode's bytes have built so far, in the shape its
    /// content law reads at the target row. `U64_TO_BYTES` / `U64_FROM_BYTES`: the four 16-bit limbs of the first eight
    /// bytes (`acc[l] = byte_{2l} + 256·byte_{2l+1}`). POSEIDON / NULLIFIER / COMMIT_U64: the 248 bits of the produced
    /// `digest_to_bytes` form re-packed into lanes — the low 24 bits of lane `l` in `acc[l]`, its top 7 in `acc[8 + l]`,
    /// so `lane_l = acc[l] + 2^24·acc[8 + l]` is exact and a canonicity law can see the top bits. Zeroed on the row that
    /// opens the opcode's accumulating sponge ([`acc_sponge`]), advanced by [`s2_accumulate`] on every byte that sponge
    /// takes, frozen otherwise (stale values carry harmlessly until the next opener). Replaced the 32-byte shift window
    /// (`hb`) and the 64-bit `acc`, which no law ever read.
    pub s2acc: [u64; S2_ACC],
    /// Bytes still to move for this opcode — the loop counter the circuit decrements. Set to the produced length when
    /// sponge C opens, −1 per byte C takes (CONCAT included), frozen otherwise, and 0 on the opcode's final row — so C
    /// absorbed exactly `plen` bytes after its last open. (A storage access reuses it as its path countdown.)
    pub remaining: u32,
    /// The length of the string this opcode PRODUCES (through sponge C), constant across its rows and 0 for an
    /// opcode that produces nothing — what L6 opens sponge C with and what L3's landing law binds the pushed
    /// string's `len` to.
    pub plen: u32,
    /// The storage root BEFORE the row.
    pub storage_root: Digest,
    /// The effects fold BEFORE the row.
    pub effects_acc: Digest,
    /// S2 — per sponge, before the row: `true` from the row that opens it until its first permutation, so a byte's
    /// POSITION in the string is `fill + BYTES_PER_BLOCK·(1 − fb)` for the two blocks a 32-byte produce spans (the
    /// content laws read it; the fill alone repeats after a permutation).
    pub fb: [bool; SPONGES],
    /// S2 — CONCAT's phase, before the row: `false` from the row that opens C until B opens, `true` after. A's bytes
    /// may only enter while it is `false`, B's only while it is `true` — so C's content is A's bytes THEN B's, never an
    /// interleaving. Stale outside CONCAT (the opener's row pins it to 0).
    pub cph: bool,
    /// A Merkle sibling (`mk::PATH` rows of a storage access).
    pub path_sib: Digest,
    /// Which side the sibling sits on.
    pub path_dir: bool,
    /// The running node of the PRE-state path — it must fold to the storage root the row carries.
    pub path_old: Digest,
    /// The running node of the POST-state path — it becomes the storage root at the access's finish. A
    /// read folds both through the same siblings, so a read cannot move the root.
    pub path_new: Digest,
    /// L8: which image this `LEAF` / `PATH` row hashes — `false` the PRE-image (old), `true` the POST-image (new;
    /// write rows only). A write lays every level twice, old then new, through the same sibling.
    pub path_phase: bool,
    /// L8: whether the accessed slot EXISTS in the pre-state. An absent slot's leaf is the empty digest and reads 0.
    pub path_present: bool,
    /// L8: the slot key this access walks — bound to the stack operand on the LEAF row and rebuilt from the path's
    /// direction bits at its exit.
    pub path_key: Digest,
    /// L8: the slot's PRE-state value (what a read returns; `Word(0)` when absent), carried onto the FINISH row so
    /// the pushed result can be bound to the leaf that was proven.
    pub path_val: VmVal,
    /// L8: the per-lane key-bit accumulators BEFORE this row — lane `d` collects the direction bits of its 31
    /// levels, MSB first, and equals `path_key[d]` when the path exits.
    pub kacc: Digest,
    /// L8: the lane the NEXT consumed direction bit belongs to (`DIGEST_LANES` = no path in flight).
    pub klane: u8,
    /// L9: the two inputs of this `EFX` row's block, as the machine resolved them from [`efx_plan`]. The circuit
    /// re-derives each from its named source; the machine's copy is what lays the block.
    pub efx_in: [Digest; 2],
    /// L9: the two carries BEFORE this row (`EfxSrc::Tmp0` / `Tmp1`).
    pub etmp: [Digest; 2],
    /// L9: which stage of its effect's schedule this `EFX` row is (0-based; `EFX_STAGES_MAX` = none).
    pub estage: u8,
    /// A `CALL`'s callee binding ([`callee_binding`]), set from the host's answer before the opcode's first row and
    /// frozen across its rows (the circuit's `C_CALLEE`); a `LIBCALL`'s library POST root; stale and unread on every
    /// other opcode's rows.
    pub callee: Digest,
    /// A `LIBCALL`'s library effects digest (the circuit's `C_LIBEFX`), frozen across its rows; stale elsewhere.
    pub lib_effects: Digest,
    /// Continuations: the boundary fold BEFORE this row (`C_BSTATE`) — zero on a run's first row, then the running
    /// Poseidon2 fold over the absorbed groups; unread off BOUND rows.
    pub bstate: Digest,
    /// Continuations: which eight-lane group of the carried state this BOUND row absorbs (`0..BOUND_GROUPS`); 0 elsewhere.
    pub bstage: u8,
    /// Continuations: `false` for the in-run (a segment opening at row 0), `true` for the out-run (closing at the last row).
    pub bout: bool,
}

/// The whole witness of one call.
#[derive(Debug, Clone)]
pub struct VmTrace {
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX — the budget is decremented and checked before
    /// every row, so the trace cannot outrun it. It is a caller's witness, discarded after proving; the
    /// node never holds one.
    pub steps: Vec<Step>,
    /// The final machine outcome the statement is built from.
    pub run: VmRun,
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Storage: a FIXED-DEPTH sparse Merkle trie. A contract's whole storage is 32 bytes on the node at any
// size, and one access costs STORAGE_DEPTH rows — the same shape `merkle_path_air` proves elsewhere.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The empty subtree digest at every level — computed once, so an absent slot has ONE spelling.
#[must_use]
pub fn empty_subtree(level: usize) -> Digest {
    static CACHE: std::sync::OnceLock<Vec<Digest>> = std::sync::OnceLock::new();
    let c = CACHE.get_or_init(|| {
        let mut v = vec![[0u64; DIGEST_LANES]];
        for i in 0..STORAGE_DEPTH {
            let prev = v[i];
            v.push(crate::poseidon2_compress::compress(&prev, &prev));
        }
        v
    });
    c[level.min(STORAGE_DEPTH)]
}

/// A slot's leaf digest: the KEY is folded in with the value, so an empty slot and a slot holding zero
/// are different leaves and a prover cannot move a value between keys.
#[must_use]
pub fn slot_leaf(key: &Digest, val: &VmVal) -> Digest {
    crate::poseidon2_compress::compress(key, &leaf_value_lanes(val))
}

/// The value half of a slot leaf — the lanes a `mk::LEAF` row's block hashes beside the key (L8). ONE encoding for
/// the machine and the circuit: a word is `[0, limb0, limb1, limb2, limb3, 0, 0, 0]`, a string one compression of its
/// digest with `[1, len]` (the circuit's second LEAF block, L8b).
///
/// ⛔ A WORD IS ENCODED AS ITS FOUR 16-BIT LIMBS, never as one lane: a lane is a 31-bit field element, so a u64 in one
/// lane is reduced mod p and two different words share a leaf (the encoding before 2026-09-29 did exactly that). The
/// limbs are the stack slot's own word columns, which is what lets the LEAF row hash the value the row holds.
#[must_use]
pub fn leaf_value_lanes(val: &VmVal) -> Digest {
    match val {
        VmVal::Word(w) => crate::poseidon2_compress::lanes_of(&[0, *w & 0xffff, (*w >> 16) & 0xffff, (*w >> 32) & 0xffff, *w >> 48]),
        VmVal::Str { digest, len } => {
            crate::poseidon2_compress::compress(digest, &crate::poseidon2_compress::lanes_of(&[1, u64::from(*len)]))
        }
    }
}

/// Bit `level` of a key — the path direction at that level.
///
/// ⛔ NO WRAP. This used to reduce `level` modulo the key width, which is silent aliasing: at a depth
/// past the key, two different levels would read the SAME bit and a path could fold through a direction
/// the key never chose. [`STORAGE_DEPTH`] is now exactly the key width, so every level reads its own bit
/// and a level past the end is a caller error the assert names rather than an alias.
#[must_use]
pub fn key_bit(key: &Digest, level: usize) -> bool {
    debug_assert!(level < DIGEST_LANES * 31, "storage path level {level} is past the key's own width");
    // LANE-INTERLEAVED: level `i` reads bit `i / DIGEST_LANES` of lane `i % DIGEST_LANES`. The fold walks levels
    // `STORAGE_DEPTH-1` down to `0`, so lane `d` sees its bits 30, 29, …, 0 in that order — MSB first — and the
    // circuit rebuilds every lane with ONE rotating lane one-hot and `acc' = 2·acc + bit` (L8), no level counter
    // arithmetic. Lane-major order would need a per-lane 31-row counter to know when a lane completes.
    let lane = level % DIGEST_LANES;
    let bit = level / DIGEST_LANES;
    (key[lane] >> bit) & 1 == 1
}

/// A contract's storage, prover-side: the live slots plus the derived root. The NODE holds only the root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StorageTrie {
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX — this is the PROVER's witness for one call
    /// (the slots that call touches), built and dropped inside `run`. The node's storage is the 32-byte
    /// root alone, which is what makes contract storage a no-growth axis.
    pub slots: std::collections::BTreeMap<[u64; DIGEST_LANES], VmVal>,
    /// The bytes of every string a slot holds, by digest (D4, `dsol_blob_air`): a call that reads a stored string
    /// re-supplies its bytes from here, and a call's blob carries the bytes of every string it writes, so whoever holds
    /// the contract's key rebuilds them from the chain. NOT part of the root (a slot commits to the digest, which binds
    /// the bytes). O1-FOOTPRINT-REVIEWED: at most one entry a string-valued slot, each at most STR_BYTES_MAX; prover-side.
    pub contents: std::collections::BTreeMap<[u64; DIGEST_LANES], Vec<u8>>,
}

impl StorageTrie {
    #[must_use]
    pub fn get(&self, key: &Digest) -> Option<VmVal> {
        self.slots.get(key).copied()
    }

    /// The sibling at each level for `key`, root-ward last. O(depth × live slots) on the PROVER only.
    #[must_use]
    pub fn path(&self, key: &Digest) -> Vec<Digest> {
        let mut sibs = Vec::with_capacity(STORAGE_DEPTH);
        for level in 0..STORAGE_DEPTH {
            sibs.push(self.subtree_at(key, level, true));
        }
        sibs
    }

    /// The digest of the subtree that sits BESIDE `key`'s path at `level` (or ON it when `sibling` is
    /// false). Derived from the live slots — an absent branch collapses to [`empty_subtree`].
    fn subtree_at(&self, key: &Digest, level: usize, sibling: bool) -> Digest {
        // The prefix that selects the subtree: levels 0..level of `key`, with the bit at `level` flipped
        // when we want the sibling.
        let mut want: Vec<bool> = (0..level).map(|l| key_bit(key, l)).collect();
        want.push(if sibling { !key_bit(key, level) } else { key_bit(key, level) });
        let members: Vec<(&[u64; DIGEST_LANES], &VmVal)> = self
            .slots
            .iter()
            .filter(|(k, _)| (0..=level).all(|l| key_bit(k, l) == want[l]))
            .collect();
        Self::fold_subtree(&members, level + 1)
    }

    /// Fold a set of slots that all share the first `depth` path bits into one subtree digest.
    fn fold_subtree(members: &[(&[u64; DIGEST_LANES], &VmVal)], depth: usize) -> Digest {
        if members.is_empty() {
            return empty_subtree(STORAGE_DEPTH - depth);
        }
        if depth == STORAGE_DEPTH {
            // One key per bucket BY CONSTRUCTION: the path reads every bit of the key, so two distinct
            // keys diverge before here. `insert_checked` holds the same claim fail-closed.
            debug_assert_eq!(members.len(), 1, "two keys reached one full-width bucket");
            return slot_leaf(members[0].0, members[0].1);
        }
        let (l, r): (Vec<_>, Vec<_>) = members.iter().partition(|(k, _)| !key_bit(k, depth));
        let lh = Self::fold_subtree(&l, depth + 1);
        let rh = Self::fold_subtree(&r, depth + 1);
        crate::poseidon2_compress::compress(&lh, &rh)
    }

    /// Insert, refusing a key that shares every one of its [`STORAGE_DEPTH`] path bits with a DIFFERENT
    /// key.
    ///
    /// ⭐ AT THE FULL KEY WIDTH THIS IS UNREACHABLE — two distinct canonical digests differ in some bit,
    /// and the path reads every bit, so no two keys can share a bucket. It stays as a fail-closed
    /// assertion rather than being deleted: it is the one place that would catch a future shortening of
    /// [`STORAGE_DEPTH`], and a wrong storage root is a fork, so the check is worth its one comparison.
    pub fn insert_checked(&mut self, key: &Digest, val: VmVal) -> Result<(), VmError> {
        let clash = self
            .slots
            .keys()
            .any(|k| k != key && (0..STORAGE_DEPTH).all(|l| key_bit(k, l) == key_bit(key, l)));
        if clash {
            return Err(VmError::BadBytecode("two storage keys collide on the whole path"));
        }
        self.slots.insert(*key, val);
        Ok(())
    }

    /// The storage root.
    #[must_use]
    pub fn root(&self) -> Digest {
        let members: Vec<(&[u64; DIGEST_LANES], &VmVal)> = self.slots.iter().collect();
        Self::fold_subtree(&members, 0)
    }
}

/// Fold a leaf up a path — the SAME recurrence the circuit's `mk::PATH` rows constrain.
#[must_use]
pub fn fold_path(leaf: Digest, key: &Digest, sibs: &[Digest]) -> Digest {
    let mut node = leaf;
    for (level, sib) in sibs.iter().enumerate().take(STORAGE_DEPTH) {
        node = if key_bit(key, STORAGE_DEPTH - 1 - level) {
            crate::poseidon2_compress::compress(sib, &node)
        } else {
            crate::poseidon2_compress::compress(&node, sib)
        };
    }
    node
}

/// One effect's leaf in the effects fold. The DISCRIMINANT rides the leaf, so a prover cannot re-read an
/// event as a nullifier or a private-slot mark as a syscall.
#[must_use]
pub fn effect_leaf(e: &Effect) -> Digest {
    use crate::poseidon2_compress::{compress, lanes_of};
    match e {
        Effect::Event { topic, data, len } => {
            compress(&compress(&lanes_of(&[1]), topic), &compress(data, &lanes_of(&[u64::from(*len)])))
        }
        Effect::Nullifier { tag } => compress(&lanes_of(&[2]), tag),
        Effect::PrivateSlot { key } => compress(&lanes_of(&[3]), key),
        Effect::Syscall { sys_op, argv, argv_len, ret, ret_len } => compress(
            &compress(&lanes_of(&[4, u64::from(*sys_op)]), &compress(argv, &lanes_of(&[u64::from(*argv_len)]))),
            &compress(ret, &lanes_of(&[u64::from(*ret_len)])),
        ),
        Effect::Call { code_id, entry_sel, argv, argv_len, ret, ret_len, callee } => compress(
            &compress(
                &lanes_of(&[5, u64::from(*entry_sel), u64::from(*ret_len)]),
                &compress(code_id, &compress(argv, &lanes_of(&[u64::from(*argv_len)]))),
            ),
            &compress(ret, callee),
        ),
        Effect::LibCall { code_id, entry_sel, argv, argv_len, ret, ret_len, pre, post, effects } => {
            // the chain the LIBCALL schedule computes with one temporary, stage for stage
            let x = compress(code_id, argv);
            let x = compress(&lanes_of(&[6, u64::from(*entry_sel), u64::from(*ret_len), u64::from(*argv_len)]), &x);
            let x = compress(&x, ret);
            let x = compress(&x, effects);
            let x = compress(&x, pre);
            compress(&x, post)
        }
    }
}

/// DEPLOY IS A SYSCALL (plan item 3, 2026-09-29): `SYSCALL SYS_DEPLOY` with the child's whole bytecode as the argument
/// returns the child's 32-byte code id (`blake3(code)`), which the contract may `CALL` in the same execution. blake3 is
/// not in-circuit, and need not be: L9b binds the argument (the code string's digest and length) and the returned id into
/// the effects fold, the node's host computes blake3 from the code the prover ships and registers it, and at apply the
/// node RE-RUNS the syscall and compares — the circuit proves ISSUED, the node AUTHORISES, as for every syscall.
pub const SYS_DEPLOY: u16 = 2;

/// What a `CALL` host answers with: the callee's returned bytes and the three digests the caller's effect binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallAnswer {
    pub ret: Vec<u8>,
    pub storage_pre: Digest,
    pub storage_post: Digest,
    pub effects_digest: Digest,
}

/// The callee binding a `CALL` effect carries: `H(H(storage_pre, storage_post), effects_digest)` — ONE spelling for
/// the machine, the circuit's layer and the node's matcher.
#[must_use]
pub fn callee_binding(storage_pre: &Digest, storage_post: &Digest, effects_digest: &Digest) -> Digest {
    use crate::poseidon2_compress::compress;
    compress(&compress(storage_pre, storage_post), effects_digest)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The host boundary. A syscall's RESULT comes from the chain, never from the contract — see `Effect`.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// What answers a `SYSCALL`. The prover's implementation reads its node; the verifying node re-derives
/// every recorded syscall against its OWN state at apply time and refuses the call on a mismatch, so a
/// lying host buys nothing.
pub trait SyscallHost {
    fn call(&mut self, sys_op: u16, argv: &[u8]) -> Option<Vec<u8>>;
    /// Answer a `CALL`: run (or look up) the callee `code_id`'s `entry_sel` on `argv` and hand back its return bytes and
    /// the digests its statement carries. The default REFUSES, so a predicate host stays a predicate host; the node's
    /// host proves the callee itself and the verifier later matches that proof to the effect.
    fn call_contract(&mut self, code_id: [u8; 32], entry_sel: u32, argv: &[u8]) -> Option<CallAnswer> {
        let _ = (code_id, entry_sel, argv);
        None
    }
    /// Answer a `LIBCALL`: run (or look up) the library `code_id`'s `entry_sel` on `argv` AGAINST `storage` — the caller's
    /// live trie — under the caller's identity, and hand back the answer (its `storage_pre` must be `storage`'s root) and
    /// the trie the library left, which becomes the caller's. The default REFUSES.
    fn call_library(&mut self, code_id: [u8; 32], entry_sel: u32, argv: &[u8], storage: StorageTrie) -> Option<(CallAnswer, StorageTrie)> {
        let _ = (code_id, entry_sel, argv, storage);
        None
    }
}

/// A host that refuses every syscall. The right default for a PREDICATE call — a contract that only
/// decides whether a settlement is permitted needs no host at all, and a predicate that tries to reach
/// one is refused rather than silently given an empty answer.
pub struct NoHost;
impl SyscallHost for NoHost {
    fn call(&mut self, _sys_op: u16, _argv: &[u8]) -> Option<Vec<u8>> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The machine
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// The entrypoint selector for a name: the first four LE bytes of blake3(name).
#[must_use]
/// `(pops, pushes)` of one opcode's WHOLE execution (all of its rows) — THE ONE TABLE the circuit's L3 STACK law
/// is written against. The interpreter asserts its own `sp` movement against it after every opcode (`run`), so a
/// machine that drifts from this table refuses instead of executing something the circuit describes differently.
/// `SWAP` moves nothing and permutes the top two; `None` for the two opcodes the circuit has no law for.
pub const fn stack_effect(o: u8) -> Option<(u8, u8)> {
    Some(match o {
        op::PUSH_U64 | op::PUSH_BYTES | op::DUP | op::LOCAL_GET | op::BLOCK_NUMBER => (0, 1),
        op::MSG_SENDER | op::MSG_SUBADDRESS | op::CONTRACT_ID | op::TX_HASH => (0, 1),
        op::POP | op::JUMPI | op::LOCAL_SET => (1, 0),
        op::SWAP | op::JUMP | op::RETURN | op::REVERT | op::ALLOC_LOCALS | op::BOUND => (0, 0),
        op::NOT | op::BYTES_LEN | op::U64_FROM_BYTES | op::U64_TO_BYTES | op::U64_TO_DEC_STR => (1, 1),
        op::POSEIDON | op::NULLIFIER | op::SYSCALL | op::SLOAD => (1, 1),
        op::ADD_U64 | op::SUB_U64 | op::MUL_U64 | op::DIV_U64 | op::MOD_U64 | op::MUL_HI => (2, 1),
        op::ADC | op::SBB | op::DIVMOD128 => (3, 2),
        op::CALL | op::LIBCALL => (2, 1),
        op::LT | op::EQ | op::AND | op::OR | op::STR_EQ | op::CONCAT | op::COMMIT_U64 | op::MAP_LOAD => (2, 1),
        op::EMIT | op::SSTORE | op::SSTORE_PRIV => (2, 0),
        op::MAP_STORE | op::MAP_STORE_PRIV => (3, 0),
        _ => return None,
    })
}

/// Where a sponge's OPEN length comes from, per `(opcode, sponge)` — THE ONE TABLE L6 reads and `supply` /
/// `produce` assert against. `Slot(k)`: the string in stack slot `k` (pre-state of the opcode's rows) is what the
/// sponge re-absorbs, so it opens with that slot's `len`. `Produced`: the opcode produces a string through this sponge
/// and opens it with [`Step::plen`]. `Never`: this opcode never opens this sponge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenLen {
    Never,
    Slot(u8),
    Produced,
}

#[must_use]
pub const fn open_source(o: u8, s: usize) -> OpenLen {
    match (o, s) {
        (op::CONCAT, SPONGE_A) => OpenLen::Slot(1),
        (op::CONCAT, SPONGE_B) => OpenLen::Slot(0),
        (op::CONCAT, SPONGE_C) => OpenLen::Produced,
        (op::U64_FROM_BYTES | op::POSEIDON | op::NULLIFIER | op::COMMIT_U64, SPONGE_A) => OpenLen::Slot(0),
        (op::POSEIDON | op::NULLIFIER | op::COMMIT_U64, SPONGE_C) => OpenLen::Produced,
        (op::U64_TO_BYTES | op::U64_TO_DEC_STR | op::RETURN | op::SYSCALL | op::CALL | op::LIBCALL, SPONGE_C) => OpenLen::Produced,
        _ => OpenLen::Never,
    }
}

/// S2 — the width of the content accumulators ([`Step::s2acc`]): eight lanes' low 24 bits and eight lanes' top 7 bits
/// for a digest producer; the first four double as the word limbs of `U64_TO_BYTES` / `U64_FROM_BYTES`.
pub const S2_ACC: usize = 16;

/// S2 — the sponge whose OPEN zeroes an opcode's accumulators and whose bytes advance them: C for the producers whose
/// content law reads what they produced, A for `U64_FROM_BYTES` (it reads what it re-absorbed). `None` for an opcode
/// with no content accumulator — its rows leave the accumulators exactly as they were.
#[must_use]
pub const fn acc_sponge(o: u8) -> Option<usize> {
    match o {
        op::U64_TO_BYTES | op::U64_TO_DEC_STR | op::POSEIDON | op::NULLIFIER | op::COMMIT_U64 => Some(SPONGE_C),
        op::U64_FROM_BYTES => Some(SPONGE_A),
        _ => None,
    }
}

/// S2 — ONE byte's contribution to the content accumulators, the machine's and the circuit's one rule. `fill` is the
/// sponge's staged count before the byte (its position in the current block), `fb` whether the sponge is still in
/// its first block, so the byte's position in the string is `fill + BYTES_PER_BLOCK·(1 − fb)` over the two blocks a
/// 32-byte produce spans.
/// - `U64_TO_BYTES` (C) / `U64_FROM_BYTES` (A): positions 0..8 of the first block land in limb `pos / 2` at byte
///   `pos % 2` — the word's four 16-bit limbs, exactly the stack's representation.
/// - POSEIDON / NULLIFIER / COMMIT_U64 (C): bit `k` of the byte at position `j` is bit `g = 8j + k` of the produced
///   `digest_to_bytes` form, i.e. bit `g mod 31` of lane `g / 31` (`digest_to_bytes` packs 31-bit lanes contiguously;
///   bits 248..256 are the zero byte 31): the low 24 bits of a lane accumulate in `acc[lane]`, its top 7 in
///   `acc[8 + lane]`.
/// - `U64_TO_DEC_STR` (C): Horner over the four 16-bit limbs — `P' = 10·P + (byte − 48)`; the circuit proves each step
///   as ONE division of `P'` by 10 with remainder `byte − 48` (so the remainder bound IS the digit range). Wrapping, so
///   a forger's schedule stays total: what overflows a word is what the division block refuses.
/// Every other (opcode, sponge) pair contributes nothing.
pub fn s2_accumulate(o: u8, s: usize, fill: usize, fb: bool, byte: u8, acc: &mut [u64; S2_ACC]) {
    let pos = fill + if fb { 0 } else { BYTES_PER_BLOCK };
    match (o, s) {
        (op::U64_TO_BYTES, SPONGE_C) | (op::U64_FROM_BYTES, SPONGE_A) if pos < 8 => {
            acc[pos / 2] += u64::from(byte) << (8 * (pos % 2));
        }
        (op::U64_TO_DEC_STR, SPONGE_C) => {
            // the stack's four 16-bit limbs, as `leaf_value_lanes` spells a word
            let p = (0..4).fold(0u64, |v, l| v | (acc[l] << (16 * l)));
            let next = p.wrapping_mul(10).wrapping_add(u64::from(byte).wrapping_sub(48));
            for l in 0..4 {
                acc[l] = (next >> (16 * l)) & 0xffff;
            }
        }
        (op::POSEIDON | op::NULLIFIER | op::COMMIT_U64, SPONGE_C) => {
            for k in 0..8 {
                let g = 8 * pos + k;
                if g < 31 * DIGEST_LANES && (byte >> k) & 1 == 1 {
                    let (lane, r) = (g / 31, g % 31);
                    if r < 24 {
                        acc[lane] += 1u64 << r;
                    } else {
                        acc[DIGEST_LANES + lane] += 1u64 << (r - 24);
                    }
                }
            }
        }
        _ => {}
    }
}

/// The FIXED produced length of an opcode that produces through sponge C, when the opcode fixes it: 8 for a word's
/// LE bytes, 32 for a digest's bytes. `None` when the length is decided by the operands (CONCAT: the two lengths'
/// sum; RETURN: 8 for a word, 0 for an empty stack; `U64_TO_DEC_STR`: the digit count) — those are bound in the
/// circuit by their own law, not by this table.
#[must_use]
pub const fn produce_len(o: u8) -> Option<u32> {
    match o {
        op::U64_TO_BYTES => Some(8),
        op::POSEIDON | op::NULLIFIER | op::COMMIT_U64 => Some(32),
        _ => None,
    }
}

pub fn entry_hash(name: &[u8]) -> u32 {
    let b = blake3::hash(name);
    let b = b.as_bytes();
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The only bytecode version this machine accepts.
pub const DSOL_VERSION: u8 = 0x02;

/// Parse the v2 header: `[0]=version`, `[1..5]=entry count u32 LE`, then `count × {nameHash | pc}`.
/// Fail-closed on a wrong version or a truncated table.
pub fn parse_entries(code: &[u8]) -> Result<Vec<(u32, u32)>, VmError> {
    if code.len() < 5 {
        return Err(VmError::BadBytecode("short"));
    }
    if code[0] != DSOL_VERSION {
        return Err(VmError::BadBytecode("version"));
    }
    let count = u32::from_le_bytes([code[1], code[2], code[3], code[4]]) as usize;
    let end = 5usize
        .checked_add(count.checked_mul(8).ok_or(VmError::BadBytecode("entry table"))?)
        .ok_or(VmError::BadBytecode("entry table"))?;
    if end > code.len() {
        return Err(VmError::BadBytecode("entry table overruns"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = 5 + i * 8;
        out.push((
            u32::from_le_bytes([code[o], code[o + 1], code[o + 2], code[o + 3]]),
            u32::from_le_bytes([code[o + 4], code[o + 5], code[o + 6], code[o + 7]]),
        ));
    }
    Ok(out)
}

struct Machine<'a, H: SyscallHost> {
    code: &'a [u8],
    ctx: VmCtx,
    pc: u32,
    stack: [VmVal; STACK_DEPTH],
    sp: u8,
    locals: [VmVal; LOCALS_MAX],
    sponges: [SpongeSlot; SPONGES],
    storage: StorageTrie,
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX × STR_BYTES_MAX — the PROVER's content witness
    /// for the strings this one call touches, built and dropped inside `run`. It is never a constraint
    /// input (every byte it yields is re-absorbed and re-checked), and the node never holds one.
    strings: std::collections::HashMap<[u64; DIGEST_LANES], Vec<u8>>,
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX — one effect costs at least one step and the
    /// budget is checked before every step.
    effects: Vec<Effect>,
    effects_acc: Digest,
    /// The storage root NOW — recomputed only where storage changes (a slot write, a library's post-state). MEASURED
    /// 2026-09-29: `row()` folded the whole trie for every recorded row (`StorageTrie::root` is O(slots × depth)
    /// compressions), 149 µs of a 149 µs step — the machine was 189 ms of a 821 ms prove for 1,270 rows.
    root_now: Digest,
    budget: u64,
    /// O1-FOOTPRINT-REVIEWED: bounded by STEP_BUDGET_MAX — `row` decrements the budget and refuses at
    /// zero, so the trace cannot be longer than the budget however the program branches.
    steps: Vec<Step>,
    // Per-row scratch that the emitters set just before pushing a row.
    byte: u8,
    feed: [bool; SPONGES],
    perm: usize,
    open: [bool; SPONGES],
    s2acc: [u64; S2_ACC],
    remaining: u32,
    plen: u32,
    fb: [bool; SPONGES],
    cph: bool,
    path_sib: Digest,
    path_dir: bool,
    path_old: Digest,
    path_new: Digest,
    path_phase: bool,
    path_present: bool,
    path_key: Digest,
    path_val: VmVal,
    kacc: Digest,
    klane: u8,
    efx_in: [Digest; 2],
    etmp: [Digest; 2],
    estage: u8,
    callee: Digest,
    lib_effects: Digest,
    bstate: Digest,
    bstage: u8,
    bout: bool,
    host: &'a mut H,
}

/// Where a machine's `run` loop stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// A RETURN: the returned bytes and their digest.
    Returned(Vec<u8>, Digest),
    /// A CUT between two opcodes: the boundary fold of the state that crosses it (`state_out`).
    Cut(Digest),
}

/// What a segment hands to its successor (prover-side only): the carried machine state, the strings the next segment
/// may re-supply, and the boundary fold the successor's in-run must reproduce.
#[derive(Debug, Clone)]
pub struct Resume {
    pub pc: u32,
    pub stack: [VmVal; STACK_DEPTH],
    pub sp: u8,
    pub locals: [VmVal; LOCALS_MAX],
    pub storage: StorageTrie,
    pub effects_acc: Digest,
    /// O1-FOOTPRINT-REVIEWED: bounded by the segment's own rows (every string here was produced or supplied in it or its
    /// predecessors, each at most STR_BYTES_MAX); prover-side, dropped after the chain is proven.
    pub strings: std::collections::HashMap<Digest, Vec<u8>>,
    /// The fold the predecessor's out-run produced — what this segment's `state_in` is.
    pub state: Digest,
}

/// The lanes of one stack or local SLOT as the circuit lays them: `[tag, limb₀..limb₃, digest₀..digest₇, len]` — a word is
/// tag 0 with its four 16-bit limbs, a string tag 1 with its digest and length. ONE spelling for the layout and for the
/// boundary fold that absorbs slots.
pub const SLOT_LANES: usize = 1 + 4 + DIGEST_LANES + 1;
#[must_use]
pub fn slot_lanes(v: &VmVal) -> [u64; SLOT_LANES] {
    let mut out = [0u64; SLOT_LANES];
    match v {
        VmVal::Word(w) => {
            for l in 0..4 {
                out[1 + l] = (w >> (16 * l)) & 0xffff;
            }
        }
        VmVal::Str { digest, len } => {
            out[0] = 1;
            out[5..5 + DIGEST_LANES].copy_from_slice(digest);
            out[5 + DIGEST_LANES] = u64::from(*len);
        }
    }
    out
}

/// The carried state a segment cut crosses, as lanes in the ONE order the machine folds and the circuit absorbs: pc, sp,
/// the sixteen stack slots, the sixteen locals, the storage root, the effects fold — every other column is per-opcode
/// scratch or a stale value that no law reads across an opcode boundary. Padded with zeros to whole groups of eight.
pub const BOUND_LANES: usize = 2 + STACK_DEPTH * SLOT_LANES + LOCALS_MAX * SLOT_LANES + 2 * DIGEST_LANES;
/// Groups of eight lanes the boundary fold absorbs, one per BOUND row.
pub const BOUND_GROUPS: usize = BOUND_LANES.div_ceil(DIGEST_LANES);
#[must_use]
pub fn bound_lanes(pc: u32, sp: u8, stack: &[VmVal; STACK_DEPTH], locals: &[VmVal; LOCALS_MAX], root: &Digest, eacc: &Digest) -> Vec<u64> {
    let mut v = Vec::with_capacity(BOUND_GROUPS * DIGEST_LANES);
    v.push(u64::from(pc));
    v.push(u64::from(sp));
    for s in stack.iter().chain(locals.iter()) {
        v.extend_from_slice(&slot_lanes(s));
    }
    v.extend_from_slice(root);
    v.extend_from_slice(eacc);
    debug_assert_eq!(v.len(), BOUND_LANES);
    v.resize(BOUND_GROUPS * DIGEST_LANES, 0);
    v
}
/// Group `k` of the carried state as a digest — the right input of BOUND row `k`'s block.
#[must_use]
pub fn bound_group(lanes: &[u64], k: usize) -> Digest {
    let mut g = [0u64; DIGEST_LANES];
    g.copy_from_slice(&lanes[k * DIGEST_LANES..(k + 1) * DIGEST_LANES]);
    g
}

impl<'a, H: SyscallHost> Machine<'a, H> {
    fn row(&mut self, op: u8, micro: u8) -> Result<(), VmError> {
        if self.budget == 0 {
            return Err(VmError::BudgetExhausted);
        }
        self.budget -= 1;
        self.steps.push(Step {
            pc: self.pc,
            op,
            micro,
            stack: self.stack,
            sp: self.sp,
            locals: self.locals,
            sponges: self.sponges,
            byte: self.byte,
            feed: self.feed,
            perm: self.perm,
            open: self.open,
            s2acc: self.s2acc,
            remaining: self.remaining,
            plen: self.plen,
            storage_root: self.root_now,
            effects_acc: self.effects_acc,
            fb: self.fb,
            cph: self.cph,
            path_sib: self.path_sib,
            path_dir: self.path_dir,
            path_old: self.path_old,
            path_new: self.path_new,
            path_phase: self.path_phase,
            path_present: self.path_present,
            path_key: self.path_key,
            path_val: self.path_val,
            kacc: self.kacc,
            klane: self.klane,
            efx_in: self.efx_in,
            etmp: self.etmp,
            estage: self.estage,
            callee: self.callee,
            lib_effects: self.lib_effects,
            bstate: self.bstate,
            bstage: self.bstage,
            bout: self.bout,
        });
        // The scratch is one-shot: a row that forgets to set it must not inherit the previous row's.
        self.byte = 0;
        self.feed = [false; SPONGES];
        self.perm = SPONGES;
        self.open = [false; SPONGES];
        self.path_sib = [0u64; DIGEST_LANES];
        self.path_dir = false;
        self.path_phase = false;
        self.efx_in = [[0u64; DIGEST_LANES]; 2];
        Ok(())
    }

    /// L9: lay one effect's fold as `EFX` rows — one Poseidon2 block per stage of [`efx_plan`] — and hand back the
    /// accumulator the last stage produced. The machine then asserts that value equals the reference fold
    /// (`compress(acc, effect_leaf(e))`) before recording it: the schedule and the reference are two spellings of one
    /// function, and a drift between them is an execution the circuit would not prove, so it is refused here by name.
    fn effect_rows(&mut self, op: u8, e: &Effect) -> Result<(), VmError> {
        use crate::poseidon2_compress::{compress, lanes_of};
        let plan = efx_plan(op);
        if plan.is_empty() {
            return Err(VmError::Internal("an effect was recorded by an opcode with no fold schedule"));
        }
        let slot_str = |s: &Self, n: u8| -> Result<(Digest, u32), VmError> {
            match s.stack.get(usize::from(n)) {
                Some(VmVal::Str { digest, len }) if usize::from(n) < usize::from(s.sp) => Ok((*digest, *len)),
                _ => Err(VmError::Internal("an effect's operand is not the string the schedule names")),
            }
        };
        let sys_op = match e {
            Effect::Syscall { sys_op, .. } => u64::from(*sys_op),
            _ => 0,
        };
        let entry_sel = match e {
            Effect::Call { entry_sel, .. } | Effect::LibCall { entry_sel, .. } => u64::from(*entry_sel),
            _ => 0,
        };
        let alen = match e {
            Effect::LibCall { argv_len, .. } => u64::from(*argv_len),
            _ => 0,
        };
        self.etmp = [[0u64; DIGEST_LANES]; 2];
        let mut acc_out: Option<Digest> = None;
        for (k, step) in plan.iter().enumerate() {
            let resolve = |s: &Self, src: EfxSrc, side: usize| -> Result<Digest, VmError> {
                Ok(match src {
                    EfxSrc::Const(c) => lanes_of(&[c]),
                    EfxSrc::ConstSysOp(c) => lanes_of(&[c, sys_op]),
                    EfxSrc::SlotDigest(n) => slot_str(s, n)?.0,
                    EfxSrc::SlotLen(n) => lanes_of(&[u64::from(slot_str(s, n)?.1)]),
                    EfxSrc::Cid => str_digest(&s.ctx.contract_id),
                    EfxSrc::SpongeA => s.sponges[SPONGE_A].digest(),
                    EfxSrc::SpongeC => s.sponges[SPONGE_C].digest(),
                    EfxSrc::Plen => lanes_of(&[u64::from(s.plen)]),
                    EfxSrc::Tmp0 => s.etmp[0],
                    EfxSrc::Tmp1 => s.etmp[1],
                    EfxSrc::Acc => s.effects_acc,
                    EfxSrc::PKey => s.path_key,
                    EfxSrc::ConstImmPlen(c) => lanes_of(&[c, entry_sel, u64::from(s.plen)]),
                    EfxSrc::Callee => s.callee,
                    EfxSrc::ConstImmPlenAlen(c) => lanes_of(&[c, entry_sel, u64::from(s.plen), alen]),
                    EfxSrc::SRoot => s.root_now,
                    EfxSrc::LibEffects => s.lib_effects,
                })
            };
            let (l, r) = (resolve(self, step.left, 0)?, resolve(self, step.right, 1)?);
            self.efx_in = [l, r];
            self.estage = k as u8;
            self.row(op, mk::EFX)?;
            let out = compress(&l, &r);
            match step.out {
                EfxDst::Tmp0 => self.etmp[0] = out,
                EfxDst::Tmp1 => self.etmp[1] = out,
                EfxDst::Acc => {
                    if k + 1 != plan.len() {
                        return Err(VmError::Internal("the fold lands the accumulator before the schedule's last stage"));
                    }
                    acc_out = Some(out);
                }
            }
        }
        self.estage = EFX_STAGES_MAX as u8;
        self.etmp = [[0u64; DIGEST_LANES]; 2];
        let reference = compress(&self.effects_acc, &effect_leaf(e));
        if acc_out != Some(reference) {
            return Err(VmError::Internal("the effects-fold schedule and effect_leaf disagree"));
        }
        Ok(())
    }

    fn push(&mut self, v: VmVal) -> Result<(), VmError> {
        if self.sp as usize >= STACK_DEPTH {
            return Err(VmError::StackOverflow);
        }
        // Slot 0 is the TOP: a push shifts everything up, which is the shape the circuit constrains.
        for i in (1..STACK_DEPTH).rev() {
            self.stack[i] = self.stack[i - 1];
        }
        self.stack[0] = v;
        self.sp += 1;
        Ok(())
    }

    fn pop(&mut self) -> Result<VmVal, VmError> {
        if self.sp == 0 {
            return Err(VmError::StackUnderflow);
        }
        let v = self.stack[0];
        for i in 0..STACK_DEPTH - 1 {
            self.stack[i] = self.stack[i + 1];
        }
        self.stack[STACK_DEPTH - 1] = VmVal::Word(0);
        self.sp -= 1;
        Ok(v)
    }

    /// The prover's cached content for a committed string. ⛔ NOT an input to any constraint — the bytes
    /// it returns are re-absorbed and re-checked against `digest` by the FEED rows that carry them.
    fn content(&self, digest: &Digest, len: u32) -> Result<Vec<u8>, VmError> {
        match self.strings.get(digest).or_else(|| self.storage.contents.get(digest)) {
            Some(b) if b.len() == len as usize => Ok(b.clone()),
            _ => Err(VmError::BadBytecode("a string on the stack has no content witness")),
        }
    }

    fn remember(&mut self, bytes: &[u8]) -> Result<VmVal, VmError> {
        if bytes.len() > STR_BYTES_MAX {
            return Err(VmError::StringTooLong);
        }
        let d = str_digest(bytes);
        self.strings.insert(d, bytes.to_vec());
        Ok(VmVal::Str { digest: d, len: bytes.len() as u32 })
    }

    /// Feed one byte to every sponge in `to`, emitting the `mk::PERM` rows a full staging area demands
    /// FIRST. This is the loop that makes a byte string provable: a byte that reaches two sponges reaches
    /// them in the SAME row under the SAME committed value, so the output of a `CONCAT` is tied to its
    /// inputs by construction rather than by a second argument.
    fn feed_byte(&mut self, op: u8, b: u8, to: &[usize]) -> Result<(), VmError> {
        for &s in to {
            if self.sponges[s].fill as usize == BYTES_PER_BLOCK {
                self.perm = s;
                self.row(op, mk::PERM)?;
                self.sponges[s].perm();
                self.fb[s] = false; // S2: the first block is over
            }
        }
        self.byte = b;
        for &s in to {
            self.feed[s] = true;
        }
        self.row(op, mk::FEED)?;
        for &s in to {
            // S2: the accumulators and the countdown advance AFTER the row that shows the byte, at the position the
            // byte lands (`fill` before the feed, in the block `fb` names) — the circuit's frame reads the same row
            s2_accumulate(op, s, usize::from(self.sponges[s].fill), self.fb[s], b, &mut self.s2acc);
            self.sponges[s].feed(b);
            if s == SPONGE_C {
                self.remaining = self
                    .remaining
                    .checked_sub(1)
                    .ok_or(VmError::Internal("the producer sponge took more bytes than its countdown holds"))?;
            }
        }
        Ok(())
    }

    /// Close a sponge: the final (possibly partial, possibly empty) block goes through the permutation,
    /// exactly as [`str_digest`] does. Every string therefore ends on a permutation.
    fn close(&mut self, op: u8, s: usize) -> Result<(), VmError> {
        self.perm = s;
        self.row(op, mk::PERM)?;
        self.sponges[s].perm();
        self.fb[s] = false; // S2: a closed sponge is past its first block
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The PQ primitives the machine's own opcodes bind to. Every one is Poseidon2 over the tree's own
// permutation, so it is enforceable in the main table at one permutation per operation.
//
// ⛔ WHY THESE ARE NOT BLAKE3. The pre-circuit interpreter derived its contract nullifier and its
// commitment blind with blake3. blake3 is post-quantum and perfectly good — but proving it needs a
// bit-level precompile table, and a primitive that cannot be proven cannot appear in a private call at
// all. Poseidon2 is the tree's OWN hash (every note commitment, every accumulator, the challenger), so
// a contract that uses these costs one row and stays inside one table. `SHA3` keeps Keccak for the
// contracts that must reproduce a foreign digest, and is refused by this machine until its precompile
// lands — refused, never silently substituted.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Domain tag folded into a contract nullifier, so a tag can never be mistaken for a commitment.
pub const DOM_NULLIFIER: u64 = 0x4E_55_4C_4C; // "NULL"
/// Domain tag folded into a confidential value commitment.
pub const DOM_COMMIT: u64 = 0x43_4D_54_30; // "CMT0"

/// A contract's spend tag over `(contract_id, secret)`. Deterministic, so a double spend is detectable;
/// and it reveals nothing about the value or the owner.
#[must_use]
pub fn vm_nullifier(contract_id: &Digest, secret: &Digest) -> Digest {
    use crate::poseidon2_compress::{compress, lanes_of};
    compress(&lanes_of(&[DOM_NULLIFIER]), &compress(contract_id, secret))
}

/// The left half of a `COMMIT_U64` block: the domain constant and the value's FOUR 16-bit limbs — the stack's own
/// representation, so the circuit binds each lane to a stack limb. ONE spelling for the machine ([`vm_commit`]) and
/// the circuit's CMT-row layer. ⛔ MEASURED 2026-09-29 (S2 census): the old `lanes_of(&[DOM_COMMIT, value])` put a
/// 64-bit value in ONE 31-bit lane, which the permutation reduces mod p — `value` and `value + p` committed
/// identically, so a hidden balance could be opened to another value. Four exact limbs make the commitment binding
/// over the whole word.
#[must_use]
pub fn commit_preimage_lanes(value: u64) -> Digest {
    crate::poseidon2_compress::lanes_of(&[DOM_COMMIT, value & 0xffff, (value >> 16) & 0xffff, (value >> 32) & 0xffff, value >> 48])
}

/// A value-hiding commitment to `value` under a blind derived from the caller's blinding string. Hiding
/// because a fresh blind makes the digest uniform; binding by Poseidon2 collision resistance over
/// [`commit_preimage_lanes`] (four exact limbs — never a u64 in one reduced lane).
#[must_use]
pub fn vm_commit(value: u64, blind: &Digest) -> Digest {
    crate::poseidon2_compress::compress(&commit_preimage_lanes(value), blind)
}

impl<'a, H: SyscallHost> Machine<'a, H> {
    fn imm_u16(&self, at: usize) -> Result<u16, VmError> {
        if at + 2 > self.code.len() {
            return Err(VmError::BadBytecode("u16 immediate overruns"));
        }
        Ok(u16::from_le_bytes([self.code[at], self.code[at + 1]]))
    }
    fn imm_u32(&self, at: usize) -> Result<u32, VmError> {
        if at + 4 > self.code.len() {
            return Err(VmError::BadBytecode("u32 immediate overruns"));
        }
        Ok(u32::from_le_bytes([self.code[at], self.code[at + 1], self.code[at + 2], self.code[at + 3]]))
    }

    fn record(&mut self, e: Effect) {
        self.effects_acc = crate::poseidon2_compress::compress(&self.effects_acc, &effect_leaf(&e));
        self.effects.push(e);
    }

    /// Re-supply a committed string's bytes into sponge `s` (and optionally into the producer too),
    /// proving the content matches the digest the stack carries.
    fn supply(&mut self, op: u8, s: usize, digest: &Digest, len: u32, also_c: bool) -> Result<Vec<u8>, VmError> {
        let bytes = self.content(digest, len)?;
        // THE MACHINE CHECKS ITSELF AGAINST THE CIRCUIT'S TABLE: this sponge opens with the length of exactly the slot
        // `open_source` names, or the two halves have drifted and the execution is refused.
        match open_source(op, s) {
            OpenLen::Slot(k) => match self.stack[k as usize] {
                VmVal::Str { len: slot_len, .. } if slot_len as usize == bytes.len() => {}
                _ => return Err(VmError::Internal("open_source drift: a supply opened a sponge with a length its slot does not hold")),
            },
            _ => return Err(VmError::Internal("open_source drift: a supply opened a sponge the table does not name")),
        }
        self.open_sponge(op, s, bytes.len());
        let targets: Vec<usize> = if also_c { vec![s, SPONGE_C] } else { vec![s] };
        for &b in &bytes {
            self.feed_byte(op, b, &targets)?;
        }
        self.close(op, s)?;
        if self.sponges[s].digest() != *digest {
            return Err(VmError::BadBytecode("a re-supplied string did not match its committed digest"));
        }
        Ok(bytes)
    }

    /// One storage access. `new` is `None` for a read. Emits [`STORAGE_DEPTH`] `mk::PATH` rows folding the
    /// pre-image leaf to the root the row carries, and the post-image leaf to the root the access leaves.
    fn access(&mut self, op: u8, key: &Digest, new: Option<VmVal>) -> Result<VmVal, VmError> {
        use crate::poseidon2_compress::compress;
        let cur = self.storage.get(key).unwrap_or(VmVal::Word(0));
        let present = self.storage.get(key).is_some();
        let sibs = self.storage.path(key);
        let leaf_old = if present { slot_leaf(key, &cur) } else { empty_subtree(0) };
        let leaf_new = match new {
            Some(v) => slot_leaf(key, &v),
            None => leaf_old,
        };
        // The LEAF row(s): the circuit re-hashes `compress(key, value)` from the key and value the row carries — the
        // pre-image value on the first row, the post-image (the stack top) on a write's second row.
        self.path_key = *key;
        self.path_present = present;
        self.path_val = cur;
        self.kacc = [0u64; DIGEST_LANES];
        self.klane = ((STORAGE_DEPTH - 1) % DIGEST_LANES) as u8; // the lane the first fold level's bit belongs to
        self.path_phase = false;
        if matches!(cur, VmVal::Str { .. }) {
            self.row(op, mk::SVAL)?; // L8b part 2: the pre-image string's value half, hashed on its own row
        }
        self.row(op, mk::LEAF)?;
        self.path_old = leaf_old;
        if let Some(v) = new {
            // `row` resets the phase after every row it records, so each φ1 row sets it afresh
            if matches!(v, VmVal::Str { .. }) {
                self.path_phase = true;
                self.row(op, mk::SVAL)?; // the written string's value half
            }
            self.path_phase = true;
            self.row(op, mk::LEAF)?;
        }
        self.path_new = leaf_new;
        for level in 0..STORAGE_DEPTH {
            let bit_index = STORAGE_DEPTH - 1 - level;
            let (sib, dir) = (sibs[bit_index], key_bit(key, bit_index));
            let (o, n) = (self.path_old, self.path_new);
            // `remaining` is this access's level countdown: STORAGE_DEPTH on the first level, 1 on the last — the
            // circuit's exact-depth law (L8) reads it, so a path can neither stop short nor run long.
            self.remaining = (STORAGE_DEPTH - level) as u32;
            self.path_sib = sib;
            self.path_dir = dir;
            self.path_phase = false;
            self.row(op, mk::PATH)?;
            self.path_old = if dir { compress(&sib, &o) } else { compress(&o, &sib) };
            if new.is_some() {
                // the same level again, folding the POST-image through the SAME sibling
                self.path_sib = sib;
                self.path_dir = dir;
                self.path_phase = true;
                self.row(op, mk::PATH)?;
            }
            self.path_new = if dir { compress(&sib, &n) } else { compress(&n, &sib) };
            // the key-bit accumulator: this level's direction bit lands in its lane, MSB first (see `key_bit`)
            let lane = bit_index % DIGEST_LANES;
            if lane != usize::from(self.klane) {
                return Err(VmError::Internal("the key-bit lane rotation drifted from the fold order"));
            }
            self.kacc[lane] = (self.kacc[lane] << 1) | u64::from(dir);
            self.klane = ((usize::from(self.klane) + DIGEST_LANES - 1) % DIGEST_LANES) as u8;
        }
        self.remaining = 0;
        if self.path_old != self.root_now {
            return Err(VmError::BadBytecode("a storage path did not fold to the root"));
        }
        // the machine asserts what the circuit proves: the direction bits rebuilt the key, a read moved nothing
        if self.kacc != *key {
            return Err(VmError::Internal("the key-bit accumulators did not rebuild the key"));
        }
        if new.is_none() && self.path_new != self.path_old {
            return Err(VmError::Internal("a read moved the post-image"));
        }
        if let Some(v) = new {
            self.storage.insert_checked(key, v)?;
            if let VmVal::Str { digest, len } = v {
                // the written string's bytes go with the slot: the blob carries them, the next call re-supplies them
                let bytes = self.content(&digest, len)?;
                self.storage.contents.insert(digest, bytes);
            }
            self.root_now = self.storage.root();
        }
        Ok(cur)
    }
}

impl<'a, H: SyscallHost> Machine<'a, H> {
    /// Push a 32-byte context value as a DSOL string. The bytes are PUBLIC (they are the call's context),
    /// so the circuit reads the digest as a statement constant and the row costs nothing extra.
    fn push_ctx_bytes(&mut self, op: u8, b: [u8; 32]) -> Result<(), VmError> {
        let v = self.remember(&b)?;
        self.row(op, mk::PLAIN)?;
        self.push(v)?;
        self.pc += 1;
        Ok(())
    }

    /// Produce a brand-new string from bytes the MACHINE derives (never the prover): feed them to the
    /// producer sponge and close it. Each byte advances the S2 accumulators ([`s2_accumulate`]) and C's countdown
    /// inside [`Self::feed_byte`], so the content law at the opcode's target row can state what the bytes encode.
    fn produce(&mut self, op: u8, bytes: &[u8]) -> Result<VmVal, VmError> {
        if bytes.len() > STR_BYTES_MAX {
            return Err(VmError::StringTooLong);
        }
        if open_source(op, SPONGE_C) != OpenLen::Produced {
            return Err(VmError::Internal("open_source drift: an opcode produced a string the table does not name"));
        }
        if let Some(fixed) = produce_len(op) {
            if fixed as usize != bytes.len() {
                return Err(VmError::Internal("produce_len drift: a fixed-length producer produced another length"));
            }
        }
        self.plen = bytes.len() as u32;
        self.open_sponge(op, SPONGE_C, bytes.len());
        for &b in bytes {
            self.feed_byte(op, b, &[SPONGE_C])?;
        }
        self.close(op, SPONGE_C)?;
        let d = self.sponges[SPONGE_C].digest();
        if d != str_digest(bytes) {
            return Err(VmError::BadBytecode("the producer sponge disagreed with the string digest"));
        }
        self.strings.insert(d, bytes.to_vec());
        Ok(VmVal::Str { digest: d, len: bytes.len() as u32 })
    }

    /// The finishing row of a multi-row opcode: the result lands and the pc advances.
    fn finish(&mut self, op: u8, width: u32, result: Option<VmVal>, pops: usize) -> Result<(), VmError> {
        self.row(op, mk::FINISH)?;
        self.plen = 0;
        // a storage access's scratch ends with its FINISH row (which still carries `path_val` for the landing law)
        self.path_key = [0u64; DIGEST_LANES];
        self.path_present = false;
        self.path_val = VmVal::Word(0);
        self.kacc = [0u64; DIGEST_LANES];
        self.klane = DIGEST_LANES as u8;
        for _ in 0..pops {
            self.pop()?;
        }
        if let Some(v) = result {
            self.push(v)?;
        }
        self.remaining = 0;
        self.pc += width;
        Ok(())
    }

    /// S2 — open sponge `s` for `op` with the length its table names: the fresh state, the OPEN flag the next recorded
    /// row carries, the first-block flag, C's byte countdown, CONCAT's phase (B's open ends A's phase) and, when `s` is
    /// the opcode's accumulating sponge, the zeroed accumulators — ONE function, so the machine's witness and the
    /// circuit's open laws cannot drift apart at one of three call sites.
    fn open_sponge(&mut self, op: u8, s: usize, len: usize) {
        self.sponges[s] = SpongeSlot::opened(len);
        self.open[s] = true;
        self.fb[s] = true;
        if s == SPONGE_C {
            self.remaining = len as u32;
        }
        if s == SPONGE_B {
            self.cph = true;
        }
        if acc_sponge(op) == Some(s) {
            self.s2acc = [0u64; S2_ACC];
        }
    }

    /// The boundary fold: [`BOUND_GROUPS`] rows of `mk::BOUND` under the `BOUND` pseudo-opcode, each absorbing one group
    /// of the carried state ([`bound_lanes`]) into the running fold. `out` names the run (`false` opens a continued
    /// segment at row 0, `true` closes one at the last row). Returns the fold — the statement's `state_in` / `state_out`.
    fn bound_run(&mut self, out: bool) -> Result<Digest, VmError> {
        use crate::poseidon2_compress::compress;
        let lanes = bound_lanes(self.pc, self.sp, &self.stack, &self.locals, &self.root_now, &self.effects_acc);
        self.bstate = [0u64; DIGEST_LANES];
        for k in 0..BOUND_GROUPS {
            self.bstage = k as u8;
            self.bout = out;
            self.row(op::BOUND, mk::BOUND)?;
            self.bstate = compress(&self.bstate, &bound_group(&lanes, k));
        }
        let fold = self.bstate;
        self.bstage = 0;
        self.bout = false;
        Ok(fold)
    }

    fn run(&mut self, start: u32, cut_after: Option<usize>) -> Result<Exit, VmError> {
        self.pc = start;
        loop {
            // a CUT falls only here, between two opcodes, once the caller's segment budget is reached
            if let Some(cut) = cut_after {
                if self.steps.len() >= cut {
                    return Ok(Exit::Cut(self.bound_run(true)?));
                }
            }
            let at = self.pc as usize;
            if at >= self.code.len() {
                return Err(VmError::BadBytecode("pc past end (no RETURN)"));
            }
            let o = self.code[at];
            let sp_before = self.sp;
            match o {
                op::PUSH_U64 => {
                    if at + 9 > self.code.len() {
                        return Err(VmError::BadBytecode("push_u64 overruns"));
                    }
                    let mut w = [0u8; 8];
                    w.copy_from_slice(&self.code[at + 1..at + 9]);
                    self.row(o, mk::PLAIN)?;
                    self.push(VmVal::Word(u64::from_le_bytes(w)))?;
                    self.pc += 9;
                }
                op::PUSH_BYTES => {
                    let len = self.imm_u16(at + 1)? as usize;
                    if at + 3 + len > self.code.len() {
                        return Err(VmError::BadBytecode("push_bytes overruns"));
                    }
                    let lit = self.code[at + 3..at + 3 + len].to_vec();
                    // The literal is IN THE CODE, and the code is public: its digest is a ROM constant,
                    // so a literal costs one row and no absorb.
                    let v = self.remember(&lit)?;
                    self.row(o, mk::PLAIN)?;
                    self.push(v)?;
                    self.pc += 3 + len as u32;
                }
                op::POP => {
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pc += 1;
                }
                op::DUP => {
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    let v = self.stack[0];
                    self.row(o, mk::PLAIN)?;
                    self.push(v)?;
                    self.pc += 1;
                }
                op::SWAP => {
                    if self.sp < 2 {
                        return Err(VmError::StackUnderflow);
                    }
                    self.row(o, mk::PLAIN)?;
                    self.stack.swap(0, 1);
                    self.pc += 1;
                }
                op::ADC | op::SBB => {
                    // WIDE: add / subtract with a carry / borrow in (top, 0 or 1) and out — a u256 add is four of these
                    if self.sp < 3 {
                        return Err(VmError::StackUnderflow);
                    }
                    let cin = self.stack[0].as_word().ok_or(VmError::TypeMismatch("a carry in must be a word"))?;
                    let b = self.stack[1].as_word().ok_or(VmError::TypeMismatch("ADC / SBB on a string"))?;
                    let a = self.stack[2].as_word().ok_or(VmError::TypeMismatch("ADC / SBB on a string"))?;
                    if cin > 1 {
                        return Err(VmError::TypeMismatch("a carry in is 0 or 1"));
                    }
                    let (r, c) = if o == op::ADC {
                        let (s1, c1) = a.overflowing_add(b);
                        let (s2, c2) = s1.overflowing_add(cin);
                        (s2, u64::from(c1 | c2))
                    } else {
                        let (d1, b1) = a.overflowing_sub(b);
                        let (d2, b2) = d1.overflowing_sub(cin);
                        (d2, u64::from(b1 | b2))
                    };
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pop()?;
                    self.pop()?;
                    self.push(VmVal::Word(r))?;
                    self.push(VmVal::Word(c))?;
                    self.pc += 1;
                }
                op::DIVMOD128 => {
                    // WIDE: (hi·2^64 + lo) / d — CHECKED: the quotient must fit a word, so hi < d, or the call fails
                    if self.sp < 3 {
                        return Err(VmError::StackUnderflow);
                    }
                    let d = self.stack[0].as_word().ok_or(VmError::TypeMismatch("DIVMOD128 on a string"))?;
                    let lo = self.stack[1].as_word().ok_or(VmError::TypeMismatch("DIVMOD128 on a string"))?;
                    let hi = self.stack[2].as_word().ok_or(VmError::TypeMismatch("DIVMOD128 on a string"))?;
                    if d == 0 {
                        return Err(VmError::DivByZero);
                    }
                    if hi >= d {
                        return Err(VmError::Overflow("DIVMOD128: the quotient does not fit a word (hi >= d)"));
                    }
                    let n = (u128::from(hi) << 64) | u128::from(lo);
                    let (q, r) = ((n / u128::from(d)) as u64, (n % u128::from(d)) as u64);
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pop()?;
                    self.pop()?;
                    self.push(VmVal::Word(q))?;
                    self.push(VmVal::Word(r))?;
                    self.pc += 1;
                }
                op::ADD_U64 | op::SUB_U64 | op::MUL_U64 | op::DIV_U64 | op::MOD_U64 | op::LT
                | op::EQ | op::AND | op::OR | op::MUL_HI => {
                    if self.sp < 2 {
                        return Err(VmError::StackUnderflow);
                    }
                    let b = self.stack[0].as_word().ok_or(VmError::TypeMismatch("binary op on a string"))?;
                    let a = self.stack[1].as_word().ok_or(VmError::TypeMismatch("binary op on a string"))?;
                    if (o == op::DIV_U64 || o == op::MOD_U64) && b == 0 {
                        return Err(VmError::DivByZero);
                    }
                    let r = match o {
                        op::ADD_U64 => a.wrapping_add(b),
                        op::SUB_U64 => a.wrapping_sub(b),
                        op::MUL_U64 => a.wrapping_mul(b),
                        op::MUL_HI => ((u128::from(a) * u128::from(b)) >> 64) as u64,
                        op::DIV_U64 => a / b,
                        op::MOD_U64 => a % b,
                        op::LT => u64::from(a < b),
                        op::EQ => u64::from(a == b),
                        op::AND => u64::from(a != 0 && b != 0),
                        _ => u64::from(a != 0 || b != 0),
                    };
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pop()?;
                    self.push(VmVal::Word(r))?;
                    self.pc += 1;
                }
                op::NOT => {
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    let a = self.stack[0].as_word().ok_or(VmError::TypeMismatch("NOT on a string"))?;
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.push(VmVal::Word(u64::from(a == 0)))?;
                    self.pc += 1;
                }
                op::JUMP => {
                    let t = self.imm_u32(at + 1)?;
                    self.row(o, mk::PLAIN)?;
                    self.pc = t;
                }
                op::JUMPI => {
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    let c = self.stack[0].as_word().ok_or(VmError::TypeMismatch("JUMPI on a string"))?;
                    let t = self.imm_u32(at + 1)?;
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pc = if c != 0 { t } else { self.pc + 5 };
                }
                op::RETURN => {
                    let (ret, d) = match (self.sp > 0, self.stack[0]) {
                        (true, VmVal::Str { digest, len }) => {
                            let bytes = self.content(&digest, len)?;
                            self.row(o, mk::PLAIN)?;
                            (bytes, digest)
                        }
                        (has_top, top) => {
                            // H2 (2026-09-29): a returned WORD's digest (and the empty return of an empty stack) used
                            // to be computed off-circuit (`str_digest`, no rows), so the statement's `ret_digest` was
                            // unprovable for them. The bytes now go through the producer sponge (FEED / PERM rows of
                            // this RETURN) and the final row carries sponge C's digest for L10 to bind.
                            let b: Vec<u8> = match top {
                                VmVal::Word(w) if has_top => w.to_le_bytes().to_vec(),
                                _ => Vec::new(),
                            };
                            let produced = self.produce(o, &b)?;
                            self.row(o, mk::FINISH)?;
                            let VmVal::Str { digest, .. } = produced else {
                                return Err(VmError::Internal("produce returned a word"));
                            };
                            (b, digest)
                        }
                    };
                    return Ok(Exit::Returned(ret, d));
                }
                op::REVERT => {
                    self.row(o, mk::PLAIN)?;
                    return Err(VmError::Revert);
                }
                op::BYTES_LEN => {
                    let (_, len) = match self.stack[0] {
                        VmVal::Str { digest, len } => (digest, len),
                        VmVal::Word(_) => return Err(VmError::TypeMismatch("BYTES_LEN on a word")),
                    };
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.push(VmVal::Word(u64::from(len)))?;
                    self.pc += 1;
                }
                op::STR_EQ => {
                    // ⭐ NO ABSORB. A string's identity IS its digest, so equality of two strings is
                    // equality of two committed digests — the content never has to enter the trace.
                    if self.sp < 2 {
                        return Err(VmError::StackUnderflow);
                    }
                    let (a, b) = (self.stack[0], self.stack[1]);
                    let eq = match (a, b) {
                        (VmVal::Str { digest: da, len: la }, VmVal::Str { digest: db, len: lb }) => {
                            u64::from(da == db && la == lb)
                        }
                        _ => return Err(VmError::TypeMismatch("STR_EQ on a word")),
                    };
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.pop()?;
                    self.push(VmVal::Word(eq))?;
                    self.pc += 1;
                }
                op::LOCAL_GET => {
                    let i = self.imm_u16(at + 1)? as usize;
                    if i >= LOCALS_MAX {
                        return Err(VmError::LocalsOverflow);
                    }
                    let v = self.locals[i];
                    self.row(o, mk::PLAIN)?;
                    self.push(v)?;
                    self.pc += 3;
                }
                op::LOCAL_SET => {
                    let i = self.imm_u16(at + 1)? as usize;
                    if i >= LOCALS_MAX {
                        return Err(VmError::LocalsOverflow);
                    }
                    if self.sp == 0 {
                        return Err(VmError::StackUnderflow);
                    }
                    let v = self.stack[0];
                    self.row(o, mk::PLAIN)?;
                    self.pop()?;
                    self.locals[i] = v;
                    self.pc += 3;
                }
                op::ALLOC_LOCALS => {
                    let n = self.imm_u16(at + 1)? as usize;
                    if n > LOCALS_MAX {
                        return Err(VmError::LocalsOverflow);
                    }
                    self.row(o, mk::PLAIN)?;
                    self.locals = [VmVal::Word(0); LOCALS_MAX];
                    self.pc += 3;
                }
                op::MSG_SENDER => self.push_ctx_bytes(o, self.ctx.caller_wallet)?,
                op::MSG_SUBADDRESS => self.push_ctx_bytes(o, self.ctx.caller_subaddress)?,
                op::CONTRACT_ID => self.push_ctx_bytes(o, self.ctx.contract_id)?,
                op::TX_HASH => self.push_ctx_bytes(o, self.ctx.tx_hash)?,
                op::BLOCK_NUMBER => {
                    let n = self.ctx.block_number;
                    self.row(o, mk::PLAIN)?;
                    self.push(VmVal::Word(n))?;
                    self.pc += 1;
                }
                op::SHA3 | op::EXT_CALL_TAIL => return Err(VmError::NotProvable(o)),
                _ => self.step_wide(o, at)?,
            }
            // THE MACHINE CHECKS ITSELF AGAINST THE CIRCUIT'S TABLE: the sp movement this opcode just made must be
            // exactly what `stack_effect` names, or the two halves have drifted and this execution is refused.
            match stack_effect(o) {
                Some((pops, pushes)) => {
                    if i32::from(self.sp) != i32::from(sp_before) - i32::from(pops) + i32::from(pushes) {
                        return Err(VmError::Internal("stack_effect drift: the interpreter moved sp by an amount the table does not name"));
                    }
                }
                None => return Err(VmError::Internal("an opcode ran with no stack_effect entry")),
            }
        }
    }
}

/// A mapping slot's key: `Poseidon(base, key)`.
///
/// ⛔ THE PRE-CIRCUIT VM DERIVED THIS WITH SHA3. Keccak is not provable in the main table, and a slot
/// derivation that cannot be proven makes every mapping in every contract unprovable — the whole point of
/// the layer. Poseidon2 is the chain's own hash and binds both operands just as tightly.
#[must_use]
pub fn map_slot(base: &Digest, key: &Digest) -> Digest {
    crate::poseidon2_compress::compress(base, key)
}

impl<'a, H: SyscallHost> Machine<'a, H> {
    /// The opcodes that take MORE THAN ONE ROW: anything that moves a byte string's content, hashes, or
    /// touches storage. Each one expands into feed / perm / path rows and closes on a `mk::FINISH`.
    fn step_wide(&mut self, o: u8, at: usize) -> Result<(), VmError> {
        // L7: a FIXED-LENGTH producer's `plen` is its produced length on EVERY row of the opcode — the circuit binds
        // `plen == produce_len(op)` under the opcode's selector, row by row, and freezes it across the run. So it is set
        // HERE, at the opcode's first row, not in `produce` (which runs after the supply rows: a NULLIFIER first
        // re-absorbs its secret through sponge A, and those rows carried `plen = 0` — the first supply-then-produce
        // opcode any pin laid, refused by the honest arm of L9's pin on 2026-09-29 04:14 at its first FEED row).
        // `produce` still asserts the length it is handed equals this table value.
        if let Some(fixed) = produce_len(o) {
            self.plen = fixed;
        }
        match o {
            op::CONCAT => {
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let (db, lb) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("CONCAT on a word")),
                };
                let (da, la) = match self.stack[1] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("CONCAT on a word")),
                };
                let total = la as usize + lb as usize;
                if total > STR_BYTES_MAX {
                    return Err(VmError::StringTooLong);
                }
                // ⭐⭐⭐ THE TIE. The producer opens FIRST, then every byte of `a` and then every byte of
                // `b` enters BOTH its own verifier and the producer IN THE SAME ROW. The output digest is
                // therefore a function of exactly the bytes two committed digests were re-checked
                // against — no fingerprint, no second challenge, no memory argument.
                self.plen = total as u32;
                self.cph = false; // S2: A's phase — B's open flips it, and no A byte may enter after that
                self.open_sponge(o, SPONGE_C, total);
                let ba = self.supply(o, SPONGE_A, &da, la, true)?;
                let bb = self.supply(o, SPONGE_B, &db, lb, true)?;
                self.close(o, SPONGE_C)?;
                let mut joined = ba;
                joined.extend_from_slice(&bb);
                let d = self.sponges[SPONGE_C].digest();
                if d != str_digest(&joined) {
                    return Err(VmError::BadBytecode("the concatenation sponge disagreed with its digest"));
                }
                self.strings.insert(d, joined);
                self.finish(o, 1, Some(VmVal::Str { digest: d, len: total as u32 }), 2)
            }
            op::U64_FROM_BYTES => {
                let (d, l) = match self.stack.first() {
                    Some(VmVal::Str { digest, len }) if self.sp > 0 => (*digest, *len),
                    _ => return Err(VmError::TypeMismatch("U64_FROM_BYTES needs a string")),
                };
                let bytes = self.supply(o, SPONGE_A, &d, l, false)?;
                let mut w = [0u8; 8];
                for (i, &b) in bytes.iter().take(8).enumerate() {
                    w[i] = b;
                }
                let v = VmVal::Word(u64::from_le_bytes(w));
                self.finish(o, 1, Some(v), 1)
            }
            op::U64_TO_BYTES => {
                if self.sp == 0 {
                    return Err(VmError::StackUnderflow);
                }
                let w = self.stack[0].as_word().ok_or(VmError::TypeMismatch("U64_TO_BYTES on a string"))?;
                let v = self.produce(o, &w.to_le_bytes())?;
                self.finish(o, 1, Some(v), 1)
            }
            op::U64_TO_DEC_STR => {
                if self.sp == 0 {
                    return Err(VmError::StackUnderflow);
                }
                let w = self.stack[0].as_word().ok_or(VmError::TypeMismatch("U64_TO_DEC_STR on a string"))?;
                let dec = w.to_string();
                let v = self.produce(o, dec.as_bytes())?;
                self.finish(o, 1, Some(v), 1)
            }
            op::POSEIDON => {
                let (d, l) = match self.stack.first() {
                    Some(VmVal::Str { digest, len }) if self.sp > 0 => (*digest, *len),
                    _ => return Err(VmError::TypeMismatch("POSEIDON needs a string")),
                };
                let _ = self.supply(o, SPONGE_A, &d, l, false)?;
                let tag = self.sponges[SPONGE_A].digest();
                let v = self.produce(o, &crate::poseidon2_compress::digest_to_bytes(&tag))?;
                self.finish(o, 1, Some(v), 1)
            }
            op::NULLIFIER => {
                let (d, l) = match self.stack.first() {
                    Some(VmVal::Str { digest, len }) if self.sp > 0 => (*digest, *len),
                    _ => return Err(VmError::TypeMismatch("NULLIFIER needs a secret string")),
                };
                let _ = self.supply(o, SPONGE_A, &d, l, false)?;
                let cid = str_digest(&self.ctx.contract_id);
                let tag = vm_nullifier(&cid, &self.sponges[SPONGE_A].digest());
                let v = self.produce(o, &crate::poseidon2_compress::digest_to_bytes(&tag))?;
                let e = Effect::Nullifier { tag };
                self.effect_rows(o, &e)?;
                self.record(e);
                self.finish(o, 1, Some(v), 1)
            }
            op::COMMIT_U64 => {
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let (bd, bl) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("COMMIT_U64 needs a blinding string")),
                };
                let value = self.stack[1].as_word().ok_or(VmError::TypeMismatch("COMMIT_U64 needs a value"))?;
                let _ = self.supply(o, SPONGE_A, &bd, bl, false)?;
                let cm = vm_commit(value, &self.sponges[SPONGE_A].digest());
                let v = self.produce(o, &crate::poseidon2_compress::digest_to_bytes(&cm))?;
                // S2-4: the row whose Poseidon2 block computes the commitment the produced bytes must encode
                self.row(o, mk::CMT)?;
                self.finish(o, 1, Some(v), 2)
            }
            op::EMIT => {
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let (data, dlen) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("EMIT needs a data string")),
                };
                let topic = match self.stack[1] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("EMIT needs a topic string")),
                };
                let e = Effect::Event { topic, data, len: dlen };
                self.effect_rows(o, &e)?;
                self.record(e);
                self.finish(o, 1, None, 2)
            }
            op::SYSCALL => {
                let sys_op = self.imm_u16(at + 1)?;
                if self.sp == 0 {
                    return Err(VmError::StackUnderflow);
                }
                let (argv, alen) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("SYSCALL needs an argv string")),
                };
                let bytes = self.content(&argv, alen)?;
                let out = self.host.call(sys_op, &bytes).ok_or(VmError::BadOpcode(o))?;
                // L9b: the host's answer is PRODUCED through sponge C (FEED / PERM rows the circuit checks), so the
                // effect's `ret` and the landed result are the digest of the bytes this execution actually consumed —
                // the node re-runs the syscall at apply and compares `ret`; the circuit proves ISSUED, the node AUTHORISES.
                let v = self.produce(o, &out)?;
                let (ret, rlen) = match v {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => unreachable!("remember always yields a string"),
                };
                let e = Effect::Syscall { sys_op, argv, argv_len: alen, ret, ret_len: rlen };
                self.effect_rows(o, &e)?;
                self.record(e);
                self.finish(o, 3, Some(v), 1)
            }
            op::CALL => {
                // SYNC CROSS-CONTRACT CALL (plan item 2): the callee's execution is its own statement. This opcode ISSUES
                // the call as an effect — argv, the callee's code id, the returned bytes PRODUCED through sponge C (as a
                // syscall's result is), and a binding of the callee's storage roots and effects — and the node AUTHORISES
                // it by verifying the callee's own proof against every field (`authorize_call_chain`).
                let entry_sel = self.imm_u32(at + 1)?;
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let (argv, alen) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("CALL needs an argv string")),
                };
                let (cid, clen) = match self.stack[1] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("CALL needs the callee's code id string")),
                };
                if clen != 32 {
                    return Err(VmError::TypeMismatch("a callee's code id is 32 bytes"));
                }
                let code_id: [u8; 32] = self.content(&cid, clen)?.try_into().map_err(|_| VmError::Internal("a 32-byte string has 32 bytes"))?;
                let argv_bytes = self.content(&argv, alen)?;
                let answer = self.host.call_contract(code_id, entry_sel, &argv_bytes).ok_or(VmError::BadOpcode(o))?;
                self.callee = callee_binding(&answer.storage_pre, &answer.storage_post, &answer.effects_digest);
                let v = self.produce(o, &answer.ret)?;
                let (ret, rlen) = match v {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => unreachable!("produce always yields a string"),
                };
                let e = Effect::Call { code_id: cid, entry_sel, argv, argv_len: alen, ret, ret_len: rlen, callee: self.callee };
                self.effect_rows(o, &e)?;
                self.record(e);
                self.finish(o, 5, Some(v), 2)
            }
            op::LIBCALL => {
                // LIBRARY CALL (the DELEGATECALL shape): the library runs against THIS contract's storage under this
                // contract's identity. The host is handed the live trie and returns the trie the library left; the root
                // jumps to the library's post root at this opcode's FINISH; the effect binds pre, post and the library's own
                // effects, and the node authorises it against the library's proof.
                let entry_sel = self.imm_u32(at + 1)?;
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let (argv, alen) = match self.stack[0] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("LIBCALL needs an argv string")),
                };
                let (cid, clen) = match self.stack[1] {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("LIBCALL needs the library's code id string")),
                };
                if clen != 32 {
                    return Err(VmError::TypeMismatch("a library's code id is 32 bytes"));
                }
                let code_id: [u8; 32] = self.content(&cid, clen)?.try_into().map_err(|_| VmError::Internal("a 32-byte string has 32 bytes"))?;
                let argv_bytes = self.content(&argv, alen)?;
                let pre = self.root_now;
                let (answer, trie) = self.host.call_library(code_id, entry_sel, &argv_bytes, self.storage.clone()).ok_or(VmError::BadOpcode(o))?;
                if answer.storage_pre != pre {
                    return Err(VmError::BadOpcode(o)); // the host did not run the library against THIS storage
                }
                if trie.root() != answer.storage_post {
                    return Err(VmError::Internal("the library host's trie does not fold to the post root it named"));
                }
                self.callee = answer.storage_post;
                self.lib_effects = answer.effects_digest;
                let v = self.produce(o, &answer.ret)?;
                let (ret, rlen) = match v {
                    VmVal::Str { digest, len } => (digest, len),
                    VmVal::Word(_) => unreachable!("produce always yields a string"),
                };
                let e = Effect::LibCall { code_id: cid, entry_sel, argv, argv_len: alen, ret, ret_len: rlen, pre, post: answer.storage_post, effects: answer.effects_digest };
                self.effect_rows(o, &e)?;
                self.record(e);
                self.finish(o, 5, Some(v), 2)?;
                // the caller's storage continues from the library's post-state: the root jumps at the FINISH just recorded
                self.storage = trie;
                self.root_now = self.storage.root();
                Ok(())
            }
            op::SLOAD => {
                let key = match self.stack.first() {
                    Some(VmVal::Str { digest, .. }) if self.sp > 0 => *digest,
                    _ => return Err(VmError::TypeMismatch("SLOAD needs a key string")),
                };
                let v = self.access(o, &key, None)?;
                self.finish(o, 1, Some(v), 1)
            }
            op::SSTORE | op::SSTORE_PRIV => {
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let val = self.stack[0];
                let key = match self.stack[1] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("SSTORE needs a key string")),
                };
                // the effect's fold rows come FIRST, so the access rows that follow carry the advanced accumulator and the
                // path's exit still lands on the opcode's FINISH (L8 / L9)
                if o == op::SSTORE_PRIV {
                    let e = Effect::PrivateSlot { key };
                    self.effect_rows(o, &e)?;
                    self.record(e);
                }
                let _ = self.access(o, &key, Some(val))?;
                self.finish(o, 1, None, 2)
            }
            op::MAP_LOAD => {
                if self.sp < 2 {
                    return Err(VmError::StackUnderflow);
                }
                let k = match self.stack[0] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("MAP_LOAD needs a key string")),
                };
                let base = match self.stack[1] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("MAP_LOAD needs a base string")),
                };
                let slot = map_slot(&base, &k);
                self.row(o, mk::KEYD)?; // L8b: the circuit derives the slot from the two operands on this row
                let v = self.access(o, &slot, None)?;
                self.finish(o, 1, Some(v), 2)
            }
            op::MAP_STORE | op::MAP_STORE_PRIV => {
                if self.sp < 3 {
                    return Err(VmError::StackUnderflow);
                }
                let val = self.stack[0];
                let k = match self.stack[1] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("MAP_STORE needs a key string")),
                };
                let base = match self.stack[2] {
                    VmVal::Str { digest, .. } => digest,
                    VmVal::Word(_) => return Err(VmError::TypeMismatch("MAP_STORE needs a base string")),
                };
                let slot = map_slot(&base, &k);
                self.row(o, mk::KEYD)?; // L8b: the circuit derives the slot from the two operands on this row
                self.path_key = slot; // the derived key rides every row that follows (a private store's effect rows read it)
                if o == op::MAP_STORE_PRIV {
                    let e = Effect::PrivateSlot { key: slot };
                    self.effect_rows(o, &e)?;
                    self.record(e);
                }
                let _ = self.access(o, &slot, Some(val))?;
                self.finish(o, 1, None, 3)
            }
            _ => Err(VmError::BadOpcode(o)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The one entry point
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ⭐⭐⭐ RUN A DSOL ENTRYPOINT AND EMIT THE WITNESS THAT PROVES IT.
///
/// `strings` is the caller's content witness for every string it puts on the stack (the argv, and any
/// literal it expects back). It is NOT trusted: a byte it yields is re-absorbed and re-checked against
/// the digest the stack carries before any operation consumes it.
/// Run one SEGMENT of a call (continuations, plan item 5). `resume = None` starts the call fresh (argv on the stack at
/// the entrypoint); `Some(r)` continues from a predecessor's cut (its state and strings, with an in-run of BOUND rows
/// whose fold must equal `r.state`). `cut_after = Some(n)` cuts the segment at the first opcode boundary once `n` rows
/// are recorded (an out-run of BOUND rows follows and the machine hands back a [`Resume`]); `None` runs to the RETURN.
/// `budget` stays the hard bound on rows the machine will ever record for this segment.
#[allow(clippy::too_many_arguments)]
pub fn run_segment<H: SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: VmCtx,
    storage: StorageTrie,
    budget: u64,
    host: &mut H,
    resume: Option<Resume>,
    cut_after: Option<usize>,
) -> Result<(VmTrace, Option<Resume>), VmError> {
    if budget > STEP_BUDGET_MAX {
        return Err(VmError::BudgetExhausted);
    }
    if argv.len() > STR_BYTES_MAX {
        return Err(VmError::StringTooLong);
    }
    let entries = parse_entries(code)?;
    let sel = entry_hash(entrypoint.as_bytes());
    let start = entries
        .iter()
        .find(|(h, _)| *h == sel)
        .map(|(_, pc)| *pc)
        .ok_or(VmError::UnknownEntrypoint)?;
    let mut strings = std::collections::HashMap::new();
    let argv_digest = str_digest(argv);
    strings.insert(argv_digest, argv.to_vec());
    let mut stack = [VmVal::Word(0); STACK_DEPTH];
    stack[0] = VmVal::Str { digest: argv_digest, len: argv.len() as u32 };
    let mut m = Machine {
        code,
        ctx,
        pc: start,
        stack,
        sp: 1,
        locals: [VmVal::Word(0); LOCALS_MAX],
        sponges: [SpongeSlot::idle(); SPONGES],
        root_now: storage.root(),
        storage,
        strings,
        effects: Vec::new(),
        effects_acc: [0u64; DIGEST_LANES],
        budget,
        steps: Vec::new(),
        byte: 0,
        feed: [false; SPONGES],
        perm: SPONGES,
        open: [false; SPONGES],
        plen: 0,
        s2acc: [0u64; S2_ACC],
        remaining: 0,
        fb: [false; SPONGES],
        cph: false,
        path_sib: [0u64; DIGEST_LANES],
        path_dir: false,
        path_old: [0u64; DIGEST_LANES],
        path_new: [0u64; DIGEST_LANES],
        path_phase: false,
        path_present: false,
        path_key: [0u64; DIGEST_LANES],
        path_val: VmVal::Word(0),
        kacc: [0u64; DIGEST_LANES],
        klane: DIGEST_LANES as u8,
        efx_in: [[0u64; DIGEST_LANES]; 2],
        etmp: [[0u64; DIGEST_LANES]; 2],
        estage: EFX_STAGES_MAX as u8,
        callee: [0u64; DIGEST_LANES],
        lib_effects: [0u64; DIGEST_LANES],
        bstate: [0u64; DIGEST_LANES],
        bstage: 0,
        bout: false,
        host,
    };
    // a CONTINUED segment: the carried state comes from the predecessor's cut, and the in-run's fold must be the fold the
    // predecessor's out-run produced — the statement's `state_in`
    let mut state_in = [0u64; DIGEST_LANES];
    if let Some(r) = resume {
        m.pc = r.pc;
        m.stack = r.stack;
        m.sp = r.sp;
        m.locals = r.locals;
        m.storage = r.storage;
        m.root_now = m.storage.root();
        m.effects_acc = r.effects_acc;
        m.strings = r.strings;
        state_in = m.bound_run(false)?;
        if state_in != r.state {
            return Err(VmError::Internal("a resumed segment's in-fold is not the predecessor's out-fold"));
        }
    }
    let pc0 = m.pc;
    let exit = m.run(pc0, cut_after)?;
    let (ret, ret_digest, state_out, resume_out) = match exit {
        Exit::Returned(ret, d) => (ret, d, [0u64; DIGEST_LANES], None),
        Exit::Cut(out) => (
            Vec::new(),
            [0u64; DIGEST_LANES],
            out,
            Some(Resume { pc: m.pc, stack: m.stack, sp: m.sp, locals: m.locals, storage: m.storage.clone(), effects_acc: m.effects_acc, strings: m.strings.clone(), state: out }),
        ),
    };
    let run = VmRun {
        ret,
        ret_digest,
        effects: m.effects.clone(),
        effects_digest: m.effects_acc,
        storage_post: m.storage.root(),
        steps: m.steps.len(),
        storage: m.storage,
        state_in,
        state_out,
    };
    Ok((VmTrace { steps: m.steps, run }, resume_out))
}

/// Run ONE call to its RETURN (no segments): [`run_segment`] with no predecessor and no cut.
pub fn run<H: SyscallHost>(
    code: &[u8],
    entrypoint: &str,
    argv: &[u8],
    ctx: VmCtx,
    storage: StorageTrie,
    budget: u64,
    host: &mut H,
) -> Result<VmTrace, VmError> {
    run_segment(code, entrypoint, argv, ctx, storage, budget, host, None, None).map(|(t, _)| t)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny assembler, so a pin reads as the PROGRAM it runs rather than as a byte array. It emits the
    /// same v2 header [`parse_entries`] reads, so the pins drive the real header path too.
    struct Asm {
        /// O1-FOOTPRINT-REVIEWED: bounded by STR_BYTES_MAX — a pin's program is a literal in this file,
        /// assembled once and dropped; it is never node state.
        body: Vec<u8>,
        /// O1-FOOTPRINT-REVIEWED: bounded by STACK_DEPTH — a pin declares a handful of entrypoints.
        entries: Vec<(u32, u32)>,
    }
    impl Asm {
        fn new() -> Self {
            Asm { body: Vec::new(), entries: Vec::new() }
        }
        fn entry(mut self, name: &str) -> Self {
            self.entries.push((entry_hash(name.as_bytes()), self.body.len() as u32));
            self
        }
        fn op(mut self, o: u8) -> Self {
            self.body.push(o);
            self
        }
        fn push_u64(mut self, v: u64) -> Self {
            self.body.push(op::PUSH_U64);
            self.body.extend_from_slice(&v.to_le_bytes());
            self
        }
        fn push_bytes(mut self, b: &[u8]) -> Self {
            self.body.push(op::PUSH_BYTES);
            self.body.extend_from_slice(&(b.len() as u16).to_le_bytes());
            self.body.extend_from_slice(b);
            self
        }
        fn jumpi(mut self, target: u32) -> Self {
            self.body.push(op::JUMPI);
            self.body.extend_from_slice(&target.to_le_bytes());
            self
        }
        /// Where the NEXT emitted byte will sit once the header is prepended — what a jump target needs.
        fn here(&self) -> u32 {
            (self.body.len() + 5 + self.entries.len().max(1) * 8) as u32
        }
        /// Finish: the header is `[version | count | (sel, pc)...]`, so every recorded pc shifts by the
        /// header's own width — computed, never guessed.
        fn build(self) -> Vec<u8> {
            let hdr = 5 + self.entries.len() * 8;
            let mut out = vec![DSOL_VERSION];
            out.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
            for (sel, pc) in &self.entries {
                out.extend_from_slice(&sel.to_le_bytes());
                out.extend_from_slice(&(pc + hdr as u32).to_le_bytes());
            }
            out.extend_from_slice(&self.body);
            out
        }
    }

    fn go(code: &[u8], argv: &[u8]) -> Result<VmTrace, VmError> {
        run(code, "main", argv, VmCtx::default(), StorageTrie::default(), 1 << 18, &mut NoHost)
    }

    /// ⭐⭐⭐ THE BYTE-STRING CLAIM, MEASURED: a `CONCAT` the machine ran produces the digest of the
    /// JOINED string, and it produced it by absorbing bytes that were themselves checked against the two
    /// input digests. This is the whole reason the VM needs no memory subsystem.
    #[test]
    fn a_concat_absorbs_its_inputs_and_lands_on_the_joined_strings_own_digest() {
        let code = Asm::new()
            .entry("main")
            .op(op::POP) // drop argv
            .push_bytes(b"hello, ")
            .push_bytes(b"private defi")
            .op(op::CONCAT)
            .op(op::RETURN)
            .build();
        let t = go(&code, b"").expect("the program runs");
        assert_eq!(t.run.ret, b"hello, private defi", "the machine joined the two strings");
        assert_eq!(
            t.run.ret_digest,
            str_digest(b"hello, private defi"),
            "⛔ and it landed on the JOINED string's own digest — if it does not, the producer sponge is \
             absorbing something other than the bytes its verifiers checked"
        );
        // NON-VACUITY: the bytes really passed through the trace, one row each, into BOTH sponges.
        let shared = t
            .steps
            .iter()
            .filter(|s| s.micro == mk::FEED && s.feed[SPONGE_A] && s.feed[SPONGE_C])
            .count();
        assert_eq!(shared, 7, "every byte of the first operand fed its verifier AND the producer");
        let shared_b = t
            .steps
            .iter()
            .filter(|s| s.micro == mk::FEED && s.feed[SPONGE_B] && s.feed[SPONGE_C])
            .count();
        assert_eq!(shared_b, 12, "and every byte of the second did too");
        eprintln!("[dsol-vm] concat of 7+12 bytes ran in {} rows", t.run.steps);
    }

    /// ⛔ THE ATTACK THE RE-ABSORB EXISTS TO STOP: a content witness that does not match the digest on
    /// the stack. If the machine took the prover's bytes on faith, a `CONCAT` would join strings nobody
    /// ever committed to and the result would still carry an honest-looking digest.
    #[test]
    fn a_string_whose_content_witness_does_not_match_its_digest_is_refused() {
        let honest = b"the real terms".to_vec();
        let forged = b"the fake terms".to_vec();
        assert_eq!(honest.len(), forged.len(), "same length, so only the CONTENT differs");
        let code = Asm::new().entry("main").push_bytes(b"x").op(op::CONCAT).op(op::RETURN).build();

        // The honest run is the calibration: the same program with a matching witness MUST work, or this
        // pin would pass for a machine that refuses everything.
        assert!(go(&code, &honest).is_ok(), "PRECONDITION: an honest witness runs");

        // Now hand the machine the forged bytes under the honest digest, exactly as a lying prover would.
        let entries = parse_entries(&code).unwrap();
        let start = entries[0].1;
        let mut strings = std::collections::HashMap::new();
        strings.insert(str_digest(&honest), forged.clone());
        let mut stack = [VmVal::Word(0); STACK_DEPTH];
        stack[0] = VmVal::Str { digest: str_digest(&honest), len: honest.len() as u32 };
        let mut host = NoHost;
        let mut m = Machine {
            code: &code,
            ctx: VmCtx::default(),
            pc: start,
            stack,
            sp: 1,
            locals: [VmVal::Word(0); LOCALS_MAX],
            sponges: [SpongeSlot::idle(); SPONGES],
            root_now: StorageTrie::default().root(),
            storage: StorageTrie::default(),
            strings,
            effects: Vec::new(),
            effects_acc: [0u64; DIGEST_LANES],
            budget: 1 << 18,
            steps: Vec::new(),
            byte: 0,
            feed: [false; SPONGES],
            perm: SPONGES,
            open: [false; SPONGES],
            s2acc: [0u64; S2_ACC],
            remaining: 0,
            plen: 0,
            fb: [false; SPONGES],
            cph: false,
            path_sib: [0u64; DIGEST_LANES],
            path_dir: false,
            path_old: [0u64; DIGEST_LANES],
            path_new: [0u64; DIGEST_LANES],
            path_phase: false,
            path_present: false,
            path_key: [0u64; DIGEST_LANES],
            path_val: VmVal::Word(0),
            kacc: [0u64; DIGEST_LANES],
            klane: DIGEST_LANES as u8,
            efx_in: [[0u64; DIGEST_LANES]; 2],
            etmp: [[0u64; DIGEST_LANES]; 2],
            estage: EFX_STAGES_MAX as u8,
            callee: [0u64; DIGEST_LANES],
            lib_effects: [0u64; DIGEST_LANES],
            bstate: [0u64; DIGEST_LANES],
            bstage: 0,
            bout: false,
            host: &mut host,
        };
        let r = m.run(start, None);
        assert!(
            matches!(r, Err(VmError::BadBytecode(_))),
            "⛔ A FORGED CONTENT WITNESS WAS ACCEPTED ({r:?}). The re-absorb is the only thing standing \
             between a committed digest and bytes the prover made up."
        );
    }

    /// ⭐⭐⭐ STORAGE KEYS CARRY THEIR FULL COLLISION WIDTH. Two keys that agree on every bit but the
    /// DEEPEST one the path reads must still be two slots. At a shortened depth they land in one bucket
    /// and the root is wrong — which is a fork, not an inconvenience. (Owner's call, 2026-09-22: the
    /// depth is the key's own width, never a cheaper one justified by a birthday bound.)
    #[test]
    fn two_keys_differing_only_in_the_deepest_bit_are_two_slots_and_two_roots() {
        assert_eq!(
            STORAGE_DEPTH,
            DIGEST_LANES * 31,
            "the path must read EVERY bit of a canonical digest, or distinct keys share a bucket"
        );
        let mut a = crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut b = a;
        let last = STORAGE_DEPTH - 1;
        a[last / 31] &= !(1u64 << (last % 31));
        b[last / 31] |= 1u64 << (last % 31);
        assert_ne!(a, b, "PRECONDITION: the two keys differ");
        assert_ne!(key_bit(&a, last), key_bit(&b, last), "and they differ AT THE DEEPEST LEVEL");
        assert!(
            (0..last).all(|l| key_bit(&a, l) == key_bit(&b, l)),
            "PRECONDITION: they agree everywhere else, so only the deepest level can separate them"
        );

        let mut t = StorageTrie::default();
        t.insert_checked(&a, VmVal::Word(11)).expect("the first key stores");
        let root_one = t.root();
        t.insert_checked(&b, VmVal::Word(22))
            .expect("⛔ the second key was REFUSED — the path is too short to separate two real keys");
        assert_eq!(t.get(&a), Some(VmVal::Word(11)), "the first slot survived the second write");
        assert_eq!(t.get(&b), Some(VmVal::Word(22)), "and the second landed");
        assert_ne!(t.root(), root_one, "the root MOVED for the second slot");

        // And each one's own path folds to the root — the property a short depth breaks silently.
        for (k, v) in [(a, VmVal::Word(11)), (b, VmVal::Word(22))] {
            let sibs = t.path(&k);
            let up: Vec<Digest> = (0..STORAGE_DEPTH).map(|l| sibs[STORAGE_DEPTH - 1 - l]).collect();
            assert_eq!(
                fold_path(slot_leaf(&k, &v), &k, &up),
                t.root(),
                "a slot's own path must fold to the root it lives under"
            );
        }
    }

    /// ⭐ A WRITE MOVES THE ROOT AND A READ DOES NOT — the two halves of `mk::PATH`, driven through the
    /// real machine rather than the trie alone.
    #[test]
    fn a_contract_reads_back_what_it_wrote_and_a_read_leaves_the_root_where_it_was() {
        let code = Asm::new()
            .entry("main")
            .op(op::POP)
            .push_bytes(b"balance")
            .push_u64(42)
            .op(op::SSTORE)
            .push_bytes(b"balance")
            .op(op::SLOAD)
            .op(op::RETURN)
            .build();
        let t = go(&code, b"").expect("the program runs");
        assert_eq!(t.run.ret, 42u64.to_le_bytes().to_vec(), "the contract read back what it stored");
        assert_ne!(t.run.storage_post, StorageTrie::default().root(), "the write MOVED the storage root");

        // Every PATH row of the READ folds both images through the same sibling, so its two running nodes
        // never separate — that is what "a read cannot move the root" means at the row level.
        let read_rows: Vec<&Step> =
            t.steps.iter().filter(|s| s.op == op::SLOAD && s.micro == mk::PATH).collect();
        assert_eq!(read_rows.len(), STORAGE_DEPTH, "a read costs exactly one row per key bit");
        assert!(
            read_rows.iter().all(|s| s.path_old == s.path_new),
            "⛔ a READ's post-image diverged from its pre-image — a read that can move the root is a write"
        );
        assert!(read_rows.iter().all(|s| !s.path_phase), "a read has no post-image rows");
        // A WRITE lays every level TWICE — the pre-image row, then the post-image row through the SAME sibling on the
        // same side — so one Poseidon2 block per row folds both images (L8, 2026-09-29; one row per level before).
        let write_rows: Vec<&Step> =
            t.steps.iter().filter(|s| s.op == op::SSTORE && s.micro == mk::PATH).collect();
        assert_eq!(write_rows.len(), 2 * STORAGE_DEPTH, "a write costs exactly two rows per key bit: pre-image, post-image");
        for pair in write_rows.chunks(2) {
            assert!(!pair[0].path_phase && pair[1].path_phase, "each level is its pre-image row then its post-image row");
            assert_eq!((pair[0].path_sib, pair[0].path_dir), (pair[1].path_sib, pair[1].path_dir), "both images fold through ONE sibling");
        }
        assert!(
            write_rows.iter().any(|s| s.path_old != s.path_new),
            "a WRITE must separate the two images, or it stored nothing"
        );
        // and both accesses opened on a LEAF row that carries the key and the pre-image value
        let leaves: Vec<&Step> = t.steps.iter().filter(|s| s.micro == mk::LEAF).collect();
        assert_eq!(leaves.len(), 3, "the write's two LEAF rows (pre, post) and the read's one");
        assert!(leaves.iter().all(|s| s.path_key == str_digest(b"balance")), "every LEAF row carries the access key");
        assert_eq!(leaves[2].path_val, VmVal::Word(42), "the read's LEAF row carries the value the root holds");
        assert!(leaves[2].path_present && !leaves[0].path_present, "the slot is absent before the write and present after");
        eprintln!("[dsol-vm] store+load over a {STORAGE_DEPTH}-bit key path ran in {} rows", t.run.steps);
    }

    /// ⭐ THE HASH AND THE NULLIFIER ARE REAL VALUES, AND THE NULLIFIER LEAVES AN EFFECT THE CHAIN CAN
    /// REFUSE. A contract that could produce a spend tag the chain never sees would be a contract that
    /// spends twice.
    #[test]
    fn hashing_produces_the_canonical_bytes_and_a_nullifier_lands_in_the_effects_fold() {
        let code = Asm::new()
            .entry("main")
            .op(op::POP)
            .push_bytes(b"secret")
            .op(op::NULLIFIER)
            .op(op::RETURN)
            .build();
        let t = go(&code, b"").expect("the program runs");
        let cid = str_digest(&[0u8; 32]);
        let want = vm_nullifier(&cid, &str_digest(b"secret"));
        assert_eq!(
            t.run.ret,
            crate::poseidon2_compress::digest_to_bytes(&want).to_vec(),
            "the tag on the stack is the canonical 32-byte form of the derived nullifier"
        );
        assert_eq!(t.run.effects, vec![Effect::Nullifier { tag: want }], "the tag rode out as an EFFECT");
        assert_ne!(
            t.run.effects_digest,
            [0u64; DIGEST_LANES],
            "⛔ the effects fold did not move — a dropped effect is a spend the chain never hears about"
        );

        // The POSEIDON opcode's own result is the digest of what it hashed, in canonical bytes.
        let hcode =
            Asm::new().entry("main").op(op::POP).push_bytes(b"abc").op(op::POSEIDON).op(op::RETURN).build();
        let h = go(&hcode, b"").expect("the hash program runs");
        assert_eq!(
            h.run.ret,
            crate::poseidon2_compress::digest_to_bytes(&str_digest(b"abc")).to_vec(),
            "POSEIDON pushes the canonical bytes of the string's own digest"
        );
    }

    /// ⛔ AN OPCODE THIS MACHINE CANNOT PROVE IS REFUSED, NOT RUN. A VM that executed `SHA3` natively and
    /// then could not prove it would produce calls that work locally and fail at every peer.
    #[test]
    fn an_unprovable_opcode_is_refused_rather_than_run() {
        for o in [op::SHA3, op::EXT_CALL_TAIL] {
            let code = Asm::new().entry("main").op(o).op(op::RETURN).build();
            assert_eq!(
                go(&code, b"").err(),
                Some(VmError::NotProvable(o)),
                "opcode 0x{o:02x} must be refused by name, so a contract author learns WHY"
            );
        }
    }

    /// ⭐ ARITHMETIC AND CONTROL FLOW, END TO END — the ordinary computation a predicate is made of.
    /// `if (7 * 6 != 42) revert; return 1`.
    #[test]
    fn the_machine_computes_and_branches() {
        let mut a = Asm::new()
            .entry("main")
            .op(op::POP)
            .push_u64(7)
            .push_u64(6)
            .op(op::MUL_U64)
            .push_u64(42)
            .op(op::EQ)
            .op(op::NOT);
        // The REVERT arm sits after `JUMPI(5) + PUSH_U64(9) + RETURN(1)`.
        let revert_at = a.here() + 5 + 9 + 1;
        a = a.jumpi(revert_at).push_u64(1).op(op::RETURN).op(op::REVERT);
        let code = a.build();
        let t = go(&code, b"").expect("the program runs");
        assert_eq!(t.run.ret, 1u64.to_le_bytes().to_vec(), "the true arm returned 1");
        assert!(
            t.steps.iter().any(|s| s.op == op::JUMPI),
            "the branch really executed — a pin over a program that never branches proves nothing"
        );

        // THE OTHER ARM, or the branch is untested: make the product wrong and the call must REVERT.
        let mut b = Asm::new()
            .entry("main")
            .op(op::POP)
            .push_u64(7)
            .push_u64(6)
            .op(op::MUL_U64)
            .push_u64(43)
            .op(op::EQ)
            .op(op::NOT);
        let r2 = b.here() + 5 + 9 + 1;
        b = b.jumpi(r2).push_u64(1).op(op::RETURN).op(op::REVERT);
        assert_eq!(go(&b.build(), b"").err(), Some(VmError::Revert), "the false arm reverts");
    }

    /// ⛔ THE BUDGET IS A BOUND, NOT A SUGGESTION. An unbounded loop must stop at the budget, because the
    /// trace height is what a verifier's shape gate reads.
    #[test]
    fn an_endless_loop_stops_at_the_budget_rather_than_running_forever() {
        let hdr = 5 + 8;
        let mut out = vec![DSOL_VERSION];
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&entry_hash(b"main").to_le_bytes());
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        out.push(op::JUMP);
        out.extend_from_slice(&(hdr as u32).to_le_bytes());
        let r = run(&out, "main", b"", VmCtx::default(), StorageTrie::default(), 64, &mut NoHost);
        assert_eq!(r.err(), Some(VmError::BudgetExhausted), "the loop was stopped by the budget");
    }
}
