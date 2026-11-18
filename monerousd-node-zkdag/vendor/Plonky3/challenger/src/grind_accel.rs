//! ⭐ SPEED G1 (MonerousD lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8) — an optional ACCELERATOR for
//! the duplex challenger's proof-of-work grind.
//!
//! MEASURED why: a 40 s stack sample of a real node proving blocks (main ffd3e074) spent 14.5 % of the prover's working
//! CPU in grinding, and the same Poseidon2 permutation runs at 122 M/s on the M1 Pro's GPU against 5.68 M/s on one
//! NEON core.
//!
//! The challenger crate is `no_std` and generic, so it knows nothing about GPUs or about which permutation it holds. A
//! higher crate installs ONE function ([`set_grind_accel`]); the duplex challenger's `try_grind` hands it the
//! permutation (as `&dyn Any`, to be recognised or declined), the state the next permutation acts on, and where the
//! witness goes in and the sample comes out. The accelerator must return the SMALLEST witness the CPU search would
//! return, or `None`. Whatever it returns is checked by the challenger's own `check_witness` before it is used, so an
//! accelerator can make a grind faster and never makes a proof invalid.
//!
//! Protects it (AGENTS §2 AI RESISTANT): (b) ordinary code — the accelerator only proposes; soundness rests on the
//! unchanged `check_witness` and on every verifier's own check of the witness.
//! Scale: nothing here grows with nodes, items or height; one atomic load per grind.

use core::any::Any;
use core::sync::atomic::{AtomicUsize, Ordering};

/// What one grind asks: find the smallest `w < order` such that permuting `base` with `w` written at `witness_idx`
/// gives an element at `out_idx` whose canonical value has its low `bits` bits zero. All values canonical.
pub struct GrindJob<'a> {
    /// The challenger's permutation, for the accelerator to recognise (by downcasting) or decline.
    pub permutation: &'a dyn Any,
    /// The state the next permutation acts on: the buffered inputs over the sponge state, canonical.
    pub base: &'a [u64],
    /// The slot the witness is written to (the input buffer's length).
    pub witness_idx: usize,
    /// The slot the sample is read from (`RATE - 1`).
    pub out_idx: usize,
    /// The number of low bits that must be zero.
    pub bits: usize,
    /// The field order; a witness is below it.
    pub order: u64,
}

/// An accelerated grind: the smallest witness, or `None` to let the CPU search run.
pub type GrindAccel = fn(&GrindJob<'_>) -> Option<u64>;

static ACCEL: AtomicUsize = AtomicUsize::new(0);

/// Install `accel` for every duplex challenger in this process (`None` removes it).
pub fn set_grind_accel(accel: Option<GrindAccel>) {
    ACCEL.store(accel.map_or(0, |f| f as usize), Ordering::Release);
}

/// The installed accelerator, if any.
pub(crate) fn installed() -> Option<GrindAccel> {
    let p = ACCEL.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: the only non-zero value ever stored is a `GrindAccel` function pointer cast to `usize`.
        Some(unsafe { core::mem::transmute::<usize, GrindAccel>(p) })
    }
}
