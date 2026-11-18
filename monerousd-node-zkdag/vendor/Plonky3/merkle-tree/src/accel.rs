//! ⭐ SPEED G2 (MonerousD lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md §8) — an optional ACCELERATOR for
//! the streamed tree's two hash passes: the leaf digests (one sponge per committed row) and the layers above them (one
//! compression per parent).
//!
//! MEASURED why: on a real node proving blocks (main ffd3e074, 40 s stack sample) the leaf sponge was 17.6 % and the
//! compressions about 12 % of the prover's working CPU; the same Poseidon2 permutation runs at 122 M/s on the M1 Pro's
//! GPU against 5.68 M/s on one NEON core.
//!
//! This crate is `no_std` and generic over its hash types with no `'static` bound, so the accelerator is handed RAW
//! words and the type NAMES: it acts only on hasher types it registered itself and on 4-byte values, and answers
//! `None` for anything else. The tree then hashes on the CPU exactly as before.
//!
//! SAFE-FALLBACK: `None` (an unknown type, no GPU, a failed dispatch, a failed spot check) runs this crate's own CPU
//! pass — the very pass the accelerator mirrors — so the alternate path computes exactly the same digests and costs
//! only time.
//! Protects it (AGENTS §2 AI RESISTANT): (b) ordinary code — a wrong digest changes the commitment, and every proof is
//! still checked in full by its prover's own verify and by every peer, so a faulty accelerator can cost a proof, never
//! pass a false one.
//! Scale: constant — nothing here grows with nodes, items or height.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// One leaf pass: hash each of `rows.len() / (width · value_bytes)` rows with the hasher at `hasher`.
pub struct LeafJob<'a> {
    pub hasher_type: &'static str,
    pub value_type: &'static str,
    pub digest_type: &'static str,
    /// The hasher, type-erased; valid only as `hasher_type`.
    pub hasher: *const (),
    /// The rows' values, raw, row-major.
    pub rows: &'a [u8],
    pub width: usize,
    pub digest_elems: usize,
}

/// One layer pass: `out_len` parents, each the compression of `step` consecutive children of `prev` (the rest of the
/// arity filled with the default digest).
pub struct CompressJob<'a> {
    pub compress_type: &'static str,
    pub digest_type: &'static str,
    /// The compression, type-erased; valid only as `compress_type`.
    pub compress: *const (),
    /// The previous layer's digests, raw.
    pub prev: &'a [u8],
    pub step: usize,
    pub arity: usize,
    pub digest_elems: usize,
    pub out_len: usize,
}

/// The two accelerated passes; each returns the raw digests (`rows · digest_elems` or `out_len · digest_elems` words) or
/// `None` to let the CPU pass run.
pub struct MerkleAccel {
    pub leaves: fn(&LeafJob<'_>) -> Option<Vec<u8>>,
    pub compress: fn(&CompressJob<'_>) -> Option<Vec<u8>>,
}

static ACCEL: AtomicUsize = AtomicUsize::new(0);

/// Install `accel` for every streamed tree in this process (`None` removes it).
pub fn set_merkle_accel(accel: Option<&'static MerkleAccel>) {
    ACCEL.store(accel.map_or(0, |a| a as *const MerkleAccel as usize), Ordering::Release);
}

pub(crate) fn installed() -> Option<&'static MerkleAccel> {
    let p = ACCEL.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: the only non-zero value ever stored is the address of a `&'static MerkleAccel`.
        Some(unsafe { &*(p as *const MerkleAccel) })
    }
}

/// `bytes` as `n` values of `T` (each `size_of::<T>()` bytes, read unaligned); `None` when the length is not exact.
pub(crate) fn values_from_bytes<T: Copy>(bytes: &[u8], n: usize) -> Option<Vec<T>> {
    let sz = core::mem::size_of::<T>();
    if bytes.len() != n * sz {
        return None;
    }
    // SAFETY: each read covers `sz` bytes inside `bytes`; `T: Copy` and the caller passes T only when the accelerator
    // was handed and returned values of exactly this type (4-byte field words checked by name and size).
    Some((0..n).map(|i| unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(i * sz) as *const T) }).collect())
}

/// `values` as raw bytes.
pub(crate) fn bytes_of<T>(values: &[T]) -> &[u8] {
    // SAFETY: a slice of `T` is `len · size_of::<T>()` initialised bytes.
    unsafe { core::slice::from_raw_parts(values.as_ptr() as *const u8, core::mem::size_of_val(values)) }
}
