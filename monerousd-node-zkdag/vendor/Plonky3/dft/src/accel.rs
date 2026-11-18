//! ⭐ SPEED G3 (MonerousD lane speed4, 2026-11-12, docs/SPEED-MAX-PROGRAM-20261112.md) — an optional ACCELERATOR for the
//! small-batch radix-2 DFT: the forward transform (`dft_batch`) and the low-degree extension (`coset_lde_batch`).
//!
//! This crate is `no_std` and generic over its field with no `'static` bound, so the accelerator is handed RAW words and
//! the field's type NAME, plus the field constants the transform needs (computed here, by the field's own arithmetic):
//! it acts only on a field it recognises and answers `None` for anything else; the CPU transform then runs as before.
//!
//! SAFE-FALLBACK: `None` (an unknown field, no GPU, a failed dispatch, a failed spot check) runs this crate's own CPU
//! transform — the very function the accelerator computes — so the alternate path produces the same values and costs
//! only time.
//! Protects it (AGENTS §2 AI RESISTANT): (b) ordinary code — a wrong evaluation changes the commitment, and every proof
//! is still checked in full by its prover's own verify and by every peer, so a faulty accelerator can cost a proof, never
//! pass a false one.
//! Scale: constant — nothing here grows with nodes, items or height.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};

/// One transform, all values raw (4-byte field words) and row-major `height × width`.
pub struct DftJob<'a> {
    pub value_type: &'static str,
    pub values: &'a [u8],
    pub height: usize,
    pub width: usize,
    /// A generator of the subgroup of order `height` (the forward transform's root).
    pub root: &'a [u8],
    /// LDE only: the inverse of `root`, `1/height`, the coset shift, the output's root (order `height << added_bits`).
    pub inv_root: &'a [u8],
    pub inv_height: &'a [u8],
    pub shift: &'a [u8],
    pub out_root: &'a [u8],
    pub added_bits: usize,
}

/// The two accelerated transforms; each returns the raw output (`height × width` words, or `(height << added_bits) ×
/// width` for the LDE) or `None` to let the CPU transform run.
pub struct DftAccel {
    pub dft: fn(&DftJob<'_>) -> Option<Vec<u8>>,
    pub lde: fn(&DftJob<'_>) -> Option<Vec<u8>>,
}

static ACCEL: AtomicUsize = AtomicUsize::new(0);

/// Install `accel` for every small-batch DFT in this process (`None` removes it).
pub fn set_dft_accel(accel: Option<&'static DftAccel>) {
    ACCEL.store(accel.map_or(0, |a| a as *const DftAccel as usize), Ordering::Release);
}

pub(crate) fn installed() -> Option<&'static DftAccel> {
    let p = ACCEL.load(Ordering::Acquire);
    if p == 0 {
        None
    } else {
        // SAFETY: the only non-zero value ever stored is the address of a `&'static DftAccel`.
        Some(unsafe { &*(p as *const DftAccel) })
    }
}

/// The forward transform of `mat` from the installed accelerator, or `None` (then the CPU transform runs).
pub(crate) fn try_dft<F: p3_field::TwoAdicField>(mat: &p3_matrix::dense::RowMajorMatrix<F>) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
    let a = installed()?;
    let (h, w) = (mat.values.len().checked_div(mat.width)?, mat.width);
    if core::mem::size_of::<F>() != 4 || w == 0 || h < 2 || !h.is_power_of_two() {
        return None;
    }
    let log_h = h.trailing_zeros() as usize;
    let root = [F::two_adic_generator(log_h)];
    let job = DftJob {
        value_type: core::any::type_name::<F>(),
        values: bytes_of(&mat.values),
        height: h,
        width: w,
        root: bytes_of(&root),
        inv_root: &[],
        inv_height: &[],
        shift: &[],
        out_root: &[],
        added_bits: 0,
    };
    let raw = (a.dft)(&job)?;
    Some(p3_matrix::dense::RowMajorMatrix::new(values_from_bytes(&raw, h * w)?, w))
}

/// The low-degree extension of `mat` (evaluations on the subgroup of order `height` in, evaluations on `shift` times
/// the subgroup of order `height << added_bits` out) from the installed accelerator, or `None`.
pub(crate) fn try_lde<F: p3_field::TwoAdicField>(
    mat: &p3_matrix::dense::RowMajorMatrix<F>,
    added_bits: usize,
    shift: F,
) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
    let a = installed()?;
    let (h, w) = (mat.values.len().checked_div(mat.width)?, mat.width);
    if core::mem::size_of::<F>() != 4 || w == 0 || h < 2 || !h.is_power_of_two() {
        return None;
    }
    let log_h = h.trailing_zeros() as usize;
    let root = [F::two_adic_generator(log_h)];
    let inv_root = [root[0].inverse()];
    let inv_height = [F::from_usize(h).inverse()];
    let shift_v = [shift];
    let out_root = [F::two_adic_generator(log_h + added_bits)];
    let job = DftJob {
        value_type: core::any::type_name::<F>(),
        values: bytes_of(&mat.values),
        height: h,
        width: w,
        root: bytes_of(&root),
        inv_root: bytes_of(&inv_root),
        inv_height: bytes_of(&inv_height),
        shift: bytes_of(&shift_v),
        out_root: bytes_of(&out_root),
        added_bits,
    };
    let raw = (a.lde)(&job)?;
    Some(p3_matrix::dense::RowMajorMatrix::new(values_from_bytes(&raw, (h << added_bits) * w)?, w))
}

/// `values` as raw bytes.
pub(crate) fn bytes_of<T>(values: &[T]) -> &[u8] {
    // SAFETY: a slice of `T` is `len · size_of::<T>()` initialised bytes.
    unsafe { core::slice::from_raw_parts(values.as_ptr() as *const u8, core::mem::size_of_val(values)) }
}

/// `bytes` as `n` values of `T`; `None` when the length is not exact.
pub(crate) fn values_from_bytes<T: Copy>(bytes: &[u8], n: usize) -> Option<Vec<T>> {
    let sz = core::mem::size_of::<T>();
    if bytes.len() != n * sz {
        return None;
    }
    // SAFETY: each read covers `sz` bytes inside `bytes`; the caller passes `T` only when the accelerator was handed and
    // returned values of exactly this 4-byte field type (checked by name and size).
    Some((0..n).map(|i| unsafe { core::ptr::read_unaligned(bytes.as_ptr().add(i * sz) as *const T) }).collect())
}
