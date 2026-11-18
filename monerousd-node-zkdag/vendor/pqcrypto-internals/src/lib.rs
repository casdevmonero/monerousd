#![no_std]

//! Vendored from pqcrypto-internals 0.2.11 (MIT OR Apache-2.0, https://github.com/rustpq/pqcrypto) — MonerousD
//! 2026-10-24 (lane b): ONE added seam, [`set_entropy_source`], so the deterministic simulator can replay a seed
//! (FoundationDB's simulator, TigerBeetle's VOPR: every random draw of a simulated process comes from the seed). A
//! daemon never registers a source, so its `randombytes` is the upstream `getrandom::fill`, byte for byte; a registered
//! source that declines (returns `false`: the calling thread has no simulated stream) also falls through to it.

use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};

/// The registered source (`fn(&mut [u8]) -> bool` as a usize; 0 = none — the upstream behaviour).
static SOURCE: AtomicUsize = AtomicUsize::new(0);

/// Register `source`: every `randombytes` call asks it first, and takes the OS RNG when it returns `false`.
/// Only the node crate's TEST harness calls this (a replayable simulated node); no node binary does.
pub fn set_entropy_source(source: fn(&mut [u8]) -> bool) {
    SOURCE.store(source as usize, Ordering::Release);
}

/// Get random bytes; exposed for PQClean implementations.
///
/// # Safety
/// Assumes inputs are valid and may panic over FFI boundary if rng failed.
///
/// # Example
/// ```rust
/// use pqcrypto_internals::*;
/// let mut buf = [0u8;10];
/// unsafe {
///   PQCRYPTO_RUST_randombytes(buf.as_mut_ptr(), buf.len());
/// }
/// ```
#[no_mangle]
pub unsafe extern "C" fn PQCRYPTO_RUST_randombytes(buf: *mut u8, len: libc::size_t) -> libc::c_int {
    let buf = slice::from_raw_parts_mut(buf, len);
    let s = SOURCE.load(Ordering::Acquire);
    if s != 0 {
        // SAFETY: `SOURCE` only ever holds a `fn(&mut [u8]) -> bool` stored by `set_entropy_source`.
        let source: fn(&mut [u8]) -> bool = core::mem::transmute::<usize, fn(&mut [u8]) -> bool>(s);
        if source(buf) {
            return 0;
        }
    }
    getrandom::fill(buf).expect("RNG Failed");
    0
}
