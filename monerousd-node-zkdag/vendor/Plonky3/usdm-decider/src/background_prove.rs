// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! MonerousD Protocol — BLOCKS FIRST: a proof nothing is waiting on runs on spare cycles.
//!
//! MEASURED 2026-11-03 (`sample`, a live `usdmd-node` on a two-node real network, 40 s): the whole-chain certificate step was on CPU the
//! whole window and its deep grinds were the largest single term, on the same worker pool as the block's proof, so a block took ~16 s
//! to prove against 9.5 s alone and each node made a block every ~18 s. The certificate only serves a joiner's bundle; a block is the
//! chain. So background proofs run on their own pool, one worker per core, at the OS's low priority: an idle machine gives them every
//! core, a proving block preempts them. Proof bytes do not depend on the pool (`a_parallel_prove_is_byte_identical_to_a_one_thread_prove`).
//! cons: 0 B; one idle pool of parked threads; while blocks are proving a certificate takes longer, so a joiner's bundle is older by that
//! much, and a joiner closes a shallower gap by the block lanes.

use std::sync::OnceLock;

fn lower_this_thread() {
    // SAFETY: both calls change only the calling thread's scheduling class and take no pointers.
    #[cfg(target_vendor = "apple")]
    unsafe {
        // UTILITY, not BACKGROUND: macOS confines BACKGROUND to the efficiency cores and throttles its I/O
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    unsafe {
        // on Linux, `who = 0` under PRIO_PROCESS is the calling thread
        libc::setpriority(libc::PRIO_PROCESS, 0, 19);
    }
}

fn pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .thread_name(|i| format!("background-prove-{i}"))
            .start_handler(|_| lower_this_thread())
            .build()
            .ok()
    })
    .as_ref()
}

/// Run `f` and every parallel loop inside it on the background pool. A pool the OS refused runs `f` here instead: slower for blocks, never wrong.
pub fn run<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    match pool() {
        Some(p) => p.install(f),
        None => f(),
    }
}
