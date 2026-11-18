// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! TEST-ONLY LOOPBACK PORT BLOCKS for the external processes a test raises (Bitcoin Core regtest, monerod,
//! monero-wallet-rpc). MEASURED 2026-10-27 (scratchpad/cert/certify-38954c151f3c-20261026-050541.log.chunk84): two
//! journeys in ONE test process each derived the same PID-based RPC port, so the second `bitcoind -daemonwait` died
//! with "Error during initialization" and the PegIn / PegOut value rows measured nothing. Reproduced on the host:
//! the second `bitcoind -regtest -rpcport=<same>` exits 1 with that line.
//! BORROWED: Bitcoin Core test_framework/util.py `p2p_port()` / `rpc_port()` — every instance takes its own index
//! inside a per-process port block (`PortSeed`), so no two instances of one process share a port — plus a bind
//! probe, so a port another process holds (a leftover daemon, a PID collision modulo the block count) is skipped.
//! Compiled only for tests and the `bridge-test-oracle` feature — absent from a release daemon.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU32, Ordering};

/// The instance counter of this process: every reservation takes the next index (Core's node index `n`).
static NEXT_INSTANCE: AtomicU32 = AtomicU32::new(0);
/// Per-process seeds cycle through this many 8-port blocks (Core: `PortSeed.n` spreads processes the same way).
const PROCESS_BLOCKS: u32 = 900;
/// Every caller's range is `base .. base + RANGE`; callers keep their bases ≥ RANGE apart.
const RANGE: u32 = 7000;

pub struct PortBlock {
    /// The first of `span` consecutive loopback ports that were all free at reservation.
    pub first: u16,
    /// This process's reservation index — also the datadir suffix, so two instances never share a directory.
    pub instance: u32,
}

/// `span` consecutive free loopback ports in `base .. base + 7000`, at the PID-seeded offset of this process's next
/// instance; a block any port of which is held is skipped. Deterministic for one (pid, instance) on a quiet host.
pub fn reserve(base: u16, span: u16) -> Result<PortBlock, String> {
    let instance = NEXT_INSTANCE.fetch_add(1, Ordering::SeqCst);
    let span32 = span.max(1) as u32;
    let seed = (std::process::id() % PROCESS_BLOCKS) * 8;
    for k in 0..256u32 {
        let first = base as u32 + (seed + (instance + k) * span32) % (RANGE - span32);
        if (first..first + span32).all(|p| TcpListener::bind(("127.0.0.1", p as u16)).is_ok()) {
            return Ok(PortBlock { first: first as u16, instance });
        }
    }
    Err(format!("no free block of {span} loopback port(s) in {base}..{}", base as u32 + RANGE))
}

#[cfg(all(test, feature = "pins-core"))]
mod pins {
    use super::reserve;

    /// The shape fact with no external process: two reservations of one process are disjoint, and a port another
    /// party holds moves the next block past it.
    #[test]
    fn two_reservations_in_one_process_are_disjoint_and_a_held_port_is_skipped() {
        let a = reserve(41000, 2).expect("first block");
        let b = reserve(41000, 2).expect("second block");
        assert!(a.first + 2 <= b.first || b.first + 2 <= a.first, "overlap: {} and {}", a.first, b.first);
        assert_ne!(a.instance, b.instance);
        // Hold the first port of the block the next instance would take; the reservation must skip past it.
        let held = std::net::TcpListener::bind(("127.0.0.1", b.first + 2)).expect("hold the next block's port");
        let held_port = held.local_addr().expect("addr").port();
        let c = reserve(41000, 2).expect("third block");
        assert!(held_port < c.first || held_port >= c.first + 2, "block {}..{} includes the held port {held_port}", c.first, c.first + 1);
        drop(held);
    }
}
