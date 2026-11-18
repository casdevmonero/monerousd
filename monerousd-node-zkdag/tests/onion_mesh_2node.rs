// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! 2-NODE ONION CONVERGENCE PROOF (real Tor, no loopback island). Brings up TWO independent
//! [`ArtiOnionTransport`] nodes — each hosts its OWN `.onion` service, dials the OTHER's `.onion`, and the two
//! exchange fixed-size cells BOTH ways over live Tor. This is the de-island primitive: two separate nodes on the
//! real onion mesh converging, not a same-process loopback. Full block-DAG graft rides on top of this cell
//! channel; here we prove the channel itself carries a node's bytes bidirectionally over onion.
//!
//! Requires outbound Tor connectivity (arti bootstrap + HS publish + rendezvous), so it is `#[ignore]` by default
//! and run explicitly: `cargo test --no-default-features --features "pq-randomx arti-onion" --test
//! onion_mesh_2node -- --ignored --nocapture`. It PRINTS the measured onion-publish + first-cell-delivery times.

#![cfg(feature = "arti-onion")]

use std::time::{Duration, Instant};
use usdmd_node::arti_transport::{ArtiOnionTransport, ONION_CELL_PORT};
use usdmd_node::net::CELL_SIZE;
use usdmd_node::transport::CellTransport;

fn wait_onion(t: &ArtiOnionTransport, label: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(240);
    let t0 = Instant::now();
    loop {
        if let Some((onion, _x, _ek)) = t.peering().own_identity() {
            eprintln!("[mesh2] {label} onion up in {:?}: {onion}", t0.elapsed());
            return onion;
        }
        assert!(
            Instant::now() < deadline,
            "{label} onion service did not publish within 240s"
        );
        std::thread::sleep(Duration::from_millis(500));
    }
}

fn wait_cell(t: &ArtiOnionTransport, want: &[u8], label: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(180);
    let t0 = Instant::now();
    while Instant::now() < deadline {
        if let Some(cell) = t.recv_cell() {
            if cell == want {
                eprintln!(
                    "[mesh2] {label} received the peer's cell over onion in {:?}",
                    t0.elapsed()
                );
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
#[ignore = "needs live Tor connectivity; run with --ignored"]
fn two_separate_nodes_converge_cells_over_onion() {
    let tmp = std::env::temp_dir();
    let a = ArtiOnionTransport::spawn(tmp.join("usdmd-mesh2-a")).expect("spawn A");
    let b = ArtiOnionTransport::spawn(tmp.join("usdmd-mesh2-b")).expect("spawn B");

    // Each node publishes its own dialable `.onion`.
    let onion_a = wait_onion(&a, "A");
    let onion_b = wait_onion(&b, "B");
    assert_ne!(
        onion_a, onion_b,
        "the two nodes must have distinct onion identities"
    );

    // MUTUAL seeding — A dials B and B dials A (bidirectional peering, `.onion` only, never an IP).
    let rec_b = format!("/dns/{onion_b}/tcp/{ONION_CELL_PORT}");
    let rec_a = format!("/dns/{onion_a}/tcp/{ONION_CELL_PORT}");
    assert!(a.peering().add("", &rec_b, &[], &[]), "A accepts B seed");
    assert!(b.peering().add("", &rec_a, &[], &[]), "B accepts A seed");

    // A -> B over onion.
    let cell_ab = vec![0x7Au8; CELL_SIZE];
    a.send_cell(cell_ab.clone()).expect("A send");
    assert!(
        wait_cell(&b, &cell_ab, "B"),
        "B never received A's cell over onion (no convergence)"
    );

    // B -> A over onion (proves the link is BIDIRECTIONAL, not one-way).
    let cell_ba = vec![0x9Cu8; CELL_SIZE];
    b.send_cell(cell_ba.clone()).expect("B send");
    assert!(
        wait_cell(&a, &cell_ba, "A"),
        "A never received B's cell over onion (link is one-way)"
    );

    eprintln!(
        "[mesh2] CONVERGED: two separate nodes exchanged cells BOTH ways over the real onion mesh"
    );
}
