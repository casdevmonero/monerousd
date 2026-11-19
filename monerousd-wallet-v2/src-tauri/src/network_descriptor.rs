// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! Canonical MonerousD NETWORK DESCRIPTOR — the SINGLE self-maintaining source of the values a fresh
//! wallet-node needs to JOIN the one canonical chain automatically. It exists so a chain split is
//! impossible by construction and every future user lands on the SAME mesh with zero manual config.
//!
//! Two facts define "the canonical chain", and both are self-maintaining:
//!   1. NETWORK — deterministic + constant per network. The node derives its network id from the network
//!      NAME alone (mirrors `main.rs::net_magic`): testnet and mainnet are distinct, and the id does NOT
//!      change across a re-genesis. Nothing to configure, nothing to drift — every node computes the same
//!      network by construction. The wallet reads the node's LIVE `chain_id` (via /get_info) as the exact
//!      genesis fingerprint and compares it to the canonical one, so a stale/forked node is auto-detected.
//!   2. BOOTSTRAP SEED PEERS — the onion entrypoint(s) a brand-new node dials to find the mesh. Once it has
//!      ONE peer it auto-discovers the rest from the chain-anchored peer directory and adopts the canonical
//!      chain via #29 DSYNC (verify-once). These are DISCOVERY entrypoints only — NO value (fee/reward/mint/
//!      bond) is ever routed to a seed, so a canonical shared list is correct, not a value-routing single
//!      point. The node still peers BIDIRECTIONALLY + converges; the seed just bootstraps the first hop.
//!
//! Everything here is a canonical DEFAULT that stands alone for ordinary users, OVERRIDABLE by env for
//! dev/ops (`MONEROUSD_NET`, `MONEROUSD_LIBP2P_SEED_PEERS`). No device-local file, no per-user hand-config.

/// The network this wallet targets. `MONEROUSD_NET` overrides (dev/ops); the canonical default is testnet.
pub fn canonical_net() -> String {
    std::env::var("MONEROUSD_NET")
        .ok()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "testnet".to_string())
}

/// The exact `MONEROUSD_LIBP2P_SEED_PEERS` value the launched node should receive to find the mesh — the
/// onion entrypoint(s) it dials for the FIRST hop, after which it auto-discovers the rest from the
/// chain-anchored peer directory and adopts the canonical chain via #29 DSYNC. `Some` = forward this;
/// `None` = nothing to force (the node uses any peer it already knows). Resolution:
///   1. `MONEROUSD_LIBP2P_SEED_PEERS` env — forwarded VERBATIM (dev/ops; never re-split, so the node's own
///      separator/format is preserved byte-for-byte).
///   2. else the compiled-in canonical published seed list for the network (identical in every wallet build).
/// Empty canonical is honest: with no override and no published seed yet, a fresh node never dials a
/// wrong/guessed peer and never silently joins the wrong network.
pub fn seed_peers_env_value() -> Option<String> {
    if let Ok(env_peers) = std::env::var("MONEROUSD_LIBP2P_SEED_PEERS") {
        let v = env_peers.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let canonical = canonical_seed_peers_for(&canonical_net());
    if canonical.is_empty() {
        None
    } else {
        // Node peer-list separator is comma; the release step verifies against the node's parser when it
        // publishes the seed onions. Discovery entrypoints only — no value is ever routed to a seed.
        Some(canonical.join(","))
    }
}

/// ⭐ OUR OWN NETWORK'S FIRST CONTACT (lane af57, 2026-11-15; user: "finish pqmix to fully replace tor now"): the relay faces
/// this wallet's node dials into our own network (pqmix), as `MONEROUSD_MIX_SEEDS` (`relay:<address>:<port>`, comma-separated).
/// MEASURED: the wallet forwarded onion seeds only, so a wallet's node never joined our network and a Tor outage stopped it.
/// The env override wins, as for the onion seeds; else the release's compiled list (`canonical_mix_relays_<net>.txt`, written
/// by `scratchpad/seed_list.py --relays` from a running node's `/get_relay_faces`). While Tor is up the node also learns relay
/// faces over Tor (kind 30), so an empty list still links a node that has reached the chain once; the list is what a node
/// installed DURING an outage has.
pub fn mix_seeds_env_value() -> Option<String> {
    if let Ok(v) = std::env::var("MONEROUSD_MIX_SEEDS") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    let canonical = canonical_mix_relays_for(&canonical_net());
    if canonical.is_empty() {
        None
    } else {
        Some(canonical.join(","))
    }
}

/// The compiled-in relay faces per network: one `relay:<address>:<port>` per line, `#` comments. Public by design (a relay face
/// names a relay, never a hidden address: docs/MONEROUSD-NATIVE-NETWORK-SPEC-20261107.md §1 limit 2).
fn canonical_mix_relays_for(net: &str) -> Vec<String> {
    match net {
        "testnet" => include_str!("canonical_mix_relays_testnet.txt")
            .lines()
            .map(|l| l.split('#').next().unwrap_or("").trim())
            .filter(|l| l.starts_with("relay:"))
            .map(|l| l.to_string())
            .collect(),
        _ => Vec::new(), // mainnet relay faces pinned at mainnet launch
    }
}

/// The compiled-in canonical seed list per network. Kept as its own fn so the release step edits ONE place
/// and every wallet build carries the identical entrypoints — the shared-by-construction bootstrap.
fn canonical_seed_peers_for(net: &str) -> Vec<String> {
    match net {
        // Canonical PUBLISHED testnet bootstrap seeds — the .onion mesh entrypoints a fresh node auto-dials
        // for its FIRST hop, after which it auto-discovers the rest from the chain-anchored peer directory and
        // adopts the canonical chain via #29 DSYNC. Each line is `peer_id|/dns/<onion>/tcp/<port>|x_pk|ek`
        // (public bootstrap addresses only — no value is ever routed to a seed, so a shared list is correct,
        // not a value-routing single point). Compiled in via include_str! so every wallet build carries the
        // identical entrypoints by construction; a re-genesis refreshes this one data file at release.
        "testnet" => include_str!("canonical_seeds_testnet.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && l.contains(".onion/tcp/"))
            .map(|l| l.to_string())
            .collect(),
        _ => Vec::new(), // mainnet seeds pinned at mainnet launch
    }
}

/// How many canonical bootstrap entrypoints this build carries (0 until seeds are published) — surfaced to
/// the UI so the mesh-join status is a live mirror, never a guess.
pub fn canonical_seed_count() -> usize {
    canonical_seed_peers_for(&canonical_net()).len()
}

/// The canonical `chain_id` (the PUBLIC genesis fingerprint every node exposes via /get_info that uniquely
/// identifies THIS chain — like a chain's genesis hash; reveals nothing about state). The wallet compares the
/// node's LIVE chain_id to this to AUTO-DETECT a node on a stale/forked chain — a chain split is surfaced,
/// never silent. Baked-in default identical for every user by construction; `MONEROUSD_CANONICAL_CHAIN_ID`
/// overrides for dev, or immediately after a testnet re-genesis before this constant is refreshed at release.
pub fn canonical_chain_id(net: &str) -> Option<String> {
    if let Ok(v) = std::env::var("MONEROUSD_CANONICAL_CHAIN_ID") {
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    // BY CONSTRUCTION, THROUGH THE NODE CRATE ITSELF (2026-08-25): the node's /get_info `chain_id` is the
    // hex of the DETERMINISTIC GENESIS BLOCK ID (the true chain identity — rpc_http.rs). The old mirror
    // here re-implemented an EARLIER formula (blake3 of the netid prefix) and silently drifted when the
    // node moved to genesis-block identity — every wallet then showed "⚠ off-canonical chain" against a
    // perfectly canonical node, forever. A re-implementation can drift again; calling the node crate's own
    // genesis constructor cannot: this computes the byte-identical header every node on `net` builds and
    // hashes it with the same block-id function. One source of truth, zero pinned constants.
    // The node crate's ONE prefix (lane dcash 2026-11-12): the mainnet genesis also commits to its launch anchor
    // (`params::LaunchAnchor`), which a copy of the old two-field formula here would have missed — the same drift class
    // the paragraph above records, on the prefix instead of the header.
    let prefix = usdmd_node::params::network_genesis_prefix(net);
    // ⛔⛔⛔ ONE DEFINITION, NEVER TWO — THIS HAND-ROLLED COPY BROKE THE WHOLE WALLET FOR TWO DAYS.
    //
    // This used to construct `usdmd_node::block::Block { .. }` field by field. `Block::settlement` was
    // replaced by `note_transition` in §CB on 2026-09-15, and from that moment `monerousd-wallet-v2` did
    // not COMPILE against the node: `error[E0560]: struct Block has no field named 'settlement'`. Nothing
    // reported it, because the node's own `cargo test` never builds this tree — the same silence that hid
    // `tests/psm_bridge_e2e.rs` dying on `credit_set` the same week.
    //
    // ⭐ A HAND-ROLLED COPY OF A CONSENSUS STRUCT IS A CLOCK THAT STARTS RUNNING THE MOMENT IT IS WRITTEN,
    // and this one is load-bearing: the id it computes is what the fork-detector compares against a live
    // node's `/get_info` chain_id, so a wallet building a shape the node no longer produces would report a
    // fork that does not exist. The node now owns the whole genesis block, for a named network too.
    let genesis = usdmd_node::block::genesis_block_for_network(&prefix);
    Some(hex::encode(genesis.id().as_bytes()))
}

#[cfg(test)]
mod canonical_id_tests {
    /// The fork-detector's canonical id must equal the LIVE node's /get_info chain_id. If the node's
    /// genesis construction ever changes shape, this pins the drift loudly instead of every wallet
    /// silently showing "off-canonical" forever.
    ///
    /// ⭐⭐⭐ THE ID MOVED AND THEN MOVED BACK, ON 2026-08-26 — AND THE LIVE CHAIN NEVER CHANGED.
    /// The confidential-AMM block carrier added `BlockHeader::amm_set_root`, which is committed into the
    /// block id unconditionally, so genesis hashed differently: `fc6a3623…` → `593957f8…`. When the pool
    /// AMM was retired at source that field was deleted, the header preimage reverted to exactly what it
    /// had always been, and genesis hashed back to `fc6a3623…` — MEASURED both times by this test.
    ///
    /// TWO THINGS WORTH KEEPING FROM THAT ROUND TRIP. First, the live 154k testnet was NEVER on the
    /// intermediate id: it kept running the deployed binary throughout, so no re-genesis was ever needed
    /// and none happened — the fork existed only in un-deployed source. Second, THIS TEST IS WHY WE KNOW
    /// THAT. A pinned constant is not "whatever the code says today"; it is the value a wallet and a node
    /// must BOTH arrive at, so it fails loudly the moment a header change moves chain identity — in
    /// either direction. Had the pin been left at the intermediate value, every wallet would have shown
    /// "⚠ off-canonical chain" against a perfectly canonical node, forever, which is exactly the defect
    /// this pin exists to prevent.
    #[test]
    fn canonical_testnet_id_matches_the_live_node_genesis_identity() {
        // ⛔⛔⛔ RED 2026-09-24, AND CORRECTLY SO — DO NOT "FIX" THIS BY EDITING THE LITERAL.
        //
        // MEASURED against the running pair (`/get_info`, ports 27780 and 28901, both answering):
        //     live testnet chain_id : 593957f8a4ad9ed5c86a2abff04af4f125ea6437a0f2c196d9f789f89de3b818
        //     current source computes: fc6a36237397ee9d66271288a9116c8a1e8671a6ea45c50d50f8214db7e3c1d1
        //
        // So a node built from THIS SOURCE forks from the live chain AT HEIGHT 1, and a wallet built from
        // it reports the live chain as off-canonical. The pinned literal is the LIVE value and is right;
        // the source has drifted since the deployed binary (~2026-09-22). Editing the literal to match the
        // source would silence the one instrument that can see this and hand every wallet a permanent
        // "⚠ off-canonical chain" against a perfectly canonical node — the exact defect this pin's own
        // doc, above, says it exists to prevent.
        //
        // ⛔ IT WENT UNSEEN BECAUSE THIS TEST COULD NOT RUN. `cargo test` builds every target, and three
        // `examples/` plus `tests/oli_live_send.rs` carried the stale 4-lane digest, so the WHOLE wallet
        // suite failed to COMPILE — which reads as an environment problem and gets skipped, not as a red
        // test. A suite that does not build is worse than one that is red. Fixed 2026-09-24.
        //
        // THE RESOLUTION IS A DEPLOY DECISION, NOT A CODE EDIT: either the live testnet is re-genesised
        // onto the current binary (regeneses are routine here — #7 by 2026-09-22 — and both DB-154's
        // committed nullifier root and governance-as-a-chain-object need one anyway, so they should ride
        // the same batch), or the change that moved genesis identity is reverted. Re-pin this literal AT
        // THAT DEPLOY, to whatever the deployed binary then answers on `/get_info`.
        assert_eq!(
            super::canonical_chain_id("testnet").as_deref(),
            // RE-PINNED 2026-10-05 AT THE DEPLOY, as the note above prescribes: after lane-night's 05:20 re-genesis roll
            // both live nodes answer `/get_info` chain_id efa9f0e6… (MEASURED 09:4x: :27780 at height 2085, :28901 at
            // 2008), and this source computes the same value. The previous literal 593957f8… was the 2026-09-19 genesis.
            // RE-PINNED 2026-10-24 with the node's genesis pin: `cover_seed_commit` joined the header preimage (lane a
            // §RF-3), a deliberate re-genesis; the paused live pair rolls onto it at F4. Again the same day: the
            // header's `member_ring_commit` joined the preimage (was 121e2601…).
            // RE-PINNED 2026-11-10 with the node's genesis pin (lane goods): the source has derived 73bd8768… since the
            // header's state commits landed (2026-11-06); both literals were left behind and read RED on main.
            Some("f10d0361e0ca1972264cc40d602cb41104649b9c8ada7d964057512b9e0f7a13"),
            "wallet fork-detector and node genesis identity must agree by construction"
        );
    }
}

/// ⭐ §BR-12 — the FIRST-PARTY APPS' PUBLISHER ADDRESS (the wallet's own interface fees go to it): the compiled-in canonical
/// file for the network, identical in every wallet build, so no device and no relay chooses where fees go. A per-entity
/// key the publisher may rotate by publishing a new build. `None` while the file is empty: fees are then shown and recorded
/// as owed but nothing is paid — never sent to a guessed address. `MONEROUSD_PUBLISHER_ADDRESS` overrides (dev/ops).
pub fn canonical_publisher_address() -> Option<String> {
    if let Some(a) = std::env::var("MONEROUSD_PUBLISHER_ADDRESS").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        return Some(a);
    }
    let raw = match canonical_net().as_str() {
        "testnet" => include_str!("canonical_publisher_testnet.txt"),
        _ => "",
    };
    raw.lines().map(str::trim).find(|l| !l.is_empty() && !l.starts_with('#')).map(str::to_string)
}
