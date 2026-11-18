// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The REAL onion [`CellTransport`]: a libp2p gossip node over Tor v3 `.onion`, linked over FFI.
//!
//! This is the production drop-in for [`crate::transport::LoopbackTransport`]. Compiled ONLY under
//! the `onion` feature (see `Cargo.toml` + `build.rs`); with it off, the node uses the in-process
//! loopback transport and builds as pure Rust. With it on, `build.rs` links the PREBUILT `libp2p_ffi`
//! cdylib (the SAME onion-gossip node the C++ daemon runs — a prebuilt-lib seam like the retired pqpool
//! decider) and no libp2p source is compiled here, so the build loop stays fast.
//!
//! MonerousD is ONION-ONLY: the node is created over a Tor SOCKS proxy ([`OnionTransport::new_onion`])
//! and reached ONLY by `.onion` multiaddr — there is no IP path. A [`crate::net`] cell is carried as a
//! gossipsub message on the fixed `musdm/cells` topic (`send_cell` = publish, `recv_cell` = the next
//! gossip on that topic). Because every cell is exactly [`CELL_SIZE`] and the [`crate::transport::CellChannel`]
//! emits them at a constant rate with cover fill, the onion wire leaks neither size nor timing.
//!
//! Live validation is an integration concern (two nodes gossiping cells over a running Tor) — this
//! module's unit bar is that it LINKS against the real cdylib with the correct C ABI; the 2-node
//! `.onion` DSYNC round-trip is exercised in the node bring-up / testnet, not a hermetic unit test.

use crate::net::{NetError, CELL_SIZE};
use crate::transport::CellTransport;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};

/// The fixed gossipsub topic every fixed-size onion cell rides on.
const CELLS_TOPIC: &str = "musdm/cells";

// Opaque libp2p node handle (owned by the cdylib). We only ever pass the pointer back over FFI.
#[repr(C)]
struct Node {
    _private: [u8; 0],
}

// The reused libp2p_ffi C ABI (see external/libp2p_ffi/src/ffi.rs). Only the onion-node lifecycle +
// gossip publish/subscribe/poll are needed for a CellTransport.
extern "C" {
    /// Bring up an onion gossip node over the Tor SOCKS proxy (C-string, e.g. "127.0.0.1:9050").
    /// Returns a node handle, or null on failure.
    fn musdm_libp2p_node_new_onion(proxy: *const c_char) -> *mut Node;
    /// Same, but with a DETERMINISTIC 32-byte identity seed → a stable base58 PeerId + static keys
    /// (so a peer can be configured with this node's PeerId + PQ keys ahead of time). Null on failure.
    fn musdm_libp2p_node_new_onion_seeded(proxy: *const c_char, seed32: *const u8) -> *mut Node;
    /// This node's own base58 PeerId (written to `buf`, true length to `*len`). 0 = ok, <0 = bad node.
    fn musdm_libp2p_own_peer_id(
        node: *mut Node,
        buf: *mut u8,
        cap: usize,
        len: *mut usize,
    ) -> c_int;
    /// This node's own X25519 static public key (32 bytes → `out32`). 0 = ok, <0 = bad node.
    fn musdm_libp2p_own_x_pk(node: *mut Node, out32: *mut u8) -> c_int;
    /// This node's own ML-KEM encapsulation key (written to `buf`, true length to `*len`). 0 = ok.
    fn musdm_libp2p_own_ek(node: *mut Node, buf: *mut u8, cap: usize, len: *mut usize) -> c_int;
    /// Register a PERSISTENT peer: base58 PeerId + its `/dns/<onion>.onion/tcp/<port>` multiaddr + its
    /// 32-byte X25519 static + ML-KEM ek. The node dials it now and RE-DIALS FOREVER on any drop
    /// (onion-only, self-healing). 0 = ok, <0 = error. This is the production seed-peer path.
    fn musdm_libp2p_add_persistent_peer(
        node: *mut Node,
        peer_id: *const c_char,
        addr: *const c_char,
        x_pk: *const u8,
        ek: *const u8,
        ek_len: usize,
    ) -> c_int;
    fn musdm_libp2p_node_free(node: *mut Node);
    /// Subscribe to a gossip topic. 0 = ok, <0 = bad node.
    fn musdm_libp2p_subscribe(node: *mut Node, topic: *const c_char) -> c_int;
    /// Publish `len` bytes to `topic`. >=0 = accepted/queued, <0 = error (e.g. bad node).
    fn musdm_libp2p_publish(
        node: *mut Node,
        topic: *const c_char,
        data: *const u8,
        len: usize,
    ) -> c_int;
    /// Dial a peer by `.onion` multiaddr. 0 = ok, <0 = error.
    fn musdm_libp2p_dial(node: *mut Node, addr: *const c_char) -> c_int;
    /// Listen on a multiaddr. 0 = ok, <0 = error.
    fn musdm_libp2p_listen(node: *mut Node, addr: *const c_char) -> c_int;
    /// Drain one event. 1 = drained (out_kind: 0=Gossip), 0 = none pending, -1 = bad node. `*_len`
    /// receive the FULL lengths (so the caller detects truncation vs cap).
    fn musdm_libp2p_poll_event(
        node: *mut Node,
        out_kind: *mut c_int,
        topic_buf: *mut u8,
        topic_cap: usize,
        topic_len: *mut usize,
        data_buf: *mut u8,
        data_cap: usize,
        data_len: *mut usize,
    ) -> c_int;
}

/// A real Tor `.onion` libp2p gossip node presented as a [`CellTransport`]. Onion-only by
/// construction — created over a SOCKS proxy and reached only by `.onion` multiaddr.
pub struct OnionTransport {
    node: *mut Node,
}

impl OnionTransport {
    /// Bring up the onion gossip node over `socks_proxy` (e.g. "127.0.0.1:9050") and subscribe to the
    /// cells topic. Returns `None` if the node could not be created (fail-closed — a node with no
    /// transport simply has no peers; it never falls back to a clearnet path).
    pub fn new_onion(socks_proxy: &str) -> Option<Self> {
        let proxy = CString::new(socks_proxy).ok()?;
        // SAFETY: `proxy` is a valid C-string for the duration of the call.
        let node = unsafe { musdm_libp2p_node_new_onion(proxy.as_ptr()) };
        if node.is_null() {
            return None;
        }
        let t = OnionTransport { node };
        t.subscribe(CELLS_TOPIC);
        Some(t)
    }

    fn subscribe(&self, topic: &str) {
        if let Ok(t) = CString::new(topic) {
            // SAFETY: node is a live handle; `t` outlives the call.
            unsafe { musdm_libp2p_subscribe(self.node, t.as_ptr()) };
        }
    }

    /// Listen on a `.onion` multiaddr. Returns whether the listen was accepted.
    pub fn listen(&self, multiaddr: &str) -> bool {
        match CString::new(multiaddr) {
            // parens: a bare `unsafe {…}` in match-arm start position parses as a statement.
            Ok(a) => (unsafe { musdm_libp2p_listen(self.node, a.as_ptr()) }) == 0,
            Err(_) => false,
        }
    }

    /// Dial a peer by `.onion` multiaddr. Returns whether the dial was accepted.
    pub fn dial(&self, multiaddr: &str) -> bool {
        match CString::new(multiaddr) {
            Ok(a) => (unsafe { musdm_libp2p_dial(self.node, a.as_ptr()) }) == 0,
            Err(_) => false,
        }
    }

    /// Bring up a DETERMINISTIC onion node from a 32-byte identity seed (stable PeerId + static keys),
    /// subscribed to the cells topic. `None` on failure (fail-closed — no clearnet fallback).
    pub fn new_onion_seeded(socks_proxy: &str, seed32: &[u8; 32]) -> Option<Self> {
        let proxy = CString::new(socks_proxy).ok()?;
        // SAFETY: `proxy` + `seed32` are valid for the call; the cdylib copies the 32 seed bytes.
        let node = unsafe { musdm_libp2p_node_new_onion_seeded(proxy.as_ptr(), seed32.as_ptr()) };
        if node.is_null() {
            return None;
        }
        let t = OnionTransport { node };
        t.subscribe(CELLS_TOPIC);
        Some(t)
    }

    /// This node's own base58 PeerId (to advertise to peers as a seed-peer identity).
    pub fn own_peer_id(&self) -> Option<String> {
        let mut buf = [0u8; 128];
        let mut len: usize = 0;
        // SAFETY: buf is a valid, sized byte buffer; the FFI writes <= cap bytes and sets *len.
        let rc =
            unsafe { musdm_libp2p_own_peer_id(self.node, buf.as_mut_ptr(), buf.len(), &mut len) };
        if rc != 0 || len == 0 || len > buf.len() {
            return None;
        }
        String::from_utf8(buf[..len].to_vec()).ok()
    }

    /// This node's own X25519 static public key (32 bytes) — the seed-peer PQ-auth material.
    pub fn own_x_pk(&self) -> Option<[u8; 32]> {
        let mut out = [0u8; 32];
        // SAFETY: out is exactly 32 bytes; the FFI writes exactly 32 on success.
        let rc = unsafe { musdm_libp2p_own_x_pk(self.node, out.as_mut_ptr()) };
        if rc == 0 {
            Some(out)
        } else {
            None
        }
    }

    /// This node's own ML-KEM encapsulation key (the PQ half of the seed-peer material).
    pub fn own_ek(&self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 4096]; // ML-KEM-768 ek is 1184B; 4096 is a safe cap
        let mut len: usize = 0;
        // SAFETY: buf is a valid, sized byte buffer; the FFI writes <= cap bytes and sets *len.
        let rc = unsafe { musdm_libp2p_own_ek(self.node, buf.as_mut_ptr(), buf.len(), &mut len) };
        if rc != 0 || len == 0 || len > buf.len() {
            return None;
        }
        buf.truncate(len);
        Some(buf)
    }

    /// Register a PERSISTENT onion seed peer (dial now + re-dial forever): base58 PeerId, its
    /// `/dns/<onion>.onion/tcp/<port>` multiaddr, and its X25519 static + ML-KEM ek. Returns whether
    /// the peer was accepted. This is the production self-healing peering the mesh seeds from.
    pub fn add_persistent_peer(
        &self,
        peer_id: &str,
        addr: &str,
        x_pk: &[u8; 32],
        ek: &[u8],
    ) -> bool {
        let (pid, a) = match (CString::new(peer_id), CString::new(addr)) {
            (Ok(p), Ok(a)) => (p, a),
            _ => return false,
        };
        // SAFETY: pid/a outlive the call; x_pk is 32B; ek is `ek.len()` bytes; the FFI copies them.
        let rc = unsafe {
            musdm_libp2p_add_persistent_peer(
                self.node,
                pid.as_ptr(),
                a.as_ptr(),
                x_pk.as_ptr(),
                ek.as_ptr(),
                ek.len(),
            )
        };
        rc == 0
    }

    /// A `Send`-able handle for a background AUTO-DISCOVERY thread to add persistent peers continuously
    /// (dial-now + re-dial-forever) without moving the transport. The cdylib node pointer is owned by this
    /// `OnionTransport` for the whole process lifetime (freed only at exit), so the handle stays valid.
    pub fn peer_adder(&self) -> PeerAdder {
        PeerAdder { node: self.node }
    }
}

/// Continuously-usable peer-dialer handle held by the auto-peering loop, so the mesh can DISCOVER + DIAL new
/// peers automatically (gossip stays live on restart) while the transport itself lives in the tick runtime.
#[derive(Clone, Copy)]
pub struct PeerAdder {
    node: *mut Node,
}
// SAFETY: mirrors `unsafe impl Send for OnionTransport` — the libp2p_ffi node handle is internally synchronized.
unsafe impl Send for PeerAdder {}
unsafe impl Sync for PeerAdder {}

impl PeerAdder {
    /// Register / re-dial a persistent onion peer. Returns whether it was accepted. Idempotent in the cdylib.
    pub fn add(&self, peer_id: &str, addr: &str, x_pk: &[u8; 32], ek: &[u8]) -> bool {
        let (pid, a) = match (CString::new(peer_id), CString::new(addr)) {
            (Ok(p), Ok(a)) => (p, a),
            _ => return false,
        };
        // SAFETY: pid/a outlive the call; x_pk is 32B; ek is `ek.len()` bytes; the FFI copies them.
        let rc = unsafe {
            musdm_libp2p_add_persistent_peer(
                self.node,
                pid.as_ptr(),
                a.as_ptr(),
                x_pk.as_ptr(),
                ek.as_ptr(),
                ek.len(),
            )
        };
        rc == 0
    }
}

// SAFETY: `OnionTransport` holds a `*mut Node` owned by the libp2p_ffi cdylib. In `run_serve` the
// transport lives inside a `NodeRuntime<OnionTransport>` behind an `Arc<Mutex<…>>`, so EVERY access
// to the node handle (send_cell / recv_cell / peering) is serialized by that Mutex — no two threads
// ever touch the pointer concurrently. Sending the handle across threads under that lock is therefore
// sound, which is exactly what the `T: Send` bound on `rpc_http::serve` / the tick thread requires.
unsafe impl Send for OnionTransport {}

/// The onion transport's [`crate::transport::PeerPeering`] handle: (re-)dial a learned peer + expose this
/// node's own dialable identity, so the generic runtime can announce our signed peer record and re-dial the
/// converged peer set across devices — the mechanism behind "any node on any device auto-joins the mesh"
/// with no single bootstrap node.
pub struct OnionPeering {
    node: *mut Node,
    identity: Option<(String, Vec<u8>, Vec<u8>)>,
}
// SAFETY: mirrors `unsafe impl Send for OnionTransport` / `PeerAdder` — the libp2p_ffi node handle is
// internally synchronized; the auto-peer thread is the only holder and dials under no shared mutation.
unsafe impl Send for OnionPeering {}

impl crate::transport::PeerPeering for OnionPeering {
    fn add(&self, peer_id: &str, addr: &str, x_pk: &[u8], ek: &[u8]) -> bool {
        if x_pk.len() != 32 {
            return false; // the FFI expects a 32-byte Noise static; reject a malformed record fail-closed
        }
        let (pid, a) = match (CString::new(peer_id), CString::new(addr)) {
            (Ok(p), Ok(a)) => (p, a),
            _ => return false,
        };
        // SAFETY: pid/a outlive the call; x_pk is exactly 32B (checked); the FFI copies ek (ek.len() bytes).
        let rc = unsafe {
            musdm_libp2p_add_persistent_peer(
                self.node,
                pid.as_ptr(),
                a.as_ptr(),
                x_pk.as_ptr(),
                ek.as_ptr(),
                ek.len(),
            )
        };
        rc == 0
    }
    fn own_identity(&self) -> Option<(String, Vec<u8>, Vec<u8>)> {
        self.identity.clone()
    }
}

impl CellTransport for OnionTransport {
    fn send_cell(&self, cell: Vec<u8>) -> Result<(), NetError> {
        if cell.len() != CELL_SIZE {
            return Err(NetError::BadCell); // never let a non-cell onto the wire
        }
        let topic = CString::new(CELLS_TOPIC).map_err(|_| NetError::BadCell)?;
        // SAFETY: node is live; topic + cell outlive the call; publish only reads them.
        let rc =
            unsafe { musdm_libp2p_publish(self.node, topic.as_ptr(), cell.as_ptr(), cell.len()) };
        // >=0 = accepted/queued (0 can mean "no peers yet", not a hard error); <0 = bad node.
        if rc >= 0 {
            Ok(())
        } else {
            Err(NetError::BadCell)
        }
    }

    fn peering(&self) -> Box<dyn crate::transport::PeerPeering> {
        // The onion transport is the REAL auto-peer path (dial + own-identity), so the generic runtime drives
        // the auto peer-directory (announce our record + re-dial learned peers) without knowing our concrete
        // type. Capture our own identity now (None until the transport identity is fully up).
        let identity = match (self.own_peer_id(), self.own_x_pk(), self.own_ek()) {
            (Some(pid), Some(xpk), Some(ek)) => Some((pid, xpk.to_vec(), ek)),
            _ => None,
        };
        Box::new(OnionPeering {
            node: self.node,
            identity,
        })
    }

    fn recv_cell(&self) -> Option<Vec<u8>> {
        // Drain events until a cells-topic gossip cell arrives (skip non-cell events), or none remain.
        loop {
            let mut kind: c_int = -1;
            let mut topic = [0u8; 64];
            let mut tlen: usize = 0;
            let mut data = vec![0u8; CELL_SIZE];
            let mut dlen: usize = 0;
            // SAFETY: all buffers are valid + sized; the FFI writes within the caps and sets *_len.
            let rc = unsafe {
                musdm_libp2p_poll_event(
                    self.node,
                    &mut kind,
                    topic.as_mut_ptr(),
                    topic.len(),
                    &mut tlen,
                    data.as_mut_ptr(),
                    data.len(),
                    &mut dlen,
                )
            };
            if rc != 1 {
                return None; // 0 = no event pending, -1 = bad node
            }
            // kind 0 = Gossip; accept only a full CELL_SIZE payload on the cells topic.
            let topic_ok = tlen <= topic.len() && &topic[..tlen] == CELLS_TOPIC.as_bytes();
            if kind == 0 && topic_ok && dlen == CELL_SIZE {
                return Some(data); // already exactly CELL_SIZE
            }
            // any other event (listening notice, other topic, truncated) — keep draining
        }
    }
}

impl Drop for OnionTransport {
    fn drop(&mut self) {
        // SAFETY: node was produced by musdm_libp2p_node_new_onion and is freed exactly once here.
        unsafe { musdm_libp2p_node_free(self.node) };
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    // Hermetic checks only (no live Tor / peers): the topic constant + type wiring. The live 2-node
    // onion cell round-trip is an integration test (node bring-up / testnet), not a unit test.
    #[test]
    fn cells_topic_is_stable_and_c_string_safe() {
        assert_eq!(CELLS_TOPIC, "musdm/cells");
        assert!(
            CString::new(CELLS_TOPIC).is_ok(),
            "topic must be a valid C string"
        );
    }

    #[test]
    fn onion_transport_is_a_cell_transport() {
        // Compile-time proof that OnionTransport satisfies the CellTransport seam (so CellChannel can
        // drive it exactly like the loopback transport). No node is created here.
        fn _assert_impl<T: CellTransport>() {}
        _assert_impl::<OnionTransport>();
    }
}
