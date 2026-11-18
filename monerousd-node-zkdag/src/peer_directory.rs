// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! Authenticated PEER directory — the gossiped, self-certifying, PERSISTED, auto-re-dialed peer set that
//! makes "every node, on any device, auto-joins the correct mesh" true WITHOUT a single point of failure.
//!
//! ## The gap this closes
//! Blocks, txs, sites, votes, @names, clue keys, and note-clues all gossip + converge across the mesh — but
//! peer ONION ADDRESSES did not. Same-host discovery used a shared `~/.usdmd-node/peers/` folder (useless
//! across devices); cross-device discovery hung off ONE pinned bootstrap seed. If that seed node went down, a
//! fresh node was islanded and a fully-restarted mesh could not re-form. That is a single point of failure for
//! DISCOVERY / mesh liveness (the chain DATA survives on every node via #106 frontier-persist, but the network
//! could not reassemble). This module makes a node's own dialable identity the 8th gossiped directory, so it
//! REPLICATES over the mesh and CONVERGES on every node, and PERSISTS to disk so a node re-dials whoever is
//! alive on restart. After ONE successful join a node never needs the seed again — the seed becomes pure
//! first-contact redundancy (pin many; any one being up suffices), never a dependency.
//!
//! ## Record shape
//! A [`PeerRecord`] is `(peer_id, addr, x_pk, ek, seq)` where `addr` is a `/dns/<v3-onion>/tcp/<port>`
//! multiaddr (onion-only BY CONSTRUCTION — [`onion_host_of`] rejects any IP or non-`.onion` host), `x_pk` is
//! the Noise static, `ek` the ML-KEM encapsulation key, and `seq` a monotonic freshness stamp (the announcer's
//! `now_unix_ms` at signing) so a newer announcement (onion rotation / restart) supersedes a replayed stale one.
//! A [`PeerGossip`] wraps the record with the announcer's ML-DSA-65 public key + a signature over
//! [`peer_record_msg`]; the owner id is `H(pubkey)` (one slot per node identity).
//!
//! ## Soundness (Pillar 3) — a forged record cannot eclipse-redirect
//! Adoption requires: a well-formed v3 `.onion` multiaddr (no IP), a non-empty `peer_id`, and a valid ML-DSA
//! self-signature. Even so, the gossip record is only an ADVERTISEMENT — the libp2p Noise handshake proves the
//! remote actually holds `peer_id` AT DIAL, so advertising "peer B lives at onion M" merely yields a failed
//! dial (M cannot prove B's identity key). The transport handshake is the verifier, exactly as with Bitcoin
//! `addr` gossip: addresses are hints, the connection is truth. Malformed / bad-signature records are rejected
//! fail-closed and the directory is size-capped ([`MAX_PEERS`]) so junk records cannot grow it without bound.
//! None of this ever gates block flow (peer records are optional directory state, like a site or a @name).

use crate::pqauth::{ml_dsa_verify, pubkey_id};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Max distinct peers retained (a DoS bound on junk gossip records; a real mesh is far smaller).
pub const MAX_PEERS: usize = 4096;

/// The dialable identity a node attests to + gossips. `addr` is a `/dns/<onion>/tcp/<port>` multiaddr.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerRecord {
    pub peer_id: String,
    /// `/dns/<v3-onion>.onion/tcp/<port>` — onion-only, validated on adopt (no IP is representable).
    pub addr: String,
    /// Noise static public key bytes.
    pub x_pk: Vec<u8>,
    /// ML-KEM encapsulation key bytes.
    pub ek: Vec<u8>,
    /// Monotonic freshness stamp (announcer's `now_unix_ms` at signing). Newer wins.
    pub seq: u64,
}

/// A self-attested, gossipable peer record: the [`PeerRecord`] + the announcer's ML-DSA-65 pubkey + a
/// signature over [`peer_record_msg`]. Owner id = `H(pubkey)`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerGossip {
    pub record: PeerRecord,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Outcome of adopting a gossiped peer record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerOutcome {
    /// New peer, or a strictly-newer `seq` for a known peer → recorded (and re-gossiped by the caller).
    Adopted,
    /// Already known at an equal-or-newer `seq`, or the directory is at capacity → not re-gossiped (dedup).
    Unchanged,
    /// Malformed onion/peer_id or a signature that did not authenticate → rejected fail-closed.
    BadSig,
}

/// The exact bytes a node signs to attest its own peer record. Length-prefixes the variable fields so no two
/// distinct records can collide onto the same preimage.
pub fn peer_record_msg(peer_id: &str, addr: &str, x_pk: &[u8], ek: &[u8], seq: u64) -> Vec<u8> {
    let mut m = Vec::with_capacity(64 + peer_id.len() + addr.len() + x_pk.len() + ek.len());
    m.extend_from_slice(b"musdm-peer-record-v1\0");
    m.extend_from_slice(&(peer_id.len() as u32).to_le_bytes());
    m.extend_from_slice(peer_id.as_bytes());
    m.extend_from_slice(&(addr.len() as u32).to_le_bytes());
    m.extend_from_slice(addr.as_bytes());
    m.extend_from_slice(&(x_pk.len() as u32).to_le_bytes());
    m.extend_from_slice(x_pk);
    m.extend_from_slice(&(ek.len() as u32).to_le_bytes());
    m.extend_from_slice(ek);
    m.extend_from_slice(&seq.to_le_bytes());
    m
}

/// Extract + validate the v3 `.onion` host from a `/dns/<host>/tcp/<port>` multiaddr. Returns the onion host
/// on success; `None` for any IP, non-`.onion` host, or malformed multiaddr — this is the onion-only gate.
pub fn onion_host_of(addr: &str) -> Option<String> {
    // "/dns/<host>/tcp/<port>" → ["", "dns", "<host>", "tcp", "<port>"]
    let parts: Vec<&str> = addr.split('/').collect();
    if parts.len() != 5 || !parts[0].is_empty() || parts[1] != "dns" || parts[3] != "tcp" {
        return None;
    }
    if parts[4].parse::<u16>().is_err() {
        return None;
    }
    // OnionAddr::parse rejects IPs + non-v3-onion hosts.
    crate::net::OnionAddr::parse(parts[2])
        .ok()
        .map(|o| o.as_str().to_string())
}

impl PeerGossip {
    /// Postcard wire bytes for gossip over the fixed cell transport.
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Parse a gossiped peer record (structure only; call [`Self::verify`] before trusting it).
    pub fn from_wire(bytes: &[u8]) -> Option<PeerGossip> {
        crate::chain_object::decode_exact(bytes)
    }
    /// Verify the onion-only multiaddr, non-empty peer_id, and ML-DSA self-signature. Returns the owner id
    /// `H(pubkey)` on success; `None` (reject fail-closed) otherwise.
    pub fn verify(&self) -> Option<[u8; 32]> {
        if self.record.peer_id.is_empty() {
            return None;
        }
        if onion_host_of(&self.record.addr).is_none() {
            return None; // rejects IPs / non-onion / malformed multiaddr
        }
        let msg = peer_record_msg(
            &self.record.peer_id,
            &self.record.addr,
            &self.record.x_pk,
            &self.record.ek,
            self.record.seq,
        );
        if !ml_dsa_verify(&msg, &self.pubkey, &self.sig) {
            return None;
        }
        Some(pubkey_id(&self.pubkey))
    }
}

/// The authenticated peer directory: `H(pubkey)` → the freshest signed record for that node identity, with
/// optional disk persistence so a node re-dials known peers on restart (no seed needed after first join).
#[derive(Default)]
pub struct PeerDirectory {
    by_owner: HashMap<[u8; 32], PeerGossip>,
    persist_path: Option<PathBuf>,
    /// This node's OWN owner id, so its own announcement is never adopted as a peer.
    ///
    /// ⛔⛔⛔ A NODE THAT ADOPTS ITSELF DIALS ITSELF.
    ///
    /// `adopt_inner` verified a gossip and filed it by owner with no check that the owner is US. A node
    /// announces itself (`WireMsg::Peer`), and any path that feeds that announcement back files this node as
    /// its own peer — after which the dialer tries to rendezvous with our own onion, which can NEVER succeed.
    ///
    /// MEASURED 2026-08-01 on a node started with NO seed peers at all: `get_info` reported
    /// `writers_held 1` (a link to something it was never told about) and the dialer logged
    /// `[arti] dial vl52qoaix….onion failed` against this node's OWN address from `own-onion.txt`, 6 times.
    /// Every attempt builds circuits through the guards the node needs to publish its service, so a node that
    /// cannot publish was actively starving its own publication.
    ///
    /// The dialer-side skip catches it at the last moment; this stops it being RECORDED at all, which is the
    /// correct layer — nothing downstream can then act on a peer entry that should never have existed.
    self_owner: Option<[u8; 32]>,
}

impl PeerDirectory {
    /// An in-memory directory (tests / non-persistent nodes).
    pub fn new() -> Self {
        Self {
            by_owner: HashMap::new(),
            persist_path: None,
            self_owner: None,
        }
    }

    /// A directory that loads any previously-learned peers from `path` and snapshots back to it on every fresh
    /// adopt. On restart the node thus re-dials whoever it last knew — the mesh re-forms among survivors.
    pub fn with_persist(path: PathBuf) -> Self {
        let mut d = Self {
            by_owner: HashMap::new(),
            persist_path: Some(path),
            self_owner: None,
        };
        d.load();
        d
    }

    /// ⭐ G1g-iii (lane a 2026-10-23) — bind persistence to `path` IN PLACE: load the peers filed there (each re-verified,
    /// a newer `seq` wins, exactly `load`), keep this node's own owner id and every peer learned before the bind, drop a
    /// self entry the file held, and write the merged set back. Replacing the directory with `with_persist` dropped the
    /// self owner and any peer adopted before the call. cons: none — one bounded (≤ `MAX_PEERS`) read and write per boot.
    pub fn enable_persist(&mut self, path: PathBuf) {
        self.persist_path = Some(path);
        self.load();
        if let Some(me) = self.self_owner {
            self.by_owner.remove(&me);
        }
        self.persist_snapshot();
    }

    /// Verify + adopt a gossiped record. A new owner or a strictly-newer `seq` is `Adopted` (caller re-gossips);
    /// an equal/older `seq` or an at-capacity insert is `Unchanged`; a bad onion/sig is `BadSig`. On `Adopted`
    /// with a persist path set, snapshots the whole (bounded) directory to disk.
    /// ⭐ SAY WHY A GOSSIP WAS NOT ADOPTED — a silent reject is indistinguishable from none arriving.
    ///
    /// MEASURED 2026-07-31: a pair with a healthy link (`cell link up`, 40 and 44 inbound messages DRAINED)
    /// still reported `0 known peer(s)` on both sides, so nothing was ever persisted and every restart paid a
    /// full Tor bootstrap. The directory only accepts SIGNED gossip, which is correct — but every refusal
    /// looked identical to silence from outside, and I spent several runs unable to tell "no gossip sent"
    /// apart from "gossip sent and rejected".
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the outcome enum and a truncated peer id the node already gossips in
    /// clear — never a note, amount, key, or owner. Fires only on a NON-adopt (a genuine anomaly), never per
    /// block and never on the healthy path.
    pub fn adopt(&mut self, g: &PeerGossip) -> PeerOutcome {
        let out = self.adopt_inner(g);
        if out != PeerOutcome::Adopted {
            crate::arti_transport::ilog(&format!(
                "[peer-adopt] REJECTED a gossip: {out:?} — the directory stays empty, so nothing persists and \
                 the next restart re-bootstraps from the seed instead of re-dialing a known peer."
            ));
        }
        out
    }

    /// ⭐ DB-355 — the ONE self test every adopt door runs: is `owner` the id this node announced itself under?
    fn is_self(&self, owner: &[u8; 32]) -> bool {
        self.self_owner == Some(*owner)
    }

    /// Declare THIS node's own owner id so its own announcement can never be filed as a peer.
    /// Idempotent; safe to call on every startup.
    pub fn set_self_owner(&mut self, owner: [u8; 32]) {
        self.self_owner = Some(owner);
        // A self entry filed before this was known is removed now — otherwise a node keeps dialing itself
        // for as long as that stale record survives on disk.
        self.by_owner.remove(&owner);
    }

    fn adopt_inner(&mut self, g: &PeerGossip) -> PeerOutcome {
        let owner = match g.verify() {
            Some(o) => o,
            None => return PeerOutcome::BadSig,
        };
        // NEVER file ourselves. A self entry is not a peer — it is a guaranteed-failing dial target that
        // burns circuits on the guards this node needs to publish its own service. See `self_owner`.
        if self.is_self(&owner) {
            return PeerOutcome::Unchanged;
        }
        match self.by_owner.get(&owner) {
            Some(cur) if cur.record.seq >= g.record.seq => return PeerOutcome::Unchanged,
            None if self.by_owner.len() >= MAX_PEERS => return PeerOutcome::Unchanged, // bounded
            _ => {}
        }
        self.by_owner.insert(owner, g.clone());
        self.persist_snapshot();
        PeerOutcome::Adopted
    }

    /// ANTI-ECLIPSE ADMISSION (the production adopt path): identical to [`Self::adopt`], except that when the
    /// directory is at [`MAX_PEERS`] a BONDED anchor (per `is_bonded`) is admitted by EVICTING a free
    /// (non-bonded) peer — so an attacker who first floods the directory to capacity with free `.onion`
    /// identities can NEVER make an honest stake-backed anchor un-adoptable (that would be a silent eclipse).
    /// A non-bonded newcomer is still dropped when full (bounded); a bonded newcomer is dropped only if the
    /// whole directory is ALREADY bonded anchors (legitimately full of stake-backed peers — never evict an
    /// anchor for another anchor). Updates to an existing owner (newer `seq`) always apply (no capacity gate).
    pub fn adopt_prioritized(
        &mut self,
        g: &PeerGossip,
        is_bonded: impl Fn(&[u8; 32]) -> bool,
    ) -> PeerOutcome {
        let owner = match g.verify() {
            Some(o) => o,
            None => return PeerOutcome::BadSig,
        };
        // ⛔⛔⛔ DB-355 — THIS DOOR NEVER CARRIED THE SELF CHECK ITS SIBLING (`adopt_inner`) RUNS, and it is the door
        // production uses: `Node::adopt_peer` comes through here, and `NodeRuntime::announce_peer` hands it this node's
        // OWN record right after `set_self_owner`. MEASURED ([slotB17c], five real daemons): node0 logged `1 known
        // peer(s)` while it was alone and `peer-directory dialing BONDED anchor <its own onion>` — its own seat makes
        // its key BONDED, so the anti-eclipse loop kept re-dialing ITSELF — and every node read `mesh 6` on a
        // five-node mesh, which engaged the nullifier-shard policy one node early (DB-353). One test, both doors.
        if self.is_self(&owner) {
            return PeerOutcome::Unchanged;
        }
        if let Some(cur) = self.by_owner.get(&owner) {
            if cur.record.seq >= g.record.seq {
                return PeerOutcome::Unchanged;
            }
            // Fresher record for a known owner — always apply (not a new slot, no capacity concern).
            self.by_owner.insert(owner, g.clone());
            self.persist_snapshot();
            return PeerOutcome::Adopted;
        }
        // A NEW owner. Enforce the bound, but never let a free-onion flood crowd out a stake-backed anchor.
        if self.by_owner.len() >= MAX_PEERS {
            if !is_bonded(&owner) {
                return PeerOutcome::Unchanged; // free newcomer at capacity → dropped (bounded)
            }
            // Bonded anchor at capacity → evict SOME free (non-bonded) peer to make room.
            let victim = self.by_owner.keys().find(|oid| !is_bonded(oid)).copied();
            match victim {
                Some(v) => {
                    self.by_owner.remove(&v);
                }
                None => return PeerOutcome::Unchanged, // all-anchor directory is legitimately full
            }
        }
        self.by_owner.insert(owner, g.clone());
        self.persist_snapshot();
        PeerOutcome::Adopted
    }

    /// Every known dialable peer record — the (re-)dial set for the auto-peer loop on boot + on each adopt.
    pub fn peers(&self) -> Vec<PeerRecord> {
        self.by_owner.values().map(|g| g.record.clone()).collect()
    }

    /// ECLIPSE RESISTANCE for onion-only: separate known peers into `(anchors, others)`. An ANCHOR is a peer
    /// whose signer identity `H(pubkey)` is a BONDED validator per `is_bonded` — a Sybil-RESISTANT identity,
    /// because each additional bonded-validator identity costs a real on-chain stake bond (`validator.rs`
    /// floor, pegged to 2x bridge TVL). `others` are unverified peers. The auto-peer loop keeps every anchor
    /// dialed, so an adversary who mints many free `.onion` identities cannot displace the honest bonded peers
    /// from a node's connections — eclipsing a victim then requires posting real stake, which is costly. The
    /// peer record is signed by the node's ML-DSA key, and that key's `H(pubkey)` is exactly its validator id
    /// when bonded, so this classification needs no extra crypto.
    pub fn classify_anchors(
        &self,
        is_bonded: impl Fn(&[u8; 32]) -> bool,
    ) -> (Vec<PeerRecord>, Vec<PeerRecord>) {
        let mut anchors = Vec::new();
        let mut others = Vec::new();
        for g in self.by_owner.values() {
            if is_bonded(&pubkey_id(&g.pubkey)) {
                anchors.push(g.record.clone());
            } else {
                others.push(g.record.clone());
            }
        }
        (anchors, others)
    }

    /// Number of distinct known peers.
    pub fn len(&self) -> usize {
        self.by_owner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.by_owner.is_empty()
    }

    /// Rewrite the whole directory to disk (a bounded ≤[`MAX_PEERS`] snapshot — O(peers), never O(chain)). The
    /// signed records are persisted so a tampered on-disk line is rejected by [`PeerGossip::verify`] on load.
    fn persist_snapshot(&self) {
        if let Some(p) = &self.persist_path {
            let all: Vec<&PeerGossip> = self.by_owner.values().collect();
            if let Ok(bytes) = postcard::to_allocvec(&all) {
                let tmp = p.with_extension("tmp");
                if std::fs::write(&tmp, &bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
        }
    }

    /// Load persisted peers, re-verifying each signature (a corrupted/forged on-disk record is dropped).
    fn load(&mut self) {
        let Some(p) = self.persist_path.clone() else {
            return;
        };
        let Ok(bytes) = std::fs::read(&p) else { return };
        let Some(all) = crate::chain_object::decode_exact::<Vec<PeerGossip>>(&bytes) else {
            return;
        };
        for g in all {
            if let Some(owner) = g.verify() {
                match self.by_owner.get(&owner) {
                    Some(cur) if cur.record.seq >= g.record.seq => {}
                    _ => {
                        self.by_owner.insert(owner, g);
                    }
                }
            }
        }
    }
}

/// Hard cap on OUTBOUND dial slots per node (per machine / datadir / port): bonded anchors take priority
/// slots, the rest are filled by the random per-epoch sample. This bounds each node's fan-out to a CONSTANT
/// (no growth) AND means one machine spinning up many node identities gains NO consensus edge — consensus
/// weight is GHOSTDAG blue_work (proof-of-useful-work), never connection count, so extra Sybil links are
/// economically pointless.
pub const MAX_OUTBOUND_PEERS: usize = 8;

/// RANDOMIZED PER-EPOCH PEER SAMPLING (eclipse-resistant; no fixed topology to attack): pick up to `k` of
/// `peers` by RENDEZVOUS HASHING — score(peer) = blake3(`own_id` ‖ `epoch` ‖ `peer_id`), take the `k` LOWEST
/// scores. The selection is (1) DETERMINISTIC per `(own_id, epoch)` — reproducible, no RNG state, identical on
/// every device, testable; (2) UNPREDICTABLE to an adversary — without a victim's id + the current epoch they
/// cannot know which peers it will dial, so they cannot pre-position Sybils in its slots (eclipse resistance
/// for the unverified `others`); (3) ROTATING — each epoch reshuffles the draw, so a transient bad sample
/// self-heals and load spreads across the mesh. PQ-safe (blake3 only). Bonded anchors are dialed SEPARATELY
/// and ALWAYS, so this samples only the unverified `others`.
pub fn rendezvous_sample(
    own_id: &str,
    epoch: u64,
    peers: &[PeerRecord],
    k: usize,
) -> Vec<PeerRecord> {
    if k == 0 || peers.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(crate::hash::Hash32, &PeerRecord)> = peers
        .iter()
        .map(|p| {
            let mut buf = Vec::with_capacity(own_id.len() + 8 + p.peer_id.len());
            buf.extend_from_slice(own_id.as_bytes());
            buf.extend_from_slice(&epoch.to_le_bytes());
            buf.extend_from_slice(p.peer_id.as_bytes());
            (crate::hash::Hash32::hash(&buf), p)
        })
        .collect();
    // Lowest HRW score wins; tie-break by peer_id so the order is total + deterministic.
    scored.sort_by(|a, b| {
        a.0.as_bytes()
            .cmp(b.0.as_bytes())
            .then_with(|| a.1.peer_id.cmp(&b.1.peer_id))
    });
    scored.into_iter().take(k).map(|(_, p)| p.clone()).collect()
}

/// The unverified peers a node opens fresh outbound connections to THIS epoch: a rotating rendezvous-sampled
/// selection sized to fill the outbound slots left after the always-dialed bonded anchors. NOT a completeness
/// truncation — every peer still receives every block by multi-hop gossip flooding over the resulting random
/// graph, so beacon-adopt convergence is unaffected; this only bounds simultaneous DIALS per machine (the
/// user-requested connection limit that makes running many node identities on one box pointless, since
/// consensus weight is GHOSTDAG blue_work, never connection count). The caller dials the FULL returned list.
pub fn others_to_dial(
    own_id: &str,
    epoch: u64,
    anchor_count: usize,
    others: &[PeerRecord],
) -> Vec<PeerRecord> {
    let budget = MAX_OUTBOUND_PEERS.saturating_sub(anchor_count);
    rendezvous_sample(own_id, epoch, others, budget)
}

#[cfg(all(test, feature = "pins-core"))]
mod sampler_tests {
    use super::*;

    fn mk_peers(n: u8) -> Vec<PeerRecord> {
        (0..n)
            .map(|i| PeerRecord {
                peer_id: format!("peer{i:02}"),
                addr: format!("/dns/x{i}.onion/tcp/27781"),
                x_pk: vec![],
                ek: vec![],
                seq: 0,
            })
            .collect()
    }
    fn ids(v: &[PeerRecord]) -> Vec<String> {
        v.iter().map(|p| p.peer_id.clone()).collect()
    }

    /// The random-peer sampler is deterministic, bounded to `k` (the per-machine cap), rotates per epoch, and
    /// differs per node (unpredictable → eclipse-resistant). No RNG, no classical crypto — blake3 HRW.
    #[test]
    fn rendezvous_sample_is_deterministic_bounded_rotating_and_per_node() {
        let peers = mk_peers(20);
        let s1 = rendezvous_sample("me", 0, &peers, MAX_OUTBOUND_PEERS);
        assert_eq!(
            s1.len(),
            MAX_OUTBOUND_PEERS,
            "bounded to k (per-machine cap)"
        );
        assert_eq!(
            ids(&s1),
            ids(&rendezvous_sample("me", 0, &peers, MAX_OUTBOUND_PEERS)),
            "deterministic"
        );
        assert_ne!(
            ids(&s1),
            ids(&rendezvous_sample("me", 1, &peers, MAX_OUTBOUND_PEERS)),
            "epoch rotates the draw"
        );
        assert_ne!(
            ids(&s1),
            ids(&rendezvous_sample("other", 0, &peers, MAX_OUTBOUND_PEERS)),
            "per-node unpredictable"
        );
        // Fewer peers than k → returns all (never panics, never over-caps).
        assert_eq!(
            rendezvous_sample("me", 0, &mk_peers(3), MAX_OUTBOUND_PEERS).len(),
            3
        );
        assert!(rendezvous_sample("me", 0, &peers, 0).is_empty());
    }

    /// The per-machine connection cap: `others_to_dial` fills only the outbound slots left after the bonded
    /// anchors, so total simultaneous dials never exceed `MAX_OUTBOUND_PEERS`; anchors filling the cap leave
    /// zero for others; and the selection rotates per epoch. (Every peer still gets every block via gossip —
    /// this bounds connections, not data.)
    #[test]
    fn others_to_dial_respects_the_per_machine_cap_after_anchors() {
        let others = mk_peers(30);
        let d = others_to_dial("me", 0, 3, &others);
        assert_eq!(
            d.len(),
            MAX_OUTBOUND_PEERS - 3,
            "fills only the slots left after 3 anchors"
        );
        assert!(
            others_to_dial("me", 0, MAX_OUTBOUND_PEERS, &others).is_empty(),
            "anchors filling the cap leave no room for extra dials (strict per-machine limit)"
        );
        assert_ne!(
            ids(&d),
            ids(&others_to_dial("me", 1, 3, &others)),
            "rotates per epoch (self-healing)"
        );
    }
}

/// A genuinely SIGNED peer gossip record, for tests in other modules that must exercise the REAL adopt path.
///
/// Exposed (test-only) rather than copied: a hand-rolled record in another module drifts from what the wire
/// actually carries, and then the test passes on a shape the network never produces.
#[cfg(test)]
pub(crate) fn signed_record_for_test(
    pk: &[u8],
    sk: &[u8],
    onion: &str,
    port: u16,
    seq: u64,
) -> PeerGossip {
    let addr = format!("/dns/{onion}/tcp/{port}");
    let rec = PeerRecord {
        peer_id: "12D3KooWtestpeeridentity".into(),
        addr,
        x_pk: vec![1u8; 32],
        ek: vec![2u8; 64],
        seq,
    };
    let msg = peer_record_msg(&rec.peer_id, &rec.addr, &rec.x_pk, &rec.ek, rec.seq);
    let sig = crate::pqauth::ml_dsa_sign(&msg, sk).unwrap();
    PeerGossip {
        record: rec,
        pubkey: pk.to_vec(),
        sig,
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::pqauth::{ml_dsa_keypair, ml_dsa_sign};

    // Two DISTINCT valid v3 onions: exactly 56 base32 chars (a-z, 2-7) + ".onion".
    const ONION_A: &str = "abcdefghij234567abcdefghij234567abcdefghij234567abcdefgh.onion";
    const ONION_B: &str = "cbcdefghij234567abcdefghij234567abcdefghij234567abcdefgh.onion";

    fn signed(pk: &[u8], sk: &[u8], onion: &str, port: u16, seq: u64) -> PeerGossip {
        super::signed_record_for_test(pk, sk, onion, port, seq)
    }

    #[test]
    fn honest_record_verifies_adopts_and_dedups_by_seq() {
        let (pk, sk) = ml_dsa_keypair();
        let mut dir = PeerDirectory::new();
        let g1 = signed(&pk, &sk, ONION_A, 35000, 100);
        assert_eq!(dir.adopt(&g1), PeerOutcome::Adopted);
        // Same record again → already known at equal seq → Unchanged (no re-gossip loop).
        assert_eq!(dir.adopt(&g1), PeerOutcome::Unchanged);
        // Older seq for the same owner → Unchanged (a replayed stale record cannot shadow the fresh one).
        let g_old = signed(&pk, &sk, ONION_A, 35000, 50);
        assert_eq!(dir.adopt(&g_old), PeerOutcome::Unchanged);
        // Newer seq (e.g. onion rotation / restart) → Adopted; the new addr replaces the old.
        let g2 = signed(&pk, &sk, ONION_B, 35000, 200);
        assert_eq!(dir.adopt(&g2), PeerOutcome::Adopted);
        assert_eq!(dir.len(), 1); // same owner → one slot, freshest wins
        assert_eq!(dir.peers()[0].addr, format!("/dns/{ONION_B}/tcp/35000"));
    }

    #[test]
    fn tampered_onion_is_rejected_fail_closed() {
        let (pk, sk) = ml_dsa_keypair();
        let mut g = signed(&pk, &sk, ONION_A, 35000, 1);
        // Adversary rewrites the advertised onion AFTER signing → signature no longer authenticates.
        g.record.addr = format!("/dns/{ONION_B}/tcp/35000");
        assert_eq!(g.verify(), None);
        let mut dir = PeerDirectory::new();
        assert_eq!(dir.adopt(&g), PeerOutcome::BadSig);
        assert!(dir.is_empty());
    }

    #[test]
    fn forged_signature_is_rejected() {
        let (pk, sk) = ml_dsa_keypair();
        let mut g = signed(&pk, &sk, ONION_A, 35000, 1);
        // Flip the signature → must not authenticate.
        for b in g.sig.iter_mut().take(8) {
            *b ^= 0xff;
        }
        assert_eq!(g.verify(), None);
        assert_eq!(PeerDirectory::new().adopt(&g), PeerOutcome::BadSig);
    }

    #[test]
    fn ip_and_clearnet_addresses_are_unrepresentable() {
        // The onion-only gate: no IP or clearnet host can ever enter the directory.
        assert!(onion_host_of("/dns/1.2.3.4/tcp/35000").is_none());
        assert!(onion_host_of("/ip4/1.2.3.4/tcp/35000").is_none());
        assert!(onion_host_of("/dns/example.com/tcp/35000").is_none());
        assert!(onion_host_of("/dns/short.onion/tcp/35000").is_none());
        assert!(onion_host_of("/dns/[::1]/tcp/35000").is_none());
        assert!(onion_host_of(&format!("/dns/{ONION_A}/tcp/notaport")).is_none());
        assert_eq!(
            onion_host_of(&format!("/dns/{ONION_A}/tcp/35000")),
            Some(ONION_A.to_string())
        );
    }

    #[test]
    fn persistence_round_trip_re_dials_known_peers_on_restart() {
        let dir_path =
            std::env::temp_dir().join(format!("usdmd-peertest-{}.pd", std::process::id()));
        let _ = std::fs::remove_file(&dir_path);
        let (pk, sk) = ml_dsa_keypair();
        {
            let mut dir = PeerDirectory::with_persist(dir_path.clone());
            assert_eq!(
                dir.adopt(&signed(&pk, &sk, ONION_A, 35000, 7)),
                PeerOutcome::Adopted
            );
            assert_eq!(dir.len(), 1);
        } // node "restarts"
        let reopened = PeerDirectory::with_persist(dir_path.clone());
        assert_eq!(
            reopened.len(),
            1,
            "a restarted node must re-load its known peers from disk"
        );
        assert_eq!(
            reopened.peers()[0].addr,
            format!("/dns/{ONION_A}/tcp/35000")
        );
        let _ = std::fs::remove_file(&dir_path);
    }

    /// ⛔ G1g-iii (lane a 2026-10-23) — binding persistence IN PLACE keeps what the live directory held: a peer adopted
    /// before the bind is written to the file, this node's own owner id survives (its own record is never filed, even when
    /// the file held it), and a second process reading the file holds the same peers. A forged on-disk record is dropped
    /// on load (the signature is re-verified). RED before: `Node::enable_peer_persist` REPLACED the directory, so the
    /// earlier peer and the self owner were lost.
    #[test]
    fn binding_persistence_in_place_keeps_the_earlier_peers_and_the_self_owner_and_refuses_a_forged_line() {
        let path = std::env::temp_dir().join(format!("usdmd-peerbind-{}-{}.pd", std::process::id(), line!()));
        let _ = std::fs::remove_file(&path);
        let (pk_me, sk_me) = ml_dsa_keypair();
        let (pk_a, sk_a) = ml_dsa_keypair();
        let me = signed(&pk_me, &sk_me, ONION_B, 35001, 3).verify().expect("own record verifies");
        // the file already holds THIS node's own record (a stale self entry) — it must never come back as a peer
        {
            let mut seed = PeerDirectory::with_persist(path.clone());
            assert_eq!(seed.adopt(&signed(&pk_me, &sk_me, ONION_B, 35001, 3)), PeerOutcome::Adopted);
        }
        let mut live = PeerDirectory::new();
        live.set_self_owner(me);
        assert_eq!(live.adopt(&signed(&pk_a, &sk_a, ONION_A, 35000, 7)), PeerOutcome::Adopted, "PRECONDITION: a peer learned before the bind");
        live.enable_persist(path.clone());
        assert_eq!(live.len(), 1, "⛔ the bind lost the earlier peer or filed this node's own record");
        assert_eq!(live.adopt(&signed(&pk_me, &sk_me, ONION_B, 35001, 9)), PeerOutcome::Unchanged, "⛔ the self owner was dropped by the bind");
        let second = PeerDirectory::with_persist(path.clone());
        assert_eq!(second.peers(), live.peers(), "⛔ a second process reading the file holds different peers than the live one");
        // TAMPER: flip one byte of the persisted record → it does not verify → nothing loads
        let mut bytes = std::fs::read(&path).expect("file written");
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        std::fs::write(&path, &bytes).expect("tampered file written");
        assert_eq!(PeerDirectory::with_persist(path.clone()).len(), 0, "⛔ TAMPER: a forged on-disk peer record loaded");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn only_bonded_validator_peers_are_eclipse_resistant_anchors() {
        // ECLIPSE RESISTANCE: a peer signed by a BONDED validator key is an anchor (Sybil-resistant — the
        // identity cost a real stake bond); a peer signed by an unbonded key is an ordinary free-onion peer.
        let (pk_bonded, sk_bonded) = ml_dsa_keypair();
        let (pk_free, sk_free) = ml_dsa_keypair();
        let bonded_id = crate::pqauth::pubkey_id(&pk_bonded);
        let mut dir = PeerDirectory::new();
        assert_eq!(
            dir.adopt(&signed(&pk_bonded, &sk_bonded, ONION_A, 35000, 1)),
            PeerOutcome::Adopted
        );
        assert_eq!(
            dir.adopt(&signed(&pk_free, &sk_free, ONION_B, 35001, 1)),
            PeerOutcome::Adopted
        );
        // The live bonded-set membership test: only the bonded validator's identity is bonded.
        let (anchors, others) = dir.classify_anchors(|id| *id == bonded_id);
        assert_eq!(
            anchors.len(),
            1,
            "the bonded-validator peer is the ONLY anchor"
        );
        assert_eq!(anchors[0].addr, format!("/dns/{ONION_A}/tcp/35000"));
        assert_eq!(others.len(), 1, "the free-onion peer is not an anchor");
        assert_eq!(others[0].addr, format!("/dns/{ONION_B}/tcp/35001"));
        // With NO bonded validators (is_bonded always false), NO peer is an anchor — an all-free-onion mesh
        // has no stake-backed anchors, which is the honest classification (not a fabricated one).
        let (none_anchor, all_other) = dir.classify_anchors(|_| false);
        assert!(none_anchor.is_empty());
        assert_eq!(all_other.len(), 2);
    }

    #[test]
    fn bonded_anchor_survives_a_full_sybil_onion_flood() {
        // ADVERSARIAL ECLIPSE: an attacker mints MAX_PEERS free `.onion` identities and floods the directory to
        // capacity BEFORE the victim learns an honest peer. The anti-eclipse admission must STILL admit a bonded
        // (stake-backed) anchor by evicting a free Sybil — otherwise the flood would make the honest peer
        // un-adoptable and the victim would be SILENTLY ECLIPSED (its view censored). This is the residual
        // onion-only attack, proven closed.
        let (pk_anchor, sk_anchor) = ml_dsa_keypair();
        let anchor_id = crate::pqauth::pubkey_id(&pk_anchor);
        let is_bonded = |id: &[u8; 32]| *id == anchor_id;

        let mut dir = PeerDirectory::new();
        // Flood to capacity with distinct free-onion Sybils (none bonded — each is a fresh unbonded identity).
        for i in 0..MAX_PEERS {
            let (pk, sk) = ml_dsa_keypair();
            let port = 40000u16.wrapping_add((i % 20000) as u16);
            assert_eq!(
                dir.adopt_prioritized(&signed(&pk, &sk, ONION_A, port, 1), is_bonded),
                PeerOutcome::Adopted
            );
        }
        assert_eq!(
            dir.len(),
            MAX_PEERS,
            "directory is now full of free-onion Sybils"
        );

        // Another free Sybil at capacity is DROPPED — the flood cannot grow the directory without bound.
        let (pk_s, sk_s) = ml_dsa_keypair();
        assert_eq!(
            dir.adopt_prioritized(&signed(&pk_s, &sk_s, ONION_B, 41000, 1), is_bonded),
            PeerOutcome::Unchanged,
            "a free-onion newcomer at capacity is dropped (bounded), never grows the directory"
        );

        // The HONEST bonded anchor is ADMITTED at capacity (evicting a Sybil) — the eclipse FAILS.
        assert_eq!(
            dir.adopt_prioritized(&signed(&pk_anchor, &sk_anchor, ONION_B, 35000, 1), is_bonded),
            PeerOutcome::Adopted,
            "a bonded anchor MUST be admitted even when a Sybil flood filled the directory (no silent eclipse)"
        );
        assert_eq!(
            dir.len(),
            MAX_PEERS,
            "admitting the anchor evicted a Sybil (still bounded)"
        );
        // It is classified as the live stake-backed anchor the dial loop always keeps connected.
        let (anchors, _others) = dir.classify_anchors(is_bonded);
        assert_eq!(
            anchors.len(),
            1,
            "the honest bonded peer is a live anchor despite the flood"
        );
        assert_eq!(anchors[0].addr, format!("/dns/{ONION_B}/tcp/35000"));
    }

    #[test]
    fn distinct_owners_each_get_a_slot() {
        let (pk1, sk1) = ml_dsa_keypair();
        let (pk2, sk2) = ml_dsa_keypair();
        let mut dir = PeerDirectory::new();
        assert_eq!(
            dir.adopt(&signed(&pk1, &sk1, ONION_A, 35000, 1)),
            PeerOutcome::Adopted
        );
        assert_eq!(
            dir.adopt(&signed(&pk2, &sk2, ONION_B, 35001, 1)),
            PeerOutcome::Adopted
        );
        assert_eq!(
            dir.len(),
            2,
            "different node identities converge to distinct peer slots"
        );
    }

    /// ⭐⭐⭐ DB-355 — BOTH ADOPT DOORS REFUSE THIS NODE'S OWN RECORD. `adopt_prioritized` is the production door
    /// (`Node::adopt_peer`), and on every real daemon of [slotB17c] it filed the node's own announce as a peer: the node
    /// re-dialed itself as a BONDED anchor and counted itself in its mesh. The original self fix (2026-08-01) had no pin,
    /// which is how a second door could ship without it.
    #[test]
    fn db355_the_bonded_priority_door_refuses_this_nodes_own_record_like_the_plain_door() {
        let (pk, sk) = ml_dsa_keypair();
        let own = signed(&pk, &sk, ONION_A, 35000, 7);
        let owner = own.verify().expect("an honest record verifies");
        let mut open = PeerDirectory::new();
        assert_eq!(
            open.adopt_prioritized(&own, |_| true),
            PeerOutcome::Adopted,
            "CALIBRATION: with no self declared, the record is an ordinary (bonded) peer"
        );
        let mut dir = PeerDirectory::new();
        dir.set_self_owner(owner);
        assert_eq!(dir.adopt(&own), PeerOutcome::Unchanged, "the plain door refuses our own record");
        assert_eq!(
            dir.adopt_prioritized(&own, |_| true),
            PeerOutcome::Unchanged,
            "⛔ DB-355: the bonded-priority door (Node::adopt_peer) filed this node's OWN record as a peer"
        );
        let newer = signed(&pk, &sk, ONION_A, 35000, 8);
        assert_eq!(dir.adopt_prioritized(&newer, |_| false), PeerOutcome::Unchanged, "at any seq, bonded or not");
        assert!(dir.peers().is_empty(), "no self entry to dial or to count");
        open.set_self_owner(owner);
        assert!(open.peers().is_empty(), "declaring self evicts an entry filed before the declaration");
        let (pk2, sk2) = ml_dsa_keypair();
        assert_eq!(
            dir.adopt_prioritized(&signed(&pk2, &sk2, ONION_B, 35001, 1), |_| false),
            PeerOutcome::Adopted,
            "a real peer still gets in through the same door"
        );
    }
}
