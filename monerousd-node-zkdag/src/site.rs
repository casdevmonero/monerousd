// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Sovereign site + service hosting: the node IS the deploy target for the whole ecosystem.
//!
//! Every MonerousD service (Ion Swap, Explorer, monerousd.org, the wallet, installers, Pay, every
//! dApp) deploys HERE — to the node — not to a central server. A site is a bundle of content-hashed
//! assets (HTML, JS, CSS, images, and **WASM front-ends** — a `.wasm` module is just another asset);
//! its whole current version is one merkle root. That root is anchored ON-CHAIN by a
//! [`SitePublish`] record, so:
//!
//! * **Uncensorable + redundant, exactly like the chain.** ANY node holding the bundle can serve it,
//!   and the client verifies each served asset against the chain-anchored root ([`verify_served`]).
//!   A hostile or tampering node is caught fail-closed; a single surviving honest node serves the
//!   entire ecosystem. Availability = the chain's availability.
//! * **Owner-controlled updates over the chain.** A site stays with its first owner (no takeover),
//!   and only a strictly-higher version supersedes (no rollback) — [`SiteRegistry`]. The publish
//!   record travels as a consensus-validated chain record, so its authenticity is enforced at the
//!   tx/consensus edge (the PQ signature over the record), the same layering as block ingress.
//!
//! Backends are served the same way: a service's dynamic responses are computed by the LOCAL node
//! from chain state via the loopback RPC ([`crate::rpc`]); this module is the content-integrity +
//! anchoring layer that makes the STATIC + WASM surface uncensorable. Transport is onion/loopback
//! ([`crate::net`]); nothing here ever reaches for an IP.

use std::collections::HashMap;

use crate::hash::Hash32;
use crate::merkle;

/// One asset in a site bundle: its path, MIME content-type, and bytes.
#[derive(Clone)]
pub struct Asset {
    pub path: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

/// A manifest entry: an asset addressed by path + content-type, bound to its content hash + length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetEntry {
    pub path: String,
    pub content_type: String,
    pub hash: Hash32,
    pub len: u64,
}

/// The canonical, ordered list of a site version's assets. Its [`SiteManifest::root`] is the site's
/// content-address — the value anchored on-chain.
pub struct SiteManifest {
    /// Sorted by `path`, unique paths.
    pub entries: Vec<AssetEntry>,
}

/// The merkle leaf binding an entry's path + content-type + content hash + length together, so a
/// verifier cannot be served the right bytes under the wrong path/type.
fn entry_leaf(e: &AssetEntry) -> Hash32 {
    let mut buf = Vec::with_capacity(8 + e.path.len() + e.content_type.len() + 40);
    buf.extend_from_slice(&(e.path.len() as u32).to_le_bytes());
    buf.extend_from_slice(e.path.as_bytes());
    buf.extend_from_slice(&(e.content_type.len() as u32).to_le_bytes());
    buf.extend_from_slice(e.content_type.as_bytes());
    buf.extend_from_slice(e.hash.as_bytes());
    buf.extend_from_slice(&e.len.to_le_bytes());
    Hash32::hash(&buf)
}

impl SiteManifest {
    /// The merkle leaves, one per entry (entry order).
    pub fn leaves(&self) -> Vec<Hash32> {
        self.entries.iter().map(entry_leaf).collect()
    }

    /// The content-address of this whole site version — the value a [`SitePublish`] anchors on-chain.
    pub fn root(&self) -> Hash32 {
        merkle::root(&self.leaves())
    }

    /// The entry index of `path` (entries are sorted, so this is a binary search).
    pub fn index_of(&self, path: &str) -> Option<usize> {
        self.entries
            .binary_search_by(|e| e.path.as_str().cmp(path))
            .ok()
    }
}

/// A stored site bundle: the manifest + the actual asset bytes a serving node holds.
pub struct SiteBundle {
    pub manifest: SiteManifest,
    assets: HashMap<String, Asset>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SiteError {
    #[error("duplicate asset path: {0}")]
    DuplicatePath(String),
}

/// An asset served with a merkle inclusion proof up to the (chain-anchored) content root.
pub struct ServedAsset {
    pub content_type: String,
    pub bytes: Vec<u8>,
    pub index: usize,
    pub proof: Vec<Hash32>,
}

/// Build a bundle from a set of assets: canonicalize (sort by path, reject duplicates), hash each,
/// and commit the manifest.
pub fn build_bundle(mut assets: Vec<Asset>) -> Result<SiteBundle, SiteError> {
    assets.sort_by(|a, b| a.path.cmp(&b.path));
    for w in assets.windows(2) {
        if w[0].path == w[1].path {
            return Err(SiteError::DuplicatePath(w[0].path.clone()));
        }
    }
    let entries: Vec<AssetEntry> = assets
        .iter()
        .map(|a| AssetEntry {
            path: a.path.clone(),
            content_type: a.content_type.clone(),
            hash: Hash32::hash(&a.bytes),
            len: a.bytes.len() as u64,
        })
        .collect();
    let map: HashMap<String, Asset> = assets.into_iter().map(|a| (a.path.clone(), a)).collect();
    Ok(SiteBundle {
        manifest: SiteManifest { entries },
        assets: map,
    })
}

impl SiteBundle {
    /// This bundle's content root (== what its [`SitePublish`] anchors on-chain).
    pub fn root(&self) -> Hash32 {
        self.manifest.root()
    }

    /// Serve `path` with a merkle inclusion proof up to the content root. Any node can serve this;
    /// the client authenticates it with [`verify_served`] against the chain-anchored root.
    pub fn serve(&self, path: &str) -> Option<ServedAsset> {
        let index = self.manifest.index_of(path)?;
        let asset = self.assets.get(path)?;
        let proof = merkle::inclusion_proof(&self.manifest.leaves(), index)?;
        Some(ServedAsset {
            content_type: asset.content_type.clone(),
            bytes: asset.bytes.clone(),
            index,
            proof,
        })
    }
}

/// CLIENT side: authenticate an asset served by ANY (possibly untrusted) node against the site's
/// on-chain content `root`. Rebinds path + content-type + served bytes into the leaf and checks the
/// proof — a tampered byte, a swapped path/type, or a wrong index all fail-closed. THIS is what makes
/// node-served sites as uncensorable as the chain: trust the root (from consensus), not the server.
pub fn verify_served(root: &Hash32, path: &str, served: &ServedAsset) -> bool {
    let leaf = entry_leaf(&AssetEntry {
        path: path.to_string(),
        content_type: served.content_type.clone(),
        hash: Hash32::hash(&served.bytes),
        len: served.bytes.len() as u64,
    });
    merkle::verify(root, served.index, &leaf, &served.proof)
}

/// An on-chain record binding a site to its current content root. It travels as a consensus-validated
/// chain record — its authenticity (the owner's PQ signature over `site_id‖version‖manifest_root`) is
/// enforced at the tx/consensus edge, exactly like any block payload; the registry below enforces
/// version-monotonicity + owner-continuity on top of an already-validated record.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SitePublish {
    pub site_id: Hash32,
    pub owner: [u8; 32],
    pub version: u64,
    pub manifest_root: Hash32,
}

impl SitePublish {
    /// A site id is namespaced to its owner: `H(owner ‖ name)`. No one can mint a publish for a
    /// site id that isn't derived from their own key + a name they chose.
    pub fn site_id_for(owner: &[u8; 32], name: &str) -> Hash32 {
        let mut buf = Vec::with_capacity(32 + name.len());
        buf.extend_from_slice(owner);
        buf.extend_from_slice(name.as_bytes());
        Hash32::hash(&buf)
    }

    pub fn new(owner: [u8; 32], name: &str, version: u64, manifest_root: Hash32) -> Self {
        SitePublish {
            site_id: Self::site_id_for(&owner, name),
            owner,
            version,
            manifest_root,
        }
    }
}

/// A sovereign-site publish AS IT TRAVELS THE MESH (bidirectional hosting): the [`SitePublish`] record
/// plus the owner's PQ public key + signature over `site_publish_msg(publish)`. Every node gossips this
/// like a block, so a site published to ONE node replicates to EVERY node — the "private MonerousD
/// internet" where each posted site has redundancy equal to the chain itself (every node stores + serves
/// it) and is permanent (the registry is version-monotonic — a version can advance but never roll back or
/// un-publish). A receiver VERIFIES the signature before adopting (fail-closed), then re-gossips a freshly
/// adopted version onward, so the mesh converges on ONE authoritative content root per site.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SiteGossip {
    pub publish: SitePublish,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl SiteGossip {
    pub fn new(publish: SitePublish, pubkey: Vec<u8>, sig: Vec<u8>) -> Self {
        SiteGossip {
            publish,
            pubkey,
            sig,
        }
    }

    /// Postcard-encode for a [`crate::protocol::WireMsg::Site`] payload.
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Decode a received site-gossip payload; a corrupt/truncated frame is `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<SiteGossip> {
        crate::chain_object::decode_exact(bytes)
    }
}

/// What happened to an adopt attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Accepted as the site's current version.
    Adopted,
    /// Rejected: the version is not strictly newer than the incumbent (no rollback / no replay).
    StaleVersion,
    /// Rejected: a different owner cannot seize an existing site id (no takeover).
    WrongOwner,
    /// Rejected: the owner's PQ signature did not authenticate the publish (fail-closed). Set at the
    /// node ingress by the PQ verifier ([`crate::pqauth`]) before a publish reaches the registry.
    Unauthenticated,
}

/// The node's live map of `site_id → current publish`. Every node keeps this from the chain, so
/// every node knows the authoritative content root of every site and can serve or verify it.
pub struct SiteRegistry {
    latest: HashMap<Hash32, SitePublish>,
}

impl SiteRegistry {
    pub fn new() -> Self {
        SiteRegistry {
            latest: HashMap::new(),
        }
    }

    /// Every published site and its current root, sorted by site id — the whole registry in one comparable value (the
    /// restart census compares it across a production restart).
    pub fn roots(&self) -> Vec<(Hash32, Hash32)> {
        let mut v: Vec<(Hash32, Hash32)> = self.latest.keys().filter_map(|k| self.current_root(k).map(|r| (*k, r))).collect();
        v.sort_by_key(|(k, _)| *k.as_bytes());
        v
    }

    /// The current chain-anchored content root for `site_id`, if published.
    pub fn current_root(&self, site_id: &Hash32) -> Option<Hash32> {
        self.latest.get(site_id).map(|p| p.manifest_root)
    }

    /// Is `root` the current content root of some site? What a node asks before it takes a byte of site content from
    /// a peer: content is carried only for a root an owner's signed publish anchors. One pass over the sites.
    pub fn anchors(&self, root: &Hash32) -> bool {
        self.latest.values().any(|p| p.manifest_root == *root)
    }

    pub fn current(&self, site_id: &Hash32) -> Option<&SitePublish> {
        self.latest.get(site_id)
    }

    /// Adopt a consensus-validated publish. The first publish claims the site; any later publish must
    /// be the SAME owner (no takeover) AND a strictly higher version (no rollback/replay). Fail-closed.
    pub fn adopt(&mut self, p: SitePublish) -> PublishOutcome {
        if let Some(cur) = self.latest.get(&p.site_id) {
            if p.owner != cur.owner {
                return PublishOutcome::WrongOwner;
            }
            if p.version <= cur.version {
                return PublishOutcome::StaleVersion;
            }
        }
        self.latest.insert(p.site_id, p);
        PublishOutcome::Adopted
    }
}

impl Default for SiteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn sample_site() -> SiteBundle {
        build_bundle(vec![
            Asset {
                path: "/index.html".into(),
                content_type: "text/html".into(),
                bytes: b"<h1>MonerousD</h1>".to_vec(),
            },
            Asset {
                path: "/app.wasm".into(),
                content_type: "application/wasm".into(),
                bytes: vec![0, 97, 115, 109, 1, 0, 0, 0],
            },
            Asset {
                path: "/style.css".into(),
                content_type: "text/css".into(),
                bytes: b"body{}".to_vec(),
            },
        ])
        .unwrap()
    }

    #[test]
    fn serve_and_verify_wasm_and_html_against_anchored_root() {
        let site = sample_site();
        let root = site.root(); // in production this is what the SitePublish anchors on-chain.

        // the WASM front-end asset serves + verifies with its content-type bound in.
        let served = site.serve("/app.wasm").expect("wasm served");
        assert_eq!(served.content_type, "application/wasm");
        assert!(
            verify_served(&root, "/app.wasm", &served),
            "honest WASM asset verifies"
        );

        // the HTML entrypoint too.
        let html = site.serve("/index.html").unwrap();
        assert!(verify_served(&root, "/index.html", &html));
    }

    #[test]
    fn tampering_node_is_caught_fail_closed() {
        let site = sample_site();
        let root = site.root();

        // a node that flips a byte in the served bytes is rejected.
        let mut bad = site.serve("/app.wasm").unwrap();
        bad.bytes[0] ^= 0xff;
        assert!(
            !verify_served(&root, "/app.wasm", &bad),
            "tampered bytes rejected"
        );

        // serving the real bytes under the WRONG path is rejected (path is bound into the leaf).
        let real = site.serve("/style.css").unwrap();
        assert!(
            !verify_served(&root, "/index.html", &real),
            "path substitution rejected"
        );

        // a forged content-type is rejected.
        let mut wrong_type = site.serve("/index.html").unwrap();
        wrong_type.content_type = "application/wasm".into();
        assert!(
            !verify_served(&root, "/index.html", &wrong_type),
            "content-type swap rejected"
        );

        // verifying against the WRONG (unrelated) root is rejected — you must trust the chain's root.
        let other_root = Hash32::hash(b"some other site");
        let honest = site.serve("/index.html").unwrap();
        assert!(
            !verify_served(&other_root, "/index.html", &honest),
            "wrong anchored root rejected"
        );
    }

    #[test]
    fn empty_site_and_duplicate_path() {
        let empty = build_bundle(vec![]).unwrap();
        assert_eq!(empty.root(), Hash32::ZERO);
        let dup = build_bundle(vec![
            Asset {
                path: "/x".into(),
                content_type: "t".into(),
                bytes: b"a".to_vec(),
            },
            Asset {
                path: "/x".into(),
                content_type: "t".into(),
                bytes: b"b".to_vec(),
            },
        ]);
        assert_eq!(dup.err(), Some(SiteError::DuplicatePath("/x".into())));
    }

    #[test]
    fn registry_owner_continuity_and_version_monotonic() {
        let mut reg = SiteRegistry::new();
        let owner = [7u8; 32];
        let attacker = [9u8; 32];
        let site = sample_site();
        let id = SitePublish::site_id_for(&owner, "ion-swap");

        // v1 claims the site.
        let v1 = SitePublish::new(owner, "ion-swap", 1, site.root());
        assert_eq!(reg.adopt(v1), PublishOutcome::Adopted);
        assert_eq!(reg.current_root(&id), Some(site.root()));

        // v2 by the same owner supersedes and updates the anchored root.
        let new_root = Hash32::hash(b"ion-swap v2 bundle");
        let v2 = SitePublish::new(owner, "ion-swap", 2, new_root);
        assert_eq!(reg.adopt(v2), PublishOutcome::Adopted);
        assert_eq!(reg.current_root(&id), Some(new_root));

        // a replay/rollback to an older version is rejected.
        let stale = SitePublish::new(owner, "ion-swap", 2, Hash32::hash(b"rollback"));
        assert_eq!(reg.adopt(stale), PublishOutcome::StaleVersion);
        assert_eq!(reg.current_root(&id), Some(new_root));

        // an attacker cannot seize the site id (same name, different owner => different id anyway),
        // but even a crafted record carrying the victim's site_id is rejected on owner mismatch.
        let mut takeover = SitePublish::new(attacker, "whatever", 99, Hash32::hash(b"evil"));
        takeover.site_id = id; // forge the target id
        assert_eq!(reg.adopt(takeover), PublishOutcome::WrongOwner);
        assert_eq!(
            reg.current_root(&id),
            Some(new_root),
            "root unchanged after rejected takeover"
        );
    }
}
