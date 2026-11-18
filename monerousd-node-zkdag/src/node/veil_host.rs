// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The node's side of MonerousD Veil (`crate::veil`): what the Veil asks of this node's own state. A site's NAME and
//! its current ROOT come from the chain (the chain directory and the site registry this node already keeps); the BYTES
//! live in the node's site store and are checked against that root. Nothing here changes consensus state.

use super::Node;
use crate::hash::Hash32;

impl Node {
    /// `flame.mud` → whose it is and the root its owner last published, from this node's own state.
    pub fn resolve_mud(&self, host: &str) -> Option<crate::veil::MudSite> {
        crate::veil::resolve_mud(&self.directory, &self.sites, host)
    }

    /// Every published `.mud` site, each the one its name's owner published, from this node's own state: what the
    /// Sovereign browser's search ranks (`crate::veil_search`).
    pub fn published_mud(&self) -> Vec<crate::veil::MudSite> {
        crate::veil_search::published(&self.directory, &self.sites)
    }

    /// Does a signed publish this node adopted anchor `root`?
    pub fn site_anchored(&self, root: &Hash32) -> bool {
        self.sites.anchors(root)
    }

    /// Is the site `root` binds one this node holds by placement (kept longest), by the node's one placement rule?
    pub fn veil_holds(&self, root: &Hash32) -> bool {
        crate::veil::holds_site(root, &self.band_provers(), self.public_id())
    }

    /// The other nodes that hold the site `root` binds, best rank first, each with the onion host a private ask is
    /// dialed at. When fewer than two of them are known, the other peers this node knows follow (bytes pass through
    /// every node, so a peer outside the placement may still hold them as a reader's copy).
    pub fn veil_holders(&self, root: &Hash32) -> Vec<(String, String)> {
        let me = self.public_id().map(str::to_string);
        let peers = self.known_peers();
        let host_of = |id: &str| -> Option<String> {
            let addr = &peers.iter().find(|p| p.peer_id == id)?.addr;
            let host = addr.strip_prefix("/dns/")?.split('/').next()?;
            host.ends_with(".onion").then(|| host.to_string())
        };
        let placed = crate::veil::site_holders(root, &self.band_provers());
        let mut out: Vec<(String, String)> = placed.iter().filter(|id| Some(*id) != me.as_ref()).filter_map(|id| Some((id.clone(), host_of(id)?))).collect();
        if out.len() < 2 {
            let mut rest: Vec<String> = peers.iter().map(|p| p.peer_id.clone()).filter(|id| Some(id) != me.as_ref() && !out.iter().any(|(o, _)| o == id)).collect();
            rest.sort();
            out.extend(rest.into_iter().filter_map(|id| Some((id.clone(), host_of(&id)?))));
        }
        out
    }

    /// What this node tells a publisher that asks its hosting terms: who it is and where its operator is paid (the
    /// reward recipient its operator's wallet provisioned). `None` until a recipient is provisioned: a node whose
    /// operator named no wallet is not paid for hosting.
    pub fn veil_terms(&self) -> Option<crate::veil_lane::Terms> {
        let rc = self.reward_recipient()?;
        Some(crate::veil_lane::Terms {
            holder: self.public_id()?.to_string(),
            spk: crate::spend_frontier::leaf_to_cm_bytes(rc.spk),
            scan_ek: rc.scan_ek.clone(),
            receive: None,
        })
    }

    /// The terms a publisher is ANSWERED with: [`Self::veil_terms`] plus a receive locator at a fresh index of the
    /// reward recipient's own `"sat"` counter, reserved now and persisted (AUDIT F11). Each answer takes the next index,
    /// so no two publishers, and no publisher and a block reward, are ever handed one tag.
    /// Scale: one index and one fixed-size file rewrite per terms answer; the operator's wallet finds a payment at any
    /// index by its doubling sweep (O(log n) probes), so a counter raised by many asks costs it nothing that grows.
    pub fn veil_terms_reserving(&mut self) -> Option<crate::veil_lane::Terms> {
        let mut terms = self.veil_terms()?;
        let rc = self.reward_recipient()?;
        let (k, j) = (rc.sat_loc_sk, rc.next_index);
        let dom = crate::satoshi::SAT_LOC_DOMAIN;
        let salt = crate::oli::address_salt(&k, dom, j);
        terms.receive = Some((crate::oli::locator_at(&k, dom, j), salt, crate::oli::address_index_hint(&k, &salt, j)));
        self.advance_reward_index();
        Some(terms)
    }

    /// A Veil frame from a peer: take what it carries when it checks out, and return the frames to pass on.
    pub fn veil_frame(&self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let Some(mut host) = crate::veil::host() else {
            return Vec::new();
        };
        crate::veil::on_frame(&mut host, |root| self.site_anchored(root), |chunk| self.veil_holds(chunk), bytes)
    }
}

impl Node {
    /// goods spec §3.3 — THE CLAIM WATCH for this node's own wallet: watch `spent_tags`, and answer with every tag seen
    /// beside one of them so far. A tag that was not watched before is looked for in the blocks this node already keeps
    /// (the claim may have landed while the node was restarting), once.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback names the tags; nothing is gossiped, logged or
    /// written, and what is answered is public chain data.
    pub fn claim_tags_beside(&self, spent_tags: &[[u8; 32]]) -> Vec<([u8; 32], [u8; 32])> {
        if !crate::claim_watch::add(spent_tags).is_empty() {
            for (_, id) in self.block_window.ascending() {
                if let Some(block) = self.block_window.get(&id) {
                    crate::claim_watch::note_block(&block);
                }
            }
        }
        crate::claim_watch::found(spent_tags)
    }
}
