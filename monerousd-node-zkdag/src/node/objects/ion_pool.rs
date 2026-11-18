// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! MonerousD Protocol — the half of `crate::ion_pool_tx` that reads or moves the node: the two classes' apply at the fold,
//! the settlement every node forms for the pools that have pending orders, and the node's own CACHE of pool rows and of
//! the contract-state tree (what a settlement's former needs and the chain does not keep). The module's own doc
//! (`ion_pool_tx.rs`) holds the design, both doors' §9.6 answers and the cons; nothing here changes them.

use crate::contract_state::ContractStateTree;
use crate::ion_pool_tx::*;
use crate::spend_frontier::Digest4;

/// What one cache write replaced, so a fold rewind can put it back (a leaf as its 32 bytes: the form a checkpoint carries).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum CacheUndo {
    Leaf { cid: [u8; 32], old: Option<[u8; 32]> },
    Row { token: [u8; 32], old: Option<IonRow> },
}

/// ⭐ THE CACHE AS A NODE'S OWN CHECKPOINT CARRIES IT (`NodeSnapshot::ion_cache`): every leaf in key order, every row,
/// AND THE UNDO LOG, so a node that restarted follows a fold rewind exactly as it would have without restarting.
/// Without the log a rewind after a restart could not be followed and the node would have to drop its pools and ask
/// its peers for them again; were every node restarted at once and the fold then rewound a step, nobody would hold
/// them. Never trusted: `IonCache::install_file` keeps it only if it IS the tree under the ledger's root.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IonCacheFile {
    /// O1-FOOTPRINT-REVIEWED: one entry a contract leaf the node holds (the cache's own stated size).
    pub leaves: Vec<([u8; 32], [u8; 32])>,
    /// O1-FOOTPRINT-REVIEWED: one row a pool the node holds (the cache's own stated size).
    pub rows: Vec<IonRow>,
    /// O1-FOOTPRINT-REVIEWED: the writes of the fold steps a rewind can reach (`Node::REWIND_RETAIN`), as in memory.
    undo: Vec<(u64, CacheUndo)>,
    logged_from: u64,
}

/// ⭐ THE NODE'S OWN COPY of what the chain keeps only a root of: every contract leaf its fold produced (the tree a path
/// is read from) and every pool's row (what a settlement carries, and what a pools list shows).
///
/// CACHE-ONLY, and checked at every use: a settlement is formed from it only when the tree's root IS the ledger's
/// contract-state root, and every node recomputes that settlement against its own root, so a wrong cache can only fail
/// to settle, never settle wrongly. It un-folds with the fold ([`IonCache::rewind`], an undo log of the steps a rewind
/// can reach), so a re-ordered step does not leave it describing an abandoned branch.
///
/// HOW A NODE COMES TO HOLD IT: its own fold writes every leaf and row from the step it starts folding at; a RESTART
/// resumes it from the node's own checkpoint (`NodeSnapshot::ion_cache`, installed only if it is the tree under the
/// restored ledger's root); a node that JOINED by a certified state asks its peers for the leaves from before it
/// (`IonCache::take_page`, each leaf checked by its own path against this node's root). Until the tree's root is the
/// ledger's, `Node::ion_cache_is_current` says so, the pools routes answer "not ready", and the node forms no settlement.
/// SAFE AT SCALE: (a) nodes that bond: no term. (b) contracts and pools: about 100 B a contract leaf with its tree node
/// and about 0.8 KB a pool row, in RAM and in this node's own checkpoint; a write, a root read and a path read cost a few
/// thousand hashes whatever the tree holds (`ContractStateTree`). (c) height: no term (an undo entry lives
/// `Node::REWIND_RETAIN` steps).
/// AVAILABILITY, stated plainly: the chain keeps the root; the rows live on the nodes. Every node keeps them through its
/// own restarts and hands them to joiners, so they are lost only if every node that holds them is lost at once, which
/// is the standing of every other record a node serves.
#[derive(Clone, Debug, Default)]
pub struct IonCache {
    tree: ContractStateTree,
    rows: std::collections::BTreeMap<[u8; 32], IonRow>,
    /// A pool's contract id → its token, for every row held (a page of the tree names leaves by id).
    /// O1-FOOTPRINT-REVIEWED: one 64 B entry a row held, written and removed with the row.
    pools: std::collections::BTreeMap<[u8; 32], [u8; 32]>,
    /// Every row held, the deepest pool first: `(its liquidity in USDm, descending; its token)`. A pools list reads a
    /// page of it; it is never sorted on a request.
    /// O1-FOOTPRINT-REVIEWED: one 48 B entry a row held, written and removed with the row.
    ranked: std::collections::BTreeSet<(std::cmp::Reverse<u128>, [u8; 32])>,
    /// The tag a pool's share notes carry (its 24 bytes) → `(the pool's token, the unlock week: 0 for plain shares)`, for
    /// every row held and every unlock date its lock table lists (spec §14.2): what lets a wallet's own node name the
    /// share notes, plain or locked, that wallet holds.
    /// O1-FOOTPRINT-REVIEWED: one 60 B entry a row held and one a lock entry of it, written and removed with the row.
    share_tags: std::collections::BTreeMap<[u8; 24], ([u8; 32], u32)>,
    /// The refill's place: the last contract id of the last page this node asked for and got (the zero key: from the start).
    refill_cursor: [u8; 32],
    /// `(fold step, what the write replaced)`, oldest first.
    /// O1-FOOTPRINT-REVIEWED: bounded by the fold steps a rewind can reach (`Node::REWIND_RETAIN`): [`IonCache::forget_below`]
    /// drops every older entry at each write.
    undo: std::collections::VecDeque<(u64, CacheUndo)>,
    /// Every write at this fold step or later is in `undo` (0 on a cache that began empty). A rewind that reaches
    /// below it cannot be followed, and the cache is then dropped whole ([`IonCache::rewind`]).
    logged_from: u64,
    /// The settlement this node last pooled for each pool: `(batch number, the newest folded step when it was formed)`.
    /// It keeps a node from forming a batch's settlement again on every tick while the first copy waits for a block.
    /// O1-FOOTPRINT-REVIEWED: one entry a pool with a settlement in flight; [`IonCache::note_sent`] drops every entry
    /// older than [`ION_RESEND_STEPS`] steps at each write.
    sent: std::collections::BTreeMap<[u8; 32], (u64, u64)>,
}

/// A settlement that has not folded this many steps after it was formed is formed again (a newer step may have changed
/// what is pending; the first copy, if it still lands, takes the batch and the second loses the one-time id).
pub const ION_RESEND_STEPS: u64 = 4;

impl IonCache {
    /// The fold wrote `leaf` under `cid` at fold step `step`.
    pub fn write_leaf(&mut self, step: u64, cid: [u8; 32], leaf: Digest4) {
        self.undo.push_back((step, CacheUndo::Leaf { cid, old: self.tree.get(&cid).map(crate::spend_frontier::leaf_to_cm_bytes) }));
        self.tree.insert(cid, leaf);
    }

    /// The fold wrote a pool's row at fold step `step`.
    pub fn write_row(&mut self, step: u64, row: IonRow) {
        self.undo.push_back((step, CacheUndo::Row { token: row.token, old: self.rows.get(&row.token).cloned() }));
        self.put_row(row);
    }

    /// Hold `row` (replacing the pool's earlier one) with its two indexes.
    fn put_row(&mut self, row: IonRow) {
        if let Some(old) = self.rows.get(&row.token).cloned() {
            self.ranked.remove(&(std::cmp::Reverse(u128::from(old.liquidity_usdm())), old.token));
            self.unindex_share_tags(&old);
        }
        self.ranked.insert((std::cmp::Reverse(u128::from(row.liquidity_usdm())), row.token));
        let cid = ion_pool_cid(&row.token);
        for (tag, week) in Self::share_tags_of(&row) {
            self.share_tags.insert(tag, (row.token, week));
        }
        self.pools.insert(cid, row.token);
        self.rows.insert(row.token, row);
    }

    /// Every share tag a row names: its plain shares' (week 0), and one for each unlock date its lock table lists.
    fn share_tags_of(row: &IonRow) -> Vec<([u8; 24], u32)> {
        let cid = ion_pool_cid(&row.token);
        std::iter::once((crate::directory::asset_tag_bytes(&share_asset_id(&cid)), 0))
            .chain(row.locks.iter().map(|(w, _)| (crate::directory::asset_tag_bytes(&locked_share_asset_id(&cid, *w)), *w)))
            .collect()
    }

    fn unindex_share_tags(&mut self, row: &IonRow) {
        for (tag, _) in Self::share_tags_of(row) {
            self.share_tags.remove(&tag);
        }
    }

    /// The token of the pool whose share notes, plain or locked, carry `tag`, if this node holds that pool's row.
    #[must_use]
    pub fn pool_of_share_tag(&self, tag: &[u8; 24]) -> Option<[u8; 32]> {
        self.share_tags.get(tag).map(|(token, _)| *token)
    }

    /// `(the pool's token, the unlock week: 0 for plain shares)` of the share notes that carry `tag` (spec §14.2).
    #[must_use]
    pub fn share_of_tag(&self, tag: &[u8; 24]) -> Option<([u8; 32], u32)> {
        self.share_tags.get(tag).copied()
    }

    /// Hold no row for `token` any more.
    fn drop_row(&mut self, token: &[u8; 32]) {
        if let Some(old) = self.rows.remove(token) {
            self.ranked.remove(&(std::cmp::Reverse(u128::from(old.liquidity_usdm())), old.token));
            self.unindex_share_tags(&old);
        }
        let cid = ion_pool_cid(token);
        self.pools.remove(&cid);
    }

    /// Every row held, the deepest pool first (ties by token id): what a pools list pages through.
    pub fn ranked(&self) -> impl Iterator<Item = &IonRow> {
        self.ranked.iter().filter_map(|(_, token)| self.rows.get(token))
    }

    /// The fold left every step from `first_evict` on: every write of those steps is taken back, newest first.
    /// ⛔ A REWIND THIS CACHE CANNOT FOLLOW DROPS IT WHOLE. If the rewind reaches a step whose writes are no longer in
    /// the log (`first_evict < logged_from`), some leaf here would stay as the abandoned branch left it, and the refill's
    /// rule "a leaf held is the newer word" would keep it for good. An empty cache is always a true one: the node then
    /// asks its peers and keeps what their pages prove (`IonCache::take_page`).
    pub fn rewind(&mut self, first_evict: u64) {
        if first_evict < self.logged_from {
            let sent = std::mem::take(&mut self.sent);
            *self = IonCache { sent, logged_from: first_evict, ..IonCache::default() };
            return;
        }
        while self.undo.back().is_some_and(|(step, _)| *step >= first_evict) {
            match self.undo.pop_back() {
                Some((_, CacheUndo::Leaf { cid, old: Some(bytes) })) => match crate::spend_frontier::cm_bytes_to_root(&bytes) {
                    Some(leaf) => self.tree.insert(cid, leaf),
                    None => self.tree.remove(&cid), // unreachable: the log holds only leaves this cache wrote or `install_file` parsed
                },
                Some((_, CacheUndo::Leaf { cid, old: None })) => self.tree.remove(&cid),
                Some((_, CacheUndo::Row { old: Some(row), .. })) => self.put_row(row),
                Some((_, CacheUndo::Row { token, old: None })) => self.drop_row(&token),
                None => {}
            }
        }
    }

    /// No rewind reaches below `floor` any more: those writes can no longer be taken back, so their undo is dropped.
    pub fn forget_below(&mut self, floor: u64) {
        while self.undo.front().is_some_and(|(step, _)| *step < floor) {
            self.undo.pop_front();
        }
        self.logged_from = self.logged_from.max(floor);
    }

    #[must_use]
    pub fn tree(&self) -> &ContractStateTree {
        &self.tree
    }

    /// Should this node form batch `batch` of `token` now, at newest folded step `step`? Not while a copy it formed
    /// fewer than [`ION_RESEND_STEPS`] steps ago is still waiting for a block.
    #[must_use]
    pub fn should_send(&self, token: &[u8; 32], batch: u64, step: u64) -> bool {
        self.sent.get(token).is_none_or(|(b, at)| *b != batch || step >= at.saturating_add(ION_RESEND_STEPS))
    }

    /// This node pooled batch `batch` of `token` at newest folded step `step`.
    pub fn note_sent(&mut self, token: [u8; 32], batch: u64, step: u64) {
        self.sent.retain(|_, (_, at)| step < at.saturating_add(4 * ION_RESEND_STEPS));
        self.sent.insert(token, (batch, step));
    }

    /// A pool's row as this node's fold left it.
    #[must_use]
    pub fn row(&self, token: &[u8; 32]) -> Option<&IonRow> {
        self.rows.get(token)
    }

    /// Every row this node holds.
    pub fn rows(&self) -> impl Iterator<Item = &IonRow> {
        self.rows.values()
    }

    /// How many pools' rows this node holds.
    #[must_use]
    pub fn rows_held(&self) -> u64 {
        self.rows.len() as u64
    }

    /// This cache as this node's checkpoint carries it: every leaf in key order, every row, and the undo log.
    #[must_use]
    pub fn export(&self) -> IonCacheFile {
        IonCacheFile {
            leaves: self.tree.entries().into_iter().map(|(k, leaf)| (k, crate::spend_frontier::leaf_to_cm_bytes(leaf))).collect(),
            rows: self.rows.values().cloned().collect(),
            undo: self.undo.iter().cloned().collect(),
            logged_from: self.logged_from,
        }
    }

    /// ⭐ RESUME FROM A FILE THIS NODE WROTE: kept only when it IS the tree under `root` (the restored ledger's own
    /// contract-state root), every row is the storage of its pool's leaf, and every leaf in it (the undo log's too) is
    /// a canonical digest. `false`, with nothing changed, otherwise: the node then holds no pools and asks its peers.
    #[must_use]
    pub fn install_file(&mut self, root: Digest4, file: IonCacheFile) -> bool {
        let mut leaves = Vec::with_capacity(file.leaves.len());
        for (k, bytes) in &file.leaves {
            let Some(leaf) = crate::spend_frontier::cm_bytes_to_root(bytes) else {
                return false;
            };
            leaves.push((*k, leaf));
        }
        let parses = |u: &(u64, CacheUndo)| match &u.1 {
            CacheUndo::Leaf { old: Some(b), .. } => crate::spend_frontier::cm_bytes_to_root(b).is_some(),
            CacheUndo::Row { old: Some(r), .. } => r.well_formed(),
            _ => true,
        };
        if !file.undo.iter().all(parses) || !file.undo.windows(2).all(|w| w[0].0 <= w[1].0) {
            return false;
        }
        let tree = ContractStateTree::from_entries(&leaves);
        if tree.root() != root {
            return false;
        }
        let mut kept = std::collections::BTreeMap::new();
        for row in file.rows {
            if !row.well_formed() || tree.get(&ion_pool_cid(&row.token)) != Some(row.leaf()) {
                return false;
            }
            kept.insert(row.token, row);
        }
        *self = IonCache { tree, undo: file.undo.into_iter().collect(), logged_from: file.logged_from, ..IonCache::default() };
        for (_, row) in kept {
            self.put_row(row);
        }
        true
    }

    /// Where this node's refill stands (what its next ask names).
    #[must_use]
    pub fn refill_cursor(&self) -> [u8; 32] {
        self.refill_cursor
    }

    /// ⭐ THE REFILL DOOR, ANSWERING SIDE — this node's next [`ION_PAGE_ITEMS`] leaves after `after`, each with its path
    /// under `root`, and the rows of the pools among them. The caller passes its ledger's root and calls only while
    /// this cache IS that root's tree (`Node::ion_cache_page`). The same bytes for every asker: published chain data.
    #[must_use]
    pub fn page(&self, root: Digest4, after: &[u8; 32]) -> IonCachePage {
        let mut next = self.tree.entries_after(after, ION_PAGE_ITEMS + 1);
        let done = next.len() <= ION_PAGE_ITEMS;
        next.truncate(ION_PAGE_ITEMS);
        let rows = next.iter().filter_map(|(cid, _)| self.pools.get(cid).and_then(|token| self.rows.get(token)).cloned()).collect();
        let items = next.into_iter().map(|(cid, leaf)| (cid, crate::spend_frontier::leaf_to_cm_bytes(leaf), self.tree.path(&cid))).collect();
        IonCachePage { root: crate::spend_frontier::leaf_to_cm_bytes(root), after: *after, items, rows, done }
    }

    /// ⭐ THE REFILL DOOR, ASKING SIDE — keep what `page` PROVES and nothing else. `on_branch` is every contract-state
    /// root THIS node's ledger stood on along its current branch, as far back as its own ring of transitions reaches
    /// (`Node::contract_roots_on_branch`: the root now, then the root before each transition this node folded), and
    /// `step` its newest folded step. A page read under a root that is not one of them is dropped whole (the answerer
    /// stands ahead of this node, on another branch, or further back than this node's ring). A leaf is kept only if
    /// this node does not hold that contract's leaf and the page's own path opens the page's root with it; a row only
    /// if it is the storage of the leaf this node holds for its pool. Returns how many leaves and rows were kept.
    ///
    /// WHY A LEAF PROVEN UNDER AN EARLIER ROOT OF THIS BRANCH IS TRUE NOW, AND WHY A LEAF HELD IS NEVER REPLACED: this
    /// node's cache holds every leaf written by a transition on that chain of roots, because its own fold applied each
    /// of them (`Node::push_contract_leaf_update` writes the ring and the cache together, and a rewind un-writes the
    /// cache while the abandoned entries fall off the chain). So a contract whose leaf this node does NOT hold was not
    /// written since the page's root, and its leaf there is its leaf now; and a leaf this node holds is the newer
    /// word. A kept leaf is filed in the undo log under `step`, so a rewind that leaves the step takes it back out and
    /// it is asked for again.
    /// THE FIRST SHAPE OF THIS RULE accepted only the root NOW, and was wrong for the chain this is built for: with a
    /// transition in every block an answer is at least one round trip old, so no page would ever have verified and a
    /// joiner on a busy chain would never have held the pools. The unit pin below holds that shape RED (a page one
    /// transition old keeps nothing under it). With the chain of roots an answer may be as old as the ring
    /// (`CONTRACT_LEAF_RING` transitions).
    ///
    /// §9.6, this door (it parallels the picture door, `Directory::keep_pic`: public data a joiner lacks, any peer
    /// answers, the asker keeps only what it verifies):
    /// (1) proof of work: not this door's (it moves no block);
    /// (2) proof: `contract_state::verify_path` of each leaf against a root this node's own ledger held on its current
    ///     branch (adopted from a certified state or produced by this node's fold); a row by the hash that IS its
    ///     pool's leaf (`IonRow::leaf`);
    /// (3) value: none moves; no ledger word is read from a page; a wrong cache cannot settle (every node recomputes a
    ///     settlement against its own root);
    /// (4) replay: a leaf already held is skipped by the map; the same page twice keeps nothing the second time;
    /// (5) bounded work: one page is at most `ION_PAGE_ITEMS` leaves (`IonCachePage::decode`), so at most that many
    ///     path checks of 256 hashes; pages are read only while this node's cache is not whole; nothing unverified
    ///     is held, so what a hostile peer can make this node keep is nothing;
    /// (6) parity with the picture door: the same, with one stated limit: a page read under a root this node has not
    ///     REACHED yet (the answerer is ahead of it) is dropped, so a node still catching up lands pages only as it
    ///     reaches the tip;
    /// (7) scale (SAFE AT SCALE): nothing per bonded node; a joiner's asks grow with the contracts the chain holds,
    ///     once (a page an answer, the next ask sent at once); with height: nothing;
    /// (8) what protects it (AI RESISTANT): (a) a check every node makes, a Merkle path against a root it already
    ///     holds. A lying peer gains nothing (a false leaf opens no root; an omitted leaf or row leaves this node short
    ///     of the ledger's root or of its pool count, which this node sees and keeps asking); a persuasive message has
    ///     no input here.
    pub fn take_page(&mut self, step: u64, on_branch: &[Digest4], page: &IonCachePage) -> usize {
        let Some(root) = crate::spend_frontier::cm_bytes_to_root(&page.root).filter(|r| on_branch.contains(r)) else {
            return 0;
        };
        let mut kept = 0;
        for (cid, leaf_bytes, path) in &page.items {
            if self.tree.get(cid).is_some() {
                continue;
            }
            let (Some(leaf), Some(sibs)) = (crate::spend_frontier::cm_bytes_to_root(leaf_bytes), path.expand()) else {
                continue;
            };
            if leaf != crate::contract_state::empty_leaf() && crate::contract_state::verify_path(root, cid, leaf, &sibs) {
                self.write_leaf(step, *cid, leaf);
                kept += 1;
            }
        }
        for row in &page.rows {
            if row.well_formed() && self.tree.get(&ion_pool_cid(&row.token)) == Some(row.leaf()) && self.rows.get(&row.token) != Some(row) {
                self.write_row(step, row.clone());
                kept += 1;
            }
        }
        if page.after == self.refill_cursor {
            self.refill_cursor = match page.items.last() {
                Some((last, _, _)) if !page.done => *last,
                _ => [0u8; 32],
            };
        }
        kept
    }
}

/// ⭐ THE FOLD DOOR of the two pool classes: every node, in canonical order, from the block's bytes and its own ledger.
/// `fold_step` is the fold ordinal of the step being applied; `chain_ms` the carrying block's chain clock.
/// An ORDER: its legs' welded spends, each spent note's membership at the Fold door, room in the pending list; then it
/// joins the list, the USDm it burned joins the layer word, and its change is recorded. A SETTLEMENT: its whole verdict
/// (`IonSettleTx::verdict`), then the layer word (the turnstile), then the root moves, the pending orders it paid leave
/// the list and its payout notes are recorded. A refusal is on the item only: nothing is written and nothing is spent.
pub fn apply_chain_ion(node: &mut crate::node::Node, blob: &[u8], fold_step: u64, chain_ms: u64) -> IonApply {
    match crate::chain_object::unframe(blob) {
        Some((crate::chain_object::Class::IonOrder, payload)) => {
            let Some(t) = IonOrderTx::decode(payload) else {
                return IonApply::Refused("the payload is not a pool order");
            };
            if let Some(why) = node.ion_order_refusal(&t, crate::respend::MemberDoor::Fold) {
                return IonApply::Refused(why);
            }
            let pending = IonPending { token: t.token, step: fold_step, id: t.id(), core: t.core.clone() };
            if !node.ion_take_order_at_fold(pending, t.usdm_in()) {
                return IonApply::Refused("the pool's pending orders have no room at this step (the order is sent again; nothing was burned)");
            }
            let h = node.tip_height();
            for f in &t.legs {
                node.record_note_payload(h, &f.change_note);
            }
            IonApply::Applied
        }
        Some((crate::chain_object::Class::IonSettle, payload)) => {
            let Some(t) = IonSettleTx::decode(payload) else {
                return IonApply::Refused("the payload is not a pool settlement");
            };
            // several pools settle in one step: a settlement whose carried path was proven before an earlier settlement of
            // THIS step moved the root is brought forward over those writes, then judged by the same verdict
            // (`IonSettleTx::brought_forward`); one that still does not open the root is refused as before
            let root = node.peg().contract_state_root();
            let t = t.brought_forward(root, node.ion_step_writes_of(fold_step)).unwrap_or(t);
            let (root_after, done) = match t.verdict(root, node.peg().ion_pending(), fold_step, chain_ms / 1_000) {
                Ok(v) => v,
                Err(why) => return IonApply::Refused(why),
            };
            if !node.ion_settle_at_fold(&t, root_after, &done, fold_step) {
                return IonApply::Refused("the pool layer would pay out more USDm than it took in");
            }
            let h = node.tip_height();
            for (note, _) in &t.notes {
                node.record_note_payload(h, note);
            }
            IonApply::Applied
        }
        _ => IonApply::NotIon,
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;
    use crate::spend_frontier::leaf_to_cm_bytes as b32;
    use usdm_decider::poseidon2_compress::lanes_of;

    fn token(i: u8) -> [u8; 32] {
        [i; 32]
    }
    /// A pool's row after `batch` batches (any well-formed row will do: the cache checks it against its leaf).
    fn row(i: u8, batch: u64) -> IonRow {
        let mut r = IonRow::new(token(i));
        r.batch = batch;
        r
    }

    /// ⭐ THE REFILL RULE ON A MOVING CHAIN — A PAGE AS OLD AS A ROOT THIS NODE PASSED IS STILL GOOD, AND NOTHING ELSE IS.
    /// A holder has three pools and one plain contract at root R0 and answers a page there. Then the chain moves: pool 2
    /// settles again (R1), and a JOINER that held nothing folds that one transition itself. The R0 page arrives late:
    /// - with the joiner's branch `[R1, R0]` it keeps the three leaves it lacks and their rows, skips pool 2 (its own
    ///   newer word), and is the holder's tree at R1 with every row;
    /// - with the branch `[R1]` alone (the FIRST shape of this rule: the root now and no other) the same page keeps
    ///   NOTHING: RED for a joiner on a chain that moves between an answer and its arrival;
    /// - a page under a root on no branch of the joiner (an abandoned fork's) keeps nothing;
    /// - a page whose path was read under R0 but which CLAIMS R1 keeps nothing (the path opens the root it was read
    ///   under and no other);
    /// - a rewind of the step the kept leaves were filed under takes them back out (they are asked for again), and a
    ///   cache RESUMED from its own file in between rewinds to the same bytes (the file carries the undo log);
    /// - a rewind the undo log no longer covers drops the cache whole.
    #[test]
    fn ion_refill_keeps_a_page_read_under_an_earlier_root_of_this_branch_and_nothing_under_any_other() {
        let plain = ([0xEEu8; 32], lanes_of(&[5, 5, 5, 5]));
        let mut holder = IonCache::default();
        for i in 1..=3u8 {
            let r = row(i, 1);
            holder.write_leaf(10, ion_pool_cid(&r.token), r.leaf());
            holder.write_row(10, r);
        }
        holder.write_leaf(10, plain.0, plain.1);
        let r0 = holder.tree().root();
        let late = holder.page(r0, &[0u8; 32]);
        assert!(late.done && late.items.len() == 4 && late.rows.len() == 3, "CALIBRATION: one page holds the whole tree");
        // the chain moves: pool 2 settles again; the joiner folds that transition itself
        let moved = row(2, 2);
        let mut joiner = IonCache::default();
        for c in [&mut holder, &mut joiner] {
            c.write_leaf(11, ion_pool_cid(&moved.token), moved.leaf());
            c.write_row(11, moved.clone());
        }
        let r1 = holder.tree().root();
        assert_ne!(r0, r1, "CALIBRATION: the settlement moved the root");
        // the first shape of the rule: only the root now
        let mut strict = joiner.clone();
        assert_eq!(strict.take_page(11, &[r1], &late), 0, "RED for the first shape: a page one transition old is dropped whole");
        // a root on no branch of this node
        let mut forked = joiner.clone();
        assert_eq!(forked.take_page(11, &[r1, lanes_of(&[9, 9, 9, 9])], &late), 0, "⛔ a page under a root this node never stood on was read");
        // a page that claims the root now over paths read under the old one
        let mut relabelled = late.clone();
        relabelled.root = b32(r1);
        let mut fooled = joiner.clone();
        assert_eq!(fooled.take_page(11, &[r1, r0], &relabelled), 0, "⛔ a path read under another root opened this one");
        assert_eq!(fooled.tree().len(), 1, "the relabelled page added no leaf");
        // the rule
        assert_eq!(joiner.take_page(12, &[r1, r0], &late), 3 + 2, "the three leaves it lacks and the two rows whose leaves it now holds unchanged");
        assert_eq!(joiner.tree().root(), r1, "⛔ the joiner's tree is not the chain's after a late page");
        assert_eq!(joiner.row(&token(2)), Some(&moved), "⛔ the late page replaced the joiner's own newer row");
        assert_eq!(joiner.rows_held(), 3, "every pool's row is held");
        assert_eq!(joiner.take_page(12, &[r1, r0], &late), 0, "the same page twice keeps nothing");
        let ranked: Vec<[u8; 32]> = joiner.ranked().map(|r| r.token).collect();
        assert_eq!(ranked.len(), 3, "every row is in the liquidity order");
        // A RESTART IN BETWEEN changes nothing: the cache resumed from its own file follows the same rewind to the same
        // bytes (the file carries the undo log); a file bent in one leaf is not installed
        let file = joiner.export();
        let mut resumed = IonCache::default();
        assert!(resumed.install_file(r1, file.clone()), "⛔ a cache's own file is refused at resume");
        let mut bent = file.clone();
        bent.leaves[0].1 = b32(lanes_of(&[4, 4, 4, 4]));
        assert!(!IonCache::default().install_file(r1, bent), "⛔ a file with a leaf the root does not hold was installed");
        resumed.rewind(12);
        // A REWIND THE LOG NO LONGER COVERS drops the cache whole (an empty cache is a true one; a half-rewound one is not)
        let mut uncovered = holder.clone();
        uncovered.forget_below(11);
        uncovered.rewind(10);
        assert!(uncovered.tree().is_empty() && uncovered.rows_held() == 0, "⛔ a rewind the undo log cannot follow left leaves standing");
        // a rewind of the step the refill was filed under takes it back out; the joiner's own fold stays
        joiner.rewind(12);
        assert_eq!(resumed.export(), joiner.export(), "⛔ a resumed cache rewinds to other bytes than the one that never restarted");
        assert_eq!((joiner.tree().len(), joiner.rows_held()), (1, 1), "⛔ a rewound refill left leaves behind");
        assert_eq!(joiner.row(&token(2)), Some(&moved));
    }
}
