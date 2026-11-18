// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE CLAIM WATCH (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §3.3): how a buyer's own node hands its wallet the
//! key a seller's delivery claim published.
//!
//! A spend publishes two tags as one row: its spent tag and its claim tag. A download's vault has one spent tag,
//! which the buyer's wallet computes when it locks the price. The spend that pays the seller lays that spent tag and,
//! beside it, a claim tag whose first lanes are the content key under a pad only the two parties hold
//! (`usdm_decider::whir_rec_block::vault_gate`, THE DELIVERY LOCK). The wallet asks ITS OWN node to note the claim
//! tag that appears beside a spent tag it names, and reads it back when it next opens.
//!
//! WHY THE NODE AND NOT THE WALLET: the wallet may be closed when the seller is paid. A node keeps a block's rows only
//! inside its block window, so the pair is noted the moment the block is kept. A wallet whose node was also off reads
//! the seller's letter instead (the seller's wallet sends the key that way too).
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: this node's own wallet over loopback names the tags; they stay in this process, are
//! never gossiped, logged or written, and a tag is public chain data that links to nothing without the vault's
//! opening, which never comes here.
//! CACHE-ONLY: a note of what blocks this node already keeps carry. It decides nothing for the chain and moves no
//! value; the chain's own record is the block.
//! MORE THAN ONE CANDIDATE. A transaction's row set also carries cover cells, and the seller of a download knows the
//! vault's spent tag, so a row may lay that tag beside something that is no claim. The watch therefore keeps the first
//! [`CANDIDATES`] distinct tags seen beside a watched tag, and the wallet takes the one that opens the lock it funded.
//!
//! O1-FOOTPRINT-REVIEWED: at most [`WATCH_MAX`] entries of `32 + 32 × CANDIDATES` bytes, in RAM, a constant.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

/// The most spent tags one node watches at a time: a bound on what its own wallet can make it hold.
// PRODUCTION-SCALE-REVIEWED: a bound on one wallet's OPEN downloads held in RAM, the same in production; a wallet
// with more open at once reads the rest from the sellers' letters.
pub const WATCH_MAX: usize = 256;

/// The distinct tags kept for one watched spent tag.
// PRODUCTION-SCALE-REVIEWED: a bound on one entry's list, the same in production; a real claim is laid once, and a
// vault's spent tag is known only to its two parties.
pub const CANDIDATES: usize = 4;

/// Spent tag → the tags seen beside it, in the order seen.
static WATCH: LazyLock<Mutex<HashMap<[u8; 32], Vec<[u8; 32]>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn table() -> std::sync::MutexGuard<'static, HashMap<[u8; 32], Vec<[u8; 32]>>> {
    WATCH.lock().unwrap_or_else(|e| e.into_inner())
}

/// Watch these spent tags. Returns the ones that were not watched before (the caller looks through the blocks it
/// already keeps for those). At the bound, an answered entry makes room; with none answered the tag is not taken.
pub fn add(spent_tags: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut t = table();
    let mut fresh = Vec::new();
    for tag in spent_tags {
        if t.contains_key(tag) {
            continue;
        }
        if t.len() >= WATCH_MAX {
            let Some(answered) = t.iter().find(|(k, v)| !v.is_empty() && !spent_tags.contains(k)).map(|(k, _)| *k) else {
                continue;
            };
            t.remove(&answered);
        }
        t.insert(*tag, Vec::new());
        fresh.push(*tag);
    }
    fresh
}

/// Is anything watched? (The block door asks before it decodes a block's rows.)
#[must_use]
pub fn waiting() -> bool {
    !table().is_empty()
}

/// A block's stated rows, as `(spent tag, claim tag)`: note the claim tag beside every watched spent tag.
pub fn note_rows(rows: impl Iterator<Item = ([u8; 32], [u8; 32])>) {
    let mut t = table();
    for (spent, claim) in rows {
        if let Some(seen) = t.get_mut(&spent) {
            if seen.len() < CANDIDATES && !seen.contains(&claim) {
                seen.push(claim);
            }
        }
    }
}

/// Note what `block` states, if anything is being waited for.
pub fn note_block(block: &crate::block::Block) {
    if !waiting() {
        return;
    }
    let Some(rows) = block.note_transition.as_ref().and_then(crate::member_transition::stated_spend_rows) else {
        return;
    };
    note_rows(rows.into_iter().map(|r| (r.nullifier, r.tag1)));
}

/// The tags seen so far beside these spent tags, as `(spent tag, tag beside it)`.
#[must_use]
pub fn found(spent_tags: &[[u8; 32]]) -> Vec<([u8; 32], [u8; 32])> {
    let t = table();
    spent_tags.iter().flat_map(|tag| t.get(tag).into_iter().flatten().map(|claim| (*tag, *claim))).collect()
}

/// Stop watching these (the wallet has the key, or the purchase is over).
pub fn forget(spent_tags: &[[u8; 32]]) {
    let mut t = table();
    for tag in spent_tags {
        t.remove(tag);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TWO-PARTY-REVIEWED: this is the table's own behaviour. That a claim tag laid by a seller's wallet through one
    /// node is read by the buyer's wallet from another is the real-node row `download`.
    #[test]
    fn a_watched_spent_tag_is_answered_by_the_rows_that_lay_it() {
        let (a, b, c) = ([0xA1u8; 32], [0xB2u8; 32], [0xC3u8; 32]);
        forget(&[a, b, c]);
        assert_eq!(add(&[a, b]), vec![a, b]);
        assert!(add(&[a]).is_empty(), "a tag already watched is not fresh");
        assert!(waiting());
        note_rows([(c, [1u8; 32]), (a, [7u8; 32])].into_iter());
        assert_eq!(found(&[a, b, c]), vec![(a, [7u8; 32])], "only the watched tag that was laid is answered");
        // the same row again adds nothing; a different tag beside the same spent tag is a second candidate, up to the bound
        note_rows([(a, [7u8; 32]), (a, [9u8; 32])].into_iter());
        assert_eq!(found(&[a]), vec![(a, [7u8; 32]), (a, [9u8; 32])]);
        note_rows((10u8..20).map(|i| (a, [i; 32])));
        assert_eq!(found(&[a]).len(), CANDIDATES);
        forget(&[a, b]);
        assert!(found(&[a, b]).is_empty());
    }
}
