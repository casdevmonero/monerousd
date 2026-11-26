// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ PRIVATE SHARDING (docs/PRIVATE-NULLIFIER-SHARDING-SPEC-20261106.md §2.2, §8): the one rule that decides whether a tag a
//! block retires was already spent, on a node holding that tag's shard or not.
//!
//! BORROWED: Zcash's nullifier set, Utreexo's proof carried with the spend, Kaspa's canonical order.
//!
//! A block carries, per retired tag, a copath showing the tag absent at the band root of a named past fold step. Every node
//! decides from the block's bytes, its band's roots and the steps' admitted tags, so a holder and a non-holder cannot differ.
//! The step's age is judged by fold ordinal, never by what a node happens to hold.
//!
//! §9.6 (the new door): (1) proof of work: the carrying block's own, checked before this runs. (2) the object's own proof: the
//! copath folded to the step's root here. (3) value: this only refuses; a tag read `Spent` or `Invalid` costs its item its
//! outputs. (4) replay: refused by the admitted tags after the step, and by the root the copath must reach. (5) work: at most
//! one depth of folds per tag, for a fixed tag count per block. (6) parity: the pool door reads this same function.
//!
//! DIGITAL-CASH-PRIVACY-REVIEWED: a tag and a copath the block publishes anyway; nothing here is asked of a holder by a wallet.

use crate::nf_sparse::{copath_proves_absent, CompressedCopath};
use crate::spend_frontier::Digest4;

/// How many fold steps back a copath's root may stand. A protocol constant: judged by ordinal, so it is the same on every node.
/// At least the band's whole lag (the fold waits at `SPINE_RING_LEN` steps, DB-396), or a slow band would make honest spends lose.
pub const EVIDENCE_WINDOW_STEPS: u64 = 64;

/// Proof that a tag was absent at the band root of fold step `ordinal`. Bound into the carrying block's id.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TagEvidence {
    pub ordinal: u64,
    pub copath: CompressedCopath,
}

/// The evidence list a block carries, index-aligned with its padded tags, `None` where it has none (spec §9). A list that does not
/// decode reads as empty, so every tag in it reads `Invalid`: the block still folds, and its spends lose.
/// ROOT-LAYER: the one place the header-bound bytes become evidence, so every node reads a malformed list the same way.
/// MEASURED: the tamper tests in this module; on real nodes, double spends refused 3 of 3 with every row judged from this list.
/// MUST-STAY-GREEN: this module's tests, `scratchpad/net/double_spend.py`.
#[must_use]
pub fn decode_list(bytes: &[u8]) -> Vec<Option<TagEvidence>> {
    match postcard::from_bytes(bytes) {
        Ok(list) => list,
        Err(_) => Vec::new(), // an unreadable list holds no evidence: its rows lose, the same on every node
    }
}

/// ⭐ A-F114 2c — the constant chain's evidence for one REAL spend tag: the spend wrapper (`usdm_agg::absence_ssa::SpendProof`)
/// and the chain end it was built to. Index-aligned with the block's padded tags in the same header-bound `tag_evidence`
/// bytes (`tag_evidence_root`), in this encoding from the network upgrade that switches `canon_chain::CANON_LIVE` on.
/// O1-FOOTPRINT-REVIEWED: per-block bytes (one wrapper per real input, a fixed lane width), never a node store.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CanonTagEvidence {
    pub end: Digest4,
    pub wrapper: Vec<u8>,
}

/// The constant chain's evidence list; a list that does not decode reads as empty, so its real spends lose, the same on
/// every node.
#[must_use]
pub fn decode_canon_list(bytes: &[u8]) -> Vec<Option<CanonTagEvidence>> {
    postcard::from_bytes(bytes).unwrap_or_default()
}

/// A node's ask to its peers about the set: tags that are in a pool or a block already, so a holder learns nothing a block will not
/// publish. Never sent by a wallet. (§9.6: answering creates no value and moves no state; the asker checks every answer.)
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum NfAsk {
    /// Evidence for tags a carrier does not hold.
    Evidence(Vec<[u8; 32]>),
    /// One page of a shard's spent tags, for a node taking that shard. The tags are public: every one was in a block.
    ShardPage { shard: u32, after: Option<[u8; 32]> },
    /// A band-step prover's ask of one shard's copaths at the band root `pre`.
    Serve { pre: Digest4, block: [u8; 32], shard: u32, tags: Vec<[u8; 32]> },
}

/// A holder's answer.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum NfAnswer {
    Evidence(Vec<([u8; 32], TagEvidence)>),
    /// A page of a shard's tags; `done` when this was the last.
    ShardPage { shard: u32, tags: Vec<[u8; 32]>, done: bool },
    /// The shard's entry after its tags, and each tag's lower copath, kept compact as `(position, value)` of the non-zero slots.
    Serve { block: [u8; 32], shard: u32, entry: Digest4, lows: Vec<([u8; 32], u16, Vec<(u16, Digest4)>)> },
}

/// A lower copath with its zero slots dropped: most of a sparse path is the constant.
#[must_use]
pub fn compact_low(low: &[Digest4]) -> (u16, Vec<(u16, Digest4)>) {
    let zero = Digest4::default();
    (low.len() as u16, low.iter().enumerate().filter(|(_, d)| **d != zero).map(|(i, d)| (i as u16, *d)).collect())
}

/// The inverse of [`compact_low`]. `None` for a position past the length.
#[must_use]
pub fn expand_low(len: u16, slots: &[(u16, Digest4)]) -> Option<Vec<Digest4>> {
    let mut low = vec![Digest4::default(); usize::from(len)];
    for (i, d) in slots {
        *low.get_mut(usize::from(*i))? = *d;
    }
    Some(low)
}

/// What one tag's evidence says at a block's fold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TagVerdict {
    /// Absent at the step and in every step after it: this spend may stand.
    Unspent,
    /// Admitted by a step after the evidence's: already spent.
    Spent,
    /// Missing, too old, not before this fold, or it folds to no root. The item loses and its block still folds.
    Invalid,
    /// This node's band has not reached a step the rule reads. It waits and never guesses.
    Wait,
}

/// Decide one tag at the fold of the step `fold_ordinal`.
/// `root_at`: the band root after a step, `None` when this node's band has not reached it.
/// `admitted_after`: is the tag admitted by a step after `ordinal` and before this fold, `None` when a step is unknown here.
pub fn judge_tag(
    tag: &[u8; 32],
    evidence: Option<&TagEvidence>,
    fold_ordinal: u64,
    root_at: impl Fn(u64) -> Option<Digest4>,
    admitted_after: impl Fn(u64, &[u8; 32]) -> Option<bool>,
) -> TagVerdict {
    let Some(e) = evidence else {
        return TagVerdict::Invalid;
    };
    if e.ordinal >= fold_ordinal || fold_ordinal - e.ordinal > EVIDENCE_WINDOW_STEPS {
        return TagVerdict::Invalid;
    }
    let Some(root) = root_at(e.ordinal) else {
        return TagVerdict::Wait;
    };
    if !copath_proves_absent(&root, tag, &e.copath) {
        return TagVerdict::Invalid;
    }
    match admitted_after(e.ordinal, tag) {
        Some(true) => TagVerdict::Spent,
        Some(false) => TagVerdict::Unspent,
        None => TagVerdict::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nf_sparse::{compress_copath, RefSparseNf};

    fn tag(i: u64) -> [u8; 32] {
        let mut t = *blake3::hash(&i.to_le_bytes()).as_bytes();
        t[31] = 0; // a tag is a digest's bytes: its top byte is always zero
        t
    }

    /// A chain of two steps: step 10 spends tags 0..40, step 11 spends `later`.
    fn chain(later: &[[u8; 32]]) -> (RefSparseNf, Digest4, Digest4) {
        let mut t = RefSparseNf::new();
        for i in 0..40 {
            t.insert_and_witness(&tag(i));
        }
        let r10 = t.root();
        for x in later {
            t.insert_and_witness(x);
        }
        let r11 = t.root();
        (t, r10, r11)
    }

    fn roots(r10: Digest4, r11: Digest4) -> impl Fn(u64) -> Option<Digest4> {
        move |o| match o {
            10 => Some(r10),
            11 => Some(r11),
            _ => None,
        }
    }

    #[test]
    fn a_fresh_tag_with_true_evidence_is_unspent_on_a_node_holding_no_set_at_all() {
        let fresh = tag(1000);
        let (t, r10, r11) = chain(&[]);
        let e = TagEvidence { ordinal: 10, copath: compress_copath(&t.copath(&fresh)) };
        // this door is handed only roots and admitted tags: there is no set here to read
        assert_eq!(judge_tag(&fresh, Some(&e), 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Unspent);
    }

    #[test]
    fn a_spent_tag_is_refused_however_old_its_true_copath_is() {
        let spent_later = tag(1000);
        let (before, _, _) = chain(&[]);
        let stale = compress_copath(&before.copath(&spent_later)); // true when made, before the spend
        let (_, r10, r11) = chain(&[spent_later]);
        let e = TagEvidence { ordinal: 10, copath: stale };
        let admitted = |o: u64, t: &[u8; 32]| Some(o < 11 && *t == spent_later);
        assert_eq!(judge_tag(&spent_later, Some(&e), 12, roots(r10, r11), admitted), TagVerdict::Spent);
    }

    #[test]
    fn a_tag_already_in_the_set_at_the_named_step_has_no_evidence_that_folds() {
        let spent = tag(3);
        let (t, r10, r11) = chain(&[]);
        let e = TagEvidence { ordinal: 10, copath: compress_copath(&t.copath(&spent)) };
        assert_eq!(judge_tag(&spent, Some(&e), 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
    }

    #[test]
    fn a_forged_copath_and_another_tags_copath_are_invalid() {
        let fresh = tag(1000);
        let (t, r10, r11) = chain(&[]);
        let mut forged = compress_copath(&t.copath(&fresh));
        assert!(!forged.siblings.is_empty(), "CALIBRATION: a set of 40 gives a copath with siblings to forge");
        forged.siblings[0][0] = forged.siblings[0][0].wrapping_add(1);
        let e = TagEvidence { ordinal: 10, copath: forged };
        assert_eq!(judge_tag(&fresh, Some(&e), 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
        let other = TagEvidence { ordinal: 10, copath: compress_copath(&t.copath(&tag(2000))) };
        assert_eq!(judge_tag(&fresh, Some(&other), 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
    }

    #[test]
    fn no_evidence_too_old_or_not_before_this_fold_is_invalid_by_ordinal_alone() {
        let fresh = tag(1000);
        let (t, r10, r11) = chain(&[]);
        let cp = compress_copath(&t.copath(&fresh));
        assert_eq!(judge_tag(&fresh, None, 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
        let at_fold = TagEvidence { ordinal: 12, copath: cp.clone() };
        assert_eq!(judge_tag(&fresh, Some(&at_fold), 12, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
        // too old even though this node still holds the root: the age is the ordinal's, not the node's
        let old = TagEvidence { ordinal: 10, copath: cp };
        let far = 10 + EVIDENCE_WINDOW_STEPS + 1;
        assert_eq!(judge_tag(&fresh, Some(&old), far, roots(r10, r11), |_, _| Some(false)), TagVerdict::Invalid);
    }

    #[test]
    fn a_node_whose_band_is_behind_waits_and_never_guesses() {
        let fresh = tag(1000);
        let (t, _, _) = chain(&[]);
        let e = TagEvidence { ordinal: 10, copath: compress_copath(&t.copath(&fresh)) };
        assert_eq!(judge_tag(&fresh, Some(&e), 12, |_| None, |_, _| Some(false)), TagVerdict::Wait);
        let (_, r10, r11) = chain(&[]);
        assert_eq!(judge_tag(&fresh, Some(&e), 12, roots(r10, r11), |_, _| None), TagVerdict::Wait);
    }
}
