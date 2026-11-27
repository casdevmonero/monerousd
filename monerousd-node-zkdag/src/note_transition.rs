// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ §BA/§BB — THE BLOCK'S NOTE TRANSITION, AS EVIDENCE A PEER CAN CHECK HOLDING NOTHING.
//!
//! ⛔⛔⛔ THE HOLE. `Node::graft_admitted_notes` is a DENY-list: a note is received unless some RESOLVED
//! transaction refuses it. Under the constant-256 cover a peer holds almost none of a block's bodies, so
//! a note whose transaction the peer never pooled is judged by nothing and applied on the producer's
//! word. Measured: `[§BA] peer RECORDED it=true · peer holds it UNSPENT=true`, and the mirror `[§BB]
//! peer root moved=true` for a burn of a victim's note.
//!
//! §BO traced four local closes and refuted every one. They fail for one reason: **the peer has no O(1)
//! evidence about notes whose bodies it does not hold.** The nullifier transition solved the identical
//! problem with a recursive carrier; the note transition had none.
//!
//! ⭐ THIS IS THAT CARRIER. The block carries ONE proof plus the tuple list it stands over. A peer:
//!   1. recomputes `rows_digest` from the list — the same chain the circuit hashed,
//!   2. verifies the aggregate ONCE against `(n, domain, output_notes_root, <fixed>, rows_digest)`,
//!   3. and then admits an output note only if its commitment is in that list, and a deletion only if
//!      its nullifier is.
//!
//! Step 3 is the ALLOW-list `graft_admitted_notes` could never have: it needs no transaction body, only
//! a list the proof pins. **Every tuple in the list is the public statement of a spend carrier that
//! VERIFIED in-circuit** — that is what the bound aggregate proves, row by row.
//!
//! ⛔ WHAT THIS IS NOT. It does not decide whether a transition HAPPENED — only inclusion in a block
//! does that. It decides whether this node ACCEPTS one, which is exactly the self-verification the
//! trustless cardinal asks for, over a chain object the block carries rather than a local mutation.

use crate::spend_frontier::Digest4;
use usdm_decider::hiding_decider::Fa4;

/// Bytes of one tuple on the wire: `out0_cm ‖ out1_cm ‖ nullifier ‖ leaf_commit ‖ tag1`, each the canonical
/// 32-byte form the node already uses everywhere (`leaf_to_cm_bytes`).
pub const TUPLE_BYTES: usize = 5 * 32;

/// The five digests one spend publishes. ⛔ ONE SPELLING: these are read back through the SAME
/// `cm_bytes_to_root` the submission path uses, so the node cannot hold two ideas of what a tuple is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendTuple {
    pub out0_cm: [u8; 32],
    pub out1_cm: [u8; 32],
    pub nullifier: [u8; 32],
    pub leaf_commit: [u8; 32],
    /// ⭐ DB-329 §7e — the spend's device-slot claim tag, proven by its carrier under the spender's own witness
    /// (`P([SLOT_CLAIM_DOMAIN, d, 0…], key)`; an ordinary send claims `(lc_blind, 0)`). The tx publishes it as
    /// `PqTx::nullifiers[1]` and the spent SET holds it beside the nullifier, so a second claim of one slot is refused
    /// by the set, never by luck. Every tuple reaches the decider's verifier (the door's `carrier_verifies`, the
    /// template's, the aggregate's rows), and that verifier refuses an all-zero tag at its own entry — the absent-field
    /// default is refused structurally, never by call order.
    pub tag1: [u8; 32],
}

impl SpendTuple {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.out0_cm);
        out.extend_from_slice(&self.out1_cm);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.leaf_commit);
        out.extend_from_slice(&self.tag1);
    }
    fn read(b: &[u8]) -> Option<Self> {
        if b.len() != TUPLE_BYTES {
            return None;
        }
        let g = |i: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b[i * 32..(i + 1) * 32]);
            a
        };
        Some(Self { out0_cm: g(0), out1_cm: g(1), nullifier: g(2), leaf_commit: g(3), tag1: g(4) })
    }
    /// The PUBLIC BIND this spend's carrier was proved over — the same call the submission path makes,
    /// so the bind the aggregate ties to is the bind the transcript absorbed. `d` is the spend's filing digest
    /// (DB-351, [`spend_filing_d`]), bound LAST.
    fn public_bind(&self, d: &Digest4) -> Option<Vec<Fa4>> {
        self.public_bind_at(d, 0)
    }
    /// [`Self::public_bind`] for a spend proven against the chain clock `clock_ms` (`PqTx::clock_ms`, goods spec §9.1):
    /// the clock rides the bind's seventh digest, which is never published. Clock 0 is the bind of the old entry points.
    fn public_bind_at(&self, d: &Digest4, clock_ms: u64) -> Option<Vec<Fa4>> {
        let f = |d: Digest4| -> [Fa4; usdm_decider::poseidon2_compress::DIGEST_LANES] {
            core::array::from_fn(|i| Fa4::new(d[i] as u32))
        };
        let c0 = crate::spend_frontier::cm_bytes_to_root(&self.out0_cm)?;
        let c1 = crate::spend_frontier::cm_bytes_to_root(&self.out1_cm)?;
        let nf = crate::spend_frontier::cm_bytes_to_root(&self.nullifier)?;
        let lc = crate::spend_frontier::cm_bytes_to_root(&self.leaf_commit)?;
        let t1 = crate::spend_frontier::cm_bytes_to_root(&self.tag1)?;
        // No root in the bind (2026-09-30: the carrier takes none — membership is the note-membership carrier's,
        // cross-bound by the blinded `leaf_commit`; the Merkle root it once discarded is gone with gate D).
        // the carrier binds its clock as a count of chain hours ([`clock_hours`]); a clock off the grid states none
        let clock_h = clock_hours(clock_ms)?;
        Some(usdm_decider::whir_rec_block::note_spend_public_bind(&[f(c0), f(c1)], &f(nf), &f(lc), &f(*d), &f(t1), clock_h))
    }
}

/// ⭐ THE SPEND CLOCK'S GRID (goods spec §9.1): one chain hour. Every clock a transaction states is a multiple of it, so
/// all the spends made in one chain hour state one value.
pub const SPEND_CLOCK_GRID_MS: u64 = usdm_decider::whir_rec_block::CHAIN_HOUR_MS;

/// A clock on the grid as the count of chain hours a carrier and a ledger bind. `None` off the grid, or past the range
/// an hour count holds (2^22 hours): no carrier and no ledger states such a clock.
#[must_use]
pub fn clock_hours(clock_ms: u64) -> Option<u64> {
    if clock_ms % SPEND_CLOCK_GRID_MS != 0 {
        return None;
    }
    usdm_decider::whir_rec_block::chain_hours(clock_ms)
}
/// How far behind the chain clock a PRODUCER sets its block's ledger clock: a sixth of the grid. The ledger is proven
/// before the block's parents are final, and the fold requires the ledger clock to be at or before the selected
/// parent's median-time-past; ten minutes is twenty times the header drift bound (`max_ts_drift_ms`, 30 s), so a
/// reorg between proof start and proof finish does not cost the block.
pub const LEDGER_CLOCK_MARGIN_MS: u64 = SPEND_CLOCK_GRID_MS / 6;
/// How far behind the chain clock a WALLET sets its spend's clock: a third of the grid, so a spend's clock is at or
/// before every honest producer's ledger clock the moment it is made, and the spend is includable in the next block.
pub const WALLET_CLOCK_MARGIN_MS: u64 = SPEND_CLOCK_GRID_MS / 3;

/// `ms` rounded down to the spend clock's grid.
#[must_use]
pub const fn spend_clock_floor(ms: u64) -> u64 {
    ms - ms % SPEND_CLOCK_GRID_MS
}

/// The ledger clock a producer lays at chain time `chain_time_ms`.
#[must_use]
pub const fn ledger_clock_at(chain_time_ms: u64) -> u64 {
    spend_clock_floor(chain_time_ms.saturating_sub(LEDGER_CLOCK_MARGIN_MS))
}

/// The clock a wallet proves a spend against at chain time `chain_time_ms`: the ONE value every wallet states in that
/// stretch of the chain hour, so the field tells a relay nothing about the spend.
#[must_use]
pub const fn wallet_spend_clock(chain_time_ms: u64) -> u64 {
    spend_clock_floor(chain_time_ms.saturating_sub(WALLET_CLOCK_MARGIN_MS))
}

/// THE POOL DOOR'S CLOCK RULE: a spend's clock is on the grid and the chain has reached it (a ledger laid now could
/// state it). `false` is "not now", never "never": the same transaction is admitted once the chain clock passes.
#[must_use]
pub const fn spend_clock_admissible(clock_ms: u64, chain_time_ms: u64) -> bool {
    clock_ms % SPEND_CLOCK_GRID_MS == 0 && clock_ms <= ledger_clock_at(chain_time_ms)
}

#[cfg(test)]
mod spend_clock_tests {
    use super::*;

    const MINUTE: u64 = 60_000;
    /// A chain time well past zero that is not on the grid.
    const T0: u64 = 1_800_000_000_000 + 7 * MINUTE + 13;

    #[test]
    fn a_clock_is_a_whole_number_of_chain_hours_or_it_is_no_clock() {
        assert_eq!(clock_hours(0), Some(0));
        assert_eq!(clock_hours(5 * SPEND_CLOCK_GRID_MS), Some(5));
        for off in [1, MINUTE, SPEND_CLOCK_GRID_MS - 1] {
            assert_eq!(clock_hours(5 * SPEND_CLOCK_GRID_MS + off), None, "an off-grid clock was read as hours");
        }
        // past the range an hour count holds (2^22 hours): no carrier and no ledger can state it
        assert_eq!(clock_hours(SPEND_CLOCK_GRID_MS << 22), None);
        assert_eq!(clock_hours((SPEND_CLOCK_GRID_MS << 22) - SPEND_CLOCK_GRID_MS), Some((1 << 22) - 1));
    }

    #[test]
    fn every_wallets_clock_is_at_or_before_every_producers_ledger_clock_from_that_moment_on() {
        // across two whole chain hours, minute by minute: the spend a wallet makes at t is statable by a ledger laid at
        // t and at any later moment, so it is includable in the next block and never has to be re-proved
        for step in 0..=120 {
            let t = T0 + step * MINUTE;
            let spend = wallet_spend_clock(t);
            assert_eq!(spend % SPEND_CLOCK_GRID_MS, 0);
            assert!(spend <= t, "a wallet stated a clock the chain has not reached");
            for later in [0, 1, MINUTE, 9 * MINUTE, 61 * MINUTE, 500 * MINUTE] {
                assert!(spend <= ledger_clock_at(t + later), "a wallet's clock ran ahead of a ledger laid {later} ms later");
                assert!(spend_clock_admissible(spend, t + later), "the pool door refused a clock a wallet just stated");
            }
        }
    }

    #[test]
    fn the_pool_door_refuses_a_clock_the_chain_has_not_reached_and_admits_it_once_it_has() {
        let reached = ledger_clock_at(T0);
        let next = reached + SPEND_CLOCK_GRID_MS;
        assert!(spend_clock_admissible(reached, T0));
        assert!(!spend_clock_admissible(next, T0), "a spend was admitted under a clock ahead of the chain");
        assert!(!spend_clock_admissible(next, next), "a clock is not reached at its own instant: the ledger runs a margin behind");
        assert!(!spend_clock_admissible(next, next + LEDGER_CLOCK_MARGIN_MS - 1));
        assert!(spend_clock_admissible(next, next + LEDGER_CLOCK_MARGIN_MS), "\"not now\" must become \"now\": the same clock is admitted once reached");
        for off in [1, MINUTE] {
            assert!(!spend_clock_admissible(reached + off, T0 + 10 * SPEND_CLOCK_GRID_MS), "an off-grid clock was admitted");
        }
        // a young chain: every clock function is zero and nothing underflows
        assert_eq!((ledger_clock_at(0), wallet_spend_clock(0), ledger_clock_at(MINUTE), wallet_spend_clock(MINUTE)), (0, 0, 0, 0));
        assert!(spend_clock_admissible(0, 0));
    }
}

/// ⭐⭐⭐ DB-351 — THE FILED LOCATOR TAGS A BLOCK CARRIES (`Block::oli_tags`: `cm ‖ k`, repeated), as a lookup.
///
/// Every spend's carrier binds its filing digest D over `(cm, k)` of its outputs (`oli::filing_d_bytes_from_keys`),
/// so a peer recomputes D from exactly the tags the block files. `None` when the bytes are not whole records, or name
/// one commitment twice: an ambiguous filing states no D, and the transition refuses rather than choosing one.
/// O1-FOOTPRINT-REVIEWED: bounded by one block's real notes (the tags are per real note); built and dropped per call.
#[must_use]
/// ⭐ THE ONE IDENTITY A NOTE IS FILED UNDER — the byte form of its ledger leaf (`note_leaf_of`: a canonical commitment
/// parses to itself; any other 32-byte form is hashed to a leaf). The ledger (`block_ledger_inputs`, `uniform_ledger_filing`)
/// names every note this way, so every reader that pairs a carried tag with a note must too, or the two readers of one
/// record disagree about which note a tag names. MEASURED 2026-10-27 (scratchpad/funds/nodepins-2.log, `[db223-q2-diag]`):
/// a credit note whose commitment bytes were not canonical was filed by the ledger under its leaf form while
/// `file_tags_at_fixed_slots` matched the raw bytes — the uniform filing dropped the owner's clue key for the cover key
/// and the fixed-slot filing then matched nothing, so the owner could never locate the note (three pins red since the
/// ledger landed, 2026-10-24..26). One function, read at every pairing site; cons: one parse per compared commitment.
#[must_use]
pub fn filing_cm(cm: &[u8; 32]) -> [u8; 32] {
    crate::spend_frontier::leaf_to_cm_bytes(crate::spend_frontier::note_leaf_of(cm))
}

/// The carried tag list as a map FILING identity → key (see `filing_cm`); `None` on a malformed list or two tags naming
/// one note.
pub fn filed_keys(oli_tags: &[u8]) -> Option<std::collections::BTreeMap<[u8; 32], [u8; crate::oli::K_BYTES]>> {
    const REC: usize = 32 + crate::oli::K_BYTES;
    if oli_tags.len() % REC != 0 {
        return None;
    }
    let mut out = std::collections::BTreeMap::new();
    for r in oli_tags.chunks_exact(REC) {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&r[..32]);
        let cm = filing_cm(&raw);
        let mut k = [0u8; crate::oli::K_BYTES];
        k.copy_from_slice(&r[32..]);
        if out.insert(cm, k).is_some() {
            return None;
        }
    }
    Some(out)
}

/// ⭐ DB-351 — one spend's filing digest D, as its carrier absorbs it, from a filing lookup (`cm → k`, or absent when
/// the spend files no clue for that output). The ONE derivation the producer, the ingress gate and the graft writer
/// share (the pool door and the wallet reach the same bytes from the clue list, `Node::tx_filing_d`).
#[must_use]
pub fn spend_filing_d(
    t: &SpendTuple,
    k_of: impl Fn(&[u8; 32]) -> Option<[u8; crate::oli::K_BYTES]>,
) -> Option<Digest4> {
    let bytes = crate::oli::filing_d_bytes_from_keys(&[t.out0_cm, t.out1_cm], k_of)?;
    Some(crate::oli::filing_d_digest(&bytes))
}

/// TEST PROVER — a spend proven the way a wallet proves one under DB-351: the two output commitments are known
/// BEFORE proving (`asset_note_cm(value, USDM_ASSET_TAG, sk)`, the formula every note is sealed with, pinned equal to
/// the prover's out_cm by the decider's `asset_zero_cm_matches_the_legacy_usdm_note_cm`), D is the filing digest
/// over them with no clue filed (what a tx with an empty clue list binds), and the carrier is proven under D.
/// Returns `(blob, cms, nf, lc, D)`. ⛔ Panics if the proven commitments differ from the precomputed ones, so a
/// drift between the seal formula and the prover can never pass as a filing mismatch.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn prove_unfiled_spend(
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    prove_filed_spend(w, [None, None])
}

/// [`prove_unfiled_spend`], with a locator key filed for either output (`keys[j]` for output j), as a payer that
/// attaches clues proves it.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn prove_filed_spend(
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    keys: [Option<[u8; crate::oli::K_BYTES]>; 2],
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    use usdm_decider::whir_rec_block::{asset_note_cm, USDM_ASSET_TAG};
    let cms = [
        asset_note_cm(w.out0_value, USDM_ASSET_TAG, w.out0_opening),
        asset_note_cm(w.out1_value, USDM_ASSET_TAG, w.out1_opening),
    ];
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let (c0, c1) = (b(cms[0]), b(cms[1]));
    let k_of = |cm: &[u8; 32]| if *cm == c0 { keys[0] } else if *cm == c1 { keys[1] } else { None };
    let d = crate::oli::filing_d_digest(&crate::oli::filing_d_bytes_from_keys(&[c0, c1], k_of)?);
    let (blob, proven, nf, lc) =
        usdm_decider::whir_rec_block::prove_spend_validity_carrier_with_commit_bytes(w, d)?;
    assert_eq!(proven, cms, "the seal formula and the prover must name the same output commitments");
    Some((blob, proven, nf, lc, d))
}

/// TEST — the wallet's filing for a pooled spend (wallet lib.rs `note_clues_hex`): one locator clue per output, a function
/// of its cm, and the carrier proven under that filing's D. The ONE fixture spelling of a spend a producer can lay on a
/// ledger block (the unfiled-spend law evicts any other). Pair with [`fixture_note_clues`] for `tx.note_clues`.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn prove_wallet_spend(
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    use usdm_decider::whir_rec_block::{asset_note_cm, USDM_ASSET_TAG};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let cms = [
        b(asset_note_cm(w.out0_value, USDM_ASSET_TAG, w.out0_opening)),
        b(asset_note_cm(w.out1_value, USDM_ASSET_TAG, w.out1_opening)),
    ];
    prove_filed_spend(w, cms.map(|cm| Some(crate::oli::index_key(&fixture_clue(&cm)))))
}

#[cfg(test)]
fn fixture_clue(cm: &[u8; 32]) -> Vec<u8> {
    [b"fixture-clue-".as_slice(), cm.as_slice()].concat()
}

/// TEST — the encoded clue list [`prove_wallet_spend`] bound its D over, for its two output commitments.
#[cfg(test)]
pub fn fixture_note_clues(cms: &[Digest4; 2]) -> Vec<u8> {
    let mut records: Vec<([u8; 32], Vec<u8>)> = cms
        .iter()
        .map(|c| {
            let cm = crate::spend_frontier::leaf_to_cm_bytes(*c);
            (cm, fixture_clue(&cm))
        })
        .collect();
    records.sort();
    crate::oli::encode_note_clue_records(&records)
}

/// TEST — a single spend's constant-width tag list as a wallet lays it (DB-329 §7f): the nullifier and the carrier's
/// claim tag (`spend_tag1(w)`) as the two REAL rows, then `TX_FIXED_NULLIFIER_COUNT − 2` pads labelled `{pad}-{row}`. The
/// ONE fixture spelling, so no test hand-builds a list whose row 1 is not the claim its carrier proved.
#[cfg(test)]
pub fn test_spend_tag_list(
    nf: Digest4,
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    pad: &str,
) -> Vec<crate::hash::Hash32> {
    use usdm_decider::nf_sparse_air::TagWitness;
    let Some(leaf) = usdm_decider::whir_rec_block::spend_input_leaf(w) else {
        return test_tag_list(nf, usdm_decider::whir_rec_block::spend_tag1(w), pad);
    };
    let (claim_key, claim_leaf) = usdm_decider::slot_ledger::slot_claim_preimage(w.lc_blind, 0);
    test_tag_list_registered(
        nf,
        usdm_decider::whir_rec_block::spend_tag1(w),
        pad,
        [TagWitness::RealSpend { key: w.owner.nk, leaf }, TagWitness::RealSpend { key: claim_key, leaf: claim_leaf }],
    )
}

/// TEST — [`test_spend_tag_list`] for a CLAIMING send (`claim(key, d)`, DB-329 §7e): the claim row's witness is the claim's
/// own pair (`slot_claim_preimage(key, d)`), the input row's the witness's.
#[cfg(test)]
pub fn test_tag_list_claiming(
    nf: Digest4,
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    key: Digest4,
    d: u64,
    pad: &str,
) -> Vec<crate::hash::Hash32> {
    use usdm_decider::nf_sparse_air::TagWitness;
    let tag1 = usdm_decider::slot_ledger::slot_claim_native(key, d);
    let Some(leaf) = usdm_decider::whir_rec_block::spend_input_leaf(w) else {
        return test_tag_list(nf, tag1, pad);
    };
    let (claim_key, claim_leaf) = usdm_decider::slot_ledger::slot_claim_preimage(key, d);
    test_tag_list_registered(
        nf,
        tag1,
        pad,
        [TagWitness::RealSpend { key: w.owner.nk, leaf }, TagWitness::RealSpend { key: claim_key, leaf: claim_leaf }],
    )
}

#[cfg(test)]
thread_local! {
    /// §18 — the spend-or-decoy carrier a fixture tag list was proven with, keyed by the list's bytes: `grind_tx` attaches it
    /// (`PqTx::spend_or_decoy`), so a raw fixture transaction carries what the wallet carries and the producer states it.
    static TEST_COVER_CARRIERS: std::cell::RefCell<std::collections::HashMap<Vec<[u8; 32]>, Vec<u8>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// The carrier registered for `tags` by [`test_tag_list_registered`], if any.
#[cfg(test)]
pub fn test_cover_carrier_for(tags: &[crate::hash::Hash32]) -> Option<Vec<u8>> {
    let key: Vec<[u8; 32]> = tags.iter().map(|t| *t.as_bytes()).collect();
    TEST_COVER_CARRIERS.with(|m| m.borrow().get(&key).cloned())
}

/// TEST — the wallet's constant-width tag list over `(nf, tag1)` with Poseidon decoys under a secret derived from `pad`, and
/// its spend-or-decoy carrier over the two real rows' witnesses, registered for [`crate::node::tests::grind_tx`]. §18: a
/// stated spend's tails are its own tags, chained by this carrier; a list without one is never stated by a producer.
#[cfg(test)]
pub fn test_tag_list_registered(
    nf: Digest4,
    tag1: Digest4,
    pad: &str,
    reals: [usdm_decider::nf_sparse_air::TagWitness; 2],
) -> Vec<crate::hash::Hash32> {
    use usdm_decider::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, TagWitness};
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let bound = crate::spend_frontier::note_leaf_of(crate::hash::Hash32::hash(pad.as_bytes()).as_bytes());
    let mut tags = vec![nf, tag1];
    tags.extend((2..crate::cover::TX_FIXED_NULLIFIER_COUNT as u64).map(|slot| cover_tag_native(bound, slot)));
    let mut wit: Vec<TagWitness> = reals.to_vec();
    while wit.len() < tags.len() {
        wit.push(TagWitness::Decoy);
    }
    let out: Vec<crate::hash::Hash32> = tags.iter().map(|t| crate::hash::Hash32(b32(*t))).collect();
    if let Some(carrier) = prove_spend_or_decoy_bytes(bound, &tags, &wit) {
        let key: Vec<[u8; 32]> = out.iter().map(|t| *t.as_bytes()).collect();
        TEST_COVER_CARRIERS.with(|m| m.borrow_mut().insert(key, carrier));
    } else {
        eprintln!("[test-tag-list] ⛔ the spend-or-decoy carrier did not prove over this fixture list — the spend will not be stated");
    }
    out
}

/// TEST — a tag list with the claim tag given and NO carrier (Poseidon decoys under `pad`'s secret): for fixtures whose
/// transaction must never be stated by a producer (no witness to prove its rows). Callers that want a stated spend use
/// [`test_spend_tag_list`] or [`test_tag_list_claiming`].
#[cfg(test)]
pub fn test_tag_list(nf: Digest4, tag1: Digest4, pad: &str) -> Vec<crate::hash::Hash32> {
    use usdm_decider::nf_sparse_air::cover_tag_native;
    let b32 = crate::spend_frontier::leaf_to_cm_bytes;
    let bound = crate::spend_frontier::note_leaf_of(crate::hash::Hash32::hash(pad.as_bytes()).as_bytes());
    let mut out = vec![crate::hash::Hash32(b32(nf)), crate::hash::Hash32(b32(tag1))];
    out.extend((2..crate::cover::TX_FIXED_NULLIFIER_COUNT as u64).map(|slot| crate::hash::Hash32(b32(cover_tag_native(bound, slot)))));
    out
}

/// TEST PROVER — [`prove_filed_spend`] for a CLAIMING send: the carrier proves `tag1 = claim(key, d)` (DB-329 §7e), with
/// a locator key filed for either output (`keys[j]` for output j) — the wallet's shape, the only one a ledger block can
/// carry (`uniform_ledger_filing`). Returns `(blob, cms, nf, lc, D, tag1)`.
#[cfg(test)]
#[allow(clippy::type_complexity)]
pub fn prove_filed_claiming_spend(
    w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    key: Digest4,
    d: u64,
    keys: [Option<[u8; crate::oli::K_BYTES]>; 2],
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4, Digest4)> {
    use usdm_decider::whir_rec_block::{asset_note_cm, USDM_ASSET_TAG};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let (c0, c1) = (
        b(asset_note_cm(w.out0_value, USDM_ASSET_TAG, w.out0_opening)),
        b(asset_note_cm(w.out1_value, USDM_ASSET_TAG, w.out1_opening)),
    );
    let k_of = |cm: &[u8; 32]| if *cm == c0 { keys[0] } else if *cm == c1 { keys[1] } else { None };
    let fd = crate::oli::filing_d_digest(&crate::oli::filing_d_bytes_from_keys(&[c0, c1], k_of)?);
    let (blob, cms, nf, lc, tag1) =
        usdm_decider::whir_rec_block::prove_spend_validity_carrier_claiming_bytes(w, fd, key, d)?;
    Some((blob, cms, nf, lc, fd, tag1))
}

/// A bind (minus its domain tag) as the class's row tuple: the bound digests, then zero digests up to the class
/// width (`out0, out1, nf, lc, D, 0, 0, 0`; the decider's padding rule, never published). `None` if it overflows.
fn delta_row(bind: &[Fa4]) -> Option<Vec<Fa4>> {
    let mut v = bind.get(1..)?.to_vec();
    if v.len() > usdm_decider::settlement_delta::DELTA_TUPLE_VALS {
        return None;
    }
    v.resize(usdm_decider::settlement_delta::DELTA_TUPLE_VALS, Fa4::new(0));
    Some(v)
}

/// What a block carries beside its notes: ONE proof, the tuples it stands over, and the shape a peer
/// needs to rebuild the circuit (it holds no carrier, so it cannot derive the shape itself).
///
/// O1-FOOTPRINT-REVIEWED: bounded by `cover::BLOCK_FIXED_TX_COUNT` — `build` refuses more tuples than
/// the block has tx slots, and the proof itself is a CONSTANT size at that slot count (§BW: the
/// committed shape is `DELTA_FIXED_SLOTS`, never a function of how many spends were real).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NoteTransition {
    /// The aggregate proof.
    pub agg: Vec<u8>,
    /// ⭐ padding spec §18 — THE TAG LEDGER's aggregate (`usdm_decider::tag_ledger`): on a ledger block, the proof that every
    /// published tag cell of a stated spend's 16 pair rows is its spend-or-decoy carrier's own tag set, chained in order on a
    /// tied bus. Its published list is DERIVED from this list (`P(tag0 ‖ tag1)` per row) and never travels. Empty on a legacy
    /// (count-stating) transition; a ledger block without a verifying one admits nothing (the door's rule — a tail row is
    /// hidden, so no block may lay one unbound).
    #[serde(default)]
    pub tag_agg: Vec<u8>,
    /// `n × TUPLE_BYTES`, in the block's own spend order.
    pub tuples: Vec<u8>,
    /// The circuit's public shape: `(nvars, per, width, powers, power_lo, seg_log, slots, n, depth)`.
    pub shape: [u32; 8],
    /// ⭐ THE BLOCK'S LEDGER CLOCK, unix ms (goods spec §9.1): the ledger proves every row's spend was proven against a
    /// clock at or before this one, and the fold counts the block's rows only when this value is at or before the
    /// chain clock at the block's selected parent (`Node::ledger_clock_is_reached`). One value per block, the same
    /// for a quiet and a busy block; no row's own clock is published. 0 on a legacy (count-stating) transition, which
    /// can state only spends proven against clock 0. LAST on the wire and `serde(default)`. cons: 8 B per block.
    #[serde(default, with = "postcard::fixint::le")]
    pub clock_ms: u64,
    /// ⭐ §22c — THE COMMITMENT TO THIS BLOCK'S SPEND TRANSACTIONS (`Block::tx_bodies`), keyed under the block's cover key
    /// (`block::tx_bodies_commit`). The transactions ride beside the block; this binds them into its id (the header's
    /// `transitions_root` hashes this struct), so every node that holds the block holds the SAME transactions: a relay
    /// cannot put another valid member leg in a carried transaction's place and split what two nodes decide at the fold.
    /// Keyed, so without the key it is 32 uniform bytes on a quiet and a busy block alike (a plain hash of an empty list
    /// would be a quiet-block oracle). Set by `Block::seal_transitions_root`, the producer's last step before the grind;
    /// checked by `spend_evidence::block_spends_are_evidenced`. cons: 32 B per block.
    #[serde(default)]
    pub bodies: [u8; 32],
}

/// ⭐ 2026-09-30: EIGHT words. The ninth (`depth`) went with gate D — the spend carrier has one constant layout and the
/// block aggregate states no depth. A wire change to every transition's `shape`, bundled into the ONE re-genesis.
pub fn shape_to_wire(s: usdm_decider::settlement_delta::DeltaShape) -> [u32; 8] {
    [
        s.nvars as u32,
        s.per as u32,
        s.width as u32,
        s.powers as u32,
        s.power_lo as u32,
        s.seg_log as u32,
        s.slots as u32,
        s.n as u32,
    ]
}

pub fn shape_from_wire(w: [u32; 8]) -> usdm_decider::settlement_delta::DeltaShape {
    usdm_decider::settlement_delta::DeltaShape {
        nvars: w[0] as usize,
        per: w[1] as usize,
        width: w[2] as usize,
        powers: w[3] as usize,
        power_lo: w[4] as usize,
        seg_log: w[5] as usize,
        slots: w[6] as usize,
        n: w[7] as usize,
    }
}

/// The transition roots this aggregate is pinned to, as field elements. ⛔ A proof that stands over a
/// DIFFERENT delta than the block applies is worthless, so the output root enters the statement. The
/// second root slot bound the deletion set until Z1 (2026-09-22); the deletion tree is gone, so it now
/// binds a fixed domain constant — the statement shape (and the decider) is unchanged.
pub fn roots(output_notes_root: &crate::hash::Hash32) -> (Vec<Fa4>, Vec<Fa4>) {
    let f = |h: &crate::hash::Hash32| -> Vec<Fa4> {
        h.as_bytes().chunks_exact(4).map(|c| Fa4::new(u32::from_le_bytes([c[0], c[1], c[2], c[3]]) >> 1)).collect()
    };
    let no_deletion_set = crate::hash::Hash32::hash(b"MUSD-note-transition-no-deletion-set-z1");
    (f(output_notes_root), f(&no_deletion_set))
}

/// The spend-validity domain tag every carrier's bind opens with.
pub fn domain() -> Fa4 {
    use p3_field::PrimeCharacteristicRing;
    Fa4::from_u64(usdm_decider::whir_rec_block::SPEND_VALIDITY_DOMAIN)
}

/// A block template's aggregate classes — the four transitions a producer lays and a peer verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemplateClass {
    Note,
    Cover,
    Bond,
    Member,
}

/// `(proof bytes, the shape the block publishes, rows_digest)` — what every class's prover returns.
pub type LaidAggregate = (Vec<u8>, usdm_decider::settlement_delta::DeltaShape, Vec<Fa4>);

/// ⛔ TEST BUILDS ONLY — R4: A SIMULATED BLOCK WEIGHS WHAT A REAL BLOCK WEIGHS.
///
/// An armed simulation proves the block ledger with the bound double (`Node::ledger_double`), whose seal is a few KB where
/// the real proof is hundreds of KB. The simulator already charges every page its bytes over the measured Tor rate
/// (`harness::netsim::Physics::TOR_Q13`: 600 ms a leg + 150 B/ms), so every simulated block crossed the wire ~10× lighter
/// than a real one. MEASURED 2026-11-02: the default test node's block is 119,612 B, a node laying its ledger real
/// 1,379,520 B, and on four real T5 pairs blocks from the 34th on were 1.5 MB and the pair ran at ~41 s per block — a
/// relay cost the simulator could not see. So the double's seal travels padded to the real proof's length (each a
/// constant of its shape: `settlement_delta::the_proof_is_byte_identical_however_many_spends_are_real`,
/// `member_transition::the_member_aggregate_is_one_size_whatever_the_real_spend_count`), and the armed door takes the
/// seal back out only from exactly that length with a zero tail. `block_wire_budget_tests::r4_a_real_ledger_block…` holds
/// the constants equal to the real provers' output, so a proof that changes size turns that pin red, never the parity.
/// cons: an armed simulation holds and moves real-size blocks — its RAM and its simulated relay time are what a real
/// node's are (that is the parity being bought).
#[cfg(test)]
pub mod bound_weight {
    /// The real JOINED note + tag + member ledger proof's wire length (`NoteTransition::agg`; `tag_agg` and the member
    /// `agg` travel empty) — R4 lever 4 step C2 (before it: C1's note + tag 681,496 B beside the member's 454,167 B).
    /// MEASURED 2026-11-03 (`block_wire_budget_tests::r4_a_real_ledger_block…`, quiet and busy alike): 944,877 B.
    /// MEASURED 2026-11-10 (lane goods, `r4_a_real_ledger_proves_note_tag_and_member_as_one_batch…`): 911,559 B, up from
    /// 907,783 B. The 3,776 B (+0.42 %) are the spend row's vault region (goods spec §30.1: 47 columns on 2,510), which
    /// every block's ledger proof now carries whether or not a spend uses a vault; stacked arity 23.
    /// MEASURED 2026-11-12/13 (lane speed4, the same pin, on main 7d5e12b2): 662,203 B, down 249,356 B (−27.4 %) — SPEED C2,
    /// a light proof sends only the next-row openings its gates read and the shift bind opens only those
    /// (`air_zerocheck::shifted_set`), and A-F51, a cross-tie endpoint on the public statement sends nothing (−432 B).
    /// MEASURED 2026-11-16 (lane speed5, the same pin, release, the binary of lane commit 52e375f7): 369,545 B laid + proved in
    /// 1,746 ms, down 292,658 B (−44.2 %) — V2: the note statement is the tree ledger (no bound step, no sponge table) and the
    /// joined proof carries no tag statement (the tag rule is read natively at the block door, `spend_evidence`).
    /// 2026-11-16 later (lane speed5): the joined proof is the tree-ledger note statement ALONE (no member statement either):
    /// 154,167 B, the decider pin's MEASURED size of that one constant-shape statement (`tree_ledger_states_the_same_list…`);
    /// the node pin `r4_a_real_ledger_proves…` asserts it on the producer's own proof.
    pub const LEDGER_JOINED: usize = 154_167;
    /// The armed double's tag seal travels in `tag_agg` at its own length-prefixed 32 B…
    pub const TAG_LEDGER: usize = 36;
    /// …and its member seal in the member `agg`, likewise (`MemberTransition::agg`)…
    pub const MEMBER_LEDGER: usize = 36;
    /// …so the note seal is padded to the rest: the double's three fields weigh the real joined proof together.
    pub const NOTE_LEDGER: usize = LEDGER_JOINED.saturating_sub(TAG_LEDGER + MEMBER_LEDGER);

    /// The double's seal, length-prefixed and zero-padded to `real` bytes. `None` when the seal outweighs the real proof
    /// (a double heavier than the proof it stands in for breaks the parity the other way, so it is refused, not truncated).
    pub fn pad(seal: Vec<u8>, real: usize) -> Option<Vec<u8>> {
        if seal.len() + 4 > real {
            return None;
        }
        let mut v = Vec::with_capacity(real);
        v.extend_from_slice(&(seal.len() as u32).to_le_bytes());
        v.extend_from_slice(&seal);
        v.resize(real, 0);
        Some(v)
    }

    /// The seal back out of a padded double: `None` unless the bytes are exactly `real` long, the prefix fits, and every
    /// pad byte is zero.
    pub fn unpad(bytes: &[u8], real: usize) -> Option<&[u8]> {
        if bytes.len() != real || real < 4 {
            return None;
        }
        let n = u32::from_le_bytes(bytes[..4].try_into().ok()?) as usize;
        let seal = bytes.get(4..4 + n)?;
        bytes[4 + n..].iter().all(|&b| b == 0).then_some(seal)
    }
}

impl TemplateClass {
    /// ⭐ THE ONE NODE-SIDE SWITCH between a class's real WHIR aggregate and — on an ARMED test node only — its BOUND
    /// template double (`usdm_decider::settlement_delta::delta_bound`; docs/SIM-SPEED-TEMPLATE-BOUND-DOUBLE-20261022.md),
    /// the band double's shape (`nf_sparse::band_prove_slices`). Every producer site (`build*_with`) proves through it. A
    /// node binary has no bound branch: `bound` is ignored outside test builds.
    pub fn prove(self, carriers: &[(Vec<u8>, Vec<Fa4>)], dom: Fa4, onr: &[Fa4], dsr: &[Fa4], bound: bool) -> Option<LaidAggregate> {
        use usdm_decider::{member_path_gate as m, settlement_delta as s};
        #[cfg(test)]
        {
            if bound {
                return match self {
                    Self::Note => s::prove_block_note_transition_bound(carriers, dom, onr, dsr),
                    Self::Cover => s::prove_block_cover_transition_bound(carriers, dom, onr, dsr),
                    Self::Bond => s::prove_block_bond_transition_bound(carriers, dom, onr, dsr),
                    Self::Member => m::prove_block_member_transition_bound(carriers, dom, onr, dsr),
                };
            }
        }
        let _ = bound;
        match self {
            Self::Note => s::prove_block_note_transition(carriers, dom, onr, dsr),
            Self::Cover => s::prove_block_cover_transition(carriers, dom, onr, dsr),
            Self::Bond => s::prove_block_bond_transition(carriers, dom, onr, dsr),
            Self::Member => m::prove_block_member_transition(carriers, dom, onr, dsr),
        }
    }

    /// [`TemplateClass::prove`]'s twin — every verify site (`verify*_with`) judges through it. An ARMED door verifies the
    /// bound double ONLY (it never falls back to the real verifier, and the real verifier never takes the double's bytes),
    /// so an armed hub never mixes the two forms.
    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        self,
        bytes: &[u8],
        shape: usdm_decider::settlement_delta::DeltaShape,
        dom: Fa4,
        onr: &[Fa4],
        dsr: &[Fa4],
        rows_digest: &[Fa4],
        bound: bool,
    ) -> bool {
        use usdm_decider::{member_path_gate as m, settlement_delta as s};
        #[cfg(test)]
        {
            if bound {
                return match self {
                    Self::Note => s::verify_block_note_transition_bound(bytes, shape, dom, onr, dsr, rows_digest),
                    Self::Cover => s::verify_block_cover_transition_bound(bytes, shape, dom, onr, dsr, rows_digest),
                    Self::Bond => s::verify_block_bond_transition_bound(bytes, shape, dom, onr, dsr, rows_digest),
                    Self::Member => m::verify_block_member_transition_bound(bytes, shape, dom, onr, dsr, rows_digest),
                };
            }
        }
        let _ = bound;
        match self {
            Self::Note => s::verify_block_note_transition(bytes, shape, dom, onr, dsr, rows_digest),
            Self::Cover => s::verify_block_cover_transition(bytes, shape, dom, onr, dsr, rows_digest),
            Self::Bond => s::verify_block_bond_transition(bytes, shape, dom, onr, dsr, rows_digest),
            Self::Member => m::verify_block_member_transition(bytes, shape, dom, onr, dsr, rows_digest),
        }
    }
}

/// DB-72: the blake3 fingerprint (8 hex) of a transition's wire bytes — printed by the producer when it lays one
/// and by a receiver when it refuses one, so a cross-node refusal says whether the SAME bytes were judged.
/// DIGITAL-CASH-PRIVACY-REVIEWED: a hash of a PUBLIC block field the chain already carries; no amount, key or owner.
#[must_use]
pub fn digest_hex(nt: &NoteTransition) -> String {
    let bytes = postcard::to_allocvec(nt).unwrap_or_default();
    blake3::hash(&bytes).to_hex()[..8].to_string()
}

/// Does this spend's validity carrier verify under the tuple it publishes? The ONE spend-carrier verify the template
/// runs (the pool door runs the same decider entry at admission). DB-73 (run 84) used to live here as `carrier_depth`:
/// the wallet proved a send at one Merkle depth and the block aggregate was laid at another, so the template searched
/// the named class depths for the one the carrier verified at. Gate D (that path) is DELETED (2026-09-30: the census
/// found it decorative — its root was read by no law) and the carrier has one constant layout, so there is no depth to
/// find: a carrier verifies under its statement or it is not a spend. Bounded: one WHIR verify (~20 ms) per spend.
/// `d`: the spend's filing digest (DB-351) — the carrier was proved over it and verifies under no other.
#[must_use]
pub fn carrier_verifies(blob: &[u8], t: &SpendTuple, d: Digest4) -> bool {
    carrier_verifies_at(blob, t, d, 0)
}

/// [`carrier_verifies`] for a spend proven against the chain clock `clock_ms` (`PqTx::clock_ms`): the carrier verifies
/// under that clock and no other.
#[must_use]
pub fn carrier_verifies_at(blob: &[u8], t: &SpendTuple, d: Digest4, clock_ms: u64) -> bool {
    let (Some(c0), Some(c1), Some(nf), Some(lc), Some(t1)) = (
        crate::spend_frontier::cm_bytes_to_root(&t.out0_cm),
        crate::spend_frontier::cm_bytes_to_root(&t.out1_cm),
        crate::spend_frontier::cm_bytes_to_root(&t.nullifier),
        crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit),
        crate::spend_frontier::cm_bytes_to_root(&t.tag1),
    ) else {
        return false; // a front, nullifier, cross-bind or claim tag that is not a canonical digest came from no prover
    };
    clock_hours(clock_ms)
        .is_some_and(|h| usdm_decider::verify_note_spend_bytes(blob, c0, c1, nf, lc, d, t1, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, h))
}

/// PRODUCER — lay the note transition for the spends this block selected.
///
/// `spends` is one `(carrier bytes, tuple, D)` per REAL spend, in the block's own order. The carrier is
/// the tx's blob; the tuple is what the submission path already derived to verify it; D is the spend's filing
/// digest (DB-351), which the block's own `oli_tags` must reproduce or no peer verifies the transition. Returns
/// `None` on anything unstateable — a block then carries NO transition rather than a claim nothing backs
/// (§BZ: a forgeable "settlement" that nobody granted on was still a loaded gun).
#[must_use]
pub fn build(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    output_notes_root: &crate::hash::Hash32,
) -> Option<NoteTransition> {
    build_with(spends, output_notes_root, false)
}

/// [`build`] on a producer that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn build_with(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    output_notes_root: &crate::hash::Hash32,
    bound: bool,
) -> Option<NoteTransition> {
    if spends.is_empty() || spends.len() > crate::cover::BLOCK_FIXED_TX_COUNT {
        return None; // fail-closed: no spends is no transition; more than the block has slots is not a block
    }
    let mut carriers: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(spends.len());
    let mut tuples = Vec::with_capacity(spends.len() * TUPLE_BYTES);
    for (blob, t, d) in spends {
        carriers.push((blob.clone(), t.public_bind(d)?));
        t.write(&mut tuples);
    }
    let (onr, dsr) = roots(output_notes_root);
    let (agg, shape, _digest) = TemplateClass::Note.prove(&carriers, domain(), &onr, &dsr, bound)?;
    Some(NoteTransition { agg, tuples, shape: shape_to_wire(shape), tag_agg: Vec::new(), clock_ms: 0, bodies: [0u8; 32] })
}

/// The ALLOW-list a verified transition yields — the thing `graft_admitted_notes` never had.
///
/// O1-FOOTPRINT-REVIEWED: bounded by `cover::BLOCK_FIXED_TX_COUNT` — at most two output commitments and
/// one nullifier per spend, and `verify` refuses a list longer than the block has tx slots. Per-BLOCK
/// and dropped when the block is applied; never accumulated across height.
#[derive(Clone, Debug, Default)]
pub struct Admissible {
    cms: std::collections::BTreeSet<[u8; 32]>,
    nullifiers: std::collections::BTreeSet<[u8; 32]>,
    /// ⭐ DB-313 §3 — `(locked out0_cm, nullifier, W)` per PROVEN bond: what the bond lane may lock and weigh
    /// ([`Admissible::admits_bond`]). A bond's `out0_cm` is NEVER in `cms` — the locked note is not receivable.
    /// O1-FOOTPRINT-REVIEWED: bounded by `cover::BLOCK_FIXED_TX_COUNT` — `verify_bond` refuses a longer list;
    /// per-BLOCK, dropped when the block is applied.
    bonds: Vec<([u8; 32], [u8; 32], u64)>,
}

impl Admissible {
    /// ⭐ FOLD ANOTHER VERIFIED TRANSITION'S ADMISSIONS IN. A block may carry BOTH a single-spend note
    /// transition and a constant-width cover transition; each is verified on its own and admits its own
    /// tags, so the block's allow-list is their union. ⛔ UNION, NEVER INTERSECTION: a note or deletion
    /// justified by EITHER verified statement is justified, and refusing on the other's silence would
    /// refuse what a peer can plainly judge (§BO refuted four local closes of exactly that shape).
    pub fn merge(&mut self, other: Self) {
        self.cms.extend(other.cms);
        self.nullifiers.extend(other.nullifiers);
        self.bonds.extend(other.bonds);
    }
    /// How many output commitments the verified statements admit (a test diagnostic's count; no production reader).
    #[cfg(test)]
    pub fn cms_len(&self) -> usize {
        self.cms.len()
    }
    /// May this output-note commitment be RECEIVED? Only if a verified spend published it.
    #[must_use]
    pub fn admits_note(&self, cm: &[u8; 32]) -> bool {
        self.cms.contains(cm)
    }
    /// May this deletion be applied? Only if a verified spend published that nullifier.
    #[must_use]
    pub fn admits_deletion(&self, nf: &[u8; 32]) -> bool {
        self.nullifiers.contains(nf)
    }
    /// §RF-3 — a held body whose ledger out cells are not its header slots: the block's spends stand (decided on what
    /// travels, the same on every node), its notes are received by none (`member_transition::spends_proven_on_block_with`).
    pub fn refuse_notes(&mut self) {
        self.cms.clear();
    }
    // ⛔ `admits_deletion_of_cm(cm)` is DELETED (DB-363, 2026-09-30). It recomputed a spend's `leaf_commit` from the
    // PUBLIC pair `(cm, nullifier)` — the very computation that let any observer join a spend to the note it consumed.
    // The commitment is now blinded (`P(P(leaf, nf), r)`, `r` the spender's secret), so no node can answer "which
    // commitment does this spend delete" from public data, by design. It had zero production callers.
    #[must_use]
    pub fn note_count(&self) -> usize {
        self.cms.len()
    }
    /// ⭐ DB-313 §3 — MAY THE BOND LANE LOCK THIS NOTE AS THIS WEIGHT? Only if a verified bond transition proved a
    /// carrier welding exactly `(locked_cm, nullifier, weight)` — a moved weight, a swapped note or a nullifier the
    /// aggregate never stated admits nothing.
    #[must_use]
    pub fn admits_bond(&self, locked_cm: &[u8; 32], nullifier: &[u8; 32], weight: u64) -> bool {
        self.bonds.iter().any(|(c, n, w)| c == locked_cm && n == nullifier && *w == weight)
    }
}

/// PEER — verify the block's transition and yield what it admits. Holds NO transaction body.
///
/// ⭐ THE ORDER MATTERS AND IS THE WHOLE POINT: the peer recomputes `rows_digest` FROM THE BLOCK'S OWN
/// LIST, then verifies the aggregate against it. A producer who ships a list that is not the list the
/// proof stands over gets a different digest and the verify refuses — so the list is pinned by the
/// proof rather than taken on the producer's word.
///
/// ⭐⭐⭐ DB-351 — `oli_tags` is the SAME block's filed locator tags. Each tuple's D is recomputed from them
/// ([`spend_filing_d`]), so the block verifies only if it files exactly the `(cm, k)` each payer's carrier bound: a
/// producer or relay that strips, rewrites or adds a spend output's tag has a transition no peer verifies.
#[must_use]
/// ⭐ DB-223 Q7 — the spend tuples a note transition states, in its own order (the order its member transition must
/// cover, tuple for tuple). `None` for a list that is not whole tuples. The ONE reader of the list outside [`verify`].
#[must_use]
pub fn spend_tuples(nt: &NoteTransition) -> Option<Vec<SpendTuple>> {
    if nt.tuples.is_empty() || nt.tuples.len() % TUPLE_BYTES != 0 {
        return None;
    }
    nt.tuples.chunks_exact(TUPLE_BYTES).map(SpendTuple::read).collect()
}

pub fn verify(nt: &NoteTransition, output_notes_root: &crate::hash::Hash32, oli_tags: &[u8]) -> Option<Admissible> {
    verify_with(nt, output_notes_root, oli_tags, false)
}

/// [`verify`] on a door that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn verify_with(nt: &NoteTransition, output_notes_root: &crate::hash::Hash32, oli_tags: &[u8], bound: bool) -> Option<Admissible> {
    let shape = shape_from_wire(nt.shape);
    if nt.tuples.len() != shape.n * TUPLE_BYTES
        || shape.n == 0
        || shape.n > crate::cover::BLOCK_FIXED_TX_COUNT
    {
        return None; // fail-closed: the list must be exactly the `n` the statement declares
    }
    let parsed: Vec<SpendTuple> = nt
        .tuples
        .chunks_exact(TUPLE_BYTES)
        .map(SpendTuple::read)
        .collect::<Option<Vec<_>>>()?;
    // ⭐ the verified-transition cache (`crate::verify_cache`): a TRUE verdict for these exact bytes is neither re-derived
    // (binds, rows digest) nor re-proved.
    let key = crate::verify_cache::key_on_door(
        crate::verify_cache::Verifier::NoteTransition,
        nt.shape,
        &[nt.agg.as_slice(), nt.tuples.as_slice(), output_notes_root.as_bytes().as_slice(), oli_tags],
        bound,
    );
    if !crate::verify_cache::verified(key, || {
        let proven = || -> Option<bool> {
            let filed = filed_keys(oli_tags)?;
            let binds: Vec<Vec<Fa4>> = parsed
                .iter()
                .map(|t| t.public_bind(&spend_filing_d(t, |cm| filed.get(cm).copied())?))
                .collect::<Option<Vec<_>>>()?;
            // The tuple the CHAIN hashes is the bind minus its domain tag — the five digests, padded to the class width.
            let tuple_vals: Vec<Vec<Fa4>> = binds.iter().map(|b| delta_row(b)).collect::<Option<Vec<_>>>()?;
            // The width is the CLASS's, named here rather than assumed: this transition states SINGLE-spend
            // carriers, so its rows are that class's tuple. A spend-or-decoy transition names its own.
            let digest = usdm_decider::settlement_delta::rows_digest_of(
                &tuple_vals,
                shape.slots,
                usdm_decider::settlement_delta::DELTA_TUPLE_VALS,
            )?;
            let (onr, dsr) = roots(output_notes_root);
            Some(TemplateClass::Note.verify(&nt.agg, shape, domain(), &onr, &dsr, &digest, bound))
        };
        proven().unwrap_or(false)
    }) {
        return None;
    }
    #[cfg(test)]
    crate::test_census::vacuity::record("note_transition::verify", false);
    let mut a = Admissible::default();
    for t in &parsed {
        a.cms.insert(t.out0_cm);
        a.cms.insert(t.out1_cm);
        a.nullifiers.insert(t.nullifier);
        // DB-329 §7e: the proven claim tag enters the spent SET beside the nullifier — the set arbitrates a slot
        a.nullifiers.insert(t.tag1);
    }
    Some(a)
}

/// ⭐⭐⭐ WHAT A BLOCK CARRIES FOR A CONSTANT-WIDTH SPEND — the half DB-83 was missing.
///
/// A `NoteTransition` states SINGLE-input spends: one nullifier per carrier. A transaction spending
/// k > 1 real notes had its other k-1 real tags go UNSTATED — they never entered the allow-list, their
/// deletions were refused, and those notes stayed spendable. The submit door refuses multi-input spends
/// (`MULTI_INPUT_NOT_STATEABLE_YET`) precisely to keep that from happening, which is a correct
/// fail-closed guard and not an oversight.
///
/// This is the object that lets the door stop refusing: ONE proof over every carried tag of every
/// selected transaction, at the protocol's constant width, with the real-input count hidden by a
/// witness selector. A peer judges it against the tag list the block already publishes.
///
/// O1-FOOTPRINT-REVIEWED: bounded by `cover::BLOCK_FIXED_TX_COUNT` transactions times
/// `cover::TX_FIXED_NULLIFIER_COUNT` tags — `build_cover` refuses more, and the proof itself is a
/// CONSTANT size at that slot count (§BW: the committed shape is `DELTA_FIXED_SLOTS`, never a function
/// of how many spends were real).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CoverTransition {
    /// The aggregate proof.
    pub agg: Vec<u8>,
    /// `n × TX_FIXED_NULLIFIER_COUNT × 32` — every carried tag, in the block's own transaction order.
    pub tags: Vec<u8>,
    /// The circuit's public shape: `(nvars, per, width, powers, power_lo, seg_log, slots, n, depth)`.
    pub shape: [u32; 8],
}

/// How many tags one transaction carries — the protocol's constant transaction width.
///
/// ⛔ PARITY, ASSERTED NOT ASSUMED: this is `cover::TX_FIXED_NULLIFIER_COUNT` and the decider's
/// `COVER_TAGS_PER_TUPLE` must be the same number. Two crates cannot hold two ideas of one protocol
/// width — that is the depth-mismatch class (DB-73/74/75) with a different name.
#[must_use]
pub fn cover_tx_width() -> usize {
    debug_assert_eq!(
        crate::cover::TX_FIXED_NULLIFIER_COUNT,
        usdm_decider::settlement_delta::COVER_TAGS_PER_TUPLE,
        "⛔ the node and the decider disagree about the constant transaction width"
    );
    crate::cover::TX_FIXED_NULLIFIER_COUNT
}

/// The tag-set digest of one transaction, as the field values a row's tuple holds — ⛔ the SAME
/// function the circuit chains in `COS_CHAIN`, never a second spelling of it.
fn cover_tuple_of(tags: &[[u8; 32]]) -> Option<Vec<Fa4>> {
    // ⛔ THE INJECTIVE DECODE, matching the submit door — see the measurement there. A tag that is not
    // a canonical digest decodes `None` and the whole transition is refused rather than mis-stated.
    let limbs: Vec<Digest4> = tags
        .iter()
        .map(|t| crate::spend_frontier::cm_bytes_to_root(t))
        .collect::<Option<Vec<_>>>()?;
    let bind = usdm_decider::nf_sparse_air::cover_tag_statement_bind(&limbs);
    if bind.len() != 1 + usdm_decider::settlement_delta::COVER_TUPLE_VALS {
        return None;
    }
    Some(bind[1..].to_vec())
}

/// PRODUCER — lay the spend-or-decoy transition for the constant-width spends this block selected.
///
/// `covers` is one `(carrier bytes, its W tags)` per selected transaction, in the block's own order —
/// exactly what the submission path already verified through `verify_spend_or_decoy_bytes`. Returns
/// `None` on anything unstateable, so a block carries NO cover transition rather than a claim nothing
/// backs (§BZ: a forgeable "settlement" that nobody granted on was still a loaded gun).
#[must_use]
pub fn build_cover(
    covers: &[(Vec<u8>, Vec<[u8; 32]>)],
    output_notes_root: &crate::hash::Hash32,
) -> Option<CoverTransition> {
    build_cover_with(covers, output_notes_root, false)
}

/// [`build_cover`] on a producer that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn build_cover_with(
    covers: &[(Vec<u8>, Vec<[u8; 32]>)],
    output_notes_root: &crate::hash::Hash32,
    bound: bool,
) -> Option<CoverTransition> {
    let w = cover_tx_width();
    if covers.is_empty() || covers.len() > crate::cover::BLOCK_FIXED_TX_COUNT {
        return None; // fail-closed: no spends is no transition; past the block's slots is not a block
    }
    let mut carriers: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(covers.len());
    let mut tags = Vec::with_capacity(covers.len() * w * 32);
    for (blob, ts) in covers {
        if ts.len() != w {
            return None; // fail-closed: a transaction at any other width publishes its real input count
        }
        let limbs: Vec<Digest4> = ts
            .iter()
            .map(|t| crate::spend_frontier::cm_bytes_to_root(t))
            .collect::<Option<Vec<_>>>()?;
        carriers.push((blob.clone(), usdm_decider::nf_sparse_air::cover_tag_statement_bind(&limbs)));
        for t in ts {
            tags.extend_from_slice(t);
        }
    }
    let (onr, dsr) = roots(output_notes_root);
    let (agg, shape, _digest) =
        TemplateClass::Cover.prove(&carriers, usdm_decider::nf_sparse_air::cover_transition_domain(), &onr, &dsr, bound)?;
    Some(CoverTransition { agg, tags, shape: shape_to_wire(shape) })
}

/// PEER — verify a block's spend-or-decoy transition and yield the tags it ADMITS.
///
/// Every input here is PUBLIC: the shape, both transition roots, and the tag list the block carries.
/// The peer recomputes the per-transaction tag-set digest and the block's `rows_digest` itself, so a
/// proof standing over different tags is refused rather than believed.
///
/// ⭐ EVERY carried tag enters the allow-list, real and decoy alike — that is what makes the real-input
/// count unobservable: the nullifier set grows by exactly `W` per transaction whatever `k` was.
#[must_use]
pub fn verify_cover(
    ct: &CoverTransition,
    output_notes_root: &crate::hash::Hash32,
) -> Option<Admissible> {
    verify_cover_with(ct, output_notes_root, false)
}

/// [`verify_cover`] on a door that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn verify_cover_with(
    ct: &CoverTransition,
    output_notes_root: &crate::hash::Hash32,
    bound: bool,
) -> Option<Admissible> {
    let w = cover_tx_width();
    let shape = shape_from_wire(ct.shape);
    if shape.n == 0
        || shape.n > crate::cover::BLOCK_FIXED_TX_COUNT
        || ct.tags.len() != shape.n * w * 32
    {
        return None; // fail-closed: the tag list must be exactly the `n` transactions the statement declares
    }
    let per_tx: Vec<Vec<[u8; 32]>> = ct
        .tags
        .chunks_exact(w * 32)
        .map(|c| {
            c.chunks_exact(32)
                .map(|t| {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(t);
                    a
                })
                .collect()
        })
        .collect();
    // ⭐ the verified-transition cache (`crate::verify_cache`): these exact bytes, once TRUE, are not re-derived or re-proved
    let key = crate::verify_cache::key_on_door(
        crate::verify_cache::Verifier::CoverTransition,
        ct.shape,
        &[ct.agg.as_slice(), ct.tags.as_slice(), output_notes_root.as_bytes().as_slice()],
        bound,
    );
    if !crate::verify_cache::verified(key, || {
        let proven = || -> Option<bool> {
            let tuples: Vec<Vec<Fa4>> = per_tx.iter().map(|ts| cover_tuple_of(ts)).collect::<Option<Vec<_>>>()?;
            let digest = usdm_decider::settlement_delta::rows_digest_of(
                &tuples,
                shape.slots,
                usdm_decider::settlement_delta::COVER_TUPLE_VALS,
            )?;
            let (onr, dsr) = roots(output_notes_root);
            let cover_domain = usdm_decider::nf_sparse_air::cover_transition_domain();
            Some(TemplateClass::Cover.verify(&ct.agg, shape, cover_domain, &onr, &dsr, &digest, bound))
        };
        proven().unwrap_or(false)
    }) {
        return None;
    }
    #[cfg(test)]
    crate::test_census::vacuity::record("note_transition::verify_cover", false);
    let mut a = Admissible::default();
    for ts in &per_tx {
        for t in ts {
            a.nullifiers.insert(*t);
        }
    }
    Some(a)
}

/// ⭐⭐⭐ DB-313 §3 — THE WELDED CLASS: WHAT A BLOCK CARRIES FOR A USDm BOND.
///
/// MEASURED (DB-313 §1; gate Q16 step 10 and every [gatepf]/[gateT1] run since): a USDm bond passed the submit door
/// (`bond_ok`) and was EVICTED at every template — the template's spend check asked only the PLAIN spend verifier, a
/// welded carrier never verifies there, and no block aggregate could state one. The bond never landed, so `unbond` answered
/// `UNBOND_REFUSED` on every run.
///
/// This is the bond's own class (`usdm_decider::settlement_delta::prove_block_bond_transition`): the SAME spend row as
/// a note transition plus the public weld `value(out0) == W`, stated over the tuple `out0_cm ‖ out1_cm ‖ nullifier ‖
/// W ‖ leaf_commit` (the decider pads it to its chain stride). A peer holding no transaction body recomputes the
/// digest from the tuples, verifies once, and then:
///   * admits `out1_cm` (the change) as receivable and the nullifier as a deletion, exactly as for a spend;
///   * NEVER admits `out0_cm` as receivable: it is the LOCKED note, and it rides `Block::bond_set` instead;
///   * yields `(out0_cm, nullifier, W)`, so the bond lane admits a validator's weight only for a statement a carrier
///     proved in circuit ([`Admissible::admits_bond`]).
///
/// It rides `Block::bond_set` (header-bound by `bond_set_root`) as a framed
/// [`crate::chain_object::Class::BondTransition`] object — the lane every bond-direction object already travels — so
/// it cannot be stripped from the block that needs it, and every apply site reads it through the ONE parser
/// (`Node::bond_set_entries`).
pub const BOND_TUPLE_BYTES: usize = BOND_SPEND_BYTES + 8;

/// Bytes of a bond's spend statement: `out0_cm ‖ out1_cm ‖ nullifier ‖ leaf_commit` — the note class's tuple WITHOUT
/// the claim tag (DB-329 §7e: the bond class publishes no claim; its carrier gate is `tag1: None`).
pub const BOND_SPEND_BYTES: usize = 4 * 32;

/// The four digests a bond's welded carrier states. A type of its own, so a bond can never carry a claim-tag field
/// that nothing binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondSpend {
    pub out0_cm: [u8; 32],
    pub out1_cm: [u8; 32],
    pub nullifier: [u8; 32],
    pub leaf_commit: [u8; 32],
}

impl BondSpend {
    pub fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.out0_cm);
        out.extend_from_slice(&self.out1_cm);
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&self.leaf_commit);
    }
    fn read(b: &[u8]) -> Option<Self> {
        if b.len() != BOND_SPEND_BYTES {
            return None;
        }
        let g = |i: usize| -> Option<[u8; 32]> { b.get(i * 32..(i + 1) * 32)?.try_into().ok() };
        Some(Self { out0_cm: g(0)?, out1_cm: g(1)?, nullifier: g(2)?, leaf_commit: g(3)? })
    }
}

/// One PROVEN bond's public statement: the spend statement (`out0_cm` is the LOCKED note, `out1_cm` the change) and
/// the weight W its carrier welded to `value(out0)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BondTuple {
    pub spend: BondSpend,
    pub weight: u64,
}

impl BondTuple {
    fn write(&self, out: &mut Vec<u8>) {
        self.spend.write(out);
        out.extend_from_slice(&self.weight.to_le_bytes());
    }
    fn read(b: &[u8]) -> Option<Self> {
        if b.len() != BOND_TUPLE_BYTES {
            return None;
        }
        let spend = BondSpend::read(&b[..BOND_SPEND_BYTES])?;
        let weight = u64::from_le_bytes(b[BOND_SPEND_BYTES..].try_into().ok()?);
        Some(Self { spend, weight })
    }
    /// The PUBLIC BIND this bond's carrier was proved over, through the decider's OWN bind function — so the tuple
    /// the aggregate ties to is the bind the carrier's transcript absorbed (one spelling, as `SpendTuple::public_bind`).
    fn public_bind(&self) -> Option<Vec<Fa4>> {
        const LANES: usize = usdm_decider::poseidon2_compress::DIGEST_LANES;
        let f = |d: Digest4| -> [Fa4; LANES] { core::array::from_fn(|i| Fa4::new(d[i] as u32)) };
        let t = &self.spend;
        let c0 = crate::spend_frontier::cm_bytes_to_root(&t.out0_cm)?;
        let c1 = crate::spend_frontier::cm_bytes_to_root(&t.out1_cm)?;
        let nf = crate::spend_frontier::cm_bytes_to_root(&t.nullifier)?;
        let lc = crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit)?;
        // No root in the bind, exactly as for a spend: membership rides the note-membership carrier, cross-bound by
        // the blinded `leaf_commit`.
        Some(usdm_decider::whir_rec_block::bond_validity_public_bind_with_commit(&[f(c0), f(c1)], &f(nf), self.weight, &f(lc)))
    }
}

/// The bond lane's aggregate: ONE proof over every bond the block carries, the tuples it stands over, and the class
/// shape (a peer holds no carrier, so it cannot derive the shape itself).
///
/// O1-FOOTPRINT-REVIEWED: bounded by `cover::BLOCK_FIXED_TX_COUNT` — `build_bond` refuses more tuples than the block
/// has tx slots, and the proof is a CONSTANT size at the class's committed slot count (MEASURED 2026-09-28: 416,369 B
/// at `DELTA_FIXED_SLOTS` = 256, 3 real bonds). A BLOCK-lifetime value riding `Block::bond_set`, consumed at graft;
/// never held across height.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BondTransition {
    /// The aggregate proof.
    pub agg: Vec<u8>,
    /// `n × BOND_TUPLE_BYTES`, in the block's own bond order.
    pub tuples: Vec<u8>,
    /// The circuit's public shape, as [`NoteTransition::shape`].
    pub shape: [u32; 8],
}

impl BondTransition {
    /// The ONE encoding of the object the bond lane frames.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Strict decode — full consumption, no tolerated tail (`chain_object::decode_exact`).
    #[must_use]
    pub fn decode(b: &[u8]) -> Option<Self> {
        crate::chain_object::decode_exact(b)
    }
}

/// The welded-carrier domain tag every bond carrier's bind opens with.
fn bond_domain() -> Fa4 {
    use p3_field::PrimeCharacteristicRing;
    Fa4::from_u64(usdm_decider::whir_rec_block::BOND_VALIDITY_DOMAIN)
}

/// DB-313 §3 — does this welded carrier verify at the bond class's ONE depth (R5)? The submit door's own verifier and
/// statement (`bond_ok`), so the template lays only what the door would admit (§9.6 q6, parity).
#[must_use]
pub fn bond_carrier_verifies(blob: &[u8], t: &BondTuple) -> bool {
    let s = &t.spend;
    let (Some(c0), Some(c1), Some(nf), Some(lc)) = (
        crate::spend_frontier::cm_bytes_to_root(&s.out0_cm),
        crate::spend_frontier::cm_bytes_to_root(&s.out1_cm),
        crate::spend_frontier::cm_bytes_to_root(&s.nullifier),
        crate::spend_frontier::cm_bytes_to_root(&s.leaf_commit),
    ) else {
        return false;
    };
    usdm_decider::verify_bond_validity_carrier_with_commit_bytes(blob, c0, c1, nf, t.weight, lc, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

/// PRODUCER — lay the bond transition for the bonds this block selected. `None` on anything unstateable; the caller
/// then lays NONE of those bonds rather than a bond whose weight no proof states (§BZ).
#[must_use]
pub fn build_bond(bonds: &[(Vec<u8>, BondTuple)], output_notes_root: &crate::hash::Hash32) -> Option<BondTransition> {
    build_bond_with(bonds, output_notes_root, false)
}

/// [`build_bond`] on a producer that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn build_bond_with(bonds: &[(Vec<u8>, BondTuple)], output_notes_root: &crate::hash::Hash32, bound: bool) -> Option<BondTransition> {
    if bonds.is_empty() || bonds.len() > crate::cover::BLOCK_FIXED_TX_COUNT {
        return None;
    }
    let mut carriers: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(bonds.len());
    let mut tuples = Vec::with_capacity(bonds.len() * BOND_TUPLE_BYTES);
    for (blob, t) in bonds {
        carriers.push((blob.clone(), t.public_bind()?));
        t.write(&mut tuples);
    }
    let (onr, dsr) = roots(output_notes_root);
    let (agg, shape, _digest) = TemplateClass::Bond.prove(&carriers, bond_domain(), &onr, &dsr, bound)?;
    Some(BondTransition { agg, tuples, shape: shape_to_wire(shape) })
}

/// PEER — verify a block's bond transition and yield what it admits. Holds NO transaction body.
///
/// §9.6 (a new admission door for bond weight; it parallels [`verify`]):
/// 1. PoW: the block's own, checked before any graft reaches this.
/// 2. Proof: the bond class aggregate, verified over the digest recomputed FROM THE BLOCK'S OWN TUPLES.
/// 3. Conservation: out1 and the deletion are admitted exactly as for a spend; out0 is never receivable — the weld
///    binds its value to W, and the lane locks it.
/// 4. Replay: the nullifier is refused by the spent set at fold; a second bond onto one vid by `AlreadyBonded`.
/// 5. Bounded work: one aggregate verify; the tuple list is bounded by `BLOCK_FIXED_TX_COUNT` before it is read.
/// 6. Parity with [`verify`]: the length/`n` bound, the class-fixed shape (plus the ONE depth, R5), the digest
///    recompute and the output-root binding all carry over; what is ADDED is the weld and the locked-note split.
#[must_use]
pub fn verify_bond(bt: &BondTransition, output_notes_root: &crate::hash::Hash32) -> Option<Admissible> {
    verify_bond_with(bt, output_notes_root, false)
}

/// [`verify_bond`] on a door that is ARMED (`bound`, test builds only) or not for the bound template double.
#[must_use]
pub fn verify_bond_with(bt: &BondTransition, output_notes_root: &crate::hash::Hash32, bound: bool) -> Option<Admissible> {
    let shape = shape_from_wire(bt.shape);
    if bt.tuples.len() != shape.n * BOND_TUPLE_BYTES || shape.n == 0 || shape.n > crate::cover::BLOCK_FIXED_TX_COUNT {
        return None; // fail-closed: exactly `n` tuples (R5); the class has one constant layout, so no depth to check
    }
    let parsed: Vec<BondTuple> = bt
        .tuples
        .chunks_exact(BOND_TUPLE_BYTES)
        .map(BondTuple::read)
        .collect::<Option<Vec<_>>>()?;
    // ⭐ the verified-transition cache (`crate::verify_cache`): these exact bytes, once TRUE, are not re-derived or re-proved
    let key = crate::verify_cache::key_on_door(
        crate::verify_cache::Verifier::BondTransition,
        bt.shape,
        &[bt.agg.as_slice(), bt.tuples.as_slice(), output_notes_root.as_bytes().as_slice()],
        bound,
    );
    if !crate::verify_cache::verified(key, || {
        let proven = || -> Option<bool> {
            let binds: Vec<Vec<Fa4>> = parsed.iter().map(BondTuple::public_bind).collect::<Option<Vec<_>>>()?;
            let tuple_vals: Vec<Vec<Fa4>> = binds.iter().map(|b| b[1..].to_vec()).collect();
            let digest = usdm_decider::settlement_delta::rows_digest_of(
                &tuple_vals,
                shape.slots,
                usdm_decider::settlement_delta::BOND_TUPLE_VALS,
            )?;
            let (onr, dsr) = roots(output_notes_root);
            Some(TemplateClass::Bond.verify(&bt.agg, shape, bond_domain(), &onr, &dsr, &digest, bound))
        };
        proven().unwrap_or(false)
    }) {
        return None;
    }
    let mut a = Admissible::default();
    for t in &parsed {
        a.cms.insert(t.spend.out1_cm);
        a.nullifiers.insert(t.spend.nullifier);
        a.bonds.push((t.spend.out0_cm, t.spend.nullifier, t.weight));
    }
    Some(a)
}

/// The bond lane's entry for a laid aggregate — `u32 length ‖ postcard(PqTx)`, the lane's one wire form
/// (`Node::bond_set_entries`), whose blob is the framed object and nothing else.
#[must_use]
pub fn bond_lane_entry(bt: &BondTransition) -> Vec<u8> {
    let blob = crate::chain_object::frame(crate::chain_object::Class::BondTransition, &bt.encode());
    let tx = crate::mempool::PqTx {
        clock_ms: 0,
        id: crate::mempool::PqTx::content_id(&blob),
        weight: blob.len() as u32,
        blob,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        output_notes: Vec::new(),
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(),
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0,
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    let enc = postcard::to_stdvec(&tx).unwrap_or_default();
    let mut out = Vec::with_capacity(4 + enc.len());
    out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
    out.extend_from_slice(&enc);
    out
}

/// Digests one slot-ledger row puts on the wire: the published row less its last digest, which the class pins to zero
/// (`ledger_list_is_canonical`) and so carries no information — 4,096 B a block not relayed.
pub const LEDGER_ROW_WIRE_DIGESTS: usize = usdm_decider::slot_ledger::PUB_DIGESTS - 1;
/// Bytes of one slot-ledger row on the wire: seven canonical 32-byte digests (`leaf_to_cm_bytes`).
pub const LEDGER_ROW_WIRE_BYTES: usize = LEDGER_ROW_WIRE_DIGESTS * 32;
/// Bytes of a block's whole published ledger list: 128 rows × 224 B = 28,672 B, the SAME for a quiet and a busy block.
pub const LEDGER_LIST_WIRE_BYTES: usize = usdm_decider::settlement_delta::LEDGER_ROWS * LEDGER_ROW_WIRE_BYTES;

/// §RF-3 — the ONE wire spelling of a block's published slot-ledger list (NOTE-TRANSITION-TUPLE-PADDING-SPEC §3, §11).
/// Every digest is written by the same `leaf_to_cm_bytes` every note commitment uses (one encoding per consensus
/// object). `None` on a list the class refuses (`ledger_list_is_canonical`: not 128 rows, `tag0` not strictly
/// ascending, a flag outside {0,1}, a nonzero pinned cell), so a producer cannot write what no verifier would read.
#[must_use]
pub fn encode_ledger_published(published: &[usdm_decider::settlement_delta::LedgerPublished]) -> Option<Vec<u8>> {
    if !usdm_decider::settlement_delta::ledger_list_is_canonical(published) {
        return None;
    }
    let mut out = Vec::with_capacity(LEDGER_LIST_WIRE_BYTES);
    for row in published {
        for d in &row[..LEDGER_ROW_WIRE_DIGESTS] {
            out.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(*d));
        }
    }
    Some(out)
}

/// The decode the ledger door reads, the exact inverse of [`encode_ledger_published`].
///
/// NEW-DOOR CHECKLIST (AGENTS.md §9.6) — this is a parse, not a door; the door that admits a block's ledger answers the
/// six. What THIS step owns: (5) the work a hostile input causes is one length compare plus 128 × 7 fixed-size digest
/// reads — no allocation sized by the input; (1)–(4), (6) are refused here only in the sense that a list the class
/// would refuse never decodes: a wrong length, a non-canonical digest (`digest_from_bytes`: bit 255 set or a lane ≥ p),
/// or a non-canonical list. Proof, PoW, replay and value checks belong to the door that calls this.
#[must_use]
pub fn decode_ledger_published(b: &[u8]) -> Option<Vec<usdm_decider::settlement_delta::LedgerPublished>> {
    if b.len() != LEDGER_LIST_WIRE_BYTES {
        return None;
    }
    let mut rows = Vec::with_capacity(usdm_decider::settlement_delta::LEDGER_ROWS);
    for chunk in b.chunks_exact(LEDGER_ROW_WIRE_BYTES) {
        let mut row = [[0u64; usdm_decider::poseidon2_compress::DIGEST_LANES]; usdm_decider::slot_ledger::PUB_DIGESTS];
        for (i, d) in chunk.chunks_exact(32).enumerate() {
            let a: &[u8; 32] = d.try_into().ok()?;
            row[i] = crate::spend_frontier::cm_bytes_to_root(a)?;
        }
        rows.push(row);
    }
    usdm_decider::settlement_delta::ledger_list_is_canonical(&rows).then_some(rows)
}

/// §RF-3 — the public filing function of one published row's two notes over the block's filing lookup: the SAME
/// `oli::filing_d` a spend's carrier bound over its own outputs ([`spend_filing_d`]), applied to every row, so the `D`
/// column follows one public rule on both classes (padding spec v2 §9.1). `None` when the two notes are one commitment.
fn ledger_row_filing_d(
    filed: &std::collections::BTreeMap<[u8; 32], [u8; crate::oli::K_BYTES]>,
    out0: &Digest4,
    out1: &Digest4,
) -> Option<Digest4> {
    let cms = [crate::spend_frontier::leaf_to_cm_bytes(*out0), crate::spend_frontier::leaf_to_cm_bytes(*out1)];
    let bytes = crate::oli::filing_d_bytes_from_keys(&cms, |cm| filed.get(cm).copied())?;
    Some(crate::oli::filing_d_digest(&bytes))
}

/// ⭐ §RF-3 §10 C1 — a cover note's filing key: a PRF of the block's SECRET cover seed (domain-separated from the cover
/// note and tag laws, spec §2.4 C3) and the note's commitment, so a filed cover key is as uniform to a peer as a payer's
/// locator key and no peer can recompute which filings are cover.
fn cover_filing_k(seed: &Digest4, cm: &[u8; 32]) -> [u8; crate::oli::K_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/ledger/cover-filing-k/v1");
    for v in seed {
        h.update(&v.to_le_bytes());
    }
    h.update(cm);
    let mut k = [0u8; crate::oli::K_BYTES];
    h.finalize_xof().fill(&mut k);
    k
}

/// ⭐ §RF-3 §10 C1 — THE UNIFORM FILING (hole H1): a ledger block's `oli_tags` files EVERY published note — each spend
/// output under the key its payer bound, a justified note under its own clue record when the block files one, every
/// other note under [`cover_filing_k`] — and nothing else, in ascending `cm` order. So "is filed" is true of every row on
/// both classes, the record count is the constant `2 · LEDGER_ROWS`, and no record's position names its class. `None`
/// when a spend output is unfiled (its carrier bound D over no key, so no producer can file it without breaking that D:
/// the spend is refused at this block, never the chain) or the block cannot be planned.
/// ROOT-LAYER: the filing is PRODUCED here, beside the plan that produces the cover notes it files; the door
///   (`verify_ledger_with`) only reads it and refuses any other filing (`ledger_filing_is_uniform`).
/// MEASURED: rf3_c1 census RED on 59c4e25 — busy 2 records / quiet 0, "is filed" split OUT0 and OUT1 (spend {true} vs
///   cover {false}), log scratchpad/night/rf3-c1-red.log.
/// MUST-STAY-GREEN: rf3 ledger round-trip + armed pins (every tamper rejects), db351 (non-ledger filing door unchanged).
/// O1-FOOTPRINT-REVIEWED: `2 · LEDGER_ROWS` records, built and dropped per block.
/// cons: `oli_tags` is 2 · 128 · 48 = 12,288 B on every ledger block (today 48 B per filed output); peers file 256
/// locator records per block, the same count quiet or busy.
#[must_use]
pub fn uniform_ledger_filing(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    oli_tags: &[u8],
) -> Option<Vec<u8>> {
    uniform_ledger_filing_with_tails(spends, &[], justified_notes, justified_tags, seed, oli_tags)
}

/// §18 — [`uniform_ledger_filing`] over the plan WITH the stated spends' tail rows ([`spend_tails`]), so the filing's cover
/// notes are the rows' (a tail row's two cover notes sit at slots of their own).
#[must_use]
pub fn uniform_ledger_filing_with_tails(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    tails: &[[Digest4; 2]],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    oli_tags: &[u8],
) -> Option<Vec<u8>> {
    let mut filed = filed_keys(oli_tags)?;
    let notes = std::cell::RefCell::new(Vec::with_capacity(2 * usdm_decider::settlement_delta::LEDGER_ROWS));
    let record = |a: &Digest4, b: &Digest4| {
        notes.borrow_mut().extend([*a, *b]);
        Some(*a) // only the notes are read here; the D the real plan computes comes from the filing this builds
    };
    usdm_decider::settlement_delta::plan_ledger_rows_with_tails(seed, spends.len(), tails, justified_notes, justified_tags, &record)?;
    let mut uniform = std::collections::BTreeMap::new();
    for (_, t, _) in spends {
        for cm in [t.out0_cm, t.out1_cm] {
            uniform.insert(cm, filed.remove(&cm)?); // a spend output files under its payer's bound key, or the spend is out
        }
    }
    for n in notes.into_inner() {
        let cm = crate::spend_frontier::leaf_to_cm_bytes(n);
        let k = match filed.remove(&cm) {
            Some(own) => own, // a justified note's own clue record
            None => cover_filing_k(&seed, &cm),
        };
        uniform.insert(cm, k);
    }
    Some(uniform.iter().flat_map(|(cm, k)| cm.iter().chain(k.iter()).copied()).collect())
}

/// §RF-3 §10 C1 — the door's law for [`uniform_ledger_filing`], read by the producer and the peer alike: `oli_tags`
/// lists records in strictly ascending `cm` order and files exactly the published list's note commitments.
fn ledger_filing_is_uniform(oli_tags: &[u8], published: &[usdm_decider::settlement_delta::LedgerPublished]) -> bool {
    use usdm_decider::slot_ledger::{PUB_OUT0, PUB_OUT1};
    const REC: usize = 32 + crate::oli::K_BYTES;
    if oli_tags.len() % REC != 0 {
        return false;
    }
    let cms: Vec<&[u8]> = oli_tags.chunks_exact(REC).map(|r| &r[..32]).collect();
    if cms.windows(2).any(|w| w[0] >= w[1]) {
        return false;
    }
    let mut published_cms: Vec<[u8; 32]> = published
        .iter()
        .flat_map(|p| [p[PUB_OUT0], p[PUB_OUT1]])
        .map(crate::spend_frontier::leaf_to_cm_bytes)
        .collect();
    published_cms.sort_unstable();
    published_cms.dedup();
    published_cms.len() == cms.len() && published_cms.iter().zip(&cms).all(|(a, b)| a.as_slice() == *b)
}

/// §RF-3 — the ledger class's wire shape: one constant from the class's layout, written by the producer and required by
/// the door, the same for a quiet and a busy block (no word of it moves with the real spend count).
#[must_use]
pub fn ledger_shape_wire() -> Option<[u32; 8]> {
    usdm_decider::settlement_delta::ledger_class_shape().map(shape_to_wire)
}

/// ⭐ §RF-3 PRODUCER — a block's slot ledger (NOTE-TRANSITION-TUPLE-PADDING-SPEC §2–§3): ONE proof over `LEDGER_ROWS`
/// rows, the published list in its one wire spelling (28,672 B), the class's constant shape, and the header seed's
/// commitment the block must carry (`BlockHeader::cover_seed_commit`). `spends` are the block's real spends (each
/// `(carrier, tuple, D)`); a block with none lays its rows on ONE null carrier (`null_spend_carrier`), so a quiet block
/// publishes the same shape as a busy one. `justified_notes` / `justified_tags` are the cells the block's other verified
/// objects state (mint/DEX/credit outputs, their nullifiers). Every row's `D` is the public filing function of its notes
/// over `oli_tags`; a spend whose bound `D` is not that function is refused here, so a producer never lays a ledger
/// the door refuses. `None` on anything unstateable (more spends or justified cells than the rows hold, an ambiguous
/// filing, a carrier of another shape, an OS source that refuses the null carrier's keys).
/// O1-FOOTPRINT-REVIEWED: bounded by `LEDGER_ROWS` rows and one constant-size proof; built and dropped per block.
/// cons: one ledger prove per block (the class's constant cost, the same quiet or busy); nothing is stored.
/// R4 lever 4 step C2: the REAL ledger is one joined proof of the block's note, tag AND member ledgers, so the producer
/// names the stated spends' member carriers (`members`, in spend order) and its anchor ring — the inputs
/// `Node::finish_member_after` reads from the template.
#[must_use]
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn build_ledger(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    members: &[(Vec<u8>, usdm_decider::member_path_gate::MemberTuple)],
    ring: &[Digest4],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
) -> Option<(NoteTransition, crate::hash::Hash32)> {
    let (mut nt, commit, statements) =
        build_ledger_with(spends, justified_notes, justified_tags, seed, output_notes_root, oli_tags, false)?;
    // V2: no member statement; the producer still refuses what laying it refused (`members_state_the_spends`)
    let published = decode_ledger_published(&nt.tuples)?;
    if !crate::member_transition::members_state_the_spends(members, &published, ring, seed) {
        return None;
    }
    prove_ledger_joined(&mut nt, statements?)?;
    Some((nt, commit))
}

/// [`build_ledger`] through the one ledger switch: on an ARMED test node (`bound`) the decider's bound ledger double
/// (`prove_block_ledger_transition_bound`) — the same rows, checks, list and bind, a 32 B seal in place of the WHIR
/// prove — as [`TemplateClass::prove`] does for the other classes. A node binary has no bound branch.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn build_ledger_with(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
    bound: bool,
) -> Option<(NoteTransition, crate::hash::Hash32, Option<LedgerStatements>)> {
    build_ledger_sets_with(spends, &[], justified_notes, justified_tags, seed, output_notes_root, oli_tags, bound)
}

/// §18 — a stated spend's TAIL pairs: its constant-width tags `2p, 2p+1` for `p ≥ 1` (the head row publishes `0, 1` from
/// its carrier). `None` when a set is not the width or a tag is not a canonical digest.
#[must_use]
pub fn spend_tails(spend_sets: &[(Vec<u8>, Vec<[u8; 32]>)]) -> Option<Vec<[Digest4; 2]>> {
    use crate::spend_frontier::cm_bytes_to_root;
    let w = cover_tx_width();
    let mut out = Vec::with_capacity(spend_sets.len() * (w / 2 - 1));
    for (_, tags) in spend_sets {
        if tags.len() != w {
            return None;
        }
        for p in 1..w / 2 {
            out.push([cm_bytes_to_root(&tags[2 * p])?, cm_bytes_to_root(&tags[2 * p + 1])?]);
        }
    }
    Some(out)
}

/// ⭐ padding spec §18 PRODUCER — [`build_ledger_with`] with every stated spend's SET: `spend_sets[i]` = (its spend-or-decoy
/// carrier, its 32 tags in the wallet's order `nullifier ‖ claim ‖ decoys…`), one per entry of `spends`, in order. The note
/// ledger lays `spends.len() × 15` hidden tail rows; the TAG LEDGER is then proved over the PUBLISHED list (each row's pair
/// looked up in the sets → a pair row of spend `i`, else a cover row) and carried as `NoteTransition::tag_agg`. A block with
/// no stated spend proves the tag ledger over one null cover carrier. cons: one tag-ledger prove per block beside the note
/// ledger's (the armed double seals; the real form MEASURED 3.4 s / 482,907 B in the decider's pin), 128 Poseidon pairs.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn build_ledger_sets_with(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    spend_sets: &[(Vec<u8>, Vec<[u8; 32]>)],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
    bound: bool,
) -> Option<(NoteTransition, crate::hash::Hash32, Option<LedgerStatements>)> {
    build_ledger_sets_at(spends, &[], 0, spend_sets, justified_notes, justified_tags, seed, output_notes_root, oli_tags, bound)
}

/// ⭐ goods spec §9.1 — [`build_ledger_sets_with`] UNDER THE BLOCK'S LEDGER CLOCK: `clocks[i]` is the chain clock stated
/// spend `i` was proven against (`PqTx::clock_ms`; empty = every spend at clock 0, the old entry points), and
/// `block_clock_ms` is the one clock the block's ledger states (`ledger_clock_at` of the producer's chain time). A
/// spend whose clock is past the block's is unstateable: the lay returns `None`, so a producer selects only spends
/// whose clock its ledger clock has reached. The form every real producer lays.
#[must_use]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn build_ledger_sets_at(
    spends: &[(Vec<u8>, SpendTuple, Digest4)],
    clocks: &[u64],
    block_clock_ms: u64,
    spend_sets: &[(Vec<u8>, Vec<[u8; 32]>)],
    justified_notes: &[Digest4],
    justified_tags: &[Digest4],
    seed: Digest4,
    output_notes_root: &crate::hash::Hash32,
    oli_tags: &[u8],
    bound: bool,
) -> Option<(NoteTransition, crate::hash::Hash32, Option<LedgerStatements>)> {
    use usdm_decider::settlement_delta as s;
    if !spend_sets.is_empty() && spend_sets.len() != spends.len() {
        return None; // fail-closed: a set per stated spend, or none (the legacy callers)
    }
    if !clocks.is_empty() && clocks.len() != spends.len() {
        return None; // fail-closed: a clock per stated spend, or none (every spend at clock 0)
    }
    let clock_of = |i: usize| clocks.get(i).copied().unwrap_or(0);
    let block_clock_h = clock_hours(block_clock_ms)?; // a ledger clock off the hour grid states nothing
    let tails = spend_tails(spend_sets)?;
    let filed = filed_keys(oli_tags)?;
    let mut carriers: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(spends.len().max(1));
    for (i, (blob, t, d)) in spends.iter().enumerate() {
        if spend_filing_d(t, |cm| filed.get(cm).copied())? != *d {
            return None; // fail-closed: the door recomputes D from the block's filing, so a mismatch is a refused block
        }
        carriers.push((blob.clone(), t.public_bind_at(d, clock_of(i))?));
    }
    if carriers.is_empty() {
        carriers.push(null_spend_carrier_for(bound)?);
    }
    let filing_d = |a: &Digest4, b: &Digest4| ledger_row_filing_d(&filed, a, b);
    let rows = s::plan_ledger_rows_with_tails(seed, spends.len(), &tails, justified_notes, justified_tags, &filing_d)?;
    let (onr, dsr) = roots(output_notes_root);
    #[cfg(test)]
    {
        if bound {
            let (agg, published, _) =
                s::prove_block_ledger_transition_bound_at(&carriers, &rows, domain(), &onr, &dsr, seed, block_clock_h)?;
            let agg = bound_weight::pad(agg, bound_weight::NOTE_LEDGER)?; // R4: the real proof's weight
            if !ledger_filing_is_uniform(oli_tags, &published) {
                return None;
            }
            let (tag_carriers, tag_rows) = lay_tag_ledger_rows(spend_sets, &published, bound)?;
            let (tag_seal, _) =
                usdm_decider::tag_ledger::prove_tag_ledger_bytes_bound(&tag_carriers, &tag_rows, &onr, &dsr, seed)?;
            let tag_agg = bound_weight::pad(tag_seal, bound_weight::TAG_LEDGER)?; // R4: the real proof's weight
            let nt = NoteTransition { agg, tuples: encode_ledger_published(&published)?, shape: ledger_shape_wire()?, tag_agg, clock_ms: block_clock_ms, bodies: [0u8; 32] };
            return Some((nt, crate::block::cover_seed_commit_of(seed), None));
        }
    }
    let _ = bound;
    // ⭐ R4 lever 4 (steps C1 + C2) — THE BLOCK'S THREE LEDGERS PROVE AS ONE BATCH (`usdm_decider::light_batch_merge`): the
    // note and tag statements are laid HERE from the same inputs their separate proves read, and proved together with the
    // member statement by [`prove_ledger_joined`] once the member ledger is laid (`Node::finish_member_after`) — one WHIR
    // pair for the block, the whole proof in `agg`, `tag_agg` and the member `agg` empty (one encoding: the door refuses a
    // non-empty one). The door re-derives all three statements from the block alone (`verify_ledger_on_wire_with`).
    // ⭐ V2 (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16) — THE NOTE STATEMENT IS THE TREE LEDGER for every block: the
    // ledger's laws without the bound step, whose content the block door checks natively on every path (audit F14: the
    // door requires the carried transactions and matches every spend row to one, `spend_evidence::rows_evidenced`, both
    // directions of the tag rule included). The tag statement's joint tie reads the same layout (`tag_ledger::note_tags_
    // tie` → `tree_ledger::TL_PUB`). FORMAT: the joined proof's note statement changes shape.
    let pbs: Vec<Vec<Fa4>> = carriers.iter().map(|c| c.1.clone()).collect();
    let (note, published, _rows_digest) =
        usdm_decider::tree_ledger::lay_tree_ledger(&pbs, &rows, domain(), &onr, &dsr, seed, block_clock_h)?;
    if !ledger_filing_is_uniform(oli_tags, &published) {
        return None; // fail-closed: the door refuses a filing that is not uniform (§10 C1), so no producer lays one
    }
    // ⭐ V2 (speed5, 2026-11-16): NO TAG STATEMENT. What the tag ledger proved in circuit — every tag cell of a stated
    // spend is its carrier's own tag set, and the set is complete — the block door now reads natively from the carried
    // transactions every node verified (`spend_evidence::rows_evidenced`: every loose tag belongs to a stated spend, and every
    // tag of every stated spend is stated), and the pair digests it published are a function of the published list. So
    // the joined proof is the note and member statements. FORMAT. `spend_sets` stays the producer's input for the rows.
    let _ = spend_sets;
    let nt = NoteTransition { agg: Vec::new(), tuples: encode_ledger_published(&published)?, shape: ledger_shape_wire()?, tag_agg: Vec::new(), clock_ms: block_clock_ms, bodies: [0u8; 32] };
    Some((nt, crate::block::cover_seed_commit_of(seed), Some(LedgerStatements { note })))
}

/// ⭐ R4 lever 4 step C2 — the note ledger's laid statement, carried from its lay to the one joined prove (it holds the
/// witness tables; never serialized, never stored — dropped when the block's proof is laid).
pub struct LedgerStatements {
    pub note: usdm_decider::light_batch_merge::LaidStatement<'static>,
}

/// ⭐ V2 (spec LEVEL-AGGREGATE §15.5, speed5 2026-11-16) — prove the block's ledger into `nt.agg`: the NOTE statement (the
/// tree ledger) alone. The tag statement left with the native tag rule; the member statement leaves because everything it
/// proved is judged natively on every path: each spend's member carrier is verified by the block door from the carried
/// transaction (or in the tree's leaves), its cross-bind to the spend is `spend_evidence::evidence_fields`, and its anchor is
/// judged at the fold against the node's OWN recent roots (`Node::native_spend_anchors_at_fold`) after the header's ring
/// commit is checked against this chain's own ring history (`member_ring_commit_is_canonical`). The ONE site every real
/// producer proves a ledger through (`Node::finish_member_after`, [`build_ledger`]). FORMAT.
#[must_use]
pub fn prove_ledger_joined(nt: &mut NoteTransition, statements: LedgerStatements) -> Option<()> {
    nt.agg = usdm_decider::light_batch_merge::prove_joined(vec![statements.note])?;
    Some(())
}

/// §18 — the TAG LEDGER's carriers and rows over a block's published note list: row `r` is a pair row of spend `i` when its
/// two tag cells are `tags[2p], tags[2p+1]` of `spend_sets[i]`, else a cover row (its cells the note row's cover tags).
/// Carriers are the sets' spend-or-decoy carriers (their binds `cover_tag_statement_bind(tags)`), or ONE null cover
/// carrier on a block with no stated spend. The published pair digests are a function of the note list and are not
/// returned to the wire. The ONE lay every tag-ledger prove form reads (joined with the note ledger, or the armed double).
#[allow(clippy::type_complexity)]
pub fn lay_tag_ledger_rows(
    spend_sets: &[(Vec<u8>, Vec<[u8; 32]>)],
    published: &[usdm_decider::settlement_delta::LedgerPublished],
    bound: bool,
) -> Option<(Vec<(Vec<u8>, Vec<Fa4>)>, Vec<usdm_decider::tag_ledger::TagRow>)> {
    use crate::spend_frontier::{cm_bytes_to_root, leaf_to_cm_bytes};
    use usdm_decider::slot_ledger::{PUB_TAG0, PUB_TAG1};
    use usdm_decider::tag_ledger as t;
    let w = cover_tx_width();
    let mut pair_of: std::collections::HashMap<([u8; 32], [u8; 32]), (usize, usize)> = std::collections::HashMap::new();
    let mut carriers: Vec<(Vec<u8>, Vec<Fa4>)> = Vec::with_capacity(spend_sets.len().max(1));
    for (i, (bytes, tags)) in spend_sets.iter().enumerate() {
        if tags.len() != w || bytes.is_empty() {
            return None;
        }
        for p in 0..w / 2 {
            if pair_of.insert((tags[2 * p], tags[2 * p + 1]), (i, p)).is_some() {
                return None; // two spends laying one pair would collide on the note ledger's strict order anyway
            }
        }
        let limbs: Vec<Digest4> = tags.iter().map(cm_bytes_to_root).collect::<Option<_>>()?;
        carriers.push((bytes.clone(), usdm_decider::nf_sparse_air::cover_tag_statement_bind(&limbs)));
    }
    if carriers.is_empty() {
        carriers.push(null_cover_carrier_for(bound)?);
    }
    let rows: Vec<t::TagRow> = published
        .iter()
        .map(|p| {
            let key = (leaf_to_cm_bytes(p[PUB_TAG0]), leaf_to_cm_bytes(p[PUB_TAG1]));
            t::TagRow { pair_of: pair_of.get(&key).copied(), tags: [p[PUB_TAG0], p[PUB_TAG1]] }
        })
        .collect();
    Some((carriers, rows))
}

/// ⭐ FRESH NULL CARRIERS, PROVED AHEAD (2026-11-03). A quiet block needs three null carriers, one of each class, and proved them one after
/// another inside its own prove. MEASURED (`sample`, a live node on a real pair): ~6 s of a 16 s block prove, while the machine sat idle
/// between blocks. Each class now keeps a small stock proved on spare cycles (`background_prove`), so a template takes one that is ready.
/// ⛔ EVERY CARRIER IS USED ONCE AND DROPPED. Sharing one between blocks is refuted: 56 % of the proof's 16-byte chunks repeated from block to
/// block (project memory, 2026-11-03). An empty stock proves one inline, exactly as before, so nothing ever waits on the stock.
/// cons: the same CPU at a lower priority; `STOCK` carriers of each class in RAM, ~1 MB in all; a carrier's secret lives in RAM until its block.
pub struct CarrierPool {
    stock: std::sync::Mutex<Vec<(Vec<u8>, Vec<Fa4>)>>,
    filling: std::sync::atomic::AtomicBool,
}

impl CarrierPool {
    const STOCK: usize = 2;

    pub const fn new() -> Self {
        Self { stock: std::sync::Mutex::new(Vec::new()), filling: std::sync::atomic::AtomicBool::new(false) }
    }

    pub fn take(&'static self, prove: fn() -> Option<(Vec<u8>, Vec<Fa4>)>) -> Option<(Vec<u8>, Vec<Fa4>)> {
        let ready = self.stock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).pop();
        self.refill(prove);
        ready.or_else(prove)
    }

    fn refill(&'static self, prove: fn() -> Option<(Vec<u8>, Vec<Fa4>)>) {
        use std::sync::atomic::Ordering::SeqCst;
        if self.filling.swap(true, SeqCst) {
            return;
        }
        let spawned = std::thread::Builder::new().name("carrier-stock".into()).spawn(move || {
            loop {
                if self.stock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).len() >= Self::STOCK {
                    break;
                }
                let Some(c) = usdm_decider::background_prove::run(prove) else { break };
                self.stock.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push(c);
            }
            self.filling.store(false, SeqCst);
        });
        if spawned.is_err() {
            self.filling.store(false, SeqCst);
        }
    }
}

/// A no-spend block's null COVER carrier (§18) — [`null_spend_carrier_for`]'s twin: 32 decoy tags under a fresh secret,
/// nothing of it published. The BOUND double reuses one per process (its cells never reach the wire); a real ledger proves
/// a fresh one per block.
fn null_cover_carrier_for(bound: bool) -> Option<(Vec<u8>, Vec<Fa4>)> {
    #[cfg(test)]
    {
        if bound {
            static NULL: std::sync::OnceLock<Option<(Vec<u8>, Vec<Fa4>)>> = std::sync::OnceLock::new();
            return NULL
                .get_or_init(|| {
                    usdm_decider::tag_ledger::null_cover_carrier(usdm_decider::poseidon2_compress::lanes_of(&[0x4e55_4c4c, 1, 2, 3, 4, 5, 6, 7]))
                })
                .clone();
        }
    }
    let _ = bound;
    static POOL: CarrierPool = CarrierPool::new();
    POOL.take(|| usdm_decider::tag_ledger::null_cover_carrier(usdm_decider::whir_rec_block::fresh_lc_blind()?))
}

/// A no-spend block's null spend carrier — the spend class's twin of `member_transition::null_carrier_for`. The BOUND
/// double (test builds only) reuses ONE per process: the carrier never leaves the producer and no cell of it is
/// published (the cover cells are the header seed's, `db_padding_the_null_carrier_block_verifies_…`), so the armed
/// ledger lays the same list from it; the fresh prove it skips was 49 % of an armed quiet block's produce (MEASURED
/// 2026-10-27, joiner pin sample, `grind_wide` 38 %). A real ledger proves a fresh one per block (fresh keys).
pub fn null_spend_carrier_for(bound: bool) -> Option<(Vec<u8>, Vec<Fa4>)> {
    #[cfg(test)]
    {
        if bound {
            static NULL: std::sync::OnceLock<Option<(Vec<u8>, Vec<Fa4>)>> = std::sync::OnceLock::new();
            return NULL.get_or_init(usdm_decider::settlement_delta::null_spend_carrier).clone();
        }
    }
    let _ = bound;
    static POOL: CarrierPool = CarrierPool::new();
    POOL.take(usdm_decider::settlement_delta::null_spend_carrier)
}

/// ⭐ §RF-3 spec §3.2 — the ledger's cells ARE the header's slots: its 256 out cells are exactly the block's 256 note
/// commitments and its 256 tag cells exactly the block's 256 `padded_tags`, each once (as multisets — the header's slot
/// order is the record's permutation, the list's is `tag0` ascending). Without it `list ∩ header` names the spend rows
/// (the R5 leak filed 2026-10-24): a list whose cover cells are not the header's cover slots partitions the header.
/// Pure and native: two sorts of 256 × 32 B per side. cons: ≈ 16 KiB transient per verify, nothing stored.
#[must_use]
pub fn ledger_cells_are_the_header_slots(
    published: &[usdm_decider::settlement_delta::LedgerPublished],
    header_cms: &[[u8; 32]],
    padded_tags: &[[u8; 32]],
) -> bool {
    ledger_cells_are_the_header_lane(published, padded_tags) && ledger_outs_are_the_header_slots(published, header_cms)
}

/// §RF-3 — the half of [`ledger_cells_are_the_header_slots`] that reads only what TRAVELS: 256 distinct out cells, and
/// tag cells that are exactly the header-bound `padded_tags`, each once. Every peer decides it from the wire alone.
#[must_use]
pub fn ledger_cells_are_the_header_lane(
    published: &[usdm_decider::settlement_delta::LedgerPublished],
    padded_tags: &[[u8; 32]],
) -> bool {
    use usdm_decider::slot_ledger::{PUB_TAG0, PUB_TAG1};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let mut outs = ledger_out_cells_sorted(published);
    outs.dedup();
    let mut tags: Vec<[u8; 32]> = published.iter().flat_map(|p| [b(p[PUB_TAG0]), b(p[PUB_TAG1])]).collect();
    let mut ht = padded_tags.to_vec();
    tags.sort_unstable();
    ht.sort_unstable();
    let once = |v: &[[u8; 32]]| v.windows(2).all(|w| w[0] != w[1]);
    outs.len() == crate::cover::BLOCK_FIXED_NOTE_COUNT
        && published.len() * 2 == crate::cover::BLOCK_FIXED_NOTE_COUNT
        && tags.len() == crate::cover::BLOCK_FIXED_NULLIFIER_COUNT
        && tags == ht
        && once(&tags)
}

/// §RF-3 — the half of [`ledger_cells_are_the_header_slots`] that reads the BODY: the 256 out cells are exactly the
/// block's 256 header note commitments (`header_note_cms_of_bodies`), as multisets. Run only where the body is held.
#[must_use]
pub fn ledger_outs_are_the_header_slots(
    published: &[usdm_decider::settlement_delta::LedgerPublished],
    header_cms: &[[u8; 32]],
) -> bool {
    let mut hc = header_cms.to_vec();
    hc.sort_unstable();
    ledger_out_cells_sorted(published) == hc
}

fn ledger_out_cells_sorted(published: &[usdm_decider::settlement_delta::LedgerPublished]) -> Vec<[u8; 32]> {
    use usdm_decider::slot_ledger::{PUB_OUT0, PUB_OUT1};
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let mut outs: Vec<[u8; 32]> = published.iter().flat_map(|p| [b(p[PUB_OUT0]), b(p[PUB_OUT1])]).collect();
    outs.sort_unstable();
    outs
}

/// The block's 256 header note commitments, read off its fixed note payload exactly as every producer wrote them
/// (`spend_frontier::note_cm_of` per `PQ_NOTE_BYTES` unit). `None` unless the payload is exactly the constant 256 units,
/// each with a canonical commitment — the §3.2 door never compares against an invented slot.
#[must_use]
pub fn header_note_cms(output_notes: &[u8]) -> Option<Vec<[u8; 32]>> {
    use crate::cover::{BLOCK_FIXED_NOTE_COUNT, PQ_NOTE_BYTES};
    if output_notes.len() != BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES {
        return None;
    }
    output_notes
        .chunks_exact(PQ_NOTE_BYTES)
        .map(|u| crate::spend_frontier::note_cm_of(u).map(crate::spend_frontier::leaf_to_cm_bytes))
        .collect()
}

/// ⭐ §RF-3 PEER DOOR INPUT — the block's 256 header note commitments from its CARRIED real notes alone: the k real cms
/// in carried order, then `cover_note_native(header_seed(reals), 1..=256−k)` — the one spelling
/// `cover::assemble_fixed_note_payload_det` writes into each cover unit's front (spec §13). So every door caller
/// (graft, fold, lane justify) states the slots [`verify_ledger_with`] compares against from the block body, never from
/// a served DA record (`node::pins::rf3_header_cms_from_bodies_are_the_served_slots`). `None` when a real unit has no
/// canonical cm or the block carries more than 256 notes.
/// cons: ≤ 256 native Poseidon pairs per door call, f(256) — never f(history); nothing stored.
#[must_use]
pub fn header_note_cms_of_bodies(real_notes: &[u8], key: &crate::cover::CoverKey) -> Option<Vec<[u8; 32]>> {
    use crate::cover::{BLOCK_FIXED_NOTE_COUNT, PQ_NOTE_BYTES};
    use crate::spend_frontier::{leaf_to_cm_bytes, note_cm_of};
    if real_notes.len() % PQ_NOTE_BYTES != 0 || real_notes.len() / PQ_NOTE_BYTES > BLOCK_FIXED_NOTE_COUNT {
        return None;
    }
    let mut cms: Vec<[u8; 32]> =
        real_notes.chunks_exact(PQ_NOTE_BYTES).map(|u| note_cm_of(u).map(leaf_to_cm_bytes)).collect::<Option<_>>()?;
    let seed = crate::cover::header_seed(real_notes, key);
    let k = cms.len();
    cms.extend(
        (1..=(BLOCK_FIXED_NOTE_COUNT - k) as u64)
            .map(|j| leaf_to_cm_bytes(usdm_decider::slot_ledger::cover_note_native(seed, j))),
    );
    Some(cms)
}

/// ⭐ §18 — THE ONE SPELLING OF A BLOCK'S COVER CELLS, from its held real bodies: the 256 cover TAG cells
/// `cover_tag_native(header_seed(reals), 1..=256)` and the 256 cover NOTE cells `cover_note_native(header_seed(reals), 1..=256)`.
/// Read by the producer's filing (`uniform_ledger_filing_with_tails`) and by the fold's ring judge
/// (`Node::member_anchors_at_fold`): a published row whose four cells all lie in these sets is a PURE COVER ROW — it states
/// no spend, so a ring the chain never held refuses nothing of it. Holder-only by construction: the seed is the bodies'
/// hash (`cover::header_seed`), a non-holder sees the header's Poseidon commit of it and cannot tell a cover row from a
/// spend row (the hidden-row class, spec §18). cons: 512 native Poseidon maps per call, f(256) — never f(history).
#[must_use]
pub fn ledger_cover_cells(
    real_notes: &[u8],
    key: &crate::cover::CoverKey,
) -> (std::collections::HashSet<[u8; 32]>, std::collections::HashSet<[u8; 32]>) {
    use crate::spend_frontier::leaf_to_cm_bytes;
    let seed = crate::cover::header_seed(real_notes, key);
    let decoys = (1..=crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64)
        .map(|s| leaf_to_cm_bytes(usdm_decider::slot_ledger::cover_tag_native(seed, s)))
        .collect();
    let cover_notes = (1..=crate::cover::BLOCK_FIXED_NOTE_COUNT as u64)
        .map(|s| leaf_to_cm_bytes(usdm_decider::slot_ledger::cover_note_native(seed, s)))
        .collect();
    (decoys, cover_notes)
}

/// ⭐ §RF-3 PRODUCER INPUTS — the ledger's JUSTIFIED cells and seed for a SEALED block, from what the block carries:
/// `output_notes` (its real notes), `padded_tags` (its 256 tags) and its stated spends. HEADER_SEED =
/// `cover::header_seed(output_notes)`; the real tags are the padded set minus its `cover_tag_native(seed, 1..=256)`
/// decoys (`cover::header_tag_fill`'s one spelling); a stated spend's two outputs and two tags are its ROW's cells, so
/// each is removed once from the justified lists. `None` when a note front or real tag is not a canonical digest, or a
/// stated spend's cell does not ride the block (a ledger over it would not be the header's slots, §3.2).
/// cons: 256 native cover-tag derives + two multiset passes over ≤ 256 cells per block; nothing stored.
#[must_use]
#[allow(clippy::type_complexity)]
pub fn block_ledger_inputs(
    output_notes: &[u8],
    padded_tags: &[[u8; 32]],
    spends: &[SpendTuple],
    key: &crate::cover::CoverKey,
) -> Option<(Vec<Digest4>, Vec<Digest4>, Digest4)> {
    let sets: Vec<Vec<[u8; 32]>> = spends.iter().map(|s| vec![s.nullifier, s.tag1]).collect();
    block_ledger_inputs_sets(output_notes, padded_tags, spends, &sets, key)
}

/// §18 — [`block_ledger_inputs`] with each stated spend's WHOLE tag set (`spend_tag_sets[i]`, its 32 constant-width tags):
/// every one of them is a cell of the spend's own 16 rows, so none is a justified cell (the `Σ t = 30 · spends` leak,
/// F2-red-found-20261027k). The legacy form above passes `[nullifier, tag1]`.
#[must_use]
pub fn block_ledger_inputs_sets(
    output_notes: &[u8],
    padded_tags: &[[u8; 32]],
    spends: &[SpendTuple],
    spend_tag_sets: &[Vec<[u8; 32]>],
    key: &crate::cover::CoverKey,
) -> Option<(Vec<Digest4>, Vec<Digest4>, Digest4)> {
    use crate::spend_frontier::{cm_bytes_to_root, leaf_to_cm_bytes, note_cm_of};
    if spend_tag_sets.len() != spends.len() {
        return None;
    }
    let seed = crate::cover::header_seed(output_notes, key);
    let (decoys, cover_notes) = ledger_cover_cells(output_notes, key);
    let mut notes: Vec<[u8; 32]> = output_notes
        .chunks_exact(crate::cover::PQ_NOTE_BYTES)
        .map(|u| note_cm_of(u).map(leaf_to_cm_bytes))
        .collect::<Option<_>>()?;
    // §18.1: the seed note's front is the ledger's cover cell `257 − k`, so it is no justified note (the tag rule, on notes)
    notes.retain(|n| !cover_notes.contains(n));
    let mut tags: Vec<[u8; 32]> = padded_tags.iter().filter(|t| !decoys.contains(*t)).copied().collect();
    let take = |v: &mut Vec<[u8; 32]>, x: &[u8; 32]| v.iter().position(|y| y == x).map(|i| v.remove(i));
    for (s, set) in spends.iter().zip(spend_tag_sets) {
        take(&mut notes, &s.out0_cm)?;
        take(&mut notes, &s.out1_cm)?;
        for t in set {
            take(&mut tags, t)?;
        }
    }
    let lanes = |v: Vec<[u8; 32]>| v.iter().map(cm_bytes_to_root).collect::<Option<Vec<_>>>();
    Some((lanes(notes)?, lanes(tags)?, seed))
}

/// ⭐ §RF-3 PEER — verify a block's slot ledger from what the block carries: the transition, the header's seed
/// commitment and its `oli_tags`. Yields the ALLOW-list: every note cell and every tag cell the ledger itself states
/// (`j = 0` / `t = 0`). A JUSTIFIED cell is admitted by the object that justifies it, never here.
///
/// NEW-DOOR CHECKLIST (AGENTS.md §9.6) — the ledger is the padded twin of [`verify_with`]:
/// (1) PoW: not this step's — it is called by the block door after the header's grind check, as `verify_with` is.
/// (2) Proof: `verify_block_ledger_transition` over the class's fixed layout, under the header's `cover_seed_commit`
///     (bound in the block id) and the `rows_digest` recomputed from the published list; every row's `D` is
///     recomputed natively from `oli_tags` before any proof work.
/// (3) Conservation: a spend row publishes only what its proven carrier states (conservation is the carrier's law); a
///     cover note is `P(COVER_CM_DOMAIN ‖ slot, seed)`, which has no opening, so it can be neither received nor spent.
/// (4) Replay: every admitted tag enters the spent SET beside `verify_with`'s nullifiers; a repeat is refused there.
/// (5) Bounded work: a 28,672 B fixed-length decode, 128 blake3 derives, two sorts of 256 × 32 B (spec §3.2: the out
///     cells ARE the header's 256 note slots and the tag cells ARE its 256 padded tags, each once —
///     [`ledger_cells_are_the_header_slots`]), one constant-size verify.
/// (6) Parity with `verify_with`: its shape check → the class's constant shape; its tuple-length check → the fixed
///     decode; its per-spend `D` from `oli_tags` → per ROW, every row; its proof → the ledger proof; its
///     nullifier + claim tag into the set → both tag cells of every row. Its verify cache is perf, not a check.
/// R4 lever 4 step C2: the member ledger is the joined proof's third statement, derived from the list, the header's
/// `ring_commit` and seed commit (`member_transition::member_ledger_stated`) — the same derivation the block door makes.
#[must_use]
pub fn verify_ledger(
    nt: &NoteTransition,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: &crate::hash::Hash32,
    oli_tags: &[u8],
    header_cms: &[[u8; 32]],
    padded_tags: &[[u8; 32]],
    ring_commit: &crate::hash::Hash32,
) -> Option<Admissible> {
    // V2: the joined proof carries no member statement; the header's ring commit is judged at the fold against this chain's
    // own ring history (`Node::member_ring_commit_is_canonical`), each spend's anchor against the node's own recent roots
    let _ = ring_commit;
    verify_ledger_with(nt, output_notes_root, seed_commit, oli_tags, header_cms, padded_tags, false)
}

/// [`verify_ledger`] through the one ledger switch: an ARMED test door (`bound`) verifies the bound ledger double ONLY
/// (`verify_block_ledger_transition_bound`; never a fallback to the real verifier, which never takes the double's
/// bytes). Every structural check above the proof runs in both forms. A node binary has no bound branch.
#[must_use]
pub fn verify_ledger_with(
    nt: &NoteTransition,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: &crate::hash::Hash32,
    oli_tags: &[u8],
    header_cms: &[[u8; 32]],
    padded_tags: &[[u8; 32]],
    bound: bool,
) -> Option<Admissible> {
    // ⛔ LIVE-LEDGER-WHY (lane livediag, 2026-11-27): each refusal names its check — the live origin refused every ledger it laid
    // ("a joined ledger proof this node's OWN verifier refuses") with no reason, on two binaries. DIGITAL-CASH-PRIVACY-REVIEWED: fixed strings.
    let Some(published) = decode_ledger_published(&nt.tuples) else {
        eprintln!("[ledger-why] the published list does not decode");
        return None;
    };
    if !ledger_outs_are_the_header_slots(&published, header_cms) {
        eprintln!("[ledger-why] the list's out cells are not the header's note slots");
        return None; // fail-closed (spec §3.2): a list that is not the header's slots names which slots are spends
    }
    verify_ledger_on_wire_with(nt, output_notes_root, seed_commit, oli_tags, padded_tags, bound)
}

/// ⭐ §RF-3 THE PEER'S SPEND VERDICT — [`verify_ledger_with`] minus the one check that reads the block BODY (the out
/// cells ↔ the header note slots, [`ledger_outs_are_the_header_slots`]). `Block::output_notes` never travels (DB-165,
/// `#[serde(skip)]`), so a door reading it judged every gossiped ledger block against an empty body (0/256 slots,
/// measured 2026-10-24: 4,556 refusals) and a node that had hydrated the body could split from one that had not. What
/// a node decides about SPENDS therefore reads only what travels — the list, its proof, the tags, the filing, the seed
/// commit; the body bind is run where the body is held and decides only that block's notes
/// (`member_transition::spends_proven_on_block_with`), the same property the legacy door has with `output_notes_root`.
#[must_use]
pub fn verify_ledger_on_wire_with(
    nt: &NoteTransition,
    output_notes_root: &crate::hash::Hash32,
    seed_commit: &crate::hash::Hash32,
    oli_tags: &[u8],
    padded_tags: &[[u8; 32]],
    bound: bool,
) -> Option<Admissible> {
    use usdm_decider::slot_ledger::{PUB_D, PUB_FLAGS, PUB_OUT0, PUB_OUT1, PUB_TAG0, PUB_TAG1};
    let why = |s: &str| eprintln!("[ledger-why] {s}"); // LIVE-LEDGER-WHY: fixed strings only
    if Some(nt.shape) != ledger_shape_wire() {
        why("the shape is not the wire shape");
        return None;
    }
    let Some(published) = decode_ledger_published(&nt.tuples) else {
        why("the published list does not decode (wire)");
        return None;
    };
    if !ledger_cells_are_the_header_lane(&published, padded_tags) {
        why("the tag cells are not the header's lane");
        return None; // fail-closed (spec §3.2): tag cells that are not the header's lane name which tags are spends
    }
    let Some(sc) = crate::block::cover_seed_commit_lanes(seed_commit) else {
        why("the seed commit does not decode");
        return None;
    };
    // goods spec §9.1: the ledger's clock, as the hour count its proof binds; a clock off the hour grid is no ledger's
    // (one encoding). Whether the chain has REACHED it is the fold's verdict (`Node::ledger_clock_is_reached`).
    let Some(block_clock_h) = clock_hours(nt.clock_ms) else {
        why("the ledger clock is off the hour grid");
        return None;
    };
    let Some(filed) = filed_keys(oli_tags) else {
        why("the filed keys do not decode");
        return None;
    };
    if !ledger_filing_is_uniform(oli_tags, &published) {
        why("the filing is not uniform with the published list");
        return None; // fail-closed (§10 C1): a filing that skips a published note, files one it does not publish, or
                     // lists records out of order names which rows are spends
    }
    for p in &published {
        match ledger_row_filing_d(&filed, &p[PUB_OUT0], &p[PUB_OUT1]) {
            Some(d) if d == p[PUB_D] => {}
            Some(_) => {
                why("a row's D is not the filing function of its notes");
                return None; // fail-closed: a row's D is not the public filing function of its notes
            }
            None => {
                why("a row's filing D is unstateable");
                return None;
            }
        }
    }
    let (onr, dsr) = roots(output_notes_root);
    #[cfg(test)]
    let digests: Vec<Digest4> =
        published.iter().map(|p| usdm_decider::tag_ledger::pair_digest_native(&p[PUB_TAG0], &p[PUB_TAG1])).collect();
    // ⭐ R4 lever 4 (steps C1 + C2) — the note, tag and member ledgers verify as ONE joined batch: every statement derived
    // from the block alone (the member's by the caller, from the header's ring and seed commits — `member_transition::
    // member_ledger_stated`), the proof in `agg`, `tag_agg` empty (the producer's one encoding). A real ledger with no
    // member statement is refused: it is the third statement of the one proof. The armed double keeps its separate seals
    // (the member's judged by the caller, as before).
    let joined_ok = {
        #[cfg(test)]
        use usdm_decider::settlement_delta as s;
        #[cfg(test)]
        use usdm_decider::tag_ledger as t;
        #[cfg(test)]
        let armed = bound.then(|| {
            bound_weight::unpad(&nt.agg, bound_weight::NOTE_LEDGER)
                .is_some_and(|seal| s::verify_block_ledger_transition_bound_at(seal, domain(), &onr, &dsr, sc, &published, block_clock_h))
                && bound_weight::unpad(&nt.tag_agg, bound_weight::TAG_LEDGER)
                    .is_some_and(|seal| t::verify_tag_ledger_bytes_bound(seal, &onr, &dsr, sc, &digests))
        });
        #[cfg(not(test))]
        let armed: Option<bool> = {
            let _ = bound;
            None
        };
        armed.unwrap_or_else(|| {
            // V2: the joined proof is the tree-ledger note statement ALONE (the producer's one encoding, `build_ledger`): no
            // tag statement (the tag rule is native at the block door, `spend_evidence`) and no member statement (each
            // spend's member carrier is verified natively, its anchor judged at the fold against this node's own roots)
            nt.tag_agg.is_empty()
                && usdm_decider::tree_ledger::tree_ledger_stated(domain(), &onr, &dsr, sc, &published, block_clock_h)
                    .is_some_and(|note| usdm_decider::light_batch_merge::verify_joined(&nt.agg, vec![note]))
        })
    };
    if !joined_ok {
        // DIGITAL-CASH-PRIVACY-REVIEWED: byte lengths and a flag — no tag, cm, amount, key or owner.
        eprintln!(
            "[tag-ledger-door] ⛔ refused a ledger whose joined note+tag proof does not verify (agg {} B, tag_agg {} B, armed {bound})",
            nt.agg.len(),
            nt.tag_agg.len()
        );
        return None;
    }
    // ⭐ §18 — THE TAG LEDGER (verified above, joined with the note ledger): every tag cell of a stated spend's 16 pair rows
    // is its carrier's own tag set, or the block admits nothing (a tail row is hidden, so the door cannot tell a bound tag
    // from a planted one any other way). The published pair digests are derived from THIS list — nothing of them travels.
    // §9.6: (2) the joined light decider (the tag statement's bus challenge drawn after its trace, as alone); (3) no value:
    // it binds tags to carriers; (4) every admitted tag enters the set below; (5) 128 Poseidon pairs + one constant-size
    // verify; (6) parity with the cover transition's door (`verify_cover_with`), whose per-carrier tag-digest tie it absorbs.
    // The joint tie (`tag_ledger::note_tags_tie`) states each tag row's two tags ARE this list's row: that is the whole binding.
    let b = crate::spend_frontier::leaf_to_cm_bytes;
    let mut a = Admissible::default();
    for p in &published {
        // flags lanes: j0, j1, t0, t1 (slot_ledger::SL_PUB)
        for (k, cell) in [PUB_OUT0, PUB_OUT1].into_iter().enumerate() {
            if p[PUB_FLAGS][k] == 0 {
                a.cms.insert(b(p[cell]));
            }
        }
        for (k, cell) in [PUB_TAG0, PUB_TAG1].into_iter().enumerate() {
            if p[PUB_FLAGS][2 + k] == 0 {
                a.nullifiers.insert(b(p[cell]));
            }
        }
    }
    Some(a)
}
