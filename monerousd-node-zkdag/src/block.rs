// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Block + header types for the GHOSTDAG ledger. Width>1: a block commits to MANY parents (the
//! tips its producer observed), so the ledger is a directed acyclic graph, never a linear chain.
//! Every root in the header is a COMMITMENT (Pillar-1 private: no raw witness in a header); the
//! amounts, keys, and linkages live inside the confidential ZK notes those roots commit to.

use crate::fixed::FixedBytes;
use serde::{Deserialize, Serialize};

use crate::hash::Hash32;

/// The canonical genesis header (version 1, no parents, zero roots, `BOOTSTRAP_WORK`). Exposed on the lib so
/// BOTH the daemon `run_serve` AND the in-process [`crate::serve::run_in_process`] (the phone's own node) build
/// the IDENTICAL genesis — a genesis match is the hard precondition for two nodes to share a chain.
pub fn genesis_header() -> BlockHeader {
    BlockHeader {
        // Genesis carries no output notes, so its commitment is the hash of the empty payload — derived,
        // never a magic constant, so every node computes the identical genesis id.
        output_notes_root: Hash32::hash(&[]),
        note_commitments_root: Hash32::hash(&[]),
        nullifier_tags_root: Hash32::hash(&[]),
        // Genesis ships no locator tags and no account targets, so both sidecar commitments are the hash of
        // the empty payload — derived by the SAME `da_sidecar_root_of` every verifier uses, never a magic
        // constant, so every node computes the identical genesis id.
        oli_tags_root: da_sidecar_root_of(&[]),
        account_targets_root: da_sidecar_root_of(&[]),
        // Genesis deletes nothing — the empty deletion sidecar, derived like its siblings above.
        // Genesis bonds no validator — the empty bond sidecar, derived like its siblings above.
        bond_set_root: da_sidecar_root_of(&[]),
        // Genesis registers no @username/group — the empty directory sidecar, derived like its siblings above.
        dir_set_root: da_sidecar_root_of(&[]),
        // Genesis anchors no letters — the empty letter sidecar, derived like its siblings above.
        letter_set_root: da_sidecar_root_of(&[]),
        tag_evidence_root: da_sidecar_root_of(&[]),
        level_root: Hash32::ZERO, fold_ordinal: 0, fold_commit: Hash32::ZERO, band_ordinal: 0, band_commit: Hash32::ZERO,
        // Genesis credits nothing that needs justifying — the empty credit sidecar, same derivation.
        credit_set_root: da_sidecar_root_of(&[]),
        // Genesis carries no transition — the empty transitions commitment, derived the same way.
        transitions_root: empty_transitions_root(),
        cover_seed_commit: crate::hash::Hash32::ZERO,
        member_ring_commit: crate::hash::Hash32::ZERO,
        version: 1,
        parents: vec![],
        timestamp: 0,
        nonce: 0,
        work: crate::miner::BOOTSTRAP_WORK,
        pow_bind: Hash32::ZERO,
        tx_merkle_root: Hash32::ZERO,
        frontier_root: Hash32::ZERO,
        nullifier_root: Hash32::ZERO,
        sparse_root: crate::hash::Hash32::ZERO,
        chain_acc: [0u8; 16],
        miner_commitment: Hash32::ZERO,
        account_root: Hash32::ZERO,
    }
}

/// ⛔⛔⛔ THE GENESIS BLOCK NAMES ITS NETWORK — a chain's public id must identify the chain.
///
/// [`genesis_header`] above is all-constant: every field is `0`/`ZERO`, with no network input anywhere. Its
/// block id is therefore a GLOBAL CONSTANT — byte-identical on every network — and `chain_id` in `/get_info`
/// is exactly that block id. So `chain_id` could not distinguish two networks, and the wallet's fork-detector,
/// which compares precisely that value, reported AGREEMENT between nodes that shared no chain at all.
///
/// The DSYNC adopt gate meanwhile compares the per-network id prefix, so the two answered differently. Measured
/// live on one machine: three nodes all reporting `chain_id 449560a82e7d06df`, every adopt returning
/// `GenesisMismatch`, permanently. A node started with no `MONEROUSD_NET` takes the mainnet prefix while every
/// wallet-spawned node passes testnet, so ordinary users hit this by default — their node meshed over Tor,
/// exchanged DSYNC bundles, refused every one, and extended its own chain while looking perfectly healthy.
/// Funds could not move between two devices because neither could ever adopt the other's chain. An invisible
/// split is far worse than a loud one.
///
/// Making the id a pure function of the network fixes both sides at once: two nodes on one network agree by
/// construction, two on different networks are now VISIBLY different at `chain_id`, and the fork-detector, the
/// RPC and the adopt gate finally answer the same question the same way. This is a network-identity input, the
/// same parity value every node on the network computes for itself — it selects no role and grants no party
/// anything. `pow_bind` carries it because genesis has no proof-of-work to bind, leaving the field free.
pub fn genesis_header_for_network(network_id_prefix: &[u8]) -> BlockHeader {
    let mut h = genesis_header();
    h.pow_bind = Hash32::hash(network_id_prefix);
    h
}

/// A block id is the blake3 digest of its canonically-encoded header.
pub type BlockId = Hash32;

/// A GHOSTDAG block header.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct BlockHeader {
    /// Consensus/version tag (hard-fork gating lives here).
    pub version: u32,
    /// DAG parents: the tips the producer observed. `>= 1` for every non-genesis block; genesis
    /// alone has none. The selected parent is chosen among these by GHOSTDAG (max blue_work).
    pub parents: Vec<BlockId>,
    /// Producer's wall-clock stamp (median-time-past bounded in consensus).
    pub timestamp: u64,
    /// PoUW grind nonce. Validity (checked in the consensus brick) = the PQ-PoUW hash over the hashing
    /// preimage (which folds in `pow_bind`) meets the target implied by `work`.
    pub nonce: u64,
    /// This block's PoUW work — the accumulated-difficulty contribution the DAG sums into
    /// blue_work. Set by the adaptive GHOSTDAG DAA at template time; consensus (brick 6) binds it
    /// to the PQ-PoUW target and the DAA window, so it is never a free/pinned value.
    pub work: u128,
    /// #73 non-outsourceable bind: `H(pi)`, where `pi` is a WHIR proof that the miner holds the
    /// coinbase reward spend key bound to this block's challenge. Folded into the PoW preimage so
    /// a valid hash *requires* the spend key — the "useful"/non-outsourceable part of PoUW.
    pub pow_bind: Hash32,
    /// Merkle root over this block's ordered PQ tx ids (its mergeset of newly-included txs).
    pub tx_merkle_root: Hash32,
    /// The confidential note-tree frontier root AFTER applying this block (#106 state commitment).
    pub frontier_root: Hash32,
    /// The O(1) nullifier-accumulator (indexed-Merkle) root this block's spends prove NON-membership
    /// (unspent) against — the spent-state commitment, at PARITY with `frontier_root` (the note side).
    /// Committed in the header id (folded into `preimage`) so the spent-state is tamper-evident and
    /// gossiped: two nodes whose tips agree on this root agree on the SPENT SET by construction, which
    /// is the split-detection substrate for the trustless double-spend gate ([[crate::nullifier_tree]]).
    /// Genesis carries `Hash32::ZERO` (no spends); its integrity rides the same carrier/recursive-proof
    /// layer that guards `frontier_root` (a wrong root fails the block's spend non-membership proofs).
    pub nullifier_root: Hash32,
    /// ⭐⭐⭐ DB-154 — THE MERKLE ROOT OF THE SPENT SET, BEFORE THIS BLOCK.
    ///
    /// `nullifier_root` above is the A_tip PROJECTION: an order-free 256-bit fold that answers "is the
    /// spent set the same" and nothing else. A wallet cannot fold a copath against a fold. So the copath
    /// lane had NOTHING in consensus to anchor to — a wallet checking a served non-membership copath was
    /// trusting the one node that served it, which is the local-state-decides-truth class wearing a proof.
    ///
    /// This is the tree root the copath actually describes, committed by the block that produced it, in
    /// the same PRE->POST shape `nullifier_root` -> `nullifier_proof.post_root` already uses.
    ///
    /// ⛔ WHY COMMITTING IT DOES NOT REPRODUCE THE 2026-08-14 STALL. That stall came from
    /// `sparse_acc.root_bytes()` — a root advanced by a LINEAR pre->post chain, which required replaying
    /// the producer's exact block ORDER (node A folded 47 blocks, node B folded 2 with 32 parked,
    /// `nf_root_agree=false` while `nf_acc_agree=TRUE`). This root is the `RefSparseNf` TREE's, whose
    /// leaves live in a sorted `BTreeSet`, so it is a function of the spent SET. MEASURED by
    /// `nf_sparse::db154_order_free_root`: 24 nullifiers, THREE insertion orders, ONE root; and a set
    /// missing one nullifier reaches a different root. Set-derived is exactly the property that makes
    /// A_tip safe to commit, so this commits on the same grounds.
    ///
    /// ZERO = this producer held no tree (a restarted or jumped node before its warm stream completes).
    /// Production and gossip are NEVER gated on it — the same law `nullifier_proof.fold` already states —
    /// so a treeless producer cannot halt the chain, and every node that DOES hold a tree still checks it.
    #[serde(default)]
    pub sparse_root: Hash32,
    /// O(1) advisory chain-accumulator digest (DOMAIN_CHAIN_ACC) folding the chain to this block.
    /// Carried so an instant-synced node references parents without their full bodies.
    pub chain_acc: [u8; 16],
    /// Confidential coinbase reward-note commitment (`crate::reward`). ZERO-ISSUANCE, and that half is
    /// real: there is no mint path for a reward anywhere in the tree, so the property holds by ABSENCE
    /// rather than by a check that could be disabled.
    ///
    /// ⛔ CORRECTED 2026-09-23 — THIS DOC USED TO SAY THE REWARD IS "a confidential spend of a
    /// fee/reserve-yield revenue note to the miner". IT IS NOT, AND NO SUCH SPEND EXISTS. Traced:
    /// `order_fill_fee_bps` reaches the circuit (`verify_order_fill`), where the taker half enforces
    /// `value_in = change + (pay_b + fee)` while the settlement's outputs are exactly three notes —
    /// maker payout, taker payout, taker change (`order_fill_tx`, "bounded by protocol constant 3 ...
    /// a settlement creates no other output"). The maker receives `pay_b`, not `pay_b + fee`, and NO
    /// output note carries `fee`. The fee is therefore BURNED — which is what `crate::liquidation`
    /// independently says it is ("the 10 bps order-fill burn ... lowers `L` with `R` untouched, so
    /// `R/L` rises with every trade"). Two docs described one value differently; the circuit settles it.
    ///
    /// So this field commits to a reward that is currently WORTH NOTHING: `crate::reward` derives an
    /// opaque per-node, block-unique digest and no value ever flows to it. The miner incentive is built
    /// in [`crate::economics`], which is the only place that may decide what funds it.
    pub miner_commitment: Hash32,
    /// ACCOUNT-INDEXED DA commitment: the O(1) running accumulator over this chain's account-bucket writes
    /// ([`crate::account_da`]). Folded into the header id, so a node cannot serve a wallet a bucket the chain
    /// never committed — which is what keeps an instant one-lookup restore SELF-VERIFYING instead of trusting
    /// whoever answered. Folds the CANONICAL `(bucket, note_cm)`, never the sealed bytes (those embed a
    /// node-local seq and would diverge between peers).
    #[serde(default)]
    pub account_root: Hash32,
    /// THE HEADER'S COMMITMENT TO THE BODY'S OUTPUT NOTES - `blake3(output_notes)`.
    ///
    /// Without it the id commits to `tx_merkle_root` (which tx IDS were selected) but NEVER to the note
    /// BYTES the block ships, so two nodes could hold the SAME block id with DIFFERENT `output_notes`: the
    /// producer assembles them from its own pool, the receiver stores whatever arrived, nothing notices.
    ///
    /// MEASURED, `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`, first divergence:
    ///   addr=91990819159692608: A=(1 chunk, 1153 B, [204,85,44,197,..]) B=(1 chunk, 1153 B, [216,202,125,14,..])
    /// Same canonical address (a pure function of the block id), same length, DIFFERENT note. From there the
    /// two nodes derive different leaves, different block roots and different `spend_frontier_root`s, so a
    /// wallet's witness verifies only on the node it happened to ask.
    ///
    /// A 32-byte COMMITMENT, not the payload: fixed size however many notes the block carries, so this adds
    /// no per-block growth. A block whose notes were altered in transit is now a DIFFERENT block.
    #[serde(default)]
    pub output_notes_root: Hash32,
    /// ⭐⭐⭐ DB-165 — THE HEADER'S COMMITMENT TO [`Block::note_commitments`].
    ///
    /// ⛔ AND IT IS NEVER THE EMPTY HASH, WHICH IS THE POINT. `output_notes_root == Hash32::hash(&[])` is
    /// how SIX call sites ask *"was this block IDLE?"* — a quiet/busy oracle sitting in the header, read
    /// by the fold, the shell door and the record path. The carrier is never empty, so this root cannot
    /// answer that question at all, and the sites that leaned on the sentinel must state their predicate
    /// some other way.
    #[serde(default)]
    pub note_commitments_root: Hash32,
    /// ⭐⭐⭐ THE HEADER'S COMMITMENT TO THE BODY'S NULLIFIER TAG SET — the spend-side twin of
    /// [`Self::output_notes_root`], and for the identical reason.
    ///
    /// `nullifier_root` commits the PRE-block accumulator, but nothing in the id committed to the TAGS the
    /// block ships (`NfBlockProof::padded_tags`) — and those tags are what every node folds into A_tip and
    /// records to its DA-nf shard. A relay could therefore strip or swap a block's tag set and re-prove the
    /// carried height-1 fold (it is publicly re-provable in ~0 ms), leaving two nodes holding the SAME block
    /// id while folding DIFFERENT spend sets. Before the accept-time fold that made the block park forever
    /// on honest nodes (a silent liveness attack); with the fold now unconditional it would instead diverge
    /// their accumulators, so the binding must close it at the id.
    ///
    /// `blake3(tag0 ‖ tag1 ‖ …)` over the block's tags in order — a 32-byte COMMITMENT, never the payload,
    /// so it is the same size whatever the block's spend count and adds no per-block growth. A block whose
    /// tag set was altered in transit is now a DIFFERENT block, and fails `validate_structural` outright.
    #[serde(default)]
    pub nullifier_tags_root: Hash32,
    /// ⭐⭐⭐ P4′a — THE HEADER'S COMMITMENT TO THE BODY'S LOCATOR TAGS ([`Block::oli_tags`]).
    ///
    /// The FINDABILITY twin of [`Self::output_notes_root`]. A note's ciphertext being on chain is only half
    /// of "the money is there": without its locator tag the note is in NO index, so its owner cannot find it
    /// from their seed and cannot spend it. Measured that exact way on 2026-08-10 — node A indexed 4 tags,
    /// node B ingested the same blocks and indexed 2, and send 2's notes sat on chain invisible to their
    /// owner. Carrying the tags on the block fixed the ingest race; this closes the other half, because a
    /// carried-but-unbound sidecar can be STRIPPED in flight (or by a backfill peer) with the block id
    /// unchanged — which is silent fund loss, not a detectable attack.
    ///
    /// This is what makes the P4′b re-derivation SOUND: a restarted node rebuilds its locator index from
    /// tags it fetched from an arbitrary peer, and it can only trust them because the id binds them.
    ///
    /// `blake3(oli_tags)` — a 32-byte COMMITMENT, never the payload, so it is the same size whatever the
    /// block's real-note count and adds no per-block growth.
    #[serde(default)]
    pub oli_tags_root: Hash32,
    /// ⭐⭐⭐ P4′a — THE HEADER'S COMMITMENT TO THE BODY'S ACCOUNT-DA TARGETS ([`Block::account_targets`]).
    ///
    /// Same reasoning as [`Self::oli_tags_root`], for the other findability sidecar: the targets are what
    /// file a note into its owner's account bucket on EVERY node, and `account_root` commits the resulting
    /// accumulator but never the target BYTES that produced it. A relay that strips them leaves a peer
    /// filing nothing while holding the same block id — the measured "recipient's node serves an empty
    /// bucket" failure.
    ///
    /// `blake3(account_targets)` — 32 bytes, constant whatever the block carries.
    #[serde(default)]
    pub account_targets_root: Hash32,
    // (the unspent-tree deletion set and its header commitment were retired on 2026-09-22 — spends are
    //  refused by the nullifier accumulators; see docs/UNSPENT-SET-UNLINKABILITY-DESIGN.md)
    /// ⭐⭐⭐ THE HEADER'S COMMITMENT TO THE BODY'S VALIDATOR-BOND SET ([`Block::bond_set`]).
    ///
    /// The FINALITY twin of [`Self::del_set_root`], closing the same "a block must carry what applies
    /// it" gap for the bonded-validator set. Bond admission used to run ONLY in the producer's produce
    /// path, from its own mempool's tx bodies — so the ONE node that produced the bond block held
    /// `validators=1` and voted, while every ingesting peer, every DSYNC joiner and every restarted
    /// node derived `validators=0`, rejected those votes at the `bond_of(voter)==0` gate, and reported
    /// `finalized_height=0` forever. MEASURED 2026-08-22 on the live pair: origin
    /// `{"validators":1}` + finality advancing 2148→2192, joiner `{"validators":0}` +
    /// `finalized_height:0` across every sample while ingesting the same blocks.
    ///
    /// `blake3(bond_set)` — a 32-byte COMMITMENT, never the payload, so a stripped or swapped bond
    /// set is a DIFFERENT block (`validate_structural` refuses it), never a quietly divergent one.
    #[serde(default)]
    pub bond_set_root: Hash32,
    /// ⭐⭐⭐ THE HEADER'S COMMITMENT TO THE BODY'S DIRECTORY SET ([`Block::dir_set`]) — the on-chain
    /// @username + Letter-group registrations this block applies. The DISCOVERY twin of `bond_set_root`:
    /// a directory (usernames, group listings) is CONSENSUS-ORDERED state that every node must reconstruct
    /// identically by FOLDING the chain — NOT a per-node disk cache (which was a pre-DA artifact that made
    /// local disk a mini-authority, violating DA-is-the-ledger + no-local-storage). Each carried entry is
    /// ML-DSA-authenticated and re-verified at apply, so first-come/owner-continuity is decided by canonical
    /// chain order, not a gossip race. `blake3(dir_set)` — a 32-byte COMMITMENT, never the payload, so a
    /// stripped or swapped registration is a DIFFERENT block (`validate_structural` refuses it).
    #[serde(default)]
    pub dir_set_root: Hash32,
    /// ⭐⭐⭐ THE HEADER'S COMMITMENT TO THE BODY'S LETTER SET ([`Block::letter_set`]) — the on-chain anchor
    /// of the Letter messenger's DA content stream. The block carries only 32-byte COMMITMENTS (constant
    /// cover-padded shape, [`crate::letter::LETTER_CMS_PER_BLOCK`]); the sealed blobs ride the record layer's
    /// letter lane and every fetched blob is VERIFIED against these committed values (a forged or swapped
    /// backfill blob is refused fail-closed). `blake3(letter_set)` — 32 bytes, constant whatever the real
    /// mail volume, so a stripped or swapped set is a DIFFERENT block.
    #[serde(default)]
    pub letter_set_root: Hash32,
    /// ⭐ PRIVATE SHARDING §2.2 — the header's commitment to [`Block::tag_evidence`], so a relay that strips or replaces a block's
    /// evidence makes a different block. A 32-byte commitment, the same size whatever the evidence holds.
    #[serde(default = "crate::block::empty_tag_evidence_root")]
    pub tag_evidence_root: Hash32,
    /// ⭐ JOINING BY WORK (`crate::join_proof`): the root of this block's level array, checked at graft like any other header rule.
    pub level_root: Hash32,
    /// The producer's newest fold position and commit. Never a reason to refuse a block: a wrong one only fails to vouch.
    pub fold_ordinal: u64,
    pub fold_commit: Hash32,
    /// The producer's newest band position and commit. Separate, because a node's band legally lags its fold.
    pub band_ordinal: u64,
    pub band_commit: Hash32,
    /// ⭐⭐⭐ §BA — THE HEADER'S COMMITMENT TO THE BODY'S CREDIT SET ([`Block::credit_set`]).
    ///
    /// The JUSTIFICATION sidecar. Every other root above commits to something the block MOVES; this one
    /// commits to the evidence that the block was ALLOWED to move it. A note that no spend published and
    /// no transaction this node resolved can justify used to be received on the producer's word — §BA,
    /// measured as `peer RECORDED it=true · peer holds it UNSPENT=true` for a commitment the producer
    /// simply invented. The credit set carries the framed CHAIN OBJECT that authorises each such note, so
    /// a peer holding no transaction body can still check it: `chain_object::admissible` on the object's
    /// own bytes, then `carried_note_payloads` must name the commitment.
    ///
    /// It binds UNCONDITIONALLY like every root above it, and for the sharper reason: an unbound
    /// justification sidecar is not a sidecar at all — a relay would simply append the object that excuses
    /// whatever note it wanted to plant. `da_sidecar_root_of` over the carried bytes, 32 B per header
    /// whatever the block carries, so it takes no term in height, notes or spends.
    #[serde(default)]
    pub credit_set_root: Hash32,
    /// ⭐⭐⭐ DB-223 — THE HEADER'S COMMITMENT TO THE BODY'S CARRIED TRANSITIONS ([`Block::note_transition`],
    /// [`Block::cover_transition`], [`Block::member_transition`]), [`transitions_root_of`].
    ///
    /// They are the ONLY evidence a peer that holds no transaction body has for a block's spend outputs (§BA) and,
    /// from DB-223, for its spends' inputs. Unbound, a relay could STRIP a genuine one and the copy would keep the
    /// block's id: a peer grafting the stripped copy refuses the outputs a peer with the full copy records, and the
    /// real copy can never repair it (a duplicate id). Bound, a stripped or replaced transition is a DIFFERENT body
    /// under this header and the gossip door refuses it (`consensus::body_commitments_admit`). UNCONDITIONAL like
    /// every root above: an absent transition commits a fixed marker, never a skip. 32 B per header, constant.
    #[serde(default)]
    pub transitions_root: Hash32,
    /// §RF-3 (padding spec v2 §2.4, C2) — THE COMMITMENT TO THE PRODUCER'S HEADER SEED: `P(HEADER_SEED_DOMAIN ‖ seed)`
    /// (`usdm_decider::slot_ledger::seed_commit_native`), its 8 canonical lanes as u32 LE. The seed itself is the
    /// producer's private randomness — never carried, never derivable — and drives every cover tag and cover note
    /// commitment of the block's slot ledger; this word is the ONE public cell the ledger aggregate binds on every row,
    /// so the door rebuilds the statement from the header alone. Bound into the id, so a swapped commit is a DIFFERENT
    /// block. Every block that does not carry a ledger commits `Hash32::ZERO` (no seed has that commit).
    /// cons: 32 B per header, constant; headers are not retained, so zero permanent state.
    #[serde(default)]
    pub cover_seed_commit: Hash32,
    /// §RF-3 — THE ANCHOR OF THE BLOCK'S MEMBER LEDGER (Zcash Sapling shape: a spend names an anchor, a prior tree
    /// root, and the node checks it against its root HISTORY): `member_ring::ring_digest_of` of the anchor ring the
    /// producer proved its member ledger under. The ring digest is a PUBLIC INPUT of that proof and producers sit at
    /// different fold positions at DAG width > 1, so a peer can never verify under its OWN ring; it verifies under this
    /// word and the fold refuses a word absent from the canonical ring-digest history. Bound into the id, so a swapped
    /// anchor is a DIFFERENT block. Every block that carries no member ledger commits `Hash32::ZERO`.
    /// cons: 32 B per header, constant; headers are not retained, so zero permanent state.
    #[serde(default)]
    pub member_ring_commit: Hash32,
}

/// §RF-3 — THE ONE SPELLING of a header seed's commitment as the header's word: the 8 lanes of
/// `usdm_decider::slot_ledger::seed_commit_native(seed)`, each a canonical KoalaBear element, as u32 LE. The producer
/// writes it with this and the door reads it back with [`cover_seed_commit_lanes`]; no second encoder exists.
#[must_use]
pub fn cover_seed_commit_of(seed: usdm_decider::poseidon2_compress::Digest) -> Hash32 {
    let lanes = usdm_decider::slot_ledger::seed_commit_native(seed);
    let mut b = [0u8; 32];
    for (c, v) in lanes.iter().enumerate() {
        b[4 * c..4 * c + 4].copy_from_slice(&(*v as u32).to_le_bytes());
    }
    Hash32(b)
}

/// The door's read of `cover_seed_commit`: its 8 lanes, or `None` when a lane is not a canonical KoalaBear element (a
/// non-canonical word would name one commit by two headers — one consensus object, one encoding).
#[must_use]
pub fn cover_seed_commit_lanes(h: &Hash32) -> Option<usdm_decider::poseidon2_compress::Digest> {
    use p3_field::PrimeField64;
    let p = <usdm_decider::hiding_decider::Fa4 as PrimeField64>::ORDER_U64;
    let mut d = [0u64; usdm_decider::poseidon2_compress::DIGEST_LANES];
    for (c, w) in h.as_bytes().chunks_exact(4).enumerate() {
        let v = u64::from(u32::from_le_bytes([w[0], w[1], w[2], w[3]]));
        if v >= p {
            return None;
        }
        d[c] = v;
    }
    Some(d)
}

#[cfg(all(test, feature = "pins-core"))]
mod cover_seed_commit_tests {
    /// §RF-3 — the header word round-trips to the ledger's bound lanes, distinct seeds commit apart, and a non-canonical
    /// lane is refused (the tamper that must REJECT).
    #[test]
    fn the_header_seed_commit_round_trips_and_a_non_canonical_word_is_refused() {
        let (s1, s2) = ([1u64, 2, 3, 4, 5, 6, 7, 8], [9u64, 2, 3, 4, 5, 6, 7, 8]);
        let h1 = super::cover_seed_commit_of(s1);
        assert_eq!(super::cover_seed_commit_lanes(&h1), Some(usdm_decider::slot_ledger::seed_commit_native(s1)));
        assert_ne!(h1, super::cover_seed_commit_of(s2), "two seeds, one commit");
        assert_ne!(h1, crate::hash::Hash32::ZERO, "a real seed commits ZERO — the no-ledger marker is ambiguous");
        let mut bad = h1;
        bad.0[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(super::cover_seed_commit_lanes(&bad), None, "⛔ a non-canonical lane was read as a commit");
    }
}

/// ⭐ DB-223 — THE ONE definition of a block's transitions commitment, used by the producer to SEAL
/// [`BlockHeader::transitions_root`] and by every verifier to CHECK it. blake3 over a domain tag and, for each of the
/// note, cover and member transitions in that order, a presence byte and (when present) the length-prefixed postcard
/// encoding. An absent transition is the presence byte 0 — a claim like any other, never a skip. (DB-353's band
/// transition rode here as a fourth part for one day and left again: the band travels by RELAY, never in a block —
/// docs/DB-353-BAND-DOOR-SPEC.md §11.10.)
pub fn transitions_root_of(
    note: Option<&crate::note_transition::NoteTransition>,
    cover: Option<&crate::note_transition::CoverTransition>,
    member: Option<&crate::member_transition::MemberTransition>,
) -> Hash32 {
    let mut buf = b"MUSD/block-transitions/v1".to_vec();
    let mut part = |enc: Option<Result<Vec<u8>, postcard::Error>>| match enc {
        None => buf.push(0),
        Some(Ok(bytes)) => {
            buf.push(1);
            buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            buf.extend_from_slice(&bytes);
        }
        // An unencodable transition commits a distinct marker, so it can never collide with a real one.
        Some(Err(_)) => buf.push(2),
    };
    part(note.map(postcard::to_allocvec));
    part(cover.map(postcard::to_allocvec));
    part(member.map(postcard::to_allocvec));
    Hash32::hash(&buf)
}

/// The transitions commitment of a block that carries none (genesis, idle blocks, header literals).
pub fn empty_transitions_root() -> Hash32 {
    transitions_root_of(None, None, None)
}

/// THE ONE definition of a block's nullifier-tag commitment — used by the producer to SET
/// `BlockHeader::nullifier_tags_root` and by every verifier to CHECK it, so the two can never drift.
/// `blake3(tag0 ‖ tag1 ‖ …)` in the block's own tag order; an empty set commits `blake3("")`.
pub fn nullifier_tags_root_of(tags: &[[u8; 32]]) -> Hash32 {
    let mut buf = Vec::with_capacity(tags.len() * 32);
    for t in tags {
        buf.extend_from_slice(t);
    }
    Hash32::hash(&buf)
}

/// THE ONE definition of a carried DA sidecar's commitment — used by the producer to SET
/// [`BlockHeader::oli_tags_root`] / [`BlockHeader::account_targets_root`] and by every verifier to CHECK
/// them, so producer and verifier can never drift. Both sidecars are already flat `Vec<u8>` wire payloads,
/// so the commitment is `blake3(bytes)` exactly as `output_notes_root` is; an absent sidecar commits
/// `blake3("")`, which is a real value and not a skip — an empty carry is a claim like any other.
pub fn da_sidecar_root_of(bytes: &[u8]) -> Hash32 {
    Hash32::hash(bytes)
}

/// ⭐⭐⭐ THE NOTE PAYLOAD'S COMMITMENT IS A CHUNK-MERKLE ROOT, NOT A FLAT HASH — AND THAT IS WHAT MAKES
/// A SHARE POSSIBLE AT ALL.
///
/// Every other sidecar is small and stays `blake3(bytes)`. `output_notes` is the bulk — 1,153 bytes per
/// real note, the one payload that grows — and a flat hash can only be checked by whoever holds the WHOLE
/// thing. That single property is why `da_mem` holds whole records on every node, why `src/da.rs` (the
/// chunk/merkle/sample primitive) has had ZERO CALLERS since it was written, and why a dozen comments
/// across this tree describe note ciphertexts as *"peer-sampled DA (#27 DAS)"* while the node is in fact
/// an implicit full archive.
///
/// A chunk-merkle root changes exactly one thing, and it is the thing that matters: **a node can hold a
/// SUBSET of the chunks and still prove each one it holds.** That is the precondition for erasure-coded
/// shares, for coordinate-assigned shards, and for a node whose stored bytes do not track the network's
/// total data. Nothing downstream of it is possible without it.
///
/// ⛔ THE EMPTY CASE KEEPS THE OLD SENTINEL, DELIBERATELY. `output_notes_root == Hash32::hash(&[])` is
/// how six separate call sites ask *"was this block IDLE?"* — `regenerate_idle_record` leans on it, and
/// `da::commit(&[])` would answer with the merkle root of one zero chunk instead. The sentinel is part of
/// the consensus meaning of the field, not an implementation detail of the hash.
///
/// ⛔ THIS IS A CONSENSUS CHANGE: the header binds this root and the block id folds the header, so every
/// note-carrying block gets a new id. It rides the §AG re-genesis rather than adding a second one.
///
/// ⭐⭐⭐ G1-DA — ONE COMMITMENT, THE BLOB SHAPE (borrowed: EIP-4844 — a blob is a FIXED width, its unused tail
/// zero-padded, and the commitment is over the whole fixed blob). The root is the chunk-merkle of the RAW carried
/// notes zero-padded to [`DA_NOTES_BLOB_BYTES`], so it always commits [`crate::node::Node::da_record_chunk_count`]
/// chunks: a sampler that holds no byte of the record knows the shape from the protocol, and the holder serves
/// chunks of the SAME bytes ([`da_notes_commit_of`]). MEASURED before (scratchpad/night/pin-g1d-da-20261023.log):
/// the holder served the assembled 256-slot cover record while the header committed the raw bytes, so no honest
/// answer ever verified (bf9755d1 ≠ c0fad7d3). The assembled form cannot be the commitment: its cover is seeded by
/// the record address, which is derived from the block id, which folds this root.
/// cons: one 295,168-byte zero-padded buffer + blake3 per call on a note-carrying block (~0.1–0.3 ms; idle blocks
/// keep the sentinel and pay nothing); no wire, disk or state change.
#[must_use]
pub fn da_notes_root_of(bytes: &[u8]) -> Hash32 {
    if bytes.is_empty() {
        return Hash32::hash(&[]); // the IDLE sentinel — unchanged, and load-bearing
    }
    da_notes_commit_of(bytes).root
}

/// The fixed DA blob width of a block's note payload: the 256-slot cover shape. A body wider than this is refused
/// ([`crate::consensus::ConsensusError::OutputNotesOverWidth`]) — otherwise its tail would sit past every
/// sampler's index range, committed yet never probed.
pub const DA_NOTES_BLOB_BYTES: usize = crate::cover::BLOCK_FIXED_NOTE_COUNT * crate::cover::PQ_NOTE_BYTES;

/// The chunk commitment behind [`da_notes_root_of`] — THE ONE the producer seals, every verifier checks and every
/// holder serves pieces of. Raw carried notes, zero-padded to [`DA_NOTES_BLOB_BYTES`].
#[must_use]
pub fn da_notes_commit_of(bytes: &[u8]) -> crate::da::DaCommit {
    let mut blob = bytes.to_vec();
    if blob.len() < DA_NOTES_BLOB_BYTES {
        blob.resize(DA_NOTES_BLOB_BYTES, 0);
    }
    crate::da::commit(&blob)
}

impl BlockHeader {
    /// The canonical, deterministic, length-prefixed encoding of every header field in a fixed order —
    /// the exact bytes [`Self::id`] hashes AND the #73 PQ-PoUW preimage grinds over (it folds `nonce`
    /// + `pow_bind = H(pi)`, so a valid PoUW hash requires both the grind and the non-outsourceable
    /// spend-key proof). Any tamper (including reordering parents) changes these bytes.
    pub fn preimage(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(320);
        b.extend_from_slice(&self.version.to_le_bytes());
        b.extend_from_slice(&(self.parents.len() as u32).to_le_bytes());
        for p in &self.parents {
            b.extend_from_slice(p.as_bytes());
        }
        b.extend_from_slice(&self.timestamp.to_le_bytes());
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.work.to_le_bytes());
        b.extend_from_slice(self.pow_bind.as_bytes());
        b.extend_from_slice(self.tx_merkle_root.as_bytes());
        b.extend_from_slice(self.frontier_root.as_bytes());
        b.extend_from_slice(self.nullifier_root.as_bytes());
        b.extend_from_slice(&self.chain_acc);
        b.extend_from_slice(self.miner_commitment.as_bytes());
        b.extend_from_slice(self.account_root.as_bytes());
        b.extend_from_slice(self.output_notes_root.as_bytes());
        // DB-165: the constant-width note carrier binds UNCONDITIONALLY, exactly like every root above
        // it. A relay that stripped or swapped the carrier would otherwise keep the block id while
        // changing which notes the block commits — the precise hole header binding exists to close.
        b.extend_from_slice(self.note_commitments_root.as_bytes());
        b.extend_from_slice(self.nullifier_tags_root.as_bytes());
        // P4′a — the two findability sidecars. A note nobody can LOCATE is a note nobody can spend, so these
        // belong in the id for the same reason `output_notes_root` does: a stripped sidecar must produce a
        // DIFFERENT block, not a quietly poorer one.
        b.extend_from_slice(self.oli_tags_root.as_bytes());
        b.extend_from_slice(self.account_targets_root.as_bytes());
        // The deletion sidecar binds UNCONDITIONALLY, exactly like every root above it — a conditional
        // fold ("only when non-zero") would let a relay zero the root, strip the sidecar and keep the
        // id, which is the precise hole header binding exists to close.
        // The bond sidecar binds UNCONDITIONALLY for the same reason: a stripped bond set must be a
        // DIFFERENT block, never a quietly finality-blind one.
        b.extend_from_slice(self.bond_set_root.as_bytes());
        // The directory sidecar binds UNCONDITIONALLY, exactly like every root above it — a stripped or
        // swapped @username/group registration must produce a DIFFERENT block, never a quietly divergent
        // directory (the same soundness the disk-cache design could not give).
        b.extend_from_slice(self.dir_set_root.as_bytes());
        // The letter sidecar binds UNCONDITIONALLY too — a stripped or swapped letter-commitment set must be
        // a DIFFERENT block, so a relay can never quietly drop a private message's anchor while keeping the id.
        b.extend_from_slice(self.letter_set_root.as_bytes());
        b.extend_from_slice(self.tag_evidence_root.as_bytes());
        b.extend_from_slice(self.level_root.as_bytes());
        b.extend_from_slice(&self.fold_ordinal.to_le_bytes());
        b.extend_from_slice(self.fold_commit.as_bytes());
        b.extend_from_slice(&self.band_ordinal.to_le_bytes());
        b.extend_from_slice(self.band_commit.as_bytes());
        // The CREDIT sidecar binds UNCONDITIONALLY, and it is the one root where a conditional fold would
        // be self-defeating: it carries the evidence that this block's non-spend notes were authorised, so
        // a relay able to append to it could excuse any note it liked. A stripped or extended credit set
        // must be a DIFFERENT block.
        b.extend_from_slice(self.credit_set_root.as_bytes());
        // DB-223: the carried transitions bind UNCONDITIONALLY too — a stripped or replaced §BA / membership
        // justification must be a DIFFERENT block, never a copy that keeps this id.
        b.extend_from_slice(self.transitions_root.as_bytes());
        // The AMM sidecar binds UNCONDITIONALLY as well: a settlement MOVES VALUE, so a relay that strips
        // or substitutes a settlement must produce a different block rather than a chain whose pools
        // quietly disagree between nodes.
        // cons: none — 32 B per header, which is f(fixed constants): it does not grow with pools, with
        // settlements, or with height. Arithmetic: a block already carries 256 × 1153 B ≈ 295 KB of note
        // payload, so this root is ~0.011% of a block, and headers are not retained (the node keeps an
        // O(1) frontier, `blocks_in_memory` ≪ `blocks`), so it adds ZERO permanent state.
        // §RF-3: the header-seed commitment binds UNCONDITIONALLY (a block without a ledger commits ZERO, never a skip).
        b.extend_from_slice(self.cover_seed_commit.as_bytes());
        // §RF-3: the member ledger's ring anchor binds UNCONDITIONALLY too (ZERO when no member ledger, never a skip).
        b.extend_from_slice(self.member_ring_commit.as_bytes());
        b
    }

    /// The block id: blake3 over [`Self::preimage`]. Any tamper changes the id.
    pub fn id(&self) -> BlockId {
        Hash32::hash(&self.preimage())
    }

    /// A header with no parents is the genesis block (the single root of the DAG).
    pub fn is_genesis(&self) -> bool {
        self.parents.is_empty()
    }
}

/// A block = its header + the ids of the PQ txs it includes. The tx BODIES live in the mempool /
/// validium DA; the header's `tx_merkle_root` commits to exactly this ordered id list, so a node
/// verifies inclusion without holding the bodies (validium).
/// ⭐⭐⭐ THE CANONICAL GENESIS BLOCK — HEADER **AND** BODY, ONE DEFINITION.
///
/// [`genesis_header`] already existed and every caller used it, but the BODY stayed hand-rolled at each
/// call site, so every new `Block` field silently broke whichever callers were not compiled that day.
///
/// ⛔ MEASURED TWICE ON THE SAME FILE. `tests/psm_bridge_e2e.rs` carries its own note that it "stopped
/// compiling the moment those landed" when `account_root … del_set_root` were added — fixed then by
/// adopting `genesis_header()` for the header. On 2026-09-17 it was found broken AGAIN, this time on the
/// body: `error[E0063]: missing field 'credit_set'`, added by §BA/§BB on 2026-09-15. **It had not
/// compiled, and therefore had not run, for two days** — and because that suite is gated behind
/// `--features bridge-test-oracle`, an ordinary `cargo test` never built it and nothing said so.
///
/// ⭐ A TEST THAT EXISTS IS NOT A TEST THAT RUNS. That suite is the ONLY end-to-end coverage of the real
/// USDm mint door, so for two days the peg's deposit gate, threshold, replay and conservation defences
/// were credited to a binary that did not exist. Adding a field to `Block` must never again be able to
/// silently retire it.
pub fn genesis_block() -> Block {
    genesis_block_with_header(genesis_header())
}

/// The canonical genesis block for a NAMED NETWORK — the same body, bound to that network's header.
///
/// ⛔ THE WALLET NEEDED THIS AND DID NOT HAVE IT, so it hand-rolled the body and fell behind. MEASURED
/// 2026-09-17: `monerousd-wallet-v2` did not COMPILE against the live node —
/// `error[E0560]: struct Block has no field named 'settlement'`, a field replaced by `note_transition` in
/// §CB on 2026-09-15. The wallet had been broken for two days and nothing said so, because the node's
/// `cargo test` never builds the wallet tree. Identical rot to `tests/psm_bridge_e2e.rs`, in a second
/// tree: **a hand-rolled copy of a consensus struct is a clock that starts running the moment it is
/// written.** The fork-detector this feeds computes the chain id a node must agree with, so a wallet
/// building a shape the node no longer produces reports a fork that does not exist.
pub fn genesis_block_for_network(prefix: &[u8]) -> Block {
    genesis_block_with_header(genesis_header_for_network(prefix))
}

fn genesis_block_with_header(header: BlockHeader) -> Block {
    Block {
        header,
        tx_ids: Vec::new(),
        pow_proof: Vec::new(),
        output_notes: Vec::new(),
        cover_key: None,
        wide_objects: Vec::new(),
        tx_bodies: Vec::new(),
        agg_tables: Vec::new(),
        oli_tags: Vec::new(),
        account_targets: Vec::new(),
        note_commitments: Vec::new(),
        bond_set: Vec::new(),
        note_transition: None,
        cover_transition: None,
        member_transition: None,
        nullifier_proof: NfBlockProof::default(),
        dir_set: Vec::new(),
        letter_set: Vec::new(),
        tag_evidence: Vec::new(),
        credit_set: Vec::new(),
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub tx_ids: Vec<Hash32>,
    /// #73 non-outsourceable PoUW proof `pi` (witness, NOT in the id): the #142 hashless WHIR light-decider
    /// carrier (~45KB, retiring the old 4 MiB STARK) proving the miner holds the coinbase spend key opening
    /// `header.miner_commitment` (retired 2026-09-18: pinned to ZERO, the coinbase bind is gone). The
    /// header commits to it via `pow_bind = H(pi)`, so it cannot be swapped; consensus recomputes the
    /// challenge, verifies `pi`, and checks the PQ-PoUW target ([`crate::pow::verify_block_pow`]). Empty on
    /// genesis (no miner) and on a #29 DSYNC anchor (the tip is certified by the decider proof, not re-mined).
    #[serde(default)]
    pub pow_proof: Vec<u8>,
    /// ⭐⭐⭐ §BA/§BB — THE BLOCK'S NOTE TRANSITION (witness, NOT in the id — like `pow_proof`): ONE bound
    /// aggregate plus the tuple list it stands over, so a peer holding NONE of this block's transaction
    /// bodies can still tell a real output note from one the producer invented. A peer recomputes
    /// `rows_digest` from the list, verifies once, and then admits an output note only if a VERIFIED
    /// spend published its commitment — the ALLOW-list `graft_admitted_notes` could never have.
    ///
    /// ⛔ THIS SLOT USED TO HOLD `settlement: Option<Vec<u8>>`, and that field is GONE rather than kept
    /// beside this one. It carried task #144's aggregate, which verified over ZERO ROWS with no inner
    /// carrier — anyone could produce one for any tx set (§BD, closed in §BZ) — and the entire point of
    /// the slot ("verify this ONE proof and settle the WHOLE block") is to be GRANTED on. Two fields,
    /// one sound and one forgeable, is how a caller grants on the wrong one.
    ///
    /// `None` is always legal and never blocks production or acceptance (liveness): a block with no
    /// spends has no transition to certify, and a peer then admits no notes from it rather than
    /// admitting them on the producer's word.
    #[serde(default)]
    pub note_transition: Option<crate::note_transition::NoteTransition>,
    /// ⭐⭐⭐ THE CONSTANT-WIDTH HALF OF THE SAME JUSTIFICATION (DB-83). `note_transition` states
    /// single-input spends; this states every carried tag of every constant-width transaction, with the
    /// real-input count hidden by a witness selector. A block may carry either, both, or neither, and a
    /// peer judges each on its own — `verify_cover` yields the tags it ADMITS and nothing else.
    #[serde(default)]
    pub cover_transition: Option<crate::note_transition::CoverTransition>,
    /// ⭐⭐⭐ DB-223 — THE MEMBERSHIP TRANSITION ([`crate::member_transition`]): one aggregate over the block's spend
    /// inputs' member-path carriers (each proved by its WALLET over its own depth-64 path), plus the tuple list it
    /// stands over. It is the block path's evidence that every spend's input EXISTS under an anchor the door checks
    /// against its own ring — naming no record. Bound into the id by `BlockHeader::transitions_root` with the two
    /// transitions above. `None` is legal (a block with no spends carries none).
    #[serde(default)]
    pub member_transition: Option<crate::member_transition::MemberTransition>,
    /// TRUSTLESS O(1) nullifier carry (witness data, NOT in the id — like `pow_proof`/`settlement`): the Gap-3
    /// recursive block proof certifying this block's WHOLE nullifier transition `header.nullifier_root` (pre) →
    /// [`NfBlockProof::post_root`] over its real spends PLUS the secret-seeded COVER decoys, padded to exactly
    /// [`crate::cover::BLOCK_FIXED_NULLIFIER_COUNT`]. Carrying the ½-MB copath witness set per block would blow the
    /// ≤1.8MB FAST pillar + the gossip budget (a per-block growth axis); this ~KB WHIR carrier instead lets a
    /// treeless VERIFIER check the transition in O(1) (`usdm_decider::nullifier_insert_air::
    /// verify_nullifier_block_carrier_bytes`) — no set stored, no copath replay, no trusted party (a forged
    /// carrier / tampered post-root fails-closed). The block's cover-count is constant, so the transition (and its
    /// carrier size) is identical every block regardless of real spend volume (digital-cash volume privacy).
    /// Empty carrier ONLY on genesis / cover-only / #29 DSYNC anchors ([[feedback_always_trustless]]
    /// [[feedback_no_growth_any_axis]] [[project_trustless_nullifier_o1_design]]).
    #[serde(default)]
    pub nullifier_proof: NfBlockProof,
    /// ⭐ THE BLOCK'S REAL OUTPUT NOTES (witness, NOT in the id — like `pow_proof`): the concatenated 1153-byte
    /// confidential note payloads this block settles. They RIDE THE BLOCK because a note is REPLICATED DATA that
    /// every node must record, and a node cannot reconstruct them from its own mempool: a peer that never
    /// admitted the tx (its spend gate verifies against ITS OWN accumulator state, so a gossiped tx can be
    /// refused there while being perfectly valid) holds no tx body, and so recorded NOTHING for a block that
    /// carried a real payment. That is precisely how a cross-device send was lost: the sender's node recorded
    /// both notes, the RECIPIENT'S node recorded zero, and the recipient's wallet — which talks only to its own
    /// node — could never see the money. Carrying them makes every grafting node record the SAME notes
    /// regardless of what its local pool happened to accept. A producer that omits or pads them can only harm
    /// its own block's recipients; the notes are opaque ciphertexts, so a forged one is simply unopenable and
    /// unspendable by anyone.
    ///
    /// ⛔⛔⛔ DB-165 — THIS FIELD NO LONGER TRAVELS. `#[serde(skip)]` keeps it in memory, where 300+ call
    /// sites read it, and takes it off the WIRE, where its LENGTH stated the block's real note count
    /// (MEASURED 2026-09-24: 0 B on a quiet block, 5,765 B on a busy one = exactly five notes).
    ///
    /// It was always a DUPLICATE: the producer builds it as
    /// `block_spendable_note_blobs(&tmpl.tx_ids)`, so it is a pure function of the block's own `tx_ids`
    /// plus the txs those ids name. Carrying it on the wire broke "one consensus object has ONE
    /// encoding" AND handed every node the input to `block_cover_secret(real_notes, seq)`, which is what
    /// let any node regenerate the DA record's 251 cover slots and name the real ones.
    ///
    /// A receiver REHYDRATES it from `tx_ids` and checks each derived note against
    /// [`Block::note_commitments`] — so §BA still holds ("a grafted block's notes must be justified by
    /// the block itself, never by local state"): the COMMITMENT is the justification, and a peer cannot
    /// record a different note than the one the block committed. A peer missing a tx now DETECTS exactly
    /// which slot it lacks instead of silently recording whatever it had.
    #[serde(skip)]
    pub output_notes: Vec<u8>,
    /// ⭐ §20.2 — THE RECORD'S COVER KEY beside the body it keys (`cover::CoverKey`): drawn fresh by the producer, it travels
    /// exactly as `output_notes` does — in process with a held body, NEVER on the wire (a peer receives it with the reals on
    /// the record lane, the sidecar page or a checkpoint row). `None` with a held body is a body no door can bind.
    #[serde(skip)]
    pub cover_key: Option<crate::cover::CoverKey>,
    /// ⭐ §22b — THE WIDE OBJECTS beside the body (Bitcoin BIP152's shape: the block names what it applies, the bytes
    /// travel beside it). A chain object whose carriage is wider than [`CREDIT_INLINE_MAX`] rides the sealed credit set
    /// as a 40-byte reference (`wide_ref_of`: its carriage's hash, bound into the id through the sealed root); its bytes
    /// are held HERE, in process with the body, and travel node-to-node in the gossip envelope beside the cover key —
    /// never in the hashed block (which stays one constant shape) and never on a wallet route. A reader resolves every
    /// reference against these bytes by hash ([`credit_set_iter`]); an unresolved reference is UNREADABLE, never empty.
    #[serde(skip)]
    pub wide_objects: Vec<Vec<u8>>,
    /// ⭐ §22c (audit F14, 2026-11-10) — THE BLOCK'S SPENDS beside the body: the encoded transaction (`postcard(PqTx)`) of
    /// every ordinary send this block states, in `tx_ids` order (Bitcoin: a block is its header AND its transactions;
    /// BIP152's shape for the wire: the hashed block names them by id, the bytes travel beside it).
    ///
    /// WHY, MEASURED: the block's aggregate lays each spend's carrier from its BYTES and never checks the carrier's own
    /// opening proof, so a block stating a spend no wallet proved verified
    /// (`usdm-decider` `producer_forgery_tests::a_block_cannot_state_a_spend_whose_carrier_nobody_proved`). Checking every
    /// opening inside the block proof is about 180 times today's block proof, so the rule is the one every other class of
    /// this chain already obeys (a framed object is judged natively at the block door, `chain_object::admissible`): every
    /// node verifies every transaction a block states, itself. A node cannot do that for bytes it does not hold, so the
    /// bytes ride the block: in process with the body, node-to-node in the gossip envelope ([`gossip_encode`]) beside the
    /// cover key, NEVER in the hashed block (one constant shape) and never on a wallet route.
    /// cons: about 0.5 MB per stated spend per block hop until peers skip bodies they already hold (compact relay); kept
    /// with the body for the block window, dropped with its proofs.
    #[serde(skip)]
    pub tx_bodies: Vec<Vec<u8>>,
    /// ⭐ THE LEVEL AGGREGATE (lane agg, docs/LEVEL-AGGREGATE-SPEC-20261115.md §12–§13) — the block's ROOT, beside its
    /// bodies: a body in TREE form carries no carrier, and this one proof (`crate::agg_root::verify_root`) proves every
    /// tree-form body's statement at once, in carried order. Exactly one entry when the block carries a tree-form body,
    /// none otherwise (`spend_evidence::block_spends_are_evidenced`). Witness, NOT in the id (as `pow_proof`): the
    /// statements it proves are the bodies' own fields, which `tx_bodies_commit` binds, and `carried_commit` binds the
    /// root beside them. Rides only where the bodies ride (the peer tail, [`gossip_encode`]), so a tree-form payment's
    /// count is seen by exactly whom a full body's is today. cons: one ≈ 338 KB root a block that aggregates, on the
    /// envelope; none on the hashed block.
    #[serde(skip)]
    pub agg_tables: Vec<Vec<u8>>,
    /// ⭐⭐⭐ DB-165 — THE CONSTANT-WIDTH NOTE CARRIER. Exactly
    /// [`crate::cover::BLOCK_NOTE_COMMITMENTS_BYTES`] (256 x 32 = 8,192) on EVERY block, quiet or busy.
    ///
    /// ⛔ THIS EXISTS BECAUSE `output_notes` STATES THE BLOCK'S REAL NOTE COUNT BY ITS LENGTH. Measured
    /// 2026-09-24 (`harness::privacy`, real blocks): `output_notes` is 0 B on a quiet block and 5,765 B
    /// on a busy one — 5,765 / 1,153 = EXACTLY five notes, read straight off the wire. Worse, the DA
    /// record's 256-wide cover is derived from `block_cover_secret(real_notes, seq)` whose ONLY secret
    /// input is those same reals, so every node that receives the block recomputes the secret and
    /// regenerates all 251 cover slots. The record's padding is sound in isolation and DEFEATED BY THE
    /// BLOCK. And for an empty block the reals are empty, so that secret degenerates to a PUBLIC
    /// `hash(prefix ‖ seq)` — a one-bit quiet/busy oracle per record.
    ///
    /// ⭐ THE LAW: **anything a node can REGENERATE, an observer can DISTINGUISH.** Cover must be STORED,
    /// never derived — and storing is affordable only at 32 B a slot (8 KB) rather than 1,153 B of
    /// ML-KEM-768 ciphertext (295 KB, ten times the Tor budget). So the BLOCK carries commitments and the
    /// ciphertexts live in the DA record, fetched only by their owner through the oblivious account
    /// bucket — measured at 1 DA read, flat from 1 record to 4,000.
    ///
    /// ⛔ NOT the Bitcoin or Zcash shape and never to be cited as one: Zcash carries `encCiphertext` IN
    /// the block and hides no output count; Bitcoin carries full transactions (BIP-152 short IDs are
    /// RELAY); Monero hides no output count either. No major chain hides per-block real output count.
    /// See `docs/DB165-CONSTANT-WIDTH-NOTE-CARRIAGE.md`.
    #[serde(default)]
    pub note_commitments: Vec<u8>,
    /// ACCOUNT-INDEXED DA targets carried WITH the block: `note_cm(32) ‖ bucket(32) ‖ ek_len(2) ‖ ek` per
    /// output note.
    ///
    /// These reach the producing node on the tx submit, but a VERIFYING node only ever sees the block — so
    /// without carrying them, every peer folds a different account accumulator and files none of the notes,
    /// and a wallet on any node but the sender's gets an empty bucket. Measured exactly that way: the
    /// producer committed a live root while its peer still committed zero. Same lesson as the locator tags —
    /// anything the account map depends on must ride the block, never a submit-time side channel.
    #[serde(default)]
    /// ⭐⭐⭐ THE LOCATOR TAGS FOR THIS BLOCK'S OWN NOTES — CARRIED, SO INGEST CANNOT LOSE THEM.
    ///
    /// The third and last carrier in this family, after `account_targets` here and `PqTx::note_clues`. Each
    /// closed the same hole one layer further out: a node-LOCAL map deciding whether a payment is findable.
    ///
    /// Tags reach a node as a clue (gossip or with the tx) and land in `pending_tags`, which the record loop
    /// drains with `remove(&cm)`. Carrying them on the TX fixed the node that receives the tx — but a node
    /// that receives the BLOCK FIRST still has nothing to drain, and block gossip routinely beats tx gossip.
    ///
    /// MEASURED 2026-08-10, both nodes, one run: node A produced both real-note blocks and indexed 4 tags
    /// (2 notes x 2 sends); node B ingested those same blocks — it logged the 3459-byte payload 114 times —
    /// and indexed only 2. Send 2's notes were on chain and in NO index on the recipient's node, so its owner
    /// could not find them. Send 1 settled, send 2 did not.
    ///
    /// A block must carry what applies it. With the tags riding here, a verifying node indexes exactly what
    /// the producer indexed, from the block alone, with nothing to order and no message it must already have
    /// received.
    ///
    /// Wire shape `cm || k`, repeated — 32 + `oli::K_BYTES` per REAL note only. Cover slots carry no tag, so
    /// this is bounded by the real notes in one block and adds no term in height, blocks or chain size.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: `k` is `index_key(clue)` — the same value already gossiped in the clue
    /// channel and already written to the DA shard by every node that indexes it. Cover shape, note count and
    /// block width are untouched, and a tag distinguishes no real note from a decoy to anyone without the
    /// locator secret.
    pub oli_tags: Vec<u8>,
    pub account_targets: Vec<u8>,
    /// ⭐⭐⭐ THE BLOCK'S UNSPENT-TREE DELETION SET — CARRIED, SO INGEST CAN APPLY ITS SPENDS.
    ///
    /// The fourth carrier in the family above, closing the last "a block must carry what applies it"
    /// gap: receives fold at ingest from the carried notes, but deletions derived ONLY from tx bodies
    /// (`PqTx::unspent_spends`) — bodies an ingesting peer does not hold under the constant-256 cover
    /// shape. Its unspent root could then only diverge from the producer's, and the by-record heal
    /// round-trip loses the 500ms race by construction (see [`BlockHeader::del_set_root`] for the
    /// measured live failure).
    ///
    /// Wire shape: the block's CANDIDATE deleted note commitments, 32 bytes each, concatenated in the
    /// block's canonical tx order. Every READY node folds the same list through the same
    /// map-authoritative refusal rules (a commitment absent from the tree refuses identically
    /// everywhere), so producer and ingester reach the same root from the same block.
    ///
    /// cons: none — f(fixed constants), never f(history). The arithmetic: worst case
    /// `cover::BLOCK_FIXED_TX_COUNT` (256) x 32 B = 8,192 B of ONE block's payload IN FLIGHT (0.1% of
    /// the 8 MB body budget; the typical 0-2 real spends = 0-64 B), consumed at graft exactly like the
    /// carried notes above, RETAINED NOWHERE (0 B at rest — the DA record's del sidecar, which
    /// already holds applied deletions on every node, is unchanged). What it REMOVES is the measured
    /// per-block growth loop: the spend-fold heal set grew +1 per ingested block forever (78→99 and
    /// 87→110 in one live probe stretch) and re-asked ~110 record ids EVERY tick.
    ///
    /// Privacy: each value here is ALREADY block-public — the same bytes every node's DA record serves
    /// in its del sidecar to any asker, and the same deletion every public unspent-tree replay
    /// consumes. Carrying it with the block moves WHEN it arrives, not WHO can see it; amounts,
    /// owners, keys and linkage stay inside the note ciphertexts and proofs. Its length equals the
    /// block's real spend-candidate count — the SAME figure `NfBlockProof::padded_tags` already
    /// exposes on every block today (see its stale-name note); the in-circuit volume-hiding redesign
    /// covers both fields under the same acceptance gate.
    /// ⭐⭐⭐ THE BLOCK'S VALIDATOR-BOND SET — CARRIED, SO EVERY NODE ADMITS THE SAME VALIDATORS.
    ///
    /// The fifth carrier in the family above. Bond admission derived ONLY from tx bodies in the
    /// PRODUCER'S mempool (`bond_notes` + the diverted output0), so the producing node admitted the
    /// validator and every other node stayed at `validators=0`, rejected its finality votes at the
    /// `bond_of(voter)==0` gate, and could neither finalize nor return the bonded note on unbond
    /// (see [`BlockHeader::bond_set_root`] for the measured live failure).
    ///
    /// Wire shape per bonding tx, canonical tx order: validator_id 32 B, then bond_amount as u64 LE
    /// 8 B, then the locked output0 note blob of [`BOND_LOCKED_NOTE_BYTES`] — [`BOND_SET_ENTRY_BYTES`]
    /// per entry. The locked note rides so ANY node can return it on an authenticated unbond — the
    /// produce path diverts output0 out of `output_notes`, so the block is the only replicated place
    /// the locked note can live (trustless liveness: no single node's stash is required to unbond).
    ///
    /// cons: none — f(bonding txs in ONE block), never f(history). A bond is a rare governance-scale
    /// action; each entry is 1,193 B of that one block's payload IN FLIGHT, consumed at graft into
    /// `validators`/`bond_locked` (state bounded by the CURRENT validator set, not by chain length),
    /// 0 B at rest on the wire path. What it removes is a liveness hole: finality only ever worked on
    /// the one node that produced the bond block.
    ///
    /// Privacy: `validator_id` and `bond_amount` are ALREADY consensus-public by design — the bonded
    /// weight is the PUBLIC stake that votes are weighed by and `/get_validator_bond` serves per-id;
    /// the locked note is the same sealed ciphertext every note on the wire is. Amounts, owners, keys
    /// and linkage of ORDINARY payments are untouched — a bond is a validator's public act.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `cover::BLOCK_FIXED_TX_COUNT` — a bond rides a
    /// transaction, so a block carries at most one per tx slot. A BLOCK-lifetime field: the node folds the
    /// set into validator weight and keeps no block bodies, so it takes no term in height or bond count.
    #[serde(default)]
    pub bond_set: Vec<u8>,
    /// ⭐⭐⭐ §BA — THE BLOCK'S CREDIT SET: THE EVIDENCE FOR EVERY NOTE NO SPEND PUBLISHED.
    ///
    /// ⛔⛔⛔ WHAT IT CLOSES. A note reaches a peer three ways. A SPEND's outputs are justified by the
    /// block's [`Self::note_transition`] — one bound aggregate over carriers that verified in circuit,
    /// checkable holding no transaction body. A note of a transaction the peer happens to have POOLED is
    /// justified by that transaction's own carrier gate. Everything else — a bridge credit, an asset or
    /// wrapped mint, a bond return, a swap fill — was staged by the node that applied the object
    /// (`Node::stage_credit_note`) and rode the next produced block with NOTHING on the wire saying why.
    /// Under the constant-256 cover a peer resolves almost none of a block's bodies, so "nothing to judge
    /// from" meant RECEIVED: §BA, measured as `peer RECORDED it=true, peer holds it UNSPENT=true` for a
    /// commitment a producer invented out of nothing.
    ///
    /// ⭐ WHAT IT IS. A length-prefixed list of FRAMED CHAIN OBJECTS — the identical bytes
    /// [`crate::chain_object`] already gates — one per staged credit, carried BY THE BLOCK so a peer needs
    /// no mempool. The peer runs the same two questions the submitting node ran: `chain_object::admissible`
    /// on the object's own bytes, and then `carried_note_payloads` must NAME the commitment. An object that
    /// fails either justifies nothing, so the note it was attached to is refused like any other plant.
    ///
    /// ⛔ AND IT IS NOT A SECOND AUTHORITY. The object is the SAME one that rode `tx_ids`; this is a second
    /// CARRIAGE of evidence the chain already required, exactly as `del_set` re-carries deletions whose
    /// transactions the peer will never see. Carrying it is what makes the peer's check local instead of a
    /// fetch, which is the whole validium bargain.
    ///
    /// Wire: `u32 len then bytes` per object, in the producer's staging order.
    /// Privacy: these are consensus-public objects whose own designs already publish what they publish (a
    /// bridge deposit id, an asset id, a validator's public bond). No ordinary payment's amount, owner, key
    /// or linkage appears — a payment's notes ride the SPEND path and are justified by the transition.
    /// ⛔ ITS LENGTH TRACKS FRAMED-OBJECT ACTIVITY, and that is filed open in `harness::privacy` on its own
    /// line (DB-224): the notes are off the block wire (every payload is a 64-byte reference here), but the
    /// objects are not and cannot be while every verifier must read them to apply them — the count is the
    /// same one tx gossip already delivers whole. Hiding it from a verifier needs the objects verified
    /// in-circuit over commitments (open design); padding a set of proofs to a constant is unaffordable.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by protocol constant `cover::BLOCK_FIXED_TX_COUNT` — at most one
    /// object per tx slot the block has, enforced at production (`credit_set_encode`) and at acceptance
    /// (`credit_set_iter` refuses a longer list). A BLOCK-lifetime field like every sidecar beside it: the
    /// node keeps an O(1) frontier and never retains block bodies, so it takes no term in height.
    /// ⛔⛔⛔ DB-224 — IT TRAVELS AGAIN, IN CARRIAGE FORM ONLY, AND THAT FORM IS A CONSENSUS RULE.
    ///
    /// DB-165 made this `#[serde(skip)]` (its length stated credit activity, and the objects carried full
    /// note ciphertexts — the only secret input of `cover::block_cover_secret`) on the premise that it is
    /// "pool-derived exactly as `output_notes` is". That premise was false: a peer rebuilt it from ITS OWN
    /// mempool, installed nothing on a miss, and grafted the block anyway — so every framed object (price
    /// mark, peg-in, wrapped mint, asset objects, fills, unbonds…) applied only where its tx happened to
    /// be pooled in time. MEASURED (DB-220 pin): the producer held the price mark, the peer held `None`.
    ///
    /// ⭐ NOW every entry is [`crate::chain_object::carriage_of`] of the object: the same class under the
    /// same codec, every note payload replaced by its 64-byte reference `cm ‖ Hash32::hash(payload)`.
    /// Every class rule reads `cm` only, so a peer judges and applies the object from the block alone;
    /// the payloads never ride the block (they reach a node as every note does — its pool or the DA
    /// record), and `validate_structural` REFUSES a block whose set holds anything but carriages
    /// (`CreditSetNotCarriage`) or names a note its own carrier does not commit (`CreditObjectWithoutSubject`).
    /// `credit_set_root` binds these bytes; the header layout is unchanged, so the genesis id is too.
    pub credit_set: Vec<u8>,
    /// ⭐⭐⭐ THE BLOCK'S DIRECTORY SET — CARRIED, SO EVERY NODE RECONSTRUCTS THE SAME @username +
    /// group directory by folding the chain (no per-node disk cache, no gossip-order divergence).
    ///
    /// The sixth carrier in the family above. A directory registration used to be adopted locally +
    /// gossiped + written to a per-node JSON file — a pre-DA design that made local disk a mini-authority
    /// and left first-come to a gossip race. Now every registration RIDES A BLOCK: the producer seals its
    /// pending registrations here, `dir_set_root` binds them to the id, and `apply_dir_set` re-verifies each
    /// ML-DSA signature + the first-come/owner-continuity rule on EVERY node — so the resolved directory is
    /// a deterministic fold of canonical chain order, reconstructed on restart/DSYNC-join from the mesh, with
    /// nothing trusted on disk.
    ///
    /// Wire shape: repeated `len(u32 LE) ‖ entry`, each `entry` a postcard-encoded
    /// [`crate::directory::DirEntry`] (kind + key + address/name/topic + owner pubkey + sig). Parsed +
    /// applied by [`crate::directory`] / `Node::apply_dir_set`.
    ///
    /// Privacy: an @username / group listing is OPT-IN discovery metadata the owner CHOSE to publish (the
    /// same public category as today's @username handle) — it names no note, amount, key, or value. Ordinary
    /// payment privacy is untouched. cons: f(registrations in ONE block), never f(history); a few KB per
    /// user-created handle IN FLIGHT, consumed at graft into the in-memory directory projection.
    #[serde(default)]
    pub dir_set: Vec<u8>,
    /// ⭐⭐⭐ THE BLOCK'S AMM SET — every confidential-AMM settlement this block carries, bound to the id
        /// ⭐⭐⭐ THE BLOCK'S LETTER SET — the seventh carrier in the family above ([`Self::del_set`],
    /// [`Self::bond_set`], [`Self::dir_set`]): [`crate::letter::LETTER_CMS_PER_BLOCK`] x 32 bytes, ALWAYS
    /// (consensus refuses any other length on a non-genesis block), the on-chain anchor of the Letter
    /// messenger's DA content stream. Real sealed-letter commitments fill the front slots; the rest are
    /// producer-seeded cover commitments byte-indistinguishable from real ones, so the carried shape is
    /// CONSTANT and an observer counting a block learns nothing about real mail volume (digital-cash
    /// volume/timing privacy). The sealed blobs themselves NEVER ride the block — they travel gossip + the
    /// record layer's letter lane, fetched by commitment and verified against this set (a blob that does not
    /// hash to a committed value is refused, so backfilled mail is trustless). Overflow past the constant
    /// rides the NEXT block (a page that drains, never a bound that drops a message).
    ///
    /// cons (the arithmetic): IN FLIGHT 2,048 B/block x 172,800 blocks/day = ~354 MB/day of transient gossip,
    /// riding beside the existing (far larger) 256-tx cover gossip — none of it retained. AT REST on this
    /// field: 0 B/block beyond the DAG's own recent blocks (an O(1) node does not keep old blocks); the flat
    /// 32-byte letter accumulator is the only permanent state this field feeds. Blob-lane storage is governed
    /// by the record layer's EXISTING ladder bound (the same one note records live under), not a new axis.
    #[serde(default)]
    pub letter_set: Vec<u8>,
    /// ⭐ PRIVATE SHARDING §2.2 — one [`crate::nf_evidence::TagEvidence`] for every padded tag, in their order, cover tags too,
    /// so the list's length says nothing about real spends. Postcard. What lets a node decide a spend with no shard of the set.
    /// Dropped with the block's proofs below `WHOLE_KEEP`.
    /// cons: about 300 B per tag today and at most about 1.3 KB at 1e12 tags, in flight and in the proof-carrying window only.
    #[serde(default)]
    pub tag_evidence: Vec<u8>,
}

/// The root of an empty evidence list: a shell or anchor block carries none.
#[must_use]
pub fn empty_tag_evidence_root() -> Hash32 {
    da_sidecar_root_of(&[])
}

/// The sealed output-note blob size a bond LOCKS (output0 of a bonding tx) — the third field of each
/// [`Block::bond_set`] entry. ONE definition, shared by the producer that seals entries and every
/// ingester that parses them, so the two can never disagree on the entry stride.
pub const BOND_LOCKED_NOTE_BYTES: usize = 1153;
/// One [`Block::bond_set`] entry: validator_id 32 B + bond_amount 8 B + the locked output0 blob.
pub const BOND_SET_ENTRY_BYTES: usize = 32 + 8 + BOND_LOCKED_NOTE_BYTES;

/// §POLES — THE CONSTANT SHAPE FOR [`Block::bond_set`] AND [`Block::dir_set`].
///
/// Every non-genesis block carries exactly this many bytes in its bond_set and dir_set, cover-padded
/// from `block_cover_secret`, so the LENGTH no longer reads 0 B quiet / 6,094 B busy. ⛔ It does NOT hide
/// the COUNT: the real entries are public length-prefixed frames ahead of the `u32::MAX` sentinel, and
/// the keyless [`sidecar_real_len`] walk every ingester runs recovers them from the bytes alone
/// (`harness::privacy` measures it; the three sidecars stay FILED_OPEN). 16,384 B covers one full bond admission (measured 8,819 B: the mempool's membership tx +
/// the bond transition entry) plus headroom for a simultaneous unbond or equivocation in the same
/// block; a block whose real entries exceed it omits the padding (mass bond activity is a public
/// governance event, already visible through tx gossip). The parser's existing malformed-tail path
/// gracefully stops before the cover bytes. cons: 16,384 B per field × 2 fields × 2 blocks/s ≈
/// 5.5 GB/day transient gossip, each field consumed at graft and never retained.
pub const SIDECAR_PADDED_BYTES: usize = 16_384;

/// Cover-pad `sidecar` to exactly [`SIDECAR_PADDED_BYTES`] using `cover_key` as the XOF seed.
/// If the real entries already exceed the constant, the sidecar is left as-is (no padding added).
///
/// The first 4 cover bytes are `u32::MAX` in LE, which the length-prefixed parser reads as a frame
/// that exceeds the buffer — so it stops cleanly at the real/cover boundary with no spurious entries.
/// The remaining cover bytes are a `blake3` XOF stream keyed by `cover_key` and `domain`; the sentinel
/// itself marks the real/cover boundary in the clear, so the pad fixes the length, not the count.
pub fn pad_sidecar_to_constant(sidecar: &mut Vec<u8>, cover_key: &[u8; 32], domain: &[u8]) {
    if sidecar.len() + 4 >= SIDECAR_PADDED_BYTES {
        return;
    }
    sidecar.extend_from_slice(&u32::MAX.to_le_bytes());
    let mut h = blake3::Hasher::new_keyed(cover_key);
    h.update(domain);
    let mut xof = h.finalize_xof();
    let old_len = sidecar.len();
    sidecar.resize(SIDECAR_PADDED_BYTES, 0);
    xof.fill(&mut sidecar[old_len..]);
}

/// Byte offset where the real length-prefixed entries end in a padded sidecar.
/// The parser walks `u32 len` + `len bytes` frames; it stops when a frame's length is zero or
/// exceeds the remaining bytes (the sentinel `u32::MAX` written by [`pad_sidecar_to_constant`]).
pub fn sidecar_real_len(sidecar: &[u8]) -> usize {
    let mut off = 0usize;
    while off + 4 <= sidecar.len() {
        let len = u32::from_le_bytes(sidecar[off..off + 4].fixed()) as usize;
        if len == 0 || off + 4 + len > sidecar.len() {
            return off;
        }
        off += 4 + len;
    }
    off
}

/// Constant target for `oli_tags`: 256 entries × 48 B (`cm(32) || k(16)`) = 12,288 B.
/// Ledger blocks already produce exactly this from `uniform_ledger_filing`; non-ledger blocks
/// are padded by [`pad_oli_tags_to_constant`].
pub const OLI_TAGS_PADDED_BYTES: usize = 256 * (32 + crate::oli::K_BYTES); // 12,288

/// Pad `oli_tags` to [`OLI_TAGS_PADDED_BYTES`] with blake3 XOF bytes keyed from the block's
/// real output notes, so padding is secret-seeded and indistinguishable from real tag records.
/// Ingesting nodes skip the padding: random CMs do not match any note in the fixed payload.
pub fn pad_oli_tags_to_constant(tags: &mut Vec<u8>, real_notes: &[u8]) {
    if tags.len() >= OLI_TAGS_PADDED_BYTES {
        return;
    }
    let mut h = blake3::Hasher::new_derive_key("MUSD/oli-tags-cover/v1");
    h.update(real_notes);
    let mut xof = h.finalize_xof();
    let old_len = tags.len();
    tags.resize(OLI_TAGS_PADDED_BYTES, 0);
    xof.fill(&mut tags[old_len..]);
}

/// The block's O(1) nullifier transition certificate (Gap-3). `carrier` is the recursive WHIR proof that the
/// block's [`crate::cover::BLOCK_FIXED_NULLIFIER_COUNT`] ordered inserts advance `header.nullifier_root` → `post_root`;
/// an empty `carrier` means "none carried" (genesis / cover-only / DSYNC anchor). A verifier checks it in constant
/// time via `usdm_decider::nullifier_insert_air::verify_nullifier_block_carrier_bytes(carrier, pre, post, N)` — it
/// holds NO nullifier tree. TRUE constant size (the carrier is a fixed-param WHIR proof), honoring no-growth.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NfBlockProof {
    /// The Gap-3 recursive block carrier (`prove_nullifier_block_carrier_bytes`); empty = none carried.
    pub carrier: Vec<u8>,
    /// The post-transition nullifier-acc root the carrier binds `header.nullifier_root` → (limb bytes).
    pub post_root: Hash32,
    /// ⭐ THE HEIGHT-1 BLOCK FOLD — the CONSTANT-size proof of this block's whole nullifier transition
    /// (`nf_sparse_air::prove_sparse_fold_height1_bytes`). MEASURED ~1,535 B and 0 ms to prove at the production
    /// 256 cover, and FLAT across a 16× nullifier-count change — versus the 32,372 B / 5,190 ms 256-row chain AIR,
    /// and versus CARRIED WITNESSES which are BANNED because they GROW with block count (64,704 B → 96,544 B in
    /// six blocks, [[feedback_never_carried_witnesses_wire]]). This is what a treeless node verifies in O(1) to
    /// adopt the transition holding NO tree. Empty = not carried (a node then simply has not adopted this
    /// transition yet — production and gossip are NEVER gated on it, so the chain cannot halt).
    #[serde(default)]
    pub fold: Vec<u8>,
    /// ⭐⭐⭐ THE PUBLIC INPUT THE FOLD PROOF IS CHECKED AGAINST — CARRIED BY THE BLOCK, NOT LOOKED UP.
    ///
    /// `fold` proves this block's nullifier transition, but verifying it needs the padded tag set as a public
    /// input. That set used to be RECONSTRUCTED on each node from its OWN MEMPOOL (`nf_inputs_for(tx_ids)` →
    /// `pad_nullifiers_to_fixed`). A node that never pooled this block's txs reconstructed an EMPTY real set,
    /// padded to 256 pure decoys instead of the producer's reals-plus-decoys, and the fold could never reach
    /// the committed post-root — so the block parked permanently. MEASURED on the live binaries:
    /// `served_seq - nf_fold_seq` = 10,419 and 10,792, and rising — ten thousand accepted blocks that never
    /// entered the accumulator. A wallet names the endpoint of the stream it was served, so spenders named a
    /// base the node had never held: "the base this proof names is not an accumulator this chain ever held".
    ///
    /// A block must carry what is needed to APPLY it — Bitcoin and Kaspa get this for free because the block
    /// contains its spends. TxReq/TxResp cannot substitute: blocks land every ~500ms and a Tor round-trip per
    /// block loses that race by construction, which is why the gap only ever grew.
    ///
    /// SOUNDNESS: carrying this forges nothing. `adopt_sparse_via_block_fold` verifies `fold` AGAINST these
    /// tags and the committed `(pre_root → post_root)`, so a tampered list fails exactly as a tampered proof
    /// does and advances nothing.
    ///
    /// ⛔ NAME IS STALE, AND THE OLD DOC HERE WAS FALSE — corrected 2026-08-14 (privacy audit): since the
    /// 256-wide decoy retirement (`cover::block_nullifier_set` is the identity), this field carries the
    /// block's BARE REAL nullifier tags — its LENGTH equals the real spend count, so per-block spend
    /// volume is observable to anyone reading blocks. The previous doc claimed a "CONSTANT 256-entry
    /// secret-seeded cover set" that no longer exists (`pad_nullifiers_to_fixed` is retired), which is
    /// exactly the lying-doc class that produced a wrong audit verdict at `nullifier_count`. The volume
    /// hiding returns with the in-circuit nullifier redesign (the wire-fill primitives in cover.rs are its
    /// wire format); the two red nf_sparse privacy tests are its acceptance gate. Until then this doc
    /// states what the field IS, not what it once was.
    pub padded_tags: Vec<[u8; 32]>,

    /// ⭐⭐⭐ DB-154/LANE-2 — THE SPARSE POST ROOT, so the transition a treeless node verifies is
    /// SELF-CONTAINED.
    ///
    /// `header.sparse_root` commits the PRE state. Without the post, a verifier could only learn it from
    /// the NEXT block, so a node could never check a block on its own — and "verify the block in front of
    /// you" is the whole property a doubter spins up a node to see. 32 bytes, constant at any height.
    ///
    /// ZERO = this producer built no sparse carrier (it held no tree). Never gated on, exactly like
    /// `fold`: a treeless producer cannot halt the chain.
    #[serde(default)]
    pub sparse_post_root: Hash32,
    /// ⛔⛔⛔ ITS OWN FIELD, NOT `carrier`. `carrier` is the IMT/`nullifier_insert_air` proof and the
    /// ingest gate verifies it with that verifier against `header.nullifier_root` -> `post_root`. A
    /// SPARSE proof placed there is handed to the wrong verifier and EVERY produced block is refused —
    /// caught before it shipped, 2026-09-22. One field, one verifier, one meaning.
    ///
    /// Proves `header.sparse_root` -> `sparse_post_root` over this block's own `padded_tags`, so any
    /// node — holding a tree or not — checks the committed Merkle root for itself instead of taking
    /// the producer's word for it. Empty = this producer held no tree; never gated on.
    #[serde(default)]
    pub sparse_carrier: Vec<u8>,
    //
    // NOTE — the fold's DIGEST is deliberately NOT carried. It is the running Poseidon absorb over the block's
    // padded nullifiers, and EVERY verifier derives it itself (treelessly: the padded set comes from the block's own
    // real spends + committed pre-root, no tree). A *carried* digest would have to be TRUSTED, and a trusted digest
    // proves nothing — a producer could weld any set it liked into the transcript. Verifier-derived is what makes a
    // tampered nullifier set diverge Fiat-Shamir and REJECT ([[feedback_always_trustless]]).
}

impl Block {
    /// This block without its proofs: every chain fact stays (header, tags, notes, sets), and the id, which binds them, is
    /// unchanged. An empty `pow_proof` is what every door already reads as "not whole", so a stripped block is never served as one.
    pub fn strip_proofs(&mut self) {
        self.pow_proof = Vec::new();
        self.tag_evidence = Vec::new();
        if let Some(t) = self.note_transition.as_mut() {
            t.agg = Vec::new();
            t.tag_agg = Vec::new();
        }
        if let Some(t) = self.cover_transition.as_mut() {
            t.agg = Vec::new();
        }
        if let Some(t) = self.member_transition.as_mut() {
            t.agg = Vec::new();
        }
        self.nullifier_proof.carrier = Vec::new();
        self.nullifier_proof.fold = Vec::new();
        self.nullifier_proof.sparse_carrier = Vec::new();
        // §22c: the spends' own proofs leave with the block's (no peer is served a proofless block to judge)
        self.tx_bodies = Vec::new();
        self.agg_tables = Vec::new();
    }
}

impl Block {
    /// ⭐ DB-223 — this block's transitions commitment over what it carries now ([`transitions_root_of`]).
    #[must_use]
    pub fn transitions_root(&self) -> Hash32 {
        transitions_root_of(
            self.note_transition.as_ref(),
            self.cover_transition.as_ref(),
            self.member_transition.as_ref(),
        )
    }

    /// ⭐ DB-223 — SEAL the header's transitions commitment over the transitions this block carries. Called by the
    /// producer after the LAST transition is attached and BEFORE the header is ground (the PoW binds it).
    pub fn seal_transitions_root(&mut self) {
        // ⭐ §22c: the note transition commits the spend transactions this block carries beside it, under its cover key
        // (`tx_bodies_commit`), so the root sealed below binds them into the id like every other carried byte.
        let bodies = carried_commit(self.cover_key.as_ref(), &self.tx_bodies, &self.agg_tables);
        if let Some(nt) = self.note_transition.as_mut() {
            nt.bodies = bodies;
        }
        // CONSENSUS-DERIVED-REVIEWED: `self` is the BLOCK, not a node — the value is a pure hash of this block's own
        // carried transition fields (`transitions_root_of`), so every node computes it identically from the block;
        // no node state is read.
        let root = transitions_root_of(
            self.note_transition.as_ref(),
            self.cover_transition.as_ref(),
            self.member_transition.as_ref(),
        );
        self.header.transitions_root = root;
    }

    /// The bytes this block holds in RAM (every variable-width field summed from its real length, plus the
    /// fixed struct) — the number a store of blocks reports to `/ram_census`. Summed, never a written-down
    /// "bytes per block" (the §AG lesson): the proof, carrier and payload widths drift with the decider.
    #[must_use]
    pub fn census_bytes(&self) -> usize {
        core::mem::size_of::<Block>()
            + self.header.parents.len() * core::mem::size_of::<BlockId>()
            + self.tx_ids.len() * core::mem::size_of::<Hash32>()
            + self.pow_proof.len()
            + self.agg_tables.iter().map(Vec::len).sum::<usize>()
            + self.note_transition.as_ref().map(|t| t.agg.len() + t.tuples.len()).unwrap_or(0)
            + self.cover_transition.as_ref().map(|t| t.agg.len() + t.tags.len()).unwrap_or(0)
            + self.member_transition.iter().map(|t| t.agg.len() + t.tuples.len()).sum::<usize>()
            + self.nullifier_proof.carrier.len()
            + self.nullifier_proof.padded_tags.len() * 32
            + self.output_notes.len()
            + self.oli_tags.len()
            + self.account_targets.len()
            + self.bond_set.len()
            + self.credit_set.len()
            + self.dir_set.len()
            + self.letter_set.len()
    }

    pub fn id(&self) -> BlockId {
        self.header.id()
    }
}

/// ⭐ A HELD BLOCK WITH ITS ID COMPUTED ONCE, at the moment it is held. A block id is `blake3(header.preimage())` — an
/// allocation plus a hash — and the node's held sets are searched by id in loops every relay tick (`holds_only_a_shell`,
/// `batch_have_ids`, the fold's body lookups: ~40 `.find(|b| b.id() == x)` sites). MEASURED 2026-10-06 (simulator
/// profile, T1.7): `locator_ask → batch_have_ids → holds_only_a_shell → BlockHeader::id` was 15 % of the journey's wall
/// time, re-hashing the same ~90 headers per asked id. Read-only by construction: it derefs to the `Block` (every field
/// and method as before) and has no `DerefMut`, so the header the id was computed from can never change under it; its
/// own `id()` shadows `Block::id` and returns the stored value, which is the same value. cons: 32 bytes per held block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdBlock {
    block: Block,
    id: BlockId,
}

impl IdBlock {
    #[must_use]
    pub fn new(block: Block) -> Self {
        let id = block.id();
        Self { block, id }
    }
    /// The id, computed when the block was held.
    #[must_use]
    pub fn id(&self) -> BlockId {
        self.id
    }
    #[must_use]
    pub fn block(&self) -> &Block {
        &self.block
    }
    #[must_use]
    pub fn into_block(self) -> Block {
        self.block
    }
    /// Set the held body's notes: the one change a held block admits. `output_notes` is `#[serde(skip)]` and no part of
    /// the id (the header commits the notes by root, and the caller has checked that root —
    /// `Node::body_from_record`), so the header the id was computed from is untouched.
    /// O1-INFINITY-REVIEWED: an in-RAM field of a block already held (serde-skipped: never encoded, never on disk);
    /// nothing is written or keyed, and the held set this is called over is bounded by protocol constants.
    pub fn set_output_notes(&mut self, notes: Vec<u8>) {
        self.block.output_notes = notes;
    }
}

impl std::ops::Deref for IdBlock {
    type Target = Block;
    fn deref(&self) -> &Block {
        &self.block
    }
}

impl From<Block> for IdBlock {
    fn from(block: Block) -> Self {
        Self::new(block)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod consensus_identity_is_the_live_chains_tests {
    /// ⭐⭐⭐ THE GENESIS ID THIS BINARY DERIVES **IS** THE LIVE CHAIN'S — the one check that says whether
    /// a deploy CONTINUES the chain or forks it, pinned to a literal so it can never drift silently.
    ///
    /// A block id is `blake3(header.preimage())`, so ANY change to `preimage()` — a field added, removed,
    /// or reordered — moves every id including genesis, and a node built that way cannot follow the chain
    /// its own datadir describes. That is not a theoretical risk: MEASURED 2026-08-26, binding an AMM
    /// `amm_set_root` into the preimage moved testnet genesis off `fc6a3623…`, which meant the live pair's
    /// 154k-block checkpoints belonged to an id-space the new binary did not share; the field was retired
    /// at source and the id came back. This literal is the live chain's own `chain_id` as both running
    /// daemons report it on /get_info at heights 153,765 and 154,824.
    ///
    /// If this test goes RED, the change under it is a HARD FORK. That may be intended — but it then
    /// requires a coordinated reset, and `NodeSnapshot::chain_id` + the restore gate are what keep an
    /// un-reset node from silently resuming a foreign tip. Update this literal ONLY together with that
    /// decision, never to make a red test green.
    ///
    /// ⭐⭐⭐ RE-GENESIS 2026-09-15, DELIBERATE AND USER-AUTHORISED — §BA. `BlockHeader::credit_set_root`
    /// entered the preimage, so every id moved and testnet genesis went
    /// `fc6a3623…` → `593957f8…`. This is the coordinated reset the doc above describes, not a red test
    /// made green: the root binds `Block::credit_set`, the justification sidecar that lets a peer tell an
    /// honest credit from a planted one, and an UNBOUND justification sidecar is worse than none — a relay
    /// could append the object that excuses whatever note it wanted to plant, with the block id unchanged.
    /// The 2026-08-26 precedent above is the OPPOSITE case and stays instructive: `amm_set_root` was
    /// retired at source because it bought nothing. This one closes an unlimited-mint hole measured on a
    /// peer, so the fork is the price and it was paid on purpose.
    ///
    /// ⭐⭐⭐ RE-GENESIS #7, 2026-09-22, DELIBERATE AND USER-AUTHORISED — THE Z-BUILD. `BlockHeader::del_set_root`
    /// LEFT the preimage: the deletion model it committed is retired at source (the tree, the sidecars, the
    /// presence serve and the readiness class with it), because a public deletion set named the spent note's
    /// COMMITMENT and so linked every spend to its receipt — the digital-cash pillar's last graph leak. A
    /// spend is now authorised by its NULLIFIER against the sharded sparse set (Zcash's shape, with the
    /// monotone set partitioned so no node holds it all). Every id moved with the field, testnet genesis
    /// went `593957f8…` → `fc6a3623…`, and the live pair was reset onto it deliberately. As above: this
    /// literal moved as PART of the decision, never to make a red test green.
    ///
    /// ⭐ RE-GENESIS #8 — DB-165 (2026-09-24) added `note_commitments_root` to the preimage, and the live pair was
    /// reset onto it (pre-authorised: every node is a testnet node until launch). The literal did not move with
    /// that change. MEASURED 2026-09-28: this tree derives `593957f8…`, and the live pair's `/get_info` `chain_id`
    /// is `593957f8a4ad…` (height 3,061). That is the SAME id as before re-genesis #7, and it is no revert:
    /// every root in a genesis header is zero, so the genesis id depends only on how many 32-byte roots the
    /// preimage holds. Counted from the backups: 22 before Z (09-18), 21 after Z (09-22), 22 after DB-165 (09-24).
    /// A header change that ADDS a root and one that REMOVES one can therefore cancel in this literal. The
    /// non-genesis ids still moved, and `del_set_root` is still out of the preimage.
    ///
    /// ⭐⭐⭐ RE-GENESIS #9, 2026-09-29, DELIBERATE AND PRE-AUTHORISED (every node is testnet until launch) — DB-223.
    /// `BlockHeader::transitions_root` entered the preimage: it binds the block's carried note, cover and membership
    /// transitions, the only evidence a peer holding no tx body has for a block's spend outputs and inputs. Unbound,
    /// a relay could strip a genuine transition and the copy kept the block's id, so a peer grafting it refused what
    /// every other peer recorded. Genesis carries none and commits the fixed empty-transitions marker, which is NOT a
    /// zero root, so the genesis id moved: `593957f8…` → `efa9f0e6…`. The live pair is reset onto it as part of this
    /// decision, never to make a red test green.
    ///
    /// ⛔ RE-GENESIS #10 WAS REVERSED BEFORE ANY ROLL (2026-09-30). DB-353 band landing 2 (a) bound a carried band
    /// transition into `transitions_root_of` as a fourth part and moved the id to `8153fd62…`; the same day the band moved
    /// to the RELAY (spec §11.10: a verified chunk has one post over the fold-canonical admitted set, so the band is a
    /// function of the chain and needs no block to carry it), the field left the block and the commitment returned to its
    /// v1 three-part form — so the genesis id is `efa9f0e6…` again, the id the live pair never left.
    /// TWO-PARTY-REVIEWED: the genesis id is a pure function of the network prefix that every node computes alone and
    /// identically; the cross-process claim (both live daemons on this id) is the real-node gate's `/get_info` check.
    #[test]
    fn testnet_genesis_id_still_matches_the_live_chain() {
        // RE-PINNED 2026-10-24 (lane a §RF-3): `cover_seed_commit` joined the preimage — a DELIBERATE re-genesis
        // (pre-authorized testnet reset, all HFs at height 1); the live pair is paused until F4 and rolls onto this id.
        // RE-PINNED again 2026-10-24 12:18 (lane a §RF-3): `member_ring_commit` joined the preimage (was 121e2601…).
        // RE-PINNED 2026-11-10 (lane goods, attribution on the bus 13:09 by lane dcash): the source has derived 73bd8768…
        // since the header's state commits landed (0dcbbbcb, 2026-11-06) and the wallet's network descriptor was moved to
        // it then; this literal was left on 87feeb17… and the pin read RED on main. No consensus byte moved here.
        let want = "f10d0361e0ca1972264cc40d602cb41104649b9c8ada7d964057512b9e0f7a13";
        let prefix = crate::params::network_genesis_prefix("testnet");
        let got = super::genesis_header_for_network(&prefix).id();
        let got_hex: String = got.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            got_hex, want,
            "TESTNET GENESIS ID MOVED — this binary derives a chain the live nodes are not on. Something \
             under `BlockHeader::preimage` changed: every block id moved with it, so deploying this \
             binary forks the network away from its own 154k-block datadirs. Either revert the consensus \
             change, or accept the fork DELIBERATELY (coordinated reset) and update this literal as part \
             of that decision."
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod genesis_names_its_network_tests {
    use super::genesis_header_for_network;
    use crate::params::network_genesis_prefix;

    /// ⭐⭐⭐ TWO NETWORKS MUST BE VISIBLY DIFFERENT AT `chain_id`, OR A SPLIT IS INVISIBLE.
    ///
    /// TWO-PARTY-REVIEWED: this is the PRECONDITION two parties agree on, asserted on the shared value both
    /// sides compute independently — the cross-node adopt itself is covered by the DSYNC tests.
    ///
    /// What this would have caught, measured live on one machine: three running nodes ALL reporting
    /// `chain_id 449560a82e7d06df`, while every DSYNC adopt between them returned `GenesisMismatch` forever.
    /// The genesis header was all-constant, so its block id — which `/get_info` publishes as `chain_id` — was a
    /// GLOBAL CONSTANT identical on every network, while the adopt gate compared the per-network id prefix.
    /// A node with no `MONEROUSD_NET` takes the mainnet prefix and a wallet-spawned node passes testnet, so two
    /// nodes on one desktop sat on different chains, meshed over Tor, exchanged bundles, rejected all of them,
    /// and each extended its own chain looking perfectly healthy. Funds cannot move between two devices that
    /// can never adopt each other's chain.
    ///
    /// Ethereum settles this the same way: the genesis config differs per network so the genesis HASH differs,
    /// and peers compare it in the handshake. A shared genesis id across networks is the anomaly, not the fix.
    #[test]
    fn a_genesis_id_names_its_network_so_two_chains_can_never_look_identical() {
        let testnet = genesis_header_for_network(&network_genesis_prefix("testnet")).id();
        let mainnet = genesis_header_for_network(&network_genesis_prefix("mainnet")).id();
        assert_ne!(
            testnet, mainnet,
            "testnet and mainnet published the SAME chain_id. Every fork-detector comparing it sees agreement \
             between nodes that share no chain, while every adopt fails as GenesisMismatch — the exact silent \
             island measured on this machine."
        );

        // …and the same network must be IDENTICAL, computed independently, or two honest devices could never
        // agree. Both halves have to hold: a per-device genesis would also make these ids differ.
        let a = genesis_header_for_network(&network_genesis_prefix("testnet")).id();
        let b = genesis_header_for_network(&network_genesis_prefix("testnet")).id();
        assert_eq!(
            a, b,
            "two independent computations of ONE network's genesis disagreed — nothing device-specific may \
             enter genesis or no two installs could ever converge."
        );
        assert_eq!(a, testnet, "the same network must be stable across calls");
    }
}

/// ⭐⭐⭐ §BA — THE CREDIT SET'S ONE ENCODING, PRODUCER AND VERIFIER SHARING IT.
///
/// `u32 len ‖ bytes` per framed chain object, in the producer's staging order. ONE spelling: the producer
/// writes with [`credit_set_encode`] and every verifier reads with [`credit_set_iter`], so the two can
/// never drift into the two-encodings class that cost the DEX a double payout.
///
/// ⛔ THE LENGTH PREFIX IS BOUNDED BEFORE IT IS TRUSTED. A `u32` read off the wire that is then used to
/// slice is the §AG lane-count class — seven door panics were exactly this shape — so the reader refuses a
/// length that runs past the buffer instead of indexing with it, and refuses more objects than the block
/// has transaction slots.
#[must_use]
pub fn credit_set_encode(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in objects.iter().take(crate::cover::BLOCK_FIXED_TX_COUNT) {
        out.extend_from_slice(&(o.len() as u32).to_le_bytes());
        out.extend_from_slice(o);
    }
    out
}

/// Read a credit set back. `None` on ANY malformed byte — a truncated length, a length running past the
/// end, or more objects than the block has transaction slots. Fail-closed: a set that does not parse
/// justifies NOTHING, which refuses the notes attached to it rather than excusing them.
///
/// §POLES: transparently strips constant-shape cover padding (the [`pad_sidecar_to_constant`] sentinel)
/// before parsing, so callers need not know whether the bytes are padded.
///
/// §22b: every wide-object reference is RESOLVED against `wide` (the bytes beside the body) by its carriage hash, so a
/// caller holds the objects themselves, in the producer's order. `None` when the set does not open under `key` OR any
/// reference has no matching bytes — unreadable, never "fewer objects" (the DB-220 class).
#[must_use]
pub fn credit_set_iter(
    bytes: &[u8],
    key: Option<&crate::cover::CoverKey>,
    wide: &[Vec<u8>],
) -> Option<Vec<Vec<u8>>> {
    let frames = credit_set_frames(bytes, key)?;
    let mut out = Vec::with_capacity(frames.len());
    for f in frames {
        match wide_ref_hash(&f) {
            Some(h) => out.push(wide.iter().find(|w| wide_carriage_hash(w) == h)?.clone()),
            None => out.push(f),
        }
    }
    Some(out)
}

/// The sealed set's raw FRAMES (inline objects and wide references unresolved) — for a counter or a door that judges
/// shape only. Every reader that APPLIES or JUDGES objects reads [`credit_set_iter`].
#[must_use]
pub fn credit_set_frames(bytes: &[u8], key: Option<&crate::cover::CoverKey>) -> Option<Vec<Vec<u8>>> {
    let plain = credit_set_open(bytes, key)?;
    credit_set_iter_plain(&plain)
}

/// §22b — the set opens under `key` and names a wide object `wide` does not hold: the body is INCOMPLETE here (a
/// reader waits for the whole body; the door refuses it as a body).
#[must_use]
pub fn credit_set_wide_missing(bytes: &[u8], key: Option<&crate::cover::CoverKey>, wide: &[Vec<u8>]) -> bool {
    credit_set_frames(bytes, key).is_some_and(|frames| {
        frames
            .iter()
            .filter_map(|f| wide_ref_hash(f))
            .any(|h| !wide.iter().any(|w| wide_carriage_hash(w) == h))
    })
}

/// ⭐ §22b — THE INLINE BOUND. A carriage at most this wide rides the sealed set whole; a wider one rides as a 40-byte
/// [`wide_ref_of`] reference with its bytes beside the body. Set so the sealed set is a list of REFERENCES: MEASURED
/// (`[frame-cost]` at the pool door, 2026-10-28) only a BridgeCredit (115 B) is smaller; every proof- or signature-carrying
/// object is ≥ 5,307 B (a FinalityVote: one ML-DSA-65 key + signature). An 8 KiB bound held two finality votes per block
/// and a validator set could not finalize (`overlays_finality_and_runtime_governance` RED, "2/3 … finalizes: 0"); at 256 B
/// the 16 KiB set holds ~350 references per block — the per-block object count bound — with every object's bytes
/// beside the body, each travelling once per peer exactly as the pre-§22 inline set carried them.
pub const CREDIT_INLINE_MAX: usize = 256;
/// A wide reference's frame body: this marker, then the carriage's hash. Never a chain object (`chain_object::unframe`
/// reads `b"MUSD"` first), so no reader can mistake one for the other.
pub const WIDE_REF_MAGIC: [u8; 8] = *b"WIDEREF1";
/// The reference's whole length.
pub const WIDE_REF_BYTES: usize = 8 + 32;

/// The hash a wide reference names: its carriage under its own domain.
#[must_use]
pub fn wide_carriage_hash(carriage: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/credit-wide/v1");
    h.update(carriage);
    *h.finalize().as_bytes()
}

/// The reference frame for a wide carriage.
#[must_use]
pub fn wide_ref_of(carriage: &[u8]) -> Vec<u8> {
    let mut r = Vec::with_capacity(WIDE_REF_BYTES);
    r.extend_from_slice(&WIDE_REF_MAGIC);
    r.extend_from_slice(&wide_carriage_hash(carriage));
    r
}

/// The hash a frame names when it is a wide reference (exact shape), else `None`.
#[must_use]
pub fn wide_ref_hash(frame: &[u8]) -> Option<[u8; 32]> {
    (frame.len() == WIDE_REF_BYTES && frame[..8] == WIDE_REF_MAGIC).then(|| frame[8..].fixed::<32>())
}

/// The frame bytes one carriage costs the sealed set (its length prefix included): whole when inline, a reference when
/// wide. The ONE cost every selector (`Mempool::select_for_template_reserving`, the producer's reserve) reads.
#[must_use]
pub fn credit_frame_cost(carriage_len: usize) -> usize {
    4 + if carriage_len > CREDIT_INLINE_MAX { WIDE_REF_BYTES } else { carriage_len }
}

/// §22b — the producer's split: each carriage stays inline or becomes a reference whose bytes go beside the body.
/// Order is kept (the frames are the producer's staging order); a carriage named twice is carried once.
#[must_use]
pub fn split_wide_carriages(carriages: &[Vec<u8>]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut frames, mut wide): (Vec<Vec<u8>>, Vec<Vec<u8>>) = (Vec::new(), Vec::new());
    for c in carriages {
        if c.len() > CREDIT_INLINE_MAX {
            frames.push(wide_ref_of(c));
            if !wide.contains(c) {
                wide.push(c.clone());
            }
        } else {
            frames.push(c.clone());
        }
    }
    (frames, wide)
}

/// §22b — seal `carriages` the way the producer does: split by [`CREDIT_INLINE_MAX`], seal the frames under `key`, and hand
/// back the sealed bytes with the wide objects that go beside the body. `None` when the frames exceed the budget.
#[must_use]
pub fn seal_carriages(carriages: &[Vec<u8>], key: &crate::cover::CoverKey) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let (frames, wide) = split_wide_carriages(carriages);
    Some((credit_set_seal(&frames, key)?, wide))
}

/// §22b — keep only the wide bytes the sealed set NAMES (a relay that appended extra bytes beside a body adds nothing:
/// they are dropped, never held). Without the key nothing can be judged, so nothing is kept — the fold heals the body.
pub fn retain_named_wide(block: &mut Block) {
    let named: Vec<[u8; 32]> = credit_seal_key(&block.header, block.cover_key.as_ref())
        .and_then(|k| credit_set_frames(&block.credit_set, Some(&k)))
        .map(|fs| fs.iter().filter_map(|f| wide_ref_hash(f)).collect())
        .unwrap_or_default();
    block.wide_objects.retain(|w| named.contains(&wide_carriage_hash(w)));
    block.wide_objects.dedup();
}

/// ⭐ §22c — THE COMMITMENT TO A BLOCK'S CARRIED SPEND TRANSACTIONS (`NoteTransition::bodies`): keyed BLAKE3 under the
/// block's cover key over the bodies in carried order, each length-prefixed. One definition for the producer
/// (`Block::seal_transitions_root`) and the door (`spend_evidence`). A block with no key commits under the all-zero key
/// (no produced block is key-less: every one carries its reward note and draws a key).
#[must_use]
pub fn tx_bodies_commit(key: Option<&crate::cover::CoverKey>, bodies: &[Vec<u8>]) -> [u8; 32] {
    let k = key.copied().unwrap_or([0u8; 32]);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(b"MUSD/block-tx-bodies/v1");
    h.update(&(bodies.len() as u64).to_le_bytes());
    for b in bodies {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    }
    *h.finalize().as_bytes()
}

/// ⭐ THE LEVEL AGGREGATE (lane agg) — the commitment `NoteTransition::bodies` holds: [`tx_bodies_commit`] exactly when the
/// block carries no openings table (so every block that aggregates nothing keeps today's bytes and id), and otherwise the
/// same keyed BLAKE3 under its own domain over the bodies AND the tables in carried order. Binding the tables into the id
/// is what makes a relay's flipped table byte a bad COPY (the door re-asks) instead of a block every peer refuses.
#[must_use]
pub fn carried_commit(key: Option<&crate::cover::CoverKey>, bodies: &[Vec<u8>], tables: &[Vec<u8>]) -> [u8; 32] {
    if tables.is_empty() {
        return tx_bodies_commit(key, bodies);
    }
    let k = key.copied().unwrap_or([0u8; 32]);
    let mut h = blake3::Hasher::new_keyed(&k);
    h.update(b"MUSD/block-tx-bodies-and-agg-tables/v1");
    for part in [bodies, tables] {
        h.update(&(part.len() as u64).to_le_bytes());
        for b in part {
            h.update(&(b.len() as u64).to_le_bytes());
            h.update(b);
        }
    }
    *h.finalize().as_bytes()
}

/// §22c — keep only the transaction bodies the block NAMES, each once, in `tx_ids` order: a body that does not decode,
/// whose id is not its own blob's (`PqTx::content_id`), or whose id the block does not list is dropped, never held (a
/// relay that appended bytes beside a body adds nothing). What a kept body PROVES is the block door's question
/// (`spend_evidence`), not this one's.
pub fn retain_named_tx_bodies(block: &mut Block) {
    let mut by_id: std::collections::HashMap<Hash32, Vec<u8>> = std::collections::HashMap::new();
    for body in std::mem::take(&mut block.tx_bodies) {
        let Some(tx) = crate::chain_object::decode_exact::<crate::mempool::PqTx>(&body) else { continue };
        if tx.id == crate::mempool::PqTx::content_id(&tx.blob) {
            by_id.entry(tx.id).or_insert(body);
        }
    }
    block.tx_bodies = block.tx_ids.iter().filter_map(|id| by_id.remove(id)).collect();
}

/// The frame walk over an OPENED (plaintext) credit set — [`credit_set_iter`] after [`credit_set_open`]. Kept
/// separate so the producer can measure what it is about to seal, and so no reader ever walks sealed bytes.
#[must_use]
pub fn credit_set_iter_plain(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    let real_end = sidecar_real_len(bytes);
    let bytes = &bytes[..real_end];
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        if off + 4 > bytes.len() {
            return None; // a truncated length prefix
        }
        let n = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]) as usize;
        off += 4;
        // BOUND BEFORE SLICING — never `&bytes[off..off + n]` on an unchecked wire length.
        if n == 0 || n > bytes.len() - off {
            return None;
        }
        out.push(bytes[off..off + n].to_vec());
        off += n;
        if out.len() > crate::cover::BLOCK_FIXED_TX_COUNT {
            return None; // more justifications than the block has slots to carry objects in
        }
    }
    Some(out)
}

/// Whether a credit set this reader can OPEN carries any real entries (`false` when it cannot be opened — a
/// caller that must tell "unreadable" from "empty" reads [`credit_set_open`] itself).
/// §POLES: replaces `credit_set.is_empty()` checks now that the field is constant-shape.
#[inline]
pub fn credit_set_has_entries(bytes: &[u8], key: Option<&crate::cover::CoverKey>) -> bool {
    credit_set_open(bytes, key).is_some_and(|p| sidecar_real_len(&p) > 0)
}

/// Whether a block CARRIES a credit set at all (sealed bytes present) — the door-level question, answered with no
/// key. Genesis and a header shell carry none.
#[inline]
#[must_use]
pub fn credit_set_present(bytes: &[u8]) -> bool {
    !bytes.is_empty()
}

// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════
// §22 — THE SEALED CREDIT SIDECAR (lane funds, 2026-10-28). `Block::credit_set` was the last register row whose
// bytes an observer could INVERT to the block's real object count: the §POLES pad fixed the LENGTH at 16,384 B, but
// the entries stayed public length-prefixed frames ahead of a `u32::MAX` sentinel, so the keyless `sidecar_real_len`
// walk recovered the count from the bytes alone (MEASURED 1/2/7 → 1/2/7 by
// `a_padded_sidecar_is_measured_for_invertibility_back_to_the_real_count`). A Monero peg-in is not public on Monero,
// so that count was NEW metadata of this chain.
//
// THE CLOSURE borrows the §20.2 record precedent exactly (no new key, no new carriage, no new trust): the whole
// sidecar is SEALED under the block's COVER KEY σ — the key the producer already draws beside the body and that
// already rides to peers on the record lane and never on a wallet route. Sealed = `check(32) ‖ frames ‖ sentinel ‖
// zero pad` to [`SIDECAR_PADDED_BYTES`], XOR-masked by a blake3 XOF keyed by (σ, domain). The header's
// `credit_set_root` binds the SEALED bytes whole, so every door binds the body without the key; the frames are read
// only by a holder of σ (the producer at its own graft; a peer once the record lane delivered the key; the fold, in
// canonical order). A keyless observer — a wallet route, a page, an indexer, the block wire itself — sees 16,384 B
// of uniform cover on every block: MEASURED by the re-stated invertibility pin (observer None · holder Some(k)),
// the same shape §20.2 measured for `Serve::da_record_notes`.
//
// WHY A CHECK PREFIX. A wrong or absent key must read as UNREADABLE, never as "an empty set" (the DB-220 class:
// a peer that silently applied nothing). The 32-byte check is `blake3(σ ‖ domain)`; a mismatch is `None`.
//
// A BLOCK WITH NO NOTES AT ALL (output_notes_root = hash("")): its record is empty, so the record lane serves no σ
// for it — such a block seals under the PUBLIC empty-record key derived from its header (`empty_record_credit_key`),
// so every node can still read it. Every produced block carries its reward note, so in production this key is never
// drawn; it exists so that no shape can stall a fold waiting for a key nobody holds.
//
// cons: +32 B of the 16,384 B budget go to the check (16,348 B of frames per block); a receiver without the record's
// key applies the block's objects at its FOLD (canonical order — the DB-344/DB-274 P4b rule) instead of at graft;
// the frozen consensus corpus is re-recorded (the root now binds the sealed bytes: a hard fork at height 1).
// ═══════════════════════════════════════════════════════════════════════════════════════════════════════════════

/// ⭐ §22 — THE GOSSIP ENVELOPE: a block as one PEER sends it to another — its wire form followed by its 32-byte cover
/// key when the sender holds one. The Block's own encoding (`postcard`, what every wallet route, page and explorer
/// serves) carries NO key (`cover_key` is `#[serde(skip)]`; pinned by `the_wire_carries_no_body_and_no_key`); the key
/// rides only in this node-to-node envelope and on the record lane — the §20.2 audience. A receiver then opens the
/// sealed credit set at GRAFT and applies the block's objects exactly as the producer did (DB-224's "a peer applies
/// from the block alone"), instead of waiting for the record lane's key at its fold.
///
/// §22b: when the body holds wide objects, they follow the key as one `postcard(Vec<Vec<u8>>)` — the BIP152 shape (the
/// block names them by hash, the bytes travel beside it). Wide objects ride only with a key: a reader without the key
/// cannot tell which bytes the block names, so a key-less envelope never carries them.
///
/// §22c: the same tail carries the block's spend transactions ([`Block::tx_bodies`]) and its real notes
/// (`Block::output_notes`), so a receiver judges every stated spend itself at its own door and tells a spend row from a
/// cover row from the body it now holds. The tail is `postcard((wide_objects, tx_bodies, output_notes))`, present when
/// any of the three is; the audience is the one that already receives the cover key (peers), never a wallet route.
#[must_use]
pub fn gossip_encode(block: &Block) -> Vec<u8> {
    let mut bytes = postcard::to_allocvec(block).unwrap_or_default();
    if let Some(k) = block.cover_key {
        bytes.extend_from_slice(&k);
        if !(block.wide_objects.is_empty() && block.tx_bodies.is_empty() && block.output_notes.is_empty() && block.agg_tables.is_empty()) {
            // lane agg: the four-part tail only when the block carries openings tables, so every other block keeps today's
            // three-part bytes (one encoding per block, decided by its own contents)
            if block.agg_tables.is_empty() {
                let tail: (&Vec<Vec<u8>>, &Vec<Vec<u8>>, &Vec<u8>) = (&block.wide_objects, &block.tx_bodies, &block.output_notes);
                bytes.extend_from_slice(&postcard::to_allocvec(&tail).unwrap_or_default());
            } else {
                #[allow(clippy::type_complexity)]
                let tail: (&Vec<Vec<u8>>, &Vec<Vec<u8>>, &Vec<u8>, &Vec<Vec<u8>>) =
                    (&block.wide_objects, &block.tx_bodies, &block.output_notes, &block.agg_tables);
                bytes.extend_from_slice(&postcard::to_allocvec(&tail).unwrap_or_default());
            }
        }
    }
    bytes
}

/// The envelope tail, in its ONE encoding for the block's contents: the four-part form (wide objects, transactions,
/// notes, openings tables) exactly when tables are carried, else today's three-part form. Either form with a trailing
/// remainder, an empty tail spelled out, or a four-part form carrying no table is malformed (`None`).
#[allow(clippy::type_complexity)]
fn decode_tail<T: serde::de::DeserializeOwned>(tail: &[u8]) -> Option<(Vec<Vec<u8>>, Vec<T>, Vec<u8>, Vec<Vec<u8>>)> {
    if let Ok(((wide, txs, notes, tables), after)) = postcard::take_from_bytes::<(Vec<Vec<u8>>, Vec<T>, Vec<u8>, Vec<Vec<u8>>)>(tail) {
        if after.is_empty() && !tables.is_empty() {
            return Some((wide, txs, notes, tables));
        }
    }
    let ((wide, txs, notes), after): ((Vec<Vec<u8>>, Vec<T>, Vec<u8>), &[u8]) = postcard::take_from_bytes(tail).ok()?;
    if !after.is_empty() || (wide.is_empty() && txs.is_empty() && notes.is_empty()) {
        return None;
    }
    Some((wide, txs, notes, Vec::new()))
}

/// The inverse of [`gossip_encode`]: a block (its `cover_key` set when the envelope carried one, else `None`). A
/// trailing remainder that is not exactly one key is a malformed envelope (`None`) — never a block with a guessed key.
#[must_use]
pub fn gossip_decode(bytes: &[u8]) -> Option<Block> {
    let (mut block, rest): (Block, &[u8]) = postcard::take_from_bytes(bytes).ok()?;
    match rest.len() {
        0 => {}
        n if n < 32 => return None,
        _ => {
            block.cover_key = Some(rest[..32].try_into().ok()?);
            let tail = &rest[32..];
            if !tail.is_empty() {
                #[allow(clippy::type_complexity)]
                let (wide, txs, notes, tables) = decode_tail::<Vec<u8>>(tail)?;
                block.wide_objects = wide;
                retain_named_wide(&mut block);
                block.tx_bodies = txs;
                retain_named_tx_bodies(&mut block);
                block.agg_tables = tables;
                // §22c: the body, taken only when it IS the body the header commits (a relay's other bytes are dropped)
                if da_notes_root_of(&notes) == block.header.output_notes_root {
                    block.output_notes = notes;
                }
            }
        }
    }
    Some(block)
}

/// ⭐ C1 (SPEED, 2026-11-12) — THE COMPACT ENVELOPE: [`gossip_encode`] with each carried spend transaction replaced by its
/// 32-byte id, for a peer that already pooled it. BORROWED: Bitcoin BIP152 (compact blocks: the block names its
/// transactions, the receiver fills them from its own mempool and asks only for what it lacks).
///
/// MEASURED why (the 24-payer trace, two real nodes, 2026-11-12, docs/SPEED-MAX-PROGRAM §14): a payment is 356,368 B and
/// a block's tail carries every stated spend's body, so a spend-bearing block reached 6.2 MB on a Tor lane of ~200 KB/s,
/// while at more than two nodes every peer had already fetched each body once by the DB-444 inv/getdata relay. A node's
/// pull bandwidth is the chain's throughput ceiling, and this paid it twice per payment.
///
/// What changes and what does not: the hashed block, its proofs, its cover key, its wide objects and its notes are the
/// [`gossip_encode`] bytes exactly; only the tail's transaction list is `Vec<[u8; 32]>` (each body's own id, in the
/// carried order) instead of the bodies. The receiver rebuilds the list from its own pool ([`gossip_decode_compact`]),
/// and [`tx_bodies_commit`] — keyed BLAKE3 over the exact bytes, which the block id commits — decides whether what it
/// rebuilt IS what the block carried. No consensus byte, proof or state changes.
/// cons: the serve decodes each carried body once per answer to read its id (≤ the block's stated spends, ~1 ms each).
#[must_use]
pub fn gossip_encode_compact(block: &Block) -> Vec<u8> {
    let ids: Vec<[u8; 32]> = block
        .tx_bodies
        .iter()
        .filter_map(|b| crate::chain_object::decode_exact::<crate::mempool::PqTx>(b))
        .map(|tx| tx.id.0)
        .collect();
    let mut bytes = postcard::to_allocvec(block).unwrap_or_default();
    if let Some(k) = block.cover_key {
        bytes.extend_from_slice(&k);
        if !(block.wide_objects.is_empty() && ids.is_empty() && block.output_notes.is_empty() && block.agg_tables.is_empty()) {
            if block.agg_tables.is_empty() {
                let tail: (&Vec<Vec<u8>>, &Vec<[u8; 32]>, &Vec<u8>) = (&block.wide_objects, &ids, &block.output_notes);
                bytes.extend_from_slice(&postcard::to_allocvec(&tail).unwrap_or_default());
            } else {
                #[allow(clippy::type_complexity)]
                let tail: (&Vec<Vec<u8>>, &Vec<[u8; 32]>, &Vec<u8>, &Vec<Vec<u8>>) = (&block.wide_objects, &ids, &block.output_notes, &block.agg_tables);
                bytes.extend_from_slice(&postcard::to_allocvec(&tail).unwrap_or_default());
            }
        }
    }
    bytes
}

/// What a compact envelope rebuilt into.
#[derive(Debug)]
pub enum CompactFill {
    /// Every named transaction came from the pool and the rebuilt list is the one the block commits: the block is whole,
    /// as [`gossip_decode`] of the full envelope would have returned it.
    Whole(Block),
    /// The pool lacks a named transaction, or holds one whose bytes are not the carried ones (the commit differs): the
    /// block cannot be judged from this copy. The caller asks the full envelope; nothing here is a verdict on the block.
    Miss,
}

/// The inverse of [`gossip_encode_compact`], filling each named transaction from `pooled` (the receiver's own pool, the
/// bytes [`gossip_encode`] would carry: `postcard` of the pooled transaction). `None` = a malformed envelope, under the same
/// one-encoding rules as [`gossip_decode`].
///
/// ⛔ The fill is accepted ONLY when [`tx_bodies_commit`] over the rebuilt list equals the transition's `bodies`, the
/// commitment the block id binds — so a pooled copy that differs in any byte from the producer's, a missing one, or a list
/// in another order is a `Miss`, never a block judged on bodies it did not carry. The block door then runs every check it
/// runs on a full copy (`spend_evidence::block_spends_are_evidenced`), on these same bytes.
/// DIGITAL-CASH-PRIVACY-REVIEWED: the fill is local (the receiver's own pool, by the ids the block names); nothing is asked.
#[must_use]
pub fn gossip_decode_compact(bytes: &[u8], pooled: impl Fn(&Hash32) -> Option<Vec<u8>>) -> Option<CompactFill> {
    let (mut block, rest): (Block, &[u8]) = postcard::take_from_bytes(bytes).ok()?;
    match rest.len() {
        0 => {}
        n if n < 32 => return None,
        _ => {
            block.cover_key = Some(rest[..32].try_into().ok()?);
            let tail = &rest[32..];
            if !tail.is_empty() {
                #[allow(clippy::type_complexity)]
                let (wide, ids, notes, tables) = decode_tail::<[u8; 32]>(tail)?;
                block.agg_tables = tables;
                block.wide_objects = wide;
                retain_named_wide(&mut block);
                let mut bodies = Vec::with_capacity(ids.len());
                for id in &ids {
                    match pooled(&Hash32(*id)) {
                        Some(b) => bodies.push(b),
                        None => return Some(CompactFill::Miss),
                    }
                }
                block.tx_bodies = bodies;
                retain_named_tx_bodies(&mut block);
                if da_notes_root_of(&notes) == block.header.output_notes_root {
                    block.output_notes = notes;
                }
            }
        }
    }
    let committed = block.note_transition.as_ref().map(|nt| nt.bodies);
    let rebuilt = carried_commit(block.cover_key.as_ref(), &block.tx_bodies, &block.agg_tables);
    match committed {
        Some(c) if c != rebuilt => Some(CompactFill::Miss),
        _ => Some(CompactFill::Whole(block)),
    }
}

/// The sealed credit sidecar's one width, on every non-genesis block: the §POLES 16,384 B. §22b keeps it there by
/// construction — only carriages ≤ [`CREDIT_INLINE_MAX`] ride inline, every wider one is a 40-byte reference — so the
/// set holds the reward (`satoshi::REWARD_FRAME_RESERVE`) plus at least one inline object of every small class, and
/// the references of up to ~300 wide objects. MEASURED and REFUTED on the way here (2026-10-28): a constant width at the
/// widest object needs 2 MiB (a five-leg Liquidation is 1,499,500 B), ≈ 37 s per block on a ~56 KB/s Tor lane; 640 KiB
/// refused that liquidation at the pool door. A frame that does not fit this block waits one block (the selection keeps
/// the budget), never refused.
/// cons: none against §POLES — the same 16 KiB on every block; a wide object costs its own bytes once per peer beside
/// the block (exactly what the pre-§22 inline set cost, without the length leak), and a 40-byte reference inside it.
pub const CREDIT_SET_SEALED_BYTES: usize = 16_384;
/// The check prefix's width inside the plaintext.
pub const CREDIT_SET_CHECK_BYTES: usize = 32;
/// The most frame bytes (length prefixes included) one block's credit set can carry: the producer selects objects
/// up to this budget and leaves the rest pooled for the next block (never refused — delayed one block at most).
pub const CREDIT_SET_FRAME_BUDGET: usize = CREDIT_SET_SEALED_BYTES - CREDIT_SET_CHECK_BYTES - 4;
const CREDIT_SEAL_DOMAIN: &[u8] = b"MUSD-credit-seal-v1";

fn credit_seal_check(key: &crate::cover::CoverKey) -> [u8; CREDIT_SET_CHECK_BYTES] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(CREDIT_SEAL_DOMAIN);
    h.update(b"check");
    *h.finalize().as_bytes()
}

fn credit_seal_mask(bytes: &mut [u8], key: &crate::cover::CoverKey) {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(CREDIT_SEAL_DOMAIN);
    h.update(b"mask");
    let mut stream = vec![0u8; bytes.len()];
    h.finalize_xof().fill(&mut stream);
    for (b, m) in bytes.iter_mut().zip(stream) {
        *b ^= m;
    }
}

/// The public key a block WITHOUT notes seals its credit set under — a pure function of its header, so every node
/// derives it (see the module note above).
#[must_use]
pub fn empty_record_credit_key(header: &BlockHeader) -> crate::cover::CoverKey {
    let mut h = blake3::Hasher::new_derive_key("MUSD/credit-seal/empty-record-key/v1");
    h.update(header.output_notes_root.as_bytes());
    h.update(header.note_commitments_root.as_bytes());
    h.update(&header.timestamp.to_le_bytes());
    for p in &header.parents {
        h.update(p.as_bytes());
    }
    *h.finalize().as_bytes()
}

/// The key a block's credit set is sealed under, given its header and the cover key its body rides with (`None` when
/// this node holds none yet). A note-less block's key is public; every other block's is its σ.
#[must_use]
pub fn credit_seal_key(header: &BlockHeader, cover_key: Option<&crate::cover::CoverKey>) -> Option<crate::cover::CoverKey> {
    match cover_key {
        Some(k) => Some(credit_seal_key_held(header, k)),
        None => (header.output_notes_root == Hash32::hash(&[])).then(|| empty_record_credit_key(header)),
    }
}

/// [`credit_seal_key`] for a holder of the block's cover key (the producer, which drew it beside the body): always a key —
/// the public empty-record key for a note-less block, else that very cover key. ONE rule; `credit_seal_key` answers through it.
#[must_use]
pub fn credit_seal_key_held(header: &BlockHeader, cover_key: &crate::cover::CoverKey) -> crate::cover::CoverKey {
    if header.output_notes_root == Hash32::hash(&[]) {
        empty_record_credit_key(header)
    } else {
        *cover_key
    }
}

/// SEAL a credit set: the frames of `objects` (the producer's carriages, in order) under `key`, exactly
/// [`CREDIT_SET_SEALED_BYTES`] wide. `None` when the frames exceed [`CREDIT_SET_FRAME_BUDGET`] — the producer bounds
/// its selection before sealing, so this is a refutation of a producer bug, never of a block on the wire.
#[must_use]
pub fn credit_set_seal(objects: &[Vec<u8>], key: &crate::cover::CoverKey) -> Option<Vec<u8>> {
    let frames = credit_set_encode(objects);
    if frames.len() > CREDIT_SET_FRAME_BUDGET {
        return None;
    }
    let mut plain = Vec::with_capacity(CREDIT_SET_SEALED_BYTES);
    plain.extend_from_slice(&credit_seal_check(key));
    plain.extend_from_slice(&frames);
    plain.extend_from_slice(&u32::MAX.to_le_bytes());
    plain.resize(CREDIT_SET_SEALED_BYTES, 0);
    credit_seal_mask(&mut plain, key);
    Some(plain)
}

/// OPEN a sealed credit set: the plaintext FRAMES (sentinel and pad still attached, as [`sidecar_real_len`] expects)
/// when `key` is the key it was sealed under. `Some(empty)` for a block that carries no set (genesis, a shell);
/// `None` for a set this reader cannot open — no key, the wrong key, or a malformed width. A caller treats `None` as
/// UNREADABLE (wait for the record lane, or refuse the item), never as empty.
#[must_use]
pub fn credit_set_open(bytes: &[u8], key: Option<&crate::cover::CoverKey>) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if bytes.len() != CREDIT_SET_SEALED_BYTES {
        return None;
    }
    let key = key?;
    let mut plain = bytes.to_vec();
    credit_seal_mask(&mut plain, key);
    if plain[..CREDIT_SET_CHECK_BYTES] != credit_seal_check(key) {
        return None;
    }
    plain.drain(..CREDIT_SET_CHECK_BYTES);
    Some(plain)
}

/// The sealed set's real frame length as a KEY HOLDER reads it (`None` when it cannot be opened).
#[must_use]
pub fn credit_set_real_len(bytes: &[u8], key: Option<&crate::cover::CoverKey>) -> Option<usize> {
    credit_set_open(bytes, key).map(|p| sidecar_real_len(&p))
}

/// The header root of a credit set: the SEALED bytes whole (`da_sidecar_root_of(&[])` for none). One function, so
/// the producer, every door and the fold's shell check cannot drift.
#[must_use]
pub fn credit_set_root_of(sealed: &[u8]) -> Hash32 {
    da_sidecar_root_of(sealed)
}
