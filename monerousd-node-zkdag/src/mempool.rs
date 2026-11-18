// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The PQ transaction mempool (brick 3).
//!
//! Transactions are opaque PQ confidential-spend blobs — the ZK spend proof + confidential
//! outputs live inside `blob`; the mempool never sees plaintext amounts or a plaintext fee
//! (Pillar-1 private). A tx is content-addressed by `id = blake3(blob)` and carries the
//! **nullifier tags** of the notes it spends (the double-spend keys) plus a **client-PoW
//! anti-spam stamp** (#72): P2P fees are free, so spam is priced in client work, not money.
//!
//! Priority is the stamp work (a public, amount-free signal) — more work ranks higher — so the
//! selector never orders by a plaintext fee. The pool is weight-bounded ([`MAX_POOL_WEIGHT`]),
//! so its memory never grows without bound.

use std::collections::{HashMap, HashSet};

use crate::hash::Hash32;
use crate::params::ChainParams;
use serde::{Deserialize, Serialize};

// The per-tx / pool weight caps and the anti-spam stamp band are governance-tunable (crate::params).

/// A spend's DELETION TRANSITIONS — `(note cm, copath)` per consumed note, the ONE thing that authorises
/// a spend on this chain (§AQ). Bounded per transaction by the fixed spend width (`TX_FIXED_NULLIFIER_COUNT`).
pub type SpendTransitions = Vec<([u8; 32], Vec<crate::spend_frontier::Digest4>)>;

/// A pooled PQ transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PqTx {
    /// Content id = `blake3(blob)`.
    pub id: Hash32,
    /// Opaque PQ confidential-spend bytes (ZK proof + confidential outputs). Verified by the ZK
    /// consensus layer (brick 6); the mempool treats it as opaque.
    pub blob: Vec<u8>,
    /// Serialized + verification weight.
    pub weight: u32,
    /// Nullifier tags of the notes this tx spends (the double-spend keys).
    pub nullifiers: Vec<Hash32>,
    /// #72 client-PoW anti-spam stamp nonce.
    /// ⛔ FIXED WIDTH ON THE WIRE (2026-10-29): a varint stamp's width is the solve counter's magnitude, so two spends of one
    /// class gossiped one and two bytes apart at random — a shape that varies per transaction (the T1 tx-shape census read it
    /// as a class difference when four samples happened to split). Eight bytes for every transaction: one shape. cons: ≤ 7 B
    /// per gossiped transaction, 0 B on any block or ledger (the stamp is pool metadata; `stamp_work` already hashes 8 LE bytes).
    #[serde(with = "postcard::fixint::le")]
    pub pow_stamp: u64,
    /// The tx's CONFIDENTIAL OUTPUT notes — concatenated 1153-byte PQ note payloads (recipient + change),
    /// each `note_cm(32) ‖ ML-KEM ct(1088) ‖ enc_amount(32) ‖ view_tag(1)`. When the tx is grafted into a
    /// block these are recorded to the served note index on the SAME generic path as cover/coinbase notes, so
    /// the recipient can locally scan its note and the sender's change reappears. Opaque to the mempool; the
    /// spend proof (`blob`) binds their commitments. `serde(default)` keeps older gossiped txs deserializable.
    #[serde(default)]
    /// ⭐⭐⭐ THE ACCOUNT-DA TARGETS FOR THIS TX'S OWN NOTES — CARRIED, NEVER NODE-LOCAL.
    ///
    /// ROOT CAUSE THIS FIELD EXISTS TO KILL (measured 2026-08-10, cross-device multi-send):
    /// the target used to live only in `pending_bucket` on the ONE node the payer submitted to. Whether a
    /// payment was findable by its owner then depended on WHICH node happened to produce the block carrying
    /// its note — a race on block authorship, not a property of the payment.
    ///   * send 1: node A produced the block -> target rode it -> settled.
    ///   * send 2: node B produced the block -> node B had no pending entry -> `carries 0` -> INVISIBLE.
    /// Node A claimed 3 targets and carried 2; node B carried 0 across all 544 of its blocks.
    ///
    /// That is the class of note the bucket cannot see, and it is why one send worked and the next did not
    /// while nothing about the payment changed. A send must never fail for a reason the sender cannot observe.
    ///
    /// The notes themselves already ride here (`output_notes`) and reach every node, so the index entry that
    /// makes them findable rides the same way. Whichever node wins authorship holds the targets by
    /// construction, because they arrived with the tx it is including — there is nothing to race for.
    /// The whole `PqTx` is postcard-encoded for gossip, so this propagates on the existing path.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the same sealed bytes the block already carried in `Block.account_targets`
    /// and that `/submit` already accepted — each entry is `cm || bucket_id || ek_len || sealed_ek`, sealed to
    /// the recipient's key. Moving them one hop earlier changes no observer's view: cover shape, note count and
    /// block width are untouched, and nothing here distinguishes a real note from a decoy.
    /// ⭐⭐⭐ THE PER-NOTE LOCATOR CLUES FOR THIS TX'S OWN NOTES — CARRIED, NEVER NODE-LOCAL.
    ///
    /// Same defect, same fix as [`PqTx::account_targets`] one field below. A clue used to reach a node only
    /// via `/submit` or a separate gossip message, landing in the node-LOCAL `pending_tags` map. The block
    /// loop drains that map with `pending_tags.remove(&cm)`, and NOTHING orders clue arrival against block
    /// ingest — so on any node that records the block first, the drain finds nothing and the note is stored
    /// with NO locator tag. A note with no tag is in no index, so its owner can never find it from their seed.
    ///
    /// MEASURED 2026-08-10, with the OLI read path already proven correct end to end:
    ///   [oli-tagdrain] this record carried 256 note slot(s) and drained ZERO locator tag(s)
    ///   node-a: 398 such blocks, indexed 2 tags total   node-b: 325 such blocks, indexed 0 tags
    /// The recipient's node held a COMPLETELY EMPTY locator index, which is why send 1 settled only while the
    /// O(chain) walk was still masking it and failed the moment the walk was deleted.
    ///
    /// Riding the tx removes the race by construction: the clue arrives with the very transaction whose notes
    /// it indexes, on the existing postcard-encoded gossip path, so every node that can include the tx in a
    /// block already holds the tags for that block's notes. There is nothing left to order.
    ///
    /// Wire shape `cm || clue_len(u16 LE) || clue`, repeated — the same shape `/submit` already parses.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the identical sender-attached clue bytes `/submit` already accepted and
    /// gossip already relayed in clear. Moving them one hop earlier changes no observer's view: cover shape,
    /// note count and block width are untouched, and a clue distinguishes no real note from a decoy.
    pub note_clues: Vec<u8>,
    #[serde(default)]
    pub account_targets: Vec<u8>,
    #[serde(default)]
    pub output_notes: Vec<u8>,
    /// STAKE-to-earn: the 32-byte `note_cm`s of this tx's output notes that are being STAKED (the staker keeps
    /// ownership; the note is locked into the stake accumulator to earn a pro-rata share of the fee-redistribution
    /// pool). Recorded into the stake tree on graft, in addition to the normal served index. Empty for a plain
    /// transfer. `serde(default)` keeps older gossiped txs deserializable.
    #[serde(default)]
    pub stake_notes: Vec<u8>,
    /// VALIDATOR BOND: `bond_id(32 bytes) ‖ bond_amount(u64 LE, 8 bytes)` — the validator's PQ-key-hash identity
    /// and the PUBLIC weight it bonds. output0 (to the validator's OWN address) locks EXACTLY `bond_amount`
    /// (welded in the carrier via `verify_bond_validity_carrier_bytes`), so on graft the node admits `bond_id`
    /// with that weight into the validator set. Empty for a non-bond tx. `serde(default)` keeps older txs OK.
    #[serde(default)]
    pub bond_notes: Vec<u8>,
    /// TRUSTLESS NON-MEMBERSHIP WITNESSES — one per entry in `nullifiers`, self-obtained by the SPENDER (queried
    /// self-built LOCALLY on the spender's OWN node from public data — `nf` never leaves the device) and carried here. Each proves its nullifier
    /// is UNSPENT against the node's O(1) `nullifier_acc` root (`verify_unspent` at admit, `verify_and_insert` at
    /// block-apply), so the node needs NO stored nullifier set to gate double-spends — no-growth + trustless (a
    /// bad/stale witness is rejected; no witness-server, no wallet-held set). `serde(default)` keeps older gossiped
    /// txs deserializable; a witness-carrying tx is gated by the O(1) acc, a witness-less one by the legacy set.
    #[serde(default)]
    pub nullifier_witnesses: Vec<crate::nf_sparse::CompressedCopath>,
    /// ⭐ FOLD-NOT-HOLD SPEND WITNESS (brick C3) — one folded ABSENCE proof per entry in `nullifiers`, the O(1)
    /// copath-free replacement for `nullifier_witnesses` (the O(DEPTH) `CompressedCopath`). The spender self-builds
    /// each from the replicated DA (`prove_nf_absence_chain`); the node verifies it against its O(1) A_tip
    /// (`verify_nf_absence_chain`) with NO copath, NO held tree. `serde(default)` keeps older txs deserializable.
    /// O1-INFINITY-REVIEWED: this is a PER-TX field, NOT a per-chain store — its length is the tx's nullifier count,
    /// bounded by the FIXED `cover::TX_FIXED_NULLIFIER_COUNT` constant (count-independent of chain height/blocks), and
    /// each `NfAbsenceWitness` is itself a CONSTANT-size fold proof (no DEPTH, no per-block growth). f(fixed constants).
    #[serde(default)]
    pub nullifier_absence: Vec<crate::nf_sparse::NfAbsenceWitness>,
    /// ⭐ THE O(1) NOTE-MEMBERSHIP CARRIER — the spender's constant-size proof that the note it is spending is
    /// a member of this chain, replacing the depth-32 copath a wallet could only rebuild by paging the whole
    /// note stream. Proves `note ∈ block_root` once and folds every later block root; the node checks it
    /// against its OWN accumulator (`Node::verify_membership_carrier`), so nothing is trusted.
    ///
    /// CONSTANT SIZE at any chain height — measured 9,349 B flat over 24 folds — so this adds no growth axis
    /// to the wire. `serde(default)` keeps older gossiped txs deserializable.
    #[serde(default)]
    pub membership_carrier: Vec<u8>,
    /// The PUBLIC stand-in for the spent note's leaf: `note_leaf_commitment(leaf, tx_binder, blind)` (DB-363). NEVER
    /// the leaf itself — that is the value written when the note was RECEIVED, so publishing it would link this spend
    /// to that receive — and never a value recomputable from public inputs: `blind` is the spender's per-send CSPRNG
    /// draw, shared only by the two proofs, so no observer joins this commitment to any leaf (the unblinded
    /// `P(leaf, tx_binder)` was recomputable from the tx's own nullifier — MEASURED, 643 of 1,024 leaves singled out).
    /// Scoped to this tx, so a carrier cannot be replayed into another one. `serde(default)` for wire back-compat.
    #[serde(default)]
    pub membership_leaf_commit: [u8; 32],
    /// The tip transition the carrier folded UP TO: `tip_prev ‖ tip_root ‖ tip_acc`, 96 bytes.
    ///
    /// The carrier NAMES its own endpoint; the node reconstructs forward from there to its own tip. Reading
    /// the tip from the node instead would make the gate vacuous, and requiring the carrier to match the
    /// node's LIVE tip would make it unsatisfiable — the accumulator moves every block while building a spend
    /// takes seconds. `serde(default)` for wire back-compat.
    #[serde(default)]
    pub membership_tip: Vec<u8>,
    /// The frontier append ordinal the carrier folded through. Bounds the node's catch-up work to how far
    /// behind this spender is, never to chain height.
    #[serde(default)]
    pub membership_folded_through: u64,
    /// ⭐⭐⭐ THE SPEND-OR-DECOY CARRIER — the proof that lets a BLOCK state this transaction's whole
    /// constant-width tag set, and therefore the thing that lets a multi-input spend settle at all.
    ///
    /// ⛔ IT HAS TO RIDE THE TRANSACTION, FOR THE SAME REASON `account_targets` DOES. It used to be
    /// parsed from the `/submit` HTTP body and dropped: the admitting node checked it and nothing kept
    /// it, so whichever node won authorship had no carrier to aggregate and the block could state only
    /// single-input spends. Whether a consolidation could settle then depended on WHICH node produced
    /// the block — a race on authorship, not a property of the payment. Carried here, the producer holds
    /// it by construction because it arrived with the transaction it is including.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a zero-knowledge carrier over the tag set the transaction ALREADY
    /// publishes in `nullifiers`. Its witness — the cover secret, every note key, and critically the
    /// REAL-INPUT COUNT — is absent by construction: the selector is a witness column and the trace is
    /// blinded, so the bytes are the same shape whatever `k` was. `serde(default)` keeps older gossiped
    /// transactions deserializable.
    #[serde(default)]
    pub spend_or_decoy: Vec<u8>,
    /// ⭐⭐⭐ DB-223 — THE SPEND INPUT'S MEMBER-PATH CARRIER: the wallet's proof, over its own depth-64 path, that the
    /// note this spend consumes is a leaf of the spend tree under the anchor its tuple names
    /// (`usdm_decider::member_path_gate::prove_member_path_carrier`). It rides the transaction for the reason
    /// `spend_or_decoy` does: the producer aggregates what arrived with the transactions it includes
    /// (`Block::member_transition`). Empty on a transaction that carries none (the legacy membership door still
    /// judges it). DIGITAL-CASH-PRIVACY-REVIEWED: zero-knowledge over the path; its public tuple names no record, no
    /// leaf and no position — `leaf_commit` hides the leaf under this spend's binder, and the binder is the
    /// nullifier this transaction already publishes.
    #[serde(default)]
    pub member_carrier: Vec<u8>,
    /// ⭐ DB-223 — the carrier's public tuple in its wire form (`member_transition::write_tuple`, 128 B), empty with it.
    #[serde(default)]
    pub member_tuple: Vec<u8>,
    /// ⭐ THE CHAIN CLOCK THIS SPEND WAS PROVEN AGAINST, unix ms (goods spec §9.1; BORROWED: Bitcoin's `nLockTime`, judged
    /// by median-time-past as BIP113 does). A note-class spend's carrier binds it in its transcript, so the door and the
    /// producer verify the carrier under exactly this value, and a block states the spend only when the block's own
    /// ledger clock has reached it (`NoteTransition::clock_ms`). It is a LOWER bound only: a spend never expires.
    /// Why a spend has one at all: a vault note (a protected purchase, a subscription period) has a branch its default
    /// party may take once the chain clock passes the vault's time, and every spend states a clock so that branch is
    /// indistinguishable from a payment.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: every wallet states the SAME value in a given chain hour
    /// ([`crate::note_transition::wallet_spend_clock`]: the hour grid, a third of an hour behind the chain clock), the
    /// pool door refuses any value off that grid, and the value never reaches a block (the ledger proves
    /// `clock ≤ block clock` on the row's absorbed tuple and publishes one clock per block). So the field tells a
    /// relay nothing the moment it saw the transaction does not already tell it.
    /// LAST on the wire and `serde(default)`: a transaction encoded before this field decodes with clock 0, which is
    /// the clock every carrier of the old entry points was proven against. cons: 8 B per gossiped transaction, 0 B on
    /// any block or ledger.
    #[serde(default, with = "postcard::fixint::le")]
    pub clock_ms: u64,
}

impl PqTx {
    /// The content id a blob must hash to.
    pub fn content_id(blob: &[u8]) -> Hash32 {
        Hash32::hash(blob)
    }

    /// The anti-spam stamp work = leading-zero bits of `blake3(id || pow_stamp || network_id)`. Doubles as the
    /// (amount-free, privacy-preserving) selection priority.
    ///
    /// ⛔⛔⛔ THE STAMP IS BOUND TO ITS NETWORK — Ethereum's EIP-155 property, in our shape. The work a tx
    /// carries is the authorization the mempool charges it for admission, and it used to be computed over
    /// `id || pow_stamp` alone: the SAME bytes on every network. So a tx stamped on testnet arrived on mainnet
    /// carrying full, valid work — nothing in the stamp gate could tell the two apart.
    ///
    /// Folding the network id in means the grind only ever satisfies the chain it was ground for. Replayed
    /// elsewhere it hashes to a different digest and fails the bits gate, exactly as an EIP-155 signature
    /// fails on a chain it was not signed for. This costs no wire byte and no new field: the value is read
    /// from the network identity this process fixed at genesis.
    ///
    /// This is the ANTI-SPAM half. The deterministic half for a SPEND is the membership carrier: it names an
    /// endpoint on this chain and the node reconstructs it from its OWN roots, so a foreign-chain spend is
    /// refused outright rather than probabilistically. Both must hold — see the tests below.
    pub fn stamp_work(&self) -> u32 {
        // The same 72 preimage bytes `id ‖ pow_stamp (le) ‖ network id`, laid in a stack buffer: every cover grind
        // (255 covers × ≈ 2^8 tries per template) and every template sort comparison hashes one, and the heap buffer
        // was ≈ 15 % of the stamp's samples (scratchpad/night/link29-sample.txt). cons: none — byte-identical preimage.
        let mut buf = [0u8; 72];
        buf[..32].copy_from_slice(self.id.as_bytes());
        buf[32..40].copy_from_slice(&self.pow_stamp.to_le_bytes());
        buf[40..].copy_from_slice(crate::params::process_network_id().as_bytes());
        leading_zero_bits(Hash32::hash(&buf).as_bytes())
    }
}

/// Count the leading zero bits of a 32-byte digest.
pub fn leading_zero_bits(h: &[u8; 32]) -> u32 {
    let mut n = 0u32;
    for b in h {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros();
            break;
        }
    }
    n
}

/// Why a tx was rejected. Every variant rejects the OFFENDING tx only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MempoolError {
    #[error("tx id does not match the blob content hash")]
    InvalidId,
    #[error("tx weight {0} exceeds the per-tx cap")]
    TooHeavy(u32),
    /// FAIL-CLOSED AT ADMISSION: the tx cannot fit a block's fixed note shape, so accepting it would strand it
    /// in the pool permanently. POOL-ACCEPT ⇒ MINEABLE is the invariant added here: every bound the block
    /// template enforces must ALSO be an admission bound, or the pool is a silent black hole — the sender is
    /// told "accepted", the tx never reaches a block, nothing is ever logged, and from the owner's view the
    /// funds simply cease to exist. Rejecting loudly at submit is what every classical chain does instead.
    #[error(
        "tx carries {got} output notes, more than a block's fixed {max} — it could never be mined"
    )]
    Unmineable { got: usize, max: usize },
    #[error("anti-spam stamp work {got} < required {need}")]
    InsufficientStampWork { got: u32, need: u32 },
    /// ⭐ H5 / DB-273 (C): a transaction carries NO account targets. The per-WALLET bucket id and the recipient's ML-KEM ek
    /// repeated in every payment to one wallet (census `PqTx::account_targets`, LINKAGE); detection runs on OLI alone since
    /// DB-273 L5, and the wallet sends none. Refused at admission so no client can reintroduce the linker.
    #[error("the transaction carries account targets — the per-wallet bucket linker is retired (DB-273 C); send none")]
    AccountTargetsCarried,
    #[error("tx already in the pool")]
    AlreadyKnown,
    #[error("the chain already carries this object's transition (a settled peg-in / peg-out / wrapped mint)")]
    AlreadySettled,
    #[error("nullifier conflict (double-spend vs a pooled tx)")]
    DoubleSpend,
    /// ⛔ THE SPEND'S CARRIED NULLIFIER-ABSENCE WITNESS DID NOT VERIFY against this node's O(1) accumulator.
    ///
    /// This shares a cause with a real double-spend and is NOT the same as [`Self::DoubleSpend`], which means
    /// "a tx ALREADY IN THIS POOL spends the same note". Both used to return `DoubleSpend`, whose text names
    /// a pooled conflict — so a wallet carrying a merely STALE witness was told it was double-spending
    /// against a pooled tx that did not exist. On the cross-device send that sent the whole diagnosis
    /// chasing a phantom. The absence proof failing is honestly ambiguous between two causes, so the message
    /// states both rather than picking the one that reads better.
    #[error("the spend's carried nullifier-absence witness did not verify against this node's accumulator — either the note is already spent on-chain, or the witness is missing/stale/forged (this is NOT a conflict with a pooled tx)")]
    NullifierWitnessRejected,
    #[error("pool is at its weight cap")]
    Full,
    /// #135 the tx's PQ spend carrier failed the ZK verify (the direct light-decider gate rejected it) — a
    /// malformed / tampered / invalid-spend blob. Fail-closed: the tx is never admitted.
    #[error("PQ spend carrier failed ZK verify")]
    InvalidProof,
    /// ⛔ DB-327 / DB-330 — THE STAKE FORMAT IS RETIRED AT THE POOL. `stake_notes` = cm ‖ amount ‖ nullifier published
    /// the staked AMOUNT and the note's FUTURE nullifier to every node the pool relays to (a value leak and a
    /// spend-to-stake link), and DB-313 measured that no block ever laid one. The private stake is DB-237.
    #[error("REFUSED: this transaction carries stake_notes, a retired format that publishes the staked amount and the note's future nullifier (DB-327); the private stake is DB-237")]
    StakeFormatRetired,
    /// ⭐⭐⭐ DB-223 PHASE C (Q7, 2026-10-02) — THE MEMBER CARRIER IS MANDATORY FOR EVERY USDm SPEND. A spend proves its
    /// input EXISTS (a member path to an anchor in this chain's ring, cross-bound to the spend), or it is not a spend: a
    /// peer refuses a block stating a spend without one, so a pool that admitted it would only lay refused blocks. Also
    /// refused: a member carrier on a transaction that states no spend. (Phase B's OPTIONAL carrier, which told spends
    /// apart, is gone with this: every spend carries one, so none is distinguished by carrying it.)
    #[error("REFUSED: a USDm spend must carry its input's member-path carrier (DB-223 phase C) — without it the chain cannot tell the spent note exists; a non-spend must carry none. Nothing was admitted")]
    MemberCarrierRequired,
    /// ⭐ DB-449 — the spend's member-path carrier is anchored at a root THIS node's fold has not produced inside its anchor
    /// ring. Not a verdict on the proof (no proof was verified): the anchor is either ahead of this node's fold (a peer
    /// folded further) or off its spine within the reach. It was answered `InvalidProof` before, which named a failed
    /// verify that never ran (MEASURED link 72: all 38 `InvalidProof` refusals of fetched spends were this check).
    #[error("the spend's member-path carrier is anchored at a root this node's fold has not produced within its anchor ring (ahead of this node's fold, or off its spine) — no proof was judged")]
    AnchorNotHeld,
    /// ⭐ §RF-3 — a carried tag is not the canonical byte form of a digest (`cm_bytes_to_root` decodes `None`). Every real
    /// tag is `leaf_to_cm_bytes(Poseidon…)` and every decoy is `cover::digest_shaped_decoy`, so no honest wallet makes one;
    /// pooled, it forces its block out of the slot-ledger class into the legacy count-stating shape.
    #[error("REFUSED: a carried tag is not a canonical digest — every real tag and every decoy is one, so this transaction came from no honest wallet. Nothing was admitted")]
    NonCanonicalTag,
}

/// The weight-bounded PQ mempool.
pub struct Mempool {
    txs: HashMap<Hash32, PqTx>,
    /// ⭐ PRIVATE SHARDING §2.3: txs a template may not carry yet, because their evidence has not arrived. They stay pooled.
    held_back: std::collections::HashSet<Hash32>,
    arrival: HashMap<Hash32, u64>,
    /// nullifier -> owning tx id, for O(1) double-spend detection.
    spent: HashMap<Hash32, Hash32>,
    total_weight: u64,
    counter: u64,
    /// TX LIFECYCLE (block age). `arrival` is an insertion COUNTER and cannot answer "how long has this been
    /// waiting?" in chain terms. This records the height each tx was admitted at, so a tx that is pooled but
    /// never settling becomes VISIBLE (`pooled_since_before`) instead of vanishing silently — the failure that
    /// makes a chain unsafe to hold real money on. Node-LOCAL only: never served, never gossiped, so it adds
    /// no which-item query and no timing metadata to any observer.
    admitted_height: HashMap<Hash32, u64>,
    /// The height the pool currently believes the chain is at, set by the node each block.
    current_height: u64,
    /// ⛔ WHAT A REFUSED RE-STAMP COSTS THIS NODE. See [`RestampGuard`]. Node-LOCAL only: never
    /// serialized, never served, never gossiped — so it adds no which-item query, no count and no timing
    /// metadata to any observer.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by `params.max_pool_weight` (MAX_POOL_WEIGHT), the SAME fixed
    /// constant that caps `txs` — one entry per POOLED id and nothing else, so this map can never hold
    /// more keys than the pool itself. It is written only for an id ALREADY in `txs` and released beside
    /// its tx in [`Mempool::remove`], exactly as `arrival` and `admitted_height` are. No term in chain
    /// height, block count or note count exists.
    restamp_bar: HashMap<Hash32, RestampGuard>,
    /// ⭐ DB-444 — ids that LEFT this pool (a block carried them, or an eviction) or were refused at its door, newest last,
    /// so a transaction inventory naming one again is not fetched again (Bitcoin Core's
    /// `m_recent_confirmed_transactions` + `m_recent_rejects`). Exact (a set mirrors the ring), process-local, never
    /// served. O1-FOOTPRINT-REVIEWED: bounded by [`TX_RECENT_GONE_MAX`]; the oldest id leaves first — forgetting one
    /// costs at most one fetch of a body this node then refuses again.
    recent_gone: (std::collections::VecDeque<Hash32>, std::collections::HashSet<Hash32>),
    /// ⭐ G14 — WHO LAYS A POOLED FINALITY VOTE ([`Mempool::set_vote_lay`]): this node's own voter id, and the 1-in-N odds a
    /// template draws a vote another voter signed. Node-local selection policy, never served; two words.
    vote_lay: (Option<[u8; 32]>, u64),
    params: ChainParams,
}

/// DB-444: how many recently gone ids the pool remembers ([`Mempool::recently_gone`]). A fixed bound: eight full
/// inventories of ids (`protocol::TX_INV_MAX` each).
pub const TX_RECENT_GONE_MAX: usize = 8 * crate::protocol::TX_INV_MAX;

/// ⭐ A-F66 — the most stamp work above the pool's floor that counts in the template's inclusion draw: 2 bits, a 4x weight.
/// A sender's congestion bump still moves its own spend ahead; a grinder can no longer buy every slot of every block with CPU
/// (at the uncapped 52 bits, ten extra bits weighed 1,024 honest spends). MEASURED why: docs/CHAIN-DEATH-AUDIT-20261115.md C9
/// (32 slots a block, a flat 0.001 USDm fee, 8-24 stamp bits: about 5,500 USDm a day and ~50 cores censored every payment at the
/// 2 blocks/s target). Node-local selection policy; no consensus rule and no observable shape changes.
pub const STAMP_PRIORITY_BITS_MAX: u32 = 2;

/// Per-pooled-id state that makes a refused re-stamp cost this node no more than it cost its sender.
///
/// ⛔⛔⛔ THE DEFECT WAS THE ASYMMETRY, NOT THE RATE. `accept_inner`'s re-stamp arm refuses any frame
/// whose envelope differs from the pooled one, and it did that by re-encoding BOTH structs on every
/// arrival. The attacker's side it had to pay anyway; the VICTIM'S side it paid for bytes the attacker
/// never sent — a forgery needs only `blob` and may leave `membership_carrier`, `nullifier_witnesses`
/// and the rest EMPTY while the pooled payment carries all of them. MEASURED by
/// `a_refused_restamp_costs_the_attacker_one_grind_and_this_node_one_arrival`: 4,717 bytes of lock-held
/// re-encode for 2,621 bytes sent, on every replay of ONE ground frame.
///
/// ⛔ TWO OBVIOUS FIXES ARE BOTH WRONG, AND BOTH WERE MEASURED RED BEFORE THIS ONE LANDED:
///   1. Raise the POOLED tx's stamp on refusal. That is a half-applied bump — a write on a path that
///      returned an error — on an envelope this node re-gossips and packs.
///      `a_restamp_that_moves_any_field_but_the_stamp_is_refused_on_both_nodes` refuses it, rightly.
///   2. Keep a node-local WORK bar and make an arriving stamp beat it. That hands a stranger a
///      censorship lever: one grind raises the bar and the payment's OWNER must then out-grind the
///      ATTACKER to bump their own starved tx.
///      `the_honest_congestion_bump_still_lands_after_a_full_gossip_round_trip` refuses it, rightly —
///      the congestion escape hatch is the only action the owner of a starved payment has.
///
/// ⭐ SO NEITHER SIDE IS GATED; THE COST IS REMOVED INSTEAD. The pooled envelope's digest is computed
/// ONCE, when the tx enters, and cached here. A refusal then costs one encode of the ARRIVING frame —
/// bytes its sender already produced and transmitted — and nothing of the victim's. The comparison's
/// verdict is bit-identical; only the work is symmetric now. Admission is untouched, so no honest bump
/// can be priced out by anybody.
pub struct RestampGuard {
    /// `envelope_sans_stamp` of the pooled tx, computed at insert. `None` when that encode failed, which
    /// keeps the arm FAIL-CLOSED exactly as it was.
    envelope: Option<Hash32>,
    /// Highest stamp work any REFUSED frame has presented for this id. It gates ONLY the diagnostic line
    /// below — never admission — so an unbounded stream of lines needs an unbounded stream of
    /// ever-higher grinds, while a payment's owner is never charged for a stranger's work.
    logged_work: u32,
}

/// TEST-ONLY counter for re-encodes of the POOLED struct on the re-stamp arm — the clone, postcard
/// encode and blake3 digest of bytes the ARRIVING party never sent, run UNDER THE NODE LOCK. This is the
/// asymmetry itself, so the pin measures it directly rather than through a proxy on the pooled stamp
/// that two sibling pins correctly forbid moving. Thread-local so cargo's parallel test threads never
/// perturb each other.
#[cfg(test)]
thread_local! {
    pub static POOLED_REENCODES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// What the PRODUCER lays into a block after its template selection, held back from the block's fixed budgets
/// ([`Mempool::select_for_template_reserving`]): tags in the nullifier lane and notes in the served payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TemplateReserve {
    pub tags: usize,
    pub notes: usize,
    /// §22 — credit-set FRAME bytes (length prefixes included) the producer lays after selection: its reward's carriage
    /// and the staged justifiers'. The selection keeps every framed object's carriage inside
    /// `block::CREDIT_SET_FRAME_BUDGET − frames`, so the sealed sidecar is one width on every block.
    pub frames: usize,
}

impl TemplateReserve {
    /// Nothing reserved — a template for a block that lays no producer object.
    pub const NONE: TemplateReserve = TemplateReserve { tags: 0, notes: 0, frames: 0 };
    /// The SATOSHI mining reward (`satoshi::SatoshiRewardTx`): its own nullifier in the block's lane (`satoshi::reward_nf`)
    /// and its note in the block's payload.
    pub const MINING_REWARD: TemplateReserve = TemplateReserve { tags: 1, notes: 1, frames: 0 };
}

impl Mempool {
    pub fn new() -> Self {
        Self::with_params(ChainParams::default())
    }

    /// A mempool bound to an explicit (e.g. governance-set) parameter set.
    pub fn with_params(params: ChainParams) -> Self {
        Mempool {
            held_back: std::collections::HashSet::new(),
            txs: HashMap::new(),
            arrival: HashMap::new(),
            spent: HashMap::new(),
            total_weight: 0,
            counter: 0,
            admitted_height: HashMap::new(),
            restamp_bar: HashMap::new(),
            recent_gone: (std::collections::VecDeque::new(), std::collections::HashSet::new()),
            vote_lay: (None, 1),
            current_height: 0,
            params,
        }
    }

    /// ⭐⭐⭐ G14 (lane b 2026-10-25) — A FINALITY VOTE IS LAID BY ITS VOTER; A RELAYER DRAWS IT 1-IN-`relayers`.
    ///
    /// THE DEFECT: a vote gossips to every node in well under one block relay, and every node's selector laid every pooled
    /// vote, so each vote rode one block per producer that pooled it before seeing a carrier. Unlike a spend (DB-443's
    /// below-saturation duplicate costs only block space nothing else wanted), a carried vote is ~5.3 KB held in every
    /// node's unfolded window until the fold, so the copies grow as producers × voters per block. MEASURED
    /// (scratchpad/verify/simmem-c99ff64.log): 10 nodes, 9,539 bond-lane entries over 1,668 distinct (5.7×, 3 nodes 2.5×),
    /// bond_set 490 MB of 645 MB unfolded, slope 340 MB/node over the 300 gate.
    ///
    /// THE SHAPE, BORROWED: Lewenberg–Sompolinsky–Zohar "Inclusive Block Chain Protocols" (FC 2015) §5 / rusty-kaspa's
    /// weighted random selector — concurrent producers draw at random so parallel blocks collide less — with the voter as the
    /// carrier of first resort (Ethereum: the attester publishes its own attestation). The voter's node always lays its own
    /// vote; a relayer's template draws someone else's with odds 1/`relayers` (the caller passes the seated voters less
    /// itself), from the template's SECRET draw, so ~one relayer per round also lays it: the vote still lands if its
    /// voter's block is orphaned or the voter never produces. Peers accept a vote from any carrier, as before — this is
    /// producer policy, not consensus.
    /// cons: a vote whose voter's node does not lay it waits a geometric ~1–2 templates for a relayer's draw instead of the
    /// next one; no state (two words), O(votes) blake3 per template.
    pub fn set_vote_lay(&mut self, own_voter: Option<[u8; 32]>, relayers: u64) {
        self.vote_lay = (own_voter, relayers.max(1));
    }

    /// G14: does the template with secret `draw` lay `tx` ([`Self::set_vote_lay`])? Every non-vote, its own vote, and a
    /// relayed vote the draw picks — yes.
    fn lays_now(&self, tx: &PqTx, draw: &[u8; 32]) -> bool {
        let Some((crate::chain_object::Class::FinalityVote, payload)) = crate::chain_object::unframe(&tx.blob) else {
            return true;
        };
        let (own, relayers) = self.vote_lay;
        let Some(cert) = crate::finality_vote_tx::decode(payload) else { return true };
        if relayers <= 1 || own == Some(crate::pqauth::pubkey_id(&cert.pubkey)) {
            return true;
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD-relayed-vote-draw-v1");
        h.update(draw);
        h.update(tx.id.as_bytes());
        let mut x = [0u8; 8];
        x.copy_from_slice(&h.finalize().as_bytes()[..8]);
        u64::from_le_bytes(x) % relayers == 0
    }

    /// ⭐ SPEED stage 2 (docs/CHAIN-SPEED-ROOT-SPEC-20261110.md §11.10) — the pooled finality votes a block being SEALED
    /// now lays that its template did not: every pooled vote the G14 policy lays for `draw` ([`Self::lays_now`]: the
    /// voter's own node always, a relayer 1-in-`relayers`) and whose id `have` does not already name.
    /// Producer policy, exactly as G14 is: peers accept a vote from any carrier.
    /// cons: one pass over the pool per sealed block (a class byte read per entry); nothing stored.
    pub fn votes_to_lay_at_seal(&self, draw: &[u8; 32], have: &dyn Fn(&Hash32) -> bool) -> Vec<PqTx> {
        self.iter()
            .filter(|tx| matches!(crate::chain_object::unframe(&tx.blob), Some((crate::chain_object::Class::FinalityVote, _))))
            .filter(|tx| !have(&tx.id) && self.lays_now(tx, draw))
            .cloned()
            .collect()
    }

    /// DB-444: did `id` leave this pool, or get refused at its door, recently ([`TX_RECENT_GONE_MAX`])?
    pub fn recently_gone(&self, id: &Hash32) -> bool {
        self.recent_gone.1.contains(id)
    }

    /// DB-444: remember `id` as gone (left or refused). Idempotent; bounded.
    pub fn note_gone(&mut self, id: Hash32) {
        if !self.recent_gone.1.insert(id) {
            return;
        }
        self.recent_gone.0.push_back(id);
        while self.recent_gone.0.len() > TX_RECENT_GONE_MAX {
            if let Some(old) = self.recent_gone.0.pop_front() {
                self.recent_gone.1.remove(&old);
            }
        }
    }

    /// Install a governance-approved parameter update (no restart; affects future accepts).
    pub fn set_params(&mut self, params: ChainParams) {
        self.params = params;
    }

    /// ⭐ THE POOL'S OWN RESIDENT BYTES — the second store the no-growth census could not see.
    ///
    /// A pooled transaction carries its carrier `blob`, its `output_notes` (the fixed cover payload) and
    /// its witness columns, so the pool's footprint is f(pool depth x tx width), not f(pool depth) alone.
    /// Summed from the real fields for the same reason the DAG's is: a written-down per-tx constant drifts.
    #[must_use]
    pub fn census_bytes(&self) -> usize {
        self.txs
            .values()
            .map(|t| {
                t.blob.len()
                    + t.output_notes.len()
                    + t.stake_notes.len()
                    + t.bond_notes.len()
                    + t.note_clues.len()
                    + t.account_targets.len()
                    + t.nullifiers.len() * 32
            })
            .sum()
    }

    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Size of the spent-nullifier map — a RAM-attribution accessor. If this grows O(spends) it is a per-block
    /// grower on the produce/ingest path (the mempool's respend gate holds one entry per seen nullifier).
    pub fn spent_len(&self) -> usize {
        self.spent.len()
    }

    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    pub fn contains(&self, id: &Hash32) -> bool {
        self.txs.contains_key(id)
    }

    /// Borrow a pooled tx by id (e.g. so a producer can read the nullifiers it is about to commit on-chain).
    pub fn iter(&self) -> impl Iterator<Item = &PqTx> {
        self.txs.values()
    }

    pub fn get(&self, id: &Hash32) -> Option<&PqTx> {
        self.txs.get(id)
    }

    /// Does some ACCEPTED transaction in this pool carry a note whose commitment is `cm`?
    ///
    /// This is the pool's half of "does this node have EVIDENCE of that commitment" — the question the
    /// locator-tag door asks before it stages anything durable for a commitment a stranger merely named.
    /// A note's commitment is the first 32 bytes of its fixed-width chunk, which is the same read the block
    /// assembly and the record loop do. cons: none — the walk is over pooled transactions and their fixed
    /// `cover::BLOCK_FIXED_NOTE_COUNT`-bounded note carriage, so it is f(the pool's fixed capacity), never
    /// f(chain height, block count or note count), and it stores nothing.
    pub fn holds_note_cm(&self, cm: &[u8; 32]) -> bool {
        self.txs.values().any(|t| {
            t.output_notes
                .chunks(crate::cover::PQ_NOTE_BYTES)
                .any(|ch| ch.len() >= 32 && ch[..32] == cm[..])
        })
    }

    /// Every pooled tx carrier blob — the REAL admitted PQ spend carriers, the whole mempool. The admission-drop
    /// benchmark times the OLD downstream cost (per-tx `pqspend_direct_verify_carrier` over a full block of txs)
    /// that the block's recursive settlement aggregate ELIMINATES (downstream verifies ONE O(1) proof instead).
    pub fn all_blobs(&self) -> Vec<Vec<u8>> {
        self.txs.values().map(|t| t.blob.clone()).collect()
    }

    /// Every pooled tx's STORED content id (= blake3 of its blob, computed once at admission) as raw 32-byte
    /// arrays, in the SAME iteration order as [`Self::all_blobs`]. The TRUE-O(1) downstream settlement verify
    /// binds against these ids the node already holds — it never re-hashes the multi-KB carrier bundles.
    /// Replay calibration (lane b, T3): the pooled ids in `arrival` order — the tiebreak selection reads.
    #[cfg(test)]
    pub fn ids_in_arrival_order_for_test(&self) -> Vec<Hash32> {
        let mut v: Vec<(u64, Hash32)> = self.arrival.iter().map(|(id, n)| (*n, *id)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, id)| id).collect()
    }

    pub fn all_tx_ids(&self) -> Vec<[u8; 32]> {
        self.txs
            .values()
            .map(|t| {
                let mut a = [0u8; 32];
                a.copy_from_slice(t.id.as_bytes());
                a
            })
            .collect()
    }

    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }

    /// The anti-spam stamp bits currently required, scaled by pool occupancy.
    pub fn required_stamp_bits(&self) -> u32 {
        let base = self.params.pow_stamp_base_bits;
        let span = self.params.pow_stamp_max_bits.saturating_sub(base);
        let cap = self.params.max_pool_weight.max(1);
        let occ = self.total_weight.min(cap);
        let extra = ((occ * span as u64) / cap) as u32;
        base + extra
    }

    /// ⭐ THE POOL'S CHEAP REFUSALS, ASKED BEFORE ANY PROOF IS VERIFIED (link 62, §9.6 q5 at the gossip door). The id must
    /// bind the blob, the weight fit, the anti-spam stamp meet this pool's LIVE floor, and an id this pool already holds is
    /// `AlreadyKnown` unless its stamp is strictly higher (the congestion bump `accept_inner` then judges). Every check is
    /// one `accept_inner` already runs, in the same order, so nothing changes about what is admitted — only that a gossiped
    /// echo or an unstamped flood is refused before the door spends a verify on it. BORROWED-FROM Bitcoin Core: the cheap
    /// `PreChecks` (already in the pool, policy) run before `CheckInputScripts`. O(1) but one blake3 over the blob.
    pub fn cheap_refusal(&self, tx: &PqTx) -> Option<MempoolError> {
        if tx.id != PqTx::content_id(&tx.blob) {
            return Some(MempoolError::InvalidId);
        }
        if tx.weight > self.params.max_tx_weight {
            return Some(MempoolError::TooHeavy(tx.weight));
        }
        let (got, need) = (tx.stamp_work(), self.required_stamp_bits());
        if got < need {
            return Some(MempoolError::InsufficientStampWork { got, need });
        }
        match self.txs.get(&tx.id) {
            Some(pooled) if got <= pooled.stamp_work() => Some(MempoolError::AlreadyKnown),
            _ => None,
        }
    }

    /// TEST-ONLY — the malicious producer: a node that pools a transaction WITHOUT its submit door's verdict (a modified
    /// node controls its own template). Only the pool's structural checks run, so what the block's peers do with the
    /// laid transaction is the fold door's question alone.
    #[cfg(test)]
    pub fn accept_as_a_producer_bypassing_its_own_door(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        self.accept(tx)
    }

    /// Validate + insert a tx. Rejects the offending tx only (never a panic/halt).
    pub fn accept(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        // ⭐ DOES A PAYMENT ACTUALLY ENTER THE POOL? — the last unmeasured hop.
        //
        // MEASURED on the first genuinely-connected pair (live_peer_contacts 93/96, after three wrong seed
        // variables left every earlier run an island):
        //   `[submit-notes] tx carries 2306 output-note byte(s) (2 whole note(s))`  — the payment HAS both notes
        //   `[block-notes] 256 selected tx(s): 255 carried no output notes`         — the one note-bearing tx
        //                                                                              selected is the entropy note
        //   `[assemble] ... -> 1153 note byte(s)`                                    — payment absent from the block
        //
        // `select_for_template` now sorts note-bearing txs FIRST, and that ordering is in the running binary.
        // A 2,306-byte payment would therefore be selected before any cover — unless it is not in the pool at
        // all. This says whether admission accepted or refused it, and with what reason.
        //
        // Fires only for NOTE-BEARING txs — cover carries none, so the common path stays silent and this adds
        // no per-block bytes. DIGITAL-CASH-PRIVACY-REVIEWED: a byte COUNT and an error NAME only. Never a tx
        // id, note, cm, amount, key, address or owner.
        let note_bytes = tx.output_notes.len();
        if note_bytes > 0 {
            let r = self.accept_inner(tx);
            match &r {
                // ⛔ "ACCEPTED" IS NOT "POOLED". `accept` can return Ok for a tx that is already present (or
                // otherwise not inserted), and `select_for_template` iterates `self.txs` — so an Ok that left
                // no row is invisible to selection forever.
                //
                // MEASURED: `[pool-admit] ACCEPTED (2306 note byte(s))` fires, `[assemble] … 2306` never
                // does, `[admit-gate]` is silent (not refused) and `[tmpl-pick]` is silent (selection always
                // picked SOME note-bearing tx — the 1,153-byte entropy note). Admitted-but-not-in-`txs` is
                // the only remaining shape that explains all four readings at once, and this checks it
                // directly instead of inferring it.
                Ok(id) => eprintln!(
                    "[pool-admit] note-bearing tx ACCEPTED ({note_bytes} note byte(s)); present_in_pool={} pool_len={}",
                    self.txs.contains_key(id),
                    self.txs.len()
                ),
                Err(e) => eprintln!(
                    "[pool-admit] ⛔ note-bearing tx REFUSED ({note_bytes} note byte(s)): {e:?} — this payment \
                     can never reach a block"
                ),
            }
            return r;
        }
        self.accept_inner(tx)
    }

    /// ⭐ THE CONFLICT SET, ASKED — half one of the ONE door every admission path funnels through.
    ///
    /// True when some nullifier this tx claims is already claimed by a DIFFERENT pooled transaction.
    /// Owner-aware rather than presence-only, because the re-stamp arm re-offers claims that are already
    /// THIS id's: a presence-only read would refuse an honest sender's own priority bump.
    /// §9.6 Q4 for every door that admits into this pool: the refusal is a SET membership test, never an
    /// ordering, a cache or luck.
    fn nullifier_claim_conflict(&self, id: &Hash32, nullifiers: &[Hash32]) -> bool {
        nullifiers.iter().any(|nf| match self.spent.get(nf) {
            Some(owner) => owner != id,
            None => false,
        })
    }

    /// ⭐ THE ENVELOPE AN ID STANDS FOR — the WHOLE carried struct, minus the one field a bump may move.
    ///
    /// ⛔⛔⛔ WHY THIS IS A DIGEST OVER THE WHOLE ENCODING AND NOT A LIST OF FIELDS. `PqTx::content_id` is
    /// `blake3(blob)` and nothing else, so every other field — `nullifiers`, `output_notes`, `weight`,
    /// `bond_notes`, `stake_notes`, `account_targets`, `note_clues`, `unspent_spends` and every witness —
    /// sits OUTSIDE the identity the re-stamp arm matches on. A hand-written comparison of "the fields that
    /// matter" is the same defect one field later: `PqTx` has grown five `serde(default)` fields already, and
    /// the arm's own comment asserted "same nullifiers, same weight, same outputs" while enforcing none of
    /// the three. Hashing the postcard encoding covers every field THAT EXISTS AND EVERY FIELD ADDED LATER,
    /// by construction — a new field is in the digest the moment it is in the struct, with nothing to
    /// remember.
    ///
    /// It is the GOSSIP encoding on purpose: a `PqTx` travels the wire as exactly these bytes, so "the same
    /// payment" here means the same thing a peer's pool means by it. The digest is taken over the DECODED
    /// struct re-encoded, so an older peer's shorter frame (trailing `serde(default)` fields absent) and this
    /// node's own frame normalise to the identical value — the gate binds the VALUE, never the framing.
    ///
    /// `None` (an encoder failure) is a refusal, never a pass: the caller fails closed.
    ///
    /// cons: none. One encode of ONE tx, whose size is already bounded by `params.max_tx_weight`, on the
    /// duplicate-id arm alone; it stores nothing, so it adds no growth axis in chain height, block count or
    /// note count.
    /// Cache the pooled envelope digest for `id`, preserving whatever refusal high-water mark it has.
    /// Called at every point a tx enters the pool or its pooled bytes change, so the cached digest is
    /// never stale — a stale one would make the re-stamp arm judge the wrong envelope.
    fn refresh_restamp_guard(&mut self, id: Hash32) {
        #[cfg(test)]
        POOLED_REENCODES.with(|c| c.set(c.get() + 1));
        let envelope = self.txs.get(&id).and_then(Self::envelope_sans_stamp);
        let logged_work = self.restamp_bar.get(&id).map_or(0, |g| g.logged_work);
        self.restamp_bar.insert(id, RestampGuard { envelope, logged_work });
    }

    fn envelope_sans_stamp(tx: &PqTx) -> Option<Hash32> {
        let mut probe = tx.clone();
        probe.pow_stamp = 0;
        postcard::to_allocvec(&probe).ok().map(|b| Hash32::hash(&b))
    }

    /// ⭐ THE CONFLICT SET, WRITTEN — half two of the same door. Idempotent for a claim this id already
    /// holds, so a re-offer of the same payment costs nothing and changes nothing. This MOVES the loop
    /// that already stood in `accept_inner` to the one site both admission arms call; no new store, no
    /// new key, no entry that did not exist before.
    ///
    /// ⛔ THE INVARIANT THIS WRITER OWNS, and the reason it is the ONLY writer: for every `nf -> owner`
    /// in `spent`, `owner` is a POOLED tx AND THAT TX CARRIES `nf`.
    ///
    /// [`Self::nullifier_claim_conflict`] is OWNER-AWARE — it refuses a claim only when some OTHER id holds
    /// it — and [`Self::remove`] frees a tx's claims by iterating the POOLED struct's `nullifiers`. Each is
    /// correct exactly while this holds, and each fails in a DIFFERENT direction when it does not: a claim
    /// no pooled tx carries can never be freed (remove never names it), so every honest spend of that note
    /// is refused `DoubleSpend` for the life of the process, and the entry itself is then bounded by
    /// nothing. Free permanent censorship of any note an attacker names, plus a map that grows per attack.
    /// That is not hypothetical — it is exactly what the first version of the re-stamp fix made reachable,
    /// by calling this with the ARRIVING struct's nullifiers under the POOLED struct's id.
    ///
    /// Both callers therefore pass the nullifiers of the tx the pool WILL hold for `id`: the ordinary
    /// insert path passes the tx it is about to store, and the re-stamp arm passes the POOLED tx's own
    /// list, after proving the arriving envelope is identical to it. `mempool::tests::stranded_claims`
    /// reads `spent` and `txs` directly and asserts the invariant.
    /// ⭐ IS THIS TAG CLAIMED BY **ANY** POOLED TX? — the OWNER-BLIND twin of
    /// [`Self::nullifier_claim_conflict`], and the two are not interchangeable.
    ///
    /// `nullifier_claim_conflict` answers *"may this id claim these tags?"* and is deliberately
    /// owner-aware, because a re-stamp of an already-pooled tx must be allowed to re-claim its own tags.
    /// This answers a different question — *"is a spend of this note already in flight from here?"* — and
    /// the owner is exactly what it must NOT consider: a byte-identical republication of a settlement is
    /// the same note spent a second time from the caller's point of view, and an owner-aware check waves
    /// it through as a re-stamp.
    ///
    /// ⛔ IT IS A LOCAL LIVENESS GATE, NEVER A CONSENSUS ONE. The pool is `LocalCache` — two nodes hold
    /// different pools by design, so nothing here may DECIDE anything a peer must agree with. It only
    /// stops THIS node from publishing a second spend of a note it has already published one for, in the
    /// window before the first is grafted. The consensus double-spend gate is, and stays, the nullifier
    /// applied from the block.
    ///
    /// cons: none. One `BTreeMap` lookup on a map already bounded by `params.max_pool_weight`; it stores
    /// nothing and adds no term in chain height, block count or note count.
    pub fn nullifier_is_claimed(&self, nf: &Hash32) -> bool {
        self.spent.contains_key(nf)
    }

    /// lane agg — the pooled tx that claims `nf`, if any (the graft's twin eviction reads it: an aggregated body's FULL twin
    /// left pooled at its origin is the same payment under another id).
    #[must_use]
    pub fn claimant_of(&self, nf: &Hash32) -> Option<Hash32> {
        self.spent.get(nf).copied()
    }

    fn register_nullifier_claims(&mut self, id: Hash32, nullifiers: &[Hash32]) {
        // O1-FOOTPRINT-REVIEWED, BY CONSTRUCTION: a pooled tx claims at most TX_FIXED_NULLIFIER_COUNT = 32
        // nullifiers, the pool is capped by the fixed `params.max_pool_weight`, and `Mempool::remove` drops
        // every entry when its tx leaves — so no term in chain height, block count or note count exists.
        for nf in nullifiers {
            self.spent.insert(*nf, id);
        }
    }

    fn accept_inner(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        if tx.id != PqTx::content_id(&tx.blob) {
            return Err(MempoolError::InvalidId);
        }
        if !tx.account_targets.is_empty() {
            return Err(MempoolError::AccountTargetsCarried);
        }
        if tx.weight > self.params.max_tx_weight {
            return Err(MempoolError::TooHeavy(tx.weight));
        }
        // §22b: no framed object is too wide for a block — a carriage wider than `block::CREDIT_INLINE_MAX` rides the
        // sealed set as a 40-byte reference with its bytes beside the body, so its frame cost is bounded by construction.
        // POOL-ACCEPT ⇒ MINEABLE. `select_for_template` bounds a block's REAL output notes by the fixed
        // `BLOCK_FIXED_NOTE_COUNT` cover shape, so a tx carrying more notes than that whole budget can never be
        // packed into any block, at any height, however long it waits. Admitting it would report success to the
        // sender and then hold the funds in the pool forever with nothing logged. Fail closed HERE, where the
        // sender still learns about it, rather than letting the template silently decline it every block.
        let tx_notes = tx.output_notes.len() / crate::cover::PQ_NOTE_BYTES;
        if tx_notes > crate::cover::BLOCK_FIXED_NOTE_COUNT {
            return Err(MempoolError::Unmineable {
                got: tx_notes,
                max: crate::cover::BLOCK_FIXED_NOTE_COUNT,
            });
        }
        let need = self.required_stamp_bits();
        let got = tx.stamp_work();
        if got < need {
            return Err(MempoolError::InsufficientStampWork { got, need });
        }
        // CONGESTION ESCAPE HATCH (the PQ- and privacy-safe answer to "my payment is stuck behind higher-priority
        // traffic"). Selection ranks purely by `stamp_work`, so under sustained load a low-stamp payment can wait
        // indefinitely with NO way for its owner to do anything about it — funds effectively frozen. The sender may
        // therefore RE-STAMP ITS OWN tx: the identical blob (same id, same nullifiers, same weight, same outputs —
        // nothing about the payment changes) carrying a `pow_stamp` that hashes to STRICTLY more leading-zero work.
        // This is a bump the sender pays for in CLIENT WORK, never a plaintext fee — a fee would be an amount-
        // correlated public signal and is exactly the metadata handout the digital-cash pillar forbids. A
        // same-or-lower-work resubmission is still `AlreadyKnown`, so this can neither be used to flood the pool
        // nor to displace anyone else's tx: it only ever raises the priority of the SAME payment.
        //
        // ⛔⛔⛔ THE BUMP MOVES THE STAMP AND NOTHING ELSE — DOOR AUDIT 2026-09-07 (§9.6, family B).
        // `content_id` is `blake3(blob)` and nothing else, so `nullifiers`, `output_notes`, `weight`,
        // `bond_notes`, `stake_notes`, `account_targets`, `note_clues` and every witness field sit OUTSIDE
        // the identity this arm matches on. The arm used to `self.txs.insert(id, tx)` — a WHOLE-STRUCT swap
        // — which let any relaying peer re-use the victim's exact blob (so the id and the ZK carrier verdict
        // stayed byte-identical), grind one more bit of stamp work, and replace the carried value on every
        // pool that re-admitted the gossip.
        //
        // ⛔⛔⛔ AND KEEPING THE POOLED STRUCT WAS NOT ENOUGH — THE FIRST FIX CARRIED ITS OWN DEFECT.
        // Holding the pooled envelope and writing ONE FIELD through `get_mut` stopped the VALUE swap, but the
        // arm still READ THE ARRIVING STRUCT for the conflict set: it registered `tx.nullifiers` under the
        // POOLED id. The two structs were never compared, so the nullifiers it wrote were whatever the
        // attacker attached. That mints a claim whose owner does not carry it — and because
        // `nullifier_claim_conflict` is owner-aware and `remove` frees claims by iterating the POOLED tx's
        // `nullifiers`, nothing can ever free that entry: an attacker names any victim's nullifier, pays one
        // bit of grind, and that note is refused `DoubleSpend` on every node for the life of the process,
        // with `spent` growing per attack. Censorship and an unbounded map, produced by the fix itself.
        //
        // THE ARM NOW ANSWERS ONE QUESTION FIRST: is this the SAME PAYMENT? `envelope_sans_stamp` is the whole
        // struct minus `pow_stamp`, so ONLY a higher stamp is admissible and ANY other difference is refused
        // outright — the contract this arm always claimed, now enforced over every field including the ones
        // added after it was written. Both refusals below run BEFORE any mutation, so a rejected bump leaves
        // the pool bit-for-bit as it was.
        if self.txs.contains_key(&tx.id) {
            // ⭐ WHAT PRODUCES THIS CONDITION, AND WHY THE REFUSAL CANNOT BE DELETED INSTEAD.
            //
            // 1. WHAT PRODUCES IT: a second `PqTx` arriving with an id this pool already holds. Two producers,
            //    both OUTSIDE this node's reach — they are bytes another party chose. (a) The honest one: the
            //    same sender re-offering the SAME payment, either as a congestion bump or as the ordinary
            //    gossip echo of its own tx coming back from a peer. (b) The hostile one: any relaying peer
            //    that re-uses the victim's blob verbatim — which is why the id and the ZK carrier verdict are
            //    byte-identical — and attaches different non-blob fields.
            // 2. CAN IT BE DELETED? No, and the two cases measure DIFFERENTLY, which is the whole point. The
            //    honest echo is byte-identical outside `pow_stamp`, so re-inserting it would be a no-op and
            //    the branch could in principle go. The hostile one is NOT identical: it carries output notes,
            //    weight, bond bytes and nullifiers that NO carrier proof judged — data nobody else has and
            //    nobody verified. Deleting the branch (i.e. letting a duplicate id overwrite) is exactly the
            //    whole-struct swap pin B-1 measured RED. The cause lives in a stranger's bytes; refusing them
            //    at the door is the only place this node owns.
            // 3. THEREFORE IT STAYS, and it is a comparison rather than a skip: the branch does not refuse
            //    "because I have seen this id", it refuses because the ENVELOPE differs. An id it has seen
            //    whose envelope matches and whose stamp is strictly higher is ACCEPTED, one field updated.
            // ⛔ THE POOLED STAMP AND NOTHING ELSE. A node-local bar here would let one stranger's grind
            // price the payment's OWNER out of their own congestion bump — see [`RestampGuard`] for the
            // measurement. Admission is gated by what the sender must beat, never by what a stranger did.
            let pooled_work = self.txs[&tx.id].stamp_work();
            if tx.stamp_work() <= pooled_work {
                return Err(MempoolError::AlreadyKnown);
            }
            // FIELD BY FIELD, VIA THE ONE DIGEST. Fail-closed: an encoder failure on either side refuses.
            //
            // THE ORDER IS LOAD-BEARING, and it is the second thing this fix makes possible: the comparison
            // costs an encode of the whole tx, which nothing on this arm used to spend. It sits AFTER the
            // work check, so the only way to make this node pay it is to grind STRICTLY more stamp work than
            // the pooled tx — the #72 client-PoW price. A flood of equal-work duplicates (the free attack)
            // is turned away one line above and never reaches an encode.
            // ⭐ THE POOLED SIDE IS READ, NOT RECOMPUTED. Its digest was taken once when the tx entered;
            // everything about the verdict is unchanged, and the bytes the arriving party never sent are
            // no longer re-encoded under the lock on every arrival. `None` still fails closed.
            let pooled_envelope = self.restamp_bar.get(&tx.id).and_then(|g| g.envelope);
            match (Self::envelope_sans_stamp(&tx), pooled_envelope) {
                (Some(incoming), Some(pooled)) if incoming == pooled => {}
                _ => {
                    // ⛔ NEVER A SILENT DROP. `AlreadyKnown` is the ONE pool error the gossip loop
                    // discards without a line (node_runtime.rs — "a dup is dropped silently"), because
                    // it is the ordinary echo of one's own tx. This refusal is not that: reaching it
                    // cost a fresh grind of strictly higher work, and it means a peer offered DIFFERENT
                    // carried bytes under an id whose blob was already judged. Left unsaid, the single
                    // most informative event on this path — someone is re-stamping a stranger's payment
                    // — would look exactly like the duplicate traffic every node sees constantly.
                    //
                    // Not a spam surface: the arm is only reached by out-working the pooled stamp, which
                    // is the #72 client-PoW price, so this line is rate-limited by proof of work.
                    //
                    // Fixed string. By construction it can carry no tx id, nullifier, cm, note, amount,
                    // key or owner — the comparison's inputs are digests and neither is printed.
                    // ⛔ THE LINE IS THE LAST THING A REPLAY CAN STILL SPEND. `log_cap` rotates fd 2 at
                    // a fixed cap and keeps two generations, so an unrate-limited line here lets one
                    // grind flush this node's real diagnostics off disk. Printing only when the refused
                    // work EXCEEDS everything refused for this id before makes an unbounded stream of
                    // lines need an unbounded stream of ever-higher grinds. It gates the diagnostic
                    // ONLY — admission never reads it — so no honest bump is priced by it.
                    let w = tx.stamp_work();
                    let first = self.restamp_bar.get(&tx.id).is_none_or(|g| w > g.logged_work);
                    if let Some(g) = self.restamp_bar.get_mut(&tx.id) {
                        g.logged_work = g.logged_work.max(w);
                    }
                    if first {
                        eprintln!(
                            "[pool-restamp] ⛔ REFUSED: a re-stamp for a pooled id carried a DIFFERENT \
                             envelope — only the anti-spam stamp may move on a bump. Nothing admitted, \
                             nothing replaced, nothing re-gossiped."
                        );
                    }
                    // ⛔⛔⛔ CONSUME THE GRIND, OR THE PRICE ABOVE IS A PRICE FOR ONE ARRIVAL AND NOT FOR
                    // ONE FRAME. Everything above prices this arm at "the #72 client-PoW price". That is
                    // true exactly ONCE unless the bar moves: a refusal is a no-op on the pool BY DESIGN,
                    // so `pooled_work` never rose, and the SAME already-ground bytes cleared the cheap
                    // guard again on every replay. MEASURED by
                    // `a_refused_restamp_costs_the_attacker_one_grind_and_this_node_one_arrival`: one
                    // grind bought 64 arrivals, each a lock-held re-encode of the VICTIM'S struct —
                    // 4,717 bytes spent for 2,621 bytes sent — plus one line per arrival toward the
                    // `log_cap` rotation that would flush this node's real diagnostics off disk.
                    //
                    // ⛔⛔⛔ AND THE BAR IS LOCAL, NOT THE POOLED STAMP. The obvious version of this fix —
                    // write the refused frame's `pow_stamp` into the pooled tx — was MEASURED RED by two
                    // sibling pins on the same run: `a_restamp_that_moves_any_field_but_the_stamp_is_
                    // refused_on_both_nodes` and `the_honest_congestion_bump_still_lands_after_a_full_
                    // gossip_round_trip` both call it what it is, "a half-applied bump, which is a write
                    // on a path that returned an error". They are right: the pooled envelope is a
                    // consensus object this node re-gossips and packs, and a refusal must leave it
                    // bit-for-bit untouched.
                    //
                    // So the high-water mark lives in `restamp_bar`: node-local, never serialized, never
                    // gossiped, dropped with the tx. It costs the attacker exactly what the comment above
                    // always claimed and the code did not charge — a fresh grind PER EXPENSIVE ARRIVAL,
                    // not one grind for unbounded arrivals — while the pool itself stays a no-op on a
                    // refusal. Monotone by construction: the cheap guard reaches here only on work
                    // strictly above the bar, so no arrival can ever lower it.
                    return Err(MempoolError::AlreadyKnown);
                }
            }
            // §9.6 Q4 — THE SAME SET, ON THIS PATH TOO. A bump is still an ADMISSION, and this arm used to
            // return before `spent` was ever written, so a nullifier arriving here was refused by nothing and
            // `select_for_template`'s intra-block skip (which reads the same map) was equally blind. The
            // conflict set is now consulted and written through the ONE shared pair below, exactly as the
            // ordinary insert path does.
            //
            // The claims are read from the POOLED struct, never the arriving one. After the envelope gate the
            // two lists are byte-identical, so this is the same value either way — and that is exactly why it
            // must be the pooled one: it makes "a claim whose owner does not carry it" unconstructible at this
            // arm by CONSTRUCTION, rather than as a consequence of the check above still being correct when
            // someone edits it. For an honest bump the claims are already this id's, so both calls are no-ops.
            let pooled_nullifiers = self.txs[&tx.id].nullifiers.clone();
            if self.nullifier_claim_conflict(&tx.id, &pooled_nullifiers) {
                return Err(MempoolError::DoubleSpend);
            }
            self.register_nullifier_claims(tx.id, &pooled_nullifiers);
            // Swap the stamp in place. `admitted_height` is deliberately NOT reset: this is the same payment that
            // has been waiting, so its age — and therefore its stuck-visibility and re-relay eligibility — keeps
            // accruing rather than being erased by every bump.
            let id = tx.id;
            let bumped = self.txs.get_mut(&id).is_some_and(|pooled| {
                pooled.pow_stamp = tx.pow_stamp;
                true
            });
            // `envelope_sans_stamp` zeroes the stamp, so a bump cannot move the digest — but refreshing
            // here keeps ONE rule ("every write to a pooled tx refreshes its guard") rather than a
            // case analysis that a later field addition would silently break.
            if bumped {
                self.refresh_restamp_guard(id);
            }
            return Ok(id);
        }
        // ⛔ DB-327 / DB-330 — ONE PREDICATE, AT THE POOL'S OWN DOOR: the submit arm, gossip, and an evicted tx's
        // re-admission all end here. A NEW id carrying stake bytes is refused; a known id's re-stamp is judged
        // by the envelope arm above, which already refuses any byte that differs.
        if !tx.stake_notes.is_empty() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no tx id, cm, amount, nullifier, key or owner.
            eprintln!(
                "[pool-admit] ⛔ REFUSED a transaction carrying stake_notes — a retired format (DB-327); nothing admitted"
            );
            return Err(MempoolError::StakeFormatRetired);
        }
        if self.nullifier_claim_conflict(&tx.id, &tx.nullifiers) {
            return Err(MempoolError::DoubleSpend);
        }
        if self.total_weight + tx.weight as u64 > self.params.max_pool_weight && !self.make_room_for(tx.weight as u64) {
            return Err(MempoolError::Full);
        }

        let id = tx.id;
        self.register_nullifier_claims(id, &tx.nullifiers);
        self.total_weight += tx.weight as u64;
        crate::budget_clock::replay_tx_trace("pool+", &id.0, None);
        self.arrival.insert(id, self.counter);
        self.admitted_height.insert(id, self.current_height);
        self.counter += 1;
        self.txs.insert(id, tx);
        self.refresh_restamp_guard(id);
        Ok(id)
    }

    /// #135 admit a PQ tx ONLY if its spend carrier passes the ZK verify — the per-tx gate for the direct
    /// light-decider Send (the retiring rec-block's replacement). `verify` runs the carrier soundness check
    /// (the node passes `|blob| whir_decider::pqspend_direct_verify_carrier(blob).is_some()`); a `false`
    /// return rejects fail-closed BEFORE any structural admission, so an invalid / tampered / non-carrier blob
    /// never enters the pool (no spam surface) and never reaches block production. On pass, structural
    /// admission then runs via [`Mempool::accept`] (id / weight / stamp / double-spend / capacity).
    pub fn accept_verified<F: Fn(&[u8]) -> bool>(
        &mut self,
        tx: PqTx,
        verify: F,
    ) -> Result<Hash32, MempoolError> {
        if !verify(&tx.blob) {
            return Err(MempoolError::InvalidProof);
        }
        self.accept(tx)
    }

    /// Select tx ids for a block template: highest stamp work first (arrival breaks ties),
    /// greedily filling up to `max_weight` and skipping any tx whose nullifiers already appear
    /// in the selection — so the produced block never double-spends within itself.
    pub fn select_for_template(&self, max_weight: u64, draw: &[u8; 32]) -> Vec<Hash32> {
        self.select_for_template_reserving(max_weight, TemplateReserve::NONE, draw)
    }

    /// [`Self::select_for_template`] with `reserve` held back from the block's fixed tag and note budgets for objects
    /// the PRODUCER lays after selection (its SATOSHI reward: one nullifier in the lane, one note in the payload).
    /// BORROWED-FROM Bitcoin Core's `BlockAssembler`: the coinbase's space is reserved before the mempool fills the rest.
    /// MEASURED why (2026-10-09, link 57, db369): eight pooled 32-tag objects filled the 256-tag budget exactly, the
    /// reward's nullifier made 257, and `produce` refused EVERY template — "[produce-refused] the SELECTED set carries 257
    /// real nullifier(s)". The pool never drained (nothing was laid), so any eight pending spends halted every rewarded
    /// producer: DB-96's wedge, re-opened by the reward the selector never counted.
    ///
    /// ⭐⭐⭐ DB-443 (link 63, 2026-10-20) — INCLUSIVE SELECTION: CONCURRENT PRODUCERS DRAW DIFFERENT SPENDS.
    ///
    /// THE DEFECT: every producer of a width-n DAG holds (by gossip) the same pool, and this rank was a function of the pool
    /// alone — so once more spends were pending than one block's spend lane holds (`BLOCK_FIXED_SPEND_TX_COUNT`, 8), every
    /// concurrent template laid the SAME top eight, and the mesh drained eight distinct spends per propagation round however
    /// many producers it had: n − 1 of every n concurrent spend blocks carried nothing new. MEASURED
    /// night/perf-load-20261020-232053-n8.log: the 65 real spends rode 4–26 templates each (median 8), P10's knee at 2 tx/s.
    ///
    /// THE SHAPE, BORROWED: Lewenberg, Sompolinsky, Zohar, "Inclusive Block Chain Protocols" (FC 2015) §5 — in a protocol
    /// whose concurrent blocks all count, a miner maximizes throughput (its own and the network's) by choosing transactions
    /// at RANDOM rather than greedily, so parallel blocks collide less; Kaspa's mining manager does exactly this (rusty-kaspa
    /// `mining/src/block_template/selector.rs`, weighted random selection without replacement once the pool exceeds the
    /// block, everything when it fits). Here: each REAL candidate gets the Efraimidis–Spirakis key `ln(u) / w` — `u` uniform
    /// in (0, 1] from the template's SECRET `draw` (`Node::template_draw`, keyed by `miner_seed`) and the tx id, `w` its
    /// stamp work `2^(bits − floor)` — and the lane fills in key order: a weighted random sample without replacement, with
    /// stamp work as the priority currency it already was. Cover keeps its old order. The chosen set is laid in the old
    /// rank order, so nothing downstream of the selection sees a different arrangement.
    ///
    /// NOT DEDUP AT LOW LOAD, ON PURPOSE: when the pending spends fit the lane every template takes all of them (key order
    /// is then irrelevant) — a producer that skipped a spend it could carry would only add latency. The inclusive analysis
    /// prices a duplicate at the block space it occupies, which below saturation is space nothing else wanted; the cost a
    /// duplicate carries TODAY (a spend-carrying block proves the note-transition aggregate and an empty one does not) is
    /// the shape leak DB-378 closes, not a reason to delay a payment.
    ///
    /// PILLARS: private — the draw is secret and per producer; which spends a block carries was already public, and the
    /// choice links nothing to anyone (no identity, no onion, no slot). Trustless / censorship — every candidate's chance
    /// per template is > 0 (`w ≥ 1`), so no pending spend starves; greedy let any stream of higher-stamp spends starve a
    /// lower one forever. No halt — the budgets, the intra-block nullifier check and the carried-forward backpressure are
    /// unchanged. No growth — no state; O(pool) keys per template, the sort it replaces.
    /// cons: none in a priority the protocol defines — stamp work keeps its weight (one extra bit doubles a spend's odds);
    /// only the arrival/id tiebreak among equal stamps, which ordered nothing anyone paid for, becomes a fair draw.
    /// Name the txs a template may not carry yet (spec §2.3).
    pub fn set_held_back(&mut self, ids: std::collections::HashSet<Hash32>) {
        self.held_back = ids;
    }

    pub fn select_for_template_reserving(&self, max_weight: u64, reserve: TemplateReserve, draw: &[u8; 32]) -> Vec<Hash32> {
        let tag_budget = crate::cover::BLOCK_FIXED_NULLIFIER_COUNT.saturating_sub(reserve.tags);
        let note_budget = crate::cover::BLOCK_FIXED_NOTE_COUNT.saturating_sub(reserve.notes);
        // §22: the sealed credit sidecar is ONE width, so a framed object whose carriage no longer fits this block's frame
        // budget stays pooled for the next block — delayed, never dropped (DB-96's rule for the tag budget).
        let frame_budget = crate::block::CREDIT_SET_FRAME_BUDGET.saturating_sub(reserve.frames);
        let frame_cost = |t: &PqTx| -> usize {
            if crate::chain_object::unframe(&t.blob).is_none() {
                return 0;
            }
            crate::block::credit_frame_cost(crate::chain_object::carriage_of(&t.blob).map_or(t.blob.len(), |c| c.len()))
        };
        let floor = self.txs.values().filter(|t| !t.output_notes.is_empty()).map(PqTx::stamp_work).min().unwrap_or(0);
        let inclusive_key = |t: &PqTx| -> f64 {
            let mut h = blake3::Hasher::new();
            h.update(b"MUSD-inclusive-draw-v1");
            h.update(draw);
            h.update(t.id.as_bytes());
            let mut x = [0u8; 8];
            x.copy_from_slice(&h.finalize().as_bytes()[..8]);
            // 53 random bits shifted off zero: u ∈ (0, 1], so ln(u) is finite and ≤ 0
            let u = ((u64::from_le_bytes(x) >> 11) + 1) as f64 / (1u64 << 53) as f64;
            // A-F66: work above the floor counts for at most STAMP_PRIORITY_BITS_MAX bits, so grinding buys a sender's bump
            // (up to 4x) and never the whole block
            u.ln() / (2f64).powi(t.stamp_work().saturating_sub(floor).min(STAMP_PRIORITY_BITS_MAX) as i32)
        };
        let keys: HashMap<Hash32, f64> =
            self.txs.values().filter(|t| !self.held_back.contains(&t.id)).filter(|t| !t.output_notes.is_empty()).map(|t| (t.id, inclusive_key(t))).collect();
        let rank = |a: &PqTx, b: &PqTx| -> std::cmp::Ordering {
            // ⭐⭐⭐ REAL PAYMENTS OUTRANK COVER — COVER IS PADDING, NOT A COMPETITOR.
            //
            // MEASURED: 175 of 175 produced blocks carried exactly 1,153 note bytes — the constant entropy
            // note and nothing else. A settling payment carries recipient + change = 2,306. And on a real
            // peered send the target lookup reported `0/1 resolved while 3 target(s) EXIST; 0 of this block's
            // note key(s) appear among them`: targets filed correctly, block holding no note to match.
            //
            // THE CAUSE IS HERE. `produce_template` mints cover txs via `pad_to_fixed_shape` and ACCEPTS them
            // into the pool before selecting. Ordering by `stamp_work` alone lets that fresh cover outrank a
            // waiting payment, and `out.len() >= BLOCK_FIXED_TX_COUNT` then breaks the loop with the block
            // full of padding. The payment is never dropped — it just never wins a seat, block after block.
            // Silent, permanent starvation that looks exactly like a payment that was never sent.
            //
            // NOT A PRIVACY REGRESSION: the block's OBSERVABLE shape is unchanged — still exactly
            // BLOCK_FIXED_TX_COUNT txs and BLOCK_FIXED_NOTE_COUNT notes, cover-filled and shuffled. Only the
            // node-local CHOICE of which candidates fill the fixed shape changes. An observer sees the same
            // constant block either way ([[feedback_all_blocks_fixed_cover_shape]]).
            //
            // NOT A WINDOW OR CAP: nothing is refused for age or bounded in reach. This is a priority within
            // one selection pass; every tx still stays pooled until it is included.
            let a_real = !a.output_notes.is_empty();
            let b_real = !b.output_notes.is_empty();
            b_real
                .cmp(&a_real)
                .then_with(|| b.stamp_work().cmp(&a.stamp_work()))
                .then_with(|| self.arrival[&a.id].cmp(&self.arrival[&b.id]))
                // FINAL deterministic tiebreak by the UNIQUE tx id. Without it, txs with equal
                // stamp_work AND equal arrival (e.g. the cover txs a single produce() mints in one
                // instant) tie, and the order falls through to `self.txs.values()` — i.e. HashMap
                // iteration order, which is randomized PER PROCESS (RandomState). Two nodes would then
                // commit DIFFERENT tx_merkle_roots over the SAME id set, so every gossiped block fails the
                // peer's `tx_merkle_root` check (TxRootMismatch) and the DAGs never converge. Sorting by id
                // makes the selected id list — and thus the merkle root — reproducible on every node.
                .then_with(|| a.id.cmp(&b.id))
        };
        let mut cand: Vec<&PqTx> = self.txs.values().filter(|t| !self.held_back.contains(&t.id)).collect();
        cand.sort_by(|a, b| match (keys.get(&a.id), keys.get(&b.id)) {
            // two real candidates: the inclusive draw decides (the larger key is drawn first), the id breaks a tie
            (Some(ka), Some(kb)) => kb.total_cmp(ka).then_with(|| a.id.cmp(&b.id)),
            _ => rank(*a, *b),
        });
        // ⭐ IS A NOTE-BEARING TX PRESENT AS A CANDIDATE AT ALL? — the last unmeasured hop.
        //
        // MEASURED across six sends on a genuinely-connected pair: `[pool-admit] ACCEPTED (2306 note
        // byte(s))` fired 5 times; `[assemble] ... 2306 note byte(s)` fired ZERO times. The payment enters
        // the pool and never reaches a block, while `[admit-gate]` stays silent (so it is not refused).
        //
        // The note-count math is not the cause: cover::PQ_NOTE_BYTES, node's PQ_NOTE_BYTES_OUT and the RPC's
        // constant are all 1153, so a 2,306-byte tx counts as exactly 2 notes against a 256 budget.
        //
        // That leaves two possibilities this separates: the tx is NOT in `cand` (evicted before the template
        // is built), or it is in `cand` and the loop skips it. Recorded before the loop runs, so the answer
        // is a fact rather than another inference.
        let cand_real = cand.iter().filter(|t| !t.output_notes.is_empty()).count();
        let cand_real_bytes: usize = cand.iter().map(|t| t.output_notes.len()).max().unwrap_or(0);
        // ⛔ SAY WHETHER A MULTI-NOTE TRANSFER IS EVEN A CANDIDATE — the comparison alone cannot.
        //
        // `[tmpl-pick]` stays silent in TWO different worlds: the payment was picked, or the payment was
        // never in `cand` (then the largest candidate is the 1,153-byte entropy note and largest-picked
        // trivially equals it). I read its silence as "the payment was selected" and was wrong twice.
        //
        // A transfer carries recipient + change = 2 notes; cover and entropy carry one. So "is any candidate
        // larger than one note" is exactly the discriminator, and it is unambiguous.
        // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS and byte LENGTHS only.
        if cand_real_bytes > crate::cover::PQ_NOTE_BYTES {
            eprintln!(
                "[tmpl-cand] a MULTI-NOTE tx ({cand_real_bytes} byte(s)) IS a candidate among {} pooled tx(s)",
                cand.len()
            );
        }
        let mut out: Vec<Hash32> = Vec::new();
        let mut used_nf: HashSet<Hash32> = HashSet::new();
        let mut w: u64 = 0;
        // Cumulative REAL served-output-note count. The served-note privacy shape (crate::cover) records EXACTLY
        // BLOCK_FIXED_NOTE_COUNT notes per block (real outputs + cover fill, shuffled), so a block's REAL output
        // notes must not exceed that fixed count — else the note-tree delta would leak real activity.
        let mut notes_out: usize = 0;
        // DB-96 (2026-09-19, run 97): the block's NULLIFIER budget is fixed too — `BLOCK_FIXED_NULLIFIER_COUNT`
        // tags, i.e. `BLOCK_FIXED_SPEND_TX_COUNT` constant-width spends. This selector capped notes and weight
        // but never the tags, so a pool holding more spends than one block's budget (16 real spends × 32 tags
        // = 512 > 256) handed `produce` a set it refuses as a whole — and it refused EVERY template from then
        // on ("Production is wedged by construction here"): node 1 produced nothing for the rest of run 97 and
        // 0 of 16 burst payments ever landed. Nine pending spends were enough to stop a producer; on a mesh
        // whose producers all pool them, that is a chain halt ([[feedback_no_chain_halts]]). A spend that
        // would push past the budget now STAYS in the pool for the next block — the same carried-forward
        // backpressure as the note and weight caps — so the chain keeps its cadence and drains the pool at
        // `BLOCK_FIXED_SPEND_TX_COUNT` spends per block.
        let mut tags_out: usize = 0;
        let mut frames_out: usize = 0;
        for tx in cand {
            // Block CAPACITY = the fixed shape (crate::cover, ported from v36_shape): once the block holds
            // BLOCK_FIXED_TX_COUNT txs it is FULL, so any remaining candidates STAY in the pool and enter the
            // NEXT block (never dropped) — the same "carried to the next block" semantics as the weight bound
            // just below. Every block is thereby identically shaped; node.produce fills a LIGHT block up to
            // the same count with cover txs so an observer cannot tell a busy block from an idle one.
            if out.len() >= crate::cover::BLOCK_FIXED_TX_COUNT {
                break;
            }
            if !self.lays_now(tx, draw) {
                continue; // G14: a relayed vote this draw did not pick stays pooled for the next template
            }
            let tx_frames = frame_cost(tx);
            if frames_out + tx_frames > frame_budget {
                continue; // §22: over the sealed sidecar's frame budget — carried to the next block, never dropped
            }
            // Constant served-NOTE shape (privacy pillar, crate::cover::assemble_fixed_note_payload): a block
            // records EXACTLY BLOCK_FIXED_NOTE_COUNT (256) served notes — real output notes padded with value-0
            // cover + shuffled — so the note-tree delta is a CONSTANT every block and never reveals real
            // activity. Cap the block's REAL output notes at that count; a tx that would push past it STAYS in
            // the pool for the NEXT block (same carried-forward backpressure as the tx-count + weight caps),
            // NEVER dropped. (A cover tx has empty output_notes ⇒ 0, so it never consumes this budget.)
            let tx_notes = tx.output_notes.len() / crate::cover::PQ_NOTE_BYTES;
            if notes_out + tx_notes > note_budget {
                continue;
            }
            if w + tx.weight as u64 > max_weight {
                continue;
            }
            if tags_out + tx.nullifiers.len() > tag_budget {
                continue; // DB-96: over the block's tag budget — carried to the next block, never dropped
            }
            if tx.nullifiers.iter().any(|nf| used_nf.contains(nf)) {
                continue;
            }
            for nf in &tx.nullifiers {
                used_nf.insert(*nf);
            }
            w += tx.weight as u64;
            notes_out += tx_notes;
            tags_out += tx.nullifiers.len();
            frames_out += tx_frames;
            out.push(tx.id);
        }
        // Fires ONLY when a note-bearing candidate existed and none was selected — the state that loses a
        // payment. Silent on ordinary cover-only rounds, so no per-block bytes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS and a byte LENGTH only. Never a tx id, note, cm, amount,
        // key, address or owner.
        // the chosen set is laid in the old rank order (DB-443: only WHICH spends changed)
        out.sort_by(|a, b| rank(&self.txs[a], &self.txs[b]));
        let _picked_real = out
            .iter()
            .filter(|id| self.txs.get(id).is_some_and(|t| !t.output_notes.is_empty()))
            .count();
        // ⛔ THE OLD TEST COULD NOT SEE THE PAYMENT. It fired only when NO note-bearing tx was picked — but
        // `produce_template` mints cover into the pool before selecting, and the 1,153-byte entropy note is
        // itself note-bearing. So ANY template satisfies `picked_real > 0` and the probe stays silent even
        // when the actual payment is passed over. I read that silence as proof the payment was selected. It
        // proved nothing of the sort.
        //
        // Track the LARGEST note-bearing candidate specifically — a 2,306-byte transfer dwarfs the 1,153-byte
        // entropy note, so "was the biggest one picked" is exactly the question that matters and the one the
        // aggregate count cannot answer.
        let picked_max: usize = out
            .iter()
            .filter_map(|id| self.txs.get(id))
            .map(|t| t.output_notes.len())
            .max()
            .unwrap_or(0);
        if cand_real > 0 && picked_max < cand_real_bytes {
            // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS and byte LENGTHS only. Never a tx id, note, cm, amount,
            // key, address or owner.
            eprintln!(
                "[tmpl-pick] ⛔ largest note-bearing candidate is {cand_real_bytes} byte(s) but the template's \
                 largest pick is {picked_max} byte(s) — {cand_real} note-bearing candidate(s), {} selected. \
                 The bigger payment is present and passed over",
                out.len()
            );
        }
        out
    }

    /// Drop txs (e.g. once included in an accepted block), freeing their weight + nullifiers.
    /// Tell the pool what height the chain is at — called once per accepted block so tx age is measured in
    /// BLOCKS, the unit that actually matters for "is my payment going through?".
    pub fn set_height(&mut self, h: u64) {
        self.current_height = h;
    }

    /// The height the pool is tracking.
    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Ids pooled for at least `blocks` blocks — the STUCK set (and the RE-RELAY set: a tx this old has almost
    /// certainly had its first gossip dropped). Sorted so the report is stable across calls.
    pub fn pooled_at_least(&self, blocks: u64) -> Vec<Hash32> {
        let mut out: Vec<Hash32> = self
            .admitted_height
            .iter()
            .filter(|(id, at)| {
                self.txs.contains_key(id) && self.current_height.saturating_sub(**at) >= blocks
            })
            .map(|(id, _)| *id)
            .collect();
        out.sort();
        out
    }

    /// A pooled tx by id — lets the node re-gossip the STUCK set without exposing any lookup to the network.
    pub fn get_pooled(&self, id: &Hash32) -> Option<&PqTx> {
        self.txs.get(id)
    }

    // ⛔⛔⛔ §AQ — `step_absence_carriers` STOOD HERE AND IS DELETED. IT WAS A PILLAR TRADE.
    //
    // It stepped every pooled transaction's absence carrier as each block was applied, which is the shape
    // `node.rs`'s own gate doc names for retiring the §AQ hole. The arithmetic refuses it:
    // `NfAbsenceBatchCarrier::step` runs TWO recursive WHIR proves (MEASURED in its own doc at 22 ms for a
    // width-32 set), once PER POOLED TRANSACTION PER BLOCK. At a pool of 256 that is ~5.6 s of proving
    // inside a 500 ms block target, and the cost carries a term in POOL DEPTH — an axis, not a constant.
    // Buying the fill's admission authority with the node's block-apply budget trades FAST/CHEAP/SCALABLE
    // for SOUND, and the pillars are never traded off. Deleted at source rather than gated behind a flag,
    // per the hygiene cardinal.
    //
    // ⭐ THE PRIMITIVE SURVIVES AND COSTS NOTHING: `NfAbsenceBatchCarrier::resume` rebuilds a carrier from
    // the state a transaction already carries — no new wire field, no work unless called — and is pinned
    // lossless byte-for-byte by `resuming_an_absence_carrier_from_the_carried_state_is_lossless`. Any
    // resumable design needs it; what none may have is the NODE paying per-transaction proving per block.
    //
    // ⛔ THE CONSTRAINT ON ANY FUTURE SHAPE, written down so this is not re-landed: the node's per-block
    // work must carry NO term in pool depth. A SPENDER maintaining its own single carrier is O(1) for the
    // node by construction; the unsolved part is that a settlement's tags are born WITH the settlement.

    /// ⭐ A-F66 — A FULL POOL TAKES A NEWCOMER BY EVICTION, NEVER BY REFUSAL (docs/CHAIN-DEATH-AUDIT-20261115.md C9). A pool
    /// that refused every arrival once full could be held shut by a flood: honest payments were turned away while the flood's
    /// own spends waited their turn and paid nothing until included. Room is made from what costs nobody a payment first —
    /// the padding cover this node minted — then by a keyed draw among plain spends; a framed chain object (a vote, a bond, a
    /// credit, an order) is never evicted. With the draw's capped stamp weight ([`STAMP_PRIORITY_BITS_MAX`]), a flood that
    /// wants to crowd out honest payments must out-NUMBER them with valid spends (a proof each, ~2 core-seconds) instead of
    /// out-hashing them, and only its spends a block carries pay the fee: censoring costs more as honest demand grows.
    /// Node-local selection policy: nothing served, nothing in consensus, no change to any block's observable shape.
    /// BORROWED: Bitcoin Core's TrimToSize (a full mempool evicts to admit; here the key is a draw, since fees are hidden).
    /// AI RESISTANT: (b) code and economics; the draw's key is node-local (`counter`), so a flood cannot aim at a victim.
    /// cons: a pooled payment can be evicted under a flood and its wallet re-sends it (as it does after any loss); 0 bytes.
    fn make_room_for(&mut self, weight: u64) -> bool {
        if weight > self.params.max_pool_weight {
            return false;
        }
        while self.total_weight + weight > self.params.max_pool_weight {
            let counter = self.counter;
            let key = |id: &Hash32| -> u64 {
                let mut h = blake3::Hasher::new();
                h.update(b"MUSD-pool-evict-v1");
                h.update(&counter.to_le_bytes());
                h.update(id.as_bytes());
                let mut x = [0u8; 8];
                x.copy_from_slice(&h.finalize().as_bytes()[..8]);
                u64::from_le_bytes(x)
            };
            let victim = self
                .txs
                .values()
                .filter(|t| crate::chain_object::unframe(&t.blob).is_none())
                .min_by_key(|t| (!t.output_notes.is_empty(), key(&t.id)))
                .map(|t| t.id);
            match victim {
                Some(v) => self.remove(&[v]),
                None => return false,
            }
            self.counter = self.counter.wrapping_add(1);
        }
        true
    }

    pub fn remove(&mut self, ids: &[Hash32]) {
        for id in ids {
            if let Some(tx) = self.txs.remove(id) {
                crate::budget_clock::replay_tx_trace("pool-", &id.0, None);
                self.note_gone(*id); // DB-444: an inventory naming it again is not fetched again
                self.total_weight = self.total_weight.saturating_sub(tx.weight as u64);
                self.arrival.remove(id);
                self.admitted_height.remove(id);
                // Released beside the tx it shadows — this is what makes the field's bound TRUE.
                self.restamp_bar.remove(id);
                for nf in &tx.nullifiers {
                    self.spent.remove(nf);
                }
            }
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod real_first_selection_tests {
    use super::*;

    /// ⛔⛔⛔ A REAL PAYMENT MUST NEVER BE STARVED BY COVER — THE DEFECT THAT BLOCKED EVERY SEND.
    ///
    /// MEASURED on the live peered pair: 175 of 175 produced blocks carried exactly 1,153 note bytes — the
    /// constant entropy note and nothing else. A settling payment carries recipient + change = 2,306. The
    /// account-target lookup reported `0/1 resolved while 3 target(s) EXIST; 0 of this block's note key(s)
    /// appear among them`: targets filed correctly, block holding no note to match.
    ///
    /// THE CAUSE: `produce_template` mints cover via `pad_to_fixed_shape` and ACCEPTS it into the pool before
    /// selecting. Ordering by `stamp_work` alone let that fresh cover outrank a waiting payment, and
    /// `out.len() >= BLOCK_FIXED_TX_COUNT` broke the loop with the block full of padding. The payment was
    /// never dropped — it never won a seat, block after block. Silent permanent starvation, indistinguishable
    /// from a payment that was never sent.
    ///
    /// This fills the pool with cover that OUTRANKS the payment on `stamp_work`, so it reproduces the exact
    /// losing condition: without the real-first ordering the payment is not selected and this FAILS.
    #[test]
    fn a_real_payment_is_selected_even_when_cover_outranks_it_on_stamp_work() {
        let mut pool = Mempool::new();

        // The payment: carries output notes, and DELIBERATELY the weakest stamp in the pool.
        let pay_blob = b"real-payment-tx".to_vec();
        let mut pay = PqTx {
            clock_ms: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            id: PqTx::content_id(&pay_blob),
            blob: pay_blob,
            weight: 1,
            nullifiers: Vec::new(),
            pow_stamp: 0,
            output_notes: vec![7u8; crate::cover::PQ_NOTE_BYTES],
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
        // Grind a valid anti-spam stamp, exactly as a real submit does.
        let need = pool.required_stamp_bits();
        let mut s = 0u64;
        loop {
            pay.pow_stamp = s;
            if pay.stamp_work() >= need {
                break;
            }
            s += 1;
        }
        let pay_id = pay.id;

        // Fill the pool with MORE cover than a block can hold, admitted BEFORE the payment so arrival
        // order alone starves it — the deterministic form of the live race, no grinding needed.
        for i in 0..(crate::cover::BLOCK_FIXED_TX_COUNT + 8) {
            let blob = format!("cover-{i}").into_bytes();
            let mut c = PqTx {
                clock_ms: 0,
                note_clues: Vec::new(),
                account_targets: Vec::new(),
                id: PqTx::content_id(&blob),
                blob,
                weight: 1,
                nullifiers: Vec::new(),
                pow_stamp: 0,
                output_notes: Vec::new(), // cover carries NO output notes — that is what makes it cover
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
            let mut cs = 0u64;
            loop {
                c.pow_stamp = cs;
                if c.stamp_work() >= need {
                    break;
                }
                cs += 1;
            }
            let _ = pool.accept(c); // cover admission mirrors `pad_to_fixed_shape` -> `mempool.accept`
        }
        // The payment arrives LAST — the losing position. Without real-first ordering it never wins a seat.
        pool.accept(pay).expect("the payment is admitted");

        // ⛔⛔⛔ ASSERT THE LOSING CONDITION EXISTS, OR THIS TEST PROVES NOTHING.
        //
        // The first version wrote `let _ = pool.accept(c)` and never checked how many cover txs were actually
        // admitted. Running the NEGATIVE CONTROL — reverting the real-first ordering — the test still PASSED,
        // which means it could not fail and was worthless as evidence. If the pool never exceeds
        // BLOCK_FIXED_TX_COUNT then every candidate fits and no starvation is possible, so the assertion below
        // is the difference between a real regression test and one of the "cannot fail" cheats.
        assert!(
            pool.len() > crate::cover::BLOCK_FIXED_TX_COUNT,
            "the pool must OVERFLOW the block's fixed tx capacity ({} held vs {} seats) — otherwise every \
             candidate fits, nothing can be starved, and a green result here says nothing at all",
            pool.len(),
            crate::cover::BLOCK_FIXED_TX_COUNT
        );

        let selected = pool.select_for_template(u64::MAX, &[0u8; 32]);

        assert!(
            selected.contains(&pay_id),
            "the REAL payment must be selected even though every cover tx out-stamps it — cover is PADDING \
             that fills the constant block shape, never a competitor for a seat. Losing this means a payment \
             sits in the pool forever while blocks go out full of cover, which is exactly what 175/175 blocks \
             carrying only the entropy note measured"
        );
        assert!(
            selected.len() <= crate::cover::BLOCK_FIXED_TX_COUNT,
            "the block shape stays CONSTANT — prioritising real txs must not change how many the block holds, \
             or an observer could tell a paying block from an idle one"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    // Grind a valid anti-spam stamp for a tx with the given blob/weight/nullifiers.
    fn mk(blob: &[u8], weight: u32, nullifiers: Vec<Hash32>, need_bits: u32) -> PqTx {
        let id = PqTx::content_id(blob);
        let mut s = 0u64;
        loop {
            let tx = PqTx {
                clock_ms: 0,
                note_clues: Vec::new(),
                account_targets: Vec::new(),
                id,
                blob: blob.to_vec(),
                weight,
                nullifiers: nullifiers.clone(),
                pow_stamp: s,
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
            if tx.stamp_work() >= need_bits {
                return tx;
            }
            s += 1;
        }
    }

    /// G14 (lane b 2026-10-25): the voter's node lays its own vote in every template; a relayer's templates draw another
    /// voter's vote 1-in-`relayers`, never zero and never all (MEASURED before: every template of every node laid it, 5.7
    /// copies per vote at 10 nodes, scratchpad/verify/simmem-c99ff64.log).
    #[test]
    fn g14_a_vote_is_laid_by_its_voter_and_a_relayer_draws_it_one_in_n() {
        use crate::pqauth::{finality_vote_msg, ml_dsa_keypair, ml_dsa_sign, pubkey_id};
        let (pk, sk) = ml_dsa_keypair();
        let block = Hash32::hash(b"g14-voted-block");
        let cert = crate::validator::VoteCert {
            pubkey: pk.clone(),
            block,
            height: 7,
            sig: ml_dsa_sign(&finality_vote_msg(&block, 7), &sk).expect("signs"),
        };
        let blob = crate::finality_vote_tx::wire(&cert).expect("an ML-DSA-65 cert frames");
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let id = mp.accept(mk(&blob, 1_000, Vec::new(), need)).expect("the vote is pooled");
        let laid = |mp: &Mempool| -> usize {
            (0..900u32)
                .filter(|i| {
                    let draw = *blake3::hash(&i.to_le_bytes()).as_bytes();
                    mp.select_for_template(u64::MAX, &draw).contains(&id)
                })
                .count()
        };
        mp.set_vote_lay(Some(pubkey_id(&pk)), 9);
        assert_eq!(laid(&mp), 900, "the voter's own node lays its vote in every template");
        mp.set_vote_lay(Some([7u8; 32]), 1);
        assert_eq!(laid(&mp), 900, "with no other relayer the one relayer lays it every time");
        mp.set_vote_lay(Some([7u8; 32]), 9);
        let relayed = laid(&mp);
        eprintln!("[g14] a relayer with odds 1/9 laid another voter's vote in {relayed} of 900 templates");
        assert!((50..=150).contains(&relayed), "⛔ a relayer laid the vote in {relayed} of 900 templates, expected ~100");
    }

    /// ⭐ A-F66 PIN (RED-first by its calibration): a flood can neither hold a full pool shut nor buy every slot with CPU, at the
    /// production pool bound and the production spend weight. (1) A pool filled to `max_pool_weight` admits a new payment by
    /// evicting, cover first, and never a framed chain object. (2) A payment ground 12 bits past the pool's floor is drawn into far
    /// fewer templates than "every one", among five blocks' worth of payments at the floor: its extra work counts for
    /// STAMP_PRIORITY_BITS_MAX bits. CALIBRATION: with the old 52-bit weight it was drawn into every template.
    /// TWO-PARTY-REVIEWED: pool admission and the template draw are ONE node's local selection policy (never served, no consensus
    /// rule), so this pin has one side by the nature of what it holds; the cross-node claim (an honest payment sent through one
    /// node lands on its peer under a flood) is the real-node check scratchpad/net/spam_stamp.py.
    #[test]
    fn af66_a_full_pool_admits_by_eviction_and_grinding_buys_a_bump_never_the_block() {
        use crate::cover::{BLOCK_FIXED_SPEND_TX_COUNT, TX_FIXED_NULLIFIER_COUNT};
        let params = crate::params::ChainParams::default();
        let w = params.max_tx_weight;
        let fit = (params.max_pool_weight / u64::from(w)) as usize;
        let tags = |i: usize| -> Vec<Hash32> { (0..TX_FIXED_NULLIFIER_COUNT).map(|k| Hash32::hash(format!("af66-{i}-{k}").as_bytes())).collect() };
        let real = |i: usize, bits: u32, weight: u32| -> PqTx {
            let mut t = mk(format!("af66-pay-{i}").as_bytes(), weight, tags(i), bits);
            t.output_notes = vec![7u8; crate::cover::PQ_NOTE_BYTES * 2];
            t
        };
        let mut mp = Mempool::with_params(params.clone());
        let cover_id = mp.accept(mk(b"af66-cover", w, tags(usize::MAX), mp.required_stamp_bits())).expect("cover pooled");
        let mut held = Vec::new();
        while mp.total_weight() + u64::from(w) <= params.max_pool_weight {
            let bits = mp.required_stamp_bits();
            held.push(mp.accept(real(held.len(), bits, w)).expect("a payment pooled"));
        }
        assert_eq!(held.len() + 1, fit, "CALIBRATION: the pool stands at its production weight bound");
        let bits = mp.required_stamp_bits();
        let late = mp.accept(real(10_000, bits, w)).expect("⛔ A-F66: a full pool refused a new payment");
        assert!(mp.txs.contains_key(&late), "the newcomer is pooled");
        assert!(!mp.txs.contains_key(&cover_id), "⛔ A-F66: room was made from a payment while cover was pooled");
        assert!(held.iter().all(|h| mp.txs.contains_key(h)), "the cover alone made the room");
        let bits = mp.required_stamp_bits();
        let next = mp.accept(real(10_001, bits, w)).expect("⛔ A-F66: a full pool of payments refused a new one");
        assert!(mp.txs.contains_key(&next) && mp.total_weight() <= params.max_pool_weight, "a payment made room for a payment, inside the bound");

        // (2) the draw: five blocks' worth of payments at the floor and one ground 12 bits past it (4,096x under the old weight)
        let mut mp = Mempool::new();
        let floor = mp.required_stamp_bits();
        let crowd = 5 * BLOCK_FIXED_SPEND_TX_COUNT;
        for i in 0..crowd {
            mp.accept(real(20_000 + i, floor, 1_000)).expect("pooled");
        }
        let grinder = mp.accept(real(99_999, floor + 12, 1_000)).expect("pooled");
        let draws = 300u32;
        let drawn = (0..draws)
            .filter(|i| mp.select_for_template(u64::MAX, blake3::hash(&i.to_le_bytes()).as_bytes()).contains(&grinder))
            .count();
        eprintln!("[af66] a payment 12 bits past the floor was drawn into {drawn} of {draws} templates (one block holds {BLOCK_FIXED_SPEND_TX_COUNT} of {crowd})");
        assert!(drawn < (draws as usize) * 9 / 10, "⛔ A-F66: grinding bought a slot in {drawn} of {draws} templates");
        assert!(drawn > 0, "the bump still counts: a ground payment is drawn sometimes");
    }

    /// DB-96 (run 97, 2026-09-19): a pool holding more constant-width spends than one block's tag budget
    /// used to hand `produce` a template it refused — forever. The selector now fills exactly the budget
    /// (`BLOCK_FIXED_SPEND_TX_COUNT` spends of `TX_FIXED_NULLIFIER_COUNT` tags) and carries the rest.
    #[test]
    fn a_template_never_exceeds_the_block_tag_budget_and_the_rest_wait_for_the_next_block() {
        use crate::cover::{BLOCK_FIXED_NULLIFIER_COUNT, BLOCK_FIXED_SPEND_TX_COUNT, TX_FIXED_NULLIFIER_COUNT};
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let over = BLOCK_FIXED_SPEND_TX_COUNT * 2 + 1; // 17 spends: two blocks and one more
        let mut ids = Vec::new();
        for i in 0..over {
            let tags: Vec<Hash32> =
                (0..TX_FIXED_NULLIFIER_COUNT).map(|k| Hash32::hash(format!("nf-{i}-{k}").as_bytes())).collect();
            let tx = mk(format!("spend-{i}").as_bytes(), 1_000, tags, need);
            ids.push(mp.accept(tx).expect("a distinct spend is admitted"));
        }
        let budget = |sel: &[Hash32], mp: &Mempool| -> usize {
            sel.iter().map(|id| mp.get(id).map(|t| t.nullifiers.len()).unwrap_or(0)).sum()
        };
        let first = mp.select_for_template(u64::MAX, &[0u8; 32]);
        assert_eq!(budget(&first, &mp), BLOCK_FIXED_NULLIFIER_COUNT, "the template fills the tag budget exactly");
        assert_eq!(first.len(), BLOCK_FIXED_SPEND_TX_COUNT, "exactly one block's worth of spends");
        // the rest WAIT (never dropped): once the first block carried its set, the next template takes the next
        mp.remove(&first);
        let second = mp.select_for_template(u64::MAX, &[0u8; 32]);
        assert_eq!(second.len(), BLOCK_FIXED_SPEND_TX_COUNT);
        assert!(second.iter().all(|id| !first.contains(id)), "a carried spend is not re-selected");
        mp.remove(&second);
        let third = mp.select_for_template(u64::MAX, &[0u8; 32]);
        assert_eq!(third.len(), 1, "the seventeenth spend lands in the third block");
        assert_eq!(mp.len(), 1, "nothing was dropped along the way");
    }

    /// ⭐⭐ DB-443 (link 63, 2026-10-20) — CONCURRENT TEMPLATES OVER ONE SATURATED POOL CARRY DIFFERENT SPENDS. Eight producers
    /// holding the same pool of three blocks' worth of spends each fill their eight spend slots; under the greedy rank
    /// every one of them picked the SAME top eight (the order was a function of the pool alone), so the mesh carried
    /// eight distinct spends per round however many producers it had. MEASURED night/perf-load-20261020-232053-n8.log:
    /// the 65 real spends rode 4–26 templates each and P10's knee sat at 2 tx/s offered. BORROWED-FROM Lewenberg,
    /// Sompolinsky, Zohar, "Inclusive Block Chain Protocols" (FC 2015) and Kaspa's weighted-random template selector.
    /// CALIBRATION: every template still fills the lane exactly; the same draw reproduces the same set; over 64 draws
    /// no pending spend starves.
    #[test]
    fn concurrent_templates_over_one_saturated_pool_carry_different_spends_and_none_starves() {
        use crate::cover::{BLOCK_FIXED_SPEND_TX_COUNT, TX_FIXED_NULLIFIER_COUNT};
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let pending = BLOCK_FIXED_SPEND_TX_COUNT * 3;
        for i in 0..pending {
            let tags: Vec<Hash32> =
                (0..TX_FIXED_NULLIFIER_COUNT).map(|k| Hash32::hash(format!("inc-{i}-{k}").as_bytes())).collect();
            let mut tx = mk(format!("inc-spend-{i}").as_bytes(), 1_000, tags, need);
            tx.output_notes = vec![0u8; crate::cover::PQ_NOTE_BYTES * 2]; // a real transfer: recipient + change
            mp.accept(tx).expect("a distinct spend is admitted");
        }
        let draw = |k: u64| Hash32::hash(format!("producer-{k}-template").as_bytes()).0;
        let picks: Vec<Vec<Hash32>> = (0..8).map(|p| mp.select_for_template(u64::MAX, &draw(p))).collect();
        for p in &picks {
            assert_eq!(p.len(), BLOCK_FIXED_SPEND_TX_COUNT, "CALIBRATION: each template still fills the spend lane exactly");
        }
        assert_eq!(mp.select_for_template(u64::MAX, &draw(0)), picks[0], "CALIBRATION: one draw, one set");
        let distinct: HashSet<Hash32> = picks.iter().flatten().copied().collect();
        assert!(
            distinct.len() >= 2 * BLOCK_FIXED_SPEND_TX_COUNT,
            "⛔ eight concurrent templates over {pending} pending spends carried only {} distinct — the selection is a \
             function of the pool alone, so every producer lays the same spends and the mesh drains one block's worth per \
             round (inclusive selection expects {pending} · (1 − (1 − 8/{pending})^8) ≈ 23)",
            distinct.len()
        );
        let union: HashSet<Hash32> = (0..64u64).flat_map(|k| mp.select_for_template(u64::MAX, &draw(1_000 + k))).collect();
        assert_eq!(union.len(), pending, "⛔ a pending spend no template drew in 64 — starvation");
    }

    /// ⛔ link 57 (db369, 2026-10-09) — A TEMPLATE LEAVES ROOM FOR THE PRODUCER'S REWARD. The SATOSHI reward lays one
    /// nullifier in the lane and one note after selection; a selection that filled the whole budget made `produce` refuse
    /// every template ("the SELECTED set carries 257 real nullifier(s)") while the pool never drained — a halt for any
    /// `BLOCK_FIXED_SPEND_TX_COUNT` pending spends.
    /// ROOT-LAYER: the selector is where a block's tag and note budgets are spent; the reward is laid after it, so the
    ///   budget the reward needs is withheld HERE (Bitcoin `BlockAssembler`'s coinbase reserve), not refused at produce.
    /// MEASURED: before — db369 on 174aa58 (night/link57-seat1.log): `[produce-refused] … 257 real nullifier(s) … (256
    ///   tx(s) selected)`, first `produce` None; after — this pin + db369 (night/link57-seat2.log).
    /// MUST-STAY-GREEN: `a_template_never_exceeds_the_block_tag_budget…` (unreserved fills the lane exactly), db369, the
    ///   fast journey.
    /// CALIBRATION: unreserved, the same pool fills the lane exactly (the shape that met the reward's tag at 257).
    #[test]
    fn a_rewarded_template_reserves_the_rewards_tag_and_note_and_the_pool_still_drains() {
        use crate::cover::{BLOCK_FIXED_NULLIFIER_COUNT, BLOCK_FIXED_SPEND_TX_COUNT, TX_FIXED_NULLIFIER_COUNT};
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let n = BLOCK_FIXED_SPEND_TX_COUNT;
        for i in 0..n {
            let tags: Vec<Hash32> =
                (0..TX_FIXED_NULLIFIER_COUNT).map(|k| Hash32::hash(format!("rw-{i}-{k}").as_bytes())).collect();
            mp.accept(mk(format!("rw-spend-{i}").as_bytes(), 1_000, tags, need)).expect("a distinct spend is admitted");
        }
        let tags = |sel: &[Hash32], mp: &Mempool| -> usize {
            sel.iter().map(|id| mp.get(id).expect("a selected id is pooled").nullifiers.len()).sum()
        };
        let unreserved = mp.select_for_template(u64::MAX, &[0u8; 32]);
        assert_eq!(tags(&unreserved, &mp), BLOCK_FIXED_NULLIFIER_COUNT, "CALIBRATION: unreserved, the lane fills exactly");
        let first = mp.select_for_template_reserving(u64::MAX, TemplateReserve::MINING_REWARD, &[0u8; 32]);
        assert!(
            tags(&first, &mp) + TemplateReserve::MINING_REWARD.tags <= BLOCK_FIXED_NULLIFIER_COUNT,
            "⛔ the selection plus the reward's tag overflows the lane: {} + 1",
            tags(&first, &mp)
        );
        assert!(!first.is_empty(), "a rewarded template still lays spends");
        mp.remove(&first);
        let second = mp.select_for_template_reserving(u64::MAX, TemplateReserve::MINING_REWARD, &[0u8; 32]);
        assert_eq!(first.len() + second.len(), n, "the spends left over wait one block, never dropped");
        mp.remove(&second);
        assert!(mp.is_empty(), "the pool drains");
    }

    #[test]
    fn accepts_valid_and_selects() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let t1 = mk(b"tx-one", 1000, vec![Hash32::hash(b"nf-a")], need);
        let t2 = mk(b"tx-two", 2000, vec![Hash32::hash(b"nf-b")], need);
        let id1 = mp.accept(t1).unwrap();
        let id2 = mp.accept(t2).unwrap();
        assert_eq!(mp.len(), 2);
        assert!(mp.contains(&id1) && mp.contains(&id2));
        // both fit in a big block
        let sel = mp.select_for_template(1_000_000, &[0u8; 32]);
        assert_eq!(sel.len(), 2);
        // a tight block takes only the lighter/higher-priority subset within weight
        let tight = mp.select_for_template(1500, &[0u8; 32]);
        assert_eq!(
            tight.iter().map(|id| mp.txs[id].weight as u64).sum::<u64>() <= 1500,
            true
        );
    }

    #[test]
    fn accept_verified_gates_on_the_zk_carrier_verify() {
        // #135 the per-tx direct-carrier admission gate: a blob the ZK verify REJECTS never enters the pool
        // (fail-closed, no spam surface); a blob it ACCEPTS then passes structural admission. The node wires
        // `verify` = `whir_decider::pqspend_direct_verify_carrier(blob).is_some()`.
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let bad = mk(b"bad-carrier", 1000, vec![Hash32::hash(b"nf-x")], need);
        assert_eq!(
            mp.accept_verified(bad, |_blob| false).unwrap_err(),
            MempoolError::InvalidProof
        );
        assert_eq!(mp.len(), 0, "a ZK-rejected carrier must not enter the pool");
        let good = mk(b"good-carrier", 1000, vec![Hash32::hash(b"nf-y")], need);
        let id = mp.accept_verified(good, |_blob| true).unwrap();
        assert!(mp.contains(&id), "a ZK-verified carrier is admitted");
        assert_eq!(mp.len(), 1);
    }

    #[test]
    fn rejects_bad_id_heavy_lowstamp_dup_and_doublespend() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        // bad id
        let mut bad = mk(b"blobX", 10, vec![], need);
        bad.id = Hash32::hash(b"not-the-blob");
        assert_eq!(mp.accept(bad).unwrap_err(), MempoolError::InvalidId);
        // too heavy
        let heavy = mk(
            b"heavy",
            crate::params::ChainParams::default().max_tx_weight + 1,
            vec![],
            need,
        );
        assert!(matches!(
            mp.accept(heavy).unwrap_err(),
            MempoolError::TooHeavy(_)
        ));
        // insufficient stamp: pow_stamp that yields 0 work while we require > 0
        let id = PqTx::content_id(b"lowstamp");
        // find a stamp with LESS work than needed (need >= base >= 8, work 0 is common)
        let mut weak = PqTx {
            clock_ms: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            id,
            blob: b"lowstamp".to_vec(),
            weight: 10,
            nullifiers: vec![],
            pow_stamp: 0,
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
        let mut s = 0u64;
        while weak.stamp_work() >= need {
            s += 1;
            weak.pow_stamp = s;
        }
        assert!(matches!(
            mp.accept(weak).unwrap_err(),
            MempoolError::InsufficientStampWork { .. }
        ));
        // duplicate
        let t = mk(b"dupe", 10, vec![Hash32::hash(b"nf-1")], need);
        mp.accept(t.clone()).unwrap();
        assert_eq!(mp.accept(t).unwrap_err(), MempoolError::AlreadyKnown);
        // double-spend: different tx, same nullifier
        let ds = mk(b"different", 10, vec![Hash32::hash(b"nf-1")], need);
        assert_eq!(mp.accept(ds).unwrap_err(), MempoolError::DoubleSpend);
    }

    /// ⭐ POOL-ACCEPT ⇒ MINEABLE. A tx the block template can never pack must be refused AT ADMISSION, not
    /// accepted and then held forever. The template bounds a block's real output notes by the fixed
    /// `BLOCK_FIXED_NOTE_COUNT` cover shape; a tx carrying more than that entire budget fits no block at any
    /// height. Accepting it would tell the sender "sent" and then strand the funds in the pool with nothing
    /// logged — the exact silent-black-hole shape that makes a chain unsafe to hold real money on.
    #[test]
    fn the_pool_refuses_a_tx_no_block_could_ever_pack_instead_of_stranding_it() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let over = crate::cover::BLOCK_FIXED_NOTE_COUNT + 1;
        let mut tx = mk(b"too-many-notes", 1_000, vec![], need);
        tx.output_notes = vec![0u8; over * crate::cover::PQ_NOTE_BYTES];
        tx.id = PqTx::content_id(&tx.blob);
        assert_eq!(
            mp.accept(tx).unwrap_err(),
            MempoolError::Unmineable {
                got: over,
                max: crate::cover::BLOCK_FIXED_NOTE_COUNT
            },
            "a tx no block could pack is refused at submit, where the sender still finds out"
        );

        // ...and a tx that fills the budget EXACTLY is still accepted AND selectable — the bound rejects only
        // the genuinely unmineable, it does not shrink what the chain will carry.
        let mut ok_tx = mk(b"exactly-full", 1_000, vec![], need);
        ok_tx.output_notes =
            vec![0u8; crate::cover::BLOCK_FIXED_NOTE_COUNT * crate::cover::PQ_NOTE_BYTES];
        ok_tx.id = PqTx::content_id(&ok_tx.blob);
        let id = mp
            .accept(ok_tx)
            .expect("a full-but-packable tx is admitted");
        assert!(
            mp.select_for_template(crate::params::ChainParams::default().max_block_weight, &[0u8; 32]).contains(&id),
            "the admitted full-width tx is actually selectable — pool-accept really does imply mineable"
        );
    }

    /// ⭐ TX LIFECYCLE — a payment that is admitted and then never settles must become VISIBLE. Before this the
    /// pool could only say "accepted"; a tx that no block ever packed produced no rejection, no log and no
    /// state change, so from the owner's side the money simply stopped existing. Age is measured in BLOCKS
    /// (`arrival` is an insertion counter and cannot answer "how long have I been waiting?" in chain terms).
    /// Node-LOCAL: never served or gossiped, so it adds no which-item query and no timing metadata.
    #[test]
    fn a_tx_that_never_settles_becomes_visible_as_stuck_instead_of_vanishing_silently() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let id = mp
            .accept(mk(b"waiting-payment", 1_000, vec![], need))
            .expect("admitted");

        // Freshly admitted: not stuck at any age.
        assert!(
            mp.pooled_at_least(1).is_empty(),
            "a tx admitted this block is not stuck yet"
        );

        // Blocks go by and it is still sitting there — exactly the live symptom.
        mp.set_height(8);
        assert_eq!(
            mp.pooled_at_least(8),
            vec![id],
            "8 blocks pooled and unsettled — reported as stuck"
        );
        assert!(
            mp.pooled_at_least(9).is_empty(),
            "the age bound is exact, not approximate"
        );
        // The node can re-gossip it WITHOUT any network lookup — the stuck set is answered locally.
        assert!(
            mp.get_pooled(&id).is_some(),
            "a stuck tx is re-relayable from local state"
        );

        // Once it settles into a block the pool forgets it — a mined tx is never reported stuck forever.
        mp.remove(&[id]);
        assert!(
            mp.pooled_at_least(1).is_empty(),
            "a settled tx leaves the stuck set"
        );
        assert!(
            mp.get_pooled(&id).is_none(),
            "and is no longer re-relayable"
        );
    }

    /// ⭐ CONGESTION ESCAPE HATCH. Selection ranks purely by `stamp_work`, so under load a low-stamp payment can
    /// wait indefinitely with no way for its owner to act — funds frozen in the pool. The sender may RE-STAMP the
    /// SAME tx at strictly higher client work to raise its own priority. NOT a fee: a plaintext fee is an
    /// amount-correlated public signal, which the digital-cash pillar forbids. Pins the anti-abuse half too — a
    /// same-or-lower-work resubmission changes nothing, so this cannot flood the pool or displace another sender.
    #[test]
    fn a_sender_can_re_stamp_its_own_stuck_tx_to_higher_priority_but_never_lower_it() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let low = mk(
            b"stuck-payment",
            1_000,
            vec![Hash32::hash(b"bump-nf")],
            need,
        );
        let id = mp.accept(low.clone()).expect("admitted");
        let base_work = mp.get_pooled(&id).expect("pooled").stamp_work();

        // A HIGHER-work re-stamp of the SAME payment is taken, and the pool now ranks it by the new work.
        let mut hi = low.clone();
        let mut s = low.pow_stamp + 1;
        loop {
            hi.pow_stamp = s;
            if hi.stamp_work() > base_work {
                break;
            }
            s += 1;
        }
        let bumped_work = hi.stamp_work();
        assert_eq!(
            mp.accept(hi).expect("a higher-work re-stamp is accepted"),
            id,
            "same payment, same id"
        );
        assert_eq!(
            mp.get_pooled(&id).unwrap().stamp_work(),
            bumped_work,
            "the pool holds the bumped stamp"
        );
        assert_eq!(
            mp.len(),
            1,
            "a bump REPLACES — it never duplicates the payment"
        );

        // A SAME/LOWER-work resubmission is rejected — no flooding, no displacing anyone else.
        assert_eq!(
            mp.accept(low).unwrap_err(),
            MempoolError::AlreadyKnown,
            "a non-bump is still already-known"
        );
        assert_eq!(
            mp.get_pooled(&id).unwrap().stamp_work(),
            bumped_work,
            "and it cannot LOWER a live priority"
        );
    }

    /// ⭐ DB-329 §7f — TWO SENDS CLAIMING ONE SLOT: exactly one enters. Each tx's list is `[nf, claim, decoys…]`; two
    /// DIFFERENT notes (distinct nullifiers) claiming the SAME `(key, d)` share row 1, and the pool refuses the second
    /// exactly as it refuses a second spend of one note — the set arbitrates, no lock and no ordering rule. CALIBRATION:
    /// two ordinary sends (fresh blindings, so distinct claims) both enter.
    /// TWO-PARTY-REVIEWED: this is the ONE set's verdict over two arriving claims (what every node's pool and fold run);
    /// the two-DEVICE form — two wallets of one seed racing their first sends on two nodes — is §7e's pin 1, the wallet
    /// half, and is not built yet.
    #[test]
    fn db329_two_sends_claiming_one_slot_land_exactly_one() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let tag = |label: &[u8]| Hash32::hash(label);
        let claim = tag(b"N_d(slot_key, d=1)");
        let a = mk(b"claim-a", 10, vec![tag(b"nf-a"), claim, tag(b"decoy-a")], need);
        let b = mk(b"claim-b", 10, vec![tag(b"nf-b"), claim, tag(b"decoy-b")], need);
        mp.accept(a).expect("the first claim of the slot enters");
        assert_eq!(mp.accept(b).unwrap_err(), MempoolError::DoubleSpend, "⛔ a second claim of one slot entered the pool");
        let c = mk(b"plain-c", 10, vec![tag(b"nf-c"), tag(b"claim(lc_blind_c, 0)"), tag(b"decoy-c")], need);
        let d = mk(b"plain-d", 10, vec![tag(b"nf-d"), tag(b"claim(lc_blind_d, 0)"), tag(b"decoy-d")], need);
        mp.accept(c).expect("CALIBRATION: an ordinary send enters");
        mp.accept(d).expect("CALIBRATION: a second ordinary send, under its own blinding, enters beside it");
    }

    #[test]
    fn select_skips_intra_block_double_spend_and_remove_frees() {
        let mut mp = Mempool::new();
        let need = mp.required_stamp_bits();
        let shared = Hash32::hash(b"shared-nf");
        // two txs spending the SAME note but with different blobs => both accepted only if the
        // first is removed; here we accept t1, and t2 (same nf) is a pool-level double-spend.
        let t1 = mk(b"a", 10, vec![shared], need);
        let id1 = mp.accept(t1).unwrap();
        let t2 = mk(b"b", 10, vec![shared], need);
        assert_eq!(mp.accept(t2).unwrap_err(), MempoolError::DoubleSpend);
        // remove t1 frees the nullifier so a competing spend can enter
        mp.remove(&[id1]);
        assert!(mp.is_empty());
        let t3 = mk(b"c", 10, vec![shared], need);
        assert!(mp.accept(t3).is_ok());
        assert_eq!(mp.select_for_template(1_000, &[0u8; 32]).len(), 1);
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // ⛔⛔⛔ DOOR AUDIT 2026-09-07, FAMILY B (§9.6 questions 3, 4 and 6). THESE ARE FIX SPECS.
    //
    // THE MECHANISM, stated with the lines: `PqTx::content_id` is `blake3(blob)` and NOTHING ELSE
    // (mempool.rs:164). `accept_inner`'s re-stamp arm (mempool.rs:437-447) finds a pooled tx by that
    // id and does `self.txs.insert(id, tx)` — a WHOLE-STRUCT replacement — before the double-spend
    // loop (448), before the capacity check (453) and before the `spent`/`total_weight` bookkeeping
    // (458-461). Its own comment asserts "the identical blob (same id, same nullifiers, same weight,
    // same outputs — nothing about the payment changes)". Only the FIRST of those four is true. The
    // id covers the blob; `nullifiers`, `output_notes`, `weight`, `bond_notes`, `stake_notes`,
    // `account_targets`, `note_clues` and every witness field are OUTSIDE it.
    //
    // WHY IT REACHES CONSENSUS ON A SECOND NODE: the swap survives the wire — a `PqTx` gossips as one
    // postcard struct, so the peer that re-admits it takes the SAME arm on its OWN pool. And no door
    // downstream re-reads the swapped fields: `accept_verified` (475) re-runs `verify` on `tx.blob`
    // only, so the replacement re-verifies the SAME bytes and passes vacuously;
    // `chain_object::wrapper_binds_object` returns TRUE for an unframed send (chain_object.rs:211-213
    // — "an ordinary send, its own carrier gate judges it"), and that carrier gate is
    // `pqspend_direct_verify_carrier(blob)` (chain_object.rs:243), which never sees `output_notes`;
    // the produce-side assembly door (node.rs:1881) and the graft door (node.rs:18333) both
    // `continue` on an unframed blob for the same reason.
    //
    // THE FIX SPEC (one shared site, per §9.5): the pool's identity for the re-stamp arm must cover
    // every field a block will carry. Either (a) make the re-stamp arm compare the incoming tx to
    // the pooled one field-by-field and mutate ONLY `pow_stamp` (refuse `AlreadyKnown` on any other
    // difference) — the arm's own stated contract, actually enforced; or (b) key the pool on a
    // commitment over the whole carried envelope, not `blake3(blob)`. (a) is the smaller change and
    // is a check at ONE shared site that every admission door already funnels through.
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⛔ THE STRANDED-CLAIM SHAPE, READ STRAIGHT OFF THE POOL'S OWN MAPS — the nullifiers in `spent`
    /// whose owning id is not pooled, or is pooled but does not carry them.
    ///
    /// This is the invariant `register_nullifier_claims` owns, asserted rather than assumed. It is a test
    /// helper on purpose: `spent` and `txs` are private to this module and a child module can read them, so
    /// the shape is pinned on the REAL state with no accessor added to the node's surface for a check
    /// nothing in production calls.
    fn stranded_claims(pool: &Mempool) -> Vec<Hash32> {
        let mut out: Vec<Hash32> = pool
            .spent
            .iter()
            .filter(|(nf, owner)| match pool.txs.get(*owner) {
                Some(tx) => !tx.nullifiers.contains(nf),
                None => true,
            })
            .map(|(nf, _)| *nf)
            .collect();
        out.sort();
        out
    }

    /// The gossip hop, for real: a `PqTx` travels as one postcard struct, so what the second node
    /// re-admits is exactly what the first node's pool would hand the wire.
    /// ⛔⛔ DB-327 / DB-330 — THE POOL'S OWN DOOR REFUSES THE RETIRED STAKE FORMAT. Every admission path (the submit
    /// door, gossip, an evicted tx's re-admission) ends in `accept_inner`, so the refusal lives there once. RED before
    /// the fix: the stake-bearing tx was accepted. CONTROL: the same shape without stake bytes is accepted.
    #[test]
    fn db330_the_pool_refuses_a_stake_bearing_tx_and_accepts_a_plain_one() {
        let mut pool = Mempool::new();
        let need = pool.required_stamp_bits();
        let plain = mk(b"db330-mempool-plain", 10, vec![Hash32::hash(b"db330-nf-plain")], need);
        assert!(pool.accept(plain).is_ok(), "CONTROL: a plain tx is accepted");
        let mut staked = mk(b"db330-mempool-stake", 10, vec![Hash32::hash(b"db330-nf-stake")], need);
        staked.stake_notes = vec![0x5Eu8; 72];
        let got = pool.accept(staked);
        assert!(got.is_err(), "⛔ DB-327: the pool ACCEPTED a stake-bearing tx (cm ‖ amount ‖ future nullifier in clear)");
        assert!(
            format!("{}", got.unwrap_err()).to_lowercase().contains("stake"),
            "the refusal must NAME the retired stake format"
        );
        assert_eq!(pool.len(), 1, "a refusal adds no row");
    }

    fn over_the_wire(tx: &PqTx) -> PqTx {
        let bytes = postcard::to_allocvec(tx).expect("a pooled tx encodes for gossip");
        postcard::from_bytes::<PqTx>(&bytes).expect("the peer decodes it")
    }

    /// ⛔ PIN B-1 — WAS RED (the whole-struct swap), NOW THE CLOSED SHAPE, AND STRICTLY STRONGER.
    ///
    /// HISTORY, so the pin cannot be read as having always been easy: this test used to ADMIT the
    /// forgery and assert only that the pooled row kept the honest values — green under the first fix,
    /// which held the pooled struct and wrote `pow_stamp` through `get_mut`. That fix left the arm
    /// reading the ARRIVING struct for the conflict set, which is the defect the sibling pin below
    /// measures. So the assertion is now the one the arm's own contract always claimed: a re-stamp that
    /// moves ANY field but the stamp is REFUSED, and the pool is untouched.
    ///
    /// TWO POOLS, TWO NODES, because the swap survives the wire: a `PqTx` gossips as one postcard
    /// struct, so the peer that re-admits it takes the SAME arm on its OWN pool. Node A is the payer's
    /// node; node B is an honest peer that already held the real payment. The attacker is any peer that
    /// saw the gossip — it re-uses the victim's EXACT blob, so the content id and the ZK carrier verdict
    /// stay byte-identical and `accept_verified` re-verifies the same bytes vacuously.
    ///
    /// The mutation list is deliberately one field at a time, over every non-witness field a block will
    /// carry: each iteration is its own complete attack, so a partial fix that guards `output_notes` and
    /// forgets `bond_notes` fails here by name rather than passing on the strength of the field someone
    /// happened to think of.
    #[test]
    fn a_restamp_that_moves_any_field_but_the_stamp_is_refused_on_both_nodes() {
        let mut node_a_pool = Mempool::new();
        let mut node_b_pool = Mempool::new();
        let need = node_a_pool
            .required_stamp_bits()
            .max(node_b_pool.required_stamp_bits());
        const BLOB: &[u8] = b"the-one-and-only-carrier-blob";
        let honest_notes = vec![0x11u8; crate::cover::PQ_NOTE_BYTES];
        let honest_nf = Hash32::hash(b"nf-honest");
        let mut honest = mk(BLOB, 10, vec![honest_nf], need);
        honest.output_notes = honest_notes.clone();
        let honest_work = honest.stamp_work();
        let id = node_a_pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the payer's node pools the payment");
        node_b_pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the honest peer pools the SAME gossiped payment");

        // Ground ONCE at strictly higher work: `stamp_work` reads only `id` (= blake3 of the blob),
        // `pow_stamp` and the network id, so mutating any other field afterwards leaves the work
        // untouched. Every forgery below therefore clears the "must out-work the original" guard.
        let base_forged = mk(BLOB, 10, vec![honest_nf], honest_work + 1);
        assert!(
            base_forged.stamp_work() > honest_work,
            "PRECONDITION: the bump out-works the original, so the arm is reached"
        );

        let mutations: Vec<(&str, fn(&mut PqTx))> = vec![
            ("nullifiers", |t| {
                t.nullifiers = vec![Hash32::hash(b"nf-forged")]
            }),
            ("output_notes", |t| {
                t.output_notes = vec![0xEEu8; crate::cover::PQ_NOTE_BYTES]
            }),
            ("output_notes (appended)", |t| {
                t.output_notes
                    .extend_from_slice(&[0xEEu8; crate::cover::PQ_NOTE_BYTES])
            }),
            ("weight", |t| t.weight = 5_000),
            ("bond_notes", |t| t.bond_notes = vec![0xEEu8; 40]),
            ("stake_notes", |t| t.stake_notes = vec![0xEEu8; 32]),
            ("note_clues", |t| t.note_clues = vec![0xEEu8; 48]),
            ("membership_carrier", |t| {
                t.membership_carrier = vec![0xEEu8; 16]
            }),
            ("membership_leaf_commit", |t| {
                t.membership_leaf_commit = [0xEEu8; 32]
            }),
            ("membership_tip", |t| t.membership_tip = vec![0xEEu8; 96]),
            ("membership_folded_through", |t| {
                t.membership_folded_through = 99
            }),
            // DB-223: the spend input's member-path carrier and its tuple — first arrival keeps them, like every field.
            ("member_carrier", |t| t.member_carrier = vec![0xEEu8; 64]),
            ("member_tuple", |t| t.member_tuple = vec![0xEEu8; 128]),
        ];

        for (field, mutate) in mutations {
            let mut forged = base_forged.clone();
            forged.output_notes = honest_notes.clone();
            mutate(&mut forged);
            for (who, pool) in [("node A", &mut node_a_pool), ("node B", &mut node_b_pool)] {
                assert_eq!(
                    pool.accept_verified(over_the_wire(&forged), |b| b == BLOB)
                        .unwrap_err(),
                    MempoolError::AlreadyKnown,
                    "⛔ HOLE on {who}: a re-stamp that moved `{field}` was ADMITTED. The id covers \
                     the blob and nothing else, so this arm is the only thing standing between a \
                     relaying peer and the value the block will carry."
                );
                let pooled = pool.get(&id).expect("still exactly one row").clone();
                assert_eq!(
                    pooled.output_notes, honest_notes,
                    "⛔ HOLE on {who}: `{field}` forgery changed the pooled OUTPUT NOTES"
                );
                assert_eq!(
                    pooled.nullifiers,
                    vec![honest_nf],
                    "⛔ HOLE on {who}: `{field}` forgery changed the pooled NULLIFIERS"
                );
                assert_eq!(
                    pooled.weight, 10,
                    "⛔ HOLE on {who}: `{field}` forgery changed the pooled WEIGHT"
                );
                assert!(
                    pooled.bond_notes.is_empty()
                        && pooled.stake_notes.is_empty()
                        && pooled.account_targets.is_empty()
                        && pooled.note_clues.is_empty(),
                    "⛔ HOLE on {who}: `{field}` forgery injected carried bytes into a payment \
                     that carried none"
                );
                assert_eq!(
                    pooled.stamp_work(),
                    honest_work,
                    "⛔ HOLE on {who}: a REFUSED `{field}` forgery still moved the stamp — a \
                     half-applied bump, which is a write on a path that returned an error"
                );
                assert_eq!(
                    pool.total_weight(),
                    pooled.weight as u64,
                    "⛔ HOLE on {who}: the pool's capacity accounting no longer describes what it \
                     holds after a `{field}` forgery"
                );
                assert_eq!(pool.len(), 1, "a refusal must not add a row on {who}");
            }
        }
    }

    /// ⛔ PIN B-2 — WAS RED (the smuggled nullifier), AND IS NOW ALSO THE PIN FOR THE DEFECT THE FIRST
    /// FIX INTRODUCED: THE STRANDED CLAIM.
    ///
    /// §9.6 question 4: replay/conflict must be refused by a SET. The `spent` map IS that set. The arm
    /// originally returned before it was written (nothing registered — the smuggle). The first fix wrote
    /// it from the ARRIVING struct while keeping the POOLED id, which is worse in a different direction:
    /// the claim's owner is a tx that does not carry it, so
    ///   * `remove` frees claims by iterating the POOLED tx's `nullifiers` and can never name it, and
    ///   * `nullifier_claim_conflict` is owner-aware, so every honest spend of that note is refused
    ///     `DoubleSpend` for the life of the process.
    /// One bit of grind buys permanent censorship of any nullifier the attacker names, and an entry in
    /// `spent` that nothing bounds. This pins BOTH halves at once: no smuggle (the honest rival is still
    /// refused when the claim is real) and no strand (the audit is empty, the victim's note is still
    /// spendable, and `remove` leaves nothing behind).
    #[test]
    fn a_restamp_can_neither_smuggle_nor_strand_a_nullifier_claim_on_either_node() {
        let mut node_a_pool = Mempool::new();
        let mut node_b_pool = Mempool::new();
        let need = node_a_pool
            .required_stamp_bits()
            .max(node_b_pool.required_stamp_bits());
        const BLOB: &[u8] = b"restamp-nullifier-blob";
        let victim_nf = Hash32::hash(b"nf-the-attacker-wants-to-spend-twice");

        // CONTROL, on node A's pool — the ordinary insert path registers a nullifier, so a competing
        // spend is refused. This is the refusal that must still exist after the fix: the fix removes a
        // FORGED claim, never the real gate.
        let control = mk(b"control-blob", 10, vec![victim_nf], need);
        node_a_pool
            .accept(control)
            .expect("PRECONDITION: the control spend pools");
        let control_rival = mk(b"control-rival-blob", 10, vec![victim_nf], need);
        assert_eq!(
            node_a_pool.accept(control_rival).unwrap_err(),
            MempoolError::DoubleSpend,
            "PRECONDITION: the ordinary path DOES refuse a second spend of a pooled nullifier"
        );

        // THE ATTACK — the same nullifier arrives through the re-stamp arm instead, on node B (the
        // honest peer, which holds only the gossiped payment and nothing of node A's control).
        let honest_nf = Hash32::hash(b"nf-honest-2");
        let honest = mk(BLOB, 10, vec![honest_nf], need);
        let honest_work = honest.stamp_work();
        let honest_id = node_b_pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the honest peer pools the gossiped payment");
        let mut forged = mk(BLOB, 10, vec![victim_nf], honest_work + 1);
        forged.output_notes = vec![0xEEu8; crate::cover::PQ_NOTE_BYTES];
        assert_eq!(
            node_b_pool
                .accept_verified(over_the_wire(&forged), |b| b == BLOB)
                .unwrap_err(),
            MempoolError::AlreadyKnown,
            "⛔ HOLE: the re-stamp arm admitted a tx whose nullifier list is not the pooled one's"
        );

        // NO STRAND. The claim the attacker named must not exist at all — not as an unowned entry, and
        // not as an entry owned by a tx that does not carry it. This is the shape stated directly.
        assert_eq!(
            stranded_claims(&node_b_pool),
            Vec::<Hash32>::new(),
            "⛔ HOLE: the conflict set holds a claim whose owning tx does not carry it. Nothing can \
             free it — `remove` iterates the POOLED tx's nullifiers — so the owner-aware conflict \
             read refuses that note forever on this node."
        );
        assert_eq!(
            node_b_pool.spent_len(),
            1,
            "⛔ HOLE: the pool registered a claim beyond the one nullifier it actually holds"
        );

        // THE CENSORSHIP PRIMITIVE IS GONE: the victim's own spend of that note still pools, because
        // nothing ever claimed it. Under the stranded-claim defect this line is a `DoubleSpend`.
        let victim_spend = mk(b"the-victims-own-spend", 10, vec![victim_nf], need);
        node_b_pool
            .accept(victim_spend)
            .expect("⛔ HOLE: an attacker censored a note by naming it in a refused re-stamp");

        // AND NO RESIDUE: removing everything the pool holds empties the conflict set. A stranded entry
        // survives this, which is the unbounded-growth half of the same defect.
        let ids: Vec<Hash32> = vec![honest_id, PqTx::content_id(b"the-victims-own-spend")];
        node_b_pool.remove(&ids);
        assert!(node_b_pool.is_empty(), "PRECONDITION: both rows removed");
        assert_eq!(
            node_b_pool.spent_len(),
            0,
            "⛔ HOLE: a claim outlived every tx in the pool — `spent` grows per attack, bounded by \
             nothing"
        );
        assert_eq!(stranded_claims(&node_b_pool), Vec::<Hash32>::new());
    }

    /// ⛔ §9.5 SELF-CHECK — WHAT THIS LANE'S OWN FIX MADE POSSIBLE THAT WAS IMPOSSIBLE BEFORE.
    ///
    /// The fix adds a REFUSAL that did not exist: before it, every higher-work re-stamp of a known id
    /// was accepted. So for the first time an HONEST bump can be turned away — and a bump exists
    /// precisely because a payment starved behind higher-priority traffic is frozen funds with no owner
    /// action available. A gate that is even slightly stricter than "the same payment" converts the
    /// congestion escape hatch into a brick, and the failure is invisible: the sender is told
    /// `AlreadyKnown`, which reads as "already fine".
    ///
    /// The narrow way to get that wrong is the encoding, not the logic. The gate compares postcard
    /// bytes, and a `PqTx` reaches a peer's pool by exactly that path — with FIVE `serde(default)`
    /// fields an older peer's frame may not carry at all. If the digest were taken over the received
    /// FRAME, the same payment would hash differently on two nodes and the honest bump would be refused
    /// on one of them. It is taken over the DECODED struct re-encoded, so this round-trips both the
    /// original AND the bump through the wire on TWO pools — the shape that would catch it.
    ///
    /// The second thing the fix makes possible is a mid-arm return: refusals that now sit between the
    /// work check and the stamp write. A refusal that has already mutated something is a torn bump.
    /// Pinned here by comparing the WHOLE pooled envelope before and after a refused forgery.
    #[test]
    fn the_honest_congestion_bump_still_lands_after_a_full_gossip_round_trip() {
        let mut node_a_pool = Mempool::new();
        let mut node_b_pool = Mempool::new();
        let need = node_a_pool
            .required_stamp_bits()
            .max(node_b_pool.required_stamp_bits());
        const BLOB: &[u8] = b"a-genuinely-stuck-payment";
        let mut honest = mk(BLOB, 10, vec![Hash32::hash(b"nf-stuck")], need);
        honest.output_notes = vec![0x11u8; 2 * crate::cover::PQ_NOTE_BYTES]; // recipient + change
        honest.note_clues = vec![0x33u8; 48];
        honest.membership_carrier = vec![0x44u8; 128];
        honest.membership_tip = vec![0x55u8; 96];
        honest.membership_folded_through = 7;
        let honest_work = honest.stamp_work();

        // Both nodes hold the payment as it arrived over the wire — the realistic case, and the one
        // where a frame-sensitive digest would diverge.
        let id = node_a_pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the payer's node pools it");
        node_b_pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the peer pools the same gossiped payment");
        let envelope_before = Mempool::envelope_sans_stamp(node_b_pool.get(&id).unwrap());

        // A REFUSED forgery must leave the envelope bit-identical — no torn bump.
        let mut forged = mk(BLOB, 10, vec![Hash32::hash(b"nf-stuck")], honest_work + 1);
        forged.output_notes = honest.output_notes.clone();
        forged.account_targets = honest.account_targets.clone();
        forged.note_clues = honest.note_clues.clone();
        forged.membership_carrier = honest.membership_carrier.clone();
        forged.membership_tip = honest.membership_tip.clone();
        forged.membership_folded_through = 7;
        forged.bond_notes = vec![0xEEu8; 40]; // ← the ONE difference
        assert_eq!(
            node_b_pool
                .accept_verified(over_the_wire(&forged), |b| b == BLOB)
                .unwrap_err(),
            MempoolError::AlreadyKnown
        );
        assert_eq!(
            Mempool::envelope_sans_stamp(node_b_pool.get(&id).unwrap()),
            envelope_before,
            "⛔ NEW DEFECT: a REFUSED re-stamp mutated the pooled envelope — the arm now has \
             returns after the work check, so a refusal can leave a torn bump behind"
        );
        assert_eq!(
            node_b_pool.get(&id).unwrap().stamp_work(),
            honest_work,
            "⛔ NEW DEFECT: a refused re-stamp still moved the stamp"
        );

        // THE HONEST BUMP: same payment, only `pow_stamp` ground higher, through the wire on both nodes.
        let mut bump = honest.clone();
        let mut s = honest.pow_stamp + 1;
        loop {
            bump.pow_stamp = s;
            if bump.stamp_work() > honest_work {
                break;
            }
            s += 1;
        }
        let bumped_work = bump.stamp_work();
        for (who, pool) in [("node A", &mut node_a_pool), ("node B", &mut node_b_pool)] {
            assert_eq!(
                pool.accept_verified(over_the_wire(&bump), |b| b == BLOB)
                    .expect(
                        "⛔ NEW DEFECT: the envelope gate REFUSED an honest bump of the same \
                         payment. The congestion escape hatch is the only action the owner of a \
                         starved payment has, and this would brick it while reporting \
                         `AlreadyKnown` — a frozen payment that reads as an ordinary duplicate."
                    ),
                id,
                "the bump is the SAME payment on {who}"
            );
            assert_eq!(
                pool.get(&id).unwrap().stamp_work(),
                bumped_work,
                "the bump actually took on {who}"
            );
            assert_eq!(
                Mempool::envelope_sans_stamp(pool.get(&id).unwrap()),
                envelope_before,
                "and it moved NOTHING but the stamp on {who}"
            );
            assert_eq!(pool.len(), 1, "a bump replaces, never duplicates, on {who}");
            assert_eq!(
                stranded_claims(pool),
                Vec::<Hash32>::new(),
                "and an ACCEPTED bump strands no claim either, on {who}"
            );
        }
    }

    /// ⛔ PIN B-4 (RED = THE DEFECT *THIS ROUND'S FIX* INTRODUCED). Read the diff and ask what it makes
    /// possible that was impossible before.
    ///
    /// The refusal added to `accept_inner` prices its own cost in its own comment: "the arm is only
    /// reached by out-working the pooled stamp, which is the #72 client-PoW price, so this line is
    /// rate-limited by proof of work", and, above it, "the only way to make this node pay it is to grind
    /// STRICTLY more stamp work than the pooled tx". That is the price of ONE GRIND, not the price of
    /// ONE ARRIVAL. A refusal is a no-op on the pool BY DESIGN — nothing admitted, nothing replaced — so
    /// `pooled_work`, the bar the arriving stamp must beat, NEVER MOVES. The identical ground bytes
    /// therefore clear the cheap guard again on every replay: one grind buys unbounded arrivals, and
    /// this pin asserts the bar rises, which is the property the comment asserts and the code does not.
    ///
    /// WHAT EACH REPLAYED FRAME BUYS, none of which this path spent before the fix:
    ///   * TWO clones + TWO postcard encodes + TWO blake3 digests, UNDER THE NODE LOCK (`accept_inner`
    ///     is reached from `Node::admit_tx_shared`, which both admission doors hold the runtime mutex
    ///     for). The second encode is of the VICTIM'S POOLED STRUCT, whose bytes the attacker never
    ///     sent: a forgery needs only `blob` (the id is `blake3(blob)`) and may leave
    ///     `nullifier_witnesses`, `nullifier_absence`, `unspent_spends`, `membership_carrier`,
    ///     `membership_tip`, `note_clues` and `account_targets` EMPTY while the pooled payment carries
    ///     all of them. The lock-held work is asymmetric in the attacker's favour, and the pre-fix arm's
    ///     work here was O(1).
    ///   * ONE fixed line to stderr. That is bounded on disk — [`crate::log_cap`] rotates fd 2 at
    ///     `STDERR_CAP_BYTES` and keeps two generations — but bounded is not free: the bound is exactly
    ///     what makes this an ERASURE. `AlreadyKnown` is the one pool error `node_runtime.rs` discards
    ///     without a line, so nothing downstream governs the rate; a stranger with ONE grind can push
    ///     both generations past the cap and flush every real diagnostic line off this node's disk.
    ///     This project decides by MEASURED log lines; the fix hands a stranger the eraser.
    ///
    /// THE PREVIOUS CODE DID NOT HAVE THIS. In `.preRefut-20260908` the arm ADMITTED the first arrival
    /// and wrote `pooled.pow_stamp = tx.pow_stamp`, so the SECOND copy of the same bytes met
    /// `tx.stamp_work() <= pooled_work` at the cheap guard and cost nothing and printed nothing — the
    /// grind was CONSUMED, once, by construction. Refusing instead of admitting is right. Refusing while
    /// leaving the bar exactly where it was, and hanging per-arrival lock-held work and a per-arrival
    /// write behind it, is the hole the fix opened.
    ///
    /// PEER-PLAUSIBLE VALUES, NOT A MAGIC CONSTANT: the pooled tx is an ordinary two-note settling
    /// payment carrying the account target, locator clue and membership carrier the wallet really
    /// attaches, and the ONE difference the forgery carries is a locator clue in `note_clues` — the same
    /// `cm ‖ len ‖ clue` bytes `/submit` itself accepts and gossip already relays in clear, i.e. a value
    /// the HONEST path produces. The replay count is not tuned: EVERY arrival re-enters the arm, and the
    /// pin fails at the FIRST one.
    #[test]
    fn a_refused_restamp_costs_the_attacker_one_grind_and_this_node_one_arrival() {
        let mut pool = Mempool::new();
        let need = pool.required_stamp_bits();
        const BLOB: &[u8] = b"an-ordinary-settling-payment-carrier-blob";
        let mut honest = mk(BLOB, 2_306, vec![Hash32::hash(b"nf-settling")], need);
        honest.output_notes = vec![0x11u8; 2 * crate::cover::PQ_NOTE_BYTES]; // recipient + change
        honest.note_clues = vec![0x33u8; 48];
        honest.membership_carrier = vec![0x44u8; 2048];
        honest.membership_tip = vec![0x55u8; 96];
        let honest_work = honest.stamp_work();
        let id = pool
            .accept_verified(over_the_wire(&honest), |b| b == BLOB)
            .expect("PRECONDITION: the node pools an ordinary payment");
        let pooled_before = pool.get(&id).expect("pooled").clone();

        // ONE GRIND, paid once. The forgery must carry the victim's blob (or the id differs and it never
        // reaches this arm) and carries NOTHING else — every witness field left empty. That is the
        // asymmetry: the node re-encodes the victim's full struct on every arrival while the attacker
        // sends only this.
        let mut forged = honest.clone();
        forged.note_clues = vec![0x33u8; 96]; // ← THE ONE DIFFERENCE: one more locator clue
        // Every witness field the attacker need not pay for is dropped; only `blob` is mandatory,
        // because the id is `blake3(blob)`. This is the asymmetry the arm now spends per arrival.
        forged.membership_carrier = Vec::new();
        forged.membership_tip = Vec::new();
        forged.nullifier_witnesses = Vec::new();
        forged.nullifier_absence = Vec::new();
        let mut s = honest.pow_stamp + 1;
        loop {
            forged.pow_stamp = s;
            if forged.stamp_work() > honest_work {
                break;
            }
            s += 1;
        }
        let forged_work = forged.stamp_work();
        assert!(
            forged_work > honest_work,
            "PRECONDITION: the bump out-works the pooled stamp, so the arm is reached at all"
        );
        let wire = postcard::to_allocvec(&forged).expect("the attacker sends these bytes ONCE");
        let pooled_wire = postcard::to_allocvec(&pooled_before).expect("the victim's pooled bytes");
        assert!(
            pooled_wire.len() > wire.len(),
            "PRECONDITION: the struct this node re-encodes per arrival ({} bytes) is larger than the \
             frame the attacker sends ({} bytes) — the asymmetry is real, not nominal",
            pooled_wire.len(),
            wire.len()
        );

        const REPLAYS: usize = 64;
        // ⭐⭐⭐ MEASURE THE DEFECT ITSELF, NOT A PROXY FOR IT. This pin first asserted that the POOLED
        // tx's `stamp_work` had risen. That proxy was WRONG twice over, and both ways were measured:
        // raising the pooled stamp on a refusal is a half-applied bump on an error path
        // (`a_restamp_that_moves_any_field_but_the_stamp_is_refused_on_both_nodes` refuses it), and a
        // node-local WORK bar instead hands a stranger a censorship lever over the owner's own
        // congestion bump (`the_honest_congestion_bump_still_lands_after_a_full_gossip_round_trip`
        // refuses that). Both are right.
        //
        // What this pin's own prose is actually about is the ASYMMETRY — "the second encode is of the
        // VICTIM'S POOLED STRUCT, whose bytes the attacker never sent". So count exactly that, and
        // demand ZERO of it across every replay. That is a strictly stronger statement than the proxy
        // made, and it needs no gate on either party.
        POOLED_REENCODES.with(|c| c.set(0));
        for arrival in 1..=REPLAYS {
            assert_eq!(
                pool.accept_verified(
                    postcard::from_bytes::<PqTx>(&wire).expect("the peer decodes it"),
                    |b| b == BLOB
                )
                .unwrap_err(),
                MempoolError::AlreadyKnown,
                "arrival {arrival}: the verdict itself is correct and must stay correct"
            );
            // The refusal is RIGHT — the pool is bit-for-bit unchanged. It is its PRICE that is wrong.
            assert_eq!(
                Mempool::envelope_sans_stamp(pool.get(&id).unwrap()),
                Mempool::envelope_sans_stamp(&pooled_before),
                "arrival {arrival}: a refusal must leave the pooled envelope untouched"
            );
            assert_eq!(pool.len(), 1, "arrival {arrival}: a refusal must not add a row");
            // ⛔ AND THE STAMP IS PART OF "UNTOUCHED". A refusal is a no-op on the pool, full stop —
            // the two sibling pins named above assert the same thing from the other direction.
            assert_eq!(
                pool.get(&id).unwrap().pow_stamp,
                pooled_before.pow_stamp,
                "arrival {arrival}: a refusal must not move the pooled stamp either"
            );
            let paid = POOLED_REENCODES.with(std::cell::Cell::get);
            assert_eq!(
                paid, 0,
                "⛔ HOLE at arrival {arrival} of {REPLAYS}: this node has re-encoded the VICTIM'S pooled \
                 struct {paid} time(s) for frames the attacker ground ONCE. Each is {} bytes of \
                 lock-held work for {} attacker bytes, plus one line toward the {}-byte `log_cap` \
                 rotation that will flush this node's real diagnostics off disk. Cost per arrival must \
                 be bounded by what the arrival changed, and it changed nothing.",
                pooled_wire.len(),
                wire.len(),
                crate::log_cap::STDERR_CAP_BYTES
            );
        }
        // ⛔ NON-VACUITY: a counter that never moves would pass the loop above for the wrong reason.
        // An honest bump DOES write the pooled tx, so it MUST refresh the cached digest — and that is
        // the one legitimate pooled re-encode. If this stays at zero the counter is dead and the loop
        // proved nothing.
        let mut honest_bump = pooled_before.clone();
        let mut s2 = forged.pow_stamp + 1;
        loop {
            honest_bump.pow_stamp = s2;
            if honest_bump.stamp_work() > forged_work {
                break;
            }
            s2 += 1;
        }
        // ⭐ AND THE OWNER'S ESCAPE HATCH STILL WORKS AFTER 64 REFUSALS. A stranger's grinds must not
        // price the payment's owner out of bumping their own starved tx — the censorship lever the
        // node-local work bar would have handed over.
        assert_eq!(
            pool.accept_verified(honest_bump, |b| b == BLOB).expect("the owner can still bump"),
            id,
            "the owner's congestion bump must still land after a flood of refused re-stamps"
        );
        assert_eq!(
            POOLED_REENCODES.with(std::cell::Cell::get),
            1,
            "⛔ the counter must move on a real pooled write, or the zero above proves nothing"
        );
        eprintln!(
            "[pool-restamp] {REPLAYS} replays of one ground frame cost ZERO re-encodes of the victim's \
             struct; the owner's own bump still landed and cost exactly one"
        );
    }
}
