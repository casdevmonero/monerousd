// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Instant-sync (brick 7): #29 DSYNC + #106 frontier — a joining / behind node jumps to tip in ONE
//! verify, never block-crawls.
//!
//! A behind node requests a [`SyncBundle`] from any peer (DSYNCREQ), then [`adopt_sync_bundle`]:
//!   1. VERIFIES the ≤1.8MB [`crate::decider::DeciderBundle`] via [`crate::decider::accept_bundle`]
//!      (the no-blowup size gate THEN the whole-chain block decider — arity-2 folded, the last FRI
//!      holdout being retired onto the light decider) — never adopt an unverified tip;
//!   2. checks the decider's O(1) chain accumulator BINDS the persisted PQ-frontier snapshot it is
//!      about to install (a forged / swapped frontier breaks the binding and is rejected);
//!   3. installs tip + blue-score + frontier in O(1) and jumps. The node now holds the tips, so it is
//!      a FIRST-CLASS PRODUCER immediately (it builds the next block from the frontier it just
//!      adopted; it never refetches parent blocks). #106 frontier-persist means a restart re-adopts
//!      the same snapshot O(1) instead of replaying history.
//!
//! There is NO block-by-block download / "SYNCHRONIZATION" path here by construction — the only sync
//! is verify-once-and-jump. Every failure is fail-closed (the node stays on its current state); a bad
//! bundle never halts it (it just asks another peer).

use crate::block::BlockId;
use crate::decider::{accept_bundle, ConsensusVerifier, DeciderBundle};
use crate::hash::Hash32;
use serde::{Deserialize, Serialize};

/// The persisted PQ-frontier snapshot (#106): the O(1) note-frontier root + the height it is at. This
/// is ALL a node needs to become a producer — it is constant-size regardless of chain history.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FrontierSnapshot {
    /// blake3 commitment to the sparse depth-32 note-membership frontier (the spendable-note set root).
    pub root: [u8; 32],
    /// The blue-score height this frontier is valid at (matches the decider tip's blue-score).
    pub height: u64,
    /// ⭐⭐⭐ THE O(32) PEAK SPINE — WHAT MAKES AN ADOPTED FRONTIER EXTENSIBLE INSTEAD OF FROZEN.
    ///
    /// A root alone tells a joining node WHERE the tree is, not HOW to continue it. Adopting only the root
    /// left `spend_frontier` holding its own (empty or short) peaks, so every leaf appended afterwards folded
    /// against the wrong left siblings and the node's spend root silently diverged from the tip it had just
    /// certified. Since `served_seq = note_frontier_count() / 256`, that divergence surfaces as the "record
    /// gap": MEASURED tonight, node A at 198,426 blocks with 168,934 folded and node B at 198,424 with
    /// 150,212 — three different answers to "what is the note root", and a copath from one that can never
    /// verify on another.
    ///
    /// Four hypotheses for that gap were refuted by measurement first (duplicate re-delivery: 0 hits;
    /// sub-record ids: still 0 served; producer drop: fixed, gap unchanged; a hole at the accept path: the
    /// `[ledger-hole]` probe fired 0 times on both nodes). What remained is structural: an O(1)-syncing node
    /// LEAPS the blue score without the blocks between, so it can never re-derive those peaks from history —
    /// the bundle must carry them.
    ///
    /// AND IT COSTS NOTHING: the spine is `8 + (SPEND_TREE_DEPTH+1)*32` = 1,064 bytes, FIXED. Measured at
    /// four chain sizes — 10 / 1,000 / 100,000 / 1,000,000 leaves — all 33 slots, all 1,064 bytes, identical.
    /// So instant sync stays O(1) in chain length while the adopted frontier becomes exactly extensible.
    ///
    /// `serde(default)` so an older bundle still deserializes: an empty spine means "root only", the previous
    /// behaviour, rather than a hard rejection that would island peers mid-upgrade.
    #[serde(default)]
    pub peaks_hex: String,
}

/// The O(1) nullifier-accumulator snapshot a #29 DSYNC bundle carries so a joining node INHERITS the certified
/// spent-state (Gap2) — the double-spend twin of [`FrontierSnapshot`]. Just the indexed-Merkle `root` (32-byte limb
/// encoding) + leaf `count`: TRUE constant size at any spend count (no set). It is BOUND into [`sync_binding`] (tied
/// to the decider-certified tip + genesis), so a peer serving a valid tip proof CANNOT lie about the spent-state — a
/// swapped root/count breaks the binding and the bundle is rejected.
///
/// ⛔⛔ THE COMMENT HERE USED TO SAY the node installs this via `NullifierTree::adopt`. **IT DOES NOT, AND
/// IT HAS NOT SINCE THE IMT WAS RETIRED AS THE SECOND AUTHORITY.** `nullifier_tree` has ZERO production
/// callers (seam census §AN, confirmed by the removal probe: the crate compiles without the module).
/// What `adopt_sync_bundle` ACTUALLY installs is `count` — into `nf_blocks`, `nf_leaves` and `nf_fold_seq`
/// — while the double-spend gate a jumped node inherits comes from [`SyncState::sparse_root`] via
/// `Node::adopt_sparse_snapshot`. The `root` here is carried and BOUND (so it cannot be forged) but not
/// installed anywhere.
/// ⭐ A DOC THAT NAMES A MECHANISM THE CODE DOES NOT RUN IS THE DEFECT THIS TREE KEEPS PAYING FOR: §AJ's
/// *"literally what step i-1 hands step i"* over a mintable fixture, and §AI's *"byte-identical"* over two
/// different spent-leaf constants. Both read as guarantees. Both were false.
/// ([[project_trustless_nullifier_o1_design]] [[feedback_always_trustless]] [[feedback_no_growth_any_axis]])
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
/// ⛔⛔⛔ THIS STRUCT IS **POSTCARD**-ENCODED (`postcard::to_allocvec`, below). POSTCARD IS POSITIONAL.
///
/// Fields are written and read BY ORDER, with no names on the wire. That has one consequence the
/// `#[serde(default)]` attributes below do NOT change, and which several comments here get wrong:
///
///   **`#[serde(default)]` does not make it safe to add, remove or reorder a field.** `default` only
///   fills a field the decoder KNOWS is absent, which requires a self-describing format. Postcard has no
///   such notion: it reads the next field's bytes from wherever the cursor happens to be. Append a field
///   and an older bundle runs out of bytes; remove one from the middle and every later field decodes from
///   the wrong offset — silently, as plausible garbage, not as an error.
///
/// MEASURED 2026-08-14, on the live origin node, from exactly this mistake made on the sibling
/// `persist::NodeSnapshot`: one field removed from the middle, `load()` returned nothing, the node booted
/// FROM GENESIS on a chain past height 22,239, and its first save overwrote the tall checkpoint. 22,019
/// blocks, unrecoverable on that node. It presented as SUCCESS — the snapshot shrank 51,692 B -> 17,436 B,
/// which was the exact number the work was chasing.
///
/// So the claims below that `serde(default)` "keeps pre-closure bundles decodable" and "keeps older
/// bundles decodable" are FALSE for this encoding. They describe an intent, not a behaviour. Any layout
/// change to this struct must be versioned by the bundle that carries it, the same way
/// `persist::SNAPSHOT_SCHEMA` versions the other one — so an incompatible bundle is REFUSED loudly rather
/// than read as garbage. A refusal costs a resync; a misparse costs the chain.
pub struct NullifierSnapshot {
    /// The nullifier IMT root (32-byte little-endian limb encoding, `spend_frontier::leaf_to_cm_bytes`).
    pub root: [u8; 32],
    /// Occupied-leaf count of the accumulator (includes the initial `(0,0)` low leaf).
    pub count: u64,
    /// CONFIDENTIAL real-spend-blob accumulator (Ask 2 idle-privacy closure) so an O(1)-jumped joiner reproduces the
    /// per-block decoy stream in lockstep. NOT consensus-critical (the acc converges via the block carriers' adopt
    /// regardless); carried mesh-only (never RPC-served), so an RPC-observer still can't recompute idle-block decoys.
    /// `serde(default)` keeps pre-closure bundles decodable (they resume from the genesis accumulator seed).
    #[serde(default)]
    pub nf_cover_conf_acc: [u8; 32],
    /// SPARSE CUTOVER — the CERTIFIED sparse nullifier-acc root (count-free), so a #29-jumped node adopts the sparse
    /// spent-state in O(1) (`Node::adopt_sparse_snapshot`) instead of rebuilding it from the stream. Bound into
    /// `sync_binding` (tied to the decider-certified tip), so a peer cannot forge it.
    /// ⛔⛔ THE BINDING IS THE ONLY THING PROTECTING THIS FIELD. The comment here used to add *"a wrong
    /// value would ALSO be self-healed by the co-rebuild on the joiner's next `rebuild_nullifier_tree`"* —
    /// **a defence-in-depth that does not exist**: `rebuild_nullifier_tree` has no production caller (seam
    /// census §AN), so nothing re-derives this root after a jump. A claimed second layer is worse than no
    /// second layer, because it is what a reviewer weighs when deciding how hard the first one must hold.
    /// `serde(default)` keeps older
    /// (IMT-only) bundles decodable — a zero root just means "rebuild sparse from the stream" (no O(1) fast-path).
    #[serde(default)]
    pub sparse_root: [u8; 32],
    /// ⭐⭐ DB-353 P5 (§11.13 C4, §13.3 C-2) — THE FOLD-POINT NULLIFIER BAND at the server's band pointer
    /// (2^NF_BAND_BITS entries), the fold ordinal it waits at, and every awaiting step pointer..tip with its ADMITTED set
    /// (`None` = unknown at the server). A joiner installs them through `BandDoor::adopt_certified`, so it verifies relayed
    /// band steps from minute 0 instead of waiting on steps it never folded (§13.3 C-2: without the sets, every joiner and
    /// every restart through a bundle was STALE with no exit). Bound into `sync_binding` exactly as `sparse_root` is —
    /// the decider proves neither (the D01/Q2 residual, unchanged and stated).
    /// O1-FOOTPRINT-REVIEWED: 8 KB of band plus ≤ the door's lag cap × the 256-slot lane × 32 B (P7 holds the lag near
    /// SPINE_RING_LEN / 2, ≈ 256 KB), whatever the height. `serde(default)`: an older bundle carries none, and its joiner
    /// keeps its own band (it waits for a certified one; never a guess).
    #[serde(default)]
    pub band: Vec<crate::spend_frontier::Digest4>,
    #[serde(default)]
    pub band_next_ordinal: u64,
    #[serde(default)]
    pub band_awaiting: Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)>,
    /// ⭐⭐⭐ THE DSOL TOKEN REGISTRY, CARRIED — count and peaks, its entire state.
    ///
    /// ⛔ A JUMPED NODE CANNOT REBUILD IT. Creations are chain objects in past blocks, and a #29 jump
    /// does not replay history, so a joiner that adopts everything else still comes up with an EMPTY
    /// registry — and the mint gate then refuses every honest mint on it, forever. Fail-closed, so nothing
    /// unregistered is admitted, but the node never participates in the asset layer again.
    ///
    /// ⛔ BOUND INTO `sync_binding` below, exactly like `sparse_root`, so a peer cannot hand a joiner a
    /// registry of its own choosing. Without that binding a relay could make a joiner believe any asset
    /// exists, which is the whole point of the gate.
    /// O1-FOOTPRINT-REVIEWED: bounded by crate::dsol::MMR_MAX_PEAKS — one peak per set bit of a u128
    /// count. `serde(default)` keeps pre-registry bundles decodable (they resume empty, which is correct).
    #[serde(default)]
    pub dsol_registry_peaks: Vec<(u32, [u8; 32])>,
    /// The registry's append count, beside the peaks it must describe.
    #[serde(default)]
    pub dsol_registry_count: u128,
    /// ⭐ NF-UNSPENT CHAIN ACC (A_tip) — the running `NfUnspentFold` acc over each block's `(block_pre, tags_digest)`,
    /// the O(1) endpoint a wallet's `prove_nf_absence_chain` binds to. A #29-jumped joiner CANNOT recompute it (that
    /// needs full history, O(N) — banned), so it is carried here and adopted VERBATIM, exactly like `sparse_root`.
    /// ⚠️ MUST be bound into `sync_binding` (node-decider's consensus domain) so a peer cannot forge it — until then a
    /// wrong value would ISLAND the joiner (tip agrees, A_tip stuck). `serde(default)` keeps older bundles decodable
    /// (a zero acc = the genesis seed = "no blocks folded yet"). ([[feedback_infinite_o1_fold_cardinal]])
    #[serde(default)]
    pub nf_unspent_acc: crate::spend_frontier::Digest4,
    /// ⭐ THE CERTIFIED UNSPENT-NOTE ROOT (deletion model) — the tree of present notes. A joiner CANNOT
    /// recompute it (that needs the receive/deletion stream it skipped), so it is carried and adopted
    /// verbatim, exactly like `nf_unspent_acc`. Adopting a root this node did not fold marks its catch-up
    /// map NOT_READY, which is what hands the ledger-replay self-heal its target. Bound into
    /// `sync_binding` (unforgeable). `serde(default)` keeps older bundles decodable (zero = genesis).
    /// ⭐ THE CERTIFIED NOTE-MEMBERSHIP FOLD, so a cold wallet folds only FORWARD.
    ///
    /// A `NoteMembershipCarrier` is O(1) PER STEP but a wallet joining at height N still has to step N block
    /// roots from the chain's start — 5.6ms each, so ~32s at 5,668 blocks and worse forever after. That is the
    /// whole cold-restore problem restated one level up. The fix is the same one #29 DSYNC already uses for
    /// consensus: the joiner ADOPTS a certified point and folds from there, so the walk is bounded by how far
    /// behind it is, not by how old the chain is.
    ///
    /// `(prev, root, acc)` is the tip transition; the acc is the start a carrier may be built from. Bound into
    /// `sync_binding`, so a peer cannot hand a joiner a forged start in which its own block root was already
    /// folded. `serde(default)` keeps older bundles decodable — a zero value means "start from genesis".
    /// O1-INFINITY-REVIEWED: three FIXED 4-limb accumulators, a compile-time constant size at 0 blocks or
    /// 10^18. Adopted verbatim, never rebuilt, never count-bounded.
    #[serde(default)]
    pub membership_tip: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    /// ⭐ THE BONDED VALIDATOR SET — the finality quorum, carried so a #29-jumped joiner can WEIGH the
    /// mesh's finality votes the instant it reaches tip. A joiner CANNOT recompute it (the admitting
    /// bond blocks are history it skipped, and the ladder prunes their per-ordinal rows), so it is
    /// carried and adopted verbatim, exactly like `nf_unspent_acc` — same island class: before this,
    /// a DSYNC joiner held `validators=0` forever, rejected every vote at `bond_of(voter)==0`, and
    /// reported `finalized_height=0` while fully converged (MEASURED live 2026-08-22). Bound into
    /// `sync_binding` (unforgeable — a peer cannot hand a joiner a stuffed or emptied quorum under a
    /// valid tip proof). Deterministically sorted (`ValidatorSet::export_state`). Bounded by the
    /// CURRENT validator set — never a history term. `serde(default)` keeps older bundles decodable.
    #[serde(default)]
    pub bonded_validators: Vec<([u8; 32], u128)>,
    /// ⭐ SATOSHI §6 — the FINALITY seats (USDm bonds, free membership seats): certified beside the custody set.
    #[serde(default)]
    pub finality_validators: Vec<([u8; 32], u128)>,
    /// ⭐ G2b (lane a 2026-10-22) — THE VIEW AT A HEIGHT (`ValidatorSet::seat_activations`): the height each seat kind
    /// activates for finality and the departed rows within retention `(id, weight, active_from, active_until)`. Without them
    /// a resumed / jumped node judged every seat active from 0 and read a different quorum than a node that watched the
    /// seat land. `serde(default)`: a pre-G2b carrier leaves every seat active from 0, as it was judged before.
    #[serde(default)]
    pub custody_seat_active_from: Vec<([u8; 32], u64)>,
    #[serde(default)]
    pub finality_seat_active_from: Vec<([u8; 32], u64)>,
    #[serde(default)]
    pub departed_custody_seats: Vec<([u8; 32], u128, u64, u64)>,
    #[serde(default)]
    pub departed_finality_seats: Vec<([u8; 32], u128, u64, u64)>,
    /// ⭐ §BR-3 17.3 — the SAT delegated to each custody seat (inside `bonded_validators`' weights), certified beside the
    /// seats so a jumped node keeps each seat's OWN locked weight apart from its delegations. Pre-sorted
    /// (`ValidatorSet::delegations`); bound into `sync_binding`.
    #[serde(default)]
    pub seat_words: Vec<crate::validator::SeatWords>,
    /// Permanently slashed ids — carried with the set so a jumped node also refuses a barred
    /// validator's re-admission (the bar is part of the quorum's meaning). Bound into `sync_binding`.
    #[serde(default)]
    pub slashed_validators: Vec<[u8; 32]>,
    /// Total bond burned by slashing (observability, travels with the set). Bound into `sync_binding`.
    #[serde(default)]
    pub slashed_bond_burned: u128,
    /// The #75 confidential bonded-stake accumulator digest. Bound into `sync_binding`.
    #[serde(default)]
    pub validator_bond_commit: crate::spend_frontier::Digest4,
    /// Per-validator bridge-custody points, so the adopter derives the SAME reserve key-aggregate as
    /// the mesh (fail-closed otherwise: no custody, no reserve address). Bound into `sync_binding`.
    #[serde(default)]
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    /// Per-bonded-custodian ML-KEM encapsulation keys (from each member's SIGNED seat header), so a jumped
    /// node can SEAL a peg-in delta to the quorum and run `/peg_in_execute` at all (`crate::peg_attest`).
    /// Bound into `sync_binding` like the custody points (a relay must not swap in its own ek and read
    /// deltas meant for a custodian). Bounded by the current custodian set — never a history term.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (one per bonded custodian)
    #[serde(default)]
    pub validator_kem_eks: Vec<([u8; 32], Vec<u8>)>,
    /// ⭐ SAFE AT SCALE — each bonded custodian's custody SEAT (`ValidatorSet::custody_seats`, sorted by id), certified
    /// beside the seats: a jumped node reads its custody vaults from these, so it sits every custodian in the vault a
    /// node that followed the chain does. Bound into `sync_binding` (a relay that moved a seat would move a custodian to
    /// another vault's quorum). Bounded by the current custodian set — never a history term.
    #[serde(default)]
    pub custody_seat_numbers: Vec<([u8; 32], u64)>,
    /// ⭐ THE PEG LEDGER'S CERTIFIED VIEW (§DD, 2026-09-17). A joiner that JUMPS never replays the peg
    /// transactions it skipped, so before this the reserve/minted commitments it held after a jump were its
    /// own stale (or genesis) values: a jumped custodian could neither attest nor execute against the
    /// chain's real reserve, and an executor's published mint rode a chain it then left (DB-5). Bound
    /// into `sync_binding`, so a bundle cannot hand a joiner a forged reserve. Fixed width: three digests
    /// and three parameters. The one-time-use id sets (`spent_burns`, deposit ids, `released`,
    /// `liquidated`) are NOT here — kill list §DD names the nullifier accumulator they must move into.
    pub peg_reserve_commit: crate::spend_frontier::Digest4,
    pub peg_minted_commit: crate::spend_frontier::Digest4,
    pub peg_reserve_hwm_commit: crate::spend_frontier::Digest4,
    /// §DD-b (2026-09-18): the (one-time id, kind) pairs of the peg transitions the certified chain applied
    /// most recently — deposits minted, burns, releases, liquidations — so a JOINER inherits the replay
    /// guard for them instead of an empty RAM-only set (the jumped-majority double-mint edge). Bound into
    /// `sync_binding`. O1-FOOTPRINT-REVIEWED: bounded by APPLIED_ONE_TIME_ID_RING_MAX
    pub applied_one_time_ids: Vec<([u8; 32], u8)>,
    pub peg_ratio_bps: u32,
    pub peg_redeem_floor_bps: u32,
    pub peg_yield_rate_bps: u32,
    /// ⭐⭐ DB-251 — THE CHAIN'S PRICE MARKS, (asset id, price, epoch), one per priced asset. A #29-jumped joiner
    /// never applies the `Class::PriceMark` objects it skipped, so without this it stood on its OWN marks (none
    /// when fresh) while every other node stood on the chain's. Under DB-124 a jumped validator then refused
    /// every mint until the next epoch's mark (≤ 1,200 blocks). Bound into `sync_binding` like the reserve beside
    /// it, so a bundle cannot hand a joiner a forged price. O1-FOOTPRINT-REVIEWED: bounded by the registered-asset
    /// set, like `wrapped_assets` — no term in height.
    #[serde(default)]
    pub peg_price_marks: Vec<(u32, u128, u64)>,
    /// ⭐ DB-259 — THE CHAIN'S BOND LOCKS, sorted by validator id: each bonded validator's maturity anchor
    /// (`bond_height`) and its locked collateral note (`bond_locked`). The bundle used to carry each validator's
    /// WEIGHT and nothing of its LOCK. A jumper then read a missing anchor as "legacy, matured", released an
    /// immature unbond that every other node refuses, and could not justify the returned note DB-257 carries.
    /// Validator weight and the unbond block's record then diverged between honest nodes.
    #[serde(default)]
    pub bond_heights: Vec<([u8; 32], u64)>,
    #[serde(default)]
    pub bond_locked_notes: Vec<([u8; 32], Vec<u8>)>,
    /// ⭐ DB-274 P2 (§8.7) — THE CHAIN'S UNBONDING COLLATERAL, sorted by validator id: each collateral bonding whose
    /// weight left at its unbond's fold and whose note waits out the evidence window (`Node::unbond_window`). Chain
    /// state like `bond_locked_notes`: a jumper without it would never release the note (the owner's collateral
    /// frozen on that node while every peer returns it) and could not burn it when late evidence folds. Bound into
    /// `sync_binding` beside the locks. O1-FOOTPRINT-REVIEWED: at most one entry per validator that held a collateral
    /// bond — bounded by the bonded set, never by height.
    #[serde(default)]
    pub unbonding: Vec<([u8; 32], crate::node::Unbonding)>,
    /// ⭐ DB-271 — THE CHAIN'S WRAPPED-ASSET REGISTRY, sorted by asset id: (asset, reserve commit, minted commit,
    /// ratio bps, reserve high-water-mark commit). The bundle carried six peg values (§DD) and the price marks
    /// (DB-251) and nothing of the per-asset registry, so a jumper refused every wrapped mint the chain applies
    /// and its per-asset PSM state diverged. O1-FOOTPRINT-REVIEWED: bounded by the registered-asset set.
    #[serde(default)]
    pub peg_wrapped_assets: Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, u32, crate::spend_frontier::Digest4)>,
    /// ⭐ LIQUIDATION §10 — every PSM's stability-pool words `(asset, T, P, S, epoch)`, sorted by asset. Bound into the
    /// sync binding like the wrapped registry. O1-FOOTPRINT-REVIEWED: bounded by the registered PSM set.
    #[serde(default)]
    pub peg_pools: Vec<(u32, crate::peg::PoolWords)>,
    /// ⭐ IONSWAP POOLS — the three chain-derived values a DSYNC joiner never held (A-F50, found by the bundle-coverage
    /// census 2026-11-12: every node that watched the chain holds the real pool book; a joiner without these refuses every
    /// settlement its peers apply). Bound into `sync_binding`. O1-FOOTPRINT-REVIEWED: `ion_pending` bounded by
    /// `ION_PENDING_MAX` (a constant); the scalars are fixed width.
    #[serde(default)]
    pub peg_ion_pending: Vec<crate::ion_pool_tx::IonPending>,
    #[serde(default)]
    pub peg_ion_usdm_held: u64,
    #[serde(default)]
    pub peg_ion_pools: u64,
    /// ⭐ THE LETTER ACCUMULATOR — the consensus anchor of the Letter DA content stream (the running fold of
    /// every block's carried `letter_set` in canonical order). A #29-jumped joiner CANNOT recompute it (that
    /// needs the history it skipped), so it is carried and adopted VERBATIM, exactly like `nf_unspent_acc` —
    /// same island class. Bound into `sync_binding` (unforgeable: a peer cannot hand a joiner a forged letter
    /// anchor under a valid tip proof). The serde default IS the genesis seed, so an older bundle with no
    /// letter field decodes straight to the correct start value — no read-side sentinel anywhere.
    #[serde(default = "letter_acc_seed")]
    pub letter_acc: [u8; 32],
    /// The CERTIFIED directory accumulator (apply-order fold over every @username/group/profile sign-up) —
    /// the registry endpoint a jumped joiner refills to through the verified door. A pre-directory bundle
    /// decodes to the genesis seed (refill disarmed — nothing certified to chase).
    #[serde(default = "dir_acc_seed")]
    pub dir_acc: [u8; 32],
    /// ⭐ DB-357 part 1 — three chain-derived values a DSYNC joiner never held (the sync census listed them), each
    /// constant-size and bound into `sync_binding` exactly as §DD / DB-251 / DB-259 / DB-271 are:
    /// the retention endowment's commitment (one opaque digest; discloses no amount), …
    #[serde(default)]
    pub peg_retention_endowment_commit: crate::spend_frontier::Digest4,
    /// … the L2 settlement root (32 B), …
    #[serde(default)]
    pub l2_state_root: [u8; 32],
    /// … and the ROOT-HISTORY anchor spine (`PoseidonSpendFrontier::peaks_hex`: count ‖ O(DEPTH) peaks, 2,088 B —
    /// height-invariant). A joiner that restores it holds the same `root_history_root()` a watching node folds
    /// into every validity verify; the adopt door refuses a spine that does not parse.
    #[serde(default)]
    pub root_history_peaks_hex: String,
    /// ⭐ SATOSHI — the chain's issued SAT total and pendulum snapshot `(epoch + 1, bonders' share bps)`, the words of
    /// `PegLedger::sat_census`. A jumper never folded the rewards or the epoch boundary it skipped: without them it held 0
    /// issued (crediting rewards past the cap the chain reached) and no snapshot (custody yield at a rate no peer pays).
    /// Bound into `sync_binding` like the reserve. Fixed width: 8 + 8 + 4 bytes, no term in height.
    #[serde(default)]
    pub peg_sat_issued: u64,
    #[serde(default)]
    pub peg_pendulum: (u64, u32),
    /// ⭐ §BR — the §BR ledger words (`peg::PegBrWords`), bound into `sync_binding` by their digest.
    #[serde(default)]
    pub peg_br: crate::peg::PegBrWords,
    /// ⭐ G2g-r2a — the serving node's QUANTIZED nullifier fold base `(base_acc, base_seq, base_prev, boundary)`: the base
    /// its spend gate admits carriers at, the base before it, and the window cut both stand on. A DSYNC joiner that set its
    /// base to the adopt-instant A_tip refused every crawler's carrier for up to two quanta (MEASURED f3-tail-small-4.log:
    /// n0/n1 at seq 0 vs the adopted n2 at 1358). The joiner holds it PENDING and switches only when the span members it
    /// pages from `boundary` reproduce A_tip from `base_acc` — never on the bundle's word. Bound into `sync_binding`; 144 B.
    #[serde(default)]
    pub nf_fold_base_words: (crate::spend_frontier::Digest4, u64, crate::spend_frontier::Digest4, u64),
    /// ⭐ G2g-r2a step 2 — the serving node's FOLD-SPAN MEMBERS `(id, blue_work, blue_score)`, ascending by (score, id):
    /// every block counted into A_tip under the current base generation (`Node::nf_span_member`). A below-anchor body's
    /// blue score is not derivable from hash links at DAG width > 1, so a joiner can only step its base on the crawler's
    /// quantum if the bundle names these; it pages each body by id and keeps it at the listed score (the same trust class
    /// as `FoldCarry.ancestors`). Bound into `sync_binding` as one fixed-width digest. ≤ (keep_depth + span) × 56 B.
    #[serde(default)]
    pub nf_fold_span: Vec<([u8; 32], u128, u64)>,
    /// ⭐ A-F114 UPGRADE (U2, docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md) — THE CANONICAL CHAIN this state stands on: its next
    /// record index, its end, the judged window's digest and its record counters. In `state_digest_parts`, so the join door's
    /// 32 mined vouchers vouch it, and in `sync_binding`. The window's records travel apart (bulk kind 33), each checked against
    /// this end link by link. Zero on today's chain (the switch off). 80 B. `serde(default)` only lets an older bundle decode:
    /// a stripped or zeroed field changes the state digest, so the join door counts no voucher for it and nothing adopts.
    #[serde(default)]
    pub canon: crate::canon_chain::CanonState,
}

/// G2g-r2a step 2: the one spelling of the fold-span member list inside `sync_binding` — domain-separated, count-prefixed.
pub fn fold_span_digest(span: &[([u8; 32], u128, u64)]) -> Hash32 {
    let mut b = Vec::with_capacity(32 + span.len() * 56);
    b.extend_from_slice(b"MUSD-nf-fold-span-v1");
    b.extend_from_slice(&(span.len() as u64).to_le_bytes());
    for (id, bw, bs) in span {
        b.extend_from_slice(id);
        b.extend_from_slice(&bw.to_le_bytes());
        b.extend_from_slice(&bs.to_le_bytes());
    }
    Hash32::hash(&b)
}

/// A-F50: the one spelling of the IonSwap pending-order list inside `sync_binding` — domain-separated, count-prefixed,
/// each order serialized deterministically (postcard). A forged, added or dropped order changes it.
pub fn ion_pending_digest(pending: &[crate::ion_pool_tx::IonPending]) -> Hash32 {
    let mut b = Vec::with_capacity(32 + pending.len() * 128);
    b.extend_from_slice(b"MUSD-ion-pending-v1");
    b.extend_from_slice(&(pending.len() as u64).to_le_bytes());
    for order in pending {
        let enc = postcard::to_allocvec(order).expect("IonPending is Serialize");
        b.extend_from_slice(&(enc.len() as u64).to_le_bytes());
        b.extend_from_slice(&enc);
    }
    Hash32::hash(&b)
}

/// The decode-layer default for [`NullifierSnapshot::letter_acc`] — the letter accumulator's genesis seed,
/// so a pre-letter bundle deserializes to the exact value a fresh node initializes with.
fn letter_acc_seed() -> [u8; 32] {
    crate::letter::letter_acc_genesis()
}

/// Decode-layer default for [`NullifierSnapshot::dir_acc`] — the directory accumulator's genesis seed.
fn dir_acc_seed() -> [u8; 32] {
    crate::directory::dir_acc_genesis()
}


/// The #29 DSYNC wire artifact a peer serves and a joiner adopts: the constant-size verified decider
/// ⛔⛔⛔ THE WHOLE-CHAIN CERTIFICATE AS IT CROSSES THE WIRE.
///
/// `DeciderBundle.chain_acc` is a value the SERVER chose, and the shipped decider proof certifies only
/// that somebody ran the prover with it — so every field `sync_binding` binds to that accumulator is
/// forgeable by construction (kill list §AH). This carries the thing that is not: a chain of
/// `usdm_decider::certificate_door` steps — each ONE Spartan-committed proof of the release's universal-row
/// R1CS running the verifier of the step below it, then folding this block's summary and work — bottoming out
/// at a base step over the genesis proof with ZERO work. Producing one REQUIRES HOLDING THE CHAIN.
///
/// Constant-size at any height — MEASURED 2026-09-28 (fixpoint runs 5 and 6 at T = 2^14): 178,093 B every
/// step, 9.9% of the ≤1.8 MB bundle budget; refused above `certificate_door::CERT_BYTES_MAX` (393,216; the T = 2^15 JB step is 377,393 B, 21% of the budget) by the
/// prover and the verifier; verify 217–221 ms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WholeChainCertWire {
    /// O1-FOOTPRINT-REVIEWED: `postcard(CertStep)` — bounded by `certificate_door::CERT_BYTES_MAX` plus the
    /// step's `IO_LEN` public words; the decider refuses a step above the cap on both the prove and the verify
    /// side, and the step is constant at any chain height.
    pub proof: Vec<u8>,
    /// The chain accumulator the certificate attests — a function of WHICH blocks were applied, in order.
    pub acc: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
    /// The PROVEN accumulated work. ⭐ This is what fork choice must read; a header's declared `blue_work`
    /// is a number the server typed.
    pub work: u128,
    /// The summary of the TIP block — recomputed by the adopter from the bundle's own declared fields.
    pub tip_summary: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
    /// The tip block's own work contribution.
    pub tip_block_work: u128,
}

impl WholeChainCertWire {
    /// Wire → the decider's own statement type. `None` when the bytes are not ONE `CertStep`: the adopt gate
    /// refuses such a bundle as `CertificateUnproven` before any check runs — a REFUSAL, never a rescue.
    /// ROOT-LAYER: this is THE wire↔statement conversion pair (one encoding); the bytes are produced by
    /// `from_proof` from a `CertStep` the decider minted, and decoded here and nowhere else.
    /// MEASURED 2026-09-28 (certificate_door fixpoint runs 5 and 6): every step 178,093 B, verify 217–221 ms;
    /// a truncated step, a flipped byte (2,920-flip census) and a moved io word are all refused downstream.
    /// MUST-STAY-GREEN: the DSYNC adopt gate's three checks (verify → work → summary) and every jump pin.
    #[must_use]
    pub fn to_proof(&self) -> Option<usdm_decider::whole_chain_cert::WholeChainProof> {
        let step: usdm_decider::certificate_door::CertStep = crate::chain_object::decode_exact(&self.proof)?;
        Some(usdm_decider::whole_chain_cert::WholeChainProof {
            step,
            acc: self.acc,
            work: self.work,
            tip_summary: self.tip_summary,
            tip_block_work: self.tip_block_work,
        })
    }

    /// The decider's statement → wire. ONE conversion pair, so a serve side and an adopt side cannot
    /// drift on the encoding of the single field that is not already an integer. Serializing a `CertStep`
    /// (two `Vec`s) cannot fail; a failure here would be a programming error and is loud.
    #[must_use]
    pub fn from_proof(p: &usdm_decider::whole_chain_cert::WholeChainProof) -> Self {
        Self {
            proof: crate::fixed::encode_plain(&p.step),
            acc: p.acc,
            work: p.work,
            tip_summary: p.tip_summary,
            tip_block_work: p.tip_block_work,
        }
    }
}

/// A certificate that cannot verify — the value a `SyncBundle` literal carries until it is certified.
/// ⭐ FAIL-CLOSED BY CONSTRUCTION: a fixture that forgets [`with_fixture_cert`] is REFUSED at the
/// certificate gate, never quietly admitted.
#[cfg(test)]
#[must_use]
pub(crate) fn unset_cert() -> WholeChainCertWire {
    WholeChainCertWire {
        proof: Vec::new(),
        acc: [0u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
        work: 0,
        tip_summary: [0u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
        tip_block_work: 0,
    }
}

/// ⛔ TEST-ONLY: certify a fixture bundle for the position IT DECLARES, so an adversarial fixture is
/// still refused for the reason it names rather than by the certificate gate standing in front of it.
#[cfg(test)]
#[must_use]
pub(crate) fn with_fixture_cert(mut b: SyncBundle) -> SyncBundle {
    b.cert = certify_position_for_test(
        &b.decider.tip,
        b.decider.blue_score,
        b.blue_work,
        &b.frontier,
        &b.nullifier,
        &b.genesis_commit,
        &b.anchor_ring,
        &b.member_ring_commits,
    );
    b
}

/// ⛔ TEST-ONLY: a REAL whole-chain certificate for a DECLARED position.
///
/// ⭐ Fixtures need this, not a stub. Most bundles in this crate's audit suites are ADVERSARIAL — they
/// declare a tampered field and assert the door names that tamper. Handing them a junk certificate would
/// make every one of them fail at the certificate gate instead, and the pin would go green while testing
/// nothing. **A gate whose attack is stopped by an outer layer is measuring the outer layer.**
///
/// This is a one-step BASE certificate: the empty chain plus this position. That is a genuine
/// certificate — `is_base` anchors at the genesis constant with zero inherited work — and it is what a
/// one-block chain's server would legitimately hold.
#[cfg(test)]
pub(crate) fn certify_position_for_test(
    tip: &BlockId,
    blue_score: u64,
    blue_work: u128,
    frontier: &FrontierSnapshot,
    nullifier: &NullifierSnapshot,
    genesis_commit: &[u8],
    anchor_ring: &[(u64, crate::spend_frontier::Digest4)],
    member_ring_commits: &[(u64, crate::hash::Hash32)],
) -> WholeChainCertWire {
    use std::collections::HashMap;
    use std::sync::Mutex;
    // TEST-ONLY memo: one GENUINE certificate step per DISTINCT position per process, keyed by the exact
    // statement the step folds — so no two positions ever share a certificate and a fixture never receives
    // one it did not declare; a repeated position is served the step already proven for it.
    // ROOT-LAYER: the fixture certificate is produced HERE (the one test-side certifier every suite calls),
    // so the cost is paid here once per position, not at every call site.
    // MEASURED 2026-09-28 (certificate_door fixpoint runs 5 and 6): one step is a T = 2^14 prove of ~5 min
    // plus the genesis proof (~6 min) once per process; 8 call sites across the suites share positions.
    // MUST-STAY-GREEN: every adopt pin that carries a genuine step; the adversarial suites whose tampers
    // must be named by the door BEHIND the certificate gate.
    static MEMO: Mutex<Option<HashMap<([u64; usdm_decider::poseidon2_compress::DIGEST_LANES], u128), WholeChainCertWire>>> = Mutex::new(None);
    let summary =
        bundle_chain_summary(tip, blue_score, blue_work, frontier, nullifier, genesis_commit, anchor_ring, member_ring_commits);
    let mut memo = MEMO.lock().expect("the fixture certificate memo is not poisoned");
    if let Some(wire) = memo.get_or_insert_with(HashMap::new).get(&(summary, blue_work)) {
        return wire.clone();
    }
    let mut cert = usdm_decider::whole_chain_cert::WholeChainCert::new();
    assert!(step_certificate(&mut cert, summary, blue_work), "a fixture certificate must fold");
    let wire = WholeChainCertWire::from_proof(&cert.finalize().expect("a stepped certificate finalises"));
    memo.get_or_insert_with(HashMap::new).insert((summary, blue_work), wire.clone());
    wire
}

/// ⭐ THE STATE A HEADER COMMITS TO, one definition, read by a node at its batch's end and by a joiner from a bundle's fields.
///
/// In it: every field that is a function of the fold step alone, measured on two real nodes over 126 steps of payments and a double spend.
/// Left out, and why: `root`, `count`, `nf_cover_conf_acc`, `nf_unspent_acc`, `letter_acc` sum over the blocks a node HOLDS, which differ
/// between nodes at one fold step, and no spend, mint or fork verdict reads them; `sparse_root`, `band`, `band_next_ordinal` and
/// `band_awaiting` have a chain of their own, because a node's band legally lags its fold; `nf_fold_base_words` and `nf_fold_span` are not
/// served at all (measured: the span differed at 85 of 120 batch ends on the same block, and its bodies are gone from every peer).
#[must_use]
pub fn state_digest(
    frontier: &FrontierSnapshot,
    n: &NullifierSnapshot,
    anchor_ring: &[(u64, crate::spend_frontier::Digest4)],
    member_ring_commits: &[(u64, crate::hash::Hash32)],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/state-digest/v1");
    for part in state_digest_parts(frontier, n, anchor_ring, member_ring_commits) {
        h.update(&part);
    }
    *h.finalize().as_bytes()
}

/// The parts of [`state_digest`], one hash per group of fields, so a disagreement between nodes can be attributed.
#[must_use]
pub fn state_digest_parts(
    frontier: &FrontierSnapshot,
    n: &NullifierSnapshot,
    anchor_ring: &[(u64, crate::spend_frontier::Digest4)],
    member_ring_commits: &[(u64, crate::hash::Hash32)],
) -> Vec<[u8; 32]> {
    // A value that cannot encode cannot be committed or claimed: the two sides then disagree, and a joiner refuses.
    fn put<T: serde::Serialize>(v: &T) -> [u8; 32] {
        match postcard::to_allocvec(v) {
            Ok(bytes) => *blake3::hash(&bytes).as_bytes(),
            Err(_) => *blake3::hash(b"unencodable").as_bytes(),
        }
    }
    vec![
        put(&(&frontier.root, frontier.height, &frontier.peaks_hex)),
        put(&anchor_ring_digest(anchor_ring)),
        put(&member_ring_commits_digest(member_ring_commits)),
        put(&n.membership_tip),
        put(&(&n.finality_validators, &n.custody_seat_active_from, &n.finality_seat_active_from, &n.departed_custody_seats, &n.departed_finality_seats, &n.seat_words)),
        put(&(&n.bonded_validators, &n.slashed_validators, n.slashed_bond_burned, &n.validator_bond_commit, &n.validator_custody, &n.validator_kem_eks, &n.custody_seat_numbers)),
        put(&(&n.dsol_registry_peaks, n.dsol_registry_count, &n.dir_acc, &n.applied_one_time_ids)),
        put(&(&n.peg_reserve_commit, &n.peg_minted_commit, &n.peg_reserve_hwm_commit, n.peg_ratio_bps, n.peg_redeem_floor_bps, n.peg_yield_rate_bps, &n.peg_price_marks)),
        put(&(&n.bond_heights, &n.bond_locked_notes, &n.unbonding, &n.peg_wrapped_assets, &n.peg_pools)),
        put(&(ion_pending_digest(&n.peg_ion_pending), n.peg_ion_usdm_held, n.peg_ion_pools)),
        put(&(&n.peg_retention_endowment_commit, &n.l2_state_root, &n.root_history_peaks_hex, n.peg_sat_issued, &n.peg_pendulum, &n.peg_br)),
        put(&n.canon), // ⭐ A-F114 U2: the canonical chain, vouched with the rest
    ]
}

/// ⭐⭐⭐ ONE DEFINITION of the value a certificate must attest for a given chain position.
///
/// The SERVE side computes it over its own state before folding it into its certificate; the ADOPT side
/// RECOMPUTES it from the bundle's own declared fields and refuses any certificate that does not name
/// exactly that value. Neither side ever reads the summary off the wire — that is what makes the
/// certificate a statement about THIS bundle rather than about some chain the server also happens to own.
///
/// ⛔ Two copies of this function is how §AI's whole class of defects happened. There is one, and both
/// sides call it.
#[must_use]
pub fn bundle_chain_summary(
    tip: &BlockId,
    blue_score: u64,
    blue_work: u128,
    frontier: &FrontierSnapshot,
    nullifier: &NullifierSnapshot,
    genesis_commit: &[u8],
    // ⭐ DB-223 / DB-274 P3: the ANCHOR RING shipped at this position. Its digest joins the frontier input below, so the
    // certificate covers EVERY ring entry (the adopter's install check alone covers only the newest) — a server cannot
    // hand a jumper a forged older root to judge spends against. No decider change: it rides the frontier's hash.
    anchor_ring: &[(u64, crate::spend_frontier::Digest4)],
    // ⭐ §RF-3: the MEMBER RING COMMIT HISTORY shipped beside the ring — bound the same way, so a server cannot hand a
    // jumper a forged older ring commit (a header naming a ring no canonical step held would then pass the fold). It
    // joins the frontier hash only when non-empty, so a bundle without one binds exactly as before.
    member_ring_commits: &[(u64, crate::hash::Hash32)],
) -> [u64; usdm_decider::poseidon2_compress::DIGEST_LANES] {
    // ⭐ A 32-byte ROOT is 256 bits and the canonical digest encoding holds 248, so these are HASHED, not
    // decoded (kill list §AI: roots take the injective decode, ids take the hash — here every input is
    // being COMMITTED to, not round-tripped, so the collision-resistant map is the right one).
    let h = |b: &[u8; 32]| usdm_decider::poseidon2_compress::hash32_to_digest(b);
    let mut fr = [0u8; 32];
    fr.copy_from_slice(
        blake3::hash(
            &[
                &frontier.root[..],
                &frontier.height.to_le_bytes()[..],
                &anchor_ring_digest(anchor_ring)[..],
                &member_ring_commits_digest(member_ring_commits)[..],
            ]
            .concat(),
        )
        .as_bytes(),
    );
    usdm_decider::whole_chain_cert::chain_summary_digest(
        h(tip.as_bytes()),
        blue_score,
        blue_work,
        h(&fr),
        h(&nullifier.root),
        h(&nullifier.sparse_root),
        nullifier.nf_unspent_acc,
        h(&nullifier.letter_acc),
        h(&nullifier.dir_acc),
        nullifier.validator_bond_commit,
        h(blake3::hash(genesis_commit).as_bytes()),
    )
}

/// ⭐⭐⭐ DB-243 — THE WHOLE-CHAIN CERTIFICATE STEP, DETACHED FROM THE STATE IT WAS TAKEN FROM.
///
/// `WholeChainCert::step` is an IVC recursive PROVE (`prove_ivc1_step_bytes`); it used to run inside
/// `Node::build_sync_bundle` under the runtime lock. A job is a CLONE of the certificate plus the one step's
/// inputs, taken at the same instant as the bundle draft, so it can run on any thread; `run` is the same step
/// and finalise the synchronous build performed, and the caller installs the result only if the live
/// certificate still equals `cert_acc_before` (`Node::install_cert_step`). Fail-closed: `None` on a step or
/// finalise that does not complete — nothing is installed and nothing is served from it.
pub struct SyncCertJob {
    /// The certificate as it stood when the draft was taken (a clone — the live one is untouched).
    pub cert: usdm_decider::whole_chain_cert::WholeChainCert,
    /// The one position's summary (`bundle_chain_summary` over the draft's own fields).
    pub summary: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
    /// The work this step adds.
    pub delta: u128,
    /// The certified work after the step — `Node::certified_blue_work` on install.
    pub blue_work: u128,
    /// The live certificate's accumulator the clone was taken at — the install's no-overwrite key.
    pub cert_acc_before: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
}

/// What a finished [`SyncCertJob`] hands back: the stepped certificate, its wire form for the bundle, the
/// certified work, and the accumulator the job started from.
pub type SteppedCert = (
    usdm_decider::whole_chain_cert::WholeChainCert,
    WholeChainCertWire,
    u128,
    [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
);

impl SyncCertJob {
    /// Step and finalise the cloned certificate — pure over the job, runs on any thread. `urgent` when a peer is waiting on this
    /// certificate to rejoin: it then runs on the normal pool, since on a machine always proving blocks the low-priority pool starves
    /// it for as long as the blocks last (MEASURED 2026-11-06: 38 minutes on two real nodes with one stuck behind). Otherwise nothing
    /// waits on it, and it runs on spare cycles (`background_prove`).
    #[must_use]
    pub fn run(self, urgent: bool) -> Option<SteppedCert> {
        let step = move || {
            let mut job = self;
            if !step_certificate(&mut job.cert, job.summary, job.delta) {
                return None; // fail-closed: an unprovable position is never certified
            }
            let wire = WholeChainCertWire::from_proof(&job.cert.finalize()?);
            Some((job.cert, wire, job.blue_work, job.cert_acc_before))
        };
        if urgent {
            step()
        } else {
            usdm_decider::background_prove::run(step)
        }
    }
}

/// ⭐⭐⭐ DB-223 / DB-274 P3 — THE ANCHOR RING'S DIGEST, defined ONCE, here (the decider-side twin was deleted,
/// `whole_chain_cert.rs` says so): the value [`bundle_chain_summary`] binds through the frontier input and an adopter
/// recomputes from the ring a bundle ships. Encoding: `blake3::derive_key("MUSD/anchor-ring/v1", u32 LE n ‖ n ×
/// (ordinal u64 LE ‖ root as 8 × u64 LE))`, oldest first; the empty ring (before the first fold) is the same derivation
/// over `n = 0`. Any moved, removed, added or reordered entry moves the digest (pinned).
#[must_use]
pub fn anchor_ring_digest(ring: &[(u64, crate::spend_frontier::Digest4)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/anchor-ring/v1");
    h.update(&(ring.len() as u32).to_le_bytes());
    for (ordinal, root) in ring {
        h.update(&ordinal.to_le_bytes());
        for lane in root.iter() {
            h.update(&lane.to_le_bytes());
        }
    }
    *h.finalize().as_bytes()
}

/// §RF-3 — THE MEMBER RING COMMIT HISTORY'S DIGEST as [`bundle_chain_summary`] binds it: `blake3::derive_key(
/// "MUSD/member-ring-commits/v1", u32 LE n ‖ n × (step u64 LE ‖ 32-B commit))`, oldest first; the EMPTY history binds
/// as zero bytes (the summary of a bundle that carries none is unchanged). Any moved, removed, added or reordered entry
/// moves it (pinned).
#[must_use]
pub fn member_ring_commits_digest(commits: &[(u64, crate::hash::Hash32)]) -> Vec<u8> {
    if commits.is_empty() {
        return Vec::new();
    }
    let mut h = blake3::Hasher::new_derive_key("MUSD/member-ring-commits/v1");
    h.update(&(commits.len() as u32).to_le_bytes());
    for (k, c) in commits {
        h.update(&k.to_le_bytes());
        h.update(&c.0);
    }
    h.finalize().as_bytes().to_vec()
}

/// ⭐ ONE whole-chain certificate step at a time per PROCESS: the single door every step in this crate goes
/// through ([`SyncCertJob::run`] and the test certifier `certify_position_for_test`).
///
/// A step is a T = 2^14 IVC prove: MEASURED 2026-09-28 at ~5 min and a peak RSS of 2–5 GB. The live runtime
/// already keeps at most one in flight (`NodeRuntime::build_sync_response` gates its spawn on `dsync_prove_job`),
/// so on a node process this lock never waits. Where two steps COULD overlap is a process holding many
/// `Node`s — the lib suite. MEASURED 2026-09-28 22:38 and 2026-09-29 00:39: the full suite was SIGKILLed by
/// memory pressure while certificate steps ran, and the fixture memo serialised only ITS OWN steps, never a
/// `build_sync_bundle` job beside them. The phone-class RAM pillar is per process, so the bound belongs here.
///
/// It is a lock on a resource, not a window: every step still runs, whole, and nothing is refused.
/// Cons: a second step waits for the first. That is 0 ms on a node (one runtime, one step in flight) and
/// serial proving time in the suite, which the kill was already costing.
/// A poisoned lock (a step that panicked) guards no data, so it is recovered, never propagated.
pub(crate) fn step_certificate(
    cert: &mut usdm_decider::whole_chain_cert::WholeChainCert,
    summary: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
    delta: u128,
) -> bool {
    // TEST BUILDS: a bound certificate step (the prover's test double, `usdm_decider::whole_chain_cert::bound`) costs
    // microseconds — no lock to queue behind and nothing to cache. `MONEROUSD_TEST_CERTS=proven` runs real proofs.
    #[cfg(test)]
    if usdm_decider::whole_chain_cert::certs_are_bound() {
        return cert.step(summary, delta);
    }
    static ONE_STEP_AT_A_TIME: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = match ONE_STEP_AT_A_TIME.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    #[cfg(test)]
    let statement = test_cert_fixture_cache::statement(cert, summary, delta);
    #[cfg(test)]
    if let Some(hit) = statement.as_ref().and_then(test_cert_fixture_cache::load) {
        *cert = hit;
        return true;
    }
    #[cfg(test)]
    test_cert_fixture_cache::genesis_loaded();
    let stepped = cert.step(summary, delta);
    #[cfg(test)]
    if stepped {
        if let Some(s) = statement.as_ref() {
            test_cert_fixture_cache::store(s, cert);
        }
        test_cert_fixture_cache::keep_genesis();
    }
    stepped
}

/// ⛔ TEST-ONLY (never compiled into a node): the CROSS-RUN certificate fixture cache. USER 2026-09-29, verbatim:
/// "you have my cross run approval permission" — recorded in `~/.claude/hooks/user-approved-local-storage.txt`.
///
/// WHY: MEASURED 2026-09-29 00:37–00:58, the lib suite sat at 84 tests for 20 min because every fixture position
/// proves a GENUINE T = 2^14 certificate step (~5 min, 2–5 GB), one at a time. Test positions are deterministic
/// (fixed genesis, fixed timestamps, deterministic grinds), so the same statement is proven again on every run.
///
/// WHAT A HIT IS: the stored proof of EXACTLY the statement this step would prove. It is used only when
/// (1) its public values equal the ones `AccStep::compute` derives natively from the certificate's own previous
/// values plus this summary and work, AND (2) `WholeChainCert::inherit` re-verifies the step
/// (`verify_whole_chain_cert`, ~220 ms). Anything else is a miss and proves afresh. Nothing a test asserts is
/// narrowed: the adopt door still verifies whatever certificate it is handed. It is never node authority: a node
/// binary does not contain this module.
///
/// KEY: blake3 over the release program digest and the full step statement (acc, work, tip summary and tip work
/// before; summary and work of this step). A prover change moves the digest, so a stale proof is never even read.
/// BOUND: at most [`test_cert_fixture_cache::TEST_CERT_FIXTURE_CACHE_MAX`] files (~178 KB each), oldest evicted,
/// under `~/.cache/monerousd-test-cert-fixtures`, outside every node datadir.
#[cfg(test)]
mod test_cert_fixture_cache {
    use usdm_decider::acc_program::{AccStep, AccStepIn, GENESIS_SUMMARY};
    use usdm_decider::whole_chain_cert::{WholeChainCert, WHOLE_CHAIN_GENESIS_ACC};

    /// The file-count bound: 512 × ~178 KB ≈ 91 MB. A full suite needs well under a tenth of it.
    pub(super) const TEST_CERT_FIXTURE_CACHE_MAX: usize = 512;

    /// One step's full statement and the file that holds its proof.
    pub(super) struct Statement {
        input: AccStepIn,
        path: std::path::PathBuf,
    }

    /// ⭐ test_cert_fixture_cache — THE GENESIS PROOF, cross-run (MEASURED 2026-10-02: 399–475 s, re-proved by EVERY test
    /// process that certifies a chain, because the step entries above never hold it — it is the base step's inner
    /// object, kept per process in the decider). Same directory, same off switch, same rule: the decider installs a
    /// stored proof ONLY after `verify_genesis_certificate` re-verifies it (`install_genesis_proof_for_test`). Keyed by
    /// the prover-source fingerprint and the release program digest, so a prover change names another file.
    fn genesis_path() -> Option<std::path::PathBuf> {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-cert-fixture/genesis/v1");
        h.update(&prover_source_digest()?);
        h.update(format!("{:?}", usdm_decider::certificate_door::CERT_PROGRAM_DIGEST).as_bytes());
        Some(dir()?.join(format!("genesis-{}.cert", h.finalize().to_hex())))
    }

    /// Before this process's FIRST prove: install the stored genesis proof if one verifies (once per process).
    pub(super) fn genesis_loaded() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let Some(bytes) = genesis_path().and_then(|p| std::fs::read(p).ok()) else { return }; // O1-INFINITY-REVIEWED: test-only (#[cfg(test)], absent from every node binary); ONE file per prover fingerprint; re-verified before use
            let _ = usdm_decider::whole_chain_cert::install_genesis_proof_for_test(bytes);
        });
    }

    /// After a prove: keep the genesis proof this process holds, if no file holds it yet. Best effort.
    pub(super) fn keep_genesis() {
        let Some(path) = genesis_path() else { return };
        if path.exists() {
            return;
        }
        let Some(bytes) = usdm_decider::whole_chain_cert::genesis_proof_held_for_test() else { return };
        let Some(d) = path.parent() else { return };
        if std::fs::create_dir_all(d).is_err() {
            return;
        }
        let tmp = path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    fn dir() -> Option<std::path::PathBuf> {
        // K5 (lane-review 2026-09-30): the ONE final landing gate runs with the cache OFF, so it certifies fresh
        // proves and never a cache artifact. `MONEROUSD_TEST_PROOF_CACHE=off` → no directory → every step proves.
        if std::env::var("MONEROUSD_TEST_PROOF_CACHE").is_ok_and(|v| v == "off") {
            return None;
        }
        match std::env::var_os("HOME") {
            Some(h) => Some(std::path::PathBuf::from(h).join(".cache").join("monerousd-test-cert-fixtures")),
            None => None, // no home, no cache: every step proves
        }
    }

    /// The statement `cert.step(summary, delta)` would prove, read from the certificate's own public values.
    pub(super) fn statement(
        cert: &WholeChainCert,
        summary: [u64; usdm_decider::poseidon2_compress::DIGEST_LANES],
        delta: u128,
    ) -> Option<Statement> {
        let input = match cert.finalize() {
            Some(p) => AccStepIn {
                acc_prev: p.acc,
                work_prev: p.work,
                summary_prev: p.tip_summary,
                bw_prev: p.tip_block_work,
                summary,
                block_work: delta,
            },
            // A certificate that has never stepped stands at the genesis constants (`WholeChainCert::new`).
            None => AccStepIn {
                acc_prev: WHOLE_CHAIN_GENESIS_ACC,
                work_prev: 0,
                summary_prev: GENESIS_SUMMARY,
                bw_prev: 0,
                summary,
                block_work: delta,
            },
        };
        let name = key_name(prover_source_digest()?, &input);
        Some(Statement { input, path: dir()?.join(name) })
    }

    /// The file name of one statement's proof, pure. K1 + K2 (lane-review 2026-09-30, the cache-key review):
    /// * K1: the key carries the PROVER SOURCE digest. `CERT_PROGRAM_DIGEST` alone is a verifier-SHAPE constant that
    ///   moves only on a shape change, so a prover regression left every cached proof verifying and MASKED the
    ///   break until eviction. With the source in the key, a hit implies byte-identical prover code.
    /// * K2: the statement enters as its canonical little-endian bytes, field by field in declaration order — never
    ///   `Debug`, which a type may redact (DB-363's `LcBlind` does), letting two statements collide.
    pub(super) fn key_name(source: [u8; 32], input: &AccStepIn) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/test-cert-fixture/v2");
        h.update(&source);
        h.update(format!("{:?}", usdm_decider::certificate_door::CERT_PROGRAM_DIGEST).as_bytes());
        for lane in input.acc_prev.iter() {
            h.update(&lane.to_le_bytes());
        }
        h.update(&input.work_prev.to_le_bytes());
        for lane in input.summary_prev.iter() {
            h.update(&lane.to_le_bytes());
        }
        h.update(&input.bw_prev.to_le_bytes());
        for lane in input.summary.iter() {
            h.update(&lane.to_le_bytes());
        }
        h.update(&input.block_work.to_le_bytes());
        format!("{}.cert", h.finalize().to_hex())
    }

    /// K1 — the PROVER SOURCE digest, from the ONE function every test proof cache shares
    /// (`usdm_decider::prover_fingerprint::prover_source_digest`, lane-recursion 2026-09-30, the decider's `test-support`
    /// feature, enabled for this crate's test builds only). It is blake3 over every `*.rs` and `Cargo.toml` under
    /// `vendor/Plonky3`, both lockfiles, `rustc -V`, the profile and `MONEROUSD_PROVER_ASSERTS`, computed once per process.
    /// `None` when the tree is unreadable: the cache then stays OFF and every step proves afresh — fail-closed toward
    /// proving, never toward trusting a stale file. (This crate kept its own copy for one hour; one derivation now.)
    fn prover_source_digest() -> Option<[u8; 32]> {
        usdm_decider::prover_fingerprint::prover_source_digest()
    }

    /// A stored proof of exactly this statement, re-derived and re-verified; `None` for anything else.
    pub(super) fn load(s: &Statement) -> Option<WholeChainCert> {
        let bytes = std::fs::read(&s.path).ok()?; // O1-INFINITY-REVIEWED: test-only (#[cfg(test)], absent from every node binary); one file per distinct fixture statement, bounded by TEST_CERT_FIXTURE_CACHE_MAX; the bytes are never authority — AccStep::compute re-derives the statement and inherit re-verifies the proof before use
        let wire: super::WholeChainCertWire = crate::chain_object::decode_exact(&bytes)?;
        let proof = wire.to_proof()?;
        let native = AccStep::compute(s.input)?;
        let same_statement = proof.acc == native.acc
            && proof.work == native.work
            && proof.tip_summary == s.input.summary
            && proof.tip_block_work == s.input.block_work;
        if !same_statement {
            return None;
        }
        WholeChainCert::inherit(&proof) // verifies the step; None when it does not
    }

    /// Keep the proof this step just made (test_cert_fixture_cache write). Best effort: a failed write only means
    /// the next run proves again.
    pub(super) fn store(s: &Statement, cert: &WholeChainCert) {
        let Some(proof) = cert.finalize() else { return };
        let Ok(bytes) = postcard::to_allocvec(&super::WholeChainCertWire::from_proof(&proof)) else { return };
        let Some(d) = s.path.parent() else { return };
        if std::fs::create_dir_all(d).is_err() {
            return;
        }
        evict_to_bound(d);
        let tmp = s.path.with_extension(format!("tmp{}", std::process::id()));
        if std::fs::write(&tmp, &bytes).is_ok() && std::fs::rename(&tmp, &s.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// Hold the directory under [`TEST_CERT_FIXTURE_CACHE_MAX`] files, oldest first out.
    fn evict_to_bound(d: &std::path::Path) {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        let mut files: Vec<(std::time::SystemTime, std::path::PathBuf)> = rd
            .filter_map(Result::ok)
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        if files.len() < TEST_CERT_FIXTURE_CACHE_MAX {
            return;
        }
        files.sort();
        for (_, p) in files.iter().take(files.len() + 1 - TEST_CERT_FIXTURE_CACHE_MAX) {
            let _ = std::fs::remove_file(p);
        }
    }

    /// ⛔ K1 + K2 PIN (lane-review 2026-09-30): the key moves with the PROVER SOURCE and with every statement field.
    /// Before K1 the key held only `CERT_PROGRAM_DIGEST`, so a prover edit left every cached proof's file name unchanged
    /// (the masking the review named); CALIBRATION: two source digests that differ in one bit must name two files. Each
    /// of the six statement fields, moved by one, must name a new file too (a field the key missed would collide).
    /// Pure: no proving, no disk.
    #[test]
    fn test_cert_fixture_cache_key_moves_with_the_prover_source_and_every_statement_field() {
        let base = AccStepIn {
            acc_prev: [1; usdm_decider::poseidon2_compress::DIGEST_LANES],
            work_prev: 2,
            summary_prev: [3; usdm_decider::poseidon2_compress::DIGEST_LANES],
            bw_prev: 4,
            summary: [5; usdm_decider::poseidon2_compress::DIGEST_LANES],
            block_work: 6,
        };
        let src = [7u8; 32];
        let mut src2 = src;
        src2[31] ^= 1;
        let k = key_name(src, &base);
        assert_eq!(k, key_name(src, &base), "the key is a pure function of (source, statement)");
        assert_ne!(k, key_name(src2, &base), "⛔ K1: a prover source change must move the key");
        let mut moved: Vec<AccStepIn> = Vec::new();
        let mut m = base;
        m.acc_prev[0] += 1;
        moved.push(m);
        m = base;
        m.work_prev += 1;
        moved.push(m);
        m = base;
        m.summary_prev[7] += 1;
        moved.push(m);
        m = base;
        m.bw_prev += 1;
        moved.push(m);
        m = base;
        m.summary[3] += 1;
        moved.push(m);
        m = base;
        m.block_work += 1;
        moved.push(m);
        let mut names = std::collections::HashSet::new();
        names.insert(k);
        for (i, s) in moved.iter().enumerate() {
            assert!(names.insert(key_name(src, s)), "⛔ K2: statement field #{i} moved by one did not move the key");
        }
    }

    /// ⛔ TAMPER PINS: a cache entry is NEVER authority. Each forged entry sits at the statement's own path, so
    /// the only thing standing between it and a test's certificate is `load`'s re-derivation and re-verify.
    /// cons: disk = f(fixed constants): ≤ TEST_CERT_FIXTURE_CACHE_MAX 512 files × 178,093 B = 91 MB ceiling on the
    /// DEVELOPER machine only (0 B on every node: the module is #[cfg(test)]); a suite run writes ~40 files × 178 KB
    /// ≈ 7 MB; this pin writes 5 small files to a scratch dir and removes it.
    #[test]
    fn test_cert_fixture_cache_refuses_every_entry_that_is_not_a_verified_proof_of_its_statement() {
        let scratch = std::env::temp_dir().join(format!("test_cert_fixture_cache-pin-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("scratch dir");
        let lanes = usdm_decider::poseidon2_compress::DIGEST_LANES;
        let summary = [7u64; usdm_decider::poseidon2_compress::DIGEST_LANES];
        let fresh = WholeChainCert::new();
        let mut s = statement(&fresh, summary, 5).expect("a statement for a fresh certificate");
        s.path = scratch.join("entry.cert");
        let native = AccStep::compute(s.input).expect("the statement computes natively");
        let wire_of = |acc, work, tip_summary, tip_block_work| {
            let step = usdm_decider::certificate_door::CertStep { bytes: vec![0u8; 64], io: Vec::new() };
            postcard::to_allocvec(&super::WholeChainCertWire::from_proof(
                &usdm_decider::whole_chain_cert::WholeChainProof { step, acc, work, tip_summary, tip_block_work },
            ))
            .expect("a wire serializes")
        };
        assert_eq!(lanes, native.acc.len(), "premise: one digest width");
        let cases: [(&str, Vec<u8>); 4] = [
            ("truncated bytes", vec![1u8, 2, 3]),
            (
                "a proof of ANOTHER statement (acc moved)",
                wire_of([9u64; usdm_decider::poseidon2_compress::DIGEST_LANES], native.work, summary, 5),
            ),
            ("a proof of ANOTHER statement (work moved)", wire_of(native.acc, native.work + 1, summary, 5)),
            ("the RIGHT statement over a step that does not verify", wire_of(native.acc, native.work, summary, 5)),
        ];
        for (what, bytes) in cases {
            std::fs::write(&s.path, &bytes).expect("write the forged entry");
            assert!(load(&s).is_none(), "⛔ the fixture cache USED {what} — a cache entry became authority");
        }
        assert!(load(&Statement { input: s.input, path: scratch.join("absent.cert") }).is_none(), "a miss is a miss");
        let _ = std::fs::remove_dir_all(&scratch);
    }

    /// The key is the WHOLE statement: moving any one input names a different file.
    #[test]
    fn test_cert_fixture_cache_key_moves_with_every_input_of_the_statement() {
        let fresh = WholeChainCert::new();
        let a = statement(&fresh, [1u64; usdm_decider::poseidon2_compress::DIGEST_LANES], 5).expect("statement");
        let b = statement(&fresh, [2u64; usdm_decider::poseidon2_compress::DIGEST_LANES], 5).expect("statement");
        let c = statement(&fresh, [1u64; usdm_decider::poseidon2_compress::DIGEST_LANES], 6).expect("statement");
        assert_ne!(a.path, b.path, "the summary is in the key");
        assert_ne!(a.path, c.path, "the step's work is in the key");
        let again = statement(&fresh, [1u64; usdm_decider::poseidon2_compress::DIGEST_LANES], 5).expect("statement");
        assert_eq!(a.path, again.path, "one statement, one file");
    }
}

/// proof PLUS the persisted frontier snapshot to install. Constant-size at ANY DAG width / history.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncBundle {
    /// The ≤1.8MB decider bundle (tip + blue-score + chain accumulator + recursive WHIR proof).
    pub decider: DeciderBundle,
    /// The persisted PQ-frontier to install so the joiner is a first-class producer.
    pub frontier: FrontierSnapshot,
    /// The O(1) nullifier spent-state to inherit (Gap2) — bound into `chain_acc` via [`sync_binding`], so the
    /// joiner's double-spend checks self-verify against a CERTIFIED spent-state, not a trusted/forged one.
    pub nullifier: NullifierSnapshot,
    /// The tip BLOCK itself (constant-size, ~1 block — NOT history). The decider proof certifies the
    /// chain up to `decider.tip`; carrying the tip block lets the adopter GRAFT it as a first-class DAG
    /// anchor (its real header/id), so it can build its next block ON the adopted tip and CONVERGE with
    /// the peer on ONE shared tip — the mergeset graft, not just a frontier jump. `tip_block.id()` MUST
    /// equal `decider.tip` (checked on adopt) so a forged tip block cannot be paired with a valid proof.
    pub tip_block: crate::block::Block,
    /// §20.2 — the tip record's COVER KEY beside `tip_block.output_notes` (which travel in the bundle while the block's own
    /// in-process key does not): the adopter assembles and binds the tip's record under it.
    #[serde(default)]
    pub tip_cover_key: Option<crate::cover::CoverKey>,
    /// §22b — the tip's WIDE OBJECTS beside `tip_block` (the bytes its sealed credit set names by hash; the block's own
    /// in-process copy does not ride its postcard form): the adopter judges the tip's notes by the whole set.
    #[serde(default)]
    pub tip_wide_objects: Vec<Vec<u8>>,
    /// The adopted tip's ACCUMULATED GHOSTDAG `blue_work` — the ORDERING key the adopter uses to decide
    /// whether to reorg onto this chain (`(blue_work, id)`). It is an ordering hint, not a validity claim
    /// (the tip's validity is what the decider proof cryptographically certifies); a lied-high value can
    /// at worst make a node follow a VALID-but-lighter certified chain, never accept an invalid one.
    pub blue_work: u128,
    /// The serving chain's GENESIS IDENTITY (`genesis_parity_commit`) — the deterministic per-network genesis
    /// this chain roots at. Constant-size (~13–77 bytes). It is BOUND into `sync_binding` (the decider's
    /// `chain_acc`), so a peer cannot serve a valid tip proof while lying about the genesis it roots at — a
    /// swapped genesis breaks the binding and the bundle is rejected. This is what lets a fresh node
    /// (which boots on the plain per-network genesis) ADOPT the canonical chain's genesis identity the first
    /// time it verifies a bundle — the Bitcoin rule "your genesis is the one the highest-work VERIFIED chain
    /// proves" — so every honest node of a network converges to ONE genesis + chain_id, by construction.
    pub genesis_commit: Vec<u8>,
    /// v31: the FOLD-ROOT block — the chain block the carried spine ends at. The adopter anchors its DAG
    /// HERE (not at the tip) so the canonical record fold continues from the same chain block the peer
    /// folded to; the blocks between it and the certified tip arrive by ordinary gossip and parent
    /// backfill. Equals `tip_block` when the peer has folded through its tip. Bound into `chain_acc` via
    /// [`sync_binding`] (id and blue score), so a forged anchor cannot ride a valid proof.
    pub anchor_block: crate::block::Block,
    pub anchor_blue_work: u128,
    pub anchor_blue_score: u64,
    /// ⭐ THE ANCHOR'S RECORD POSITION, as the SERVER folded it.
    ///
    /// BORROWED-FROM: Zcash's anchor + tree-size model (github.com/zcash/zcash) — a jumping node adopts a
    /// commitment-tree ROOT together with the SIZE that produced it, and appends from exactly there.
    ///
    /// Without it the adopter had to INFER where it stood (from a counter, a stored row, or the leaf count)
    /// and the two sides picked different answers: MEASURED 2026-09-04 across the runtime backend and both
    /// searches, one party folded every later block exactly ONE ordinal above the other (p0@3 p1@4, p0@4
    /// p1@5, …). One value, sent by the side that already knows it, ends that whole class — the adopter
    /// stores it as the anchor's row and every later position follows from the DAG.
    pub anchor_ordinal: u64,
    /// v31: what the adopter needs above and just below the fold root to reach the certified tip and fold
    /// canonically — bound into `chain_acc` through `FoldCarry::digest`.
    pub fold_carry: FoldCarry,
    /// ⛔ D-36 (2026-09-11): EVERY tip of the serving node's DAG, not only the selected one. The certified
    /// nullifier state is a sum over every block the server ACCEPTED — its whole DAG, the past of ALL its
    /// tips — while `decider.tip` names only the selected chain. A sibling tip the server accepted by
    /// gossip is in that sum and in nothing else the bundle carries, so a jumper that already holds the
    /// same block cannot tell it is covered: MEASURED, it re-folded it and came out one 256-cover over
    /// (`nullifier_count 1281 vs 1537`). With the tips, the covered set is exactly the past of these ids.
    /// O1-FOOTPRINT-REVIEWED: bounded by DAG_WIDTH_CEILING — a DAG has at most `dag_width` (≤ the ceiling)
    /// tips by construction. `serde(default)` keeps a pre-tips bundle decodable (empty ⇒ the jumper
    /// falls back to the selected tip alone).
    #[serde(default)]
    pub tips: Vec<crate::block::BlockId>,
    /// ⭐ DB-223 / DB-274 P3 — THE ANCHOR RING at the bundle's fold root: `(ordinal, spine root)`, oldest first, the
    /// CANONICAL ring for `anchor_ordinal` (dense, `min(merge_depth_cap, anchor_ordinal)` long). A jumper installs it,
    /// so it can judge spend anchors that predate its adopt. Served only by a node holding the complete ring (else
    /// empty, and the jumper's ring refills from its own fold). The adopter installs it only when its newest entry is
    /// `anchor_ordinal` at the ADOPTED spine root (`Node::install_anchor_ring`); its digest
    /// ([`anchor_ring_digest`]) joins the certificate's statement (lane-recursion's `state_hash` input), which then
    /// covers every entry, not only the newest.
    /// O1-FOOTPRINT-REVIEWED: bounded by `merge_depth_cap` entries of 72 B (259,200 B at 3,600), refused past it.
    #[serde(default)]
    pub anchor_ring: Vec<(u64, crate::spend_frontier::Digest4)>,
    /// ⭐ §RF-3 — THE MEMBER RING COMMIT HISTORY at the bundle's fold root (`Node::member_ring_commits`), served only with
    /// a complete anchor ring; bound in the certificate's statement beside the ring ([`member_ring_commits_digest`]). The
    /// adopter installs it only after the ring and only when its newest entry is the commit of that ring
    /// (`Node::install_member_ring_commits`). O1-FOOTPRINT-REVIEWED: bounded by `merge_depth_cap` entries of 40 B
    /// (144,000 B at 3,600), refused past it.
    #[serde(default)]
    pub member_ring_commits: Vec<(u64, crate::hash::Hash32)>,
    /// ⛔ THE CERTIFICATE THAT MAKES THE REST MEAN ANYTHING. Without it every field above rides a
    /// `chain_acc` the server chose. `adopt_sync_bundle` REFUSES a bundle whose certificate does not
    /// verify, or whose certificate names a chain position other than the one this bundle declares.
    /// ⭐ JOINING BY WORK: what shows this bundle's anchor sits on real work and its state is vouched for (`crate::join_proof`).
    pub join: crate::join_proof::JoinProof,
    pub cert: WholeChainCertWire,
}

/// The carry a checkpoint and a bundle transport (see `Node::unfolded_carry`). Every vector is bounded by a
/// fixed constant: the window by `daa_sample_len`, the ancestors by depth × DAG width, the unfolded blocks by
/// `record_fold_depth` chain blocks and their merge sets.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FoldCarry {
    /// O1-FOOTPRINT-REVIEWED: bounded by daa_sample_len samples (fixed constant) — the (timestamp, work) pairs
    /// of the selected chain BELOW the fold root, newest first: what the difficulty and median-time walks
    /// need, 24 bytes each, never a header.
    pub window: Vec<crate::dag::DaaSample>,
    /// O1-FOOTPRINT-REVIEWED: bounded by depth × DAG width (fixed constants) — the FOLDED parents the unfolded
    /// blocks name outside the window, header + tx ids + blue data.
    pub ancestors: Vec<(crate::block::Block, u128, u64)>,
    /// The difficulty/MTP window BELOW each ancestor shell (same shape as `window`): a selected-chain walk
    /// on the jumped node can end on a shell that is not the anchor (a side parent that out-weighs it by
    /// the tie-break), and without its own window that walk computes a different expected work than the
    /// full nodes — MEASURED by the restart schedule search (2026-09-03): `WrongWork { expected: 5, got:
    /// 4 }` both ways after one restart. Bounded by the ancestor count × `daa_sample_len`.
    pub ancestor_windows: Vec<([u8; 32], Vec<crate::dag::DaaSample>)>,
    /// O1-FOOTPRINT-REVIEWED: bounded by record_fold_depth chain blocks and their merge sets (fixed constants) —
    /// the full blocks above the fold root with the blue data their holder computed.
    pub unfolded: Vec<(crate::block::Block, u128, u64)>,
    /// ⛔⛔ db333-r — THE BLOCKS THE STATE THIS CARRY RIDES WITH ALREADY COUNTS, by `(id, blue_work, blue_score)`.
    /// The served bundle positions at the fold root (G11b) and clears `unfolded`, but its nullifier, letter, peg and
    /// validator state is the server's LIVE state: it counts every block it accepted above that root. Those blocks reach
    /// the adopter later by page or gossip, and the ordinary apply counted them a second time (MEASURED, db333 pin,
    /// scratchpad/verify/g2gr-db333-g.log: `nf_fold_seq` 40 → 72 on the joiner vs 40 on its origin, roots apart from
    /// then). An adopter PLACES such a block when it arrives — the carried-block graft, never the apply — exactly as it
    /// placed the bodies `unfolded` carried before G11b (Kaspa: state at the pruning point already holds its past;
    /// Bitcoin: a connected block is never connected twice). Bound by `digest`, so a forged list breaks the certified
    /// binding. O1-FOOTPRINT-REVIEWED: one entry per block the server holds unfolded or still awaits as covered — the
    /// `unfolded` bound (record_fold_depth chain blocks and their merge sets) — 48 B each; never f(height).
    pub covered: Vec<([u8; 32], u128, u64)>,
    /// ⭐ §22b — THE CARRIED BODIES' SIDECARS, by block id: each `unfolded` body's cover key and its wide objects, the two
    /// in-process fields a `Block` keeps `#[serde(skip)]` (they travel node-to-node in the gossip envelope, never in the
    /// hashed block). Without them a checkpoint resume or a carried graft held a body whose sealed set names references it
    /// cannot resolve, and the fold waited on it forever (MEASURED: consensus_scenarios db119/db120 + the runtime
    /// backend's restart cases RED, 66 × "held body true · wide bytes missing true", f248-cs.log). Placement re-attaches
    /// them and drops every wide byte the body's sealed set does not name (`block::retain_named_wide`), so a forged entry
    /// changes nothing: a wrong key opens nothing, an unnamed object is discarded, and a reference resolves by its hash.
    /// O1-FOOTPRINT-REVIEWED: one entry per `unfolded` body (the same bound), each one key plus that body's wide objects.
    /// §22c: and its stated spends' transactions (`Block::tx_bodies`, the fourth element): a resumed node judges each
    /// carried body's spend anchors at its fold exactly as it would have without the restart (`spend_evidence`); a body
    /// not named by the block's own `tx_ids` is dropped on placement (`block::retain_named_tx_bodies`).
    #[allow(clippy::type_complexity)]
    pub sidecars: Vec<([u8; 32], Option<crate::cover::CoverKey>, Vec<Vec<u8>>, Vec<Vec<u8>>)>,
}

impl FoldCarry {
    pub fn is_empty(&self) -> bool {
        self.window.is_empty() && self.ancestors.is_empty() && self.unfolded.is_empty() && self.ancestor_windows.is_empty() && self.covered.is_empty() && self.sidecars.is_empty()
    }
    /// The digest `sync_binding` folds over the carry (ids and blue data), so a forged carry cannot ride a
    /// valid proof.
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(1 + 32 * self.window.len() + 56 * (self.ancestors.len() + self.unfolded.len()));
        // 0x32 (2026-09-18): each window sample binds its BLUE SCORE too — the DAG-wide difficulty rule
        // reads it, so a carried sample with a forged blue score must break the certified binding.
        buf.push(0x32);
        for (t, w, bs) in &self.window {
            buf.extend_from_slice(&t.to_le_bytes());
            buf.extend_from_slice(&w.to_le_bytes());
            buf.extend_from_slice(&bs.to_le_bytes());
        }
        buf.push(0xff);
        for part in [&self.ancestors, &self.unfolded] {
            for (b, bw, bs) in part.iter() {
                buf.extend_from_slice(b.id().as_bytes());
                buf.extend_from_slice(&bw.to_le_bytes());
                buf.extend_from_slice(&bs.to_le_bytes());
            }
            buf.push(0xff);
        }
        for (id, w) in &self.ancestor_windows {
            buf.extend_from_slice(id);
            for (t, wk, bs) in w {
                buf.extend_from_slice(&t.to_le_bytes());
                buf.extend_from_slice(&wk.to_le_bytes());
                buf.extend_from_slice(&bs.to_le_bytes());
            }
            buf.push(0xfe);
        }
        buf.push(0xfd);
        for (id, bw, bs) in &self.covered {
            buf.extend_from_slice(id);
            buf.extend_from_slice(&bw.to_le_bytes());
            buf.extend_from_slice(&bs.to_le_bytes());
        }
        *crate::hash::Hash32::hash(&buf).as_bytes()
    }
}


impl SyncBundle {
    /// The least work the serving chain holds: the anchor's weight plus the heaviest path through the mined suffix above it
    /// (`join_proof::suffix_chain_work`). The anchor alone sits tens of blocks below the serving tip, so on a fork it always read
    /// lighter than the receiving node's tip even when the serving chain was heavier (MEASURED 2026-11-07, heal.py: 118 against 152
    /// while the serving tip held 160). Every suffix header's work is verified by the join door before an adopt compares this.
    /// The suffix stands on the ANCHOR, so the path is added to the anchor's weight; the certified tip's weight is the floor, for a suffix
    /// cut at `MAX_SUFFIX`. Both weights are bound into the certified sync binding (`sync_binding`).
    pub fn chain_work(&self) -> u128 {
        let path = crate::join_proof::suffix_chain_work(self.anchor_block.header.id().as_bytes(), &self.join.suffix);
        self.blue_work.max(self.anchor_blue_work.saturating_add(path))
    }

    /// Serialize for onion transport (postcard, the MonerousD-parity wire format).
    pub fn to_wire(&self) -> Vec<u8> {
        // postcard::to_allocvec only fails on a serializer defect, not on this all-owned data.
        postcard::to_allocvec(self).unwrap_or_default()
    }

    /// Deserialize a received frame. A corrupt / truncated / oversize frame returns `None`
    /// (fail-closed) — a node never adopts from a frame it cannot even decode.
    pub fn from_wire(bytes: &[u8]) -> Option<SyncBundle> {
        crate::chain_object::decode_exact(bytes)
    }
}

/// Domain-separated commitment binding the adopted tip to the frontier AND the serving chain's GENESIS
/// IDENTITY. The decider bundle's `chain_acc` MUST equal this — so a valid decider proof for chain X cannot
/// be paired with a forged frontier OR a lied genesis for chain Y (either swap breaks the commitment and
/// adoption is rejected). Binding the genesis is what makes genesis-identity adoption SOUND: a fresh node
/// only adopts a peer's genesis when the verified proof certifies the chain roots at exactly that genesis.
/// 16 bytes to match `DeciderBundle::chain_acc` (the O(1) DOMAIN_CHAIN_ACC accumulator width).
///
/// ⭐⭐⭐ THE COMPLETENESS LAW OF THIS PREIMAGE (2026-09-07, holes A3/A4).
///
/// **Every field of [`SyncBundle`] that an adopting node ACTS ON must be in this preimage.** A field
/// that is not here rides a valid proof unbound: the proof still verifies, `chain_acc == expected`
/// still passes, and the adopter installs whatever the sender typed. That is not a subtle property
/// of one field — it is the shape of the whole door, so the audit is a field-by-field enumeration of
/// `SyncBundle`, and it is repeated here in full so the next field added to that struct cannot be
/// added without answering for itself.
///
/// ⛔ THE TABLE IS RE-DERIVED HONESTLY (adversarial review, 2026-09-08). The previous version wrote
/// `tip_block | by id` and `fold_carry | carry_digest` as if those rows were whole answers. They were
/// not, and the review proved it by construction: `Block::id()` IS `header.id()`, so an id — and
/// every accumulator folded over ids — binds the HEADER ONLY, and `FoldCarry::digest` folds ids and
/// blue data and nothing else. A relay that rewrote a certified block's BODY left `chain_acc`
/// byte-identical and the adopter filed the attacker's notes at a real block's address. So every row
/// below now says WHICH of the three things it is — **PREIMAGE** (hashed here), **COMMITMENT** (bound
/// by a value that IS hashed here, with the enforcing site named), or **NOT BOUND** — and a row that
/// cannot say one of the three is written as a finding, not smoothed over.
///
/// | `SyncBundle` field | bound how | where |
/// |---|---|---|
/// | `decider.tip` | PREIMAGE | `tip` below |
/// | `decider.blue_score` | PREIMAGE | `blue_score` below |
/// | `decider.chain_acc` | IS this value | compared in `adopt_sync_bundle` |
/// | `decider.proof` | COMMITMENT | verified against `chain_acc` by `accept_bundle` (see the ⛔ note below on what that proof does NOT certify) |
/// | `frontier.root` / `.height` | PREIMAGE | below |
/// | `frontier.peaks_hex` | PREIMAGE | below — **ADDED 2026-09-08**. It was called "DERIVED-BOUND" and was not: the derivation `instant_sync` runs is guarded by `if !peaks_hex.is_empty()`, so a relay that STRIPPED the field skipped the binding entirely and adopted fine (review attack 3). The spine is now hashed, length-prefixed, so a strip and an edit are the same refusal. |
/// | `nullifier.root` / `.count` / `.sparse_root` / `.nf_unspent_acc` / `.unspent_note_root` / `.membership_tip` / `.letter_acc` / `.dir_acc` / `.bonded_validators` / `.slashed_validators` / `.slashed_bond_burned` / `.validator_bond_commit` / `.validator_custody` | PREIMAGE | below |
/// | `nullifier.nf_cover_conf_acc` | PREIMAGE | below — **ADDED 2026-09-07** (was unbound) |
/// | `tip_block.header` (hence `.tx_ids`, through `tx_merkle_root`) | PREIMAGE, by id | `tip` below; `adopt_sync_bundle` refuses `tip_block.id() != decider.tip`, and `Node::header_door_admits` re-hashes the tx ids against the id-pinned `tx_merkle_root` |
/// | `tip_block` BODY (`output_notes`, `account_targets`, every sidecar) | COMMITMENT when PRESENT; **NOT BOUND when STRIPPED** | the header's own `output_notes_root` / `account_targets_root` / … , enforced for every block a bundle carries by `Node::bundle_blocks_admitted` → `Node::header_door_admits` → `consensus::validate_carried_body_commitments` — **that enforcement ADDED 2026-09-08**; it was declared by the header and checked NOWHERE on this path. The STRIP residual is a real finding, stated in full below. |
/// | `blue_work` | PREIMAGE | below — **ADDED 2026-09-07** (was unbound: HOLE A3) |
/// | `genesis_commit` | PREIMAGE | below |
/// | `anchor_block.header` | PREIMAGE, by id | `anchor` below |
/// | `anchor_block` BODY | COMMITMENT when PRESENT; **NOT BOUND when STRIPPED** | identical to `tip_block`'s body row — same door, same residual |
/// | `anchor_blue_work` | PREIMAGE | below — **ADDED 2026-09-07** (was unbound: HOLE A3) |
/// | `anchor_blue_score` | PREIMAGE | below |
/// | `anchor_ordinal` | PREIMAGE | below — **ADDED 2026-09-07** (was unbound; found by this enumeration, not by the pin) |
/// | `fold_carry`'s two difficulty/MTP sample vectors | PREIMAGE | `carry_digest` — the `(timestamp, work)` samples, verbatim |
/// | `fold_carry.ancestors` / `.unfolded`: ids + `(blue_work, blue_score)` | PREIMAGE | `carry_digest` |
/// | `fold_carry.ancestors` / `.unfolded`: BLOCK BODIES | COMMITMENT when PRESENT; **NOT BOUND when STRIPPED** | `FoldCarry::digest` folds ids and blue data ONLY — the review proved a body edit leaves that digest byte-identical. The bodies are bound instead by the same door as the tip's, `Node::header_door_admits` on every carried block, **ADDED 2026-09-08**. |
///
/// ⛔ THE ONE ROW THAT IS STILL A FINDING — a STRIPPED body part, reported OPEN, not papered over.
/// The doors above judge a PRESENT body part against the commitment the miner sealed into the id
/// before the PoW, which no third party can reopen. A part that is ABSENT is admitted, because the
/// serve DELIBERATELY ships a reduced body — `Node::build_sync_bundle` blanks every sidecar,
/// `Node::unfolded_carry` blanks carried note payloads and `Node::header_shell` blanks all of them —
/// so "absent" is the honest shape on this path, not an attack signature. What that leaves a relay
/// is SUBTRACTION, never substitution: it can delete `tip_block.output_notes` and the adopter files
/// nothing at that address. Nothing false is installed and no value moves, but it is the findability
/// downgrade `Block::oli_tags` names ("a note nobody can LOCATE is a note nobody can spend"),
/// bounded by the by-id record lane that re-asks for a rid this node holds no bytes for. CLOSING it
/// is a DIFFERENT change from this one: the SHIPPED bytes must enter this preimage — a digest of the
/// reduced body, produced at the ONE site that builds it, so `current_chain_acc` and
/// `build_sync_bundle` can never fold different bytes — because no header commitment can bind a body
/// the header does not commit to. It is NOT closed here and must not be read as closed.
///
/// WHY EACH OF THE FOUR MATTERED, with the reader named:
/// * `blue_work` — `Node::instant_sync` refuses a bundle unless `(bundle.blue_work, tip) > (ours)`.
///   Typed `u128::MAX`, it beats every honest chain forever and the node is wedged off the mesh.
/// * `anchor_blue_work` — handed to `admit_anchor_block` → `Dag::add_anchor`, which decides the reorg
///   on it and then STORES it as that block's permanent `BlockNode::blue_work`. `add_anchor` CLEARS
///   the tip set on a win, so the honest chain is discarded, not merely outranked. The 2026-09-07
///   header-grind gate does NOT cover this: the grind binds `header.work`, the figure ON the header;
///   `anchor_blue_work` is a different number carried beside the block and compared to nothing.
/// * `anchor_ordinal` — stored by `instant_sync` as the anchor's record row, and every later record
///   position follows from it. A forged one hands the joiner a numbering the mesh does not share:
///   the record-spine split class (MEASURED 2026-09-04: p0 folded rid 238810 at ordinal 48, p1 at 9),
///   whose consequence is copaths that verify nowhere and a recipient balance that stays 0.
/// * `nf_cover_conf_acc` — installed as `SyncState::nf_cover_conf_acc` and drives the per-block decoy
///   stream. Not fund-safety, but a forged value desynchronises a joiner's cover from the mesh, which
///   is a privacy leak, and "not consensus-critical" is not a reason to leave a field a peer can type.
///
/// SCHEMA: a pre-fix peer folds a shorter preimage, so its `chain_acc` cannot equal what a fixed node
/// computes and its bundle is REFUSED (`FrontierUnbound`) — fail-closed, never silently adopted with
/// unbound weights. That refusal IS the version gate; both sides of a pair must roll together.
///
/// ⛔ WHAT THIS DOES **NOT** FIX, stated here because a binding is easy to mistake for soundness:
/// binding a field makes it unforgeable **by a third party who tampers with someone else's bundle**.
/// It does NOT make it unforgeable by the party that MINTS the bundle, because
/// `whir_decider::decider_prove_light(chain_acc)` takes the accumulator as its ONLY input and proves a
/// FIXED public AIR — anyone can mint a verifying proof for any accumulator they invent (pin D-1 in
/// `family_d_door_audit_tests.rs`). Until that prover takes the chain transition as a WITNESS, this
/// preimage is a consistency weld, not a certificate. See `adopt_sync_bundle`'s §9.6 answers.
///
/// § 9.6 ANSWERS FOR THIS DOOR are on [`adopt_sync_bundle`], which is the door; this function is the
/// preimage it compares against.
/// cons: 4 more fixed-size fields in a hashed preimage (56 bytes) on a path that runs once per adopt
/// and once per serve — no store, no growth on any axis, O(1) at any chain length.
/// ⛔⛔⛔ DB-376 — THE NOTE-FRONTIER SPINE IS THE SPINE AT THE ANCHOR'S POSITION, OR THE BUNDLE IS REFUSED.
///
/// Three facts, each on its own refused as `FrontierUnbound` before any state moves:
/// 1. the spine DECODES (`from_peaks_hex`; the wire encoding is fixed-width, so an empty string is never a spine —
///    `peaks_hex()` emits the encoding of count 0 for a frontier with nothing folded);
/// 2. its root REPRODUCES `frontier.root` (the root the certificate and the chain accumulator bind);
/// 3. its leaf count is exactly `anchor_ordinal × BLOCK_FIXED_NOTE_COUNT` — the leaf law the adopter's next fold would
///    otherwise fail forever ("[fold-leaf-law] ⛔ the spine holds 1024 leaves but the fold base at position 5 requires
///    1280"): a certified POSITION without the spine that produces it is a numbering nobody can extend.
///
/// MEASURED 2026-10-04: every jump fixture served a spine-less frontier and every jumper wedged at that line; a server
/// that strips the spine before proving produces a bundle that VERIFIES (the stripped spine is what it bound), so one
/// such bundle wedges every honest jumper. ROOT-LAYER: the ONE predicate both doors call — `adopt_sync_bundle` (the pure
/// verifier) and `Node::served_bundle_prefix_refusal` (the cheap exit before the proof verify).
/// cons: none — one spine decode the adopt already performs; a bundle refused here installed nothing.
#[must_use]
pub fn frontier_spine_binds(frontier: &FrontierSnapshot, anchor_ordinal: u64) -> bool {
    let Some(f) = crate::spend_frontier::PoseidonSpendFrontier::from_peaks_hex(&frontier.peaks_hex) else {
        return false;
    };
    crate::spend_frontier::leaf_to_cm_bytes(f.root()) == frontier.root
        && f.count() == anchor_ordinal.saturating_mul(crate::cover::BLOCK_FIXED_NOTE_COUNT as u64)
}

pub fn sync_binding(
    tip: &BlockId,
    blue_score: u64,
    frontier: &FrontierSnapshot,
    nullifier: &NullifierSnapshot,
    genesis_commit: &[u8],
    anchor: &BlockId,
    anchor_blue_score: u64,
    carry_digest: &[u8; 32],
    // The fork-choice weights and the record base. Appended (never inserted) so the existing call
    // sites read unchanged above and a transposition is a type error on three of the four.
    blue_work: u128,
    anchor_blue_work: u128,
    anchor_ordinal: u64,
) -> [u8; 16] {
    let mut buf = Vec::with_capacity(1 + 32 + 8 + 32 + 8 + 32 + 8 + genesis_commit.len());
    buf.push(0x29); // DSYNC domain separator
    buf.extend_from_slice(tip.as_bytes());
    buf.extend_from_slice(&blue_score.to_le_bytes());
    buf.extend_from_slice(&frontier.root);
    buf.extend_from_slice(&frontier.height.to_le_bytes());
    // ⭐ THE SPINE, HASHED — not "derived-bound" (review attack 3, 2026-09-08). The adopter INSTALLS
    // this peak spine, and the derivation that was claimed to bind it (`instant_sync` refuses a spine
    // that does not reproduce `frontier.root`) sits behind `if !peaks_hex.is_empty()`: a relay that
    // DELETED the field skipped the check and the bundle adopted — a field the adopter acts on riding
    // a valid proof unbound, the exact shape this completeness law exists to refuse. LENGTH-PREFIXED,
    // so the encoding stays injective against the fixed-width fields that follow, and so the EMPTY
    // spine (a fresh chain with nothing folded yet) is bound as the real value it is rather than as an
    // absence: a strip and an edit are then the same refusal, and no honest bundle is refused for
    // carrying no spine.
    // cons: none — the peak spine is the MMR PEAK set, `O(log2(leaves))` hex chars (`peaks_hex`), a
    // few hundred bytes at any chain length and the same bytes this bundle ALREADY carries on the
    // wire; this hashes them, it does not store or retain them. Arithmetic: at 2^40 leaves the spine
    // is 40 peaks x 32 B = 1.3 KB hashed ONCE per serve and ONCE per adopt — f(log height), not
    // f(history), with zero persisted bytes and no new term on any growth axis.
    buf.extend_from_slice(&(frontier.peaks_hex.len() as u64).to_le_bytes());
    buf.extend_from_slice(frontier.peaks_hex.as_bytes());
    buf.extend_from_slice(&nullifier.root); // Gap2: bind the spent-state so a peer can't forge it under a valid tip proof
    buf.extend_from_slice(&nullifier.count.to_le_bytes());
    buf.extend_from_slice(&nullifier.sparse_root); // SPARSE CUTOVER: certify the sparse root too (unforgeable O(1) jump)
    // ⭐ DB-353 P5: the band, the ordinal it waits at, and every awaiting step with its admitted set (or the unknown
    // marker) — every list length-prefixed, so no two different carriages share one encoding.
    buf.extend_from_slice(&(nullifier.band.len() as u64).to_le_bytes());
    for entry in &nullifier.band {
        for limb in entry {
            buf.extend_from_slice(&limb.to_le_bytes());
        }
    }
    buf.extend_from_slice(&nullifier.band_next_ordinal.to_le_bytes());
    buf.extend_from_slice(&(nullifier.band_awaiting.len() as u64).to_le_bytes());
    for (ordinal, block, admitted) in &nullifier.band_awaiting {
        buf.extend_from_slice(&ordinal.to_le_bytes());
        buf.extend_from_slice(block);
        match admitted {
            None => buf.push(0),
            Some(tags) => {
                buf.push(1);
                buf.extend_from_slice(&(tags.len() as u64).to_le_bytes());
                for t in tags {
                    buf.extend_from_slice(t);
                }
            }
        }
    }
    // ⭐ AND THE TOKEN REGISTRY. Unbound, a relay could hand a joiner a registry of its own choosing and
    // make it believe any asset exists — which is exactly what the mint gate was added to prevent. Length
    // first so a shorter peak list cannot be extended into a longer one with the same bytes.
    buf.extend_from_slice(&nullifier.dsol_registry_count.to_le_bytes());
    buf.extend_from_slice(&(nullifier.dsol_registry_peaks.len() as u64).to_le_bytes());
    for (h, d) in &nullifier.dsol_registry_peaks {
        buf.extend_from_slice(&h.to_le_bytes());
        buf.extend_from_slice(d);
    }
    // The confidential decoy accumulator the adopter installs verbatim: bound so a peer cannot
    // desynchronise a joiner's cover stream from the mesh under a valid tip proof.
    buf.extend_from_slice(&nullifier.nf_cover_conf_acc);
    for limb in &nullifier.nf_unspent_acc {
        buf.extend_from_slice(&limb.to_le_bytes()); // A_tip: certify the nf-unspent chain acc so a joiner can't be given a forged one (island fix)
    }
    // Certify the LETTER accumulator too — a joiner handed a forged letter anchor under a valid tip proof
    // would island its Letter stream exactly the way a forged A_tip islanded spends.
    buf.extend_from_slice(&nullifier.letter_acc);
    buf.extend_from_slice(&nullifier.dir_acc);
    // Certify the note-membership fold too: a joiner that adopts an unbound start could be handed one in
    // which a forged block root was already folded, and would then accept membership proofs for notes that
    // were never on this chain.
    for part in [
        nullifier.membership_tip.0,
        nullifier.membership_tip.1,
        nullifier.membership_tip.2,
    ] {
        for limb in &part {
            buf.extend_from_slice(&limb.to_le_bytes());
        }
    }
    // Certify the BONDED VALIDATOR SET (finality quorum): every collection is length-prefixed so the
    // encoding is injective, and the set is pre-sorted (export_state) so producer and adopter fold
    // byte-identical values. A stuffed/emptied quorum breaks the binding and the bundle is rejected.
    buf.extend_from_slice(&(nullifier.bonded_validators.len() as u64).to_le_bytes());
    for (id, bond) in &nullifier.bonded_validators {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&bond.to_le_bytes());
    }
    // SATOSHI §6: the finality seats are certified too (length-prefixed, pre-sorted by `finality_seats`)
    buf.extend_from_slice(&(nullifier.finality_validators.len() as u64).to_le_bytes());
    for (id, w) in &nullifier.finality_validators {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&w.to_le_bytes());
    }
    // G2b: the view at a height is certified with the seats (length-prefixed, pre-sorted by `seat_activations`) — a
    // relay that strips or moves an activation height changes the quorum a joiner judges with, so it breaks the binding.
    for v in [&nullifier.custody_seat_active_from, &nullifier.finality_seat_active_from] {
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        for (id, h) in v {
            buf.extend_from_slice(id);
            buf.extend_from_slice(&h.to_le_bytes());
        }
    }
    for v in [&nullifier.departed_custody_seats, &nullifier.departed_finality_seats] {
        buf.extend_from_slice(&(v.len() as u64).to_le_bytes());
        for (id, w, from, until) in v {
            buf.extend_from_slice(id);
            buf.extend_from_slice(&w.to_le_bytes());
            buf.extend_from_slice(&from.to_le_bytes());
            buf.extend_from_slice(&until.to_le_bytes());
        }
    }
    // §BR-3 17.3/17.6: the seat words are certified with the seats (length-prefixed, pre-sorted by `seat_words`): the
    // delegated word, the own-yield index (a presence byte, then 16 bytes) and the own-yield accrual
    buf.extend_from_slice(&(nullifier.seat_words.len() as u64).to_le_bytes());
    for (id, d, last, accrued) in &nullifier.seat_words {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&d.to_le_bytes());
        buf.push(u8::from(last.is_some()));
        buf.extend_from_slice(&last.unwrap_or(0).to_le_bytes());
        buf.extend_from_slice(&accrued.to_le_bytes());
    }
    buf.extend_from_slice(&(nullifier.slashed_validators.len() as u64).to_le_bytes());
    for id in &nullifier.slashed_validators {
        buf.extend_from_slice(id);
    }
    buf.extend_from_slice(&nullifier.slashed_bond_burned.to_le_bytes());
    for limb in &nullifier.validator_bond_commit {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&(nullifier.validator_custody.len() as u64).to_le_bytes());
    for (id, secp33, ed32) in &nullifier.validator_custody {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&(secp33.len() as u64).to_le_bytes());
        buf.extend_from_slice(secp33);
        buf.extend_from_slice(ed32);
    }
    // The custodian encapsulation keys, length-prefixed like the custody points above (2026-09-17): an
    // adopter SEALS peg-in deltas to these, so a relay that swapped one in would read a custodian's
    // deltas. Same schema rule: a pre-fix peer folds a shorter preimage and its bundle is refused.
    buf.extend_from_slice(&(nullifier.validator_kem_eks.len() as u64).to_le_bytes());
    for (id, ek) in &nullifier.validator_kem_eks {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&(ek.len() as u64).to_le_bytes());
        buf.extend_from_slice(ek);
    }
    // SAFE AT SCALE: the custody seat numbers are certified with the seats (length-prefixed, pre-sorted by
    // `custody_seats`) — a relay that moves one moves a custodian into another vault's quorum, so it breaks the binding.
    buf.extend_from_slice(&(nullifier.custody_seat_numbers.len() as u64).to_le_bytes());
    for (id, seat) in &nullifier.custody_seat_numbers {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&seat.to_le_bytes());
    }
    // §DD: the peg ledger's certified view rides the binding — a bundle cannot hand a joiner a forged
    // reserve, minted supply, high-water mark or ratio.
    for d in [
        &nullifier.peg_reserve_commit,
        &nullifier.peg_minted_commit,
        &nullifier.peg_reserve_hwm_commit,
    ] {
        for limb in d.iter() {
            buf.extend_from_slice(&limb.to_le_bytes());
        }
    }
    // §DD-b: the recent one-time ids ride the binding too — a forged or emptied ring breaks the proof.
    for (id, kind) in &nullifier.applied_one_time_ids {
        buf.extend_from_slice(id);
        buf.push(*kind);
    }
    buf.extend_from_slice(&nullifier.peg_ratio_bps.to_le_bytes());
    buf.extend_from_slice(&nullifier.peg_redeem_floor_bps.to_le_bytes());
    buf.extend_from_slice(&nullifier.peg_yield_rate_bps.to_le_bytes());
    // DB-251: the chain's price marks ride the binding, length-prefixed so the preimage stays injective. A forged,
    // added or dropped mark breaks the proof exactly as a forged reserve does.
    buf.extend_from_slice(&(nullifier.peg_price_marks.len() as u64).to_le_bytes());
    for (asset, price, epoch) in &nullifier.peg_price_marks {
        buf.extend_from_slice(&asset.to_le_bytes());
        buf.extend_from_slice(&price.to_le_bytes());
        buf.extend_from_slice(&epoch.to_le_bytes());
    }
    // DB-259: the bond locks ride the binding, length-prefixed at both levels so the preimage stays injective. A
    // forged, added or dropped anchor or locked note breaks the proof exactly as a forged mark does.
    buf.extend_from_slice(&(nullifier.bond_heights.len() as u64).to_le_bytes());
    for (id, h) in &nullifier.bond_heights {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&h.to_le_bytes());
    }
    buf.extend_from_slice(&(nullifier.bond_locked_notes.len() as u64).to_le_bytes());
    for (id, note) in &nullifier.bond_locked_notes {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&(note.len() as u64).to_le_bytes());
        buf.extend_from_slice(note);
    }
    // DB-274 P2 (§8.7): the unbonding collateral rides the binding, every field length-prefixed or fixed-width, so a
    // forged, added, dropped or re-dated entry (a stolen release, a shortened window) breaks the proof.
    buf.extend_from_slice(&(nullifier.unbonding.len() as u64).to_le_bytes());
    for (id, u) in &nullifier.unbonding {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&u.due_blue.to_le_bytes());
        // A-F60: the window's time half rides the binding too, so a re-dated tick breaks the proof like a re-dated score
        buf.extend_from_slice(&u.due_tick.to_le_bytes());
        buf.extend_from_slice(&u.amount.to_le_bytes());
        buf.extend_from_slice(&(u.note.len() as u64).to_le_bytes());
        buf.extend_from_slice(&u.note);
        // DB-273 §19.3 L2: the returned note's owner is its OLI clue (length-prefixed), in place of (bucket, ek).
        buf.extend_from_slice(&(u.owner_clue.len() as u64).to_le_bytes());
        buf.extend_from_slice(&u.owner_clue);
    }
    // DB-271: the wrapped-asset registry rides the binding, length-prefixed, each digest limb by limb exactly as the
    // §DD peg commitments above. A forged, added or dropped asset breaks the proof.
    buf.extend_from_slice(&(nullifier.peg_wrapped_assets.len() as u64).to_le_bytes());
    for (asset, reserve, minted, ratio, hwm) in &nullifier.peg_wrapped_assets {
        buf.extend_from_slice(&asset.to_le_bytes());
        for d in [reserve, minted, hwm] {
            for limb in d.iter() {
                buf.extend_from_slice(&limb.to_le_bytes());
            }
        }
        buf.extend_from_slice(&ratio.to_le_bytes());
    }
    // LIQUIDATION §10: the pool words ride the binding the same way — a forged, added or dropped pool breaks the proof.
    buf.extend_from_slice(&(nullifier.peg_pools.len() as u64).to_le_bytes());
    for (asset, w) in &nullifier.peg_pools {
        buf.extend_from_slice(&asset.to_le_bytes());
        for d in [&w.t, &w.p, &w.s] {
            for limb in d.iter() {
                buf.extend_from_slice(&limb.to_le_bytes());
            }
        }
        buf.extend_from_slice(&w.epoch.to_le_bytes());
    }
    // A-F50: the IonSwap pool book — the pending orders as one digest (count-prefixed, so a dropped or added order changes
    // it), plus the USDm held and the pool count. A forged order breaks the proof exactly as a forged pool word does.
    buf.extend_from_slice(ion_pending_digest(&nullifier.peg_ion_pending).as_bytes());
    buf.extend_from_slice(&nullifier.peg_ion_usdm_held.to_le_bytes());
    buf.extend_from_slice(&nullifier.peg_ion_pools.to_le_bytes());
    // DB-357 part 1: the retention endowment's commitment (limb by limb, as §DD), the L2 settlement root, and the
    // root-history spine LENGTH-PREFIXED (so a strip and an edit are the same refusal, and the preimage stays injective).
    for limb in nullifier.peg_retention_endowment_commit.iter() {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&nullifier.l2_state_root);
    buf.extend_from_slice(&(nullifier.root_history_peaks_hex.len() as u64).to_le_bytes());
    buf.extend_from_slice(nullifier.root_history_peaks_hex.as_bytes());
    buf.extend_from_slice(genesis_commit);
    // v31: the fold-root anchor the adopter grafts its DAG at — bound so it cannot be forged under a valid proof.
    buf.extend_from_slice(anchor.as_bytes());
    buf.extend_from_slice(&anchor_blue_score.to_le_bytes());
    buf.extend_from_slice(carry_digest); // bind the genesis identity the chain roots at
    // ⭐ THE FORK-CHOICE WEIGHTS AND THE RECORD BASE (holes A3/A4, 2026-09-07). These three are the
    // numbers the adopter ACTS on — the NotHeavier comparison, `Dag::add_anchor`'s reorg-and-store,
    // and the anchor's record row — and until this line they were the only acted-on fields outside
    // the preimage. They are appended AFTER the variable-length `genesis_commit`, which keeps the
    // encoding injective (everything past it is fixed width, so the preimage parses from the end).
    buf.extend_from_slice(&blue_work.to_le_bytes());
    buf.extend_from_slice(&anchor_blue_work.to_le_bytes());
    buf.extend_from_slice(&anchor_ordinal.to_le_bytes());
    // ⭐ SATOSHI: the issued SAT total and the pendulum snapshot — fixed width, after the fixed-width weights, so the
    // preimage still parses from the end. A forged total or share breaks the proof exactly as a forged reserve does.
    buf.extend_from_slice(&nullifier.peg_sat_issued.to_le_bytes());
    buf.extend_from_slice(&nullifier.peg_pendulum.0.to_le_bytes());
    buf.extend_from_slice(&nullifier.peg_pendulum.1.to_le_bytes());
    // G2g-r2a: the quantized fold base words — fixed width, after the SAT words, so the preimage still parses from the end.
    let (fb, fseq, fprev, fbound) = &nullifier.nf_fold_base_words;
    for limb in fb.iter().chain(fprev.iter()) {
        buf.extend_from_slice(&limb.to_le_bytes());
    }
    buf.extend_from_slice(&fseq.to_le_bytes());
    buf.extend_from_slice(&fbound.to_le_bytes());
    // G2g-r2a step 2: the fold-span member list, as one fixed-width digest (count-prefixed, so a dropped or added member
    // and a moved score or weight each change it).
    buf.extend_from_slice(fold_span_digest(&nullifier.nf_fold_span).as_bytes());
    // ⭐ §BR: the §BR ledger words (pools, quarters, yield index, set-aside, stake snapshot + paid-out total, deployments,
    // attestations) as one fixed-width digest, last — the preimage still parses from the end.
    buf.extend_from_slice(&nullifier.peg_br.digest());
    // ⭐ A-F114 U2: the canonical chain the state stands on (fixed width, after §BR)
    buf.extend_from_slice(&nullifier.canon.index.to_le_bytes());
    buf.extend_from_slice(&nullifier.canon.c);
    buf.extend_from_slice(&nullifier.canon.window);
    for s in [nullifier.canon.seqs.0, nullifier.canon.seqs.1, nullifier.canon.seqs.2] {
        buf.extend_from_slice(&s.to_le_bytes());
    }
    let h = Hash32::hash(&buf);
    let mut acc = [0u8; 16];
    acc.copy_from_slice(&h.as_bytes()[..16]);
    acc
}

/// The state a node installs on a successful instant-sync — the O(1) jump target. Rides the checkpoint as held (v47).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SyncState {
    /// ⭐ THE PROVEN ACCUMULATED WORK, carried out of the certificate. Fork choice reads THIS, never the
    /// bundle's declared `blue_work` — a header's weight is a number the server typed, and the whole
    /// point of the certificate is that this one is not.
    pub proven_work: u128,
    pub tip: BlockId,
    pub blue_score: u64,
    pub frontier_root: [u8; 32],
    pub height: u64,
    /// The CERTIFIED nullifier spent-state (Gap2), carried and bound into `sync_binding`.
    /// ⛔ NOT INSTALLED ANYWHERE — see [`NullifierSnapshot`]. The adopter takes `nullifier_count` (into
    /// `nf_blocks`/`nf_leaves`/`nf_fold_seq`) and gets its double-spend gate from `sparse_root` below.
    /// The retired IMT (`nullifier_tree`) is called by nothing in production.
    pub nullifier_root: [u8; 32],
    pub nullifier_count: u64,
    /// SPARSE CUTOVER — the CERTIFIED sparse nullifier-acc root the adopter installs O(1) via
    /// [`crate::node::Node::adopt_sparse_snapshot`], so a jumped node's sparse double-spend gate is warm immediately
    /// (no rebuild). Bound into `sync_binding`; a zero value (older bundle) means "rebuild sparse from the stream".
    pub sparse_root: [u8; 32],
    /// ⭐ DB-353 P5 — the certified band, the fold ordinal it waits at, and the awaiting steps with their admitted sets
    /// (see [`NullifierSnapshot::band`]), installed by the adopter through `BandDoor::adopt_certified`.
    pub band: Vec<crate::spend_frontier::Digest4>,
    pub band_next_ordinal: u64,
    pub band_awaiting: Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)>,
    /// ⭐ THE DSOL TOKEN REGISTRY, CARRIED — see `NullifierSnapshot`'s copy for why a jumped node cannot
    /// rebuild it and why it is bound into `sync_binding`.
    /// O1-FOOTPRINT-REVIEWED: bounded by crate::dsol::MMR_MAX_PEAKS — one peak per set bit of a u128 count.
    pub dsol_registry_peaks: Vec<(u32, [u8; 32])>,
    /// The registry's append count, beside the peaks it must describe.
    pub dsol_registry_count: u128,
    /// The CONFIDENTIAL real-spend-blob accumulator (Ask 2 idle-privacy closure) the adopter installs so its
    /// per-block decoy stream stays in lockstep with the mesh from the instant it jumps to tip.
    pub nf_cover_conf_acc: [u8; 32],
    /// The verified chain's genesis identity, so the adopter can converge its OWN genesis/chain_id onto the
    /// canonical chain it just proved (a fresh node's plain-genesis bootstrap becomes the canonical genesis).
    pub genesis_commit: Vec<u8>,
    /// The CERTIFIED nf-unspent chain acc (A_tip) the adopter installs, so a jumped node's O(1) absence-proof
    /// endpoint is correct the instant it reaches tip — no history replay. Bound into `sync_binding` above so a peer
    /// cannot forge it (island fix). A zero value (older bundle) = the genesis seed.
    /// O1-INFINITY-REVIEWED: a FIXED 4-limb (32-byte) accumulator, not a per-item store — its size is a compile-time
    /// constant at 0 blocks OR 10^18 (it is the one folded root, never count-bounded); adopted verbatim, never rebuilt.
    pub nf_unspent_acc: crate::spend_frontier::Digest4,
    /// The CERTIFIED unspent-note root (deletion model) the adopter installs; a foreign value flips its
    /// catch-up map NOT_READY and the ledger-replay self-heal converges it to this exact root.
    /// The CERTIFIED note-membership tip `(prev, root, acc)` the adopter installs, so a wallet talking to a
    /// jumped node can build a carrier from a start that node actually vouches for.
    /// O1-INFINITY-REVIEWED: three FIXED 4-limb accumulators, constant at any height; adopted, never rebuilt.
    pub membership_tip: (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4),
    /// The CERTIFIED bonded validator set (finality quorum) the adopter installs verbatim — what lets a
    /// jumped node weigh finality votes immediately (see the `NullifierSnapshot` field doc).
    pub bonded_validators: Vec<([u8; 32], u128)>,
    /// ⭐ SATOSHI §6 — the FINALITY seats (USDm bonds, free membership seats): certified beside the custody set.
    pub finality_validators: Vec<([u8; 32], u128)>,
    /// G2b: the seats' activation heights and departed rows, certified beside them (see `NullifierSnapshot`).
    pub custody_seat_active_from: Vec<([u8; 32], u64)>,
    pub finality_seat_active_from: Vec<([u8; 32], u64)>,
    pub departed_custody_seats: Vec<([u8; 32], u128, u64, u64)>,
    pub departed_finality_seats: Vec<([u8; 32], u128, u64, u64)>,
    /// §BR-3 17.3: each custody seat's delegated weight, certified beside the seats (see `NullifierSnapshot`).
    pub seat_words: Vec<crate::validator::SeatWords>,
    pub slashed_validators: Vec<[u8; 32]>,
    pub slashed_bond_burned: u128,
    pub validator_bond_commit: crate::spend_frontier::Digest4,
    pub validator_custody: Vec<([u8; 32], Vec<u8>, [u8; 32])>,
    /// The CERTIFIED custodian encapsulation keys the adopter installs beside the custody points.
    /// O1-FOOTPRINT-REVIEWED: bounded by PEG_ATTEST_SEALED_MAX (one per bonded custodian)
    pub validator_kem_eks: Vec<([u8; 32], Vec<u8>)>,
    /// SAFE AT SCALE — the CERTIFIED custody seat numbers the adopter installs beside the seats (its custody vaults are
    /// read from them). O1-FOOTPRINT-REVIEWED: one row per bonded custodian.
    pub custody_seat_numbers: Vec<([u8; 32], u64)>,
    /// ⭐ THE PEG LEDGER'S CERTIFIED VIEW (§DD, 2026-09-17). A joiner that JUMPS never replays the peg
    /// transactions it skipped, so before this the reserve/minted commitments it held after a jump were its
    /// own stale (or genesis) values: a jumped custodian could neither attest nor execute against the
    /// chain's real reserve, and an executor's published mint rode a chain it then left (DB-5). Bound
    /// into `sync_binding`, so a bundle cannot hand a joiner a forged reserve. Fixed width: three digests
    /// and three parameters. The one-time-use id sets (`spent_burns`, deposit ids, `released`,
    /// `liquidated`) are NOT here — kill list §DD names the nullifier accumulator they must move into.
    pub peg_reserve_commit: crate::spend_frontier::Digest4,
    pub peg_minted_commit: crate::spend_frontier::Digest4,
    pub peg_reserve_hwm_commit: crate::spend_frontier::Digest4,
    /// §DD-b (2026-09-18): the (one-time id, kind) pairs of the peg transitions the certified chain applied
    /// most recently — deposits minted, burns, releases, liquidations — so a JOINER inherits the replay
    /// guard for them instead of an empty RAM-only set (the jumped-majority double-mint edge). Bound into
    /// `sync_binding`. O1-FOOTPRINT-REVIEWED: bounded by APPLIED_ONE_TIME_ID_RING_MAX
    pub applied_one_time_ids: Vec<([u8; 32], u8)>,
    pub peg_ratio_bps: u32,
    pub peg_redeem_floor_bps: u32,
    pub peg_yield_rate_bps: u32,
    /// DB-251 — the CERTIFIED price marks the adopter installs verbatim (see the `NullifierSnapshot` field doc).
    pub peg_price_marks: Vec<(u32, u128, u64)>,
    /// DB-259 — the CERTIFIED bond locks (maturity anchors and locked notes) the adopter installs verbatim (see the
    /// `NullifierSnapshot` field doc).
    pub bond_heights: Vec<([u8; 32], u64)>,
    pub bond_locked_notes: Vec<([u8; 32], Vec<u8>)>,
    /// DB-274 P2 (§8.7) — the CERTIFIED unbonding collateral the adopter installs verbatim (see the
    /// `NullifierSnapshot` field doc).
    pub unbonding: Vec<([u8; 32], crate::node::Unbonding)>,
    /// DB-271 — the CERTIFIED wrapped-asset registry the adopter installs verbatim (see the `NullifierSnapshot`
    /// field doc).
    pub peg_wrapped_assets: Vec<(u32, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, u32, crate::spend_frontier::Digest4)>,
    /// LIQUIDATION §10 — the CERTIFIED stability-pool words the adopter installs verbatim.
    pub peg_pools: Vec<(u32, crate::peg::PoolWords)>,
    /// A-F50 — the CERTIFIED IonSwap pool book the adopter installs verbatim (see the `NullifierSnapshot` field doc).
    /// Bound into `sync_binding`.
    pub peg_ion_pending: Vec<crate::ion_pool_tx::IonPending>,
    pub peg_ion_usdm_held: u64,
    pub peg_ion_pools: u64,
    /// The CERTIFIED letter accumulator the adopter installs verbatim — the Letter stream anchor
    /// (see the `NullifierSnapshot` field doc). Bound into `sync_binding`, so it cannot be forged.
    pub letter_acc: [u8; 32],
    /// The CERTIFIED directory accumulator — on mismatch with the local fold, the adopter resets its
    /// registry and refills to exactly this endpoint through the verified door. Bound into `sync_binding`.
    pub dir_acc: [u8; 32],
    /// DB-357 part 1 — the CERTIFIED retention-endowment commitment, L2 settlement root and root-history spine the
    /// adopter installs verbatim (see the `NullifierSnapshot` field docs). Bound into `sync_binding`.
    pub peg_retention_endowment_commit: crate::spend_frontier::Digest4,
    pub l2_state_root: [u8; 32],
    pub root_history_peaks_hex: String,
    /// ⭐ SATOSHI — the CERTIFIED issued SAT total and pendulum snapshot the adopter installs verbatim (see the
    /// `NullifierSnapshot` field doc). Bound into `sync_binding`.
    pub peg_sat_issued: u64,
    pub peg_pendulum: (u64, u32),
    /// ⭐ §BR — the §BR ledger words (`peg::PegBrWords`), bound into `sync_binding` by their digest.
    #[serde(default)]
    pub peg_br: crate::peg::PegBrWords,
    /// G2g-r2a — the CERTIFIED quantized fold base words the adopter holds PENDING (see the `NullifierSnapshot` field doc).
    pub nf_fold_base_words: (crate::spend_frontier::Digest4, u64, crate::spend_frontier::Digest4, u64),
    /// G2g-r2a — the CERTIFIED fold-span members (id, blue_work, blue_score) whose bodies the adopter places before it
    /// switches to `nf_fold_base_words`. Bound into `sync_binding` (`fold_span_digest`).
    pub nf_fold_span: Vec<([u8; 32], u128, u64)>,
    /// ⭐ A-F114 U2 — the CERTIFIED canonical chain (see the `NullifierSnapshot` field doc); the adopter pulls its window.
    #[serde(default)]
    pub canon: crate::canon_chain::CanonState,
}

/// Outcome of an adopt attempt. `Adopted` carries the state to install; every rejection leaves the
/// node on its current state (fail-closed, never a halt).
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum AdoptOutcome {
    /// Verified + bound: jump to this state.
    Adopted(SyncState),
    /// The decider proof did not verify (bad / tampered / oversize / empty).
    Unverified,
    /// The decider verified but its accumulator does not bind the offered frontier (forged DA state).
    FrontierUnbound,
    /// The bundle is a VALID proof of a DIFFERENT chain — its `genesis_commit` is not this node's genesis, so
    /// grafting it would fork the node onto a foreign chain. Fail-closed: a node converges ONLY with peers that
    /// share its exact genesis, so a coexisting foreign-genesis producer can never poison the DAG (deterministic,
    /// split-proof cross-device convergence). Enforced in [`crate::node::Node::instant_sync`], which holds the
    /// node's own genesis identity (this pure `adopt_sync_bundle` verifies bundle-internal consistency only).
    GenesisMismatch,
    /// The bundle verified and shares our genesis, but proves a chain position NO HEAVIER than the tip this
    /// node already stands on under the deterministic GHOSTDAG total order `(blue_work, tip id)`. This is the
    /// ORDINARY level-peer steady state — or a stale Tor-delayed / unsolicited response — and it is refused so
    /// a certified-but-OLD bundle can never walk a node's state layer backwards (nullifier root, unspent-note
    /// root, fold base). Without this gate a live pair FLAPS: each side keeps installing the other's older
    /// position (MEASURED 2026-08-26 gate run 12, adopt trail 998→1080→964 on one node, 1010→962 on the
    /// other) and `unspent_root`/height never reconverge. The heavier-only rule is exactly the promise the
    /// beacon filter already makes (`blue_work > ours`); this enforces it where the install actually happens.
    /// Enforced in [`crate::node::Node::instant_sync`], which holds the node's own tip (this pure
    /// `adopt_sync_bundle` verifies bundle-internal consistency only).
    NotHeavier,
    /// The bundle's whole-chain certificate did not verify, or it certifies a DIFFERENT chain position
    /// than the one the bundle declares. ⛔ This is the join door's certificate half: without it a
    /// server that holds no chain can mint an accumulator and every field bound to it rides along
    /// (kill list §AH/§AJ). Fail-closed — a node never installs state on an uncertified claim.
    CertificateUnproven,
}

/// Adopt a #29 DSYNC bundle: verify-once, bind the frontier, jump. Fail-closed on either check; the
/// node never adopts a tip it cannot verify, and never installs a frontier the proof does not commit
/// to. This is the ONLY sync path — no block-by-block replay exists.
///
/// ⛔⛔ §9.6 NEW-DOOR CHECKLIST — THE #29 DSYNC CERTIFIED-BUNDLE ADOPT (answered 2026-09-07, before
/// the edit; the honest answers, including the two that are still NO).
///
/// 1. **PROOF OF WORK** — *on this path, partly, and only since 2026-09-07.* `adopt_sync_bundle`
///    itself verifies no grind (it holds no PoUW hasher, by construction: it is the pure gate). The
///    node-level door `Node::instant_sync` now runs the shared `Node::header_grind_admits` over EVERY
///    block a bundle carries — `tip_block`, `anchor_block`, `fold_carry.ancestors`,
///    `fold_carry.unfolded` — and refuses the WHOLE bundle before any field is installed. Before that
///    the grind ran only at the three placement doors (`add_anchor` / `add_ancestor_anchor` /
///    `add_carried_block`), so a refused anchor still returned `Adopted` and the state fields — the
///    quorum included — landed anyway. RESIDUAL, NOT CLOSED HERE: the target compare
///    `H · work ≤ 2^256 − 1` is satisfied by EVERY digest at `work = 1`, so a fabrication claiming
///    the cheapest work still shows a grind for free. The gossip door's answer is the DAA equality
///    `header.work == miner::adaptive_work(dag, selected_parent)`, which the descent door adopted on
///    2026-09-07 — but THIS door cannot run it: a jumping adopter holds none of the carried tip's
///    ancestry (that is why it is jumping), so it has nothing to compute the expected difficulty
///    from. Closing it needs the bundle to carry the difficulty samples for the TIP's parents the
///    way `FoldCarry`'s per-anchor samples already do for the fold root — and those are only worth
///    something once question 2 is answered, since a self-minting peer chooses them too. Reported,
///    not assumed. MEASURED 2026-09-07: family-D pin D-4's `work = 1` shell is refused here by the
///    tx-merkle half of the header door (its `tx_merkle_root` does not commit to its own empty tx
///    list), NOT by the grind — a fabrication that gets that root right still walks through.
/// 2. **PROOF / SIGNATURE** — ⛔ **NO. This is the door's open hole (D01/Q2), and it is a DESIGN
///    ITEM, not an omission.** What verifies the bundle is `accept_bundle` →
///    `whir_decider::WhirDecider` → `usdm_decider::whole_chain::verify_whole_chain_light_decider_bytes`.
///    That verifier rebuilds a FIXED public AIR (`build_whole_chain_artifacts(t)`, which reads nothing
///    from any chain) and checks openings under a transcript seeded with `chain_acc`. Its prover,
///    `decider_prove_light(chain_acc)`, takes the accumulator as its ONLY argument. So the pair
///    attests exactly one fact — "somebody ran the public prover with THIS 16-byte value" — and every
///    party, including one holding no chain, can produce it. MEASURED (pin D-2): a node running the
///    PRODUCTION verifier returned `Adopted(SyncState { blue_score: 9_999_999 })` for a bundle whose
///    every field the attacker chose. The FIX is stated on `SyncBundle` and in this lane's report: the
///    whole-chain decider must take the chain transition as a WITNESS and constrain it. It cannot be
///    landed by binding more fields, and pretending otherwise is what the tree's old comments did.
/// 3. **CONSERVATION** — this path mints no note and folds no value: it INSTALLS certified roots
///    (`unspent_note_root`, `nullifier.root/count`, `sparse_root`, `nf_unspent_acc`, `membership_tip`)
///    and the finality quorum. It cannot inflate a balance directly, but a forged root IS whole-state
///    substitution, and the only thing standing between a peer and that substitution is question 2.
///    So conservation on this door is exactly as sound as the certificate, i.e. NOT YET SOUND. Every
///    installed field is at least in the binding preimage (see `sync_binding`'s completeness table) —
///    that closes third-party tamper, not self-minting.
/// 4. **REPLAY** — a re-served identical bundle is refused by the `NotHeavier` gate in
///    `Node::instant_sync`, which compares `(blue_work, tip)` against this node's own position under
///    the DAG's deterministic total order — a comparison against held state, not a cache. Since
///    2026-09-07 `blue_work` is inside the binding, so a replayer cannot re-weight an old bundle to
///    beat that gate. A bundle for a tip this node already holds re-installs the same values.
/// 5. **BOUNDED WORK** — `accept_bundle`'s size gate (≤1.8MB) runs BEFORE the verify; the decider
///    trace is the pinned `WHOLE_CHAIN_T = 32` shape, identical work at any chain length; the carry is
///    bounded by fixed constants (`daa_sample_len` samples, depth × DAG width ancestors,
///    `record_fold_depth` unfolded blocks) as stated on `FoldCarry`; the grind loop added at
///    `instant_sync` is one Poseidon2 hash per carried block over that same bounded set. Nothing here
///    walks history, and nothing is retained on a refusal.
/// 6. **PARITY WITH THE DOOR IT PARALLELS** — the reference door is `Node::preverify_block` (the
///    gossip ingress). Checks it runs, and whether this path carries them:
///    * header grind — reference YES; this path YES since 2026-09-07 (question 1), with the `work<=1`
///      vacuity above as a shared residual on BOTH doors.
///    * `verify_block_pow` with the witness — reference YES; this path NO and CANNOT: the serve side
///      builds `tip_block`/`anchor_block` with `pow_proof: Vec::new()` (`build_sync_bundle`), because
///      the DAG retains header + tx ids only. The header-only grind is the half that survives without
///      a witness, and it is the half taken.
///    * tx-merkle re-hash of the body against `header.tx_merkle_root` — reference YES (and
///      `graft_block_shell_from_trusted_id` runs it too); this path NO. NAMED, NOT CLOSED by this
///      lane: the carried bodies are `tx_ids` + the tip's note payload, and the note payload's own
///      admission is the record/graft lane's `graft_admitted_notes`. Reported as an open parity gap.
///    * settlement / nullifier carrier verifies — reference YES; this path NO, and no node retains
///      the witnesses to re-run them for a folded block. This is the substitution the whole-chain
///      certificate is SUPPOSED to stand in for, which is why question 2 is the door's real answer.
///    * genesis identity — this path runs a check the reference does not (`GenesisMismatch`).
///    * fork-choice ordering — this path runs `NotHeavier`, which the reference has no analogue for.
///
/// ⭐⭐ A-F49 (lane goods, 2026-11-12) — WHICH PROOF AUTHENTICATES WHICH BUNDLE. `joined_by_work` is the verdict of the
/// join door (`join_proof::verify_join`, through `Node::join_verdict`: at least `VOUCHERS` mined headers above the anchor
/// that vouch for its fold and band commits, and a work estimate the declared total must meet) for THIS bundle, or `None`.
/// Every proof a bundle CARRIES is verified, whatever authenticated it: a carried decider proof that does not verify is
/// `Unverified`, a carried certificate that does not verify or does not stand for this bundle is `CertificateUnproven`.
/// A proof the bundle does NOT carry is demanded unless the join door authenticated the bundle by work: with `None`, D01
/// holds exactly as it landed (no decider proof: `Unverified`; no certificate: `CertificateUnproven`).
/// WHAT WAS WRONG (measured on three real nodes, 2026-11-12 17:16-17:32, finding A-F49): the bundles a node serves to a
/// joiner by work (`serve_join_bundle` over `join_frozen`, drafted by `draft_sync_bundle`) carry NO decider proof and
/// NO certificate (an empty certificate field, which `WholeChainCertWire::to_proof` reads as absent), by design since
/// joining by work (2026-11-06): their authority is the join door's work vouchers. D01 demanded both of every bundle, so every honest join bundle passed the join door and was then refused
/// `Unverified`: a wiped node at height 290 took 14 bundles from two peers and adopted none in 901 s. No node could join a
/// chain deeper than its block lanes could carry.
/// AI RESISTANT: (a) proofs every node checks — the join door's work vouchers, and any decider proof or certificate the
/// bundle carries. A lying server gains nothing it could not gain past the join door alone: a bundle with no proof at
/// all still needs a verdict, which only the door gives. SCALE: no term in the bonded set or height.
pub fn adopt_sync_bundle(
    verifier: &dyn ConsensusVerifier,
    joined_by_work: Option<&crate::join_proof::JoinVerdict>,
    bundle: &SyncBundle,
) -> AdoptOutcome {
    // 1) size gate + decider verify — fail-closed when no verifier is installed; a bundle the join door authenticated by
    // work need not carry a decider proof, and one it carries is verified all the same.
    let decider_carried = !bundle.decider.proof.is_empty();
    if (joined_by_work.is_none() || decider_carried) && !accept_bundle(verifier, &bundle.decider) {
        return AdoptOutcome::Unverified;
    }
    // 2) bind the frontier AND the genesis identity to the verified accumulator — reject a forged/swapped
    // frontier OR a lied genesis (a peer serving a valid tip proof but claiming the wrong root genesis).
    let expected = sync_binding(
        &bundle.decider.tip,
        bundle.decider.blue_score,
        &bundle.frontier,
        &bundle.nullifier,
        &bundle.genesis_commit,
        &bundle.anchor_block.id(),
        bundle.anchor_blue_score,
        &bundle.fold_carry.digest(),
        bundle.blue_work,
        bundle.anchor_blue_work,
        bundle.anchor_ordinal,
    );
    if bundle.anchor_blue_score > bundle.decider.blue_score {
        return AdoptOutcome::FrontierUnbound; // the anchor lies at or below the certified tip, never above
    }
    if bundle.decider.chain_acc != expected {
        return AdoptOutcome::FrontierUnbound;
    }
    // 2b) the carried tip block MUST be the very tip the proof certified — a forged/swapped tip block
    // paired with a valid proof is rejected (else a peer could graft an unrelated block as the anchor).
    if bundle.tip_block.id() != bundle.decider.tip {
        return AdoptOutcome::FrontierUnbound;
    }
    // DB-357 part 1: the carried root-history spine must be a spine. The binding above already refuses an edited one;
    // this refuses a malformed one a server bound honestly, so the installer never meets a spine it cannot restore.
    if crate::spend_frontier::PoseidonSpendFrontier::from_peaks_hex(&bundle.nullifier.root_history_peaks_hex).is_none() {
        return AdoptOutcome::FrontierUnbound;
    }
    // ⛔⛔⛔ DB-376: the note-frontier spine must decode, reproduce the certified root, and be the spine AT the anchor's
    // position (docs/DB-376-SPINELESS-BUNDLE-REFUSAL.md). The same question the node's pre-check asks before the
    // proof verify; asked here too so the pure verifier refuses it on every path.
    if !frontier_spine_binds(&bundle.frontier, bundle.anchor_ordinal) {
        return AdoptOutcome::FrontierUnbound;
    }
    // ⛔ D01 CERT GATE: the whole-chain certificate must VERIFY and must attest THIS bundle's position.
    // Without this gate every field above rides a `chain_acc` the server chose — a party holding no chain
    // can mint an accumulator and every field bound to it (kill list §AH/§AJ, pin D-1, finding CERT).
    // A-F49: a bundle the join door authenticated by work need not carry a certificate; one it carries is held to all of
    // the checks below.
    match bundle.cert.to_proof() {
        None if joined_by_work.is_some() => {}
        None => return AdoptOutcome::CertificateUnproven,
        Some(cert_proof) => {
            if !usdm_decider::whole_chain_cert::verify_whole_chain_cert(&cert_proof) {
                return AdoptOutcome::CertificateUnproven;
            }
            let expected_summary = bundle_chain_summary(
                &bundle.decider.tip,
                bundle.decider.blue_score,
                bundle.blue_work,
                &bundle.frontier,
                &bundle.nullifier,
                &bundle.genesis_commit,
                &bundle.anchor_ring,
                &bundle.member_ring_commits,
            );
            // The position a certificate STANDS FOR is its `tip_summary`: `WholeChainCert::step` sets `tip_summary = summary` and
            // `acc = AccStep(acc_prev, summary).acc`, the FOLDED accumulator, which `verify_whole_chain_cert` already binds through
            // the step's `state_hash`. MEASURED 2026-11-12 (lane goods, main's own pin binary): comparing `acc` with the summary
            // refused every honest certified bundle (`honest_bundle_is_adopted_and_jumps_to_tip` and 17 adopt pins red at their
            // honest calibration, so every tamper refusal they guard measured nothing).
            if cert_proof.tip_summary != expected_summary {
                return AdoptOutcome::CertificateUnproven;
            }
            if cert_proof.work != bundle.blue_work {
                return AdoptOutcome::CertificateUnproven;
            }
        }
    }
    // 3) O(1) jump: the node installs tip + frontier and is immediately a first-class producer. It also
    // learns the canonical genesis identity (proof-bound above), so a fresh node converges its chain_id.
    AdoptOutcome::Adopted(SyncState {
        proven_work: bundle.blue_work,
        tip: bundle.decider.tip,
        blue_score: bundle.decider.blue_score,
        frontier_root: bundle.frontier.root,
        height: bundle.frontier.height,
        nullifier_root: bundle.nullifier.root,
        nullifier_count: bundle.nullifier.count,
        sparse_root: bundle.nullifier.sparse_root,
        band: bundle.nullifier.band.clone(),
        band_next_ordinal: bundle.nullifier.band_next_ordinal,
        band_awaiting: bundle.nullifier.band_awaiting.clone(),
        // The carried token registry, taken from the SAME bound nullifier snapshot as the sparse root
        // beside it, so a relay cannot substitute one.
        dsol_registry_peaks: bundle.nullifier.dsol_registry_peaks.clone(),
        dsol_registry_count: bundle.nullifier.dsol_registry_count,
        nf_cover_conf_acc: bundle.nullifier.nf_cover_conf_acc,
        genesis_commit: bundle.genesis_commit.clone(),
        nf_unspent_acc: bundle.nullifier.nf_unspent_acc,
        membership_tip: bundle.nullifier.membership_tip,
        finality_validators: bundle.nullifier.finality_validators.clone(),
        custody_seat_active_from: bundle.nullifier.custody_seat_active_from.clone(),
        finality_seat_active_from: bundle.nullifier.finality_seat_active_from.clone(),
        departed_custody_seats: bundle.nullifier.departed_custody_seats.clone(),
        departed_finality_seats: bundle.nullifier.departed_finality_seats.clone(),
        seat_words: bundle.nullifier.seat_words.clone(),
        bonded_validators: bundle.nullifier.bonded_validators.clone(),
        slashed_validators: bundle.nullifier.slashed_validators.clone(),
        slashed_bond_burned: bundle.nullifier.slashed_bond_burned,
        validator_bond_commit: bundle.nullifier.validator_bond_commit,
        validator_custody: bundle.nullifier.validator_custody.clone(),
        validator_kem_eks: bundle.nullifier.validator_kem_eks.clone(),
        custody_seat_numbers: bundle.nullifier.custody_seat_numbers.clone(),
        letter_acc: bundle.nullifier.letter_acc,
        dir_acc: bundle.nullifier.dir_acc,
        peg_reserve_commit: bundle.nullifier.peg_reserve_commit,
        peg_minted_commit: bundle.nullifier.peg_minted_commit,
        peg_reserve_hwm_commit: bundle.nullifier.peg_reserve_hwm_commit,
        applied_one_time_ids: bundle.nullifier.applied_one_time_ids.clone(),
        peg_ratio_bps: bundle.nullifier.peg_ratio_bps,
        peg_redeem_floor_bps: bundle.nullifier.peg_redeem_floor_bps,
        peg_yield_rate_bps: bundle.nullifier.peg_yield_rate_bps,
        peg_price_marks: bundle.nullifier.peg_price_marks.clone(),
        bond_heights: bundle.nullifier.bond_heights.clone(),
        bond_locked_notes: bundle.nullifier.bond_locked_notes.clone(),
        unbonding: bundle.nullifier.unbonding.clone(),
        peg_wrapped_assets: bundle.nullifier.peg_wrapped_assets.clone(),
        peg_pools: bundle.nullifier.peg_pools.clone(),
        peg_ion_pending: bundle.nullifier.peg_ion_pending.clone(),
        peg_ion_usdm_held: bundle.nullifier.peg_ion_usdm_held,
        peg_ion_pools: bundle.nullifier.peg_ion_pools,
        peg_retention_endowment_commit: bundle.nullifier.peg_retention_endowment_commit,
        l2_state_root: bundle.nullifier.l2_state_root,
        root_history_peaks_hex: bundle.nullifier.root_history_peaks_hex.clone(),
        peg_sat_issued: bundle.nullifier.peg_sat_issued,
        peg_pendulum: bundle.nullifier.peg_pendulum,
        peg_br: bundle.nullifier.peg_br.clone(),
        nf_fold_base_words: bundle.nullifier.nf_fold_base_words,
        nf_fold_span: bundle.nullifier.nf_fold_span.clone(),
        canon: bundle.nullifier.canon,
})
}

#[cfg(all(test, feature = "pins-harness"))]
mod tests {
    use super::*;
    use crate::decider::UnverifiedDecider;

    /// ⭐⭐⭐ THE BOUND CERTIFICATE KEEPS EVERYTHING A NODE-LOGIC TEST OBSERVES (the testing format, 2026-10-02).
    ///
    /// Node tests run the certificate prover's test double by default (`usdm_decider::whole_chain_cert::bound`; the real
    /// WHIR step is 320–506 s, the bound one microseconds). This pins what the double must still do, so a node test's
    /// certificate gate is still a gate: CALIBRATION — a two-step chain verifies and is inherited. TAMPERS (each REFUSED):
    /// the accumulator, the work, the tip summary, the tip's work, a proof byte, the io's state block. SEPARATION — a bound
    /// certificate is never accepted by the REAL door. Runs in the default (bound) tier; the proven tier skips `bound_cert`.
    #[test]
    fn the_bound_cert_binds_every_public_value_and_never_passes_the_real_door() {
        use usdm_decider::whole_chain_cert::{certs_are_bound, real_door_accepts_for_test, verify_whole_chain_cert, WholeChainCert};
        assert!(certs_are_bound(), "run this pin in the default (bound) tier — MONEROUSD_TEST_CERTS=proven skips `bound_cert`");
        let t0 = std::time::Instant::now();
        let s = |i: u64| usdm_decider::poseidon2_compress::lanes_of(&[0xB0, i, 0, 0]);
        let mut c = WholeChainCert::new();
        assert!(c.step(s(1), 5) && c.step(s(2), 7), "CALIBRATION: a bound chain of two steps folds");
        let p = c.finalize().expect("a stepped certificate finalises");
        assert!(verify_whole_chain_cert(&p), "CALIBRATION: the honest bound certificate verifies");
        assert!(WholeChainCert::inherit(&p).is_some(), "CALIBRATION: … and is inherited");
        let refused = |name: &str, f: &dyn Fn(&mut usdm_decider::whole_chain_cert::WholeChainProof)| {
            let mut q = p.clone();
            f(&mut q);
            assert!(!verify_whole_chain_cert(&q), "⛔ the bound certificate accepted a moved {name}");
            assert!(WholeChainCert::inherit(&q).is_none(), "⛔ a moved {name} was inherited");
        };
        refused("accumulator", &|q| q.acc[0] ^= 1);
        refused("work", &|q| q.work += 1);
        refused("tip summary", &|q| q.tip_summary[1] ^= 1);
        refused("tip work", &|q| q.tip_block_work += 1);
        refused("proof byte", &|q| q.step.bytes[0] ^= 1);
        refused("state block", &|q| {
            let n = q.step.io.len();
            q.step.io.swap(n - 1, n - 2); // two lanes of the state block exchanged
        });
        assert!(!real_door_accepts_for_test(&p), "⛔⛔ a BOUND certificate passed the REAL certificate door");
        // (the real door's release parameters cost a one-time setup; the bound path itself is microseconds)
        eprintln!("[bound-cert] pin in {:?}", t0.elapsed());
    }

    /// ⭐ THE FOUR FIELDS THAT USED TO RIDE A VALID PROOF UNBOUND (holes A3/A4, 2026-09-07).
    ///
    /// DELIBERATE-DEVIATION: Bitcoin Core (headers-first most-work, github.com/bitcoin/bitcoin) and
    /// Kaspa (GHOSTDAG blue work, github.com/kaspanet/rusty-kaspa) never CARRY an accumulated weight
    /// as a standalone number — each node re-derives it from headers it has itself PoW-checked, so
    /// there is nothing to forge. A #29 node jumps the blue score without the blocks between and can
    /// never re-derive that sum, so this chain carries it; the deviation's price is that a carried
    /// weight must be authenticated by something, and the only thing certifying it is the binding
    /// this pin drives. The record base beside it is Zcash's anchor + tree-size shape
    /// (github.com/zcash/zcash): adopt the root together with the size that produced it.
    ///
    /// The adversary here is NOT a chain: it is a relay that takes a bundle which already verifies —
    /// its own honest one, or one it re-serves — and edits the numbers the adopter acts on. Before
    /// this landed, `blue_work`, `anchor_blue_work`, `anchor_ordinal` and `nf_cover_conf_acc` were
    /// outside `sync_binding`'s preimage, so all four edits produced the SAME accumulator and ONE
    /// valid proof certified every one of them. Each tamper must now move the binding.
    ///
    /// Asserted on `sync_binding` itself — the function that produces the value the proof is
    /// transcript-bound to — so every consumer (the serve side, `adopt_sync_bundle`, any future adopt
    /// lane) inherits the check with no new door.
    /// MUST-STAY-GREEN: `a_forged_bonded_validator_set_breaks_the_sync_binding` and the #29 adopt
    /// suite — this pin states the same law for the fields that were left out of it.
    /// cons: none — pure hashing of fixed-shape preimages. No node, no chain, no store.
    #[test]
    fn the_fork_choice_weights_and_the_record_base_are_bound_by_the_sync_binding() {
        let tip = Hash32::hash(b"weights-tip");
        let frontier = FrontierSnapshot {
            root: *Hash32::hash(b"fr").as_bytes(),
            height: 9,
            peaks_hex: String::new(),
        };
        let base = NullifierSnapshot {
            peg_reserve_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_minted_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_reserve_hwm_commit: usdm_decider::poseidon2_compress::zero_digest(),
            applied_one_time_ids: Vec::new(),
            peg_ratio_bps: 0,
            peg_redeem_floor_bps: 0,
            peg_yield_rate_bps: 0,
            peg_sat_issued: 0,
            peg_pendulum: (0, 0),
            peg_br: Default::default(),
            nf_fold_base_words: Default::default(),
            nf_fold_span: Vec::new(),
            canon: Default::default(),
            peg_price_marks: Vec::new(),
            bond_heights: Vec::new(),
            bond_locked_notes: Vec::new(),
            unbonding: Vec::new(),
            peg_wrapped_assets: Vec::new(),
            peg_pools: Vec::new(),
            peg_ion_pending: Vec::new(),
            peg_ion_usdm_held: 0,
            peg_ion_pools: 0,
            peg_retention_endowment_commit: usdm_decider::poseidon2_compress::zero_digest(),
            l2_state_root: [0u8; 32],
            root_history_peaks_hex: crate::spend_frontier::PoseidonSpendFrontier::new().peaks_hex(),
            finality_validators: Vec::new(),
            custody_seat_active_from: Vec::new(),
            finality_seat_active_from: Vec::new(),
            departed_custody_seats: Vec::new(),
            departed_finality_seats: Vec::new(),
            seat_words: Vec::new(),
            bonded_validators: Vec::new(),
            slashed_validators: Vec::new(),
            slashed_bond_burned: 0,
            validator_bond_commit: usdm_decider::poseidon2_compress::zero_digest(),
            validator_custody: Vec::new(),
            validator_kem_eks: Vec::new(),
            custody_seat_numbers: Vec::new(),
            root: *Hash32::hash(b"nf").as_bytes(),
            count: 3,
            sparse_root: [0u8; 32],
            band: Vec::new(),
            band_next_ordinal: 0,
            band_awaiting: Vec::new(),
            nf_cover_conf_acc: [0u8; 32],
            nf_unspent_acc: usdm_decider::poseidon2_compress::zero_digest(),
            membership_tip: (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()),
            letter_acc: crate::letter::letter_acc_genesis(),
            dir_acc: crate::directory::dir_acc_genesis(),
            dsol_registry_peaks: Vec::new(),
            dsol_registry_count: 0,
        };
        let carry = FoldCarry::default().digest();
        let honest = sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &carry, 41, 41, 7);

        // (1) THE FORK-CHOICE WEIGHT the NotHeavier gate reads.
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &carry, u128::MAX, 41, 7),
            "a tampered blue_work is a different binding"
        );
        // (2) THE ANCHOR'S WEIGHT — what `Dag::add_anchor` reorgs on and then stores forever.
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &carry, 41, u128::MAX, 7),
            "a tampered anchor_blue_work is a different binding"
        );
        // (3) THE RECORD BASE every later ordinal follows from (the numbering-split class).
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &carry, 41, 41, 8),
            "a tampered anchor_ordinal is a different binding"
        );
        // (4) THE CONFIDENTIAL DECOY ACCUMULATOR the adopter installs verbatim.
        let mut cover_tampered = base.clone();
        cover_tampered.nf_cover_conf_acc = [0x5Au8; 32];
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &cover_tampered, b"g", &tip, 9, &carry, 41, 41, 7),
            "a tampered nf_cover_conf_acc is a different binding"
        );
        // And the honest inputs still reproduce themselves — the binding is a function, not a nonce.
        assert_eq!(
            honest,
            sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &carry, 41, 41, 7),
            "the same inputs must fold to the same binding"
        );
    }

    /// ⭐ THE END-TO-END REFUSAL: a bundle whose only edits are the newly-bound weights is rejected by
    /// the production adopt door, `FrontierUnbound`, with nothing installed. The verifier here accepts
    /// any within-size proof, which is the honest model of the CURRENT decider (see `adopt_sync_bundle`
    /// question 2): the binding is what refuses this bundle, not the proof.
    /// DELIBERATE-DEVIATION: as above — a carried weight is not Bitcoin's re-derived chainwork, so it
    /// is authenticated here instead of recomputed.
    #[test]
    fn a_bundle_with_tampered_fork_weights_is_refused_by_the_adopt_door() {
        let mut bundle = well_formed_bundle();
        assert!(
            matches!(
                adopt_sync_bundle(&AcceptProof, None, &bundle),
                AdoptOutcome::Adopted(_)
            ),
            "premise: the untampered bundle adopts"
        );
        let honest_work = bundle.blue_work;
        bundle.blue_work = u128::MAX;
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &bundle),
            AdoptOutcome::FrontierUnbound,
            "a re-weighted bundle must not adopt"
        );
        bundle.blue_work = honest_work;
        bundle.anchor_blue_work = u128::MAX;
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &bundle),
            AdoptOutcome::FrontierUnbound,
            "a re-weighted ANCHOR must not adopt"
        );
        bundle.anchor_blue_work = honest_work;
        bundle.anchor_ordinal = 4_096;
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &bundle),
            AdoptOutcome::FrontierUnbound,
            "a re-based record position must not adopt"
        );
    }

    /// The plain bundle nullifier half the binding pins mutate one field at a time.
    fn binding_fixture_nullifier() -> NullifierSnapshot {
        NullifierSnapshot {
            peg_reserve_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_minted_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_reserve_hwm_commit: usdm_decider::poseidon2_compress::zero_digest(),
            applied_one_time_ids: Vec::new(),
            peg_ratio_bps: 0,
            peg_redeem_floor_bps: 0,
            peg_yield_rate_bps: 0,
            peg_sat_issued: 0,
            peg_pendulum: (0, 0),
            peg_br: Default::default(),
            nf_fold_base_words: Default::default(),
            nf_fold_span: Vec::new(),
            canon: Default::default(),
            peg_price_marks: Vec::new(),
            bond_heights: Vec::new(),
            bond_locked_notes: Vec::new(),
            unbonding: Vec::new(),
            peg_wrapped_assets: Vec::new(),
            peg_pools: Vec::new(),
            peg_ion_pending: Vec::new(),
            peg_ion_usdm_held: 0,
            peg_ion_pools: 0,
            peg_retention_endowment_commit: usdm_decider::poseidon2_compress::zero_digest(),
            l2_state_root: [0u8; 32],
            root_history_peaks_hex: crate::spend_frontier::PoseidonSpendFrontier::new().peaks_hex(),
            finality_validators: Vec::new(),
            custody_seat_active_from: Vec::new(),
            finality_seat_active_from: Vec::new(),
            departed_custody_seats: Vec::new(),
            departed_finality_seats: Vec::new(),
            seat_words: Vec::new(),
            bonded_validators: vec![([0x11u8; 32], 5_000u128)],
            slashed_validators: Vec::new(),
            slashed_bond_burned: 0,
            validator_bond_commit: usdm_decider::poseidon2_compress::zero_digest(),
            validator_custody: Vec::new(),
            validator_kem_eks: Vec::new(),
            custody_seat_numbers: Vec::new(),
            root: *Hash32::hash(b"nf").as_bytes(),
            count: 3,
            sparse_root: [0u8; 32],
            band: Vec::new(),
            band_next_ordinal: 0,
            band_awaiting: Vec::new(),
            nf_cover_conf_acc: [0u8; 32],
            nf_unspent_acc: usdm_decider::poseidon2_compress::zero_digest(),
            membership_tip: (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()),
            letter_acc: crate::letter::letter_acc_genesis(),
            dir_acc: crate::directory::dir_acc_genesis(),
            dsol_registry_peaks: Vec::new(),
            dsol_registry_count: 0,
        }
    }

    /// ⭐ SATOSHI — A FORGED ISSUED TOTAL OR PENDULUM SNAPSHOT BREAKS THE BINDING. Two bundles identical except for the
    /// carried SAT words commit to different accumulators, so a peer cannot hand a joiner a smaller issued total (rewards past
    /// the cap the chain reached) or another share (custody yield at a rate no peer pays) under a valid tip proof.
    #[test]
    fn a_forged_sat_issued_total_or_pendulum_snapshot_breaks_the_sync_binding() {
        let tip = Hash32::hash(b"sat-tip");
        let frontier = FrontierSnapshot { root: *Hash32::hash(b"fr").as_bytes(), height: 9, peaks_hex: String::new() };
        let mut base = binding_fixture_nullifier();
        base.peg_sat_issued = 4_159_090;
        base.peg_pendulum = (4, 10_000);
        let bind = |n: &NullifierSnapshot| sync_binding(&tip, 9, &frontier, n, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0);
        let honest = bind(&base);
        assert_eq!(bind(&base.clone()), honest, "CALIBRATION: the unmoved bundle binds to itself");
        let mut t = base.clone();
        t.peg_sat_issued -= 1;
        assert_ne!(bind(&t), honest, "⛔ a smaller issued total rode the binding");
        let mut t = base.clone();
        t.peg_pendulum.1 = 5_000;
        assert_ne!(bind(&t), honest, "⛔ a moved pendulum share rode the binding");
        let mut t = base.clone();
        t.peg_pendulum.0 = 3;
        assert_ne!(bind(&t), honest, "⛔ a moved pendulum epoch rode the binding");
    }

    /// ⭐ §BR — A FORGED §BR LEDGER WORD BREAKS THE BINDING. Each of the fourteen words moved alone, the stakers' paid-out
    /// commitment, a deployment's state and an added attestation each yield a different binding, so no server can hand a
    /// joiner fuller pools (claims every peer refuses), an emptier one (claims every peer pays, refused), another quarter or
    /// another deployment state under a valid tip proof.
    #[test]
    fn a_forged_br_ledger_word_breaks_the_sync_binding() {
        let tip = Hash32::hash(b"br-tip");
        let frontier = FrontierSnapshot { root: *Hash32::hash(b"fr").as_bytes(), height: 9, peaks_hex: String::new() };
        let mut base = binding_fixture_nullifier();
        base.peg_br.words = [400, 250, 250, 100, 3, 7, 11, 2, 5, 1, 9, 1, 20_001, 400, 10_000, 1_000, 500, 300, 1, 4, 60, 2, 9, 700, 80];
        let bind = |n: &NullifierSnapshot| sync_binding(&tip, 9, &frontier, n, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0);
        let honest = bind(&base);
        assert_eq!(bind(&base.clone()), honest, "CALIBRATION: the unmoved bundle binds to itself");
        for i in 0..base.peg_br.words.len() {
            let mut t = base.clone();
            t.peg_br.words[i] += 1;
            assert_ne!(bind(&t), honest, "⛔ §BR word {i} moved and rode the binding");
        }
        let mut t = base.clone();
        t.peg_br.stake_paid_commit[0] ^= 1;
        assert_ne!(bind(&t), honest, "⛔ a moved stakers' paid-out commitment rode the binding");
        let mut t = base.clone();
        t.peg_br.deployments.states.insert("x".into(), crate::deployment::DeployState::Started);
        assert_ne!(bind(&t), honest, "⛔ a forged deployment state rode the binding");
        let mut t = base.clone();
        t.peg_br.deployments.update_needed = true;
        assert_ne!(bind(&t), honest, "⛔ a forged update-needed flag rode the binding");
    }

    /// ⛔ G2g-r2a (lane b, T2) — A FORGED QUANTIZED FOLD BASE BREAKS THE BINDING: each of the four words a DSYNC joiner holds
    /// pending (base, seq, prev, boundary) moved alone yields a different binding, so no server can hand a joiner a base the
    /// proof did not certify.
    #[test]
    fn a_forged_quantized_fold_base_word_breaks_the_sync_binding() {
        let tip = Hash32::hash(b"fb-tip");
        let frontier = FrontierSnapshot { root: *Hash32::hash(b"fr").as_bytes(), height: 9, peaks_hex: String::new() };
        let mut base = binding_fixture_nullifier();
        base.nf_fold_base_words = ([1, 2, 3, 4, 5, 6, 7, 8], 71, [9, 10, 11, 12, 13, 14, 15, 16], 64);
        base.nf_fold_span = vec![([3u8; 32], 40, 64), ([4u8; 32], 41, 65)];
        let bind = |n: &NullifierSnapshot| sync_binding(&tip, 9, &frontier, n, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0);
        let honest = bind(&base);
        assert_eq!(bind(&base.clone()), honest, "CALIBRATION: the unmoved bundle binds to itself");
        for (k, f) in [
            ("base_acc", (|t: &mut NullifierSnapshot| t.nf_fold_base_words.0[2] ^= 1) as fn(&mut NullifierSnapshot)),
            ("base_seq", |t| t.nf_fold_base_words.1 += 1),
            ("base_prev", |t| t.nf_fold_base_words.2[0] ^= 1),
            ("boundary", |t| t.nf_fold_base_words.3 -= 1),
            ("span member dropped", |t| { t.nf_fold_span.pop(); }),
            ("span member added", |t| t.nf_fold_span.push(([7u8; 32], 5, 70))),
            ("span score moved", |t| t.nf_fold_span[0].2 += 1),
            ("span weight moved", |t| t.nf_fold_span[1].1 += 1),
            ("span id swapped", |t| t.nf_fold_span[0].0[0] ^= 1),
        ] {
            let mut t = base.clone();
            f(&mut t);
            assert_ne!(bind(&t), honest, "⛔ a moved fold-base {k} rode the binding");
        }
    }

    /// ⭐ A FORGED FINALITY QUORUM BREAKS THE BINDING: two bundles identical except for the carried
    /// bonded-validator set commit to DIFFERENT chain accumulators, so a peer cannot stuff (or empty)
    /// a joiner's quorum under a valid tip proof — the same weld that guards nf_unspent_acc.
    #[test]
    fn a_forged_bonded_validator_set_breaks_the_sync_binding() {
        let tip = Hash32::hash(b"quorum-tip");
        let frontier = FrontierSnapshot {
            root: *Hash32::hash(b"fr").as_bytes(),
            height: 9,
            peaks_hex: String::new(),
        };
        let base = binding_fixture_nullifier();
        let honest = sync_binding(&tip, 9, &frontier, &base, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0);
        // Stuffed weight, added member, and an EMPTIED quorum each break the binding.
        let mut stuffed = base.clone();
        stuffed.bonded_validators = vec![([0x11u8; 32], 500_000u128)];
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &stuffed, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0),
            "a stuffed weight is a different binding"
        );
        let mut added = base.clone();
        added.bonded_validators.push(([0x22u8; 32], 5_000u128));
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &added, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0),
            "an added member is a different binding"
        );
        let mut emptied = base.clone();
        emptied.bonded_validators.clear();
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &emptied, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0),
            "an emptied quorum is a different binding"
        );
        // A slashed-bar tamper breaks it too (the bar is part of the quorum's meaning).
        let mut unbarred = base.clone();
        unbarred.slashed_validators = vec![[0x33u8; 32]];
        assert_ne!(
            honest,
            sync_binding(&tip, 9, &frontier, &unbarred, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0),
            "a tampered slash bar is a different binding"
        );
    }

    /// ⭐ A-F50 — A FORGED ION POOL BOOK BREAKS THE BINDING: a tampered pending order, a moved USDm held and a moved
    /// pool count each yield a different binding, so no server can hand a joiner a wrong pool book under a valid tip proof.
    #[test]
    fn af50_a_forged_ion_pool_book_breaks_the_sync_binding() {
        let tip = Hash32::hash(b"ion-tip");
        let frontier = FrontierSnapshot { root: *Hash32::hash(b"fr").as_bytes(), height: 9, peaks_hex: String::new() };
        let mut base = binding_fixture_nullifier();
        base.peg_ion_usdm_held = 500_000;
        base.peg_ion_pools = 3;
        base.peg_ion_pending = vec![crate::ion_pool_tx::IonPending {
            token: [0xAAu8; 32],
            step: 7,
            id: [0xBBu8; 32],
            core: crate::ion_pool_tx::IonOrderCore {
                kind: 1,
                x: 1_000,
                y: 500,
                shares: 0,
                min_out: 100,
                owner_opening: [0xCCu8; 32],
                shell_ct: Vec::new(),
                shell_pad: [0u8; 32],
                shell_vt: 0,
                locators: [[0u8; 32]; 3],
                hop: [0u8; 32],
                hop_min_out: 0,
                lock_from: 0,
                lock_until: 0,
            },
        }];
        let bind = |n: &NullifierSnapshot| sync_binding(&tip, 9, &frontier, n, b"g", &tip, 9, &FoldCarry::default().digest(), 9, 9, 0);
        let honest = bind(&base);
        assert_eq!(bind(&base.clone()), honest, "CALIBRATION: the unmoved bundle binds to itself");
        let mut t = base.clone();
        t.peg_ion_usdm_held -= 1;
        assert_ne!(bind(&t), honest, "⛔ a moved USDm held rode the binding");
        let mut t = base.clone();
        t.peg_ion_pools = 99;
        assert_ne!(bind(&t), honest, "⛔ a moved pool count rode the binding");
        let mut t = base.clone();
        t.peg_ion_pending.clear();
        assert_ne!(bind(&t), honest, "⛔ a dropped pending order rode the binding");
        let mut t = base.clone();
        t.peg_ion_pending[0].core.x = 9_999;
        assert_ne!(bind(&t), honest, "⛔ a tampered pending order rode the binding");
    }

    // A test verifier that accepts any within-size-bound proof, so we can exercise the frontier
    // binding independently of the real WHIR verify (which is covered under the whir_decider
    // feature). The size gate in accept_bundle still runs.
    struct AcceptProof;
    impl ConsensusVerifier for AcceptProof {
        fn verify_bundle(&self, _b: &DeciderBundle) -> bool {
            true
        }
    }

    /// A minimal real block whose `id()` we bind the bundle to (so the anchor graft is authentic).
    fn a_tip_block(seed: u64) -> crate::block::Block {
        use crate::block::{Block, BlockHeader};
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(),
            header: BlockHeader {
            note_commitments_root: crate::hash::Hash32::hash(&[]),
                nullifier_tags_root: crate::hash::Hash32::hash(&[]),
                output_notes_root: crate::hash::Hash32::hash(&[]),
                // P4'a fixture: this block ships no locator tags and no account targets, so both sidecar
                // commitments are the empty-payload hash the verifier re-derives.
                oli_tags_root: crate::block::da_sidecar_root_of(&[]),
                // ⭐ §BA — no credit set here, so the DERIVED empty sidecar root, never a magic constant.
                credit_set_root: crate::block::da_sidecar_root_of(&[]),
                transitions_root: crate::block::empty_transitions_root(),
                cover_seed_commit: crate::hash::Hash32::ZERO,
                member_ring_commit: crate::hash::Hash32::ZERO,
                account_targets_root: crate::block::da_sidecar_root_of(&[]),
                bond_set_root: crate::block::da_sidecar_root_of(&[]),
                dir_set_root: crate::block::da_sidecar_root_of(&[]),
                letter_set_root: crate::block::da_sidecar_root_of(&[]),
                tag_evidence_root: crate::block::da_sidecar_root_of(&[]),
                level_root: crate::hash::Hash32::ZERO, fold_ordinal: 0, fold_commit: crate::hash::Hash32::ZERO, band_ordinal: 0, band_commit: crate::hash::Hash32::ZERO,
                version: 1,
                parents: vec![],
                timestamp: seed,
                nonce: 0,
                work: 1,
                pow_bind: Hash32::ZERO,
                tx_merkle_root: Hash32::ZERO,
                frontier_root: Hash32::ZERO,
                nullifier_root: Hash32::ZERO,
                sparse_root: crate::hash::Hash32::ZERO,
                chain_acc: [0u8; 16],
                miner_commitment: Hash32::ZERO,
                account_root: Hash32::ZERO,
            },
            tx_ids: vec![],
            pow_proof: Vec::new(),
            note_transition: None,
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            nullifier_proof: crate::block::NfBlockProof::default(),
            cover_transition: None,
            member_transition: None,
        }
    }

    /// Recompute a bundle's `chain_acc` over its OWN (possibly tampered) fields — the internally
    /// consistent server. Without this a tamper is caught by [`sync_binding`] and a certificate pin
    /// measures that check instead of its own.
    fn rebind_for_test(mut b: SyncBundle) -> SyncBundle {
        b.decider.chain_acc = sync_binding(
            &b.decider.tip,
            b.decider.blue_score,
            &b.frontier,
            &b.nullifier,
            &b.genesis_commit,
            &b.anchor_block.id(),
            b.anchor_blue_score,
            &b.fold_carry.digest(),
            b.blue_work,
            b.anchor_blue_work,
            b.anchor_ordinal,
        );
        b
    }

    fn well_formed_bundle() -> SyncBundle {
        let tip_block = a_tip_block(7);
        let tip = tip_block.id();
        // the EMPTY frontier, served as itself: its real root and its wire-encoded (count 0) spine — the only
        // honest frontier for an anchor at position 0 (DB-376: a spine-less serve is a lie).
        let empty = crate::spend_frontier::PoseidonSpendFrontier::new();
        let frontier = FrontierSnapshot {
            root: crate::spend_frontier::leaf_to_cm_bytes(empty.root()),
            height: 6,
            peaks_hex: empty.peaks_hex(),
        };
        let nullifier = NullifierSnapshot {
            peg_reserve_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_minted_commit: usdm_decider::poseidon2_compress::zero_digest(),
            peg_reserve_hwm_commit: usdm_decider::poseidon2_compress::zero_digest(),
            applied_one_time_ids: Vec::new(),
            peg_ratio_bps: 0,
            peg_redeem_floor_bps: 0,
            peg_yield_rate_bps: 0,
            peg_sat_issued: 0,
            peg_pendulum: (0, 0),
            peg_br: Default::default(),
            nf_fold_base_words: Default::default(),
            nf_fold_span: Vec::new(),
            canon: Default::default(),
            peg_price_marks: Vec::new(),
            bond_heights: Vec::new(),
            bond_locked_notes: Vec::new(),
            unbonding: Vec::new(),
            peg_wrapped_assets: Vec::new(),
            peg_pools: Vec::new(),
            peg_ion_pending: Vec::new(),
            peg_ion_usdm_held: 0,
            peg_ion_pools: 0,
            peg_retention_endowment_commit: usdm_decider::poseidon2_compress::zero_digest(),
            l2_state_root: [0u8; 32],
            root_history_peaks_hex: crate::spend_frontier::PoseidonSpendFrontier::new().peaks_hex(),
            finality_validators: Vec::new(),
            custody_seat_active_from: Vec::new(),
            finality_seat_active_from: Vec::new(),
            departed_custody_seats: Vec::new(),
            departed_finality_seats: Vec::new(),
            seat_words: Vec::new(),
            bonded_validators: Vec::new(),
            slashed_validators: Vec::new(),
            slashed_bond_burned: 0,
            validator_bond_commit: usdm_decider::poseidon2_compress::zero_digest(),
            validator_custody: Vec::new(),
            validator_kem_eks: Vec::new(),
            custody_seat_numbers: Vec::new(),
            root: *Hash32::hash(b"nf-acc").as_bytes(),
            count: 9,
            sparse_root: [0u8; 32],
            band: Vec::new(),
            band_next_ordinal: 0,
            band_awaiting: Vec::new(),
            nf_cover_conf_acc: [0u8; 32],
            nf_unspent_acc: usdm_decider::poseidon2_compress::zero_digest(),
            membership_tip: (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()),
            letter_acc: crate::letter::letter_acc_genesis(),
            dir_acc: crate::directory::dir_acc_genesis(),
            dsol_registry_peaks: Vec::new(),
            dsol_registry_count: 0,
        };
        // A per-network genesis identity the served chain roots at.
        let genesis_commit = crate::params::network_genesis_prefix("testnet");
        // A correctly-produced bundle binds chain_acc to the frontier + nullifier it ships AND the genesis it roots at.
        let chain_acc = sync_binding(&tip, 6, &frontier, &nullifier, &genesis_commit, &tip, 6, &FoldCarry::default().digest(), 6, 6, 0);
        crate::sync::with_fixture_cert(SyncBundle {
            join: Default::default(),
            cert: crate::sync::unset_cert(),
            tip_cover_key: None,
            tip_wide_objects: Vec::new(),
            decider: DeciderBundle {
                tip,
                blue_score: 6,
                chain_acc,
                proof: vec![1u8; 4096],
            },
            frontier,
            nullifier,
            anchor_block: tip_block.clone(),
            anchor_blue_work: 6,
            anchor_blue_score: 6,
            anchor_ordinal: 0, // fixture: the anchor is genesis-side, position 0
            fold_carry: FoldCarry::default(),
            tips: Vec::new(), // test fixture: no sibling tips beyond the selected one
            anchor_ring: Vec::new(),
            member_ring_commits: Vec::new(),
            tip_block,
            blue_work: 6,
            genesis_commit,
        })
    }

    #[test]
    fn forged_genesis_breaks_the_binding_and_is_rejected() {
        // A peer serves a valid tip proof but LIES about the genesis its chain roots at. The genesis is bound
        // into chain_acc, so the swap breaks the binding -> FrontierUnbound, no adoption. This is what makes
        // genesis-identity adoption SOUND: a node only ever adopts a genesis the verified proof certifies.
        let mut b = well_formed_bundle();
        b.genesis_commit = crate::params::network_genesis_prefix("mainnet"); // wrong root genesis
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &b),
            AdoptOutcome::FrontierUnbound
        );
        // The adopted state surfaces the (authentic) genesis so a fresh node can converge its chain_id onto it.
        let good = well_formed_bundle();
        if let AdoptOutcome::Adopted(s) = adopt_sync_bundle(&AcceptProof, None, &good) {
            assert_eq!(
                s.genesis_commit, good.genesis_commit,
                "adopter learns the canonical genesis identity"
            );
        } else {
            panic!("well-formed bundle must adopt");
        }
    }

    #[test]
    fn gap2_forged_nullifier_spent_state_breaks_the_binding_and_honest_is_inherited() {
        // Gap2: the O(1) nullifier spent-state (root+count) is BOUND into chain_acc. A peer serving a valid tip
        // proof but LYING about the spent-state — swapping the root OR the count — breaks the binding →
        // FrontierUnbound, no adoption. So a joiner can NEVER inherit a forged double-spend accumulator (a peer
        // can't erase a spend or fabricate the set); the inherited spent-state is certified, not trusted.
        let mut bad_root = well_formed_bundle();
        bad_root.nullifier.root[0] ^= 1; // one-bit flip of the spent-state root
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &bad_root),
            AdoptOutcome::FrontierUnbound
        );
        let mut bad_count = well_formed_bundle();
        bad_count.nullifier.count += 1; // lie about how many nullifiers are spent
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &bad_count),
            AdoptOutcome::FrontierUnbound
        );
        // An HONEST bundle adopts AND surfaces the certified spent-state for the node to install (inherit).
        let good = well_formed_bundle();
        match adopt_sync_bundle(&AcceptProof, None, &good) {
            AdoptOutcome::Adopted(s) => {
                assert_eq!(
                    s.nullifier_root, good.nullifier.root,
                    "adopter inherits the certified spent-state root"
                );
                assert_eq!(
                    s.nullifier_count, good.nullifier.count,
                    "adopter inherits the certified spent count"
                );
            }
            other => panic!("honest bundle must adopt, got {other:?}"),
        }
    }

    #[test]
    fn forged_tip_block_is_rejected() {
        // The carried tip block MUST be the very tip the proof certified. A swapped/forged tip block
        // (different id) paired with an otherwise-valid bundle is rejected — an attacker cannot graft an
        // unrelated block as the convergence anchor. (Adversarial tamper test for the mergeset graft.)
        let mut b = well_formed_bundle();
        b.tip_block = a_tip_block(999); // different timestamp -> different id != decider.tip
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &b),
            AdoptOutcome::FrontierUnbound
        );
    }

    #[test]
    fn honest_bundle_is_adopted_and_jumps_to_tip() {
        let b = well_formed_bundle();
        match adopt_sync_bundle(&AcceptProof, None, &b) {
            AdoptOutcome::Adopted(s) => {
                assert_eq!(s.tip, b.decider.tip);
                assert_eq!(s.blue_score, 6);
                assert_eq!(s.height, 6);
                assert_eq!(s.frontier_root, b.frontier.root);
            }
            other => panic!("honest bundle must be adopted, got {other:?}"),
        }
    }

    #[test]
    fn unverified_decider_never_adopts() {
        // The fail-closed default verifier rejects every proof -> no adoption, ever (never jump to an
        // unverified tip). This is what a build without an installed verifier does — always fail-closed.
        let b = well_formed_bundle();
        assert_eq!(
            adopt_sync_bundle(&UnverifiedDecider, None, &b),
            AdoptOutcome::Unverified
        );
    }

    #[test]
    fn forged_frontier_breaks_the_binding_and_is_rejected() {
        // Swap in a frontier the verified accumulator does not commit to -> FrontierUnbound, no jump.
        let mut b = well_formed_bundle();
        b.frontier.root = *Hash32::hash(b"attacker-frontier").as_bytes();
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &b),
            AdoptOutcome::FrontierUnbound
        );
        // Also a swapped HEIGHT breaks the binding (frontier.height is part of the commitment).
        let mut b2 = well_formed_bundle();
        b2.frontier.height = 999;
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &b2),
            AdoptOutcome::FrontierUnbound
        );
    }

    #[test]
    fn oversize_or_empty_proof_is_rejected_before_frontier_check() {
        // The no-blowup size gate rejects an over-cap / empty proof as Unverified (never even reaches
        // the frontier binding), so a huge blob can't be used to smuggle a frontier.
        let mut big = well_formed_bundle();
        big.decider.proof = vec![7u8; DeciderBundle::MAX_PROOF_BYTES + 1];
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &big),
            AdoptOutcome::Unverified
        );
        let mut empty = well_formed_bundle();
        empty.decider.proof = vec![];
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &empty),
            AdoptOutcome::Unverified
        );
    }

    #[test]
    fn wire_roundtrip_survives_transport_and_still_adopts() {
        let b = well_formed_bundle();
        let bytes = b.to_wire();
        assert!(!bytes.is_empty());
        let recv = SyncBundle::from_wire(&bytes).expect("decodes a well-formed frame");
        // The bundle survives onion serialization intact and still adopts through the real gate.
        match adopt_sync_bundle(&AcceptProof, None, &recv) {
            AdoptOutcome::Adopted(s) => assert_eq!(s.tip, b.decider.tip),
            other => panic!("wire-roundtripped bundle must adopt, got {other:?}"),
        }
    }

    #[test]
    fn in_transit_frontier_tamper_is_caught() {
        // An attacker on the wire swaps the frontier for one the verified accumulator does not bind.
        let mut recv = SyncBundle::from_wire(&well_formed_bundle().to_wire()).unwrap();
        recv.frontier.root = *Hash32::hash(b"in-transit-swap").as_bytes();
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &recv),
            AdoptOutcome::FrontierUnbound
        );
    }

    #[test]
    fn corrupt_wire_frame_fails_closed() {
        assert!(SyncBundle::from_wire(&[]).is_none());
        assert!(SyncBundle::from_wire(&[0xffu8; 8]).is_none());
        // truncating a valid frame also fails to decode (fail-closed, no partial adopt).
        let bytes = well_formed_bundle().to_wire();
        assert!(SyncBundle::from_wire(&bytes[..bytes.len() / 2]).is_none());
    }

    /// ⛔⛔⛔ THE JOIN DOOR'S CERTIFICATE HALF, AT THE DOOR ITSELF.
    ///
    /// Everything else `adopt_sync_bundle` checks binds this bundle's fields to `decider.chain_acc` — a
    /// value the SERVER chose, which the shipped decider proof does not constrain (it proves a FIXED
    /// public AIR that reads nothing from any chain). So a party holding NO chain could mint an
    /// accumulator and every field bound to it rode along: kill list §AH, and the reason `pin_d1` stood
    /// red for so long.
    ///
    /// ⭐ CALIBRATION FIRST: the bundle below ADOPTS. Every gate ahead of the certificate passes on it,
    /// so when the same bundle is refused after only its certificate changes, the certificate is what
    /// refused it — not a size bound, not the binding, not the tip check.
    /// ⛔⛔ A-F49 (measured on three real nodes 2026-11-12, lane goods) — A BUNDLE IN THE SHAPE EVERY JOIN BUNDLE HAS (no
    /// decider proof, no certificate: `draft_sync_bundle`, `maybe_freeze_join_bundle`) ADOPTS ON THE JOIN DOOR'S
    /// VERDICT, AND ONLY ON IT. On the rig a wiped node took 14 such bundles from two peers, each past the join door, and
    /// D01 refused every one `Unverified`: no node could join a chain deeper than its block lanes carry.
    /// RED before: the adoption function had no way to be told the door's verdict, so the join-shaped bundle was refused.
    /// Held: with no verdict D01 is unchanged (both refusals stand); with the verdict, every proof the bundle DOES carry is
    /// still checked (a carried decider proof that fails, a carried certificate for another work total), and the binding
    /// gates still run (a swapped frontier root).
    /// TWO-PARTY-REVIEWED: the server's bundle shape and the adopter's door are both in this file's own fixture; the two
    /// processes are the real-node checks join and market (a node wiped and joined again by bundle).
    #[test]
    fn af49_a_join_bundle_with_no_decider_proof_or_certificate_adopts_only_on_the_join_doors_verdict() {
        let good = well_formed_bundle();
        assert!(matches!(adopt_sync_bundle(&AcceptProof, None, &good), AdoptOutcome::Adopted(_)), "CALIBRATION: the honest proved bundle adopts");
        let mut join = good.clone();
        join.decider.proof = Vec::new();
        join.cert = unset_cert();
        let verdict = crate::join_proof::JoinVerdict {
            estimate: join.blue_work,
            vouchers: crate::join_proof::VOUCHERS,
            fold_commit: [0x51; 32],
            band_commit: [0x52; 32],
            band_ordinal: join.nullifier.band_next_ordinal,
        };
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, None, &join),
            AdoptOutcome::Unverified,
            "CALIBRATION: with no verdict D01 stands as it landed (the refusal every live join bundle met)"
        );
        assert!(
            matches!(adopt_sync_bundle(&AcceptProof, Some(&verdict), &join), AdoptOutcome::Adopted(_)),
            "⛔⛔ A-F49: a bundle the join door authenticated by work, carrying no decider proof and no certificate (as every \
             join bundle does), was refused — no node can join a chain deeper than its block lanes carry"
        );
        // every proof the bundle DOES carry is still held to its check
        let mut carried_bad = join.clone();
        carried_bad.decider.proof = vec![7u8; 64];
        assert_eq!(
            adopt_sync_bundle(&UnverifiedDecider, Some(&verdict), &carried_bad),
            AdoptOutcome::Unverified,
            "⛔ A-F49: a CARRIED decider proof that does not verify was accepted because the join door passed the bundle"
        );
        let mut lied = good.clone();
        lied.decider.proof = Vec::new();
        lied.cert.work = lied.cert.work.saturating_add(1 << 100);
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, Some(&verdict), &lied),
            AdoptOutcome::CertificateUnproven,
            "⛔ A-F49: a CARRIED certificate for another work total was accepted because the join door passed the bundle"
        );
        let mut swapped = join.clone();
        swapped.frontier.root = *Hash32::hash(b"af49-a-different-frontier").as_bytes();
        assert_eq!(
            adopt_sync_bundle(&AcceptProof, Some(&verdict), &swapped),
            AdoptOutcome::FrontierUnbound,
            "⛔ A-F49: the binding gate stopped running once the join door passed the bundle"
        );
    }

    #[test]
    fn a_bundle_whose_certificate_does_not_stand_for_its_own_position_is_refused() {
        let good = well_formed_bundle();
        assert!(
            matches!(adopt_sync_bundle(&AcceptProof, None, &good), AdoptOutcome::Adopted(_)),
            "CALIBRATION: the honest bundle must ADOPT, or every refusal below proves nothing"
        );

        // 1) NO CERTIFICATE. This is the shape every bundle in this tree had before the certificate
        // existed: a valid decider proof, a consistent binding, and nothing saying a chain was ever built.
        let mut none = good.clone();
        none.cert = unset_cert();
        assert!(
            matches!(adopt_sync_bundle(&AcceptProof, None, &none), AdoptOutcome::CertificateUnproven),
            "⛔ A BUNDLE WITH NO WHOLE-CHAIN CERTIFICATE WAS ADOPTED. Every field it carries is bound to \
             an accumulator the server chose, so a party with no chain can mint the lot."
        );

        // 2) A CERTIFICATE FOR A DIFFERENT POSITION — and the tamper must be REBOUND first, or the
        // older `sync_binding` check refuses it and this measures that check instead of this one.
        // ⭐ That is not a detail: a gate whose attack is stopped by an outer layer is measuring the
        // outer layer. The server here is internally consistent — it recomputed `chain_acc` over its
        // tampered fields — so every gate ahead of the certificate passes.
        let mut swapped = good.clone();
        swapped.nullifier.root = *Hash32::hash(b"a-different-nullifier-root").as_bytes();
        let swapped = rebind_for_test(swapped);
        assert!(
            !matches!(adopt_sync_bundle(&AcceptProof, None, &swapped), AdoptOutcome::FrontierUnbound),
            "CALIBRATION: the rebound tamper must get PAST the binding gate, or the certificate gate \
             below is never reached"
        );
        assert!(
            matches!(adopt_sync_bundle(&AcceptProof, None, &swapped), AdoptOutcome::CertificateUnproven),
            "⛔ A CERTIFICATE CERTIFIED ONE CHAIN POSITION AND THE BUNDLE INSTALLED ANOTHER. The \
             adopter must RECOMPUTE the summary from the fields it is about to install, never read it \
             off the wire."
        );

        // 3) A LIED WORK TOTAL. The certificate's chain of steps sums to one figure; the bundle declares
        // another. That pairing is how a forged weight would ride a valid certificate into fork choice.
        let mut lied = good.clone();
        lied.cert.work = lied.cert.work.saturating_add(1 << 100);
        assert!(
            matches!(adopt_sync_bundle(&AcceptProof, None, &lied), AdoptOutcome::CertificateUnproven),
            "⛔ A BUNDLE DECLARED ONE WORK TOTAL AND CARRIED A CERTIFICATE FOR ANOTHER"
        );

        // 4) AND THE PROVEN TOTAL REACHES THE ADOPTER. A consumer must be able to act on the figure the
        // certificate attests rather than on the one a header declares.
        match adopt_sync_bundle(&AcceptProof, None, &good) {
            AdoptOutcome::Adopted(st) => assert_eq!(
                st.proven_work, good.blue_work,
                "the adopted state must carry the work the CERTIFICATE stands for"
            ),
            other => panic!("the honest bundle must adopt, got {other:?}"),
        }
    }

    /// ⭐⭐⭐ THE BUNDLE-COVERAGE CENSUS — EVERY CHAIN-DERIVED FIELD A JUMPER NEEDS RIDES THE CERTIFIED BUNDLE.
    ///
    /// A node that joins by DSYNC holds ONLY what the certified bundle carries. The authority manifests declare which
    /// node and peg fields are `ChainDerived` (a node fed blocks must reach the same value), but that claim is
    /// tested for BLOCK-fed peers, never for BUNDLE-fed ones. The same miss was found three times, each by reading the
    /// adopt path after the divergence was already possible: §DD (the peg ledger, 9/17), DB-251 (price marks), and
    /// DB-259 (bond locks: a jumper released an immature unbond the origin refused, measured weight 0 vs 50,000).
    ///
    /// Every `ChainDerived` entry must be CARRIED (the bundle fields named below exist in `NullifierSnapshot` or
    /// `SyncBundle`) or REDERIVED (a named mechanism rebuilds it on a jumper, with the reason). Anything else is listed
    /// as uncovered, and this test is RED until it is closed. The uncovered list is the measurement.
    #[test]
    fn every_chain_derived_field_rides_the_certified_bundle_or_is_rebuilt_by_a_named_mechanism() {
        use crate::harness::fuzz::authority::{Authority, AUTHORITY_MANIFEST};
        use crate::harness::fuzz::authority_peg::PEG_AUTHORITY_MANIFEST;
        let src = include_str!("sync.rs");
        let fields_of = |decl: &str| -> std::collections::BTreeSet<String> {
            let start = src.find(decl).unwrap_or_else(|| panic!("the census must find `{decl}`"));
            let body = &src[start..];
            let end = body.find("\n}").expect("the struct closes");
            body[..end]
                .lines()
                .filter_map(|l| l.trim().strip_prefix("pub "))
                .filter_map(|l| l.split(':').next())
                .map(|n| n.trim().to_string())
                // Digits are legal in a Rust field name: `l2_state_root` read as "not a bundle field" while it was
                // declared, carried and bound (DB-357) — a census that cannot read a field reports a false gap.
                .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
                .collect()
        };
        let mut bundle = fields_of("pub struct NullifierSnapshot {");
        bundle.extend(fields_of("pub struct SyncBundle {"));
        assert!(bundle.len() > 20, "CALIBRATION: the census reads the bundle's fields ({})", bundle.len());
        const CARRIED: &[(&str, &[&str])] = &[
            ("validators", &["bonded_validators", "finality_validators", "custody_seat_active_from", "finality_seat_active_from", "departed_custody_seats", "departed_finality_seats", "slashed_validators", "slashed_bond_burned", "validator_bond_commit", "validator_custody", "validator_kem_eks", "custody_seat_numbers"]),
            ("bond_locked", &["bond_locked_notes"]),
            ("unbonding", &["unbonding"]),
            ("bond_height", &["bond_heights"]),
            ("letter_acc", &["letter_acc"]),
            ("sparse_acc", &["sparse_root"]),
            ("nf_unspent_acc", &["nf_unspent_acc"]),
            ("nf_cover_conf_acc", &["nf_cover_conf_acc"]),
            ("dsol_tokens", &["dsol_registry_peaks", "dsol_registry_count"]),
            ("served_membership_acc", &["membership_tip"]),
            ("membership_tip_prev", &["membership_tip"]),
            ("membership_tip_root", &["membership_tip"]),
            ("spend_frontier", &["frontier"]),
            ("nf_fold_seq", &["fold_carry"]),
            ("nf_fold_base", &["nf_fold_base_words", "nf_fold_span"]),
            ("nf_base_prev", &["nf_fold_base_words"]),
            ("certified_anchor_score", &["anchor_blue_score"]),
            // peg sub-fields
            ("reserve_commit", &["peg_reserve_commit"]),
            ("minted_commit", &["peg_minted_commit"]),
            ("reserve_hwm_commit", &["peg_reserve_hwm_commit"]),
            ("ratio_bps", &["peg_ratio_bps"]),
            ("redeem_floor_bps", &["peg_redeem_floor_bps"]),
            ("yield_rate_bps", &["peg_yield_rate_bps"]),
            ("price_marks", &["peg_price_marks"]),
            // DB-357 part 1: carried + bound in sync_binding.
            ("wrapped_assets", &["peg_wrapped_assets"]), // DB-271 carried it; the census map was stale
            ("pools", &["peg_pools"]), // LIQUIDATION §10: carried + bound in sync_binding
            // LIQUIDATION §10: `PegLedger::pool_census` carries every closed epoch's words INSIDE `peg_pools` (an asset's
            // highest epoch is its pool, every lower one a close) and `adopt_certified_pools` splits them back.
            ("pool_closes", &["peg_pools"]),
            // A-F50: the IonSwap pool book — pending orders, USDm held, pool count — carried + bound in sync_binding.
            ("ion_pending", &["peg_ion_pending"]),
            ("ion_usdm_held", &["peg_ion_usdm_held"]),
            ("ion_pools", &["peg_ion_pools"]),
            // DB-274 (dir_set): the certified `dir_acc` is bound; the entries behind it are rebuilt by the refill door
            // (`dir_refill_page`), which applies the certified sequence in its one order and refuses any other.
            ("directory", &["dir_acc"]),
            ("retention_endowment_commit", &["peg_retention_endowment_commit"]),
            ("l2_state_root", &["l2_state_root"]),
            ("root_history", &["root_history_peaks_hex"]),
            // SATOSHI: carried + bound in sync_binding (the issued total and the pendulum snapshot).
            ("sat_issued", &["peg_sat_issued"]),
            ("pendulum_epoch_next", &["peg_pendulum"]),
            ("pendulum_share_bps", &["peg_pendulum"]),
            ("contract_state_root", &["peg_br"]), // §BR-12 L1: carried + bound (`PegBrWords`)
            ("fee_pool_stakers", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("fee_pool_bonders", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("fee_pool_surplus", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("fee_pool_miner", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("miner_quarter_next", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("miner_rate", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("miner_accrual", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("miner_quarter_start", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("bond_yield_lo", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("bond_yield_hi", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("bonder_accrual", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("set_aside_applied", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("deployments", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("release_attestations", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("stake_paid_commit", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("stakers_snap_epoch_next", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("stakers_snap_pool", &["peg_br"]), // §BR: carried + bound (`PegBrWords`)
            ("epoch_keys", &["peg_br"]), // §BR-9a: carried + bound (`PegBrWords`)
            ("epoch_anchors", &["peg_br"]), // §19.4: carried + bound (`PegBrWords`)
            ("price_history", &["peg_br"]), // §BR-4: carried + bound (`PegBrWords`)
            ("repayment_sat_pot", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("theft_loss_open_sats", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("repayment_owed_atomic", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("haircut_remainder_atomic", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("haircut_events", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("decoy_epoch_next", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("decoy_credit", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("decoy_budget", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("decoy_spent", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("vault_keys", &["peg_br"]), // SAFE AT SCALE §3f R1: the custody key record, carried + bound (`PegBrWords::vault_keys`)
            ("vault_parts", &["peg_br"]), // SAFE AT SCALE §3g.1: the parts at rest, carried + bound (`PegBrWords::vault_parts`)
            ("custody_cost_debt", &["peg_br"]), // SAFE AT SCALE §3f R6: carried + bound (`PegBrWords`)
            ("custody_cost_retired", &["peg_br"]), // SAFE AT SCALE §3f R6: carried + bound (`PegBrWords`)
            ("open_decoys", &["peg_br"]), // §BR-3 17.5 / §BR-8: carried + bound (`PegBrWords`)
            ("unit_book", &["peg_br"]), // §BR-4/§BR-7: carried + bound (`PegBrWords`)
            ("defi_book", &["peg_br"]), // §BR-15: carried + bound (`PegBrWords`)
        ];
        const REDERIVED: &[(&str, &str)] = &[
            ("relay", "the DAG is rebuilt from the bundle's anchor_block, tip_block and tips"),
            ("account_acc", "read from the certified tip header"),
            ("account_buckets", "the account DA lane delivers bucket rows, admitted against the certified accumulator"),
            ("da_mem", "the DA lane: each fetched record is admitted against the certified accumulator"),
            ("da_ladder_mem", "the DA lane (sealed ladder blobs are served, not carried)"),
            ("da_tags_mem", "the DA lane"), ("da_targets_mem", "the DA lane"), ("da_ord_mem", "the DA lane"),
            ("da_leafstart_mem", "the DA lane"), ("da_ord_rev_mem", "the DA lane"), ("da_ord_top", "the DA lane"),
            ("da_macc_rev_mem", "the DA lane"), ("da_macc_fwd_mem", "the DA lane"), ("da_macc_first", "the DA lane"),
            ("da_top", "the DA lane"), ("da_base", "the DA lane"), ("served_seq", "the DA lane"),
            ("nf_blocks", "the nullifier warm stream rebuilds the tree store behind the certified sparse root"),
            ("nf_leaves", "the nullifier warm stream"),
            // DB-357 part 1 — rebuilt, each with its reason (docs/DB-357-*.md §2):
            ("order_book", "a RAM-only matching index, refilled by gossip reflood (`reflood_page`); not an authority — a \
                fill is authorized by the pool and by the maker note's nullifier in the CARRIED spent set, so a stale \
                order books but can never fill"),
            ("finality", "re-formed from the CARRIED finality votes (`Class::FinalityVote` in `Block::bond_set`, tallied at \
                each body's graft over the CARRIED validator set — G2 2026-10-22); `None` is the designed 'no bound' \
                state, and an uncertified carried floor would be a permanent-capture lever"),
            // DB-274 P4b B1 — a one-time id (a burned USDm note, a deposit's key, a liquidation key) RETIRES AS A
            // NULLIFIER in the certified spent set the bundle carries (`sparse_root` + the band); the ledger's sets are
            // the class doors' early refusal over what THIS node applied, and a re-carried object is refused at the fold
            // by the set rule (`respend_decide_at_fold`, measured by the db367 / db358 r3 pins). A jumper's empty set
            // therefore admits nothing the chain refused: the fold decides before the door's answer matters.
            ("spent_burns", "a burned note's nullifier is in the CARRIED spent set (P4b B1); the set is a local cache"),
            ("confidential_deposit_ids", "a deposit's one-time id retires as a nullifier in the CARRIED spent set (P4b B1)"),
            ("liquidated", "a liquidation key retires as a nullifier in the CARRIED spent set (P4b B1)"),
        ];
        let mut uncovered: Vec<String> = Vec::new();
        let mut judge = |name: &str, what: &str| {
            if let Some((_, fs)) = CARRIED.iter().find(|(n, _)| *n == name) {
                let missing: Vec<&str> = fs.iter().copied().filter(|f| !bundle.contains(*f)).collect();
                if !missing.is_empty() {
                    uncovered.push(format!("{what}{name} (named carrier(s) {missing:?} are not bundle fields)"));
                }
            } else if !REDERIVED.iter().any(|(n, _)| *n == name) {
                uncovered.push(format!("{what}{name}"));
            }
        };
        for (name, a) in AUTHORITY_MANIFEST {
            if matches!(a, Authority::ChainDerived) && *name != "peg" {
                judge(name, "");
            }
        }
        for (name, a) in PEG_AUTHORITY_MANIFEST {
            if matches!(a, Authority::ChainDerived) {
                judge(name, "peg.");
            }
        }
        assert!(
            uncovered.is_empty(),
            "⛔⛔⛔ {} CHAIN-DERIVED FIELD(S) A NODE THAT JOINS BY DSYNC DOES NOT INHERIT — each is a value a jumper \
             holds differently from every node that watched the chain (the DB-259 shape: measured weight 0 vs 50,000):\n  {}",
            uncovered.len(),
            uncovered.join("\n  ")
        );
    }
}
