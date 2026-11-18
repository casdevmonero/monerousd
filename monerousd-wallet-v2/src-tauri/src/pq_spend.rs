// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! # Send engine (wallet side) — the in-process trustless-WHIR spend carrier.
//!
//! The wallet produces its spend proof IN-PROCESS via the SHARED, config-pinned entry
//! `usdm_decider::{prove,verify}_spend_carrier_bytes` (the SMALL crate — never the pqpool
//! circuit.rs monolith). The wallet owns ONLY the witness (the selected input note values +
//! the transfer amounts); the WHIR config and the AIR live in `usdm-decider`, which the NODE
//! also verifies carriers through — so prover and verifier share a SINGLE definition and the
//! spend is sound by construction (no divergence, no trusted setup, spend key never leaves).
//!
//! This is the conservation (no-inflation) layer of the shared entry: `in == out + fee`.
//! The completing bricks (extending the row to the full PqSpendAir membership + nullifier +
//! confidential balance, then repointing the node verify at this shared entry) light up a
//! node-accepted Send; they are tracked, not hidden.


// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 170 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;

use usdm_decider::{
    // ⚠️ API SYNC 2026-08-17 — the decider replaced every `*_validity_carrier_bytes` with the
    // `*_with_commit_bytes` form that binds the note-membership leaf commit, and the WALLET was never
    // updated: it imported five functions that no longer exist in the root, so `monerousd-wallet-v2` did
    // not COMPILE against the current node. A wallet that cannot build cannot send — this was the real
    // blocker behind "do repeated sends work cross-node", not anything in the node.
    // ⛔ `prove_spend_carrier_bytes`, `verify_spend_carrier_bytes` and `SpendRow` are NOT imported.
    // They are the conservation-only carrier — a statement whose whole public input is a constant, so
    // it names no note, key, nullifier, output, transaction or chain. Its wallet-side producer was
    // deleted 2026-09-08 and no door accepts it any more. Leaving the imports would leave the
    // shortcut one keystroke away from the next author who finds a sound carrier inconvenient.
    poseidon_pair, prove_bond_validity_carrier_with_commit_bytes, prove_mint_validity_bytes,
    prove_multi_spend_validity_carrier_bytes,
    prove_spend_validity_carrier_with_commit_bytes,
    verify_bond_validity_carrier_with_commit_bytes, verify_mint_validity_bytes,
    verify_multi_spend_validity_carrier_bytes, verify_spend_validity_carrier_bytes,
    MultiSpendInput, MultiSpendValidityWitness, SpendValidityWitness,
};

/// Build a MINT-VALIDITY carrier — proves `out0_cm` opens to EXACTLY `value` (the node-computed stake reward R) as a
/// confidential note under `reward_sk`, so the node can credit precisely R with no KEM key + the wallet cannot
/// inflate it. Thin wrapper over the shared `usdm_decider` entry the node verifies through. Returns
/// `(carrier, self_root, [reward_cm, out1_cm], nf)`; the caller seals the reward note to `reward_sk` (cm == cms[0]).
// API SYNC 2026-08-17: the mint carrier no longer carries a root/nullifier — `prove_mint_validity_bytes`
// returns `(carrier, out0_cm)` and the gate binds only the commitment and the value.
pub fn build_mint_carrier(value: u64, reward_opening: Digest4) -> Option<(Vec<u8>, Digest4)> {
    prove_mint_validity_bytes(value, &reward_opening)
}

/// DB-80 (2026-09-19): the mint-validity carrier that publishes NO amount — it binds the note's
/// commitment to `delta_commit = solvency_commit_256(value, d_blind)`, the same committed number the
/// custodians' solvency carrier opens. Returns `(carrier, out0_cm, delta_commit)`; `d_blind` is sealed to the
/// custodians with the request and never travels in the clear.
pub fn build_mint_carrier_committed(value: u64, reward_opening: Digest4, d_blind: Digest4) -> Option<(Vec<u8>, Digest4, Digest4)> {
    usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(value, &reward_opening, &d_blind)
}

/// A fresh mint-delta blind: eight field lanes from the OS CSPRNG (each below the KoalaBear modulus).
pub fn fresh_mint_blind() -> Digest4 {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    core::array::from_fn(|_| (rng.next_u64() >> 33) & 0x7fff_ffff)
}

/// Wallet self-check of a mint carrier (the SAME verify the node runs) before broadcast — fail-closed.
pub fn mint_carrier_selfverifies(carrier: &[u8], out0_cm: Digest4, value: u64) -> bool {
    verify_mint_validity_bytes(carrier, out0_cm, value)
}

/// The in-circuit note commitment the spend proves it opens — THE decider's `asset_note_cm` under the
/// USDm tag, never a local formula.
///
/// ⛔ THIS WAS A LOCAL COPY, `poseidon_pair(usdm_decider::poseidon2_compress::lanes_of(&[value_in, 0, 0, 0]), sk)`, used at nine sites on the live
/// spend path (2026-09-11). When the decider's commitment became the two-round
/// `P(limbs(value), P([tag, 0], sk))` — the value as limbs, so a note holding `v` cannot be spent as
/// `v + p` — a copy here would have silently derived a DIFFERENT leaf from the one the chain holds,
/// and every owned note would have been unfindable and unspendable. One formula, defined once.
pub fn note_commitment(value_in: u64, opening: Digest4) -> Digest4 {
    usdm_decider::whir_rec_block::asset_note_cm(value_in, usdm_decider::whir_rec_block::USDM_ASSET_TAG, opening)
}

/// Production frontier depth (== node `NOTE_TREE_DEPTH`). The Poseidon frontier is SPARSE: only the N
/// real note commitments are stored; every other position is the empty leaf, so the tree is NOTE_TREE_DEPTH deep
/// but built in O(N·32), never O(2^32).
// ⛔⛔⛔ MUST EQUAL the node's `spend_frontier::SPEND_TREE_DEPTH`. It was 32 on both sides, and 32 gave the
// chain a DEATH DATE 97 days after genesis: the frontier is fixed-height, `append` refuses at
// `2^depth` leaves, and the constant 256-leaf cover shape burns that capacity at 44,236,800 leaves/day
// regardless of traffic. A refusal to append is a refusal to RECEIVE. At 64 the capacity saturates u64 —
// ~1.1e9 years at the same rate. A mismatch between this and the node makes every spend unverifiable, so
// these two constants move together or not at all.
pub const NOTE_TREE_DEPTH: usize = usdmd_node::spend_frontier::SPEND_TREE_DEPTH;
// DB-81's per-class carrier depths (`BOND_/BURN_/SPEND_CARRIER_DEPTH`) are GONE (2026-09-30): the spend, burn and
// welded bond carriers take no depth and no root any more — gate D, the Merkle path they parameterised, was found
// decorative by the census and deleted at source — so the 2026-09-18 class (this file said 64 where the aggregate
// said 0, and the burn door said 128) is closed by construction, not by three constants that had to agree.

/// ⭐ DB-363 (2026-09-30) — THE PER-OBJECT BLINDING OF THE MEMBERSHIP CROSS-BIND, carried from where a spend, burn,
/// order or fill is assembled to the ONE other place that must see it: the note-membership carrier built for the same
/// object. `leaf_commit = P(P(leaf, nullifier), blind)`; the blind is drawn once from the OS CSPRNG
/// (`usdm_decider::whir_rec_block::fresh_lc_blind`) and is what stops an observer joining the spend to the leaf it
/// consumed (the unblinded `P(leaf, nullifier)` was recomputable from the tx's own nullifier — MEASURED, 643 of 1,024
/// leaves singled out). It lives only inside the call that assembles the object: `Debug` prints nothing of it, so no
/// log or error string can carry it, and it is never persisted or put on the wire.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LcBlind(pub Digest4);

impl core::fmt::Debug for LcBlind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LcBlind(<hidden>)")
    }
}

/// The empty-leaf sentinel for unfilled frontier positions. (Node-parity: this must equal the node's
/// Poseidon empty-leaf value; matching that exact constant is the node-serve step.)
fn poseidon_empty_leaf() -> Digest4 {
    // ⭐ ONE DEFINITION, THE NODE'S. A literal `usdmd_node::spend_frontier::empty_leaf()` is a 4-lane value wearing an 8-lane type's
    // name; `empty_leaf()` is the constant the node's own padding uses, so the two can never disagree.
    usdmd_node::spend_frontier::empty_leaf()
}

/// Hash of a fully-empty subtree of the given level (memo-free; `level` ≤ 32 so ≤32 hashes).
fn poseidon_empty_subtree(level: usize) -> Digest4 {
    let mut h = poseidon_empty_leaf();
    for _ in 0..level {
        h = poseidon_pair(h, h);
    }
    h
}

/// Hash of the subtree of height `level` whose leftmost leaf is index `start`, over the SPARSE real
/// leaf set (positions ≥ `leaves.len()` are empty). An all-empty subtree short-circuits to
/// `poseidon_empty_subtree` — so the whole tree is O(N·depth), never O(2^depth).
fn poseidon_subtree_hash(leaves: &[Digest4], level: usize, start: usize) -> Digest4 {
    if start >= leaves.len() {
        return poseidon_empty_subtree(level);
    }
    if level == 0 {
        return leaves[start];
    }
    let half = 1usize << (level - 1);
    let l = poseidon_subtree_hash(leaves, level - 1, start);
    let r = poseidon_subtree_hash(leaves, level - 1, start + half);
    poseidon_pair(l, r)
}

/// The sparse production-depth (NOTE_TREE_DEPTH) Poseidon frontier root over the real note commitments (append order) — what the
/// spend-membership gate recomputes from a leaf + its copath.
pub fn poseidon_frontier_root(leaves: &[Digest4]) -> Digest4 {
    poseidon_subtree_hash(leaves, NOTE_TREE_DEPTH, 0)
}

/// Build the `NOTE_TREE_DEPTH` copath (`siblings`, `dirs`) of the leaf at `index` in the sparse Poseidon
/// frontier — `dirs[i] = true` when the node is the RIGHT child at level `i` (the gate's direction bit).
/// Each sibling is the subtree hash of the sibling range (empty ranges short-circuit). Feeds directly
/// into [`build_spend_validity_carrier`].
pub fn poseidon_frontier_copath(leaves: &[Digest4], index: usize) -> Option<(Vec<Digest4>, Vec<bool>)> {
    // ⛔ AT DEPTH >= 64 THE CEILING IS UNREACHABLE, AND COMPUTING IT OVERFLOWS.
    //
    // This read `index >= (1usize << NOTE_TREE_DEPTH)`, which is a compile error at depth 64: the shift
    // does not fit a usize. That is the same shape the node hit in `capacity()` and it says something
    // real — an index is a usize, so a tree of 2^64 leaves cannot be indexed past its end. The depth was
    // raised from 32 because 32 gave the chain a DEATH DATE 97 days after genesis (the frontier fills at
    // 256 leaves/block regardless of traffic, and a refusal to append is a refusal to receive), so this
    // bound must express "unreachable", not compute an unrepresentable number.
    //
    // Below 64 the ceiling is real and still checked; at 64 and above every usize index is in range.
    if NOTE_TREE_DEPTH < usize::BITS as usize && index >= (1usize << NOTE_TREE_DEPTH) {
        return None;
    }
    let mut siblings = Vec::with_capacity(NOTE_TREE_DEPTH);
    let mut dirs = Vec::with_capacity(NOTE_TREE_DEPTH);
    for level in 0..NOTE_TREE_DEPTH {
        dirs.push((index >> level) & 1 == 1);
        let sib_start = (((index >> level) ^ 1) << level) & !((1usize << level) - 1);
        siblings.push(poseidon_subtree_hash(leaves, level, sib_start));
    }
    Some((siblings, dirs))
}

/// KoalaBear prime — for canonicalizing unpacked note_cm limbs. MUST match the node's `spend_frontier::KB_P`.
const KB_P: u64 = 2_130_706_433;

/// Unpack a 32-byte on-chain `note_cm` into a Poseidon leaf (4 little-endian KoalaBear limbs) — the SAME
/// packing the node's `spend_frontier::cm_bytes_to_leaf` uses, so the wallet's copath binds to the exact
/// leaf the node recorded (and to its served `spend_root`).
pub fn cm_bytes_to_leaf(cm: &[u8; 32]) -> Digest4 {
    // ⛔⛔⛔ THIS WAS A SECOND COPY OF THE NODE'S FUNCTION, AND IT HAD DRIFTED THREE WAYS: four lanes
    // instead of eight (§AG), the PRE-§AG decode rather than the current one, and — after §AO — the wrong
    // one of the two. A note's LEAF is its COMMITMENT, reached by the INJECTIVE decode; the hash is for
    // arbitrary ids. The doc directly above this function has always said so:
    //     "the spend proves membership of exactly `cm_bytes_to_leaf(note_cm) = note_commitment(value, sk)`"
    // — which is true only of the decode, and is exactly what §AO made true on the node side.
    //
    // ⭐ ONE DEFINITION, THE NODE'S. A copath built over a different value cannot attach to the record
    // that holds it, and a spend whose membership names a different note cannot verify.
    usdmd_node::spend_frontier::note_leaf_of(cm)
}

/// The 32-byte on-chain `note_cm` the RECIPIENT publishes = its Poseidon note commitment serialized. When the
/// note is later spent, the spend proves membership of exactly `cm_bytes_to_leaf(note_cm) = note_commitment(value, sk)`.
/// The note's commitment under an ASSET TAG — `poseidon([value, t0, t1, t2], sk)`, packed the same
/// way as [`note_cm_bytes`]. With the USDm tag (all zeros) it produces byte-identical output, which is
/// what lets a tagged and an untagged USDm note be the same object on chain.
///
/// ROOT-LAYER: the asset enters value here, in the commitment itself, because that is the only place a
/// note's denomination can be made unforgeable. A tag carried beside the note (in a payload field, an
/// index, or a wallet-side label) is an assertion any party could restate differently; a tag inside the
/// Poseidon preimage is a fact the spend circuit re-derives and the node re-checks.
/// MEASURED: `usdm_decider::whir_rec_block` pins the equivalence at the circuit end —
/// `asset_zero_cm_matches_the_legacy_usdm_note_cm` compares all 4 limbs at values 0, 1, 100000000 and
/// u64::MAX, and 322/322 decider tests pass with the tagged gates in.
/// MUST-STAY-GREEN: every existing USDm path — `note_cm_bytes`, `note_nullifier`, the spend carriers,
/// and the wallet's 104 lib tests — none of which pass a tag and all of which must keep their bytes.
pub fn note_cm_asset_bytes(value: u64, asset: [u64; 3], opening: Digest4) -> [u8; 32] {
    usdmd_node::spend_frontier::leaf_to_cm_bytes(usdm_decider::whir_rec_block::asset_note_cm(
        value, asset, opening,
    ))
}

/// The canonical 32-byte form of a 4-limb commitment or nullifier — the SAME encoding
/// `note_cm_bytes` writes and the node's `spend_frontier::leaf_to_cm_bytes` reads.
///
/// ⛔ ONE ENCODING, IN ONE PLACE. Each limb is reduced mod the KoalaBear prime before it is written; a
/// second, unreduced conversion beside this one would eventually produce a DIFFERENT 32 bytes for the
/// SAME value, and a note with two nullifier encodings is a note that can be spent twice.
// ⛔⛔⛔ THE ENCODERS HAD DRIFTED, MEASURED 2026-09-17. `cm_bytes_to_leaf` above was routed to the node's
// injective DECODE in §AO, and these three ENCODERS were left as they were: four 8-byte little-endian limbs
// of an EIGHT-lane digest — lanes 4..7 dropped, and a layout the node's `digest_from_bytes` (8 × 31-bit
// packed) reads as a DIFFERENT digest. So every note this wallet SEALED — a recipient's note, a change
// note, a mint note — carried a commitment front the node decoded to `[lane0, 0, garbage, …]`, and the
// spend cross-bind (`cm_bytes_to_root(note[..32]) == the carrier's commitment`) could never hold: a
// wallet-sealed note was unspendable on the current node. The wallet's own cross-check
// (`sealed_note_is_a_spendable_poseidon_leaf_and_scan_recovers_amount_and_sk`) says exactly this — and it
// had not compiled since 2026-09-15 (a `settlement` field removed from `Block`), so nobody saw it.
// ONE definition: the node's `leaf_to_cm_bytes`, whatever the lane count is or becomes.
pub fn cm_limbs_to_bytes(limbs: Digest4) -> [u8; 32] {
    usdmd_node::spend_frontier::leaf_to_cm_bytes(limbs)
}

pub fn note_cm_bytes(value: u64, opening: Digest4) -> [u8; 32] {
    usdmd_node::spend_frontier::leaf_to_cm_bytes(note_commitment(value, opening))
}

/// The note's PUBLIC nullifier `nf = P(nk, leaf)` (`leaf = note_commitment(value, owner.opening())`) — the SAME value the
/// spend carrier welds and the node records when this note is spent. The wallet computes it locally for each owned note to
/// tell whether that note is already spent (so a spent note is excluded from the balance). ⛔ DB-395: it needs the owner's
/// `nk`, which the note's sender never holds — the sender cannot watch for the payee's spend.
pub fn note_nullifier(value: u64, owner: &usdm_decider::whir_rec_block::NoteOwner) -> [u8; 32] {
    note_nullifier_asset(value, owner, usdm_decider::whir_rec_block::USDM_ASSET_TAG)
}

/// ⭐ THE ONE NULLIFIER RULE, FOR A NOTE OF ANY ASSET: `nf = P(nk, asset_note_cm(value, asset, o))` — the value every gate
/// that spends a note welds (the USDm spend, the stake gate over a staked input, the pool deposit, the asset transfer: each
/// lays `leaf` under the note's OWN tag, then `nf = compress(nk, leaf)`). [`note_nullifier`] is this at the USDm tag. A
/// wrapped or staked note's nullifier spelled with the USDm tag names a nullifier no spend ever records, so its spent
/// status could never be read.
pub fn note_nullifier_asset(value: u64, owner: &usdm_decider::whir_rec_block::NoteOwner, asset: [u64; 3]) -> [u8; 32] {
    let leaf = usdm_decider::whir_rec_block::asset_note_cm(value, asset, owner.opening());
    // The node records a spent nullifier as `leaf_to_cm_bytes(nf)` (the same canonical digest form every
    // carrier's burn is compared against); the 4-limb LE loop that stood here was the same drift as the
    // commitment encoders above (measured 2026-09-17).
    usdmd_node::spend_frontier::leaf_to_cm_bytes(owner.nullifier(&leaf))
}

/// Parse the node's `/get_pq_output_tree` `notes_hex` (concatenated 32-byte `note_cm`, hex) into the Poseidon
/// leaf set the copath builder needs. `None` if the hex is malformed (not a whole number of 32-byte leaves).
pub fn parse_served_leaves(notes_hex: &str) -> Option<Vec<Digest4>> {
    if notes_hex.len() % 2 != 0 {
        return None;
    }
    let bytes: Option<Vec<u8>> =
        (0..notes_hex.len()).step_by(2).map(|i| u8::from_str_radix(&notes_hex[i..i + 2], 16).ok()).collect();
    let bytes = bytes?;
    if bytes.len() % 32 != 0 {
        return None;
    }
    Some(bytes
        .chunks_exact(32)
        .map(|c| {
            let mut a = [0u8; 32];
            a.copy_from_slice(c);
            cm_bytes_to_leaf(&a)
        })
        .collect())
}

// ⛔⛔⛔ DELETED 2026-09-08 — `transfer_rows`, `build_spend_carrier`, `carrier_selfverifies`.
//
// These built the CONSERVATION-ONLY spend carrier: a proof of `in - out - fee == 0` whose entire
// public input is the constant `SPEND_CARRIER_DOMAIN` — no note, no key, no nullifier, no output
// commitment, no anchor, no chain. A carrier that names no transaction admits every transaction, and
// it took no secret to build: three integers.
//
// They had NO production caller. Every real send in this wallet goes through
// `build_spend_validity_carrier_cross_bound` (single input) or `build_multi_spend_validity_carrier`
// (multi input), which weld the anchor root, both output commitments, the nullifier and the
// membership cross-bind. The only callers these ever had were their own tests — so this was a public
// producer for a statement no honest sender sent, sitting beside the door that accepted it.
//
// Deleted at SOURCE rather than gated around (hygiene cardinal): a dead producer for an unsound
// statement is exactly the thing a future author reaches for when a sound carrier is inconvenient.
// The node's matching admission arm is gone in the same change (`chain_object::admissible`'s unframed
// arm, and `direct_ok` in the `/submit_pq_tx` door).

/// Build the FULL confidential-spend carrier — the byte-parity PqSpendAir row (conservation +
/// note-opening + nullifier + the blinded membership cross-bind) — for a transfer of `send` (+ `fee`) from an
/// input note worth `value_in` held by `owner` (DB-395: the wallet's `(ask, nk)` and the note's seed). No Merkle path and
/// no root: membership is the
/// note-membership carrier's, welded to this proof by `leaf_commit = P(P(leaf, nullifier), lc_blind)`, so the
/// caller passes the SAME `lc_blind` to both builders (DB-363). The change `value_in − send − fee` is folded into
/// the output so `value_out = value_in − fee` and conservation holds by construction. Returns
/// `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit)`; None if the note cannot fund `send + fee`.
/// `filing_d`: the spend's filing digest ([`spend_filing_d`], DB-351), bound LAST — the carrier verifies only under the
/// clue list this spend attaches.
#[allow(clippy::too_many_arguments)]
pub fn build_spend_validity_carrier(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
    filing_d: Digest4,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4)> {
    let need = send.checked_add(fee)?;
    if value_in < need {
        return None; // unfunded — never fabricate a shortfall
    }
    let value_out = value_in.checked_sub(fee)?; // = send + change
    let change = value_out.checked_sub(send)?; // value_in − send − fee ≥ 0
    // The remainder is a FRESH note sealed to the spender's own address (`pq::seal_note_change`, DB-273 D0 — the re-issue
    // that copied the input's ciphertext is retired). DB-395: neither output carries a key; each is the OPENING
    // `P(spk_owner, seed)` its sealer computed, so the commitment opens for the conservation proof while spend authority
    // stays with each note's own `(ask, nk)`.
    //
    // Two confidential outputs: out0 = the recipient note (send, recipient_opening), out1 = the change note
    // (change, change_opening). The carrier welds both commitments PUBLIC + proves value_out = send + change, so
    // the node records EXACTLY these notes and no output can inflate.
    let w = SpendValidityWitness {
        value_in,
        owner,
        value_out,
        fee,
        lc_blind,
        out0_value: send,
        out0_opening: recipient_opening,
        out1_value: change,
        out1_opening: change_opening,
    };
    prove_spend_validity_carrier_with_commit_bytes(&w, filing_d)
}

/// ⭐⭐⭐ DB-351 — THE FILING DIGEST D A SPEND BINDS LAST: over its outputs' `(cm, k)` from the clue list it attaches,
/// through the node's ONE encoding (`usdmd_node::oli`), so the pool door's recompute from the pooled tx and every
/// peer's recompute from the block's `oli_tags` reach the same bytes. `outputs` are the two sealed notes' fronts;
/// `clue_records` is exactly the list the tx carries as `note_clues`. `None` when that list is not canonical
/// (records strictly ascending by cm, every cm one of these outputs): the node would refuse it by name, so the
/// wallet refuses to prove over it.
pub fn spend_filing_d(outputs: &[[u8; 32]], clue_records: &[u8]) -> Option<Digest4> {
    let records = usdmd_node::oli::canonical_clue_records(outputs, clue_records)?;
    let bytes = usdmd_node::oli::filing_d_bytes_from_clues(outputs, &records)?;
    Some(usdmd_node::oli::filing_d_digest(&bytes))
}

/// DB-351 — a clue list in its ONE encoding: the same records (`cm ‖ len u16 LE ‖ clue`, parsed by the node's one
/// reader), reordered strictly ascending by cm. `None` when the bytes do not parse whole or name one cm twice (no
/// canonical order exists). The node refuses any other order by name, so a send builds its list through here.
pub fn canonical_clue_bytes(records: &[u8]) -> Option<Vec<u8>> {
    let mut parsed = usdmd_node::node::Node::parse_note_clue_records(records)?;
    parsed.sort_by(|a, b| a.0.cmp(&b.0));
    if parsed.windows(2).any(|w| w[0].0 == w[1].0) {
        return None;
    }
    let mut out = Vec::with_capacity(records.len());
    for (cm, clue) in parsed {
        out.extend_from_slice(&cm);
        out.extend_from_slice(&u16::try_from(clue.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&clue);
    }
    Some(out)
}

/// ⭐ [`build_spend_validity_carrier`] with the change note under its own key (`change_opening`) — the shape every live
/// send builds. Cross-bound exactly as above.
///
/// Returns the `leaf_commit = P(P(spent_leaf, nullifier), lc_blind)` — the same value the wallet's
/// `NoteMembershipCarrier` binds — proven IN-CIRCUIT. That is what stops the two proofs being about two
/// different notes: without the weld a spender could hold a valid membership proof for note X and spend
/// note Y, and both statements would be true.
///
/// The leaf never leaves the wallet. It is the value written when the note was RECEIVED, so publishing it
/// would link this spend to that receive; the commitment names the note without identifying it, and because
/// `lc_blind` is fresh per send (DB-363) no observer can recompute it from the public nullifier and the public
/// leaves — the same note commits differently in every transaction and the carrier cannot be replayed into another.
#[allow(clippy::too_many_arguments)]
pub fn build_spend_validity_carrier_cross_bound(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    // DB-363: the per-send blinding — `fresh_lc_blind()` at the assembly site, shared with the membership carrier.
    lc_blind: Digest4,
    // DB-351: [`spend_filing_d`] of the clue list this tx attaches, bound LAST.
    filing_d: Digest4,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4)> {
    let w = send_witness(value_in, owner, send, fee, recipient_opening, change_opening, lc_blind)?;
    prove_spend_validity_carrier_with_commit_bytes(&w, filing_d)
}

/// DB-329 §7e — [`build_spend_validity_carrier_cross_bound`] as a SELF-CLAIMING send: row 1 of the tag list is
/// `N_d = P([SLOT_CLAIM_DOMAIN, d, 0…], slot_key)` ([`self_claim_tag`]) proven in-circuit under the spender's own
/// witness, so the nullifier SET — not luck or a local store — refuses a second install of the same seed claiming
/// slot `d`. Returns the carrier tuple plus `tag1` READ FROM THE PROVER's row (the decider's one spelling).
#[allow(clippy::too_many_arguments)]
pub fn build_spend_validity_carrier_self_claiming(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
    filing_d: Digest4,
    slot_key: Digest4,
    d: u64,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    let w = send_witness(value_in, owner, send, fee, recipient_opening, change_opening, lc_blind)?;
    usdm_decider::whir_rec_block::prove_spend_validity_carrier_claiming_bytes(&w, filing_d, slot_key, d)
}

/// ⭐ goods spec §9.1 — THE NOTE-CLASS SPEND AS EVERY SEND BUILDS IT: [`build_spend_validity_carrier_cross_bound`] /
/// [`build_spend_validity_carrier_self_claiming`] proven against the chain clock and with the vault lanes `extras`
/// names (`NoteSpendExtras::plain(clock_h)` for an ordinary payment; an output that opens a vault; a vault spent
/// through a lock or its clock). `claim` is the claim's `(key, d)`: `(lc_blind, 0)` for an ordinary send, `(slot_key, d)`
/// for a device-slot claim (unread on a vault's lock branch, whose claim is the lock). ONE carrier shape for all of
/// them, so no relay and no node tells a protected purchase from a payment. Returns
/// `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit, tag1)`.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn build_note_spend(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
    filing_d: Digest4,
    claim: (Digest4, u64),
    extras: &usdm_decider::whir_rec_block::NoteSpendExtras,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    let w = send_witness(value_in, owner, send, fee, recipient_opening, change_opening, lc_blind)?;
    usdm_decider::whir_rec_block::prove_note_spend_bytes(&w, extras, filing_d, claim.0, claim.1)
}

/// [`validity_carrier_selfverifies`] under the chain clock (in chain hours) the carrier was proven against: the SAME
/// verify the node's pool door runs on `PqTx::clock_ms`.
#[allow(clippy::too_many_arguments)]
pub fn note_spend_selfverifies(
    carrier: &[u8],
    out0_cm: Digest4,
    out1_cm: Digest4,
    nullifier: Digest4,
    leaf_commit: Digest4,
    filing_d: Digest4,
    tag1: Digest4,
    clock_h: u64,
) -> bool {
    usdm_decider::whir_rec_block::verify_note_spend_bytes(
        carrier, out0_cm, out1_cm, nullifier, leaf_commit, filing_d, tag1, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, clock_h,
    )
}

/// The one-input/two-output witness of a send; None when `value_in` cannot fund `send + fee` (never fabricate a
/// shortfall).
fn send_witness(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
) -> Option<SpendValidityWitness> {
    let need = send.checked_add(fee)?;
    if value_in < need {
        return None;
    }
    let value_out = value_in.checked_sub(fee)?;
    let change = value_out.checked_sub(send)?;
    Some(SpendValidityWitness {
        value_in,
        owner,
        value_out,
        fee,
        lc_blind,
        out0_value: send,
        out0_opening: recipient_opening,
        out1_value: change,
        out1_opening: change_opening,
    })
}

/// Wallet-side self-check of a full-validity carrier against the two output commitments, the nullifier, the
/// cross-bind and the filing digest (the SAME verify the node runs — no root, no depth), before broadcast. Fail-closed.
///
/// API SYNC 2026-08-17: the cross-bind is MANDATORY — the decider takes `Digest4`, not an `Option`. There is no
/// "carrier with no membership claim" variant, so an absent commit can never silently skip the bind that ties the
/// spend to its note.
pub fn validity_carrier_selfverifies(
    carrier: &[u8],
    out0_cm: Digest4,
    out1_cm: Digest4,
    nullifier: Digest4,
    leaf_commit: Digest4,
    // DB-351: the filing digest the carrier was proved over — the node recomputes it from the tx's clue list.
    filing_d: Digest4,
    // DB-329 §7f: the claim tag the tx publishes as row 1 of its tag list ([`ordinary_claim_tag`] for a plain send).
    tag1: Digest4,
) -> bool {
    verify_spend_validity_carrier_bytes(carrier, out0_cm, out1_cm, nullifier, leaf_commit, filing_d, tag1, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

/// DB-329 §7f — the claim tag an ORDINARY send publishes (row 1 of its tag list): the claim of `(lc_blind, 0)`, the
/// decider's one spelling. Distinct per send because `lc_blind` is fresh per send, so it links nothing.
#[must_use]
pub fn ordinary_claim_tag(lc_blind: Digest4) -> Digest4 {
    usdm_decider::whir_rec_block::ordinary_claim_tag(lc_blind)
}

/// DB-329 §7e — the domain of the seed's device-slot key (distinct from every other `P(nk, ·)` the wallet spells).
const SLOT_KEY_DOMAIN: u64 = 0x534c_4b59; // "SLKY"

/// DB-329 §7e — the seed's DEVICE-SLOT KEY `P(nk, lanes(SLOT_KEY_DOMAIN))`: every install of one seed derives the
/// same key (so two installs claiming slot `d` publish the same `N_d` and the set refuses the second), and it is
/// built from the secret `nk`, so no observer can compute any `N_d` or link two claims of one seed.
#[must_use]
pub fn slot_key(nk: &Digest4) -> Digest4 {
    usdm_decider::whir_rec_block::poseidon_pair(*nk, usdm_decider::poseidon2_compress::lanes_of(&[SLOT_KEY_DOMAIN]))
}

/// DB-329 §7e — the self-claim tag `N_d` of slot `d` under `slot_key` (the decider's one spelling).
#[must_use]
pub fn self_claim_tag(slot_key: Digest4, d: u64) -> Digest4 {
    usdm_decider::slot_ledger::slot_claim_native(slot_key, d)
}

/// One input note for a fully-private multi-input consolidation spend (its confidential value, spend key, copath).
pub struct SpendInputNote {
    pub value_in: u64,
    pub owner: usdm_decider::whir_rec_block::NoteOwner,
    pub siblings: Vec<Digest4>,
    pub dirs: Vec<bool>,
}

/// Build the FULLY-PRIVATE MULTI-INPUT carrier — ONE transaction spending N confidential input notes to a single
/// recipient note + a change note, with conservation `Σ value_in == send + fee` proven IN-CIRCUIT (every input
/// amount stays private, never public IO). This is the sound replacement for the N-separate-tx sweep: a fragmented
/// balance is spent as ONE private tx, so the recipient gets ONE note and there is no input-count / cross-tx
/// correlation leak. Returns the carrier + the shared frontier `root` + the two output cms + the N nullifiers the
/// node records as spent. None if the inputs cannot fund `send + fee` (never fabricate a shortfall).
pub fn build_multi_spend_validity_carrier(
    inputs: Vec<SpendInputNote>,
    send: u64,
    fee: u64,
    recipient_opening: Digest4,
    change_opening: Digest4,
    // DB-351: [`spend_filing_d`] of the clue list this tx attaches, bound LAST.
    filing_d: Digest4,
) -> Option<(Vec<u8>, Digest4, [Digest4; 2], Vec<Digest4>)> {
    let mut total: u64 = 0;
    for i in &inputs {
        total = total.checked_add(i.value_in)?;
    }
    let need = send.checked_add(fee)?;
    if total < need {
        return None; // unfunded across all inputs — never fabricate a shortfall
    }
    let change = total.checked_sub(need)?; // Σ value_in − send − fee ≥ 0
    // The remainder is the caller's FRESH change note (DB-273 D0); its opening is `change_opening` (DB-395).
    let w = MultiSpendValidityWitness {
        inputs: inputs
            .into_iter()
            .map(|i| MultiSpendInput { value_in: i.value_in, owner: i.owner, siblings: i.siblings, dirs: i.dirs })
            .collect(),
        out0_value: send,
        out0_opening: recipient_opening,
        out1_value: change,
        out1_opening: change_opening,
        fee,
    };
    prove_multi_spend_validity_carrier_bytes(&w, filing_d)
}

/// Wallet-side self-check of a multi-input carrier (the SAME verify the node runs — root + 2 cms + N nullifiers + D)
/// before broadcast. Fail-closed.
pub fn multi_validity_carrier_selfverifies(
    carrier: &[u8],
    root: Digest4,
    out0_cm: Digest4,
    out1_cm: Digest4,
    nullifiers: &[Digest4],
    depth: usize,
    filing_d: Digest4,
) -> bool {
    verify_multi_spend_validity_carrier_bytes(carrier, root, out0_cm, out1_cm, nullifiers, depth, filing_d, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

/// Build a VALIDATOR-BOND carrier — the full PqSpendAir row PLUS a public `out0_value == bond` weld — for a
/// validator locking `bond` (+ `fee`) from an input note worth `value_in` under spend key `sk`. output0 (the
/// bonded note, to the validator's OWN address under `bond_opening`) locks EXACTLY `bond`; output1 is change. On
/// graft the node admits the validator with weight `bond`, provably equal to the locked value (no over-claim),
/// while `bond_opening` NEVER leaves the wallet. `lc_blind`: the per-object blinding shared with the membership carrier
/// (DB-363). Returns `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit)`; None if unfunded.
pub fn build_bond_validity_carrier(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    bond: u64,
    fee: u64,
    bond_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4)> {
    let need = bond.checked_add(fee)?;
    if value_in < need {
        return None; // unfunded — never fabricate a bond it can't back
    }
    let value_out = value_in.checked_sub(fee)?; // = bond + change
    let change = value_out.checked_sub(bond)?; // value_in − bond − fee ≥ 0
    let w = SpendValidityWitness {
        value_in,
        owner,
        value_out,
        fee,
        lc_blind,
        out0_value: bond, // the BONDED note, to the validator's own address
        out0_opening: bond_opening,
        out1_value: change,
        out1_opening: change_opening,
    };
    prove_bond_validity_carrier_with_commit_bytes(&w, bond)
}

/// Build a BOND-class carrier that takes its membership from the ACCUMULATOR, not from a Merkle root.
///
/// ⛔⛔⛔ WHY: the plain builder above welds the LIVE frontier root, which appends on every block — so a
/// carrier built before a block landed is refused after it. That race is what the wallet used to paper over
/// with `for _attempt in 0..6u32` (stake claim) and `for _attempt in 0..8u32` (peg-out): a bound on how many
/// tries a user's own money gets, ending in a refusal that named a counter rather than a reason.
///
/// Returns the extra `leaf_commit` the caller must pair with a note-membership carrier binding the SAME
/// value (built with the SAME `lc_blind`, DB-363). With the two together nothing the proof depends on moves, so
/// ONE attempt always suffices and the counters are deleted rather than tuned. There is no path and no root in
/// this carrier at all any more (gate D deleted 2026-09-30).
#[allow(clippy::too_many_arguments)]
pub fn build_bond_validity_carrier_cross_bound(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    bond: u64,
    fee: u64,
    bond_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4)> {
    let need = bond.checked_add(fee)?;
    if value_in < need {
        return None; // unfunded — never fabricate a bond it can't back
    }
    let value_out = value_in.checked_sub(fee)?;
    let change = value_out.checked_sub(bond)?;
    let w = SpendValidityWitness {
        value_in,
        owner,
        value_out,
        fee,
        lc_blind,
        out0_value: bond,
        out0_opening: bond_opening,
        out1_value: change,
        out1_opening: change_opening,
    };
    usdm_decider::prove_bond_validity_carrier_with_commit_bytes(&w, bond)
}

/// ⭐ B15 — a COMMITTED peg-out burn: the same spend as [`build_bond_validity_carrier_cross_bound`], its burned amount bound
/// only to `solvency_commit_256(burn, b_blind)` (the piece's leg blind derives `b_blind`, `peg::peg_out_burn_blind`), never
/// a public weight — so the chain verifies the burn without learning a cash-out's size. Returns
/// `(carrier, [out0_cm, out1_cm], nullifier, leaf_commit, burn_commit)`; `None` if unfunded.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn build_burn_carrier_committed(
    value_in: u64,
    owner: usdm_decider::whir_rec_block::NoteOwner,
    burn: u64,
    fee: u64,
    burn_opening: Digest4,
    change_opening: Digest4,
    lc_blind: Digest4,
    b_blind: Digest4,
) -> Option<(Vec<u8>, [Digest4; 2], Digest4, Digest4, Digest4)> {
    let need = burn.checked_add(fee)?;
    if value_in < need {
        return None;
    }
    let value_out = value_in.checked_sub(fee)?;
    let change = value_out.checked_sub(burn)?;
    let w = SpendValidityWitness {
        value_in,
        owner,
        value_out,
        fee,
        lc_blind,
        out0_value: burn,
        out0_opening: burn_opening,
        out1_value: change,
        out1_opening: change_opening,
    };
    usdm_decider::whir_rec_block::prove_burn_validity_committed_bytes(&w, &b_blind)
}

/// Wallet-side self-check of a CROSS-BOUND bond carrier — the same verify the node runs, including the
/// `leaf_commit` cross-bind; no root and no depth exist to mismatch. Fail-closed, so a carrier the node would
/// refuse is caught here rather than after a broadcast.
pub fn bond_carrier_cross_bound_selfverifies(
    carrier: &[u8],
    out0_cm: Digest4,
    out1_cm: Digest4,
    nullifier: Digest4,
    bond: u64,
    leaf_commit: Digest4,
) -> bool {
    usdm_decider::verify_bond_validity_carrier_with_commit_bytes(carrier, out0_cm, out1_cm, nullifier, bond, leaf_commit, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

/// Wallet-side self-check of a bond carrier against the two output commitments, the nullifier, the public `bond`
/// weight AND the cross-bind (the SAME verify the node runs), before broadcast. Fail-closed.
pub fn bond_carrier_selfverifies(
    carrier: &[u8],
    out0_cm: Digest4,
    out1_cm: Digest4,
    nullifier: Digest4,
    bond: u64,
    leaf_commit: Digest4,
) -> bool {
    verify_bond_validity_carrier_with_commit_bytes(carrier, out0_cm, out1_cm, nullifier, bond, leaf_commit, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC)
}

#[cfg(test)]
mod tests {
    use super::*;
    use usdm_decider::whir_rec_block::NoteOwner;

    /// DB-395 — a deterministic test OWNER from one digest: `ask = k`, and `nk` / `seed` derived from it under fixed
    /// domains, so two owners built from different digests share nothing (the wallet links the decider without its
    /// test-support feature, so it spells its own).
    fn test_owner(k: Digest4) -> NoteOwner {
        let dom = |d: u64| usdm_decider::poseidon2_compress::lanes_of(&[0x0395_7E57, d]);
        NoteOwner {
            ask: k,
            nk: usdm_decider::whir_rec_block::poseidon_pair(k, dom(1)),
            seed: usdm_decider::whir_rec_block::poseidon_pair(k, dom(2)),
        }
    }

    /// A filing digest these carrier pins prove and verify under (DB-351). Each pin asks about ONE property (funding,
    /// the copath root, the cross-bind), so D is held fixed; the DB-351 pin below asks about D itself.
    const TD: Digest4 = [0x0351, 1, 2, 3, 4, 5, 6, 7];

    /// ⭐⭐⭐ DB-351 — THE WALLET'S D IS THE NODE'S D, AND A MOVED CLUE LIST IS REFUSED.
    ///
    /// Two parties, the real functions on each side: the wallet builds its clue list through `canonical_clue_bytes`
    /// and its D through `spend_filing_d`, proves the carrier under it, and the NODE's pool-door recompute
    /// (`usdmd_node::node::Node::tx_filing_d`, over the `PqTx` it would pool) reaches the same D, under which the
    /// node's own verify entry accepts the carrier. Then the relay's three moves: a STRIPPED list, a REWRITTEN clue and
    /// a list in another ORDER each yield no D or a different D, and the carrier verifies under none of them.
    /// TWO-PARTY-REVIEWED: wallet side (`canonical_clue_bytes`, `spend_filing_d`, `build_spend_validity_carrier`) and
    /// node side (`Node::tx_filing_d`, `verify_spend_validity_carrier_bytes`) are each the production function.
    #[test]
    fn db351_the_wallets_filing_digest_is_the_nodes_and_a_moved_clue_list_verifies_nowhere() {
        let owner = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10]));
        let (recip_o, change_o) =
            (usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]));
        // The two sealed fronts, known BEFORE proving (the seal formula the prover's out_cm is pinned equal to).
        let (send, change) = (600u64, 300u64);
        let fronts = [note_cm_bytes(send, recip_o), note_cm_bytes(change, change_o)];
        // A clue per output, appended in the order a send builds them (change first), so the list is NOT ascending.
        let rec = |cm: &[u8; 32], clue: &[u8]| {
            let mut r = cm.to_vec();
            r.extend_from_slice(&(clue.len() as u16).to_le_bytes());
            r.extend_from_slice(clue);
            r
        };
        let (hi, lo) = if fronts[0] > fronts[1] { (fronts[0], fronts[1]) } else { (fronts[1], fronts[0]) };
        let unordered = [rec(&hi, b"clue-for-the-higher-cm"), rec(&lo, b"clue-for-the-lower-cm")].concat();
        assert!(spend_filing_d(&fronts, &unordered).is_none(), "⛔ a list out of ascending order is not canonical");
        let clues = canonical_clue_bytes(&unordered).expect("the same records reorder into the one encoding");
        let d = spend_filing_d(&fronts, &clues).expect("a canonical list names a filing");
        let (carrier, cms, nf, lc) =
            build_spend_validity_carrier_cross_bound(1000, owner, send, 100, recip_o, change_o, usdmd_node::spend_frontier::TEST_LC_BLIND, d)
                .expect("funded spend proves under its filing");
        assert_eq!([cm_limbs_to_bytes(cms[0]), cm_limbs_to_bytes(cms[1])], fronts, "the fronts the wallet sealed are the proven outputs");
        // The NODE's side: the tx it would pool, and its own recompute of D.
        let mut output_notes = Vec::new();
        for f in &fronts {
            let mut n = vec![0u8; usdmd_node::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(f);
            output_notes.extend_from_slice(&n);
        }
        let tx = |note_clues: Vec<u8>| usdmd_node::mempool::PqTx {
            clock_ms: 0,
            id: usdmd_node::hash::Hash32::hash(b"db351-wallet-pin"),
            weight: 1,
            blob: carrier.clone(),
            nullifiers: Vec::new(),
            pow_stamp: 0,
            note_clues,
            account_targets: Vec::new(),
            output_notes: output_notes.clone(),
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
        let node_d = usdmd_node::node::Node::tx_filing_d(&tx(clues.clone())).expect("the pool door states D");
        assert_eq!(node_d, d, "⛔ the wallet and the node disagree about D — every honest send would be refused");
        let tag1 = ordinary_claim_tag(usdmd_node::spend_frontier::TEST_LC_BLIND);
        let node_verifies = |dd: Digest4| {
            usdm_decider::verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, lc, dd, tag1, 100)
        };
        assert!(node_verifies(node_d), "CALIBRATION: the node accepts the honest send under its own recompute");
        // The relay's moves.
        let stripped = usdmd_node::node::Node::tx_filing_d(&tx(Vec::new())).expect("an empty list is canonical");
        assert_ne!(stripped, d, "stripping the clues changes D");
        assert!(!node_verifies(stripped), "⛔⛔ a send stripped of its clues verified — it would settle unfiled");
        let rewritten = canonical_clue_bytes(&[rec(&lo, b"clue-for-the-lower-cm"), rec(&hi, b"a-relays-own-clue")].concat())
            .expect("a rewritten list is still well-formed");
        let rewritten_d = usdmd_node::node::Node::tx_filing_d(&tx(rewritten)).expect("canonical");
        assert!(!node_verifies(rewritten_d), "⛔⛔ a send whose clue was rewritten in flight verified");
        assert!(
            usdmd_node::node::Node::tx_filing_d(&tx(unordered)).is_none(),
            "⛔ the node refuses a list in any other order by name (NON_CANONICAL_CLUES), never files a reordering"
        );
    }

    // ⛔ DELETED 2026-09-08 with its subject — `wallet_produces_selfverifying_spend_carrier`.
    //
    // It asserted that the wallet could build a CONSERVATION-ONLY carrier and that the carrier
    // self-verified. Both were true, and neither was worth anything: the statement names no note, no
    // key, no nullifier and no transaction, so "it self-verifies" says only that a public prover ran.
    // A test whose green is compatible with the carrier admitting every transaction on the chain is
    // not coverage, and keeping it after the producer was deleted would have kept the producer.
    //
    // What replaces it is already here: `wallet_produces_full_pqspend_validity_carrier` (below), which
    // builds the carrier real sends use and checks it against the anchor root, both output
    // commitments, the nullifier and the membership cross-bind — and, crucially, asserts that a WRONG
    // cross-bind, a WRONG nullifier and SWAPPED output commitments each REJECT.

    /// The wallet produces the FULL PqSpendAir carrier in-process (conservation + note-opening +
    /// nullifier + the blinded cross-bind) that self-verifies through the SAME shared entry the node runs — and
    /// an unfunded transfer never builds one.
    #[test]
    fn wallet_produces_full_pqspend_validity_carrier() {
        let owner = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[11, 22, 33, 44]));
        let blind = usdmd_node::spend_frontier::TEST_LC_BLIND;
        // §BR-14: value_in 600 + 300 + F, send 600, the protocol fee F → change 300; conserves.
        let (carrier, cms, nf, leaf_commit) =
            build_spend_validity_carrier(900 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, owner, 600, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]), blind, TD)
                .expect("funded full spend must build a carrier");
        assert!(
            validity_carrier_selfverifies(&carrier, cms[0], cms[1], nf, leaf_commit, TD, ordinary_claim_tag(blind)),
            "the wallet's full PqSpendAir carrier MUST self-verify via the shared usdm-decider entry"
        );
        // DB-329 §7f: the claim tag is a statement — the same carrier under another send's claim tag does not verify.
        assert!(
            !validity_carrier_selfverifies(
                &carrier, cms[0], cms[1], nf, leaf_commit, TD,
                ordinary_claim_tag(usdm_decider::poseidon2_compress::lanes_of(&[0x363, 9, 9, 9])),
            ),
            "⛔ a carrier self-verified under a claim tag it never proved"
        );
        // Unfunded: send 2000 from a 1000 note → None.
        assert!(
            build_spend_validity_carrier(900 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, owner, 2000, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]), blind, TD).is_none(),
            "an unfunded full spend must not build a carrier"
        );
    }

    // ⛔ DELETED 2026-09-30 with its subject — `wallet_poseidon_copath_makes_full_validity_recompute_the_frontier_root`
    // and `wallet_consumes_served_frontier_and_spends_against_spend_root` asserted that the spend carrier RECOMPUTES the
    // wallet's Poseidon frontier root from a copath. The carrier walks no path any more (gate D — decorative since §BY,
    // deleted by the census) and names no root; membership is the note-membership carrier's, welded by the blinded
    // `leaf_commit`. The copath helpers (`poseidon_frontier_copath`, `poseidon_frontier_root`) stay for the multi-input
    // class and are pinned by `self_built_witness_copath_equals_the_full_leaf_copath` below.

    /// ⭐ DB-363 (2026-09-30) — THE WALLET'S CROSS-BIND IS THE MEMBERSHIP CARRIER'S VALUE, AND IT IS HIDING. The
    /// validity carrier's `leaf_commit` equals `note_leaf_commitment(leaf, nf, lc_blind)` — the value the wallet's
    /// `NoteMembershipCarrier` commits when built with the SAME blind — so the two proofs name ONE note; and it is NOT
    /// `poseidon_pair(leaf, nf)`, the public one-hash join that let any node name the note a send consumed.
    /// TWO-PARTY-REVIEWED: the two sides are the spend prover (this crate's builder) and the membership carrier's
    /// commitment formula (`usdm_decider::note_membership_air::note_leaf_commitment`, what the node's door compares
    /// the carrier against); the real-pair send is the node-lane journey, not claimed here.
    #[test]
    fn db363_the_wallets_cross_bind_is_the_membership_carriers_blinded_value_and_not_the_public_join() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let owner = test_owner(l(&[7, 8, 9, 10]));
        let (value, send, fee) = (1000u64, 600u64, 100u64);
        let blind = l(&[0x363, 7, 7, 7]);
        let (_carrier, _cms, nf, lc) =
            build_spend_validity_carrier_cross_bound(value, owner, send, fee, l(&[1, 1, 1, 1]), l(&[2, 2, 2, 2]), blind, TD)
                .expect("funded");
        let leaf = note_commitment(value, owner.opening());
        assert_eq!(
            lc,
            usdm_decider::note_membership_air::note_leaf_commitment(leaf, nf, blind),
            "⛔ the wallet's two proofs would name different objects — every send refused (§AO)"
        );
        assert_ne!(
            lc,
            usdm_decider::whir_rec_block::poseidon_pair(leaf, nf),
            "⛔⛔ the cross-bind is the PUBLIC one-hash join of (leaf, nullifier) — every send links to its receive"
        );
        let (_c2, _cms2, nf2, lc2) =
            build_spend_validity_carrier_cross_bound(value, owner, send, fee, l(&[1, 1, 1, 1]), l(&[2, 2, 2, 2]), l(&[0x363, 8, 8, 8]), TD)
                .expect("funded");
        assert_eq!(nf, nf2, "same note, same nullifier");
        assert_ne!(lc, lc2, "a fresh blind gives a fresh commitment — no cross-send join through the commitment");
    }

    /// THE SERVE→CONSUME BRIDGE: the wallet takes the node's `notes_hex` (recipient note_cm = Poseidon commitments),
    /// unpacks it to the leaf set and confirms its OWN served leaf equals its Poseidon note commitment — the leaf the
    /// membership carrier is built for — then builds the cross-bound spend carrier the node verifies.
    #[test]
    fn the_wallet_cross_bound_carrier_is_what_the_node_verifies_and_dropping_the_bind_fails() {
        // ⭐ THE WIRING, not the primitive. The wallet builds a CROSS-BOUND spend carrier and the NODE'S OWN
        // verify entry must accept it under the same commitment — that is the whole point of the weld: the
        // spend proof and the note-membership carrier become one claim about one note.
        //
        // The decisive assertion is the pair. Accepting under the commitment alone would also pass if the
        // commitment were ignored; it is the REJECTION under the zero commitment, and under another note's
        // commitment, that shows the bind is load-bearing on the wire.
        let owner = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[7, 8, 9, 10]));
        let value = 1000u64;
        let mut cms_in: Vec<[u8; 32]> =
            (0..5u64).map(|i| note_cm_bytes(i + 50, usdm_decider::poseidon2_compress::lanes_of(&[i + 1, i + 2, i + 3, i + 4]))).collect();
        cms_in[2] = note_cm_bytes(value, owner.opening());
        let notes_hex: String =
            cms_in.iter().flat_map(|c| c.iter()).map(|b| format!("{:02x}", b)).collect();
        let leaves = parse_served_leaves(&notes_hex).expect("served notes_hex parses");
        assert_eq!(leaves.len(), 5);
        assert_eq!(leaves[2], note_commitment(value, owner.opening()), "our served leaf == our Poseidon note commitment");

        let (carrier, cms, nf, commit) = build_spend_validity_carrier_cross_bound(
            value, owner, 600, 100, usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]), usdmd_node::spend_frontier::TEST_LC_BLIND, TD,
        )
        .expect("funded cross-bound spend must build");

        // The NODE's verify entry — the same function `rpc_http` calls — accepts it under its commitment.
        let t1 = ordinary_claim_tag(usdmd_node::spend_frontier::TEST_LC_BLIND);
        assert!(
            usdm_decider::verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, TD, t1, 100),
            "the node MUST accept the wallet's cross-bound carrier under the commitment the wallet sends"
        );

        // Dropping the commitment on the wire must NOT let it through unbound — otherwise the weld is
        // optional in practice and a spender simply omits the field.
        assert!(
            !usdm_decider::verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, usdmd_node::spend_frontier::empty_leaf(), TD, t1, 100),
            "a cross-bound carrier must NOT verify under the zero (absent-bind) commitment"
        );

        // And under ANOTHER note's commitment it must fail — this is the "valid proof for a note I am not
        // spending" attack the weld exists to stop.
        let other = {
            let mut c = commit;
            c[0] ^= 1;
            c
        };
        assert!(
            !usdm_decider::verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, other, TD, t1, 100),
            "a spend must not verify under a commitment to a note it is not spending"
        );
    }

    /// DB-329 §7e (RED-first adversarial pin for the self-claim carrier): a self-claiming send for slot `d` verifies
    /// under `N_d` (and its row-read `tag1` equals the wallet's [`self_claim_tag`] spelling), and is REFUSED under the
    /// ordinary tag, under `N_{d+1}` and under another seed's `N_d` — so the published row-1 tag is load-bearing, and
    /// two installs of one seed publish the same `N_d` while different seeds never do.
    #[test]
    fn db329_s7e_self_claim_carrier_binds_n_d_and_refuses_every_other_tag() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let owner = test_owner(l(&[7, 8, 9, 10]));
        let other = test_owner(l(&[11, 12, 13, 14]));
        let key = slot_key(&owner.nk);
        assert_eq!(key, slot_key(&owner.nk), "one seed, one slot key on every install");
        assert_ne!(key, slot_key(&other.nk), "two seeds never share a slot key");
        let lc = usdmd_node::spend_frontier::TEST_LC_BLIND;
        let d = 3u64;
        let (carrier, cms, nf, commit, tag1) =
            build_spend_validity_carrier_self_claiming(1000, owner, 600, 100, l(&[1, 1, 1, 1]), l(&[2, 2, 2, 2]), lc, TD, key, d)
                .expect("funded self-claiming spend must build");
        assert_eq!(tag1, self_claim_tag(key, d), "row-read tag1 == the wallet's N_d spelling");
        assert_ne!(tag1, ordinary_claim_tag(lc), "a claim tag is never the ordinary tag");
        let v = |t| usdm_decider::verify_spend_validity_carrier_bytes(&carrier, cms[0], cms[1], nf, commit, TD, t, 100);
        assert!(v(tag1), "the node MUST accept a self-claiming carrier under its N_d");
        assert!(!v(ordinary_claim_tag(lc)), "a self-claim must NOT verify as an ordinary send");
        assert!(!v(self_claim_tag(key, d + 1)), "a claim of slot d must NOT verify as a claim of slot d+1");
        assert!(!v(self_claim_tag(slot_key(&other.nk), d)), "a claim must NOT verify under another seed's N_d");
        assert!(
            build_spend_validity_carrier_self_claiming(500, owner, 600, 100, l(&[1, 1, 1, 1]), l(&[2, 2, 2, 2]), lc, TD, key, d).is_none(),
            "an unfunded self-claim never builds"
        );
    }

    /// PEG-OUT BURN CARRIER (the wallet side of the reserve-drain fix): a Sell/unwrap seals a DESTROYED burn
    /// output worth EXACTLY the atomic burn amount + a change output, builds the BOND-style burn carrier (no path, no
    /// root — membership is the note-membership carrier's, welded by the blinded cross-bind), and it must (a)
    /// self-verify with the bond weld `out0_value == atomic` the node runs,
    /// (b) the node's recomputed `cm0 = usdmd_node::spend_frontier::note_leaf_of(burn_out_payload[..32])` (and cm1) must EQUAL the carrier's
    /// cms[0]/cms[1] — cm-consistency, so the node can't be handed a mismatched destroyed-note / change payload —
    /// and (c) a WRONG weld (claiming a bigger release than burned) must be REJECTED fail-closed. This is the
    /// money-path soundness for peg-out: a burn can only release the peg value the sender actually OWNS + destroys.
    #[test]
    fn wallet_peg_out_burn_carrier_welds_atomic_and_is_cm_consistent() {
        let owner = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[31, 32, 33, 34]));
        let note_amt = 1_000_00000000u64; // own a 1000-USDm note (atomic units)
        let atomic = 250_00000000u64; // burn 250 USDm
        let change_amt = note_amt - atomic - usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC; // §BR-14: the burn pays the network fee
        // Per-output OPENINGS, exactly what seal_note_full returns for out0 (burn) and out1 (change) (DB-395).
        let burn_out_o = usdm_decider::poseidon2_compress::lanes_of(&usdm_decider::poseidon2_compress::lanes_of(&[41, 42, 43, 44]));
        let change_o = usdm_decider::poseidon2_compress::lanes_of(&usdm_decider::poseidon2_compress::lanes_of(&[51, 52, 53, 54]));
        // Build the burn carrier EXACTLY as wallet_sell_usdm does (the protocol fee, §BR-14; out0 welds the burn amount).
        let (carrier, cms, nf, leaf_commit) = build_bond_validity_carrier(
            note_amt, owner, atomic, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, burn_out_o, change_o, usdmd_node::spend_frontier::TEST_LC_BLIND,
        )
        .expect("a funded burn must build a carrier");
        // (a) self-verifies with the atomic weld the node runs.
        assert!(
            bond_carrier_selfverifies(&carrier, cms[0], cms[1], nf, atomic, leaf_commit),
            "the burn carrier MUST self-verify with out0_value == atomic (the SAME bond weld the node runs)"
        );
        // (b) cm-consistency: the node recomputes cm0/cm1 from the sealed payloads' first 32 bytes; both MUST equal
        // the carrier's commitments. seal_note_full writes note_cm_bytes(value, opening) as exactly those 32 bytes.
        assert_eq!(
            usdmd_node::spend_frontier::note_leaf_of(&note_cm_bytes(atomic, burn_out_o)),
            cms[0],
            "node cm0 = leaf(burn_out_payload[..32]) MUST equal the carrier's out0 commitment"
        );
        assert_eq!(
            usdmd_node::spend_frontier::note_leaf_of(&note_cm_bytes(change_amt, change_o)),
            cms[1],
            "node cm1 = leaf(change_note_payload[..32]) MUST equal the carrier's out1 commitment"
        );
        // (c) ADVERSARIAL: claiming a bigger release than the burn (wrong weld) is REJECTED fail-closed.
        assert!(
            !bond_carrier_selfverifies(&carrier, cms[0], cms[1], nf, atomic + 1, leaf_commit),
            "a burn welded to `atomic` MUST NOT verify against a larger claimed release (no over-redeem)"
        );
    }

    /// FULLY-PRIVATE MULTI-INPUT wallet builder: TWO of the wallet's OWN notes (600 + 400, neither alone covers a
    /// 900 send) live in ONE sparse depth-32 Poseidon frontier; the wallet builds each note's real copath + the
    /// SINGLE multi-input carrier (900 recipient + 90 change + 10 fee) → it recomputes the SAME served root and
    /// self-verifies against root + the 2 output cms + the 2 nullifiers. Every amount stays private (in-circuit);
    /// the recipient receives ONE note. This is the sound replacement for the N-separate-tx sweep.
    #[test]
    fn wallet_builds_fully_private_multi_input_carrier_over_depth32_copaths() {
        let owner0 = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[11, 12, 13, 14]));
        let owner1 = test_owner(usdm_decider::poseidon2_compress::lanes_of(&[21, 22, 23, 24]));
        let (v0, v1) = (600u64 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, 400u64); // §BR-14: the inputs fund the protocol fee
        // Sparse production-depth-32 frontier: 6 notes; OUR two spendable notes at indices 2 and 4.
        let mut leaves: Vec<Digest4> = (0..6u64).map(|i| usdm_decider::poseidon2_compress::lanes_of(&[i + 1, i + 2, i + 3, i + 4])).collect();
        leaves[2] = note_commitment(v0, owner0.opening());
        leaves[4] = note_commitment(v1, owner1.opening());
        let root = poseidon_frontier_root(&leaves);
        let (sib0, dir0) = poseidon_frontier_copath(&leaves, 2).expect("production-depth copath 0");
        let (sib1, dir1) = poseidon_frontier_copath(&leaves, 4).expect("production-depth copath 1");
        let inputs = vec![
            SpendInputNote { value_in: v0, owner: owner0, siblings: sib0.clone(), dirs: dir0.clone() },
            SpendInputNote { value_in: v1, owner: owner1, siblings: sib1.clone(), dirs: dir1.clone() },
        ];
        let (carrier, carrier_root, cms, nfs) =
            build_multi_spend_validity_carrier(inputs, 900, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]), TD)
                .expect("funded fully-private multi-input spend must build");
        assert_eq!(nfs.len(), 2, "one nullifier per input");
        assert_eq!(carrier_root, root, "the multi-input circuit recomputes the SAME served frontier root");
        assert!(
            multi_validity_carrier_selfverifies(&carrier, root, cms[0], cms[1], &nfs, NOTE_TREE_DEPTH, TD),
            "the fully-private multi-input carrier over the real depth-32 copaths MUST self-verify"
        );
        // Unfunded across all inputs (Σ = 1000, send 1200 + fee) → no shortfall fabrication.
        let inputs2 = vec![
            SpendInputNote { value_in: v0, owner: owner0, siblings: sib0, dirs: dir0 },
            SpendInputNote { value_in: v1, owner: owner1, siblings: sib1, dirs: dir1 },
        ];
        assert!(
            build_multi_spend_validity_carrier(inputs2, 1200, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, usdm_decider::poseidon2_compress::lanes_of(&[1, 1, 1, 1]), usdm_decider::poseidon2_compress::lanes_of(&[2, 2, 2, 2]), TD).is_none(),
            "a multi-input spend exceeding the summed inputs MUST NOT build (no shortfall fabrication)"
        );
    }

    /// BRICK 4 PROOF (the wallet↔node membership-witness bridge): a wallet's SELF-BUILT `IncrementalWitness` —
    /// captured from the served O(DEPTH) peaks + the streamed block leaves, NEVER the O(n) leaf set the no-store
    /// node cannot serve — produces the BYTE-IDENTICAL `(siblings, dirs)` copath the working spend carrier already
    /// consumes, and recomputes the exact live `spend_frontier_root`. So the fix for "owned note not yet in the
    /// served frontier" is drop-in: the spend swaps `parse_served_leaves` + `position` + `poseidon_frontier_copath`
    /// for `witness.authpath()`, and the SAME WHIR carrier verifies against live consensus — cross-device.
    #[test]
    fn self_built_witness_copath_equals_the_full_leaf_copath() {
        use usdmd_node::spend_frontier::{IncrementalWitness, PoseidonSpendFrontier};
        let n = 300u64;
        let leaves: Vec<Digest4> = (0..n).map(|i| note_commitment(1000 + i, usdm_decider::poseidon2_compress::lanes_of(&[i + 1, 2, 3, 4]))).collect();
        let mut f = PoseidonSpendFrontier::new();
        for l in &leaves {
            f.append(*l);
        }
        // Precondition: the wallet's sparse root == the node's MMR root (the two Poseidon frontiers agree — else
        // NO wallet copath could ever verify against the node's spend_frontier_root).
        assert_eq!(poseidon_frontier_root(&leaves), f.root(), "wallet sparse root == node MMR root");
        for &index in &[0u64, 1, 5, 63, 127, 128, 255, 256, 257, 299] {
            // WALLET path: capture the left siblings from the peaks at catch, then observe every later block leaf.
            let mut at_catch = PoseidonSpendFrontier::new();
            for l in &leaves[..index as usize] {
                at_catch.append(*l);
            }
            let mut w = IncrementalWitness::new(index, leaves[index as usize]);
            w.capture_left_from_peaks(&at_catch);
            for j in (index + 1)..n {
                w.observe(j, leaves[j as usize]);
            }
            let (sw, dw) = w.authpath();
            let (sc, dc) = poseidon_frontier_copath(&leaves, index as usize).expect("full-leaf copath");
            assert_eq!(dw, dc, "dirs identical @ index={index}");
            assert_eq!(sw, sc, "self-built copath == full-leaf copath @ index={index}");
            assert_eq!(w.root(), f.root(), "witness recomputes the live frontier root @ index={index}");
        }
    }

    /// DB-322 — the welded carrier states the whole bond: every weld that matters refuses its tamper. It has no path and
    /// no root at all since 2026-09-30 (gate D deleted), so there is no depth or root a wallet and a door could spell
    /// differently — the census below holds that lib.rs spells NO carrier depth and NO filler any more.
    #[test]
    fn db322_a_pathless_welded_carrier_states_the_whole_bond() {
        let l = usdm_decider::poseidon2_compress::lanes_of;
        let (owner, bond_o, change_o) = (test_owner(l(&[3, 1, 4, 1])), l(&[5, 9, 2, 6]), l(&[5, 3, 5, 8]));
        let (value_in, bond, fee) = (1_000u64 + usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, 300u64, usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC); // §BR-14: the bond pays the protocol fee
        let blind = usdmd_node::spend_frontier::TEST_LC_BLIND;
        let (c, cms, nf, lc) =
            build_bond_validity_carrier_cross_bound(value_in, owner, bond, fee, bond_o, change_o, blind)
                .expect("a funded bond builds a welded carrier");
        let v = |o0, o1, nf, w, lc| bond_carrier_cross_bound_selfverifies(&c, o0, o1, nf, w, lc);
        assert!(v(cms[0], cms[1], nf, bond, lc), "the honest welded carrier verifies");
        assert!(!v(cms[0], cms[1], nf, bond + 1, lc), "TAMPER: a weight the locked note does not hold");
        assert!(!v(cms[0], cms[1], nf, bond - 1, lc), "TAMPER: a weight below the locked value");
        assert!(!v(cms[1], cms[0], nf, bond, lc), "TAMPER: swapped output commitments");
        assert!(!v(cms[0], cms[1], l(&[7, 7, 7, 7]), bond, lc), "TAMPER: a nullifier of another note");
        assert!(!v(cms[0], cms[1], nf, bond, l(&[8, 8, 8, 8])), "TAMPER: a cross-bind naming another note");
        assert!(
            build_bond_validity_carrier_cross_bound(value_in, owner, value_in + 1, fee, bond_o, change_o, blind).is_none(),
            "an unfunded bond never builds"
        );
        // The wallet spells NO carrier depth and pads NO filler path any more: the class of 2026-09-18 (this file said 64
        // where the aggregate said 0, and the burn door said 128) has nothing left to disagree about. The stake claim
        // stays refused before anything is built (DB-327).
        let lib = include_str!("lib.rs");
        for word in ["filler_depth", "BOND_CARRIER_DEPTH", "BURN_CARRIER_DEPTH", "SPEND_CARRIER_DEPTH"] {
            assert!(!lib.contains(word), "lib.rs spells `{word}` again — a carrier depth or a filler path has come back");
        }
        assert!(lib.contains("Err(CLAIM_PAUSED.to_string())"), "DB-327: the stake claim is refused, not built");
    }

    // ⛔ DELETED 2026-09-30 with its subject — `db322_calibration_the_same_welded_statement_at_depth_0_and_64` measured the
    // same welded statement at 0 and 64 filler levels (the layout bind, and the bytes the dead levels cost). The levels
    // are gone at source: the carrier has ONE constant layout and no depth parameter, so there is nothing to calibrate.

    /// ⭐ THE WALLET READS A STAKED NOTE'S SPENT STATUS UNDER THE NULLIFIER ITS SPEND RECORDS. The stake gate proves
    /// `nf = compress(nk, asset_note_cm(v, stake_tag(e0), o))` for a staked input (DB-395); the wallet's presence mask, own-log
    /// and pending-change pairing ask under [`note_nullifier_asset`] at the note's own tag. TAMPER (the calibration):
    /// the USDm-tag spelling every owned-note site used before names a DIFFERENT nullifier, which no spend records —
    /// a staked (or wrapped) note spelled that way could never read spent.
    /// TWO-PARTY-REVIEWED: the two sides are the wallet's derivation and the stake GATE's own witness fill (the
    /// decider's `stake_row`, what every node verifies), and the assertion is that they agree; the two-process side
    /// (a real wallet staking through one real node, the other observing) is the real-node stake journey.
    #[test]
    fn a_staked_notes_nullifier_is_the_one_its_stake_spend_records() {
        use usdm_decider::poseidon2_compress::lanes_of;
        use usdm_decider::whir_rec_block as wr;
        let (v, e0) = (1_000u64, 20_000u64);
        let owner = test_owner(lanes_of(&[0x51, 2, 3, 4]));
        let w = wr::StakeWitness {
            value_in: v,
            owner,
            in_staked: true,
            e0,
            lc_blind: lanes_of(&[9, 9, 9, 9]),
            out0_value: v,
            out0_opening: lanes_of(&[5, 5, 5, 5]),
            out0_staked: true,
            out1_opening: lanes_of(&[6, 6, 6, 6]),
            reward_blind: lanes_of(&[7, 7, 7, 7]),
        };
        let (_carrier, o) = wr::prove_stake_carrier_bytes(&w, e0, 500).expect("a claim of a staked note proves");
        let recorded = usdmd_node::spend_frontier::leaf_to_cm_bytes(o.nullifier);
        assert_eq!(
            note_nullifier_asset(v, &owner, wr::stake_tag(e0)),
            recorded,
            "⛔ the wallet's nullifier for a staked note is not the one its stake spend records"
        );
        assert_ne!(note_nullifier(v, &owner), recorded, "CALIBRATION: the USDm-tag spelling names another nullifier");
        assert_eq!(
            note_cm_asset_bytes(v, wr::stake_tag(e0), owner.opening()),
            usdmd_node::spend_frontier::leaf_to_cm_bytes(wr::stake_input_leaf(&w)),
            "the wallet's commitment for a staked note is the leaf the stake gate opens"
        );
    }
}
