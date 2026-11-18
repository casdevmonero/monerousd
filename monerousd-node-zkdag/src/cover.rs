// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! Constant per-block COVER SHAPE — the privacy invariant that makes it impossible to observe whether a
//! real transaction occurred in any block. Ported (in the PQ/DAG shape) from the old clean tree's design:
//! `v36_shape` + `dummy_tx_filler` + `PQ_COVER_NOTES_PER_BLOCK`.
//!
//! Two layers, both FIXED BY CONSTRUCTION (privacy is never a governance choice — like the mix cell size in
//! [`crate::net`], these are hard constants, not tunable state that could be weakened):
//!   • Every block is padded to a CONSTANT tx count ([`BLOCK_FIXED_TX_COUNT`]): the producer fills the
//!     template with byte-indistinguishable value-0 COVER TXS until the count is reached, so `tx_ids.len()`
//!     and `tx_merkle_root` never reveal how many real txs the block carried.
//!   • Every block records a CONSTANT count of SERVED NOTES ([`BLOCK_FIXED_NOTE_COUNT`] = 256): the producer
//!     takes the block's real output notes and appends value-0 cover notes to fill to the fixed count
//!     ([`assemble_fixed_note_payload_det`]). ⛔ NO SHUFFLE — this doc claimed one for months and it was
//!     never safe to add: a note's POSITION in the payload IS its offset from the record's first leaf, an
//!     invariant `node::tests::a_notes_global_leaf_index_is_recoverable_from_its_record...` asserts
//!     directly. Permuting would mis-index every later leaf and make the notes unspendable. Positional
//!     hiding comes from the cover being byte-indistinguishable, not from moving reals around. The
//!     served note-tree therefore grows by the SAME constant 256 every block (every block on the chain is
//!     shaped identically) — an observer watching it can NEVER tell whether, or how many, real transactions
//!     occurred, and the confidential anonymity set grows identically block-to-block. A per-block note count
//!     that VARIES with real activity (e.g. "N cover notes PLUS the real outputs") is a hard Pillar-1 leak.
//!
//! A cover note / cover tx is byte-indistinguishable from a real one to any observer (a REAL ML-KEM
//! ciphertext to a throwaway key + high-entropy commitment/mask fields), carries ZERO value, and is
//! spendable by nobody (the throwaway key is discarded) — so it is inert: it moves no value, cannot
//! double-spend, and the verifier NEVER requires it (NO-HALTS: a block carrying fewer cover items is still
//! valid; consensus only CAPS the count, it never demands cover). This is producer-side privacy.

use crate::hash::Hash32;
use crate::mempool::PqTx;
use crate::pqkem;

/// On-chain PQ note size: note_cm(32) ‖ ML-KEM ct(1088) ‖ enc_amount(32) ‖ view_tag(1).
pub const PQ_NOTE_BYTES: usize = 1153;
/// The ML-KEM-768 ciphertext region inside a note.
pub const CT_OFF: usize = 32;
pub const CT_LEN: usize = 1088;

/// Fixed transactions-per-block target (ported from `BLOCK_FIXED_TX_COUNT_V36`). An honest producer pads
/// every block to EXACTLY this many tx slots (real + cover), so the tx count leaks no real activity.
/// Consensus CAPS at this value (rejects more) but never REQUIRES it (no-halts). Fixed by construction.
/// 256 (user 2026-07-15: "cover traffic 256 instead of 128 for the whole chain … more coverage = more
/// privacy … still no growth"): the WIDER constant cover shape wears more anonymity on EVERY block (real or
/// idle) while staying no-growth — the cover is regenerated at serve, never stored, so a larger constant is a
/// bigger constant per-block DELTA, not an accumulating axis (node state stays O(1)).
pub const BLOCK_FIXED_TX_COUNT: usize = 256;

/// The FIXED number of SERVED NOTES every block records (real output notes + value-0 cover fill; NO shuffle,
/// because a note's position IS its leaf offset). Equal to [`BLOCK_FIXED_TX_COUNT`], so a block can always fill its served-note shape from its own tx slots +
/// cover, and every block on the chain is byte-indistinguishable in note-tree shape. Fixed by construction
/// (never governance-tunable): shrinking it below the constant, or letting the per-block served-note count VARY
/// with real activity, is a hard Pillar-1 (privacy) violation — an observer could then count real outputs per block.
pub const BLOCK_FIXED_NOTE_COUNT: usize = BLOCK_FIXED_TX_COUNT;

/// 32 high-entropy bytes from a fresh ML-KEM shared secret + a domain tag — for the note fields (commitment,
/// amount-mask) that must look uniformly random to an observer. A blake3 digest is computationally
/// indistinguishable from random.
fn rand_field(ss: &[u8], tag: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(ss.len() + tag.len());
    buf.extend_from_slice(ss);
    buf.extend_from_slice(tag);
    *Hash32::hash(&buf).as_bytes()
}

/// Produce ONE byte-indistinguishable value-0 cover note (1153 bytes). Its layout matches a real note
/// exactly: a random-looking commitment, a REAL ML-KEM-768 ciphertext to a throwaway key (so even a
/// structural analyzer cannot separate it from a real note's ct without the secret key), and random-looking
/// encrypted-amount + view-tag fields. Cheap (one KEM encapsulation), inert (throwaway key discarded ⇒
/// unspendable, value 0). Returns `None` only if the KEM primitive fails — never a panic.
pub fn cover_note() -> Option<[u8; PQ_NOTE_BYTES]> {
    let (pk, _sk) = pqkem::keypair(); // throwaway recipient — discarded, so nobody can ever spend this note
    let (ss, ct) = pqkem::encapsulate(&pk)?; // ss = fresh randomness; ct = a REAL 1088-byte ML-KEM ciphertext
    if ct.len() != CT_LEN {
        return None;
    }
    let note_cm = rand_field(&ss, b"MUSD-cover-cm");
    let enc = rand_field(&ss, b"MUSD-cover-enc");
    let vt = rand_field(&ss, b"MUSD-cover-vt")[0];
    let mut out = [0u8; PQ_NOTE_BYTES];
    out[0..CT_OFF].copy_from_slice(&note_cm);
    out[CT_OFF..CT_OFF + CT_LEN].copy_from_slice(&ct);
    out[1120..1152].copy_from_slice(&enc);
    out[1152] = vt;
    Some(out)
}

/// ONE fresh HIGH-ENTROPY value-0 note used to SEED an otherwise-empty block, so the per-block cover secret is
/// NEVER derivable from public data even when the block carried ZERO real notes. The per-block cover secret folds
/// the block's confidential reals ([`assemble_fixed_note_payload_det`]); if `reals` were empty the secret would
/// degrade to a PUBLIC `blake3(seq)` and an observer could recompute the whole 256-cover fill and know the block
/// was empty. Prepending ONE of these makes `reals` non-empty, so the secret is always unpredictable AND the block
/// is a private 1-note+255-cover shape byte-indistinguishable from a real 1-note block (an observer cannot even
/// tell it was "empty"). Chain-wide cover (user 2026-07-15: "cover traffic 256 instead of 128 for the whole
/// chain"). Identical in shape + privacy to [`cover_note`] (a real ML-KEM ct to a throwaway
/// key, value 0, unspendable), but returned UNCONDITIONALLY — a rare KEM hiccup falls back to fresh keypair bytes
/// (still high-entropy, secret key dropped) rather than `None`, because an empty block MUST still carry confidential
/// entropy. It is stored like a real note (so record == serve), never re-derivable by an observer.
///
/// ⭐ §RF-3 spec §14 (2026-10-24): its leaf cm is [`seed_note_cm`] of its own body — a blake3 value, never a Poseidon
/// note commitment, so no spend circuit opens it (value 0, unspendable by construction) and the §BA door can admit it
/// by that one equation (`Node::graft_admitted_notes`, [`is_seed_note`]) without any object justifying it.
/// ⭐ THE SEED NOTE A KEY HOLDER CAN REBUILD (lane funds, 2026-10-28). The quiet block's seed note used to be drawn from
/// the OS RNG, so a peer fed the block over the wire could never rebuild its record (`Node::rehydrate_block_body` derived
/// the pool's notes and the credit set's whole notes and stopped short by exactly this one note), waited on the record
/// lane for a body no object justifies, and — in a pair with no lane — never folded the block: the four
/// `db224_a_price_mark_crosses…` / `db240…` / `db274_p2…` reds (NEVER-PASSED since 2026-10-25, the day the seed landed).
/// The body is now the XOF of the block's own cover key σ under this domain: a holder of σ (the producer; every peer,
/// which receives σ beside the body, §20.2/§22) rebuilds the whole quiet block from the wire alone; a non-holder sees a
/// pseudorandom note it cannot regenerate — exactly the property the OS draw had, since σ is itself fresh per block and
/// never on a wallet route. The front stays a cover cell (`seal_seed_note_front`). A seeded test world seeds σ
/// (`fresh_cover_key`), so a replayable simulation replays its seed notes too. cons: none — one XOF per quiet block,
/// no bytes change shape; a quiet block's record no longer needs the record lane at all (fewer asks, not more).
#[must_use]
pub fn seed_note_for_key(key: &CoverKey) -> [u8; PQ_NOTE_BYTES] {
    let mut h = blake3::Hasher::new_keyed(key);
    h.update(b"MUSD/seed-note/v1");
    let mut out = [0u8; PQ_NOTE_BYTES];
    h.finalize_xof().fill(&mut out);
    out[..32].fill(0); // UNSEALED: the front is sealed by `seal_seed_note_front` once the block's bodies are fixed (§18.1)
    out
}

/// A test fixture's seed note from the OS RNG (production draws [`seed_note_for_key`]).
#[cfg(test)]
pub fn fresh_seed_note() -> [u8; PQ_NOTE_BYTES] {
    let mut n = fresh_seed_note_unsealed();
    n[..32].fill(0); // UNSEALED: the front is sealed by `seal_seed_note_front` once the block's bodies are fixed (§18.1)
    n
}

/// ⭐ padding spec §18.1 — THE SEED NOTE'S FRONT IS A LEDGER COVER CELL. The quiet block's seed note (§14/§17) used to
/// wear a blake3 front of its own (`seed_note_cm`), so the ledger filed it as a JUSTIFIED note and its public `j` bit
/// read "quiet block" (MEASURED Σj quiet 1 · busy 0, `rf3_the_published_ledgers_flags_do_not_count_the_blocks_real_spends`).
/// `header_seed` zeroes every front (§13(c)), so the front may be `cover_note_native(HEADER_SEED, 257 − k)` — the cover
/// slot right after the `1..=256−k` padding `header_note_cms_of_bodies` lays — with no circularity: the header's cms are
/// then `reals′ ‖ cover(1..=257−k)`, the ledger lays `257 − k` cover cells at `1..=257−k`, and no `j` is set. `k` = the
/// block's real bodies INCLUDING the seed. Still value 0 and unspendable: no opening commits to a cover cell.
#[must_use]
pub fn seed_front_slot(k_bodies: usize) -> u64 {
    (BLOCK_FIXED_NOTE_COUNT + 1).saturating_sub(k_bodies) as u64
}

/// The front a seed note wears among `all_bodies` (every real unit of the block, the seed included, fronts ignored).
#[must_use]
pub fn seed_note_front(all_bodies: &[u8], key: &CoverKey) -> [u8; 32] {
    let k = all_bodies.len() / PQ_NOTE_BYTES;
    let seed = header_seed(all_bodies, key);
    crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::slot_ledger::cover_note_native(seed, seed_front_slot(k)))
}

/// Seal the LAST unit of `all_bodies` as the block's seed note (its front := [`seed_note_front`]). The producer calls it
/// once, after it appended the fresh seed and fixed every other body (`produce.rs`).
pub fn seal_seed_note_front(all_bodies: &mut [u8], key: &CoverKey) {
    let n = all_bodies.len();
    if n < PQ_NOTE_BYTES || n % PQ_NOTE_BYTES != 0 {
        return;
    }
    let front = seed_note_front(all_bodies, key);
    all_bodies[n - PQ_NOTE_BYTES..n - PQ_NOTE_BYTES + 32].copy_from_slice(&front);
}

/// True iff `note` is one whole unit of `all_bodies` wearing the block's seed front — the §BA door's one seed rule
/// (§18.1): judged against the WHOLE body, so a body tampered anywhere, or a second seed, moves the front and refuses.
#[must_use]
pub fn is_seed_note_in(note: &[u8], all_bodies: &[u8], key: &CoverKey) -> bool {
    note.len() == PQ_NOTE_BYTES && note[..32] == seed_note_front(all_bodies, key)
}

/// ⛔ TEST BUILDS ONLY — SEEDED SEED-NOTE ENTROPY FOR A REPLAYABLE SIMULATION (2026-10-27). A fresh seed note draws
/// ML-KEM randomness, so two runs of one (parties, seed, ops) produce different unspent roots and padded tags, and a
/// replay-determinism oracle (H-3, the fuzz catalogue) cannot tell a real order/entropy dependence from this one by
/// design. A simulator sets its thread's seed once (`seed_fresh_notes_for_test`); every fresh seed note on that thread
/// is then a blake3 XOF of (seed, counter) — still unique per call, still unspendable (no key), never a production
/// path (the hook does not exist outside test builds and is `None` until a simulator sets it).
#[cfg(test)]
thread_local! {
    static SEEDED_FRESH_NOTES: std::cell::Cell<Option<(u64, u64)>> = const { std::cell::Cell::new(None) };
}

/// Arm this thread's fresh seed notes on `seed` (see `SEEDED_FRESH_NOTES`); `None` restores the ML-KEM draw.
#[cfg(test)]
pub fn seed_fresh_notes_for_test(seed: Option<u64>) {
    SEEDED_FRESH_NOTES.with(|c| c.set(seed.map(|s| (s, 0))));
}

#[cfg(test)]
fn seeded_fresh_note_unsealed() -> Option<[u8; PQ_NOTE_BYTES]> {
    SEEDED_FRESH_NOTES.with(|c| {
        let (seed, ctr) = c.get()?;
        c.set(Some((seed, ctr.wrapping_add(1))));
        let mut h = blake3::Hasher::new_derive_key("MUSD/test/seeded-fresh-seed-note/v1");
        h.update(&seed.to_le_bytes());
        h.update(&ctr.to_le_bytes());
        let mut out = [0u8; PQ_NOTE_BYTES];
        h.finalize_xof().fill(&mut out);
        Some(out)
    })
}

#[cfg(test)]
fn fresh_seed_note_unsealed() -> [u8; PQ_NOTE_BYTES] {
    #[cfg(test)]
    if let Some(n) = seeded_fresh_note_unsealed() {
        return n;
    }
    if let Some(n) = cover_note() {
        return n;
    }
    // KEM hiccup fallback (never a halt): fill from a FRESH keypair's public-key bytes. Each keypair() draws fresh
    // CSPRNG, so this is high-entropy and unique per call; the secret key is dropped ⇒ the note stays unspendable.
    let (pk, _sk) = pqkem::keypair();
    let mut out = [0u8; PQ_NOTE_BYTES];
    let mut off = 0;
    let mut ctr: u64 = 0;
    while off < PQ_NOTE_BYTES {
        let mut buf = Vec::with_capacity(pk.len() + 32);
        buf.extend_from_slice(b"MUSD-seed-note-fallback-v2");
        buf.extend_from_slice(&pk);
        buf.extend_from_slice(&ctr.to_le_bytes());
        let h = Hash32::hash(&buf);
        let b = h.as_bytes();
        let take = core::cmp::min(32, PQ_NOTE_BYTES - off);
        out[off..off + take].copy_from_slice(&b[..take]);
        off += take;
        ctr = ctr.wrapping_add(1);
    }
    out
}

/// The DETERMINISTIC idle-block seed note — the DA-layer twin of [`fresh_seed_note`]. An idle block (a record
/// with no explicit real notes) seeds its private cover fill from ONE note derived as a keyed PRF of the node's
/// persisted per-chain DA secret and the block's served index, so the block's full constant-256 shape REGENERATES
/// byte-identically forever from O(1) state — record == serve at ANY height, across restarts, with NOTHING stored
/// per idle block (the no-growth pillar) and NO window a note could age out of. The secret never leaves the node,
/// so the cover fill stays SECRET-SEEDED (unpredictable to any observer — never a recomputable index function);
/// the note is uniform high-entropy bytes (byte-indistinguishable from a real note) with no spend secret (unspendable).
/// The ONE seed note of a record whose block carried no real notes — a pure function of the record's
/// address (`seq`), which every node derives from the block id alone. This is why an idle record is
/// never persisted and never fetched: any node that holds its coordinates regenerates it byte-identically
/// on demand (`Node::da_record_notes` → `regenerate_idle_record`), and a receiver still verifies served
/// bytes against the roots IT holds. BYTES ARE FROZEN — every idle record on the chain folds these
/// leaves (da_seed_regen_tests, idle_record_regeneration_tests, the canonical-ordinal pins).
pub fn public_idle_seed_note(seq: u64) -> [u8; PQ_NOTE_BYTES] {
    let mut out = [0u8; PQ_NOTE_BYTES];
    let mut off = 0usize;
    let mut ctr = 0u64;
    while off < PQ_NOTE_BYTES {
        let h = idle_seed_block(seq, ctr);
        let take = core::cmp::min(32, PQ_NOTE_BYTES - off);
        out[off..off + take].copy_from_slice(&h[..take]);
        off += take;
        ctr = ctr.saturating_add(1);
    }
    out
}

/// The FIRST 32 bytes of [`public_idle_seed_note`]`(seq)` — one hash instead of thirty-seven. A note whose leading
/// block differs from this is not the idle seed, so a reader asking "is this the idle seed?" builds the whole seed only
/// for a note that already matches its head (`Node::record_carries_real_notes`). MEASURED (`sample` of the simulator's
/// fast journey, scratchpad/night/link29-sample.txt): 1,317 of the relay drain's 1,618 parked-page samples were the
/// full seed rebuilt per record by the retention rule. cons: none — the same bytes, fewer of them computed.
pub fn public_idle_seed_head(seq: u64) -> [u8; 32] {
    idle_seed_block(seq, 0)
}

/// One 32-byte block of the idle seed: `blake3("MUSD-da-seed-note-v2-public" ‖ seq (le) ‖ ctr (le))` — the frozen
/// preimage, laid in a stack buffer.
fn idle_seed_block(seq: u64, ctr: u64) -> [u8; 32] {
    const TAG: &[u8] = b"MUSD-da-seed-note-v2-public";
    let mut blk = [0u8; TAG.len() + 16];
    blk[..TAG.len()].copy_from_slice(TAG);
    blk[TAG.len()..TAG.len() + 8].copy_from_slice(&seq.to_le_bytes());
    blk[TAG.len() + 8..].copy_from_slice(&ctr.to_le_bytes());
    *Hash32::hash(&blk).as_bytes()
}

/// ⭐ §20.2 — THE RECORD'S COVER KEY: 32 B the producer draws fresh for its block (never derivable from anything public or
/// from the reals), carried WITH the reals on every node route (the record lane, the sidecar page, the checkpoint row) and
/// never on a wallet route. The record's cover bodies are `cover_note_det(record_cover_secret(seq, key), slot)` and its
/// header seed is `header_seed(reals, key)`, so a fetcher holding the 256 served units and no key can test no unit and no
/// subset (spec §20.2, refuted on the bus 2026-10-28: two-node diff, subset search, the fronts, a lying lane, a degenerate
/// producer). A holder regenerates record == serve from `(reals, key)` with nothing else stored.
pub type CoverKey = [u8; 32];

/// TEST — the one cover key hand-made test records are written and read under (a fixture is its own producer).
#[cfg(test)]
pub const TEST_COVER_KEY: CoverKey = [0x5a; 32];

/// A fresh cover key for a block this node produces: high-entropy, from a fresh ML-KEM keypair's public key through a
/// derive-key hash (the same entropy source the fresh seed note uses). In a seeded test simulation it follows the
/// simulation's seed like every fresh seed note does (`seed_fresh_notes_for_test`), so a replay is byte-exact.
#[must_use]
pub fn fresh_cover_key() -> CoverKey {
    #[cfg(test)]
    if let Some(k) = fixed_cover_key_for_test() {
        return k;
    }
    #[cfg(test)]
    if let Some(n) = seeded_fresh_note_unsealed() {
        return *blake3::Hasher::new_derive_key("MUSD/cover-key/seeded-test/v1").update(&n).finalize().as_bytes();
    }
    let (pk, _sk) = pqkem::keypair();
    *blake3::Hasher::new_derive_key("MUSD/cover-key/v1").update(&pk).finalize().as_bytes()
}

/// ⛔ TEST BUILDS ONLY — PROCESS-WIDE SEEDED COVER KEYS. A fixture that builds two nodes from one recipe and compares what
/// they put on the wire (DB-350's ask-privacy pins) needs both to draw the same keys, and a node's produce may run on a
/// runtime thread the thread-local seed above never reaches. Set once per fixture (`seed_cover_keys_for_test`); every
/// fresh key is then a blake3 XOF of (seed, counter) — unique per draw, never a production path.
#[cfg(test)]
static FIXED_COVER_KEYS: std::sync::Mutex<Option<(u64, u64)>> = std::sync::Mutex::new(None);

#[cfg(test)]
pub fn seed_cover_keys_for_test(seed: Option<u64>) {
    *FIXED_COVER_KEYS.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = seed.map(|s| (s, 0));
}

#[cfg(test)]
fn fixed_cover_key_for_test() -> Option<CoverKey> {
    let mut g = FIXED_COVER_KEYS.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let (seed, ctr) = (*g)?;
    *g = Some((seed, ctr.wrapping_add(1)));
    let mut h = blake3::Hasher::new_derive_key("MUSD/test/seeded-cover-key/v1");
    h.update(&seed.to_le_bytes());
    h.update(&ctr.to_le_bytes());
    Some(*h.finalize().as_bytes())
}

/// The ONE public cover key: an IDLE record regenerated from its address alone (`Node::regenerate_idle_record`, the
/// public idle seed note) has no producer-drawn key and no secret to keep — such a record is already publicly idle (its one
/// unit is `public_idle_seed_note(addr)`), so its key is this public function. Never used for a record with a real note.
#[must_use]
pub fn idle_cover_key(addr: u64) -> CoverKey {
    *blake3::Hasher::new_derive_key("MUSD/idle-cover-key/v1").update(&addr.to_le_bytes()).finalize().as_bytes()
}

/// The per-record COVER SECRET every cover body is derived from: `(seq, cover key)`, never the reals (§20.2 — a secret
/// derived from the reals was recomputable by anyone who could guess them, `C(256, k)` tries).
#[must_use]
pub fn record_cover_secret(seq: u64, key: &CoverKey) -> [u8; 32] {
    let mut buf = Vec::with_capacity(24 + 8 + 32);
    buf.extend_from_slice(b"MUSD-cover-secret-v3");
    buf.extend_from_slice(&seq.to_le_bytes());
    buf.extend_from_slice(key);
    *Hash32::hash(&buf).as_bytes()
}

/// TEST — an arbitrary per-block secret for the scan tests (`note_scan`), which only need SOME secret a decoy is derived
/// from; production derives every cover from [`record_cover_secret`] and a record's own key, never from its reals.
#[cfg(test)]
pub fn block_cover_secret(real_notes: &[u8], seq: u64) -> [u8; 32] {
    record_cover_secret(seq, blake3::hash(real_notes).as_bytes())
}

/// ⭐ §RF-3 spec §13 (2026-10-24) — the block's HEADER_SEED: the Poseidon map of a blake3 secret over `seq` and the
/// record's real note BODIES (every unit's 32 B cm front read as zero). Every holder of the reals (every node) regenerates
/// it with nothing stored (R1c); a non-holder (leaf cms only) cannot, because the bodies are the secret input, and an idle
/// block's reals are its producer's fresh seed note (spec §14). It never reads a front, so the header's cover cms may BE
/// ledger cover cells `slot_ledger::cover_note_native(seed, slot)` without circularity.
/// ⛔ §15: NO record address. The address is `record_key(block id)` and the id binds `nullifier_tags_root`, so a seed
/// over the address could not seed the decoy TAGS it is meant to seed (tags → id → address → seed → tags). Per-block
/// uniqueness comes from the reals: every honest block carries a producer-fresh body (its reward note or seed note).
/// cons: one blake3 pass over the reals per record (the same bytes [`block_cover_secret`] already hashes).
#[must_use]
pub fn header_seed(real_notes: &[u8], key: &CoverKey) -> crate::spend_frontier::Digest4 {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD-header-seed-v3");
    h.update(key); // §20.2 item 8: the cover FRONTS follow this seed, so a non-holder can test no subset of the reals
    for u in real_notes.chunks(PQ_NOTE_BYTES) {
        let front = u.len().min(32);
        h.update(&[0u8; 32][..front]);
        h.update(&u[front..]);
    }
    usdm_decider::poseidon2_compress::hash32_to_digest(h.finalize().as_bytes())
}

/// The per-block NULLIFIER-cover secret — the SINGLE source of truth that ALL THREE padded-transition sites derive
/// their decoys from (`Node::build_block_sparse_nf_carrier`, `Node::commit_block_nullifiers`, and the peer-block
/// ingest advance), so the three CANNOT drift. It folds the block's confidential reals AND the block's PRE-block
/// nullifier-acc root (the value the header commits): because the acc advances by the CONSTANT count EVERY block,
/// that pre-root is DISTINCT for every block — so an IDLE block (empty `confidential`) still derives a UNIQUE secret
/// and NO decoy ever repeats across blocks, while each decoy stays byte-shaped exactly like a real PRF nullifier
/// (indistinguishable). This is the nullifier side's exact parallel to the note side folding its per-block `seq`
/// ([`block_cover_secret`]) — here the acc's own pre-root IS the per-block index, so there is no bare/constant seed.
pub fn nullifier_block_secret(confidential: &[u8], pre_root: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(30 + 32 + confidential.len());
    buf.extend_from_slice(b"MUSD-nullifier-block-secret-v1");
    buf.extend_from_slice(pre_root); // per-block-unique: the acc's pre-root, distinct every block
    buf.extend_from_slice(confidential); // the confidential reals — an RPC observer lacks these
    *Hash32::hash(&buf).as_bytes()
}

/// ONE value-0 cover note that is DETERMINISTIC IN THE PER-BLOCK SECRET (`secret` = [`block_cover_secret`]) and
/// `slot` — NOT in the public `(height, slot)`. A single blake3 counter-stream over `secret ‖ slot` fills every
/// field (note_cm / ct / enc / view-tag), so the whole note is byte-shaped exactly like a real one, value 0,
/// spendable by nobody. This keeps the constant 256-note cover shape O(1) (the holder regenerates it from the
/// block's stored reals — nothing about the cover accumulates in RAM or the snapshot) WHILE closing the privacy
/// leak: because the seed is the block SECRET, an observer who enumerates a block's 256 leaf commitments over
/// the public `/get_pq_output_tree` can NO LONGER recompute the cover subset and count/locate the reals
/// ([[cover_privacy_not_public_function]]). "det" now means deterministic-given-the-secret, never a public
/// constant of the indices. Record and serve still agree leaf-for-leaf (same reals+seq ⇒ same secret).
pub fn cover_note_det(secret: &[u8; 32], slot: usize) -> [u8; PQ_NOTE_BYTES] {
    // A single blake3 counter-stream over `secret ‖ slot` fills every field. No stored randomness — the note is
    // a function of the block SECRET + slot, so the holder reproduces record==serve, but an observer lacking the
    // secret cannot recompute it (unlike the old public (height, slot) constant).
    let mut seed = Vec::with_capacity(25 + 32 + 8);
    seed.extend_from_slice(b"MUSD-cover-note-secret-v2");
    seed.extend_from_slice(secret);
    seed.extend_from_slice(&(slot as u64).to_le_bytes());
    let mut out = [0u8; PQ_NOTE_BYTES];
    let mut ctr: u64 = 0;
    let mut off = 0;
    while off < PQ_NOTE_BYTES {
        let mut buf = Vec::with_capacity(seed.len() + 8);
        buf.extend_from_slice(&seed);
        buf.extend_from_slice(&ctr.to_le_bytes());
        let block = Hash32::hash(&buf);
        let b = block.as_bytes();
        let take = core::cmp::min(32, PQ_NOTE_BYTES - off);
        out[off..off + take].copy_from_slice(&b[..take]);
        off += take;
        ctr = ctr.wrapping_add(1);
    }
    out
}

/// FIXED per-block NULLIFIER shape (digital-cash volume privacy): every block records EXACTLY this many nullifiers
/// (real spends + secret-seeded DECOYS), so the on-chain nullifier count per block is CONSTANT regardless of real
/// spend volume — an observer counting nullifiers learns NOTHING about how many real spends occurred (the opposite
/// of transparent crypto, which reveals every input). Matches the served-note cover shape; a block's real spends
/// all fit within this fixed count.
/// The block's nullifier BUDGET is fixed independently, so raising this does NOT raise proving cost — it trades
/// spend-slots for per-tx hiding: [`BLOCK_FIXED_SPEND_TX_COUNT`] = budget / width. Every block carries exactly `256 / 8 = 32` such slots.
/// ⭐ 8 SINCE 2026-11-04 (was 32), so a block holds 32 spends instead of 8, and the tag proof in a send fell from 3.6 s to 0.4 s. A send is single-input already: a
/// many-note payment goes as a sequence, and each spend has 2 real tags, so the rest were only decoys. 8 is the smallest width the blinded proof admits (`COMMITTED_FOLDING`).
pub const TX_FIXED_NULLIFIER_COUNT: usize = 8;

pub const BLOCK_FIXED_NULLIFIER_COUNT: usize = BLOCK_FIXED_NOTE_COUNT;

/// The CONSTANT number of spend-bearing slots in every block = the block's nullifier budget divided by the fixed
/// per-tx width. This is what makes "cover in EVERY block" structural: the count of spend-bearing txs is itself a
/// CONSTANT, not "however many arrived", so it carries zero information about real volume. A block assembles
/// exactly this many constant-width carries or it is refused — a producer cannot ship a thin block precisely when
/// there is something to hide. ([[feedback_all_blocks_fixed_cover_shape]] [[feedback_digital_cash_pillar]])
pub const BLOCK_FIXED_SPEND_TX_COUNT: usize =
    BLOCK_FIXED_NULLIFIER_COUNT / TX_FIXED_NULLIFIER_COUNT;

const _: () = assert!(
    BLOCK_FIXED_NULLIFIER_COUNT % TX_FIXED_NULLIFIER_COUNT == 0,
    "the per-tx width must divide the block's nullifier budget exactly, else the block shape is not constant"
);
const _: () = assert!(
    TX_FIXED_NULLIFIER_COUNT > 1,
    "a width of 1 hides nothing per tx AND makes the under-width consensus rule unreachable — never ship it"
);

/// ONE DECOY nullifier, DETERMINISTIC IN THE PER-BLOCK SECRET (`secret` = [`block_cover_secret`]) and `slot` — NOT
/// a public function of the indices. A domain-separated blake3 over `secret ‖ slot` yields a 256-bit tag byte-
/// shaped EXACTLY like a real PRF nullifier, but there is no note behind it (it spends nothing). It pads the
/// nullifier tree to the constant per-block count so real spend VOLUME + TIMING are hidden (digital cash). Because
/// the seed is the block SECRET, an observer cannot recompute the decoy subset to separate reals from cover
/// ([[cover_privacy_not_public_function]]); domain-separated 256-bit means a ~2^-256 chance of equalling any real
/// nullifier, so a decoy never blocks a future real spend. The node still stores only the O(1) root+count; decoys
/// grow only the DA (constant-rate, served via #27 DAS), never node state.
pub fn cover_nullifier_det(secret: &[u8; 32], slot: usize) -> [u8; 32] {
    digest_shaped_decoy(b"MUSD-cover-nullifier-secret-v2", secret, slot as u64)
}

/// ⭐⭐⭐ DB-353 — ONE DECOY SHAPE, AND IT IS A REAL TAG'S. Every decoy this crate makes goes through here.
///
/// A real nullifier is `leaf_to_cm_bytes(poseidon_pair(sk, leaf))`: eight 31-bit KoalaBear lanes packed into 248 bits,
/// so its top byte is ALWAYS zero and every lane is below p. A blake3 output is uniform over all 256 bits, so its top
/// byte is non-zero 255 times in 256 — and both decoy generators were blake3 (this file's `cover_nullifier_det`, which
/// pads every node-built transaction, and `nullifier_wire_fill`, the block's 256-wide fill). READ 2026-09-28: one byte
/// told a decoy from a real tag, so the constant-width set hid which tags were real from nobody who looked at it.
///
/// Each decoy is now eight lanes, each a 64-bit blake3 XOF word, packed by the SAME `leaf_to_cm_bytes` a real tag goes
/// through (it reduces every lane mod p; the reduction's bias is ≤ p / 2^64 ≈ 2^-33 per lane against a Poseidon output's
/// uniform lane). Keyed by `domain ‖ secret ‖ index`, so a party without the secret still cannot recompute it
/// ([[cover_privacy_not_public_function]]). A collision with a given real tag is ≤ 2^-247.
/// cons: one XOF squeeze of 64 B and eight reductions per decoy instead of one 32-byte hash (~0.3 µs); no growth axis.
fn digest_shaped_decoy(domain: &[u8], secret: &[u8; 32], index: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(domain);
    h.update(secret);
    h.update(&index.to_le_bytes());
    let mut xof = h.finalize_xof();
    let mut lanes = crate::spend_frontier::Digest4::default();
    for lane in lanes.iter_mut() {
        let mut w = [0u8; 8];
        xof.fill(&mut w);
        *lane = u64::from_le_bytes(w);
    }
    crate::spend_frontier::leaf_to_cm_bytes(lanes)
}

/// ⭐ §RF-3 (2026-10-24; R5) — A SYNTHETIC RIGHT'S NULLIFIER WEARS A REAL TAG'S ENCODING. The one-shot rights a carried
/// object retires (`satoshi::reward_nf`, `peg::one_time_id_nf`, `asset_tx::issue_right_nf`,
/// `membership_bond_tx::seat_right_nf`, `unbond_tx::unbond_right_nf`) were raw blake3 words: not canonical digests, so
/// each was told from every other tag by its top byte (DB-353's leak, on the justified side), and the slot ledger — whose
/// justified tag cells are digests — could not state any block carrying one (every rewarded block). The 32-byte hash is
/// mapped by the same `hash32_to_digest` HEADER_SEED uses and packed by `leaf_to_cm_bytes`, like every real tag.
/// MEASURED: `node::pins::rf3_ledger_tag_cells_are_the_header_padded_tags` (rewarded) refused the reward's tag.
/// cons: one Poseidon-domain map per derivation (~1 µs); 248-bit collision bound instead of 256.
#[must_use]
pub fn canonical_tag_of_hash(h: &[u8; 32]) -> [u8; 32] {
    crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::poseidon2_compress::hash32_to_digest(h))
}

/// The block wire fill's `i`-th tag under `secret` — the ONE derivation `nullifier_wire_fill` and
/// `nullifier_wire_strip` share, so the holder's strip can never disagree with the producer's fill.
fn wire_fill_tag(secret: &[u8; 32], i: u64) -> [u8; 32] {
    digest_shaped_decoy(b"MUSD-nf-wire-fill-v2", secret, i)
}

/// ⭐ FIXED PER-TRANSACTION NULLIFIER WIDTH — the shape that makes the PRODUCER treeless.
///
/// Every spend-bearing tx settles EXACTLY this many nullifiers: its real spends, padded with decoys derived from
/// the SPENDER's own per-tx secret. Two consequences, and the second is the point:
///   • VOLUME PRIVACY, per tx rather than only per block — a tx's real input count is hidden inside a constant
///     width, so an observer cannot tell a 1-input send from a 4-input consolidation.
///   • EVERY INSERTION IS OWNED. The spender builds the copath for its decoys exactly as it does for its real
///     spends (it derives them at note-receipt time and maintains all of them incrementally, O(DEPTH) each). So
///     no insertion is an "orphan" that some node must build a witness for — which is the ONLY reason a producer
///     ever had to hold an O(spent) tree. The producer just FOLDS carried copaths against its O(1) root.
///
/// Blocks stay at [`BLOCK_FIXED_NULLIFIER_COUNT`], so this width divides it evenly.
/// ([[feedback_no_growth_any_axis]] [[feedback_all_actions_128_cover_shape]] [[cover_privacy_not_public_function]])

/// Pad ONE TX's real nullifiers to [`TX_FIXED_NULLIFIER_COUNT`] with decoys seeded from the SPENDER's own per-tx
/// secret. `None` when the tx carries more reals than the fixed width — fail-closed, never a silently wider tx
/// (a wider tx would leak that it consolidated more inputs than the shape allows).
pub fn pad_tx_nullifiers_to_fixed(
    real: &[[u8; 32]],
    tx_secret: &[u8; 32],
) -> Option<Vec<[u8; 32]>> {
    if real.len() > TX_FIXED_NULLIFIER_COUNT {
        return None;
    }
    let mut out: Vec<[u8; 32]> = real.to_vec();
    let mut slot = 0usize;
    while out.len() < TX_FIXED_NULLIFIER_COUNT {
        out.push(cover_nullifier_det(tx_secret, slot));
        slot += 1;
    }
    Some(out)
}

/// ⭐ CONSTANT-SHAPE NULLIFIER WIRE FILL — the tag-side twin of [`assemble_fixed_note_payload_det`].
///
/// PRIVACY (user 2026-08-14: volume hidden at EVERY surface): a block's shipped tag vector must be the
/// FIXED [`BLOCK_FIXED_NULLIFIER_COUNT`] shape whether it settles 0 or 200 real spends, or its LENGTH is a
/// per-block volume gauge for any wire observer. Fill tags are `H(secret ‖ index)` — the `secret` is
/// [`nullifier_block_secret`], derived from the block's CONFIDENTIAL reals, so a VALIDATING HOLDER (who
/// carries the block's confidential payload) re-derives the fill set and strips it exactly, while a pure
/// observer — who sees only 256 uniform hash-shaped tags — cannot partition fill from real. Blocks with
/// ≥ the fixed count keep every real (never drop a spend). Deterministic in `(real, secret)`: every node
/// derives the byte-identical vector, so there is never a second definition of the block's contents (the
/// defect family the 2026-08-10 retirement removed stays removed).
/// This is the WIRE FORMAT for the in-circuit nullifier redesign (its call sites arrive with that
/// redesign, which is what makes the hiding real rather than theater: today every validator can derive
/// the strip secret, so a fill alone hides nothing from a peer — only from a passive observer already
/// blinded by the constant-rate onion cover). Callers: the redesign's producer/receiver pair; the two
/// red `nf_sparse` privacy tests are its acceptance gate. Tamper-tested here and now
/// (`nullifier_wire_fill_privacy_tests`: 3 passed) so the primitive is proven before it is load-bearing.
/// cons: 256 blake3 hashes per block at fill and again at strip (~tens of µs); wire tag bytes become the
/// constant 256 x 32 B = 8,192 B per block regardless of load (vs 32 B x real-count today — the constant
/// IS the point, and tags were already regenerable, never stored).
pub fn nullifier_wire_fill(real: &[[u8; 32]], secret: &[u8; 32]) -> Vec<[u8; 32]> {
    if real.len() >= BLOCK_FIXED_NULLIFIER_COUNT {
        return real.to_vec(); // never drop a real spend
    }
    let mut out: Vec<[u8; 32]> = real.to_vec();
    let mut i: u64 = 0;
    while out.len() < BLOCK_FIXED_NULLIFIER_COUNT {
        out.push(wire_fill_tag(secret, i)); // DB-353: digest-shaped, like every real tag
        i += 1;
    }
    out
}

/// ⭐ §RF-3 spec §15 (2026-10-24; R5) — THE BLOCK'S TAG SET: its reals, then decoy `s` = the ledger's cover tag cell
/// `cover_tag_native(seed, s)` for `s = 1..=256−k` (`seed` = [`header_seed`] over the block's output notes). The slot
/// numbering is the ledger's (`settlement_delta::plan_ledger_rows`) whether the reals ride as spend rows or justified
/// tags, so the header's 256 tags ARE the ledger's 256 tag cells (`node::pins::rf3_ledger_tag_cells_are_the_header_padded_tags`).
/// Each decoy is a canonical digest like every real tag; a non-holder of the bodies cannot compute `seed`, so it cannot
/// partition the set. Blocks with ≥ the fixed count keep every real (never drop a spend).
/// cons: ≤ 255 native Poseidon pairs per produce (~tens of µs); wire bytes unchanged (256 × 32 B); nothing stored.
#[must_use]
pub fn header_tag_fill(real: &[[u8; 32]], seed: crate::spend_frontier::Digest4) -> Vec<[u8; 32]> {
    let mut out: Vec<[u8; 32]> = real.to_vec();
    let mut slot = 1u64;
    while out.len() < BLOCK_FIXED_NULLIFIER_COUNT {
        out.push(crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::slot_ledger::cover_tag_native(seed, slot)));
        slot += 1;
    }
    out
}

/// Recover EXACTLY the real tags from a [`nullifier_wire_fill`] vector, given the holder's `secret`.
/// DB-353: the fill it regenerates is `wire_fill_tag` — the same helper the fill uses, never a second spelling.
/// Recomputes the fill members and removes them by value; everything left is real, in original order.
/// A wrong secret recomputes fill members that match nothing, so nothing is stripped and the caller's
/// count check fails loudly — never a silent partial strip.
pub fn nullifier_wire_strip(padded: &[[u8; 32]], secret: &[u8; 32]) -> Vec<[u8; 32]> {
    let mut fill: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
    for i in 0..BLOCK_FIXED_NULLIFIER_COUNT as u64 {
        fill.insert(wire_fill_tag(secret, i));
    }
    padded
        .iter()
        .filter(|t| !fill.contains(*t))
        .copied()
        .collect()
}

/// Assemble a block's SERVED-NOTE payload at the FIXED 256 shape — the O(1), holder-regenerable twin of
/// [`assemble_fixed_note_payload`], now PRIVATE BY CONSTRUCTION. Real notes are placed first; the per-block
/// SECRET ([`block_cover_secret`], which folds the block's confidential reals + `seq`) seeds both the value-0
/// cover fill ([`cover_note_det`]) and the permutation ([`permute_units_det`]) that mixes every real note to a
/// pseudo-random leaf. Every byte is a deterministic function of `(real_notes, seq)`, so this is BOTH the
/// record-time frontier-leaf source AND the serve-time materializer (record == serve, leaf-for-leaf) and the
/// node stores ONLY `real_notes` per seq (cover is regenerated ⇒ O(1), no per-block growth). But because the
/// seed is the SECRET — not the public `(height, slot)` — a public-RPC observer, who has the 256 leaf
/// commitments yet lacks the confidential reals, CANNOT recompute the cover subset and therefore cannot count
/// or locate the real notes. Real notes are never dropped (≥256 real ⇒ all kept, no cover, no permute).
pub fn assemble_fixed_note_payload(real_notes: &[u8], seq: u64, key: &CoverKey) -> Vec<u8> {
    #[cfg(test)]
    {
        payload_memo::get_or_compute(real_notes, seq, key)
    }
    #[cfg(not(test))]
    {
        assemble_fixed_note_payload_computed(real_notes, seq, key)
    }
}

/// ⭐ THE SIMULATOR'S PAYLOAD MEMO — [`assemble_fixed_note_payload_det`] through an EXACT bounded cache in test builds.
///
/// WHY (MEASURED 2026-10-07, `sample` of the fast journey, scratchpad/night/link21-sample.txt): the assembly was ~14 % of
/// every simulated node's step CPU (2,096 samples; 255 cover notes × 37 blake3 calls each). One record's payload is
/// regenerated at record, at fold, at every DA read (`da_record_notes`, `block_leaves_from_notes`) — and on every
/// simulated node, three in one process. It is a pure function of `(real_notes, seq)`, so an exact cache (the key is the
/// whole input) changes no byte — only how often the fill runs.
/// WHERE: `cfg(test)` only. A node binary regenerates as before (nothing about the cover is stored: R1c).
/// cons: ≤ 2 × [`payload_memo::CAP`] payloads (~19 MB) in a test process; none in a node.
#[cfg(test)]
pub mod payload_memo {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    /// Payloads per generation (295 KB each); two generations are kept.
    pub const CAP: usize = 32;
    type Key = (Vec<u8>, u64, super::CoverKey);

    #[derive(Default)]
    struct Gen {
        cur: HashMap<Key, std::sync::Arc<Vec<u8>>>,
        old: HashMap<Key, std::sync::Arc<Vec<u8>>>,
    }

    static MEMO: std::sync::OnceLock<Mutex<Gen>> = std::sync::OnceLock::new();
    /// [lookups, misses] in this process.
    pub static COUNTS: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

    /// What a hit is charged: the fill's measured miss cost (`usdm_decider::poseidon2_compress::sim_charge` — a node binary
    /// regenerates every payload, so a simulated node is charged the fill it skipped; one mean over the journey's records,
    /// most of which carry one real note and so fill 255 cover notes).
    static MISS: usdm_decider::poseidon2_compress::sim_charge::MissCost =
        usdm_decider::poseidon2_compress::sim_charge::MissCost::new();

    pub fn get_or_compute(real_notes: &[u8], seq: u64, cover_key: &super::CoverKey) -> Vec<u8> {
        let memo = MEMO.get_or_init(|| Mutex::new(Gen::default()));
        let key: Key = (real_notes.to_vec(), seq, *cover_key);
        COUNTS[0].fetch_add(1, Ordering::Relaxed);
        let hit = {
            let g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            g.cur.get(&key).or_else(|| g.old.get(&key)).cloned()
        };
        if let Some(p) = hit {
            MISS.charge_hit();
            return p.as_ref().clone();
        }
        COUNTS[1].fetch_add(1, Ordering::Relaxed);
        let out = MISS.measure(|| super::assemble_fixed_note_payload_computed(real_notes, seq, cover_key));
        let mut g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= CAP {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(key, std::sync::Arc::new(out.clone()));
        out
    }
}

/// The fill itself — see [`assemble_fixed_note_payload_det`].
pub fn assemble_fixed_note_payload_computed(real_notes: &[u8], seq: u64, key: &CoverKey) -> Vec<u8> {
    let mut units: Vec<[u8; PQ_NOTE_BYTES]> = Vec::with_capacity(BLOCK_FIXED_NOTE_COUNT);
    let mut off = 0;
    while off + PQ_NOTE_BYTES <= real_notes.len() {
        let mut u = [0u8; PQ_NOTE_BYTES];
        u.copy_from_slice(&real_notes[off..off + PQ_NOTE_BYTES]);
        units.push(u);
        off += PQ_NOTE_BYTES;
    }
    // Never drop a real note: if already at/over the fixed count, keep them all in order (no cover, no permute).
    if units.len() >= BLOCK_FIXED_NOTE_COUNT {
        let mut out = Vec::with_capacity(units.len() * PQ_NOTE_BYTES);
        for u in &units {
            out.extend_from_slice(u);
        }
        return out;
    }
    // Derive the per-block cover secret from the confidential reals + seq (a public-RPC observer cannot recompute
    // it), then fill + permute under it — cover is unpredictable to anyone who cannot already identify the reals.
    let secret = record_cover_secret(seq, key);
    // ⭐⭐⭐ COVER FILL — REINSTATED 2026-08-16 (user: "the 256 cover is no longer retired and is reinstated
    // as a privacy necessity"). The 2026-08-10 retirement that stood here is HISTORY.
    //
    // COST ARITHMETIC (the thing nobody wrote when this was removed):
    //   work    = (256 - reals) `cover_note_det` calls per block, each one blake3-class over a 32 B secret
    //             + slot index. Worst case 255/block. At a 500 ms block clock that is 255 x 172,800/day =
    //             44.1 M derivations/day, ~0.5 us each => ~22 s of CPU per node per DAY. Bounded by the
    //             CONSTANT 256, never by height, notes, spends or age.
    //   bytes   = 256 x 1153 B = 295,168 B assembled per block, TRANSIENT — regenerated at record and at
    //             serve, never persisted (R1c NO PER-BLOCK COVER STORAGE forbids storing the filled shape;
    //             only the REAL notes are stored).
    //   storage growth = ZERO. The fill is a pure function of (`real_notes`, `seq`), so an idle block's 256
    //             units regenerate byte-identically forever from O(1) state with NOTHING stored per block.
    //   cons: none on any growth axis — every term above is f(fixed constant 256), not f(history).
    //
    // MEASURED before this fix, `cover::idle_block_cover_hole::an_idle_block_wears_the_same_shape_as_a_busy_one`:
    //     busy = 1153 B (1 unit), idle = 0 B (0 units), fixed = 256 units
    // The secret was computed and discarded (`let _ = secret;`) with no fill loop, so EVERY block's served
    // payload equalled its real note count exactly — leaking block ACTIVITY and per-block VOLUME.
    //
    // WHAT THE RETIRED COMMENT GOT WRONG: it argued served-count == real-count makes detection "an ordinary
    // indexed lookup". It does — for the owner AND for every observer. That is the leak, not the feature.
    // Its SECOND claim (position == leaf offset) is still TRUE and is why there is still no permute.
    //
    // COUPLED INVARIANT, measured the same day: `node::tests::a_notes_global_leaf_index_is_recoverable...`
    // asserts `leaves.len() == BLOCK_FIXED_NOTE_COUNT` and was RED (left: 1, right: 256). The `ordinal x 256`
    // coordinate is only wrong when the cover is ABSENT; the two are coupled, and removing one without the
    // other is what made 99% of notes unspendable on 2026-08-10. Never separate them again.
    //
    // NOT a node-local secret: a PRF of this node's own DA secret is what caused the cross-node divergence
    // at node.rs:2908 (both nodes recorded nothing, both held one note, DIFFERENT bytes).
    // ⭐ §RF-3 spec §13 (2026-10-24): each cover unit's cm FRONT is the ledger's cover cell for its slot — the k reals
    // are the ledger's spend outs and justified notes, so `plan_ledger_rows` numbers the cover note cells 1..=256-k and
    // the header's cover slots are exactly those cells (`node::pins::rf3_ledger_out_cells_are_the_header_note_slots`).
    // MEASURED before: the blake3 front was not even a canonical digest, so every cover slot was told from a real cm by
    // its encoding alone (R5). The body stays the blake3 stream over `secret`.
    // cons: ≤ 255 native Poseidon pairs per assembled record, f(256) — never f(history); nothing stored.
    let seed = header_seed(real_notes, key);
    let k = units.len();
    while units.len() < BLOCK_FIXED_NOTE_COUNT {
        let i = units.len();
        let mut u = cover_note_det(&secret, i);
        let cell = usdm_decider::slot_ledger::cover_note_native(seed, (i - k + 1) as u64);
        u[..32].copy_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(cell));
        units.push(u);
    }
    let mut out = Vec::with_capacity(units.len() * PQ_NOTE_BYTES);
    for u in &units {
        out.extend_from_slice(u);
    }
    out
}

/// The EXACT INVERSE of [`assemble_fixed_note_payload_det`]: recover a record's REAL notes from the served
/// constant-256 shape, so a node STORES what the producer stores and REGENERATES the same 256 units at serve.
///
/// ⛔⛔⛔ THIS CHANGES STORAGE ONLY — THE SHAPE IS UNTOUCHED. Every block still records, folds and serves the
/// full constant 256-unit shape through [`assemble_fixed_note_payload_det`]; the frontier still takes a
/// constant 256-leaf delta per block, and an observer still cannot count a block's real outputs. What this
/// restores is the producer's OWN rule, applied on every node: the node holds `real_notes` and derives the
/// fill, exactly as R1c requires.
///
/// ⛔⛔⛔ WHY IT HAS TO EXIST. MEASURED 2026-09-04 (`diag_case_08_unspent_root_split`): the restarted party
/// ended on a 766-leaf unspent root against the producer's 256-leaf one, and all 510 extra leaves were
/// regenerated fill units of two idle records (510 = 2 x 255) that the receiving node had filed as OWNED
/// notes. Cause: the by-id record serve answers with the assembled shape (295,168 B), and the receiver stored
/// those bytes as the record's reals — so one record meant two different things on two nodes. See the call
/// site in `Node::record_note_payload_inner` for the whole chain.
///
/// HOW IT IS EXACT, not a guess. Reals are a PREFIX (there is no permute — see this module's header), and
/// unit `i >= k` is `cover_note_det(block_cover_secret(reals, seq), i)`. So the real count `k` is the first
/// slot whose unit equals the fill unit derived from the prefix before it. `block_cover_secret` hashes
/// `domain ‖ seq ‖ reals`, with the reals LAST, so one streaming pass tests every candidate: clone the state
/// to finalise `secret_k`, then absorb unit `k` to advance.
///
/// FAIL-CLOSED. A candidate is accepted ONLY if the prefix RE-ASSEMBLES to these exact bytes, so a payload
/// this function does not fully account for — an altered or forged shape, or 256 genuinely real notes —
/// returns `None` and is left untouched for the caller's own root check to judge. It can never silently
/// discard a real note.
///
/// ⭐ COST ARITHMETIC — f(FIXED CONSTANT 256), NEVER f(history). The loop bound is `BLOCK_FIXED_NOTE_COUNT`,
/// a protocol constant; nothing here reads a second record, walks the DAG, or touches height, note count or
/// age. Per invocation, worst case:
///   * one streaming blake3 pass over 256 x 1,153 B = 295,168 B, plus <=256 hasher clone+finalise (32 B each);
///   * <=256 `cover_note_det` probes + <=256 more in the one re-assembly = 512 x 37 blake3 compressions
///     over ~65 B = ~19k tiny hashes ~= 0.6 MB hashed.
///   * TOTAL ~0.9 MB of blake3 per record ~= <=2 ms on an M-class core, and ONLY for a payload arriving at
///     exactly 295,168 B — the produce path (1-2 notes) returns on the length check with zero work.
/// cons: none, and it DELETES an axis. A node that stored the served shape held 295,168 B/record against the
/// producer's 1,153 B — 256x. At the 500 ms clock (172,800 records/day) that is 51.0 GB/day = 18.6 TB/year of
/// RAM + snapshot on any node that backfills, versus 199 MB/day for the reals. This trades <=2 ms of bounded
/// CPU per backfilled record for removing 51 GB/day of storage growth.
pub fn strip_fixed_note_payload(payload: &[u8], seq: u64, key: &CoverKey) -> Option<Vec<u8>> {
    // Not the assembled width ⇒ these bytes are already the canonical reals (or malformed).
    if payload.len() != BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES {
        return None;
    }
    let secret = record_cover_secret(seq, key);
    for k in 0..BLOCK_FIXED_NOTE_COUNT {
        let unit = &payload[k * PQ_NOTE_BYTES..(k + 1) * PQ_NOTE_BYTES];
        // the BODY only: a cover unit's front is its ledger cell (§RF-3 §13), proven by the re-assembly below
        if unit[32..] == cover_note_det(&secret, k)[32..] {
            let reals = &payload[..k * PQ_NOTE_BYTES];
            // The whole contract in one line: these reals are the answer iff they rebuild these bytes.
            return (assemble_fixed_note_payload(reals, seq, key) == payload).then(|| reals.to_vec());
        }
    }
    // Every one of the 256 slots is a real note, so the payload IS the reals and there is nothing to undo.
    None
}

/// Build ONE value-0 cover TRANSACTION used to pad a block template up to [`BLOCK_FIXED_TX_COUNT`]. Its body
/// is a single cover-note payload; it spends nothing (no nullifiers). At the block level it is
/// byte-indistinguishable from a real tx — the header commits only the id list, and every id is the content
/// hash of an opaque body.
pub fn cover_tx(need_stamp_bits: u32) -> Option<PqTx> {
    let blob = cover_note()?.to_vec();
    let id = PqTx::content_id(&blob);
    let weight = blob.len() as u32;
    let mut tx = PqTx {
        clock_ms: 0,
        note_clues: Vec::new(),
        account_targets: Vec::new(),
        id,
        blob,
        weight,
        nullifiers: Vec::new(),
        pow_stamp: 0,
        output_notes: Vec::new(), // cover-tx notes are the block_cover_notes recorded separately
        stake_notes: Vec::new(),
        bond_notes: Vec::new(),
        nullifier_witnesses: Vec::new(), // cover txs carry no nullifiers → no witnesses
        nullifier_absence: Vec::new(),
        membership_carrier: Vec::new(),
        membership_leaf_commit: [0u8; 32],
        membership_tip: Vec::new(),
        membership_folded_through: 0, // ...and therefore no absence proofs
        spend_or_decoy: Vec::new(),
        member_carrier: Vec::new(),
        member_tuple: Vec::new(),
    };
    // Grind the #72 client-PoW anti-spam stamp so this cover tx clears the SAME mempool admission check as a
    // real tx — the old tree's dummies pass all standard verification, and so does this cover. The grind is
    // cheap at the base floor; the ceiling below is a hard upper bound the low floor never approaches.
    const GRIND_CEILING: u64 = 268_435_456; // 2^28 safety ceiling for the stamp search
    let mut nonce: u64 = 0;
    while nonce < GRIND_CEILING {
        tx.pow_stamp = nonce;
        if tx.stamp_work() >= need_stamp_bits {
            return Some(tx);
        }
        nonce += 1;
    }
    None
}

/// Pad a real-tx selection out to the fixed shape: append fresh cover txs until the total reaches
/// [`BLOCK_FIXED_TX_COUNT`], and return the (id, body) of each cover tx so the producer can make the bodies
/// available (mempool/DA) and record their cover notes. Already-full (or over-full) selections are returned
/// unchanged — this only ADDS cover, never drops real txs.
///
/// ## The block's ENTROPY NOTE rides here
///
/// Every pad tx has a content id in `Block::tx_ids`, exactly like a real tx — 256 ids per block either way.
/// In addition, ONE pad tx declares its cover note as an `output_note`, so that note lands in
/// `Block::output_notes` and travels with the block. This is what makes a block's 256-leaf shape CANONICAL:
/// [`assemble_fixed_note_payload_det`] keys its fill and permutation on [`block_cover_secret`], which folds
/// the block's confidential notes, and that key must be identical on every node yet underivable by an RPC
/// observer. Block-carried entropy is the only source that is both — every full node has the block, and
/// tx/block bodies are not RPC-served. See `project_block_leaves_canonical_seed_must_ride_block` for the
/// three alternatives that were measured and what each one broke.
///
/// ONE note, not 256: the other 255 slots regenerate from the key it supplies, so block and record each carry
/// 1153 bytes, unchanged from before. Declaring all 256 would push [`assemble_fixed_note_payload_det`] past
/// its fixed count and return them verbatim in selection order, losing the permutation.
pub fn pad_to_fixed_shape(real_count: usize, need_stamp_bits: u32) -> Vec<PqTx> {
    // ⭐⭐⭐ FIXED 256-SLOT COVER REMOVED — DELIBERATE, USER-AUTHORIZED PRIVACY AMENDMENT (2026-08-10).
    //
    // user: *"Maybe hiding that a tx occurred in a block was a mistake to try to get right … lets remove the
    // fixed 256 cover."* This trades ONE property — hiding THAT a payment happened, and how many — for a
    // system that can actually move money. Everything that protects a user is kept: PQ stealth addresses, ZK
    // amounts, nullifier unlinkability, onion-only transport. Sender, recipient, amount and linkage stay
    // hidden, so this remains stronger than any shipped chain; only occurrence/count becomes visible, which
    // is what Bitcoin, Monero and Zcash have always exposed.
    //
    // WHY: at 10,005 blocks the chain held 2,561,280 note slots for ~4 real notes. That ratio is the direct
    // cause of every defect measured this session — detection could not be indexed without revealing which
    // slots were real (hence OLI/PIR/clue tags), the index had to cover all 2.5M slots (hence a 73,240ms
    // restore), and the witness book had to count 256 leaves per block (hence the `ordinal x 256` alignment
    // gap that currently blocks every send).
    //
    // Cover is now zero-width: a block carries exactly its real notes. Nothing else about the note format,
    // the proof, or the gates changes — a cover note was always an ML-KEM ciphertext to a discarded key, so
    // removing it removes bytes, never a check.
    // ⛔⛔⛔ TX-LAYER COVER IS STILL OFF — AND THIS SHORT-CIRCUIT IS A KNOWN OPEN DEFECT, NOT A DECISION.
    //
    // Enabling the loop below (removing these two lines) is CORRECT for privacy — `tx_ids.len()` otherwise
    // tracks real activity and an observer counts payments per block, which is why
    // `every_block_reaches_the_constant_tx_count_whatever_its_real_load` and
    // `cover_padding_tops_every_block_up_to_the_constant_and_never_over` are RED. They are the defect report.
    //
    // ⚠️ BUT IT REGRESSES LEAF INDEXING, MEASURED 2026-08-16: with the fill enabled,
    // `node::tests::a_notes_global_leaf_index_is_recoverable_from_its_record_so_no_stream_walk_is_needed`
    // goes from GREEN back to RED, and node::tests as a whole from 111/22 to 107/26. Unspendable notes
    // outrank a metadata leak, so the fill stays off until the interaction is understood.
    // SUSPECTED (untested): the 255 cover txs perturb the note/leaf accounting the record layer derives.
    // `cover_tx` sets `output_notes: Vec::new()` claiming "cover-tx notes are recorded separately" — verify
    // whether that separate path double-counts once the note-layer cover is also live. Do NOT enable the
    // loop again without a RED->GREEN on the leaf-index test itself.
    // DIGITAL-CASH-PRIVACY-REVIEWED: `real_count` is the INPUT to cover padding, never an output — how many slots must be FILLED so every block reaches the same constant 256. Never served, logged or committed; this erases the count rather than revealing it.
    let need = BLOCK_FIXED_TX_COUNT.saturating_sub(real_count);
    // ⛔ A COVER TX DECLARES **NO** OUTPUT NOTE. Two wrong versions preceded this, both
    // measured at 127/9 against a 132/4 baseline:
    //   (a) `if covers.is_empty() { tx.output_notes = tx.blob }` — one note across 255 covers,
    //       so `tx_ids.len()` and the note count disagreed;
    //   (b) a note on EVERY cover — each then filed its OWN record, and
    //       `a_notes_global_leaf_index_is_recoverable…` failed `ordinals are DENSE` with 3
    //       records where 2 were expected. 255 extra records per block is worse than (a).
    // The NOTE cover is already handled one layer down: `assemble_fixed_note_payload_det` grows
    // the block's single note payload to `BLOCK_FIXED_NOTE_COUNT`. This function's only job is
    // the TX-COUNT shape, so a cover tx must add a slot and nothing else.
    // ⭐ THE COVERS ARE MINTED ON UP TO FOUR LANES (2026-10-07). Each is independent — a fresh ML-KEM note to a discarded key
    // plus its own anti-spam stamp grind — and `begin_produce` runs this under the runtime lock. MEASURED (`sample` of the
    // simulator's fast journey, scratchpad/night/link21-sample.txt): the 255 covers were ~11 % of every node's step CPU
    // (`stamp_work` 1,033 samples, `cover_note` 484). The result is the sequential loop's: `need` covers in slot order,
    // cut at the first KEM failure (no-halts — cover is best-effort, never required).
    // cons: up to three short-lived threads per template; no state, no growth.
    let lanes = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get).clamp(1, 4);
    let per = need.div_ceil(lanes).max(1);
    #[cfg(test)]
    let net = crate::params::thread_network_for_test(); // a simulated process's lanes stamp under ITS network
    // a REPLAYABLE simulated node's lanes draw slot k's KEM randomness from its own seeded stream (`None` on a daemon:
    // the OS RNG, unchanged). MEASURED (replay-r2.log): these lanes drew from the OS, so one seed's first block differed.
    let entropy = crate::budget_clock::fork_entropy();
    let minted: Vec<Option<PqTx>> = std::thread::scope(|s| {
        let running: Vec<_> = (0..need)
            .step_by(per)
            .map(|from| {
                s.spawn(move || {
                    #[cfg(test)]
                    crate::params::adopt_thread_network_for_test(net);
                    (from..(from + per).min(need))
                        .map(|k| {
                            if let Some(e) = entropy {
                                crate::budget_clock::seed_entropy_this_thread(Some(e.child(k as u64)));
                            }
                            cover_tx(need_stamp_bits)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        // a lane that panicked contributes one missing slot, where `map_while` below cuts the covers (best-effort)
        running.into_iter().flat_map(|l| crate::fixed::join_or_else(l, "cover lane", || vec![None])).collect()
    });
    minted.into_iter().map_while(|c| c).collect()
}

/// Consensus block-shape CAP (ported from `v36_shape`): a valid block carries AT MOST
/// [`BLOCK_FIXED_TX_COUNT`] transactions. Fail-CLOSED on the over-cap block ONLY (reject it); it never
/// requires the count to be exact, so a block with fewer (or zero) txs still validates — no-halts by
/// construction.
pub fn within_block_tx_cap(tx_count: usize) -> bool {
    tx_count <= BLOCK_FIXED_TX_COUNT
}
#[cfg(all(test, feature = "pins-core"))]
mod nullifier_wire_fill_privacy_tests {
    use super::*;

    fn nfs(seed: u8, k: usize) -> Vec<[u8; 32]> {
        (0..k)
            .map(|i| *Hash32::hash(&[seed, i as u8, 0x5a]).as_bytes())
            .collect()
    }

    /// The wire shape is the CONSTANT 256 for every real count — the length carries zero volume signal.
    #[test]
    fn wire_vector_length_is_invariant_to_real_spend_volume() {
        let secret = [7u8; 32];
        for k in [0usize, 1, 50, 255] {
            assert_eq!(
                nullifier_wire_fill(&nfs(1, k), &secret).len(),
                BLOCK_FIXED_NULLIFIER_COUNT,
                "K={k} must ship the fixed shape"
            );
        }
    }

    /// A HOLDER (right secret) strips back to exactly the reals, order preserved; a WRONG secret strips
    /// NOTHING (no silent partial recovery) — fail-closed for the receiver's count check.
    #[test]
    fn holder_strips_exactly_the_reals_and_a_wrong_secret_recovers_nothing() {
        let secret = [9u8; 32];
        for k in [0usize, 1, 50] {
            let real = nfs(2, k);
            let padded = nullifier_wire_fill(&real, &secret);
            assert_eq!(
                nullifier_wire_strip(&padded, &secret),
                real,
                "round-trip at K={k}"
            );
            let mut wrong = secret;
            wrong[0] ^= 1;
            assert_eq!(
                nullifier_wire_strip(&padded, &wrong).len(),
                BLOCK_FIXED_NULLIFIER_COUNT,
                "a wrong secret must strip NOTHING at K={k} — the count check then refuses loudly"
            );
        }
    }

    /// ≥ the fixed count: every real kept, none dropped, no fill added.
    #[test]
    fn overfull_blocks_keep_every_real_spend() {
        let secret = [3u8; 32];
        let real = nfs(4, BLOCK_FIXED_NULLIFIER_COUNT + 9);
        assert_eq!(
            nullifier_wire_fill(&real, &secret),
            real,
            "never drop a real spend"
        );
    }
}

#[cfg(test)]
mod idle_block_cover_hole {
    use super::*;

    /// The primitive the idle-block fix rests on: a producer's seed note must be UNPREDICTABLE.
    ///
    /// `block_cover_secret` folds the CONFIDENTIAL reals, so with `reals` empty it degrades to a PUBLIC
    /// `blake3(domain ‖ seq)` and an observer recomputes all 256 cover units — the constant shape then hides
    /// the COUNT but not the FACT of emptiness. The fix prepends ONE `fresh_seed_note()` at PRODUCE time
    /// (node.rs), so `reals` is never empty and the secret is never public.
    ///
    /// ⚠️ SCOPE: this asserts the PRIMITIVE only. The composition — that a produced idle block is not
    /// publicly recomputable — cannot be tested here (this module has no Node); it is covered at node level
    /// by `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`, which also proves the seed
    /// note travels IN THE BLOCK rather than being regenerated per node (the cross-node divergence trap).
    /// An earlier version of this test compared `assemble_fixed_note_payload(&[], seq, &TEST_COVER_KEY)` with itself and
    /// could NEVER have failed once the fix landed a layer above — a test that cannot fail proves nothing.
    #[test]
    fn a_producers_seed_note_is_fresh_high_entropy_so_an_idle_blocks_secret_is_never_public() {
        let a = fresh_seed_note();
        let b = fresh_seed_note();
        assert_eq!(
            a.len(),
            PQ_NOTE_BYTES,
            "a seed note is a well-shaped note, indistinguishable from real"
        );
        assert_ne!(
            a, b,
            "seed notes must be FRESH — a derivable one would leave the secret public"
        );
        // §20.2: the record's secret is its producer-drawn key's, and the idle key (the one public key) never matches a
        // fresh one — so a record with a seed note is never served under a publicly-derivable secret.
        let public_secret = record_cover_secret(4242, &idle_cover_key(4242));
        let keyed_secret = record_cover_secret(4242, &fresh_cover_key());
        assert_ne!(public_secret, keyed_secret, "a produced record's cover secret is never the idle (public) one");
    }

    /// EMPIRICAL (TX LAYER): does a block reach the constant tx count, whatever its real tx count?
    ///
    /// This is the FIRST of the two cover layers the module doc describes. If `tx_ids.len()` tracks real
    /// activity, an observer counts payments per block off the tx list and the note-layer cover buys
    /// nothing — they simply read the other layer. Proven by
    /// `node::tests::a_produced_block_carries_its_own_entropy...` failing with left: 1, right: 256.
    #[test]
    fn every_block_reaches_the_constant_tx_count_whatever_its_real_load() {
        for reals in [0usize, 1, 7, 64] {
            let covers = pad_to_fixed_shape(reals, 0);
            assert_eq!(
                reals + covers.len(),
                BLOCK_FIXED_TX_COUNT,
                "a block with {reals} real tx(s) must still present {} slots — otherwise tx_ids.len() \
                 reveals how many real payments it carried",
                BLOCK_FIXED_TX_COUNT
            );
        }
    }

    /// EMPIRICAL: does an IDLE block wear the same shape as a BUSY one?
    ///
    /// If it does not, block ACTIVITY is observable from the served payload alone — the count/volume
    /// metadata the fixed cover exists to remove. This test states the property; it is expected to FAIL
    /// against the current code, and that failure IS the defect report.
    #[test]
    fn an_idle_block_wears_the_same_shape_as_a_busy_one() {
        let busy_real = vec![7u8; PQ_NOTE_BYTES]; // one real note
        let busy = assemble_fixed_note_payload(&busy_real, 42, &TEST_COVER_KEY);
        let idle = assemble_fixed_note_payload(&[], 42, &TEST_COVER_KEY);
        println!(
            "[cover-shape] busy={} B ({} units), idle={} B ({} units), fixed={} units",
            busy.len(),
            busy.len() / PQ_NOTE_BYTES,
            idle.len(),
            idle.len() / PQ_NOTE_BYTES,
            BLOCK_FIXED_NOTE_COUNT
        );
        assert_eq!(
            idle.len(),
            busy.len(),
            "an idle block is DISTINGUISHABLE from a busy one by payload size — activity leaks"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod served_shape_canonicalisation_tests {
    use super::*;

    /// `k` arbitrary 1153-byte units standing in for a record's real notes. `assemble_fixed_note_payload_det`
    /// copies note bytes verbatim, so nothing here depends on them being well-formed ML-KEM.
    fn reals(seed: u8, k: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(k * PQ_NOTE_BYTES);
        for i in 0..k {
            let mut off = 0usize;
            let mut ctr = 0u64;
            while off < PQ_NOTE_BYTES {
                let d = Hash32::hash(&[&[seed, i as u8][..], &ctr.to_le_bytes()[..]].concat());
                let take = core::cmp::min(32, PQ_NOTE_BYTES - off);
                out.extend_from_slice(&d.as_bytes()[..take]);
                off += take;
                ctr += 1;
            }
        }
        out
    }

    /// THE INVARIANT: whatever a node is SERVED, it stores what the PRODUCER stores. Round-trips at every
    /// interesting real count, including the idle record (k=1, one seed note) that case 08 diverged on.
    #[test]
    fn the_served_shape_canonicalises_back_to_exactly_the_reals_it_was_built_from() {
        for k in [0usize, 1, 2, 7, 128, 255] {
            let real = reals(0xA1, k);
            let served = assemble_fixed_note_payload(&real, 4242, &TEST_COVER_KEY);
            assert_eq!(
                served.len(),
                BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES,
                "k={k}: the serve must always be the constant shape"
            );
            assert_eq!(
                strip_fixed_note_payload(&served, 4242, &TEST_COVER_KEY),
                Some(real.clone()),
                "k={k}: the served shape must canonicalise back to exactly these reals"
            );
            // And the node that stored the canonical form re-serves byte-identical bytes.
            assert_eq!(
                assemble_fixed_note_payload(&real, 4242, &TEST_COVER_KEY),
                served,
                "k={k}: record == serve on the node that stored only the reals"
            );
        }
    }

    /// ADVERSARIAL — A TAMPERED FILL UNIT MUST BE REFUSED. A peer that alters one byte of the padding must
    /// never get this node to store a truncated record: the re-assembly check fails, so the bytes are left
    /// exactly as they arrived for the caller's own root check to reject.
    #[test]
    fn a_single_altered_fill_byte_is_refused_and_never_truncates_the_record() {
        let real = reals(0xB2, 3);
        let served = assemble_fixed_note_payload(&real, 77, &TEST_COVER_KEY);
        for slot in [3usize, 4, 200, BLOCK_FIXED_NOTE_COUNT - 1] {
            let mut bad = served.clone();
            bad[slot * PQ_NOTE_BYTES] ^= 0x01;
            assert_eq!(
                strip_fixed_note_payload(&bad, 77, &TEST_COVER_KEY),
                None,
                "an altered unit at slot {slot} must be REFUSED, never canonicalised"
            );
        }
    }

    /// ADVERSARIAL — AN ALTERED REAL UNIT MUST BE REFUSED. Changing a real note changes the per-record
    /// secret, so the padding no longer matches it; accepting a prefix here would store notes the chain
    /// never committed.
    #[test]
    fn a_single_altered_real_byte_is_refused() {
        let real = reals(0xC3, 5);
        let served = assemble_fixed_note_payload(&real, 9001, &TEST_COVER_KEY);
        for slot in [0usize, 1, 4] {
            let mut bad = served.clone();
            bad[slot * PQ_NOTE_BYTES + 17] ^= 0x80;
            assert_eq!(
                strip_fixed_note_payload(&bad, 9001, &TEST_COVER_KEY),
                None,
                "an altered real note at slot {slot} must be REFUSED"
            );
        }
    }

    /// ADVERSARIAL — THE BYTES ARE BOUND TO THEIR RECORD ADDRESS. The same payload offered under a
    /// different address canonicalises to nothing, so a served record can never be re-homed.
    #[test]
    fn a_served_shape_offered_under_the_wrong_address_is_refused() {
        let real = reals(0xD4, 2);
        let served = assemble_fixed_note_payload(&real, 500, &TEST_COVER_KEY);
        assert_eq!(strip_fixed_note_payload(&served, 500, &TEST_COVER_KEY), Some(real));
        assert_eq!(
            strip_fixed_note_payload(&served, 501, &TEST_COVER_KEY),
            None,
            "the same bytes under a neighbouring address must be REFUSED"
        );
    }

    /// A FULL RECORD LOSES NOTHING. 256 real notes assemble with no padding at all, so there is nothing to
    /// undo — and the canonicaliser must say so rather than shorten a record that is entirely real.
    #[test]
    fn a_record_of_256_real_notes_is_left_whole() {
        let real = reals(0xE5, BLOCK_FIXED_NOTE_COUNT);
        let served = assemble_fixed_note_payload(&real, 31337, &TEST_COVER_KEY);
        assert_eq!(served, real, "256 reals assemble to themselves");
        assert_eq!(
            strip_fixed_note_payload(&served, 31337, &TEST_COVER_KEY),
            None,
            "a wholly-real record must be left exactly as it is"
        );
    }
}

/// ⭐⭐⭐ DB-165 — THE CONSTANT-WIDTH NOTE CARRIER: what a block says about its notes, and nothing more.
///
/// ⛔⛔⛔ THE DEFECT THIS REPLACES, MEASURED 2026-09-24 (`harness::privacy`, real blocks):
///
/// ```text
/// output_notes   quiet 0 · quiet 0 · busy 5765      5765 / 1153 = EXACTLY 5 real notes
/// credit_set     quiet 0 · quiet 0 · busy 6015
/// ```
///
/// The block body stated its real note count directly. Worse, it handed every node the key to the DA
/// record's cover: `block_cover_secret(real_notes, seq)` takes the REALS as its only secret input, and
/// the block carries those reals in the clear — so any node recomputes the secret, regenerates all 251
/// cover slots and names the real ones. The record's padding is sound in isolation and **defeated by the
/// block**. For an empty block the reals are empty, so the secret degenerates to `hash(prefix ‖ seq)` — a
/// public function, which is what `public_idle_seed_note` is: a one-bit quiet/busy oracle per record.
///
/// ## ⭐ THE LAW THAT FORCES THIS SHAPE
///
/// > **Anything a node can REGENERATE, an observer can DISTINGUISH.**
///
/// Regeneration needs derivability; derivability makes cover identifiable; and every node is a possible
/// observer, so there is no seed that serving nodes have and observers do not. "Regenerate cover at
/// serve" and "cover indistinguishable from a real note" are mutually exclusive. The privacy pillar
/// decides: **cover is STORED, never derived.**
///
/// Storing cover is affordable only if cover is SMALL. 256 × 1153 B of ciphertext is 295 KB/block — 10x
/// over the ≤25 KB Tor budget, and 1153 B is ML-KEM-768, fixed by the PQ pillar. 256 × 32 B of
/// commitment is **8,192 bytes, constant**. So the block carries commitments; the ciphertexts live in the
/// DA record and are fetched only by their owner through the oblivious account-bucket path — measured
/// 2026-09-24 at **1 DA read, flat from 1 record to 4,000**.
///
/// ⛔ THIS IS NOT THE BITCOIN OR ZCASH SHAPE AND MUST NOT BE CITED AS ONE. Zcash puts note ciphertexts
/// INSIDE the block (`encCiphertext` per output — that is how a recipient trial-decrypts) and does not
/// hide per-block output counts; Bitcoin blocks carry full transactions, and BIP-152 short-ID fetching is
/// RELAY, not block structure; Monero does not hide output counts either. **No major chain hides
/// per-block real output count.** This requirement is stronger than all three, so the shape is derived
/// here; the nearest honest borrow is a data-availability separation (Celestia / EIP-4844 blobs).
#[derive(Clone, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub struct BlockNoteCommitments {
    /// Exactly [`BLOCK_FIXED_NOTE_COUNT`] × 32 bytes. Always. On every block, quiet or busy.
    slots: Vec<u8>,
}

/// One commitment, in bytes.
pub const NOTE_COMMITMENT_BYTES: usize = 32;
/// The carrier's constant wire width: 256 × 32 = 8,192 bytes.
pub const BLOCK_NOTE_COMMITMENTS_BYTES: usize = BLOCK_FIXED_NOTE_COUNT * NOTE_COMMITMENT_BYTES;

impl BlockNoteCommitments {
    /// Build the carrier from this block's REAL note commitments plus stored cover.
    ///
    /// ⛔ `cover` SUPPLIES THE COVER COMMITMENTS AND IS NOT DERIVED FROM ANYTHING THE BLOCK CARRIES. That
    /// is the whole point: a caller that passed `f(reals, seq)` here would rebuild the defeated design.
    /// The producer draws them from its own entropy and they travel with the block; nobody regenerates
    /// them, so nobody can subtract them.
    ///
    /// Real commitments are placed at positions chosen by `order`, so their INDICES carry no information
    /// either — a real note always first would leak the count by where the cover starts.
    ///
    /// Returns `None` if there are more real commitments than the fixed width can hold; a block may never
    /// silently drop a note.
    #[must_use]
    pub fn assemble(
        reals: &[[u8; NOTE_COMMITMENT_BYTES]],
        cover: &[[u8; NOTE_COMMITMENT_BYTES]],
        order: &[usize],
    ) -> Option<Self> {
        if reals.len() > BLOCK_FIXED_NOTE_COUNT || order.len() != reals.len() {
            return None;
        }
        if cover.len() < BLOCK_FIXED_NOTE_COUNT - reals.len() {
            return None;
        }
        let mut slots = vec![0u8; BLOCK_NOTE_COMMITMENTS_BYTES];
        let mut taken = vec![false; BLOCK_FIXED_NOTE_COUNT];
        for (r, &pos) in reals.iter().zip(order.iter()) {
            if pos >= BLOCK_FIXED_NOTE_COUNT || taken[pos] {
                return None; // two reals in one slot would lose a note
            }
            taken[pos] = true;
            let off = pos * NOTE_COMMITMENT_BYTES;
            slots[off..off + NOTE_COMMITMENT_BYTES].copy_from_slice(r);
        }
        let mut c = 0usize;
        for (pos, t) in taken.iter().enumerate() {
            if *t {
                continue;
            }
            let off = pos * NOTE_COMMITMENT_BYTES;
            slots[off..off + NOTE_COMMITMENT_BYTES].copy_from_slice(&cover[c]);
            c += 1;
        }
        Some(Self { slots })
    }

    /// The wire bytes — a constant [`BLOCK_NOTE_COMMITMENTS_BYTES`], whatever the block carried.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.slots
    }

    /// Parse, refusing anything that is not exactly the constant width. ⛔ FAIL-CLOSED: a short carrier
    /// is the leak coming back, so it is not a carrier at all.
    #[must_use]
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        if b.len() != BLOCK_NOTE_COMMITMENTS_BYTES {
            return None;
        }
        Some(Self { slots: b.to_vec() })
    }

    /// The commitment at a slot.
    #[must_use]
    pub fn slot(&self, i: usize) -> Option<[u8; NOTE_COMMITMENT_BYTES]> {
        let off = i.checked_mul(NOTE_COMMITMENT_BYTES)?;
        let end = off.checked_add(NOTE_COMMITMENT_BYTES)?;
        if end > self.slots.len() {
            return None;
        }
        let mut out = [0u8; NOTE_COMMITMENT_BYTES];
        out.copy_from_slice(&self.slots[off..end]);
        Some(out)
    }

    /// The header's commitment to this carrier. ⛔ Never `hash(&[])`: the carrier is never empty, so this
    /// root can no longer double as a "did this block carry notes" oracle the way `output_notes_root`
    /// did in five load-bearing places.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        Hash32::hash(&self.slots)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db165_carrier_tests {
    use super::*;

    fn c(b: u8) -> [u8; NOTE_COMMITMENT_BYTES] {
        [b; NOTE_COMMITMENT_BYTES]
    }
    fn cover_set(n: usize, seed: u8) -> Vec<[u8; NOTE_COMMITMENT_BYTES]> {
        (0..n).map(|i| c(seed.wrapping_add(i as u8))).collect()
    }

    /// ⭐⭐⭐ THE PROPERTY THE WHOLE CHANGE EXISTS FOR: the carrier is BYTE-CONSTANT whatever the block
    /// carried. This is what `output_notes` was not — measured at 0 bytes quiet and 5,765 busy.
    #[test]
    fn the_carrier_is_the_same_width_on_an_empty_block_and_a_full_one() {
        let quiet = BlockNoteCommitments::assemble(&[], &cover_set(BLOCK_FIXED_NOTE_COUNT, 0), &[])
            .expect("a quiet block assembles");
        let one = BlockNoteCommitments::assemble(
            &[c(0xAA)],
            &cover_set(BLOCK_FIXED_NOTE_COUNT, 0),
            &[7],
        )
        .expect("one real note assembles");
        let many: Vec<_> = (0..64u8).map(c).collect();
        let order: Vec<usize> = (0..64).collect();
        let busy = BlockNoteCommitments::assemble(&many, &cover_set(BLOCK_FIXED_NOTE_COUNT, 0), &order)
            .expect("64 real notes assemble");

        assert_eq!(quiet.as_bytes().len(), BLOCK_NOTE_COMMITMENTS_BYTES);
        assert_eq!(one.as_bytes().len(), BLOCK_NOTE_COMMITMENTS_BYTES);
        assert_eq!(busy.as_bytes().len(), BLOCK_NOTE_COMMITMENTS_BYTES);
        assert_eq!(
            BLOCK_NOTE_COMMITMENTS_BYTES, 8_192,
            "the carrier must weigh 8 KB — 256 x 32 B. 256 x 1153 B of CIPHERTEXT would be 295 KB, ten \\
             times the Tor budget, which is precisely why the block carries commitments"
        );

        // ⛔ AND THE ROOT IS NEVER THE EMPTY HASH. `output_notes_root == Hash32::hash(&[])` was the
        // "this block carried no real notes" test in FIVE load-bearing places — a quiet/busy oracle
        // sitting in the header. A carrier that is never empty cannot answer that question at all.
        assert_ne!(quiet.root(), Hash32::hash(&[]), "a quiet block's root must not be the empty hash");
        assert_ne!(one.root(), Hash32::hash(&[]));
        assert_ne!(busy.root(), Hash32::hash(&[]));
    }

    /// ⛔⛔⛔ THE ADVERSARY ARM — the attack that succeeds against the old design must fail here.
    ///
    /// Old design: cover = f(reals, seq), and the block carries the reals, so any node recomputes the
    /// cover and subtracts it. Here the cover is SUPPLIED and STORED, so the identical attacker — who
    /// holds the whole block and the public seq — has nothing to recompute from.
    #[test]
    fn an_attacker_holding_the_whole_carrier_cannot_separate_cover_from_real() {
        let reals = [c(0x11), c(0x22), c(0x33)];
        // Cover drawn from entropy the block does NOT carry. Two different draws over the SAME reals.
        let a = BlockNoteCommitments::assemble(&reals, &cover_set(BLOCK_FIXED_NOTE_COUNT, 0x40), &[3, 9, 200])
            .expect("assembles");
        let b = BlockNoteCommitments::assemble(&reals, &cover_set(BLOCK_FIXED_NOTE_COUNT, 0x90), &[3, 9, 200])
            .expect("assembles");

        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "⛔ the same reals produced the SAME carrier under different cover — the cover is being \\
             derived from the reals, which is the defeated design coming back"
        );
        assert_eq!(a.as_bytes().len(), b.as_bytes().len(), "and both are still the constant width");

        // The real slots are where the producer put them; nothing about the LAYOUT says how many.
        assert_eq!(a.slot(3), Some(c(0x11)));
        assert_eq!(a.slot(200), Some(c(0x33)));
        // ⛔ REALS ARE NOT PACKED AT THE FRONT. Placing them first would make "where the cover starts"
        // the count, which is the same leak wearing an index instead of a length.
        assert_ne!(
            a.slot(0),
            Some(c(0x11)),
            "a real note landed at slot 0 although the order said 3 — packing reals at the front leaks \\
             the count through the boundary"
        );
    }

    /// ⛔ FAIL-CLOSED ON WIDTH, IN BOTH DIRECTIONS. A short carrier is the leak returning, and a block
    /// that carries more reals than the fixed width would have to drop one.
    #[test]
    fn a_carrier_that_is_not_exactly_the_fixed_width_is_refused() {
        assert!(BlockNoteCommitments::from_bytes(&[]).is_none(), "an empty carrier is not a carrier");
        assert!(
            BlockNoteCommitments::from_bytes(&vec![0u8; BLOCK_NOTE_COMMITMENTS_BYTES - 32]).is_none(),
            "a carrier one slot short states a count by its length — exactly the defect being removed"
        );
        assert!(
            BlockNoteCommitments::from_bytes(&vec![0u8; BLOCK_NOTE_COMMITMENTS_BYTES + 32]).is_none(),
            "a carrier one slot long is equally a length signal"
        );
        assert!(
            BlockNoteCommitments::from_bytes(&vec![0u8; BLOCK_NOTE_COMMITMENTS_BYTES]).is_some(),
            "calibration: the exact width must parse, or every arm above passes vacuously"
        );

        let too_many: Vec<_> = (0..=BLOCK_FIXED_NOTE_COUNT).map(|i| c(i as u8)).collect();
        let order: Vec<usize> = (0..too_many.len()).collect();
        assert!(
            BlockNoteCommitments::assemble(&too_many, &cover_set(BLOCK_FIXED_NOTE_COUNT, 0), &order).is_none(),
            "⛔ more reals than slots must REFUSE — silently dropping one is a lost note, and a lost note \\
             is lost money"
        );
        // Two reals claiming one slot is the same loss by another route.
        assert!(
            BlockNoteCommitments::assemble(&[c(1), c(2)], &cover_set(BLOCK_FIXED_NOTE_COUNT, 0), &[5, 5])
                .is_none(),
            "⛔ two real notes in one slot must REFUSE — the second would overwrite the first"
        );
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod db353_decoy_shape_tests {
    use super::*;

    /// Shaped like a Poseidon digest packed by `leaf_to_cm_bytes`: eight 31-bit lanes, each below p, and the top byte 0.
    fn digest_shaped(t: &[u8; 32]) -> bool {
        const P: u64 = 0x7f00_0001;
        t[31] == 0
            && (0..8usize).all(|lane| {
                let mut v = 0u64;
                for bit in 0..31usize {
                    let idx = lane * 31 + bit;
                    if (t[idx >> 3] >> (idx & 7)) & 1 == 1 {
                        v |= 1 << bit;
                    }
                }
                v < P
            })
    }

    /// ⭐⭐⭐ DB-353 — EVERY DECOY IS SHAPED LIKE A REAL TAG, AND THE OLD FILL WAS NOT (the calibration arm).
    #[test]
    fn db353_every_decoy_is_shaped_like_a_real_tag_and_the_old_fill_was_not() {
        let lanes = |i: u64| -> crate::spend_frontier::Digest4 { core::array::from_fn(|k| i * 31 + k as u64 + 1) };
        let reals: Vec<[u8; 32]> = (0..64u64)
            .map(|i| {
                crate::spend_frontier::leaf_to_cm_bytes(usdm_decider::nullifier_insert_air::poseidon_pair_native(
                    lanes(i),
                    lanes(i + 1_000),
                ))
            })
            .collect();
        assert!(reals.iter().all(digest_shaped), "CALIBRATION: every real tag is digest-shaped");
        // The v1 fill, exactly as it was derived: the tell this change closes.
        let v1 = |i: u64| -> [u8; 32] {
            let mut b = Vec::new();
            b.extend_from_slice(b"MUSD-nf-wire-fill-v1");
            b.extend_from_slice(&[7u8; 32]);
            b.extend_from_slice(&i.to_le_bytes());
            *Hash32::hash(&b).as_bytes()
        };
        let told = (0..256u64).filter(|i| !digest_shaped(&v1(*i))).count();
        assert!(told > 240, "CALIBRATION: the v1 blake3 fill was told from a real tag by its bytes ({told}/256)");

        let secret = [7u8; 32];
        let fill = nullifier_wire_fill(&reals[..3], &secret);
        assert_eq!(fill.len(), BLOCK_FIXED_NULLIFIER_COUNT);
        assert!(fill.iter().all(digest_shaped), "⛔ DB-353: a block fill tag is told from a real tag by its bytes");
        let padded = pad_tx_nullifiers_to_fixed(&reals[..1], &secret).expect("one real pads to the fixed width");
        assert!(padded.iter().all(digest_shaped), "⛔ DB-353: a per-tx decoy is told from the real tag by its bytes");
        assert_eq!(
            nullifier_wire_strip(&fill, &secret),
            reals[..3].to_vec(),
            "the holder's strip still recovers exactly the reals"
        );
        assert!(
            nullifier_wire_strip(&fill, &[8u8; 32]).len() == BLOCK_FIXED_NULLIFIER_COUNT,
            "a wrong secret strips nothing"
        );
    }
}
