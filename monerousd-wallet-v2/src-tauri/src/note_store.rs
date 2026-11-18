// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! OBLIVIOUS COLD-RESTORE PERSISTENCE KEYSTONE — a local, encrypted, chain+scan-key-scoped store of THIS wallet's
//! OWNED note ciphertexts, so a USDm balance is PERMANENT no matter how many blocks go by. It is required (not a
//! mere cache) because MonerousD is a private VALIDIUM: notes are confidential (only the scan key detects which are
//! yours) AND nodes SAMPLE / prune old DA bulk ([[Tor-stack DAS]], task #27) to stay O(1)/small — so an old note's
//! ciphertext is NOT guaranteed re-servable forever. Without this store, a wallet that only re-fetches from a
//! pruning node loses notes that aged out of the served window (the exact bug this fixes). Transparent chains
//! (BTC/ETH) can rebuild from public UTXOs, so there disk is only a speed cache; a PRIVATE chain must persist.
//!
//! PILLAR-SAFE BY CONSTRUCTION:
//! - PRIVACY (P1): the file holds ONLY raw note records (already public on-chain) encrypted at rest under a key
//!   derived from the scan secret, so a stolen disk file leaks NOTHING about which notes are yours. The scan/spend
//!   key never leaves the wallet; nothing is registered with any node.
//! - SOUND (P3): the disk NEVER asserts an amount. On load every record is RE-DECAPSULATED locally under the scan
//!   key (the amount is re-derived, not trusted) and every note's UNSPENT status is RE-CHECKED live against the
//!   node's nullifier set — the chain stays the source of validity truth. A tampered/garbage record simply fails
//!   to decap and is ignored; a since-spent note is dropped. So a malicious store can never inflate the balance.
//! - PQ (P2): confidentiality-at-rest is a blake3 keystream (SHA3-family hash), no classical crypto.
//! - FAST (P4): O(owned) — load re-decaps only YOUR records, not the whole chain; save is O(owned) atomic write.
use std::path::{Path, PathBuf};
// ⛔⛔⛔ §AG WIDENED A DIGEST FROM 4 LANES TO 8, AND THIS TREE KEPT SPELLING IT `[u64; 4]`.
// The width belongs to the TYPE, never to a literal repeated 149 times. `Digest4` is the node's own
// alias (`usdm_decider::poseidon2_compress::Digest`), so the wallet can never again disagree with the
// chain about how wide a commitment, root, nullifier or key is.
use usdmd_node::spend_frontier::Digest4;

/// File magic so a foreign/corrupt file is rejected rather than mis-parsed.
///
/// ⭐ DB-311: VERSION 2 — every record's u64 is a POSITION and nothing else: the record address `persist_owned_notes`
/// stamped from `da_pos`, or `u64::MAX` (not yet placed). The wallet's writers put only those two there, and a reader
/// may file a version-2 value as the note's position. Version 1 is still read, through [`legacy_position`].
const MAGIC: &[u8; 8] = b"MUSDMNS2";
/// DB-311: the version-1 magic. Its per-record u64 was written three ways (a stamped record address, the applied
/// stream's placement HEIGHT, a Refresh's 0), and the old reader filed all three as a record address: the position the
/// spend's membership carrier reads before it resolves one.
const MAGIC_V1: &[u8; 8] = b"MUSDMNS1";
/// DB-311 (lane-db224-carriage's review): the least value a version-1 field can hold AS A STAMPED RECORD ADDRESS. The
/// three meanings are disjoint by range in every store written before version 2: a placement height at 2 blocks/s
/// reaches 2^40 only after ~17,400 years, the Refresh wrote 0, the sentinel is `u64::MAX`, and a stamped address is a
/// 64-bit hash (~10^17). An address that hashed below 2^40 (p ~ 2^-24 per note) reads as unplaced and is re-derived by
/// the next detection pass, the safe side. A one-time decoder for version-1 bytes only: version 2 never consults it.
const LEGACY_ADDRESS_FLOOR: u64 = 1 << 40;

/// DB-311: a version-1 record's u64 as a position — its stamped address, else the sentinel.
fn legacy_position(v: u64) -> u64 {
    if (LEGACY_ADDRESS_FLOOR..u64::MAX).contains(&v) {
        v
    } else {
        u64::MAX
    }
}

/// The store file for a given (open-wallet key_id, chain_id) — scoped so a different seed OR a different chain
/// (a re-genesis) resolves to a DIFFERENT file (clean slate by construction, like the swap store). Lives under the
/// wallet data dir alongside the swap store.
pub fn store_path(data_dir: &Path, key_id: &[u8; 32], chain_id: &str) -> PathBuf {
    let kid = hex::encode(&key_id[..6]);
    let cid: String = chain_id.chars().filter(|c| c.is_ascii_alphanumeric()).take(16).collect();
    let cid = if cid.is_empty() { "nochain".to_string() } else { cid };
    data_dir.join(format!("notes-{kid}-{cid}.dat"))
}

/// The at-rest confidentiality key — derived from the scan decapsulation secret (which never leaves the wallet), so
/// only this wallet can read its own note-set file. Domain-separated from every other use of the scan secret.
fn store_key(scan_dk: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"musdm.notestore.v1.key");
    h.update(scan_dk);
    *h.finalize().as_bytes()
}

/// In-place blake3 keystream XOR (counter-mode). Confidentiality only — soundness/integrity come from re-decap +
/// the live nullifier re-check on load, so no AEAD tag is needed (a flipped byte just fails to decap → ignored).
fn xor_keystream(key: &[u8; 32], data: &mut [u8]) {
    let mut counter: u64 = 0;
    let mut pos = 0;
    while pos < data.len() {
        let mut h = blake3::Hasher::new_keyed(key);
        h.update(&counter.to_le_bytes());
        let block = *h.finalize().as_bytes();
        let n = (data.len() - pos).min(32);
        for i in 0..n {
            data[pos + i] ^= block[i];
        }
        pos += n;
        counter = counter.wrapping_add(1);
    }
}

/// Persist the owned records (each = raw note bytes + the height it was recorded at) + the scan cursor. Atomic
/// (temp + rename) so a crash mid-write never tears the file. Best-effort: an IO error is swallowed (a failed
/// persist must never break a balance read); the next successful save re-writes the full set.
pub fn save(path: &Path, scan_dk: &[u8], cursor: u64, records: &[(Vec<u8>, u64)], spent: &[(u64, Digest4)]) {
    write_store(path, scan_dk, cursor, records, spent, None, MAGIC)
}

/// TEST ONLY (DB-311): the bytes an OLDER binary wrote, so a pin can reopen a store whose per-note u64 holds whatever
/// that binary put there (a stamped address, a placement height, a Refresh's 0).
#[cfg(test)]
pub fn save_v1(path: &Path, scan_dk: &[u8], cursor: u64, records: &[(Vec<u8>, u64)], spent: &[(u64, Digest4)]) {
    write_store(path, scan_dk, cursor, records, spent, None, MAGIC_V1)
}

/// ⭐ DB-279 §7 — what the wallet's OWN spend log cannot yet answer for. `log_from` is the blue score at which this
/// store's spend log began (every note accepted at or above it can only have been spent by this log's owner).
/// `entries` lists owned notes whose acceptance height is not yet known to be at or above it: `(nf, due)` means
/// "answer from the own log until the applied stream's cursor passes `due`, then ask the chain once"; `due == 0`
/// asks now. A note NOT listed is answered from the own spent set and no node is asked about it.
/// `proven_spent` (DB-279 §7c/§7d) holds this wallet's notes the CHAIN answered spent: an earlier holder's spends,
/// which a restore finds, and this wallet's own sent inputs once confirmed. A spent answer is a positive proof, and the
/// nullifier set only grows, so it is final: the display and send selection read these notes spent, and nothing asks
/// about them again.
/// `marked_at` (DB-298) holds, for each of this wallet's spends not yet confirmed, the height at which it marked the
/// input spent. The spent-marking reconciliation counts a PRESENT answer only from a view that stands the DB-97 horizon
/// past that height, in every process; before, only the RAM-only send log carried the height, so a later process
/// un-marked a spend on two answers from a view that had not folded it yet.
/// `pending_change` (DB-300) holds, for each of this wallet's own remainders the chain has not carried yet, the
/// remainder's nullifier and the nullifier of the input its transaction spends. The remainder is pending (never
/// spendable) until the chain carries it, and it leaves with its transaction if that expires, in every process;
/// before, only the RAM-only send log carried the pairing, so a later process read an uncarried remainder spendable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Unresolved {
    pub log_from: u64,
    pub entries: Vec<([u8; 32], u64)>,
    pub proven_spent: Vec<[u8; 32]>,
    pub marked_at: Vec<([u8; 32], u64)>,
    pub pending_change: Vec<([u8; 32], [u8; 32])>,
    /// DB-273 §15 R4: the `chg` indices this wallet wrote into an ACCEPTED object the chain has not shown yet, each with
    /// the object's input nullifier. A later process reserves around them exactly as the sending one did, so a restart
    /// inside a settlement window never writes a second change at an index whose send is still landing (a shared tag).
    pub in_flight_chg: Vec<(u64, [u8; 32])>,
    /// ⭐ DB-329 (C): this install's DEVICE SLOT `d`. Its change notes take the `chg` domain's slot-`d` space, so two
    /// devices on one seed never share a change tag. Assigned once, at import, in the owner's add-device order, and
    /// kept here: the same approved encrypted write, so a restart never takes a new slot. Slot 0 is every wallet written
    /// before version 6, so its domain is the unchanged `chg`.
    pub device_slot: u32,
    /// ⭐ DB-223 Q2 §11 R-b3 (version 7): each owned note's place in its record — `(cm, fold ordinal, RecordPath)` — so a
    /// restarted process re-captures the note's member witness with NO record fetch (`MemberWitnessBook::path_restored`).
    /// Ordinal 0 means "not folded yet" (genesis holds ordinal 0 and no notes). The levels it holds are fixed forever at
    /// the record's fold; nothing in it moves (class J refused the MOVING siblings, never these). Never authority: a
    /// path that does not refold to the node's own ring root is refused at the carrier.
    pub member_paths: Vec<([u8; 32], u64, usdmd_node::member_witness::RecordPath)>,
    /// ⭐ DB-329 step 3 (version 8): where this install stands on its device slot (§7, §7c F1, §7d).
    pub slot: SlotStatus,
    /// ⭐ DB-329 §7d A1 (version 8): the slot `d` of an add THIS device (the slot-0 adder) paid a marker for, which the
    /// sweep has not seen yet; 0 = none. A second add refuses while it is set, so one adder never pays two markers to one
    /// slot before the first folds.
    pub pending_add: u32,
    /// ⭐ DB-223 Q2 §12d L (version 9): each owned note's KEPT siblings at levels `RECORD_LEVEL..HIGH_LEVEL`
    /// (`MemberWitnessBook::held_fixed_levels`), handed out only once no fold rewind can move them, so a restarted process
    /// needs no stream entry and no index ask for those levels (`fixed_levels_restored`). Never authority: a kept root is
    /// taken only at the note's own sibling window, and a path that does not refold to the node's ring root is refused.
    pub fixed_levels: FixedLevels,
}

/// ⭐ DB-223 Q2 §12d L — `(cm, its kept levels RECORD_LEVEL..HIGH_LEVEL)` per owned note.
pub type FixedLevels = Vec<([u8; 32], [Digest4; usdmd_node::member_witness::FIXED_LEVELS])>;

/// ⭐ DB-329 step 3 — this install's standing on its device slot, kept in the encrypted store (version 8) so a restart
/// never re-decides it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SlotStatus {
    /// The slot in `device_slot` is this install's. Every store written before version 8 reads so: that device already
    /// wrote under its slot.
    #[default]
    Decided,
    /// Restored from the seed on this device, with no store: the slot is not known yet. No self-note is written until
    /// the chain settles it (a free add-device marker is claimed; otherwise slot 0, §7d A2).
    Undecided,
    /// Claiming slot `d` with a self-send of its marker. `own_claims` holds every claim cm this device built, so a claim
    /// that lands late still reads as won (§7c F1). `input_nf` (DB-329 §7i) is a SELF-claim's input nullifier (no marker
    /// at `d`): while it reads unspent no claim of this device landed, so a dropped self-claim is rebuilt; `None` for a
    /// marker claim (the marker's own verdict decides).
    Claiming { d: u32, own_claims: Vec<[u8; 32]>, input_nf: Option<[u8; 32]> },
    /// Lost a claim and found no free marker left. Slot 0 is provably alive (it added), so writes refuse until the user
    /// adds this device again from the first device.
    NeedsAdd,
}

/// ⭐ DB-279 §7 — [`save`] plus the UNRESOLVED section ([`Unresolved`]).
/// cons: 18 B, plus 40 B per listed note (entries leave on their first chain answer, or on placement at or above
/// `log_from`), plus 32 B per held spent verdict (§7c/§7d: one per note of this wallet's own, owned or sent from it,
/// beside the 40 B per send the spent section keeps; 1,000 such notes write 32 KB). Older files have no section, and
/// [`load_unresolved`] reports that as `Some(None)`, so the caller treats every loaded note as due now (today's asks)
/// and starts `log_from` at the tip it next reads.
pub fn save_with_unresolved(
    path: &Path,
    scan_dk: &[u8],
    cursor: u64,
    records: &[(Vec<u8>, u64)],
    spent: &[(u64, Digest4)],
    unresolved: &Unresolved,
) {
    write_store(path, scan_dk, cursor, records, spent, Some(unresolved), MAGIC)
}

/// The versioned tag that opens the UNRESOLVED section (after the spent section). Absent in older files.
/// Layout (version 4, DB-300): tag(2) ‖ log_from(8) ‖ count(4) ‖ count × (nf(32) ‖ due(8)) ‖ proven(4) ‖
/// proven × nf(32) ‖ marked(4) ‖ marked × (nf(32) ‖ height(8)) ‖ pending(4) ‖ pending × (remainder nf(32) ‖ input
/// nf(32)). Version 3 is the same without the pending tail and reads with NO pending remainders. Versions 1 and 2 are
/// deliberately NOT parsed (they read ABSENT): see [`parse_body`].
const UNRESOLVED_TAG: [u8; 2] = [b'U', 9];
/// Version 8 (DB-329 step 3): everything but the kept fixed-level tail (DB-223 Q2 §12d L); it reads with NO kept levels.
const UNRESOLVED_TAG_V8: [u8; 2] = [b'U', 8];
/// Version 7 (DB-223 R-b3): everything but the slot-status tail (DB-329 step 3); it reads as DECIDED at its stored
/// device slot, with no pending add.
const UNRESOLVED_TAG_V7: [u8; 2] = [b'U', 7];
/// Version 6 (DB-329 (C)): everything but the member-path tail (DB-223 R-b3); it reads with NO member paths.
const UNRESOLVED_TAG_V6: [u8; 2] = [b'U', 6];
/// Version 5 (DB-273 §15 R4): everything but the device-slot tail (DB-329 (C)); it reads as device slot 0.
const UNRESOLVED_TAG_V5: [u8; 2] = [b'U', 5];
/// Version 4 (DB-300): everything but the in-flight tail.
const UNRESOLVED_TAG_V4: [u8; 2] = [b'U', 4];
/// The one earlier version still read: version 3 (DB-298), everything but the pending tail.
const UNRESOLVED_TAG_V3: [u8; 2] = [b'U', 3];
/// One marking-height record's width in the section, shared by the writer and the reader.
const MARKED_REC: usize = 32 + 8;
/// One pending-remainder record's width (DB-300), shared by the writer and the reader.
const PENDING_REC: usize = 32 + 32;
/// One in-flight `chg` record's width (DB-273 §15 R4): index(8) ‖ input nullifier(32), shared by the writer and reader.
const IN_FLIGHT_REC: usize = 8 + 32;
/// One listed note's width in the UNRESOLVED section, shared by the writer and the reader.
const UNRESOLVED_REC: usize = 32 + 8;
/// One member-path record's width (DB-223 R-b3): cm(32) ‖ ordinal(8) ‖ the path's ONE byte spelling, shared by the
/// writer and the reader.
const MEMBER_PATH_REC: usize = 32 + 8 + usdmd_node::member_witness::RecordPath::BYTES;
/// One kept fixed-level record's width (DB-223 Q2 §12d L, version 9): cm(32) ‖ FIXED_LEVELS × one digest's lane bytes,
/// shared by the writer and the reader. 32 + 11 × 64 = 736 B.
const FIXED_LEVELS_REC: usize =
    32 + usdmd_node::member_witness::FIXED_LEVELS * usdmd_node::spend_frontier::DIGEST_LANE_BYTES;
/// DB-329 step 3 (version 8): the slot-status kind byte, shared by the writer and the reader.
const SLOT_DECIDED: u8 = 0;
const SLOT_UNDECIDED: u8 = 1;
const SLOT_CLAIMING: u8 = 2;
const SLOT_NEEDS_ADD: u8 = 3;
/// DB-329 §7i: a SELF-claim — `SLOT_CLAIMING`'s body, then its input nullifier (32 B).
const SLOT_CLAIMING_SELF: u8 = 4;

fn write_store(
    path: &Path,
    scan_dk: &[u8],
    cursor: u64,
    records: &[(Vec<u8>, u64)],
    spent: &[(u64, Digest4)],
    unresolved: Option<&Unresolved>,
    magic: &[u8; 8],
) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut body = Vec::with_capacity(12 + records.iter().map(|(r, _)| r.len() + 12).sum::<usize>());
    body.extend_from_slice(&cursor.to_le_bytes());
    body.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for (rec, height) in records {
        body.extend_from_slice(&height.to_le_bytes());
        body.extend_from_slice(&(rec.len() as u32).to_le_bytes());
        body.extend_from_slice(rec);
    }
    // ⭐⭐⭐ THE WALLET'S OWN SPENT-SET RIDES THE SAME ENCRYPTED SELF-CUSTODY STORE.
    //
    // Spent-status is wallet-LOCAL by pillar (#151): the which-nullifier node query is a banned linkage
    // oracle, so the exclusion authority is the wallet's own record of what it consumed
    // (`remove_spent_inputs` → `st.spent`). That set was RAM-only, so any reopened/one-shot wallet
    // re-counted its consumed inputs and DISPLAYED an inflated balance — measured live: 12.5 shown against
    // 1.5 truly spendable after three settled sends (the chain's double-spend gate was never wrong; the
    // display was). Persisting `(amount, sk)` pairs after the records section makes the exclusion survive
    // reopen with zero new files and zero new queries.
    // cons: O(this wallet's OWN spend history) bytes in its own encrypted store — the same self-custody
    // axis the note store and witness book already occupy (sanctioned by the survivability cardinal);
    // 40 B per spend, no node state, no wire bytes, no oracle. Older files without the section load as
    // an empty set (same display as before this fix, never worse).
    body.extend_from_slice(&(spent.len() as u32).to_le_bytes());
    // ⛔⛔⛔ §AG CLASS 9 — A BYTE BUFFER SIZED BY A LANE COUNT, LIVE IN THIS WALLET'S PERSISTENCE.
    //
    // The writer below iterates `for l in sk`, so it followed `DIGEST_LANES` from 4 to 8 and began
    // emitting 72-byte records. The READER kept the literal `40` for both its bounds check and its
    // stride, read 64 bytes out of a 40-byte record, and PANICKED on load:
    //     range end index 164 out of range for slice of length 157
    // A crash on wallet restart, on the file holding this wallet's own spent set.
    //
    // ⭐ ONE DEFINITION OF THE RECORD WIDTH, DERIVED FROM THE LANE COUNT (`SPENT_REC`), used by the
    // writer and the reader alike — so the two can never again disagree about how long a record is.
    for (amt, sk) in spent {
        body.extend_from_slice(&amt.to_le_bytes());
        for l in sk {
            body.extend_from_slice(&l.to_le_bytes());
        }
    }
    if let Some(u) = unresolved {
        body.extend_from_slice(&UNRESOLVED_TAG);
        body.extend_from_slice(&u.log_from.to_le_bytes());
        body.extend_from_slice(&(u.entries.len() as u32).to_le_bytes());
        for (nf, due) in &u.entries {
            body.extend_from_slice(nf);
            body.extend_from_slice(&due.to_le_bytes());
        }
        body.extend_from_slice(&(u.proven_spent.len() as u32).to_le_bytes());
        for nf in &u.proven_spent {
            body.extend_from_slice(nf);
        }
        body.extend_from_slice(&(u.marked_at.len() as u32).to_le_bytes());
        for (nf, h) in &u.marked_at {
            body.extend_from_slice(nf);
            body.extend_from_slice(&h.to_le_bytes());
        }
        // DB-300: this wallet's remainders the chain has not carried yet, each with the input its transaction spends.
        body.extend_from_slice(&(u.pending_change.len() as u32).to_le_bytes());
        for (remainder, input) in &u.pending_change {
            body.extend_from_slice(remainder);
            body.extend_from_slice(input);
        }
        // DB-273 §15 R4: the in-flight `chg` indices of this wallet's accepted objects, each with its input nullifier.
        body.extend_from_slice(&(u.in_flight_chg.len() as u32).to_le_bytes());
        for (index, input) in &u.in_flight_chg {
            body.extend_from_slice(&index.to_le_bytes());
            body.extend_from_slice(input);
        }
        // DB-329 (C), version 6: this install's device slot.
        body.extend_from_slice(&u.device_slot.to_le_bytes());
        // DB-223 R-b3, version 7: each owned note's (cm, ordinal, record path), the section's last tail.
        body.extend_from_slice(&(u.member_paths.len() as u32).to_le_bytes());
        for (cm, ordinal, path) in &u.member_paths {
            body.extend_from_slice(cm);
            body.extend_from_slice(&ordinal.to_le_bytes());
            body.extend_from_slice(&path.to_bytes());
        }
        // DB-329 step 3, version 8: the slot status (one kind byte; a claim adds its slot and its own claim cms), then
        // the pending add — the section's last tail.
        match &u.slot {
            SlotStatus::Decided => body.push(SLOT_DECIDED),
            SlotStatus::Undecided => body.push(SLOT_UNDECIDED),
            SlotStatus::Claiming { d, own_claims, input_nf } => {
                body.push(if input_nf.is_some() { SLOT_CLAIMING_SELF } else { SLOT_CLAIMING });
                body.extend_from_slice(&d.to_le_bytes());
                body.extend_from_slice(&(own_claims.len() as u32).to_le_bytes());
                for cm in own_claims {
                    body.extend_from_slice(cm);
                }
                if let Some(nf) = input_nf {
                    body.extend_from_slice(nf);
                }
            }
            SlotStatus::NeedsAdd => body.push(SLOT_NEEDS_ADD),
        }
        body.extend_from_slice(&u.pending_add.to_le_bytes());
        // DB-223 Q2 §12d L, version 9: each owned note's kept levels RECORD_LEVEL..HIGH_LEVEL — the section's last tail.
        body.extend_from_slice(&(u.fixed_levels.len() as u32).to_le_bytes());
        for (cm, levels) in &u.fixed_levels {
            body.extend_from_slice(cm);
            for l in levels {
                body.extend_from_slice(&usdmd_node::spend_frontier::digest_to_lane_bytes(l));
            }
        }
    }
    xor_keystream(&store_key(scan_dk), &mut body);
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&body);
    let tmp = path.with_extension("dat.tmp");
    if std::fs::write(&tmp, &out).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

/// Load the persisted (cursor, records). Returns None if the file is absent / has the wrong magic / is truncated —
/// the caller then starts a fresh scan (never a hard error). Decrypts, then parses the record list. The records are
/// RAW ciphertexts; the caller MUST re-decap them under the scan key (never trust their contents) and re-check
/// unspent — this function only recovers the ciphertext inventory + where to resume the delta scan from.
pub fn load(path: &Path, scan_dk: &[u8]) -> Option<(u64, Vec<(Vec<u8>, u64)>, Vec<(u64, Digest4)>)> {
    parse_store(path, scan_dk).map(|(cursor, records, spent, _)| (cursor, records, spent))
}

/// DB-279 §7 — the UNRESOLVED section written by [`save_with_unresolved`]: `None` when the file is absent or
/// unreadable, `Some(None)` when it predates the section (the caller must then treat every loaded note as due now:
/// it cannot know which of them it has held all along), `Some(Some(u))` otherwise.
/// O1-INFINITY-REVIEWED: this reads THIS WALLET'S OWN encrypted self-custody store, the file that already carries
/// its spent set (sanctioned by the survivability cardinal), not any node's authority. Its size is O(this wallet's
/// unresolved notes), independent of chain height, block count or the chain's spent total, and entries leave on
/// their first chain answer. It decides only whether the DISPLAY may answer from the wallet's own spend log or must
/// ask; no chain state is reconstructed from it, and a missing section errs toward asking.
pub fn load_unresolved(path: &Path, scan_dk: &[u8]) -> Option<Option<Unresolved>> {
    parse_store(path, scan_dk).map(|(_, _, _, unresolved)| unresolved)
}

/// O1-INFINITY-REVIEWED: the parser of THIS WALLET'S OWN encrypted store (see [`load_unresolved`]); every section it
/// reads is O(this wallet's own notes and spends), never a term in chain height or the chain's totals.
#[allow(clippy::type_complexity)]
fn parse_store(
    path: &Path,
    scan_dk: &[u8],
) -> Option<(u64, Vec<(Vec<u8>, u64)>, Vec<(u64, Digest4)>, Option<Unresolved>)> {
    let raw = std::fs::read(path).ok()?;
    if raw.len() < 8 {
        return None;
    }
    // DB-311: a version-1 store is read whole; only its per-record u64 is decoded, through `legacy_position`.
    // ROOT-LAYER: the store's format is this module's own; the version decides what its per-record u64 means, so the
    // decode lives where the bytes are read, and every caller (`seed_scan_from_store`'s position filing) receives
    // positions only.
    // MEASURED: before → db311_a_reopened_wallet_never_files_a_height_or_a_zero_as_a_notes_position RED (15:14); the
    // live receipt in [gatepf] step 12 showed a record address as a height; after → the same pin and the v1-decode pin.
    // MUST-STAY-GREEN: every note_store round trip (records, spent, the U section at v3/v4), and a v1 store's notes,
    // spent set and cursor loading exactly as before, since only the position field is decoded.
    let v1 = &raw[0..8] == MAGIC_V1;
    if &raw[0..8] != MAGIC && !v1 {
        return None;
    }
    let mut body = raw[8..].to_vec();
    xor_keystream(&store_key(scan_dk), &mut body);
    let mut parsed = parse_body(&body)?;
    if v1 {
        for (_, place) in parsed.1.iter_mut() {
            *place = legacy_position(*place);
        }
    }
    Some(parsed)
}

/// The decrypted store body's sections, in order: cursor and records, the spent set, the UNRESOLVED section.
/// O1-INFINITY-REVIEWED: parses THIS WALLET'S OWN store body (see [`load_unresolved`]); O(its own notes and spends).
#[allow(clippy::type_complexity)]
fn parse_body(body: &[u8]) -> Option<(u64, Vec<(Vec<u8>, u64)>, Vec<(u64, Digest4)>, Option<Unresolved>)> {
    if body.len() < 12 {
        return None;
    }
    let cursor = u64::from_le_bytes(body[0..8].try_into().ok()?);
    let n = u32::from_le_bytes(body[8..12].try_into().ok()?) as usize;
    let mut off = 12usize;
    let mut records = Vec::with_capacity(n.min(1 << 20));
    for _ in 0..n {
        if off + 12 > body.len() {
            break;
        }
        let height = u64::from_le_bytes(body[off..off + 8].try_into().ok()?);
        let len = u32::from_le_bytes(body[off + 8..off + 12].try_into().ok()?) as usize;
        off += 12;
        if off + len > body.len() {
            break;
        }
        records.push((body[off..off + len].to_vec(), height));
        off += len;
    }
    // The wallet's own spent-set section (absent in older files → empty set, never a parse failure).
    let mut spent: Vec<(u64, Digest4)> = Vec::new();
    if off + 4 <= body.len() {
        let n = u32::from_le_bytes(body[off..off + 4].try_into().ok()?) as usize;
        off += 4;
        for _ in 0..n {
            // ⛔ THE BOUND AND THE STRIDE ARE THE SAME NUMBER AS THE WRITE. Both were the literal 40
            // while the write followed the lane count to 72 — see `SPENT_REC` above.
            if off + SPENT_REC > body.len() {
                break;
            }
            let amt = u64::from_le_bytes(body[off..off + 8].try_into().ok()?);
            let mut sk = usdmd_node::spend_frontier::empty_leaf();
            for (c, l) in sk.iter_mut().enumerate() {
                *l = u64::from_le_bytes(body[off + 8 + c * 8..off + 16 + c * 8].try_into().ok()?);
            }
            spent.push((amt, sk));
            off += SPENT_REC;
        }
    }
    // DB-279 §7: the UNRESOLVED section, present only in files written by `save_with_unresolved`. A section that
    // opens with the tag but is truncated is read as ABSENT (every note unresolved), never as "none unresolved":
    // an under-read here would silence the asks that keep a restored spent note from reading unspent.
    // DB-279 §7c / DB-298: version 3 appends the held spent verdicts and then the marking heights after the listed
    // notes. VERSION-1 and VERSION-2 sections read ABSENT on purpose: v1's writer dropped every spent answer (the
    // self-inflicted DB-279 §7 defect, §9 of its doc), so a note it does not list may be one the chain proved spent;
    // v2 carries no marking heights. Absent lists every loaded note due now, and a marking with no height waits for
    // the first node tip this process reads. A cut anywhere in version 3 also reads ABSENT: never under-read.
    // DB-300: version 4 appends the pending remainders after the marking heights, and a cut anywhere in it (the tail
    // included) reads ABSENT. Version 3 (no tail) still reads, with NO pending remainders: every other field it carries
    // is unchanged in meaning, and a remainder it was sending keeps the reading it had before (spendable at once).
    // DB-273 §15 R4: version 5 appends the in-flight `chg` tail after the pending tail; a cut anywhere in it reads ABSENT.
    // Version 4 (no in-flight tail) still reads, with NO in-flight indices: a restart of a v4 process simply reserves
    // from the mark as before.
    let mut unresolved: Option<Unresolved> = None;
    let tag = (off + 2 <= body.len()).then(|| [body[off], body[off + 1]]);
    let version: u8 = match tag {
        Some(t) if t == UNRESOLVED_TAG => 9,
        Some(t) if t == UNRESOLVED_TAG_V8 => 8,
        Some(t) if t == UNRESOLVED_TAG_V7 => 7,
        Some(t) if t == UNRESOLVED_TAG_V6 => 6,
        Some(t) if t == UNRESOLVED_TAG_V5 => 5,
        Some(t) if t == UNRESOLVED_TAG_V4 => 4,
        Some(t) if t == UNRESOLVED_TAG_V3 => 3,
        _ => 0,
    };
    if off + 14 <= body.len() && version >= 3 {
        let log_from = u64::from_le_bytes(body[off + 2..off + 10].try_into().ok()?);
        let n = u32::from_le_bytes(body[off + 10..off + 14].try_into().ok()?) as usize;
        let start = off + 14;
        let end = start + n * UNRESOLVED_REC;
        if end + 4 <= body.len() {
            let p = u32::from_le_bytes(body[end..end + 4].try_into().ok()?) as usize;
            let (pstart, pend) = (end + 4, end + 4 + p * 32);
            // DB-298: the marked tail must be present in full too, or the whole section reads ABSENT.
            if pend + 4 <= body.len() {
                let m = u32::from_le_bytes(body[pend..pend + 4].try_into().ok()?) as usize;
                let (mstart, mend) = (pend + 4, pend + 4 + m * MARKED_REC);
                // DB-300: version 4+'s pending tail, read in full or not at all, with the offset it ends at.
                let pending: Option<(Vec<([u8; 32], [u8; 32])>, usize)> = if version < 4 {
                    (mend <= body.len()).then(|| (Vec::new(), mend))
                } else if mend + 4 <= body.len() {
                    let k = u32::from_le_bytes(body[mend..mend + 4].try_into().ok()?) as usize;
                    let (kstart, kend) = (mend + 4, mend + 4 + k * PENDING_REC);
                    (kend <= body.len()).then(|| {
                        let list = body[kstart..kend]
                            .chunks_exact(PENDING_REC)
                            .map(|c| {
                                let (mut remainder, mut input) = ([0u8; 32], [0u8; 32]);
                                remainder.copy_from_slice(&c[..32]);
                                input.copy_from_slice(&c[32..]);
                                (remainder, input)
                            })
                            .collect();
                        (list, kend)
                    })
                } else {
                    None
                };
                // DB-273 §15 R4: version 5's in-flight tail, read in full or not at all (with where it ends).
                let in_flight: Option<(Vec<(u64, [u8; 32])>, usize)> = match &pending {
                    None => None,
                    Some((_, pend_end)) if version < 5 => Some((Vec::new(), *pend_end)),
                    Some((_, pend_end)) if pend_end + 4 <= body.len() => {
                        let f = u32::from_le_bytes(body[*pend_end..pend_end + 4].try_into().ok()?) as usize;
                        let (fstart, fend) = (pend_end + 4, pend_end + 4 + f * IN_FLIGHT_REC);
                        (fend <= body.len()).then(|| {
                            let list = body[fstart..fend]
                                .chunks_exact(IN_FLIGHT_REC)
                                .map(|c| {
                                    let (mut index, mut input) = ([0u8; 8], [0u8; 32]);
                                    index.copy_from_slice(&c[..8]);
                                    input.copy_from_slice(&c[8..]);
                                    (u64::from_le_bytes(index), input)
                                })
                                .collect();
                            (list, fend)
                        })
                    }
                    Some(_) => None,
                };
                // DB-329 (C): version 6's device slot (with where it ends); earlier versions are slot 0.
                let device_slot: Option<(u32, usize)> = match &in_flight {
                    None => None,
                    Some((_, fend)) if version < 6 => Some((0, *fend)),
                    Some((_, fend)) => body.get(*fend..fend + 4).map(|b| {
                        let mut w = [0u8; 4];
                        w.copy_from_slice(b);
                        (u32::from_le_bytes(w), fend + 4)
                    }),
                };
                // DB-223 R-b3: version 7's member-path tail, read in full or not at all; earlier versions hold none. A
                // record whose path bytes do not decode reads the whole section ABSENT, never a shorter list.
                type MemberPaths = Vec<([u8; 32], u64, usdmd_node::member_witness::RecordPath)>;
                let member_paths: Option<(MemberPaths, usize)> = match &device_slot {
                    None => None,
                    Some((_, dend)) if version < 7 => Some((Vec::new(), *dend)),
                    Some((_, dend)) if dend + 4 <= body.len() => {
                        let mut w = [0u8; 4];
                        w.copy_from_slice(&body[*dend..dend + 4]);
                        let cstart = dend + 4;
                        let cend = (u32::from_le_bytes(w) as usize)
                            .checked_mul(MEMBER_PATH_REC)
                            .and_then(|n| cstart.checked_add(n))
                            .filter(|e| *e <= body.len());
                        cend.and_then(|cend| {
                            body[cstart..cend]
                                .chunks_exact(MEMBER_PATH_REC)
                                .map(|r| {
                                    let mut cm = [0u8; 32];
                                    cm.copy_from_slice(&r[..32]);
                                    let mut o = [0u8; 8];
                                    o.copy_from_slice(&r[32..40]);
                                    usdmd_node::member_witness::RecordPath::from_bytes(&r[40..])
                                        .map(|p| (cm, u64::from_le_bytes(o), p))
                                })
                                .collect::<Option<MemberPaths>>()
                                .map(|paths| (paths, cend))
                        })
                    }
                    Some(_) => None,
                };
                // DB-329 step 3: version 8's slot-status tail, read in full or not at all; earlier versions read DECIDED at
                // their stored device slot (that device already wrote under it) with no pending add. An unknown kind byte
                // or a claim list that runs past the body reads the whole section ABSENT, never a guessed status.
                let slot: Option<(SlotStatus, u32, usize)> = match &member_paths {
                    None => None,
                    Some((_, pend_paths)) if version < 8 => Some((SlotStatus::Decided, 0, *pend_paths)),
                    Some((_, pend_paths)) => {
                        let at = *pend_paths;
                        let u32_at = |o: usize| -> Option<u32> {
                            let b = body.get(o..o.checked_add(4)?)?;
                            let mut w = [0u8; 4];
                            w.copy_from_slice(b);
                            Some(u32::from_le_bytes(w))
                        };
                        let status_end: Option<(SlotStatus, usize)> = match body.get(at).copied() {
                            Some(SLOT_DECIDED) => Some((SlotStatus::Decided, at + 1)),
                            Some(SLOT_UNDECIDED) => Some((SlotStatus::Undecided, at + 1)),
                            Some(SLOT_NEEDS_ADD) => Some((SlotStatus::NeedsAdd, at + 1)),
                            Some(kind @ (SLOT_CLAIMING | SLOT_CLAIMING_SELF)) => u32_at(at + 1).zip(u32_at(at + 5)).and_then(|(d, n)| {
                                let cstart = at + 9;
                                let cend = (n as usize).checked_mul(32).and_then(|k| cstart.checked_add(k))?;
                                let own_claims = body
                                    .get(cstart..cend)?
                                    .chunks_exact(32)
                                    .map(|c| {
                                        let mut cm = [0u8; 32];
                                        cm.copy_from_slice(c);
                                        cm
                                    })
                                    .collect();
                                if kind == SLOT_CLAIMING {
                                    return Some((SlotStatus::Claiming { d, own_claims, input_nf: None }, cend));
                                }
                                let nf: [u8; 32] = body.get(cend..cend.checked_add(32)?)?.try_into().ok()?;
                                Some((SlotStatus::Claiming { d, own_claims, input_nf: Some(nf) }, cend + 32))
                            }),
                            _ => None,
                        };
                        status_end.and_then(|(s, e)| u32_at(e).map(|pending_add| (s, pending_add, e + 4)))
                    }
                };
                // DB-223 Q2 §12d L: version 9's kept fixed-level tail, read in full or not at all; earlier versions keep
                // none (those notes re-capture levels 8..18 from the stream or the catch-up, as before). A digest that
                // does not decode reads the whole section ABSENT, never a shorter list.
                let fixed_levels: Option<FixedLevels> = match &slot {
                    None => None,
                    Some(_) if version < 9 => Some(Vec::new()),
                    Some((_, _, send)) => body.get(*send..send + 4).and_then(|w| {
                        let n = u32::from_le_bytes(w.try_into().ok()?) as usize;
                        let fstart = send + 4;
                        let fend = n.checked_mul(FIXED_LEVELS_REC).and_then(|k| fstart.checked_add(k))?;
                        body.get(fstart..fend)?
                            .chunks_exact(FIXED_LEVELS_REC)
                            .map(|r| {
                                let mut cm = [0u8; 32];
                                cm.copy_from_slice(&r[..32]);
                                let mut levels = [Digest4::default(); usdmd_node::member_witness::FIXED_LEVELS];
                                for (l, b) in levels.iter_mut().zip(r[32..].chunks_exact(usdmd_node::spend_frontier::DIGEST_LANE_BYTES)) {
                                    *l = usdmd_node::spend_frontier::digest_from_lane_bytes(b)?;
                                }
                                Some((cm, levels))
                            })
                            .collect::<Option<FixedLevels>>()
                    }),
                };
                if let (
                    true,
                    Some((pending_change, _)),
                    Some((in_flight_chg, _)),
                    Some((device_slot, _)),
                    Some((member_paths, _)),
                    Some((slot, pending_add, _)),
                    Some(fixed_levels),
                ) = (mend <= body.len(), pending, in_flight, device_slot, member_paths, slot, fixed_levels)
                {
                    let entries = body[start..end]
                        .chunks_exact(UNRESOLVED_REC)
                        .map(|c| {
                            let (mut nf, mut due) = ([0u8; 32], [0u8; 8]);
                            nf.copy_from_slice(&c[..32]);
                            due.copy_from_slice(&c[32..]);
                            (nf, u64::from_le_bytes(due))
                        })
                        .collect();
                    let proven_spent = body[pstart..pend]
                        .chunks_exact(32)
                        .map(|c| {
                            let mut nf = [0u8; 32];
                            nf.copy_from_slice(c);
                            nf
                        })
                        .collect();
                    let marked_at = body[mstart..mend]
                        .chunks_exact(MARKED_REC)
                        .map(|c| {
                            let (mut nf, mut h) = ([0u8; 32], [0u8; 8]);
                            nf.copy_from_slice(&c[..32]);
                            h.copy_from_slice(&c[32..]);
                            (nf, u64::from_le_bytes(h))
                        })
                        .collect();
                    unresolved = Some(Unresolved {
                        log_from,
                        entries,
                        proven_spent,
                        marked_at,
                        pending_change,
                        in_flight_chg,
                        device_slot,
                        member_paths,
                        slot,
                        pending_add,
                        fixed_levels,
                    });
                }
            }
        }
    }
    Some((cursor, records, spent, unresolved))
}

/// ⭐ ONE DEFINITION OF A PERSISTED SPENT RECORD'S WIDTH: `amount(8) + sk(DIGEST_LANES x 8)`. Derived
/// from the lane count so a digest widening can never again leave the reader and the writer disagreeing
/// about how many bytes a record occupies (§AG class 9 — measured as a PANIC on wallet restart).
const SPENT_REC: usize = 8 + 8 * usdm_decider::poseidon2_compress::DIGEST_LANES;

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip: what we save decrypts back byte-identical, and a WRONG scan key produces garbage (never the real
    /// records) — proving the file is confidential at rest (a disk thief learns nothing about which notes are ours).
    #[test]
    fn save_load_roundtrip_and_wrong_key_is_opaque() {
        let dir = std::env::temp_dir().join(format!("musdm-notestore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let key_id = [7u8; 32];
        let path = store_path(&dir, &key_id, "dfc6cf626c439134abcd");
        let dk = b"scan-decap-secret-A";
        let records = vec![(vec![1u8, 2, 3, 4, 5], 100u64), (vec![9u8; 40], 12345u64)];
        let spent = vec![(500u64, usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]))];
        save(&path, dk, 999, &records, &spent);

        let (cursor, got, got_spent) = load(&path, dk).expect("load");
        assert_eq!(cursor, 999);
        assert_eq!(got, records, "records must round-trip byte-identical under the right key");
        assert_eq!(got_spent, spent, "the spent exclusion set rides the same encrypted store");

        // A DIFFERENT scan key must NOT recover the real records (confidentiality at rest).
        let wrong = load(&path, b"scan-decap-secret-B");
        assert!(
            wrong.map(|(_, r, _)| r != records).unwrap_or(true),
            "a wrong scan key must never yield the real note records"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Scoping: a different key_id OR a different chain_id resolves to a DIFFERENT file (no cross-seed / cross-chain
    /// bleed — a re-genesis is a clean slate by construction).
    #[test]
    fn store_path_is_scoped_per_key_and_chain() {
        let d = Path::new("/tmp/x");
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(store_path(d, &a, "chain1"), store_path(d, &a, "chain2"));
        assert_ne!(store_path(d, &a, "chain1"), store_path(d, &b, "chain1"));
        assert_eq!(store_path(d, &a, "chain1"), store_path(d, &a, "chain1"));
    }

    /// DB-279 §7: the UNRESOLVED section round-trips beside the records and the spent set; a file written without it
    /// reads `Some(None)` (every loaded note due now), and a section cut short reads ABSENT, never as "none listed".
    /// The section this pins costs 14 B + 40 B per listed note in this wallet's own store: a restore that finds 1,000
    /// notes writes 14 + 40,000 B ≈ 40 KB once, and the steady state is 14 B. No history term: it is a want-set of
    /// this wallet's own restored notes that drains on each note's first chain answer, never f(chain height).
    /// O1-INFINITY-REVIEWED: the reads here are of THIS WALLET'S OWN encrypted store written a line above (the
    /// survivability-sanctioned self-custody file); its size is f(this wallet's own notes), and no node or chain
    /// authority is reconstructed from it. The test pins the parser, not a store.
    #[test]
    fn db279_the_unresolved_section_round_trips_and_a_short_one_reads_absent() {
        let dir = std::env::temp_dir().join(format!("musdm-notestore-db279-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = store_path(&dir, &[3u8; 32], "db279chain");
        let dk = b"scan-decap-secret-U";
        let records = vec![(vec![5u8; 48], 77u64)];
        let spent = vec![(9u64, usdm_decider::poseidon2_compress::lanes_of(&[4, 3, 2, 1]))];
        // DB-279 §7c: the retained spent verdicts ride the same section. cons: no history term. It costs 4 B + 32 B per
        // retained verdict, kept for OWNED notes only, so a wallet owning N notes holds at most 4 + 32·N B here
        // (1,000 owned notes → 32 KB, once): f(this wallet's own notes), with no term in chain height, blocks or the
        // chain's spent total, and each note's own record in the section above already outweighs its 32 B here.
        let u = Unresolved {
            log_from: 4_242,
            entries: vec![([1u8; 32], 0), ([2u8; 32], 9_000)],
            proven_spent: vec![[7u8; 32], [8u8; 32]],
            // DB-298: two unconfirmed own spends' marking heights. cons: no history term — a bounded want-set that
            // drains: 4 B + 40 B per UNCONFIRMED own spend, and an entry leaves once its spend is held (confirmed), so
            // a wallet with 3 sends in flight writes 124 B and a settled one writes 4 B.
            marked_at: vec![([5u8; 32], 1_000), ([6u8; 32], 1_096)],
            // DB-300: one remainder not yet carried, paired with the input its transaction spends. cons: no history
            // term — 4 B + 64 B per remainder of this wallet's own sends in flight; it drains as each one lands.
            pending_change: vec![([9u8; 32], [5u8; 32])],
            // DB-273 §15 R4: two accepted objects' `chg` indices still in flight. cons: no history term — 4 B + 40 B
            // per in-flight index of this wallet's own sends; it drains as each lands or is returned.
            in_flight_chg: vec![(12, [3u8; 32]), (13, [4u8; 32])],
            // DB-329 (C): a NON-ZERO device slot, so a reader that dropped it could not pass as the default 0.
            device_slot: 3,
            // DB-223 R-b3: two owned notes' record paths, one not folded yet (ordinal 0). cons: no history term — 4 B +
            // 553 B per OWNED note, leaving with the note: f(this wallet's own notes), no term in height or blocks.
            member_paths: vec![
                (
                    [0xA1; 32],
                    5,
                    usdmd_node::member_witness::RecordPath {
                        slot: 7,
                        siblings: std::array::from_fn(|l| usdm_decider::poseidon2_compress::lanes_of(&[l as u64 + 1, 2, 3, 4])),
                    },
                ),
                (
                    [0xA2; 32],
                    0,
                    usdmd_node::member_witness::RecordPath {
                        slot: 255,
                        siblings: std::array::from_fn(|l| usdm_decider::poseidon2_compress::lanes_of(&[9, l as u64, 7, 1])),
                    },
                ),
            ],
            // DB-329 step 3: a claim in flight with two own claim cms (a rebuilt claim), and a pending add, so a reader
            // that dropped either could not pass as the pre-v8 default. cons: no history term — 1 B + (a claim) 8 B + 32 B
            // per own claim cm (one, or a few after a dropped claim, cleared on its verdict) + 4 B: f(fixed constants).
            slot: SlotStatus::Claiming { d: 2, own_claims: vec![[0xC1; 32], [0xC2; 32]], input_nf: None },
            pending_add: 5,
            // DB-223 Q2 §12d L: two owned notes' kept levels 8..18. cons: no history term — 4 B + 736 B per OWNED note,
            // leaving with the note (`retain_notes`): f(this wallet's own notes), no term in height or blocks.
            fixed_levels: vec![
                ([0xA1; 32], std::array::from_fn(|l| usdm_decider::poseidon2_compress::lanes_of(&[l as u64 + 8, 0xF1]))),
                ([0xA2; 32], std::array::from_fn(|l| usdm_decider::poseidon2_compress::lanes_of(&[l as u64 + 8, 0xF2]))),
            ],
        };
        save_with_unresolved(&path, dk, 11, &records, &spent, &u);
        let (cursor, got, got_spent) = load(&path, dk).expect("load");
        assert_eq!((cursor, got, got_spent), (11, records.clone(), spent.clone()), "the older sections are unchanged");
        // O1-INFINITY-REVIEWED: reads back THIS TEST'S OWN wallet store written a line above: f(this wallet's own
        // notes and unconfirmed sends), never a node or chain authority reconstructed from local storage.
        assert_eq!(
            load_unresolved(&path, dk),
            Some(Some(u.clone())),
            "log_from, every (nf, due), every retained spent verdict and every marking height round-trip"
        );

        // TAMPER: the same body with its last byte cut. The reader must not report the surviving entries as complete.
        let raw = std::fs::read(&path).expect("read"); // O1-INFINITY-REVIEWED: this test's own wallet store (above)
        let mut body = raw[8..].to_vec();
        xor_keystream(&store_key(dk), &mut body);
        let whole = parse_body(&body).expect("the whole body parses").3;
        assert_eq!(whole, Some(u.clone()), "calibration: the untouched body carries the section");
        let cut = parse_body(&body[..body.len() - 1]).expect("the older sections still parse").3;
        assert_eq!(cut, None, "a truncated section reads ABSENT (every note due now), never as the entries it kept");
        // DB-300: a cut into the pending tail (a record or its count), DB-298 one that also removes a whole marking or
        // the marking count, and (§7c) one that also removes the held tail or a held verdict, all read absent.
        // DB-329 step 3, version 8: the section's last tail — kind(1) ‖ d(4) ‖ n(4) ‖ n × cm(32) ‖ pending add(4).
        let status_tail = 1 + 4 + 4 + 32 * 2 + 4;
        let paths_tail = 4 + MEMBER_PATH_REC * u.member_paths.len(); // DB-223 R-b3, version 7
        let slot_tail = 4usize; // DB-329 (C), version 6: the device slot
        let in_flight_tail = 4 + IN_FLIGHT_REC * u.in_flight_chg.len();
        let pending_tail = 4 + PENDING_REC * u.pending_change.len();
        let marked_tail = 4 + 40 * u.marked_at.len();
        let held_tail = 4 + 32 * u.proven_spent.len();
        // DB-223 Q2 §12d L (version 9): the kept fixed-level tail is the section's LAST tail. A cut into it (a digest, a
        // record, the count) reads ABSENT, never a shorter list; version 8 (no such tail) reads with no kept levels.
        let fixed_tail = 4 + FIXED_LEVELS_REC * u.fixed_levels.len();
        for drop in [1usize, 64, FIXED_LEVELS_REC, fixed_tail - 4, fixed_tail - 1, fixed_tail] {
            let cut = parse_body(&body[..body.len() - drop]).expect("the older sections still parse").3;
            assert_eq!(cut, None, "a kept-level tail missing its last {drop} B reads ABSENT");
        }
        let mut overclaim = body.clone();
        let fcount_at = body.len() - fixed_tail;
        overclaim[fcount_at..fcount_at + 4].copy_from_slice(&((u.fixed_levels.len() + 1) as u32).to_le_bytes());
        assert_eq!(parse_body(&overclaim).expect("the older sections parse").3, None, "an over-claimed count reads ABSENT");
        let u8_ = Unresolved { fixed_levels: Vec::new(), ..u.clone() };
        let tag_at9 = body.len()
            - fixed_tail
            - status_tail
            - paths_tail
            - slot_tail
            - in_flight_tail
            - pending_tail
            - marked_tail
            - held_tail
            - (14 + 40 * u.entries.len());
        assert_eq!(body[tag_at9..tag_at9 + 2], UNRESOLVED_TAG, "calibration: the v9 tag sits where the layout says");
        let mut body = body[..body.len() - fixed_tail].to_vec();
        body[tag_at9 + 1] = 8;
        assert_eq!(
            parse_body(&body).expect("the older sections parse").3,
            Some(u8_.clone()),
            "a version-8 section reads every field it carries, with NO kept levels (they re-capture as before)"
        );
        let body = body;
        // DB-329 step 3 (version 8): the slot-status tail is the section's LAST tail of a v8 body. A cut into it (the
        // pending add, a claim cm, the claim count, the claimed slot, the kind byte) reads ABSENT, never a guessed status.
        // cons: none — the v8 tail is 1 B (kind) + 4 B (pending add), plus 8 B + 32 B per own claim cm only while a claim
        // is in flight (1 cm normally, 2 here): 5 B steady, 77 B in this fixture, per WALLET STORE, rewritten in place by
        // the save that already rewrites the section. f(fixed constants): no term in notes, sends, blocks or height.
        for drop in [4usize, 5, 4 + 32, 4 + 64, 4 + 64 + 4, 4 + 64 + 8, status_tail] {
            let cut = parse_body(&body[..body.len() - drop]).expect("the older sections still parse").3;
            assert_eq!(cut, None, "a slot-status tail missing its last {drop} B reads ABSENT");
        }
        let kind_at = body.len() - status_tail;
        assert_eq!(body[kind_at], SLOT_CLAIMING, "calibration: the kind byte sits where the layout says");
        let mut unknown_kind = body.clone();
        unknown_kind[kind_at] = 9;
        assert_eq!(parse_body(&unknown_kind).expect("the older sections parse").3, None, "an unknown slot kind reads ABSENT");
        // Every status round-trips, each with its own pending add. cons: none — this rewrites the ONE temp store file above
        // in place, 4 times (~1.3 KB each, same path), and the test removes the directory at its end: f(fixed constants).
        for (slot, pending_add) in [
            (SlotStatus::Decided, 0u32),
            (SlotStatus::Undecided, 0),
            (SlotStatus::NeedsAdd, 3),
            (SlotStatus::Claiming { d: 7, own_claims: Vec::new(), input_nf: None }, 0),
            // DB-329 §7i: a self-claim keeps its input nullifier across a restart.
            (SlotStatus::Claiming { d: 9, own_claims: vec![[0xC4; 32]], input_nf: Some([0xD9; 32]) }, 2),
        ] {
            let each = Unresolved { slot, pending_add, ..u.clone() };
            save_with_unresolved(&path, dk, 11, &records, &spent, &each);
            assert_eq!(load_unresolved(&path, dk), Some(Some(each.clone())), "{:?} round-trips", each.slot);
        }
        // Version 7 (no slot-status tail) still reads: every field it carries, DECIDED at its device slot, no pending add.
        // Every older layout below is checked on this v7 prefix, so the pre-v8 reading is pinned at every version.
        let u7 = Unresolved { slot: SlotStatus::Decided, pending_add: 0, ..u8_.clone() };
        let tag_at8 = body.len()
            - status_tail
            - paths_tail
            - slot_tail
            - in_flight_tail
            - pending_tail
            - marked_tail
            - held_tail
            - (14 + 40 * u.entries.len());
        assert_eq!(body[tag_at8..tag_at8 + 2], UNRESOLVED_TAG_V8, "calibration: the v8 tag sits where the layout says");
        let mut body = body[..body.len() - status_tail].to_vec();
        body[tag_at8 + 1] = 7;
        assert_eq!(
            parse_body(&body).expect("the older sections parse").3,
            Some(u7.clone()),
            "a version-7 section reads every field it carries, as DECIDED at its stored slot with no pending add"
        );
        let body = body;
        // DB-273 §15 R4 / DB-329 (C) / DB-223 R-b3: a cut into the member-path, slot or in-flight tail (a record or its
        // count) reads absent too.
        let t = paths_tail;
        for drop in [
            1usize,
            MEMBER_PATH_REC,
            t - 4,
            t,
            t + slot_tail,
            t + slot_tail + in_flight_tail - 4,
            t + slot_tail + in_flight_tail,
            t + slot_tail + in_flight_tail + pending_tail - 4,
            t + slot_tail + in_flight_tail + pending_tail,
            t + slot_tail + in_flight_tail + pending_tail + 40,
            t + slot_tail + in_flight_tail + pending_tail + marked_tail,
            t + slot_tail + in_flight_tail + pending_tail + marked_tail + 32,
            t + slot_tail + in_flight_tail + pending_tail + marked_tail + held_tail,
        ] {
            let cut = parse_body(&body[..body.len() - drop]).expect("the older sections still parse").3;
            assert_eq!(cut, None, "a section missing its last {drop} B reads ABSENT, never a shorter list");
        }
        let tag_at = body.len()
            - paths_tail
            - slot_tail
            - in_flight_tail
            - pending_tail
            - marked_tail
            - held_tail
            - (14 + 40 * u.entries.len());
        assert_eq!(tag_at, tag_at8, "calibration: the v7 prefix keeps the section's tag where the v8 body has it");
        assert_eq!(body[tag_at..tag_at + 2], UNRESOLVED_TAG_V7, "calibration: the section's tag sits where the layout says");
        // TAMPER (R-b3): a member-path record whose path bytes cannot be a path is never read as a shorter list. The
        // slot byte is free, so the tamper is a length the reader must refuse: the count claims one record more.
        let mut overclaim = body.clone();
        let count_at = body.len() - paths_tail;
        overclaim[count_at..count_at + 4].copy_from_slice(&((u.member_paths.len() + 1) as u32).to_le_bytes());
        assert_eq!(parse_body(&overclaim).expect("the older sections parse").3, None, "an over-claimed path count reads ABSENT");
        // Version 6 (DB-329 (C), no member-path tail) still reads: every field it carries, and NO member paths.
        let mut v6 = body[..body.len() - paths_tail].to_vec();
        v6[tag_at + 1] = 6;
        assert_eq!(
            parse_body(&v6).expect("the older sections parse").3,
            Some(Unresolved { member_paths: Vec::new(), ..u7.clone() }),
            "a version-6 section reads every field it carries, with no member paths (they re-capture at arrival)"
        );
        // Version 5 (DB-273 §15 R4, no device-slot tail) still reads: every field it carries, as device slot 0.
        let mut v5 = body[..body.len() - paths_tail - slot_tail].to_vec();
        v5[tag_at + 1] = 5;
        assert_eq!(
            parse_body(&v5).expect("the older sections parse").3,
            Some(Unresolved { device_slot: 0, member_paths: Vec::new(), ..u7.clone() }),
            "a version-5 section reads every field it carries, as device slot 0 (the unchanged `chg` domain)"
        );
        // Version 4 (DB-300, no in-flight tail) still reads: every field it carries, and NO in-flight indices.
        let mut v4 = body[..body.len() - paths_tail - slot_tail - in_flight_tail].to_vec();
        v4[tag_at + 1] = 4;
        assert_eq!(
            parse_body(&v4).expect("the older sections parse").3,
            Some(Unresolved { in_flight_chg: Vec::new(), device_slot: 0, member_paths: Vec::new(), ..u7.clone() }),
            "a version-4 section reads every field it carries, with no in-flight indices"
        );
        // Version 3 (DB-298, no pending tail) still reads: every field it carries, and NO pending remainders.
        let mut v3 = body[..body.len() - paths_tail - slot_tail - in_flight_tail - pending_tail].to_vec();
        v3[tag_at + 1] = 3;
        let read_v3 = parse_body(&v3).expect("the older sections parse").3;
        assert_eq!(
            read_v3,
            Some(Unresolved {
                pending_change: Vec::new(),
                in_flight_chg: Vec::new(),
                device_slot: 0,
                member_paths: Vec::new(),
                ..u7.clone()
            }),
            "a version-3 section reads every field it carries, with no pending remainders"
        );
        // Earlier versions read ABSENT on purpose (v1 lost spent answers; v2 carries no marking heights), so every
        // loaded note is asked again and a marking waits for this process's first node tip. Built in memory: the body
        // cut after its listed notes, then re-tagged as version 1 and as version 2.
        let listed_end = body.len() - paths_tail - slot_tail - in_flight_tail - pending_tail - marked_tail - held_tail;
        let mut old = body[..listed_end].to_vec();
        for version in [1u8, 2] {
            old[tag_at + 1] = version;
            assert_eq!(parse_body(&old).expect("the older sections parse").3, None, "a version-{version} section reads ABSENT");
        }

        save(&path, dk, 11, &records, &spent);
        assert_eq!(load_unresolved(&path, dk), Some(None), "a file without the section says so; it is not 'none'");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⛔ DB-311 — THE FORMAT VERSION DECIDES WHAT A RECORD'S u64 MEANS. Version 2 (every writer since DB-311) holds a
    /// position or the sentinel and round-trips EXACTLY. Version 1 held a stamped address, a placement height or a
    /// Refresh's 0 in the same field: it loads its notes, spent set and cursor as before, and its field decodes to the
    /// stamped address (2^40 <= v < u64::MAX) or the sentinel, both ways at the boundary.
    /// cons: none — DB-311 adds 0 bytes to the store: the 8-byte magic it already had carries the version, and the
    /// per-record u64 is the same u64; f(fixed constants), no per-item write added, no history term.
    /// O1-INFINITY-REVIEWED: writes this wallet's own encrypted store (six records) only to read it back; O(own notes).
    #[test]
    fn db311_a_version_one_field_is_a_position_only_when_it_can_be_one() {
        let dir = std::env::temp_dir().join(format!("musdm-notestore-db311-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = store_path(&dir, &[0x31u8; 32], "db311chain");
        let dk = b"scan-decap-secret-db311";
        const ADDR: u64 = 46_209_351_854_700_264;
        let floor = LEGACY_ADDRESS_FLOOR;
        let fields = [217u64, 0, ADDR, u64::MAX, floor - 1, floor];
        let records: Vec<(Vec<u8>, u64)> = fields.iter().enumerate().map(|(i, f)| (vec![i as u8; 40], *f)).collect();
        let spent = vec![(500u64, usdm_decider::poseidon2_compress::lanes_of(&[1, 2, 3, 4]))];

        save(&path, dk, 777, &records, &spent);
        let (cursor, got, got_spent) = load(&path, dk).expect("a version-2 store loads");
        assert_eq!((cursor, &got, &got_spent), (777, &records, &spent), "version 2 round-trips byte-identical");

        save_v1(&path, dk, 777, &records, &spent);
        let (cursor, got, got_spent) = load(&path, dk).expect("a version-1 store still loads");
        assert_eq!((cursor, &got_spent), (777, &spent), "a version-1 store keeps its cursor and spent set");
        assert_eq!(
            got.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            records.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>(),
            "and every note it held"
        );
        assert_eq!(
            got.iter().map(|(_, p)| *p).collect::<Vec<_>>(),
            vec![u64::MAX, u64::MAX, ADDR, u64::MAX, u64::MAX, floor],
            "a version-1 height and zero read unplaced; a stamped address keeps its place; the floor is exact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
