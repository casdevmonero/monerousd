// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE WALLET'S ABSENCE CARRIER (A-F114 phase 3 step 3, lane speed5, 2026-11-22; docs/SPENT-SET-GROWTH-DEEP-AUDIT-20261122.md).
//!
//! User 2026-11-22: *"the memory shouldnt be growing with time"*. A node that holds no spent set needs the spender to prove
//! its note made in this chain and its nullifier unspent since, against the node's canonical tag chain. This keeps ONE
//! carrier for the wallet's notes, built from the universal family (`usdm_agg::absence_u`: one merge program, one claim):
//! * the wallet's notes live in a FIXED-LENGTH list of [`WALLET_SLOTS`] slots; an unused slot is `absence_u::empty_entry`;
//! * every record it follows (`/canon/records`, the same public stream for every caller) is proven as a LEAF and merged into
//!   the ONE running carrier, so the wallet holds one proof of the family's one size at any history length;
//! * a NEW note takes an empty slot (`prove_reshape`) before the record that makes it;
//! * a note this wallet SPENT leaves its slot (`prove_reshape`, back to empty) before the record that carries the spend, so
//!   that record's leaf never meets a created entry's nullifier among its tags;
//! * a SEND proves the spend WRAPPER (`prove_spend`), which exposes only the nullifier, binder, leaf commitment and end.
//! A wallet holding more unspent notes than [`WALLET_SLOTS`] keeps a further list (another carrier over the same records).
//! COST: one leaf and one merge a record followed (MEASURED in usdm-agg u1/u2: 2^15 rows each, ~341 KB a proof, ~2–3 s
//! each on this machine), one reshape per note received or spent; RAM is the family's fixed tables (absence_u's COST).
//! AI RESISTANT: (a) — every value the node accepts is a proof it checks; a forged carrier proves nothing.

// A-F114: the carrier itself lives in the node crate (`usdmd_node::canon_carrier_core`), one implementation for the
// wallet and for a node's custody cover carrier.
pub use usdmd_node::canon_carrier_core::{CanonCarrier, WALLET_SLOTS};
use usdm_agg::absence_ssa::Entry;
use usdm_agg::absence_u::empty_entry;

/// The wallet's carriers, in process (saved beside the wallet by [`save`], loaded by [`load`]): one LIST of
/// [`WALLET_SLOTS`] slots per sixteen notes held, every list following the same records (one chain end, one next index).
/// A list starts when every list is full, at the lists' shared end, which lies before the making record of any note
/// waiting to join (the follower never runs ahead of the scan); a list whose notes have all left is dropped (one is kept).
/// COST: a leaf and a merge a record for EACH list (MEASURED u3: ~341 KB, 2^15 rows each), so a wallet holding n notes
/// pays ⌈n/16⌉ of them a record; the bytes held are ⌈n/16⌉ carriers, a term in the notes the wallet HOLDS, never in height.
static CANON: std::sync::Mutex<Option<Vec<CanonCarrier>>> = std::sync::Mutex::new(None);

/// ⛔ A REGISTRATION IS NEVER DROPPED (lane livewedge, 2026-11-26). A note registered while no carrier stands (before the first
/// start, or after the carrier had to start again below every span it can undo) waits HERE and joins the first carrier that
/// starts ([`drain_prestart`], run by every start path); [`standing`] reads it as pending, so a send waits for its span (bounded
/// by `CANON_SPAN_WAIT`) instead of being refused "in no carrier list". Lock order: `CANON`, then this. SCALE: the notes this
/// wallet holds, never height. MEASURED why: testnet gate 20261126-030735, 7 wallets refused every send for good.
static PRESTART: std::sync::Mutex<Vec<Entry>> = std::sync::Mutex::new(Vec::new());

/// Move every note waiting in [`PRESTART`] into the carrier, once one stands. Every start path calls it.
fn drain_prestart() {
    if CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().is_none_or(Vec::is_empty) {
        return;
    }
    let waiting = std::mem::take(&mut *PRESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
    for e in waiting {
        register_entry(e);
    }
}

type Digest4 = usdmd_node::spend_frontier::Digest4;

fn entry_of(leaf: Digest4, nf: Digest4) -> Entry {
    (usdmd_node::canon_chain::tag_lanes(&usdmd_node::spend_frontier::leaf_to_cm_bytes(nf)), usdmd_node::canon_chain::to_lanes(&leaf))
}

fn free_slots(c: &CanonCarrier) -> usize {
    let empty = (0..WALLET_SLOTS).filter(|&j| c.slots[j] == empty_entry(j as u64)).count();
    empty.saturating_sub(c.pending.len())
}

/// ⭐ A-F114 — START the carrier if this process holds none, absorbing nothing: at the chain's own start (index 0, the genesis
/// end) while the node holds record 0, else right after the oldest span-closing record the node holds. `Ok(true)` when it
/// started one now. ⛔ MEASURED 2026-11-22 (testnet gate on 24189da6: `pay`, `change` FAIL, "this note is not in a carrier's
/// list yet"): `register` drops a note while no carrier exists, and `follow` started the carrier and absorbed in one call, so
/// a fresh process's notes were registered before the carrier existed (dropped) and their records absorbed after (missed).
/// Start, then register, then follow: a note always joins a list before the record that makes it is absorbed.
pub fn start(agent: &ureq::Agent, base: &str) -> Result<bool, String> {
    if CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().is_some_and(|l| !l.is_empty()) {
        return Ok(false);
    }
    let resp: serde_json::Value = agent
        .post(&format!("{base}/canon/records"))
        .send_json(serde_json::json!({ "from": 0, "count": 64 }))
        .map_err(|e| format!("the node's records did not answer: {e}"))?
        .into_json()
        .map_err(|e| format!("the node's records are not JSON: {e}"))?;
    let oldest = resp["oldest"].as_i64().unwrap_or(-1);
    let carrier = if oldest <= 0 {
        let genesis = parse_digest(resp["genesis"].as_str().unwrap_or(""))?;
        CanonCarrier::starting_at(usdmd_node::canon_chain::to_lanes(&genesis), 0)
    } else {
        let span = usdmd_node::canon_carrier_core::SPAN as u64;
        let recs = resp["records"].as_array().cloned().unwrap_or_default();
        let Some(first) = recs.iter().find(|r| r["i"].as_u64().is_some_and(|i| (i + 1) % span == 0)) else {
            return Ok(false); // no span closes in the node's first page yet: the next pass starts it
        };
        let end = parse_digest(first["end"].as_str().unwrap_or(""))?;
        let i = first["i"].as_u64().ok_or("a record without an index")?;
        CanonCarrier::starting_at(usdmd_node::canon_chain::to_lanes(&end), i + 1)
    };
    let mut g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if g.as_ref().is_some_and(|l| !l.is_empty()) {
        return Ok(false); // another thread started it meanwhile
    }
    *g = Some(vec![carrier]);
    drop(g);
    drain_prestart();
    Ok(true)
}

/// Register a note this wallet received (its leaf and nullifier digest): it waits in the first list with a free slot (a new
/// list when all are full) and takes that slot before the record that makes it. A note already held or waiting is not
/// added twice.
pub fn register(leaf: Digest4, nf: Digest4) {
    register_entry(entry_of(leaf, nf));
}

fn register_entry(e: Entry) {
    let mut g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let lists = match g.as_mut() {
        Some(l) if !l.is_empty() => l,
        _ => {
            let mut w = PRESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if !w.contains(&e) {
                w.push(e);
            }
            return;
        }
    };
    if lists.iter().any(|c| c.slots.contains(&e) || c.pending.contains(&e)) {
        return;
    }
    if let Some(c) = lists.iter_mut().find(|c| free_slots(c) > 0) {
        c.pending.push(e);
        return;
    }
    let Some(first) = lists.first() else { return };
    // a new list starts where the first stands, its span being gathered included, so every list absorbs one record stream
    let mut c = CanonCarrier::starting_at(first.end, first.next_index).with_span(first.span);
    c.buffer = first.buffer.clone();
    c.pending.push(e);
    lists.push(c);
}

/// ⭐ FOLLOW the node's canonical records (`/canon/records`, the same public stream for every caller) into every list, from
/// the record they expect. Not yet started, the carrier starts at the oldest record the node's window holds (its end is the
/// start). Every record's chain end is recomputed here and checked against the one the node served, so a node serving
/// another chain is refused. Returns how many records were absorbed. A carrier BEHIND the node's window cannot follow
/// (`Err`): an archive of older records is the open piece (audit, phase 3).
/// ⛔ IT NEVER RUNS AHEAD OF THE SCAN: a note joins a list only BEFORE the record that makes it, and the wallet learns a
/// note is its own by scanning that very record, so a record is absorbed only when its block's blue score is below
/// `scanned_below` (the scan's cursor: every block below it is scanned and its notes registered).
pub fn follow(agent: &ureq::Agent, base: &str, scanned_below: u64) -> Result<u64, String> {
    let mut absorbed = 0u64;
    loop {
        drain_prestart(); // a carrier this loop just started takes every note waiting for one
        let from = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner).as_ref().and_then(|l| l.first()).map_or(0, CanonCarrier::expects);
        let resp: serde_json::Value = agent
            .post(&format!("{base}/canon/records"))
            // ⛔ A-F121: one record BEHIND the carrier's position, so its end is checked before anything is absorbed
            .send_json(serde_json::json!({ "from": from.saturating_sub(1), "count": 64 }))
            .map_err(|e| format!("the node's records did not answer: {e}"))?
            .into_json()
            .map_err(|e| format!("the node's records are not JSON: {e}"))?;
        let recs = resp["records"].as_array().cloned().unwrap_or_default();
        let oldest = resp["oldest"].as_i64().unwrap_or(-1);
        let mut g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.as_ref().is_none_or(Vec::is_empty) {
            // start right after a record that CLOSES a global span (`(i + 1) % SPAN == 0`), the oldest such the window holds and
            // the scan has read: its end is the start. ⭐ A-F114 — spans are aligned to the chain, so every carrier's ends fall
            // on global multiples of SPAN and a DeFi batch's slots can name ONE end (A-F26's class: covers and real slots
            // must not partition by end; audit 13:30)
            let span = usdmd_node::canon_carrier_core::SPAN as u64;
            // ⛔ A-F114 (MEASURED 2026-11-22, the testnet gate on af833a45: `pay` and `change` FAIL, "the absence carrier is not
            // started"): a carrier starts only after a span closes, and a note made before the carrier's start can never be
            // proven absent — so on a fresh chain nothing could be sent, and a note made in the chain's first span (genesis
            // funds) never could. While the node still holds the chain's FIRST record (`oldest` 0) or no record yet, the
            // carrier starts at the chain's own start: index 0, the genesis end, which is span-aligned by construction.
            if oldest <= 0 {
                let genesis = parse_digest(resp["genesis"].as_str().unwrap_or(""))?;
                *g = Some(vec![CanonCarrier::starting_at(usdmd_node::canon_chain::to_lanes(&genesis), 0)]);
                drop(g);
                continue;
            }
            let closer = recs.iter().find(|r| {
                r["i"].as_u64().is_some_and(|i| (i + 1) % span == 0) && r["score"].as_u64().is_some_and(|sc| sc < scanned_below)
            });
            let Some(first) = closer else {
                // no span closes in this page yet: read on from its last record (nothing is absorbed before an aligned start)
                if recs.is_empty() || recs.iter().any(|r| r["score"].as_u64().is_none_or(|sc| sc >= scanned_below)) {
                    return Ok(absorbed);
                }
                let last = recs.last().and_then(|r| r["i"].as_u64()).ok_or("a record without an index")?;
                drop(g);
                let _ = last;
                return Ok(absorbed);
            };
            let end = parse_digest(first["end"].as_str().unwrap_or(""))?;
            let i = first["i"].as_u64().ok_or("a record without an index")?;
            *g = Some(vec![CanonCarrier::starting_at(usdmd_node::canon_chain::to_lanes(&end), i + 1)]);
            drop(g);
            continue;
        }
        let lists = g.as_mut().ok_or("no carrier")?;
        let next = lists[0].next_index;
        if oldest >= 0 && (next as i64) < oldest {
            return Err(format!("this carrier expects record {next} but the node's window starts at {oldest}: an archive is needed"));
        }
        // ⛔ A-F121 / A-F141 (ported to main 2026-11-26 from the Solstice lane's b6344ffc) — A REORG OF THE CANONICAL CHAIN UNDER THIS
        // CARRIER IS UNDONE, NEVER FOLLOWED. MEASURED (testnet gate 20261126-002408 and -005844, restart): after a restart the node's
        // fold re-folded 7 and 12 records and its canonical ring rewound; the carrier kept the old ends, so its wrapper named an end
        // the node's window no longer held and every send was refused MEMBERSHIP_PROOF_MISSING (82 and 56 times). The node's end of
        // the record just behind this carrier must be the carrier's own (`open_end`, stepped from its proven end, never the node's
        // word): a mismatch inside the open span drops the buffer (re-read from the span's start); one at a span close undoes that
        // span's proof (`rewind_prev`), and the next pass checks again, so a rewind across several closes is undone one span at a
        // time. The node rewinds at most REWIND_RETAIN records, which `REWIND_SPANS` saved states cover.
        // AI RESISTANT: (b) code — a node serving a forged end only makes the carrier re-read; nothing is proven on its word.
        // SCALE: one record more per pass, a constant.
        if from > 0 {
            if let Some(r) = recs.iter().find(|r| r["i"].as_u64() == Some(from - 1)) {
                let node_end = usdmd_node::canon_chain::to_lanes(&parse_digest(r["end"].as_str().unwrap_or(""))?);
                if lists[0].open_end() != Some(node_end) {
                    if lists[0].buffer.is_empty() {
                        // every list undoes together (never `all`, which stops at the first list that cannot)
                        let undone = lists.iter_mut().map(CanonCarrier::rewind_prev).fold(true, |a, b| a && b);
                        if !undone {
                            // ⛔ NOTHING HALTS (lane livewedge, 2026-11-26): below every saved state the carrier STARTS AGAIN from
                            // the node's window, the one general start path, and keeps every note it held; it never refuses every
                            // later send for good. MEASURED why (testnet gate 20261126-030735, 7 wallets): the error was returned
                            // on every pass, so no note was ever spendable again on that wallet. A note made before the new start
                            // waits its bounded `CANON_SPAN_WAIT` and says so; on a young chain the start is genesis and all re-prove.
                            let held: Vec<Entry> = lists
                                .iter()
                                .flat_map(|c| {
                                    (0..c.slots.len()).filter(|&j| c.slots[j] != empty_entry(j as u64)).map(|j| c.slots[j]).chain(c.pending.iter().copied())
                                })
                                .collect();
                            eprintln!(
                                "[canon] the chain reorganized below every span this carrier can undo (record {}): the carrier starts again from the node's window, keeping {} note(s)",
                                from - 1,
                                held.len()
                            );
                            *g = None;
                            {
                                let mut w = PRESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                                for e in held {
                                    if !w.contains(&e) {
                                        w.push(e);
                                    }
                                }
                            }
                            drop(g);
                            continue;
                        }
                        eprintln!("[canon] the chain reorganized across a span close: the carrier undid that span and re-follows from record {}", lists[0].next_index);
                    } else {
                        for c in lists.iter_mut() {
                            c.buffer.clear();
                        }
                        eprintln!("[canon] the chain reorganized inside the open span: the carrier re-reads it from record {}", lists[0].next_index);
                    }
                    drop(g);
                    continue;
                }
            }
        }
        let mut moved = false;
        for r in &recs {
            let i = r["i"].as_u64().ok_or("a record without an index")?;
            if i < lists[0].expects() {
                continue;
            }
            if r["score"].as_u64().is_none_or(|sc| sc >= scanned_below) {
                return Ok(absorbed); // the scan has not read this record's block yet: its notes may be unregistered
            }
            let tags = parse_list32(r["tags"].as_str().unwrap_or(""))?;
            let leaves: Vec<Digest4> = parse_list32(r["leaves"].as_str().unwrap_or(""))?
                .iter()
                .map(|b| usdmd_node::canon_chain::digest_of_bytes(b).ok_or("a non-canonical leaf"))
                .collect::<Result<_, _>>()?;
            let rec = usdmd_node::canon_chain::record(&tags, &leaves, i);
            let want = usdmd_node::canon_chain::to_lanes(&parse_digest(r["end"].as_str().unwrap_or(""))?);
            for c in lists.iter_mut() {
                c.absorb(i, &rec)?;
                // a carrier's end moves when it closes a span: checked against the node's end of that span's last record
                if c.buffer.is_empty() && c.end != want {
                    return Err(format!("record {i}'s chain end is not the one this carrier computes: the node serves another chain"));
                }
            }
            absorbed += 1;
            moved = true;
        }
        // a list whose notes have all left (and none waits) is dropped; the first is kept, so the lists keep their end
        let mut keep_first = true;
        lists.retain(|c| {
            let k = keep_first || !c.pending.is_empty() || (0..WALLET_SLOTS).any(|j| c.slots[j] != empty_entry(j as u64));
            keep_first = false;
            k
        });
        if !moved {
            return Ok(absorbed);
        }
    }
}

fn parse_list32(h: &str) -> Result<Vec<[u8; 32]>, String> {
    let b = hex::decode(h).map_err(|e| format!("not hex: {e}"))?;
    if b.len() % 32 != 0 {
        return Err("a list that is not whole 32-byte items".into());
    }
    Ok(b.chunks(32).map(|c| c.try_into().expect("32 bytes")).collect())
}

fn parse_digest(h: &str) -> Result<Digest4, String> {
    let b: [u8; 32] = hex::decode(h).map_err(|e| format!("not hex: {e}"))?.try_into().map_err(|_| "not 32 bytes")?;
    usdmd_node::canon_chain::digest_of_bytes(&b).ok_or_else(|| "a non-canonical chain value".to_string())
}

/// ⭐ THE SEND'S ABSENCE WITNESS (under `canon_chain::CANON_LIVE`): the spend wrapper of the note `leaf` (nullifier `nf`),
/// from the list that holds it, bound to the spend's own DB-363 blind `lc_blind` (the one its member leg and validity
/// carrier commit with), carried in the one `NfAbsenceWitness`'s proof bytes as `postcard(Vec<CanonAbsence>)`, hex for
/// `nullifier_absence_hex`.
pub fn absence_hex(nf: Digest4, leaf: Digest4, lc_blind: Digest4) -> Result<String, String> {
    let ca = vec![wrapper_of(nf, leaf, lc_blind)?];
    let witness = usdmd_node::nf_sparse::NfAbsenceWitness { proof: postcard::to_allocvec(&ca).map_err(|e| e.to_string())?, ..Default::default() };
    postcard::to_allocvec(&vec![witness]).map(hex::encode).map_err(|e| e.to_string())
}

/// ⭐ AN OBJECT'S ABSENCE WRAPPERS (under `canon_chain::CANON_LIVE`): one per note leg the object spends, in the order the
/// node reads its legs (`chain_object::object_tag_roles`), as `postcard(Vec<CanonAbsence>)` hex for an object route's
/// `canon_absence_hex` (the node carries it as the object's one `NfAbsenceWitness`'s proof bytes). Built from the running
/// carrier right before the post, so each ends at a chain value the node's window holds.
pub fn object_wrappers_hex(legs: &[(Digest4, Digest4, Digest4)]) -> Result<String, String> {
    let ca = legs.iter().map(|(nf, leaf, b)| wrapper_of(*nf, *leaf, *b)).collect::<Result<Vec<_>, String>>()?;
    postcard::to_allocvec(&ca).map(hex::encode).map_err(|e| e.to_string())
}

/// Where a note stands in the carrier: in a slot (spendable now), pending (its making record's span has not closed yet: it
/// joins a slot when that span is absorbed, at most `SPAN` records on), or in no list at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    Slot,
    Pending,
    Absent,
}

#[must_use]
pub fn standing(nf: Digest4, leaf: Digest4) -> Standing {
    let e = entry_of(leaf, nf);
    let g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let waiting = PRESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner).contains(&e);
    let lists = g.as_deref().unwrap_or(&[]);
    if lists.iter().any(|c| c.slots.contains(&e)) {
        Standing::Slot
    } else if waiting || lists.iter().any(|c| c.pending.contains(&e)) {
        Standing::Pending
    } else {
        Standing::Absent
    }
}

/// The carrier's shape as counts: `(lists, slots held, notes pending, the next record index)`. A diagnostic only: no leaf,
/// nullifier or amount.
#[must_use]
pub fn census() -> (usize, usize, usize, u64) {
    let g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(lists) = g.as_ref() else { return (0, 0, 0, 0) };
    let held = lists.iter().map(|c| (0..WALLET_SLOTS).filter(|&j| c.slots[j] != empty_entry(j as u64)).count()).sum();
    let pending = lists.iter().map(|c| c.pending.len()).sum();
    (lists.len(), held, pending, lists.first().map_or(0, |c| c.next_index))
}

/// The spend wrapper of the note `leaf` (nullifier `nf`) from the list that holds it, bound to the spend's `lc_blind`.
fn wrapper_of(nf: Digest4, leaf: Digest4, lc_blind: Digest4) -> Result<usdmd_node::nf_sparse::CanonAbsence, String> {
    let e = entry_of(leaf, nf);
    let g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let lists = g.as_ref().ok_or("the absence carrier is not started (follow the node's records first)")?;
    let Some((c, j)) = lists.iter().find_map(|c| c.slots.iter().position(|s| *s == e).map(|j| (c, j))) else {
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts and one flag only — no leaf, nullifier or amount.
        let pending = lists.iter().any(|c| c.pending.contains(&e));
        eprintln!(
            "[canon] lookup failed: the note is {} — {} list(s), next record index {}",
            if pending { "PENDING (its making record not absorbed yet)" } else { "in no list at all (never registered, or registered under another digest)" },
            lists.len(),
            lists.first().map_or(0, |c| c.next_index)
        );
        return Err("this note is not in a carrier's list yet".into());
    };
    let (w, end) = c.spend(j, usdmd_node::canon_chain::to_lanes(&nf), usdmd_node::canon_chain::to_lanes(&lc_blind))?;
    Ok(usdmd_node::nf_sparse::CanonAbsence { proof: w, end: usdmd_node::canon_chain::of_lanes(&end) })
}

/// Save the carriers beside the wallet (one file, rewritten whole).
pub fn save(path: &std::path::Path) -> Result<(), String> {
    let g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(lists) = g.as_ref() else { return Ok(()) };
    let bytes = postcard::to_allocvec(lists).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// Forget the carriers in process (another wallet was opened).
pub fn reset() {
    let mut g = CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    *g = None;
    PRESTART.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clear();
}

/// Load the carriers saved beside the wallet, if any.
pub fn load(path: &std::path::Path) {
    if let Ok(b) = std::fs::read(path) {
        if let Ok(lists) = postcard::from_bytes::<Vec<CanonCarrier>>(&b) {
            *CANON.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(lists);
        }
    }
}

// TWO-PARTY-REVIEWED: the carrier's second party is the node's door (`canon_absence_refusal`); this module's pin checks the
// wallet-built wrapper with the door's own verifier, and the cross-node run is the batch proof (audit phase 5).
#[cfg(test)]
mod tests {
    use usdm_agg::absence_ssa::{Lanes, Record};
    use super::*;
    use p3_field::PrimeCharacteristicRing;
    use usdm_decider::hiding_decider::Fa4;

    fn lanes(seed: u64) -> Lanes {
        core::array::from_fn(|i| Fa4::from_u32(((seed.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64 * 7919 + 1)) % 2_130_706_433) as u32))
    }
    fn rec(i: u64) -> Record {
        let items = |s: u64| (0..usdm_agg::absence_ssa::CHUNK_TAGS as u64).map(|t| lanes(s * 1000 + t + 1)).collect::<Vec<_>>();
        Record { tags: vec![(items(i), [Fa4::ZERO; 8])], outs: vec![(items(i + 500), usdm_agg::absence_ssa::end_aux(i))] }
    }

    /// ⭐ C1: the wallet follows five records, receives two notes (records 2 and 4), each spends by a wrapper the door
    /// accepts at the carrier's end; a note not yet made refuses to spend; a skipped record is refused; and the record that
    /// carries a spent note's nullifier is followed after its slot leaves the list.
    #[test]
    fn c1_the_wallet_follows_records_and_spends_each_note() {
        // one note a list (the carrier's shape), here over one-record spans so each step is visible
        let mut rs: Vec<Record> = (1..=6).map(rec).collect();
        let a = (lanes(71), rs[1].outs[0].0[3]);
        let b = (lanes(72), rs[3].outs[0].0[8]);
        rs[5].tags[0].0[0] = a.0; // record 6 carries A's spend
        let mut ca = CanonCarrier::starting_at(lanes(1), 1).with_span(1);
        let mut cb = CanonCarrier::starting_at(lanes(1), 1).with_span(1);
        ca.pending = vec![a];
        cb.pending = vec![b];
        for (i, r) in rs.iter().take(5).enumerate() {
            ca.absorb(i as u64 + 1, r).expect("each record follows");
            cb.absorb(i as u64 + 1, r).expect("each record follows");
            if i == 1 {
                assert!(cb.spend(0, lanes(40), lanes(41)).is_err(), "B is not made yet");
            }
        }
        for (j, (c, (nf, leaf))) in [(&ca, a), (&cb, b)].into_iter().enumerate() {
            let (binder, blind) = (lanes(40 + j as u64), lanes(50 + j as u64));
            let (w, end) = c.spend(0, binder, blind).expect("the note spends");
            let lc = usdm_agg::absence_ssa::leaf_commit(&leaf, &binder, &blind);
            assert!(usdm_agg::absence_u::verify_spend(&w, (1, 1, 1, 1), &nf, &binder, &lc, &end), "the door accepts note {j}'s spend");
        }
        ca.absorb(6, &rs[5]).expect("the record carrying A's spend follows once A's slot has left");
        assert!(!ca.slots.contains(&a), "A left the list");
        assert!(ca.absorb(9, &rec(9)).is_err(), "a skipped record is refused");
    }

    /// ⭐ A-F114 — C2: a carrier over TWO-record spans gathers, proves at the span's close, and spends its note after it.
    #[test]
    fn c2_a_carrier_proves_a_span_at_its_close_and_spends_after_it() {
        let rs: Vec<Record> = (1..=4).map(rec).collect();
        let a = (lanes(73), rs[0].outs[0].0[2]);
        let mut c = CanonCarrier::starting_at(lanes(1), 1).with_span(2);
        c.pending = vec![a];
        c.absorb(1, &rs[0]).expect("gathered");
        assert!(c.carrier.is_none() && c.expects() == 2, "the span is gathered, not proven");
        assert!(c.spend(0, lanes(40), lanes(41)).is_err(), "a note is not spendable before its span closes");
        c.absorb(2, &rs[1]).expect("the span closes");
        assert!(c.buffer.is_empty() && c.next_index == 3, "the span proved");
        let (binder, blind) = (lanes(40), lanes(50));
        let (w, end) = c.spend(0, binder, blind).expect("the note spends after its span");
        let lc = usdm_agg::absence_ssa::leaf_commit(&a.1, &binder, &blind);
        assert!(usdm_agg::absence_u::verify_spend(&w, (1, 1, 1, 2), &a.0, &binder, &lc, &end), "the door accepts the spend");
        assert!(!usdm_agg::absence_u::verify_spend(&w, usdmd_node::canon_chain::SPEND_SHAPE, &a.0, &binder, &lc, &end), "a test shape is not the shape the node admits");
    }
}
