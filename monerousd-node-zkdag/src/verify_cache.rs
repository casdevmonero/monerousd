// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ THE VERIFIED-TRANSITION CACHE — Bitcoin Core's script-execution cache (`validation.cpp` `g_scriptExecutionCache`,
//! `sigcache.cpp` `CSignatureCache`) for a block's transition proofs.
//!
//! A block's note, member, cover and bond transitions are verified when the block is admitted (the ingest door, the
//! graft) and AGAIN at its fold (`Node::lane_justified_parts`, `Node::member_anchors_at_fold`) — the same proof bytes
//! against the same public inputs, up to three times per node. MEASURED (night/link23-sample.txt, 20 s of a fast
//! journey): `fold_canonical_records` was 43 % of the simulator's node-step samples, 35 % in `spends_proven_with_members`,
//! the WHIR verify of these four transitions most of it. Bitcoin answers the identical shape — a script checked at
//! mempool admission and again at block connection — with a bounded cache of inputs ALREADY VERIFIED VALID.
//!
//! THE RULES (each is what makes a hit return exactly what the verifier would):
//! - **only a success is cached** — a refused input is verified in full every time it is presented;
//! - **the key binds every input byte the verifier reads** — a per-verifier domain tag, the wire shape, the proof, the
//!   stated tuples or tags, the block's output-notes root and (note class) its filed OLI tags, each length-prefixed, hashed
//!   with BLAKE3 (256-bit); one byte that differs is a different key and a full derive + verify;
//! - **the verifiers are pure** — their answer is a function of those bytes and the compiled-in decider constants only, so
//!   a hit skips the bind derivation and the rows digest (Poseidon2) as well as the WHIR verify.
//!
//! §9.6 door questions (a cache in front of five existing doors — it admits nothing they would refuse):
//! 1 PoW — unchanged, not on this path. 2 Proof — the decider's verify runs on every miss; a hit is a prior TRUE verdict
//! for byte-identical inputs. 3 Conservation — every stated tuple byte is in the key, and the caller builds its admissions
//! from those same parsed bytes, so no admission differs from the verified one. 4 Replay — a replay of the exact bytes is the same statement and gets the same verdict;
//! the spent SET still refuses a double spend downstream. 5 Bounded work — one BLAKE3 pass over the inputs per call; the
//! cache holds at most [`CAPACITY`] 32-byte keys. 6 Parity — every caller of the five verifiers goes through
//! [`verified`], so the ingest, graft and fold doors judge identically.
//!
//! O1-FOOTPRINT-REVIEWED: at most `CAPACITY` keys (40,960 × 32 B ≈ 1.25 MiB + set overhead), FIFO-evicted; never a function of
//! height. A key evicted before its block folds only costs that fold one full verify.
//! cons: ≤ ~3.1 MiB resident at the DAG-width ceiling (+0.6 MiB for the SAT-bond weld slot) (≈ 0.3 MiB at the default width's working set); one BLAKE3 pass
//! over each transition's proof bytes (tens of µs) on every call, a hit saving the WHIR verify (milliseconds).

use std::collections::{HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};

/// How many verified keys the cache holds: every transition of every block between its admission and its fold — the
/// fold depth (blue score) × the DAG-width ceiling (blocks per blue-score step at most) × the five verifiers (four block transitions + a carried SAT bond's weld).
pub const CAPACITY: usize =
    crate::params::RECORD_FOLD_DEPTH_DEFAULT as usize * crate::params::DAG_WIDTH_CEILING * Verifier::COUNT;

/// Which verifier a key belongs to — part of the key, so one verifier's TRUE can never answer another's question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verifier {
    NoteTransition,
    MemberTransition,
    CoverTransition,
    BondTransition,
    /// A carried SAT bond's welded validity carrier (`SatBondTx::weld_is_authorised`): judged at the objects step of every
    /// lane justification and fold of its block, the same carrier against the same stated outputs each time.
    SatBondWeld,
}

impl Verifier {
    const COUNT: usize = 5;
    fn tag(self) -> &'static [u8] {
        match self {
            Verifier::NoteTransition => b"monerousd/verified/note-transition/v1",
            Verifier::MemberTransition => b"monerousd/verified/member-transition/v1",
            Verifier::CoverTransition => b"monerousd/verified/cover-transition/v1",
            Verifier::BondTransition => b"monerousd/verified/bond-transition/v1",
            Verifier::SatBondWeld => b"monerousd/verified/sat-bond-weld/v1",
        }
    }
}

struct Cache {
    keys: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

fn cache() -> &'static Mutex<Cache> {
    static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(Cache { keys: HashSet::new(), order: VecDeque::new() }))
}

#[cfg(test)]
thread_local! {
    /// TEST: how many times THIS thread's calls ran the verifier (a miss), so a pin can show a hit skips it.
    static RUNS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// TEST: the number of verifier runs (misses) on this thread so far.
#[cfg(test)]
pub fn runs_on_this_thread() -> u64 {
    RUNS.with(std::cell::Cell::get)
}

/// The key of one verification: the verifier's tag, the transition's wire shape and EVERY input byte the verifier reads —
/// the proof, the stated tuples (or tags), the block's output-notes root and, for the note class, the block's filed OLI
/// tags — each length-prefixed. Everything the verifier derives (binds, rows digest, roots) is a function of these.
#[must_use]
pub fn key(which: Verifier, shape: [u32; 8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    let tag = which.tag();
    h.update(&(tag.len() as u64).to_le_bytes());
    h.update(tag);
    for w in shape {
        h.update(&w.to_le_bytes());
    }
    h.update(&(parts.len() as u64).to_le_bytes());
    for p in parts {
        h.update(&(p.len() as u64).to_le_bytes());
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// The key of one verification on a door that is ARMED or not for the bound template double (`note_transition::
/// TemplateClass`): an armed door's verdict is keyed apart, so a TRUE it cached for the double's bytes is never read by a
/// real door in the same process (the cache is process-wide; one test process may hold armed and real meshes at once).
/// Unarmed, this is [`key`] exactly.
#[must_use]
pub fn key_on_door(which: Verifier, shape: [u32; 8], parts: &[&[u8]], bound: bool) -> [u8; 32] {
    if !bound {
        return key(which, shape, parts);
    }
    let mut armed: Vec<&[u8]> = parts.to_vec();
    armed.push(b"monerousd/verified/bound-template-double/v1");
    key(which, shape, &armed)
}

/// Run `verify` unless this exact statement (`key`) already verified TRUE; cache a TRUE answer, never a FALSE one.
pub fn verified(key: [u8; 32], verify: impl FnOnce() -> bool) -> bool {
    if cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner).keys.contains(&key) {
        return true;
    }
    #[cfg(test)]
    RUNS.with(|r| r.set(r.get() + 1));
    let ok = verify();
    if ok {
        let mut c = cache().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if c.keys.insert(key) {
            c.order.push_back(key);
            while c.order.len() > CAPACITY {
                if let Some(old) = c.order.pop_front() {
                    c.keys.remove(&old);
                }
            }
        }
    }
    ok
}
