// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐⭐⭐ THE LEVEL AGGREGATE, STAGE A AT BLOCK SCALE (lane agg, docs/LEVEL-AGGREGATE-SPEC-20261115.md §10) — the two
//! modes of the carrier DOORS that let a block carry a payment's carriers as CORES while its query openings are proven,
//! for every aggregated payment of the block at once, by the block's OPENINGS TABLES (`stir_group_air`, the bound batch
//! engine). A peer then holds ≈ the cores (~12 KB a carrier) instead of the full carriers (~90 KB), and the producer's
//! prover — not every node's Tor intake — pays for the openings: settled throughput rises with the producers.
//!
//! WHY AT THE DOORS. ~40 verify families reach WHIR through exactly two bodies (`committed_air`'s committed and chained
//! doors). A mode the node sets around its ONE existing admit gate reaches every one of them, so an aggregated payment is
//! judged by the SAME checks as a full one (§9.6 question 6 by construction: there is no second gate to fall behind),
//! and only the WHIR query openings move into the block's table.
//!
//! * [`Mode::Record`] — the HOLDER's mode: the node verifies a FULL carrier exactly as today and the door records what
//!   the block needs of it: its core (the proof with every query opening removed, plus one claim per query group), the
//!   groups' statements (root, drawn positions, fold weights, γ powers, claim) and the openings themselves.
//! * [`Mode::Core`] — the PEER's mode: the door accepts ONLY a core ([`CoreCarrier`]), verifies it with the unchanged
//!   verifier taking each group's contribution from the core's claims (`WhirVerifier::with_group_claims`), and records
//!   the groups' statements — which the block's tables must prove, or the block is refused.
//! * `Off` (the default) — today: a door verifies a full carrier; a core is refused (it carries no openings, so the
//!   unchanged verifier fails its query count) and so is a [`CoreCarrier`] encoding (not a bundle).
//!
//! SOUNDNESS (C4 stage A's argument, lane c4 §14.1d–e, kept): every fold the table proves is of a leaf authenticated to
//! its round's root at a position the PEER's own verifier drew from the core's transcript; a lied claim survives only if
//! the table's own transcript-drawn combination is a root of the difference (≤ rows / 2^124). The table runs on the BOUND
//! batch engine (never the direct light decider, which does not bind its opened row: A-F55) and its pins run that
//! engine's solved-row forger beside an honest control (`stir_group_air`).
//!
//! PROTECTED BY (AI RESISTANT): (a) a proof every node checks — the core verify and the table verify, both native.
//! SCALE: per block O(aggregated payments) group statements; per table ≤ 2^[`TABLE_MAX_ROWS_LOG`] rows (the two-adicity
//! cap, `committed_air.rs:202`, holds at 2^(rows + 9) stacked cells); nothing grows with height or with bonded nodes.
//! PRIVACY: a core is the carrier minus its openings (hiding carriers: no witness in either), and the cores ride where
//! full bodies ride today (`Block::tx_bodies`, the gossip envelope), so a peer sees what it sees today and less.

use crate::hiding_decider::Ea4;
use crate::stir_group_air::{GroupStatement, QueryOpening};
use core::cell::{Cell, RefCell};
use serde::{Deserialize, Serialize};

/// The door modes (see the module doc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Record,
    Core,
}

/// The wire form of a carrier in an aggregated payment: its core and one claim per query group (every round, then the
/// final group; an empty group's claim is zero). The leading tag gives the form ONE encoding that no full bundle has.
#[derive(Clone, Serialize, Deserialize)]
pub struct CoreCarrier<B> {
    pub tag: [u8; 4],
    pub core: B,
    pub claims: Vec<Ea4>,
}

/// The tag every [`CoreCarrier`] leads with.
pub const CORE_TAG: [u8; 4] = *b"AGG1";

/// What a door recorded of ONE carrier, in verification order.
#[derive(Clone)]
pub struct Recorded {
    /// `blake3` of the bytes the door was handed (Record: the full carrier; Core: the core carrier).
    pub digest: [u8; 32],
    /// Record mode: the [`CoreCarrier`] bytes that replace the full carrier on the block. Core mode: empty.
    pub core: Vec<u8>,
    /// The carrier's query groups as statements for the block's openings table (empty groups skipped).
    pub groups: Vec<GroupStatement>,
    /// Record mode: each group's openings (the producer lays them in the table). Core mode: empty.
    pub openings: Vec<Vec<QueryOpening>>,
}

thread_local! {
    static MODE: Cell<Mode> = const { Cell::new(Mode::Off) };
    static LOG: RefCell<Vec<Recorded>> = const { RefCell::new(Vec::new()) };
}

/// The mode the doors on THIS thread are in. A door reached from another thread (a parallel sub-verify) sees `Off` and
/// therefore refuses a core: a missing mode can only refuse, never admit.
#[must_use]
pub fn mode() -> Mode {
    MODE.with(Cell::get)
}

pub(crate) fn push(r: Recorded) {
    LOG.with(|l| l.borrow_mut().push(r));
}

fn run<R>(m: Mode, f: impl FnOnce() -> R) -> (R, Vec<Recorded>) {
    let prev = MODE.with(|c| c.replace(m));
    let prev_log = LOG.with(|l| core::mem::take(&mut *l.borrow_mut()));
    let out = f();
    let log = LOG.with(|l| core::mem::replace(&mut *l.borrow_mut(), prev_log));
    MODE.with(|c| c.set(prev));
    (out, log)
}

/// Run `f` (one node-side verification of a FULL transaction) with the doors in [`Mode::Record`].
pub fn record<R>(f: impl FnOnce() -> R) -> (R, Vec<Recorded>) {
    run(Mode::Record, f)
}

/// Run `f` (one node-side verification of an AGGREGATED transaction) with the doors in [`Mode::Core`].
pub fn core<R>(f: impl FnOnce() -> R) -> (R, Vec<Recorded>) {
    run(Mode::Core, f)
}

/// log2 of the largest openings table a block lays: 2^16 rows × 258 columns = 2^25 stacked cells, inside the
/// two-adicity cap (`vars + start_rate − first_fold ≤ 24` at the light parameters' rate 1/4 and first fold 4: ≤ 26).
/// MEASURED cost to replace: lane c4 §14.1f proved 2^14 rows in 5.3 s at 4 threads; 2^16 is the size P2 measures.
pub const TABLE_MAX_ROWS_LOG: usize = 16;

/// The canonical split of a block's groups (in block order) into tables: greedy, never splitting a group, each table
/// within `2^max_log` rows. The SAME function lays and checks, so prover and peer cannot disagree on the split. `None`
/// when one group alone exceeds a table (fail-closed: no such carrier class exists at the live parameters).
#[must_use]
pub fn split(groups: &[GroupStatement], max_log: usize) -> Option<Vec<core::ops::Range<usize>>> {
    let cap = 1usize << max_log;
    let mut out = Vec::new();
    let (mut start, mut used) = (0usize, 0usize);
    for (i, g) in groups.iter().enumerate() {
        let w = g.work_rows();
        if w > cap {
            return None;
        }
        if used + w > cap {
            out.push(start..i);
            start = i;
            used = 0;
        }
        used += w;
    }
    if start < groups.len() {
        out.push(start..groups.len());
    }
    Some(out)
}

/// PROVE a block's openings tables over every aggregated carrier's groups (block order).
#[must_use]
pub fn prove_tables(groups: &[GroupStatement], openings: &[Vec<QueryOpening>], max_log: usize) -> Option<Vec<Vec<u8>>> {
    if groups.len() != openings.len() || groups.is_empty() {
        return None;
    }
    split(groups, max_log)?
        .into_iter()
        .map(|r| crate::stir_group_air::prove_table(crate::opening_auth_air::SEED, &groups[r.clone()], &openings[r]))
        .collect()
}

/// VERIFY a block's openings tables against the groups the PEER's own core verifications recorded (block order).
/// NEW-DOOR CHECKLIST (§9.6), the aggregated slot's openings: (1) PoW — the header's, not this door's; (2) proof — each
/// table's bound light proof and its public columns, verified here, against groups this peer derived itself; (3) value —
/// none moves here (the cores' own verifies are the spend's conservation, unchanged); (4) replay — the tables bind their
/// groups' statement (`table_bind`), and the spends' tags are the nullifier set's; (5) bounded work — the split is a
/// function of the groups, each table ≤ 2^max_log rows, the count of tables = the split's; (6) parity — the full door's
/// WHIR opening check, query by query, is what each table row proves.
#[must_use]
pub fn verify_tables(groups: &[GroupStatement], tables: &[Vec<u8>], max_log: usize) -> bool {
    if groups.is_empty() {
        return tables.is_empty();
    }
    let Some(parts) = split(groups, max_log) else { return false };
    parts.len() == tables.len()
        && parts
            .into_iter()
            .zip(tables)
            .all(|(r, t)| crate::stir_group_air::verify_table(crate::opening_auth_air::SEED, &groups[r], t))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hiding_decider::Fa4;
    use p3_field::PrimeCharacteristicRing;

    /// One payment's four carriers, real, each with the production door that verifies it — the same calls the node's
    /// admit gate makes (member path: chained; spend-or-decoy: chained; membership: committed; spend: committed).
    struct Payment {
        carriers: Vec<Vec<u8>>,
        verify: Vec<Box<dyn Fn(&[u8]) -> bool>>,
        names: [&'static str; 4],
    }

    fn payment(salt: u64) -> Payment {
        use crate::member_path_gate::{prove_member_path_carrier, verify_member_path_carrier, MEMBER_PATH_DEPTH};
        let d = |i: u64| crate::poseidon2_compress::lanes_of(&[i, i + 1, i + 2, i + 3]);
        let siblings: Vec<_> = (0..MEMBER_PATH_DEPTH as u64).map(|i| d(salt + 100 + 4 * i)).collect();
        let dirs: Vec<bool> = (0..MEMBER_PATH_DEPTH).map(|i| ((salt ^ 0x5A3C_96E1) >> (i % 32)) & 1 == 1).collect();
        let (m, t) = prove_member_path_carrier(d(salt + 1), &siblings, &dirs, d(salt + 2), d(salt + 3), d(salt + 4)).expect("member proves");
        let bound = crate::poseidon2_compress::lanes_of(&[salt + 7, 8, 9, 10]);
        let tags: Vec<_> = (0..8u64).map(|s| crate::nf_sparse_air::cover_tag_native(bound, s)).collect();
        let wit = vec![crate::nf_sparse_air::TagWitness::Decoy; 8];
        let s = crate::nf_sparse_air::prove_spend_or_decoy_bytes(bound, &tags, &wit).expect("spend_or_decoy proves");
        let msib: Vec<_> = (0..32u64).map(|i| crate::poseidon2_compress::lanes_of(&[salt + i * 4 + 1, i * 4 + 2, i * 4 + 3, i * 4 + 4])).collect();
        let mdirs: Vec<bool> = (0..32u64).map(|i| ((salt ^ 0x0A5C_3F17) >> (i % 32)) & 1 == 1).collect();
        let w = crate::whir_rec_block::MembershipWitness { leaf: crate::poseidon2_compress::lanes_of(&[salt + 7, 8, 9, 10]), siblings: msib, dirs: mdirs };
        let (c, root) = crate::whir_rec_block::prove_membership_carrier_bytes(&w).expect("membership proves");
        // the send's `blob`: the note-spend carrier (the class `note_transition::carrier_verifies_at` verifies)
        use crate::whir_rec_block::{prove_note_spend_bytes, test_clue_digest, verify_note_spend_bytes, NoteSpendExtras, PROTOCOL_FEE_ATOMIC};
        let sk = crate::poseidon2_compress::lanes_of(&[0xC10C + salt, 12, 13, 14]);
        let sw = crate::whir_rec_block::SpendValidityWitness {
            value_in: 800 + salt + PROTOCOL_FEE_ATOMIC,
            owner: crate::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + salt,
            fee: PROTOCOL_FEE_ATOMIC,
            lc_blind: crate::poseidon2_compress::lanes_of(&[0x363, salt, 2, 3]),
            out0_value: 750 + salt,
            out0_opening: crate::poseidon2_compress::lanes_of(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        };
        let cd = test_clue_digest(salt);
        let (sp, cms, nf, lc, tag1) = prove_note_spend_bytes(&sw, &NoteSpendExtras::plain(1), cd, sw.lc_blind, 0).expect("the note spend proves");
        Payment {
            carriers: vec![sp, m, s, c],
            verify: vec![
                Box::new(move |b: &[u8]| verify_note_spend_bytes(b, cms[0], cms[1], nf, lc, cd, tag1, PROTOCOL_FEE_ATOMIC, 1)),
                Box::new(move |b: &[u8]| verify_member_path_carrier(b, &t)),
                Box::new(move |b: &[u8]| crate::nf_sparse_air::verify_spend_or_decoy_bytes(b, &tags)),
                Box::new(move |b: &[u8]| crate::whir_rec_block::verify_membership_carrier_bytes(b, root, 32)),
            ],
            names: ["note_spend (blob)", "member_carrier", "spend_or_decoy", "membership_carrier"],
        }
    }

    /// ⭐⭐⭐ LEVEL AGGREGATE STAGE A AT BLOCK SCALE — two payments' four carriers each, through the PRODUCTION doors:
    /// the holder's Record pass verifies every full carrier and yields its core; the peer's Core pass verifies every core
    /// through the SAME door calls and derives the SAME group statements itself; the block's openings tables prove those
    /// statements and verify. Refused, each on its own: a core verified outside Core mode; a full carrier handed to Core
    /// mode; one claim moved inside one core; a core with its openings left in; a table verified for another block's
    /// groups; a dropped table; a table byte flipped. Prints the bytes a peer holds against the full carriers.
    #[test]
    fn agg_a_blocks_payments_ride_as_cores_and_one_set_of_tables_and_every_lie_is_refused() {
        let pays = [payment(0), payment(1_000)];
        // HOLDER: Record pass (the production verify, unchanged verdict)
        let mut cores: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut groups = Vec::new();
        let mut openings = Vec::new();
        let (mut full_b, mut core_b) = (0usize, 0usize);
        for p in &pays {
            let mut pc = Vec::new();
            for (bytes, v) in p.carriers.iter().zip(&p.verify) {
                let (ok, log) = record(|| v(bytes));
                assert!(ok, "⛔ the holder's Record pass refused an honest full carrier");
                let [r] = log.as_slice() else { panic!("⛔ one door call must record exactly one carrier, got {}", log.len()) };
                assert_eq!(r.digest, *blake3::hash(bytes).as_bytes(), "the record names the bytes it was handed");
                full_b += bytes.len();
                core_b += r.core.len();
                let rows: usize = r.groups.iter().map(GroupStatement::work_rows).sum();
                eprintln!("[agg-p0] {}: full {} B · core {} B · {} groups · {rows} table rows", p.names[pc.len()], bytes.len(), r.core.len(), r.groups.len());
                pc.push(r.core.clone());
                groups.extend(r.groups.iter().cloned());
                openings.extend(r.openings.iter().cloned());
            }
            cores.push(pc);
        }
        let t0 = std::time::Instant::now();
        let tables = prove_tables(&groups, &openings, TABLE_MAX_ROWS_LOG).expect("⛔ the holder's tables did not prove");
        let prove_ms = t0.elapsed().as_millis();
        let table_b: usize = tables.iter().map(Vec::len).sum();
        // PEER: Core pass through the same door calls
        let mut peer_groups = Vec::new();
        for (p, pc) in pays.iter().zip(&cores) {
            for (core, v) in pc.iter().zip(&p.verify) {
                assert!(!v(core), "⛔ a core verified OUTSIDE Core mode");
                let (ok, log) = super::core(|| v(core));
                assert!(ok, "⛔ the peer's Core pass refused an honest core");
                let [r] = log.as_slice() else { panic!("one record per door call") };
                peer_groups.extend(r.groups.iter().cloned());
            }
            let (ok, _) = super::core(|| p.verify[0](&p.carriers[0]));
            assert!(!ok, "⛔ Core mode accepted a FULL carrier (one encoding: a core or nothing)");
        }
        assert_eq!(peer_groups.len(), groups.len(), "the peer derives the holder's group count");
        for (a, b) in peer_groups.iter().zip(&groups) {
            assert!(a.root == b.root && a.positions == b.positions && a.claim == b.claim && a.weights == b.weights, "⛔ the peer's own statements must be the holder's");
        }
        let t1 = std::time::Instant::now();
        assert!(verify_tables(&peer_groups, &tables, TABLE_MAX_ROWS_LOG), "⛔ the peer refused the honest tables");
        let verify_ms = t1.elapsed().as_millis();
        eprintln!(
            "[agg-a] {} payments × 4 carriers: full {full_b} B → cores {core_b} B + {} table(s) {table_b} B = {:.1} KB a payment (from {:.1}); {} groups, {} rows; prove {prove_ms} ms, verify {verify_ms} ms, {} thread(s)",
            pays.len(),
            tables.len(),
            (core_b + table_b) as f64 / pays.len() as f64 / 1024.0,
            full_b as f64 / pays.len() as f64 / 1024.0,
            groups.len(),
            crate::stir_group_air::table_rows(&groups),
            rayon::current_num_threads()
        );
        // LIES
        // one claim moved inside one core: the core no longer verifies, or its groups no longer match the tables
        // slot 1 is the member leg (a chained core); slot 0, the note spend, is a committed one
        let mut cc: CoreCarrier<crate::committed_air::ChainedAirBundle> = postcard::from_bytes(&cores[0][1]).expect("a chained core");
        cc.claims[0] += Ea4::ONE;
        let moved = postcard::to_allocvec(&cc).expect("encodes");
        let (ok, log) = super::core(|| pays[0].verify[1](&moved));
        let refused_at_core = !ok;
        let refused_at_table = ok && {
            let mut g2 = peer_groups.clone();
            // the member leg's groups follow the note spend's in the block's order
            let start: usize = cores[0][..1].iter().map(|c| super::core(|| pays[0].verify[0](c)).1[0].groups.len()).sum();
            let n1 = log[0].groups.len();
            g2.splice(start..start + n1, log[0].groups.iter().cloned());
            !verify_tables(&g2, &tables, TABLE_MAX_ROWS_LOG)
        };
        assert!(refused_at_core || refused_at_table, "⛔ a core whose claim moved was accepted end to end");
        // a core with its openings left in (the full bundle under the core tag)
        let full: crate::committed_air::ChainedAirBundle = postcard::from_bytes(&pays[0].carriers[1]).expect("full bundle");
        let fake = postcard::to_allocvec(&CoreCarrier { tag: CORE_TAG, core: full, claims: cc.claims.clone() }).expect("encodes");
        assert!(!super::core(|| pays[0].verify[1](&fake)).0, "⛔ a 'core' still carrying its openings was accepted");
        // a table for another block's groups
        let other = payment(5_000);
        let (_, olog) = record(|| other.verify[0](&other.carriers[0]));
        let mut og = peer_groups.clone();
        og[0] = olog[0].groups[0].clone();
        assert!(!verify_tables(&og, &tables, TABLE_MAX_ROWS_LOG), "⛔ tables verified for groups the block does not state");
        // a dropped table / a flipped byte
        if tables.len() > 1 {
            assert!(!verify_tables(&peer_groups, &tables[1..], TABLE_MAX_ROWS_LOG), "⛔ a dropped table verified");
        }
        let mut flipped = tables.clone();
        let mid = flipped[0].len() / 2;
        flipped[0][mid] ^= 1;
        assert!(!verify_tables(&peer_groups, &flipped, TABLE_MAX_ROWS_LOG), "⛔ a flipped table byte verified");
        // a split the peer did not derive: the same groups under a smaller cap need more tables
        assert!(!verify_tables(&peer_groups, &tables, 8), "⛔ tables verified under another split than the canonical one");
        let _ = Fa4::ZERO;
    }
}
