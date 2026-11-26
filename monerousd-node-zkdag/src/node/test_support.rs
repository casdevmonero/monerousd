// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! test_support — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// ⭐ THE BUNDLE A REAL NODE SERVES, FOR A PIN (lane af58, 2026-11-15, the join class). A joiner adopts only what passes the join
    /// door (`join_proof::verify_join`: the anchor's level array, its links, `VOUCHERS` vouching headers above a frozen anchor), and a
    /// node serves exactly that through `serve_join_bundle` (the frozen bundles of `maybe_freeze_join_bundle`). The pins of the
    /// DSYNC class served `build_sync_bundle` instead — a DRAFT with an empty join proof — which the door rightly refuses
    /// (`AnchorArray`, `WeightAboveEstimate`): MEASURED on main a91aa906, node::pins::db271_… red at the door-registry audit, and
    /// the AnchorArray family red since 11/10. This grows THIS node's own chain, one block at a time, until the production path
    /// has a bundle its own door accepts, and returns it as the wire answer a peer would receive. Nothing about the door changes.
    /// Blocks are stamped at the chain's OWN target spacing: MEASURED 2026-11-16 (lane af58), a 1 s stamp against the derived
    /// ~5.3 s target (A-F60) made the DAA raise the work every window, and two pins spent 410 CPU-minutes in
    /// `PqPouwHasher::hash` without reaching a frozen bundle. At the target the work stays where the chain started.
    pub(crate) fn serve_production_bundle_for_test(&mut self, mut ts: u64, tag: &str) -> crate::protocol::WireMsg {
        let step = self.params().target_spacing_ms.max(1);
        for k in 0..256u64 {
            if let Some(wire) = self.serve_join_bundle() {
                return crate::protocol::WireMsg::SyncResponse(wire);
            }
            ts = ts.saturating_add(step);
            self.produce(ts, Hash32::hash(format!("{tag}-serve-{k}").as_bytes()), Hash32::hash(b"serve-production-bundle"))
                .expect("the serving node grows its own chain");
        }
        panic!("no production bundle became servable within 256 blocks: the freeze path did not reach a bundle its own join door accepts");
    }

    /// ⛔ THE ONE WAY A TEST GETS A BUNDLE TO HAND A JOINER (census S-DRAFT-ADOPT, scratchpad/secure.py; user 2026-11-26: "make sure
    /// the fixtures can never fall behind our code again and update automatically"): the bundle this node SERVES, grown from its
    /// own tip at the chain's own spacing until one is servable. A tamper test edits a field of THIS bundle, so its refusal is
    /// the door's verdict on the field it changed, never `AnchorArray` on a draft (a refusal that could not fail).
    pub(crate) fn served_bundle_for_test(&mut self) -> crate::sync::SyncBundle {
        let ts = self.selected_tip().and_then(|t| self.relay.dag().get(&t).map(|n| n.header.timestamp)).unwrap_or(0);
        self.production_bundle_for_test(ts, "served-fixture")
    }

    /// The same production bundle, decoded, for a pin that hands it to `instant_sync` or edits one field of it.
    pub(crate) fn production_bundle_for_test(&mut self, ts: u64, tag: &str) -> crate::sync::SyncBundle {
        let crate::protocol::WireMsg::SyncResponse(wire) = self.serve_production_bundle_for_test(ts, tag) else { unreachable!() };
        crate::sync::SyncBundle::from_wire(&wire).expect("the production bundle decodes")
    }

    /// DB-402 census diagnostic (lane stable 2026-10-30): the finality tally by key — the fold cursor, the open tally's
    /// `(height, voter)` rows, and the deferred votes' keys — so two nodes whose `finality` field differs name the vote.
    pub(crate) fn finality_keys_for_test(&self) -> String {
        let s = |v: &[u8; 32]| crate::hash::Hash32(*v).to_hex()[..6].to_string();
        let open: Vec<String> = self.finality.open_keys_for_test().iter().map(|(h, v, b)| format!("{h}:{}→{}", s(v), &b.to_hex()[..6])).collect();
        let deferred: Vec<String> = self.deferred_votes.keys().map(|(h, v)| format!("{h}:{}", s(v))).collect();
        format!("cursor {} · finalized {} · open {open:?} · deferred {deferred:?}", self.fold_cursor_blue(), self.finality.finalized_height())
    }

    /// DB-402 census diagnostic (lane stable 2026-10-30): WHERE this node's retained history starts, per store — the DAG,
    /// the record rows (in ordinal space), the per-ordinal indexes, the ladder spans and the certified prefix. Two nodes on
    /// one chain whose lines differ name the store whose retention floor is not a function of the chain.
    pub(crate) fn retention_shape_for_test(&self) -> String {
        let dag = self.relay.dag();
        let min_score = dag.dag_recent_view(1 << 20).iter().map(|r| r.2).min();
        let ords = |m: &std::collections::HashMap<u64, u64>| {
            let mut v: Vec<u64> = m.keys().filter_map(|a| self.da_ord_mem.get(a).copied()).collect();
            v.sort_unstable();
            (v.len(), v.first().copied(), v.last().copied())
        };
        let mut fwd: Vec<u64> = self.da_macc_fwd_mem.keys().copied().collect();
        fwd.sort_unstable();
        let mut rows: Vec<u64> = self.da_mem.keys().filter_map(|a| self.da_ord_mem.get(a).copied()).collect();
        rows.sort_unstable();
        let mut ladder: Vec<(u64, usize)> = self.da_ladder_mem.iter().map(|(k, v)| (*k, v.len())).collect();
        ladder.sort_unstable();
        format!(
            "dag {} blocks, min blue {:?}, horizon {}, keep {} · served_seq {} · anchor {:?} score {} prefix {} · da_mem {} rows \
             ({} ordinal-mapped, ords {:?}..{:?}) · leafstart {:?} · macc_fwd {} ({:?}..{:?}) rev {} first {:?} · ladder {:?}",
            dag.len(),
            min_score,
            dag.horizon_blue_score(),
            dag.keep_depth(),
            self.served_seq,
            self.certified_anchor.map(|a| a.to_hex()[..8].to_string()),
            self.certified_anchor_score,
            self.certified_prefix_len,
            self.da_mem.len(),
            rows.len(),
            rows.first(),
            rows.last(),
            ords(&self.da_leafstart_mem),
            fwd.len(),
            fwd.first(),
            fwd.last(),
            self.da_macc_rev_mem.len(),
            self.da_macc_first.map(|(o, _)| o),
            ladder
        )
    }

    /// DB-402 census diagnostic (lane a 2026-10-27): why THIS node holds (or lacks) the record row at `seq` — its ordinal,
    /// whether the ordinal resolves back to it, the block that carries it, the row's shape and the retention reason.
    /// Read by `NetSim::replica_census` for a `da_mem`/`da_tags_mem` key one node holds and another lacks.
    pub(crate) fn record_holding_diag_for_test(&self, seq: u64) -> String {
        let ord = self.da_record_ordinal(seq);
        let row = self.da_mem.get(&seq).map(|r| {
            let seed = r.0.len() == 1 && crate::cover::is_seed_note_in(&r.0[0], &r.0[0], &r.3);
            format!("held notes {} letters {} chain-bound {} seed-only {}", r.0.len(), r.1.len(), r.2, seed)
        });
        format!(
            "ord {:?} resolves {} · block {} · tags {} · {} · retain {:?}",
            ord,
            ord.map_or(false, |o| self.da_addr_at_ordinal(o) == Some(seq)),
            self.block_for_record_addr(seq).map_or("none".to_string(), |h| h.to_hex()[..12].to_string()),
            self.da_tags_mem.get(&seq).map_or(0, |t| t.len()),
            row.unwrap_or_else(|| "NOT HELD".to_string()),
            self.record_retention_reason(seq),
        )
    }

    /// A node that folds every record AT THE TIP (`record_fold_depth = 0`): the canonical order and the
    /// whole fold machinery are unchanged, only the wait is gone. For tests whose subject is not the fold
    /// delay — the production depth is pinned by canonical_record_fold_tests and the live gate.
    /// v31 fixture: the notes of `payload` ride ONE block this node produces now (staged, then produced),
    /// and the block's record address is returned with the block. A test that used to write a block-less
    /// record at a height writes the same notes this way — the only way a record exists on any node.
    /// v31 fixture: fold a record that a test wrote for a block outside the DAG (a synthetic block id or an
    /// exact address) — the SAME `fold_record_into_spine` a real block's fold calls, invoked on demand, so a
    /// test of the unspent-set / sidecar / heal layers keeps its synthetic ledger without a second fold path.
    #[cfg(test)]
    pub fn fold_record_now_for_test(&mut self, seq: u64) -> Option<u64> {
        // A synthetic record has no DAG block, so the fixture appends it at the next free position —
        // the same position the derived rule would give the next block in order. v32 SETTLED LAW
        // (2026-09-05): genesis holds ordinal 0 and real records start at 1 — `fold_canonical_records`
        // starts its cursor at 1 on a fresh node, so this fixture must too. `served_seq` alone gave the
        // OLD genesis-counted position: the first synthetic record took ordinal 0 and every later one
        // was refused by the settled-law position check (it only stayed green while a refused fold
        // still committed its row — the belt that stopped that exposed this fixture's old law).
        let next = self.served_seq.max(1);
        self.fold_record_into_spine(seq, next)
    }

    /// ⭐⭐⭐ THE CORPUS'S SPENDABLE NOTE — DERIVED FROM THE WITNESS THE SPEND WILL ACTUALLY PROVE.
    ///
    /// ⛔⛔⛔ THIS HELPER EXISTS BECAUSE THE FIXTURE BOUNCED OFF A THIRD DOOR. `spend_tx_for_test`'s own
    /// comment records two already: an id that bound nothing (`InvalidId`, 0 of 28 sends landed across 16
    /// campaign runs — every send-side verdict the fuzz lane had ever produced was vacuous), then an
    /// unground anti-spam stamp. The §BB deletion door is the third: a spend with no nullifier, no output
    /// notes and a blob that is not a carrier can be stated by NO note transition, so every peer refuses
    /// its deletion. **A corpus that models a spend the chain would refuse cannot certify the chain.**
    ///
    /// ⭐ THE FIX IS THE SAME ONE BOTH PREVIOUS TIMES: make the fixture pass the real door. A note is
    /// spendable only if its commitment is the LEAF the prover writes, because the spend cross-bind is
    /// `Poseidon(note_leaf(cm), nf)` and the carrier proves it over the leaf from its own row. So the
    /// corpus plants notes AT witness-derived commitments, and the spend proves that same witness. One
    /// spelling, both ends.
    ///
    /// `k` indexes a deterministic witness, so a note planted at `k` in one test is the note spent at `k`
    /// in another, and a reproducer replays identically.
    #[cfg(test)]
    pub(crate) fn test_spend_witness(k: u64) -> usdm_decider::whir_rec_block::SpendValidityWitness {
        let lanes = |v: &[u64; 4]| -> [u64; usdm_decider::poseidon2_compress::DIGEST_LANES] {
            core::array::from_fn(|i| v[i % 4].wrapping_add(i as u64))
        };
        let sk = lanes(&[11 + k, 12, 13, 14]);
        usdm_decider::whir_rec_block::SpendValidityWitness {
            value_in: 900 + k + 99900, // §BR-14: the input funds the protocol fee
            owner: usdm_decider::whir_rec_block::NoteOwner::from_test_key(sk),
            value_out: 800 + k,
            fee: usdm_decider::whir_rec_block::PROTOCOL_FEE_ATOMIC, // §BR-14
            // DB-329 §7f: distinct per note, as `fresh_lc_blind` is per send in production — an ordinary spend's claim
            // tag is `claim(lc_blind, 0)`, so one shared blinding would make every corpus spend claim ONE tag and the
            // set would (rightly) refuse the second.
            lc_blind: lanes(&[0x363, k + 1, 2, 3]),
            out0_value: 750 + k,
            out0_opening: lanes(&[7, 7, 7, 7]),
            out1_value: 50,
            out1_opening: sk,
        }
    }

    /// The note payload the corpus plants for witness `k`, and its commitment. The commitment IS the
    /// prover's own spent leaf (`spend_input_leaf`, which exists precisely so nobody re-derives it), so a
    /// later `spend_tx_for_test` over the same `k` produces a carrier whose cross-bind names this note.
    ///
    /// Remembers `cm -> k` process-wide so `spend_tx_for_test` keeps its `(cm, salt)` signature — the two
    /// production-shaped callers (`consensus_scenarios::Sim::spend`, `mesh_runtime_scenarios`) hold a
    /// commitment, never a witness index, exactly as a wallet does.
    #[cfg(test)]
    pub(crate) fn test_spendable_note(k: u64) -> (Vec<u8>, [u8; 32]) {
        let w = Self::test_spend_witness(k);
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w)
            .expect("the production prover states the spent note's leaf for a well-formed witness");
        let cm = crate::spend_frontier::leaf_to_cm_bytes(leaf);
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(&cm);
        // The tail is filler: the corpus never decapsulates these, and the front 32 bytes are the only
        // part any door reads. Derived from `k` so two notes are never byte-identical.
        for (i, b) in note.iter_mut().enumerate().skip(32) {
            *b = ((i as u64).wrapping_mul(31).wrapping_add(k * 7) % 251) as u8;
        }
        Self::test_witness_index().lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(cm, k);
        (note, cm)
    }

    /// `cm -> witness index` for the corpus's planted notes. Test-only, process-wide, and bounded by the
    /// number of notes a campaign plants (tens), which is why a plain map is the right shape here.
    #[cfg(test)]
    pub(super) fn test_witness_index() -> &'static std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>> {
        static IDX: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<[u8; 32], u64>>> =
            std::sync::OnceLock::new();
        IDX.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
    }

    /// ⭐ A PRODUCTION-SHAPED RECEIVE: the two output notes of a REAL proven spend, as a pooled tx.
    ///
    /// ⛔ THE SHAPE A FIXTURE CANNOT FAKE. `lay_note_transition` states a spend only when the transaction
    /// is a two-output spend with a nullifier AND a carrier blob, and the aggregate then proves that blob
    /// in circuit. A fixture that fills `output_notes` and `nullifiers` by hand but leaves a grind blob in
    /// place satisfies the SHAPE check and fails the PROVE, so the block carries notes with no transition
    /// — and every peer refuses them (§BA), while the producer records them through its own path. The two
    /// roots then diverge, which is what `a_resumed_node_heals_from_its_verified_anchor…` measured as
    /// `setup: one root with the receive folded` failing.
    ///
    /// So this proves witness `k` for real and reads every field off the proof. One spelling with
    /// [`Self::spend_tx_for_test`]: both take their nullifier, outputs and cross-bind from the prover.
    #[cfg(test)]
    pub(crate) fn test_receive_tx(
        k: u64,
        base: crate::mempool::PqTx,
        need: u32,
    ) -> Option<crate::mempool::PqTx> {
        // ⭐ THE SAME MEMOISED CARRIER the spend path uses (§CD): proving is not byte-deterministic, and a
        // receive that re-proves on every replay moves the block's nullifier decoy seed with it.
        let (blob, out_cms, nf, lc, tag1) = Self::test_spend_carrier(k, 0)?;
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
        for c in out_cms.iter() {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(&b32(*c));
            output_notes.extend_from_slice(&n);
        }
        // The id must bind the blob — `PqTx::content_id` is the rule, and swapping the blob without
        // recomputing it is the `InvalidId` refusal this fixture family has already hit twice.
        let id = crate::mempool::PqTx::content_id(&blob);
        // ⛔ AND THE STAMP MUST BE RE-GROUND FOR THE NEW ID. The caller's `base` was ground against its
        // OWN blob; swapping in the carrier moves the id, so the inherited stamp is worth nothing and the
        // pool answers `InsufficientStampWork { got: 0, need: 8 }` — measured the first time this ran.
        // The #72 client-PoW price is part of what a transaction COSTS, and a fixture that inherits a
        // stale stamp is bouncing off the door rather than passing it.
        let mut stamp = 0u64;
        let pow_stamp = loop {
            let mut buf = Vec::with_capacity(72);
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&stamp.to_le_bytes());
            buf.extend_from_slice(crate::params::process_network_id().as_bytes());
            if crate::mempool::leading_zero_bits(Hash32::hash(&buf).as_bytes()) >= need {
                break stamp;
            }
            stamp += 1;
        };
        Some(crate::mempool::PqTx {
            id,
            blob,
            pow_stamp,
            // ⭐⭐⭐ THE FIFTH DOOR: A SPEND SETTLES EXACTLY `TX_FIXED_NULLIFIER_COUNT` TAGS.
            //
            // `nullifier_witnesses_gate` refuses any other count outright — the constant-width rule is
            // consensus, and it is what hides WHICH of a transaction's tags are real. One real nullifier
            // is not a production spend, it is a spend with its cover stripped, and the door said so:
            // `[spend-miss] the spend's carried nullifier-absence witness did not verify`. Padded the way
            // `execute_order_fill` pads — `cover::pad_tx_nullifiers_to_fixed` seeded from the tx id, i.e.
            // decoys the SPENDER derives from its own per-tx secret.
            // DB-329 §7f: the two REAL rows are the nullifier and the carrier's claim tag, in that order.
            nullifiers: crate::cover::pad_tx_nullifiers_to_fixed(&[b32(nf), b32(tag1)], id.as_bytes())?
                .iter()
                .map(|n| Hash32(*n))
                .collect(),
            output_notes,
            note_clues: crate::note_transition::fixture_note_clues(&out_cms),
            membership_leaf_commit: b32(lc),
            ..base
        })
    }

    /// ⭐⭐⭐ THE CORPUS PROVES EACH SPEND ONCE, THE WAY A WALLET DOES — AND THAT IS NOT A SHORTCUT.
    ///
    /// ⛔⛔⛔ §CD: `prove_spend_validity_carrier_with_commit_bytes` is NOT byte-deterministic. Measured
    /// `138010 vs 138010, equal=false` on the same witness, public outputs identical. In production that
    /// costs nothing — a wallet proves ONCE and gossips the bytes, so every node folds the same blob — but
    /// a fixture that re-proves on every replay gets different bytes, and the block's nullifier DECOY SEED
    /// is derived from those bytes. Five corpus pins went red with exactly that signature: `uns_root`,
    /// `uns_fold`, `uns_leaves` and `nf_count` IDENTICAL across two replays, `nf_acc`/`nf_root` DIFFERENT.
    ///
    /// Memoising per `(k, salt)` makes the corpus model the real thing — one prove per spend, the same
    /// bytes everywhere it is seen — instead of modelling a world where every node re-proves a stranger's
    /// transaction, which no node does. ⛔ It does NOT paper over §CD: the property is pinned by
    /// `note_transition::tests::proving_the_same_spend_twice_is_byte_identical`, and THIS COMMENT NAMES
    /// THE MEMOISATION AS THE THING TO DELETE when that pin flips.
    ///
    /// The INPUT LEAF is fixed by `k` (or the cross-bind stops naming the note); the OUTPUTS vary by
    /// `salt` through `out0_sk`, so a retried attempt mints fresh outputs for the same input exactly as a
    /// wallet re-randomising a change address would — without which a retry collided and the fold reported
    /// `⛔⛔⛔ FUND STRANDING: a carried note could NOT fold into the unspent tree (AlreadyPresent)`.
    ///
    /// O1-FOOTPRINT-REVIEWED: test-only, bounded by the number of distinct `(k, salt)` a campaign spends
    /// (tens), built in-process and dropped with it. Never reachable from any production path.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn test_spend_carrier(
        k: u64,
        salt: u64,
    ) -> Option<(
        Vec<u8>,
        [crate::spend_frontier::Digest4; 2],
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
        crate::spend_frontier::Digest4,
    )> {
        // `(blob, out_cms, nf, lc, tag1)` — tag1 the carrier's claim tag (DB-329 §7f), row 1 of the tx's tag list.
        type Carrier = (
            Vec<u8>,
            [crate::spend_frontier::Digest4; 2],
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
        );
        static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(u64, u64), Carrier>>> =
            std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Some(hit) = cache.lock().unwrap_or_else(std::sync::PoisonError::into_inner).get(&(k, salt)) {
            return Some(hit.clone());
        }
        let mut w = Self::test_spend_witness(k);
        w.out0_opening = core::array::from_fn(|i| {
            w.out0_opening[i].wrapping_add(salt.wrapping_mul(1_000_003).wrapping_add(i as u64))
        });
        // DB-351: proved under the wallet's filing (`fixture_note_clues`, one clue per output) — what `spend_tx_for_test`
        // builds; the unfiled-spend law evicts a pooled spend whose outputs the ledger cannot file.
        let (blob, out_cms, nf, lc, _d) = crate::note_transition::prove_wallet_spend(&w)?;
        let v: Carrier = (blob, out_cms, nf, lc, usdm_decider::whir_rec_block::spend_tag1(&w));
        cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((k, salt), v.clone());
        Some(v)
    }

    /// TEST — ⭐ DB-223 Q7: the MEMBER LEG a wallet builds for note `cm` this node holds in a FOLDED record, by the
    /// production path: a `MemberWitnessBook` told the note arrived (its record's 256 leaves) and fed ONLY this node's
    /// public path-refresh stream, then `carrier_for` against the newest ring root. `None` when the book cannot build it
    /// (the record has not folded, or the stream does not reach it) — exactly when a wallet could not send either.
    #[cfg(test)]
    pub(crate) fn member_leg_for_test(
        &self,
        cm: &[u8; 32],
        binder: crate::spend_frontier::Digest4,
        blind: crate::spend_frontier::Digest4,
        out0_cm: &[u8; 32],
        out1_cm: &[u8; 32],
    ) -> Option<(Vec<u8>, usdm_decider::member_path_gate::MemberTuple)> {
        // Each refusal names its step (test-only, so a fixture that cannot build a member leg says WHY, not just `None`).
        let book = match self.member_book_for_test(cm) {
            Ok(b) => b,
            Err(why) => {
                eprintln!("[member-leg-miss] {why}");
                return None;
            }
        };
        match book.carrier_for(cm, binder, blind, out0_cm, out1_cm) {
            Ok(c) => Some(c),
            Err(e) => {
                let raw = self.path_refresh_stream(0);
                eprintln!(
                    "[member-leg-miss] carrier_for refused: {e} (pending its record's fold: {}) — book: {} — node stream from 0: \
                     {} entries, ordinals {:?}..{:?}, newest {:?}, catch_up {}, spine ring {} entries, completed windows {}",
                    book.is_pending(cm),
                    book.explain_pending(cm),
                    raw.entries.len(),
                    raw.entries.first().map(|e| e.0),
                    raw.entries.last().map(|e| e.0),
                    raw.newest.map(|(o, _)| o),
                    raw.catch_up,
                    self.spine_recent_roots.len(),
                    self.completed_windows.len()
                );
                None
            }
        }
    }

    /// The witness book a wallet holding `cm` builds from THIS node's public stream — the note's arrival from its held
    /// record, then the path-refresh stream from the book's cursor. Shared by [`Self::member_leg_for_test`] and
    /// [`Self::member_path_ready_for_test`], so "can this note be spent here" and "build its leg" read one capture.
    #[cfg(test)]
    pub(super) fn member_book_for_test(&self, cm: &[u8; 32]) -> Result<crate::member_witness::MemberWitnessBook, String> {
        let Some((seq, reals)) = self.da_mem.iter().find_map(|(rid, row)| {
            row.0
                .iter()
                .any(|n| n.len() >= 32 && &n[..32] == cm)
                .then(|| (*rid, row.0.iter().flat_map(|x| x.iter().copied()).collect::<Vec<u8>>()))
        }) else {
            return Err("no held record names the note".into());
        };
        let mut book = crate::member_witness::MemberWitnessBook::new();
        book.note_arrived(*cm, Self::block_leaves_from_notes(&reals, seq, &self.cover_key_of(seq)));
        book.apply_stream(&self.path_refresh_stream(book.cursor()))
            .map_err(|e| format!("the path-refresh stream did not apply: {e:?}"))?;
        Ok(book)
    }

    /// Whether a wallet could spend `cm` through this node RIGHT NOW: its record has FOLDED here and the captured path
    /// refolds to the newest ring root — the wallet's "confirmed" (DB-372), before which no member leg exists. A note
    /// still inside the fold lag is not spendable yet; that is the chain's confirmation depth, not a defect.
    #[cfg(test)]
    pub(crate) fn member_path_ready_for_test(&self, cm: &[u8; 32]) -> bool {
        self.member_book_for_test(cm).is_ok_and(|b| b.path_ready(cm))
    }

    /// A spend of the note `cm`, as a mempool transaction: the Zcash shape this chain uses since Z1 —
    /// a real nullifier in the cover-padded lane, each tag proving itself UNSPENT against the live sparse
    /// root by a carried copath, plus the self-built base-state absence carrier, and (DB-223 Q7) the input's
    /// member leg from this node's own public stream.
    /// Test-only: production transactions arrive from wallets with their carriers and stamps.
    /// Returns `(tx id, the NULLIFIER this spend published)`. Z1: a scenario can no longer ask a node
    /// "is this commitment spent" — under the Zcash shape spent-ness is a fact about a nullifier, and the
    /// commitment stays in the append-only frontier forever. So the caller is handed the one coordinate
    /// the nullifier lane answers about, or it cannot check the double-spend law at all.
    #[cfg(test)]
    pub(crate) fn spend_tx_for_test(
        &mut self,
        cm: &[u8; 32],
        salt: u64,
    ) -> Result<(Hash32, [u8; 32]), crate::mempool::MempoolError> {
        // ⛔⛔ THE ID MUST BIND THE BLOB — `PqTx::content_id` IS THE RULE, NOT A FORMALITY.
        //
        // This helper used to set `id` to `hash("spend-for-test-{salt}")` over an EMPTY blob, so the id
        // bound nothing and `Mempool::accept` refused every one of them with `InvalidId`. That refusal
        // was correct: the door was doing its job. The DRIVER was building a transaction no production
        // path would ever admit — and `Sim::spend` discarded the error and returned `Ok(())`, so the
        // harness recorded a spend that never happened.
        //
        // MEASURED before this fix: 0 sends landed out of 28 scheduled across 16 campaign runs. Every
        // send-side verdict the fuzz lane had ever produced was therefore vacuous — "no double-spend
        // was found" over a campaign in which nothing was ever spent. A helper that cannot pass the
        // real door is not a test of the send path; it is a test of nothing.
        // ⛔ AND THE ANTI-SPAM STAMP MUST BE GROUND, THE WAY A REAL SENDER GRINDS IT. With the id fixed,
        // the next real door spoke: `anti-spam stamp work 1 < required 8`. `pow_stamp: 0` is not a
        // transaction a wallet would ever send — the #72 client-PoW price is part of what a spend COSTS,
        // and a driver that skips it is not exercising the send path, it is bouncing off the second door
        // instead of the first. Ground here against the pool's own live requirement.
        // ⭐⭐⭐ THE THIRD DOOR (§BB): THE BLOB MUST BE A REAL CARRIER, OR NO TRANSITION CAN STATE IT.
        //
        // `lay_note_transition` states a spend only when it is a two-output spend with a nullifier and a
        // carrier blob. (The deletion lane this line used to describe is GONE — the Z-build retired the
        // deletion tree and a spent note is refused by the NULLIFIER SET, so nothing admits deletions.)
        // The stated spend BINDS
        // the commitment (the blinded `leaf_commit` cross-bind). A fixture blob of `b"spend-for-test-N"` satisfies neither,
        // so every peer refused the deletion — measured as `party 0 and party 1 diverge on
        // unspent_note_root` in `d52`. Same lesson as the two doors above it: a helper that cannot pass
        // the real door tests nothing.
        //
        // So this proves the SAME witness the note was planted from (`test_spendable_note`), which is why
        // the corpus plants at witness-derived commitments at all. The prove is the honest cost of a
        // corpus that models a spend the chain would accept.
        let k = *Self::test_witness_index()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(cm)
            .ok_or(crate::mempool::MempoolError::InvalidId)?;
        // ⭐ THE INPUT LEAF IS FIXED BY `k`; THE OUTPUTS VARY BY `salt`, AND BOTH HALVES MATTER.
        //
        // The leaf must stay exactly what `test_spendable_note(k)` planted, or the cross-bind stops naming
        // this note and the deletion is refused. But a spend ATTEMPT that does not land is retried, and
        // re-proving the identical witness produced the identical output commitments — measured as
        // `[uns-recv] ⛔⛔⛔ FUND STRANDING: a carried note could NOT fold into the unspent tree
        // (AlreadyPresent)`. Varying `out0_sk` moves the OUTPUT commitments while leaving the spent
        // note's leaf (a function of `sk` and `value_in`) untouched, so a retry mints fresh outputs for
        // the same input exactly as a real wallet re-randomising a change address would.
        let carrier = Self::test_spend_carrier(k, salt).ok_or(crate::mempool::MempoolError::InvalidId)?;
        self.spend_tx_from_carrier_for_test(cm, carrier, &Self::test_spend_witness(k))
    }

    /// ⭐ DB-395 — the same production-shaped spend for an EXPLICIT witness. The pins that ask WHO can spend a note (a payer
    /// holding exactly what its own seal returned) build the spend from what THAT party holds, never from the corpus index.
    #[cfg(test)]
    pub(crate) fn spend_tx_for_witness_for_test(
        &mut self,
        cm: &[u8; 32],
        w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    ) -> Result<(Hash32, [u8; 32]), crate::mempool::MempoolError> {
        let (blob, out_cms, nf, lc, _filing) =
            crate::note_transition::prove_wallet_spend(w).ok_or(crate::mempool::MempoolError::InvalidId)?;
        let carrier = (blob, out_cms, nf, lc, usdm_decider::whir_rec_block::spend_tag1(w));
        self.spend_tx_from_carrier_for_test(cm, carrier, w)
    }

    /// The pooled spend around a proven carrier `(blob, out_cms, nf, lc, tag1)`: its member leg under the carrier's own
    /// blinding, the constant-width tag set, the lane evidence and the client stamp — each door's production shape.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn spend_tx_from_carrier_for_test(
        &mut self,
        cm: &[u8; 32],
        carrier: (
            Vec<u8>,
            [crate::spend_frontier::Digest4; 2],
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
        ),
        w: &usdm_decider::whir_rec_block::SpendValidityWitness,
    ) -> Result<(Hash32, [u8; 32]), crate::mempool::MempoolError> {
        use crate::mempool::MempoolError;
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        // ⭐ §18 (2026-10-28): a stated spend carries its spend-or-decoy carrier over the wallet's tag list — the producer lays
        // its 15 tail rows from it and chains them in the tag ledger; a spend without one is never stated (Q7's rule). So the
        // prechecked-door builder attaches what the wallet attaches (`test_wallet_tag_list_for`), as the production-shaped
        // builder does. MEASURED before: four green pins (db358 r3 ×2, the re-spend refusal, db329's two claims) read
        // "B credits the FRESH control spend" red — their spends were pooled without a carrier and never laid.
        let (blob, _, nf_d, _, tag1) = carrier.clone();
        let (tags, cover) = Self::test_wallet_tag_list_for(w, &blob, nf_d, tag1).ok_or(MempoolError::InvalidProof)?;
        // The RPC's door: its caller verified the carrier off the lock (`ingest_tx_prechecked`'s contract).
        let (mut tx, nf) = self.build_spend_tx_for_test(cm, carrier, w.lc_blind)?;
        tx.spend_or_decoy = cover;
        let padded: Vec<[u8; 32]> = tags.iter().map(|t| b32(*t)).collect();
        let (lane_witnesses, lane_absence) = self.spend_lane_evidence(&padded);
        tx.nullifiers = padded.iter().map(|t| Hash32(*t)).collect();
        tx.nullifier_witnesses = lane_witnesses;
        tx.nullifier_absence = lane_absence;
        self.ingest_tx_prechecked(tx).map(|id| (id, nf))
    }

    /// TEST — ⭐ link 62: the spend of corpus note `cm` in the WALLET'S shape, the one `/submit_pq_tx` admits and the gossip
    /// door now judges with the same [`Self::send_verdict`]. [`Self::spend_tx_for_test`]'s transaction is one no submit door
    /// admits (no one-step membership carrier, no spend-or-decoy carrier, decoys seeded from the tx id), which is why it
    /// enters only through the prechecked door. This one carries what `send_pq_tx` sends (wallet lib.rs ~13600–13800):
    ///  * the tag list `aligned_padded_tags_of(&[nf, tag1], tx_secret)` — the two reals at rows 0 and 1, then
    ///    `cover_tag_native(note_leaf_of(tx_secret), slot)` decoys — with its lane evidence;
    ///  * `build_spend_or_decoy_proof`: `RealSpend(nk, leaf)`, the claim pair `slot_claim_preimage(lc_blind, 0)`, decoys;
    ///  * the one-step note-membership carrier and tip over the note's folded record (binder = nf, blind = lc_blind);
    ///  * the wallet's clue list, one locator clue per output (`fixture_note_clues`, set by `build_spend_tx_for_test`) and
    ///    the weight the RPC sets (blob bytes).
    /// `tx_secret` is a per-tx secret, as the wallet's is. Not pooled: the caller offers it to a door.
    #[cfg(test)]
    pub(crate) fn production_spend_tx_for_test(
        &mut self,
        cm: &[u8; 32],
        salt: u64,
    ) -> Result<(crate::mempool::PqTx, [u8; 32]), crate::mempool::MempoolError> {
        use crate::mempool::MempoolError;
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let k = *Self::test_witness_index()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(cm)
            .ok_or(MempoolError::InvalidId)?;
        // The salt moves only the OUTPUTS (`test_spend_carrier`), so the input's opening is witness `k`'s.
        let w = Self::test_spend_witness(k);
        let carrier = Self::test_spend_carrier(k, salt).ok_or(MempoolError::InvalidId)?;
        let nf = carrier.2;
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w).ok_or(MempoolError::InvalidId)?;
        let (tags, cover) = Self::test_wallet_tag_list(k, salt).ok_or(MempoolError::InvalidProof)?;
        let (mut tx, nf_bytes) = self.build_spend_tx_for_test(cm, carrier, w.lc_blind)?;
        tx.spend_or_decoy = cover;
        let padded: Vec<[u8; 32]> = tags.iter().map(|t| b32(*t)).collect();
        let (lane_witnesses, lane_absence) = self.spend_lane_evidence(&padded);
        tx.nullifiers = padded.iter().map(|t| Hash32(*t)).collect();
        tx.nullifier_witnesses = lane_witnesses;
        tx.nullifier_absence = lane_absence;
        let (membership_carrier, membership_tip) =
            crate::node::tests::one_step_membership_for_test(self, cm, leaf, nf, w.lc_blind)
                .ok_or(MempoolError::MemberCarrierRequired)?;
        tx.membership_carrier = membership_carrier;
        tx.membership_tip = membership_tip;
        tx.weight = u32::try_from(tx.blob.len()).map_err(|_| MempoolError::InvalidId)?;
        Ok((tx, nf_bytes))
    }

    /// TEST — the wallet's constant-width tag list for corpus spend `(k, salt)` and its spend-or-decoy carrier: the two reals
    /// (nf, claim tag) at rows 0 and 1, then `cover_tag_native(note_leaf_of(tx_secret), slot)` decoys, `tx_secret` a per-tx
    /// secret from the spend's own id (`aligned_padded_tags_of` + `build_spend_or_decoy_proof`). A function of `(k, salt)`
    /// alone, so a load fixture proves it before the load, in parallel, as a wallet proves before it submits; memoised like
    /// [`Self::test_spend_carrier`] (proving is not byte-deterministic). O1-FOOTPRINT-REVIEWED: test-only, tens of entries.
    /// [`Self::test_wallet_tag_list`] for an explicit witness and its proven carrier `(blob, nf, tag1)` — uncached (a
    /// witness is not a corpus index), the same list and carrier shape.
    #[cfg(test)]
    pub(crate) fn test_wallet_tag_list_for(
        w: &usdm_decider::whir_rec_block::SpendValidityWitness,
        blob: &[u8],
        nf: crate::spend_frontier::Digest4,
        tag1: crate::spend_frontier::Digest4,
    ) -> Option<(Vec<crate::spend_frontier::Digest4>, Vec<u8>)> {
        use usdm_decider::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, TagWitness};
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(w)?;
        let id = crate::mempool::PqTx::content_id(blob);
        let tx_secret = *Hash32::hash(&[b"MONEROUSD-TEST-WALLET-TX-SECRET-v1".as_slice(), id.as_bytes()].concat()).as_bytes();
        let bound = crate::spend_frontier::note_leaf_of(&tx_secret);
        let mut tags = vec![nf, tag1];
        tags.extend((2..crate::cover::TX_FIXED_NULLIFIER_COUNT as u64).map(|slot| cover_tag_native(bound, slot)));
        let (claim_key, claim_leaf) = usdm_decider::slot_ledger::slot_claim_preimage(w.lc_blind, 0);
        let mut wit = vec![
            TagWitness::RealSpend { key: w.owner.nk, leaf },
            TagWitness::RealSpend { key: claim_key, leaf: claim_leaf },
        ];
        while wit.len() < tags.len() {
            wit.push(TagWitness::Decoy);
        }
        Some((tags.clone(), prove_spend_or_decoy_bytes(bound, &tags, &wit)?))
    }

    #[cfg(test)]
    pub(crate) fn test_wallet_tag_list(k: u64, salt: u64) -> Option<(Vec<crate::spend_frontier::Digest4>, Vec<u8>)> {
        use usdm_decider::nf_sparse_air::{cover_tag_native, prove_spend_or_decoy_bytes, TagWitness};
        type Entry = (Vec<crate::spend_frontier::Digest4>, Vec<u8>);
        static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(u64, u64), Entry>>> =
            std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
        if let Some(hit) = cache.lock().expect("the fixture cache is never poisoned").get(&(k, salt)) {
            return Some(hit.clone());
        }
        let w = Self::test_spend_witness(k);
        let (blob, _, nf, _, tag1) = Self::test_spend_carrier(k, salt)?;
        let leaf = usdm_decider::whir_rec_block::spend_input_leaf(&w)?;
        let id = crate::mempool::PqTx::content_id(&blob);
        let tx_secret = *Hash32::hash(&[b"MONEROUSD-TEST-WALLET-TX-SECRET-v1".as_slice(), id.as_bytes()].concat()).as_bytes();
        let bound = crate::spend_frontier::note_leaf_of(&tx_secret);
        let mut tags = vec![nf, tag1];
        tags.extend((2..crate::cover::TX_FIXED_NULLIFIER_COUNT as u64).map(|slot| cover_tag_native(bound, slot)));
        let (claim_key, claim_leaf) = usdm_decider::slot_ledger::slot_claim_preimage(w.lc_blind, 0);
        let mut wit = vec![
            TagWitness::RealSpend { key: w.owner.nk, leaf },
            TagWitness::RealSpend { key: claim_key, leaf: claim_leaf },
        ];
        while wit.len() < tags.len() {
            wit.push(TagWitness::Decoy);
        }
        let entry = (tags.clone(), prove_spend_or_decoy_bytes(bound, &tags, &wit)?);
        cache.lock().expect("the fixture cache is never poisoned").insert((k, salt), entry.clone());
        Some(entry)
    }

    /// The pooled-spend shape around a proven carrier, BUILT but not offered to any door: its member leg, the constant-width
    /// tag set, the lane evidence and the client stamp. Returns the transaction and the nullifier it publishes.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn build_spend_tx_for_test(
        &mut self,
        cm: &[u8; 32],
        carrier: (
            Vec<u8>,
            [crate::spend_frontier::Digest4; 2],
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
            crate::spend_frontier::Digest4,
        ),
        lc_blind: crate::spend_frontier::Digest4,
    ) -> Result<(crate::mempool::PqTx, [u8; 32]), crate::mempool::MempoolError> {
        let (blob, out_cms, nf, lc, tag1) = carrier;
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        // ⭐ DB-223 Q7: the input's MEMBER LEG, built the wallet's way under the SAME blinding the carrier was proven with.
        let (member_carrier, member_tuple) = self
            .member_leg_for_test(cm, nf, lc_blind, &b32(out_cms[0]), &b32(out_cms[1]))
            .ok_or(crate::mempool::MempoolError::MemberCarrierRequired)?;
        let mut member_tuple_bytes = Vec::with_capacity(crate::member_transition::MEMBER_TUPLE_BYTES);
        crate::member_transition::write_tuple(&member_tuple, &mut member_tuple_bytes);
        // The two output notes the carrier proved, in ITS order — the same order the tuple welds, so a
        // fixture that reordered them would bind nothing.
        let mut output_notes = Vec::with_capacity(2 * crate::cover::PQ_NOTE_BYTES);
        for c in out_cms.iter() {
            let mut n = vec![0u8; crate::cover::PQ_NOTE_BYTES];
            n[..32].copy_from_slice(&b32(*c));
            output_notes.extend_from_slice(&n);
        }
        let need = self.mempool.required_stamp_bits();
        let id = crate::mempool::PqTx::content_id(&blob);
        let mut stamp = 0u64;
        // The exact constant-width tag set this spend settles — computed once, so the tags, their
        // copaths and the absence carrier all describe the SAME set (three independent `pad_...` calls
        // could not be relied on to agree, and a spend whose witness set names other tags is refused).
        // DB-329 §7f: the two REAL rows are the nullifier and the carrier's claim tag, in that order.
        let padded_tags = crate::cover::pad_tx_nullifiers_to_fixed(&[b32(nf), b32(tag1)], id.as_bytes())
            .ok_or(crate::mempool::MempoolError::InvalidId)?;
        let (lane_witnesses, lane_absence) = self.spend_lane_evidence(&padded_tags);
        let pow_stamp = loop {
            let mut buf = Vec::with_capacity(72);
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&stamp.to_le_bytes());
            buf.extend_from_slice(crate::params::process_network_id().as_bytes());
            if crate::mempool::leading_zero_bits(Hash32::hash(&buf).as_bytes()) >= need {
                break stamp;
            }
            stamp += 1;
        };
        let tx = crate::mempool::PqTx {
            clock_ms: 0,
            // The wallet's filing the carrier was proven under (`prove_wallet_spend`).
            note_clues: crate::note_transition::fixture_note_clues(&out_cms),
            account_targets: Vec::new(),
            id,
            blob,
            weight: 1,
            // ⭐⭐⭐ THE FIFTH DOOR: A SPEND SETTLES EXACTLY `TX_FIXED_NULLIFIER_COUNT` TAGS.
            //
            // `nullifier_witnesses_gate` refuses any other count outright — the constant-width rule is
            // consensus, and it is what hides WHICH of a transaction's tags are real. One real nullifier
            // is not a production spend, it is a spend with its cover stripped, and the door said so:
            // `[spend-miss] the spend's carried nullifier-absence witness did not verify`. Padded the way
            // `execute_order_fill` pads — `cover::pad_tx_nullifiers_to_fixed` seeded from the tx id, i.e.
            // decoys the SPENDER derives from its own per-tx secret.
            nullifiers: padded_tags.iter().map(|n| Hash32(*n)).collect(),
            pow_stamp,
            output_notes,
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            // ⭐⭐⭐ THE SPEND LANE'S OWN EVIDENCE BUILDER — the call a real submitter makes.
            //
            // ⛔ THIS USED TO MAP `compress_copath(da_sparse_copath(t))` OVER THE TAGS DIRECTLY, AND THAT
            // IS A SHAPE NO PRODUCTION SPENDER CAN PRODUCE. On a node whose working tree is COLD — every
            // restarted node, every jumped node; the tree is O(spent) and is deliberately never persisted
            // — `da_sparse_copath` returns the ALL-EMPTY copath by design ("a node holding only roots
            // cannot source a witness, and must not pretend to"). Mapped blindly, that yields a
            // full-length copath that cannot fold to the live root, and the gate refuses the spend for
            // carrying a witness that proves nothing. Production never builds that: `spend_lane_evidence`
            // is all-or-nothing — every tag provable, or NO copath lane at all and the recursive absence
            // carrier alone (which is the admission authority; the copaths are corroboration).
            //
            // A fixture that builds the refused shape measures the gate's reaction to a malformed spend
            // and calls it the spend path. Route through the production builder instead.
            nullifier_witnesses: lane_witnesses,
            // ⭐⭐⭐ THE FOURTH DOOR: A REAL NULLIFIER MEANS THE ABSENCE GATE ACTUALLY RUNS.
            //
            // While `nullifiers` was empty this transaction passed the double-spend gate VACUOUSLY — a
            // nullifier-free tx (cover, coinbase) has nothing to check. Giving it the nullifier the
            // carrier proved turned the gate on, and the fixture immediately failed it: `[spend-miss] the
            // spend's carried nullifier-absence witness did not verify against this node's accumulator`.
            //
            // A real sender attaches its OWN self-built absence proof at publish
            // (`self_build_publish_absence_witness`, the same call `execute_order_fill` makes), so that
            // is what this does. `None` leaves the witness empty and the door refuses — which is the
            // honest outcome for a node that cannot state its own accumulator, and it will show up as a
            // counted `spend-miss` rather than a silently vacuous send.
            nullifier_absence: lane_absence,
            membership_carrier: Vec::new(),
            // ⭐ THE CROSS-BIND THE CARRIER PROVED — what makes this spend's deletion statable at all.
            membership_leaf_commit: b32(lc),
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            // ⭐ DB-223 Q7: the input's member leg — every spend proves its input exists.
            member_carrier,
            member_tuple: member_tuple_bytes,
        };
        Ok((tx, b32(nf)))
    }

    /// ⭐ §BA — THIS HELPER CARRIES A NOTE THE WAY PRODUCTION DOES, JUSTIFICATION INCLUDED.
    ///
    /// It used to stage the note alone, which is the shape `graft_admitted_notes` now refuses on every
    /// peer: a note nothing justifies is the §BA plant, and a test fixture that models the plant while
    /// asserting the note ARRIVES is asserting the hole. Every D-series and fuzz case that carries a real
    /// note comes through here, so pairing the note with its object here keeps them testing what they
    /// test — record space, folds, restarts, jumps — over a shape the chain actually admits.
    ///
    /// ⛔ IT DOES NOT WEAKEN THE DOOR. The object is a real `BridgeCreditTx` that passes
    /// `chain_object::admissible` on its own bytes, and the peer re-runs both questions for itself. A
    /// fixture that wanted the note refused would simply not stage one — which is exactly what the §BA
    /// pin does.
    #[cfg(test)]
    pub fn carry_notes_in_a_block_for_test(&mut self, ts: u64, payload: &[u8]) -> (Block, u64) {
        self.record_note_payload(0, payload);
        for chunk in payload.chunks(crate::cover::PQ_NOTE_BYTES) {
            if chunk.len() < crate::cover::PQ_NOTE_BYTES {
                continue;
            }
            let mut deposit_id = [0u8; 32];
            deposit_id.copy_from_slice(&chunk[..32]);
            let object = crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id,
                asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                amount: 1_000,
                note: chunk.to_vec(),
                owner_clue: Vec::new(),
                attestors: Vec::new(),
            }
            .wire();
            // ⛔⛔⛔ DB-354 — THE FIXTURE MODELS WHAT THIS CHAIN ADMITS, OR IT REFUSES LOUDLY.
            //
            // This helper promised a note carried "the way production does", but on a genesis with no open-mint
            // allowance (every chain but the exact testnet identity) its credit is refused by `admissible`, so every
            // peer's §BA door refused the note. MEASURED 2026-09-28: 17 of the 30 tests reaching this helper ran on
            // such a chain. Four were red; three of those were the producer and peer disagreeing about the record
            // (the DB-354 divergence itself). Thirteen were green while modelling the §BA plant. A test that wants
            // the plant stages it explicitly (see `db276_the_applied_stream_never_serves_a_note_the_graft_door_refused`).
            let attested = crate::bridge_credit_tx::credit_attested_by_bonded_quorum(self.validators(), &object);
            assert!(
                crate::chain_object::admissible(
                    &object,
                    self.params().order_fill_fee_bps,
                    self.params().genesis_mint_allowance(),
                    attested
                ),
                "FIXTURE (DB-354): this chain refuses the credit that justifies the carried note (open-mint allowance \
                 {} and no bonded quorum attests it), so every peer's §BA door refuses the note. Build the party on the \
                 testnet identity (`node::tests::testnet_party_folding_at_tip`), or stage a plant explicitly.",
                self.params().genesis_mint_allowance()
            );
            self.stage_credit_justifier(object);
        }
        let b = self
            .produce(ts, Hash32::hash(b"carrier-frontier"), Hash32::hash(b"carrier-miner"))
            .expect("the carrier block produces");
        // ⛔ NEVER ASSUME SUB 0 — the same rule the by-id record serve states in its own arm. A block's
        // record lands at its ACTUAL sub-address, and a fixture that hardcodes sub 0 asks for a record
        // that does not exist, so `da_block_leaves` answers None and the test reads as "the block did not
        // regenerate" when in fact it was never looked up.
        let seq = self.record_addr_for_block_or_canonical(&b.id());
        (b, seq)
    }

    #[cfg(test)]
    pub fn new_folding_at_tip_for_test(genesis: Block) -> Result<Self, DagError> {
        let mut p = ChainParams::default();
        p.record_fold_depth = 0;
        let mut n = Self::with_params(genesis, p)?;
        #[cfg(test)]
        Ok(n)
    }

    /// Read a DA record by its canonical address. Test-only accessor over the real store.
    #[cfg(test)]
    pub fn da_load_for_test(&self, addr: u64) -> Option<Vec<Vec<u8>>> {
        self.da_load(addr)
    }

    /// Every note this node has RECORDED, read straight from the DA shard's own keys.
    ///
    /// Not a chain walk: it enumerates the records that exist rather than probing a dense range of addresses.
    /// Since a record is named by its BLOCK ID, addresses are 32-byte-derived and unordered, so "page from 0"
    /// stopped meaning anything — the range walk it replaces was the sweep's data source and is retired.
    ///
    /// ⚠️ ITS COST IS THE SHARD'S SIZE, so it must never reach a serve path: every caller today is a test
    /// (verified by grep — 5 call sites, all in `#[cfg(test)]` modules). It is `#[cfg(test)]` for that reason.
    /// Serving needs `da_record_notes(addr)`, ONE indexed read; enumerating the whole shard is a test affordance
    /// and would be an O(records) walk in production.
    #[cfg(test)]
    pub fn da_recorded_notes(&self) -> Vec<(u64, Vec<u8>)> {
        let mut out = Vec::new();
        let addrs: Vec<u64> = self.da_mem.keys().copied().collect();
        for addr in addrs {
            if let Some(blob) = self.da_record_notes(addr) {
                out.push((addr, blob));
            }
        }
        out.sort_by_key(|(a, _)| *a);
        out
    }

    /// SIMULATOR INSTRUMENT (test builds only): this node's whole view of ONE record address — the row's note count and
    /// provenance, the block it names here, whether the held notes hash to that block's header `output_notes_root`, the
    /// derived 256-leaf root a membership door compares, and the fold verdict — so a cross-node root refusal names which
    /// node's bytes left the chain's.
    #[cfg(test)]
    pub(crate) fn record_forensic(&self, addr: u64) -> String {
        let row = self.da_mem.get(&addr).map(|r| (r.0.len(), r.2));
        let block = self.block_for_record_addr(addr);
        let header_root = block.and_then(|b| self.relay.dag().get(&b).map(|n| n.header.output_notes_root));
        let reals = self.da_record_reals(addr);
        let reals_hash_header = match (&reals, header_root) {
            (Some(r), Some(h)) => Some(crate::block::da_notes_root_of(&r.concat()) == h),
            _ => None,
        };
        let derived = self
            .da_record_notes(addr)
            .map(|n| Self::fold_leaves_to_root(&Self::block_leaves_from_notes(&n, addr, &self.cover_key_of(addr))))
            .map(|d| format!("{:?}", d).chars().take(40).collect::<String>());
        format!(
            "row(notes,bound) {row:?} · resolved reals {:?} · block {} · reals hash to its header {reals_hash_header:?} · \
             derived root {derived:?} · folded {}",
            reals.as_ref().map(|r| r.len()),
            block.map(|b| format!("{b:?}").chars().take(16).collect::<String>()).unwrap_or_else(|| "none".into()),
            self.named_record_folded(addr)
        )
    }

    #[cfg(test)]
    pub(crate) fn mark_spine_stale_for_test(&mut self) {
        self.mark_spine_stale("test: a reorg below the fork point");
    }

    #[cfg(test)]
    pub(crate) fn certified_anchor_for_test(&self) -> Option<crate::block::BlockId> {
        self.certified_anchor
    }

    #[cfg(test)]
    pub(crate) fn certified_prefix_len_for_test(&self) -> u64 {
        self.certified_prefix_len
    }

    /// Push a block into the unfolded set — the quantity DB-161's gate reads.
    ///
    /// The gate refused on `unfolded_blocks.len()`, so that count IS the condition under test. Reaching
    /// 512 by mining takes ~45 minutes (measured: 300 blocks in 25 min), which is not a unit pin; this
    /// drives the same counter with real blocks so the refusal path is exercised in seconds.
    #[cfg(test)]
    pub(crate) fn push_unfolded_for_test(&mut self, b: crate::block::Block) {
        self.unfolded_blocks.push(b.into());
    }

    /// How many blocks this node holds unfolded — the fold lag, for the DB-161 pin.
    #[cfg(test)]
    pub(crate) fn unfolded_blocks_len_for_test(&self) -> usize {
        self.unfolded_blocks.len()
    }

    /// The unfolded blocks themselves — the §SIMMEM pin breaks their bytes down by component.
    #[cfg(test)]
    pub(crate) fn unfolded_blocks_for_test(&self) -> &[crate::block::IdBlock] {
        &self.unfolded_blocks
    }

    /// Arm a fold wait on a named block, through the SAME bookkeeping the fold's own `Err(missing)` arm
    /// uses — only the SOURCE of the id is the test's, never the accounting. A fixture cannot reach the
    /// live precondition honestly (a fold waiting on a block that the DAG has ALREADY pruned needs a
    /// chain both deeper than the retention window and stranded across a jump), and re-spelling the
    /// bookkeeping in the test would pin the spelling instead of the mechanism.
    #[cfg(test)]
    pub(crate) fn arm_fold_wait_for_test(&mut self, id: crate::block::BlockId) {
        self.note_fold_wait_on(Some(id), "a test-armed wait");
    }

    /// Drive the want-stall counter and the wanted set to a named shape. The counter's INCREMENT is one
    /// comparison inside `retire_held_record_ids`; what this drives is the VERDICT it feeds, which a
    /// fixture cannot otherwise reach without reproducing a peer whose index outlived its bytes.
    #[cfg(test)]
    pub(crate) fn force_da_want_stall_for_test(&mut self, stalled_ms: u64, wants: u64) {
        self.da_want_stall_passes = stalled_ms / 450; // the sweep cadence this was measured at
        self.da_want_stall_since_ms = if stalled_ms == 0 {
            0
        } else {
            Self::now_ms_for_stall().saturating_sub(stalled_ms)
        };
        self.wanted_record_ids.clear();
        for i in 0..wants {
            self.wanted_record_ids.insert(1_000 + i);
        }
    }

    /// Drive the no-progress counter to `n` passes. A fixture cannot spend ~27,000 real fold passes, and
    /// the counter's INCREMENT is one line in the `[fold-stuck]` branch that a pin cannot reach without
    /// also reproducing a stranded DAG; what this test drives is the VERDICT the counter feeds.
    #[cfg(test)]
    pub(crate) fn force_fold_no_progress_for_test(&mut self, n: u64) {
        self.fold_no_progress_passes = n;
    }

    /// The reset the fold performs the instant it folds anything.
    #[cfg(test)]
    pub(crate) fn clear_fold_no_progress_for_test(&mut self) {
        self.fold_no_progress_passes = 0;
        self.fold_wait_on = None;
    }

    /// G1g-v: the kept anchor body by its id and ONE wire encoding (postcard), compared live vs booted.
    #[cfg(test)]
    pub(crate) fn anchor_body_wire_for_test(&self) -> Option<(crate::block::BlockId, Vec<u8>)> {
        self.anchor_block_full.as_ref().map(|b| (b.id(), postcard::to_allocvec(b).expect("a held block encodes")))
    }

    /// The fold cursor, for the nameless-wedge pin.
    #[cfg(test)]
    pub(crate) fn fold_chain_tip_for_test(&self) -> Option<crate::block::BlockId> {
        self.fold_chain_tip
    }

    /// Whether block `id`'s record has folded here — so a pin reading "the node holds no record for X" can first
    /// assert X was FOLDED, and never passes because a stuck node folded nothing.
    #[cfg(test)]
    pub(crate) fn block_record_folded_for_test(&self, id: &crate::block::BlockId) -> bool {
        self.block_record_folded(id)
    }

    /// The blocks this node's A_tip fold stamped and that have not yet entered its window, each as `(id, held in the DAG?,
    /// whole body held anywhere?, in the window?, blue score)` — the census pin's view of a stamp left behind.
    #[cfg(test)]
    pub(crate) fn nf_stamps_diag_for_test(&self) -> Vec<(crate::block::BlockId, bool, bool, bool, u64)> {
        let dag = self.relay.dag();
        self.nf_unfolded_gen
            .keys()
            .map(|id| {
                (
                    *id,
                    dag.get(id).is_some(),
                    self.full_block_by_id(id).is_some_and(|b| !b.pow_proof.is_empty()),
                    self.block_window.contains(id),
                    dag.get(id).map_or(u64::MAX, |n| n.blue_score),
                )
            })
            .collect()
    }

    /// `(selected tip blue score, plain-heaviest tip blue score, fold cursor blue score, record fold depth, served_seq)` —
    /// the census pin's view of where this node's fold root stands.
    #[cfg(test)]
    pub(crate) fn fold_root_diag_for_test(&self) -> (u64, u64, u64, u64, u64) {
        let dag = self.relay.dag();
        let score = |id: Option<crate::block::BlockId>| id.and_then(|i| dag.get(&i)).map_or(u64::MAX, |n| n.blue_score);
        let heaviest = dag.tips().iter().copied().max_by_key(|t| dag.canonical_order_key(t));
        (score(dag.selected_tip()), score(heaviest), score(self.fold_chain_tip), dag.record_fold_depth(), self.served_seq)
    }

    /// Every buffered unfolded block as `(id, whole body?, record folded?, record ordinal, blue score, in the window?)` —
    /// for a census pin naming why one node still buffers a block its peers windowed.
    #[cfg(test)]
    pub(crate) fn unfolded_diag_for_test(&self) -> Vec<(crate::block::BlockId, bool, bool, Option<u64>, u64, bool)> {
        let dag = self.relay.dag();
        self.unfolded_blocks
            .iter()
            .map(|b| {
                let id = b.id();
                (
                    id,
                    !b.pow_proof.is_empty(),
                    self.block_record_folded(&id),
                    self.da_ord_mem.get(&Self::da_record_id_for_block(&id, 0)).copied(),
                    dag.get(&id).map_or(u64::MAX, |n| n.blue_score),
                    self.block_window.contains(&id),
                )
            })
            .collect()
    }

    /// Block `id`'s staged record row as this node holds it (the notes, in row order), for a pin comparing one node's
    /// row across its own restart (§8.14: a resume places, never re-grafts).
    #[cfg(test)]
    pub(crate) fn record_row_for_test(&self, id: &crate::block::BlockId) -> Option<Vec<Vec<u8>>> {
        self.da_mem.get(&Self::da_record_id_for_block(id, 0)).map(|row| row.0.clone())
    }

    /// TEST FIXTURE — drop block `id`'s record row from this node's store (its bytes have "not arrived yet"), so its fold
    /// step is REFUSED at the record fold after its objects and bond steps ran — the retried-fold shape a live mesh meets
    /// whenever a block lands before its record. The fold then wants the record by id, and the production fetch path
    /// (`deliver_wanted_records_for_test` → `accept_fetched_record`) brings it back from a peer.
    /// cons: none — test builds only; it removes one row and adds nothing.
    #[cfg(test)]
    pub(crate) fn withhold_block_record_for_test(&mut self, id: &crate::block::BlockId) -> bool {
        self.da_mem.remove(&Self::da_record_id_for_block(id, 0)).is_some()
    }

    /// This node's own frontier snapshot, built from the SAME public accessors the serve path uses, so a
    /// pin exercises the real bundle shape and not a second spelling of it.
    #[cfg(test)]
    pub(crate) fn frontier_snapshot_for_test(&self) -> crate::sync::FrontierSnapshot {
        crate::sync::FrontierSnapshot {
            root: *self.note_frontier_root().as_bytes(),
            height: self.note_frontier_count(),
            peaks_hex: self.spend_frontier_peaks_hex(),
        }
    }

    /// TESTS: how many spent leaves this node's sparse VIEW holds (`None` when it holds no view) — a diagnostic count.
    #[cfg(test)]
    pub(crate) fn sparse_view_spent_leaf_count_for_test(&self) -> Option<usize> {
        self.sparse_work.as_ref().map(|t| t.spent_leaf_count())
    }

    /// TEST — the producer's own note carrier over `real_notes`, for a pin outside this module that lays a rogue block the way
    /// a producer seals one (the rogue-role census).
    #[cfg(test)]
    pub(crate) fn note_commitment_carrier_for_test(&self, real_notes: &[u8]) -> Vec<u8> {
        self.assemble_note_commitment_carrier(real_notes)
    }

    /// TEST LEVER (runtime-level pins only): place this node at a certified record position without a
    /// full DSYNC bundle — the shape a jumper is in. Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn test_raise_certified_position(&mut self, position: u64) {
        if position > self.served_seq {
            self.served_seq = position;
        }
    }

    /// TEST LEVER (runtime-level pins only): register a by-id BYTE want, the state a node is in while
    /// a copath needs a record it does not hold. Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn test_want_record_by_id(&mut self, rid: u64) {
        self.wanted_record_ids.insert(rid);
    }

    /// TEST LEVER (readiness pins only): name an ordinal-space hole, the state a node is in when a row
    /// it needs was skipped. Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn want_ordinal_for_test(&mut self, ordinal: u64) {
        self.wanted_ordinals.insert(ordinal);
    }

    /// TEST LEVER (diagnostics): the by-ordinal wants as values, so a pin can NAME the ordinal a
    /// stuck want holds instead of only counting it. Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn wanted_ordinals_for_test(&self) -> Vec<u64> {
        self.wanted_ordinals.iter().copied().collect()
    }

    /// TEST LEVER (diagnostics): the by-ORDINAL `da_load`-miss wants (`da_wanted`) as values, with
    /// the fold position beside them — so a pin can tell a hole BELOW the fold cursor (a
    /// folded-then-released regenerable row, not missing) from one above it. Never compiled in.
    #[cfg(test)]
    /// TEST LEVER (diagnostics): the BY-ID byte wants (`da_wanted_ids`). This is the set that feeds
    /// `missing_record_count`, and it is hard-capped at `TX_REQ_FIXED_COUNT`, so its LENGTH cannot
    /// distinguish "32 holes" from "at least 32 holes" — a reader that needs the difference must look at
    /// the members, which is what this hands back.
    pub(crate) fn da_wanted_ids_for_test(&self) -> Vec<u64> {
        self.da_wanted_ids.borrow().iter().copied().collect()
    }

    /// TEST LEVER (scenario diagnostics): is this commitment OWNED — filed to an account target or a
    /// pending bucket? Ownership is the discriminator between a real note and the ownerless idle-block
    /// cover seed (they are byte-identical by design). Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn note_is_owned_for_test(&self, cm: &[u8; 32]) -> bool {
        self.note_target_addr.contains_key(cm) || self.pending_bucket.contains_key(cm)
    }

    /// TEST LEVER (scenario diagnostics): where a commitment is filed, and whether the record it is filed
    /// at genuinely CARRIES it as a real note (`da_load` = the reals; the 255 cover slots are regenerated
    /// at serve and are in no record's real list). Never compiled into the binary.
    #[cfg(test)]
    pub(crate) fn note_filing_for_test(&self, cm: &[u8; 32]) -> (Option<u64>, bool, bool) {
        let addr = self.note_target_addr.get(cm).copied();
        let pending = self.pending_bucket.contains_key(cm);
        let real_at_addr = addr
            .and_then(|a| self.da_load(a))
            .map(|reals| reals.iter().any(|n| n.len() >= 32 && n[..32] == cm[..]))
            .unwrap_or(false);
        (addr, pending, real_at_addr)
    }

    /// ⭐ THE RANGE-VERIFIED NAMED HOLES — the by-ordinal want entries that are REAL in range terms:
    /// inside the tracked span (at or above the retention floor — ordinals released below it are
    /// proven by ladder rung folds, the same floor the rolling reseed walks from — and below the
    /// certified position, since nothing past it exists to be owed) and genuinely ROWLESS on this
    /// node. An entry naming a row this node holds, or a coordinate outside the span, is request-list
    /// residue and counts for nothing. De-duplicated across the two by-ordinal sets.
    /// cons: none — both source sets are refused at TX_REQ_FIXED_COUNT (32) by every insert site, so
    /// this is ≤ 2 × 32 = 64 map reads per call (~64 × 40 ns ≈ 2.6 µs): f(protocol constants), never
    /// f(history, height, records or notes). No state is stored.
    /// The named-hole term of `sidecar_gap_count`, for a scenario's failure message.
    #[cfg(test)]
    pub(crate) fn sidecar_named_hole_count_for_test(&self) -> u64 {
        self.sidecar_named_hole_count()
    }

    /// ⛔⛔⛔ HOW MANY DISTINCT RECORDS CARRY THIS COMMITMENT. The carriage-count primitive.
    ///
    /// `da_seq_at_note_cm` answers WHERE a commitment is and stops at the first hit, which is right for
    /// building a membership proof and useless for the question this answers: was the same value
    /// carried TWICE? That question is not conservation and cannot be reached from it — in the
    /// 2026-09-03 DEX double-payout BOTH copies were individually legitimate, every amount balanced,
    /// and the maker's lot still paid out twice. A sum cannot see a duplicate; only a count can.
    ///
    /// The answer must be 0 or 1 for every real commitment. 2 means one note occupies two records, so
    /// two independent membership proofs exist for money that was received once.
    ///
    /// cons: O(records held x notes per record) per call, and it is called at QUIESCENCE over the
    /// schedule's own real notes — never per block, never on a serve path. No state, nothing retained.
    /// How many orders this node's book holds — the DEX surface's one consensus-visible size.
    ///
    /// ⛔ THIS IS AN ECOSYSTEM FUNDS-SAFETY READ, not a statistic. The 2026-09-03 double payout was a
    /// fill whose BURN WAS LOCAL: the node that saw the fill retired the maker's order, the node that
    /// did not still held it, and the same lot paid out twice. Both nodes were individually correct.
    /// The order book is therefore exactly the kind of state that must be a FUNCTION OF THE CHAIN, and
    /// the only way to see it is to ask a node that was fed nothing but blocks.
    ///
    /// cons: one `len()`; nothing is stored and no order content is exposed — a COUNT, never an owner,
    /// price or amount.
    /// ⛔ SELF-PROOF ONLY — put a resting order in this node's book that no block carried.
    ///
    /// The violating state for the ORDER-BOOK half of `I-CP`: a maker's lot alive on one node and
    /// absent from a chain-only replay. That is the 2026-09-03 double payout exactly — the fill's burn
    /// was local, so the order stayed live everywhere else and the same lot paid twice while every
    /// node self-verified correctly. Bypasses `post` deliberately: a VALID order is not the violation,
    /// an order the chain never carried is.
    ///
    /// Nothing but the refutation lane may call it; the name says so at every call site.
    /// ⛔ SELF-PROOF ONLY — a serve position the chain does not support.
    ///
    /// A wallet FOLDS THE SERVED STREAM TO ITS END to name a spend endpoint, so a node claiming a
    /// position the chain cannot back hands every spender an endpoint no peer will honour. This is the
    /// recorded cause of "sends that worked on a young chain and stopped forever on an older one".
    #[cfg(test)]
    pub(crate) fn force_served_seq_for_selfproof(&mut self, seq: u64) {
        self.served_seq = seq;
    }

    /// ⛔ SELF-PROOF ONLY — a finality height the chain has not reached.
    ///
    /// A party ahead here treats as IRREVERSIBLE what the mesh may still reorg: a payment declared
    /// final that can still be undone.
    #[cfg(test)]
    pub(crate) fn force_finalized_height_for_selfproof(&mut self, h: u64) {
        self.finality.force_finalized_height_for_selfproof(h);
    }

    /// ⛔ SELF-PROOF ONLY — a spent-set size the chain did not produce.
    ///
    /// The nullifier set is what refuses a SECOND spend. Builds the violating state so that
    /// comparison is proven able to go red: two nodes disagreeing here disagree about what has already
    /// been spent, and one will accept a double-spend the other refuses.
    #[cfg(test)]
    pub(crate) fn force_nf_leaves_for_selfproof(&mut self, leaves: u64) {
        self.nf_leaves = leaves;
    }

    /// ⛔ SELF-PROOF ONLY — a mint collateral ratio the chain did not set.
    ///
    /// Not a disagreement about STATE but about the RULES: a node running a different
    /// `mint_ratio_bps` authorises mints its peers refuse, against collateral that does not cover
    /// them — and every gate on that node agrees with itself perfectly, because they are all measured
    /// against the same wrong yardstick.
    /// ⛔ NOTE FOR THE AUTHORITY MANIFEST: `Node::params` is NOT what `Node::params()` returns.
    /// The accessor reads `self.relay.dag().params()`, so the DAG's copy is the one every gate is
    /// measured against and the field is a second copy. Writing the field alone changes nothing — the
    /// refutation caught exactly that (15000 -> 15000) — so this goes through `set_params`, which
    /// updates the DAG and the mempool together. Two copies of the rules with one accessor is the
    /// authority question this manifest exists to ask; recorded rather than quietly worked around.
    #[cfg(test)]
    pub(crate) fn force_mint_ratio_bps_for_selfproof(&mut self, bps: u32) {
        let mut p = self.params().clone();
        p.mint_ratio_bps = bps;
        self.set_params(p);
    }

    /// ⛔ SELF-PROOF ONLY — a membership tip no block produced (a holder would prove against a tree
    /// its peers do not have).
    #[cfg(test)]
    pub(crate) fn force_membership_tip_root_for_selfproof(&mut self, root: crate::spend_frontier::Digest4) {
        self.membership_tip_root = root;
    }

    /// ⛔ SELF-PROOF ONLY — an L2 settlement root no block produced.
    #[cfg(test)]
    pub(crate) fn force_l2_state_root_for_selfproof(&mut self, root: [u8; 32]) {
        self.l2_state_root = root;
    }

    /// ⛔ SELF-PROOF ONLY — a retention-endowment commitment no door produced (the doors have no production caller
    /// yet, so every real node holds the genesis commitment; DB-357's pin needs a value that differs from it).
    #[cfg(test)]
    pub(crate) fn force_retention_endowment_for_selfproof(&mut self, d: crate::spend_frontier::Digest4) {
        self.peg.adopt_certified_retention_endowment(d);
    }

    /// ⛔ SELF-PROOF ONLY — an account commitment no block produced.
    ///
    /// The account commitment is WHERE EACH RECIPIENT'S NOTES ARE FILED. A party holding one the chain
    /// did not produce has its holders' money indexed somewhere its peers do not agree with, and a note
    /// nobody can locate is a note nobody can spend. Builds that violating state so the comparison in
    /// `Sim::cold_peer_verdict` is proven reachable rather than assumed.
    #[cfg(test)]
    pub(crate) fn force_account_acc_for_selfproof(&mut self, acc: crate::hash::Hash32) {
        self.account_acc = acc;
    }

    /// ⛔ SELF-PROOF ONLY — a cover-conf accumulator no block produced.
    ///
    /// Advanced per block from the block's own confidential blobs, so two nodes that disagree here have
    /// folded different spend sets. Builds that violating state.
    #[cfg(test)]
    pub(crate) fn force_nf_cover_conf_acc_for_selfproof(&mut self, acc: [u8; 32]) {
        self.nf_cover_conf_acc = acc;
    }

    /// ⛔ SELF-PROOF ONLY — a Letter accumulator no block produced.
    ///
    /// Builds the violating state for the LETTER half of `I-CP`, so that comparison is proven
    /// reachable rather than assumed. Nothing but the refutation lane may call it.
    #[cfg(test)]
    pub(crate) fn force_letter_acc_for_selfproof(&mut self, acc: [u8; 32]) {
        self.letter_acc = acc;
    }

    /// ⛔ SELF-PROOF ONLY — a `@username` directory accumulator no block produced.
    ///
    /// The sharpest of the ecosystem surfaces: `#64 Pay @username` sends money to whoever the directory
    /// resolves, so a directory that is not a function of the chain misdirects a PAYMENT, not just a
    /// name lookup. Builds that violating state so the comparison is proven reachable.
    #[cfg(test)]
    pub(crate) fn force_dir_acc_for_selfproof(&mut self, acc: [u8; 32]) {
        self.directory.acc = acc;
    }

    // ────────────────────────────────────────────────────────────────────────────────────────────
    // BATCH 5 OF THE AUTHORITY MANIFEST — the violating states for the `ChainDerived` fields whose
    // comparisons land in `Sim::cold_peer_verdict` alongside them.
    //
    // ⛔ EVERY ONE OF THESE IS PAIRED WITH A NON-VACUITY ASSERTION AT ITS CALL SITE. A setter that
    // writes a field the projection does not read moves NOTHING, and the refutation then passes
    // against a violating state that was never built — the exact failure `record_note_payload_for`
    // with an invented block id produced (it lands in `da_mem` and never takes an ORDINAL, so no
    // counter moves). Each was chosen by reading the projection first: the census entry, the accessor
    // body, or the snapshot field that actually reads the field being mutated.
    //
    // ⛔ WHERE A PRODUCTION DOOR ALREADY BUILDS THE STATE, NO SETTER IS ADDED. The sidecar family
    // (`da_recv_mem`, `da_del_mem`, `da_tags_mem`) and the account buckets are driven
    // through `adopt_ledger_sidecars*` / `adopt_account_bucket`, which is what a peer-served page
    // does — a better violating state than a field poke, because it is the real writer.
    // ────────────────────────────────────────────────────────────────────────────────────────────

    /// ⛔ SELF-PROOF ONLY — a canonical DA address top the chain never wrote.
    ///
    /// `da_top` bounds the serve and backfill walks. A node claiming a higher one advertises record
    /// addresses no block produced; one claiming a lower one truncates the served range, and a
    /// recipient's record falls outside what any peer will hand over.
    #[cfg(test)]
    pub(crate) fn force_da_top_for_selfproof(&mut self, top: u64) {
        self.da_top = top;
    }

    /// ⛔ SELF-PROOF ONLY — a DA floor the chain never wrote.
    ///
    /// `da_base` is the LOWEST address this node ever wrote, and synthesis of an idle block's cover
    /// shape is valid only at or above it. A node holding a base below the chain's invents a cover
    /// shape for a height it never applied — measured once as 512 leaves served for ONE ingested
    /// block.
    #[cfg(test)]
    pub(crate) fn force_da_base_for_selfproof(&mut self, base: u64) {
        self.da_base = base;
    }

    /// ⛔ SELF-PROOF ONLY — an absence-fold position the chain did not reach.
    ///
    /// `nf_fold_seq` advances EXACTLY with `nf_unspent_acc` and is the key of the absence-fold
    /// sidecar. A node off by one keys every served fold row at a block other than the one it
    /// describes, and a spender folding that stream can never reproduce A_tip — its absence proof is
    /// refused and its money will not move.
    #[cfg(test)]
    pub(crate) fn force_nf_fold_seq_for_selfproof(&mut self, seq: u64) {
        self.nf_fold_seq = seq;
    }

    /// ⛔ SELF-PROOF ONLY — a served-prefix membership accumulator no block produced.
    ///
    /// THIS IS THE VALUE A SPENDER CAN ACTUALLY BUILD: a wallet folds what `/membership_roots`
    /// served and proves against the result. A node holding one the chain does not derive refuses
    /// the very proof its own stream taught the wallet to build — measured on a real cross-device
    /// send as `MEMBERSHIP_PROOF_INVALID`, with nothing wrong on either side.
    #[cfg(test)]
    pub(crate) fn force_served_membership_acc_for_selfproof(&mut self, acc: crate::spend_frontier::Digest4) {
        self.served_membership_acc = acc;
    }

    /// ⛔ SELF-PROOF ONLY — a locked bond note no block carried.
    ///
    /// The locked note is the value that BACKS a validator's weight and is deliberately unspendable
    /// while bonded. A bond the chain never carried is free Sybil weight: weight admitted against
    /// collateral no block ever locked. (`admit_bond_unverified` is deliberately NOT reused — it also
    /// admits the validator, so the bonded-set comparison would answer first and this field's own
    /// comparison would never be exercised.)
    #[cfg(test)]
    pub(crate) fn selfproof_plant_bond_locked_row(&mut self, id: [u8; 32]) {
        let bonded_note = id.to_vec();
        self.bond_locked.insert(id, bonded_note);
    }

    /// ⛔ SELF-PROOF ONLY — a bond height anchor no block carried.
    ///
    /// `bond_height + stake_lock_blocks` is the unbond delay. An anchor the chain did not set lets a
    /// bond mature early on this node — a flash-bond exit that drains the bond backing bridge
    /// security the instant an attack completes.
    #[cfg(test)]
    pub(crate) fn selfproof_plant_bond_height_row(&mut self, id: [u8; 32], height: u64) {
        self.bond_height.insert(id, height);
    }

    /// ⛔ SELF-PROOF ONLY — a spend ANCHOR the chain never committed.
    ///
    /// A wallet's note copath is frozen at its receipt anchor forever, and the spend proves
    /// in-circuit that that anchor is a leaf under `root_history_root()`. A node holding an anchor
    /// set the chain did not produce accepts spends against an anchor no block ever committed, and
    /// refuses the anchors its peers accept. One O(1) append to the existing O(DEPTH) peak spine.
    #[cfg(test)]
    pub(crate) fn force_root_history_append_for_selfproof(&mut self, leaf: [u8; 32]) -> bool {
        self.root_history
            .append(crate::spend_frontier::note_leaf_of(&leaf))
    }

    #[cfg(test)]
    pub(crate) fn post_selfproof_resting_order(&mut self) {
        let order = Self::selfproof_resting_order();
        self.order_book.insert_selfproof_entry(order);
    }

    /// DB-402 R1 CALIBRATION — DB-401's exact shape: the SAME offer with its maker's membership bind dropped (what every
    /// non-posting book held before DB-401). Same count, hollow content: only a content comparison can see it.
    #[cfg(test)]
    pub(crate) fn post_selfproof_resting_order_without_its_bind(&mut self) {
        let mut order = Self::selfproof_resting_order();
        order.membership_carrier.clear();
        order.membership_tip.clear();
        self.order_book.insert_selfproof_entry(order);
    }

    /// DB-402 R1: a content digest of the whole book (every offer, every byte its `Debug` prints — terms, maker half, bind,
    /// payout), order-insensitive across levels. Replaces the cold-peer verdict's COUNT, which a hollow copy passes.
    #[cfg(test)]
    pub(crate) fn order_book_digest_for_audit(&self) -> (u64, usize) {
        restart_census_fields::canonical_debug_of(&self.order_book)
    }

    #[cfg(test)]
    pub(super) fn selfproof_resting_order() -> crate::order_book::RestingOrder {
        use usdm_decider::whir_rec_block::{MakerHalfPublic, OrderTerms};
        crate::order_book::RestingOrder {
                terms: OrderTerms {
                    lot: 1,
                    pay_b: 1,
                    asset_a: [0u64; 3],
                    asset_b: [1u64; 3],
                    expires_at_height: u64::MAX,
                },
                maker: MakerHalfPublic {
                    nullifier: [7u64; 8],
                    leaf_commit: [8u64; 8],
                    payout_cm: [9u64; 8],
                },
                maker_bytes: Vec::new(),
                payout_note: Vec::new(),
                membership_carrier: crate::order_book::test_membership_bind().0,
                membership_tip: crate::order_book::test_membership_bind().1,
                payout_clue: Vec::new(), // the refutation lane's entry bypasses the post door; nothing fills it
            }
    }

    /// The OLI locator-tag rows this node currently HOLDS, as `(address, tags)`.
    ///
    /// ⭐ Same contract — `evict_orphan_row` removes a `da_tags_mem` row with its record.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: test-only. ⛔ A LOCATOR TAG IS A `which-item` VALUE, so this is
    /// `cfg(test)` and returns to this process's own harness ONLY — it is never served, logged or sent.
    /// The comparison that consumes it prints COUNTS, never a tag.
    #[cfg(test)]
    pub(crate) fn da_tag_rows_for_test(&self) -> Vec<(u64, Vec<(u8, [u8; crate::oli::K_BYTES])>)> {
        let mut out: Vec<(u64, Vec<(u8, [u8; crate::oli::K_BYTES])>)> = self
            .da_tags_mem
            .iter()
            .map(|(k, v)| {
                let mut t = v.clone();
                t.sort_unstable();
                (*k, t)
            })
            .collect();
        out.sort_unstable_by_key(|(a, _)| *a);
        out
    }

    /// The ordinal → address rows this node currently HOLDS.
    ///
    /// ⭐ Same contract — `evict_orphan_row` and four other sites remove entries as records are
    /// superseded or orphaned. What is chain-derived is WHICH ADDRESS an ordinal names, not how many
    /// ordinals this node still remembers.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: test-only; local coordinates, no note, tag, amount, key or owner.
    #[cfg(test)]
    pub(crate) fn da_ord_rev_rows_for_test(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = self.da_ord_rev_mem.iter().map(|(o, a)| (*o, *a)).collect();
        out.sort_unstable_by_key(|(o, _)| *o);
        out
    }


    #[cfg(test)]
    pub fn test_roots_run_debug(&self) -> String {
        format!(
            "before={:x?} target={:x?} served_acc={:x?} ord_at_before={:?} certified_pos={} ord_top={} genesis_rid={:?} rev={:x?}",
            self.note_body_acc_before[0],
            self.note_body_acc_target[0],
            self.served_membership_acc[0],
            self.da_ordinal_at_membership_acc(self.note_body_acc_before),
            self.certified_record_position(),
            self.da_ord_top,
            self.dag().genesis().map(|g| Self::da_record_id_for_block(&g, 0)),
            {
                let mut ords: Vec<u64> = self.da_macc_rev_mem.values().copied().collect();
                ords.sort_unstable();
                let mut f: Vec<u64> = self.da_macc_fwd_mem.keys().copied().collect();
                f.sort_unstable();
                let mut rows: Vec<u64> = self.da_ord_rev_mem.keys().copied().collect();
                rows.sort_unstable();
                (f.clone(), self.da_ord_top, rows, self.served_fold_count())
            }
        )
    }

    /// ⭐⭐⭐ DB-150 TEST HELPER — PUT A NOTE ON CHAIN AND BUILD ITS MEMBERSHIP CROSS-BIND.
    ///
    /// Every spend this chain admits must prove its input note is in the append-only note frontier. A
    /// fixture that proves a half over a note nobody ever recorded is proving a trade between notes that
    /// do not exist — which is exactly what DB-150 measured — so a fixture that wants a SETTLED verdict
    /// has to do what a real wallet does: receive the note on chain first, then prove where it sits.
    ///
    /// Produces one block carrying `cm`, then folds the carrier over every block this node has folded,
    /// returning `(carrier_bytes, endpoint_bytes)` in the 3-slot endpoint shape `check_bond_membership`
    /// reads. Test-only: production carriers are built by the spender from served data.
    #[cfg(test)]
    pub(crate) fn plant_note_and_bind_for_test(
        &mut self,
        cm: &[u8; 32],
        binder: crate::spend_frontier::Digest4,
        tag: &[u8],
        now_ms: u64,
    ) -> Option<(Vec<u8>, Vec<u8>, Block)> {
        use usdm_decider::note_membership_air::NoteMembershipCarrier;
        let mut note = vec![0u8; crate::cover::PQ_NOTE_BYTES];
        note[..32].copy_from_slice(cm);
        // ⭐ §BA — THE NOTE AND THE OBJECT THAT JUSTIFIES IT, together, exactly as the production credit
        // paths stage them. A note nothing justifies is refused at every PEER's graft door, so a fixture
        // that staged the note alone would put a note on the producer's chain and nowhere else.
        self.stage_credit_note(note.clone());
        self.stage_credit_justifier(
            crate::bridge_credit_tx::BridgeCreditTx {
                deposit_id: *cm,
                asset_tag: usdm_decider::whir_rec_block::USDM_ASSET_TAG,
                amount: 1,
                note: note.clone(),
                owner_clue: Vec::new(),
                attestors: Vec::new(),
            }
            .wire(),
        );
        let Some(blk) = self.produce(now_ms, Hash32::hash(tag), Hash32::hash(b"membership-mc")) else {
            eprintln!("[plant] no block produced");
            return None;
        };
        // Its ACTUAL record address, never a hardcoded sub 0 (see `carry_notes_in_a_block_for_test`).
        let rid = self.record_addr_for_block_or_canonical(&blk.id());
        // Which slot did it land in? The record's own notes answer; a fixture never guesses a position.
        let Some(notes) = self.da_record_notes(rid) else {
            eprintln!("[plant] the producer holds no record for its own block");
            return None;
        };
        let Some(slot) = notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .position(|n| n.len() >= 32 && n[..32] == cm[..])
        else {
            eprintln!(
                "[plant] the staged note did not ride the block ({} note slot(s) recorded)",
                notes.len() / crate::cover::PQ_NOTE_BYTES
            );
            return None;
        };
        let slot = slot as u8;
        let Some(leaf) = self.da_block_leaves(rid).and_then(|l| l.get(slot as usize).copied()) else {
            eprintln!("[plant] no frontier leaf at the note's own slot");
            return None;
        };
        let Some((sibs, dirs, want_root)) = self.da_note_copath_in_block(rid, slot) else {
            eprintln!("[plant] the producer serves no in-block copath for its own note");
            return None;
        };
        let mut carrier =
            NoteMembershipCarrier::new(leaf, want_root, Self::MEMBERSHIP_GENESIS_ACC, binder, crate::spend_frontier::TEST_LC_BLIND);
        if !carrier.attach_membership(leaf, &sibs, &dirs) {
            eprintln!("[plant] the in-block copath does not prove the note in its own block root");
            return None;
        }
        // DB-213c: the ONE-STEP form — the note's own record root, proven by the DIRECT membership proof
        // attached above. `finalize_one_step` reads only that attached proof, so no `step()` runs here: it
        // would pay two merged recursive proves whose output nothing reads (lane-prover-shapes, 2026-09-25).
        let Ok((proof, acc, tip_prev, tip_root)) = carrier.finalize_one_step() else {
            eprintln!("[plant] the carrier did not certify");
            return None;
        };
        let mut tip = Vec::with_capacity(4 * crate::spend_frontier::DIGEST_LANE_BYTES + 8);
        for d in [Self::MEMBERSHIP_GENESIS_ACC, tip_prev, tip_root, acc] {
            tip.extend_from_slice(&crate::spend_frontier::digest_to_lane_bytes(&d));
        }
        tip.extend_from_slice(&rid.to_le_bytes());
        // The block travels back so a peer can graft it: a note is only on THE chain when every party
        // holds the block that carried it, and a fixture that plants privately proves nothing.
        Some((proof, tip, blk))
    }

    /// DB-302: a by-ordinal byte want this node holds a ROW for, deferred only because the open headers-first span cannot
    /// judge its position. It is OWED, not satisfied: the Sim's range lane reads this so that an empty askable list
    /// (`wanted_record_ordinals`) is never read as "nothing owed" (review, lane-wallet-cover).
    #[cfg(test)]
    pub(crate) fn headers_first_defers_a_record_want(&self) -> bool {
        self.wanted_ordinals
            .iter()
            .copied()
            .chain(self.da_wanted.borrow().iter().copied())
            .any(|o| self.da_addr_at_ordinal(o).is_some() && self.headers_first_door_open_at(o))
    }

    /// Test-only: hold a span blob as if sealed here, so a serve-side pin has something to serve.
    #[cfg(test)]
    pub(crate) fn hold_ladder_span_for_test(&mut self, span_index: u64, blob: Vec<u8>) {
        self.da_ladder_mem.insert(span_index, blob);
    }

    /// How many parked payload holes name a record whose bytes this node ALREADY HOLDS — a hole that
    /// is not a hole. Splits "the mesh still owes me bytes" from "I was owed and never wrote it off",
    /// which are opposite defects with opposite fixes.
    #[cfg(test)]
    pub(crate) fn payload_gap_stale_count_for_test(&self) -> usize {
        self.payload_gap
            .values()
            .filter(|rid| self.da_record_held(**rid))
            .count()
    }

    /// Number of note commitments appended to the membership frontier so far (the next leaf index). Equal to
    /// `spend_frontier.count()` — every note is appended to the (now sole) Poseidon frontier.
    /// Test-only door: append ONE leaf to the note frontier, so a test can prove an ADOPTED frontier is
    /// genuinely extensible (the same next leaf on two nodes must keep their roots equal). Production code
    /// appends only through `record_note_payload_for`, which folds a whole 256-leaf record.
    #[cfg(test)]
    pub(crate) fn append_note_leaf_for_test(&mut self, leaf: crate::spend_frontier::Digest4) {
        self.spend_frontier.append(leaf);
    }

    /// Test-only accessors for the treeless double-spend gate: the exact calls the produce path makes.
    #[cfg(test)]
    pub(crate) fn sparse_acc_verify_unspent_for_test(
        &self,
        nf: &[u8; 32],
        copath: &[crate::spend_frontier::Digest4],
    ) -> bool {
        self.sparse_acc.verify_unspent(nf, copath).is_ok()
    }

    /// DIAGNOSTIC (test-only): the authority root, the copath-source root, and whether a FRESH tag can be
    /// proved unspent right now. The three together say whether this node can still witness a spend at all.
    #[cfg(test)]
    pub(crate) fn sparse_lockstep_for_test(&self) -> ([u8; 32], Option<[u8; 32]>, bool) {
        let probe = Hash32::hash(b"sparse-lockstep-probe").0;
        (
            self.sparse_acc.root_bytes(),
            self.sparse_work.as_ref().map(|t| t.root_bytes()),
            self.sparse_acc
                .verify_unspent(&probe, &self.da_sparse_copath(&probe))
                .is_ok(),
        )
    }

    #[cfg(test)]
    pub(crate) fn sparse_acc_verify_and_insert_for_test(
        &mut self,
        nf: &[u8; 32],
        copath: &[crate::spend_frontier::Digest4],
    ) -> bool {
        self.sparse_acc.verify_and_insert(nf, copath).is_ok()
    }

    /// Every position this node has FILED in an account bucket — `(bucket, seq)`. Test-only: it is the exact
    /// value a recipient's wallet receives, so it is the only thing that can catch a bug in what is filed.
    #[cfg(test)]
    /// ⛔⛔⛔ AN ENTRY IS SEALED — OPEN IT, NEVER SLICE IT. This read `raw[32..40]` as a little-endian u64 and
    /// called that the filed position. Those bytes are ML-KEM CIPHERTEXT: an entry is sealed to the recipient,
    /// so `(cm, seq, slot)` only exists after `open_entry` with the recipient's decapsulation key.
    ///
    /// The number it produced was therefore ciphertext read as an integer, and it could not match any address
    /// the node ever wrote. MEASURED: it reported a filed position of 5,514,385,592,605,529,513 while the store
    /// held six records at 1.9e16–2.0e17 — outside the range `da_record_id_for_block` can even produce (56 bits
    /// masked, times 4). Every "the filed position does not resolve" conclusion traced back to this accessor,
    /// not to the protocol, and it survived because the value LOOKED like a plausible address.
    ///
    /// Takes the recipient's `scan_dk` because that is the only thing that can open the entry — a node cannot,
    /// and must not be able to, read what it stores.
    pub(crate) fn account_bucket_positions_for_test(&self, scan_dk: &[u8]) -> Vec<([u8; 32], u64)> {
        let mut out = Vec::new();
        for (bucket, entries) in self.account_buckets.iter() {
            for raw in entries {
                if let Some(e) = crate::account_da::open_entry(scan_dk, raw) {
                    out.push((*bucket, e.seq));
                }
            }
        }
        out
    }

    // ⛔ `da_store_nf_fold_by_pre` DELETED 2026-08-15 — backed by a PER-BLOCK RAM store (`da_fold_mem` /
    // `da_nf_pre_mem`), one entry per block forever. Its readers were TEST-ONLY; the wallet takes
    // only the O(1) base and the spend gate answers from the node's own roots. Readers AND writers
    // deleted together — removing one alone leaves the map filling in silence.

    // ⛔ `nf_fold_inputs_at_pre_root` DELETED 2026-08-15 with its only caller (the parked-block TxReq
    // serve) and its store `da_nf_pre_mem`. One entry per block in RAM, answering a question no node asks
    // now that blocks fold at accept from carried tags.

    // ⛔ `pending_fold_pre_roots`, `accept_served_fold_inputs`, `has_pending_folds`, `nf_inputs_for` and
    // `drain_pending_nf_folds` RETIRED with the stash (DB-353 landing 2, spec §13.5 item 2): the drain looked its
    // stash up by `sparse_acc`'s Merkle root while the stash was keyed by an A_tip projection, so it could never
    // unlock; the fold it retried is a pure function of the block, so a retry could only fail the same way. What the
    // drain also did — release the bodies of folded blocks — is `release_folded_tx_evictions`, called directly.

    /// ⭐ THE FILL SUBMITTER'S RECURSIVE ABSENCE CARRIER (hole-closure 2026-09-06, lane A).
    ///
    /// A settlement's inputs are born WITH the settlement — the maker and taker tags plus the
    /// tx-id-seeded cover set — so the freshest recursive absence carrier any submitter can hold for
    /// that exact set is `NfAbsenceBatchCarrier` AT ITS GENESIS BASE: zero blocks folded, an empty
    /// proof span. This returns precisely that state as the wire witness. The DECLARED genesis base
    /// is what separates a submitter attesting an empty span from a tx that simply carries nothing
    /// (the default witness's zero base stays refused at the door), and the door closes the span
    /// itself from state it already wrote down — `nf_absent_by_reconstructed_tip`, the base-state
    /// lane, which also demands a verifying live-root copath per tag.
    ///
    /// Self-built from this node's own O(1) state, liveness-trustless, never a witness server. A
    /// node that did not fold from the genesis base returns `None`: it cannot vouch for the span it
    /// leapt, the door on any honest peer would refuse the shape anyway, and publishing a witness
    /// this node cannot itself admit would be a settlement that works on one device and dies on the
    /// next — fail-closed, publish nothing.
    /// ⭐ A REPRODUCER MUST CONTROL THE NODE'S SECRETS, NOT JUST ITS OPS.
    ///
    /// `derive_node_miner_seed` draws a fresh ML-DSA keypair per node, which is exactly right in
    /// production — each node's decoys must be its own, and §CE now derives the nullifier decoy secret from
    /// this seed. But a replay lane that re-runs the SAME `(parties, seed, ops)` and expects the same
    /// consensus state cannot tolerate a secret drawn from the OS: MEASURED as `D-37 HAS ESCALATED` with
    /// `uns_root`, `uns_fold`, `uns_leaves` and `nf_count` identical and only `nf_acc`/`nf_root` moving —
    /// different decoys, therefore different tags, therefore a different spent-state accumulator.
    ///
    /// ⛔ THIS WEAKENS NOTHING IN PRODUCTION: there is no production caller and the default path still
    /// draws fresh randomness. It lets `Sim` derive each party's seed from its OWN seed and index, so a
    /// reproducer reproduces — which is the whole contract of the corpus.
    #[cfg(test)]
    pub(crate) fn set_miner_seed_for_test(&mut self, seed: [u8; 32]) {
        self.miner_seed = seed;
        self.reward_recipient = Self::initial_reward_recipient(&seed);
        self.pow_miner = crate::pow::PowMiner::new();
    }

    /// ⭐⭐⭐ §CC — A NODE DECLARES **ITS OWN BASE**, WHICH IS GENESIS OR A CERTIFIED ONE. BOTH ARE CHAIN
    /// VALUES; NEITHER IS THIS NODE'S OPINION.
    ///
    /// ⛔⛔⛔ THIS USED TO RETURN `None` FOR ANY NODE WHOSE BASE WAS NOT GENESIS, AND THAT MEANT EVERY
    /// JOINER. #29 DSYNC is the ONLY join the project offers — block-by-block replay is retired as
    /// vestigial — and the adopt is the one place `nf_fold_base` is ever written. So taking the only
    /// supported route to joining cost the ability to spend: MEASURED as §CC, `joiner BEFORE adopting=true
    /// · adopted=true · joiner AFTER=false`. A node that can receive money and never move it is not a
    /// participant.
    ///
    /// ⭐ THE REASON IT REFUSED DOES NOT APPLY TO A CERTIFIED BASE. The doc said a jumped node "cannot
    /// vouch for the span it leapt" — true if vouching meant having FOLDED the span. It does not. The
    /// joiner adopted a bundle carrying a WHOLE-CHAIN CERT and verified it; that cert IS the vouching, and
    /// it is the same evidence that let the node jump at all. The adopt site says so in as many words:
    /// *"The certified base is recognised through `nf_fold_base` itself — the value is bound in
    /// `sync_binding`, so it is a CHAIN value, not this node's opinion."* Refusing to declare a value the
    /// chain certified, on a node that checked the certificate itself, is not caution — it is discarding
    /// evidence.
    ///
    /// ⛔ AND THE SUBSTANTIVE CHECK WAS NEVER THE BASE. `nf_absent_by_reconstructed_tip` admits this shape
    /// on **carried copaths verified against the LIVE sparse root** — the base-state carrier only declares
    /// where the carrier stands, while the live-root copath per tag is what proves the tags are unspent
    /// NOW. That check is identical whatever the base, which is why widening the base trades no soundness:
    /// a forged base buys nothing, because a tag already spent fails its live-root copath regardless.
    ///
    /// `None` only when this node has no base at all — it can then vouch for nothing and publishes nothing,
    /// which is the fail-closed answer the original doc wanted and the only case that actually needed it.
    /// ⭐⭐⭐ THE NODE BUILDS ITS OWN SPEND'S CARRIER — the same Lane B a wallet uses, self-built from
    /// this node's own copy of the replicated stream.
    ///
    /// ROOT-LAYER: where a NODE-BUILT spend (peg-out burn, order fill, asset transfer, asset mint's
    /// issuance right) gets its spend authority. It had none of its own: `spend_lane_evidence` carried
    /// Merkle copaths from `sparse_work` and a base-state stub, which the gate admits through Lane A.
    ///
    /// ⛔ WHY LANE A CANNOT BE THE ANSWER, in the gate's own words two functions below: *"the nullifier
    /// set is authoritative at the present instant … **This node holds no set by design**, so the only
    /// value it can vouch for at the present instant is its live accumulator: the endpoint must equal
    /// it."* The Merkle view Lane A rests on contradicts that design, and MEASURED 2026-09-24 it costs:
    ///   * 208 ms of EVERY block apply to maintain (`[sparse-shadow]`, n=232, live gate), and
    ///   * a rebuild after any restart or DSYNC jump priced at 732 us per tag — on a chain FIVE MINUTES
    ///     old the live joiner reported `absorbed 41 tag(s) this tick (2381/103680 total)`, i.e. ~11
    ///     minutes of warming, and the set is 256 x height so it only grows.
    ///
    /// This builds the real thing instead: fold every block of the certified span into a recursive
    /// absence carrier and finalize it AT THE LIVE TIP. Absence through the live tip IS absence now,
    /// because the first spend of any member moves that tip — which is exactly why Lane B needs no tree.
    ///
    /// Fail-closed at three points, and each means something different:
    ///   * a refused `step` means a member of this set SETTLED in that block — this node refuses to prove
    ///     otherwise rather than re-rooting around it, the same rule the wallet's carrier states;
    ///   * an accumulator that does not reach the live tip means the span this node holds does not
    ///     describe its own chain — never proven "close enough";
    ///   * a zero-step carrier finalizes to `None` by construction, so an empty span cannot pass.
    ///
    /// cons: O(span) Poseidon steps plus one recursive prove, where the span is bounded by the DAG's
    /// `keep_depth` — a protocol constant every node derives identically. No term in height or supply.
    ///
    /// ⛔ DB-400: NO PRODUCTION CALLER. `spend_lane_evidence` carried this until it was measured proving for 98 s
    /// under the node lock while deciding nothing (DB-217); a node-built spend now carries the base-state witness,
    /// as every wallet spend does (DB-284). It stays as the span-integrity instrument the fold pins use: a span that
    /// does not reproduce the live accumulator cannot finalize here.
    #[cfg(test)]
    pub fn self_build_spend_carrier(
        &self,
        nfs: &[[u8; 32]],
    ) -> Option<crate::nf_sparse::NfAbsenceWitness> {
        use usdm_decider::nf_sparse_air::{nf_to_limbs, NfAbsenceBatchCarrier};
        if nfs.is_empty() {
            return None;
        }
        let (base, _seq) = self.nf_fold_base;
        if base == usdm_decider::poseidon2_compress::zero_digest() {
            return None; // neither folded from genesis nor adopted a certified base ⇒ attests nothing
        }
        // ⛔ TIME THE WHOLE BUILD, NOT `finalize`. Measured 2026-09-24: `finalize()` alone reports 0 ms,
        // because the carrier proves INCREMENTALLY inside `step` — timing the last call would have
        // published a reassuring zero for work that is entirely in the loop below. That is the same
        // residual-naming mistake `bulk-page` made.
        let t0 = std::time::Instant::now();
        let limbs: Vec<crate::spend_frontier::Digest4> = nfs.iter().map(nf_to_limbs).collect();
        let mut carrier = NfAbsenceBatchCarrier::new(limbs, base);
        // ⛔ NOT `nf_fold_inputs_len()` AS THE COUNT. That is the window's CLAIMED size; the page is
        // all-or-nothing and answers empty when it cannot honour the claim, so sizing the request from
        // the claim would quietly ask for more than the span can be. Ask for everything and let the page
        // decide what it can honestly hand back.
        let span = self.nf_fold_inputs_page(0, usize::MAX);
        let mut folded = 0usize;
        for (_id, pre, tags) in &span {
            if !carrier.step(tags, *pre) {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name and a block COUNT — never a tag, amount,
                // key or owner.
                eprintln!(
                    "[node-carrier] a member of this spend's set SETTLED at block {folded} of {} — \
                     refusing to prove otherwise; this spend cannot be published",
                    span.len()
                );
                return None;
            }
            folded += 1;
        }
        if carrier.acc() != self.nf_unspent_acc {
            // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS only.
            // ⛔ NAME THE ARITHMETIC, NOT JUST THE SYMPTOM. A_tip counts `nf_fold_seq` block steps; the
            // base has absorbed `base_seq` of them; so the span MUST be exactly the difference. When it
            // is not, the two disagree about WHICH BLOCKS ARE COUNTED, and the gap size says whether the
            // span is short (blocks lost from it) or long (blocks folded twice). Without these numbers
            // this line only says "it did not work", which is what it said for three sightings.
            // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS only — never a tag, amount, key or owner.
            let (_, base_seq) = self.nf_fold_base;
            let expected = self.nf_fold_seq.saturating_sub(base_seq);
            eprintln!(
                "[node-carrier] the {folded}-block span this node holds does not reproduce its own live \
                 accumulator — the carrier is NOT at the tip and the gate would refuse it; publishing \
                 nothing rather than something that cannot settle. ARITHMETIC: A_tip has taken \
                 nf_fold_seq={} step(s), the base absorbed base_seq={base_seq}, so the span should be \
                 {expected} block(s) and it is {folded} — {}.",
                self.nf_fold_seq,
                if (folded as u64) < expected {
                    "SHORT: blocks A_tip counted are missing from the span"
                } else if (folded as u64) > expected {
                    "LONG: the span carries blocks A_tip never counted (or counted once and the span twice)"
                } else {
                    "the COUNTS agree, so the disagreement is in the block CONTENTS or their order"
                }
            );
            return None;
        }
        let (proof, _acc, tip_prev, tip_bp, tip_td) = carrier.finalize()?;
        // ⛔ THE PROVE TIME IS A PERFORMANCE-PILLAR NUMBER, NOT A CURIOSITY. This runs on the path that
        // publishes a node-built spend; a multi-second prove under the runtime lock would be the
        // `nf-warm-page` freeze wearing a different name. Named here so it is measured every time rather
        // than assumed once.
        // DIGITAL-CASH-PRIVACY-REVIEWED: an input count, a block count, a proof SIZE and a duration —
        // never a tag, amount, key, owner or accumulator value.
        eprintln!(
            "[node-carrier] built a {}-byte recursive absence proof for {} input(s) over {folded} \
             folded block(s) in {}ms TOTAL (fold + prove), standing on this node's live tip",
            proof.len(),
            nfs.len(),
            t0.elapsed().as_millis()
        );
        Some(crate::nf_sparse::NfAbsenceWitness {
            proof,
            tip_prev,
            tip_bp,
            tip_td,
            base_acc: base,
            // DB-246: this carrier folded this node's whole span, so it closes over the span's tips.
            tips: self.nf_fold_span_tips().into_iter().map(|id| id.0).collect(),
        })
    }

    /// G1e-iv audit: the rewind ring as `(fold ordinal, frontier root, leaf count, membership accumulator)`, oldest first.
    #[cfg(test)]
    pub(crate) fn spine_ring_for_audit(&self) -> Vec<(u64, crate::spend_frontier::Digest4, u64, Option<crate::spend_frontier::Digest4>)> {
        self.spine_recent_frontiers.iter().map(|(o, f, a, _)| (*o, f.root(), f.count(), *a)).collect()
    }

    /// TEST FIXTURE — this node holds no view (restarted, DSYNC-jumped, still warming): it can prove nothing, so its band
    /// moves only by relayed steps. Through the one wholesale view write.
    #[cfg(test)]
    pub(crate) fn drop_view_for_test(&mut self) {
        self.set_sparse_work(None);
    }

    /// The band door's solicited window as held (G1g-iv: compared live vs booted).
    #[cfg(test)]
    pub(crate) fn band_solicit_cap(&self) -> usize {
        self.band_door.solicit_cap()
    }

    /// TEST FIXTURE — plant `tags` as fold step `ordinal`'s ADMITTED set (what a block whose lane admitted exactly these
    /// tags leaves at the fold, under a block id derived from them) and move it through the REAL door: prove the step with
    /// this node's own held view (the owner path's synchronous twin — the holder's fold serve leaves the view as it was),
    /// offer it, drain. One real proof at `band_relay_k()`. Returns the verified transition, so a SECOND node that noted
    /// the same step (`band_note_step_for_test`) is offered the same object, as the relay would. `None` when the step
    /// cannot be proven here: no view, a tag already spent, or the prover refused.
    #[cfg(test)]
    pub(crate) fn band_plant_for_test(
        &mut self,
        ordinal: u64,
        tags: &[[u8; 32]],
    ) -> Option<crate::nf_sparse::BandTransition> {
        self.band_note_step_for_test(ordinal, tags);
        self.band_prove_pointer_for_test()
    }

    /// TEST FIXTURE — prove the step at the band POINTER with this node's own held view and offer it: the owner path's
    /// synchronous twin, through the owner's own serve (`BandCursor::serve_and_absorb`, which also serves the FILLERS
    /// that pad a short admitted set to the constant step width — applied and taken back, never spent). One real proof
    /// at `band_relay_k()`. `None`: nothing awaits, the step's admitted set is unknown here, no view is held, or the
    /// step did not verify.
    #[cfg(test)]
    pub(crate) fn band_prove_pointer_for_test(&mut self) -> Option<crate::nf_sparse::BandTransition> {
        let (ordinal, block, admitted) = self.band_door.awaiting_steps().into_iter().next()?;
        let admitted = admitted?;
        let k = self.band_door.chain_k();
        let view = self.sparse_work.as_ref()?;
        let (band_pre, serves, fillers) = crate::nf_sparse::BandCursor::new().serve_and_absorb(
            view,
            self.band_door.band(),
            ordinal,
            block,
            &admitted,
            0,
        )?;
        let t = if self.band_door.bound_double() {
            crate::nf_sparse::build_band_transition_bound(block, &band_pre, &serves, &fillers, k)?
        } else {
            crate::nf_sparse::build_band_transition(block, &band_pre, &serves, &fillers, k)?
        };
        (self.band_offer(t.clone(), false) == crate::nf_sparse::BandReceipt::Verified).then_some(t)
    }

    /// ⛔ TEST BUILDS ONLY — arm the BOUND band-step double on this node: its band door verifies, and its prove worker lays,
    /// bound steps (`usdm_decider::nf_sparse_air::band_bound`; the bound certificate's law). An in-process hub arms every
    /// party together, so an armed node never meets a real step and a real door never meets a bound one.
    #[cfg(test)]
    pub(crate) fn arm_band_double_for_test(&mut self) {
        self.band_door.arm_bound_double_for_test();
    }

    /// ⛔ TEST BUILDS ONLY — DB-454: the bound double's prove job declares `ms` of simulated cost per step, so a charged
    /// simulated mesh has the real lane's band timing (the reference step) with the double's microsecond proofs.
    #[cfg(test)]
    pub(crate) fn set_band_double_charge_for_test(&mut self, ms: u64) {
        self.band_door.set_double_charge_for_test(ms);
    }

    /// TEST FIXTURE — prove and apply every awaiting step, in fold order, until the band is current (one real proof
    /// each). Returns the transitions, oldest first, so a peer can be offered the same objects.
    #[cfg(test)]
    pub(crate) fn band_catch_up_for_test(&mut self) -> Vec<crate::nf_sparse::BandTransition> {
        let mut out = Vec::new();
        while self.band_door.pointer().is_some() {
            match self.band_prove_pointer_for_test() {
                Some(t) => out.push(t),
                None => break,
            }
        }
        out
    }

    /// TEST FIXTURE — THE DA LANE, IN PROCESS (2026-10-04): each record this node WANTS (`want_held_block_record`, the
    /// fold's "bytes not held") that `from` holds is built by `from`'s own by-id serve (`ledger_record_for_rid`) and taken
    /// through this node's own fetched-record door (`accept_fetched_record`) — the two production doors the by-id lane
    /// joins over the wire, with nothing in between. Returns how many records landed. A jumper's fold stands on the
    /// carried window's records, which only a peer can serve; without this a jump pin's fold is stuck by construction
    /// (MEASURED: db249 / db286 "[fold-stuck] … 33 block(s) still unfolded" after their adopt).
    /// TESTS: plant a CONSISTENT spent set — the view (`sparse_work`) over `tags` and the band door's band as that SAME
    /// tree's subtree roots at `NF_BAND_LEVEL` (empty-subtree constants where no tag lands), adopted together with no
    /// awaiting step, the fold-point root following the band. This is exactly the relation the production warm installs
    /// (`install_healed_pivot`: the view's root reproduces the band root); it exists because a fixture that needs a LARGE
    /// set cannot prove one band step per 256 tags (MEASURED: a band step proves in 9.6 s at k = 1, 14 s at k = 8 — a
    /// 16,385-tag page would be 65 steps, eleven minutes). `false` when the band door refuses the adopt; nothing moved.
    #[cfg(test)]
    pub(crate) fn plant_spent_set_for_test(&mut self, tags: &[[u8; 32]], next_ordinal: u64) -> bool {
        use usdm_decider::nf_sparse_air::{NF_BAND_ENTRIES, NF_BAND_LEVEL};
        let mut tree = crate::nf_sparse::RefSparseNf::new();
        for t in tags {
            let _ = tree.insert_and_witness(t);
        }
        let (_touched, _ordered, by_shard) = crate::nf_sparse::admitted_order(tags);
        let mut band: Vec<crate::spend_frontier::Digest4> =
            (0..NF_BAND_ENTRIES).map(|_| crate::nf_sparse::empty_subtree_pub(NF_BAND_LEVEL)).collect();
        for (s, shard_tags) in &by_shard {
            let Some(first) = shard_tags.first() else { continue };
            let canon = crate::nf_sparse::RefSparseNfMemo::canon(&crate::nf_sparse::SparseKey::of(first), NF_BAND_LEVEL);
            band[*s as usize] = tree.node_at_pub(NF_BAND_LEVEL, &canon);
        }
        if !self.band_door.adopt_certified(band, next_ordinal, Vec::new()) {
            return false;
        }
        self.set_sparse_work(Some(tree));
        self.view_follow_band_root();
        true
    }

    /// TESTS: THE STALE-SPINE RE-ANCHOR LANE — the runtime's tick asks a peer for its certified bundle while
    /// `spine_needs_reanchor` holds (node_runtime's stale-spine ask) and the adopt takes it as the re-anchor regardless of
    /// the catch-up depth (`instant_sync`'s `reanchor` arm). A spine goes stale on a fold reorg deeper than the rewind
    /// ring (`SPINE_RING_LEN`). MEASURED (db265, ~half the runs): origin A re-folded 69 records from ordinal 13, its peg
    /// journal floor sat above 13 → `[fold-conflict]`, and with no such lane in the fixture A folded nothing again (82 vs
    /// the joiner's 86). The bundle's proof bytes are the fixtures' placeholder: the node's own verifier judges them.
    /// `true` iff a bundle was adopted this call.
    /// Also the runtime's DB-4 poll: a node held for shells whose bodies no lane brought takes the certified bundle that
    /// covers them (`instant_sync`'s shell-hold arm).
    #[cfg(test)]
    pub(crate) fn reanchor_if_stale_for_test(&mut self, from: &mut Node) -> bool {
        if !(self.spine_stale || self.production_held_for_unapplied_shells()) || from.spine_stale {
            return false;
        }
        let frontier = crate::sync::FrontierSnapshot {
            root: *from.note_frontier_root().as_bytes(),
            height: from.note_frontier_count(),
            peaks_hex: from.spend_frontier_peaks_hex(),
        };
        let Some(bundle) = from.build_sync_bundle(vec![1u8; 4096], frontier) else {
            eprintln!("[reanchor-lane] the peer served no bundle — the stale node stays stale");
            return false;
        };
        let ReplayOutcome::Adopt(got) = self.derive_replicated(ReplicaBase::CertifiedBundle(bundle)) else {
            unreachable!("a CertifiedBundle base replays to an Adopt verdict")
        };
        let adopted = matches!(got, crate::sync::AdoptOutcome::Adopted(_));
        if !adopted {
            eprintln!("[reanchor-lane] the stale node refused the peer's bundle: {got:?}");
        }
        adopted
    }

    /// TESTS: THE SHELL-BODY LANE — the held shells oldest first, each body taken from the peer's live window
    /// (`whole_blocks_by_ids`, the by-id serve) into `fill_shell_body_preverified`. Returns the bodies landed.
    #[cfg(test)]
    pub(crate) fn fill_held_shells_for_test(&mut self, from: &Node) -> usize {
        let ids = self.held_shell_ids_oldest(16);
        if ids.is_empty() {
            return 0;
        }
        from.whole_blocks_by_ids(&ids, crate::arti_transport::BULK_FRAME_MAX)
            .into_iter()
            .filter(|b| self.fill_shell_body_preverified(b.clone()))
            .count()
    }

    /// TESTS: THE KIND-5 COORDINATE LANE — one page as node_runtime's tick asks it (heal, then the named hole or the
    /// cursor, `DA_LADDER_SPAN` rows) and `on_sidecar_page` adopts it (the ONE row writer, holes named, cursor moved). An
    /// adopt evicts every local ordinal claim the certified spine does not name ("the peer's pages re-supply the
    /// coordinates"); this is that lane. Returns the fresh rows landed.
    #[cfg(test)]
    pub(crate) fn page_coordinates_for_test(&mut self, from: &Node) -> usize {
        if self.sidecar_backlog() > 0 {
            self.sidecar_cursor_heal();
        }
        if !self.sidecar_ask_wanted() {
            return 0;
        }
        let cursor = self.sidecar_ask_from();
        let (rows, covered_upto) =
            from.sidecar_page(cursor, Self::DA_LADDER_SPAN, crate::arti_transport::BULK_FRAME_MAX);
        if rows.is_empty() {
            return 0; // the server answers an empty page with no reply
        }
        let fresh = rows.iter().filter(|(o, r)| self.adopt_sidecar_row(*o, *r)).count();
        self.name_sidecar_page_holes(cursor, covered_upto);
        self.sidecar_paged_through(covered_upto);
        self.note_sidecar_page_outcome(fresh);
        fresh
    }

    /// TESTS: a jumper (a pivot and NO view) warms its view from `from` through the ONE warm door
    /// ([`Self::warm_view_from_for_test`]); any other node is left alone. `true` iff a view was installed this call.
    #[cfg(test)]
    pub(crate) fn warm_if_viewless_for_test(&mut self, from: &Node) -> bool {
        if self.sparse_work.is_some() {
            return false;
        }
        if self.sparse_pivot().is_none() || from.sparse_work.is_none() {
            eprintln!(
                "[warm-lane] viewless node NOT warmed: pivot placeable {}, door stale {}, peer view held {}",
                self.sparse_pivot().is_some(),
                self.band_door.is_stale(),
                from.sparse_work.is_some()
            );
            return false;
        }
        match self.warm_view_from_for_test(from) {
            Ok(()) => true,
            Err(e) => {
                eprintln!(
                    "[warm-lane] viewless node NOT warmed: {e} (this node: band pointer {:?}, newest applied {:?}, floor {}, \
                     lag {}; peer: pointer {:?}, newest applied {:?}, floor {}, lag {})",
                    self.band_door.pointer(),
                    self.band_door.newest_applied(),
                    self.band_door.floor(),
                    self.band_door.lag(),
                    from.band_door.pointer(),
                    from.band_door.newest_applied(),
                    from.band_door.floor(),
                    from.band_door.lag()
                );
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn deliver_wanted_records_for_test(&mut self, from: &Node) -> usize {
        // Both want sets — `wanted_record_ids` (the fold's `want_held_block_record`, the by-id lane) and `da_wanted_ids`
        // — exactly as the public `wanted_record_ids()` request is built. MEASURED 2026-10-05 21:24 (pins-r3c.log): the
        // helper read only `da_wanted_ids` and served nothing while the fold had three records wanted by id.
        self.deliver_records_from_for_test(&|rid| from.ledger_record_for_rid(rid).map(|r| (r.notes.clone(), r.key())))
    }

    /// The one shared site of the by-id record lane in tests: each wanted record id `holder` answers enters through the
    /// production door (`accept_fetched_record`, judged against the root this node holds). A peer node is one holder;
    /// the frozen-consensus corpus (the records its recorded blocks commit to) is another.
    #[cfg(test)]
    pub(crate) fn deliver_records_from_for_test(&mut self, holder: &dyn Fn(u64) -> Option<(Vec<u8>, Option<crate::cover::CoverKey>)>) -> usize {
        let mut landed = 0usize;
        for rid in self.wanted_record_ids() {
            if let Some((notes, key)) = holder(rid) {
                if self.accept_fetched_record(rid, &notes, key) {
                    self.wanted_record_ids.remove(&rid);
                    landed += 1;
                }
            }
        }
        landed
    }

    /// TEST FIXTURE — note fold step `ordinal` with `tags` as its admitted set under the block id
    /// `band_plant_for_test` derives, so a second node can take the SAME relayed transition.
    #[cfg(test)]
    pub(crate) fn band_note_step_for_test(&mut self, ordinal: u64, tags: &[[u8; 32]]) -> [u8; 32] {
        let mut pre = b"MUSD/test/planted-band-step".to_vec();
        pre.extend_from_slice(&ordinal.to_le_bytes());
        for t in tags {
            pre.extend_from_slice(t);
        }
        let block = *Hash32::hash(&pre).as_bytes();
        assert!(self.band_door.note_fold_step(ordinal, block, Some(tags.to_vec())), "the door notes the planted step");
        block
    }

    /// TEST DIAGNOSTIC — the band door's wait state in one line (ordinals and counts only): what a scenario verdict prints
    /// when a fold stands short of its spine, so a band wedge names its cause (an UNKNOWN step, a missing carrier, no view).
    #[cfg(test)]
    pub(crate) fn band_diag_for_test(&self) -> String {
        let steps = self.band_door.awaiting_steps();
        let unknown: Vec<u64> = steps.iter().filter(|(_, _, a)| a.is_none()).map(|(o, _, _)| *o).take(4).collect();
        let idle = steps.iter().filter(|(_, _, a)| a.as_ref().is_some_and(|a| a.is_empty())).count();
        let ptr_wants = steps.first().is_some_and(|(_, b, _)| self.band_door.wants(b));
        format!(
            "band pointer {:?} wants {ptr_wants} (verified/solicited/n_ver/n_sol/cap/parked {:?}) lag {} wait {:?} stale {} floor {} unknown {} {:?} idle {} view {} cursor {:?} applied {} fold_wait {:?}",
            self.band_door.pointer(),
            self.band_door.pointer_diag_for_test(),
            self.band_door.lag(),
            self.band_door.last_wait(),
            self.band_door.is_stale(),
            self.band_door.floor(),
            steps.iter().filter(|(_, _, a)| a.is_none()).count(),
            unknown,
            idle,
            self.sparse_work.is_some(),
            self.band_cursor.through(),
            self.band_steps_applied,
            self.fold_wait_on.map(|(_, k)| k),
        )
    }

    /// TEST LEVER (DB-396) — make this in-process node keep its band moving the way a production node's prove worker does:
    /// arm the bound band double (a step costs microseconds) and prove the backlog inline whenever the fold would otherwise
    /// wait at the lag cap. A fixture that folds more than `SPINE_RING_LEN` reward-carrying blocks with no band prover
    /// measures a node no mesh runs: before DB-396 its door went STALE silently; since, its fold waits at the cap.
    /// TEST LEVER — the mesh size both shard policies read (`Node::visible_mesh_size`); `None` restores `known_peers() + 1`.
    #[cfg(test)]
    pub(crate) fn set_visible_mesh_size_for_test(&mut self, mesh: Option<u32>) {
        self.mesh_size_override_for_test = mesh;
    }

    #[cfg(test)]
    pub(crate) fn autoprove_band_for_test(&mut self) {
        self.band_door.arm_bound_double_for_test();
        self.band_autoprove_for_test = true;
    }

    /// ⛔ TEST BUILDS ONLY — arm the BOUND template double on this node: its producer lays, and every door it judges a block
    /// by (preverify, graft, lane justification, the fold's anchor check, the bond lane) verifies, the four template
    /// aggregates as the double (`note_transition::TemplateClass`). An honest in-process mesh arms every party together
    /// before its runtime is built (the off-lock preverify worker reads the flag then), so an armed door never meets a real
    /// aggregate and a real door never meets a bound one. NOT a soundness door: a simulation with a rogue producer never
    /// arms it.
    #[cfg(test)]
    pub(crate) fn arm_template_double_for_test(&mut self) {
        self.template_double_for_test = true;
    }

    /// ⛔ TEST BUILDS ONLY — §RF-3: this node lays and judges the block ledger (note + member ledger) REAL rather than as the
    /// bound double. A real-ledger mesh arms every party together before its runtime is built (the preverify worker reads
    /// the flag then); a pin asserting real ledger bytes arms every node it builds. Ignored on a template-armed node.
    #[cfg(test)]
    pub(crate) fn arm_real_ledger_for_test(&mut self) {
        self.real_ledger_for_test = true;
    }

    /// [`Self::autoprove_band_for_test`] as a builder, for a fixture node that is FED BLOCKS ALONE (a restarted process, a
    /// third node that never peered): no fold-past helper proves its band, and a production node's prove worker does.
    /// MEASURED 2026-10-09 (link 57): the restarted custodian and the never-pooled third node of the custody pins each
    /// stopped at "[fold-wait] ⏸ DB-396: the band lags the fold by its whole cap (64 step(s))", so the mint never folded.
    #[cfg(test)]
    pub(crate) fn with_band_prover_for_test(mut self) -> Self {
        self.autoprove_band_for_test();
        self
    }

    /// TEST LEVER (DB-396 C1) — an unfolded backlog of `n` distinct header-only blocks, planted with no fold pass, so P7's
    /// verdict at the DAG's retention window is asked without laying 7,516 blocks. The pin calls no fold after it.
    #[cfg(test)]
    pub(crate) fn plant_unfolded_backlog_for_test(&mut self, n: usize) {
        let Some(g) = self.relay.dag().genesis().and_then(|g| self.relay.dag().get(&g)).map(|n| n.header.clone()) else {
            return;
        };
        for i in 0..n {
            let mut header = g.clone();
            header.timestamp = header.timestamp.wrapping_add(1 + i as u64);
            self.unfolded_blocks.push(Self::header_shell(header, Vec::new()).into());
        }
    }

    /// TEST DOOR — this node's band door past an unbridgeable gap (see `BandDoor::force_stale_for_test`).
    #[cfg(test)]
    pub(crate) fn force_band_stale_for_test(&mut self) {
        self.band_door.force_stale_for_test();
    }

    /// TEST DOOR (DB-428) — the held view's root (`None`: no view held).
    #[cfg(test)]
    pub(crate) fn sparse_view_root_for_test(&self) -> Option<[u8; 32]> {
        self.sparse_work.as_ref().map(|t| t.root_bytes())
    }

    /// TEST DOOR (DB-428) — drop this node's view and point its accumulator at its band root: the state a joiner's adopt
    /// leaves (`forget_unvouched_sparse_root`, then the P1 follow), so a runtime pin can warm it toward its own band root.
    #[cfg(test)]
    pub(crate) fn go_viewless_on_band_for_test(&mut self) {
        self.forget_unvouched_sparse_root();
        self.view_follow_band_root();
    }

    /// TEST DOOR — install an empty held view, the state a completed warm or an adopt that carries one leaves.
    #[cfg(test)]
    pub(crate) fn install_empty_view_for_test(&mut self) {
        self.set_sparse_work(Some(crate::nf_sparse::RefSparseNf::new()));
    }

    #[cfg(test)]
    pub(crate) fn per_ordinal_map_sizes_for_test(&self) -> (usize, usize, usize, usize) {
        (
            self.da_macc_fwd_mem.len(),
            self.da_macc_rev_mem.len(),
            self.da_leafstart_mem.len(),
            self.da_targets_mem.len(),
        )
    }

    /// Test-only write access to the ledger (a pin plants chain state a fixture has not folded yet).
    #[cfg(test)]
    pub(crate) fn peg_mut_for_test(&mut self) -> &mut crate::peg::PegLedger {
        &mut self.peg
    }
    /// Test-only mutable pool access — lets a test drive the pool's block-age clock and settlement directly,
    /// so the re-relay/stuck-detection logic is exercised without mining a real chain to age a tx.
    #[cfg(test)]
    /// TEST — the RAW book level's empty-slot count at `(pair, level)`, with no in-flight overlay: what the book itself
    /// holds, so a pin can assert the served width stays constant when the overlay hides a rung.
    pub(crate) fn order_book_level_empty_for_test(&self, pair: crate::order_book::PairKey, level: u32) -> usize {
        self.order_book.level(pair, level).1
    }
    pub(crate) fn mempool_mut(&mut self) -> &mut Mempool {
        &mut self.mempool
    }

    /// Test-only raw admission (NO ZK carrier verify) — for produce / extend / selection tests that seed the
    /// pool with synthetic blobs. The production ZK gate is [`Node::ingest_tx`] (proven by the mempool
    /// `accept_verified` gate test + the `whir_decider` carrier-gate test).
    #[cfg(test)]
    pub(crate) fn ingest_tx_unverified(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        self.mempool.accept(tx)
    }

    #[cfg(test)]
    pub(crate) fn test_drop_record_bytes(&mut self, seq: u64) -> bool {
        self.da_mem.remove(&seq).is_some()
    }

    #[cfg(test)]
    pub(crate) fn test_plant_ladder_root(&mut self, ordinal: u64, root: crate::spend_frontier::Digest4) {
        // The format's ONE encoder (`ladder_slot_encode`), so a planted root reads back through the one
        // decoder. ⛔ §AG class 9: this laid eight LE limbs into a 32-byte slot — 64 bytes — overwriting
        // the next slot and PANICKING on the last (`range end index 72 out of range for slice of length
        // 64`, measured 2026-09-13 in `a_held_ladder_root_that_disagrees_refuses_the_regeneration…`).
        let span = ordinal / Self::DA_LADDER_SPAN;
        let slot = Self::LADDER_SLOT_BYTES;
        let off = ((ordinal % Self::DA_LADDER_SPAN) as usize) * slot;
        let blob = self.da_ladder_mem.entry(span).or_default();
        if blob.len() < off + slot {
            blob.resize(off + slot, 0);
        }
        blob[off..off + slot].copy_from_slice(&Self::ladder_slot_encode(&root));
    }

    #[cfg(test)]
    pub(crate) fn test_want_record_by_ordinal(&mut self, ordinal: u64) {
        self.da_wanted.borrow_mut().insert(ordinal);
    }

    #[cfg(test)]
    pub(crate) fn test_byte_wants(&self) -> (usize, usize) {
        (self.wanted_record_ids.len(), self.da_wanted.borrow().len())
    }

    /// ⛔⛔⛔ VALIDATOR BONDS ARE SAT-ONLY (2026-10-07, the user's design question decided on architecture — memory
    /// `feedback_bonds_sat_only_thorchain_20261007`). A NEW USDm bond seats nothing: the submit door refuses it with this
    /// reason, the template never lays it, and the fold's apply refuses it if a producer laid it anyway.
    /// WHY — the borrowed shape (THORChain bonds RUNE only; Ethereum ETH; Cosmos ATOM): ONE bond asset, never a claim on
    /// what it secures. (1) Custody: a USDm bond is a claim on the reserve it would guard, so the theft refunds it
    /// (DB-391). (2) Finality: two bond assets need a price to be added — the raw sum lets an attacker buy weight in the
    /// cheaper unit, a priced sum puts the validator-voted mark inside the weight that votes it (DB-387: a 1/3 colluder
    /// moved the mark 10×), and finality picks the chain custody acts on (DB-391 by the side door). MEASURED at the
    /// decision: the finality tally and governance already weighed `bond_of` (SAT) only.
    /// An existing USDm seat keeps its unbond (DB-409) — Bitcoin's soft-fork shape: no new instances of a retired type,
    /// the old ones still redeem. USDm keeps its utility as money, DEX liquidity, private staking and issuance.
    /// TEST-ONLY: make THIS thread's producers lay a pooled USDm bond as the pre-ruling template did — a rogue producer
    /// running a template that skipped `USDM_BOND_RETIRED` (the `pool_unbond_past_the_door_for_test` shape), so a pin can
    /// prove the fold seats nothing even from a block carrying the bond WITH its proven statement.
    #[cfg(test)]
    pub(crate) fn set_rogue_lays_usdm_bonds_for_test(on: bool) {
        ROGUE_LAYS_USDM_BONDS_FOR_TEST.with(|c| c.set(on));
    }

    /// A re-bond whose new weight is `weight` (the rest returns as change) — the §9.3 R1 attacker's shape, for the pins.
    #[cfg(test)]
    pub(crate) fn build_sat_rebond_with_weight_for_test(&mut self, fresh_note: &[u8], locked_note: &[u8], wallet: &crate::faucet::RecipientSecrets, pk: &[u8], sk: &[u8], weight: u64) -> Option<crate::sat_bond_tx::SatBondTx> {
        self.build_sat_bond_in_process(fresh_note, Some(locked_note), wallet, pk, sk, Some(weight))
    }
    /// TEST ONLY — a ROGUE producer's pool: `t` enters this node's pool with no admission door run, so a pin can lay what an
    /// honest pool refuses (a second seat) and assert the FOLD's own verdict on every node.
    #[cfg(test)]
    pub(crate) fn pool_sat_bond_past_the_door_for_test(&mut self, t: &crate::sat_bond_tx::SatBondTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let tx = self.spending_object_tx(t.to_object(), &t.own_nullifiers(), t.notes[1].clone())?;
        self.mempool.accept(tx)
    }

    /// Test-only raw bond admission (NO carrier verify) — for LOCK/UNBOND-semantics tests, mirroring
    /// [`Node::ingest_tx_unverified`]'s role and doc. The production admission gate is
    /// [`Node::apply_bond_set`] (proven by its own tamper/forged-entry refusal tests).
    #[cfg(test)]
    pub(crate) fn admit_bond_unverified(
        &mut self,
        vid: [u8; 32],
        amount: u128,
        out0: Vec<u8>,
        height: u64,
    ) {
        // TEST/DEV direct seat (a locked note + weight, no proof): the custody fixtures' stand-in for a SAT bond, so it
        // seats CUSTODY weight; the production USDm bond (`apply_bond_set`) seats finality weight (SATOSHI §6).
        let _ = self.admit_validator(vid, amount, 0);
        self.bond_locked.insert(vid, out0);
        self.bond_height.insert(vid, height);
    }

    /// ⭐ DB-274 P2 (§8.7) — TESTS: produce `record_fold_depth + 1` blocks on this node, each grafted by every peer, so
    /// every block produced before the call has FOLDED on all of them (the bond class applies at the fold, not at
    /// graft). The protocol's own depth, never a tuned count. Returns the last timestamp used, so later blocks stay
    /// after it.
    #[cfg(test)]
    pub(crate) fn fold_past_for_test(&mut self, peers: &mut [&mut Node], ts: u64, tag: &[u8]) -> u64 {
        self.fold_past_stepped_for_test(peers, ts, 1_000, tag)
    }

    /// [`Self::fold_past_for_test`] with the blocks `step_ms` apart, for a pin whose later blocks carry fixed
    /// timestamps the fold blocks must stay below.
    #[cfg(test)]
    pub(crate) fn fold_past_stepped_for_test(
        &mut self,
        peers: &mut [&mut Node],
        ts: u64,
        step_ms: u64,
        tag: &[u8],
    ) -> u64 {
        self.fold_past_blocks_for_test(peers, ts, step_ms, tag).0
    }

    /// [`Self::fold_past_stepped_for_test`], also handing back the blocks it produced, for a pin that replays the
    /// exact chain into a node that was not a peer (a restarted process, a third node fed blocks alone).
    #[cfg(test)]
    pub(crate) fn fold_past_blocks_for_test(
        &mut self,
        peers: &mut [&mut Node],
        mut ts: u64,
        step_ms: u64,
        tag: &[u8],
    ) -> (u64, Vec<crate::block::Block>) {
        let mut made = Vec::new();
        for i in 0..=self.params().record_fold_depth {
            ts += step_ms;
            let mut seed = tag.to_vec();
            seed.extend_from_slice(&i.to_le_bytes());
            let blk = self
                .produce(ts, Hash32::hash(&seed), Hash32::hash(b"db274-p2-fold"))
                .expect("the node produces past the record fold depth");
            for p in peers.iter_mut() {
                let got = p.ingest_block(blk.clone(), ts + 400);
                assert!(
                    matches!(got, crate::relay::RelayOutcome::Added(_)),
                    "a peer grafts the fold-past block: {got:?}"
                );
            }
            made.push(blk);
        }
        // ⭐ DB-353 P1 (the helper made faithful, 2026-10-04): a fold step that admits a nullifier — a spend, or a class
        // object's one-time id (a peg-in's deposit, a liquidation key) — WAITS until that step's band transition is
        // proven ("[respend] ⏸ DB-353 §13.6 … an earlier step's admitted set is unknown here"). On the mesh the band
        // worker proves it and the relay carries it; here THIS node proves each awaiting step with its own view (one real
        // proof each) and offers the same object to every peer, as the relay would, then every node folds again — until
        // nothing awaits and nothing folds. Bounded by the blocks this run produced (each pass folds or proves at least one).
        // MEASURED before: the 2-of-2 custody pin and both executor re-propose pins waited here forever, so a carried
        // peg-in never reached its fold apply (no `[peg-in]` line at all).
        // And the DA LANE: a node whose fold wants a record it does not hold (a jumper's carried window) takes it from a
        // peer that does, through the same two doors the by-id lane joins (`deliver_wanted_records_for_test`), both ways.
        let bound = made.len() + 2;
        self.settle_mesh_lanes_for_test(peers, bound);
        (ts + 400, made)
    }

    /// TESTS — THE MESH LANES, the one shared site every in-process fixture settles through: the DA record lane, the warm
    /// lane and the band relay, then every node folds again — until nothing lands, nothing folds and nothing awaits, or
    /// `max_passes` passes (each pass folds, proves or lands at least one thing while the loop runs). A fixture whose
    /// jumper runs none of these measures a node no mesh runs (2026-10-08: canonical_record_fold_tests' jumpers waited at
    /// "[fold-wait-why] … the fold-point spent set is blind" forever, leaving 69 of the origin's ordinals None).
    #[cfg(test)]
    pub(crate) fn settle_mesh_lanes_for_test(&mut self, peers: &mut [&mut Node], max_passes: usize) {
        let mut passes = 0usize;
        loop {
            let mut landed = 0usize;
            for p in peers.iter_mut() {
                landed += self.deliver_wanted_records_for_test(p);
                landed += p.deliver_wanted_records_for_test(self);
                // THE SHELL-BODY LANE (node_runtime's `held_shell_ids_oldest` → by-id pull → `fill_shell_body_preverified`):
                // a body the peer still holds in its live window. One it folded and dropped is the bundle's (below).
                landed += self.fill_held_shells_for_test(p);
                landed += p.fill_held_shells_for_test(self);
                // THE STALE-SPINE RE-ANCHOR LANE (the runtime's stale-spine ask) — before the warm lane: an adopt leaves
                // the node viewless, and the warm lane below warms it in the same pass.
                landed += self.reanchor_if_stale_for_test(p) as usize;
                landed += p.reanchor_if_stale_for_test(self) as usize;
                // THE KIND-5 COORDINATE LANE: an adopt's evicted ordinal claims come back as the peer's page rows
                landed += self.page_coordinates_for_test(p);
                landed += p.page_coordinates_for_test(self);
                // ⭐ THE WARM LANE (2026-10-04, the helper made faithful, part 3): a node that JUMPED holds the certified
                // spent-set root and NO view, so its fold cannot decide a carried spend or one-time id against the set
                // ("[respend] ⏸ DB-353 §13.6 … its tag's shard is not held") and its band prover has no view to serve
                // from — on a mesh it warms its view from a peer's key-ordered stream (DB-290, the pivot flow the runtime's
                // worker runs). MEASURED before this (db249, both executor re-propose pins): the jumper's cursor stayed at
                // the adopted tip's row (37) while the peer folded on (38, 39, 40); the merging block never folded on the
                // jumper, so its held mint never applied — "[db249] … minted A false B true".
                landed += self.warm_if_viewless_for_test(p) as usize;
                landed += p.warm_if_viewless_for_test(self) as usize;
            }
            let folded = self.fold_canonical_records();
            let mut folded_peers = 0usize;
            for p in peers.iter_mut() {
                folded_peers += p.fold_canonical_records();
            }
            let steps = self.band_catch_up_for_test();
            for t in &steps {
                for p in peers.iter_mut() {
                    let _ = p.band_offer(t.clone(), false);
                }
            }
            passes += 1;
            if (folded == 0 && folded_peers == 0 && steps.is_empty() && landed == 0) || passes > max_passes {
                for (who, n) in std::iter::once(("self", &*self)).chain(peers.iter().map(|p| ("peer", &**p))) {
                    eprintln!(
                        "[mesh-lanes] settled after {passes} pass(es): {who} folded to {}, {} unfolded, view {}, band pointer \
                         {:?}, lag {}, stale {}",
                        n.served_seq(),
                        n.unfolded_blocks.len(),
                        n.sparse_work.is_some(),
                        n.band_door.pointer(),
                        n.band_door.lag(),
                        n.band_door.is_stale()
                    );
                }
                break;
            }
        }
    }

    /// ⭐ DB-274 P2 (§8.7) — TESTS: produce until every unbonding window open on this node has closed AND the releasing
    /// block has folded on this node and every peer. Bounded by the window plus the fold depth, never open-ended.
    #[cfg(test)]
    pub(crate) fn fold_past_unbond_window_for_test(&mut self, peers: &mut [&mut Node], mut ts: u64, tag: &[u8]) -> u64 {
        let due = self.unbonding.values().map(|u| u.due_blue).max().unwrap_or(0);
        // A-F60: and the window's time half, on the chain tick
        let due_tick = self.unbonding.values().map(|u| u.due_tick).max().unwrap_or(0);
        let mut i = 0u64;
        while self.relay.dag().get(&self.selected_tip().expect("a tip")).map(|n| n.blue_score).unwrap_or(0) < due || self.chain_tick() < due_tick {
            ts += 1_000;
            let mut seed = tag.to_vec();
            seed.extend_from_slice(b"-window-");
            seed.extend_from_slice(&i.to_le_bytes());
            i += 1;
            let blk = self
                .produce(ts, Hash32::hash(&seed), Hash32::hash(b"db274-p2-window"))
                .expect("the node produces through the unbonding window");
            for p in peers.iter_mut() {
                let got = p.ingest_block(blk.clone(), ts + 400);
                assert!(
                    matches!(got, crate::relay::RelayOutcome::Added(_)),
                    "a peer grafts the window block: {got:?}"
                );
            }
        }
        self.fold_past_for_test(peers, ts, tag)
    }

    /// DB-258 (tests): V's v2 unbond statement for THIS node's live bonding of V, filed under `(bucket, ek)`, signed.
    #[cfg(test)]
    /// V's signature over a FRESH unbond request (DB-258d: a fresh nonce on every call), with the nonce it signed.
    pub(crate) fn sign_unbond_for_test(
        &self,
        sk: &[u8],
        vid: &[u8; 32],
        // DB-273 §19.3 L2: the returned note's OLI clue.
        owner_clue: &[u8],
    ) -> (Vec<u8>, [u8; 32]) {
        let instance = self.bond_instance_of(vid).expect("V holds an anchored bonding on this node");
        let nonce = crate::unbond_tx::fresh_unbond_nonce();
        let msg = crate::pqauth::validator_unbond_msg(vid, &instance, &crate::oli::owner_clue_digest(owner_clue), &nonce);
        let sig = crate::pqauth::ml_dsa_sign(&msg, sk).expect("V signs its unbond");
        (sig, nonce)
    }

    /// TEST-ONLY (DB-409): pool a signed unbond WITHOUT the publish door's seat and maturity refusals — what a producer that
    /// skipped the door puts in its own block. The graft-side release (`unbond_tx::apply_chain_unbond`) is the consensus
    /// rule such a block meets; a pin that needs an immature unbond carried uses this, never the door.
    #[cfg(test)]
    pub(crate) fn pool_unbond_past_the_door_for_test(
        &mut self,
        pubkey: &[u8],
        sig: &[u8],
        owner_clue: &[u8],
        nonce: [u8; 32],
    ) -> AssetSpendOutcome {
        let vid = crate::unbond_tx::validator_id(pubkey);
        let bond_instance = self.bond_instance_of(&vid).expect("V holds an anchored bonding on this node");
        let header =
            crate::unbond_tx::UnbondHeader { owner_clue_digest: crate::oli::owner_clue_digest(owner_clue), bond_instance, nonce };
        let blob = crate::unbond_tx::wire(&header, pubkey, sig, owner_clue).expect("the unbond encodes");
        let right = crate::unbond_tx::unbond_right_nf(&vid, &header);
        self.publish_asset_object_with_note(blob, &[], Some(right), "unbond")
    }

    /// TEST BUILDS ONLY: seat weight directly (the satoshi pins seat a finality-only validator to show it weighs no custody).
    #[cfg(test)]
    pub(crate) fn validators_mut_for_test(&mut self) -> &mut ValidatorSet {
        &mut self.validators
    }

    /// TEST (G1d): the three resume-derived fields as held — `(fold_checkpoint as (k, Debug of its frontier), synced,
    /// folded_floor sorted)`. cons: none — a test door; reads only.
    #[cfg(test)]
    pub(crate) fn g1d_resume_fields_for_audit(&self) -> (Option<(u64, String)>, Option<SyncState>, Vec<crate::block::BlockId>) {
        let mut floor: Vec<crate::block::BlockId> = self.folded_floor.iter().copied().collect();
        floor.sort();
        (self.fold_checkpoint.as_ref().map(|(k, f, rh)| (*k, format!("{f:?} {rh:?}"))), self.synced.clone(), floor)
    }

    /// TEST: this node's checkpoint exactly as a boot reads it — the snapshot AND its fold record, held in RAM.
    /// cons: none — a test door (cfg(test)) over the existing O(1) capture; writes nothing.
    #[cfg(test)]
    pub(crate) fn checkpoint_for_test(&self) -> Option<(crate::persist::NodeSnapshot, crate::persist::FoldRecord)> {
        Some((self.export_snapshot()?, self.capture_fold_record().0))
    }

    /// TEST: warm this (restored, viewless) node's nullifier view from `peer`'s held view, as a restarted node's runtime
    /// does — stream the peer's set at its view root, sync the tail from THIS node's own band journal, and install
    /// through the ONE door (`install_healed_pivot`, which refuses a root this node cannot place). Since DB-353 §13.6 a
    /// viewless node's fold WAITS on every tag it cannot decide, so a restart pin folds only after this. `false` when
    /// the peer holds no view, this node cannot place the peer's root, or the door refuses.
    /// cons: none — a test door (cfg(test)); writes nothing beyond the view the runtime's warm installs.
    #[cfg(test)]
    pub(crate) fn warm_view_from_for_test(&mut self, peer: &Node) -> Result<(), &'static str> {
        // ⛔ A FIXTURE NEVER FALLS BEHIND THE CODE (2026-11-26): under the constant chain (`params::canon_live()`, ON in every build
        // since the A-F114 network upgrade) no node holds the spent set and the runtime warms NO view
        // (`NodeRuntime::drive_nf_pivot_job` returns at once, A-F114 U1). This door is the runtime's warm in process, so it does
        // exactly what the runtime does: nothing. Before, it demanded a pivot the constant chain never has ("this node stands on
        // no placeable pivot") and two restart pins of `canonical_record_fold_tests` stood red on a step production no longer
        // takes, while the resume they cover went unchecked.
        if crate::canon_chain::canon_live() {
            return Ok(());
        }
        // the runtime's warm, in process: THIS node's own placeable pivot, the peer's key-ordered pages after the cursor,
        // and this node's band tail synced before each page (a page moves the cursor or the empty page closes the stream)
        let pivot = self.sparse_pivot().ok_or("this node stands on no placeable pivot")?;
        let mut pw = crate::nf_sparse::PivotWarm::new(pivot);
        loop {
            let more = self.sparse_pivot_tail_since(pw.pivot(), pw.tail_synced()).ok_or("the warm's target left the journal")?;
            pw.sync_tail(&more);
            if pw.stream_done() {
                break;
            }
            // DB-426/428: the ONE serve — `set(pivot)` exactly, or nothing from a peer that cannot place this node's pivot
            // The peer's refusal names its own band state (DB-428 `place_class`).
            let got = peer.sparse_stream_page_for(&pw.pivot(), pw.cursor().as_ref(), 4_096)?;
            if !pw.absorb_page(&got, true) {
                return Err("a served page was refused");
            }
            if pw.restart_if_exact_missed() {
                return Err("an all-exact stream missed the pivot");
            }
        }
        let healed = pw.into_healed().map_err(|_| "the stream does not reach the pivot")?;
        if self.install_healed_pivot(healed) { Ok(()) } else { Err("the door refused the install") }
    }

    /// TEST: restart from a checkpoint through the ONE resume a node's boot runs ([`Self::resume_from_checkpoint`]).
    /// cons: none — a test door (cfg(test)); writes nothing.
    #[cfg(test)]
    pub(crate) fn resume_from_checkpoint_for_test(
        &mut self,
        snap: crate::persist::NodeSnapshot,
        fold: crate::persist::FoldRecord,
    ) -> bool {
        matches!(self.resume_from_checkpoint(snap, Some(fold)), RestoreOutcome::Restored)
    }

    /// TEST PROBE (G1, lane b): the DAG span against the block window around the certified anchor —
    /// `(dag len, min non-genesis blue score, certified_anchor_score, dag blocks ≤ it, window entries ≤ it,
    /// window entries the DAG does not hold, their (min, max) blue score)`.
    #[cfg(test)]
    pub(crate) fn dag_window_floor_probe(&self) -> (usize, u64, u64, usize, usize, usize, Option<(u64, u64)>) {
        let dag = self.relay.dag();
        let g = dag.genesis();
        let ids = dag.block_ids();
        let scores: Vec<u64> = ids.iter().filter(|id| Some(**id) != g).filter_map(|id| dag.get(id).map(|n| n.blue_score)).collect();
        let cas = self.certified_anchor_score;
        let win = self.block_window.ascending();
        let off: Vec<u64> = win.iter().filter(|(_, id)| dag.get(id).is_none()).map(|(s, _)| *s).collect();
        (
            ids.len(),
            scores.iter().copied().min().unwrap_or(0),
            cas,
            scores.iter().filter(|s| **s <= cas).count(),
            win.iter().filter(|(s, _)| *s <= cas).count(),
            off.len(),
            off.iter().copied().min().zip(off.iter().copied().max()),
        )
    }

    /// DIAGNOSTIC (test builds) — where this node holds block `id`, for a span member another node holds and this one lacks:
    /// (in DAG + its blue score, in window + its stamp, in the unfolded carry, in-flight stamp, owed/placed by a pending base,
    /// in the adopted floor, this node's fold base seq and current generation).
    #[cfg(test)]
    pub(crate) fn span_member_whereabouts(&self, id: &crate::block::BlockId) -> String {
        let dag = self.relay.dag().get(id).map(|n| n.blue_score);
        let pend = self.nf_fold_base_pending.as_ref().map(|p| (p.owed.contains_key(id.as_bytes()), p.placed.contains(id.as_bytes())));
        format!(
            "dag {:?} · window {:?} · carry {} · inflight {:?} · pending(owed,placed) {:?} · floor {} · base_seq {} · gen {} · anchor_score {}",
            dag,
            self.block_window.gen_of(id),
            self.unfolded_blocks.iter().any(|b| b.id() == *id),
            self.nf_unfolded_gen.get(id),
            pend,
            self.folded_floor.contains(id),
            self.nf_fold_base.1,
            self.block_window.base_gen(),
            self.certified_anchor_score,
        )
    }

    /// DIAGNOSTIC (test builds) — this node's fold base words and A_tip.
    #[cfg(test)]
    pub(crate) fn fold_base_words_for_test(&self) -> (crate::spend_frontier::Digest4, u64, crate::spend_frontier::Digest4, u64) {
        (self.nf_fold_base.0, self.nf_fold_base.1, self.nf_unspent_acc, self.nf_fold_seq)
    }

}
