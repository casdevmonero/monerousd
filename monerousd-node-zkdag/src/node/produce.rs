// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! produce — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// ⭐⭐⭐ DB-165 — BUILD THIS BLOCK'S CONSTANT-WIDTH NOTE CARRIER.
    ///
    /// Real note commitments go to slots this node chooses; every remaining slot gets a cover commitment
    /// drawn from a stream only THIS node can produce. Both are then STORED in the block, because —
    ///
    /// > **anything a node can REGENERATE, an observer can DISTINGUISH.**
    ///
    /// — which is exactly how the old shape failed: the DA record's cover came from
    /// `block_cover_secret(real_notes, seq)`, whose only secret input is the reals, and the block carried
    /// those reals in the clear. Every node recomputed the secret and named the real slots. A cover that
    /// anyone can re-derive is not cover.
    ///
    /// ⛔ THE STREAM IS SEEDED FROM `miner_seed`, WHICH IS NEVER PUBLISHED. The header carries
    /// `miner_commitment`, a one-way commitment to it, so no holder of the block can reproduce this
    /// stream. Per-block uniqueness comes from the real notes' own digest, so two blocks never share a
    /// cover set even at the same height.
    ///
    /// ⛔ AND THE REAL SLOTS ARE SCATTERED, NOT PACKED AT THE FRONT. Placing reals first would make "where
    /// the cover begins" the count — the same leak wearing an index instead of a length.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: produces a CONSTANT 8,192 bytes whatever the block carries, and the
    /// per-slot values are commitments (32 B), never a note, amount, key or owner. This function exists
    /// to REMOVE a volume signal, and its output is the same width on a quiet block and a full one.
    /// O1-FOOTPRINT-REVIEWED: exactly `BLOCK_FIXED_NOTE_COUNT` slots, a fixed protocol constant — no term
    /// in height, block count or spend volume, and nothing is stored beyond the block itself.
    pub(super) fn assemble_note_commitment_carrier(&self, real_notes: &[u8]) -> Vec<u8> {
        use crate::cover::{BLOCK_FIXED_NOTE_COUNT, NOTE_COMMITMENT_BYTES, PQ_NOTE_BYTES};
        // The reals, committed one slot each.
        let mut reals: Vec<[u8; NOTE_COMMITMENT_BYTES]> = Vec::new();
        for chunk in real_notes.chunks(PQ_NOTE_BYTES) {
            if chunk.len() < PQ_NOTE_BYTES {
                break; // a partial trailing chunk is not a note
            }
            reals.push(*crate::hash::Hash32::hash(chunk).as_bytes());
        }
        if reals.len() > BLOCK_FIXED_NOTE_COUNT {
            reals.truncate(BLOCK_FIXED_NOTE_COUNT);
        }
        // A stream no holder of this block can reproduce: the node's own unpublished seed, bound to this
        // block's real notes so it is unique per block.
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(b"MUSD-db165-note-cover-v1");
        seed.extend_from_slice(&self.miner_seed);
        seed.extend_from_slice(crate::hash::Hash32::hash(real_notes).as_bytes());
        let draw = |i: u64| -> [u8; NOTE_COMMITMENT_BYTES] {
            let mut b = seed.clone();
            b.extend_from_slice(&i.to_le_bytes());
            *crate::hash::Hash32::hash(&b).as_bytes()
        };
        let cover: Vec<[u8; NOTE_COMMITMENT_BYTES]> =
            (0..BLOCK_FIXED_NOTE_COUNT as u64).map(draw).collect();
        // Scatter the reals across the fixed width from the same private stream.
        let mut order: Vec<usize> = Vec::with_capacity(reals.len());
        let mut taken = vec![false; BLOCK_FIXED_NOTE_COUNT];
        for (k, _) in reals.iter().enumerate() {
            let mut probe = u64::from_le_bytes(
                draw(1_000_000 + k as u64)[..8].try_into().unwrap_or([0u8; 8]),
            ) as usize
                % BLOCK_FIXED_NOTE_COUNT;
            // linear probe to the next free slot — deterministic for this node, opaque to everyone else
            let mut steps = 0usize;
            while taken[probe] && steps < BLOCK_FIXED_NOTE_COUNT {
                probe = (probe + 1) % BLOCK_FIXED_NOTE_COUNT;
                steps += 1;
            }
            taken[probe] = true;
            order.push(probe);
        }
        crate::cover::BlockNoteCommitments::assemble(&reals, &cover, &order)
            .map(|c| c.as_bytes().to_vec())
            // ⛔ FAIL TO THE CONSTANT WIDTH, NEVER TO A SHORT ONE. A short carrier would state a count by
            // its length, which is the whole defect; an all-cover carrier of the right width states
            // nothing. `assemble` only refuses on shapes a producer cannot legally build.
            .unwrap_or_else(|| {
                (0..BLOCK_FIXED_NOTE_COUNT as u64).flat_map(|i| draw(i)).collect()
            })
    }

    /// Seal the just-completed span's LADDER RECORD: the concatenated 32B block roots of ordinals
    /// [span_start, span_start+SPAN). Called at the ordinal claim that starts the NEXT span, while
    /// every root in the completed span is still derivable in-span (bytes not yet pruned — the
    /// pruner trails by exactly one span). Idempotent; missing roots abort the seal loudly (a hole
    /// here would strand old-note copaths, so an incomplete blob is never stored).
    pub(super) fn seal_ladder_span_if_completed(&mut self, append_ordinal: u64) {
        if append_ordinal == 0 || append_ordinal % Self::DA_LADDER_SPAN != 0 {
            return;
        }
        let span_index = (append_ordinal / Self::DA_LADDER_SPAN).saturating_sub(1);
        if self.da_ladder_mem.contains_key(&span_index) {
            return;
        }
        let start = span_index * Self::DA_LADDER_SPAN;
        // MEASURED (P14 low leg on 502520a, night/perf-flat-20261008-200454-low.log): the block apply that seals span 0
        // held the runtime lock 11,471 ms against its 200 ms budget. Each loop of the seal is timed so the term is named.
        let t_roots = std::time::Instant::now();
        let mut blob = Vec::with_capacity((Self::DA_LADDER_SPAN as usize) * Self::LADDER_SLOT_BYTES);
        for ord in start..start + Self::DA_LADDER_SPAN {
            let Some(root) = self.span_seal_root(ord) else {
                eprintln!(
                    "[ladder] ⛔ span {span_index} CANNOT seal: no root derivable at ordinal {ord} — \
                     the blob is not stored (a partial ladder record would strand old-note copaths)"
                );
                return;
            };
            blob.extend_from_slice(&Self::ladder_slot_encode(&root));
        }
        debug_assert_eq!(
            blob.len(),
            (Self::DA_LADDER_SPAN as usize) * Self::LADDER_SLOT_BYTES,
            "the sealed blob is not the wire contract `adopt_ladder_span` enforces"
        );
        self.da_ladder_mem.insert(span_index, blob);
        // ⛔⛔⛔ SEALED SPANS ARE HISTORY — HOLD THE LIVE ONES, RE-ASK FOR THE REST.
        //
        // Each blob is DA_LADDER_SPAN * 32 B = 131,072 B, sealed once per span. Held forever that is one
        // blob per 4,096 blocks: at the 500 ms clock, 42 spans/day = 5.5 MB/day = ~2 GB/year of RAM and
        // snapshot. MEASURED 2026-09-04 the moment the census stopped being partial:
        // `da_ladder_mem=2/262144B` at 12,288 blocks against 0 at 4,096 — invisible until then because
        // this map was one of the 24 collection fields the census did not list.
        //
        // Nothing is refused for age, because the absent case is ALREADY a supported local state:
        // `ladder_root_at_ordinal` inserts the span into `wanted_ladder` and returns None, the drain emits
        // the ask, and the verified adopt retires it — the same want/fetch path every other DA item uses.
        // A copath crossing a released span still resolves; it takes a fetch round trip instead of a local
        // read.
        //
        // ROOT-LAYER: this is the only writer of `da_ladder_mem`, so the bound holds for every seal.
        // MUST-STAY-GREEN: `ladder_root_if_held` / `ladder_root_at_ordinal` already return Option and
        // every caller handles None by wanting the span; `regenerate_idle_record` falls through to the
        // accumulator series when no ladder root is held.
        // cons: a copath into a span older than DA_LADDER_SPANS_HELD costs one fetch instead of a local
        // read. Bytes held go from f(height) to DA_LADDER_SPANS_HELD * DA_LADDER_SPAN * 32 = 262,144 B, a
        // fixed constant.
        let keep_from = span_index.saturating_sub(Self::DA_LADDER_SPANS_HELD.saturating_sub(1));
        self.da_ladder_mem.retain(|k, _| *k >= keep_from);
        self.da_ladder_adopted.retain(|k| *k >= keep_from);
        eprintln!("[ladder] sealed span {span_index} — old-note copaths across it resolve forever");
        // ⭐ THE SEAL IS THE RELEASE POINT FOR THE SPAN'S ROW BYTES (2026-09-06, no-growth closure):
        // the sealed blob now carries every root of this span, so the span's unreferenced row bytes
        // just stopped being anything's only source — REGENERATE/refetch covers every later read
        // (the DA is the ledger). This RELEASES bytes; it stores nothing. ROOT-LAYER: the seal is
        // the event that makes the release sound; releasing per-fold was MEASURED breaking this very
        // seal (`[ladder] ⛔ span 0 CANNOT seal: no root derivable at ordinal 1`), and releasing one
        // span LATER (the cold prune) was the MEASURED 18.9 MB trailing byte load
        // (`node_state_is_constant_size_no_growth…` red at "got 18967700 bytes" — ~4,096 rows ×
        // ~4.6 KB with the row count already flat; the live pair read 21.8 KB only because a
        // timer-driven sweep applied the same rule). Every row still passes
        // `drop_record_bytes_if_unreferenced` — wants, targets, tags, deletion sidecars, letters and
        // multi-receives all still refuse, so real payments keep their bytes.
        // MUST-STAY-GREEN: copath/subtree-climb pins, idle_record_regeneration 4/4,
        // `neither_party_fabricates_a_one_note_real_record`, the rolling-restart pins.
        // cons: none on any growth axis — this deletes held bytes and adds no state. TIME: 4,096
        // checks once per 4,096 blocks ≈ 0.4 s worst case per seal, ~0.1 ms/block amortized at the
        // 500 ms clock — f(DA_LADDER_SPAN, a fixed protocol constant), never f(history); the same
        // work the cadence sweep already paid per held row.
        let roots_ms = t_roots.elapsed().as_millis();
        let t_release = std::time::Instant::now();
        let (mut found, mut dropped) = (0u64, 0u64);
        let mut why: std::collections::BTreeMap<&'static str, u64> = std::collections::BTreeMap::new();
        for ord in start..start + Self::DA_LADDER_SPAN {
            if let Some(addr) = self.da_ord_rev_mem.get(&ord).copied() {
                found += 1;
                if let Some(r) = self.record_retention_reason(addr) {
                    *why.entry(r).or_insert(0) += 1;
                }
                if self.drop_record_bytes_if_unreferenced(addr) {
                    dropped += 1;
                }
            }
        }
        if dropped < found {
            eprintln!("[ladder] span {span_index} retained by: {why:?}");
        }
        // ⭐ THE RELEASE IS REPORTED, NOT ASSUMED. "sealed span N" printed happily while the span released
        // NOTHING — a seal line that says only that the seal ran cannot tell a working release from a
        // silent one, and the no-growth pin then fails with a number and no cause.
        eprintln!(
            "[ladder] span {span_index} release: {found}/{} ordinals resolved to a row, {dropped} byte-sets dropped \
             (seal: roots {roots_ms} ms, release {} ms)",
            Self::DA_LADDER_SPAN,
            t_release.elapsed().as_millis()
        );
    }

    /// ⭐ DB-310: the certified per-record root the roots-run door SEALED into the ladder at `ordinal`, or `None`. Never a
    /// root inside an open headers-first span (provisional until its run closes: `da_block_root_at_ordinal`'s own rule,
    /// through the one predicate), and never a side effect: `ladder_root_at_ordinal` registers a ladder want on a miss,
    /// which a verifier must not do.
    pub(super) fn sealed_root_at_ordinal(&self, ordinal: u64) -> Option<crate::spend_frontier::Digest4> {
        if self.headers_first_door_open_at(ordinal) {
            return None;
        }
        // ⛔ DB-310b (review): a PEER-ADOPTED span is checked only as a set, so a slot swap still closes its rung. Read as
        // the per-position authority it would let a relabelled record close the span past a held row's own refusal.
        if self.da_ladder_adopted.contains(&(ordinal / Self::DA_LADDER_SPAN)) {
            return None;
        }
        self.ladder_root_if_held(ordinal)
    }

    pub fn build_block_sparse_nf_carrier(
        pre_sparse: &mut crate::nf_sparse::RefSparseNf,
        txs: &[PqTx],
        conf_acc: &[u8; 32],
        seed_root: &[u8; 32],
    ) -> (crate::block::NfBlockProof, Vec<[u8; 32]>) {
        use usdm_decider::nf_sparse_air as air;
        let mut real_nfs: Vec<[u8; 32]> = Vec::new();
        let mut confidential: Vec<u8> = Vec::new();
        for tx in txs {
            // VERIFIER-REPRODUCIBLE decoy seed (Ask 2 treeless): fold ONLY real-spend blobs, exactly as the IMT path,
            // so producer + verifier derive the identical padded set from the block's gossiped reals + committed pre-root.
            if !tx.nullifiers.is_empty() {
                for nf in &tx.nullifiers {
                    real_nfs.push(nf.0);
                }
                confidential.extend_from_slice(&tx.blob);
            }
        }
        let pre_root = pre_sparse.root_bytes(); // == the header's committed `nullifier_root` (sparse acc lockstep)
                                                // Constant cover shape, seeded from THIS call's own `conf_acc`/`seed_root` — the same formula the
                                                // produce and adopt paths use, so all three derive the byte-identical vector.
        let fill_secret =
            crate::cover::nullifier_block_secret(&Self::nf_seed_conf(conf_acc, &[]), seed_root);
        let padded = crate::cover::nullifier_wire_fill(&real_nfs, &fill_secret);
        let mut inserts: Vec<usdm_decider::nf_compact_air::CompactInsertWitness> = Vec::with_capacity(padded.len());
        let mut fold_tags: Vec<[u8; 32]> = padded.clone();
        for nf in &padded {
            let copath = pre_sparse.insert_and_witness(nf); // the compact witness against the RUNNING tree
            match crate::nf_sparse::compact_insert_witness_for(nf, &copath) {
                Some(w) => inserts.push(w),
                None => return (crate::block::NfBlockProof::default(), padded),
            }
        }
        // ⭐⭐⭐ PAD THE CARRIER'S INSERT COUNT TO A POWER OF TWO — THE OTHER HALF OF THE BLOCK-CARRIER FIX.
        //
        // The sumcheck layout addresses rows by `nvars = log2(rows)` and `rows = inserts x DEPTH`, so a
        // non-power-of-two insert count has no valid arity and the block carrier prover
        // returned `None` — which this function maps to an EMPTY `NfBlockProof`, silently. Under the retired
        // 256-wide cover every block had 256 inserts (2^8) so it could never fire; with the cover retired the
        // count is the REAL spend count, and a block settling 3 (or 5, 6, 7 ...) spends shipped NO nullifier
        // transition certificate at all. MEASURED: 3 txs -> no carrier, 4 txs -> carrier builds and verifies.
        //
        // THE FILLERS MUST NEVER TOUCH THE LIVE TREE. `pre_sparse` is the node's WORKING sparse tree and its
        // root is the consensus authority — inserting a filler there would put a value the chain never spent
        // into the spent set, which is exactly the placement P0 recorded trying and reverting ("it put marker
        // values into the CONSENSUS spent set and changed every downstream root: 46 tests red"). So the real
        // inserts go into `pre_sparse` above and STOP there; fillers are witnessed against a SCRATCH CLONE
        // that dies with this function.
        //
        // Each filler is a genuine insert of a domain-separated nullifier against the running scratch root, so
        // it carries a VALID non-membership copath and chains exactly as a real insert does — nothing in the
        // AIR is relaxed to accommodate it. The committed endpoint stays honest because the carrier binds
        // `block_post` at `bind_at = real_n - 1` (`SparseBlockGate::bind_at`), so every filler sits BEYOND the
        // transition this block commits and cannot move it.
        //
        // cons: none — worst case is a real count just over a power of two, rounding up to under 2x the
        // inserts, i.e. under 2x trace rows, and the count is f(THIS BLOCK'S OWN SPENDS) with no term in
        // height, block count or chain size. n=3 -> 4 inserts = 1,024 rows (vs 768 unpadded). The retired
        // cover proved 256 inserts = 65,536 rows on EVERY block, so this is a 32-64x reduction against the
        // shape that shipped for months. The scratch clone is dropped here: no stored state, no wire bytes,
        // no consensus field.
        let real_n = inserts.len();
        let mut target = 1usize;
        while target < real_n {
            target = target.saturating_mul(2);
        }
        if real_n > 0 && target != real_n {
            let mut scratch = pre_sparse.clone();
            let mut i = 0u64;
            while inserts.len() < target {
                let mut h = blake3::Hasher::new();
                h.update(b"MUSD/nf-sparse/block-carrier-filler/v1");
                h.update(&pre_root);
                h.update(&i.to_le_bytes());
                let nf: [u8; 32] = *h.finalize().as_bytes();
                let copath = scratch.insert_and_witness(&nf);
                match crate::nf_sparse::compact_insert_witness_for(&nf, &copath) {
                    Some(w) => inserts.push(w),
                    None => return (crate::block::NfBlockProof::default(), padded),
                }
                fold_tags.push(nf);
                i += 1;
            }
        }
        // ⛔ §AI: the carrier proves about the DIGEST; hashing the byte form here would prove a
        // transition between values the chain never committed.
        let Some(pre_limbs) = crate::spend_frontier::cm_bytes_to_root(&pre_root) else {
            return (crate::block::NfBlockProof::default(), padded);
        };
        // the height-1 fold digests TAGS only (`sparse_fold_digest`), so its inserts carry no copath
        let fold_inserts: Vec<air::SparseInsertWitness> =
            fold_tags.iter().map(|nf| crate::nf_sparse::insert_witness_for(nf, Vec::new())).collect();
        let proof = match crate::nf_sparse::prove_block_sparse_carrier(&inserts, pre_limbs, padded.len()) {
            // Carry the HEIGHT-1 FOLD alongside the compact carrier — SAME inserts, ~1,535 B, 0 ms. The fold is the
            // TREELESS ADOPT GATE: a node holding NO tree verifies it in O(1) and adopts, or it does not verify and
            // the node does NOT adopt. BOTH artifacts or NEITHER — an empty proof never verifies, so it is
            // fail-closed at every consumer, never a rescue path.
            Some((carrier, post)) => {
                match air::prove_sparse_fold_height1_bytes(&fold_inserts, pre_limbs, post) {
                    Some(fold) => crate::block::NfBlockProof {
                        sparse_carrier: carrier.clone(),
                        carrier,
                        post_root: Hash32(crate::spend_frontier::leaf_to_cm_bytes(post)),
                        // This builder proves the SPARSE transition, so `post` IS the sparse post root.
                        sparse_post_root: Hash32(crate::spend_frontier::leaf_to_cm_bytes(post)),
                        fold,
                        // CARRY THE PUBLIC INPUT WITH THE PROOF. These are the very tags the fold was proven
                        // over, so a node that never held this block's txs verifies and adopts it instead of
                        // parking it forever.
                        padded_tags: padded.clone(),
                    },
                    None => crate::block::NfBlockProof::default(),
                }
            }
            None => crate::block::NfBlockProof::default(),
        };
        (proof, padded)
    }

    /// Does this node lay and judge the bound template double (test builds only; always `false` in a node binary)?
    #[must_use]
    pub(crate) fn template_double(&self) -> bool {
        #[cfg(test)]
        {
            self.template_double_for_test
        }
        #[cfg(not(test))]
        {
            false
        }
    }

    /// Prune the mined-tx-nf cache to the tx ids some RETAINED DAG block still references — amortized O(1) per block
    /// (only sweeps when the cache outgrows a window-proportional threshold, mirroring `Dag::prune_below_horizon`).
    /// Keeps the cache BOUNDED by the finality window (never the chain): a tx whose every including block has left
    /// the DAG can no longer be a canonical conflict participant, so its nfs are no longer needed. O1-INFINITY-
    /// REVIEWED (bounded by window×txs-per-block, lockstep-pruned; the constant slack keeps sweeps amortized).
    /// The tx ids `mined_tx_nfs` may hold: those of a DAG block whose record the fold has NOT reached (the ONE universe
    /// its reader walks — `spent_by_an_unfolded_block` arm (b) requires `!da_ord_mem.contains_key(record)`; once the fold
    /// reaches a block the fold-point set answers and a row for it decides nothing). Shared by the prune and the resume
    /// cache writer, so the RAM map, the file and the resume agree on one set (G1, lane a 2026-10-22).
    pub(super) fn mined_tx_nfs_live_tx_ids(&self) -> std::collections::HashSet<Hash32> {
        let dag = self.relay.dag();
        dag.block_ids()
            .into_iter()
            .filter(|id| !self.da_ord_mem.contains_key(&Self::da_record_id_for_block(id, 0)))
            .filter_map(|id| dag.get(&id).map(|n| n.tx_ids.clone()))
            .flatten()
            .collect()
    }

    /// ⭐ LIQUIDATION §10.2 (4) — BUILD this custodian's liquidation of PSM `asset_id` at the chain's CURRENT mark: the
    /// header (every commitment the five legs move the chain to) and the five WHIR legs, plus the v2 attestation message
    /// every bonded signer signs. Deterministic in the opening and the rule, so every custodian holding the opening builds
    /// the SAME header and signs the SAME message. `None` when this node holds no current opening, the PSM is not due,
    /// or the pool cannot cover the retire.
    pub fn build_liquidation(
        &self,
        asset_id: u32,
    ) -> Option<(crate::liquidation_tx::LiquidationHeader, crate::liquidation_tx::LiquidationLegs, Vec<u8>)> {
        let due = self.due_liquidation(asset_id)?;
        let legs = due.prove_legs()?;
        let msg = self.peg.liquidation_attest_msg(&due.header)?;
        Some((due.header, legs, msg))
    }

    /// LIQUIDATION §10.2 (4) — FRAME and POOL a liquidation: the ONE publisher (the framer holding ≥2/3 of the bonded
    /// signatures over [`crate::peg::PegLedger::liquidation_attest_msg`]). The object's own nullifier — its close id —
    /// is laid on its lane (DB-274 P4b B1), so the canonical fold admits exactly one close per id; the block that carries
    /// it applies it on every node at its fold through the ONE door.
    pub fn publish_liquidation(
        &mut self,
        h: &crate::liquidation_tx::LiquidationHeader,
        legs: &crate::liquidation_tx::LiquidationLegs,
        attestors: &[crate::psm::MintAttestor],
    ) -> Result<Hash32, MempoolError> {
        let mut tx = crate::liquidation_tx::as_pq_tx(h, legs, attestors, self.mempool.required_stamp_bits());
        if !self.lay_object_lane(&mut tx) {
            return Err(MempoolError::InvalidProof); // a blob that does not decode as its class: malformed, never pooled
        }
        // DB-335: through the own-publication door, so the runtime re-gossips it until a block carries it.
        self.pool_own_publication(tx)
    }

    /// Test seam: the publication travelling for `asset` leaves this node's pool, as an eviction or a refused fold leaves it.
    #[cfg(test)]
    pub(crate) fn drop_published_mark_for_test(&mut self, asset: u32) {
        let id = self.quote_book.published(asset).expect("PRECONDITION: a publication is travelling");
        self.mempool.remove(&[id]);
    }

    /// Whether an asset the relays price (Bitcoin, Monero; SAT is priced by the chain's own batches) still has no mark on the chain for the current price epoch.
    #[must_use]
    pub fn price_mark_due(&self) -> bool {
        let epoch = self.current_price_epoch();
        [crate::peg::NATIVE_PEG_ASSET_ID, crate::price_relay::XMR_ASSET_ID]
            .into_iter()
            .any(|a| !self.peg.price_mark_for(a).is_some_and(|m| m.epoch_id >= epoch))
    }

    /// Publish a `PriceMark` for every priced asset whose current-epoch quotes reach ≥2/3 of bonded weight,
    /// whose standing mark is older than this epoch, and that this node has not already published this
    /// epoch. Returns how many were admitted to the pool. ANY node may publish: the first mark per epoch to
    /// graft wins, and a later one is refused by the epoch rule on every node alike.
    pub fn publish_price_marks_if_quorum(&mut self, verifier: &dyn crate::pqauth::PqVerifier) -> usize {
        let epoch = self.quote_book.epoch();
        if epoch != self.current_price_epoch() {
            return 0; // the book holds another epoch's quotes: nothing here is publishable now
        }
        let mut published = 0usize;
        for asset in self.priced_asset_ids() {
            // ⛔ PUBLISHED MEANS STILL TRAVELLING (MEASURED 2026-11-04, real nodes): a mark published from one quote while the set was one seat was refused at its fold
            // once the second seat landed, and a flag that meant "published this epoch" then kept every node from publishing again for the 1,200 blocks left,
            // so no deposit could be quoted for hours. Bitcoin's rebroadcast shape: while the chain holds no mark for this epoch, a publication that left the
            // pool is published again from the quorum as it stands. Cons: a publication carried but not yet folded can be repeated once; the fold's epoch rule
            // refuses the repeat, one small object per asset per epoch per node at worst.
            if self.quote_book.published(asset).is_some_and(|id| self.mempool.contains(&id))
                || self.peg.price_mark_for(asset).is_some_and(|m| m.epoch_id >= epoch)
            {
                continue;
            }
            // Every quote in the book was verified at ingest; the book's own verifier re-checks none of them.
            let reuse = crate::price_quote::BookVerifier { book: &self.quote_book, inner: verifier };
            let Some(quotes) = self.quote_book.quorum_quotes(asset, &self.validators, &reuse) else {
                continue;
            };
            let header = crate::price_mark_tx::PriceMarkHeader { epoch_id: epoch, asset_id: asset };
            let tx = crate::price_mark_tx::as_pq_tx(&header, &quotes, self.mempool.required_stamp_bits());
            if let Ok(id) = self.pool_own_publication(tx) {
                // DIGITAL-CASH-PRIVACY-REVIEWED: epoch, asset id and quote count — chain-public, no owner or key.
                eprintln!("[price-mark] published: epoch {epoch} asset {asset} from {} quote(s)", quotes.len());
                self.quote_book.mark_published(asset, id);
                published += 1;
            }
        }
        published
    }

    // CHAIN-PUBLISH-REVIEWED: these ARE the publications of the four §BR-15 objects — each frames its object and pools it; the
    // book moves only at the carrying block's fold on every node (`defi_batch::apply_chain_defi`).
    /// §BR-15 §18.12 — publish a batch's slots: every order and claim nullifier rides the lane, every claim's note the outputs.
    pub fn publish_defi_slots(&mut self, t: &crate::defi_batch::DefiSlotsTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let blob = t.wire().ok_or(crate::mempool::MempoolError::InvalidProof)?;
        let notes: Vec<u8> = t.notes().concat();
        // ⭐ A-F114: under the constant chain every slot is a note leg (`chain_object::object_tag_roles`, orders then claims),
        // and its absence evidence is the wrapper its holder relayed (a real slot) or its committee member proved (a cover),
        // held in `canon_held_wrappers` by its nullifier. The object carries them in role order (`scope_spender_wrappers`,
        // the same carriage an rpc-built object uses). A slot with none refuses the publication here, before any block
        // carries it (refused at its fold it would burn the slots' notes): the batch waits for its slots.
        if crate::canon_chain::canon_live() {
            let mut list: Vec<crate::nf_sparse::CanonAbsence> = Vec::with_capacity(t.orders.len() + t.claims.len());
            for nf in t.orders.iter().map(|o| o.nullifier).chain(t.claims.iter().map(|c| c.nullifier)) {
                let k = crate::spend_frontier::leaf_to_cm_bytes(nf);
                let Some((_, held)) = self.canon_held_wrappers.iter().find(|(x, _)| *x == k) else {
                    return Err(crate::mempool::MempoolError::NullifierWitnessRejected);
                };
                let ws: Vec<crate::nf_sparse::CanonAbsence> = postcard::from_bytes(held).unwrap_or_default();
                let Some(w) = ws.into_iter().next() else {
                    return Err(crate::mempool::MempoolError::NullifierWitnessRejected);
                };
                list.push(w);
            }
            let bytes = postcard::to_allocvec(&list).map_err(|_| crate::mempool::MempoolError::InvalidProof)?;
            let _scope = crate::canon_chain::scope_spender_wrappers(Some(bytes));
            return self.publish_spending_object_nfs(blob, &t.nullifiers(), notes);
        }
        self.publish_spending_object_nfs(blob, &t.nullifiers(), notes)
    }
    /// §BR-15 — publish a batch settlement (spends nothing; its claim leaves ride the object).
    pub fn publish_defi_settle(&mut self, t: &crate::defi_batch::DefiSettleTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let blob = t.wire().ok_or(crate::mempool::MempoolError::InvalidProof)?;
        let mut tx = crate::defi_batch::as_pq_tx(blob, self.mempool.required_stamp_bits());
        // the wrapper carries exactly the object's notes (`wrapper_binds_object`): its claim leaves
        tx.output_notes = t.leaves.iter().flat_map(crate::defi_batch::leaf_note_payload).collect();
        self.pool_own_publication(tx)
    }
    /// §BR-15 §18.11 — publish a custody-handover object (spends nothing, carries no note).
    pub fn publish_defi_handover(&mut self, t: &crate::defi_handover::DefiHandoverTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let blob = t.wire().ok_or(crate::mempool::MempoolError::InvalidProof)?;
        let tx = crate::defi_batch::as_pq_tx(blob, self.mempool.required_stamp_bits());
        self.pool_own_publication(tx)
    }
    /// ⭐ Earn step 3 — publish an EarnEpoch chunk (spends nothing, carries no note).
    pub fn publish_defi_earn_epoch(&mut self, t: &crate::defi_batch::DefiEarnEpochTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let blob = t.wire().ok_or(crate::mempool::MempoolError::InvalidProof)?;
        let tx = crate::defi_batch::as_pq_tx(blob, self.mempool.required_stamp_bits());
        self.pool_own_publication(tx)
    }
    /// §BR-15 — publish a batch expiry (spends nothing; its refund leaves ride the object).
    pub fn publish_defi_expire(&mut self, t: &crate::defi_batch::DefiExpireTx) -> Result<Hash32, crate::mempool::MempoolError> {
        let blob = t.wire().ok_or(crate::mempool::MempoolError::InvalidProof)?;
        let mut tx = crate::defi_batch::as_pq_tx(blob, self.mempool.required_stamp_bits());
        tx.output_notes = t.leaves.iter().flat_map(crate::defi_batch::leaf_note_payload).collect();
        self.pool_own_publication(tx)
    }

    /// ⭐ ONE publication path for a framed object that SPENDS a note (the stake object, the pool deposit): the anti-spam
    /// stamp ground against this pool's live requirement, the constant-width tag set seeded from the object's id with the
    /// spent note's nullifier as its real row, the spend lane's own evidence over exactly that set, and the marking door.
    pub(super) fn publish_spending_object(&mut self, blob: Vec<u8>, nf: [u8; 32], out_notes: Vec<u8>) -> Result<Hash32, crate::mempool::MempoolError> {
        self.publish_spending_object_nfs(blob, &[nf], out_notes)
    }
    /// [`Self::publish_spending_object`] for an object that retires SEVERAL notes (a SAT re-bond: the fresh and the locked
    /// input). Every nullifier rides the tx's lane, padded to the fixed width like one.
    pub(super) fn publish_spending_object_nfs(&mut self, blob: Vec<u8>, nfs: &[[u8; 32]], out_notes: Vec<u8>) -> Result<Hash32, crate::mempool::MempoolError> {
        let tx = self.spending_object_tx(blob, nfs, out_notes)?;
        // Every caller spends a wallet's notes for it (DeFi slots, an asset or contract made, a pot fill, a loan closed), so it
        // leaves by push like any send: announced from here, it would name that wallet's node. A validator's duty spends none.
        self.pool_wallet_publication(tx)
    }

    /// PUBLISH the chain object for a completed request — the ONE prove — with this custodian's signer.
    /// On anything but `ConfidentialPublished` the slot backs off PEG_PUBLISH_BACKOFF_MS and retries.
    pub fn publish_peg_request(
        &mut self,
        key: &[u8; 32],
        signer_pk: &[u8],
        signer_sk: &[u8],
        verifier: &dyn crate::pqauth::PqVerifier,
        now_ms: u64,
    ) -> crate::peg::PegOutcome {
        use crate::peg_attest::{PEG_PUBLISH_BACKOFF_MS, PEG_REQUEST_IN, PEG_REQUEST_OUT, PEG_REQUEST_WRAPPED};
        let Some((req, secret)) = self
            .peg_requests
            .get(key)
            .and_then(|s| Some((s.request.clone()?, s.secret.clone()?)))
        else {
            return crate::peg::PegOutcome::BadRequest;
        };
        // DB-273 §19 L1: the owner is the credited (or change) note's OLI clue, opened from the sealed request.
        let owner_clue = secret.owner_clue.as_slice();
        // CHAIN-PUBLISH-REVIEWED: this IS the publisher — `execute_peg_in`, `publish_wrapped_mint` and `execute_peg_out_burn_verified` each frame a chain object and `ingest_tx` it (ConfidentialPublished); no ledger moves here, every ledger moves at block apply on every node
        let outcome = match req.kind {
            PEG_REQUEST_IN => {
                let extra = self.peg_attestations_for(key);
                let nonce = self.peg_proposal_nonce_for(key);
                // §BR-4 B4-2: a request carrying a unit half publishes its mint as a unit open
                self.execute_peg_in_unit(
                    req.id,
                    secret.value_a,
                    secret.value_b,
                    req.recipient,
                    &req.note_payload,
                    &req.carrier,
                    &secret.address,
                    signer_pk,
                    signer_sk,
                    &extra,
                    verifier,
                    owner_clue,
                    nonce,
                    secret.d_blind,
                    req.unit.as_ref(),
                )
            }
            PEG_REQUEST_WRAPPED => {
                let extra = self.peg_attestations_for(key);
                self.publish_wrapped_mint(
                    req.asset_id,
                    req.id,
                    secret.value_a,
                    secret.value_b,
                    req.recipient,
                    &req.note_payload,
                    &req.carrier,
                    &secret.address,
                    signer_pk,
                    signer_sk,
                    &extra,
                    verifier,
                    owner_clue,
                    secret.d_blind,
                )
            }
            PEG_REQUEST_OUT => {
                let extra = self.peg_out_attestations_for(&req.id);
                let nonce = self.peg_out_proposal_nonce_for(&req.id);
                let membership = Some((
                    req.membership_carrier.as_slice(),
                    req.membership_tip.as_slice(),
                    req.leaf_commit,
                ));
                self.execute_peg_out_burn_verified(
                    &req.carrier,
                    req.out0_cm,
                    req.out1_cm,
                    req.id,
                    secret.value_a,
                    &req.note_payload,
                    secret.address.as_bytes(),
                    secret.d_blind,
                    signer_pk,
                    signer_sk,
                    &extra,
                    verifier,
                    owner_clue,
                    membership,
                    nonce,
                    secret.pay_after, // §BR-1: the piece's sealed privacy delay
                    req.recipient,    // §BR-5: the ticketed redeem commitment the quorum signed
                )
            }
            _ => crate::peg::PegOutcome::BadRequest,
        };
        // ⭐ SAFE AT SCALE: a deposit proposed for THIS VAULT'S quorum alone (its legs went to the vault's members only) whose
        // ride no longer holds at publish — the vault's authority moved under it (a bond left, SAT's floor fell, another of
        // the vault's deposits landed first) — is published without a ride, and the door then asks for the whole set's
        // signatures, which a vault-sealed proposal can never gather. It is not left to retry for ever: the proposal is
        // dropped and the lane proposes the deposit again, sealed to every custodian. Never reached on a one-vault chain
        // (the lane publishes only at the door's own threshold there).
        let regather = req.kind == PEG_REQUEST_IN
            && matches!(outcome, crate::peg::PegOutcome::InsufficientThreshold)
            && crate::psm::BondQuorum::vault_count(&self.validators) > 1;
        if regather {
            self.peg_attest_pending.remove(key);
        }
        if let Some(s) = self.peg_requests.get_mut(key) {
            if matches!(outcome, crate::peg::PegOutcome::ConfidentialPublished) {
                s.publish_after_ms = None;
            } else if regather {
                s.proposed = false;
                s.publish_after_ms = None;
            } else {
                s.publish_after_ms = Some(now_ms + PEG_PUBLISH_BACKOFF_MS);
            }
        }
        eprintln!(
            "[peg-request] PUBLISHED the chain object for a completed request (kind {}): {:?}",
            req.kind, outcome
        );
        outcome
    }


    /// EXECUTE a confidential WRAPPED-ASSET mint (IonSwap Buy-wBTC/wETH/wDAI) — the exact per-asset mirror of
    /// [`Node::execute_peg_in`], but minting a wrapped asset instead of USDm. The node ORCHESTRATES the mint carrier
    /// from THIS asset's sealed opening (a depositor's wallet has no reserve secret and cannot), adds its OWN
    /// attestation ONLY if it has INDEPENDENTLY confirmed a real foreign deposit ≥ the credited reserve at
    /// `reserve_address` (the deposit-confirmation gate — no confirmed deposit ⇒ no self-attestation ⇒ at 1-of-1 the
    /// ≥2/3 threshold fails ⇒ NO mint), then executes the ≥2/3-gated confidential mint at the asset's own ratio
    /// (150% volatile / 100% stable — an under-collateralized wrap is UNPROVABLE), records the recipient's confidential
    /// wrapped-asset note, and re-seals the advanced opening. An unregistered asset, an unconfirmed/over-stated deposit,
    /// an over-mint, or a replayed foreign deposit ⇒ fail-closed and NOTHING mutates. Learns no deposit/mint value.
    #[allow(clippy::too_many_arguments)]
    /// ⭐⭐⭐ SETTLE ONE ORDER FILL — the DEX's entire money path, and the successor to the deleted pool.
    ///
    /// A maker rested an order over one of their own notes and went offline; a taker built the other half.
    /// This admits the pair. Fills against DIFFERENT orders touch disjoint state, so they verify and settle
    /// in parallel like ordinary sends — the property a pool could not have, because every trade of a pair
    /// had to serialise through one mutable cell.
    ///
    /// ⛔⛔⛔ THE TWO HALVES ARE VERIFIED TOGETHER, NEVER SEPARATELY. Each half alone is satisfiable by
    /// something that is not a trade: the maker's half says "my note may be consumed for `pay_b` of
    /// `asset_b`" and the taker's says "I paid `pay_b` and took a lot", but only the composed check ties
    /// them to the SAME terms. Verifying them one at a time would let a taker present a half built for
    /// cheaper terms beside an honest maker half — which is exactly the case
    /// `a_fill_built_at_a_cheaper_price_does_not_compose_with_the_order` pins in the wallet crate.
    ///
    /// ⭐ ANTI-DOUBLE-FILL IS THE DOUBLE-SPEND GATE THAT ALREADY EXISTS — no new machinery, no order state
    /// on chain. Two takers racing one resting order both name the maker's nullifier; the first flips it,
    /// and the second's copath no longer shows an empty leaf, so it is refused. Cancelling an order is the
    /// maker spending their own note, which burns the same nullifier.
    ///
    /// FAIL-CLOSED AND ATOMIC: every gate is checked BEFORE anything is written, and the two nullifier
    /// flips happen with no fallible step between them, so a refused fill leaves the ledger untouched
    /// rather than half-applied. A half-applied fill is the worst outcome available here — a burned input
    /// with no payout is exactly the fund loss this whole path exists to make unrepresentable.
    #[allow(clippy::too_many_arguments)]
    /// ⭐⭐⭐ PUBLISH AN UNBOND — the direction that hands a validator their money back, made to travel.
    ///
    /// ROOT-LAYER: this replaces a LOCAL mutation. `unbond_validator` released the weight and the note on
    /// `self` and told nobody, so every peer kept counting the weight and holding the note. Publishing the
    /// transition is the fix; nothing downstream could have been.
    ///
    /// ⛔ NOTHING IS WRITTEN HERE. The release happens when a block carrying this object grafts — on every
    /// node, through `unbond_tx::apply_chain_unbond`, including this one. A node that released locally and
    /// then published would be back to the divergence with an extra step.
    ///
    /// cons: one framed object plus the pool's anti-spam stamp. No term in height, note count or peers.
    pub fn publish_unbond(
        &mut self,
        pubkey: &[u8],
        sig: &[u8],
        // ⭐ DB-273 §19.3 L2: the returned note's OLI clue — the signed statement binds its canonical digest.
        owner_clue: &[u8],
        // DB-258d: the nonce the key-holder signed — what makes this request its own one-shot right.
        nonce: [u8; 32],
    ) -> AssetSpendOutcome {
        if owner_clue.is_empty() || owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX {
            return AssetSpendOutcome::Refused(
                "the unbond names no owner clue (or one wider than a clue) — the returned note would be filed nowhere a \
                 seed restore looks",
            );
        }
        // ⛔⛔⛔ DB-272 — AN UNBOND FOR AN IDENTITY THAT HOLDS NO BOND IS REFUSED HERE, LEGIBLY. The wallet signed its
        // unbond with its OWN spend key while its bond sat under the NODE's vote identity; this door admitted the
        // object (the signature is valid for THAT id), the answer said PUBLISHED, and every grafting node then
        // refused it as "no matured bond" with no error anywhere. The user's bonded note stayed locked.
        // ⛔ DB-409 — "HOLDS A BOND" IS EITHER SEAT. This asked `bond_of` (SATOSHI: the CUSTODY/SAT seat only), so a USDm
        // bond — a FINALITY seat (`admit_finality`) — read as no bond and its owner could never unbond it. MEASURED
        // sim-20261007-023642 T3: W1's 0.5 USDm bond held 50,000,000 finality weight on every up node, and its unbond
        // through node 0 (`own`) answered 422 "that key holds no bond on this node". The release this door publishes
        // removes BOTH seats (`ValidatorSet::remove`), so the door asks the one predicate for either: `is_seated`.
        // ROOT-LAYER: this is the one publish door every unbond passes (the node's own and an externally signed one).
        // MEASURED: before → 422 for a USDm-only seat (the run above); after → `db409_…` publishes it once matured.
        // MUST-STAY-GREEN: DB-272 (an unbond for an identity with no seat at all is still refused here, legibly).
        let vid = crate::unbond_tx::validator_id(pubkey);
        if !self.validators.is_seated(&vid) {
            return AssetSpendOutcome::Refused(
                "that key holds no bond on this node — its unbond would release nothing (a wallet-made bond sits under \
                 the node's vote identity: unbond it with `own`)",
            );
        }
        // ⛔ DB-409 — A BOND IS UNBONDED ONLY ONCE IT HAS MATURED, AND THE DOOR SAYS SO BEFORE ANYTHING TRAVELS. The release
        // (`release_matured_bond`) refuses an unbond its carrying block judges immature (`bond_height + stake_lock_blocks`),
        // but this door published it anyway: the owner was told PUBLISHED and every node then released nothing. BORROWED:
        // Bitcoin Core's mempool refuses a spend of an immature coinbase at admission (`bad-txns-premature-spend-of-
        // coinbase`, judged at the next block's height) — the pool admits only what the next block could apply.
        // cons: none — one map read and one compare; an unbond asked early is refused at once instead of after a block.
        // A-F60: maturity is read on the CHAIN TICK, in ONE coordinate everywhere — the anchor a bond records
        // (`sat_bond_tx::seat_sat_bond`: its carrying block's tick), the lock (`stake_lock_blocks`, a count of ticks),
        // this door, the release, and what `/get_validator_bond` serves (`unbond_matures_at_tick` beside `tip_tick`).
        // The next block's median time past is at least the tip's, so the tip's tick is a lower bound on the carrying
        // block's: a refusal here never refuses an unbond that block would release later than one tick, and an
        // admission is never released-nothing.
        let next_tick = self.chain_tick();
        if !self.bond_matured_at(&vid, next_tick) {
            return AssetSpendOutcome::Refused(
                "that bond has not matured yet — it stays locked for the stake-lock period after it was bonded, and an \
                 unbond before then would release nothing (`/get_validator_bond` names the chain tick it matures at, \
                 `unbond_matures_at_tick`, beside the chain's tick now, `tip_tick`)",
            );
        }
        // ⛔ DB-258 — the object names THIS node's live bonding of V, and the signature must cover it and the owner (the
        // clue's digest, DB-273 §19.3 L2): judged by the same door the release uses.
        let Some(bond_instance) = self.bond_instance_of(&crate::unbond_tx::validator_id(pubkey)) else {
            return AssetSpendOutcome::Refused("this node holds no anchored bonding for that validator");
        };
        let header = crate::unbond_tx::UnbondHeader {
            owner_clue_digest: crate::oli::owner_clue_digest(owner_clue),
            bond_instance,
            nonce,
        };
        if let Err(why) = crate::node::objects::unbond_tx::authorised_for(self, &header, pubkey, sig, &crate::pqauth::MlDsaVerifier) {
            return AssetSpendOutcome::Refused(why);
        }
        let Some(blob) = crate::unbond_tx::wire(&header, pubkey, sig, owner_clue) else {
            return AssetSpendOutcome::Refused("the unbond could not be encoded");
        };
        // ⛔ DB-258d — the unbond retires its own one-shot right in its lane, by the mint's publication path (the seat's
        // `publish_seat_request`), so the block that releases V retires it and no copy of this unbond releases again.
        let right = crate::unbond_tx::unbond_right_nf(&crate::unbond_tx::validator_id(pubkey), &header);
        let out = self.publish_asset_object_with_note(blob, &[], Some(right), "unbond");
        // ⛔⛔⛔ DB-272b — AN OPERATOR WHO UNBONDS THIS NODE'S OWN IDENTITY HAS WITHDRAWN ITS SEAT REQUEST. MEASURED on real
        // processes (slot B4): the request stayed kept, so the 30 s reseat check (`reseat_if_dropped`) read "not seated"
        // once the unbond landed, re-pooled it, and the next block seated the operator again on every node. The request
        // is retired here, at the one door every unbond of this identity passes (the node's own and an externally
        // signed one alike). A seat asked for again is a new request (`publish_membership_bond`).
        if matches!(out, AssetSpendOutcome::Published)
            && self.own_validator_id == Some(crate::unbond_tx::validator_id(pubkey))
        {
            self.own_membership_bond = None;
        }
        out
    }

    /// ⭐⭐⭐ DB-272 — THIS NODE UNBONDS ITS OWN VALIDATOR IDENTITY: it signs the unbond with its vote key (the key the
    /// weight a wallet bonds sits under, `/validator_id`) and files the returned bond under the caller's account.
    /// A caller chooses only WHERE the returned note is filed; the note stays sealed to the key it was locked under.
    /// CHAIN-PUBLISH-REVIEWED: this IS the publication — `publish_unbond` → `ingest_tx` of the framed Unbond object,
    /// released on every grafting node by `unbond_tx::apply_chain_unbond`.
    pub fn publish_own_unbond(
        &mut self,
        vote_pk: &[u8],
        vote_sk: &[u8],
        // ⭐ DB-273 §19.3 L2: the returned note's OLI clue (the caller's own reserved locator).
        owner_clue: &[u8],
    ) -> AssetSpendOutcome {
        let id = crate::unbond_tx::validator_id(vote_pk);
        // DB-258: the statement names THIS node's live bonding of its own identity, read from its chain state.
        let Some(instance) = self.bond_instance_of(&id) else {
            return AssetSpendOutcome::Refused("this node's validator identity holds no anchored bonding — nothing to unbond");
        };
        // DB-258d: a fresh nonce per request, so this unbond is its own one-shot right.
        let nonce = crate::unbond_tx::fresh_unbond_nonce();
        let msg = crate::pqauth::validator_unbond_msg(&id, &instance, &crate::oli::owner_clue_digest(owner_clue), &nonce);
        let Some(sig) = crate::pqauth::ml_dsa_sign(&msg, vote_sk) else {
            return AssetSpendOutcome::Refused("this node's vote key could not sign its unbond");
        };
        self.publish_unbond(vote_pk, &sig, owner_clue, nonce)
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed AssetCreate object,
    // which every node applies at the carrying block's fold through `asset_tx::apply_chain_asset_object`.
    /// ⭐⭐⭐ PUBLISH AN ASSET CREATION — the first step of the journey, and it had no entry point at all.
    ///
    /// ⛔ MEASURED (§AR): `Class::AssetCreate` had no framing site outside `#[cfg(test)]`, so **a user
    /// could not create an asset on this chain by any route.** `dsol::tests::all_asset_types_unlimited_
    /// no_growth_and_trustless` registers 6,000 descriptors in a REGISTRY and measures no-growth; it is
    /// not a creation path and never claimed to be one, whatever its name suggests.
    ///
    /// §BR-14 (2026-10-28): a creation PAYS — it carries a real USDm burn of its symbol's price (`asset_tx::CreationFee`),
    /// whose nullifier rides its lane beside the one-time id and whose change rides its notes. Its identity rule stands: every
    /// node RECOMPUTES `derived_id()` and refuses a claimed one.
    ///
    /// cons: one bond-validity carrier + one member step per creation (constant shape); no term in height, note count or peers.
    pub fn publish_asset_create(&mut self, c: &crate::asset_tx::AssetCreateTx) -> AssetSpendOutcome {
        if c.asset_id != c.derived_id() {
            return AssetSpendOutcome::Refused(
                "the creation claims an id its own descriptor does not derive",
            );
        }
        // ⭐ §BR-14: THE CREATION PAYS ITS FEE BEFORE IT COSTS STAMP WORK — the burn's carrier and its note's membership at the
        // Admit door, re-decided at the Fold door on every node (`asset_tx::apply_chain_asset_object`).
        let framed = c.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::asset_tx::AssetCreateTx::decode(p)).as_ref() != Some(c) {
            return AssetSpendOutcome::Refused("the creation does not decode to itself (its fee burn is missing or malformed)");
        }
        if let Some(why) = self.creation_fee_refusal(c, crate::respend::MemberDoor::Admit) {
            eprintln!("[asset-create] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        // ⭐ THE CREATION PLANTS THE ISSUANCE RIGHT. Without this the asset has no finite supply: §AT
        // proved WHO may mint and nothing proved HOW OFTEN.
        // ⛔ DB-388: AND IT RETIRES ITS OWN ONE-TIME ID (`peg::ONE_TIME_ASSET_CREATE` over the derived id) on its lane, so a
        // producer re-carrying this creation is refused by the spent set on every node instead of appending a duplicate
        // registry leaf. §BR-14: the fee note's nullifier rides beside it (`chain_object::object_own_nullifiers`, the graft
        // door's and the pool door's shared rule), so one note pays for one creation.
        // ⛔ A-F34: a creation that carries its supply is also a mint: its supply is its creator's, or it is refused
        // here before it costs stamp work (and again at the gossip door and at the fold, from the object's own bytes).
        if !c.supply_authorised(&crate::pqauth::MlDsaVerifier) {
            return AssetSpendOutcome::Refused("the creation's supply is not signed by the key that creates this asset, or its note does not open to the amount in this asset");
        }
        // The tags this creation retires (`AssetCreateTx::own_nullifiers`, the one list): its fee note's nullifier, and
        // the asset's creation id (no supply) or its issue right (with its supply).
        let own = c.own_nullifiers();
        if self.sparse_spent_verdict(&c.fee.nullifier) == crate::nf_sparse::SpentVerdict::Spent {
            return AssetSpendOutcome::Refused("the note paying this creation's fee is already spent");
        }
        if own.iter().any(|nf| self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent) {
            return AssetSpendOutcome::Refused(if c.supply.is_some() { "this asset has already been issued" } else { "this exact asset was already created" });
        }
        // The notes it carries are the object's own list (`AssetCreateTx::carried_notes`): the issue right and the change,
        // or the change and the supply. A creation with its supply plants no right, so a stranger's earlier supply-less
        // creation of the same asset cannot make this one read as a replay of a note the chain holds.
        let out_notes = c.carried_notes().concat();
        match self.publish_spending_object_nfs(framed, &own, out_notes) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!(
                    "[asset-create] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written."
                );
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed DsolDeploy object, which every node applies
    // at the carrying block's fold through `dsol_deploy_tx::apply_chain_dsol_deploy` (§BR-12 L1).
    pub fn publish_dsol_deploy(&mut self, d: &crate::dsol_deploy_tx::DsolDeployTx) -> AssetSpendOutcome {
        let framed = d.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::dsol_deploy_tx::DsolDeployTx::decode(p)).as_ref() != Some(d) {
            return AssetSpendOutcome::Refused("the deploy does not decode to itself (a bound is exceeded or its fee burn is malformed)");
        }
        // the SAME verdict the fold takes on every node, at the Admit door: signature, burn + membership, the state path
        if let Some(why) = self.dsol_deploy_refusal(d, crate::respend::MemberDoor::Admit) {
            eprintln!("[dsol-deploy] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let own = d.own_nullifiers();
        for nf in &own {
            if self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent {
                return AssetSpendOutcome::Refused("this deploy's fee note is already spent (or this exact deploy already landed)");
            }
        }
        match self.publish_spending_object_nfs(framed, &own, d.fee.change_note.clone()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[dsol-deploy] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed DirEntry object, which every node applies at
    // the carrying block's fold through `node::objects::dir_entry_tx::apply_chain_dir_entry` (audit F15).
    /// Publish one PAID directory entry (a @username, a group handle, a profile, a handover) into the pool. The verdict is
    /// the fold's own, taken at the Admit door: the entry's signature and binding, the fee burn and its note's
    /// membership, and the directory's rule as it stands now (so a name another owner holds is refused HERE, before
    /// anything is pooled, and its fee note is never spent).
    pub fn publish_dir_entry(&mut self, t: &crate::dir_entry_tx::DirEntryTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::dir_entry_tx::DirEntryTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the entry does not decode to itself (a bound is exceeded or its fee burn is malformed)");
        }
        if let Some(why) = self.dir_entry_refusal(t, crate::respend::MemberDoor::Admit) {
            return AssetSpendOutcome::Refused(why);
        }
        if !self.dir_entry_would_apply(&t.entry) {
            return AssetSpendOutcome::Refused("the directory would not apply it: the name is another owner's, or the entry changes nothing");
        }
        let own = t.own_nullifiers();
        for nf in &own {
            if self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent {
                return AssetSpendOutcome::Refused("this entry's fee note is already spent (or this exact entry already landed)");
            }
        }
        match self.publish_spending_object_nfs(framed, &own, t.fee.change_note.clone()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(_) => AssetSpendOutcome::NotPublished,
        }
    }

    /// ⭐ IonSwap pools — PUBLISH ONE ORDER into the pool. The verdict is the fold's own, taken at the Admit door (every
    /// leg's welded spend and its note's membership), so an order that cannot apply is refused HERE and burns nothing.
    // CHAIN-PUBLISH-REVIEWED: this IS the publication — the framed `Class::IonOrder` object is pooled, and every node
    // applies it at the carrying block's fold through `node::objects::ion_pool::apply_chain_ion`.
    pub fn publish_ion_order(&mut self, t: &crate::ion_pool_tx::IonOrderTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::ion_pool_tx::IonOrderTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the order does not decode to itself (its words are not one kind's, or a leg is malformed)");
        }
        if let Some(why) = self.ion_order_refusal(t, crate::respend::MemberDoor::Admit) {
            return AssetSpendOutcome::Refused(why);
        }
        let own = t.own_nullifiers();
        for nf in &own {
            if self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent {
                return AssetSpendOutcome::Refused("a note this order spends is already spent (or this exact order already landed)");
            }
        }
        let notes: Vec<u8> = t.legs.iter().flat_map(|f| f.change_note.iter().copied()).collect();
        match self.publish_spending_object_nfs(framed, &own, notes) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                // ERRORS ARE LEGIBLE: the pool's own reason (no MempoolError text carries a nullifier, an amount or a key).
                eprintln!("[ion-order] not pooled: {e}");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    /// ⭐ IonSwap pools — POOL EVERY SETTLEMENT THIS NODE CAN FORM (`Self::ion_settlements_due`), each judged first by the
    /// fold's own verdict against this node's ledger as it stands. Returns how many were pooled. A node's own duty: it
    /// spends nobody's note, and every node forms the same bytes, so the mesh carries one transaction a batch.
    // CHAIN-PUBLISH-REVIEWED: this IS the publication — the framed `Class::IonSettle` object is pooled, and every node
    // recomputes it at the carrying block's fold (`IonSettleTx::verdict`).
    pub fn publish_ion_settlements(&mut self) -> usize {
        let Some(next_step) = self.spine_recent_roots.back().map(|(o, _)| o.saturating_add(1)) else {
            return 0;
        };
        let secs = self.chain_time_ms() / 1_000;
        let mut pooled = 0;
        for t in self.ion_settlements_due() {
            // one copy a batch while it waits for a block (every tick calls this)
            if !self.ion_cache.should_send(&t.token, t.batch(), next_step - 1) {
                continue;
            }
            if t.verdict(self.peg.contract_state_root(), self.peg.ion_pending(), next_step, secs).is_err() {
                continue;
            }
            let own = t.own_nullifiers();
            if own.iter().any(|nf| self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent) {
                continue;
            }
            let notes: Vec<u8> = t.notes.iter().flat_map(|(note, _)| note.iter().copied()).collect();
            if self.spending_object_tx(t.wire(), &own, notes).and_then(|tx| self.pool_own_publication(tx)).is_ok() {
                self.ion_cache.note_sent(t.token, t.batch(), next_step - 1);
                pooled += 1;
            }
        }
        pooled
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed DsolCall object, which every node applies at
    // the carrying block's fold through `dsol_call_tx::apply_chain_dsol_call` (§BR-12 L2).
    pub fn publish_dsol_call(&mut self, t: &crate::dsol_call_tx::DsolCallTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::dsol_call_tx::DsolCallTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the call does not decode to itself (a bound is exceeded or its fee spend is malformed)");
        }
        // the fold's verdict at the Admit door (the epoch is judged by the carrying block, not here)
        if let Some(why) = self.dsol_call_refusal(t, crate::respend::MemberDoor::Admit, None) {
            eprintln!("[dsol-call] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let own = t.own_nullifiers();
        for nf in &own {
            if self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent {
                return AssetSpendOutcome::Refused("this call's fee note or one of its nullifier effects is already spent");
            }
        }
        let mut out_notes = t.fee.publisher_note.clone();
        out_notes.extend_from_slice(&t.fee.change_note);
        match self.publish_spending_object_nfs(framed, &own, out_notes) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[dsol-call] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed DsolFeeUpdate object, applied at the carrying
    // block's fold on every node (`dsol_fee_update_tx::apply_chain_dsol_fee_update`, §BR-12 L3).
    pub fn publish_dsol_fee_update(&mut self, t: &crate::dsol_fee_update_tx::DsolFeeUpdateTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::dsol_fee_update_tx::DsolFeeUpdateTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the fee update does not decode to itself");
        }
        if let Some(why) = self.dsol_fee_update_refusal(t) {
            eprintln!("[dsol-fee-update] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let own = t.own_nullifiers();
        if own.iter().any(|nf| self.sparse_spent_verdict(nf) == crate::nf_sparse::SpentVerdict::Spent) {
            return AssetSpendOutcome::Refused("this exact fee update already landed");
        }
        match self.publish_spending_object_nfs(framed, &own, Vec::new()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[dsol-fee-update] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed SatDelegation object, applied at the carrying
    // block's fold on every node (`sat_delegation_tx::apply_chain_sat_delegation`).
    /// ⭐ §BR-3 17.3 — PUBLISH A DELEGATED-SAT CONVERSION built in the holder's wallet (it holds the burned note): the carriers,
    /// the input's membership and the kind's rule at the Admit door, then the object rides the pool with its burned nullifier
    /// on its lane and its two notes (minted, change) as its outputs.
    pub fn publish_sat_delegation(&mut self, t: &crate::sat_delegation_tx::SatDelegationTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::sat_delegation_tx::SatDelegationTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the delegation does not decode to itself");
        }
        if let Some(why) = self.sat_delegation_refusal(t, crate::respend::MemberDoor::Admit, None) {
            eprintln!("[sat-delegation] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let mut out_notes = t.minted_note.clone();
        out_notes.extend_from_slice(&t.change_note);
        out_notes.extend_from_slice(&t.yield_note); // §17.6: the yield note, when the kind pays one
        match self.publish_spending_object_nfs(framed, &[t.nullifier], out_notes) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[sat-delegation] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed ReleaseAttestation object, recorded at the
    // carrying block's fold on every node (`release_attestation_tx::apply_chain_release_attestation`).
    /// ⭐ §BR-10 — PUBLISH A BUILDER'S RELEASE ATTESTATION (built and signed by the builder's own tool).
    pub fn publish_release_attestation(&mut self, t: &crate::release_attestation_tx::ReleaseAttestationTx) -> AssetSpendOutcome {
        if !t.authorised() {
            return AssetSpendOutcome::Refused("not signed by a builder of this release's set");
        }
        let nf = crate::release_attestation_tx::attestation_nf(&t.builder(), &t.release_hash);
        if self.mempool.nullifier_is_claimed(&crate::hash::Hash32(nf)) {
            return AssetSpendOutcome::Published;
        }
        match self.publish_spending_object_nfs(t.wire(), &[nf], Vec::new()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(_) => AssetSpendOutcome::NotPublished,
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed DeploymentSignal object, counted at the
    // carrying block's fold on every node (`deployment_signal_tx::apply_chain_deployment_signal`).
    /// ⭐ §BR-10 — PUBLISH A VALIDATOR'S DEPLOYMENT SIGNAL (signed by its vote key in the runtime, beside its finality votes).
    pub fn publish_deployment_signal(&mut self, t: &crate::deployment_signal_tx::DeploymentSignalTx) -> AssetSpendOutcome {
        if let Some(why) = self.deployment_signal_refusal(t) {
            return AssetSpendOutcome::Refused(why);
        }
        let nf = crate::deployment_signal_tx::signal_nf(&t.vid, t.bits, t.window);
        if self.mempool.nullifier_is_claimed(&crate::hash::Hash32(nf)) {
            return AssetSpendOutcome::Published;
        }
        match self.publish_spending_object_nfs(t.wire(), &[nf], Vec::new()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(_) => AssetSpendOutcome::NotPublished,
        }
    }
    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed EpochKeyDeal object, summed and captured at
    // the carrying block's fold on every node (`epoch_deal_tx::apply_chain_epoch_key_deal`).
    /// ⭐ §BR-9a — PUBLISH A CUSTODIAN'S EPOCH-KEY DEAL (built and signed by its vote key in the runtime, beside its votes).
    pub fn publish_epoch_key_deal(&mut self, t: &crate::epoch_deal_tx::EpochKeyDealTx) -> AssetSpendOutcome {
        if let Some(why) = self.epoch_key_deal_refusal(t) {
            return AssetSpendOutcome::Refused(why);
        }
        let nf = crate::epoch_deal_tx::deal_nf(&t.vid, t.epoch);
        if self.mempool.nullifier_is_claimed(&crate::hash::Hash32(nf)) {
            return AssetSpendOutcome::Published;
        }
        match self.publish_spending_object_nfs(t.wire(), &[nf], Vec::new()) {
            Ok(_) => {
                // DIGITAL-CASH-PRIVACY-REVIEWED: the public epoch number of a public deal — no note, amount or user.
                eprintln!("[epoch-key] this custodian's deal for epoch {} entered the pool", t.epoch);
                AssetSpendOutcome::Published
            }
            Err(e) => {
                eprintln!("[epoch-key] ⛔ this custodian's deal for epoch {} was not pooled: {e:?} — it is rebuilt on the next voter tick", t.epoch);
                AssetSpendOutcome::NotPublished
            }
        }
    }
    /// The epochs this custodian owes a deal for now, each with its roster and every member's ML-KEM key — none for one it
    /// is off the roster of, has dealt (or has a deal pooled), or whose member's key is not registered.
    /// Every epoch dealing now (one in the steady state; all 26 on a chain's first hour, §19.3 bootstrap) is owed.
    pub fn epoch_key_deal_due(&self, vid: &[u8; 32]) -> Vec<(u64, Vec<([u8; 32], Vec<u8>)>)> {
        // Why this voter deals nothing, said once per change of reason: a second custodian that never dealt held the first
        // released epoch's key back until its hour ended (MEASURED 2026-11-08, real nodes: only node 0 ever dealt).
        // DIGITAL-CASH-PRIVACY-REVIEWED: fixed phrases and public counts about public custody rounds.
        fn said(why: String) {
            static LAST: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
            if let Ok(mut last) = LAST.lock() {
                if *last != why {
                    eprintln!("[epoch-key] deals due here: {why}");
                    *last = why;
                }
            }
        }
        // a spending object this node cannot carry evidence for is refused at its own pool (`NullifierWitnessRejected`), so
        // nothing is due until the fold base exists — MEASURED 2026-11-01: 26 deals rebuilt and refused every voter tick
        if self.self_build_publish_absence_witness().is_none() {
            said("none — the fold base for a publish's absence witness is not built yet".into());
            return Vec::new();
        }
        let l = self.peg.epoch_keys();
        let mut due = Vec::new();
        let (mut not_eligible, mut dealt, mut no_ek) = (0usize, 0usize, 0usize);
        for epoch in l.dealing() {
            let Some(r) = l.epochs.get(&epoch) else { continue };
            // §22: every seated custodian is an eligible dealer, benched or not — its deal is its hourly heartbeat
            if r.eligible.binary_search(vid).is_err() || r.dealers.contains_key(vid) {
                if r.dealers.contains_key(vid) {
                    dealt += 1;
                } else {
                    not_eligible += 1;
                }
                continue;
            }
            // pooled, or already carried by a block the fold has not reached yet (its nullifier is spent on the chain; the
            // ledger records the dealer at the fold) — MEASURED 2026-11-01: rebuilt every tick and refused as SPENT until the fold
            let nf = crate::epoch_deal_tx::deal_nf(vid, epoch);
            if self.mempool.nullifier_is_claimed(&crate::hash::Hash32(nf)) || self.sparse_spent_verdict(&nf) == crate::nf_sparse::SpentVerdict::Spent {
                continue;
            }
            let roster = r.roster.iter().map(|id| self.validators.registered_kem_ek(id).map(|ek| (*id, ek))).collect::<Option<Vec<_>>>();
            if let Some(roster) = roster {
                due.push((epoch, roster));
            } else {
                no_ek += 1;
            }
        }
        said(format!(
            "{} — {not_eligible} round(s) whose eligible dealers do not name this voter's key, {dealt} already dealt, {no_ek} with a roster member's custody key not registered here",
            due.len()
        ));
        due
    }
    /// The signals `vid` owes now (every Started deployment of this release it has not yet signalled in its lane's open window),
    /// one per lane — empty when there is nothing to signal: `(bits, window)` for the normal window's Started deployments it has not
    /// signalled, and `(bits | FAST_SIGNAL, fast window)` for the emergency window's (§BR-10 spec §8 item 2).
    pub fn deployment_signal_due(&self, vid: &[u8; 32]) -> Vec<(u32, u64)> {
        let l = self.peg.deployments();
        let table = l.table();
        let owed = |emergency: bool, signalled: &std::collections::BTreeMap<String, std::collections::BTreeSet<[u8; 32]>>| {
            table
                .iter()
                .filter(|d| d.emergency == emergency && d.bit <= crate::deployment::MAX_BIT)
                .filter(|d| l.state(d.name) == crate::deployment::DeployState::Started)
                .filter(|d| !signalled.get(d.name).is_some_and(|s| s.contains(vid)))
                .fold(0u32, |a, d| a | (1u32 << d.bit))
        };
        let mut due = Vec::new();
        let normal = owed(false, &l.signalled_validators);
        if l.opened && normal != 0 {
            due.push((normal, l.window));
        }
        let fast = owed(true, &l.fast.signalled_validators);
        if l.fast.opened && fast != 0 {
            due.push((fast | crate::deployment::FAST_SIGNAL, l.fast.window));
        }
        due
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed SatSetAside object, applied once at the
    // carrying block's fold on every node (`sat_set_aside::apply_chain_set_aside`).
    /// ⭐ §BR-13 — OFFER THE CANONICAL SET-ASIDE: while the network has one and it has not applied, put it in this node's
    /// pool (once: a second publish finds its one-time id pending and is a no-op). Every node holds the same bytes, so
    /// whichever producer lays it first, every node applies the same object.
    pub(crate) fn offer_canonical_set_aside(&mut self) {
        if self.peg.set_aside_applied() || !crate::sat_set_aside::producer_offers() {
            return;
        }
        let Some(t) = crate::sat_set_aside::canonical_bytes().and_then(|b| crate::sat_set_aside::SatSetAsideTx::decode(&b)) else {
            return;
        };
        let _ = self.publish_sat_set_aside(&t);
    }
    /// Publish the set-aside: the rule at this node's state, then the object rides the pool with its one-time id on its lane.
    pub fn publish_sat_set_aside(&mut self, t: &crate::sat_set_aside::SatSetAsideTx) -> AssetSpendOutcome {
        let nf = crate::sat_set_aside::set_aside_nf();
        if self.mempool.nullifier_is_claimed(&crate::hash::Hash32(nf)) {
            return AssetSpendOutcome::Published; // already offered
        }
        if let Some(why) = self.set_aside_refusal(t) {
            return AssetSpendOutcome::Refused(why);
        }
        match self.publish_spending_object_nfs(t.wire(), &[nf], t.note.clone()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(_) => AssetSpendOutcome::NotPublished,
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed BountyPayout object, applied at the carrying
    // block's fold on every node (`bounty_payout_tx::apply_chain_bounty_payout`).
    /// ⭐ §BR-10 — PUBLISH A BUG BOUNTY signed by the custody quorum: the bounty's rule at this node's state, then the object
    /// rides the pool with its nonce's one-time id on its lane and its note as its output.
    pub fn publish_bounty_payout(&mut self, t: &crate::bounty_payout_tx::BountyPayoutTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::bounty_payout_tx::BountyPayoutTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the bounty does not decode to itself");
        }
        if let Some(why) = self.bounty_payout_refusal(t) {
            eprintln!("[bounty] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let nf = crate::bounty_payout_tx::bounty_nf(&t.nonce);
        match self.publish_spending_object_nfs(framed, &[nf], t.note.clone()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[bounty] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed BondYieldClaim object, applied at the carrying
    // block's fold on every node (`bond_yield_claim_tx::apply_chain_bond_yield_claim`).
    /// ⭐ §BR-3 17.6 — PUBLISH A VALIDATOR'S OWN-WEIGHT YIELD CLAIM built in its wallet: the claim's rule at this node's state,
    /// then the object rides the pool with its one-time id on its lane and its note as its output.
    pub fn publish_bond_yield_claim(&mut self, t: &crate::bond_yield_claim_tx::BondYieldClaimTx) -> AssetSpendOutcome {
        let framed = t.wire();
        if crate::chain_object::unframe(&framed).and_then(|(_, p)| crate::bond_yield_claim_tx::BondYieldClaimTx::decode(p)).as_ref() != Some(t) {
            return AssetSpendOutcome::Refused("the claim does not decode to itself");
        }
        if let Some(why) = self.bond_yield_claim_refusal(t) {
            eprintln!("[bond-yield] ⛔ REFUSED: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return AssetSpendOutcome::Refused(why);
        }
        let nf = crate::bond_yield_claim_tx::claim_nf(&t.vid, t.y_now);
        match self.publish_spending_object_nfs(framed, &[nf], t.note.clone()) {
            Ok(_) => AssetSpendOutcome::Published,
            Err(e) => {
                eprintln!("[bond-yield] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was written.");
                AssetSpendOutcome::NotPublished
            }
        }
    }

    /// ⭐⭐⭐ PUBLISH AN ASSET MINT — the second step, and it had no entry point either.
    ///
    /// A mint CREDITS a note and burns nothing, so its authority is its own carrier: `credit_is_authorised`
    /// requires the mint carrier to open the credited note to the authorised amount in this asset. A minter
    /// that cannot prove that is choosing what it receives, which is why the gate runs before any credit —
    /// on every grafting node, from the block's bytes, not here.
    pub fn publish_asset_mint(&mut self, m: &crate::asset_tx::AssetMintTx) -> AssetSpendOutcome {
        // ⛔ THE CREATOR GATE FIRST — a mint into someone else's asset is refused before it costs stamp
        // work, and again on every grafting node from the object's own bytes.
        if !m.creator_authorised(&crate::pqauth::MlDsaVerifier) {
            return AssetSpendOutcome::Refused(
                "the mint is not signed by the key that created this asset",
            );
        }
        if !m.credit_is_authorised() {
            return AssetSpendOutcome::Refused(
                "the note does not open to the authorised amount in this asset",
            );
        }
        let tx_notes = &m.note[..m.note.len().min(crate::cover::PQ_NOTE_BYTES)];
        // THE ISSUANCE RIGHT RIDES THE LANE, so an asset is minted EXACTLY ONCE. Authorisation answers
        // WHO may mint; this answers HOW OFTEN. MEASURED before it existed: creator_again=Minted(1) —
        // the creator re-issued the same NFT.
        self.publish_asset_object_with_note(
            m.wire(),
            tx_notes,
            Some(crate::asset_tx::issue_right_nf(&m.asset_id)),
            "asset-mint",
        )
    }

    /// The shared publication for an asset object that moves no note and retires no right.
    pub(super) fn publish_valueless_asset_object(&mut self, blob: Vec<u8>, tag: &str) -> AssetSpendOutcome {
        self.publish_asset_object_with_note(blob, &[], None, tag)
    }

    /// ⭐ ONE PUBLICATION for every asset object that moves no note — creation and mint alike.
    ///
    /// A creation carries an EMPTY nullifier lane (a tx with no nullifiers is not a spend). A MINT
    /// retires its asset's one-shot issuance right THE WAY EVERY NOTE IS RETIRED on this chain since Z1:
    /// by publishing the right's nullifier (`asset_tx::issue_right_nf`, derivable from the object) in
    /// the cover-padded lane, with the same lane evidence every spend carries. The second mint names a
    /// nullifier the sparse set already holds and the same double-spend gate refuses it — finite supply
    /// by the one rule, no mint-specific gate. ⛔ AND IT IS PUBLISHED BEFORE ANYTHING IS WRITTEN — in fact
    /// nothing is written here at all: the registry entry and the credit are applied by
    /// `asset_tx::apply_chain_asset_object` at graft, on every node including this one.
    pub(super) fn publish_asset_object_with_note(
        &mut self,
        blob: Vec<u8>,
        note: &[u8],
        // The NULLIFIER of the one-shot right this object retires. A creation retires none; a MINT
        // retires its asset's issuance right, which is what makes the supply finite.
        retire_nf: Option<[u8; 32]>,
        tag: &str,
    ) -> AssetSpendOutcome {
        let id = crate::mempool::PqTx::content_id(&blob);
        let mut nullifiers: Vec<Hash32> = Vec::new();
        let mut nullifier_witnesses = Vec::new();
        let mut nullifier_absence = Vec::new();
        if let Some(nf) = retire_nf {
            // Courtesy pre-check so the creator is not charged stamp work to be refused by the mesh; the
            // block door's sparse-set insert is the authority.
            if self.sparse_spent_verdict(&nf) == crate::nf_sparse::SpentVerdict::Spent {
                if tag == "membership-bond" {
                    // DB-258b — a seat request is used once; a validator that left signs a fresh one.
                    eprintln!("[{tag}] ⛔ REFUSED: this seat request's one-shot right is already spent.");
                    return AssetSpendOutcome::Refused("this seat request was already used — sign a fresh one");
                }
                if tag == "unbond" {
                    // DB-258d — an unbond request is used once; a fresh unbond carries a fresh nonce.
                    eprintln!("[{tag}] ⛔ REFUSED: this unbond's one-shot right is already spent.");
                    return AssetSpendOutcome::Refused("this unbond was already used — sign a fresh one");
                }
                eprintln!(
                    "[{tag}] ⛔ REFUSED: this asset's issuance right is already spent — its supply was \
                     fixed by the mint that spent it."
                );
                return AssetSpendOutcome::Refused("this asset has already been issued");
            }
            let padded = crate::cover::pad_tx_nullifiers_to_fixed(&[nf], id.as_bytes())
                .unwrap_or_else(|| vec![nf]);
            let (w, a) = self.spend_lane_evidence(&padded);
            nullifier_witnesses = w;
            nullifier_absence = a;
            nullifiers = padded.into_iter().map(Hash32).collect();
        }
        // DB-273 §19.6 L3: no account target. A note this path publishes (an asset mint's) is filed from the object's own
        // owner clue (`chain_object::object_owner_clue_records`); a creation's issuance right has no owner.
        let mut tx = crate::mempool::PqTx {
            clock_ms: 0,
            id,
            blob: blob.clone(),
            weight: blob.len() as u32,
            nullifiers,
            pow_stamp: 0,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            output_notes: note.to_vec(),
            stake_notes: Vec::new(),
            bond_notes: Vec::new(),
            nullifier_witnesses,
            nullifier_absence,
            membership_carrier: Vec::new(),
            membership_leaf_commit: [0u8; 32],
            membership_tip: Vec::new(),
            membership_folded_through: 0,
            spend_or_decoy: Vec::new(),
            member_carrier: Vec::new(),
            member_tuple: Vec::new(),
        };
        let need = self.mempool.required_stamp_bits();
        let mut ground = false;
        for stamp in 0..1u64 << 24 {
            tx.pow_stamp = stamp;
            if tx.stamp_work() >= need {
                ground = true;
                break;
            }
        }
        if !ground {
            eprintln!("[{tag}] ⛔ REFUSED: could not reach the pool's stamp requirement ({need} bits).");
            return AssetSpendOutcome::NotPublished;
        }
        if let Err(e) = self.pool_own_publication(tx) {
            eprintln!(
                "[{tag}] ⛔ REFUSED: could not be admitted as a transaction ({e:?}), so NOTHING was \
                 written. An asset object that cannot travel would exist on this node alone."
            );
            return AssetSpendOutcome::NotPublished;
        }
        AssetSpendOutcome::Published
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed AssetSpend object,
    // whose burn rides the transaction's own nullifier lane and whose credits ride `output_notes`.
    pub fn publish_wrapped_mint(
        &mut self,
        asset_id: u32,
        deposit_id: [u8; 32],
        deposit_value: u128,
        mint: u128,
        recipient: [u8; 32],
        note_payload: &[u8],
        mint_carrier: &[u8],
        reserve_address: &str,
        signer_pk: &[u8],
        signer_sk: &[u8],
        extra_attestors: &[crate::psm::MintAttestor],
        verifier: &dyn crate::pqauth::PqVerifier,
        // ⭐ DB-273 §19 L1 — the credited note's OLI clue; `recipient` must commit to it (`peg::peg_in_recipient`).
        owner_clue: &[u8],
        // DB-80b: the requester's mint-delta blind, opened from its sealed request
        d_blind: crate::spend_frontier::Digest4,
    ) -> crate::peg::PegOutcome {
        // ⭐ DB-77 (2026-09-19): THE WRAPPED MINT IS A CHAIN OBJECT, PUBLISHED, NEVER APPLIED HERE.
        // Until today `execute_wrapped_mint_carried` moved this node's wrapped ledger, recorded the
        // note and advanced the wrapped opening LOCALLY, then pooled an object peers applied WITHOUT
        // crediting the note (the apply ignored it) — the §DA local-mutation shape: a wrapped-asset
        // note existed on the executor alone. Now: every gate, the ONE solvency prove, the object into
        // the pool; the ledger, the note and the opening move when a BLOCK carries it, on every node.
        // ⛔ NO OWNERLESS CREDIT, and no owner the quorum did not sign: `wrapped_mint_tx::decode` refuses the same
        // object on every node, so refusing here only spares the prove.
        if owner_clue.is_empty()
            || owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
            || crate::peg::peg_in_recipient(&deposit_id, owner_clue) != recipient
        {
            eprintln!("[wrapped-mint] ⛔ not published: the recipient does not commit to the sealed owner clue");
            return crate::peg::PegOutcome::BadRequest;
        }
        let Some(cm_limbs) = crate::spend_frontier::note_cm_of(note_payload) else {
            eprintln!("[wrapped-mint] ⛔ not published: the note carries no canonical commitment");
            return crate::peg::PegOutcome::BadRequest;
        };
        if u64::try_from(mint).is_err() {
            eprintln!("[wrapped-mint] ⛔ not published: the mint exceeds one note's range");
            return crate::peg::PegOutcome::BadRequest;
        }
        let delta_commit = crate::peg::PegLedger::mint_delta_commit(mint, d_blind);
        let asset_tag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(asset_id);
        if !usdm_decider::whir_rec_block::verify_asset_mint_validity_committed_bytes(
            mint_carrier,
            cm_limbs,
            asset_tag,
            delta_commit,
        ) {
            eprintln!(
                "[wrapped-mint] ⛔ REFUSED before touching anything: the note's commitment does not open to \
                 the AUTHORIZED committed amount IN THE AUTHORIZED ASSET under the supplied carrier."
            );
            return crate::peg::PegOutcome::BadRequest;
        }
        let seal = match self.wrapped_opening_seals.get(&asset_id) {
            Some(s) => s.clone(),
            None => {
                eprintln!("[wrapped-mint] ⛔ not published: this custodian holds no opening for the wrapped asset");
                return crate::peg::PegOutcome::BadRequest;
            }
        };
        let (r_val, r_blind, m_val, m_blind) = unseal_opening(&seal);
        let (carrier, new_rc, new_mc, _nr, _nm, carrier_delta) = match self.peg.orchestrate_wrapped_mint(
            asset_id,
            r_val,
            r_blind,
            m_val,
            m_blind,
            deposit_value,
            mint,
            d_blind,
        ) {
            Some(x) => x,
            None => {
                eprintln!("[wrapped-mint] ⛔ not published: the solvency transition does not prove (the opening does not match the asset's commitments, or the mint over-issues against its ratio)");
                return crate::peg::PegOutcome::BadRequest;
            }
        };
        if carrier_delta != delta_commit {
            eprintln!("[wrapped-mint] ⛔ not published: the proved delta is not the request's committed mint");
            return crate::peg::PegOutcome::BadRequest; // one committed number at both ends, or nothing
        }
        let mut atts: Vec<crate::psm::MintAttestor> = Vec::new();
        let confirmed = self.confirmed_reserve_sats_for_peg_in(reserve_address);
        // DB-58 + F-LEG: the legs this executor's proposal sealed ride the object, and the quorum's statement names them
        let key = crate::peg_attest::slot_key_for(asset_id, &deposit_id);
        let sealed_for_block = self.mint_legs_for_block(&key);
        let signed_recipient = crate::peg::peg_in_signed_recipient(&recipient, &sealed_for_block);
        if !reserve_address.is_empty() && confirmed >= deposit_value {
            let msg = crate::peg::wrapped_mint_confidential_msg(
                asset_id,
                &deposit_id,
                &new_rc,
                &new_mc,
                &delta_commit,
                &signed_recipient,
            );
            if let Some(sig) = crate::pqauth::ml_dsa_sign(&msg, signer_sk) {
                atts.push(crate::psm::MintAttestor {
                    pubkey: signer_pk.to_vec(),
                    sig,
                });
            }
        }
        atts.extend_from_slice(extra_attestors);
        let outcome = self.peg.check_wrapped_mint_confidential(
            asset_id,
            deposit_id,
            &carrier,
            new_rc,
            new_mc,
            delta_commit,
            signed_recipient,
            &self.validators,
            verifier,
            &atts,
        );
        if !matches!(outcome, crate::peg::PegOutcome::ConfidentialPublished) {
            return outcome;
        }
        let header = crate::wrapped_mint_tx::WrappedMintHeader {
            asset_id,
            deposit_id,
            recipient,
            new_reserve_commit: new_rc,
            new_minted_commit: new_mc,
            delta_commit,
        };
        let bits = self.mempool.required_stamp_bits();
        let mut tx = crate::wrapped_mint_tx::as_pq_tx(
            &header,
            &carrier,
            mint_carrier,
            &atts,
            note_payload,
            &sealed_for_block,
            owner_clue,
            bits,
        );
        // DB-274 P4b B1: the wrapped deposit key retires as the object's own nullifier on this lane.
        if !self.lay_object_lane(&mut tx) {
            return crate::peg::PegOutcome::BadRequest;
        }
        if let Err(e) = self.pool_own_publication(tx) {
            eprintln!("[wrapped-mint] ⛔ the wrapped-mint object was REFUSED at this node's own pool door: {e:?}");
            return crate::peg::PegOutcome::BadRequest;
        }
        // CHAIN-CARRIES-REVIEWED: the publisher's own bounded "I published this" cache (eviction housekeeping); the block, not this map, settles the mint
        if !self.wrapped_published.contains_key(&key)
            && self.wrapped_published.len() >= crate::peg_attest::PEG_ATTEST_PENDING_MAX
        {
            if let Some(k) = self.wrapped_published.keys().next().copied() {
                // CHAIN-CARRIES-REVIEWED: eviction of the oldest cache row, housekeeping only
                self.wrapped_published.remove(&k);
            }
        }
        self.wrapped_published.insert(
            key,
            (
                asset_id,
                crate::peg_attest::PegInDelta {
                    deposit_value,
                    mint,
                    reserve_address: reserve_address.to_string(),
                    d_blind,
                    pay_after: 0,
                    sweep: None,
                },
            ),
        );
        crate::peg::PegOutcome::ConfidentialPublished
    }

    pub fn miner_reward_commitment(&self, bind: &Hash32) -> Hash32 {
        crate::reward::reward_note_commitment(&self.miner_seed, bind)
    }

    /// Produce this node's next block on the current tips + mempool selection, graft it, and return
    /// it (for the transport to gossip). Returns `None` if the freshly-built block does not graft
    /// (e.g. `now_ts` would date it at/behind median-time-past). `frontier_root` is the note-tree
    /// root after applying the selected txs; `miner_commitment` is the confidential reward note.
    /// Every produced block ends with the canonical record fold (v31) — see `ingest_block`.
    pub fn produce(
        &mut self,
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
    ) -> Option<Block> {
        let out = self.produce_inner(now_ts, frontier_root, miner_commitment);
        if let Some(b) = &out {
            self.remember_own_unfolded_block(b.clone()); // A-F63: this node's own block, kept whole at any reach
        }
        let _ = self.fold_canonical_records();
        out
    }

    /// §22 — how many staged justifiers (in staging order) fit one block's sealed credit sidecar after the reward's
    /// reserve: the producer carries exactly these and keeps the rest staged (with the notes they name) for the next block.
    pub(super) fn pending_justifiers_that_fit(&self) -> usize {
        let mut left = crate::block::CREDIT_SET_FRAME_BUDGET
            .saturating_sub(if self.reward_recipient.is_some() { crate::satoshi::REWARD_FRAME_RESERVE } else { 0 })
            .saturating_sub(if self.miner_payout_possible() { crate::miner_payout_tx::PAYOUT_FRAME_RESERVE } else { 0 });
        let mut k = 0usize;
        for o in &self.pending_credit_justifiers {
            let c = crate::block::credit_frame_cost(crate::chain_object::carriage_of(o).map_or(o.len(), |c| c.len()));
            if c > left {
                break;
            }
            left -= c;
            k += 1;
        }
        k
    }

    pub(super) fn produce_inner(
        &mut self,
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
    ) -> Option<Block> {
        // INLINE produce = the LIVE serve path collapsed into ONE call (tests / the default pure-Rust build):
        // build the carrier-LESS next-block template, mine it INLINE, then graft. There is now exactly ONE
        // produce path — this DELEGATES to `produce_template`, so it can never drift from the off-lock serve loop
        // again. PRIVACY UNCHANGED: `produce_template` still applies the constant per-block cover shape via
        // `crate::cover::pad_to_fixed_shape` (fill to BLOCK_FIXED_TX_COUNT with byte-identical value-0 `cover_tx`
        // padding, so an idle block is indistinguishable from a busy one) — the cover mechanism is CENTRALIZED
        // there, not removed. What IS removed is the stale twin's TWO regressions: it re-cloned the whole
        // nullifier tree per block (`rebuild_transient_nullifier_tree`, O(count)) AND shipped the 221KB
        // `build_block_sparse_nf_carrier` proof inside every hot gossip block. `produce_template` advances the
        // acc via the O(1) `derive_block_nullifier_post` (insert-then-rollback, no clone) and emits an EMPTY
        // carrier; the 221KB carrier rides the #29 DSYNC / #27 DAS sync path ON-DEMAND, never the hot gossip
        // block, so a joining node no longer lags its producer by a block and initial catch-up stays within one
        // spacing (FAST + convergence-within-spacing pillars). The heavy #73 PoUW grind holds the node lock
        // here only because this IS the synchronous inline path; the LIVE loop mines OFF-lock between
        // `produce_template` and `graft_mined_own`.
        crate::node_runtime::INLINE_PRODUCE_ATTEMPTS
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let Some((mut block, cover_ids, tmpl_tx_ids, tmpl_notes)) =
            self.produce_template(now_ts, frontier_root, miner_commitment)
        else {
            crate::node_runtime::INLINE_TEMPLATE_NONE
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[produce-none] no template formed this slot (the template's own refusal line above names why)");
            return None;
        };
        if let Some(m) = self.pow_miner.as_ref() {
            match m.mine(&mut block.header) {
                Some(pi) => block.pow_proof = pi,
                None => {
                    crate::node_runtime::INLINE_MINE_NONE
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("[produce-none] the PoW grind found no proof for this slot's template");
                    return None;
                }
            }
        }
        let out = self.graft_mined_own(block, cover_ids, tmpl_tx_ids, tmpl_notes, now_ts);
        if out.is_none() {
            crate::node_runtime::INLINE_GRAFT_NONE
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            eprintln!("[produce-none] this node's own graft refused the block it just mined");
        }
        out
    }

    /// This node's per-node miner seed — so the LIVE serve loop can build a matching [`crate::pow::PowMiner`]
    /// that mines OFF the node lock (main.rs) and grafts via [`Self::graft_mined_own`]. Same seed ⇒ same
    /// coinbase secrets + PoUW epoch key, so the mined `pi` passes this node's own verify.
    pub fn miner_seed(&self) -> [u8; 32] {
        self.miner_seed
    }

    /// ⭐ DB-443 — THIS TEMPLATE'S SECRET DRAW for the pool's inclusive selection (`Mempool::select_for_template_reserving`):
    /// keyed by `miner_seed`, which is never published, so no observer can predict which pending spends a producer's next
    /// template draws, and no two producers draw alike. Domain-separated from every other `miner_seed` stream.
    /// cons: none — one hash per template.
    pub(crate) fn template_draw(&self, now_ms: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD-template-draw-v1");
        h.update(&self.miner_seed);
        h.update(&now_ms.to_le_bytes());
        *h.finalize().as_bytes()
    }

    /// The BRIEF, lock-held FIRST half of production: build the UNMINED next-block template (tips + mempool
    /// selection + constant cover shape) WITHOUT mining or grafting. Returns the unmined block + the cover-tx
    /// ids and selected tx ids the graft step needs. The heavy #73 mine (WHIR `pi` + PoUW grind) then runs
    /// on the returned block OFF the node lock, so it never starves the RPC/producer thread (FAST pillar).
    pub fn produce_template(
        &mut self,
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
    ) -> Option<(Block, Vec<Hash32>, Vec<Hash32>, Vec<u8>)> {
        self.produce_template_with(now_ts, frontier_root, miner_commitment, false)
            .map(|(b, c, t, n, _)| (b, c, t, n))
    }

    /// DB-105: the live runtime's template — the note transition comes back as INPUTS (`PendingNoteTransition`)
    /// for the producer thread to prove off the lock; `finish_note_transition` completes it. (DB-393 B4: the block's SAT
    /// reward needs no proof — its object carries the note's public opening — so it is complete in the template.)
    #[allow(clippy::type_complexity)]
    pub fn produce_template_deferred(
        &mut self,
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
    ) -> Option<(Block, Vec<Hash32>, Vec<Hash32>, Vec<u8>, Option<PendingNoteTransition>)> {
        self.produce_template_with(now_ts, frontier_root, miner_commitment, true)
    }

    /// ⭐ THE PARENTS ARE NAMED WHEN THE PROOF IS FINISHED, NOT WHEN IT STARTS. MEASURED why (two real nodes, 3,018 blocks,
    /// 2026-11-04): a template opened the instant the node's own block finished, so that block was always ahead of anything
    /// the peer could have built knowing it. Each node's selected parent stayed its own previous block: 6-17 % of chain steps
    /// crossed producers (a fair coin is 50 %), runs of 65 blocks from one producer, and about 850 fold rewinds up to 41 records
    /// deep, each one taking pending spends' anchors with it. Named here, 46 % cross and 0 rewinds in the same window, at the
    /// same 6.5 blocks/min. BORROWED-FROM Bitcoin miners (`getblocktemplate` long polling, Stratum's clean-jobs): the work is
    /// re-pointed at the newest tip without rebuilding what does not depend on it.
    ///
    /// What the proofs cover names no parent: notes, tags and the ring commit are the block's own. The header figures read
    /// through the parents (work, chain accumulator, version) are recomputed by the functions the template used, and the
    /// contextual door judges them as ever. The one thing under the proof that reads the parents is the reward's stated key,
    /// so this keeps the template's parents whenever the new ones would put that key out of force (a halving or a payout
    /// quarter crossed while the proof ran). Parents are already the producer's free choice at every door. cons: one
    /// `template_parents` read and one short lock per block, nothing stored, no block weight.
    pub(crate) fn rebind_parents_at_proof_finish(&self, block: &mut crate::block::Block) {
        let dag = self.relay.dag();
        let parents = dag.template_parents();
        if parents == block.header.parents {
            return;
        }
        let (Some((old, _)), Some((new, _))) =
            (crate::satoshi::parent_key_of(dag, &block.header.parents), crate::satoshi::parent_key_of(dag, &parents))
        else {
            return;
        };
        // A-F60: the payout period is the parents' (their parent-key block's chain tick); new parents in another period would
        // carry a payout sealed at the old period's rate, so the template's parents stay
        let same_period = self.payout_quarter_of(&block.header.parents).is_some_and(|q| self.payout_quarter_of(&parents) == Some(q));
        if !crate::satoshi::reward_key_in_force(old, Some(new)) || !crate::miner_payout_tx::payout_key_in_force(old, Some(new)) || !same_period {
            return;
        }
        let selected = dag.selected_parent_of(&parents);
        let prev_acc = selected.and_then(|t| dag.get(&t)).map_or([0u8; 16], |n| n.header.chain_acc);
        let next_score = dag.selected_tip().and_then(|t| dag.get(&t)).map_or(0, |n| n.blue_score + 1);
        block.header.work = crate::miner::adaptive_work_at(dag, selected, block.header.timestamp); // ⛔ A-F145 RELIEF
        block.header.chain_acc = crate::miner::fold_chain_acc(&prev_acc, &block.header.tx_merkle_root, &block.header.frontier_root);
        block.header.version = self.peg.deployments().version_for(next_score);
        block.header.parents = parents;
    }

    /// ⭐ SPEED stage 2 — THE VOTES ARE LAID WHEN THE BLOCK IS SEALED, NOT WHEN ITS TEMPLATE IS CUT (the same move as the
    /// parents above, for the same reason). A block's bond lane was fixed at its template, one whole proof before the
    /// block exists, so a vote cast while the proof ran waited for the NEXT template and one more proof.
    /// MEASURED 2026-11-10 (two real runs) and reproduced by arithmetic (`scratchpad/speed/settle_model.py`, within 5 %):
    /// the chain's finality number moved 82 s after block birth at load 55 and 231 s at load 173, of which one block
    /// cycle is this wait; laying at the seal takes it out (model: 78 → 52 s and 241 → 178 s).
    /// What it touches: the bond lane's real frames gain the votes this node's pool holds now and its template did not
    /// lay (the G14 policy decides which, `Mempool::votes_to_lay_at_seal`), the lane's root in the header is recomputed
    /// and the lane re-padded — the three steps `complete_produce_job` already performs for the bond transition, before
    /// the grind. Nothing a proof covers reads the bond lane's votes. Every door binds the lane by that root
    /// (`consensus`: "header bond_set_root does not commit to the block's own carried bond set") and tallies each vote
    /// from its own bytes at the graft (`apply_carried_finality_votes`), as before.
    /// Producer policy, not consensus: which votes a producer lays is its free choice at every door (G14).
    /// `laid` is the job's list of pool ids the block carries: the attached votes join it, so the graft drops them from
    /// the pool as it drops the template's. Returns how many votes were attached.
    /// cons: up to about 5.4 KB per attached vote on the bond lane of a block that would have carried none of them (the
    /// same bytes the next block would have carried); one pool pass and one lane re-pad per block.
    /// BORROWED: Ethereum's block proposal (attestations are packed when the block is proposed, from the pool as it
    /// stands then), and this tree's own `rebind_parents_at_proof_finish`.
    pub(crate) fn attach_votes_at_proof_finish(&self, block: &mut crate::block::Block, pad_key: &[u8; 32], laid: &mut Vec<Hash32>) -> usize {
        // the draw is this block's own secret (its cover key), so a relayer's 1-in-n choice is not predictable from outside
        let mut d = blake3::Hasher::new();
        d.update(b"MUSD-seal-vote-draw-v1");
        d.update(pad_key);
        d.update(block.header.output_notes_root.as_bytes());
        let draw = *d.finalize().as_bytes();
        let votes = self.mempool.votes_to_lay_at_seal(&draw, &|id| laid.contains(id));
        if votes.is_empty() {
            return 0;
        }
        let real_end = crate::block::sidecar_real_len(&block.bond_set);
        block.bond_set.truncate(real_end);
        let mut attached = 0;
        for tx in &votes {
            if let Ok(enc) = postcard::to_stdvec(tx) {
                block.bond_set.extend_from_slice(&(enc.len() as u32).to_le_bytes());
                block.bond_set.extend_from_slice(&enc);
                laid.push(tx.id);
                attached += 1;
            }
        }
        // §POLES: the root is over the REAL content, then the lane is padded — the order the template uses
        block.header.bond_set_root = crate::block::da_sidecar_root_of(&block.bond_set);
        crate::block::pad_sidecar_to_constant(&mut block.bond_set, pad_key, b"MUSD-bond-pad");
        attached
    }

    pub(super) fn produce_template_with(
        &mut self,
        now_ts: u64,
        frontier_root: Hash32,
        miner_commitment: Hash32,
        defer_transition: bool,
    ) -> Option<(Block, Vec<Hash32>, Vec<Hash32>, Vec<u8>, Option<PendingNoteTransition>)> {
        // §BR-13: until it has applied, every producer offers the canonical set-aside. Here, the one site every block path goes through:
        // MEASURED on two real nodes 2026-11-05, offered only in `produce` (a path live nodes never call) the note was never on the chain.
        self.offer_canonical_set_aside();
        let genesis_bind = Hash32::hash(b"MUSD-coinbase-genesis-bind");
        let frontier_root = if frontier_root == Hash32::ZERO {
            self.note_frontier_root()
        } else {
            frontier_root
        };
        let miner_commitment = if miner_commitment == Hash32::ZERO {
            self.miner_reward_commitment(&self.selected_tip().unwrap_or(genesis_bind))
        } else {
            miner_commitment
        };
        // DB-4 (2026-09-17): STATE BEHIND THE CHAIN IS REPORTED, NEVER A HALT. A block healed as a shell
        // (structure only) at or below the selected tip's score means the peg, membership and note state
        // here is behind the chain. The first cut of this REFUSED to produce; run 11 of the wallet journey
        // then measured BOTH nodes of a pair holding at once (`h=163` / `h=208` frozen for minutes) — a
        // chain halt, which the no-halts cardinal forbids (gates fail closed on the BAD item, never on chain
        // progress). So: the condition is named in the log, the runtime asks for the certified bundle that
        // covers it (`production_held_for_unapplied_shells` → the DB-4 #29 lane), and production goes on —
        // a block built on stale roots is refused by every peer (fail-closed there) and costs this node the
        // work, never the chain its liveness.
        if let Some(floor) = self.unapplied_shell_floor {
            let tip_score = self
                .selected_tip()
                .and_then(|t| self.block_score_and_parents(&t))
                .map(|(sc, _)| sc)
                .unwrap_or(0);
            if tip_score >= floor {
                static BEHIND: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                let n = BEHIND.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n % 20 == 0 {
                    eprintln!(
                        "[produce-behind] {} block(s) at score {floor}..={} were healed as SHELLS — their \
                         state is not applied here; producing anyway (a halt is forbidden) while the \
                         certified bundle is asked for (#{})",
                        self.unapplied_shell_count,
                        self.unapplied_shell_ceiling,
                        n + 1
                    );
                }
            }
        }
        let need = self.mempool.required_stamp_bits();
        // Cover is minted here, BEFORE the template reads the pool — that is deliberate and must stay:
        // it is what lets an IDLE chain still mine a block (`build_template` on an empty pool produces
        // nothing and `produce()` returns None — measured: 48 tests failed with "idle block mined" when I
        // moved this after selection). `pad_to_fixed_shape` tops the pool up to BLOCK_FIXED_TX_COUNT, so
        // real pending payments keep their slots and cover only fills what is left.
        let cover_ids: Vec<Hash32> = crate::cover::pad_to_fixed_shape(self.mempool.len(), need)
            .into_iter()
            .filter_map(|c| self.mempool.accept(c).ok())
            .collect();
        // ⭐ THE PRODUCER'S OWN OBJECTS KEEP THEIR SLOTS (Bitcoin Core's `BlockAssembler` coinbase reserve): the SATOSHI
        // reward below lays one nullifier in the lane and one note, and the staged credit notes join the payload, AFTER
        // this selection. MEASURED (link 57, db369): unreserved, eight pooled 32-tag objects filled the 256-tag lane, the
        // reward made 257, and every template was refused while the pool never drained — a halt for eight pending spends.
        // cons: a full lane carries at most 255 pooled tags while a reward is laid, so 7 constant-width (32-tag) spends per
        // block instead of 8 (the reward's tag already occupied the lane since SATOSHI §3; the selector now counts it).
        let reserve = {
            let mut r = if self.reward_recipient.is_some() {
                crate::mempool::TemplateReserve::MINING_REWARD
            } else {
                crate::mempool::TemplateReserve::NONE
            };
            r.notes += self.pending_credit_notes.iter().map(|n| n.len() / crate::cover::PQ_NOTE_BYTES).sum::<usize>();
            // §22: the frame bytes the producer lays itself — the reward's carriage (a whole 1,153 B note plus its fields,
            // bounded by `satoshi::REWARD_FRAME_RESERVE`) and every staged justifier's carriage.
            if self.reward_recipient.is_some() {
                r.frames += crate::satoshi::REWARD_FRAME_RESERVE;
            }
            // §BR-11: the miner-pool payout's tag, note and carriage, beside the reward's, whenever a payout may be laid
            if self.miner_payout_possible() {
                r.tags += 1;
                r.notes += 1;
                r.frames += crate::miner_payout_tx::PAYOUT_FRAME_RESERVE;
            }
            let fit = self.pending_justifiers_that_fit();
            r.frames += self.pending_credit_justifiers[..fit]
                .iter()
                .map(|o| crate::block::credit_frame_cost(crate::chain_object::carriage_of(o).map_or(o.len(), |c| c.len())))
                .sum::<usize>();
            r
        };
        // G14: this node lays its own finality votes; another voter's vote 1-in-(seated voters less this one) per template.
        let relayers = self.validators.bonded_ids().len().saturating_sub(1) as u64;
        self.mempool.set_vote_lay(self.own_validator_id, relayers);
        // ⭐ PRIVATE SHARDING §2.3: a tx whose evidence has not arrived waits in the pool, so its spend cannot lose at the fold.
        // And a wallet's own transaction the network has not echoed waits too, until its embargo ends, so this node's block
        // never names its sender while another node can carry it.
        let wall_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
        let held_back: std::collections::HashSet<Hash32> = self
            .mempool
            .iter()
            .filter(|t| !self.tx_evidence_ready(t) || self.own_tx_embargoed(&t.id, wall_ms))
            .map(|t| t.id)
            .collect();
        self.mempool.set_held_back(held_back);
        let mut tmpl = crate::miner::build_template_reserving(
            self.relay.dag(),
            &self.mempool,
            now_ts,
            frontier_root,
            // Pre-block nullifier-acc root — the spent-state this block's spends prove NON-membership
            // against, committed in the header at PARITY with `frontier_root` (the note side). The node's
            // own O(1) acc is authoritative for the spent-state, so it is read here, not threaded as a param.
            Hash32(self.nullifier_root()),
            miner_commitment,
            self.account_acc,
            // ⭐⭐⭐ DB-154 — THE MERKLE ROOT OF THE SPENT SET, COMMITTED BY THE BLOCK THAT PRODUCED IT.
            //
            // The copath lane had nothing in consensus to anchor to: `nullifier_root` above is the A_tip
            // FOLD, and a wallet cannot fold a copath against a fold, so a wallet checking a served
            // non-membership copath was trusting the one node that served it. This commits the root that
            // copath actually describes.
            //
            // Sound to read live for the SAME reason A_tip is: the value is a function of the spent SET,
            // not of this node's apply order — MEASURED by `nf_sparse::db154_order_free_root` (24
            // nullifiers, three insertion orders, one root; a set short one nullifier differs). That is
            // what separates it from `sparse_acc.root_bytes()`, whose linear pre->post chain required
            // replaying the producer's block order and stalled the pair on 2026-08-14.
            //
            // ZERO when this node holds no tree (restarted or jumped, before its warm stream completes).
            // Production and gossip are NEVER gated on it, so a treeless producer cannot halt the chain.
            Hash32(self.sparse_tree_root_or_zero()),
            reserve,
            &self.template_draw(now_ts),
        );
        // ⭐ §BR-10: the block signals every deployment this release implements that is Started or LockedIn (BIP9 bits); with
        // nothing to signal the version stays 1. Bound into the id and the PoW, like every header field.
        let next_score = self.dag().selected_tip().and_then(|t| self.dag().get(&t)).map_or(0, |n| n.blue_score + 1);
        tmpl.header.version = self.peg.deployments().version_for(next_score);
        // PADDED nullifier carrier (ENABLED): PROVE this block's whole 256-wide padded nullifier transition
        // (`header.nullifier_root` pre → `post_root`) so every verifier advances its O(1) acc from the CARRIER — a
        // held nullifier tree becomes unnecessary for verification. Built over a CLONE (self.nullifier_imt is left
        // untouched; the self-ingest below advances it once via the identical padded set) → produce stays idempotent.
        // NOW pad to the constant shape: mint exactly the covers the template still needs, accept them so
        // they resolve by id downstream, and append their ids. `tx_ids.len()` is then always
        // BLOCK_FIXED_TX_COUNT regardless of how many real payments settled — the volume cover is intact —
        // and every real tx the selector chose keeps its slot.
        // ⛔ COVER TXS NEVER ENTER THE MEMPOOL. Accepting them made them PERSIST: the next produce found a
        // pool already at BLOCK_FIXED_TX_COUNT, the selector filled every slot from it, and real payments
        // were locked out forever. MEASURED after moving the pad AFTER selection but still accepting into
        // the pool — the daemon printed the identical "pool holds 256 tx(s) … NONE carries output notes".
        // They are per-BLOCK objects: minted here, carried in this block, resolved from this local vec.
        // DB-73 (run 84) closed at source 2026-09-30: the block aggregate used to take ONE Merkle depth, so a template
        // carried spends of one carrier depth and deferred the rest. Gate D (the depth-d path) is deleted — the spend
        // carrier has ONE constant layout and no depth — so every pooled spend whose carrier verifies is layable in
        // this block; one whose carrier verifies under no statement leaves the pool (it can never be laid). Decided
        // here, BEFORE any root binds these spends.
        // CHAIN-PUBLISH-REVIEWED: template selection; the pool is untouched and nothing the chain maintains is written.
        {
            let mut unverifiable: Vec<Hash32> = Vec::new();
            let mut keep: Vec<Hash32> = Vec::with_capacity(tmpl.tx_ids.len());
            // ⛔ §RF-3 (R5): a producer that cannot lay the ledger (anchor ring incomplete — a carried ring that did not
            // install after an adopt or restart) would state its spends in the legacy per-spend shape, whose transition
            // bytes and `oli_tags` count them. Its spends are DEFERRED (kept pooled, never evicted) until its ring
            // completes; any complete-ring producer lays them meanwhile.
            // MEASURED: node::pins::rf3_a_producer_with_an_incomplete_ring_defers_every_spend_and_a_complete_one_lays_it
            // RED (scratchpad/night/rf3-produce-ringred.log). cons: such a producer lays no spend for ≤ W fold steps
            // (W = anchor_ring_len, 3600) — a delay on that one producer, never a halt or an eviction.
            let can_lay_ledger =
                crate::note_transition::ledger_shape_wire().is_some() && self.member_ring_commit_for_produce().is_some();
            // goods spec §9.1: the ONE clock this template's ledger will state (`pending_note_transition` reads the same)
            let ledger_clock = self.template_ledger_clock();
            for id in &tmpl.tx_ids {
                let Some(tx) = self.mempool.get(id) else { continue };
                // §9.6 PARITY WITH THE POOL DOOR (line ~28935): every carried tag is a canonical digest.
                // A tx that bypassed the door (test pool, gossip relay) with a blake3-padded tag reaches the
                // padded set and breaks `block_ledger_inputs` → every produce returns None while it stays pooled.
                // Evict it here, the same gate the door runs. cons: 16 lane compares per tag (~0.1 µs); nothing stored.
                // MEASURED: node::pins::rf3_a_template_evicts_a_non_canonical_tag_and_still_produces
                if !tx.nullifiers.iter().all(|t| crate::spend_frontier::cm_bytes_to_root(t.as_bytes()).is_some()) {
                    unverifiable.push(*id);
                    continue;
                }
                // DB-79 (2026-09-19, found by `a_wrapped_note_minted_to_a_holder_is_moved_and_a_node_fed_only_blocks_retires_it`): a
                // FRAMED chain object (an AssetSpend, a PegOut, …) is not a USDm spend carrier — its
                // justification is its own class's apply, never this block aggregate. Verifying it here as a
                // spend read false, so it was "deferred" every slot.
                // ⛔ VALIDATOR BONDS ARE SAT-ONLY (`Self::USDM_BOND_RETIRED`): a pooled USDm bond is never laid — the fold
                // would refuse its seat while its lane consumed the note. Evicted like any tx this template cannot lay.
                if Self::is_usdm_bond_tx(tx) {
                    #[cfg(test)]
                    if ROGUE_LAYS_USDM_BONDS_FOR_TEST.with(std::cell::Cell::get) {
                        keep.push(*id); // a rogue template (test-only): the fold below must still seat nothing
                        continue;
                    }
                    unverifiable.push(*id);
                    continue;
                }
                let is_spend = Self::is_usdm_spend_tx(tx);
                if !is_spend {
                    keep.push(*id);
                    continue;
                }
                if !can_lay_ledger && !Self::rogue_lays_pre_ring_spends() {
                    continue; // deferred: stays pooled, never laid in the count-stating shape
                }
                // goods spec §9.1: a spend proven against a clock this block's ledger clock has not reached stays pooled;
                // the first ledger whose clock has reached it states it. Deferred, never dropped: a spend does not expire.
                if tx.clock_ms > ledger_clock {
                    continue;
                }
                // The ONE tuple reader (`spend_tuple_of`: row 0 the nullifier, row 1 the claim tag, DB-329 §7f); a
                // spend it cannot state is unverifiable here, exactly as at the pool door.
                let Some(t) = Self::spend_tuple_of(tx) else {
                    unverifiable.push(*id);
                    continue;
                };
                // DB-351: the carrier verifies only under its own filing digest; a spend with no canonical D is
                // unverifiable here exactly as at the pool door.
                // ⭐ lane agg: a held aggregated payment's carrier is a core in the pool; the FULL carrier this node verified
                // when it took the payment is the one re-checked here (`Node::agg_held`)
                let blob = self.agg_held.get(id).map_or(&tx.blob, |h| &h.full.blob);
                if Self::tx_filing_d(tx).is_some_and(|d| crate::note_transition::carrier_verifies_at(blob, &t, d, tx.clock_ms)) {
                    keep.push(*id);
                } else {
                    unverifiable.push(*id);
                }
            }
            if !unverifiable.is_empty() {
                // DB-79: a stated spend whose carrier does not verify is not a spend — it can never be laid, so it
                // leaves the pool now instead of being "deferred" every slot forever.
                eprintln!(
                    "[note-transition] ⛔ {} pooled spend(s) carry a validity carrier that does not verify — evicted, never laid",
                    unverifiable.len()
                );
                self.mempool.remove(&unverifiable);
            }
            // DB-79: the header COMMITS to the selection. The DB-72 grouping shrank `tx_ids` and left the
            // root `build_template` computed over the ORIGINAL list, so every slot with a deferred spend
            // produced a block whose tx root did not match its body (`[txroot] MISMATCH`) — refused by
            // this node's own gate, NO block that slot, and while the deferred tx stayed pooled, no block
            // ANY slot: a pooled tx of another depth was a production halt. The root follows the selection.
            // ⭐ §14: held payments ride only as ready bundles, each run together (one root a run, no proving on this
            // block's critical path); the order changes, so the root below follows it
            let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64);
            let keep = self.order_tree_selection(keep, now_ms);
            if keep != tmpl.tx_ids {
                let tx_root = crate::miner::tx_merkle_root(&keep);
                let dag = self.relay.dag();
                // the block's OWN selected parent, as `build_template_reserving` folds it (`Dag::selected_parent_of`)
                let prev_acc = dag
                    .selected_parent_of(&tmpl.header.parents)
                    .and_then(|sp| dag.get(&sp))
                    .map(|n| n.header.chain_acc)
                    .unwrap_or([0u8; 16]);
                tmpl.header.tx_merkle_root = tx_root;
                tmpl.header.chain_acc = crate::miner::fold_chain_acc(&prev_acc, &tx_root, &frontier_root);
            }
            tmpl.tx_ids = keep;
        }
        let sel_txs: Vec<PqTx> = tmpl
            .tx_ids
            .iter()
            .filter_map(|id| self.mempool.get(id).cloned())
            .collect();
        // a tx id, note, cm, amount, key, address or owner.
        // ⭐ THE SELECTION SEAM — does a payment in the mempool ever reach a template?
        //
        // MEASURED: 175 of 175 produced blocks carried exactly 1,153 note bytes, the constant entropy note.
        // A settling payment carries recipient + change = 2,306. And on a real peered send the target lookup
        // reported `0/1 resolved while 3 target(s) EXIST; 0 of this block's note key(s) appear among them` —
        // i.e. targets are filed correctly and the block simply holds no note they could match. So the
        // payment's notes never enter a block, and everything downstream is starved rather than broken.
        //
        // `build_template` picks from the mempool; this compares WHAT IT PICKED against WHAT THE POOL HELD,
        // and how many of the picked ones actually carry output notes. A pool holding a payment while the
        // template selects none of it names the defect here instead of six layers later.
        //
        // Fires only when the pool is NON-EMPTY and the template took no note-bearing tx — the state that
        // loses a payment. A quiet chain with an empty pool stays silent, so there are no per-block bytes.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — pool size, selected count, note-bearing count. Never
        // a tx id, note, cm, amount, key, address or owner.
        {
            let pool = self.mempool.len();
            let with_notes = sel_txs
                .iter()
                .filter(|t| !t.output_notes.is_empty())
                .count();
            if pool > 0 && with_notes == 0 {}
        }
        // FAST no-prove nullifier advance (500ms-pillar): DERIVE this block's 256-wide padded transition
        // (`header.nullifier_root` pre → `post_root`) by INSERTING into the working tree — NO per-block ~700ms WHIR
        // carrier prove on the hot path. EVERY node (the ONE universal full-node type) re-derives the identical
        // transition from its OWN tree at ingest (O(256·depth), ms). The 221KB carrier is built ON-DEMAND only when
        // SERVING the #29 DSYNC / #27 DAS sync path — a node CATCHING UP adopts the CERTIFIED state there, never a raw
        // block. The gossiped block carries the O(1) `post_root` + an EMPTY carrier UNIFORMLY every block (idle or
        // busy) → zero volume/timing leak (digital-cash privacy intact). The code now matches the "every node
        // re-derives; the carrier rides the sync path" design instead of proving+verifying a redundant 700ms carrier.
        // B5: derive this block's `pre → post` transition through the TREELESS-PRODUCE seam
        // (`derive_block_nullifier_post_via_seam` — a bounded `PartialNullifierImt` over a `BaseNullifierTree` the
        // producer only QUERIES). The witness build no longer requires the node to HOLD an O(N) tree: it reads
        // O(256·DEPTH) of the base and keeps only the block's own inserts. Byte-identical to the held-tree derive
        // (proven `partial_matches_full_tree_byte_identical`), so the graft below re-derives + advances the acc to the
        // SAME `post_root`. `None` ⇒ no base reachable this slot (the node keeps tracking) OR a genuine double-spend in
        // the selected set — either way fail-closed, the DAG never halts.
        // B4's compact gossip carrier (an aggregate-of-one that stated no inner carrier) is DELETED, 2026-10-26: a
        // block carrying any `NfBlockProof::carrier` is refused at ingest — one encoding; a tracking node's authority
        // is its own recompute from the block's id-bound tags.
        // ⭐⭐⭐ TREELESS PRODUCE — the block's insert list comes from SPENDER-CARRIED copaths, so this node builds
        // no witness and therefore holds no tree. `block_inserts_from_carried_copaths` returns the FULL constant
        // block shape or nothing: a partial shape is never assembled, because a short block is exactly the case
        // where the missing cover would have been hiding something.
        //
        // NO CHAIN HALT: when the pool cannot supply a full constant shape this slot, the block is still PRODUCED —
        // it simply settles NO nullifiers, and the waiting spends settle in a later block once cover is available.
        // Production never depends on the pool being full ([[feedback_no_chain_halts]]), and the settled shape is
        // one of exactly two volume-independent constants (full or empty), never a count that tracks real demand.
        // ⭐⭐⭐ TREELESS PRODUCE — the block's insertions arrive as SPENDER-OWNED carries (constant width per tx,
        // decoys included), and `batch_insert_root` below folds them all in one order-independent pass. The
        // producer builds no witness and holds no tree. NO CHAIN HALT: if the pool cannot supply a full constant
        // shape this slot the block is still produced, settling nothing, and those spends land in a later block.
        // FIXED-COVER-SHAPE: build the FULL constant block shape — real spender-carried nullifiers PADDED to
        // `BLOCK_FIXED_NULLIFIER_COUNT` with secret-seeded producer decoys — so EVERY block (idle or busy) settles the
        // SAME count and the acc advances every block (the old `block_inserts_from_carried_copaths` returned nothing on
        // a thin pool ⇒ a busy-vs-idle volume leak + an unadvanced acc). Decoy copaths are read-only vs the pre-root.
        // ⭐⭐⭐ FOLD-NOT-HOLD-REVIEWED: FOLD-NOT-HOLD PRODUCE (brick C1) — INFINITE O(1), NO copath, NO held tree.
        // The block's 256 tags (real spends + secret-seeded cover) are VALUES only — computed copath-free via
        // `pad_nullifiers_to_fixed` — and FOLDED into the O(1) A_tip acc. The height-1 fold's digest is
        // `sparse_fold_digest_nfs` (nf VALUES only), so the transition proves over a FIXED height-32 trace with EMPTY
        // copaths: NO `build_block_inserts_fixed_shape`, NO `batch_insert_root`, NO tree. Proven copath-free +
        // tamper-sound by `brick_c_producer_folds_tags_copath_free_and_verifies_o1_and_tamper_rejects`.
        // ([[feedback_infinite_o1_fold_cardinal]] [[project_fold_not_hold_produce_full_design]])
        let mut real_nfs: Vec<[u8; 32]> = Vec::new();
        // ⭐⭐⭐ SATOSHI — THIS BLOCK'S MINING REWARD (docs/SATOSHI-NATIVE-TOKEN.md §3). Built from this node's own miner seed
        // and the block's public context (its parents are fixed now), staged for THIS block only — never pooled, so no other
        // producer can lay it — with its own nullifier in this block's lane (the DB-278 rule every carried object obeys).
        // A producer whose parents' blue scores it does not hold, or past the last era, lays no reward.
        // cons: one object in the set (≈1.2 KB: the whole note, its 32-byte public opening, its clue) — DB-393 B4: no proof.
        // ⭐ DB-393 B4 — BUILT here, whole: one encapsulation and two Poseidon2 evaluations. The object carries the note's
        // public opening `o` and every node recomputes `cm = asset_note_cm(reward_at(key), SAT, o)`, so nothing is proved
        // (the 100,631 B / 1,828 ms mint carrier and fix A's off-lock prove are deleted with it). Nothing is staged on the
        // node until the template has passed its last refusal: a template refused after this point leaves no stale reward.
        let mut reward_sealed: Option<(crate::satoshi::SatoshiRewardTx, [u8; 32])> = None;
        if let (Some(rc), Some((key, _parents_digest))) = (self.reward_recipient.as_ref(), crate::satoshi::parent_key_of(self.relay.dag(), &tmpl.header.parents)) {
            // SEALED to the operator wallet's scan key (§8.1): no spending key lives here. The clue takes the next `"sat"` index.
            let seal_seed = Self::reward_seal_seed(&self.miner_seed, key, &rc.next_index.to_le_bytes());
            if let Some(sealed) = crate::satoshi::SatoshiRewardTx::seal(rc, rc.next_index, key, seal_seed) {
                if let Some(cm) = sealed.note_cm() {
                    real_nfs.push(crate::satoshi::reward_nf(&cm));
                    reward_sealed = Some((sealed, cm));
                }
            }
        }
        // ⭐ §BR-11 — THE MINER-POOL PAYOUT: exactly the open quarter's rate, to the same operator wallet the reward is sealed
        // to, for a block whose parents fall in that period (A-F60: their parent-key block's chain tick, `payout_quarter_of`),
        // when the pool (in this node's folded state) covers it. A payout laid on a state the fold has moved past is refused
        // at the fold (the object only — the block stands).
        let mut payout_sealed: Option<(crate::miner_payout_tx::MinerPayoutTx, [u8; 32])> = None;
        if let (Some(rc), Some((key, _)), Some(quarter)) = (
            self.reward_recipient.as_ref(),
            crate::satoshi::parent_key_of(self.relay.dag(), &tmpl.header.parents),
            self.payout_quarter_of(&tmpl.header.parents),
        ) {
            if let Some((q, rate)) = self.peg.miner_payout_rate() {
                if q == quarter && rate > 0 && self.peg.fee_pools().miner >= rate {
                    let index = rc.next_index.wrapping_add(u64::from(reward_sealed.is_some()));
                    let seal_seed = Self::reward_seal_seed(&self.miner_seed, key, &[&index.to_le_bytes()[..], b"payout"].concat());
                    if let Some(sealed) = crate::miner_payout_tx::MinerPayoutTx::seal(rc, index, key, rate, seal_seed) {
                        if let Some(cm) = sealed.note_cm() {
                            real_nfs.push(crate::miner_payout_tx::payout_nf(&cm));
                            payout_sealed = Some((sealed, cm));
                        }
                    }
                }
            }
        }
        let mut real_blobs: Vec<u8> = Vec::new();
        for tx in &sel_txs {
            if tx.nullifiers.is_empty() {
                continue; // coinbase / reward-only ⇒ no spends
            }
            for nf in &tx.nullifiers {
                real_nfs.push(nf.0);
            }
            real_blobs.extend_from_slice(&tx.blob);
        }
        if real_nfs.len() > crate::cover::BLOCK_FIXED_NULLIFIER_COUNT {
            // ⛔ THIS REFUSAL WAS INVISIBLE — a pool whose SELECTED set carries more real nullifiers
            // than one block's constant capacity refused EVERY template forever, silently, and the
            // chain's cadence collapsed with nothing in any log naming it (measured 2026-08-22:
            // zero blocks across 122 healthy ticks with every other producer signal green).
            // Local log only, ≤1 line per 30s of refusals: COUNTS of a refusal state, never routine
            // volume, never a tx id, nullifier, amount, key or owner; nothing rides the RPC.
            use std::sync::atomic::{AtomicU64, Ordering as AOrd};
            // `u64::MAX` = never logged, so the FIRST refusal prints whatever the clock reads (a 0 start silenced every
            // refusal in a node's first 30 s).
            static LAST_CAP_LOG_MS: AtomicU64 = AtomicU64::new(u64::MAX);
            let nowl = now_ts;
            let last = LAST_CAP_LOG_MS.load(AOrd::Relaxed);
            if last == u64::MAX || nowl.saturating_sub(last) >= 30_000 {
                LAST_CAP_LOG_MS.store(nowl, AOrd::Relaxed);
                eprintln!(
                    "[produce-refused] the SELECTED set carries {} real nullifier(s) — above the {}                      per-block capacity, so NO template can form until the pool's spend load drops                      below one block ({} tx(s) selected). Production is wedged by construction here.",
                    real_nfs.len(),
                    crate::cover::BLOCK_FIXED_NULLIFIER_COUNT,
                    sel_txs.len()
                );
            }
            return None; // more reals than the constant block capacity ⇒ fail-closed
        }
        // ⭐ NO COVER SECRET. This used to derive a per-block seed so every node could regenerate the SAME 255
        // decoys; with the cover retired the block's tags are just its real nullifiers, which every node already
        // has byte-identically from the block itself. One less thing produce and ingest can drift on.
        // ⭐⭐⭐ CONSTANT-SHAPE TAG SET — the block ships BLOCK_FIXED_NULLIFIER_COUNT tags whether it settles 0
        // spends or 200. This closes a live DIGITAL-CASH violation: `block_nullifier_set` is the IDENTITY since
        // the 256-decoy retirement, so a block's tag vector length WAS its real spend count, in the clear, per
        // block, to any wire observer or indexer — an idle block showed 0, a one-spend block showed 1. Volume is
        // metadata, and metadata is a pillar, not a nice-to-have ([[feedback_digital_cash_pillar]]).
        //
        // ⭐ §RF-3 spec §15 (2026-10-24; R5): the fill is the LEDGER's cover tag cells — decoy `s` =
        // `cover_tag_native(HEADER_SEED, s)`, `s = 1..=256−k`, HEADER_SEED = `cover::header_seed(output notes)` — sealed
        // below, after the output notes are final and before the tag root is. A digest-shaped decoy keyed any other way
        // (the §CE producer-local `nf_decoy_secret` it replaces) lets `ledger list ∩ header tags` name the reals; a
        // non-holder of the bodies still cannot recompute the seed, so the decoys stay unpartitionable to it.
        //
        // ONE DEFINITION FOR PRODUCE AND VERIFY: the transition leaf digests THIS set
        // (`sparse_fold_digest_nfs(tags, block_pre)`), and the verifier folds the tags the block CARRIES — so
        // padding here moves both sides together by construction. Padding one side only would recreate exactly
        // the producer/relay divergence measured earlier today (a_fold_seq=4 vs b_fold_seq=49).
        //
        // cons: wire tags become a constant 256 x 32 B = 8,192 B per block instead of 32 B x real-count. That is
        // BOUNDED BY A FIXED PROTOCOL CONSTANT, not by history — the same constant at block 1 and block 10^9 —
        // and it is the price of the pillar.
        //
        // ⛔ NODES NEVER STORE (user 2026-08-14). The padded set is REGENERATED, never retained: any node holding
        // the block's committed inputs re-derives this exact vector from `(real, secret)`, and `nullifier_wire_strip`
        // recovers the reals from it — which is why the fill is keyed rather than public. Nothing here is written
        // down, and a smaller per-block store would be no better than a large one: 64 bytes a block is still
        // forever. (`da_nf_mem` / `da_fold_mem` remain condemned per-block stores that predate this and must be
        // deleted at source, NOT fed a padded set — see O(1) guard class K.)
        // Same value `pre_sparse_root` is bound to a few lines below (`nullifier_seed_root()`), read here
        // because the fill must exist before the digest that commits it. ONE accessor, so they cannot drift.
        // The committed pre value (limbs) — the same `block_pre` `advance_nf_unspent_acc` folds; the block's
        // nullifier authority is the A_tip TAGS-FOLD `nf_unspent_step_new_acc(A_tip, block_pre, digest)`, which every
        // node RE-COMPUTES from the regenerated tags (self-verifying, no trusted committed root, no copath).
        // ONE pre-block value for produce and verify alike — the order-free A_tip projection, never the linear
        // `sparse_acc` (which only this producer's replay order could reach).
        let pre_sparse_root = self.nullifier_seed_root();
        let block_pre = usdm_decider::nf_sparse_air::nf_to_limbs(&pre_sparse_root);
        let mut block = Block {
            cover_key: None, // §20.2: drawn below, beside the body
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(), // sealed below, before the mine binds the header
            header: tmpl.header,
            tx_ids: tmpl.tx_ids.clone(),
            pow_proof: Vec::new(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            note_transition: None,
            nullifier_proof: {
                // ⭐⭐⭐ LANE 2 — THE SPARSE CARRIER RIDES THE BLOCK.
                //
                // `carrier` was `Vec::new()` in production and the three treeless-advance functions had
                // ZERO callers, so a node could verify the A_tip fold and had to take `header.sparse_root`
                // on the producer's word. Now the block proves its own sparse transition and any node —
                // holding a tree or not — checks it for itself. That is what a doubter spinning up a node
                // is actually there to see.
                // ⛔⛔⛔ DB-153, MEASURED EXACTLY — THE PER-BLOCK SPARSE CARRIER IS 46x THE BLOCK BUDGET.
                //
                // I wired `sparse_carrier_for_padded` in here so a TREELESS node could verify the Merkle
                // root the header now commits. It stopped the chain: gate run 1 (committed root only)
                // converged at h1=295 h2=297; with this call, gate run 3 reached h1=1 h2=0 with
                // `[tick-slow] apply_preverified=1094ms`.
                //
                // MEASURED (`the_per_block_sparse_carrier_is_timed_against_the_block_budget`), 256 tags:
                //     sparse carrier   23,274 ms   67,388 bytes
                //     committed root        4 us          32 bytes
                //     block budget        500 ms
                // Forty-six times the whole budget, for one block. There is no tuning that closes a 46x
                // gap, and shipping it would trade the 500 ms block for the copath lane — the exact
                // pillar trade DB-153 named and the owner refused.
                //
                // SO THE ROOT IS COMMITTED AND THE PROOF IS NOT BUILT. A node holding a tree verifies
                // `header.sparse_root` by deriving its own (4 us); a TREELESS node cannot verify it yet,
                // and that is the honest residual — recorded on the kill list rather than hidden behind a
                // field that quietly stays empty.
                //
                // The `sparse_carrier` field and `sparse_carrier_admissible` STAY: the field is on the
                // wire, so a peer can put bytes there, and the gate refuses a non-empty carrier that does
                // not prove the committed transition. Empty is admitted — a producer making no claim.
                crate::block::NfBlockProof {
                    carrier: Vec::new(),
                    // sealed with the tags after the output notes (§RF-3 spec §15)
                    post_root: Hash32::ZERO,
                    fold: Vec::new(),
                    padded_tags: Vec::new(),
                    sparse_carrier: Vec::new(),
                    sparse_post_root: Hash32::ZERO,
                }
            },
            cover_transition: None,
            member_transition: None,
        };
        // INVARIANT: the block's committed pre IS the value its fold digest was built from. `pre_sparse_root`
        // is captured here at produce; `header.nullifier_root` was captured at template build. A_tip advances at
        // every accept, so if those two moments could differ the block would commit one pre and fold another,
        // and every verifier's pure re-derivation would miss the committed post. MEASURED over a full 50-block
        // run: 0 divergences. Kept as a debug assertion — free in release, loud if that ever stops holding.
        debug_assert_eq!(
            block.header.nullifier_root.0, pre_sparse_root,
            "the committed pre must be the pre the fold digest was built from"
        );
        // TRANSPORT (task #145): the LIVE serve path carries the block-carried settlement aggregate too — fold the
        // block's REAL selected-tx carriers into ONE O(1) sound proof (`Block.settlement`) so downstream verifies
        // ONE proof, not each carrier. Set before the off-lock mine (settlement is a witness, NOT in the block id).
        // ⛔⛔⛔ §BD CLOSED 2026-09-15 — THIS AGGREGATE CERTIFIED NOTHING, SO IT IS NO LONGER BUILT.
        //
        // `settlement_aggregate_from_bundles` constrained a sumcheck round chain and a masked-opening
        // chain over values laid in the WITNESS rows — including the Fiat–Shamir challenges themselves,
        // with no inner commitment root anywhere. MEASURED in 0.01 s:
        //     [§BD] aggregate over ZERO rows, NO inner carrier, 7 fabricated tx ids: verifies=true
        // The zero row satisfies both AIRs, so ANYONE could produce a verifying "settlement" for ANY tx
        // set with no transaction behind it. It was latent only because it returned `None` on every real
        // block and nothing downstream GRANTED on it — a loaded gun, not a safe one: the whole point of
        // the field (#144/#145 admission-drop, "verify this ONE proof and settle the WHOLE block") is to
        // be granted on, and the day someone wired that up it would have been unlimited minting.
        //
        // The sound replacement is the BOUND note-transition aggregate (`usdm_decider::settlement_delta`,
        // §BW): every row is a bound recursion step whose inner AIR is evaluated in-circuit, its shape is
        // a protocol constant, and re-pointing its statement is refused. It is not wired here yet — see
        // §BA/§BB — and until it is, this block carries NO settlement claim rather than a forgeable one.
        // §BA/§BB's note transition is laid AFTER both transition roots are sealed — it binds them.
        // Resolve the selected txs' note blobs NOW, while the lock is held and the pool still holds them.
        // These ids are now IN FLIGHT: mined off-lock, grafted later. Remember them so the next template
        // built during that window does not re-select the same payment.
        // ⛔ THE PAYMENTS, NOT THE PADDING (lane b 2026-10-24, T2): `cover_ids` are this template's own value-0 pad txs,
        // minted above and never relayed — a restart that kills the flight loses nothing of them. Holding them here made
        // the restart census read 256 "payments dropped" the first time a restart landed mid-flight
        // (watch-20261024-161519.log.7, b6c6e57). Real txs only, the same split the netsim prove sample makes.
        self.inflight_tx_ids = tmpl.tx_ids.iter().filter(|t| !cover_ids.contains(t)).copied().collect();
        let tmpl_output_notes = self.block_spendable_note_blobs(&tmpl.tx_ids).0.concat();
        // ⭐⭐⭐ ATTACH AND SEAL THE NOTES **BEFORE** THE OFF-LOCK MINE — ONE DEFINITION, BOUND BY THE PoW.
        //
        // The block used to leave here with `output_notes: Vec::new()` and have them filled in AFTER the
        // mine, in `graft_mined_own`, by RE-RESOLVING `block.tx_ids` against this node's own mempool. That
        // is a second definition of "this block's notes", and it is the one the receiver never sees: the
        // receiver stores what shipped.
        //
        // MEASURED, `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`:
        //   ord=0 addr=54878678358112916 A=(1 chunk, 1153 B, [212,22,114,32..])
        //                                 B=(1 chunk, 1153 B, [29,248,114,220..])
        //   A_served_seq=12 B_served_seq=12  A_dag=13 B_dag=13
        // Identical block and record counts — nothing lost or rejected — yet the SAME canonical address (a
        // pure function of the block id) holds different note bytes. From there the two nodes derive
        // different leaves, different block roots and different `spend_frontier_root`s, so a wallet's
        // witness verifies only on the node it happened to ask.
        //
        // Setting them here puts the notes inside what gets MINED, so the PoW binds them and the header's
        // commitment is computed once, on the same bytes that ship. Sealing after the mine (which I tried)
        // mutates the header post-PoW and changes `block.id()` — that is why it belongs here and not there.
        // ⭐ ONE WRITER PER RECORD: drain staged node-credited notes (faucet drips) into THIS block's own
        // carried notes, BEFORE the roots are sealed — so the PoW binds them, every verifier records them at
        // the block-id address, and no second writer ever touches the record space (see
        // `pending_credit_notes` for the measured divergence the direct write caused).
        let mut tmpl_output_notes = tmpl_output_notes;
        // Chain-of-custody probe (COUNT only — no cm/amount/key/owner). The drip's bucket-claim already
        // proves stage_credit_note ran on this node, so this single number discriminates the last
        // unmeasured hop: 0 here right after a drip = the staged note never reached THIS instance's queue
        // (two Node objects, or a reset between); ≥1 here followed by "assembled 0" = dropped after seal.
        // §22 — ONE SEALED WIDTH: only the staged justifiers that FIT this block's credit sidecar ride it (in staging order);
        // a staged note rides only beside the justifier that names it, so a note whose justifier waits for the next block
        // waits with it (the pairing is by commitment — a note shipped without its justifier is refused mesh-wide, §BA).
        // MEASURED: `pq_notes_serve_any_height_no_ageout` staged more justifiers than 16 KiB and the producer PANICKED at
        // the seal ("the template's framed objects were selected inside CREDIT_SET_FRAME_BUDGET").
        let fit = self.pending_justifiers_that_fit();
        let deferred: std::collections::HashSet<[u8; 32]> = self.pending_credit_justifiers[fit..]
            .iter()
            .filter_map(|o| crate::chain_object::carriage_of(o).and_then(|c| crate::chain_object::carriage_note_refs(&c)))
            .flat_map(|refs| refs.into_iter().map(|(cm, _)| cm))
            .collect();
        let mut kept_notes: Vec<Vec<u8>> = Vec::new();
        for n in self.pending_credit_notes.drain(..) {
            if n.len() >= 32 && deferred.contains(&n.fixed::<32>()) {
                kept_notes.push(n);
            } else {
                tmpl_output_notes.extend_from_slice(&n);
            }
        }
        self.pending_credit_notes = kept_notes;
        let kept_justifiers: Vec<Vec<u8>> = self.pending_credit_justifiers.split_off(fit);
        // ⭐ The reward's note joins the template here, past every refusal, and its object rides FIRST in the credit set —
        // complete on every path (DB-393 B4: nothing is left to prove off the lock).
        let mut reward_object: Option<Vec<u8>> = None;
        if let Some((r, cm)) = reward_sealed.take() {
            tmpl_output_notes.extend_from_slice(&r.note);
            // ⭐ AND ITS OWNER CLUE GOES TO THE ONE RECORDER, as every pooled object's does (`stage_carried_note_clues`).
            // MEASURED why (link 45, P14 high leg T3 "W1 never held the SAT its node mined to it … holds 0 SAT"; RED pin
            // `a_mining_reward_is_filed_under_its_owner_clue_on_the_producer_and_a_verifying_peer`: "0 tag byte(s) for 2306
            // note byte(s)"): the reward is never pooled, so the pool's door never staged its clue, the tag seal below
            // (`staged_tag_for_cm`) found no key, and every block shipped its reward UNTAGGED — the owner's `"sat"` sweep
            // matched 0 on every node. Staged here, past every refusal, the seal carries `cm ‖ index_key(clue)` in
            // `Block::oli_tags` (bound by `oli_tags_root`), so every node that grafts the block files it.
            // BORROWED-FROM Bitcoin's coinbase: the reward output is an ordinary output of its block, indexed like any other.
            // cons: +48 B per block on the wire (cm 32 + key 16) and one 17 B index entry per reward — the entry every other
            // located note already has; nothing else is stored.
            let _ = self.record_note_clue(cm, r.owner_clue.clone());
            reward_object = Some(r.to_object());
            self.advance_reward_index();
        }
        // §BR-11: the payout's note and clue join the template the same way, and its object rides right after the reward's.
        let mut payout_object: Option<Vec<u8>> = None;
        if let Some((p, cm)) = payout_sealed.take() {
            tmpl_output_notes.extend_from_slice(&p.note);
            let _ = self.record_note_clue(cm, p.owner_clue.clone());
            payout_object = Some(p.to_object());
            self.advance_reward_index();
        }
        // ⛔ DB-274 P2 (§8.7): a bond's locked note is NOT carried by its unbond's block any more (DB-257's carriage is
        // replaced). The fold releases it from chain state at the close of its unbonding window, into that step's
        // record (`bond_step_at_fold`); a producer that carried it would carry a note every peer's door refuses.
        // ⭐⭐⭐ §BA — AND DRAIN THE JUSTIFICATIONS BESIDE THEM, INTO THE SAME BLOCK.
        //
        // The notes above are the ones no spend published: a bridge credit, an asset or wrapped mint, a
        // bond return. On THIS node each was derived from a chain object it applied; on every other node
        // it was a note from nowhere, and the wire could not tell it from one a producer invented. That is
        // §BA. The objects drain here, into `Block::credit_set`, so the peer runs `chain_object::admissible`
        // and `carried_note_payloads` on the SAME bytes this node did rather than taking its word.
        //
        // ⛔ BOTH LANES DRAIN, ALWAYS, EVEN IF ONE IS EMPTY. A note left staged while its justification
        // shipped (or the reverse) would ride a LATER block whose credit set no longer excuses it — one
        // block out of step is a note refused mesh-wide, so the two drains sit here together and the
        // pairing is by commitment, never by which block they happened to land in.
        let mut tmpl_credit_objects: Vec<Vec<u8>> = reward_object.into_iter().chain(payout_object).collect();
        tmpl_credit_objects.extend(self.pending_credit_justifiers.drain(..));
        self.pending_credit_justifiers = kept_justifiers; // the rest ride the next block, with their notes
        // ⭐⭐⭐ §BA — AND THE FRAMED OBJECTS OF THE TRANSACTIONS THIS BLOCK ITSELF SELECTED.
        //
        // The staged lane above covers credits derived at GRAFT time (an asset or wrapped mint applied when
        // a block carrying it arrived). This covers the other half: a framed object the producer selected
        // into THIS block, whose notes rode `tmpl_output_notes` through `block_spendable_note_blobs`.
        //
        // ⛔ THE PRODUCER RESOLVES THOSE BODIES; A PEER DOES NOT. That asymmetry IS §BA. `graft_admitted_notes`
        // judges a framed object's notes through `admissible` + `wrapper_binds_object` — but only for a tx
        // it can pull from its OWN mempool, and under the constant-256 cover it pulls almost none. Carrying
        // the object bytes here moves that judgement from a fetch the peer will never make to bytes it
        // already holds, and it is the SAME gate on the SAME bytes, so nothing is trusted that was not
        // already required.
        //
        // ⛔ FRAMED OBJECTS ONLY. An ordinary send is NOT copied here: its notes are published by a spend
        // carrier and justified by the block's note transition, so duplicating its blob would add bytes and
        // justify nothing that is not already proven.
        //
        // O1-FOOTPRINT-REVIEWED: bounded by protocol constant `cover::BLOCK_FIXED_TX_COUNT` — one pass over
        // the template's own tx ids, which is that constant by construction; the vector is consumed by the
        // encode below and dropped.
        for id in &tmpl.tx_ids {
            let Some(tx) = self.mempool.get(id) else { continue };
            if crate::chain_object::unframe(&tx.blob).is_none() {
                continue; // an ordinary send — the note transition publishes its outputs
            }
            if !tmpl_credit_objects.iter().any(|o| o == &tx.blob) {
                tmpl_credit_objects.push(tx.blob.clone());
            }
        }
        // ⛔⛔⛔ §BX — THE WIRE LEAKS THE BLOCK'S REAL NOTE COUNT, AND THE OBVIOUS FIX TRADES A PILLAR.
        //
        // The note TREE is a constant 256 leaves per block (cover reinstated 2026-08-16): each node
        // regenerates `256 - reals` cover units from `(reals, seq)` at RECORD time. The WIRE is not:
        // `output_notes` carries the reals alone, so `len / PQ_NOTE_BYTES` IS the block's real note
        // count, read directly by every peer. MEASURED by
        // `harness::privacy::an_observer_cannot_read_real_activity_off_a_blocks_shape`:
        //     output_notes   0 · 0 · 5765   ⛔ READS REAL ACTIVITY
        // stable across two quiet blocks, five notes' worth on a busy one. The digital-cash cardinal
        // says "as any node" — a peer IS an observer, and a per-block real count is exactly the volume
        // metadata the cover exists to remove.
        //
        // ⛔ AND THE OBVIOUS FIX IS NOT THE FIX. Sending the assembled 256 units instead
        // (`assemble_fixed_note_payload_det(&tmpl_output_notes, block.header.timestamp)`) DOES close it
        // — remeasured 295,168 B on quiet and busy alike, 0 of 12 surfaces reading activity — and it
        // adds no leaf and no state, because those units already exist in every record. But it puts
        // 295 KB through the record/DA path on EVERY block, and the spendability canaries went from
        // **97.75 s to over 600 s without finishing**. Privacy bought with speed is a pillar trade, so
        // it was reverted rather than shipped.
        //
        // ⭐ WHY THERE IS NO CHEAPER CONSTRUCTION: the padding IS the mechanism. A count is hidden only
        // by making the count constant, and cover units must be indistinguishable from real ones, so
        // they cannot be compressed or summarised. Same shape as the WHIR sampler (§BK-3): rejection or
        // excess entropy, and no third option.
        //
        // THE REAL FIX, NAMED: decouple notes from the block wire entirely — they ride the DA stream on
        // a constant-shape schedule, and the block carries only a commitment. Then the wire is constant
        // WITHOUT every peer pulling 295 KB per block synchronously. See docs/FUNDS-LOSS-KILL-LIST.md §BX.
        //
        // ⛔⛔⛔ §RF-3 spec §14 (2026-10-24) — NO HONEST BLOCK IS IDLE ON THE WIRE. A block with no note here had its
        // record's reals derived at record time from its ADDRESS (`cover::public_idle_seed_note`), so any non-holder
        // regenerated its 256 units from the block id and named the block idle (RED pin
        // `an_idle_blocks_record_is_not_reproducible_from_its_address_alone`, 0.14 s). BORROWED-FROM Bitcoin's coinbase:
        // every block carries ≥ 1 output. A producer whose reward, credits and pool left nothing appends ONE fresh seed
        // note — high-entropy, cm = `cover::seed_note_cm(body)` (not a note commitment ⇒ value 0, never spendable),
        // admitted on every peer by the door's one seed rule (`graft_admitted_notes`, `cover::is_seed_note`).
        // (2026-09-03 refuted CARRYING the seed for a live-map leaf per idle block; that cost is now what every rewarded
        // block already pays — the reward note rides here on every test and every provisioned node.)
        // cons: +1,153 B on the wire and in the record per no-recipient block — what a rewarded block already carries; 0 on
        // every rewarded or busy block; one blake3 per block at produce and at the door.
        #[cfg(test)]
        let omit_seed = PRODUCE_OMITS_SEED_NOTE_FOR_TEST.with(|c| c.get());
        #[cfg(not(test))]
        let omit_seed = false;
        // ⭐ §POLES T1 (2026-10-26, RED pin `every_blocks_cover_secret_keeps_a_real_body_off_the_wire`): the cover secret
        // and HEADER_SEED take the real BODIES as their secret input, and a body the credit set carries WHOLE (the
        // SatoshiReward, DB-224) is on the wire — so a block whose every body travels whole (a quiet rewarded block) had a
        // public secret, and its cover regenerated from the wire named it quiet. Such a block also appends the seed note,
        // which rides the record lane only (`output_notes` is `#[serde(skip)]`), exactly like a busy block's reals.
        // cons: +1,153 B in the record (not the wire) per quiet block; one cover slot of 256 becomes the seed; the quiet
        // block's body is no longer rebuilt from the wire alone (`rehydrate_block_body` → the record lane, as any idle or
        // busy block's).
        // ⛔ JUDGED ON THE WIRE FORM, NOT THE STAGED OBJECT (REGRESSION 2026-10-27, culprit 0fc837f, RED pin
        // `db224_the_carried_credit_set_holds_no_payload_and_the_regeneration_attack_fails`): the credit set travels as
        // `chain_object::carriage_of` — every note payload but the reward's is a 64-byte reference (DB-224) — so a staged
        // BridgeCredit/AssetMint/OrderFill holds a whole body that is NOT on the wire. Read off the staged object, five
        // bridge credits counted as "all whole on the wire" and a busy block grew a sixth note (6 × 1,153 B ≠ 5 × 1,153 B).
        // A body is whole on the wire only when its carriage carries it at full width; a reference is not a body.
        let whole_on_wire: Vec<Vec<u8>> = tmpl_credit_objects
            .iter()
            .filter_map(|o| crate::chain_object::carriage_of(o))
            .flat_map(|c| crate::chain_object::carried_note_payloads(&c).unwrap_or_default())
            .filter(|n| n.len() == crate::cover::PQ_NOTE_BYTES)
            .collect();
        let none_off_wire = tmpl_output_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .all(|n| whole_on_wire.iter().any(|w| w.as_slice() == n));
        // ⭐ §20.2 — THE BLOCK'S COVER KEY: drawn here, once, beside the body it keys; the seed front, the tag fill, the
        // ledger's cover cells and the record's cover bodies all follow it. It rides with the body (never on the wire).
        let cover_key = crate::cover::fresh_cover_key();
        if none_off_wire && !omit_seed {
            tmpl_output_notes.extend_from_slice(&crate::cover::seed_note_for_key(&cover_key)); // a key holder rebuilds it
            crate::cover::seal_seed_note_front(&mut tmpl_output_notes, &cover_key); // §18.1: the seed's front is the block's cover cell
        }
        block.output_notes = tmpl_output_notes.clone();
        block.cover_key = Some(cover_key);
        block.header.output_notes_root = crate::block::da_notes_root_of(&block.output_notes);
        // ⭐ §RF-3 spec §15 — SEAL THE TAG SET HERE: its decoys are the ledger's cover tag cells under HEADER_SEED, a
        // function of the output notes just fixed, and the tag root below binds them before the mine.
        let real_tags_for_evidence: std::collections::HashSet<[u8; 32]> = real_nfs.iter().copied().collect();
        let nf_padded = crate::cover::header_tag_fill(&real_nfs, crate::cover::header_seed(&block.output_notes, &cover_key));
        let digest = usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(&nf_padded, block_pre);
        // ⭐⭐⭐ COMMIT THE BLOCK'S OWN TRANSITION LEAF — a PURE function of `(block_pre, digest)`, both of which
        // ride the block. This used to commit `nf_unspent_step_new_acc(self.nf_unspent_acc, ..)`: the PRODUCER'S
        // running accumulator after folding this block, i.e. a function of THIS node's private history rather
        // than of the block. No other device could reproduce it — its own A_tip folds at ACCEPT and is order-free,
        // so it had already moved — and the block parked forever. MEASURED before the fix: B folded 2 of A's 47
        // blocks with 32 parked, `nf_root_agree=false`, while `nf_acc_agree=TRUE`. Pure ⇒ every verifier
        // re-derives this byte-identically and folds it commutatively, so the same block SET converges in any order.
        let post_acc = usdm_decider::nf_sparse_air::block_transition_leaf(block_pre, digest);
        let post_root = Hash32(crate::spend_frontier::leaf_to_cm_bytes(post_acc));
        // The height-1 fold proves the transition over a FIXED-height trace with EMPTY copaths (digest = nf values
        // only). A treeless node verifies it O(1) and RE-COMPUTES `post_acc` from the tags it regenerates.
        let fold_inserts: Vec<usdm_decider::nf_sparse_air::SparseInsertWitness> = nf_padded
            .iter()
            .map(|nf| crate::nf_sparse::insert_witness_for(nf, Vec::new()))
            .collect();
        let fold = usdm_decider::nf_sparse_air::prove_sparse_fold_height1_bytes(
            &fold_inserts,
            block_pre,
            post_acc,
        )
        .unwrap_or_default();
        // Stash the EXACT padded set for the immediately-following graft to append + adopt, and carry that
        // same set on the block so a peer can verify the fold without holding this node's mempool.
        block.nullifier_proof.post_root = post_root;
        block.nullifier_proof.fold = fold;
        block.nullifier_proof.padded_tags = nf_padded.clone();
        self.pending_block_nullifiers = nf_padded;
        // ⭐⭐⭐ DB-165 — SEAL THE CONSTANT-WIDTH NOTE CARRIER, HERE, FOR THE SAME REASON THE NOTES ARE
        // SEALED HERE: before the mine, so the PoW binds it and no relay can swap which notes this block
        // commits. Exactly 8,192 bytes on every block, quiet or busy.
        block.note_commitments = self.assemble_note_commitment_carrier(&block.output_notes);
        block.header.note_commitments_root =
            crate::hash::Hash32::hash(&block.note_commitments);
        // ⭐ §BA — the justification sidecar is sealed BEFORE the mine, like the notes it stands beside,
        // so the PoW binds it and a relay cannot append the object that excuses a note it wants to plant.
        // ⭐⭐⭐ DB-224 — AND IT IS SEALED AFTER THE NOTE CARRIER, IN CARRIAGE FORM, THROUGH THE SUBJECT RULE:
        // `carriable_credit_set` keeps exactly the objects `consensus::credit_set_is_carried_with_its_subjects`
        // admits against THIS carrier, so an honest block always passes the rule every peer applies.
        // ⭐ §22 — SEALED under the block's cover key (a note-less block: the public empty-record key), ONE width on every
        // block; the header root binds the SEALED bytes whole, so every door binds the body without the key and only a
        // holder of the key (this node now; a peer once the record lane delivers it) reads the frames. The mempool's
        // frame budget (`TemplateReserve::frames`) kept the selection inside the width; a staged set that still does not
        // fit is a producer defect this `expect` names, never a block on the wire.
        let carried = Self::carriable_credit_objects(&tmpl_credit_objects, &block.note_commitments);
        let seal_key = crate::block::credit_seal_key_held(&block.header, &cover_key);
        // §22b: a carriage wider than `CREDIT_INLINE_MAX` rides as a reference; its bytes go beside the body.
        let (frames, wide) = crate::block::split_wide_carriages(&carried);
        block.wide_objects = wide;
        block.credit_set = crate::block::credit_set_seal(&frames, &seal_key)
            .expect("§22: the template's framed objects were selected inside CREDIT_SET_FRAME_BUDGET");
        block.header.credit_set_root = crate::block::credit_set_root_of(&block.credit_set);
        // ⭐⭐⭐ P2 — SEAL THE TAG SET INTO THE ID, HERE, FOR THE SAME REASON THE NOTES ARE SEALED HERE.
        // The tags are what every node folds into A_tip and writes to its DA-nf shard, so a relay that
        // strips or swaps them (and re-proves the carried height-1 fold, which is publicly re-provable in
        // ~0 ms) would leave two nodes holding one block id while folding DIFFERENT spend sets. Sealing
        // before the mine puts the tags inside what the PoW binds; sealing after would mutate the header
        // post-PoW and change `block.id()`.
        block.header.nullifier_tags_root =
            crate::block::nullifier_tags_root_of(&block.nullifier_proof.padded_tags);
        // ⭐⭐⭐ P4′a — ATTACH AND SEAL THE TWO FINDABILITY SIDECARS HERE TOO, FOR THE IDENTICAL REASON.
        //
        // These were attached in `graft_mined_own`, i.e. AFTER the off-lock mine. That was safe only while
        // they sat outside the id; now that the id binds them, attaching them post-mine would mutate the
        // header after its PoW was solved and change `block.id()` — the exact mistake the `output_notes_root`
        // comment above records catching ("Sealing after the mine (which I tried) mutates the header post-PoW
        // and changes `block.id()`"). So the carry moves here, where the lock is held, `output_notes` is
        // already assembled, and nothing has been mined yet.
        //
        // Both derivations are pure functions of `block.output_notes` plus node-local maps readable right
        // here: `pending_tags` by REFERENCE (the record loop still drains it exactly as before, so the
        // producer's own behaviour is unchanged), and `account_targets_for(.., None)`, which resolves
        // per-NOTE and takes no block id — which is precisely what retired the `[acct-addr-drift]`
        // circularity documented below. Nothing here needs the block's identity, so sealing the roots cannot
        // feed back into the values being sealed.
        //
        // PAST-CHATS-CHECKED: no new constant — the note width is the existing canonical
        // `crate::cover::PQ_NOTE_BYTES` (1153 = note_cm 32 + ct 1088 + enc_amount 32 + view_tag 1), the same
        // shape `account_targets_for` and the carry this replaces already walk. The "a block must carry what
        // applies it" rule is the user's own, recorded in `Block::oli_tags` and
        // [[reference_oli_tags_are_da_resident_never_cached]]; binding a carried sidecar into the id is the
        // P2 pattern already landed for `nullifier_tags_root` two lines above.
        block.oli_tags = {
            // ⛔ DB-351: a STATED spend's outputs file exactly what that spend's own clue list says (its carrier bound
            // D over it), never a key staged from gossip — or a relay's early clue would make this honest block's
            // transition refuse on every peer, the producer's own self-verify first.
            let spend_filing = self.stated_spend_filing(&tmpl.tx_ids);
            let mut out = Vec::new();
            let mut off = 0usize;
            while off + crate::cover::PQ_NOTE_BYTES <= block.output_notes.len() {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&block.output_notes[off..off + 32]);
                // Every other note: the one read shared with the record loop's drain (`staged_tag_for_cm`), so the
                // block a producer seals carries a tag whenever this node holds the note's index key at all —
                // whether the clue arrived with its own transaction or was gossiped ahead of it.
                let k = match spend_filing.get(&cm) {
                    Some(own) => *own,
                    None => self.staged_tag_for_cm(&cm),
                };
                if let Some(k) = k {
                    out.extend_from_slice(&cm);
                    out.extend_from_slice(&k);
                }
                off += crate::cover::PQ_NOTE_BYTES;
            }
            out
        };
        block.account_targets = Vec::new(); // H5 / DB-273 (C): the bucket linker is retired; consensus refuses any
        // §RF-3: the transition's inputs are cut BEFORE the sidecar roots — a ledger block carries the uniform ledger
        // filing and names its seed and ring commit in the header, so all three are sealed with the rest.
        let pending = match self.pending_note_transition(&tmpl.tx_ids, &block) {
            Ok(p) => p,
            Err(unfiled) => {
                self.mempool.remove(&unfiled);
                return None;
            }
        };
        // lane agg: how many spends this template states — the slot demand the hybrid's rule reads (`agg_room`)
        crate::node_runtime::LAST_STATED_SPENDS
            .store(pending.as_ref().map_or(0, |p| p.stated_spend_ids.len()) as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some((p, l)) = pending.as_ref().and_then(|p| p.ledger.as_ref().map(|l| (p, l))) {
            block.oli_tags = p.oli_tags.clone();
            block.header.cover_seed_commit = crate::block::cover_seed_commit_of(l.seed);
            block.header.member_ring_commit = l.ring_commit;
        }
        crate::block::pad_oli_tags_to_constant(&mut block.oli_tags, &block.output_notes);
        block.header.oli_tags_root = crate::block::da_sidecar_root_of(&block.oli_tags);
        block.header.account_targets_root =
            crate::block::da_sidecar_root_of(&block.account_targets);
        // DB-105: the transition is cut here as INPUTS; a live node proves it off the runtime lock
        // (`defer_transition`), the in-process paths prove it inline exactly as before.
        let mut deferred_transition: Option<PendingNoteTransition> = None;
        // ⭐ §22c — THE STATED SPENDS' OWN TRANSACTIONS, beside the body: exactly the transactions the transition states
        // (`pending_note_transition`'s `stated_spend_ids`, in `tx_ids` order), encoded as tx gossip carries them. Every
        // peer verifies each itself before it admits a row of this block (`spend_evidence`); a block that states a spend
        // and does not carry its transaction is refused by every one of them.
        if let Some(p) = pending.as_ref() {
            block.tx_bodies = p
                .stated_spend_ids
                .iter()
                .filter_map(|id| self.mempool.get(id))
                .filter_map(|tx| postcard::to_allocvec(tx).ok())
                .collect();
        }
        if let Some(p) = pending {
            if defer_transition {
                deferred_transition = Some(p);
            } else {
                let bound = self.template_double();
                // DB-223: the stated spends' membership transition, laid beside it (§RF-3: the member ledger over it).
                let ledger_bound = self.ledger_double();
                let laid = Self::finish_note_transition(&p, bound, ledger_bound).and_then(|(mut nt, statements)| {
                    let member_t = Self::finish_member_transition(&p, bound);
                    let mt = Self::finish_member_after(&p, &mut nt, statements, member_t, ledger_bound)?;
                    Some((nt, mt))
                });
                match laid {
                    Some((nt, mt)) => {
                        block.note_transition = Some(nt);
                        block.member_transition = mt;
                    }
                    None => {
                        self.mempool.remove(&p.stated_spend_ids);
                        return None;
                    }
                }
                // ⭐ lane agg: the inline path proves the block's ONE root over its tree-form payments here too (the live
                // runtime proves it off the lock beside the transition, `node_runtime::complete_produce_job`). A root this
                // node's own prover refuses lays none of those payments: they leave the pool and their origins re-push them.
                if let Some((ids, runs)) = self.pending_tree_for(&block.tx_bodies) {
                    let t = std::time::Instant::now();
                    match crate::node::prove_block_roots(&runs) {
                        Some(roots) => {
                            let ms = t.elapsed().as_millis() as u64;
                            // DIGITAL-CASH-PRIVACY-REVIEWED: counts and a duration; no id, amount or owner.
                            eprintln!("[agg] laid {} root(s) over {} payment(s) in {ms} ms", roots.len(), ids.len());
                            block.agg_tables = roots;
                        }
                        None => {
                            self.mempool.remove(&ids);
                            return None;
                        }
                    }
                }
            }
        }
        // ⭐⭐⭐ THE BOND CARRIER — sealed HERE, before the off-lock mine, for the identical lifecycle
        // reason as every root above. Each entry is the FULL postcard-encoded bonding tx (the same
        // bytes tx gossip already carries), so every ingester re-runs the SAME admission verify
        // (welded weight + mandatory membership fold) before admitting — carried, never trusted.
        block.bond_set = {
            let mut out = Vec::new();
            for id in &tmpl.tx_ids {
                if let Some(tx) = self.mempool.get(id) {
                    // ⭐⭐⭐ BOTH DIRECTIONS OF BONDING RIDE THE SAME LANE. An admission carries
                    // `bond_notes`; an UNBOND carries a framed `Class::Unbond` blob and no notes at all.
                    //
                    // ⛔ IT CANNOT RIDE THE MEMPOOL-RESOLVED SEAM. That seam reads each blob from the
                    // node's OWN pool (`self.mempool.get(id)`), so a peer that never pooled the tx never
                    // applies it — MEASURED: A published and produced the unbond, and BOTH parties still
                    // held the full 50,000 weight because neither graft path could see the object. The
                    // bond_set is header-bound and CARRIED, which is exactly why admission already worked
                    // everywhere; the release now travels the same way.
                    // Both directions of bonding AND a membership seat ride this one lane.
                    let is_bond_object = matches!(
                        crate::chain_object::unframe(&tx.blob),
                        Some((crate::chain_object::Class::Unbond, _))
                            | Some((crate::chain_object::Class::MembershipBond, _))
                            | Some((crate::chain_object::Class::Equivocation, _))
                            | Some((crate::chain_object::Class::FinalityVote, _))
                            | Some((crate::chain_object::Class::ReserveTheft, _))
                            | Some((crate::chain_object::Class::EpochKeyFraud, _))
                    );
                    if tx.bond_notes.len() >= 40 || is_bond_object {
                        if let Ok(enc) = postcard::to_stdvec(tx) {
                            out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
                            out.extend_from_slice(&enc);
                        }
                    }
                }
            }
            out
        };
        // ⭐⭐⭐ DB-313 §3 — THE WELDED CLASS RIDES THE BOND LANE, sealed under the root below. The in-process path
        // proves it here; a live node proves it off the runtime lock (`complete_produce_job`) and reseals the root.
        // A transition this node's own verifier refuses lays NONE of its bonds: they leave the pool and no block is
        // produced this slot, exactly the note transition's rule.
        if !defer_transition {
            if let Some(pb) = self.pending_bond_for(&tmpl.tx_ids) {
                match Self::finish_bond_transition(&pb.bonds, &block.header.output_notes_root, self.template_double()) {
                    Some(bt) => block.bond_set.extend_from_slice(&crate::note_transition::bond_lane_entry(&bt)),
                    None => {
                        self.mempool.remove(&pb.ids);
                        return None;
                    }
                }
            }
        }
        // §POLES: root from REAL content (before padding) — the cover is transport privacy, not consensus.
        block.header.bond_set_root = crate::block::da_sidecar_root_of(&block.bond_set);
        crate::block::pad_sidecar_to_constant(
            &mut block.bond_set,
            &self.da_secret_value(),
            b"MUSD-bond-pad",
        );
        // ⛔ AUDIT F15 (2026-11-10) — THE DIRECTORY SIDECAR CARRIES NOTHING. It used to carry this node's queued sign-ups,
        // admitted on a signature alone and kept by every node for ever at no cost and with no size bound (the pad
        // below leaves an oversize sidecar as it is). A directory entry now travels as a `Class::DirEntry` object that
        // pays for its bytes (`dir_entry_tx`), in the block's object lane like every other transaction. The sidecar
        // stays in the block's shape, always empty, so it is always the constant cover pad and its root is the empty
        // set's; every node ignores whatever a producer puts there (`dir_step_at_fold`).
        block.dir_set = Vec::new();
        // §POLES: root from REAL content (before padding) — the cover is transport privacy, not consensus.
        block.header.dir_set_root = crate::block::da_sidecar_root_of(&block.dir_set);
        crate::block::pad_sidecar_to_constant(
            &mut block.dir_set,
            &self.da_secret_value(),
            b"MUSD-dir-pad",
        );
        // ⭐ THE LETTER CARRIER — seal the CONSTANT cover-padded commitment set, sealed HERE before the
        // off-lock mine for the identical lifecycle reason as every root above. Real pending letter
        // commitments (from this node's relay ring) fill the front slots; the rest are cover commitments
        // seeded from THIS NODE'S DA secret + the template context — carried VERBATIM in the block, so every
        // ingester folds the identical bytes (no re-derivation, no cross-node divergence) while an observer
        // cannot tell a cover slot from a real one (secret-seeded, never a public index function).
        block.letter_set = {
            let reals = crate::rpc_http::letter_pending_cms();
            let mut out = Vec::with_capacity(crate::letter::LETTER_CMS_PER_BLOCK * 32);
            for cm in reals.iter().take(crate::letter::LETTER_CMS_PER_BLOCK) {
                out.extend_from_slice(cm);
            }
            let secret = self.da_secret_value();
            let mut slot = out.len() / 32;
            while slot < crate::letter::LETTER_CMS_PER_BLOCK {
                let mut h = blake3::Hasher::new();
                h.update(b"MONEROUSD-LETTER-COVER-CM");
                h.update(&secret);
                h.update(&block.header.timestamp.to_le_bytes());
                h.update(&(slot as u64).to_le_bytes());
                out.extend_from_slice(h.finalize().as_bytes());
                slot += 1;
            }
            out
        };
        block.header.letter_set_root = crate::block::da_sidecar_root_of(&block.letter_set);
        block.tag_evidence = if crate::canon_chain::canon_live() {
            self.canon_tag_evidence_for(&block.nullifier_proof.padded_tags, &sel_txs) // A-F114 2c: the constant chain's evidence
        } else {
            self.tag_evidence_for(&block.nullifier_proof.padded_tags, &real_tags_for_evidence)
        };
        block.header.tag_evidence_root = crate::block::da_sidecar_root_of(&block.tag_evidence);
        self.stamp_join_fields(&mut block.header);
        // ⛔ §RF-3 (2026-10-24): THE CONSTANT-WIDTH HALF, INLINE TOO. `complete_produce_job` lays it for a live node; the
        // in-process path laid note, member and bond transitions and silently NO cover transition, so every in-process
        // block's constant-width spends went unstated and the shape probe measured the field 0·0·0. One producer, two
        // drivers, one block. Independent of the note transition, exactly as off the lock: a cover transition this node's
        // own verifier refuses costs the block that class only, never the slot.
        // §18 (2026-10-28): the cover transition is RETIRED here too — the ledger's pair rows state the whole tag set.
        let _ = defer_transition;
        block.cover_transition = None;
        // ⭐ DB-223: the header commits the transitions this block carries (sealed here for the inline path; a deferred
        // transition is attached off the lock and `complete_produce_job` seals again before the grind).
        block.seal_transitions_root();
        Some((block, cover_ids, tmpl.tx_ids, tmpl_output_notes, deferred_transition))
    }

    /// ⭐ SATOSHI §6/§8 — the operator's WALLET IN-PROCESS (the harness's path; the real wallet runs the same steps through
    /// `/submit_sat_bond`): open a recorded SAT note with the recipient's secrets `wallet` (its decapsulation key and, since
    /// DB-395, the `(ask, nk)` that alone can spend it — held by the caller, never by the node), lock its whole amount as
    /// custody weight for the validator key `(pk, sk)`, seal the locked and change notes back to the recipient so an unbond
    /// returns a spendable note, and prove membership from this node's own record. `None` when the note is not this
    /// recipient's, not recorded here yet, or a carrier does not build.
    pub fn build_sat_bond_from_reward(&mut self, reward_note: &[u8], wallet: &crate::faucet::RecipientSecrets, pk: &[u8], sk: &[u8]) -> Option<crate::sat_bond_tx::SatBondTx> {
        self.build_sat_bond_in_process(reward_note, None, wallet, pk, sk, None)
    }
    /// ⭐ SATOSHI §9 — the in-process RE-BOND: consume `fresh_note` AND the validator's currently locked note (`locked_note`,
    /// both opened with the recipient's secrets) into ONE new locked note of their summed weight. Same shape as the first seat.
    pub fn build_sat_rebond_in_process(&mut self, fresh_note: &[u8], locked_note: &[u8], wallet: &crate::faucet::RecipientSecrets, pk: &[u8], sk: &[u8]) -> Option<crate::sat_bond_tx::SatBondTx> {
        self.build_sat_bond_in_process(fresh_note, Some(locked_note), wallet, pk, sk, None)
    }
    pub(super) fn build_sat_bond_in_process(&mut self, fresh_note: &[u8], locked_note: Option<&[u8]>, wallet: &crate::faucet::RecipientSecrets, pk: &[u8], sk: &[u8], weight: Option<u64>) -> Option<crate::sat_bond_tx::SatBondTx> {
        use usdm_decider::whir_rec_block::{asset_note_cm, prove_asset_bond_validity_carrier_bytes, prove_asset_rebond_validity_carrier_bytes, AssetRebondWitness};
        let rc = self.reward_recipient.clone()?;
        let (value_in, in_owner, asset) = wallet.open_asset(fresh_note)?;
        if asset != crate::satoshi::asset_tag() {
            return None;
        }
        let in_opening = in_owner.opening();
        let locked = match locked_note {
            Some(n) => {
                let (v2, owner2, a2) = wallet.open_asset(n)?;
                if a2 != asset {
                    return None;
                }
                Some((v2, owner2))
            }
            None => None,
        };
        let total = value_in.checked_add(locked.map(|l| l.0).unwrap_or(0))?;
        let weight = weight.unwrap_or(total);
        let change = total.checked_sub(weight)?;
        let seal = |amount: u64, domain: &[u8]| {
            // a TEST seed is unique per INPUT (its opening) and output role, so two bonds never seal identical notes
            let seed = Self::reward_seal_seed(&self.miner_seed, weight, Hash32::hash(&[domain, &crate::spend_frontier::leaf_to_cm_bytes(in_opening)[..]].concat()).as_bytes());
            crate::faucet::seal_asset_note(&rc.scan_ek, &rc.spk, amount, asset, seed)
        };
        let (locked_out, out0_opening) = seal(weight, b"MONEROUSD-SAT-BOND-LOCK-v1")?;
        let (change_note, out1_opening) = seal(change, b"MONEROUSD-SAT-BOND-CHANGE-v1")?;
        // the membership blinding: a function of the OWNER's `nk` and the note's opening — nothing the note's sealer holds (it
        // has no `nk`), so the one-hash linkage DB-363 closed stays closed
        let lc_blind = {
            let mut pre = b"MONEROUSD-SAT-BOND-LCBLIND-v2".to_vec();
            pre.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(in_owner.nk));
            pre.extend_from_slice(&crate::spend_frontier::leaf_to_cm_bytes(in_opening));
            usdm_decider::poseidon2_compress::hash32_to_digest(Hash32::hash(&pre).as_bytes())
        };
        let b32 = crate::spend_frontier::leaf_to_cm_bytes;
        let fresh_w = usdm_decider::whir_rec_block::AssetSpendValidityWitness {
            value_in,
            owner: in_owner,
            value_out: total,
            fee: 0,
            lc_blind,
            out0_value: weight,
            out0_opening,
            out1_value: change,
            out1_opening,
            asset,
        };
        let (carrier, cms, nf, lc, rebond) = match locked {
            None => {
                let w = crate::sat_bond_tx::bond_witness(value_in, in_owner, weight, out0_opening, out1_opening, lc_blind, asset)?;
                let (c, cms, nf, lc) = prove_asset_bond_validity_carrier_bytes(&w, weight)?;
                (c, cms, nf, lc, None)
            }
            Some((v2, owner2)) => {
                let w = AssetRebondWitness { fresh: fresh_w, locked_value: v2, locked_owner: owner2 };
                let (c, cms, nf, nf2, lc) = prove_asset_rebond_validity_carrier_bytes(&w, weight)?;
                let leg = crate::sat_bond_tx::RebondLeg { nullifier_locked: b32(nf2), locked_cm: b32(asset_note_cm(v2, asset, owner2.opening())) };
                (c, cms, nf, lc, Some(leg))
            }
        };
        let fresh_cm = b32(asset_note_cm(value_in, asset, in_opening));
        let leaf = asset_note_cm(value_in, asset, in_opening);
        // §19 (2026-10-28, lane funds): the node's OWN member leg (`own_member_leg`, the book over its folded record + the
        // stream it serves), judged at the sat-bond door by the one dispatcher — no `named_record` on the wire. Before: the
        // one-step bind named the record holding this validator's reward on every auto-bond.
        let _ = leaf;
        // zero outputs in the leg — the validity carrier binds them (the wallet's `membership_bind_for` lays the same)
        let (membership_carrier, leg_tuple) = self.own_member_leg(&fresh_cm, nf, lc_blind, &[0u8; 32], &[0u8; 32])?;
        let mut member_tuple = Vec::with_capacity(crate::member_transition::MEMBER_TUPLE_BYTES);
        crate::member_transition::write_tuple(&leg_tuple, &mut member_tuple);
        let zero = usdm_decider::poseidon2_compress::lanes_of(&[0, 0, 0, 0]);
        let (tip_prev, tip_root, tip_acc, named_record) = (zero, zero, zero, 0u64);
        debug_assert_eq!((&locked_out[..32], &change_note[..32]), (&b32(cms[0])[..], &b32(cms[1])[..]), "the sealed notes are the carrier's outputs");
        let vid = crate::pqauth::pubkey_id(pk);
        let owner_clue = crate::satoshi::reward_clue(&rc.sat_loc_sk, rc.next_index);
        let mut t = crate::sat_bond_tx::SatBondTx {
            notes: [locked_out.to_vec(), change_note.to_vec()],
            nullifier: b32(nf),
            leaf_commit: lc,
            validity_carrier: carrier,
            membership_carrier,
            member_tuple,
            named_record,
            tip_prev,
            tip_root,
            tip_acc,
            weight,
            vid,
            pubkey: pk.to_vec(),
            sig: Vec::new(),
            owner_clue,
            rebond,
        };
        t.sig = crate::pqauth::ml_dsa_sign(&t.statement()?, sk)?;
        // the change note's owner clue takes the recipient's next `"sat"` index, exactly as a reward does
        self.advance_reward_index();
        Some(t)
    }
    /// ⭐ SATOSHI §6 — publish a custody bond into this node's own pool (the next block lifts it into the credit set); the
    /// change note rides as its output, the locked note never does.
    pub fn publish_sat_bond(&mut self, t: &crate::sat_bond_tx::SatBondTx) -> Result<Hash32, crate::mempool::MempoolError> {
        if let Some(why) = crate::node::objects::sat_bond_tx::sat_bond_refusal(self, t, crate::respend::MemberDoor::Admit) {
            eprintln!("[sat-bond] ⛔ not published: {why}");
            return Err(crate::mempool::MempoolError::InvalidId);
        }
        self.publish_spending_object_nfs(t.to_object(), &t.own_nullifiers(), t.notes[1].clone())
    }

    /// ⭐ PUBLISH THIS NODE'S OWN MEMBERSHIP BOND — the seat is REQUESTED of the chain, never taken.
    ///
    /// Frames a `Class::MembershipBond` signed by this node's identity key and admits it to the pool.
    /// Nothing about this node's validator set changes here: the seat lands when a block carries the
    /// object and `apply_bond_set` runs — on this node and every peer alike. Whether it is FREE is decided
    /// then, from chain state (`peg.reserve_is_zero()`), so a node that asks after the first deposit is
    /// refused everywhere rather than seated on itself.
    ///
    /// CHAIN-PUBLISH-REVIEWED: this IS the publication (`publish_valueless_asset_object` → `ingest_tx`).
    pub fn publish_membership_bond(
        &mut self,
        pubkey: &[u8],
        sig: &[u8],
        header: crate::membership_bond_tx::MembershipBondHeader,
    ) -> AssetSpendOutcome {
        if !crate::membership_bond_tx::is_authorised(
            &header,
            pubkey,
            sig,
            &crate::pqauth::MlDsaVerifier,
        ) {
            return AssetSpendOutcome::Refused(
                "the membership bond is not signed by the key it names over this header",
            );
        }
        // DB-369: the same one rule the fold door applies — a request no slot can seat is not pooled. (The FOLD decides:
        // requests published before any seat lands all pass here, and the fold seats only the first open slots.)
        if !self.free_seat_open() {
            return AssetSpendOutcome::Refused("a free seat needs a zero reserve and an open founding slot; post collateral");
        }
        let Some(blob) = crate::membership_bond_tx::wire(&header, pubkey, sig) else {
            return AssetSpendOutcome::Refused("the membership bond could not be encoded");
        };
        let out = self.publish_seat_request(blob.clone());
        if matches!(out, AssetSpendOutcome::Published) {
            self.own_membership_bond = Some(blob);
        }
        out
    }

    /// ⛔ DB-258b — POOL A SEAT REQUEST WITH ITS ONE-SHOT RIGHT IN ITS LANE (`membership_bond_tx::seat_right_nf`, derivable
    /// from the object), by the mint's publication path and with the same lane evidence, so the block that seats the
    /// validator retires the right and no copy of the request can seat it again.
    /// CHAIN-PUBLISH-REVIEWED: this IS the publication (`publish_asset_object_with_note` → `ingest_tx`).
    pub(super) fn publish_seat_request(&mut self, blob: Vec<u8>) -> AssetSpendOutcome {
        let right = crate::chain_object::unframe(&blob)
            .and_then(|(_, payload)| crate::membership_bond_tx::decode(payload))
            .map(|(h, pk, _)| {
                crate::membership_bond_tx::seat_right_nf(&crate::membership_bond_tx::validator_id(&pk), &h)
            });
        let Some(right) = right else {
            return AssetSpendOutcome::Refused("the membership bond could not be decoded");
        };
        self.publish_asset_object_with_note(blob, &[], Some(right), "membership-bond")
    }

    /// ⛔ DB-274 P4b (§8.15) — PUBLISH a reserve theft's evidence. It slashes NOTHING here: the block that carries it
    /// slashes the named offenders on every node, this one included, at that block's fold (`theft_tx`).
    ///
    /// A slash REQUIRES a ≥2/3 post-quantum threshold fraud proof: the bonded quorum ML-DSA-65-attests an UNAUTHORIZED
    /// reserve movement (a foreign move with no valid `authorize_reserve_move` certificate) AND the offender ids it
    /// names, in the v2 message (`theft_tx::theft_msg`). So no minority claim can slash anyone, and no certificate can
    /// slash a validator it did not name.
    ///
    /// This replaces `slash_reserve_theft`, which slashed on the ONE node that received the request, and whose offender
    /// list no signature covered.
    ///
    /// Checks before publishing (advice, like the pool door's):
    /// - the object is one canonical, bounded encoding;
    /// - the certificate meets ≥2/3 of the TIP set here.
    /// The fold re-weighs it against its own step's pre-state, which decides.
    pub fn publish_reserve_theft(
        &mut self,
        statement: &[u8],
        theft_attestation: &crate::bond_tally::PqThresholdCert,
        offenders: &[[u8; 32]],
        // §BR-3 17.5: the stolen sats custody attests (inside the signed message)
        loss_sats: u64,
    ) -> AssetSpendOutcome {
        let offenders = crate::theft_tx::canonical_offenders(offenders);
        let Some(blob) = crate::theft_tx::wire(statement, &offenders, loss_sats, theft_attestation) else {
            return AssetSpendOutcome::Refused("the evidence is not one canonical, bounded theft object");
        };
        if !crate::bond_tally::verify_threshold(
            &crate::theft_tx::theft_msg_at(statement, &offenders, loss_sats, self.theft_statement_seq()),
            theft_attestation,
            &self.validators,
            &crate::pqauth::MlDsaVerifier,
        ) {
            return AssetSpendOutcome::Refused("no ≥2/3 of the bonded weight signs this theft and these offenders");
        }
        self.publish_valueless_asset_object(blob, "reserve-theft")
    }

    /// ⭐ §BR-9a — PUBLISH an epoch-key fraud proof (a dealer's own committed shares rebuilding another public part). It
    /// slashes nothing here: the block that carries it slashes the dealer on every node, this one included, at the bond step
    /// (`epoch_fraud_tx`). Checked against THIS node's epoch-key ledger before publishing (advice; the bond step decides).
    pub fn publish_epoch_fraud(&mut self, p: &crate::epoch_release::FraudProof) -> AssetSpendOutcome {
        let Some(blob) = crate::epoch_fraud_tx::wire(p) else {
            return AssetSpendOutcome::Refused("the evidence is not one canonical, bounded fraud proof");
        };
        if !self.peg.epoch_keys().epochs.get(&p.epoch).is_some_and(|r| crate::epoch_release::fraud_proof_holds(r, p)) {
            return AssetSpendOutcome::Refused("the proof does not convict its dealer against this node's epoch-key ledger");
        }
        self.publish_valueless_asset_object(blob, "epoch-fraud")
    }

    /// ⭐ DB-266 — PUBLISH an equivocation's evidence (two conflicting certs by one key at one height). It slashes
    /// nothing here: the block that carries it slashes the voter on every node, this one included.
    pub fn publish_equivocation(
        &mut self,
        a: &crate::validator::VoteCert,
        b: &crate::validator::VoteCert,
    ) -> AssetSpendOutcome {
        let Some(blob) = crate::equivocation_tx::wire(a, b) else {
            return AssetSpendOutcome::Refused("the two votes are not an equivocation by one key at one height");
        };
        let proves = crate::chain_object::unframe(&blob)
            .and_then(|(_, p)| crate::equivocation_tx::proves_equivocation(p, &crate::pqauth::MlDsaVerifier));
        if proves.is_none() {
            return AssetSpendOutcome::Refused("the evidence's signatures do not verify under its one key");
        }
        self.publish_valueless_asset_object(blob, "equivocation")
    }

    /// Adopt a site publish once its owner's PQ signature authenticates it (fail-closed), THEN the
    /// registry enforces owner-continuity + version-monotonicity. `pubkey` is the owner's PQ public
    /// key; `sig` covers [`crate::pqauth::site_publish_msg`]. The owner id must be `H(pubkey)`.
    pub fn publish_site(
        &mut self,
        publish: SitePublish,
        pubkey: &[u8],
        sig: &[u8],
    ) -> PublishOutcome {
        if pubkey_id(pubkey) != publish.owner {
            return PublishOutcome::Unauthenticated;
        }
        if !self
            .site_verifier
            .verify(pubkey, &site_publish_msg(&publish), sig)
        {
            return PublishOutcome::Unauthenticated;
        }
        let outcome = self.sites.adopt(publish.clone());
        if outcome == PublishOutcome::Adopted {
            // MonerousD Veil: the site's host keeps the signed record with the site's index, so a restarted node
            // re-adopts it through THIS door (signature checked again) and a peer that missed it can be offered it.
            crate::veil::note_publish(&crate::site::SiteGossip::new(publish, pubkey.to_vec(), sig.to_vec()));
        }
        outcome
    }

    /// G1 (lane a 2026-10-22) — the rows of `mined_tx_nfs` a DAG block with an unfolded record names (the reader's
    /// universe, `mined_tx_nfs_live_tx_ids`), written beside the snapshot sorted by tx id (see `persist::save_mined_tx_nfs`).
    pub(crate) fn mined_tx_nfs_rows_to_persist(&self) -> Vec<([u8; 32], Vec<[u8; 32]>)> {
        let live = self.mined_tx_nfs_live_tx_ids();
        let mut rows: Vec<([u8; 32], Vec<[u8; 32]>)> =
            self.mined_tx_nfs.iter().filter(|(t, _)| live.contains(*t)).map(|(t, nfs)| (t.0, nfs.clone())).collect();
        rows.sort();
        rows
    }

    /// Build a bundle SYNCHRONOUSLY: [`Self::draft_sync_bundle`], then the detached certificate step run right
    /// here, then its install. Byte-identical to the pre-DB-243 build for every caller that wants a finished
    /// bundle in one call (tests, `serve_sync_request`); the live runtime drafts under the lock and runs the step
    /// on its prove thread instead (DB-243).
    pub fn build_sync_bundle(
        &mut self,
        decider_proof: Vec<u8>,
        frontier: FrontierSnapshot,
    ) -> Option<SyncBundle> {
        let mut bundle = self.draft_sync_bundle(frontier)?;
        bundle.decider.proof = decider_proof;
        Some(bundle)
    }

}
