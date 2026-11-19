// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! fold — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// Fold a block's leaves pairwise to its root — the same walk [`Self::da_note_copath_in_block`] takes
    /// while recording siblings, so a copath from that call always refolds to this value.
    pub fn fold_leaves_to_root(
        leaves: &[crate::spend_frontier::Digest4],
    ) -> crate::spend_frontier::Digest4 {
        let mut level = leaves.to_vec();
        while level.len() > 1 {
            let mut up = Vec::with_capacity(level.len() / 2);
            let mut i = 0;
            while i + 1 < level.len() {
                up.push(crate::spend_frontier::poseidon_pair(level[i], level[i + 1]));
                i += 2;
            }
            level = up;
        }
        level.first().copied().unwrap_or_default()
    }

    /// THE CANONICAL FOLD OF ONE RECORD (v31). Everything order-dependent that `record_note_payload_inner`
    /// used to do at ingest happens here, and only here, when `fold_canonical_records` reaches the record's
    /// block in the DAG's canonical order: the ordinal claim, the ladder seal and cold prune, the leaf start,
    /// the accumulator step, the 256 spine leaves and the root-history anchor. The bytes must already be
    /// written (ingest writes them; an idle record regenerates) — a record whose bytes are not held is not
    /// folded, and the pass waits for the by-id lane to bring them.
    ///
    /// MEASURED 2026-09-03 (gate 41, scratch jUhX9D): folding at ingest gave 597 of 598 co-written records
    /// DIFFERENT ordinals on the two nodes — every restart wall since gate 32 was that. Folding here, in
    /// the same order on every node, is what makes ordinals, spines and accumulator series agree.
    /// MUST-STAY-GREEN: canonical_ordinal_after_resume_tests, da_seed_regen_tests, every copath/witness test.
    /// Fold one record into the spine AT THE POSITION THE DAG GIVES IT.
    ///
    /// BORROWED-FROM: Zcash note-commitment-tree insertion order + Kaspa GHOSTDAG mergeset ordering —
    /// github.com/zcash/zcash (a note's leaf index IS the position produced by applying the chain in
    /// consensus order; no node ever tells another node an index) and github.com/kaspanet/rusty-kaspa
    /// (consensus/src/processes/ghostdag — a chain block's mergeset has ONE canonical order, so every node
    /// walks the same total order over the same DAG).
    ///
    /// THIS USED TO CLAIM `served_seq`, A COUNTER OVER "WHAT THIS NODE HAPPENED TO FOLD" — a SECOND global
    /// numbering, separate from the block DAG, which made a record's address a function of each node's own
    /// history instead of a function of consensus. Everything built to keep it agreed (peer row hints,
    /// sidecar-page ordinal reconciliation, ordinal eviction at adopt, the interleave fix, the
    /// unknown-block wait) existed only to paper over that. MEASURED 2026-09-04, gate 46 on a fresh pair:
    /// after a rolling restart the two nodes disagreed about which record was ORDINAL 0 — the genesis
    /// record — so every 261-row page the peer served yielded "0 new", the readiness gap grew to 778 and
    /// they never reconverged; the same failure as gates 43, 44 and 45.
    ///
    /// The caller passes the position derived from the DAG (`fold_canonical_records`), so two nodes holding
    /// the same DAG produce the same numbering by construction, with nothing to reconcile on the wire.
    /// `served_seq` survives ONLY as a cached high-water mark for the spine's leaf count.
    pub(super) fn fold_record_into_spine(&mut self, seq: u64, dag_ordinal: u64) -> Option<u64> {
        // ⛔ v32 (item 9): GENESIS IS NEVER FOLDED. Its record exists (an empty, chain-derived payload at
        // position 0) but it contributes NO leaves and NO accumulator step — folding it here is what put
        // 256 phantom leaves under the frontier and wedged the first real record on every persist-enabled
        // boot (`[fold-order] ordinal 1 would append at leaf 256 but its ordinal places it at 0`,
        // measured by `item9_measurement_leaf_law_on_a_had_false_boot`). Belt for every future caller:
        // genesis answers "in place at 0" and the spine is untouched.
        if self
            .relay
            .dag()
            .genesis()
            .map(|g| Self::da_record_id_for_block(&g, 0))
            == Some(seq)
        {
            return Some(0);
        }
        let reals = self.da_load(seq)?;
        let addr = seq;
        // The DAG's position is the authority. A row that disagrees came from a peer's page or from this
        // node's own pre-derivation history: it is dropped, never allowed to move the record.
        let placed = match self.da_ord_mem.get(&addr).copied() {
            Some(existing) if existing == dag_ordinal => Some(existing),
            Some(existing) => {
                self.da_ord_rev_mem.remove(&existing);
                self.da_ord_mem.remove(&addr);
                self.da_leafstart_mem.remove(&addr);
                self.note_row_hint_mismatch(existing, addr);
                None
            }
            None => None,
        };
        // ⛔⛔⛔ NOTHING COMMITS UNTIL THE POSITION CHECK BELOW PASSES. The row store, the other-claim
        // eviction and the `served_seq` watermark all used to run HERE — before the append-position
        // check — so a REFUSED fold left a row + watermark behind: `block_record_folded` then read the
        // refused block as folded (`o < served_seq`), `fold_canonical_records` skipped it via `continue`
        // WITHOUT advancing `next_ord`, the next block inherited its ordinal, and the whole chain
        // numbered one-apart with the fork-front block rowless — MEASURED (canonical rewind pin,
        // 2026-09-05): final rows (b0, None, Some(5)), (b1, Some(5), Some(6)), … A refused fold must
        // leave NO trace, so the retry re-folds the SAME block at the SAME ordinal once the record
        // below it lands. The commits now sit AFTER the check.
        let append_ordinal = match placed {
            Some(existing) => existing,
            None => dag_ordinal,
        };
        // The frontier has NOT yet been appended for this record (that happens in the note loop below), so its
        // current count IS this record's first leaf index. Captured here, where it is exact and free.
        // The leaf index is where the CHAIN'S OWN accumulator stands — also a function of the chain, and the
        // only one that is exact: genesis holds ordinal 0 and contributes NO leaves, so a record at ordinal
        // k occupies leaves [(k-1)·256, k·256). MEASURED 2026-09-04: deriving it as ordinal × 256 instead
        // put every append one record past the frontier's real end, the accumulator refused, and a
        // re-anchored node folded NOTHING (two adopt pins went all-`None`).
        // ⛔⛔⛔ A RECORD MAY ONLY APPEND WHERE ITS ORDINAL SAYS IT BELONGS.
        //
        // The frontier is an MMR: it appends at its end, in the order this node happened to fold. The
        // ordinal says where the leaves belong. When those two disagree the append still SUCCEEDS and the
        // node ends with a spine root no other node can reach — same records, same ordinals, different
        // root, and nothing anywhere says so.
        //
        // MEASURED 2026-09-04, `fold_schedule_fuzz::a_random_schedule_of_produce_deliver_restart_and_jump`
        // seed 5: "party 2 spine root differs from party 0" with every per-block ordinal in agreement. The
        // two parties folded the same set in different orders after a restart, and the MMR remembered the
        // order.
        //
        // So the position is CHECKED against the rule the comment below already states, and a record that
        // would land out of place is REFUSED. The caller (`fold_canonical_records`) treats `None` as "want
        // this record and stop", so the node waits for the ordinal below it and then folds in order —
        // which is the outcome, rather than a divergence it can never detect or heal.
        if placed.is_none() {
            let expect = append_ordinal
                .saturating_sub(1)
                .saturating_mul(crate::cover::BLOCK_FIXED_NOTE_COUNT as u64);
            if self.spend_frontier.count() != expect {
                static OUT_OF_ORDER: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                if OUT_OF_ORDER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 64 == 0 {
                    eprintln!(
                        "[fold-order] ⛔ ordinal {append_ordinal} would append at leaf {} but its ordinal \
                         places it at {expect} — folding it here would give this node a spine root no peer \
                         can reach. Refused; the record below it is what this node is waiting for.",
                        self.spend_frontier.count()
                    ); // DIGITAL-CASH-PRIVACY-REVIEWED: ordinals and leaf positions only; no tag, amount, key or owner.
                }
                return None;
            }
        }
        // ⛔⛔⛔ SEAL BEFORE ANY COLD PRUNE CAN TOUCH THE SPAN — ORDER IS LOAD-BEARING (2026-09-06).
        //
        // `da_store_ordinal` below runs the writer-side cold prune for `dag_ordinal − DA_LADDER_SPAN`,
        // and at a span boundary that is exactly the PREVIOUS span's rung row — whose bytes the seal
        // of that span still needs (a span's roots are DERIVED from its records; no per-item file).
        // With the seal placed after the store, the prune dropped the rung's bytes first and the seal
        // failed forever after span 0: MEASURED 2026-09-06 (no-growth pin run, this tree):
        //     [ladder] ⛔ span 1 CANNOT seal: no root derivable at ordinal 4096
        //     [ladder] ⛔ span 2 CANNOT seal: no root derivable at ordinal 8192
        // — each at the fold of the NEXT boundary (8192 / 12288), where the store's prune released
        // ordinal 4096 / 8192 before the seal ran. Sealing first, the blob captures every root while
        // the rows are all still held, and the prune (and the seal's own release sweep) then release
        // bytes whose roots the blob provably carries. cons: none — the same calls, reordered.
        self.seal_ladder_span_if_completed(append_ordinal);
        // The position is proven — NOW commit (see the NOTHING-COMMITS note above the check).
        if placed.is_none() {
            // Another record sitting at this position lost its claim to the DAG's answer.
            if let Some(other) = self.da_ord_rev_mem.get(&dag_ordinal).copied() {
                if other != addr {
                    self.da_ord_rev_mem.remove(&dag_ordinal);
                    self.da_ord_mem.remove(&other);
                    self.da_leafstart_mem.remove(&other);
                    self.note_row_hint_mismatch(dag_ordinal, other);
                }
            }
            self.da_store_ordinal(addr, dag_ordinal);
        }
        // A cached high-water mark for the spine's leaf count — never an allocator.
        self.served_seq = self.served_seq.max(append_ordinal.saturating_add(1));
        // PHASE 2: one cold ordinal leaves the open ladder span as each new one enters — O(1) per
        // block, every per-ordinal row bounded by DA_LADDER_SPAN by construction. (An earlier
        // unbounded block-door byte drop was reverted — in-span records ARE design-load-bearing for
        // the climb/copath/ordinal-agreement; the ladder span is exactly the bound that keeps those
        // promises while ending the growth. The SEAL now runs above, before any prune — see the
        // order note there.)
        if let Some(cold) = append_ordinal.checked_sub(Self::DA_LADDER_SPAN) {
            self.prune_cold_ordinal_rows(cold);
        }
        let leaf_start = match placed {
            Some(existing) => existing
                .saturating_sub(1)
                .saturating_mul(crate::cover::BLOCK_FIXED_NOTE_COUNT as u64),
            None => self.spend_frontier.count(),
        };
        self.da_leafstart_mem.insert(addr, leaf_start);
        // ⭐ ADVANCE THE SERVED-PREFIX ACCUMULATOR HERE — where the append ordinal is claimed.
        //
        // A spender folds the roots `/membership_roots` serves, one per ordinal, so this running fold is the
        // endpoint its carrier names. It MUST advance exactly as often as `served_seq` does.
        //
        // ⚠️ TWO EARLIER PLACEMENTS BOTH FAILED SILENTLY, and only a live four-process send showed it. Folding
        // it after `da_store` (150 lines below) put it past early returns, so it advanced a handful of times
        // against 176 records — measured on the wire as `served_prefix` two orders of magnitude short of the
        // value every wallet was folding. Folding it before the record existed made `da_block_leaves` answer
        // None and advance nothing at all. The root is therefore derived from the notes IN HAND, through the
        // SAME shared assembly the serve uses — no re-read, no ordering hazard, nothing to skip.
        // ⛔⛔⛔ THE PREPEND MUST RUN BEFORE THE ROOT IS FOLDED. IT DID NOT, AND I CAUSED THAT.
        //
        // I added the seed note AFTER `served_root` was computed, so the accumulator folded a root derived
        // from the EMPTY note set while `/membership_roots` later RE-derived that block's root from the
        // STORED record — which by then held the seed note. Two different roots for one block, so a spender
        // folding the served set landed on an accumulator this node had never held.
        //
        // MEASURED 2026-08-11 on the real submit route, only once the refusal was made to discriminate:
        //   [membership] refused. … named_indexed=false named_equals_our_served_acc=false
        // The second flag is what proves it — not an index off-by-one, a genuinely different fold.
        // ONE source of `reals`, for BOTH the fold and the store, in that order.
        // WRITE THE ROOT DOWN — it is already computed here, and recomputing it at SERVE time meant
        // regenerating 256 leaves and re-folding them for EVERY root in a page (up to 4096), on the wallet's
        // carrier-build path. Measured: `/membership_roots` timed out at 5s under load. One indexed read
        // replaces that. ([[feedback_no_growth_any_axis]])
        // ⛔⛔⛔ KEY THE ROOT BY THE DA ADDRESS — NEVER BY A PER-NODE COUNTER, AND NEVER BY BOTH.
        //
        // `append_ordinal` is the order THIS node happened to write records in, so it names a DIFFERENT block
        // on every node. The account bucket hands wallets the BLOCK-DERIVED record address, which is identical
        // everywhere, and `accept_fetched_record` fail-closes when it holds no root for the address it was
        // handed. With the root filed under the local counter it refused every by-id fetch: MEASURED, node A
        // asked 1,975 times, node B (which HOLDS the record) served 2,032 answers, and A still ended with
        // `notes:[], pending:true` — the wallet read 0.0/0 while the money sat one hop away.
        //
        // Writing it under BOTH keys would be the same per-node defect wearing a second hat: two authorities
        // for one fact, and the local one still wrong. The DA address is the single source — it is a pure
        // function of the block, so every node derives the identical key and one lookup answers on all of
        // them. Callers holding a local ordinal resolve it through `da_addr_at_ordinal` first.
        // Same rule as the accumulator above: the write key matches the read key, which is the append ordinal.
        // ...and climb the subtree ladder this ordinal completes, so a note's UPPER copath is 24 indexed
        // reads forever instead of a re-fold over every root the chain has produced. Must follow the block
        // -root write: the ladder's level-0 input IS that root.
        // ⛔⛔⛔ ORDERING — THE LADDER USED TO CLIMB BEFORE THE RECORD IT READS WAS WRITTEN.
        //
        // `da_store(seq, &reals)` — the write that makes `da_record_notes` answer — runs LATER in this same
        // graft. The climb calls `da_block_root_at_ordinal`, which reads exactly that record, so it found
        // nothing and returned on the spot. Nothing ever retries a completed-subtree climb, so EVERY block
        // left a permanent hole and every copath crossing that span refused forever.
        //
        // MEASURED 2026-07-31 on the live daemon: `[ladder-hole] block 75578 ... address_mapping=present
        // notes_at_address=None notes_at_ordinal=None` — the address mapping (written at line ~2219) was
        // there, so the coordinate spaces were never the problem; the record simply did not exist yet.
        // That is why the send failed identically whether the peer answered or not: the local ladder was
        // empty by construction, and the fetch was chasing a value this node should have had all along.
        //
        // ⚠️ MEASURED AFTER LANDING THIS: ordering was NOT the whole fix. 113 `[ladder-hole]` lines still
        // fired with `notes_at_address=None`, so writing earlier did not make the read answer. The write is
        // kept (the ladder genuinely must not precede the record) but the cause is elsewhere: either `reals`
        // is empty here, or `seq` is not the key `da_record_notes` reads. Probe both rather than guess again.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a note COUNT and a record key that /get_info already exposes as
        // served_seq — never a commitment, amount, key or owner. Fires only when the write is EMPTY (a
        // genuine anomaly that guarantees a ladder hole), never on the healthy path.
        // ⛔⛔⛔ THE SEED-NOTE PREPEND, FINALLY WRITTEN. IT WAS SPECIFIED IN THE COMMENT ABOVE AND SKIPPED.
        //
        // An EMPTY `reals` writes an empty record, so `da_record_notes` answers None for that block FOREVER.
        // The completed-subtree climb then abandons at that span and every copath crossing it refuses —
        // permanently, for every note on either side of the hole. That is fund loss, and it is not an age
        // bound: the note is refused because of what a NEIGHBOURING block did, not because of how old it is.
        //
        // MEASURED 2026-08-11 in `a_stale_carrier_settles_through_the_real_submit_route…`: every block in the
        // test logged `writing ZERO real note(s)`, `/note_copath` answered an empty `block_root_hex`, and the
        // membership carrier could not be built — the exact chain from an idle block to a failing send.
        //
        // ONE DETERMINISTIC SEED NOTE, byte-indistinguishable from a real one, so `reals` is never empty:
        //   * derived from the node's persisted per-chain DA secret + this record's key, so it REGENERATES
        //     byte-identically forever from O(1) state — nothing is stored per idle block, at any height;
        //   * secret-seeded, never an index function, so an observer cannot recompute the fill and learn the
        //     block was idle. That is the metadata leak the cover shape exists to close.
        // It is PREPENDED, so a real note's slot within the record shifts by exactly one on both the write and
        // the read path — `da_block_leaves` already regenerates from the record it finds, so the two agree by
        // construction rather than by a second constant that could drift.
        let served_root = {
            let concat: Vec<u8> = reals.iter().flat_map(|n| n.iter().copied()).collect();
            Self::fold_leaves_to_root(&Self::block_leaves_from_notes(&concat, seq, &self.cover_key_of(seq)))
        };
        // RESUME, NEVER RESTART. `served_membership_acc` is in-memory, and a DSYNC adopt or a restore
        // replaces the node's in-memory state while the DA records stay on disk. When that happens the
        // running fold silently begins again at zero, so every later prefix is wrong and every accumulator a
        // wallet can build is one this node has no memory of — measured live as `folds=1 records=176`, with
        // every send refused and nothing visibly broken.
        //
        // Recover the previous prefix in ONE indexed read. Replaying the roots to rebuild it would be
        // O(chain) and is banned; this costs the same at any height. ([[feedback_no_windows_no_caps_cardinal]])
        // ⭐ DB-402 (lane stable 2026-10-30): the step always extends the CHAIN'S accumulator at the ordinal below
        // this record — the index entry, when held — never "whatever this process folded last". It fired only while
        // a per-process fold counter read 0 (just after an adopt or a restore); that counter is gone (not a function
        // of the chain: an adopter counted from its adopt, a fold reorg left it one past a replayer's value). A
        // re-record of a held ordinal now re-folds from the same base and lands on the same value.
        if append_ordinal > 0 {
            if let Some(prev) = self.da_membership_acc_at_ordinal(append_ordinal - 1) {
                self.served_membership_acc = prev;
            }
        }
        // ⚠️ A FOLD-ONCE GUARD WAS TRIED HERE AND MADE THE MEASUREMENT WORSE — REVERTED, NOT TUNED.
        //
        // The reasoning still stands: `note_membership_step_new_acc` is a COMMUTATIVE SUM over the set of
        // block roots, so folding one block twice is not a no-op, and this function genuinely does run twice
        // for a producer's own block (produce, then graft). The `[fold-once]` line fired 15 times in one run,
        // so the double fold is REAL and is still unfixed.
        //
        // What failed was the TEST for "already folded": `da_record_ordinal(addr).is_some()` is already true
        // on the FIRST write, because the address is registered earlier in this same function. So the guard
        // skipped every fold and the gate went from `folds=10 records=10` to `folds=0 records=10` — strictly
        // worse. A worse number is a stop signal, so the guard is removed rather than adjusted; the correct
        // discriminator is "has THIS RECORD's root already been added to the sum", which needs a test that
        // does not exist yet.
        // ⭐ NAME THE (ordinal, address) PAIR ON EVERY FOLD — the datum the double-fold fix needs.
        //
        // The double fold is confirmed (a `[fold-once]` probe fired 15 times in one run), and it is why a
        // wallet's honest sum can never match this node's: the accumulator is a commutative SUM, so adding
        // one block's root twice lands on a value no other node holds. What is MISSING is a sound test for
        // "this record's root is already a summand". `da_record_ordinal(addr)` is not it — it is already true
        // on the first write, and using it took the gate from `folds=10 records=10` to `folds=0`.
        //
        // The key that would work is the canonical ADDRESS, but the acc index is written by `append_ordinal`
        // and read the same way, and the comment at `da_store_membership_acc` records that re-keying ONE side
        // has already corrupted live datadirs. So the fix must change write and read together, with the
        // datadirs rebuilt — and it needs to see which (ordinal, address) pairs actually repeat.
        //
        // This line is that evidence: an ADDRESS appearing under two ordinals is the double fold, in the open.
        // Ordinals and a record address only — chain-public via /get_info, never a note, amount, key or owner.
        // ⛔ THE NODE TAG IS NOT DECORATION — WITHOUT IT I MISREAD THIS LINE.
        //
        // The first version printed only `ordinal` and `addr`, and the route test runs TWO nodes whose stderr
        // interleaves. I read `addr=X` appearing three times as "one node folded it three times" and was
        // about to build a de-duplication fix on that. Two nodes each folding the same block ONCE is the
        // CORRECT behaviour and looks identical without a tag. Name the emitter, or the log invites the
        // wrong fix — which is exactly how the `folds=10 -> folds=0` regression happened this session.
        //
        // The tag is two bytes of this node's own DA secret: node-local, never chain data, never a note,
        // amount, key or owner — it only separates two processes in one interleaved log.
        let _node_tag = {
            let s = self.da_secret_value();
            u16::from_le_bytes([s[0], s[1]])
        };
        // ⛔⛔⛔ FOLD A RECORD'S ROOT ONCE. THE ACCUMULATOR IS A COMMUTATIVE SUM, WHICH IS NOT IDEMPOTENT.
        //
        // MEASURED 2026-08-11, only after the provenance line gained a NODE TAG (without it two nodes each
        // folding once is indistinguishable from one node folding twice, and I nearly built the wrong fix on
        // exactly that misreading):
        //     node=35e8  ordinals 0..4, five DISTINCT addresses, one fold each     <- correct
        //     node=0336  ordinal=8 addr=11978670698004492
        //     node=0336  ordinal=9 addr=11978670698004492                          <- SAME address, twice
        // A node that produces a block and later ingests it back records it twice, and each write folded its
        // root again. The sum then double-counts that root, so this node's accumulator is a value no wallet
        // can reach — a wallet folds each root `/membership_roots` serves exactly ONCE. That is
        // `named_indexed=false`, and it refuses a spend whose proof is perfectly valid.
        //
        // THE DISCRIMINATOR IS THE RECORD STORE, not the address bookkeeping. My first attempt asked
        // `da_record_ordinal(addr)`, which is already true on the FIRST write because the address is
        // registered earlier in this same function — it skipped every fold and took the gate from
        // `folds=10 records=10` to `folds=0`. `da_record_notes(addr)` answers about the RECORD BYTES, which
        // exist only if this node already wrote (and therefore already folded) this block.
        // Folded unconditionally, because every call that reaches here is a first record of its block.
        //
        // A skip-when-already-folded branch lived here. It was a PATCH: it left the duplicate write in place
        // and taught this one consumer to tolerate it, so the next consumer would have needed the same
        // lesson. The duplicate is now deleted at the top of this function — MEASURED as an empty 0-byte
        // re-record of an address already holding 1,153 bytes, five times in one run, and `redundant=true`
        // reached this site 0 times afterwards. With the cause gone the branch was dead code, so it is gone
        // too. user 2026-08-12: "why not simply make the records non redundant 100% of the time?"
        // The TIP TRANSITION a carrier names — `(prev_acc, block_root, acc)` — is published HERE, at the one
        // place the accumulator actually advances. It used to be set by `fold_block_into_membership_acc`
        // from a SECOND accumulator, so the transition a wallet was told to name belonged to a different
        // series than the one the gate indexes.
        self.membership_tip_prev = self.served_membership_acc;
        self.membership_tip_root = served_root;
        self.served_membership_acc =
            usdm_decider::note_membership_air::note_membership_step_new_acc(
                self.served_membership_acc,
                served_root,
            );
        let served_acc = self.served_membership_acc;
        // ⛔⛔⛔ SAME SINGLE-AUTHORITY RULE AS THE BLOCK ROOT — key the committed accumulator by the DA
        // ADDRESS, never by this node's append counter. `append_ordinal` is the order THIS node happened to
        // write records in; the account bucket hands wallets the block-derived address, and a node verifying
        // a fetched record needs BOTH sides of the fold AT THAT ADDRESS. Keyed by the local counter it held
        // neither, so it refused correct records: MEASURED, `REFUSED 256 note(s): the folded root does not
        // carry the committed membership acc forward`, 47 times, on valid data that had folded correctly.
        // The address is a pure function of the block, so every node derives the identical key.
        // ⛔⛔⛔ THE WRITE KEY MUST MATCH THE READ KEY. I changed this to `exact_addr` (the canonical record
        // address) while the reader stayed on `append_ordinal`, so every accumulator written afterwards was
        // filed where nothing ever looks. Both indexes are ON DISK, so the mismatch persisted into the datadirs
        // and the spend gate began refusing every send: "the carried nullifier-absence witness did not verify
        // against this node's accumulator", with the payer holding 3.55 / 12 notes. Reverting the READ alone
        // could not undo it — the damage was in what had already been written.
        //
        // If this index is ever re-keyed, the write and the read change in the SAME edit, and the existing
        // datadirs are rebuilt. Never one side.
        // ⭐ THE SERIES COMPARISON. user 2026-08-12: "find the remaining cause of named_indexed=false by
        // comparing the node's stored acc-per-ordinal series against a wallet's fold of /membership_roots".
        //
        // This prints the node's own series: after folding the root at THIS ordinal, the accumulator is X.
        // A wallet folding `/membership_roots` from `genesis_acc_hex` must walk the identical sequence. The
        // first ordinal where the two differ is the defect — and printing the node's side is the half that
        // was never visible, so every previous diagnosis of `named_indexed=false` was inference.
        // Accumulators and ordinals only, both chain-public via /get_membership_acc and /membership_roots.
        self.da_store_membership_acc(append_ordinal, served_acc);
        // §20.2: the row keeps its key (a fetched record's, or this producer's draw held beside the body)
        let key = self.da_cover_key(seq).unwrap_or_else(|| crate::cover::idle_cover_key(seq));
        self.da_store(seq, &reals, key);
        // DIGITAL-CASH-PRIVACY-REVIEWED: emits ORDINAL COUNTS only — the same chain-progress figures
        // /get_info already serves — never a note, leaf, amount, key or owner. Counts are the only way to
        // tell "the fold ran once" from "the fold ran for every record", which is the difference between a
        // gate that refuses every send and one that works.
        // SELF-CHECK THE ROUND TRIP. Writing the index and reading it back are different code paths (files
        // under the data directory vs an in-memory mirror), and a write that silently fails leaves the gate
        // refusing every spend with nothing to see. Verify it on the spot rather than inferring it.
        if append_ordinal % 32 == 0 {
            let back = self.da_ordinal_at_membership_acc(served_acc);
            eprintln!(
                "[servedacc] ordinal {append_ordinal}; served_seq {}; index read-back {}",
                self.served_seq,
                if back.is_some() { "OK" } else { "FAILED" }
            );
        }
        // ⛔⛔⛔ INDEX THE COMMITMENTS THE FRONTIER ACTUALLY FOLDS — NOT THE RAW PAYLOAD ORDER.
        //
        // This indexed `reals` directly, i.e. the notes as they arrived in the payload. But the frontier folds
        // `assemble_fixed_note_payload_det(reals, seq)`, which PERMUTES every real note to a pseudo-random
        // slot among the 256 (that permutation is what stops an observer counting the real notes). So the
        // address filed here described a coordinate the tree never used.
        //
        // MEASURED on the live peered pair: the payer's node files its targets fine
        // (`[account-target] recorded; 2 target(s) now pending` -> `[produce] attached 2500 byte(s)` ->
        // `[bucket-push] offering 2 freshly filed bucket(s)`), the recipient's node receives the blocks, and
        // yet logs `[bucket-file] block touched 0 bucket(s)` on EVERY one. `record_account_target` needs
        // `da_seq_at_note_cm(&note_cm)` to resolve before it can seal the recipient's entry, so an index built
        // on the wrong ordering means the note settles on chain and its owner can never find it — and the
        // recipient's bucket read degrades to 9,173ms against the payer's 1ms.
        //
        // The assembly happens below (it needs `seq`), so index from ITS output: every commitment, at the slot
        // the tree gave it. Cover slots are indexed too and that is correct — they are real leaves under the
        // root, and a wallet only ever asks about a cm it owns.
        //
        // Deliberately AFTER `assemble_fixed_note_payload_det`, which is why this block moved down.
        let reals_concat: Vec<u8> = reals.iter().flat_map(|n| n.iter().copied()).collect();
        if placed.is_none() {
            let fixed = crate::cover::assemble_fixed_note_payload(&reals_concat, seq, &self.cover_key_of(seq));
            let mut foff = 0usize;
            // DB-223 Q2: the windows at level ≥ 8 this record completes, captured as the walk merges them — BOTH
            // children of each merge (§9 item 5): the right (odd) one a refreshing wallet needs, and the left (even)
            // one a wallet restoring from its seed needs, having never seen the peaks at its note's arrival.
            let mut completed: Vec<(u8, u64, crate::spend_frontier::Digest4)> = Vec::new();
            while foff + crate::cover::PQ_NOTE_BYTES <= fixed.len() {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&fixed[foff..foff + 32]);
                let after = self.spend_frontier.count().saturating_add(1);
                self.spend_frontier.append_with(crate::spend_frontier::note_leaf_of(&cm), |level, left, right| {
                    completed.extend(crate::window_index::merged_windows(level, after, left, right).into_iter().flatten());
                });
                foff += crate::cover::PQ_NOTE_BYTES;
            }
            if self.completed_windows.len() >= self.anchor_ring_len() {
                self.completed_windows.pop_front();
            }
            // DB-223 Q2 catch-up: the same windows, kept by position in the index this node holds.
            for (level, window, root) in &completed {
                self.window_index.record(usize::from(*level), *window, *root);
            }
            self.completed_windows.push_back((append_ordinal, completed));
        }
        let anchor = self.spend_frontier.root();
        let anchor_idx = self.root_history.count(); // leaf index this anchor lands at == this block's seq
        // ⛔ G2a: ONE anchor per record the frontier folded — a record already in place (`placed`) appended no leaves, so it
        // appends no anchor (the law `root_history.count() == folded records` the canonical fold pins assert).
        if placed.is_none() {
            self.root_history.append(anchor);
        }
        // ⛔⛔⛔ THE ANCHOR RELAY IS DELETED — IT WAS A LITERAL WINDOW AND NOTHING EVER READ IT.
        //
        // user 2026-07-29: *"Make monerousd one root and validity is a copath against that root just like
        // mina."* / *"window logic is banned."*
        //
        // `recent_root_history` retained 8,192 per-block anchors (256 KiB) behind a front-evicting bound named
        // RECENT_ROOT_HISTORY_WINDOW — a per-item store AND a reach bound, both banned, and grep found no
        // reader anywhere: it was pushed and evicted, never served, never consulted. It existed to answer
        // "what was the receipt anchor at block N?", which is the same when/where question the one state root
        // retires: a note's validity is a copath to the notes half of `state_root`, at any age, with nothing
        // retained per block. `root_history` itself stays — it is O(DEPTH) peaks folded into the WHIR decider,
        // not a per-item list.
        let _ = anchor_idx;
        // Serve-time regeneration keeps the shape no-growth: the 255 cover slots are NEVER stored, they are
        // rebuilt from the record at serve. NOTHING is windowed or evicted — a note must never age out, and
        // the wallet reads the DA layer at ANY height rather than a tip-anchored cache.
        // ⭐⭐ DB-407 — A NOTE IS FILED WHERE THE CANONICAL ORDER FIRST CARRIES IT, never where it ARRIVED first.
        //
        // On a DAG of width > 1 one pooled transaction is routinely carried by two parallel blocks. The fold keeps the
        // copy that comes first in the canonical order and strips the later copy's outputs from ITS record (DB-358 —
        // borrowed: Kaspa's mergeset accepts a transaction once, a later duplicate is ignored). The `cm → record` index
        // was filed by ARRIVAL (the record-write's first-writer-while-on-chain rule), so a node that grafted the later
        // copy first named the DUPLICATE's record for that note. Every membership carrier built through
        // `/note_ordinal_by_cm` before the fold then bound the duplicate's pre-strip root, and the strip's retraction
        // left the note with NO filing at all, so no later rebuild could find the record that does carry it.
        // ROOT-LAYER: this is the fold step that PRODUCES the canonical record, so the filing is produced here, in the
        //   one order every node shares: a real note left in this row after the strip is filed at this record unless an
        //   EARLIER folded record already carries it (the first canonical carrier wins, exactly the strip's verdict).
        // MEASURED: sim-20261007-011239 T2 — the maker's lot cut rode two blocks; node 1 answered the fill "not folded"
        //   (409) five times with the bind's root MATCHING, then `[respend] ⛔ DB-358: 2 output(s) … revoked` and 422
        //   MEMBERSHIP_REFUSED: `[record-forensic] maker record …` held 1 note on all three nodes, the cut's 2 stripped.
        // MUST-STAY-GREEN: DB-249b's re-filing pins, DB-377's strip-retraction pin, db274 strip-rewind pins.
        // cons: none — one HashMap lookup per real note of the folded row (a few; ≤ BLOCK_FIXED_NOTE_COUNT) plus one
        //   held-block probe when the entry names another record; no new state, no term in height, blocks or notes.
        if let Some(row) = self.da_mem.get(&seq) {
            let idle_seed = crate::cover::public_idle_seed_note(seq);
            let cms: Vec<[u8; 32]> = row
                .0
                .iter()
                .filter(|n| n.len() >= 32 && n[..] != idle_seed[..])
                .map(|n| {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&n[..32]);
                    cm
                })
                .collect();
            for cm in cms {
                let earlier_canonical = self.note_target_addr.get(&cm).copied().is_some_and(|old| {
                    old == seq || self.block_for_record_addr(old).is_some_and(|b| self.block_record_folded(&b))
                });
                if !earlier_canonical {
                    self.note_target_addr.insert(cm, seq);
                }
            }
        }
        // ⛔⛔ J19 (lane speed5, 2026-11-18, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J19) — A ROW'S PROVENANCE IS A FUNCTION OF THE CHAIN.
        // A provisional row (bytes a peer paged in) whose block header this node holds is bound here by the fetch door's own
        // header-root check (`accept_fetched_record_judged`'s held-header arm: the header, authenticated at graft, binds
        // `output_notes_root`). That arm ran only for a record with NO ordinal row, so a row whose ordinal came first by the
        // sidecar page stayed provisional for ever on the joiner while every replayer held it bound — MEASURED (replica
        // census, main 624311e7 + F6): `da_mem` DIFFERS at record 50034961733658040 (ordinal 51, block 6e091f16), "chain-bound
        // true" on both seeds and "false" on the joiner, the same 260 items otherwise.
        // AI RESISTANT: (a) — the header's PoW and the notes-root hash decide; the row's own bytes are only hashed, never
        //   trusted, so a forged row still reads provisional.
        // SCALE: one hash of one record's real notes per folded provisional row; none on a bound row; nothing grows.
        // cons: one notes-root hash per provisional row at its fold (the fetch door pays the same hash).
        if self.da_mem.get(&seq).is_some_and(|row| !row.2) {
            let root = self
                .block_for_record_addr(seq)
                .and_then(|b| self.relay.dag().get(&b).map(|n| n.header.output_notes_root))
                .filter(|r| *r != Hash32::hash(&[]));
            if let (Some(root), Some(reals)) = (root, self.da_record_reals(seq)) {
                if crate::block::da_notes_root_of(&reals.concat()) == root {
                    self.da_mark_chain_bound(seq);
                }
            }
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: a record address and its ordinal — chain-public coordinates only.
        eprintln!("[record-fold] seq={seq} ordinal={append_ordinal}");
        // ⛔ A PER-FOLD BYTE DROP WAS TRIED HERE AND IS REMOVED — MEASURED BREAKING THE SEAL, not
        // reasoned away: with `drop_record_bytes_if_unreferenced(seq)` at this line, the very first
        // span could never seal — `[ladder] ⛔ span 0 CANNOT seal: no root derivable at ordinal 1 —
        // the blob is not stored` (2026-09-06, no-growth pin run) — because a span's seal DERIVES each
        // ordinal's root from the record's bytes (`da_block_root_at_ordinal_derive`: "derive the root
        // from the record", the no-per-item-file law), and a multi-note row's bytes are its only local
        // source. This is the same lesson as the reverted block-door byte drop this function's ladder
        // comment records: in-OPEN-SPAN rows are design-load-bearing. The correct release point is the
        // SEAL itself (`seal_ladder_span_if_completed`), where the span's roots enter the sealed blob
        // and the bytes provably stop being the root's only source — the release now lives there.
        Some(append_ordinal)
    }

    /// Is `anchor` on this node's own selected chain at or below its fold cursor? (A walk of at most
    /// cursor-score − anchor-score steps.)
    pub(super) fn anchor_on_our_chain(&self, anchor: &crate::block::BlockId, anchor_score: u64) -> bool {
        let dag = self.relay.dag();
        let mut cur = self.fold_chain_tip.or_else(|| dag.selected_tip());
        while let Some(c) = cur {
            if c == *anchor {
                return true;
            }
            match dag.get(&c) {
                Some(node) => {
                    if node.blue_score < anchor_score {
                        return false;
                    }
                    cur = node.selected_parent;
                }
                None => return false,
            }
        }
        false
    }

    /// The fold is stopped awaiting a certified bundle (a reorg below its fork point, or a base it cannot derive): the one
    /// state a node inside the catch-up depth still needs a bundle for. Read by the runtime's certified ask.
    #[must_use]
    pub fn fold_awaits_reanchor(&self) -> bool {
        self.spine_stale
    }

    pub fn fold_canonical_records(&mut self) -> usize {
        let folded = self.fold_canonical_records_inner();
        // ⭐ G2b: the landing context is a fact about a step IN PROGRESS, never about this node between steps (the inner
        // fold returns from many wait points); and the votes deferred below the cursor are judged now that it moved.
        self.fold_landing_blue = None;
        self.judge_deferred_votes();
        self.rebuild_adopted_stream_windows(); // DB-471: an adopted node's stream reaches as far back as a replayer's
        self.complete_adopted_prefix(); // DB-471: and its index rows below the base, once the record lane delivered them
        folded
    }

    /// One readout line whenever the fold root's place changes: how many levels below the tip it stands and what set it
    /// (seen finality, or the seat-activation distance). Process-local logging only.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a public level count and a flag; no block id, note, key or amount.
    fn note_fold_root(&self, depth: u64, by_finality: bool) {
        static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(u64::MAX);
        let now = depth.saturating_mul(2) + u64::from(by_finality);
        if LAST.swap(now, std::sync::atomic::Ordering::Relaxed) != now {
            eprintln!(
                "[fold-final] the fold root stands {depth} level(s) below the tip, set by {}",
                if by_finality { "the block this node has seen final" } else { "the depth rule (nothing final within the seat-activation delay)" }
            );
        }
    }

    pub(super) fn fold_canonical_records_inner(&mut self) -> usize {
        self.retire_pruned_anchor();
        let Some(tip) = self.selected_tip() else {
            return 0;
        };
        // ⭐ A BLOCK SETTLES WHEN IT IS FINAL (`Dag::fold_root_by_finality`, spec §11.13; lane goodshalt 2026-11-15): the root
        // is the highest block of this tip's selected chain this node has SEEN final (carried or verified on receipt,
        // `user_final_block`) while that block is at most `FINALITY_SEAT_ACTIVATION_DELAY` levels below the tip; with nothing
        // final, or finality further behind, it is the depth rule's root `fold_depth_at` levels below the tip, as before
        // (SAFE-FALLBACK: settlement never waits on a committee). The fork choice floors at the final block, so nothing this
        // pass folds under it can be rewound. MEASURED why (2026-11-15, real nodes): with the depth rule alone every node
        // rewound its fold 35 to 38 times in 40 minutes.
        // CHAIN-OBJECT: what is folded is the chain's blocks in canonical order; the rule decides only how far this pass goes.
        let final_seen = self.user_final_block();
        let depth_rule = self.relay.dag().fold_depth_at(&tip);
        let Some((root, by_finality)) =
            self.relay.dag().fold_root_by_finality(&tip, final_seen, crate::params::FINALITY_SEAT_ACTIVATION_DELAY, depth_rule)
        else {
            return 0;
        };
        let depth = {
            let dag = self.relay.dag();
            let blue = |id: &crate::block::BlockId| dag.get(id).map_or(0, |n| n.blue_score);
            blue(&tip).saturating_sub(blue(&root))
        };
        self.note_fold_root(depth, by_finality);
        let mut cursor_above_root = false;
        let mut at = tip;
        while at != root {
            cursor_above_root |= Some(at) == self.fold_chain_tip;
            match self.relay.dag().get(&at).and_then(|n| n.selected_parent) {
                Some(p) => at = p,
                None => break,
            }
        }
        // SPEED L6: the cursor stands on the selected chain AHEAD of the root — the depth grew by more than the tip
        // advanced. Everything the cursor folded is this chain's own prefix in its canonical order, so there is nothing to
        // fold yet and NOTHING TO UNFOLD: a record never leaves the spine because the depth changed. (A reorg is a tip
        // whose selected chain does not pass through the cursor; the walk above does not meet it and the arms below run.)
        if cursor_above_root {
            return 0;
        }
        // ⛔⛔⛔ THE FOLD ONLY EVER WALKS UP, SO A BLOCK THAT ARRIVES LATE IS SKIPPED FOREVER.
        //
        // The cursor at the fold root means "everything below me is in the spine". A block delivered after
        // the chain block that MERGES it was folded makes that false: it sits in an already-passed merge
        // set, `merge_set_unfolded` is never asked about that chain block again, and the record never gets
        // an ordinal on this node while every peer that saw the block earlier gave it one.
        //
        // MEASURED 2026-09-04, `fold_schedule_fuzz::a_random_schedule_…` seed 5: party 0 holds NO ordinal
        // for block 0 while party 1 has it at ordinal 1, shifting every later record by one — two honest
        // nodes numbering the same chain one apart. This diagnostic fired ~1,150 times in one run: the node
        // KNEW it had unfolded blocks and returned 0 anyway.
        //
        // ⛔ ATTEMPTED AND REVERTED 2026-09-04 UNDER THE WORSE-RESULT RULE — do not re-try it as written.
        // The remedy tried here was `rewind_fold_to_common` to a chain block below the late arrival, so the
        // fold would re-walk the complete merge set (the reorg machinery applied to a completeness event).
        // It made things WORSE: `restarts_interleaved_with_undelivered_blocks…` went from GREEN to RED with
        // parties holding FEWER ordinals than before (`p1@-` where it had folded), because a rewind drops
        // the spine and the re-fold cannot always complete — the node ends up behind where it started.
        //
        // WHAT THE NEXT ATTEMPT SHOULD DO INSTEAD: the ordinal must stop being a function of ARRIVAL. It is
        // currently `next_ord` from this node's own fold walk, so a node that folded on a partial DAG burns
        // in a numbering no later-arriving block can correct. Derive it from the DAG's own order
        // ([[project_second_numbering_removed_dag_position]]) and the late arrival simply gets the number it
        // always had, with no rewind, no eviction and nothing to lose.
        if Some(root) == self.fold_chain_tip {
            if !self.unfolded_blocks.is_empty() {
                // THE PASS HELD WORK AND WILL RETURN 0. Counted here rather than at each of the five
                // `return folded` sites, because this is the one branch that means "the fold has stopped
                // and its own past gives it nothing more to do" — the live 27780 state.
                if self.fold_no_progress_passes == 0 {
                    // J15: the streak's start, on the chain's own length (the A-F96 coordinate)
                    self.fold_progress_since_len =
                        self.relay.dag().selected_tip().and_then(|t| self.relay.dag().get(&t)).map_or(0, |n| n.selected_chain_len);
                }
                self.fold_no_progress_passes = self.fold_no_progress_passes.saturating_add(1);
                static STUCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                if STUCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 16 == 0 {
                    // NAME WHICH CASE THIS IS (MEASURED 2026-10-06: this line read "stuck" through an ordinary depth wait and
                    // cost a diagnosis): blocks ABOVE the root are only waiting for `record_fold_depth` confirmations; a
                    // block BELOW the root's blue score is genuinely stranded under the cursor.
                    let (root_score, below) = {
                        let dag = self.relay.dag();
                        let rs = dag.get(&root).map_or(0, |n| n.blue_score);
                        let below = self
                            .unfolded_blocks
                            .iter()
                            .filter(|b| dag.get(&b.id()).is_some_and(|n| n.blue_score < rs))
                            .count();
                        (rs, below)
                    };
                    if below == 0 {
                        eprintln!(
                            "[fold-depth] the fold is current to its root (blue score {root_score}); {} block(s) above it wait for \
                             their {} confirmations — not stuck (dense counter {})",
                            self.unfolded_blocks.len(),
                            depth,
                            self.served_seq
                        ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts only; no tag, amount, key or owner.
                    } else {
                        eprintln!(
                            "[fold-stuck] the cursor sits at the fold root (blue score {root_score}) with {below} of {} unfolded \
                             block(s) BELOW it and a dense counter of {} — nothing below the cursor is ever revisited",
                            self.unfolded_blocks.len(),
                            self.served_seq
                        ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts only; no tag, amount, key or owner.
                    }
                }
            }
            // ⛔⛔⛔ THE CLAIM THAT USED TO STAND HERE IS FALSE, AND BLUE SCORE COULD NEVER HAVE
            // TESTED IT.
            //
            // It read: "the unfolded buffer holds ONLY blocks at or above the fold root … never a
            // block stranded below it", on the evidence of one in-process case whose print happened
            // to show `min blue_score Some(421) vs root 421`. The live gate FALSIFIES it — n1.log,
            // 2026-09-05, scratch /tmp/musd-ecocheck-D6U9H2:
            //     [fold-stuck-diag] 52 unfolded, 52 in the DAG, min blue_score Some(178) vs root 216
            //     [fold-stuck-diag] 119 unfolded, 119 in the DAG, min blue_score Some(178) vs root 790
            //     [fold-stuck-diag] 119 unfolded, 119 in the DAG, min blue_score Some(178) vs root 921
            // — a straggler set 743 deep that the certified adopt GREW (52 → 87 → 119). The
            // consequence is the run's mutual hole: n1 served `[roots-serve] kind 6 from ordinal 1:
            // 0 of 139` after its restart (139 of 139 before), and `[id-lane] serving by-id: asked 1,
            // hold 0`, so n2's 275 by-id copath wants went unanswered and its own missing_records
            // pinned at 33. A node that holds blocks it can never fold is a node that can never
            // serve them.
            //
            // AND THE COMPARISON WAS NEVER THE QUESTION. Blue score is not ancestry: a side block
            // that forked long ago carries a low blue score and is NOT in the cursor's past — it is
            // an ordinary member waiting for a FUTURE chain block to merge it, which is the healthy
            // steady state this branch sees on every quiet node. The question is ancestry, and the
            // walk that answers it exactly already exists: `chain_block_mergeset(cursor, first_ord)`
            // is past(cursor) ∪ {cursor} minus the POSITION-VERIFIED folded prefix. Run at the
            // cursor with the prefix boundary open (`u64::MAX` — every position-verified row below
            // counts as prefix), it returns EMPTY exactly when the cursor's whole past is folded and
            // verified, and otherwise names precisely the blocks the canonical order places below
            // the cursor that this node never folded. It stops at the boundary, so on a healthy node
            // it is one pop and a return; its cost is O(stranded), never O(DAG).
            //
            // ⛔ AND A STRANDED BLOCK IS NOT PLACEABLE, EVEN UNDER THE DERIVED ORDINAL (C1).
            // C1 made a record's position a function of the DAG rather than of arrival — the fix the
            // 2026-09-04 note above hoped for — but the position it derives for a late arrival is
            // INSIDE a batch whose records are already materialised in the spine. Taking it would
            // mean inserting leaves beneath ones already appended, which is precisely the
            // `rewind_fold_to_common` remedy attempted and REVERTED twice (2026-09-04: the fuzz pin
            // went green→red with parties holding FEWER ordinals than before, because a rewind drops
            // the spine and the re-fold cannot always complete; 2026-09-05: the second attempt
            // regressed 8 fold pins). So it fails CLOSED onto the machinery that already exists for
            // exactly this: `mark_spine_stale` stops the fold, `spine_needs_reanchor` fires the
            // certified-bundle ask every tick, and the adopt's spine arm re-anchors the numbering
            // from a peer that holds the DAG. That is the only sound repair, and it is a repair —
            // where before the node kept a numbering it knew was short and kept serving from it.
            //
            // ROOT-LAYER: this is the one branch that observes "the fold has stopped and cannot
            // resume", so it is where the two cases are told apart. A detector anywhere else would
            // be reading a state this branch produces.
            // MUST-STAY-GREEN: nothing stales while the stranded set is empty, which is the healthy
            // case and (by the in-process measurements above) the common one; a member that is
            // merely NOT HELD is the ordinary C1 wait and is named to the by-id block lane instead
            // of staling anything.
            // cons: one bounded mergeset walk per stuck pass — O(stranded), one pop on a healthy
            // node — and no state.
            if !self.unfolded_blocks.is_empty() {
                let stranded = match self.chain_block_mergeset(&root, u64::MAX) {
                    Ok(batch) => {
                        // ⛔ NOTHING IS MISSING, SO NOTHING IS BEING WAITED FOR — CLEAR THE NAME.
                        //
                        // `fold_wait_on` is otherwise cleared only by the fold FOLDING something, which is
                        // right for progress but wrong here: a node that waited on block X, got X, and then
                        // stopped for a different reason would keep reporting X. The verdict would still
                        // fire (the nameless arm counts these passes) but it would NAME THE WRONG BLOCK —
                        // and sending a reader to the wrong subsystem is the single most expensive thing a
                        // detector does ([[project_census_blind_on_sixteen_surfaces]], where a private fork
                        // was reported as its own downstream symptom and cost three wrong fixes in a night).
                        // Cleared here, the nameless arm reports the CURSOR, which is the position that is
                        // actually not moving.
                        self.fold_wait_on = None;
                        batch
                    }
                    Err(missing) => {
                        // Not stranded — NOT HELD. The ordinary C1 wait: name each to the by-id
                        // block lane and let the pass resume when the block lands.
                        //
                        // ⛔⛔⛔ AND THIS ARM FED NOTHING, WHICH IS HOW 27780 STAYED WEDGED. The wait
                        // site inside the fold's own walk records what it is waiting on; this one —
                        // reached when the cursor sits AT the fold root, the state the live node was
                        // in — only re-issued the want. `[fold-stuck]` fired 1,704 times (sampled
                        // 1-in-16, so ~27,000 passes) over ~2.5 days with the chain dead, and nothing
                        // anywhere could say the node had been asking for the same thing all along.
                        // One wait, one accounting, wherever the fold waits.
                        self.note_fold_wait_on(missing.first().copied(), "a stranded mergeset member is not held here (asked on the by-id lane)");
                        for m in missing {
                            self.want_block_by_id(m);
                        }
                        Vec::new()
                    }
                };
                if !stranded.is_empty() {
                    // Counts and stream POSITIONS only — no block id, note, commitment, amount, key
                    // or owner. Fires once per stale transition (the next pass exits at the
                    // `spine_stale` early-out above this line), never per block.
                    eprintln!(
                        "[fold-stranded] ⛔ {} block(s) sit in the fold cursor's own past unfolded, \
                         with {} block(s) buffered and a dense counter of {} — the canonical order \
                         places their records BELOW this node's cursor, so its numbering is short \
                         and every later position is wrong. Folding them in place would need the \
                         reverted spine rewind; this node stops serving its numbering and waits for \
                         the certified re-anchor.",
                        stranded.len(),
                        self.unfolded_blocks.len(),
                        self.served_seq
                    );
                    self.mark_spine_stale(
                        "blocks in the fold cursor's past were never folded, so this node's \
                         numbering is short of the canonical order",
                    );
                }
            }
            return 0;
        }
        if self.spine_stale {
            return 0; // nothing folds until the next certified bundle re-anchors this node
        }
        // THE FORK POINT is the last chain block the old fold and the new chain SHARE: the lowest common
        // ancestor of the fold cursor's chain and the new root's chain, found by walking both down by
        // blue score in lockstep (cost: the reorg depth, never the chain length). It is NOT "the highest
        // block on the new chain that is in the spine" — a block folded as a side member sits at an
        // order-dependent position (the schedule search: a party that folded its own chain kept a peer's
        // chain block at the side ordinal it had given it and never re-folded).
        let dag = self.relay.dag();
        let score = |b: &crate::block::BlockId| dag.get(b).map(|x| x.blue_score).unwrap_or(0);
        let parent = |b: &crate::block::BlockId| dag.get(b).and_then(|x| x.selected_parent);
        let mut a = Some(root);
        let mut b = self.fold_chain_tip;
        let mut seg: Vec<crate::block::BlockId> = Vec::new(); // the new chain above the fork, tip first
        let fork_point: Option<crate::block::BlockId> = loop {
            match (a, b) {
                (Some(x), Some(y)) if x == y => break Some(x),
                (Some(x), Some(y)) => {
                    if score(&x) > score(&y) || (score(&x) == score(&y) && x != y && !self.block_record_folded(&x)) {
                        seg.push(x);
                        a = parent(&x);
                    } else {
                        b = parent(&y);
                    }
                }
                (Some(x), None) => {
                    if self.fold_chain_tip.is_some() {
                        // The cursor's chain ended at this node's anchor without meeting the new chain:
                        // the fork is BELOW the anchor, where this node holds shells. Stale — the next
                        // certified bundle re-anchors it (the schedule search: a restarted party's LCA
                        // walk fell through to the first folded block on the new chain, a side-folded
                        // record, and re-folded from an order-dependent position).
                        self.spine_stale = true;
                        eprintln!(
                            "[fold-reorg] ⛔ the selected chain forked below this node's anchor — the certified \
                             prefix it adopted no longer names the chain; folding stops and the next \
                             certified bundle re-anchors it"
                        );
                        return 0;
                    }
                    // no cursor: a fresh node folds from its floor
                    if self.block_record_folded(&x) {
                        break Some(x);
                    }
                    seg.push(x);
                    a = parent(&x);
                }
                (None, _) => break None,
            }
        };
        if let Some(f) = fork_point {
            if self.fold_chain_tip.is_some() && Some(f) != self.fold_chain_tip {
                // The fork point is a chain block whose record is in the spine. This node can re-fold from
                // it iff everything above it is held in full — which is exactly "at or above the certified
                // anchor". A fork AT the anchor (a restarted node's genesis anchor, its checkpoint's fold
                // root) re-folds locally; a fork strictly below it — a shell of an earlier anchor, or a
                // record inside the adopted prefix — cannot.
                let at_anchor = Some(f) == self.certified_anchor
                    || (self.certified_anchor.is_none() && self.relay.dag().genesis() == Some(f));
                let f_ord = self.da_ord_mem.get(&Self::da_record_id_for_block(&f, 0)).copied();
                let anchor_ord = self
                    .certified_anchor
                    .and_then(|a| self.da_ord_mem.get(&Self::da_record_id_for_block(&a, 0)).copied())
                    .unwrap_or(self.certified_prefix_len.saturating_sub(1));
                let below_anchor = !at_anchor
                    && (self.folded_floor.contains(&f) || f_ord.map_or(false, |o| o < anchor_ord));
                // ⭐ one-DAG rule: below the anchor but inside the span this node holds WHOLE (its block
                // window after a restart), the reorg re-folds here like any live reorg — see `can_refold_from`.
                if below_anchor && !self.can_refold_from(&f) && seg.is_empty() {
                    // ⭐ THE CURSOR STANDS AHEAD OF THE FOLD ROOT ON ONE CHAIN — NOTHING TO FOLD YET, NOT A FORK (lane stable
                    // 2026-11-01, the re-anchor churn). Right after an adopt a joiner holds fewer than the fold depth of blocks
                    // above its anchor, so the selected chain's fold root (that depth below its tip) lies BELOW the cursor; the
                    // walk above descends from the cursor to the root itself without the new chain contributing a block (`seg`
                    // empty), and naming that root a "fork below the floor" marked the spine stale — a fresh adopt — the same
                    // state again. MEASURED: stable/c11.log 35 and stable/c12.log 8 such abandons on the launch tail's joiner,
                    // every one with the anchor IN the selected tip's past (one with the selected tip == the anchor).
                    // A genuine fork below the floor still marks stale: once the root climbs a branch that is not the cursor's,
                    // the walk meets the cursor's chain below the anchor with `seg` non-empty and the arm below runs.
                    // MUST-STAY-GREEN: the DB-265/267/269/282/358 joiner pins, the replay calibrations, the launch tail.
                    return 0;
                }
                if below_anchor && !self.can_refold_from(&f) {
                    // Below the adopted floor this node holds shells, not the DAG: it cannot compute the
                    // canonical order there. Defer to the next certified bundle (the peer that holds the
                    // DAG rewound properly); fail closed on THIS node's serve, never on chain progress.
                    self.spine_stale = true;
                    // WHY the chain left the floor (lane stable 2026-11-01, the re-anchor churn: 35 of these on one joiner in
                    // stable/c11.log): the selected tip and the anchor, their blue scores and work, and whether the anchor is in
                    // the selected tip's past — a competing heavier branch, or blue data that disagrees. Public chain structure
                    // only (block ids, scores, work): no note, tag, amount, key or owner. DIGITAL-CASH-PRIVACY-REVIEWED.
                    let (sel, anc) = (self.relay.dag().selected_tip(), self.certified_anchor);
                    let node = |b: Option<crate::block::BlockId>| {
                        b.and_then(|b| self.relay.dag().get(&b).map(|n| (b.to_hex()[..8].to_string(), n.blue_score, n.blue_work)))
                    };
                    let anchor_in_past = match (sel, anc) {
                        (Some(s), Some(a)) => !self.relay.dag().which_in_past_of(&s, &[a]).is_empty() || s == a,
                        _ => false,
                    };
                    // A-F80 (lane af58, 2026-11-16): EACH tip's rank, so one run names why the head is not on the anchor's chain
                    // (MEASURED: 23 re-anchors on one restarted validator, the head always its own a59f3313 at blue_work 129
                    // while anchors of 145..177 were adopted, "tips 2"). Per tip: id prefix, blue score, blue work, the head
                    // rule's admission bit (`Dag::finality_admits`), whether the certified anchor is in its past. Public chain
                    // structure only. DIGITAL-CASH-PRIVACY-REVIEWED.
                    let ranks: Vec<(String, u64, u128, u8, bool)> = self
                        .relay
                        .dag()
                        .tips()
                        .iter()
                        .filter_map(|t| {
                            let n = self.relay.dag().get(t)?;
                            let has_anchor = anc.is_some_and(|a| *t == a || !self.relay.dag().which_in_past_of(t, &[a]).is_empty());
                            Some((t.to_hex()[..8].to_string(), n.blue_score, n.blue_work, self.relay.dag().finality_admits(t), has_anchor))
                        })
                        .collect();
                    eprintln!(
                        "[fold-reorg] ⛔ the selected chain moved below this node's adopted floor (block {}) — \
                         the certified prefix it adopted no longer names the chain; folding stops and the \
                         next certified bundle re-anchors it · selected tip {:?} · anchor {:?} · anchor in its past {} · tips {} \
                         · (tip, score, work, admits, anchor in past) {:?}",
                        &f.to_hex()[..8],
                        node(sel),
                        node(anc),
                        anchor_in_past,
                        ranks.len(),
                        ranks
                    );
                    return 0;
                }
                self.rewind_fold_to_common(f);
            }
        }
        seg.reverse();
        let mut folded = 0usize;
        // ⭐ THE POSITION COMES FROM THE DAG, NOT FROM A COUNTER.
        //
        // BORROWED-FROM: Kaspa GHOSTDAG mergeset ordering (github.com/kaspanet/rusty-kaspa,
        // consensus/src/processes/ghostdag) + Zcash note-commitment insertion order (github.com/zcash/zcash):
        // a chain block's mergeset has ONE canonical order, the chain block sorts last, and a record's index
        // is simply how many records precede it in that total order. Every node holding the same DAG walks
        // the same order, so the numbering needs no reconciliation on the wire — which is the whole reason
        // the row-hint / page-reconcile / interleave machinery existed.
        //
        // The base is the position of the block the fold currently stands on: the fold cursor, or genesis
        // (position 0) on a node that has folded nothing, or — on a node that jumped — the anchor's position,
        // which arrived certified with its bundle.
        // WHERE THIS NODE STANDS, in three exact cases — never a guess:
        //   • nothing folded yet  → genesis, position 0 (the DAG's base case);
        //   • the cursor's row is held → that position, itself derived from the DAG;
        //   • a jumped node at its anchor, whose row is inside the adopted prefix → the CERTIFIED leaf
        //     count, which IS the anchor's position: every folded record contributes exactly
        //     BLOCK_FIXED_NOTE_COUNT leaves and genesis contributes none. MEASURED 2026-09-04
        //     (`diag_jump_base_position`): producer at anchor ordinal 7 with a 7-record certified frontier,
        //     and again at 18 with 4608 leaves — the count and the anchor's position agree in both.
        // ⛔ ONE SOURCE FOR WHERE THIS NODE STANDS: THE FOLD CURSOR'S OWN ROW.
        //
        // Genesis has a row (position 0) on every node, a jumped node's anchor row arrives CERTIFIED in the
        // bundle (`anchor_ordinal`), and every record this node folds stores its own — so the cursor always
        // has one and no inference is needed. MEASURED 2026-09-04: deriving it instead from a counter, or
        // from the accumulator's leaf count, gave the two sides DIFFERENT answers and one party folded every
        // later block exactly one ordinal above the other (seed 5: p0@3 p1@4, p0@4 p1@5, …; adversary seed
        // 1: p0@14 p2@15, …). Two derivations of one value is the same error as a second numbering.
        // Seeded ONCE from where this node stands, then advanced per record: the cursor does not move
        // until its chain block finishes, so re-reading it per record handed every record in a segment the
        // SAME position (measured: the plain two-producer pin broke instantly).
        // THE NEXT POSITION, not a base — the two differ at the very start of a chain.
        //
        // Position 0 is GENESIS on every node, and the first block's record takes 1 — whether or not the
        // genesis row has been materialised here (`enable_persist` writes it; a bare in-process node holds
        // none). This paragraph used to say an in-process node's first record takes 0: that was the
        // pre-v32 shape, and it numbered a persisted peer and an in-process peer one apart (MEASURED
        // 2026-09-04, the merging-pair fold pin). The match below is the settled law; the old counter
        // blurred both shapes because whatever folded first simply took the counter's current value.
        let mut next_ord: u64 = match self.fold_chain_tip {
            // ⭐ POSITION 0 IS RESERVED FOR GENESIS, whether or not its record has been materialised on
            // this node. Making the start CONDITIONAL on holding that row looked tidier and was worse: two
            // nodes in one mesh can differ on whether they hold it (a persisted peer does, a fresh
            // in-process one does not), and they then numbered the same chain one apart — MEASURED
            // 2026-09-04, the merging-pair fold pin broke immediately. One rule, no branch.
            None => 1,
            Some(c) => match self.da_ord_mem.get(&Self::da_record_id_for_block(&c, 0)).copied() {
                Some(o) => o.saturating_add(1),
                // A genesis cursor without a row is still position 0 — BY THE CHAIN'S LAW, not by
                // inference: genesis holds position 0 on every node whether or not its record row has
                // been materialised (a bare in-process node adopting a genesis-side anchor holds no
                // genesis row; `ensure_genesis_record` only runs under persist).
                None if self.relay.dag().genesis() == Some(c) => 1,
                None => {
                    // ⛔ C3 (derived-ordinal stage 2): THE COUNT/256 BASE INFERENCE IS DELETED —
                    // a missing cursor row now FAILS CLOSED instead of being guessed.
                    //
                    // ROOT-LAYER: the fold BASE is where the numbering of every later record is
                    // PRODUCED (each `next_ord` is base+k); a leaf-count rescue here was a SECOND
                    // derivation of the same value, and every consumer of the numbering (rows, pages,
                    // sidecars, bundles) reads what this line seeds. Under derivation the cursor
                    // ALWAYS has a row — genesis writes position 0 (`ensure_genesis_record`, or the
                    // law arm above), a jump stores the CERTIFIED `bundle.anchor_ordinal`, a resume
                    // stamps the snapshot's cursor row and asserts it against the restored spine, and
                    // every folded chain block writes its own — so a missing row is a broken
                    // invariant, never a case to bridge.
                    // MEASURED 2026-09-04 (the note above this match): seeding the base from a counter
                    // or the accumulator's leaf count gave two sides DIFFERENT answers and one party
                    // folded every later block exactly one ordinal above the other (seed 5: p0@3 p1@4,
                    // p0@4 p1@5 …; adversary seed 1: p0@14 p2@15 …) — the exact "local inferences
                    // that failed" the second-numbering removal recorded.
                    // MUST-STAY-GREEN: the canonical_record_fold suite (incl. the rewind pin),
                    // fold_schedule_fuzz, two_mining_nodes_that_exchange_blocks_agree_on_every_record_
                    // ordinal, the item9 leaf-law pin, the four certify-absence pins, the graft/strand
                    // landing pins, a_staged_credit_rides_the_next_block_and_lands_in_the_unspent_set.
                    //
                    // The spine-supported position (the block-width coordinate, still the correct
                    // GEOMETRY — only its use as a base authority is deleted) is named for the
                    // operator so the refusal is diagnosable. The print carries a position count
                    // only — no tag, amount, key or owner.
                    // cons: none — nothing is persisted or retained; one map read + one count read on
                    // a path that then STOPS (the next pass exits at the `spine_stale` early-out
                    // before reaching this base read, so the print fires once per stale transition,
                    // never per block; no term in height, blocks or notes).
                    let spine_pos =
                        self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                    eprintln!(
                        "[fold-base] ⛔ the fold cursor holds NO ordinal row while the spine stands at \
                         position {spine_pos} — the base is derived from the DAG's rows, never inferred \
                         from a leaf count"
                    );
                    self.mark_spine_stale(
                        "the fold cursor holds no ordinal row, so the fold's base cannot be derived \
                         from the DAG",
                    );
                    return folded;
                }
            },
        };
        // ⭐ C5 (derived-ordinal stage 3) — THE LEAF LAW AS A CHECKED INVARIANT, at the pass gate.
        //
        // THE LAW: genesis holds position 0 and contributes no leaves; the record at ordinal o
        // occupies leaves (o-1)*BLOCK_FIXED_NOTE_COUNT..o*BLOCK_FIXED_NOTE_COUNT — so a spine folded
        // through the base holds EXACTLY (next_ord - 1) * BLOCK_FIXED_NOTE_COUNT leaves. A numbering
        // that already forked (a legacy snapshot, an old-code peer's spine) stops SERVING here instead
        // of continuing to write a private spine: fail-closed onto the existing certified re-anchor
        // (`mark_spine_stale` + the stale tick-ask + the adopt's spine arm), never onto chain progress.
        //
        // The one lawful departure from strict equality is UPWARD, and it is C2's, not this gate's: a
        // pass that stopped mid-batch (missing record bytes at the `want_record_at_id` return below)
        // leaves materialised records ABOVE the cursor while `fold_chain_tip` — and so the base —
        // stays at the previous chain block, so the next pass legitimately starts with
        // count > (next_ord-1)*width. C2's slot accounting then verifies EVERY such record in its
        // exact slot (state 1 advances; state 2 — materialised out of place — stales), and equality is
        // re-established at every batch boundary. Staling that resume here would halt every mid-batch
        // retry the fold_schedule_fuzz pins keep green. What can never stand is a spine SHORT of its
        // own base (the cursor claims positions the leaves cannot back — the C4 resume check's in-run
        // twin) or a torn spine (a count off the fixed cover shape: no record can legally produce it).
        // The print carries leaf/position counts only — figures /get_info already serves; never a
        // note, amount, key or owner.
        // cons: none — two u64 reads and two compares per pass; nothing stored, no growth on any axis.
        {
            let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
            let base_leaves = next_ord.saturating_sub(1).saturating_mul(width);
            let have = self.spend_frontier.count();
            if have < base_leaves || have % width != 0 {
                eprintln!(
                    "[fold-leaf-law] ⛔ the spine holds {have} leaves but the fold base at position {} \
                     requires {base_leaves} on the fixed {width}-leaf cover — a forked numbering stops \
                     serving and waits for the certified re-anchor",
                    next_ord.saturating_sub(1)
                );
                self.mark_spine_stale(
                    "the spine's leaf count disagrees with the fold base under the leaf law — only a \
                     certified bundle can re-anchor this numbering",
                );
                return folded;
            }
        }
        for c in seg {
            // ⭐ G2b: every seat and exit this step applies lands at THIS chain block's height (see `fold_landing_blue`)
            self.fold_landing_blue = self.relay.dag().get(&c).map(|n| n.blue_score);
            let batch = match self.chain_block_mergeset(&c, next_ord) {
                Ok(batch) => batch,
                Err(missing) => {
                    // C1's WAIT: a mergeset member is not HELD in this DAG. The wait names each
                    // missing BLOCK to the by-id block lane — never only `want_record_at_id`, which
                    // asks for record bytes of blocks this node holds. The blocks arrive by gossip, a
                    // strand release, a graft, or the by-id ask; the pass resumes next tick.
                    let n = missing.len();
                    // ⭐ WHICH block, not just THAT we waited. The first missing member is the one the
                    // fold cannot pass; tracking it is what turns a retry loop into a decidable state.
                    let primary = missing.first().copied();
                    self.note_fold_wait_on(primary, "a mergeset member is not held here (C1: asked on the by-id lane)");
                    for m in missing {
                        self.want_block_by_id(m);
                    }
                    if self.fold_waits % 64 == 0 {
                        eprintln!(
                            "[fold-wait] chain block {} has {n} mergeset member(s) this node does not \
                             hold — the fold waits for the block(s), named to the by-id block lane",
                            &c.to_hex()[..8]
                        );
                    }
                    self.fold_waits = self.fold_waits.saturating_add(1);
                    self.drain_folded_unfolded_blocks();
                    return folded;
                }
            };
            for b in &batch {
                let seq = Self::da_record_id_for_block(b, 0);
                // ⭐ C2 — SLOT ACCOUNTING. The member's derived position is `next_ord`, and exactly one
                // of three states holds:
                //
                //   1. VERIFIED IN ITS SLOT — its row equals the derived position, its leafstart is
                //      exactly (ordinal-1)*BLOCK_FIXED_NOTE_COUNT, and the frontier holds its leaves
                //      (count >= ordinal*BLOCK_FIXED_NOTE_COUNT). It occupies its slot in the
                //      linearisation: skip WITH `next_ord` advanced — the old skip did not advance, so
                //      a mid-batch retry re-derived every later position from the cursor row alone and
                //      numbered the rest of the chain one apart (the measured `[fold-order] ordinal 5
                //      would append at leaf 1280 but its ordinal places it at 1024` shape).
                //   2. MATERIALISED OUT OF PLACE — its leaves are in the frontier but its position
                //      disagrees with the derived order. NOT refold-able: the append check would refuse
                //      forever, and forcing it through would be a spine rewind (the rejected
                //      stuck-state rewind in disguise). That is a spine-root split by definition —
                //      fail closed (`spine_stale`; the certified re-anchor lane resolves it), never an
                //      evict.
                //   3. A ROW-ONLY CLAIM or NO ROW — nothing of it is in the frontier. It folds at the
                //      derived position; a disagreeing bare row is dropped by the position-mismatch arm
                //      inside `fold_record_into_spine`, and an AGREEING bare row (a peer's page filed
                //      the slot this pass now derives) is dropped here first so the fold takes the
                //      appending path with its position check, instead of the row-trusting path that
                //      appends nothing.
                let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                let derived = next_ord;
                let row = self.da_ord_mem.get(&seq).copied();
                let leafstart = self.da_leafstart_mem.get(&seq).copied();
                if row == Some(derived)
                    && leafstart == Some(derived.saturating_sub(1).saturating_mul(width))
                    && self.spend_frontier.count() >= derived.saturating_mul(width)
                {
                    next_ord = derived.saturating_add(1);
                    continue; // state 1: verified in its slot
                }
                if let Some(ls) = leafstart {
                    if self.spend_frontier.count() >= ls.saturating_add(width) {
                        // state 2: materialised out of place — a spine-root split only the certified
                        // fork choice can resolve.
                        // Positions and block ids only — public chain coordinates, never a note, amount, key or owner.
                        eprintln!(
                            "[fold-slot] block {} derived ordinal {derived}, row {row:?}, leaf start {ls}, spine {} leaves, rows held {}, leaf starts held {}",
                            &b.to_hex()[..8],
                            self.spend_frontier.count(),
                            self.da_ord_mem.len(),
                            self.da_leafstart_mem.len(),
                        );
                        self.mark_spine_stale(
                            "a materialised record's leaves disagree with its DAG-derived position — \
                             refolding it locally would need the rejected spine rewind",
                        );
                        return folded;
                    }
                }
                if row == Some(derived) {
                    // state 3, agreeing bare row: produced by a peer's sidecar page filing the slot
                    // this pass derives (`adopt_sidecar_row` stores coordinates only — no leafstart,
                    // no leaves). The adopt cannot be deleted — a NOT_READY node heals through those
                    // pages — so the coordinate-only claim is dropped here and the record folds for
                    // real: the appending path writes the row back along with the leaves it appends.
                    self.da_ord_rev_mem.remove(&derived);
                    self.da_ord_mem.remove(&seq);
                    self.da_leafstart_mem.remove(&seq);
                }
                if !self.da_holds(seq) {
                    // An IDLE block's record is a pure function of the block: its header commits to an empty
                    // note payload, so the record is the public seed — written here from the header alone,
                    // never fetched. A block that carried real notes waits for the by-id lane.
                    let idle = self
                        .relay
                        .dag()
                        .get(b)
                        .map(|node| node.header.output_notes_root == Hash32::hash(&[]))
                        .unwrap_or(false);
                    if idle {
                        let h = self.relay.dag().get(b).map(|node| node.blue_score).unwrap_or(0);
                        // The payload is EMPTY (an idle block's record is its public seed) and the writer has no
                        // failure return; what it RETURNS is the record's actual address, and this pass addresses the
                        // record as `seq` from here on — so the two are compared, never discarded (the fund-loss
                        // census's `FILED_SILENT` row for this site, retired 2026-10-04).
                        let idle_addr = self.record_note_payload_for(Some(*b), h, &[], None);
                        if idle_addr != seq {
                            eprintln!(
                                "[fold] ⛔ an idle block's record landed at a sub-slot other than the one this pass \
                                 addresses — the fold reads its row at the canonical address and will want it"
                            ); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string; no address, note, amount or owner.
                        }
                    }
                }
                // ⛔⛔ A RECORD THIS NODE DOES NOT HOLD STOPS THE PASS BEFORE ANYTHING MOVES — AND THE WAIT IS NAMED.
                // `fold_record_into_spine` below cannot place a record it does not hold, so this block's step could only
                // ever end unwound. It used to run first — anchors, the respend verdict, credits, class objects, the band
                // note, the bond step — then unwind all of it and return with NO wait noted, every pass.
                // MEASURED (link 60, night/perf-load-20261020-211354-n8.log, 8 producers): 7 of 8 nodes looped on ordinal
                // 3 (a credit block whose 0-byte wire body none of them could rehydrate) for the whole 1,280 s funding
                // budget — 958 `[fold-place] … ordinal=3` in the first 120 s, 343,639 `[bond-apply]` and 442,548
                // `[credit-auth]` lines of re-applied work — while `fold_wait` read 0 and `wedge_reason` saw nothing.
                // ROOT-LAYER: the fold is where a record is required; the check runs where the requirement is, once.
                // MUST-STAY-GREEN: every fold-wait pin (DB-274 P5, DB-223, DB-396), the genesis row (no record needed),
                //   an idle block (its empty record is written just above), the db224 heal pins.
                // cons: none — one map lookup per folded block; the state is the unwound state the old path reached.
                let genesis_seq = self.relay.dag().genesis().map(|g| Self::da_record_id_for_block(&g, 0));
                if !self.da_holds(seq) && genesis_seq != Some(seq) {
                    self.want_held_block_record(seq);
                    for later in batch.iter().skip_while(|x| *x != b).skip(1) {
                        let s = Self::da_record_id_for_block(later, 0);
                        if !self.da_holds(s) && !self.da_ord_mem.contains_key(&s) {
                            self.want_held_block_record(s);
                        }
                    }
                    self.note_fold_wait_on(Some(*b), "the block's record (its note payload) is not held here — wanted on the by-id record lane");
                    self.drain_folded_unfolded_blocks();
                    return folded;
                }
                let dag_ordinal = next_ord;
                // ⛔⛔⛔ DB-358 — first spender of a nullifier in canonical order counts: a losing item's outputs leave
                // this block's staged row HERE, before the record takes its position (`respend_decide_at_fold`).
                // DB-353 §13.6: decided over the canonical `S_b`, or WAIT — the pass stops BEFORE `b` (nothing has moved
                // yet) and resumes when this node's set can answer; the block is never excluded and nothing is guessed.
                // ⛔⛔ DB-274 P5 (hole 5) — A SHELL WHOSE HEADER COMMITS A BOND OR CREDIT SET WAITS FOR ITS BODY. The fold's
                // bond, credit and class-object steps read the block's body; folding a shell (header + tx ids) skipped them
                // on this node only, so its validator set and peg ledger split from every node that held the body. The
                // header commits both sets, so a shell knows what it lacks: the pass stops BEFORE `b` (nothing has moved)
                // and resumes when the body lands (`fill_shell_body_preverified`, by the shell-body want lane).
                // ROOT-LAYER: the fold is where these sets are applied; the wait belongs where they would be skipped.
                // MEASURED: before — `db274_p5_a_shell_whose_header_commits_a_bond_set_waits_for_its_body_then_seats_like_
                //   the_producer` RED (B's set 0 vs A's 1: B folded the shell and skipped the seat).
                // MUST-STAY-GREEN: an idle shell (both roots empty) folds as before; a whole block folds as before; the DB-4
                //   heal (`apply_healed_shell_body_in_order`) and the DB-224 wire pins (a wire block keeps its sets).
                // cons: a shell with a non-empty set holds this node's fold until its body arrives — the record wait's shape
                //   (a record-less block already waits); no growth axis.
                if let Some((bond_root, credit_root, evidence_root)) =
                    self.relay.dag().get(b).map(|n| (n.header.bond_set_root, n.header.credit_set_root, n.header.tag_evidence_root))
                {
                    let empty = crate::block::da_sidecar_root_of(&[]);
                    let held = self.unfolded_blocks.iter().find(|x| x.id() == *b);
                    // §POLES: roots commit to REAL content; strip constant-shape cover before hashing.
                    let lacks = |root: Hash32, set: fn(&Block) -> &Vec<u8>| {
                        root != empty
                            && held
                                .map(|x| {
                                    let s = set(x);
                                    let real = &s[..crate::block::sidecar_real_len(s)];
                                    crate::block::da_sidecar_root_of(real)
                                })
                                != Some(root)
                    };
                    // §22: the credit root binds the SEALED bytes whole (no key needed to tell a shell from a body).
                    let lacks_credit = credit_root != empty
                        && held.map(|x| crate::block::credit_set_root_of(&x.credit_set)) != Some(credit_root);
                    // §22b: a held body whose sealed set names wide bytes it does not hold is INCOMPLETE — the fold waits on it,
                    // never a partial set applied (the DB-220 class). ⛔ READ 2026-11-17 (J12, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md):
                    // it is NOT healed like a shell — the want lane counts a whole body as held (`shell_predicate`) and
                    // `fill_shell_body_preverified` keeps the held slot — so the wait ends only by the outgrown verdict's certified
                    // re-anchor, whose carry ships every body with its sidecar (`FoldCarry::sidecars`; the census S-CARRY-SIDECAR
                    // refuses a carry that does not). Every ingest door checks the carriage, so a carry is the one way such a body
                    // enters; J12 closed the one that did.
                    let lacks_wide = held.is_some_and(|x| {
                        self.credit_key_of(x)
                            .is_some_and(|k| crate::block::credit_set_wide_missing(&x.credit_set, Some(&k), &x.wide_objects))
                    });
                    let lacks_bond = lacks(bond_root, |x| &x.bond_set);
                    // ⛔ PRIVATE SHARDING §2.2: every verdict at this step reads the block's own evidence, so a node that does not hold it cannot reach the
                    // verdict every other node reaches. ROOT-LAYER: the one place a block enters the fold. MEASURED 2026-11-06: a joined node folded a
                    // member block it held without evidence, kept an output its two peers revoked as a double spend, and split the record spine 96 steps
                    // later. MUST-STAY-GREEN: `scratchpad/net/join.py`, `restart.py`; an unheld body waits, and the certified bundle covers it.
                    let lacks_evidence = evidence_root != empty && held.map(|x| crate::block::da_sidecar_root_of(&x.tag_evidence)) != Some(evidence_root);
                    if lacks_bond || lacks_credit || lacks_wide || lacks_evidence {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string and three booleans — no id, tag, cm, amount, key or owner.
                        eprintln!(
                            "[fold-wait] ⏸ DB-274 P5: a block held only as a shell commits a bond or credit set this node \
                             does not hold — the fold waits for its body (held body {} · bond set missing {lacks_bond} · \
                             credit set missing {lacks_credit} · wide bytes missing {lacks_wide} · evidence missing {lacks_evidence})",
                            held.is_some_and(|x| !x.pow_proof.is_empty())
                        );
                        // the DB-4 hold, not only the id: the body by id first, then the certified bundle that covers it
                        self.hold_for_unapplied_shell(*b);
                        self.note_fold_wait_on(Some(*b), "the block is a SHELL here (no body) — wanted on the shell-body lane");
                        self.drain_folded_unfolded_blocks();
                        return folded;
                    }
                }
                // ⛔⛔⛔ DB-396 — A BAND THAT CANNOT HOLD THIS STEP MAKES THE FOLD WAIT; THE DOOR NEVER DROPS ONE. MEASURED on the
                // live pair 2026-10-05: the band fell 64 steps behind, `note_fold_step` refused the 65th and set the door STALE,
                // the fold-point set went blind, and the fold stopped forever at the first block carrying a spend or a credit
                // (both nodes `fold_wedged`, ~1,300 blocks unfolded; the certified re-adopt's prove never finished). The pass
                // stops BEFORE `b` (nothing has moved) and resumes when the band applies a step. At the cap the pointer step has
                // `cap − 1 ≥ band_open_after(m)` later steps noted, so it is OPEN to every view-holder (§11.13 C2): the wait
                // ends by proofs, never by a committee or another node's production. A rewind's re-fold re-notes into the room
                // `BandDoor::rewind_to` freed (DB-396 C3).
                // ROOT-LAYER: the fold is the one place a step is noted; the wait belongs where the drop happened.
                // MEASURED: before — `db396_a_band_that_cannot_keep_up_makes_the_fold_wait_and_never_drops_a_step` RED.
                // MUST-STAY-GREEN: the db353 boundary pins (the door's own refusal), every fold-wait pin (DB-274 P5, DB-223).
                // cons: under a band slower than block production the fold runs at the band's rate (payments confirm later);
                //   one map lookup per folded block; no growth axis (the door still holds ≤ the cap; P7 bounds the backlog).
                // TEST: a node standing in for one with a prove worker proves its backlog here first (bound double).
                #[cfg(test)]
                if self.band_autoprove_for_test && !self.band_door.can_note(dag_ordinal) {
                    let _ = self.band_catch_up_for_test();
                }
                if !self.band_door.can_note(dag_ordinal) {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a step count — no id, tag, cm, amount, key or owner.
                    eprintln!(
                        "[fold-wait] ⏸ DB-396: the band lags the fold by its whole cap ({} step(s)) — the fold waits for the \
                         band to apply a step; nothing is dropped",
                        self.band_door.lag()
                    );
                    self.note_fold_wait_on(Some(*b), "the band lags the fold by its whole cap (DB-396)");
                    self.drain_folded_unfolded_blocks();
                    return folded;
                }
                // ⭐⭐⭐ DB-223 Q7: the stated spends' input ANCHORS, judged against the canonical ring BEFORE anything moves
                // (Q1). An incomplete ring that cannot answer WAITS, the P5 shape; a refused spend spends nothing (below).
                let anchor_refused: Vec<crate::note_transition::SpendTuple> = match self.member_anchors_at_fold(b, dag_ordinal) {
                    AnchorVerdict::Decided(refused) => refused,
                    AnchorVerdict::Wait => {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no anchor, tag, cm, amount, key or owner.
                        eprintln!(
                            "[fold-wait] ⏸ DB-223: a stated spend's input anchor is not in this node's anchor ring, and the \
                             ring is incomplete (a fresh adopt or restart) — the fold waits rather than judge on a ring it \
                             cannot vouch for"
                        );
                        let why = "DB-223: a stated spend's input lies outside an incomplete ring (fresh adopt or restart)";
                        self.note_fold_wait_on(Some(*b), why);
                        self.drain_folded_unfolded_blocks();
                        return folded;
                    }
                };
                self.fold_strip_unjustified_notes(b, seq);
                // DB-223 Q7: the refused spends' own tags (nullifier + claim tag) — they contest nothing and retire nothing.
                let refused_tags: Vec<[u8; 32]> = anchor_refused.iter().flat_map(|s| [s.nullifier, s.tag1]).collect();
                // ⛔⛔⛔ DB-367: what this block's lane may retire at all — built once per step from the block's own body.
                let just = self.unfolded_blocks.iter().find(|x| x.id() == *b).map(|body| {
                    let mut j = self.lane_justified(body);
                    j.refuse(refused_tags);
                    j
                });
                let Some((losers, lost_objects)) = self.respend_decide_at_fold(b, seq, dag_ordinal, just.as_ref()) else {
                    self.note_fold_wait_on(Some(*b), "the respend verdict is undecidable at this fold point (the fold-point spent set is blind)"); // the wedge counter names it, exactly as a missing record does
                    self.drain_folded_unfolded_blocks();
                    return folded;
                };
                // ⭐ DB-274 P4 (§8.11): a credit's WEIGHT is judged HERE, in the step's canonical pre-state (after the
                // respend decision, BEFORE the bond class moves). Unattested credits leave the row now; attested ones
                // reconcile below, only once this step succeeds.
                // ⭐ §22 — THE SEALED CREDIT SET OPENS HERE, in canonical order. Without its key (the record lane has not
                // delivered this record's cover key yet) the step WAITS exactly as a record-less block waits — never
                // "applies nothing". With it, a receiver that could not read the set at graft applies the graft-class objects
                // now (idempotent doors: Replay / AlreadySeated / same-cm), so every node's ledger is a function of the chain
                // in fold order, whoever produced the block.
                if let Some(body) = self.unfolded_blocks.iter().find(|x| x.id() == *b) {
                    if crate::block::credit_set_present(&body.credit_set) && self.credit_key_of(body).is_none() {
                        self.note_fold_wait_on(Some(*b), "the block's sealed credit set has no key here yet — wanted on the record lane");
                        self.drain_folded_unfolded_blocks();
                        return folded;
                    }
                    let (ids, lane) = (body.tx_ids.clone(), body.nullifier_proof.padded_tags.clone());
                    if let Some(objects) = self.opened_credit_objects(body) {
                        self.apply_chain_objects_opened(&ids, objects, &lane);
                    }
                }
                let credits_attested = self.credit_decide_at_fold(b, seq);
                // ⭐ DB-274 P4b increment 2: the class objects (the peg ledger's writers, the set readers) apply HERE, in
                // the step's canonical pre-state; a refused (or re-carried) object's notes leave the row. Unwound below.
                // Decided BEFORE the band note (DB-367): a refused object's own nullifiers are not admitted. No class
                // apply reads the spent set, so this order changes nothing any apply sees.
                // §BR-14: the ordinary spends this step applies, each of which paid the protocol's flat fee in its carrier.
                let applied_spends = self.applied_spend_count_at_fold(b, &anchor_refused, &losers);
                if applied_spends > 0 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a node-local count in this node's own log — the node already verified
                    // every spend it relays; no tag, cm, amount, key or owner.
                    eprintln!("[fee-pools] fold step {dag_ordinal}: {applied_spends} applied spend transaction(s) pay the flat fee");
                }
                let (objects_stepped, refused_own, sat_seats, seat_swaps) =
                    self.objects_decide_at_fold(b, seq, dag_ordinal, &lost_objects, applied_spends);
                // ⛔ A-F59: a spend refused for its anchor is in THIS block's fold verdict too, so the held tx returns to the
                // pool (`held_tx_refused_by_fold`) and the next canonical block lays it — it retired nothing here, so it is
                // still a pending payment, never one this block settled. Filed after `objects_decide_at_fold`, which writes
                // the verdict's object half; only where this node holds the block's evicted txs (the DB-389 condition: the
                // verdict entry exists), so a node that never pooled the tx files nothing.
                let refused_keys: Vec<Hash32> = anchor_refused.iter().map(|s| Self::anchor_refused_spend_key(&s.nullifier)).collect();
                self.fold_verdicts.get_mut(b).into_iter().for_each(|v| v.extend(refused_keys.iter().copied()));
                // ⭐ DB-223 Q7: a spend refused for its anchor leaves its outputs out of this block's record (its tags were
                // un-proven above, so it retires nothing). Idempotent on a retried fold, like the class objects' strip.
                if !anchor_refused.is_empty() {
                    let gone: std::collections::HashSet<[u8; 32]> =
                        anchor_refused.iter().flat_map(|s| [s.out0_cm, s.out1_cm]).collect();
                    let n = self.fold_strip_row(b, seq, &gone);
                    // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — no cm, anchor, tag, amount, key or owner.
                    eprintln!(
                        "[spend-fold] ⛔ DB-223: {} stated spend(s) whose input anchor is not in the canonical ring were \
                         refused at their fold; {n} note(s) left this block's record",
                        anchor_refused.len()
                    );
                }
                // ⭐ DB-353 SHAPE (3): this fold step's ADMITTED nullifier set is noted for the band door HERE — after the
                // canonical respend decision (its losers leave the set, R2b), before the record takes its position. The
                // band itself moves only when a later block carries this step's verified transition (`band_drain`).
                // ⛔ DB-367: admitted = the lane's JUSTIFIED tags minus the losers, minus the own nullifiers of a refused
                // object. A tag nothing justifies never enters the set.
                // ⛔⛔⛔ A REFUSED OBJECT RETIRES NOTHING, PROVEN OR NOT (MEASURED 2026-11-10, round 27, two real nodes, lane dcash
                // ca78710f): a DeFi order refused at its fold ("an order slot's note is not under an anchor this node's fold
                // produced") had its outputs stripped, but its input's deletion is proven by the block's ledger, so the old filter
                // (`!j.proven(t)`) kept the nullifier ADMITTED: the buyer's 0.01 BTC coin note was spent on both nodes with no
                // order behind it (the lane later dropped the re-send as NullifierSpent; the wallet's re-send found the note in
                // its proven-spent set; custody reported no fill). That is the DB-223 Q7 rule a plain spend refused for its anchor
                // already gets (`j.refuse`), held for every class object. The one tag that stays is one an APPLIED plain spend of
                // this block also spends (its evidenced head, not refused, not a respend loser); an applied object's own tags were
                // taken out of `refused_own` already (`objects_decide_at_fold`). cons: none — an object that applied nothing now
                // spends nothing, on every node alike (the fold is canonical).
                let unadmitted: std::collections::HashSet<[u8; 32]> = match (
                    just.as_ref(),
                    self.unfolded_blocks.iter().find(|x| x.id() == *b),
                ) {
                    (Some(j), Some(body)) => {
                        let lost: std::collections::HashSet<[u8; 32]> = losers.iter().copied().collect();
                        let spent_by_a_spend: std::collections::HashSet<[u8; 32]> = crate::spend_evidence::block_evidence(body)
                            .iter()
                            .flat_map(|e| e.tags.iter().copied())
                            .filter(|t| j.proven(t) && !lost.contains(t))
                            .collect();
                        body.nullifier_proof
                            .padded_tags
                            .iter()
                            .filter(|t| !j.holds(t))
                            .chain(refused_own.iter().filter(|t| !spent_by_a_spend.contains(*t)))
                            .copied()
                            .collect()
                    }
                    _ => std::collections::HashSet::new(), // no body held: the step is noted UNKNOWN below
                };
                self.band_note_fold_step(b, dag_ordinal, &losers, &unadmitted);
                // ⭐ DB-274 P2 (§8.7): the bond class moves HERE, in canonical order, before the record takes its
                // position (a release writes into it). A refused fold below unwinds it.
                let bond_stepped = self.bond_step_at_fold(b, seq, dag_ordinal, &sat_seats, &seat_swaps);
                // ⭐ DB-274 (dir_set): the block's carried sign-ups, read from the HELD BODY now (the record fold below may
                // drain it) and applied by `dir_step_at_fold` once this step has folded. A block whose body this node does
                // not hold (a carried shell) carries none here — the same named close as the bond step's (P5's body door).
                // ROOT-LAYER: the fold step is where the directory is produced (one canonical order on every node); the
                // body is the only source of the set, and the fold reads it exactly where `objects_decide_at_fold` does.
                // MEASURED: db274 pin at 81b9ad7 RED (one name → two owners across two nodes); this landing's run of the
                // same pin, through sibling blocks and the fold, is recorded in scratchpad/pin-results.tsv.
                // MUST-STAY-GREEN: every honest-chain fold pin (a block without sign-ups applies nothing here).
                let dir_set: Vec<u8> = match self.unfolded_blocks.iter().find(|x| x.id() == *b) {
                    Some(body) => body.dir_set.clone(),
                    None => Vec::new(), // the shell case, named above: nothing to apply, nothing hidden
                };
                // DB-379 instrument (2026-10-04): where every record is PLACED — the member, its chain block, the position
                // it takes and its role — so two nodes' placements diff line by line (the quorum CONTROL's four nodes
                // interleave unlabelled prints; this line names the block). Chain-public coordinates only.
                // DIGITAL-CASH-PRIVACY-REVIEWED: block ids and positions are what the chain publishes; no tag, cm, amount or owner.
                eprintln!(
                    "[fold-place] block={} chain={} ordinal={} role={}",
                    &b.to_hex()[..8],
                    &c.to_hex()[..8],
                    dag_ordinal,
                    if *b == c { "chain" } else { "member" }
                );
                if self.fold_record_into_spine(seq, dag_ordinal).is_none() {
                    if bond_stepped {
                        self.unwind_bond_step();
                    }
                    if objects_stepped {
                        self.unwind_objects_step(dag_ordinal); // C1: the retry decides from the same pre-state
                    }
                    self.dir_unwind_open_step(); // audit F15: and the paid directory entries this step applied leave with it
                    self.band_door.unwind_fold_step(dag_ordinal); // a refused fold leaves no band step behind
                    // held but refused its spine position (`[fold-order]`): the wedge counter names it like every wait
                    self.note_fold_wait_on(Some(*b), "the held record could not take its spine position (fold order)");
                    // bytes not held: want THIS record and every other real record the segment still needs,
                    // so the by-id lane fetches them together instead of one per pass
                    self.want_held_block_record(seq);
                    for later in batch.iter().skip_while(|x| *x != b).skip(1) {
                        let s = Self::da_record_id_for_block(later, 0);
                        if !self.da_holds(s) && !self.da_ord_mem.contains_key(&s) {
                            self.want_held_block_record(s);
                        }
                    }
                    self.drain_folded_unfolded_blocks();
                    return folded;
                }
                folded += 1;
                // ⭐ DB-274 (dir_set): the directory moves HERE, in canonical order, now that the step has folded.
                self.dir_step_at_fold(&dir_set, dag_ordinal);
                // ⭐ DB-274 P4 (§8.11 item 6): the attested credits' reconcile (the staged-copy unstage), now that the
                // step has folded. It does NOT re-tally: the bonded set may already stand at the step's post-state.
                for blob in &credits_attested {
                    if let Some((cm, amount)) = crate::bridge_credit_tx::credit_cm_and_amount(blob) {
                        let _ = crate::node::objects::bridge_credit_tx::reconcile_attested_credit(self, &cm, amount);
                    }
                }
                self.band_drain(); // a noted idle step, or a step whose transition already arrived, applies now
                // PROGRESS ENDS THE WAIT. Nothing else may clear it: a wait that is cleared by anything
                // other than a fold advancing would hide exactly the state this records.
                self.fold_wait_on = None;
                self.fold_no_progress_passes = 0;
                next_ord = dag_ordinal.saturating_add(1); // dense by construction
                // Correction 7 stage 3: remember the spine root this fold just produced, keyed by the
                // ordinal it stands at — the record-spine ring a level peer's beacon claim is compared
                // against. One push + at most one pop per folded record.
                // ⭐ DB-223 / DB-274 P3: the SAME ring is the ANCHOR RING a spend's anchor is judged against, so it reaches
                // `merge_depth_cap` fold steps (DB-361: a mergeable block's fold point sits within that reach) — 72 B an
                // entry (u64 + 8-lane digest), 259,200 B at 3,600, constant in height. The frontier ring beside it stays
                // SPINE_RING_LEN (rewinds).
                if self.spine_recent_roots.len() >= self.anchor_ring_len() {
                    self.spine_recent_roots.pop_front();
                }
                self.spine_recent_roots
                    .push_back((dag_ordinal, self.spend_frontier.root()));
                // ⭐ §19.4: the first step of a later 10-minute slot of the chain clock keeps its root as an EPOCH ANCHOR (consensus
                // state, `PegLedger::push_epoch_anchor`),
                // and this node keeps the frontier it stood at — the one its own wallet's cash-out claim is proven against
                let step_ms = self.chain_time_ms_at(b);
                if self.peg.push_epoch_anchor(dag_ordinal, step_ms, self.spend_frontier.root()) {
                    self.epoch_anchor_frontier = Some((dag_ordinal, self.spend_frontier.clone()));
                }
                // §RF-3: the member ring commit of the ring standing at this step, the history a header's
                // `member_ring_commit` is judged against (one push + at most one pop, like the ring).
                self.push_member_ring_commit();
                // DB-268: the same step's frontier + accumulator, so a rewind to here restores the prefix in O(1).
                if self.spine_recent_frontiers.len() >= Self::REWIND_RETAIN {
                    self.spine_recent_frontiers.pop_front();
                }
                let acc_here = self.da_membership_acc_at_ordinal(dag_ordinal);
                self.spine_recent_frontiers
                    .push_back((dag_ordinal, self.spend_frontier.clone(), acc_here, self.root_history.clone()));
            }
            // ⭐⭐⭐ CAPTURE THE ANCHOR'S PoUW WITNESS AT THE ONE INSTANT IT IS STILL AVAILABLE.
            //
            // `c` is becoming the fold root — the block a DSYNC bundle serves as its ANCHOR, and the one
            // whose weight `Dag::add_anchor` stores verbatim as a permanent fork score on every joiner.
            // A joiner's door asks whether it was mined (door-audit R1/R2), and the witness lives only in
            // the BODY, which this node is about to let go: `drain_folded_unfolded_blocks()` below removes
            // exactly these blocks, and the DAG keeps header + tx ids by design.
            //
            // ⛔ CAPTURING AT GRAFT CANNOT WORK, AND THAT IS STRUCTURAL, NOT A MISSED CALL SITE. A block
            // becomes the anchor LATER — when the fold reaches it — so `retain_pow_witness`, which asks
            // "is this the tip or the anchor NOW?", always answered no at graft time. MEASURED: the served
            // bundle carried `tip_pi=21525 anchor_pi=0`, and five `canonical_record_fold_tests` scenarios
            // failed as "J adopts A's bundle".
            //
            // ⭐ This is one `Option`, replaced as the fold advances — not a window of witnesses, which
            // would have been a per-block store this tree bans.
            if let Some(pi) = self.unfolded_blocks.iter().find(|b| b.id() == c).map(|b| b.pow_proof.clone())
            {
                if !pi.is_empty() {
                    self.anchor_pow_witness = Some((c, pi));
                }
            }
            self.fold_chain_tip = Some(c);
            self.sync_prune_floor();
            self.join_batch_end();
        }
        if folded > 0 {
            self.drain_folded_unfolded_blocks();
            self.maybe_freeze_join_bundle();
        }
        folded
    }

    /// How far behind its own DAG this node's canonical fold is. PUBLIC because a node that cannot say
    /// this cannot be seen to be stuck: on 2026-09-24 the live pair had been frozen for ~2.5 days while
    /// `/get_info` answered `200 OK` at a constant height, and this number — 97,706 — existed only inside
    /// a sampled log line on one of the two nodes.
    #[must_use]
    pub fn unfolded_blocks_len(&self) -> usize {
        self.unfolded_blocks.len()
    }

    /// Consecutive fold passes spent waiting on the SAME block, if the fold is waiting at all.
    #[must_use]
    pub fn fold_wait_state(&self) -> Option<(crate::block::BlockId, u64)> {
        self.fold_wait_on
    }

    /// ⭐⭐⭐ IS THIS FOLD WAITING FOR SOMETHING THAT CAN NEVER ARRIVE?
    ///
    /// Returns `(block, passes, backlog, window)` when waiting is PROVABLY futile, `None` while it is
    /// still the right thing to do.
    ///
    /// ⛔⛔⛔ THE DEFECT THIS EXISTS FOR (live pair, 2026-09-24, both nodes, ~2.5 days): the canonical fold
    /// waits for a mergeset member it does not hold and names it to the by-id block lane, every pass,
    /// forever. There is no term anywhere that decides the block will never come — so a node whose fold
    /// has fallen further behind than the network RETAINS asks ~5,700 times for a block that no honest
    /// node still has, while its DAG keeps advancing and the backlog only grows. One missing object stops
    /// a whole chain, permanently, with no alarm ([[feedback_no_chain_halts]]).
    ///
    /// ⭐ THE STRUCTURAL ARM IS THE REAL ONE: `backlog > keep_depth` means the block the fold is waiting
    /// for sits below the pruning horizon every honest node computes identically — it is not late, it is
    /// GONE, and only a DSYNC jump can move this node. MEASURED live: backlog 97,706 against a ~7,516
    /// keep_depth, i.e. the wanted block was ~90,000 blocks below what anyone retains.
    ///
    /// The passes arm is a backstop for a wedge the structural test cannot see (a block genuinely held by
    /// nobody while the backlog is still inside the window — 27780's shape, where the wanted RECORD's
    /// index entry had outlived its bytes and the peer answered `0 of 32` 12,283 times).
    ///
    /// ⛔ THIS NEVER REFUSES ANYTHING AND NEVER DROPS A BLOCK. It reports a state; the runtime converts it
    /// into the jump that already exists. Failing closed on chain progress is what DB-161 was.
    #[must_use]
    pub fn fold_wait_is_unrecoverable(&self) -> Option<(crate::block::BlockId, u64, usize, u64)> {
        let backlog = self.unfolded_blocks.len();
        let window = self.relay.dag().keep_depth().max(1);
        if let Some((id, passes)) = self.fold_wait_on {
            let below_retention =
                backlog as u64 > window && passes >= Self::FOLD_WAIT_STRUCTURAL_MIN_PASSES;
            if below_retention || passes >= Self::FOLD_WAIT_UNRECOVERABLE_PASSES {
                return Some((id, passes, backlog, window));
            }
        }
        // ⛔ AND THE NAMELESS WEDGE — work held, none done, no block named. 27780's shape exactly, and a
        // verdict keyed only on a named block would have stayed silent through all ~27,000 of its passes.
        // The id reported is the fold's own cursor, because that is the position that will not move.
        if backlog > 0 && self.fold_no_progress_passes >= Self::FOLD_WAIT_UNRECOVERABLE_PASSES {
            if let Some(cursor) = self.fold_chain_tip {
                return Some((cursor, self.fold_no_progress_passes, backlog, window));
            }
        }
        None
    }

    /// Consecutive fold passes that held unfolded blocks and folded nothing.
    #[must_use]
    pub fn fold_no_progress_passes(&self) -> u64 {
        self.fold_no_progress_passes
    }

    /// The SERVED bundle's carry, the one a jumper adopts. Side blocks ride as header SHELLS (DB-100b: the other
    /// branch's proofs must not ride the Tor lane that closes the fork; DB-117b: they must still reach the DAG).
    pub(crate) fn unfolded_carry(&self) -> crate::sync::FoldCarry {
        self.carry_for(false)
    }

    /// ⭐ DB-274 §8.14 step 1 — the CHECKPOINT's carry: this node's OWN resume.
    ///
    /// A side block whose body holds anything a fold decides on rides WHOLE: a non-empty `bond_set` or `credit_set`,
    /// or real notes (spends, credits, releases). So a restarted node folds it from its body exactly as a peer that
    /// never restarted does. Before this, every such block came back as a bodiless shell, and its bond step, credit
    /// verdict and respend decision were silently skipped. MEASURED RED: the restarted node kept V's weight (A=0,
    /// B=50,000) and kept an unattested credit its peer stripped (A=false, B=true).
    ///
    /// This is the node's own data, so no root needs to vouch for it. DB-100b's size reason is the served bundle's
    /// (Tor), not a local file's. An idle side block with no sets still rides as a shell: a fold decides nothing on it.
    ///
    /// Same ids in the same `unfolded` list as the bundle, so DB-117b's placement and numbering are unchanged; only the
    /// side entries' content differs.
    /// Con: the checkpoint grows by the non-idle side blocks' bodies — ≤ `LIVE_LANE_DEPTH` in a deep fork, typically
    /// 0–2 blocks.
    pub(crate) fn checkpoint_carry(&self) -> crate::sync::FoldCarry {
        self.carry_for(true)
    }

    /// The selected chain moved below the fold root: `common` is the highest chain block whose record is
    /// already in the spine (the fork point). Everything folded after it leaves the spine and re-folds in
    /// the new canonical order from there — never from genesis.
    pub(super) fn rewind_fold_to_common(&mut self, common: crate::block::BlockId) {
        // Genesis is the floor: it may carry a record (a persisted node files one at ordinal 0) or none
        // (an in-memory node). Everything above the common block's record — or everything, when the
        // common block is a record-less genesis — leaves the spine.
        let keep_through: Option<u64> = self
            .da_ord_mem
            .get(&Self::da_record_id_for_block(&common, 0))
            .copied();
        let first_evict = keep_through.map(|k| k.saturating_add(1)).unwrap_or(0);
        // ⛔ §POLES spec 5: the rewind journals are read through their effective window, fixed at the tip BEFORE anything is
        // evicted — an entry below it is slack this node's own fold history left (a retreat keeps up to `REWIND_RETAIN`),
        // which a never-folded peer at the same tip does not hold, so it can decide nothing here.
        let window_floor = self.rewind_window_floor();
        // ⭐ DERIVE THE PREFIX BEFORE ANYTHING IS EVICTED — AND FAIL CLOSED (2026-09-21, one-DAG rule).
        // The frontier below the fork point and the membership accumulator AT it are both pure functions of
        // the per-ordinal roots (Kaspa's UTXO-diff replay; Bitcoin's reindex). `da_macc_fwd_mem` dies with
        // the process, so a rewind on a RESTARTED node used to land the accumulator on the genesis value
        // whenever the fork point's step was not in the map, and an underivable prefix installed an EMPTY
        // frontier under a non-zero cursor. Both are now computed first; if either cannot be, the spine is
        // marked stale with nothing evicted and the certified re-anchor lane settles it. The stale mark is
        // this node's OWN serve verdict (NOT READY, fold stopped) — a local fail-closed on what it serves,
        // never a transition another node must agree on; the chain's progress is untouched.
        let width = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        // ⛔ DB-268: a fork point inside the recent-frontier ring restores its prefix (and accumulator) from the ring —
        // O(1), and the ONLY way a joiner can rewind above its certified anchor (it holds no root below it).
        let from_ring = if first_evict == 0 {
            None
        } else {
            self.spine_recent_frontiers
                .iter()
                .rev()
                .find(|(o, _, _, _)| *o == first_evict - 1 && *o >= window_floor)
                .map(|(_, f, a, rh)| (f.clone(), *a, rh.clone()))
        };
        // ⛔ G2a: the anchor spine rewinds WITH the frontier — `root_history` through the fork point (one anchor per kept
        // record), from the same ring entry / re-fold base. Until G2a every fold reorg re-appended the re-folded records'
        // anchors on top of the evicted ones (pin-g2a-red.log: 14 anchors over 12 folded records).
        let (prefix, acc_at_fork, rh_prefix) = if first_evict == 0 {
            (
                crate::spend_frontier::PoseidonSpendFrontier::new(),
                Self::MEMBERSHIP_GENESIS_ACC,
                crate::spend_frontier::PoseidonSpendFrontier::new(),
            )
        } else {
            let (prefix, rh_prefix) = match &from_ring {
                Some((f, _, rh)) => (f.clone(), rh.clone()),
                None => self.refold_frontier_prefix(first_evict),
            };
            if prefix.count() != first_evict.saturating_sub(1).saturating_mul(width)
                || rh_prefix.count() != first_evict.saturating_sub(1)
            {
                self.mark_spine_stale(
                    "the record prefix below the fork point is not derivable here — the certified re-anchor \
                     lane settles this reorg",
                );
                return;
            }
            let k = first_evict - 1;
            let ring_acc = from_ring.as_ref().and_then(|(_, a, _)| *a);
            let acc = match self.da_membership_acc_at_ordinal(k).or(ring_acc) {
                Some(a) => a,
                None if k == 0 => Self::MEMBERSHIP_GENESIS_ACC,
                None => match self.derive_membership_acc_through(k) {
                    Some(a) => a,
                    None => {
                        self.mark_spine_stale(
                            "the membership accumulator at the fork point is not derivable here — the \
                             certified re-anchor lane settles this reorg",
                        );
                        return;
                    }
                },
            };
            (prefix, acc, rh_prefix)
        };
        // ⛔ FOLD-ROOT-DROP (lane a 2026-10-25, census4 reduced to the 2-node pin): the published TIP TRANSITION
        // `(prev_acc, block_root)` — set at the one place the accumulator advances (`record_note_payload_inner`) —
        // rewinds with the spine to what a node that folded only through k = first_evict − 1 holds. Derived BEFORE
        // anything is evicted, failing closed like its siblings. Genesis files a record but never folds one, so
        // k ≤ 0 is the initial (zero) transition.
        let zero = usdm_decider::poseidon2_compress::zero_digest();
        let tip_transition = if first_evict <= 1 {
            (zero, zero)
        } else {
            let k = first_evict - 1;
            let prev = match self.da_membership_acc_at_ordinal(k - 1) {
                Some(a) => Some(a),
                None if self.da_macc_first.is_some_and(|(o, _)| o == k) => self.da_macc_first.map(|(_, a)| a),
                None if k == 1 => Some(Self::MEMBERSHIP_GENESIS_ACC),
                None => self.derive_membership_acc_through(k - 1),
            };
            match (prev, self.da_block_root_at_ordinal(k)) {
                (Some(p), Some(r)) => (p, r),
                _ => {
                    self.mark_spine_stale(
                        "the membership tip transition at the fork point is not derivable here — the certified \
                         re-anchor lane settles this reorg",
                    );
                    return;
                }
            }
        };
        // ⛔ DB-358 — a re-fold decides again from identical inputs: restore the revoked notes of every block whose record
        // this rewind un-folds (ordinal ≥ `first_evict`). The reach ring records the ordinal each block actually folded
        // at, so this reads no per-record index. The blocks leave the ring (their re-fold re-enters them). DB-353 §13.6:
        // the re-fold reads the same `S_b`, because `rewind_to` took the evicted steps' tags back out of the view and the
        // awaiting set alike — no arrival fact has to survive the rewind. A step older than the ring was released with
        // it; a rewind that deep re-folds from the certified base.
        let rewound: Vec<crate::block::BlockId> =
            self.respend_reach.iter().filter(|(o, _)| *o >= first_evict.max(window_floor)).map(|(_, id)| *id).collect();
        // ⭐ DB-274 P2 (§8.7) — the bond class un-folds with its records, newest first, BEFORE DB-358's revokes are
        // put back (its step ran after them at the fold, and a release appended to the same row). A step older than
        // the journal cannot be undone: the set is marked stale rather than silently kept.
        // ⛔⛔⛔ DB-396 C3 (2026-10-27) — ORDINAL 0 IS GENESIS AND FOLDS NO STEP. A rewind to the fork point GENESIS
        // (`keep_through` None ⇒ `first_evict` 0: every record leaves the spine) needs the class journals down to the
        // image BEFORE ordinal 1 — the genesis state — which is exactly the entry the journals keep for ordinal 1. Asking
        // them for ordinal 0 asked for an image no fold ever wrote, so a reorg of exactly the ring's depth was refused
        // as "below the journal" and the node stopped folding forever (spine stale, no re-anchor in sight).
        // MEASURED 2026-10-27 (scratchpad/funds/c3-1.log, db396_c3): `[fold-reorg] … 64 record(s) from ordinal 0 left the
        // spine and re-fold … from the fork point 87feeb17` then `[fold-conflict] ⛔ a rewind reached below the peg
        // ledger's fold journal` — B re-folded nothing (unfolded 76, every ordinal None) while A numbered 76 blocks.
        // ROOT-LAYER: a journal's floor is a statement about ORDINALS THAT FOLDED; genesis never did, so the ordinal a
        // rewind needs is `max(first_evict, 1)` at every journal (bond, directory, peg objects, the band door). The window
        // is unchanged (NO GROWTH: REWIND_RETAIN entries, SPINE_RING_LEN effective); a reorg deeper than the ring still
        // fails closed to the certified re-anchor lane. BORROWED: a reorg re-applies from the fork point and never
        // below genesis (Bitcoin reorg; Kaspa: order by the consensus rule, never by arrival).
        let need = first_evict.max(1);
        while self.bond_fold_journal.back().is_some_and(|s| s.ordinal >= first_evict) {
            if let Some(step) = self.bond_fold_journal.pop_back() {
                self.restore_bond_fold_step(step);
            }
        }
        if need < self.bond_journal_floor {
            self.mark_spine_stale(
                "a rewind reached below the bond class's fold journal — the validator set cannot be un-folded there",
            );
        }
        // ⭐ DB-274 (dir_set) — the directory un-folds with its steps, newest first, so a re-fold from identical inputs
        // reaches the identical directory and accumulator. Below its journal's floor it is STALE, said loudly.
        while self.dir_fold_journal.back().is_some_and(|s| s.ordinal >= first_evict) {
            if let Some(s) = self.dir_fold_journal.pop_back() {
                self.directory.undo_step(s.step);
            }
        }
        // A-F38: and the writes of un-folded steps that were HELD while a refill is owed leave with their steps (the
        // re-fold holds them again in its own order); a write of a step still open has no ordinal and goes too
        self.dir_refill_held.retain(|(o, _)| o.is_some_and(|o| o < first_evict));
        self.dir_refill_held_closed = self.dir_refill_held.len();
        if need < self.dir_journal_floor {
            self.mark_spine_stale(
                "a rewind reached below the directory's fold journal — the sign-ups cannot be un-folded there",
            );
        }
        // ⛔ DB-274 P4b increment 2 — the peg ledger un-folds with its object steps: the OLDEST before-image at or after
        // `first_evict` is the ledger as it stood before every rewound object step (each later image is newer state).
        // §POLES spec 5: an image below the effective floor is slack — popped with its step, never restored.
        let objects_floor = self.objects_journal_floor.max(window_floor);
        let mut restore: Option<crate::peg::PegLedger> = None;
        while self.objects_fold_journal.back().is_some_and(|(o, _, _)| *o >= first_evict) {
            if let Some((o, img, _)) = self.objects_fold_journal.pop_back() {
                if o >= objects_floor {
                    restore = Some(img);
                }
            }
        }
        if let Some(img) = restore {
            self.peg = img;
            if let Some(back) = self.objects_fold_journal.back_mut() {
                back.2 = None; // DB-417: the step that followed it is gone; its next state is the live ledger again
            }
        }
        // IonSwap pools: this node's cache of the contract tree and the pool rows un-folds with the same steps
        self.ion_cache.rewind(first_evict);
        // ⛔ Below the floor the oldest image left is NEWER than the rewound steps: their effects would stay applied. Said
        // loudly — the certified re-anchor settles it — never kept silently.
        if need < objects_floor {
            self.mark_spine_stale(
                "a rewind reached below the peg ledger's fold journal — its class objects cannot be un-folded there",
            );
        }
        // ⭐ DB-353 SHAPE (3) — the band un-folds with its steps (R3), BEFORE DB-358's revokes are put back: every rewound
        // step's entries return byte-identically and the re-fold notes the steps again. Below the band journal's floor the
        // band is STALE, said loudly, never silently kept.
        // ⭐ P1 (spec §13.4): the held view IS the band-pointer state, so the rewind takes every un-applied step's admitted
        // inserts back OUT of it — after a reorg the view never keeps an insert the band no longer holds. The accumulator
        // then follows the band's live root, exactly as `band_drain` makes it follow each applied step.
        let misses_before = self.band_door.held_rewind_misses;
        // the band door keeps its genesis entry (ordinal 0) under a rewind to genesis — the same rule, `need`
        if !self.band_door.rewind_to(need, self.sparse_work.as_mut()) {
            self.mark_spine_stale(
                "a rewind reached below the band door's fold journal — the nullifier band cannot be un-folded there",
            );
        }
        self.view_follow_band_root();
        if self.band_door.held_rewind_misses > misses_before {
            // a tag the view could not take back: its tree no longer describes the band, so it is DROPPED rather than
            // served (a copath from it would fold to neither root) and re-warmed by the wholesale path
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count of tags, never a tag, cm, amount or owner.
            eprintln!(
                "[band-door] ⛔ the rewind could not take {} admitted tag(s) back out of the held view — the view is dropped \
                 and re-warmed",
                self.band_door.held_rewind_misses - misses_before
            );
            self.set_sparse_work(None);
        }
        // the cursor's overlay is of steps the rewind may have evicted: rebuilt lazily from the pointer
        self.band_cursor = crate::nf_sparse::BandCursor::new();
        for id in &rewound {
            self.respend_pop_journal(id);
        }
        // §POLES spec 5: a slack block (below the window) leaves the reach as a released one does — nothing restored
        let slack: Vec<crate::block::BlockId> =
            self.respend_reach.iter().filter(|(o, _)| *o >= first_evict && *o < window_floor).map(|(_, id)| *id).collect();
        for id in &slack {
            self.respend_journal.remove(id);
            self.respend_tag_journal.remove(id);
        }
        self.respend_reach.retain(|(o, _)| *o < first_evict);
        // ⭐ UN-FLOOR THE EVICTED SPAN. A floor block whose record leaves the spine is a mergeset member
        // again (it re-folds at its canonical position below); left in `folded_floor` it would read as
        // "folded" forever and its record would vanish from this node's numbering. Shells with no ordinal
        // (a jumper's certified past) and floor blocks below the fork point stay floor.
        self.folded_floor.retain(|id| {
            self.da_ord_mem
                .get(&Self::da_record_id_for_block(id, 0))
                .map_or(true, |o| *o < first_evict)
        });
        if let Some(a) = self.certified_anchor {
            let a_ord = self.da_ord_mem.get(&Self::da_record_id_for_block(&a, 0)).copied();
            if a_ord.map_or(false, |o| o >= first_evict) {
                // the anchor's own record left the spine: the fork point is the highest block whose record
                // this node keeps as settled prefix, so it is the anchor from here on
                self.certified_anchor = Some(common);
                self.certified_anchor_score = self.relay.dag().get(&common).map(|n| n.blue_score).unwrap_or(0);
                self.certified_prefix_len = self.certified_prefix_len.min(first_evict);
            }
        }
        let evicted = self.evict_ordinals_from(first_evict);
        if self.fold_checkpoint.as_ref().map_or(false, |(k, _, _)| *k >= first_evict) {
            self.fold_checkpoint = None; // DB-268: its ordinal left the spine
        }
        self.fold_reorgs = self.fold_reorgs.saturating_add(1);
        crate::persist::lower_watermark_after_fold_rewind(self.relay.dag().get(&common).map_or(0, |n| n.blue_score));
        self.served_seq = first_evict;
        // Every block whose record just left the spine is known unfolded now — this node holds the DAG
        // there — so it re-enters the unfolded set (shells: the record bytes are already keyed by id).
        // ALL of them, not only the fork point's descendants: an evicted record can sit on a sibling
        // branch of the fork block (pin: the producer's round-1 side block fell out of the set and its
        // fold waited on it as "unknown" forever).
        self.rebuffer_unfolded_blocks();
        self.spend_frontier = prefix;
        // CACHE-ONLY: root_history is f(chain) — the spine root after each record the canonical fold holds, rewound here to
        // the fork point with the frontier and re-appended by the re-fold of the selected chain's records (G2a).
        self.root_history = rh_prefix;
        self.served_membership_acc = acc_at_fork;
        self.fold_chain_tip = Some(common);
        self.sync_prune_floor();
        // ⛔ FOLD-ROOT-DROP: every other field the fold step writes returns to the fork point's value too — the tip
        // transition (derived above), the sidecar cursor (it owes from the first evicted ordinal again; domain floor 1,
        // as the reconcile's eviction), the anchor's witness (the anchor moved to the fork point; a witness of an evicted
        // anchor is dropped, never kept), and the window index (only windows the rewound spine binds, DB-418's rule).
        self.membership_tip_prev = tip_transition.0;
        self.membership_tip_root = tip_transition.1;
        self.sidecar_cursor = self.sidecar_cursor.min(first_evict.max(1));
        // ⭐ DB-472 (lane stable 2026-10-30): a carried finality vote is judged only once the fold cursor stands at
        // `height − FINALITY_SEAT_ACTIVATION_DELAY`; the cursor just dropped, so every open row above what it can judge now
        // returns to the deferred queue and is judged again by the same rule — the tally a node holds is the one its fold
        // position reaches, never one it reached at a cursor it no longer stands on. Finalized heights are never re-opened.
        let judgeable = self.fold_cursor_blue().saturating_add(crate::params::FINALITY_SEAT_ACTIVATION_DELAY);
        for (voter, cert) in self.finality.reopen_above(judgeable) {
            self.deferred_votes.insert((cert.height, voter), cert);
        }
        // SPEED L7: the observed tally is judged by the same rule, so its open rows above what the dropped cursor can
        // judge leave it too. They are not queued: the carried votes re-enter both tallies when the fold reaches them.
        let _ = self.observed.reopen_above(judgeable);
        while self.deferred_votes.len() > FINALITY_DEFERRED_VOTES_MAX {
            self.deferred_votes.pop_last();
        }
        let anchor = self.fold_anchor_block();
        let held = anchor.and_then(|a| {
            self.full_block_by_id(&a).filter(|b| !b.pow_proof.is_empty()).map(|b| (a, b.pow_proof))
        });
        if held.is_some() || self.anchor_pow_witness.as_ref().map(|(id, _)| *id) != anchor {
            self.anchor_pow_witness = held;
        }
        let _ = self.window_index.retain_bound_to(&self.spend_frontier);
        self.refresh_anchor_body(); // G1g-v: the anchor moved
        eprintln!(
            "[fold-reorg] the selected chain moved below the fold root — {evicted} record(s) from ordinal \
             {first_evict} left the spine and re-fold in the new canonical order from the fork point {}",
            &common.to_hex()[..8]
        );
    }

    /// ⭐ THE SPINE'S OWN ROOT OF THE RECORD AT FOLD ORDINAL `o`, in one indexed read: the level-8 window this node folded over
    /// the record's 256 leaves (block index = fold ordinal − 1; genesis contributes no leaves).
    /// - `window_index`: the fold files BOTH children of every merge at level ≥ 8; a rewind forgets from the rewound block
    ///   (`forget_from_block`); an adopt or a resume keeps only windows bound by hashes to the certified spine
    ///   (`retain_bound_to`); a closed roots-run merges only windows of roots it proved against that spine.
    /// - the frontier's level-8 PEAK, for the newest record at an odd ordinal: its window is filed only when its right
    ///   sibling folds.
    /// `None` = this node holds no fold of `o`; the caller decides what that means.
    /// ONE rule for its two readers: `folded_root_admits` (the row-write door) and `span_seal_root` (the ladder seal).
    pub(super) fn spine_record_root(&self, o: u64) -> Option<crate::spend_frontier::Digest4> {
        let window = o.checked_sub(1)?;
        if let Some(root) = self.window_index.get(Self::RECORD_SUBTREE_LEVEL, window) {
            return Some(root);
        }
        let leaves_per_record = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        if o.checked_mul(leaves_per_record)? == self.spend_frontier.count() {
            return self.spend_frontier.peak_at(Self::RECORD_SUBTREE_LEVEL);
        }
        None
    }

    /// The record position this node is CERTIFIED to: the larger of its own write count (`served_seq`)
    /// and the position the adopted note-frontier spine names — every record is exactly
    /// `BLOCK_FIXED_NOTE_COUNT` leaves of that spine, so the certified leaf count IS a record count.
    /// A DSYNC jump moves the spine in O(1) without writing records, so `served_seq` alone would say a
    /// jumped node owes nothing (measured in-process: served_seq 0 vs cursor 0 right after a jump).
    pub fn certified_record_position(&self) -> u64 {
        let spine = self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        self.served_seq.max(spine)
    }

    /// Encode one block root into its slot. ⛔⛔⛔ THERE WERE THREE COPIES OF THIS ENCODING AND ONLY THE
    /// READER KNEW THE SLOT WAS 32 BYTES. Both writers laid `limb.to_le_bytes()` per lane, which was
    /// exactly 32 bytes while a digest had four lanes and became SIXTY-FOUR at eight — so the seal wrote
    /// double-width slots and `ladder_write_roots` overwrote its own next slot, while the reader went on
    /// striding by 32. Every decoded root was then garbage, `regenerate_idle_record` could not match a
    /// row it should have matched, and `drop_record_bytes_if_unreferenced` kept EVERY row.
    ///
    /// MEASURED, this session: `[ladder] span 0 release: 4095/4096 ordinals resolved to a row, 0
    /// byte-sets dropped` — three spans sealed, nothing released, and the no-growth pin failed with
    /// `circulating_records +37,894,095 B`. ⭐ THE NODE'S O(1) PROPERTY WAS LOST TO A BYTE STRIDE.
    ///
    /// The canonical digest encoding is the fix in both directions: eight 31-bit lanes pack into exactly
    /// 32 bytes, it is INJECTIVE (so two roots can never share a slot), and it REFUSES a non-canonical
    /// slot rather than laundering it into a root nothing else can reproduce. The file's own header
    /// already said this function should be the format's single interpreter; now it is.
    pub(crate) fn ladder_slot_encode(root: &crate::spend_frontier::Digest4) -> [u8; Self::LADDER_SLOT_BYTES] {
        usdm_decider::poseidon2_compress::digest_to_bytes(root)
    }

    /// Decode one slot. `None` for a slot that is not a canonical digest — the fail-closed half of the pair.
    pub(crate) fn ladder_slot_decode(b: &[u8]) -> Option<crate::spend_frontier::Digest4> {
        let mut sb = [0u8; Self::LADDER_SLOT_BYTES];
        if b.len() < Self::LADDER_SLOT_BYTES {
            return None;
        }
        sb.copy_from_slice(&b[..Self::LADDER_SLOT_BYTES]);
        usdm_decider::poseidon2_compress::digest_from_bytes(&sb)
    }

    pub(super) fn ladder_write_roots(&mut self, at: u64, roots: &[crate::spend_frontier::Digest4]) {
        // ⛔⛔⛔ DB-262 — THIS WAS A REPLACE, AND A SPAN IS WRITTEN IN SEVERAL RUNS. It built a blob with ZEROS for every
        // slot below `at` and swapped it in whenever the held blob was shorter, so the closing run of a span erased
        // every root an earlier partial run of the SAME span had written: the span closed on the certified spine (the
        // cursor fold never reads the ladder) while the ladder held zero — absent — below the closing run. Every by-id
        // record there then had no root to verify against, and the reconcile read every own row there as an orphan.
        // ROOT-LAYER: this is the one writer both roots-run callers (partial and closing) share; the seal and
        // `adopt_ladder_span` write whole spans and are unaffected. Overwriting a held slot is right at both callers:
        // a partial run's slots are provisional (a refused closure removes the span blobs whole), and the closing
        // run's slots — and the earlier runs' — are exactly what the closure verified.
        // MEASURED: `db262_a_span_closed_across_two_runs_keeps_the_first_runs_roots_and_its_records_verify` (RED on
        // the replace); real nodes close spans over several runs (gate O: partial runs of 1, 2, 105, 1, 572 roots).
        // MUST-STAY-GREEN: roots_run_tests (7), the ladder pins, idle_record_regeneration_tests, canonical_record_fold_tests.
        // (The reconcile's cited pin `orphaned_prerestart_records_tests` has had NO #[test] since 2026-09-22 — DB-261.)
        // cons: none — the blob is never longer than the replace made it, one slot copy per root as before.
        let span_index = at / Self::DA_LADDER_SPAN;
        let slot = Self::LADDER_SLOT_BYTES;
        let first = ((at % Self::DA_LADDER_SPAN) as usize) * slot;
        let end = first + roots.len() * slot;
        let blob = self.da_ladder_mem.entry(span_index).or_default();
        if blob.len() < end {
            blob.resize(end, 0);
        }
        for (i, r) in roots.iter().enumerate() {
            let off = first + i * slot;
            blob[off..off + slot].copy_from_slice(&Self::ladder_slot_encode(r));
        }
    }

    /// How many record roots `served_membership_acc` covers — a FUNCTION OF THE CHAIN (DB-402), never a per-process
    /// counter. Genesis (ordinal 0) is never folded and every record folds at its own ordinal, contiguously from 1 (the
    /// append-position check refuses anything else), so the accumulator covers ordinals `1..served_seq` on every node:
    /// a replayer, a DSYNC adopter (`served_seq` = certified records + 1, the bundle's accumulator installed) and a
    /// node whose fold root dropped (`served_seq` = the first evicted ordinal) alike.
    /// MEASURED before (a1.log 2026-10-30): the stored counter read 3/3/2 bytes across a joiner and two replayers, and a
    /// fold reorg left it one past a never-folded peer's.
    pub(crate) fn served_fold_count(&self) -> u64 {
        self.served_seq.saturating_sub(1)
    }

    #[cfg(test)] // a test accessor by name: it is not production surface
    pub(crate) fn fold_reorgs_for_test(&self) -> u64 {
        self.fold_reorgs
    }

    pub(crate) fn spine_stale_for_test(&self) -> bool {
        self.spine_stale
    }

    /// TEST — this node's fold leaves every step above `common`'s, exactly as a reorg below them does before it folds the
    /// blocks again: the production rewind ([`Self::rewind_fold_to_common`]) by name, for a pin outside this module.
    #[cfg(test)]
    pub(crate) fn rewind_fold_to_common_for_test(&mut self, common: crate::block::BlockId) {
        self.rewind_fold_to_common(common);
    }

    /// Stage-3 cross-party pin (c): the fold cursor's own row, read exactly as the fold base reads it
    /// — so a scenario verdict can assert the leaf law (`spend_frontier_count == cursor_row * width`)
    /// from OUTSIDE, against the same value the pass gate checks from inside.
    pub(crate) fn fold_cursor_row_for_test(&self) -> Option<u64> {
        let c = self.fold_chain_tip?;
        self.da_ord_mem
            .get(&Self::da_record_id_for_block(&c, 0))
            .copied()
    }

    /// Does this node's spine need a certified re-anchor? TRUE while `mark_spine_stale` holds: the
    /// fold is stopped and only a certified bundle (the adopt's spine arm) can restart it — so the
    /// runtime's tick must actively ASK for one rather than wait for a beacon split that a level
    /// pair never produces (a stale node on the SAME tip as its peer sees no split and would sit
    /// stale forever). One bool read.
    pub(crate) fn spine_needs_reanchor(&self) -> bool {
        self.spine_stale
    }

    /// A pruned ordinal's block root, from its span's ladder record. The in-span/real path stays
    /// `da_block_root_at_ordinal`; this is the cold-span answer.
    pub fn ladder_root_at_ordinal(&self, ordinal: u64) -> Option<crate::spend_frontier::Digest4> {
        let span_index = ordinal / Self::DA_LADDER_SPAN;
        if !self.da_ladder_mem.contains_key(&span_index) {
            // A cold root was asked and the blob is absent — want it from the mesh; the drain
            // emits the ask and the verified adopt retires it. Nothing refused: the asker retries
            // once the blob lands (the same want/fetch shape every other DA item uses).
            self.wanted_ladder.borrow_mut().insert(span_index);
            return None;
        }
        // ONE decoder (`ladder_root_if_held`) reads the blob — it carries the zero-slot sentinel, and
        // a second inline decode here is how one reader gets a rule the other misses.
        self.ladder_root_if_held(ordinal)
    }

    /// Serve one sealed span blob for a peer's LadderReq.
    pub fn ladder_span_blob(&self, span_index: u64) -> Option<Vec<u8>> {
        self.da_ladder_mem.get(&span_index).cloned()
    }

    /// ⭐⭐⭐ Fold ONE block's `(block_pre, tags_digest)` into the O(1) nf-unspent chain acc (A_tip). `block_pre` is
    /// the pre-block sparse root and `tags_digest` = `sparse_fold_digest_nfs(padded_tags, block_pre)` — the SAME
    /// per-block digest a wallet's one-block absence step commits, so the wallet's folded proof and this node's acc
    /// agree by construction. Called once per applied block, in canonical order, so `nf_unspent_acc()` is the tip a
    /// spender's `prove_nf_absence_chain` binds to. O(1): one Poseidon fold, no per-block store.
    /// Fold ONE accepted block into the nullifier accumulators, in canonical order.
    ///
    /// The whole body used to live inline in `ingest_block` behind `if acc_root == pre_root`, with no else —
    /// so a block that arrived early was silently never folded. The order gate is deleted and a carried fold is a
    /// witness field, so every tag-carrying block folds on arrival; the retry stash this once fed is retired
    /// (DB-353 §13.5 item 2).
    ///
    /// Returns `true` iff the block's carried fold verified and the accumulators advanced. Fail-closed: a
    /// forged post, a tampered set or a non-chaining pre advances nothing.
    ///
    /// O1-DEFINITION-REVIEWED: BY CONSTRUCTION — one height-1 WHIR verify over a fixed-height-32 trace plus a
    /// fixed `BLOCK_FIXED_NULLIFIER_COUNT` Poseidon absorb. No term in chain height or spent-set total, and
    /// nothing is retained per item.
    /// The two per-block fold inputs — this block's REAL spend nullifiers and the confidential blobs
    /// that seed its decoys — resolved from the block's own txs.
    ///
    /// ⭐ ONE ENCODING WITH THE PRODUCER. The filter is `!tx.nullifiers.is_empty()` and the two
    /// projections are `tx.nullifiers` / `tx.blob`, character for character what `graft_mined_own`
    /// builds as `graft_real` / `graft_conf` and what the named-block ingest path builds as
    /// `real_vals` / `block_confidential`. A verifier that seeded decoys from a DIFFERENT set could
    /// never reach the producer's committed post-root, so a second shape here would not be a style
    /// difference — it would be an unfoldable block on every node but the miner.
    ///
    /// A tx this node has not pooled simply does not contribute: that is the already-handled case the
    /// caller stashes on (the fold cannot reach the post-root, so it is retried, never dropped).
    /// cons: none — f(one block's tx ids), no store, nothing retained.
    pub(super) fn nf_fold_inputs_for_block(&self, gid: &Hash32) -> Vec<u8> {
        let tx_ids: Vec<Hash32> = self
            .relay
            .dag()
            .get(gid)
            .map(|n| n.tx_ids.clone())
            .unwrap_or_default();
        let txs: Vec<&PqTx> = tx_ids
            .iter()
            .filter_map(|id| self.mempool.get(id))
            .filter(|tx| !tx.nullifiers.is_empty())
            .collect();
        txs.iter().flat_map(|tx| tx.blob.clone()).collect()
    }

    pub(super) fn fold_block_nf_in_order(
        &mut self,
        pre_root: [u8; 32],
        post_root: [u8; 32],
        // ⛔ CAPTURED BEFORE THE BLOCK'S TXS ARE EVICTED FROM THE POOL. `ingest_block` removes a grafted
        // block's txs from the mempool BEFORE it reaches the fold, so rebuilding this here would read an
        // already-emptied pool and seed the wrong decoys — the fold would then fail on a node that had the
        // txs all along. (D-41: nothing reads it any more — the fold runs on the block's carried tags.)
        confidential: &[u8],
        fold_carried: &[u8],
        carried_tags: &[[u8; 32]],
    ) -> bool {
        // ⛔ NO "THIS BLOCK'S TURN" GATE. It required `sparse_acc.root == pre_root`, i.e. the producer's exact
        // replay order, and it is what stashed every out-of-turn block into `nf_fold_pending` forever. The fold
        // below is order-free and self-verifying from block-carried data, so a block is foldable the moment it
        // is accepted — on any node, in any order.
        // ⭐⭐⭐ PREFER THE TAGS THE BLOCK CARRIED. Reconstructing them from this node's own mempool is what
        // made a verifying peer fold NOTHING: without the txs the real set is EMPTY, padding yields 256 pure
        // decoys instead of the producer's reals-plus-decoys, and the fold can never reach the committed
        // post-root. The carried set is verified against the fold proof below, so trusting it forges nothing.
        if !carried_tags.is_empty() {
            // ⭐ DB-353 §13.6: NOTHING of the respend decision is taken here any more. It used to take the lane's
            // first-contact memo at this point — an arrival fact a garbage `nullifier_proof.fold` (a field outside the
            // block id) could suppress (`a_peer_refuses_a_respend_whose_block_carries_a_garbage_fold`). The canonical fold
            // now decides from `S_b`, which no graft-time field reaches, so that hole has nothing left to suppress.
            if !self.adopt_sparse_via_block_fold(fold_carried, pre_root, post_root, carried_tags) {
                // §BD's law for the claimed post, applied to the carried fold: it is a WITNESS field, not an authority.
                // The transition was already taken from the id-bound tags, so a fold that disagrees is REPORTED and this
                // node applies the block exactly as a node holding a clean copy does. Returning here skipped the view
                // advance and the counters too, so a relay's mangling split two honest nodes' state.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed phrase and a byte length; no tag, root, amount or owner.
                eprintln!(
                    "[fold-reject] a block's carried fold ({} B) failed verification against the transition taken from \
                     its id-bound tags — ignored as a witness field; the block applies as a clean copy does",
                    fold_carried.len()
                );
            }
            self.nf_blocks = self.nf_blocks.saturating_add(1);
            // PRIVACY (user 2026-08-14, volume must be hidden at every surface): advance the REPORTED
            // occupancy by the FIXED per-block constant, never by the real spend count — `nf_leaves`
            // feeds only `nullifier_count` (a wire-served figure) and the snapshot resume; the sparse
            // accumulator itself is count-free, so this changes NO consensus state. The served count
            // becomes 1 + 256 x blocks_applied: a pure function of the already-public block count,
            // zero real-volume signal. cons: none — same one u64 add per block; the count no longer
            // equals true occupancy, which nothing reads (the acc is a bare root by construction).
            self.nf_leaves = self
                .nf_leaves
                .saturating_add(crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64);
            // ⛔⛔⛔ D-41 (2026-09-11) — THE MEMPOOL-DERIVED SHARD WRITE IS DELETED. It stored
            // `(real_vals, confidential)` read from THIS node's pool at fold time, keyed by the sparse-fold
            // ordinal — a second writer to `da_nf_mem` beside `fold_atip_at_accept`, which already stores
            // the BLOCK-CARRIED reals at accept. Two writers, two keys, one map: a node whose pool had
            // evicted the txs wrote nothing here, a cold peer fed the blocks wrote a DUPLICATE row for the
            // same block under the other key. MEASURED by the cold-peer verdict: party 0 held 11 rows
            // where a chain-only replay derived 25 (48-op catalogue), 1 vs 2 on the 5-op case. A store
            // that depends on what was in the pool when the fold ran is local state read as truth (§F);
            // the block carries its tags, and the accept-side writer stores exactly those. One encoding.
            // `confidential` had no consumer — every `da_nf_load` reader takes the reals alone.
            // ⭐ §CE — THE COVER-CONF ADVANCE IS GONE FROM HERE, AND THIS IS THE SITE THAT WAS WRONG.
            //
            // This path is conditional twice over — the `!carried_tags.is_empty()` skip around it, and the
            // `sparse_acc.root == committed_pre` gate above it that "a peer block in onion flight loses
            // routinely" — so a PEER advanced only sometimes while a PRODUCER advanced every block. The
            // accumulator was counting ROUTES, not blocks. It now advances once per INGESTED block in
            // `fold_atip_at_accept` and once for a node's OWN block in `graft_mined_own_budgeted`, which
            // together are every accepted block exactly once.
                // ⭐ A_TIP IS DECOUPLED — it advances at BLOCK ACCEPT (`fold_atip_at_accept`), never here. This
            // path is gated on `sparse_acc.root == committed_pre`, a race a peer block in onion flight loses
            // routinely, so no state a SPENDER must reach may ride it. See `fold_atip_at_accept`.
            //
            // ⭐⭐⭐ DB-353 LANDING 2 (P1 §13.4, §13.6): the SPENT SET does not advance here. The view's ONLY advance is
            // `band_drain`, which applies each fold step's ADMITTED set (losers excluded, canonical order) through the band
            // door; the respend decision reads the canonical `S_b` at the fold. (Z1's graft-time flip and DB-358's
            // first-contact memo, both taken at this line, retired with it.)
            return true;
        }
        // ⛔ OLD-TAG (tag-less) BLOCK SHAPE: REMOVED at source (user 2026-08-23 — "yes i meant the
        // old tags"; the chain holds 0 real funds, so no historical block of this shape is owed
        // anything). The reconstruction that stood here rebuilt the producer's padded set from
        // THIS node's own cover-conf seed + mempool blobs — a fold whose inputs depended on local
        // pool state at apply time, which diverges under deferred application. ONE path, works or
        // fails: the tags ride the block (`nullifier_proof.padded_tags`, enforced at the ingest
        // gate in `preverify_block`), and a transition without them is refused — fail-closed on
        // the BAD block only, never a halt. This line is event-driven (a refused legacy shape),
        // never per-block steady state.
        eprintln!(
            "[nf-fold] REFUSED a tag-less (old-format) block transition — carried tags are mandatory"
        );
        false
    }

    /// ⭐⭐⭐ THE ACCEPT-TIME A_TIP FOLD (P1) — the Bitcoin/Kaspa invariant for the absence accumulator:
    /// accepting a block and folding its spend transition are ONE act, once per grafted block (cascade
    /// included), from what the block itself carries.
    ///
    /// `nf_unspent_step_new_acc` is COMMUTATIVE (a wrapping 256-bit sum of domain-separated Poseidon leaves —
    /// the same shape `note_membership_step_new_acc` already uses, for the same measured reason), so fold
    /// ORDER is not part of the value and no block can "miss its turn". The linear pre-root race it replaces
    /// left `nf_fold_seq` at 57,382 against `served_seq` 116,976 on node A and 57,477 against 109,849 on node
    /// B (MEASURED live 2026-08-12, both gaps growing monotonically) — accepted blocks whose spends never
    /// entered the accumulator, so every absence endpoint a wallet could name drifted from the chain.
    ///
    /// TRUSTLESS: the folded leaf derives ONLY from block-carried values — the header-committed pre-root and
    /// the carried tag set. A carried height-1 fold that disagrees with those tags is refused as a WITNESS
    /// (loudly) without blocking the block; the transition folds from the tags either way, and a tampered tag
    /// set yields a leaf no honest node folds, isolating the tamperer instead of halting the chain. Binding
    /// the tags digest into the header id (P2) upgrades that divergence to an outright reject.
    ///
    /// O(1) per accepted block by construction: one digest over the block's own tag rows, one Poseidon leaf,
    /// one 4-limb add, and the SAME single fold-inputs sidecar row the gated path already wrote at the same
    /// per-block rate. No term in height, blocks, notes or age.
    pub(super) fn fold_atip_at_accept(
        &mut self,
        block_id: [u8; 32],
        pre_root: [u8; 32],
        carried_tags: &[[u8; 32]],
        fold_carried: &[u8],
    ) {
        let a_pre = usdm_decider::nf_sparse_air::nf_to_limbs(&pre_root);
        let a_td = usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(carried_tags, a_pre);
        if !fold_carried.is_empty() {
            // The carried proof's statement is the block's PURE transition leaf — never this node's running
            // accumulator, which differs on every device and made the check unreproducible off the producer.
            let post = usdm_decider::nf_sparse_air::block_transition_leaf(a_pre, a_td);
            if !usdm_decider::nf_sparse_air::verify_sparse_fold_height1_bytes(
                fold_carried,
                a_pre,
                post,
                a_td,
            ) {
                eprintln!("[fold-accept] a block's carried height-1 fold disagrees with its carried tags — folding from the tags, which the committed pre-root and digest bind");
            }
        }
        self.fold_block_into_atip(block_id, a_pre, a_td, carried_tags);
        // ⭐⭐⭐ §CE — THE COVER-CONF ACCUMULATOR ADVANCES FOR EVERY INGESTED BLOCK, HERE, UNCONDITIONALLY.
        //
        // ⛔ THE ASYMMETRY WAS ROUTE-SHAPED, AND THE FIRST TWO GUESSES BOTH MISSED IT. A PEER reached its
        // advance only through `fold_block_nf_in_order`, which is inside `if !carried_tags.is_empty()` and
        // is itself gated on `sparse_acc.root == committed_pre` — "a race a peer block in onion flight
        // loses routinely". A PRODUCER advanced unconditionally in `graft_mined_own_budgeted`. So the
        // producer advanced once per block and the peer advanced only sometimes.
        //
        // ⛔ AND MOVING *BOTH* SITES HERE WAS MEASURED WORSE (d38 went red): `graft_mined_own_budgeted`
        // SKIPS ITS OWN BLOCK in the carry loop (`if gid == own_id { continue }`), so a producer never
        // reaches this function for the block it just made. Removing its site left it advancing NEVER.
        //
        // ⭐ SO THE SPLIT IS BY WHICH BLOCK, NOT BY WHICH CONDITION: this covers every block a node
        // INGESTS, and the produce path covers the one block a node MAKES. Exactly one advance per
        // accepted block on every node, over the carried tags the header binds.
        self.advance_nf_cover_conf_acc(carried_tags);
        // ⛔ NO PER-BLOCK SHARD WRITE (D-41 class, 2026-09-11). This wrote the block's stripped reals to
        // `da_nf_mem` at `nf_fold_seq - 1` — while the produce path wrote its own block at `nf_blocks - 1`
        // and a served page wrote under a record id. Three key spaces, one map, rows overwriting rows;
        // the spend-gate sweep that read them is deleted (`nf_absent_by_reconstructed_tip`: the endpoint
        // must be the live accumulator), and with it the store. The fold above is the whole of what a
        // block contributes to the spent state on this node: one commutative O(1) step.
        // The sidecar row a spender's O(1) absence proof folds — a wallet cannot rebuild a past block's tag
        // set itself. One row per accepted block, at the SAME key as the shard above.
        // ⛔ fold-input WRITE deleted: this stored one entry PER BLOCK in `da_fold_mem` so a serve
        // could replay it. Nothing consumes that replay — the wallet reads only the O(1) base — and
        // the spend gate answers from the node's own roots. The write is the growth; removing the
        // reader without it would have left the map filling silently.
    }

    // ⛔ `stash_pending_nf_fold` / `pending_fold_missing_tx_ids` RETIRED with the stash (§13.5 item 2): nothing parks,
    // so nothing waits on a tx body (a fold reads the block's id-bound tags) and `TxReq` has had no responder since
    // 2026-09-24.

    /// ⛔⛔⛔ THE EMPTY-TREE COPATH — this node keeps NO per-nullifier index, BY DESIGN.
    ///
    /// user 2026-07-30: "close that already accepted map because thats the growth vector."
    ///
    /// This used to read `da_nf_node_mem`, a map holding one entry per interior node of the sparse tree along
    /// every inserted path. MEASURED when it was finally listed in the census: 1,502,330 entries /
    /// 60,093,200 bytes at TWENTY-FOUR blocks — ~2.5 MB PER BLOCK, against ~278 KB for every other map
    /// combined. RAM is a banned axis exactly like disk, and that map is what made nodes blow up.
    ///
    /// The map is DELETED. What remains is the empty-subtree constant at each level, which is the truthful
    /// description of a tree this node stores nothing about. Against a root that has advanced, folding it
    /// yields `Unprovable` — so the gate FAILS CLOSED rather than admitting on a witness the node invented.
    /// That is the honest state, and it is why `/get_nf_copath` now answers 503 instead of 200.
    ///
    /// THE WITNESS IS THE SPENDER'S JOB. A nullifier non-membership copath is invalidated by every insertion
    /// anywhere in the tree, so it cannot be HELD by anyone — it must be MAINTAINED. The block already carries
    /// every tag it inserts (`NfBlockProof::padded_tags`), so a wallet can update its own copath at a fixed
    /// per-block cost and CARRY it; the gate already prefers a carried copath over this.
    /// ([[feedback_node_footprint_size_cardinal]] [[feedback_no_growth_any_axis]])
    /// ⭐⭐⭐ THE ONE DOUBLE-SPEND QUESTION, asked in ONE place.
    ///
    /// "Has this note already been spent?" is decided by the SPARSE nullifier accumulator and by nothing
    /// else — the Zcash shape this tree borrowed on purpose (`feedback_borrow_proven_chains_no_rederiving`:
    /// *the nullifier SET decides; an unspent tree as a second authority was the root of the D-3x class*).
    /// Every burning object asks through here, so a second spelling of the question cannot drift from the
    /// first and a note cannot be unspent to one door and spent to another.
    ///
    /// Fail-closed: a copath this node cannot build is NOT an answer of "unspent".
    #[must_use]
    /// ⛔⛔⛔ THIS NODE CANNOT PROVE A NULLIFIER UNSPENT FROM ITS OWN STATE, AND THAT IS BY DESIGN.
    ///
    /// A sparse non-membership copath is invalidated by every insertion, so it cannot be HELD — it must be
    /// MAINTAINED, and holding the index costs 256 tags × 256 levels = 65,536 node writes per block
    /// (MEASURED at ~2.5 MB/block before that mirror was reverted; see `adopt_sparse_via_block_fold`).
    /// The spender maintains its own witness instead, and carries it.
    ///
    /// So this returns the VERDICT, never a bool. `Unprovable` is this node's NORMAL answer once it has
    /// grafted or produced anything, and it means *"my index cannot describe the tree my root commits
    /// to"* — not *"spent"*. ⛔ **A CALLER THAT READS `Unprovable` AS SPENT REFUSES HONEST MONEY**, and a
    /// caller that reads it as unspent admits a double spend; the enum's own doc says so in as many words.
    /// The positive proof of absence rides the TRANSACTION (`PqTx::nullifier_absence` +
    /// `nullifier_witnesses`, judged at the pool door) — the same authority every spend class is judged by.
    ///
    /// MEASURED: a fresh node answers `Unspent`; after ONE `produce` it answers `Unprovable` for every
    /// nullifier, including ones nobody has ever spent. That is not drift — the produce path adopts the
    /// block's committed sparse root in O(1) and deliberately writes no path index.
    /// ⭐⭐⭐ Z2 (2026-09-22) — THIS NODE'S NULLIFIER SHARD POLICY: `(shard_bits, owned shard ids)`.
    ///
    /// The working nullifier tree is the one structure that tracked total SPENDS. Sharding it by nf prefix
    /// turns that into this node's SHARE: it holds the leaves of the shards it is responsible for plus the
    /// fixed `2^s` band for the rest, and the share shrinks as the mesh grows.
    ///
    /// REPLICATION FIRST, SHRINK SECOND. Every shard must live on at least `NF_SHARD_REPLICATION` nodes or
    /// a spender can find no copath for it — so a small mesh holds EVERYTHING (identical to the pre-Z2
    /// behaviour, and honestly so: two nodes cannot shard anything and stay available), and the share only
    /// falls once there are enough peers to keep the replication factor. Membership is a deterministic
    /// function of this node's own identity, so it is stable across restarts and uncorrelated between
    /// nodes — no coordination, no registry, no assignment message.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the owned set is derived from this node's miner seed alone and is
    /// independent of which notes it holds — it reveals nothing about this node's money. A copath ASK
    /// names a nullifier that is public seconds later in the block that spends it.
    pub fn nf_shard_policy(&self) -> (usize, Vec<u32>) {
        // The mesh this node can see: its known peers plus itself.
        self.nf_shard_policy_for(self.visible_mesh_size())
    }

    /// The policy this node would take AT A GIVEN MESH SIZE. Split out from `nf_shard_policy` so the
    /// decision can be exercised at a mesh larger than a fixture can fabricate signed peer records for —
    /// otherwise the only reachable branch is "too small to shard", which is the branch that hid the fact
    /// that sharding had never run.
    pub fn nf_shard_policy_for(&self, mesh: u32) -> (usize, Vec<u32>) {
        let bits = crate::nf_sparse::NF_SHARD_BITS_DEFAULT;
        let total = 1u32 << bits;
        if mesh <= Self::NF_SHARD_REPLICATION {
            return (bits, (0..total).collect()); // too small to shard and stay available
        }
        // Keep every shard on ~NF_SHARD_REPLICATION nodes: this node takes `total * k / mesh`, rounded up.
        let want = ((u64::from(total) * u64::from(Self::NF_SHARD_REPLICATION)
            + u64::from(mesh)
            - 1)
            / u64::from(mesh)) as usize;
        let mut ranked: Vec<(u64, u32)> = (0..total)
            .map(|id| {
                let mut h = blake3::Hasher::new();
                h.update(b"MUSD-nf-shard-rank-v1");
                h.update(&self.miner_seed);
                h.update(&id.to_le_bytes());
                let d = *h.finalize().as_bytes();
                (u64::from_le_bytes(d[..8].try_into().unwrap_or_default()), id)
            })
            .collect();
        ranked.sort_unstable();
        ranked.truncate(want.max(1));
        (bits, ranked.into_iter().map(|(_, id)| id).collect())
    }

    /// `(shard_bits, owned shard count)` as this node's working tree actually stands — what `/get_info`
    /// advertises so a wallet can route a copath ask to a node that can answer it.
    pub fn nf_shard_state(&self) -> (usize, usize) {
        self.sparse_work
            .as_ref()
            .map(|t| t.shard_policy())
            .unwrap_or((crate::nf_sparse::NF_SHARD_BITS_DEFAULT, 0))
    }

    /// ⭐⭐⭐ CAN THIS NODE SERVE LANE A AT ALL — i.e. does it hold a copath source that describes the
    /// accumulator it is judged by? `(view_present, view_matches_acc)`.
    ///
    /// ⛔⛔⛔ THE BLINDNESS THIS CLOSES. `advance_sparse_shadow` compares `tree_root != acc_root` once per
    /// block and logs loudly, and that alarm is the only thing that ever reported this. It can only fire
    /// when the tree EXISTS **and** a block is folding — so it is silent in exactly the two states that
    /// produce the symptom: a treeless node (restarted, or DSYNC-jumped and still warming) and a node
    /// whose fold has stopped. A detector silent precisely when the thing it detects is happening reports
    /// health, not health.
    ///
    /// MEASURED 2026-09-24 on both live nodes: `POST /get_nf_copath` with a random, never-spent tag
    /// answered `503 … "its copath index does not describe the root it committed"` on 27780 AND 28901,
    /// while `[sparse-fold] ⛔ the copath source drifted` had fired **zero** times on either. Lane A — the
    /// only full-history non-membership evidence this chain has, and the one thing that can see a
    /// nullifier settled BELOW the certified fold base (DB-160) — was unavailable chain-wide and nothing
    /// said so.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: two booleans about this node's OWN index health. No tag, note,
    /// amount, key, owner or count — and emphatically not a which-item answer: it is asked of no tag.
    #[must_use]
    pub fn nf_copath_source_state(&self) -> (bool, bool) {
        match self.sparse_work.as_ref() {
            Some(t) => (true, t.root_bytes() == self.sparse_acc.root_bytes()),
            None => (false, false),
        }
    }

    /// ⛔⛔ DB-226 — THE ONE PLACE A VERDICT FROM `sparse_acc` BECOMES A SPEND AUTHORITY. Every reader that
    /// trusts an `Unspent` (the gate's own view, both carried-copath lanes, the serve check) routes through
    /// here. A STALE accumulator (it missed a tag the chain settled — see `sparse_acc_stale`) still proves
    /// `Spent` truthfully, because the set only grows; its `Unspent` is downgraded to `Unprovable`, because a
    /// copath built on its frozen root for a tag spent after the freeze folds EMPTY there.
    ///
    /// MEASURED (gate I, 2026-09-26): after a restart node 1's view warm absorbed ~60 tags per 40 ms tick
    /// against a stream of 155,136 while the chain adds ~512 a second, so it never installed — the node sat
    /// viewless, its accumulator frozen, for the rest of the run. Every restarted or jumped node spends that
    /// window with a root that would vouch for a spent tag.
    /// ⭐⭐⭐ P2' (spec §13.1, §13.5) — THE EXACT VERDICT FOR A CARRIED COPATH, AGAINST THE BAND. The copath describes two
    /// roots: the one it folds to with `nf`'s leaf EMPTY, and the one with it SPENT (`copath_described_roots`).
    /// - Spent at a root the door can place ⇒ SPENT now (the set only grows).
    /// - Absent at a placeable root ⇒ `spent_since` answers over every applied step after it AND every step noted and
    ///   still awaiting its carrier (the fold-point set, pending included): `NotSpent` ⇒ UNSPENT, `Spent` ⇒ SPENT.
    /// - A root the door cannot place, or a step after it that is UNKNOWN here (or a gap) ⇒ UNPROVABLE: the gate refuses
    ///   the item and the spender re-builds on a newer root — never a guess.
    /// Replaces `RecentSpentRoots` (`nf_recent`), which answered the same question over APPLIED steps only and so missed
    /// a tag spent by a folded block whose step still awaited its carrier.
    pub(super) fn band_copath_verdict(
        &self,
        nf: &[u8; 32],
        copath: &[crate::spend_frontier::Digest4],
    ) -> crate::nf_sparse::SpentVerdict {
        use crate::nf_sparse::{Since, SpentVerdict};
        let Some((if_empty, if_spent)) = crate::nf_sparse::copath_described_roots(nf, copath) else {
            return SpentVerdict::Unprovable;
        };
        if self.band_door.spent_since(&if_spent, nf) != Since::UnknownRoot {
            return SpentVerdict::Spent;
        }
        // DB-453: a member-form copath names no pre-spend root (`copath_described_roots`) — it answers only the line above
        let Some(if_empty) = if_empty else {
            return SpentVerdict::Unprovable;
        };
        match self.band_door.spent_since(&if_empty, nf) {
            Since::NotSpent => SpentVerdict::Unspent,
            Since::Spent => SpentVerdict::Spent,
            Since::Stale | Since::UnknownRoot => SpentVerdict::Unprovable,
        }
    }

    /// ⭐⭐ DB-246 — THE ONE PRODUCTION A_tip ADVANCE. It folds `block_id`'s leaf into A_tip AND records the block
    /// in the recent-fold ring, in one act, so no advance site can move the sum without the ring seeing it. A
    /// ring that missed a fold would make the gate's exact accounting refuse honest carriers until it turned
    /// over. [`Self::advance_nf_unspent_acc`] stays for the pins that model a bare fold chain with no block.
    pub(crate) fn fold_block_into_atip(
        &mut self,
        block_id: [u8; 32],
        a_pre: crate::spend_frontier::Digest4,
        a_td: crate::spend_frontier::Digest4,
        padded_tags: &[[u8; 32]],
    ) {
        self.advance_nf_unspent_acc(a_pre, a_td);
        let leaf = usdm_decider::nf_sparse_air::block_transition_leaf(a_pre, a_td);
        // Both callers fold a block the DAG already holds (the accept path after insert, the produce path after
        // `RelayOutcome::Added`), so its canonical key is its own GHOSTDAG blue work — never this node's arrival order.
        let (blue_work, _) = self.dag().canonical_order_key(&Hash32(block_id));
        self.nf_recent_folds.record(blue_work, block_id, leaf, padded_tags);
        // ⛔ DB-270 — AND IT STAMPS THE BLOCK A MEMBER OF THE FOLD SPAN under the current base generation, in the same act,
        // so no fold can move A_tip without the span knowing it. The window's stamp when the window holds the block (a
        // re-fold after an adopt), the in-flight stamp otherwise.
        let bid = Hash32(block_id);
        let gen = self.block_window.base_gen();
        if !self.block_window.restamp(&bid, gen) {
            self.nf_unfolded_gen.insert(bid, gen);
        }
        // (DB-353 C1: the DB-316c pivot move that stood here was a graft-time `sparse_acc` writer — retired, since the
        // accumulator IS the band root.)
    }

    /// ⛔⛔⛔ DB-270 — IS `id` IN THE NULLIFIER FOLD SPAN: folded into A_tip by this node under the CURRENT fold-base
    /// generation. The ONE membership definition every span reader asks (the page, its length, its tips, the DB-252
    /// delta, the DB-246 tip check and the prune absorb). The record-fold store (window ∪ unfolded) holds more than the
    /// span — the fold carry and the held tail of an adopted past, and after a fold-reorg the re-buffered window blocks a
    /// second time — which is why every reader that treated that store as the span was LONG. MEASURED 2026-09-27
    /// (postQ8): 10 vs 2 (depth 0), 42 vs 2 (production depth), 34 vs 2 (a fresh joiner), 146 vs 110 (a fold-reorg).
    pub(super) fn nf_span_member(&self, id: &crate::block::BlockId) -> bool {
        let gen = self.block_window.base_gen();
        match self.block_window.gen_of(id) {
            Some(g) => g == gen,
            None => self.nf_unfolded_gen.get(id) == Some(&gen),
        }
    }

    /// ⭐ G2g-r2a step 2 — THE FOLD-SPAN MEMBERS this node serves: every block [`Self::nf_span_member`] counts (window and
    /// unfolded), `(id, blue_work, blue_score)` ascending by (score, id), one canonical order on every server. Bounded by the
    /// span itself (≤ keep_depth + span blocks); the window's entries are read from its store, the unfolded ones off the DAG.
    pub(crate) fn nf_fold_span_members(&self) -> Vec<([u8; 32], u128, u64)> {
        let gen = self.block_window.base_gen();
        let dag = self.relay.dag();
        // ⭐ PERF (lane stable 2026-11-01): a member's blue data is read from the DAG node the window's span mirrors (one
        // definition of the span, `Dag::keep_depth`; after DB-471 a joiner's DAG holds its adopted past too) and the stored
        // body is decoded only for a block the DAG does not hold. MEASURED (stable/relay2.sample.txt): decoding every held
        // body (`BlockWindow::entry` → `decode_entry`, ~1,740 of 13,999 node-step samples) to read two numbers, on every
        // bundle and checkpoint build. cons: none — the same values (the window keeps the DAG's blue data at `keep`).
        let mut out: Vec<([u8; 32], u128, u64)> = self
            .block_window
            .ascending()
            .into_iter()
            .filter(|(_, id)| self.block_window.gen_of(id) == Some(gen))
            .filter_map(|(_, id)| match dag.get(&id) {
                Some(n) => Some((*id.as_bytes(), n.blue_work, n.blue_score)),
                None => self.block_window.entry(&id).map(|e| (*id.as_bytes(), e.blue_work, e.blue_score)),
            })
            .collect();
        for (id, g) in self.nf_unfolded_gen.iter() {
            if *g == gen && !self.block_window.contains(id) {
                if let Some(n) = dag.get(id) {
                    out.push((*id.as_bytes(), n.blue_work, n.blue_score));
                }
            }
        }
        out.sort_by(|a, b| (a.2, a.0).cmp(&(b.2, b.0)));
        out
    }

    /// G2g-r2a — the listed fold-span ids whose bodies this node still owes its pending base (empty when none is pending),
    /// lowest blue score first, so a member above the anchor is asked after the parents it grafts on.
    pub(crate) fn nf_fold_span_owed(&self) -> Vec<[u8; 32]> {
        let Some(p) = self.nf_fold_base_pending.as_ref() else {
            return Vec::new();
        };
        let mut owed: Vec<(u64, [u8; 32])> = p.owed.iter().map(|(id, (_, bs))| (*bs, *id)).collect();
        owed.sort_unstable();
        owed.into_iter().map(|(_, id)| id).collect()
    }

    /// The base immediately before the current one — the boundary race, see [`Self::nf_base_prev`].
    pub fn nf_fold_base_prev(&self) -> crate::spend_frontier::Digest4 {
        self.nf_base_prev
    }

    /// ⭐⭐⭐ THE SPAN BETWEEN THE BASE AND THE TIP, READ OUT OF THE BLOCK WINDOW.
    ///
    /// A spender's absence carrier steps on `(block_pre, padded_tags)` — the same two values
    /// `fold_block_nf_in_order` uses to advance A_tip, and both RIDE THE BLOCK: `block_pre` is
    /// `header.nullifier_root` and the tag set is `nullifier_proof.padded_tags`, which the ingest gate
    /// already makes mandatory (*"a block must carry what is needed to APPLY it"*).
    ///
    /// ROOT-LAYER: the span is produced by the BLOCK, not by a sidecar. The previous serve read
    /// `da_fold_mem` — one entry per block, in RAM, kept forever — and it was deleted for exactly that
    /// growth. That deletion was right and is not undone: this reads the block window (Kaspa's block
    /// store, already held, already cut at the DAG horizon) and derives the two values on the way out, so
    /// it adds no store, no index and no retained byte. `nf_fold_base` now follows the SAME horizon, so
    /// what this returns is precisely the difference between the base and A_tip — never a walk of the
    /// chain, and bounded by `keep_depth`, a protocol constant.
    ///
    /// MEASURED: with nothing served, a spender could fold nothing, so `nullifier_absence_hex` was empty
    /// on every wallet send and the door answered `REJECT: N input(s) carried NO absence proof` — 0
    /// wallet spends admissible at any height (ecosystem gate run 8yFZ28: `balance never reached 25.0
    /// spendable`). After → a spender reproduces A_tip from the base and the gate's one admit condition
    /// (`claimed_tip == live`) can be met.
    ///
    /// MUST-STAY-GREEN: no node state is written or read that was not already held; `da_fold_mem` stays
    /// deleted; block-window pruning is unchanged.
    ///
    /// SELF-VERIFYING, SO NOTHING HERE IS TRUSTED: the caller folds from the served base and compares its
    /// accumulator against the node's published A_tip. A node that hands back a doctored or partial span
    /// simply never matches, and the caller stays honestly un-ready rather than proving something else.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a CONSTANT broadcast — identical bytes for every caller, derived
    /// from blocks every node already replicates. Not a which-item query: nothing is keyed by nullifier,
    /// address, scope or key, and the reply does not vary with who asks or what they hold.
    ///
    /// O1-DEFINITION-REVIEWED: `count` is the caller's fixed page width and the work is one window lookup
    /// per returned entry. The window span is `keep_depth` = `2*merge_depth_cap + daa_sample_len +
    /// DAG_PRUNE_KEEP_MARGIN`, all protocol constants, so no term in chain height appears.
    /// ⛔ THE WINDOW ALONE IS NOT THE SPAN, AND THE PIN CAUGHT IT: `absorbed 21, span 67` against 90
    /// blocks produced. A block enters the window when its RECORD folds
    /// (`drain_folded_unfolded_blocks`), which is `record_fold_depth` blocks after A_tip absorbed it — so
    /// the window trails A_tip by the not-yet-folded set and `base ⊕ window` misses those blocks. A
    /// spender folding that span lands on an accumulator this node does not hold, and every carrier fails
    /// closed. The span is therefore the window PLUS `unfolded_blocks`; the two are disjoint by
    /// construction (`drain_folded_unfolded_blocks` retains only the unfolded ones and the window keeps
    /// only the folded ones), so nothing is counted twice.
    ///
    /// Each entry carries the BLOCK ID, because a caller cannot key on position: the window shifts as
    /// blocks age out and the base absorbs them. The id is what lets a follower fold each block exactly
    /// once across pages, and the fold being commutative is what makes order irrelevant.
    /// One window block's part of the fold span, from its file the first time and from memory after.
    fn nf_span_entry(&self, id: &crate::block::BlockId) -> Option<NfSpanEntry> {
        let mut g = self.nf_span_cache.lock().unwrap_or_else(|e| e.into_inner());
        g.1 = std::time::Instant::now();
        if let Some(e) = g.0.get(id) {
            return Some(e.clone());
        }
        let blk = self.block_window.get(id)?;
        let e = (usdm_decider::nf_sparse_air::nf_to_limbs(&blk.header.nullifier_root.0), blk.nullifier_proof.padded_tags.clone());
        g.0.insert(*id, e.clone());
        Some(e)
    }

    /// Frees the span entries once no wallet has read them for `NF_SPAN_CACHE_IDLE_MS`, so a node nobody is spending through holds none.
    pub(crate) fn nf_span_cache_drop_if_idle(&self) {
        let mut g = self.nf_span_cache.lock().unwrap_or_else(|e| e.into_inner());
        if !g.0.is_empty() && g.1.elapsed().as_millis() as u64 >= NF_SPAN_CACHE_IDLE_MS {
            g.0 = std::collections::HashMap::new();
        }
    }

    pub fn nf_fold_inputs_page(
        &self,
        from: usize,
        count: usize,
    ) -> Vec<(crate::block::BlockId, crate::spend_frontier::Digest4, Vec<[u8; 32]>)> {
        // ⛔⛔⛔ THE SPAN IS ALL-OR-NOTHING. A HOLE IN IT IS WORSE THAN NO SPAN AT ALL.
        //
        // This was a `filter_map` over `block_window.get(&id)`, and `BlockWindow::entry` reads the block
        // FROM A FILE — `std::fs::read(..).ok()?`. Any transient failure (fd pressure, a slow disk on a
        // loaded node) became `None`, and the filter SILENTLY DROPPED that block from the span.
        //
        // ⛔ WHAT A DROPPED BLOCK COSTS: this span is what `/get_nf_fold_inputs` serves and what a
        // spender's absence carrier folds. A carrier folded over a span with a hole can never reach the
        // node's A_tip, so it never becomes Ready and the send fails — intermittently, under load, with
        // no diagnostic anywhere, because the short span looks exactly like a legitimately short one.
        // MEASURED 2026-09-24: `a_node_built_spend_carries_a_real_recursive_carrier…` passes alone and
        // fails under `--test-threads=2` with *"the 19-block span this node holds does not reproduce its
        // own live accumulator"* — the node refusing its own span, which is the fail-closed half working
        // and the serve half lying.
        //
        // So: every block the window claims to hold must be READ, or this answers with NOTHING and says
        // why. An empty span refuses a spend loudly; a holed span refuses it silently, forever.
        // ⛔ DB-270: MEMBERS ONLY (`nf_span_member`), deduplicated by id — the window first, then the in-flight set.
        let ordered = self.block_window.ascending();
        let mut seen: std::collections::HashSet<crate::block::BlockId> = std::collections::HashSet::new();
        let mut held: Vec<(crate::block::BlockId, crate::spend_frontier::Digest4, Vec<[u8; 32]>)> =
            Vec::with_capacity(ordered.len());
        for (_, id) in ordered {
            if !self.nf_span_member(&id) || !seen.insert(id) {
                continue;
            }
            let Some((pre, tags)) = self.nf_span_entry(&id) else {
                // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS and a public block-id prefix — never a tag,
                // amount, key or owner.
                eprintln!(
                    "[fold-span] ⛔ the window claims block {} but cannot read it back ({}) — serving NO \
                     span rather than one with a hole in it. A carrier folded over a hole can never reach \
                     this node's A_tip, and the spend it backs would fail with nothing to point at.",
                    &id.to_hex()[..8],
                    self.block_window.read_failure_reason(&id)
                );
                return Vec::new();
            };
            held.push((id, pre, tags));
        }
        // Blocks that left the window leave the entries with them.
        self.nf_span_cache.lock().unwrap_or_else(|e| e.into_inner()).0.retain(|id, _| seen.contains(id));
        for blk in &self.unfolded_blocks {
            let id = blk.id();
            if !self.nf_span_member(&id) || !seen.insert(id) {
                continue;
            }
            let pre = usdm_decider::nf_sparse_air::nf_to_limbs(&blk.header.nullifier_root.0);
            held.push((id, pre, blk.nullifier_proof.padded_tags.clone()));
        }
        held.into_iter().skip(from).take(count).collect()
    }

    /// How many entries the span above can hand back — the caller's end-of-stream signal. DB-270: the window's members
    /// in O(1) (its per-generation count) plus the in-flight members the window does not already hold.
    pub fn nf_fold_inputs_len(&self) -> usize {
        let in_flight = self
            .unfolded_blocks
            .iter()
            .filter(|b| {
                let id = b.id();
                !self.block_window.contains(&id) && self.nf_span_member(&id)
            })
            .count();
        self.block_window.count_gen(self.block_window.base_gen()) + in_flight
    }

    /// ⭐⭐ DB-246 — THE TIP ANTICHAIN OF THE FOLD SPAN: every span block (the block window plus the in-flight set,
    /// exactly what [`Self::nf_fold_inputs_page`] serves) that is no span block's parent.
    ///
    /// A carrier that folded the whole span folded exactly `closure(tips)` above the base. That is the coordinate
    /// the gate re-derives its gap from on ANY node. It is computed from the SPAN, never from the DAG's tip set:
    /// the DAG can hold header-only shells that were never folded into A_tip, and tips taken there would close
    /// over blocks no carrier folded.
    ///
    /// O1-DEFINITION-REVIEWED: one pass over the span, which is bounded by the window's protocol-constant depth
    /// plus the in-flight set — the same bound as the page it rides beside. No term in height.
    pub fn nf_fold_span_tips(&self) -> Vec<crate::block::BlockId> {
        // DB-270: members only.
        let mut span: std::collections::HashSet<crate::block::BlockId> = self
            .block_window
            .ascending()
            .into_iter()
            .map(|(_, id)| id)
            .filter(|id| self.nf_span_member(id))
            .collect();
        span.extend(self.unfolded_blocks.iter().map(|b| b.id()).filter(|id| self.nf_span_member(id)));
        let dag = self.dag();
        let mut parents: std::collections::HashSet<crate::block::BlockId> = std::collections::HashSet::new();
        for id in &span {
            if let Some(n) = dag.get(id) {
                parents.extend(n.header.parents.iter().copied());
            }
        }
        let mut tips: Vec<crate::block::BlockId> = span.into_iter().filter(|id| !parents.contains(id)).collect();
        tips.sort();
        tips
    }

    /// ⭐⭐ DB-252 — THE FOLD SPAN ABOVE A BLUE-SCORE CURSOR: the absence follower's incremental page.
    ///
    /// The follower re-downloaded the WHOLE span every pass. MEASURED on real processes: 2.57 → 7.34 MB per pass,
    /// passes 30–63 s apart, so its witness left a pass stale (63 of the ring's 64 blocks). This answers only the
    /// span blocks whose blue score is `> above`, in the same (id, block_pre, padded tags) shape and page order as
    /// [`Self::nf_fold_inputs_page`]. Block FILES are read only for those; there is no walk, only a filter over the
    /// window's own (score, id) index plus the in-flight set, deduplicated by id.
    ///
    /// The cursor is chosen by the caller from PUBLIC time (the start of the previous blue-score quantum), so every
    /// follower polling in a quantum sends the same one. A cursor of the caller's own tips would let a node chain
    /// one follower's polls into a session (DB-252 §8).
    ///
    /// Correct because blue score is monotone along parent edges: no block above the cursor is an ancestor of
    /// anything at or under it. A LATE block at or under the cursor that the caller never folded leaves its sum
    /// short of `a_tip`, so it stays un-ready and asks for the full span. Nothing here is trusted by the caller.
    ///
    /// `None` when the cursor is under the window floor (those blocks are absorbed into the certified base, so the
    /// caller re-roots on the full span) or when a delta block cannot be read back (the page is all-or-nothing, like
    /// the full one).
    ///
    /// O1-DEFINITION-REVIEWED: one pass over the window index plus the in-flight set (both protocol-constant bounded)
    /// and file reads for the delta blocks only. No term in height.
    pub fn nf_fold_inputs_above(
        &self,
        above: u64,
    ) -> Option<Vec<(crate::block::BlockId, crate::spend_frontier::Digest4, Vec<[u8; 32]>)>> {
        // Under the window floor the blocks were absorbed into the certified base: the base moved since the
        // caller's cursor, so it must re-root on the full span. (It would re-root anyway on the served `base_acc`;
        // this only spares it a useless delta.) An EMPTY window is a young chain whose whole span is in flight,
        // and the delta is still exact.
        if self.block_window.floor_blue_score().is_some_and(|floor| above < floor) {
            return None;
        }
        let dag = self.dag();
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut out = Vec::new();
        for (score, id) in self.block_window.ascending() {
            // DB-270: members only, like the full page.
            if score <= above || !self.nf_span_member(&id) || !seen.insert(id.0) {
                continue;
            }
            let (pre, tags) = self.nf_span_entry(&id)?;
            out.push((id, pre, tags));
        }
        for blk in &self.unfolded_blocks {
            let id = blk.id();
            // A block the DAG cannot score is served (never silently dropped): the caller dedups by id.
            let above_cursor = match dag.get(&id) {
                Some(n) => n.blue_score > above,
                None => true,
            };
            if !above_cursor || !self.nf_span_member(&id) || !seen.insert(id.0) {
                continue;
            }
            let pre = usdm_decider::nf_sparse_air::nf_to_limbs(&blk.header.nullifier_root.0);
            out.push((id, pre, blk.nullifier_proof.padded_tags.clone()));
        }
        Some(out)
    }

    /// Blocks folded into A_tip so far — the key space of the absence-fold sidecar.
    pub fn nf_fold_seq(&self) -> u64 {
        self.nf_fold_seq
    }

    /// Blocks folded into the sparse spent set so far (`fold_block_nf_in_order`) — the count a served bundle certifies.
    pub fn nf_blocks_folded(&self) -> u64 {
        self.nf_blocks
    }


    // ⛔ `nf_fold_base_accessor` DELETED 2026-08-15 — it read/wrote a PER-BLOCK store (`da_fold_mem`/`da_nf_mem`),
    // one entry per block FOREVER, in RAM. The spend gate has not needed it since
    // `nf_absent_by_reconstructed_tip` went live (node.rs): a spender builds its carrier against the
    // live A_tip and NAMES its endpoint, and the node closes the gap from its own O(1) roots.
    // MEASURED: the only wallet caller sends {from:0,count:1} and reads ONLY `base_acc` — the
    // per-block array it also returned was consumed by NOTHING.

    // ⛔ `nf_fold_servable_base` DELETED 2026-08-15 — backed by a PER-BLOCK RAM store (`da_fold_mem` /
    // `da_nf_pre_mem`), one entry per block forever. Its readers were TEST-ONLY; the wallet takes
    // only the O(1) base and the spend gate answers from the node's own roots. Readers AND writers
    // deleted together — removing one alone leaves the map filling in silence.

    /// ⭐⭐⭐ THE CERTIFIED FOLD BASE A SPENDER'S ABSENCE CARRIER MUST BE ROOTED AT — `(acc, seq)`.
    ///
    /// ROOT-LAYER: this value is PRODUCED here, in the node, and it is the node's own state — genesis on a
    /// node that folded the chain itself, and the accumulator it adopted on a node that #29 DSYNC-jumped
    /// (the one place `nf_fold_base` is ever written, bound in `sync_binding`). The spend gate compares a
    /// carried witness's `base_acc` against exactly this field, so serving anything else means an honest
    /// spender roots its proof at a value this node's own door will refuse.
    ///
    /// MEASURED: `/get_nf_fold_inputs` served `nf_unspent_acc()` — the LIVE A_tip — under the name
    /// `base_acc`, while the wallet's `fetch_fold_base` doc says it expects *"the adopted accumulator and
    /// its seq"*. A carrier rooted at the live tip attests an EMPTY span, which the gate answers with
    /// `REJECT: N input(s) carried NO absence proof`: 0 wallet spends admissible at any height. After →
    /// the base a proof is rooted at is the same field the gate checks it against.
    ///
    /// MUST-STAY-GREEN: `self_build_publish_absence_witness` and the base-state admit lane both read
    /// `nf_fold_base` directly and are untouched; this only EXPOSES the field they already use.
    ///
    /// O1-DEFINITION-REVIEWED: returns one fixed-width field. No history term, nothing scanned.
    pub fn nf_fold_base(&self) -> (crate::spend_frontier::Digest4, u64) {
        self.nf_fold_base
    }

    /// The O(1) nf-unspent chain acc (A_tip) a wallet's `prove_nf_absence_chain` proof is verified against
    /// (`usdm_decider::nf_sparse_air::verify_nf_absence_chain`). FIXED 32 bytes at any chain height.
    pub fn nf_unspent_acc(&self) -> crate::spend_frontier::Digest4 {
        self.nf_unspent_acc
    }

/// ⭐⭐⭐ THE CROSS-NODE CENSUS'S READ SIDE — every field two nodes on the same chain MUST agree on.
    /// The nullifier-set occupancy — what refuses a SECOND spend. Two nodes disagreeing here disagree
    /// about what has already been spent, and one will admit a double spend the other refuses.
    pub fn nf_leaves_for_audit(&self) -> u64 {
        self.nf_leaves
    }
    pub fn nf_cover_conf_acc(&self) -> [u8; 32] {
        self.nf_cover_conf_acc
    }

    /// Verify ONE spend's absence proof by RECONSTRUCTING the tip it was built for, then closing the gap
    /// to now ourselves.
    ///
    /// The naive check — verify the proof against the CURRENT A_tip — cannot work: A_tip advances every
    /// block (measured: it changes within 2s), so a proof is stale before a producer ever sees it and no
    /// honest spend can settle. The obvious repair, accepting any of the last K accumulators, is the
    /// WINDOW shape that has repeatedly made users' funds vanish, and it is not used here.
    ///
    /// Instead: the witness names its own tip via `(tip_prev, tip_bp, tip_td)`, so recompute
    /// `claimed_tip = fold(tip_prev, tip_bp, tip_td)` and verify the proof against THAT. Then prove the
    /// spender could not have hidden a spend that happened afterwards, by checking the nullifier against
    /// the blocks WE folded since — blocks we already hold, whose tag sets are recorded. Absence over
    /// base→claimed_tip (their proof) plus absence over claimed_tip→now (our own check) is absence over
    /// base→now.
    ///
    /// WHAT THIS BOUNDS, AND WHAT IT DOES NOT: it bounds how STALE A PROOF may be, never how OLD A NOTE
    /// may be. A note from block 1 stays spendable forever; if its proof has gone stale the wallet simply
    /// attaches a fresh one and the spend proceeds. No note ages out, no balance disappears — which is the
    /// precise failure the banned window caused.
    ///
    /// A forged `claimed_tip` fails closed: it must equal an accumulator this node actually passed
    /// through, and those are matched against our OWN recorded fold history, never taken on the
    /// spender's word.
    pub(super) fn nf_absent_by_reconstructed_tip(
        &self,
        nfs: &[[u8; 32]],
        w: &crate::nf_sparse::NfAbsenceWitness,
        carried: &[crate::nf_sparse::CompressedCopath],
    ) -> bool {
        // ⭐⭐⭐ ONE ROOT. VALIDITY IS A COPATH AGAINST IT — THE WHOLE GATE, NOTHING ELSE.
        //
        // user 2026-07-30: *"make monerousd one root and validity is a copath against that root just like
        // mina"* / *"remove the useless questions from our logic"*.
        //
        // WHAT THIS DELETED, and why every piece of it was a question Mina never asks:
        //   * "which fold TIP does your proof name?" — `claimed_tip`, recomputed then looked up in a fold
        //     history. A_tip MOVES EVERY BLOCK (~500ms), and building a spend takes seconds, so an honest
        //     spender was racing a value that had already changed. This gate anchored on a moving target
        //     TWICE before and broke sends both times.
        //   * "which BASE did you fold from?" — `named_base` / `base_is_ours` / `da_seq_at_nf_acc`. MEASURED
        //     live: node at `seq 102` while the payer honestly proved from `([0,0,0,0], seq 0)`, and the
        //     spend was REFUSED with a perfectly sound proof. A node that re-bases mid-send refused its own
        //     users.
        //   * "did anything settle AFTER that tip?" — the gap close, which needed a settling sequence per
        //     tag (`da_nfseq_mem`, 256 entries per block forever, 88% of the node's footprint).
        //
        // None of it decided anything the live root does not already decide. A spend is valid iff every one
        // of its nullifiers is ABSENT from the nullifier accumulator RIGHT NOW — non-membership under
        // `nullifier_root()`, the nullifier half of `state_root()`, proven by a copath and checked by folding
        // it. That is one question, asked against one root, at a fixed 2·DEPTH hashes per tag.
        //
        // STRICTLY SOUNDER, not merely simpler. The old chain could reject only what its own fold history
        // recorded, so a node that adopted by DSYNC admitted a double spend it had no inputs for; and it
        // refused honest spends for naming a tip or base this node had moved past. The live root is
        // authoritative for every tag at any age, recorded or not, because the root IS what consensus commits.
        //
        // The carried witness `w` is no longer consulted: there is nothing left for it to attest that the
        // root does not settle. It stays on the wire for now so older peers still parse a tx; the gate simply
        // does not depend on it.
        // ⭐⭐⭐ EITHER CRYPTOGRAPHIC PROOF SATISFIES THE GATE — AND BOTH FOLD AGAINST THIS NODE'S OWN ROOT.
        //
        // I removed the recursive absence proof from this gate earlier today, judging it a "useless question"
        // because it anchored on A_tip, a value that moves every ~500ms. The moving anchor WAS a real defect;
        // deleting the whole mechanism was not, and the live pair said so immediately.
        //
        // WHY BOTH ARE NEEDED, stated as the property that distinguishes them: a NOTE copath is append-only —
        // frozen once, valid forever — so a spender can hold it. A nullifier NON-MEMBERSHIP copath is not:
        // every insertion anywhere in the sparse tree invalidates it. So a spender cannot hold one; it must
        // MAINTAIN it, which is exactly what the recursive absence carrier does in O(1) per block.
        //
        // MEASURED, the live consequence of having only the copath path: `[nf-gate] witness source for input
        // 0: carried (carried=32 of 32 inputs, copath len 256)` — the spender carried all 32 witnesses, the
        // right length, and they still failed. The node had served them from `da_nf_node_mem`, which after
        // today's storage deletion is IN-RAM ONLY and persisted NOWHERE (0 references in persist.rs), while
        // `sparse_acc` IS restored from the O(1) snapshot (4 references). After any restart the accumulator
        // resumes at height 150k with an EMPTY index, so every copath folds to the empty-tree root and an
        // UNSPENT tag reads SPENT — honest money refused.
        //
        // NOT a weakened gate: each branch is a full cryptographic check against `sparse_acc`, this node's own
        // root. A forged, stale or foreign witness fails both. What the union removes is a FALSE REFUSAL when
        // one witness kind is unavailable for reasons that have nothing to do with the spender's honesty.
        // ⛔⛔⛔ A POSITIVE PROOF OF SPENTNESS ALWAYS WINS — CHECKED BEFORE ANY ACCEPT PATH.
        //
        // My first union let a valid absence proof accept on its own, and two tests caught it immediately:
        // `…_rejects_spent` and `brick_c4_…_rejects_spent_and_forged`. They were right and the union was
        // wrong. An absence proof attests absence THROUGH THE TIP IT FOLDED — not absence NOW — so a tag
        // spent after that tip still carries a cryptographically valid proof. That is precisely the gap the
        // deleted settling index used to close, and dropping it re-opened a double-spend.
        //
        // The sound composition is not OR. A tag that this node can POSITIVELY prove spent (its copath
        // reproduces the live root with the SPENT leaf) is refused unconditionally, whatever it carries. Only
        // then may an absence proof supply the liveness half — answering for a restarted or DSYNC-adopted
        // node whose local index cannot describe the tree, where the alternative is refusing honest money.
        // ⛔⛔⛔ `Unprovable` IS NOT `Unspent`. This tested only `== Spent`, so a verdict of `Unprovable` —
        // which by its own definition "proves NOTHING" — fell through as if the tag were absent, and the
        // stale-but-valid absence proof then carried the accept on its own. That is a DOUBLE SPEND, and it is
        // the hole my storage deletion opened: `da_sparse_copath` reads a local index that no longer survives
        // a restart, so the check that was supposed to catch a settled tag simply could not fire.
        //
        // CAUGHT BY: `a_stale_absence_proof_still_settles_while_forged_and_overtaken_ones_are_rejected` step 3
        // ("once the input settles, the stale proof is a DOUBLE-SPEND and must be rejected") and
        // `the_gate_admits_a_full_width_batched_absence_proof_and_rejects_a_settled_member`. Both were RED and
        // both were right.
        //
        // `SpentVerdict`'s own doc states the rule: "Fail-closed belongs at the GATE, which requires a POSITIVE
        // proof of absence." So the gate demands `Unspent` under the LIVE root — not merely "not Spent".
        // Guessing "unspent" from an index that cannot describe the tree admits a double spend; that is never
        // an acceptable trade, and an absence proof cannot substitute because it attests absence THROUGH ITS
        // OWN TIP, not absence NOW.
        //
        // OBSERVABILITY: the verdict that DECIDED is named, and the three are counted per tx. "Rejected" told
        // us nothing all session; "Unprovable ⇒ this node's index cannot describe its own tree" is what
        // distinguishes a genuine double-spend from a node that lost its index and is refusing honest money.
        // ⛔⛔⛔ THE COPATH GATE IS DELETED — IT DEMANDED THE STRUCTURALLY IMPOSSIBLE.
        //
        // The header's "nullifier root" IS the A_tip fold accumulator (`adopt_sparse_via_block_fold` commits
        // `leaf_to_cm_bytes(post_acc)`), not a Merkle root. A Merkle copath can never fold to it, so every
        // verdict was `Unprovable` BY CONSTRUCTION — measured live as `0 unspent / 0 spent / 1 unprovable`
        // on an untouched faucet note, on a fresh chain, on every node. The fold-not-hold carrier is the one
        // authority that can exist here, and with the serve now reproducing the fold byte-for-byte
        // (instrument: served 3/3, verifier 3/3, tips agree) an honest spender can finally converge to it.
        //
        // THE SOUND COMPOSITION (no held tree, no copath, no window):
        //   1. the carried recursive proof must VERIFY — absence of every input through the tip it NAMES;
        //   2. the named tip must be an accumulator THIS CHAIN HELD (live, or recognised by the written-down
        //      acc->seq index) — a spender cannot invent a start or end point;
        //   3. the GAP between the named tip and the live tip is swept against the REAL spends recorded per
        //      block (`da_nf_load`), which are stored VERBATIM — no regeneration, no tree. A tag settled
        //      after the proof's tip is caught HERE; a decoy colliding with a real nullifier is a 2^-256
        //      event. Stale settles, forged rejects, overtaken rejects — no age refusal anywhere.
        //
        // ⚠️ THE SWEEP IS NOT O(1), AND IS NOT CLAIMED TO BE (user 2026-07-31: "be sure not to add a
        // O-chain growth vector... I see you cited it as reviewed"). Its trip count is the STALENESS of this
        // one proof — a quantity the SPENDER controls (a live wallet keeps its carrier within 0..~3 blocks of
        // the tip, and the swept count is printed so real staleness is MEASURED, not assumed), priced by the
        // tx's own PoW stamp, and costing ZERO stored state: it reads only the per-block reals the DA ledger
        // already keeps. Nothing is refused for age — an arbitrarily stale proof still settles.
        //
        // THE SHAPE THAT RETIRES IT (the recursive endgame): the tx carries its RESUMABLE carrier state and
        // the NODE steps every pooled carrier by one block as it applies that block — tags in hand at apply,
        // O(pool) per block, no history read anywhere. Endpoint-at-inclusion then equals the live tip BY
        // CONSTRUCTION and this sweep deletes. Until that lands, this is the honest bridge, stated as such.
        if nfs.is_empty() {
            return true;
        }
        // ⛔⛔⛔ DB-160 — A POSITIVE PROOF OF SPENTNESS WINS, CHECKED BEFORE EVERY ACCEPT PATH.
        //
        // ROOT-LAYER: this is the ONLY point in the gate that can see a nullifier published BELOW the
        // certified fold base, and without it the chain has a live double spend.
        //
        // MEASURED 2026-09-24 with this node's own gate
        // (`a_tag_that_settled_below_the_certified_base_is_not_provable_absent`, which was RED against the
        // shape that shipped): a tag the chain had already absorbed was proven absent and ADMITTED —
        // `[nf-gate] ADMIT: 1 input(s) — recursive absence proof verified THROUGH THE LIVE TIP`.
        //
        // WHY LANE B CANNOT SEE IT. `verify_nf_absence_batch_chain` attests, in its own words, that every
        // nullifier is *"absent from every block BETWEEN `genesis_acc` AND THE TIP"* — over the SPAN. Since
        // `nf_fold_base` began advancing on the DAG's quantized horizon (2026-09-23) that span is a WINDOW,
        // and blocks below it are absorbed into an accumulator that is a WRAPPING SUM of domain-separated
        // leaves. A sum cannot express non-membership. So: spend a note, wait `keep_depth` blocks for its
        // block to fall below the base, and spend it again — the note commitment lives in an append-only
        // frontier forever, so nothing else refuses the second spend.
        //
        // ⛔ `Spent` REFUSES; `Unprovable` DOES NOT. That asymmetry is the whole design of this check and it
        // is not a softened bound. A node that is treeless (restarted, or DSYNC-jumped and still warming —
        // ~98 minutes at 732 us/tag) answers `Unprovable` for everything, and refusing on that would refuse
        // HONEST money on every such node, which is DB-149 exactly. Positive evidence of a double spend is
        // actionable; absence of evidence from a node that admits it cannot describe its own tree is not.
        //
        // ⛔⛔⛔ AND ITS COVERAGE IS `NF_SHARD_REPLICATION / mesh`, NOT 1. MEASURED
        // (`the_db160_containment_covers_only_a_shrinking_share_of_the_tag_space_as_the_mesh_grows`):
        //
        //     mesh 4: 100.0%   mesh 8: 50.0%   mesh 16: 25.0%   mesh 64: 6.2%   mesh 256: 1.6%   mesh 1024: 0.4%
        //
        // The full-history view this reads is Z2-SHARDED, so a tag whose shard this node does not hold
        // answers `Unprovable` and passes. A security control whose strength FALLS as the network grows is
        // strongest exactly where it matters least — and every fixture, and the live pair, run at a mesh
        // too small to shard, which is the only reason this reads as a containment at all.
        //
        // ⛔ THIS DOES NOT CLOSE DB-160 EVERYWHERE, AND SAYING SO IS THE POINT: a node whose view is cold
        // still cannot see below its base, and at a production mesh 99% of tags are outside its share.
        // The complete fix is a COMMITTED Merkle nullifier root (DB-154) — then a spender carries a
        // non-membership copath against the header's own root and the verifier holds a SINGLE root, which
        // every node already holds unsharded (`sparse_acc` is one `Digest4` over the whole history; only
        // the witness-SERVING tree is sharded). DB-153 and DB-154 are one problem: the chain commits a SUM
        // where it needs a SET. This is a partial containment that trades no pillar, not the cure.
        // ⭐⭐⭐ DB-198 (DB-154 step 4) — ASK THE FULL-HISTORY ACCUMULATOR WITH THE **SPENDER'S** COPATH,
        // NOT THIS NODE'S SHARD.
        //
        // ⛔ WHAT THE OLD LINE MEASURED. `sparse_spent_verdict(nf)` sources its copath from
        // `da_sparse_copath` — this node's LOCAL, Z2-SHARDED serving tree. A tag whose shard this node
        // does not hold yields no usable copath, answers `Unprovable`, and PASSES. So the containment's
        // coverage was `NF_SHARD_REPLICATION / mesh`:
        //     mesh 4: 100.0%   mesh 8: 50.0%   mesh 64: 6.2%   mesh 256: 1.6%   mesh 1024: 0.4%
        // A security control whose strength falls as the network grows, strongest exactly where it
        // matters least. It read as a containment only because every fixture and the live pair run at a
        // mesh too small to shard.
        //
        // ⭐ THE AUTHORITY WAS ALREADY RIGHT; THE INPUT WAS WRONG. `sparse_acc` is ONE `Digest4` over the
        // WHOLE history and is NOT sharded — only the witness-SERVING tree is. The verdict is
        // `sparse_acc.spent_verdict(nf, copath)`, so the only thing the shard supplied was the COPATH.
        // The spender already carries one (`carried`, self-built from the replicated DA stream — the
        // trustless shape [[feedback_always_trustless]] blesses), and using it makes the check
        // full-history for EVERY tag at ANY mesh size, with no tree consulted at all.
        //
        // ⛔ AND IT CANNOT BE GAMED, WHICH IS WHY THE SPENDER MAY SUPPLY IT. `spent_verdict` accepts a
        // copath only if it FOLDS TO THE ACCUMULATOR'S OWN ROOT — `fold_sparse(empty_leaf(), ..) == root`
        // for Unspent, `fold_sparse(spent_leaf(), ..) == root` for Spent. A forged copath folds to
        // neither and returns `Unprovable`, so a spender cannot make a SPENT tag read UNSPENT without a
        // Poseidon collision. This node's own root remains the sole authority.
        //
        // ⛔ `Unprovable` STILL PASSES, deliberately and unchanged. A merely STALE copath (built before
        // recent blocks) cannot fold to the current root, and refusing on that would reject honest
        // spenders for a timing difference they do not control — recency is the gap sweep's job, as the
        // carrier arm below already says. So this strictly ADDS definite `Spent` verdicts; it refuses
        // nothing that was admitted before for an honest reason.
        // ⛔⛔⛔ DB-217 (2026-09-25) — ADMISSION NOW REQUIRES A **POSITIVE** PROOF OF ABSENCE FOR EVERY TAG.
        //
        // MEASURED by the prover lane (DB-213c, `usdm-decider/src/db213_forgery_census.rs`, each arm
        // calibrated against the honest prover): the recursive fold verifiers behind Lane B certify
        // statements with NO witness behind them — `verify_nf_absence_chain` / `_batch_chain` return TRUE
        // for a nullifier INSIDE the tip block's own tags. So the carrier below is not an authority at all,
        // and every path that let it admit on its own was a double spend wherever this loop answered
        // `Unprovable`: a restarted or jumped node (cold view), any node at a mesh large enough to shard,
        // and — DB-160 — any tag that settled below the moving base.
        //
        // THE RULE, borrowed rather than invented (Zcash: a spent note is refused by the SET): every tag
        // must fold to `sparse_acc` — ONE full-history root, unsharded — as UNSPENT, by the spender's carried
        // copath or, failing that, by this node's own view. `Spent` REJECTS (unchanged). `Unprovable` now
        // REFUSES: a node that cannot describe its own tree cannot vouch for absence, and the carrier that
        // used to stand in for it vouches for nothing. Everything the old gate required AFTER this loop is
        // still required — this adds a precondition and removes no check.
        //
        // NEW-DOOR CHECKLIST (§9.6), answered for the changed admission logic:
        //   1. PoW — the tx stamp is checked by the pool door before this runs; unchanged.
        //   2. Proof — the ONLY proof trusted here is a copath folding to this node's own root
        //      (`spent_verdict`: EMPTY leaf ⇒ Unspent, SPENT leaf ⇒ Spent, neither ⇒ Unprovable). A forged
        //      copath folds to neither. No recursive carrier is trusted (DB-213c).
        //   3. Conservation — not this door's job (the spend's validity carrier); this door refuses
        //      DUPLICATION, which is how value is created twice.
        //   4. Replay — refused by the SET: a repeat of a settled tag folds to the SPENT leaf.
        //   5. Bounded work — 2·DEPTH hashes per tag (one carried fold, at most one local-view fold) over
        //      the protocol-constant tag count. No history is walked.
        //   6. Parity — the door this parallels is block apply (`verify_and_insert`), which admits a tag
        //      into the set only on a non-membership copath against the same root. Admission now asks the
        //      same question the apply asks; before, it could admit what the apply would silently drop.
        //
        // cons, stated: a node whose view cannot answer (restarted and still warming, DSYNC-jumped, or not
        // holding the tag's shard) REFUSES an honest spend that carries no copath until its view answers or
        // the spender carries one — a LIVENESS cost on that node, fail-closed on the item, never a halt
        // (any node that can answer admits it). Before this, the same node ADMITTED a forged double spend.
        let mut unproven = 0usize;
        for (i, nf) in nfs.iter().enumerate() {
            let carried_verdict = carried
                .get(i)
                .and_then(crate::nf_sparse::expand_copath)
                // THE COPATH CURRENCY's one layout: `NF_COPATH_LEN` (the 256 siblings + the terminal slot, DB-453 brick 2).
                // This read `NF_SPARSE_DEPTH` (256) after the terminal slot landed, so `expand_copath`'s 257 never matched
                // and EVERY carried copath was dropped here — a node blind to a spender's shard refused every honest spend.
                .filter(|cp| cp.len() == crate::nf_sparse::NF_COPATH_LEN)
                // The spender's own witness, judged against a band root the door can place, with every applied AND
                // pending step after it swept (P2', §13.5).
                .map(|cp| self.pool_copath_verdict(nf, &cp));
            let verdict = match carried_verdict {
                Some(v) if v != crate::nf_sparse::SpentVerdict::Unprovable => v,
                // No carried witness, or one that describes no root this node holds: ask the local verdict, which reads
                // the fold's decided spends and an unfolded block's lane before the lagging view. A garbage copath can
                // therefore never HIDE a tag this node can prove spent.
                _ => self.sparse_spent_verdict(nf),
            };
            if verdict == crate::nf_sparse::SpentVerdict::Spent {
                // DIGITAL-CASH-PRIVACY-REVIEWED: an input COUNT and a branch name — never a tag, amount,
                // key, owner or accumulator value.
                eprintln!(
                    "[nf-gate] REJECT: this node can POSITIVELY prove one of the {} input(s) already SPENT \
                     against its own full-history nullifier view — refused whatever it carries, because an \
                     absence proof attests only over its own span and the tag may have settled below the \
                     certified base (DB-160); slot {i} ({})",
                    nfs.len(),
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a SLOT of a constant-width list (slot 0 is every spend's own tag, the rest its
                    // cover tags) — a position in a fixed shape, never a tag, note, amount or owner.
                    if i == 0 { "the spend's own tag" } else { "a cover tag" }
                );
                return false;
            }
            if verdict != crate::nf_sparse::SpentVerdict::Unspent {
                unproven += 1;
            }
        }
        if unproven > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two COUNTS and a branch name — never a tag, copath, amount,
            // key, owner or accumulator value.
            eprintln!(
                "[nf-gate] REFUSE: {unproven} of {} input(s) have NO POSITIVE proof of absence against this \
                 node's full-history nullifier root — no carried copath folds to it and this node's own view \
                 cannot answer (warming after a restart, jumped, or not holding that shard). The recursive \
                 carrier is not an authority (DB-213c). Nothing was admitted and the note is untouched: \
                 carry a copath, or submit to a node whose view answers (DB-217).",
                nfs.len()
            );
            return false;
        }
        // ⭐ THE CARRIER AT ITS BASE — an EMPTY proof span, answered by state this node already
        // wrote down (hole-closure 2026-09-06, lane A: the shape that let the OrderFill copath
        // arm be deleted from the caller, so the door is ONE rule for every class).
        //
        // A settlement's inputs are born WITH the settlement — the maker and taker tags plus the
        // tx-id-seeded cover set — so no carrier for that exact set can predate it: the freshest
        // recursive absence carrier any submitter can hold is `NfAbsenceBatchCarrier` AT ITS
        // GENESIS BASE, zero blocks folded. The witness DECLARES that state by naming the chain's
        // REAL genesis base with an empty proof. A tx that simply carries nothing arrives here as
        // the DEFAULT witness, whose base is the zero literal, and stays refused by the
        // no-proof reject below — measured RED-first by
        // `a_copath_only_fill_without_the_recursive_carrier_is_refused_on_both_parties`.
        //
        // WHAT ADMITS IT — two authorities composed, both O(1) per tag, both already written
        // down (no history is walked here):
        //   1. the declared base must BE the genesis base, AND this node must have folded from it
        //      (`nf_fold_base == (genesis, 0)`). A jump-adopted node cannot vouch for the span it
        //      leapt and REFUSES this shape outright — fail-closed, never a guess;
        //   2. carried copaths verified against the LIVE sparse root in the caller
        //      (`carried` non-empty, or this lane refuses). On a genesis-folded node,
        //      `sparse_acc` IS the written-down settled set for its whole history — a fixed
        //      2·DEPTH hashes per tag, no term in height — and it also covers engine-applied
        //      burns no block has carried yet, which no fold history could show.
        //
        // WHAT THIS DOES NOT CLAIM, stated plainly: a genesis-folded node that silently dropped a
        // non-folding copath at apply (`sparse_apply_with_copath`) holds a root that misses that
        // settlement, and this lane inherits that residual exactly as the deleted class arm did —
        // narrowed here to genesis-folded nodes and to submitters that DECLARE the base-state
        // carrier. The shape that retires the residual is the resumable pooled carrier (the tx
        // carries its carrier state; the node steps the pooled carriers as it applies a block, so
        // the freshest carrier is AT the live tip by construction) — the fold-it shape, and this
        // lane deletes when it lands.
        // ⭐⭐⭐ §CC — THE BASE MAY BE GENESIS **OR** THIS NODE'S CERTIFIED ADOPTED BASE.
        //
        // ⛔ NARROWING THIS TO GENESIS MADE EVERY DSYNC JOINER UNABLE TO SPEND — and DSYNC is the only join
        // the project offers. The widened arm still demands the two things that actually decide: the
        // witness declares THIS node's own base (a chain value bound in `sync_binding`, never local
        // opinion), and every tag carries a copath that VERIFIES AGAINST THE LIVE SPARSE ROOT. The second
        // is the substantive check and it is unchanged: a tag already spent fails its live-root copath
        // whatever base was declared, so a forged base buys an attacker nothing.
        // ⭐ THE BASE NOW MOVES, SO THE BOUNDARY MUST BE ACCEPTED TOO. Two honest nodes cross the DAG
        // horizon a block apart; a spender that rooted at the newer base would otherwise be refused by
        // the node still on the older one, for a timing difference neither party controls. Exactly two
        // values, and neither refuses anything for age.
        if w.proof.is_empty()
            && (w.base_acc == self.nf_fold_base.0 || w.base_acc == self.nf_base_prev)
        {
            if !carried.is_empty() {
                // Privacy: a count and a branch name only — never a tag, copath, amount or owner.
                eprintln!(
                    "[nf-gate] ADMIT: {} input(s) — base-state carrier from the genesis base on a \
                     genesis-folded node, every tag proved UNSPENT against the live root by its \
                     carried copath",
                    nfs.len()
                );
                return true;
            }
            // A DECLARED base-state carrier this node cannot vouch for (jumped fold base, or no
            // carried copaths): fall through to the fail-closed no-proof reject below.
        }
        if w.proof.is_empty() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count and a branch name; no tag, amount, key or owner.
            eprintln!(
                "[nf-gate] REJECT: {} input(s) carried NO absence proof — the recursive carrier is the sole \
                 spend authority (the node holds no tree to answer from), so nothing can settle without it",
                nfs.len()
            );
            return false;
        }
        let limbs: Vec<crate::spend_frontier::Digest4> = nfs
            .iter()
            .map(usdm_decider::nf_sparse_air::nf_to_limbs)
            .collect();
        let claimed_tip =
            usdm_decider::nf_sparse_air::nf_unspent_step_new_acc(w.tip_prev, w.tip_bp, w.tip_td);
        if !usdm_decider::nf_sparse_air::verify_nf_absence_batch_chain(
            &w.proof,
            &limbs,
            w.base_acc,
            w.tip_prev,
            w.tip_bp,
            w.tip_td,
            claimed_tip,
        ) {
            eprintln!(
                "[nf-gate] REJECT: the carried absence proof does not verify — forged or malformed (a merely \
                 STALE proof still verifies; recency is the gap sweep's job, not the proof's)"
            ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only; no tag, sequence, amount, key or owner.
            return false;
        }
        // The base the proof grew from must be one this chain held: genesis-zero, this node's certified jump
        // base, or any acc the written-down index recognises. A fabricated base can prove anything after it.
        let (jump_base, _) = self.nf_fold_base;
        // ⛔⛔⛔ THE GENESIS EXEMPTION NAMED A VALUE THIS CHAIN NEVER HOLDS. It tested `w.base_acc != [0u64;4]`,
        // but A_tip's genesis is `nf_unspent_acc_genesis()` — `blake3("MUSD-nf-unspent-acc-genesis-v1" ‖
        // network_id)` folded to limbs, never the zero literal. So an HONEST spend proving from the chain's
        // actual genesis base fell through to `da_seq_at_nf_acc`, and any node that had re-based past it
        // answered None and REFUSED a perfectly sound proof — the "node at seq 102 refuses a payer proving
        // from seq 0" symptom. The zero literal only ever matched a default-initialised witness.
        // Keep BOTH: `[0u64;4]` stays accepted for wire compatibility with a witness that never set a base.
        let genesis_base = Self::nf_unspent_acc_genesis();
        // ⭐ …AND THE IMMEDIATELY PREVIOUS ONE, for the same one-block horizon race. `nf_fold_base` is no
        // longer written once at a DSYNC adopt and left there: it advances as each block crosses
        // `Dag::horizon_blue_score`, a value every node derives from the same DAG, so the span a spender
        // must prove is bounded by `keep_depth` rather than by how long ago its node adopted.
        if w.base_acc != usdm_decider::poseidon2_compress::zero_digest()
            && w.base_acc != genesis_base
            && w.base_acc != jump_base
            && w.base_acc != self.nf_base_prev
        {
            eprintln!(
                "[nf-gate] REJECT: the base this proof names is neither the genesis base nor this node's \
                 certified jump base"
            ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only.
            // (The index that once sat behind this test — `da_nacc_rev_mem`, written only at a DSYNC
            // adopt — is deleted with the sweep it fed; `nf_fold_base` IS the certified jump base, bound
            // in `sync_binding`, so a value that is neither it nor genesis is foreign to this node.)
            return false;
        }
        // ⛔⛔⛔ THE ENDPOINT IS THE LIVE ACCUMULATOR — ONE AUTHORITY FOR "SPENT" (D-41 class, 2026-09-11).
        //
        // What stood here was a SWEEP: any endpoint the node once held was accepted, and the gap between it
        // and the live tip was scanned against `da_nf_mem`, a per-block store of "the reals this node saw".
        // That store had THREE key spaces (the accept ordinal `nf_fold_seq-1`, the sparse-fold ordinal
        // `nf_blocks-1` on the produce path, and a served page's record id), so a producer's own block
        // overwrote an accept row whenever the two counters disagreed — and they disagree by construction
        // on a DAG, because the sparse fold parks sibling blocks. MEASURED (fuzz lane, 48-op catalogue):
        // party 0 held 11 rows where a chain-only replay derived 25. A sweep over an incomplete ledger
        // ADMITS the double-spend it cannot see; the recognised-endpoint index (`da_nacc_rev_mem`) was
        // written only at a DSYNC adopt, so in practice the sweep ran exactly for carriers rooted at a jump
        // base on a node that had produced since — the narrow case where its rows were wrong.
        //
        // BORROWED (Zcash): the nullifier set is authoritative at the present instant; an anchor is
        // accepted only as a value the chain committed, and nothing is "swept". This node holds no set by
        // design, so the only value it can vouch for at the present instant is its live accumulator: the
        // endpoint must equal it. A carrier that folded through an older tip is refused with its reason
        // named, and the SPENDER rebuilds it one block forward (its own O(1) step); the note is untouched
        // and stays spendable at any depth. Nothing about the NOTE is refused for age — only a proof that
        // stopped short of the present.
        //
        // Deleted with the sweep: `da_nf_mem` (+ `da_nf_store` / `da_nf_load` / `da_nf_tags_wire`, the
        // served `nf_tags` sidecar write), `da_nacc_rev_mem` (+ `da_store_nf_acc` / `da_seq_at_nf_acc` /
        // `nf_acc_index_len`) and the dead `is_nullifier_spent` scan. No per-block store is read here.
        // O1-DEFINITION-REVIEWED: one comparison of two fixed-width values; no history term.
        let live = self.nf_unspent_acc;
        if claimed_tip == live {
            // DIGITAL-CASH-PRIVACY-REVIEWED: an input count and a branch name only.
            eprintln!(
                "[nf-gate] ADMIT: {} input(s) — recursive absence proof verified THROUGH THE LIVE TIP",
                nfs.len()
            );
            return true;
        }
        // ⭐⭐ DB-246 — A CARRIER A FEW BLOCKS SHORT OF THE LIVE TIP, JUDGED EXACTLY (spec:
        // docs/DB-246-ABSENCE-DOOR-RECENT-ANCHOR.md).
        //
        // A_tip moves every accepted block, about two per second, and an honest carrier always arrives after
        // its prove and a Tor submit. Exact equality therefore refused every real send (3 of 3 measured,
        // 3.8–68.7 s). The carrier names the tip antichain `T` of the span it folded, which is a coordinate
        // every node shares. This node derives the gap from its OWN recent folds, then demands:
        //   * the exact accounting `claimed + Σ leaf(gap) == live`. That one equation proves:
        //     - the carrier's set lies inside this node's accepted set;
        //     - every accepted block outside the ring lies inside `closure(T)`;
        //     - the gap is exactly what the carrier did not fold;
        //   * the sweep: no input tag in any gap block.
        // DB-217's positive-Unspent check ran FIRST above and stays the authority, so this branch can only
        // unblock an honest stale carrier, never admit a spent tag on its own.
        let gap = match self.recent_fold_gap(&w.tips) {
            Ok(g) => g,
            Err(why) => {
                // DIGITAL-CASH-PRIVACY-REVIEWED: an input count and a fixed reason string only.
                eprintln!(
                    "[nf-gate] REFUSE: {} input(s) — the carried absence proof ends at a tip that is NOT this \
                     node's live accumulator, and its gap cannot be accounted: {why}. Rebuild the carrier at \
                     the tip and resubmit; the input is untouched.",
                    nfs.len()
                );
                return false;
            }
        };
        let mut accounted = claimed_tip;
        for f in &gap {
            accounted = usdm_decider::nf_sparse_air::nf_unspent_acc_add(accounted, f.leaf);
        }
        if accounted != live {
            // DIGITAL-CASH-PRIVACY-REVIEWED: counts only — never an accumulator value, tag or owner.
            eprintln!(
                "[nf-gate] REFUSE: {} input(s) — the carrier's folded set plus this node's {} recent block(s) \
                 outside its tips does not sum to the live A_tip: the carrier is older than the recent-fold \
                 ring, or its tips do not close over what it folded",
                nfs.len(),
                gap.len()
            );
            return false;
        }
        if gap.iter().any(|f| nfs.iter().any(|nf| f.tags.contains(nf))) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: an input count only — never which tag or which block.
            eprintln!(
                "[nf-gate] REJECT: {} input(s) — a tag this carrier proves absent SETTLED in a block after it \
                 (the DB-246 gap sweep)",
                nfs.len()
            );
            return false;
        }
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts only.
        eprintln!(
            "[nf-gate] ADMIT: {} input(s) — recursive absence proof verified through a tip {} block(s) short \
             of live, the gap accounted exactly and swept (DB-246)",
            nfs.len(),
            gap.len()
        );
        true
    }
    /// The lowest ordinal of the rewind journals' effective window: tip + 1 − `SPINE_RING_LEN` (tip = `served_seq` − 1).
    pub(crate) fn rewind_window_floor(&self) -> u64 {
        self.served_seq.saturating_sub(Self::SPINE_RING_LEN as u64)
    }

    /// ⭐ DB-223 / DB-274 P3 — the ANCHOR RING's reach in fold steps: the governance merge depth (each fold step adds at
    /// least one blue score, so `merge_depth_cap` steps cover every block DB-361 lets a node merge), never below the
    /// rewind ring. One definition, read by the push, the restore and the pins.
    pub(crate) fn anchor_ring_len(&self) -> usize {
        Self::anchor_ring_len_of(self.params())
    }

    /// [`Self::anchor_ring_len`] for a parameter set — the ONE definition the node's ring and stream window and the
    /// wallet's member witness book (which keeps the same reach of stream entries) all read.
    pub(crate) fn anchor_ring_len_of(p: &crate::params::ChainParams) -> usize {
        crate::params::anchor_ring_len_of(p)
    }

    /// ⭐ DB-223 / DB-274 P3 — whether this node holds the CANONICAL anchor ring for its fold position `k` (its newest
    /// folded ordinal): the dense ordinals `max(1, k − W + 1) ..= k`, W = [`Self::anchor_ring_len`] (ordinals start at 1;
    /// genesis holds 0 and folds nothing). Only a complete ring may be certified or served — a node holding a partial
    /// one (fresh after an adopt, a restart whose checkpoint carried none) answers "not yet" rather than vouch for it.
    pub(crate) fn anchor_ring_is_complete(&self) -> bool {
        let Some(&(k, _)) = self.spine_recent_roots.back() else {
            return false;
        };
        let want = (self.anchor_ring_len() as u64).min(k);
        self.spine_recent_roots.len() as u64 == want
            && self
                .spine_recent_roots
                .iter()
                .zip(self.spine_recent_roots.iter().skip(1))
                .all(|(a, b)| b.0 == a.0.saturating_add(1))
    }

    /// ⭐ DB-223 Q7 — whether this node holds EXACTLY the canonical pre-state ring for folding step `ordinal`: the dense
    /// ordinals `max(1, ordinal − W) ..= ordinal − 1` (W = [`Self::anchor_ring_len`]). The fold judges a stated spend's
    /// anchor against it, so "not in the ring" is a verdict only when the ring is this one; a node folding its FIRST step
    /// holds the empty ring, which is complete (no spine root exists yet, so no anchor can be this chain's).
    pub(crate) fn anchor_ring_is_canonical_before(&self, ordinal: u64) -> bool {
        let w = self.anchor_ring_len() as u64;
        let lo = ordinal.saturating_sub(w).max(1);
        let Some(hi) = ordinal.checked_sub(1).filter(|h| *h >= lo) else {
            return self.spine_recent_roots.is_empty();
        };
        self.spine_recent_roots.len() as u64 == hi - lo + 1
            && self.spine_recent_roots.front().map(|(o, _)| *o) == Some(lo)
            && self.spine_recent_roots.back().map(|(o, _)| *o) == Some(hi)
            && self
                .spine_recent_roots
                .iter()
                .zip(self.spine_recent_roots.iter().skip(1))
                .all(|(a, b)| b.0 == a.0.saturating_add(1))
    }

    /// The anchor ring, oldest first — what a certificate binds (via [`crate::sync::anchor_ring_digest`]) and a bundle
    /// ships (DB-274 P3).
    pub(crate) fn anchor_ring(&self) -> Vec<(u64, crate::spend_frontier::Digest4)> {
        self.spine_recent_roots.iter().copied().collect()
    }

    /// ⭐⭐ DB-274 P4 (§8.11 item 7) — THE ONE FOLD-TIME ROW STRIP, shared by DB-358's respend verdict and P4's credit
    /// verdict. Both strip the same staged row at the same fold, and a journal is only rewind-exact if it holds ORIGINAL
    /// positions. So any earlier strip of this block's row is put back first: the respend strip of this same fold, or
    /// this block's own strip from a refused fold now being retried. Then the UNION is stripped once, and the journal
    /// keeps every original position. One `respend_pop_journal` restores the row byte-for-byte.
    ///
    /// Returns how many notes this call NEWLY stripped: the union minus what the earlier strip already held.
    ///
    /// MEASURED by reading, 2026-09-30: before this helper, a fold refused after its respend strip (the record was not
    /// yet held) and then retried re-ran the strip on an already-stripped row. That strip found nothing and OVERWROTE
    /// the journal with an empty revoked list, so a later rewind could not put the notes back, and the spine root
    /// diverged from a node that never retried. Pinned by `db274_p4_a_refused_then_retried_fold_still_rewinds_its_row_exactly`.
    /// ⭐⭐⭐ A NOTE NOTHING JUSTIFIES NEVER ENTERS A FOLDED RECORD, WHICHEVER LANE BROUGHT IT. A block's notes do not ride its wire
    /// frame: a receiver gets them from the record lane (`apply_backfilled_notes`), which checks them against the block's root and
    /// writes the row. The root only says the producer committed those bytes, and the note door (`graft_admitted_notes`) ran
    /// only where a body arrived whole, so a producer could commit a note out of nothing and every honest record held it.
    /// MEASURED (real nodes, 2026-11-04, a patched producer that keeps a mint's justifier to itself): honest nodes logged no
    /// refusal, judged no credit object, and a wallet read through each held the 7.77. Judged HERE, at the fold, the one step every
    /// node runs in one canonical order, on the row as the producer committed it, by the note door's own rule over what the block
    /// carries: its credit set, its proven spends, its bond class, its one seed note. The node's own pool plays no part (the door
    /// is handed no tx ids), so every node strips the same notes. BORROWED-FROM Bitcoin: a block's outputs exist only if the
    /// block's own contents justify them, checked by every validator when it connects the block; Zcash Sapling's value balance.
    /// NEW-DOOR CHECKLIST: this is the last gate on an existing door. (1) PoW: the block was grafted. (2) Proofs: the transition
    /// verifies here, only when the credit set alone does not justify every note. (3) Value: what it refuses leaves the row; it
    /// admits nothing. (4) Replay: the nullifier set, unchanged. (5) Work: one ledger verify at most per block with a spend, none
    /// on a quiet block. (6) Parity: the same function as the graft door. cons: that verify per spending block at its fold, in
    /// exchange for the one the door could not run without the body; nothing stored.
    pub(super) fn fold_strip_unjustified_notes(&mut self, b: &crate::block::BlockId, seq: u64) -> usize {
        let Some(body) = self.unfolded_blocks.iter().find(|x| x.id() == *b).cloned() else { return 0 };
        let Some(header) = self.relay.dag().get(b).map(|n| n.header.clone()) else { return 0 };
        let Some((mut row, key)) = self.da_mem.get(&seq).map(|r| (r.0.clone(), r.3)) else { return 0 };
        // The row as committed: a retried fold puts this block's earlier strip back first.
        if let Some((_, earlier)) = self.respend_journal.get(b) {
            for (i, note) in earlier {
                row.insert((*i).min(row.len()), note.clone());
            }
        }
        let idle_seed = crate::cover::public_idle_seed_note(seq);
        let raw: Vec<u8> = row.iter().filter(|n| n[..] != idle_seed[..]).flat_map(|n| n.iter().copied()).collect();
        if raw.is_empty() {
            return 0;
        }
        let lane = &body.nullifier_proof.padded_tags;
        let held = || Some((header.clone(), Vec::new()));
        let by_objects = self.graft_admitted_notes_given(b, held(), &raw, Some(key), None, None, None, &body.credit_set, &body.wide_objects, &[], lane, &body.oli_tags);
        if by_objects.len() == raw.len() {
            return 0;
        }
        let admitted = self.graft_admitted_notes_given(
            b,
            held(),
            &raw,
            Some(key),
            body.note_transition.as_ref(),
            body.member_transition.as_ref(),
            body.cover_transition.as_ref(),
            &body.credit_set,
            &body.wide_objects,
            &body.bond_set,
            lane,
            &body.oli_tags,
        );
        if admitted.len() == raw.len() {
            return 0;
        }
        let kept: std::collections::HashSet<&[u8]> = admitted.chunks(crate::cover::PQ_NOTE_BYTES).collect();
        let gone: std::collections::HashSet<[u8; 32]> = raw
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .filter(|c| c.len() >= 32 && !kept.contains(c))
            .map(|c| {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&c[..32]);
                cm
            })
            .collect();
        // DIGITAL-CASH-PRIVACY-REVIEWED: a count of notes a rogue block carried, and no cm, amount, key or owner.
        eprintln!("[fold] ⛔ {} note(s) this block committed have nothing that justifies them: they leave its record on every node", gone.len());
        self.fold_strip_row(b, seq, &gone)
    }

    pub(super) fn fold_strip_row(
        &mut self,
        b: &crate::block::BlockId,
        seq: u64,
        gone: &std::collections::HashSet<[u8; 32]>,
    ) -> usize {
        let mut union = gone.clone();
        let mut earlier = 0usize;
        if let Some((at_seq, earlier_revoked)) = self.respend_journal.remove(b) {
            earlier = earlier_revoked.len();
            if let Some(row) = self.da_mem.get_mut(&at_seq) {
                for (i, note) in &earlier_revoked {
                    let at = (*i).min(row.0.len());
                    row.0.insert(at, note.clone());
                }
            }
            // the earlier strip's tags come back with its notes, so the union below compacts from the original slots; no
            // tags left with it (none were tagged, or a restart carried only the notes) is the empty list
            let idx: Vec<usize> = earlier_revoked.iter().map(|(i, _)| *i).collect();
            let returned = self.respend_tag_journal.remove(b).unwrap_or_default();
            let restored = tags_after_restore(&self.da_load_tags(at_seq), &returned, &idx);
            self.da_tags_replace(at_seq, restored);
            for (_, note) in &earlier_revoked {
                if note.len() >= 32 {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&note[..32]);
                    union.insert(cm);
                }
            }
        }
        let mut revoked: Vec<(usize, Vec<u8>)> = Vec::new();
        if !union.is_empty() {
            if let Some(row) = self.da_mem.get_mut(&seq) {
                let mut kept = Vec::with_capacity(row.0.len());
                for (i, note) in std::mem::take(&mut row.0).into_iter().enumerate() {
                    let hit = note.len() >= 32 && {
                        let mut cm = [0u8; 32];
                        cm.copy_from_slice(&note[..32]);
                        union.contains(&cm)
                    };
                    if hit {
                        revoked.push((i, note));
                    } else {
                        kept.push(note);
                    }
                }
                row.0 = kept;
            }
        }
        // ⛔ DB-377 (2026-10-04) — THE INDEX MIRRORS THE ROW. A note that leaves this record is no longer filed here, so
        // its `note_target_addr` entry (cm → this record) leaves with it. `tx_notes_already_on_chain` reads that index;
        // a stale entry made the honest publisher skip its own pooled mint FOREVER after a rogue block carried the
        // mint's note bytes beside an unproven object: the fold refused the object and stripped the note from the row,
        // the index still said "filed at a settled record", and `[assemble-dup] … ALREADY on chain` fired on every
        // template — the burn class, mesh-wide for the price of one block. Only entries that name THIS record are
        // retracted (a note filed elsewhere keeps its address); `respend_pop_journal` re-files them on a rewind.
        // ROOT-LAYER: this is the ONE strip every fold-time removal goes through (DB-358 respend losers, P4 refused
        //   credits, P4b refused class objects) — the index has one writer-pair, here and the rewind, as the row does.
        // MEASURED: `an_under_attested_peg_in_carried_by_a_rogue_producer_mints_nothing_on_the_peer` RED at its
        //   CONTROL (the honest block laid WITHOUT its pooled mint, `[assemble-dup]` in the log) before this edit.
        // MUST-STAY-GREEN: `db274_p4_a_refused_then_retried_fold_still_rewinds_its_row_exactly` (the journal keeps
        //   original positions — unchanged), the three peg-in census pins, db367's burn pin, the DB-5/db249 executor pins.
        for (_, note) in &revoked {
            if note.len() >= 32 {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&note[..32]);
                if self.note_target_addr.get(&cm) == Some(&seq) {
                    self.note_target_addr.remove(&cm);
                }
            }
        }
        // The row compacted, so its tags compact with it: each tag keeps naming the slot its note now holds, and the stripped
        // notes' tags wait beside the journal for a rewind (`tags_after_strip`; `bond_step_at_fold` moves tags the same way
        // when a row grows).
        if !revoked.is_empty() {
            let idx: Vec<usize> = revoked.iter().map(|(i, _)| *i).collect();
            let (kept, left) = tags_after_strip(&self.da_load_tags(seq), &idx);
            self.da_tags_replace(seq, kept);
            if !left.is_empty() {
                self.respend_tag_journal.insert(*b, left);
            }
        }
        let newly = revoked.len().saturating_sub(earlier);
        if !revoked.is_empty() {
            self.respend_journal.insert(*b, (seq, revoked));
        }
        newly
    }

    /// ⭐ DB-353 SHAPE (3) — §3 step 1 at the fold: the ADMITTED nullifier set of fold step `ordinal` is noted for the band
    /// door — the block's header-bound `padded_tags` (TAG space) minus one occurrence per losing tag
    /// (`respend_decide_at_fold`'s verdict, canonical on every node; a contested tag's WINNING occurrence stays). An idle
    /// block — no lane, or a held header committing the empty lane — is an empty step. A block whose body this node does
    /// not hold is noted UNKNOWN: the band pointer waits there and only a certified re-adopt moves it; a carrier's word
    /// never stands in for the header. The band itself moves only in [`Self::band_drain`].
    /// ⛔ DB-367: `unadmitted` are tags this step never admits, whatever their count in the lane — a tag nothing justifies
    /// ([`Node::lane_justified`]) and the own nullifier of an object its class door refused at this fold.
    pub(super) fn band_note_fold_step(
        &mut self,
        b: &crate::block::BlockId,
        ordinal: u64,
        losers: &[[u8; 32]],
        unadmitted: &std::collections::HashSet<[u8; 32]>,
    ) {
        let admitted: Option<Vec<[u8; 32]>> = match self.unfolded_blocks.iter().find(|x| x.id() == *b) {
            Some(body) => {
                let lane = &body.nullifier_proof.padded_tags;
                let mut remove: std::collections::HashMap<[u8; 32], usize> = std::collections::HashMap::new();
                for t in losers {
                    *remove.entry(*t).or_insert(0) += 1;
                }
                Some(
                    lane.iter()
                        .filter(|t| !unadmitted.contains(*t))
                        .filter(|t| match remove.get_mut(*t) {
                            Some(n) if *n > 0 => {
                                *n -= 1;
                                false
                            }
                            _ => true,
                        })
                        .copied()
                        .collect(),
                )
            }
            None => match self.relay.dag().get(b) {
                Some(n) if n.header.nullifier_tags_root == crate::block::nullifier_tags_root_of(&[]) => Some(Vec::new()),
                _ => None,
            },
        };
        self.join_note_fold_step(b, ordinal, admitted.as_deref());
        if !self.band_door.note_fold_step(ordinal, b.0, admitted) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two counters of fold steps — no tag, cm, amount, key or owner.
            eprintln!(
                "[band-door] ⚠️ the fold ran {} steps ahead of the band and this step could not be held: the band needs a \
                 certified re-adopt (steps dropped so far: {})",
                self.band_door.lag(),
                self.band_door.dropped_for_lag
            );
        }
    }

    /// ⭐ DB-353 §11.12 / DB-454 — a RELAYED band step arrives (a by-id pull's `BANDSTEP` answer, `solicited` when this node
    /// asked for it — every pulled copy is): the door verifies it against the pre and band it derives, or holds it within
    /// the solicited window, then the pointer drains. Logged as a fixed string, never a tag.
    pub(crate) fn band_offer(&mut self, t: crate::nf_sparse::BandTransition, solicited: bool) -> crate::nf_sparse::BandReceipt {
        // SPEED (speed5): a relayed copy of a benched owner's new step ends its bench here (`band_relayed_step_seen`)
        let block = t.for_block;
        self.band_relayed_step_seen(&block);
        let receipt = self.band_door.offer_step(t, solicited);
        self.band_offer_settle(receipt)
    }

    /// ⭐ DB-454 — THIS NODE'S OWN proof of a step: offered to its own door and, when held ahead of its predecessor, marked
    /// servable (`BandDoor::offer_own_step`) so a peer's pull is answered from it the moment it exists.
    pub(crate) fn band_offer_own(&mut self, t: crate::nf_sparse::BandTransition) -> crate::nf_sparse::BandReceipt {
        let receipt = self.band_door.offer_own_step(t);
        self.band_offer_settle(receipt)
    }

    /// DB-454 — can this node serve `block`'s band step by id (what its `BandInv` may name)?
    pub(crate) fn band_holds_step(&self, block: &[u8; 32]) -> bool {
        self.band_door.holds_step(block)
    }

    pub(super) fn band_offer_settle(&mut self, receipt: crate::nf_sparse::BandReceipt) -> crate::nf_sparse::BandReceipt {
        match &receipt {
            crate::nf_sparse::BandReceipt::Refused(why) => eprintln!("[band-door] a relayed band step was refused before any proof work: {why}"),
            crate::nf_sparse::BandReceipt::Invalid(why) => eprintln!("[band-door] a relayed band step FAILED verification: {why}"),
            crate::nf_sparse::BandReceipt::Verified | crate::nf_sparse::BandReceipt::Held => {}
        }
        self.band_drain();
        receipt
    }

    /// [`Self::band_offer`], unsolicited — the one caller left from landing 2 part (a)'s pins.
    pub(crate) fn band_receive(&mut self, t: crate::nf_sparse::BandTransition) -> crate::nf_sparse::BandReceipt {
        self.band_offer(t, false)
    }

    /// ⭐ DB-353 §11.10 — a VERIFIED step's wire bytes, for a peer's `BandReq` (only verified bytes are ever served).
    pub(crate) fn band_serve_bytes(&self, block: &[u8; 32]) -> Option<Vec<u8>> {
        self.band_door.serve_step(block).and_then(|t| postcard::to_allocvec(t).ok())
    }

    /// ⭐ DB-353 §11.10 — the awaiting steps this node would take a copy of NOW (the door's `wants`), lowest first, at
    /// most `cap`: what the relay asks its peers for.
    pub(crate) fn band_wanted_steps(&self, cap: usize) -> Vec<[u8; 32]> {
        self.band_door
            .awaiting_steps()
            .into_iter()
            .map(|(_, b, _)| b)
            .filter(|b| self.band_door.wants(b))
            .take(cap)
            .collect()
    }

    /// The steps the band door's cascade verified since the last call — the ids the relay ANNOUNCES (`WireMsg::BandInv`,
    /// DB-454); each is servable by id now.
    pub(crate) fn band_take_newly_verified(&mut self) -> Vec<[u8; 32]> {
        let ids = self.band_door.take_newly_verified();
        ids.into_iter().filter(|b| self.band_door.holds_step(b)).collect()
    }

    pub(crate) fn band_take_invalidated(&mut self) -> Vec<[u8; 32]> {
        self.band_door.take_invalidated()
    }

    /// ⭐ DB-353 §11.13 — the provers this node can see for band-step ownership: its own public id and every peer it knows,
    /// sorted and deduplicated (HRW is order-free; a stable list keeps logs comparable). Two nodes seeing different sets may
    /// pick different owners for a step; the open rule (`band_open_after`) bounds what that costs — never a halt.
    /// ⛔ DB-404: NEVER BENCHED. P7's one-turn-per-applied-step rule (`p7_turn_is_mine`), the owner count and the solicited
    /// window read this set, and a turn set must be a function every node computes alike: MEASURED sim-20261007-002009, a
    /// bench applied here left the benched peer out of ONE node's turn set, both nodes held the same turns, and the doubled
    /// production split the selected chain. The bench lives in step ownership only ([`Self::band_live`]).
    pub(crate) fn band_provers(&self) -> Vec<String> {
        if let Some((_, ids)) = &self.band_mix {
            return ids.clone();
        }
        let mut ids: Vec<String> = self.known_peers().into_iter().map(|r| r.peer_id).collect();
        if let Some(me) = self.public_id() {
            ids.push(me.to_string());
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// Is `id` benched from step ownership HERE right now (DB-404: a lapsed pointer lease; SPEED R4: this node itself
    /// after losing a step it owns)?
    pub(super) fn band_benched_here(&self, id: &str) -> bool {
        self.band_benched.get(id).is_some_and(|(until, _, _)| *until > self.band_steps_applied)
    }

    /// ⭐⭐ SPEED R4 (2026-11-10) — WHO PROVES STEP `ordinal`, IN THE ORDER THEY ARE ASKED. First the step's owner over
    /// the FULL prover set (`band_step_owner` — the one function every node computes alike), then every other prover in
    /// the epoch's HRW rank; the provers benched HERE keep that order but move to the back. `order[0]` proves the step
    /// inside the first lease; each further lapse of the pointer's lease hands it to the next (`order[lapses mod len]`).
    ///
    /// ⛔ WHAT THIS REPLACES, MEASURED on two real nodes (2026-11-10, the landed binary): ownership was judged over the
    /// provers NOT benched here (`band_step_owner` over a filtered list). Removing one prover from that list changes the
    /// round-robin for EVERY step, and a bench is one node's own observation, so two nodes that benched differently
    /// disagreed about every owner. On a pair: node 0 benched node 1 after one lapsed lease (a restart), took all of its
    /// steps for the next 128, and node 1 — which cannot know — kept proving them too. 4 of node 0's 14 step proofs in
    /// 8 minutes were refused "already applied" and thrown away, 273 in one night's log: about a quarter of all step
    /// proofs, each a 7-million-cell prove.
    /// Here a bench moves ONLY the benched prover's own steps, and only to the next prover in that step's own order.
    /// Two nodes that bench differently still agree on every other step, so the only step two provers can both hold is
    /// one whose owner is benched somewhere and alive — and that ends at the first race (`band_own_proof_lost`).
    /// A benched prover is asked LAST, never left out: with every other prover gone the band still reaches it.
    /// SAFE-FALLBACK: the next prover in a step's order proves the SAME statement and its proof enters through the
    /// SAME band door (`BandDoor::offer_step`: pre, band and admitted set derived there, slices verified) as the first
    /// prover's would. The order decides whose CPU proves a step and when; it is never read by any verifier.
    /// BORROWED: rendezvous (HRW) hashing's own rule for a node that is down — a key goes to the next node in THAT
    /// key's ranking, and no other key moves (Thaler and Ravishankar 1998; Dynamo's preference list).
    /// cons: none — the same O(provers log provers) ranking the lapse rule already computed per step.
    pub(super) fn band_order(ordinal: u64, provers: &[String], m: usize, benched: &dyn Fn(&str) -> bool) -> Vec<String> {
        let Some(owner) = crate::nf_sparse::band_step_owner(ordinal, provers, m) else { return Vec::new() };
        let epoch = ordinal / crate::oli::EPOCH_BLOCKS;
        let ranked = crate::nf_sparse::band_step_owners(epoch, provers, provers.len());
        let chain: Vec<String> = std::iter::once(owner.clone()).chain(ranked.into_iter().filter(|p| *p != owner)).collect();
        let (asked_first, asked_last): (Vec<String>, Vec<String>) = chain.into_iter().partition(|p| !benched(p));
        asked_first.into_iter().chain(asked_last).collect()
    }

    /// ⭐⭐ SPEED R4 (2026-11-10) — THIS NODE'S OWN PROOF OF STEP `ordinal` LOST A RACE: its door had already verified or
    /// applied another proof of that step (`BandReceipt::lost_to_another_proof`). Two provers held the same step, which
    /// means their views of who proves it differ, and the race itself says how:
    /// - the step is this node's OWN (it is first in the step's full order): another prover took it over, which the
    ///   next prover in the order only does after this node's lease lapsed THERE. This node is too slow for its steps
    ///   as its peers see it, and whoever took the step has benched it. It benches ITSELF for the same span, so its
    ///   steps are proven once — by the prover that already holds them — instead of twice. (A phone whose proofs take
    ///   longer than the mesh's lease stops burning them.)
    /// - otherwise this node held the step because a prover ahead of it in the step's order is benched here, and a
    ///   proof arrived anyway before its own was done: that prover is alive and at least as fast. Every benched prover
    ///   ahead of this node in the step's order is trusted again, with one lapse forgiven.
    /// Either way the two views agree again after ONE discarded proof, where the bench used to cost a discarded proof
    /// for each of the benched prover's steps until it ran out.
    /// What a wrong guess costs, bounded: a prover trusted again that is in fact gone lapses its next step's lease and
    /// is benched for twice as long (`band_bench`); a prover that benched itself while its peers still expect it costs
    /// them one lease, after which they bench it too. Never a stall: `band_order` still asks a benched prover, last.
    /// Local policy: nothing here is on the wire or in a block, and no door reads it.
    /// cons: none — O(provers log provers) on a lost race; ≤ one map entry per prover (this node's own included).
    ///
    /// ⭐⭐ SPEED (speed5, 2026-11-17) — A NODE BENCHES ITSELF ONLY WHEN IT IS SLOW (`self_slow`: its own last proof took longer
    /// than twice the band's step time, the lease its peers give it), never because it started LATE. MEASURED on real nodes (two
    /// nodes, main 36491f4b + [band-time], 12 min): node 1 joined after node 0 had laid 19 blocks, its first owned step (1) was
    /// taken by node 0 on a lease lapse, and node 1 benched ITSELF for 128 applied steps — so it proved nothing, could never
    /// "win one", and node 0 proved 150 of 156 steps alone at a median 5,401 ms: the band, and with it the chain (P7 holds
    /// production while the band lags), ran at ONE prover's pace — 13 blocks a minute against a 1,953 ms target. Node 1's own
    /// proofs took 5,140-5,420 ms against a ~12 s lease: not slow. A node that is not slow keeps proving its owned steps; the
    /// holder that benched it trusts it again the first time its proof arrives first (below: the A-F48 guard). A slow prover
    /// (a phone past the lease) still benches itself exactly as before.
    /// cons: while the holder still has it benched, both may prove one of its steps (one duplicate proof, then the bench ends);
    /// no growth axis. What protects it: (b) code — local proving policy; every step is still verified by every door.
    pub(crate) fn band_own_proof_lost(&mut self, ordinal: u64, provers: &[String], self_slow: bool) {
        let Some(me) = self.public_id().map(str::to_string) else { return };
        let m = crate::nf_sparse::band_owner_count(self.params().target_spacing_ms, provers.len().max(1));
        let chain = Self::band_order(ordinal, provers, m, &|_| false);
        if chain.first() == Some(&me) {
            if self_slow {
                self.band_bench(me);
            }
            return;
        }
        let ahead: Vec<String> = chain.into_iter().take_while(|p| *p != me).filter(|p| self.band_benched_here(p)).collect();
        for id in ahead {
            self.band_unbench_on_delivery(&id, ordinal, "before this node's own proof of it");
        }
    }

    /// ⭐⭐ SPEED (speed5, 2026-11-17) — A BENCHED OWNER'S RELAYED PROOF OF A NEW STEP ENDS ITS BENCH HERE. MEASURED on real
    /// nodes (two nodes, d709c89e, 29 min): node 0 benched node 1 at genesis (a lease lapse while node 1 joined, then 128 and
    /// 256 applied steps), so node 0 counted itself first for node 1's steps and proved them too; node 1, no longer benching
    /// itself, proved them as well — 491 proofs for 349 steps, 140 proven by BOTH (29 % of the band's work). Node 0's door always
    /// applied its OWN proof first and refused node 1's copy ("already applied"), so its own proof never LOST a race and the
    /// lost-race un-bench above never fired. A relayed copy of a step past the bench's horizon whose first owner (in the
    /// unbenched order) is benched here is that evidence too: the step was proven elsewhere while this node was benching its
    /// owner. Called for every relayed copy, accepted or refused as already applied.
    /// What a wrong guess costs, bounded: with three or more provers a flooded copy may be another backup's, and the owner
    /// trusted again lapses its next lease and is benched for twice as long (`band_bench`) — one lease (~12 s), never a stall.
    /// cons: one awaiting-window scan per relayed step (≤ the lag cap); no growth axis. Local policy; every door still verifies.
    pub(crate) fn band_relayed_step_seen(&mut self, block: &[u8; 32]) {
        let Some(ordinal) = self.band_door.awaiting_ordinal_of(block) else { return };
        let provers = self.band_provers();
        let m = crate::nf_sparse::band_owner_count(self.params().target_spacing_ms, provers.len().max(1));
        let Some(owner) = Self::band_order(ordinal, &provers, m, &|_| false).into_iter().next() else { return };
        if self.public_id() == Some(owner.as_str()) || !self.band_benched_here(&owner) {
            return;
        }
        self.band_unbench_on_delivery(&owner, ordinal, "as a relayed copy");
    }

    /// The un-bench both evidence paths share: `id` delivered fold step `ordinal` (`how`), which counts only for a step past
    /// the bench's horizon (A-F48).
    fn band_unbench_on_delivery(&mut self, id: &str, ordinal: u64, how: &str) {
        {
            let id = id.to_string();
            let (forgiven, last_awaiting) = match self.band_benched.get(&id) {
                Some((_, lapses, la)) => (lapses.saturating_sub(1), *la),
                None => return,
            };
            // A-F48: a proof for a step that was awaiting when the bench was applied is not evidence of liveness — it
            // was proven before the bench (e.g. relayed after a fold rewind). Only un-bench for steps past the bench's
            // horizon. BORROWED: Cosmos SDK's jail-until — a jailed validator re-enters only by a NEW unjail tx, never
            // by an old block arriving. MEASURED (audit rig, 2026-11-12): step 562's old proof un-benched the down
            // prover, whose 26 remaining awaiting steps then each cost one full lease (a halt).
            if ordinal <= last_awaiting {
                return;
            }
            if forgiven == 0 {
                self.band_benched.remove(&id);
            } else {
                // not benched from here on (`band_benched_here` reads `until`); its remaining lapses still double the next bench
                self.band_benched.insert(id.clone(), (self.band_steps_applied, forgiven, 0));
            }
            // DIGITAL-CASH-PRIVACY-REVIEWED: a peer's PUBLIC announced id (prefix) and a fold ordinal — no tag, note, amount or key.
            eprintln!(
                "[band-bench] prover {} delivered fold step {ordinal} {how}: it owns its band steps here again",
                id.chars().take(12).collect::<String>()
            );
        }
    }

    /// ⛔⛔ DB-404 — THE PROVER WHOSE OWNED POINTER STEP LAPSED IS BENCHED FROM OWNERSHIP (borrowed: the Cosmos SDK
    /// `x/slashing` downtime JAIL — a validator that misses its signing window leaves the active set for
    /// `DowntimeJailDuration`, then may return; here with no slash, since a missed step costs the chain only time).
    /// ROOT-LAYER: ownership is DECIDED in `band_next_owned_step` (the one site that names a step's prover), so the lapse is
    ///   recorded where it is observed (this holder taking over an owned pointer step) and filtered there — and only there.
    /// MEASURED (before): sim-20261006-234445, 3 nodes — the joiner stood ~600 band steps behind the frontier yet every peer
    ///   counted it among the step OWNERS, so one step in three waited out a full pointer lease before a holder took it
    ///   over: the band lag went +0 → +64 (the cap) over t = 1,560 → 1,980 sim s and P7 held production to that pace;
    ///   sim-20261007-002601 T3: lag 63/64 on both nodes. Pin `db404_an_absent_owner_costs_one_lease_and_never_moves_p7s_turn`
    ///   RED on the no-bench rule (20 leases for the ghost's 20 steps, scratchpad/night/link11-db404b-red.log).
    /// MUST-STAY-GREEN: the band-worker pins (`db353_the_owner_serves_the_first_step_it_owns`,
    ///   `db353_an_open_step_its_owner_never_proved…`, `db353_two_owners_split_a_full_band…`), the P7 turn pins, the journey.
    /// The same rule made a free `.onion` Sybil set a band throttle: S announced ids that never prove cost S leases per epoch
    /// of steps; now one lease per id per bench.
    /// The bench: `2 · oli::EPOCH_BLOCKS` applied steps (ownership's own rotation unit — a benched prover sits out the rest
    /// of this epoch and the next), doubling on each further lapse.
    /// SPEED R4 (2026-11-10): a bench moves only the benched prover's OWN steps (`band_order`), ends when that prover
    /// wins a race, and a prover that loses a step it owns benches itself (`band_own_proof_lost`) — `owner` may be this
    /// node's own id. MEASURED before (two real nodes): the cons line that stood here, "a step both think theirs is
    /// proven twice", was a quarter of all step proofs.
    /// cons: two nodes that bench differently both hold the benched prover's next step until one proof of it lands
    ///   (ONE discarded proof, then they agree). O(provers) per call; ≤ one entry per prover.
    pub(super) fn band_bench(&mut self, owner: String) {
        let known: std::collections::BTreeSet<String> = self.known_peers().into_iter().map(|r| r.peer_id).collect();
        let me = self.public_id().map(str::to_string);
        self.band_benched.retain(|id, _| known.contains(id) || Some(id) == me.as_ref());
        let lapses = match self.band_benched.get(&owner) {
            Some((_, m, _)) => m.saturating_add(1),
            None => 1,
        };
        // 2^(lapses − 1) saturates at u64::MAX once the shift passes the word (`checked_shl` is None there)
        let doubling = match 1u64.checked_shl(lapses - 1) {
            Some(d) => d,
            None => u64::MAX,
        };
        let span = (2 * crate::oli::EPOCH_BLOCKS).saturating_mul(doubling);
        let until = self.band_steps_applied.saturating_add(span);
        if Some(&owner) == me.as_ref() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: step counts only — no tag, note, amount, key or peer id.
            eprintln!(
                "[band-bench] this node's own band step was proven by another prover first (time {lapses}): it leaves its \
                 steps to the next prover in their order for the next {span} applied step(s); P7's turn set is unchanged"
            );
        } else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a peer's PUBLIC announced id (prefix) and step counts — no tag, note, amount or key.
            eprintln!(
                "[band-bench] prover {} lapsed its pointer lease (lapse {lapses}): its band steps go to the next prover in \
                 their order here for the next {span} applied step(s), or until it wins one; P7's turn set is unchanged",
                owner.chars().take(12).collect::<String>()
            );
        }
        // A-F48: record the highest awaiting step at bench time — proofs at or below this ordinal are old relays and
        // must not un-bench in `band_own_proof_lost`. BORROWED: Cosmos SDK's jail-until (a jailed validator re-enters
        // only by a NEW unjail tx after the jail height, never by an old block arriving).
        let last_awaiting = self.band_door.awaiting_steps().last().map_or(0, |(ord, _, _)| *ord);
        self.band_benched.insert(owner, (until, lapses, last_awaiting));
    }

    /// ⭐⭐ DB-353 §11.12 / §11.13 — THE PROVE WORKER'S UNDER-LOCK HALF: the next step this node should prove, SERVED here.
    /// Walks the noted steps the cursor has not absorbed, in fold order:
    /// - a step this node OWNS (its epoch's HRW round-robin over `provers`, `band_step_owner`) or that is OPEN, and that the
    ///   door does not already hold VERIFIED, is served against the view ∪ the cursor's overlay (`serve_and_absorb`) and
    ///   returned to be proven off the lock;
    /// - every other step is ABSORBED, so a later owned step is proven ahead of the door (its pre is native).
    /// ⛔⛔ OPEN IS A LEASE ON THE POINTER STEP, NOT A COUNT OF NOTED STEPS. Only the step the band WAITS ON opens, and only
    /// once the band has not moved for the lease (`pointer_lease_expired`, the runtime's 2 × band service time — P7's own
    /// budget): the borrowed work-lease shape (an owner holds its work for a timeout; on expiry anyone takes it over).
    /// MEASURED 2026-10-06 (`sim-20261006-033642`, 2 nodes): the old rule (open once `band_open_after(m)` later steps were
    /// noted) is ALWAYS true once the fold waits at the 64-step cap — every step from the pointer to `latest − 2m` read open
    /// — so both nodes proved every pointer step (node 0: 276 jobs, all verified; node 1: 278 jobs, 275 refused "already
    /// applied") and the band moved at ONE node's pace however many owners there were. A dead owner still costs at most one
    /// lease per step it owns, then its steps become any holder's in turn as each reaches the pointer.
    /// Stops at an UNKNOWN step (no body held at its fold — nothing past it can be served), a stale door, or no held view.
    /// Bounded: at most the door's lag cap of steps per call; the overlay sheds applied steps once it outgrows that cap.
    /// ⭐ DB-454 — THE BACKUP TAKER of an open pointer step: is THIS node the one holder that should prove it on this lapse?
    /// Deterministic from the public ids every holder shares: the provers ranked by HRW over the step's epoch
    /// (`band_step_owners` over ALL provers), with the step's own owner removed, indexed by `(lapses − 1)`. So the first
    /// lapse hands the step to the owner's immediate successor, and each further lapse rotates to the next rank — cycling
    /// through every prover until a live one proves it (liveness if the backup is itself absent), while never making two
    /// holders prove the same open step on the same lapse (the stampede). `lapses == 0` is still within the lease: no backup.
    /// cons: two nodes measuring the lapse count across a lease boundary can briefly disagree by one and both prove the step
    ///   (CPU on two nodes, the door keeps one copy); bounded to the transition tick, never a slower band. O(provers log provers).
    pub(super) fn band_backup_is_me(ordinal: u64, owner: &Option<String>, provers: &[String], me: Option<&str>, lapses: u64) -> bool {
        let Some(me) = me else { return false };
        if lapses == 0 {
            return false;
        }
        let epoch = ordinal / crate::oli::EPOCH_BLOCKS;
        let ranked = crate::nf_sparse::band_step_owners(epoch, provers, provers.len());
        let backups: Vec<&String> = ranked.iter().filter(|p| owner.as_deref() != Some(p.as_str())).collect();
        if backups.is_empty() {
            return false;
        }
        let idx = ((lapses - 1) % backups.len() as u64) as usize;
        backups.get(idx).is_some_and(|b| b.as_str() == me)
    }

    /// SPEED (lane speed5, 2026-11-18): is this node a fold step's first owner over the full prover set, ignoring any bench (the
    /// unbiased split the `[band-time]` line is compared against)? `None` without a public id. Read-only; a log field only.
    pub(crate) fn band_step_first_owner_is_me(&self, ordinal: u64) -> Option<bool> {
        let provers = self.band_provers();
        let m = crate::nf_sparse::band_owner_count(self.params().target_spacing_ms, provers.len().max(1));
        let me = self.public_id()?;
        Some(crate::nf_sparse::band_step_owner(ordinal, &provers, m).as_deref() == Some(me))
    }

    pub(crate) fn band_next_owned_step(&mut self, provers: &[String], pointer_lease_lapses: u64) -> Option<BandProveJob> {
        self.band_next_owned_step_why(provers, pointer_lease_lapses).ok()
    }

    /// [`Self::band_next_owned_step`], naming WHY nothing was served (a fixed reason string: the worker logs it on change,
    /// so a node whose worker idles says where it stopped — public band position only).
    pub(crate) fn band_next_owned_step_why(
        &mut self,
        provers: &[String],
        pointer_lease_lapses: u64,
    ) -> Result<BandProveJob, &'static str> {
        // DB-454 — the lease has lapsed `pointer_lease_lapses` times (0 = still within the owner's lease). Only the backup
        // taker for this lapse count proves the open pointer step, so a lapse makes ONE node prove it, not every holder.
        let pointer_lease_expired = pointer_lease_lapses > 0;
        let pointer = self.band_door.pointer().ok_or("the door has no pointer")?;
        // a door STALE past a lag-cap gap still holds every awaiting step BEFORE the gap (nothing at or past it is
        // noted), and those stay valid to prove: the band advances up to the gap, and only a certified re-adopt crosses
        // it. Stopping here would strand the band short of a gap it could reach.
        if self.band_cursor.through().is_some_and(|t| t < pointer) {
            // every absorbed step is applied: the view already holds them
            self.band_cursor = crate::nf_sparse::BandCursor::new();
        }
        // DB-404 / SPEED R4: ownership is the step's order over the FULL prover set with the provers benched here asked last
        // (`band_order`; this function only — never the set P7's turn reads). `mine(ordinal, lapses)` answers for one step:
        // is this node first in its order (`owned`), is it the one the current lapse hands the step to (`open`), and who
        // was first (the prover whose lease lapsed when the step is taken open).
        let m = crate::nf_sparse::band_owner_count(self.params().target_spacing_ms, provers.len().max(1));
        let me = self.public_id().map(str::to_string);
        let (benched_now, applied_now) = (self.band_benched.clone(), self.band_steps_applied);
        let benched = move |p: &str| benched_now.get(p).is_some_and(|(until, _, _)| *until > applied_now);
        let mine = |ordinal: u64, lapses: u64| -> (bool, bool, Option<String>) {
            let order = Self::band_order(ordinal, provers, m, &benched);
            let first = order.first().cloned();
            let owned = me.is_some() && first == me;
            let open = !owned
                && lapses > 0
                && me.is_some()
                && order.get((lapses % order.len().max(1) as u64) as usize) == me.as_ref();
            (owned, open, first)
        };
        let steps = self.band_door.awaiting_steps();
        steps.last().ok_or("no step awaits a carrier")?; // nothing awaits a carrier: nothing to prove
        let k = self.band_door.chain_k();
        // ⛔⛔ DB-353 §11.13 — THE POINTER STEP, ABSORBED WHILE SOMEONE ELSE'S AND NOW OPEN, IS THIS HOLDER'S TO PROVE.
        // A step this node does not own is absorbed into the cursor (so later steps can be served on top of it) and skipped
        // from then on; the cursor is only rebuilt when the pointer passes it. So when its owner never proved it and it
        // turned OPEN, no holder that had absorbed it ever proved it, and the band waited there until the lag cap made the
        // door stale — after which every pool refuses every spend.
        // ROOT-LAYER: this is where a step is CHOSEN for proving; the open rule only means anything if it is applied to the
        //   step the band waits on, whatever the cursor already absorbed.
        // MEASURED: before — `db353_an_open_step_its_owner_never_proved_is_proven_by_a_holder_that_absorbed_it` RED (the
        //   holder served step 1 past the open step 0); on the hub, both parties' bands sat at the first real step until
        //   stale (515 lag-cap drops in one journey).
        // MUST-STAY-GREEN: the band-worker pins (`db353_the_owner_serves_the_first_step_it_owns`, the relay worker pin), the
        //   §11.12/§11.13 boundary pins (an owned step is still served first; a step already served is never re-proven).
        // cons: one cursor rebuild per open, unserved pointer step (a re-serve over at most the absorbed steps, bounded by
        //   `SPINE_RING_LEN`); no growth axis.
        if let (Some(t), Some((p_ord, p_block, _))) = (self.band_cursor.through(), steps.first()) {
            // DB-454: rebuild the absorbed pointer step ONLY on the node that will take it (its owner over its live set, or
            // this lapse's backup taker) — a non-taker holder rebuilding here is pure cursor churn and never serves.
            if *p_ord <= t && pointer_lease_expired && self.band_door.wants_own(p_block) {
                let (owned, open, _) = mine(*p_ord, pointer_lease_lapses);
                if owned || open {
                    self.band_cursor = crate::nf_sparse::BandCursor::new();
                }
            }
        }
        // ⭐ PRIVATE SHARDING §9: a node holding part of the set proves the pointer step only, gathering foreign shards from holders.
        if self.nf_view_is_partial() {
            let Some((ordinal, block, admitted)) = steps.first().cloned() else {
                return Err("no awaiting step past the cursor is owned here");
            };
            let admitted = admitted.ok_or("an UNKNOWN step (no body held at its fold)")?;
            let (owned, open, _) = mine(ordinal, if ordinal == pointer { pointer_lease_lapses } else { 0 });
            if !(owned || open) || !self.band_door.wants_own(&block) {
                return Err("no awaiting step past the cursor is owned here");
            }
            return self.band_partial_job(ordinal, block, &admitted, k);
        }
        let door_band = self.band_door.band().to_vec();
        let view = self.sparse_work.as_ref().ok_or("no held view")?;
        if self.band_cursor.absorbed_steps() > Self::SPINE_RING_LEN {
            // shed the applied steps: the overlay becomes exactly the absorbed ones still pending
            let through = self.band_cursor.through();
            let pending: Vec<(u64, [u8; 32], Vec<[u8; 32]>)> = steps
                .iter()
                .filter(|(o, _, _)| through.is_some_and(|t| *o <= t))
                .filter_map(|(o, b, a)| a.clone().map(|a| (*o, *b, a)))
                .collect();
            if !self.band_cursor.rebuild(view, &pending) {
                self.band_cursor = crate::nf_sparse::BandCursor::new();
            }
        }
        let mut owned_any = false;
        for (ordinal, block, admitted) in steps {
            if self.band_cursor.through().is_some_and(|t| ordinal <= t) {
                continue;
            }
            let admitted = admitted.ok_or("an UNKNOWN step (no body held at its fold)")?;
            let (owned, open, first) = mine(ordinal, if ordinal == pointer { pointer_lease_lapses } else { 0 });
            // ⛔⛔ DB-454 — ONE TAKER PER OPEN POINTER STEP. The old rule (`pointer_lease_expired && ordinal == pointer`)
            // was true on EVERY holder at once, so a single lease lapse made all N holders prove the pointer step — 2 of 3
            // proofs per lapse were wasted ("already applied" at the door, cursor rebuilt, prove again) and the band never
            // closed its lag. Now the open step is taken by exactly ONE deterministic backup: the prover ranked next after
            // the step's owner (by HRW over the epoch, rotated one further per further lapse). Borrowed shape: Bitcoin's
            // one-producer-per-template — a single deterministic producer per unit of work, not a race every node joins.
            // MEASURED (link 85): the stampede held the real-proof relay pin at 161 jobs / 89 steps with 80 own
            // "already applied" refusals; one taker drives jobs toward steps.
            // SPEED R4: the taker is `order[lapses mod len]` of the step's own order (`mine`, above) — with nobody benched
            // exactly the prover `band_backup_is_me` names for that lapse.
            // ⛔ ONLY A STEP THE DOOR WANTS (`BandDoor::wants`: not held verified, no solicited copy held, room in the window).
            // MEASURED 2026-10-06 (`sim-20261006-035001`): asking only "not verified" re-served a step proven AHEAD and held
            // for its predecessor — the door refused the duplicate ("a solicited copy of this step is already held", 477 of
            // 485 own refusals), the cursor reset, and the worker proved it again, ~120 times per node in 180 s.
            owned_any |= owned;
            if (owned || open) && self.band_door.wants_own(&block) {
                let (band_pre, serves, fillers) =
                    self.band_cursor.serve_and_absorb(view, &door_band, ordinal, block, &admitted, 0).ok_or("an owned step the cursor cannot serve")?;
                if let (false, Some(lapsed)) = (owned, first) {
                    // DB-404: the first prover in the step's order let the pointer's lease run out — this holder takes the
                    // step and that prover is benched (once: one already benched here was asked last and is not counted again)
                    if !self.band_benched_here(&lapsed) {
                        self.band_bench(lapsed);
                    }
                }
                return Ok(BandProveJob {
                    ordinal,
                    block,
                    band_pre,
                    serves,
                    fillers,
                    k,
                    #[cfg(test)]
                    bound_double: self.band_door.bound_double(),
                    #[cfg(test)]
                    declared_cost_ms: self.band_door.double_charge_ms(),
                });
            }
            if !self.band_cursor.absorb(view, ordinal, block, &admitted) {
                return Err("a step the cursor cannot absorb");
            }
        }
        Err(if owned_any {
            "every owned awaiting step is already held by the door"
        } else {
            "no awaiting step past the cursor is owned here"
        })
    }

    /// The prover's cursor is dropped (a proof this node built was refused or failed): the next worker round rebuilds it
    /// from the pointer.
    pub(crate) fn band_cursor_reset(&mut self) {
        self.band_cursor = crate::nf_sparse::BandCursor::new();
    }

    /// ⭐ DB-353 §11.13 — the solicited window `W = M`, the owner count derived from the mesh target and the provers this
    /// node knows. The relay re-reads it every tick, so a changing peer set moves it.
    pub(crate) fn band_set_solicit_window(&mut self, provers: usize) -> usize {
        let m = crate::nf_sparse::band_owner_count(self.params().target_spacing_ms, provers);
        self.band_door.set_solicit_cap(m);
        m
    }

    /// ⭐⭐⭐ DB-353 LANDING 2 (P1, spec §13.4) — apply every band step the pointer can take, and with it THE ONLY ADVANCE of
    /// this node's sparse view. The door applies each step's ADMITTED inserts to the held tree (`drain(held)` →
    /// `advance_block_rooted`, its holder check), so `sparse_work` is exactly the view at the band pointer: a respend
    /// loser's tag never enters it (DB-358 r5), and no graft path moves it (the C1 census). The accumulator then follows the
    /// band's live root; a copath built against any earlier band root the door can still place is judged by
    /// `band_copath_verdict` (`spent_since` over the applied AND pending steps after it).
    pub(super) fn band_drain(&mut self) {
        let ring_len = self.anchor_ring_len();
        let refused_before = self.band_door.copies_refused;
        let applied = self.band_door.drain(self.sparse_work.as_mut(), ring_len);
        self.join_sync_band();
        self.band_steps_applied = self.band_steps_applied.saturating_add(applied.len() as u64);
        if !applied.is_empty() {
            // the accumulator is the band's live root: a copath built on any earlier band root is judged by the door
            // (`band_copath_verdict` → `spent_since`), so no per-step root has to be kept here
            self.view_follow_band_root();
        }
        for a in &applied {
            if !a.holder_disagreed.is_empty() {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a shard count and a fold ordinal — no tag, cm, amount, key or owner.
                eprintln!(
                    "[band-door] ⛔ this node's held subtree disagreed with the carried band on {} shard(s) at fold step {}: \
                     the carried value stands; the shard(s) must be re-warmed",
                    a.holder_disagreed.len(),
                    a.ordinal
                );
            }
        }
        if self.band_door.copies_refused > refused_before {
            eprintln!(
                "[band-door] ⛔ {} carried band transition(s) failed verification at the pointer and were dropped; the band \
                 waits for the next carried copy",
                self.band_door.copies_refused - refused_before
            );
        }
    }

    /// ⭐⭐⭐ P2' (spec §13.1) — the admitted tags of every KNOWN step that awaits its carrier: the half of the fold-point
    /// spent set the view does not hold yet. The union `view ∪ this` is a function of the FOLD, never of band progress — a
    /// drain only moves a step's tags from here into the view — so two nodes at different pointers read the same set.
    /// A step noted UNKNOWN (no body held at its fold) contributes nothing; its tags are unknown here, never "fresh" by
    /// assertion. Bounded by the door's lag cap × the 256-slot lane, whatever the height.
    pub(super) fn band_pending_admitted(&self) -> std::collections::HashSet<[u8; 32]> {
        self.band_door.awaiting_steps().into_iter().filter_map(|(_, _, a)| a).flatten().collect()
    }

    /// ⭐⭐⭐ P2' — THE FOLD-POINT SPENT SET as one membership test: the held view (every band-APPLIED step) ∪ every KNOWN
    /// step still awaiting its carrier. The ONE reader of band/view state a graft path may take (C1's pointer-free class):
    /// its answer does not move when the pointer does, because a drain carries a step's tags from the awaiting side into
    /// the view (pinned by `db353_p1_the_fold_point_set_is_pointer_free`). A tag outside the held shards and outside every
    /// known pending step reads NOT held — the same answer the view gave before P1 (§13.5's stated residual).
    pub(crate) fn fold_point_spent_set(&self) -> FoldPointSpent<'_> {
        // §13.6: blind while any noted step's admitted set is unknown here, or the door is stale past a gap.
        let blind = self.band_door.is_stale() || self.band_door.awaiting_steps().iter().any(|(_, _, a)| a.is_none());
        FoldPointSpent { view: self.sparse_work.as_ref(), pending: self.band_pending_admitted(), blind }
    }

    /// ⭐ PRIVATE SHARDING §9 — the band step job of a prover holding part of the set: its own shards served from its view, foreign
    /// ones from holders' answers (`nf_take_answer`), fillers only from its own shards (their keys are public, so no holder is needed).
    /// `Err` while a holder's answer is outstanding, recording what to ask. The proof is what judges every copath.
    fn band_partial_job(&mut self, ordinal: u64, block: [u8; 32], admitted: &[[u8; 32]], k: usize) -> Result<BandProveJob, &'static str> {
        let bits = usdm_decider::nf_sparse_air::NF_BAND_BITS;
        let cover = usdm_decider::nf_sparse_air::PRODUCTION_BLOCK_COVER;
        let band_pre = self.band_door.band().to_vec();
        let pre = self.band_door.band_root();
        let (_, ordered, by_shard) = crate::nf_sparse::admitted_order(admitted);
        let need = cover.checked_sub(ordered.len()).ok_or("a step with more tags than the cover")?;
        self.nf_band_gathered.retain(|(b, _), _| *b == block);
        let view = self.sparse_work.as_mut().ok_or("no held view")?;
        if view.root() != pre {
            return Err("the view is not on the band's root");
        }
        let foreign: Vec<(u32, Vec<[u8; 32]>)> =
            by_shard.iter().filter(|(s, _)| !view.owns_shard(**s)).map(|(s, t)| (*s, t.clone())).collect();
        let missing: Vec<(crate::spend_frontier::Digest4, [u8; 32], u32, Vec<[u8; 32]>)> = foreign
            .iter()
            .filter(|(s, _)| !self.nf_band_gathered.contains_key(&(block, *s)))
            .map(|(s, t)| (pre, block, *s, t.clone()))
            .collect();
        if !missing.is_empty() {
            self.nf_band_wants = missing;
            return Err("waiting on holders for the pointer step's copaths");
        }
        self.nf_band_wants.clear();
        // Fillers land only in shards this view holds.
        let mut fill_by_shard: std::collections::BTreeMap<u32, Vec<u64>> = std::collections::BTreeMap::new();
        let mut found = 0;
        let mut i = 0u64;
        while found < need {
            let s = crate::nf_sparse::key_shard(&crate::nf_sparse::band_filler_key(i), bits);
            if view.owns_shard(s) {
                fill_by_shard.entry(s).or_default().push(i);
                found += 1;
            }
            i += 1;
            if i > (need as u64 + 1) << (bits + 1) {
                return Err("this view holds no shard a filler can land in");
            }
        }
        let shards: std::collections::BTreeSet<u32> =
            by_shard.keys().filter(|s| view.owns_shard(**s)).chain(fill_by_shard.keys()).copied().collect();
        let (mut serves, mut fillers) = (Vec::new(), Vec::new());
        for s in shards {
            let tags: &[[u8; 32]] = by_shard.get(&s).map_or(&[], Vec::as_slice);
            let fills: &[u64] = fill_by_shard.get(&s).map_or(&[], Vec::as_slice);
            let (lows, entry, fl) = view.serve_fold_copaths(tags, fills).ok_or("an own shard could not serve")?;
            if !tags.is_empty() {
                serves.push((s, entry, tags.iter().copied().zip(lows).collect::<Vec<_>>()));
            }
            for (idx, (low, after)) in fills.iter().zip(fl) {
                fillers.push((*idx, s, low, after));
            }
        }
        for (s, _) in &foreign {
            let (entry, lows) = self.nf_band_gathered.get(&(block, *s)).cloned().ok_or("a holder's answer went missing")?;
            serves.push((*s, entry, lows));
        }
        Ok(BandProveJob {
            ordinal,
            block,
            band_pre,
            serves,
            fillers,
            k,
            #[cfg(test)]
            bound_double: self.band_door.bound_double(),
            #[cfg(test)]
            declared_cost_ms: self.band_door.double_charge_ms(),
        })
    }

    /// The fold-point nullifier band root (shape (3)). NOT-A-TAG: a root.
    pub(crate) fn band_root(&self) -> crate::spend_frontier::Digest4 {
        self.band_door.band_root()
    }

    /// The newest fold step this node's band applied (`None`: none in its ring) — a PUBLIC fold ordinal, for logs.
    pub(crate) fn band_newest_applied(&self) -> Option<u64> {
        self.band_door.newest_applied()
    }

    /// The band door's rewind floor (its journal's reach) — a PUBLIC fold ordinal, for logs.
    pub(crate) fn band_floor(&self) -> u64 {
        self.band_door.floor()
    }

    /// The band root AFTER fold step `ordinal`; `None` while that step's transition is pending or the step left the ring
    /// (R2c: a spend anchored at a pending step waits).
    pub(crate) fn band_root_at(&self, ordinal: u64) -> Option<crate::spend_frontier::Digest4> {
        self.band_door.band_root_at(ordinal)
    }

    /// ⭐ THE CANONICAL FOLD-POINT STATE (a read for the simulator's same-state checks): the newest fold ordinal for which
    /// this node holds BOTH its spine root (the anchor ring) and its band root (the band ring). Both rings are written per
    /// CANONICAL fold step (the record fold's ordinal, a function of the chain — DB-223 P3, DB-353), so two nodes on one
    /// chain hold the same pair at the same ordinal whatever order their blocks arrived in.
    pub(crate) fn fold_point_newest(&self) -> Option<u64> {
        Some(self.spine_recent_roots.back()?.0.min(self.band_door.newest_applied()?))
    }

    /// The (spine root, band root) pair after canonical fold step `ordinal`, when both rings hold it (see
    /// [`Self::fold_point_newest`]). A different pair at one ordinal on one chain is a fork of state.
    pub(crate) fn fold_point_roots_at(
        &self,
        ordinal: u64,
    ) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        let spine = self.spine_recent_roots.iter().rev().find(|(k, _)| *k == ordinal)?.1;
        Some((spine, self.band_door.band_root_at(ordinal)?))
    }

    /// Fold steps noted and not yet applied — the band's lag behind the fold (P7's input).
    pub(crate) fn band_lag(&self) -> usize {
        self.band_door.lag()
    }

    /// Band steps applied since this node started (monotone) — P7's measure of progress.
    pub(crate) fn band_steps_applied(&self) -> u64 {
        self.band_steps_applied
    }

    /// Is the band door past a lag-cap gap it cannot cross without a certified re-adopt?
    pub(crate) fn band_door_is_stale(&self) -> bool {
        self.band_door.is_stale()
    }

    /// Fold steps the band door could not note because its lag reached the cap (a counter, never a tag).
    pub(crate) fn band_dropped_for_lag(&self) -> u64 {
        self.band_door.dropped_for_lag
    }

    /// ⭐⭐ DB-353 P5 — what a certified bundle (and this node's own sync state) CARRIES of the band: the band at the
    /// pointer, the fold ordinal the pointer waits at, and every awaiting step with its admitted set (`None` = unknown
    /// here). When nothing awaits, the next ordinal is the fold's own next ordinal (the band's ordinals ARE fold
    /// ordinals: the fold notes the block after `fold_chain_tip` next). A door STALE past a lag-cap gap carries NOTHING:
    /// its awaiting list stops before the gap, so a joiner's drain would apply the steps after it over the dropped one —
    /// a wrong band — while an empty band is refused by the joiner's `adopt_certified` and it waits for a certified one.
    pub(crate) fn band_carriage(
        &self,
    ) -> (Vec<crate::spend_frontier::Digest4>, u64, Vec<(u64, [u8; 32], Option<Vec<[u8; 32]>>)>) {
        if self.band_door.is_stale() {
            return (Vec::new(), 0, Vec::new());
        }
        (self.band_door.band().to_vec(), self.band_next_ordinal(), self.band_door.awaiting_steps())
    }

    /// The fold ordinal this node's band waits at — the `band_next_ordinal` its own bundle would carry
    /// ([`Self::band_carriage`]): the pointer, or the fold's own next ordinal when nothing awaits; 0 for a door STALE past a
    /// lag-cap gap (its band is no position at all until a certified one is adopted).
    pub(crate) fn band_next_ordinal(&self) -> u64 {
        if self.band_door.is_stale() {
            return 0;
        }
        match self.band_door.pointer() {
            Some(ordinal) => ordinal,
            None => self
                .fold_chain_tip
                .and_then(|c| self.da_ord_mem.get(&Self::da_record_id_for_block(&c, 0)).copied())
                .map_or(1, |o| o.saturating_add(1)),
        }
    }

    /// The fold step the band waits at (`None`: the band is current).
    /// Diagnostic: (awaiting steps, of which the admitted tag set is unknown, the first such ordinal) — the step chooser stops
    /// at the first awaiting step whose admitted set is unknown, so this names why a band does not move.
    /// Diagnostic (the simulator's failure reasons): (fold cursor's blue score, the fold root's blue score at this tip, the
    /// lowest and highest blue score among the unfolded blocks, how many unfolded blocks sit at or below the cursor).
    pub(crate) fn fold_position(&self) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>, usize) {
        let dag = self.relay.dag();
        let score = |id: &crate::block::BlockId| dag.get(id).map(|n| n.blue_score);
        let cursor = self.fold_chain_tip.as_ref().and_then(score);
        let root = self.selected_tip().map(|tip| {
            let mut r = tip;
            for _ in 0..dag.fold_depth_at(&tip) {
                match dag.get(&r).and_then(|n| n.selected_parent) {
                    Some(p) => r = p,
                    None => break,
                }
            }
            r
        });
        let root_score = root.as_ref().and_then(score);
        let scores: Vec<u64> = self.unfolded_blocks.iter().filter_map(|b| score(&b.id())).collect();
        let below = cursor.map_or(0, |c| scores.iter().filter(|s| **s <= c).count());
        (cursor, root_score, scores.iter().min().copied(), scores.iter().max().copied(), below)
    }

    /// Diagnostic: (adopted a certified bundle, spine ring entries, completed witness windows, certified anchor's score).
    pub(crate) fn spine_state(&self) -> (bool, usize, usize, u64) {
        (self.synced.is_some(), self.spine_recent_roots.len(), self.completed_windows.len(), self.certified_anchor_score)
    }

    pub(crate) fn band_unknown_admitted(&self) -> (usize, usize, Option<u64>) {
        let steps = self.band_door.awaiting_steps();
        let unknown: Vec<u64> = steps.iter().filter(|(_, _, a)| a.is_none()).map(|(o, _, _)| *o).collect();
        (steps.len(), unknown.len(), unknown.first().copied())
    }

    pub(crate) fn band_pointer(&self) -> Option<u64> {
        self.band_door.pointer()
    }

    /// ⭐ DB-403 — this node's band journal measured against a bundle certified at band pointer `pointer`
    /// (`BandDoor::bundle_reach`): `(stranded, moves_since, reach)`.
    pub(crate) fn band_bundle_reach(&self, pointer: u64) -> (bool, usize, usize) {
        self.band_door.bundle_reach(pointer)
    }

    /// The band journal's reach (`BandDoor::journal_reach`): the band-moving steps below its pointer a door serves.
    pub(crate) fn band_journal_reach(&self) -> usize {
        self.band_door.journal_reach()
    }

    /// ⭐ DB-353 landing 2 — a VIEWLESS node whose band door is stale past a gap. It holds no placeable warm target, and
    /// only a certified re-adopt (a #29 bundle carrying the band, P5) gives it one; until then it is treeless, which is
    /// sound. (Replaces DB-316c's "pivot absent": under P1 a viewless node's accumulator IS the proven band root, so
    /// it always has a target unless its door cannot place anything.)
    pub fn nf_view_needs_certified_band(&self) -> bool {
        self.sparse_work.is_none() && self.band_door.is_stale()
    }

    /// Does this node hold its nullifier view (the copath source a warm rebuilds)?
    pub fn nf_view_held(&self) -> bool {
        self.sparse_work.is_some()
    }

    /// ⭐⭐⭐ THE ONE DEFINITION OF THE A_TIP ORIGIN — network-derived, domain-separated, never all-zero.
    ///
    /// TWO fields must hold this value: the accumulator itself (`nf_unspent_acc`) and the base a spender's
    /// absence witness is checked against (`nf_fold_base`). They are the SAME number, and a second literal is
    /// exactly how they drift: seeding the accumulator here while `nf_fold_base` stayed `usdm_decider::poseidon2_compress::zero_digest()` made the
    /// gate REFUSE HONEST SPENDS — fail-closed, so nothing forged got in, but an owner's good money was
    /// rejected, which is the worse failure to ship. The spender's TIP still matched the node's A_tip exactly;
    /// only the BASE disagreed. One function, both callers, no way to update one and forget the other.
    /// ([[feedback_ecosystem_chain_aware]] [[feedback_chains_nondeterministic_network_ids]])
    pub fn nf_unspent_acc_genesis() -> crate::spend_frontier::Digest4 {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(b"MUSD-nf-unspent-acc-genesis-v1");
        seed.extend_from_slice(crate::params::process_network_id().as_bytes());
        usdm_decider::nf_sparse_air::nf_to_limbs(blake3::hash(&seed).as_bytes())
    }

    /// The count of applied nullifier-BLOCKS = `(acc.count − 1) / 256` (each block adds the CONSTANT
    /// `BLOCK_FIXED_NULLIFIER_COUNT` padded entries; leaf 0 is the sentinel). Derived from the O(1) acc — no separate
    /// persisted field — and used both as the DA-nf replay bound and the store key (the block just applied lives at
    /// `nf_blocks_applied() − 1`). The nullifier twin of `served_seq` for notes.
    pub(super) fn nf_blocks_applied(&self) -> u64 {
        self.nf_blocks
    }

    pub fn nf_blocks_applied_count(&self) -> u64 {
        self.nf_blocks_applied()
    }

    /// How many times this node advanced the cover-conf accumulator. §CE diagnostic: two nodes that folded
    /// the same blocks must agree, and a difference names a route rather than a value.
    /// O1-FOOTPRINT-REVIEWED: one u64 counter, never keyed by height, block or note.
    #[must_use]
    pub fn nf_conf_advances(&self) -> u64 {
        self.nf_conf_advances
    }

    /// The per-block nullifier decoy seed input = the confidential accumulator (pre-state) ‖ this block's real-spend
    /// blobs. Prepending the accumulator is what makes even an idle block (empty `confidential`) RPC-unpredictable.
    pub(super) fn nf_seed_conf(acc: &[u8; 32], confidential: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + confidential.len());
        out.extend_from_slice(acc);
        out.extend_from_slice(confidential);
        out
    }

    /// How many DSOL assets this node has registered, and how many peaks that costs it.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a count of PUBLIC chain objects (creations are public by design —
    /// a token nobody can find is not a token); it names no holder, amount, note or owner.
    /// The blue score of the CERTIFIED anchor this node stands on. A read, not a setter — the value is
    /// written only from the certified bundle and the DAG's own node for the common ancestor, and the
    /// authority census compares it across parties because a node holding an anchor score no block
    /// produced is a node that certified a position the chain never did.
    pub fn certified_anchor_score(&self) -> u64 {
        self.certified_anchor_score
    }

    /// DB-449: the newest fold ordinal in this node's anchor ring (0 while it is empty) — the clock a waiting spend's reach
    /// is measured on.
    pub(crate) fn anchor_ring_newest(&self) -> u64 {
        self.spine_recent_roots.back().map_or(0, |(o, _)| *o)
    }

    /// The ladder root for `ordinal` if this node holds the blob — a pure read (unlike
    /// `ladder_root_at_ordinal`, no ladder want is registered on a miss). THE one blob decoder.
    pub(super) fn ladder_root_if_held(&self, ordinal: u64) -> Option<crate::spend_frontier::Digest4> {
        let blob = self.da_ladder_mem.get(&(ordinal / Self::DA_LADDER_SPAN))?;
        let off = ((ordinal % Self::DA_LADDER_SPAN) as usize) * Self::LADDER_SLOT_BYTES;
        if off + Self::LADDER_SLOT_BYTES > blob.len() {
            return None;
        }
        let root = Self::ladder_slot_decode(&blob[off..])?;
        // ⛔⛔⛔ AN ALL-ZERO SLOT IS ABSENCE, NEVER A ROOT. The blob is positional (offset =
        // ordinal%SPAN × 32) so `ladder_write_roots` MUST fill slots below the run's first ordinal
        // with something, and it fills them with zeros ("zero prefix below `at`") — ordinal 0
        // (genesis) of span 0 is the slot that stays zero forever, since genesis has no record and
        // no root. Reading those zeros back as real made a resumed node ADVERTISE an all-zero root.
        // ROOT-LAYER: zero-as-not-written is the positional format's OWN semantics — the producer of
        // the zero is the encoding itself (a prefix must exist at write; a validity bitmap would be
        // second state for the same fact; materializing a genesis root was MEASURED 2026-09-04 to
        // move chain identity, 768-vs-512 leaves, and reverted) — and this fn is the format's single
        // interpreter (`ladder_root_at_ordinal` now delegates here precisely so no second decoder
        // can miss the rule).
        // MEASURED: `a_resumed_node_never_re_records_its_seed_only_tip_and_backfills_it_from_the_peer`
        // red with `left: [0, 0, 0, 0]` (the advertised root) vs the peer's real root — the zero
        // came from this decode, the only path that can emit one.
        // MUST-STAY-GREEN: `ladder_span_bounds_every_per_ordinal_row_and_real_records_survive_forever`
        // (real pruned ordinals keep answering from their span blob — their slots are non-zero by
        // the seed-note rule) and the roots-run admit path, which writes real roots before reading.
        if root == usdm_decider::poseidon2_compress::zero_digest() {
            return None;
        }
        Some(root)
    }

    /// ⭐ G2b — the fold cursor in blue score: the selected-chain block the canonical fold last completed (`0` before any
    /// fold; a DSYNC joiner's is its certified anchor). Every seat and exit landing at or below it has been applied here.
    pub(crate) fn fold_cursor_blue(&self) -> u64 {
        self.fold_chain_tip.and_then(|c| self.relay.dag().get(&c).map(|n| n.blue_score)).unwrap_or(0)
    }

    /// ⛔ DB-270 — THE FOLD SPAN AS THIS PROCESS CAN PROVE IT: `base ⊕ Σ leaf(members)` over the window's blocks stamped
    /// with the current base generation plus the carried in-flight blocks stamped with it, against A_tip and
    /// `nf_fold_seq - base_seq`. The ONE tally the restore's verify ([`Self::settle_restored_fold_span`]) and the restart
    /// pins read, so a live process whose span a restore could not reproduce is measured before the restart, not after.
    /// `stamped_unheld` counts the in-flight stamps (`nf_unfolded_gen` at this generation) whose block neither the window
    /// nor the carry holds — a member a restore cannot read.
    pub(crate) fn fold_span_tally(&self) -> FoldSpanTally {
        let gen = self.block_window.base_gen();
        let leaf = |b: &Block| {
            let pre = usdm_decider::nf_sparse_air::nf_to_limbs(&b.header.nullifier_root.0);
            let td = usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(&b.nullifier_proof.padded_tags, pre);
            usdm_decider::nf_sparse_air::block_transition_leaf(pre, td)
        };
        let mut acc = self.nf_fold_base.0;
        let (mut members, mut unreadable) = (0u64, 0usize);
        let mut seen: std::collections::HashSet<crate::block::BlockId> = std::collections::HashSet::new();
        for (_, id) in self.block_window.ascending() {
            if self.block_window.gen_of(&id) != Some(gen) {
                continue;
            }
            match self.block_window.get(&id) {
                Some(b) => {
                    acc = usdm_decider::nf_sparse_air::nf_unspent_acc_add(acc, leaf(&b));
                    members += 1;
                    seen.insert(id);
                }
                None => unreadable += 1,
            }
        }
        for b in &self.unfolded_blocks {
            let id = b.id();
            if seen.contains(&id) || self.nf_unfolded_gen.get(&id) != Some(&gen) {
                continue;
            }
            acc = usdm_decider::nf_sparse_air::nf_unspent_acc_add(acc, leaf(b));
            members += 1;
            seen.insert(id);
        }
        let stamped_unheld =
            self.nf_unfolded_gen.iter().filter(|(id, g)| **g == gen && !seen.contains(*id)).count();
        let (mut window_nonmember, mut window_old_gen) = (0usize, 0usize);
        for (_, id) in self.block_window.ascending() {
            match self.block_window.gen_of(&id) {
                Some(g) if g == gen => {}
                Some(crate::block_window::GEN_NONMEMBER) => window_nonmember += 1,
                _ => window_old_gen += 1,
            }
        }
        let counted = self.nf_fold_seq.saturating_sub(self.nf_fold_base.1);
        FoldSpanTally {
            members,
            counted,
            unreadable,
            reproduces: acc == self.nf_unspent_acc,
            seen,
            stamped_unheld,
            window_nonmember,
            window_old_gen,
        }
    }

    #[cfg(test)] // a test accessor by name: it is not production surface
    /// Whether this node's background checkpoint write is still running. The scenario harness waits on
    /// it before examining the datadir (the write is asynchronous by design — DB-89's cadence); a runtime
    /// never needs to, the next block's `autosave` coalesces. One atomic load; harness-only by name.
    pub(crate) fn checkpoint_in_flight_for_test(&self) -> bool {
        match self.persist_path.as_ref() {
            Some(t) => t.save_in_flight.load(std::sync::atomic::Ordering::Acquire),
            None => false, // persistence is off: no save can be running
        }
    }

    /// ⭐⭐⭐ RECURSIVE CROSS-BLOCK FOLD — absorb ONE block's nullifier transition into the CONSTANT-SIZE chain
    /// accumulator. This is what makes INFINITE blocks carry ONE small proof: each block folds
    /// `acc' = H(acc ‖ block_pre ‖ block_post)`, so the accumulator is a FIXED 16 bytes after 1 block or 10^18 —
    /// it never grows, and the whole-chain WHIR proof binds THIS value (transcript-bound, see
    /// `prove_whole_chain_light_decider_bytes`). A verifier that knows the folded accumulator and verifies the ONE
    /// constant-size proof has certified the whole chain — NO per-block witnesses on the wire, which is the growth
    /// axis measured by `carried_witnesses_are_transient_wire_never_retained_state` (64,704 B → 96,544 B in six
    /// blocks). Order-dependent and transition-dependent by construction: reordering blocks or altering ANY
    /// `(pre, post)` yields a different accumulator, so a forged chain cannot reach the honest binding.
    /// ([[project_o1_fold_plan_measured]] [[project_mina_o1_treeless_node]])
    pub fn fold_block_into_chain(
        acc: [u8; 16],
        block_pre: [u8; 32],
        block_post: [u8; 32],
    ) -> [u8; 16] {
        let mut buf = Vec::with_capacity(1 + 16 + 32 + 32);
        buf.push(0xF0); // domain separator: cross-block chain fold
        buf.extend_from_slice(&acc);
        buf.extend_from_slice(&block_pre);
        buf.extend_from_slice(&block_post);
        let h = Hash32::hash(&buf);
        let mut out = [0u8; 16];
        out.copy_from_slice(&h.as_bytes()[..16]);
        out
    }

    /// THE chain-state accumulator this node certifies for `frontier` — the value the whole-chain WHIR proof is
    /// TRANSCRIPT-BOUND to. ONE computation, shared by [`Self::build_sync_bundle`] and the DSYNC serve path's prove
    /// step, so the value the PROOF binds and the value the BUNDLE carries can never drift apart (that drift class
    /// has already caused two real bugs). O(1) on every axis: a FIXED 16 bytes at height 1 or 10^18, and computing
    /// it is a single hash over constant-size roots — no tree, no replay, no per-height work.
    /// v31: the block the carried spine ends at (the fold root) and its blue score — the DSYNC bundle's
    /// anchor, bound into `chain_acc`. The selected tip until the first fold.
    /// THE ANCHOR a checkpoint and a bundle stand on: the fold cursor when this node has one, else the
    /// highest block on its selected chain whose record is already in the spine — genesis at worst.
    /// Never a block whose record is not folded: a resumed or jumped party takes the anchor as its floor
    /// (folded, no row), and an unfolded anchor shifts every ordinal it files afterwards (the schedule
    /// search found it in one run: parties that had folded nothing checkpointed at their tips).
    /// ⛔ THE ONE WRITER-SIDE SYNC of the DAG's prune floor with the fold anchor (`Dag::prune_floor`): called after every
    /// write of `fold_chain_tip` (the fold step, the fold-root rewind, the certified adopt, the checkpoint resume), so
    /// the anchor the checkpoint needs is never swept out from under `export_snapshot`.
    pub(crate) fn sync_prune_floor(&mut self) {
        let floor = self.fold_chain_tip.and_then(|c| self.relay.dag().get(&c).map(|n| n.blue_score));
        self.relay.dag_mut().set_prune_floor(floor);
    }

    pub(crate) fn fold_anchor_block(&self) -> Option<crate::block::BlockId> {
        if let Some(c) = self.fold_chain_tip {
            return Some(c);
        }
        let dag = self.relay.dag();
        let mut cur = dag.selected_tip();
        while let Some(c) = cur {
            if self.block_record_folded(&c) {
                return Some(c);
            }
            cur = dag.get(&c).and_then(|n| n.selected_parent);
        }
        dag.genesis()
    }

    pub fn fold_anchor(&self) -> Option<(crate::block::BlockId, u64)> {
        let a = self.fold_anchor_block()?;
        let n = self.dag().get(&a)?;
        Some((a, n.blue_score))
    }

    /// THE ONE derivation of the fold root's CERTIFIED record position — read by both writers of the
    /// #29 binding: `current_chain_acc` (which the serve loop's proof cache calls) and
    /// `build_sync_bundle` (which fills the wire field). The position entered the binding preimage on
    /// 2026-09-07 with hole A3's field enumeration, and a value DERIVED at one writer and DERIVED
    /// AGAIN at the other is the second-numbering shape this tree has already paid for four times —
    /// so it is derived here, once, and both writers read it.
    ///
    /// ROOT-LAYER: this is where a served position is PRODUCED, one hop before it is hashed into the
    /// binding and one hop before it is written to the wire. The read site (the adopter's
    /// `da_store_ordinal`) cannot tell a certified position from an invented one, which is exactly
    /// why the C3 refusal was put on the producing side in the first place; this method is that
    /// refusal, made shared instead of inline so the second writer cannot skip it.
    /// FAIL-CLOSED ON THE DEFAULT, not on statement order: 0 is returned ONLY for the genesis fold
    /// root, whose position is 0 by the chain's law. Any other block with no row — or holding the
    /// zero placeholder — yields nothing, and the caller refuses to build OR to bind a bundle this
    /// tick. A certified position is never a value this node invented.
    /// MEASURED (why the position must be bound at all): 2026-09-04, two parties folded rid 238810 at
    /// ordinal 48 and at 9 on the SAME selected tip — a numbering split whose copaths verify nowhere.
    /// The bundle twin of that error ships as a CERTIFIED value, so it cannot heal downstream.
    /// MUST-STAY-GREEN: the #29 DSYNC adopt suite, the canonical_record_fold jump/adopt pins, the
    /// four certify-absence pins, and `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`.
    /// cons: one map lookup and one genesis compare; nothing stored, nothing walked.
    pub(crate) fn certified_fold_base_position(
        &self,
        fold_root: &crate::block::BlockId,
    ) -> Option<u64> {
        let rid = Self::da_record_id_for_block(fold_root, 0);
        let is_genesis = self.dag().genesis().map_or(false, |g| g == *fold_root);
        match self.da_ord_mem.get(&rid) {
            Some(row) if *row > 0 => Some(*row),
            // Genesis IS position 0 by the chain's law — the only block for which the value is not a
            // row. Every other rowless (or zero-row) fold root fails the serve closed.
            _ if is_genesis => Some(0),
            _ => None,
        }
    }

}

/// A record's locator tags once its notes at ORIGINAL positions `removed` left it (the fold's strip compacts the row):
/// those slots' tags leave (the second list, at their original slots), and every later slot moves down by the number of
/// removed positions before it, so each tag still names the slot its note now holds.
/// ⛔ The strip compacted the row and left the tags where they were, so every note after a stripped one was named at a
/// slot holding a different note. MEASURED 2026-11-09, real nodes (launch_trade.py round 17): 9 fold-time strips of
/// refused class objects (36 notes) and 1 respend strip on both nodes; the developer's wallet located 373 notes whose tag
/// matched its own locator and that did not open with its key, and its prepared sell never found its exact note. Any
/// record a refused object or a double-spend loser shares with honest notes hid those notes from a restored wallet.
pub(crate) fn tags_after_strip(
    tags: &[(u8, [u8; crate::oli::K_BYTES])],
    removed: &[usize],
) -> (Vec<(u8, [u8; crate::oli::K_BYTES])>, Vec<(u8, [u8; crate::oli::K_BYTES])>) {
    let mut kept = Vec::with_capacity(tags.len());
    let mut gone = Vec::new();
    for (s, k) in tags {
        let at = *s as usize;
        if removed.contains(&at) {
            gone.push((*s, *k));
        } else {
            let below = removed.iter().filter(|r| **r < at).count();
            kept.push(((at - below) as u8, *k));
        }
    }
    (kept, gone)
}

/// The inverse of [`tags_after_strip`]: the record's tags once the notes at ORIGINAL positions `removed` return. Each
/// compacted slot `c` goes back to the `c`-th position that was never removed, and the returned tags rejoin at their
/// original slots, in slot order.
pub(crate) fn tags_after_restore(
    tags: &[(u8, [u8; crate::oli::K_BYTES])],
    returned: &[(u8, [u8; crate::oli::K_BYTES])],
    removed: &[usize],
) -> Vec<(u8, [u8; crate::oli::K_BYTES])> {
    let survivors: Vec<usize> = (0..=u8::MAX as usize).filter(|s| !removed.contains(s)).collect();
    let mut out: Vec<(u8, [u8; crate::oli::K_BYTES])> =
        tags.iter().filter_map(|(c, k)| survivors.get(*c as usize).map(|s| (*s as u8, *k))).collect();
    out.extend_from_slice(returned);
    out.sort_by_key(|(s, _)| *s);
    out
}
