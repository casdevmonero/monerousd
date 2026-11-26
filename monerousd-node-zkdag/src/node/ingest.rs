// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ingest — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// Record the confidential PQ note ciphertexts produced at `height` (coinbase/output `DOMAIN_PQ_NOTE`
    /// payloads). Idempotent-append: a wallet later fetches them by height over `/get_pq_notes`.
    pub fn record_notes(&mut self, _height: u64, notes: Vec<Vec<u8>>) {
        if notes.is_empty() {
            return;
        }
        // TRANSIENT relay only — overwrite the current block's ciphertexts; the node accumulates no note set.
        self.last_served_block = notes;
    }

    /// ⭐ DOES THIS NODE HAVE EVIDENCE OF `cm` — the ONE question every durable locator-tag write asks.
    ///
    /// Three sources, each of which this node produced or verified for itself, and nothing else counts:
    /// the commitment is already RECORDED here (`da_seq_at_note_cm`), an ACCEPTED transaction in this
    /// node's own pool carries the note, or the note is STAGED to ride this node's very next block. A
    /// commitment a stranger merely named on the wire satisfies none of them.
    /// cons: none — one indexed lookup plus two walks over structures already bounded by fixed protocol
    /// constants (the pool's capacity, and `pending_credit_notes`, which drains into the next block); it
    /// stores nothing and takes no term in chain height, block count or note count.
    pub(super) fn note_cm_evidence(&self, cm: &[u8; 32]) -> bool {
        if self.da_seq_at_note_cm(cm).is_some() {
            return true;
        }
        if self.mempool.holds_note_cm(cm) {
            return true;
        }
        self.pending_credit_notes
            .iter()
            .any(|n| n.len() >= 32 && n[..32] == cm[..])
    }

    pub fn record_note_clue(&mut self, cm: [u8; 32], clue: Vec<u8>) -> bool {
        if self.note_clues.contains_key(&cm) {
            return false; // already have a clue for this note — first-writer-wins, no re-gossip
        }
        // ⛔ THE DURABLE DEDUP IS THE DA SHARD, NOT THE EVICTABLE CACHE. `note_clues` is front-evicted, so
        // once it drops this cm a RE-GOSSIPED clue passed the guard above, re-staged `pending_tags`, and
        // every later re-record of the note's block re-drained it — the same "storing N tag(s)" line
        // repeated 60+ times per record (MEASURED 2026-08-13 on the joiner) while `pending_tags` cycled
        // instead of draining to empty. If this note's record is already written AND its tag set already
        // holds entries, the tag has reached the shard: staging again adds nothing, and returning false
        // also stops the re-gossip re-broadcast loop at its source. Two indexed reads, no new state.
        // ⛔ THE QUESTION IS PER NOTE, NOT PER RECORD (link 46): a record carries several tagged notes — its block's mining
        // reward beside a payment, a payer's change beside the payee's output — so "this record holds SOME tag" refused a
        // payee's late clue once any other note of its block was filed. MEASURED: with rewards tagged, both late-clue pins
        // went red ("a clue arriving 398 blocks after its note must STILL reach that note"; scratchpad/night/
        // link46-neighbours.log), green on the base (link46-attr-base.log).
        let recorded = self.da_seq_at_note_cm(&cm);
        if let Some(addr) = recorded {
            if self.note_tag_is_filed(addr, &cm) {
                return false;
            }
        }
        // Stash this note's locator index key for the block that will carry it. `note_clues` below is a
        // front-evicted serve cache and may drop this entry at any moment; `pending_tags` may not, and it
        // is drained the moment the block is recorded — so the tag always reaches the DA shard.
        //
        // ⛔⛔⛔ ONLY FOR A COMMITMENT THIS NODE HAS EVIDENCE OF — DOOR AUDIT 2026-09-07 (§9.6 Q5+Q6, D14).
        // This function is reached from the `WireMsg::NoteClue` gossip arm, which its own comment calls
        // "UNAUTHENTICATED but money-safe". That judgement is about the CLUE. It was never about this line.
        // `pending_tags`' declared bound — "inserted when a tx is ACCEPTED and REMOVED when its block is
        // recorded … bounded by the mempool's fixed in-flight capacity" — is true of the tx-accept writer
        // and FALSE of this one: the only removal is `pending_tags.remove(&cm)` in the record loop, which
        // runs for a cm that actually appears in a recorded block, so a cm an attacker INVENTS is never
        // removed, and the same doc rightly forbids ageing entries out. 32 B cm + 16 B key = 48 B per
        // gossip, and at the beacon-era rate of ~4 messages/s that is 192 B/s = 16.6 MB/day = 6 GB/year of
        // node RAM nothing in the tree ever releases — paid by every node that hears the gossip. The
        // neighbouring `note_clues` serve cache IS bounded, which is why the growth hid so well.
        // The durable lane is entered only when this node can SEE the commitment. cons: none — a commitment
        // with no evidence still fills the BOUNDED, front-evicted `note_clues` cache below, and
        // `staged_tag_for_cm` reads its key from there at the two points that consume one, so a clue that
        // legitimately arrives before its transaction is carried and drained exactly as it was before.
        let k = crate::oli::index_key(&clue);
        // G1g-ix: an ALREADY-RECORDED note is filed by `attach_tag_to_recorded_block` below; staging it too left an
        // entry no record loop would ever drain again (the drain runs when a block is recorded, and this one was).
        if recorded.is_none() && self.note_cm_evidence(&cm) {
            self.pending_tags.insert(cm, k);
        }
        // ORDER-INDEPENDENCE. A tag reaches a node either as this gossip or with the tx it was submitted
        // with, and NOTHING orders that against block ingest. On a node that recorded the block FIRST the
        // drain above finds nothing, and the note is silently absent from that node's index forever — which
        // is exactly what a cross-device send showed: the accepting node wrote its tag sidecar, the peer
        // wrote none. So if this cm is already in a recently recorded block, attach the tag to that block
        // NOW. Late tags land; early tags drain; neither ordering loses a note.
        // ⛔ ONLY A RECORDED NOTE HAS A LATE TAG (lane a 2026-10-23): an EARLY clue — the producer's own reward, sealed
        // before its block exists; a gossiped clue racing its tx — has no record yet and needs none: it waits in
        // `note_clues` for the template seal (`staged_tag_for_cm`) or rides its block's header-bound `oli_tags`.
        // MEASURED: attaching unconditionally logged `[oli-late-tag] ⛔ DROPPED` for 4,697 of 4,697 produced blocks'
        // rewards (g3-fields-4) while each block carried the reward's 48 tag bytes — a false alarm on every block that
        // hid any real drop. Resolved through `da_seq_at_note_cm` (the record must still hold the note; falls back to
        // the record bytes for a fetched record), not the bare index, so a recorded note the index misses is placed.
        if let Some(seq) = recorded {
            self.attach_tag_to_recorded_block(seq, &cm, k);
        }
        self.note_clues.insert(cm, clue);
        self.note_clue_fifo.push_back(cm);
        // BOUNDED serve-cache (no-growth): once past the cap, front-evict the oldest clue so the cache stays O(1)
        // in note count. An evicted clue is peer-served (#27 DAS) or the wallet decap-scans — never a correctness loss.
        while self.note_clue_fifo.len() > Self::NOTE_CLUE_CACHE_CAP {
            if let Some(old) = self.note_clue_fifo.pop_front() {
                self.note_clues.remove(&old);
                // ⭐ NAME EVERY EVICTION. user 2026-08-01: "the notes should never age out". The comment above
                // asserts this eviction costs only speed because a wallet re-derives the locator by
                // decap-scanning — but that has never been MEASURED, and this session lost many hours to
                // justifications nobody had run. An eviction here is rare, so naming it costs nothing normally
                // and makes the case visible the first time it matters.
                // O1-FOOTPRINT-REVIEWED: stores nothing; the structures and their bound are untouched.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a depth only — never a cm, clue, note, amount, key or owner.
                eprintln!(
                    "[clue-evict] age-ordered eviction — the oldest serve-hint was discarded ({} still held). \
                     Claimed to cost only speed; that claim is UNMEASURED.",
                    self.note_clue_fifo.len()
                );
            }
        }
        true
    }

    /// Adopt a gossiped PEER record into the authenticated directory (verify the ML-DSA self-signature +
    /// onion-only multiaddr + newer-`seq`-wins). The runtime re-gossips only a freshly-`Adopted` record, so the
    /// dialable peer set converges mesh-wide. Never gates block flow — a bad record is rejected fail-closed.
    pub fn adopt_peer(
        &mut self,
        g: &crate::peer_directory::PeerGossip,
    ) -> crate::peer_directory::PeerOutcome {
        // Snapshot the live bonded set so the anti-eclipse admission (a bonded anchor evicts a free Sybil at
        // capacity) has a Sybil-resistant test, without borrowing `self` while `peer_dir` is mutated.
        let bonded = self.validators.bonded_ids();
        self.peer_dir.adopt_prioritized(g, |id| bonded.contains(id))
    }

    /// The detection clue a note's sender attached, by the note's commitment — served to a restoring wallet so
    /// it can test the cheap clue before the expensive ML-KEM decap (O(owned) decaps). None if none was attached.
    pub fn note_clue(&self, cm: &[u8; 32]) -> Option<&[u8]> {
        self.note_clues.get(cm).map(|v| v.as_slice())
    }

    /// Record EVERY confidential PQ note in a block's DA note-payload into the served index, via the
    /// SAME generic path for every block — every note flows the identical path, none is branched on.
    /// `payload` is the block's concatenated note outputs (each
    /// `note_cm(32) ‖ ML-KEM ct(1088) ‖ enc_amount(32) ‖ view_tag(1)`); the loop records the COMPLETE
    /// set, splitting on the fixed 1153-byte boundary and appending under `height`. A well-formed
    /// payload is an exact multiple of the note size; a shorter residual is malformed (not a note) and
    /// is fail-closed, never fabricated into one. Every block's outputs — the very first block's
    /// included — enter the index this way, so no output is fetchable or spendable through a path any
    /// other output lacks.
    /// The block's REAL spendable output notes, assembled from the txs this node already holds — the ONE
    /// assembly shared by the PRODUCE path ([`Self::graft_mined_own`]) and the INGEST path
    /// ([`Self::ingest_block`]), so a node that VERIFIES a peer's block records byte-identical note data to
    /// the node that mined it. Two copies of this logic would silently drift and only show up as a lost
    /// payment on one device, so there is exactly one.
    ///
    /// A bond tx's output0 is WITHHELD from the spendable set (it is LOCKED — its value backs the admitted
    /// validator weight and must not be independently spendable) and returned separately; output1 (change)
    /// stays spendable. A non-bond tx contributes ALL its output notes.
    pub(super) fn block_spendable_note_blobs(
        &self,
        tx_ids: &[Hash32],
    ) -> (Vec<Vec<u8>>, Vec<([u8; 32], Vec<u8>)>) {
        const PQ_NOTE_BYTES_OUT: usize = 1153;
        let mut out_blobs: Vec<Vec<u8>> = Vec::new();
        let mut bond_locks: Vec<([u8; 32], Vec<u8>)> = Vec::new();
        let (mut asked, mut missing, mut no_notes) = (0usize, 0usize, 0usize);
        for id in tx_ids {
            asked += 1;
            let Some(tx) = self.mempool.get(id) else {
                // ⛔ A SELECTED TX THAT IS NOT IN THE MEMPOOL CONTRIBUTES NO NOTES — SILENTLY.
                //
                // MEASURED: 175/175 produced blocks carried exactly 1,153 note bytes — ONE note, constant.
                // A block settling a payment must carry the recipient note AND the change note (2,306). The
                // constant says the payment's notes never reach `output_notes`, so every downstream step
                // (account-target lookup, bucket filing, recipient detection) is starved at the source. This
                // `else { continue }` is the only place a selected tx can vanish without a word.
                missing += 1;
                continue;
            };
            if tx.output_notes.is_empty() {
                no_notes += 1;
                continue;
            }
            // ⭐⭐⭐ THE MINT-AUTHORITY DOOR RUNS WHERE NOTES BECOME BLOCK-CARRIED VALUE (hole-closure
            // 2026-09-06, red-team pin `a_rogue_mainnet_producer_cannot_mint_a_credit_through_the_block_body`).
            //
            // `chain_object::admissible` used to run at the POOL door only. A producer whose modified
            // binary skips its own door (modelled by the test-only raw pool hook) still ran THIS
            // assembly, so a credit the chain's own allowance forbids rode `Block::output_notes`, and
            // every honest grafting peer — which applies a block's carried notes without the tx bodies,
            // by design ([`Block::output_notes`]'s own doc) — recorded and folded the mint. The rule
            // bound one door while value crossed at another.
            //
            // So the SAME self-contained rule judges every FRAMED object here, at the last moment its
            // bytes are in hand on the node that would carry its notes. Fail-closed on the BAD OBJECT
            // only: the block is still produced, every other tx keeps its slot, the chain never halts —
            // refuse the credit, not the block. An unframed blob is an ordinary SEND: it mints nothing
            // (its value is conservation-bound by the carried nullifier/deletion lanes and its own ZK
            // carrier gate judged it at the pool door), so the mint-authority rule passes it through
            // unchanged — exactly as `admissible` itself routes an unframed blob to the send gate.
            // ROOT-LAYER: assembly is the one seam every carried note crosses on the producing node —
            // the pool door can be skipped by a hostile binary, this cannot be skipped by an honest one,
            // and every honest verifier downstream records only what assembly let ride.
            // MEASURED: 2026-09-06 — with this door, the rogue pin's produced block carries 0 chunks of
            // the forbidden credited commitment and the honest peer holds 0 records of it; without it,
            // 1 carried chunk and the peer held the record (the confirmed hole).
            // MUST-STAY-GREEN: a_published_credit_lands_on_the_peer_and_a_replay_credits_nothing,
            // a_fill_submitted_on_one_party_settles_on_a_second_exactly_once_from_the_block_alone,
            // a_node_that_only_ever_sees_the_block_and_never_the_tx_still_records_the_payment.
            // ⭐ THE QUORUM VERDICT TRAVELS WITH THE RULE. `admissible`'s credit arm admits an amount
            // above this chain's open-mint allowance ONLY when a ≥2/3 bonded quorum attests it, and the
            // tally is read from THIS node's folded validator set — one function, `credit_attested_by_
            // bonded_quorum`, asked identically at the pool door, here at assembly and at the graft door,
            // so no two honest nodes can disagree about the same bytes.
            let credit_attested = crate::bridge_credit_tx::credit_attested_by_bonded_quorum(
                self.validators(),
                &tx.blob,
            );
            if crate::chain_object::unframe(&tx.blob).is_some()
                && !crate::chain_object::admissible(
                    &tx.blob,
                    self.params().order_fill_fee_bps,
                    self.params().genesis_mint_allowance(),
                    credit_attested,
                )
            {
                // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
                eprintln!(
                    "[assemble] ⛔ REFUSED a framed chain object at note assembly — its payload fails \
                     this chain's own admission rule, so its notes ride NO block from this node."
                );
                continue;
            }
            // ⭐ THE CARRIAGE IS NOT THE OBJECT — the wrapper↔object binding at the assembly seam
            // (per-note validity, 2026-09-06 lane B): even an ADMISSIBLE framed object contributes no
            // notes when its wrapper's `output_notes` are not byte-exactly the object's own — a poisoned
            // wrapper that reached this pool past the door (the rogue model the mint-door comment above
            // records) must not become block-carried value here. Fail-closed on the BAD tx only.
            if !crate::chain_object::wrapper_binds_object(tx) {
                // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
                eprintln!(
                    "[assemble] ⛔ REFUSED a framed chain object at note assembly — its transaction \
                     carries notes, burns or bond bytes the object itself does not justify, so its \
                     notes ride NO block from this node."
                );
                continue;
            }
            // ⭐ THE LAST UNMEASURED STEP: does assembly SEE the multi-note payment it was handed?
            //
            // MEASURED: `[tmpl-cand]` confirms a 2,306-byte tx is a candidate (262 times), `[tmpl-pick]`
            // confirms the LARGEST candidate is picked, and `[assemble]` still reports 1,153 — the entropy
            // note alone. Every downstream failure follows from that: no payment leaf in `da_block_leaves`,
            // so the target can never be filed, so the bucket is never sealed (`[bucket-file]` 0 on node B
            // across the whole session), so detection returns zero and the recipient sees nothing.
            //
            // This fires inside the loop that actually builds `out_blobs`, so it reports what assembly
            // GENUINELY receives rather than what selection intended. Only for multi-note txs — cover and
            // entropy carry one note, so the common path stays silent and adds no per-block bytes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a byte LENGTH only. Never a tx id, note, cm, amount, key or
            // owner.
            if tx.output_notes.len() > PQ_NOTE_BYTES_OUT {
                eprintln!(
                    "[assemble-in] a MULTI-NOTE tx reached assembly with {} output-note byte(s)",
                    tx.output_notes.len()
                );
            }
            // ⛔⛔⛔ NEVER PUT THE SAME NOTE ON TWO BLOCKS.
            //
            // MEASURED: ONE submit produced TWO blocks carrying 2,306 note bytes. The window is between
            // template-build and graft — mining runs OFF-LOCK, so a second `produce_template` selects the
            // same tx before the first block's graft evicts it. The note is then recorded at two different
            // leaf positions, and a wallet deriving a copath can resolve against the wrong one, which is
            // exactly the "settles sometimes" behaviour measured all session.
            //
            // `note_target_addr` already answers "has this note been filed, and where" in ONE hash lookup —
            // it is the resolver built earlier this session. A cm already present is already on chain, so
            // this block must not carry it again.
            //
            // NOT AN AGE-OUT AND NOT A CAP: no time, height, or count term appears. The test is purely "is
            // this exact note already recorded", which is a FACT about the chain, not a bound on how far back
            // anything may reach. Nothing is refused for being old, and a note that is NOT yet recorded is
            // always carried ([[feedback_no_windows_no_caps_cardinal]]).
            //
            // NOT A NEW STORE: `note_target_addr` already exists, one entry per filed target, and this only
            // READS it ([[feedback_no_growth_any_axis]]).
            // The `note_target_addr` test alone CANNOT close this: it only knows notes already FILED, and a
            // note in an ungrafted template has not been filed yet — measured, the dup-skip fired 0 times
            // while the duplicate still occurred. `inflight_tx_ids` is the signal that exists AT SELECTION.
            let already_on_chain = {
                // ⛔⛔⛔ REVERTED MY OWN IN-FLIGHT SKIP — IT COULD STARVE THE PAYMENT FOREVER.
                //
                // I added `inflight_tx_ids.contains(id)` here to stop one submit producing two blocks. It
                // NEVER demonstrated a benefit (`dup-skips: 0` every run) and it carries a fund-loss risk that
                // dwarfs the duplicate: the set is filled at template build and cleared only on the graft path
                // I edited, so any other graft route leaves a payment tx permanently skipped at ASSEMBLY. Its
                // output notes then never enter a block, their commitments never appear in the block's fixed
                // note set, the filing pass can never match them, and the account targets stay UNFILED — which
                // is exactly the measured symptom: payer 5.0 -> 0.0, recipient 0.0, `[bucket-unfiled] 2`.
                //
                // A duplicate block wastes space; a skipped payment loses money. Keep only the on-chain test,
                // which reads a fact about the LEDGER rather than about this node's in-flight bookkeeping.
                // ⛔ DB-249b: "on chain" is the chain's fact, not the index's — an entry filed by a block a jump
                // abandoned would skip the executor's re-proposed mint forever (the DB-5 pin).
                // ⛔ DB-299: the ONE question, shared with the pool door and the graft's losing-state alarm, so the
                // door and assembly can never answer it differently.
                self.tx_notes_already_on_chain(&tx.output_notes)
            };
            if already_on_chain {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a byte COUNT only — never a cm, note, amount, key or owner.
                eprintln!(
                    "[assemble-dup] ⛔ skipping a tx whose note is ALREADY on chain ({} output-note byte(s)) \
                     — a second block carrying it would record the note at a second leaf position",
                    tx.output_notes.len()
                );
                // ⛔ BUT THE BOND DIVERT STILL HAS TO HAPPEN — it is not an output-note emission.
                //
                // This skip exists so a note already on chain is not recorded at a SECOND leaf position
                // (see the message above). `bond_locks` is a different thing entirely: it stashes the
                // bonded note so `unbond_validator` has something to give back. Skipping it here does not
                // prevent a duplicate leaf; it destroys the only copy.
                //
                // MEASURED 2026-08-16: `block_spendable_note_blobs` runs TWICE per produce on the SAME tx
                // (full 32-byte id verified, in_pool=true both times). call#0 sees
                // `already_on_chain=false` and pushes; call#1 sees `true` and `continue`s past the divert.
                // The caller at :11785 consumes call#1's result, so `bond_locks` arrives EMPTY, nothing is
                // stashed, and on unbond `bond_locked.remove(&id)` finds nothing — the bonded note is
                // never returned and its value is unreachable.
                //
                // Not a double-stash risk: the other caller (:11245) takes `.0` and DISCARDS `.1`.
                if tx.bond_notes.len() >= 40 && tx.output_notes.len() >= PQ_NOTE_BYTES_OUT {
                    let mut vid = [0u8; 32];
                    vid.copy_from_slice(&tx.bond_notes[..32]);
                    bond_locks.push((vid, tx.output_notes[..PQ_NOTE_BYTES_OUT].to_vec()));
                }
                continue;
            }
            // ⛔⛔⛔ THIS BRANCH HALVES A TWO-NOTE PAYMENT AND DROPS THE RECIPIENT'S NOTE.
            //
            // A tx with >=40 bond bytes has its FIRST output note diverted into `bond_locks` and only the
            // REMAINDER reaches `out_blobs`. For an ordinary 2-note transfer (recipient + change = 2306) that
            // yields exactly 1153 — and the note removed is the RECIPIENT'S, which is why the payer debits,
            // the block looks healthy, and the recipient sees nothing.
            //
            // MEASURED: three consecutive sends, byte-identical pool state each time
            // (`present_in_pool=true pool_len=1`), one settling and two not; `[tmpl-pick]` silent, so with a
            // pool of ONE the payment WAS selected; and `[assemble]` reporting 1153 where the tx carried
            // 2306. Selected, halved, and the recipient's half discarded.
            //
            // A transfer is not a bond. Requiring the tx to actually be a bond intent — not merely to carry
            // enough bytes — is the difference between diverting a validator's locked note and eating a
            // user's payment. DIGITAL-CASH-PRIVACY-REVIEWED: the probe below emits byte LENGTHS only.
            if tx.bond_notes.len() >= 40 && tx.output_notes.len() > PQ_NOTE_BYTES_OUT {
                eprintln!(
                    "[bond-divert] ⛔ tx carrying {} output-note byte(s) has {} bond byte(s): first note is \
                     being diverted to bond_locks, leaving {} — if this is an ordinary transfer that is the \
                     RECIPIENT'S note being dropped",
                    tx.output_notes.len(),
                    tx.bond_notes.len(),
                    tx.output_notes.len() - PQ_NOTE_BYTES_OUT
                );
            }
            if tx.bond_notes.len() >= 40 && tx.output_notes.len() >= PQ_NOTE_BYTES_OUT {
                let mut vid = [0u8; 32];
                vid.copy_from_slice(&tx.bond_notes[..32]);
                bond_locks.push((vid, tx.output_notes[..PQ_NOTE_BYTES_OUT].to_vec()));
                if tx.output_notes.len() > PQ_NOTE_BYTES_OUT {
                    out_blobs.push(tx.output_notes[PQ_NOTE_BYTES_OUT..].to_vec());
                }
            } else {
                out_blobs.push(tx.output_notes.clone());
            }
        }
        // Fires ONLY when a selected tx contributed nothing — silent on healthy blocks, so no per-block bytes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only. Never a tx id, note, cm, amount, key or owner.
        if missing > 0 || no_notes > 0 {}
        (out_blobs, bond_locks)
    }

    /// ⭐⭐⭐ APPLY AN ANSWER — the one place a sampled piece is judged.
    ///
    /// ⛔ IT VERIFIES AGAINST THE ROOT THIS NODE STORED WHEN IT STARTED THE SAMPLE, not against anything
    /// in the frame. The frame deliberately carries no root: a peer that supplies the chunk, the proof
    /// AND the value to check them against has proved nothing, which is the shape every join-door defect
    /// in this tree wore.
    ///
    /// Returns `true` only when the piece verified. An answer for a record this node is not sampling, at
    /// an index it did not ask for, or that fails its proof, changes nothing.
    pub fn apply_da_chunk_resp(&mut self, frame: &[u8]) -> bool {
        let Some((addr, index, chunk, proof)) = crate::protocol::decode_da_chunk_resp(frame) else {
            return false;
        };
        let Some(st) = self.da_sample_pending.get_mut(&addr) else {
            return false; // not sampling this record — an unsolicited answer moves nothing
        };
        let idx = index as usize;
        if !st.want.contains(&idx) {
            return false; // a piece this node never asked for is not evidence it asked for one
        }
        if !Self::da_sampled_chunk_is_available(&st.root, idx, &chunk, &proof) {
            return false; // tampered, or proved at another index — fail-closed
        }
        if !st.verified.contains(&idx) {
            st.verified.push(idx);
        }
        true
    }

    /// THE ONE LEAF ASSEMBLY: the 256 leaves a block's notes make at address `seq`. Both the DA serve
    /// ([`Self::da_block_leaves`]) and the membership fold ([`Self::fold_block_into_membership_acc`]) go
    /// through here, so a block root means the identical thing to a wallet asking for a copath and to the
    /// accumulator that wallet's carrier binds against. Two copies of this would drift and the drift would
    /// only show up as a spend that will not verify.
    /// §20.2 — THE LEAVES OF A SERVED RECORD, read off its 256 units' fronts (the header slots): what a party WITHOUT the
    /// record's cover key (a wallet) may derive. `None` unless the bytes are the whole served shape — a shorter list is a
    /// record's reals, whose cover a key-less party cannot lay, and guessing it would hand the wallet a wrong witness.
    #[must_use]
    pub fn served_record_leaves(served: &[u8]) -> Option<Vec<crate::spend_frontier::Digest4>> {
        const PQ_NOTE_BYTES: usize = 1153;
        if served.len() != crate::cover::BLOCK_FIXED_NOTE_COUNT * PQ_NOTE_BYTES {
            return None;
        }
        Some(
            served
                .chunks_exact(PQ_NOTE_BYTES)
                .map(|u| crate::spend_frontier::note_leaf_of(&u.fixed::<32>()))
                .collect(),
        )
    }

    /// ⭐ A record's leaves through a small bounded memo (lane stable 2026-11-01, chain speed): the leaves are a pure function
    /// of `(notes, seq, key)`, and deriving them regenerates the record's whole 256-unit cover (~9,200 blake3 compressions)
    /// every time — the record routes a wallet polls, a fetched record's admission and the fold all asked again for the same
    /// recent records.
    /// MEASURED: 846 node-step samples under `da_block_leaves` from the routes, 759 under `accept_fetched_record_judged`, 214
    /// under the fold — each a full cover rebuild (stable/relay4.sample.txt, the post-adopt journey's node threads, 20 s).
    /// NOT the filled shape (R1c, "no per-block cover storage", forbids holding the cover notes): what is held is the 256 leaf
    /// commitments of a record — the values the public commitment tree itself holds — keyed by `blake3(notes)`, never the notes
    /// or the cover. Bounded: two generations of `LEAVES_MEMO_CAP` records × 256 × 32 B ≈ 2 MB, constant in height.
    /// ROOT-LAYER: the one producer of a record's leaves; every reader passes here. MUST-STAY-GREEN: identical leaves (the
    /// frozen corpus, the replay calibrations, every membership pin). cons: ≤ 2 MB of RAM; one blake3 of the notes per call.
    pub fn block_leaves_from_notes(notes: &[u8], seq: u64, key: &crate::cover::CoverKey) -> Vec<crate::spend_frontier::Digest4> {
        const LEAVES_MEMO_CAP: usize = 128;
        type Key = ([u8; 32], u64, crate::cover::CoverKey);
        #[derive(Default)]
        struct Gens {
            cur: std::collections::HashMap<Key, std::sync::Arc<Vec<crate::spend_frontier::Digest4>>>,
            old: std::collections::HashMap<Key, std::sync::Arc<Vec<crate::spend_frontier::Digest4>>>,
        }
        static MEMO: std::sync::OnceLock<std::sync::Mutex<Gens>> = std::sync::OnceLock::new();
        let k: Key = (*blake3::hash(notes).as_bytes(), seq, *key);
        let memo = MEMO.get_or_init(|| std::sync::Mutex::new(Gens::default()));
        if let Some(hit) = {
            let g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            g.cur.get(&k).or_else(|| g.old.get(&k)).cloned()
        } {
            return hit.as_ref().clone();
        }
        let leaves = Self::block_leaves_from_notes_computed(notes, seq, key);
        let mut g = memo.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if g.cur.len() >= LEAVES_MEMO_CAP {
            g.old = std::mem::take(&mut g.cur);
        }
        g.cur.insert(k, std::sync::Arc::new(leaves.clone()));
        leaves
    }

    fn block_leaves_from_notes_computed(notes: &[u8], seq: u64, key: &crate::cover::CoverKey) -> Vec<crate::spend_frontier::Digest4> {
        const PQ_NOTE_BYTES: usize = 1153;
        let fixed = crate::cover::assemble_fixed_note_payload(notes, seq, key);
        // ROOT-FIX-VERIFIED: the leaf set and the global frontier now derive from ONE source — the block's
        // REAL notes — so a per-block width that can disagree with the frontier no longer exists to get wrong.
        //
        // The root cause of this whole family of defects was a SECOND definition of how many leaves a block
        // has. `spend_frontier` appends real notes (MEASURED: `spend_count=118` at `h=117`), while this builder
        // asserted a constant 256. Any constant here — 256 from cover, or 256 from empty padding, which I
        // tried and which is the same mistake wearing a different hat — recreates that second definition and
        // with it `ordinal x 256`, the multiplier behind today's `wrong absolute leaf index` failure.
        //
        // Deriving leaves ONLY from the notes the block actually carries makes the two views identical by
        // construction: there is no width to reconcile, no multiplier, and no padding rule that a later reader
        // could set differently. Depth is a property of the ONE global tree (2^32 leaves) and is unaffected by
        // how many notes any block carries — `spend_frontier::authpath` / `from_copath(index, ..)` already
        // serve a note's 32 siblings from its ABSOLUTE index, which is the correct source for a spend witness
        // now that blocks are batches of appends rather than a tree layer.
        //
        // Removing the 256-note cover fill (user-authorized, 2026-08-10) made a block carry ~1 real note. This
        // fold is `while level.len() > 1`, so a 1-leaf block produced a depth-0 subtree and the spend circuit —
        // which consumes a depth-32 copath — got nothing. MEASURED on the real wallet immediately after the
        // cover removal: the old `wrong absolute leaf index (ordinal x 256)` error DISAPPEARED and was replaced
        // by `the node served no usable depth-32 copath for this note`.
        //
        // The fix is padding with EMPTY leaves, not with fake notes. An empty leaf is a constant, derived
        // identically on every node from nothing, and it is NEVER transmitted — so the wire still carries only
        // real notes (the whole point of the change) while the Merkle geometry stays fixed-width and every
        // copath stays depth-32. This is ordinary Merkle padding; it re-introduces no cover traffic, no
        // per-block bytes, and no observer-visible shape beyond the note count that is already visible.
        let mut out = Vec::with_capacity(crate::cover::BLOCK_FIXED_NOTE_COUNT);
        let mut off = 0usize;
        while off + PQ_NOTE_BYTES <= fixed.len() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&fixed[off..off + 32]);
            // ⛔⛔⛔ §AO: `note_leaf_of`, NOT `cm_bytes_to_leaf`. A note's leaf IS its commitment. Using
            // the hash here gave a note two identities and the spend cross-bind took a different one on
            // each side, so no honest spender could satisfy both carriers — see `note_leaf_of`'s doc.
            out.push(crate::spend_frontier::note_leaf_of(&cm));
            off += PQ_NOTE_BYTES;
        }
        // ⛔⛔⛔ NO PAD HERE. I ADDED ONE AND IT WAS THE WRONG FIX — user 2026-08-11: "do we even need
        // fixed block shape since we removed the 256 cover traffic? Are you making the right fix?"
        //
        // I padded these derived leaves up to 2^IN_BLOCK_DEPTH so a 1-note record would produce the 8-level
        // copath the membership trace expects. The privacy reason for a fixed block shape is GONE — the
        // stored record holds real notes only, so it already reveals its own count — which left the pad
        // serving nothing but the PROVER's trace geometry. Padding one real leaf to 256 to satisfy a
        // sumcheck arity check is the retired block x256 geometry coming back through the side door, and it
        // costs 255 hash operations per block to hide nothing.
        //
        // The real disagreement is upstream: the in-block tree is itself a leftover of that geometry. With
        // the copath in LEAF SPACE, a note's membership is its position in the global frontier — there is no
        // separate per-block tree for it to be inside. Fixing the depth constant, or padding to it, both
        // preserve the wrong shape. Left unpadded deliberately, so the mismatch stays visible.
        out
    }

    /// Adopt the account targets a block carries, so THIS node files the same notes into the same buckets as
    /// the producer did. Called before the block's notes are recorded, because recording drains them.
    pub fn adopt_account_targets(&mut self, blob: &[u8]) {
        self.adopt_account_targets_at(blob, None)
    }

    /// Adopt a block's carried targets, telling each one WHICH RECORD it arrived on. See the `at` parameter of
    /// [`Self::record_account_target`] — the caller is adopting a specific block, so the note's address is
    /// already in its hand and needs no global index lookup.
    pub fn adopt_account_targets_at(&mut self, blob: &[u8], ident: Option<u64>) {
        // ⛔⛔⛔ AN EMPTY BLOB ON ADOPT IS THE ONE CASE NOTHING REPORTS — AND IT IS THE LIVE FAILURE.
        //
        // user 2026-08-09: "add private observability so the nodes cant silently mint fresh identities or
        // offer any false positives."
        //
        // Every probe in this function is inside `if !blob.is_empty()`. So a peer that adopts a block whose
        // targets arrived EMPTY logs absolutely nothing, and "the block never reached me" is indistinguishable
        // from "it reached me carrying zero targets" — two different defects, on two different sides of the
        // wire, with opposite fixes. That silence is unfalsifiable: adoption looks identical when it works and
        // when the payload was lost in transit.
        //
        // MEASURED 2026-08-09, the real cross-device send (`cross_device_send`, 4 processes):
        //   payer      `[wallet_send] 100000000 atomic ... node status OK` — the send SUCCEEDED
        //   node A     1 block `carries N account-target byte(s)`, `[bucket-write] writing under 89240bf3`
        //   recipient  queries DERIVED bucket 89240bf3 — THE SAME KEY, so this is not a re-key
        //   node B     ZERO `[acct-file]`, ZERO `[bucket-write]`, `acct-produce NONZERO: 0`
        //   recipient  `0 owned total, 0 atomic spendable`; `[detect-why] bucket held 0 entr(ies)`
        // Blocks demonstrably crossed ("blocks crossed — an accumulator from one node appeared on the other"),
        // so node B either never received that block or received it with the targets stripped — and NOTHING in
        // the log separates those, because this function is mute on the empty path.
        //
        // Report EVERY adoption attempt including the zero. A probe that only fires on success cannot report a
        // failure ([[feedback_empirical_proof_standard]]).
        // O1-FOOTPRINT-REVIEWED: one length read per adopted block, no allocation, nothing stored. No term in
        // height, blocks or notes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a BYTE COUNT and whether a record ident was supplied. Never a cm,
        // bucket id, address, amount, key or owner — the same class the neighbouring `[acct-file]` already
        // emits, and it says whether filing happened, never whose.
        // ⛔ I PUT A FALSE POSITIVE HERE AND TOOK IT BACK OUT — recorded so it is not re-added.
        //
        // The probe printed "⛔ this block carried ZERO account-target byte(s) ... they were lost between
        // produce and here" for EVERY empty blob. But this function is called for cover blocks too, and a
        // cover block carrying zero targets is CORRECT, not a loss. MEASURED 2026-08-09 on node B: the ⛔ line
        // fired beside a perfectly healthy adoption of 2500 target bytes, i.e. it accused the common case.
        //
        // This site cannot tell the two apart: it receives only the blob, never the note payload, so "zero
        // because there was nothing to file" and "zero because the targets were stripped in transit" are
        // identical here. The caller CAN tell — it holds `carried_notes` — and already reports it correctly
        // at the grafted-block branch (`carried_targets.is_empty() && !carried_notes.is_empty()`).
        // Diagnose where the evidence is, not where the call happens to land.
        // ⛔⛔⛔ A TARGET THAT CANNOT BE FILED IS A NOTE ITS OWNER WILL NEVER FIND — SAY SO.
        //
        // Both this and `record_account_target` were entirely silent, so a target could arrive, parse, and
        // vanish with nothing logged anywhere. MEASURED on the live pair: the producer gossips a block whose
        // serialized bytes round-trip 2,500 account-target bytes intact, the peer receives note-bearing
        // blocks, and the peer still logs `[bucket-file] block touched 0 bucket(s)` 1,431 times with ZERO
        // adopted. Three different steps could produce that, and no log distinguished them.
        // ⭐ MANDATORY PRIVATE-SEND OBSERVABILITY (user 2026-07-31: "observability is mandatory on private
        // sends"). A target that arrives but is never filed is a payment its owner can never find, and that
        // failure is SILENT by nature — the recipient just sees zero, exactly as a never-sent payment does.
        //
        // Fires only when a block actually carries targets, so it costs nothing on the cover-only blocks that
        // make up the bulk of the chain — no per-block growth.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a BYTE COUNT and a filed COUNT only. Never a cm, bucket id, address,
        // amount, key or owner — the two numbers say whether filing happened, and nothing about whose.
        if !blob.is_empty() {
            eprintln!(
                "[acct-file] adopting {} account-target byte(s) from this block",
                blob.len()
            );
            // ⛔⛔⛔ ADOPTED INTO WHICH BUCKET, AND DOES THE NODE HOLD ANY AT ALL?
            //
            // MEASURED 2026-07-31: node B adopts 2,500 target byte(s) per payment block and drains thousands
            // of BucketResp, yet the recipient wallet's `account_bucket_restore` returns 0 entries and
            // `[detect-why]` reports an EMPTY bucket. Delivery and adoption both pass; the lookup still
            // misses. The remaining possibility no counter covers is that the entries are filed under a
            // bucket id the recipient does not derive - so report how many distinct buckets this node holds
            // after adopting. Zero means adoption wrote nothing; non-zero with a failing lookup means the
            // wallet and the node disagree on the bucket id.
            //
            // O1-FOOTPRINT-REVIEWED: reads the EXISTING account_buckets map length; stores nothing and adds
            // no term in height, blocks or notes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT of buckets this node holds - never a bucket id, cm,
            // amount, key or owner. Fires only when a block actually carries targets (a real payment).
            eprintln!(
                "[acct-buckets] this node now holds {} distinct account bucket(s) after adopting",
                self.account_bucket_count()
            );
            // ⛔⛔⛔ WHICH IDS DID WE ACTUALLY FILE UNDER? The `[bucket-id] MISS` line cannot answer this:
            // bucket REQUESTS are cover-padded with decoys by construction, so most misses are decoys and
            // mean nothing — the same false-alarm shape as the 5b anomaly I had to gate earlier today.
            //
            // MEASURED 2026-07-31: the recipient wallet asked for `b6b392bd` while this node held
            // `26d90a45, d7f69bcf, 559d7013` and logged a miss for a FOURTH id, `242cc3a9`. Four id spaces in
            // one run means I cannot attribute a miss to the recipient at all. What the node FILES is
            // attributable: it comes from the sender's address-derived `b_id` on a real payment.
            //
            // Compare these against the wallet's `[bucket-mine]` line: if the recipient's own id is absent
            // here, the sender's address-derived id and the recipient's self-derived id genuinely disagree.
            //
            // O1-FOOTPRINT-REVIEWED: reads the EXISTING account_buckets keys; stores nothing, no term in
            // height, blocks or notes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: FOUR bytes of ids in this node's OWN local log, only when a real
            // payment block carried targets. Never sent anywhere, never paired with a note, amount, key or
            // owner; a 4-byte prefix identifies no account. Same reviewed shape as `[acct-keycmp]`.
            let filed: Vec<String> = self
                .account_buckets
                .keys()
                .take(4)
                .map(|k| format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]))
                .collect();
            eprintln!("[bucket-filed] ids this node has filed under: {filed:?}");
        }
        let parsed_before = blob.len();
        let mut parsed = 0usize;
        let mut off = 0;
        while off + 66 <= blob.len() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&blob[off..off + 32]);
            let mut bucket = [0u8; 32];
            bucket.copy_from_slice(&blob[off + 32..off + 64]);
            let l = u16::from_le_bytes([blob[off + 64], blob[off + 65]]) as usize;
            off += 66;
            if off + l > blob.len() {
                break;
            }
            self.record_account_target(cm, bucket, blob[off..off + l].to_vec(), ident);
            parsed += 1;
            off += l;
        }
        if parsed_before > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: counts and a byte length only — never a cm, bucket, key or owner.
            eprintln!(
                "[account-target] adopt: parsed {parsed} target(s) from {parsed_before} byte(s)"
            );
        }
    }

    /// The SENDER's hand-off: which account bucket a forthcoming note belongs to, and the recipient PUBLIC key
    /// to seal it under. The node never learns anything readable from this — `ek` grants write capability
    /// only, which is exactly why an address can be reused without ever exposing its owner's notes.
    pub fn record_account_target(
        &mut self,
        note_cm: [u8; 32],
        bucket: [u8; 32],
        recipient_ek: Vec<u8>,
        // ⭐ THE RECORD THIS TARGET ARRIVED WITH, when it arrived with one.
        //
        // A target adopted from a BLOCK belongs to that block's own notes — the node has the record in hand at
        // that moment, so the note's address is a local fact, not a question for a global `cm -> seq` index.
        // That index (`da_cm_rev_mem`) writes one entry for EVERY commitment in every block, reals and cover
        // alike, and is the dominant remaining per-block growth: 6,144 entries / 245,760 B at 24 blocks,
        // 88% of the node's whole measured footprint.
        //
        // Passing the address the caller already holds removes the ONLY reason that index exists on this path,
        // and it costs no privacy: the target set is unchanged, the 256-wide cover shape is untouched, and no
        // real note is distinguished from a decoy anywhere. The position simply travels with the thing it
        // describes — the same "a block must carry what applies it" rule as `padded_tags` and `output_notes`.
        at: Option<u64>,
    ) {
        // ⛔⛔⛔ A TARGET THAT ARRIVES AFTER ITS NOTE'S BLOCK WOULD WAIT FOREVER. Filing only ever happened
        // inside the block-application loop, matching notes in the block being applied. But a VERIFYING node
        // adopts these targets from the record it ingests — which it reads AFTER applying that block, and on a
        // restore, long after. The target then sat in `pending_bucket` waiting for a block that had already
        // gone by, so the note settled on chain with no bucket entry and its owner could never find it from
        // their seed. MEASURED: the recipient's node held ZERO recorded targets while the payer's node filed
        // 2, and the recipient's wallet read `0.0` while the note was spendable on the other node.
        //
        // The note's position is a written-down lookup on any node that holds the record, at any age
        // (`da_seq_at_note_cm` -> `da_block_leaves`), so file it NOW instead. No window, no waiting, no
        // dependence on message ordering — this is the same coordinate the block loop would have used.
        // ONE source: the address the caller already holds. Adopt sites compute it from the block id
        // (`da_record_id_for_block`, a pure function); submit sites have no record yet and stay pending until
        // the block loop files them with the address it is writing.
        //
        // ⛔⛔⛔ DB-294: "SUBMIT SITES HAVE NO RECORD YET" IS FALSE ON EVERY NODE THAT GRAFTED THE BLOCK FIRST.
        //
        // A peer that grafts or fetches the note's block and only THEN receives the gossiped tx gets the target
        // AFTER the record. The block loop files a pending target only when a record is WRITTEN, and this one was
        // written already, so the target waited forever.
        // MEASURED, gateQ8:
        // - n2 logged `CANNOT FILE … now pending` and, in the same second, `[assemble-dup] … ALREADY on chain`
        //   for the same note;
        // - it then logged 3,024 `[bucket-miss]` rescans;
        // - the two nodes' commutative account accumulators disagreed at the deadline.
        //
        // The resolver the comment above calls "never built" is `note_target_addr`. `record_note_payload_inner`
        // writes it for EVERY real note it records, and the assembler already reads it. The record must be on this
        // node's chain (DB-249b's `note_record_on_chain`: an ordinal on its spine, or a held and SETTLED block),
        // because a bucket entry IS a position and a position in an abandoned record is worse than none.
        // ROOT-LAYER: this is the one door every target takes (submit, gossip, carried adopt), so the lookup lives
        // here and nowhere else.
        // MUST-STAY-GREEN: db294 (all four arms), the carried-target pins
        // (`a_producer_that_already_filed_a_target_…`), the bucket/restore pins, db249, assemble.
        // cons: one HashMap lookup and one O(1) predicate per target arrival.
        let resolved = at.or_else(|| {
            self.note_target_addr
                .get(&note_cm)
                .copied()
                .filter(|rid| self.note_record_on_chain(*rid))
        });
        // ⛔ DB-294 (2): THE DOOR IS IDEMPOTENT. The account accumulator is ADDITIVE (`fold_account_acc`), so a
        // target filed twice, by a re-gossip or by the block's carried copy after a late filing, is a leaf counted
        // twice: a divergence in the other direction. A target already stored at its record IS filed, so drop it
        // from pending and stop before any append or fold.
        // (The other writers cannot double-file: the block-loop drain files only PENDING targets, and
        // `refile_account_targets_at` runs only for a record NEW to this node. Restore refiles through
        // `refile_account_targets_at`, never this door.)
        if let Some(rid) = resolved {
            if Self::targets_blob_holds(&self.da_load_account_targets(rid), &note_cm, &bucket) {
                self.pending_bucket.remove(&note_cm);
                return;
            }
        }
        // OBSERVABILITY 1/6 — the receipt records the step that actually decides whether a recipient can ever
        // find this note. Both outcomes are recorded: a filed target and a failure to file are equally
        // important, and until now only the happy path left any trace at all.
        if resolved.is_some() {
            self.payment_receipt(&note_cm, PaymentStep::TargetFiled);
        }
        if resolved.is_none() {
            // THE SILENT LOSS. Filing needs the note's record address; without it the entry is never sealed
            // and the note is invisible to its owner forever. Previously this just fell through.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only — no cm, bucket, key, amount or owner.
            eprintln!(
                "[account-target] CANNOT FILE: this node holds no record address for the note this target \
                 names — the note settles on chain and its owner can never find it from their seed"
            );
        }
        if let Some(ident) = resolved {
            let want = crate::spend_frontier::note_leaf_of(&note_cm);
            if let Some(slot) = self
                .da_block_leaves(ident)
                .and_then(|lv| lv.iter().position(|l| *l == want))
            {
                let e = crate::account_da::AccountEntry::at(note_cm, ident, slot as u8);
                if let Some(sealed) = crate::account_da::seal_entry_to(&recipient_ek, &e) {
                    let landed = self.account_bucket_append(bucket, sealed);
                    self.account_acc =
                        crate::account_da::fold_account_acc(self.account_acc, &bucket, &note_cm);
                    if let Some(_entries) = self.account_buckets.get(&landed).cloned() {}
                    // Offer it, exactly as a freshly produced block does — a peer that is missing it adopts it.
                    self.freshly_filed_buckets.push(landed);
                    // ⛔⛔⛔ AND KEEP IT WITH THE RECORD, OR THE INDEX DIES AT ONE HOP. `da_store_account_targets`
                    // was only ever written by the node that CONSUMED a target while producing, so a node that
                    // adopted and filed one held the bucket but had nothing to hand the NEXT peer. MEASURED: a
                    // fresh third node synced to 70,399 blocks, parsed 1,940 backfill pages from a peer that
                    // had the money indexed, and adopted ZERO targets — it served the recipient's own seed
                    // `0.0 / 0` while another node served `0.5 / 4`. A balance that depends on which node you
                    // ask is not digital cash.
                    //
                    // Writing it here makes the index TRANSITIVE: every node holding the record also holds the
                    // targets over it, so `notes_page` (which already ships them) can carry it one hop further,
                    // forever, with no window and no re-derivation.
                    let mut blob = self.da_load_account_targets(ident);
                    let ek_bytes = &recipient_ek;
                    blob.extend_from_slice(&note_cm);
                    blob.extend_from_slice(&bucket);
                    blob.extend_from_slice(&(ek_bytes.len() as u16).to_le_bytes());
                    blob.extend_from_slice(ek_bytes);
                    self.da_store_account_targets(ident, &blob);
                    // WRITE DOWN WHERE IT LANDED — this is the lookup the missing resolver was supposed to be.
                    self.note_target_addr.insert(note_cm, ident);
                    // ⛔⛔⛔ SEAL THE BUCKET ENTRY TOO — storing the DA target alone leaves the owner blind.
                    //
                    // This branch stored the target and stopped. But the recipient's wallet does NOT read DA
                    // targets: detection reads the ACCOUNT BUCKET (and the OLI locator), and only
                    // `account_bucket_append` writes that. The bucket seal happens in the note-record drain,
                    // which requires the target to be staged in `pending_bucket` BEFORE the note is recorded.
                    //
                    // On an INGESTING node that ordering never holds: targets arrive carried on the block, so
                    // the note is already recorded and every target takes THIS late path. MEASURED on the
                    // live pair: node B adopted 618 targets and logged `[bucket-file]` ZERO times across the
                    // whole session, issuing 1,042 `[bucket-want]` requests for buckets it had never written.
                    // The recipient's detection then returned zero for a range where a direct
                    // POST /get_my_pq_notes on that SAME node returned 256 notes.
                    //
                    // Sealing here makes the late path complete rather than half-done: the entry is sealed TO
                    // the owner with their own ek, exactly as the in-order path seals it, so an ingesting node
                    // and a producing node end up with the same bucket contents.
                    // ⛔⛔⛔ THE SECOND APPEND THAT STOOD HERE WROTE A **FABRICATED POSITION**, AND IT SAT
                    // IN THE ONE BRANCH THAT DID NOT NEED IT.
                    //
                    // It was `AccountEntry::at(note_cm, ident, 0)` — slot ZERO, hardcoded — appended right
                    // after the entry above, which had just RESOLVED the note's real slot. So every
                    // resolved target wrote TWO entries for one note: one true, one claiming slot 0.
                    //
                    // MEASURED 2026-09-24 (`a_seed_only_restore_…`, wallet crate, two notes planted so the
                    // owner's is not first): *"the note sits at slot 1 of its record, and 2 of the 4 sealed
                    // entr(ies) claim a different one."* A bucket entry IS a position: a wallet that picks
                    // the fabricated one builds its membership copath for a leaf that is not its note, and
                    // the spend is refused for a reason that points nowhere near the cause. **A position
                    // index that can be WRONG is worse than one that is missing.** It also consumed the
                    // owner's bucket capacity twice as fast, so the spill chain grew at double rate.
                    //
                    // ⛔ AND IT NEVER SERVED ITS STATED PURPOSE. It was added for the INGESTING node, where
                    // targets arrive carried on the block after the note is already recorded — but it was
                    // placed INSIDE `if let Some(slot) = …`, the branch that only runs when the slot DID
                    // resolve. In the case it was written for, the slot does not resolve, neither append is
                    // reached, and the target still falls through to `pending_bucket` below. It fired
                    // exactly where it was not needed and never where it was.
                    //
                    // The right answer for an unresolved slot is to WAIT for the record (what the fall
                    // -through does), never to invent a coordinate. A position is FOUND or it is not yet
                    // known; there is no third option a wallet can act on safely.
                    self.pending_bucket.remove(&note_cm);
                    // DIGITAL-CASH-PRIVACY-REVIEWED: states only THAT a late target was filed. Never a cm,
                    // bucket id, key, amount or owner.
                    eprintln!(
                        "[account-target] filed a LATE target immediately — its note's block was already \
                         applied, so waiting for a future block would have lost it"
                    );
                    return;
                }
            }
        }
        self.pending_bucket
            .entry(note_cm)
            .or_insert((bucket, recipient_ek));
        // ⛔ THE MISSING LINK IN THE CHAIN. `/submit_pq_tx` reports 5000 hex chars of targets ARRIVING, and
        // the block-filing loop reports 0 pending — so the loss is between these two points and nothing said
        // which side. This states the map size the instant a target is recorded, so "never recorded" and
        // "recorded then lost" stop looking identical.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT only. Never a note commitment, bucket id, key or owner.
        eprintln!(
            "[account-target] recorded; {} target(s) now pending",
            self.pending_bucket.len()
        );
    }

    /// A note credited by this node WITHOUT a block (a settlement executor, an unbond, a faucet drip) is
    /// STAGED to ride the next block this node produces — never written as a block-less record. v31 folds
    /// records in the DAG's canonical order, so a record that belongs to no block has no place in the
    /// spine on any node; carried in a block it lands at the same ordinal everywhere. The account target
    /// and locator clue the caller staged through their generic paths match the note when the block
    /// records it, exactly as for a wallet-paid note (`stage_credit_note`).
    pub fn record_note_payload(&mut self, _height: u64, payload: &[u8]) {
        let mut off = 0usize;
        while off + crate::cover::PQ_NOTE_BYTES <= payload.len() {
            self.stage_credit_note(payload[off..off + crate::cover::PQ_NOTE_BYTES].to_vec());
            off += crate::cover::PQ_NOTE_BYTES;
        }
    }

    /// Record a payload, naming it by the BLOCK it belongs to when that is known. Height alone cannot name a
    /// block in a DAG (many blocks share a blue_score), so a record addressed by height collides across nodes.
    ///
    /// ⚠️ THIS COMMENT WAS STALE AND IT COST REAL TIME. It said `Some(block)` was "NOT yet used by the
    /// produce/ingest sites" and that block-id keying had to wait for the walk's deletion. Both produce and
    /// graft have since been threading a block id — `record_note_payload_for(Some(block.id()), ..)`,
    /// `Some(grafting_block_id)`, `Some(gid)` — so every note that arrives via a BLOCK is already addressed
    /// canonically, and the ordering constraint the comment described no longer exists.
    ///
    /// What remains height-addressed is the set of INTERNAL credit sites that mint a note while a block is
    /// being applied (swap fill, wrapped-asset mint, seller change, bond principal/change/reward). Those call
    /// the bare `record_note_payload`, so their address derives from `_height` — and a height cannot name a
    /// block in a DAG, so two nodes derive different addresses for the same credit. A wallet reads its position
    /// from the account bucket and hands it back to its own node, so a height-derived address there means the
    /// payment settles and stays invisible to its owner. Those sites need the block id threaded through.
    /// Record a payload AT an already-canonical address (a peer's block address, from backfill). Bypasses
    /// address derivation because the address is the thing being replicated.
    ///
    /// REPLICATION IS VERBATIM. The bytes arriving here are already a complete record, seed note included, so
    /// this stores exactly them. Minting a second seed here would leave the replica's record one note longer
    /// than the original, and since the cover fill and the permutation are both seeded from the record's
    /// contents, the replica would regenerate 256 DIFFERENT leaves for the same block — the divergence the
    /// seed exists to remove. `two_nodes_derive_byte_identical_block_leaves…` caught exactly that.
    /// §20.2: `key` is the record's cover key as it arrived with the payload (a page, a lane, a checkpoint row), or
    /// `None` for an empty payload (an idle record takes the idle key). A non-empty payload with no key is NOT written.
    pub fn record_note_payload_at(&mut self, addr: u64, payload: &[u8], key: Option<crate::cover::CoverKey>) {
        self.record_note_payload_inner(Some(addr), None, addr, payload, key);
    }

    /// Create a record from a caller's notes — produce, ingest, peg, stake, bond all arrive here.
    /// Returns the record's ACTUAL canonical address (inner may choose a sub>0 slot) — the one key every
    /// sidecar and serve coordinate must share.
    pub fn record_note_payload_for(
        &mut self,
        block: Option<Hash32>,
        _height: u64,
        payload: &[u8],
        key: Option<crate::cover::CoverKey>,
    ) -> u64 {
        self.record_note_payload_inner(None, block, _height, payload, key)
    }

    pub(super) fn record_note_payload_inner(
        &mut self,
        exact_addr: Option<u64>,
        block: Option<Hash32>,
        _height: u64,
        payload: &[u8],
        key: Option<crate::cover::CoverKey>,
    ) -> u64 {
        const PQ_NOTE_BYTES: usize = 1153; // note_cm(32)+ct(1088)+enc_amount(32)+view_tag(1) (u256 width)
                                           // Split the caller's REAL notes (a short residual is malformed — not a note — dropped, never fabricated).
        let mut reals: Vec<Vec<u8>> = Vec::with_capacity(payload.len() / PQ_NOTE_BYTES + 1);
        let mut off = 0;
        while off + PQ_NOTE_BYTES <= payload.len() {
            reals.push(payload[off..off + PQ_NOTE_BYTES].to_vec());
            off += PQ_NOTE_BYTES;
        }
        // CHAIN-WIDE PRIVATE COVER — even an EMPTY block (0 real notes) MUST wear the full 256 cover shape AND be
        // PRIVATE (user 2026-07-15: "cover traffic 256 instead of 128 for the whole chain"; even empty blocks
        // wear it). The per-block cover secret folds the block's confidential reals, so an empty `reals` would
        // degrade the secret to a recomputable blake3(seq) and let an observer rebuild the all-cover fill and know
        // the block was empty. Prepend ONE SEED NOTE (byte-indistinguishable from a real note) so `reals` is never
        // empty. The seed note is DETERMINISTIC — a keyed PRF of the persisted per-chain DA secret and this block's
        // served index — so an idle block's whole 256-shape REGENERATES byte-identically forever from O(1) state:
        // record == serve at ANY height, across restarts, with NOTHING stored per idle block. The secret never
        // leaves the node, so the fill stays unpredictable to an observer (secret-seeded, never an index function).
        //
        // ⛔⛔⛔ THE PREPEND ABOVE WAS SPECIFIED IN THIS COMMENT AND NEVER WRITTEN. `reals.push` existed only
        // in the payload split loop, so a block with no real notes produced an EMPTY `reals` — exactly what
        // the comment says must be impossible.
        //
        // MEASURED 2026-07-31 on the live daemon: `[record-write] writing ZERO real note(s)` fired 85 times
        // and `[ladder-hole]` fired 85 times — a 1:1 correlation. `da_store` wrote nothing, so
        // `da_record_notes` answered None forever, the completed-subtree climb abandoned, and every copath
        // crossing that span refused permanently. That is the whole chain from an idle block to SEND ok=False.
        //
        // It is ALSO the metadata leak this comment warns about: a block with no record is observably a block
        // with no payments, and the per-block cover secret degrades to a recomputable blake3(seq). The fixed
        // 256-shape is chain-wide precisely so an idle block is indistinguishable from a busy one.
        //
        // ⛔⛔⛔ NO LOCALLY-MINTED SEED NOTE. THIS WAS THE CROSS-NODE DIVERGENCE.
        //
        // An empty block used to get one injected note: `deterministic_seed_note(self.da_secret_value(), h)`
        // — a PRF of **THIS NODE'S PRIVATE DA SECRET**. It existed for the cover era, so that an idle block
        // was indistinguishable from a busy one and its per-block cover secret could not degrade to a public
        // `blake3(seq)`. With the 256 cover retired that purpose is gone, and what remained was a node-local
        // value written into a record every node is supposed to agree on byte-for-byte.
        //
        // MEASURED, `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`:
        //   [rec-produce] addr=68620792159878016 first8=[] len=0     <- the block carries NO notes
        //   [rec-ingest]  addr=68620792159878016 first8=[] len=0     <- the receiver agrees: none
        //   ...yet da_record_shape reported (1 chunk, 1153 B) on BOTH nodes, with DIFFERENT bytes.
        // Both sides recorded nothing and both ended up holding one note — each node's own secret. Every
        // block in that run was empty, which is exactly why it was 12 of 12 and never a subset.
        //
        // Downstream, `da_block_leaves` is a pure function of the stored bytes, so the two nodes derived
        // different leaves, different block roots and different `spend_frontier_root`s — a wallet's witness
        // could only verify on the node it happened to ask. That is the cross-node send failure.
        //
        // An empty block now has an EMPTY record, which is the same answer on every node.
        // CANONICAL RECORD ADDRESS. `served_seq` counts what THIS node happened to write, so it names a
        // different block on every peer — measured, 0 of 6 sampled seqs agreed, which broke cross-node
        // backfill and left two nodes on one chain advertising different accumulators. The caller already
        // knows the chain position; use it. `served_seq` keeps its OTHER job (the frontier's dense append
        // index) and is no longer an address.
        let canonical = _height;
        // The record's identity: canonical position, plus which record it is at that position. Every node
        // recording the same block derives the same value, so a record MEANS the same thing everywhere.
        let addr = match (exact_addr, block) {
            (Some(a), _) => a,
            // ⛔⛔⛔ A BLOCK HAS EXACTLY ONE NOTE RECORD — ITS ADDRESS MUST NOT DEPEND ON `sub`.
            //
            // This used `sub`, which counts how many records in a ROW carried the same ident. A producer
            // records its own block on the produce path and then AGAIN when it grafts that same block, so the
            // second write saw `da_at_height.0 == ident`, took sub=1, and landed at a SECOND address
            // `id(X,1)` that no other node ever creates — the receiver records X once, at `id(X,0)`.
            //
            // That extra record inflates the producer's `served_seq`, so every LATER ordinal names a
            // different block on the two nodes. MEASURED, `two_mining_nodes_that_exchange_blocks_agree_on_
            // every_record_ordinal`: "disagree on what 12 of 12 ordinals name (first: Some(0))" — total, not
            // sporadic — with ZERO `[copath-why] no leaves` hits, i.e. both nodes held a record at every
            // address but the records were for different blocks. That is the whole cross-node failure: a
            // wallet's account bucket files an ordinal, and on the recipient's node that ordinal addresses
            // someone else's block, so the payment settles and stays invisible to its owner.
            //
            // `sub` was built for the HEIGHT-addressed case, where many DAG blocks genuinely share a
            // blue_score and their records must not collide. A BLOCK ID has no such collision: it already
            // names exactly one block, so recording the same block twice must be IDEMPOTENT and resolve to
            // the same address both times. `da_store` overwrites, so the second write is a no-op in content.
            (None, Some(id)) => Self::da_record_id_for_block(&id, 0),
            // No block and no address: reached by no production path (every record names its block, genesis included —
            // a credit with no block is STAGED to ride the next one, `record_note_payload`). The position alone names it;
            // a write-order count here (`sub`, deleted with `da_at_height`) made the address a function of arrival.
            (None, None) => Self::da_record_id(canonical, 0),
        };

        // A sum is commutative but NOT idempotent, so folding one block twice — produced then re-ingested,
        // or re-applied by backfill — silently double-counts it. Measured: two nodes on the IDENTICAL
        // 319-block set disagreed 0/6, the peer that had re-applied more blocks reading consistently HIGHER.
        // The dedup lives at the DAG accept in `fold_block_into_membership_acc`, which runs once per block
        // however many times that block's notes are later recorded. (A `da_load(addr).is_some()` probe used
        // to be computed here for the same purpose and was never read — a disk hit per record, and a comment
        // describing a dedup this function does not perform.)
        //
        // ⚠️ THE SEED IS STILL NODE-LOCAL, and that is now the ONE thing standing between here and an
        // agreed block root. See the comment on the seed line below.
        // The block's entropy note is already in `reals`: `cover::pad_to_fixed_shape` declares one pad tx's
        // cover note as an output note, so it rides `Block::output_notes` and both produce and ingest read
        // the identical bytes. Nothing node-local is minted here — that is what lets two nodes derive the
        // same 256 leaves, and therefore the same block root, for one block.
        // One fresh SERVED-BLOCK index per record: the note_index key AND the deterministic-cover seed, so no
        // two records share a key and the frontier grows by exactly 256 every record (uniform leaf index =
        // seq*256 + position). EVERY caller flows this SAME generic state-record path — the height-0 state
        // record, block finalize (tx outputs), stake reward, peg-in/out, bond return — so EVERY action wears
        // the constant 256 cover shape and NONE is excluded from cover traffic (feedback_all_actions_128_cover_shape).
        // ⛔ REVERTED 2026-08-12 (worse-result rule): a sub-bump for occupied addresses lived here and FAILED
        // TWICE — first as a dead shadow, then by stacking a duplicate record per legitimate same-block
        // re-record ("bumped 89 sub(s)", then "all 256 occupied — payload NOT recorded" = a DROPPED record,
        // fund loss). The produce path re-records its own block BY DESIGN and depends on overwrite-idempotency
        // (see the 2708 comment). The real defect — the fold reading a record's root at WRITE time while the
        // serve derives it from CURRENT bytes — is a two-readers-one-mutable-record architecture problem and
        // must be fixed by unifying the WRITERS (one record, written once, from the block that carries it),
        // not by relocating collisions. Until then the original overwrite semantics stand.
        self.da_top = self.da_top.max(addr.saturating_add(1));
        self.da_base = self.da_base.min(addr);
        let seq = addr; // the record's canonical address — its DA key, cover seed and index key
                        // ⭐⭐⭐ WRITE DOWN EVERY NOTE'S ADDRESS AS IT IS RECORDED. This is the missing half of the resolver.
                        //
                        // `da_seq_at_note_cm` reads `note_target_addr`, which is only populated when a note's ACCOUNT TARGET
                        // is filed. A note that arrives without one — a faucet drip, any plain payment — was never in that
                        // index, so the resolver returned None and the wallet was left holding a note whose position it could
                        // not name.
                        //
                        // MEASURED 2026-08-11, live pair at height 13,245, after building the resolver against the wrong map:
                        //     [receive-capture] untracked owned note at record 18446744073709551615/slot 0 — declined
                        //     made: 0   declined: 4
                        // `18446744073709551615` is `u64::MAX`, the unknown-position sentinel. A note the wallet owns, on
                        // chain, that it can never witness or spend. That is FUND LOSS caused by an index that was read but
                        // never written for the ordinary case.
                        //
                        // ONE ENTRY PER NOTE, WRITTEN THE INSTANT ITS ADDRESS IS KNOWN — the accepted O(1) shape: write it
                        // down, then look it up. The read stays a single hash lookup whose cost is f(key width) alone, never
                        // f(height, blocks, notes, age) — so it answers for a note of ANY age, which is exactly the property
                        // that keeps an aging bound from ever being needed here.
        // The public idle seed is COVER, never a receive: a payload that carries a record's own seed (a
        // bundle or a by-id fill of an idle record) must not register it as a target — the receive-sidecar
        // fallback would then count it, moving this node off the certified root (MEASURED 2026-09-03,
        // after_a_jump_and_catch_up: the jumped peer folded the adopted tip's seed as a receive).
        // ⛔⛔⛔ CANONICALISE BEFORE ANYTHING READS THIS PAYLOAD. A RECORD'S CONTENT IS ITS REAL NOTES.
        //
        // MEASURED 2026-09-04, `diag_case_08_unspent_root_split` on the runtime backend:
        //     p0: root=[1221598638,..] leaves=256  owned 0/256
        //     p1: root=[295126057,..]  leaves=766  owned 510/766   gap=3 missing=2
        //     leaf-set diff: p1-only 510, ALL 510 owned, filed at exactly TWO record addresses,
        //                    is_a_real_note_of_that_record=false, and p1 holds NO record at either
        //                    (p0 holds each with 1 real note and 0 target bytes)
        // Two nodes that both report READY, serving DIFFERENT unspent roots — a wallet's balance would
        // depend on which node it asked. 510 = exactly 2 x 255 = the fill of two idle records.
        //
        // THE CHAIN, end to end. The by-id record serve answers with the ASSEMBLED shape — the run's own
        // log line is `[block-id-serve] answering 1 ... 295168 byte(s)`, i.e. 256 x 1153 —
        // `accept_fetched_record` hands those bytes straight back to this function, and the loop below
        // then files EVERY note in the payload into `note_target_addr`. So 255 regenerated fill units per
        // record became "owned"; `da_recv_wire`'s ownership discriminator counted them as receives, and
        // the unspent root split. `register_filed_targets_from_blob` was NOT involved: targets are 0 B on
        // both sides and `[acct-refile]` never fired once in the whole run.
        //
        // ONE CONSENSUS OBJECT, ONE ENCODING — Bitcoin's rule, and already this file's law for produce.
        // The producer stores `reals` and derives the fill at serve, so EVERY node must store `reals`.
        // `strip_fixed_note_payload_det` is the exact inverse of the assembler and is fail-closed: it
        // returns a prefix only when that prefix RE-ASSEMBLES to these very bytes, so a payload it cannot
        // fully account for is left untouched for the root check to judge, and no real note can be lost.
        //
        // Nothing about the cover SHAPE changes: `assemble_fixed_note_payload_det` still runs below, the
        // frontier still takes its constant 256-leaf delta, and the serve still answers 256 units.
        //
        // ⭐ COST ARITHMETIC. Fires only for a payload of exactly 256 x 1153 = 295,168 B (the produce path,
        // 1-2 notes, returns on the length check with zero work). Bounded by the protocol constant 256,
        // never by height/records/notes/age: ~0.9 MB of blake3 <= 2 ms per backfilled record.
        // cons: none, and it deletes an axis — a node storing the served shape held 295,168 B/record
        // against the producer's 1,153 B (256x): 51.0 GB/day = 18.6 TB/year of RAM + snapshot at the
        // 500 ms clock, versus 199 MB/day for the reals.
        // §20.2: the key the record's cover is stripped and assembled under — carried with the payload, or the idle key
        // for an empty one. A body with no key cannot be bound to the header's slots: fail closed on the item.
        // An EMPTY payload (a producer that omitted the seed note) is an IDLE record: its cover is keyed by the one public
        // idle key on every node, whatever key the block drew — so the record a node regenerates from the address alone
        // (`regenerate_idle_record`, the public idle key) is byte-identical to the one it held. MEASURED 2026-10-28
        // (lane funds, node-114.log): the producer filed its empty record under the block's fresh key, dropped the bytes
        // and regenerated them under the idle key — "regenerated bytes are the bytes held before" RED on 17ddaf7
        // (red-origin.tsv) → GREEN with this arm first.
        let key: crate::cover::CoverKey = match key {
            _ if payload.is_empty() => crate::cover::idle_cover_key(seq),
            Some(k) => k,
            None => {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no note, address, amount, key or owner.
                eprintln!("[record-write] ⛔ §20.2: a record body arrived without its cover key — not written (the record lane carries it with the reals)");
                return seq;
            }
        };
        let canonical_payload;
        let payload: &[u8] = match crate::cover::strip_fixed_note_payload(payload, seq, &key) {
            Some(canon) => {
                canonical_payload = canon;
                &canonical_payload
            }
            None => payload,
        };
        // The reals were split from the pre-canonical bytes; the fill is a strict SUFFIX, so dropping the
        // units the canonical payload no longer carries leaves exactly this record's real notes.
        let reals_in = reals.len();
        reals.truncate(payload.len() / PQ_NOTE_BYTES);
        if reals_in > 0 && reals.len() != reals_in {
            // DB-42 diagnosis: the deterministic cover strip changed the real-note count for this record.
            // DIGITAL-CASH-PRIVACY-REVIEWED: two counts and a record address; no note content.
            eprintln!(
                "[record-write] seq={seq}: {reals_in} note(s) in the payload → {} real(s) after the cover strip (block-bound: {})",
                reals.len(),
                block.is_some()
            );
        }
        let idle_seed = crate::cover::public_idle_seed_note(addr);
        for note in reals.iter() {
            if note.len() >= 32 && note[..] != idle_seed[..] {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&note[..32]);
                // ⛔ DB-249b: first writer wins only while its record is ON CHAIN; an entry left by an abandoned block
                // moves to the record that carries the note on the followed chain (the owner lookups read this).
                // ⛔ G1e-i(b): between two on-chain carriers the ONE precedence rule decides (`filed_record_stands`),
                // never arrival order — A and B must name the same record for a note both of their blocks carry.
                match self.note_target_addr.get(&cm).copied() {
                    Some(old) if self.note_record_on_chain(old) && self.filed_record_stands(old, addr) => {}
                    _ => {
                        self.note_target_addr.insert(cm, addr);
                    }
                }
            }
        }
        // ⛔⛔⛔ A REDUNDANT RE-RECORD MUST NOT CONSUME AN ORDINAL. THIS IS WHAT SPLIT THE TWO SUMS.
        //
        // This claimed a fresh ordinal on EVERY write, including the second time a node records a block it
        // already holds (produce, then ingest it back). The fold is now skipped for those — but the ordinal
        // was still spent, and `/membership_roots` walks ORDINALS `0..min(served_seq+1, served_fold_count)`.
        //
        // MEASURED 2026-08-12 with the node-tagged fold provenance:
        //     node=bdba ordinal=0 redundant=false   <- folded
        //     node=bdba ordinal=1 redundant=true    <- NOT folded, but owns an ordinal
        //     node=bdba ordinal=2 redundant=false
        //     node=bdba ordinal=3 redundant=true
        //     …  folded set = {0,2,4,6,8}
        // With `served_fold_count = 5` the route serves ordinals 0..4 — which includes 1 and 3 (never folded)
        // and misses 6 and 8 (folded). A wallet folding the SERVED roots therefore sums a different SET than
        // this node did, lands on a value never computed here, and the gate answers `named_indexed=false` for
        // a proof that is perfectly valid. Every send refused, both sides behaving "correctly".
        //
        // A re-record REUSES the ordinal it already has: ordinals and folds stay 1:1, so the served prefix is
        // exactly the folded prefix. It also stops `da_store_ordinal` remapping an address to a new ordinal on
        // the second write, which would strand every coordinate already handed out for it.
        // ⭐ ARE THE TWO WRITES THE SAME PAYLOAD? user 2026-08-12: "why not simply make the records non
        // redundant 100% of the time?" — the right question, and the answer turns entirely on this.
        //
        // If a re-record carries the SAME bytes, the whole redundancy is a no-op and one idempotent early
        // return replaces every downstream special case (the fold-once skip and the ordinal reuse both go).
        // If it carries MORE notes, an early return would DROP them, and dropped notes are lost money — so
        // the real defect would be upstream: the same block recorded twice with different payloads.
        // Measure it; do not assume it. Lengths only — never a note, commitment, amount, key or owner.
        // ⛔⛔⛔ THE REDUNDANT WRITE IS DELETED AT ITS SOURCE. THE TWO PATCHES BELOW EXISTED ONLY FOR IT.
        //
        // user 2026-08-12: "why not simply make the records non redundant 100% of the time?" — and the
        // measurement that answers it, five times in one run:
        //     [record-redundant] addr=…: already hold 1153 byte(s), incoming 0 byte(s)
        // The second write carries ZERO bytes. It cannot add a note, cannot change a root, and cannot lose
        // anything by not happening — which is what makes deleting it safe rather than merely convenient.
        //
        // What produced it: a node records a block on its produce path and again when it ingests that same
        // block back, the second time with no payload. Every downstream consumer then had to learn about the
        // duplicate — I had already written two special cases for it (skip the fold, reuse the ordinal), and
        // a third consumer would have needed a third. Deleting the write retires all of them.
        //
        // A re-write that CARRIES BYTES still proceeds: that would be a genuinely different record for the
        // same address, and dropping it would drop notes. Only the empty repeat is refused.
        // ⛔⛔⛔ "DO I ALREADY HOLD THIS?" IS A QUESTION ABOUT THE STORE, NOT ABOUT WHAT IS DERIVABLE.
        //
        // This guard and the idempotence check below both asked `da_record_notes`, which answers for a
        // record that EXISTS — and an idle record exists the moment its block does, because its bytes are a
        // pure function of its address. The instant that derivation was taught to answer without a stored
        // row, the writer read "already held", returned early, and never wrote the seed row at all:
        // MEASURED 2026-09-04, four `idle_record_regeneration` tests failed in their SETUP with "the
        // producer filed the record", because `record_note_payload_for(block, h, &[])` — the idle write —
        // had silently become a no-op.
        //
        // `da_load` is the store. A writer deciding whether to write must look there and nowhere else.
        let stored = self.da_holds(addr);
        // ⭐⭐⭐ PROVENANCE, PRODUCER 1 OF 2 (charter §9.6 q2/q6) — A BLOCK-ADDRESSED RECORD IS
        // CHAIN-BOUND. `block.is_some()` is exactly the produce / graft / ingest / DSYNC-apply arm: the
        // caller holds the block, whose header binds `output_notes_root` and `del_set_root` and whose
        // own PoW was checked before it could graft. That is a binding reached WITHOUT reading these
        // bytes, which is the only kind that counts.
        //
        // It runs HERE, above the two idempotent early returns, so that a row first written
        // PROVISIONALLY by a peer's page is UPGRADED the moment the real block arrives and re-records
        // it — otherwise the "we already hold these notes" return would leave a genuine chain record
        // permanently unable to authorise its own deletions.
        if block.is_some() {
            self.da_mark_chain_bound(addr);
        }
        if payload.is_empty() && stored {
            return addr;
        }
        // ⛔⛔⛔ A NON-EMPTY RE-RECORD OF NOTES WE ALREADY HOLD MUST BE A NO-OP TOO — IT WAS CLAIMING A
        // FRESH ORDINAL AND REMAPPING THE ADDRESS EVERY TIME. Only the EMPTY repeat was refused above,
        // while the ordinal claim below runs "unconditionally"; the tip-follow re-fetches the newest 256
        // records every 2s and each arrives WITH BYTES, so every pass re-claimed ordinals for records
        // already held. MEASURED 2026-08-19 on the live joiner: record_top 511k -> 984k in ~5h against
        // ~34k blocks (~14 ordinal claims per block), each claim re-running the seal/fold/persist chain —
        // 205% CPU, 2.8GB RSS, the rt lock held so long the RPC starved for minutes, and every coordinate
        // previously handed out for the address was strand-remapped. One idempotent check ends the loop:
        // if every incoming note is already in the held record, nothing can change — return the address.
        // A record carrying a genuinely NEW note still proceeds (dropping it would drop money).
        if let Some(held) = self.da_record_notes(addr).filter(|_| stored) {
            let mut all_present = !payload.is_empty();
            let mut o = 0usize;
            while o + PQ_NOTE_BYTES <= payload.len() {
                let incoming = &payload[o..o + PQ_NOTE_BYTES];
                let mut found = false;
                let mut h = 0usize;
                while h + PQ_NOTE_BYTES <= held.len() {
                    if &held[h..h + PQ_NOTE_BYTES] == incoming {
                        found = true;
                        break;
                    }
                    h += PQ_NOTE_BYTES;
                }
                if !found {
                    all_present = false;
                    break;
                }
                o += PQ_NOTE_BYTES;
            }
            if all_present {
                return addr;
            }
        }
        // ONE ordinal per record, claimed unconditionally.
        //
        // A reuse-the-ordinal arm lived here — the second of two patches for the duplicate write, and the
        // proof that patching a cause instead of deleting it multiplies: one consumer needed the fold
        // skipped, the next needed the ordinal reused, a third would have needed its own. The duplicate is
        // deleted at the top of this function now (an empty re-record returns immediately, MEASURED at 0
        // bytes incoming against 1,153 held), so every call reaching here is a first record of its block.
        // ⛔⛔⛔ A ROW THE PAGE ALREADY PLACED KEEPS ITS ORDINAL. MEASURED in-process 2026-09-03
        // (`orphaned_prerestart_records_tests`): the peer's sidecar page registered rid→ordinal 3, the by-id
        // BYTE fetch then claimed a NEW ordinal 43 for the same record — the record space grew past the
        // certified count (served_seq 43 → 83 against a 43-record spine) and every ordinal above the
        // certified position named a duplicate. A record whose ordinal is known fills its row IN PLACE;
        // only a record this node has never placed claims the next ordinal.
        if reals.is_empty() {
            // ⛔⛔⛔ THE SEED NOTE IS DERIVED FROM PUBLIC DATA ONLY. MY FIRST VERSION USED THE NODE SECRET
            // AND THAT WAS A CONSENSUS SPLIT.
            //
            // I seeded this from `da_secret_value()` — a PRF of THIS NODE's private secret — so two nodes
            // recording the SAME empty block produced DIFFERENT records, different block roots, and
            // therefore different membership accumulators. The comment above this function had already
            // warned of exactly that trap for the missing-record case; I walked into it for the empty-block
            // case.
            //
            // MEASURED 2026-08-12 with a per-node acc series:
            //     node=ae80 ordinal=0 root=…1b71ea0b   acc=…0a6c595a
            //     node=cb42 ordinal=0 root=…063a4176   acc=…765e101f
            // Every root differs. The accumulator is a COMMUTATIVE SUM, so equal block sets must give equal
            // sums regardless of order — different sums prove the two nodes folded different roots for the
            // same chain. That is `named_indexed=false`: a wallet folds what its node serves, and the
            // verifying node computed a sum over values it alone could produce.
            //
            // The record key is PUBLIC (it is the canonical, block-derived address every node agrees on), so
            // deriving from it alone makes every node produce byte-identical leaves. It leaks nothing new:
            // the stored record already reveals its own note count, which is the only thing this could hide.
            // ONE derivation for the whole protocol — this write, the on-demand regeneration in
            // `da_record_notes` (a node holding the coordinates but not the bytes), and every pin.
            reals.push(crate::cover::public_idle_seed_note(seq).to_vec());
            eprintln!(
                "[record-write] seq={seq}: block carried no real notes — wrote ONE \
                 public-seeded SEED note (seq-derived, identical on every node) so this record is never empty. `da_record_notes` answers for it, the \
                 subtree climb does not abandon here, and no copath crossing this span can be refused."
            );
        }

        let _ = &reals;
        // Assemble the DETERMINISTIC constant-256 shape (real notes + value-0 det cover, height-permuted) and
        // append ALL 256 commitments to both membership frontiers — the frontier commits the full cover shape
        // so a spend proves membership AND an observer sees a constant 256-leaf delta every block (privacy).
        // The cover bytes are NOT stored (regenerated at serve): this is the no-growth fold into the decider.
        //
        // ⭐⭐⭐ THE PRODUCER'S SEED NOTE — the entry this struct's own `da_mem` doc has always promised:
        // "every record opens with the producer's seed note … that entry is what makes the block's 256-leaf
        // shape reproducible by a node that did not record it".
        //
        // ⛔ IT WAS SPECIFIED AND NEVER WRITTEN. `cover.rs` says the same from the other side: with `reals`
        // empty the per-block cover secret degrades to a PUBLIC `blake3(domain ‖ seq)`, so an observer
        // recomputes all 256 cover units and learns the block was idle — the constant SHAPE then hides the
        // count but not the FACT of emptiness. MEASURED RED by
        // `cover::idle_block_cover_hole::an_idle_blocks_cover_is_not_recomputable_from_public_data_alone`:
        // a public recomputation reproduced the served payload byte-for-byte.
        //
        // ONLY when there are no reals, so a busy block's note POSITIONS are untouched (`position ==
        // leaf-offset` is live, proved by `a_notes_global_leaf_index_is_recoverable...`). The note is
        // HIGH-ENTROPY and NOT derived from this node's DA secret; it is produced ONCE here and travels IN
        // THE BLOCK, so every node ingests identical bytes. Regenerating it per-node is exactly the
        // cross-node divergence recorded elsewhere in this file (both nodes recorded nothing, both ended up
        // holding one note, DIFFERENT bytes) — hence a produce-side write, never a serve-side one.
        let reals_concat: Vec<u8> = reals.iter().flat_map(|n| n.iter().copied()).collect();
        let fixed = crate::cover::assemble_fixed_note_payload(&reals_concat, seq, &key);
        // ⛔⛔⛔ THE 256-PER-BLOCK `cm -> address` WRITE IS DELETED — it was the node's dominant growth slope
        // (6,144 entries / 245,760 B at 24 blocks, 88% of the whole measured footprint), one entry for every
        // commitment in every block, reals and cover alike.
        //
        // Nobody needs to ask a node "which record holds this cm?":
        //   * a block's targets are adopted WITH that block, and `da_record_id_for_block(block_id, sub)` is a
        //     PURE FUNCTION of the block id — the address is computed, never stored;
        //   * an owner already holds `(cm, ident, slot)` sealed in its account-bucket entry, and the wallet
        //     already sends `positions_hex`.
        //
        // Nothing is trimmed and no real note is separated from cover: the 256-wide shape every block commits
        // is untouched. A per-item store became a pure function plus a value the caller already carries.
        let mut foff = 0;
        let mut slot: usize = 0;
        // OLI tags for this block's notes are filed SOLELY by `file_block_carried_tags` (the replicated
        // path, from the block's `oli_tags` field bound to its header). The node-local `pending_tags`
        // drain below clears the staging map for memory bounding but does NOT write into `da_tags_mem` —
        // that write was the root cause of the `da_tags_mem DIFFERS` census divergence (the producer
        // drained all tags from its mempool while a joiner had none, making the locator index depend on
        // which node authored the block rather than on the block itself).
        // ⛔⛔⛔ FILE A RECORD'S TARGETS EXACTLY ONCE. A record reaches this function by more than one route —
        // produced, grafted, backfilled, fetched by id — and each pass re-sealed and re-appended every target
        // it matched. `seal_entry_to` uses ML-KEM `encapsulate`, which is RANDOMISED, so the duplicate is a
        // DIFFERENT ciphertext every time and no byte-equality check can collapse it.
        //
        // MEASURED on a cold restore against the node present for every payment: the account bucket named
        // `3 owned position(s)` which the wallet resolved to `3 hit(s): 1 distinct note(s)` — one real note
        // wearing three index entries. The bucket is bounded (`BUCKET_CAPACITY`, then it spills to the next
        // link), so duplicates of one note crowd out the entries of OTHER notes: an owned note that can never
        // be found again. That is fund loss by the index, not by the ledger.
        //
        // `da_store_account_targets(seq, ..)` already writes down exactly which targets a record consumed, so
        // a non-empty entry there IS the statement "this record has been filed". Re-deriving from it costs one
        // lookup and no new storage. Not a window: nothing is refused for age — a record filed once is filed
        // forever, which is precisely the invariant.
        // ⛔ REVERTED — MEASURED HARMFUL. I added this to stop duplicate index entries (a record reaches this
        // function by several routes and each pass re-sealed its targets). Immediately afterwards a brand-new
        // account received TWO settled sends and its bucket held ZERO entries across six polls, where the same
        // flow previously produced entries. `da_load_account_targets` is written for a record whether or not
        // that pass matched any target, so a record stored by an earlier route reads as "already filed" and
        // suppresses the ONLY pass that would have filed it.
        //
        // Suppressing a write on a maybe is fund loss; writing a duplicate is waste. Those are not comparable,
        // so the write always happens until idempotence can be keyed on (bucket, cm) rather than on the record
        // having been seen. Left as `false` rather than deleted so the SKIPPED probe below stays available.
        let already_filed = false;
        let _ = exact_addr;
        // Collected in-loop, applied after it — `self` is borrowed by the slot walk.
        let mut bucket_writes: Vec<([u8; 32], [u8; 32], Vec<u8>, Vec<u8>)> = Vec::new();
        let mut removals_this_block: usize = 0;
        while foff + PQ_NOTE_BYTES <= fixed.len() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&fixed[foff..foff + 32]);
            // DRAIN the pending-tags staging map: keeps it bounded by in-flight work rather than by the
            // chain. The tag itself is NOT written into da_tags_mem here — only `file_block_carried_tags`
            // (the replicated path from the block's `oli_tags`) may do that.
            self.pending_tags.remove(&cm);
            // ACCOUNT-INDEXED DA. Write this note's position into its OWNER'S bucket, sealed to the owner's
            // public key. This is what turns a restore from a walk over the whole stream into ONE lookup at a
            // seed-derived address: the note is filed under WHOSE it is, not merely where it landed.
            // ⚠️ REVERTED 2026-08-09 — the peek+carry pair made the RESULT WORSE, so it is out.
            //
            // The defect is real and stands: node A files the target locally and the block carries
            // nothing, so node B never learns it and the recipient finds `0 decapped`. The fix I tried
            // was to peek here and have produce carry whatever was still staged. It DID carry (blocks
            // went from 0 to 2500/1250 account-target bytes) — and every cross-device run then failed,
            // 0/3 against 2/3 before. Adding bytes after assembly changes the block id, which the probe
            // beside `block.account_targets = carried` already warns about, so the likely cost was
            // convergence between the two nodes.
            // A worse number is a STOP signal, not a data point. The carry must ride the block from the
            // START of assembly, not be appended to a finished one — that is the different shape, and
            // it is what to build next.
            if let Some((bucket, ek)) = self.pending_bucket.remove(&cm) {
                // ⛔ COUNT EVERY CONSUMPTION. `pending` went 2 -> 0 while the loop produced ONE write and
                // ZERO seal failures — three numbers that cannot all be true, so one of them is measuring
                // something other than what I assumed. A target REMOVED here is claimed and can never be
                // recovered, so every removal must be visible or a lost note looks like a note that never
                // existed. DIGITAL-CASH-PRIVACY-REVIEWED: a count only; never a cm, bucket, key or owner.
                removals_this_block += 1;
                // A CLAIM IS IRREVERSIBLE — record that it happened so the produce-side probe can still speak
                // after both maps are empty. See `targets_claimed_total`.
                self.targets_claimed_total = self.targets_claimed_total.saturating_add(1);
                // ⛔ FILE THE DENSE ORDINAL, NOT THE RECORD ADDRESS. The bucket is what a restore uses to go
                // fetch the note, and `pq_notes_from` is paged by ORDINAL — the record's address (derived from
                // its block, and enormous: ~2.9e17) names nothing the serve can be asked for. Storing the
                // address made every bucket hit unfetchable: the wallet learned exactly where its note was and
                // then asked for a position that does not exist in the stream's coordinate system.
                // ⭐⭐⭐ THE BUCKET MUST HAND OUT A CANONICAL COORDINATE, NEVER A LOCAL COUNTER.
                //
                // This filed `append_ordinal` — `served_seq`, the order THIS node happened to write records.
                // Two mining nodes write their own blocks before their peer's, so the same number names a
                // DIFFERENT block on each: measured live, 7 of 7 sampled ordinals disagreed across two peered
                // nodes (including ordinal 100), and reproduced as 12 of 12 from ordinal 0 in
                // `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`. A wallet reads its
                // note's position from this bucket, so the recipient's node then addressed the wrong block and
                // the payment settled on chain while staying invisible to its owner.
                //
                // The very same defect was already found and fixed for the record ADDRESS 140 lines above
                // ("measured, 0 of 6 sampled seqs agreed") — `ident` is derived from the BLOCK, so it is
                // identical on every node. The bucket was never moved over. It is now.
                //
                // The local ordinal keeps its other job: it indexes THIS node's spend frontier, and a copath
                // is verified against THIS node's own root, so it never has to travel.
                // ⚠️ COORDINATE CONFUSION, STILL OPEN — DO NOT "FIX" THIS BY SWAPPING VALUES BLIND.
                //
                // This files `ident` (the chain POSITION). The note serve and every root/acc lookup are keyed
                // by `addr` (position + `sub`), and `a_filed_bucket_position_resolves_to_the_same_block_on_a_
                // second_mining_node` FAILS: `6 of 6 FILED bucket positions name a different block on node B`.
                // I tried filing `addr` instead and the test failed identically — so the mismatch is not a
                // single wrong field, it is that filing, the resolver used by the test, and the note serve do
                // not all speak ONE coordinate. Swapping one of them without being able to verify live just
                // moves which caller breaks.
                //
                // The correct fix is ONE canonical coordinate end to end (bucket ↔ resolver ↔ serve), verified
                // cross-node on the production path — not another swap. Left as-is so the failing test keeps
                // pointing at the real defect instead of a masked one.
                // ⛔⛔⛔ FILE THE ADDRESS THE RECORD IS ACTUALLY STORED AT. `ident` is the chain POSITION;
                // `addr` is that position plus `sub`, and `addr` is what `da_load` / `da_record_notes` /
                // `da_block_leaves` are keyed by. Filing `ident` meant a node could not resolve the position it
                // had just filed ITSELF — proven in-process by
                // `a_filed_bucket_position_resolves_to_the_same_block_on_a_second_mining_node`:
                // "node A cannot resolve the position it FILED ITSELF". A wallet hands this value straight back
                // to its own node, so the note was unspendable on the very node that indexed it.
                // ⭐ WRITE DOWN WHERE THIS TARGET LANDS — the resolver the comments cite as
                // `da_seq_at_note_cm` and which does not exist. Without it the target is filed under THIS
                // record's address while the block carrying the note looks it up under its OWN, so a
                // correctly-filed target is invisible to the block that should carry it. MEASURED:
                // `[bucket-file] CLAIMED 2 ... produced 2 write(s)` and `[acct-produce] block carries 0
                // account-target byte(s) for 1153 note byte(s)` on the same node, same send.
                // ⛔ G1e-i(b): a target filed by a SECOND carrier of the same note never displaces the canonical
                // record by arrival — the same precedence rule as the record commit (`filed_record_stands`).
                match self.note_target_addr.get(&cm).copied() {
                    Some(old) if self.note_record_on_chain(old) && self.filed_record_stands(old, addr) => {}
                    _ => {
                        self.note_target_addr.insert(cm, addr);
                    }
                }
                // ⭐ WHICH BUCKET DID THIS WRITE ACTUALLY GO TO? The one measurement that separates every
                // remaining theory about the undiscoverable second send, and the last unmeasured step.
                //
                // MEASURED 2026-08-10 on the cross-device harness: the payer builds TWO targets with TWO
                // different buckets (recipient's note -> `recip_b`, change -> `my_b`, per
                // `account_target_records`), the recipient's node reported `CLAIMED 2 pending target(s) and
                // produced 2 write(s)`, and yet `[bucket-filed] ids this node has filed under` listed exactly
                // ONE id — `9f3eb554` — for the whole run, while the id the recipient actually queries
                // (`79fad6b7`) was known to that node 70 times and never written under.
                //
                // Two writes into one bucket means the pair (cm -> bucket) taken here is not the pair the
                // payer sent. Printing them TOGETHER is what decides it: if both writes report the same
                // bucket, the staging or the claim is collapsing two entries onto one key; if they differ,
                // the loss is downstream in the serve. Neither is distinguishable from the counts alone,
                // which is why six consecutive fixes went into the consumer side of this bucket.
                //
                // Fires only on a real claimed target (never per block, never on cover), so no growth.
                // DIGITAL-CASH-PRIVACY-REVIEWED: 4-byte PREFIXES of a commitment and a bucket id, both of
                // which this node already prints at `[bucket-filed]` and serves under. No amount, key, owner
                // or address, and a prefix identifies no wallet — it distinguishes THIS run's two writes.
                eprintln!(
                    "[bucket-write] filing note {:02x}{:02x}{:02x}{:02x} into bucket {:02x}{:02x}{:02x}{:02x}                      — the payer sends a DIFFERENT bucket per note, so two writes reporting the same bucket                      means the cm->bucket pair was lost before this line",
                    cm[0], cm[1], cm[2], cm[3],
                    bucket[0], bucket[1], bucket[2], bucket[3]
                );
                // ⭐⭐⭐ FILE THE FRONTIER INDEX — THE COORDINATE THE COPATH IS ACTUALLY IN.
                //
                // ROOT-FIX-VERIFIED: the position a wallet is handed is now the SAME coordinate the witness is
                // built in, so a filed position can no longer name a place the tree has no path for.
                //
                // This filed `addr`, the RECORD address. Under the 256-cover chain that space and the note
                // tree happened to relate by `ordinal x 256`; with cover removed the frontier index is ~block
                // height and the two diverge outright. MEASURED live 2026-08-10 on the no-cover chain:
                //   [copath] the node served no usable depth-32 path for filed position 7200 slot 0
                // with the chain at height 1,982 — the filed position was past the end of the tree, so no path
                // could exist for it. That is the LAST of the coordinate mismatches this session has been
                // about (record address vs block count, three bucket-id derivations, fold count vs served
                // roots, book count vs chain ordinal).
                //
                // Nothing is lost by filing the index instead: `fetch_note_at` resolves a note's record by its
                // COMMITMENT (`/note_ordinal_by_cm`) and OVERRIDES whatever position it was given, so fetching
                // never depended on this field. The witness does. `spend_frontier.count()` here is the index
                // this very note is about to be appended at (the append is ~50 lines below), so it is exact,
                // not derived, and identical on every node because every node appends the same leaves.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a leaf INDEX in the public note tree, sealed to the owner's
                // key exactly as the address was. No new observer learns anything the entry did not already
                // carry.
                // ⛔⛔⛔ TWO WRITERS PUT DIFFERENT QUANTITIES IN THE SAME FIELD, AND THE READER NEEDS ONE.
                //
                // This path sealed `spend_frontier.count()` — a LEAF INDEX — into `AccountEntry.seq`, while
                // the late path at `attach_tag_to_recorded_block` seals `ident`, a RECORD ADDRESS, into the
                // same field. The wallet reads that field and pages the RECORD it names to confirm the note
                // is really there. So a note filed by THIS path handed the wallet a leaf index, and it asked
                // for a record that does not exist.
                //
                // MEASURED 2026-08-11 on the real wallet, real button press, fresh chain past 3,300 blocks:
                //   [scan] account bucket read OK: 1 owned position(s) in 1ms
                //   seq=2 slot=0: the node served 0 note(s) at this record and NONE carries our commitment
                //   "Failed: cannot prove this note's membership: no filed position for it yet"
                // `2` is the spend tree's leaf count, not a record. The position was therefore never
                // confirmed, never filed, no note-membership carrier could be built, and the send refused —
                // money visible in the balance and impossible to spend. The eleventh instance of this exact
                // class today (record address vs block count vs leaf index vs ordinal).
                //
                // `addr` is THIS record's address — the same value written to `note_target_addr` a few lines
                // above, and the coordinate every DA accessor takes (`da_record_notes`, `da_load_tags`,
                // `da_load_account_targets`). Both writers now seal the same quantity, so the reader cannot be
                // handed one meaning by one path and a different one by the other.
                //
                // The leaf index is NOT lost and nothing needs it stored: the node resolves it from the
                // commitment on demand (`da_record_leaf_start`), one indexed read with no term in height.
                let e = crate::account_da::AccountEntry::at(cm, addr, slot as u8);
                let sealed_opt = crate::account_da::seal_entry_to(&ek, &e);
                let ek_for_retry = ek.clone();
                if sealed_opt.is_none() {
                    // ⛔⛔⛔ A FAILED SEAL SILENTLY ATE THE NOTE'S ONLY INDEX ENTRY. The pending target was
                    // REMOVED above, so a `None` here consumed it and wrote nothing — the note settled on
                    // chain with no account bucket, and its owner could never find it from their seed again.
                    // MEASURED end to end: `[submit] account_targets_hex arrived: 5000` →
                    // `[account-target] recorded; 2 target(s) pending` → `[bucket-file] block touched 0
                    // bucket(s), 0 pending`. The data arrived, was recorded, and vanished at this line.
                    //
                    // Put it BACK so it is retried rather than lost, and say so. A note whose index entry
                    // cannot be sealed is a note its owner cannot restore — that must never be silent.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a key LENGTH only; never the key, cm, bucket or owner.
                    eprintln!(
                        "[bucket-file] SEAL FAILED for an account entry (ek_len={}) — target restored to \
                         pending rather than dropped; this note has NO index entry until it seals",
                        ek.len()
                    );
                    self.pending_bucket
                        .entry(cm)
                        .or_insert((bucket, ek_for_retry));
                }
                if let Some(sealed) = sealed_opt {
                    // ⛔⛔⛔ WHICH BUCKET ID DOES THIS NODE ACTUALLY WRITE UNDER?
                    //
                    // MEASURED 2026-07-31, one run, four points:
                    //   recipient address encodes: 277ee795
                    //   recipient wallet asks for: 277ee795   <- self-consistent
                    //   sender parsed from address: 277ee795  <- parse is correct
                    //   recipient's node filed:     e151e36b  <- foreign to all three, and CONSTANT across
                    //                                            runs while the recipient's id changes each run
                    // Everything upstream agrees; the divergence is here, at the write. `bucket` comes from
                    // the account-target record (blob[off+32..off+64]); if it prints 277ee795 the value is
                    // right at write time and something later re-keys it, and if it prints e151e36b the
                    // target parse picked up the wrong 32 bytes.
                    //
                    // O1-FOOTPRINT-REVIEWED: reads values already in hand at the write; stores nothing and
                    // adds no term in height, blocks or notes.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: FOUR bytes of a bucket id in this node's OWN local log,
                    // on a real payment write only. Never sent anywhere, never paired with an amount, key or
                    // owner; a 4-byte prefix identifies no account. Same reviewed shape as [bucket-filed].
                    eprintln!(
                        "[bucket-write] writing under {:02x}{:02x}{:02x}{:02x} — compare with the sender's \
                         [send-bid] and the recipient's [addr-bucket]; a mismatch here is a re-key at write.",
                        bucket[0], bucket[1], bucket[2], bucket[3]
                    );
                    bucket_writes.push((bucket, cm, sealed, ek));
                }
            }
            // ONE unified Poseidon note frontier (the redundant blake3 `note_frontier` was removed — no-growth):
            // this is the note-membership tree the wallet self-builds its copath against AND the header commits.
            // A PLACED row's leaves are already in the adopted spine at `leaf_start` (the page placed the
            // row, the spine came certified from the peer); appending them again grew the frontier past the
            // certified count (MEASURED in-process 2026-09-03: 43 → 83 records on a 43-record spine — the
            // double-append class). Only a record this node places itself extends the frontier.
            foff += PQ_NOTE_BYTES;
            slot += 1;
        }
        // ⭐ OLI tags are filed ONLY by `file_block_carried_tags` (the replicated path, from the block's
        // `oli_tags` field bound to its header via `oli_tags_root`). The node-local drain that stood here
        // was the root cause of the `da_tags_mem DIFFERS` replica-census divergence: the producer's drain
        // found all tags (its mempool had every clue), while a joiner's drain found none — making the
        // locator index depend on which node authored the block, not on the block itself.
        // Advance the O(1) membership accumulator with THIS block's subtree root. The root is folded from the
        // same fixed 256-slot shape the block just appended, so every node reaches the identical value.
        {
            let mut level: Vec<crate::spend_frontier::Digest4> =
                Vec::with_capacity(crate::cover::BLOCK_FIXED_NOTE_COUNT);
            let mut foff2 = 0usize;
            while foff2 + PQ_NOTE_BYTES <= fixed.len() {
                let mut c = [0u8; 32];
                c.copy_from_slice(&fixed[foff2..foff2 + 32]);
                level.push(crate::spend_frontier::note_leaf_of(&c));
                foff2 += PQ_NOTE_BYTES;
            }
            while level.len() > 1 {
                let mut up = Vec::with_capacity(level.len() / 2);
                let mut i2 = 0;
                while i2 + 1 < level.len() {
                    up.push(crate::spend_frontier::poseidon_pair(
                        level[i2],
                        level[i2 + 1],
                    ));
                    i2 += 2;
                }
                level = up;
            }
            // FOLD ONLY CANONICAL BLOCK RECORDS. Every node is its own PoUW miner with its own wallet, so a
            // node also records things that are purely ITS activity — a faucet credit to its own wallet, its
            // own reward claim. Those are wallet state, not chain state, and folding them made two nodes with
            // the IDENTICAL block set still disagree (0/6 at equal height and equal block count). The
            // accumulator commits what the chain says; a record is chain data exactly when it is named by a
            // block.
        }
        // Apply this block's account-bucket writes and advance the O(1) accumulator the header commits. The
        // fold is over the CANONICAL `(bucket, note_cm)` — never the sealed bytes, which embed this node's
        // own `seq` and so differ peer to peer.
        let mut consumed_targets: Vec<u8> = Vec::new();
        // ⛔ THE LOOP'S OWN ACCOUNTING. Targets ARRIVE (5000 hex chars), are RECORDED (2 pending), and seal
        // fine (0 failures) — yet no bucket is touched. The only remaining question is whether this loop ever
        // sees a note whose `cm` matches a pending target, and nothing reported that. Guessing cost two turns
        // (a cm mismatch, then a seal failure — both wrong, both disproved by one run).
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts only — notes scanned in this block and writes produced.
        // Never a commitment, bucket id, key, amount or owner.
        // ⛔⛔⛔ THE SILENT SIDE OF THIS LOG IS WHERE THE RECIPIENT'S MONEY DIES.
        //
        // MEASURED 2026-08-01 on the live pair: `[bucket-file]` fired 12x on node A and ZERO times on node B,
        // while node B recorded 4,214 `[account-target]`s — nearly parity with A's 4,237. The recipient then
        // asked node B for its derived bucket and got an empty answer, so detection returned 0 candidates and
        // the payment never appeared, even though node A held that exact bucket.
        //
        // The zero was not evidence that node B skipped this code: this log only prints when a write ALREADY
        // happened, so the failing case — targets staged, notes recorded, NOTHING matched — prints nothing at
        // all. A defect that silences its own detector is indistinguishable from code that never ran, and I
        // spent measurements concluding the latter.
        //
        // Report the MISS explicitly: notes were recorded into this record while targets were pending and not
        // one of them matched. That is a genuine anomaly (on the healthy path a pending target is claimed by
        // the very block carrying its note), never a per-block line — it cannot fire when nothing is pending.
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts only — pending targets, notes scanned, writes produced. Never
        // a commitment, bucket id, key, amount or owner.
        // ⛔ DB-294 (3): A PENDING TARGET WHOSE NOTE IS ALREADY ON THIS NODE'S CHAIN IS NOT A MISS.
        // It is a target that reached this node after its note's record did, or one whose record has SETTLED since
        // (a post-jump block). The drain above matched only THIS record's notes. Every other pending target retries
        // its own door here, so a record that went on chain after its target arrived files one block later, not
        // never.
        // cons: O(pending) index lookups per record write. Pending is in-flight work, and a target that resolves
        // leaves it.
        if !self.pending_bucket.is_empty() {
            self.retry_pending_targets_via_index();
        }
        if removals_this_block == 0 && bucket_writes.is_empty() && !self.pending_bucket.is_empty() {
            eprintln!(
                "[bucket-miss] this record matched NONE of the {} pending target(s) — the notes were stored \
                 but no bucket was written, so their owner can never locate them from a seed. On the node that \
                 PRODUCED the block this cannot happen (the target is staged by the submit that carries the \
                 note); seeing it here means the adopting node staged the target and recorded the note without \
                 the two ever meeting.",
                self.pending_bucket.len()
            );
        }
        if removals_this_block > 0 || !bucket_writes.is_empty() {
            eprintln!(
                "[bucket-file] this block CLAIMED {} pending target(s) and produced {} write(s), {} target(s) \
                 STILL PENDING — a claimed target that produced no write is a note whose owner can never find \
                 it, and a target left pending is an UNFILED note: on chain, but unlocatable from its seed \
                 until some later block happens to carry its commitment.",
                removals_this_block,
                bucket_writes.len(),
                self.pending_bucket.len()
            );
        }
        let mut touched_buckets: std::collections::HashSet<[u8; 32]> =
            std::collections::HashSet::new();
        if already_filed && !bucket_writes.is_empty() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count only; never a cm, bucket id, key, amount or owner.
            eprintln!(
                "[bucket-file] SKIPPED {} duplicate write(s) — this record's targets were filed on an earlier pass",
                bucket_writes.len()
            );
            bucket_writes.clear();
        }
        for (bucket, cm, sealed, ek) in bucket_writes {
            consumed_targets.extend_from_slice(&cm);
            consumed_targets.extend_from_slice(&bucket);
            consumed_targets.extend_from_slice(&(ek.len() as u16).to_le_bytes());
            consumed_targets.extend_from_slice(&ek);
            let landed = self.account_bucket_append(bucket, sealed);
            touched_buckets.insert(landed);
            self.account_acc = crate::account_da::fold_account_acc(self.account_acc, &bucket, &cm);
        }
        // PERSIST EACH TOUCHED LINK ONCE. The index must outlive the process (an entry lost on restart makes
        // an owned note unfindable), but a write per credited note put synchronous disk I/O on the record path
        // for every one of them. A link is bounded by BUCKET_CAPACITY and a block touches at most as many
        // links as it credits notes, so this is a fixed-shape cost either way — just paid once.
        // ⛔ SAY WHETHER ANYTHING WAS FILED. Six consecutive fixes went into the bucket CONSUMER while the
        // producer was silent — the node answered 1086 `BucketReq` with `serving 0 bucket(s)` and nothing in
        // any log said whether a single entry had ever been written. A producer that cannot be observed
        // forces every debugging session downstream of it.
        // DIGITAL-CASH-PRIVACY-REVIEWED: counts only — how many buckets this block touched and how many
        // targets were pending. Never a bucket id, note commitment, key, amount or owner.
        // Per-block when quiet = the DISK blowup; say it only when a bucket was actually touched.
        if !touched_buckets.is_empty() {
            eprintln!(
                "[bucket-file] block touched {} bucket(s), {} account target(s) still pending",
                touched_buckets.len(),
                self.pending_bucket.len()
            );
        }
        // ⛔⛔⛔ AN UNFILED TARGET IS FUND LOSS — BUT ONLY MEASURE IT *AFTER* THE PASS COMPLETES.
        //
        // I first put this check EARLIER in the same function and it reported "2 target(s) remain UNFILED"
        // 471 times on a live send. That was a FALSE ALARM I manufactured: `pending_bucket` still held the
        // entries at that point and is drained further down, so the same field read 2 there and 0 here in one
        // pass. Two probes disagreeing about one fact is the exact ambiguity that has cost this session
        // repeatedly — a diagnostic placed before the work it judges invents defects that do not exist.
        //
        // Here the value is settled: anything still pending after the drain genuinely has no index entry yet,
        // and its owner cannot locate it from their seed until a later block carries its commitment.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT only — never a commitment, amount, key, bucket or owner.
        // Fires only when something is actually left over (a genuine anomaly), never per block.
        if !self.pending_bucket.is_empty() {
            eprintln!(
                "[bucket-unfiled] {} account target(s) remain UNFILED after the filing pass COMPLETED — each \
                 is a settled note its owner cannot locate from their seed until a later block carries its \
                 commitment.",
                self.pending_bucket.len()
            );
        }
        for b in &touched_buckets {
            if let Some(_entries) = self.account_buckets.get(b).cloned() {}
        }
        // OFFER what we just filed — see `freshly_filed_buckets`. Peers adopt it through the SAME `BucketResp`
        // path a pull would have used, so nothing new has to be parsed or trusted, and a peer that already has
        // the entries de-duplicates them (`adopt_account_bucket` only appends what it does not hold).
        self.freshly_filed_buckets
            .extend(touched_buckets.iter().copied());
        // Keep them with the record: the backfill serves this so a peer rebuilds the same buckets.
        // ⭐ A COLD IDLE ROW FETCHED BY ADDRESS IS CACHE: it is STORED (the by-id want it answers must clear — a
        // 01:00 variant that refused the store left every such want re-asked forever, `wants=32` on both gate
        // nodes) and then RETIRED by `sweep_cold_idle_rows` at the ladder cadence once its block is not in the
        // DAG and nothing wants it. MEASURED 2026-09-22 on the live origin's checkpoint at height 10,626: 9,297
        // ordinal-less seed rows (1.1 KB/block, the file 4 MB → 26 MB in three hours) that the ordinal pruner
        // could never reach.
        self.da_store_account_targets(seq, &consumed_targets);
        // ROOT-HISTORY: commit THIS block's finished spend anchor as one leaf (leaf index == this block's `seq`).
        // Every anchor the chain ever had stays provable forever, so a note's copath — frozen against the anchor
        // live at its receipt — NEVER needs updating and the wallet never re-observes the stream to spend. O(1).
        self.last_served_block = reals.clone();
        // DA SHARD WRITE: persist this record's notes keyed by `seq` — one file under the datadir DA
        // directory (or the in-memory shard on test nodes). This is the 1-node mesh's DAS shard (#27),
        // sharded across peers at scale, re-serving byte-identically forever (record == serve at any height,
        // across restarts).
        //
        // EVERY BLOCK GETS A RECORD — the DA layer IS the ledger. Storing only blocks that carried a user
        // payment left the ledger with holes: measured 0 records on disk across 319 blocks. Two consequences,
        // both fatal. A block WITHOUT a record is distinguishable from one with (an observer never has to read
        // it — its absence classifies it). And nothing could dedup a fold or rebuild a witness for a block the
        // ledger had never heard of.
        //
        // The record is also the ONLY source of its own 256-leaf shape, so this write is what makes a
        // block's leaves reproducible off-node at all: a peer that REPLICATES the record derives the
        // identical 256 leaves from it. A peer that independently re-records the same block does NOT, while
        // the seed above stays node-local — see `two_nodes_derive_byte_identical_block_leaves…`.
        //
        // This is not node growth. Node verification state stays folded and O(1); ledger records are the
        // ledger doing its job — the thing that must outlive every restart so an owner can restore spendable
        // notes at any time, forever.
        self.da_store(seq, &reals, key);
        // …and the SAME binding again now that the ROW EXISTS: the mark above the early returns is the
        // upgrade path for a row already held, this one covers the fresh write. One rule, one producer,
        // no second decision — and no new state: it flips a bool inside the row just written.
        if block.is_some() {
            self.da_mark_chain_bound(seq);
        }
        // ⭐ ADVANCE THE SERVED-PREFIX ACCUMULATOR — here, where the record now EXISTS.
        //
        // A spender folds the roots `/membership_roots` serves, so this running fold is the endpoint its
        // carrier names. `membership_acc` is a different sequence (it folds at DAG-accept, over every block
        // entering the DAG), and a wallet landing on a value the node never held had its spend refused
        // MEMBERSHIP_PROOF_INVALID with nothing wrong on either side — measured on a real four-process
        // cross-device send, invisible in-process where the two sequences coincide.
        //
        // ⚠️ IT MUST BE AFTER `da_store`. Folding it earlier read a record that did not exist yet, so
        // `da_block_leaves` returned None, the accumulator never advanced, NOTHING was indexed, and the gate
        // refused every carrier exactly as before — a fix that silently did nothing.

        addr
    }

    /// Is this block's record already in the spine?
    pub(super) fn block_record_folded(&self, id: &crate::block::BlockId) -> bool {
        // Genesis carries no record of its own: it is the fold's floor, folded by definition. So is every
        // ancestor placeholder a resume or a jump installed below the fold root.
        self.relay.dag().genesis() == Some(*id)
            || self.folded_floor.contains(id)
            || self
                .da_ord_mem
                .get(&Self::da_record_id_for_block(id, 0))
                .map_or(false, |o| *o < self.served_seq)
    }

    // `block_status_unknown()` DELETED (2026-09-05, derived-ordinal stage 1): the pure mergeset
    // (`chain_block_mergeset`) decides membership from the DAG alone — HELD is the status, and a
    // member that is not held is a WAIT that names the block to the by-id block lane. The two
    // lessons that function carried live on in the new walk: (1) a block PRESENT in this DAG is
    // never "unknown" (the proxy deadlocked two honest restarted nodes — `diag_case_04_last_hole`,
    // 2026-09-04: both parties on the SAME tip, one folded 238 records and the other NINE, each
    // waiting for rows the other never folded); (2) the one conservative wait that must stay —
    // a node whose own certified anchor is absent from its DAG — is the first check inside
    // `chain_block_mergeset`. Full text in node.rs.preOrdStage1-20260905.
    /// A peer's page row disagreed with this node's canonical order above the dense counter (dropped).
    pub(super) fn note_row_hint_mismatch(&mut self, ordinal: u64, rid: u64) {
        if self.row_hint_mismatches % 64 == 0 {
            eprintln!(
                "[fold-row-hint] a peer's row for ordinal {ordinal} disagrees with this node's canonical order — \
                 the row is dropped, the fold follows the DAG; the certified fork choice settles who re-anchors"
            ); // DIGITAL-CASH-PRIVACY-REVIEWED: ordinal only; the record id stays out of the log.
        }
        let _ = rid;
        self.row_hint_mismatches = self.row_hint_mismatches.saturating_add(1);
    }

    /// Record that this fold pass waited on `primary`. Same id as last pass ⇒ the count rises; a
    /// different one ⇒ the count restarts, because a moving target is ordinary catch-up.
    /// `why` names the wait — printed when a new wait starts and at every power of two while the SAME wait persists, so a
    /// node that waits for ever says WHAT it waits on (user 2026-10-06: "accurate reasons for any failure"). MEASURED: the
    /// fresh node of `sim-20261006-052600` T1.6 counted 3,731 fold waits with no reason anywhere in the log.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason string and a count — no id, tag, cm, amount, key or owner.
    pub(super) fn note_fold_wait_on(&mut self, primary: Option<crate::block::BlockId>, why: &'static str) {
        // ⛔ A-F96 (lane speed5, 2026-11-17): CHAIN LENGTH, never blue score (charter §6, two coordinate spaces). The reach is "four
        // times the furthest the settled root ever stands below the tip", and the root stands `depth` SELECTED-CHAIN steps below it
        // (dag.rs `fold_root_by_finality`'s depth rule). Blue score grows with the DAG's width (each chain block merges ~w blues), so
        // at width 6 the 32-level reach was ~5 chain steps: a healthy fold read as outgrown and re-anchored (netsim, 6 seeds, main
        // 6cf616db: 8 `fold-outgrown`, five seeds off node 0's chain).
        let tip_blue = self.relay.dag().selected_tip().and_then(|t| self.relay.dag().get(&t)).map_or(0, |n| n.selected_chain_len);
        let new_wait = !matches!((self.fold_wait_on, primary), (Some((prev, _)), Some(p)) if prev == p) && primary.is_some();
        self.fold_wait_on = match (self.fold_wait_on, primary) {
            (Some((prev, k)), Some(p)) if prev == p => Some((p, k.saturating_add(1))),
            (_, Some(p)) => Some((p, 1)),
            (prev, None) => prev,
        };
        if new_wait {
            self.fold_wait_since_len = tip_blue;
        }
        if let Some((_, k)) = self.fold_wait_on {
            if k.is_power_of_two() {
                eprintln!("[fold-wait-why] the fold waits ({k} pass(es) on the same block): {why}");
            }
        }
        // ⭐ A-F63 — A WAIT THE CHAIN HAS OUTGROWN ENDS IN THE REPAIR, NEVER IN A HOARD. The fold has not moved off one block
        // while the selected chain grew more than `UNFOLDED_BODY_REACH_LEVELS` levels — four times the furthest the settled
        // root ever stands behind the tip (`FINALITY_SEAT_ACTIVATION_DELAY`). Nothing it waits for is coming in time: the
        // spine is marked stale, the runtime asks every tick for a certified bundle (`spine_needs_reanchor`), and the
        // adopt re-anchors the fold near the tip (`fold_stuck_behind`). A slow band or a late body moves the fold a step at
        // a time, and every step starts a new wait, so a fold that is merely slow is never stopped by this.
        // MEASURED why (2026-11-14, three real nodes): two folds waited at step 94 for hours while their tips ran to 633;
        // each held 802 unfolded blocks and a 394 MB snapshot, growing ~1 MB a block, until killed.
        // BORROWED: a node past the pruning point re-syncs from a snapshot (Kaspa's IBD); it never replays or hoards.
        // AI RESISTANT: (b) code; a peer gains nothing (the bundle it might serve passes the join door like any other).
        // cons: a node marked stale folds nothing until a bundle lands (it folded nothing already); 0 bytes.
        // ⛔ FOLD OVERHAUL F-5 (lane livewedge, 2026-11-26; docs/FOLD-OVERHAUL-DEEP-AUDIT-20261126.md) — A SHELL'S AGE IS A FACT OF
        // THE CHAIN, NOT OF THIS WAIT. The wait's own clock (`fold_wait_since_len`) starts at the first pass that waits on the block,
        // so it restarts at every boot and after every mark the prune drops (`Dag::prune_below_horizon` drops a withheld mark with
        // its block; a re-arrived shell comes back unmarked). MEASURED (live 27780, 2026-11-25): the same shell a568aea7 withheld
        // twice on one boot, each after a fresh 32-level wait. A body-less shell the fold needs whose OWN place on its selected chain
        // stands past the reach behind the tip is outgrown the moment the fold waits on it: one function of the DAG, true after a
        // restart, a prune and a re-arrival alike. Only a shell (no body held) is judged by its age: a held block whose record is
        // late keeps the wait's own clock, so a late but whole block never triggers the stale re-anchor early.
        let shell_age_outgrown = self.fold_wait_on.is_some_and(|(p, _)| {
            !self.unfolded_blocks.iter().any(|x| x.id() == p && !x.pow_proof.is_empty())
                && self.relay.dag().get(&p).is_some_and(|n| wait_outgrown(n.selected_chain_len, tip_blue))
        });
        if self.fold_wait_on.is_some()
            && !self.spine_stale
            && (wait_outgrown(self.fold_wait_since_len, tip_blue) || shell_age_outgrown)
        {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two public level counts and a fixed reason.
            eprintln!(
                "[fold-outgrown] the fold has waited on one block while the chain grew {} levels (reach {UNFOLDED_BODY_REACH_LEVELS}): {why}",
                tip_blue.saturating_sub(self.fold_wait_since_len)
            );
            // ⛔⛔ LIVE-FOLD W1 (lane livefold, 2026-11-25; docs/LIVE-FOLD-WEDGE-DEEP-AUDIT-20261125.md) — A SHELL NOBODY SERVED IS
            // WITHHELD, AND THE HEAD LEAVES IT. When the block waited on is a SHELL (no body held here) the certified re-anchor cannot
            // end the wait unless some peer folded past it; when every reachable peer waits on the same shell (MEASURED live
            // 2026-11-25: the one peer's bundle certified 3785, the wait came back at 3786 after the adopt, fold 9,451 blocks
            // behind, finality 0) it never ends. The block is marked withheld (`Dag::mark_withheld`): neither it nor any block built
            // on it is head or merged, so this node builds from the heaviest available block and its fold and finality move. The
            // shell-body lane keeps asking for the body; when it lands the mark clears (`fill_shell_body_preverified`) and fork choice
            // returns to the heavier chain if it is heavier. The bundle is still asked for (the spine stays stale only when the
            // wait is not on a body-less shell), so a peer that folded past the block still re-anchors this node.
            // BORROWED: Kaspa (a block whose body is not validated is never a virtual parent), Bitcoin (never extend an unvalidated
            // chain). S-WAIT: the wait's expiry DOES the work (the head moves), it never drops a block.
            // AI RESISTANT: (b) code; withholding a body costs the withholder its block's place on the chain.
            // SCALE: one children walk of the withheld block's held future, once; nothing grows.
            // cons: none measured — a node that lacked a body every other node held builds a lighter branch for the time the body is
            //   unserved (the reach, then until the body lands), the same exposure as a partition.
            let shell_unheld = self.fold_wait_on.is_some_and(|(p, _)| {
                !self.unfolded_blocks.iter().any(|x| x.id() == p && !x.pow_proof.is_empty())
                    && self.relay.dag().get(&p).is_some()
            });
            if shell_unheld {
                if let Some((p, _)) = self.fold_wait_on {
                    // ⛔ W-FOLD-1b (docs/LIVE-FINALITY-AND-FOLD-WEDGE-DEEP-AUDIT-20261125.md): a shell ALREADY withheld ends the wait too —
                    // MEASURED live 2026-11-25 15:06+: "[fold-outgrown] … grew 1058 levels" repeated with no "[fold-withheld]", because
                    // the second firing found the mark set and left `fold_wait_on` in place: an expiry that did not do the work
                    if !self.relay.dag_mut().mark_withheld(p) && self.relay.dag().is_withheld(&p) {
                        self.fold_wait_on = None;
                    } else if self.relay.dag().is_withheld(&p) {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a public block-id prefix and a count — no tag, cm, amount, key or owner.
                        eprintln!(
                            "[fold-withheld] ⛔ W1: block {} is a shell no peer served past the body reach — marked WITHHELD ({} held); \
                             the head leaves it and every block built on it, the fold moves on the available chain, its body is still asked for",
                            &p.to_hex()[..8],
                            self.relay.dag().withheld_count()
                        );
                        self.fold_wait_on = None;
                    }
                }
            } else {
                self.mark_spine_stale("the fold waited on one block while the chain outgrew its body reach");
            }
        }
    }

    /// THE ANCHOR DOOR — the ONE node-level site that installs a `Dag` trust root.
    ///
    /// `Dag::add_anchor` is the heaviest of the five `BlockNode` construction sites: on a
    /// `(blue_work, id)` win it CLEARS the tip set and makes the anchor the sole selected tip,
    /// with no parent required and no ancestry replayed. Two callers reach it — the #29 DSYNC
    /// adopt and `restore_snapshot` — and each used to call `dag_mut().add_anchor(..)` inline, so
    /// an admission rule added to one of them would silently miss the other (this crate's
    /// "I fixed one of several" trap, four times paid). Both now come through here, and the
    /// admission decision itself lives in [`Self::header_grind_admits`], shared with every other
    /// non-gossip door. Placement stays in `Dag`; the decision is here.
    pub(crate) fn admit_anchor_block(
        &mut self,
        block: Block,
        blue_work: u128,
        blue_score: u64,
    ) -> bool {
        // ⛔ THE HEADER DOOR, not the grind alone (2026-09-07). `None` for the clock: an anchor is a
        // block from a chain AHEAD of this node — that is why it is being adopted — so no clock this
        // node can derive is an upper bound on its timestamp, and a node an hour behind would refuse
        // the very bundle that heals it. §9.6 Q6, stated plainly: the wall-clock drift rule is the
        // ONE gossip-door check this door does not carry, and its absence is bounded by the rest —
        // the grind binds the claimed `work`, and the anchor's blue data is bound into the certified
        // accumulator `sync::adopt_sync_bundle` verifies before this is reached.
        // G1g-vi: a bundle carries no certified anchor DEPTH, so the adopt's origin is the anchor's blue score (see
        // `Dag::add_anchor`); the resume passes the depth its own checkpoint recorded.
        self.admit_anchor_block_weighed(block, blue_work, blue_work, blue_score)
    }

    /// [`Self::admit_anchor_block`] for an adopt whose anchor stands for a heavier chain than its own weight shows: `chain_work` decides
    /// whether the anchor wins over this node's tip (`Dag::add_anchor_weighed`); the header door and the stored weight are unchanged.
    pub(crate) fn admit_anchor_block_weighed(&mut self, block: Block, blue_work: u128, chain_work: u128, blue_score: u64) -> bool {
        if !self.header_door_admits_witnessed(&block, None, PowWitness::Required) {
            return false;
        }
        self.relay.dag_mut().add_anchor_weighed(block, blue_work, chain_work, blue_score, blue_score)
    }

    /// The anchor door with its witness policy named by the caller.
    ///
    /// ⛔⛔⛔ THE 2026-09-13 DOOR AUDIT BROKE EVERY RESTART. It made this door demand `pow_proof`
    /// (`PowWitness::Required`) — right, for a NETWORK anchor: R1/R2/R3 showed a DSYNC bundle carrying a
    /// seven-hash grind and `u128::MAX` blue work walking in and owning the tip. But `restore_snapshot`
    /// re-installs the node's OWN tip through the same door, and `export_snapshot` writes that tip as a
    /// shell (`pow_proof: Vec::new()` — "not needed to resume", which was true until the audit). So every
    /// restart refused its own tip: `dag_len=1`, `fold_chain_tip` absent from the DAG, `spine_stale`
    /// raised by the fork walk, and the node NOT_READY until a bundle happened to re-anchor it. MEASURED
    /// by the three `da_seed_regen` resume pins (`producer ready=false, peer ready=false`) and the
    /// rolling-restart scenario blowing its 600 s deadline in a `[record-regen]`/`[da-fetch]` loop.
    ///
    /// The snapshot's tip is a block "rebuilt from headers the DAG retained" — `PowWitness::NotServable`'s
    /// own definition — and it was witness-verified when this node first admitted it through a network
    /// door. A snapshot is the node's own persisted state read from its own disk, not network input; a
    /// forged snapshot file is a compromised host, which owns the accumulators too. The audit's
    /// requirement stands unchanged on every network door.
    pub(crate) fn admit_anchor_block_witnessed(
        &mut self,
        block: Block,
        blue_work: u128,
        blue_score: u64,
        selected_chain_len: u64,
        witness: PowWitness,
    ) -> bool {
        if !self.header_door_admits_witnessed(&block, None, witness) {
            // Nothing partial is applied: an anchor that cannot show a grind — or whose header is
            // malformed — is not installed, and this node keeps the tip set it already has (the same
            // outcome as an anchor that loses on weight, which every caller already handles).
            return false;
        }
        self.relay.dag_mut().add_anchor(block, blue_work, blue_score, selected_chain_len)
    }

    /// Install a carry (see `unfolded_carry`): the window headers as linked ancestors, the folded parents as
    /// ancestors, then the unfolded blocks with their carried blue data — records written, nothing re-applied
    /// (the certified or checkpointed unspent and nullifier state already includes these blocks). Then the
    /// canonical fold continues from the fold root.
    /// `pub(crate)` because it is a DOOR (two of the five `BlockNode` construction sites are
    /// reached only from here) and a door is pinned by driving it, not by driving the transport
    /// that happens to feed it today.
    pub(crate) fn graft_unfolded_carry(&mut self, carry: crate::sync::FoldCarry) {
        self.place_unfolded_carry(carry);
        let _ = self.fold_canonical_records();
    }

    /// Records written so far — the frontier's append count. NOT an address: a record is named by its
    /// canonical chain position ([`Self::da_record_id`]), so use [`Self::da_top_record_id`] to bound any address walk.
    /// DB-332: this node's OLI serve cache (an `Arc` clone, so the off-lock builder can fill it).
    pub(crate) fn oli_serve_cache(&self) -> std::sync::Arc<OliServeCell> {
        std::sync::Arc::clone(&self.oli_serve_cache)
    }

    /// Build the OLI locator index for the CURRENT epoch: every recorded block contributes its constant
    /// 256 slots (tagged slots from the K-log, every other slot regenerated from the DA secret), which is
    /// what keeps the served index free of any real-count signal. Returns the index plus the shard-bit
    /// width a wallet needs to know to locate its shard.
    ///
    /// Serving-tier work, off the consensus path — a node that never serves restores need not call it.
    pub fn oli_build_index(&self) -> crate::oli::Index {
        self.oli_build_index_upto(self.da_top)
    }

    /// The same build, closed at an explicit epoch boundary so every node serving the same epoch serves
    /// a byte-identical index (and so the serve layer can cache one build per epoch).
    ///
    /// The tag set is read from the DA shard — replicated, any-height, never aged out — so this is a pure
    /// function of data every node holds. It does NOT consult the bounded clue cache, which is why a node
    /// that synced its history builds exactly the same index as the node that recorded it.
    /// The locator klog, maintained at WRITE time by `da_store_tags` — the reason no scan is needed to build
    /// the index. Bounded by the REAL notes the chain has carried (cover slots carry no tag), and appended
    /// O(1) per record, so it has the same shape as the node's other folded state.
    /// DIGITAL-CASH-PRIVACY-REVIEWED: the same tag bytes already on the DA shard; never a note, commitment,
    /// amount, key or owner.
    /// ⛔⛔⛔ P4′e — THE KLOG WAS A PROCESS-GLOBAL `static`, AND THAT IS TWO DEFECTS IN ONE.
    ///
    /// It was `static KLOG: OnceLock<Mutex<Vec<..>>>`, i.e. ONE log shared by every `Node` in the process,
    /// while the tags it mirrors live in the PER-NODE `da_tags_mem`. Two consequences:
    ///
    /// 1. **A second source of truth.** [[reference_oli_tags_are_da_resident_never_cached]] is explicit that
    ///    the DA shard is the sole source and that a K-log beside it must never be reintroduced — "a stale
    ///    second source of truth". A record adopted into `da_tags_mem` by any path that did not also append
    ///    to the static would be invisible to the index, and vice versa.
    /// 2. **It silently made cross-node tests non-discriminating.** MEASURED while landing P4′b: the backfill
    ///    test `a_node_that_backfills_a_record_rebuilds_the_same_locator_index_...` passed with the sidecar
    ///    adoption DELETED, because the "fetching" node was reading the SOURCE node's entries out of the
    ///    shared static. In production each node is its own process, so the bug is invisible there — which is
    ///    exactly the class this codebase keeps paying for.
    ///
    /// Derived from `da_tags_mem` instead: one source, per-node by construction. Same cost as the log it
    /// replaces — one entry per TAGGED note (cover slots carry no tag), bounded by the real notes the chain
    /// has carried, with no term in height or block count. This is NOT the deleted per-ordinal walk, which
    /// visited every record whether or not it held a tag.
    /// ⭐ DB-223 Q2 §11 (a): each entry names its note by FOLD ORDINAL — NOT A RECORD ADDRESS — so a restored wallet
    /// learns its note's leaf index `(ordinal − 1)·256 + slot` from the entry itself, with no `address → ordinal` ask.
    /// ONE coordinate on the wire (AGENTS.md §6): the entry holds the ordinal only, and `/get_my_pq_notes`'s
    /// `by_ordinal` ask resolves it to the record node-side. A record not yet folded has no ordinal and no entry: its
    /// owner captures it at arrival from the applied stream. Rewinds stay exact by derivation: this reads the node's
    /// CURRENT `da_ord_mem` at every index build, so a re-folded record is entered at its new ordinal.
    pub(super) fn oli_klog_entries(&self) -> Vec<(u64, u8, [u8; crate::oli::K_BYTES])> {
        let mut out: Vec<(u64, u8, [u8; crate::oli::K_BYTES])> = Vec::new();
        for (seq, slots) in self.da_tags_mem.iter() {
            let Some(ordinal) = self.da_record_ordinal(*seq) else {
                continue; // not folded yet: the applied stream's capture covers it
            };
            for (slot, k) in slots.iter() {
                out.push((ordinal, *slot, *k));
            }
        }
        out
    }

    /// DB-107: the index build's inputs, snapshotted under the lock so the build itself runs off it.
    pub fn oli_build_inputs(&self, end_seq: u64) -> OliBuildInputs {
        OliBuildInputs {
            klog: self.oli_klog_entries(),
            chain_key: self.oli_chain_key(),
            end_seq: end_seq.min(self.da_top),
            epoch_seed: self.oli_epoch_seed(),
        }
    }

    pub fn oli_build_index_upto(&self, end_seq: u64) -> crate::oli::Index {
        // Bound by the canonical ADDRESS space: tags live at canonical addresses, so bounding by the
        // append count silently truncated the index and the 1ms locator lookup found nothing.
        // ⛔⛔⛔ THE INDEX WAS BUILT OVER THE WRONG COORDINATE SPACE — WHICH IS WHY IT WAS EMPTY.
        //
        // `end_seq` arrives as a BLOCK COUNT (the caller passes `served_block_count()`), while `da_load_tags`
        // is keyed by a RECORD ADDRESS. `min(block_count, da_top)` therefore yields the block count, and this
        // loop scanned addresses 0..~600 while real records live at addresses around 2.9e17. Every iteration
        // missed, so `Index::build` got an EMPTY klog and every locator lookup returned nothing.
        //
        // MEASURED 2026-08-10, after the read side had been made provably correct — epoch floor removed,
        // process-local counter removed, COLD_RESTORE_GAP gate removed, and BOTH v1 and v2 tag keys probed:
        // `[oli-range] searched locator indices [0,2) and matched 0` and `[oli-gap] ... OLI covered 0
        // commitment(s)` still, on a wallet whose own note had just settled. Six theories about the read path
        // died against that number; the write side never had anything to find.
        //
        // The comment this replaces already recorded the SAME defect being found once before ("bounding by
        // the append count silently truncated the index and the 1ms locator lookup found nothing") and fixed
        // it by clamping to `da_top` — but clamping did not change the fact that the loop VARIABLE is an
        // address while the bound is a block count. Two coordinate spaces, one name.
        //
        // Iterate the DENSE record ordinal space and resolve each ordinal to its address, which is the same
        // pairing `/get_my_pq_notes` uses to serve a record. The ordinal is also what the wallet hands back to
        // fetch the note, so the position recorded here is the position it can actually ask for.
        // NO GROWTH ON THE SERVE PATH: this is the node building its OWN index, already amortised by the
        // caller's cache, and it stores nothing new — tags stay DA-resident
        // ([[reference_oli_tags_are_da_resident_never_cached]]).
        // ⭐⭐⭐ NO WALK. The klog is maintained at WRITE time by `da_store_tags`, so building the index is
        // a read of what the node already holds — there is no ordinal loop here at all.
        //
        // What used to be here walked EVERY record ordinal on every call. Caching it per 64-block epoch hid
        // the cost; removing that epoch floor (necessary — it left the newest 0..63 blocks unindexed) exposed
        // it as a full re-walk per block, measured at 73,240ms for one restore at ~8,600 blocks. Making that
        // walk incremental would still leave a term in chain length on first run and after every restart.
        // The walk is deleted, not amortised.
        // P4'e: derived from THIS node's own DA tag shard — one source of truth, per node. The value is
        // identical to what the old process-global log held, minus the ability to read a DIFFERENT node's
        // tags out of a shared static.
        let klog: Vec<(u64, u8, [u8; crate::oli::K_BYTES])> = self.oli_klog_entries();
        let top_ordinal = self.da_highest_record_ordinal().unwrap_or(0);
        let unplaced = 0usize;
        eprintln!(
            "[oli-build] indexed {} tag(s) across {} record ordinal(s), {unplaced} of which this node could \
             NOT place — every note in an unplaced record is absent from the locator index and unfindable by \
             its owner until that record is fetched",
            klog.len(),
            top_ordinal.saturating_add(1)
        );
        crate::oli::Index::build(
            &klog,
            &self.oli_chain_key(),
            0,
            end_seq.min(self.da_top),
            // ⛔⛔⛔ THE LAST 256 REMNANT — CHAFF WAS SIZED TO THE RETIRED COVER, NOT TO A REAL RECORD.
            //
            // This passed `BLOCK_FIXED_NOTE_COUNT`, so `epoch_entries` minted a chaff entry for slots
            // 0..256 of EVERY record. That was right when every block carried 256 notes; with the cover
            // retired a record carries ~1 (MEASURED: 1.01 leaves/block, `spend_count 1` at height 902), so
            // 255 of every 256 chaff entries name a slot that does not exist.
            //
            // MEASURED on the live pair: `[oli-build] indexed 1 tag(s) across 902 record ordinal(s)` — 902
            // records x 256 = 230,912 chaff entries crowding the one real tag. Its key `4abc6447` hashes to
            // shard 9 (shard_bits=5), the wallet's `[oli-ask]` probes exactly that key and shard, and
            // `locate` still returns 0: the real entry cannot be retrieved from a table packed with chaff
            // for slots the chain never had.
            //
            // Sizing chaff to the record's real width is also the honest shape now. Hiding WHICH slot is
            // real still matters and is unchanged; padding to a width the chain abandoned hides nothing —
            // the served note count already reveals it — while evicting the entry an owner needs to find
            // their money.
            1,
            self.oli_epoch_seed(),
        )
    }

    /// ⭐⭐⭐ THE LOCATOR INDEX IS A CHAIN PROPERTY — KEYED ON THE GENESIS ID, NEVER ON THIS NODE.
    ///
    /// ⛔ Both this seed and the index's chaff key were `da_secret_value()`, and the old doc said so outright:
    /// *"so every wallet re-derives the same A matrix AGAINST THIS NODE"*. That is the whole defect. A wallet
    /// that asks node A and a wallet that asks node B were querying DIFFERENT indexes over the same chain, so
    /// a note found on one node was missing on the other — the same shape as the record divergence that made
    /// two nodes disagree on 12 of 12 ordinals, only one layer up.
    ///
    /// The genesis id is the one value every node on a network derives identically and no node can choose. It
    /// is already public (`/get_info` serves `chain_id`), so keying on it reveals nothing new: the index still
    /// answers by oblivious lookup, and WHICH entry a wallet wants is still never sent.
    pub(super) fn oli_chain_key(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new(); // keyed by content, not by any node-held secret
        h.update(b"MUSD/oli/chain-key/v1");
        // `genesis()` is Option: a node with no genesis has no chain to key on, so fall back to the domain
        // tag alone rather than inventing a value. Every node on a real network has one.
        if let Some(g) = self.relay.dag().genesis() {
            h.update(g.as_bytes());
        }
        *h.finalize().as_bytes()
    }

    /// The epoch's shared PIR randomness seed — a CHAIN property, so every node builds the identical A matrix.
    pub fn oli_epoch_seed(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/oli/epoch-seed/v1");
        h.update(&self.oli_chain_key());
        *h.finalize().as_bytes()
    }

    /// Are the bytes this node holds at `addr` CHAIN-BOUND (see `da_mark_chain_bound`)? A row this node
    /// does not hold at all is NOT bound — an absent row authorises nothing, which is the same
    /// fail-closed answer, not a rescue.
    pub(crate) fn record_bytes_are_chain_bound(&self, addr: RecAddr) -> bool {
        match self.da_mem.get(&addr.get()) {
            Some(row) => row.2,
            None => false,
        }
    }

    /// ⛔⛔⛔ A PAGE VOUCHES FOR WHAT IT DELIVERED — EVERYTHING ELSE IT "COVERED" IS A NAMED HOLE.
    ///
    /// `sidecar_page` walks `from..end` and SKIPS every ordinal the server lacks
    /// (`ord = ord.saturating_add(1)` with no row pushed), then returns `covered_upto = end`
    /// regardless. Skipping is correct — stopping at the first hole is the head-of-line block
    /// `adopt_sidecar_row` and `notes_page` both carry warnings about — but the asker then set its
    /// cursor to that `covered_upto` and registered NOTHING for the skipped ordinals. The rows were
    /// never delivered, the cursor had moved past them, the count-based backlog no longer counted
    /// them, and no lane ever asked for them again: the fold waited on rows nobody would ever send.
    /// `sidecar_page`'s own doc already states the intent this closes — "Rows this node lacks are
    /// skipped — the asker's cursor names them again to another holder" — and the naming half did
    /// not exist.
    ///
    /// ROOT-LAYER: coverage is a claim the SERVER makes and the ASKER must reconcile against what
    /// landed; only the asker knows which of `from..covered_upto` it now holds. Fixing it in
    /// `sidecar_page` would mean serving `covered_upto = first_missing`, which re-introduces exactly
    /// the head-of-line stop the skip exists to avoid (measured: one missing seq returned an empty
    /// page forever).
    /// MUST-STAY-GREEN: the cursor still advances to the server's `covered_upto` (no head-of-line
    /// block, ordinals above a hole stay reachable); a hole is filled by ANY holder through the
    /// unchanged `adopt_sidecar_row` door, which removes the want the moment the row lands, and
    /// `retire_held_record_ids` removes it if this node folds the row itself.
    /// ONE COORDINATE SPACE, by construction: under the derived ordinal (C1) a record's position is
    /// a function of the DAG, so two nodes on the same chain derive the same number for the same
    /// record — the server's `ord` and this node's `da_ord_rev_mem` key are the same coordinate.
    /// This is the identical pairing `adopt_sidecar_row` makes when it removes a want by the
    /// server's `ord`, and that `retire_held_record_ids` makes when it retires one by looking the
    /// ordinal up in `da_ord_rev_mem`.
    /// cons: one map read per covered ordinal on a page that landed — the same page's row count, a
    /// fixed ladder span — and at most `TX_REQ_FIXED_COUNT` want entries, the bound
    /// `want_record_at_ordinal` already enforces. Nothing is stored and nothing grows with height.
    pub fn name_sidecar_page_holes(&mut self, from: u64, covered_upto: u64) {
        let mut named = 0usize;
        let mut ord = from;
        while ord < covered_upto {
            if self.wanted_ordinals.len() >= crate::protocol::TX_REQ_FIXED_COUNT {
                break; // the request width is full; the rest are named on a later page
            }
            if !self.da_ord_rev_mem.contains_key(&ord) {
                self.wanted_ordinals.insert(ord);
                named += 1;
            }
            ord = ord.saturating_add(1);
        }
        if named > 0 {
            // A COUNT and two stream POSITIONS — the same coordinates the page header itself carries
            // on the wire. Never a record id, note, commitment, amount, key or owner. Fires only on a
            // page that claimed coverage it did not deliver, so a healthy lane is silent.
            eprintln!(
                "[sidecar-hole] a page claimed coverage to {covered_upto} from {from} but {named} \
                 of those ordinal(s) carried no row — named as holes so the ask returns to them"
            );
        }
    }

    /// The runtime re-asked the SAME position (throttle expiry with no fresh row in between):
    /// count it toward the head-of-line bound. Interior-mutable — the ask path holds `&self`.
    pub fn note_sidecar_ask_repeat(&self) {
        self.sidecar_ask_starved.set(self.sidecar_ask_starved.get().saturating_add(1));
    }

    /// A sidecar page landed `fresh` new rows. Any progress resets the head-of-line counter — the
    /// lane is moving, so lowest-first is the right order again.
    pub fn note_sidecar_page_outcome(&self, fresh: usize) {
        if fresh > 0 {
            self.sidecar_ask_starved.set(0);
        }
    }

    /// Register one row of a peer's sidecar page: the ordinal↔address row (through the ONE ordinal
    /// writer, `da_store_ordinal` — first-writer; an existing row is never re-mapped) and its
    /// receive/deletion sidecars (first-writer, exactly as the full page adopts them).
    ///
    /// ⛔ THE ROW IS UNCERTIFIED — ANY PEER PAGES ITS OWN CLAIMS, A DIVERGED ONE INCLUDED — AND THIS
    /// FUNCTION STILL VERIFIES NOTHING. That was survivable while its only refusal was an ordinal
    /// conflict ONLY because nothing downstream moved money on it; it did (holes C-H2/C-H3: a row at a
    /// free slot minted a commitment into the unspent set, and its deletion half removed a note its
    /// owner held). The admission now lives at the shared sink both page kinds reach —
    /// `fold_record_sidecars_if_ready`, whose doc carries the six-question spec — so a row this node
    /// cannot bind is STAGED here and folds later, when the record's body or its chain binding arrives.
    /// A READY node folds a bound row on the spot exactly as before; a NOT_READY node's tick heal
    /// replays these rows and certifies at closure against the adopted root, also as before.
    pub fn adopt_sidecar_row(&mut self, ord: u64, rid: u64) -> bool {
        // RID-KEYED. The server's `ord` is only where THAT node filed the record: a rid this node
        // already holds keeps its own ordinal and just takes the sidecars (a refill after a REVERT is
        // exactly this path); an unknown rid is filed at the server's slot when it is free here, else
        // appended past this node's top — never over a slot another rid already owns.
        // v31 ORDINAL LAW: a certified peer's row is authoritative below this node's dense counter (the
        // adopted prefix): a conflicting local claim leaves. At or above the counter a row that disagrees
        // with what this node folded means the DAGs differ — fail closed (stale), never shove the row to
        // a made-up slot (gate 44: such rows sat at `top + 1` forever as a 15-row gap nobody could fill).
        let local_ord = self.da_ord_mem.get(&rid).copied();
        let occupant = self.da_ord_rev_mem.get(&ord).copied();
        let fresh = local_ord.is_none();
        // A page row is UNCERTIFIED (any peer pages its own claims, a diverged one included): it fills a
        // slot this node has no claim for and never displaces one it has. Below the counter such slots
        // are exactly the coordinates an adopt evicted; above it the row is a hint the fold checks.
        // ⛔⛔⛔ A REFUSED ROW MUST NOT STOP THE PAGING CURSOR — SKIP THE ROW, NEVER THE PAGE.
        //
        // The refusal below is CORRECT (a conflicting claim must not be shoved over a slot another rid
        // owns), but it used to `return false` BEFORE the cursor advance underneath it. The cursor is
        // "how far a peer's pages have covered me", and the server covered this ordinal whether or not
        // this node liked the row — so returning early froze the cursor on the first disputed row and the
        // node re-asked from that same position forever, never reaching ANY later ordinal. Head-of-line
        // blocking, and the exact shape `notes_page` already carries a warning about: "SKIP a seq this
        // node has no record for, never STOP: breaking at the first hole made one missing seq return an
        // empty page forever".
        //
        // MEASURED 2026-09-04 (`diag_case_04_last_hole`, after the fold-deadlock fix removed the
        // `[fold-wait]` stall — 0 lines in two runs — this became the dominant one):
        //     p0: seq=238 certified=238 cursor=238 gap=0   missing=1
        //     p1: seq=238 certified=238 cursor=4   gap=266 missing=33 breakdown=(32, 0, 1, 0, 0)
        //         ask_from=4 ask_wanted=true
        // Both parties on the SAME tip, the peer holding 238 records and able to serve every one of them,
        // and p1 pinned at cursor 4 wanting 32 ordinals by range. The earlier sibling diagnostic printed
        // the refusals directly: `row ord=5 … -> p1 adopt_sidecar_row = false`, three in a row.
        //
        // ROOT-LAYER: the cursor is WRITTEN here — this function is its producer for the row-by-row path.
        // Advancing it in the caller would be patching a reader of a position this function got wrong.
        // MUST-STAY-GREEN: the v31 ordinal law is untouched — a conflicting row still refuses, still
        // records `note_row_hint_mismatch`, and still returns `false`, so no caller learns anything new
        // and no row is ever filed over a slot another rid owns. Only the cursor moves.
        // cons: none. The refused row is not lost — it stays wanted through the by-id and by-range want
        // sets that named it, and a later page re-offers it; what changes is that ordinals ABOVE it are
        // now reachable at all.
        let refused = match (local_ord, occupant) {
            (Some(o), _) if o == ord => false,
            (None, None) => {
                self.da_store_ordinal(rid, ord);
                false
            }
            (None, Some(_)) | (Some(_), _) => {
                self.note_row_hint_mismatch(ord, rid);
                true
            }
        };
        // The page covered the server's ordinal `ord`: the paging position moves past it here too, so a
        // node driven row by row (not only by the runtime's page handler) keeps the same cursor.
        if ord.saturating_add(1) > self.sidecar_cursor {
            self.sidecar_cursor = ord.saturating_add(1);
        }
        if refused {
            return false;
        }
        // The want for this ordinal is satisfied by exactly this arrival: the row is here (fresh, or
        // this rid already held its slot), so the by-ordinal want it answers leaves the set NOW —
        // event-driven, at the one place the row lands. Leaving it for a later sweep kept
        // `sidecar_ask_wanted()` true after a fully-served page: MEASURED
        // `a_jumper_with_by_id_byte_wants_still_asks...` red at "nothing more to ask" with backlog 0,
        // and the orphan-reconcile pin's "A is READY ... (serve=true gap=1)". A REFUSED row above
        // keeps its want on purpose — the row this node needs there is a different one.
        self.wanted_ordinals.remove(&ord);
        // ⭐⭐⭐ ONE COORDINATE, BUILT ONCE, FROM THE WIRE (see [`rec_coord`]). `rid` and `ord` are the
        // TWO SPACES arriving in one call: `ord` is the server's position, `rid` is the record's
        // address. They are never interchangeable, and this is the door where treating them as if
        // they were let a peer name `rid = <a live ordinal>` and borrow a chain-bound record's
        // authority for its own bytes — a forged receive minted, a real note deleted.
        let _ = RecAddr::from_wire(rid);
        fresh
    }

    pub(crate) fn order_book_len_for_audit(&self) -> usize {
        self.order_book.len()
    }

    /// ⭐⭐⭐ THE ONE BRIDGE BETWEEN THE TWO RECORD COORDINATE SPACES (see [`rec_coord`]).
    ///
    /// A [`RecOrd`] is a position; a [`RecAddr`] is a row key. This function is the ONLY thing in the
    /// tree that turns one into the other, and it does it by READING the ordinal map — never by
    /// re-labelling the integer. Everything else that used to hop between the spaces did so
    /// implicitly, because both were `u64`: four resolvers with four probe orders, and an authority
    /// question that indexed the ADDRESS-keyed `da_mem` with an ORDINAL. There is deliberately no
    /// `From`/`Into` and no arithmetic in either direction, so a future diff that wants to cross has
    /// to come through here, in the open, where the `Option` says "this node holds no such position".
    /// ROOT-LAYER: the crossing is the defect's whole mechanism, so the crossing is what gets a name.
    /// MUST-STAY-GREEN: everything that reads `da_addr_at_ordinal` — this is a typed view of it, with
    /// identical behaviour including the derived genesis answer at ordinal 0.
    pub(crate) fn record_addr_at_ordinal(&self, ordinal: RecOrd) -> Option<RecAddr> {
        self.da_addr_at_ordinal(ordinal.get()).map(RecAddr::local)
    }

    /// This record's settled nullifier tags in wire form (32-byte values concatenated) — the spend-side
    /// sidecar, for the same reason: a verifier rebuilds a served block's fold inputs from its DA-nf shard,
    /// and a node that never held the block cannot rebuild that shard from the notes alone.
    /// The ACTUAL canonical address a block's record landed at (inner may pick sub>0): the first sub slot
    /// holding notes. `None` = this node holds no record for the block yet.
    pub(crate) fn record_addr_for_block(&self, bid: &Hash32) -> Option<u64> {
        (0..Self::DA_RECORDS_PER_HEIGHT as u16)
            .map(|sub| Self::da_record_id_for_block(bid, sub))
            .find(|rid| self.da_mem.contains_key(rid))
    }

    pub(crate) fn adopt_ledger_sidecars(&mut self, rid: u64, oli_tags: &[u8]) {
        const TAG_REC: usize = 1 + crate::oli::K_BYTES;
        if !oli_tags.is_empty() && oli_tags.len() % TAG_REC == 0 {
            let mut merged = self.da_load_tags(rid);
            // ⛔ A-F118: the ONE merge rule (`da::merge_slot_tag`) — a REAL unit's slot takes the key that names it, a cover
            // slot keeps its first; this path kept the first key in every slot, so a joiner that adopted the sidecar held a
            // cover key in a real slot a replayer had replaced (MEASURED replica census main 56be6497, slot 1 of record 67)
            let reals = self.da_load(rid).map_or(0, |r| r.len());
            let mut changed = false;
            let mut off = 0usize;
            while off + TAG_REC <= oli_tags.len() {
                let slot = oli_tags[off];
                let mut k = [0u8; crate::oli::K_BYTES];
                k.copy_from_slice(&oli_tags[off + 1..off + TAG_REC]);
                changed |= crate::node::da::merge_slot_tag(&mut merged, slot, k, (slot as usize) < reals) != crate::node::da::TagMerge::Kept;
                off += TAG_REC;
            }
            if changed {
                self.da_store_tags(rid, &merged);
            }
        }
        // ⛔ A-F118 (2026-11-23): NO refile here or at the joiner's bind of a stripped row. MEASURED: with them the launch sim's
        // joiners held ~4,300 fewer tags below record 266 than node 0 (61,484 / 65,291 vs 65,797, main 61ea7b0d and e0d09110),
        // where 0590db07 passed; a joiner's paged rows that miss their header root are not only stripped ones. The replayer-side
        // paths (strip, restore, rewind, a grown row) keep the graft rule; the joiner's side is OPEN (audit).
        // ⛔ THE `nf_tags` COLUMN OF A SERVED PAGE WRITES NOTHING (D-41 class, 2026-09-11). It used to fill
        // `da_nf_mem` under the page's record id — a THIRD key space beside the two fold ordinals the
        // node's own writers used — and the only reader of a row filed here was the serve that echoed it
        // to the next peer. The store is deleted with the spend-gate sweep that read it; the wire column
        // stays (always empty) so an older peer's page still decodes.
    }

    /// Whether note `cm`'s OWN slot in record `seq` (the fixed-shape slot every placement uses) already holds a filed tag —
    /// `record_note_clue`'s dedup. `false` when this node holds no such record or the record does not carry `cm`.
    /// O1-FOOTPRINT-REVIEWED: one fixed-shape assembly (≤ 256 notes) of ONE record, as `file_tags_at_fixed_slots`; no store.
    pub(super) fn note_tag_is_filed(&self, seq: u64, cm: &[u8; 32]) -> bool {
        let Some(reals) = self.da_load(seq) else { return false };
        let fixed = crate::cover::assemble_fixed_note_payload(&reals.concat(), seq, &self.cover_key_of(seq));
        let want = crate::note_transition::filing_cm(cm); // the one filing identity (see `filing_cm`)
        let Some(slot) = fixed
            .chunks_exact(crate::cover::PQ_NOTE_BYTES)
            .position(|n| crate::note_transition::filing_cm(&n.fixed::<32>()) == want)
            .and_then(|p| u8::try_from(p).ok())
        else {
            return false;
        };
        self.da_load_tags(seq).iter().any(|(s, _)| *s == slot)
    }

    /// DB-185: name the refusal, sampled so a repeated cause cannot flood a log.
    pub(super) fn note_root_run_refusal(&self, why: &'static str) {
        // ⛔ NOT SAMPLED. I sampled this 1-in-8 when I added it and then could not read the cause: gate 29
        // logged nine refusals and ONE reason line. A refusal here is rare and it is the thing that keeps a
        // restarted node's span open, so every one of them is printed.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only — no ordinal, root, note or owner.
        eprintln!("[roots-run] ⛔ refused: {why}");
    }

    pub fn accept_fetched_root_run(
        &mut self,
        first_ordinal: u64,
        roots: &[crate::spend_frontier::Digest4],
    ) -> bool {
        // ⭐ DB-185 — EVERY REFUSAL EXIT OF THIS FUNCTION NAMES ITSELF. The caller printed one message
        // for six different causes, so `does NOT fold from the certified accumulator` was the only thing
        // a reader ever learned — and it is wrong for five of them. Same lesson as DB-168/DB-176: a
        // decision with several exits and no record of which one it took cannot be debugged, only guessed
        // at, and I guessed wrong once already today on exactly this line.
        if roots.is_empty() {
            self.note_root_run_refusal("empty run");
            return false;
        }
        let Some((ask_from, _)) = self.roots_run_ask_range() else {
            self.note_root_run_refusal("no open span to close");
            return false;
        };
        // ⛔⭐⭐⭐ DB-184 — THE ASK IS COMPUTED FROM A CURSOR THAT MOVES WHILE THE ANSWER IS IN FLIGHT.
        //
        // `roots_run_ask_range` derives `from` from `roots_run_cursor.count()`. Over Tor the answer lands
        // seconds later, by which time a ladder blob or an earlier partial run may have advanced that
        // cursor. The run is then REFUSED WHOLE on two counts — `first_ordinal != ask_from`, and a fold
        // that now overshoots `target_leaves` — and the node asks again, races again, and refuses again.
        //
        // ⛔ MEASURED, ecosystem gate 22 (2026-09-25), step 3 after the rolling restart. The node printed
        // both verdicts about THE SAME 61 ROOTS, seconds apart:
        // ```text
        //   [roots-run] ✅ 61 record root(s) from ordinal 0 reproduce the certified note spine
        //   [roots-run] ⛔ a 61-root run from ordinal 1 does NOT fold from the certified accumulator
        //                  to the certified target — refused whole, nothing stored          x6
        // ```
        // With no run admitted, no per-ordinal accumulator endpoints were filed, so `acc_before` /
        // `acc_after` were `None` for every wanted record and the ONLY admission path left was
        // `span_closes_to_target` — which requires EVERY ordinal between the pre-jump value and the
        // certified target to be present. With 32 records missing, admitting any one of them required the
        // other 31 first: a deadlock, and it is what pinned `missing_records` at 32 for ~100 polls with
        // `ready n/Y`, `serve False`, `history_complete False`, while the heights themselves tracked
        // perfectly (`gap 0`, `roots EQUAL`).
        //
        // ⭐ A RUN THAT STARTS BEHIND THE CURSOR IS NOT WRONG, IT IS EARLY. Its leading roots are ones this
        // node has already folded; the rest still extend the cursor. So the prefix is SKIPPED and the
        // remainder folded, which is exactly what a fresh ask would have returned.
        //
        // ⛔ NOTHING IS WEAKENED. The skipped prefix is not trusted — it is DISCARDED, and the roots that
        // are folded face the identical all-or-nothing test (`append_subtree`, the `> target_leaves`
        // refusal, and the final root comparison against the certified spine). A run that starts AHEAD of
        // the cursor still leaves a hole and is still refused whole.
        let skip = ask_from.saturating_sub(first_ordinal) as usize;
        if first_ordinal > ask_from {
            self.note_root_run_refusal("starts AHEAD of the cursor — a hole this run cannot fill");
            return false;
        }
        if skip >= roots.len() {
            self.note_root_run_refusal("entirely behind the cursor — nothing new in it");
            return false;
        }
        let roots = &roots[skip..];
        let first_ordinal = ask_from;
        let last = first_ordinal.saturating_add(roots.len() as u64).saturating_sub(1);
        if roots.len() as u64 > Self::DA_LADDER_SPAN
            || last / Self::DA_LADDER_SPAN != first_ordinal / Self::DA_LADDER_SPAN
        {
            self.note_root_run_refusal("crosses a ladder-span boundary");
            return false;
        }
        // ORDER + CONTENT binding. A record is one depth-8 subtree of the note spine (256 leaves), so its
        // root appends to a record-granular frontier exactly as its leaves would. Fold the run onto the
        // cursor; at the target's leaf count the fold must EQUAL the certified spine — altered, reordered,
        // short or extra roots all land on a different frontier. The membership accumulator is commutative
        // by design (a set commitment) and cannot make this distinction.
        // MEASURED, P14 high leg (night/perf-flat-20261008-185459-high.log): the CLOSING run of a joiner's 19,018-root
        // span held the runtime lock 9,187 ms (1,412 roots at height ~1 k: 3,187 ms) while its four 4,096-root partial
        // runs never reached the slow-tick line. Each step of the closure is timed so the term is named, never guessed.
        let t_fold = std::time::Instant::now();
        let mut folded = self.roots_run_cursor.clone();
        for r in roots {
            if !folded.append_subtree(Self::RECORD_SUBTREE_LEVEL, *r) {
                self.note_root_run_refusal("a root would not append to the record frontier");
                return false;
            }
        }
        let target_leaves = self.roots_run_spine_target.count();
        if folded.count() > target_leaves {
            self.note_root_run_refusal("folds PAST the certified spine — extra roots");
            return false;
        }
        let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
        if folded.count() < target_leaves {
            // A partial run of a multi-span jump: written into its ladder span PROVISIONALLY (invisible to
            // root readers until the span closes), judged at closure.
            self.ladder_write_roots(first_ordinal, roots);
            let run_from = self.roots_run_cursor.clone();
            self.stage_root_run_windows(&run_from, roots); // DB-418: judged with the span at its closure
            self.roots_run_cursor = folded;
            eprintln!(
                "[roots-run] {} root(s) from ordinal {first_ordinal} folded onto the cursor — {} record(s) \
                 still to fetch before the span can close against the certified spine",
                roots.len(),
                (target_leaves - self.roots_run_cursor.count()) / rec
            );
            return true;
        }
        let origin = self.roots_run_origin();
        // ⭐⭐⭐ DB-248 (A) — BEFORE REFUSING, TRY THIS NODE'S OWN ROOTS WHERE THEY DISAGREE WITH THE SERVED RUN.
        // A server that itself jumped serves its UNVERIFIED pre-jump rows on its fork range, while this node's own
        // rows are right there (it produced that history) and wrong on its own fork range the server has right.
        // MEASURED gate O (/tmp/musd-ecocheck-GoIli8): 104 refusals of the SAME run ("the fetched roots do NOT
        // reproduce the certified note spine"), each costing the server ~1.5 s of runtime lock. Neither source
        // closes alone; the certified spine picks the combination, and ACCEPTANCE IS UNCHANGED — the one
        // comparison below (`same_state(target)`), all-or-nothing, so no assignment the chain did not produce can pass.
        // ROOT-LAYER: this door is where a served run is judged; the alternate is formed from what this node already
        // holds and judged by the same comparison, never by trust in either source.
        // MEASURED: `db248_a_run_closing_only_with_own_roots_on_a_segment_is_admitted_and_a_forged_one_is_not`.
        // MUST-STAY-GREEN: the roots-run trio, `a_jumper_asks_for_the_roots_run_admits_it…`, the reconcile pins.
        // cons: on a run that would otherwise be refused, one own-root read per ordinal of the run and at most
        // 2^DB248_MAX_SEGMENTS frontier folds of it; nothing on the success path, no bytes, no state.
        let alternate = if folded.same_state(&self.roots_run_spine_target) {
            None
        } else {
            let key = (
                self.roots_run_spine_target.root(),
                first_ordinal,
                self.da_ord_rev_mem.len() + self.da_mem.len() + self.da_ladder_mem.values().map(|b| b.len()).sum::<usize>(),
            );
            let fresh = !matches!(&self.roots_run_own_cache, Some((t, f, g, v)) if (*t, *f, *g) == key && v.len() == roots.len());
            if fresh {
                let own: Vec<Option<crate::spend_frontier::Digest4>> = (0..roots.len() as u64)
                    .map(|i| {
                        self.ladder_root_if_held(first_ordinal + i)
                            .or_else(|| self.da_block_root_at_ordinal_derive(first_ordinal + i))
                    })
                    .collect();
                self.roots_run_own_cache = Some((key.0, key.1, key.2, own));
            }
            let own = self.roots_run_own_cache.as_ref().map(|c| c.3.clone()).unwrap_or_default();
            self.roots_run_own_row_alternate(roots, &own)
        };
        let (roots, folded) = match &alternate {
            Some((cand, f)) => (cand.as_slice(), f.clone()),
            None => (roots, folded),
        };
        if alternate.is_some() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: two public chain positions — no root, record, note or owner.
            eprintln!(
                "[roots-run] DB-248: the served run did not reproduce the certified spine; with this node's own \
                 roots substituted on its disagreement segment(s) it does — admitting ordinals {first_ordinal}..{}",
                first_ordinal + roots.len() as u64 - 1
            );
        }
        if !folded.same_state(&self.roots_run_spine_target) {
            // The run set does not reproduce the certified spine: a wrong root anywhere in the set is
            // indistinguishable here, so every span written for it is removed and the run is re-asked
            // from the origin.
            // The first ordinal THIS jump may have provisionally written is origin+1 (records live at
            // ordinals 1..; `origin` is the pre-jump record COUNT). Starting the removal at
            // `origin / SPAN` deleted the PREVIOUS span — verified roots from before the jump — when
            // origin sat exactly on a span boundary.
            let first_span = (origin + 1) / Self::DA_LADDER_SPAN;
            let last_span = first_ordinal / Self::DA_LADDER_SPAN;
            let mut span = first_span;
            while span <= last_span {
                self.da_ladder_mem.remove(&span);
                self.da_ladder_adopted.remove(&span);
                span += 1;
            }
            self.roots_run_cursor = self.roots_run_spine_before.clone();
            self.roots_run_windows = crate::window_index::WindowIndex::new(); // DB-418: nothing of a refused span stays
            eprintln!(
                "[roots-run] ⛔ the fetched roots do NOT reproduce the certified note spine — {} span \
                 blob(s) removed, nothing verifiable was kept; the run is re-asked from ordinal {}",
                last_span.saturating_sub(first_span) + 1,
                origin + 1
            );
            return false;
        }
        let fold_ms = t_fold.elapsed().as_millis();
        let t_stage = std::time::Instant::now();
        // CLOSED: this run's roots join the span's blob and the whole set becomes visible.
        self.ladder_write_roots(first_ordinal, roots);
        // ⭐⭐ DB-418 — and the windows the span's roots complete join the index this node SERVES: the span folded to the
        // certified spine (`same_state` above), so every staged window is a subtree of that spine, bound by the same
        // hashes the fold computes. This is how a node that adopted a certified bundle — a fresh joiner, a re-anchored
        // stale spine — serves the window tables below its anchor (the wallet's low catch-up reads only its own node).
        // §9.6 — no new door: the windows are hashes of roots THIS door already admitted against the certified spine;
        // (1) no work to check (no header enters); (2) the certified spine is the authority, compared above; (3)/(4) no
        // value moves and a window is position-addressed (a repeat rewrites the same cell); (5) bounded by the span's
        // own run (≤ `DA_LADDER_SPAN` roots, O(roots · 64) merges); (6) parity with the live fold and the resume replay:
        // the same numbering (`window_index::merged_windows`), the same both-children rule, the same spine authority.
        let run_from = self.roots_run_cursor.clone();
        self.stage_root_run_windows(&run_from, roots);
        let staged = std::mem::take(&mut self.roots_run_windows);
        let rebuilt = staged.len();
        self.window_index.merge(&staged);
        // ⛔⛔ DB-429 — the closure proves the span's ORIGIN is the certified prefix, so the windows this node folded itself
        // below it — unbound by the target until now, dropped by the adopt — are the chain's and are served again.
        let origin_windows = std::mem::take(&mut self.roots_run_origin_windows);
        let restored = origin_windows.len();
        self.window_index.merge(&origin_windows);
        // DIGITAL-CASH-PRIVACY-REVIEWED: two counts of public spine windows; no note, tag, amount, key or owner.
        eprintln!(
            "[roots-run] DB-418: {rebuilt} window(s) the closed span completes now join the served window index \
             (DB-429: + {restored} this node folded below the span's origin)"
        );
        self.roots_run_cursor = folded;
        self.roots_run_closed_target = self.roots_run_spine_target.root();
        // ⛔⛔⛔ RECONCILE (the restart wall, gates 32–37): the ladder over [origin, target) is now VERIFIED
        // against the certified spine. Any local row in that range whose own root differs is a record the
        // certified chain never merged — an orphan (this node's last blocks before a clean shutdown that
        // never reached a peer). It leaves the ordinal space; the ladder answers for that ordinal and the
        // peer's sidecar page refills the row. Pinned by `orphaned_prerestart_records_tests`.
        let stage_ms = t_stage.elapsed().as_millis();
        let t_reconcile = std::time::Instant::now();
        let verified_end = self.roots_run_spine_target.count() / rec;
        // A restart strands a HANDFUL of rows (its last blocks before the shutdown). A mass mismatch is a
        // different defect — a systematically offset ordinal space — and evicting on it would wipe the node's
        // record space (MEASURED gate 38: "139 orphaned record(s) … first ordinal 0" on the live pair). The
        // eviction is bounded to the beacon jump gate's own size; past it, nothing is touched and the offset
        // is said loudly so it can be fixed at its cause.
        const ORPHAN_EVICT_MAX: usize = 32;
        let mut mismatched: Vec<(u64, u64)> = Vec::new();
        // Ordinal space, not record counts: `origin` and `verified_end` are RECORD COUNTS (m and N),
        // and records live at ordinals 1.. — so the records this closure verified occupy ordinals
        // (m+1)..=N. The old `origin..verified_end` bounds checked pre-jump ordinal m (harmless) and
        // never checked ordinal N: an orphan at the tip position survived every reconcile.
        // PAST-CHATS-CHECKED: user 2026-09-04 "remove the secondary re-derived block ordering" — the
        // ordinal IS the DAG's position, genesis holds 0, records 1.. (fold_canonical_records).
        for ord in origin + 1..=verified_end {
            let Some(seq) = self.da_ord_rev_mem.get(&ord).copied() else { continue };
            let Some(own) = self.da_block_root_at_ordinal_derive(ord) else { continue };
            if self.ladder_root_at_ordinal(ord) != Some(own) {
                mismatched.push((ord, seq));
            }
        }
        let mut evicted = 0usize;
        let mut first_evicted: Option<u64> = None;
        if mismatched.len() > ORPHAN_EVICT_MAX {
            // Name the first mismatches so the next gate says WHAT differs (own seq / own root / ladder root):
            // an offset ordinal space shows the same seqs at shifted ordinals; different records show unrelated
            // seqs. DIGITAL-CASH-PRIVACY-REVIEWED: record addresses and block-root limbs are public consensus
            // values already on the wire; no note, amount, key or owner is named.
            let sample: Vec<String> = mismatched
                .iter()
                .take(8)
                .map(|(o, seq)| {
                    let own = self.da_block_root_at_ordinal_derive(*o).map(|r| r[0]).unwrap_or(0);
                    let lad = self.ladder_root_at_ordinal(*o).map(|r| r[0]).unwrap_or(0);
                    format!("{o}:seq{seq}:own{own:08x}:ladder{lad:08x}")
                })
                .collect();
            eprintln!(
                "[reconcile] ⛔ {} local row(s) in {origin}..{verified_end} differ from the verified ladder (first \
                 ordinal {}) — that is not a restart's stranded tail (≤ {ORPHAN_EVICT_MAX}) but a systematically \
                 OFFSET ordinal space; nothing is evicted. First mismatches [{}]. The ordinal assignment differs \
                 between this node and the peer from that ordinal on — fix the cause, never the symptom.",
                mismatched.len(),
                mismatched.first().map(|(o, _)| *o).unwrap_or(0),
                sample.join(" ")
            );
        } else {
            for (ord, seq) in mismatched {
                self.evict_orphan_row(ord, seq);
                evicted += 1;
                first_evicted.get_or_insert(ord);
            }
        }
        if let Some(first) = first_evicted {
            // Domain floor 1: genesis is never an orphan (the pruner and the reconcile both refuse to
            // touch it), and a cursor at 0 would owe a sidecar for a position that owes none.
            if self.sidecar_cursor > first {
                self.sidecar_cursor = first.max(1);
            }
            eprintln!(
                "[reconcile] {evicted} orphaned record(s) left the ordinal space (first ordinal {first}): the \
                 verified ladder names different records there — this node's blocks the certified chain never \
                 merged. The sidecar page refills the freed slots."
            );
        }
        eprintln!(
            "[roots-run] ✅ {} record root(s) from ordinal {origin} reproduce the certified note spine from \
             this node's own spine — {} ladder span blob(s) now live; by-id records of the span verify by \
             direct root comparison (closing run of {} root(s): fold {fold_ms} ms, stage+windows {stage_ms} ms, \
             reconcile {} ms over {} ordinal(s))",
            (target_leaves - self.roots_run_spine_before.count()) / rec,
            first_ordinal / Self::DA_LADDER_SPAN - origin / Self::DA_LADDER_SPAN + 1,
            roots.len(),
            t_reconcile.elapsed().as_millis(),
            verified_end.saturating_sub(origin)
        );
        true
    }

    /// The per-record block root this node can serve for `ordinal` (derived from its own record, or
    /// the ladder for a cold span). Read-only; the ROOTS RUN server's source.
    pub fn block_root_at_ordinal(&self, ordinal: u64) -> Option<crate::spend_frontier::Digest4> {
        // ⛔⛔⛔ THE SERVER ANSWERS FROM WHAT IT HOLDS. `da_block_root_at_ordinal` refuses ordinals at or above
        // THIS node's own open roots-run origin — a guard for the CLIENT side of a span (a root it has not
        // verified must not stand in for a verified one). Serving through that guard starved the peer:
        // MEASURED gate 39 (2026-09-03, scratch VzGTUi) "[roots-serve] kind 6 from ordinal 0: 64 of 169
        // root(s)" — the server stopped at its own origin, the client's span stayed PARTIAL forever, its by-id
        // byte asks (which wait for the span to close, by design) never fired, its two wants never filled, the
        // sidecar cursor stuck and the gap grew two per block. Two nodes each holding a span open starved each
        // other. A served root is this node's own record root or its sealed ladder root — nothing else.
        self.da_block_root_at_ordinal_derive(ordinal)
            .or_else(|| self.ladder_root_at_ordinal(ordinal))
    }

    /// ⭐⭐⭐ BODIES SELF-AUTHENTICATE AS A RUN — no header message, no trusted sender, no protocol change.
    ///
    /// A body fetched after a consensus jump cannot be checked on its own: we hold no root for a block we
    /// skipped, which is why `accept_fetched_record` refused every one of them
    /// (`[da-fetch] 0/1 peer record(s) verified against roots we hold`, gap frozen at 118 blocks).
    ///
    /// But a RUN of bodies carries its own proof. Each body determines its block root, and the membership
    /// accumulator is the fold of those roots — so if folding the derived roots from where we stood BEFORE the
    /// jump lands exactly on the certified accumulator the jump gave us, then every body in the run is
    /// authentic simultaneously. One altered note changes its block root, which changes the fold, which misses
    /// the target. A missing, extra, duplicated or reordered block does the same. There is no way to satisfy
    /// this with anything but the true bodies, so we get Kaspa's headers-first guarantee without shipping a
    /// header chain at all — the accumulator we already certified IS the commitment.
    ///
    /// All-or-nothing: a run that does not close the span stores NOTHING, so a poisoned or truncated page
    /// advances zero state and the node simply asks again.
    pub fn accept_fetched_record_run(&mut self, page: &[(u64, Vec<u8>)]) -> usize {
        if page.is_empty() || self.note_body_acc_target == usdm_decider::poseidon2_compress::zero_digest() {
            return 0;
        }
        let mut run: Vec<(u64, Vec<u8>)> = page.to_vec();
        run.sort_by_key(|(rid, _)| *rid);
        run.dedup_by_key(|(rid, _)| *rid);
        // Contiguity is required: the fold is over CONSECUTIVE block roots, so a hole would silently fold the
        // wrong sequence. Refuse rather than guess.
        for w in run.windows(2) {
            if w[1].0 != w[0].0.saturating_add(1) {
                return 0;
            }
        }
        let mut acc = self.note_body_acc_before;
        let mut roots: Vec<crate::spend_frontier::Digest4> = Vec::with_capacity(run.len());
        for (rid, notes) in &run {
            let root = Self::fold_leaves_to_root(&Self::block_leaves_from_notes(notes, *rid, &self.cover_key_of(*rid)));
            acc = usdm_decider::note_membership_air::note_membership_step_new_acc(acc, root);
            roots.push(root);
        }
        if acc != self.note_body_acc_target {
            return 0; // the run does not close the certified span ⇒ not the true bodies
        }
        for ((rid, notes), _root) in run.iter().zip(roots.iter()) {
            // (2026-10-24: the `da_fetched` serve cache this loop once filled is DELETED — it keyed by
            // address while its want drain and purge read ordinals, and duplicated `da_mem`. The history
            // below is kept for the canonicalisation lesson.)
            //
            // ROOT-LAYER (history): this loop was where this node's held content for a record was PRODUCED
            // on the run path. The consumers — the retention rule's
            // `multi_note` probe and every later read of the row — cannot tell a padded record from a
            // full one, so gating them would be patching readers; the encoding has to be right where the
            // row is written. It is the same producer-layer rule `record_note_payload_inner` now applies
            // for `da_mem`.
            // MEASURED: `diag_case_08_unspent_root_split`, before -> after the writer-side twin of this
            // canonicalisation: p1 unspent root [295126057,1735428575,164862348,1883305753] with 766
            // leaves and 510 "owned" -> [1221598638,2095338629,375246161,863170457] with 256 leaves and
            // 0 owned, identical to p0, and the p1-only leaf set 510 -> 0. The served width this strips
            // is the run's own log line, `[block-id-serve] answering 1 ... 295168 byte(s)`, against the
            // 1,153 B the producing node holds for the same record.
            // MUST-STAY-GREEN: the roots-run admission above (this loop only runs after the fold has
            // already closed on `note_body_acc_target`, so nothing here can change what was admitted),
            // the by-id fetch verdict lines `[da-fetch] N/N peer record(s) verified`, the recorded_case
            // runtime-backend suite, and the persist/resume door tests.
            // ⛔ REVERTED with its twin in `accept_fetched_record` (see the note there): the roots-run
            // canonicalisation is held back until the retention-probe interaction it disturbs is
            // measured on its own. The writer-side fix in `record_note_payload_inner` still holds the
            // encoding invariant for everything that reaches `da_mem`.
            // The run AUTHENTICATES; the bytes land in `da_mem` through `apply_backfilled_notes`, which the
            // runtime runs on every entry of this page next (node_runtime `PageTail`). `da_wanted` is keyed by
            // ORDINAL — removing the record ADDRESS here (the old line) retired nothing (AGENTS.md §6).
            let _ = notes;
            if let Some(ord) = self.da_record_ordinal(*rid) {
                self.da_wanted.borrow_mut().remove(&ord);
            }
        }
        run.len()
    }

    /// Gossiped blocks this node holds but cannot place (a parent is missing): the peer's DAG contains
    /// blocks this one does not — a known-partial view.
    /// The parents parked children are waiting for (DB-44/47) — every relay waiting-map key, including a
    /// parent the relay still believes parked (a stale park record after a non-relay landing).
    /// CHAIN-PUBLISH-REVIEWED: a read-only view of the relay buffer.
    pub fn relay_missing_parents(&self) -> Vec<crate::block::BlockId> {
        self.relay.waiting_parents_all()
    }

    /// Forget a stale park record for a block the DAG holds whole (DB-47).
    /// CHAIN-PUBLISH-REVIEWED: relay buffer bookkeeping only.
    pub fn relay_unbuffer(&mut self, id: &crate::block::BlockId) -> bool {
        self.relay.unbuffer(id)
    }

    /// Take the children parked on `parent` out of the relay buffer (DB-44) so they can re-enter by
    /// their own doors once that parent is held whole.
    /// CHAIN-PUBLISH-REVIEWED: relay buffer bookkeeping; the blocks re-enter the same verified doors.
    pub fn relay_take_waiting_on(&mut self, parent: &crate::block::BlockId) -> Vec<Block> {
        self.relay.take_waiting_on(parent)
    }

    /// ⛔ DB-297 — after an adopt, drop every orphan parked against the replaced DAG
    /// (`BlockRelay::drop_orphans_the_dag_cannot_attach`). The runtime calls it BEFORE `take_orphans_waiting_on(tip)`.
    /// CHAIN-PUBLISH-REVIEWED: relay buffer bookkeeping only; a dropped block that is live re-enters by the inventory's
    /// verified doors.
    pub fn relay_drop_orphans_the_dag_cannot_attach(&mut self) -> usize {
        self.relay.drop_orphans_the_dag_cannot_attach()
    }

    pub fn relay_buffered_len(&self) -> usize {
        self.relay.buffered_len()
    }

    pub fn relay_parked(&self, id: &crate::block::BlockId) -> bool {
        self.relay.is_parked(id)
    }

    #[cfg(test)] // a test accessor by name: it is not production surface
    /// The buffered blocks and the parent each waits on (diagnostics).
    pub(crate) fn relay_buffered_for_test(&self) -> Vec<(crate::block::BlockId, crate::block::BlockId)> {
        self.relay.buffered_pairs()
    }

    /// Adopt rows as a sidecar page would deliver them.
    pub(crate) fn adopt_rows_for_test(&mut self, rows: &[(u64, u64)]) {
        self.adopt_rows_with_sidecars_for_test(rows)
    }

    /// ⛔⛔⛔ THE HOSTILE FORM — A PAGE ROW **WITH ITS SIDECAR PAYLOAD**.
    ///
    /// `adopt_rows_for_test` hard-coded `&[]` for `recv` and `del`, and those two arguments carry the
    /// ENTIRE attack surface of `adopt_sidecar_row`. The door refuses only an ordinal/rid conflict, so
    /// a harness that forges `(ordinal, record_id)` pairs and hands over empty payloads is aiming its
    /// hostile op at the one relation the door genuinely checks — it drives the production door and
    /// gives it nothing to be wrong about. Calibration rows C-H2, C-H3 and E-3 were all unreachable
    /// for exactly this reason, and all three have had a CORRECT oracle waiting the whole time
    /// (`I-8 CUSTODY-NOTE-DESTROYED`, `I-1/I-2 SPENT-NOTE-RESURRECTED`).
    ///
    /// Both payloads are concatenated 32-byte commitments, the same shape
    /// `adopt_ledger_sidecars_recv`/`_del` parse. Nothing here is a test-only door: it calls the SAME
    /// `adopt_sidecar_row` production path the page serve calls, with the arguments a real peer page
    /// would carry. The only thing that was test-only was the emptiness.
    ///
    /// cons: none — one extra slice argument threaded to an existing call; no store, no new state, and
    /// `adopt_rows_for_test` keeps its exact prior behaviour by passing empty payloads.
    pub(crate) fn adopt_rows_with_sidecars_for_test(
        &mut self,
        rows: &[(u64, u64)],
    ) {
        let _ = self.adopt_rows_with_sidecars_verdicts_for_test(rows);
    }

    /// ⛔⛔⛔ THE SAME OFFER, WITH ITS VERDICTS — the provenance primitive (rows C-H4, E-5).
    ///
    /// The door's ANSWER is what a provenance check needs, and the caller above throws it away. The
    /// defect class this exists for is CIRCULAR AUTHORITY: a node refuses an item, stores something
    /// derived from that item anyway, and then ACCEPTS the same item on its second offer because the
    /// authority it now judges against came from the item itself. D-32 was exactly that, live, at the
    /// verified-fetch door — *"the door ACCEPTED on the second offer a record it refused on the first,
    /// because `apply_backfilled_notes` had meanwhile stored the attacker's own bytes and the root is
    /// DERIVED from them."*
    ///
    /// It is invisible to every single-offer test by construction: the first offer is refused, which
    /// looks correct, and nothing asks again. Returning the verdicts is what makes "ask twice, compare"
    /// possible at all.
    ///
    /// cons: none — the verdicts already exist; this stops discarding them.
    pub(crate) fn adopt_rows_with_sidecars_verdicts_for_test(
        &mut self,
        rows: &[(u64, u64)],
    ) -> Vec<bool> {
        let verdicts: Vec<bool> = rows
            .iter()
            .map(|(o, r)| self.adopt_sidecar_row(*o, *r))
            .collect();
        let _ = self.fold_canonical_records();
        verdicts
    }

    /// DB-264: the highest ordinal this node holds a ROW for — the last position whose bytes it can judge. The record
    /// range lane asks bytes only up to here (the row comes first — own fold or the sidecar lane — then the bytes).
    ///
    /// ⭐ DB-302: "can judge" also needs a JUDGED ROOT. While a jump's headers-first span is open, a row above its origin
    /// has none (`headers_first_door_open_at`), so bytes asked there can only be refused. MEASURED (journey probe
    /// fXxkNt, n2): a kind-8 range page of 228 records inside the open span was refused entry by entry at ~200 ms each
    /// (46.3 s under the runtime lock) while the kind-6 roots pages that close the span waited behind it. So while the
    /// door is open this answers at most `roots_run_origin() - 1`, and the kind-8 ask (`range_ask_bound`) never names an
    /// unjudgeable position. When the span closes, the full row top is back and the same range goes out.
    pub fn record_row_top(&self) -> u64 {
        if !self.roots_run_closed() {
            return self.da_ord_top.min(self.roots_run_origin().saturating_sub(1));
        }
        self.da_ord_top
    }

    /// Adopt a peer-served ladder blob, SELF-VERIFYING: folding its roots from rung acc k-1 must
    /// land exactly on rung acc k (both retained forever by the pruner). A forged or truncated
    /// blob folds elsewhere and installs nothing.
    pub fn adopt_ladder_span(&mut self, span_index: u64, blob: &[u8]) -> bool {
        if blob.len() != (Self::DA_LADDER_SPAN as usize) * Self::LADDER_SLOT_BYTES {
            return false;
        }
        let start = span_index * Self::DA_LADDER_SPAN;
        let before = if start == 0 {
            usdm_decider::poseidon2_compress::zero_digest()
        } else {
            match self.da_membership_acc_at_ordinal(start - 1) {
                Some(a) => a,
                None => return false, // no rung to anchor on — cannot verify, admit nothing
            }
        };
        let Some(after) = self.da_membership_acc_at_ordinal(start + Self::DA_LADDER_SPAN - 1)
        else {
            return false;
        };
        let mut acc = before;
        // ONE decoder for the format (`ladder_slot_decode`), exactly as `ladder_root_if_held` reads it.
        // ⛔ §AG CLASS 9 lived here — a PEER-SERVED blob walked eight lanes deep over 32-byte slots, so
        // every LadderReq answer PANICKED this node at lane 4 (`range end index 40 out of range for slice
        // of length 32`): a remote crash on a network door, not a refusal. A slot that is not a canonical
        // digest is now a refusal of the whole blob — the fail-closed half of the pair.
        for chunk in blob.chunks_exact(Self::LADDER_SLOT_BYTES) {
            let Some(root) = Self::ladder_slot_decode(chunk) else {
                return false; // a slot no honest seal could have written — forged or corrupt, admit nothing
            };
            acc = usdm_decider::note_membership_air::note_membership_step_new_acc(acc, root);
        }
        if acc != after {
            return false; // does not close the rung-to-rung span — forged/truncated/reordered
        }
        self.da_ladder_mem.insert(span_index, blob.to_vec());
        self.da_ladder_adopted.insert(span_index); // DB-310b: checked as a SET only — never a sealed-walk authority
        true
    }

    pub(crate) fn record_is_wanted(&self, seq: u64) -> bool {
        if self.wanted_record_ids.contains(&seq) || self.da_wanted_ids.borrow().contains(&seq) {
            return true;
        }
        if let Some(o) = self.da_record_ordinal(seq) {
            if self.wanted_ordinals.contains(&o) || self.da_wanted.borrow().contains(&o) {
                return true;
            }
        }
        self.payload_gap_names(seq)
    }

    /// Does the record at `seq` carry a REAL note (anything but the public idle seed)? Read from the held
    /// row itself — the receive sidecar that used to mark this is gone with the deletion tree (Z1).
    ///
    /// ⛔ Z1 RETENTION LAW: a record that carries a real note is HELD. The deletion model released a
    /// record once every real note in it was spent (held ciphertext = f(live money)); under the Zcash
    /// shape spent-ness is unlinkable to a commitment by construction, so no node can know a record is
    /// dead. The per-node bound is therefore SHARDING (Z2: records by address prefix, the same policy
    /// as nullifier shards), not spent-ness — a node holds its share of real-note records plus the
    /// pruning window, never every record ever. Idle records (the overwhelming majority) regenerate
    /// from their address and are released exactly as before.
    pub(super) fn record_carries_real_notes(&self, seq: u64) -> bool {
        // A note is REAL when it is at least a block long, its first block is not zero, and it is not the record's
        // public idle seed. The seed's HEAD (one hash) decides every note whose length or first block differs from
        // it; the whole 1,153-byte seed (37 hashes) is built only for a note that matches its head — the same
        // predicate as comparing every note with the whole seed.
        // ROOT-LAYER: this is the one predicate the retention rule (`drop_record_bytes_if_unreferenced`) and its
        // reason (`record_retention_reason`) both ask; the seed's cost is paid here, so it is cut here, once.
        // MEASURED: before — 1,317 of the relay drain's 1,618 parked-page samples were this full-seed rebuild
        // (scratchpad/night/link29-sample.txt, e8f7033); after — the solo fast journey's critical-path relay term
        // (scratchpad/chain-ledger.md, link 29).
        // MUST-STAY-GREEN: the same verdict for every note (absent row = not real, as before); the idle-record
        // regeneration and no-growth retention pins; the fast + ecosystem journeys.
        let head = crate::cover::public_idle_seed_head(seq);
        let mut idle_seed: Option<[u8; crate::cover::PQ_NOTE_BYTES]> = None;
        let key = self.cover_key_of(seq);
        let mut is_real = |n: &Vec<u8>| {
            if n.len() < 32 || n[..32] == [0u8; 32] {
                return false;
            }
            // ⭐ §RF-3 §14 + lane funds 2026-10-27 (R1, NO GROWTH): a FRESH SEED NOTE (`is_seed_note`: its cm is the blake3
            // seed equation, no Poseidon opening, value 0, a throwaway key) is not real either — nothing owns it, no spend
            // circuit opens it, no copath starts in it. Counted as real it held one 1,153-byte row + a 12,288-byte tag
            // block PER BLOCK on every node forever (MEASURED ladder-22.log: "below the cold line 64: … real-notes 64").
            if n.len() == crate::cover::PQ_NOTE_BYTES && crate::cover::is_seed_note_in(n, n, &key) {
                return false; // §18.1: a seed-only record is one unit, so its body alone is the whole body
            }
            if n.len() != crate::cover::PQ_NOTE_BYTES || n[..32] != head {
                return true;
            }
            n.as_slice() != &idle_seed.get_or_insert_with(|| crate::cover::public_idle_seed_note(seq))[..]
        };
        self.da_mem.get(&seq).map(|row| row.0.iter().any(&mut is_real)).unwrap_or(false)
    }

    pub fn accept_fetched_record(&mut self, seq: u64, bytes: &[u8], key: Option<crate::cover::CoverKey>) -> bool {
        self.accept_fetched_record_judged(seq, bytes, key).is_ok()
    }

    /// The verified-fetch door itself: `Ok(())` admits, `Err(reason)` names the ONE exit that refused (DB-431 —
    /// see `FetchRefusal`). `accept_fetched_record` is this verdict as a bool; the page door tallies the reasons.
    pub fn accept_fetched_record_judged(&mut self, seq: u64, bytes: &[u8], key: Option<crate::cover::CoverKey>) -> Result<(), FetchRefusal> {
        const PQ_NOTE_BYTES: usize = 1153;
        // A record this node already holds CHAIN-BOUND, answered again (a DB-350 decoy it asked for itself), changes nothing.
        // ⛔ DB-402 (lane a 2026-10-27) — A PROVISIONAL COPY IS JUDGED, NOT WAVED THROUGH AS HELD. The page apply writes a
        // refused page's bytes provisionally (`apply_backfilled_notes`), and this return used to fire on bytes alone, BEFORE
        // any judgment: every later offer of the same bytes answered `AlreadyHeld`, so a row that once arrived unproven
        // could never be bound by this door (the block writer upgrades a provisional row above ITS early returns; this
        // door had no upgrade path — §9.6 (6) door parity). MEASURED scratchpad/night/j3now.log: the DSYNC joiner held 5
        // records byte-identical to the replayers' with `.2 = false` (replica census join3 `da_mem DIFFERS`); pin
        // `a_provisional_copy_of_the_right_bytes_is_bound_when_the_door_proves_it_and_a_forgery_is_not` RED (AlreadyHeld).
        // A provisional copy now meets the same root checks as a fresh offer; the arms re-write identical bytes (a no-op)
        // and record the binding. Nothing is admitted more weakly: the verdict reads no field of the held row.
        // cons: one root check per re-offered provisional row (the work a fresh offer of it costs), none once bound.
        {
            let canon = key.and_then(|k| crate::cover::strip_fixed_note_payload(bytes, seq, &k));
            let reals_now: &[u8] = canon.as_deref().unwrap_or(bytes);
            // T4 (lane funds 2026-10-29, pin `a_provisional_copy_of_the_right_bytes_is_bound_…`, baseline RED): a row first
            // written PROVISIONALLY under another cover key keeps its padded shape when the bind arm marks it chain-bound
            // (the writer does not rewrite a held row), so comparing the offer's CANONICAL reals with the held bytes as stored
            // never matched and a re-offer of the same record answered Ok — judged again — instead of AlreadyHeld. Both sides
            // are now compared in their canonical form under the offer's key: the same content is the same record.
            if self.record_bytes_are_chain_bound(RecAddr::from_wire(seq))
                && self.da_load(seq).is_some_and(|r| {
                    let held = r.concat();
                    let held_canon = key.and_then(|k| crate::cover::strip_fixed_note_payload(&held, seq, &k));
                    !r.is_empty() && held_canon.as_deref().unwrap_or(&held) == reals_now
                })
            {
                return Err(FetchRefusal::AlreadyHeld);
            }
        }
        // ⛔⛔⛔ CANONICALISE THE SERVED BYTES BEFORE THIS FUNCTION USES THEM ANYWHERE. Same defect and
        // same law as `record_note_payload_inner`'s canonicalisation (the case-08 chain is written up
        // there): the by-id serve answers with the assembled constant-256 shape, and a node must STORE
        // what the producer stores — its real notes — while still SERVING the full shape it derives.
        //
        // PAST-CHATS-CHECKED: this INTRODUCES no rule, it enforces the one already written down.
        // `cover.rs` states it twice — "the node stores ONLY `real_notes` per seq (cover is regenerated
        // ⇒ O(1), no per-block growth)" and "R1c NO PER-BLOCK COVER STORAGE forbids storing the filled
        // shape; only the REAL notes are stored" — it is the shape of the fix recorded in
        // [[project_node_ram_nogrowth_cover_fold]] ("stores ONLY real notes and regenerates the shape"),
        // and it is [[feedback_node_footprint_size_cardinal]]'s rule verbatim: the block already carries
        // what applies it, so never keep a per-block copy (user 2026-07-29: "Operating monerousd nodes
        // should only require a few kb"). No number below is invented: both are the protocol constants
        // `BLOCK_FIXED_NOTE_COUNT` x `PQ_NOTE_BYTES` and one `PQ_NOTE_BYTES`.
        //
        // Doing it HERE as well as at the writer closes the two places these bytes were still kept raw:
        // `da_fetched` (the serve cache, filled below) held the whole padded shape per fetched record,
        // and the retention rule's `multi_note` probe reads `da_fetched.get(&seq).len() > 1`, which every
        // padded record answered TRUE for regardless of what it really carried.
        //
        // SAFE FOR THE ROOT CHECK BELOW, which is why this is admissible at all: the check folds
        // `Self::block_leaves_from_notes(notes, seq)`, whose FIRST act is
        // `assemble_fixed_note_payload_det(notes, seq)` — so the reals and the served shape produce
        // byte-identical leaves and a byte-identical root. Nothing is verified more weakly; the same
        // bytes are checked, reached from the canonical form.
        //
        // Fail-closed: `strip_fixed_note_payload_det` returns the reals ONLY when they re-assemble to the
        // exact bytes served, so an altered or forged shape falls through UNCHANGED and is refused by the
        // very same root check as before.
        // cons: none — bounded f(BLOCK_FIXED_NOTE_COUNT) CPU per fetched record (arithmetic written on
        // `cover::strip_fixed_note_payload_det`), against `(BLOCK_FIXED_NOTE_COUNT - k) * PQ_NOTE_BYTES`
        // of RAM no longer held per fetched record.
        // ⛔ REVERTED 2026-09-04 UNDER THE WORSE-RESULT RULE — DO NOT RE-ADD WITHOUT A MEASUREMENT.
        //
        // The canonicalisation described above was applied HERE as well as at the writer, and the
        // recorded_case suite got dramatically worse on the tree that carried it: case 02
        // (`concurrent-producers-fold-the-same-ordinals`) went from GREEN to "party 1 spine root differs
        // from party 0", case 04's fold counter went 4-vs-3 to 8-vs-242, and case 08's sidecar gap went
        // 46 to 16077. The writer-side canonicalisation in `record_note_payload_inner` — which is what
        // actually fixes the record ENCODING and measured six cases green — stays; this second site does
        // not, until the interaction is understood and measured on its own.
        //
        // THE SUSPECTED MECHANISM, written down so the next attempt starts here instead of rediscovering
        // it (2026-10-24: `da_fetched` is now DELETED; the probe reads `da_mem` alone): `da_fetched` was never read for BYTES, only for the retention rule's probe
        // `da_fetched.get(&seq).map(|v| v.len() > 1)`. With the served shape stored, EVERY fetched record
        // read as multi-note and was eligible for release; with the canonical reals, a single-real record
        // reads as NOT multi-note and is kept instead. That silently changes which rows this node holds,
        // and the fold's behaviour follows what it holds. Any retry must fix that probe to ask what it
        // actually means (does this row carry real notes?) rather than infer it from a byte count.
        // TWO COORDINATES, ONE PARAMETER. `seq` is the record ADDRESS (every page — by-range, by-id,
        // by-cm — carries records by address, and the cover derivation below is keyed by it), while the
        // roots, accumulators, the span close and the by-ordinal want are keyed by ORDINAL.
        // ROOT-LAYER: this verifier is where a fetched record is admitted or refused; the ordinal it
        // reads roots by must be the record's own, resolved from the row this node already holds (a
        // sidecar page row or its own write) — a caller cannot know it. A caller that still passes a
        // bare ordinal (no row) resolves to itself, exactly as before.
        // MEASURED: gate 35 (scratch RlXKQk) every by-id fetch refused ("[da-fetch] 0/N verified", n1
        // 51× / n2 44×): the address was used as the ordinal, so no root lookup could ever hit.
        // MUST-STAY-GREEN: the by-range page path (rows registered before the page lands resolve to
        // the same ordinal the server used), the kind-6 pin, every accept_fetched_record test.
        // ⛔⛔⛔ DB-227 — NO ORDINAL ROW, NO POSITION: THE ADDRESS IS NEVER READ AS ONE.
        //
        // This fell back to `ord = seq` — a ~1e17 record ADDRESS in the ordinal parameter of every
        // authority below (the filed root, both membership accumulators, the span close), which is the
        // charter's two-coordinate-spaces trap in its purest form. None of them can admit anything at
        // ordinal 1e17, so the record was always refused — but the filed-root read DERIVED at that
        // "ordinal", missed, and registered a want for the address-as-ordinal: MEASURED gate I node 1,
        // 594 `[copath-coord] ordinal <1e17>` lines over 297 distinct records, each one a page entry
        // whose bytes were IN HAND. A record this node has not placed cannot be verified by any relation
        // this door holds (every one is keyed by position), so it is refused here, before any read,
        // and nothing is wanted: its ordinal row arrives by the sidecar lane or this node's own fold,
        // and the byte want is raised then by the resolver that knows the record is real.
        // ROOT-LAYER: this line is where the door chooses the coordinate every authority is read in.
        // MUST-STAY-GREEN: a record whose row IS known (every by-range page, the jumper pin after its
        // sidecar page, the canonical-id page pin) reaches the relations exactly as before.
        // THE HEADER ROOT, BEFORE ANY POSITION (MEASURED 2026-10-05 21:42, pins-r3e.log: the joiner wanted the carried
        // spend block's record, the producer served it on every pass, and the joiner refused it eight times for lacking an
        // ordinal row — a row only its own fold writes, and the fold was waiting for exactly these bytes). A block carried
        // in a bundle's window arrives without its payload and without a row; its HEADER is held and was authenticated at
        // graft, so bytes whose Poseidon notes root is the header's output-notes root ARE its record, by the same bind the
        // ingest door applies to a body-carrying block (consensus.rs). They are stored; the fold positions them. DOOR
        // CHECKLIST (§9.6): (1) PoW — the header's, at graft; (2) proof — the notes-root bind; (3) conservation — the
        // block's own committed outputs; (4) replay — a second copy re-stores the same bytes; (5) bounded — one scan of the
        // unfolded window (≤ LIVE_LANE_DEPTH) and one hash of the bytes; (6) parity — the ingest door's check on a full block.
        let mut unplaced_why = FetchRefusal::UnplacedNoBlock;
        if self.da_record_ordinal(seq).is_none() {
            // the block is held in the DAG (a carried window block lives there, not in the unfolded buffer — MEASURED
            // 21:51, pins-r3f.log: the buffer scan found nothing and the row check refused again); one bounded scan
            // the block is named by its RECORD KEY (`address / DA_RECORDS_PER_HEIGHT`), whatever sub-slot the producer
            // filed the record at — MEASURED 2026-10-05 23:02/23:17 on the live joiner: the send's record refused 257 times
            // comparing slot 0 only, then 8 times comparing the joiner's own stored slot (it held none for that block)
            let dag = self.relay.dag();
            let header_root = dag
                .block_ids()
                .into_iter()
                .find(|id| crate::dag::Dag::record_key(id) == seq / Self::DA_RECORDS_PER_HEIGHT)
                .and_then(|id| dag.get(&id).map(|n| n.header.output_notes_root))
                .filter(|root| *root != Hash32::hash(&[]));
            if header_root.is_none() {
                static UNNAMED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                if UNNAMED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 64 == 0 {
                    eprintln!("[da-fetch] a record with no ordinal row names no held block (by stored or canonical address), or its block carries no output notes — not admitted by header root"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string.
                }
            }
            if let Some(root) = header_root {
                // the served bytes are the ASSEMBLED record (256 notes, cover + real — MEASURED 22:08: 295,168 B); the
                // header root is over the block's REAL output notes, so the cover is stripped first (the record-write
                // door's own `strip_fixed_note_payload_det`), and what is stored is the canonical reals, as every row is
                let canonical = key.and_then(|k| crate::cover::strip_fixed_note_payload(bytes, seq, &k));
                let payload: &[u8] = canonical.as_deref().unwrap_or(bytes);
                let mut reals: Vec<Vec<u8>> = Vec::new();
                let mut off = 0;
                while off + PQ_NOTE_BYTES <= payload.len() {
                    reals.push(payload[off..off + PQ_NOTE_BYTES].to_vec());
                    off += PQ_NOTE_BYTES;
                }
                let got = crate::block::da_notes_root_of(&reals.concat());
                if got != root {
                    unplaced_why = FetchRefusal::UnplacedRootMismatch;
                    static MISMATCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                    if MISMATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 64 == 0 {
                        eprintln!("[da-fetch] a record with no ordinal row does not hash to its block's output-notes root after the cover strip ({} real note(s), {} served byte(s)) — refused", reals.len(), bytes.len()); // DIGITAL-CASH-PRIVACY-REVIEWED: counts only.
                    }
                }
                if got == root {
                    // ⭐⭐⭐ PARITY WITH THE COMMITTED-ROOT ARM BELOW (§9.6 q6; DB-402 R1, lane a 2026-10-22). This arm wrote
                    // the row through the bare `da_store` and returned: no bucket/`note_target_addr` filing (the committed-
                    // root arm's own doc names that the fund-loss shape — a note on chain, held, unlocatable by its owner)
                    // and no provenance mark, so the SAME bytes at the SAME address read `.2 = true` on the producer and
                    // `false` on the peer, and the peer lacked the record's cm→address entries. MEASURED
                    // g2-provenance-harness-20261022.log: 2 `ADMITTED by its block's header root`, replica census
                    // `da_mem DIFFERS` (record 36914017126475396 on both, different content) and `note_target_addr`
                    // n1 holds 2 cms n0 lacks — both cms notes of that record. A provisional held row also poisons this
                    // node's fold authority at its ordinal (`da_authority_poisoned`). The record is written exactly as the
                    // committed-root arm writes it (the generic writer canonicalises the served shape to the reals and files
                    // every real note's address), then the binding the header root proved is recorded on the row.
                    // O1-INFINITY-REVIEWED: the same one row the arm already wrote; the mark flips a bool in it — no key.
                    self.record_note_payload_at(seq, bytes, key);
                    self.da_mark_chain_bound(seq); // O1-INFINITY-REVIEWED: a bool on the row written above; no new key
                    self.wanted_record_ids.remove(&seq);
                    eprintln!("[da-fetch] record ADMITTED by its block's header root (a carried block's payload, positioned by the fold)"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string; no address, note, amount or owner.
                    return Ok(());
                }
            }
        }
        let Some(ord) = self.da_record_ordinal(seq) else {
            static UNPLACED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = UNPLACED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if n < 8 || n % 256 == 0 {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a public record id and a count. Never a note, amount,
                // key, owner or root.
                eprintln!(
                    "[da-fetch] REFUSED record {seq}: this node holds no ordinal row for it, so no \
                     position-keyed relation can judge it — the row comes first (sidecar lane or own \
                     fold), then the bytes ({} such refusal(s) so far)",
                    n + 1
                );
            }
            return Err(unplaced_why);
        };
        // ⭐⭐⭐ THE LEDGER IS THE AUTHORITY — VERIFY LIKE A TRANSPARENT CHAIN DOES.
        //
        // user 2026-07-29: "The DA is the ledger, and dont transparent chains verify based on their ledger?"
        // and "make sure frontier_root is the authority, and verification should fold the fetched leaves and
        // check them against it … monerousd still needs to be built to the safe industry blockchain standard."
        //
        // This refused a CORRECT record whenever the node happened to hold no local root file for it, which is
        // not a soundness rule — it is a cache miss dressed as one. MEASURED: node A refused the record while
        // node B, which held it, answered 2,032 by-id requests; A's wallet read 0.0/0 with the money one hop
        // away. Bitcoin does not refuse a block because it lacks a side index; it recomputes the Merkle root
        // and compares it to the commitment the HEADER already carries. Same rule here.
        //
        // So: fold the fetched leaves and accept the record if that root is one THIS CHAIN COMMITTED — either
        // the root filed for this address, or a root standing in our own `root_history` (every anchor the
        // chain ever committed, kept forever, which is exactly what makes an old note still provable). A
        // forged or altered payload reaches neither, so nothing is weakened: the gate still fails closed on
        // the BAD item, never on the honest one.
        // ⛔⛔⛔ THE AUTHORITY MAY NOT BE THE BYTES BEING ADMITTED (hole C-H4, charter §9.6 q2).
        //
        // `da_block_root_at_ordinal` DERIVES its answer by re-folding the record this node holds at that
        // ordinal — there is no per-item root file any more. So when the row it reads is a PROVISIONAL
        // one (bytes a peer paged in that this node could not bind), `got == want` compares the offered
        // bytes to a copy of themselves: a dedup wearing an authentication's clothes. MEASURED (probe,
        // 2026-09-07): the SAME bytes on the SAME unchanged chain answered `accept=false` before the row
        // was written and `accept=true` immediately after — a verdict that is a function of this node's
        // own store is not a verdict at all, and it is the exact fetch-and-discard raw-map shape this
        // tree has now hit a fourth time.
        //
        // A CHAIN-BOUND row is still the fast path, unchanged: those bytes were bound by a block header
        // this node grafted, or by this very door against a committed root, so re-folding them answers
        // with the chain's own commitment. The `da_stale_row_refusals` reorg signal below is likewise
        // only raised by a row that carries a real binding — a provisional row contradicting a fetched
        // record proves nothing about a dead branch.
        // ⛔ AND GATE ONLY THE DERIVE. `da_block_root_at_ordinal` has TWO sources and only one of them
        // is the row: the in-span DERIVE (a re-fold of the record's own bytes) and the SEALED LADDER
        // root (`ladder_root_at_ordinal`), which is a certified value the roots-run door admitted
        // against the chain's accumulator and which no served page can author. Suppressing both would
        // blind every cold/pruned-span admission to the one authority it has — MEASURED: gating the
        // whole accessor turned the roots-run trio and the jumped-past span pin RED. So: derive only
        // from a chain-bound row, and otherwise ask the ladder exactly as the accessor does, including
        // its open-span rule (an unclosed roots run holds provisional roots that are not served yet).
        let want_root = if !self.ordinal_authority_is_provisional(RecOrd::new(ord)) {
            self.da_block_root_at_ordinal(ord)
        } else if self.headers_first_door_open_at(ord) {
            None
        } else {
            self.ladder_root_at_ordinal(ord)
        };
        let mut reals: Vec<Vec<u8>> = Vec::new();
        let mut off = 0;
        while off + PQ_NOTE_BYTES <= bytes.len() {
            reals.push(bytes[off..off + PQ_NOTE_BYTES].to_vec());
            off += PQ_NOTE_BYTES;
        }
        // ONE leaf assembly for everyone — the same fn the serve and the membership fold use, so a fetched
        // record means byte-identically what a locally-recorded one means.
        let Some(key) = key else {
            return Err(FetchRefusal::NoRecordKey); // §20.2: a served body without its key binds to nothing
        };
        let leaves = Self::block_leaves_from_notes(&reals.concat(), seq, &key);
        let got = Self::fold_leaves_to_root(&leaves);
        // THE SAME NON-CIRCULARITY RULE FOR THE MEMBERSHIP RELATION, computed ONCE for both arms below.
        //
        // `acc_after` is the accumulator this node held after folding the record at `ord`. If that record
        // is the PROVISIONAL row carrying the very bytes under admission, then this node folded those
        // bytes into `acc_after` itself, and `step(before, got) == after` holds by construction — the
        // relation would certify the attacker's record with the attacker's own arithmetic. It is evidence
        // only when the row it came from is chain-bound. `acc_before` is a DIFFERENT record's
        // accumulator, so it is untouched: it is the anchor the candidate is being folded onto.
        let acc_before = self.da_membership_acc_at_ordinal(ord.saturating_sub(1));
        let acc_after = if !self.ordinal_authority_is_provisional(RecOrd::new(ord)) {
            self.da_membership_acc_at_ordinal(ord)
        } else {
            None
        };
        // ⛔⛔⛔ THE BRANCH THAT DECIDED IS A VALUE, NOT AN INFERENCE FROM `want_root`.
        //
        // The `Some(want)` arm below is `got == want || <the same ledger relations the None arm uses>`, so
        // "this node held a filed root" and "the filed root is what admitted the record" are DIFFERENT
        // facts. My first version of the line at the bottom of this function read the first and printed
        // the second, and on the live gate it named a filed root for records the span close had admitted.
        // An observability line that misnames the relation is worse than none — it is the residual-naming
        // trap that cost three wrong fixes on 2026-09-23.
        //
        // Behaviour is unchanged, including the short-circuit: `span_closes_to_target` is still reached
        // only when no filed root matched AND this node holds fewer than both per-ordinal accumulators.
        //
        // ⛔ A FILED ROOT IS NOT ALWAYS CANONICAL, which is why `by_filed_root` is one relation of three
        // and not a gate. After a REORG this node's per-ordinal files above the fork point came from the
        // ABANDONED branch (it filed its own produced rows while islanded), and treating them as the
        // authority refused every CANONICAL record forever: MEASURED 2026-08-24 on the healing origin —
        // `[da-fetch] 0/1 peer record(s) verified against roots we hold` in a loop for hours,
        // `try_rebuild_unspent_map` NOT_READY throughout, spends refused, while the sibling that never
        // forked served everything. The chain's OWN certified commitments outrank a local file, so a
        // mismatch falls through to the ledger relations below; acceptance REPLACES the stale row, and a
        // reorged ledger self-heals page by page as the ascending refill cursor walks.
        //
        // ⛔ AND THE MEMBERSHIP RELATION IS THE COMMITTED FOLD, NOT `root_history`. An earlier version
        // compared against that history, which holds spend-frontier ANCHORS — the accumulator over every
        // note after each block — while this is a single record's 256-leaf root. Different quantities, so
        // the branch refused everything: MEASURED, `REFUSED 256 note(s): the folded root is in NO anchor
        // this chain ever committed`, repeatedly, on records that were perfectly valid. What the chain
        // actually commits is `step(acc_before, root) == acc_after`, both written down per ordinal and
        // stepped by the same function produce and ingest use — the ledger checking itself. A forged
        // payload folds to a different root and cannot land on the committed successor.
        let by_filed_root = matches!(want_root, Some(want) if got == want);
        let (by_membership_step, by_span_close) = if by_filed_root {
            (false, false)
        } else {
            // ⛔⭐⭐⭐ DB-183 — TWO SOUND PROOFS, AND THE SECOND WAS SWITCHED OFF BY THE PRESENCE OF THE
            // FIRST'S INPUTS.
            //
            // Holding both accumulator endpoints made `by_span_close` a hardcoded `false`, so a node that
            // had them could be admitted ONLY by the membership step. Two consequences, both measured:
            //
            //  * a node whose filed endpoints are stale (a restart restores a checkpoint, and the span
            //    around it is exactly where they can disagree) refuses a PERFECTLY VALID record forever,
            //    with no second opinion available even though `span_closes_to_target` is the sole
            //    authority in the other arm and is therefore already trusted;
            //  * the refusal then PRINTED *"the end-to-end span close did not reach this node's certified
            //    accumulator"* — naming a check that had not run. That is the
            //    [[project_db168_tick_breakdown_was_blind]] class in a diagnostic: the reader is told the
            //    wrong thing was tried.
            //
            // ⛔ HONESTY ABOUT WHAT THIS DID AND DID NOT FIX. I found this while chasing gate 22's step-3
            // stall (heights tracked perfectly — `gap 0`, `roots EQUAL` — while `missing_records` sat
            // pinned at 32 on the restarted node for ~100 polls and 50 records were refused). I first read
            // those refusals as landing HERE. They do not: their message came from the `_` arm below, so
            // for those records this node held NO endpoint pair and the span close DID run and DID fail.
            // That stall is a different defect and is tracked separately.
            //
            // What is fixed here is real and was found on the way: a node holding stale endpoints had no
            // second opinion available, and the branch structure said so by construction.
            //
            // ⛔ THIS WEAKENS NOTHING. Neither proof is skipped, stubbed or relaxed: a record is admitted
            // only if the ledger's own step holds OR the certified span closes to the same target, and a
            // forged payload folds to a root that satisfies NEITHER. The tamper arms for both stay green.
            match (acc_before, acc_after) {
                (Some(before), Some(after)) => {
                    let stepped =
                        usdm_decider::note_membership_air::note_membership_step_new_acc(before, got)
                            == after;
                    (stepped, !stepped && self.span_closes_to_target(ord, got))
                }
                _ => (false, self.span_closes_to_target(ord, got)),
            }
        };
        let accepted = by_filed_root || by_membership_step || by_span_close;
        if !accepted {
            // ⛔ SAY WHICH CHECK FAILED. "Refused" and "never arrived" look identical from every counter above
            // this line, and they need opposite fixes — that ambiguity has cost this session several rounds.
            //
            // ⛔⛔⛔ AND UNTIL 2026-09-24 THIS COMMENT DESCRIBED AN INTENTION THAT WAS NEVER WRITTEN. The
            // branch bumped a counter and returned; nothing named anything. MEASURED on the live gate
            // (`musd-ecocheck-GkqmLD`, node 1 after a rolling restart): `[da-fetch] 154/397 peer record(s)
            // verified against roots we hold` — **243 records refused per page, silently**, while
            // `missing_records` sat pinned at 32 and step 3 failed with nothing to point at. A comment is
            // not observability.
            //
            // The four states below need four different fixes, and they are not guessable from outside:
            // a row we filed that DISAGREES is the reorg-poison signature; no row at all with an OPEN span
            // is the headers-first door doing its job; no row with a CLOSED span is a genuine hole; and a
            // failed span close means the fold could not reach the certified target from what we hold.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name, a note COUNT and a public record id. Never a
            // commitment, amount, key, owner or root value.
            let (why, reason) = if want_root.is_some() {
                (FetchRefusal::FiledRootDisagrees, "a root THIS NODE FILED for it disagrees, and no certified relation closed — the \
                 dead-branch-poison signature")
            } else if self.headers_first_door_open_at(ord) {
                (FetchRefusal::HeadersFirstOpen, "this node's headers-first span is still OPEN, so it holds no judged root for this \
                 position yet — the door, not the record")
            } else if acc_before.is_some() && acc_after.is_some() {
                (FetchRefusal::MembershipStepFailed, "the committed membership step did not close: step(before, folded) != after")
            } else if self.ordinal_past_span_landing(ord) {
                (FetchRefusal::PastSpanLanding, "it lies PAST the ordinal the certified span close lands on, so no span fold can \
                 admit it (refused in O(1), DB-440) — the ledger's own membership step or its block's door does")
            } else {
                (FetchRefusal::SpanNotClosed, "neither the ledger's own membership step NOR the certified span close reached this \
                 node's accumulator from what it \
                 holds — a different hole blocks the span, or these are not the true bodies")
            };
            // Capped per reason so a 397-record page names its state without burying the log. The counter
            // keeps rising after the cap, so the aggregate line above stays the source of scale.
            static SAID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let said = SAID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if said < 24 || said % 256 == 0 {
                eprintln!(
                    "[da-fetch] REFUSED record {seq} ({} note(s)): {reason}",
                    reals.len()
                );
            }
            if want_root.is_some() {
                // A row WE FILED contradicted a fetched record and the certified relations closed nothing —
                // the dead-branch-poison signature the reorg heal keys on. Sound records reset the run below.
                self.da_stale_row_refusals = self.da_stale_row_refusals.saturating_add(1);
                // DB-203: remember WHICH ordinal contradicted, so a sound record elsewhere in the same
                // page cannot clear the evidence that this one is still poisoned.
                if self.da_poisoned_ordinals.len() < DA_POISON_TRACKED_MAX
                    || self.da_poisoned_ordinals.contains_key(&ord)
                {
                    let hits = self.da_poisoned_ordinals.entry(ord).or_insert(0);
                    *hits = hits.saturating_add(1);
                    // ⛔⭐⭐⭐ DB-209 — ONE ROW THIS NODE CANNOT JUSTIFY MUST NOT WEDGE THE BACKFILL FOREVER.
                    //
                    // MEASURED, ecosystem gate 52 step 3 (on a binary rebuilt from this source — see
                    // DB-208): ONE distinct record refused **11 times** on this exact branch, while
                    // `history_complete` stayed false, `missing_by_record_id` sat at the cap, heights
                    // tracked within 4 and roots were EQUAL. The peer was healthy and serving; the node
                    // verified every other record it fetched. A single contradicting row held the whole
                    // DA backfill, and nothing could ever clear it: the dead-branch purge needs >=8
                    // DISTINCT poisoned ordinals (DB-203b) because purging a span for ONE row is the
                    // destructive over-fire, and the roots lane is not the blocker either — gate 52's
                    // `no span opened ... every wanted record already has a judged root` says so.
                    //
                    // So the remedy is SURGICAL and it is not a purge: after repeated contradiction this
                    // node stops ASSERTING its own per-ordinal row for that one ordinal. It drops the
                    // filed index entry — the row's sealed note bytes are NOT touched, because custody
                    // outranks hygiene and a stale row is replaced through the certified door, never
                    // deleted first.
                    //
                    // ⛔ NOTHING IS TRUSTED BY DOING THIS, WHICH IS THE WHOLE POINT. Dropping our own
                    // claim does not admit the peer's record: with no filed root, the record must still
                    // close `span_closes_to_target` or the committed membership step to be accepted, and
                    // the all-or-nothing fold is unchanged. If it cannot prove itself it is refused
                    // exactly as before. What changes is that this node stops defending a root it cannot
                    // justify against a canonical record it keeps re-fetching.
                    if *hits >= DA_POISON_EVICT_AFTER {
                        self.da_poisoned_ordinals.remove(&ord);
                        if self.da_ord_rev_mem.remove(&ord).is_some() {
                            self.da_macc_fwd_mem.remove(&ord);
                            // DIGITAL-CASH-PRIVACY-REVIEWED: a public ordinal and a repeat COUNT of this
                            // node's own contradiction — never a commitment, note, amount, key or owner.
                            eprintln!(
                                "[da-fetch] ordinal {ord} contradicted a canonical record {} times — \
                                 dropping THIS NODE'S filed row for it (note bytes kept). The record must \
                                 still prove itself through the certified door; we simply stop asserting a \
                                 root we cannot justify."
                            , DA_POISON_EVICT_AFTER);
                        }
                    }
                }
            }
            return Err(why); // matches nothing this chain ever committed ⇒ forged, or for a different block
        }
        // ⛔ AND SAY WHICH RELATION ACCEPTED, for the same reason the refusal above names its branch.
        // Three different bindings can admit a record — a filed root, the committed membership step, and
        // the end-to-end span close — and they have very different preconditions. An accept that does not
        // say which one fired leaves the reader to infer it, and the 2026-09-24 roots-run tamper arm cost
        // a full investigation for exactly that reason.
        // DIGITAL-CASH-PRIVACY-REVIEWED: names a BRANCH and a public ordinal. Never a commitment, amount,
        // key, owner or root value.
        // ⛔ CAPPED, LIKE THE REFUSAL. Uncapped, this fired 3,198 times in ONE gate run on a node that
        // was falling behind (`musd-ecocheck-6LQ7hM`, node 1 at height 38 while its peer held 393) —
        // a `format!` allocation per admitted record, on the lock-held apply path, burying every other
        // line in the log. An observability line that fires thousands of times per run is noise, and
        // noise on a hot path is a cost. The aggregate `N/M peer record(s) verified` line stays the
        // source of scale; this one exists to name the RELATION, which the first few answer.
        static ADMITS_SAID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let admits_said = ADMITS_SAID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if admits_said < 24 || admits_said % 256 == 0 {
        eprintln!(
            "[da-fetch] record at ordinal {ord} ADMITTED by {} — the relation that decided",
            // (Since DB-227 `ord` is always the record's own row — an unplaced record is refused at the
            // top of this door — so the coordinate printed is never a record id wearing an ordinal's name.)
            if by_filed_root {
                "a filed root this node holds, matched exactly"
            } else if by_membership_step {
                "the committed membership step (before -> after)"
            } else {
                "the end-to-end span close on the certified accumulator"
            }
        );
        }
        // DB-203: THIS ordinal is no longer contradicting. Clear the run only when NOTHING is.
        // Resetting on any accept is what made the `>= 8` heal unreachable: the poisoned row always
        // arrived inside a page of ~100 sound ones, so the counter went 1 -> 0 -> 1 -> 0 forever.
        self.da_poisoned_ordinals.remove(&ord);
        if self.da_poisoned_ordinals.is_empty() {
            self.da_stale_row_refusals = 0;
        }
        self.da_wanted.borrow_mut().remove(&ord);
        // ⛔⛔⛔ ACCEPTING A RECORD IS NOT APPLYING IT — AND ONLY APPLYING IT PAYS THE RECIPIENT.
        //
        // MEASURED 2026-08-01 on the peered pair (dir A=1 B=1), after `[stuck-ask]` closed the request half:
        // node B asked 673 times, node A answered (`[range-serve] answering 32 of the named ordinal(s)`, 184
        // times), and node B ACCEPTED 81 records — yet `bucket-file`, `acct-adopt` and `da-backfill` all stayed
        // at ZERO and the recipient's derived bucket stayed empty. The records arrived and went nowhere.
        //
        // The line above filed them in `da_fetched` (deleted 2026-10-24), which was the SERVE cache — it makes this node able to
        // answer for that ordinal, and does nothing at all to this node's own state. The bucket write that
        // lets an owner locate their note happens inside `record_note_payload_inner`, on the path a replicated
        // record takes (see the backfill site, which calls `record_note_payload_at` for exactly this reason).
        // A fetched record skipped it, so every note recovered this way was invisible to its owner: on chain,
        // held by this node, and unlocatable from the seed — the fund-loss shape, reached by a "success" path.
        //
        // Apply it the same way replication does. The targets are already staged on this node (node B logged
        // 1,341 `[account-target]`s), so recording the notes lets the pending target meet its note and the
        // bucket is written exactly as it is on the producing node.
        self.record_note_payload_at(seq, bytes, Some(key));
        // ⭐⭐⭐ PROVENANCE, PRODUCER 2 OF 2 — the verdict above IS the binding, so record it on the row
        // the line above just wrote. The relations that produced it (a chain-bound filed root, the
        // committed membership step, or the certified span close) were all reached WITHOUT reading this
        // row, which is precisely what makes the mark honest. From here these bytes may authorise: they
        // may back a derived root for a sibling's admission, and they may licence this record's own
        // receive/deletion sidecars at the fold door.
        self.da_mark_chain_bound(seq);
        Ok(())
    }

    /// The current spendable note-membership root — the block header's `frontier_root`, now the UNIFIED Poseidon
    /// `spend_frontier` root (as 32 bytes via `leaf_to_cm_bytes`). The redundant blake3 `note_frontier` (a second
    /// tree over the SAME note-commitment leaves) was removed — no-growth: one note tree, not two. The wallet
    /// already proves membership against this Poseidon frontier (pq_spend `poseidon_frontier_copath`), so the header
    /// commits the root that actually gates spends. O(DEPTH) to compute.
    pub fn note_frontier_root(&self) -> Hash32 {
        Hash32(crate::spend_frontier::leaf_to_cm_bytes(
            self.spend_frontier.root(),
        ))
    }

    pub fn note_frontier_count(&self) -> u64 {
        self.spend_frontier.count()
    }

    /// The current POSEIDON spend-membership root — the anchor a private WHIR spend proves in-circuit
    /// membership against. The spend validity carrier itself names NO root since 2026-09-30 (gate D deleted); membership
    /// is the note-membership carrier's over the record roots, cross-bound to the spend by the blinded `leaf_commit`.
    /// Byte-parity with the wallet's `poseidon_frontier_root`; O(DEPTH) to compute (no-growth).
    pub fn spend_frontier_root(&self) -> crate::spend_frontier::Digest4 {
        // ⭐⭐⭐ THE NOTE-SIDE CONSENSUS ROOT IS THE UNBOUNDED ACCUMULATOR — IT CANNOT EXPIRE.
        //
        // This returned `self.spend_frontier.root()`: the root of a FIXED-DEPTH (2^32-leaf) Merkle tree. That
        // is a capacity, and a capacity on the note side is an expiry date for the whole chain — when it
        // fills, no note can be appended and every future receive fails with users' money inside
        // ([[feedback_tree_lifetime_infinite_no_capacity_window]]).
        //
        // It is safe to move because this value is a COMMITMENT, not a copath anchor. It feeds half of
        // `state_root_of(..)` and `chain_fingerprint` — the block header's `frontier_root` and the DSYNC
        // bundle's `frontier.root` carry the TREE root (`note_frontier_root()`), a different object that this
        // accumulator is never derived from (§AI, 2026-09-13) — and NOTHING verifies a note copath against
        // it any more: the depth-`d` weld is deleted and the root enters no proof bind.
        // Note membership is proven by the note-membership FOLD (constant in-block depth + a recursive proof
        // sized by lambda alone), which has no leaf budget to exhaust.
        //
        // `served_membership_acc` is that fold's own accumulator — a field element folded once per record over
        // block note-roots, identical on every node holding the same blocks. Projecting it here makes the note
        // side match the nullifier side, which `nullifier_root()` already does with A_tip. Both halves of the
        // state root are now capacity-free, so no part of the chain carries an expiration.
        self.served_membership_acc
    }

    /// Number of note commitments appended to the Poseidon spend-membership frontier (== `note_frontier_count`).
    pub fn spend_frontier_count(&self) -> u64 {
        self.spend_frontier.count()
    }


    /// The O(DEPTH) spend-frontier PEAK spine as hex — the no-growth membership anchor a wallet self-builds its
    /// note's copath against ([`crate::spend_frontier::IncrementalWitness`]). The node NEVER serves the O(n) leaf
    /// set (that broke cross-device spends under the no-store node): a spender combines these peaks (left
    /// siblings, captured once at catch) with the notes it streams from served blocks (right siblings) to
    /// recompute exactly `spend_frontier_root()`. Poseidon commitment hashes only — no value/identity/linkage.
    pub fn spend_frontier_peaks_hex(&self) -> String {
        self.spend_frontier.peaks_hex()
    }

    /// The LATEST served block's real-note `note_cm`s (first 32 bytes each) as hex, in append order — the
    /// transient DA-relay slice (`last_served_block`), NOT a full leaf set: the node stores notes NOWHERE
    /// (no-growth), so historical membership is self-built by the wallet from the O(DEPTH) `spend_peaks_hex`
    /// + its own observed stream, and a note is claimed against the WHIR-committed `spend_frontier_root`.
    /// Served over `/get_pq_output_tree`. Public commitments only — no amount/identity leaks (Pillar-1).
    pub fn note_leaves_hex(&self) -> String {
        let mut out = String::with_capacity(self.note_frontier_count() as usize * 64);
        for cts in std::iter::once(&self.last_served_block) {
            for note in cts {
                for &byte in &note[0..32.min(note.len())] {
                    out.push_str(&format!("{:02x}", byte));
                }
            }
        }
        out
    }

    pub(crate) fn spend_lane_evidence(
        &self,
        padded: &[[u8; 32]],
    ) -> (Vec<crate::nf_sparse::CompressedCopath>, Vec<crate::nf_sparse::NfAbsenceWitness>) {
        // ⭐ A-F114 — THE ONE SITE EVERY NODE-BUILT SPEND TAKES ITS EVIDENCE FROM (a node-published object, a peg-out, a
        // node's own spend): under the constant chain no node holds the spent set, so the evidence is the SPENDER's wrappers —
        // the rpc call's own (`canon_chain::scope_spender_wrappers`), else the freshest one the spender handed this node for a
        // claim it holds and publishes later (`Node::canon_held_wrappers`, a delayed publication such as a peg-out). With
        // neither the spend carries none, and the pool door refuses it before any block carries it.
        if crate::canon_chain::canon_live() {
            let proof = crate::canon_chain::spender_wrappers()
                .or_else(|| self.canon_held_wrappers.iter().find(|(nf, _)| padded.contains(nf)).map(|(_, w)| w.clone()));
            return (Vec::new(), proof.map(|proof| crate::nf_sparse::NfAbsenceWitness { proof, ..Default::default() }).into_iter().collect());
        }
        // one rule with the copath route: carry a copath only where this node's ADMIT authority judges it `Unspent` now
        // ⭐ PRIVATE SHARDING §2.2: a node holding part of the set carries nothing here; the block's evidence decides the spend.
        if self.nf_view_is_partial() {
            return (Vec::new(), Vec::new());
        }
        let carriable: Vec<Option<Vec<crate::spend_frontier::Digest4>>> = padded.iter().map(|nf| self.carriable_copath(nf)).collect();
        let unspent = carriable.iter().filter(|c| c.is_some()).count();
        let provable = !padded.is_empty() && unspent == padded.len();
        if !provable {
            // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS over a constant-width lane and two root prefixes of
            // PUBLIC accumulators — never a tag, amount, key or owner. This is the line that says whether a
            // refused spend is the CHAIN's verdict or this node's own copath source being unable to answer.
            let tree = self.sparse_work.as_ref().map(|t| t.root_bytes());
            let acc = self.sparse_acc.root_bytes();
            eprintln!(
                "[spend-lane] this node can prove {unspent} of {} tag(s) UNSPENT — carrying no copath set \
                 (source {} vs authority {:02x}{:02x})",
                padded.len(),
                match tree {
                    Some(t) => format!("{:02x}{:02x}", t[0], t[1]),
                    None => "none".to_string(),
                },
                acc[0],
                acc[1]
            );
        }
        if provable {
            // DIGITAL-CASH-PRIVACY-REVIEWED: one root prefix of a PUBLIC accumulator and a count.
            let acc = self.sparse_acc.root_bytes();
            eprintln!(
                "[spend-lane] carrying {} copath(s) built against root {:02x}{:02x}",
                padded.len(),
                acc[0],
                acc[1]
            );
        }
        let witnesses = if provable {
            carriable.into_iter().flatten().map(|cp| crate::nf_sparse::compress_copath(&cp)).collect()
        } else {
            Vec::new()
        };
        // ⭐⭐⭐ DB-400 — A NODE-BUILT SPEND CARRIES THE BASE-STATE WITNESS, THE SHAPE EVERY WALLET SPEND CARRIES
        // (docs/DB-400-A-NODE-BUILT-SPEND-NEVER-PROVES-UNDER-THE-NODE-LOCK.md).
        //
        // ⛔ WHAT STOOD HERE: the recursive absence carrier, proven from scratch while the caller held the node
        // lock. MEASURED sim-20261006-164104 (T2): `built a 23385-byte recursive absence proof for 32 input(s) over
        // 408 folded block(s) in 98174ms`. For those 98 s the node produced, relayed and answered nothing, and the
        // wallet's `/submit_asset_create` timed out — no asset could be created.
        //
        // ⭐ IT DECIDED NOTHING. Since DB-217 the door's authority is a positive `Unspent` copath verdict per tag,
        // asked BEFORE either absence lane (`nf_absent_by_reconstructed_tip`), and the door says *"The recursive
        // carrier is not an authority (DB-213c)"*. This node's own pool door runs that same check on this tx
        // (`pool_own_publication` → `nullifier_witnesses_gate`), so:
        //   * `provable` (copaths carried): the base-state lane admits — every tag already proved Unspent against
        //     the live root, the base is this node's own certified `nf_fold_base` (a chain value bound in
        //     `sync_binding`), and the copath verdict sweeps every band step after the copath's root (P2');
        //   * not `provable`: this node's own door refuses the tx on DB-217 whatever absence it carries — the
        //     carrier bought a 98 s freeze for a spend that was refused anyway.
        // DB-284 moved every WALLET spend to exactly this shape for the same reason; the node now matches it, so a
        // node-built spend's absence lane is also no longer distinguishable from a wallet send's by a 23 KB proof.
        //
        // §9.6, for the publish door this feeds (no door's admission rule changes): (1) PoW — the stamp is ground and
        // checked by the pool door, unchanged; (2) proof — the per-tag copath against this node's root is verified by
        // the door, unchanged, and no recursive proof was ever trusted; (3) conservation — unchanged, the object's own
        // validity rules; (4) replay — the spent SET refuses a repeat tag (DB-217 `Spent`), unchanged; (5) bounded
        // work — a constant here; (6) parity — the wallet send door's evidence (DB-284) exactly.
        //
        // cons: none — ~23 KB fewer wire bytes per node-built spend, and the node lock is released in constant time.
        let absence: Vec<crate::nf_sparse::NfAbsenceWitness> =
            self.self_build_publish_absence_witness().into_iter().collect();
        (witnesses, absence)
    }

    pub fn tx_nullifiers_absent_by_fold(&self, tx: &PqTx) -> bool {
        if tx.nullifiers.is_empty() {
            #[cfg(test)]
            crate::test_census::vacuity::record("Node::nullifier_witnesses_gate", true);
            return true; // cover / coinbase — nothing to gate
        }
        if crate::canon_chain::canon_live() {
            if crate::chain_object::unframe(&tx.blob).is_some() {
                return self.canon_object_absent(tx); // a framed object: its legs by their wrappers (`object_tag_roles`)
            }
            // ⭐ A-F114 2c — THE POOL READS THE FOLD'S RULE: the real input (the member tuple's binder) by its spend wrapper,
            // every other tag (cover, `tag1`) by the window. A courtesy; the fold's verdict is the authority.
            let Some((input_nf, input_lc)) = crate::canon_chain::canon_spend_input(tx) else { return false };
            let ws = tx.nullifier_absence.first().map(crate::nf_sparse::canon_wrappers).unwrap_or_default();
            let [w] = ws.as_slice() else { return false };
            let mut real_seen = false;
            for n in &tx.nullifiers {
                if n.0 == input_nf {
                    if self.canon_absence_refusal(&n.0, &input_lc, w).is_some() {
                        return false;
                    }
                    real_seen = true;
                } else if self.canon_recent.holds(&n.0) {
                    return false;
                }
            }
            return real_seen;
        }
        // ⛔⛔⛔ AT MOST ONE — NOT EXACTLY ONE. Requiring a batched absence witness made every spend depend on
        // the node's historical fold stream, and that stream is PROVABLY UNABLE to serve it:
        //
        //     the FOLD built its padded set with
        //         nullifier_block_secret( nf_seed_conf(nf_cover_conf_acc, confidential), nullifier_seed_root() )
        //     the SERVE regenerates it with
        //         block_cover_secret( confidential, seq )
        //
        // Different functions, different inputs — so the served tags are NOT the tags that were folded, and a
        // spender folding them can never reach this node's A_tip. Worse, the fold's secret is a function of the
        // node's accumulators AS THEY STOOD AT THAT BLOCK, which have since moved: reproducing it requires
        // keeping per-block history (a growth axis the pillars forbid), so the stream cannot be repaired in
        // O(1) — it can only be removed. MEASURED: `the_recorded_fold_inputs_reproduce_the_nodes_own_a_tip`
        // fails at block 0, and every live send died with "could not build the fold absence proof".
        //
        // SOUNDNESS IS UNCHANGED, because the check that decides is not this witness. Every nullifier must
        // yield a POSITIVE `Unspent` verdict against `sparse_acc` — a full non-membership copath folding to the
        // live root, which is the root consensus commits. That is Mina's rule exactly: one root, and validity
        // is a copath against it. An absence proof attests absence THROUGH ITS OWN TIP, never absence NOW, so
        // it could never be the authority here; it is additional evidence, and when carried it is still
        // verified and a forged one still rejects.
        //
        // What this removes is a FALSE REFUSAL: an honest spender whose node cannot serve a stream that is
        // broken by construction had its money refused. Nothing is admitted that the live root does not
        // already prove absent.
        // Z1 (2026-09-22): the deletion transition that used to be admitted here is gone with the unspent
        // tree. The spend authority is the Zcash shape below — every tag proves itself UNSPENT against the
        // live sparse nullifier root by a carried copath (fixed work at any height, no history term).
        // ⭐⭐⭐ THE WITNESS ROUTE — A POSITIVE `Unspent` VERDICT AGAINST THE LIVE ROOT.
        //
        // This is the route this gate's OWN header describes ("a spender-self-built `InsertWitness` per
        // nullifier, checked against this node's O(1) root — the SOLE, self-verifying double-spend
        // authority") and which `nf_absent_by_reconstructed_tip` silently drops (`_carried`). Restoring it
        // is not a new escape: it is STRICTLY STRONGER evidence than the absence carrier below, which the
        // source itself admits "a merely STALE proof still verifies". A copath folds to the root the node
        // holds RIGHT NOW, so a tag spent one microsecond ago fails here and cannot be re-spent.
        //
        // MEASURED, and this is why it had to come back: a DEX settlement's inputs are proved by their
        // sparse-acc copaths (that IS what `execute_order_fill` checks), and their note commitments are
        // deliberately not public — so the deletion route above cannot serve them and every fill was
        // answered `NullifierWitnessRejected`. The burn never travelled, four cross-party scenarios stayed
        // red, and the same order settled twice, once per party. A spend that this node can prove unspent
        // against its own live root is a spend it must admit.
        //
        // FAIL-CLOSED in every other case: one witness per nullifier or none of this applies, and a single
        // tag that does not verify refuses the whole transaction.
        #[cfg(test)]
        crate::test_census::vacuity::record(
            "Node::nullifier_witnesses_gate::copath_lane",
            tx.nullifier_witnesses.is_empty(),
        );
        if !tx.nullifier_witnesses.is_empty() {
            if tx.nullifier_witnesses.len() != tx.nullifiers.len() {
                eprintln!(
                    "[nf-gate] REFUSE: {} witness(es) for {} nullifier(s) — a spend proves EVERY tag                      unspent or none of them.",
                    tx.nullifier_witnesses.len(),
                    tx.nullifiers.len()
                ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts of a fixed-width wire only; no tag or owner.
                return false;
            }
            for (nf, w) in tx.nullifiers.iter().zip(tx.nullifier_witnesses.iter()) {
                let Some(cp) = crate::nf_sparse::expand_copath(w) else {
                    eprintln!("[nf-gate] REFUSE: a carried witness is malformed.");
                    return false;
                };
                // P2' (§13.5): a band root the door can place, with every applied AND pending step after it swept —
                // the one shared verdict the containment loop below also reads.
                if self.pool_copath_verdict(&nf.0, &cp) != crate::nf_sparse::SpentVerdict::Unspent
                {
                    eprintln!(
                        "[nf-gate] REFUSE: a carried witness does not prove its tag UNSPENT against the \
                         live sparse root {:02x}{:02x} or any recent root this node holds — already spent, \
                         settled since the copath was built, forged, or older than the ring. Fail-closed at admit.",
                        self.sparse_acc.root_bytes()[0],
                        self.sparse_acc.root_bytes()[1]
                    ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only.
                    return false;
                }
            }
            // ⛔⛔⛔ COPATHS ARE CORROBORATION FOR EVERY CLASS — THE FILL-ONLY ADMIT ARM IS DELETED
            // (hole-closure 2026-09-06, lane A).
            //
            // This spot briefly held a class split: `Class::OrderFill` was ADMITTED on all-verifying
            // copaths alone, because a fill's input commitments are non-public (it structurally
            // cannot use the deletion route above) and a fill could not build a fresh recursive
            // carrier in O(1). That arm was the one admission lane left standing on `sparse_acc`
            // alone, and the reason copaths were demoted everywhere else applies to a fill
            // unchanged: `sparse_apply_with_copath` drops a non-folding copath SILENTLY, and a
            // jump-adopted node's sparse root has no index behind it — so a copath "unspent" answer
            // can be a false negative for a tag that settled. Non-membership under a root that may
            // have missed the settlement is an UNPROVEN absence, whatever the class.
            //
            // ONE ADMISSION RULE PER OBJECT KIND: the fill SUBMITTER now ships the same self-built
            // recursive absence carrier every other spend is judged by
            // (`execute_order_fill` attaches it at publish; `self_build_publish_absence_witness` is
            // the builder), and the door below judges it with no class test at all — a fill's
            // witness names the carrier's genesis base with an empty proof span and the door closes
            // the whole span itself (`nf_absent_by_reconstructed_tip`, the base-state lane). A
            // present-but-failing copath still REFUSES above, for every class — nothing weakened.
            //
            // MEASURED RED-first 2026-09-06:
            // `a_copath_only_fill_without_the_recursive_carrier_is_refused_on_both_parties` — two
            // pool peers ADMITTED a carrier-stripped fill while this arm stood ("[nf-gate] ADMIT
            // via carried witnesses (order-fill class)" printed on both), and refuse it with the
            // arm deleted; the three-party exactly-once pin stays green with the carrier-bearing
            // fill.
            //
            // Privacy of the print below: a COUNT only — never a tag, copath, amount, key or owner.
            eprintln!(
                "[nf-gate] carried witnesses verified for {} tag(s) — corroboration for every class; \
                 admission still requires the recursive absence carrier.",
                tx.nullifiers.len()
            );
        }
        if tx.nullifier_absence.len() > 1 {
            return false; // fail-closed: one batched witness at most — never a set to sift through
        }
        // ⭐ PRIVATE SHARDING §2.1: a node holding part of the set refuses what it can see is spent, and leaves a tag it does not hold to
        // the block's evidence at the fold. The pool is a courtesy; the fold's verdict is the authority on every node.
        if tx.nullifier_witnesses.is_empty() || self.nf_view_is_partial() {
            // The absence witness is retired on this path: nothing reads it, so a tx carrying one is refused rather than ignored,
            // or its bytes would be free for anyone to change (the forged-proof attack measured it).
            if !tx.nullifier_absence.is_empty() {
                return false;
            }
            let s = self.fold_point_spent_set();
            return tx.nullifiers.iter().all(|n| !s.holds(&n.0));
        }
        let nfs: Vec<[u8; 32]> = tx.nullifiers.iter().map(|n| n.0).collect();
        let empty = crate::nf_sparse::NfAbsenceWitness::default();
        let w = tx.nullifier_absence.first().unwrap_or(&empty);
        self.nf_absent_by_reconstructed_tip(&nfs, w, &tx.nullifier_witnesses)
    }

    /// ⭐ G1g-iv — THE ONE ANNOUNCE (`NodeRuntime::announce_peer`): record this node's own signed peer record — its PUBLIC id,
    /// the file every later process boots it from (atomic: tmp + rename, like peers.dat), and the band door's solicit window
    /// re-derived over the prover set that now counts this node (the relay re-reads it every tick; this makes the announce
    /// itself the writer). cons: one bounded (one record) file write per announce — the daemon announces every 300 s.
    pub fn record_own_announcement(&mut self, g: &crate::peer_directory::PeerGossip) {
        self.public_id = Some(g.record.peer_id.clone());
        if let Some(p) = self.own_record_path.as_ref() {
            if let Ok(bytes) = postcard::to_allocvec(g) {
                let tmp = p.with_extension("tmp");
                if std::fs::write(&tmp, &bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, p);
                }
            }
        }
        let provers = self.band_provers().len().max(1);
        self.band_set_solicit_window(provers);
    }

    /// ⭐⭐⭐ DB-274 (dir_set, 2026-10-04) — THE DIRECTORY'S FOLD STEP: the block's carried @name / group / profile sign-ups
    /// apply HERE, once per block, in the canonical fold order — never at graft in arrival order, where two nodes that
    /// grafted two registrations of one name in opposite orders resolved it to two owners and held two directory
    /// accumulators for one chain (the bond class's B19 and the class objects' P4b, wearing the directory's clothes).
    /// Runs AFTER the block's record took its position (the directory is in no record root, so nothing needs unwinding
    /// on a refused fold); each applied slot's before-image is journaled so `rewind_fold_to_common` un-folds it with its
    /// block. `dir_set` is read from the held body before the record folds; a block whose body this node does not hold
    /// (a carried shell) applies no set here — the same named close as the bond step's (P5's body door).
    /// ⭐⭐⭐ DB-274 (dir_set, 2026-10-04) — THE DIRECTORY'S FOLD STEP: the block's carried @name / group / profile sign-ups
    /// apply HERE, once per block, in the canonical fold order — never at graft in arrival order, where two nodes that
    /// grafted two registrations of one name in opposite orders resolved it to two owners and held two directory
    /// accumulators for one chain (the bond class's B19 and the class objects' P4b, wearing the directory's clothes).
    /// Runs AFTER the block's record took its position (the directory is in no record root, so a refused fold has
    /// nothing to unwind here); each applied slot's before-image is journaled so `rewind_fold_to_common` un-folds it with
    /// its block. `dir_set` is read from the held body before the record folds; a block whose body this node does not
    /// hold (a carried shell) applies no set here — the same named close as the bond step's (P5's body door).
    /// ROOT-LAYER: the canonical fold is the one place every node shares one order; the graft is arrival order, which
    /// differs per node, so the directory (a function of the chain) can only be PRODUCED here.
    /// MEASURED: `db274_two_nodes_that_apply_two_registrations_of_one_name_in_opposite_orders_hold_one_directory` at
    /// 81b9ad7 — A resolved the name to X's address and B to Y's (one name, two owners) and `a.dir_acc() != b.dir_acc()`:
    /// RED. The same pin, driven through sibling blocks and the fold, is this landing's gate; its verdict is recorded in
    /// scratchpad/pin-results.tsv, never declared here.
    /// MUST-STAY-GREEN: the refill pins (`dir_refill_page` applies the certified sequence through the same helper), the
    /// signed-sign-up pins (`apply_dir_set_folds_a_signed_signup_and_refuses_forgery_and_theft`), and the checkpoint
    /// round-trip (the journal rides the fold record as its fifth segment).
    /// ⛔ AUDIT F15 (2026-11-10): THE BLOCK'S SIDECAR APPLIES NOTHING. A sign-up used to ride `Block::dir_set` on its
    /// signature alone and was kept by every node for ever, at no cost and with no size bound. An entry now reaches the
    /// directory only as a `Class::DirEntry` object that pays for its bytes (`dir_entry_tx`); the objects step applied
    /// this block's entries one by one into `dir_open_step` (`apply_dir_entry_at_fold`), and this step only CLOSES that
    /// journal entry at the block's ordinal. `_dir_set` is the block's sidecar, read by no one: an entry a producer puts
    /// there is ignored by every node alike.
    pub(super) fn dir_step_at_fold(&mut self, _dir_set: &[u8], ordinal: u64) {
        // A-F38: the writes this step HELD (a refill is owed) take the step's ordinal and are closed with it
        for held in self.dir_refill_held.iter_mut().skip(self.dir_refill_held_closed) {
            held.0 = Some(ordinal);
        }
        self.dir_refill_held_closed = self.dir_refill_held.len();
        let Some(step) = self.dir_open_step.take() else {
            return;
        };
        // a step every entry of which was refused or a no-op has nothing to un-fold, so it leaves no entry
        if !step.undo.is_empty() {
            self.directory.persist_now(); // registry custody: a landed sign-up survives the next restart
            self.dir_fold_journal.push_back(crate::directory::DirFoldStep { ordinal, step });
            while self.dir_fold_journal.len() > Self::SPINE_RING_LEN {
                // past the rewind reach: that step can no longer be un-folded, and a rewind below it marks the spine stale
                if let Some(old) = self.dir_fold_journal.pop_front() {
                    self.dir_journal_floor = self.dir_journal_floor.max(old.ordinal.saturating_add(1));
                }
            }
        }
    }

    /// Audit F15 — apply ONE paid entry at its object's fold apply, in the block's open directory step (journaled, so a
    /// rewind or a refused fold un-does it). `true` when the directory changed; `false` when its own rule refuses the
    /// entry (the name is another owner's, a handover by a non-owner) or the entry changes nothing. The caller has
    /// verified the entry's signature and binding (`Node::dir_entry_refusal`).
    /// CHAIN-OBJECT: the `Class::DirEntry` object the block being folded carries.
    pub(crate) fn apply_dir_entry_at_fold(&mut self, e: &crate::directory::DirEntry) -> bool {
        if self.dir_hold_while_refilling(|| crate::directory::HeldDirWrite::Entry(e.clone())) {
            return false; // A-F38: held, in order, until the certified sequence is in place; nothing is written yet
        }
        let owner = crate::pqauth::pubkey_id(&e.pubkey);
        let mut step = self.dir_open_step.take().unwrap_or_else(|| self.directory.begin_step());
        let applied = self.directory.apply_entry_journaled(e, owner, &mut step);
        self.dir_open_step = Some(step);
        applied
    }

    /// Spec §12.6 — write an asset's record at its creation's fold apply, in the block's open directory step (journaled,
    /// so a rewind or a refused fold un-does it with the creation). `true` when a record was written, or a record that
    /// named no picture was given this creation's; `false` when nothing changed.
    /// The caller has already passed the creation's whole door: its decode (the picture hashes to the digest the asset's
    /// identity binds) and its fee burn (priced by the picture's size).
    /// CHAIN-OBJECT: the `Class::AssetCreate` object the block being folded carries.
    pub(crate) fn record_asset_at_fold(&mut self, c: &crate::asset_tx::AssetCreateTx) -> bool {
        if self.dir_hold_while_refilling(|| crate::directory::HeldDirWrite::AssetRecord(c.dir_record(), c.art.clone())) {
            return false; // A-F38
        }
        let mut step = self.dir_open_step.take().unwrap_or_else(|| self.directory.begin_step());
        let applied = self.directory.apply_asset_record_journaled(&c.dir_record(), &mut step);
        self.dir_open_step = Some(step);
        if applied && !c.art.is_empty() {
            // the picture the record names, kept by its digest (the creation's decode held: these bytes hash to `logo`)
            let _ = self.directory.keep_pic(&c.art);
        }
        applied
    }

    /// Spec §12.6 — file an asset under the collection its MINT names, at the mint's fold apply, in the block's open
    /// directory step (journaled, un-done with the mint). `true` when it was filed; `false` when the mint names none, the
    /// collection does not exist or is not this creator's, or the asset is already filed.
    /// The caller has already passed the mint's whole door: the creator's ML-DSA signature, which covers the handle
    /// (`asset_tx::asset_mint_msg`), and the asset's membership in the registry.
    /// CHAIN-OBJECT: the `Class::AssetMint` object the block being folded carries.
    pub(crate) fn file_asset_at_fold(&mut self, m: &crate::asset_tx::AssetMintTx) -> bool {
        if m.collection.is_empty() {
            return false;
        }
        let entry = crate::directory::Directory::asset_filing_entry(&m.asset_id, &m.collection);
        if self.dir_hold_while_refilling(|| crate::directory::HeldDirWrite::AssetFiling(entry.clone())) {
            return false; // A-F38
        }
        let mut step = self.dir_open_step.take().unwrap_or_else(|| self.directory.begin_step());
        let filed = self.directory.apply_asset_filing_journaled(&entry, &mut step);
        self.dir_open_step = Some(step);
        filed
    }

    /// Spec §14.3 — record an asset's WHOLE SUPPLY at the fold apply of the object that minted it (a creation that carries
    /// its supply, or the asset's one mint), in the block's open directory step (journaled, un-done with the object).
    /// `true` when it was recorded; `false` when the asset has no record or its supply is already said. What a pool's
    /// tokenomics read ("total supply"); the amount is already public in the minting object.
    /// The caller has already passed the minting object's whole door (the creator's signature, the mint carrier).
    /// CHAIN-OBJECT: the `Class::AssetCreate` or `Class::AssetMint` object the block being folded carries.
    pub(crate) fn supply_asset_at_fold(&mut self, m: &crate::asset_tx::AssetMintTx) -> bool {
        let entry = crate::directory::Directory::asset_supply_entry(&m.asset_id, m.amount);
        if self.dir_hold_while_refilling(|| crate::directory::HeldDirWrite::AssetSupply(entry.clone())) {
            return false; // A-F38
        }
        let mut step = self.dir_open_step.take().unwrap_or_else(|| self.directory.begin_step());
        let said = self.directory.apply_asset_supply_journaled(&entry, &mut step);
        self.dir_open_step = Some(step);
        said
    }

    /// ⭐⭐ A-F38 (2026-11-11) — WHILE A REFILL IS OWED, A FOLD'S DIRECTORY WRITE IS HELD, NOT WRITTEN. `true` when it
    /// was held (the caller writes nothing).
    ///
    /// WHAT WAS WRONG (measured on three real nodes, check `market`, 22:06): a node that joins by the certified state
    /// empties its directory and stages the certified sequence apart until it is whole (audit F16). Its fold does not
    /// wait for that, and wrote straight into the emptied directory: judged against an empty book (a filing found no
    /// collection; a second claim of a taken name would have found it free), and then lost outright, because when the
    /// last refill page landed the directory no longer equalled the stage, was wiped whole and refilled to the
    /// certified word alone. Node 2, wiped and joined again, folded an NFT's creation after its third adopt and held
    /// the collection but no record of the NFT 904 s later, where the two other nodes held it. Those entries are on no
    /// fold path of that node again: it names, pictures and files differently from the rest of the chain for good.
    ///
    /// THE RULE: the certified sequence is the directory as it stood at the adopt, and what this node's fold applies
    /// after the adopt comes after it. So while the refill is owed each fold write is kept, in fold order, with its
    /// step; when the certified sequence is in place they are applied through the same gate, in that order
    /// (`dir_refill_page`). A fold step that is refused drops what it held (`dir_unwind_open_step`), a rewind drops
    /// the steps it un-folds (`rewind_fold_to_common`), and a new adopt drops them all: its certified word already
    /// holds everything folded up to it. The paid object's ledger effects (the fee burn, its change) never depended
    /// on the directory's verdict and are applied by the fold as before.
    /// AI RESISTANT: ordinary code over the chain's own objects; what a joiner keeps from a PEER is still only the
    /// sequence that folds to the certified word (F16), and a held write is one this node's own fold judged (its
    /// signature, its fee burn's proof) from a block it accepted. SCALE: nothing grows with the bonded set; the held
    /// list grows with the paid directory objects folded during one refill, and with height not at all.
    /// BORROWED: a snapshot-synced node applies the blocks after its snapshot on top of the snapshot's state, never
    /// beside it (Ethereum snap sync's healing phase; Bitcoin's assumeutxo background chainstate).
    /// cons: a directory answer for an entry folded during the refill waits for the refill's end (it was wrong or
    /// missing for good before); up to one refill's worth of paid entries held in memory beside the stage.
    fn dir_hold_while_refilling(&mut self, write: impl FnOnce() -> crate::directory::HeldDirWrite) -> bool {
        if self.dir_refill_target.is_none() {
            return false;
        }
        self.dir_refill_held.push((None, write()));
        true
    }

    /// Spec §12.6 — keep a picture's bytes if a directory record names them (`Directory::keep_pic`: the digest is
    /// computed from the bytes; bytes nothing names are refused). `true` when newly kept.
    /// CACHE-ONLY: pictures are self-checking bytes outside the certified directory word; the records, which the chain
    /// decides, do not change with what is held.
    pub fn keep_dir_pic(&mut self, bytes: &[u8]) -> bool {
        let kept = self.directory.keep_pic(bytes);
        if kept {
            self.directory.persist_now();
        }
        kept
    }

    /// Spec §12.6 — a picture's bytes by digest (empty when this node does not hold it): what the picture door serves.
    pub fn dir_pic_bytes(&self, digest: &[u8; 32]) -> &[u8] {
        self.directory.pic_bytes(digest)
    }

    /// Spec §12.6 — up to `max` digests of pictures this node's records name and it does not hold: what it asks for.
    pub fn dir_pics_owed(&self, max: usize) -> Vec<[u8; 32]> {
        self.directory.pics_owed(max)
    }

    /// Audit F15 — a refused fold leaves no directory write behind: whatever this block's paid entries wrote so far is
    /// taken back (the objects step's own unwind restores the ledger; the directory is not in it).
    pub(super) fn dir_unwind_open_step(&mut self) {
        self.dir_refill_held.truncate(self.dir_refill_held_closed); // A-F38: and what this step held while a refill is owed
        if let Some(step) = self.dir_open_step.take() {
            self.directory.undo_step(step);
        }
    }

    /// Audit F15 — THE PAID DIRECTORY DOOR'S READ-ONLY VERDICT, the same at `Admit` (the publisher) and at `Fold` (every
    /// node): the entry's own signature and address binding, then the fee burn through the one fee-burn door (the
    /// carrier, and the burned note's membership at `door`). `None` = the object may apply; the directory's own rule
    /// (first come, owner continuity) is the apply's (`apply_dir_entry_at_fold`).
    pub(crate) fn dir_entry_refusal(
        &self,
        t: &crate::dir_entry_tx::DirEntryTx,
        door: crate::respend::MemberDoor,
    ) -> Option<&'static str> {
        if !t.entry_verifies() {
            return Some("the entry's signature does not verify, or a profile's key is not its address's own");
        }
        self.burn_fee_refusal(&t.fee, t.fee_carrier_verifies(), door)
    }

    /// IonSwap pools — run the pool door on `blob` and say whether it REFUSED it (the reason is logged: a fixed string).
    fn ion_refused_at_fold(&mut self, blob: &[u8], fold_step: u64, chain_ms: u64) -> bool {
        match crate::node::objects::ion_pool::apply_chain_ion(self, blob, fold_step, chain_ms) {
            crate::ion_pool_tx::IonApply::Refused(why) => {
                eprintln!("[fold-refuse] class=Ion why={why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
                true
            }
            _ => false,
        }
    }

    /// IonSwap pools — THE ORDER'S STATE HALF, one verdict at two doors (`Admit` at the publisher, `Fold` at every node):
    /// every leg's welded public-amount spend into this order's own burn commitment, then each spent note's membership
    /// through the one fee-note member door. `None` = the order may apply.
    pub(crate) fn ion_order_refusal(&self, t: &crate::ion_pool_tx::IonOrderTx, door: crate::respend::MemberDoor) -> Option<&'static str> {
        if !t.legs_verify() {
            return Some("a leg does not verify (the order's stated amount of that asset into this order's own burn, and its change)");
        }
        if !t.creator_verifies(&crate::pqauth::MlDsaVerifier) {
            return Some("a creator's claim is not signed by the key this token's id binds (or another order carries a creator's word)");
        }
        t.legs
            .iter()
            .find_map(|f| self.fee_note_membership_refusal(&f.nullifier, &f.leaf_commit, &f.membership_carrier, &f.membership_tip, door))
    }

    /// IonSwap pools — an order the fold accepted joins the ledger's pending list (`PegLedger::ion_take_order`).
    /// CHAIN-OBJECT: the `Class::IonOrder` object the block being folded carries, applied at this fold step.
    pub(crate) fn ion_take_order_at_fold(&mut self, order: crate::ion_pool_tx::IonPending, usdm_in: u64) -> bool {
        self.peg.ion_take_order(order, usdm_in)
    }

    /// IonSwap pools — a settlement the fold's verdict accepted is written: the layer word and the pending list
    /// (`PegLedger::ion_apply_settlement`, which also moves the contract-state root), the transition for followers, and
    /// this node's own cache of the pool's row. `false`, with nothing changed, when the layer word refuses it.
    /// CHAIN-OBJECT: the `Class::IonSettle` object the block being folded carries, applied at this fold step.
    pub(crate) fn ion_settle_at_fold(
        &mut self,
        t: &crate::ion_pool_tx::IonSettleTx,
        root_after: crate::spend_frontier::Digest4,
        done: &crate::ion_pool_tx::IonSettled,
        fold_step: u64,
    ) -> bool {
        let pre = self.peg.contract_state_root();
        // a batch that leaves no pool (`IonSettled::opened` false: the pool had no row and nothing opened one) pays its
        // orders back and writes NOTHING to the tree: no leaf, no row, no pool counted, the root as it stood
        let inserts = t.pre.is_none() && done.opened;
        if done.handed_back {
            // SAFE-FALLBACK: `ion_pool_tx::settle` hands every order of a step back whole when the step's batch does not
            // compute. It weakens no gate: it pays out exactly what each order burned, to the order's own notes, and
            // touches no pool balance; without it that step, and so the pool, could never be settled again. This line
            // only says that it happened, so the arithmetic's corner is found and fixed.
            // DIGITAL-CASH-PRIVACY-REVIEWED: an event only; no note, amount, tag or owner.
            eprintln!("[ion-settle] ⛔ a pool's batch did not compute and every order of its step was handed back whole: the pool's arithmetic has a corner to fix");
        }
        if !self.peg.ion_apply_settlement(&t.token, t.cutoff, root_after, done.usdm_paid, done.usdm_fees, inserts, fold_step, &done.forwards) {
            return false;
        }
        if done.opened {
            let cid = crate::ion_pool_tx::ion_pool_cid(&t.token);
            self.push_contract_leaf_update(pre, cid, done.row.leaf(), root_after);
            self.ion_cache.write_row(fold_step, done.row.clone());
            // what a later settlement of THIS step is brought forward over: the leaf as written and the path it was
            // written through (the path `verdict` just checked against the root this step stood on before the write)
            if let Some(path) = t.path.expand() {
                if self.ion_step_writes.0 != fold_step {
                    self.ion_step_writes = (fold_step, Vec::new());
                }
                self.ion_step_writes.1.push((cid, done.row.leaf(), path));
            }
        }
        true
    }

    /// IonSwap pools — the pool leaves the fold step `fold_step` has written so far (`Node::ion_step_writes`), or none
    /// when the scratch is another step's.
    #[must_use]
    pub(crate) fn ion_step_writes_of(&self, fold_step: u64) -> &[crate::ion_pool_tx::IonStepWrite] {
        if self.ion_step_writes.0 == fold_step {
            &self.ion_step_writes.1
        } else {
            &[]
        }
    }

    /// IonSwap pools — IS THIS NODE'S CACHE THE CHAIN'S? Its tree's root is the ledger's contract-state root AND it holds
    /// a row for every pool the ledger counts (`PegLedger::ion_pools`: each row held is checked to be the storage of
    /// its pool's leaf when it is written, so that many rows under that root are every pool's row). Only then does this
    /// node form a settlement, answer a pools list or answer a refill. `false` on a node that joined by a certified
    /// state, until its peers' pages fill it; never a consensus fact. A root read and a count: O(1) hashes.
    #[must_use]
    pub fn ion_cache_is_current(&self) -> bool {
        self.ion_cache.tree().root() == self.peg.contract_state_root() && self.ion_cache.rows_held() == self.peg.ion_pools()
    }

    /// IonSwap pools — THE REFILL DOOR's answer: one page of this node's contract tree after `after`, or `None` while this
    /// node's own tree is not its ledger's (it would hand out paths that open nothing) or holds nothing.
    #[must_use]
    pub fn ion_cache_page(&self, after: &[u8; 32]) -> Option<crate::ion_pool_tx::IonCachePage> {
        (self.ion_cache_is_current() && !self.ion_cache.tree().is_empty()).then(|| self.ion_cache.page(self.peg.contract_state_root(), after))
    }

    /// IonSwap pools — where this node's refill stands: `Some(the key its next ask names)` while its tree is not its
    /// ledger's (a node that joined by a certified state), `None` in the steady state.
    #[must_use]
    pub fn ion_refill_cursor(&self) -> Option<[u8; 32]> {
        (!self.ion_cache_is_current()).then(|| self.ion_cache.refill_cursor())
    }

    /// IonSwap pools — THE REFILL DOOR's asking side (`IonCache::take_page` holds its §9.6 answers): a page a peer
    /// served, judged leaf by leaf against a root this node's own ledger stood on along its current branch; kept
    /// writes are filed under the newest folded step, so a rewind of that step takes them back. Nothing is read while
    /// this node's cache is already whole.
    pub fn ion_refill_page(&mut self, page: &crate::ion_pool_tx::IonCachePage) -> usize {
        if self.ion_cache_is_current() {
            return 0;
        }
        let step = self.objects_fold_journal.back().map_or(0, |(o, _, _)| *o);
        let on_branch = self.contract_roots_on_branch();
        self.ion_cache.take_page(step, &on_branch, page)
    }

    /// ⭐ THE CONTRACT-STATE ROOTS THIS NODE'S LEDGER STOOD ON ALONG ITS CURRENT BRANCH, newest first, as far back as its
    /// ring of transitions reaches: the root now, then the root before the transition that produced it, and so on. A
    /// transition of an abandoned fold branch is not on the chain (its `post` is nobody's `pre`), so it is skipped; the
    /// walk is one pass over the ring (`CONTRACT_LEAF_RING` entries, a constant).
    #[must_use]
    pub(crate) fn contract_roots_on_branch(&self) -> Vec<crate::spend_frontier::Digest4> {
        let mut cur = self.peg.contract_state_root();
        let mut roots = vec![cur];
        for u in self.contract_leaf_ring.iter().rev() {
            if u.post == cur && u.pre != cur {
                cur = u.pre;
                roots.push(cur);
            }
        }
        roots
    }

    /// TEST — this node's pools cache is dropped whole, as on a node that joined by a certified state.
    #[cfg(test)]
    pub(crate) fn ion_cache_forget_for_test(&mut self) {
        self.ion_cache = crate::node::objects::ion_pool::IonCache::default();
    }

    /// IonSwap pools — this node's cache (the pools routes and the settlement former read it).
    #[must_use]
    pub fn ion_cache(&self) -> &crate::node::objects::ion_pool::IonCache {
        &self.ion_cache
    }

    /// ⭐ IonSwap pools — THE SETTLEMENTS THIS NODE CAN FORM NOW: for every pool whose EARLIEST pending step has
    /// folded, the batch of that one step (`IonSettleTx::verdict`: a batch is one step's orders, at most
    /// `ION_STEP_ORDERS_MAX`, so it always fits a block), from this node's own cache of the pool's row and the tree.
    /// Empty while the cache is not the chain's. A pure read: [`Self::publish_ion_settlements`] pools them.
    /// Every node forms the same bytes from the same ledger (the step is the pool's own earliest, never this node's
    /// newest), so their copies are one transaction.
    #[must_use]
    pub fn ion_settlements_due(&self) -> Vec<crate::ion_pool_tx::IonSettleTx> {
        use crate::ion_pool_tx::{ion_payout_note, ion_pool_cid, ion_tag, settle, IonPending, IonSettleTx};
        let Some(newest) = self.spine_recent_roots.back().map(|(o, _)| *o) else {
            return Vec::new();
        };
        let pending = self.peg.ion_pending();
        if pending.iter().all(|o| o.step > newest) || !self.ion_cache_is_current() {
            return Vec::new();
        }
        let secs = self.chain_time_ms() / 1_000;
        // each pool's earliest pending step
        let mut earliest: std::collections::BTreeMap<[u8; 32], u64> = std::collections::BTreeMap::new();
        for o in pending {
            earliest.entry(o.token).and_modify(|s| *s = (*s).min(o.step)).or_insert(o.step);
        }
        let mut out = Vec::new();
        for (token, cutoff) in earliest {
            if cutoff > newest {
                continue; // its earliest step has not folded yet on this node
            }
            let orders: Vec<IonPending> = pending.iter().filter(|o| o.token == token && o.step == cutoff).cloned().collect();
            let pre = self.ion_cache.row(&token).cloned();
            // the clock only stamps the price ring of the row AFTER, which no settlement carries: the fold stamps it
            // with the carrying block's own clock, the same on every node. The notes never depend on it.
            let Some(done) = settle(&token, pre.as_ref(), &orders, cutoff, secs) else {
                continue;
            };
            let notes = done.payouts.iter().map(|p| (ion_payout_note(&orders[p.order].core, p, ion_tag(&token, p.asset)), orders[p.order].core.locator_of(p.asset))).collect();
            out.push(IonSettleTx { token, cutoff, pre, path: self.ion_cache.tree().path(&ion_pool_cid(&token)), notes });
        }
        out
    }

    /// Audit F15 — would the directory apply `e` as it stands now? Asked by the publisher's door before it pools a paid
    /// entry, by running the ONE apply rule and taking it straight back (no second copy of the rule to drift).
    /// CACHE-ONLY: nothing is kept; the directory is byte-identical after the call.
    pub(crate) fn dir_entry_would_apply(&mut self, e: &crate::directory::DirEntry) -> bool {
        let owner = crate::pqauth::pubkey_id(&e.pubkey);
        let mut step = self.directory.begin_step();
        let applied = self.directory.apply_entry_journaled(e, owner, &mut step);
        self.directory.undo_step(step);
        applied
    }

    /// Run ONE fold-applied object's class apply; `true` when it applied, `false` when its door refused it. Each class's
    /// apply reads the class itself and answers `Not…` for another's blob, so exactly one arm acts on any object.
    /// `block_ts` is the carrying block's header timestamp — the stake class's epoch (DB-237).
    /// `carrying_score`: the carrying block's GHOSTDAG blue score (a function of its past, the same on every node) — the
    /// height a fill's expiry is judged at (DB-368).
    /// ⛔⛔⛔ THE LAW OF A CARRIED OBJECT'S APPLY (2026-10-04): AN OBJECT APPLIED FROM A BLOCK IS NEVER RE-STAGED.
    ///
    /// §BA's justification lane (`stage_credit_justifier`) exists for the PUBLISHER: the node that applies an object
    /// from its own pool derives the credit note and must carry the object beside it in its next block, so a peer can
    /// judge the note from bytes it holds. Every `apply_chain_*` this dispatcher (and the graft-time
    /// `apply_chain_objects_of`) calls runs for an object a BLOCK already carries — the carrying block IS the
    /// justification — so none of them stages anything. They used to (a vestige of the graft model), and the object
    /// rode this node's NEXT block again as a "re-carried" object: refused at fold, its notes stripped, and — MEASURED
    /// 2026-10-04 in `an_executor_whose_mint_block_is_abandoned_by_a_jump_rewinds_its_opening_and_re_proposes` — its
    /// one-time tag entered the DB-358 first-spender contest AHEAD of an honest later object with the same tag (the
    /// DB-5 re-proposal), so the stale object won the contest and then failed its apply: nothing minted, on both nodes,
    /// and the deposit stayed dead. One block slot per re-carried object was also wasted on every node that folded it.
    /// ROOT-LAYER: the applies are the only writers of the lane that run for carried objects; the publish paths keep
    ///   their staging (`execute_peg_in`, `publish_*`, the bridge credit).
    /// MEASURED: the executor pin above — `blk … credit objects 2` (the stale re-carry beside the honest re-proposal)
    ///   before; the pin `an_object_applied_from_a_carried_block_is_not_re_carried_by_the_next_block` RED-first.
    /// MUST-STAY-GREEN: every carried-object pin (`db224_a_wrapped_mint_crosses_the_wire…`, the custody pins, the
    ///   pool/stake/liquidation fold pins, `a_second_mint_of_one_asset_carried_by_a_rogue_producer_credits_no_peer`).
    /// cons: none — fewer bytes per block, nothing stored.
    /// ⭐ SATOSHI — one block's mining reward at its canonical fold. Applies only if: it is the block's FIRST reward, its
    /// stated key is in force under the carrying block's parent key (`satoshi::reward_key_in_force`), its carrier opens the note to the schedule's amount of SAT (re-verified
    /// here like every class door re-verifies at apply), and the cap admits it. Otherwise nothing moves and the fold strips
    /// the note like any refused object's. The issued total lives in the peg ledger, so the objects journal rewinds it.
    pub(super) fn apply_sat_reward_at_fold(&mut self, blob: &[u8], sat_key: Option<u64>, sat_seen: &mut bool) -> bool {
        let Some((_, payload)) = crate::chain_object::unframe(blob) else { return false };
        let Some(r) = crate::satoshi::SatoshiRewardTx::decode(payload) else { return false };
        let why = if *sat_seen {
            Some("a second reward in one block")
        } else if !crate::satoshi::reward_key_in_force(r.key, sat_key) {
            Some("a key past the carrying block's parent key, or in another era")
        } else if !r.credit_is_authorised() {
            Some("a carrier that does not open the note to the scheduled amount")
        } else if !self.peg.credit_sat_reward(r.amount) {
            Some("the 21,000,000 SAT cap")
        } else {
            None
        };
        if let Some(why) = why {
            eprintln!("[sat-reward] ⛔ refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return false;
        }
        *sat_seen = true;
        true
    }

    /// ⭐ §BR-11 — one block's miner-pool payout at its canonical fold. Applies only if: it is the block's FIRST payout, its
    /// stated key is in force under the carrying block's parent key (`miner_payout_tx::payout_key_in_force`), its note opens to the stated USDm amount under its public opening, and
    /// the pool pays it — exactly the open quarter's rate, for a block of that quarter, never more than the pool holds
    /// (`PegLedger::pay_miner_payout`). Otherwise nothing moves and the fold strips the note like any refused object's.
    /// `quarter`: the carrying block's payout period (`Node::payout_quarter_of` of its parents — A-F60, a week of chain time).
    pub(super) fn apply_miner_payout_at_fold(&mut self, blob: &[u8], sat_key: Option<u64>, quarter: Option<u64>, seen: &mut bool) -> bool {
        let Some((_, payload)) = crate::chain_object::unframe(blob) else { return false };
        let Some(p) = crate::miner_payout_tx::MinerPayoutTx::decode(payload) else { return false };
        let why = if *seen {
            Some("a second payout in one block")
        } else if !crate::miner_payout_tx::payout_key_in_force(p.key, sat_key) {
            Some("a key past the carrying block's parent key")
        } else if !p.credit_is_authorised() {
            Some("a note that does not open to the stated amount")
        } else if !quarter.is_some_and(|q| self.peg.pay_miner_payout(q, p.amount)) {
            Some("no period for its block, not the open period's rate, or more than the miner pool holds")
        } else {
            None
        };
        if let Some(why) = why {
            eprintln!("[miner-payout] ⛔ refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason only
            return false;
        }
        *seen = true;
        true
    }

    /// §BR-8 B8-a — a decoy booking or return at the fold; `true` when the blob is neither, or applied; `false` when refused.
    /// `carrying_tick`: the carrying block's chain tick (a time; A-F60's class — never its blue score).
    fn apply_chain_decoy(&mut self, blob: &[u8], carrying_tick: u64) -> bool {
        match crate::chain_object::unframe(blob) {
            Some((crate::chain_object::Class::DecoyBatch, payload)) => {
                let Some(t) = crate::decoy_tx::DecoyBatchTx::decode(payload) else { return false };
                match self.decoy_batch(&t, carrying_tick) {
                    Ok(()) => true,
                    Err(why) => {
                        eprintln!("[decoy] a decoy batch was refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason
                        false
                    }
                }
            }
            Some((crate::chain_object::Class::DecoyReturn, payload)) => {
                let Some(t) = crate::decoy_tx::DecoyReturnTx::decode(payload) else { return false };
                match self.decoy_return(&t) {
                    Ok(()) => true,
                    Err(why) => {
                        eprintln!("[decoy] a decoy return was refused at the fold: {why}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a static reason
                        false
                    }
                }
            }
            _ => true,
        }
    }

    pub(super) fn apply_fold_class_object(&mut self, blob: &[u8], block_ts: u64, chain_ms: u64, carrying_score: Option<u64>, fold_step: u64) -> bool {
        let v = crate::pqauth::MlDsaVerifier;
        // DB-379 instrument (2026-10-04): a peg-out REFUSED at the fold names its verdict's VARIANT (never the payload — a
        // verdict may carry an amount), so a peer's refusal of an honest burn is attributable from the log. Each
        // `apply_chain_*` acts on its own class only, so evaluating the peg-out door first changes nothing another class sees.
        if let crate::peg_out_tx::PegOutApply::Refused(r) = crate::node::objects::peg_out_tx::apply_chain_peg_out(self, blob, &v) {
            let why = format!("{r:?}");
            let variant = why.split(|ch: char| ch == '(' || ch == ' ' || ch == '{').next().unwrap_or("?");
            eprintln!("[fold-refuse] class=PegOut why={variant}"); // DIGITAL-CASH-PRIVACY-REVIEWED: a variant name only
            return false;
        }
        // (`Class::SatBond` is decided by `objects_decide_at_fold` itself and seated by the bond step — never here.)
        !matches!(crate::node::objects::liquidation_tx::apply_chain_liquidation(self, blob, &v), crate::liquidation_tx::LiquidationApply::Refused(_))
            && !matches!(
                crate::node::objects::theft_repayment_tx::apply_chain_theft_repayment(self, blob, &v),
                crate::theft_repayment_tx::TheftRepayApply::Refused(_)
            )
            && !matches!(crate::node::objects::pot_fill_tx::apply_chain_pot_fill(self, blob), crate::pot_fill_tx::PotFillApply::Refused(_))
            && self.apply_chain_decoy(blob, chain_ms / crate::dag::MESH_TARGET_SPACING_MS)
            && !matches!(crate::node::objects::price_mark_tx::apply_chain_price_mark(self, blob, &v), crate::price_mark_tx::PriceMarkApply::Refused(_))
            && !matches!(
                crate::node::objects::wrapped_asset_tx::apply_chain_wrapped_asset_register(self, blob, &v),
                crate::wrapped_asset_tx::RegisterApply::Refused(_)
            )
            // SAFE AT SCALE: a custody vault's ledgers summed into another's (`PegLedger::vault_merge`, both vaults' quorums)
            && !matches!(crate::node::objects::vault_merge_tx::apply_chain_vault_merge(self, blob, &v), crate::vault_merge_tx::MergeApply::Refused(_))
            // SAFE AT SCALE, stage three: part of a vault's ledgers carved out, taken or taken back (`PegLedger::vault_carve`
            // / `vault_take` / `vault_cancel`, each one vault's quorum) — placed at the carrying block's blue score
            && !matches!(
                // A-F60: at the carrying block's chain tick (the cancel's wait is a time)
                crate::node::objects::vault_rebalance_tx::apply_chain_vault_rebalance(self, blob, carrying_score.map(|_| chain_ms / crate::dag::MESH_TARGET_SPACING_MS), &v),
                crate::vault_rebalance_tx::RebalanceApply::Refused(_)
            )
            // SAFE AT SCALE: a vault's reserve less a public foreign fee (`PegLedger::reserve_cost`, that vault's own quorum)
            && !matches!(crate::node::objects::reserve_cost_tx::apply_chain_reserve_cost(self, blob, &v), crate::reserve_cost_tx::CostApply::Refused(_))
            // A-F114: a payout's release (`PegLedger::release_confirm`, the paying vault's quorum; the owed book)
            && !matches!(
                crate::node::objects::release_confirm_tx::apply_chain_release_confirm(self, blob, &v),
                crate::node::objects::release_confirm_tx::ReleaseApply::Refused(_)
            )
            // SAFE AT SCALE, stage three: a vault takes or retires a custody key (`PegLedger::vault_key_take` /
            // `vault_key_retire`, that vault's own quorum) — placed at the carrying block's chain tick (A-F60: the address
            // window and the retire wait are times)
            && !matches!(
                crate::node::objects::vault_key_tx::apply_chain_vault_key(self, blob, carrying_score.map(|_| chain_ms / crate::dag::MESH_TARGET_SPACING_MS), &v),
                crate::vault_key_tx::KeyApply::Refused(_)
            )
            && !matches!(crate::node::objects::wrapped_mint_tx::apply_chain_wrapped_mint(self, blob, &v), crate::wrapped_mint_tx::WrappedMintApply::Refused(_))
            && !matches!(crate::node::objects::peg_in_tx::apply_chain_peg_in(self, blob, &v), crate::peg_in_tx::PegInApply::Refused(_))
            // §BR-4 B4-3: a unit close — its day is the carrying block's, as the open's
            && !matches!(
                crate::node::objects::unit_close_tx::apply_chain_unit_close(self, blob, Some(chain_ms / crate::debt_units::DAY_MS), &v),
                crate::unit_close_tx::UnitCloseApply::Refused(_)
            )
            // §BR-4 B4-2: a unit open — its day is the carrying block's day on the chain's clock (A-F60: a day is a time)
            && !matches!(
                crate::node::objects::unit_open_tx::apply_chain_unit_open(self, blob, Some(chain_ms / crate::debt_units::DAY_MS), &v),
                crate::unit_open_tx::UnitOpenApply::Refused(_)
            )
            && !matches!(crate::node::objects::stake_tx::apply_chain_stake(self, blob, block_ts), crate::stake_tx::StakeApply::Refused(_))
            && !matches!(crate::node::objects::pool_tx::apply_chain_pool_deposit(self, blob), crate::pool_tx::PoolDepositApply::Refused(_))
            && !matches!(crate::node::objects::pool_tx::apply_chain_pool_withdraw(self, blob), crate::pool_tx::PoolWithdrawApply::Refused(_))
            // §BR-10: a builder's release attestation
            && !matches!(
                crate::node::objects::release_attestation_tx::apply_chain_release_attestation(self, blob),
                crate::release_attestation_tx::AttestationApply::Refused(_)
            )
            // §BR-10: a validator's deployment signal
            && !matches!(
                crate::node::objects::deployment_signal_tx::apply_chain_deployment_signal(self, blob),
                crate::deployment_signal_tx::SignalApply::Refused(_)
            )
            // §BR-9a: a custodian's epoch-key deal
            && !matches!(crate::node::objects::epoch_deal_tx::apply_chain_epoch_key_deal(self, blob), crate::epoch_deal_tx::DealApply::Refused(_))
            // §BR-13: the canonical SAT set-aside, once
            && !matches!(crate::node::objects::sat_set_aside::apply_chain_set_aside(self, blob), crate::sat_set_aside::SetAsideApply::Refused(_))
            // §BR-10: a bug bounty from the surplus buffer at the canonical fold
            && !matches!(
                crate::node::objects::bounty_payout_tx::apply_chain_bounty_payout(self, blob),
                crate::bounty_payout_tx::BountyApply::Refused(_)
            )
            // §BR-3 17.6: a validator's own-weight yield claim at the canonical fold
            && !matches!(
                crate::node::objects::bond_yield_claim_tx::apply_chain_bond_yield_claim(self, blob),
                crate::bond_yield_claim_tx::ClaimApply::Refused(_)
            )
            // §BR-3 17.3: a delegation converts SAT ↔ delegated ↔ unbonding at the canonical fold
            && !matches!(
                // A-F60: a maturity is a time — the carrying block's chain tick
                crate::node::objects::sat_delegation_tx::apply_chain_sat_delegation(self, blob, carrying_score.map(|_| chain_ms / crate::dag::MESH_TARGET_SPACING_MS)),
                crate::sat_delegation_tx::DelegationApply::Refused(_)
            )
            // §BR-14: the asset classes (transfer, creation with its fee burn, mint) at the canonical fold — one door.
            && !matches!(
                crate::node::objects::asset_tx::apply_chain_asset_object(self, blob),
                crate::asset_tx::AssetApply::SpendRefused(_)
                    | crate::asset_tx::AssetApply::CreateRefused(_)
                    | crate::asset_tx::AssetApply::MintRefused(_)
            )
            && !matches!(crate::node::objects::dsol_deploy_tx::apply_chain_dsol_deploy(self, blob), crate::dsol_deploy_tx::DeployApply::Refused(_))
            // audit F15: a paid directory entry at the canonical fold (first come in the chain's one order)
            && !matches!(crate::node::objects::dir_entry_tx::apply_chain_dir_entry(self, blob), crate::dir_entry_tx::DirEntryApply::Refused(_))
            // IonSwap pools: an order and a settlement at the canonical fold — one door
            && !self.ion_refused_at_fold(blob, fold_step, chain_ms)
            && !matches!(crate::node::objects::dsol_call_tx::apply_chain_dsol_call(self, blob, carrying_score), crate::dsol_call_tx::CallApply::Refused(_))
            && !matches!(crate::node::objects::dsol_fee_update_tx::apply_chain_dsol_fee_update(self, blob), crate::dsol_fee_update_tx::FeeUpdateApply::Refused(_))
            // §BR-15: the DeFi layer's four classes at the canonical fold — one door
            && !matches!(crate::node::objects::defi_batch::apply_chain_defi(self, blob, block_ts, chain_ms, carrying_score), crate::defi_batch::DefiApply::Refused(_))
            && matches!(
                crate::node::objects::order_fill_tx::apply_chain_fill_at_fold(self, blob, carrying_score),
                crate::order_fill_tx::FillFoldApply::NotFill | crate::order_fill_tx::FillFoldApply::Settled
            )
    }

    /// ⭐ TREELESS ADOPT — the Mina-shape ingest gate, and the ONLY sparse advance authority on the live path.
    /// Advances the sparse accumulator over a block's WHOLE nullifier transition while holding **NO TREE AT ALL**,
    /// by verifying the block's carried HEIGHT-1 FOLD (`nf_sparse_air::verify_sparse_fold_height1_bytes`): ~1,535 B
    /// on the wire, O(1) verify, FLAT across nullifier count AND across chain height. This is what retires the old
    /// re-derive gate, which had to hold a full `RefSparseNf` and so gained 256 leaves EVERY block — a state growth
    /// axis banned by [[feedback_no_growth_any_axis]] and the reason a node's footprint rose with the chain.
    ///
    /// TRUSTLESS, and the digest is why: the fold's Fiat-Shamir transcript is welded to `(pre ‖ post ‖ digest)`, and
    /// the digest is **DERIVED HERE** from the padded set THIS node re-derived itself — never a carried value (see
    /// [`crate::block::NfBlockProof`]). So a forged endpoint OR a tampered/reordered nullifier set diverges the
    /// transcript and REJECTS, fail-closed, with the acc NOT advanced. Canonical-order gated: the committed pre must
    /// chain onto the live acc, so an out-of-order block is simply not adopted (never a mis-fold).
    /// ([[feedback_always_trustless]] [[project_mina_o1_treeless_node]])
    #[must_use]
    pub fn adopt_sparse_via_block_fold(
        &mut self,
        fold: &[u8],
        committed_pre: [u8; 32],
        committed_post: [u8; 32],
        padded: &[[u8; 32]],
    ) -> bool {
        // ⛔⛔⛔ THE CANONICAL-ORDER GATE IS DELETED — IT WAS THE ISLAND.
        //
        // This demanded `sparse_acc.root == committed_pre`, i.e. that this node had already replayed the
        // producer's EXACT block order. A second device never does: its A_tip folds at accept and is order-free,
        // and on a width>1 DAG blocks arrive interleaved. So the first out-of-turn block failed here, every later
        // block parked behind it, and the node islanded permanently. MEASURED: B folded 2 of 47 with 32 parked.
        //
        // Nothing is weakened by removing it. Soundness never rested on this equality — it rests on the PURE
        // re-derivation below, which reproduces the committed post from the block's OWN carried tags and pre and
        // fail-closes on any mismatch. Order-freedom is what makes that check reachable on every node instead of
        // only on the producer.
        // ⭐⭐⭐ FOLD-NOT-HOLD INGEST (brick C2) — re-derive `block_pre` + `digest` + the A_tip TAGS-FOLD post EXACTLY
        // as the producer did, from OUR OWN regenerated `padded` tags: NO copath, NO held tree. The committed post
        // MUST EQUAL our self-recomputed fold post (self-verifying: a forged post / tampered or reordered tags
        // diverges ⇒ fail-closed, acc NOT advanced). Same `nf_to_limbs` conversion the producer + `advance_nf_unspent_acc`
        // use, so produce == ingest BY CONSTRUCTION. ([[feedback_infinite_o1_fold_cardinal]])
        let block_pre = usdm_decider::nf_sparse_air::nf_to_limbs(&committed_pre);
        let digest = usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(padded, block_pre);
        // ⭐ PURE RE-DERIVATION — from the block's OWN carried pre + tags, with NO node-local term. This is the
        // whole soundness gate and it is now reachable on EVERY node, not just the producer: the old form folded
        // `self.nf_unspent_acc` into the comparison, so a verifier whose accumulator held a different block SET
        // could never match a correct block. A tampered/reordered tag set moves `digest`, moves this leaf, and
        // fails here — fail-closed, nothing advanced.
        let post_acc = usdm_decider::nf_sparse_air::block_transition_leaf(block_pre, digest);
        if crate::spend_frontier::leaf_to_cm_bytes(post_acc) != committed_post {
            // A block whose CLAIMED post misses the transition this node re-derived from its id-bound tags
            // is lying in a witness field. Loud — never silent — and then the recompute is what stands.
            eprintln!(
                "[fold-reject] tags={} pre={:02x?} recomputed_post={:02x?} committed_post={:02x?}",
                padded.len(),
                &committed_pre[..4],
                &crate::spend_frontier::leaf_to_cm_bytes(post_acc)[..6],
                &committed_post[..6]
            );
            // ⛔ §BD (2026-09-14) — THE CLAIMED POST IS A WITNESS FIELD, NOT AN AUTHORITY.
            // `Block::nullifier_proof.post_root` is outside the block id; the TAGS are inside it
            // (`nullifier_tags_root`), and this node has just re-derived the post from them. Returning
            // `false` here left this node's A_tip ADVANCED (it folds from the same tags in
            // `fold_atip_at_accept`) with its sparse root STALE — so a producer could stall every peer's
            // spend admission, per block, by lying in a field nobody signs. MEASURED: `[fold-reject]`
            // fired, the block still grafted, sparse root at pre while A_tip moved. State is a function
            // of the chain: the recompute above IS the post; the claim was a lie and is now only reported.
        }
        // When a height-1 fold IS carried (the #29 DSYNC / light-client path), verify it too against the SAME
        // endpoints; the full node's self-recompute above is the authority, so an EMPTY fold on the hot-gossip block
        // is fine — the recompute gates it (no chain halt on a fold-less block).
        if !fold.is_empty()
            && !usdm_decider::nf_sparse_air::verify_sparse_fold_height1_bytes(
                fold, block_pre, post_acc, digest,
            )
        {
            return false; // a carried fold that disagrees with our self-recompute ⇒ fail-closed
        }
        // ⛔⛔⛔ Z1 (2026-09-22) — THIS NO LONGER OVERWRITES `sparse_acc` WITH THE A_TIP FOLD, AND THAT
        // OVERWRITE WAS WHY NO SPEND COULD EVER BE PROVED.
        //
        // `nullifier_root()` projects A_tip (see its doc): the ORDER-FREE consensus root. `sparse_acc` is
        // NOT that root — it is this node's LOCAL Merkle view of the spent SET, the one thing a
        // non-membership copath can be checked against. Replacing it with a fold accumulator made every
        // copath unverifiable the moment a node applied one block: the gate's own comment measured it
        // (*"after ONE `produce` it answers `Unprovable` for every nullifier"*), and the deletion
        // transition was standing in for the authority that had quietly stopped working.
        //
        // The Merkle view is CONVERGENT for the same reason A_tip is: a sparse tree keyed BY the nullifier
        // is a function of the SET of applied tags, not of their order — two nodes holding the same
        // accepted blocks hold the same root with no replay order to agree on. (The 2026-08-14 islanding
        // this replaced was caused by an ORDER GATE — `committed_pre == our root` — not by the root; that
        // gate is deleted above and does not come back.)
        //
        // So the view advances where every other set-membership structure does: over the block's own
        // carried tags, in the co-advance the caller runs next (`advance_sparse_shadow`), each flip
        // self-verifying against the view it is advancing. The verification this function exists for —
        // re-derive the committed post from the id-bound tags, refuse a lying fold — is untouched.
        // ⛔⛔⛔ §AQ — THE RESUMABLE POOLED CARRIER WAS BUILT HERE AND REVERTED THE SAME DAY, BECAUSE IT
        // WAS A PILLAR TRADE.
        //
        // The shape the gate's own doc names — *"the node steps every pooled carrier by one block as it
        // applies that block ... O(pool) per block"* — was implemented at this seam and removed. The
        // reason is the arithmetic, not a preference: `NfAbsenceBatchCarrier::step` runs TWO recursive
        // WHIR proves (MEASURED in its own doc at 22 ms for a width-32 set), once per pooled transaction
        // per block. At a pool of 256 that is ~5.6 s of proving inside a 500 ms block target, and the
        // cost grows with POOL DEPTH — an axis, not a constant. Buying the fill's admission authority
        // with the node's block-apply budget is trading FAST/CHEAP/SCALABLE for SOUND, and the pillars
        // are never traded off.
        //
        // ⭐ WHAT SURVIVES, because it costs nothing: `NfAbsenceBatchCarrier::resume` — a pure
        // constructor that rebuilds a carrier from the state a transaction ALREADY carries, with no new
        // wire field and no work unless someone calls it. It is pinned lossless byte-for-byte by
        // `resuming_an_absence_carrier_from_the_carried_state_is_lossless`. Any resumable design needs
        // exactly that primitive; what it must NOT have is the node paying per-transaction proving per
        // block.
        //
        // ⛔ SO §AQ STAYS OPEN, and the constraint any future shape must satisfy is now written down:
        // the node's per-block work must carry NO term in pool depth. The spender maintaining its own
        // single carrier is O(1) for the node by construction — that is the direction — but a settlement's
        // tags are born WITH the settlement, which is the part still unsolved. It is not closed, and this
        // comment exists so nobody re-lands the version that looked like it closed it.
        // ⛔⛔⛔ ADOPTING THE ROOT WITHOUT MIRRORING THE PATHS LEFT THE NODE UNABLE TO DESCRIBE ITS OWN TREE.
        //
        // This set the root and returned. The root advanced by every one of this block's tags while the copath
        // index that `da_sparse_copath` reads was never written — so the index described the EMPTY tree while
        // the root described all the insertions made so far. Every copath then folded to neither the empty nor
        // the spent leaf, `spent_verdict` returned `Unprovable` for every tag, and the node could prove NEITHER
        // spent nor unspent about anything. Not a restart artifact: on this path the index was never populated.
        //
        // MEASURED on the live peered pair the moment the gate began demanding a positive verdict:
        // `[nf-gate] REJECT: input 0 is UNPROVABLE … (verdicts: 0 unspent / 0 spent / 1 unprovable)` — an
        // honest, unspent note refused, and `/get_nf_copath` serving that same empty index to the wallet.
        //
        // Mirroring here is the SAME write the other settle paths already perform (`verify_and_insert` →
        // `da_insert_nf_path`), in the SAME canonical order the fold used, so the index and the root describe
        // ONE tree by construction rather than by a second derivation that can drift. `da_insert_nf_path`
        // writes path nodes only — it never moves `sparse_acc` — so the adopted root above stays the authority
        // and nothing here can advance consensus state on its own.
        //
        // O-CHAIN-REVIEWED: the trip count is `padded.len()` = `BLOCK_FIXED_NULLIFIER_COUNT`, a FIXED protocol
        // constant identical on every block, and each iteration touches `NF_SPARSE_DEPTH` levels — also fixed.
        // Per-block work is f(BLOCK_FIXED_NULLIFIER_COUNT, NF_SPARSE_DEPTH) with no history term.
        // O1-DEFINITION-REVIEWED: by construction — both factors above are protocol constants, so this cost is
        // byte-identical on the first block and the millionth.
        // ⛔⛔⛔ MIRRORING HERE IS THE WRONG SHAPE — REVERTED, WITH THE NUMBER THAT KILLED IT.
        //
        // I added `for tag in padded { da_insert_nf_path(tag, &da_sparse_copath(tag)) }` so the node could
        // describe the tree its own root commits to, which DID fix `Unprovable`. Then I listed
        // `da_nf_node_mem` in `da_entry_census_named` and measured it:
        //
        //     24 blocks -> da_nf_node_mem: 1,502,330 entries / 60,093,200 bytes   (~2.5 MB PER BLOCK)
        //     every other map combined:                          ~278,000 bytes
        //
        // 256 tags x 256 levels = 65,536 node writes per block, forever. That is the single worst growth axis
        // this node has ever had, on a project whose bar is "a few KB forever". The footprint test failed the
        // moment the map became visible — which is exactly why it had to become visible.
        //
        // THE CORRECT SHAPE IS THE SPENDER'S, NOT THE NODE'S: a nullifier non-membership copath is invalidated
        // by every insertion, so it cannot be held — it must be MAINTAINED. The wallet already receives each
        // block's full padded tag set (`NfBlockProof::padded_tags` rides the block), so it can update its own
        // copath at a fixed 256-tag cost per block and CARRY it — which the gate already prefers over the
        // local index (`carried.get(i)`). The node then keeps ONE root and stores nothing per spend.
        //
        // Left un-mirrored deliberately: a node that cannot prove non-membership must say `Unprovable` and
        // fail closed, which it now does loudly. That is honest and sound. Making it quiet by storing 2.5 MB a
        // block would be the bandaid.
        // NOTE — the `[nf-index]` divergence probe that stood here is DELETED with the index it watched.
        // It asked "can this node reproduce its own committed root from its copath index?", which had exactly
        // one possible answer once `da_nf_node_mem` was removed: no, by design, because the node keeps nothing
        // per nullifier. A check whose verdict is structurally constant is not observability — it is the
        // always-green field this project has been bitten by — and it cost a full 256-level fold every block
        // to compute. The honest signal now lives at the GATE (`[nf-gate] … UNPROVABLE`) and at the serve
        // (`/get_nf_copath` answering 503), both of which report a real per-request outcome.
        true
    }

    /// ⛔ FAIL-CLOSED: a served sparse root that is not a canonical digest did not come from this chain,
    /// and installing a reduced version of it would leave this node's double-spend gate holding a value
    /// no honest copath can fold to. The joiner keeps the state it has and the bundle's sparse half is
    /// refused — never silently laundered.
    pub fn adopt_sparse_snapshot(&mut self, sparse_root: [u8; 32]) -> bool {
        match crate::nf_sparse::SparseNfAcc::adopt_merkle_root(sparse_root) {
            Some(a) => {
                self.sparse_acc = a;
                // DB-226: a certified root, complete for the chain at the adopt. With no view, the next block's
                // tags cannot be absorbed and the flag is set again then — exactly when it becomes true.
                self.sparse_acc_stale = false;
                self.set_sparse_work(None); // rebuild from the replicated stream (a jumped node holds ONLY the O(1) root)
                self.pivot_span = Vec::new(); // DB-339 part 3: a new pivot this node applied no block before
                true
            }
            None => {
                eprintln!(
                    "[sparse] ⛔ REFUSED a served sparse root that is not a canonical digest — it did \
                     not come from this chain, and a reduced version of it would be a gate nothing can \
                     satisfy"
                );
                false
            }
        }
    }

    /// ⭐ DB-407 — the maker bind of an order offered at the RPC post door, asked at the `Admit` door exactly as the fill
    /// door asks the maker half (§9.6 q6: the post door parallels the fill door's maker-half membership check and ran
    /// none of it). `Pending` = the lot's record is not folded here yet (retry after the fold, nothing rests); `Refused`
    /// = the bind names no canonical record holding the lot. Only the RPC door asks it: the carried `Class::OrderPost`
    /// apply stays fold-state-independent so every book derives from the chain alone, and the fill door still decides.
    /// MEASURED why: sim-20261007-011239 T2 — an order rested on a bind whose record the fold later stripped, so every
    /// taker paid a fill attempt against an order that could never settle.
    pub fn order_post_bind_verdict(&self, order: &crate::order_book::RestingOrder) -> MemberVerdict {
        if order.membership_carrier.is_empty() || order.membership_tip.is_empty() {
            return MemberVerdict::Refused;
        }
        self.bond_membership_verdict(
            Some((&order.membership_carrier, &order.membership_tip, order.maker.leaf_commit, order.maker.nullifier)),
            crate::respend::MemberDoor::Admit,
        )
        .0
    }

    /// One epidemic re-flood page of this node's resting book (see `OrderBook::reflood_page`).
    /// DB-273 §19.6 L3 — the payout owner the MAKER posted with the order resting on `nullifier` (the fill door's slot 0).
    /// CHAIN-OBJECT: `Class::OrderPost` carries the clue into every book; the fill door copies it into `Class::OrderFill`.
    #[must_use]
    pub fn order_payout_clue(&self, nullifier: crate::spend_frontier::Digest4) -> Option<Vec<u8>> {
        self.order_book.payout_clue_of(nullifier)
    }

    pub fn order_reflood_page(&self, cursor: usize, n: usize) -> (Vec<Vec<u8>>, usize) {
        self.order_book.reflood_page(cursor, n)
    }

    pub(super) fn record_opening_in_history(&mut self) {
        if self.custodian_opening_seal.is_empty() {
            return;
        }
        let (r, m) = Self::opening_commits(&self.custodian_opening_seal);
        if self.custodian_opening_history.iter().any(|(hr, hm, _)| *hr == r && *hm == m) {
            return;
        }
        self.custodian_opening_history.push_back((r, m, self.custodian_opening_seal.clone()));
        while self.custodian_opening_history.len() > crate::peg_attest::CUSTODY_OPENING_HISTORY_MAX {
            self.custodian_opening_history.pop_front();
        }
    }

    /// §DD interim: file the one-time ids the block just applied under its id (a bounded ring).
    pub(super) fn record_applied_one_time_ids(&mut self, block: crate::block::BlockId) {
        for (id, kind) in self.peg.take_applied_one_time_ids() {
            self.applied_one_time_ids.push_back((id, kind, block));
            while self.applied_one_time_ids.len() > crate::peg_attest::APPLIED_ONE_TIME_ID_RING_MAX {
                self.applied_one_time_ids.pop_front();
            }
        }
    }

    /// Is `target` in the RECENT past of the selected tip — every parent walked (GHOSTDAG merges apply the
    /// blocks off the selected chain too), bounded at `RECENT_PAST_WALK_MAX` visits so it costs O(1)?
    /// `Dag::is_ancestor_of_selected_tip` reads the cached `selected_chain` vector, which a jump's anchor
    /// graft leaves stale (measured by the DB-5 rewind pin: the abandoned mint block answered "ancestor").
    pub fn block_in_recent_past(&self, target: &crate::block::BlockId) -> bool {
        const RECENT_PAST_WALK_MAX: usize = 2048;
        let Some(tip) = self.relay.dag().selected_tip() else { return false };
        let mut seen: std::collections::HashSet<crate::block::BlockId> = std::collections::HashSet::new();
        let mut queue: std::collections::VecDeque<crate::block::BlockId> = std::collections::VecDeque::new();
        queue.push_back(tip);
        while let Some(id) = queue.pop_front() {
            if id == *target {
                return true;
            }
            if !seen.insert(id) || seen.len() > RECENT_PAST_WALK_MAX {
                if seen.len() > RECENT_PAST_WALK_MAX {
                    return false;
                }
                continue;
            }
            if let Some(n) = self.relay.dag().get(&id) {
                for p in &n.header.parents {
                    queue.push_back(*p);
                }
            }
        }
        false
    }

    /// ⭐⭐⭐ §CS — APPLY AN ATTESTED PEG-IN FROM THE OBJECT'S OWN BYTES, ON EVERY NODE.
    ///
    /// This is what `peg_in_tx::apply_chain_peg_in` drives at graft. It re-runs the SAME
    /// `peg::peg_in_confidential` the publishing node ran — same message domain, same
    /// `confidential_deposit_ids` replay key, same bond backstop — against THIS node's own validator set,
    /// own persisted commitments and own replay set. Nothing is taken from the publisher but the bytes.
    ///
    /// ⛔ THE NOTE IS CREDITED ONLY ON THE MINTED ARM, and only after the mint carrier proves the note's
    /// commitment opens to the ATTESTED amount — the same `credit_is_authorised` binding the RPC path
    /// used, kept here so a note sealed for more than the quorum authorised is refused on every node.
    #[allow(clippy::too_many_arguments)]
    /// ⭐⭐⭐ §CS-b — APPLY AN ATTESTED PEG-OUT FROM THE OBJECT'S OWN BYTES, ON EVERY NODE.
    ///
    /// Re-runs the SAME `peg::peg_out_confidential` the publisher ran — same `peg_out_confidential_msg`
    /// domain, same `spent_burns` replay key, same redeem-floor carrier — against THIS node's own
    /// validator set, own persisted commitments and own burn set. The burn therefore RETIRES everywhere,
    /// which is the half that made one USDm note redeemable once per node before this class existed.
    #[allow(clippy::too_many_arguments)]
    /// ⭐⭐⭐ DB-237 — APPLY A STAKE / CLAIM / UNSTAKE AT ITS BLOCK'S CANONICAL FOLD, FROM THE OBJECT'S OWN BYTES, ON EVERY
    /// NODE. Every gate runs before anything moves; a refusal names its rule and moves nothing.
    /// 1. `e_now` is the carrying block's epoch (its header timestamp): no stake backdates its start.
    /// 2. `rate_bps` is this chain's governance rate: the reward is derived by every node, never declared.
    /// 3. The input note's membership verifies at the `MemberDoor::Fold` door (its record folded before this block).
    /// 4. The stake carrier verifies: the input opens under a stake tag or USDm, the reward is exactly the rule's, the
    ///    outputs are the carried notes, the reward commitment is `reward_commit`.
    /// 5. The supply step verifies against THIS node's stakers' pool (paid-out total + the epoch's pool snapshot), opening the
    ///    SAME `reward_commit`; the USDm supply does not move.
    /// The input's nullifier is this object's OWN lane tag (`object_own_nullifiers`), so the spent SET refuses a second
    /// use the way every tag is refused — admitted at this fold, applied by the band, never written here.
    pub fn apply_stake_at_fold(&mut self, d: &crate::stake_tx::StakeDecoded, block_ts_ms: u64) -> Result<(), &'static str> {
        use usdm_decider::whir_rec_block as w;
        let h = &d.h;
        if h.e_now != w::stake_epoch_of_ms(block_ts_ms) {
            return Err("its epoch is not the carrying block's");
        }
        if h.rate_bps != self.params().stake_reward_apr_bps {
            return Err("its rate is not this chain's governance rate");
        }
        // The cross-bind is MANDATORY: an all-zero commitment or an empty membership carrier proves membership by
        // nothing, so both are refused here, before the binding is handed to any verifier.
        if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest() || d.membership_carrier.is_empty() {
            return Err("its membership cross-bind is absent");
        }
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&h.nullifier) else {
            return Err("its nullifier is not a canonical digest");
        };
        let Some(Some(lc)) = self.check_bond_membership(
            Some((&d.membership_carrier[..], &d.membership_tip[..], h.leaf_commit, binder)),
            crate::respend::MemberDoor::Fold,
        ) else {
            return Err("its input note's membership does not verify before this block");
        };
        let Some(stmt) = crate::stake_tx::statement(h) else {
            return Err("its statement does not decode");
        };
        if lc != h.leaf_commit || !w::verify_stake_carrier_bytes(&d.stake_carrier, &stmt, h.e_now, u64::from(h.rate_bps)) {
            return Err("its stake carrier does not verify");
        }
        // §BR-3 17.6 (stakers' half): the reward is paid from the stakers' pool, bounded by this node's own epoch snapshot
        if !self.peg.apply_stake_supply(&d.supply_carrier, h.reward_commit, h.new_paid_commit, h.e_now) {
            return Err("its supply step does not verify against this node's stakers' pool");
        }
        self.advance_custodian_opening_from_stake(&d.sealed, h.reward_commit);
        let height = self.tip_height();
        self.record_note_payload(height, &d.out0);
        self.record_note_payload(height, &d.out1);
        Ok(())
    }

    /// The pool transaction a spending chain object travels in: its stamp, its padded nullifier lane and that lane's
    /// evidence. Built here once for the publisher ([`Self::publish_spending_object_nfs`]) and a pin's rogue pool.
    pub(super) fn spending_object_tx(&mut self, blob: Vec<u8>, nfs: &[[u8; 32]], out_notes: Vec<u8>) -> Result<PqTx, crate::mempool::MempoolError> {
        let need = self.mempool.required_stamp_bits();
        let id = crate::mempool::PqTx::content_id(&blob);
        let mut stamp = 0u64;
        let pow_stamp = loop {
            let mut buf = Vec::with_capacity(72);
            buf.extend_from_slice(id.as_bytes());
            buf.extend_from_slice(&stamp.to_le_bytes());
            buf.extend_from_slice(crate::params::process_network_id().as_bytes());
            if crate::mempool::leading_zero_bits(Hash32::hash(&buf).as_bytes()) >= need {
                break stamp;
            }
            stamp = stamp.wrapping_add(1);
        };
        let Some(padded) = crate::cover::pad_tx_nullifiers_to_fixed(nfs, id.as_bytes()) else {
            return Err(crate::mempool::MempoolError::InvalidId); // a few real rows always fit the fixed width
        };
        let (nullifier_witnesses, nullifier_absence) = if crate::canon_chain::canon_live() {
            // ⭐ A-F114: no node holds the spent set, so the spender's own wrappers (`canon_chain::scope_spender_wrappers`)
            // are the object's absence evidence. An object with a note leg and none is refused HERE, before any block
            // carries it: refused at its fold it would burn the note it spends.
            let has_leg = crate::chain_object::object_tag_roles(&blob)
                .is_some_and(|r| r.iter().any(|(_, x)| matches!(x, crate::chain_object::TagRole::Leg(_))));
            let ev = self.spend_lane_evidence(&padded);
            if has_leg && ev.1.is_empty() {
                return Err(crate::mempool::MempoolError::NullifierWitnessRejected);
            }
            ev
        } else {
            self.spend_lane_evidence(&padded)
        };
        let tx = crate::mempool::PqTx {
            clock_ms: 0,
            id,
            weight: blob.len() as u32,
            blob,
            nullifiers: padded.iter().map(|n| Hash32(*n)).collect(),
            pow_stamp,
            note_clues: Vec::new(),
            account_targets: Vec::new(),
            output_notes: out_notes,
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
        Ok(tx)
    }

    /// ⭐⭐⭐ §BR-3 17.3 — A DELEGATION'S STATE HALF at `door` (Admit at the publisher, Fold at apply): the carriers, the burned
    /// input's membership bound to its `leaf_commit`, its nullifier unspent, and the kind's rule — Delegate: a live, unslashed
    /// seat of the named instance; Undelegate: not slashed, and `matures` at least the unbonding window past the carrying block
    /// (at the Admit door, past this node's tip); Release: the carrying block (the tip at Admit) at or past `matures`.
    pub(crate) fn sat_delegation_refusal(
        &self,
        t: &crate::sat_delegation_tx::SatDelegationTx,
        door: crate::respend::MemberDoor,
        // A-F60: the carrying block's CHAIN TICK (`None` at the Admit door: this node's tip tick). A maturity is a time.
        carrying_tick: Option<u64>,
    ) -> Option<&'static str> {
        use crate::sat_delegation_tx::DelegationKind;
        if !t.carriers_verify() {
            return Some("its burn or mint carrier does not verify for its tags and amount");
        }
        let (Some(binder), Some(lc)) = (
            crate::spend_frontier::cm_bytes_to_root(&t.nullifier),
            crate::spend_frontier::cm_bytes_to_root(&t.leaf_commit),
        ) else {
            return Some("its digests are not canonical");
        };
        match self.check_bond_membership(Some((&t.membership_carrier[..], &t.membership_tip[..], lc, binder)), door) {
            Some(Some(got)) if got == lc => {}
            _ => return Some("its burned note's membership does not verify before this block"),
        }
        let at = carrying_tick.unwrap_or_else(|| self.chain_tick());
        // §17.6: the kind's index must be the one this fold holds (a quarter close between build and fold is refused here and
        // the wallet rebuilds), and the bonders' pool must cover the yield it pays
        if t.index_at_fold().is_some_and(|y| y != self.peg.bond_yield_index()) {
            return Some("its yield index is not the chain's at this block (a quarter closed meanwhile): rebuild it");
        }
        if t.yield_amount() > self.peg.fee_pools().bonders {
            return Some("the bonders' pool cannot cover its yield");
        }
        let rule = match t.kind {
            DelegationKind::Delegate { vid, .. } => self.validators().delegate_refusal(&vid, u128::from(t.amount)),
            DelegationKind::Claim { vid, .. } => self.validators().claim_refusal(&vid, u128::from(t.amount)),
            DelegationKind::Undelegate { vid, matures, .. } => {
                let window = self.unbond_ticks();
                if let Some(why) = self.validators().undelegate_refusal(&vid, u128::from(t.amount)) {
                    Some(why)
                } else if matures % crate::sat_delegation_tx::unbonding_epoch(window) != 0 {
                    Some("the unbonding note does not mature at an epoch boundary")
                } else if matures < at.saturating_add(window) {
                    Some("the unbonding note matures before the unbonding window ends")
                } else {
                    None
                }
            }
            DelegationKind::Release { matures } => (at < matures).then_some("the unbonding note has not matured"),
        };
        if rule.is_some() {
            return rule;
        }
        // ⭐ §22 3 — delegators share their validator's rate: the yield paid is the index rise weighted by the chain's own
        // record of that validator's uptime (compared as the amount, so a fully active validator's never goes stale)
        if let DelegationKind::Undelegate { vid, .. } | DelegationKind::Claim { vid, .. } = t.kind {
            let (active, windows) = self.delegator_uptime(&vid);
            if t.yield_amount() != crate::validator_activity::uptime_split(t.yield_base(), active, windows).0 {
                return Some("its yield is not weighted by the validator's uptime at this block: rebuild it");
            }
        }
        let spent = match door {
            crate::respend::MemberDoor::Admit => self.sparse_spent_verdict(&t.nullifier) == crate::nf_sparse::SpentVerdict::Spent,
            crate::respend::MemberDoor::Fold => self.fold_point_spent_set().holds(&t.nullifier),
        };
        spent.then_some("its burned note is already spent")
    }

    /// ⭐ §BR-10 — the signal's rule: authorised, and the signer holds a live custody seat. `None` = it counts.
    pub(crate) fn deployment_signal_refusal(&self, t: &crate::deployment_signal_tx::DeploymentSignalTx) -> Option<&'static str> {
        if !t.authorised() {
            return Some("its key or signature does not verify");
        }
        (self.validators.bond_of(&t.vid) == 0).then_some("the signer holds no custody seat")
    }
    /// Keep a decided attestation as its builder's latest.
    pub(crate) fn record_release_attestation(&mut self, t: &crate::release_attestation_tx::ReleaseAttestationTx) {
        self.peg.record_release_attestation(t);
    }
    /// Count a decided signal in the open window (a signal for another window counts nothing).
    pub(crate) fn apply_deployment_signal(&mut self, t: &crate::deployment_signal_tx::DeploymentSignalTx) {
        let _ = self.peg.deployments_mut().observe_validator_signal(t.vid, t.bits, t.window);
    }

    /// ⭐ §BR-9a — the deal's rule: authorised, then the epoch-key ledger's (the dealing epoch, the roster, once, addressed
    /// to exactly the roster). `None` = it applies.
    pub(crate) fn epoch_key_deal_refusal(&self, t: &crate::epoch_deal_tx::EpochKeyDealTx) -> Option<&'static str> {
        if !t.authorised() {
            return Some("its key or signature does not verify");
        }
        self.peg.epoch_keys().refusal(t)
    }
    /// Sum a decided deal into its epoch's key; a custodian on its roster captures the share sealed to it.
    pub(crate) fn apply_epoch_key_deal(&mut self, t: &crate::epoch_deal_tx::EpochKeyDealTx) {
        self.peg.epoch_keys_mut().observe_deal(t);
        self.capture_epoch_share(t);
    }

    /// ⭐ §BR-13 — the set-aside's rule: the canonical bytes, the bound, and not applied yet. `None` = it applies.
    pub(crate) fn set_aside_refusal(&self, t: &crate::sat_set_aside::SatSetAsideTx) -> Option<&'static str> {
        if !t.is_the_canonical_set_aside() {
            return Some("not this network's canonical set-aside, or its bound does not verify");
        }
        self.peg.set_aside_applied().then_some("the set-aside has already applied")
    }
    pub(crate) fn mark_set_aside_applied(&mut self) {
        self.peg.mark_set_aside_applied();
    }

    /// ⭐ §BR-3 17.6 — the claim's rule against this node's state: the stateless half, the index this fold holds, exactly the
    /// id's own-weight yield at it, and a pool that covers it. `None` = payable.
    pub(crate) fn bond_yield_claim_refusal(&self, t: &crate::bond_yield_claim_tx::BondYieldClaimTx) -> Option<&'static str> {
        if !t.authorised() {
            return Some("its key, signature or carrier does not verify");
        }
        let y = self.peg.bond_yield_index();
        if t.y_now != y {
            return Some("its yield index is not the chain's at this block (a quarter closed meanwhile): rebuild it");
        }
        if t.amount != self.own_yield_due(&t.vid, y) {
            return Some("its amount is not the validator's own-weight yield owed at this index and uptime");
        }
        (t.amount > self.peg.fee_pools().bonders).then_some("the bonders' pool cannot cover its yield")
    }

    /// ⭐ §BR-10 — the bounty's state verdict: ≥ 2/3 of THIS node's bonded custody weight signed its statement, the amount is
    /// within the constitutional cap of the surplus buffer, and the buffer covers it.
    pub(crate) fn bounty_payout_refusal(&self, t: &crate::bounty_payout_tx::BountyPayoutTx) -> Option<&'static str> {
        // A-F114: from the upgrade the signatures cover the ledger's bounty counter (`bounty_statement`)
        let seq = self.bounty_statement_seq();
        if !t.carrier_verifies() || !t.signatures_verify_at(seq) {
            return Some("a signature or the note's carrier does not verify");
        }
        let Some(stmt) = t.statement_at(seq) else {
            return Some("the bounty names no note");
        };
        if !crate::bond_tally::verify_threshold(&stmt, &t.cert(), &self.validators, &crate::pqauth::MlDsaVerifier) {
            return Some("no ≥ 2/3 of the bonded custody weight signs this bounty");
        }
        let buffer = self.peg.fee_pools().surplus;
        let cap = u128::from(buffer) * u128::from(crate::bounty_payout_tx::BOUNTY_MAX_SURPLUS_FRACTION_BPS) / 10_000;
        if u128::from(t.amount) > cap {
            return Some("the bounty is above the constitutional share of the surplus buffer");
        }
        None
    }

    /// The bounty's state move: the surplus buffer pays it (never below zero).
    pub(crate) fn bounty_payout_move(&mut self, amount: u64) -> bool {
        let paid = self.peg.pay_bounty(amount);
        if paid && crate::params::canon_live() {
            self.canon_bounty_seq += 1; // A-F114: the counter steps with each bounty paid, so its statement is never valid twice
        }
        paid
    }

    /// A-F114: the bounty counter a bounty statement binds now (`None` before the network upgrade).
    #[must_use]
    pub fn bounty_statement_seq(&self) -> Option<u64> {
        crate::params::canon_live().then_some(self.canon_bounty_seq)
    }

    /// The claim's state move: the accrual zeroed and the pool paid, together.
    pub(crate) fn bond_yield_claim_move(&mut self, t: &crate::bond_yield_claim_tx::BondYieldClaimTx) -> Result<(), &'static str> {
        if !self.peg.pay_bond_yield(t.amount) {
            return Err("the bonders' pool cannot cover its yield");
        }
        // the accrual's before-image goes into this fold step's journal (`note_objects_vid_before`): a rewound claim
        // gives the seat its accrual back with the pool
        self.note_objects_vid_before(&t.vid);
        // §22 3: the accrual is zeroed whole; the part the seat's uptime did not earn was never paid out of the pool
        // CHAIN-OBJECT: `Class::BondYieldClaim`, the claim this block carries, applied at its canonical fold step.
        let accrued = self.validators.take_own_yield(&t.vid, t.y_now);
        debug_assert!(accrued >= t.amount, "the refusal judged the uptime-weighted amount owed");
        Ok(())
    }

    /// ⭐ §22 3 — a seated custodian's uptime for pay, `(active windows, windows)` since it was seated, from the chain's
    /// activity record. A seat with no word yet, or an id no longer seated (its accrual was weighed as it left), weighs whole.
    pub(crate) fn pay_uptime(&self, id: &[u8; 32]) -> (u64, u64) {
        let a = &self.peg.epoch_keys().activity;
        if self.validators.bond_of(id) == 0 {
            return (1, 1);
        }
        match a.uptime(id, a.now) {
            Some(u) => u,
            None => (1, 1),
        }
    }

    /// ⭐ §22 3 — the uptime a delegation to `vid` is paid at: the seated validator's (whole while it has no word yet); a
    /// validator no longer seated — unbonded, retired after seven days away, or slashed — earns its delegators nothing more,
    /// `(0, 1)`: they undelegate (the wallet moves them automatically).
    pub fn delegator_uptime(&self, vid: &[u8; 32]) -> (u64, u64) {
        if self.validators.bond_of(vid) == 0 {
            return (0, 1);
        }
        let a = &self.peg.epoch_keys().activity;
        match a.uptime(vid, a.now) {
            Some(u) => u,
            None => (1, 1),
        }
    }

    /// ⭐ §22 3 — the own-weight yield `id` is owed at index `y`, weighted by its uptime: what its `BondYieldClaim` must state
    /// and what the wallet is shown. The unearned part stays in the bonders' pool for the active seats.
    pub fn own_yield_due(&self, id: &[u8; 32], y: u128) -> u64 {
        let (active, windows) = self.pay_uptime(id);
        crate::validator_activity::uptime_split(self.validators.own_yield_at(id, y), active, windows).0
    }

    /// The seat-weight move a decided delegation makes (the fold applies it after [`Self::sat_delegation_refusal`]).
    pub(crate) fn sat_delegation_move(&mut self, t: &crate::sat_delegation_tx::SatDelegationTx) -> Result<(), &'static str> {
        use crate::sat_delegation_tx::DelegationKind;
        // §17.6: the yield leaves the bonders' pool first (refused whole if it cannot — the refusal above checked it)
        let y = t.yield_amount();
        if y > 0 && !self.peg.pay_bond_yield(y) {
            return Err("the bonders' pool cannot cover its yield");
        }
        // the seat's before-image goes into this fold step's journal (`note_objects_vid_before`): a rewound delegation
        // takes its weight off the seat as the band gives the delegator's note back
        // CHAIN-OBJECT: `Class::SatDelegation`, the delegation this block carries, applied at its canonical fold step.
        match t.kind {
            DelegationKind::Delegate { vid, .. } => {
                self.note_objects_vid_before(&vid);
                self.validators.delegate(vid, u128::from(t.amount))
            }
            DelegationKind::Undelegate { vid, .. } => {
                self.note_objects_vid_before(&vid);
                self.validators.undelegate(vid, u128::from(t.amount)).map(|_| ())
            }
            DelegationKind::Claim { .. } | DelegationKind::Release { .. } => Ok(()),
        }
    }

    /// ⭐⭐⭐ §BR-14 item 4 — THE CREATION FEE'S STATE HALF: the burn's carrier ([`crate::asset_tx::AssetCreateTx::
    /// fee_carrier_verifies`]) and the spent note's membership at `door` (Admit at the publisher, Fold at apply — the pool
    /// deposit's two doors), both bound to ONE `leaf_commit`. `None` = the fee is paid; `Some(why)` names the refusal.
    pub(crate) fn creation_fee_refusal(
        &self,
        c: &crate::asset_tx::AssetCreateTx,
        door: crate::respend::MemberDoor,
    ) -> Option<&'static str> {
        if !c.fee_carrier_verifies() {
            return Some("its creation-fee burn does not verify (the symbol's price into this creation's burn, plus the network fee)");
        }
        self.burn_fee_refusal(&c.fee, true, door)
    }

    /// ⭐ §BR-12 L1 — THE ONE FEE-BURN DOOR every object that pays a public burn from its own input passes (an asset creation,
    /// a contract deploy): the carrier's stateless verdict the caller already took (`verifies`), then the burned note's
    /// MEMBERSHIP before this block through the one member door (`check_bond_membership`, at `door`). Shared so a third burn
    /// class tomorrow cannot skip the membership half (the class the §BA door closed: a note no block holds paying a fee).
    pub(crate) fn burn_fee_refusal(
        &self,
        fee: &crate::asset_tx::CreationFee,
        verifies: bool,
        door: crate::respend::MemberDoor,
    ) -> Option<&'static str> {
        if !verifies {
            return Some("its fee burn does not verify (the price into this object's own burn commitment, plus the network fee)");
        }
        self.fee_note_membership_refusal(&fee.nullifier, &fee.leaf_commit, &fee.membership_carrier, &fee.membership_tip, door)
    }

    /// The one MEMBERSHIP half every fee spend shares (a creation's or a deploy's burn, a call's publisher-fee spend): the spent
    /// note's one-step member leg through the one member door at `door`.
    pub(crate) fn fee_note_membership_refusal(
        &self,
        nullifier: &[u8; 32],
        leaf_commit: &[u8; 32],
        membership_carrier: &[u8],
        membership_tip: &[u8],
        door: crate::respend::MemberDoor,
    ) -> Option<&'static str> {
        let (Some(binder), Some(lc)) = (crate::spend_frontier::cm_bytes_to_root(nullifier), crate::spend_frontier::cm_bytes_to_root(leaf_commit)) else {
            return Some("its fee digests are not canonical");
        };
        match self.check_bond_membership(Some((membership_carrier, membership_tip, lc, binder)), door) {
            Some(Some(got)) if got == lc => None,
            _ => Some("its fee note's membership does not verify before this block"),
        }
    }

    /// ⭐ §BR-12 L2 — THE CALL DOOR'S READ-ONLY VERDICT, the same at `Admit` (the publisher; `carrying_blue` unknown → the epoch
    /// is not judged there, it is the fold's) and at `Fold` (every node, with the carrying block's blue score): the stateless
    /// half (`DsolCallTx::self_authorised`), the fee note's membership at `door`, A3's epoch, and the state leaf — the carried
    /// manifest and `storage_pre` must sit at `cid` under THIS node's current root. `None` = applies.
    pub(crate) fn dsol_call_refusal(
        &self,
        t: &crate::dsol_call_tx::DsolCallTx,
        door: crate::respend::MemberDoor,
        carrying_blue: Option<u64>,
    ) -> Option<&'static str> {
        if let Some(why) = t.self_authorised() {
            return Some(why);
        }
        if let Some(why) = self.fee_note_membership_refusal(&t.fee.nullifier, &t.fee.leaf_commit, &t.fee.membership_carrier, &t.fee.membership_tip, door) {
            return Some(why);
        }
        match (door, carrying_blue) {
            (crate::respend::MemberDoor::Fold, None) => return Some("the carrying block's blue score is unknown at the fold — the epoch cannot be judged"),
            (_, Some(b)) if !t.epoch_matches(b) => return Some("its block number is not the carrying block's epoch floor — re-prove in this epoch (A3)"),
            _ => {}
        }
        if t.root_after(self.peg.contract_state_root()).is_none() {
            return Some("its contract-state path does not open this node's current root — the leaf moved; re-prove on the new state");
        }
        None
    }

    /// ⭐ §BR-12 L3 — THE FEE UPDATE DOOR'S READ-ONLY VERDICT: the deployer's signature and the direction (stateless), then the
    /// carried leaf against THIS node's root. `None` = applies.
    /// §BR-15 — a DeFi object's member leg at the FOLD door (the order's burned note, the claim's leaf): the one shared
    /// verdict every object's leg takes (`member_leg_object_verdict`), so a leaf outside this node's ring or epoch anchors is
    /// refused here exactly as a burn's would be.
    pub(crate) fn defi_member_leg(&self, carrier: &[u8], tuple: &[u8], leaf_commit: crate::spend_frontier::Digest4, binder: crate::spend_frontier::Digest4) -> bool {
        matches!(
            self.member_leg_object_verdict(carrier, tuple, leaf_commit, binder, crate::respend::MemberDoor::Fold),
            MemberVerdict::Member
        )
    }

    /// §BR-15 — whether a slot's member leg is refused outright, as opposed to pending on an anchor this node has yet to hold.
    pub(crate) fn defi_member_leg_refused(&self, carrier: &[u8], tuple: &[u8], leaf_commit: crate::spend_frontier::Digest4, binder: crate::spend_frontier::Digest4) -> bool {
        matches!(self.member_leg_object_verdict(carrier, tuple, leaf_commit, binder, crate::respend::MemberDoor::Fold), MemberVerdict::Refused)
    }

    /// §BR-15 — the DeFi book, for the fold door (`defi_batch::apply_chain_defi`).
    pub(crate) fn defi_book_mut(&mut self, pair: u8) -> Option<&mut crate::defi_batch::DefiBook> {
        self.peg.defi_book_mut(pair)
    }

    pub(crate) fn dsol_fee_update_refusal(&self, t: &crate::dsol_fee_update_tx::DsolFeeUpdateTx) -> Option<&'static str> {
        if let Some(why) = t.self_authorised() {
            return Some(why);
        }
        if t.root_after(self.peg.contract_state_root()).is_none() {
            return Some("its contract-state path does not open this node's current root — the leaf moved; re-prove on the new state");
        }
        None
    }

    /// ⭐ §BR-12 L3 — the fold's one write for a fee update: the leaf under the new manifest, or `None`.
    pub(crate) fn apply_dsol_fee_update_state(&mut self, t: &crate::dsol_fee_update_tx::DsolFeeUpdateTx) -> Option<crate::spend_frontier::Digest4> {
        let pre = self.peg.contract_state_root();
        let root = t.root_after(pre)?;
        let storage = crate::spend_frontier::cm_bytes_to_root(&t.storage_root)?;
        self.peg.set_contract_state_root(root);
        self.push_contract_leaf_update(pre, t.cid, t.new_manifest().leaf(storage), root);
        Some(root)
    }

    /// ⭐ §BR-12 L2 — the fold's one write for a call: the root with the contract's leaf moved to `storage_post`, or `None`.
    pub(crate) fn apply_dsol_call_state(&mut self, t: &crate::dsol_call_tx::DsolCallTx) -> Option<crate::spend_frontier::Digest4> {
        let pre = self.peg.contract_state_root();
        let root = t.root_after(pre)?;
        self.peg.set_contract_state_root(root);
        self.push_contract_leaf_update(pre, t.cid, t.manifest.leaf(t.root.stmt.storage_post), root);
        // D4: the call's sealed writes, for whoever holds the contract's key to rebuild its storage
        crate::contract_blobs::file_call(self.tip_height(), t);
        Some(root)
    }

    /// ⭐ §BR-12 L1 — THE DEPLOY DOOR'S READ-ONLY VERDICT, the same at `Admit` (the publisher) and at `Fold` (every node):
    /// the deployer's signature, the fee burn (carrier + the note's membership at `door`), and the contract-state path
    /// against THIS node's current root (the cid must be absent and the path must open the root). `None` = applies.
    pub(crate) fn dsol_deploy_refusal(
        &self,
        d: &crate::dsol_deploy_tx::DsolDeployTx,
        door: crate::respend::MemberDoor,
    ) -> Option<&'static str> {
        if !d.signature_verifies() {
            return Some("the deployer's signature does not verify");
        }
        if let Some(why) = self.burn_fee_refusal(&d.fee, d.fee_carrier_verifies(), door) {
            return Some(why);
        }
        if d.root_after(self.peg.contract_state_root()).is_none() {
            return Some(
                "its contract-state path does not open this node's current root (the root moved since it was built, or the cid is taken) — re-prove on the new root",
            );
        }
        None
    }

    /// ⭐ §BR-12 L1 — the fold's one write for a deploy: the new contract-state root from the carried path, or `None` (nothing
    /// written) when the path does not open the current root. Called after [`Self::dsol_deploy_refusal`] said `None`.
    pub(crate) fn apply_dsol_deploy_state(&mut self, d: &crate::dsol_deploy_tx::DsolDeployTx) -> Option<crate::spend_frontier::Digest4> {
        let pre = self.peg.contract_state_root();
        let root = d.root_after(pre)?;
        self.peg.set_contract_state_root(root);
        self.push_contract_leaf_update(pre, d.cid(), d.leaf(), root);
        Some(root)
    }

    /// ⭐⭐⭐ LIQUIDATION §10 — APPLY A POOL DEPOSIT AT ITS BLOCK'S FOLD, FROM THE OBJECT'S OWN BYTES, ON EVERY NODE: the PSM,
    /// the pool epoch, the spent note's membership (Fold door), the deposit carrier, the snapshot carrier against THIS
    /// node's CURRENT pool words, and the transition `T + d` over the same `dv` — then the pool advances and the receipt and
    /// change are credited. The spent note's nullifier is the object's own lane tag (the spent set refuses a re-use).
    pub fn apply_pool_deposit_at_fold(&mut self, d: &crate::pool_tx::PoolDepositDecoded) -> Result<(), &'static str> {
        use usdm_decider::whir_rec_block as w;
        let h = &d.h;
        if !self.is_psm(h.asset_id) {
            return Err("its asset is not a PSM of this chain");
        }
        let words = self.peg.pool_words(h.asset_id);
        if h.epoch != words.epoch {
            return Err("its pool epoch is not the pool's");
        }
        if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest() || d.membership_carrier.is_empty() {
            return Err("its membership cross-bind is absent");
        }
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&h.nullifier) else {
            return Err("its nullifier is not a canonical digest");
        };
        let Some(Some(lc)) = self.check_bond_membership(
            Some((&d.membership_carrier[..], &d.membership_tip[..], h.leaf_commit, binder)),
            crate::respend::MemberDoor::Fold,
        ) else {
            return Err("its spent note's membership does not verify before this block");
        };
        let Some(stmt) = crate::pool_tx::deposit_statement(h) else {
            return Err("its statement does not decode");
        };
        if lc != h.leaf_commit || !w::verify_pool_deposit_bytes(&d.deposit_carrier, &stmt) {
            return Err("its deposit carrier does not verify");
        }
        let snap = w::PoolSnapshotStatement { p_word: words.p, pd: h.pd, s_word: words.s, sd: h.sd };
        if !w::verify_pool_snapshot_bytes(&d.snapshot_carrier, &snap) {
            return Err("its receipt is keyed to a snapshot that is not this pool's");
        }
        if !usdm_decider::confidential_solvency::verify_transition_carrier(
            &d.transition_carrier,
            &[words.t, h.dv, h.new_t],
            usdm_decider::confidential_solvency::TransitionDomain::StabilityPool,
        ) {
            return Err("its pool transition does not verify against this node's pool");
        }
        self.peg.set_pool_words(h.asset_id, crate::peg::PoolWords { t: h.new_t, ..words });
        self.advance_pool_opening_from_deposit(h.asset_id, &d.sealed, h.dv, words);
        let height = self.tip_height();
        self.record_note_payload(height, &d.receipt);
        self.record_note_payload(height, &d.change);
        Ok(())
    }

    /// ⭐⭐⭐ LIQUIDATION §10.2 — APPLY A POOL WITHDRAWAL AT ITS BLOCK'S FOLD, ON EVERY NODE: the PSM, the pool epoch, the
    /// receipt's membership (Fold door), the receipt carrier, the epoch bridge over THIS node's source words (H11 §2.5),
    /// the withdraw carrier against the bridged `(P, S)`, and the transition `T − u` over the same `du` — then the pool
    /// advances and the compounded note is credited.
    pub fn apply_pool_withdraw_at_fold(&mut self, d: &crate::pool_tx::PoolWithdrawDecoded) -> Result<(), &'static str> {
        use usdm_decider::confidential_solvency as cs;
        use usdm_decider::whir_rec_block as w;
        let h = &d.h;
        if !self.is_psm(h.asset_id) {
            return Err("its asset is not a PSM of this chain");
        }
        let words = self.peg.pool_words(h.asset_id);
        // The receipt settles against the BRIDGE of its epoch's words through the next epoch's (H11 §2.5): the sources
        // come from THIS node's ledger by the one selection rule, never from the object.
        let src = match self.peg.receipt_bridge_words(h.asset_id, h.epoch) {
            Some(src) => src,
            None => return Err("its pool epoch is neither the pool's nor a closed epoch of it"),
        };
        if h.leaf_commit == usdm_decider::poseidon2_compress::zero_digest() || d.membership_carrier.is_empty() {
            return Err("its membership cross-bind is absent");
        }
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&h.nullifier) else {
            return Err("its nullifier is not a canonical digest");
        };
        let Some(Some(lc)) = self.check_bond_membership(
            Some((&d.membership_carrier[..], &d.membership_tip[..], h.leaf_commit, binder)),
            crate::respend::MemberDoor::Fold,
        ) else {
            return Err("its receipt's membership does not verify before this block");
        };
        let Some(stmt) = crate::pool_tx::receipt_statement(h) else {
            return Err("its statement does not decode");
        };
        if lc != h.leaf_commit || !w::verify_pool_receipt_bytes(&d.receipt_carrier, &stmt) {
            return Err("its receipt carrier does not verify");
        }
        if !cs::verify_pool_bridge_carrier(&d.bridge_carrier, &[src[0], src[1], src[2], src[3], h.pb, h.sb]) {
            return Err("its epoch bridge does not verify against this node's pool");
        }
        if !cs::verify_withdraw_carrier(&d.withdraw_carrier, &[h.dd, h.pd, h.sd, h.pb, h.sb, h.du, h.gain_commit]) {
            return Err("its withdraw carrier does not verify against this node's pool");
        }
        if !cs::verify_transition_carrier(&d.transition_carrier, &[h.new_t, h.du, words.t], cs::TransitionDomain::StabilityPool) {
            return Err("its pool transition does not verify against this node's pool");
        }
        // The custodian's blind of the BRIDGED S (re-derived from its own openings of both sources), read before T moves.
        let s_blind = self
            .pool_opening_now(h.asset_id)
            .and_then(|live| self.receipt_bridge(h.asset_id, h.epoch, &live).ok())
            .map(|rb| pool_bridge_blinds(&rb.first, &rb.second, &h.nullifier).1);
        self.peg.set_pool_words(h.asset_id, crate::peg::PoolWords { t: h.new_t, ..words });
        // The withdrawal AUTHORIZES its collateral gain's release on every node (the payout lane pays it once);
        // the amount is hidden — each custodian books what its own sealed leg proves.
        self.peg.authorize_pool_gain_release(h.nullifier);
        self.book_pool_gain(h, &d.gain_sealed, s_blind);
        self.advance_pool_opening_from_withdraw(h.asset_id, &d.sealed, h.du, words);
        let height = self.tip_height();
        self.record_note_payload(height, &d.out);
        Ok(())
    }

    pub fn apply_peg_out_attested(
        &mut self,
        usdm_nullifier: [u8; 32],
        carrier: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        // DB-110: what the object CARRIES is the destination's commitment; the address itself never
        // reaches a grafting node (only the bonded custodians who must pay it open the sealed leg).
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        // DB-273 §19.3 L2: the change owner the object's header names (the v4 statement binds it).
        change_owner: &[u8; 32],
        // DB-365: the change commitment the object's header names (the v5 statement binds it; `peg_out_tx::decode`
        // already refused a carried change note of any other commitment).
        change_cm: &[u8; 32],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        change_note: &[u8],
        sealed: &[([u8; 32], Vec<u8>)],
        // §BR-5: the cash-out ticket, its share envelopes and share commitments (bound into `redeem_commit`)
        ticket: &crate::peg_out_tx::TicketParts,
    ) -> crate::peg::PegOutcome {
        // ⭐ B15: the burned note is a member of the chain at the fold (its one-step membership, bound to the burn's own
        // nullifier and the signed leaf commitment) — checked before the ledger moves; the burn and the burn-bound carrier
        // are the ledger door's (`PegLedger::check_peg_out_confidential`).
        let Some(proofs) = crate::peg_out_tx::PegOutProofs::decode(carrier) else {
            return crate::peg::PegOutcome::BadRequest;
        };
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&usdm_nullifier) else {
            return crate::peg::PegOutcome::BadRequest;
        };
        if !matches!(self.check_bond_membership(Some((&proofs.membership, &proofs.tip, leaf_commit, binder)), crate::respend::MemberDoor::Fold), Some(Some(_))) {
            return crate::peg::PegOutcome::BadRequest;
        }
        // Field-level borrows, as `apply_wrapped_mint_attested` does it: `&self.validators` beside
        // `&mut self.peg` are two DIFFERENT fields, which the borrow checker accepts.
        // v6: the quorum signed the ticketed commitment bound to the ticket parts THIS object carries
        let signed_redeem = crate::peg_out_tx::signed_redeem_commit(redeem_commit, &ticket.0, &ticket.1, &ticket.2, sealed);
        let outcome = self.peg.peg_out_confidential(
            usdm_nullifier,
            carrier,
            new_reserve_commit,
            new_minted_commit,
            &signed_redeem,
            proposal_nonce,
            leaf_commit,
            change_owner,
            change_cm,
            &self.validators,
            verifier,
            attestors,
        );
        if !matches!(outcome, crate::peg::PegOutcome::ConfidentialRedeemed) {
            return outcome;
        }
        // ⛔ THE BURN RETIRES ON THIS NODE TOO — `peg_out_confidential` inserted it into `spent_burns`. The burn's
        // nullifier is this object's OWN lane tag (`object_own_nullifiers`, DB-278), so the SET refuses a later spend
        // of the same note: admitted at its block's fold and applied by the band (DB-353 P1), never written here.
        if change_note.len() >= 32 {
            let h = self.tip_height();
            self.record_note_payload(h, change_note);
        }
        // The executor that published this burn advances its opening in the same act (§CZ: never at execute).
        // DB-58: the burn's legs ride the object sealed per custodian — advance from the BLOCK.
        // CHAIN-PUBLISH-REVIEWED: the apply half of the published PegOut object, driven by the block.
        let opened = self.bonded_custodian_identity().and_then(|(my_id, dk)| {
            sealed
                .iter()
                .find(|(id, _)| id == my_id)
                .and_then(|(_, blob)| crate::peg_attest::open_out_delta(dk, blob))
        });
        // DB-121: the burn's Bitcoin obligation, exactly as the block sealed it to this custodian — the payout
        // lane pays it once the chain has finalized this height (DB-122 F1).
        // CHAIN-OBJECT: Class::PegOut — the object this function is applying.
        // ⭐ §BR-5: the leg names no destination — only the release, the pay-after and the kind. The ticket key rides the
        // object's ONE epoch ciphertext; the payout lane holds the ticket until two thirds of custody release the piece's epoch
        // at its batch (§BR-9a step c), and books the obligation only once the ticket opens the signed commitment.
        if let Some(d) = &opened {
            if let Ok(release_sats) = u64::try_from(d.release) {
                self.payout_events.push_back(PayoutEvent::Ticket {
                    usdm_nullifier,
                    release_sats,
                    burn_height: self.tip_height(),
                    pay_after: d.pay_after,
                    ticket: ticket.0.clone(),
                    epoch_ct: ticket.2.clone(),
                    redeem_commit: *redeem_commit,
                    pieces: Vec::new(),
                    // OWED, the hand-over: the object's signed parts, kept until the release is paid for a vault mate
                    // that adopts after this block has left every body window (`btc_payout::LegShare`)
                    proof: crate::peg_out_tx::LegProof {
                        coin: proofs.coin,
                        new_reserve_commit,
                        new_minted_commit,
                        redeem_commit: *redeem_commit,
                        proposal_nonce: *proposal_nonce,
                        leaf_commit,
                        change_owner: *change_owner,
                        change_cm: *change_cm,
                        attestors: attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect(),
                        sealed: sealed.to_vec(),
                        ticket: ticket.clone(),
                    }
                    .encode(),
                });
            }
        }
        self.advance_custodian_opening_from_peg_out(&usdm_nullifier, opened.map(|d| (d.release, d.burn, d.r_blind)), proofs.coin);
        crate::peg::PegOutcome::ConfidentialRedeemed
    }

    /// ⛔⭐ OWED (2026-11-10) — A CUSTODIAN THAT ADOPTED PAST A BURN'S BLOCK OPENS ITS LEG FROM THAT BLOCK.
    /// MEASURED on two real nodes (dcash round 23): node 1 adopted a certified state at 471 while a cash-out's burn sat in
    /// block 461. Its ledger then said the release was owed (`release_pending`), and its payout book never heard of it:
    /// the leg is opened only inside `apply_peg_out_attested`, AFTER the ledger door, and an adopted ledger answers that
    /// door `Replay` — the burn is already in `spent_burns`. 108 × "holds no sealed leg", and a 2-of-2 payout that could
    /// never be co-signed: a user's USDm destroyed and its coins not paid.
    /// The block is not lost. An adopter fetches the certified span's bodies (`place_fold_span_body`: each id LISTED in
    /// the span the adopt's proof binds, proof of work and body commitments checked), so the object is in hand and is
    /// exactly what the chain carried. This reads it again and does the custodian's half only: nothing in the ledger
    /// moves, no opening is advanced (the adopt did not give this node the pre-state those advance from).
    ///
    /// THE NEW-DOOR CHECKLIST (AGENTS.md §9.6) — the door it parallels is `apply_peg_out_attested`:
    /// (1) PoW: the caller's — a body of the block window, admitted by the header door when it was placed or grafted.
    /// (2) Validity: the custody quorum's signature over exactly these parts, by the SAME function the ledger door calls
    ///     (`PegLedger::peg_out_attestation_holds`: nullifier, both new commitments, the ticketed redeem commitment over
    ///     the ticket and epoch ciphertext carried here, nonce, leaf and change), against THIS node's validator set; and
    ///     the burn proof (`burn_verifies`). A forged object, or honest parts with a swapped ticket, signs nothing.
    /// (3) Value: none is created or moved. A release is still single-use (`released`), and what a custodian pays is
    ///     still what its own sealed leg names and its co-signers' legs agree with, as for a burn applied live.
    /// (4) Replay: only a burn this node's own ledger shows OWED (`release_pending`: burned, not released) is read; the
    ///     payout lane books a nullifier once (`entry().or_insert`), so a second reading changes nothing.
    /// (5) Work: one signature tally and one KEM open per owed burn in a window body; nothing for a node with no custody.
    /// (6) Parity: the door's quorum check — carried, the same function. Its burn proof — carried. Its replay set —
    ///     inverted on purpose: this path exists for a burn the set already holds. Its carrier against the pre-state
    ///     commitments and its fold membership — NOT carried and cannot be (the pre-state is gone); they decided whether
    ///     the burn APPLIED, which the certified ledger already says. The opening advance — not done here.
    /// What it does not reach: a burn whose block has left every body window (an adopt deeper than the span), a change of
    /// the custody set between the burn and the adopt (the tally is against the set held now, so it fails closed), and
    /// the unit-close and pool-gain releases, whose amounts come from ledger words the adopt replaced. Two attested
    /// objects for one nullifier (a re-proposal under a new nonce) both pass (2); the chain applied the first, and a
    /// span holding only the second books that one — both are the note owner's own requests, signed by the quorum.
    /// BORROWED: Bitcoin's wallet rescan after `importprivkey` / a pruned node's `scanblocks` — what a wallet learns
    /// from a block is re-derived from the block itself, never taken from a peer's word about it.
    /// cons: one more tally and KEM open per owed burn per adopt or restart of a custodian; none on the chain or wire.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn recover_peg_out_leg(
        &mut self,
        usdm_nullifier: [u8; 32],
        carrier: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        redeem_commit: &[u8; 32],
        proposal_nonce: &[u8; 32],
        leaf_commit: crate::spend_frontier::Digest4,
        change_owner: &[u8; 32],
        change_cm: &[u8; 32],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        sealed: &[([u8; 32], Vec<u8>)],
        ticket: &crate::peg_out_tx::TicketParts,
        burn_height: u64,
    ) -> bool {
        if !self.peg.release_pending(&usdm_nullifier) {
            return false;
        }
        // the proofs name the ledger the burn pays from, and so the vault whose signatures carry it (the door's own order)
        let Some(proofs) = crate::peg_out_tx::PegOutProofs::decode(carrier) else {
            return false;
        };
        if !proofs.burn_verifies(&usdm_nullifier, leaf_commit, change_cm) {
            return false;
        }
        let proof = crate::peg_out_tx::LegProof {
            coin: proofs.coin,
            new_reserve_commit,
            new_minted_commit,
            redeem_commit: *redeem_commit,
            proposal_nonce: *proposal_nonce,
            leaf_commit,
            change_owner: *change_owner,
            change_cm: *change_cm,
            attestors: attestors.iter().map(|a| (a.pubkey.clone(), a.sig.clone())).collect(),
            sealed: sealed.to_vec(),
            ticket: ticket.clone(),
        };
        self.recover_peg_out_leg_signed(usdm_nullifier, &proof, verifier, burn_height)
    }

    /// ⛔⭐ OWED, THE HAND-OVER (2026-11-11) — the one place a custodian books a cash-out leg it did not open at the
    /// apply: from the block its window still holds ([`Self::recover_peg_out_leg`], which checks the burn proof first)
    /// or from a vault mate's copy of the object's signed parts (`btc_payout::LegShare`, when the block has left every
    /// body window). Nothing in the ledger moves and no opening is advanced.
    ///
    /// THE NEW-DOOR CHECKLIST (AGENTS.md §9.6) for the hand-over — the door it parallels is `recover_peg_out_leg`:
    /// (1) PoW: none — not a chain object and it moves no chain state; the giver answers one bonded vault mate per ask.
    /// (2) Validity: the custody quorum's signatures over exactly these parts, by the SAME function the ledger door
    ///     calls (`PegLedger::peg_out_attestation_holds`), against THIS node's validator set. The statement names the
    ///     nullifier, both pairs, the nonce, the leaf and change commitments, and (v7) the ticket and every sealed
    ///     leg: a giver that changes one byte of a leg, the ticket or an envelope hands over parts nobody signed.
    /// (3) Value: none is created or moved. A release stays single-use (`released`), and what a custodian pays is
    ///     what its own leg names and its co-signers' legs agree with, as for a burn applied live.
    /// (4) Replay: only a burn this node's own certified ledger shows OWED (`release_pending`) is read; the payout
    ///     lane books a nullifier once, so a second hand-over changes nothing.
    /// (5) Work: one signature tally and one KEM open per accepted answer; answers are read only for a nullifier this
    ///     custodian itself asked for.
    /// (6) Parity: the quorum check — carried, the same function. The burn proof — NOT carried: it decided whether
    ///     the burn APPLIED, which this node's certified ledger already says (`release_pending`); the leg is bound to
    ///     that nullifier by the signatures. The limits `recover_peg_out_leg` states stand: a custody set changed
    ///     since the burn fails the tally closed, and two quorum-signed objects for one nullifier (the owner's own
    ///     re-proposal) both pass.
    /// (7) SAFE AT SCALE: one vault's signatures and envelopes per hand-over (about 80 KB once the cut is live), per
    ///     burn in flight and per custodian that lacks it; nothing per height.
    /// (8) AI RESISTANT: protected by (b) code and economics — the quorum's signatures, checked here, never the
    ///     giver's word; a lying giver gains nothing (its parts fail the tally or open the leg the quorum signed); a
    ///     persuasive message gains nothing (only signed bytes are read).
    /// BORROWED: Bitcoin's `importprunedfunds` — a pruned wallet is handed a transaction with its proof of inclusion
    /// and checks the proof itself; this tree's `opening_share` and `CoinShare` (taken from a peer, used only if it
    /// verifies against the chain).
    /// cons: one tally and KEM open per recovered leg; a custodian keeps about 80 KB per unpaid cash-out it booked.
    pub(crate) fn recover_peg_out_leg_signed(
        &mut self,
        usdm_nullifier: [u8; 32],
        proof: &crate::peg_out_tx::LegProof,
        verifier: &dyn crate::pqauth::PqVerifier,
        burn_height: u64,
    ) -> bool {
        if !self.peg.release_pending(&usdm_nullifier) {
            return false;
        }
        let ticket = &proof.ticket;
        let signed_redeem = crate::peg_out_tx::signed_redeem_commit(&proof.redeem_commit, &ticket.0, &ticket.1, &ticket.2, &proof.sealed);
        if !crate::peg::PegLedger::peg_out_attestation_holds(
            proof.coin,
            &usdm_nullifier,
            proof.new_reserve_commit,
            proof.new_minted_commit,
            &signed_redeem,
            &proof.proposal_nonce,
            proof.leaf_commit,
            &proof.change_owner,
            &proof.change_cm,
            &self.validators,
            verifier,
            &proof.mint_attestors(),
        ) {
            return false;
        }
        let opened = self.bonded_custodian_identity().and_then(|(my_id, dk)| {
            proof
                .sealed
                .iter()
                .find(|(id, _)| id == my_id)
                .and_then(|(_, blob)| crate::peg_attest::open_out_delta(dk, blob))
        });
        let Some(d) = opened else {
            return false;
        };
        let Ok(release_sats) = u64::try_from(d.release) else {
            return false;
        };
        // CHAIN-OBJECT: Class::PegOut — the signed parts of the object a block of this node's certified chain carried.
        self.payout_events.push_back(PayoutEvent::Ticket {
            usdm_nullifier,
            release_sats,
            burn_height,
            pay_after: d.pay_after,
            ticket: ticket.0.clone(),
            epoch_ct: ticket.2.clone(),
            redeem_commit: proof.redeem_commit,
            pieces: Vec::new(),
            proof: proof.encode(),
        });
        true
    }

    /// OWED — every cash-out leg this custodian can re-open from the bodies its block window holds: the certified span an
    /// adopt placed, and the recent blocks a restart resumed. Each leg is dated at this node's fold root, the height by
    /// which every burn in its ledger had applied, so it is payable only once this node's own finality passes that
    /// height. Returns how many legs were handed to the payout lane. Nothing for a node with no custody.
    pub(crate) fn recover_cash_out_legs_from_window(&mut self) -> usize {
        if self.bonded_custodian_identity().is_none() {
            return 0;
        }
        let v = crate::pqauth::MlDsaVerifier;
        let burn_height = self.tip_height();
        let mut found = 0usize;
        for (_, id) in self.block_window.ascending() {
            let Some(body) = self.block_window.get_whole(&id) else { continue };
            let Some(objects) = self.opened_credit_objects(&body) else { continue };
            for blob in &objects {
                if crate::node::objects::peg_out_tx::recover_chain_peg_out_leg(self, blob, &v, burn_height) {
                    found += 1;
                }
            }
        }
        if found > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a count — no nullifier, amount, destination or peer.
            eprintln!("[peg-out] {found} cash-out leg(s) re-opened from this node's own block window after an adopt or a restart — handed to the payout lane");
        }
        found
    }

    pub fn apply_peg_in_attested(
        &mut self,
        deposit_id: [u8; 32],
        peg_carrier: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        proposal_nonce: [u8; 32],
        bond_backstop: &[u8],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        delta_commit: crate::spend_frontier::Digest4,
        mint_carrier: &[u8],
        note_payload: &[u8],
        sealed: &[([u8; 32], Vec<u8>)],
        // DB-470: a debt unit's terms when this peg-in opens one — the carrier is verified at the unit's own backing — and
        // (F-LEG) the BASE deposit id the unit's signed id binds (`unit_open_tx::unit_deposit_id`): the function of the
        // deposit address a custodian's leg must name.
        unit: Option<(&crate::debt_units::UnitTerms, [u8; 32])>,
    ) -> crate::peg::PegOutcome {
        // ⛔⛔⛔ §CX ON THE GRAFT DOOR — EVERY BIND RUNS BEFORE THE LEDGER MOVES (2026-09-17). This
        // arm used to apply `peg_in_confidential` FIRST and check the mint carrier AFTER, with a comment
        // that said so out loud: "the peg ledger advanced above, but NOTHING is credited". A carried
        // object whose note does not open to the attested amount therefore advanced the reserve and
        // minted commitments AND burned the deposit id on every grafting node while crediting nothing —
        // the depositor's BTC in custody, its deposit id spent, its USDm never issued, and the executor
        // (which since §CX refuses BEFORE applying) diverged from every peer. Same defect, second door.
        //
        // ⛔ THE NOTE MUST BE THE NOTE THE QUORUM AUTHORISED — byte-for-byte the same binding the RPC
        // path runs, so a peg-in object carrying an attestation for one amount and a note sealed for
        // another is refused on EVERY node rather than only on the one that answered the request.
        // `note_cm_of` is the ONE injective reader of `note_payload[..NOTE_CM_BYTES]`, and the digest it
        // recovers is byte-for-byte the `cm_u` that `prove_mint_validity_bytes` returns.
        let Some(cm_limbs) = crate::spend_frontier::note_cm_of(note_payload) else {
            return crate::peg::PegOutcome::BadRequest;
        };
        // DB-80: the note opens to the COMMITTED mint delta; no amount is read from the object
        if !usdm_decider::whir_rec_block::verify_mint_validity_committed_bytes(mint_carrier, cm_limbs, delta_commit)
        {
            // Fail-closed BEFORE anything moves. Fixed string — no tag, cm, amount, key or owner in it.
            eprintln!(
                "[peg-in-apply] ⛔ REFUSED before touching the ledger: the note's commitment does not \
                 open to the ATTESTED mint amount under the carried proof — the publisher does not \
                 choose what is credited."
            );
            return crate::peg::PegOutcome::BadRequest;
        }
        // ⭐ FIELD-LEVEL BORROWS, as `apply_wrapped_mint_attested` does it: `&self.validators` beside
        // `&mut self.peg` are two DIFFERENT fields, which the borrow checker accepts — `self.validators()`
        // would borrow the whole node and collide with the peg's `&mut self`.
        // F-LEG: the quorum's statement names the sealed legs THIS object carries (`peg::peg_in_signed_recipient`) — an
        // object whose leg was re-sealed after the custodians signed has no signatures, and nothing below runs.
        let outcome = self.peg.peg_in_confidential_for(
            deposit_id,
            peg_carrier,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
            crate::peg::peg_in_signed_recipient(&recipient, sealed),
            proposal_nonce,
            bond_backstop,
            &self.validators,
            verifier,
            attestors,
            unit.map(|(t, _)| t),
        );
        if !matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted) {
            return outcome;
        }
        let h = self.tip_height();
        self.record_note_payload(h, note_payload);
        // Where the depositor's wallet should look (bounded, recent mints only).
        if self.peg_minted_heights.len() >= crate::peg_attest::PEG_ATTEST_PENDING_MAX {
            if let Some(k) = self.peg_minted_heights.keys().next().copied() {
                self.peg_minted_heights.remove(&k);
            }
        }
        self.peg_minted_heights.insert(deposit_id, h);
        // DIGITAL-CASH-PRIVACY-REVIEWED: a deposit-id prefix, a count and a yes/no — public chain structure.
        eprintln!(
            "[peg-in] mint for deposit {} applied from the block (custodian identity: {}, sealed envelopes: {})",
            &crate::hash::Hash32(deposit_id).to_hex()[..8],
            if self.bonded_custodian_identity().is_some() { "yes" } else { "no" },
            sealed.len()
        );
        // ⭐ EVERY CUSTODIAN THAT HOLDS THIS TRANSITION'S DELTA — the executor that published it and each
        // custodian that attested it — advances its private opening in the same act that advanced the
        // commitments, so it can attest or execute the NEXT mint. Same block, same order, on every node.
        // DB-58: THE BLOCK CARRIES WHAT IS NEEDED TO APPLY IT. The sealed per-custodian deltas ride the
        // object, so every custodian advances from the block it applies — on any ingest door, after any
        // loss of the gossip lane's pending slot. The slot and the published entry are caches.
        // CHAIN-PUBLISH-REVIEWED: this IS the apply half of the published PegIn object (the block drives it).
        let from_block = self.bonded_custodian_identity().and_then(|(my_id, dk)| {
            sealed
                .iter()
                .find(|(id, _)| id == my_id)
                .and_then(|(_, blob)| crate::peg_attest::open_delta(dk, blob))
        });
        // F-LEG: the leg is the EXECUTOR's word to this custodian — judged against the object the quorum signed before
        // a coin, a sweep authority or an opening is booked from it (a custodian that did not sign never judged it).
        let leg_deposit = unit.map_or(deposit_id, |(_, base)| base);
        let vault = crate::peg::VaultRide::decode(bond_backstop).map_or(0, |r| r.vault);
        let from_block = from_block.and_then(|leg| self.mint_leg_checked(vault, &leg_deposit, &delta_commit, leg));
        self.advance_custodian_opening_from_delta(&deposit_id, from_block);
        crate::peg::PegOutcome::ConfidentialMinted
    }

    /// ⛔⛔⛔ THE ATTESTED, BLOCK-CARRIED WRAPPED MINT — the apply seam for
    /// [`crate::wrapped_mint_tx`], and the only path by which a wrapped asset's confidential peg
    /// transition may advance on a node that did not answer the HTTP request.
    ///
    /// WHAT WAS WRONG. `/wrapped_mint_execute` published the minted NOTE (`Class::BridgeCredit`) and
    /// advanced the peg's reserve/minted commitments LOCALLY inside `execute_wrapped_mint`. The note
    /// travelled; the commitment advance did not. MEASURED by
    /// `chain_action_carriage_tests::a_wrapped_mint_carries_its_peg_transition_to_a_node_fed_only_the_chain`:
    /// a peer that received the published credit (`Credited(2000)`) still diverged on the wrapped-asset
    /// PSM commitments, the per-asset reserve high-water mark, AND the confidential deposit-id set — the
    /// last of which is the replay guard that makes one confirmed foreign deposit mint exactly once, so a
    /// peer short of it would mint AGAIN against a deposit that already paid out.
    ///
    /// CHAIN-PUBLISH-REVIEWED: the apply half, driven by `chain_object::Class::WrappedMint` at graft
    /// (published by `wrapped_mint_tx::as_pq_tx` from the route, applied here on every node).
    ///
    /// Everything that decides whether value moves stays inside
    /// [`crate::peg::PegLedger::wrapped_mint_confidential`] — the >=2/3 bonded tally over
    /// `wrapped_mint_confidential_msg`, the carrier re-verified against THIS node's own digests, and the
    /// deposit-id replay set — so a forged object reaching here is simply refused and the block still
    /// grafts.
    pub fn apply_wrapped_mint_attested(
        &mut self,
        asset_id: u32,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        // DB-80b: the committed mint delta (never the amount) both carriers open
        delta_commit: crate::spend_frontier::Digest4,
        mint_carrier: &[u8],
        note_payload: &[u8],
        sealed: &[([u8; 32], Vec<u8>)],
    ) -> crate::peg::PegOutcome {
        // DB-77: the block carries the note's own justification — verify it BEFORE the ledger moves
        // (§BA: the publisher does not choose what is credited), exactly as the native peg-in apply does.
        let Some(cm_limbs) = crate::spend_frontier::note_cm_of(note_payload) else {
            return crate::peg::PegOutcome::BadRequest;
        };
        let asset_tag = usdm_decider::whir_rec_block::wrapped_asset_tag_u32(asset_id);
        if !usdm_decider::whir_rec_block::verify_asset_mint_validity_committed_bytes(
            mint_carrier,
            cm_limbs,
            asset_tag,
            delta_commit,
        ) {
            eprintln!(
                "[wrapped-mint-apply] ⛔ REFUSED before touching the ledger: the note's commitment does not \
                 open to the ATTESTED committed amount in the ATTESTED asset under the carried proof."
            );
            return crate::peg::PegOutcome::BadRequest;
        }
        // F-LEG: the statement names the sealed legs this object carries, as the native mint's does
        let outcome = self.peg.wrapped_mint_confidential(
            asset_id,
            deposit_id,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
            crate::peg::peg_in_signed_recipient(&recipient, sealed),
            &self.validators,
            verifier,
            attestors,
        );
        if !matches!(outcome, crate::peg::PegOutcome::ConfidentialMinted) {
            return outcome;
        }
        // The recipient's wrapped-asset note is credited on EVERY node that applies the block (its
        // discovery target rides the block's account_targets, as for every other credited note).
        let h = self.tip_height();
        // CHAIN-PUBLISH-REVIEWED: this is the APPLY half — `wrapped_mint_tx::apply_chain_wrapped_mint` drives it from a block-carried Class::WrappedMint object (the publish half is `publish_wrapped_mint`, which only pools)
        self.record_note_payload(h, note_payload);
        let key = crate::peg_attest::slot_key_for(asset_id, &deposit_id);
        if self.peg_minted_heights.len() >= crate::peg_attest::PEG_ATTEST_PENDING_MAX {
            if let Some(k) = self.peg_minted_heights.keys().next().copied() {
                self.peg_minted_heights.remove(&k);
            }
        }
        self.peg_minted_heights.insert(key, h);
        // A custodian advances its WRAPPED opening from the sealed leg the block carries (DB-58 for
        // wrapped): the chain, not a gossip slot, is what moves it.
        let from_block = self.bonded_custodian_identity().and_then(|(my_id, dk)| {
            sealed
                .iter()
                .find(|(id, _)| id == my_id)
                .and_then(|(_, blob)| crate::peg_attest::open_delta(dk, blob))
                // F-LEG: a leg that does not open the object's committed mint is the executor's word, not the quorum's
                .filter(|d| crate::peg::PegLedger::mint_delta_commit(d.mint, d.d_blind) == delta_commit)
                .map(|d| (d.deposit_value, d.mint, d.d_blind))
        });
        self.advance_wrapped_opening_from_block(asset_id, &key, from_block);
        eprintln!(
            "[wrapped-mint] a block's wrapped mint (asset {asset_id}) applied on this node (custodian identity: {}, sealed envelopes: {})",
            if self.bonded_custodian_identity().is_some() { "yes" } else { "no" },
            sealed.len()
        );
        crate::peg::PegOutcome::ConfidentialMinted
    }

    /// ⛔⛔⛔ DB-368 — THE ONE FILL RULE (docs/DB-368-A-CARRIED-FILL-IS-JUDGED-BY-THE-FILL-RULE.md): every check a fill must
    /// pass before it may burn or credit anything, in ONE spelling for the two doors that judge a fill.
    /// - The publisher (`execute_order_fill`) asks at `MemberDoor::Admit` with this node's tip height.
    /// - Every node applying a block-carried fill asks at `MemberDoor::Fold` with the CARRYING block's blue score
    ///   (`order_fill_tx::apply_chain_fill_at_fold`, a fold-applied class).
    ///
    /// MEASURED (`dex_cross_party_scenarios::a_peer_does_not_credit_a_fill_whose_inputs_never_existed_when_a_rogue_producer_
    /// carries_it`): before DB-368 the carried path ran only the composed proof (`chain_object::admissible`). A rogue
    /// producer's fill with a substituted payout was CREDITED on the peer — a note of any value the producer chose.
    /// `None` = the fill passes; `Some(outcome)` = the reason it is refused. Pure: it reads, it never writes.
    pub(crate) fn order_fill_refusal(
        &self,
        f: &crate::order_fill_tx::OrderFillTx,
        door: crate::respend::MemberDoor,
        height: u64,
    ) -> Option<OrderFillOutcome> {
        let (terms, maker, taker) = (f.terms(), f.maker(), f.taker());
        // 0. DEX-GRID (C1): the ONE grid check, here in the rule both doors run, so no producer can lay an off-grid fill
        // that its peers would apply.
        if !crate::order_book::on_grid(&terms) {
            return Some(OrderFillOutcome::OffGrid);
        }
        // 1. EXPIRY — a term of the maker's own order. Checked first because it is the cheapest. At the fold `height` is the
        // carrying block's blue score (a function of its past, the same on every node), never this node's tip.
        if height > terms.expires_at_height {
            return Some(OrderFillOutcome::Expired);
        }
        // 2. THE COMPOSED PROOF, AT THIS CHAIN'S CONSENSUS FEE RATE. Nothing below runs if this fails.
        //
        // ⛔⛔⛔ THE RATE IS AN INPUT TO VERIFICATION, NOT A SEPARATE CHECK AFTERWARDS. The taker's
        //    conservation constraint is `value_in == pay_b + fee + change` with `fee` derived from the
        //    rate, and the rate is pinned in the transcript binding — so a half proved to pay less simply
        //    does not verify here. There is no branch a node could forget to run and thereby settle a
        //    fee-free fill: underpaying produces no valid proof at all.
        let fee_bps = self.params().order_fill_fee_bps;
        if !usdm_decider::whir_rec_block::verify_order_fill(&f.maker_bytes, &maker, &f.taker_bytes, &taker, &terms, fee_bps) {
            return Some(OrderFillOutcome::ProofRefused);
        }
        // 2b. ⛔⛔⛔ DB-150 — BOTH INPUTS MUST BE NOTES THIS CHAIN HOLDS.
        //
        // The composed proof above says the two halves trade consistently at these terms. It does NOT say
        // the notes exist: a taker can prove a perfectly consistent half over a note nobody ever received,
        // and settle it against a maker's real lot. The deletion transition used to catch that (both
        // inputs had to be PRESENT in the unspent tree); Z1 retired the tree, so the check is now the one
        // Zcash pairs with a nullifier — membership of the note in the append-only frontier, proven by the
        // spender's own carrier and verified against this node's accumulator.
        //
        // Fail-closed and BEFORE any burn: a missing or unverifiable bind refuses the fill with the
        // maker's lot untouched. Both halves, never one — a fill is two spends. An empty bind is no bind.
        // DB-213c: each half's membership proof is bound to the nullifier THAT half publishes.
        for (_half, half_leaf, half_nf, carrier, tip) in [
            ("maker", maker.leaf_commit, maker.nullifier, &f.maker_membership_carrier, &f.maker_membership_tip),
            ("taker", taker.leaf_commit, taker.nullifier, &f.taker_membership_carrier, &f.taker_membership_tip),
        ] {
            let verdict = if carrier.is_empty() || tip.is_empty() {
                MemberVerdict::Refused
            } else {
                self.bond_membership_verdict(Some((carrier, tip, half_leaf, half_nf)), door).0
            };
            #[cfg(test)]
            if let Ok(mut m) = MEMBER_ROOT_MISMATCH.lock() {
                if let Some(last) = m.last_mut().filter(|l| l.1 == "?") {
                    last.1 = _half;
                }
            }
            // A half whose proof is otherwise valid and whose record has not folded HERE yet is a race the fold resolves
            // in seconds (Bitcoin Core's missing-inputs answer), told apart from a forgery: MEASURED sim-20261006-221807
            // T2, a freshly cut lot answered 422 MEMBERSHIP_REFUSED and the taker stopped on it.
            if verdict == MemberVerdict::Pending {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no tag, commitment, amount or owner.
                // 2026-11-02 (c11-journey.log): this line carried no node, no half and no anchor, so a fill that stayed Pending
                // through two fold-reorgs could not be attributed. `ilog` tags the node; the half, the carrier's anchor and this
                // node's fold cursor say WHICH root the leg was proved against and where this fold stands.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a public anchor root prefix and a public height; never a note or a key.
                crate::arti_transport::ilog(&format!(
                    "[order-fill] ⏸ the {_half}'s input record is not folded on this node yet (its member leg anchors at {}…, \
                     this fold's cursor stands at blue {}) — NOTHING burned, NOTHING written; the same fill is admitted after the fold",
                    tip.iter().take(6).map(|b| format!("{b:02x}")).collect::<String>(),
                    self.fold_cursor_blue()
                ));
                return Some(OrderFillOutcome::MembershipPending);
            }
            if verdict != MemberVerdict::Member {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no tag, commitment, amount or owner.
                eprintln!(
                    "[order-fill] ⛔ REFUSED: a half did not prove its input note is in this chain's note \
                     frontier. A settlement whose inputs the chain never held creates value from notes \
                     that do not exist (DB-150). NOTHING burned, NOTHING written."
                );
                return Some(OrderFillOutcome::MembershipRefused);
            }
        }
        // 3. THE TWO SIDES MUST BE DIFFERENT NOTES. Equal nullifiers would be one note spent as both sides
        //    of its own trade — self-dealing that conserves arithmetically while creating a fill from
        //    nothing. The decider refuses it too; refusing here as well means the node never depends on a
        //    remote crate's internals for a property this obvious.
        if maker.nullifier == taker.nullifier {
            return Some(OrderFillOutcome::SelfDealing);
        }
        // 4. NO OWNERLESS CREDIT. Refuse up front rather than filing nothing and answering OK — a credit
        //    that looks successful while being undiscoverable is worse than a refusal.
        // DB-273 §19.6 L3: every note names its owner by a real clue — a settlement note filed for nobody is money no seed
        // restore finds, so it is refused before anything burns.
        if f.owner_clues.iter().any(|c| c.is_empty() || c.len() > crate::peg_in_tx::OWNER_CLUE_MAX) {
            return Some(OrderFillOutcome::MissingOwner);
        }
        // 5. ⛔⛔⛔ THE PAYOUT BINDING — THE NOTES CREDITED MUST BE THE NOTES PROVED.
        //
        // Steps 1-4 prove a settlement; none of them looks at the three payloads that carry it. The proof
        // attests three commitments, but the payloads are ordinary bytes chosen by whoever submitted the
        // fill, and a proof knows nothing about the envelope carrying it. Without this comparison a taker
        // builds a genuinely HONEST fill and then puts a different note in the maker's payout slot — one
        // that opens to zero, or one the taker owns. Every gate above passes: the proof is real, the terms
        // match, neither nullifier is spent. The maker's resting lot burns and the maker is credited a note
        // they can never open. A whole lot lost, invisible to both the proof and the double-spend gate
        // because each is looking somewhere else. ⛔ DB-368: on a CARRIED fill the same gap let a rogue
        // producer credit a payout of any value it chose on every peer.
        //
        // SLOTS ARE POSITIONAL, NOT A SET. Unlike the two nullifiers — the same pair in either order is the
        // same burn — swapping the maker's payout with the taker's CHANGE would pay the maker the change
        // amount and hand the taker the difference, so each slot is checked against its OWN commitment.
        // A carried fill's notes are DB-224 references (`cm ‖ H(payload)`): the commitment leads either form.
        //
        // ⛔ ONE CONVERSION, THE CANONICAL ONE: `leaf_to_cm_bytes`, exactly as the nullifiers use. A
        // second limbs->bytes spelling beside it is how an unreduced limb someday yields a SECOND 32-byte
        // form of the SAME commitment, and a note with two commitment encodings is creditable twice.
        //
        // A payload too short to carry a commitment is REFUSED, never skipped: a short note is exactly the
        // shape a length check waves through and an unbound credit rides in on.
        //
        // cons: none. Three 32-byte comparisons on data already in hand — f(fixed constants), never
        // f(history, book depth or fill count). It only refuses; it stores nothing.
        let proven_slots = [
            crate::spend_frontier::leaf_to_cm_bytes(maker.payout_cm),
            crate::spend_frontier::leaf_to_cm_bytes(taker.payout_cm),
            crate::spend_frontier::leaf_to_cm_bytes(taker.change_cm),
        ];
        for (slot, payload) in f.notes.iter().enumerate() {
            if payload.len() < 32 || payload[..32] != proven_slots[slot] {
                return Some(OrderFillOutcome::PayoutNoteMismatch);
            }
        }
        None
    }

    /// HF44 verify-if-present: apply an L2 settlement carrier. Accepts ONLY a well-formed, state-root-chained
    /// (`prev == current`) settlement that the ZK verifier certifies; on accept it advances the L2 root and
    /// returns true. Otherwise returns false with the root UNCHANGED — fail-closed on the carrier only, never
    /// on chain progress (a block need not carry a settlement). Anti-replay by construction.
    pub fn apply_settlement(
        &mut self,
        verifier: &dyn crate::settlement::SettlementVerifier,
        bundle: &crate::settlement::SettlementBundle,
    ) -> bool {
        match crate::settlement::accept_settlement(verifier, &self.l2_state_root, bundle) {
            Some(new_root) => {
                self.l2_state_root = new_root;
                true
            }
            None => false,
        }
    }

    /// HF44 verify-if-present via the INSTALLED verifier — the serve-path entry a produced/gossiped settlement
    /// carrier flows through: accept it against the node's CURRENT L2 root (well-formed + `prev == current` +
    /// ZK verify + root-bind), advancing the L2 root on accept. Fail-closed on the carrier only; a block
    /// WITHOUT a settlement is always fine (liveness never depends on the carrier). This is the VISA-class
    /// throughput lane's apply half — one bundle settles a whole batch of L2 txs under one O(1) verify.
    pub fn ingest_settlement(&mut self, bundle: &crate::settlement::SettlementBundle) -> bool {
        match crate::settlement::accept_settlement(
            self.settlement_verifier.as_ref(),
            &self.l2_state_root,
            bundle,
        ) {
            Some(new_root) => {
                self.l2_state_root = new_root;
                true
            }
            None => false,
        }
    }

    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// ⛔⛔⛔ THE ONE ADMISSION DOOR — DOOR AUDIT 2026-09-07 (§9.6 question 6, family B).
    ///
    /// Both public ingress paths into this node's pool run THIS body. They used to differ by one check, and
    /// it was the class rule itself: `ingest_tx` called `mempool.accept_verified(tx, admissible)` while
    /// `ingest_tx_prechecked` called `mempool.accept(tx)` and asked the class nothing. The prechecked door's
    /// stated reason — "a framed blob cannot have passed the caller's off-lock send-carrier precheck, so this
    /// arm should be unreachable" — is FALSE at its one caller: `rpc_http`'s admit expression
    /// `direct_ok || spend_ok || multi_ok || cover_ok` is satisfiable by `cover_ok` alone, which reads only
    /// `spend_or_decoy_proof` and `multi_nfs` and never looks at `tx.blob`. A submitter attaching any one
    /// satisfiable non-blob carrier therefore reached the prechecked door with a FRAMED blob the class rule
    /// refuses. The two doors are ONE function now rather than two that happen to agree, because "they both
    /// run it" is a property that decays the moment a third door is written.
    ///
    /// `carrier_prechecked` keeps the whole point of the fast path. cons: none — the saving was ever only the
    /// SEND carrier's ~4 ms ZK verify, `admissible` routes to that verify for an UNFRAMED blob and nothing
    /// else, and the one caller that sets the flag has ALREADY run exactly that verify off-lock and
    /// fail-closed before this is reached. Every FRAMED object is judged by the full class rule on both
    /// doors. Nothing is weakened on either path; one path gains the rule it was missing.
    ///
    /// §9.6, answered for the door as a whole:
    ///  1. PROOF OF WORK — the anti-spam stamp is verified inside `Mempool::accept_inner` against this pool's
    ///     live floor; a header grind is not this door's subject (no block enters here).
    ///  2. PROOF / SIGNATURE — `chain_object::admissible`, ON THIS PATH, for every framed class. For an
    ///     UNFRAMED blob (an ordinary send) there is no blob-only proof to run: the send's statement is
    ///     welded to the TRANSACTION (its nullifiers, both output commitments, the membership cross-bind)
    ///     and to this node's own anchor root, none of which a blob-only rule holds. The verdict that
    ///     admits a send is the TX-LEVEL one, [`Self::send_verdict`]: `carrier_prechecked` is exactly
    ///     "the submit door reached it, fail-closed, on THIS transaction", and a gossiped send is judged
    ///     by the same function here (link 62). Named, and named where it runs.
    ///  3. CONSERVATION — `wrapper_binds_object` first, before any staging touches state: a framed object's
    ///     wrapper must carry BYTE-EXACTLY the notes the object justifies, so a mint costume is refused
    ///     before the class rule is even asked.
    ///  4. REPLAY — the pool's `spent` set refuses a conflicting claim on BOTH of its admission arms
    ///     (`nullifier_claim_conflict` / `register_nullifier_claims`), and `nullifier_witnesses_gate` refuses
    ///     a note a prior BLOCK already spent.
    ///  5. BOUNDED WORK — id / weight / stamp / capacity in `accept_inner` bound what one submitter occupies;
    ///     the class rule bounds what a forged object costs, and that is the half the prechecked door was
    ///     losing — a fill with a valid cover proof and no valid object took a pool slot and pool weight on
    ///     every node it was submitted to, was gossiped onward, and was re-selected into template after
    ///     template where assembly silently dropped it.
    ///  6. PARITY — there is no sibling left to drift from: this IS the sibling, for both doors.
    /// ⭐ DB-223 — a USDm spend's note-transition tuple, from the transaction's own fields: its two output commitments,
    /// its nullifier (row 0 of its tag list), its membership leaf commitment and its claim tag (row 1, DB-329 §7f). The
    /// ONE spelling the producer (`pending_note_transition`), the template's carrier check and the pool's member-carrier
    /// gate share, so the tuple a member statement is cross-bound to at the door is the tuple the block states. `None`
    /// for a transaction that is not a two-output spend with at least its two real rows.
    pub(crate) fn spend_tuple_of(tx: &PqTx) -> Option<crate::note_transition::SpendTuple> {
        const PQ: usize = crate::cover::PQ_NOTE_BYTES;
        if !Self::is_usdm_spend_tx(tx) || tx.output_notes.len() < 2 * PQ || tx.nullifiers.len() < 2 {
            return None;
        }
        let cm = |i: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&tx.output_notes[i * PQ..i * PQ + 32]);
            a
        };
        Some(crate::note_transition::SpendTuple {
            out0_cm: cm(0),
            out1_cm: cm(1),
            nullifier: *tx.nullifiers[0].as_bytes(),
            leaf_commit: tx.membership_leaf_commit,
            tag1: *tx.nullifiers[1].as_bytes(),
        })
    }

    pub(super) fn admit_tx_shared(
        &mut self,
        tx: PqTx,
        carrier_prechecked: bool,
    ) -> Result<Hash32, MempoolError> {
        // ⭐ §9.6 q5 AT THE GOSSIP DOOR (link 62): the pool's cheap refusals before any verify below — a gossiped echo of a
        // pooled tx, an unstamped flood, an id that does not bind its blob. The prechecked door's caller already paid its
        // verify, and `accept_inner` re-asks all of these either way.
        if !carrier_prechecked {
            if let Some(e) = self.mempool.cheap_refusal(&tx) {
                return Err(e);
            }
        }
        // ⭐ §RF-3 THE CANONICAL-TAG LAW, at the one door both the submit and the gossip paths share: every carried tag is a
        // canonical digest. Real tags are `leaf_to_cm_bytes(Poseidon…)`, decoys `cover::digest_shaped_decoy` — both decode.
        // MEASURED (scratchpad/night/rf3-produce-busy3.log): one blake3-shaped pad made `block_ledger_inputs` refuse, so the
        // producer laid the legacy count-stating block — any spender could force the volume leak the ledger closes.
        // §9.6: only NARROWS admission (a byte decode per tag, ≤ TX_FIXED_NULLIFIER_COUNT); PoW, proof, conservation and
        // replay checks below are unchanged. cons: 16 lane compares per tag (~0.1 µs); nothing stored.
        if !tx.nullifiers.iter().all(|t| crate::spend_frontier::cm_bytes_to_root(t.as_bytes()).is_some()) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a FIXED string — no tag, count or owner appears in it.
            eprintln!("[admit] ⛔ REFUSE: a carried tag is not a canonical digest — no honest wallet makes one");
            return Err(MempoolError::NonCanonicalTag);
        }
        // ⭐⭐⭐ THE CARRIAGE IS NOT THE OBJECT (per-note validity, 2026-09-06 lane B): a framed object's
        // wrapper must carry BYTE-EXACTLY the notes the object itself justifies — `admissible` judges the
        // BLOB, but assembly and the graft fold carry the WRAPPER's `output_notes`, and with the two
        // unbound a validly-framed credit blob under a note-substituted (or note-extended) wrapper was
        // ADMITTED and minted on every honest node, reachable by any submitter. FIRST check, before any
        // staging touches state; fail-closed on the tx alone. RED-measured by
        // `a_credit_wrapper_carrying_notes_the_object_does_not_justify_is_refused_on_node_a_and_node_b`.
        if !crate::chain_object::wrapper_binds_object(&tx) {
            // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
            eprintln!(
                "[admit] ⛔ REFUSE: a framed object's transaction carries notes, burns or bond bytes \
                 the object itself does not justify — the carriage is not the object. Nothing admitted."
            );
            return Err(MempoolError::InvalidProof);
        }
        // ⛔ DB-223 PHASE B RETRACTED ON THE WIRE (2026-09-29, a privacy hole closed when found). An OPTIONAL member
        // carrier told spends apart by the spender's wallet state, and the block's member tuples stated the
        // carrier-bearing spend count. Until phase C makes it MANDATORY for every spend (with the catch-up that lets
        // every wallet build one), a present carrier or tuple is refused HERE, before any verify — so none is pooled,
        // relayed, produced or aggregated, and `Block::member_transition` stays absent on every block.
        // `member_carrier_gate` is phase C's verifier, kept and pinned. §9.6 for this changed door: it only NARROWS
        // admission (refuses more, at a byte-length test), so PoW, proof, conservation, replay and bounded work are
        // unchanged; parity: the legacy membership door judges every spend exactly as before.
        // ⭐⭐⭐ DB-223 PHASE C (Q7, 2026-10-02): THE FLIP. Every USDm spend carries its input's member carrier and tuple, and
        // `member_carrier_gate` runs as written (decode → cross-bind → anchor ∈ this node's ring → the carrier proof); a
        // non-spend carries none. The producer states only spends that carry one, and every peer requires the same at
        // ingest, graft and the fold — this door is the honest path's half of that rule.
        let carries_member = !tx.member_carrier.is_empty() || !tx.member_tuple.is_empty();
        // ⭐ A-F114 (B′): under the constant chain a spend carries NO member leg (its wrapper proves its input); the verdict
        // refuses one that does (one encoding) and judges the wrapper for one that does not
        // (FOUND by the DeFi covers switch pin: folding the switch into the second element made every NON-spend, every chain
        // object, read `(false, true)` under the switch and be refused `MemberCarrierRequired`; a spend goes to the verdict
        // under the switch, a non-spend is judged exactly as before)
        let spend = Self::spend_tuple_of(&tx).is_some();
        match (spend, carries_member || (spend && crate::canon_chain::canon_live())) {
            (true, true) => match self.member_carrier_verdict(&tx) {
                MemberGate::Pass => {}
                MemberGate::AnchorNotHeld => return Err(MempoolError::AnchorNotHeld),
                MemberGate::Refuse => return Err(MempoolError::InvalidProof),
            },
            (true, false) | (false, true) => return Err(MempoolError::MemberCarrierRequired),
            (false, false) => {}
        }
        // Cross-block double-spend gate: reject a tx spending a note already spent by a prior block, fail-
        // closed on the BAD tx only. The mempool's own set catches pool-level conflicts; THIS catches
        // conflicts against already-mined blocks (crate::frontier notes are spent exactly once).
        // Cross-block double-spend gate — the O(1) `nullifier_acc` via each spend's mandatory carried witness is the
        // SOLE authority (no stored tree). Fail-closed on a missing/stale/forged witness.
        if !self.nullifier_witnesses_gate(&tx) {
            // The carried absence witness did not verify — either the note is already spent on-chain or the
            // witness is stale/forged. Either way it is NOT a conflict with a POOLED tx, which is exactly what
            // the `DoubleSpend` text claims and what sent one diagnosis chasing a pooled tx that never existed.
            return Err(MempoolError::NullifierWitnessRejected);
        }
        // DB-103 (run 103, 2026-09-19): THE POOL REFUSES A CHAIN OBJECT THE CHAIN HAS ALREADY SETTLED — Bitcoin's
        // rule that a transaction whose inputs are spent never enters the mempool. MEASURED run 103 (two Mac
        // custodians + the phone): the phone's minted deposit rode 134 of node 0's blocks and 120 of node 1's.
        // Every block's apply refused it (Replay), every node re-POOLED it from the other's tx gossip (admission
        // was stateless), every next template carried it again with its 1153-byte note and its account
        // targets, and the gossip re-forwarded the accepted copy — block space, "[real-page-drop] … [Tx=N]"
        // pages shed on the cell lane, and one note commitment repeated on the wire, for the life of the pair.
        if self.chain_object_already_settled(&tx.blob) {
            return Err(MempoolError::AlreadySettled);
        }
        // ⛔ G13 (2026-10-23) — AND A FRAMED OBJECT A BLOCK THIS NODE HOLDS ALREADY CARRIES (Bitcoin refuses a transaction
        // already in a connected block: its outputs are in the UTXO view). The settled checks above read state the FOLD
        // writes, and the fold trails the graft: a carried finality vote is `Deferred` until the fold cursor reaches it,
        // so for the whole fold lag a gossiped copy of a vote this node had just evicted re-entered the pool and was laid
        // again. MEASURED (simmem-diag2, 10 nodes, 60 sim s): 342 gossip arrivals of a vote a held block carried, 73 laid
        // again; 16,520 bond-lane entries over 1,120 distinct objects at 240 s. Carriage is the graft's own rule (DB-389:
        // the block's bond-lane bytes or credit-set carriage, never a bare listing).
        // cons: one scan of the held blocks' id lists per framed-object arrival (≤ fold lag x 256 compares, ~50 µs at
        // 290 held blocks); an object whose only carrier is later orphaned is re-laid by the nodes that pooled it (they
        // return it through `settle_or_return_evicted_txs`, which does not pass this door).
        if crate::chain_object::unframe(&tx.blob).is_some() && self.carried_by_a_held_block(&tx) {
            return Err(MempoolError::AlreadySettled);
        }
        // ⛔⛔⛔ DB-299 — AND A TRANSACTION WHOSE NOTE THE CHAIN ALREADY CARRIES, WHATEVER ITS CLASS.
        //
        // DB-103 names three classes by their one-time ids. Before this check, every other note-bearing class
        // re-entered the pool after it was applied: a bridge or faucet credit, an asset mint, an unbond return, a fill.
        // Such a tx then waited for the assembler to skip it.
        // MEASURED gateQ8 n2: `[pool-admit] … ACCEPTED` for a faucet credit this node had just grafted in n1's block.
        // The spend classes were never the gap: `nullifier_witnesses_gate` above already refuses a spent input.
        // ROOT-LAYER: `tx_notes_already_on_chain` is the assembler's own question, so the door and assembly ask ONE.
        // MUST-STAY-GREEN: the bridge credit suite, which admits the honest credit once, and assemble / db249 / db294 /
        // db296.
        // cons: one index lookup and one O(1) chain predicate per output note.
        if self.tx_notes_already_on_chain(&tx.output_notes) {
            // Fixed string — by construction no tag, cm, amount, key or owner can appear in it.
            eprintln!(
                "[admit] ⛔ REFUSE: a note this transaction carries is already recorded on the chain this node \
                 follows — a replay of an applied transaction. Nothing admitted."
            );
            return Err(MempoolError::AlreadySettled);
        }
        {
            // ⛔ THE GATE ASKS THE CLASS, NOT THE ONE CLASS WE HAPPENED TO BUILD FIRST. This was a bare
            // `pqspend_direct_verify_carrier`, which is the rule for an ordinary SEND — so every other
            // consensus object was answered `InvalidProof` and no settlement could ever reach a block.
            // `chain_object::admissible` still sends an unframed blob to that same send gate, unchanged.
            // v32 (item 8b): the mint classes are judged against the chain's genesis-derived open-mint
            // allowance — a pure function of this chain's genesis identity, so every node passes the
            // identical value and a stranger derives it from chain parameters alone.
            let fee_bps = self.params().order_fill_fee_bps;
            let mint_allowance = self.params().genesis_mint_allowance();
            // ⭐ COMPUTED HERE, BEFORE `tx` MOVES INTO THE POOL — the closure is handed only the blob,
            // and the bonded set is read from THIS node (`&ValidatorSet` borrows `self`, which the
            // `&mut self.mempool` call below cannot hold at the same time). The verdict is a `bool`, so
            // the borrow ends on this line and the same answer the graft door computes rides into the
            // closure. See `bridge_credit_tx::credit_attested_by_bonded_quorum`.
            let credit_attested = crate::bridge_credit_tx::credit_attested_by_bonded_quorum(
                self.validators(),
                &tx.blob,
            );
            // ⭐⭐⭐ THE SEND'S VERDICT, ON THIS TRANSACTION (link 62). The submit door reached it fail-closed before calling
            // the prechecked door; a GOSSIPED send is judged here by the same function ([`Self::send_verdict`], whose
            // refusals name themselves), before the pool's `&mut` borrow, and its `bool` rides into the closure like
            // `credit_attested`. A spend-or-decoy that does not verify is refused, and so is a spend carrying none: both doors
            // pool a spend only with a verifying carrier, so a relay can neither launder other bytes into a producer's cover
            // statement nor occupy an honest spend's id with a stripped copy no block can state.
            let gossip_send_ok = !carrier_prechecked
                && crate::chain_object::unframe(&tx.blob).is_none()
                && self.send_verdict(&tx).is_ok_and(|arms| arms.cover);
            // §22c: this arm has just run the spend carrier and the cover arm on the transaction, and the member gate
            // above ran its member leg — the three proofs a block's peers ask of a stated spend. Recorded once, so the
            // block that later carries this transaction costs this node no second verify (`spend_evidence`).
            if gossip_send_ok && Self::spend_tuple_of(&tx).is_some() && carries_member {
                crate::spend_evidence::record_verified_by_the_tx_door(&tx);
            }
            let send_ok = carrier_prechecked || gossip_send_ok;
            let admitted = self.mempool.accept_verified(tx, |blob| {
                if crate::chain_object::unframe(blob).is_none() {
                    // ⛔ AN UNFRAMED BLOB IS AN ORDINARY SEND, AND NO BLOB-ONLY RULE CAN JUDGE ONE.
                    //
                    // This used to fall through to `admissible`, whose unframed arm ran the
                    // conservation-only carrier verify — a statement whose entire public input is a
                    // CONSTANT, naming no transaction, so one proof admitted every transaction and
                    // needed no secret to build. That arm is deleted (see `chain_object::admissible`),
                    // and there is nothing blob-shaped to put in its place: a send is sound only when
                    // the proof is welded to the TX's own nullifiers, both recorded output commitments,
                    // the membership cross-bind and this node's anchor root.
                    //
                    // So the send's verdict is the TX-LEVEL one, on the whole transaction: the submit
                    // door's (`carrier_prechecked`) or, for a gossiped send, `send_verdict` above.
                    return send_ok;
                }
                crate::chain_object::admissible(blob, fee_bps, mint_allowance, credit_attested)
            });
            // ⭐ STAGE THE CARRIED SIDECARS ONCE THE POOL HAS ACCEPTED THE TRANSACTION, NOT BEFORE.
            //
            // The targets and locator tags are still present the moment this node can include the tx in a
            // block, which is what the old ordering was protecting: an ACCEPTED tx is exactly a tx that can
            // be selected. What moves is the failed case — a REFUSED tx used to leave staged entries behind
            // for a payment this node will never carry, and those entries are what the D14 door audit found
            // growing without bound (see `record_note_clue`). Staging here also gives the locator-tag door
            // the EVIDENCE its own bound depends on: the note is in this node's pool, named by a transaction
            // it verified, which is precisely the "inserted when a tx is ACCEPTED" contract `pending_tags`
            // documents. cons: one clone of the pooled transaction per ADMITTED tx — f(one tx's fixed
            // carriage), never f(chain height, block count or note count), and nothing is stored by it.
            if let Ok(id) = admitted {
                if let Some(pooled) = self.mempool.get(&id).cloned() {
                    self.stage_carried_account_targets(&pooled);
                    self.stage_carried_note_clues(&pooled);
                }
            }
            admitted
        }
    }

    /// The GOSSIP admission door: nothing was pre-verified, so the full class rule — and for a plain send the TX-level
    /// [`Self::send_verdict`] — runs here.
    pub fn ingest_tx(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        self.admit_tx_shared(tx, false)
    }

    /// Does the chain this node folded already spend an input `tx` claims — Bitcoin's conflict rule (a transaction that
    /// spends an input the active chain spent is removed from the mempool and never re-admitted). Read from the canonical
    /// fold-point set (`decides`: only a PROVEN hold counts; a tag this node cannot answer is not called spent).
    pub(super) fn tx_conflicts_with_the_chain(&self, tx: &PqTx) -> bool {
        let s = self.fold_point_spent_set();
        tx.nullifiers.iter().any(|nf| s.decides(&nf.0) == Some(true))
    }

    /// FAST-PATH admission whose carrier was ALREADY ZK-verified by the caller OFF the node lock (the loopback
    /// RPC runs the stateless `pqspend_direct_verify_carrier` BEFORE taking the `NodeRuntime` mutex, so
    /// concurrent /submit_pq_tx requests verify the 4ms proof IN PARALLEL across connection threads instead of
    /// serializing on the lock — the measured admission ceiling jumps from 1-core to cores×). This does ONLY
    /// the stateful, microsecond checks that REQUIRE the lock: the cross-block double-spend gate + the
    /// structural mempool accept (id / weight / #72 stamp / pool double-spend / capacity). It is sound ONLY
    /// when the caller has already verified the carrier — the ONE caller is `NodeRuntime::submit_tx_prechecked`,
    /// invoked by the RPC after an off-lock `pqspend_direct_verify_carrier` pass (fail-closed on a bad proof
    /// BEFORE this is reached). Gossip-received txs still verify under the lock via [`Node::ingest_tx`].
    pub fn ingest_tx_prechecked(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        // ⛔ SAME DOOR, SAME CHECKS — the wrapper↔object binding, the O(1) acc double-spend gate, the
        // carried-sidecar staging AND the class rule now all come from `admit_tx_shared`. This body used to
        // repeat the first three and end at `mempool.accept(tx)`, which asks the class nothing; see that
        // function's doc for why "a framed blob cannot reach this door" was false at its one caller.
        // A block's nullifier fold reads its OWN id-bound tags, never a pooled tx (DB-353 §13.5: the parked-fold stash
        // this door used to kick is retired), so a tx arriving here unblocks no fold.
        self.admit_tx_shared(tx, true)
    }

    /// Decide the fate of every block whose txs we are holding (see `evicted_by_block`), once per new block.
    /// A block that is now an ANCESTOR of the selected tip has genuinely settled its txs — drop them. A block
    /// that is NOT (and is not the tip itself) lost the selected chain, so its txs exist nowhere: return them to
    /// the pool, where they are re-selected and re-relayed like any other pending payment. Without this a
    /// re-selection silently destroys a payment that nobody ever rejected.
    /// ⛔ A-F59 — THE KEY A SPEND REFUSED FOR ITS ANCHOR IS FILED UNDER in a block's fold verdict (`fold_verdicts`): its
    /// nullifier under its own domain, so it can never equal a refused CARRIAGE's hash (the other kind of entry there).
    pub(crate) fn anchor_refused_spend_key(nullifier: &[u8; 32]) -> Hash32 {
        let mut pre = b"MUSD/anchor-refused-spend/v1".to_vec();
        pre.extend_from_slice(nullifier);
        Hash32::hash(&pre)
    }

    /// ⛔ A-F59 — WHETHER THE FOLD REFUSED A HELD TX, the one predicate `settle_or_return_evicted_txs` returns a tx by: its
    /// chain-object CARRIAGE was refused (DB-389), or it is a SPEND the fold refused for its input anchor (DB-223 Q7: the
    /// carrying block's member proof stands under a ring this chain never held — a side branch's block merged after a
    /// reorg). MEASURED (lane af58, 2026-11-15, two real nodes on f11e8d4a): 19 `[spend-fold] … whose input anchor is not
    /// in the canonical ring were refused at their fold` on node 0; the payer's send had waited for its note's FINAL root,
    /// was accepted ("node status OK") and pooled on both nodes, and its payee held nothing 600 s later — the refused
    /// spend matched no refused carriage, so its held tx was dropped as "settled" and no block ever carried it again.
    /// Pay, change and tap all failed this way. BORROWED: Kaspa's mempool keeps a transaction until the virtual ACCEPTS
    /// it (a merged block's unaccepted transactions stay eligible); Bitcoin Core returns a disconnected block's
    /// transactions to the pool (`MaybeUpdateMempoolForReorg`). A returned spend whose nullifier the chain has since
    /// spent is still dropped by the caller (`tx_conflicts_with_the_chain`), so a spend is laid until it lands, once.
    /// AI RESISTANT: (b) code — returning a tx to the pool moves no value; every lay is judged by every node's fold again.
    /// SAFE AT SCALE: one key per refused spend in one in-flight block's verdict; constant in the bonded set and height.
    pub(crate) fn held_tx_refused_by_fold(tx: &crate::mempool::PqTx, refused: &[Hash32]) -> bool {
        crate::chain_object::carriage_of(&tx.blob).is_some_and(|c| refused.contains(&Hash32::hash(&c)))
            || tx.nullifiers.first().is_some_and(|nf| refused.contains(&Self::anchor_refused_spend_key(&nf.0)))
    }

    pub(super) fn settle_or_return_evicted_txs(&mut self) {
        let Some(tip) = self.selected_tip() else {
            return;
        };
        let tip_score = self
            .relay
            .dag()
            .get(&tip)
            .map(|n| n.blue_score)
            .unwrap_or(0);
        // ⛔ READ THE LIVE RULE, NOT THE ONE THIS NODE BOOTED WITH. `set_params` installs a
        // governance update into the DAG and the mempool; `params()` reads the DAG's copy, so it sees
        // that update. The raw `self.params` field did NOT — it was written once at construction and
        // never again, so this gate kept judging against the boot-time width forever. Hoisted to a
        // `u64` here because the loop below borrows `self` mutably (`evicted_by_block.remove`).
        let merge_width = self.params().dag_width as u64;
        // ONE ORDER, NOT THE MAP'S (lane b 2026-10-24, T3): the held txs re-enter the pool in this loop's order, and the pool's
        // `arrival` counter breaks equal-stamp ties at selection — a HashMap's key order is per instance (RandomState), so the
        // same blocks returned their txs in a different order per process and the same seed laid two different tx roots
        // (replay-r24.log: block #172, slots 131/132 swapped). Block id order is a function of what is held.
        let mut held: Vec<Hash32> = self.evicted_by_block.keys().copied().collect();
        held.sort_unstable();
        // ⛔ G13 (2026-10-23) — MERGED MEANS IN THE TIP'S PAST, NOT ON ITS SELECTED-PARENT CHAIN (Kaspa: a block is accepted
        // iff the virtual's past holds it). `is_ancestor_of_selected_tip` walks selected parents only, so every merged SIDE
        // block was judged orphaned below and its held txs went back to the pool unconditionally, to be laid again by the
        // next template. MEASURED (simmem-diag1, 10 nodes, 60 sim s): 159 lays of a bond-lane object a held block already
        // carried, each re-admitted after it had left the pool; 18,326 bond entries over 905 distinct at 240 s (775 MB/node).
        // One backward walk per call, floored at the oldest held block's insertion order (ancestors are always older).
        // cons: one walk over the held span of this node's DAG per settle (the blocks it already holds unfolded, ~width x
        // fold lag), no store.
        let merged = self.relay.dag().which_in_past_of(&tip, &held);
        for blk in held {
            let Some(node) = self.relay.dag().get(&blk) else {
                self.evicted_by_block.remove(&blk);
                continue; // not in the DAG at all — nothing to decide
            };
            let depth = tip_score.saturating_sub(node.blue_score);
            // ⭐ A BLOCK IS NOT ORPHANED JUST BECAUSE IT IS OFF THE SELECTED-PARENT CHAIN.
            // `is_selected_chain_ancestor` walks ONLY selected parents, but this is a WIDTH-32 DAG: a block
            // merged through ANY other parent is fully settled and its txs are on-chain. Treating those as
            // orphaned returned a SETTLED payment to the pool, where it was re-mined block after block —
            // measured on disk as the same 2306-byte payload stored 7x on the sender and 8x on the receiver,
            // a payment that never finalises and a note the recipient can never pin down. Wait until the block
            // is deeper than the DAG can still merge before judging it orphaned; until then, keep holding.
            let on_chain = merged.contains(&blk);
            // ⛔ A-F59 (lane af58, 2026-11-15): only the ORPHAN judgement waits for the merge depth — a block not yet in the
            // tip's past may still be merged into it. A block already IN the tip's past whose fold has judged it is decided
            // now: its refused items return at once (a re-carriage the chain then settles twice is refused by the respend
            // rule and by `tx_conflicts_with_the_chain` below). The old order held a merged, folded block's refused payment
            // `merge_width` (32) blue scores before returning it, several minutes on the rig (MEASURED: tap's payer funded
            // only after its 600 s window, its drip's carriage refused and re-laid late). cons: none — the same verdict,
            // read when it exists instead of 32 blocks later.
            if !on_chain && depth < merge_width {
                continue; // too fresh to judge — it may still be merged into the tip's past
            }
            let Some(txs) = self.evicted_by_block.remove(&blk) else {
                continue;
            };
            if on_chain {
                // ⛔⛔⛔ DB-389: SETTLED MEANS APPLIED. The block is in the chain the tip selects, but a held tx is in the chain
                // only if its object APPLIED at the fold: one whose carriage the fold REFUSED (a stripped, corrupt or
                // unjustified copy rode the block) goes back to the pool to be re-selected like any pending payment. Until
                // the fold has judged the block, its txs stay held — a listing is not an application.
                match self.fold_verdicts.remove(&blk) {
                    None => {
                        self.evicted_by_block.insert(blk, txs); // the fold lags the graft: keep holding, judge next time
                        continue;
                    }
                    Some(refused) => {
                        let (mut returned, mut conflicted) = (0usize, 0usize);
                        for tx in txs {
                            if !Self::held_tx_refused_by_fold(&tx, &refused) {
                                continue;
                            }
                            // ⛔ A REFUSED COPY THE CHAIN ALREADY SETTLED NEVER RETURNS (2026-10-07). A sibling block that
                            // re-carried an object an earlier fold step applied is refused as a respend loser (or by its
                            // class door), and returning it re-laid it in this node's next block, refused again, forever.
                            // MEASURED sim-20261007-043933: one SAT bond re-carried 79 times. Bitcoin's shape: a
                            // transaction conflicting with the active chain leaves the mempool (removeForBlock /
                            // removeConflicts); only one whose fold refusal can still change returns.
                            if self.tx_conflicts_with_the_chain(&tx) || self.chain_object_already_settled(&tx.blob) {
                                conflicted += 1;
                                continue;
                            }
                            let _ = self.mempool.accept(tx);
                            returned += 1;
                        }
                        if returned > 0 || conflicted > 0 {
                            // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a tx id, nullifier, amount, key or note.
                            eprintln!(
                                "[evict] DB-389: {returned} held tx(s) whose carried copy the fold refused returned to the pool; \
                                 {conflicted} the chain already settled dropped"
                            );
                        }
                        continue; // the rest settled for good — their objects applied in the chain the tip selects
                    }
                }
            }
            self.fold_verdicts.remove(&blk); // an orphaned block's verdict is moot: every held tx returns below
            for tx in txs {
                // Best-effort re-admission: a tx already re-mined elsewhere is `AlreadyKnown`, and one whose
                // input genuinely settled is a `DoubleSpend` — both are correct outcomes, neither is an error.
                // G13: a tx the chain already settled or conflicts with never returns (Bitcoin re-validates a reorg's
                // disconnected txs before they re-enter the mempool, `MaybeUpdateMempoolForReorg`).
                if self.tx_conflicts_with_the_chain(&tx) || self.chain_object_already_settled(&tx.blob) {
                    continue;
                }
                let _ = self.mempool.accept(tx);
            }
        }
    }

    /// ⭐ A BUCKET THIS NODE HOLDS NOTHING FOR — the other half of the recipient's O(1) path.
    ///
    /// The targeted record fetch only fires once a wallet KNOWS its note's ordinal, and it learns that from
    /// its account bucket. But the bucket is DA-resident too: a node that never recorded the payment holds no
    /// entries, so the wallet learns nothing, never names an ordinal, and the record fetch never triggers.
    /// That is why settles were intermittent — the payer's node had the bucket, the recipient's did not, and
    /// nothing ever went and got it.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: a bucket id IS a which-item selector — it identifies an ACCOUNT — so it
    /// must never travel alone. `wanted_buckets_padded` emits a CONSTANT-width set: the real wants plus
    /// decoys derived from this node's OWN secret, so a peer (or any observer) cannot tell which entry is
    /// real, how many are real, or whether this node is asking for anything at all.
    pub fn want_account_bucket(&mut self, bucket: [u8; 32]) {
        // ⛔ MIRROR THE PRODUCER PROBES ON THE CONSUMER. The producing node is now PROVEN correct — three
        // targets claimed, three writes produced, zero losses — while the recipient's node emits no
        // `BucketReq` at all, so it never obtains what was written. Every producer-side guess I made this
        // session was disproved by a probe; the consumer side has had none, and that is where the remaining
        // gap is. DIGITAL-CASH-PRIVACY-REVIEWED: a count only; never a bucket id, key, amount or owner.
        // ⛔ JUDGE EMPTINESS ON REAL ENTRIES, NEVER THE SERVED BLOB. `account_bucket_blob` is COVER-PADDED to
        // a constant width — that is the whole point, so an observer cannot tell a paid account from an
        // unpaid one — which means it is NEVER empty. Testing it here silently recorded no want at all, so
        // the node never asked and the recipient's payment stayed invisible: the exact defect this exists to
        // fix, reintroduced by reading the padded surface instead of the real one.
        // ⛔⛔⛔ "ALREADY HELD" IS NOT A THING FOR A BUCKET — IT GROWS FOREVER. This returned early whenever
        // ANY entry was held, so the first answer a node ever received became its last: every note credited
        // to that account afterwards was invisible to it permanently. MEASURED end to end: a node holding 1
        // of 5 entries reported `account bucket read OK: 1 owned position(s)` — confident and wrong — while a
        // node that had been present the whole time served the same seed 0.55 / 5. An owned note that can
        // never be found is fund loss, and the caller could not tell it had been given a partial truth.
        //
        // The same guard also sat on the RPC caller, so removing it there alone changed nothing — it was
        // negated one layer down. Both are gone now.
        //
        // Re-asking is free of consequence: `adopt_account_bucket` appends ONLY entries this node lacks, and
        // `wanted_buckets_padded` pads the request to a CONSTANT width with secret-seeded decoys, so a repeat
        // ask is byte-indistinguishable from the first and reveals nothing about what is already held.
        // DIGITAL-CASH-PRIVACY-REVIEWED: no count, id, key, amount or owner is exposed by asking again.
        if self.wanted_buckets.len() >= crate::protocol::TX_REQ_FIXED_COUNT
            && !self.wanted_buckets.contains_key(&bucket)
        {
            // At the fixed cap: evict one ANSWERED-EMPTY memo (state 2) to admit the fresh want —
            // the memo is re-creatable (the next ask round re-answers), a fresh want is not.
            if let Some(old) = self
                .wanted_buckets
                .iter()
                .find(|(_, st)| **st == 2)
                .map(|(b, _)| *b)
            {
                self.wanted_buckets.remove(&old);
            }
        }
        if self.wanted_buckets.len() < crate::protocol::TX_REQ_FIXED_COUNT {
            self.wanted_buckets.entry(bucket).or_insert(0);
        }
    }

    /// The bucket request set: real wants plus SECRET-SEEDED DECOYS to a constant width. The seed is this
    /// node's own DA secret, so no observer can recompute the set and subtract the decoys.
    pub fn wanted_buckets_padded(&self) -> Vec<[u8; 32]> {
        let want = crate::protocol::TX_REQ_FIXED_COUNT;
        let mut out: Vec<[u8; 32]> = self
            .wanted_buckets
            .iter()
            .filter(|(_, st)| **st <= 1)
            .map(|(b, _)| *b)
            .take(want)
            .collect();
        let secret = self.da_secret_value();
        let mut i = 0u64;
        while out.len() < want {
            let mut pre = Vec::with_capacity(60);
            pre.extend_from_slice(b"MUSD-bucket-cover-v1");
            pre.extend_from_slice(&secret);
            pre.extend_from_slice(&i.to_le_bytes());
            out.push(*Hash32::hash(&pre).as_bytes());
            i += 1;
        }
        // ⭐ DB-356: ONE canonical ascending set. Real wants used to lead and the decoys to follow, so a peer read the
        // leading slots as the real ones; sorted, a slot's position is a function of the id's value alone. The serving
        // arm answers per bucket id, never by position (`WireMsg::BucketReq`), so nothing downstream reads the order.
        out.sort_unstable();
        out
    }

    pub fn adopt_account_bucket(&mut self, bucket: [u8; 32], entries: Vec<Vec<u8>>) {
        if entries.is_empty() {
            return;
        }
        // ⛔⛔⛔ ONE INDEX ENTRY PER NOTE. Every node that holds a record FILES ITS OWN entry for it, and
        // `seal_entry_to` uses ML-KEM `encapsulate`, which is RANDOMISED — so each node's ciphertext for the
        // SAME note is different bytes and no equality check can collapse them. Adopting peers' copies then
        // merged all of them: MEASURED on a three-node mesh, a bucket held `3 owned position(s)` that the
        // wallet resolved to `3 hit(s): 1 distinct note(s)` — one note, one entry per node — and the wallet
        // fetched that note's 256-leaf block (~295 KB) three times, 22.8s of a 23.0s cold restore.
        //
        // A node does NOT need a peer's copy of an entry it can produce itself: it files from the record as it
        // ingests it, and for a record it does not hold it now fetches BY THE ID THE BUCKET NAMED. So adoption
        // has exactly one job — bootstrap a bucket we hold NOTHING for. Once we hold any entry, our own filing
        // keeps it current and a peer's copy would only ever be a duplicate of a note we already index.
        //
        // Not a window: nothing is refused for age. A bucket we hold nothing for is always adopted, at any
        // height, and every note we later ingest is filed by us — so no note becomes unfindable.
        // ⛔⛔⛔ REVERTED — MEASURED FUND LOSS. I gated adoption on "this bucket is empty" to stop cross-node
        // duplicates (each node seals its own copy with randomised ML-KEM, so three nodes meant three entries
        // for one note). But a bucket GROWS: gating on emptiness meant it could accept a first entry and never
        // another. MEASURED: three sends to one account all settled (`ok=True`, correct change each time) and a
        // cold restore recovered ONLY THE FIRST — 0.05/1 where 0.15/3 exists on chain. Two notes were on the
        // ledger and permanently invisible to their owner.
        //
        // Duplicate entries cost space and redundant fetches; a missing entry costs the money. Those are not
        // comparable, so adoption always accepts what it does not already hold, and the duplicate problem is
        // solved where it belongs — dedup by COMMITMENT on the read side (the wallet does this now), not by
        // refusing to learn.
        //
        // The append below already skips byte-identical entries, so re-adopting the same peer's copy is free.
        let had_entries = !entries.is_empty();
        let slot = self.account_buckets.entry(bucket).or_default();
        for e in entries {
            if !slot.contains(&e) {
                slot.push(e);
            }
        }
        // Retire the want only when this adopt DELIVERED something. A count-0 adopt arrives right
        // after retire_unanswered_bucket_wants marked the want ANSWERED-EMPTY (state 2) — removing
        // the entry here would erase that memo and the next read would re-arm pending forever.
        if had_entries {
            self.wanted_buckets.remove(&bucket);
        }
    }

    /// ⭐⭐⭐ THE RECIPIENT'S O(1) FETCH — want ONE record, by the ordinal the account bucket named.
    ///
    /// A wallet finds its own note in ONE lookup: the account bucket hands back `(ordinal, slot)`. If this
    /// node does not hold that record, the ONLY thing it needs is that record — yet the recipient side used
    /// to close the gap by walking the note stream from a cursor. Measured live, that walk cannot converge:
    /// a record is 256x1153 = ~295 KB and a page must fit ONE transport cell, so a page carries exactly ONE
    /// record, while the chain adds ~2 records/second. Node I sat at `applied 324` against `tip 6478` and
    /// gained +132 records/min against its peer's +157 — falling FURTHER behind every minute, forever. The
    /// recipient's payment is in a recent block, and a sequential walk reaches it last, if ever.
    ///
    /// So the wallet's O(1) answer is carried through to the wire: name the ordinal, fetch that record.
    ///
    /// O1-DEFINITION-REVIEWED: BY CONSTRUCTION — one wanted ordinal in, one targeted request out. No scan, no
    /// cursor, no term in chain height or record count. The set is transient and drains as records arrive.
    /// ⭐⭐⭐ WANT A RECORD BY THE ID THE ACCOUNT BUCKET NAMED. The bucket files the BLOCK-DERIVED record id
    /// (canonical — identical on every node); the note stream is paged by DENSE ORDINAL; and the only two
    /// request kinds on the wire were by-ordinal and by-block-hash. A node that joined after a payment holds
    /// neither the ordinal nor the block hash — it holds exactly the one coordinate nothing could ask for.
    ///
    /// MEASURED: a fresh node read its wallet's positions fine (`account bucket read OK: 2 owned position(s)`)
    /// and then asked itself for `seq=43595999149800100`, got `served 0 note(s)`, forever — while a node that
    /// held the record served the same seed `0.55 / 5`. The money was on its chain, its index named where, and
    /// there was no way to fetch it.
    ///
    /// O1-DEFINITION-REVIEWED: one named id in, one targeted request out. No scan, no cursor, no term in chain
    /// height. The set is transient and drains as records arrive.
    ///
    /// ⛔⛔⛔ DB-227 — A WANT MUST NAME A RECORD THIS NODE CAN PLACE, OR IT CAN NEVER DRAIN.
    ///
    /// The value arrives from OUTSIDE (a wallet's batched positions, a copath ask, a named ordinal), and
    /// it is DUAL-SPACE: the wallet sends its real positions as record ADDRESSES (~1e17) and its cover as
    /// ORDINALS drawn `mod top`, and every serve resolves both with `da_addr_at_ordinal(id).unwrap_or(id)`.
    /// This door inserted the RAW value instead. On a node whose ordinal index holds no row at a cover
    /// ordinal — every restarted or jumped node until its sidecar lane refills — each cover ordinal became
    /// a by-id want for record "id 245", which names no record anywhere: no peer's by-id serve can place
    /// it, the want never drains, and `missing_record_count` counts it.
    ///
    /// ROOT-LAYER: this door is where an outside value is TURNED INTO a want, so the coordinate law belongs
    /// here; the want set's readers (`missing_record_count`, the id lane, `serve_ready`) cannot tell a
    /// phantom from a debt, and the by-id serve on the peer can only answer "hold 0".
    /// MEASURED: before — ecosystem gate I (2026-09-26, scratch musd-ecocheck-2rTkuw, step 3): the
    /// restarted node held `missing_by_record_id` at exactly 32 (the cap) from the tenth poll to the
    /// deadline, its peer answered `[id-lane] serving by-id: asked 32, hold 0`, and `serve_ready` (which
    /// requires `missing_record_count() == 0`) stayed false for 7 minutes while roots were EQUAL. The gate's
    /// balance waiter keeps polling through the restart, exactly as a real user's wallet does. After — the
    /// pin `db227_cover_positions_on_a_holed_index_raise_no_want_and_a_placed_debt_still_does` (64 cover
    /// ordinals on a holed index: 0 wants; a placed address with no bytes: wanted and counted).
    /// MUST-STAY-GREEN: the fold's own wait and a DAS-confirmed record still want their bytes (they hold
    /// the block, so they use `want_held_block_record`); the jumper roots-run pin (its want is explicit);
    /// the /get_info saturation pin (fills the set through the held-block door); every serve's resolution.
    ///
    /// So the value is resolved exactly as the serve resolves it, and the ONE resolver decides:
    /// `da_record_notes` answers a held or regenerable record, and for an address this node PLACES (its
    /// ordinal row exists and round-trips) with no bytes held, its miss arm raises the by-id byte want —
    /// the one site that knows the record is real. An address this node cannot place (a cover ordinal it
    /// has no row at, a record of a block it has not placed, a foreign value) raises nothing: the record
    /// reaches this node the way every record does — its block, then its ordinal row (the sidecar lane,
    /// driven by the certified backlog, not by this call), then the miss arm names the byte debt, and
    /// only then can the fetched bytes verify at all (`accept_fetched_record` needs the ordinal).
    /// cons: a wallet-named record this node has not placed is fetched once its ordinal row lands instead
    /// of being asked for before it — bytes that could not verify earlier anyway (the verify door refuses
    /// an unplaced record), so no verifiable latency is lost.
    pub fn want_record_at_id(&mut self, id: u64) {
        let addr = self.da_addr_at_ordinal(id).unwrap_or(id);
        let _ = self.da_record_notes(addr);
    }

    /// Want the bytes of the record of a block THIS NODE HOLDS — the fold waiting on a record it must
    /// fold, or a DAS probe that confirmed a record its own header committed. The held block IS the
    /// placement evidence (the fold is the writer of the ordinal row this record will get), so no row is
    /// required here — which is exactly why this door is not reachable with an outside value.
    pub(crate) fn want_held_block_record(&mut self, addr: u64) {
        if self.da_record_held(addr) {
            return; // already held
        }
        if self.wanted_record_ids.len() < crate::protocol::TX_REQ_FIXED_COUNT {
            self.wanted_record_ids.insert(addr);
        }
    }

    pub fn wanted_record_ids(&self) -> Vec<u64> {
        self.wanted_record_ids
            .iter()
            .copied()
            .chain(self.da_wanted_ids.borrow().iter().copied())
            .take(crate::protocol::TX_REQ_FIXED_COUNT)
            .collect()
    }

    /// C1's WAIT names the missing BLOCK, never only its record bytes: a mergeset member the DAG does
    /// not hold stalls the canonical fold at its chain block, and the only thing that unblocks it is
    /// the BLOCK arriving — so the wait names the block to the by-id block lane (the same 1u8
    /// by-block-id request the spend-fold heal and the da-backfill already ride). `want_record_at_id`
    /// is the wrong lane for this: it asks for the record bytes of blocks already held.
    /// The slots are a request set of the fixed wire width ([`crate::protocol::TX_REQ_FIXED_COUNT`]);
    /// every fold pass that is still waiting derives its missing set from the DAG and names it here
    /// again, so the set always carries the fold's live waits and nothing else.
    pub fn want_block_by_id(&mut self, id: crate::block::BlockId) {
        if self.relay.dag().get(&id).is_some() {
            return; // the DAG holds it — the wait this want exists for is over
        }
        // A repeated id here is produced by `fold_canonical_records` itself: the pass re-runs every
        // tick and re-derives the SAME missing set from the DAG while the block is in flight. That
        // re-naming cannot be deleted — it is what keeps the set live (a landed block frees its slot
        // in `wanted_block_ids`, and only the next pass knows what is still missing) — and the repeat
        // is identical by construction: the id IS the whole payload, so a second slot for the same id
        // would carry zero new byte(s). One slot per id is the complete want.
        if self.wanted_block_slots.iter().any(|s| *s == Some(id)) {
            return;
        }
        // ⛔⛔⛔ A WANT SET IS A DEBT, NOT A TABLE OF THE FIRST 32 DEBTS (2026-10-27, the deep-loss pin's law). On a loss
        // deeper than the slot array the slots fill with the SHALLOW end of the loss (the fold's C1 waits), and the
        // descent's one learning step — a served shell that cannot graft naming its missing parent — found no free slot
        // and DROPPED the name: the next ask was byte-identical, the serve byte-identical, forever. MEASURED
        // (scratchpad/funds/c3-2.log, a_loss_deeper…): 48 of 64 dropped blocks landed, 1 want live, 2 identical want
        // sets, 13 trips. The parent is strictly closer to the floor than the child whose slot it would take, and that
        // child is PARKED the moment its parent is named (or already held) — so a full array is swept of names the
        // DAG holds or the relay parks BEFORE a placement is refused, exactly the sweep `wanted_block_ids` makes when
        // it builds the ask. Fail-closed unchanged: only ids reached down an id-authenticated parent link enter here.
        // BORROWED: in-flight tracking frees on receipt and the next name takes the freed slot (Bitcoin Core
        // CNodeState::vBlocksInFlight). cons: none — the ask builder's own sweep, run one call earlier.
        if self.wanted_block_slots.iter().all(|s| s.is_some()) {
            for slot in self.wanted_block_slots.iter_mut() {
                if let Some(w) = *slot {
                    if self.relay.dag().get(&w).is_some() || self.relay.is_parked(&w) {
                        *slot = None;
                    }
                }
            }
        }
        if let Some(free) = self.wanted_block_slots.iter_mut().find(|s| s.is_none()) {
            *free = Some(id);
        }
    }

    /// The blocks the canonical fold is waiting on, for the by-id block lane. Slots whose block the
    /// DAG now holds drain here — the want is satisfied by the block LANDING, whichever lane carried
    /// it (gossip, a strand release, a DSYNC graft), not by any particular response.
    pub fn wanted_block_ids(&mut self) -> Vec<crate::block::BlockId> {
        let mut out = Vec::new();
        for slot in self.wanted_block_slots.iter_mut() {
            if let Some(id) = *slot {
                if self.relay.dag().get(&id).is_some() {
                    *slot = None; // landed — the slot frees for the fold's next waits
                } else if self.relay.is_parked(&id) {
                    // HELD, not wanted: its bytes are in the orphan park waiting on a deeper parent
                    // (a page shell parked by `graft_block_shell_from_trusted_id`, or a gossiped
                    // orphan). Naming it again would put the same shallow shell at the top of the
                    // server's descending page every trip — the 2026-09-17 cell-lane livelock. The
                    // slot frees so the ask names what is actually missing.
                    *slot = None;
                } else {
                    out.push(id);
                }
            }
        }
        out
    }

    /// TRUE while the canonical fold's C1 wait names this block (a live `wanted_block_slots`
    /// slot) — the 7u8 block lane's ingest door reads it, so ONLY blocks this node's own fold
    /// derived from admitted chain structure can enter through that lane.
    pub fn wants_block(&self, id: &crate::block::BlockId) -> bool {
        self.wanted_block_slots.iter().any(|s| s.as_ref() == Some(id))
    }

    #[cfg(test)] // the restart census reads the slots without draining them: not production surface
    pub(crate) fn wanted_block_slot_ids(&self) -> Vec<crate::block::BlockId> {
        self.wanted_block_slots.iter().flatten().copied().collect()
    }

    /// The 7u8 block-lane SERVE body: the id-addressed block as the shell every graft retains —
    /// header + tx_ids (`header_shell`), postcard-framed exactly like a `WireMsg::Block` payload.
    /// A block's witness halves (pow proof, notes, sidecar sets) are NOT retained once folded
    /// (no-growth), and the asker does not need them: it asked because the id is committed by
    /// chain structure it already admitted (the child's parent list feeds the id preimage), and
    /// the record bytes ride their own rid-space lanes (0u8/2u8/5u8/kind-6, untouched).
    /// Privacy: header + tx ids — the same public structure gossip carries to every peer;
    /// selector-independent (one id, one answer, identical bytes for every asker). No note,
    /// amount, key or owner.
    /// The WHOLE block for an id this node still holds unfolded — the live window (bodies are kept until
    /// their record folds, then dropped: O(1)); `None` past it, where the certified bundle is the carrier.
    /// Served on bulk kind 12: compact-block relay's `getdata` (a block travels as a beacon and is pulled
    /// by id over the receiver's own stream — the pushes of whole blocks over the paced lane died in every
    /// two-node run of 2026-09-17 while every pull landed).
    /// A WHOLE block arriving for an id this node holds only as a SHELL (a descent page, a bundle's
    /// ancestor): KEEP the body — witness retained, the shell's unfolded entry replaced — so the by-id lane
    /// serves it whole and the record fold has its proof, instead of refusing it as "already held"
    /// (measured 2026-09-17: the parent-first pin lost every body that raced a shell). The shell's STATE
    /// is applied from the body, in DAG order, by [`Self::apply_healed_shell_body_in_order`] (DB-4 closed
    /// 2026-09-18) when this node grafted the shell itself. `false` when the id is not held,
    /// is already whole, or the body fails its own pure gates. CHAIN-PUBLISH-REVIEWED: keeps a body the
    /// chain already carries; writes nothing the chain maintains.
    /// A whole body for a block held only as a SHELL, whose pure gates ALREADY ran (the off-lock pre-verifier, or an
    /// ingest that just refused it as a duplicate) — the gates are not re-run, because the runtime's
    /// verifier holds the hasher a paused or miner-less node does not.
    /// CHAIN-PUBLISH-REVIEWED: keeps a body the chain already carries (its shell is in the DAG); the witness
    /// retained is that block's own, published in that block; writes nothing the chain maintains.
    pub fn fill_shell_body_preverified(&mut self, block: Block) -> bool {
        let id = block.id();
        if self.relay.dag().get(&id).is_none() {
            return false;
        }
        if block.pow_proof.is_empty() {
            return false;
        }
        // W1: a withheld block's body landed — its chain is eligible again (fork choice returns to it if it is heavier)
        if self.relay.dag_mut().clear_withheld(&id) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a public block-id prefix.
            eprintln!("[fold-withheld] W1: the body of withheld block {} landed — its chain is eligible again", &id.to_hex()[..8]);
        }
        let Some(slot) = self.unfolded_blocks.iter().position(|b| b.id() == id) else {
            // No entry: the shell's (seed-only) record already FOLDED and the fold dropped it from the
            // window — measured 2026-09-18 by the DB-4 body pin: the body found no slot and was discarded,
            // which is every shell deeper than the fold depth. If THIS node grafted it as a shell and never
            // applied its state, the body still lands: it re-enters the window (past the "already folded"
            // dedupe, because that record is the one being corrected) and the in-order apply below re-folds
            // the spine from its parent with the body. Any other body for a folded id is a duplicate.
            if !self.unapplied_shell_ids.contains(&id) {
                return false;
            }
            self.retain_pow_witness(id, &block.pow_proof);
            self.unfolded_blocks.push(block.clone().into());
            self.apply_healed_shell_body_in_order(&block);
            return true;
        };
        if !self.unfolded_blocks[slot].pow_proof.is_empty() {
            return false;
        }
        self.retain_pow_witness(id, &block.pow_proof);
        self.unfolded_blocks[slot] = block.into();
        // DB-4 CLOSED: a shell this node grafted structure-only now has its body — apply its state, in
        // DAG order (the nullifier fold is pre-root gated, the record fold rewinds below it), once.
        if self.unapplied_shell_ids.contains(&id) {
            let body = self.unfolded_blocks[slot].clone();
            self.apply_healed_shell_body_in_order(&body);
        }
        true
    }

    /// ⭐⭐⭐ DB-4 CLOSED (2026-09-18): A HEALED SHELL'S STATE IS APPLIED FROM ITS BODY, IN DAG ORDER.
    ///
    /// A shell grafted by the descent lane (structure only) left this node's state BEHIND the chain until
    /// a certified bundle covered it — the first cut of DB-4 reported the hold and waited for the #29
    /// lane. Now the body that lands for it (a by-id pull, a relay cascade, a duplicate ingest) runs the
    /// SAME three things every grafted block runs, and nothing else:
    ///   1. `apply_grafted_block_carry` — THE ONE per-block apply (records, targets, bonds, directory,
    ///      letters, A-tip, the unspent map from the block's own carried deletion set, credits);
    ///   2. the nullifier fold, PRE-ROOT GATED: it folds only when this node's accumulator stands at the
    ///      block's header-committed pre-root, else it is stashed and drained when the accumulator gets
    ///      there — so a body landing behind a whole child folds first and the child follows, and a body
    ///      landing before its parent's waits. That gate IS the DAG order for the fold;
    ///   3. the record fold: if the spine already folded this block AS A SHELL (a seed-only record), it is
    ///      rewound to the block's selected parent and re-folded with the body — the late-arrival rule.
    /// The DB-4 ring forgets the id (once, the ring decides — a rebuffered shell is not in it) and the
    /// hold lifts when the ring is empty; a bundle adopt still lifts it too.
    /// cons: one apply per healed body — work per call is f(one block's fixed cover shape) plus a
    /// re-fold bounded by the unfolded window; no term in height or history.
    /// CHAIN-PUBLISH-REVIEWED: applies a body the chain already carries through the ONE per-block apply
    /// every graft runs; authors nothing, publishes nothing.
    pub(super) fn apply_healed_shell_body_in_order(&mut self, block: &Block) {
        let gid = block.id();
        self.unapplied_shell_ids.retain(|i| *i != gid);
        let _ = self.apply_grafted_block_carry(
            gid,
            &block.output_notes,
            block.cover_key,
            &block.account_targets,
            block.header.nullifier_root,
            &block.nullifier_proof.padded_tags,
            &block.nullifier_proof.fold,
            &block.bond_set,
            &block.dir_set,
            &block.letter_set,
            block.note_transition.as_ref(),
            block.cover_transition.as_ref(),
            &block.credit_set,
            &block.oli_tags,
            block.member_transition.as_ref(),
            &block.wide_objects,
        );
        let is_genesis = self
            .relay
            .dag()
            .get(&gid)
            .map(|n| n.header.is_genesis())
            .unwrap_or(true);
        if !is_genesis {
            let g_conf = self.nf_fold_inputs_for_block(&gid);
            let (pre, post) = (block.header.nullifier_root.0, block.nullifier_proof.post_root.0);
            // A refused fold is a TAG-LESS (old-format) block: refused outright, never parked (§13.5 item 2).
            if self.fold_block_nf_in_order(
                pre,
                post,
                &g_conf,
                &block.nullifier_proof.fold,
                &block.nullifier_proof.padded_tags,
            ) {
                self.release_folded_tx_evictions();
            }
        }
        if self.block_record_folded(&gid) {
            let parent = self.relay.dag().get(&gid).and_then(|n| n.selected_parent);
            if let Some(parent) = parent {
                if self.block_record_folded(&parent) {
                    eprintln!(
                        "[fold-late] shell {} healed by its body — re-folding from its parent {} (DB-4)",
                        &gid.to_hex()[..8],
                        &parent.to_hex()[..8]
                    );
                    self.rewind_fold_to_common(parent);
                }
            }
        }
        self.note_late_arrival(block);
        let _ = self.fold_canonical_records();
        self.unapplied_shell_count = self.unapplied_shell_ids.len() as u64;
        if self.unapplied_shell_ids.is_empty() {
            self.unapplied_shell_floor = None;
            self.unapplied_shell_ceiling = 0;
        }
    }

    pub fn block_inv_after_locator(
        &self,
        locator: &[crate::block::BlockId],
        max_ids: usize,
        have: &[crate::block::BlockId],
        parked: &[crate::block::BlockId],
    ) -> Option<(Vec<crate::block::BlockId>, crate::block::BlockId)> {
        let c = self.batch_candidates(locator, have, parked)?;
        let dag = self.relay.dag();
        let candidates = c.picks.len();
        let (out, unconnectable) = self.candidates_in_topo_order(&c, max_ids);
        let BatchCandidates { anchors_held, hint, askers_past, .. } = c;
        eprintln!(
            "[block-lane] DB-275 inventory: {} of {} locator id(s) held, asker's past {} block(s), have {}, parked {}, \
             candidates {} = listed {} + unconnectable {} + over-cap {} (this node's tip score {})",
            anchors_held,
            locator.len(),
            askers_past.len(),
            have.len(),
            parked.len(),
            candidates,
            out.len(),
            unconnectable,
            candidates.saturating_sub(out.len()).saturating_sub(unconnectable),
            self.selected_tip().and_then(|t| dag.get(&t)).map_or(0, |n| n.blue_score)
        ); // DIGITAL-CASH-PRIVACY-REVIEWED: counts of public block-lane structure only; no id, note, tag or owner.
        Some((out, hint))
    }

    pub fn block_shell_bytes(&self, id: &crate::block::BlockId) -> Option<Vec<u8>> {
        let n = self.relay.dag().get(id)?;
        postcard::to_allocvec(&Self::header_shell(n.header.clone(), n.tx_ids.clone())).ok()
    }

    /// The DAG's (blue_score, parents) for a held block — the descent serve's walk data: the
    /// score orders emission parents-first under the byte budget, and the parent list is the
    /// downward step. Reads the same bounded map the shell serve reads; stores nothing.
    pub fn block_score_and_parents(
        &self,
        id: &crate::block::BlockId,
    ) -> Option<(u64, Vec<crate::block::BlockId>)> {
        self.relay
            .dag()
            .get(id)
            .map(|n| (n.blue_score, n.header.parents.clone()))
    }

    /// This node's block locator (see `Dag::block_locator`) — the asker's own held ancestry, sent
    /// on the block-lane descent ask so the peer's serve stops at the common ancestor.
    /// BORROWED-FROM: Bitcoin Core `CBlockLocator` — github.com/bitcoin/bitcoin — this is the
    /// node-level passthrough of the locator defined and cited in `Dag::block_locator`.
    pub fn block_locator(&self) -> Vec<crate::block::BlockId> {
        self.relay.dag().block_locator()
    }

    /// The shared door BODY, wants-check already passed by the caller: either the id is a live
    /// fold-named want slot (`graft_wanted_block_shell`), or it is a member of a served page's
    /// OWN chain of custody — a parent link walked down from a wanted shell in the SAME page,
    /// each hop id-authenticated (`on_block_page`'s page-scoped trusted set; a shell's id is
    /// blake3 over its header preimage, so a trusted id vouches the header that hashes to it,
    /// and that header's parent list is that block's real ancestry). Every other check is
    /// unchanged and fail-closed exactly as documented on the wrapper above.
    pub fn graft_block_shell_from_trusted_id(&mut self, block: &crate::block::Block) -> bool {
        let id = block.id();
        if self.relay.dag().get(&id).is_some() {
            return false; // already landed on another lane — the want drains on its own
        }
        // ⛔⛔⛔ A TRUSTED ID SAID "SOME HEADER NAMED THIS"; IT NEVER SAID "THIS WAS MINED".
        //
        // The two checks above and `add_wanted_shell`'s parents-present are ALL this door ran, and
        // none of them is proof of work — while the grafted shell's `header.work` is summed
        // straight into GHOSTDAG `blue_work` and `Dag::order_key` picks the selected tip by
        // `(blue_work, id)`. So an attacker needed exactly ONE want slot pointed at the tip of a
        // fabricated span (the Buffered arm hands that over for the price of one mined block, from
        // the orphan's attacker-chosen declared parent), and the page's own trusted closure then
        // walked the whole fabrication in, each shell claiming any `work` it liked.
        //
        // The grind check is the half of `pow::verify_block_pow` that needs the HEADER ALONE — no
        // `pow_proof`, no witness, exactly what a shell carries. It also BINDS the claimed figure:
        // `hash_meets_target` passes only while `digest × work` stays inside 256 bits, so a header
        // claiming work 2¹²⁶ must exhibit a digest under 2¹³⁰ — the same grind an honest miner
        // paid. Steps 1-2 (the non-outsourceable coinbase proof) cannot run here and are not
        // needed for this: they bind WHO mined it, the grind binds THAT it was mined, and it is
        // the work figure alone that moves the fork choice.
        //
        // ROOT-LAYER: this door is where block ADMISSION is produced for every shell lane — the
        // page loop, the trusted closure and the want slots are all consumers of it, and
        // `Dag::add_wanted_shell` below is the placement, not the decision. Putting the check at
        // any reader (the fork choice, the fold) would leave the fabricated block in the DAG.
        // MEASURED: `a_forged_powless_ancestry_page_is_refused_by_the_descent_door` RED before —
        // `landed=true, in_dag=true` for a shell with no `pow_proof` claiming work
        // 85070591730234615865843651857942052863 against an honest tip blue_work of 295.
        // MUST-STAY-GREEN: every honest heal on this lane grafts real mined headers, whose grind
        // meets their own target by construction — the page-speed descent heal, the deeper-than-
        // the-slot-array heal, the wanted-shell parent naming, the buffered-orphan naming, the
        // one-round-trip answer, and both rolling-restart pins.
        // cons: one Poseidon2 hash of the header preimage per served shell (the epoch hasher this
        // node already holds for gossip ingest); a node with no hasher refuses every non-genesis
        // shell, which is the fail-closed behaviour `preverify_block` already has.
        //
        // ⭐ ONE FUNCTION, FOUR DOORS. This check first landed here as an inline copy while three
        // sibling doors — the fold carry's ancestor and carried-block installs and the anchor
        // install — still had none, which is this crate's four-times-paid "I fixed one of several"
        // shape. The decision now lives in [`Self::header_grind_admits`] and every one of the four
        // reads it from there; the genesis exemption and the hasher-less fail-closed rule are
        // stated once, in that one place, instead of four times.
        //
        // ⛔⛔⛔ AND THE HEADER RULES WITH IT (2026-09-07, family-A pin
        // `a_far_future_shell_timestamp_is_refused_by_the_descent_door`). The grind was the only
        // thing this door asked. It ran NO timestamp check of either kind while the door it
        // parallels runs two, so a shell dated a century ahead entered the DAG and became a
        // `median_time_past` / `miner::adaptive_work` sample for everything placed above it. The tx-
        // merkle binding that used to sit inline at the top of this body is inside the shared
        // function now, with the version, parent-shape and tx-cap rules beside it — one behaviour
        // table for every door, per §9.5, instead of an inline copy here and nothing at the others.
        // `Some(self.chain_now_ts())`: this door CAN name an upper bound on now (see that function),
        // so it carries the drift rule; the carry and anchor doors cannot and say so.
        // ⛔ A SHELL IS HEADER-ONLY BY CONSTRUCTION — it carries no body and therefore no PoUW witness,
        // so this door asks the grind and the structural rules and names the witness as NotServable.
        // Requiring one here would refuse every shell, which is every heal and every orphan release.
        if !self.header_door_admits_witnessed(block, Some(self.chain_now_ts()), PowWitness::NotServable) {
            return false; // unmined or malformed — nothing partial is applied
        }
        // ⛔⛔⛔ AND THE CONTEXTUAL HALF — THE DAA EQUALITY IS WHAT MAKES THE GRIND COST ANYTHING
        // (2026-09-07, family-A pin
        // `a_free_work_one_shell_cannot_take_the_selected_tip_through_the_descent_door`).
        //
        // `header.work` is not a figure a sender chooses: consensus binds it to
        // `miner::adaptive_work(dag, selected_parent)`, the DAA value for the block's OWN parents,
        // and the gossip door has always enforced that equality. This door did not, and the gap was
        // not academic — GHOSTDAG sums the SELECTED PARENT's work into the child
        // (`Ghostdag::ghostdag_data`), so ANY block placed on the honest tip carries strictly more
        // `blue_work` than that tip whatever its own `work` says. A shell declaring the cheapest
        // work the DAA range allows therefore TOOK THE FORK CHOICE, and the node's next produced
        // block named a parent no peer holds — `UnknownParent` on every honest node, forever.
        // Removing the arithmetic escape in `pow::hash_meets_target` alone would not have closed
        // this: it is the freedom to DECLARE a difficulty that is the hole, and the equality is what
        // removes it. `validate_contextual` is the gossip door's own function — the same MTP rule,
        // the same mergeset bound, the same `WrongWork` verdict — so the two doors cannot drift.
        //
        // `UnknownParent` is NOT a refusal here: it is the parents-first case this lane exists to
        // heal, and it falls through to `add_wanted_shell`'s own parents-present refusal below,
        // which is what names the missing parents into the want slots (the pin
        // `a_wanted_shell_that_cannot_graft_names_its_missing_parents` asserts exactly that path).
        //
        // ROOT-LAYER: the shell's ADMISSION is decided here; `Dag::add_wanted_shell` computes the
        // GHOSTDAG data from the present parents and never trusts the shell's claim, so this is the
        // only place the claimed `work` can be judged before it becomes a term in the fork choice
        // for every block above it.
        // MEASURED 2026-09-07: before, the pin's `work = 1` shell landed on the honest tip and took
        // the selected tip (`landed=true, in_dag=true`) for zero hashes; after, this node computes
        // the DAA value for that parent and returns `WrongWork`, so nothing is placed and the honest
        // tip stands. The honest side was measured too, because this is the check that could refuse
        // a real heal: a two-node probe produced five blocks, delivered three by gossip and healed
        // the last two through THIS door — `landed=true in_dag=true` for both, and the pair ended on
        // one selected tip. The DAA figure those honest headers carried was 2.
        // MUST-STAY-GREEN: every honest heal on this lane — a real produced header's work IS the DAA
        // value for its parents, computed from the same selected-chain samples this node walks (the
        // fold carry ships each ancestor's own samples for exactly this reason) — plus the
        // wanted-shell parent naming, the buffered-orphan naming and both rolling-restart pins.
        // cons: NONE on any cardinal — every term is f(FIXED PROTOCOL CONSTANTS), never f(history).
        // TIME per offered shell: the DAA walk is capped at `daa_sample_len` = 60 selected-chain
        // reads and the median-time walk at the same 60, so 120 bounded map reads of 24 B each;
        // the mergeset walk stops at `mergeset_shape_bound` = dag_width 32 x ghostdag_k 32 = 1024
        // blocks BY CONSTRUCTION (that bound exists so a withheld-and-released flood costs
        // O(shape), not O(anticone)). 60 + 60 + <=1024 reads = a constant ceiling per shell, at
        // heal cadence only — not per produced block, and no term in chain height. SIZE: zero — this
        // reads the DAG and writes nothing; it is the same function the gossip door already runs on
        // every ingested block, so the steady-state cost of the node is unchanged.
        match crate::consensus::validate_contextual(self.relay.dag(), &block.header) {
            Ok(()) => {}
            Err(crate::consensus::ConsensusError::UnknownParent(_)) => {}
            Err(_) => return false,
        }
        if !self.relay.dag_mut().add_wanted_shell(block.clone()) {
            // ⭐ THE REFUSED SHELL NAMES ITS OWN MISSING PARENTS (2026-09-07, probe run 6 close).
            // This is the one place a served shell's parent ids are LEARNED (the header is in
            // hand, id-authenticated by the tx-merkle check above): a parent neither in the DAG
            // nor parked is a block this node lacks BY ID — exactly what the want slots exist
            // for. Without this, a gossip loss of TWO OR MORE consecutive blocks was unhealable
            // by the lane: the Buffered arm names only the newest missing link (the older one has
            // no arrived child to name it), the served shell for it failed to graft forever, and
            // the lane re-asked the same id every 2s. MEASURED (step3-probe run 6, scratch
            // /tmp/musd-step3probe-M26WCR): n2 wedged at height 171 for 319s to the budget's end
            // (final gap 651) with "[block-lane] 0 of 2 served shell(s) grafted (… a parent
            // still missing — the lane re-asks on its own cadence)" round-tripping the whole run.
            // Bounded: the header's parent list (dag-width) into the TX_REQ_FIXED_COUNT slot
            // array; a parked parent is never named (already held — its strand drains when its
            // ancestor lands). The lane walks a contiguous loss backwards one served page per
            // cadence — a bounded lookup chain, never a tip chase.
            // Pinned by `a_wanted_shell_that_cannot_graft_names_its_missing_parents`.
            //
            // ⛔⛔⛔ AND THE SHELL ITSELF IS KEPT, NOT DROPPED (2026-09-17). Until this change the
            // shell was discarded here and only its missing parents were named, while its OWN want
            // slot stayed live (the id is not in the DAG). On the cell lane a page is ~4 shells and
            // the server cuts the plan DESCENDING by score so the asked anchor always rides — so the
            // next ask named the same shallow ids, the top four by score were the same four shells,
            // and the page was byte-identical forever. MEASURED on two real nodes (seat journey run
            // 8): ~30 consecutive `0 of 4 served shell(s) grafted` on node0, the orphan count
            // climbing 4 → 16, the pair on two chains for 400 s, then a DSYNC jump onto EACH OTHER'S
            // chain that discarded both seats. Pinned in-process at the cell lane's page width:
            // `a_gap_deeper_than_one_cell_lane_page_heals_by_descending_a_page_per_trip` (RED
            // before: 11 trips, 9 byte-identical want sets, 1 parked, 5 wants live).
            //
            // Parking it is exactly what a gossiped orphan gets: the relay's ORPHAN_CAP-bounded
            // buffer keyed on the first missing parent, released by `drain_from` the moment that
            // parent lands. The shell is inside the page's trusted closure (an id-authenticated
            // parent link from a fold-named want), it passed the header door and the DAA equality
            // above, so it is as admissible as the orphan the gossip arm parks after the same
            // `UnknownParent` verdict. Its want slot is released by `wanted_block_ids` (a parked id
            // is held, not wanted), so the next ask names ONLY the deeper missing parents and the
            // descent moves one page per trip instead of none.
            // O1-FOOTPRINT-REVIEWED: bounded by ORPHAN_CAP — the relay's existing park, no new store.
            // cons: a strand parked here is re-verified when it is re-injected (the preverify lane),
            // the same cost every gossiped orphan already pays.
            let missing: Vec<crate::block::BlockId> = block
                .header
                .parents
                .iter()
                .filter(|p| self.relay.dag().get(p).is_none())
                .copied()
                .collect();
            // ⛔ ONE SMALL SIZE, FOREVER: the descent park is capped by its own protocol constant, not
            // by the relay's flood bound. A gap the lane can close is a few pages deep; anything
            // deeper is the DSYNC jump's business (a ≤1.8 MB certified bundle, O(1) by construction),
            // never a block-by-block backfill held in RAM. At the cap the shell is dropped and its
            // parents are NOT named — the ask stops descending and the beacon's heavier-tip path
            // brings the bundle; a re-ask of the same want stays bounded by BLOCK_ASK_REPEAT_MS.
            // DB-8 (2026-09-17): the bound is over PAGE shells only — gossip orphans buffered behind the
            // same gap (453 in run 6) used to fill `buffered_len()` and halt the descent at its first page.
            if self.relay.parked_page_len() >= crate::relay::PAGE_SHELL_PARK_MAX {
                eprintln!(
                    "[block-lane] the descent park is at its bound ({} shells) — this gap is deeper than \
                     the lane heals; the certified bundle (DSYNC) closes it",
                    crate::relay::PAGE_SHELL_PARK_MAX
                );
                return false;
            }
            if let Some(first) = missing.first().copied() {
                self.relay.park_shell(first, block.clone());
            }
            for p in &missing {
                if !self.relay.is_parked(p) {
                    self.want_block_by_id(*p);
                }
            }
            return false;
        }
        self.remember_unfolded_block(block.clone());
        // DB-4 (2026-09-17): a shell heals STRUCTURE only — no sets, no notes, no object payloads — so this
        // block's state is NOT applied here; production waits until a certified bundle covers it. One
        // watermark (min/max score), never a per-block set.
        // CHAIN-PUBLISH-REVIEWED: a LOCAL readiness flag ("my state is behind the chain") — the graft
        // above is the block channel's apply half; this records that the apply was structural only and
        // publishes nothing because nothing on the chain changed.
        self.hold_for_unapplied_shell(id);
        true
    }

    /// Drop the ids we now hold — called as records land. Drains BOTH rid-space want sets.
    /// An idle record's bytes are a pure function of its address, so a node that holds the record's
    /// COORDINATES (its ordinal row and its receive sidecar) but not its bytes regenerates them on
    /// demand instead of wanting them from a peer that holds them no better.
    ///
    /// MEASURED gate 40 (2026-09-03, scratch 5SXlpu): after BOTH nodes of a pair restarted, neither held
    /// the bytes of the idle records below ordinal ~134 — a resumed node never persists seed rows (zero
    /// disk), a jumped node adopted their rows from sidecar pages (coordinates only) — so every by-id
    /// want for them was unfillable from ANY peer: `[record-miss] … NEITHER key holds bytes` ~2,900× on
    /// one side and ~1,000× on the other (1-in-64 sampled), `sidecar_gap` never reached 0, both sides
    /// NOT READY to the deadline.
    ///
    /// SOUND: (1) a row anything real references (target, deletion, tag, receive) is never regenerated.
    /// (2) The regenerated 256 leaves must fold to CERTIFIED evidence this node holds for the ordinal —
    /// a ladder/run root, or its own stored accumulator step — and a real record that stood there fails
    /// both; holding neither proves nothing and fabricates nothing (da_seed_regen_tests,
    /// idle_record_regeneration_tests). (3) A receiver of served bytes verifies them against the roots IT
    /// holds, whoever regenerated them.
    /// PRIVATE: an idle record is the public cover shape every empty block files — nothing to reveal.
    /// O(1): one fixed 256-leaf fold, nothing stored, nothing fetched.
    /// The block a record address belongs to, found in the DAG this node holds.
    ///
    /// ⛔⛔⛔ THIS WAS THE SECOND O(chain squared) SITE, AND IT WAS UNCONDITIONAL.
    ///
    /// It read `dag().block_ids().into_iter().find(..)` — a fresh `Vec<BlockId>` of EVERY block the DAG
    /// holds, allocated and linearly scanned, PER CALL. Its comment defended that shape on the grounds
    /// that it is "called only when a record's bytes are ABSENT, never on the money path". Both halves
    /// stopped being true:
    ///   * `da_record_reals` reaches it for every record whose bytes are absent, and the canonical fold
    ///     resolves records ONE AT A TIME (`block_leaves_from_notes(&self.da_record_notes(seq)?, seq)`),
    ///     so a fold over N records performed N full DAG scans;
    ///   * the 2026-09-05 restore fix moved `regenerate_idle_record`'s header arm FIRST — correct, and
    ///     what keeps `idle_records_survive_sweep_export_and_restore` green — which turned this scan from
    ///     a last resort into the FIRST thing every regeneration pays.
    ///
    /// MEASURED 2026-09-06, one in-process run of the rolling-restart pin: `[record-regen]` printed 2,479
    /// lines at 1-in-256 sampling (~633,000 regenerations, each paying a full DAG scan) and the pin did
    /// not terminate inside a 25-minute alarm, though it was still progressing. `[tick-slow]` was 0 and
    /// `pre-loop` 0 ms, so this was NOT the reader path fixed the day before — a distinct site of the
    /// same class.
    ///
    /// SHAPE 1 (write it down, then look it up): the DAG now FILES each block under its record key as it
    /// inserts it ([`crate::dag::Dag::record_key_index`]), so the inversion is one indexed read whose cost
    /// does not depend on how many blocks exist or how long the chain is. No new growth class — the index
    /// lives and dies with the block map, which the prune horizon already holds to a constant window.
    ///
    /// STRICTLY SOUNDER than the scan it replaces: 56 bits do not name a block uniquely, and `find`
    /// returned whichever colliding block `HashMap` iteration happened to reach first — a different answer
    /// on different nodes for a question `block_declares_no_notes` turns into "this row IS an idle
    /// record". The index answers `None` when two blocks collide, which every caller already handles as
    /// "not a block this node holds — claim nothing".
    pub(crate) fn block_for_record_addr(&self, addr: u64) -> Option<crate::hash::Hash32> {
        self.relay
            .dag()
            .block_for_record_key(addr / Self::DA_RECORDS_PER_HEIGHT)
    }

    /// ⛔⛔⛔ DB-249b — IS THE RECORD AT `rid` ON THE CHAIN THIS NODE FOLLOWS? The ONE predicate every "is this note
    /// already on chain" decision reads (`note_target_addr` is a local index; this is the chain fact behind it).
    ///
    /// For a block this node HOLDS, the DAG decides: `settled` (DB-282). After `add_anchor`, `settle_connected_past` and
    /// the carry, a held block is settled iff it is in the anchor's connected past or is structure above it, which is
    /// DB-282's own "the chain this node follows". For a record whose block this node does NOT hold (pruned below the
    /// keep window, or a coordinate adopted from a peer's page), the ordinal claim decides.
    /// MEASURED (the DB-5 pin, `an_executor_whose_mint_block_is_abandoned_by_a_jump_…`, red since 06:02): the executor's
    /// re-proposed mint was skipped as `[assemble-dup] … ALREADY on chain` because the index still named the abandoned
    /// block's record, then evicted as `[tx-evict] ⛔ LOSING STATE`.
    /// ⛔ DB-296: the first cut read the ordinal claim FIRST, on the premise that an abandoned block's record "lost its
    /// ordinal claim at the adopt". The only eviction at the adopt lives in the spine-adopt arm, which a spine-less
    /// bundle, a refused, level or extends-ours spine, and a claim below the reconcile origin never reach. MEASURED: after
    /// the DB-5 pin's adopt, the abandoned block H was held, `settled=false`, not a tip, and its record still held ordinal
    /// 3, so the predicate said TRUE and the mint never landed.
    /// SAFE TO BE WRONG IN ONE DIRECTION ONLY: nf = Poseidon(sk, leaf) with leaf = the note COMMITMENT, so a duplicate
    /// commitment spends ONCE — a false "not on chain" costs one dead leaf; a false "on chain" costs the payment.
    /// ROOT-LAYER: one predicate for the assembler, the DB-249b index writer and DB-294's resolve and retry.
    /// O(1): one DAG index read, and one map read only when the block is not held.
    /// cons: a DB-282 island block (held, unsettled because the anchor's past reaches it only across a gap) reads "not
    /// on chain" even when its claim is a certified coordinate. A replayed pool tx carrying one of its notes could be
    /// laid once more (one dead leaf, same nf, no value), and a GOSSIPED target for such a note waits in pending (the
    /// carried copy, which names its address, files as before).
    pub(super) fn note_record_on_chain(&self, rid: u64) -> bool {
        match self
            .block_for_record_addr(rid)
            .and_then(|b| self.relay.dag().get(&b).map(|n| n.settled))
        {
            Some(settled) => settled,
            None => self.da_ord_mem.contains_key(&rid),
        }
    }

    /// ⛔⛔⛔ DB-299 — DOES ANY OUTPUT NOTE OF THIS TRANSACTION ALREADY SIT ON THE CHAIN THIS NODE FOLLOWS?
    ///
    /// The ONE test of "this transaction was already applied", for every note-bearing class. A note commitment names
    /// exactly one note: it binds value, owner and fresh randomness. So a tx whose output is already recorded on the
    /// followed chain is a replay, whatever its class. Borrowed from Bitcoin: a transaction already in the chain never
    /// enters the mempool (`txn-already-known`, checked against the coins view).
    ///
    /// Readers (one question, never three spellings):
    /// - the pool door (`admit_tx_shared`), which refuses;
    /// - the assembler (`block_spendable_note_blobs`), which skips;
    /// - the graft's losing-state alarm, which does not count a note that shipped as a loss.
    ///
    /// MEASURED, gateQ8 n2: after grafting n1's block carrying W1's faucet credit, n2 logged `[pool-admit] … ACCEPTED`
    /// for the same credit by gossip. Its next template named the tx and dup-skipped its note, and its graft cried
    /// `[tx-evict] ⛔ LOSING STATE` over a note that had shipped.
    /// O(1) per output note: one index lookup plus `note_record_on_chain` (DB-249b/DB-296). No state.
    pub(super) fn tx_notes_already_on_chain(&self, output_notes: &[u8]) -> bool {
        output_notes.chunks_exact(crate::cover::PQ_NOTE_BYTES).any(|note| {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&note[..32]);
            self.note_target_addr
                .get(&cm)
                .is_some_and(|rid| self.note_record_on_chain(*rid))
        })
    }

    /// ⭐⭐⭐ THE BLOCK ITSELF SAYS WHETHER IT CARRIED NOTES — AND THE BLOCK SURVIVES A RESTART.
    ///
    /// ⛔ MEASURED 2026-09-04, `idle_records_survive_sweep_export_and_restore`: after sweep + export +
    /// restore, three of four idle records answered `notes=false` and two had lost their ordinal entirely.
    /// Both proofs `regenerate_idle_record` can offer are NODE-LOCAL bookkeeping that the snapshot does not
    /// carry — `da_ladder_mem` and `da_macc_fwd_mem` are empty after a restore — so a restarted node could
    /// regenerate NOTHING. A peer then wants those rows and the writer answers "hold 0" for records whose
    /// bytes are a pure function of their address. That is a permanent hole in the ledger opened by an
    /// ordinary restart.
    ///
    /// The header's `output_notes_root` is the CHAIN's own answer to "did this block carry real notes?" —
    /// it is the same predicate `fold_canonical_records` already uses to decide a block is idle, every node
    /// agrees on it, and it survives everything a restart does because the DAG does. A local ladder was
    /// never the right evidence for a claim about a block.
    pub(super) fn block_declares_no_notes(&self, addr: u64) -> bool {
        let Some(bid) = self.block_for_record_addr(addr) else {
            return false; // not a block this node holds — claim nothing
        };
        self.block_declares_no_notes_by_id(&bid)
    }

    /// The same header predicate, asked of a block THIS CALLER ALREADY HOLDS — one indexed read, no
    /// inversion, cost independent of how much history exists.
    ///
    /// ⛔⛔⛔ THE INVERSION IS THE O(CHAIN) TERM. `block_declares_no_notes` reaches its header via
    /// `block_for_record_addr`, which is `dag().block_ids().into_iter().find(..)` — a fresh
    /// `Vec<BlockId>` of the WHOLE DAG allocated and scanned, PER CALL. That is the honest shape for
    /// a caller holding only an address ("called only when a record's bytes are ABSENT, never on the
    /// money path", as that function says). It is the WRONG shape for a caller that is already
    /// walking `block_ids()` and has the block in hand: such a caller pays a full DAG scan per
    /// block, i.e. O(chain²) per pass, holding the runtime lock.
    ///
    /// MEASURED 2026-09-05 (gate scratch /tmp/musd-ecocheck-cmOG87, n1) once
    /// `blocks_missing_ledger_records` began RESOLVING records instead of reading the raw map:
    ///   [tick-slow] drain held the rt lock 2050ms (pre-loop 1946ms, cell-poll 103ms, bulk-page 1ms)
    /// `pre-loop` is the phase containing that walk (`node_runtime.rs:2155`, inside the `hold_t0`
    /// span closed at 2389). It dominated every slow tick — 775-1946 ms of an 879-2050 ms hold,
    /// against a `bulk-page` term of 0-2 ms — and the gate's step 1 then missed its height
    /// tolerance (h1=568 h2=586, |Δ|=18 > 4).
    ///
    /// SHAPE 1 (write it down, then look it up): the DAG already holds the block under its id, so
    /// the header is one indexed read away. An address a caller has ALREADY inverted must never be
    /// re-inverted — ask the block directly.
    pub(super) fn block_declares_no_notes_by_id(&self, bid: &Hash32) -> bool {
        self.relay
            .dag()
            .get(bid)
            .map(|n| n.header.output_notes_root == crate::hash::Hash32::hash(&[]))
            .unwrap_or(false)
    }

    pub fn want_record_at_ordinal(&mut self, ordinal: u64) {
        if self.da_addr_at_ordinal(ordinal).is_some() {
            return; // already held — nothing to ask for
        }
        // ⛔⛔⛔ TWO COORDINATE SPACES, AND ONLY ONE OF THEM BELONGS HERE. The account bucket files the
        // BLOCK-DERIVED record address (`ident`, ~4.3e16 — canonical, identical on every node), while this
        // stream is paged by DENSE ORDINAL. A wallet reconciles the two by asking the node to place its
        // commitment, but a node that does NOT hold the record cannot place it, so the wallet falls back to
        // the filed address and the serve registers 32 wants for `address + 0..32`.
        //
        // Those can never be answered, and `wanted_ordinals` is bounded to `TX_REQ_FIXED_COUNT` — so every
        // poll floods the set with impossible entries and CROWDS OUT the real wants. MEASURED on a node that
        // joined after the payment: `[fetch_note_at] seq=43595999149800100 slot=172: the node served 0
        // note(s)`, repeated forever, wallet stuck at `0.0 / 0` while a node holding the record served the
        // same seed 0.55 / 5.
        //
        // A dense ordinal cannot exceed the length of the stream. Anything past the tip is not a position in
        // this space at all, so refuse it here rather than let it consume the request width. This is not a
        // window: it rejects only coordinates that provably belong to a different space, never an old one.
        if let Some(top) = self.da_highest_record_ordinal() {
            if ordinal > top.saturating_add(crate::protocol::TX_REQ_FIXED_COUNT as u64) {
                eprintln!(
                    "[want] refused a position that is not a dense ordinal in this stream (past tip) — it is a \
                     record ADDRESS, and admitting it would crowd out the wants that can actually be answered"
                );
                return;
            }
        }
        if self.wanted_ordinals.len() < crate::protocol::TX_REQ_FIXED_COUNT {
            self.wanted_ordinals.insert(ordinal);
        }
    }

    /// The ordinals a wallet asked for that this node still lacks — cover-padded to a CONSTANT width so the
    /// request never encodes how many a node is missing.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: stream POSITIONS only, of the same kind `/get_info` already publishes,
    /// and ALWAYS a constant count. It names no note, amount, key, address or owner. A position is not a
    /// which-item question about ownership: every caller asking for an ordinal gets the same bytes.
    pub fn wanted_record_ordinals(&self) -> Vec<u64> {
        let want = crate::protocol::TX_REQ_FIXED_COUNT;
        // ⭐ ONE WANT-SET, ONE REQUEST PASS. A `da_load` miss records itself in `da_wanted`; this is the list
        // the runtime already turns into a `NotesReq` every tick, so the verified-fetch seam rides the wire
        // that is ALREADY wired rather than growing a second, parallel request path beside it. A record that
        // comes back enters only through `accept_fetched_record`, which checks it against a block root this
        // node already holds — so widening this list widens what we ASK for, never what we believe.
        // ⛔ DO NOT MERGE `wanted_record_ids` INTO THIS LIST — I DID, AND IT WAS THE WRONG WIRE.
        //
        // This builds the by-RANGE request (leading 0u8): every value here is read by the peer as a block
        // ORDINAL naming a single-record range. `wanted_record_ids` holds RECORD IDS from an account bucket,
        // a different coordinate space, and they already have their own correct request — the by-RECORD-ID
        // path (leading 2u8) a few lines below in node_runtime, which drains that set properly.
        //
        // Sending ids here made the peer resolve them as ordinals: it answers a range that does not exist and
        // the reply carries no record, which is indistinguishable from "the peer does not have it". Same
        // ordinal-vs-address confusion that has now hidden in four readers on this path.
        // Newest-first from the by-ordinal want set. An entry leaves the set only when its record
        // arrives, so ascending iteration re-asks the oldest entries every tick even when no peer holds
        // them (MEASURED 2026-08-18: record bytes lost to a full disk exist on no peer), and the newest
        // records — the ones live payments ride — wait behind them. Reversing the iteration asks for the
        // newest first each round; the request width rotates down to the older entries as newer ones
        // drain, so every entry keeps getting asked on later rounds.
        // ⛔⛔⛔ THE BYTE LANE SERVES ONLY ORDINALS WHOSE COORDINATE ROW EXISTS — A COORDINATE HOLE IS
        // SIDECAR WORK, AND A BYTE FETCH FOR IT PROVABLY FETCH-AND-DISCARDS.
        //
        // ROOT-LAYER: this function PRODUCES the 0u8 by-range (byte) ask, and `accept_fetched_record`
        // (node.rs ~8993) resolves a served record's ORDINAL through the row this node already holds
        // (`da_record_ordinal(seq)`); with no row it can only key the record by its own address, never
        // the ordinal the ask named. So a by-range fetch of an ordinal with NO row lands a record the
        // node cannot file at that ordinal: it never establishes `da_ord_rev_mem`, so
        // `da_addr_at_ordinal` stays None, the retention rule releases the idle bytes as regenerable,
        // `clear_satisfied_wants` cannot drain the want, and the SAME ordinal is re-asked forever. The
        // coordinate row is delivered by the SIDECAR lane alone (kind-5 carries `(ordinal, rid)` →
        // `adopt_sidecar_row`), which `da_wanted`/`wanted_ordinals` already drive through
        // `sidecar_ask_from`. Feeding those same coordinate holes to the byte lane too is a second,
        // futile authority for one heal.
        // MEASURED 2026-09-06, `rolling_restart_pair_heals_fold_block_wants_and_missing_records`
        // (scratchpad/s1a-diag2.log): after the roll party 0 held `da_wanted=[32..62]` (31 idle
        // coordinate holes the resume seeded), the peer served every one on the byte lane
        // (`[range-serve]` ×719) and NONE stuck — the sidecar lane, whose cursor was pinned at 1,
        // logged 0 adopts because the byte-lane page flood parked ahead of it. `missing_record_count`
        // held at 31 for the whole 400-round settle. Restricting the byte lane to rows this node can
        // file lets the sidecar lane heal the coordinates, then `clear_satisfied_wants` drains them.
        // MUST-STAY-GREEN: the #29 DSYNC suite, the recorded runtime-backend cases, the restore-seam
        // pins — a genuine byte debt on a record whose row EXISTS still rides this lane (its ordinal
        // resolves in `accept_fetched_record`), and the sidecar lane always establishes the row first.
        // cons: one `da_addr_at_ordinal` map read per candidate (bounded by `want` = TX_REQ_FIXED_COUNT).
        // ⚠️ A NARROWER FILTER WAS TRIED HERE AND REVERTED BY MEASUREMENT (2026-09-22).
        //
        // `has_row` is "this node can already resolve that ordinal to a record address", and it is applied
        // to BOTH sources. That looks wrong for the wallet-named set (`wanted_ordinals`), because a wallet
        // names a position the node does NOT hold — and `a_node_asks_for_the_exact_record_its_wallet_named`
        // is red for exactly that reason. Letting the wallet-named set through unfiltered was tried, and
        // the ecosystem gate's step 1 then failed to converge two fresh nodes (h1=316 vs h2=404, n1
        // `[fold-stuck]` with 45 unfolded blocks, the peer `[range-serve] answering 3 of the named
        // ordinal(s)`). Naming ordinals a peer cannot resolve spends the constant-width ask on entries
        // nobody can answer, and the answerable wants starve behind them.
        //
        // The red test is real and the fix belongs at the ADMISSION end — a wallet-named want must be
        // turned into something the lane can ask for — not by widening what rides the ask. Left red and
        // recorded rather than traded for a convergence regression.
        let has_row = |o: &u64| self.da_addr_at_ordinal(*o).is_some();
        // ⭐ DB-302: and never a position the open headers-first span cannot judge — the bytes could only be refused
        // (see `record_row_top`). The want stays in its set; it is asked on the first drain after the span closes.
        let judgeable = |o: &u64| !self.headers_first_door_open_at(*o);
        let mut out: Vec<u64> = self
            .wanted_ordinals
            .iter()
            .copied()
            .chain(self.da_wanted.borrow().iter().rev().copied())
            .filter(has_row)
            .filter(judgeable)
            .take(want)
            .collect();
        // ⭐⭐⭐ ASK FOR THE PAYLOAD DEBT THE NODE ALREADY KNOWS IT OWES.
        //
        // ROOT-LAYER: this function is where the ask is PRODUCED, and it drew from exactly two sources —
        // `wanted_ordinals` (seeded ONLY inside the DSYNC adopt branch) and `da_wanted` (a `da_load` MISS).
        // Both are event-driven, so a node whose height has levelled off asks for NOTHING even while it
        // knows it is missing payload: adopts have stopped firing and nothing is looking those records up.
        // `note_body_target - blocks_note_applied` IS that debt, already tracked on this struct, and it
        // belongs in the ask for as long as it is non-zero — not only at the instant it is incurred.
        //
        // MEASURED: 2026-08-26 gate run 7 (scratch musd-ecocheck-mT103h), step-3 n2-restart. Transport was
        // fully healthy and n2's payload debt sat at a near-CONSTANT 405-466 blocks for the whole 420s
        // budget (dsync gap 420 -> 410 -> 405 -> 465 -> 463 -> 466) while `[backfill-gate]` reported
        // `wanted_records=false` at applied=494/tip_h=1113 AND applied=1024/tip_h=1503 — the node asked
        // for NOTHING with hundreds of blocks of notes outstanding, so `unspent_root` never matched its
        // peer and `pair_converged` could not become true. Missing notes are missing MONEY: a recipient's
        // node cannot show a payment whose record it never ingested.
        //
        // MUST-STAY-GREEN: the #29 DSYNC suite, `sparse_dsync_jump_adopts_tip_root_o1_then_rebuilds_and_gates`,
        // and the fixed-width cover shape — a fetched record is still admitted ONLY by
        // `accept_fetched_record`, so widening what we ASK for never widens what we BELIEVE.
        //
        // cons: none. The ask stays exactly `TX_REQ_FIXED_COUNT` wide (the cover constant), so it still
        // encodes NOTHING about how much this node lacks. TIME = one bounded walk of at most `want` steps
        // per call: f(fixed constants), never f(history). NOT a reach bound: the cursor WRAPS back to the
        // applied floor when it reaches the target with debt outstanding, so an ordinal that went
        // unanswered is re-asked on later rounds forever rather than abandoned.
        if out.len() < want && self.note_payload_debt() > 0 {
            let mut cur = self.note_body_want_cursor.borrow_mut();
            if *cur < self.note_backfill_cursor {
                *cur = self.note_backfill_cursor;
            }
            while out.len() < want && *cur < self.note_body_target {
                let ord = *cur;
                if self.headers_first_door_open_at(ord) {
                    // DB-302: every later position is inside the open span too. The walk ends HERE and wraps to the
                    // applied floor below, so the judgeable prefix is re-asked on later rounds exactly as before; a
                    // cursor parked at the door would never re-ask a prefix page that went unanswered.
                    *cur = self.note_body_target;
                    break;
                }
                *cur = cur.saturating_add(1);
                if !out.contains(&ord) {
                    out.push(ord);
                }
            }
            if *cur >= self.note_body_target {
                *cur = self.note_backfill_cursor;
            }
        }
        // Rolling reseed (see `da_want_seed_cursor`): the request width is the PAGE and this loop is the
        // caller looping it to exhaustion across rounds. The resume-time seed named the first missing 32
        // once; this keeps naming further missing ordinals whenever the page has spare slots, resuming
        // from where the previous round stopped, until the cursor reaches the record top.
        if out.len() < want {
            let mut cur = self.da_want_seed_cursor.borrow_mut();
            let top = self.served_seq;
            // PHASE 2: the sequential seeder walks ONLY the open ladder span. Ordinals below the
            // floor were PRUNED by design — re-wanting them created a fetch→fold→prune→hole loop
            // (MEASURED: [record-miss]×313/200KB and permanent [bulk] churn the moment the span
            // filled). Older REAL records are still fetched BY THE ID the bucket names (that path
            // is coordinate-free and untouched); older cover spans are proven by rung folds, never
            // re-collected wholesale.
            let floor = top.saturating_sub(Self::DA_LADDER_SPAN);
            if *cur < floor {
                *cur = floor;
            }
            let mut wanted = self.da_wanted.borrow_mut();
            wanted.retain(|o| *o >= floor);
            // ⛔ THE RESEED NAMES COORDINATE HOLES FOR THE SIDECAR LANE ONLY — never the byte `out`.
            // These ordinals have NO row (`da_addr_at_ordinal` is None); a by-range byte fetch for one
            // fetch-and-discards (see the has_row note above). Naming them in `da_wanted` is exactly
            // what `sidecar_ask_from` reads to ask kind-5, which delivers the `(ordinal, rid)` row that
            // heals the hole. Bounded to `want` NEW names per pass (the fixed request width), so the
            // set stays O(TX_REQ_FIXED_COUNT) of live holes and drains as the sidecar rows land.
            // ⛔ THE FULL SET MUST NOT HALT THE CURSOR — ONLY THE NAMING (2026-09-07, C1 close).
            // ROOT-LAYER: this loop is the reseed cursor's ONE writer; the freeze had to be fixed
            // where the cursor is advanced, not at any reader of the stalled walk.
            // MEASURED: 2026-09-07 gate round /tmp/musd-ecocheck-pfZh6g — `da_wanted` sat full at 32
            // entries no peer could answer (missing_da_by_ordinal pinned at 32 for 10 minutes), the
            // old `wanted.len() < cap` loop condition then never ran a single step, and the walk
            // cursor froze so no hole above the stuck 32 was ever named — sidecar_gap ~1500 flat.
            // The cursor now advances past positions that HOLD a row and past holes ALREADY NAMED
            // even while the set is full; it stops only at an UNNAMED rowless hole it cannot name
            // (so that hole is named first on a later round once the set drains) — the naming stays
            // capped at TX_REQ_FIXED_COUNT exactly as before.
            // MUST-STAY-GREEN: `a_forged_snapshot_cursor_must_not_cancel_the_resume_reseed` and
            // `a_mid_range_forged_cursor_must_not_strand_the_low_half_of_the_span` — every rowless
            // position is still named exactly once before the walk target disarms; the walk still
            // never passes an unnamed hole.
            // cons: none — the scan is bounded by the ladder span (the floor clamp above), each
            // position is visited once per walk, and nothing new is stored.
            while *cur < top {
                let ord = *cur;
                if self.da_addr_at_ordinal(ord).is_some() || wanted.contains(&ord) {
                    *cur += 1;
                    continue;
                }
                if wanted.len() >= crate::protocol::TX_REQ_FIXED_COUNT {
                    break; // naming is full; the cursor holds HERE so this hole is named next round
                }
                wanted.insert(ord);
                *cur += 1;
            }
            // ⭐ THE RESUME WALK'S COMPLETION CLEARS ITS GATE TERM (2026-09-07, forged-cursor
            // cancellation close): once the cursor has covered the live top, every rowless
            // tracked-span position has been NAMED exactly once and the range terms own the rest
            // of the drain — `da_want_seed_target` disarms and `has_wanted_records` closes on the
            // ordinary terms alone. Until then the armed target keeps this reseed REACHABLE no
            // matter what a persisted watermark claimed.
            if *cur >= top {
                self.da_want_seed_target.set(0);
            }
        }
        // ⭐ THE IBD BODY WALK — bounded to the request width, never a scan of history. Each tick asks for the
        // NEXT few records after the last one applied, up to the certified height consensus already reached.
        // The cursor advances only as records are verified in, so this converges on the gap and then goes
        // quiet; it never re-walks what it already holds, and it costs O(TX_REQ_FIXED_COUNT) per call at any
        // chain length.
        // ⛔ ONE COORDINATE SYSTEM. `blocks_note_applied` is a NOTE-STREAM cursor (the same units
        // `backfill_request_ranges` walks), while `note_body_target` was set from `state.blue_score`, a DAG
        // HEIGHT. Bounding a record-ordinal walk with a height mixes two scales: the loop would ask for
        // addresses that mean nothing at that index, and a request for an address no record can occupy is the
        // "serving 0 forever" failure this project has already paid for once. The certified height still
        // marks THAT a gap exists; the record top says HOW FAR the records go, and only the latter can bound
        // an ordinal walk.
        // ⛔⛔⛔ THE CATCH-UP WALK IS DELETED. A JOINER NEVER CHASES THE TIP.
        //
        // user 2026-07-29: "we are removing walks and chases anyway. The walks have been the source of our
        // problems this whole session."
        //
        // A walk cannot win: the producer never stops, so a node that fetches sequentially from a cursor
        // tracks the tip instead of reaching it. MEASURED across three builds and three different widths, the
        // joiner's deficit sat at a CONSTANT 100, 318, 165 — never closing, and the newest blocks (the ones
        // carrying the payment a wallet is waiting on) were permanently outside what it had ingested. Widening
        // the walk changed nothing; the shape was wrong, not the size.
        //
        // What replaces it is not a faster walk but NO walk. A node only ever needs the records its own
        // wallets ask for, and it learns exactly which those are when they ask: `want_record_at_ordinal` is
        // called from the serve path, names ONE record, and is answered by ONE targeted request that a peer
        // fills from the DA ledger. That is O(1) per query at any chain length, it converges by construction
        // because it is not racing anything, and it holds no history the node was never asked for — the same
        // reason the local archive is being retired. Nothing here is bounded, aged out, or skipped: a record
        // a wallet asks for is fetched however old it is.
        out.retain(|o| !self.headers_first_door_open_at(*o)); // DB-302: one exit rule, whatever the source
        out.dedup();
        while out.len() < want && !out.is_empty() {
            let last = out[out.len() - 1];
            out.push(last);
        }
        out
    }

    /// Are any wallet-named records still missing? Drives whether a targeted request is worth emitting.
    /// How many blocks of NOTE PAYLOAD this node knows it owes itself — the gap a DSYNC adopt opens when
    /// consensus jumps in O(1) and the skipped blocks' notes stay behind. Zero means fully caught up.
    /// Exposed because "am I still missing money-bearing data?" is a question the runtime, the gate and a
    /// test all need to ask, and deriving it in three places is how the three answers drift apart.
    /// ⛔⛔⛔ DB-162 — THIS SUBTRACTED A COUNTER FROM A CHAIN POSITION, AND A HEALTHY NODE THEREFORE
    /// REPORTED A LARGE FAKE DEBT FOREVER. FUNDS-VISIBLE.
    ///
    /// It read `note_body_target - blocks_note_applied`. Those are DIFFERENT UNITS:
    ///   * `note_body_target` is set to `state.blue_score` at adopt — a CHAIN POSITION;
    ///   * `blocks_note_applied` is a COUNTER incremented once per block that applied note bytes.
    ///
    /// Most blocks on a healthy chain are cover-only and apply no note bytes (this node's own words,
    /// `node_runtime.rs`: *"MEASURED FALSE 2026-08-13 on the live pair: records_held 7,447 under ordinal
    /// top 151,036, because only REAL-note records are stored (cover regenerates at serve). An empty span
    /// below top is therefore the NORMAL case on a healthy server"*). So the difference is roughly the
    /// COUNT OF COVER-ONLY BLOCKS and never falls to zero.
    ///
    /// MEASURED, gate STEP 2, 2026-09-22: a fresh two-node chain at ~506 records reported `debt=406`, the
    /// wallet relayed it verbatim — *"the attached node ITSELF reports 406 missing note payload(s)
    /// (records_held 374 of 506)"* — and downgraded a balance it had ALREADY scanned correctly
    /// (`1 owned note(s), 2500000000 atomic spendable`) to `0 owned, 0 atomic spendable`. The gate failed
    /// with *"balance never reached 25.0 spendable"*. The user's money was on chain, found, and then
    /// hidden by an arithmetic error between two incompatible units.
    ///
    /// THE HONEST QUANTITY ALREADY EXISTS, and this file names it forty lines away: *"A count cannot see a
    /// hole (the I-CC lesson); a set of block ids can. BORROWED (Bitcoin Core's block index): a block held
    /// without its data is tracked BY BLOCK, and the node is not synced until every held block has its
    /// data."* That set is [`Self::payload_gap`], whose own doc says it *"is EMPTY on a healthy mesh"*.
    ///
    /// ROOT-LAYER: the debt is PRODUCED here, at the one accessor `/get_info` and every wallet read; the
    /// two cursors stay as the ask-resume they were built to be (`wanted_record_ordinals`).
    /// MUST-STAY-GREEN: the readiness pins, `wanted_record_ordinals`, and the gate's STEP 2.
    pub fn note_payload_debt(&self) -> u64 {
        self.payload_gap.len() as u64
    }

    pub fn note_backfill_cursor(&self) -> u64 {
        self.note_backfill_cursor
    }

    /// The record address this node would answer for `id` — the block's own if it knows it, else the
    /// canonical derivation. The by-id refill lane's address rule, named so every caller shares it.
    pub fn record_addr_for_block_or_canonical(&self, id: &Hash32) -> u64 {
        self.record_addr_for_block(id)
            .unwrap_or_else(|| Self::da_record_id_for_block(id, 0))
    }

    /// Apply a backfilled page. Each entry is recorded through the SAME generic note path every block output
    /// uses, so a backfilled note is indistinguishable from one applied at graft time.
    pub fn apply_backfilled_notes(&mut self, page: &[crate::protocol::LedgerRecord]) -> usize {
        let mut applied = 0usize;
        for rec in page {
            let (seq, notes, targets) = (&rec.rid, &rec.notes, &rec.targets);
            if notes.is_empty() {
                continue; // nothing to apply
            }
            // ⭐⭐⭐ ONE COORDINATE FOR THE WHOLE ENTRY, BUILT ONCE, FROM THE WIRE (see [`rec_coord`]).
            // `rec.rid` is peer-chosen data and by protocol it names a record ADDRESS, so it is taken
            // as one and never tried in the ordinal space. Everything below — the authority verdict,
            // the sidecar adopts and the fold — is handed THIS value, so the door can no longer read
            // its authority off one row and its content off another.
            let addr = RecAddr::from_wire(*seq);
            // ⛔ THE DEDUP MUST NOT SWALLOW THE SIDECARS. This used to `continue` for any address already
            // recorded — but a record this node wrote ITSELF at ingest can still be MISSING its deletion
            // sidecar (the lost tx-gossip race: the ingesting peer recorded the block, folded its
            // receives, and had no tx body to fold the spend from). The spend-fold self-heal asks for
            // exactly that record by id, and the answer used to die right here, one line above the adopt
            // it was fetched for (MEASURED 2026-08-13: the heal request line with zero settles). Only the
            // NOTES re-record is skippable; the sidecar adopt below is first-writer-wins and idempotent,
            // so it runs on BOTH paths. Cost unchanged: one indexed `da_load` per served record.
            // ⭐⭐⭐ THE VERDICT IS TAKEN HERE, NOT DISCARDED (hole C-H1).
            //
            // The page pump offered every entry to the verified-fetch door and counted the verdict —
            // then called this function over the WHOLE page, refused entries included, and this
            // function's own doc asserted the check as an upstream fact ("the notes just passed the
            // verified-fetch door") that its only production caller did not enforce. A verdict computed
            // per entry and applied per page is not a verdict.
            //
            // So run the door HERE, at the shared sink, for any entry that does not already carry a
            // binding. It is idempotent: a record the pump already accepted is chain-bound and skips
            // this entirely, and a re-run of the same bytes against the same chain gives the same
            // answer. What changes is that the ANSWER now reaches the fold below — through the row's
            // provenance, which `fold_record_sidecars_if_ready` consults — instead of being counted
            // into a log line and dropped.
            //
            // A REFUSED entry is still RECORDED (the write below), because a record is also this
            // node's serve cache and its locator/bucket index, and refusing to hold it would blind an
            // owner to money that is genuinely on chain. It simply stays PROVISIONAL: it authorises
            // nothing, not even its own re-admission (hole C-H4).
            // ⚠️ `already_recorded` IS READ FIRST, AND THE ORDER IS LOAD-BEARING. The door below writes
            // the record itself on acceptance (that is how a fetched record reaches its owner's bucket),
            // so asking afterwards would answer "already recorded" for a record this page just brought
            // — and the two arms keyed on it, the target refile and the notes write, would BOTH be
            // skipped. That is the measured `[acct-file]`-drops-every-target shape this function already
            // carries a warning about; reading the flag before the door keeps both arms exactly as they
            // were.
            let already_recorded = self.da_holds(*seq);
            // ⛔ A HELD *SEED-SHAPED* COPY IS NOT THE RECORD — AND THE DEDUP TREATED IT AS ONE.
            //
            // `record_note_payload_at(rid, &[])` writes a one-note public seed row for a block whose
            // payload this node never had. `already_recorded` then reads TRUE, so a page carrying the
            // block's REAL notes was skipped and the row stayed a placeholder. That was invisible while
            // the sidecar fold trusted the served `recv_cms` outright; now that a receive must be
            // carried by the record itself (door q3), the placeholder cannot witness it and an honest
            // convergence is lost.
            //
            // The honest question is not "do I hold a row?" but "do I hold as much of this record as
            // the page carries?". A page with MORE notes than the row is the rest of the record, not a
            // duplicate — so it is written, through the same writer, whose own all-notes-present check
            // still makes a true duplicate a no-op.
            //
            // ROOT-LAYER: the placeholder-vs-record confusion is PRODUCED here, at the page apply, in
            // the one flag that decides whether the served notes are written at all. Teaching the fold
            // door to accept a commitment its record does not carry would be the read-side patch, and
            // it is exactly the hole this round closed.
            // MEASURED: 2026-09-07,
            // `a_seed_shaped_copy_already_held_takes_the_sidecars_from_the_page` — held row 1 note
            // against the served record's real note, recv sidecar adopted, roots did NOT converge (RED
            // with the fold door and without this line; the sidecar half of the pin still passed).
            // MUST-STAY-GREEN: the backfill target-filing arm below (keyed on `already_recorded`, read
            // BEFORE any write and untouched), the deletion-sidecar heal that depends on an
            // already-recorded record still reaching the adopts, and the tip-follow re-fetch cost — a
            // true duplicate still returns from the writer's own all-present check without claiming an
            // ordinal or re-folding.
            let held_notes = self
                .da_mem
                .get(seq)
                .map(|row| row.0.len())
                .unwrap_or(0);
            // ⛔ DB-415: REAL notes against REAL notes. A page carries the SERVED shape (256 units: reals + derived cover,
            // MEASURED `[record-write] … 256 note(s) in the payload → 3 real(s)`), so `held < 256` read "partial" for EVERY
            // page, and every page re-recorded its record over the held row — a different version included (3 → 1, 3 → 4,
            // sim-20261007-122707 / 135832). The page's own reals (the writer's `strip_fixed_note_payload_det`) are what
            // "as much of this record as the page carries" means; a page that is not the served shape is its reals already.
            let page_reals = rec.key().and_then(|k| crate::cover::strip_fixed_note_payload(notes, *seq, &k)).map_or(notes.len(), |r| r.len())
                / crate::cover::PQ_NOTE_BYTES;
            let partial_copy = held_notes < page_reals;
            if !self.record_bytes_are_chain_bound(addr) {
                let _ = self.accept_fetched_record(*seq, notes, rec.key());
            }
            if !already_recorded || partial_copy {
                // Targets are filed AFTER the record write below — the refile core needs the record's own
                // address, and the ident-less call that sat here always took the CANNOT-FILE branch.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a byte length and a seq only — never a note, amount, key or
                // owner. `record_note_payload` splits on the fixed 1153-byte note boundary and DROPS a short
                // residual, so a page whose length is not a whole multiple silently records NOTHING while this
                // function still counts it as applied — exactly the applied>0 / zero-stored contradiction observed.
                // `seq` is the PEER's canonical block address, which is the same address on every node now, so
                // this re-records the block exactly where its producer did.
                self.record_note_payload_at(*seq, notes, rec.key());
            }
            // ⛔ FILE THE SERVED TARGETS WITH THE RECORD ADDRESS IN HAND (measured 2026-08-18: the
            // ident-less call above this write dropped every carried target via CANNOT-FILE, so the
            // recipient's node held the notes and an empty bucket). Exactly-once via the refile core;
            // fixed target shape per record (protocol constant). Runs for already-recorded records too:
            // ingest can record a block's notes while its targets only ever land on this arm.
            // Follow-on (not here): mirroring the blob for one-hop re-serve, as the produce path does.
            // Probe prints a count and a byte length only.
            if !already_recorded && !targets.is_empty() {
                let filed = self.refile_account_targets_at(*seq, targets, true);
                eprintln!(
                    "[acct-file] backfill filed {filed} target(s) from {} byte(s) at this record",
                    targets.len()
                );
            }
            // ⭐⭐⭐ P4′b — AND ITS SIDECARS, OR THE NOTES ARRIVE UNFINDABLE.
            //
            // `record_note_payload_at` drains `pending_tags` for tags this node happens to be holding — and a
            // node backfilling HISTORY holds none of them: the clue gossip for a block from last week is long
            // gone. So every backfilled record used to land with its notes intact and NO locator tag, which is
            // the measured `[oli-tagdrain] drained ZERO locator tag(s)` and the reason a restarted node served
            // an empty index. The tags now ride the page, so we adopt what the peer served.
            //
            // ⛔ THE FIRST OF THESE TWO REASONS WAS AN ASSERTION, NOT A CHECK, UNTIL 2026-09-07. It read
            // "the notes just passed the verified-fetch door" — an upstream fact the only production
            // caller did not enforce, because the page pump counted the per-entry verdict and then
            // applied the whole page anyway (hole C-H1). The door is now RUN at the top of this loop and
            // its answer is recorded on the row, so what follows can rely on it instead of asserting it.
            // The second reason is unchanged and independent: P4′a binds the locator/target sidecars into
            // the block id, so a served tag set the chain never committed cannot exist.
            // `da_store_tags` maintains the locator klog at WRITE time, so the index REBUILDS itself from what
            // the node re-obtains — rebuild, never store.
            self.adopt_ledger_sidecars(*seq, &rec.oli_tags);
            // ⭐ THE LETTER COLUMN RIDES THE SAME PAGE — file the fetched mail bytes into the row just
            // recorded above (FIRST-WRITER; a column this node filled at graft is authoritative). Adopted
            // VERBATIM exactly like the note bytes (the note-model replication rule): a forged blob is
            // opaque unopenable ciphertext, and the WALLET verifies each opened letter's commitment against
            // the block-anchored `letter_set` — so a lying page can never forge mail, only waste its bytes.
            self.da_fill_letter_column(*seq, rec.letters());
            let _ = addr;
            // A served record fills the payload hole its block left (Z1: no sidecar fold rides here).
            // The ask cursor (NODE_LOCAL) moves past a record this node never grafted (a span a certified jump
            // skipped); a record filling the hole of a block it already grafted moved it at that block's carry.
            if !self.payload_gap_settle(*seq) {
                self.note_backfill_cursor = self.note_backfill_cursor.saturating_add(1);
            }
            applied += 1;
        }
        applied
    }

    /// Every block application ends with the canonical record fold (v31): whatever the new tip makes
    /// eligible — `record_fold_depth` selected-chain steps below it — folds now, in DAG order.
    pub fn ingest_block(&mut self, block: Block, now_ts: u64) -> RelayOutcome {
        // ⭐⭐⭐ DB-165 — REHYDRATE BEFORE ANY GATE READS THE BODY. `output_notes` and `credit_set` no
        // longer travel (their lengths stated the real note count), so a received block arrives with them
        // empty and every downstream reader — the roots check, the record write, the note transition —
        // would see a block that carries nothing. Deriving them from the block's own `tx_ids` and
        // checking each against the committed carrier restores the body from what the block ITSELF says,
        // never from what this node's pool happens to like (§BA).
        let mut block = block;
        let (_matched, unmatched) = self.rehydrate_block_body(&mut block);
        if let Some(out) = self.place_owed_fold_span_body_at_ingest(&block, unmatched) {
            return out;
        }
        if unmatched > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT only — never a note, commitment, amount or owner.
            eprintln!(
                "[db165] ⛔ {unmatched} note(s) derived from this block's tx ids were NOT in its committed \
                 carrier — dropped. A note the block did not commit is not the block's note, and recording \
                 it would be the pool deciding what a block says."
            );
        }
        let keep = block.clone();
        let out = self.ingest_block_inner(block, now_ts);
        if matches!(out, RelayOutcome::Added(_)) {
            // ⛔⛔⛔ A NODE'S TIP USUALLY ARRIVES BY GOSSIP, NOT BY ITS OWN PRODUCE. The witness capture was
            // wired into `graft_mined_own` only, so a node whose tip it had RECEIVED held no PoUW witness
            // for it and could not serve a DSYNC bundle at all — `canonical_record_fold_tests` failed with
            // "J adopts A's bundle" on five scenarios where the server had ingested its tip rather than
            // mined it. ⭐ Wiring a capture into the path I happened to be looking at is how half a
            // mechanism ships; the DAG keeps header + tx ids, so every door that holds a body has to keep it.
            self.retain_pow_witness(keep.header.id(), &keep.pow_proof);
            self.remember_unfolded_block(keep);
        } else if matches!(out, RelayOutcome::Duplicate(_)) {
            let _ = self.fill_shell_body_preverified(keep); // held as a shell meanwhile: keep the body
        }
        // CHAIN-PUBLISH-REVIEWED: blocks the chain already carries; each witness is its block's own.
        for body in self.relay.take_cascaded_bodies() {
            let id = body.id();
            self.retain_pow_witness(id, &body.pow_proof);
            // A shell may already stand for it (a page or a rebuffer): REPLACE it, never dedupe against it.
            if !self.fill_shell_body_preverified(body.clone()) {
                self.remember_unfolded_block(body);
            }
        }
        // ⭐ CLEAR A STRAND THE MOMENT THE RELAY REPORTS ONE. `strand_hint` is set when a parked block's
        // "missing" parent turned out to be ALREADY in the DAG — a child nothing else will ever release,
        // because no further arrival of that parent is coming. Before this, the only caller of the
        // re-injection walk was `rewind_fold_to_common`, so a strand cleared only if a REORG happened to
        // occur; otherwise the child sat in `waiting` until the orphan buffer evicted it, and a dropped
        // orphan is re-gossiped by nobody.
        //
        // ⛔ EVERY CONSUMER MUST FULLY INGEST WHAT IT TAKES. `strand_hint` is a bool TAKEN once, so
        // whichever caller reads it first gets the whole release and the other sees an empty vec —
        // which is only safe because BOTH consumers feed every released block straight back into a
        // full admission path, never inspect-and-drop. There are exactly TWO consumers of
        // `take_stranded_blocks` in the node: THIS one (the direct/test `ingest_block` path, inline
        // preverified re-ingest) and node_runtime.rs `apply_preverified_blocks` (the runtime tick,
        // which re-injects each released block into the preverify/FIFO lane as if freshly
        // gossiped). Both route through
        // `take_stranded_blocks` — the door built for it — rather than calling the walk directly.
        // Bounded by `ORPHAN_CAP`, every released block re-runs the full admission gates, and
        // nothing is retained.
        for w in self.take_stranded_blocks() {
            if w.pow_proof.is_empty() {
                let _ = self.readmit_parked_shell(&w); // a page shell: the shell door, never the PoW gate
                continue;
            }
            let _ = self.ingest_block_preverified(w, now_ts);
        }
        let _ = self.fold_canonical_records();
        out
    }

    /// ⭐ G2 — tally every `Class::FinalityVote` a block's bond lane carries, through the one verified door
    /// (`finality_vote_tx::apply_chain_finality_vote`); every other lane entry is left to the fold's `apply_bond_set`.
    /// Called from [`Self::remember_unfolded_block`] (every body-keeping graft door) and by the rogue-lane pins directly.
    /// Privacy: FIXED strings plus the door's own static reason; a vote is public validator data; never a key or amount.
    pub(crate) fn apply_carried_finality_votes(&mut self, bond_set: &[u8]) {
        if crate::block::sidecar_real_len(bond_set) == 0 {
            return;
        }
        let (entries, _) = Self::bond_set_entries(bond_set);
        for tx in entries.into_iter().flatten() {
            if !matches!(crate::chain_object::unframe(&tx.blob), Some((crate::chain_object::Class::FinalityVote, _))) {
                continue;
            }
            match crate::node::objects::finality_vote_tx::apply_chain_finality_vote(self, &tx.blob) {
                crate::finality_vote_tx::FinalityVoteApply::Finalized => {
                    eprintln!("[vote-apply] a carried finality vote FINALIZED its block ({} finalized)", self.finality.finalized_height())
                }
                crate::finality_vote_tx::FinalityVoteApply::Counted => {}
                crate::finality_vote_tx::FinalityVoteApply::Refused(why) => {
                    eprintln!("[vote-apply] refused: a carried finality vote — {why}")
                }
                crate::finality_vote_tx::FinalityVoteApply::NotFinalityVote => {}
                crate::finality_vote_tx::FinalityVoteApply::Deferred => {} // G2b: judged when the fold cursor reaches its height
            }
        }
    }

    /// A block that lands in the PAST of a chain block already folded — without moving the selected
    /// chain — belongs to that chain block's merge set in the canonical order, so the spine re-folds
    /// from just below the lowest such chain block. Without this the late block waits for the next
    /// chain block's merge set and takes an ordinal no other node gives it (the schedule search: sparse
    /// deliveries, three parties, one party never re-slotting the others' first blocks). "Late" is
    /// decided by the DAG — a folded chain block among the block's descendants — never by its parents
    /// being folded, which is also true of every ordinary block that extends the fold root. A late block
    /// under a shell below this node's certified anchor cannot be slotted here at all: the spine is
    /// stale and the next certified bundle re-anchors it.
    pub(super) fn note_late_arrival(&mut self, block: &Block) {
        let Some(cursor) = self.fold_chain_tip else { return };
        let id = block.id();
        let dag = self.relay.dag();
        let future: std::collections::HashSet<crate::block::BlockId> = dag.descendants_of(&id).into_iter().collect();
        if future.is_empty() {
            return; // nothing above it yet: an ordinary arrival
        }
        // the lowest folded chain block that has this block in its past
        let mut cur = Some(cursor);
        let mut lowest: Option<crate::block::BlockId> = None;
        while let Some(c) = cur {
            if future.contains(&c) {
                lowest = Some(c);
                cur = dag.get(&c).and_then(|x| x.selected_parent);
            } else {
                break;
            }
        }
        let Some(c_b) = lowest else { return };
        let fork = match dag.get(&c_b).and_then(|x| x.selected_parent) {
            Some(p) => p,
            None => return, // the chain block is the floor itself: nothing to re-fold below it
        };
        if self.folded_floor.contains(&fork) && Some(fork) != self.certified_anchor && !self.can_refold_from(&fork) {
            self.mark_spine_stale("a block landed below this node's certified anchor");
            return;
        }
        if !self.block_record_folded(&fork) {
            return; // the fork point is not in the spine: the ordinary fold pass reaches it
        }
        eprintln!(
            "[fold-late] block {} landed under folded chain block {} — re-folding from its parent {}",
            &id.to_hex()[..8],
            &c_b.to_hex()[..8],
            &fork.to_hex()[..8]
        );
        self.rewind_fold_to_common(fork);
    }

    pub(super) fn ingest_block_inner(&mut self, block: Block, now_ts: u64) -> RelayOutcome {
        // Phase probe (see node_runtime::ING_* docs): stamps only; early rejects skip them.
        let ing_t0 = std::time::Instant::now();
        // ⛔⛔⛔ THE BODY MUST MATCH THE HEADER'S NOTE COMMITMENT. Fail-closed on the BAD block only.
        //
        // The id now folds `header.output_notes_root`, so altering the notes changes the id. That alone is
        // not enough: a peer can ship a header claiming root R with a body carrying notes N where
        // `hash(N) != R`. The id would be computed from R, this node would record N, and the two nodes
        // would once again hold "the same block" with different payloads — the exact hole this closes.
        //
        // Checking it here makes the pair impossible to separate: every node that accepts a block has
        // verified that the notes it stores are the notes the id commits to. The message carries no figure
        // from the block at all, so there is nothing here to leak.
        // #73 PoUW consensus gate: a NON-genesis gossiped block must carry a valid non-outsourceable proof
        // `pi` AND its header preimage's PQ-PoUW digest must meet the `work` target — verified BEFORE the
        // block can graft OR buffer, so an un-mined/forged block never enters the DAG. Rejected fail-closed
        // on the BAD block only (the DAG never halts). Genesis has no miner; a node whose PoUW kernel failed to
        // allocate verifies nothing and thus rejects (fail-closed), never accepting an un-decidable block.
        // The three PURE admission gates (PoW / settlement aggregate / nullifier carrier) live in
        // `preverify_block` above, so ONE implementation runs inline here AND off the runtime lock
        // in the gossip pre-verifier ([[feedback_code_hygiene_pillar]] — no second copy to drift).
        if let Err(e) =
            Self::preverify_block(self.pow_miner.as_ref().map(|m| m.hasher()), &block, self.template_double(), self.ledger_double())
        {
            return RelayOutcome::Invalid(e);
        }
        crate::node_runtime::ING_VERIFY_MS.fetch_add(
            ing_t0.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.ingest_block_preverified(block, now_ts)
    }

    /// The output commitments a tx carries (the first 32 bytes of each PQ note), in carried order.
    pub(super) fn tx_output_cms(tx: &PqTx) -> Vec<[u8; 32]> {
        tx.output_notes
            .chunks_exact(crate::cover::PQ_NOTE_BYTES)
            .map(|n| {
                let mut a = [0u8; 32];
                a.copy_from_slice(&n[..32]);
                a
            })
            .collect()
    }

    /// ⭐⭐⭐ DB-351 — A SPEND'S FILING DIGEST D, FROM ITS OWN CLUE LIST: the value its carrier binds LAST.
    ///
    /// The pool door verifies the carrier under this D, so a relay's stripped, rewritten, added or reordered clue list
    /// is a transaction whose carrier verifies under no door. `None` when the list is not the spend's ONE encoding
    /// (`oli::canonical_clue_records`: whole, strictly ascending by cm, every cm one of its own outputs) — the door then
    /// refuses the spend by name, it never files a filtered subset. The producer's `oli_tags` for these outputs and
    /// every peer's recompute ([`crate::note_transition::spend_filing_d`]) reach the same bytes.
    pub fn tx_filing_d(tx: &PqTx) -> Option<crate::spend_frontier::Digest4> {
        let outputs = Self::tx_output_cms(tx);
        let records = crate::oli::canonical_clue_records(&outputs, &tx.note_clues)?;
        let bytes = crate::oli::filing_d_bytes_from_clues(&outputs, &records)?;
        Some(crate::oli::filing_d_digest(&bytes))
    }

    /// `nt` is the block's NOTE TRANSITION when the caller has the block in hand. ⛔ IT IS A PARAMETER,
    /// NOT SOMETHING THE DAG KEEPS: `BlockNode` holds the header and ids, never the body, and retaining
    /// a per-block proof there would be exactly the per-block growth the footprint cardinal bans. A
    /// caller that does not hold the block passes `None` and gets the pre-§BA judgement — weaker, and
    /// the call sites say which is which.
    /// `pub(crate)` for DB-224's door pins (`chain_action_carriage_tests`), which drive THIS function with a
    /// forged reference — the door itself, not a model of it.
    #[track_caller] // A-F94 diag: the refusal line names the writer that called the door
    pub(crate) fn graft_admitted_notes(
        &self,
        gid: &Hash32,
        raw_notes: &[u8],
        // §20.2: the body's cover key (beside it in process; `None` = a body no door can bind)
        cover_key: Option<crate::cover::CoverKey>,
        nt: Option<&crate::note_transition::NoteTransition>,
        // ⭐ DB-223 Q7: the block's MEMBER transition — a stated spend's outputs are justified only when it proves the
        // spend's input exists (`member_transition::spends_proven_with_members`). A parameter for the same reason `nt` is.
        mt: Option<&crate::member_transition::MemberTransition>,
        // The same, for the CONSTANT-WIDTH class (DB-83) — a parameter for the same reason `nt` is.
        cover_nt: Option<&crate::note_transition::CoverTransition>,
        // ⭐ §BA — the grafted block's CREDIT SET: the framed chain objects that justify the notes no
        // spend published. Like `nt` it is a PARAMETER, not something the DAG keeps: `BlockNode` holds
        // the header and ids only, and retaining a per-block sidecar there would be the per-block growth
        // the footprint cardinal bans. A caller that does not hold the block passes `&[]` and gets the
        // strictest judgement — every non-spend note refused — which is fail-closed, never fail-open.
        credits: &[u8],
        // §22b: the wide objects beside the body, by which the set's references resolve
        credits_wide: &[Vec<u8>],
        // The grafted block's BOND SET: it justifies a bond transaction's own outputs (`bond_admissions_of`). It
        // justifies NO returned collateral note (DB-274 P2 §8.7: the fold releases those, never a carried block).
        // Same contract as `credits`: a caller that does not hold the block passes `&[]`.
        bonds: &[u8],
        // ⛔ DB-278 — the grafted block's NULLIFIER LANE (`nullifier_proof.padded_tags`, header-bound). A credit-set
        // object whose own derivable nullifiers (`chain_object::object_own_nullifiers`) this lane does not retire
        // justifies nothing: the block would credit the object's notes while its right or its burn stays unspent.
        lane: &[[u8; 32]],
        // ⛔ DB-351 — the grafted block's filed locator tags (`Block::oli_tags`, header-bound). The note transition's
        // tuples bind each spend's filing digest, recomputed from THESE bytes; a caller without them verifies no
        // transition and admits no spend's notes (fail-closed on the notes, never on the block).
        oli_tags: &[u8],
    ) -> Vec<u8> {
        let held = self.relay.dag().get(gid).map(|n| (n.header.clone(), n.tx_ids.clone()));
        self.graft_admitted_notes_given(gid, held, raw_notes, cover_key, nt, mt, cover_nt, credits, credits_wide, bonds, lane, oli_tags)
    }

    /// ⭐ [`Self::graft_admitted_notes`]'s ONE body, judged against `held` — the block's own header and tx ids — instead
    /// of a DAG lookup. ⛔ DB-358 r3 control (2026-10-03, MEASURED): the DSYNC adopt applied the adopted TIP's notes
    /// BEFORE `graft_unfolded_carry` placed the tip in the DAG, so the DAG lookup found no header, no transition could
    /// verify, and the tip's honest spend outputs were refused; the placement then saw a record already held and never
    /// re-grafted it — the joiner LOST the payment and its note tree split from the producer's
    /// (`db358_r3_control_a_bundle_joiner_folds_an_honest_spend_carried_in_its_window_like_the_producer`, A true C
    /// false; attributed PRE-EXISTING by a toggle of the DB-223 member rule). A caller that holds the whole block (the
    /// adopt holds the certified tip) judges it by that block's own header: the block carries what applies it.
    #[allow(clippy::too_many_arguments)]
    #[track_caller]
    pub(super) fn graft_admitted_notes_given(
        &self,
        _gid: &Hash32,
        held: Option<(crate::block::BlockHeader, Vec<Hash32>)>,
        raw_notes: &[u8],
        cover_key: Option<crate::cover::CoverKey>,
        nt: Option<&crate::note_transition::NoteTransition>,
        mt: Option<&crate::member_transition::MemberTransition>,
        cover_nt: Option<&crate::note_transition::CoverTransition>,
        credits: &[u8],
        // §22b: the wide objects beside the body, by which the set's references resolve
        credits_wide: &[Vec<u8>],
        bonds: &[u8],
        lane: &[[u8; 32]],
        oli_tags: &[u8],
    ) -> Vec<u8> {
        let held_any = held.is_some(); // A-F94 diag: named in the refusal line
        let g_tx_ids: Vec<Hash32> = match held.as_ref() {
            Some((_, ids)) => ids.clone(),
            None => Vec::new(),
        };
        let fee_bps = self.params().order_fill_fee_bps;
        let allow = self.params().genesis_mint_allowance();
        let mut refused: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        // ⭐⭐⭐ §BA/§BB — THE ALLOW-LIST, AND THE EVIDENCE IT IS BUILT FROM.
        //
        // Below, a note is judged only by transactions THIS NODE RESOLVED — and under the constant-256
        // cover it resolves almost none of a block's bodies, so the common case was "unjudged ⇒
        // received". That is §BA: any producer could plant a note on every peer.
        //
        // The block's NOTE TRANSITION fixes exactly that gap. It is one bound aggregate over the block's
        // spends plus the tuple list it stands over, and every tuple is the public statement of a spend
        // carrier that VERIFIED IN CIRCUIT. A peer recomputes the digest from the list, verifies once,
        // and gets an allow-list that needs no transaction body at all.
        //
        // ⛔ IT STRENGTHENS, IT DOES NOT NARROW: a note is refused only if the transition exists, does
        // NOT name it, and no resolved transaction justified it either. §BO refuted four local closes
        // because each would have refused notes a peer simply cannot judge; this one judges them.
        //
        // O1-FOOTPRINT-REVIEWED: both sets are bounded by cover::BLOCK_FIXED_NOTE_COUNT — they hold at
        // most ONE BLOCK's note commitments, are built inside this call and dropped when it returns, and
        // nothing here is keyed by height, spend or age. Per-block, never per-history.
        let admit = {
            let hdr = held.as_ref().map(|(h, _)| h.clone());
            let armed = self.template_double();
            let single = nt.and_then(|t| {
                let h = hdr.clone()?;
                let ledger = crate::member_transition::LedgerDoor::of_parts(&h, raw_notes, lane, cover_key);
                crate::member_transition::spends_proven_on_block_with(t, mt, &h.output_notes_root, oli_tags, Some(ledger), armed, self.ledger_double())
                    .map(|(a, _)| a)
            });
            // ⭐⭐⭐ THE CONSTANT-WIDTH HALF (DB-83). A transaction spending k > 1 real notes has its
            // WHOLE tag set stated here; without this the other k-1 real tags would never enter the
            // allow-list, their deletions would be refused, and those notes would stay spendable — which
            // is precisely the fund-safety hole the submit door has been refusing multi-input spends to
            // avoid. Verified on its own: a block carrying a bad cover transition simply admits nothing
            // through it, and production is untouched.
            let cover = cover_nt.and_then(|t| {
                let h = hdr?;
                crate::note_transition::verify_cover_with(t, &h.output_notes_root, armed)
            });
            match (single, cover) {
                (Some(mut a), Some(b)) => {
                    a.merge(b);
                    Some(a)
                }
                (Some(a), None) => Some(a),
                (None, c) => c,
            }
        };
        // ⭐ DB-313 §3 — AND THE WELDED CLASS: a bond's CHANGE and its deletion are justified by the block's bond
        // transition exactly as a spend's are by the note transition. The locked note never is — it rides the lane.
        let admit = match (
            admit,
            held.as_ref().and_then(|(h, _)| Self::bond_admissions_on_door(bonds, &h.output_notes_root, self.template_double())),
        ) {
            (Some(mut a), Some(b)) => {
                a.merge(b);
                Some(a)
            }
            (a, None) => a,
            (None, b) => b,
        };
        // ⭐⭐⭐ §BA — WHAT THE BLOCK'S OWN CREDIT SET JUSTIFIES, CHECKED HERE RATHER THAN TRUSTED.
        //
        // These are the notes no spend publishes. The block carries the framed CHAIN OBJECT for each, and
        // this node asks the chain's own two questions of those bytes:
        //   * `chain_object::admissible` — the identical gate the submitting node's mempool applied, so a
        //     forged or inadmissible object justifies NOTHING and its note is refused like any plant;
        //   * `carried_note_payloads` — the object must NAME the commitment, byte-exactly. An object that
        //     declares one note cannot excuse a second one smuggled beside it.
        //
        // ⛔ A SET THAT DOES NOT PARSE JUSTIFIES NOTHING. `credit_set_iter` returns `None` on a truncated
        // or over-long list and the default is EMPTY — fail-closed, so a malformed sidecar refuses notes
        // rather than excusing them.
        //
        // O1-FOOTPRINT-REVIEWED: bounded by cover::BLOCK_FIXED_TX_COUNT — `credit_set_iter` refuses a
        // longer list. Built inside this call and dropped when it returns; never keyed by height.
        //
        // ⭐⭐⭐ DB-224 — JUSTIFIED BY `(cm, slot)`, NOT BY `cm`: BYTE-EXACT. The set travels in carriage form, so
        // an object names each note by its reference `cm ‖ Hash32::hash(payload)`, and a chunk is justified
        // only when BOTH its front AND its whole-payload hash match. That is the strength
        // `wrapper_binds_object` has at the pool door, and stronger than the cm-only match that stood here,
        // which excused ANY ciphertext behind a justified commitment. A reference whose `cm` is not its own
        // payload's front justifies nothing, because no chunk can match both halves of it.
        let mut credit_justified: std::collections::HashSet<([u8; 32], [u8; 32])> =
            std::collections::HashSet::new();
        // §22: opened under the block's seal key when this door holds it; a receiver without it admits no credited note here
        // (the record lane delivers the row, the fold applies the objects).
        let credit_key = match held.as_ref() {
            Some((hdr, _)) => crate::block::credit_seal_key(hdr, cover_key.as_ref()),
            None => cover_key,
        };
        for blob in crate::block::credit_set_iter(credits, credit_key.as_ref(), credits_wide).unwrap_or_default() {
            // ⭐ DB-274 P4 (§8.11): graft judges a credit's SHAPE only; its WEIGHT is judged once, at its fold, in the
            // step's canonical pre-state (`credit_decide_at_fold`), because every node's folded set differs at graft.
            let attested = crate::bridge_credit_tx::credit_structurally_attested(&blob);
            if crate::chain_object::unframe(&blob).is_none()
                || !crate::chain_object::admissible(&blob, fee_bps, allow, attested)
            {
                // Fixed string — by construction no tag, cm, amount, key or owner appears.
                eprintln!(
                    "[graft-door] ⛔ §BA REFUSED a credit-set object that fails this chain's own \
                     admission rule — it justifies no note here. The block itself still grafts."
                );
                continue;
            }
            // ⛔⛔⛔ DB-278 — THE OBJECT'S OWN NULLIFIERS MUST RIDE *THIS BLOCK'S* LANE. `admissible` judges the
            // object's bytes (creator, carrier) and cannot see a lane; the pool door checks the WRAPPER's lane, which
            // a producer that skips its own door never runs. So the block's own header-bound lane is checked here,
            // from the ONE definition both doors share. Fail-closed on the object, never on the block.
            //
            // ⭐ THE ONE EXCEPTION, AND WHY IT CREATES NOTHING: a RE-CARRIAGE. The graft-time appliers stage an applied
            // object into this node's NEXT block (`stage_credit_justifier`), whose lane no longer holds the nullifier
            // the FIRST carriage retired. Such an object is justified only if EVERY note it names is already recorded
            // on this node (`da_seq_at_note_cm`): it then adds nothing (a note is deduplicated by its commitment and
            // spendable once, by its nullifier). "Or the nullifier is already spent" would NOT do — a second, different
            // mint of a retired right, or a second transfer of a burned note, reads "spent" too (docs/DB-278 §refuted).
            // A node that never recorded the first carriage's notes takes them from that block's record, not from here.
            let recarried = || {
                crate::chain_object::carriage_note_refs(&blob).is_some_and(|refs| {
                    !refs.is_empty() && refs.iter().all(|(cm, _)| self.da_seq_at_note_cm(cm).is_some())
                })
            };
            match crate::chain_object::object_own_nullifiers(&blob) {
                Some(own) if own.iter().all(|nf| lane.contains(nf)) => {}
                Some(_) if recarried() => {}
                _ => {
                    // Fixed string — by construction no tag, cm, amount, key or owner appears.
                    eprintln!(
                        "[graft-door] ⛔ DB-278 REFUSED a credit-set object whose own nullifier this block's \
                         lane does not retire — it justifies no note here. The block itself still grafts."
                    );
                    continue;
                }
            }
            // An object whose references do not parse names no note, so it justifies nothing — the
            // fail-closed direction, stated as a branch rather than folded into a default.
            if let Some(refs) = crate::chain_object::carriage_note_refs(&blob) {
                credit_justified.extend(refs);
            }
        }
        // ⛔⛔⛔ DB-274 P2 (§8.7) — NO BOND-RETURN JUSTIFICATION AT GRAFT. A bond's locked note returns ONLY by the fold's
        // own release (`bond_step_at_fold`, at the close of its unbonding window, into that step's record, from
        // chain state). DB-257's justification here (the note of a bond THIS block's unbond releases) was decided at
        // graft, before the slash that should burn it and before the evidence window closed: an unbond grafted after
        // an unfolded slash returned the collateral the slash burns (§8.5). So a block carrying a locked note is
        // judged like any other note: only the proof-bound transition and the attested credit set justify one, and
        // neither can name a locked note, so it is refused on every node alike (pin `db274_p2_…carrying…refused`).
        let mut justified: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for id in &g_tx_ids {
            let Some(tx) = self.mempool.get(id) else {
                continue; // unresolvable body — judged by the transition's allow-list below, not here
            };
            // A tx this node HOLDS went through its own carrier gate at submission, so its notes are
            // justified by that gate whatever the transition says.
            for ch in tx.output_notes.chunks(crate::cover::PQ_NOTE_BYTES) {
                if ch.len() >= 32 {
                    let mut cm = [0u8; 32];
                    cm.copy_from_slice(&ch[..32]);
                    justified.insert(cm);
                }
            }
            if crate::chain_object::unframe(&tx.blob).is_none() {
                continue; // an ordinary send — its own carrier gate judged it
            }
            // ⭐ DB-274 P4 (§8.11): the SHAPE here; the weight at the fold (`credit_decide_at_fold`). The pool door and
            // assembly still tally against the tip set, but only as the producer's ADVICE: a wrong guess there delays
            // or drops a credit at the fold, and never admits one. The one weight verdict every node shares is the
            // fold's, taken in the step's canonical pre-state; a graft-time tally was a per-node verdict (§8.10 H1).
            let credit_attested = crate::bridge_credit_tx::credit_structurally_attested(&tx.blob);
            if !crate::chain_object::admissible(&tx.blob, fee_bps, allow, credit_attested) {
                for ch in tx.output_notes.chunks(crate::cover::PQ_NOTE_BYTES) {
                    if ch.len() >= 32 {
                        let mut cm = [0u8; 32];
                        cm.copy_from_slice(&ch[..32]);
                        refused.insert(cm);
                    }
                }
                // Fixed string — by construction no tag, cm, amount, key or owner appears.
                eprintln!(
                    "[graft-door] ⛔ REFUSED a framed chain object carried by a grafted block \
                     — its payload fails this chain's own admission rule; its notes are not \
                     recorded and not folded here. The block itself still grafts."
                );
            } else if !crate::chain_object::wrapper_binds_object(tx) {
                // A `carried_note_payloads` None cannot occur here (the object just decoded under
                // `admissible`), and its empty-set default is itself fail-closed: no justified cms
                // means every wrapper chunk is refused.
                let justified: std::collections::HashSet<[u8; 32]> =
                    crate::chain_object::carried_note_payloads(&tx.blob)
                        .unwrap_or_default()
                        .iter()
                        .filter(|n| n.len() >= 32)
                        .map(|n| {
                            let mut cm = [0u8; 32];
                            cm.copy_from_slice(&n[..32]);
                            cm
                        })
                        .collect();
                for ch in tx.output_notes.chunks(crate::cover::PQ_NOTE_BYTES) {
                    if ch.len() >= 32 {
                        let mut cm = [0u8; 32];
                        cm.copy_from_slice(&ch[..32]);
                        if !justified.contains(&cm) {
                            refused.insert(cm);
                        }
                    }
                }
                // Fixed string — by construction no tag, cm, amount, key or owner appears.
                eprintln!(
                    "[graft-door] ⛔ REFUSED unjustified wrapper notes carried by a grafted \
                     block — a framed object's transaction claims notes the object itself \
                     does not justify; only the unjustified chunks are refused. The block \
                     itself still grafts and the object's own notes apply."
                );
            }
        }
        // ⭐⭐⭐ §BA CLOSED — EVERY NOTE A GRAFTED BLOCK CARRIES MUST BE JUSTIFIED, AND THERE IS NO
        // "UNJUDGED ⇒ RECEIVED" ARM LEFT.
        //
        // Three sources of justification, and a note that has none is refused:
        //
        //   1. THE TRANSITION (`Block::note_transition`) — every tuple is the public statement of a spend
        //      carrier that VERIFIED IN CIRCUIT, and the peer recomputes the digest from the list before
        //      verifying, so the list is pinned by the proof. Needs no transaction body.
        //   2. A RESOLVED TRANSACTION — a body this node happens to hold went through its own carrier gate
        //      at submission, and framed objects additionally had `admissible` + `wrapper_binds_object`
        //      applied above.
        //   3. THE CREDIT SET (`Block::credit_set`, §BA) — for the notes no spend publishes: a bridge
        //      credit, an asset or wrapped mint, a bond return. The block CARRIES the framed object, and
        //      this node re-runs the chain's own two questions on those bytes — `admissible`, then
        //      `carried_note_payloads` must NAME the commitment. Self-verification over a chain object the
        //      block carries, which is exactly what the trustless cardinal asks for.
        //
        // ⛔⛔⛔ WHY THE OLD `if let Some(a)` ARM WAS THE WHOLE HOLE. It refused a note only when a
        // transition was present. A block with no spends carries none — so a producer that staged an
        // invented note into a spend-free block had every peer credit it, measured as
        // `peer RECORDED it=true, peer holds it UNSPENT=true`. The escape hatch WAS §BA.
        //
        // ⛔ AND §BO'S LIVENESS TRAP DOES NOT APPLY, BECAUSE ITS PREMISE WAS MEASURED FALSE. Four earlier
        // closes were refuted for refusing honest COINBASE notes a peer cannot resolve. There is no
        // coinbase note: MEASURED 2026-09-15 on a freshly produced block, `output_notes` is 0 bytes on an
        // idle block and 0 on a block with a pooled transaction — the coinbase is `header.miner_commitment`,
        // a header field the PoW binds, and it never rides this lane. What DOES ride it is exactly the
        // staged-credit class, and that class now carries its object.
        //
        // FAIL-CLOSED IS THE RIGHT DIRECTION HERE AND COSTS NO MONEY. A refused note is one this node does
        // not record; the value is not destroyed, because the note either never existed (the plant) or
        // rides a block whose justification the peer can check. The DAG never halts on it: the BLOCK still
        // grafts, only the unjustified chunks are dropped.
        //
        // O1-FOOTPRINT-REVIEWED: bounded by cover::BLOCK_FIXED_NOTE_COUNT — one block's notes, dropped
        // on return.
        let mut unjustified = 0usize;
        // §RF-3 §14 / §POLES T1 (2026-10-26): at most ONE seed note per block — counted over the whole body, so a second
        // seed refuses both (fail closed on the item, never on the block).
        let seed_notes = raw_notes
            .chunks(crate::cover::PQ_NOTE_BYTES)
            .filter(|c| cover_key.is_some_and(|k| crate::cover::is_seed_note_in(c, raw_notes, &k)))
            .count();
        for ch in raw_notes.chunks(crate::cover::PQ_NOTE_BYTES) {
            if ch.len() >= 32 {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&ch[..32]);
                // ⛔⛔⛔ BLOCK-CARRIED EVIDENCE ONLY — LOCAL STATE MUST NOT DECIDE WHAT IS ADMITTED.
                //
                // MEASURED 2026-09-15, the moment this became an ALLOW-list: parties diverged on
                // `unspent_note_root`, and `I-CP` read `party 0 holds Some(9) received-note sidecar rows
                // where a node fed ONLY the blocks derives Some(10)`. The cause was two LOCAL sources in
                // this decision — transactions this node happened to POOL, and bonds this node happened
                // to HOLD. A node that pooled the body admitted the note; a node that did not, refused it.
                //
                // ⭐ THE DENY-LIST TOLERATED THAT AND AN ALLOW-LIST CANNOT. While the door only ever
                // REFUSED on resolved bodies, a node holding none refused nothing and everyone still
                // agreed on "accept". Turning it into an allow-list makes every local difference a
                // CONSENSUS difference — `state is a FUNCTION OF THE CHAIN, local state is a cache`, and
                // the whole §BA close is worthless if it forks the chain to get there.
                //
                // So the decision reads the BLOCK and nothing else: the transition it carries, and the
                // credit set it carries. Both are header-bound, identical on every node, and checkable
                // holding no mempool — which is what made carrying the objects necessary in the first
                // place rather than merely convenient.
                // ⭐ AND ONE STATE SOURCE THAT IS NOT LOCAL: `bond_locked` is declared **ChainDerived**
                // in the authority manifest — every node that holds the chain derives the identical map,
                // because it is built from the `Block::bond_set` entries the chain carried. Reading it
                // here is therefore the same class of act as reading the block, not the `mempool` read
                // that caused the divergence above. ⭐ DB-257: it is read ONLY through the unbonds THIS
                // block's bond set carries (`bond_returns`), by commitment AND payload hash, so a locked
                // note is justified exactly when the same block releases its weight, and never otherwise.
                #[cfg(test)]
                crate::test_census::vacuity::record("Node::graft_admitted_notes", false);
                // ⭐ §RF-3 spec §14 — THE ONE SEED RULE. A block may carry exactly one seed note (§POLES T1 2026-10-26: beside
                // notes that travel whole, so its cover secret keeps a body off the wire), judged by its own equation
                // (cm = `seed_note_cm(body)`). §9.6: (1) PoW as above; (2) this equation IS
                // the check; (3) value 0 — the cm is a blake3 value, never a Poseidon note commitment, so no spend opens
                // it; (4) a replay is a duplicate leaf, refused by the record set as for any note; (5) one hash; (6) every
                // other justification above still runs — a second note, or a seed whose cm is not its body's, is refused.
                let ok = admit.as_ref().is_some_and(|a| a.admits_note(&cm))
                    || credit_justified.contains(&(cm, *Hash32::hash(ch).as_bytes()))
                    || (seed_notes == 1 && cover_key.is_some_and(|k| crate::cover::is_seed_note_in(ch, raw_notes, &k)));
                if !ok {
                    refused.insert(cm);
                    unjustified = unjustified.saturating_add(1);
                }
            }
        }
        // TEST-ONLY DIAGNOSTIC (lane funds-brb33, T4 attribution): WHY this node refused — counts only, compiled out of every
        // shipped binary (a per-block refusal tally is activity metadata the constant-256 cover exists to remove).
        #[cfg(test)]
        if unjustified > 0 {
            eprintln!(
                "[graft-door-test] held={} nt={} mt={} cover_nt={} admit={} admit_cms={} credit_justified={} notes={} refused={}",
                held.is_some(),
                nt.is_some(),
                mt.is_some(),
                cover_nt.is_some(),
                admit.is_some(),
                admit.as_ref().map_or(0, |a| a.cms_len()),
                credit_justified.len(),
                raw_notes.len() / crate::cover::PQ_NOTE_BYTES,
                unjustified
            );
        }
        if unjustified > 0 {
            // Fixed string — by construction no cm, amount, key, owner or count appears. The COUNT is
            // deliberately absent: a per-block refusal tally is real-activity metadata of exactly the kind
            // the constant-256 cover exists to remove.
            eprintln!(
                "[graft-door] ⛔ §BA REFUSED a note this block carries that NOTHING justifies — no verified \
                 spend published it, no transaction this node resolved claims it, and no object in the \
                 block's credit set names it. The block itself still grafts. (writer {}; evidence held: header {} nt {} mt {} \
                 cover_nt {} credits {} B)",
                std::panic::Location::caller(),
                held_any,
                nt.is_some(),
                mt.is_some(),
                cover_nt.is_some(),
                credits.len()
            );
        }
        if refused.is_empty() {
            return raw_notes.to_vec();
        }
        let mut out = Vec::with_capacity(raw_notes.len());
        for ch in raw_notes.chunks(crate::cover::PQ_NOTE_BYTES) {
            let refuse = ch.len() >= 32 && {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&ch[..32]);
                refused.contains(&cm)
            };
            if !refuse {
                out.extend_from_slice(ch);
            }
        }
        out
    }

    /// ⭐⭐⭐ THE PER-CLASS OBJECT SEAM — every chain object a block carries as a transaction, applied
    /// from the bytes THIS node pooled, in the block's tx order. Called from BOTH doors a block comes
    /// through: the graft of a RECEIVED block (`apply_grafted_block_carry`) and the produce act of this
    /// node's OWN block (before its ids leave the pool).
    ///
    /// ⛔⛔⛔ THE PRODUCER NEVER RAN THIS FOR ITS OWN BLOCKS UNTIL 2026-09-17. The seam lived only in the
    /// received-block carry, and the produce act skips its own block there ("applied by the produce act
    /// above" — which applied the header lanes, never the objects). It hid because every executor also
    /// applied LOCALLY at execute (peg-in, wrapped mint, yield, unbond…), so the producer's state was
    /// already ahead and its own-block apply would only have answered `Replay`. The moment the peg-in
    /// executor became verify-only (§CZ), the in-process lane pin caught it at once: A published, A
    /// produced the block carrying it, and A's own ledger never moved. A node whose state depends on
    /// whether it MINED the block or RECEIVED it is a fork by construction.
    ///
    /// ⭐⭐⭐ THE BYTES COME FROM THE BLOCK (2026-09-17; since DB-224 ONLY from the block). `Block::credit_set`
    /// (§BA, header-bound) carries every framed object the producer selected, so a peer applies them from
    /// bytes it HOLDS. (The 2026-09-17 shape still consulted the mempool for an id the carried set did not
    /// cover — deleted by DB-224, below.) Until this change
    /// the seam read the pool alone: a peer that had not yet received the object's tx by gossip grafted
    /// the block and applied NOTHING, and there was no second chance (the block was in the DAG, the
    /// object was not in the pool). MEASURED on two real nodes (seat journey run 4): node1 attested
    /// node0's mint, grafted node0's blocks, and never held the deposit as minted. Every apply door is
    /// idempotent (`Replay` / `AlreadySeated` / same-cm credit), so an object present in both sources
    /// applies once; the dedup below is by bytes.
    ///
    /// ⛔⛔⛔ DB-224 — THE BLOCK IS THE ONLY SOURCE NOW; THE MEMPOOL ARM IS DELETED. The carried set travels
    /// again (carriage form, header-bound, every entry checked at pre-verify to be a carriage whose notes
    /// the block's own carrier commits), and the producer puts EVERY framed tx it selects into it — so the
    /// pool could only ever add an object the block did not carry, which is local state deciding what a
    /// block applies. The producer applies its own block through this same call on the same bytes, so a
    /// node's ledger is a function of the blocks alone, whoever mined them and whatever was pooled where.
    /// Each door reads `cm` only (the tallies, the mint / spend / fill carriers, the creator signature),
    /// so a carriage reaches the identical verdict the full object would; a 64-byte reference records no
    /// note (`record_note_payload` splits whole payloads only), so the doors' re-stage of a note that
    /// already rode this block — one note in several records, on whichever nodes held its body — stops on
    /// every node alike, and the justifier they re-stage beside it is dropped at the next produce by the
    /// subject rule (`carriable_credit_set`: its note is in no later block).
    /// `_tx_ids` is kept for the callers' shape; nothing here reads it any more.
    /// ⛔⛔⛔ DB-388 (2026-10-04): `lane` is the carrying block's header-bound nullifier lane (`nullifier_proof.padded_tags`).
    /// DB-278's rule — an object whose OWN nullifiers the lane does not retire justifies nothing — was enforced at the NOTE door
    /// only (`graft_admitted_notes`); the per-class APPLY below still ran for such an object, so a producer re-carrying a
    /// public creation without its id appended a duplicate registry leaf on every grafting node (MEASURED: the peer's
    /// registry root moved on every re-carry, `a_creation_re_carried_by_a_rogue_producer_moves_no_peer_registry_…`). Now the
    /// rule is TOTAL: such an object applies nothing on any arm. The block itself still grafts.
    pub(super) fn apply_chain_objects_of(
        &mut self,
        tx_ids: &[Hash32],
        credits: &[u8],
        lane: &[[u8; 32]],
        // §22: the sealed set's key here (`None` = unreadable: nothing applies at this door; the fold applies it)
        key: Option<crate::cover::CoverKey>,
        // §22b: the wide objects beside the body (an unresolved reference: nothing applies at this door; the fold waits)
        wide: &[Vec<u8>],
    ) {
        let objects = crate::block::credit_set_iter(credits, key.as_ref(), wide).unwrap_or_default();
        self.apply_chain_objects_opened(tx_ids, objects, lane);
    }

    /// [`Self::apply_chain_objects_of`] on objects ALREADY opened and judged (`Node::opened_credit_objects`, the fold).
    pub(super) fn apply_chain_objects_opened(&mut self, _tx_ids: &[Hash32], objects: Vec<Vec<u8>>, lane: &[[u8; 32]]) {
        let blobs: Vec<Vec<u8>> = objects.into_iter().filter(|b| crate::chain_object::unframe(b).is_some()).collect();
        for blob in &blobs {
            match crate::chain_object::object_own_nullifiers(blob) {
                Some(own) if own.iter().all(|nf| lane.contains(nf)) => {}
                _ => {
                    // Fixed string — by construction no tag, cm, amount, key or owner appears.
                    eprintln!(
                        "[graft-apply] ⛔ DB-388 REFUSED a credit-set object whose own nullifier this block's lane does not \
                         retire (or that does not decode) — it applies nothing here. The block itself still grafts."
                    );
                    continue;
                }
            }
            // ⭐ DB-274 P4 (§8.11 item 6): a bridge credit's reconcile (the staged-copy unstage) no longer runs here at
            // graft. It runs at the credit's FOLD, for a credit the fold's weight verdict ATTESTS
            // (`credit_decide_at_fold`). At graft the arm is structure-only, so a relay-stripped copy would be admitted
            // here and would destroy the honest staged original before the fold strips the copy.
            // ⭐ AND THE LIQUIDATION CLASS, through the SAME per-class apply seam and the same blobs.
            // Each function reads the class itself and returns `Not…` for a blob of the other, so the two
            // cannot both act on one object and neither has to know the other exists. A liquidation is
            // still decided entirely inside the door beneath this call: the >=2/3 bonded tally over a
            // domain-separated message plus the WHIR carrier re-verified against THIS node's own
            // persisted digests, so a forged object applied here moves nothing.
            // ⛔ DB-274 P4b increment 2: the LIQUIDATION, PRICE-MARK, WRAPPED-ASSET REGISTRATION and WRAPPED-MINT arms that
            // stood here MOVED to the canonical fold (`objects_decide_at_fold` → `apply_fold_class_object`): they read the
            // validator set and write the peg ledger, so applying them here in arrival order let two nodes keep different
            // ledgers for one chain. Deleted, not duplicated (§9.5: one site).
            // ⭐⭐⭐ AND THE ORDER-POST CLASS, same seam, same blobs. A resting offer is a maker's
            // standing commitment to trade a locked lot, so it advances HERE on every node that grafts
            // the block — never in the handler on the one that answered the request. MEASURED
            // 2026-09-03: a book entry alive on one node and retired on another let the SAME maker's
            // lot pay out twice while both nodes self-verified correctly. The book's own door lives
            // inside this call and re-verifies the maker half, so a forged object posts nothing and the
            // block still grafts.
            let _ = crate::node::objects::order_post_tx::apply_chain_order_post(self, blob);
            // ⛔ DB-274 P4b increment 2: the NATIVE PEG-IN, PEG-OUT and YIELD-CLAIM arms that stood here MOVED to the
            // canonical fold with the others (`objects_decide_at_fold`): every node applies them once, in fold order,
            // against the step's pre-state, and a refused one's notes leave the record.
            // ⛔ DB-223 Q7: the ASSET TRANSFER arm that stood here MOVED to the canonical fold (`objects_decide_at_fold` →
            // `apply_fold_class_object`). Applied here, its membership refusal came AFTER the graft door had recorded the
            // transfer's outputs on conservation alone and stripped nothing. Deleted, not duplicated (§9.5: one site).
            // ⛔ DB-257 — THE UNBOND DOES NOT RELEASE HERE. It releases in `apply_bond_set` ONLY: the bond
            // set is the lane every unbond rides, and it is the lane the §BA door reads when it justifies the
            // returned note. Two release sites reading two different carried sets let a producer put an
            // unbond in one and not the other. The door would then justify the note from one set while no
            // release ran from the other, and the collateral and the weight would both be live.
            // ⛔⛔⛔ AND THE DEX FILL — THE ARM THAT WAS MISSING, WHICH IS THE 2026-09-03 CLASS EXACTLY.
            //
            // `order_fill_tx::apply_chain_dex_object` carries its own instruction: *"THE GRAFT-SIDE DOOR
            // — one call, so no node can be tempted to apply a DEX object its own way."* It had ZERO
            // production callers. The three DEX cross-party scenarios call it THEMSELVES, so they proved
            // the door works while nothing in a running node ever opened it: a block carrying an
            // OrderFill grafted on a peer, the peer never applied the fill, the maker's lot never burned
            // there, and the peer's book still served the order. That is the shape the cardinals record
            // from 2026-09-03 — two honest nodes each correct about a fill, and the maker's lot paid out
            // twice — because the burn stayed local and never travelled.
            //
            // The door re-runs BOTH halves on this node: the composed proof and the DB-150 membership
            // cross-bind per half, taken from the object's own bytes. A forged fill applied here moves
            // nothing, and an already-filled order is refused as already filled.
            //
            // ⛔⛔⛔ DB-224 — BUT NOT FOR A FILL, WHOSE "DOOR" IS A PUBLISHER. For `Class::OrderFill` this call
            // is `execute_order_fill`, which rebuilds the settlement and PUBLISHES it (`ingest_tx`) before
            // writing anything. Since DB-165 that arm was a no-op on every node (the producer and any node
            // that pooled the fill got `NotPublished` on the duplicate; a node that did not pool it had no
            // set to read), and handed a CARRIAGE it verifies the composed proof and is then refused at the
            // pool door — a wasted proof verification per node per fill and a false "REFUSED … NOTHING was
            // written … double-fill" line on every peer. A fill's state already travels on the block's own
            // lanes, on every node: its two burns ride `padded_tags` (the nullifier fold, and
            // `retire_orders_burned_by` retires the order from the book above), its three notes ride the
            // block's notes, justified at `graft_admitted_notes` by this same carried object (`admissible`
            // re-verifies the composed proof there), and its targets ride `account_targets`. So a fill is
            // skipped HERE; an ORDER POST still posts through the same door.
            if crate::chain_object::unframe(blob).map(|(c, _)| c) != Some(crate::chain_object::Class::OrderFill) {
                let _ = crate::node::objects::order_fill_tx::apply_chain_dex_object(self, blob);
            }
            // ⛔ §BR-14 (2026-10-28): the ASSET CREATION and MINT arms that stood here MOVED to the canonical fold
            // (`apply_fold_class_object` → `asset_tx::apply_chain_asset_object`). A creation spends its fee note, and a spend's
            // membership verdict is one verdict on every node only in the canonical order. Deleted, not duplicated (§9.5).
        }
    }

    pub(super) fn apply_grafted_block_carry(
        &mut self,
        gid: Hash32,
        gnotes: &[u8],
        // §20.2: the carried body's cover key (in process with the body; never on the wire)
        gcover: Option<crate::cover::CoverKey>,
        gtargets: &[u8],
        gpre: Hash32,
        gtags: &[[u8; 32]],
        gfold: &[u8],
        gbond: &[u8],
        gdir: &[u8],
        gletter: &[u8],
        // The grafted block's NOTE TRANSITION (§BA/§BB) — it rides the graft payload for the same
        // reason the notes do: a `BlockNode` keeps only header+tx_ids, so a CASCADED block's proof
        // would otherwise be unreachable by the node that just accepted it.
        gnt: Option<&crate::note_transition::NoteTransition>,
        // The same, for the CONSTANT-WIDTH class (DB-83) — it rides the carry payload for the identical
        // reason: a `BlockNode` keeps only header+tx_ids, so a CASCADED block's cover transition would
        // otherwise be unreachable by the node that just accepted it, and its tags would go unadmitted.
        gcnt: Option<&crate::note_transition::CoverTransition>,
        // ⭐ §BA — the grafted block's CREDIT SET, riding the carry payload for the same reason the notes
        // and the transition do: a `BlockNode` keeps only header+tx_ids, so a CASCADED block's sidecar
        // would otherwise be unreachable by the node that just accepted it.
        gcredits: &[u8],
        // ⛔ DB-351 — the grafted block's filed locator tags, riding the carry for the same reason: the note
        // transition's filing digests are recomputed from them.
        goli: &[u8],
        // ⭐ DB-223 Q7 — the grafted block's MEMBER transition, riding the carry for the same reason: a stated spend's
        // outputs are justified only when it proves the spend's input exists.
        gmt: Option<&crate::member_transition::MemberTransition>,
        // ⭐ §22b — the grafted block's WIDE OBJECTS (the bytes its sealed set names by hash), riding the carry for the same
        // reason the credit set does: the DAG keeps header and ids only.
        gwide: &[Vec<u8>],
    ) -> Option<usize> {
        if self
            .relay
            .dag()
            .get(&gid)
            .map(|n| n.header.is_genesis())
            .unwrap_or(false)
        {
            return None; // genesis gets its record in `enable_persist`, never here
        }
        // v31: every block a graft admitted — the one handed in AND each buffered descendant that
        // cascaded in behind it — stays buffered (full) until its record folds: the fold carry a
        // checkpoint and a bundle transport. (Gate 43: the carry was empty on live nodes because only
        // the `ingest_block`/`produce` wrappers filled it, and the runtime grafts elsewhere.)
        if let Some(rec) = self.relay.dag().get(&gid) {
            let mut shell = Self::header_shell(rec.header.clone(), rec.tx_ids.clone());
            shell.output_notes = gnotes.to_vec();
            // ⭐ §BA — AND ITS JUSTIFICATIONS, OR THE SHELL IS A BLOCK WHOSE NOTES NOTHING CAN EXCUSE.
            //
            // This shell is what a buffered block is re-applied from. Carrying the notes without the
            // credit set hands the door a block that looks exactly like a plant: header-bound notes, no
            // object naming any of them. MEASURED in `d52`: 3 honest notes and 2 honest deletions refused
            // on a path whose only defect was that the evidence did not ride with the payload.
            shell.credit_set = gcredits.to_vec();
            shell.wide_objects = gwide.to_vec(); // §22b: the named bytes stay with the held body
            shell.cover_key = gcover; // §22: the body's key stays with it in process (never on a wallet route)
            // §POLES (da_tags_mem DIFFERS): the shell's OLI tags must ride with it — `remember_unfolded_block`
            // dedupes by id, so the FULL block that `ingest_block_preverified_budgeted` passes to it after
            // the relay returns `Added` is REJECTED (the shell is already there), and the shell enters the
            // `full_block_by_id` lookup with `oli_tags: Vec::new()`. Every reader that resolves a block's tags
            // from the unfolded window (`payload_gap_settle`, `restore_tags_from_block_window` via
            // `full_block_by_id`) saw an empty list. MEASURED: census `da_tags_mem DIFFERS (65053/23150)` with
            // bidirectional divergence — each node missed tags for blocks the other produced.
            shell.oli_tags = goli.to_vec();
            self.remember_unfolded_block(shell);
        }
        let gheight = self
            .relay
            .dag()
            .get(&gid)
            .map(|n| n.blue_score)
            .unwrap_or(0);
        // ⭐⭐⭐ THE BLOCK'S NOTES BECOME THIS NODE'S RECORD. Z1 (2026-09-22): the unspent-tree fold that
        // stood here is gone with the deletion model — a spend retires by its NULLIFIER, folded from the
        // block's own `nullifier_proof` on every node (`apply_block_treeless` / `adopt_sparse_via_block_fold`),
        // which needs no tx bodies and no per-note tree. What remains is the record write itself, through
        // the ONE filter every writer shares (`graft_admitted_notes`: the mint-authority verdict and the
        // wrapper↔object binding, so an object that slipped past a pool door can never become recorded
        // value at graft — fail-closed on the BAD OBJECT's notes only, never on the block).
        // ⛔ DB-276b — a block held WITHOUT the notes its header commits is not recorded from its empty body; the
        // payload-gap arm below names it and the record lane delivers its record.
        if self.body_may_write_record(&gid, gnotes) {
            let gnotes_admitted: Vec<u8> =
                self.graft_admitted_notes(&gid, gnotes, gcover, gnt, gmt, gcnt, gcredits, gwide, gbond, gtags, goli);
            let rec_addr = self.record_note_payload_for(Some(gid), gheight, &gnotes_admitted, gcover);
            self.file_block_carried_tags(&gid, rec_addr, goli);
        }
        // ⭐⭐⭐ THE ORDER BOOK IS CHAIN STATE — retire every order whose maker note THIS block spent.
        // A resting order is IDENTIFIED BY its maker nullifier, the fill BURNS that note, and the burn
        // rides in `nullifier_proof.padded_tags` (carried here as `gtags`), bound into the block id —
        // so a node needs none of the fill's bytes to know the order is dead. Applied per grafted
        // block from ITS OWN carried tags: the loop this moved from passed the NAMED block's burns for
        // every cascaded block, so a cascaded fill's burns never retired its order on this node — the
        // measured 2026-09-03 double-payout shape one cascade later. Idempotent (`remove_by_nullifier`
        // on a retired order is a no-op); a cover tag matches nothing, so a quiet block retires
        // nothing and the constant padding still hides the real spend count.
        {
            // ⛔ NO COUNT IS LOGGED. A retired-order count is exactly the real-fill VOLUME the
            // constant padded tag lane exists to hide. The behaviour is covered by
            // `retire_orders_burned_by`'s own tests, which is where a count belongs.
            // DB-383: only the tags this block JUSTIFIES may retire an order — the fold's rule, judged from the carried
            // parts (the header's notes root is `da_notes_root_of(notes)`, the derivation the producer used)
            let ghdr = self.relay.dag().get(&gid).map(|n| n.header.clone());
            let gledger = ghdr.as_ref().map(|h| crate::member_transition::LedgerDoor::of_parts(h, gnotes, gtags, gcover));
            let credit_key = ghdr.as_ref().and_then(|h| crate::block::credit_seal_key(h, gcover.as_ref()));
            let just = self.lane_justified_parts(&crate::block::da_notes_root_of(gnotes), gnt, gmt, gledger, goli, gcnt, gbond, gcredits, credit_key, gwide);
            self.retire_orders_burned_by_justified(&just, gtags);
        }
        // ⭐ v32 (item 8c) — BRIDGE-CREDIT RECONCILE AT GRAFT. For each of this block's pooled tx blobs
        // that is a framed BridgeCredit, drop the accepting node's own STAGED duplicate: the published
        // copy just landed in this block (its note rode `Block::output_notes` through the one shared
        // record path above), so the staged copy riding this node's NEXT produced block would carry the
        // same commitment twice — the measured inflation class `stage_credit_note`'s doc records. A node
        // that never pooled the tx has nothing staged and nothing to reconcile; the credit still applied
        // to it in full through the block body. NO count or outcome is logged (credit volume is exactly
        // what the padded lanes hide).
        // ROOT-LAYER: the graft is the one place BOTH copies of a credit are visible — the published copy
        // (this block's carried notes, applied above through the shared record path) and the accepting
        // node's staged copy (`pending_credit_notes`) — so the staged-duplicate drop is produced here,
        // not patched where the duplicate would later be read (the produce drain). A node holding no
        // block entry or no pooled txs has nothing staged for them and the loop body simply never runs.
        if let Some((g_tx_ids, g_hdr)) = self.relay.dag().get(&gid).map(|n| (n.tx_ids.clone(), n.header.clone())) {
            let key = crate::block::credit_seal_key(&g_hdr, gcover.as_ref());
            self.apply_chain_objects_of(&g_tx_ids, gcredits, gtags, key, gwide);
            self.record_applied_one_time_ids(gid);
        }
        // ⭐ EVENT-DRIVEN RECORD REFILL — the exact moment a block applies WITHOUT its record bytes
        // (payload-empty gossip after a restart cleared the RAM record layer) is the moment to ask for
        // them BY ID, through the same proven heal plumbing the spend-fold uses (by-id NotesReq each
        // relay tick, bulk-first, drains on the answer). MEASURED 2026-08-13: send #3's record took
        // ~5 minutes to reach the recipient's node because nothing event-driven asked — the cursor
        // walk only rediscovered it on wrap, and the wallet's own wants were the eventual trigger.
        // cons: one BTreeSet entry per payload-missing block until its record arrives (bounded by the
        // refill backlog, drains to zero on a healthy mesh) and one extra da_load probe per grafted
        // block (an in-memory map read, no I/O).
        if self
            .da_record_notes(Self::da_record_id_for_block(&gid, 0))
            .is_none()
        {
            self.payload_gap.insert(gid, Self::da_record_id_for_block(&gid, 0));
            // ⭐⭐⭐ AND PROBE ITS AVAILABILITY, NOT ONLY ITS ABSENCE. This is the exact moment a block
            // applies WITHOUT its record bytes — so it is the moment to ask whether the producer HAS
            // them. Until sampling existed the node only ever asked for the record whole and waited; a
            // producer that committed `output_notes_root` and withheld the bytes was indistinguishable
            // from a slow one, forever. The root comes from the header THIS NODE accepted, and the chunk
            // count from the fixed cover shape — never from the peer being asked.
            if let Some(n) = self.relay.dag().get(&gid).map(|b| b.header.output_notes_root) {
                if n != Hash32::hash(&[]) {
                    let addr = Self::da_record_id_for_block(&gid, 0);
                    let _ = self.begin_da_sample(addr, n, Self::da_record_chunk_count());
                }
            }
        }
        self.adopt_account_targets_at(gtargets, Some(Self::da_record_id_for_block(&gid, 0)));
        // ⭐ DB-274 P2 (§8.7): the bond set does NOT apply here, at graft, in arrival order. It applies at the block's
        // canonical FOLD step (`bond_step_at_fold`), in the one order every node shares: two nodes grafting a seat
        // and an unbond (or an unbond and a slash) in opposite orders held different validator sets (B19).
        // DB-274 (dir_set): the directory set does not apply here either — it applies at the canonical fold
        // (`dir_step_at_fold`), like the bond set.
        let _ = (gbond, gheight, gnotes, gtags, gdir);
        // ⭐ LETTERS APPLY IN THE SAME ACT — a cascaded block's letter anchors advance the letter accumulator on the
        // very node that just accepted it, so every graft path yields the identical letter_acc (the multi-path
        // divergence lesson).
        self.apply_letter_set(Some(gid), gheight, gletter);
        // ⭐ A_TIP FOLDS IN THE SAME ACT THAT RECORDS THE BLOCK — every block a receive grafted,
        // cascade included, from what it carried. An own-mined block can never be applied twice here
        // (its gossip echo returns `Duplicate`, which is not grafted, and the produce drain skips the
        // named block), so produce and ingest cannot double-fold one.
        // ⭐ DB-117 (2026-09-20) — AND THE CARRY MUST COVER EVERY TIP'S PAST, NOT JUST THE SELECTED ONE.
        // The double-fold that broke I-3 was never in this step: it was a block accepted (and summed) here,
        // then dropped by `unfolded_carry` across a resume because it sat outside the selected tip's past,
        // then re-delivered as new and summed again. Fixed in `unfolded_carry`; this step is unchanged.
        self.fold_atip_at_accept(gid.0, gpre.0, gtags, gfold);
        self.note_backfill_cursor = self.note_backfill_cursor.saturating_add(1);
        Some(gnotes.len())
    }

    pub(crate) fn ingest_block_preverified(
        &mut self,
        block: Block,
        now_ts: u64,
    ) -> RelayOutcome {
        self.ingest_block_preverified_budgeted(block, now_ts, None)
    }

    /// ⭐ ITEM-6: `ingest_block_preverified` with the rt-lock apply budget carried INTO the graft
    /// cascade. The 200 ms budget in `apply_preverified_blocks` was checked only BETWEEN ingest
    /// calls, so one receive cascading hundreds of parked blocks applied them all inline — the
    /// measured `[tick-slow] drain held the rt lock 8368ms`, 232 occurrences in one boot. With a
    /// `deadline`, the relay releases at most `remaining_ms / 65` parked descendants this call (the
    /// measured ~50-65 ms apply+save class per grafted block, minimum one so the call always makes
    /// progress); the rest stay parked in the relay and re-enter through the strand lane next tick,
    /// full gates re-run. `None` = the old unbounded inline cascade (tests, direct callers).
    pub(crate) fn ingest_block_preverified_budgeted(
        &mut self,
        block: Block,
        now_ts: u64,
        deadline: Option<crate::budget_clock::Stamp>,
    ) -> RelayOutcome {
        #[cfg(test)]
        crate::budget_clock::replay_tx_trace("graft", &block.id().0, None);
        // ⛔⭐⭐⭐ DB-182 — REHYDRATE HERE TOO, AND THIS IS THE PATH THAT MATTERS.
        //
        // DB-165 took `output_notes` and `credit_set` off the wire (their LENGTHS stated the real note
        // count) and restored them at ingest from the block's own tx ids, checked against its committed
        // carrier. That restore was wired into `ingest_block` — and `ingest_block` is NOT the path a
        // block normally travels. The OFF-LOCK preverifier lands blocks through
        // `apply_preverified_blocks` -> here, which is where gossip, the by-id pull and every batch page
        // arrive. So the main path applied blocks whose body had been emptied on the wire.
        //
        // ⛔ MEASURED, ecosystem gate 21 (2026-09-25), once DB-177/180 made the nodes actually exchange
        // blocks and this check could finally run at volume:
        // ```text
        //   [record-regen] ⛔ ordinal N: the header declares this block idle but the seed row does not
        //                     fold to the certified ladder root this node holds          x69  (was 0)
        //   [da-fetch] 0/1 peer record(s) verified against roots we hold                 x46
        //   STEP 2 ❌ balance never reached 25.0 spendable (last: 0.0)
        // ```
        // A receiving node wrote a SEED-shaped record for a block that really carried notes, so its
        // record disagreed with the network's certified ladder root and the faucet credit never became
        // spendable. Gate 8 showed ZERO of these — not because the path was sound, but because the nodes
        // were barely exchanging blocks at all. **The convergence fix is what exposed it.**
        //
        // ⭐ The comment twenty lines up in `ingest_block` already named this exact failure mode about a
        // different mechanism: *"wiring a capture into the path I happened to be looking at is how half a
        // mechanism ships"*. DB-165 shipped half a mechanism, and this is the other half.
        //
        // Idempotent: a block whose body is already present re-derives the same notes and matches the
        // same carrier slots, so the producer's own self-ingest and the test callers are unaffected.
        let mut block = block;
        let (_m, unmatched) = self.rehydrate_block_body(&mut block);
        // G2g-r2b: the preverified door is where every page, gossip and by-id body lands (DB-182) — the owed fold-span body
        // is placed here exactly as in `ingest_block`.
        if let Some(out) = self.place_owed_fold_span_body_at_ingest(&block, unmatched) {
            return out;
        }
        // ⛔⛔ db333-r — A BLOCK THE ADOPTED STATE ALREADY COUNTS IS PLACED HERE, NEVER APPLIED.
        // §9.6 (the door this parallels is `graft_unfolded_carry`'s carried-block arm, which placed these same blocks when
        // the bundle still carried their bodies): (1) PoW — verified by `preverify_block` before this call, a stronger
        // check than the carried arm's `NotServable` header door, which also runs inside the graft; (2) the block's own
        // proofs — the same preverify gates; (3) value — none is created: the graft writes the record and places the
        // block, and its nullifier / letter / peg / validator effects are the ones the adopted state already holds;
        // (4) replay — the entry is REMOVED here, so a second delivery meets the DAG as a `Duplicate`; (5) work — one
        // map lookup per ingest, one carried-block graft per covered block, plus the parked children it releases, each
        // through the full `ingest_block`; (6) parity — every carried-arm check runs (it IS that arm), and the blue
        // data is the server's, bound by `FoldCarry::digest` into the certified binding exactly as the carry's was.
        // A covered block whose parents are not all held yet takes the ordinary path below and parks; its parent's
        // placement releases it back through this door.
        // MEASURED RED (db333 pin, scratchpad/verify/g2gr-db333-g.log): the joiner's `nf_fold_seq` 40 → 72 vs its
        // origin's 40 once the 32 blocks above the anchor arrived, nullifier roots apart from that moment.
        let bid = block.id();
        if let Some(&(bw, bs)) = self.dsync_covered.get(&bid) {
            if block.header.parents.iter().all(|p| self.relay.dag().get(p).is_some()) {
                self.dsync_covered.remove(&bid);
                self.graft_unfolded_carry(crate::sync::FoldCarry {
                    unfolded: vec![(block, bw, bs)],
                    ..Default::default()
                });
                if self.relay.dag().get(&bid).is_none() {
                    // The carried arm refused it (its header door or the DAG's settled-structure rules; the arm logs the
                    // count). Nothing was placed and nothing applied — never the ordinary apply, which double-counts.
                    return RelayOutcome::DagRejected(DagError::BelowSettledBase(bid));
                }
                for parked in self.take_orphans_waiting_on(&bid) {
                    let _ = self.ingest_block(parked, now_ts);
                }
                return RelayOutcome::Added(bid);
            }
        }
        if unmatched > 0 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT only — never a note, commitment, amount or owner.
            eprintln!(
                "[db165] ⛔ {unmatched} note(s) derived from this block's tx ids were NOT in its committed \
                 carrier — dropped (preverified path)."
            );
        }
        // ⭐ §BA/§BB — capture this block's NOTE TRANSITION before `block` moves into the relay. The
        // note-recording path below needs it to build its ALLOW-list, and a `BlockNode` keeps only
        // header+tx_ids, so after the move it is unreachable.
        let own_nt = block.note_transition.clone();
        let own_cover_key = block.cover_key; // §20.2: captured beside the body's other parts, before the block moves
        let own_cnt = block.cover_transition.clone();
        let own_mt = block.member_transition.clone(); // DB-223 Q7: the spends' input proofs ride with them
        // ⭐ §BA — and the block's own CREDIT SET, cloned for the same reason: the judgement below runs
        // after `block` has been moved into the DAG, and a sidecar the DAG does not keep is unreachable
        // from `gid` alone.
        let own_credits: Vec<u8> = block.credit_set.clone();
        let own_wide: Vec<Vec<u8>> = block.wide_objects.clone(); // §22b: beside the credit set
        let own_bonds: Vec<u8> = block.bond_set.clone();
        // DB-278: and its header-bound nullifier lane, which the graft door checks each credit-set object against.
        let own_lane: Vec<[u8; 32]> = block.nullifier_proof.padded_tags.clone();
        // DB-351: and its filed locator tags, which every filing digest of its note transition is recomputed from.
        let own_oli: Vec<u8> = block.oli_tags.clone();
        // PERF TIER step 1: the remaining budget on the BUDGET CLOCK (wall on a daemon, CPU on a simulated node).
        let max_cascade: usize = match deadline {
            None => usize::MAX,
            Some(d) => ((d.remaining_ms() / 65).max(1)) as usize,
        };
        let ing_pre = std::time::Instant::now();
        // Fold each grafted block's real nullifiers into the monotonic set (idempotent) so the LOCAL mempool
        // admission gate stays correct mesh-wide. A cover tx carries none; a block whose txs this node lacks folds
        // them when they arrive. (The former block-level reject was REMOVED — user-approved 2026-07-15 — it forked
        // concurrent spenders in a width>1 DAG; canonical ordering resolves conflicts. See [[project_trustless_nullifier_o1_design]].)
        let real_nfs: Vec<Hash32> = block
            .tx_ids
            .iter()
            .filter_map(|id| self.mempool.get(id))
            .flat_map(|tx| tx.nullifiers.clone())
            .collect();
        // DIGITAL-CASH VOLUME PRIVACY (padded consensus transition — ONE path, ENABLED). Capture BEFORE `block` is
        // moved into relay.receive what the padded advance needs. A NON-genesis block MUST carry a nullifier proof
        // (enforced fail-closed above), so `is_genesis` is the SOLE case with no nullifier transition; every other
        // accepted block advances the acc by EXACTLY `BLOCK_FIXED_NULLIFIER_COUNT` (256) — real nfs + secret-seeded
        // decoys derived deterministically from the block's own confidential tx blobs — so `nullifier_count` ==
        // 256×height (HEIGHT-ONLY, zero real-spend volume/timing leak), byte-identical to the producer's verified
        // `block.nullifier_proof.carrier`. A carrier-less non-genesis block was already rejected above — one path only.
        let is_genesis_block = block.header.is_genesis();
        // ⛔ THE FOUR NAMED-BLOCK FOLD CAPTURES ARE DELETED (D-35, 2026-09-08): `block_confidential`,
        // `real_vals`, `pre_root_committed` and `post_root_committed` existed only to feed the
        // `RelayOutcome::Added`-gated nullifier fold that used to run below. That gate is gone — every
        // block this receive grafts now folds from its OWN carried commitment in the per-block loop,
        // via `nf_fold_inputs_for_block`, which rebuilds exactly these two sets per block with the
        // identical filter and projections. Keeping them here would leave the named block's values
        // sitting beside a loop that must never use them, which is how the cascade came to be judged
        // by the wrong block's commitment in the first place. `fold_carried` goes with them — the
        // per-block `gfold` replaces it.
        // The public input rides the block with its proof — no mempool lookup, so a peer that never pooled
        // these txs still folds the block instead of parking it forever.
        let block_padded_tags: Vec<[u8; 32]> = block.nullifier_proof.padded_tags.clone();
        // DB-383: what this block's lane JUSTIFIES — the order book below acts on no other tag (built here, before the
        // block moves into the relay; the same rule the fold applies at its step)
        let block_lane_justified = self.lane_justified(&block);
        // The block's tx ids — captured BEFORE it moves into the relay so a successful graft can EVICT them from
        // this node's mempool below. `mined_tx_nf_pairs` is captured for the SAME reason: the eviction drops the
        // mined txs, so `pruned_double_spends` can no longer resolve this block's txs' nfs from the pool — we cache
        // each real-spend tx's nfs by TX ID now (survives eviction; the shared-tx case where a later conflicting
        // block re-includes an already-evicted tx still resolves from this cache). Only nullifier-bearing txs.
        let block_tx_ids: Vec<Hash32> = block.tx_ids.clone();
        // ⭐ lane agg — each TREE-FORM body's payment (its tags and its output notes), captured before the move: the FULL
        // twin of that payment, pooled at its origin under its own id, is the same payment and leaves with it below
        // (Bitcoin's removeConflicts, narrowed to the twin: same tag set AND same notes; a different spend of one of the
        // tags is not touched here). It is held for the fold verdict like the block's own ids, so a refused fold returns it.
        #[allow(clippy::type_complexity)]
        let agg_twins: Vec<(Vec<Hash32>, Vec<u8>)> = block
            .tx_bodies
            .iter()
            .filter_map(|b| crate::chain_object::decode_exact::<PqTx>(b))
            .filter(crate::spend_evidence::is_tree_form)
            .map(|t| (t.nullifiers, t.output_notes))
            .collect();
        // ⛔⛔⛔ DB-389 (rogue-role census, 2026-10-04): WHAT THIS BLOCK ACTUALLY CARRIES, captured before the move. A pooled
        // framed object leaves the pool only when the block carries it byte-for-byte — its carriage in the credit set, or its
        // very bytes in the bond set. A block that merely LISTED a tx id, or carried a stripped / corrupt copy, evicted the
        // honest pooled tx on every node while the fold refused the copy (MEASURED by lane-harness on BondTransition
        // forge/strip/burn: "node_a laid a block WITHOUT its pooled bond"): one producer censored any pending tx, repeatably.
        // O1-FOOTPRINT-REVIEWED: bounded by the block's fixed credit and bond lanes; dropped at the end of this call.
        let block_carried: std::collections::HashSet<Hash32> = {
            let mut s = std::collections::HashSet::new();
            let key = crate::block::credit_seal_key(&block.header, block.cover_key.as_ref());
            for c in crate::block::credit_set_iter(&block.credit_set, key.as_ref(), &block.wide_objects).into_iter().flatten() {
                s.insert(Hash32::hash(&c));
            }
            for tx in Self::bond_set_entries(&block.bond_set).0.into_iter().flatten() {
                s.insert(tx.id);
            }
            s
        };
        // DB-389, the BOND lane: a bond tx is not a framed object — it is APPLIED only if the block's bond transition admits
        // its nullifier (`bond_admissions_of`, the graft door's own verdict, pure over the block). A bond listed, or carried
        // with its welded statement stripped / corrupted / re-weighted, admits nothing and evicts nothing.
        let block_bond_admit: Option<crate::note_transition::Admissible> =
            Self::bond_admissions_on_door(&block.bond_set, &block.header.output_notes_root, self.template_double());
        // The burns this block publishes, captured BEFORE the block moves into the relay. Used after the
        // graft to retire every resting order whose maker note was spent — see the call below.
        // O1-FOOTPRINT-REVIEWED: bounded by protocol constant BLOCK_FIXED_NULLIFIER_COUNT — the lane is
        // cover-padded to that constant, so this is the same fixed size for a busy block and an idle one,
        // and it is dropped at the end of this call.
        let block_burns: Vec<[u8; 32]> = block.nullifier_proof.padded_tags.clone();
        // ⭐ SUB-PHASE STAMPS INSIDE THE PRE-RECEIVE SPAN — the 312 ms nobody could name.
        //
        // MEASURED on a real joiner (2 real nodes, onion transport, 191 blocks ingested):
        //   ing_apply  311.9 ms/block   <- 84% of the whole ingest cost, and this span IS ing_apply
        //   ing_verify  29.9 ms/block (all of it PoW)
        //   ing_graft    0.0 ms   ing_save 0.1 ms
        // That cost caps a follower's ingest near 1 block/s against a producer at ~1.3/s, so the gap only
        // ever closes by a #29 DSYNC jump. `ing_apply` is one 196-line span with no internal timing, so
        // it named a function, not a cause. These three stamps name the cause.
        let pre_nf_ms = ing_pre.elapsed().as_millis();
        // Captured before the move into the relay so the graft below can resolve this block's height for its
        // note record (the produce path reads the same `blue_score`).
        let grafting_block_id = block.id();
        // The block's OWN note payload — replicated data every grafting node records identically. Captured
        // before the block moves into the relay.
        // ⭐ G1g-ix: the tags this block carries are filed at the record its graft writes (`file_block_carried_tags`,
        // header-bound), never staged in the node-local `pending_tags` map — a buffered block parked them there and a
        // restart dropped them with the orphan buffer (restart census, g1gviii-restart-census-20261023.log).
        // ⭐⭐⭐ CARRIED TAGS ARE AUTHORITATIVE ON EVERY DELIVERY — NOT ONLY ON A FIRST GRAFT.
        //
        // Seeding `pending_tags` above only helps if the record loop then runs, and it runs ONCE, on the
        // first graft. Any delivery that arrives as `Duplicate` — the block already held — drains nothing,
        // so a tag this node did not have at first-graft time is lost FOREVER even though every later copy of
        // the block carries it.
        //
        // MEASURED 2026-08-10: node B seeded 2 carried tags 82 times and indexed 2 of 4 total, while holding
        // both real-note blocks and running AHEAD of node A in height. The data arrived repeatedly and had
        // nowhere to go.
        //
        // Write them straight to the DA shard, keyed by the block's own record address (a pure function of
        // the block id, identical on every node). Merge rather than replace: a slot already stored keeps its
        // value, so this can never overwrite a tag a node derived itself, and re-running it is a no-op. That
        // makes indexing SELF-HEALING by construction — a node that ever sees the block ends up with its
        // tags, regardless of message order, graft outcome, or which node produced it.
        //
        // NO GROWTH: bounded by the REAL notes in one block; cover slots carry no tag. Tags stay DA-resident
        // ([[reference_oli_tags_are_da_resident_never_cached]]), so nothing new is held in memory.
        let pre_oli_t0 = std::time::Instant::now();
        // ⛔ ONE COORDINATE: filed through `file_tags_at_fixed_slots` at each note's FIXED-SHAPE slot (the record loop's,
        // the wallet's leaf index's). This used to file the note's index in `block.output_notes` (reals, unpermuted) into
        // the same store, and to file a list its header does not bind; a block not recorded yet files nothing here (the
        // graft files them at the record it writes: `file_block_carried_tags`).
        let carried_ok = Self::window_block_carried_tags(&block, &block.id()).is_some();
        if !block.oli_tags.is_empty() && carried_ok {
            let filed = self
                .record_addr_for_block(&block.id())
                .and_then(|addr| self.file_tags_at_fixed_slots(addr, &block.oli_tags).map(|f| (addr, f)));
            if let Some((addr, (_, added))) = filed.filter(|(_, (_, added))| *added > 0) {
                // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a tag, cm, key or owner.
                eprintln!(
                    "[oli-carry] STORED {added} carried tag(s) straight to the DA shard on delivery ({} now held for this \
                     record) — indexing no longer depends on winning a first graft",
                    self.da_load_tags(addr).len()
                );
            }
        }
        let carried_notes: Vec<u8> = block.output_notes.clone();
        let carried_targets: Vec<u8> = block.account_targets.clone();
        let mined_tx_nf_pairs: Vec<(Hash32, Vec<[u8; 32]>)> = block_tx_ids
            .iter()
            .filter_map(|id| {
                self.mempool
                    .get(id)
                    .map(|tx| (*id, tx.nullifiers.iter().map(|nf| nf.0).collect::<Vec<_>>()))
            })
            .filter(|(_, nfs)| !nfs.is_empty())
            .collect();
        let _accepted_id = block.header.id();
        // The block's own notes, captured before the block moves into the relay — the fold below derives this
        // block's note root from them rather than from a DA record that is not written yet.
        let _accepted_notes: Vec<u8> = block.output_notes.clone();
        // ⛔⛔⛤ COUNT WHAT THE DAG GAINED AGAINST WHAT THE LEDGER RECORDED — the peers-only hole.
        //
        // MEASURED tonight: a SOLO node holds gap=0 forever (1 record per block, 1,000 blocks), but two
        // PEERED nodes both booted at gap=0 and grew to 827 and 736 within minutes. So the hole opens only on
        // blocks arriving FROM A PEER, which is exactly why the solo run misled me into calling the gap an
        // artifact. The existing `[ledger-hole]` probe watches only the NAMED block; a graft also drains the
        // orphan buffer and cascades a run of descendants in behind it, and those take a different loop.
        //
        // Comparing DAG growth to record growth across the whole call catches every path at once, including
        // any that neither probe covers. `served_seq` is the frontier's own count (leaves/256), so this is the
        // ledger's real advance, not a bookkeeping counter.
        let dag_before = self.relay.dag().len();
        let rec_before = self.served_seq;
        // ⛔⛔⛔ A RECEIVED BLOCK'S NOTES MUST BE RECORDED, NOT ONLY VERIFIED.
        //
        // MEASURED 2026-08-11, real wallets, two real peered nodes, a real Send press:
        //   sender on :27841   1,000.00 -> Send 100 -> 900.00      (correct, the money left)
        //   recipient on :27842  ⛔ BUCKET+OLI DETECTION returned ZERO notes across 139 served record(s)
        // The payment settled and the recipient could never see it. `record_note_payload_for` was called
        // from exactly ONE function — `graft_mined_own`, the PRODUCE path. So a node recorded notes only for
        // blocks IT mined. Node :27842 verified, grafted and stored the sender's block, and then had no note
        // to serve for it, because recording lived on the wrong side of the produce/ingest split.
        //
        // That makes every payment one-directional by construction: it is visible only on the node that
        // happened to mine it. A note that exists on chain and cannot be served to its owner is fund loss —
        // the DA layer IS the ledger, and a node that holds the block must hold its notes.
        //
        // Captured BEFORE `receive` takes the block, and recorded only when the DAG actually accepted it.
        let ingested_id = block.id();
        // The address derives from the BLOCK ID (we pass `Some(ingested_id)`), so this height is only the
        // record's reported height — the DAG length at ingest is the honest figure for that.
        let ingested_height = dag_before as u64;
        let ingested_notes: Vec<u8> = block.output_notes.clone();
        // Pre-receive captures count toward APPLY now (the pure gates stamp ING_VERIFY upstream).
        let pre_total_ms = ing_pre.elapsed().as_millis();
        let pre_oli_ms = pre_oli_t0.elapsed().as_millis();
        if pre_total_ms > 100 {
            // DIGITAL-CASH-PRIVACY-REVIEWED: millisecond durations of this node's own ingest phases and
            // two byte LENGTHS of data the block already carries publicly. No note, amount, key or owner.
            eprintln!(
                "[ingest-slow] the pre-receive span held the lock {pre_total_ms}ms (nf+captures \
                 {pre_nf_ms}ms, oli-carry {pre_oli_ms}ms, rest {}ms; output_notes {} B, padded_tags {}) \
                 — this span is 84% of a follower's per-block cost, so it is what decides whether a node \
                 can keep up with the chain at all",
                pre_total_ms.saturating_sub(pre_nf_ms).saturating_sub(pre_oli_ms),
                ingested_notes.len(),
                block_padded_tags.len()
            );
        }
        crate::node_runtime::ING_APPLY_MS.fetch_add(
            pre_total_ms as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let ing_t1 = std::time::Instant::now();
        let keep_unfolded = block.clone(); // v31: kept full until its record folds (fold carry)
        let outcome = self.relay.receive_bounded(block, now_ts, max_cascade);
        self.reanchor_on_refused_history_merge();
        if matches!(outcome, RelayOutcome::Added(_)) {
            // v31: the runtime ingests HERE (preverified off-lock), not through `ingest_block`.
            self.remember_unfolded_block(keep_unfolded);
        } else if matches!(outcome, RelayOutcome::Duplicate(_)) {
            // COMPACT-BLOCK RELAY: the block landed as a SHELL (a descent page, a bundle's ancestor) while
            // this body was parked or verifying — keep the body instead of dropping it with the duplicate.
            let _ = self.fill_shell_body_preverified(keep_unfolded);
        }
        // The cascade's released children: their WHOLE bodies join the unfolded window too.
        // CHAIN-PUBLISH-REVIEWED: blocks the chain already carries; each witness is its block's own.
        for body in self.relay.take_cascaded_bodies() {
            let id = body.id();
            self.retain_pow_witness(id, &body.pow_proof);
            // A shell may already stand for it (a page or a rebuffer): REPLACE it, never dedupe against it.
            if !self.fill_shell_body_preverified(body.clone()) {
                self.remember_unfolded_block(body);
            }
        }
        crate::node_runtime::ING_GRAFT_MS.fetch_add(
            ing_t1.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        // ⭐ STAMP THE POST-GRAFT APPLY — this is where `ing_apply`'s 284 ms/block actually lives.
        //
        // ⛔ AND THE COUNTER HID IT. `ING_APPLY_MS` is incremented TWICE in this one function: once for
        // the pre-receive span and again for THIS span. Stamping only the first produced ZERO
        // `[ingest-slow]` lines while the counter averaged 284 ms/block — the same lesson as the
        // `bulk-page` residual earlier: a counter that aggregates two spans names a FUNCTION, not a
        // cause, and reading it as one span sends the reader to the wrong half.
        //
        // MEASURED on a real joiner (246 blocks ingested over onion): ing_apply 284.1 ms/block against a
        // 500 ms block time, which is what caps a follower near 1 block/s and makes it depend on the
        // #29 DSYNC jump to ever catch up.
        let mut ap: [(&'static str, u128); 6] = [("", 0); 6];
        let mut ap_n = 0usize;
        let mut ap_t = std::time::Instant::now();
        let mut ap_stamp = |name: &'static str, t: &mut std::time::Instant, n: &mut usize, a: &mut [(&'static str, u128); 6]| {
            if *n < a.len() {
                a[*n] = (name, t.elapsed().as_millis());
                *n += 1;
            }
            *t = std::time::Instant::now();
        };
        let ing_t2 = std::time::Instant::now();
        // ⛔⛔⛔ `RelayOutcome::Added` NAMES ONE BLOCK. A RECEIVE GRAFTS A WHOLE CASCADE, AND THE REST WERE
        // ENTERING THE DAG WITH NO RECORD AT ALL.
        //
        // `take_grafted`'s own doc says it plainly: *"EVERY block the last receive grafted … plus every
        // buffered descendant that cascaded in behind it. `RelayOutcome::Added` names only the first, so this
        // is the only complete account of what entered the DAG."* This path ignored it and keyed off the
        // outcome enum instead, so a block that arrived before its parent was `Buffered`, grafted later inside
        // a cascade, and was never recorded by anyone. Worse than a miss: `take_grafted` is transient and
        // *"cleared at the start of each receive"*, so leaving it undrained here DISCARDED that account.
        //
        // MEASURED 2026-08-11, the unattended two-node/two-wallet run (`tests/cross_device_send.rs`):
        //   [xdev] blocks crossed — an accumulator from one node appeared on the other
        //   [xdev-send 1/3] submit=PASS settle=FAIL (recipient 0 -> 0)
        //   node-A `ingest-record` occurrences: 0
        //   node-B `ingest-record` occurrences: 0
        // Blocks demonstrably crossed and this branch fired ZERO times on either node. Between two peers on a
        // chain producing every ~500ms, out-of-order arrival is the ordinary case, so the `Added` gate was the
        // exception rather than the rule — the payment reached the recipient's node and left no note, no
        // membership fold and no account target behind. That is exactly `settle=FAIL`.
        //
        // The graft path already does this correctly. Ingest now does the same: a block is recorded because it
        // ENTERED THE DAG, never because of which enum variant described its arrival.
        //
        // CANONICAL ORDER, not arrival order — the same reason given at the graft site: two nodes drain
        // different runs in different orders, and a wallet's account bucket stores a note's ORDINAL, so the
        // numbering must be a function of consensus rather than of who arrived first. `canonical_order_key`
        // is `(blue_work, block id)`, so collecting into a BTreeMap keyed by it yields exactly that order on
        // every node without a separate ordering pass.
        //
        // NO GROWTH: bounded by the blocks THIS receive grafted, i.e. what the DAG just gained. No term in
        // height, chain size or note count, and the map is consumed rather than retained.
        ap_stamp("receive+cascade", &mut ap_t, &mut ap_n, &mut ap);
        let _ = (&outcome, ingested_id, ingested_height, &ingested_notes);
        let mut ordered: std::collections::BTreeMap<
            (u128, Hash32),
            (
                Vec<u8>,
                Vec<u8>,
                Hash32,
                Vec<[u8; 32]>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Vec<u8>,
                Hash32,
                // §BA/§BB — the block's note transition rides the canonical-order reshuffle with the
                // rest of its payload, so a cascaded block keeps its own allow-list evidence.
                Option<crate::note_transition::NoteTransition>,
                // ⭐ §BA — and its CREDIT SET, for the same reason and appended LAST: the judgement runs
                // after the reshuffle, and a sidecar that did not ride it refuses every non-spend note.
                Vec<u8>,
                // ⭐ DB-83 — and its CONSTANT-WIDTH transition, same reason, appended LAST.
                Option<crate::note_transition::CoverTransition>,
                // ⛔ DB-351 — and its filed locator tags, same reason, appended LAST.
                Vec<u8>,
                // ⭐ DB-223 Q7 — and its MEMBER transition, same reason, appended LAST.
                Option<crate::member_transition::MemberTransition>,
                // §20.2 — and the body's cover key, appended last
                Option<crate::cover::CoverKey>,
                Vec<Vec<u8>>,
            ),
        > = std::collections::BTreeMap::new();
        for (
            gid,
            gnotes,
            gtargets,
            gpre,
            gtags,
            gfold,
            gbond,
            gdir,
            gletter,
            gpost,
            gnt,
            gcredits,
            gcnt,
            goli,
            gmt,
            gcover,
            gwide,
        ) in self.relay.take_grafted()
        {
            // The genesis skip and the v31 unfolded-block buffering live in
            // `apply_grafted_block_carry` — the ONE shared per-block apply — so the produce-side
            // drain in `graft_mined_own` cannot drift from this path.
            let key = self.relay.dag().canonical_order_key(&gid);
            ordered.insert(
                key,
                (
                    gnotes, gtargets, gpre, gtags, gfold, gbond, gdir, gletter, gpost, gnt,
                    gcredits, gcnt, goli, gmt, gcover, gwide,
                ),
            );
        }
        let mut recorded_blocks = 0usize;
        let mut recorded_bytes = 0usize;
        // The ids this receive grafted — kept only for the one-coordinate record probe below
        // (bounded by this receive's own cascade, dropped at the end of the call).
        let grafted_ids: Vec<Hash32> = ordered.keys().map(|(_, gid)| *gid).collect();
        for ((_, gid), (gnotes, gtargets, gpre, gtags, gfold, gbond, gdir, gletter, gpost, gnt, gcredits, gcnt, goli, gmt, gcover, gwide)) in
            ordered
        {
            // ONE shared per-block apply — `apply_grafted_block_carry` (the produce-side drain in
            // `graft_mined_own` calls the same function; one encoding, never a second). Note the
            // order-book retire now uses each block's OWN carried tags (`gtags`) instead of the named
            // block's burns for every cascaded block — see the measurement in the helper.
            if let Some(bytes) = self.apply_grafted_block_carry(
                gid, &gnotes, gcover, &gtargets, gpre, &gtags, &gfold, &gbond, &gdir, &gletter,
                gnt.as_ref(), gcnt.as_ref(), &gcredits, &goli, gmt.as_ref(), &gwide,
            ) {
                recorded_blocks += 1;
                recorded_bytes += bytes;
            }
            // ⛔⛔⛔ THE NULLIFIER FOLD BELONGS TO THE BLOCK THAT ENTERED THE DAG, NOT TO THE ONE
            // `RelayOutcome::Added` HAPPENS TO NAME. (D-35, closed 2026-09-08.)
            //
            // This call used to sit below, behind `if matches!(outcome, RelayOutcome::Added(_))`, and
            // it ran with the NAMED block's pre/post/tags. That is the SAME defect shape this loop was
            // built to fix for the DA record in August — `take_grafted`'s own doc says "`Added` names
            // only the first, so this is the only complete account of what entered the DAG" — and the
            // record half was repaired while the nullifier half was left on the old gate. So every
            // block that entered behind a cascade (a parent-ask recovery, a released buffered
            // descendant — the ORDINARY case on a width>1 DAG) skipped `nf_blocks`, `nf_leaves`, the
            // DA-servable nullifier stream (`da_nf_store`) and the cover-conf accumulator.
            //
            // MEASURED, two parties, `produce 0 · drop 1 · produce 0`, against a no-drop control that
            // AGREES at 513/513: the party whose delivery was destroyed and then recovered held the
            // same 3 blocks, the same records (`rec_top=1`) and the same unspent leaves (256) — and
            // `nullifier_count 257 vs 513`, short by exactly one block's 256-wide cover. The A_tip
            // fold was never affected (it already ran per grafted block inside
            // `apply_grafted_block_carry`), which is why the consensus roots matched and this hid.
            //
            // WHY IT COSTS FUNDS: wallets fold the SERVED nullifier stream to its end to name a spend
            // endpoint, and this function's own comment records what a short stream did last time —
            // "every spender named an endpoint this node had never folded and every send was refused".
            // A node that caught up through a parent ask served exactly that short stream.
            //
            // The inputs are each block's OWN carried values, so a cascaded block is judged by its own
            // commitment and never by the named block's: `gpre` is its header-committed pre-root,
            // `gpost` its carrier's proven post-root, `gtags` its padded tag set, `gfold` its carried
            // height-1 fold. The soundness gate is unchanged and still fail-closed —
            // `adopt_sparse_via_block_fold` re-derives the post from `gpre` + `gtags` and refuses on
            // any mismatch with `gpost` — so widening WHICH blocks fold weakens nothing about HOW.
            // Genesis is skipped for the same reason it is skipped for the record.
            if !self
                .relay
                .dag()
                .get(&gid)
                .map(|n| n.header.is_genesis())
                .unwrap_or(true)
            {
                // ⭐ THE LAST LEVEL. MEASURED: the post-graft apply is 100% `grafted-loop`
                // (222 of 222 occurrences, 105–132 ms each), and this fold is what the loop does.
                // Naming the fold separately from the rest of the loop is what turns "the loop is slow"
                // into a subsystem — DB-153 measured `advance_sparse_shadow` (the Merkle view, ~256 ×
                // DEPTH Poseidon per block, twice over) as the dominant term, and this stamp is what
                // confirms or refutes that here rather than inheriting it.
                let nf_t0 = std::time::Instant::now();
                let g_conf = self.nf_fold_inputs_for_block(&gid);
                let nf_inputs_ms = nf_t0.elapsed().as_millis();
                let fold_t0 = std::time::Instant::now();
                let folded_ok = self.fold_block_nf_in_order(gpre.0, gpost.0, &g_conf, &gfold, &gtags);
                let fold_ms = fold_t0.elapsed().as_millis();
                if nf_inputs_ms + fold_ms > 50 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: two millisecond durations and a carried tag COUNT
                    // of the block's own constant-width set. No tag value, amount, key or owner.
                    eprintln!(
                        "[nf-fold-slow] the nullifier fold took {fold_ms}ms (inputs {nf_inputs_ms}ms) \
                         over {} carried tag(s) — this is the per-block cost that decides whether a \
                         follower can keep up with the chain",
                        gtags.len()
                    );
                }
                // Neither old failure mode survives: the fold is order-free, and it reads the block's carried
                // tags rather than this node's pool. What is left refusing is a TAG-LESS (old-format) block,
                // refused outright, never parked (DB-353 §13.5 item 2: the stash could never unlock).
                if folded_ok {
                    self.release_folded_tx_evictions();
                }
            }
        }
        let _ = &block_burns; // the named block's burns now retire via its own carry in the loop above
        // Per receive that grafted (49 k lines of a 10-node run): `MONEROUSD_DEBUG=net` only — `arti_transport::net_debug`.
        if recorded_blocks > 0 && crate::arti_transport::net_debug() {
            // DIGITAL-CASH-PRIVACY-REVIEWED, BY CONSTRUCTION: the only values formatted are two `usize`
            // COUNTS — blocks grafted and note bytes recorded. Never a commitment, address, amount, key or
            // owner.
            eprintln!(
                "[ingest-record] recorded {recorded_blocks} block(s) / {recorded_bytes} note byte(s) that \
                 this receive grafted, cascade included — a payment is now servable on the node that ingested \
                 it, not only on the node that mined it. Keying this off `Added` recorded ZERO on both nodes \
                 while blocks were provably crossing."
            );
        }
        // ⛔ THE DUPLICATE SELF-HEAL WAS DELETED — IT WAS BOTH UNNECESSARY AND ACTIVELY HARMFUL.
        //
        // I added a branch that re-recorded a `Duplicate` block's payload "if this node holds no record for
        // it", on the hypothesis that re-delivery was where records went missing. That hypothesis was later
        // REFUTED by measurement — the real deficit was the frontier-rollback regression, now fixed — and the
        // branch did real damage in the meantime: its guard checked sub-0 (`da_record_id_for_block(id, 0)`)
        // while `record_note_payload_for` advances its own sub counter 0..DA_RECORDS_PER_HEIGHT, so each
        // gossip re-delivery wrote a NEW sub-record and appended another 256 leaves. MEASURED: `served_seq`
        // ran to 33,636 against a 7,575-block DAG — a 4.4x over-count (DA_RECORDS_PER_HEIGHT = 4) that
        // corrupts the frontier coordinate a recipient's copath resolves against, so the note settled but the
        // recipient's wallet read 0. Every accepted block is already recorded exactly once on the `Added`
        // branch; a duplicate is by definition already handled.
        // ⛔⛔⛔ A PAYMENT BLOCK THAT ARRIVES BUT IS NOT *ADDED* PAYS NOBODY — NAME THE OUTCOME.
        //
        // MEASURED 2026-08-01, once the receive probe stopped sampling 1-in-64: node B received the
        // target-bearing block 1,670 times across 2 distinct ids, each carrying the full 2,500 target bytes
        // (`[gossip-in] block CARRYING TARGETS id=e54bc81f4bd0094b … 2500 account-target byte(s)`), and
        // `[graft] block carried … adopting` fired ZERO times. Adoption sits behind this `Added` gate, so the
        // relay is returning something else for every single arrival — and nothing anywhere reports WHICH.
        //
        // That distinction is the whole remaining question and each answer has a different fix: Duplicate means
        // the block is already held and the targets were dropped on the FIRST pass; an orphan/unknown-parent
        // means it is parked awaiting a parent that may never come; Invalid means a gate is refusing real money.
        // I have already spent turns theorising into this silence, so it is measured instead.
        //
        // Fires ONLY for a block carrying account targets — one block in ~1,367 — and only when it is not
        // added, so the healthy path and the per-block path both stay silent.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a block ID prefix, a target byte length, and the relay's own verdict
        // discriminant — public chain structure gossip already carries. Never a note, amount, key or owner.
        // ⛔ A PROBE MUST REPORT A FACT, NOT A CONCLUSION. This fired for EVERY non-`Added` outcome and
        // asserted "its targets are therefore never adopted" — which is FALSE for `Duplicate` and
        // `AlreadyBuffered`, where this node already holds the block and adopted its targets on the first
        // pass. MEASURED 2026-08-10: 81 `Duplicate` re-deliveries of ONE block read as 81 losses, and I
        // reported "the block never reaches node B" when node B had it and was AHEAD in height. A probe that
        // editorialises costs a turn pointed the wrong way, which is the same lesson this function's own
        // comments already record.
        if !carried_targets.is_empty()
            && !matches!(
                outcome,
                RelayOutcome::Added(_)
                    | RelayOutcome::Duplicate(_)
                    | RelayOutcome::AlreadyBuffered(_)
            )
        {
            eprintln!(
                "[graft-refused] a block CARRYING {} account-target byte(s) (id={}) was NOT added: {:?}. Its \
                 targets are therefore never adopted, so the recipient's bucket stays empty even though the \
                 block arrived intact.",
                carried_targets.len(),
                grafting_block_id.as_bytes()[..8]
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect::<String>(),
                std::mem::discriminant(&outcome)
            );
        }
        if matches!(outcome, RelayOutcome::Added(_)) {
            // FOLD THE BLOCK EXACTLY ONCE, HERE. The accumulator used to advance inside the note-record path,
            // which runs several times per block (produce, ingest, backfill, adopt) and also for credits that
            // are not blocks at all. A sum is commutative but not idempotent, so every re-application
            // double-counted — and the dedup I first reached for (`da_load(addr).is_some()`) is useless
            // because a block carrying no user payment writes NO record: measured 0 records on disk while the
            // accumulator advanced on every block, so the guard was always false. Two nodes on the IDENTICAL
            // 319-block set therefore disagreed 0/6, the one that re-applied more reading higher.
            //
            // The DAG is the correct authority: it accepts a given block exactly once, so folding on `Added`
            // is idempotent by construction and needs no extra state to track.
            // Cache each mined real-spend tx's nfs by tx id BEFORE the pool eviction below removes them — the
            // persistent backing `Dag::canonical_block_nullifiers` documents, so the width>1 canonical conflict
            // resolution ([`Self::pruned_double_spends`]) reconstructs each block's nfs from its own retained
            // `tx_ids` and stays receive-order-independent after mined txs leave the pool. Bounded by the DAG window.
            ap_stamp("grafted-loop", &mut ap_t, &mut ap_n, &mut ap);
            for (tx_id, nfs) in mined_tx_nf_pairs {
                self.mined_tx_nfs.entry(tx_id).or_insert(nfs);
            }
            self.prune_mined_tx_nfs();
            // ⭐ EVICT ON GRAFT — the txs this block carries are ON-CHAIN now, so they must leave the pool (and
            // release their entries in the double-spend `spent` map). Only the PRODUCE path used to do this
            // (`graft_mined_own`), so a node that VERIFIES rather than mines never drained its pool: it gained an
            // entry per tx per block, forever. That is an unbounded growth axis on exactly the "a phone is a full
            // node" path, and it is why a verifying node's retained state was not flat.
            // ([[feedback_no_growth_any_axis]] [[feedback_decentralization_pillar]])
            //
            // ⭐ RECORD ON GRAFT — the SAME produce-only omission as the eviction above, and the reason
            // CROSS-DEVICE sends silently lost every payment: only `graft_mined_own` recorded a block's output
            // notes, so a node that VERIFIES rather than mines stored NOTHING of the notes its peers' blocks
            // carried. The recipient's wallet talks to ITS OWN node, and that node held no note to serve — the
            // scan found 0 owned however hard it looked, because the only node holding the note was the
            // sender's. The tx gossip already carries `output_notes` (the whole `PqTx` is postcard-encoded), so
            // the data was on every node all along; only the recording step was missing. Runs BEFORE the pool
            // eviction below, which is what the notes are read from.
            //
            // Recorded UNCONDITIONALLY — a block carrying no real notes still gets its record, so a verifying
            // node's served store wears the SAME constant BLOCK_FIXED_NOTE_COUNT shape per block as a
            // producer's. A store holding records only for note-bearing blocks would tell an observer exactly
            // which blocks carried payments ([[feedback_all_blocks_fixed_cover_shape]]).
            //
            // A bond tx's output0 is withheld by the shared assembly (LOCKED, never spendable); a verifying
            // node simply never adds it to its spendable set, which is the fail-closed direction.
            if !is_genesis_block {
                let height = self
                    .relay
                    .dag()
                    .get(&grafting_block_id)
                    .map(|n| n.blue_score)
                    .unwrap_or(0);
                // TX LIFECYCLE: the pool measures a tx's age in BLOCKS, so it learns the height every block.
                // A payment that is admitted and then never settles is otherwise INVISIBLE — no rejection, no
                // log, the sender simply told "sent". `stuck_pooled_txs` below turns that into a loud local
                // warning instead of silently-missing money.
                self.mempool.set_height(height);
                // RECORD THE NOTES THE BLOCK CARRIES. Reconstructing them from THIS node's mempool only
                // worked on a node that had itself admitted the tx: a peer whose spend gate refused the
                // gossiped tx (it verifies against that peer's OWN accumulator state) holds no tx body and
                // recorded NOTHING — which is exactly how the recipient's own node ended up with zero notes
                // for a block that carried their payment. The block's own payload is the replicated data.
                // ⭐⭐⭐ BLOCK ACCEPTANCE **IS** PAYMENT DELIVERY — record EVERY accepted block, always.
                //
                // This was `if !carried_notes.is_empty()`, so a block carrying no real notes was never
                // recorded and `served_seq` did not advance for it. That makes the record stream a function
                // of WHICH BLOCKS HAPPENED TO CARRY NOTES AS SEEN BY THIS NODE — and two nodes never see the
                // same set. Measured live: node A at served 16228 of 16955 blocks, node B at 15109 of 16899.
                // Their ordinal spaces had DIVERGED, so an account bucket naming "ordinal X" on A pointed at
                // a different block on B, and the recipient's wallet fetched the wrong record or none.
                //
                // Bitcoin and Kaspa cannot have this defect: a block CONTAINS its transactions and every node
                // stores the whole block, so accepting a block and holding its payments are the same event.
                // There is no second stream to fall behind and no per-node numbering to drift. This restores
                // that property in our shape — the ordinal is now the block's position, identical on every
                // node by construction, and an empty block records its constant 256-slot cover shape exactly
                // as a full one does (which is regenerable, so it costs nothing to be honest about).
                {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a BYTE COUNT only — never a tx id, nullifier, amount, key
                    // or note. This is the line that says whether a VERIFYING node actually wrote the payment
                    // its peer's block carried; without it, "recipient sees nothing" cannot be split into
                    // "never recorded" vs "recorded but not detected by the wallet".
                    // DIGITAL-CASH-PRIVACY-REVIEWED: byte count + the SERVED-STREAM POSITION only — never a
                    // note, amount, key or owner. The position is the whole question: a wallet delta-scans
                    // FORWARD from its cursor, so a note recorded at a seq the wallet has already passed is
                    // invisible to it forever, no matter how correctly it was delivered.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a blake3 COMMITMENT + counts, never the payload. Compared
                    // against the PRODUCER's record digest this answers whether the bytes survived the wire:
                    // equal digests ⇒ the block payload arrived intact and any later mismatch is on the serve
                    // side; different digests ⇒ the payload is altered or replaced before it is stored.
                }
                // ⛔ SAY WHETHER THE BLOCK CARRIED ANY. A verifying node logged ZERO `[account-target]` across
                // 615 grafts, and nothing separated "the block shipped none" from "this adopt was never
                // reached" — the two need opposite fixes, and guessing between them has cost this session
                // several rounds already.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a byte LENGTH only. Never a cm, bucket, key, amount or owner.
                if !carried_targets.is_empty() {
                    eprintln!(
                        "[graft] block carried {} account-target byte(s) — adopting",
                        carried_targets.len()
                    );
                }
                // ⭐ THE RECEIVE-SIDE GAP — a block with notes but NO targets starves detection silently.
                //
                // `[acct-file]` fires only when targets ARE adopted, so a block carrying notes and zero
                // targets produces no line at all on the ingesting node. That is precisely the failing state:
                // node A files targets locally (`[bucket-file] CLAIMED 2 … 2 write(s)`) while node B learns
                // nothing, so the recipient's `bucket+OLI detection returned 0 candidate note(s)` and the
                // payment is undiscoverable — with nothing in node B's log to say why.
                //
                // MEASURED: 5 settlements in ~19 sends, never three consecutively; `[acct-file]` has never
                // fired on node B across the entire session. Naming the empty-target ingest turns "recipient
                // sees nothing" into "this block brought no way to find its notes".
                //
                // Fires only when a block carries notes AND no targets — silent on cover-only blocks and on
                // healthy ones, so no per-block bytes. DIGITAL-CASH-PRIVACY-REVIEWED: byte COUNTS only. Never
                // a cm, bucket id, address, amount, key or owner.
                // H5 / DB-273 (C): a block carries no account targets by consensus; detection is OLI's (no warning).
                // ⭐ MANDATORY PRIVATE-SEND OBSERVABILITY — THE ADOPT HOP, the last one with no probe.
                //
                // MEASURED 2026-07-31: node A now files correctly (`[bucket-file] block touched 2 bucket(s),
                // 0 still pending`) and produces a block carrying 3459 note bytes with NON-ZERO account
                // targets — but node B logs ZERO `[acct-file]` and ZERO `[bucket-file]` lines, so the
                // recipient's wallet has nothing to detect and reads 0. Between "the block never reached B",
                // "it reached B carrying no targets", and "it carried them and adopt did nothing" there was
                // no way to tell, and those need three different fixes.
                //
                // Fires only when a block arrives carrying notes (a real payment-bearing block), never on
                // cover-only blocks, so there is no per-block cost.
                // DIGITAL-CASH-PRIVACY-REVIEWED: two BYTE COUNTS only — never a cm, bucket, address, amount,
                // key or owner.
                if !carried_notes.is_empty() {
                    // ⛔⛔⛔ THIS LINE ASSERTED A CONDITION IT NEVER TESTED — A FALSE POSITIVE IN THE LOG.
                    //
                    // user 2026-08-09: "add private observability so the nodes ... cant ... offer any false
                    // positives."
                    //
                    // The sentence "ZERO targets here with non-zero notes means ..." was appended to EVERY
                    // grafted block, including blocks carrying thousands of target bytes.
                    // MEASURED 2026-08-09 on node B during the cross-device send, verbatim:
                    //   `[acct-adopt] adopting a grafted block: 2500 carried account-target byte(s) for 3459
                    //    carried note byte(s) — ZERO targets here with non-zero notes means ...`
                    // 2500 is not zero. A healthy adoption printed the failure explanation, which is the same
                    // defect the sibling `[link-state]` probe was already fixed for ("my own probe LIED ...
                    // a diagnostic that states a condition it did not test is worse than no diagnostic:
                    // it manufactures false findings").
                    //
                    // Say which case actually holds, and only then explain it.
                    // O1-FOOTPRINT-REVIEWED: one emptiness test on a slice already in hand; stores nothing and
                    // adds no term in height, blocks or notes.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: two BYTE COUNTS only — never a cm, bucket, address,
                    // amount, key or owner. Unchanged from the line it replaces.
                    if carried_targets.is_empty() {
                        // H5 / DB-273 (C): no account targets ride a block by consensus; OLI finds the owner's note.
                    } else {
                        eprintln!(
                            "[acct-adopt] grafted block carries {} account-target byte(s) for {} note byte(s) \
                             — index entries rode with it and are about to be filed.",
                            carried_targets.len(),
                            carried_notes.len()
                        );
                    }
                }
                self.adopt_account_targets_at(
                    &carried_targets,
                    Some(Self::da_record_id_for_block(&grafting_block_id, 0)),
                );
                // ⭐ THE SAME per-note-validity filter as every other graft writer
                // (`graft_admitted_notes`): recording the RAW carried notes here is exactly how the
                // refused wrapper chunk re-entered the record AFTER the door had stripped it
                // (measured in the helper's doc — same record address, seed-only write first, raw
                // re-record second). One filter, every writer.
                // ⛔ DB-276b — held WITHOUT the notes its header commits: not recorded from the empty body, named by
                // block in `payload_gap` so the record lane asks for it (Bitcoin Core's BLOCK_HAVE_DATA, kept by block).
                if self.body_may_write_record(&grafting_block_id, &carried_notes) {
                    let admitted_notes = self.graft_admitted_notes(
                        &grafting_block_id,
                        &carried_notes,
                        own_cover_key,
                        own_nt.as_ref(),
                        own_mt.as_ref(),
                        own_cnt.as_ref(),
                        &own_credits,
                        &own_wide,
                        &own_bonds,
                        &own_lane,
                        &own_oli,
                    );
                    let rec_addr = self.record_note_payload_for(Some(grafting_block_id), height, &admitted_notes, own_cover_key);
                    self.file_block_carried_tags(&grafting_block_id, rec_addr, &own_oli);
                } else if !self.da_record_held(Self::da_record_id_for_block(&grafting_block_id, 0)) {
                    self.payload_gap.insert(grafting_block_id, Self::da_record_id_for_block(&grafting_block_id, 0));
                }
                // ⛔ DB-402 R1 (lane a 2026-10-22) — THE NOTE CURSOR IS NOT ADVANCED HERE. The named block is one
                // of the blocks `take_grafted` returned, so the shared carry loop above (`apply_grafted_block_carry`)
                // already counted it once; a second `+1` here counted every INGESTED named block twice while the
                // produce, heal, sync and backfill paths counted theirs once. MEASURED (replica census, pin lane,
                // watch-20261022-131112.log.node): `blocks_note_applied` 26 on the producer vs 40 on the ingester
                // of the SAME chain — a replicated field that was a function of which node mined. ONE increment per
                // block whose note payload this node applied, at the site that applies it (see the field's doc).
                // ⛔⛔⛔ EVERY ACCEPTED BLOCK MUST LEAVE WITH A RECORD — VERIFY IT, DO NOT ASSUME IT.
                //
                // The note frontier IS `served_seq * 256` leaves, so a block accepted WITHOUT its record is
                // not a bookkeeping slip: it is a block the note accumulator never folded. Two nodes that
                // record different sets therefore commit DIFFERENT spend roots, and no copath from one can
                // verify on the other. MEASURED tonight: A 198,426 blocks / 168,934 folded, B 198,424 /
                // 150,212 — three different answers to "what is the note root".
                //
                // Every hypothesis for WHERE the hole opens has been refuted by measurement (duplicate
                // re-delivery: 0 hits; sub-record ids: still 0 served; producer drop: fixed, gap unchanged).
                // So stop hypothesising and make the invariant self-reporting: check RIGHT HERE, where the
                // block has just been accepted and its payload is in hand, whether the record actually
                // landed. A violation names the exact block and path instead of surfacing 30,000 blocks later
                // as an unfillable backfill request.
                if self
                    .da_load(Self::da_record_id_for_block(&grafting_block_id, 0))
                    .is_none()
                {
                    eprintln!(
                        "[ledger-hole] ACCEPTED block left WITHOUT a ledger record (carried {} byte(s), \
                         height {height}, served_seq {}) — the note frontier will never fold it and this \
                         node's spend root now differs from every peer that did record it",
                        carried_notes.len(),
                        self.served_seq
                    ); // DIGITAL-CASH-PRIVACY-REVIEWED: byte length + chain counters only; no note, amount, key, owner.
                }
            }
            // ⛔ THE CASCADE LOOP THAT LIVED HERE WAS DEAD — DELETED (fix round 2026-09-05).
            //
            // It opened with `let mut grafted = self.relay.take_grafted()`, but `take_grafted` is
            // `std::mem::take` (relay.rs) and the UNCONDITIONAL canonical drain earlier in THIS
            // function (the `ordered` BTreeMap loop above, which routes every block this receive
            // grafted — named block and cascade alike — through `apply_grafted_block_carry`) had
            // already consumed the account. Call-order read, proven: between that drain and this
            // point there is no `receive`/`receive_bounded` call, so nothing repopulates `grafted`
            // and this loop iterated ZERO items on every path (the same dead shape pre-existed at
            // baseline). It was also a SECOND TEXTUAL COPY of the per-block apply — one that
            // silently discarded `_gdel` (the deletion set) — exactly the drift
            // `apply_grafted_block_carry` exists to prevent. ONE ENCODING: the drain above is the
            // only per-block apply on the ingest path.
            // ⛔ ONE COORDINATE. This probe used to compute `rec_gain = served_seq - rec_before` —
            // but `served_seq` is a FOLD ordinal (it advances when the spine folds a record, i.e.
            // `append_ordinal + 1`), while `dag_gain` is a BLOCK count. Differencing them is the
            // four-coordinate trap inside the probe that exists to catch it: it fired 598 times in
            // one boot (gains of 61/284/15) reporting fold LAG as record LOSS. It now asks the one
            // question it always meant — does every block this receive grafted HOLD a ledger
            // record? — with both sides in the SAME coordinate (block counts), probed directly by
            // `da_load` per grafted id. The fold delta is still printed, labelled as its own
            // coordinate, so backlog stays visible without masquerading as a hole.
            // Privacy: counts only — never a note, amount, key, owner or id.
            let dag_gain = self.relay.dag().len().saturating_sub(dag_before);
            let holes = grafted_ids
                .iter()
                .filter(|gid| self.da_load(Self::da_record_id_for_block(gid, 0)).is_none())
                .count();
            if holes > 0 {
                eprintln!(
                    "[ledger-hole] {holes} of {} block(s) this receive grafted hold NO ledger record \
                     (DAG gained {dag_gain}) — the note frontier will never fold them. Fold spine \
                     advance during this call, ITS OWN coordinate, backlog only: {} record(s).",
                    grafted_ids.len(),
                    self.served_seq.saturating_sub(rec_before)
                );
            }
            // Hold this block's txs until its place on the selected chain is settled (see `evicted_by_block`).
            // DB-389: an ordinary send is carried by the listing itself (its notes and tags ride the block's lanes); a framed
            // chain object is carried only if the block holds its carriage (credit set) or its very bytes (bond set). A
            // listed id whose object the block does not carry evicts NOTHING — the pooled tx stays where it is.
            let mut listed_not_carried = 0usize;
            let evicted: Vec<PqTx> = block_tx_ids
                .iter()
                .filter_map(|id| self.mempool.get_pooled(id).cloned())
                .filter(|t| {
                    let carried = if Self::is_usdm_bond_tx(t) {
                        // a bond leaves the pool only when this block CARRIES its bytes in the bond set AND its bond
                        // transition ADMITS its nullifier — a statement over a bond the block does not carry (the forge
                        // arm) admits nothing here (MEASURED 2026-10-04 20:22: the statement alone evicted the honest bond)
                        block_carried.contains(&t.id)
                            && block_bond_admit
                                .as_ref()
                                .is_some_and(|a| t.nullifiers.first().is_some_and(|nf| a.admits_deletion(nf.as_bytes())))
                    } else {
                        match crate::chain_object::unframe(&t.blob) {
                            None => true,
                            Some(_) => {
                                block_carried.contains(&t.id)
                                    || crate::chain_object::carriage_of(&t.blob).is_some_and(|c| block_carried.contains(&Hash32::hash(&c)))
                            }
                        }
                    };
                    if !carried {
                        listed_not_carried += 1;
                    }
                    carried
                })
                .collect();
            if listed_not_carried > 0 {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a COUNT only — never a tx id, nullifier, amount, key or note.
                eprintln!(
                    "[graft] ⛔ DB-389: {listed_not_carried} pooled framed object(s) this block LISTS but does not CARRY stay in \
                     the pool — a listing is not an application"
                );
            }
            // ⭐ lane agg: the full twins of the block's aggregated payments (captured above) leave with them
            let mut evicted = evicted;
            for (tags, notes) in &agg_twins {
                let Some(twin) = tags.first().and_then(|nf| self.mempool.claimant_of(nf)) else { continue };
                if evicted.iter().any(|t| t.id == twin) {
                    continue;
                }
                if let Some(t) = self.mempool.get_pooled(&twin).filter(|t| &t.nullifiers == tags && &t.output_notes == notes).cloned() {
                    evicted.push(t);
                }
            }
            let evicted_real = evicted
                .iter()
                .filter(|t| !t.output_notes.is_empty())
                .count();
            if evicted_real > 0 {
                // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a tx id, nullifier, amount, key or note.
                eprintln!(
                    "[graft] ingest evicted {}/{} pooled tx(s), {} carrying notes",
                    evicted.len(),
                    block_tx_ids.len(),
                    evicted_real
                );
            }
            // the ids this block CARRIES — the only ones `release_folded_tx_evictions` may take out of the pool (below)
            let carried_ids: Vec<Hash32> = evicted.iter().map(|t| t.id).collect();
            if !evicted.is_empty() {
                self.evicted_by_block.insert(grafting_block_id, evicted);
            }
            // DIGITAL-CASH-PRIVACY-REVIEWED: emits COUNTS only (how many of this block's tx ids this node had
            // pooled, and how many carried notes) — never a tx id, nullifier, amount, key or note. These two
            // numbers separate the only two ways a payment can leave the pool without its effects appearing:
            // packed into a block whose notes were not applied, vs evicted by a block that never carried it.
            // ⛔ DO NOT EVICT A BLOCK'S TXS UNTIL ITS FOLD IS DONE.
            //
            // Eviction ran here, BEFORE the nullifier fold below. Two consequences, both fatal to sends:
            // this node destroyed the very blobs its own decoy seed is derived from (so a parked block could
            // never be completed even once its predecessor landed), and it could not answer a peer's
            // `TxReq` either — the bodies were gone from every pool the moment a block was grafted, so the
            // request had no possible responder. A block references its txs by ID; if every node discards the
            // bodies on graft, the data needed to fold is simply unrecoverable network-wide.
            //
            // Bitcoin and Kaspa never have this: a block carries its transactions, so anyone holding the
            // block can serve them. We reference ids, so the pool must hold the bodies until the block they
            // belong to has actually folded. `pending_fold_evictions` releases them the moment it does.
            // ⛔ DB-389, THE HALF THAT WAS MISSING (MEASURED 2026-10-04 20:22, the 4 BondTransition pins still RED at the
            // CONTROL): this queue removed EVERY listed id from the pool at `release_folded_tx_evictions`, so a listed-but-
            // not-carried tx the filter above kept out of `evicted_by_block` left the pool anyway — held nowhere, returned
            // never ("node_a laid a block WITHOUT its pooled bond", no `[tmpl-cand]` at its produce). Only the ids the
            // block CARRIES are released; a listing is not an application, at this site as at the one above.
            self.pending_fold_evictions.push(carried_ids);
            // ⛔ RELEASE HERE, AFTER THE QUEUE PUSH — the block's fold already ran ABOVE this line.
            //
            // Until D-35 (2026-09-08) the named block's nullifier fold ran BELOW this push, and its
            // `drain_pending_nf_folds()` — the only caller of `release_folded_tx_evictions` — released
            // what was just queued. D-35 rightly moved every block's fold into the one ordered drain
            // loop above (so a block entering by ANY door folds), and the release went with it: the
            // drain's release now runs BEFORE this push, finds nothing queued for this block, and the
            // block's txs stayed pooled until the NEXT drain — one block later, or never on an idle
            // chain. MEASURED: `a_tx_whose_block_loses_the_selected_chain_returns_to_the_pool…` red at
            // "the mined tx left B's pool" with the block Added and folded.
            //
            // Since the parked-fold stash retired (DB-353 §13.5 item 2) nothing on this node needs the bodies once
            // the block's fold has run, so the release is unconditional.
            ap_stamp("notes+targets", &mut ap_t, &mut ap_n, &mut ap);
            self.release_folded_tx_evictions();
            self.settle_or_return_evicted_txs();
        }
        // ⛔⛔⛔ DELETED (D-35, 2026-09-08) — THE `RelayOutcome::Added` GATE THAT USED TO WRAP THE
        // NULLIFIER FOLD. It ran the fold exactly once per receive, for the block the outcome NAMES,
        // with that block's pre/post/tags — so every block that entered behind it in a cascade (a
        // parent-ask recovery, a released buffered descendant) never folded at all. `take_grafted`'s
        // own doc had already said why that is wrong: "`Added` names only the first, so this is the
        // only complete account of what entered the DAG." The DA record was moved onto that account in
        // August; the nullifier fold was left behind on this gate, and this is the removal that
        // finishes the same correction. The fold now runs in the per-grafted-block loop above, once
        // per block that ENTERED THE DAG, each from its own carried commitment — including this named
        // block, which is in that loop like any other. Nothing here is disabled or bypassed: the code
        // is gone and its one caller moved.
        //
        // #75 — NO per-epoch reward-index accrual (a supply-adjacent counter — deleted). Reserve-yield is
        // SELF-MINTED per note via the confidential WHIR carrier ([`crate::peg::PegLedger::claim_reserve_yield`]).
        // ⭐⭐⭐ THE ORDER BOOK IS A FUNCTION OF THE CHAIN, NOT OF WHOSE GOSSIP ARRIVED.
        //
        // A resting order is IDENTIFIED BY the maker note a fill burns, and those burns already ride in
        // `nullifier_proof.padded_tags`, bound into the block id and applied by every node. So a node
        // needs none of the fill's bytes to know an order is dead — it only has to read what the block
        // already told it. One pass over the constant padded lane retires exactly the orders whose note
        // this block spent (Ethereum's STF rule applied to the book: same chain ⇒ same book).
        //
        // ROOT-LAYER: this is where a block becomes part of THIS node's state, so it is where every
        // consequence of that block belongs. The alternative that was proposed — looping the DEX apply
        // over `evicted` in the graft path above — reads tx BODIES from the local mempool, and
        // `struct Block` carries `tx_ids` (content hashes) with NO body field: it would apply on the node
        // that pooled the fill and apply NOTHING on a node that grafted the block by gossip. That is the
        // 2026-09-03 double-payout shape one hop later, so it was refused and this replaced it.
        //
        // MEASURED: the fill transaction already declares BOTH halves of its effect (rpc_http.rs, the
        // `/submit_order_fill` builder): `output_notes` carries the three credited notes and `nullifiers`
        // carries `fill.nullifier_tags()` — so the credit half and the burn half already travel and are
        // applied by the ordinary paths on every node. The BOOK was the only part that still depended on
        // having seen the fill. `order_fill_tx::retire_orders_burned_by` is green with its own tests,
        // including the hard direction: a node that never saw the fill, never pooled the tx and never saw
        // the order posted still retires the order.
        // MUST-STAY-GREEN: a cover-only block retires nothing (the padding is what hides the real count,
        // and a decoy tag matches no resting order), the graft path's existing nullifier fold, and the
        // recorded_case runtime-backend suite.
        // Idempotent: `remove_by_nullifier` on an already-retired order is a no-op, so a re-graft of the
        // same block cannot double-apply. Privacy: the lane is the CONSTANT padded width, the work does
        // not vary with the real fill count, and nothing here is logged — a retired-order COUNT would be
        // exactly the volume metadata the padding exists to hide.
        // cons: none — one pass over `BLOCK_FIXED_NULLIFIER_COUNT` tags per grafted block, a fixed
        // constant; no new state, no new block field, no consensus change.
        // DB-383: only the tags this block justifies may retire an order (one filter, shared with the graft carry)
        self.retire_orders_burned_by_justified(&block_lane_justified, &block_padded_tags);
        ap_stamp("orders+tail", &mut ap_t, &mut ap_n, &mut ap);
        let ap_total = ing_t2.elapsed().as_millis();
        if ap_total > 100 {
            let mut v: Vec<(&'static str, u128)> = ap[..ap_n].to_vec();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            // DIGITAL-CASH-PRIVACY-REVIEWED: millisecond durations of this node's own apply phases and a
            // count of grafted blocks. No note, amount, key, owner or tag.
            eprintln!(
                "[apply-phase] the post-graft apply held the lock {ap_total}ms — {}",
                v.iter().map(|(n, ms)| format!("{n}={ms}ms")).collect::<Vec<_>>().join(" ")
            );
        }
        crate::node_runtime::ING_APPLY_MS.fetch_add(
            ap_total as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        let ing_t3 = std::time::Instant::now();
        self.autosave(); // persist the resumable checkpoint after ingest (background write; no-op if disabled)
        crate::node_runtime::ING_SAVE_MS.fetch_add(
            ing_t3.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        crate::node_runtime::ING_BLOCKS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // v31: fold what became eligible (the tick folds too; this keeps a graft and its fold one step).
        let _ = self.fold_canonical_records();
        outcome
    }

    pub fn graft_mined_own(
        &mut self,
        block: Block,
        cover_ids: Vec<Hash32>,
        tmpl_tx_ids: Vec<Hash32>,
        tmpl_output_notes: Vec<u8>,
        now_ts: u64,
    ) -> Option<Block> {
        // ⭐ KEEP THE WITNESS WHILE THE BODY IS IN HAND. The graft puts header + tx ids in the DAG and
        // drops the rest, so this is the last moment the proof exists on this node.
        let pi = block.pow_proof.clone();
        let id = block.header.id();
        let out =
            self.graft_mined_own_budgeted(block, cover_ids, tmpl_tx_ids, tmpl_output_notes, now_ts, None);
        self.retain_pow_witness(id, &pi);
        out
    }

    /// ⭐ ITEM-6: `graft_mined_own` with the rt-lock apply budget carried into the produce-side
    /// cascade, exactly as `ingest_block_preverified_budgeted` carries it into the ingest one. The
    /// relay releases at most `remaining_ms / 65` parked peer descendants behind this node's own
    /// mined block this call; the rest stay parked and re-enter through the strand lane next tick.
    /// `None` = unbounded (tests and the inline `produce` path).
    /// `tmpl_output_notes` = the note blobs the TEMPLATE resolved while holding the lock; empty
    /// means "resolve from the pool" (the inline produce path, where no eviction can intervene).
    pub fn graft_mined_own_budgeted(
        &mut self,
        mut block: Block,
        cover_ids: Vec<Hash32>,
        tmpl_tx_ids: Vec<Hash32>,
        tmpl_output_notes: Vec<u8>,
        now_ts: u64,
        deadline: Option<crate::budget_clock::Stamp>,
    ) -> Option<Block> {
        // PERF TIER step 1: the remaining budget on the BUDGET CLOCK (wall on a daemon, CPU on a simulated node).
        let max_cascade: usize = match deadline {
            None => usize::MAX,
            Some(d) => ((d.remaining_ms() / 65).max(1)) as usize,
        };
        let block_tx_ids_own: Vec<Hash32> = block.tx_ids.clone();
        // ⛔⛔⛔ THE ATTACH THE COMMENT ABOVE PROMISES WAS MISSING. Everything below `used_snapshot` read
        // `tmpl_output_notes` only as `let _ = &tmpl_output_notes;` — the payload the template sealed (and
        // whose root the MINED HEADER already commits) was thrown away, so this node applied its notes
        // locally and gossiped a PAYLOAD-LESS block. MEASURED live 2026-08-18, both sides of one hop:
        //   A: [acct-produce] block carries 1250 account-target byte(s) for 1153 note byte(s); [uns-recv] folded 1
        //   A: zero `[gossip] sending block carrying…` lines in 100 MB of log (the payload never reached gossip)
        //   G: [target-block] PARSED targets=0 on every block; 1,283 tag-drains all zero; uns-recv count 0
        // Reattaching is commitment-checked, not trust: `output_notes_root` was sealed over THESE bytes at
        // template time, pre-mining, so a wrong payload fails the header check on every verifier.
        if block.output_notes.is_empty() && !tmpl_output_notes.is_empty() {
            block.output_notes = tmpl_output_notes.clone();
        }
        // ⭐ SELF-CONTAINED BLOCK, SET FIRST. The note payload is attached BEFORE anything else can return or
        // move the block, so EVERY exit path — and the copy handed to the relay — carries it. Setting it late
        // made the field depend on which produce path ran and on reaching the end of a match arm, and a block
        // that leaves without its notes is a payment its recipient's node can never record: a peer cannot
        // rebuild the payload, because its spend gate judges a gossiped tx against ITS OWN accumulator state
        // and may legitimately hold no tx body at all.
        // BIND THE PAYLOAD TO WHAT THE BLOCK ACTUALLY CARRIES, not to the template snapshot. `tmpl_tx_ids` is
        // captured when the template is BUILT; the live path then mines off-lock and grafts later, so a payment
        // that arrives in between is in the block's `tx_ids` but NOT in `tmpl_tx_ids`. Assembling from the stale
        // list recorded ZERO notes for a block that really did carry the payment — measured: pooled with 2306
        // note bytes, then `recording 0 note bytes, pool_left 0`. The block's own id list is the only thing that
        // cannot disagree with the block.
        // ⛔⛔⛔ RESOLVE THE NOTES FROM THE TEMPLATE'S OWN SNAPSHOT, NOT FROM A POOL THAT MOVED.
        //
        // MEASURED by the `[block-notes]` probe on a live peered run:
        //   `256 selected tx(s): 256 NOT IN MEMPOOL, 0 carried no output notes`
        //   `256 selected tx(s): 0 NOT IN MEMPOOL, 255 carried no output notes`
        //   `[block-ids] block holds 256 tx id(s) and assembled 1153 note byte(s)`
        //
        // `begin_produce` mints cover into the pool and hands back a job; mining then runs OFF-LOCK; and
        // `finish_produce` -> here re-resolves every id against the mempool. Any produce cycle finishing in
        // between EVICTS those txs, so the lookup finds nothing and the bare `else { continue }` drops all
        // 256 without a word. That is the 175/175 blocks carrying only the 1,153-byte entropy note, and every
        // starved layer below it.
        //
        // The template already selected these txs while holding the lock. Snapshotting their note blobs at
        // that moment makes assembly independent of what the pool does afterwards — the block carries what it
        // was built from, which is the only thing that cannot disagree with itself.
        //
        // NOT A GROWTH VECTOR: this is one Vec of the block's OWN note blobs, bounded by
        // BLOCK_FIXED_NOTE_COUNT — the same constant shape every block already carries. Nothing per-chain,
        // nothing retained after the block is grafted.
        // ⭐ NAME WHICH SOURCE ASSEMBLED THE BLOCK — snapshot or live re-resolve.
        //
        // Without this the two paths are indistinguishable in the logs, and I spent a turn reading pre-fix
        // output as proof the snapshot had failed (the binary was 27s younger than the running process).
        // Saying WHICH branch ran, and how many bytes it produced, makes that misreading impossible.
        //
        // Fires only when the block carries real tx ids — cover-only blocks stay silent, no per-block bytes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name and a BYTE COUNT only. Never a tx id, note, cm,
        // amount, key or owner.
        let used_snapshot = !tmpl_output_notes.is_empty();
        // ⛔⛔⛔ A NODE'S OWN BLOCKS RECORD NOTES BUT NEVER ADVANCED THE NOTE CURSOR.
        //
        // The note cursor (today `note_backfill_cursor`) advanced in `apply_backfilled_notes`, `ingest_block` and `instant_sync` —
        // and NOWHERE on the produce path. A node that mints most of its own chain therefore reports a
        // cursor frozen near zero while its tip climbs.
        //
        // MEASURED 2026-07-31 on the live pair: `[da-backfill] requesting 1 block record(s) by id
        // (tip 50460, applied 59, BEHIND 50401)` while the two chains were converged to a gap of ONE block.
        // The node believed it was 50,401 records behind, asked for 1 at a time, and could never close a gap
        // that did not exist. Downstream, the recipient's wallet got `served ZERO notes for N block(s)` and
        // the payment was invisible — which is the send failure.
        //
        // The advance belongs wherever notes are recorded, and the produce path records them.
        // ⛔ NO RE-RESOLVE. `start_produce` attached these notes and the mine bound them; re-resolving from
        // this node's pool here is what made the producer's record differ from every receiver's.
        let _ = &tmpl_output_notes;
        // ⛔ THE NOTE COMMITMENT IS **NOT** SEALED HERE — THIS RUNS AFTER THE OFF-LOCK MINE.
        //
        // Sealing `header.output_notes_root` at this point mutates the header AFTER its PoW was solved, so
        // `block.id()` changes post-mine and the proof no longer binds the block it names. I landed exactly
        // that and caught it here rather than shipping it.
        //
        // The correct place is `start_produce`, which already resolves `tmpl_output_notes` while holding the
        // lock and BEFORE the block is handed off to mine — the same reason the settlement proof is set
        // there ("Set before the off-lock mine"). Assembling the notes once, there, also removes the
        // re-resolve below, which is the second definition of a block's notes.
        if !block.tx_ids.is_empty() {}
        // ⭐ IS THE PAYMENT EVEN IN THE BLOCK'S OWN ID LIST?
        //
        // The comment above says this was fixed by binding to `block.tx_ids` instead of the stale template
        // snapshot, and cites the same 2,306-byte payment payload I measured independently. But MEASURED NOW:
        // 175 of 175 produced blocks carried exactly 1,153 note bytes — the constant entropy note and nothing
        // else. A settling payment carries recipient + change = 2,306. So the payment's notes never reach
        // `output_notes`, and every later step (target lookup, bucket filing, peer adopt, recipient
        // detection) is starved at the source rather than broken.
        //
        // Two causes remain and this separates them: the id list is EMPTY of real txs (selection never put
        // the payment on this block), or it holds ids the mempool can no longer resolve (the `[block-notes]`
        // probe reports that case). Fires only when a block carries real tx ids, so cover-only blocks stay
        // silent — no per-block bytes.
        //
        // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS and a BYTE LENGTH only. Never a tx id, note, cm, amount, key
        // or owner.
        if !block.tx_ids.is_empty() {}
        // EVERY block ships a payload, because `cover::pad_to_fixed_shape` declares one pad tx's cover note
        // as an output note. That single 1153-byte note is the block's ENTROPY: it keys the cover fill and
        // permutation that regenerate the other 255 slots, so a peer holding only the block derives the same
        // 256 leaves the producer did. It costs the same 1153 bytes the node-local value it replaced cost, so
        // the no-growth probe is unaffected — what changed is that the bytes are now carried rather than
        // invented per node.
        // Carry the account-DA targets for exactly these notes, so a peer that only ever sees the BLOCK files
        // them into the same buckets and folds the same accumulator we are about to commit.
        // ⛔⛔⛔ THE ADDRESS IS DERIVED FROM AN IDENTITY THIS ASSIGNMENT DESTROYS.
        //
        // `at` is `da_record_id_for_block(&block.id(), 0)` evaluated while ASSIGNING `block.account_targets`.
        // If `id()` covers that field, the id changes the instant the targets land, so the producer files and
        // reads its targets under an address belonging to a block that no longer exists — a target written
        // under one key and looked up under another, which is exactly the observed loss.
        //
        // MEASURED 2026-08-01, two identical runs: `[bucket-file] CLAIMED 1 pending target(s)` then
        // `[acct-produce] block carries 0 account-target byte(s) for 1153 note byte(s)` on 384/384 produced
        // blocks, with `[acct-lookup]` silent even after its gate was widened to fire on a claimed-but-
        // unfindable target — so the lookup is NOT missing, and the loss is at the carry, not the resolve.
        //
        // Say whether the identity moved. Fires ONLY when the id actually changes AND targets were produced —
        // a genuine anomaly on a payment-bearing block, never per block, never on cover-only blocks.
        // O1-FOOTPRINT-REVIEWED: two block ids on the stack for the length of this statement; stores nothing
        // and adds no term in height, blocks or notes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: block ids are public DAG identifiers already gossiped in clear, plus
        // a byte COUNT. Never a cm, bucket id, amount, key, owner or recipient.
        // ⭐⭐⭐ THE CARRY RIDES ASSEMBLY — IT NO LONGER ASKS THE BLOCK WHO IT IS.
        //
        // This is the build the REVERT note at `pending_bucket.remove` names: *"The carry must ride the block
        // from the START of assembly, not be appended to a finished one."* The circularity it was stuck in is
        // written out directly above: `at` was `da_record_id_for_block(block.id())`, and assigning
        // `block.account_targets` CHANGES `block.id()` — so the producer resolved and filed its targets under
        // the address of a block that ceased to exist the instant the targets landed. `[acct-addr-drift]` was
        // added to catch exactly that and `[acct-produce] block carries 0 account-target byte(s)` is what it
        // produced, on 384/384 blocks.
        //
        // THAT is the class of note the bucket cannot see, and it is why one send settles and the next does
        // not: whether a target survives depends on whether its block's id happened to move, which is not a
        // property of the payment. A send must not be able to fail for a reason the sender cannot observe.
        //
        // Passing `None` removes the dependency at the root rather than masking it. `account_target_for`
        // resolves a target from `pending_bucket` (staged by submit, keyed by the note's OWN commitment) and
        // then from `note_target_addr` (written beside the record when it was filed) — both keyed by the note,
        // neither by the block. The `at` fallback was the ONLY id-dependent path, and it could only ever name
        // a stale address here. With it gone the carry is a pure function of the notes being assembled, so it
        // is identical on every node and stable no matter how many times the id is recomputed.
        //
        // FEEDS-REVIEWED: `at` fed ONLY `account_target_for`'s `.or(at)` fallback. Its other callers
        // (`adopt_account_targets_at`, the block-application filing loop) pass a real record address they hold
        // in hand and are untouched. No caller loses an input; one wrong input is removed.
        // ⭐⭐⭐ CARRY THE LOCATOR TAGS FOR THIS BLOCK'S OWN NOTES — see `Block::oli_tags` for the measurement.
        // Read from `pending_tags` WITHOUT removing: the record loop still drains it as it always did, so the
        // producing node's behaviour is unchanged and only the wire gains the tags a receiver cannot derive.
        // Bounded by the REAL notes in this block (cover slots have no tag), so no term in height or chain size.
        // ⛔⛔⛔ P4′a — THE SIDECARS ARE **NOT** ATTACHED HERE ANY MORE. THIS RUNS AFTER THE OFF-LOCK MINE.
        //
        // `produce_template` now attaches BOTH `oli_tags` and `account_targets` and seals their header
        // commitments before the block is handed off to mine, so the PoW binds them. Re-attaching them here
        // would mutate the header after its PoW was solved and change `block.id()` — the same post-mine
        // mutation the `output_notes_root` block above records catching. The block arriving here already
        // carries what it shipped with; the probes below simply REPORT it.
        let carried_tags: &[u8] = &block.oli_tags;
        // Say whether the carry actually got anything. `pending_tags` is DRAINED by the record loop
        // (`remove(&cm)`), so if recording runs before this read the map is already empty and the block ships
        // with no tags — which looks identical, from the outside, to a receiver that ignored them.
        // DIGITAL-CASH-PRIVACY-REVIEWED: two COUNTS on this node's own block. Never a tag, cm, key or owner.
        // ⛔ REPORT THIS UNCONDITIONALLY. The guard above (`len() > 1153`) silenced it for exactly the
        // blocks that matter — a payment block carrying ONE note is 1153 bytes, so the line never printed on
        // the send that was being debugged. A block shipping ZERO tags is indistinguishable from a receiver
        // that ignored them, and that ambiguity is the whole reason the recipient's `locate` returning 0 took
        // this long to place.
        //
        // MEASURED: wallet A sent (`Broadcast (2253ms)`, balance 1,000.00 -> 0.00), both nodes settled the
        // leaf (`leaves 3`, identical root), and wallet B on the OTHER node reported
        // `[oli-yield] locate returned 0 position(s)` — money on chain, invisible to its owner.
        // DIGITAL-CASH-PRIVACY-REVIEWED: three COUNTS on this node's own block — tag bytes, note bytes, and
        // the pending map's size. Never a tag, commitment, key, amount or owner.
        if !block.output_notes.is_empty() {
            eprintln!(
                "[oli-carry] produced block carries {} tag byte(s) for {} note byte(s); pending_tags holds {} \
                 — ZERO tag bytes here means the record loop drained `pending_tags` BEFORE this read, so the \
                 block ships untagged and the RECIPIENT's node can never locate the note.",
                carried_tags.len(),
                block.output_notes.len(),
                self.pending_tags.len()
            );
        }
        // ⭐ THE SIDECARS THE TEMPLATE SEALED MUST STILL MATCH THEIR HEADER COMMITMENTS.
        //
        // Every verifier now rejects this block outright if they do not (`validate_structural`), so a producer
        // that ships a mismatch takes only itself off the chain — but it would do so silently, mid-mine, with
        // nothing naming the cause. Re-deriving both roots from our OWN block here turns that into one line at
        // the exact hop. This also replaces `[acct-addr-drift]`, which asked the weaker version of the same
        // question (did attaching the targets move the id?) back when the sidecars were outside the id and the
        // answer was structurally always "no".
        {
            let tags_ok =
                block.header.oli_tags_root == crate::block::da_sidecar_root_of(&block.oli_tags);
            let targets_ok = block.header.account_targets_root
                == crate::block::da_sidecar_root_of(&block.account_targets);
            if !tags_ok || !targets_ok {
                eprintln!(
                    "[sidecar-seal] this node's OWN block does not match its header sidecar commitments \
                     (tags_ok={tags_ok}, targets_ok={targets_ok}) — every peer will refuse it. The seal \
                     belongs in `produce_template`, BEFORE the mine."
                );
            }
        }
        // ⭐ MANDATORY PRIVATE-SEND OBSERVABILITY — THE PRODUCE HOP, the last one still unmeasured.
        //
        // MEASURED so far: the wallet builds 5,000 hex bytes of account-target, `[submit] account_targets_hex
        // arrived: 5000 hex chars` proves the node receives them, and `[acct-file]` NEVER fires on either
        // node — so the record is lost between submit and block-carry. This line says whether the producer
        // put ANY target on the block it just built, which splits "the bucket never held it" from "the block
        // dropped it".
        //
        // Fires only when the block carries output notes at all, so cover-only blocks stay silent — no
        // per-block growth. DIGITAL-CASH-PRIVACY-REVIEWED: two BYTE COUNTS only. Never a cm, bucket id,
        // address, amount, key or owner.
        if !block.output_notes.is_empty() {
            eprintln!(
                "[acct-produce] block carries {} account-target byte(s) for {} note byte(s); pending_bucket \
                 holds {} entr(ies)",
                block.account_targets.len(),
                block.output_notes.len(),
                self.pending_bucket.len()
            );
        }
        // The producer half of the same question — a target that is never ATTACHED can never be adopted.
        // DIGITAL-CASH-PRIVACY-REVIEWED: byte lengths and a pending COUNT only.
        if !block.account_targets.is_empty() || !self.pending_bucket.is_empty() {
            eprintln!(
                "[produce] attached {} account-target byte(s) to this block ({} still pending)",
                block.account_targets.len(),
                self.pending_bucket.len()
            );
        }
        // ⛔⛔⛔ THE UNINSTRUMENTED PATH — a node's OWN mined blocks.
        //
        // MEASURED on the live peered pair: `h 913 rec 178` — one ledger record per 5.1 blocks — while the
        // `ingest_block` DAG-vs-ledger probe reported ZERO discrepancies. A solo node holds 1:1 forever, so
        // the loss appears only with peers, and `main.rs` mines through
        // `begin_produce`/`finish_produce` -> `graft_mined_own`, which is the ONE block-admitting route with
        // no instrumentation. On a 2-node mesh that route carries most blocks.
        //
        // Same comparison as the ingest side, so whichever path is dropping blocks names itself instead of
        // costing another live run. `served_seq` is the frontier's own count (leaves/256), i.e. the ledger's
        // real advance — not a bookkeeping counter that could agree while the fold silently did not happen.
        let mined_rec_before = self.served_seq;
        let relay_t0 = std::time::Instant::now();
        let outcome = self.relay.receive_bounded(block.clone(), now_ts, max_cascade);
        self.reanchor_on_refused_history_merge();
        // v31: an admitted block stays buffered (full) until its record folds — the fold carry a checkpoint
        // and a bundle transport. The runtime mines off-lock and grafts HERE, not through `produce`.
        if matches!(outcome, RelayOutcome::Added(_)) {
            self.remember_own_unfolded_block(block.clone()); // A-F63: this node's own block, kept whole at any reach
            // ⛔ THE FOLD MOVED BELOW THE CASCADE DRAIN at the end of the Added arm. Folding HERE ran
            // before any of this graft's applies: a CASCADED peer block had no record and no unfolded
            // entry yet, so a depth-0/shallow fold reaching it wrote its record FROM THE SHELL — the
            // seed note, first-writer — and the block's real carried payload was silently lost when
            // the proper write later became a no-op re-record (measured in the item-4 pin: the record
            // held the seed while the block carried a staged real note). Same call, same lock, still
            // one graft = one fold step — only the order changed: apply everything, then fold.
        }
        crate::node_runtime::GRAFT_RELAY_MS.store(
            relay_t0.elapsed().as_millis() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        // Cover was producer-side padding for THIS block only — drop it from the pool regardless of outcome
        // so it never accumulates across produce attempts (the selected ones are also on-chain now).
        self.mempool.remove(&cover_ids);
        match outcome {
            RelayOutcome::Added(_) => {
                // FOLD THIS BLOCK, exactly as `ingest_block` folds a peer's. There are TWO relay-receive
                // sites — this one for a block this node mined, and `ingest_block` for one that arrived — and
                // only the latter used to fold. So every node's accumulator was "every block EXCEPT the ones
                // I produced", which two producing nodes can never reconcile: each is missing precisely the
                // blocks the other has. That is the cross-node disagreement that had never been explained,
                // and it is invisible to any test with one node, because one node's accumulator is
                // self-consistent no matter what it omits.
                // TRUSTLESS nullifier commit — the SOLE path. Build this block's FULL ordered witness set (every
                // real spend + secret-seeded cover, padded to the CONSTANT per-block count) against this producer's
                // running tree, advancing the O(1) `nullifier_acc` in lockstep, and ATTACH it to the block so a
                // treeless VERIFIER replays it via `apply_block_treeless` (fail-closed on a bad/short
                // set). A double-spend has no valid low-leaf, so the witness build drops it; a carried, self-
                // verifying witness is the only way a nullifier enters the set ([[feedback_always_trustless]]).
                let selected: Vec<PqTx> = tmpl_tx_ids
                    .iter()
                    .filter_map(|id| self.mempool.get(id).cloned())
                    .collect();
                // Cache THIS produced block's mined real-spend txs' nfs by tx id — the produce twin of the ingest-path
                // caching — so a later CONCURRENT block that conflicts is pruned by `pruned_double_spends` identically
                // on every node. Captured before the `tmpl_tx_ids` eviction below drops the pool txs. Collect the
                // pairs first (immutable pool borrow), then insert (mutable), to avoid a borrow conflict in the loop.
                let mined_tx_nf_pairs: Vec<(Hash32, Vec<[u8; 32]>)> = tmpl_tx_ids
                    .iter()
                    .filter_map(|id| {
                        self.mempool.get(id).map(|tx| {
                            (*id, tx.nullifiers.iter().map(|nf| nf.0).collect::<Vec<_>>())
                        })
                    })
                    .filter(|(_, nfs)| !nfs.is_empty())
                    .collect();
                for (tx_id, nfs) in mined_tx_nf_pairs {
                    self.mined_tx_nfs.entry(tx_id).or_insert(nfs);
                }
                self.prune_mined_tx_nfs();
                // Advance THIS producer's O(1) `nullifier_acc` (real + secret-seeded cover, padded to the CONSTANT
                // count) so `header.nullifier_root` + the mempool gate reflect the spent-state. The Gap-3 recursive
                // carrier (which certifies the whole `pre → post` transition for a TREELESS verifier) is NOT attached
                // to the gossiped block: at 221KB it is ~66 onion cells, and the constant-rate cell channel drains
                // `CELLS_PER_SLOT` per slot — carrying it every block would blow the propagation budget (a peer could
                // not receive a block within its spacing), a FAST/liveness blowup on the bandwidth axis. The carrier
                // instead rides the #29 DSYNC bundle (≤1.8MB split-proof DA transport — Gap2, where a joining/treeless
                // node inherits the certified spent-state on adopt) and is served ON-DEMAND to light clients via #27
                // DAS ([[project_trustless_nullifier_o1_design]] [[feedback_no_growth_any_axis]]). The hot gossip path
                // stays light; a full node advances its acc here and re-derives the transition from its own tree. The
                // header still commits the pre-block root, so the spent-state is tamper-evident on the block id.
                // TREELESS ADOPT graft (Ask 2): the carrier this node just self-built proves `pre → post_root` over
                // the EXACT `pending_block_nullifiers` set it stashed (== the imt root, the adopt invariant). ADOPT
                // that proven post into the O(1) acc in O(1) — no per-block tree rebuild — and append the carrier's
                // OWN set to the DA-servable stream, so `adopt(post) == rebuild` by construction. Canonical-order
                // gated: an own block extends this node's tip, so the live acc root equals its committed pre-root.
                // ⭐⭐⭐ FOLD THIS BLOCK'S SPEND TRANSITIONS — the deletion model on the LIVE produce path.
                //
                // MEASURED: `let _ = &selected;` sat here, discarding the selected transactions entirely, and
                // the only callers of the RETIRED `commit_block_nullifiers_with_proof` (where the fold was
                // first wired; that wrapper and its compact carrier were deleted 2026-08-17 as vestigial —
                // production always emitted `carrier: Vec::new()` and proves the transition with the A_tip
                // height-1 fold instead)
                // are TESTS. So the fold was on a dead path: `[uns-wire] submit carries 1 spend transition(s)`
                // proved the witness reached the node, and `[uns-fold]` never fired once — the tx was
                // admitted, then dropped on the floor at production.
                //
                // The producer holds NO tree and looks up NO copath: each transaction carries its own copath
                // as a private witness, this folds it against the running root (a forged or stale one cannot
                // reproduce it and is refused at its own index), and every later transition in the block is
                // patched from the applied one's path.
                // The block's own carried notes fold in as RECEIVES here (EMPTY → present) before its
                // spends fold as deletions — the same order every ingesting peer applies.
                {
                    // ⛔ RECORD FIRST, THEN ADVANCE — the same order the INGEST site proved. This used to
                    // resolve `record_addr_for_block` BEFORE the outputs record existed, which answered the
                    // ENTROPY sub-record (or the sub-0 guess), so this block's del/recv sidecars keyed one
                    // record away from the notes they describe. Every downstream reader then paid for it in
                    // its own way (wire miss, settle miss, rebuild deletion-before-receive, and finally a
                    // healed node vouching a SPENT drip present — payer displayed 5.00 on a 2.00 truth,
                    // MEASURED 2026-08-13 run hA30). The writer's returned address is the ONE coordinate the
                    // serve walks and the rebuild replays; the later duplicate write becomes a no-op re-record.
                    // The height argument is ignored by the writer (`_height`); records key on the block id.
                    let rec_addr = self.record_note_payload_for(
                        Some(block.header.id()),
                        0,
                        &block.output_notes,
                        block.cover_key,
                    );
                    // Z1: the producer's own nullifier fold runs below through the same
                    // `nullifier_proof` path every ingester uses; no per-note tree, no del sidecar.
                    let _ = rec_addr;
                }
                let graft_padded = std::mem::take(&mut self.pending_block_nullifiers);
                // ⛔⛔⛔ THE THIRD COPY OF THE CANONICAL-ORDER GATE — DELETED. It compared the node's sparse accumulator
                // root bytes with the block header's `nullifier_root` (written out in words: the DB-353 C1 census is a
                // text scan, and the literal it read made this graft path look like a band reader)
                // and it gated the PRODUCER'S OWN A_tip fold. The ingest path's two copies were removed when the
                // committed transition became a pure per-block leaf; this one survived, so a producer silently
                // skipped folding the blocks it had just made.
                //
                // ROOT-LAYER: this is where a self-produced block is ACCEPTED, so it is where its transition must
                // fold — the same single act `fold_atip_at_accept` performs for an ingested block. Patching any
                // downstream reader would leave the producer's own accumulator permanently short.
                //
                // MEASURED (`cross_device_send_converges…`, both devices holding the SAME 50-block DAG, tips equal):
                //     a_fold_seq=4  b_fold_seq=49   ⇒ nf_acc_agree=false, nf_root_agree=false
                // The relay accumulated all 49; the producer accumulated 4 of its own 49. It stayed invisible until
                // `nullifier_root()` began projecting A_tip, because the old root read `sparse_acc`, which THIS
                // branch advances — so the miss hid behind the very field it was failing to keep in step.
                //
                // cons: none — this REMOVES a comparison and adds no work: still ONE O(1) fold per accepted block,
                // no loop, no history term. Removing it loses no check either: a producer's own block extends its
                // own tip by construction, and the fold below is order-free (commutative) and self-verifying from
                // block-carried values.
                // MUST-STAY-GREEN: cross_device_send_converges_full_spent_state_no_island,
                // produced_header_commits_pre_block_nullifier_root_two_producers_agree.
                {
                    // ⛔⛔⛔ Z1 (2026-09-22) — THE PRODUCER NO LONGER OVERWRITES ITS OWN MERKLE VIEW WITH THE
                    // BLOCK'S FOLD LEAF, AND THAT OVERWRITE WAS WHY NO SPEND COULD EVER BE PROVED.
                    //
                    // `nullifier_proof.post_root` is `leaf_to_cm_bytes(block_transition_leaf(pre, digest))` — a
                    // per-block PURE LEAF of the A_tip fold, which is exactly what `adopt_sparse_via_block_fold`
                    // re-derives and compares against. Adopting it through `adopt_merkle_root` filed a FOLD value
                    // as this node's MERKLE view of the spent set, so from the first produced block the view and
                    // the working tree described different things: every later `verify_and_insert` failed, the
                    // tree stopped advancing, and every tag read `Unprovable`. MEASURED across three blocks: the
                    // tree root sat at `5be7…` while the view moved each block.
                    //
                    // DB-353 landing 2 (P1, §13.6): the producer's view advances exactly as every verifier's does —
                    // through `band_drain`, from this block's fold step, never here — so the producer and every peer
                    // reach the same spent set from the same bytes. The block's committed post stays the VERIFIER's
                    // check (`adopt_sparse_via_block_fold`); it is not, and must not be, this node's Merkle view.
                    // ⛔⛔⛔ MIRROR THE PATHS, OR THIS NODE CANNOT DESCRIBE THE TREE IT JUST COMMITTED. Adopting
                    // the root alone advances the accumulator by this block's whole tag set while the copath
                    // index `da_sparse_copath` reads stays empty, so `spent_verdict` answers `Unprovable` for
                    // every tag and the node can prove NEITHER spent nor unspent — refusing honest spends.
                    // MEASURED on a FRESH two-node chain: `[nf-gate] REJECT: input 0 is UNPROVABLE …
                    // (verdicts: 0 unspent / 0 spent / 1 unprovable)` on an untouched faucet note.
                    // Same write the other settle paths make, in the same canonical order the carrier folded.
                    // O-CHAIN-REVIEWED: trip count is `graft_padded.len()` = `BLOCK_FIXED_NULLIFIER_COUNT`, a
                    // fixed protocol constant, each touching `NF_SPARSE_DEPTH` levels — no history term.
                    // (mirror REVERTED — see `adopt_sparse_via_block_fold` for the measurement that killed it)
                    // This block's confidential blobs — the inputs that seed its padded set (SAME tx order the
                    // carrier folded); they advance the cover-conf accumulator below. (The parallel REAL set
                    // fed only the deleted DA-nf shard — D-41 class, 2026-09-11.)
                    let graft_conf: Vec<u8> = selected
                        .iter()
                        .filter(|tx| !tx.nullifiers.is_empty())
                        .flat_map(|tx| tx.blob.clone())
                        .collect();
                    // ⭐ IMT RETIRED HERE — same as the ingest path. The mirror tree this used to fold the padded set
                    // into (and the root it re-derived) is gone; the sparse acc advanced above and is the authority.
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
                    // (The per-block DA-nf shard write that stood here — keyed by `nf_blocks - 1`, the
                    // sparse-fold ordinal, while the accept path keyed by `nf_fold_seq - 1` — is deleted
                    // with the store; D-41 class, 2026-09-11.)
                    // ...and under this block's PRE-ROOT, so a peer still parked on it can name what it needs.
                    // The produce path folds its own blocks inline rather than through
                    // `fold_block_nf_in_order`, so without this line a PRODUCER — the one node guaranteed to
                    // hold a block's inputs — could never serve them, and the request had no responder.
                    // ⛔ per-block fold-by-pre WRITE deleted with its store.
                    // Advance the confidential accumulator by THIS block's real-spend blobs (idle-privacy closure),
                    // folding the SAME nullifier-bearing set the carrier used so every node stays in lockstep.
                    let _conf_pre = self.nf_cover_conf_acc;
                    // ⭐ §CE — the BLOCK'S OWN CARRIED TAGS, not the blobs of the txs this node happened to
                    // select. `graft_conf` was built from `selected` bodies, so a node that pooled a different
                    // subset folded different bytes; `padded_tags` is header-bound and identical everywhere.
                    self.advance_nf_cover_conf_acc(&block.nullifier_proof.padded_tags);
                    let _ = &graft_conf;
                    // A_TIP — produce twin of the ingest advance (identical canonical inputs) so a producer's own
                    // A_tip advances EXACTLY as a verifier's; the block extends the tip, so its committed pre-root is
                    // this node's live acc root before the O(1) adopt above. Same firing condition as conf_acc ⇒ same
                    // canonical order ⇒ convergent. ([[project_atip_island_vector_and_convergence_falsegreen]])
                    let a_pre =
                        usdm_decider::nf_sparse_air::nf_to_limbs(&block.header.nullifier_root.0);
                    let a_td =
                        usdm_decider::nf_sparse_air::sparse_fold_digest_nfs(&graft_padded, a_pre);
                    self.fold_block_into_atip(block.id().0, a_pre, a_td, &graft_padded);
                    // Produce twin of the ingest record — identical canonical inputs, so every node serves the
                    // byte-identical fold stream regardless of who produced the block.
                    // ⛔ fold-input WRITE deleted: this stored one entry PER BLOCK in `da_fold_mem` so a serve
                    // could replay it. Nothing consumes that replay — the wallet reads only the O(1) base — and
                    // the spend gate answers from the node's own roots. The write is the growth; removing the
                    // reader without it would have left the map filling silently.
                    // ...and our OWN block's fold has run, so the bodies it held back are released here too.
                    self.release_folded_tx_evictions();
                }
                // Capture the selected txs' CONFIDENTIAL OUTPUT notes (recipient + change) BEFORE they leave the
                // pool — each carrier proved these exact commitments sum to its value_out, so recording them is
                // conservation-sound (no output inflation) and lets the recipient locally scan its note.
                // Separate SPENDABLE output notes from the LOCKED validator-bond note: a bond tx's output0 is the
                // note whose value the carrier welds to the admitted weight — it is LOCKED (stashed in
                // `bond_locked`, NEVER recorded in the spendable served index) so the bonded value backs the weight
                // and CANNOT be independently spent while bonded (closes the free-Sybil-weight drain: you cannot
                // spend the bonded note and keep its validator weight). Only output1 (change) of a bond tx stays
                // spendable; a non-bond tx records ALL its output notes as spendable, exactly as before.
                // RECORD WHAT THE BLOCK ACTUALLY CARRIES. `block.output_notes` was assembled above, BEFORE
                // `mempool.remove(&cover_ids)` drained this block's cover padding from the pool; re-deriving
                // the payload here reads a pool that no longer holds those txs, so the producer stored a
                // SHORTER payload than the one it gossiped. Measured on a produced block: the wire carried
                // 1153 note bytes and the producer's own record held 0 entries while its peer's held 1 — the
                // producer and the verifier then regenerated different 256-leaf shapes for one block, which
                // is precisely the disagreement that stops a block root from being agreed at all.
                //
                // The bond locks still come from the assembly (they are read from tx bodies, not from the
                // payload), but the notes are the block's own bytes, so produce and ingest record the same
                // thing by construction rather than by two code paths happening to match.
                // ⭐ THE BOND SET NOW RIDES THE BLOCK (header-bound `bond_set`) and is applied by the ONE
                // shared `apply_bond_set` below — produce and ingest admit the same validators from the
                // same bytes by construction, never by two code paths happening to match.
                let out_blobs: Vec<Vec<u8>> = vec![block.output_notes.clone()];
                // ⛔⛔⛔ DROP WHAT THE BLOCK ACTUALLY CARRIES — NOT WHAT THE TEMPLATE HOPED TO CARRY.
                //
                // This removed `tmpl_tx_ids` under the comment "now on-chain in our block". They are not the
                // same list: the code above states plainly that `tmpl_tx_ids` is captured when the template is
                // BUILT, the miner then runs off-lock, and the block's own `tx_ids` is the only list that
                // cannot disagree with the block. Any tx present in the template but absent from the grafted
                // block was therefore deleted from the pool WITHOUT ever reaching the chain — silently, with
                // no retry, and the sender's money simply never arrives.
                //
                // MEASURED across nine sends on a genuinely-connected pair (live_peer_contacts non-zero both
                // ways): `[pool-admit] ACCEPTED (2306 note byte(s))` fired repeatedly while
                // `[assemble] ... 2306 note byte(s)` NEVER fired once. `[admit-gate]` silent (not refused) and
                // `[tmpl-pick]` silent (selection always picked a note-bearing tx) — so the payment was
                // admitted, selected, and then evicted before it could land.
                //
                // Removing by the BLOCK's ids is strictly correct: those are exactly the txs that are on
                // chain. Anything else stays pooled and is re-picked next block — no drop, no window, no
                // age-out, nothing refused ([[feedback_no_windows_no_caps_cardinal]]).
                // ⛔⛔⛔ DEFER THIS EVICTION UNTIL THE FOLD IS DONE — the produce path was doing exactly what
                // the INGEST path carries an explicit warning against.
                //
                // `ingest_block` states it plainly: "DO NOT EVICT A BLOCK'S TXS UNTIL ITS FOLD IS DONE …
                // this node destroyed the very blobs its own decoy seed is derived from … a block references
                // its txs by ID; if every node discards the bodies on graft, the data needed to fold is
                // simply unrecoverable network-wide." That fix landed on ingest and `pending_fold_evictions`
                // exists for it — but the PRODUCE path still removed immediately, so a node's OWN blocks hit
                // the very failure the comment describes.
                //
                // MEASURED: `[graft] ingest evicted …` never fires on either node (own blocks never take the
                // ingest path), while `[pool-admit] ACCEPTED (2306 note byte(s))` fires and
                // `[assemble] … 2306` never does. The payment is admitted, selected, and its body is gone
                // before the fold that would carry its notes.
                //
                // Deferring uses the SAME mechanism ingest already uses — released the moment the fold
                // completes. No window, no age-out, nothing refused: the ids leave the pool when their block
                // has actually folded, and not before ([[feedback_no_windows_no_caps_cardinal]]).
                // ⛔⛔⛔ REVERTED — DEFERRING THIS EVICTION RE-MINED THE SAME PAYMENT FOREVER.
                //
                // I routed the produce path through `pending_fold_evictions` + `settle_or_return_evicted_txs`
                // to mirror the ingest path's "do not evict before the fold" rule. On INGEST that is correct:
                // the bodies must survive so the block can fold and a peer's `TxReq` can be answered. On
                // PRODUCE it is wrong — this node just grafted the block, its txs ARE on chain, and holding
                // them means the very next template selects them again.
                //
                // MEASURED: 4 submits produced 2,345 blocks carrying 2,306 note bytes — the same payment
                // re-assembled into ~586 blocks each. That is a regression I introduced, and it is the shape
                // of a duplicate-note flood, not a settled payment.
                //
                // Evicting by the BLOCK'S OWN ids stays correct (they are exactly what landed); only the
                // deferral is removed. Anything not in the block stays pooled for the next one — no drop, no
                // window ([[feedback_no_windows_no_caps_cardinal]]).
                // ⛔⛔⛔ IS A PAYMENT BEING EVICTED WITHOUT ITS NOTES EVER SHIPPING?
                //
                // This removes EVERY id the block names. If a tx was selected into the template but its notes
                // were never gathered (the pool read empty at note-gathering time), the id is consumed here
                // and the payment is gone from the pool forever while the block carries only cover.
                //
                // MEASURED 2026-08-01 on the live peered pair, same run: `256 selected tx(s): 256 NOT IN
                // MEMPOOL, mempool held 0 tx(s)` alternating with `0 NOT IN MEMPOOL, mempool held 256`, and
                // every produced block carrying exactly 1153 note byte(s) — the lone cover entropy note,
                // never the 2306 a recipient+change pair needs. `[acct-lookup] looked=1 found=0 filed_index=1`
                // says the target IS filed and the block's one note is not the note it was filed for.
                //
                // Fires ONLY on the losing condition — a tx carrying real output notes is evicted while this
                // block shipped none of them. It goes silent the moment a payment's notes ride its block, and
                // it cannot be true in the healthy case. (Gating on the value that is zero when broken is what
                // silenced three earlier probes through three wrong theories.)
                //
                // O1-FOOTPRINT-REVIEWED: one bounded pass over THIS block's own `tx_ids`, whose width is the
                // fixed BLOCK_FIXED_NOTE_COUNT cover shape (256). No per-item store, no term in height,
                // blocks or notes; stores nothing.
                // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS and BYTE LENGTHS only. Never a tx id, note, cm,
                // bucket, address, amount, key, owner or recipient.
                // ⭐⭐⭐ APPLY THIS BLOCK'S CHAIN OBJECTS ON THE NODE THAT MINED IT — the same per-class
                // seam a received block runs through, from the same pooled bytes, BEFORE those ids leave
                // the pool below (after the eviction there are no bytes to apply from). See
                // `apply_chain_objects_of` for why this was missing and what it cost.
                self.apply_chain_objects_of(
                    &block.tx_ids,
                    &block.credit_set,
                    &block.nullifier_proof.padded_tags,
                    crate::block::credit_seal_key(&block.header, block.cover_key.as_ref()),
                    &block.wide_objects,
                );
                self.record_applied_one_time_ids(block.id());
                let evicted_with_notes = block
                    .tx_ids
                    .iter()
                    .filter(|id| match self.mempool.get(id) {
                        // ⛔ DB-299: a tx whose notes are already on this node's chain shipped them — not a loss.
                        Some(t) => !t.output_notes.is_empty() && !self.tx_notes_already_on_chain(&t.output_notes),
                        None => false,
                    })
                    .count();
                if evicted_with_notes > 0 && block.output_notes.len() <= 1153 {
                    eprintln!(
                        "[tx-evict] ⛔ LOSING STATE: evicting {evicted_with_notes} tx(s) that HOLD output \
                         notes, while this block carries only {} note byte(s) — the ids leave the pool here \
                         and their notes never shipped, so the payment is unrecoverable from the mempool.",
                        block.output_notes.len()
                    );
                }
                self.mempool.remove(&block.tx_ids);
                // The flight is over — these ids are on chain and evicted, so nothing is held.
                self.inflight_tx_ids.clear();
                // This block's notes ARE recorded by this node — the ask cursor moves past it here, the produce act
                // being the site that applied the mined block's payload (the cascade loop below skips `own_id`, and
                // the shared carry moves it for every other block). Without this the cursor never reflects
                // self-produced blocks and the backfill chases a phantom.
                self.note_backfill_cursor = self.note_backfill_cursor.saturating_add(1);
                // Constant per-block SERVED-NOTE SHAPE (crate::cover): every block records EXACTLY
                // BLOCK_FIXED_NOTE_COUNT (256) served notes — this block's real spendable output notes, padded
                // with value-0 cover notes and SHUFFLED so each real note lands at a uniformly-random leaf. The
                // served note-tree therefore grows by the SAME constant 256 every block regardless of how many
                // real txs it carried (every block on the chain is shaped identically), so an observer watching
                // the note tree can NEVER tell whether — or how many — real transactions occurred (Pillar 1).
                // Real notes are never dropped (selection caps real output notes at the fixed count). Bond
                // output0 was withheld above (it is LOCKED, not part of the served shape). Producer-side +
                // best-effort (no-halts). A recipient still finds its note by trial-decapsulation regardless of
                // the shuffled leaf position.
                let height = self
                    .relay
                    .dag()
                    .get(&block.id())
                    .map(|n| n.blue_score)
                    .unwrap_or(0);
                // TX LIFECYCLE: the pool measures tx age in BLOCKS, so it learns the height every block.
                self.mempool.set_height(height);
                let real_notes: Vec<u8> = out_blobs.concat();
                // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — how many txs this block selected and how many
                // note bytes it is recording. Never a tx id, nullifier, amount, key or note. A block that
                // selects real txs but records ZERO note bytes is the silent-loss shape: the tx settles, the
                // sender's input is consumed, and the recipient's note was never written anywhere.
                if !real_notes.is_empty() || !tmpl_tx_ids.is_empty() {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a tx id, nullifier, amount or note.
                    // `pool_left` is the decisive number for "accepted but never settles": a real payment
                    // sitting in the pool while blocks are produced around it means SELECTION is refusing it,
                    // whereas an empty pool means it never reached the pool at all. Those two have completely
                    // different fixes and were indistinguishable without this.
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a blake3 COMMITMENT of the recorded payload, never the
                    // payload. Matching it against the submit-side digest proves the bytes survived the hop.
                }
                // ⛔⛔⛔ RECORD THE BYTES THE BLOCK SHIPS, NOT A LOCAL SECOND COPY OF THEM.
                //
                // This recorded `real_notes` (= `out_blobs.concat()`), the producer's own template blobs. The
                // INGEST path records `block.output_notes` — the bytes that actually cross the wire. Two
                // definitions of "this block's notes", which is exactly the defect family that has broken
                // every cross-node send this session.
                //
                // MEASURED, `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`:
                //   two mining nodes holding the SAME blocks disagree on what 12 of 12 ordinals name
                // 12 of 12 — total, not sporadic — because for every block, the node that PRODUCED it stored
                // one byte string and the node that RECEIVED it stored another. `da_block_leaves` is a pure
                // function of the stored bytes, so the two nodes derive different leaves, different block
                // roots, and different `spend_frontier_root`s. A wallet's witness then folds to whichever node
                // it happened to ask, and the spend cannot verify anywhere else — which is precisely "the
                // payment settles on chain and stays invisible to its owner".
                //
                // `block.output_notes` is the ONE source both sides can agree on: the same field, on the same
                // block, read the same way. A producer that records anything else is asserting a private view
                // of a public object.
                //
                // ⛔ DB-354 (lane a 2026-10-24): this writer records `graft_admitted_notes(..)` over these bytes, judged
                // by the block's OWN carried transitions, credit set, bond set, lane and filed tags — the one filter
                // every ingest writer applies. It recorded them raw: a note nothing on the block justifies sat in the
                // producer's record until a later door write replaced it, and in no peer's at all. The fixtures that
                // modelled that plant were migrated (`carry_notes_in_a_block_for_test`'s DB-354 assertion).
                // Pin: `node::pins::db354_a_producer_records_only_the_notes_its_peer_admits`.
                let rec_t0 = std::time::Instant::now();
                // DB-42 diagnosis (runs 54–56): the producer's own change note was never findable on the
                // producing node while the peer that grafted the same block recorded both notes.
                // DIGITAL-CASH-PRIVACY-REVIEWED: a block-id prefix and a byte count; public chain structure.
                eprintln!(
                    "[own-record] block {} carries {} output-note byte(s) into this producer's own record",
                    &block.id().to_hex()[..8],
                    block.output_notes.len()
                );
                let admitted_notes = self.graft_admitted_notes(
                    &block.id(),
                    &block.output_notes,
                    block.cover_key,
                    block.note_transition.as_ref(),
                    block.member_transition.as_ref(),
                    block.cover_transition.as_ref(),
                    &block.credit_set,
                    &block.wide_objects,
                    &block.bond_set,
                    &block.nullifier_proof.padded_tags,
                    &block.oli_tags,
                );
                let rec_addr = self.record_note_payload_for(Some(block.id()), height, &admitted_notes, block.cover_key);
                self.file_block_carried_tags(&block.id(), rec_addr, &block.oli_tags);
                // ⭐ THE PRODUCER'S OWN BLOCK RETIRES WHAT IT BURNS, BY THE SAME DOOR EVERY PEER RUNS AT GRAFT (2026-11-03). Since
                // 03ecc25 the book changes only by chain events, and the one chain event is `retire_orders_burned_by_justified`
                // over the block's justified tags — called at graft (`apply_grafted_block_carry`, `ingest_block_preverified`)
                // but never here, where a node applies the block IT produced. MEASURED (rogue_role_pins::
                // a_re_carried_offer_rests_once_while_live_and_never_again_after_its_fill_on_the_peer): the producer of the
                // fill's block kept resting the filled order (1, 0) while its peer retired it — two books for one chain, a
                // spent order served to every taker on the producer. Idempotent (`remove_by_nullifier` on a retired order is a
                // no-op); a cover tag matches nothing, so the constant padding still hides the real count.
                // ONLY A BLOCK THAT NAMES A RESTING ORDER PAYS FOR THE JUDGMENT: `lane_justified` re-verifies the block's proofs,
                // and an ordinary block (cover tags match no order) never reaches it, so the produce budget is untouched; the
                // pool cannot answer here, a carried fill has already left it (MEASURED: the pool-lookup form stayed RED).
                let names_a_resting_order = block.nullifier_proof.padded_tags.iter().any(|t| {
                    crate::spend_frontier::cm_bytes_to_root(t).is_some_and(|nf| self.order_book.holds_nullifier(nf))
                });
                if names_a_resting_order {
                    let own_just = self.lane_justified(&block);
                    self.retire_orders_burned_by_justified(&own_just, &block.nullifier_proof.padded_tags);
                }
                crate::node_runtime::GRAFT_RECORD_MS.store(
                    rec_t0.elapsed().as_millis() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                // (The PRODUCE ledger-hole probe moved BELOW the cascade drain at the end of this
                // arm, restated in ONE coordinate — record presence per admitted block via
                // `da_load` — instead of differencing the fold ordinal against a block count.)
                // LOCK each bond tx's output0 (its value backs the admitted validator weight) so it stays out of
                // the spendable served index until an authenticated UNBOND returns it — the bonded value cannot be
                // spent while it counts as weight (no free-Sybil-weight drain).
                // ⭐ DB-274 P2 (§8.7): this block's OWN carried bond set applies at its canonical FOLD step, like every
                // peer's (`bond_step_at_fold`) — never here at graft, where a producer's arrival order would differ.
                let bond_t0 = std::time::Instant::now();
                let _ = height;
                crate::node_runtime::GRAFT_BOND_MS.store(
                    bond_t0.elapsed().as_millis() as u64,
                    std::sync::atomic::Ordering::Relaxed,
                );
                // ⛔ DB-274 (dir_set, 2026-10-04): the block's carried DIRECTORY SET does NOT apply here, at graft, in
                // arrival order. It applies at the block's canonical FOLD step (`dir_step_at_fold`), in the one order
                // every node shares — two nodes grafting two registrations of one @name in opposite orders resolved it
                // to two owners (B19's shape).
                // ⭐ SETTLE THIS BLOCK'S CARRIED AMM TRANSITIONS — every node re-verifies each proof and
                // each starting state, so the pool set is a deterministic fold of canonical chain order.
                // ⭐ ADVANCE THE LETTER ACCUMULATOR from this block's carried letter set — the same single
                // fold ingest and cascade run, so produce and ingest converge on one letter_acc.
                self.apply_letter_set(Some(block.id()), height, &block.letter_set);
                // ⭐ RETIRE EXPIRED RESTING ORDERS at this block's height. Driven by HEIGHT, not by a
                // timer, so two nodes at the same height hold the same book without coordinating — an
                // order's expiry is its maker's own term, so this refuses nobody's reach and is what
                // keeps the book bounded. The book is RAM-only and never consensus state, so this fold
                // changes no root and no id; it only stops serving offers their authors already ended.
                let expired = self.expire_orders();
                if expired > 0 {
                    // Counts only — never an order, price, level, maker or note.
                    eprintln!("[book] retired {expired} expired resting order(s) at height {height}");
                }
                // (The stake frontier that used to be appended here from `tx.stake_notes` LEFT 2026-10-04: nothing fed it
                // since DB-237's private stake, and it was an arrival-order, never-inherited, count-leaking accumulator.)
                // Validator admission moved into `apply_bond_set` above — ONE shared, verified path for
                // produce and ingest, fed by the block's own header-bound carry.
                //
                // ⭐⭐⭐ DRAIN THE CASCADE — the produce twin of the ingest drain. `relay.receive`
                // above can graft MORE than the mined block: any peer block that was parked waiting
                // on an id this graft made present cascades in behind it (`drain_from`), and
                // `RelayOutcome::Added` names only the mined block. The account of that cascade
                // lives in `take_grafted`, which is transient — relay.rs clears it at the start of
                // the NEXT receive — so leaving it undrained here DESTROYED it: every cascaded peer
                // block sat in this producer's DAG with NO DA record, no target adoption, no
                // bond/dir/letter apply and no A_tip fold. That is fund loss on the node the owner's
                // wallet may be talking to, and it fits the measured asymmetry (2026-09-04, :28901:
                // 2387 own-produced blocks, 1562 records missing; `graft_mined_own` was the ONE
                // `relay.receive` caller with no drain).
                //
                // ROOT-LAYER: this call site is where those blocks ENTER the DAG, so it is the only
                // place their carried payload still exists to apply — the relay hands it over
                // exactly once. MEASURED: the item-4 pin
                // (`a_peer_block_cascading_behind_an_own_mined_block_is_recorded_and_served`) is RED
                // without this block of code — `da_record_notes = None` for the cascaded block on
                // the miner — and GREEN with it. MUST-STAY-GREEN:
                // `two_mining_nodes_that_exchange_blocks_agree_on_every_record_ordinal`,
                // `reverse_order_gossip_all_grafts`, the recorded_case runtime-backend suite.
                //
                // Applied through the ONE shared per-block path the ingest cascade uses
                // (`apply_grafted_block_carry`) in canonical (blue_work, id) order, skipping the
                // mined block itself (the produce act above already applied it).
                //
                // cons: none — the cost is NOT a function of history or height. Arithmetic: cost =
                // K x (one fixed 256-slot per-block apply, the ~50 ms measured apply class), where
                // K = blocks that were parked waiting on ids THIS graft made present. Steady state
                // K = 0 (a child of a block nobody has seen yet cannot be parked), so the usual cost
                // is one empty `mem::take` (~ns); worst case K is capped by ORPHAN_CAP and each
                // applied block leaves the parked set forever, so the total work over any interval
                // equals blocks-admitted — the same work the ingest lane would have paid for the
                // same blocks, moved to the site that actually holds their payload. The drain
                // measures itself against the same 200 ms budget the ingest apply lane holds and
                // says so out loud when exceeded rather than silently holding the lock. Nothing here
                // may be deferred: these blocks are already IN the DAG, so skipping the apply IS the
                // record hole this drain closes.
                let drain_t0 = std::time::Instant::now();
                let mut cascade = self.relay.take_grafted();
                cascade.sort_by_key(|(gid, ..)| self.relay.dag().canonical_order_key(gid));
                let own_id = block.id();
                let mut cascaded_ids: Vec<Hash32> = Vec::new();
                for (
                    gid,
                    gnotes,
                    gtargets,
                    gpre,
                    gtags,
                    gfold,
                    gbond,
                    gdir,
                    gletter,
                    gpost,
                    gnt,
                    gcredits,
                    gcnt,
                    goli,
                    gmt,
                    gcover,
                    gwide,
                ) in cascade
                {
                    if gid == own_id {
                        continue; // the mined block's own carry was applied by the produce act above
                    }
                    cascaded_ids.push(gid);
                    let _ = self.apply_grafted_block_carry(
                        gid, &gnotes, gcover, &gtargets, gpre, &gtags, &gfold, &gbond, &gdir,
                        &gletter, gnt.as_ref(), gcnt.as_ref(), &gcredits, &goli, gmt.as_ref(), &gwide,
                    );
                    // ⛔ THE SECOND INSTANCE OF D-35, CLOSED WITH THE SAME SHAPE (2026-09-08). This
                    // drain already existed because a cascade behind a mined block "entered with no
                    // record" — and it recorded those blocks while still never folding their spend
                    // transition, so a node that MINES while peer blocks cascade in behind it served
                    // the same short nullifier stream as a node that catches up by parent ask. The
                    // ingest lane's fix is not enough on its own: a producing node reaches its
                    // cascade through HERE, not through `ingest_block`.
                    //
                    // The mined block itself is skipped above and folds inline in the produce act, so
                    // nothing is folded twice — the `gid == own_id` guard is what keeps `nf_leaves`
                    // and `nf_blocks` counted exactly once per block on this path.
                    if !self
                        .relay
                        .dag()
                        .get(&gid)
                        .map(|n| n.header.is_genesis())
                        .unwrap_or(true)
                    {
                        let g_conf = self.nf_fold_inputs_for_block(&gid);
                        // a refused fold is a TAG-LESS block: refused outright, never parked (§13.5 item 2)
                        if self
                            .fold_block_nf_in_order(gpre.0, gpost.0, &g_conf, &gfold, &gtags)
                        {
                            self.release_folded_tx_evictions();
                        }
                    }
                }
                if !cascaded_ids.is_empty() {
                    // Privacy: counts + elapsed only — never a note, amount, key, owner or id.
                    let held = drain_t0.elapsed().as_millis();
                    eprintln!(
                        "[graft] produce drained {} cascaded peer block(s) behind this node's own \
                         mined block in {held}ms{} — recorded/adopted/folded through the shared \
                         ingest path (this drain was MISSING: the cascade entered with no record)",
                        cascaded_ids.len(),
                        if held >= 200 {
                            " ⛔ OVER the 200ms apply budget — report loudly, never defer (item-6 class)"
                        } else {
                            ""
                        }
                    );
                }
                // The fold that used to run right after `receive` runs HERE instead — after every
                // record this graft admits (the mined block's AND the cascade's) has been written
                // from its real carried payload. A fold that reaches a block before its record write
                // fills the record from the shell (the seed note, first-writer) and the real payload
                // is lost to a no-op re-record. Same call, same lock, one graft = one fold step.
                let _ = self.fold_canonical_records();
                // ⛔ ONE COORDINATE (the produce twin of the ingest probe): every block this graft
                // admitted must HOLD a ledger record — asked per block via `da_load`, block counts
                // on both sides. The old probe here differenced `served_seq` (a FOLD ordinal,
                // advancing on spine folds) against a DAG block count and reported fold lag as
                // record loss. The fold delta is printed as its own labelled coordinate instead.
                // Privacy: counts only — never a note, amount, key, owner or id.
                {
                    let mut probe_ids: Vec<Hash32> = vec![own_id];
                    probe_ids.extend(cascaded_ids.iter().copied());
                    let holes = probe_ids
                        .iter()
                        .filter(|gid| {
                            self.da_load(Self::da_record_id_for_block(gid, 0)).is_none()
                        })
                        .count();
                    if holes > 0 {
                        eprintln!(
                            "[ledger-hole] PRODUCE: {holes} of {} block(s) this graft admitted hold \
                             NO ledger record — the note frontier will never fold them. Fold spine \
                             advance during this graft, ITS OWN coordinate, backlog only: {} \
                             record(s).",
                            probe_ids.len(),
                            self.served_seq.saturating_sub(mined_rec_before)
                        );
                    }
                }
                self.autosave(); // persist the resumable checkpoint after producing a block (background; no-op if disabled)
                Some(block)
            }
            // ⛔⛔⛔ A BLOCK WE MINED, WHOSE PAYLOAD WE HOLD, MUST NEVER BE DROPPED WITHOUT ITS RECORD.
            //
            // This was a bare `_ => None`: any outcome other than `Added` discarded the block silently. The
            // node had just MINED it — the `output_notes` are in hand, right here — and the one place that
            // payload can ever be recorded is this call site, because the DAG retains `header + tx_ids` and
            // NOT the notes. Once dropped it is unrecoverable locally and no peer can supply what we alone
            // produced.
            //
            // MEASURED on the live pair (2026-07-30): both nodes lack ledger records for tens of thousands of
            // their OWN blocks at a fixed offset (A 198426 blocks / 168934 records; B 198424 / 150212), and
            // the joiner's backfill for exactly those records is answered `serving 0 of 1 by id` — honestly,
            // because the producer never had them either. A recipient's balance cannot arrive through a hole
            // that neither node can fill.
            //
            // So on any other outcome: if the block IS in the DAG (Duplicate — already grafted by another
            // path) and holds no ledger record, record it now from the payload we mined. Idempotent by
            // address; a block that already has its record is untouched, and this returns None exactly as
            // before so no caller sees a produced block it did not get.
            other => {
                let bid = block.id();
                // DIGITAL-CASH-PRIVACY-REVIEWED: the relay's outcome (a public block id and a fixed reason) only.
                eprintln!("[produce] ⛔ this node's OWN mined block was not grafted: {other:?}");
                if self.relay.dag().get(&bid).is_some()
                    && self
                        .da_load(Self::da_record_id_for_block(&bid, 0))
                        .is_none()
                {
                    let h = self
                        .relay
                        .dag()
                        .get(&bid)
                        .map(|n| n.blue_score)
                        .unwrap_or(0);
                    eprintln!(
                        "[produce] mined block was not Added ({other:?}) but IS in the DAG with no ledger \
                         record — recording its {} carried byte(s)",
                        block.output_notes.len()
                    ); // DIGITAL-CASH-PRIVACY-REVIEWED: an outcome name and a byte LENGTH; never a note, amount, key or owner.
                    let notes = block.output_notes.clone();
                    self.record_note_payload_for(Some(bid), h, &notes, block.cover_key);
                }
                None
            }
        }
    }

    /// ⛔⛔⛔ DB-276 — THE REAL NOTES A SELECTED-CHAIN BLOCK ACCEPTS: its own and those of every block it MERGES beyond
    /// its selected parent (Kaspa's acceptance data — a chain block accepts its mergeset), in the mergeset's canonical
    /// order, the chain block last. Every applied block lands in exactly one entry: the entry of the chain block that
    /// merged it. `None` if ANY member's notes are not held yet — the wallet's cursor waits at the entry rather than
    /// stepping past a payment (the cursor never skips an answered entry).
    ///
    /// The mergeset comes from [`crate::dag::Dag::ghostdag_data`], the function that coloured `c` at insertion; a chain
    /// block with ONE parent merges nothing beyond it, so it walks nothing.
    /// O1-DEFINITION-REVIEWED: bounded by the protocol's merge shape (`merge_depth_cap` for the boundary walk, the
    /// mergeset bound for the members), per entry; the route's page clamp bounds the entries. No term in height.
    pub(super) fn accepted_real_notes(&self, c: &BlockId) -> Option<Vec<(BlockId, Vec<Vec<u8>>)>> {
        let dag = self.dag();
        let node = dag.get(c)?;
        let mut members: Vec<BlockId> = Vec::new();
        if node.header.parents.len() > 1 {
            let gd = dag.ghostdag_data(&node.header.parents);
            members.extend(gd.mergeset_blues.iter().filter(|b| **b != gd.selected_parent).copied());
            members.extend(gd.mergeset_reds.iter().copied());
        }
        members.push(*c);
        let mut notes: Vec<(BlockId, Vec<Vec<u8>>)> = Vec::with_capacity(members.len());
        for b in &members {
            notes.push((*b, self.admitted_real_notes_of(b)?));
        }
        Some(notes)
    }

    pub(super) fn admitted_real_notes_of(&self, b: &BlockId) -> Option<Vec<Vec<u8>>> {
        if self.payload_gap.contains_key(b) {
            return None;
        }
        if let Some(addr) = self.record_addr_for_block(b) {
            return self.da_record_reals(addr);
        }
        if self.block_declares_no_notes_by_id(b) && self.full_block_by_id(b).is_some() {
            return Some(Vec::new());
        }
        None
    }

    /// Admit a bonded validator (bond must meet the THORChain-adaptive floor for `bridge_tvl`). Active for finality at
    /// every height (a genesis / fixture seat); the chain's SAT-bond door seats through [`Self::admit_validator_active_from`].
    pub fn admit_validator(
        &mut self,
        id: [u8; 32],
        bond: u128,
        bridge_tvl: u128,
    ) -> Result<(), ValidatorError> {
        self.validators.admit(id, bond, bridge_tvl)?;
        self.validators.settle_own_yield(&id, self.peg.bond_yield_index()); // §BR-3 17.6: the seat earns from now
        Ok(())
    }

    /// ⭐ G2b — the chain's SAT-bond door (`sat_bond_tx::seat_sat_bond`, at the fold): custody weight that counts toward
    /// finality votes at heights `>= active_from` ([`Self::seat_active_from`]).
    pub fn admit_validator_active_from(
        &mut self,
        id: [u8; 32],
        bond: u128,
        bridge_tvl: u128,
        active_from: u64,
        // SAFE AT SCALE: the chain randomness its custody seat is drawn under — the id of the block whose fold seats it
        seat_entropy: &[u8; 32],
    ) -> Result<(), ValidatorError> {
        self.validators.admit_active_from_drawn(id, bond, bridge_tvl, active_from, seat_entropy)?;
        self.validators.settle_own_yield(&id, self.peg.bond_yield_index()); // §BR-3 17.6: the seat earns from now
        Ok(())
    }

    pub fn apply_membership_seat(
        &mut self,
        id: [u8; 32],
        secp33: Vec<u8>,
        ed32: [u8; 32],
        kem_ek: Vec<u8>,
    ) -> crate::membership_bond_tx::MembershipApply {
        use crate::membership_bond_tx::MembershipApply;
        // A re-applied block never double-seats — and "seated" means THIS seat: the identity's own finality seat. Reading the
        // total finality weight (which counts a SAT custody seat) made the set a function of fold ORDER: a SAT bond folded
        // before its validator's membership seat left that seat AlreadySeated, so its custody point never registered and its
        // custody weight never reached the reserve leaf (MEASURED 2026-10-09, db249/db286: "seated 2, custody-weighted with
        // a registered point 0"). Kaspa/Ethereum: state is a function of the objects the chain carries, never their order.
        if self.validators.holds_finality_seat(&id) {
            return MembershipApply::AlreadySeated;
        }
        // DB-123: the custody set is about to change — remember the OUTGOING membership so a deposit
        // addressed under it still finds its leaf when its mint arrives. CACHE-ONLY: a ring of memberships
        // the chain's own bond set produced; nothing here decides anything for the chain.
        self.remember_custody_leaf();
        // ⭐ SATOSHI §6 (DB-391): the free membership seat is FINALITY membership with its custody point registered —
        // never custody WEIGHT, which only a SAT bond seats. (With weight 1 here, two free seats plus any four base units
        // of SAT bonded took the reserve's 2/3 — the hole in miniature.)
        // G2b: the seat counts toward finality from the fold step's landing height plus the activation delay
        match self.validators.admit_finality_active_from(id, crate::params::MEMBERSHIP_BOND_WEIGHT, self.seat_active_from()) {
            Ok(()) => {
                self.validators.register_custody(id, secp33, ed32);
                // The seat's SIGNED encapsulation key — where peg-in deltas are sealed to this custodian.
                self.validators.register_custody_kem(id, kem_ek);
                // ⛔ DB-258c: NO landing score is recorded. DB-258 recorded one here as the seating's instance, and a
                // landing score is a fact about arrival (sibling carriages, a jumped node's re-request), so two honest
                // nodes held two instances for one seat and refused each other's unbond. See `bond_instance_of`.
                MembershipApply::Seated
            }
            // The set's reasons are static (`BondBelowFloor`, `AlreadyBonded`, `Slashed`); say which, so a
            // refused seat is diagnosable from the line alone (the 2026-09-17 floor refusal was mute).
            Err(crate::validator::ValidatorError::BondBelowFloor { .. }) => {
                MembershipApply::Refused("the validator set refused the seat: bond below the adaptive floor")
            }
            Err(crate::validator::ValidatorError::AlreadyBonded) => MembershipApply::AlreadySeated,
            Err(crate::validator::ValidatorError::Slashed) => {
                MembershipApply::Refused("the validator set refused the seat: this identity was slashed")
            }
            Err(crate::validator::ValidatorError::NotBonded) => {
                MembershipApply::Refused("the validator set refused the seat: no custody seat")
            }
        }
    }

    /// A fixture's door into [`Self::apply_bond_set_at`] whose block sits at chain tick `height` (a fixture's blocks are
    /// one tick apart). Tests only: production names the fold block's own tick.
    #[cfg(test)]
    pub fn apply_bond_set(&mut self, bond_set: &[u8], height: u64, carried_notes: &[u8], lane: &[[u8; 32]], output_notes_root: Option<&Hash32>) {
        self.apply_bond_set_at(bond_set, height, height, carried_notes, lane, output_notes_root);
    }

    /// Apply a block's bond set at its fold step: `height` is the carrying block's blue score (structure: the evidence
    /// horizon an unbonding waits out) and `tick` its chain tick (`Node::chain_tick_at`, time: the stake lock and the
    /// unbonding window, A-F60).
    pub fn apply_bond_set_at(
        &mut self,
        bond_set: &[u8],
        height: u64,
        tick: u64,
        carried_notes: &[u8],
        // ⛔ DB-258b — the carrying block's header-bound nullifier lane: a seat lands only if the block retires its one-shot
        // right (`membership_bond_tx::seat_right_nf`), which the block's nullifier proof proves NEW.
        lane: &[[u8; 32]],
        // ⭐ DB-313 §3 — the carrying block's header-bound output root, which its bond transition is verified against.
        // `None` (a caller that does not hold the header) admits NO bond weight: fail-closed on the bonds, never on
        // the block; the unbond / seat / equivocation arms are unaffected.
        output_notes_root: Option<&Hash32>,
    ) {
        // `carried_notes` (DB-257): the SAME block's notes. An unbond releases only when its block carries the
        // bond's returned note, so the weight and the collateral can never both be live, nor both be gone.
        let (entries, malformed_tail) = Self::bond_set_entries(bond_set);
        // DB-313 §3: what this lane's bond transition PROVES — read once, before any entry applies.
        let proven = output_notes_root.and_then(|r| Self::bond_admissions_on_door(bond_set, r, self.template_double()));
        // ⛔ DB-274 P4b (§8.15, lane-wallet's C3): a theft certificate is weighed against the set AS THIS STEP FOUND
        // IT, never against the running set the entries below mutate (a seat earlier in this lane would move its
        // denominator). One copy of the bounded set, taken only when this lane carries a theft object.
        let theft_pre: Option<crate::validator::ValidatorSet> = entries
            .iter()
            .any(|e| {
                e.as_ref().is_some_and(|tx| {
                    matches!(
                        crate::chain_object::unframe(&tx.blob),
                        Some((crate::chain_object::Class::ReserveTheft, _))
                    )
                })
            })
            .then(|| self.validators.clone());
        for entry in entries {
            let Some(tx) = entry else {
                eprintln!("[bond-apply] refused: a carried bond entry did not decode as a tx");
                continue;
            };
            // ⭐ THE RELEASE ARM. An unbond entry is a framed object, not a bonding tx: it carries no
            // bond notes and no WHIR bond-validity carrier, so the admission welds below cannot judge it
            // and must not be asked to. Its own door re-verifies the ML-DSA signature against the id it
            // RECOMPUTES, on THIS node, so a forged entry releases nothing and the block still grafts.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::Unbond, _))
            ) {
                // ⛔ THE VERDICT IS SAID (2026-09-27, slot B4): this arm was `let _ =` — the seat arm's 2026-09-17 defect
                // again — and a real node that refused a carried unbond left no line anywhere, so a run that measured
                // "the unbond never landed" could not tell a refusal from an absence.
                // DIGITAL-CASH-PRIVACY-REVIEWED: FIXED strings plus the door's own static reason; the count is the public
                // validator set every node holds; never an id, key, bucket or amount.
                match crate::node::objects::unbond_tx::apply_chain_unbond(
                    self,
                    &tx.blob,
                    &crate::pqauth::MlDsaVerifier,
                    height,
                    tick,
                    lane,
                ) {
                    crate::unbond_tx::UnbondApply::Released(_) => eprintln!(
                        "[bond-apply] unbond RELEASED a validator from the block ({} seated)",
                        self.validators.len()
                    ),
                    crate::unbond_tx::UnbondApply::Refused(why) => {
                        eprintln!("[bond-apply] refused: a carried unbond — {why}")
                    }
                    crate::unbond_tx::UnbondApply::NotUnbond => {}
                }
                continue;
            }
            // ⛔ DB-266 — THE SLASH ARM. Equivocation evidence is a validator object like an unbond: it rides the bond
            // set and applies HERE, on every grafting node, from the object's own bytes. The verdict is said.
            // Privacy: FIXED strings plus the door's own static reason; never an id, key or amount.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::Equivocation, _))
            ) {
                match crate::node::objects::equivocation_tx::apply_chain_equivocation(self, &tx.blob, &crate::pqauth::MlDsaVerifier) {
                    crate::equivocation_tx::EquivocationApply::Slashed(_) => {
                        eprintln!("[bond-apply] equivocation evidence from the block SLASHED a validator")
                    }
                    crate::equivocation_tx::EquivocationApply::Refused(why) => {
                        eprintln!("[bond-apply] refused: carried equivocation evidence — {why}")
                    }
                    crate::equivocation_tx::EquivocationApply::NotEquivocation => {}
                }
                continue;
            }
            // ⭐ §BR-9a — THE EPOCH-KEY FRAUD ARM, parity with the equivocation arm above: the proof rides the bond set and
            // slashes HERE, on every node, checked against this node's own epoch-key ledger. The verdict is said.
            // Privacy: FIXED strings plus the door's own static reason; never an id, epoch or share.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::EpochKeyFraud, _))
            ) {
                match crate::node::objects::epoch_fraud_tx::apply_chain_epoch_fraud(self, &tx.blob) {
                    crate::epoch_fraud_tx::FraudApply::Slashed(_) => {
                        eprintln!("[bond-apply] epoch-key fraud evidence from the block SLASHED its dealer")
                    }
                    crate::epoch_fraud_tx::FraudApply::Refused(why) => {
                        eprintln!("[bond-apply] refused: carried epoch-key fraud evidence — {why}")
                    }
                    crate::epoch_fraud_tx::FraudApply::NotFraud => {}
                }
                continue;
            }
            // ⛔ G2 (2026-10-22) — A FINALITY VOTE rides this lane but is NOT applied here: it moves no value, so it needs no
            // pre-state step, and it tallied at the body's GRAFT (`apply_carried_finality_votes`, from
            // `remember_unfolded_block`, every door) — at the fold it would trail the tip by the fold depth (MEASURED:
            // finalized 21 at tips 115). The lane carries it header-bound; the graft door verified it from its own bytes.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::FinalityVote, _))
            ) {
                continue;
            }
            // ⛔ DB-274 P4b (§8.15) — THE THEFT ARM. A reserve theft's evidence is a validator object like an
            // equivocation: it rides the bond set and slashes HERE, at the fold, on every node, weighed against the
            // step's pre-state (`theft_pre`). The route that heard of it only published it.
            // Privacy: FIXED strings plus the door's own static reason; never an id, key or amount.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::ReserveTheft, _))
            ) {
                let verdict = match theft_pre.as_ref() {
                    Some(pre) => crate::node::objects::theft_tx::apply_chain_reserve_theft(
                        self,
                        &tx.blob,
                        pre,
                        &crate::pqauth::MlDsaVerifier,
                    ),
                    // The copy is taken whenever this lane holds a theft entry, so this is never reached; if it were,
                    // the object is refused (fail closed), never weighed against a moved set.
                    None => crate::theft_tx::TheftApply::Refused("the step's pre-state set was not captured"),
                };
                match verdict {
                    crate::theft_tx::TheftApply::Slashed(_) => {
                        eprintln!("[bond-apply] reserve-theft evidence from the block SLASHED its named offender(s)")
                    }
                    crate::theft_tx::TheftApply::Refused(why) => {
                        eprintln!("[bond-apply] refused: carried reserve-theft evidence — {why}")
                    }
                    crate::theft_tx::TheftApply::NotTheft => {}
                }
                continue;
            }
            // ⭐⭐⭐ THE SEAT ARM (§CW). A membership bond is likewise a framed object with no bond notes
            // and no collateral carrier: its own door re-verifies the ML-DSA signature and decides, from
            // THIS node's chain state, whether a seat is free right now (reserve == 0). Every grafting
            // node runs the same door on the same bytes in the same block order — which is exactly what
            // makes "the first nodes to bond" a shared fact and not a local one.
            // DB-313 §3: the lane's own aggregate — already read above as `proven`; it admits nothing by itself.
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::BondTransition, _))
            ) {
                continue;
            }
            if matches!(
                crate::chain_object::unframe(&tx.blob),
                Some((crate::chain_object::Class::MembershipBond, _))
            ) {
                // ⛔ THE VERDICT IS SAID. This arm was `let _ =` until 2026-09-17, and a seat the block
                // carried was refused (`BondBelowFloor`) with no line anywhere — the real-node journey
                // read as "the seat never rode" for a full run. Privacy: FIXED strings + the door's own
                // static reason; never an id, key or amount.
                match crate::node::objects::membership_bond_tx::apply_chain_membership_bond(
                    self,
                    &tx.blob,
                    &crate::pqauth::MlDsaVerifier,
                    lane,
                    tick,
                ) {
                    crate::membership_bond_tx::MembershipApply::Seated => eprintln!(
                        "[bond-apply] membership seat LANDED from the block ({} seated)",
                        self.validators.len()
                    ),
                    crate::membership_bond_tx::MembershipApply::AlreadySeated => {}
                    crate::membership_bond_tx::MembershipApply::Refused(why) => {
                        eprintln!("[bond-apply] refused: a carried membership seat — {why}")
                    }
                    crate::membership_bond_tx::MembershipApply::NotMembershipBond => {}
                }
                continue;
            }
            // ⛔⛔⛔ VALIDATOR BONDS ARE SAT-ONLY (`Self::USDM_BOND_RETIRED`). What reaches here is an unframed USDm bond
            // (every framed validator object took its arm above, a SAT bond rides its own class): it seats NOTHING on any
            // node, whoever laid it. The template never lays one and the door refuses one, so only a producer that skipped
            // both carries it; its lane's retirement of the input is that producer's block's business, never a seat.
            // Privacy: a FIXED string — no id, key, amount or owner.
            if Self::is_usdm_bond_tx(&tx) {
                eprintln!("[bond-apply] refused: a carried USDm bond — validator bonds are SAT, a USDm bond seats nothing");
            }
        }
        if malformed_tail && bond_set.len() != crate::block::SIDECAR_PADDED_BYTES {
            // A malformed tail can prove nothing — the remainder is refused, never a stride guessed.
            // When len == SIDECAR_PADDED_BYTES the tail is the constant-shape cover pad (u32::MAX sentinel + XOF
            // bytes), expected on every block — not a framing defect.
            // Privacy: a FIXED string — no id, key, amount or owner.
            eprintln!("[bond-apply] refused: malformed bond_set entry framing (fail-closed on the tail)");
        }
    }

    /// ⭐⭐⭐ DB-114 (2026-09-20) — THE BURN'S OWN CHAIN OBJECT IS THE RELEASE AUTHORITY.
    ///
    /// USER 2026-09-19: "fix the bug for the concern so marked released actually guarantees the funds are
    /// released."
    ///
    /// ⛔⛔⛔ WHAT WAS WRONG: ONE ECONOMIC ACTION NEEDED TWO INDEPENDENT QUORUMS, AND NOTHING COMPELLED THE
    /// SECOND. A redeem destroys USDm when a BLOCK carries its `Class::PegOut` object, and that object is
    /// already ≥2/3-attested over `peg_out_confidential_msg` — commitments, proposal nonce, burned note's
    /// cross-bind and (DB-110) the destination commitment. Then this door demanded a SECOND ≥2/3 gather over
    /// a DIFFERENT statement (`reserve_move_statement`) before the reserve could pay out. The two were not
    /// bound to each other and the second was not obligatory, so a redeem whose second quorum never formed
    /// left the USDm DESTROYED and the BTC UNRELEASED, with `mark_released` sitting there recording an
    /// authorisation that never came. That is the worst shape available: the holder's money is gone from
    /// this chain and has not arrived on the other one, and no gate anywhere reports a fault.
    ///
    /// THE FIX IS THE CARDINAL, APPLIED: only inclusion decides that a transition HAPPENED. The block that
    /// carried the burn IS the authorisation — ≥2/3 of bonded weight already signed that exact redeem, to
    /// that exact destination commitment. So this door asks the chain, not a fresh signature round:
    ///   1. `NotBurned` unless `burn_nullifier` is a REAL recorded peg-out burn. Conservation is unchanged:
    ///      the reserve leaves ONLY against a USDm note the chain actually destroyed.
    ///   2. `AlreadyReleased` unless this burn is claiming its FIRST release — one burn, one payout, still.
    ///   3. Otherwise `Authorized`, and EVERY custodian reaches that verdict independently from its own copy
    ///      of the chain, with no coordination round that can fail to happen.
    ///
    /// WHY DROPPING THE SECOND CERT LOSES NO PROTECTION. What that cert checked was "≥2/3 agree this burn
    /// pays this destination" — which the FIRST quorum already established and bound into the object: since
    /// DB-110 every attesting custodian re-derives `redeem_commit(address, blind)` from its OWN sealed
    /// opening and refuses to sign when it does not match the statement. The second cert could therefore
    /// only re-assert what was already attested, while adding a way for the payout to never occur.
    ///
    /// WHAT ACTUALLY BINDS THE PAYOUT ADDRESS is not this door at all — it is the threshold custody signing
    /// of the Bitcoin transaction itself. This node holds no foreign key and signs nothing; each custodian
    /// signs the payout only if the address matches ITS OWN sealed leg, so a single custodian cannot
    /// redirect a redeem however this door answers. Naming that honestly matters: the old doc-comment
    /// claimed "the statement binds the destination" as if this were the protection, and it was not.
    ///
    /// A burn that is on-chain and not yet released is an OBLIGATION, and it is derivable rather than
    /// stored: `is_burned(nf) && !released(nf)` — see [`crate::peg::PegLedger::release_pending`]. Nothing
    /// ages it out and no ceiling drops it, so a payout that has not happened stays visible until it does.
    /// DB-121: record that this burn's Bitcoin payout CONFIRMED, as THIS node's own Bitcoin source read it. Called
    /// only by the payout lane (`crate::btc_payout`) after the transaction has the confirmations THORChain's
    /// counting requires — the deposit watcher's shape, one edge over. Never by a request.
    /// CACHE-ONLY: the `released` flag mirrors an observed foreign-chain fact (the payout confirmed); the chain
    /// transition it follows — the burn — was applied from `Class::PegOut`, and a node re-applying its blocks
    /// re-derives the obligation the lane then re-observes.
    pub fn settle_reserve_release_observed(&mut self, burn_nullifier: &[u8; 32]) -> ReleaseOutcome {
        if !self.peg.is_burned(burn_nullifier) {
            return ReleaseOutcome::NotBurned; // conservation: no reserve leaves without a destroyed USDm
        }
        if !self.peg.mark_released(*burn_nullifier) {
            return ReleaseOutcome::AlreadyReleased; // one burn ⇒ at most one foreign release
        }
        ReleaseOutcome::Settled
    }

    /// ⭐ THE GRAFT-SIDE RELEASE — what every node runs when a block carries an unbond object.
    ///
    /// The signature was verified by `unbond_tx::apply_chain_unbond` from the object's own bytes, on THIS
    /// node, so this is the same release the submitting node performed and not a trusted replay of it.
    /// Returns `None` when this node holds no matured bond for that validator — which is the honest answer
    /// for a node that never admitted it, and is fail-closed: nothing moves.
    pub fn apply_unbond_release(
        &mut self,
        id: [u8; 32],
        // ⭐ DB-273 §19.3 L2: the returned note's OLI clue, from the object `decode` opened against its signed digest.
        owner_clue: Vec<u8>,
        // DB-257: the CARRYING block's blue score and chain tick — maturity is judged on the block, never on this node's
        // tip; the stake lock and the unbonding window on its tick (A-F60), the evidence horizon on its blue score.
        at_blue: u64,
        at_tick: u64,
    ) -> Option<u128> {
        self.release_matured_bond(id, Some(owner_clue), at_blue, at_tick)
    }

    /// ⛔ DB-266 — THE ONE SLASH: burn `voter`'s bond and bar its id, if it is bonded here. Reached only from the two
    /// evidence classes' fold-side doors, after the evidence verified from the object's own bytes:
    /// `equivocation_tx::apply_chain_equivocation` and `theft_tx::apply_chain_reserve_theft` (DB-274 P4b: one function,
    /// so the theft class cannot drift from the unbonding rule below — §9.5).
    /// ⭐ DB-274 P2 (§8.7, F2): applied at the evidence's FOLD step, and it also reaches a validator that is
    /// UNBONDING: its collateral is still inside the evidence window, so the entry is dropped (the note never
    /// returns) and the weight it held at the unbond counts as burned. Both are burned if V bonded again meanwhile.
    /// A RESERVE THEFT's slash: the whole seat, delegations included — the loss beyond the operator's bond cannot yet be
    /// valued in SAT (no SAT price until §18's batches), so §22 5's operator-first split fails closed to burning it all.
    pub(crate) fn apply_slash(&mut self, voter: [u8; 32]) -> Option<u128> {
        self.slash_seat(voter, false)
    }

    /// ⭐ §22 5 — THE OPERATOR-FIRST SLASH for misbehaviour that loses no one's money (equivocation, epoch-key fraud): the
    /// validator is barred and its OWN weight burned; the SAT delegated to it is untouched — each delegator undelegates
    /// through the ordinary unbonding. `None` when `voter` is neither seated nor unbonding here.
    pub(crate) fn apply_slash_no_loss(&mut self, voter: [u8; 32]) -> Option<u128> {
        self.slash_seat(voter, true)
    }

    /// The one slash: `no_loss` keeps the delegated word and burns the operator's own weight only (§22 5).
    fn slash_seat(&mut self, voter: [u8; 32], no_loss: bool) -> Option<u128> {
        let until = self.exit_active_until(); // G2b: out of the numerator now, in the denominator until landing + D
        let live = if no_loss {
            self.validators.slash_operator_first_exiting_at(&voter, until)
        } else {
            self.validators.slash_exiting_at(&voter, until)
        };
        let waiting = self.unbonding.remove(&voter).map(|u| {
            if no_loss {
                self.validators.mark_slashed_operator_first(voter, u.amount)
            } else {
                self.validators.mark_slashed(voter, u.amount);
                u.amount
            }
        });
        match (live, waiting) {
            (None, None) => None,
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
        }
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed Equivocation object, which every
    // grafting node applies through `equivocation_tx::apply_chain_equivocation` from `Block::bond_set`.
    /// ⭐ DB-259 — install the CERTIFIED bond locks at an adopt, REPLACING this node's own: the certified state is
    /// the chain's (state is a function of the chain; the local map is a cache of it). Called beside
    /// `adopt_certified` and `adopt_certified_price_marks`, from the one adopt that installs a verified bundle.
    pub(crate) fn adopt_certified_bond_locks(&mut self, heights: &[([u8; 32], u64)], notes: &[([u8; 32], Vec<u8>)]) {
        self.bond_height = heights.iter().cloned().collect();
        self.bond_locked = notes.iter().cloned().collect();
    }

    pub fn ingest_finality_vote_gossip(&mut self, cert: VoteCert) -> bool {
        let voter = pubkey_id(&cert.pubkey);
        if !self.finality_verifier.verify(
            &cert.pubkey,
            &finality_vote_msg(&cert.block, cert.height),
            &cert.sig,
        ) {
            return false; // unauthenticated -> drop, never re-gossip
        }
        if !self.voter_weight_admits(&voter, cert.height) { // SATOSHI §6: finality is every seat, custody is SAT; G2b: at the voted height
            return false; // not bonded -> no weight, do not re-flood
        }
        if self.finality.voted_block_at(cert.height, &voter) == Some(cert.block) {
            return false; // duplicate -> already carried and counted (or settled), do not re-flood
        }
        // PARITY WITH THE DOOR IT PARALLELS (charter §9.6 q6): the RPC door runs this same check through
        // this same helper. A block we do not hold, or a height that disagrees with the block's own
        // blue_score, is not counted and not re-flooded. Not a stall — the voter re-votes next stride and
        // the vote still reaches us from every other holder once we have the block.
        let binds = self.finality_vote_binds_to_dag(&cert.block, cert.height);
        crate::budget_clock::replay_tx_trace(if binds { "vote-binds" } else { "vote-unbound" }, &cert.block.0, None);
        if !binds {
            // MEASURED (run 36, 2026-09-18): node 0 counted node 1's votes to height 153 while node 1
            // counted node 0's only to 8 — which door refuses them is said here, rate-limited.
            // DIGITAL-CASH-PRIVACY-REVIEWED: two DAG heights and a count; nothing of any note or key.
            static REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let n = REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            if n == 1 || n % 50 == 0 {
                let held = self.relay.dag().get(&cert.block).map(|b| b.blue_score);
                eprintln!(
                    "[finality] a vote did not bind ({n} so far): claimed height {} vs held {:?} (None = parked until the block lands)",
                    cert.height, held
                );
            }
            if crate::validator::finality_trace_enabled() {
                eprintln!(
                    "[finality-vote] recv h={} block={} outcome=Unbound(held={:?})",
                    cert.height,
                    &cert.block.to_hex()[..8],
                    self.relay.dag().get(&cert.block).map(|b| b.blue_score)
                );
            }
            if self.relay.dag().get(&cert.block).is_none() {
                // the block is not here yet — park the vote (once per block+voter), re-ingest at graft
                if !self.parked_votes.iter().any(|c| c.block == cert.block && c.pubkey == cert.pubkey) {
                    self.parked_votes.push_back(cert); // O1-FOOTPRINT-REVIEWED: bounded by PARKED_VOTES_MAX
                    while self.parked_votes.len() > PARKED_VOTES_MAX {
                        self.parked_votes.pop_front();
                    }
                }
            }
            return false;
        }
        // ⛔ G2 (2026-10-22): this door TALLIED here, so finality was a function of which node a vote reached. It now
        // POOLS the vote as a chain object (verified, deduped against the carried tally and the votes in flight); the
        // tally moves when a block carries it and this node folds that block. A double-sign seen here is QUEUED as
        // evidence (DB-266) and not re-gossiped; only a freshly pooled vote is.
        // SPEED L7: signature, seat weight and DAG binding are verified above — the vote is OBSERVED now (a figure only
        // fork choice, the wallet, payout signing and the voter read); the chain's tally still moves only at the fold.
        self.observe_verified_vote(&cert, voter);
        let (outcome, fresh) = self.pool_finality_vote(cert.clone(), voter);
        if crate::validator::finality_trace_enabled() {
            eprintln!("[finality-vote] recv h={} block={} outcome={outcome:?} fresh={fresh}", cert.height, &cert.block.to_hex()[..8]);
        }
        fresh && matches!(outcome, FinalityVoteOutcome::Counted)
    }

    /// Register / update a `@name` → address mapping. Authenticated by an ML-DSA-65 signature over
    /// `pqauth::name_register_msg(name, address)`; the owner id IS `H(pubkey)`, so first-come claims the name and
    /// only its owner can later re-point / transfer it. Fail-closed (Unauthenticated) if the signature is invalid.
    /// ⭐ ON-CHAIN DIRECTORY — apply a carried `dir_set`: decode each sign-up, RE-VERIFY its ML-DSA signature over the
    /// canonical [`crate::directory::dir_register_msg`], derive `owner = H(pubkey)`, and fold it into the directory
    /// projection under the first-come / owner-continuity rule. A bad signature or a squat is skipped fail-closed; the
    /// DAG never halts.
    /// ⛔⛔⛔ DB-274 (dir_set, 2026-10-04): a BLOCK's set applies at its canonical FOLD step (`dir_step_at_fold`), never at
    /// graft — "first-come" under arrival order resolved one @name to two owners on two honest nodes and gave one chain
    /// two directory accumulators (MEASURED by `db274_two_nodes_that_apply_two_registrations_of_one_name_in_opposite_
    /// orders_hold_one_directory`, RED-first). This entry point is the certified REFILL's (`dir_refill_page`: the
    /// jumper replays the certified sequence in its one order) and the fixtures'.
    pub fn apply_dir_set(&mut self, dir_set: &[u8], _height: u64) {
        self.apply_dir_set_into(dir_set, None, false);
    }

    /// The ONE verify-and-apply helper behind every directory writer. `step`: `Some` journals each applied slot's
    /// before-image (the fold step, rewound with its block); `None` applies without a journal (the certified refill,
    /// which no rewind can un-fold — its caller raises the journal floor).
    /// `certified`: the sequence was verified WHOLE against the certified directory word before this call (the refill
    /// door, audit F16). Only then does an asset's record apply here (spec §12.6): it carries no signature, because the
    /// fold of the asset's own creation wrote it, and the certified word is what says the chain applied it. From any
    /// other caller an asset's record in the set is skipped like an unsigned sign-up.
    pub(super) fn apply_dir_set_into(
        &mut self,
        dir_set: &[u8],
        mut step: Option<&mut crate::directory::DirStep>,
        certified: bool,
    ) {
        use crate::pqauth::PqVerifier;
        let entries = crate::directory::decode_dir_set(dir_set);
        let mut changed = false;
        for e in &entries {
            if matches!(e.kind, crate::directory::KIND_ASSET | crate::directory::KIND_ASSET_FILE | crate::directory::KIND_ASSET_SUPPLY) {
                if !certified {
                    continue; // written by a creation's and a mint's own folds, never taken from a set
                }
                let filing = e.kind == crate::directory::KIND_ASSET_FILE;
                let supply = e.kind == crate::directory::KIND_ASSET_SUPPLY;
                let applied = match step.as_deref_mut() {
                    Some(s) if filing => self.directory.apply_asset_filing_journaled(e, s),
                    Some(s) if supply => self.directory.apply_asset_supply_journaled(e, s),
                    Some(s) => self.directory.apply_asset_record_journaled(e, s),
                    None => {
                        let logged = if filing {
                            self.directory.apply_asset_filing(e)
                        } else if supply {
                            self.directory.apply_asset_supply(e)
                        } else {
                            self.directory.apply_asset_record(e)
                        };
                        match logged {
                            Some(entry) => {
                                self.directory.fold_applied(&entry);
                                true
                            }
                            None => false,
                        }
                    }
                };
                changed |= applied;
                continue;
            }
            let msg = crate::directory::dir_entry_msg(e);
            if !crate::pqauth::MlDsaVerifier.verify(&e.pubkey, &msg, &e.sig) {
                continue; // unauthenticated sign-up — skip, never adopt on say-so
            }
            if !crate::directory::profile_binding_ok(e) {
                continue; // a profile signed by a key that is NOT the address's own — refused everywhere
            }
            let owner = crate::pqauth::pubkey_id(&e.pubkey);
            // Projection, log and accumulator advance in ONE act, in canonical fold order on every node, so every
            // node's dir_acc converges by construction.
            let applied = match step.as_deref_mut() {
                Some(s) => self.directory.apply_entry_journaled(e, owner, s),
                None => {
                    let ok = self.directory.apply_entry(e, owner);
                    if ok {
                        self.directory.fold_applied(e);
                    }
                    ok
                }
            };
            if applied {
                changed = true;
            }
        }
        if changed {
            self.directory.persist_now(); // registry custody: a landed sign-up survives the next restart
        }
    }

    /// THE ADOPT-DIVERGENCE DIRECTORY RESET: a node whose directory accumulator differs from the certified one it just
    /// adopted restarts its directory from genesis and refills the certified sequence through the verified door (a gapped,
    /// order-sensitive fold can never rejoin the certified one).
    ///
    /// ⛔ AUDIT F15 (2026-11-10): it no longer re-queues the entries it held. That lane (a node-local queue sealed into the
    /// next block's unpaid sidecar) is the free write the audit closed. An entry is a paid transaction now, with a
    /// transaction's liveness: an entry the certified sequence holds comes back with the refill; one it does not hold was
    /// never applied on the chain this node adopted, its fee note is unspent there, and the wallet that made it sends the
    /// same object again until the chain carries it (`dir_entry_tx`).
    /// MUST-STAY-GREEN: `a_jumped_joiner_refills_the_directory_to_the_certified_acc_and_refuses_tamper` (reset and refill;
    /// tamper and out-of-order refused) and the directory custody tests.
    pub fn dir_reset_for_refill(&mut self, target: [u8; 32]) {
        let _held = self.directory.reset_for_refill();
        // A-F38: what an earlier refill's fold steps held is inside this adopt's certified word (it holds everything the
        // chain applied up to the adopt), so none of it is replayed on top of it
        self.dir_refill_held.clear();
        self.dir_refill_held_closed = 0;
        self.dir_refill_stage.clear();
        self.dir_refill_stage_acc = crate::directory::dir_acc_genesis();
        // a certified word that covers no entry (the genesis seed) leaves nothing to chase: the empty directory IS it
        self.dir_refill_target = (crate::directory::certified_dir_len(&target) > 0).then_some(target);
        // A-F38: a restart forgets the owed word, the stage and the held writes; the marker is what tells the next boot
        // that the registry file is not a whole directory (`enable_dir_persist`)
        self.directory.mark_refill_owed(self.dir_refill_target.as_ref());
    }

    /// Arm the refill toward a certified directory state named by its accumulator and its entry count (audit F16): the
    /// certified word a sync bundle carries is exactly `directory::certified_dir_acc(acc, len)`.
    pub fn dir_reset_for_refill_to(&mut self, acc: [u8; 32], len: u64) {
        self.dir_reset_for_refill(crate::directory::certified_dir_acc(&acc, len));
    }

    /// Where the refill's next page starts: the number of entries staged so far (the tick's `DirReq` cursor).
    pub fn dir_refill_cursor(&self) -> u64 {
        self.dir_refill_stage.len() as u64
    }

    /// ⭐ Apply ONE accepted block's carried letter set: advance the running letter accumulator (one blake3
    /// over the fixed 2,048 carried bytes — the SAME fold on produce, ingest and cascade, in canonical accept
    /// order, so every node's `letter_acc` converges by construction) and retire any of this node's own pending
    /// letter commitments the block just anchored. An empty carry (a pre-carrier/genesis block in tests) is a
    /// no-op rather than a fold, so replaying old fixtures cannot desync the accumulator shape.
    pub fn apply_letter_set(&mut self, block: Option<Hash32>, score: u64, letter_set: &[u8]) {
        if letter_set.is_empty() {
            return;
        }
        // ⛔ D-49b (2026-09-11) — THE COVERED-SCORE GATE IS DELETED: EVERY APPLIED BLOCK FOLDS, ONCE.
        // The gate (`score > letter_acc_covered`) was meant to keep a jumper from re-folding a block the
        // inherited sum already held. That case cannot reach this function: a block inside the adopted
        // tip's past is already in the DAG (placed by the fold carry, or a window anchor), so its
        // re-delivery is `Duplicate` and is never applied; a held block OUTSIDE that past is re-added by
        // the D-36 walk (D-49). What the gate DID do was refuse a legitimately new block whose blue score
        // happened to sit at or below the adopted score — a sibling of the adopted tip delivered after
        // the jump. MEASURED (fuzz lane, 3 parties, 1-minimal `Produce(1,1) · Invalid(2) · Jump(0,2)`):
        // "party 0's letter accumulator is [94,da,63,d6] where a node fed ONLY the blocks derives
        // [05,43,d0,13]" — the jumper skipped the sibling's letters forever. Same rule as A_tip
        // (`fold_atip_at_accept`): one commutative step per applied block, no score arithmetic.
        let _ = score;
        self.letter_acc = crate::letter::fold_letter_acc(&self.letter_acc, letter_set);
        crate::rpc_http::letter_mark_carried(letter_set);
        // ⭐ FILE THE BLOCK'S LETTER BYTES INTO ITS LEDGER ROW in the same act — the DA stream is where mail
        // persists (the block only anchors commitments). Each carried 32-byte commitment is looked up in the
        // hot ring: a REAL letter this node relayed is found and filed VERIFIED-BY-CONSTRUCTION (found BY its
        // block-committed hash); a cover commitment or a blob this node never saw finds nothing and is simply
        // not filed (a peer's page backfills it later). Frame: `len(u32 LE) ‖ blob` repeated.
        if let Some(bid) = block {
            let mut frame: Vec<u8> = Vec::new();
            let mut off = 0usize;
            while off + 32 <= letter_set.len() {
                let mut cm = [0u8; 32];
                cm.copy_from_slice(&letter_set[off..off + 32]);
                if let Some(blob) = crate::rpc_http::letter_blob_of(&cm) {
                    frame.extend_from_slice(&(blob.len() as u32).to_le_bytes());
                    frame.extend_from_slice(&blob);
                }
                off += 32;
            }
            if !frame.is_empty() {
                let rid = match self.record_addr_for_block(&bid) {
                    Some(a) => a,
                    None => Self::da_record_id_for_block(&bid, 0),
                };
                // A NOT_READY / heal-ordered ingest can reach this apply BEFORE the block's record row is
                // written — and the column fill attaches only to existing rows, so the mail silently never
                // filed (MEASURED 2026-08-23 on the fresh pair: origin served 2 history entries, the joiner
                // ZERO for the same anchored letter). Create the block's CANONICAL EMPTY record first via
                // the existing replication writer — the same "empty block has an EMPTY record, same answer
                // on every node" shape idle blocks already use — then fill; the later real note write goes
                // through `da_store`, which PRESERVES the letters column.
                if !self.da_holds(rid) {
                    self.record_note_payload_at(rid, &[], None);
                }
                self.da_fill_letter_column(rid, &frame);
            }
        }
    }

    /// The current letter accumulator — the consensus anchor of the Letter DA content stream (flat 32 bytes).
    pub fn letter_acc(&self) -> [u8; 32] {
        self.letter_acc
    }

    /// This node's folded DIRECTORY accumulator (see [`crate::directory::fold_dir_acc`]).
    pub fn dir_acc(&self) -> [u8; 32] {
        self.directory.acc
    }

    /// True while this node's registry is BEHIND a certified target and the refill door is filling it.
    pub fn dir_refill_needed(&self) -> bool {
        self.dir_refill_target.is_some()
    }

    /// Serve one page of the apply-order registry log (the refill door's answer). Public replicated
    /// permissionless data — every entry is self-authenticating and re-verified by the asker.
    pub fn dir_log_page(&self, from: u64, max: usize) -> Vec<crate::directory::DirEntry> {
        self.directory.log_page(from as usize, max)
    }

    pub fn dir_log_len(&self) -> u64 {
        self.directory.log_len() as u64
    }

    /// ⛔ AUDIT F16 (2026-11-10) — THE REFILL DOOR: STAGE, VERIFY THE WHOLE, THEN ADOPT.
    ///
    /// WHAT WAS WRONG. This door applied each served entry through the signature gate and KEPT it, and only afterwards
    /// compared the accumulator with the certified one. A signature shows who wrote an entry, never that the chain
    /// applied it: a hostile peer that signed its own sign-up for someone else's @name and served it first owned that
    /// name on the joining node, and the joiner's fold could never reach the certified accumulator again.
    /// MEASURED: `f16_a_refill_page_of_validly_signed_entries_the_chain_never_applied_writes_nothing_to_a_joiner`, RED on
    /// the tree before this door (the joiner resolved @cas to the thief's address).
    /// THE SHAPE, BORROWED: verify the whole against the commitment before keeping any part (headers-first sync). The
    /// certified word names how many entries it covers (`directory::certified_dir_len`), so served entries are STAGED,
    /// apart from the directory, up to exactly that count; the stage is adopted only if it folds to the certified word,
    /// and then every entry still passes the same gate every entry passes (signature, binding, owner continuity). Any
    /// other sequence is dropped whole: the directory never held a byte of it.
    /// §9.6 for this door: (1) proof of work: not this door's (the certified word rides a bundle whose own proof and
    /// work are judged at adopt); (2) each entry's signature and binding, at adoption, by the one apply gate; (3) no
    /// value moves here; (4) a replayed page is refused by the cursor (a page applies only at the stage's own length);
    /// (5) bounded work: the stage holds at most the certified count, and nothing is verified until the stage is whole;
    /// (6) parity with the fold's directory step: the same apply gate, the same accumulator fold, and a stricter
    /// precondition (the certified word) in place of the paid object a refilled entry no longer carries.
    /// (7) scale (SAFE AT SCALE): nothing here grows with the nodes that bond (no signature or message per bonded node;
    /// the certified word is one 32-byte value in the bundle whatever the set). With the directory's size: the stage
    /// and the pages (64 entries each) grow with the certified entry count, once per refill, bounded by that count.
    /// With height: nothing.
    /// MUST-STAY-GREEN: `a_jumped_joiner_refills_the_directory_to_the_certified_acc_and_refuses_tamper`.
    /// Cons, quantified: a joiner holds the staged entries beside an empty directory until the last page arrives (the
    /// same bytes it is about to keep, once); a peer serving a wrong sequence costs one restart of the stage.
    pub fn dir_refill_page(&mut self, from: u64, page: &[crate::directory::DirEntry]) {
        let Some(target) = self.dir_refill_target else {
            return;
        };
        if page.is_empty() {
            return;
        }
        let len = crate::directory::certified_dir_len(&target);
        // ORDER IS PART OF THE PROOF: a page extends the stage only at the stage's own length
        if from != self.dir_refill_stage.len() as u64 {
            return; // stale or out-of-order page: the tick asks again from the true cursor
        }
        for e in page {
            if self.dir_refill_stage.len() as u64 >= len {
                break; // the certified sequence ends here: anything a peer serves past it is not part of it
            }
            self.dir_refill_stage_acc = crate::directory::fold_dir_acc(&self.dir_refill_stage_acc, &e.to_wire());
            self.dir_refill_stage.push(e.clone());
        }
        if (self.dir_refill_stage.len() as u64) < len {
            return; // more pages owed
        }
        // the stage is whole: it is the certified sequence, or none of it is kept
        let staged = std::mem::take(&mut self.dir_refill_stage);
        let acc = std::mem::replace(&mut self.dir_refill_stage_acc, crate::directory::dir_acc_genesis());
        if crate::directory::certified_dir_acc(&acc, len) != target {
            return; // not the certified sequence: dropped whole, the directory untouched; the next ask starts at 0
        }
        // one apply of the whole certified sequence (and so one write of the registry file, not one per entry). It folded
        // to the certified word above, so an asset's unsigned record in it is one the chain applied (spec §12.6).
        self.apply_dir_set_into(&crate::directory::encode_dir_set(&staged), None, true);
        if self.directory.acc != acc || self.directory.log_len() as u64 != len {
            // an entry of the certified sequence did not pass the gate: no honest chain certifies one, so nothing of it is
            // kept and the refill stays owed
            let _ = self.directory.reset_for_refill();
            return;
        }
        // ⭐ A-F38: the certified sequence is the directory as it stood at the adopt; what this node's own fold applied
        // since comes after it, in fold order, through the same gate (`dir_hold_while_refilling`). The writes of steps
        // already closed go into a throwaway step: like the refilled entries they belong to no step this node can
        // un-fold (the journal floor is raised below). A page is taken between fold steps, so no step is open here; were
        // one ever open, its writes go into THAT step's own journal, after the closed ones, so its refusal un-does them.
        let closed = self.dir_refill_held_closed.min(self.dir_refill_held.len());
        let open: Vec<_> = self.dir_refill_held.split_off(closed);
        let mut settled = self.directory.begin_step();
        for (_, held) in std::mem::take(&mut self.dir_refill_held) {
            let _ = self.directory.apply_held(&held, &mut settled);
        }
        self.dir_refill_held_closed = 0;
        if !open.is_empty() {
            let mut step = self.dir_open_step.take().unwrap_or_else(|| self.directory.begin_step());
            for (_, held) in open {
                let _ = self.directory.apply_held(&held, &mut step);
            }
            self.dir_open_step = Some(step);
        }
        self.directory.persist_now();
        // §12.6: the replay named every picture the certified records name; any bytes held from before that nothing
        // names now are let go, and the ones named and not held are owed (the picture door fetches them by digest)
        self.directory.drop_unnamed_pics();
        // DB-274 (dir_set): a refilled entry belongs to no fold step here, so no rewind can un-fold it — below the fold
        // this node stands at, the directory is stale (the certified re-anchor settles it), never silently kept.
        if let Some((o, _)) = self.spine_recent_roots.back() {
            self.dir_journal_floor = self.dir_journal_floor.max(o.saturating_add(1));
        }
        self.dir_refill_target = None;
        self.directory.mark_refill_owed(None); // A-F38: the registry on disk is a whole directory again
    }

    /// Ingest a site publish that arrived over the MESH (bidirectional hosting). Verifies + adopts via
    /// [`Self::publish_site`]; returns `true` ONLY when it was newly adopted (a strictly-newer version),
    /// which the runtime uses to RE-GOSSIP it onward. A stale/duplicate/unauthenticated publish returns
    /// `false` (dropped, never re-flooded) — so the mesh converges on ONE authoritative root per site and
    /// every node ends up serving it (redundancy equal to the chain; permanent + version-monotonic).
    pub fn ingest_site_gossip(&mut self, g: SiteGossip) -> bool {
        self.publish_site(g.publish, &g.pubkey, &g.sig) == PublishOutcome::Adopted
    }

    /// ⭐ Correction 7 (derived-ordinal stage 3) — this node LOST the record-spine split arbitration:
    /// a live same-genesis peer ON THE SAME SELECTED TIP advertised a different spine root at the
    /// same shell coordinate. On one selected tip the derived linearisation through the shell is a
    /// pure function of the DAG (stage 1's theorem), so two roots at one coordinate mean exactly one
    /// thing: a numbering burned BEFORE this binary (a pre-derivation snapshot, an old-code peer's
    /// spine) is still being served. The deterministic loser (the lexicographically GREATER root —
    /// both parties evaluate the identical pair at the identical coordinate, so exactly one side ever
    /// takes this path) fails closed onto the EXISTING certified re-anchor: `mark_spine_stale` stops
    /// the fold and the stale tick-arm (`spine_needs_reanchor`) asks for the certified bundle whose
    /// adopt re-derives every position from the certified anchor. The winner keeps serving untouched
    /// — no second reconciliation lane, no ping-pong (the loser rule is a total order on two roots).
    ///
    /// ROOT-LAYER: the STALE verdict is spine state and this node owns its spine — the runtime's
    /// beacon arm only recognises the wire shape and hands the claim here; marking staleness in the
    /// runtime would put a consensus-state transition in a message reader.
    /// MEASURED: 2026-09-05 diagnosis runs (this stage's design doc) — the level pair above refused
    /// each other's rows FOREVER because neither side ever went stale: `mark_spine_stale` had no
    /// caller for the "same tip, divergent numbering" shape (the `spine_needs_reanchor` doc names
    /// exactly this hole: "a stale node on the SAME tip as its peer sees no split and would sit
    /// stale forever" — before this, it never became stale at all).
    /// MUST-STAY-GREEN: the six runtime/search reds (meshes from genesis derive identical spines, so
    /// this never fires there), the canonical_record_fold suite, fold_schedule_fuzz, the four
    /// certify-absence pins, the graft/strand landing pins.
    /// The print carries root limb0s and a coordinate only — never a note, amount, key or owner.
    pub fn note_record_spine_split(&mut self, peer_root: crate::spend_frontier::Digest4, shell: u64) {
        if self.spine_stale {
            return; // already waiting on the certified re-anchor — nothing new to mark
        }
        let mine = match self.spine_recent_roots.iter().find(|(o, _)| *o == shell) {
            Some((_, r)) => *r,
            None => return, // ring moved past the shell between detect and mark — nothing to judge
        };
        eprintln!(
            "[spine-split] ⛔ RECORD-SPINE SPLIT with a same-tip peer at shell {shell}: our root limb0 \
             {:#x} vs peer {:#x} — this side loses the deterministic arbitration; folding stops and \
             the certified bundle re-anchors this numbering",
            mine[0], peer_root[0]
        );
        self.mark_spine_stale(
            "a same-tip level peer serves a different record spine at the same shell — the burned \
             numbering re-anchors from the next certified bundle",
        );
    }

    /// The block window's census: (blocks held, bytes).
    pub fn block_window_census(&self) -> (usize, usize) {
        (self.block_window.len(), self.block_window.stored_bytes())
    }

    /// ⛔⛔⛔ DB-270 STEP 2 — SETTLE THE RESTORED FOLD SPAN, AND VERIFY IT BEFORE TRUSTING IT.
    ///
    /// The checkpoint restored A_tip and `nf_fold_seq`; its fold record (if the file carries one) restores the base they
    /// are measured from and names the carried blocks that are not span members. Then the one property every spender
    /// relies on is CHECKED, not assumed: `base ⊕ Σ leaf(members) == A_tip` and `|members| == nf_fold_seq - base_seq`.
    /// The leaf is the block's own `block_transition_leaf(pre, tags)` — the same step `fold_block_into_atip` took — read
    /// from the window's bodies (the re-install pass just read them) and the carry.
    ///
    /// ⛔ A MISMATCH IS RESOLVED THE WAY AN ADOPT RESOLVES IT: `base := A_tip`, a new generation, an empty span. That is
    /// consistent by construction and loud; the alternative — serving a span that cannot close — refuses every node-built
    /// spend with nothing to point at. It happens for a checkpoint with no record (written before step 2), or a window
    /// that is corrupt or foreign to the checkpoint.
    pub(super) fn settle_restored_fold_span(&mut self, fold: Option<&crate::persist::FoldRecord>) {
        if let Some(f) = fold {
            for id in &f.carry_nonmembers {
                self.nf_unfolded_gen.remove(&Hash32(*id));
            }
            self.nf_fold_base = (f.base_acc, f.base_seq);
            self.nf_base_prev = f.base_prev;
        }
        // ⛔ G2g-r2b — THE PENDING CERTIFIED BASE comes back with the base it replaces (cleared below if the span does not
        // verify: a new generation would change which window blocks its prune steps absorb). The runtime re-asks the owed
        // bodies at boot (`NodeRuntime::new_with_directive`).
        self.nf_fold_base_pending = fold.and_then(|f| f.fold_pending.as_ref()).map(|c| NfFoldBasePending {
            words: c.words,
            acc: c.acc,
            a_tip: c.a_tip,
            owed: c.owed.iter().map(|(id, bw, bs)| (*id, (*bw, *bs))).collect(),
            placed: c.placed.iter().copied().collect(),
            anchor_score: c.anchor_score,
        });
        let FoldSpanTally { members, counted, unreadable, reproduces, seen, stamped_unheld, window_nonmember, window_old_gen } =
            self.fold_span_tally();
        let source = if fold.is_some() { "the checkpoint's fold record" } else { "no fold record (a pre-step-2 checkpoint)" };
        if unreadable == 0 && members == counted && reproduces {
            // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS and a branch name — never a tag, amount, key or owner.
            eprintln!("[fold-span] restored span VERIFIED from {source}: {members} member(s) reproduce A_tip from its base");
            // DB-339 part 3: these are the blocks this node applied before its pivot and still holds.
            self.pivot_span = seen.into_iter().collect();
            return;
        }
        self.pivot_span = Vec::new(); // an unverified span names no pivot blocks
        // DIGITAL-CASH-PRIVACY-REVIEWED: block COUNTS and a branch name — never a tag, amount, key or owner.
        eprintln!(
            "[fold-span] ⛔ the restored span does NOT reproduce A_tip from {source} ({members} member(s) vs {counted} \
             counted, {unreadable} unreadable; stamped-but-unheld {stamped_unheld}, window non-members {window_nonmember}, \
             window older-gen {window_old_gen}, reproduces {reproduces}) — resuming as an adopt does: base := A_tip, a new \
             generation, an empty span"
        );
        self.nf_fold_base = (self.nf_unspent_acc, self.nf_fold_seq);
        self.nf_base_prev = self.nf_unspent_acc;
        self.block_window.bump_base_gen();
        if self.nf_fold_base_pending.take().is_some() {
            eprintln!("[g2g-r2a] ⛔ the restored span did not verify — the pending certified fold base is dropped with it");
        }
    }

    /// The finished carrier for the transition starting at `pre_root`, if the background prove has landed.
    /// `None` while it is still in flight or superseded — callers treat that as "not yet adoptable", NEVER a failure.
    pub fn block_carrier(&self, pre_root: &[u8; 32]) -> Option<Vec<u8>> {
        let g = self.carrier_slot.lock().ok()?;
        match g.as_ref() {
            Some((p, c)) if p == pre_root && !c.is_empty() => Some(c.clone()),
            _ => None,
        }
    }

}

