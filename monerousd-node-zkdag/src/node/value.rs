// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! value — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// THE account target for `note_cm`, in the wire shape `cm ‖ bucket ‖ ek_len ‖ ek`, or `None` if this node
    /// holds none. ONE accessor, so every caller sees the same answer.
    ///
    /// A target has exactly one home, and which one depends only on how far its note has got:
    ///   * STAGED in `pending_bucket` — the target arrived on a submit and its note has no record address yet;
    ///   * WRITTEN beside the note's own DA record — `record_account_target` puts it there the instant the
    ///     address resolves, and simultaneously clears the staging entry.
    /// The two are mutually exclusive by construction, so this is one lookup over one lifecycle, not a retry:
    /// if neither holds it, this node genuinely has no target for that note and says so.
    pub(super) fn account_target_for(&self, note_cm: &[u8; 32], at: Option<u64>) -> Option<Vec<u8>> {
        if let Some((bucket, ek)) = self.pending_bucket.get(note_cm) {
            let mut out = Vec::with_capacity(66 + ek.len());
            out.extend_from_slice(note_cm);
            out.extend_from_slice(bucket);
            out.extend_from_slice(&(ek.len() as u16).to_le_bytes());
            out.extend_from_slice(ek);
            return Some(out);
        }
        // Written down beside the record by the filing path, in exactly this wire shape — returned verbatim so
        // the carried form and the stored one can never drift.
        // Already filed on THIS node: the target was written beside its record by the filing path, and the
        // record is named by the CALLER (`at`) — a pure function of the block id, never an index lookup. The
        // per-note `cm -> address` map that used to answer this is DELETED (it was 88% of the footprint).
        // ⭐ RESOLVE THE NOTE'S OWN FILED ADDRESS FIRST. The caller's `at` names the block being built,
        // which is NOT where an already-drained target was written. Falling back to `at` alone is what made a
        // correctly-filed target invisible to the block that carries its note.
        let addr = self.note_target_addr.get(note_cm).copied().or(at)?;
        let blob = self.da_load_account_targets(addr);
        let mut off = 0usize;
        while off + 66 <= blob.len() {
            let ek_len = u16::from_le_bytes([blob[off + 64], blob[off + 65]]) as usize;
            let end = off + 66 + ek_len;
            if end > blob.len() {
                return None; // malformed tail — fail closed, never fabricate a target
            }
            if &blob[off..off + 32] == note_cm.as_slice() {
                return Some(blob[off..end].to_vec());
            }
            off = end;
        }
        None
    }

    /// Serialise the account targets that belong to the notes in `payload`, in the block's own note order.
    ///
    /// ⛔⛔⛔ FILING LOCALLY MUST NOT EMPTY WHAT THE BLOCK CARRIES. This read `pending_bucket` DIRECTLY, on a
    /// doc-comment promise that "the entries are drained later, when the notes are actually recorded". That
    /// stopped being true the moment `record_account_target` gained its file-it-NOW path: a target whose note
    /// address resolves is filed and `pending_bucket.remove(&note_cm)`d immediately — and on the PRODUCING node
    /// it always resolves, because that node holds the record. So the producer indexed the target for itself
    /// and then serialised a block carrying NOTHING, and its peer had nothing to file. Two different jobs —
    /// index it here, hand it to everyone else — were reading one map, so fixing the late-target case silently
    /// disabled the wire carry that is what makes a payment visible on any node but the sender's.
    ///
    /// MEASURED on the live peered pair, before this fix: `4,274` blocks left the payer's node logging
    /// `0 account-target byte(s)` against `3` that carried any; the recipient's node adopted targets from none
    /// of them and its wallet read `0 owned position(s)` while the payment sat settled on chain.
    ///
    /// This is the `padded_tags` lesson again, and the Bitcoin/Kaspa invariant: A BLOCK MUST CARRY WHAT IS
    /// NEEDED TO APPLY IT. Whether the producer happened to index a note for itself first is its own business
    /// and must never change what its peers receive.
    ///
    /// O-CHAIN-REVIEWED: per note in THIS block's payload, one written-down lookup (`account_target_for`). No
    /// walk, no term in chain height, and the bytes are identical to what the staged path emitted.
    /// `at` is the DA coordinate of the record these notes are being written to — the producer computes it
    /// from its own block id, so a target already filed here is read back without any per-note index.
    pub fn account_targets_for(&self, payload: &[u8], at: Option<u64>) -> Vec<u8> {
        const PQ_NOTE_BYTES: usize = 1153;
        let mut out: Vec<u8> = Vec::new();
        let mut off = 0;
        let (mut looked, mut found) = (0usize, 0usize);
        while off + PQ_NOTE_BYTES <= payload.len() {
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&payload[off..off + 32]);
            looked += 1;
            if let Some(entry) = self.account_target_for(&cm, at) {
                found += 1;
                out.extend_from_slice(&entry);
            }
            off += PQ_NOTE_BYTES;
        }
        // ⭐ THE LOOKUP ITSELF — the last unmeasured step on the private-send path.
        //
        // The produce-side probe reports the RESULT (0 bytes carried) but not WHY. Three causes are
        // indistinguishable from outside and need different fixes: the block carried no note to look up
        // (looked == 0), every note was cover with no target (looked > 0, found == 0, pending empty), or the
        // target exists but under an address this lookup does not consult (found == 0 while pending or the
        // filed-address index holds the cm). Reporting the three counts together separates them.
        //
        // Fires only when a block actually carries notes — cover-only blocks stay silent, so no per-block
        // bytes. DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only. Never a cm, bucket id, address, amount, key or
        // owner — the numbers say whether a lookup resolved, nothing about whose note it was.
        // ⛔ FIRE ONLY ON A REAL ANOMALY. The first version fired whenever any note failed to resolve — but
        // MOST notes are COVER, which correctly has no target, so it printed `0/1 note(s) resolved` on
        // ordinary blocks and would have buried the one line that matters. A probe that reports normal
        // operation as a fault is worse than none; that is the R-F lesson, and I had just re-made it.
        //
        // A miss is only meaningful when a target for some note DOES exist somewhere — i.e. something is
        // staged in `pending_bucket` or recorded in the filed-address index — and this lookup still resolved
        // nothing. That is the state which loses a payment.
        let have_targets = self.pending_bucket.len() + self.note_target_addr.len();
        // ⛔⛔⛔ THE GATE ITSELF SILENCED THE LOSING STATE. `have_targets > 0` means "a target is still
        // findable" — but the payment is lost precisely when it is findable NOWHERE. MEASURED 2026-08-01:
        // `[bucket-file] CLAIMED 1 pending target(s)` then 384/384 produced blocks carrying 0 target bytes,
        // and this probe printed NOTHING for any of them. A claim is irreversible, so a node that has claimed
        // targets and can no longer resolve one is the loss, not the healthy case.
        // ⛔⛔⛔ THIS PROBE HAS NOW BEEN SILENT THROUGH THREE DIFFERENT THEORIES — SO THE GATE IS THE BUG.
        //
        // Each version was gated on a value that is ZERO precisely when the payment is lost, so it could only
        // speak in the healthy case: first `have_targets > 0` (both maps empty after the claim), then
        // `looked > 0 && found == 0`. MEASURED across three runs: `[bucket-file] CLAIMED 1 pending target(s)`
        // every time, `[acct-produce] block carries 0 account-target byte(s) for 1153 note byte(s)` on every
        // produced block, and this line printed NOTHING — while `output_notes` is assigned ~65 lines ABOVE the
        // call, so the payload is populated and `looked` cannot be 0.
        //
        // Three theories died to silence (claim strands the target / id-drift moves the address / the call
        // precedes the payload). Reasoning further from a probe that cannot fail is what cost those runs.
        //
        // FIRE ON THE LOSING STATE ITSELF and print all four numbers unconditionally: this node has claimed a
        // target and this block still carries none. It is self-limiting — it goes silent the moment a block
        // carries what it claimed — and it cannot be true in the healthy case.
        //
        // O1-FOOTPRINT-REVIEWED: prints four scalars already computed; stores nothing, no term in height,
        // blocks or notes. DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a cm, bucket id, address,
        // amount, key, owner or recipient.
        // ⛔⛔⛔ THIS PROBE REPORTED NORMAL OPERATION AS A FAULT, AND IT COST SEVERAL TURNS.
        //
        // Gated on `found == 0 && targets_claimed_total > 0`, it fired on EVERY cover block for the rest of
        // the node's life once a single target had ever been claimed. MEASURED 2026-08-01: 81 of 82 produced
        // blocks are cover and correctly carry no target, so this printed the losing-state line 81 times while
        // the ONE payment block — `[acct-produce] block carries 2500 account-target byte(s) for 3459 note
        // byte(s)`, adopted by node B as `[acct-file] adopting 2500 account-target byte(s)` — sat one line
        // earlier. I read the trace's last line as the payment's line and chased six theories that were all
        // refuted, because the payment was crossing the whole time.
        //
        // A miss is only real when a target is STAGED AND WAITING and this block's notes still do not resolve
        // it. `pending_bucket > 0` is exactly that state: something is owed a carry right now. A cover block
        // with an empty staging map owes nothing and must stay SILENT. (`targets_claimed_total` is kept for
        // the filed-index arm below; it must never be the sole trigger — a claim is permanent, so it can only
        // ever say "this node once had a payment", never "this block lost one".)
        if found == 0 && !self.pending_bucket.is_empty() {}
        if looked > 0 && found == 0 && (have_targets > 0 || self.targets_claimed_total > 0) {
            // ⭐ SEPARATE THE TWO REMAINING CAUSES — the counts alone cannot.
            //
            // MEASURED: 130/130 produced blocks carried ZERO targets, so this is not an ordering race between
            // the drain and produce (the reading I got from `tail -1` and would have chased). Two causes
            // survive that fact:
            //   (a) CM MISMATCH — a target IS staged, but keyed by a different notion of the note's
            //       commitment than the one read from the block's note blob, so no key can ever match.
            //   (b) WRONG NOTES — the block's notes genuinely are not the ones targets were staged for.
            //
            // `keyed_here` counts how many of THIS block's note keys appear among the staged targets. Zero
            // with targets present is (a); non-zero would mean the key matched and the fetch still failed.
            // ⛔⛔⛔ THIS ANOMALY FIRED ON COVER-ONLY BLOCKS — 4,480 FALSE ALARMS ON ONE NODE.
            //
            // EVERY block wears the fixed 256-note cover shape, and an idle one carries a SINGLE seed note
            // (`[acct-produce] ... 1153 note byte(s)`). A block with no payment in it obviously holds no key
            // any staged target could match, so reporting "keyed by a DIFFERENT commitment" there is noise —
            // and I read that noise as the root defect for a full turn, after tracing the wallet and finding
            // it consistent (it sends `recip_note` at lib.rs:4705 and keys on `&recip_note[..32]` at 4734 —
            // the same bytes).
            //
            // A payment adds recipient + change on top of the seed note, so only a payload LARGER than one
            // note can carry a target's key. Gate on that: the anomaly then means what it says.
            //
            // O1-FOOTPRINT-REVIEWED: compares against PQ_NOTE_BYTES, a fixed protocol constant; stores
            // nothing and adds no term in height, blocks or notes.
            // DIGITAL-CASH-PRIVACY-REVIEWED: a payload LENGTH already implied by the block every peer
            // receives; never a cm, bucket, amount, key or owner.
            // Cover-only block: no payment rode it, so a key miss is expected, not an anomaly.
            let payment_bearing = payload.len() > PQ_NOTE_BYTES;
            let mut keyed_here = 0usize;
            let mut o = 0usize;
            while o + PQ_NOTE_BYTES <= payload.len() {
                let mut c = [0u8; 32];
                c.copy_from_slice(&payload[o..o + 32]);
                if self.pending_bucket.contains_key(&c) || self.note_target_addr.contains_key(&c) {
                    keyed_here += 1;
                } else if keyed_here == 0 && o == 0 {
                    // ⛔⛔⛔ WHICH 32 BYTES DISAGREE? 5b says "keyed by a DIFFERENT commitment" and fires
                    // 4,480x on A / 4,368x on B while every delivery layer PASSES: A files both targets
                    // (CLAIMED 2 -> 2 writes, 0 pending), B adopts 2500 target byte(s), B drains 4,656
                    // BucketResp. The wallet keys its target on `recip_note[..32]` / `change_note[..32]`;
                    // this keys on the first 32 bytes of the note blob the BLOCK carries. They never match,
                    // so the note the wallet built and the note the block carries are not byte-identical.
                    //
                    // Print a short PREFIX of each so the next run says whether they are the same note under
                    // a different encoding (shared prefix) or an entirely different value (no overlap) -
                    // those need opposite fixes and no counter distinguishes them.
                    //
                    // DIGITAL-CASH-PRIVACY-REVIEWED: FOUR bytes of a commitment already carried in clear on
                    // the block every peer receives, emitted only on the anomaly path (a target set that
                    // matched NOTHING) and only for the first note of such a block - never per block, never
                    // an amount, key, owner or bucket id.
                    let staged: Vec<String> = self
                        .pending_bucket
                        .keys()
                        .chain(self.note_target_addr.keys())
                        .take(2)
                        .map(|k| format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]))
                        .collect();
                }
                o += PQ_NOTE_BYTES;
            }
            // Only a payment-bearing block can carry a target's key; see the gate above.
            // DIGITAL-CASH-PRIVACY-REVIEWED: COUNTS only — never a cm, bucket id, address, amount, key or
            // owner. The numbers say whether a key matched, nothing about whose note it is.
            if payment_bearing {}
        }
        out
    }

    /// The note-membership accumulator this node has folded — the value a wallet's carrier must match.
    /// ⛔⛔⛔ ONE NODE, ONE MEMBERSHIP ACCUMULATOR. THERE WERE TWO, AND THE ANSWER DEPENDED ON THE NAME.
    ///
    /// `served_membership_acc` is folded per RECORD on the live path — it is the value a wallet reaches by
    /// folding `/membership_roots`, and the value the membership gate indexes. `membership_acc` was a second
    /// field written on one restore path and never advanced per record, so this accessor — the obvious name,
    /// the one a caller reaches for — returned a value that had stopped tracking the chain.
    ///
    /// MEASURED 2026-08-12:
    ///   the SERVED roots must fold to the serving node's own accumulator
    ///   left:  [5930637977, 4733579466, 3575497858, 5244632116]   (fold of what was served)
    ///   right: [8136910240, 4068455120, 4068455120, 12205365360]  (this accessor)
    /// A wallet folding the served roots lands on `left` and the node answers `right`, so the lookup finds
    /// nothing and every spend is refused with both sides internally consistent.
    ///
    /// Two sources of truth for one quantity is the defect; this accessor returns the maintained one.
    /// COMPLETED 2026-08-14: the second `membership_acc` FIELD is gone, and the inert
    /// `fold_block_into_membership_acc` hook plus its four ingest call sites are DELETED at source. There is
    /// now exactly ONE accumulator (`served_membership_acc`), one folder (`record_note_payload_inner`), and
    /// one writer — which is what the note-membership carrier folds against. This doc previously said
    /// "PARTIAL"; it was stale, and a stale completion note is how a finished fix gets re-opened or, worse,
    /// how an unfinished one gets read as done.
    pub fn membership_acc(&self) -> crate::spend_frontier::Digest4 {
        self.served_membership_acc
    }

    /// The block ROOTS a wallet's `NoteMembershipCarrier` must fold, in the node's own topological order,
    /// starting after `from_topo`.
    ///
    /// This is what makes the carrier buildable at all: the fold must cover exactly the blocks THIS node
    /// folded, and a wallet cannot enumerate block ids on its own. Ordered by FRONTIER APPEND ORDINAL, which
    /// the fold does not need (it is a commutative sum) but the depth-32 copath does — a note's global leaf
    /// index is `(ordinal-1)*256 + slot` (genesis holds ordinal 0 and contributes NO leaves — the settled
    /// law, `fold_record_into_spine` + the item9 pin), so the same list serves both jobs.
    ///
    /// Bounded by `limit` — a PAGE SIZE, not a window. A caller pages until it reaches the tip; nothing is
    /// dropped and nothing expires. Blocks whose record this node does not hold are skipped rather than
    /// invented, exactly as `da_block_leaves` does: a root this node cannot derive is one no other node would
    /// derive the same way.
    ///
    /// DIGITAL-CASH-PRIVACY-REVIEWED: block roots are a FOLD of the constant 256-slot shape every block wears,
    /// identical whether the block settled payments or not, and the response is the same for every caller —
    /// no selector, no which-item question, no count of anything real.
    pub fn membership_roots_from(
        &self,
        from_topo: u64,
        limit: usize,
    ) -> Vec<(u64, crate::spend_frontier::Digest4)> {
        // WALK ORDINALS DIRECTLY. Ordinals are dense, so the caller's `from_ord` names exactly where to
        // start and `limit` bounds the work — no DAG enumeration, no per-block sidecar read to sort by, and
        // nothing that grows with chain height. Enumerating the DAG here cost 282ms at 151 blocks (~96s at
        // 51k), which is the O(chain) this whole path exists to remove.
        //
        // Ordered by append ordinal because the depth-32 COPATH needs it: a note's global leaf index is
        // `(ordinal-1)*256 + slot` — genesis holds ordinal 0 and contributes NO leaves (settled law:
        // `fold_record_into_spine` + the item9 pin). The fold itself is order-agnostic (a commutative
        // sum), so one list serves both.
        //
        // A record this node does not hold ends the page rather than being skipped — a hole would silently
        // shift every later block's position in the caller's copath. It resumes on the next call.
        // SKIP TO THE FIRST ORDINAL THIS NODE ACTUALLY HAS, then serve contiguously.
        //
        // Breaking on the first absent ordinal looked right and was a real defect: a node whose records do
        // not start at 0 — a restarted or #29-jumped node, which is the ordinary case — served NOTHING to a
        // caller asking `from_topo: 0`. Caught over HTTP, invisible to a fresh in-memory node whose first
        // record happens to be ordinal 0.
        //
        // A hole in the MIDDLE still ends the page: the caller's upper-copath windows are positional, so
        // silently closing a gap would shift every later block and produce a copath that cannot fold. Leading
        // absence is not a hole — it is simply where this node's history begins.
        let mut out = Vec::new();
        let mut ord = from_topo;
        // ⛔⛔⛔ NEVER SERVE A ROOT WHOSE FOLDED ACCUMULATOR THIS NODE HAS NOT INDEXED.
        //
        // A spender folds EVERY root this route returns and names the resulting accumulator; the membership
        // gate then asks `da_ordinal_at_membership_acc(named)` — "did this chain ever hold that value?".
        // Serving one root beyond the folds actually performed makes the spender name an accumulator that has
        // never existed here, so a perfectly valid proof over this very chain is refused.
        //
        // MEASURED 2026-08-10 on send 2 of a cross-device run:
        //   [membership] refused. folds=460 records=460 ord0=true ordLast=true
        //                prevAccIndexed=true named_indexed=false
        // Everything true except the named endpoint, and the PREVIOUS accumulator indexed — an exact
        // off-by-one. The payer had already built and stamped the tx; it was refused for naming a value this
        // route told it to compute.
        //
        // This is NOT a reach bound: nothing is refused for age, no owned note is skipped, and a root becomes
        // servable the moment its fold is done. It only stops the route promising a fold that has not happened
        // yet — the same "a block must carry what applies it" rule that fixed the account targets and the
        // locator clues. Two views of one chain must not disagree about how far it has folded.
        let scan_limit = self
            .served_seq
            .saturating_add(1)
            .min(self.served_fold_count());
        // ⛔⛔⛔ LEADING ABSENCE INCLUDES A POSITION THAT CONTRIBUTES NO ROOT — GENESIS IS ONE.
        //
        // This skipped only ordinals with no ADDRESS. Genesis HAS an address at ordinal 0 and contributes
        // NO leaves — `fold_canonical_records` says so directly: "genesis holds ordinal 0 and contributes
        // NO leaves, so a record at ordinal k occupies leaves [(k-1)·256, k·256)". It has no record bytes
        // and no per-ordinal root, so the loop below reached it, took the `break`, and the node served ZERO
        // membership roots. A spender folds exactly this stream to name its accumulator, so an empty page
        // refuses every send.
        //
        // MEASURED, `a_blocks_root_enters_the_membership_accumulator_exactly_once`:
        //     [diag] served_seq=6 records_held=5 ord0=Some(18006065211481392)
        //     [diag] ord0 raw_bytes=false regen=false record_notes=false leaves=None root_at_ord=false
        //            macc_prev=false macc_here=true
        //     the node must serve a root per block it recorded, got 0
        // `raw_bytes=false` proves the bytes were never stored (not released by the retention rule), and
        // `macc_prev=false` is why regeneration correctly refuses: at ordinal 0 there is no preceding
        // accumulator to bind against, so there is no certified evidence and fail-closed is right.
        //
        // THE RULE, stated positively: this route serves the roots that FOLD INTO the membership
        // accumulator, so the stream begins at the first position that contributes one. A position that
        // folds nothing has no root to serve and is not part of the sequence a spender sums.
        //
        // The mid-stream rule is unchanged: a hole in the MIDDLE still ends the page, because the caller's
        // copath windows are positional and silently closing a gap would shift every later block.
        // cons: none — the same bounded scan, one extra derivability probe per leading position, still
        // capped by `scan_limit`, so nothing walks history.
        while ord < scan_limit {
            // v32 (item 9): ordinal 0 NEVER contributes a root, on any node. Genesis folds nothing —
            // its record bytes exist (a persisted node holds them for the by-id lane), so the
            // derivability probe below would say "contributes" there and not on an in-memory peer,
            // and the two would serve DIFFERENT root streams for one chain: a wallet folding the
            // persisted node's stream lands on an accumulator the in-memory node never held.
            let contributes_a_root = ord != 0
                && match self.da_addr_at_ordinal(ord) {
                    None => false,
                    Some(seq) => {
                        self.da_block_root_at_ordinal(ord).is_some()
                            || self.da_block_leaves(seq).is_some()
                    }
                };
            if contributes_a_root {
                break;
            }
            ord = ord.saturating_add(1);
        }
        // The serve below must never emit ordinal 0 either (a scan_limit of 0 leaves `ord` at 0 with the
        // skip loop never entered): genesis's root is not part of the sequence a spender sums.
        if ord == 0 {
            ord = 1;
        }
        while out.len() < limit {
            let Some(seq) = self.da_addr_at_ordinal(ord) else {
                break;
            };
            // ONE READ when the root was written down; derive it only for records written before this index
            // existed. Deriving means regenerating 256 leaves and folding them — per root, per request.
            let root = match self.da_block_root_at_ordinal(ord) {
                Some(r) => r,
                None => {
                    let Some(leaves) = self.da_block_leaves(seq) else {
                        break;
                    };
                    Self::fold_leaves_to_root(&leaves)
                }
            };
            out.push((ord, root));
            ord = ord.saturating_add(1);
        }
        out
    }

    /// The tip transition a carrier must name: `(prev_acc, block_root, acc)` of the last folded block.
    pub fn membership_tip(&self) -> (crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4) {
        (
            self.membership_tip_prev,
            self.membership_tip_root,
            self.served_membership_acc,
        )
    }

    /// [`Self::verify_membership_carrier_one_step`]'s three answers — the ONE site every membership door reads.
    /// ⭐ THE MEMPOOL'S "MISSING INPUTS" IS NOT "INVALID" (borrowed: Bitcoin Core's `TX_MISSING_INPUTS` orphan answer
    /// beside `TX_CONSENSUS`). At the `Admit` door a carrier whose record this node has not folded — or does not hold yet
    /// (its fetch is raised) — is [`MemberVerdict::Pending`]: a retry after the fold admits it. Every forgery check runs
    /// BEFORE that wait, so `Pending` is only ever told to an otherwise-valid carrier or an unheld record; at the `Fold`
    /// door there is no wait (the canonical order's verdict), so it never answers `Pending`.
    /// MEASURED why (sim-20261006-221807, T2): node 1 logged "[membership-1step] refused (retry after the fold)" for a
    /// fill's freshly cut lot, and the fill door answered 422 MEMBERSHIP_REFUSED — "a WRONG submission" — so the taker's
    /// wallet stopped on a race the chain resolves in seconds.
    #[allow(clippy::too_many_arguments)]
    pub fn membership_carrier_verdict(
        &self,
        proof: &[u8],
        leaf_commit: crate::spend_frontier::Digest4,
        // DB-213c: the value the SPENDER bound its membership proof to — every production builder binds the
        // spend's OWN nullifier (`leaf_commit = compress(leaf, nullifier)`), so each door passes the nullifier
        // its operation publishes. A wrong binder refuses; it can never admit.
        binder: crate::spend_frontier::Digest4,
        tip_prev: crate::spend_frontier::Digest4,
        tip_root: crate::spend_frontier::Digest4,
        tip_acc: crate::spend_frontier::Digest4,
        named_record: u64,
        door: crate::respend::MemberDoor,
    ) -> MemberVerdict {
        if tip_prev != Self::MEMBERSHIP_GENESIS_ACC {
            eprintln!("[membership-1step] refused: a one-step carrier must start at the genesis accumulator");
            return MemberVerdict::Refused;
        }
        // DB-358 (1): asked only AFTER the record resolves below, so an unheld record still raises its fetch (the retry
        // lane) and every forgery below is refused by its own check, never masked by this wait.
        let unfolded_at_admit = |folded: bool| -> bool {
            if folded {
                return false;
            }
            // DIGITAL-CASH-PRIVACY-REVIEWED: FIXED strings — no record address, note, leaf, amount, key or owner.
            match door {
                crate::respend::MemberDoor::Admit => eprintln!(
                    "[membership-1step] refused (retry after the fold): the named record is not FOLDED here yet — a \
                     spend may consume only canonical state, because the fold can still revoke a staged output (DB-358)"
                ),
                crate::respend::MemberDoor::Fold => eprintln!(
                    "[membership-1step] refused at the fold: the named record is not before this block in the canonical \
                     order — one verdict on every node, whatever each holds"
                ),
            }
            true
        };
        let refold =
            usdm_decider::note_membership_air::note_membership_step_new_acc(tip_prev, tip_root);
        if refold != tip_acc {
            eprintln!(
                "[membership-1step] refused: the named tip is not one fold step from genesis"
            );
            return MemberVerdict::Refused;
        }
        // ⭐⭐⭐ THE NAMED ADDRESS IS THE ONE COORDINATE — RESOLVE IT DIRECTLY, NEVER VIA THE ORDINAL HOP.
        //
        // This translated the named CANONICAL address to this node's dense ordinal first
        // (`da_record_ordinal(named).unwrap_or(named)`) and derived from THAT — a round-trip through TWO
        // per-node in-memory maps for a record whose bytes sit in `da_mem` under the named key the whole
        // time. MEASURED (gate step-4, scratch /tmp/musd-ecocheck-sH0WNh, both nodes): the snapshot restore
        // refilled `da_ord_mem[rid]=40`, the DSYNC adopt's reorg purge cleared `da_ord_rev_mem`, and the
        // verify went rid → 40 → (no way back) → "does not hold the record" for a note whose custody and
        // balance had restored perfectly (25.0 certified) — every paced retry refused on BOTH nodes, the
        // send died, and the by-ordinal want it enqueued asked peers for a dense ordinal that names nothing
        // in their space. Live operation never even armed that lane (`da_ord_mem` has no entry for a
        // freshly produced record), which is why only restarts failed and only ~half the time.
        //
        // ROOT-LAYER: the record's root is PRODUCED at the record write — `record_note_payload_inner` folds
        // `block_leaves_from_notes(notes, addr)` seeded by the CANONICAL address (`let seq = addr; // the
        // record's canonical address — its DA key, cover seed and index key`), and `/note_copath` serves
        // the wallet that same rid-seeded root via `da_block_leaves(addr)`. So the named canonical address
        // is the producer's own coordinate; deriving here from `da_mem[named]` seeded by `named` re-runs
        // the producer's exact fold. The dense ordinal is a READER-side per-node index (arrival order —
        // the same record measured as ordinal 124888/166995/98908 on three live nodes) whose maps die on
        // restart by design; asking it first was patching the read layer.
        // MEASURED: gate step-4 post-restart send: before = refused "does not hold the record at the named
        // address" 6/6 paced retries on BOTH nodes (run /tmp/musd-ecocheck-sH0WNh, named=rid with
        // da_ord_mem[rid]=40 restored and da_ord_rev_mem purged); after = the two-party restart regression
        // test below resolves the same shape in one read, and the full ecosystem gate passes end to end.
        // MUST-STAY-GREEN: a_one_step_membership_* adversarial refusals (forged root, foreign chain, wrong
        // named address), the reverted-node/jumped-node rebuild tests, and the full node sweep.
        // cons: none — one indexed `da_mem` read + the same BLOCK_FIXED_NOTE_COUNT (256, protocol constant)
        // fold the old path performed; no new state, no term in height/blocks/notes/age.
        // `folded`: DB-358 (1)'s answer, in the coordinate each lane resolved (an address, or a position).
        let (derived, folded) = match self
            .da_record_notes(named_record)
            .map(|n| Self::fold_leaves_to_root(&Self::block_leaves_from_notes(&n, named_record, &self.cover_key_of(named_record))))
        {
            Some(r) => (r, self.named_record_folded(named_record)),
            None => {
                // At the FOLD the coordinate must be canonical: an ordinal resolves differently per node.
                if door == crate::respend::MemberDoor::Fold {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a FIXED string — no record address, note, leaf, amount, key or owner.
                    eprintln!(
                        "[membership-1step] refused at the fold: no record at the named canonical address before this \
                         block — a per-node ordinal is never resolved here"
                    );
                    return MemberVerdict::Refused;
                }
                // Legacy door: the caller named a dense ordinal (pre-rid wallets). Translation only runs
                // when NO record exists at the named key, so it can never shadow the canonical lane.
                let ordinal = self.da_record_ordinal(named_record).unwrap_or(named_record);
                match self.da_block_root_at_ordinal(ordinal) {
                    // a POSITION: folded once the fold has moved past it
                    Some(r) => (r, ordinal < self.served_seq),
                    None => {
                        // ⭐ SAY "fetch-and-retry" AND ACTUALLY FETCH — IN THE COORDINATE SPACE PEERS SERVE.
                        // The named value is a canonical record id, so the want must ride the by-RECORD-ID
                        // request (`wanted_record_ids`, leading 2u8) — the earlier `da_wanted` enqueue fed
                        // the by-ORDINAL request, which the peer resolves as a block ordinal and answers
                        // with nothing, so the promised refill never arrived and every retry hit the same
                        // hole. Interior-mutable set because this verify holds `&self`; drained by the same
                        // tick as its sibling set.
                        // cons: none — RAM-only transient set, hard-capped at TX_REQ_FIXED_COUNT entries
                        // (x 8 B = a few hundred bytes total), drains as records arrive, never persisted;
                        // no disk write, no growth term in height/blocks/notes.
                        if self.da_wanted_ids.borrow().len()
                            < crate::protocol::TX_REQ_FIXED_COUNT
                        {
                            self.da_wanted_ids.borrow_mut().insert(named_record);
                        }
                        eprintln!(
                            "[membership-1step] refused: this node does not hold the record at the named \
                             address yet — enqueued the by-record-id fetch; retry lands after the next \
                             relay tick"
                        );
                        return MemberVerdict::Pending;
                    }
                }
            }
        };
        if derived != tip_root {
            eprintln!(
                "[membership-1step] refused: the carried root is NOT the root of the record at the named \
                 address — forged, or folded on a foreign chain"
            );
            #[cfg(test)]
            if let Ok(mut m) = MEMBER_ROOT_MISMATCH.lock() {
                m.push((named_record, "?"));
            }
            return MemberVerdict::Refused;
        }
        // ⛔⛔⛔ DB-213c (2026-09-25) — THE DIRECT ONE-STEP PROOF, NOT THE RECURSIVE FOLD.
        //
        // MEASURED by the prover lane (`db213_forgery_census.rs`, arm M, calibrated): the recursive fold
        // verifier this called certified statements with NO witness behind it — `verify_note_membership_chain`
        // returned TRUE for a leaf in NO block. This gate is the ONLY membership authority a spend has (the
        // spend carrier binds `leaf_commit` and nothing else), so that was a spend of a FABRICATED note:
        // inflation. A one-step carrier needs no recursion at all — it is ONE membership step, `leaf ∈ root`,
        // and `verify_note_membership_one_step` checks that step's own proof, shape-pinned, against the root
        // THIS node derived from the named record above and the binder the spend publishes.
        if !usdm_decider::note_membership_air::verify_note_membership_one_step(
            proof,
            leaf_commit,
            binder,
            tip_root,
        ) {
            eprintln!(
                "[membership-1step] refused: the carried proof does not prove this note is a member of the \
                 named record's root under the spend's own binder"
            );
            return MemberVerdict::Refused;
        }
        // DB-358 (1), LAST: only an otherwise-valid carrier is told to wait for the fold.
        if unfolded_at_admit(folded) {
            return match door {
                crate::respend::MemberDoor::Admit => MemberVerdict::Pending,
                crate::respend::MemberDoor::Fold => MemberVerdict::Refused,
            };
        }
        MemberVerdict::Member
    }

    pub fn membership_transition_at(&self, ordinal: u64) -> Option<(crate::spend_frontier::Digest4, crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)> {
        // ⛔ REVERTED — MEASURED REGRESSION. I made this DERIVE `acc_after` by folding `acc_before` with the
        // block root instead of reading the recorded value, on the theory that a fold is the same fact. On the
        // live pair it rejected every send: two in a row came back "the spend's carried nullifier-absence
        // witness did not verify against this node's accumulator", where the immediately previous build settled
        // (`ok=True 0.05 change 0.3`). So the recorded `acc_after` and a locally-folded one are NOT equal here —
        // the recorded value tracks something the naive re-fold does not reproduce, and that difference is the
        // real thing to understand before this store can go.
        //
        // `membership_transition_from` above stays: it is the storeless shape a CARRIER-supplied `acc_before`
        // will use, and it is what removes the last per-block file once the divergence above is explained.
        // ⭐⭐⭐ v32 (item 9): ORDINAL 0 IS DEFINED BY THE CHAIN, NEVER READ FROM ROWS. Genesis folds
        // nothing, so its transition is the identity at the membership base — and its "root" is the
        // genesis record's own root, a pure function of the genesis block id (an EMPTY record's 256-leaf
        // shape seeded by genesis's record address), identical on every node of this chain at any time.
        //
        // Two defects lived here, both MEASURED:
        //   * a node that had STORED rows at ordinal 0 (the retired enable_persist genesis fold) answered
        //     the recorded pair while a fresh node answered the substitute constants — the LIVE pair
        //     divergence (:27780 all-zero vs :28901 `32118f41…`/`85c3d9f2…` at ordinal 0, same binary);
        //   * the substitute root was `empty_subtree_root(RECORD_SUBTREE_LEVEL)`, whose comment claimed
        //     "never all-zero" — FALSE: `poseidon_pair` has no round constant, zero is a fixed point, so
        //     `empty_subtree_root(8) == [0;4]` (pinned by
        //     `the_all_zero_sentinel_is_a_poseidon_fixed_point_and_is_never_served_at_ordinal_0`), and
        //     the route served the ALL-ZERO SENTINEL as a positive answer.
        // Answering the defined constants unconditionally makes both nodes byte-identical at ordinal 0
        // regardless of what a legacy datadir stored, and makes the sentinel impossible to serve.
        if ordinal == 0 {
            let root = self.genesis_membership_record_root()?;
            return Some((Self::MEMBERSHIP_GENESIS_ACC, root, Self::MEMBERSHIP_GENESIS_ACC));
        }
        let acc_after = match self.da_membership_acc_at_ordinal(ordinal) {
            Some(a) => a,
            None => return None,
        };
        let root = match self.da_block_root_at_ordinal(ordinal) {
            Some(r) => r,
            None => return None,
        };
        // Ordinal 1's before-value is the membership chain's DEFINED base — genesis folds nothing, so no
        // stored row may ever stand in for it (a legacy datadir that folded genesis stored a poisoned row
        // at ordinal 0; reading it re-created the live divergence one ordinal later).
        let acc_before = if ordinal == 1 {
            Self::MEMBERSHIP_GENESIS_ACC
        } else {
            match self.da_membership_acc_at_ordinal(ordinal - 1) {
                Some(a) => a,
                None => return None,
            }
        };
        Some((acc_before, root, acc_after))
    }

    /// The account-DA accumulator this node has folded — the value its headers commit.
    pub fn account_root(&self) -> crate::hash::Hash32 {
        self.account_acc
    }

    /// Append a sealed entry to an account's bucket. The entry is already sealed TO the recipient by whoever
    /// wrote it, so this node stores bytes it cannot read — it is a carrier, never a reader.
    /// Append one sealed entry and return the LINK it landed in, so the caller can persist each touched
    /// link exactly once per block. Persisting inside here meant one whole-link write PER CREDITED NOTE on the
    /// record path, which is synchronous disk work under a 500ms block cadence.
    pub fn account_bucket_append(&mut self, bucket: [u8; 32], sealed: Vec<u8>) -> [u8; 32] {
        // SPILL, NEVER DROP. This used to evict the oldest entry when a bucket filled — a cap dressed up as a
        // "fixed window". It loses the position of a note the wallet still owns, and with the linear sweep
        // gone that note becomes permanently unfindable: silent fund loss. Each bucket keeps its constant
        // width and a full one spills into the next link of a chain the wallet re-derives from its own id.
        let mut at = bucket;
        loop {
            let b = self.account_buckets.entry(at).or_default();
            if b.len() < crate::account_da::BUCKET_CAPACITY {
                b.push(sealed);
                // ⛔⛔⛔ THE INDEX MUST OUTLIVE THE PROCESS. This wrote ONLY to the in-memory map, so every
                // account-bucket entry died on restart while the note it points at stayed on the chain
                // forever. Reproduced end to end: a funded seed restored to 2.5 USDm, the node was restarted,
                // and the SAME seed on the SAME datadir restored to 0 — "account bucket read OK: 1 owned"
                // became "0 owned". The money is not gone; the one lookup that finds it is, and with the
                // linear sweep retired that note is unfindable. The DA layer IS the ledger: a fact it writes
                // down is kept forever, exactly like every other `da_store_*` index beside it.
                //
                // A bucket is bounded by `BUCKET_CAPACITY`, so rewriting the link whole is a fixed-size write
                // — never a function of chain height or how many notes the account has ever held.
                return at; // the link this entry landed in — the caller persists it ONCE per block
            }
            at = crate::account_da::next_bucket(&at);
        }
    }

    /// Serve one account bucket — ALWAYS the same constant width, whether or not this account has ever been
    /// paid. Selector-independent by construction: the response shape carries no answer.
    pub fn account_bucket_blob(&self, bucket: &[u8; 32]) -> Vec<u8> {
        // COUNT IT. A seed-only restore's whole cost is bucket reads, and this one was uncounted — so the
        // flat-cost proof compared 0 reads on a short chain against 0 reads on a 20x taller one and passed
        // trivially. A counter that never counts the work it measures is the fake test the standard exists
        // to prevent. ([[feedback_empirical_proof_standard]])
        self.da_reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // READ THROUGH TO DISK. In-memory alone meant a restarted node served an EMPTY bucket for an account
        // it had really paid — the reader cannot tell that from "never paid", so the balance read zero.
        let empty: Vec<Vec<u8>> = Vec::new();
        let real = match self.account_buckets.get(bucket) {
            Some(m) if !m.is_empty() => m,
            _ => &empty,
        };
        // ⛔⛔⛔ CHAIN KEY, NOT THIS NODE'S SECRET. Same class as the injected seed note and the OLI index.
        //
        // The bucket serve pads with chaff keyed on `da_secret_value()` — a value only THIS node holds — so a
        // recipient asking node A and the same recipient asking node B received DIFFERENT bucket contents for
        // the same chain. This is the path a payee uses to FIND its payment, so a per-node answer here means a
        // note that is visible on one device and missing on another: the precise symptom chased all session.
        //
        // `oli_chain_key()` is derived from the genesis id — every node on a network computes it identically
        // and no node can choose it. It is already public (`chain_id` is served by `/get_info`), so keying on
        // it reveals nothing new; the lookup stays oblivious and WHICH entry a wallet wants is still never sent.
        crate::account_da::serve_bucket(real, &self.oli_chain_key(), bucket)
    }

    /// The pool's verdict on a CARRIED copath: a tag an unfolded grafted block already spent is SPENT whatever the copath
    /// says (it was built before that block), else the band door's verdict under the authority rule.
    pub(super) fn pool_copath_verdict(&self, nf: &[u8; 32], cp: &[crate::spend_frontier::Digest4]) -> crate::nf_sparse::SpentVerdict {
        if self.spent_by_an_unfolded_block(nf) {
            return crate::nf_sparse::SpentVerdict::Spent;
        }
        self.authority_verdict(self.band_copath_verdict(nf, cp))
    }

    /// The O(1) confidential cover accumulator (the mesh-only decoy-seed input, advanced once per applied block by
    /// [`Self::advance_nf_cover_conf_acc`]). Exposed so a convergence check can assert FULL spent-state parity —
    /// a node that grafts the tip but islands its cover lockstep diverges here. FIXED 32 bytes at any height.
    ///
    /// ⛔⛔⛔ THESE HAD NO GETTER, AND THAT IS WHY THE CENSUS WAS BLIND. `cold_peer_verdict` compares
    /// what it can READ, and a field with no accessor is a field it cannot compare — so a party could
    /// hold an account commitment, a nullifier count, a DA window or a rule set that NO BLOCK PRODUCED
    /// and the verdict returned `Ok(())`. MEASURED (refutation suite, 2026-09-24): five arms panicked
    /// with *"THE … COMPARISON CANNOT FIRE … Verdict: Ok(())"* — account commitment, nullifier set,
    /// serve position, letter accumulator, directory.
    ///
    /// A census that reads no field is silent in EXACTLY the way a clean chain is, which is the worst
    /// possible failure mode for a funds-safety detector: it reports success while the two nodes
    /// disagree about where money is indexed and what has already been spent.
    ///
    /// Read-only, O(1) each, no state touched.
    pub fn account_acc_for_audit(&self) -> crate::hash::Hash32 {
        self.account_acc
    }
    /// The tip every holder's membership proof is rooted at.
    pub fn membership_tip_root_for_audit(&self) -> crate::spend_frontier::Digest4 {
        self.membership_tip_root
    }
    /// The mint ratio in basis points — a RULE, not state. A node applying different rules to the same
    /// block agrees with itself perfectly and with nobody else.
    pub fn mint_ratio_bps_for_audit(&self) -> u32 {
        self.params().mint_ratio_bps
    }

    /// §RF-3 — the member ring commit history, oldest first: what a checkpoint and a bundle carry.
    pub(crate) fn member_ring_commits(&self) -> Vec<(u64, crate::hash::Hash32)> {
        self.member_ring_commits.iter().copied().collect()
    }

    /// §RF-3 — whether `commit` is the member ring commit of a canonical fold step this node holds.
    pub(crate) fn member_ring_commit_is_canonical(&self, commit: &crate::hash::Hash32) -> bool {
        self.member_ring_commits.iter().any(|(_, c)| c == commit)
    }

    /// ⛔ DB-358 — every nullifier-revealing item a block credits outputs for, as (its tags, its output cms), in the
    /// block's own order. ONE site for the item classes:
    /// * a SPEND: its note-transition tuple, whose tags widen to its whole cover group when it carries one (a
    ///   multi-input spend retires all of them);
    /// * a CREDIT-SET object that retires nullifiers of its own (`chain_object::object_own_nullifiers`), with the
    ///   notes it carries.
    /// NAMED, not covered: bond-lane items, which are refused at every door and every graft while DB-345 pauses the
    /// USDm bond. They join this census when that pause lifts.
    /// ⛔⛔⛔ DB-367 — THE ONE JUSTIFICATION OF A BLOCK'S LANE, from the block's own body: the SAME verifiers the graft door
    /// credits notes through (`graft_admitted_notes`: `note_transition::verify`, `verify_cover`, `bond_admissions_of`) and
    /// the SAME object admission rule (`chain_object::admissible`). Every node holding the body computes the same value.
    ///
    /// ROOT-LAYER: the spent set is PRODUCED by the fold's admitted steps (the band, and through it the view, `sparse_acc`
    ///   and the pool's copath verdict). Admission used to take the whole header-bound lane minus the respend losers, so a
    ///   tag no proof and no object justified — the producer's unverifiable fill, or the group of a cover transition that
    ///   does not verify — entered the set.
    /// MEASURED (before): `db367_a_lane_tag_nothing_proves_does_not_burn_a_victims_pending_spend_on_a_peer` RED on lane/p4b2
    ///   at c6dcad6 + the pin: a block whose lane named a victim's nullifier with no carrier made B revoke the victim's
    ///   honest spend in the next block ("B revoked the victim's HONEST spend").
    /// MUST-STAY-GREEN: every honest-chain fold pin (an honest block's spends are stated by its transitions and its objects
    ///   are admissible, so nothing it spends is dropped); the DB-358 respend pins; the DB-274 B1 pin.
    /// cons: one more verify of the block's note, cover and bond transitions per fold step (the graft verified them once
    ///   already; measured in the blast); the fill's decoys and an object wrapper's padding decoys no longer enter the set —
    ///   they spend nothing, and the fill is already the lane minus what the PUBLIC body justifies, so nothing about which
    ///   tag was real is newly revealed. No growth axis: built per step, dropped with it.
    /// ⭐⭐⭐ DB-223 Q7 — THE INPUT'S ANCHOR, JUDGED AT THE FOLD (Q1), in the step's canonical pre-state. Every stated
    /// spend of block `b` is covered by a member tuple (`member_transition::spends_proven_with_members`, required at
    /// ingest, graft and the lane); its ANCHOR must be a spine root of THIS chain — the ring the fold has produced so
    /// far — or the input may be a member of a tree its producer invented. Answers [`AnchorVerdict::Decided`] with the
    /// spends refused here (anchor not in a COMPLETE ring: one verdict on every node, since every node folds the same
    /// steps), or [`AnchorVerdict::Wait`]: the ring is incomplete (fresh after an adopt or a restart whose checkpoint
    /// carried none) and does not hold an anchor, so this node cannot tell — refusing would split it from every node that
    /// can. A block with no stated spend, a body not held (its spends were never justified here) or spends not covered
    /// (justified nothing) refuses nothing new.
    /// §9.6: 5 Bounded work — one scan of the fixed-length ring per stated spend (≤ `BLOCK_FIXED_TX_COUNT`).
    /// §18 — every cell a block's CARRIED OBJECTS justify on the ledger: each credit-set and bond-set object's carried
    /// note cms (`chain_object::carriage_note_refs`) and own nullifiers (`chain_object::object_own_nullifiers`). Read by
    /// the ring judge above a non-canonical ring commit; an unparseable set contributes nothing (fail-closed, as at graft).
    /// cons: one decode per carried object, bounded by the two sets' fixed slot counts.
    pub(super) fn object_own_cells_of(&self, body: &crate::block::Block) -> std::collections::HashSet<[u8; 32]> {
        let mut cells = std::collections::HashSet::new();
        let mut take = |blob: &[u8]| {
            cells.extend(crate::chain_object::carriage_note_refs(blob).into_iter().flatten().map(|(cm, _)| cm));
            cells.extend(crate::chain_object::object_own_nullifiers(blob).into_iter().flatten());
        };
        for blob in self.opened_credit_objects(body).into_iter().flatten() {
            take(&blob);
        }
        for tx in Self::bond_set_entries(&body.bond_set).0.into_iter().flatten() {
            take(&tx.blob);
        }
        cells
    }

    /// ⭐ §BR-14 — HOW MANY SPEND TRANSACTIONS THIS FOLD STEP APPLIES (each paid the flat fee once, in its one carrier). A
    /// ledger block's spend rows are told from its cover rows exactly as the anchor check tells them (the record's own cover
    /// cells and the block's objects' cells — one predicate, read from the RECORD every folding node holds, so one count on
    /// every node). A transaction rides as its WHOLE constant-width tag set — `TX_FIXED_NULLIFIER_COUNT` tags, two per row —
    /// and by design no node can tell its real row from its decoy rows (MEASURED: one single-input spend states 16 rows,
    /// br14-node-261.log), so the unit is the transaction: applied rows ÷ (TX_FIXED_NULLIFIER_COUNT / 2). A legacy block
    /// states one tuple per spend. Rows refused for their anchor or lost to a respend leave the count. 0 when the body,
    /// its transition or its record is not held (the fold waits for the record before it gets here for a ledger block).
    pub(super) fn applied_spend_count_at_fold(
        &self,
        b: &crate::block::BlockId,
        anchor_refused: &[crate::note_transition::SpendTuple],
        losers: &[[u8; 32]],
    ) -> u64 {
        let Some(body) = self.unfolded_blocks.iter().find(|x| x.id() == *b) else {
            return 0;
        };
        let Some(nt) = body.note_transition.as_ref() else {
            return 0;
        };
        let stated: Vec<crate::note_transition::SpendTuple> = if Some(nt.shape) == crate::note_transition::ledger_shape_wire() {
            let Some((addr, reals)) = self.record_addr_for_block(b).and_then(|a| self.da_record_reals(a).map(|r| (a, r))) else {
                return 0;
            };
            let (decoys, cover_notes) = crate::note_transition::ledger_cover_cells(&reals.concat(), &self.cover_key_of(addr));
            let objects = self.object_own_cells_of(body);
            let keeps = |cell: &[u8; 32], covers: &std::collections::HashSet<[u8; 32]>| covers.contains(cell) || objects.contains(cell);
            // ⛔⛔⛔ §BR-14 × ROGUE PRODUCER (2026-10-29, `a_block_whose_ledger_was_laid_for_other_notes_credits_no_fee_pool_on_the_peer`):
            // a FEE PAYER is a spend whose two outputs are notes this record really holds. MEASURED: a rogue block whose ledger
            // was laid over other notes (its cover seed derives from the notes, so every cover row moved off the record's cover
            // cells) was credited 7 spend transactions nobody paid — 700,000 atomic into pools that pay miners, bonders and
            // stakers. A real spend's outputs are recorded in its block, so requiring both outputs among the record's real notes
            // counts every honest spend and none of the displaced cover rows (their outputs are the OLD seed's cover notes, which
            // no valid object can open).
            let real_cms: std::collections::HashSet<[u8; 32]> = reals
                .iter()
                .flat_map(|r| r.chunks(crate::cover::PQ_NOTE_BYTES).filter_map(|n| <[u8; 32]>::try_from(n.get(..32)?).ok()).collect::<Vec<_>>())
                .collect();
            match crate::member_transition::ledger_rows_as_spends(nt) {
                Some(rows) => rows
                    .into_iter()
                    .filter(|r| {
                        !(keeps(&r.nullifier, &decoys)
                            && keeps(&r.tag1, &decoys)
                            && keeps(&r.out0_cm, &cover_notes)
                            && keeps(&r.out1_cm, &cover_notes))
                    })
                    .filter(|r| {
                        real_cms.contains(&r.out0_cm)
                            && real_cms.contains(&r.out1_cm)
                            && !objects.contains(&r.out0_cm)
                            && !objects.contains(&r.out1_cm)
                    })
                    .collect(),
                None => return 0,
            }
        } else {
            crate::note_transition::spend_tuples(nt).unwrap_or_default()
        };
        let ledger = Some(nt.shape) == crate::note_transition::ledger_shape_wire();
        let refused: std::collections::HashSet<[u8; 32]> = anchor_refused.iter().map(|s| s.nullifier).collect();
        let applied = stated
            .iter()
            .filter(|s| !refused.contains(&s.nullifier) && !losers.contains(&s.nullifier) && !losers.contains(&s.tag1));
        if !ledger {
            return applied.count() as u64;
        }
        // A ledger spend is ONE transaction per distinct pair of real recorded outputs (each spend's two outputs are notes of
        // its own; the rest of its constant-width tag set rides as justified cells with no outputs of their own).
        applied.map(|s| (s.out0_cm, s.out1_cm)).collect::<std::collections::HashSet<_>>().len() as u64
    }

    pub(super) fn member_anchors_at_fold(&self, b: &crate::block::BlockId, ordinal: u64) -> AnchorVerdict {
        let nothing = AnchorVerdict::Decided(Vec::new());
        let Some(body) = self.unfolded_blocks.iter().find(|x| x.id() == *b) else {
            return nothing;
        };
        let Some(nt) = body.note_transition.as_ref() else {
            return nothing;
        };
        let covered = crate::member_transition::spends_proven_on_block_with(
            nt,
            body.member_transition.as_ref(),
            &body.header.output_notes_root,
            &body.oli_tags,
            Some(crate::member_transition::LedgerDoor::of_block(body)),
            self.template_double(),
            self.ledger_double(),
        );
        // §RF-3: a ledger block publishes no anchor — its member proof stands under the header's ring commit, which must
        // be a commit THIS chain's ring held (Zcash Sapling's anchor set). Not canonical in a complete history: every
        // row that STATES A SPEND is refused — told from a cover row by the record's own cover cells (§18, below); an
        // incomplete history waits.
        if covered.is_some() && Some(nt.shape) == crate::note_transition::ledger_shape_wire() {
            // ⭐ goods spec §9.1 — THE LEDGER CLOCK. The ledger proved every stated spend's clock is at or before
            // `nt.clock_ms`; here that clock must be at or before the chain clock at the block's selected parent
            // (`Node::ledger_clock_is_reached`, BIP113's shape). A ledger past it states spends under a clock the chain
            // has not reached (a vault's clock branch taken early), so its spend rows are refused below, exactly as rows
            // under a ring commit this chain never held: the block stays, its unverifiable spends do not apply. The
            // verdict reads the DAG alone, so every node that holds the block decides it the same way and never waits.
            let clock_reached = self.ledger_clock_is_reached(b, nt.clock_ms);
            // ⭐ A-F114 (B′): under the constant chain a spend names no anchor (its wrapper's end is judged per tag by
            // `canon_tag_spent`), so a reached clock leaves nothing to judge here; a clock not reached still refuses below
            if crate::canon_chain::canon_live() && clock_reached {
                return nothing;
            }
            if clock_reached && self.member_ring_commit_is_canonical(&body.header.member_ring_commit) {
                // §22c: the ledger's ring is this chain's; each stated spend's OWN anchor still has to be in it.
                return self.native_spend_anchors_at_fold(b, body, nt, ordinal);
            }
            if clock_reached && !self.anchor_ring_is_canonical_before(ordinal) {
                return AnchorVerdict::Wait;
            }
            // ⛔ §18 (2026-10-28, MEASURED node-87.log): a block merged from a side branch after a reorg carries the ring
            // commit of the branch it was laid on (its producer's ring then — on the merged chain no prefix of any node's
            // ring, `[anchor-judge] … prefix of length None`), and under the hidden-row class every row's flags are
            // zero, so "every ledger-stated row" refused a QUIET member block's 127 cover rows and stripped its seed
            // note — the fold then diverged from the record (`a_node_holding_the_peers_orphans_adopts_…`: ordinals
            // differ for 8 blocks, the re-anchored peer waiting 128 passes for a record no node served). Refused here
            // are the rows that STATE A SPEND: a row with a cell outside the block's own cover cells
            // (`ledger_cover_cells`, holder-only by construction) and outside its carried objects' own cells — a spend
            // head (nullifier, claim, real outs) or a tail (pair-digest tags). A pure cover row, or a cover row filing an
            // object's note or nullifier, states no spend and keeps its cells (the pre-§18 flag rule, now derived).
            // ONE VERDICT ON EVERY NODE: the cells are read from the block's RECORD (what every folding node holds and
            // folds, byte-identical), never from the body a producer alone holds; a node without the record waits, as it
            // would for the fold itself. Kaspa's merge rule in this chain's terms: a merged block stays, its unverifiable
            // spends do not apply (Zcash: an anchor off the chain invalidates the spend, never the block).
            let Some((addr, reals)) = self.record_addr_for_block(b).and_then(|a| self.da_record_reals(a).map(|r| (a, r))) else {
                return AnchorVerdict::Wait;
            };
            let (decoys, cover_notes) = crate::note_transition::ledger_cover_cells(&reals.concat(), &self.cover_key_of(addr));
            let objects = self.object_own_cells_of(body);
            let keeps = |cell: &[u8; 32], covers: &std::collections::HashSet<[u8; 32]>| {
                covers.contains(cell) || objects.contains(cell)
            };
            return match crate::member_transition::ledger_rows_as_spends(nt) {
                Some(rows) => AnchorVerdict::Decided(
                    rows.into_iter()
                        .filter(|r| {
                            !(keeps(&r.nullifier, &decoys)
                                && keeps(&r.tag1, &decoys)
                                && keeps(&r.out0_cm, &cover_notes)
                                && keeps(&r.out1_cm, &cover_notes))
                        })
                        .collect(),
                ),
                None => nothing,
            };
        }
        let (Some((_, members)), Some(spends)) = (covered, crate::note_transition::spend_tuples(nt)) else {
            return nothing;
        };
        let complete = self.anchor_ring_is_canonical_before(ordinal);
        let mut refused = Vec::new();
        for (m, s) in members.iter().zip(&spends) {
            if self.spine_recent_roots.iter().any(|(_, r)| *r == m.anchor) {
                continue;
            }
            if !complete {
                return AnchorVerdict::Wait;
            }
            refused.push(*s);
        }
        AnchorVerdict::Decided(refused)
    }

    /// ⭐ §22c (audit F14, 2026-11-10) — A LEDGER SPEND'S OWN ANCHOR, JUDGED AT THE FOLD. The block's member ledger says
    /// every spend row's input is under a root of the ring the header commits, but it lays each member carrier from its
    /// bytes, so a forged one can name any ring root while the transaction's real member leg stands under a tree its
    /// sender invented. The door verified each stated spend's transaction natively (`spend_evidence`); the anchor THAT
    /// proof stands under is read here and must be a root of this chain's ring at the block's fold position — the rule
    /// the legacy list has always had below (Zcash Sapling: an anchor off the chain invalidates the spend, never the
    /// block). A spend whose anchor is not in a COMPLETE ring is refused with its tail rows, one verdict on every node
    /// (every node folds the same steps and holds the same carried transactions); an incomplete ring waits.
    /// A block that states no spend, or that entered with no carried transactions (nothing above the door admits one that
    /// states a spend; a checkpoint written before §22c may hold one), has no native anchor to judge.
    /// §9.6: 5 Bounded work — one row classification over the record's cover cells and ≤ `BLOCK_FIXED_TX_COUNT` evidence
    /// reads (cached verdicts), one ring scan per stated spend.
    fn native_spend_anchors_at_fold(
        &self,
        b: &crate::block::BlockId,
        body: &crate::block::Block,
        nt: &crate::note_transition::NoteTransition,
        ordinal: u64,
    ) -> AnchorVerdict {
        if body.tx_bodies.is_empty() {
            return AnchorVerdict::Decided(Vec::new());
        }
        let Some((addr, reals)) = self.record_addr_for_block(b).and_then(|a| self.da_record_reals(a).map(|r| (a, r))) else {
            return AnchorVerdict::Wait; // the rows are told apart by the record every folding node holds
        };
        let Some(published) = crate::note_transition::decode_ledger_published(&nt.tuples) else {
            return AnchorVerdict::Decided(Vec::new());
        };
        let (decoys, cover_notes) = crate::note_transition::ledger_cover_cells(&reals.concat(), &self.cover_key_of(addr));
        let objects = self.object_own_cells_of(body);
        let rows = crate::spend_evidence::ledger_rows(&published);
        let stated = |r: &crate::spend_evidence::Row| crate::spend_evidence::spend_stated_cells(r, &decoys, &cover_notes, &objects);
        let Some(heads) = crate::spend_evidence::stated_spend_anchors(body, &rows, &decoys, &cover_notes, &objects, nt.clock_ms) else {
            // The record's rows are not what the carried transactions prove (the door judged this block with these same
            // bodies, so this is a record or a body that changed underneath): no stated spend of it applies.
            return AnchorVerdict::Decided(rows.iter().filter(|r| stated(r).iter().any(|s| *s)).map(|r| r.tuple).collect());
        };
        let complete = self.anchor_ring_is_canonical_before(ordinal);
        let mut refused: Vec<crate::note_transition::SpendTuple> = Vec::new();
        for (head, anchor, tags) in &heads {
            if self.spine_recent_roots.iter().any(|(_, r)| r == anchor) {
                continue;
            }
            if !complete {
                return AnchorVerdict::Wait;
            }
            // the spend's head row and every tail row that carries one of its tags
            refused.push(*head);
            refused.extend(rows.iter().filter(|r| r.tuple != *head).filter(|r| {
                let s = stated(r);
                !s[0] && !s[1] && ((s[2] && tags.contains(&r.tuple.nullifier)) || (s[3] && tags.contains(&r.tuple.tag1)))
            }).map(|r| r.tuple));
        }
        AnchorVerdict::Decided(refused)
    }

    /// ⭐⭐⭐ DB-274 P2 (§8.7) — THE BOND CLASS'S FOLD STEP. The validator set moves HERE, once per block, in the
    /// canonical fold order every node shares, never at graft in arrival order: measured B19 (two real processes held
    /// validator sets 0 and 300 M after 421.8 s) and the DB-274 opposite-order pins. Runs after DB-358's respend
    /// decision and BEFORE the block's record takes its position, because a release writes into that record.
    ///
    /// 1. The block's `bond_set` applies against the folded pre-state (the one `apply_bond_set`: same verifies, same
    ///    maturity rule, judged at the block's own blue score). An unbond of a collateral bond moves the locked
    ///    note into `unbonding`; a slash also burns an unbonding entry.
    /// 2. Every `unbonding` entry whose `due_blue` this block has reached is RELEASED into this block's record row
    ///    while the row has a free cover slot (the 256-leaf shape is kept: the note replaces a cover leaf), in vid
    ///    order, and filed under its owner's bucket. The row is canonical at its fold, so "free" is too.
    /// 3. The before-state of every validator the step touched is journaled (`bond_fold_journal`); a rewind restores
    ///    it and takes the released notes back out of the row.
    ///
    /// Returns whether a journal entry was pushed, so a fold that is then refused can unwind it
    /// ([`Self::unwind_bond_step`]): a refused fold leaves no trace.
    ///
    /// §9.6 (the release is a door into a record): (1) PoW n/a, chain-state-derived; (2) the unbond's ML-DSA
    /// statement and one-shot right were verified at its own fold step; (3) one write per unbonding entry, which
    /// leaves `unbonding` in the same step, and a slash drops the entry first; (4) a second unbond of an unbonding
    /// validator finds no weight and is refused; (5) bounded by the entries due and the row's free slots; (6) the
    /// same `record_account_target` filing the graft-time release used, and DB-358's row discipline.
    /// A block whose body this node does not hold (a carried shell) applies no bond set here: P5's body door is the
    /// close, named, not hidden. Its releases still run: they read chain state, not the body.
    ///
    /// 0. (2026-10-07) The SAT bonds this block's objects step DECIDED (`sat_seats`, `sat_bond_tx::decide_chain_sat_bond`)
    ///    seat FIRST, inside this step's journal, locked at this block's blue score (DB-257) — so a refused fold unwinds a
    ///    seat with the rest of the step and a retry decides it again from the same pre-state.
    /// ⭐ §22 2 — retire a custodian seven days away: its own yield is settled and weighed by its uptime, then its weight
    /// leaves the tally exactly as an unbond takes it (G2b: it weighs on in the denominator until landing + D). Nothing is
    /// slashed and nothing is released here: the locked note stays locked and returns through the operator's own signed
    /// unbond, the ordinary 21-day window (`release_matured_bond` admits a retired seat).
    /// CHAIN-OBJECT: the activity record folded from the chain's deals (see the bond step's call).
    fn exit_away_seat(&mut self, id: [u8; 32]) {
        let y = self.peg.bond_yield_index();
        self.validators.settle_own_yield(&id, y);
        let (active, windows) = self.pay_uptime(&id);
        let _ = self.validators.scale_own_yield(&id, active, windows);
        if self.validators.remove_exiting_at(&id, self.exit_active_until()).is_some() {
            self.validators.settle_own_yield(&id, y); // unseated now: it stops earning
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string; no id, weight or key.
            eprintln!("[bond-fold] §22: a custodian away for seven days left the tally (nothing slashed; its note returns by its unbond)");
        }
    }

    pub(super) fn bond_step_at_fold(
        &mut self,
        b: &crate::block::BlockId,
        seq: u64,
        ordinal: u64,
        sat_seats: &[crate::sat_bond_tx::SatSeat],
        // ⭐ R5 (spec §3f.2): the custody seats this step's rotation rule swaps (`Node::vault_rotations_at_fold`, decided
        // in the objects step from the step's pre-state) — applied here, inside this step's journal, so a refused or
        // rewound fold puts every custodian back on the seat, and so in the vault, it held.
        seat_swaps: &[(u64, u64)],
    ) -> bool {
        // ⭐ THE OBJECTS STEP'S WRITES TO THE VALIDATOR SET JOIN THIS STEP'S JOURNAL (lane vaults, 2026-11-11; see
        // `Node::objects_vids_before`): a delegation's seat weight, a yield claim's accrual, R4b's diversion. Taken
        // here whatever this step itself moves, so a rewind and a refused fold restore them with the bond class.
        let touched = std::mem::take(&mut self.objects_vids_before);
        let Some(blue) = self.relay.dag().get(b).map(|n| n.blue_score) else {
            // a block the DAG no longer holds cannot name its position: the bond class moves nothing
            return self.journal_objects_vids_alone(b, seq, ordinal, touched);
        };
        // A-F60: the step's place on the chain's own clock — what every time-meaning window here is judged against
        let tick = self.chain_tick_at(b);
        let body = self
            .unfolded_blocks
            .iter()
            .find(|x| x.id() == *b)
            .filter(|x| crate::block::sidecar_real_len(&x.bond_set) > 0)
            .map(|x| {
                (
                    x.bond_set.clone(),
                    x.output_notes.clone(),
                    x.nullifier_proof.padded_tags.clone(),
                    x.header.output_notes_root,
                )
            });
        // ⭐ SAFE AT SCALE, stage three (spec §3f R4) — THE RELEASE GATE: collateral whose window has passed returns only
        // when NO ALIVE CUSTODY KEY HOLDS its owner (`PegLedger::vault_key_holds`): a custodian that left still holds a
        // key to the coins deposited while it sat, until its old vault has swept them and retired that key. "No key
        // outlives its bond" is then true whatever foreign fees do. The same fail-closed shape as the cover-slot wait
        // below: nothing mutates, the release is taken at a later step. On a chain whose custody recorded no key the
        // gate holds nobody (the chain as it was). Proven first in the lifecycle model (K1; red without the gate).
        // CHAIN-OBJECT: read at this fold step from the key record `Class::VaultKey` objects wrote, the ledgers' pairs
        // and the seats — every node holds the same at the same step, so every node releases the same notes.
        let key_window = self.vault_key_window_ticks();
        let due: Vec<[u8; 32]> =
            self.unbonding.iter().filter(|(vid, u)| u.due(blue, tick) && !self.peg.vault_key_holds(vid, tick, key_window, &self.validators)).map(|(vid, _)| *vid).collect();
        // ⭐ §22 2 — the custodians away for seven days (168 folded hours with no deal): each leaves the tally now, nothing
        // slashed; its locked note stays and returns through its own unbond. Ethereum's inactivity response, as a clean exit.
        let away: Vec<[u8; 32]> = {
            let a = &self.peg.epoch_keys().activity;
            a.due_unbond(a.now).into_iter().filter(|id| self.validators.bond_of(id) > 0 && !self.validators.is_slashed(id)).collect()
        };
        // ⭐ A-F60 (lane tickfix) — A GENESIS SEAT'S LOCK STARTS WHEN THE CHAIN'S CLOCK DOES. A bond's maturity anchor is the
        // chain tick it was laid at, and the founding seats are laid before any block (`Node::new`: anchor 0). The tick is
        // median time past over the target, so a chain's first blocks stand at a tick near 3·10⁸ (wall time): against an
        // anchor of 0 every founding bond read as matured from the first block, where before A-F60 it stayed locked for
        // the whole stake-lock period (the anchor and the lock were both blue scores). So an anchor still at 0 is set to
        // the tick of the first folded block whose tick is past 0: the lock then runs its full period from the moment
        // the chain has a clock. A bond laid by a block carries that block's tick, which is never 0 on a chain with wall
        // time, so only genesis seats take this step.
        // CHAIN-OBJECT: a function of this fold step's block (its own tick) and the anchors every node holds alike; it is
        // journaled with the step (`before_height` below), so a re-order re-anchors at the block that then folds first.
        // SAFE AT SCALE: one pass over the validator set's anchors a block until none is 0; nothing grows.
        // cons: a pass over the anchors on every block of a chain whose stamps never leave tick 0 (a fixture, never a
        // network); FORMAT: the founding seats' anchors in the snapshot and the bundle are the first tick, not 0.
        // ⛔ ONLY THE FOUNDING SEATS THEMSELVES (fix of this rule's first cut, a2fd70f0, the same evening): it took every
        // locked bond whose anchor read 0, and a bond a BLOCK laid at tick 0 (a fixture's early blocks) was then moved by a
        // LATER block's step — the anchor stopped being a fact of the carrying block, and two nodes at different fold
        // points read two maturities (pin `a_sat_bond_folded_by_a_retried_step_at_a_later_tip_seats_once_with_the_producers_
        // state`: 16,234 against 16,235). A founding seat is named by the launch (`defi_launch::genesis_seats`, a genesis
        // fact on every node) AND still holds the note it was founded with; nothing else is touched, so every other
        // bond's anchor stays what its carrying block set.
        let unanchored: Vec<([u8; 32], Vec<u8>)> = if tick > 0 && self.bond_height.iter().any(|(vid, h)| *h == 0 && self.bond_locked.contains_key(vid)) {
            let mut v: Vec<([u8; 32], Vec<u8>)> = crate::defi_launch::genesis_seats()
                .into_iter()
                .filter(|(vid, _, seat, _)| self.bond_height.get(vid) == Some(&0) && self.bond_locked.get(vid) == Some(&seat.locked_note))
                .map(|(vid, _, seat, _)| (vid, seat.locked_note))
                .collect();
            v.sort();
            v
        } else {
            Vec::new()
        };
        if body.is_none() && due.is_empty() && sat_seats.is_empty() && away.is_empty() && seat_swaps.is_empty() && unanchored.is_empty() {
            return self.journal_objects_vids_alone(b, seq, ordinal, touched);
        }
        // The before-state, transient: only the validators the step changes are kept. For every validator the objects
        // step already changed, the before-state is the one THAT step kept (`touched`): each entry's own state, newest
        // first so the first touch is what stands, and the scalars of the oldest touch — or, when the objects step
        // touched nobody, the set's scalars as they stand now (nothing has moved them since the step began).
        let before_set = {
            let mut set = self.validators.clone();
            for e in touched.iter().rev() {
                set.set_vid_state(e.vid, e.set.clone());
            }
            set
        };
        let before_locked = self.bond_locked.clone();
        let before_height = self.bond_height.clone();
        let before_unbonding = self.unbonding.clone();
        for (vid, note) in unanchored {
            // A-F60: the genesis seats' lock starts at the chain's first tick (above) — the same note, locked at this
            // block's tick through the one writer every seated bond uses
            self.lock_bond_note(vid, note, tick);
        }
        let (burned, commit) = touched.iter().map(|e| (e.burned, e.commit)).next().unwrap_or_else(|| self.validators.scalars());
        // R5: the mix first — it was decided from the step's pre-state, before anything this block carries moves a seat.
        // CHAIN-OBJECT: the rotation rule's consequence at this fold step (see `ValidatorSet::swap_custody_seats`).
        if !seat_swaps.is_empty() {
            let _ = self.validators.swap_custody_seats(seat_swaps);
        }
        for s in sat_seats {
            // SAFE AT SCALE: the folded block's own id is the randomness the new custodian's seat is drawn under
            let _ = crate::node::objects::sat_bond_tx::seat_sat_bond(self, s, tick, &b.0);
        }
        if let Some((bond_set, notes, lane, root)) = body {
            self.apply_bond_set_at(&bond_set, blue, tick, &notes, &lane, Some(&root));
        }
        // §22 2: the seven-day exits, after the block's own objects (evidence in this block still slashes first).
        // CHAIN-OBJECT: the deals the chain carried — or 168 folded hours without one — folded into the activity record every
        // node holds alike; the exit is that record's consequence at this fold step, as an unbonding's release is its due_blue's.
        for id in away {
            self.exit_away_seat(id);
        }
        // Releases AFTER the block's own objects, so evidence in the releasing block itself still burns.
        let mut pushed = 0usize;
        let due_now: Vec<([u8; 32], Unbonding)> = self
            .unbonding
            .iter()
            // R4, the release gate (above): re-read here, AFTER the block's own objects — a key retired by this very
            // block's objects frees its leaver at the next bond step, and a key taken in it holds nobody it does not name
            .filter(|(vid, u)| u.due(blue, tick) && !self.peg.vault_key_holds(vid, tick, key_window, &self.validators))
            .map(|(vid, u)| (*vid, u.clone()))
            .collect();
        for (vid, u) in due_now {
            let room = self
                .da_mem
                .get(&seq)
                .is_some_and(|row| row.0.len() < crate::cover::BLOCK_FIXED_NOTE_COUNT);
            if !room || u.note.len() < 32 {
                break; // no free cover slot (or no row held): the release waits for the next step
            }
            let released_slot = self.da_mem.get(&seq).map(|row| row.0.len()).unwrap_or(0);
            if let Some(row) = self.da_mem.get_mut(&seq) {
                row.0.push(u.note.clone());
                pushed += 1;
            }
            // The released note takes slot `released_slot` of the record's fixed shape (reals first), so every cover unit
            // from that slot on moves one slot up and the last one leaves: the tags the block's uniform filing laid for
            // those cover slots move with them (one falls off), and the real key below lands at the freed slot.
            {
                let mut tags = self.da_load_tags(seq);
                tags.retain(|(s, _)| (*s as usize) < crate::cover::BLOCK_FIXED_NOTE_COUNT - 1 || (*s as usize) < released_slot);
                for t in tags.iter_mut() {
                    if (t.0 as usize) >= released_slot {
                        t.0 += 1;
                    }
                }
                self.da_store_tags(seq, &tags);
            }
            let mut cm = [0u8; 32];
            cm.copy_from_slice(&u.note[..32]);
            // ⭐ DB-273 §19.3 L2: the returned note's OLI tag is placed in THIS step's record, from the CERTIFIED entry's
            // clue, by the one placement every node runs on the same record — no carrying block brings it, and no
            // per-wallet (bucket, ek) target is written.
            // CHAIN-OBJECT: the unbond object the validator signed (its clue digest) — this is its fold-applied release.
            let _ = self.place_note_tag_in_record(seq, &cm, crate::oli::index_key(&u.owner_clue));
            // ⛔ A-F118: the grown row's cover slots follow the graft rule over its regenerated payload (`refile_row_by_filing`;
            // the positional shift above is what a node without the block's filing keeps)
            let _ = self.refile_row_by_filing(seq);
            self.unbonding.remove(&vid);
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string; no id, note, amount, bucket or key.
            eprintln!("[bond-fold] ⭐ DB-274 P2: an unbonding window closed — its collateral note was released into this step's record");
        }
        // ⭐ A-F114 — from the network upgrade a slashed id that holds nothing (`ValidatorSet::settled_slashed`) and no
        // bond lock, bond height or unbonding here leaves the slashed set; the diff below journals it, so a rewind puts it
        // back. The set is then bounded by the slashed ids still referenced, never by every slashing ever.
        if crate::params::canon_live() {
            let settled: Vec<[u8; 32]> = self
                .validators
                .settled_slashed()
                .into_iter()
                .filter(|id| !self.bond_locked.contains_key(id) && !self.bond_height.contains_key(id) && !self.unbonding.contains_key(id))
                .collect();
            self.validators.forget_slashed(&settled);
        }
        let mut vids: Vec<[u8; 32]> = before_set
            .every_vid()
            .into_iter()
            .chain(self.validators.every_vid())
            .chain(before_locked.keys().copied())
            .chain(self.bond_locked.keys().copied())
            .chain(before_height.keys().copied())
            .chain(self.bond_height.keys().copied())
            .chain(before_unbonding.keys().copied())
            .chain(self.unbonding.keys().copied())
            // the ids the objects step touched, named outright: an id that holds only an accrual or a delegated word
            // (an unseated leaver R4b credited) is in none of the lists above
            .chain(touched.iter().map(|e| e.vid))
            .collect();
        vids.sort();
        vids.dedup();
        let changed: Vec<BondVidBefore> = vids
            .into_iter()
            .filter_map(|vid| {
                let was = BondVidBefore {
                    vid,
                    set: before_set.vid_state(&vid),
                    locked: before_locked.get(&vid).cloned(),
                    height: before_height.get(&vid).copied(),
                    unbonding: before_unbonding.get(&vid).cloned(),
                };
                let now = (
                    self.validators.vid_state(&vid),
                    self.bond_locked.get(&vid),
                    self.bond_height.get(&vid),
                    self.unbonding.get(&vid),
                );
                let same = now.0 == was.set
                    && now.1 == was.locked.as_ref()
                    && now.2 == was.height.as_ref()
                    && now.3 == was.unbonding.as_ref();
                (!same).then_some(was)
            })
            .collect();
        if changed.is_empty() && pushed == 0 && self.validators.scalars() == (burned, commit) {
            return false; // nothing moved (every object refused): no entry, so no trace
        }
        self.push_bond_fold_step(BondFoldStep {
            ordinal,
            block: b.0,
            vids: changed,
            burned,
            commit,
            row: seq,
            pushed,
        });
        true
    }

    /// One bond-class journal entry, and the ring's bound.
    fn push_bond_fold_step(&mut self, step: BondFoldStep) {
        self.bond_fold_journal.push_back(step);
        while self.bond_fold_journal.len() > Self::SPINE_RING_LEN {
            // past the rewind reach: that step can no longer be un-folded, and a rewind below it marks the set stale
            if let Some(old) = self.bond_fold_journal.pop_front() {
                self.bond_journal_floor = self.bond_journal_floor.max(old.ordinal.saturating_add(1));
            }
        }
    }

    /// ⭐ A FOLD STEP WHOSE BOND CLASS MOVED NOTHING STILL JOURNALS WHAT ITS OBJECTS WROTE TO THE VALIDATOR SET (lane
    /// vaults, 2026-11-11): a block that carries a delegation or a yield claim and no bond set took the early return
    /// above, and the seat's new weight (or its zeroed accrual) was in no journal. One entry of this step, holding the
    /// before-state of each validator the objects changed and the scalars as they stood before the first of them.
    /// `false` (no entry, no trace) when the objects left the set as it was.
    /// CACHE-ONLY: journals before-images of moves `Class::SatDelegation` / `Class::BondYieldClaim` objects (and the
    /// quarter close's diversion) already made at this fold step; it moves nothing itself.
    fn journal_objects_vids_alone(&mut self, b: &crate::block::BlockId, seq: u64, ordinal: u64, touched: Vec<ObjectsVidBefore>) -> bool {
        let Some((burned, commit)) = touched.first().map(|e| (e.burned, e.commit)) else {
            return false;
        };
        let mut first_touch: Vec<&ObjectsVidBefore> = Vec::with_capacity(touched.len());
        for e in &touched {
            if !first_touch.iter().any(|f| f.vid == e.vid) {
                first_touch.push(e);
            }
        }
        let vids: Vec<BondVidBefore> = first_touch
            .into_iter()
            .filter(|e| self.validators.vid_state(&e.vid) != e.set)
            .map(|e| BondVidBefore {
                vid: e.vid,
                set: e.set.clone(),
                locked: self.bond_locked.get(&e.vid).cloned(),
                height: self.bond_height.get(&e.vid).copied(),
                unbonding: self.unbonding.get(&e.vid).cloned(),
            })
            .collect();
        if vids.is_empty() && self.validators.scalars() == (burned, commit) {
            return false;
        }
        self.push_bond_fold_step(BondFoldStep { ordinal, block: b.0, vids, burned, commit, row: seq, pushed: 0 });
        true
    }

    /// ⛔⛔ DB-417 — the object fold journal as a checkpoint carries it: each step's before-image as the undo from the NEXT
    /// state (the next step's image, or for the newest step this node's ledger now — the one the snapshot carries), oldest
    /// first, with the journal's floor. Each older step's undo was computed when the step after it was journaled; only the
    /// newest is diffed here, against the live ledger. O(the steps' own changes), never the ledger itself.
    pub(super) fn peg_carry(&self) -> crate::persist::PegCarry {
        let mut journal = Vec::with_capacity(self.objects_fold_journal.len());
        for (i, (ordinal, img, undo)) in self.objects_fold_journal.iter().enumerate() {
            let undo = match (undo, self.objects_fold_journal.get(i + 1)) {
                (Some(u), Some(_)) => u.clone(),
                (_, next) => next.map_or(&self.peg, |(_, n, _)| n).undo_to(img), // the newest (or an unset older) step
            };
            journal.push((*ordinal, undo));
        }
        crate::persist::PegCarry { journal, floor: self.objects_journal_floor }
    }

    /// ⛔⛔ DB-417 — the object fold journal rebuilt from a carried one: walking back from this node's restored ledger (the
    /// snapshot's), each undo yields its step's before-image. `None` — keep no journal — when any undo names a field this
    /// build does not know, holds more steps than the ring, or whose ordinals descend or sit below its floor (a carry no
    /// fold journal could have produced).
    pub(super) fn peg_journal_from_carry(
        &self,
        carry: &crate::persist::PegCarry,
    ) -> Option<(std::collections::VecDeque<(u64, crate::peg::PegLedger, Option<crate::peg::PegUndo>)>, u64)> {
        if carry.journal.len() > Self::REWIND_RETAIN
            || carry.journal.windows(2).any(|w| w[0].0 > w[1].0)
            || carry.journal.first().is_some_and(|(o, _)| *o < carry.floor)
        {
            return None;
        }
        let mut journal = std::collections::VecDeque::with_capacity(carry.journal.len());
        let mut state = self.peg.clone();
        for (k, (ordinal, undo)) in carry.journal.iter().enumerate().rev() {
            if !state.apply_undo(undo) {
                return None;
            }
            // as the live node holds it: every step but the newest keeps its undo to the next image
            let kept = (k + 1 < carry.journal.len()).then(|| undo.clone());
            journal.push_front((*ordinal, state.clone(), kept));
        }
        Some((journal, carry.floor))
    }

    /// F-LEG — the sealed legs a mint's object carries: the ones this executor's own proposal gossiped under `slot_key`
    /// (`peg_attest::slot_key_for`: the deposit id of a native mint, the wrapped deposit key otherwise). ONE reader for
    /// the three sites that must agree — the executor's signature, the publish check and the framed object — because the
    /// quorum's statement names these exact bytes (`peg::peg_in_signed_recipient`). Empty when this node holds no
    /// proposal for the mint (a one-custodian chain signing alone): the statement then names no leg and the object
    /// carries none.
    /// CACHE-ONLY: a read of this node's own gathering slot to PUBLISH; the chain's copy is the object's.
    /// cons: none — the read the publish already made, at one site.
    pub(crate) fn mint_legs_for_block(&self, slot_key: &[u8; 32]) -> Vec<([u8; 32], Vec<u8>)> {
        self.peg_attest_pending
            .get(slot_key) // CHAIN-CARRIES-REVIEWED: read to PUBLISH the envelopes into the object
            .map(|s| s.proposal.sealed.clone())
            .unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn peg_in_confidential(
        &mut self,
        deposit_id: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        recipient: [u8; 32],
        note_payload: &[u8],
        // DB-80: `delta_commit` — the COMMITTED mint delta the threshold attestation authorised; the credited
        // note's commitment must open to the value inside it under `mint_carrier`, or nothing is credited.
        // No amount rides the object.
        delta_commit: crate::spend_frontier::Digest4,
        // `mint_carrier`: the WHIR proof that `note_payload`'s commitment opens to `delta_commit`'s value.
        mint_carrier: &[u8],
        bond_backstop_bytes: &[u8],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        // ⭐ DB-273 §19 L1 — the credited note's OLI clue, so a seed-only restore finds it on any node. The object
        // carries it and `recipient` COMMITS to it (`peg::peg_in_recipient`), so the quorum signed the owner.
        owner_clue: &[u8],
        // The proposal instance the quorum signed over (`peg_in_confidential_msg` v2); rides the object.
        proposal_nonce: [u8; 32],
        // ⭐ §BR-4 B4-2: a debt unit's half — the mint publishes as a `Class::UnitOpen` wrapping this peg-in
        unit: Option<&crate::unit_open_tx::UnitPart>,
    ) -> crate::peg::PegOutcome {
        // ⛔ NO OWNERLESS CREDIT. A note with no clue is filed nowhere a restore looks, so accepting the request
        // would make the credit look successful while the money is undiscoverable. Refuse up front — the caller
        // learns immediately, and nothing is minted. A clue that does not open the SIGNED recipient is refused the
        // same way (`peg_in_tx::decode` refuses the object too, on every node).
        if owner_clue.is_empty()
            || owner_clue.len() > crate::peg_in_tx::OWNER_CLUE_MAX
            || crate::peg::peg_in_recipient(&deposit_id, owner_clue) != recipient
        {
            return crate::peg::PegOutcome::BadRequest;
        }

        // ⛔⛔⛔ THE AUTHORIZED-AMOUNT BIND RUNS **BEFORE** THE LEDGER MOVES. IT USED TO RUN AFTER.
        //
        // MEASURED 2026-09-17 by `psm_bridge_e2e`'s "rejected mints mutate NOTHING" assertion, once the
        // bond gate stopped masking it: a peg-in with a VALID solvency carrier and a FULL quorum but NO
        // mint carrier passed replay → threshold → solvency, **applied the peg ledger**, and only then
        // failed this check and returned `BadRequest`. The reserve and minted commitments had already
        // advanced and the `deposit_id` was already consumed.
        //
        // The old code knew and thought it safe — its comment read "the reserve/minted commitments were
        // advanced by the peg ledger above, but NOTHING is credited, so no value enters circulation on an
        // unproven note." ⛔ THAT IS NOT SAFE. Two things break even with no note issued:
        //   1. `minted_commit` now claims USDm that does not exist, so the SOLVENCY figure every later
        //      mint and redeem proves against is wrong — accounting inflation, invisible because the
        //      totals are confidential.
        //   2. the depositor's `deposit_id` is burned in `confidential_deposit_ids`, so their real BTC
        //      deposit can NEVER be retried. Their money is in threshold custody with nothing issued and
        //      no way to claim it.
        //
        // ⭐ NOTHING HERE NEEDS LEDGER STATE — it reads `note_payload`, `mint_authorized` and
        // `mint_carrier` only — so running it first is a pure ordering fix with no behaviour change for an
        // honest credit. A rejected mint now truly mutates NOTHING.
        let Some(pre_cm_limbs) = crate::spend_frontier::note_cm_of(note_payload) else {
            return crate::peg::PegOutcome::BadRequest;
        };
        // DB-80: the note opens to the COMMITTED mint delta — the same commitment the solvency carrier opens
        if !usdm_decider::whir_rec_block::verify_mint_validity_committed_bytes(
            mint_carrier,
            pre_cm_limbs,
            delta_commit,
        ) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only; no tag, amount, key or owner.
            eprintln!(
                "[peg] ⛔ REFUSED a peg-in credit BEFORE touching the ledger: the note's commitment does \
                 not open to the AUTHORIZED mint amount under the supplied carrier — the caller does not \
                 get to choose the amount it receives."
            );
            return crate::peg::PegOutcome::BadRequest;
        }
        // ⛔⛔⛔ VERIFY, PUBLISH, AND MOVE NOTHING (2026-09-17). This used to call the MUTATING ledger door
        // and advance this node's commitments + replay set at execute, before any block carried the
        // object — the local-mutation shape. MEASURED on two real nodes: node1, on a transient fork
        // that lacked node0's mint, re-executed the SAME deposit with the attestations it had cached and
        // credited a second note on its own ledger. Now every node — this one included — applies the
        // peg-in only from a block (`peg_in_tx::apply_chain_peg_in`), so the chain's order mints a
        // deposit exactly once and a fork resolves to ONE credit everywhere.
        // SAFE AT SCALE: the old backstop field is the deposit's vault ride (`peg::VaultRide`) — the ledger door reads it:
        // which vault's ledgers the mint lands on, and whether that vault's own quorum carries it alone
        // DB-58 + F-LEG: the object carries the sealed per-custodian deltas the proposal gossiped, so every custodian opens
        // its leg from the BLOCK it applies — and the quorum's statement names exactly these envelopes.
        let sealed_for_block = self.mint_legs_for_block(&deposit_id);
        let outcome = self.peg.check_peg_in_confidential_riding(
            bond_backstop_bytes,
            deposit_id,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            delta_commit,
            crate::peg::peg_in_signed_recipient(&recipient, &sealed_for_block),
            proposal_nonce,
            &self.validators,
            verifier,
            attestors,
            unit.map(|u| &u.claim.terms),
        );
        if let crate::peg::PegOutcome::ConfidentialPublished = outcome {
            // ⛔⛔⛔ THE CREDITED NOTE MUST BE THE AUTHORIZED AMOUNT — this is where that is decided.
            //
            // ROOT-LAYER: this is the ONLY place a peg-in note reaches the ledger, so it is where the
            // note's value becomes real. The threshold attestation above binds
            // `(deposit_id, new_reserve_commit, new_minted_commit, recipient)` — it does NOT name the
            // note, and the node cannot read a sealed note's amount. So without a bind HERE, the
            // credited note is whatever the CALLER sealed while the committed pair advances by the
            // authorized `mint`: the caller picks the number, which is minting from nothing.
            // MEASURED: 2026-08-26 — `verify_mint_validity` had **0 call sites** across node.rs, peg.rs
            // and rpc_http.rs while the primitive sat unused at whir_rec_block.rs:10673; this path ended
            // in a bare `record_note_payload(h, note_payload)`. A note sealed for 1e6 was credited under
            // an authorized `mint` of 100 (pinned RED-first by
            // `a_peg_in_note_sealed_for_more_than_the_authorized_mint_is_refused`).
            // MUST-STAY-GREEN: `wrapped_mint_execute_route_full_stack_and_gates`, the peg suites, and the
            // node suite (617) — an HONEST credit, whose carrier opens its own cm to the authorized
            // amount, still lands exactly as before.
            //
            // The cm encoding is settled end-to-end: every producer writes `leaf_to_cm_bytes(cm)` into
            // `note_payload[..NOTE_CM_BYTES]`, and `note_cm_of` is the ONE injective reader of it — the
            // digest it recovers is byte-for-byte the `cm_u` that `prove_mint_validity_bytes` returns.
            // (§AG class 9: this used to read `DIGEST_LANES` raw LE u64s — 64 bytes of a different
            // encoding at eight lanes — and panicked on a 32..63-byte payload instead of refusing it.)
            // ⭐ ALREADY PROVEN ABOVE, BEFORE THE LEDGER MOVED. `cm_limbs` is the commitment the carrier
            // bound to `mint_authorized`; re-deriving it here would be a SECOND spelling of the same
            // decode, which is this tree's most expensive recurring defect.
            let cm_limbs = pre_cm_limbs;
            // ⭐⭐⭐ §CS — THE CREDIT IS PUBLISHED, NOT WRITTEN HERE. See `peg_in_tx` for the measurement.
            //
            // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed PegIn object,
            // judged by `chain_object::admissible` at the pool door and applied by
            // `peg_in_tx::apply_chain_peg_in` on EVERY node that grafts the block.
            //
            // ⛔ WHAT THIS REPLACED, AND WHY IT WAS THE WORST HOLE ON THE CHAIN. These lines used to be
            // `record_account_target` + `record_note_payload` — node-local writes — with the peg ledger
            // advanced just above them, also node-local. The depositor's USDm then existed on ONE machine,
            // and because `confidential_deposit_ids` and the solvency commitments are per-node, the same
            // attested request re-submitted to the next node minted again. The verification above was
            // sound; it was never the problem. *Self-verification is not consensus.*
            //
            // The object carries everything a peer needs to reach the SAME verdict from bytes alone: the
            // deposit id (the native replay key), both new commitments, the recipient, the amount, the
            // solvency carrier, the mint-validity carrier, the bond backstop and the attestations.
            let header = crate::peg_in_tx::PegInHeader {
                deposit_id,
                recipient,
                new_reserve_commit,
                new_minted_commit,
                delta_commit,
                proposal_nonce,
            };
            let mut carried_notes = note_payload.to_vec();
            let blob = match unit {
                None => crate::peg_in_tx::wire(
                    &header,
                    carrier_bytes,
                    mint_carrier,
                    bond_backstop_bytes,
                    attestors,
                    note_payload,
                    &sealed_for_block,
                    owner_clue,
                ),
                // §BR-4 B4-2: the same peg-in inside a unit open; the unit's note rides the carriage after the USDm note
                Some(u) => {
                    if u.claim.deposit_id() != deposit_id || !u.verifies() {
                        eprintln!("[unit-open] ⛔ not published: the unit half does not bind this mint or does not prove");
                        return crate::peg::PegOutcome::BadRequest;
                    }
                    let peg_in = crate::peg_in_tx::encode(
                        &header,
                        carrier_bytes,
                        mint_carrier,
                        bond_backstop_bytes,
                        attestors,
                        note_payload,
                        &sealed_for_block,
                        owner_clue,
                    );
                    carried_notes.extend_from_slice(&u.unit_note);
                    let wrapped = crate::unit_open_tx::UnitOpenTx {
                        peg_in,
                        base_deposit_id: u.claim.base_deposit_id,
                        terms: u.claim.terms,
                        unit_note: u.unit_note.clone(),
                        unit_clue: u.unit_clue.clone(),
                        unit_carrier: u.unit_carrier.clone(),
                    };
                    let Some(w) = wrapped.wire() else { return crate::peg::PegOutcome::BadRequest };
                    w
                }
            };
            // ⭐ DB-273 §19 L1: the owner's clue rides the OBJECT (above), and every node stages the note's OLI record
            // from it (`chain_object::object_owner_clue_records`) — so the note is findable on every node, and no
            // per-wallet (bucket, ek) target and no relay-mutable sidecar copy is written.
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
            let mut tx = crate::mempool::PqTx {
                clock_ms: 0,
                id,
                blob: blob.clone(),
                weight: blob.len() as u32,
                nullifiers: Vec::new(),
                pow_stamp,
                note_clues: Vec::new(),
                account_targets: Vec::new(),
                output_notes: carried_notes,
                stake_notes: Vec::new(),
                bond_notes: Vec::new(),
                // A peg-in MINTS: it spends no NOTE, so it carries no membership cross-bind. Its lane carries ONE
                // real tag — the deposit id's own nullifier (DB-274 P4b B1), laid below with its evidence.
                nullifier_witnesses: Vec::new(),
                nullifier_absence: Default::default(),
                membership_carrier: Vec::new(),
                membership_leaf_commit: [0u8; 32],
                membership_tip: Vec::new(),
                membership_folded_through: 0,
                spend_or_decoy: Vec::new(),
                member_carrier: Vec::new(),
                member_tuple: Vec::new(),
            };
            if !self.lay_object_lane(&mut tx) {
                return crate::peg::PegOutcome::BadRequest;
            }
            if let Err(e) = self.pool_wallet_publication(tx) {
                // Fixed string — no tag, cm, amount, key or owner in it.
                eprintln!("[peg-in] ⛔ the peg-in object was REFUSED at this node's own pool door: {e:?}");
                return crate::peg::PegOutcome::BadRequest;
            }
        }
        outcome
    }

    /// #75 — CONFIDENTIAL PEG-OUT (Buy-USDm redeem/burn), no cleartext amount. The custodian supplies the
    /// WHIR-bound peg-out carrier + the NEW committed state (conservation + post-state ≥150% backing, no drain);
    /// the node VERIFIES the threshold + the carrier against its persisted commitments and PUBLISHES the
    /// `Class::PegOut` object (carrying the depositor's change note and its owner target, when given). The
    /// digest pair advances and the burned USDm nullifier retires when a block carries it
    /// (`peg_out_tx::apply_chain_peg_out`), on every node alike — never here (§CZ: the local-mutation shape
    /// let a fork mint twice, and the same shape lets a fork REDEEM twice). Learns no burn / release value.
    /// cons: none — the object already carried a (possibly empty) note column and an attestor list; the
    /// change note + its sealed owner target are the same 1153 + ~1250 bytes the executor's second object
    /// carried until now, on ONE object instead of two (a fixed shape, no term in history).
    #[allow(clippy::too_many_arguments)]
    pub fn peg_out_confidential(
        &mut self,
        usdm_nullifier: [u8; 32],
        carrier_bytes: &[u8],
        new_reserve_commit: crate::spend_frontier::Digest4,
        new_minted_commit: crate::spend_frontier::Digest4,
        // DB-110 (2026-09-19): THE COMMITMENT TO THE DESTINATION, NEVER THE DESTINATION. The Bitcoin
        // address a redeem pays rides ONLY the per-custodian sealed opening; this object and this
        // statement carry `peg::redeem_commit(address, blind)`, so no relaying node and no chain reader
        // can link a burn to the address that cashes it out.
        redeem_commit: &[u8; 32],
        proposal_nonce: [u8; 32],
        // The burned note's verified cross-bind commit — bound into the statement and carried by the
        // object so every grafting node can justify the note's deletion (§BB for the redeem).
        leaf_commit: crate::spend_frontier::Digest4,
        // ⛔⛔⛔ DB-365 — the change note's commitment the quorum signed (`leaf_to_cm_bytes(out1_cm)`, the burn carrier's
        // out1). The object carries it and `peg_out_tx::decode` refuses a change note of any other commitment.
        change_cm: [u8; 32],
        verifier: &dyn crate::pqauth::PqVerifier,
        attestors: &[crate::psm::MintAttestor],
        change_note: &[u8],
        // ⭐ DB-273 §19 L1 — the change note's OLI clue (empty when there is no change note).
        owner_clue: &[u8],
    ) -> crate::peg::PegOutcome {
        // The checks below mutate nothing; the framed PegOut object goes through `ingest_tx` — that IS
        // the publication — and `apply_peg_out_attested` is the block-driven apply half.
        // DB-273 §19.3 L2: the change owner the v4 statement binds — the ONE rule `peg_out_tx::decode` re-checks.
        let change_owner = crate::peg_out_tx::change_owner_of(owner_clue);
        // ⭐ §BR-5: the cash-out ticket and its epoch ciphertext, as the proposal carried them — the v6 statement binds them
        let ticket_for_block: crate::peg_out_tx::TicketParts = self
            .peg_out_attest_pending
            .get(&usdm_nullifier) // CHAIN-CARRIES-REVIEWED: read to PUBLISH the ticket into the object
            .map(|s| (s.proposal.ticket.clone(), s.proposal.ticket_envelopes.clone(), s.proposal.epoch_ct.clone()))
            .unwrap_or_default();
        // DB-58: the object carries the sealed per-custodian legs the proposal gossiped — v7: the SAME list the quorum
        // signed, read once here for the statement and for the object below.
        let sealed_for_block: Vec<([u8; 32], Vec<u8>)> = self
            .peg_out_attest_pending
            .get(&usdm_nullifier) // CHAIN-CARRIES-REVIEWED: read to PUBLISH the envelopes into the object
            .map(|s| s.proposal.sealed.clone())
            .unwrap_or_default();
        let signed_redeem =
            crate::peg_out_tx::signed_redeem_commit(redeem_commit, &ticket_for_block.0, &ticket_for_block.1, &ticket_for_block.2, &sealed_for_block);
        let outcome = self.peg.check_peg_out_confidential(
            usdm_nullifier,
            carrier_bytes,
            new_reserve_commit,
            new_minted_commit,
            &signed_redeem,
            &proposal_nonce,
            leaf_commit,
            &change_owner,
            &change_cm,
            &self.validators,
            verifier,
            attestors,
        );
        if let crate::peg::PegOutcome::ConfidentialPublished = outcome {
            // ⭐⭐⭐ §CS-b — THE SECOND PEG-OUT DOOR, AND IT NEEDED THE SAME FIX AS THE FIRST.
            //
            // CHAIN-PUBLISH-REVIEWED: this IS the publication — `ingest_tx` of the framed PegOut object,
            // applied by `peg_out_tx::apply_chain_peg_out` on every node that grafts the block.
            //
            // ⛔ THE DETECTOR FOUND THIS ONE, NOT I. After `execute_peg_out_burn_verified` was put on the
            // transaction path, `no_handler_performs_a_consensus_transition_without_publishing_it` still
            // named `rpc_http.rs /peg_out_confidential -> node_mut().peg_out_confidential(..)`: a SECOND,
            // lower-level route reaching the same ledger past the door I had just fixed. Exactly the
            // "check ALL the doors" trap — one fixed publisher does not make a transition travel while a
            // sibling route still writes it locally. This carries no change note (that route supplies
            // none), so the object's note column is empty and it justifies nothing it does not carry.
            let header = crate::peg_out_tx::PegOutHeader {
                usdm_nullifier,
                new_reserve_commit,
                new_minted_commit,
                proposal_nonce,
                leaf_commit,
                change_owner,
                change_cm,
            };
            // ⭐ DB-273 §19.3 L2: the change note's clue rides the OBJECT, under the quorum's v4 statement (`change_owner`),
            // and every node stages its OLI record from the object (`chain_object::object_owner_clue_records`) — so the
            // remainder is findable from the seed on every node, and a relay that strips or replaces the clue voids
            // the object. No per-wallet (bucket, ek) target and no relay-mutable sidecar copy is written.
            let blob = crate::peg_out_tx::wire(
                &header,
                carrier_bytes,
                redeem_commit,
                attestors,
                change_note,
                &sealed_for_block,
                owner_clue,
                &ticket_for_block,
            );
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
            // The lane is cover-padded to the constant width every spend carries, seeded from this tx's own
            // id so every node derives the same wire; the real burn sits among covers (`AssetSpend` shape).
            let padded: Vec<Hash32> =
                crate::cover::pad_tx_nullifiers_to_fixed(&[usdm_nullifier], id.as_bytes())
                    .unwrap_or_else(|| vec![usdm_nullifier])
                    .into_iter()
                    .map(Hash32)
                    .collect();
            // ⭐ A BURN IS A SPEND: it carries the same lane evidence every spend carries (Z1).
            let (nullifier_witnesses, nullifier_absence) =
                self.spend_lane_evidence(&padded.iter().map(|h| *h.as_bytes()).collect::<Vec<_>>());
            let tx = crate::mempool::PqTx {
                clock_ms: 0,
                id,
                blob: blob.clone(),
                weight: blob.len() as u32,
                nullifiers: padded,
                pow_stamp,
                note_clues: Vec::new(),
                account_targets: Vec::new(),
                output_notes: change_note.to_vec(),
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
            if let Err(e) = self.pool_wallet_publication(tx) {
                eprintln!("[peg-out] ⛔ the peg-out object was REFUSED at this node's own pool door: {e:?}");
                return crate::peg::PegOutcome::BadRequest;
            }
        }
        outcome
    }

    /// RECORD a proposal — own (`authored`) or relayed. Returns `true` when it is NEW to this node (first
    /// sight, or the executor re-proposed under moved commitments), which is the re-gossip signal. A
    /// relayed proposal never displaces an authored one for the same deposit, so a stranger cannot reset
    /// the executor's gathering; a changed statement drops the signatures gathered over the old one
    /// (`threshold_ok` fails CLOSED on any stale bonded signature, so none may be kept).
    pub fn peg_attest_note_proposal(
        &mut self,
        p: crate::peg_attest::PegInProposal,
        delta: Option<crate::peg_attest::PegInDelta>,
        authored: bool,
        now_ms: u64,
    ) -> bool {
        use crate::peg_attest::PendingProposal;
        // ⭐ DB-113 — THE ADMISSION STAMP, CHECKED BEFORE A SLOT EXISTS. A relayed proposal costs this node
        // a gathering slot and costs every bonded custodian a signature; unstamped, that work was free to
        // demand and unbounded to supply, which is exactly what made the oldest-first eviction look
        // necessary. An AUTHORED proposal is this node's own and was ground at `propose_peg_in`, so it is
        // not re-judged against a requirement that may have moved since.
        if !authored && p.stamp_work() < self.mempool.required_stamp_bits() {
            return false;
        }
        // ⭐ DB-337: a SETTLED proposal is refused by the chain's set before any slot is touched — so a copy
        // arriving after the tick's sweep freed its slot is never re-admitted as fresh and never relayed again.
        // CHAIN-CARRIES-REVIEWED: the refusal reads the ledger's settled set (block-apply written); the slot is cache.
        if self.peg_in_slot_settled(&p.slot_key()) {
            return false;
        }
        if let Some(slot) = self.peg_attest_pending.get_mut(&p.slot_key()) {
            // ⛔ F-LEG (2026-11-11; the cash-out lane's rule since v7): "the same proposal" is the same STATEMENT — what
            // a custodian signs — and that now names the sealed legs. Compared by commits, recipient and nonce alone, a
            // relayed copy with one leg re-sealed (its stamp re-ground) that reached a custodian first was kept, signed
            // for a statement the executor's object never matches, and every honest re-broadcast was dropped as "the
            // same": that mint stalled for the price of one stamp. Now the honest copy is a different statement and
            // replaces a relayed one (below). cons: two hashes per relayed proposal for a deposit this node tracks.
            let same = slot.proposal.statement() == p.statement();
            if same {
                if delta.is_some() {
                    slot.delta = delta;
                }
                if authored && !slot.authored {
                    // ⛔ A RELAYED SLOT BECOMING AUTHORED STARTS ITS GATHERING FROM ZERO (measured 2026-09-17,
                    // seat journey run 6): node1 had relayed node0's proposal and held both custodians'
                    // signatures over the identical statement (both openings were at genesis); asked to
                    // execute the same deposit, its slot flipped to authored with those signatures inside,
                    // and it published a second object 8.7 s after node0's mint. Signatures are gathered
                    // for the executor that asked — this executor asks now, and the custodian whose chain
                    // already minted the deposit refuses it.
                    slot.attestations.clear();
                }
                slot.authored |= authored;
                return false;
            }
            if slot.authored && !authored {
                return false; // a relayed variant never displaces this executor's own proposal
            }
            slot.proposal = p;
            slot.attestations.clear();
            if delta.is_some() {
                slot.delta = delta;
            }
            slot.authored |= authored;
            return true;
        }
        // DB-113: the mint lane loses its oldest-first eviction for the same reason the redeem lane does —
        // an in-flight mint was being deleted to make room, taking its gathered signatures with it, on a map
        // that nothing ever retired so it filled with settled deposits. `retire_settled_peg_slots` frees
        // what the chain has minted; the admission stamp keeps a stranger from filling the rest.
        self.peg_attest_pending.insert(
            p.slot_key(),
            PendingProposal {
                proposal: p,
                delta,
                authored,
                attestations: Vec::new(),
                first_seen_ms: now_ms,
                last_broadcast_ms: 0,
            },
        );
        true
    }

    /// INGEST one attestation (own, or gossiped). Counted ONLY against a proposal this node holds, ONLY
    /// from a bonded key, ONLY if the signature verifies over that proposal's statement, and ONLY once per
    /// key id. Returns `true` when it was fresh and valid — the re-gossip signal (a vote's shape).
    pub fn peg_attest_ingest(
        &mut self,
        a: &crate::peg_attest::PegInAttestation,
        verifier: &dyn PqVerifier,
    ) -> bool {
        let id = pubkey_id(&a.pubkey);
        if self.validators.bond_of(&id) == 0 {
            return false;
        }
        let Some(slot) = self.peg_attest_pending.get_mut(&a.slot_key()) else {
            return false; // no statement to verify against — never stored unverified
        };
        if slot
            .attestations
            .iter()
            .any(|x| pubkey_id(&x.pubkey) == id)
        {
            return false;
        }
        if slot.attestations.len() >= crate::peg_attest::PEG_ATTEST_SEALED_MAX {
            return false;
        }
        if !verifier.verify(&a.pubkey, &slot.proposal.statement(), &a.sig) {
            return false;
        }
        slot.attestations.push(a.as_attestor());
        // Counts only — never a key or an id.
        eprintln!(
            "[peg-attest] counted a bonded custodian's attestation ({} gathered for this proposal)",
            slot.attestations.len()
        );
        true
    }

    /// The proposal nonce THIS executor uses for a deposit: the one its authored proposal already carries
    /// (stable across polls, so the gathered signatures stay valid), else a fresh one — unique per
    /// (executor, deposit, instant): this node's own DA secret, the deposit and `budget_clock::instance_nonce` (a seed draw on a sim node)
    /// under blake3. The nonce is an instance tag, not a secret.
    #[must_use]
    pub fn peg_proposal_nonce_for(&self, deposit_id: &[u8; 32]) -> [u8; 32] {
        if let Some(slot) = self.peg_attest_pending.get(deposit_id) {
            if slot.authored {
                return slot.proposal.nonce;
            }
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/peg-proposal-nonce/v1");
        h.update(&self.da_secret_value());
        h.update(deposit_id);
        h.update(&crate::budget_clock::instance_nonce());
        *h.finalize().as_bytes()
    }

    /// Remember a peg-in THIS node published (its delta), until a block carries it. Bounded.
    pub(super) fn peg_in_published_remember(&mut self, deposit_id: [u8; 32], delta: crate::peg_attest::PegInDelta) {
        if !self.peg_in_published.contains_key(&deposit_id)
            && self.peg_in_published.len() >= crate::peg_attest::PEG_ATTEST_PENDING_MAX
        {
            if let Some(k) = self.peg_in_published.keys().next().copied() {
                self.peg_in_published.remove(&k);
            }
        }
        self.peg_in_published.insert(deposit_id, delta);
    }

    /// Remember a peg-out THIS node published (its `(release, burn, redeem blind)`), until a block carries it. Bounded.
    pub(super) fn peg_out_published_remember(
        &mut self,
        usdm_nullifier: [u8; 32],
        release: u128,
        burn: u128,
        leg_blind: crate::spend_frontier::Digest4,
    ) {
        if !self.peg_out_published.contains_key(&usdm_nullifier)
            && self.peg_out_published.len() >= crate::peg_attest::PEG_ATTEST_PENDING_MAX
        {
            if let Some(k) = self.peg_out_published.keys().next().copied() {
                self.peg_out_published.remove(&k);
            }
        }
        self.peg_out_published.insert(usdm_nullifier, (release, burn, leg_blind));
    }

    /// Has this node published a peg-out for the burn that no block has carried yet?
    #[must_use]
    pub fn peg_out_is_published(&self, usdm_nullifier: &[u8; 32]) -> bool {
        self.peg_out_published.contains_key(usdm_nullifier)
    }

    /// DB-113 HOUSEKEEPING, run from the tick — not an apply door and not a transition path: free the
    /// gathering slots whose work the CHAIN has already finished. Nothing here completes a transition or
    /// moves a value; every slot it frees is one whose redeem or mint is settled, and the values inside are
    /// discarded rather than read. A slot that outlives its settlement by a few ticks costs only memory,
    /// and one freed early is simply re-recorded by the next relayed copy.
    ///
    /// The settlement itself is decided where it always was: `peg_out_tx::apply_chain_peg_out` and
    /// `peg_in_tx::apply_chain_peg_in` move `peg.spent_burns` / `peg.confidential_deposit_ids` when a BLOCK
    /// carries the object, on every node alike.
    /// ⭐ DB-337 — THE ONE "SETTLED" ANSWER FOR THE ATTESTATION LANES' GATHERING SLOTS, read by the sweep below that
    /// frees a slot AND by the doors that admit a proposal (`peg_attest_note_proposal`, `peg_out_attest_note_proposal`).
    /// MEASURED ([slotB11]): with dedup living only in the slot, a settled proposal's next copy found no slot after the
    /// sweep, answered fresh, and was relayed — the pair ping-ponged two ~1 MB proposals ~900 times each in 25 min.
    /// A settled item is refused by the CHAIN'S SET (the request lane's `ALREADY_REDEEMED` / `ALREADY_MINTED` shape).
    /// §9.6 (admission logic of an existing door changes): (1) PoW: the DB-113 stamp is still checked first; (2) proof:
    /// unchanged, `attest_*` verifies; (3) conservation: refusing a settled proposal gathers nothing and mints nothing;
    /// (4) replay: a settled proposal is refused by `spent_burns` / `confidential_deposit_ids`, written only by block
    /// apply, never by a cache a sweep empties; (5) bounded work: a refused copy costs one set lookup, no slot, no
    /// relay; (6) parity: the `PegRequest` door refuses the same settled items via `peg_request_verify_public`.
    pub(super) fn peg_out_slot_settled(&self, usdm_nullifier: &[u8; 32]) -> bool {
        self.peg.burn_redeemed(usdm_nullifier)
    }
    /// The peg-in twin: `slot_key` is `peg_attest::slot_key_for(asset_id, deposit_id)` — the native deposit id or the
    /// wrapped deposit key, the very key `confidential_deposit_ids` records a native or a wrapped mint under.
    pub(super) fn peg_in_slot_settled(&self, slot_key: &[u8; 32]) -> bool {
        self.peg.deposit_minted(slot_key)
    }

    /// The peg-out twin of `peg_attest_note_proposal`: same slot rules (an authored slot is never
    /// displaced by a relayed variant; a changed statement clears gathered signatures; relayed → authored
    /// clears them too), and the same DB-113 retirement. Gathering state only — the chain decides.
    /// CHAIN-PUBLISH-REVIEWED: an instrument of gathering (`peg_out_attest_pending` is LocalCache); the
    /// ledger moves only at the block door.
    pub fn peg_out_attest_note_proposal(
        &mut self,
        p: crate::peg_attest::PegOutProposal,
        delta: Option<crate::peg_attest::PegOutDelta>,
        authored: bool,
        now_ms: u64,
    ) -> bool {
        use crate::peg_attest::PendingOutProposal;
        // ⭐ DB-113 — THE ADMISSION STAMP, CHECKED BEFORE A SLOT EXISTS. See the mint lane's twin in
        // `peg_attest_note_proposal`: a relayed proposal costs this node a slot and every bonded custodian
        // a signature, so it clears the same bar a pooled transaction clears. An AUTHORED proposal is this
        // node's own and was ground at `propose_peg_out`.
        if !authored && p.stamp_work() < self.mempool.required_stamp_bits() {
            return false;
        }
        // ⭐ DB-337: a SETTLED proposal is refused by the chain's set before any slot is touched — so a copy
        // arriving after the tick's sweep freed its slot is never re-admitted as fresh and never relayed again.
        // CHAIN-CARRIES-REVIEWED: the refusal reads the ledger's settled set (block-apply written); the slot is cache.
        if self.peg_out_slot_settled(&p.usdm_nullifier) {
            return false;
        }
        if let Some(slot) = self.peg_out_attest_pending.get_mut(&p.usdm_nullifier) {
            // ⛔ v7 (F-LEG; dcash on the bus, 2026-11-10): "the same proposal" is the same STATEMENT — what a custodian
            // signs — and since v7 that binds the sealed legs and the ticket's envelopes. Compared by commits, redeem
            // commitment and nonce alone, a relayed copy with one leg re-sealed (and its stamp re-ground) that reached
            // a custodian first was kept, signed for a statement the executor's object never matches, and every honest
            // re-broadcast was dropped as "the same": that redeem stalled for the price of one stamp. Now the honest
            // copy is a different statement and replaces it (below). cons: two hashes per relayed proposal for a
            // nullifier this node already tracks.
            let same = slot.proposal.statement() == p.statement();
            if same {
                if delta.is_some() {
                    slot.delta = delta;
                }
                if authored && !slot.authored {
                    slot.attestations.clear();
                }
                slot.authored |= authored;
                return false;
            }
            if slot.authored && !authored {
                return false;
            }
            slot.proposal = p;
            slot.attestations.clear();
            if delta.is_some() {
                slot.delta = delta;
            }
            slot.authored |= authored;
            return true;
        }
        // ⭐⭐⭐ DB-113 (2026-09-19) — NOTHING AGES OUT OF THIS MAP; ONLY A SETTLED REDEEM LEAVES IT.
        //
        // USER 2026-09-19: "for our pqfrost automated setup there should be no maximum of proposals, this
        // chain is meant to be used by millions so proposal verification should be quick and automatic."
        //
        // TWO DEFECTS STOOD HERE and they compounded into a redeem that stops with no diagnosis:
        //  (1) NOTHING EVER RETIRED A SETTLED SLOT. `peg_out_attest_pending` was removed from in exactly one
        //      place — the oldest-first eviction that stood right here — so every redeem this node ever saw
        //      stayed in the map after the chain had settled it. The map reached its ceiling on DEAD entries
        //      alone, on any node up long enough, whatever the live load.
        //  (2) THE EVICTION THEN TOOK LIVE ONES. The victim search preferred a relayed slot but fell through
        //      to `min_by_key` over ALL slots, so once the map held this node's own AUTHORED redeems the
        //      oldest of those was deleted MID-GATHERING and its gathered signatures went with it. No USDm
        //      was destroyed (a burn publishes only with its quorum), but the redeem simply stopped.
        //
        // This is the `payments_in_flight` shape exactly: a gauge of unresolved work behind an oldest-first
        // ring reads "nothing pending" precisely when something is stuck. Same fix — RETAIN UNRESOLVED
        // ENTRIES AT ANY AGE, and retire only what the chain has settled, which `retire_settled_peg_slots`
        // does from the tick. The map is then bounded by how many redeems are genuinely in flight, which the
        // chain's own settlement governs, and DB-113's admission stamp is what stops a stranger adding to
        // that count for free.
        // ⛔ ONE SMALL SIZE: a RELAYED proposal's carriers are verified from the wire copy the
        // custodian was handed (`attest_peg_out` takes `p`, not the slot) and are never read from the
        // slot again — the slot keeps the statement (commits, destination, nonce) it dedups and
        // signs over, and the delta it opened. Only the executor's AUTHORED slot keeps the carriers,
        // for its own re-broadcast. So the pending map is PEG_ATTEST_PENDING_MAX statements plus at
        // most this node's own authored redeems, never 64 × two carriers of relayed bytes.
        let mut p = p;
        if !authored {
            p.burn_carrier = Vec::new();
            p.membership_carrier = Vec::new();
            p.membership_tip = Vec::new();
        }
        self.peg_out_attest_pending.insert(
            p.usdm_nullifier,
            PendingOutProposal {
                proposal: p,
                delta,
                authored,
                attestations: Vec::new(),
                first_seen_ms: now_ms,
                last_broadcast_ms: 0,
            },
        );
        true
    }

    /// Count one custodian's peg-out attestation against a held proposal — bonded key, verified over the
    /// proposal's statement, once per key. The peg-out twin of `peg_attest_ingest`.
    /// CHAIN-PUBLISH-REVIEWED: gathering state only (`peg_out_attest_pending` is LocalCache).
    pub fn peg_out_attest_ingest(
        &mut self,
        a: &crate::peg_attest::PegOutAttestation,
        verifier: &dyn PqVerifier,
    ) -> bool {
        let id = pubkey_id(&a.pubkey);
        if self.validators.bond_of(&id) == 0 {
            return false;
        }
        let Some(slot) = self.peg_out_attest_pending.get_mut(&a.usdm_nullifier) else {
            return false;
        };
        if slot.attestations.iter().any(|x| pubkey_id(&x.pubkey) == id) {
            return false;
        }
        if slot.attestations.len() >= crate::peg_attest::PEG_ATTEST_SEALED_MAX {
            return false;
        }
        if !verifier.verify(&a.pubkey, &slot.proposal.statement(), &a.sig) {
            return false;
        }
        slot.attestations.push(a.as_attestor());
        eprintln!(
            "[peg-out-attest] counted a bonded custodian's attestation ({} gathered for this redeem)",
            slot.attestations.len()
        );
        true
    }

    /// The attestations gathered for THIS executor's OWN peg-out proposal (authored slots only).
    #[must_use]
    pub fn peg_out_attestations_for(&self, usdm_nullifier: &[u8; 32]) -> Vec<crate::psm::MintAttestor> {
        self.peg_out_attest_pending
            .get(usdm_nullifier)
            .filter(|s| s.authored)
            .map(|s| s.attestations.clone())
            .unwrap_or_default()
    }

    /// CHAIN-PUBLISH-REVIEWED: a broadcast-cadence stamp on gathering state; nothing of the ledger.
    pub fn peg_out_attest_due_for_broadcast(&mut self, usdm_nullifier: &[u8; 32], now_ms: u64) -> Option<Vec<u8>> {
        let slot = self.peg_out_attest_pending.get_mut(usdm_nullifier)?;
        if !slot.authored {
            return None;
        }
        if now_ms.saturating_sub(slot.last_broadcast_ms) < crate::peg_attest::PEG_ATTEST_REBROADCAST_MS {
            return None;
        }
        slot.last_broadcast_ms = now_ms;
        Some(slot.proposal.wire())
    }

    pub fn peg_out_attest_own_for(&self, usdm_nullifier: &[u8; 32], signer_pk: &[u8]) -> Option<crate::peg_attest::PegOutAttestation> {
        let id = pubkey_id(signer_pk);
        let slot = self.peg_out_attest_pending.get(usdm_nullifier)?;
        let a = slot.attestations.iter().find(|x| pubkey_id(&x.pubkey) == id)?;
        Some(crate::peg_attest::PegOutAttestation {
            usdm_nullifier: *usdm_nullifier,
            pubkey: a.pubkey.clone(),
            sig: a.sig.clone(),
        })
    }

    pub fn peg_out_proposal_nonce_for(&self, usdm_nullifier: &[u8; 32]) -> [u8; 32] {
        if let Some(slot) = self.peg_out_attest_pending.get(usdm_nullifier) {
            if slot.authored {
                return slot.proposal.nonce;
            }
        }
        let mut h = blake3::Hasher::new();
        h.update(b"MUSD/peg-out-proposal-nonce/v1");
        h.update(&self.da_secret_value());
        h.update(usdm_nullifier);
        h.update(&crate::budget_clock::instance_nonce());
        *h.finalize().as_bytes()
    }

    /// The pooled peg-in object for a deposit, if this node's pool still holds it (O(pool), pool bounded).
    pub(super) fn peg_in_pooled_tx_for(&self, deposit_id: &[u8; 32]) -> Option<Hash32> {
        for raw in self.mempool.all_tx_ids() {
            let id = Hash32(raw);
            if let Some(tx) = self.mempool.get(&id) {
                if let Some((crate::chain_object::Class::PegIn, payload)) = crate::chain_object::unframe(&tx.blob) {
                    if let Some((h, ..)) = crate::peg_in_tx::decode(payload) {
                        if h.deposit_id == *deposit_id {
                            return Some(id);
                        }
                    }
                }
            }
        }
        None
    }

    /// DB-5, the executor's poll: a published mint counts as "in flight" only while its object is still
    /// in this node's pool. A jump that swapped the chain drops it (see `resync_custodian_opening_to_chain`)
    /// or the pool retired it — either way the caller must propose afresh rather than report
    /// `CONFIDENTIAL_PUBLISHED` forever (measured 2026-09-17: runs 3, 4 and 9 of the wallet journey).
    /// CHAIN-PUBLISH-REVIEWED: local bookkeeping; the fresh proposal the caller then makes IS the publish.
    pub fn peg_in_published_still_pooled(&mut self, deposit_id: &[u8; 32]) -> bool {
        if !self.peg_in_published.contains_key(deposit_id) {
            return false;
        }
        if self.peg_in_pooled_tx_for(deposit_id).is_some() {
            return true;
        }
        self.peg_in_published.remove(deposit_id);
        self.peg_attest_pending.remove(deposit_id);
        eprintln!("[peg-attest] the published mint's object is no longer pooled — proposing it afresh (DB-5)");
        false
    }

    /// Has this node published a peg-in for the deposit that no block has carried yet?
    #[must_use]
    pub fn peg_in_is_published(&self, deposit_id: &[u8; 32]) -> bool {
        self.peg_in_published.contains_key(deposit_id)
    }

    /// The height a recently-applied peg-in grafted at, if this node still remembers it (0 = unknown; a
    /// wallet then rescans from its own cursor floor rather than skipping past the note).
    #[must_use]
    pub fn peg_minted_height(&self, deposit_id: &[u8; 32]) -> u64 {
        self.peg_minted_heights.get(deposit_id).copied().unwrap_or(0)
    }

    /// The verified signatures gathered for a deposit — for a proposal THIS NODE AUTHORED only.
    ///
    /// ⛔ A RELAYED PROPOSAL'S SIGNATURES ARE NOT THIS NODE'S TO SPEND (measured 2026-09-17, seat journey
    /// run 5): node1 had relayed node0's proposal and counted both custodians' attestations on it; asked
    /// to execute the same deposit 0.2 s after node0 minted, and not yet holding node0's block, it passed
    /// threshold on those borrowed signatures and PUBLISHED a second object for the deposit. The chain
    /// refuses that object as `Replay` at apply, so nothing minted twice — but a custodian's signature was
    /// gathered for ONE executor's statement, and only that executor's poll may present it.
    pub fn peg_attestations_for(&self, deposit_id: &[u8; 32]) -> Vec<crate::psm::MintAttestor> {
        self.peg_attest_pending
            .get(deposit_id)
            .filter(|s| s.authored)
            .map(|s| s.attestations.clone())
            .unwrap_or_default()
    }

    /// This node's own pending proposal for a deposit, and whether it is due for a re-broadcast.
    pub fn peg_attest_due_for_broadcast(&mut self, deposit_id: &[u8; 32], now_ms: u64) -> Option<Vec<u8>> {
        let slot = self.peg_attest_pending.get_mut(deposit_id)?;
        if !slot.authored {
            return None;
        }
        if now_ms.saturating_sub(slot.last_broadcast_ms) < crate::peg_attest::PEG_ATTEST_REBROADCAST_MS {
            return None;
        }
        slot.last_broadcast_ms = now_ms;
        Some(slot.proposal.wire())
    }

    /// The attestation this node already produced for a relayed proposal, if any — re-sent on a repeat
    /// request without re-proving.
    /// DB-85: the statement of the proposal this node's slot holds for a key (its own, if it authored one).
    #[must_use]
    pub fn peg_attest_slot_statement(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        // CHAIN-CARRIES-REVIEWED: the lane's own slot, read to compare statements before re-sending a signature
        self.peg_attest_pending.get(key).map(|s| s.proposal.statement())
    }
    /// DB-85: the peg-out twin of `peg_attest_slot_statement`.
    #[must_use]
    pub fn peg_out_attest_slot_statement(&self, usdm_nullifier: &[u8; 32]) -> Option<Vec<u8>> {
        // CHAIN-CARRIES-REVIEWED: the lane's own slot, read to compare statements before re-sending a signature
        self.peg_out_attest_pending.get(usdm_nullifier).map(|s| s.proposal.statement())
    }
    pub fn peg_attest_own_for(&self, deposit_id: &[u8; 32], signer_pk: &[u8]) -> Option<crate::peg_attest::PegInAttestation> {
        let id = pubkey_id(signer_pk);
        let slot = self.peg_attest_pending.get(deposit_id)?;
        let a = slot.attestations.iter().find(|x| pubkey_id(&x.pubkey) == id)?;
        Some(crate::peg_attest::PegInAttestation {
            asset_id: slot.proposal.asset_id,
            deposit_id: slot.proposal.deposit_id,
            pubkey: a.pubkey.clone(),
            sig: a.sig.clone(),
        })
    }

    /// LIQUIDATION §10 — this custodian's opening of PSM `asset_id`'s pool words, or `None` when it does not open the
    /// chain's CURRENT words (stale after a jump or a restart; it may not build against them).
    pub(crate) fn pool_opening_now(&self, asset_id: u32) -> Option<PoolOpening> {
        let words = self.peg.pool_words(asset_id);
        let o = match self.pool_openings.get(&asset_id) {
            Some(o) => *o,
            None => PoolOpening::genesis(), // never advanced here: the public genesis opening
        };
        (o.words(words.epoch) == words).then_some(o)
    }

    /// LIQUIDATION §10 — the snapshot a depositor keys its receipt to: fresh `(PD, SD)` re-randomizing the pool's current
    /// `(P, S)`, with blinds DERIVED from this custodian's pool blinds and the requester's `nonce` (no state is kept; the
    /// same nonce re-derives the same grant at execute). `None` when this node holds no current pool opening.
    #[must_use]
    pub fn pool_snapshot_grant(&self, asset_id: u32, nonce: u128) -> Option<PoolSnapshotGrant> {
        use usdm_decider::confidential_solvency::solvency_commit_256;
        if !self.is_psm(asset_id) {
            return None;
        }
        let o = self.pool_opening_now(asset_id)?;
        let epoch = self.peg.pool_words(asset_id).epoch;
        let pd_blind = yield_blind(b"USDMD-POOL-PD", &o.p_blind, nonce);
        let sd_blind = yield_blind(b"USDMD-POOL-SD", &o.s_blind, nonce);
        Some(PoolSnapshotGrant {
            asset_id,
            epoch,
            pd: solvency_commit_256(o.p, pd_blind),
            sd: solvency_commit_256(o.s, sd_blind),
            p: o.p,
            pd_blind,
            s: o.s,
            sd_blind,
        })
    }

    /// Record a request this node has seen. `own` = this node's own wallet asked (the request is kept
    /// to re-gossip until the chain settles it); `keep` = keep the payload (a custodian that will act
    /// on it). Returns whether it was FRESH (first sight → the caller relays it once).
    pub fn peg_request_note(
        &mut self,
        req: &crate::peg_attest::PegRequest,
        own: bool,
        keep: bool,
        now_ms: u64,
    ) -> bool {
        use crate::peg_attest::{PegRequestSlot, PEG_ATTEST_PENDING_MAX};
        let key = req.slot_key();
        if let Some(slot) = self.peg_requests.get_mut(&key) {
            // ⭐ A-F78 (lane af58, 2026-11-16): a variant that names a custodian this slot has not seen an envelope for is
            // FRESH (relayed once more), so a requester's re-seal to a vault's new member crosses every relay that held the
            // first variant; ids past PEG_SEEN_IDS_MAX are not remembered (the bound a stream of made-up ids meets).
            let mut new_ids = false;
            for (id, _) in &req.sealed {
                if !slot.seen_ids.contains(id) && slot.seen_ids.len() < crate::peg_attest::PEG_SEEN_IDS_MAX {
                    slot.seen_ids.push(*id);
                    new_ids = true;
                }
            }
            if own {
                slot.own = true;
            }
            if (own || keep) && slot.request.is_none() {
                slot.request = Some(req.clone());
            } else if own && new_ids {
                // ONLY the requester's own door replaces what it re-gossips (`own` is set by `publish_peg_request` alone),
                // and only by a variant naming new custodians: a relayed variant never displaces it, so a junk envelope
                // cannot stand in for the honest one. The door sealed the same body again (`peg_attest::covers`).
                slot.request = Some(req.clone());
            }
            return new_ids;
        }
        if self.peg_requests.len() >= PEG_ATTEST_PENDING_MAX {
            let victim = self
                .peg_requests
                .iter()
                .filter(|(_, s)| !s.own)
                .min_by_key(|(_, s)| s.first_seen_ms)
                .or_else(|| self.peg_requests.iter().min_by_key(|(_, s)| s.first_seen_ms))
                .map(|(k, _)| *k);
            if let Some(k) = victim {
                self.peg_requests.remove(&k);
            }
        }
        self.peg_requests.insert(
            key,
            PegRequestSlot {
                kind: req.kind,
                asset_id: req.asset_id,
                id: req.id,
                own,
                request: if own || keep { Some(req.clone()) } else { None },
                secret: None,
                first_seen_ms: now_ms,
                last_broadcast_ms: 0,
                last_action_ms: 0,
                proposed: false,
                publish_after_ms: None,
                done: false,
                relay_after_ms: 0,
                seen_ids: req.sealed.iter().map(|(id, _)| *id).take(crate::peg_attest::PEG_SEEN_IDS_MAX).collect(),
                own_secret: None,
            },
        );
        true
    }

    /// ⭐ A-F78 — THE ONE ANSWER to "which custodians is this request sealed to now": a bridge deposit (native or a coin ledger)
    /// to the members of the vault its reserve address belongs to (none when the address is no vault's: nothing to seal), any
    /// other request to every bonded custodian. The request doors and the re-seal (`peg_requests_due_for_broadcast`) read it.
    #[must_use]
    pub fn request_seal_set(&self, kind: u8, asset_id: u32, s: &crate::peg_attest::RequestSecret) -> Vec<([u8; 32], Vec<u8>)> {
        use crate::peg_attest::{PEG_REQUEST_IN, PEG_REQUEST_WRAPPED};
        let vaulted = kind == PEG_REQUEST_IN || (kind == PEG_REQUEST_WRAPPED && crate::peg::PegLedger::is_coin_ledger(asset_id));
        if !vaulted {
            return self.validators.bonded_custodian_eks();
        }
        self.vault_of_reserve_address(&s.address, &s.d_blind, s.sweep.as_ref().map(|a| &a.depositor_x))
            .map(|v| self.custodian_eks_of_vault(v))
            .unwrap_or_default()
    }

    /// ⭐ A-F78 — keep this node's OWN wallet's secret beside its own request (`PegRequestSlot::own_secret`), so the re-gossip
    /// tick can seal the same request to a custodian that joined since. Called by the request doors right after they publish.
    pub fn peg_request_own_secret(&mut self, key: &[u8; 32], secret: crate::peg_attest::RequestSecret) {
        if let Some(s) = self.peg_requests.get_mut(key).filter(|s| s.own) {
            s.own_secret = Some(secret);
        }
    }

    /// ⭐ §19.4 — hold this node's own request `key` from the mesh until `relay_after_ms` (the claim's drawn relay moment).
    pub fn peg_request_relay_after(&mut self, key: &[u8; 32], relay_after_ms: u64) {
        if let Some(s) = self.peg_requests.get_mut(key).filter(|s| s.own) {
            s.relay_after_ms = relay_after_ms;
        }
    }

    #[must_use]
    pub fn peg_request_slot(&self, key: &[u8; 32]) -> Option<&crate::peg_attest::PegRequestSlot> {
        self.peg_requests.get(key)
    }

    /// Has the CHAIN settled this request (applied from a block on this node)? Chain state, never a slot.
    #[must_use]
    pub fn peg_request_settled(&self, kind: u8, asset_id: u32, id: &[u8; 32]) -> bool {
        use crate::peg_attest::{PEG_REQUEST_IN, PEG_REQUEST_OUT, PEG_REQUEST_STAKE, PEG_REQUEST_WRAPPED};
        match kind {
            PEG_REQUEST_IN => self.peg.deposit_minted(id),
            PEG_REQUEST_OUT => self.peg.burn_redeemed(id),
            PEG_REQUEST_WRAPPED => self.peg.wrapped_deposit_minted(asset_id, id),
            // §17.6: a stake is settled when the chain spent its input (the spent SET, never a slot)
            PEG_REQUEST_STAKE => self.sparse_spent_verdict(id) == crate::nf_sparse::SpentVerdict::Spent,
            _ => true,
        }
    }

    /// The requester's own requests due for re-gossip (every PEG_REQUEST_REBROADCAST_MS until the chain
    /// settles them); settled slots are forgotten here. Returns the wires to queue.
    pub fn peg_requests_due_for_broadcast(&mut self, now_ms: u64) -> Vec<Vec<u8>> {
        let settled: Vec<[u8; 32]> = self
            .peg_requests
            .iter()
            .filter(|(_, s)| self.peg_request_settled(s.kind, s.asset_id, &s.id))
            .map(|(k, _)| *k)
            .collect();
        for k in settled {
            self.peg_requests.remove(&k);
        }
        // ⭐ A-F78 (lane af58, 2026-11-16) — THE ONE RE-SEAL, for every kind the request lane carries: this node's own request is
        // sealed again, to the custodians it would seal to NOW (`request_seal_set`), whenever the one it holds carries no
        // envelope for one of them (`peg_attest::covers`) — a custodian joined the vault after the request was made. The body is
        // unchanged, so it is the same mint; only the envelopes and the stamp over them are new, and the variant goes out at
        // once (relays pass it on: `peg_request_note` answers fresh for an id they have not seen). Before, a request was sealed
        // once and a deposit made while a custodian joined never minted (MEASURED 2026-11-16 07:00, rig speed5wrap).
        // AI RESISTANT: (b) code; the mint still needs the quorum's signatures over the same body. SCALE: O(members) a due
        // own request, at most PEG_ATTEST_PENDING_MAX of them; constant in height and in the bonded set.
        let reseal: Vec<([u8; 32], crate::peg_attest::PegRequest)> = self
            .peg_requests
            .iter()
            .filter(|(_, s)| s.own && !s.done)
            .filter_map(|(k, s)| {
                let (held, secret) = (s.request.as_ref()?, s.own_secret.as_ref()?);
                let set = self.request_seal_set(held.kind, held.asset_id, secret);
                let ids: Vec<[u8; 32]> = set.iter().map(|(id, _)| *id).collect();
                if ids.is_empty() || crate::peg_attest::covers(Some(held), &ids) {
                    return None;
                }
                let mut req = held.clone();
                req.sealed = set
                    .iter()
                    .filter_map(|(id, ek)| match held.envelope_for(id) {
                        Some(b) => Some((*id, b.to_vec())),
                        None => crate::peg_attest::seal_request_to(ek, secret).map(|b| (*id, b)),
                    })
                    .collect();
                req.stamp_to(self.required_stamp_bits());
                // DIGITAL-CASH-PRIVACY-REVIEWED: two counts of custodians and the public request kind; no id, amount or key.
                eprintln!(
                    "[peg-request] A-F78: an own request of kind {} was sealed to {} custodian(s); its set is now {}: sealed again",
                    held.kind,
                    held.sealed.len(),
                    req.sealed.len()
                );
                Some((*k, req))
            })
            .collect();
        for (k, req) in reseal {
            if let Some(s) = self.peg_requests.get_mut(&k) {
                for (id, _) in &req.sealed {
                    if !s.seen_ids.contains(id) && s.seen_ids.len() < crate::peg_attest::PEG_SEEN_IDS_MAX {
                        s.seen_ids.push(*id);
                    }
                }
                s.request = Some(req);
                s.last_broadcast_ms = 0; // out at once, below
            }
        }
        let mut out = Vec::new();
        for s in self.peg_requests.values_mut() {
            if !s.own || s.done || now_ms < s.relay_after_ms {
                continue;
            }
            if now_ms.saturating_sub(s.last_broadcast_ms) < crate::peg_attest::PEG_REQUEST_REBROADCAST_MS {
                continue;
            }
            if let Some(r) = s.request.as_ref() {
                s.last_broadcast_ms = now_ms;
                out.push(r.wire());
            }
        }
        out
    }

    /// What ANY node verifies about a request WITHOUT the sealed secret: the admission stamp, the
    /// chain-state replay answer, the note's shape, and for a redeem the burned note's on-chain
    /// membership cross-bind and its presence in the live unspent tree. Bounds live in `decode`.
    pub fn peg_request_verify_public(&self, req: &crate::peg_attest::PegRequest) -> Result<(), &'static str> {
        use crate::peg_attest::{PEG_REQUEST_IN, PEG_REQUEST_OUT, PEG_REQUEST_WRAPPED};
        // The relay floor is the chain's BASE stamp, not this node's occupancy-adaptive requirement: the
        // requester cannot know a far custodian's pool fullness, and a request refused for a stamp the
        // requester could not have predicted is a liveness hole (Bitcoin's analogue: a static min relay
        // fee). Requests are bounded by PEG_ATTEST_PENDING_MAX slots and deduped by id, so the floor holds.
        if req.stamp_work() < self.params().pow_stamp_base_bits {
            return Err("STAMP");
        }
        if crate::spend_frontier::note_cm_of(&req.note_payload).is_none() {
            return Err("NOTE");
        }
        match req.kind {
            PEG_REQUEST_IN => {
                if self.peg.deposit_minted(&req.id) {
                    return Err("ALREADY_MINTED");
                }
                // DB-80: any node verifies the mint-validity carrier against the request's COMMITTED delta
                // — the amount is sealed to custodians only; the carrier still binds the note to it.
                if let Some(cm) = crate::spend_frontier::note_cm_of(&req.note_payload) {
                    if !usdm_decider::whir_rec_block::verify_mint_validity_committed_bytes(&req.carrier, cm, req.delta_commit) {
                        return Err("MINT_CARRIER");
                    }
                }
            }
            PEG_REQUEST_WRAPPED => {
                if self.peg.wrapped_asset_ratio_bps(req.asset_id).is_none() {
                    return Err("ASSET");
                }
                if self.peg.wrapped_deposit_minted(req.asset_id, &req.id) {
                    return Err("ALREADY_MINTED");
                }
                // DB-80b: the request's note opens to the committed delta in the named asset
                if let Some(cm) = crate::spend_frontier::note_cm_of(&req.note_payload) {
                    if !usdm_decider::whir_rec_block::verify_asset_mint_validity_committed_bytes(
                        &req.carrier,
                        cm,
                        usdm_decider::whir_rec_block::wrapped_asset_tag_u32(req.asset_id),
                        req.delta_commit,
                    ) {
                        return Err("MINT_CARRIER");
                    }
                }
            }
            PEG_REQUEST_OUT => {
                if self.peg.burn_redeemed(&req.id) {
                    return Err("ALREADY_REDEEMED");
                }
                if crate::spend_frontier::cm_bytes_to_root(&req.id).is_none() {
                    return Err("NULLIFIER");
                }
                // A-F64: the membership check is SKIPPED here — the receiver's fold may lag the sender's,
                // so a valid proof created against the sender's tree fails Pending on a node that hasn't
                // folded the same record yet. The request is noted and the tick retries; the custodian's
                // own gate (propose_peg_out) checks membership at proposal time, when the fold has caught up.
                // DoS is bounded by the stamp (line 2511) and the pending-slots limit.
                // Z1: the burned note is named by its NULLIFIER (`req.id` on a redeem); a tag this node
                // already holds spent is refused here, before any custodian work.
                if self.sparse_spent_verdict(&req.id) == crate::nf_sparse::SpentVerdict::Spent {
                    return Err("ALREADY_SPENT");
                }
            }
            crate::peg_attest::PEG_REQUEST_STAKE => {
                // §17.6 — everything a stake proves without its sealed reward: the input unspent, its membership, the
                // governance rate, and the stake carrier against the request's own statement.
                if self.sparse_spent_verdict(&req.id) == crate::nf_sparse::SpentVerdict::Spent {
                    return Err("ALREADY_SPENT");
                }
                let Some((h, _, _, _)) = crate::stake_tx::request_parts(req) else {
                    return Err("STAKE_FIELDS");
                };
                if h.rate_bps != self.params().stake_reward_apr_bps {
                    return Err("RATE");
                }
                let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&req.id) else {
                    return Err("NULLIFIER");
                };
                let Some(Some(lc)) = self.check_bond_membership(
                    Some((&req.membership_carrier, &req.membership_tip, req.leaf_commit, binder)),
                    crate::respend::MemberDoor::Admit,
                ) else {
                    return Err("MEMBERSHIP");
                };
                let Some(stmt) = crate::stake_tx::statement(&h) else {
                    return Err("STAKE_FIELDS");
                };
                if lc != h.leaf_commit
                    || !usdm_decider::whir_rec_block::verify_stake_carrier_bytes(&req.carrier, &stmt, h.e_now, u64::from(h.rate_bps))
                {
                    return Err("STAKE_CARRIER");
                }
            }
            _ => return Err("KIND"),
        }
        Ok(())
    }

    /// Authored proposals whose attestation request should be re-gossiped (the cadence lives in the
    /// per-lane `*_due_for_broadcast`): `(key, is_redeem)`.
    #[must_use]
    pub fn peg_lane_rebroadcasts_due(&self) -> Vec<([u8; 32], bool)> {
        self.peg_requests
            .iter()
            .filter(|(_, s)| s.proposed && !s.done)
            .map(|(k, s)| if s.kind == crate::peg_attest::PEG_REQUEST_OUT { (s.id, true) } else { (*k, false) })
            .collect()
    }

    /// The requester's OWN node verifies a redeem request in full before it asks the mesh: everything
    /// `peg_request_verify_public` checks PLUS the burn carrier at the amount the wallet stated (the
    /// custodians re-run this at the sealed amount; a mismatch there proposes nothing).
    pub fn peg_out_request_verify_full(
        &self,
        req: &crate::peg_attest::PegRequest,
        burn_amount: u128,
        // ⭐ B15: the piece's leg blind — the committed burn opens `peg_out_burn_commit(burn_amount, leg_blind)`
        leg_blind: &crate::spend_frontier::Digest4,
    ) -> Result<(), &'static str> {
        self.peg_request_verify_public(req)?;
        let Some(binder) = crate::spend_frontier::cm_bytes_to_root(&req.id) else {
            return Err("NULLIFIER");
        };
        let Some(Some(lc)) = self.check_bond_membership(Some((
            &req.membership_carrier,
            &req.membership_tip,
            req.leaf_commit,
            binder,
        )), crate::respend::MemberDoor::Admit) else {
            return Err("MEMBERSHIP");
        };
        let Some(nf_limbs) = crate::spend_frontier::cm_bytes_to_root(&req.id) else {
            return Err("NULLIFIER");
        };
        if !crate::peg_out_tx::burn_carrier_verifies(req.asset_id, &req.carrier, req.out0_cm, req.out1_cm, nf_limbs, lc, crate::peg::peg_out_burn_commit(burn_amount, leg_blind)) {
            return Err("BURN_CARRIER");
        }
        Ok(())
    }

    /// Requests this custodian holds a secret for but has not proposed yet (its watcher did not confirm
    /// at first sight) — re-tried every PEG_REQUEST_REBROADCAST_MS by the runtime tick.
    pub fn peg_requests_awaiting_action(
        &mut self,
        now_ms: u64,
    ) -> Vec<(crate::peg_attest::PegRequest, crate::peg_attest::RequestSecret)> {
        // A slot recorded with its payload but no opened secret — this node had no custody identity when
        // the request arrived (its own wallet asked before it bonded; a relayed request seen before the
        // seat) — is opened now that it has one. Without this a node that became a custodian after a
        // request never acted on it (the wrapped route pin, 2026-09-19, after DB-93 made the poll and the
        // request one slot).
        // class 4: a node without a live custody seat acts on no request — not even one it opened while seated
        if self.bonded_custodian_identity().is_none() {
            return Vec::new();
        }
        let opened: Vec<([u8; 32], crate::peg_attest::RequestSecret)> = self
            .peg_requests
            .iter()
            .filter(|(_, s)| !s.proposed && !s.done && s.secret.is_none())
            .filter_map(|(k, s)| {
                let r = s.request.as_ref()?;
                self.custodian_open_request(r).map(|sec| (*k, sec))
            })
            .collect();
        for (k, sec) in opened {
            if let Some(s) = self.peg_requests.get_mut(&k) {
                s.secret = Some(sec);
                eprintln!("[peg-request] opened a request slot recorded before this node had its custody identity");
            }
        }
        let mut out = Vec::new();
        for s in self.peg_requests.values_mut() {
            if s.proposed || s.done {
                continue;
            }
            if now_ms.saturating_sub(s.last_action_ms) < crate::peg_attest::PEG_REQUEST_REBROADCAST_MS {
                continue;
            }
            if let (Some(r), Some(sec)) = (s.request.as_ref(), s.secret.as_ref()) {
                s.last_action_ms = now_ms;
                out.push((r.clone(), sec.clone()));
            }
        }
        out
    }

    /// Authored proposals this custodian holds whose gathered signatures (plus its own) meet the ≥2/3
    /// weight — due to PUBLISH. The lowest-id attestor publishes at once; every other custodian backs off
    /// PEG_PUBLISH_BACKOFF_MS and publishes only if the chain has not settled it by then (the chain applies
    /// exactly one; a second is `Replay`). Returns the slot keys due now.
    pub fn peg_lane_completions_due(&mut self, now_ms: u64) -> Vec<[u8; 32]> {
        use crate::peg_attest::{PEG_PUBLISH_BACKOFF_MS, PEG_REQUEST_IN, PEG_REQUEST_OUT, PEG_REQUEST_WRAPPED};
        let Some(my_id) = self.bonded_custodian_identity().map(|(id, _)| *id) else {
            return Vec::new();
        };
        let keys: Vec<[u8; 32]> = self
            .peg_requests
            .iter()
            .filter(|(_, s)| s.proposed && !s.done && s.secret.is_some())
            .map(|(k, _)| *k)
            .collect();
        let mut due = Vec::new();
        for key in keys {
            let (kind, asset_id, id) = match self.peg_requests.get(&key) {
                Some(s) => (s.kind, s.asset_id, s.id),
                None => continue,
            };
            if self.peg_request_settled(kind, asset_id, &id) {
                if let Some(s) = self.peg_requests.get_mut(&key) {
                    s.done = true;
                }
                continue;
            }
            // Already published and still pooled → the block will settle it; nothing to do. Published but
            // GONE from the pool without applying (DB-5) → clear and re-propose.
            let published = match kind {
                PEG_REQUEST_IN => {
                    if self.peg_in_is_published(&id) {
                        if self.peg_in_published_still_pooled(&id) {
                            true
                        } else {
                            if let Some(s) = self.peg_requests.get_mut(&key) {
                                s.proposed = false;
                                s.publish_after_ms = None;
                            }
                            continue;
                        }
                    } else {
                        false
                    }
                }
                PEG_REQUEST_OUT => self.peg_out_is_published(&id),
                PEG_REQUEST_WRAPPED => self.wrapped_mint_is_published(&key),
                _ => true,
            };
            if published {
                continue;
            }
            // CHAIN-CARRIES-REVIEWED: the lane's OWN authored slot, read to count gathered signatures and decide WHEN to publish; the publish re-tallies at the door and only a block settles the request
            let attestor_ids: Option<Vec<[u8; 32]>> = match kind {
                PEG_REQUEST_OUT => self
                    .peg_out_attest_pending
                    .get(&id) // CHAIN-CARRIES-REVIEWED: same — the lane's own authored redeem slot
                    .filter(|s| s.authored)
                    .map(|s| s.attestations.iter().map(|a| pubkey_id(&a.pubkey)).collect()),
                _ => self
                    .peg_attest_pending
                    .get(&key) // CHAIN-CARRIES-REVIEWED: same — the lane's own authored mint slot
                    .filter(|s| s.authored)
                    .map(|s| s.attestations.iter().map(|a| pubkey_id(&a.pubkey)).collect()),
            };
            let Some(mut ids) = attestor_ids else {
                continue;
            };
            if !ids.contains(&my_id) {
                ids.push(my_id); // the publish adds this custodian's own signature
            }
            // SAFE AT SCALE: the SAME rule the ledger door tallies under (`PegLedger::signer_ids_suffice`): a cash-out by its
            // paying vault's own two thirds; a deposit this vault's quorum carries alone (its legs went to the vault's own
            // members) by the same; any other mint by the whole set's two thirds with the vault's own beside them. On a
            // one-vault chain: two thirds of the bonded weight, as it was.
            let own = self.my_custody_vault().unwrap_or_default();
            let alone = kind == PEG_REQUEST_IN
                && self
                    .peg_attest_pending
                    .get(&key) // CHAIN-CARRIES-REVIEWED: the lane's own authored slot, read to count signers only
                    .is_some_and(|s| !s.proposal.sealed.is_empty() && s.proposal.sealed.iter().all(|(id, _)| own.binary_search(id).is_ok()));
            if !crate::peg::PegLedger::signer_ids_suffice(&self.validators, self.vault_here(), alone, kind == PEG_REQUEST_OUT, &ids) {
                continue;
            }
            let min_id = ids.iter().min().copied().unwrap_or(my_id);
            let Some(slot) = self.peg_requests.get_mut(&key) else {
                continue;
            };
            if min_id == my_id {
                // the first publisher publishes at once, and after a refused publish waits PEG_PUBLISH_BACKOFF_MS like
                // everyone else: each publish is a full solvency prove, and one refused object was re-proven on every
                // tick (MEASURED 2026-11-08, real nodes: 4,061 publishes of one wrapped mint in about 40 minutes)
                if slot.publish_after_ms.map_or(true, |t| now_ms >= t) {
                    due.push(key);
                }
            } else {
                match slot.publish_after_ms {
                    None => slot.publish_after_ms = Some(now_ms + PEG_PUBLISH_BACKOFF_MS),
                    Some(t) if now_ms >= t => due.push(key),
                    _ => {}
                }
            }
        }
        due
    }

    /// The note-membership cross-bind a BOND-class carrier may ride: `(carrier, tip96, leaf_commit)`.
    ///
    /// `None` keeps the pre-existing behaviour EXACTLY — the bond carrier stays welded to the live root.
    /// `Some(..)` means membership is proven by the accumulator fold instead, so the moving root binds
    /// nothing and ONE attempt always suffices. Fail-closed: a present-but-unverifiable cross-bind refuses.
    /// The endpoint layouts a note-membership cross-bind may name — the SAME three the spend door accepts
    /// (DB-48, 2026-09-18): THREE lanes (prev, root, acc from the genesis accumulator), FOUR (a carried start
    /// accumulator this chain held, then prev, root, acc), ONE_STEP (four lanes and an 8-byte record ordinal,
    /// verified by the one-step carrier). Run 60 measured the burn door refusing every real-node redeem with
    /// "named no 192-byte endpoint (got 264 bytes)" while the send door took the same 264-byte endpoint.
    ///
    /// ⛔ DB-213c (2026-09-25): ONE-STEP ONLY. The THREE- and FOUR-lane forms were verified by the recursive
    /// fold verifier, which certified statements with no witness behind them (measured: a leaf in NO block
    /// verified). With no sound verifier for them, a length that names them is refused at every door.
    pub fn membership_endpoint_len_ok(len: usize) -> bool {
        crate::member_transition::membership_endpoint_len_ok(len)
    }

    /// ⭐ §19 (2026-10-28) — AN OBJECT'S MEMBER LEG: `(carrier, tuple)` proving the object's note sits under an anchor this
    /// node's own fold produced (`spine_recent_roots`), cross-bound to the object (`binder` = its nullifier, `leaf_commit`
    /// = its blinded leaf commit, `outs` = the digest of two ZERO outputs — an object binds its outputs by its own
    /// statement, never through the leg). The twin of [`Self::member_carrier_verdict`] for orders, deposits, receipts and
    /// burns, which carried the ONE-STEP endpoint naming the RECORD that holds the note (`PqTx::membership_tip` /
    /// `Serve::order_book_membership_bind`, FILED_OPEN: a spend-to-receive join). The anchor is the NEWEST ring root the
    /// wallet's stream named, so it says nothing of the note's age. `Pending` at the Admit door for an anchor outside this
    /// node's ring (the wallet is ahead; retry), `Refused` at the Fold door (the ring at that step is canonical).
    /// §9.6: (1) PoW — the enclosing object's door; (2) `verify_member_path_carrier` (WHIR); (3) no value moves here;
    /// (4) replay is the object's nullifier rule; (5) one tuple decode, one ring scan, one constant-size verify;
    /// (6) parity with the one-step door it replaces: cross-bind, anchor rule, proof — each kept, the record name dropped.
    pub(super) fn member_leg_object_verdict(
        &self,
        carrier: &[u8],
        tip: &[u8],
        leaf_commit: crate::spend_frontier::Digest4,
        binder: crate::spend_frontier::Digest4,
        door: crate::respend::MemberDoor,
    ) -> MemberVerdict {
        let Some(t) = crate::member_transition::read_tuple(tip) else {
            eprintln!("[member-leg] refused: the carried tuple does not decode");
            return MemberVerdict::Refused;
        };
        let Some(zero_outs) = crate::member_transition::outs_digest(&[0u8; 32], &[0u8; 32]) else {
            return MemberVerdict::Refused;
        };
        if t.binder != binder || t.leaf_commit != leaf_commit || t.outs != zero_outs {
            eprintln!("[member-leg] refused: the leg speaks for another object (binder, leaf commit or outputs differ)");
            return MemberVerdict::Refused;
        }
        // ⭐ §19.4: an object's leg may also name an EPOCH ANCHOR (`PegLedger::epoch_anchors`, consensus state every node holds
        // alike) — a cash-out claim proven hours before its batch. Same carrier, same cross-bind, same nullifier set at the fold.
        let ring_at = self.spine_recent_roots.iter().find(|(_, r)| *r == t.anchor).map(|(o, _)| *o);
        let epoch_at = self.peg.epoch_anchors().iter().find(|(_, _, r)| *r == t.anchor).map(|(o, _, _)| *o);
        // Where the anchor sits against what this node can judge it by: the ring's ordinal span and the epoch anchors kept. A bond
        // admitted and later refused at the fold (MEASURED 2026-11-08, btc_bridge.py: one of two custody bonds, both nodes, about 24
        // fold steps apart against a 64-step ring) is told apart from one whose anchor really left by these positions.
        // DIGITAL-CASH-PRIVACY-REVIEWED: public fold ordinals and counts only, to this node's own log; no root, note, amount or key.
        if door == crate::respend::MemberDoor::Admit || ring_at.is_none() {
            eprintln!(
                "[member-leg] {door:?}: anchor at ring ordinal {ring_at:?} / epoch anchor ordinal {epoch_at:?}; ring spans {:?}..{:?} ({} roots), {} epoch anchors kept",
                self.spine_recent_roots.front().map(|(o, _)| *o),
                self.spine_recent_roots.back().map(|(o, _)| *o),
                self.spine_recent_roots.len(),
                self.peg.epoch_anchors().len()
            );
        }
        if ring_at.is_none() && epoch_at.is_none() {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string and a door name — never the anchor, tag, cm or owner.
            eprintln!("[member-leg] the leg's anchor is not a root this node's fold produced within its ring or epoch anchors ({door:?})");
            return match door {
                crate::respend::MemberDoor::Admit => MemberVerdict::Pending,
                crate::respend::MemberDoor::Fold => MemberVerdict::Refused,
            };
        }
        if carrier.is_empty() || !usdm_decider::member_path_gate::verify_member_path_carrier(carrier, &t) {
            eprintln!("[member-leg] refused: the member-path carrier does not verify");
            return MemberVerdict::Refused;
        }
        MemberVerdict::Member
    }

    /// [`Self::check_bond_membership`] with the verifier's own three-way answer beside it — the fill door reads the
    /// verdict, so a bind whose record has not folded HERE YET is a wait ([`MemberVerdict::Pending`]), never "invalid".
    /// `(Refused, None)` for a missing bind or a malformed endpoint.
    /// §19 — the ASSET-SPEND door's membership verdict: the member leg (carrier + tuple) judged by the one shared
    /// dispatcher (`bond_membership_verdict`, which reads the tuple's width); the one-step bind never reaches it.
    pub(crate) fn asset_member_leg_verdict(
        &self,
        carrier: &[u8],
        tuple: &[u8],
        leaf_commit: crate::spend_frontier::Digest4,
        binder: crate::spend_frontier::Digest4,
        door: crate::respend::MemberDoor,
    ) -> MemberVerdict {
        self.bond_membership_verdict(Some((carrier, tuple, leaf_commit, binder)), door).0
    }

    /// ⭐ §19 (2026-10-28, lane funds) — THE NODE'S OWN MEMBER LEG for a note it holds in a record it folded (its
    /// auto-bond of the reward it mined, SATOSHI §8.4). The node is its own wallet here: it builds a member witness book
    /// from the record's served leaves (under the record's cover key it holds) and the path-refresh stream it serves —
    /// exactly what a wallet does with `/applied_notes_from` + `/path_refresh` — and lays the leg the one dispatcher
    /// (`bond_membership_verdict`) judges. Before, the auto-bond carried the ONE-STEP bind: `named_record` — which
    /// record holds the bonded reward — on the wire of every validator's bond (a which-item leak the §19 doors retired
    /// for wallets). `None` when the record is not held or its path is not ready (the bond waits for the next pass).
    /// ROOT-LAYER: the leg is PRODUCED where the witness lives — this node's own folded records and stream — the same
    ///   producer `member_leg_for_test` reads; the door only judges.
    /// MEASURED: the sat-bond door's tuple branch with the node's own leg → the satoshi/auto-bond pins of this landing.
    /// MUST-STAY-GREEN: `db223_*`, `member_witness` pins (the book is unchanged); the asset door's leg branch.
    /// cons: one 256-leaf book build + the stream replay per auto-bond (bonds are rare: one per validator per epoch).
    pub(crate) fn own_member_leg(
        &self,
        cm: &[u8; 32],
        binder: crate::spend_frontier::Digest4,
        blind: crate::spend_frontier::Digest4,
        out0_cm: &[u8; 32],
        out1_cm: &[u8; 32],
    ) -> Option<(Vec<u8>, usdm_decider::member_path_gate::MemberTuple)> {
        let Some((seq, reals)) = self.da_mem.iter().find_map(|(rid, row)| {
            row.0
                .iter()
                .any(|n| n.len() >= 32 && &n[..32] == cm)
                .then(|| (*rid, row.0.iter().flat_map(|x| x.iter().copied()).collect::<Vec<u8>>()))
        }) else {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed reason on this node's own stderr; no note, key, amount or owner.
            eprintln!("[own-member-leg] no held record names this node's own note — the auto-bond waits a pass");
            return None;
        };
        let mut book = crate::member_witness::MemberWitnessBook::new();
        book.note_arrived(*cm, Self::block_leaves_from_notes(&reals, seq, &self.cover_key_of(seq)));
        if let Err(e) = book.apply_stream(&self.path_refresh_stream(book.cursor())) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: a stream-apply reason (ordinals/levels of this node's own book); local stderr.
            eprintln!("[own-member-leg] the node's own path-refresh stream did not apply to its book: {e:?} — the auto-bond waits a pass");
            return None;
        }
        match book.carrier_for(cm, binder, blind, out0_cm, out1_cm) {
            Ok(leg) => Some(leg),
            Err(e) => {
                // DIGITAL-CASH-PRIVACY-REVIEWED: ordinals and levels of this node's own book, on its own stderr only.
                eprintln!(
                    "[own-member-leg] carrier_for refused: {e} (pending its record's fold: {}; {}) — the auto-bond waits a pass",
                    book.is_pending(cm),
                    book.explain_unready(cm)
                );
                None
            }
        }
    }

    pub(super) fn bond_membership_verdict(
        &self,
        m: Option<(&[u8], &[u8], crate::spend_frontier::Digest4, crate::spend_frontier::Digest4)>,
        door: crate::respend::MemberDoor,
    ) -> (MemberVerdict, Option<Option<crate::spend_frontier::Digest4>>) {
        match m {
            None => (MemberVerdict::Refused, None),
            Some((carrier, tip, leaf_commit, binder)) => {
                const SLOT: usize = crate::spend_frontier::DIGEST_LANE_BYTES;
                const THREE: usize = 3 * SLOT;
                const FOUR: usize = 4 * SLOT;
                const ONE_STEP: usize = 4 * SLOT + 8;
                let tip_len = tip.len();
                // §19: a member-leg tip — the record-free membership evidence; the one-step endpoint below is the
                // legacy form (every wallet build now sends the leg).
                if tip_len == crate::member_transition::MEMBER_TUPLE_BYTES {
                    let v = self.member_leg_object_verdict(carrier, tip, leaf_commit, binder, door);
                    return match v {
                        MemberVerdict::Member => (v, Some(Some(leaf_commit))),
                        MemberVerdict::Pending | MemberVerdict::Refused => (v, None),
                    };
                }
                if !Self::membership_endpoint_len_ok(tip_len) {
                    eprintln!(
                        "[bond-membership] refused: the cross-bind named no {THREE}-, {FOUR}- or {ONE_STEP}-byte endpoint (got {tip_len} bytes)"
                    );
                    return (MemberVerdict::Refused, None);
                }
                let limb = |o: usize| -> Option<crate::spend_frontier::Digest4> {
                    crate::spend_frontier::digest_from_lane_bytes(tip.get(o..o + SLOT)?)
                };
                let three_from = |o: usize| -> Option<[crate::spend_frontier::Digest4; 3]> {
                    Some([limb(o)?, limb(o + SLOT)?, limb(o + 2 * SLOT)?])
                };
                // ⛔ DB-213c: ONE-STEP ONLY — the multi-step forms are refused by length above (no sound
                // verifier exists for them), so there is no branch for them here.
                let verdict = {
                    let named_record = u64::from_le_bytes(tip[FOUR..ONE_STEP].try_into().unwrap_or([0u8; 8]));
                    match three_from(SLOT) {
                        Some([prev, root, acc]) => self.membership_carrier_verdict(
                            carrier,
                            leaf_commit,
                            binder,
                            prev,
                            root,
                            acc,
                            named_record,
                            door,
                        ),
                        None => MemberVerdict::Refused,
                    }
                };
                match verdict {
                    MemberVerdict::Member => (verdict, Some(Some(leaf_commit))),
                    MemberVerdict::Pending => {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed string — no tag, commitment, amount or owner.
                        eprintln!("[bond-membership] the carried note-membership proof waits for its record's fold here — retry");
                        (verdict, None)
                    }
                    MemberVerdict::Refused => {
                        eprintln!("[bond-membership] the carried note-membership proof did not verify — refused");
                        (verdict, None)
                    }
                }
            }
        }
    }

    /// ⭐⭐⭐ DB-223 — THE POOL'S MEMBER-CARRIER GATE (§9.6, the member-path door at submit):
    /// 1. PoW: n/a here (a transaction), its anti-spam stamp is the pool's own gate.
    /// 2. Proof: `verify_member_path_carrier` over the carrier and its PUBLIC tuple, the class's fixed shape.
    /// 3. Conservation: the tuple is CROSS-BOUND to this transaction's own spend tuple (binder = its nullifier,
    ///    leaf_commit = its membership leaf commitment, outs = the digest of its two outputs), so a proof for one note
    ///    cannot vouch for another spend's input or outputs.
    /// 4. Replay: the binder is the spend's nullifier, refused by the spent set like the spend itself.
    /// 5. Bounded work: one constant-size verify per transaction, one scan of the fixed-length anchor ring.
    /// 6. Parity with the door it parallels (the one-step membership door): that door judges the note against a record
    ///    THIS node holds; this one judges the anchor against a root THIS node's own fold produced (the ring), never a
    ///    value from the transaction.
    ///
    /// An ABSENT carrier passes (the legacy membership door still judges the spend: DB-223 phase B). A PRESENT one
    /// that fails any of the above is refused, never ignored.
    pub(super) fn member_carrier_gate(&self, tx: &PqTx) -> bool {
        self.member_carrier_verdict(tx) == MemberGate::Pass
    }

    /// DB-449: does this node's anchor ring hold the anchor `tx`'s member tuple names? (`false` for a tuple that does not
    /// decode.) The cheap test before a spend that waited for its anchor is judged again, whole.
    pub(crate) fn member_anchor_held(&self, tx: &PqTx) -> bool {
        crate::member_transition::read_tuple(&tx.member_tuple)
            .is_some_and(|t| self.spine_recent_roots.iter().any(|(_, r)| *r == t.anchor))
    }

    /// The member-path gate's three outcomes (DB-449): the anchor check runs before the carrier's verify, so an anchor this
    /// node does not hold is told apart from a carrier that fails — the block door's `AnchorVerdict::Wait` / `Decided` split
    /// at the tx door.
    pub(super) fn member_carrier_verdict(&self, tx: &PqTx) -> MemberGate {
        // ⭐ A-F114 (B′) — UNDER THE CONSTANT CHAIN THE WRAPPER IS THE MEMBERSHIP. Its created bit proves the input's leaf an
        // output of a record of THIS chain, and it binds the spend's own `(nf, lc)` (`canon_chain::canon_spend_input`), so
        // a member leg would prove the same thing twice: it is refused (one encoding), and the spend's one wrapper decides.
        // An end the window does not hold is the old "anchor not held" (a retry once this node folds there).
        // §9.6: (2) the wrapper by `canon_absence_refusal` (`absence_u::verify_spend` at the admitted shape); (3) none
        // created; (4) the window and the carrier refuse a spent input; (6) parity with the member door: the same input,
        // the same "is it in this chain" question, against a value this node holds; (8) (a) a proof every node checks.
        if crate::canon_chain::canon_live() {
            if !tx.member_carrier.is_empty() || !tx.member_tuple.is_empty() {
                eprintln!("[admit] ⛔ REFUSE: a member leg under the constant chain (the spend's wrapper is its membership)");
                return MemberGate::Refuse;
            }
            let Some((nf, lc)) = crate::canon_chain::canon_spend_input(tx) else {
                eprintln!("[admit] ⛔ REFUSE: a spend whose input does not decode");
                return MemberGate::Refuse;
            };
            let ws = tx.nullifier_absence.first().map(crate::nf_sparse::canon_wrappers).unwrap_or_default();
            let [w] = ws.as_slice() else {
                eprintln!("[admit] ⛔ REFUSE: a spend without exactly one absence wrapper");
                return MemberGate::Refuse;
            };
            if self.canon_recent.ordinal_of_end(&w.end).is_none() {
                return MemberGate::AnchorNotHeld;
            }
            if let Some(why) = self.canon_absence_refusal(&nf, &lc, w) {
                eprintln!("[admit] ⛔ REFUSE: {why}");
                return MemberGate::Refuse;
            }
            return MemberGate::Pass;
        }
        // ⭐ DB-223 phase C (Q7): there is no legacy door left to leave a spend to — an absent carrier proves nothing.
        if tx.member_carrier.is_empty() || tx.member_tuple.is_empty() {
            eprintln!("[admit] ⛔ REFUSE: a spend with no member-path carrier proves no input");
            return MemberGate::Refuse;
        }
        let Some(t) = crate::member_transition::read_tuple(&tx.member_tuple) else {
            eprintln!("[admit] ⛔ REFUSE: a member-path carrier whose tuple does not decode");
            return MemberGate::Refuse;
        };
        let Some(spend) = Self::spend_tuple_of(tx) else {
            eprintln!("[admit] ⛔ REFUSE: a member-path carrier on a transaction that states no spend");
            return MemberGate::Refuse;
        };
        if !crate::member_transition::cross_binds(&t, &spend) {
            eprintln!("[admit] ⛔ REFUSE: a member-path carrier speaks for another spend (binder, leaf or outputs differ)");
            return MemberGate::Refuse;
        }
        if !self.spine_recent_roots.iter().any(|(_, r)| *r == t.anchor) {
            // DIGITAL-CASH-PRIVACY-REVIEWED: the ring's fold-step SPAN (two public spine positions) and nothing of the
            // spend — the anchor root itself is never printed. The span is what tells a rewound ring (newest fell) from a
            // spend that is simply ahead of this node's fold (launch-leg1-g11b-20261022-2245.log:24046 had neither).
            eprintln!(
                "[admit] ⛔ REFUSE: a member-path carrier anchored at a root this node's own fold never produced within its ring \
                 (the ring holds fold steps {}..={}, {} entr(ies))",
                self.spine_recent_roots.front().map_or(0, |(o, _)| *o),
                self.spine_recent_roots.back().map_or(0, |(o, _)| *o),
                self.spine_recent_roots.len()
            );
            return MemberGate::AnchorNotHeld;
        }
        if !usdm_decider::member_path_gate::verify_member_path_carrier(&tx.member_carrier, &t) {
            eprintln!("[admit] ⛔ REFUSE: a member-path carrier that does not verify");
            return MemberGate::Refuse;
        }
        MemberGate::Pass
    }

    /// ⭐⭐ DB-335 — THE ONE DOOR A CHAIN OBJECT THIS NODE BUILT ENTERS ITS POOL BY. The full admission rule runs (the
    /// gossip door below), and the pooled id is MARKED so the runtime gossips it at once and again once per relay floor
    /// until a block carries it (`own_publications_due`). Every `publish_*` / `execute_*` pooled through the gossip door
    /// directly and queued nothing, so the object travelled only inside a block its own node authored — or never, on a
    /// node whose pool height is frozen (the faucet-drip loss, MEASURED 2026-09-23). Census:
    /// `every_node_level_publication_enters_the_pool_through_the_marking_door`.
    pub(crate) fn pool_own_publication(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        let id = self.ingest_tx(tx)?;
        self.own_publications.entry(id).or_insert(None);
        Ok(id)
    }

    /// The same door for an object a WALLET asked this node to build (a peg in or out, an asset spend, an order fill): it names
    /// that wallet's node if this node announces it, so the runtime sends it by push instead (`NodeRuntime::send_own_tx`), and
    /// this node's own templates keep it out until the network echoes it. A validator's duty stays on `pool_own_publication`:
    /// its keys are public by design.
    pub(crate) fn pool_wallet_publication(&mut self, tx: PqTx) -> Result<Hash32, MempoolError> {
        let id = self.pool_own_publication(tx)?;
        let pool = &self.mempool;
        self.wallet_publications.retain(|t| pool.contains(t));
        self.wallet_publications.insert(id);
        self.hold_own_tx(id);
        Ok(id)
    }

    /// Whether a pooled own publication was built for a wallet.
    pub(crate) fn is_wallet_publication(&self, id: &Hash32) -> bool {
        self.wallet_publications.contains(id)
    }

    /// The raw entries this node holds for a bucket — what a peer's `BucketReq` is answered from.
    /// How many distinct account buckets this node holds. Diagnostic only; see `[acct-buckets]`.
    pub fn account_bucket_count(&self) -> usize {
        self.account_buckets.len()
    }

    pub fn account_bucket_entries(&self, bucket: &[u8; 32]) -> Vec<Vec<u8>> {
        let hit = self
            .account_buckets
            .get(bucket)
            .cloned()
            .unwrap_or_default();
        // ⛔⛔⛔ DO THE WALLET AND THIS NODE AGREE ON THE BUCKET ID?
        //
        // MEASURED 2026-07-31: node B holds THREE distinct account buckets after adopting 2,500 target
        // byte(s) (`[acct-buckets] 3`), while the recipient wallet's `account_bucket_restore` returns ZERO
        // entries and `[detect-why]` reports an EMPTY bucket. Adoption writes - it is not a no-op - so the
        // entries exist under SOME id and the lookup asks for a DIFFERENT one. Every delivery layer already
        // measures clean, so this is the last disagreement left.
        //
        // Print a 4-byte prefix of the asked id beside the held ids, ONLY on a miss while this node actually
        // holds buckets. That is the one comparison no counter can make.
        //
        // O1-FOOTPRINT-REVIEWED: reads the EXISTING account_buckets map; stores nothing and adds no term in
        // height, blocks or notes.
        // DIGITAL-CASH-PRIVACY-REVIEWED: FOUR bytes of a bucket id, in this node's OWN local log, only on an
        // anomaly (a miss against a non-empty map). It is never sent anywhere, never paired with a note,
        // amount, key or owner, and a 4-byte prefix identifies no account - the same shape as the reviewed
        // `[acct-keycmp]` probe. It exists to prove two derivations disagree, which is a correctness fact.
        if hit.is_empty() && !self.account_buckets.is_empty() {
            let held: Vec<String> = self
                .account_buckets
                .keys()
                .take(3)
                .map(|k| format!("{:02x}{:02x}{:02x}{:02x}", k[0], k[1], k[2], k[3]))
                .collect();
            eprintln!(
                "[bucket-id] MISS for {:02x}{:02x}{:02x}{:02x} while this node holds {} bucket(s) starting \
                 {:?} - the wallet and the node derive DIFFERENT bucket ids, so no lookup can ever match.",
                bucket[0], bucket[1], bucket[2], bucket[3],
                self.account_buckets.len(),
                held
            );
        }
        hit
    }

    /// The two-output, one-nullifier, UNFRAMED shape both USDm carrier classes share.
    pub(super) fn usdm_two_output_shape(tx: &PqTx) -> bool {
        tx.output_notes.len() == 2 * crate::cover::PQ_NOTE_BYTES
            && !tx.nullifiers.is_empty()
            && !tx.blob.is_empty()
            && crate::chain_object::unframe(&tx.blob).is_none()
    }

    /// ⭐ DB-313 §3 — WHAT A BLOCK'S BOND LANE PROVES: the admissions of the ONE `Class::BondTransition` entry it
    /// carries, verified against the block's own output root. `None` for no entry, more than one, or one that does not
    /// verify — so no bond weight is admitted and no bond change is receivable, fail-closed on the bonds, never on the
    /// block. Read by the graft's note door and by `apply_bond_set` through the ONE parser (`bond_set_entries`).
    #[must_use]
    pub(crate) fn bond_admissions_of(
        bond_set: &[u8],
        output_notes_root: &Hash32,
    ) -> Option<crate::note_transition::Admissible> {
        Self::bond_admissions_on_door(bond_set, output_notes_root, false)
    }

    /// [`Self::bond_admissions_of`] on a door that is ARMED (`bound`, test builds only) or not for the bound template
    /// double — every node-side reader passes [`Node::template_double`].
    #[must_use]
    pub(crate) fn bond_admissions_on_door(
        bond_set: &[u8],
        output_notes_root: &Hash32,
        bound: bool,
    ) -> Option<crate::note_transition::Admissible> {
        let mut found: Option<crate::note_transition::BondTransition> = None;
        for tx in Self::bond_set_entries(bond_set).0.into_iter().flatten() {
            if let Some((crate::chain_object::Class::BondTransition, payload)) = crate::chain_object::unframe(&tx.blob) {
                if found.is_some() {
                    // Fixed string — no id, key, amount or owner.
                    eprintln!("[bond-apply] refused: a bond lane carrying TWO bond transitions states nothing");
                    return None;
                }
                found = Some(crate::note_transition::BondTransition::decode(payload)?);
            }
        }
        let bt = found?;
        let a = crate::note_transition::verify_bond_with(&bt, output_notes_root, bound);
        if a.is_none() {
            eprintln!("[bond-apply] refused: the block's bond transition does not verify — its bonds admit nothing");
        }
        a
    }

    /// The note a seated validator has locked (custody or USDm bond), as every node holds it — consensus state.
    #[must_use]
    pub fn bond_locked_note(&self, vid: &[u8; 32]) -> Option<&[u8]> {
        self.bond_locked.get(vid).map(Vec::as_slice)
    }
    /// This node's reward recipient (§8.1), if provisioned.
    #[must_use]
    pub fn reward_recipient(&self) -> Option<&crate::satoshi::RewardRecipient> {
        self.reward_recipient.as_ref()
    }
    /// The encapsulation randomness of a reward or bond note: a TEST build derives it from the node's reproducible context so
    /// the chain is the same bytes every run; production draws it from the OS (`None`) — never from node-held data (DB-382).
    pub(super) fn reward_seal_seed(miner_seed: &[u8; 32], key: u64, context: &[u8]) -> Option<[u8; 32]> {
        // ⛔ NEVER THE PARENTS' IDS (v1 hashed them). A block's id is not a function of the schedule — its cover notes are
        // freshly keyed by design (the privacy pillar) — so a reward seeded from it made the reward note, its nullifier and
        // the block's decoy secret (derived from the block's reals) differ on every replay of one `(parties, seed, ops)`:
        // MEASURED `h3_the_state_the_catalogue_judges_replays_identically_from_seed_and_ops` red on every lane since SAT
        // increment 1, `uns_root`/`nf_root`/`nf_acc` differing at equal counts. A reward passes the parent KEY (a blue score)
        // and this node's reward index as `context` — functions of the schedule, and the index advances on every laid reward,
        // so no two of this node's rewards share a seed; a bond note passes its input's opening.
        #[cfg(test)]
        {
            let mut pre = b"MUSD-test-reward-seal-v2".to_vec();
            pre.extend_from_slice(miner_seed);
            pre.extend_from_slice(&key.to_le_bytes());
            pre.extend_from_slice(context);
            Some(*Hash32::hash(&pre).as_bytes())
        }
        #[cfg(not(test))]
        {
            let _ = (miner_seed, key, context);
            None
        }
    }
    /// ⭐ DB-257 — ONE PARSER FOR `Block::bond_set` (length-prefixed postcard `PqTx` entries), read by BOTH
    /// `apply_bond_set` and the §BA door, so the release and the justification of its returned note can never
    /// read two different parses of one set. Entries come back in order; an entry that does not decode is
    /// `None`. Parsing STOPS at the first malformed frame (zero length, or past the end), and the second value
    /// reports it: a malformed tail can prove nothing and no stride is guessed.
    ///
    /// O1-FOOTPRINT-REVIEWED: bounded by one block's bond set; the vector is consumed by the caller.
    pub(crate) fn bond_set_entries(bond_set: &[u8]) -> (Vec<Option<PqTx>>, bool) {
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + 4 <= bond_set.len() {
            let mut lb = [0u8; 4];
            lb.copy_from_slice(&bond_set[off..off + 4]);
            let len = u32::from_le_bytes(lb) as usize;
            off += 4;
            if len == 0 || off + len > bond_set.len() {
                return (out, true);
            }
            out.push(crate::chain_object::decode_exact::<PqTx>(&bond_set[off..off + len]));
            off += len;
        }
        (out, false)
    }

    /// The node-computed BTC + XMR reserve deposit addresses for one swap, from the LIVE bonded validator set's
    /// custody points. `(None, None)` when no bonded validator has registered custody (fail-closed — never fake).
    ///
    /// §BR-2 (spec §14): a Bitcoin deposit is CO-SIGNED — its address is the two-leaf output over the custody quorum AND
    /// the depositor's key `D` (`btc_tx::deposit_output`), so custody alone can never spend an unminted deposit and the
    /// depositor reclaims it alone after one week. With no `D` there is no Bitcoin address (fail-closed: a single-leaf
    /// custody-only deposit is the theft path this closes).
    pub fn reserve_addresses(&self, swap_nonce: &[u8], depositor_x: Option<&[u8; 32]>) -> (Option<String>, Option<String>) {
        let btc = depositor_x.and_then(|d| {
            // SAFE AT SCALE: the deposit's vault is a function of its own nonce (`deposit_vault_for`) — the whole set on a
            // one-vault chain
            let vault = self.deposit_vault_for(swap_nonce);
            // stage three: once the chain records the vault's key, its CURRENT key's leaf is the one address served
            // (rebuilt from the record's own inputs); the live seats' leaf only before any key is recorded
            let leaf = match self.peg.vault_key_current(vault) {
                Some(k) => crate::btc_tx::custody_leaf(&k.btc.members).filter(|l| l.leaf_hash == k.btc.leaf)?,
                None if self.vault_keys_mintable(vault).is_some() => return None, // keys recorded, none current: no address
                None => crate::btc_tx::custody_leaf(&self.custody_members_of_vault(vault))?,
            };
            let out = crate::btc_tx::deposit_output(&leaf, d, swap_nonce)?;
            Some(crate::btc_tx::reserve_address(crate::bridge::btc_hrp(), &out.output_x))
        });
        // DB-121x: the Monero address is the bonded set's k-of-n multisig wallet (known from the set's signed
        // announcements — a user's node needs no wallet), integrated with a payment id that is a function of the
        // set and the swap's blind, so every custodian re-derives it (DB-123). No known wallet ⇒ no address.
        let xmr = self.xmr_reserve_address_for_nonce(swap_nonce);
        // ⭐ ISSUING AN ADDRESS IS WHAT COMMITS THIS NODE TO WATCH IT — DOOR AUDIT 2026-09-07 (D15).
        // The deposit watcher's swept set used to be written by whoever CALLED the status read, which made
        // it f(callers) and unbounded. It is written HERE instead: the moment this node derives a reserve
        // address from its own live bonded custody, it is this node's own pending business and worth a
        // sweep. `watch_issued_reserve` validates the string at its own door, so a custody set that
        // produced no address (or a shape the watcher cannot read) registers nothing.
        if let Some(a) = &btc {
            let _ = crate::btc_watch::watch_issued_reserve(a);
        }
        if let Some(a) = &xmr {
            let _ = crate::xmr_watch::watch_issued_reserve(a);
        }
        (btc, xmr)
    }

    pub fn reserve_solvency_hold(&self) -> bool {
        self.reserve_solvency_hold
    }

    /// The LIVE bonded set's custody membership as `(x-only key, bond weight)` — the members of the k-of-n leaf.
    /// CACHE-ONLY: derived from the chain's bonded set (`Class::MembershipBond` applied at graft).
    /// ⭐ SAFE AT SCALE: the members of THIS custodian's vault ([`Self::vault_here`]) — the whole bonded set on a one-vault
    /// chain, and vault 0's off a custody seat. A custody lane signs with its own vault's leaf, never the whole set's.
    pub fn custody_members_current(&self) -> Vec<([u8; 32], u128)> {
        self.custody_members_of_vault(self.vault_here())
    }

    /// ⭐ SAFE AT SCALE — the custody membership of vault `vault` as `(x-only key, bond weight)`, in id order: the members of
    /// that vault's k-of-n leaf. Empty for a vault that does not exist.
    /// CACHE-ONLY: derived from the chain's bonded set.
    /// SCALE: at most `custody_vaults::VAULT_MAX` members, so the leaf's script and every witness that satisfies it are
    /// bounded by the vault, never by the nodes that bond.
    pub fn custody_members_of_vault(&self, vault: u32) -> Vec<([u8; 32], u128)> {
        self.custody_weighted_of_vault(vault)
            .into_iter()
            .filter_map(|(c, w)| {
                let x: [u8; 32] = c.secp33.get(1..33)?.try_into().ok()?;
                Some((x, w))
            })
            .collect()
    }

    /// ⭐ SAFE AT SCALE — THE VAULT A DEPOSIT GOES TO: a function of the deposit's own nonce (the mint blind's bytes), spread
    /// evenly over the vaults that hold MORE than `custody_vaults::VAULT_MIN` members — a vault one leave away from half
    /// strength, a young vault still filling its seats and a vault that merged out take nothing new. When no vault is
    /// that full, the one with the most members takes them all (the lowest index among equals). Any node derives a
    /// deposit address with it and every custodian re-derives the same vault from its sealed leg, so no table of "which
    /// vault took which deposit" exists anywhere. 0 on a one-vault chain.
    /// BORROWED: THORChain routes an inbound to a vault by rule; here the rule reads no balance (balances are hidden).
    /// cons: the spread is even by count, not by headroom — a vault already at its authority still receives its share,
    /// and those deposits are signed by the whole set.
    pub fn deposit_vault_for(&self, swap_nonce: &[u8]) -> u32 {
        let vaults = self.validators.custody_vaults();
        if vaults.len() <= 1 {
            return 0;
        }
        let full: Vec<usize> = (0..vaults.len()).filter(|i| vaults[*i].len() > crate::custody_vaults::VAULT_MIN).collect();
        let pool: Vec<usize> = if full.is_empty() {
            // `max_by_key` keeps the LAST of equal keys: reversed, that is the lowest index
            (0..vaults.len()).rev().max_by_key(|i| vaults[*i].len()).into_iter().collect()
        } else {
            full
        };
        if pool.is_empty() {
            return 0;
        }
        let mut h = blake3::Hasher::new_derive_key("MonerousD deposit vault v1");
        h.update(swap_nonce);
        let mut w = [0u8; 8];
        w.copy_from_slice(&h.finalize().as_bytes()[..8]);
        u32::try_from(pool[(u64::from_le_bytes(w) % pool.len() as u64) as usize]).unwrap_or(0)
    }

    /// The custody leaf of THIS custodian's vault (DB-121) — `None` when it has no seated member with a custody point.
    pub fn custody_leaf_current(&self) -> Option<crate::btc_tx::CustodyLeaf> {
        crate::bridge::custody_leaf_from_bonded_custody(&self.custody_weighted_of_vault(self.vault_here()))
    }

    /// The custody points of vault `vault` with their bond weights, in id order. On a one-vault chain this IS
    /// `ValidatorSet::bonded_custody_weighted` — the very list the leaf was always built from, read the very same way —
    /// so no deposit address or leaf of a chain of sixteen custodians or fewer moves by a byte.
    fn custody_weighted_of_vault(&self, vault: u32) -> Vec<(crate::validator::BridgeCustody, u128)> {
        let vaults = self.validators.custody_vaults();
        if vaults.len() <= 1 {
            return if vault == 0 { self.validators.bonded_custody_weighted() } else { Vec::new() };
        }
        match vaults.get(vault as usize) {
            Some(members) => self.validators.custody_weighted_of(members),
            None => Vec::new(),
        }
    }

    /// DB-121/DB-123: the reserve deposit addresses for a swap whose mint blind is `d_blind` — the blind IS the
    /// per-deposit tweak, so every custodian can re-derive the address from the sealed leg it receives.
    pub fn reserve_addresses_for_blind(
        &self,
        d_blind: &crate::spend_frontier::Digest4,
        depositor_x: Option<&[u8; 32]>,
    ) -> (Option<String>, Option<String>) {
        self.reserve_addresses(&crate::spend_frontier::digest_to_lane_bytes(d_blind), depositor_x)
    }

    /// Is this burn's foreign payout still owed? True from the moment the block destroys the USDm until the
    /// release is claimed. A custodian polls this to find the work it has not finished; it is the gauge that
    /// says money is in flight, and it is derived from the chain rather than remembered, so a restart cannot
    /// forget an obligation.
    #[must_use]
    pub fn reserve_release_pending(&self, burn_nullifier: &[u8; 32]) -> bool {
        self.peg.release_pending(burn_nullifier)
    }

    /// ⭐⭐⭐ DB-123 (2026-09-20) — IS THIS DEPOSIT ADDRESS THE RESERVE'S OWN? Until today a custodian confirmed
    /// that a deposit landed at whatever address the requester NAMED, and never that the k-of-n custody script
    /// controls that address: a depositor could deposit to an address only they hold and mint USDm against
    /// coins the reserve does not have — the bridge attack class the user asked to be armoured against. The
    /// address is a function of the sealed mint blind under the bonded set's custody leaf (`btc_tx`), so every
    /// custodian re-derives it — under the live set and the recent ring — and refuses any other.
    /// CACHE-ONLY: a pure re-derivation from the chain's bonded set and the sealed blind; nothing is decided
    /// for the chain here, only whether THIS custodian will attest.
    ///
    /// §BR-2: a Bitcoin deposit address is ours only as the CO-SIGNED two-leaf output for this blind AND the depositor key
    /// the sealed leg names (`depositor_x`); a custody-only (single-leaf) deposit, or no depositor key, is refused.
    pub fn reserve_address_is_ours(
        &self,
        address: &str,
        d_blind: &crate::spend_frontier::Digest4,
        depositor_x: Option<&[u8; 32]>,
    ) -> bool {
        if crate::bridge::is_monero_address(address) {
            return self.xmr_reserve_address_is_ours(address, d_blind);
        }
        depositor_x.is_some_and(|d| self.deposit_leaf_for(address, d_blind, d).is_some())
    }

    /// ⭐ SAFE AT SCALE — is `address` a deposit address of vault `vault`, for this blind? [`Self::reserve_address_is_ours`]
    /// for this custodian's own vault; for another vault (a deposit this custodian only witnesses): the co-signed output
    /// under that vault's live leaf, or — Monero — the integrated address of that vault's announced wallet for this blind.
    /// CACHE-ONLY: a pure re-derivation; it decides only whether THIS custodian signs.
    pub fn reserve_address_is_vaults(
        &self,
        vault: u32,
        address: &str,
        d_blind: &crate::spend_frontier::Digest4,
        depositor_x: Option<&[u8; 32]>,
    ) -> bool {
        if vault == self.vault_here() {
            return self.reserve_address_is_ours(address, d_blind, depositor_x);
        }
        if crate::bridge::is_monero_address(address) {
            // the one Monero door, for any vault: the chain's key record when it has one, the announced wallet before
            return self.xmr_reserve_address_is_vaults_own(vault, address, d_blind);
        }
        depositor_x.is_some_and(|d| self.deposit_leaf_in(vault, address, d_blind, d).is_some())
    }

    /// §BR-2 — the custody leaf (the live set's, or one of the recent ring) under which `address` is the co-signed deposit
    /// output for (`d_blind`, `depositor_x`); `None` when no leaf derives it.
    pub fn deposit_leaf_for(
        &self,
        address: &str,
        d_blind: &crate::spend_frontier::Digest4,
        depositor_x: &[u8; 32],
    ) -> Option<crate::btc_tx::CustodyLeaf> {
        self.deposit_leaf_in(self.vault_here(), address, d_blind, depositor_x)
    }

    /// ⭐ SAFE AT SCALE — [`Self::deposit_leaf_for`] under the leaf of vault `vault`: this custodian's own vault (its live
    /// members, or one of its recent ring) or — for a deposit this custodian only WITNESSES on the whole-set path — another
    /// vault's live members. `None` when that vault's leaf does not derive `address`: the coin is not under that vault's keys.
    pub fn deposit_leaf_in(
        &self,
        vault: u32,
        address: &str,
        d_blind: &crate::spend_frontier::Digest4,
        depositor_x: &[u8; 32],
    ) -> Option<crate::btc_tx::CustodyLeaf> {
        let nonce = crate::spend_frontier::digest_to_lane_bytes(d_blind);
        let hrp = crate::bridge::btc_hrp();
        let want = address.trim();
        // ⭐ SAFE AT SCALE, stage three (spec §3f R2): once the chain records this vault's keys, a deposit address is
        // ours only under a key a deposit may be minted to NOW (`vault_keys_mintable`: the current key, or a replaced
        // one inside its address window) — each leaf rebuilt from the record's OWN inputs, so every node, whenever it
        // joined, judges the same addresses. A leaf of a set the chain no longer names is refused, however recently
        // this node saw that set live.
        if let Some(keys) = self.vault_keys_mintable(vault) {
            return keys.into_iter().find_map(|k| {
                let leaf = crate::btc_tx::custody_leaf(&k.btc.members).filter(|l| l.leaf_hash == k.btc.leaf)?;
                let out = crate::btc_tx::deposit_output(&leaf, depositor_x, &nonce)?;
                (crate::btc_tx::reserve_address(hrp, &out.output_x) == want).then_some(leaf)
            });
        }
        let current = self.custody_members_of_vault(vault);
        // the ring holds THIS custodian's own vault's recent memberships; another vault is judged by its live set alone
        let ring: &[Vec<([u8; 32], u128)>] = if vault == self.vault_here() { self.custody_leaf_ring.as_slices().0 } else { &[] };
        let ring_tail: &[Vec<([u8; 32], u128)>] = if vault == self.vault_here() { self.custody_leaf_ring.as_slices().1 } else { &[] };
        let candidates = std::iter::once(&current).chain(ring.iter()).chain(ring_tail.iter());
        for members in candidates {
            if members.is_empty() {
                continue;
            }
            let Some(leaf) = crate::btc_tx::custody_leaf(members) else {
                continue;
            };
            let Some(out) = crate::btc_tx::deposit_output(&leaf, depositor_x, &nonce) else {
                continue;
            };
            if crate::btc_tx::reserve_address(hrp, &out.output_x) == want {
                return Some(leaf);
            }
        }
        None
    }

    // CHAIN-PUBLISH-REVIEWED: this IS the publication — `publish_valueless_asset_object` of the framed ReserveTheft
    // object, which every grafting node carries in `Block::bond_set` and applies in `apply_bond_set` at the fold.
    /// ⭐ DB-274 P2 (§8.7) + A-F60 — when `vid`'s unbonding collateral is released, while it waits: `(blue score, chain
    /// tick)`, both of which the releasing fold step must have reached. `None` when `vid` is not unbonding (never bonded
    /// collateral, already released, or burned by a slash).
    pub fn unbonding_due(&self, vid: &[u8; 32]) -> Option<(u64, u64)> {
        self.unbonding.get(vid).map(|u| (u.due_blue, u.due_tick))
    }

    /// ⭐ DB-274 P2 (§8.7) — THE EVIDENCE HORIZON of an unbonding, in BLUE SCORE, DERIVED, never tuned: evidence
    /// published inside the merge depth of the vote it proves is merged by then, and folds `record_fold_depth` later.
    /// So misbehaviour before an unbond, reported within the merge depth, folds before the collateral is released and
    /// burns it. At the defaults 3,600 + 32 = 3,632 blue score. A count of BLOCKS on purpose: merging is structure, and
    /// it takes that many blocks whatever the pace.
    /// ⭐ A-F60 (lane speed5, user 2026-11-15: "there should be no assumptions in our blockchain") — this used to be
    /// `max(horizon, 21 days of blocks at the target)`, one number standing for two clocks: on a mesh running slower
    /// than its target the "21 days" was longer, on a faster one shorter. The two halves are now two gates, each on its
    /// own clock: this one (blocks) and [`Self::unbond_ticks`] (the chain's time). A release waits for both.
    pub(crate) fn unbond_horizon_blue(&self) -> u64 {
        (self.params().merge_depth_cap as u64).saturating_add(self.params().record_fold_depth)
    }

    /// ⭐ §BR-3 17.2 + A-F60 — THE GOVERNED UNBONDING WINDOW in CHAIN TICKS (21 days by default): a time, so it is
    /// read on the chain's own clock (`Node::chain_tick_at`, median time past over `dag::MESH_TARGET_SPACING_MS`),
    /// never as a count of blocks at an assumed pace. Every time-meaning custody window derives from it (the address
    /// window, the rotation period, a delegation's maturity). The governed parameter keeps its persisted name
    /// `unbonding_blocks`; its unit is ticks, and `params::UNBONDING_BLOCKS_DEFAULT` is `blocks_for_ms(21 days)`.
    pub(crate) fn unbond_ticks(&self) -> u64 {
        self.params().unbonding_blocks
    }

    /// ⭐ DB-258 / DB-258c — WHICH bonding of V is live here, as a function of the chain's OBJECT and never of arrival.
    ///
    /// ⛔ DB-258c (2026-09-27, MEASURED on real processes, slot B4): the first cut digested the score V's current bonding
    /// LANDED at (`bond_height`, first writer at apply). A landing score is a fact about ARRIVAL — sibling blocks carry
    /// one pooled seat request, a jumped node re-requests its seat into a later block — so two honest nodes held two
    /// instances for one seat, and the one that did not publish the unbond refused it: V released on one node, seated on
    /// the other. REVERTED (§9.2) to what the object itself fixes:
    ///   * a COLLATERAL bond: its locked note's commitment (`bond_locked`, carried in the certified bundle since DB-259).
    ///     One note, locked once, spendable once, so a re-bond locks another and V's old unbond names a dead instance;
    ///   * a SEAT: the validator alone. RESIDUAL, NAMED: a seat has no per-seating value yet, so V's old seat unbond
    ///     (public) can end a later seating of V while seats are free (reserve zero). That is the DB-258b class (an old
    ///     seat object re-seats V), closed by the same shape — a seat that retires a one-shot right (`seat_nf`, docs/
    ///     DB-258 §6b) — and that right then joins this digest.
    /// `None` when V holds no weight here.
    pub fn bond_instance_of(&self, id: &[u8; 32]) -> Option<[u8; 32]> {
        if self.validators.finality_weight_of(id) == 0 { // SATOSHI §6: a vote instance exists for any seat
            return None;
        }
        // A-F47: the instance names THIS network (`pqauth::node_statement`), so the unbond statement that signs it — built by the
        // wallet too, which fixes no process network — names its chain: a seat's instance was `H(domain ‖ id)` alone, so a seat
        // unbond signed on the testnet ended the same validator's seating on mainnet.
        let mut pre = crate::pqauth::node_statement(b"musdm.validator.instance.v2");
        pre.extend_from_slice(id);
        if let Some(note) = self.bond_locked.get(id) {
            pre.extend_from_slice(&note[..note.len().min(32)]);
        }
        Some(*crate::hash::Hash32::hash(&pre).as_bytes())
    }

    /// The maturity rule, ONE definition (DB-257): a bond with a recorded anchor matures at
    /// `bonded_at + stake_lock_blocks`, judged at `at_tick`, the carrying block's own chain tick (A-F60: the lock is a
    /// time — `params::STAKE_LOCK_BLOCKS_DEFAULT` is a day of ticks — never blocks at an assumed pace). A legacy bond
    /// with no anchor is matured (liveness over an anchor the chain never recorded).
    ///
    /// ⛔ THE LIVE LOCK, NOT THE BOOT-TIME ONE: `params()` reads the DAG, which is where governance installs a
    /// changed `stake_lock_blocks` on every node alike.
    ///
    /// A SEAT (no locked collateral) records no anchor at all (DB-258c): it has nothing to lock, so it is always matured.
    pub(super) fn bond_matured_at(&self, id: &[u8; 32], at_tick: u64) -> bool {
        self.unbond_matures_at(id).is_none_or(|due| at_tick >= due)
    }

    /// ⭐ DB-409 — the chain tick (A-F60) from which a block may release `id`'s bond: `bond_height + stake_lock_blocks` for a bond
    /// with locked collateral, `None` when nothing locks it (a SEAT, or an anchor the chain never recorded — matured).
    /// The one definition [`Self::bond_matured_at`] judges and `/get_validator_bond` names, so an owner reads the same
    /// height the door and the release apply. Consensus-public: a bond's height and the governed lock.
    #[must_use]
    pub fn unbond_matures_at(&self, id: &[u8; 32]) -> Option<u64> {
        if !self.bond_locked.contains_key(id) {
            return None;
        }
        let lock_blocks = self.params().stake_lock_blocks;
        self.bond_height.get(id).map(|&bonded_at| bonded_at.saturating_add(lock_blocks))
    }

    /// ⭐ DB-259 — the chain's maturity anchors, sorted by validator id: what a certified bundle carries.
    /// O1-FOOTPRINT-REVIEWED: bounded by the validator set (`bond_height`'s own declared bound).
    pub(crate) fn bond_heights_census(&self) -> Vec<([u8; 32], u64)> {
        let mut v: Vec<([u8; 32], u64)> = self.bond_height.iter().map(|(k, h)| (*k, *h)).collect();
        v.sort();
        v
    }

    /// ⭐ DB-259 — the chain's locked collateral notes, sorted by validator id: what a certified bundle carries.
    /// O1-FOOTPRINT-REVIEWED: bounded by the validator set (`bond_locked`'s own declared bound).
    pub(crate) fn bond_locked_census(&self) -> Vec<([u8; 32], Vec<u8>)> {
        let mut v: Vec<([u8; 32], Vec<u8>)> = self.bond_locked.iter().map(|(k, n)| (*k, n.clone())).collect();
        v.sort();
        v
    }

    /// ⭐ DB-274 P2 (§8.7) — the chain's unbonding collateral in validator-id order (the map is a `BTreeMap`): what the
    /// checkpoint and the certified bundle carry, and what the cold-peer verdict compares. ONE spelling for all of them.
    /// O1-FOOTPRINT-REVIEWED: bounded by the bonded set (`unbonding`'s own declared bound).
    pub(crate) fn unbonding_census(&self) -> Vec<([u8; 32], Unbonding)> {
        self.unbonding.iter().map(|(k, u)| (*k, u.clone())).collect()
    }

    /// DB-313 R2 (a) — does this node's pool already hold a bond onto `vid`? `/sign_bond` refuses a second signature
    /// while one waits: a second bond would consume its note for no weight. O(pool), on a rare loopback route only.
    #[must_use]
    pub fn pool_holds_bond_onto(&self, vid: &[u8; 32]) -> bool {
        self.mempool
            .all_tx_ids()
            .iter()
            .filter_map(|id| self.mempool.get(&Hash32(*id)))
            .any(|tx| tx.bond_notes.get(..32) == Some(&vid[..]))
    }

    /// ⭐ G2 — WHAT A RECEIPT DOOR DOES WITH A VERIFIED VOTE: judge it against the CARRIED tally and the votes already in
    /// flight, then POOL it as a `Class::FinalityVote` object (the DB-335 marking door, so it travels until a block carries
    /// it). Returns the door's outcome and whether the vote is FRESH here: `Counted` means pooled (it is counted when a
    /// block carries it and this node folds that block); a duplicate (already tallied, or already in flight) is `Counted`
    /// but not fresh, so the gossip door never re-floods it.
    pub(super) fn pool_finality_vote(&mut self, cert: VoteCert, voter: [u8; 32]) -> (FinalityVoteOutcome, bool) {
        // against the chain: a vote the fold already tallied is a duplicate; a different block at that height is an
        // equivocation (the evidence is queued, the vote is not pooled)
        if let Some(prev) = self.finality.voted_block_at(cert.height, &voter) {
            if prev == cert.block {
                return (FinalityVoteOutcome::Counted, false); // idempotent: already carried and tallied
            }
            self.queue_equivocation(cert);
            return (FinalityVoteOutcome::Equivocation, false);
        }
        // against the votes in flight: drop the rows whose tx left the pool (a block carried it, or it was evicted)
        let pool = &self.mempool;
        self.pooled_votes.retain(|_, (_, id)| pool.contains(id));
        if let Some((prev, _)) = self.pooled_votes.get(&(cert.height, voter)) {
            if *prev == cert.block {
                return (FinalityVoteOutcome::Counted, false); // already pooled, waiting for a block
            }
            self.queue_equivocation(cert);
            return (FinalityVoteOutcome::Equivocation, false);
        }
        let Some(blob) = crate::finality_vote_tx::wire(&cert) else {
            return (FinalityVoteOutcome::Unauthenticated, false); // not an ML-DSA-65 cert: no honest voter signs one
        };
        let id = crate::mempool::PqTx::content_id(&blob);
        match self.publish_valueless_asset_object(blob, "finality-vote") {
            AssetSpendOutcome::Published => {
                self.pooled_votes.insert((cert.height, voter), (cert.block, id));
                while self.pooled_votes.len() > FINALITY_POOLED_VOTES_MAX {
                    self.pooled_votes.pop_first();
                }
                (FinalityVoteOutcome::Counted, true)
            }
            _ => (FinalityVoteOutcome::NotPooled, false),
        }
    }

}
