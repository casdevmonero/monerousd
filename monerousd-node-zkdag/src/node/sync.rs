// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! sync — `impl Node` moved VERBATIM out of node.rs (user 2026-10-27, lever 5: one responsibility per file; borrowed shape:
//! Bitcoin Core's src/ layout). A child module of `node` sees Node's private fields, so nothing here changed but its address.
#![allow(clippy::all)]
use super::*;

impl Node {
    /// A block carrying only its header and tx ids (an ancestor placeholder on the wire and on disk).
    pub(crate) fn header_shell(header: crate::block::BlockHeader, tx_ids: Vec<Hash32>) -> Block {
        Block {
            cover_key: None,
            wide_objects: Vec::new(),
            tx_bodies: Vec::new(),
            agg_tables: Vec::new(),
            note_commitments: Vec::new(), // a header shell carries no body
            header,
            tx_ids,
            pow_proof: Vec::new(),
            note_transition: None,
            nullifier_proof: crate::block::NfBlockProof::default(),
            output_notes: Vec::new(),
            oli_tags: Vec::new(),
            account_targets: Vec::new(),
            bond_set: Vec::new(),
            // ⭐ §BA — no staged credit rides this construction, so it justifies nothing and carries nothing.
            credit_set: Vec::new(),
            dir_set: Vec::new(),
            letter_set: Vec::new(),
            tag_evidence: Vec::new(),
            cover_transition: None,
            member_transition: None,
        }
    }

    /// ⛔⛔⛔ THE ONE GRIND DOOR — HEADER-ONLY PROOF OF WORK, SHARED BY EVERY NON-GOSSIP ADMISSION.
    ///
    /// THE CLASS, stated once. `dag.rs` builds a `BlockNode` at exactly FIVE literal `BlockNode{..}`
    /// sites (`add_block`, `add_ancestor_anchor`, `add_carried_block`, `add_wanted_shell`,
    /// `add_anchor`), and every one of them goes through the single store writer `Dag::insert_block`
    /// — the completeness anchor: `blocks.insert` appears at one line in the crate, and no site
    /// assigns `BlockNode.blue_work` after construction. So those five sites ARE every `blue_work`
    /// the fork choice reads, and each of them is a door that must ask whether the block was mined.
    /// One of the five (`add_block`) is gated upstream by `Node::preverify_block`'s full 3-step
    /// `pow::verify_block_pow` on every gossip/relay path. The other four had NO grind check at all,
    /// and each of them takes its weight from the wire.
    ///
    /// THIS IS THAT CHECK, WRITTEN ONCE. Four doors call it — the block-lane shell graft, the fold
    /// carry's ancestor and carried-block installs, and the anchor install — instead of four inline
    /// copies that drift (this crate has paid four times for "I fixed one of several", most recently
    /// three graft record writers where fixing one let the second re-record raw notes).
    ///
    /// WHAT IT PROVES, and what it does not. It is step 3 of `pow::verify_block_pow`, the half that
    /// needs the HEADER ALONE and no witness — exactly what a shell or a carried header carries. It
    /// also BINDS the claimed figure: `hash_meets_target` passes only while `digest × work` stays
    /// inside 256 bits, so a header claiming work 2¹²⁶ must exhibit a digest below 2¹³⁰ — the same
    /// grind an honest miner paid. Steps 1-2 (the non-outsourceable coinbase proof) cannot run on a
    /// witness-less header and are not needed here: they bind WHO mined it; the grind binds THAT it
    /// was mined, and `header.work` is the figure GHOSTDAG sums.
    ///
    /// THE NEW-DOOR CHECKLIST, for the four doors that share this: (1) PROOF OF WORK — this
    /// function, on every one of them. (2) PROOF/SIGNATURE — a carry's and an anchor's own validity
    /// is certified by the #29 decider proof over `chain_acc` verified in `sync::adopt_sync_bundle`
    /// before the install; a shell's tx list is re-hashed against its id-pinned header at its own
    /// door. (3) CONSERVATION — none of these paths mints: notes ride `graft_admitted_notes`, the
    /// one filter every graft writer passes. (4) REPLAY — every door's first act is
    /// `blocks.contains_key(&id)` / `dag().get(&id)`, a SET, so identical bytes are refused, not
    /// merely reordered. (5) BOUNDED WORK — one Poseidon2 hash of a header preimage per offered
    /// block, and `prune_below_horizon` bounds the store the block would enter. (6) PARITY WITH THE
    /// DOOR IT PARALLELS — the door these parallel is `preverify_block`; the checks it runs and
    /// these do not are the coinbase proof and the settlement/nullifier carrier verifies, which
    /// require a witness no folded block retains on any node; the grind is the one check that
    /// survives on a header alone, and it was the one missing.
    ///
    /// FAIL-CLOSED, twice: a genesis header is admitted (it is constructed locally, never fetched —
    /// `add_wanted_shell` refuses a genesis shell outright), and a node with no PoUW hasher admits
    /// NOTHING else, which is precisely what `preverify_block` has always done with a `None` hasher.
    ///
    /// ROOT-LAYER: admission is DECIDED here and PLACED in `dag.rs`. Putting the check at a reader
    /// (the fork choice, the fold, the serve) would leave the fabricated block in the store for
    /// every other reader, and a copy inside each lane's own bookkeeping is the per-site shape this
    /// round exists to replace.
    /// MEASURED 2026-09-07, three pins RED before this landed, on two real runtime nodes each:
    /// the carry's ANCESTOR door admitted a fabrication with blue_work
    /// 170141183460469231731687303715884105727 against an honest tip's 295; the carry's CARRIED
    /// door admitted one and the victim's selected tip moved to it (5433ac88… against the untouched
    /// peer's f4aa02d1…); the ANCHOR door installed one as a trust root (installed=true) and the
    /// victim's tip became b585d99d… against the peer's df128679… — a total fork-choice takeover,
    /// since `add_anchor` clears the tip set on a weight win. After: all three refuse, both parties
    /// still name one tip. The fourth door (`add_wanted_shell`) is the reviewer's own pin.
    /// cons: one Poseidon2 hash of the header preimage per offered block on the heal/adopt paths —
    /// paths that run on a loss or a jump, never per produced block. The steady-state ingest path
    /// (`add_block`) is unchanged and still pays exactly one `verify_block_pow`.
    ///
    /// ⛔⛔⛔ THE GENESIS EXEMPTION IS KEYED TO THE GENESIS ID, NEVER TO A SHAPE THE SENDER PICKS
    /// (closed 2026-09-07, family-D pin `pin_d3_a_self_minted_bundle_must_not_take_the_selected_tip_
    /// with_an_unmined_shell`). `BlockHeader::is_genesis()` is `parents.is_empty()` — a field the
    /// sender writes. So "genesis is exempt from the grind" read, to an attacker, as "any header I
    /// send with an empty parent list is exempt from the grind", and a typed-out block with no
    /// `pow_proof` and `work = u128::MAX` walked through this gate at every door that shares it. The
    /// gossip door survived that by accident (`Dag::add_block` returns `SecondGenesis` for a second
    /// parentless block); the anchor and fold-carry doors did not — `Dag::add_anchor` CLEARS the tip
    /// set on a weight win and `add_carried_block` inserts straight into `tips`, so a parentless
    /// fabrication became the sole selected tip.
    ///
    /// The exemption now names the ONE block it was written for: the block THIS node was constructed
    /// on (`Dag::genesis`), by id. Not a shape, not a count, not a flag — a sender that produces a
    /// header hashing to this node's own genesis id has produced this node's own genesis.
    ///
    /// ROOT-LAYER: the exemption is CONSUMED here, at the one function all four non-gossip doors ask
    /// for their admission verdict, and `Dag::genesis` is the value the node's own construction
    /// PRODUCED — not a field read off the wire like `parents`. Keying it at any door instead would
    /// leave the other three trusting the sender's shape, which is the "I fixed one of several"
    /// trap this crate has paid for four times.
    /// MEASURED: the family-D pins recorded the before state — a never-mined, `pow_proof`-less block
    /// with `work = u128::MAX` taking the selected tip through the anchor door on a node running the
    /// production verifier; after, that header is not this node's genesis id, so it must exhibit a
    /// grind for `u128::MAX` (a digest below 2¹²⁸) and is refused.
    /// MUST-STAY-GREEN: the #29 DSYNC adopt suite, the rolling-restart pins, and `restore_snapshot`
    /// — a datadir resume re-admits its own genesis by that exact id, and every other snapshot tip
    /// it re-admits is a block this node itself mined.
    pub(crate) fn header_grind_admits(&self, header: &crate::block::BlockHeader) -> bool {
        if header.is_genesis() && self.relay.dag().genesis() == Some(header.id()) {
            return true; // THIS node's own genesis, by id — constructed locally, never fetched
        }
        match self.pow_miner.as_ref() {
            Some(m) => crate::pow::hash_meets_target(
                &m.hasher().hash(&header.preimage()),
                header.work,
            ),
            None => false,
        }
    }

    /// The door, with the PoUW-witness requirement made EXPLICIT at the call site.
    ///
    /// ⛔⛔⛔ WHY THIS IS A PARAMETER AND NOT A CONSTANT, MEASURED 2026-09-13. The witness is the only
    /// thing separating "this header was ground to its own declared target" (a handful of hashes at the
    /// live DAA figure — the audit's R1 pin does it in SEVEN) from "somebody mined this". Every door
    /// should want it. But a DSYNC bundle's FOLD CARRY is a window of blocks rebuilt from the DAG, which
    /// retains header + tx ids and nothing else — so those blocks have no witness to carry, and one
    /// witness is **21,527 bytes**: requiring it for the carry would put ~83 blocks over the ≤1.8 MB
    /// bundle budget the sync pillar guarantees. That is a real constraint, not a preference.
    ///
    /// So the requirement is placed where the audit DEMONSTRATED the attack — the anchor and the tip,
    /// the blocks whose weight `Dag::add_anchor` stores verbatim as a permanent fork score
    /// (`admit_anchor_block(fake, u128::MAX, 7)` in R1/R2/review_b1/b2) — and the carry is named as the
    /// remaining surface rather than silently exempted.
    ///
    /// ⛔ THE CARRY IS NOT SAFE, IT IS UNPROVEN HERE AND PROVEN ELSEWHERE OR NOT AT ALL. Its blocks ride
    /// a certificate that `family_d_door_audit_tests::pin_d1` shows proves nothing about a chain — that
    /// pin is RED by design and is the real fix for this surface. Closing it is what lets this parameter
    /// become a constant `Required`, and until then every `NotServable` below is a piece of the join
    /// door that is still open.
    pub(crate) fn header_door_admits_witnessed(
        &self,
        block: &crate::block::Block,
        now_ts: Option<u64>,
        witness: PowWitness,
    ) -> bool {
        let header = &block.header;
        // ⛔⛔⛔ THE NON-OUTSOURCEABLE PoUW WITNESS — THE ONE CHECK THIS DOOR DID NOT CARRY, AND THE ONE
        // THAT MAKES THE GRIND MEAN ANYTHING (2026-09-13, door-audit R1/R2/R3 + review_b1/b2).
        //
        // `header_grind_admits` below asks only that `hash(preimage)` meets the header's OWN DECLARED
        // `work`. At the live DAA figure that is a handful of hashes: the audit's R1 pin grinds an
        // anchor in SEVEN, with `pow_proof` EMPTY, and this door admitted it — after which
        // `Dag::add_anchor` stored the caller's `blue_work` verbatim (the pin passes `u128::MAX`) as
        // that block's permanent fork score. A joiner then holds a sole selected tip no honest chain
        // can ever outrank. That is not a difficulty question; it is chain takeover through the DSYNC
        // anchor door, and it needed no mining at all.
        //
        // ⭐ THE GOSSIP DOOR HAS ALWAYS CHECKED THIS and the four non-gossip doors never did — one call
        // to `pow::verify_block_pow`, the proof `pi` that binds the miner's spend key so the work
        // cannot be bought from a pool. `header_work_is_bound` could not substitute: it returns TRUE
        // whenever a parent is absent from this DAG, and a DSYNC anchor's parents are absent BY
        // CONSTRUCTION on the node adopting it (R2), and TRUE on `is_genesis()`, which is how a
        // parentless second genesis walked in (R3).
        //
        // ROOT-LAYER: asked HERE, so all four doors (`add_anchor`, `add_ancestor_anchor`,
        // `add_carried_block`, the bundle admission) get it from one site — the same reason the grind
        // and the structural rules live here rather than at each caller.
        // ⛔ FAIL-CLOSED ON A HASHER-LESS NODE, exactly as `preverify_block` does: a node that cannot
        // verify work admits nothing rather than admitting everything.
        // ⛔⛔⛔ THE GENESIS EXEMPTION IS BY **ID**, NEVER BY SHAPE (door-audit R3).
        //
        // My first version of this gate exempted `is_genesis()` — the SHAPE — on the reasoning that
        // `header_grind_admits` already decides genesis by id. It does, for the GRIND; it does not stop
        // a foreign parentless shell reaching the rest of this door, and the audit's R3 pin is exactly
        // that shell: `is_genesis()` true, id NOT this node's genesis, work declared 1. It skipped the
        // PoUW check on the shape, satisfied the grind in a handful of hashes, and then sailed through
        // `validate_header_structural` — which skips EVERY parent rule for that shape — and through
        // `header_work_is_bound`, which returns true on `is_genesis()`. A second genesis with
        // `blue_work = u128::MAX`, mined by nobody.
        //
        // ⭐ AN EXEMPTION WRITTEN ON A SHAPE IS AN EXEMPTION ANYONE CAN WEAR. This node has exactly ONE
        // genesis and it knows its id, so that is the whole of the rule: a parentless header is admitted
        // only when it IS that block. Every other parentless header is a shell and is refused here,
        // before the rules that do not apply to genesis can be borrowed by something that is not.
        let own_genesis =
            header.is_genesis() && self.relay.dag().genesis() == Some(header.id());
        if header.is_genesis() && !own_genesis {
            return false;
        }
        if !own_genesis && witness == PowWitness::Required {
            let mined = match self.pow_miner.as_ref() {
                Some(m) => crate::pow::verify_block_pow(header, &block.pow_proof, m.hasher()),
                None => false,
            };
            if !mined {
                return false;
            }
        }
        if !self.header_grind_admits(header) {
            return false;
        }
        if crate::consensus::validate_header_structural(
            header,
            &block.tx_ids,
            now_ts,
            self.params(),
        )
        .is_err()
        {
            return false;
        }
        if crate::consensus::validate_carried_body_commitments(block).is_err() {
            return false;
        }
        self.header_work_is_bound(header)
    }

    /// ⛔⛔⛔ THE THIRD CLAUSE OF THE ONE HEADER DOOR — THE SENDER DOES NOT GET TO DECLARE ITS OWN
    /// DIFFICULTY (2026-09-08, §9.6 adversarial review MUST-FIX 1 and MUST-FIX 2).
    ///
    /// WHAT WAS PROVEN AGAINST THE PREVIOUS ROUND. `pow::hash_meets_target` is EXACT arithmetic and
    /// stays exact: at `work == 1` the target is the whole digest space, so every digest meets it —
    /// and `work == 1` is an HONEST value (`miner::adaptive_work` ends `next.max(1)`, and its own
    /// lower clamp is `(avg/4).max(1)`), which is why no minimum-work constant was added then and
    /// none is added now: a floor above the live DAA figure — MEASURED at 2 on this tree, with
    /// `WrongWork { expected: 5, got: 4 }` in the restart search — refuses blocks the running chain
    /// has already accepted. That is a halt dressed as a hardening.
    ///
    /// THE FREEDOM IS THE FIGURE, NOT THE ARITHMETIC, and it is removed by the DAA equality:
    /// `header.work` is not a value a sender chooses, it is `miner::adaptive_work(dag,
    /// selected_parent)` for the block's OWN parents. The gossip door has always enforced that
    /// (`consensus::validate_contextual` → `WrongWork`) and the block-locator descent door adopted
    /// it in the last round. The other FOUR callers of this door — the anchor install, the carry's
    /// ancestor and carried-block installs, and the #29 DSYNC bundle verdict — did not, so at every
    /// one of them a header could declare `work = 1`, exhibit no grind at all, and be admitted.
    /// MEASURED by the reviewer: a bundle whose tip/anchor is a never-mined header with `work = 1`
    /// and a `tx_merkle_root` matching its empty tx list PASSED `bundle_blocks_admitted` whole.
    ///
    /// SO THE EQUALITY MOVES TO THE SHARED SITE — all five callers, one edit, per §9.5. It is asked
    /// HERE and not by adding `validate_contextual` to each door, because that function also carries
    /// the median-time-past and mergeset rules, and those two read a selected-chain walk that a
    /// jumped or restored node does not have: running them here would refuse honest carried blocks.
    /// The work equality is the one rule of the three that can be made SAFE at every door, and this
    /// is how:
    ///
    /// ⛔ IT BINDS ONLY WHEN THIS NODE IS ENTITLED TO JUDGE. `miner::adaptive_work_checked` reports
    /// whether the sample it walked IS the chain's (a full `daa_sample_len` span, or rooted at this
    /// DAG's own genesis by id) or merely the most this node could see. On an INCOMPLETE sample the
    /// door does not refuse: a node that has jumped, restored, or not yet backfilled has no standing
    /// to call an honest peer's figure wrong, and this crate has already paid for pretending
    /// otherwise (the restart search's two-way `WrongWork`). That is not a hole left open by choice
    /// — it is the same `UnknownParent` tolerance the descent door has always had, stated as the
    /// completeness predicate that actually names the condition.
    ///
    /// ⛔ AND ONLY WHEN THE PARENTS ARE ALL HELD. With a partial parent set the selected parent this
    /// node would pick is not the one the producer picked, so the figure computed from it is not the
    /// figure the producer was bound to. Judging on it would refuse honest blocks whose ancestry is
    /// still arriving — the parents-first case every heal lane exists to serve.
    ///
    /// ROOT-LAYER: this is the ONE function all five non-gossip admissions ask for their verdict
    /// (`dag.rs` only PLACES what they decide), so the rule governs all five at once; added at any
    /// single door it would leave the other four trusting a sender-written field, which is the
    /// "I fixed one of several" shape this crate has paid for five times. And it is asked BEFORE the
    /// block is placed, because `header.work` becomes a `miner::adaptive_work` sample and a
    /// GHOSTDAG blue_work term for everything above it the moment it lands — no reader can undo it.
    /// MEASURED 2026-09-08, filtered single-test runs, warm dir ~/.cargo-targets/refut-laneA —
    /// before, the reviewer's fixture (never mined, no `pow_proof`, `work = 1`, `tx_merkle_root` =
    /// `miner::tx_merkle_root` of its own empty tx list) passed `bundle_blocks_admitted` whole.
    /// After, the three pins print:
    ///   `[refut] bundle_blocks_admitted=false declared_work=1 expected=16 daa_sample_complete=true`
    ///   `[refut] anchor installed=false in_dag=false tip_after=e59280cc… honest_tip=e59280cc…`
    ///   `[refut] honest header work=3 expected=3 complete=true`
    ///   `[refut] no-tip walk figure=16 complete=false`
    /// — the fabrication is refused at BOTH the bundle verdict door and the anchor door, the honest
    /// tip is untouched, and an honestly produced header is admitted by a clause that DID run
    /// (`complete=true`, so the pass is not vacuous).
    /// MUST-STAY-GREEN: the honest heal and adopt paths, which is why the two guards above exist —
    /// the #29 DSYNC adopt suite and `two_nodes_instant_sync_roundtrip_serve_then_adopt` (an
    /// adopter's DAG does not hold the anchor's parents ⇒ not judged), `restore_snapshot` (a resume
    /// re-admits its own genesis by id and its own mined tips, and its walks end on a parentless
    /// restored anchor ⇒ not judged), the page-speed descent heal and every other honest shell graft
    /// (a real produced header's work IS the DAA figure for its parents, computed from the same
    /// selected-chain samples), and both rolling-restart pins.
    /// cons: at most one DAA walk per offered block, on heal/adopt/carry paths only — bounded by
    /// `daa_sample_len` = 60 reads of 24 B, a CONSTANT ceiling at any chain length. The steady-state
    /// gossip path does not reach this function at all. SIZE: zero — it reads and writes nothing.
    pub(super) fn header_work_is_bound(&self, header: &crate::block::BlockHeader) -> bool {
        if header.is_genesis() {
            // A parentless header has no parent to compute a figure from. `header_grind_admits`
            // above has already decided this case by id (only THIS node's own genesis is exempt
            // from the grind), and `validate_contextual` returns `Ok` for the same shape, so the
            // two doors agree.
            return true;
        }
        let dag = self.relay.dag();
        if header.parents.iter().any(|p| !dag.contains(p)) {
            // Parents still arriving: not judgeable here, and the heal lanes exist for exactly this.
            return true;
        }
        // The producer's selected parent, by the DAG's own total order key — the ONE function
        // `consensus::validate_contextual` and the template read (`Dag::selected_parent_of`), so no two doors can
        // disagree on WHICH parent the figure is computed from.
        let Some(sp) = dag.selected_parent_of(&header.parents) else {
            return true; // unreachable: `validate_header_structural` refused NoParents above
        };
        let (expected, complete) = crate::miner::adaptive_work_checked(dag, Some(sp));
        !complete || header.work == expected
    }

    /// WHY the header door refuses a bundle, named (run 28, 2026-09-18: eighteen refusals read only
    /// "grind or header structure"). `None` = admitted.
    pub(crate) fn bundle_blocks_refusal(&self, bundle: &SyncBundle) -> Option<String> {
        // ⭐ DB-135b (2026-09-21): a tip or anchor THIS DAG ALREADY HOLDS was admitted through a door once —
        // the gossip door with its witness, or this node's own checkpoint — so its witness is not demanded
        // again. Re-demanding it refused honest bundles from a resumed peer whose anchor was OURS already
        // (MEASURED, live pair 19:13: "REFUSED a bundle … (anchor block: no witness carried)" on both
        // nodes). A block this DAG does NOT hold keeps the full `Required` policy: nothing a stranger names
        // walks in without its witness, and a forged body for a held header still fails the body
        // commitments and tx-merkle checks the door runs whatever the policy.
        // ROOT-LAYER: the witness policy for a bundle block is decided here and nowhere else.
        // MUST-STAY-GREEN: `family_d_door_audit_tests` (a witness-less anchor this node does not hold is
        // refused). cons: none — one DAG lookup per bundle block, O(1); no new store, no growth.
        let policy = |b: &crate::block::Block| {
            if self.relay.dag().get(&b.id()).is_some() { PowWitness::NotServable } else { PowWitness::Required }
        };
        if let Some(r) = self.header_door_refusal(&bundle.tip_block, None, policy(&bundle.tip_block)) {
            return Some(format!("tip block: {r}"));
        }
        if let Some(r) = self.header_door_refusal(&bundle.anchor_block, None, policy(&bundle.anchor_block)) {
            return Some(format!("anchor block: {r}"));
        }
        for (b, _, _) in bundle.fold_carry.ancestors.iter() {
            if let Some(r) = self.header_door_refusal(b, None, PowWitness::NotServable) {
                return Some(format!("a carried ancestor: {r}"));
            }
        }
        for (b, _, _) in bundle.fold_carry.unfolded.iter() {
            if let Some(r) = self.header_door_refusal(b, None, PowWitness::NotServable) {
                return Some(format!("a carried unfolded block: {r}"));
            }
        }
        None
    }

    /// The header door's checks in their order, naming the first that refuses (`None` = admitted). The
    /// same checks as [`Self::header_door_admits_witnessed`], which stays the boolean door.
    pub(crate) fn header_door_refusal(
        &self,
        block: &crate::block::Block,
        now_ts: Option<u64>,
        witness: PowWitness,
    ) -> Option<&'static str> {
        let header = &block.header;
        let own_genesis = header.is_genesis() && self.relay.dag().genesis() == Some(header.id());
        if header.is_genesis() && !own_genesis {
            return Some("a foreign genesis");
        }
        // ⭐ KASPA'S MERGE-DEPTH BOUND (2026-09-21, the one-DAG rule): a block may not name a parent this
        // node holds more than `merge_depth_cap` blue score below its selected tip. Below that depth the
        // DAG is settled — every node keeps the same span above it (`Dag::keep_depth`) and the block window
        // deletes below it — so a block reaching under it would reorganize what peers have already pruned.
        // Kaspa refuses such a block outright (its merge depth rule); so does this door. A parent this node
        // does NOT hold is not judged here: it parks as an orphan and is fetched, exactly as before.
        // A node that RESUMED behind (the resume rule, DB-135b) builds on its own held tip, which is
        // inside the bound for any peer within the live-tip span, so an honest restart is never refused.
        // ROOT-LAYER: the bound is a function of the live params and the selected tip, the same on every
        // node. MUST-STAY-GREEN: every carried-block and gossip-door pin (their parents sit at the tip).
        // cons: none — one DAG lookup per parent, at most `dag_width` of them.
        if !own_genesis {
            let dag = self.relay.dag();
            if let Some(tip) = dag.selected_tip().and_then(|t| dag.get(&t)) {
                let bound = tip.blue_score.saturating_sub(self.params().merge_depth_cap as u64);
                if bound > 0
                    && header.parents.iter().any(|p| dag.get(p).is_some_and(|pn| pn.blue_score < bound))
                {
                    return Some("merges below the merge depth");
                }
            }
        }
        if !own_genesis && witness == PowWitness::Required {
            let mined = match self.pow_miner.as_ref() {
                Some(m) => crate::pow::verify_block_pow(header, &block.pow_proof, m.hasher()),
                None => false,
            };
            if !mined {
                return Some(if block.pow_proof.is_empty() { "no witness carried" } else { "witness does not verify" });
            }
        }
        if !self.header_grind_admits(header) {
            return Some("grind below the claimed work");
        }
        if crate::consensus::validate_header_structural(header, &block.tx_ids, now_ts, self.params()).is_err() {
            return Some("header structure");
        }
        if crate::consensus::validate_carried_body_commitments(block).is_err() {
            return Some("carried body commitments");
        }
        if !self.header_work_is_bound(header) {
            return Some("work figure differs from this node's difficulty reading");
        }
        None
    }

    /// ⭐ DB-302: THE HEADERS-FIRST DOOR, ONE PREDICATE. True while a jump's roots-run span is open and `ordinal` lies at or
    /// above its origin: this node holds no judged root there yet, so bytes for that position can only be refused (the
    /// door, not the record). Every reader of the rule calls this — the root read (`da_block_root_at_ordinal`), the
    /// verified-fetch door's want root and refusal reason, and the two byte asks (`record_row_top`,
    /// `wanted_record_ordinals`). The by-id ask applies the same door to the whole ask (`roots_run_closed`).
    pub fn headers_first_door_open_at(&self, ordinal: u64) -> bool {
        !self.roots_run_closed() && ordinal >= self.roots_run_origin()
    }

    /// Push the quorum's finalized block into the DAG as its fork-choice floor.
    ///
    /// Called after any outcome that may have advanced finality, so the floor and
    /// `FinalityTracker::finalized_height` can never disagree. The DAG treats a floor it does not hold as
    /// no floor at all, so this is safe to call unconditionally — see [`Dag::selected_tip`].
    pub(super) fn sync_finality_floor_into_dag(&mut self) {
        // SPEED L7: the floor follows the higher of the chain's finality and this node's observed one (`user_final_block`);
        // honest floors lie on one chain by quorum overlap, and with the lever off the two are the same block.
        let floor = self.user_final_block();
        // Votes arrive far more often than finality ADVANCES (a stride-aligned checkpoint every few
        // blocks, versus one vote per validator per second), so read the installed floor first and take
        // the `&mut` borrow only when it actually changed.
        if self.relay.dag().finality_floor() == floor {
            return;
        }
        self.relay.dag_mut().set_finality_floor(floor);
    }

    pub fn instant_sync(&mut self, bundle: SyncBundle) -> AdoptOutcome {
        // The record fold this node VERIFIED before anything from the bundle is adopted. The adopt below
        // rewrites `served_membership_acc` with the bundle's spine root; the roots-run door needs the
        // pre-adopt value (= GENESIS for a node that folded nothing) as the run's fold origin.
        let own_record_acc_at_entry = self.served_membership_acc;
        // db333-r: the blocks the adopted state counts (`FoldCarry::covered`), held here or not — D-36 never re-folds one.
        let mut adopted_covered: std::collections::HashSet<BlockId> = std::collections::HashSet::new();
        let sync_t0 = std::time::Instant::now();
        // ⭐ DB-316c: the spine binding and the header door run in ONE helper that both #29 doors call.
        let verdict = match self.served_bundle_prefix_refusal(&bundle) {
            Ok(v) => v,
            Err(refused) => return refused,
        };
        // A-F49: the join door's verdict authenticates a bundle that carries no decider proof or certificate.
        let outcome = adopt_sync_bundle(&*self.decider_verifier, Some(&verdict), &bundle);
        let ms_verify = sync_t0.elapsed().as_millis();
        // D-50: the certified unspent root is adopted AFTER the fold carry (below the block that reads
        // it), so the I2 keep sees every hole the carry names by id. Captured here, applied there.
        let mut certified_unspent_root: crate::spend_frontier::Digest4 = usdm_decider::poseidon2_compress::lanes_of(&usdm_decider::poseidon2_compress::zero_digest());
        if let AdoptOutcome::Adopted(state) = &outcome {
            // GENESIS-EXACT GRAFT GATE (deterministic-convergence keystone, user 2026-07-14: "two separate
            // devices must converge on the SAME chain"). Genesis identity is a DETERMINISTIC per-network constant
            // (`network_genesis_prefix`): every node on a network computes the identical genesis by construction,
            // with zero per-node/per-device input — so two honest same-network nodes ALWAYS share it and a chain
            // split is impossible by construction. A node therefore grafts ONLY a tip whose proof-bound chain
            // roots at its OWN genesis; a self-consistent bundle proving a chain rooted at a DIFFERENT genesis is
            // REJECTED and never grafted, so a node can never be dragged onto a chain it does not share a genesis
            // with (this is what makes cross-device convergence DETERMINISTIC — each device settles on the one
            // chain its f(network) genesis roots at, never flip-flopping). Fail-closed on the bad bundle only,
            // exactly like the datadir-resume genesis refusal (`restore_snapshot`) — never a halt.
            if state.genesis_commit != self.params().genesis_parity_commit {
                return AdoptOutcome::GenesisMismatch;
            }
            // M6-S (2026-09-28): a joiner CONTINUES the served certificate. The certificate is a chain object
            // carried forward, not a per-node possession — a node that jumped can never fold from genesis to this
            // tip on its own, so without this line it could never serve a bundle that verifies. The gate above
            // verified the step and its work against this bundle; `inherit` re-verifies (fail-closed, `None` is
            // "keep what we hold"). ROOT-LAYER: installed where the adopted state is installed, beside the
            // validator set and the peg view. MEASURED: certificate_door fixpoint runs 5 and 6 — an inherited
            // certificate's third step proves and verifies (178,093 B, verify 221 ms). MUST-STAY-GREEN: every
            // jump pin; `install_cert_step`'s DB-243 guard (a stepped-off-the-lock result over a moved base is
            // still refused — inheritance moves the base, as any adopt does).
            // ⭐⭐⭐ RESPONSE-SIDE FORK CHOICE — ADOPT ONLY A STRICTLY HEAVIER CERTIFIED CHAIN.
            //
            // The beacon filter already promises "a same-or-lighter beacon is ignored", but the promise
            // was only kept at the HINT: a SyncResponse that arrived late (Tor delivers in seconds, and a
            // node overtakes the peer it asked in that time) or unsolicited was installed here with NO
            // comparison against this node's own position. Every certified field below — sparse nullifier
            // root, unspent-note root, fold base, synced state — then moved BACKWARDS onto the older chain
            // position while the DAG tip (guarded separately inside `add_anchor`) stayed ahead, splitting
            // the state layer from the DAG. MEASURED 2026-08-26 (gate run 12, scratch musd-ecocheck-aGt9YA):
            // both nodes' adopt trails were non-monotonic (n1 …998→1080→964; n2 …1010→962) and the pair
            // flapped for the full 420s reconvergence allowance, each side re-installing the other's stale
            // bundle. It is also a REWIND ATTACK surface: any peer could push a verified-but-old bundle and
            // drag a node's spent-state gate backwards. ([[feedback_adversarial_by_design]])
            //
            // The order is the DAG's own deterministic total order `(blue_work, tip id)` — the SAME key
            // `add_anchor` reorgs by — so the equal-work island merge is preserved exactly: of two islands
            // at identical blue_work, precisely ONE sees the other as greater and adopts; the other refuses.
            // Strictly-lighter and self-same bundles are the level-peer steady state, refused quietly
            // (NotHeavier), never an alarm. Fail-closed on the stale bundle only — never a halt; a node
            // with no tip of its own (nothing to regress) adopts anything verified, as before.
            {
                // A node that holds gossiped blocks it cannot place (the peer's blocks whose parents it
                // lacks) knows the peer's DAG contains blocks its own does not: its own tip's weight is
                // a partial count, not a fork choice. Gate 45 (2026-09-03, scratch H90thk): a restarted
                // node produced alone on its old tip while the peer's blocks piled up as orphans, each
                // side saw itself heavier, and 17 bundles were refused NotHeavier until an ordinal
                // conflict finally forced the adopt minutes later.
                let behind = self.relay.buffered_len() > 0
                    && self.relay.dag().get(&bundle.decider.tip).is_none()
                    && self.relay.dag().get(&bundle.anchor_block.id()).is_none();
                // ⭐ THE BAND'S RE-ANCHOR (lane b 2026-10-22, the launch journey's T1.6 at 10 nodes). A JOINED node is
                // brought every block by the lanes, so every later served bundle is lighter than its live tip — while
                // its band, more than the band journal's reach behind the served one, can be moved by nothing but a
                // certified re-adopt (no honest door serves those steps: `band_past_journal_reach`, link 84). The
                // runtime takes "the certified jump inside the catch-up depth" for exactly this, and this gate refused
                // every one of them against the LIVE tip. MEASURED scratchpad/verify/f1-launch-20261022-1329.log: the
                // joiner adopted twice (blue 991, 1114), then grafted the live tip by relay (tip 7961) with its band at
                // ordinal 986 and the mesh's at ~7800 — 108 bundles refused NotHeavier, band jobs 0, fold wedged at
                // 1003 for the rest of the run. Such a band is the band twin of a stale spine: the bundle is the
                // certified re-anchor its fold waits for, measured against the ANCHOR. Monotone, never a rewind: the
                // bundle's band is strictly AHEAD of ours by more than the reach and its work at least the anchor's.
                // cons: none for a node — a band inside the reach, or ahead of the bundle's, keeps today's gate.
                let band_far = crate::node_runtime::band_past_journal_reach(
                    self.band_next_ordinal(),
                    bundle.nullifier.band_next_ordinal,
                    self.band_journal_reach(),
                );
                // ⭐ THE SHELL HOLD'S RE-ANCHOR (lane a 2026-10-26, T4): a node held for shells whose state it never applied
                // (DB-4 / DB-274 P5) polls the certified bundle that covers them — and the lanes bring such a node every
                // block, so the bundle is always lighter than its live tip and this gate refused the one carrier of a body
                // past every peer's window. Measured against the ANCHOR like a stale spine, and only a bundle whose tip is
                // at or above the lowest held shell's score (it covers one). Door checklist (§9.6): PoW + the decider proof
                // are verified below exactly as on every adopt; value is the certified state, never this node's; replay
                // is refused by the anchor-work monotone check; work is one bundle verify; parity: the stale-spine arm's
                // checks, all kept. cons: none — a node with no held shell keeps today's gate.
                let shells_covered = self.unapplied_shell_floor.map_or(false, |f| bundle.decider.blue_score >= f);
                let reanchor = self.spine_stale || behind || band_far || shells_covered || self.fold_stuck_behind(bundle.anchor_ordinal);
                let ours = {
                    let dag = self.relay.dag();
                    // A node whose spine is stale — or whose DAG is known-partial, or whose band is past the relay's
                    // reach — measures a bundle against its ANCHOR (the last certified state it holds), not its tip.
                    let against = if reanchor {
                        self.certified_anchor.or_else(|| dag.genesis())
                    } else {
                        dag.selected_tip()
                    };
                    against.and_then(|t| dag.get(&t).map(|n| (n.blue_work, *t.as_bytes(), n.blue_score)))
                };
                // A bundle anchored on a fork this node does not hold is weighed by its chain (`chain_work`): its anchor alone sits
                // tens of blocks below its tip and always reads lighter than our tip, so a deeper fork was never adopted (MEASURED
                // 2026-11-07, heal.py). A bundle on this node's own chain keeps the anchor's work: its suffix is blocks this node
                // already weighs, and counting them again would take an older anchor over a live tip.
                let other_fork = self.relay.dag().get(&bundle.anchor_block.header.id()).is_none();
                let served_work = if other_fork { bundle.chain_work() } else { bundle.blue_work };
                if let Some((our_work, our_tip, our_score)) = ours {
                    if (served_work, *bundle.decider.tip.as_bytes()) <= (our_work, our_tip)
                        && !(reanchor && bundle.blue_work >= our_work)
                    {
                        // DB-32 (run 44): 62 heavier beacons, 3 fetched bundles, all NotHeavier — the two
                        // weights are said here so a stale served bundle is told apart from a real refusal.
                        // DIGITAL-CASH-PRIVACY-REVIEWED: chain weights, scores and two public fold ordinals only.
                        eprintln!(
                            "[dsync] NotHeavier: the bundle certifies blue_score {} / blue_work {} against ours {our_score} / {our_work} (behind={behind}, spine_stale={}, band_far={band_far}: ours {} vs served {})",
                            bundle.decider.blue_score, bundle.blue_work, self.spine_stale, self.band_next_ordinal(), bundle.nullifier.band_next_ordinal
                        );
                        // (DB-353 landing 2: the DB-316c "candidate from a NotHeavier bundle" retired with the pivot move.
                        // A band is adopted only WITH the DAG it belongs to — rebasing a stale door at another node's fold
                        // ordinal would drop the steps this node folded past it — so a node whose door is stale keeps its
                        // vouched-only ask due until a certified bundle it can adopt arrives.)
                        return AdoptOutcome::NotHeavier;
                    }
                    if reanchor && (bundle.blue_work, *bundle.decider.tip.as_bytes()) <= (our_work, our_tip) {
                        // the re-anchor arm admitted a bundle no heavier than the anchor — say which term opened it
                        // DIGITAL-CASH-PRIVACY-REVIEWED: chain weights and flags only.
                        eprintln!(
                            "[dsync] re-anchor adopt at blue_work {} (ours {our_work}): behind={behind}, spine_stale={}, band_far={band_far}, shells={shells_covered}",
                            bundle.blue_work, self.spine_stale
                        );
                    }
                }
            }
            self.synced = Some(state.clone());
            // Where this node's own fold last agrees with the bundle's chain, read BEFORE the bundle's steps are seeded into it:
            // afterwards every step matches by construction (MEASURED 2026-11-07, heal.py: the origin stayed at the live depth).
            let shared_fold = self.last_shared_fold_ordinal(&bundle);
            self.join_take_adopted(&bundle);
            self.certified_blue_work = bundle.blue_work;
            // Gap2 — INHERIT the certified spent-state: jump the O(1) nullifier accumulator to the bundle's
            // proof-bound `(root, count)`. Because it was welded into `sync_binding` (checked above against the
            // decider-certified `chain_acc`), a peer could not have forged it, so the joiner's double-spend checks
            // self-verify against a spent-state it never had to replay — the nullifier twin of the frontier jump.
            // (Verifier-side O(1) state; a node that will PRODUCE rebuilds its full DA tree `nullifier_imt` from the
            // #27 DAS nullifier stream, exactly as it rebuilds the note set — the acc is the authoritative verify root.)
            // IMT RETIRED: the jumped node inherits the certified nullifier BLOCK COUNT (one u64) instead of an
            // IMT root+count. The spent-state root it gates against is the certified SPARSE root adopted below.
            self.nf_blocks = state.nullifier_count.saturating_sub(1)
                / crate::cover::BLOCK_FIXED_NULLIFIER_COUNT as u64;
            // ⛔ INHERIT THE LEAF COUNT TOO — `nullifier_count()` is `1 + nf_leaves`, so deriving `nf_blocks`
            // here while leaving `nf_leaves` at its genesis value left a jumped node reporting a spent count of
            // 1 against the certified 257 it had just adopted. MEASURED: `two_nodes_instant_sync_roundtrip…`
            // failed "B inherited A's spent count" left:1 right:257 — with B's nullifier ROOT already matching
            // A's, i.e. the accumulator jumped correctly and only this wire-served figure lagged.
            // ROOT-LAYER: this is the one place a jumped node installs the certified nullifier state, so it is
            // where every field of that state must land — not a downstream reader that patches the count back up.
            // Same certified `state.nullifier_count` already bound into `chain_acc`, so a peer cannot forge it.
            // cons: none — one u64 assignment, no growth on any axis.
            // MUST-STAY-GREEN: two_nodes_instant_sync_roundtrip_serve_then_adopt,
            // a_jumped_node_adopts_the_certified_nf_unspent_acc_and_a_forged_one_is_rejected.
            self.nf_leaves = state.nullifier_count.saturating_sub(1);
            // ⛔ D-47 (2026-09-11) — THE A_TIP FOLD COUNT INHERITS FROM THE SAME CERTIFIED COUNT. `nf_fold_seq`
            // (blocks folded into A_tip; the "absence-fold position" the cold-peer verdict compares) stayed
            // at this node's OWN pre-jump value while the accumulator, `nf_blocks` and `nf_leaves` all
            // jumped: MEASURED (fuzz lane, 1-minimal `Produce(1,1) · Jump(0,1)`) the jumper held
            // nullifier_count 513 (two blocks) with nf_fold_seq 0 where a chain-only replay derives 2 —
            // and the jump base it then published was `(acc, 0)`. One sent value (`nullifier_count`, bound
            // into `chain_acc`), every derived count read from it; the D-36 re-fold of held blocks outside
            // the inherited past advances it further exactly as it advances the accumulator.
            self.nf_fold_seq = self.nf_blocks;
            // SPARSE CUTOVER — O(1) SPARSE JUMP: adopt the CERTIFIED sparse root too (bound into `chain_acc` above, so
            // a peer cannot forge it), warming the jumped node's sparse double-spend gate WITHOUT a rebuild.
            // ⛔ DB-321: ZERO is a server that could not VOUCH for its root (`vouched_sparse_root`), and a non-canonical
            // root is refused by the adopt. Either way this node's OLD accumulator describes a set the adopt just
            // replaced, so it keeps NO pivot rather than one no warm can reach.
            if state.sparse_root == [0u8; 32] || !self.adopt_sparse_snapshot(state.sparse_root) {
                self.forget_unvouched_sparse_root();
            }
            // ⭐⭐ DB-353 P5 (§11.13 C4, §13.3 C-2) — THE CERTIFIED BAND, adopted with the fold ordinal it waits at and every
            // awaiting step's admitted set, so this node verifies relayed band steps from minute 0 instead of waiting on
            // steps it never folded. The accumulator then follows the band; the view warms to it (a jumped node holds none).
            // §9.6, this door's admission change answered:
            // 1. PoW — unchanged: the bundle's tip passed the header door; the band rides the same bundle.
            // 2. Proof — bound into `sync_binding` beside `sparse_root` and certified with it; the decider proves neither
            //    (the D01/Q2 residual, stated, unchanged). Cross-checked here: a vouched `sparse_root` must EQUAL the
            //    carried band's fold, or the band is refused.
            // 3. Conservation — the band is a spent-set commitment and moves no value; admission still rides the A_tip
            //    absence carrier.
            // 4. Replay — `adopt_certified` REPLACES the band: the same bundle twice lands on the same state.
            // 5. Bounded work — one fold of a fixed-width band; `adopt_certified` refuses the wrong width, a step below
            //    its next ordinal, more steps than the lag cap, an ordinal twice.
            // 6. Parity — the sparse-root adopt above (same binding, same trust), plus those structural refusals.
            // A carriage refused for any reason (an older or stale server carries none) leaves this node's band as it
            // was: it waits for a certified one, never guesses.
            let band_fold = usdm_decider::nf_sparse_air::fold_band(&state.band);
            let agrees = band_fold.is_some_and(|r| {
                state.sparse_root == [0u8; 32] || crate::spend_frontier::leaf_to_cm_bytes(r) == state.sparse_root
            });
            if agrees
                && self.band_door.adopt_certified(state.band.clone(), state.band_next_ordinal, state.band_awaiting.clone())
            {
                self.band_cursor = crate::nf_sparse::BandCursor::new();
                self.join_install_history();
                self.view_follow_band_root();
            } else {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a fixed phrase; no tag, root, amount or owner.
                eprintln!(
                    "[dsync] the bundle carried no band this node could adopt (an older or stale server, or a band that \
                     disagrees with the bound sparse root) — the band waits for a certified one"
                );
            }
            // ⭐ AND THE TOKEN REGISTRY, adopted VERBATIM like the sparse root beside it: a jumped node
            // cannot rebuild it (creations live in past blocks a jump does not replay), and without it the
            // mint gate refuses every honest mint on this node forever. It is bound into `sync_binding`,
            // so a peer cannot substitute one, and it is REFUSED rather than repaired if the parts do not
            // describe their own count.
            // A-F31: adopted VERBATIM, an EMPTY one included. A node re-anchoring from a branch that registered assets the
            // certified chain never registered must not keep them (the registry is a function of the chain it follows).
            match crate::dsol::DsolRegistry::from_parts(state.dsol_registry_count, &state.dsol_registry_peaks) {
                Some(r) => *self.peg.dsol_tokens_mut() = r,
                None => {
                    *self.peg.dsol_tokens_mut() = crate::dsol::DsolRegistry::new();
                    if state.dsol_registry_count != 0 {
                        // DIGITAL-CASH-PRIVACY-REVIEWED: counts of PUBLIC creations only.
                        eprintln!(
                            "[dsol] ⛔ REFUSED a carried token registry whose {} peak(s) do not describe its count of {}: this \
                             node holds an empty registry, which refuses mints and never admits an unregistered one",
                            state.dsol_registry_peaks.len(),
                            state.dsol_registry_count
                        );
                    }
                }
            }
            // ⭐⭐⭐ ADOPT THE CERTIFIED BONDED VALIDATOR SET (finality quorum) — the island fix's bond
            // twin: a jumped joiner cannot recompute the quorum (the admitting bond blocks are pruned
            // history), so it installs the set the binding above just certified. This is what lets a
            // DSYNC joiner weigh the mesh's finality votes the instant it converges, instead of holding
            // `validators=0` and a frozen finalized_height forever (MEASURED live 2026-08-22). Adopt
            // only a NON-EMPTY carried set: an empty one certifies "no quorum yet", and overwriting a
            // local set with empty would let an old-format bundle strip a node's quorum.
            // ⛔ G2g-r (lane b 2026-10-24): "non-empty" is the SET's emptiness (`ValidatorSet::is_empty`: custody
            // OR finality weight), never the custody map alone — bonds are SAT-only, so a launch mesh seats by
            // finality weight with no custody bond, and gating on `bonded_validators` dropped every certified seat
            // (pin `g2g_r_a_dsync_joiner_holds_the_certified_finality_seats_when_no_custody_bond_exists`: 0 vs 4).
            if !(state.bonded_validators.is_empty() && state.finality_validators.is_empty()) {
                self.validators.import_state(
                    state.bonded_validators.clone(),
                    state.slashed_validators.clone(),
                    state.slashed_bond_burned,
                    state.validator_bond_commit,
                    state.validator_custody.clone(),
                );
                self.validators.import_finality_state(state.finality_validators.clone()); // SATOSHI §6
                // G2b: the view at every height rides the certified set (bound into sync_binding beside it)
                self.validators.import_seat_activations(
                    state.custody_seat_active_from.clone(),
                    state.finality_seat_active_from.clone(),
                    state.departed_custody_seats.clone(),
                    state.departed_finality_seats.clone(),
                );
                // §BR-3 17.3: each seat's delegated part, certified beside the seats (the weights already include it)
                self.validators.import_seat_words(state.seat_words.clone());
                // …and the custodian encapsulation keys certified beside them, so this jumped node can
                // seal a peg-in delta to the quorum (`crate::peg_attest`).
                self.validators.import_kem_eks(state.validator_kem_eks.clone());
                // SAFE AT SCALE: each custodian's custody seat, certified beside the seats (the adopter's vaults are the
                // chain's, not a re-derivation of them)
                self.validators.import_custody_seats(state.custody_seat_numbers.clone());
            }
            // ⭐⭐⭐ ADOPT THE NOTE FRONTIER'S PEAK SPINE — THE MISSING HALF OF THE O(1) JUMP.
            //
            // ⛔ SCOPE: this sits OUTSIDE the `state.sparse_root != 0` branch. I first nested it there and a
            // test caught it immediately — joiner 0 leaves vs origin 1,792 — because a bundle whose sparse
            // root is zero skipped the frontier adopt entirely. The NOTE frontier has nothing to do with the
            // NULLIFIER snapshot; gating one on the other is how a jumped node silently kept an empty spine.
            //
            // The bundle certified a frontier ROOT and this node installed it, but a root says WHERE the
            // tree is, not HOW to continue it. `spend_frontier` kept its own short peaks, so every leaf
            // appended after the jump folded against the wrong left siblings and this node's spend root
            // silently diverged from the tip it had just certified. Because
            // `served_seq = note_frontier_count() / 256`, that divergence is exactly the "record gap":
            // MEASURED tonight A 198,426 blocks / 168,934 folded, B 198,424 / 150,212 — three different
            // answers to "what is the note root", so no copath from one node could ever verify on
            // another, and the recipient's balance stayed 0 while the payer's spend settled.
            //
            // Four earlier hypotheses for that gap were each refuted by measurement (duplicate
            // re-delivery: 0 hits; sub-record ids: still 0 served; producer drop: fixed, gap unchanged;
            // a hole at the accept path: the `[ledger-hole]` probe fired 0 times). What was left is
            // structural — an O(1)-syncing node LEAPS the blue score without the blocks between, so it
            // can never re-derive these peaks from history. The bundle has to carry them.
            //
            // O(1) PRESERVED: the spine is 1,064 bytes FIXED — measured at 10 / 1,000 / 100,000 /
            // 1,000,000 leaves, all 33 slots, all identical. Instant sync stays constant-size.
            //
            // FAIL-CLOSED: the spine is adopted ONLY if it reproduces the root the bundle already
            // certified. A peer that ships a spine for a different tree is ignored and this node keeps
            // what it had, so a lying peer cannot steer another node's accumulator.
            // ⛔⛔⛔ THE NOTE ACCUMULATOR IS NOT ADOPTED FROM `frontier.root` — DELETED 2026-09-13 (§AI).
            //
            // A write lived here: `served_membership_acc = cm_bytes_to_leaf(&bundle.frontier.root)`. It was
            // wrong twice over. (1) `frontier.root` is the note TREE's root — the serve side fills it from
            // `note_frontier_root()` (node_runtime `build_sync_bundle` call) and the spine below is certified
            // against it — while `served_membership_acc` is the record FOLD (`note_membership_step_new_acc`
            // over block roots). The two are different objects; the fold travels separately as
            // `nullifier.membership_tip`, is bound into `sync_binding`, and is installed at its ONE adopt
            // site below. (2) Even for the value it meant, `cm_bytes_to_leaf` is a HASH since §AG, so what
            // landed was hash(tree root) — the §AI root round-trip class, the same shape as the
            // `SparseNfAcc::adopt_merkle_root` defect closed the same day.
            //
            // MEASURED: `a_jumped_node_adopts_an_extensible_frontier_spine…` — the joiner adopted the spine
            // (1,792 leaves) and then held [1618066820, …] against the origin's [1374900450, …]. On the live
            // chain the site below overwrote this value whenever the peer had folded a record, which is what
            // hid it; on a jump inside a fresh chain's first `record_fold_depth` blocks (`membership_tip`
            // all-zero, tree empty) nothing overwrote it, so the joiner folded its first record from
            // hash(empty tree root) instead of `MEMBERSHIP_GENESIS_ACC` and its whole accumulator series —
            // and every `da_macc_*` row it filed — sat off the chain's from the first ordinal.
            //
            // ONE CERTIFIED SOURCE, ONE WRITER: the accumulator lands from `membership_tip` only.
            {
                // DB-376: `served_bundle_prefix_refusal` already bound this spine to its root and to the anchor's
                // position (an empty spine is refused there), so only the matching arm below is reachable.
                match crate::spend_frontier::PoseidonSpendFrontier::from_peaks_hex(
                    &bundle.frontier.peaks_hex,
                ) {
                    // ⛔⛔⛔ NEVER MOVE THE LEDGER BACKWARDS — a regression I introduced today.
                    //
                    // The spine adopt replaced the local frontier with the peer's whenever that spine
                    // reproduced its own certified root. But the root is certified for the PEER's chain
                    // position, which can be BEHIND ours: a node that had folded more blocks then threw them
                    // away and reset `served_seq = count/256` to the smaller value. MEASURED across two runs
                    // of the same clean pair: records went 116 -> 59 while the DAG grew, and the deficit only
                    // ever appeared with peers — which is exactly when adopts run.
                    //
                    // Dropping folded leaves is not a bookkeeping slip: those leaves ARE notes, and a note
                    // that leaves the frontier is unspendable. Adopt ONLY when the certified spine is strictly
                    // AHEAD of what we hold; otherwise keep ours, since we are already at least as far along.
                    // ⛔⛔⛔ THE SPINE CERTIFICATION IS RESTORED. I removed this comparison when the projection
                    // made the two roots stop matching, and that WEAKENED a live security check: without it a
                    // peer can serve a spine for a DIFFERENT tree and steer another node's note state. The
                    // test `a_jumped_node_adopts_an_extensible_frontier_spine_and_a_mismatched_one_is_refused`
                    // exists to catch exactly that, and it caught me.
                    //
                    // `bundle.frontier.root` IS the tree root (`note_frontier_root()` on the serve side), so a
                    // spine that reproduces it is certified and installs; one that does not is refused. The
                    // fold accumulator is a different certified field (`membership_tip`) and never enters
                    // this comparison.
                    Some(f)
                        if crate::spend_frontier::leaf_to_cm_bytes(f.root())
                            == bundle.frontier.root
                        =>
                    {
                        // The spine follows the DAG this node just adopted. Three cases: the certified
                        // spine is LONGER than ours (a jump forward: take it); it is LEVEL with ours (same
                        // tree: nothing to do); it is SHORTER — either ours already extends it (our
                        // records above the anchor fold on the same chain: keep ours) or ours was built
                        // on the branch this adopt just abandoned (gate 45: a restarted node that mined
                        // alone kept its longer, wrong spine while standing on the peer's DAG). Only an
                        // exact prefix match keeps ours.
                        let theirs = f.count();
                        let ours_count = self.spend_frontier.count();
                        let level = theirs == ours_count && f.root() == self.spend_frontier.root();
                        // "Extends ours" is decided by the DAG, not by re-folding: the certified spine is
                        // the fold of the anchor's past, so it is a prefix of ours exactly when the anchor
                        // sits on OUR selected chain at or below our fold cursor.
                        let anchor_id = bundle.anchor_block.id();
                        // ⛔⛔ J11 (lane speed5, 2026-11-17, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J11) — "THE ANCHOR IS
                        // UNDER OUR FOLD" PROVES ONLY THE PREFIX. It says the records up to the anchor are the certified ones;
                        // it says nothing about the records this node folded ABOVE the anchor. Those are this DAG's fold only
                        // while the spine is not stale (the stale verdict IS "this spine is not this DAG's fold": a reorg below
                        // the fork point, a record off its derived slot) and the fold chain still lies on the selected chain.
                        // MEASURED (netsim launch, main 4e899429, scratchpad r5_join.log:25296-25308): joiner n2, stale, re-adopted
                        // at anchor ordinal 151 and logged "already part of ours (38656 leaves vs our 44544) — keeping ours"; the
                        // next pass found block 98e229a4 at row 169 where the DAG derives 164 ("a materialised record's leaves
                        // disagree") and went stale again; every later re-adopt kept the same spine (27009: waiting for a
                        // re-anchor again), and the state census read n0 and n2 on DIFFERENT ring roots from fold ordinal 164.
                        // Taking the certified spine here is the adopt arm below that gate 45 already uses for a spine built
                        // on an abandoned branch: orphan claims leave the index, the peers' pages refill them, and the anchor
                        // ring the bundle carries installs (its newest root is now this spine's).
                        // BORROWED: Kaspa's pruning-point sync and Bitcoin's reorg — state past the common point is re-derived
                        // from the chain, never kept from the branch that lost.
                        // AI RESISTANT: (b) code; a peer gains nothing — the spine taken is the one the join door certified.
                        // SCALE: one selected-parent walk of at most the fold depth; nothing grows with nodes, items or height.
                        // cons: a non-stale node whose fold chain sits off the selected chain only for an instant (a tip
                        // flip above the fold root cannot cause it: the fold chain tip stands at the fold root) re-fetches the
                        // coordinates above the anchor from its peers' pages (≤ the anchor depth, 40-112 levels).
                        let fold_still_this_dags = !self.spine_stale && {
                            let dag = self.relay.dag();
                            match (self.fold_chain_tip, dag.selected_tip()) {
                                (Some(f), Some(s)) => dag.selected_chain_through(&s, &f),
                                (None, _) => true,
                                (Some(_), None) => false,
                            }
                        };
                        let extends_ours = theirs < ours_count
                            && fold_still_this_dags
                            && self.anchor_on_our_chain(&anchor_id, bundle.anchor_blue_score);
                        if level || extends_ours {
                            eprintln!(
                                "[dsync] carried frontier spine is CERTIFIED and already part of ours ({theirs} \
                                 leaves vs our {ours_count}) — keeping ours"
                            ); // DIGITAL-CASH-PRIVACY-REVIEWED: leaf counts only; no note, amount, key or owner.
                        } else {
                        // ⭐⭐⭐ ADOPT THE CERTIFIED SPINE. `bundle.frontier.root` is the TREE root the peer
                        // serves (`note_frontier_root()`), `f` reproduces it, and the peer is strictly ahead.
                        // The fold accumulator (`spend_frontier_root()` projects `served_membership_acc`) is
                        // NOT derived from this root — it is its own certified field, adopted from
                        // `membership_tip` below. The earlier "left [0,0,0,0] vs right [1191159687, ..]"
                        // measurement of the spine test was the fixture's all-zero `membership_tip` (a
                        // 7-record tree with no fold — a state no live producer reaches), not a missing adopt.
                        //
                        // The monotone rule is UNCHANGED and still load-bearing: adopt only when the peer is
                        // strictly AHEAD, so a lagging peer can never walk this node's ledger backwards
                        // (dropping folded notes makes them unspendable — the defect the guard above records).
                        let before = self.spend_frontier.count();
                        // ⛔⛔⛔ THE RESTART WALL (gates 32–37, MEASURED on scratch WTm2JE 2026-09-03): a node's
                        // last blocks before a clean shutdown can be recorded locally and NEVER reach a peer.
                        // After the restart it adopts the peer's certified spine but KEEPS those orphaned rows,
                        // so its record space is the peer's plus extras interleaved — two different record SETS
                        // — and every ROOTS RUN the peer serves is refused because the fold origin (this very
                        // `spend_frontier`) was built over the orphans. Reconcile FIRST: rows whose blocks are
                        // in the DAG but not in the adopted tip's ancestry leave the ordinal space (the peer's
                        // sidecar page refills the freed slots), and the span opens from a frontier refolded over
                        // the certified prefix. Pinned by `orphaned_prerestart_records_tests`.
                        let k = self.reconcile_origin_for(shared_fold);
                        let origin = if k == 0 {
                            crate::spend_frontier::PoseidonSpendFrontier::new()
                        } else {
                            self.refold_frontier_prefix(k).0
                        };
                        self.open_roots_run_span(origin, f.clone());
                        self.spend_frontier = f;
                        // v31: the fold cursor is set to the bundle's anchor once the DAG is anchored there (below).
                        // ⭐ THE CERTIFIED SPINE NAMES THE NEXT RECORD ORDINAL — RAISE `served_seq` TO IT.
                        //
                        // A record is exactly BLOCK_FIXED_NOTE_COUNT leaves of this spine by construction
                        // (`block_leaves_from_notes` folds the fixed-shape payload), so the certified leaf
                        // count IS a record count: MEASURED (gate 32, scratch 2BMAaO) 45,824/256 and
                        // 50,432/256 exact; in-process 1,024 leaves ↔ 4 records. `served_seq` is the
                        // ordinal the record path claims next, and a jumper that left it at its LOCAL
                        // write count filed its first live record INSIDE the span the sidecar pages had
                        // just registered — gate 32: 'served_seq now 179' against a 197-record spine, live
                        // records written at 180, 181, 182… over paged rows 180–196; connect-9f's pin
                        // after_a_jump_and_catch_up_live_blocks_move_both_parties_roots_identically has
                        // the jumper file its first live record at ordinal 1 inside rows 1–3. Fold-space
                        // corruption; the two roots never meet again.
                        //
                        // ONE-WRITER RULE KEPT: the record path still advances the counter; this is a
                        // MONOTONE RAISE at the one certified event that moves the position. It never
                        // lowers the value — the 2026-08-12 incident (a resume-era re-derivation that
                        // overwrote a restored 348 with 49) was a LOWERING, and `max` cannot repeat it.
                        // `certified_record_position()` reads the same figure, so the sidecar backlog and
                        // the next ordinal share one coordinate.
                        // The SPINE ADOPT IS the certified event: this arm runs only when a heavier,
                        // certified spine replaced ours, and from that moment the records it covers are
                        // the peer's rows (paged, rid-keyed), never this node's own writes — so the next
                        // ordinal this node claims must sit above it. Whether a heavier bundle is
                        // adopted at all across a small gap is the BEACON's decision (its jump gate,
                        // one DAG width); once adopted, in-process or live, the position follows the
                        // spine. (A gap-size test here left a 3-block in-process adopt with the spine
                        // at 4 records and the counter at 1 — the live record then landed under a paged
                        // row: connect-9f's after_a_jump pin.)
                        let certified_records =
                            self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                        // v31: local ordinal claims that are not part of the certified spine must go. A
                        // node that folded its own blocks while the peer folded others (gate 44: the
                        // restarted node's claims at 165..168 against the peer's 165..192) would otherwise
                        // treat those blocks as folded, skip them in every later merge set and diverge for
                        // good. Everything from the reconcile origin up is re-adopted as coordinates from
                        // the peer's pages; real bytes stay keyed by record id. The spine names the next
                        // ordinal EXACTLY — a local counter ahead of it (own folds above the certified
                        // state) is as wrong as one behind it.
                        // Ordinal 0 is genesis on every persisted node — the same block, the same record,
                        // the same row everywhere — and the peer's pages start at 1 (gate 45: a node that
                        // evicted its own row 0 carried a 1-row gap forever, served every roots run with a
                        // hole at 0, and the restarted peer refused those runs whole).
                        let origin = self.reconcile_origin_for(shared_fold).max(1);
                        let dropped = self.evict_ordinals_from(origin);
                        if dropped > 0 {
                            // REWIND THE PAGING CURSOR TO THE FIRST FREED SLOT — the same rule the
                            // roots-run reconcile's evict already applies. The cursor only moves
                            // forward on its own, so without this the freed ordinals are NEVER
                            // re-asked: the kind-5 ask resumes past them and the peer's real rows for
                            // those certified blocks can never land. MEASURED (orphan-reconcile pin):
                            // A's orphans at ordinals 4..6 evicted here, cursor stayed 7, the page
                            // served 37 of 43 rows (7..43), and A converged with a permanent hole —
                            // want [6] unanswerable forever and ordinals 4..6 unservable onward.
                            if self.sidecar_cursor > origin {
                                self.sidecar_cursor = origin;
                            }
                            eprintln!(
                                "[dsync] {dropped} local ordinal claim(s) from ordinal {origin} left the index — \
                                 the certified spine names the records; the peer's pages re-supply the coordinates"
                            );
                        }
                        // POSITION, not count: records live at ordinals 1.. (genesis holds 0), so
                        // "one past the last certified ordinal" is certified_records + 1 — exactly
                        // what the fold path's own `served_seq = append_ordinal + 1` reaches after
                        // folding the same records, and what the restore path already stores
                        // (`certified_prefix_len = self.served_seq`). Setting the COUNT here left a
                        // jumped node exactly one position behind its peer forever: MEASURED
                        // `a_node_whose_last_blocks_never_propagated_reconciles...` red with
                        // "served_seq A=43 B=44" on identical record spaces.
                        self.served_seq = certified_records.saturating_add(1);
                        self.certified_prefix_len = self.served_seq;
                        eprintln!(
                            "[dsync] adopted the certified note-frontier spine: {} -> {} leaves \
                             (served_seq now {}) — the jump is now EXTENSIBLE, not just named",
                            before,
                            self.spend_frontier.count(),
                            self.served_seq
                        ); // DIGITAL-CASH-PRIVACY-REVIEWED: leaf counts only; no note, amount, key or owner.
                        }
                    }
                    // ⛔ ONE MESSAGE FOR TWO OPPOSITE OUTCOMES IS A FALSE DIAGNOSIS. The arm above needs
                    // BOTH a root match AND a strictly-ahead peer, so the catch-all printed
                    // "does not reproduce the certified root" — a SECURITY alarm — for the ordinary case
                    // of a peer that is simply level with us. MEASURED 2026-08-26 (gate run 7, scratch
                    // musd-ecocheck-mT103h): 48 such lines across the pair (30 n1 / 18 n2) were read as
                    // "DSYNC spine verification is failing 100%", while the SAME logs held 11 successful
                    // adopts and the whole #29 suite was green — the mechanism was working and the log
                    // said otherwise. Two nodes that sync constantly are level most of the time, so this
                    // benign branch is the COMMON one; naming it honestly is what keeps the genuine
                    // mismatch (a peer steering our accumulator) legible when it does happen.
                    _ => {
                        // unreachable past the DB-376 pre-check; fail closed on the spine only, never on chain progress
                        eprintln!(
                            "[dsync] ⛔ a carried frontier spine the pre-check admitted did not reproduce its root here — \
                             keeping our own"
                        ); // DIGITAL-CASH-PRIVACY-REVIEWED: a branch name only.
                    }
                }
            }
            // Ask 2 idle-privacy closure: install the certified confidential accumulator so this jumped node's
            // per-block decoy stream stays in lockstep with the mesh from tip onward.
            self.nf_cover_conf_acc = state.nf_cover_conf_acc;
            // ⭐ ISLAND FIX — adopt the CERTIFIED nf-unspent chain acc (A_tip; bound into `chain_acc` above, so a peer
            // cannot forge it). A jumped node CANNOT recompute A_tip (needs full history, O(N) — banned), so it MUST
            // install the certified value; without this it would reseed A_tip=[0;4] at a live height and ISLAND on it
            // (tip agrees, absence-proof endpoint stuck). A zero value is an older bundle → stays the genesis seed.
            // RE-BASE the absence-fold stream, but ONLY on a real jump. Everything folded before a jump
            // belongs to a history this node no longer has, so a spender must start from the adopted value
            // at the current seq — without that, the served records and A_tip describe two different chains
            // and every spend fails closed. Re-basing when the adopted value is UNCHANGED is just as
            // damaging in the other direction: sync runs constantly, so the base would creep forward on
            // every response and a spender's fold would restart forever, never converging.
            // ⭐ Install the CERTIFIED deletion-model unspent root. A foreign value flips the catch-up
            // map NOT_READY (adopt_unspent_note_root says so loudly), which hands the ledger-replay
            // self-heal its exact target — the missing piece that left a joiner self-consistently WRONG
            // (genesis map + genesis root while the chain's real root had moved; measured: B joined,
            // folded nothing, rebuild never triggered because nothing marked it incomplete).
            // THE JUMP IS GAP EVIDENCE — record the payload debt it opens BEFORE the root adopt, so the
            // adopt's (I2) keep-branch reads "behind, with a named gap" (adopt + heal), never "gapless
            // and READY" (keep). The same assignment below is idempotent.
            if state.blue_score > self.note_body_target {
                self.note_body_target = state.blue_score;
            }
            // ⛔⛔⛔ THE ROOT ADOPT MOVED BELOW THE WANT SEEDING. The I2 keep inside
            // `adopt_unspent_note_root` reads `sidecar_gap_count()` — the by-ORDINAL wants — as its
            // gap evidence, and those wants are seeded ~150 lines below this point (the
            // `jumped_from..certified_position` loop). Adopting HERE meant a genuinely-holed resumed
            // peer read "gapless" at adopt time (`note_body_target` above is NOT in the sidecar gap),
            // I2-kept its stale root and advertised it as certified — MEASURED 2026-09-05
            // (rolling-restart pins): [diagB-adopt] gap=0 printed immediately before "[dsync] … block(s)
            // of note payload were NOT applied". The adopt now runs AFTER the jump names its debt —
            // the I2 comment's stated precondition, made true.
            if state.nf_unspent_acc != self.nf_unspent_acc {
                // A JUMPED NODE'S WINDOW IS EMPTY, so `A_tip == base ⊕ {}` — the adopted accumulator IS
                // the base, and the horizon advance takes over from here as blocks arrive and age out.
                // The previous base moves with it: keeping a pre-jump value would name an accumulator
                // belonging to a history this node just replaced, and the boundary arm exists to cover a
                // one-block timing difference, never a jump.
                self.nf_base_prev = state.nf_unspent_acc;
                self.nf_fold_base = (state.nf_unspent_acc, self.nf_fold_seq);
                // ⛔ DB-270 — A NEW FOLD-BASE GENERATION: every block this node holds (the pre-jump window, the held tail
                // inside the adopted past, the fold carry) is counted by the certified base it just adopted, so none of
                // them is in the span any more. O(1), no file touched. The DB-269 re-fold below re-stamps exactly the held
                // blocks outside the adopted past through `fold_block_into_atip`.
                self.block_window.bump_base_gen();
                // ⛔ G2g-r2a step 3 — THE CHAIN'S QUANTIZED BASE, PENDING. The adopt-instant value above keeps this node
                // spending-capable at once; the certified words (bound in `sync_binding`) replace it the moment every
                // listed span body is placed and reproduces the adopted A_tip (`place_fold_span_body`).
                self.nf_fold_base_pending = None;
                let (wb, wseq, wprev, _) = state.nf_fold_base_words;
                if state.nf_fold_base_words != Default::default() {
                    self.nf_fold_base_pending = Some(NfFoldBasePending {
                        words: (wb, wseq, wprev),
                        acc: wb,
                        a_tip: state.nf_unspent_acc,
                        owed: state.nf_fold_span.iter().map(|(id, bw, bs)| (*id, (*bw, *bs))).collect(),
                        placed: std::collections::HashSet::new(),
                        anchor_score: bundle.anchor_blue_score,
                    });
                    // A listed body this node already holds (the held tail inside the adopted past, in the window OR the
                    // unfolded carry — G2g-r2b: the window alone left carried bodies owed forever, since a held body is
                    // never served back to this node's own ingest) is placed now, through the server's own body reader.
                    let held_owed: Vec<crate::block::BlockId> = self.nf_fold_span_owed().into_iter().map(Hash32).collect();
                    for b in self.whole_blocks_by_ids(&held_owed, usize::MAX) {
                        self.place_fold_span_body(&b);
                    }
                    self.try_switch_fold_base_pending();
                }
                // The certified base is recognised through `nf_fold_base` itself — the value is bound in
                // `sync_binding`, so it is a CHAIN value, not this node's opinion. (An acc->seq index once
                // mirrored it for the spend-gate sweep; both are deleted, D-41 class, 2026-09-11.)
            }
            self.nf_unspent_acc = state.nf_unspent_acc;
            // DB-246: A_tip was REPLACED wholesale, so no recent fold describes it any more. The re-fold of held
            // blocks outside the adopted past (below) records through `fold_block_into_atip` like any fold.
            self.nf_recent_folds.reset();
            // ⭐ ADOPT THE CERTIFIED LETTER ACCUMULATOR verbatim — same island class as A_tip: a jumped
            // joiner cannot recompute the letter anchor for history it leapt over, so it inherits the
            // certified one (bound in sync_binding; a pre-letter bundle decodes to the genesis seed).
            self.letter_acc = state.letter_acc;
            // ⭐ DIRECTORY CONVERGENCE ON JUMP — a jumped joiner MISSED the spans it leapt, so registrations
            // carried in those blocks never folded here (measured live 2026-08-25: a profile published on
            // one node resolved null on its DSYNC-jumping peer). The certified dir_acc is bound in
            // sync_binding; on mismatch the gapped local registry can never re-fold to it (order-sensitive
            // fold), so it RESETS and the refill door re-delivers the full certified sequence, every entry
            // re-verified through the same apply gate. One-time on divergence, never a steady-state walk.
            // ⛔ AUDIT F16: `state.dir_acc` is the CERTIFIED word (`directory::certified_dir_acc`: accumulator AND entry
            // count), compared with this node's own directory in the same form. The count is what lets the refill door
            // check a served sequence against the certified one before it keeps any of it.
            let mine = crate::directory::certified_dir_acc(&self.directory.acc, self.directory.log_len() as u64);
            if state.dir_acc != mine && state.dir_acc != [0u8; 32] {
                // Reset and refill (`dir_reset_for_refill`): the certified sequence returns through the verified door; an
                // entry it does not hold is a paid transaction its wallet sends again (audit F15, `dir_entry_tx`).
                self.dir_reset_for_refill(state.dir_acc);
            } else if self.dir_refill_target.is_none() {
                // A-F38: this node's directory IS the certified one and nothing is owed: a marker a stopped refill left
                // (the reason this node asked for the bundle at boot) has done its work
                self.directory.mark_refill_owed(None);
            }
            // ⭐ REORG HYGIENE (see `reorg_purge_da_above`) — NOW EVIDENCE-GATED, same standard as the
            // other two purge sites (`try_rebuild_cheap`, the rebuild path): ≥8 certified-door refusals
            // against locally-filed rows.
            //
            // ROOT-LAYER: "is my per-ordinal state dead-branch?" is answered where the contradiction is
            // PRODUCED — `accept_fetched_record`, where a row THIS node filed refuses a canonical record
            // (`da_stale_row_refusals`). "The adopted tip is not in my RAM DAG" is a reader-side inference
            // that is TRUE ON EVERY POST-RESTART ADOPT of a moving chain (the DAG is in-memory; the tip
            // advanced while we were down), so it cannot distinguish a reorg from a routine restart.
            // MEASURED (gate step-3→4, scratch /tmp/musd-ecocheck-sH0WNh): every post-restart adopt fired
            // this purge with boundary = finalized_height() = 0 (finality quorum not yet re-heard), wiping
            // the ordinal maps `circulating_records` had JUST restored — n1.log shows "purged 26/20/1
            // per-ordinal row(s) above finalized height 0" seconds before each membership-1step refusal.
            // A restart leaves ZERO stale-row refusals (nothing contradicts), so the gate keeps restored
            // state intact; a true foreign-lineage adopt hits contradictions on its first refill pages,
            // trips the latch, and the NEXT adopt (they arrive continuously) purges exactly as before.
            // MUST-STAY-GREEN: the 2026-08-24 dead-branch-poison heal (hours of refused pages → purge →
            // refill through the verified door) still fires via the latch; restart-survival gate steps 3/6.
            // cons: none — one u64 comparison; no new state, no growth term.
            // ⭐⭐⭐ DB-203b — THE DEAD-BRANCH SIGNATURE IS *MANY ROWS CONTRADICTING*, NOT *ONE ROW
            // REFUSED MANY TIMES*. Measuring the right quantity is what makes this gate correct in BOTH
            // directions at once, and it is why the two failures below can no longer happen.
            //
            // ROOT-FIX-VERIFIED: the gate now counts OUTSTANDING CONTRADICTING ORDINALS
            // (`da_poisoned_ordinals`), which is precisely the condition "my per-ordinal state belongs to
            // a branch this chain abandoned" asserts. That eliminates both failure modes by construction:
            //   • UNREACHABLE (DB-203): the old counter was reset by ANY accepted record, and a poisoned
            //     row always arrives inside a page of ~100 sound ones, so it ran 1 -> 0 -> 1 -> 0 and could
            //     never reach 8. A per-ordinal set cannot be cleared by a record at a different ordinal,
            //     because a sound record at X is not evidence about a row at Y.
            //   • OVER-TRIGGERING: a count of REFUSALS can be driven to any value by a single row retried,
            //     and at `finalized_height() == 0` this purge is a FULL RESET of the ordinal maps — the harm
            //     measured at gate step-3->4 (`musd-ecocheck-sH0WNh`), where post-restart adopts wiped maps
            //     `circulating_records` had just restored. A set counts each ordinal ONCE, so one row can
            //     contribute at most 1 and can never reach the threshold however often it is retried.
            // The quantity is now the thing the gate claims to measure, so neither a repeated single row
            // nor an unrelated sound page can move it, and the heal fires exactly on a real dead branch.
            //
            // The gate's original standard is unchanged and still holds: a routine restart contradicts
            // nothing, so the set is empty and this purge still cannot fire on it.
            if self.relay.dag().get(&state.tip).is_none() && self.da_poisoned_ordinals.len() >= 8 {
                let boundary = self.finalized_height();
                let purged = self.reorg_purge_da_above(boundary);
                if purged > 0 {
                    eprintln!(
                        "[reorg-hygiene] foreign-lineage adopt ({} certified-door refusals): purged {purged} per-ordinal row(s) above                          finalized height {boundary} — the refill re-fetches the canonical span through the                          verified door (dead-branch rows can no longer poison verification).",
                        self.da_stale_row_refusals
                    );
                }
            }
            // ⭐ ADOPT THE CERTIFIED NOTE-MEMBERSHIP FOLD. A jumped node skips every block between its old
            // state and the tip, so re-deriving this by folding is exactly the O(chain) walk the jump exists
            // to avoid. The value is bound into `sync_binding`, so a peer cannot hand over a forged start.
            //
            // Guarded on non-zero: an older bundle carries zeros, and installing those would silently reset a
            // node that had folded a real chain back to the genesis start — worse than not adopting at all.
            let (m_prev, m_root, m_acc) = state.membership_tip;
            // ⛔ CAPTURE BOTH ENDS OF THE SPAN *BEFORE* THE OVERWRITE BELOW.
            // The adopt replaces our accumulator with the certified one, which already has the skipped
            // blocks' roots folded into it. So a root run can NOT be checked by folding from the value we
            // hold AFTER the jump — it is the wrong end, and the check could never match. What is verifiable
            // is the SPAN: fold the run from where we stood before the jump and it must land exactly on the
            // certified value the jump gave us.
            if (m_prev, m_root, m_acc) != (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()) {
                // The maintained accumulator, not the retired field — this is a LIVE read that decides
                // what a note-body carrier anchors to, and it was taking the value that stopped advancing.
                self.note_body_acc_before = own_record_acc_at_entry;
                self.note_body_acc_target = m_acc;
            }
            // ⛔ THE ADOPT WRITES THE ACCUMULATOR THE CHAIN ACTUALLY MAINTAINS.
            //
            // This set `membership_acc`, the second field. Once the accessor, the tip transition and the
            // index all moved to `served_membership_acc`, a DSYNC-jumped node adopted a certified fold into
            // a field nothing reads — so it converged on paper and refused carriers in practice. Caught by
            // `a_jumped_node_adopts_the_certified_membership_fold…`, which is exactly what that test is for.
            //
            // One accumulator means every writer targets it: the record fold, the tip publisher, and this
            // adopt.
            if (m_prev, m_root, m_acc) != (usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest(), usdm_decider::poseidon2_compress::zero_digest()) {
                self.membership_tip_prev = m_prev;
                self.membership_tip_root = m_root;
                self.served_membership_acc = m_acc;
            }
            // ⭐ SYNC MUST APPLY BLOCKS, NOT SKIP THEM. A DSYNC adopt jumps CONSENSUS state to a certified tip in
            // O(1) — correct, and the pillar we keep. But it also skips every block between here and there, and
            // those blocks are where NOTE PAYLOADS live. A node can therefore hold a perfect tip, height and
            // accumulator set while holding ZERO notes — which is exactly what makes a payment invisible to the
            // only node its recipient talks to. MEASURED on a live pair: the recipient's node reached the
            // producer's height 220 with 11 adopts and recorded notes for NONE of those blocks.
            // DIGITAL-CASH-PRIVACY-REVIEWED: heights and a count only — the same chain-progress figures
            // /get_info already serves — never a note, amount, key or id.
            let jumped_from = self.note_backfill_cursor;
            // ⭐⭐⭐ THE JUMP NAMES ITS OWN DATA. Consensus lands in O(1); the records it skipped are named
            // HERE, at the moment they are skipped, and fetched by id — never walked toward from a cursor.
            //
            // user 2026-07-29: "Change everything you have to change to make the data land with the jump."
            //
            // The adopt is the only moment that knows exactly which span went missing, so it is the only
            // place that can ask for it precisely. Each named record is answered from any peer's DA ledger
            // and admitted only by `accept_fetched_record` / `accept_fetched_record_run` — against a block
            // root or a certified span this node already holds — so naming them costs nothing in trust.
            // Bounded by the fixed request width, so this is O(1) per adopt at any chain length, and the
            // want-set drains as records arrive rather than being re-derived from a moving cursor.
            {
                let width = crate::protocol::TX_REQ_FIXED_COUNT as u64;
                // Floor 1: ordinal 0 is genesis — the one record every node already holds (derived,
                // not fetched) — so a want for it is unanswerable by any page and sat in the want set
                // keeping `sidecar_ask_wanted()` true forever on a fresh jumper.
                let mut o = jumped_from.max(1);
                // The exclusive bound is the CERTIFIED POSITION (one past the last certified record
                // ordinal — served_seq was set to it just above), never `state.blue_score`: blue score
                // is a BLOCK coordinate, ordinals are the record stream, and the two diverge on any
                // DAG (the four-coordinate trap). Bounding by blue score seeded wants PAST the record
                // space — ordinals no chain position exists for, which no row can ever answer and no
                // arrival can ever clear. MEASURED: the orphan-reconcile pin converged on every axis
                // and still held "wants = (1, 0, 0, 0, 0)" forever.
                let top = self.certified_record_position();
                while o < top && self.wanted_ordinals.len() < crate::protocol::TX_REQ_FIXED_COUNT {
                    // Only an ordinal this node CANNOT ANSWER FOR is a want — and the tree's one
                    // predicate for that is `da_addr_at_ordinal` (the same one `want_record_at_ordinal`
                    // and `clear_satisfied_wants` use): it regenerates a retention-RELEASED cover row,
                    // which is held by design, not missing. Testing the raw `da_ord_rev_mem` map here
                    // wanted exactly those released rows — MEASURED: the orphan-reconcile pin converged
                    // on every axis (roots equal, served_seq 44==44, backlog 0) and still held
                    // "wanted ordinals by VALUE = [6]" forever: ordinal 6 was a cold cover row both
                    // sides had released, so no page could ever serve it and no arrival could clear it.
                    if self.da_addr_at_ordinal(o).is_none() {
                        self.wanted_ordinals.insert(o);
                    }
                    o = o.saturating_add(1);
                }
                let _ = width;
            }
            // HEADERS-FIRST, BODIES ALWAYS FOLLOW. Name the certified height as the body-fetch target; the
            // want-set below hands the next batch of missing records to the request pass every tick, and each
            // one is admitted only by `accept_fetched_record` (its 256 leaves must reproduce a block root we
            // already hold). Consensus still jumps in O(1) — the pillar is untouched — but the data no longer
            // stays behind, so the gap closes instead of widening.
            if state.blue_score > self.note_body_target {
                self.note_body_target = state.blue_score;
            }
            // ⭐ THE ROOT ADOPT LANDS HERE — after the jump has NAMED its debt (the by-ordinal wants
            // seeded just above + `note_body_target`), never before.
            // ROOT-LAYER: `adopt_unspent_note_root`'s I2 keep is the point that decides keep-vs-heal,
            // and its gap evidence is `sidecar_gap_count()` — the by-ordinal wants PRODUCED by the
            // seeding loop above. The old call site sat ~250 lines up, before the seeding, so the
            // evidence the keep reads was produced AFTER the decision consumed it: a genuinely-holed
            // resumed peer read gap=0 and kept/advertised its stale root as certified.
            // MEASURED: 2026-09-05 rolling-restart pins — [diagB-adopt] present_complete=true gap=0
            // printed immediately before "[dsync] … block(s) of note payload were NOT applied"; the
            // stale resume I2-kept the genesis root, the funded peer adopted it, and the funded note
            // was served CERTIFIED-ABSENT (verifying proof). After: the same adopt reads the seeded
            // wants (gap>0), takes the heal path, and the funded node's Some(true) liveness pin holds.
            // MUST-STAY-GREEN: the three rolling-restart/resumed-behind certify-absence pins, the #29
            // DSYNC suite, off_lock_heal_*, a_jumped_node_rebuilds_its_unspent_map…,
            // two_nodes_instant_sync_roundtrip_serve_then_adopt.
            // ⛔⛔⛔ THE ROOT ADOPT MOVED BELOW THE TIP-NOTE APPLY (D-36, 2026-09-08).
            //
            // It ran HERE, before the adopted tip's notes were applied, so `adopt_unspent_note_root`'s
            // arbiter judged the certified root against a ledger that did not yet hold the block's
            // notes. It could not reproduce the root, took the I2 keep, and a FRESH JOINER therefore
            // kept its own GENESIS root and locked itself READY — measured verbatim:
            //   "[uns-adopt] 🔒 KEPT own root 0x48d01dae: the offered root 0x2b63f423 is neither ahead
            //    on my lineage nor reproducible from my gapless ledger — a holed peer's subset root"
            // 0x2b63f423 was the SOURCE's correct root. The joiner dismissed the node that was right,
            // reported sidecar_gap=0 (so it never healed), and ADVERTISED the stale root onward, which
            // is a verifying certified-absence proof for a note that exists.
            //
            // The principle this path already states three lines up — the adopt lands "after the jump
            // has NAMED its debt … never before" — was correct and incompletely applied: the tip's own
            // notes are part of that debt. Moving the call below the apply satisfies the SAME
            // invariant (it is still after the by-ordinal want seeding and `note_body_target`) and lets
            // the arbiter judge against a ledger that actually holds what the bundle handed over.
            eprintln!(
                "[dsync] adopted certified state to height {} — {} block(s) of note payload were NOT applied                  (data-availability gap: consensus jumped, notes did not follow)",
                state.blue_score,
                state.blue_score.saturating_sub(jumped_from)
            );
            // A-F77: the runtime reads this as "joining" and builds on no lighter chain until it has caught up.
            self.dsync_adopts = self.dsync_adopts.wrapping_add(1);
            // MERGESET GRAFT: install the certified peer tip as a DAG anchor and reorg onto it iff it is
            // strictly heavier (GHOSTDAG (blue_work, id)). This is what makes two independent producers
            // converge on ONE shared tip — the lighter follows the heavier, then builds its next block on
            // the adopted tip so the peer grafts it. The anchor carries the peer's REAL accumulated blue_work.
            // ⭐ SYNC APPLIES BLOCKS, IT DOES NOT SKIP THEIR DATA. The adopted tip is a REAL block and it now
            // carries its own note payload, so an adopting node records it instead of jumping past it. Consensus
            // still jumps in O(1) — the pillar is untouched — but the notes ride along, so a node that syncs
            // rather than mines no longer ends up with a perfect tip and ZERO notes, which is what made a
            // cross-device payment invisible to the only node its recipient talks to.
            let adopted_notes: Vec<u8> = bundle.tip_block.output_notes.clone();
            let adopted_targets: Vec<u8> = bundle.tip_block.account_targets.clone();
            // ⛔⛔⛔ THE JUMP ADOPTED ONLY THE TIP'S TARGETS — EVERY SKIPPED BLOCK'S INDEX ENTRIES WERE LOST.
            //
            // MEASURED 2026-07-31 on the live pair: node B holds 88,195 blocks and `[gossip-in]` — which fires
            // on EVERY inbound WireMsg::Block before any condition — fired ZERO times. B never ingests a block
            // over gossip; it takes the whole chain through this certified tip-adopt. So the per-block adopt
            // at ingest, the ONLY place account targets are filed on a receiving node, never runs: `[graft]
            // carried`, `[acct-adopt]` and `[acct-file]` are all 0 on B, and the recipient's wallet reports
            // `bucket+OLI detection returned 0 candidate note(s)` forever.
            //
            // A payment that settles in a block BELOW the adopted tip is therefore undiscoverable by its
            // owner — the note is on chain, its index entry is not. Adopt every carried target the bundle
            // brought, not just the tip's.
            //
            // NOT a window/cap/age-out: nothing is refused, skipped or bounded in reach — this widens what is
            // filed. Bounded by the bundle's own fixed <=1.8MB shape, never by chain height.
            // DIGITAL-CASH-PRIVACY-REVIEWED: byte counts only; targets are sealed to their owners' keys and
            // are already carried on the block.
            // `SyncBundle` carries ONLY `tip_block` (fields: decider, frontier, nullifier, tip_block,
            // blue_work, genesis_commit) — by design, since the whole point is an O(1) jump that does not
            // ship history. So the skipped blocks' targets CANNOT come from here; they must be adopted where
            // their records actually arrive, in the DA note backfill. Fixed there, not by growing the bundle.
            if !adopted_notes.is_empty() {
                // DIGITAL-CASH-PRIVACY-REVIEWED: a byte count only — never a note, amount, key or id.
                eprintln!(
                    "[dsync] applying {} note bytes from the adopted tip",
                    adopted_notes.len()
                );
                // A node that JUMPS its consensus state still has to file the notes under their owners, or
                // its wallets get an empty bucket and the account commitment diverges from the producer's.
                // Measured exactly that way: the producer committed a live root while the adopting peer,
                // having taken the same tip, still committed zero.
                self.adopt_account_targets_at(
                    &adopted_targets,
                    Some(Self::da_record_id_for_block(&bundle.tip_block.id(), 0)),
                );
                // Name it by the BLOCK, exactly as produce and ingest do. Keyed by blue_score, an adopting
                // node filed the same block at a different address than the node that mined it, so the two
                // folded different content and their accumulators could never agree.
                // ⛔ A SEED-ONLY tip is deliberately NOT recorded here: the adopted spine already holds
                // its leaves, and the record path APPENDS — recording it again double-counted 256 leaves
                // (measured 2026-09-03: 2304 vs 1536 on connect-9f's live-behind pin). Its ROW arrives
                // through the sidecar page at the server's ordinal, rid-keyed, without appending.
                // The notes go through `graft_admitted_notes` first, exactly as the graft-side writers
                // do: that is the shared mint-authority + wrapper-binding filter, and a writer that
                // skips it records value the door refuses. This is the fourth writer that helper
                // exists to keep identical.
                // ⭐ DB-358 r3 control: judged by the adopted tip's OWN header — the tip enters the DAG only in
                // `graft_unfolded_carry` below, so a DAG lookup here found nothing and refused its honest spends.
                let tip_key = bundle.tip_cover_key.or(bundle.tip_block.cover_key);
                let admitted: Vec<u8> = self.graft_admitted_notes_given(
                    &bundle.tip_block.id(),
                    Some((bundle.tip_block.header.clone(), bundle.tip_block.tx_ids.clone())),
                    &adopted_notes,
                    tip_key,
                    bundle.tip_block.note_transition.as_ref(),
                    bundle.tip_block.member_transition.as_ref(),
                    bundle.tip_block.cover_transition.as_ref(),
                    // ⭐ §BA — the adopted tip's own credit set: a joiner resolves none of its bodies, so
                    // this is the ONLY thing that can justify a non-spend note the tip carries.
                    &bundle.tip_block.credit_set,
                    // §22b: the tip's wide objects ride beside it in the bundle
                    if bundle.tip_wide_objects.is_empty() { &bundle.tip_block.wide_objects } else { &bundle.tip_wide_objects },
                    // DB-257: the tip's own bond set. The adopt installs the certified POST-tip state first, so
                    // a return the tip itself carries finds its bond already released and is not justified
                    // here. That residual is named in docs/DB-257 §7.
                    &bundle.tip_block.bond_set,
                    // DB-278: the tip's own lane — the certified post-tip state already holds its tags.
                    &bundle.tip_block.nullifier_proof.padded_tags,
                    // DB-351: the tip's own filed tags, header-bound, which its transition's filing digests bind.
                    &bundle.tip_block.oli_tags,
                );
                let rec_addr = self.record_note_payload_for(
                    Some(bundle.tip_block.header.id()),
                    state.blue_score,
                    &admitted,
                    tip_key,
                );
                let tip_id = bundle.tip_block.header.id();
                if let Some(carried) = Self::window_block_carried_tags(&bundle.tip_block, &tip_id) {
                    if !carried.is_empty() {
                        let _ = self.file_tags_at_fixed_slots(rec_addr, carried);
                    }
                }
                self.note_backfill_cursor = self.note_backfill_cursor.saturating_add(1);
            }
            // v31: the DAG anchors at the peer's FOLD ROOT (the carried spine ends there); the blocks between it
            // and the certified tip arrive by gossip and parent backfill and fold canonically here too.
            let anchor_id = bundle.anchor_block.header.id();
            let anchor_ordinal_from_bundle = bundle.anchor_ordinal;
            let anchor_notes = bundle.anchor_block.output_notes.clone();
            let anchor_score_from_bundle = bundle.anchor_blue_score;
            // ⭐ THE ADOPTED ANCHOR'S WITNESS IS KEPT (2026-10-29). A joiner serves its fold anchor (G11b), and the header door
            // of a THIRD node demands that block's PoUW witness (`bundle_blocks_refusal`: "tip block: no witness carried") —
            // but the witness arrives exactly once, here, in the bundle, and `retain_pow_witness` only captures it at a graft.
            // MEASURED: db321's CALIBRATION "K jumps from J" refused at K's header door. The bundle's own door verified this
            // witness above, so keeping it moves nothing a peer did not prove. cons: one 32-byte copy per adopt.
            let anchor_witness = bundle.anchor_block.pow_proof.clone();
            // The same weight the door weighed this bundle by: a fork this node does not hold by its chain, its own chain by the anchor.
            let anchor_chain_work = if self.relay.dag().get(&anchor_id).is_none() { bundle.chain_work() } else { bundle.anchor_blue_work };
            let anchor_blue_work = bundle.anchor_blue_work;
            let anchor_blue_score = bundle.anchor_blue_score;
            // A-F80 (lane af58, 2026-11-16): the door's verdict was dropped here. The adopt goes on either way (its state is
            // certified), but a DAG that did not take the anchor (already held, or lighter by its own chain) keeps following its
            // own head, and the fold then reads "the selected chain moved below this node's adopted floor". Named so one run
            // tells which. Public chain structure only. DIGITAL-CASH-PRIVACY-REVIEWED.
            let anchor_held_before = self.relay.dag().get(&anchor_id).is_some();
            if !self.admit_anchor_block_weighed(bundle.anchor_block, anchor_blue_work, anchor_chain_work, anchor_blue_score) {
                let head = self.relay.dag().selected_tip();
                eprintln!(
                    "[dsync] ⚠ A-F80: the DAG did not take the bundle's anchor {} as its floor ({}; chain work {anchor_chain_work}) — \
                     the head stays {:?} (work {:?})",
                    &anchor_id.to_hex()[..8],
                    if anchor_held_before { "already held" } else { "lighter than this node's head, or its header refused" },
                    head.map(|h| h.to_hex()[..8].to_string()),
                    head.and_then(|h| self.relay.dag().get(&h).map(|n| n.blue_work))
                );
            }
            if !anchor_witness.is_empty() {
                self.anchor_pow_witness = Some((anchor_id, anchor_witness));
            }
            // The anchor's record is INSIDE the adopted spine: its coordinates and sidecars arrive with the
            // sidecar page like every other folded record's, and its bytes by id if wanted. Writing its notes
            // here re-folded a receive the certified root already held (MEASURED: root moved off the certified
            // value right after the adopt) — so nothing is written for it.
            let _ = anchor_notes;
            self.fold_chain_tip = Some(anchor_id);
            self.sync_prune_floor();
            self.refresh_anchor_body(); // G1g-v: the anchor moved
            self.certified_anchor = Some(anchor_id);
            self.certified_anchor_score = anchor_score_from_bundle;
            self.end_spine_stale(); // A-F79: the adopt answers the wait that made the spine stale; its age starts again
            // Correction 7 stage 3: the adopt replaced the frontier with the certified spine — every
            // ring entry describes the spine this node just stopped serving. Cleared whole; the live
            // fold refills it from the adopted base (the cold path stays quiet, never wrong).
            self.spine_recent_roots.clear();
            self.member_ring_commits.clear(); // §RF-3: its rings were the replaced spine's; the bundle's history replaces it
            // DB-223 Q2: the stream describes the spine this node just stopped serving too; its live fold refills it.
            self.completed_windows.clear();
            // ⭐⭐ DB-418 — AND THE INDEX KEEPS EVERY WINDOW THE CERTIFIED SPINE BINDS (`retain_bound_to`: a held pair whose
            // parent is a peak of the spine this node now stands on, or under a kept window). Only a window of the spine
            // just replaced is dropped. The windows this node never held below the anchor (a fresh joiner holds none) are
            // rebuilt from the ROOTS RUN when its span closes against the certified spine (`accept_fetched_root_run`) —
            // Kaspa's pruning-point sync shape: the state below the anchor is fetched and judged against the commitment
            // the certified header carries, never believed.
            // MEASURED (link 23, sweep simpar-20261007-180330 0x3 T1.7): the old `clear()` — "served by the range's other
            // holders", which no wallet asks — left a re-anchored node serving NO shard table ("0 own-shard root(s) read
            // from 0 whole shard table(s)"), and the wallet's post-restart send never built its path.
            let (held, kept) = self.window_index.retain_bound_to(&self.spend_frontier);
            // DIGITAL-CASH-PRIVACY-REVIEWED: two counts of public spine windows; no note, tag, amount, key or owner.
            eprintln!("[dsync] DB-418: the window index keeps {kept} of {held} held window(s) — those the certified spine binds");
            // ⭐ DB-274 P2 (§8.7): the bond journal described steps of the spine just replaced; nothing below the
            // anchor can be un-folded here, so a rewind below it marks the set stale.
            self.bond_fold_journal.clear();
            self.objects_fold_journal.clear(); // DB-274 P4b: its images described the spine just replaced
            self.objects_journal_floor = bundle.anchor_ordinal.saturating_add(1);
            self.bond_journal_floor = bundle.anchor_ordinal.saturating_add(1);
            self.dir_fold_journal.clear(); // DB-274 (dir_set): its steps described the spine just replaced
            self.dir_journal_floor = bundle.anchor_ordinal.saturating_add(1);
            // ⭐ DB-223 / DB-274 P3: the bundle's ring replaces it when it is the canonical ring AT THIS ANCHOR over the
            // spine just adopted (dense, within reach, newest = anchor ordinal at the adopted root). Else the ring stays
            // empty and refills from the live fold; a spend whose anchor predates the adopt then waits.
            if bundle.anchor_ring.last().map(|(o, _)| *o) == Some(bundle.anchor_ordinal)
                && self.install_anchor_ring(&bundle.anchor_ring)
            {
                // §RF-3: the certificate binds the history beside the ring (`bundle_chain_summary`).
                let _ = self.install_member_ring_commits(&bundle.member_ring_commits);
            } else if !bundle.member_ring_commits.is_empty() {
                // ⭐ DB-223 — the ring did not describe this node's spine (it stands past the anchor: an adopt never walks a
                // ledger backwards), so the held-record replay rebuilds this node's own ring; the certified history waits
                // for it there, beneath the commits the replay computes for the steps above the anchor. MEASURED
                // 2026-11-10 (round 22, real nodes): with neither installed, a spend anchored before the adopt made the
                // fold wait 806 passes and the node's finality, fold and wallets stood still from height 280 on.
                self.carried_ring_commits = Some(bundle.member_ring_commits.clone());
            }
            // DB-268: the certified frontier is the base every rewind above the anchor restores from — a joiner holds
            // no root below it, so without this entry any reorg above its anchor could only go stale.
            self.spine_recent_frontiers.clear();
            {
                let rec = crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                let k = self.spend_frontier.count() / rec;
                // The accumulator at k is NOT seeded: only the frontier's own leaf count is verifiable here (the rewind
                // re-checks it); a rewind to exactly k takes its accumulator from the filed per-ordinal rows as before.
                self.spine_recent_frontiers.push_back((k, self.spend_frontier.clone(), None, self.root_history.clone()));
                self.fold_checkpoint = Some((k, self.spend_frontier.clone(), self.root_history.clone()));
            }
            // ⭐ THE POSITION CAME WITH THE CERTIFIED BUNDLE — store it as the anchor's row so every later
            // position follows from the DAG rather than from an inference this node makes alone.
            // (Zcash's anchor + tree-size: adopt the root AND the size that produced it.)
            if anchor_ordinal_from_bundle > 0 {
                self.da_store_ordinal(
                    Self::da_record_id_for_block(&anchor_id, 0),
                    anchor_ordinal_from_bundle,
                );
            }

            // v31: every block this node holds in the anchor's past is folded by construction — the
            // certified spine at the anchor IS that past — whether or not its coordinates have landed
            // from the peer's pages yet. Without this, a block whose local claim the adopt evicted looks
            // unfolded to the next merge set and folds twice (pin: a_node_with_stale_local_claims…).
            // The floor belongs to THIS anchor: a block below an earlier anchor that is not below this
            // one is judged by its row like any other (pin: a_jumped_node_whose_chain_moves_below_its_anchor…
            // — the first anchor stayed "folded" through a re-adopt and was skipped in a later merge set).
            self.folded_floor.clear();
            self.folded_floor.insert(anchor_id);
            let past = self.relay.dag().past_of(&anchor_id);
            self.folded_floor.extend(past);
            // db333-r: the adopted state replaces the old one wholesale, so what the old one awaited is void.
            adopted_covered = bundle.fold_carry.covered.iter().map(|(id, _, _)| Hash32(*id)).collect();
            self.dsync_covered.clear();
            self.graft_unfolded_carry(bundle.fold_carry);
            // DB-282: held structure reaching gap-free down from the anchor is placeable here (a crawl that met the
            // anchor); an island across a gap stays history. See `Dag::settle_connected_past`.
            let _ = self.relay.dag_mut().settle_connected_past(&anchor_id);
            // ⛔ J20 (lane speed5, 2026-11-18, docs/JOIN-FINALITY-DEEP-AUDIT-20261117.md J20): the carried past is placed now, so the
            // positional chain index is rebuilt ONCE over it — the walk crosses the anchor (`walk_parent`) and the chain lengths are
            // re-derived from one fixed point. The incremental refresh returns "already correct" while the tip is unchanged, so the
            // padded span the anchor install left below the anchor was never filled. MEASURED (replica census, production paused):
            // the chain blocks at blue scores 40-47 read "not on the selected chain" on the joiner and "on it" on both seeds.
            // cons: one pass over the held span per adopt (bounded by the DAG window); none per block.
            self.relay.dag_mut().rebuild_selected_chain_index();
        }
            let new_tip: crate::block::BlockId = bundle.decider.tip; // `fold_carry` was moved out; `decider` was not
            // DB-249: the held blocks D-36 re-folds below, read again after the certified peg / validator install.
            let mut held_outside_adopted_past: Vec<Block> = Vec::new();
            // ⛔⛔⛔ D-36 — RE-FOLD WHAT THE INHERITED STATE DOES NOT COVER (2026-09-11).
            // Placed AFTER the carry GRAFT (the last step of the jump), for two measured reasons: (1) the
            // A_tip inherit (`nf_unspent_acc = state.nf_unspent_acc`) runs late in this function and
            // overwrote a re-add placed before it — counts agreed at 513 while `nullifier_root` diverged;
            // (2) the new tip and its carried past enter the DAG only in `graft_unfolded_carry`, so an
            // ancestry walk before the graft saw NO tip, judged every held block uncovered, and
            // double-counted the ones already in the inherited state — `8705 vs 9473`, three blocks over.
            //
            // The jump REPLACES this node's nullifier accumulator with the bundle's certified state, which
            // covers exactly the new tip's PAST. Any block this node already held that is NOT in that past
            // — its own freshly produced sibling, a peer block that arrived first — had its nullifiers in
            // the old accumulator and has none in the new one. `graft_unfolded_carry` then sees the block
            // "already in this DAG" and passes it through without a fold, so the node ends one 256-wide
            // cover short of every peer that folds the same block on delivery.
            //
            // MEASURED (lane F, `Produce(1,0) · Receive(0) · Jump(1,0)`): `nullifier_count 513 vs 257`,
            // and only when the fork-choice tie-break `(blue_work, id)` made the jump ADOPT — block ids
            // vary per run (cover notes mint fresh keypairs, D-37), which is why this fired in roughly
            // half of all runs and every "passes in isolation" was a coin toss.
            //
            // BORROWED (Bitcoin's reorg rule): when the active view switches, what you hold off the new
            // branch is re-applied — never dropped. The accumulator is commutative and the fold is
            // order-free and self-verifying from block-carried data, so re-folding a held block into the
            // inherited state is exactly the "connect" half of a reorg. Only blocks OUTSIDE the tip's
            // past are re-folded: a block inside it is already counted by the certified state, and
            // folding it again is the double count that made the first fix measure worse.
            //
            // The held set is `unfolded_blocks` (bounded by record_fold_depth chain blocks and their merge
            // sets — its own O1 review); the ancestry test walks parents from the served tips down to the
            // certified anchor (DB-442), since anything at or below it is inside the certified past.
            // O1-FOOTPRINT-REVIEWED: bounded by the blocks above the certified anchor (the bundle's carry
            // plus the held unfolded set), never by chain height.
            // ⛔⛔⛔ DB-250 — ONLY AN ADOPTED BUNDLE REPLACED THE SUMS, SO ONLY AN ADOPTED BUNDLE RE-FOLDS.
            // This block sat at the function's TOP LEVEL, after the `Adopted` scope above had closed, so it ran
            // for EVERY outcome — `Unverified`, `NotHeavier`, `GenesisMismatch`, `FrontierUnbound` — and
            // re-summed every held unfolded block outside the near past of the bundle's CLAIMED tip into A_tip,
            // the letter sum and the DB-246 recent-fold ring (`fold_block_into_atip` has no dedup, by design: a
            // sum cannot tell a repeat). A peer answering a sync ask with a garbage bundle naming a tip this node
            // lacks moved this node's consensus nullifier root with ONE message; an honest lighter bundle (the
            // asker caught up by pages first) did the same.
            // ROOT-LAYER: the double count is produced by this loop; the replacement it compensates for happens
            // only inside the `Adopted` scope, so the compensation is gated on exactly that outcome.
            // MEASURED: `db250_a_sync_response_this_node_does_not_adopt_moves_no_accumulator` RED before —
            // "a bundle A REFUSED (Some(Unverified)) moved A_tip — 4 held block(s) were summed a second time".
            // MUST-STAY-GREEN: every jump pin (an ADOPTED bundle re-folds exactly as before), the DB-246 ring
            // pins, `honest_bundle_is_adopted_and_jumps_to_tip`, the fold-schedule fuzz lanes.
            if matches!(outcome, AdoptOutcome::Adopted(_)) {
                // The covered set is the past of EVERY tip the server had — a sibling tip it accepted by
                // gossip is in its accumulator too. Seed the walk with all of them (the selected tip alone
                // re-folded exactly such a sibling and came out one cover over: `1281 vs 1537`).
                let mut near_past: std::collections::BTreeSet<crate::block::BlockId> = std::collections::BTreeSet::new();
                let mut frontier: Vec<crate::block::BlockId> = vec![new_tip];
                for t in bundle.tips.iter() {
                    if near_past.insert(*t) {
                        frontier.push(*t);
                    }
                }
                near_past.insert(new_tip);
                // ⛔⛔⛔ DB-442 — THE COVERED WALK GOES DOWN TO THE CERTIFIED ANCHOR, NEVER A FIXED 32 LEVELS.
                // It stopped after RECORD_FOLD_DEPTH levels below the served tips, which equals "down to the anchor" only
                // while the server's fold cursor trails its tip by at most that depth. Nothing bounds that lag: the cursor
                // moves only when a fold pass runs, so a serving node can trail by more (a paused fold, a node that has just
                // adopted). The carry is the served tip's whole past above the fold root, and the certified A_tip already
                // counts all of it. So every carried block deeper than 32 levels and above the anchor fell out of
                // `near_past`, passed the anchor-floor filter below, and was folded into A_tip a SECOND time.
                // MEASURED (`db282_…`, `db269_…`, red since the SAT reward increment, scratchpad/sat-batch2.log 2026-10-04):
                // origin tip 100, fold anchor 64. The jumper "re-folded 3 held block(s) outside the adopted tip's past" —
                // carried blocks 65..67 — and its A_tip came out unlike the carried A_tip it had just adopted.
                // ROOT-LAYER: the walk now expands every held block scoring ABOVE the anchor floor, the exact region the
                // filter below examines. So `near_past` is past(served tips) ∩ (above the anchor), and a held block the walk
                // cannot reach is outside that past, which is D-36's definition.
                // O1-FOOTPRINT-REVIEWED: it expands only DAG blocks above the certified anchor reachable from the served
                // tips: the bundle's carry (bounded by the bundle door) plus held unfolded blocks (bounded by
                // `unfolded_blocks`). Nothing below the anchor is expanded, so the cost never depends on chain height.
                // MUST-STAY-GREEN: db249 (a held RECENT side block above the anchor, outside the tips' past, still re-folds),
                // db250, db286, db246, the D-36/D-49 fuzz lanes, every jump pin.
                // cons: none. The walk visits the carry once more than before (≤ the bundle's carry), with no new state,
                // no new wire bytes and no added disk.
                let walk_floor = self.certified_anchor_score;
                loop {
                    let mut next: Vec<crate::block::BlockId> = Vec::new();
                    for id in frontier.drain(..) {
                        if let Some(n) = self.relay.dag().get(&id).filter(|n| n.blue_score > walk_floor) {
                            for p in n.header.parents.iter() {
                                if near_past.insert(*p) {
                                    next.push(*p);
                                }
                            }
                        }
                    }
                    if next.is_empty() {
                        break;
                    }
                    frontier = next;
                }
                // ⛔⛔⛔ DB-269 — AT OR BELOW THE CERTIFIED ANCHOR A HELD BLOCK IS NEVER "OUTSIDE THE ADOPTED PAST" TO RE-COUNT.
                // `near_past` walks only RECORD_FOLD_DEPTH levels below the served tips, so a joiner's unfolded CRAWL tail —
                // deep inside the certified past — fell outside it and was re-folded into A_tip (ADDITIVE, no dedup: counted
                // twice) and re-applied by DB-249. A held block at or below the anchor is either inside the certified past
                // (already counted) or, under the merge horizon (DB-267), never mergeable; only one ABOVE the anchor can be a
                // block this node's next block legally merges. ROOT-LAYER: this set is the one D-36 re-folds AND DB-249
                // re-applies, so the filter serves both. MEASURED: `db269_a_joiner_that_crawled_counts_no_held_block_twice…`
                // (gate Q2 n2: "re-folded 32 held block(s)" after a crawl to 208 and a jump to 496).
                // MUST-STAY-GREEN: db249_… (its held mint block is a RECENT side block, above the anchor), db250_…, db265_…
                // ⛔⛔⛔ DB-286 — A HELD BLOCK THE ADOPT LEFT UNSETTLED IS STALE: IT JOINS NEITHER SET.
                // D-36 and DB-249 rest on "this node's next block merges it (it is a tip here)". That holds exactly while
                // the adopt left this node's tips alone (the anchor already held, or lighter than this node's own tip:
                // `Dag::add_anchor` returns before touching anything — the db249 case). On a REAL jump `add_anchor` marks
                // every block held before it UNSETTLED (DB-282) and clears the tips; `add_block` then refuses any block
                // naming an unsettled parent and `build_template` names only the tips, so no block of this node's can
                // ever merge it. Its state reaches this node only through a later certified re-anchor, whose state then
                // already counts it. BORROWED: Kaspa's virtual state (a block outside the virtual's past contributes
                // nothing) and Bitcoin's stale block (disconnected, never connected again).
                // MEASURED (lane-dsol-zkvm's finding 09:32, pin `db286_a_held_side_block_left_off_a_real_jump_…`, a
                // partition heal: the lone side branch scores above the mesh's anchor while weighing less): before
                // this line the jumper minted a deposit no peer minted and re-folded stale leaves into A_tip.
                // ROOT-LAYER: `uncovered` is the ONE set D-36/D-49 re-fold and DB-249 re-applies; `settled` is final
                // here (the carry graft and `settle_connected_past` ran above in this scope).
                // MUST-STAY-GREEN: db249 (settled, a tip), db250, db269, db246, the D-36/D-49 fuzz lanes, jump/adopt pins.
                // cons: one bool read per candidate; a stale block's contents are re-offered only by peers that pooled
                // them (the block carries no tx bodies), exactly as a stale block's in Bitcoin.
                let anchor_floor = self.certified_anchor_score;
                let mut stale_held = 0usize;
                let uncovered: Vec<Block> = self
                    .unfolded_blocks
                    .iter()
                    .filter(|b| {
                        let id = b.id();
                        // db333-r: a held block the adopted state already counts is inside the certified past even when the
                        // walk cannot reach it (its served tips are not held here yet) — re-folding it is D-36's double count.
                        if id == new_tip || near_past.contains(&id) || adopted_covered.contains(&id) || b.header.is_genesis() {
                            return false;
                        }
                        match self.relay.dag().get(&id) {
                            Some(n) if n.blue_score > anchor_floor && !n.settled => {
                                stale_held += 1;
                                false
                            }
                            Some(n) => n.blue_score > anchor_floor,
                            None => false,
                        }
                    })
                    .map(|b| b.block().clone())
                    .collect();
                if stale_held > 0 {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a block COUNT only — no id, tag, amount, key or owner.
                    eprintln!(
                        "[dsync] DB-286: {stale_held} held block(s) outside the adopted past are pre-anchor history after \
                         this real jump — stale, neither re-folded nor re-applied (no block of this node's can merge them)"
                    );
                }
                held_outside_adopted_past = uncovered.clone(); // DB-249: the same set, re-applied below
                let mut refolded = 0usize;
                for b in uncovered {
                    let id = b.id();
                    let g_conf = self.nf_fold_inputs_for_block(&id);
                    let ok = self.fold_block_nf_in_order(
                        b.header.nullifier_root.0,
                        b.nullifier_proof.post_root.0,
                        &g_conf,
                        &b.nullifier_proof.fold,
                        &b.nullifier_proof.padded_tags,
                    );
                    // A_tip (`nf_unspent_acc`, the order-free SUM every committed root projects) advances at
                    // block ACCEPT, not in the sparse fold above — and the inherit replaced it too. Re-add this
                    // block's leaf exactly once: it is outside the adopted tip's past, so the inherited sum
                    // does not contain it. (MEASURED without this line: counts agreed at 513 and
                    // `nullifier_root` / `nf_unspent_acc` still diverged.)
                    self.fold_atip_at_accept(
                        id.0,
                        b.header.nullifier_root.0,
                        &b.nullifier_proof.padded_tags,
                        &b.nullifier_proof.fold,
                    );
                    // ⛔ D-49 (2026-09-11) — THE LETTER SUM IS RE-FOLDED BY THE SAME RULE. `letter_acc` is a
                    // commutative per-block sum exactly like A_tip; the jump replaced it with the certified
                    // sum (which covers the adopted tip's past) and `apply_letter_set`'s covered-score gate
                    // then refuses every block at or below the adopted score — including THIS held block,
                    // which is outside that past and therefore in no sum at all. MEASURED (fuzz lane,
                    // 1-minimal `Produce(0,1) · Produce(1,1) · Jump(0,1)`, and the `Invalid(_) · … ·
                    // Jump` twins): "party 0's letter accumulator is X where a node fed ONLY the blocks
                    // derives Y". The sum is re-added directly — the block's filing and pending-letter
                    // retirement already ran when it was first applied here; only the SUM was dropped.
                    if !b.letter_set.is_empty() {
                        self.letter_acc = crate::letter::fold_letter_acc(&self.letter_acc, &b.letter_set);
                    }
                    // a refused fold is a TAG-LESS block: refused outright, never parked (§13.5 item 2)
                    if ok {
                        refolded += 1;
                    }
                }
                if refolded > 0 {
                    self.release_folded_tx_evictions();
                    // Privacy: a COUNT only — never a block id, tag, amount or key.
                    eprintln!("[dsync] re-folded {refolded} held block(s) outside the adopted tip's past into the inherited nullifier state");
                }
            }
        // ⛔ DEFECT DETECTOR — the #29 adopt IS the O(1)-instant path and MUST complete in ms.
        // MEASURED 2026-08-20: ONE SyncResponse held the rt lock 28-47s ([msg-slow]) — a violation
        // of the instant-sync construction — and nothing said WHICH half (decider verify vs the
        // install). This anomaly line names the offending half so it gets ROOT-FIXED, never accepted.
        // Durations of this node's own scheduler only — no chain data.
        // ⛔ AFTER the DAG re-anchors (the bundle's anchor graft above): `selected_tip` is now the chain's,
        // so "which of my applied blocks did the jump abandon" is answerable — the first placement of this
        // block ran before the graft and saw the old tip (measured by the DB-5 rewind pin).
        if let AdoptOutcome::Adopted(state) = &outcome {
                // §DD: the certified peg view is the chain's — install it, bring this custodian's opening to it
                // (DB-5), and lift the production hold for shells the bundle now covers (DB-4).
                // CHAIN-PUBLISH-REVIEWED: the ADOPT half of a decider-certified bundle (the same act that
                // installs the validator set three lines up) — the chain's state, nothing local is authored.
                self.peg.adopt_certified(
                    state.peg_reserve_commit,
                    state.peg_minted_commit,
                    state.peg_reserve_hwm_commit,
                    state.peg_ratio_bps,
                    state.peg_redeem_floor_bps,
                    state.peg_yield_rate_bps,
                );
                // DB-251: the chain's certified price marks replace this jumper's own, which are stale by definition.
                self.peg.adopt_certified_price_marks(&state.peg_price_marks);
                // DB-259: and the chain's bond locks, so this node judges every later unbond exactly as a
                // node that watched the bond land (maturity anchor + the locked note DB-257 carries back).
                self.adopt_certified_bond_locks(&state.bond_heights, &state.bond_locked_notes);
                // DB-274 P2 (§8.7): and the chain's unbonding collateral, so this node releases (or burns) each note at
                // the same fold step as every peer.
                self.unbonding = state.unbonding.iter().cloned().collect();
                // DB-271: and the chain's wrapped-asset registry, so a jumper applies every wrapped mint the chain
                // applies, against the same per-asset ratio and commitments.
                self.peg.adopt_certified_wrapped_assets(&state.peg_wrapped_assets);
                // LIQUIDATION §10: and the chain's stability-pool words, so a jumper applies every deposit, withdrawal and
                // liquidation against the same pool.
                self.peg.adopt_certified_pools(&state.peg_pools);
                // A-F50: and the chain's IonSwap pool book (pending orders, USDm held, pool count), so a jumper applies every
                // settlement its peers apply, against the same pending list and the same layer word.
                self.peg.adopt_certified_ion(
                    state.peg_ion_pending.clone(),
                    state.peg_ion_usdm_held,
                    state.peg_ion_pools,
                );
                // SATOSHI: and the chain's issued SAT total and pendulum snapshot, so a jumper credits the next reward against
                // the same cap and pays custody yield at the same rate as every peer.
                self.peg.adopt_certified_sat(state.peg_sat_issued, state.peg_pendulum);
                // §BR: and the chain's §BR words (fee pools, miner quarter, bonders' index, set-aside, stake snapshot and
                // paid-out total, deployments, attestations), so a jumper pays and refuses exactly what every peer does.
                self.peg.adopt_certified_br(&state.peg_br);
                // IonSwap pools: the ledger just took a contract-state root (and a pool count) this node's own fold did
                // not produce. Its pools cache describes the chain it stood on BEFORE the jump: a leaf it holds may
                // have moved since, and the refill's rule "a leaf held is the newer word" would keep the stale one for
                // good. Unless the cache already IS this state's tree with every pool's row, it is dropped whole and
                // the pools are asked for again, each leaf proven against the adopted root (`IonCache::take_page`).
                if !self.ion_cache_is_current() {
                    self.ion_cache = crate::node::objects::ion_pool::IonCache::default();
                }
                // DB-357 part 1: and the chain's retention-endowment commitment, L2 settlement root and root-history
                // spine, so a jumper stands on the same three values every watching node holds (the sync census
                // listed all three as never inherited). The adopt door refused a spine that does not parse, so the
                // restore below cannot fail on an adopted state; if it ever did, the node keeps its own spine and
                // says so, rather than installing half a state silently.
                self.peg.adopt_certified_retention_endowment(state.peg_retention_endowment_commit);
                self.l2_state_root = state.l2_state_root;
                match crate::spend_frontier::PoseidonSpendFrontier::from_peaks_hex(&state.root_history_peaks_hex) {
                    Some(rh) => {
                        self.root_history = rh;
                        // ⛔ G2a: the rewind base this adopt seeded (ring entry + checkpoint at the certified ordinal) was
                        // taken before the adopted anchor spine landed: it carries THAT spine, so a rewind to the anchor
                        // restores the chain's anchors, never this node's pre-adopt ones.
                        let k = self.spend_frontier.count() / crate::cover::BLOCK_FIXED_NOTE_COUNT as u64;
                        if let Some(back) = self.spine_recent_frontiers.back_mut().filter(|e| e.0 == k && e.2.is_none()) {
                            back.3 = self.root_history.clone();
                        }
                        if let Some(ck) = self.fold_checkpoint.as_mut().filter(|c| c.0 == k) {
                            ck.2 = self.root_history.clone();
                        }
                    }
                    None => eprintln!(
                        "[dsync] ⛔ DB-357: the adopted root-history spine did not restore — the adopt door should have \
                         refused it; this node keeps its own spine and its root_history_root() will differ"
                    ),
                }
                // §DD-b: the certified chain's recent one-time ids become this node's replay guard.
                self.peg.adopt_one_time_ids(&state.applied_one_time_ids);
                for (id, k) in &state.applied_one_time_ids {
                    if !self.applied_one_time_ids.iter().any(|(i, kk, _)| i == id && kk == k) {
                        self.applied_one_time_ids.push_back((*id, *k, state.tip)); // O1-FOOTPRINT-REVIEWED: bounded by APPLIED_ONE_TIME_ID_RING_MAX
                        while self.applied_one_time_ids.len() > crate::peg_attest::APPLIED_ONE_TIME_ID_RING_MAX {
                            self.applied_one_time_ids.pop_front();
                        }
                    }
                }
                // §DD interim: one-time ids applied by blocks the certified chain does NOT contain are not chain
                // state — forget them, so `deposit_minted` and the burn/release/liquidation guards answer for the
                // chain this node now follows (§DD-b moves these ids into the nullifier slots for good).
                // CHAIN-PUBLISH-REVIEWED: the adopt half of a certified bundle; nothing local is authored.
                let abandoned: Vec<([u8; 32], u8)> = self
                    .applied_one_time_ids
                    .iter()
                    .filter(|(_, _, b)| !self.block_in_recent_past(b))
                    .map(|(id, k, _)| (*id, *k))
                    .collect();
                for (id, k) in &abandoned {
                    self.peg.forget_one_time_id(id, *k);
                }
                let kept: Vec<([u8; 32], u8, crate::block::BlockId)> = self
                    .applied_one_time_ids
                    .iter()
                    .filter(|(_, _, b)| self.block_in_recent_past(b))
                    .cloned()
                    .collect();
                self.applied_one_time_ids = kept.into_iter().collect();
                if !abandoned.is_empty() {
                    eprintln!(
                        "[peg] {} one-time id(s) applied by blocks the jump abandoned were forgotten — their \
                         transitions are not on the chain this node now follows",
                        abandoned.len()
                    );
                }
                // ⛔⛔⛔ DB-249 — A HELD BLOCK OUTSIDE THE ADOPTED PAST IS RE-APPLIED FOR EVERY STATE THE ADOPT
                // REPLACED, NOT ONLY THE NULLIFIER AND LETTER SUMS. D-36/D-49 above re-fold such a block into
                // A_tip and the letter sum ("what you hold off the new branch is re-applied — never dropped"),
                // but the peg ledger + one-time ids and the validator set were REPLACED by the certified view and
                // the block's own transitions were dropped with them — while this node's next block merges it (it
                // is a tip here — true only for a block the adopt left SETTLED; a real jump's pre-anchor blocks are
                // stale and never reach this set, DB-286) and every peer that grafts it applies them. MEASURED (lane-db224-carriage 06:02,
                // `an_executor_whose_mint_block_is_abandoned…`): A read its own mint as unminted, its re-mint was
                // refused as `[assemble-dup] … ALREADY on chain` + `[tx-evict] ⛔ LOSING STATE`, and the pair could
                // end on two `minted_commit`s. The SAME set D-36 re-folds, through the graft's OWN two calls
                // (`apply_bond_set` + `apply_chain_objects_of`, then `record_applied_one_time_ids`), in (blue
                // score, id) order: parity with the graft door by construction, and every door refuses a repeat
                // (`Replay` / `AlreadySeated` / same-cm), so a kept class is not applied twice.
                // ROOT-LAYER: the adopt is where these states are replaced, so the compensation is produced here,
                // after the certified install and before the DB-5 resync reads the peg commitments.
                // MEASURED: `db249_a_held_mint_block_left_off_the_adopted_past_keeps_its_mint_and_the_pair_agrees_on_one`.
                // MUST-STAY-GREEN: every jump pin, db250, db246, the dd peg pins, the D-36/D-49 pins.
                // cons: one apply per held block per adopt — D-36's set, bounded by RECORD_FOLD_DEPTH x DAG width;
                // a held block that already FOLDED locally is in neither set (DB-249b, named, not closed here).
                let mut held = std::mem::take(&mut held_outside_adopted_past);
                held.retain(|b| !b.pow_proof.is_empty()); // a shell carries no sets; it applies when its body lands
                held.sort_by_key(|b| (self.relay.dag().get(&b.id()).map(|n| n.blue_score).unwrap_or(0), b.id()));
                for b in &held {
                    // ⭐ DB-274 P2 (§8.7): a held block's bond set applies when it FOLDS (`bond_step_at_fold`), not here.
                    let key = self.credit_key_of(b);
                    self.apply_chain_objects_of(&b.tx_ids, &b.credit_set, &b.nullifier_proof.padded_tags, key, &b.wide_objects);
                    self.record_applied_one_time_ids(b.id());
                }
                if !held.is_empty() {
                    // DIGITAL-CASH-PRIVACY-REVIEWED: a block COUNT only — no id, object, amount, key or owner.
                    eprintln!(
                        "[dsync] DB-249: re-applied {} held block(s) outside the adopted past (chain objects, \
                         one-time ids) — the certified state does not count them and this node's next block merges them",
                        held.len()
                    );
                }
                self.forget_published_mints_the_chain_lacks();
                let _ = self.resync_custodian_opening_to_chain();
                if self.unapplied_shell_floor.is_some() {
                    if state.blue_score >= self.unapplied_shell_ceiling {
                        self.unapplied_shell_floor = None;
                        self.unapplied_shell_ceiling = 0;
                        self.unapplied_shell_count = 0;
                        self.unapplied_shell_ids.clear();
                    } else {
                        self.unapplied_shell_floor = Some(state.blue_score.saturating_add(1));
                        // the bundle covered every shell at or below its tip's score: those are applied
                        let covered = state.blue_score;
                        self.unapplied_shell_ids
                            .retain(|i| self.relay.dag().get(i).map_or(false, |n| n.blue_score > covered));
                        self.unapplied_shell_count = self.unapplied_shell_ids.len() as u64;
                    }
                }
        }
        let ms_total = sync_t0.elapsed().as_millis();
        if ms_total > 1_000 {
            eprintln!(
                "[dsync-hold] ⛔ the O(1) adopt violated its instant bound: {ms_total}ms total                  (decider verify {ms_verify}ms, install {}ms) — root-fix the named half",
                ms_total.saturating_sub(ms_verify)
            );
        }
        outcome
    }

    /// The instant-sync state this node last adopted (tip + frontier), if it has jumped via #29 DSYNC.
    pub fn synced_state(&self) -> Option<&SyncState> {
        self.synced.as_ref()
    }

    // ---- Local-disk persistence (#106 frontier-persist for the greenfield node; see [`crate::persist`]) ----

    /// Serve a peer's [`WireMsg::SyncRequest`] (#29 DSYNC): build this node's sync bundle and wrap it
    /// as a [`WireMsg::SyncResponse`] to send back over the onion transport. Returns `None` only
    /// pre-genesis (no tip to serve). Any synced node can answer — no single sync source.
    pub fn serve_sync_request(
        &mut self,
        decider_proof: Vec<u8>,
        frontier: FrontierSnapshot,
    ) -> Option<WireMsg> {
        Some(WireMsg::SyncResponse(
            self.build_sync_bundle(decider_proof, frontier)?.to_wire(),
        ))
    }

}
