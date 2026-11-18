// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE CHAIN-ACTION MANIFEST — an ECOSYSTEM-WIDE sweep for transitions that SHOULD ride a block
//! and do not.
//!
//! WHY THIS EXISTS. On 2026-09-11 a collateral ratio was being set by `POST /register_wrapped_asset`
//! straight into the node's ledger: no threshold, no vote, no block. The
//! `no-node-local-in-replicated-state` hook did not fire, and the reason is instructive — that hook models
//! NON-DETERMINISTIC bytes reaching replicated state (a secret, an RNG, a clock). The ratio was two
//! perfectly deterministic integers. **The defect is the AUTHORITY, not the bytes**: two honest nodes
//! diverge just as hard on deterministic input when only ONE of them performed the transition.
//!
//! The hook was then given a rule for that shape, but a PreToolUse hook only ever sees the edit in front
//! of it, and its rule names mutators in a HAND-WRITTEN list — which catches exactly what somebody
//! remembered to list. This sweep is the other half: it reads the tree itself, DERIVES the call sites,
//! and fails when a new one appears. The user asked for precisely this — "something that finds these
//! types of errors where things that should be chain actions arent chain actions automatically
//! ecosystem wide".
//!
//! THE RULE IT ENFORCES. In a REQUEST-HANDLER file, a call of the form `node_mut().F(..)` where `F` is
//! neither the chain path itself nor a node-local cache must sit in a route that also PUBLISHES a chain
//! object. A handler may read anything and may publish; what it may not do is perform a replicated
//! transition on its own authority. Route-scoped, so a neighbouring route's publish cannot vouch for it.
//!
//! ⛔⛔ WHAT THIS SWEEP CANNOT SEE, stated plainly so nobody reads a green run as more than it is.
//! It checks that a route publishes SOMETHING; it cannot check that the published object carries the
//! WHOLE transition the handler performed. MEASURED on this very tree the day the sweep was written:
//! `/wrapped_mint_execute` publishes a `Class::BridgeCredit` carrying the minted NOTE, and passes this
//! sweep — yet `BridgeCreditTx` has no field for the peg's new reserve/minted commitments and
//! `apply_chain_bridge_credit` never advances them, so the note travels and the COMMITMENT ADVANCE stays
//! local. Two nodes end with the same notes and different peg digests. Catching that needs the RUNTIME
//! chain-derivability oracle (the harness's I-CP: a node fed only blocks must derive the same state), and
//! its gap is COVERAGE — the campaign does not drive these bridge routes. Static sweep and runtime oracle
//! are two halves of one answer; neither replaces the other.
//!
//! Shrink-only: [`FILED_OPEN`] may lose entries, never gain them.

#[cfg(test)]
mod tests {
    /// Request-handler surfaces: network- or IPC-facing code that answers a caller.
    const HANDLERS: &[&str] = &["rpc_http.rs", "rpc.rs", "node_runtime.rs", "sovereign.rs"];

    /// The chain path ITSELF — applying or publishing an object is the correct direction, not the defect.
    const CHAIN_PATH: &[&str] = &["ingest_block", "ingest_tx", "ingest_tx_unverified"];

    /// This node's OWN caches, wants and signer config. Read by nobody else and agreed by nobody, so they
    /// are not replicated state and a handler may set them. Each is here because it fails the question
    /// "must another node agree on this byte-for-byte?" with a NO.
    const NODE_LOCAL: &[&str] = &[
        "want_record_at_id",
        "want_account_bucket",
        "record_note_clue",
        "set_bridge_signer",
        "set_decider_verifier",
        // DB-77 (2026-09-19): the REQUEST lane. `peg_request_note` files a wallet's sealed mint/redeem
        // request into this node's own lane slot and gossips the request; no other node must agree on
        // the slot byte-for-byte — the TRANSITION it leads to is what a custodian publishes as a framed
        // `Class::PegIn` / `Class::PegOut` / `Class::WrappedMint` from its lane tick, and every node
        // applies that object at graft. `peg_in_published_still_pooled` only re-checks this node's pool.
        "peg_request_note",
        "peg_in_published_still_pooled",
        // §BR-15 §18.12 (filed 2026-11-10 by the audit lane; the route landed without it and this sweep stood red): the
        // DeFi REQUEST lane, the same shape as `peg_request_note`. `/submit_defi_order` and `/submit_defi_claim` hand a
        // wallet's sealed slot to THIS node's own bounded intake (`DEFI_INTAKE_MAX`); the node's custody lane drains it
        // (`defi_lane::drain_intake`) and the TRANSITION it leads to is the batch's framed `Class::DefiSlots` object,
        // which every node applies at the fold. No other node holds or must agree on another node's intake.
        "push_defi_intake",
        // `/get_my_pq_notes`: the by-ORDINAL sibling of `want_record_at_id` above — it files a fetch want into this node's
        // own bounded want set (`TX_REQ_FIXED_COUNT`) so a record it lacks is pulled from a peer. No other node holds or
        // must agree on another node's wants; the record it fetches is chain data every node verifies against its roots.
        "want_record_at_ordinal",
        // `/provision_reward_recipient`: the OPERATOR's choice of where THIS node's own block rewards are sealed (the file
        // its wallet provisions, `satoshi::reward_recipient_path`). Peers agree on the reward NOTE a block carries, which
        // they verify at graft — never on a producer's setting, which no other node could even read.
        "set_reward_recipient",
    ];

    /// Publishing the transition as a chain object — the sanctioned shape.
    const PUBLISH: &[&str] = &["ingest_tx(", "as_pq_tx(", "::wire(", "chain_object::frame", "submit_object"];

    /// ⛔ THE OPEN SET, every entry a KNOWN defect filed in `docs/FUNDS-LOSS-KILL-LIST.md` §V: a handler
    /// performing a replicated transition with nothing published in its route. This list is SHRINK-ONLY —
    /// the test refuses any call site not already named here, so the class cannot grow quietly while the
    /// backlog is worked down.
    const FILED_OPEN: &[&str] = &[
        // ⭐ `authorize_reserve_release` LEFT THIS LIST 2026-09-20 (DB-121): the RPC door that MARKED a burn
        // released with nothing paid is gone. `settle_reserve_release_observed` is now called only by the
        // Bitcoin payout lane (`crate::btc_payout`) when THIS node's own Bitcoin source has watched the payout
        // confirm — the same shape as the deposit watcher recording a confirmed deposit: an observation of the
        // foreign chain, never a MonerousD transition. `/reserve_release_status` is read-only.
        // ⭐ `execute_order_fill` LEFT THIS LIST 2026-09-14 — not by being excused, but because the
        // resolver can now see that it reaches `ingest_tx`. §AK put a fill on the transaction path; the
        // ratchet only noticed once the sweep stopped reading one call deep.
        // ⭐ `execute_yield_claim` LEFT THIS LIST 2026-09-16 (§CL): the harvest now publishes a framed
        // `Class::YieldClaim` carrying the stake note's nullifier, so the burn and the three credits
        // travel instead of existing on the node that answered `/claim_yield`.
        // ⭐ `peg_in_confidential` LEFT THIS LIST 2026-09-16 (§CS): the BTC/XMR deposit route — how USDm
        // comes into existence — now publishes a framed `Class::PegIn` through `ingest_tx`, and every
        // peer applies the same bytes at graft via `peg_in_tx::apply_chain_peg_in`.
        // ⭐ `peg_out_confidential` LEFT THIS LIST 2026-09-16 (§CS-b): the redeem now publishes a framed
        // `Class::PegOut` carrying the burned note's nullifier, so the BURN retires on every node.
        "recarry_stranded_note",
        // ⭐ `record_account_target` LEFT THIS LIST 2026-10-06: no request handler calls it any more (the sweep found no
        // site in rpc_http / rpc / sovereign — DB-273 §19.6 L3 moved owners onto the objects' own clues).
        // ⭐ `stage_credit_note` LEFT THIS LIST 2026-09-14 (§BA brick 2): the faucet drip — its only
        // production caller — now publishes a `Class::BridgeCredit` through `ingest_tx` instead of
        // staging a note no transaction stands behind.
        // ⭐ `submit_dir_entry_verdict` LEFT THIS LIST 2026-11-10 (audit F15): a directory entry is published as a paid
        // `Class::DirEntry` object through `publish_dir_entry`; no handler queues a sign-up on this node any more.
    ];

    /// Split a handler source into its route arms, so a neighbouring route's publish cannot vouch for
    /// this one. A file with no route arms (the runtime) is one segment — its whole body.
    fn route_arms(src: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = src.lines().collect();
        let mut starts: Vec<(usize, String)> = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let t = l.trim_start();
            if !t.starts_with("(\"") {
                continue;
            }
            // ("METHOD", "/path") => — take the second quoted field as the route name.
            let q: Vec<&str> = t.split('"').collect();
            if q.len() >= 5 && t.contains("=>") && q[3].starts_with('/') {
                starts.push((i, q[3].to_string()));
            }
        }
        if starts.is_empty() {
            return vec![("<file>".to_string(), src.to_string())];
        }
        let mut out = Vec::new();
        for (k, (i, name)) in starts.iter().enumerate() {
            let end = if k + 1 < starts.len() { starts[k + 1].0 } else { lines.len() };
            out.push((name.clone(), lines[*i..end].join("\n")));
        }
        out
    }

    /// Every `node_mut().F(` in a body, skipping comment lines.
    fn mutations(body: &str) -> Vec<String> {
        let mut out = Vec::new();
        for l in body.lines() {
            let t = l.trim_start();
            if t.starts_with("//") || t.starts_with("///") || t.starts_with('*') {
                continue;
            }
            let mut rest = l;
            while let Some(p) = rest.find("node_mut()") {
                rest = &rest[p + "node_mut()".len()..];
                let after = rest.trim_start();
                let after = after.strip_prefix('.').unwrap_or(after).trim_start();
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                if !name.is_empty() && after[name.len()..].trim_start().starts_with('(') {
                    out.push(name);
                }
            }
        }
        out
    }

    /// The classifier both the test and its own calibration call — ONE definition, so the detector that
    /// is proven in the self-test is the detector that judges the tree.
    fn unpublished_transitions(src: &str) -> Vec<(String, String)> {
        unpublished_transitions_with(src, &publishing_node_methods())
    }

    /// ⭐⭐⭐ THE NODE METHODS THAT REALLY PUBLISH — RESOLVED, NOT LISTED.
    ///
    /// ⛔ WHY THIS EXISTS. `PUBLISH` is a set of TEXTUAL markers (`ingest_tx(`, `::wire(`, …), so a route
    /// that delegates its publication to a named method — `node_mut().publish_asset_create(&c)` — reads as
    /// if it published NOTHING, even though the method it calls ends at `ingest_tx`. MEASURED: the four
    /// asset/unbond routes landed as publishers and this sweep flagged every one of them.
    ///
    /// ⛔ AND THE LAZY FIX WOULD HAVE BEEN A HOLE: treating any method NAMED `publish_*` as a publisher
    /// lets a method vouch for itself by its own name, which is exactly the kind of evidence this file
    /// exists to refuse. So the body is read from `node.rs` and must CONTAIN a real publish marker.
    fn publishing_node_methods() -> Vec<String> {
        // `impl Node` spans node.rs and its production modules since the §SPLIT: read them all (the shared reader)
        let src = crate::test_census::node_production_source().expect("node.rs reads");
        // Every method on `Node`, public or not, with its body — private ones matter because the public
        // publishers delegate to them (`publish_asset_create` -> `publish_asset_object_with_note`).
        let mut methods: Vec<(String, String)> = Vec::new();
        let mut at = 0usize;
        let bytes = src.as_bytes();
        while at < src.len() {
            let Some(rel) = src[at..].find("\n    ") else { break };
            let start = at + rel + 5;
            if start >= src.len() {
                break;
            }
            // Slice on a CHAR BOUNDARY — this source is full of `—`, and a byte-indexed window lands
            // mid-codepoint. MEASURED: `byte index … is not a char boundary`.
            // wide enough for the longest visibility (`pub(super) fn `) plus any method name: a 40-byte window cut
            // `publish_spending_object_nfs` to `…_nf`, so no call ever matched it and the resolver went blind
            let mut stop = (start + 200).min(src.len());
            while stop > start && !src.is_char_boundary(stop) {
                stop -= 1;
            }
            let head = &src[start..stop];
            let after_vis = head
                .strip_prefix("pub(crate) fn ")
                .or_else(|| head.strip_prefix("pub(super) fn "))
                .or_else(|| head.strip_prefix("pub fn "))
                .or_else(|| head.strip_prefix("fn "));
            at = start;
            let Some(rest) = after_vis else { continue };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() {
                continue;
            }
            // The body ends at the next item at this indentation.
            let body_end = src[start..]
                .find("\n    }")
                .map(|k| start + k)
                .unwrap_or(src.len());
            let _ = bytes;
            methods.push((name, src[start..body_end].to_string()));
        }
        // ⭐ TRANSITIVE, TO A FIXPOINT. A route's publisher is usually two calls from `ingest_tx`:
        // `publish_asset_create` -> `publish_asset_object_with_note` -> `ingest_tx`. A one-level resolver
        // misses exactly that shape — MEASURED: the calibration below caught it on the first run.
        let mut known: Vec<String> = Vec::new();
        for _ in 0..6 {
            let before = known.len();
            for (n, body) in &methods {
                if known.iter().any(|k| k == n) {
                    continue;
                }
                let direct = PUBLISH.iter().any(|p| body.contains(p));
                let delegated = known.iter().any(|k| body.contains(&format!("{k}(")));
                if direct || delegated {
                    known.push(n.clone());
                }
            }
            if known.len() == before {
                break;
            }
        }
        known
    }

    fn unpublished_transitions_with(src: &str, resolved: &[String]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (route, body) in route_arms(src) {
            let publishes = PUBLISH.iter().any(|p| body.contains(p))
                || resolved.iter().any(|m| body.contains(&format!("{m}(")));
            if publishes {
                continue;
            }
            for f in mutations(&body) {
                if CHAIN_PATH.contains(&f.as_str())
                    || NODE_LOCAL.contains(&f.as_str())
                    || f.ends_with("_for_test")
                {
                    continue;
                }
                out.push((f, route.clone()));
            }
        }
        out
    }

    /// ⛔⛔⛔ THE SWEEP: no request handler may perform a replicated transition on its own authority.
    #[test]
    fn no_handler_performs_a_consensus_transition_without_publishing_it() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src");
        let mut found: Vec<(String, String, String)> = Vec::new();
        for h in HANDLERS {
            let p = std::path::Path::new(dir).join(h);
            let Ok(src) = std::fs::read_to_string(&p) else {
                continue;
            };
            for (f, route) in unpublished_transitions(&src) {
                found.push((h.to_string(), f, route));
            }
        }
        let mut unfiled: Vec<String> = found
            .iter()
            .filter(|(_, f, _)| !FILED_OPEN.contains(&f.as_str()))
            .map(|(h, f, r)| format!("{h} {r} -> node_mut().{f}(..)"))
            .collect();
        unfiled.sort();
        unfiled.dedup();

        let distinct: std::collections::BTreeSet<&str> =
            found.iter().map(|(_, f, _)| f.as_str()).collect();
        eprintln!(
            "[chain-action] {} call site(s), {} distinct transition(s) still executed in a handler: {:?}",
            found.len(),
            distinct.len(),
            distinct
        );

        assert!(
            unfiled.is_empty(),
            "⛔ A HANDLER PERFORMS A REPLICATED TRANSITION THAT NO BLOCK CARRIES:\n  {}\n\n\
             A request handler may READ any node state and may PUBLISH a chain object. It may not perform \
             the transition itself: the bytes may be perfectly deterministic and two nodes still diverge, \
             because only the one that got the request ever applied it. Fix it the way the wrapped-asset \
             ratio was fixed — frame the transition as a `chain_object::Class`, publish it from the route, \
             and apply it at the block-apply seam on EVERY node. If this really is node-local state that \
             nobody else must agree on, add it to NODE_LOCAL with the reason it fails \"must another node \
             agree on this byte-for-byte?\".",
            unfiled.join("\n  ")
        );

        // Shrink-only: an entry that has been fixed must be REMOVED from FILED_OPEN, so the backlog can
        // never quietly refill with a name that is already spent.
        let live: std::collections::BTreeSet<&str> =
            found.iter().map(|(_, f, _)| f.as_str()).collect();
        let stale: Vec<&&str> = FILED_OPEN.iter().filter(|f| !live.contains(*f)).collect();
        assert!(
            stale.is_empty(),
            "these are no longer found and must be DELETED from FILED_OPEN (the ratchet only shrinks): {stale:?}"
        );
    }

    /// CALIBRATION — the detector is proven to fire AND to stay silent, on the real shapes. A sweep that
    /// has never been shown to catch anything is a green light with nothing behind it.
    #[test]
    fn the_detector_fires_on_an_unpublished_transition_and_is_silent_on_a_published_one() {
        // The ACTUAL pre-fix shape that slipped past every hook.
        let bad = "        (\"POST\", \"/register_wrapped_asset\") => {\n\
                   \x20           rt.node_mut().register_wrapped_asset(asset_id, ratio_bps);\n\
                   \x20       }\n";
        let hits = unpublished_transitions(bad);
        assert_eq!(hits.len(), 1, "the detector must catch the unpublished transition: {hits:?}");
        assert_eq!(hits[0].0, "register_wrapped_asset");

        // The FIXED shape — same route, now publishing an object.
        let good = "        (\"POST\", \"/register_wrapped_asset\") => {\n\
                    \x20           let tx = crate::wrapped_asset_tx::as_pq_tx(&h, &att, bits);\n\
                    \x20           match rt.node_mut().ingest_tx(tx) { Ok(_) => (), Err(_) => () }\n\
                    \x20       }\n";
        assert!(
            unpublished_transitions(good).is_empty(),
            "publishing the transition is the sanctioned shape and must pass"
        );

        // A read-only handler must never be flagged.
        let ro = "        (\"GET\", \"/peg_status\") => {\n\
                  \x20           let eff = rt.node().peg().wrapped_asset_ratio_bps(1);\n\
                  \x20       }\n";
        assert!(unpublished_transitions(ro).is_empty(), "a read-only route is not a transition");

        // A node-local want is not replicated state.
        let local = "        (\"POST\", \"/want\") => {\n\
                     \x20           rt.node_mut().want_record_at_id(id);\n\
                     \x20       }\n";
        assert!(unpublished_transitions(local).is_empty(), "a node-local want is not replicated state");

        // ⭐⭐⭐ AND THE DELEGATION RESOLVER, BOTH WAYS. A route that hands its transition to a node
        // method is sanctioned ONLY IF that method really publishes — never because of what it is named.
        let delegating = "        (\"POST\", \"/submit_thing\") => {\n\
                          \x20           rt.node_mut().publish_thing(&t);\n\
                          \x20       }\n";
        assert!(
            !unpublished_transitions_with(delegating, &[]).is_empty(),
            "⛔ CALIBRATION FAILED: a route delegating to a method that publishes NOTHING must still be \
             flagged. If this passes, the resolver excuses any call and the sweep is blind."
        );
        assert!(
            unpublished_transitions_with(delegating, &["publish_thing".to_string()]).is_empty(),
            "⛔ CALIBRATION FAILED: a route delegating to a VERIFIED publisher must pass, or every real \
             publisher in the tree reads as a defect and the sweep gets muted."
        );
        // ⛔ AND THE NAME ALONE MUST NOT BE ENOUGH: `publish_thing` is only sanctioned because it was
        // RESOLVED above. With an empty resolved set — which is what a method whose body never reaches
        // `ingest_tx` yields — the identical route is a finding.
        let resolved_live = publishing_node_methods();
        assert!(
            resolved_live.iter().any(|m| m == "publish_asset_create"),
            "⛔ CALIBRATION FAILED: the resolver did not find `publish_asset_create` in node.rs, so it is \
             reading the wrong file or the wrong shape and every route it excuses is unchecked."
        );
        assert!(
            !resolved_live.iter().any(|m| m == "tip_height"),
            "⛔ CALIBRATION FAILED: the resolver called a pure READ (`tip_height`) a publisher. A resolver \
             that says yes to everything excuses everything. (found {} methods)",
            resolved_live.len()
        );
    }
}
