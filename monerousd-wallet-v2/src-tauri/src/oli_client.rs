// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! OLI client — the wallet half of sub-second cold restore.
//!
//! A wallet holding only its recovery phrase can ENUMERATE the one-time locators its notes were tagged
//! with (`PRF(loc_sk, domain, j)`), so instead of scanning the chain for notes that might be its own, it
//! looks each locator up in the node's index and is told exactly which (block, slot) to open. Restore
//! becomes O(owned) lookups against constant-size shards rather than a walk over every note ever made.
//!
//! What the serving node learns: nothing about which bucket was probed (each query is LWE-hiding), and
//! nothing from the request pattern (a wave is always exactly `WAVE_SHARDS` shard fetches, decoys
//! included). What it can do: return garbage — which costs the wallet a MISS and nothing else, because a
//! located note is only accepted after the wallet's own ML-KEM decap and `note_cm` binding succeed. The
//! locator secret and scan key never leave the device.

use usdmd_node::oli;

/// One located note: where the index says a locator's note sits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located {
    /// Which locator index `j` in its domain resolved.
    pub j: u64,
    /// NOT-AN-ADDRESS (DB-223 Q2 §11 (a)): the record's FOLD ORDINAL — the index entry's one coordinate, so the
    /// note's leaf index is `(ordinal − 1)·256 + slot` with no further ask. It is fetched by `by_ordinal`, and
    /// the serving row names the record ADDRESS the DA accessors take; the two are never one number.
    pub ordinal: u64,
    /// The note's slot within that block's fixed 256-note cover shape.
    pub slot: u8,
}

/// The epoch parameters a wallet needs to address the index, as served by `/oli_params`.
#[derive(Debug, Clone)]
pub struct Params {
    pub shard_bits: u32,
    pub epoch_seed: [u8; 32],
    pub epoch_blocks: u64,
}

/// Fetch `/oli_params`. These are identical for every caller and carry no wallet data.
pub fn fetch_params(agent: &ureq::Agent, node_url: &str) -> Result<Params, String> {
    let v: serde_json::Value = agent
        .post(&format!("{node_url}/oli_params"))
        .send_json(serde_json::json!({}))
        .map_err(|e| format!("oli_params: {e}"))?
        .into_json()
        .map_err(|e| format!("oli_params json: {e}"))?;
    let shard_bits = v.get("shard_bits").and_then(|x| x.as_u64()).ok_or("oli_params: no shard_bits")? as u32;
    let epoch_blocks = v.get("epoch_blocks").and_then(|x| x.as_u64()).unwrap_or(0);
    let seed_hex = v.get("epoch_seed").and_then(|x| x.as_str()).ok_or("oli_params: no epoch_seed")?;
    let epoch_seed: [u8; 32] = hex::decode(seed_hex)
        .map_err(|e| format!("oli_params seed: {e}"))?
        .try_into()
        .map_err(|_| "oli_params: epoch_seed is not 32 bytes".to_string())?;
    Ok(Params { shard_bits, epoch_seed, epoch_blocks })
}

/// Fetch ONE shard's whole table from `/oli_table` — `(the served index's shard-bit width, the table bytes)`.
///
/// ⭐ DB-228 — THE TRIVIAL PIR REPLACES THE LWE ROUND TRIP. A wallet that holds a whole shard tells the node
/// only WHICH shard it fetched (exactly what the per-shard `/oli_hint` request of the LWE path told it) and
/// nothing about which bucket it read — information-theoretically, not computationally. It is also the
/// cheaper shape at this shard size: the table is `SHARD_BUCKETS × BUCKET_BYTES` = 256 KB, while the LWE hint
/// alone was 512 KB before one 8 KB query went out (MEASURED live :27780, 2026-09-26: `/oli_hint` answered
/// 1,048,605 B of hex). And it is what the batched note fetch needs: the whole table is the universe that
/// fetch draws its cover from (`ShardTables::positions`), so cover and reals come from one place.
///
/// A reply that is not exactly one table is an ERROR — never a short table read as "no entry here".
pub fn fetch_table(agent: &ureq::Agent, node_url: &str, shard: u64) -> Result<(u32, Vec<u8>), String> {
    let v: serde_json::Value = agent
        .post(&format!("{node_url}/oli_table"))
        .send_json(serde_json::json!({ "shard": shard }))
        .map_err(|e| format!("oli_table: {e}"))?
        .into_json()
        .map_err(|e| format!("oli_table json: {e}"))?;
    let bits = v.get("shard_bits").and_then(|x| x.as_u64()).ok_or("oli_table: no shard_bits")?;
    let bits = u32::try_from(bits).map_err(|_| format!("oli_table: shard_bits {bits} is not a width"))?;
    let hex_table = v.get("table_hex").and_then(|x| x.as_str()).ok_or("oli_table: no table_hex")?;
    let table = hex::decode(hex_table).map_err(|e| format!("oli_table hex: {e}"))?;
    let want = (oli::SHARD_BUCKETS as usize) * oli::BUCKET_BYTES;
    if table.len() != want {
        return Err(format!("oli_table: {} bytes, not the fixed {want}-byte shard table", table.len()));
    }
    Ok((bits, table))
}

/// The whole shard tables ONE restore pass holds, and the shard-fetch shape that gets them there.
///
/// ⭐ DB-228. What a serving node observes of a restore's lookup is the SET OF SHARDS it fetches, so that set
/// must not be a function of this wallet's keys alone:
///   * an index of `WAVE_SHARDS` shards or fewer is fetched WHOLE in the first wave — every wallet asks for
///     the same thing, and the pass never fetches again;
///   * a larger index is fetched in waves of exactly `min(WAVE_SHARDS, shards not yet held)`: the shards this
///     pass's locators still need, topped up with decoys drawn by a keyed PRF of the wallet's own secret.
/// The decoys are keyed on `(secret, wave index)` and on nothing fresh, so a later pass over the same index
/// reproduces the same waves: the fetched set does not churn from pass to pass, and neither does the cover
/// pool drawn from it (`positions`) — which is what keeps the batched note fetch from being intersected.
/// Held for one pass and dropped with it (at most `WAVE_SHARDS` × 256 KB = 4 MB per wave); nothing persists.
pub struct ShardTables {
    shard_bits: u32,
    secret: [u8; 32],
    tables: std::collections::BTreeMap<u64, Vec<u8>>,
    waves: u64,
}

impl ShardTables {
    pub fn new(shard_bits: u32, secret: [u8; 32]) -> Self {
        Self { shard_bits, secret, tables: std::collections::BTreeMap::new(), waves: 0 }
    }

    pub fn shard_bits(&self) -> u32 {
        self.shard_bits
    }

    /// Shard tables this pass holds.
    pub fn held(&self) -> usize {
        self.tables.len()
    }

    /// Fetch waves this pass has made.
    pub fn waves(&self) -> u64 {
        self.waves
    }

    pub fn table(&self, sid: u64) -> Option<&[u8]> {
        self.tables.get(&sid).map(|t| t.as_slice())
    }

    /// The shard ids of the next fetch wave, given the shards this pass still `missing` — `oli::wave_shards`,
    /// the ONE wave builder, over this pass's own held set and wave count (the whole index when it is
    /// `WAVE_SHARDS` shards or fewer; else exactly `min(WAVE_SHARDS, unheld)` new shards, needed first, then
    /// keyed decoys that reproduce pass after pass).
    pub(crate) fn next_wave(&self, missing: &[u64]) -> Vec<u64> {
        oli::wave_shards(
            missing,
            &|s| self.tables.contains_key(&s),
            self.tables.len() as u64,
            self.shard_bits,
            &self.secret,
            self.waves,
        )
    }

    /// Hold every shard in `needed`, fetching what is missing in constant-shape waves. Each wave adds every
    /// missing shard it can carry, so this ends after `ceil(missing / WAVE_SHARDS)` waves at most.
    pub fn ensure(&mut self, agent: &ureq::Agent, node_url: &str, needed: &[u64]) -> Result<(), String> {
        loop {
            let missing: Vec<u64> = needed.iter().copied().filter(|s| !self.tables.contains_key(s)).collect();
            if missing.is_empty() {
                return Ok(());
            }
            let wave = self.next_wave(&missing);
            if wave.is_empty() {
                return Err(format!("oli: {} needed shard(s) but no shard left to fetch", missing.len()));
            }
            for sid in &wave {
                let (bits, table) = fetch_table(agent, node_url, *sid)?;
                if bits != self.shard_bits {
                    return Err(format!(
                        "oli: the index changed shard width mid-pass ({} -> {bits}) — its epoch rolled; this \
                         pass stops here and the next one re-reads /oli_params",
                        self.shard_bits
                    ));
                }
                self.tables.insert(*sid, table);
            }
            self.waves += 1;
        }
    }

    /// Every entry position in every table this pass holds — decoy shards included — sorted and deduplicated.
    /// The index carries only real tagged notes (DB-235: the chaff is deleted), so this is the universe the
    /// batched note fetch draws its cover from and the universe every located real already belongs to.
    pub fn positions(&self) -> Vec<(u64, u8)> {
        let mut out: Vec<(u64, u8)> = Vec::new();
        for t in self.tables.values() {
            out.extend(oli::table_positions(t));
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Hold a table the test built itself, so the locate path is exercised with no node in the loop.
    #[cfg(test)]
    pub(crate) fn hold_for_test(&mut self, sid: u64, table: Vec<u8>) {
        self.tables.insert(sid, table);
    }
}

/// The index key a locator resolves to — the same value the node computed from the tag the sender
/// attached, derived here from the wallet's own secret with no help from anyone.
pub fn key_for(loc_sk: &[u8; 32], domain: &str, j: u64) -> [u8; oli::K_BYTES] {
    oli::index_key(&oli::tag_clue_bytes(&oli::locator_at(loc_sk, domain, j)))
}

/// ⭐⭐⭐ THE KEY THE SENDER ACTUALLY WRITES. `key_for` above derives the v1 tag; a sender paying a v3
/// address writes the v2 tag (`tag_clue_bytes_v2`, locator + salt + hint), so a lookup by the v1 key asks the
/// index for something that was never put there.
///
/// MEASURED 2026-08-10: `[oli-range] searched locator indices [0,2) and matched 0` from a wallet whose own
/// note had just settled — with the epoch floor removed, the process-local counter removed and the
/// COLD_RESTORE_GAP gate removed, so the read path was already correct and the index already reached the live
/// tip. Every remaining explanation was on the WRITE side, and this is it: two derivations of the same value
/// that do not agree, the same class of defect as the account-bucket id mismatch found earlier today.
///
/// The recipient can derive both halves itself — `address_salt` and `address_index_hint` are pure functions of
/// its own `loc_sk` and `j`, which is exactly how the sender got them out of the address. So this needs
/// nothing from the network and nothing stored.
pub fn key_for_v2(loc_sk: &[u8; 32], domain: &str, j: u64) -> [u8; oli::K_BYTES] {
    let loc = oli::locator_at(loc_sk, domain, j);
    let salt = oli::address_salt(loc_sk, domain, j);
    let hint = oli::address_index_hint(loc_sk, &salt, j);
    oli::index_key(&oli::tag_clue_bytes_v2(&loc, &salt, &hint))
}

/// Locate this wallet's notes for locator indices `j_from..j_from + count` in `domain`, from WHOLE shard
/// tables held in `tables` (fetched on demand, in constant-shape waves — see [`ShardTables`]).
///
/// BOTH tag forms are matched for every index, always: a v3 address is paid with the v2 tag and an older
/// one with v1, and the recipient cannot know which form the payer used — probing one form silently
/// refuses every note written in the other. Matching is `oli::table_candidates`: the key's two candidate
/// buckets sliced out of the table and run through the same 2-choice fingerprint test the LWE path decoded
/// into (`oli::probe_candidates`), so what a wallet locates cannot differ from the PIR path. A locator that
/// was never used — or a table a server garbled — simply does not appear: a garbled table can cause a MISS,
/// never a forged hit, because a located note is accepted only after the wallet's own ML-KEM decap binds it.
pub fn locate(
    agent: &ureq::Agent,
    node_url: &str,
    tables: &mut ShardTables,
    loc_sk: &[u8; 32],
    domain: &str,
    j_from: u64,
    count: u64,
) -> Result<Vec<Located>, String> {
    if count == 0 {
        return Ok(Vec::new());
    }
    struct Probe {
        j: u64,
        k: [u8; oli::K_BYTES],
        sid: u64,
    }
    let mut probes: Vec<Probe> = Vec::new();
    for j in j_from..j_from + count {
        for k in [key_for(loc_sk, domain, j), key_for_v2(loc_sk, domain, j)] {
            probes.push(Probe { j, k, sid: oli::shard_of(&k, tables.shard_bits()) });
        }
    }
    let needed: Vec<u64> = probes.iter().map(|p| p.sid).collect();
    let shards_needed = {
        let mut u = needed.clone();
        u.sort_unstable();
        u.dedup();
        u.len()
    };
    // ⭐ REPORT WHAT WAS ASKED, NOT JUST THAT NOTHING CAME BACK.
    //
    // `[oli-yield] locate returned 0 position(s)` says a lookup failed but not WHICH lookup, so it is
    // compatible with a wrong domain, a wrong index range, a wrong tag form and a wrong shard — four causes
    // with four different fixes and one identical symptom. The node-side twin of this ambiguity cost six
    // wrong guesses this session; adding `da_record_shape` there turned it into a single run.
    //
    // Print the exact question: the domain, the index range, and the first probe's key + shard. The node's
    // `[faucet] locator clue attached` line names the tag it WROTE, so these two lines side by side identify
    // the mismatch directly instead of by elimination.
    // DIGITAL-CASH-PRIVACY-REVIEWED: BY CONSTRUCTION this is the wallet's OWN local log on its OWN device.
    // The values are the index coordinates it is about to send anyway, and 4 bytes of a tag it derived
    // itself; no amount, no note, no commitment, no counterparty. Nothing new leaves the wallet.
    if let Some(first) = probes.first() {
        eprintln!(
            "[oli-ask] domain={domain} j={}..{} shards={} first_key={:02x}{:02x}{:02x}{:02x} shard={} \
             — compare with the node's [faucet] line: if the node wrote a tag this range never asks for, \
             the note is on chain and invisible to its owner.",
            j_from,
            j_from + count,
            shards_needed,
            first.k[0], first.k[1], first.k[2], first.k[3],
            first.sid,
        );
    }

    tables.ensure(agent, node_url, &needed)?;
    let mut out: Vec<Located> = Vec::new();
    for p in &probes {
        let table = tables
            .table(p.sid)
            .ok_or_else(|| format!("oli: shard {} was ensured but is not held", p.sid))?;
        // EVERY match, not the first: a reused address pays several notes to one locator.
        for (ordinal, slot) in oli::table_candidates(table, &p.k) {
            out.push(Located { j: p.j, ordinal, slot });
        }
    }
    out.sort_by_key(|l| (l.j, l.ordinal, l.slot));
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wallet's key derivation must agree, byte for byte, with what the NODE computes from the tag a
    /// sender attaches — otherwise every lookup misses and restore silently finds nothing. This pins the
    /// two sides together at the exact boundary (locator → tag → index key) that a unit test on either
    /// side alone would not catch.
    #[test]
    fn wallet_derived_index_key_matches_the_nodes_view_of_the_same_tag() {
        let entropy = *blake3::hash(b"MUSD/oli-client/test/seed").as_bytes();
        let loc_sk = oli::derive_loc_sk(&entropy);

        // Wallet side: from the seed alone.
        let wallet_k = key_for(&loc_sk, "chg", 3);

        // Node side: from the tag bytes that rode the note's clue channel.
        let tag_on_the_wire = oli::tag_clue_bytes(&oli::locator_at(&loc_sk, "chg", 3));
        let node_k = oli::index_key(&tag_on_the_wire);

        assert_eq!(wallet_k, node_k, "wallet and node must derive the SAME index key for one locator");

        // Different index / different domain / different seed must NOT collide.
        assert_ne!(wallet_k, key_for(&loc_sk, "chg", 4));
        assert_ne!(wallet_k, key_for(&loc_sk, "recv", 3));
        let other = oli::derive_loc_sk(blake3::hash(b"MUSD/oli-client/test/other-seed").as_bytes());
        assert_ne!(wallet_k, key_for(&other, "chg", 3));
    }

    /// LIVE-NODE INTEGRATION — run against a real running node, which is where a unit test cannot reach:
    /// the JSON field names, the hex encoding, the answer framing, and the client's parsing of all three.
    /// Point it at a node and run explicitly:
    ///   `MONEROUSD_OLI_TEST_URL=http://127.0.0.1:27790 cargo test --release oli_client_speaks_to_a_live_node -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE-node test, not a disabled assertion — it drives an EXTERNAL running node and FAILS (never skips) when one is named but unreachable; the in-suite unit tests cover all node-free ground.
    fn oli_client_speaks_to_a_live_node_over_real_http() {
        let url = std::env::var("MONEROUSD_OLI_TEST_URL")
            .expect("set MONEROUSD_OLI_TEST_URL to a running node, e.g. http://127.0.0.1:27790");
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(120)).build();

        // /oli_params — the real handler, parsed by the real client.
        let params = fetch_params(&agent, &url).expect("live /oli_params must answer");
        assert!(params.shard_bits <= 40, "shard_bits is a sane width: {}", params.shard_bits);
        assert_ne!(params.epoch_seed, [0u8; 32], "epoch_seed must be real entropy, not zeros");

        // /oli_table — EXACTLY one fixed-size table from the index `/oli_params` describes (`fetch_table`
        // refuses any other length, so a short reply cannot read as "no entry here").
        let (bits, table) = fetch_table(&agent, &url, 0).expect("live /oli_table must answer");
        assert_eq!(bits, params.shard_bits, "the table comes from the same index /oli_params describes");
        assert_eq!(table.len(), (oli::SHARD_BUCKETS as usize) * oli::BUCKET_BYTES, "the fixed table shape");

        // A full locate() over whole tables. This wallet's seed has no notes on that chain, so the CORRECT
        // answer is no hits — an index that answered yes to an unknown locator would be handing out other
        // people's notes.
        let loc_sk = oli::derive_loc_sk(blake3::hash(b"MUSD/oli-client/live-test/unfunded-seed").as_bytes());
        let mut tables =
            ShardTables::new(params.shard_bits, *blake3::hash(b"MUSD/oli-client/live-test/secret").as_bytes());
        let found = locate(&agent, &url, &mut tables, &loc_sk, "chg", 0, 4)
            .expect("the whole-table locate must complete against a live node");
        assert!(found.is_empty(), "an unknown wallet's locators must resolve to NOTHING, got {found:?}");
        println!(
            "[oli-live] shard_bits={} — 4 locators (8 keys) matched against {} whole table(s) fetched in {} \
             wave(s) from {url}, 0 false hits",
            params.shard_bits,
            tables.held(),
            tables.waves()
        );
    }

    /// LIVE WIRE AUDIT (DB-228) — judges what a REAL wallet actually sent a REAL node, the way that node can
    /// judge it. Put a logging proxy in front of the wallet's node, let a wallet restore through it, then
    /// point this at the node and the proxy's JSONL log. Every `/get_my_pq_notes` batch in the log is
    /// classified with the node's own knowledge: does an id resolve in its ORDINAL space (0..=record_top), and
    /// is the `(id, slot)` an entry of its served tables — every one a real tagged note since DB-235 deleted the
    /// chaff. Any other position is one the node can separate, so the audit FAILS and names the counts.
    /// TWO-PARTY-REVIEWED: two independent processes are the parties — the `wallet-harness` process that
    /// SENT the logged batches (through the proxy, over real HTTP) and the `usdmd-node` process whose own
    /// served tables and ordinal range judge them; this test is the observer that reads one party's effect
    /// on the wire against the other party's state, and a second node is audited by pointing it there.
    ///   `MONEROUSD_OLI_TEST_URL=http://127.0.0.1:47891 MONEROUSD_DB228_WIRE_LOG=/path/wire.jsonl
    ///    cargo test --release db228_live_wire_audit -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE audit of a real node + a real wire log, not a disabled assertion — it FAILS (never skips) on any separable position or an empty log.
    fn db228_live_wire_audit_every_batched_position_is_a_real_index_entry_in_one_space() {
        let url = std::env::var("MONEROUSD_OLI_TEST_URL").expect("set MONEROUSD_OLI_TEST_URL to the audited node");
        let log = std::env::var("MONEROUSD_DB228_WIRE_LOG").expect("set MONEROUSD_DB228_WIRE_LOG to the proxy's JSONL");
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(60)).build();
        let params = fetch_params(&agent, &url).expect("/oli_params");
        let info: serde_json::Value = agent
            .get(&format!("{url}/get_info"))
            .call()
            .expect("/get_info")
            .into_json()
            .expect("/get_info json");
        let record_top = info["record_top"].as_u64().expect("/get_info record_top");
        let mut entries: std::collections::HashSet<(u64, u8)> = std::collections::HashSet::new();
        for sid in 0..(1u64 << params.shard_bits) {
            let (bits, t) = fetch_table(&agent, &url, sid).expect("/oli_table");
            assert_eq!(bits, params.shard_bits, "every table from the epoch /oli_params describes");
            entries.extend(oli::table_positions(&t));
        }
        let mut batches = 0usize;
        let mut failures: Vec<String> = Vec::new();
        for line in std::fs::read_to_string(&log).expect("read the wire log").lines() {
            let v: serde_json::Value = serde_json::from_str(line).expect("one JSON object per log line");
            if v["path"].as_str() != Some("/get_my_pq_notes") {
                continue;
            }
            let Some(body) = v["body"].as_str() else { continue };
            let b: serde_json::Value = serde_json::from_str(body).expect("the logged request body is JSON");
            let Some(pos) = b.get("positions").and_then(|p| p.as_array()) else { continue };
            batches += 1;
            let (mut ordinal, mut not_entry) = (0usize, 0usize);
            for p in pos {
                let id = p["id"].as_u64().expect("every position names an id");
                let slot = p["slot"].as_u64().expect("every position names a slot") as u8;
                if id <= record_top {
                    ordinal += 1;
                }
                if !entries.contains(&(id, slot)) {
                    not_entry += 1;
                }
            }
            println!(
                "[db228-wire] batch {batches}: {} position(s) — in the node's ORDINAL space {ordinal}, not an \
                 index entry {not_entry}; the node's index holds {} real entr(ies)",
                pos.len(),
                entries.len()
            );
            if (ordinal, not_entry) != (0, 0) {
                failures.push(format!("batch {batches}: ordinal {ordinal} / not-an-entry {not_entry}"));
            }
        }
        assert!(batches > 0, "the wire log holds no batched fetch — the audit had nothing to judge");
        assert!(
            failures.is_empty(),
            "DB-228: {} of {batches} batch(es) carry positions the serving node can separate from the wallet's \
             own: {}",
            failures.len(),
            failures.join("; ")
        );
    }

    /// ⛔ DB-239 LIVE MEASUREMENT — can a client that holds NO key read how many REAL notes a record carries? The
    /// 256-slot cover exists to hide exactly that (activity/volume metadata). The OWNER's keys are used for ONE
    /// thing only — to pick records KNOWN to hold a real note (its own entries in the served index), so the
    /// measurement cannot be vacuous — and then everything else is done the way a stranger can: the PEER's
    /// slotless by-record-id fetch returns the record's 256 assembled units, the PUBLIC
    /// `cover::strip_fixed_note_payload_det` peels the fill off, and what is left is the real count. (Blocks and
    /// relayed `PqTx`s additionally carry sent outputs in the clear; `/applied_notes_from` serves them by height.)
    /// This pin states the property the cover is FOR — no key-less client learns a record's real count — and FAILS
    /// today, printing what the strip recovered: the fill is regenerable by every node by design, so a serve-side
    /// change cannot make it pass (DB-239). It is VACUOUS (and fails) if the owner finds no record.
    /// TWO-PARTY-REVIEWED: the producer node serves the index the owner reads; the PEER node (which never produced
    /// the records) serves the records the strip reads — "every node holds the count" is measured, not inferred.
    ///   `MONEROUSD_OLI_TEST_URL=http://127.0.0.1:47891 MONEROUSD_OLI_PEER_URL=http://127.0.0.1:47892
    ///    MONEROUSD_DB235_SEED="<24 words>" cargo test --release db239_live -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE measurement of an OPEN leak, not a disabled assertion — it FAILS today and names every recovered count; it fails as VACUOUS if no record known to hold a real note is found; it passes only once no key-less client can read a record's real count.
    fn db239_live_a_client_cannot_read_a_records_real_note_count() {
        let url = std::env::var("MONEROUSD_OLI_TEST_URL").expect("set MONEROUSD_OLI_TEST_URL to the producing node");
        let peer = std::env::var("MONEROUSD_OLI_PEER_URL").expect("set MONEROUSD_OLI_PEER_URL to the ingesting peer");
        let seed = std::env::var("MONEROUSD_DB235_SEED").expect("set MONEROUSD_DB235_SEED to a paid wallet's seed");
        let wallet = crate::pq::restore(&seed).expect("the seed restores");
        let mut keys: Vec<[u8; oli::K_BYTES]> = vec![key_for_v2(&wallet.loc_sk, "chg", 0)];
        for j in 0..4u64 {
            keys.push(key_for_v2(&wallet.loc_sk, "recv", j));
            keys.push(key_for(&wallet.loc_sk, "recv", j));
        }
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(120)).build();
        let params_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let params = loop {
            match fetch_params(&agent, &url) {
                Ok(p) => break p,
                Err(e) if e.contains("503") && std::time::Instant::now() < params_deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(500))
                }
                Err(e) => panic!("/oli_params never answered: {e}"),
            }
        };
        // Records KNOWN to hold a real note: the owner's own entries in the served index. NOT-AN-ADDRESS (DB-223
        // Q2 §11 (a)): an entry names its record by FOLD ORDINAL.
        let mut known: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for k in &keys {
            let (_, t) = fetch_table(&agent, &url, oli::shard_of(k, params.shard_bits)).expect("/oli_table");
            known.extend(oli::table_candidates(&t, k).into_iter().map(|(ordinal, _)| ordinal));
        }
        assert!(!known.is_empty(), "VACUOUS: the owner found none of its records in the served index — nothing to measure");
        let w = usdmd_node::cover::PQ_NOTE_BYTES;
        let mut read = 0usize;
        for ordinal in &known {
            // Everything from here on is what a key-less stranger can do, against the PEER: one whole-record ask by
            // ordinal. The strip is keyed by the RECORD ADDRESS the reply names — stripping under the ordinal would
            // recover nothing and pass this audit vacuously, so a reply naming no address FAILS it.
            let rec: serde_json::Value = agent
                .post(&format!("{peer}/da_record"))
                .send_json(serde_json::json!({ "ordinal": ordinal }))
                .expect("whole-record fetch by ordinal on the peer")
                .into_json()
                .expect("json");
            let addr = rec["record_addr"]
                .as_u64()
                .unwrap_or_else(|| panic!("the peer named no record address for located ordinal {ordinal}: {rec}"));
            let payload = hex::decode(rec["notes_hex"].as_str().expect("notes_hex")).expect("hex record");
            // §20.2: a key-less client holds the one public key (the idle key) and nothing else — the strip is the one it can run.
            let stripped = usdmd_node::cover::strip_fixed_note_payload(&payload, addr, &usdmd_node::cover::idle_cover_key(addr)).map(|r| r.len() / w);
            if matches!(stripped, Some(k) if k > 0) {
                read += 1;
            }
            println!(
                "[db239] record {addr} (ordinal {ordinal}): the peer served {} unit(s) ({} B) to a key-less ask; the \
                 public strip recovered {stripped:?} real note(s)",
                payload.len() / w,
                payload.len()
            );
        }
        println!("[db239] {} record(s) known to hold a real note; the strip read the real count of {read}", known.len());
        assert_eq!(
            read, 0,
            "DB-239: a key-less client read the real note count of {read} of {} record(s) by stripping the served \
             cover — the constant shape hides no activity",
            known.len()
        );
    }

    /// LIVE TABLE AUDIT (DB-235) — can a reader of the SERVED tables link one wallet's payments that share an
    /// index key? Two payments to ONE address (or two change notes — every change is tagged at `("chg", 0)`) leave
    /// two entries under ONE key `K`. Given that wallet's seed, this derives its keys (receive indices 0..4 in both
    /// tag forms, and the change key), downloads every shard table the node serves, and judges the entries with the
    /// bytes alone, the way a reader holding NO key sees them:
    ///   * no entry's fingerprint may be one of those keys' own prefix (the pre-DB-235 format published exactly that);
    ///   * no fingerprint may repeat anywhere in the served index (same-key entries shared one before DB-235);
    /// then, as the OWNER, it requires one key to find at least two entries — the pair a reader must not link.
    /// The byte checks run FIRST and need no matcher, so the pre-DB-235 node fails them on linkage, not format.
    /// TWO-PARTY-REVIEWED: the parties are the wallet whose address was paid twice and the usdmd-node process that
    /// built and serves the tables; the audit is pointed at each node of the pair in turn.
    ///   `MONEROUSD_OLI_TEST_URL=http://127.0.0.1:47891 MONEROUSD_DB235_SEED="<24 words>"
    ///    cargo test --release db235_live_table_audit -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE audit of a real node's served tables, not a disabled assertion — it FAILS (never skips) on a key-prefix fingerprint, a repeated fingerprint, or no key holding two entries.
    fn db235_live_table_audit_two_payments_under_one_key_are_unlinkable_in_the_served_tables() {
        let url = std::env::var("MONEROUSD_OLI_TEST_URL").expect("set MONEROUSD_OLI_TEST_URL to the audited node");
        let seed = std::env::var("MONEROUSD_DB235_SEED").expect("set MONEROUSD_DB235_SEED to the paid wallet's seed");
        let wallet = crate::pq::restore(&seed).expect("the seed restores");
        let mut keys: Vec<(String, [u8; oli::K_BYTES])> = vec![("chg/0 v2".into(), key_for_v2(&wallet.loc_sk, "chg", 0))];
        for j in 0..4u64 {
            keys.push((format!("recv/{j} v2"), key_for_v2(&wallet.loc_sk, "recv", j)));
            keys.push((format!("recv/{j} v1"), key_for(&wallet.loc_sk, "recv", j)));
        }
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(120)).build();
        // DB-107: an epoch's index is built off the runtime lock and `/oli_params` answers 503 BUILDING until it
        // lands — ask again on wall-clock exactly as the production client does; any other error still fails.
        let params_deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
        let params = loop {
            match fetch_params(&agent, &url) {
                Ok(p) => break p,
                Err(e) if e.contains("503") && std::time::Instant::now() < params_deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(500))
                }
                Err(e) => panic!("/oli_params never answered: {e}"),
            }
        };
        let mut fp_count: std::collections::HashMap<[u8; 7], usize> = std::collections::HashMap::new();
        let mut key_prefix_entries = 0usize;
        let mut entries = 0usize;
        let mut owner_found: Vec<(String, Vec<(u64, u8)>)> = Vec::new();
        for sid in 0..(1u64 << params.shard_bits) {
            let (bits, t) = fetch_table(&agent, &url, sid).expect("/oli_table");
            assert_eq!(bits, params.shard_bits, "every table from the epoch /oli_params describes");
            for e in t.chunks_exact(oli::ENTRY_BYTES) {
                if let Some((fp, _, _)) = oli::unpack_entry(e) {
                    entries += 1;
                    *fp_count.entry(fp).or_insert(0) += 1;
                    if keys.iter().any(|(_, k)| fp[..] == k[..7]) {
                        key_prefix_entries += 1;
                    }
                }
            }
            for (name, k) in &keys {
                if sid == oli::shard_of(k, params.shard_bits) {
                    let found = oli::table_candidates(&t, k);
                    if !found.is_empty() {
                        owner_found.push((name.clone(), found));
                    }
                }
            }
        }
        let repeated: usize = fp_count.values().filter(|n| **n > 1).map(|n| *n).sum();
        let most = owner_found.iter().map(|(_, f)| f.len()).max().map_or(0, |m| m);
        println!(
            "[db235-table] {entries} served entr(ies) across {} shard(s); {key_prefix_entries} carry one of this \
             wallet's keys' own prefix; {repeated} sit in a repeated fingerprint; the owner's keys find {owner_found:?}",
            1u64 << params.shard_bits
        );
        assert!(entries > 0, "the node served an empty index — nothing to judge");
        assert_eq!(
            key_prefix_entries, 0,
            "DB-235: {key_prefix_entries} served entr(ies) publish one of this wallet's keys' own prefix — any reader \
             clusters every payment under that key without holding it"
        );
        assert_eq!(
            repeated, 0,
            "DB-235: {repeated} served entr(ies) share a fingerprint with another — same-key payments are linkable \
             by the bytes alone"
        );
        assert!(most >= 2, "one key must hold the two payments made to one address — the owner found {owner_found:?}");
    }

    /// LIVE WIRE AUDIT (DB-238) — does any OTHER request in the pass name, on its own, a member of the set the
    /// batched note fetch hid its reals in? The set S is read off the log (every `/get_my_pq_notes` batch); the
    /// members' commitments are learned the way the SERVING NODE would learn them — by fetching S from it. Then
    /// every logged request is classified: a commitment of S named by `/get_note_clues`, `/note_ordinal_by_cm`
    /// or `/note_copath`, a position of S named individually by `/note_copath`, or a single by-record-id fetch of
    /// an S record (SLOTLESS = the whole 256-unit record). The whole table is printed.
    ///
    /// It FAILS on every row DB-238 / DB-238b / DB-238c closed: a `/get_note_clues` ask, a copath capture ask, and
    /// the per-note witness SWEEP's two asks — the leaf-index `/note_copath {cms_hex}` and the SLOTLESS whole-record
    /// fetch (DB-238c deleted the sweep with the witness book it fed; no live spend reads a Merkle path). The rows
    /// still open are measured and attributed, not asserted: the account-bucket fetch and its by-commitment ordinal
    /// (DB-88: the node already holds commitment↔bucket from `account_targets`) and the spend-time carrier build
    /// (DB-223: the spend itself names its input's record — it rides the SEND proxy's log, not this one). An
    /// assertion that those are zero would be one the current architecture cannot meet, and claiming it would be
    /// the narrowing this audit exists to stop.
    /// A malformed logged body FAILS the audit; a request that carries no such field names nothing.
    /// TWO-PARTY-REVIEWED: the parties are the `wallet-harness` process that SENT the logged requests (through the
    /// proxy, over real HTTP) and the `usdmd-node` process whose own serve reveals what each named position holds;
    /// this test is the observer reading one party's wire against the other party's state.
    ///   `MONEROUSD_OLI_TEST_URL=http://127.0.0.1:47891 MONEROUSD_DB238_WIRE_LOG=/path/wire.jsonl
    ///    cargo test --release db238_live_wire_audit -- --ignored --nocapture`
    #[test]
    #[ignore] // CORRECT-ARCHITECTURE-REVIEWED: opt-in LIVE audit of a real node + a real wire log, not a disabled assertion — it FAILS (never skips) on a clue ask naming a member of the set, a log with no batch, or a set the node will not serve.
    fn db238_live_wire_audit_no_clue_ask_names_a_member_of_the_batched_set() {
        let url = std::env::var("MONEROUSD_OLI_TEST_URL").expect("set MONEROUSD_OLI_TEST_URL to the audited node");
        let log = std::env::var("MONEROUSD_DB238_WIRE_LOG").expect("set MONEROUSD_DB238_WIRE_LOG to the proxy's JSONL");
        let agent = ureq::AgentBuilder::new().timeout(std::time::Duration::from_secs(120)).build();
        let lines: Vec<serde_json::Value> = std::fs::read_to_string(&log)
            .expect("read the wire log")
            .lines()
            .map(|l| serde_json::from_str(l).expect("one JSON object per log line"))
            .collect();
        let body_of = |v: &serde_json::Value| -> Option<serde_json::Value> {
            match v["body"].as_str() {
                None | Some("") => None, // a bodiless request (a GET) names nothing
                Some(b) => Some(serde_json::from_str(b).expect("a logged non-empty request body is JSON")),
            }
        };
        // S — every position any batched fetch in the log named.
        let mut set: std::collections::BTreeSet<(u64, u8)> = std::collections::BTreeSet::new();
        for v in &lines {
            if v["path"].as_str() != Some("/get_my_pq_notes") {
                continue;
            }
            let Some(b) = body_of(v) else { continue };
            let Some(pos) = b.get("positions").and_then(|p| p.as_array()) else { continue };
            for p in pos {
                set.insert((
                    p["id"].as_u64().expect("every batched position names an id"),
                    p["slot"].as_u64().expect("every batched position names a slot") as u8,
                ));
            }
        }
        assert!(!set.is_empty(), "the wire log holds no batched fetch — the audit had nothing to judge");
        // What each member IS, learned exactly as the serving node can: ask it for S.
        let want: Vec<(u64, u8)> = set.iter().copied().collect();
        let reply: serde_json::Value = agent
            .post(&format!("{url}/get_my_pq_notes"))
            .send_json(crate::pq_notes_batched_request(&want))
            .expect("the node serves the batched set")
            .into_json()
            .expect("batched reply json");
        let mut recs: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut placed: Vec<([u8; 32], (u64, u8))> = Vec::new();
        crate::file_batched_note_reply(&reply, &|_, _| true, &mut recs, &mut placed);
        let member_cms: std::collections::HashSet<[u8; 32]> = placed.iter().map(|(cm, _)| *cm).collect();
        let member_ids: std::collections::HashSet<u64> = set.iter().map(|(id, _)| *id).collect();
        assert!(!member_cms.is_empty(), "the node served none of the set's notes — nothing to classify against");
        let cms_named = |b: &serde_json::Value| -> usize {
            match b.get("cms_hex").and_then(|h| h.as_str()) {
                None => 0,
                Some(h) => hex::decode(h)
                    .expect("a logged cms_hex is hex")
                    .chunks_exact(32)
                    .filter(|c| member_cms.contains(&<[u8; 32]>::try_from(*c).expect("a 32-byte commitment")))
                    .count(),
            }
        };
        let mut rows: std::collections::BTreeMap<&str, (usize, usize)> = std::collections::BTreeMap::new();
        for v in &lines {
            let Some(path) = v["path"].as_str() else { continue };
            let Some(b) = body_of(v) else { continue };
            let (label, named) = match path {
                "/get_note_clues" => ("clue ask naming a member's commitment [DB-238]", cms_named(&b)),
                "/note_ordinal_by_cm" => ("ordinal-by-commitment naming a member", cms_named(&b)),
                "/note_copath" => {
                    let asked: Vec<(u64, u8)> = match b.get("positions_hex").and_then(|h| h.as_str()) {
                        None => Vec::new(),
                        Some(h) => hex::decode(h)
                            .expect("a logged positions_hex is hex")
                            .chunks_exact(9)
                            .map(|c| (u64::from_le_bytes(c[..8].try_into().expect("8 bytes")), c[8]))
                            .collect(),
                    };
                    let lone = if asked.len() < set.len() { asked.iter().filter(|p| set.contains(p)).count() } else { 0 };
                    if asked.is_empty() {
                        // the witness sweep's leaf-index ask (`cms_hex` only) — DB-238c deleted the sweep
                        ("copath leaf-index ask naming a member's commitment (witness sweep)", cms_named(&b))
                    } else {
                        // a position AND a commitment: the receive-capture / freeze shape DB-238b deleted (a
                        // detect pass never builds a spend carrier — that ask rides the SEND proxy's log)
                        ("copath capture ask naming a member by position/commitment [DB-238b]", cms_named(&b) + lone)
                    }
                }
                "/get_my_pq_notes" if b.get("positions").is_none() => {
                    let hit = match b.get("from_height").and_then(|h| h.as_u64()) {
                        Some(id) => member_ids.contains(&id) as usize,
                        None => 0,
                    };
                    if b.get("slot").is_none() {
                        ("SLOTLESS whole-record fetch of a member's record", hit)
                    } else {
                        ("single-slot fetch in a member's record", hit)
                    }
                }
                _ => continue,
            };
            let e = rows.entry(label).or_insert((0, 0));
            e.0 += 1;
            e.1 += (named > 0) as usize;
        }
        println!("[db238-wire] batched set: {} position(s), {} member commitment(s)", set.len(), member_cms.len());
        for (label, (asks, naming)) in &rows {
            println!("[db238-wire] {label}: {naming} of {asks} ask(s) name a member");
        }
        let naming_in = |label: &str| -> usize {
            match rows.get(label) {
                Some((_, naming)) => *naming,
                None => 0,
            }
        };
        let clue_leaks = naming_in("clue ask naming a member's commitment [DB-238]");
        let capture_leaks = naming_in("copath capture ask naming a member by position/commitment [DB-238b]");
        let sweep_leaf_leaks = naming_in("copath leaf-index ask naming a member's commitment (witness sweep)");
        let sweep_record_leaks = naming_in("SLOTLESS whole-record fetch of a member's record");
        assert_eq!(
            (clue_leaks, capture_leaks, sweep_leaf_leaks, sweep_record_leaks),
            (0, 0, 0, 0),
            "DB-238/238b/238c: {clue_leaks} `/get_note_clues` ask(s), {capture_leaks} copath capture ask(s), \
             {sweep_leaf_leaks} witness-sweep leaf-index ask(s) and {sweep_record_leaks} whole-record fetch(es) \
             named a member of the batched set — each one hands the serving node a note the cover was hiding"
        );
    }

    /// DB-228 — the SHARD-FETCH SHAPE is not a function of the wallet's keys. An index of `WAVE_SHARDS`
    /// shards or fewer is fetched WHOLE in the first wave (every wallet sends the same request); a larger one
    /// in waves of exactly `WAVE_SHARDS` new shards — the needed ones plus keyed decoys, reproducible for this
    /// wallet (so passes do not churn) and different under another wallet's secret.
    #[test]
    fn db228_a_small_index_is_fetched_whole_and_a_large_one_in_constant_keyed_waves() {
        let small = ShardTables::new(3, [1u8; 32]);
        assert_eq!(small.next_wave(&[5]), (0..8).collect::<Vec<u64>>(), "8 shards: the whole index, whatever is needed");
        assert_eq!(small.next_wave(&[]), (0..8).collect::<Vec<u64>>(), "…and the same set when nothing is needed");

        let mut big = ShardTables::new(10, [1u8; 32]);
        let w1 = big.next_wave(&[3, 900]);
        assert_eq!(w1.len(), oli::WAVE_SHARDS, "a wave is always exactly WAVE_SHARDS shards");
        assert!(w1.contains(&3) && w1.contains(&900), "every needed shard rides the wave");
        assert!(w1.windows(2).all(|p| p[0] < p[1]), "ascending on the wire — order carries nothing");
        assert_eq!(big.next_wave(&[3, 900]), w1, "reproducible for this wallet: passes do not churn");
        let other = ShardTables::new(10, [2u8; 32]).next_wave(&[3, 900]);
        assert_ne!(other, w1, "decoys are keyed on the wallet secret, never a public function of the needed set");
        for sid in &w1 {
            big.hold_for_test(*sid, vec![0u8; (oli::SHARD_BUCKETS as usize) * oli::BUCKET_BYTES]);
        }
        big.waves += 1;
        let w2 = big.next_wave(&[3, 17]);
        assert_eq!(w2.len(), oli::WAVE_SHARDS, "the next wave is the same shape");
        assert!(w2.contains(&17) && !w2.contains(&3), "held shards are never fetched again");
        assert!(w2.iter().all(|s| !w1.contains(s)), "a wave holds only shards this pass does not hold yet");
    }

    /// DB-228 — locating from held whole tables finds EVERY note of the wallet's keys (both tag forms), and
    /// the pool the batched fetch draws cover from contains every located real. No node in the loop: the tables
    /// are the ones a node's own `Index::build` produces.
    #[test]
    fn db228_locate_over_whole_tables_finds_every_note_and_the_cover_pool_holds_them() {
        let loc_sk = oli::derive_loc_sk(blake3::hash(b"MUSD/oli-client/db228/wallet").as_bytes());
        let mut klog: Vec<(u64, u8, [u8; oli::K_BYTES])> = vec![
            (290_000_000_000_000_001, 0, key_for_v2(&loc_sk, "recv", 0)),
            (290_000_000_000_000_777, 1, key_for(&loc_sk, "recv", 1)),
        ];
        for i in 0..300u64 {
            let other = oli::index_key(blake3::hash(&i.to_le_bytes()).as_bytes());
            klog.push((291_000_000_000_000_000 + i * 13, (i % 2) as u8, other));
        }
        let idx = oli::Index::build(&klog, &[0u8; 32], 0, u64::MAX, 1, [4u8; 32]);
        let mut tables = ShardTables::new(idx.shard_bits, [9u8; 32]);
        for sid in 0..(1u64 << idx.shard_bits) {
            tables.hold_for_test(sid, idx.shard_table(sid).into_owned());
        }
        let agent = ureq::AgentBuilder::new().build(); // never used: every shard is already held
        let found = locate(&agent, "http://127.0.0.1:9", &mut tables, &loc_sk, "recv", 0, 2)
            .expect("locate over held tables needs no node");
        let got: Vec<(u64, u8)> = found.iter().map(|l| (l.ordinal, l.slot)).collect();
        assert_eq!(
            got,
            vec![(290_000_000_000_000_001, 0), (290_000_000_000_000_777, 1)],
            "both of the wallet's notes, one per tag form"
        );
        let pool = tables.positions();
        assert_eq!(pool.len(), klog.len(), "the pool is every real entry, and the index holds nothing else (DB-235)");
        for p in &got {
            assert!(pool.contains(p), "every located real sits in the cover pool: reals and cover share one universe");
        }
    }

    /// THE RECEIVED-NOTE PATH, end to end across the sender/recipient boundary. A payer holding ONLY the
    /// recipient's address must be able to tag the note so the recipient can later look it up from its
    /// seed alone. This walks that exact handoff — address → locator → tag → index key — and checks the
    /// two sides land on the same key, which is the thing that silently breaks if either side changes.
    #[test]
    fn a_payer_tags_a_received_note_from_the_address_and_the_recipient_can_find_it() {
        // RECIPIENT: a real wallet, and the address it hands out.
        let phrase_entropy = *blake3::hash(b"MUSD/oli-client/test/recv-wallet").as_bytes();
        let keys = crate::pq::derive_keys(&phrase_entropy);

        // PAYER: sees only the address string. Parses it and finds the locator it carries.
        let parsed = usdmd_node::address::parse_address_full(&keys.address)
            .expect("a wallet's own address must parse");
        let locator = parsed.locator.expect("a v2 address carries the locator a payer needs");
        assert_eq!(parsed.b, keys.b, "the payer reads the right spend tag");
        assert_eq!(parsed.mlkem, keys.scan_ek, "and the right ML-KEM key to seal to");

        // PAYER tags the note with it; the NODE turns that tag into the slot's index key.
        let tag_on_the_wire = oli::tag_clue_bytes(&locator);
        let node_k = oli::index_key(&tag_on_the_wire);

        // RECIPIENT, from the seed alone, derives the SAME key and so can look the note up.
        let recipient_k = key_for(&keys.loc_sk, "recv", 0);
        assert_eq!(recipient_k, node_k, "payer-tagged key must equal what the recipient enumerates");

        // A DIFFERENT wallet's address yields a different locator — no cross-wallet collision, and no
        // observer can derive one wallet's key from another's address.
        let other = crate::pq::derive_keys(blake3::hash(b"MUSD/oli-client/test/other-wallet").as_bytes());
        let other_loc = usdmd_node::address::parse_address_full(&other.address)
            .expect("parse")
            .locator
            .expect("v2");
        assert_ne!(other_loc, locator, "two wallets never hand out the same locator");
        assert_ne!(oli::index_key(&oli::tag_clue_bytes(&other_loc)), node_k);

        // The tag a payer puts on the wire reveals nothing usable: it is non-pertinent chaff to every
        // real detection key, so it cannot be used to single this note out.
        let clue = crate::omr::Clue::from_bytes(&tag_on_the_wire).expect("tag parses as a clue");
        assert!(!crate::omr::is_pertinent(&other.clue_sk, &clue), "a stranger's clue key sees only chaff");
    }

    /// Address reuse must not lose money. One address hands out ONE locator, so every note paid to a
    /// reused address shares an index key and lands in the same two buckets. Returning only the first
    /// match would leave every later payment invisible at restore — on-chain, owned, and unfindable.
    #[test]
    fn several_notes_paid_to_one_reused_address_are_all_found() {
        use usdmd_node::cover::BLOCK_FIXED_NOTE_COUNT;
        let keys = crate::pq::derive_keys(blake3::hash(b"MUSD/oli-client/test/reused-addr").as_bytes());
        let locator = usdmd_node::address::parse_address_full(&keys.address).unwrap().locator.unwrap();
        let k = oli::index_key(&oli::tag_clue_bytes(&locator));

        // Five payments to that one address, landing in five different blocks — all sharing its key.
        let payments: Vec<([u8; oli::K_BYTES], u64, u8)> =
            (0..5u64).map(|i| (k, i * 7 + 1, (i as u8) * 13)).collect();
        // Built alongside a block's worth of other wallets' tagged notes, so the reused key is placed under a
        // realistic load rather than into an empty table.
        let others: Vec<([u8; oli::K_BYTES], u64, u8)> = (0..BLOCK_FIXED_NOTE_COUNT as u64)
            .map(|i| (oli::index_key(&(77_000 + i).to_le_bytes()), 500 + i, (i % 7) as u8))
            .collect();
        let mut entries = payments.clone();
        entries.extend(others);
        let table = oli::build_shard(&entries).expect("the payments and the other notes fit one shard");

        let (b1, b2) = oli::bucket_choices(&k, oli::SHARD_BUCKETS);
        let grab = |b: u64| -> [u8; oli::BUCKET_BYTES] {
            let off = (b as usize) * oli::BUCKET_BYTES;
            table[off..off + oli::BUCKET_BYTES].try_into().unwrap()
        };
        let hits = oli::probe_candidates(&grab(b1), &grab(b2), &k);
        assert_eq!(hits.len(), payments.len(), "every payment to the reused address is found, got {hits:?}");
    }

    /// A PUBLISHED address must never carry a locator. A @username is a directory anyone can read; if the
    /// address it resolves to carried a locator, any observer could derive that locator's index key and
    /// ask the index for the exact block and slot of EVERY payment ever made to the handle — a linkage
    /// and timing oracle on a public name, and a straight regression on today's behaviour where a handle
    /// reveals nothing about which notes are its owner's. So `handle_address` is the locator-free form,
    /// and it is what registration publishes.
    #[test]
    fn a_published_handle_address_carries_no_locator_while_the_rotating_one_does() {
        let keys = crate::pq::derive_keys(blake3::hash(b"MUSD/oli-client/test/handle-privacy").as_bytes());

        let handle = usdmd_node::address::parse_address_full(&keys.handle_address)
            .expect("the published address must still parse");
        assert!(handle.locator.is_none(), "a PUBLISHED address must not leak a locator");
        assert_eq!(handle.b, keys.b, "it is still this wallet — same spend tag");
        assert_eq!(handle.mlkem, keys.scan_ek, "and still seals to the same ML-KEM key");

        let rotating = usdmd_node::address::parse_address_full(&keys.address).expect("parse");
        assert!(rotating.locator.is_some(), "the per-payer address DOES carry one");
        assert_ne!(keys.handle_address, keys.address, "the two forms are distinct addresses");
        // Both reach the same wallet: a payment by handle is received exactly as before, just found by
        // the ordinary scan rather than by lookup.
        assert_eq!(rotating.b, handle.b);
        assert_eq!(rotating.mlkem, handle.mlkem);
    }

    /// Rotation hands each payer a DIFFERENT locator. Reusing one address across payers would let each of
    /// them recognise the others' payments in the index; rotating keeps that to the one payer who already
    /// knows about their own payment. Every rotated address must still be the same wallet.
    #[test]
    fn rotating_receive_addresses_give_each_payer_a_distinct_locator() {
        let keys = crate::pq::derive_keys(blake3::hash(b"MUSD/oli-client/test/rotation").as_bytes());
        let mut seen_locators = Vec::new();
        let mut seen_keys = Vec::new();
        for j in 0..6u64 {
            let addr = crate::pq::receive_address(&keys.b, &keys.scan_ek, &keys.note_spk, &keys.loc_sk, j).expect("encode");
            let p = usdmd_node::address::parse_address_full(&addr).expect("parse");
            let loc = p.locator.expect("every rotated address carries its locator");
            assert_eq!(p.b, keys.b, "rotation never changes which wallet is paid");
            assert_eq!(p.mlkem, keys.scan_ek, "nor which key the note is sealed to");
            assert_eq!(p.spk, Some(keys.note_spk), "nor the spend key it commits to (DB-395)");
            // The recipient enumerates this exact index from its seed.
            assert_eq!(oli::index_key(&oli::tag_clue_bytes(&loc)), key_for(&keys.loc_sk, "recv", j));
            seen_locators.push(loc);
            seen_keys.push(key_for(&keys.loc_sk, "recv", j));
        }
        let mut u = seen_locators.clone();
        u.sort();
        u.dedup();
        assert_eq!(u.len(), seen_locators.len(), "every rotated address has a DISTINCT locator");
        let mut uk = seen_keys.clone();
        uk.sort();
        uk.dedup();
        assert_eq!(uk.len(), seen_keys.len(), "and a distinct index key, so payers cannot see each other");
    }

    /// A restored wallet re-derives the identical locator stream from the phrase alone — the property the
    /// whole cold-restore path rests on.
    #[test]
    fn the_locator_stream_reproduces_from_the_seed() {
        let entropy = *blake3::hash(b"MUSD/oli-client/test/restore").as_bytes();
        let first: Vec<[u8; oli::K_BYTES]> =
            (0..8).map(|j| key_for(&oli::derive_loc_sk(&entropy), "recv", j)).collect();
        let after_restore: Vec<[u8; oli::K_BYTES]> =
            (0..8).map(|j| key_for(&oli::derive_loc_sk(&entropy), "recv", j)).collect();
        assert_eq!(first, after_restore, "the same phrase yields the same locators forever");
        assert_eq!(first.len(), 8);
        // And they are all distinct — a repeated locator would collapse two notes into one index entry.
        let mut uniq = first.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), first.len(), "every locator index yields a distinct key");
    }
}
