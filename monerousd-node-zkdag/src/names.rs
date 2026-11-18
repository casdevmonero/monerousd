// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⛔ RETIRED AS AN AUTHORITY (audit F9, 2026-11-10). No node resolves a name from this registry any more, no wire
//! frame writes it and no boot opens it: first-come here was ARRIVAL order on each node, so one name could have two
//! owners and the first peer to reach a fresh node owned every name on it. A `@name` is a chain directory entry
//! ([`crate::directory`]). What is still live in this file: [`canon_name`] (the `.mud` host rule reads it) and
//! [`parse_registry_bytes`] (the decode-door corpus). The registry type stays only so the pin
//! `a_peers_gossip_names_nobody` can show that the claim it sends is one this registry would have adopted.
//!
//! The text below describes the retired design.
//!
//! Authenticated @username registry — a name maps to a confidential PQ receive address, owner-bound. First
//! registration is permissionless (first-come); an existing name may only be re-pointed / transferred by its
//! CURRENT owner (owner-continuity), exactly like the sovereign-site registry ([`crate::site`]). The address a
//! name resolves to is an OPT-IN public payment handle — the payments TO it stay confidential (each lands as a
//! PQ stealth note only the recipient's scan key can detect). Registration is authenticated by an ML-DSA-65
//! signature over [`crate::pqauth::name_register_msg`]; the owner id IS `H(pubkey)`, so no one can claim or
//! transfer a name they do not hold the key for.
use std::collections::HashMap;

/// CANONICAL @username form — the ONE normalization every register + resolve funnels through, so a name is
/// CASE-INSENSITIVE and the leading `@` is optional: `@Flame`, `flame`, `fLame`, `FLAME` all map to the SAME
/// owner. This is what makes payments fool-proof (you can't be tricked into paying a look-alike) AND closes the
/// squat where a fraudster claims `flaMe` to bypass the uniqueness of `Flame` — they canonicalize to the identical
/// key, so first-come on the canonical form wins. Enforced at CONSENSUS (here + `register_name`), not just the UI,
/// so a raw RPC/gossip cannot bypass it. Trim → strip a leading `@` → trim again → ASCII-lowercase.
pub fn canon_name(name: &str) -> String {
    name.trim()
        .trim_start_matches('@')
        .trim()
        .to_ascii_lowercase()
}

/// A registered name's record: the address it resolves to + the ML-DSA-key-hash of its owner.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct NameRecord {
    /// The cnBase58 PQ receive address `@name` resolves to (a public opt-in handle; payments stay confidential).
    pub address: String,
    /// `H(owner ML-DSA pubkey)` — only this key can update / transfer the name (owner-continuity).
    pub owner: [u8; 32],
    /// The owner's ML-DSA PUBKEY + registration SIG, retained so this node can RE-GOSSIP the record
    /// verifiably (peers re-verify before adopting). Without them a name was one-shot gossip: MEASURED
    /// 2026-08-13 launch sim — @launchw2 REGISTERED on B, its single gossip message died in link churn,
    /// A resolved None forever (zero inbound Name messages) and pay-by-name failed cross-node. Cost:
    /// ~5KB per NAME (a user-created handle, opt-in public directory state) — never per block/note.
    /// `#[serde(default)]` keeps pre-existing registries loading; legacy entries (empty sig) still
    /// resolve locally but are skipped by re-gossip (honest: they never carried a verifiable proof).
    #[serde(default)]
    pub pubkey: Vec<u8>,
    #[serde(default)]
    pub sig: Vec<u8>,
}

/// The on-disk registry's decode, ONE function so the decode doors (`decode_doors::NAME_REGISTRY_FILE`, B1 (ii),
/// 2026-10-22) drive the same bytes the boot reads. `None` = the bytes are not a registry; `open` keeps its documented
/// fail-open (an empty registry) at its own site, unchanged.
/// ROOT-LAYER: this IS where the registry value is produced from the file's bytes (the decode), not a reader of it.
/// MEASURED: names.rs:111 was one of the 20 "decode of outside bytes no fuzzer reaches" rows (scratchpad/holes-latest.txt,
/// 1,154 holes on 441837f); the replay pin drives this function with the corpus and seeded hostile bytes (its log is the
/// ledger section's number).
/// MUST-STAY-GREEN: `names` tests (a registry survives a restart; a corrupt file starts empty), the restart census.
pub fn parse_registry_bytes(bytes: &[u8]) -> Option<HashMap<String, NameRecord>> {
    serde_json::from_slice(bytes).ok()
}

/// The result of adopting a name registration.
#[derive(Debug, PartialEq, Eq)]
pub enum NameOutcome {
    /// The name was unclaimed and is now the caller's (first-come).
    Registered,
    /// The name's CURRENT owner re-pointed / transferred it.
    Updated,
    /// A DIFFERENT owner holds this name → rejected (name-squat protection).
    Taken,
    /// An IDENTICAL re-registration by the SAME owner (same name → same address) — a no-op. The gossip layer
    /// treats this as "nothing new" and does NOT re-broadcast, so an echoed registration dies instead of looping
    /// forever across the mesh (the dedup that keeps the bidirectional name gossip loop-free).
    Unchanged,
    /// The ML-DSA signature did not authenticate the registration → rejected fail-closed.
    Unauthenticated,
}

/// A gossiped @username registration — the wire form the name directory REPLICATES across the mesh so every node
/// converges on the same @name → address (like [`crate::site::SiteGossip`]). It carries the SAME fields a
/// `/register_username` RPC would; a receiving node re-runs the AUTHENTICATED adopt (ML-DSA sig over
/// `name_register_msg` + the first-come/owner rule) before accepting, so a peer can never forge or squat a name.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NameGossip {
    pub name: String,
    pub address: String,
    pub pubkey: Vec<u8>,
    pub sig: Vec<u8>,
}

impl NameGossip {
    /// Postcard wire bytes (the [`crate::protocol::WireMsg::Name`] payload).
    pub fn to_wire(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }
    /// Decode a received frame; a corrupt/truncated one returns `None` (fail-closed).
    pub fn from_wire(bytes: &[u8]) -> Option<NameGossip> {
        crate::chain_object::decode_exact(bytes)
    }
}

/// A node's live set of registered names (mirrored from the chain). DISK-PERSISTED (cardinal: every asset-type
/// registry survives a node restart) — `open` loads the on-disk copy at startup, every state-changing `adopt` saves.
pub struct NameRegistry {
    names: HashMap<String, NameRecord>,
    /// Port-keyed persist file (`~/.usdmd-node/names-<port>.json`). `None` = in-memory only (unit tests); `Some`
    /// once the serve loop calls `open`, after which every registration auto-saves so it survives a node restart.
    persist_path: Option<std::path::PathBuf>,
}

impl NameRegistry {
    pub fn new() -> Self {
        NameRegistry {
            names: HashMap::new(),
            persist_path: None,
        }
    }

    /// Open the registry at `path`, LOADING any existing on-disk copy so a node restart RESUMES with every name
    /// intact (cardinal: asset registries are restart-proof, like #106 frontier-persist). Every future `adopt`
    /// auto-saves to this path. A missing/corrupt file just starts empty (fail-open — never blocks startup).
    pub fn open(path: std::path::PathBuf) -> Self {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // O1-INFINITY-REVIEWED: unchanged boot read of the opt-in @name directory (per NAME a user registered, never per block or note — names.rs:36); this edit only routes its bytes through the one decode function the decode doors drive (B1 (ii))
        // ROOT-LAYER: `open` is where the registry is PRODUCED from the file's bytes; `parse_registry_bytes` is that decode, and the empty-registry default on a file that does not decode is this function's documented fail-open (its doc comment), unchanged in shape.
        // MEASURED: names.rs:111 was one of the 20 "decode of outside bytes no fuzzer reaches" rows (scratchpad/holes-latest.txt, 1,154 holes on 441837f); the decode-door replay now drives this decode with the corpus and seeded hostile bytes.
        // MUST-STAY-GREEN: the `names` tests (a registry survives a restart, a corrupt file starts empty), the restart census's names field.
        let loaded: HashMap<String, NameRecord> = std::fs::read(&path).ok().and_then(|b| parse_registry_bytes(&b)).unwrap_or_default();
        // MIGRATE any legacy pre-canon (mixed-case) keys to the canonical form so the case-insensitive rule applies
        // uniformly to the whole registry — a name registered before canonicalization still resolves by any case.
        // Idempotent (canon of a canonical key is itself); a collision keeps the first-seen (dedup).
        let mut names = HashMap::with_capacity(loaded.len());
        for (k, v) in loaded {
            names.entry(canon_name(&k)).or_insert(v);
        }
        NameRegistry {
            names,
            persist_path: Some(path),
        }
    }

    /// Atomically persist the registry (temp file + rename, so a crash mid-write never tears the file). Best-effort:
    /// an IO error is swallowed so persistence can NEVER halt a registration or block production (liveness pillar).
    fn save(&self) {
        let Some(path) = self.persist_path.as_ref() else {
            return;
        };
        let Ok(bytes) = serde_json::to_vec(&self.names) else {
            return;
        };
        let tmp = path.with_extension("json.tmp");
        if std::fs::write(&tmp, &bytes).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }

    /// Every record this node can RE-GOSSIP verifiably (retained pubkey+sig). The directory-sync
    /// anti-entropy: sent to each newly-joined link so one lost gossip can never diverge the mesh
    /// forever. Bounded by the directory size — user-created handles, never a chain quantity.
    pub fn regossip_all(&self) -> Vec<NameGossip> {
        self.names
            .iter()
            .filter(|(_, r)| !r.sig.is_empty() && !r.pubkey.is_empty())
            .map(|(n, r)| NameGossip {
                name: n.clone(),
                address: r.address.clone(),
                pubkey: r.pubkey.clone(),
                sig: r.sig.clone(),
            })
            .collect()
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Resolve `@name` → its current address, if registered. Case-insensitive + `@`-optional via [`canon_name`].
    pub fn resolve(&self, name: &str) -> Option<&str> {
        self.names
            .get(&canon_name(name))
            .map(|r| r.address.as_str())
    }

    /// The key that owns `@name` (`H(owner ML-DSA pubkey)`), if registered: what a `name.mud` site is looked up under
    /// ([`crate::veil::resolve_mud`]). Read from this node's own registry, like [`Self::resolve`].
    pub fn owner_of(&self, name: &str) -> Option<[u8; 32]> {
        self.names.get(&canon_name(name)).map(|r| r.owner)
    }

    /// The public REVERSE lookup: every name currently pointing at `address`. Names are a public directory, so
    /// inverting them leaks nothing beyond what `resolve` already exposes — it lets a wallet re-discover ITS OWN
    /// handles after a restart (restart-proof, no local persistence, no scan-key involved). O(registry) over a
    /// small per-user-handle set; returned sorted for a stable render.
    pub fn names_of(&self, address: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .names
            .iter()
            .filter(|(_, r)| r.address == address)
            .map(|(n, _)| n.clone())
            .collect();
        out.sort();
        out
    }

    /// Adopt a name registration whose ML-DSA signature the caller has ALREADY verified. First-come claims the
    /// name; an existing name may only be updated/transferred by its CURRENT owner. A claim on a name a DIFFERENT
    /// owner holds is rejected (fail-closed, never overwrites).
    pub fn adopt(
        &mut self,
        name: String,
        address: String,
        owner: [u8; 32],
        pubkey: &[u8],
        sig: &[u8],
    ) -> NameOutcome {
        let name = canon_name(&name); // CASE-INSENSITIVE + @-optional key — squatting a case-variant is impossible
        let outcome = match self.names.get(&name) {
            Some(rec) if rec.owner != owner => NameOutcome::Taken,
            // Same owner + same address = an identical re-registration (e.g. a gossip echo) → no-op, do NOT
            // re-broadcast (keeps the bidirectional name gossip loop-free). ONE exception, still Unchanged
            // to the caller: a LEGACY record (persisted before pubkey/sig retention, loaded via
            // `#[serde(default)]` as empty) is UPGRADED in place with the verified credentials the caller
            // just supplied — without this, an owner's re-registration could never make an old name
            // re-gossipable and the directory-sync would skip it forever.
            Some(rec) if rec.address == address => {
                if rec.pubkey.is_empty() && !pubkey.is_empty() {
                    if let Some(rec) = self.names.get_mut(&name) {
                        rec.pubkey = pubkey.to_vec();
                        rec.sig = sig.to_vec();
                        self.save();
                    }
                }
                NameOutcome::Unchanged
            }
            Some(_) => {
                self.names.insert(
                    name,
                    NameRecord {
                        address,
                        owner,
                        pubkey: pubkey.to_vec(),
                        sig: sig.to_vec(),
                    },
                );
                NameOutcome::Updated
            }
            None => {
                self.names.insert(
                    name,
                    NameRecord {
                        address,
                        owner,
                        pubkey: pubkey.to_vec(),
                        sig: sig.to_vec(),
                    },
                );
                NameOutcome::Registered
            }
        };
        // Persist on every state change so the name survives a node restart (cardinal: asset-registry disk-persist).
        if matches!(outcome, NameOutcome::Registered | NameOutcome::Updated) {
            self.save();
        }
        outcome
    }
}

impl Default for NameRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    fn owner(n: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = n;
        a
    }

    #[test]
    fn first_come_owner_continuity_and_squat_rejected() {
        let mut reg = NameRegistry::new();
        // First claim wins.
        assert_eq!(
            reg.adopt("alice".into(), "addrA".into(), owner(1), b"pk", b"sig"),
            NameOutcome::Registered
        );
        assert_eq!(reg.resolve("alice"), Some("addrA"));
        // The owner may re-point / transfer their OWN name.
        assert_eq!(
            reg.adopt("alice".into(), "addrA2".into(), owner(1), b"pk", b"sig"),
            NameOutcome::Updated
        );
        assert_eq!(reg.resolve("alice"), Some("addrA2"));
        // A DIFFERENT owner cannot steal the name — fail-closed, the record is untouched.
        assert_eq!(
            reg.adopt("alice".into(), "addrB".into(), owner(2), b"pk", b"sig"),
            NameOutcome::Taken
        );
        assert_eq!(
            reg.resolve("alice"),
            Some("addrA2"),
            "a squat attempt must NOT overwrite the owner's record"
        );
        // An unregistered name resolves to nothing.
        assert_eq!(reg.resolve("bob"), None);
    }

    /// CASE-INSENSITIVE + @-OPTIONAL usernames (user 2026-07-11): every capitalization + the @-form map to ONE
    /// canonical owner, so payments are fool-proof AND a fraudster cannot squat a case-variant to bypass uniqueness.
    #[test]
    fn username_is_case_insensitive_and_at_optional() {
        let mut reg = NameRegistry::new();
        assert_eq!(
            reg.adopt("Flame".into(), "addrA".into(), owner(1), b"pk", b"sig"),
            NameOutcome::Registered
        );
        // A DIFFERENT owner canNOT squat a case-variant / @-form — they canonicalize to the SAME key → Taken.
        assert_eq!(
            reg.adopt("flaMe".into(), "addrB".into(), owner(2), b"pk", b"sig"),
            NameOutcome::Taken
        );
        assert_eq!(
            reg.adopt("FLAME".into(), "addrB".into(), owner(2), b"pk", b"sig"),
            NameOutcome::Taken
        );
        assert_eq!(
            reg.adopt("@flame".into(), "addrB".into(), owner(2), b"pk", b"sig"),
            NameOutcome::Taken
        );
        assert_eq!(
            reg.resolve("Flame"),
            Some("addrA"),
            "the squat must not have overwritten the owner"
        );
        // Resolve is case-insensitive + @-optional + whitespace-tolerant — every spelling pays the SAME owner.
        for spelling in [
            "Flame",
            "flame",
            "FLAME",
            "fLaMe",
            "@Flame",
            "@FLAME",
            "  @flame  ",
        ] {
            assert_eq!(
                reg.resolve(spelling),
                Some("addrA"),
                "spelling {spelling:?} must resolve to the owner"
            );
        }
        // The owner CAN re-point their OWN name via any spelling (owner-continuity on the canonical key).
        assert_eq!(
            reg.adopt("@FLAME".into(), "addrA2".into(), owner(1), b"pk", b"sig"),
            NameOutcome::Updated
        );
        assert_eq!(reg.resolve("flame"), Some("addrA2"));
    }

    #[test]
    fn persist_survives_reopen() {
        // Simulate a NODE RESTART: open a registry at a path, adopt a name, DROP the registry (the node stops),
        // then reopen the SAME path (the node restarts). The name MUST still resolve — proving save-on-adopt +
        // load-on-open (the asset-registry disk-persist cardinal: usernames survive a node restart).
        let dir = std::env::temp_dir().join(format!("usdmd-names-test-{}", std::process::id()));
        let path = dir.join("names.json");
        let _ = std::fs::remove_dir_all(&dir);
        {
            let mut reg = NameRegistry::open(path.clone());
            assert_eq!(
                reg.adopt("alice".into(), "addrA".into(), owner(1), b"pk", b"sig"),
                NameOutcome::Registered
            );
            assert_eq!(reg.names_of("addrA"), vec!["alice".to_string()]);
        } // dropped → the node "restarted"; only what was SAVED to disk survives
        let reg2 = NameRegistry::open(path.clone());
        assert_eq!(
            reg2.resolve("alice"),
            Some("addrA"),
            "a persisted name must survive a node restart"
        );
        assert_eq!(
            reg2.names_of("addrA"),
            vec!["alice".to_string()],
            "reverse lookup survives too"
        );
        // Owner-continuity holds across the restart: a DIFFERENT owner still cannot squat the persisted name.
        let mut reg3 = NameRegistry::open(path.clone());
        assert_eq!(
            reg3.adopt("alice".into(), "addrX".into(), owner(2), b"pk", b"sig"),
            NameOutcome::Taken
        );
        // And the owner's OWN re-point persists across another reopen.
        assert_eq!(
            reg3.adopt("alice".into(), "addrA2".into(), owner(1), b"pk", b"sig"),
            NameOutcome::Updated
        );
        drop(reg3);
        assert_eq!(
            NameRegistry::open(path.clone()).resolve("alice"),
            Some("addrA2")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
